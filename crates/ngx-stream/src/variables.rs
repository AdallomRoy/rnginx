//! Stream variables (ngx_stream_variables.c).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::*;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
use ngx_core::string::{eq_ignore_case, B};
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::*;

pub const NGX_STREAM_VAR_CHANGEABLE: u32 = 1;
pub const NGX_STREAM_VAR_NOCACHEABLE: u32 = 2;
pub const NGX_STREAM_VAR_INDEXED: u32 = 4;
pub const NGX_STREAM_VAR_NOHASH: u32 = 8;
pub const NGX_STREAM_VAR_WEAK: u32 = 16;
pub const NGX_STREAM_VAR_PREFIX: u32 = 32;

/// ngx_stream_variable_value_t
#[derive(Clone, Default, Debug)]
pub struct VariableValue {
    pub data: Vec<u8>,
    pub valid: bool,
    pub no_cacheable: bool,
    pub not_found: bool,
}

impl VariableValue {
    /// ngx_stream_variable("...")
    pub fn new(data: &[u8]) -> VariableValue {
        VariableValue { data: data.to_vec(), valid: true, no_cacheable: false, not_found: false }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// ngx_stream_variable_null_value
pub fn null_value() -> VariableValue {
    VariableValue::new(b"")
}

/// ngx_stream_variable_true_value
pub fn true_value() -> VariableValue {
    VariableValue::new(b"1")
}

pub type GetHandler = fn(&Session, &mut VariableValue, usize) -> i64;
pub type SetHandler = fn(&Session, &mut VariableValue, usize);

/// ngx_stream_variable_t
pub struct Variable {
    pub name: Vec<u8>,
    pub set_handler: Cell<Option<SetHandler>>,
    pub get_handler: Cell<Option<GetHandler>>,
    pub data: Cell<usize>,
    pub flags: Cell<u32>,
    pub index: Cell<usize>,
}

impl Variable {
    fn new(name: &[u8], flags: u32) -> Rc<Variable> {
        Rc::new(Variable {
            name: ngx_core::string::to_lower_vec(name),
            set_handler: Cell::new(None),
            get_handler: Cell::new(None),
            data: Cell::new(0),
            flags: Cell::new(flags),
            index: Cell::new(0),
        })
    }
}

/// An entry of a module's variables table (static ngx_stream_variable_t []).
pub struct VarDef {
    pub name: &'static str,
    pub set: Option<SetHandler>,
    pub get: Option<GetHandler>,
    pub data: usize,
    pub flags: u32,
}

/// Add a module's variables table (the loop of the modules'
/// add_variables()).
pub fn add_variables(cf: &mut Conf, vars: &[VarDef]) -> ConfResult {
    for cv in vars {
        let v = add_variable(cf, cv.name.as_bytes(), cv.flags)?;
        v.get_handler.set(cv.get);
        v.set_handler.set(cv.set);
        v.data.set(cv.data);
    }
    Ok(())
}

thread_local! {
    static VARIABLE_DEPTH: Cell<usize> = const { Cell::new(100) };
    /// The name a prefix variable is looked up by in get_variable() (the
    /// data of the handler is then usize::MAX)
    static PREFIX_NAME: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// The full name of the variable of a prefix variable handler: the data C
/// passes is a pointer to the name (&v[i].name for the indexed ones, the
/// name looked up in ngx_stream_get_variable()); here it is the index of
/// the variable, usize::MAX for a lookup by name.
pub fn prefix_var_name(s: &Session, data: usize) -> Vec<u8> {
    if data == usize::MAX {
        return PREFIX_NAME.with(|n| n.borrow().clone());
    }

    let cmcf = s.cmcf();
    let m = cmcf.borrow();

    m.variables.get(data).map(|v| v.name.clone()).unwrap_or_default()
}

/// ngx_stream_add_variable
pub fn add_variable(cf: &mut Conf, name: &[u8], flags: u32) -> Result<Rc<Variable>, ConfError> {
    if name.is_empty() {
        return Err(cf.emerg(format_args!("invalid variable name \"$\"")));
    }

    if flags & NGX_STREAM_VAR_PREFIX != 0 {
        return add_prefix_variable(cf, name, flags);
    }

    let cmcf = core_main_conf(cf);
    let mut m = cmcf.borrow_mut();

    let keys = m.variables_keys.as_ref().expect("variables keys");

    for k in keys.keys() {
        if name.len() != k.key.len() || !eq_ignore_case(name, &k.key) {
            continue;
        }

        let v = k.value.clone();

        if v.flags.get() & NGX_STREAM_VAR_CHANGEABLE == 0 {
            drop(m);
            return Err(cf.emerg(format_args!("the duplicate \"{}\" variable", B(name))));
        }

        if flags & NGX_STREAM_VAR_WEAK == 0 {
            v.flags.set(v.flags.get() & !NGX_STREAM_VAR_WEAK);
        }

        return Ok(v);
    }

    let v = Variable::new(name, flags);

    let rc = m.variables_keys.as_mut().unwrap().add_key(v.name.clone(), v.clone(), 0);

    if rc == NGX_ERROR {
        return Err(ConfError::Logged);
    }

    if rc == NGX_BUSY {
        drop(m);
        return Err(cf.emerg(format_args!("conflicting variable name \"{}\"", B(name))));
    }

    Ok(v)
}

/// ngx_stream_add_prefix_variable
fn add_prefix_variable(cf: &mut Conf, name: &[u8], flags: u32) -> Result<Rc<Variable>, ConfError> {
    let cmcf = core_main_conf(cf);
    let mut m = cmcf.borrow_mut();

    for v in m.prefix_variables.iter() {
        if name.len() != v.name.len() || !eq_ignore_case(name, &v.name) {
            continue;
        }

        if v.flags.get() & NGX_STREAM_VAR_CHANGEABLE == 0 {
            drop(m);
            return Err(cf.emerg(format_args!("the duplicate \"{}\" variable", B(name))));
        }

        if flags & NGX_STREAM_VAR_WEAK == 0 {
            v.flags.set(v.flags.get() & !NGX_STREAM_VAR_WEAK);
        }

        return Ok(v.clone());
    }

    let v = Variable::new(name, flags);
    m.prefix_variables.push(v.clone());

    Ok(v)
}

/// ngx_stream_get_variable_index
pub fn get_variable_index(cf: &mut Conf, name: &[u8]) -> Result<usize, ConfError> {
    if name.is_empty() {
        return Err(cf.emerg(format_args!("invalid variable name \"$\"")));
    }

    let cmcf = core_main_conf(cf);
    let mut m = cmcf.borrow_mut();

    for (i, v) in m.variables.iter().enumerate() {
        if name.len() != v.name.len() || !eq_ignore_case(name, &v.name) {
            continue;
        }

        return Ok(i);
    }

    let v = Variable::new(name, 0);
    let index = m.variables.len();
    v.index.set(index);
    m.variables.push(v);

    Ok(index)
}

fn ensure_variables(s: &Session, n: usize) {
    let mut vars = s.variables.borrow_mut();
    if vars.len() < n {
        vars.resize(n, VariableValue::default());
    }
}

/// ngx_stream_get_indexed_variable
pub fn get_indexed_variable(s: &Session, index: usize) -> Option<VariableValue> {
    let cmcf = s.cmcf();

    let (var, nvars) = {
        let m = cmcf.borrow();

        if m.variables.len() <= index {
            ngx_log_error!(NGX_LOG_ALERT, s.connection.log, None, "unknown variable index: {}", index);
            return None;
        }

        (m.variables[index].clone(), m.variables.len())
    };

    ensure_variables(s, nvars);

    {
        let vars = s.variables.borrow();
        let v = &vars[index];
        if v.not_found || v.valid {
            return Some(v.clone());
        }
    }

    if VARIABLE_DEPTH.with(|d| d.get()) == 0 {
        ngx_log_error!(NGX_LOG_ERR, s.connection.log, None, "cycle while evaluating variable \"{}\"", B(&var.name));
        return None;
    }

    VARIABLE_DEPTH.with(|d| d.set(d.get() - 1));

    let mut vv = s.variables.borrow()[index].clone();

    let rc = match var.get_handler.get() {
        Some(get) => get(s, &mut vv, var.data.get()),
        None => NGX_ERROR,
    };

    VARIABLE_DEPTH.with(|d| d.set(d.get() + 1));

    if rc == NGX_OK {
        if var.flags.get() & NGX_STREAM_VAR_NOCACHEABLE != 0 {
            vv.no_cacheable = true;
        }

        s.variables.borrow_mut()[index] = vv.clone();

        return Some(vv);
    }

    let mut vars = s.variables.borrow_mut();
    vars[index].valid = false;
    vars[index].not_found = true;

    None
}

/// ngx_stream_get_flushed_variable
pub fn get_flushed_variable(s: &Session, index: usize) -> Option<VariableValue> {
    let nvars = s.cmcf().borrow().variables.len();
    ensure_variables(s, nvars);

    {
        let mut vars = s.variables.borrow_mut();

        if let Some(v) = vars.get_mut(index) {
            if v.valid || v.not_found {
                if !v.no_cacheable {
                    return Some(v.clone());
                }

                v.valid = false;
                v.not_found = false;
            }
        }
    }

    get_indexed_variable(s, index)
}

/// ngx_stream_get_variable
pub fn get_variable(s: &Session, name: &[u8], key: usize) -> Option<VariableValue> {
    let cmcf = s.cmcf();

    let found = {
        let m = cmcf.borrow();
        m.variables_hash.as_ref().and_then(|h| h.find(key, name).cloned())
    };

    if let Some(v) = found {
        if v.flags.get() & NGX_STREAM_VAR_INDEXED != 0 {
            return get_flushed_variable(s, v.index.get());
        }

        if VARIABLE_DEPTH.with(|d| d.get()) == 0 {
            ngx_log_error!(NGX_LOG_ERR, s.connection.log, None, "cycle while evaluating variable \"{}\"", B(name));
            return None;
        }

        VARIABLE_DEPTH.with(|d| d.set(d.get() - 1));

        let mut vv = VariableValue::default();

        let rc = match v.get_handler.get() {
            Some(get) => get(s, &mut vv, v.data.get()),
            None => NGX_ERROR,
        };

        VARIABLE_DEPTH.with(|d| d.set(d.get() + 1));

        if rc == NGX_OK {
            return Some(vv);
        }

        return None;
    }

    let mut vv = VariableValue::default();

    let prefix = {
        let m = cmcf.borrow();
        let mut len = 0;
        let mut found = None;

        for v in m.prefix_variables.iter() {
            if name.len() >= v.name.len() && name.len() > len && name.starts_with(&v.name) {
                len = v.name.len();
                found = Some(v.clone());
            }
        }

        found
    };

    if let Some(v) = prefix {
        PREFIX_NAME.with(|n| *n.borrow_mut() = name.to_vec());

        let rc = match v.get_handler.get() {
            Some(get) => get(s, &mut vv, usize::MAX),
            None => NGX_ERROR,
        };

        if rc == NGX_OK {
            return Some(vv);
        }

        return None;
    }

    vv.not_found = true;

    Some(vv)
}

fn set_value(v: &mut VariableValue, data: &[u8]) {
    v.data = data.to_vec();
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
}

fn variable_binary_remote_addr(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let sa = s.connection.sockaddr.borrow().clone();

    match sa {
        ngx_core::inet::SockAddr::V6(a) => set_value(v, &a.ip().octets()),
        ngx_core::inet::SockAddr::Unix(_) => {
            let t = s.connection.addr_text.borrow().clone();
            set_value(v, &t);
        }
        ngx_core::inet::SockAddr::V4(a) => set_value(v, &a.ip().octets()),
    }

    NGX_OK
}

fn variable_remote_addr(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let t = s.connection.addr_text.borrow().clone();
    set_value(v, &t);
    NGX_OK
}

fn port_text(port: u16) -> Vec<u8> {
    if port > 0 {
        port.to_string().into_bytes()
    } else {
        Vec::new()
    }
}

fn variable_remote_port(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let port = s.connection.sockaddr.borrow().port();
    set_value(v, &port_text(port));
    NGX_OK
}

fn proxy_protocol(s: &Session) -> Option<Rc<ngx_core::proxy_protocol::ProxyProtocol>> {
    let pp = s.connection.proxy_protocol.borrow().clone()?;
    pp.downcast::<ngx_core::proxy_protocol::ProxyProtocol>().ok()
}

const PP_SRC: usize = 0;
const PP_DST: usize = 1;

fn variable_proxy_protocol_addr(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let pp = match proxy_protocol(s) {
        Some(pp) => pp,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    set_value(v, if data == PP_SRC { &pp.src_addr } else { &pp.dst_addr });

    NGX_OK
}

fn variable_proxy_protocol_port(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let pp = match proxy_protocol(s) {
        Some(pp) => pp,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    let port = if data == PP_SRC { pp.src_port } else { pp.dst_port };

    set_value(v, &port_text(port));

    NGX_OK
}

fn variable_proxy_protocol_tlv(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    // data: the variable name (ngx_str_t *)
    let name = prefix_var_name(s, data);

    let tlv = &name[b"proxy_protocol_tlv_".len()..];

    let pp = match proxy_protocol(s) {
        Some(pp) => pp,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    match ngx_core::proxy_protocol::get_tlv(&pp, &s.connection.log, tlv) {
        Err(()) => NGX_ERROR,
        Ok(None) => {
            v.not_found = true;
            NGX_OK
        }
        Ok(Some(value)) => {
            set_value(v, &value);
            NGX_OK
        }
    }
}

fn variable_server_addr(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    match s.connection.local_sockaddr() {
        Some(sa) => {
            set_value(v, &sa.to_text(false));
            NGX_OK
        }
        None => NGX_ERROR,
    }
}

fn variable_server_port(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    match s.connection.local_sockaddr() {
        Some(sa) => {
            set_value(v, &port_text(sa.port()));
            NGX_OK
        }
        None => NGX_ERROR,
    }
}

fn variable_server_name(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let name = s.cscf().borrow().server_name.clone();
    set_value(v, &name);
    NGX_OK
}

fn variable_bytes(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let n = if data == 1 { s.received.get() } else { s.connection.sent.get() as i64 };
    set_value(v, n.to_string().as_bytes());
    NGX_OK
}

fn variable_session_time(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let tp = ngx_core::times::cached();

    let ms = (tp.sec - s.start_sec.get()) * 1000 + (tp.msec as i64 - s.start_msec.get() as i64);
    let ms = ms.max(0);

    set_value(v, format!("{}.{:03}", ms / 1000, ms % 1000).as_bytes());

    NGX_OK
}

fn variable_status(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    set_value(v, format!("{:03}", s.status.get()).as_bytes());
    NGX_OK
}

fn variable_connection(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    set_value(v, s.connection.number.to_string().as_bytes());
    NGX_OK
}

fn variable_nginx_version(_s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    set_value(v, ngx_core::NGINX_VERSION.as_bytes());
    NGX_OK
}

fn variable_hostname(_s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    set_value(v, &ngx_core::cycle::cycle().hostname);
    NGX_OK
}

fn variable_pid(_s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    set_value(v, ngx_core::log::pid().to_string().as_bytes());
    NGX_OK
}

fn variable_msec(_s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let tp = ngx_core::times::cached();
    set_value(v, format!("{}.{:03}", tp.sec, tp.msec).as_bytes());
    NGX_OK
}

fn variable_time_iso8601(_s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    set_value(v, ngx_core::times::cached_http_log_iso8601().as_bytes());
    NGX_OK
}

fn variable_time_local(_s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    set_value(v, ngx_core::times::cached_http_log_time().as_bytes());
    NGX_OK
}

fn variable_protocol(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    set_value(v, if s.connection.ty == libc::SOCK_DGRAM { b"UDP" } else { b"TCP" });
    NGX_OK
}

static CORE_VARIABLES: &[VarDef] = &[
    VarDef { name: "binary_remote_addr", set: None, get: Some(variable_binary_remote_addr), data: 0, flags: 0 },
    VarDef { name: "remote_addr", set: None, get: Some(variable_remote_addr), data: 0, flags: 0 },
    VarDef { name: "remote_port", set: None, get: Some(variable_remote_port), data: 0, flags: 0 },
    VarDef { name: "proxy_protocol_addr", set: None, get: Some(variable_proxy_protocol_addr), data: PP_SRC, flags: 0 },
    VarDef { name: "proxy_protocol_port", set: None, get: Some(variable_proxy_protocol_port), data: PP_SRC, flags: 0 },
    VarDef { name: "proxy_protocol_server_addr", set: None, get: Some(variable_proxy_protocol_addr), data: PP_DST, flags: 0 },
    VarDef { name: "proxy_protocol_server_port", set: None, get: Some(variable_proxy_protocol_port), data: PP_DST, flags: 0 },
    VarDef { name: "proxy_protocol_tlv_", set: None, get: Some(variable_proxy_protocol_tlv), data: 0, flags: NGX_STREAM_VAR_PREFIX },
    VarDef { name: "server_addr", set: None, get: Some(variable_server_addr), data: 0, flags: 0 },
    VarDef { name: "server_port", set: None, get: Some(variable_server_port), data: 0, flags: 0 },
    VarDef { name: "server_name", set: None, get: Some(variable_server_name), data: 0, flags: 0 },
    VarDef { name: "bytes_sent", set: None, get: Some(variable_bytes), data: 0, flags: 0 },
    VarDef { name: "bytes_received", set: None, get: Some(variable_bytes), data: 1, flags: 0 },
    VarDef { name: "session_time", set: None, get: Some(variable_session_time), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "status", set: None, get: Some(variable_status), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "connection", set: None, get: Some(variable_connection), data: 0, flags: 0 },
    VarDef { name: "nginx_version", set: None, get: Some(variable_nginx_version), data: 0, flags: 0 },
    VarDef { name: "hostname", set: None, get: Some(variable_hostname), data: 0, flags: 0 },
    VarDef { name: "pid", set: None, get: Some(variable_pid), data: 0, flags: 0 },
    VarDef { name: "msec", set: None, get: Some(variable_msec), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "time_iso8601", set: None, get: Some(variable_time_iso8601), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "time_local", set: None, get: Some(variable_time_local), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "protocol", set: None, get: Some(variable_protocol), data: 0, flags: 0 },
];

// --- map ---

/// ngx_stream_map_regex_t
pub struct MapRegex<T> {
    pub regex: Rc<StreamRegex>,
    pub value: T,
}

/// ngx_stream_map_t
pub struct StreamMap<T: Clone> {
    pub hash: HashCombined<T>,
    pub regex: Vec<MapRegex<T>>,
}

/// ngx_stream_map_find
pub fn map_find<T: Clone>(s: &Session, map: &StreamMap<T>, m: &[u8]) -> Option<T> {
    let len = m.len();

    // the value lowercased on the stack for the usual values
    let mut stack = [0u8; 256];
    let mut heap = Vec::new();

    let low: &mut [u8] = if len <= stack.len() {
        &mut stack[..len]
    } else {
        heap.resize(len, 0);
        &mut heap
    };

    let key = hash_strlow(low, m);

    if let Some(v) = map.hash.find(key, low) {
        return Some(v.clone());
    }

    if len > 0 && !map.regex.is_empty() {
        for reg in map.regex.iter() {
            let n = regex_exec(s, &reg.regex, m);

            if n == NGX_OK {
                return Some(reg.value.clone());
            }

            if n == NGX_DECLINED {
                continue;
            }

            // NGX_ERROR

            return None;
        }
    }

    None
}

// --- regex ---

/// ngx_stream_regex_t
pub struct StreamRegex {
    pub regex: Rc<Regex>,
    pub ncaptures: usize,
    /// (capture, variable index) of the named captures
    pub variables: Vec<(usize, usize)>,
    pub name: Vec<u8>,
}

fn variable_not_found(_s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    v.not_found = true;
    NGX_OK
}

/// ngx_stream_regex_compile
pub fn regex_compile(cf: &mut Conf, pattern: &[u8], options: u32) -> Result<Rc<StreamRegex>, ConfError> {
    let re = match Regex::compile(pattern, options) {
        Ok(r) => r,
        Err(e) => return Err(cf.emerg(format_args!("{}", e))),
    };

    let cmcf = core_main_conf(cf);
    {
        let mut m = cmcf.borrow_mut();
        m.ncaptures = m.ncaptures.max(re.captures);
    }

    let mut variables = Vec::new();

    for (name, capture) in re.names.iter() {
        let v = add_variable(cf, name, NGX_STREAM_VAR_CHANGEABLE)?;

        let index = get_variable_index(cf, name)?;

        v.get_handler.set(Some(variable_not_found));

        variables.push((2 * capture, index));
    }

    Ok(Rc::new(StreamRegex { ncaptures: re.captures, regex: re, variables, name: pattern.to_vec() }))
}

/// ngx_stream_regex_exec: NGX_OK (the captures are set), NGX_DECLINED
/// (no match) or NGX_ERROR
///
/// The captures and their subject go to the session's own arrays, reused
/// from match to match; the subject may be borrowed from anything but
/// them and s->variables.
pub fn regex_exec(s: &Session, re: &StreamRegex, str: &[u8]) -> i64 {
    // the return code of pcre2_match(): the highest set pair plus one
    let rc;

    if re.ncaptures > 0 {
        let len = s.cmcf().borrow().ncaptures;

        let mut captures = s.captures.borrow_mut();

        let pairs = match re.regex.exec_into(str, &mut captures) {
            None => return NGX_DECLINED,
            Some(n) => n,
        };

        rc = (0..pairs).rposition(|i| captures[2 * i] >= 0).map(|i| i + 1).unwrap_or(1);

        if !re.variables.is_empty() {
            let nvars = s.cmcf().borrow().variables.len();
            ensure_variables(s, nvars);

            let mut vars = s.variables.borrow_mut();

            for (n, index) in re.variables.iter() {
                let (a, b) = if n / 2 < pairs { (captures[*n], captures[*n + 1]) } else { (-1, -1) };

                // the value of the named capture, its buffer reused
                let vv = &mut vars[*index];
                vv.data.clear();
                if a >= 0 && b >= a {
                    vv.data.extend_from_slice(&str[a as usize..b as usize]);
                }
                vv.valid = true;
                vv.no_cacheable = false;
                vv.not_found = false;
            }
        }

        // the pairs that fit in the array of cmcf->ncaptures ints
        captures.truncate(2 * pairs.min(len / 3));
    } else {
        // no captures: nothing is written to s->captures (len 0 in C)
        if !re.regex.is_match(str) {
            return NGX_DECLINED;
        }

        rc = 1;
    }

    s.ncaptures.set(rc * 2);

    let mut data = s.captures_data.borrow_mut();
    data.clear();
    data.extend_from_slice(str);

    NGX_OK
}

/// ngx_stream_variables_add_core_vars
pub fn add_core_vars(cf: &mut Conf) -> ConfResult {
    let cmcf = core_main_conf(cf);

    {
        let mut m = cmcf.borrow_mut();
        m.variables_keys = Some(HashKeysArrays::new(HashKind::Small));
        m.prefix_variables = Vec::new();
    }

    add_variables(cf, CORE_VARIABLES)
}

/// ngx_stream_variables_init_vars
pub fn init_vars(cf: &mut Conf) -> ConfResult {
    // set the handlers for the indexed stream variables

    let cmcf = core_main_conf(cf);

    let (variables, keys, prefix) = {
        let m = cmcf.borrow();
        let keys: Vec<(Vec<u8>, Rc<Variable>)> = m.variables_keys.as_ref().expect("variables keys").keys().iter().map(|k| (k.key.clone(), k.value.clone())).collect();
        (m.variables.clone(), keys, m.prefix_variables.clone())
    };

    'next: for (i, v) in variables.iter().enumerate() {
        for (key, av) in keys.iter() {
            if v.name.len() == key.len() && v.name == *key {
                v.get_handler.set(av.get_handler.get());
                v.data.set(av.data.get());

                av.flags.set(av.flags.get() | NGX_STREAM_VAR_INDEXED);
                v.flags.set(av.flags.get());

                av.index.set(i);

                if av.get_handler.get().is_none() || av.flags.get() & NGX_STREAM_VAR_WEAK != 0 {
                    break;
                }

                continue 'next;
            }
        }

        let mut len = 0;
        let mut found: Option<Rc<Variable>> = None;

        for pv in prefix.iter() {
            if v.name.len() >= pv.name.len() && v.name.len() > len && v.name.starts_with(&pv.name) {
                found = Some(pv.clone());
                len = pv.name.len();
            }
        }

        if let Some(av) = found {
            v.get_handler.set(av.get_handler.get());
            // v[i].data = (uintptr_t) &v[i].name: prefix_var_name()
            v.data.set(i);
            v.flags.set(av.flags.get());

            continue 'next;
        }

        if v.get_handler.get().is_none() {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "unknown \"{}\" variable", B(&v.name));
            return Err(ConfError::Logged);
        }
    }

    let (max_size, bucket_size) = {
        let m = cmcf.borrow();
        (*m.variables_hash_max_size as usize, *m.variables_hash_bucket_size as usize)
    };

    let names: Vec<HashKey<Rc<Variable>>> = {
        let m = cmcf.borrow();
        m.variables_keys
            .as_ref()
            .unwrap()
            .keys()
            .iter()
            .filter(|k| k.value.flags.get() & NGX_STREAM_VAR_NOHASH == 0)
            .map(|k| HashKey { key: k.key.clone(), key_hash: k.key_hash, value: k.value.clone() })
            .collect()
    };

    let hinit = HashInit { name: "variables_hash", max_size, bucket_size, log: &cf.log };

    let hash = match Hash::init(&hinit, names) {
        Ok(h) => h,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
            return Err(ConfError::Logged);
        }
    };

    let mut m = cmcf.borrow_mut();
    m.variables_hash = Some(hash);
    m.variables_keys = None;

    Ok(())
}
