//! HTTP variables (ngx_http_variables.c).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::*;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
use ngx_core::string::{B, eq_ignore_case};
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::*;

pub const NGX_HTTP_VAR_CHANGEABLE: u32 = 1;
pub const NGX_HTTP_VAR_NOCACHEABLE: u32 = 2;
pub const NGX_HTTP_VAR_INDEXED: u32 = 4;
pub const NGX_HTTP_VAR_NOHASH: u32 = 8;
pub const NGX_HTTP_VAR_WEAK: u32 = 16;
pub const NGX_HTTP_VAR_PREFIX: u32 = 32;

pub type GetHandler = fn(&R, &mut VariableValue, usize) -> i64;
pub type SetHandler = fn(&R, &mut VariableValue, usize);

pub struct Variable {
    pub name: Vec<u8>,
    pub set_handler: Cell<Option<SetHandler>>,
    pub get_handler: Cell<Option<GetHandler>>,
    pub data: Cell<usize>,
    pub flags: Cell<u32>,
    pub index: Cell<usize>,
}

impl Variable {
    /// The name is stored lowercased (ngx_strlow() in ngx_http_add_variable,
    /// ngx_http_add_prefix_variable and ngx_http_get_variable_index).
    fn new(name: &[u8], flags: u32) -> Rc<Variable> {
        Rc::new(Variable { name: name.to_ascii_lowercase(), set_handler: Cell::new(None), get_handler: Cell::new(None), data: Cell::new(0), flags: Cell::new(flags), index: Cell::new(0) })
    }
}

/// A "static" variable definition used by modules to register at preconfiguration.
pub struct VarDef {
    pub name: &'static str,
    pub set: Option<SetHandler>,
    pub get: Option<GetHandler>,
    pub data: usize,
    pub flags: u32,
}

/// ngx_http_add_variable
pub fn add_variable(cf: &mut Conf, name: &[u8], flags: u32) -> Result<Rc<Variable>, ConfError> {
    if name.is_empty() {
        return Err(cf.emerg(format_args!("invalid variable name \"$\"")));
    }
    if flags & NGX_HTTP_VAR_PREFIX != 0 {
        return add_prefix_variable(cf, name, flags);
    }
    let cmcf = core_main_conf(cf);
    let mut m = cmcf.borrow_mut();
    if m.variables_keys.is_none() {
        m.variables_keys = Some(HashKeysArrays::new(HashKind::Small));
    }
    let keys = m.variables_keys.as_ref().unwrap();
    for k in keys.keys() {
        if k.key.len() == name.len() && eq_ignore_case(&k.key, name) {
            let v = k.value.clone();
            if v.flags.get() & NGX_HTTP_VAR_CHANGEABLE == 0 {
                drop(m);
                return Err(cf.emerg(format_args!("the duplicate \"{}\" variable", B(name))));
            }
            if (flags & NGX_HTTP_VAR_WEAK) == 0 {
                v.flags.set(v.flags.get() & !NGX_HTTP_VAR_WEAK);
            }
            return Ok(v);
        }
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

/// ngx_http_add_prefix_variable
pub fn add_prefix_variable(cf: &mut Conf, name: &[u8], flags: u32) -> Result<Rc<Variable>, ConfError> {
    let cmcf = core_main_conf(cf);
    let mut m = cmcf.borrow_mut();
    for v in m.prefix_variables.iter() {
        if v.name.len() == name.len() && eq_ignore_case(&v.name, name) {
            if v.flags.get() & NGX_HTTP_VAR_CHANGEABLE == 0 {
                drop(m);
                return Err(cf.emerg(format_args!("the duplicate \"{}\" variable", B(name))));
            }
            if (flags & NGX_HTTP_VAR_WEAK) == 0 {
                v.flags.set(v.flags.get() & !NGX_HTTP_VAR_WEAK);
            }
            return Ok(v.clone());
        }
    }
    let v = Variable::new(name, flags);
    m.prefix_variables.push(v.clone());
    Ok(v)
}

/// ngx_http_get_variable_index
pub fn get_variable_index(cf: &mut Conf, name: &[u8]) -> Result<usize, ConfError> {
    if name.is_empty() {
        return Err(cf.emerg(format_args!("invalid variable name \"$\"")));
    }
    let cmcf = core_main_conf(cf);
    let mut m = cmcf.borrow_mut();
    for (i, v) in m.variables.iter().enumerate() {
        if v.name.len() == name.len() && eq_ignore_case(&v.name, name) {
            return Ok(i);
        }
    }
    // v->flags = 0: whatever defines the variable does so through
    // ngx_http_add_variable (the "set" directive, map, geo, ...), and
    // ngx_http_variables_init_vars() fails on names nothing defined
    let v = Variable::new(name, 0);
    let idx = m.variables.len();
    v.index.set(idx);
    m.variables.push(v);
    Ok(idx)
}

/// ngx_http_get_indexed_variable
pub fn get_indexed_variable(r: &R, index: usize) -> Option<VariableValue> {
    with_indexed_variable(r, index, |v| v.cloned())
}

/// ngx_http_get_indexed_variable without a copy of the value: it is
/// evaluated if not cached yet, cached in r->variables, and lent to `f`
/// (None when it cannot be evaluated, where C returns NULL).
///
/// r->variables stays borrowed while `f` runs: `f` must not evaluate
/// variables (nor set them).
pub fn with_indexed_variable<T>(r: &R, index: usize, f: impl FnOnce(Option<&VariableValue>) -> T) -> T {
    if !index_variable(r, index) {
        return f(None);
    }
    let vars = r.variables.borrow();
    f(vars.get(index))
}

/// The evaluation of ngx_http_get_indexed_variable: true when
/// r->variables[index] holds the value (valid or not found), false when
/// the variable cannot be evaluated.
fn index_variable(r: &R, index: usize) -> bool {
    {
        // r->variables has an element for each indexed variable (no more
        // than cmcf->variables.nelts), so a cached value is a known index
        let vars = r.variables.borrow();
        if let Some(v) = vars.get(index) {
            if v.not_found || v.valid {
                return true;
            }
        }
    }
    let cmcf = r.cmcf();
    let (var, nvars) = {
        let m = cmcf.borrow();
        if index >= m.variables.len() {
            ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "unknown variable index: {}", index);
            return false;
        }
        (m.variables[index].clone(), m.variables.len())
    };
    {
        let mut vars = r.variables.borrow_mut();
        if vars.len() < nvars {
            vars.resize(nvars, VariableValue::default());
        }
    }
    if VARIABLE_DEPTH.with(|d| d.get()) == 0 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "cycle while evaluating variable \"{}\"", B(&var.name));
        return false;
    }
    VARIABLE_DEPTH.with(|d| d.set(d.get() - 1));
    let mut vv = VariableValue::default();
    // ngx_http_variables_init_vars() left no indexed variable without one
    let rc = match var.get_handler.get() {
        Some(g) => g(r, &mut vv, var.data.get()),
        None => NGX_ERROR,
    };
    VARIABLE_DEPTH.with(|d| d.set(d.get() + 1));
    let mut vars = r.variables.borrow_mut();
    if rc == NGX_OK {
        if !vv.not_found {
            vv.valid = true;
        }
        // Propagate NGX_HTTP_VAR_NOCACHEABLE from the variable definition to
        // the per-request slot so get_flushed_variable knows to re-evaluate
        // this entry (used by e.g. `map ... { volatile; }`).
        if var.flags.get() & NGX_HTTP_VAR_NOCACHEABLE != 0 {
            vv.no_cacheable = true;
        }
        vars[index] = vv;
        return true;
    }
    // the get handler fills r->variables[index] itself in C: what it has
    // set before failing (e.g. no_cacheable) stays
    vars[index] = vv;
    vars[index].valid = false;
    vars[index].not_found = true;
    false
}

/// ngx_http_get_flushed_variable
pub fn get_flushed_variable(r: &R, index: usize) -> Option<VariableValue> {
    with_flushed_variable(r, index, |v| v.cloned())
}

/// ngx_http_get_flushed_variable without a copy of the value, as
/// with_indexed_variable(): a non-cacheable value is evaluated again.
pub fn with_flushed_variable<T>(r: &R, index: usize, f: impl FnOnce(Option<&VariableValue>) -> T) -> T {
    flush_variable(r, index);
    with_indexed_variable(r, index, f)
}

/// The cached value of a non-cacheable variable dropped, as
/// ngx_http_get_flushed_variable() does before ngx_http_get_indexed_variable()
/// (and ngx_http_script_flush_complex_value() for the variables of a value).
pub fn flush_variable(r: &R, index: usize) {
    let mut vars = r.variables.borrow_mut();
    if let Some(v) = vars.get_mut(index) {
        if (v.valid || v.not_found) && v.no_cacheable {
            v.valid = false;
            v.not_found = false;
        }
    }
}

/// ngx_http_get_variable (by name at runtime).
pub fn get_variable(r: &R, name: &[u8]) -> Option<VariableValue> {
    // every C caller (ssi, perl) passes the name lowercased with
    // ngx_hash_strlow(); the variable names are stored lowercased
    let name = &name.to_ascii_lowercase()[..];
    let cmcf = r.cmcf();
    let key = hash_key(name);
    let v = {
        let m = cmcf.borrow();
        m.variables_hash.as_ref().and_then(|h| h.find(key, name).cloned())
    };
    if let Some(v) = v {
        if v.flags.get() & NGX_HTTP_VAR_INDEXED != 0 {
            return get_flushed_variable(r, v.index.get());
        }
        if VARIABLE_DEPTH.with(|d| d.get()) == 0 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "cycle while evaluating variable \"{}\"", B(name));
            return None;
        }
        VARIABLE_DEPTH.with(|d| d.set(d.get() - 1));
        let mut vv = VariableValue::default();
        let rc = match v.get_handler.get() {
            Some(g) => g(r, &mut vv, v.data.get()),
            None => NGX_ERROR,
        };
        VARIABLE_DEPTH.with(|d| d.set(d.get() + 1));
        if rc == NGX_OK {
            return Some(vv);
        }
        return None;
    }
    // prefix variables: the longest one the name starts with, looked up in
    // the configuration's list where it is
    let best: Option<Rc<Variable>> = {
        let m = cmcf.borrow();
        let mut best: Option<&Rc<Variable>> = None;
        let mut len = 0;
        for pv in m.prefix_variables.iter() {
            if name.len() >= pv.name.len() && name.len() > len && name[..pv.name.len()] == pv.name[..] {
                len = pv.name.len();
                best = Some(pv);
            }
        }
        best.cloned()
    };
    if let Some(pv) = best {
        let mut vv = VariableValue::default();
        if let Some(g) = pv.get_handler.get() {
            // data = pointer to name in C; we pass name via a thread local
            PREFIX_NAME.with(|n| *n.borrow_mut() = name.to_vec());
            if g(r, &mut vv, usize::MAX) == NGX_OK {
                return Some(vv);
            }
        }
        return None;
    }
    let mut vv = VariableValue::default();
    vv.not_found = true;
    Some(vv)
}

thread_local! {
    /// ngx_http_variable_depth: how many more get handlers may nest before
    /// the evaluation is taken for a cycle
    static VARIABLE_DEPTH: Cell<usize> = const { Cell::new(100) };
    static PREFIX_NAME: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static VAR_NAMES: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// The full variable name for prefix-variable handlers (data == usize::MAX means "current prefix lookup").
pub fn prefix_var_name(r: &R, data: usize) -> Vec<u8> {
    with_prefix_var_name(r, data, |name| name.to_vec())
}

/// prefix_var_name() lent to `f`, without a copy
pub fn with_prefix_var_name<T>(r: &R, data: usize, f: impl FnOnce(&[u8]) -> T) -> T {
    if data == usize::MAX {
        return PREFIX_NAME.with(|n| f(&n.borrow()));
    }
    let cmcf = r.cmcf();
    let m = cmcf.borrow();
    match m.variables.get(data) {
        Some(v) => f(&v.name),
        None => f(b""),
    }
}

/// ngx_http_variables_init_vars
pub fn init_vars(cf: &mut Conf) -> ConfResult {
    let cmcf = core_main_conf(cf);
    let (vars, prefixes, keys) = {
        let m = cmcf.borrow();
        (m.variables.clone(), m.prefix_variables.clone(), m.variables_keys.as_ref().map(|k| k.keys().iter().map(|k| k.value.clone()).collect::<Vec<_>>()).unwrap_or_default())
    };
    // set the handlers for the indexed http variables
    'next: for v in vars.iter() {
        for av in keys.iter() {
            if v.name == av.name {
                v.get_handler.set(av.get_handler.get());
                v.data.set(av.data.get());
                av.flags.set(av.flags.get() | NGX_HTTP_VAR_INDEXED);
                v.flags.set(av.flags.get());
                av.index.set(v.index.get());
                if av.get_handler.get().is_none() || (av.flags.get() & NGX_HTTP_VAR_WEAK) != 0 {
                    break;
                }
                continue 'next;
            }
        }
        let mut len = 0;
        let mut found: Option<&Rc<Variable>> = None;
        for pv in prefixes.iter() {
            if v.name.len() >= pv.name.len() && v.name.len() > len && v.name[..pv.name.len()] == pv.name[..] {
                found = Some(pv);
                len = pv.name.len();
            }
        }
        if let Some(pv) = found {
            v.get_handler.set(pv.get_handler.get());
            // v[i].data = (uintptr_t) &v[i].name: prefix_var_name()
            v.data.set(v.index.get());
            v.flags.set(pv.flags.get());
            continue 'next;
        }
        if v.get_handler.get().is_none() {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "unknown \"{}\" variable", B(&v.name));
            return Err(ConfError::Logged);
        }
    }
    // build the hash of non-indexed / all variables (NOHASH excluded)
    let mut names: Vec<HashKey<Rc<Variable>>> = Vec::new();
    for av in keys.iter() {
        if av.flags.get() & NGX_HTTP_VAR_NOHASH != 0 {
            continue;
        }
        names.push(HashKey { key: av.name.clone(), key_hash: hash_key(&av.name), value: av.clone() });
    }
    let (max_size, bucket_size) = {
        let m = cmcf.borrow();
        (*m.variables_hash_max_size as usize, *m.variables_hash_bucket_size as usize)
    };
    let hinit = HashInit { name: "variables_hash", max_size, bucket_size, log: &cf.log };
    let h = Hash::init(&hinit, names).map_err(|e| {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
        ConfError::Logged
    })?;
    let mut m = cmcf.borrow_mut();
    m.variables_hash = Some(h);
    m.variables_keys = None;
    VAR_NAMES.with(|n| *n.borrow_mut() = m.variables.iter().map(|v| v.name.clone()).collect());
    Ok(())
}

/// Register a list of static variable definitions.
pub fn add_variables(cf: &mut Conf, defs: &[VarDef]) -> ConfResult {
    for d in defs {
        let v = add_variable(cf, d.name.as_bytes(), d.flags)?;
        v.get_handler.set(d.get);
        v.set_handler.set(d.set);
        v.data.set(d.data);
    }
    Ok(())
}

// --- regex with named captures ------------------------------------------------

pub struct HttpRegex {
    pub regex: Rc<Regex>,
    pub ncaptures: usize,
    /// (capture index, variable index)
    pub variables: Vec<(usize, usize)>,
    pub name: Vec<u8>,
}

/// ngx_http_regex_compile
pub fn regex_compile(cf: &mut Conf, pattern: &[u8], options: u32) -> Result<Rc<HttpRegex>, ConfError> {
    let re = match Regex::compile(pattern, options) {
        Ok(r) => r,
        Err(e) => return Err(cf.emerg(format_args!("{}", e))),
    };
    let cmcf = core_main_conf(cf);
    {
        let mut m = cmcf.borrow_mut();
        if re.captures > m.ncaptures {
            m.ncaptures = re.captures;
        }
    }
    let mut variables = Vec::new();
    for (name, idx) in re.names.iter() {
        let v = add_variable(cf, name, NGX_HTTP_VAR_CHANGEABLE)?;
        v.get_handler.set(Some(variable_not_found));
        let vi = get_variable_index(cf, name)?;
        let _ = v;
        variables.push((*idx, vi));
    }
    Ok(Rc::new(HttpRegex { ncaptures: re.captures, regex: re, variables, name: pattern.to_vec() }))
}

/// ngx_http_regex_exec: NGX_OK on match (captures stored), NGX_DECLINED on no match, NGX_ERROR.
///
/// The captures and their subject go to the request's own arrays, reused
/// from match to match (C allocates r->captures once per request); the
/// subject may be borrowed from anything but them and r->variables.
pub fn regex_exec(r: &R, re: &Rc<HttpRegex>, s: &[u8]) -> i64 {
    let cmcf = r.cmcf();
    let ncaptures = cmcf.borrow().ncaptures;
    if re.ncaptures > 0 || !re.variables.is_empty() || ncaptures > 0 {
        // full exec with captures
        let n = match re.regex.exec_into(s, &mut r.captures.borrow_mut()) {
            None => return NGX_DECLINED,
            Some(n) => n,
        };
        r.ncaptures.set(n * 2);
        {
            let mut data = r.captures_data.borrow_mut();
            data.clear();
            data.extend_from_slice(s);
        }
        if !re.variables.is_empty() {
            let nvars = cmcf.borrow().variables.len();
            let caps = r.captures.borrow();
            let mut vars = r.variables.borrow_mut();
            if vars.len() < nvars {
                vars.resize(nvars, VariableValue::default());
            }
            for (cap, vi) in re.variables.iter() {
                if *vi >= vars.len() {
                    continue;
                }
                // the value of the named capture, its buffer reused
                let vv = &mut vars[*vi];
                vv.data.clear();
                if *cap < n {
                    let (a, b) = (caps[2 * cap], caps[2 * cap + 1]);
                    if a >= 0 {
                        vv.data.extend_from_slice(&s[a as usize..b as usize]);
                    }
                }
                vv.valid = true;
                vv.no_cacheable = false;
                vv.not_found = false;
                vv.escape = false;
            }
        }
        return NGX_OK;
    }
    if re.regex.is_match(s) {
        NGX_OK
    } else {
        NGX_DECLINED
    }
}

pub fn variable_not_found(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    v.not_found = true;
    NGX_OK
}

// --- core variables ----------------------------------------------------------

fn set_str(v: &mut VariableValue, s: &[u8]) {
    v.data = s.to_vec();
    v.valid = true;
}

/// A value made already: set without a copy
fn set_owned(v: &mut VariableValue, s: Vec<u8>) {
    v.data = s;
    v.valid = true;
}

/// A number as the value (ngx_sprintf() "%ui", "%O", "%uA", ...)
fn set_uint(v: &mut VariableValue, n: u64) {
    v.data.clear();
    push_u64(&mut v.data, n);
    v.valid = true;
}

/// A signed number as the value (ngx_sprintf() "%i", "%O")
fn set_int(v: &mut VariableValue, n: i64) {
    v.data.clear();
    push_i64(&mut v.data, n);
    v.valid = true;
}

/// Milliseconds as seconds with three decimals ("%T.%03M")
fn set_msec(v: &mut VariableValue, sec: i64, msec: u64) {
    v.data.clear();
    push_i64(&mut v.data, sec);
    v.data.push(b'.');
    push_u64_pad(&mut v.data, msec, 3);
    v.valid = true;
}

/// The decimal digits of `n` appended to `buf`, as ngx_sprintf() writes an
/// unsigned number, without format!() and its String
pub fn push_u64(buf: &mut Vec<u8>, n: u64) {
    push_u64_pad(buf, n, 1);
}

/// The decimal digits of `n`, zero-padded to `width` ("%03ui"); a number
/// is never cut to the width
pub fn push_u64_pad(buf: &mut Vec<u8>, mut n: u64, width: usize) {
    let mut tmp = [b'0'; 20];
    let mut i = tmp.len();

    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;

        if n == 0 {
            break;
        }
    }

    let width = width.min(tmp.len());

    if tmp.len() - i < width {
        i = tmp.len() - width;
    }

    buf.extend_from_slice(&tmp[i..]);
}

/// The decimal digits of a signed `n`, "-" first if negative
pub fn push_i64(buf: &mut Vec<u8>, n: i64) {
    if n < 0 {
        buf.push(b'-');
    }

    push_u64(buf, n.unsigned_abs());
}

fn var_host(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    {
        let hin = r.headers_in.borrow();
        if !hin.server.is_empty() {
            set_str(v, &hin.server);
            return NGX_OK;
        }
    }
    let cscf = r.cscf();
    set_str(v, &cscf.borrow().server_name);
    NGX_OK
}

fn var_remote_addr(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, &r.connection.addr_text.borrow());
    NGX_OK
}

fn var_binary_remote_addr(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    // the bytes of SockAddr::ip_bytes(), from the address itself
    match &*r.connection.sockaddr.borrow() {
        ngx_core::inet::SockAddr::V4(a) => set_str(v, &a.ip().octets()),
        ngx_core::inet::SockAddr::V6(a) => set_str(v, &a.ip().octets()),
        ngx_core::inet::SockAddr::Unix(_) => set_str(v, b""),
    }
    NGX_OK
}

fn var_remote_port(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let p = r.connection.sockaddr.borrow().port();
    if p > 0 {
        set_uint(v, p as u64);
    } else {
        set_str(v, b"");
    }
    NGX_OK
}

fn var_server_addr(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    match r.connection.local_sockaddr() {
        Some(a) => set_owned(v, a.addr_text()),
        None => return NGX_ERROR,
    }
    NGX_OK
}

fn var_server_port(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    match r.connection.local_sockaddr() {
        Some(a) => set_uint(v, a.port() as u64),
        None => return NGX_ERROR,
    }
    NGX_OK
}

fn var_scheme(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    if r.connection.ssl.borrow().is_some() {
        set_str(v, b"https");
    } else {
        set_str(v, b"http");
    }
    NGX_OK
}

fn var_https(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    if r.connection.ssl.borrow().is_some() {
        set_str(v, b"on");
    } else {
        set_str(v, b"");
    }
    NGX_OK
}

fn var_request_uri(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    // ngx_http_variable_request: r->unparsed_uri.data is NULL until the
    // request line is parsed
    let m = r.main();
    let u = m.unparsed_uri.borrow();
    if u.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    set_str(v, &u);
    NGX_OK
}

fn var_uri(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, &r.uri.borrow());
    NGX_OK
}

fn var_args(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    // ngx_http_variable_request: r->args.data is set only for arguments
    // after "?" (ngx_http_process_request_uri: r->uri_end > r->args_start)
    let a = r.args.borrow();
    if a.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    set_str(v, &a);
    NGX_OK
}

fn var_is_args(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    if r.args.borrow().is_empty() {
        set_str(v, b"");
    } else {
        set_str(v, b"?");
    }
    NGX_OK
}

fn var_request(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let m = r.main();
    let rl = m.request_line.borrow();
    if rl.is_empty() {
        if let Some(l) = m.partial_request_line() {
            set_owned(v, l);
            return NGX_OK;
        }
    }
    set_str(v, &rl);
    NGX_OK
}

fn var_request_method(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let m = r.main();
    let mn = m.method_name.borrow();
    if mn.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    set_str(v, &mn);
    NGX_OK
}

fn var_server_protocol(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, &r.http_protocol.borrow());
    NGX_OK
}

fn var_server_name(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let cscf = r.cscf();
    set_str(v, &cscf.borrow().server_name);
    NGX_OK
}

fn var_document_root(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let clcf = r.clcf();
    let (root, script) = {
        let c = clcf.borrow();
        (c.root.clone(), c.root_script.clone())
    };
    match script {
        None => set_str(v, &root),
        Some(s) => {
            let mut p = match crate::script::complex_value(r, &s) {
                Ok(p) => p,
                Err(_) => return NGX_ERROR,
            };
            if p.first() != Some(&b'/') {
                let mut full = ngx_core::cycle::cycle().prefix.clone();
                full.extend_from_slice(&p);
                p = full;
            }
            set_str(v, &p);
        }
    }
    NGX_OK
}

fn var_realpath_root(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let clcf = r.clcf();
    let (root, script) = {
        let c = clcf.borrow();
        (c.root.clone(), c.root_script.clone())
    };
    let mut path = match script {
        None => root,
        Some(s) => match crate::script::complex_value(r, &s) {
            Ok(p) => p,
            Err(_) => return NGX_ERROR,
        },
    };
    if path.first() != Some(&b'/') {
        let mut full = ngx_core::cycle::cycle().prefix.clone();
        full.extend_from_slice(&path);
        path = full;
    }
    match std::fs::canonicalize(ngx_core::os::path(&path)) {
        Ok(p) => {
            use std::os::unix::ffi::OsStrExt;
            set_str(v, p.as_os_str().as_bytes());
        }
        Err(e) => {
            ngx_log_error!(NGX_LOG_CRIT, r.connection.log, e.raw_os_error(), "realpath() \"{}\" failed", B(&path));
            return NGX_ERROR;
        }
    }
    NGX_OK
}

fn var_request_filename(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    match map_uri_to_path(r, 0) {
        Some((p, _)) => set_str(v, &p),
        None => return NGX_ERROR,
    }
    NGX_OK
}

fn var_remote_user(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let rc = auth_basic_user(r);
    if rc == NGX_DECLINED {
        v.not_found = true;
        return NGX_OK;
    }
    if rc == NGX_ERROR {
        return NGX_ERROR;
    }
    set_str(v, &r.headers_in.borrow().user);
    NGX_OK
}

fn var_bytes_sent(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_uint(v, r.connection.sent.get());
    NGX_OK
}

fn var_body_bytes_sent(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let sent = r.connection.sent.get() as i64 - r.header_size.get() as i64;
    let sent = if sent < 0 { 0 } else { sent };
    set_int(v, sent);
    NGX_OK
}

fn var_pipe(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, if r.pipeline.get() { b"p" } else { b"." });
    NGX_OK
}

fn var_request_completion(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, if r.request_complete.get() { b"OK" } else { b"" });
    NGX_OK
}

fn var_request_body(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let rb = r.request_body.borrow().clone();
    let rb = match rb {
        Some(rb) => rb,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };
    let b = rb.borrow();
    if b.bufs.is_empty() || b.temp_file.is_some() {
        v.not_found = true;
        return NGX_OK;
    }
    let mut data = Vec::new();
    for buf in b.bufs.iter() {
        if let ngx_core::buf::BufData::Memory(m) = &buf.data {
            data.extend_from_slice(&m[buf.pos..buf.last]);
        }
    }
    set_str(v, &data);
    NGX_OK
}

fn var_request_body_file(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let rb = r.request_body.borrow().clone();
    match rb.and_then(|rb| rb.borrow().temp_file.as_ref().map(|t| t.name.clone())) {
        Some(name) => set_str(v, &name),
        None => v.not_found = true,
    }
    NGX_OK
}

fn var_request_length(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_int(v, r.request_length.get());
    NGX_OK
}

fn var_request_time(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let (sec, msec) = ngx_core::times::with_cached(|t| (t.sec, t.msec));
    let ms = (sec - r.start_sec.get()) * 1000 + (msec as i64 - r.start_msec.get() as i64);
    let ms = ms.max(0);
    set_msec(v, ms / 1000, (ms % 1000) as u64);
    NGX_OK
}

fn var_request_id(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let mut bytes = [0u8; 16];
    if openssl::rand::rand_bytes(&mut bytes).is_err() {
        return NGX_ERROR;
    }
    let _ = r;
    set_owned(v, ngx_core::string::hex_string(&bytes));
    NGX_OK
}

fn var_request_port(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    // C's ngx_http_variable_request_port: numeric port parsed from the
    // Host header. When Host had no `:port`, the port stays 0 and the
    // variable emits nothing.
    let p = r.port.get();
    if p == 0 {
        v.data = Vec::new();
        v.valid = true;
        return NGX_OK;
    }
    set_uint(v, p as u64);
    NGX_OK
}

fn var_is_request_port(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    // Emits `:` when a port is present so `$is_request_port$request_port`
    // renders as `:8080` when needed and empty otherwise
    // (ngx_http_variable_null_value).
    if r.port.get() == 0 {
        set_str(v, b"");
        return NGX_OK;
    }
    set_str(v, b":");
    NGX_OK
}

fn var_status(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let status = if r.err_status.get() != 0 {
        r.err_status.get()
    } else {
        let s = r.headers_out.borrow().status;
        if s != 0 {
            s
        } else if r.http_version.get() == NGX_HTTP_VERSION_9 {
            9
        } else {
            0
        }
    };
    if status >= 0 {
        // "%03ui"
        v.data.clear();
        push_u64_pad(&mut v.data, status as u64, 3);
        v.valid = true;
    } else {
        set_str(v, format!("{:03}", status).as_bytes());
    }
    NGX_OK
}

fn var_connection(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_uint(v, r.connection.number);
    NGX_OK
}

fn var_connection_requests(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_uint(v, r.connection.requests.get());
    NGX_OK
}

fn var_connection_time(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    // Both timestamps are wall-clock ms since epoch (connection.start_msec
    // is set from cached sec*1000 + msec). current_msec() is MONOTONIC and
    // cannot be subtracted from that. Use the cached wall time.
    let now_ms = ngx_core::times::with_cached(|t| t.sec as u64 * 1000 + t.msec);
    let ms = now_ms.saturating_sub(r.connection.start_msec.get());
    set_msec(v, (ms / 1000) as i64, ms % 1000);
    NGX_OK
}

fn var_nginx_version(_r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, ngx_core::NGINX_VERSION.as_bytes());
    NGX_OK
}

fn var_hostname(_r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, &ngx_core::cycle::cycle().hostname);
    NGX_OK
}

fn var_pid(_r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_int(v, ngx_core::log::pid() as i64);
    NGX_OK
}

fn var_msec(_r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let (sec, msec) = ngx_core::times::with_cached(|t| (t.sec, t.msec));
    set_msec(v, sec, msec);
    NGX_OK
}

fn var_time_iso8601(_r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, ngx_core::times::cached_http_log_iso8601().as_bytes());
    NGX_OK
}

fn var_time_local(_r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, ngx_core::times::cached_http_log_time().as_bytes());
    NGX_OK
}

fn var_limit_rate(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let clcf = r.clcf();
    let rate = if r.limit_rate_set.get() { r.limit_rate.get() } else { crate::script::complex_value_size(r, &clcf.borrow().limit_rate, 0) };
    set_uint(v, rate as u64);
    NGX_OK
}

fn set_limit_rate(r: &R, v: &mut VariableValue, _d: usize) {
    match ngx_core::parse::parse_size(&v.data) {
        Some(s) => {
            r.limit_rate.set(s);
            r.limit_rate_set.set(true);
        }
        None => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid $limit_rate \"{}\"", B(&v.data));
        }
    }
}

fn var_content_length(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let hin = r.headers_in.borrow();
    if let Some(h) = &hin.content_length {
        set_str(v, &h.value.borrow());
    } else if r.reading_body.get() {
        v.not_found = true;
        v.no_cacheable = true;
    } else if hin.content_length_n >= 0 {
        set_int(v, hin.content_length_n);
    } else if hin.chunked {
        // ngx_http_variable_content_length: known once the body is read
        v.not_found = true;
        v.no_cacheable = true;
    } else {
        v.not_found = true;
    }
    NGX_OK
}

// The ngx_table_elt_t lists ngx_http_variable_header() and
// ngx_http_variable_cookies() read: offsetof(ngx_http_request_t, ...) in C.
const HEADERS_IN_HOST: usize = 0;
const HEADERS_IN_USER_AGENT: usize = 1;
const HEADERS_IN_REFERER: usize = 2;
const HEADERS_IN_VIA: usize = 3;
const HEADERS_IN_X_FORWARDED_FOR: usize = 4;
const HEADERS_IN_COOKIE: usize = 5;
const HEADERS_IN_CONTENT_TYPE: usize = 6;
const HEADERS_OUT_CACHE_CONTROL: usize = 7;
const HEADERS_OUT_LINK: usize = 8;

/// `*(ngx_table_elt_t **) ((char *) r + data)` and its h->next chain,
/// lent to `f`.
fn with_variable_header_lines<T>(r: &R, data: usize, f: impl FnOnce(&[Header]) -> T) -> T {
    match data {
        HEADERS_IN_HOST => f(r.headers_in.borrow().host.as_slice()),
        HEADERS_IN_USER_AGENT => f(&r.headers_in.borrow().user_agent),
        HEADERS_IN_REFERER => f(&r.headers_in.borrow().referer),
        HEADERS_IN_VIA => f(&r.headers_in.borrow().via),
        HEADERS_IN_X_FORWARDED_FOR => f(&r.headers_in.borrow().x_forwarded_for),
        HEADERS_IN_COOKIE => f(&r.headers_in.borrow().cookie),
        HEADERS_IN_CONTENT_TYPE => f(&r.headers_in.borrow().content_type),
        HEADERS_OUT_CACHE_CONTROL => f(&r.headers_out.borrow().cache_control),
        HEADERS_OUT_LINK => f(&r.headers_out.borrow().link),
        _ => f(&[]),
    }
}

/// ngx_http_variable_header
fn variable_header(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    variable_headers_internal(r, v, data, b',')
}

/// ngx_http_variable_cookies
fn variable_cookies(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    variable_headers_internal(r, v, data, b';')
}

/// ngx_http_variable_headers_internal
fn variable_headers_internal(r: &R, v: &mut VariableValue, data: usize, sep: u8) -> i64 {
    match with_variable_header_lines(r, data, |h| join_header_lines(h, sep)) {
        Some(value) => {
            v.data = value;
            v.valid = true;
            v.no_cacheable = false;
            v.not_found = false;
        }
        None => v.not_found = true,
    }
    NGX_OK
}

/// The value of ngx_http_variable_headers_internal(): the lines with a
/// nonzero hash joined with "<sep> ", None (not found) if there are none.
fn join_header_lines(h: &[Header], sep: u8) -> Option<Vec<u8>> {
    let mut len = 0;
    for th in h.iter() {
        if th.hash.get() == 0 {
            continue;
        }
        len += th.value.borrow().len() + 2;
    }
    if len == 0 {
        return None;
    }
    len -= 2;
    if h.len() == 1 {
        return Some(h[0].value.borrow().clone());
    }
    let mut p = Vec::with_capacity(len);
    for th in h.iter() {
        if th.hash.get() == 0 {
            continue;
        }
        p.extend_from_slice(&th.value.borrow());
        if p.len() == len {
            break;
        }
        p.push(sep);
        p.push(b' ');
    }
    Some(p)
}

/// ngx_http_variable_unknown_header: the headers named as `var` without its
/// `prefix` bytes (letters lowercased, '-' read as '_'), joined with ", ".
pub fn variable_unknown_header(v: &mut VariableValue, var: &[u8], headers: &[Header], prefix: usize) -> i64 {
    let want = &var[prefix..];
    let matches = |h: &Header| {
        h.hash.get() != 0
            && h.key.len() == want.len()
            && h.key.iter().zip(want.iter()).all(|(&c, &w)| {
                let ch = if c.is_ascii_uppercase() {
                    c | 0x20
                } else if c == b'-' {
                    b'_'
                } else {
                    c
                };
                ch == w
            })
    };
    // the length of the value first, then the value in a buffer of it
    let mut found = 0;
    let mut len = 0;
    for h in headers.iter().filter(|h| matches(h)) {
        len += h.value.borrow().len() + 2;
        found += 1;
    }
    if found == 0 {
        v.not_found = true;
        return NGX_OK;
    }
    len -= 2;
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    let mut p = Vec::with_capacity(len);
    for (i, h) in headers.iter().filter(|h| matches(h)).enumerate() {
        if i > 0 {
            p.extend_from_slice(b", ");
        }
        p.extend_from_slice(&h.value.borrow());
    }
    v.data = p;
    NGX_OK
}

fn var_cookie_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    with_prefix_var_name(r, d, |name| {
        let name = &name["cookie_".len()..];
        let hin = r.headers_in.borrow();
        let vals: Vec<std::cell::Ref<'_, Vec<u8>>> = hin.cookie.iter().map(|h| h.value.borrow()).collect();
        let refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();
        match crate::parse::parse_multi_header_lines(&refs, name, b';') {
            Some(val) => set_str(v, &val),
            None => v.not_found = true,
        }
    });
    NGX_OK
}

fn var_arg_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    with_prefix_var_name(r, d, |name| {
        let name = &name["arg_".len()..];
        let args = r.args.borrow();
        match crate::parse::arg(&args, name) {
            Some(val) => set_str(v, val),
            None => v.not_found = true,
        }
    });
    NGX_OK
}

/// ngx_http_variable_unknown_header_in
fn var_http_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    with_prefix_var_name(r, d, |name| variable_unknown_header(v, name, &r.headers_in.borrow().headers, "http_".len()))
}

/// ngx_http_variable_unknown_header_out
fn var_sent_http_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    with_prefix_var_name(r, d, |name| variable_unknown_header(v, name, &r.headers_out.borrow().headers, "sent_http_".len()))
}

/// ngx_http_variable_unknown_trailer_out
fn var_sent_trailer_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    with_prefix_var_name(r, d, |name| variable_unknown_header(v, name, &r.headers_out.borrow().trailers, "sent_trailer_".len()))
}

/// ngx_http_variable_sent_content_type
fn var_sent_content_type(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let ho = r.headers_out.borrow();
    if !ho.content_type.is_empty() {
        set_str(v, &ho.content_type);
    } else {
        v.not_found = true;
    }
    NGX_OK
}

/// ngx_http_variable_sent_content_length
fn var_sent_content_length(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let ho = r.headers_out.borrow();
    if let Some(h) = &ho.content_length {
        set_str(v, &h.value.borrow());
        return NGX_OK;
    }
    if ho.content_length_n >= 0 {
        set_int(v, ho.content_length_n);
        return NGX_OK;
    }
    v.not_found = true;
    NGX_OK
}

/// ngx_http_variable_sent_location
fn var_sent_location(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let ho = r.headers_out.borrow();
    if let Some(h) = &ho.location {
        set_str(v, &h.value.borrow());
        return NGX_OK;
    }
    variable_unknown_header(v, b"sent_http_location", &ho.headers, "sent_http_".len())
}

/// ngx_http_variable_sent_last_modified
fn var_sent_last_modified(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let ho = r.headers_out.borrow();
    if let Some(h) = &ho.last_modified {
        set_str(v, &h.value.borrow());
        return NGX_OK;
    }
    if ho.last_modified_time >= 0 {
        set_str(v, ngx_core::times::http_time(ho.last_modified_time).as_bytes());
        return NGX_OK;
    }
    v.not_found = true;
    NGX_OK
}

/// ngx_http_variable_sent_connection
fn var_sent_connection(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let p: &[u8] = if r.headers_out.borrow().status == NGX_HTTP_SWITCHING_PROTOCOLS {
        b"upgrade"
    } else if r.keepalive.get() {
        b"keep-alive"
    } else {
        b"close"
    };
    set_str(v, p);
    NGX_OK
}

/// ngx_http_variable_sent_keep_alive
fn var_sent_keep_alive(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    if r.keepalive.get() {
        let clcf = r.clcf();
        let kh = *clcf.borrow().keepalive_header;
        if kh != 0 {
            v.data.clear();
            v.data.extend_from_slice(b"timeout=");
            push_i64(&mut v.data, kh as i64);
            v.valid = true;
            return NGX_OK;
        }
    }
    v.not_found = true;
    NGX_OK
}

/// ngx_http_variable_sent_transfer_encoding
fn var_sent_transfer_encoding(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    if r.chunked.get() {
        set_str(v, b"chunked");
    } else {
        v.not_found = true;
    }
    NGX_OK
}

fn var_proxy_protocol_addr(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let pp = r.connection.proxy_protocol.borrow().clone();
    match pp.and_then(|p| p.downcast::<ngx_core::proxy_protocol::ProxyProtocol>().ok()) {
        Some(p) => match d {
            0 => set_str(v, &p.src_addr),
            1 => set_str(v, &p.dst_addr),
            2 => set_uint(v, p.src_port as u64),
            _ => set_uint(v, p.dst_port as u64),
        },
        None => v.not_found = true,
    }
    NGX_OK
}

fn var_proxy_protocol_tlv(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let name = prefix_var_name(r, d);
    let tlv = &name["proxy_protocol_tlv_".len()..];
    let pp = r.connection.proxy_protocol.borrow().clone();
    match pp.and_then(|p| p.downcast::<ngx_core::proxy_protocol::ProxyProtocol>().ok()) {
        Some(p) => match ngx_core::proxy_protocol::get_tlv(&p, &r.connection.log, tlv) {
            Ok(Some(val)) => set_owned(v, val),
            Ok(None) => v.not_found = true,
            Err(()) => return NGX_ERROR,
        },
        None => v.not_found = true,
    }
    NGX_OK
}

fn var_tcpinfo(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    use std::os::fd::AsFd;

    let ti = match ngx_core::fd::get(r.connection.fd.get()) {
        Ok(s) => ngx_sys::os::tcp_info(s.as_fd()),
        Err(e) => Err(e),
    };
    let ti = match ti {
        Ok(ti) => ti,
        Err(_) => {
            v.not_found = true;
            return NGX_OK;
        }
    };
    let val = match d {
        0 => ti.rtt,
        1 => ti.rttvar,
        2 => ti.snd_cwnd,
        _ => ti.rcv_space,
    };
    set_uint(v, val as u64);
    NGX_OK
}

pub static CORE_VARIABLES: &[VarDef] = &[
    VarDef { name: "http_host", set: None, get: Some(variable_header), data: HEADERS_IN_HOST, flags: 0 },
    VarDef { name: "http_user_agent", set: None, get: Some(variable_header), data: HEADERS_IN_USER_AGENT, flags: 0 },
    VarDef { name: "http_referer", set: None, get: Some(variable_header), data: HEADERS_IN_REFERER, flags: 0 },
    VarDef { name: "http_via", set: None, get: Some(variable_header), data: HEADERS_IN_VIA, flags: 0 },
    VarDef { name: "http_x_forwarded_for", set: None, get: Some(variable_header), data: HEADERS_IN_X_FORWARDED_FOR, flags: 0 },
    VarDef { name: "http_cookie", set: None, get: Some(variable_cookies), data: HEADERS_IN_COOKIE, flags: 0 },
    VarDef { name: "content_length", set: None, get: Some(var_content_length), data: 0, flags: 0 },
    VarDef { name: "content_type", set: None, get: Some(variable_header), data: HEADERS_IN_CONTENT_TYPE, flags: 0 },
    VarDef { name: "host", set: None, get: Some(var_host), data: 0, flags: 0 },
    VarDef { name: "binary_remote_addr", set: None, get: Some(var_binary_remote_addr), data: 0, flags: 0 },
    VarDef { name: "remote_addr", set: None, get: Some(var_remote_addr), data: 0, flags: 0 },
    VarDef { name: "remote_port", set: None, get: Some(var_remote_port), data: 0, flags: 0 },
    VarDef { name: "proxy_protocol_addr", set: None, get: Some(var_proxy_protocol_addr), data: 0, flags: 0 },
    VarDef { name: "proxy_protocol_port", set: None, get: Some(var_proxy_protocol_addr), data: 2, flags: 0 },
    VarDef { name: "proxy_protocol_server_addr", set: None, get: Some(var_proxy_protocol_addr), data: 1, flags: 0 },
    VarDef { name: "proxy_protocol_server_port", set: None, get: Some(var_proxy_protocol_addr), data: 3, flags: 0 },
    VarDef { name: "proxy_protocol_tlv_", set: None, get: Some(var_proxy_protocol_tlv), data: 0, flags: NGX_HTTP_VAR_PREFIX },
    VarDef { name: "server_addr", set: None, get: Some(var_server_addr), data: 0, flags: 0 },
    VarDef { name: "server_port", set: None, get: Some(var_server_port), data: 0, flags: 0 },
    VarDef { name: "server_protocol", set: None, get: Some(var_server_protocol), data: 0, flags: 0 },
    VarDef { name: "scheme", set: None, get: Some(var_scheme), data: 0, flags: 0 },
    VarDef { name: "https", set: None, get: Some(var_https), data: 0, flags: 0 },
    VarDef { name: "request_uri", set: None, get: Some(var_request_uri), data: 0, flags: 0 },
    VarDef { name: "uri", set: None, get: Some(var_uri), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "document_uri", set: None, get: Some(var_uri), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "request", set: None, get: Some(var_request), data: 0, flags: 0 },
    VarDef { name: "document_root", set: None, get: Some(var_document_root), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "realpath_root", set: None, get: Some(var_realpath_root), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "query_string", set: None, get: Some(var_args), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "args", set: Some(set_args), get: Some(var_args), data: 0, flags: NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "is_args", set: None, get: Some(var_is_args), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "request_filename", set: None, get: Some(var_request_filename), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "server_name", set: None, get: Some(var_server_name), data: 0, flags: 0 },
    VarDef { name: "request_method", set: None, get: Some(var_request_method), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "remote_user", set: None, get: Some(var_remote_user), data: 0, flags: 0 },
    VarDef { name: "bytes_sent", set: None, get: Some(var_bytes_sent), data: 0, flags: 0 },
    VarDef { name: "body_bytes_sent", set: None, get: Some(var_body_bytes_sent), data: 0, flags: 0 },
    VarDef { name: "pipe", set: None, get: Some(var_pipe), data: 0, flags: 0 },
    VarDef { name: "request_completion", set: None, get: Some(var_request_completion), data: 0, flags: 0 },
    VarDef { name: "request_body", set: None, get: Some(var_request_body), data: 0, flags: 0 },
    VarDef { name: "request_body_file", set: None, get: Some(var_request_body_file), data: 0, flags: 0 },
    VarDef { name: "request_length", set: None, get: Some(var_request_length), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "request_time", set: None, get: Some(var_request_time), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "request_id", set: None, get: Some(var_request_id), data: 0, flags: 0 },
    VarDef { name: "request_port", set: None, get: Some(var_request_port), data: 0, flags: 0 },
    VarDef { name: "is_request_port", set: None, get: Some(var_is_request_port), data: 0, flags: 0 },
    VarDef { name: "status", set: None, get: Some(var_status), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "sent_http_content_type", set: None, get: Some(var_sent_content_type), data: 0, flags: 0 },
    VarDef { name: "sent_http_content_length", set: None, get: Some(var_sent_content_length), data: 0, flags: 0 },
    VarDef { name: "sent_http_location", set: None, get: Some(var_sent_location), data: 0, flags: 0 },
    VarDef { name: "sent_http_last_modified", set: None, get: Some(var_sent_last_modified), data: 0, flags: 0 },
    VarDef { name: "sent_http_connection", set: None, get: Some(var_sent_connection), data: 0, flags: 0 },
    VarDef { name: "sent_http_keep_alive", set: None, get: Some(var_sent_keep_alive), data: 0, flags: 0 },
    VarDef { name: "sent_http_transfer_encoding", set: None, get: Some(var_sent_transfer_encoding), data: 0, flags: 0 },
    VarDef { name: "sent_http_cache_control", set: None, get: Some(variable_header), data: HEADERS_OUT_CACHE_CONTROL, flags: 0 },
    VarDef { name: "sent_http_link", set: None, get: Some(variable_header), data: HEADERS_OUT_LINK, flags: 0 },
    VarDef { name: "sent_http_", set: None, get: Some(var_sent_http_prefix), data: 0, flags: NGX_HTTP_VAR_PREFIX },
    VarDef { name: "sent_trailer_", set: None, get: Some(var_sent_trailer_prefix), data: 0, flags: NGX_HTTP_VAR_PREFIX },
    VarDef { name: "limit_rate", set: Some(set_limit_rate), get: Some(var_limit_rate), data: 0, flags: NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "connection", set: None, get: Some(var_connection), data: 0, flags: 0 },
    VarDef { name: "connection_requests", set: None, get: Some(var_connection_requests), data: 0, flags: 0 },
    VarDef { name: "connection_time", set: None, get: Some(var_connection_time), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "nginx_version", set: None, get: Some(var_nginx_version), data: 0, flags: 0 },
    VarDef { name: "hostname", set: None, get: Some(var_hostname), data: 0, flags: 0 },
    VarDef { name: "pid", set: None, get: Some(var_pid), data: 0, flags: 0 },
    VarDef { name: "msec", set: None, get: Some(var_msec), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "time_iso8601", set: None, get: Some(var_time_iso8601), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "time_local", set: None, get: Some(var_time_local), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "tcpinfo_rtt", set: None, get: Some(var_tcpinfo), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "tcpinfo_rttvar", set: None, get: Some(var_tcpinfo), data: 1, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "tcpinfo_snd_cwnd", set: None, get: Some(var_tcpinfo), data: 2, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "tcpinfo_rcv_space", set: None, get: Some(var_tcpinfo), data: 3, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "http_", set: None, get: Some(var_http_prefix), data: 0, flags: NGX_HTTP_VAR_PREFIX },
    VarDef { name: "cookie_", set: None, get: Some(var_cookie_prefix), data: 0, flags: NGX_HTTP_VAR_PREFIX },
    VarDef { name: "arg_", set: None, get: Some(var_arg_prefix), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX },
];

/// ngx_http_variable_set_args: the arguments, and the request line's URI no
/// longer valid for them
fn set_args(r: &R, v: &mut VariableValue, _d: usize) {
    *r.args.borrow_mut() = std::mem::take(&mut v.data);
    r.valid_unparsed_uri.set(false);
}

/// ngx_http_variables_add_core_vars (preconfiguration of the core module).
pub fn core_variables_add(cf: &mut Conf) -> ConfResult {
    add_variables(cf, CORE_VARIABLES)
}

/// Set a variable value by index (used by "set" and similar).
pub fn set_indexed_variable(r: &R, index: usize, value: Vec<u8>) {
    let mut vars = r.variables.borrow_mut();
    if vars.len() <= index {
        vars.resize(index + 1, VariableValue::default());
    }
    vars[index] = VariableValue { data: value, valid: true, no_cacheable: false, not_found: false, escape: false };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(key: &str, value: &str) -> Header {
        TableElt::new(key.as_bytes(), value.as_bytes())
    }

    fn removed(key: &str, value: &str) -> Header {
        let e = h(key, value);
        e.hash.set(0);
        e
    }

    #[test]
    fn headers_internal_joins_lines() {
        assert_eq!(join_header_lines(&[], b';'), None);
        assert_eq!(join_header_lines(&[h("Cookie", "a=1")], b';'), Some(b"a=1".to_vec()));
        assert_eq!(join_header_lines(&[h("Cookie", "a=1"), h("Cookie", "b=2; c=3")], b';'), Some(b"a=1; b=2; c=3".to_vec()));
        let xff = [h("X-Forwarded-For", "10.0.0.1"), h("X-Forwarded-For", "10.0.0.2, 10.0.0.3")];
        assert_eq!(join_header_lines(&xff, b','), Some(b"10.0.0.1, 10.0.0.2, 10.0.0.3".to_vec()));
        // empty lines keep their separators, as the C copy loop does
        assert_eq!(join_header_lines(&[h("Cookie", ""), h("Cookie", "a=5"), h("Cookie", "")], b';'), Some(b"; a=5; ".to_vec()));
    }

    #[test]
    fn headers_internal_skips_removed_lines() {
        assert_eq!(join_header_lines(&[removed("Cache-Control", "a")], b','), None);
        assert_eq!(join_header_lines(&[removed("Cache-Control", "a"), h("Cache-Control", "b")], b','), Some(b"b".to_vec()));
        assert_eq!(join_header_lines(&[h("Cache-Control", "a"), removed("Cache-Control", "b")], b','), Some(b"a".to_vec()));
        let cc = [h("Cache-Control", "a"), removed("Cache-Control", "b"), h("Cache-Control", "c")];
        assert_eq!(join_header_lines(&cc, b','), Some(b"a, c".to_vec()));
    }

    #[test]
    fn unknown_header_matches_names() {
        let headers = [h("X-Foo", "one"), h("x-foo", "two"), h("X_FOO", "three"), h("X-Foo-Bar", "no"), removed("X-Foo", "gone")];
        let mut v = VariableValue::default();
        assert_eq!(variable_unknown_header(&mut v, b"sent_http_x_foo", &headers, "sent_http_".len()), NGX_OK);
        assert!(v.valid && !v.not_found);
        assert_eq!(v.data, b"one, two, three".to_vec());

        let mut v = VariableValue::default();
        variable_unknown_header(&mut v, b"http_x_foo_bar", &headers, "http_".len());
        assert_eq!(v.data, b"no".to_vec());

        let mut v = VariableValue::default();
        variable_unknown_header(&mut v, b"http_x_bar", &headers, "http_".len());
        assert!(v.not_found && !v.valid);
    }

    #[test]
    fn decimal_writers() {
        let mut b = Vec::new();
        push_u64(&mut b, 0);
        b.push(b' ');
        push_u64(&mut b, 1234567890123);
        b.push(b' ');
        push_u64(&mut b, u64::MAX);
        b.push(b' ');
        push_i64(&mut b, -42);
        b.push(b' ');
        push_i64(&mut b, i64::MIN);
        assert_eq!(b, format!("0 1234567890123 {} -42 {}", u64::MAX, i64::MIN).into_bytes());

        // "%03ui": padded, never cut
        for (n, s) in [(0u64, "000"), (7, "007"), (200, "200"), (1234, "1234")] {
            let mut b = Vec::new();
            push_u64_pad(&mut b, n, 3);
            assert_eq!(b, s.as_bytes());
        }

        let mut v = VariableValue::default();
        set_msec(&mut v, 1696000000, 5);
        assert_eq!(v.data, b"1696000000.005".to_vec());
        assert!(v.valid);
    }
}
