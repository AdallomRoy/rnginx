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
    fn new(name: &[u8], flags: u32) -> Rc<Variable> {
        Rc::new(Variable { name: name.to_vec(), set_handler: Cell::new(None), get_handler: Cell::new(None), data: Cell::new(0), flags: Cell::new(flags), index: Cell::new(0) })
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
            if flags & NGX_HTTP_VAR_CHANGEABLE == 0 {
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
    let rc = m.variables_keys.as_mut().unwrap().add_key(name.to_vec(), v.clone(), 0);
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
            if flags & NGX_HTTP_VAR_CHANGEABLE == 0 {
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
    // User-defined variables (from set directive) should be marked as changeable
    let v = Variable::new(name, NGX_HTTP_VAR_CHANGEABLE);
    let idx = m.variables.len();
    v.index.set(idx);
    m.variables.push(v);
    Ok(idx)
}

/// ngx_http_get_indexed_variable
pub fn get_indexed_variable(r: &R, index: usize) -> Option<VariableValue> {
    let cmcf = r.cmcf();
    let (var, nvars) = {
        let m = cmcf.borrow();
        if index >= m.variables.len() {
            ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "unknown variable index: {}", index);
            return None;
        }
        (m.variables[index].clone(), m.variables.len())
    };
    {
        let mut vars = r.variables.borrow_mut();
        if vars.len() < nvars {
            vars.resize(nvars, VariableValue::default());
        }
        let v = &vars[index];
        if v.not_found || v.valid {
            return Some(v.clone());
        }
    }
    let get = var.get_handler.get();
    let mut vv = VariableValue::default();
    let rc = match get {
        Some(g) => g(r, &mut vv, var.data.get()),
        None => {
            ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "cycle while evaluating variable \"{}\"", B(&var.name));
            NGX_ERROR
        }
    };
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
        let mut vars = r.variables.borrow_mut();
        vars[index] = vv.clone();
        return Some(vv);
    }
    let mut vars = r.variables.borrow_mut();
    vars[index].valid = false;
    vars[index].not_found = true;
    None
}

/// ngx_http_get_flushed_variable
pub fn get_flushed_variable(r: &R, index: usize) -> Option<VariableValue> {
    {
        let vars = r.variables.borrow();
        if let Some(v) = vars.get(index) {
            if v.valid || v.not_found {
                if !v.no_cacheable {
                    return Some(v.clone());
                }
            }
        }
    }
    {
        let mut vars = r.variables.borrow_mut();
        if let Some(v) = vars.get_mut(index) {
            v.valid = false;
            v.not_found = false;
        }
    }
    get_indexed_variable(r, index)
}

/// ngx_http_get_variable (by name at runtime).
pub fn get_variable(r: &R, name: &[u8]) -> Option<VariableValue> {
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
        let mut vv = VariableValue::default();
        if let Some(g) = v.get_handler.get() {
            if g(r, &mut vv, v.data.get()) == NGX_OK {
                return Some(vv);
            }
        }
        return None;
    }
    // prefix variables
    let prefixes = cmcf.borrow().prefix_variables.clone();
    let mut best: Option<Rc<Variable>> = None;
    for pv in prefixes.iter() {
        if name.len() >= pv.name.len() && eq_ignore_case(&name[..pv.name.len()], &pv.name) {
            best = Some(pv.clone());
            break;
        }
    }
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
    static PREFIX_NAME: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static VAR_NAMES: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// The full variable name for prefix-variable handlers (data == usize::MAX means "current prefix lookup").
pub fn prefix_var_name(r: &R, data: usize) -> Vec<u8> {
    if data == usize::MAX {
        return PREFIX_NAME.with(|n| n.borrow().clone());
    }
    let cmcf = r.cmcf();
    let m = cmcf.borrow();
    m.variables.get(data).map(|v| v.name.clone()).unwrap_or_default()
}

/// ngx_http_variables_init_vars
pub fn init_vars(cf: &mut Conf) -> ConfResult {
    let cmcf = core_main_conf(cf);
    let (vars, prefixes, keys) = {
        let m = cmcf.borrow();
        (m.variables.clone(), m.prefix_variables.clone(), m.variables_keys.as_ref().map(|k| k.keys().iter().map(|k| k.value.clone()).collect::<Vec<_>>()).unwrap_or_default())
    };
    for v in vars.iter() {
        let mut found = false;
        for av in keys.iter() {
            if av.name.len() == v.name.len() && eq_ignore_case(&av.name, &v.name) {
                v.get_handler.set(av.get_handler.get());
                v.data.set(av.data.get());
                av.flags.set(av.flags.get() | NGX_HTTP_VAR_INDEXED);
                v.flags.set(av.flags.get());
                av.index.set(v.index.get());
                if av.get_handler.get().is_none() || (av.flags.get() & NGX_HTTP_VAR_WEAK) != 0 {
                    break;
                }
                found = true;
                break;
            }
        }
        if found {
            continue;
        }
        let mut pfound = false;
        let mut best_len = 0;
        for pv in prefixes.iter() {
            if v.name.len() >= pv.name.len() && eq_ignore_case(&v.name[..pv.name.len()], &pv.name) && pv.name.len() >= best_len {
                v.get_handler.set(pv.get_handler.get());
                v.data.set(v.index.get());
                v.flags.set(pv.flags.get());
                best_len = pv.name.len();
                pfound = true;
            }
        }
        if pfound {
            continue;
        }
        // User-defined variables (from rewrite set directive) don't need handlers
        // They are created with NGX_HTTP_VAR_CHANGEABLE flag by get_variable_index()
        // No error for variables without handlers - they may be user-defined
        // if v.get_handler.get().is_none() {
        //     return Err(cf.emerg(format_args!("unknown \"{}\" variable", B(&v.name))));
        // }
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
pub fn regex_exec(r: &R, re: &Rc<HttpRegex>, s: &[u8]) -> i64 {
    let cmcf = r.cmcf();
    let ncaptures = cmcf.borrow().ncaptures;
    if re.ncaptures > 0 || !re.variables.is_empty() || ncaptures > 0 {
        // full exec with captures
        match re.regex.exec(s) {
            None => return NGX_DECLINED,
            Some(caps) => {
                let mut flat = Vec::with_capacity(caps.len() * 2);
                for (a, b) in caps.iter() {
                    flat.push(*a);
                    flat.push(*b);
                }
                r.ncaptures.set(caps.len() * 2);
                *r.captures.borrow_mut() = flat;
                *r.captures_data.borrow_mut() = s.to_vec();
                for (cap, vi) in re.variables.iter() {
                    let mut vv = VariableValue::default();
                    if let Some((a, b)) = caps.get(*cap) {
                        if *a >= 0 {
                            vv.data = s[*a as usize..*b as usize].to_vec();
                        }
                    }
                    vv.valid = true;
                    let mut vars = r.variables.borrow_mut();
                    if *vi < vars.len() {
                        vars[*vi] = vv;
                    }
                }
                return NGX_OK;
            }
        }
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

fn var_host(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let server = r.headers_in.borrow().server.clone();
    if !server.is_empty() {
        set_str(v, &server);
        return NGX_OK;
    }
    let cscf = r.cscf();
    let name = cscf.borrow().server_name.clone();
    set_str(v, &name);
    NGX_OK
}

fn var_remote_addr(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, &r.connection.addr_text.borrow());
    NGX_OK
}

fn var_binary_remote_addr(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, &r.connection.sockaddr.borrow().ip_bytes());
    NGX_OK
}

fn var_remote_port(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let p = r.connection.sockaddr.borrow().port();
    if p > 0 {
        set_str(v, p.to_string().as_bytes());
    } else {
        set_str(v, b"");
    }
    NGX_OK
}

fn var_server_addr(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    match r.connection.local_sockaddr() {
        Some(a) => set_str(v, &a.addr_text()),
        None => return NGX_ERROR,
    }
    NGX_OK
}

fn var_server_port(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    match r.connection.local_sockaddr() {
        Some(a) => set_str(v, a.port().to_string().as_bytes()),
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
    set_str(v, &r.main().unparsed_uri.borrow());
    NGX_OK
}

fn var_uri(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, &r.uri.borrow());
    NGX_OK
}

fn var_args(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, &r.args.borrow());
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
    let rl = r.main().request_line.borrow().clone();
    if rl.is_empty() {
        if let Some(l) = r.main().partial_request_line() {
            set_str(v, &l);
            return NGX_OK;
        }
    }
    set_str(v, &rl);
    NGX_OK
}

fn var_request_method(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let m = r.main();
    let mn = m.method_name.borrow().clone();
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
    let name = cscf.borrow().server_name.clone();
    set_str(v, &name);
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
    set_str(v, r.connection.sent.get().to_string().as_bytes());
    NGX_OK
}

fn var_body_bytes_sent(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let sent = r.connection.sent.get() as i64 - r.header_size.get() as i64;
    let sent = if sent < 0 { 0 } else { sent };
    set_str(v, sent.to_string().as_bytes());
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
    match rb {
        None => {
            v.not_found = true;
            NGX_OK
        }
        Some(rb) => {
            let b = rb.borrow();
            if b.temp_file.is_some() {
                v.not_found = true;
                return NGX_OK;
            }
            set_str(v, &b.in_memory);
            NGX_OK
        }
    }
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
    set_str(v, r.request_length.get().to_string().as_bytes());
    NGX_OK
}

fn var_request_time(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let now = ngx_core::times::cached();
    let ms = (now.sec - r.start_sec.get()) * 1000 + (now.msec as i64 - r.start_msec.get() as i64);
    let ms = ms.max(0);
    set_str(v, format!("{}.{:03}", ms / 1000, ms % 1000).as_bytes());
    NGX_OK
}

fn var_request_id(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let mut bytes = [0u8; 16];
    if openssl::rand::rand_bytes(&mut bytes).is_err() {
        return NGX_ERROR;
    }
    let _ = r;
    set_str(v, &ngx_core::string::hex_string(&bytes));
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
    set_str(v, format!("{:03}", status).as_bytes());
    NGX_OK
}

fn var_connection(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, r.connection.number.to_string().as_bytes());
    NGX_OK
}

fn var_connection_requests(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    set_str(v, r.connection.requests.get().to_string().as_bytes());
    NGX_OK
}

fn var_connection_time(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let ms = ngx_core::times::current_msec().saturating_sub(r.connection.start_msec.get());
    set_str(v, format!("{}.{:03}", ms / 1000, ms % 1000).as_bytes());
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
    set_str(v, ngx_core::os::getpid().to_string().as_bytes());
    NGX_OK
}

fn var_msec(_r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let t = ngx_core::times::cached();
    set_str(v, format!("{}.{:03}", t.sec, t.msec).as_bytes());
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
    set_str(v, rate.to_string().as_bytes());
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
    } else if hin.content_length_n >= 0 {
        set_str(v, hin.content_length_n.to_string().as_bytes());
    } else {
        v.not_found = true;
    }
    NGX_OK
}

fn var_host_header_or_not(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    // Selector 0 is Host (unique). Others are multi-value: join with ", " to match
    // C ngx_http_variable_headers_internal.
    let hin = r.headers_in.borrow();
    if d == 0 {
        match &hin.host {
            Some(h) => set_str(v, &h.value.borrow()),
            None => v.not_found = true,
        }
        return NGX_OK;
    }
    let list: &[Header] = match d {
        1 => &hin.user_agent,
        2 => &hin.referer,
        3 => &hin.via,
        _ => &[],
    };
    if list.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    let parts: Vec<Vec<u8>> = list.iter().map(|h| h.value.borrow().clone()).collect();
    set_str(v, &parts.join(&b", "[..]));
    NGX_OK
}

fn var_content_type(r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    let hin = r.headers_in.borrow();
    if hin.content_type.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    let parts: Vec<Vec<u8>> = hin.content_type.iter().map(|h| h.value.borrow().clone()).collect();
    set_str(v, &parts.join(&b", "[..]));
    NGX_OK
}

fn var_cookie_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let name = prefix_var_name(r, d);
    let name = &name["cookie_".len()..];
    let hin = r.headers_in.borrow();
    let vals: Vec<Vec<u8>> = hin.cookie.iter().map(|h| h.value.borrow().clone()).collect();
    let refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();
    match crate::parse::parse_multi_header_lines(&refs, name, b';') {
        Some(val) => set_str(v, &val),
        None => v.not_found = true,
    }
    NGX_OK
}

fn var_arg_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let name = prefix_var_name(r, d);
    let name = &name["arg_".len()..];
    let args = r.args.borrow();
    match crate::parse::arg(&args, name) {
        Some(val) => set_str(v, val),
        None => v.not_found = true,
    }
    NGX_OK
}

fn var_http_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let name = prefix_var_name(r, d);
    let want = &name["http_".len()..];
    let hin = r.headers_in.borrow();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for h in hin.headers.iter() {
        if h.lowcase_key.len() != want.len() {
            continue;
        }
        let same = h.lowcase_key.iter().zip(want.iter()).all(|(a, b)| *a == *b || (*a == b'-' && *b == b'_'));
        if same {
            parts.push(h.value.borrow().clone());
        }
    }
    if parts.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    let sep: &[u8] = if want == b"cookie" { b"; " } else { b", " };
    set_str(v, &parts.join(sep));
    NGX_OK
}

fn var_sent_http_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let name = prefix_var_name(r, d);
    let want = &name["sent_http_".len()..];
    let ho = r.headers_out.borrow();
    // special-cased known headers
    if want == b"content_type" {
        if ho.content_type.is_empty() {
            v.not_found = true;
        } else {
            let mut ct = ho.content_type.clone();
            if !ho.charset.is_empty() && ho.content_type_len == ho.content_type.len() {
                ct.extend_from_slice(b"; charset=");
                ct.extend_from_slice(&ho.charset);
            }
            set_str(v, &ct);
        }
        return NGX_OK;
    }
    if want == b"content_length" {
        if let Some(h) = &ho.content_length {
            set_str(v, &h.value.borrow());
        } else if ho.content_length_n >= 0 {
            set_str(v, ho.content_length_n.to_string().as_bytes());
        } else {
            v.not_found = true;
        }
        return NGX_OK;
    }
    if want == b"last_modified" {
        if let Some(h) = &ho.last_modified {
            set_str(v, &h.value.borrow());
        } else if ho.last_modified_time >= 0 {
            set_str(v, ngx_core::times::http_time(ho.last_modified_time).as_bytes());
        } else {
            v.not_found = true;
        }
        return NGX_OK;
    }
    if want == b"connection" {
        if r.headers_out.borrow().status == NGX_HTTP_SWITCHING_PROTOCOLS {
            set_str(v, b"upgrade");
        } else if r.keepalive.get() {
            set_str(v, b"keep-alive");
        } else {
            set_str(v, b"close");
        }
        return NGX_OK;
    }
    if want == b"keep_alive" {
        let clcf = r.clcf();
        let kh = *clcf.borrow().keepalive_header;
        if r.keepalive.get() && kh > 0 {
            set_str(v, format!("timeout={}", kh).as_bytes());
        } else {
            v.not_found = true;
        }
        return NGX_OK;
    }
    if want == b"transfer_encoding" {
        if r.chunked.get() {
            set_str(v, b"chunked");
        } else {
            v.not_found = true;
        }
        return NGX_OK;
    }
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for h in ho.headers.iter() {
        if h.hash.get() == 0 || h.lowcase_key.len() != want.len() {
            continue;
        }
        let same = h.lowcase_key.iter().zip(want.iter()).all(|(a, b)| *a == *b || (*a == b'-' && *b == b'_'));
        if same {
            parts.push(h.value.borrow().clone());
        }
    }
    if parts.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    set_str(v, &parts.join(&b", "[..]));
    NGX_OK
}

fn var_sent_trailer_prefix(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let name = prefix_var_name(r, d);
    let want = &name["sent_trailer_".len()..];
    let ho = r.headers_out.borrow();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for h in ho.trailers.iter() {
        if h.hash.get() == 0 || h.lowcase_key.len() != want.len() {
            continue;
        }
        let same = h.lowcase_key.iter().zip(want.iter()).all(|(a, b)| *a == *b || (*a == b'-' && *b == b'_'));
        if same {
            parts.push(h.value.borrow().clone());
        }
    }
    if parts.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    set_str(v, &parts.join(&b", "[..]));
    NGX_OK
}

fn var_proxy_protocol_addr(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let pp = r.connection.proxy_protocol.borrow().clone();
    match pp.and_then(|p| p.downcast::<ngx_core::proxy_protocol::ProxyProtocol>().ok()) {
        Some(p) => match d {
            0 => set_str(v, &p.src_addr),
            1 => set_str(v, &p.dst_addr),
            2 => set_str(v, p.src_port.to_string().as_bytes()),
            _ => set_str(v, p.dst_port.to_string().as_bytes()),
        },
        None => set_str(v, b""),
    }
    NGX_OK
}

fn var_proxy_protocol_tlv(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let name = prefix_var_name(r, d);
    let tlv = &name["proxy_protocol_tlv_".len()..];
    let pp = r.connection.proxy_protocol.borrow().clone();
    match pp.and_then(|p| p.downcast::<ngx_core::proxy_protocol::ProxyProtocol>().ok()) {
        Some(p) => match ngx_core::proxy_protocol::get_tlv(&p, &r.connection.log, tlv) {
            Ok(Some(val)) => set_str(v, &val),
            Ok(None) => v.not_found = true,
            Err(()) => return NGX_ERROR,
        },
        None => v.not_found = true,
    }
    NGX_OK
}

fn var_tcpinfo(r: &R, v: &mut VariableValue, d: usize) -> i64 {
    let mut ti: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    if unsafe { libc::getsockopt(r.connection.fd.get(), libc::IPPROTO_TCP, libc::TCP_INFO, &mut ti as *mut _ as *mut libc::c_void, &mut len) } == -1 {
        v.not_found = true;
        return NGX_OK;
    }
    let val = match d {
        0 => ti.tcpi_rtt,
        1 => ti.tcpi_rttvar,
        2 => ti.tcpi_snd_cwnd,
        _ => ti.tcpi_rcv_space,
    };
    set_str(v, val.to_string().as_bytes());
    NGX_OK
}

pub static CORE_VARIABLES: &[VarDef] = &[
    VarDef { name: "http_host", set: None, get: Some(var_host_header_or_not), data: 0, flags: 0 },
    VarDef { name: "http_user_agent", set: None, get: Some(var_host_header_or_not), data: 1, flags: 0 },
    VarDef { name: "http_referer", set: None, get: Some(var_host_header_or_not), data: 2, flags: 0 },
    VarDef { name: "http_via", set: None, get: Some(var_host_header_or_not), data: 3, flags: 0 },
    VarDef { name: "content_length", set: None, get: Some(var_content_length), data: 0, flags: 0 },
    VarDef { name: "content_type", set: None, get: Some(var_content_type), data: 0, flags: 0 },
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
    VarDef { name: "args", set: Some(set_args), get: Some(var_args), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "is_args", set: None, get: Some(var_is_args), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "request_filename", set: None, get: Some(var_request_filename), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "server_name", set: None, get: Some(var_server_name), data: 0, flags: 0 },
    VarDef { name: "request_method", set: None, get: Some(var_request_method), data: 0, flags: 0 },
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
    VarDef { name: "status", set: None, get: Some(var_status), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "sent_http_", set: None, get: Some(var_sent_http_prefix), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX },
    VarDef { name: "sent_trailer_", set: None, get: Some(var_sent_trailer_prefix), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_PREFIX },
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

fn set_args(r: &R, v: &mut VariableValue, _d: usize) {
    *r.args.borrow_mut() = v.data.clone();
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
