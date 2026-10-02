//! ngx_http_userid_filter_module: the user id cookie (port of
//! ngx_http_userid_filter_module.c).

use std::any::Any;
use std::cell::Cell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::request::{Header, VariableValue};
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_userid_filter_module");

const NGX_HTTP_USERID_OFF: u32 = 0;
const NGX_HTTP_USERID_LOG: u32 = 1;
const NGX_HTTP_USERID_V1: u32 = 2;
const NGX_HTTP_USERID_ON: u32 = 3;

const NGX_HTTP_USERID_COOKIE_OFF: u32 = 0x0002;
const NGX_HTTP_USERID_COOKIE_SECURE: u32 = 0x0004;
const NGX_HTTP_USERID_COOKIE_HTTPONLY: u32 = 0x0008;
const NGX_HTTP_USERID_COOKIE_SAMESITE: u32 = 0x0010;
const NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT: u32 = 0x0020;
const NGX_HTTP_USERID_COOKIE_SAMESITE_LAX: u32 = 0x0040;
const NGX_HTTP_USERID_COOKIE_SAMESITE_NONE: u32 = 0x0080;

/// NGX_CONF_BITMASK_SET
const NGX_CONF_BITMASK_SET: u32 = 1;

/// 31 Dec 2037 23:55:55 GMT
const NGX_HTTP_USERID_MAX_EXPIRES: i64 = 2145916555;

const EXPIRES: &[u8] = b"; expires=Thu, 31-Dec-37 23:55:55 GMT";

thread_local! {
    static START_VALUE: Cell<u32> = const { Cell::new(0) };
    static SEQUENCER_V1: Cell<u32> = const { Cell::new(1) };
    static SEQUENCER_V2: Cell<u32> = const { Cell::new(0x03030302) };

    /// ngx_http_userid_reset_index
    static RESET_INDEX: Cell<usize> = const { Cell::new(0) };
}

pub struct UserIdConf {
    pub enable: Val<u32>,
    pub flags: u32,

    pub service: Val<i64>,

    pub name: Val<Vec<u8>>,
    pub domain: Val<Vec<u8>>,
    pub path: Val<Vec<u8>>,
    pub p3p: Val<Vec<u8>>,

    pub expires: Val<i64>,

    pub mark: Val<u8>,
}

/// ngx_http_userid_ctx_t
struct UserIdCtx {
    uid_got: [u32; 4],
    uid_set: [u32; 4],
    cookie: Vec<u8>,
    reset: bool,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(UserIdConf {
        enable: Val::unset(),
        flags: 0,
        service: Val::unset(),
        name: Val::unset(),
        domain: Val::unset(),
        path: Val::unset(),
        p3p: Val::unset(),
        expires: Val::unset(),
        mark: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<UserIdConf>(prev).borrow();
    let mut c = conf_cell::<UserIdConf>(conf).borrow_mut();

    c.enable.merge(&p.enable, NGX_HTTP_USERID_OFF);

    // ngx_conf_merge_bitmask_value
    if c.flags == 0 {
        c.flags = if p.flags == 0 { NGX_CONF_BITMASK_SET | NGX_HTTP_USERID_COOKIE_OFF } else { p.flags };
    }

    c.name.merge(&p.name, b"uid".to_vec());
    c.domain.merge(&p.domain, Vec::new());
    c.path.merge(&p.path, b"; path=/".to_vec());
    c.p3p.merge(&p.p3p, Vec::new());

    // NGX_CONF_UNSET stays when nothing sets it
    c.service.merge(&p.service, -1);
    c.expires.merge(&p.expires, 0);

    c.mark.merge(&p.mark, 0);

    Ok(())
}

pub fn userid_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(userid_add_variables),
        postconfiguration: Some(userid_init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!("userid", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, enable, set_enum, &[("off", NGX_HTTP_USERID_OFF), ("log", NGX_HTTP_USERID_LOG), ("v1", NGX_HTTP_USERID_V1), ("on", NGX_HTTP_USERID_ON)]),
        ngx_core::cmd!("userid_service", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, service, set_num),
        ngx_core::cmd!("userid_name", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, name, set_str),
        ngx_core::cmd_fn!("userid_domain", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, userid_domain),
        ngx_core::cmd_fn!("userid_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, userid_path),
        ngx_core::cmd_fn!("userid_expires", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, userid_expires),
        ngx_core::cmd_fn!("userid_flags", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::Loc, userid_flags),
        ngx_core::cmd_fn!("userid_p3p", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, userid_p3p),
        ngx_core::cmd_fn!("userid_mark", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, userid_mark),
    ];
    let mut m = http_module_def("ngx_http_userid_filter_module", def, commands);
    m.init_process = Some(userid_init_worker);
    m
}

/// ngx_http_userid_filter
fn userid_filter(r: R, next: &HeaderFilter) -> Step {
    if !r.is_main() {
        return next(r);
    }

    let conf = r.loc_conf::<UserIdConf>(ctx_index());

    if *conf.borrow().enable < NGX_HTTP_USERID_V1 {
        return next(r);
    }

    let ctx = userid_get_uid(&r, &conf.borrow());

    if userid_set_uid(&r, &ctx, &conf.borrow()) == NGX_OK {
        return next(r);
    }

    Step::Ready(NGX_ERROR)
}

/// ngx_http_userid_got_variable
fn userid_got_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let r = r.main();
    let conf = r.loc_conf::<UserIdConf>(ctx_index());
    let conf = conf.borrow();

    if *conf.enable == NGX_HTTP_USERID_OFF {
        v.not_found = true;
        return NGX_OK;
    }

    let ctx = userid_get_uid(&r, &conf);
    let ctx = ctx.borrow();

    if ctx.uid_got[3] != 0 {
        return userid_variable(v, &conf.name, &ctx.uid_got);
    }

    v.not_found = true;

    NGX_OK
}

/// ngx_http_userid_set_variable
fn userid_set_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let r = r.main();
    let conf = r.loc_conf::<UserIdConf>(ctx_index());
    let conf = conf.borrow();

    if *conf.enable < NGX_HTTP_USERID_V1 {
        v.not_found = true;
        return NGX_OK;
    }

    let ctx = userid_get_uid(&r, &conf);

    if userid_create_uid(&r, &ctx, &conf) != NGX_OK {
        return NGX_ERROR;
    }

    let ctx = ctx.borrow();

    if ctx.uid_set[3] == 0 {
        v.not_found = true;
        return NGX_OK;
    }

    userid_variable(v, &conf.name, &ctx.uid_set)
}

/// ngx_http_userid_get_uid: the request's context, created with the uid
/// of the cookie the client sent
fn userid_get_uid(r: &R, conf: &UserIdConf) -> Rc<std::cell::RefCell<UserIdCtx>> {
    if let Some(ctx) = r.get_ctx::<UserIdCtx>(ctx_index()) {
        return ctx;
    }

    let ctx = r.set_ctx(ctx_index(), UserIdCtx { uid_got: [0; 4], uid_set: [0; 4], cookie: Vec::new(), reset: false });

    let cookies = r.headers_in.borrow().cookie.clone();

    let (cookie, value) = match parse_cookie_lines(r, &cookies, &conf.name) {
        Some(found) => found,
        None => return ctx,
    };

    http_debug!(r, "uid cookie: \"{}\"", B(&value));

    let mut c = ctx.borrow_mut();

    c.cookie = value;

    if c.cookie.len() < 22 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client sent too short userid cookie \"{}\"", B(&cookie.value.borrow()));
        drop(c);
        return ctx;
    }

    /*
     * we have to limit the encoded string to 22 characters because
     *  1) cookie may be marked by "userid_mark",
     *  2) and there are already the millions cookies with a garbage
     *     instead of the correct base64 trail "=="
     */

    match decode_uid(&c.cookie[..22]) {
        Some(uid) => c.uid_got = uid,
        None => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client sent invalid userid cookie \"{}\"", B(&cookie.value.borrow()));
            drop(c);
            return ctx;
        }
    }

    http_debug!(r, "uid: {:08X}{:08X}{:08X}{:08X}", c.uid_got[0], c.uid_got[1], c.uid_got[2], c.uid_got[3]);

    drop(c);

    ctx
}

/// ngx_decode_base64() of the 22 characters into the uid words, which get
/// the bytes in memory order
fn decode_uid(src: &[u8]) -> Option<[u32; 4]> {
    let decoded = ngx_core::string::decode_base64(src)?;

    let mut bytes = [0u8; 16];
    let n = decoded.len().min(16);
    bytes[..n].copy_from_slice(&decoded[..n]);

    let mut uid = [0u32; 4];
    for (i, w) in uid.iter_mut().enumerate() {
        *w = u32::from_ne_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    }

    Some(uid)
}

/// ngx_encode_base64() of the uid words in memory order
fn encode_uid(uid: &[u32; 4]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    for w in uid {
        bytes.extend_from_slice(&w.to_ne_bytes());
    }
    ngx_core::string::encode_base64(&bytes)
}

/// ngx_http_parse_cookie_lines: the Cookie header with `name` and the
/// cookie value
fn parse_cookie_lines(r: &R, headers: &[Header], name: &[u8]) -> Option<(Header, Vec<u8>)> {
    for h in headers {
        http_debug!(r, "parse header: \"{}: {}\"", B(&h.key), B(&h.value.borrow()));

        if let Some(value) = cookie_value(&h.value.borrow(), name) {
            return Some((h.clone(), value));
        }
    }

    None
}

/// The value of the `name` cookie in one Cookie header line, as
/// ngx_http_parse_multi_header_lines_internal() finds it with a value
fn cookie_value(value: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    if name.len() > value.len() {
        return None;
    }

    let end = value.len();
    let mut start = 0;

    while start < end {
        'skip: {
            if end - start < name.len() || !value[start..start + name.len()].eq_ignore_ascii_case(name) {
                break 'skip;
            }

            start += name.len();

            while start < end && value[start] == b' ' {
                start += 1;
            }

            if start == end {
                break 'skip;
            }

            let ch = value[start];
            start += 1;

            if ch != b'=' {
                /* the invalid header value */
                break 'skip;
            }

            while start < end && value[start] == b' ' {
                start += 1;
            }

            let mut last = start;
            while last < end && value[last] != b';' {
                last += 1;
            }

            return Some(value[start..last].to_vec());
        }

        // skip:

        while start < end {
            let ch = value[start];
            start += 1;
            if ch == b';' {
                break;
            }
        }

        while start < end && value[start] == b' ' {
            start += 1;
        }
    }

    None
}

/// ngx_http_userid_set_uid
fn userid_set_uid(r: &R, ctx: &Rc<std::cell::RefCell<UserIdCtx>>, conf: &UserIdConf) -> i64 {
    if userid_create_uid(r, ctx, conf) != NGX_OK {
        return NGX_ERROR;
    }

    let ctx = ctx.borrow();

    if ctx.uid_set[3] == 0 {
        return NGX_OK;
    }

    let cookie = userid_cookie(&ctx, conf, ngx_core::times::time());

    drop(ctx);

    let mut ho = r.headers_out.borrow_mut();

    http_debug!(r, "uid cookie: \"{}\"", B(&cookie));

    ho.add_generated(b"Set-Cookie", cookie);

    if conf.p3p.is_empty() {
        return NGX_OK;
    }

    ho.add(b"P3P", &conf.p3p);

    NGX_OK
}

/// The Set-Cookie value of ngx_http_userid_set_uid; `now` is ngx_time()
fn userid_cookie(ctx: &UserIdCtx, conf: &UserIdConf, now: i64) -> Vec<u8> {
    let mut p = Vec::with_capacity(conf.name.len() + 1 + 24 + conf.path.len() + EXPIRES.len() + 2 + conf.domain.len() + 64);

    p.extend_from_slice(&conf.name);
    p.push(b'=');

    let mark = *conf.mark;

    if ctx.uid_got[3] == 0 || ctx.reset {
        p.extend_from_slice(&encode_uid(&ctx.uid_set));

        if mark != 0 {
            let n = p.len();
            p[n - 2] = mark;
        }
    } else {
        p.extend_from_slice(&ctx.cookie[..22]);
        p.push(mark);
        p.push(b'=');
    }

    let expires = *conf.expires;

    if expires == NGX_HTTP_USERID_MAX_EXPIRES {
        p.extend_from_slice(EXPIRES);
    } else if expires != 0 {
        p.extend_from_slice(&EXPIRES[.."; expires=".len()]);
        p.extend_from_slice(ngx_core::times::http_cookie_time(now + expires).as_bytes());
    }

    p.extend_from_slice(&conf.domain);

    p.extend_from_slice(&conf.path);

    if conf.flags & NGX_HTTP_USERID_COOKIE_SECURE != 0 {
        p.extend_from_slice(b"; secure");
    }

    if conf.flags & NGX_HTTP_USERID_COOKIE_HTTPONLY != 0 {
        p.extend_from_slice(b"; httponly");
    }

    if conf.flags & NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT != 0 {
        p.extend_from_slice(b"; samesite=strict");
    }

    if conf.flags & NGX_HTTP_USERID_COOKIE_SAMESITE_LAX != 0 {
        p.extend_from_slice(b"; samesite=lax");
    }

    if conf.flags & NGX_HTTP_USERID_COOKIE_SAMESITE_NONE != 0 {
        p.extend_from_slice(b"; samesite=none");
    }

    p
}

/// ngx_http_userid_create_uid
fn userid_create_uid(r: &R, ctx: &Rc<std::cell::RefCell<UserIdCtx>>, conf: &UserIdConf) -> i64 {
    {
        let c = ctx.borrow();

        if c.uid_set[3] != 0 {
            return NGX_OK;
        }
    }

    if ctx.borrow().uid_got[3] != 0 {
        let vv = match get_indexed_variable(r, RESET_INDEX.with(|i| i.get())) {
            Some(vv) if !vv.not_found => vv,
            _ => return NGX_ERROR,
        };

        let mut c = ctx.borrow_mut();

        if vv.data.is_empty() || vv.data == b"0" {
            let mark = *conf.mark;

            if mark == 0 || (c.cookie.len() > 23 && c.cookie[22] == mark && c.cookie[23] == b'=') {
                return NGX_OK;
            }

            c.uid_set = c.uid_got;

            return NGX_OK;
        }

        c.reset = true;

        if vv.data == b"log" {
            ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "userid cookie \"{}={:08X}{:08X}{:08X}{:08X}\" was reset", B(&conf.name), c.uid_got[0], c.uid_got[1], c.uid_got[2], c.uid_got[3]);
        }
    }

    /*
     * TODO: in the threaded mode the sequencers should be in TLS and their
     * ranges should be divided between threads
     */

    let service = *conf.service;
    let now = ngx_core::times::time() as u32;
    let start_value = START_VALUE.with(|v| v.get());

    let uid_set = if *conf.enable == NGX_HTTP_USERID_V1 {
        let seq = SEQUENCER_V1.with(|s| {
            let v = s.get();
            s.set(v.wrapping_add(0x100));
            v
        });

        [if service == -1 { 0 } else { service as u32 }, now, start_value, seq]
    } else {
        let addr = if service == -1 {
            match r.connection.local_sockaddr() {
                // sin_addr.s_addr, and the last 4 bytes of an IPv6 address,
                // are the bytes of the word in memory order
                Some(ngx_core::inet::SockAddr::V6(a)) => {
                    let s = a.ip().octets();
                    u32::from_ne_bytes([s[12], s[13], s[14], s[15]])
                }
                Some(ngx_core::inet::SockAddr::Unix(_)) => 0,
                Some(ngx_core::inet::SockAddr::V4(a)) => u32::from_ne_bytes(a.ip().octets()),
                None => return NGX_ERROR,
            }
        } else {
            (service as u32).to_be()
        };

        let seq = SEQUENCER_V2.with(|s| {
            let v = s.get();
            let mut next = v.wrapping_add(0x100);
            if next < 0x03030302 {
                next = 0x03030302;
            }
            s.set(next);
            v
        });

        [addr, now.to_be(), start_value.to_be(), seq.to_be()]
    };

    ctx.borrow_mut().uid_set = uid_set;

    NGX_OK
}

/// ngx_http_userid_variable
fn userid_variable(v: &mut VariableValue, name: &[u8], uid: &[u32; 4]) -> i64 {
    let mut data = Vec::with_capacity(name.len() + "=00001111222233334444555566667777".len());
    data.extend_from_slice(name);
    data.extend_from_slice(format!("={:08X}{:08X}{:08X}{:08X}", uid[0], uid[1], uid[2], uid[3]).as_bytes());

    v.data = data;
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    NGX_OK
}

/// ngx_http_userid_reset_variable: ngx_http_variable_null_value
fn userid_reset_variable(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    *v = VariableValue { valid: true, ..Default::default() };

    NGX_OK
}

/// ngx_http_userid_add_variables
fn userid_add_variables(cf: &mut Conf) -> ConfResult {
    let vars = [
        VarDef { name: "uid_got", set: None, get: Some(userid_got_variable), data: 0, flags: 0 },
        VarDef { name: "uid_set", set: None, get: Some(userid_set_variable), data: 0, flags: 0 },
        VarDef { name: "uid_reset", set: None, get: Some(userid_reset_variable), data: 0, flags: NGX_HTTP_VAR_CHANGEABLE },
    ];

    add_variables(cf, &vars)?;

    let n = get_variable_index(cf, b"uid_reset")?;

    RESET_INDEX.with(|i| i.set(n));

    Ok(())
}

/// ngx_http_userid_init
fn userid_init(_cf: &mut Conf) -> ConfResult {
    crate::install_header_filter_fn(userid_filter);

    Ok(())
}

/// ngx_conf_set_str_slot with ngx_http_userid_domain as the post handler
fn userid_domain(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    set_str(cf, cmd, &mut c.domain)?;

    let domain = c.domain.get().clone();

    if domain == b"none" {
        c.domain = Val::set(Vec::new());
        return Ok(());
    }

    let mut new = b"; domain=".to_vec();
    new.extend_from_slice(&domain);

    c.domain = Val::set(new);

    Ok(())
}

/// ngx_conf_set_str_slot with ngx_http_userid_path as the post handler
fn userid_path(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    set_str(cf, cmd, &mut c.path)?;

    let mut new = b"; path=".to_vec();
    new.extend_from_slice(c.path.get());

    c.path = Val::set(new);

    Ok(())
}

/// ngx_http_userid_expires
fn userid_expires(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let mut ucf = cell.borrow_mut();

    if ucf.expires.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = &cf.args[1];

    if value == b"max" {
        ucf.expires = Val::set(NGX_HTTP_USERID_MAX_EXPIRES);
        return Ok(());
    }

    if value == b"off" {
        ucf.expires = Val::set(0);
        return Ok(());
    }

    match ngx_core::parse::parse_time(value, true) {
        Some(expires) => {
            ucf.expires = Val::set(expires);
            Ok(())
        }
        None => Err(msg("invalid value")),
    }
}

/// ngx_conf_set_bitmask_slot with ngx_http_userid_flags[]
fn userid_flags(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    const FLAGS: [(&str, u32); 6] = [
        ("off", NGX_HTTP_USERID_COOKIE_OFF),
        ("secure", NGX_HTTP_USERID_COOKIE_SECURE),
        ("httponly", NGX_HTTP_USERID_COOKIE_HTTPONLY),
        ("samesite=strict", NGX_HTTP_USERID_COOKIE_SAMESITE | NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT),
        ("samesite=lax", NGX_HTTP_USERID_COOKIE_SAMESITE | NGX_HTTP_USERID_COOKIE_SAMESITE_LAX),
        ("samesite=none", NGX_HTTP_USERID_COOKIE_SAMESITE | NGX_HTTP_USERID_COOKIE_SAMESITE_NONE),
    ];

    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    set_bitmask(cf, cmd, &mut c.flags, &FLAGS)
}

/// ngx_conf_set_str_slot with ngx_http_userid_p3p as the post handler
fn userid_p3p(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    set_str(cf, cmd, &mut c.p3p)?;

    if c.p3p.get() == b"none" {
        c.p3p = Val::set(Vec::new());
    }

    Ok(())
}

/// ngx_http_userid_mark
fn userid_mark(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let mut ucf = cell.borrow_mut();

    if ucf.mark.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = &cf.args[1];

    if value == b"off" {
        ucf.mark = Val::set(0);
        return Ok(());
    }

    if value.len() != 1 || !(value[0].is_ascii_alphanumeric() || value[0] == b'=') {
        return Err(msg("value must be \"off\" or a single letter, digit or \"=\""));
    }

    ucf.mark = Val::set(value[0]);

    Ok(())
}

/// ngx_http_userid_init_worker
fn userid_init_worker(_cycle: &Rc<ngx_core::cycle::Cycle>) -> Result<(), ()> {
    let usec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_micros())
        .unwrap_or(0);

    /* use the most significant usec part that fits to 16 bits */
    let start_value = ((usec / 20) << 16) | ngx_core::os::getpid() as u32;

    START_VALUE.with(|v| v.set(start_value));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf() -> UserIdConf {
        UserIdConf {
            enable: Val::set(NGX_HTTP_USERID_ON),
            flags: NGX_CONF_BITMASK_SET | NGX_HTTP_USERID_COOKIE_OFF,
            service: Val::set(-1),
            name: Val::set(b"uid".to_vec()),
            domain: Val::set(Vec::new()),
            path: Val::set(b"; path=/".to_vec()),
            p3p: Val::set(Vec::new()),
            expires: Val::set(0),
            mark: Val::set(0),
        }
    }

    fn ctx(uid_got: [u32; 4], uid_set: [u32; 4], cookie: &[u8], reset: bool) -> UserIdCtx {
        UserIdCtx { uid_got, uid_set, cookie: cookie.to_vec(), reset }
    }

    #[test]
    fn cookie_lines() {
        assert_eq!(cookie_value(b"uid=abc", b"uid"), Some(b"abc".to_vec()));
        assert_eq!(cookie_value(b"a=1; UID = abc ; b=2", b"uid"), Some(b"abc ".to_vec()));
        // a longer name, or the name without a value, does not match
        assert_eq!(cookie_value(b"uidx=1; uid=2", b"uid"), Some(b"2".to_vec()));
        // after a name without "=" the rest of the line up to the next
        // ";" is skipped, which here is the whole line
        assert_eq!(cookie_value(b"uid; uid=3", b"uid"), None);
        assert_eq!(cookie_value(b"uid; a=1; uid=3", b"uid"), Some(b"3".to_vec()));
        assert_eq!(cookie_value(b"uid", b"uid"), None);
        assert_eq!(cookie_value(b"xuid=1", b"uid"), None);
        assert_eq!(cookie_value(b"ui", b"uid"), None);
        assert_eq!(cookie_value(b"a=uid=1;uid=4", b"uid"), Some(b"4".to_vec()));
    }

    #[test]
    fn uid_roundtrip() {
        let uid = [0x0100007f, 0x12345678, 0x9abcdef0, 0x02030303];
        let enc = encode_uid(&uid);
        assert_eq!(enc.len(), 24);
        assert!(enc.ends_with(b"=="));
        assert_eq!(decode_uid(&enc[..22]), Some(uid));
        // what the 22 characters decode to when marked or with a garbage tail
        let mut marked = enc.clone();
        marked[22] = b't';
        assert_eq!(decode_uid(&marked[..22]), Some(uid));
        assert_eq!(decode_uid(b"!!!!!!!!!!!!!!!!!!!!!!"), None);
        // decoding stops at '=': a partial uid
        assert_eq!(decode_uid(b"AAAAAAA=AAAAAAAAAAAAAA").map(|u| u[3]), Some(0));
        assert_eq!(decode_uid(b"AAAA=AAAAAAAAAAAAAAAAA").map(|u| u[3]), Some(0));
        assert_eq!(decode_uid(b"AAAAA=AAAAAAAAAAAAAAAA"), None);
    }

    #[test]
    fn set_cookie_value() {
        let mut c = conf();
        let uid = [1, 2, 3, 4];
        let x = ctx([0; 4], uid, b"", false);
        let enc = encode_uid(&uid);
        assert_eq!(userid_cookie(&x, &c, 0), [b"uid=".as_ref(), &enc, b"; path=/"].concat());

        // the order of the attributes, the mark on the base64 padding
        c.mark = Val::set(b't');
        c.expires = Val::set(NGX_HTTP_USERID_MAX_EXPIRES);
        c.domain = Val::set(b"; domain=example.com".to_vec());
        c.path = Val::set(b"; path=/p".to_vec());
        c.flags = NGX_HTTP_USERID_COOKIE_SECURE | NGX_HTTP_USERID_COOKIE_HTTPONLY | NGX_HTTP_USERID_COOKIE_SAMESITE | NGX_HTTP_USERID_COOKIE_SAMESITE_NONE;
        let mut marked = enc.clone();
        marked[22] = b't';
        assert_eq!(
            userid_cookie(&x, &c, 0),
            [b"uid=".as_ref(), &marked, b"; expires=Thu, 31-Dec-37 23:55:55 GMT; domain=example.com; path=/p; secure; httponly; samesite=none"].concat()
        );

        // an unmarked cookie that is kept: its 22 characters, the mark and "="
        c.expires = Val::set(100);
        let got = ctx(uid, uid, b"ABCDEFGHIJKLMNOPQRSTUV==", false);
        let s = userid_cookie(&got, &c, 784111777 - 100);
        assert!(s.starts_with(b"uid=ABCDEFGHIJKLMNOPQRSTUVt=; expires=Sun, 06-Nov-94 08:49:37 GMT; domain="));

        // a reset cookie gets the new uid
        let reset = ctx(uid, [5, 6, 7, 8], b"ABCDEFGHIJKLMNOPQRSTUV==", true);
        assert!(userid_cookie(&reset, &c, 0).starts_with(&[b"uid=".as_ref(), &encode_uid(&[5, 6, 7, 8])[..22]].concat()));
    }

    #[test]
    fn variable() {
        let mut v = VariableValue::default();
        userid_variable(&mut v, b"uid", &[0x0100007f, 1, 0xabcdef, 0x03030302]);
        assert_eq!(v.data, b"uid=0100007F0000000100ABCDEF03030302");
        assert!(v.valid && !v.not_found);
    }
}
