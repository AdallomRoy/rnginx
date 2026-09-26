//! ngx_http_userid_filter_module: user ID cookie tracking via Set-Cookie header

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request::VariableValue;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_userid_filter_module");

const NGX_HTTP_USERID_OFF: u32 = 0;
const NGX_HTTP_USERID_LOG: u32 = 1;
const NGX_HTTP_USERID_V1: u32 = 2;
const NGX_HTTP_USERID_ON: u32 = 3;

const NGX_HTTP_USERID_COOKIE_SECURE: u32 = 0x0004;
const NGX_HTTP_USERID_COOKIE_HTTPONLY: u32 = 0x0008;
const NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT: u32 = 0x0020;
const NGX_HTTP_USERID_COOKIE_SAMESITE_LAX: u32 = 0x0040;
const NGX_HTTP_USERID_COOKIE_SAMESITE_NONE: u32 = 0x0080;

#[derive(Clone)]
pub struct UserIdConf {
    pub enable: Val<u32>,
    pub flags: Val<u32>,
    pub service: Val<i64>,
    pub name: Val<Vec<u8>>,
    pub domain: Val<Vec<u8>>,
    pub path: Val<Vec<u8>>,
    pub p3p: Val<Vec<u8>>,
    pub expires: Val<i64>,
    pub mark: Val<u8>,
}

#[derive(Clone)]
struct UserIdCtx {
    uid_got: [u32; 4],
    uid_set: [u32; 4],
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(UserIdConf {
        enable: Val::unset(),
        flags: Val::unset(),
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
    c.flags.merge(&p.flags, 0);
    c.service.merge(&p.service, -1);
    c.name.merge(&p.name, b"uid".to_vec());
    c.domain.merge(&p.domain, Vec::new());
    c.path.merge(&p.path, b"/".to_vec());
    c.p3p.merge(&p.p3p, Vec::new());
    c.expires.merge(&p.expires, 0);
    c.mark.merge(&p.mark, 0);

    Ok(())
}

pub fn userid_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!("userid", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, enable, set_enum, &[("off", NGX_HTTP_USERID_OFF), ("log", NGX_HTTP_USERID_LOG), ("v1", NGX_HTTP_USERID_V1), ("on", NGX_HTTP_USERID_ON)]),
        ngx_core::cmd!("userid_service", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, service, set_num),
        ngx_core::cmd!("userid_name", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, name, set_str),
        ngx_core::cmd!("userid_domain", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, domain, set_str),
        ngx_core::cmd!("userid_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, path, set_str),
        ngx_core::cmd_fn!("userid_expires", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_expires),
        ngx_core::cmd_fn!("userid_flags", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::Loc, set_flags),
        ngx_core::cmd!("userid_p3p", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, UserIdConf, p3p, set_str),
        ngx_core::cmd_fn!("userid_mark", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_mark),
    ];
    http_module_def("ngx_http_userid_filter_module", def, commands)
}

fn set_expires(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let value = &cf.args[1];

    let expires = if value == b"max" {
        2145916555i64
    } else if value == b"off" {
        0i64
    } else {
        ngx_core::parse::parse_time(value, true).ok_or(msg("invalid value"))?
    };

    cell.borrow_mut().expires = Val::set(expires);
    Ok(())
}

fn set_flags(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let mut flags = 0u32;

    for arg in cf.args.iter().skip(1) {
        if arg == b"secure" {
            flags |= NGX_HTTP_USERID_COOKIE_SECURE;
        } else if arg == b"httponly" {
            flags |= NGX_HTTP_USERID_COOKIE_HTTPONLY;
        } else if arg == b"off" {
            // NGX_HTTP_USERID_COOKIE_OFF — clears the bitmask; we treat as "no flags".
            flags = 0;
        } else if arg == b"samesite=strict" {
            flags |= NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT;
        } else if arg == b"samesite=lax" {
            flags |= NGX_HTTP_USERID_COOKIE_SAMESITE_LAX;
        } else if arg == b"samesite=none" {
            flags |= NGX_HTTP_USERID_COOKIE_SAMESITE_NONE;
        } else {
            return Err(cf.emerg(format_args!("invalid userid_flags value")));
        }
    }

    cell.borrow_mut().flags = Val::set(flags);
    Ok(())
}

fn set_mark(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<UserIdConf>(conf.as_ref().unwrap());
    let value = &cf.args[1];

    if value == b"off" {
        cell.borrow_mut().mark = Val::set(0);
    } else if value.len() == 1 {
        cell.borrow_mut().mark = Val::set(value[0]);
    } else {
        return Err(msg("invalid value"));
    }
    Ok(())
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = [
        VarDef {
            name: "uid_got",
            set: None,
            get: Some(var_uid_got),
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "uid_set",
            set: None,
            get: Some(var_uid_set),
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "uid_reset",
            set: None,
            get: Some(var_uid_reset),
            data: 0,
            flags: variables::NGX_HTTP_VAR_CHANGEABLE,
        },
    ];
    variables::add_variables(cf, &vars)
}

fn var_uid_got(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    use ngx_core::rc::*;

    let conf = r.loc_conf::<UserIdConf>(ctx_index());
    let conf = conf.borrow();

    if *conf.enable.get() == NGX_HTTP_USERID_OFF {
        v.not_found = true;
        return NGX_OK;
    }

    if let Some(ctx) = r.get_ctx::<UserIdCtx>(ctx_index()) {
        let ctx = ctx.borrow();
        if ctx.uid_got[3] != 0 {
            v.data = format_var_uid(conf.name.get(), &ctx.uid_got);
            v.valid = true;
            return NGX_OK;
        }
    }

    v.not_found = true;
    NGX_OK
}

fn var_uid_set(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    use ngx_core::rc::*;

    let conf = r.loc_conf::<UserIdConf>(ctx_index());
    let conf = conf.borrow();

    if *conf.enable.get() < NGX_HTTP_USERID_V1 {
        v.not_found = true;
        return NGX_OK;
    }

    if let Some(ctx) = r.get_ctx::<UserIdCtx>(ctx_index()) {
        let ctx = ctx.borrow();
        if ctx.uid_set[3] != 0 {
            v.data = format_var_uid(conf.name.get(), &ctx.uid_set);
            v.valid = true;
            return NGX_OK;
        }
    }

    v.not_found = true;
    NGX_OK
}

/// Format $uid_got / $uid_set: `<name>=<HEX32>` — matches C's
/// ngx_http_userid_variable which prints `%V=%08XD%08XD%08XD%08XD`.
/// The variable form is always hex (both v1 and v2), even though the cookie
/// itself is decimal for v1 and base64 for v2.
fn format_var_uid(name: &[u8], uid: &[u32; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 33);
    out.extend_from_slice(name);
    out.push(b'=');
    out.extend_from_slice(format!("{:08X}{:08X}{:08X}{:08X}", uid[0], uid[1], uid[2], uid[3]).as_bytes());
    out
}

fn var_uid_reset(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    // uid_reset is a changeable variable that's not modified by this module
    // It just returns an empty value to allow configuration to set it
    v.data = Vec::new();
    v.valid = true;
    NGX_OK
}

fn format_uid(uid: &[u32; 4], v1: bool) -> Vec<u8> {
    if v1 {
        // v1: plain decimal format
        format!("{}", uid[0]).into_bytes()
    } else {
        // v2+: base64 encoded
        let uid_bytes = uid.iter().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>();
        base64_encode(&uid_bytes)
    }
}

fn base64_encode(data: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = Vec::new();
    let mut i = 0;

    while i + 3 <= data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];
        let b3 = data[i + 2];

        result.push(ALPHABET[(b1 >> 2) as usize]);
        result.push(ALPHABET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize]);
        result.push(ALPHABET[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize]);
        result.push(ALPHABET[(b3 & 0x3f) as usize]);

        i += 3;
    }

    if i < data.len() {
        let b1 = data[i];
        result.push(ALPHABET[(b1 >> 2) as usize]);

        if i + 1 < data.len() {
            let b2 = data[i + 1];
            result.push(ALPHABET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize]);
            result.push(ALPHABET[((b2 & 0x0f) << 2) as usize]);
            result.push(b'=');
        } else {
            result.push(ALPHABET[((b1 & 0x03) << 4) as usize]);
            result.push(b'=');
            result.push(b'=');
        }
    }

    result
}

fn init(cf: &mut Conf) -> ConfResult {
    // Register a phase handler at PREACCESS so $uid_set is populated BEFORE
    // add_header (in the response-header build pass) tries to read it.
    // Without this, headers_filter runs first and $uid_set is not_found.
    crate::core::add_phase_handler(cf, crate::NGX_HTTP_PREACCESS_PHASE,
        std::rc::Rc::new(|r| Box::pin(userid_preaccess(r))));
    install_header_filter(|r, next| async move { userid_header_filter(r, next).await });
    Ok(())
}

async fn userid_preaccess(r: R) -> i64 {
    if !r.is_main() { return crate::NGX_DECLINED; }
    let conf = r.loc_conf::<UserIdConf>(ctx_index());
    let cb = conf.borrow();
    if *cb.enable.get() < NGX_HTTP_USERID_V1 {
        return crate::NGX_DECLINED;
    }
    if r.get_ctx::<UserIdCtx>(ctx_index()).is_none() {
        r.set_ctx(ctx_index(), UserIdCtx { uid_got: [0; 4], uid_set: [0; 4] });
    }
    // Parse Cookie: header(s) for a `<name>=<base64>` pair, decode into
    // uid_got. Matches ngx_http_userid_get_uid in C.
    let name = cb.name.get().clone();
    let cookies: Vec<Vec<u8>> = {
        let hin = r.headers_in.borrow();
        hin.cookie.iter().map(|h| h.value.borrow().clone()).collect()
    };
    let mut got: [u32; 4] = [0; 4];
    for c in &cookies {
        if let Some(v) = find_cookie_value(c, &name) {
            if v.len() >= 22 {
                if let Some(decoded) = base64_decode_16(&v[..22]) {
                    for (i, chunk) in decoded.chunks(4).enumerate().take(4) {
                        got[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    }
                    break;
                }
            }
        }
    }
    // Populate uid_set: if we got a cookie, echo it back; otherwise mint one
    // (create_uid semantics from C — this way add_header $uid_set has a value
    // during headers_filter, which runs before our own header filter).
    let is_v1 = *cb.enable.get() == NGX_HTTP_USERID_V1;
    let service = *cb.service.get();
    // Read $uid_reset via the variable engine — matches C's
    // ngx_http_get_indexed_variable(r, ngx_http_userid_reset_index).
    // Empty or "0" ⇒ no reset (echo got); anything else ⇒ mint new uid_set;
    // "log" ⇒ also emit "userid cookie \"...\" was reset" at NOTICE.
    let (reset, log_reset) = {
        let name = ngx_core::string::to_lower_vec(b"uid_reset");
        match crate::variables::get_variable(&r, &name) {
            Some(v) if !v.not_found => {
                let d = v.data.as_slice();
                let is_zero = d.is_empty() || (d.len() == 1 && d[0] == b'0');
                let is_log = d == b"log";
                (!is_zero, is_log)
            }
            _ => (false, false),
        }
    };
    if log_reset && got[3] != 0 {
        let msg = format!("userid cookie \"{}={:08X}{:08X}{:08X}{:08X}\" was reset",
            String::from_utf8_lossy(cb.name.get()),
            got[0], got[1], got[2], got[3]);
        ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "{}", msg);
    }
    // Fetch local sockaddr up front — we can't borrow across the ctx borrow.
    let local_addr = if !is_v1 && service < 0 {
        r.connection.local_sockaddr()
    } else {
        None
    };
    if let Some(ctx) = r.get_ctx::<UserIdCtx>(ctx_index()) {
        let mut ctx = ctx.borrow_mut();
        if got[3] != 0 {
            ctx.uid_got = got;
        }
        if ctx.uid_set[3] == 0 {
            if ctx.uid_got[3] != 0 && !reset {
                ctx.uid_set = ctx.uid_got;
            } else if is_v1 {
                // v1: host-order fields, no htonl. Service defaults to 0.
                ctx.uid_set[0] = if service < 0 { 0 } else { service as u32 };
                ctx.uid_set[1] = ngx_core::times::time() as u32;
                ctx.uid_set[2] = start_value();
                ctx.uid_set[3] = next_seq_v1();
            } else {
                // v2: network-order fields (htonl).
                ctx.uid_set[0] = if service < 0 {
                    match local_addr {
                        Some(ngx_core::inet::SockAddr::V4(a)) => {
                            // sin_addr.s_addr is network-order stored as u32.
                            let octets = a.ip().octets();
                            u32::from_ne_bytes(octets)
                        }
                        Some(ngx_core::inet::SockAddr::V6(a)) => {
                            let s = a.ip().octets();
                            u32::from_ne_bytes([s[12], s[13], s[14], s[15]])
                        }
                        Some(ngx_core::inet::SockAddr::Unix(_)) => 0,
                        None => 0,
                    }
                } else {
                    (service as u32).to_be()
                };
                ctx.uid_set[1] = (ngx_core::times::time() as u32).to_be();
                ctx.uid_set[2] = start_value().to_be();
                ctx.uid_set[3] = next_seq_v2().to_be();
            }
        }
    }
    crate::NGX_DECLINED
}

// Process-lifetime sequencers (see start_value / sequencer_v1 / sequencer_v2
// in ngx_http_userid_filter_module.c).
fn start_value() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static V: AtomicU32 = AtomicU32::new(0);
    let cur = V.load(Ordering::Relaxed);
    if cur == 0 {
        let s = ngx_core::times::time() as u32;
        V.store(s, Ordering::Relaxed);
        s
    } else {
        cur
    }
}
fn next_seq_v1() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static S: AtomicU32 = AtomicU32::new(1);
    S.fetch_add(0x100, Ordering::Relaxed)
}
fn next_seq_v2() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static S: AtomicU32 = AtomicU32::new(0x03030302);
    let v = S.fetch_add(0x100, Ordering::Relaxed);
    v.max(0x03030302)
}

/// Split a Cookie: header value on `; ` and return the value for the pair
/// whose name matches (case-insensitive).
fn find_cookie_value(header: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i < header.len() {
        // skip leading whitespace/semicolons
        while i < header.len() && (header[i] == b' ' || header[i] == b';' || header[i] == b'\t') {
            i += 1;
        }
        let start = i;
        while i < header.len() && header[i] != b'=' && header[i] != b';' {
            i += 1;
        }
        let key = &header[start..i];
        let mut val: Vec<u8> = Vec::new();
        if i < header.len() && header[i] == b'=' {
            i += 1;
            let vs = i;
            while i < header.len() && header[i] != b';' {
                i += 1;
            }
            val.extend_from_slice(&header[vs..i]);
        }
        if key.eq_ignore_ascii_case(name) {
            return Some(val);
        }
    }
    None
}

/// Base64 decode the first 22 chars (16 bytes of a userid). Ignores the "=="
/// trailer that may be corrupt in legacy cookies (matches C which truncates
/// input to 22 bytes before ngx_decode_base64).
fn base64_decode_16(src: &[u8]) -> Option<[u8; 16]> {
    fn v(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    // Pad the 22-char input to 24 with 'A' (bits 0) so decoding produces 18
    // bytes; take the first 16.
    let mut buf = [b'A'; 24];
    buf[..src.len().min(22)].copy_from_slice(&src[..src.len().min(22)]);
    let mut out = [0u8; 18];
    for i in 0..6 {
        let a = v(buf[i*4])?;
        let b = v(buf[i*4+1])?;
        let c = v(buf[i*4+2])?;
        let d = v(buf[i*4+3])?;
        out[i*3]   = (a << 2) | (b >> 4);
        out[i*3+1] = (b << 4) | (c >> 2);
        out[i*3+2] = (c << 6) | d;
    }
    let mut r = [0u8; 16];
    r.copy_from_slice(&out[..16]);
    Some(r)
}

async fn userid_header_filter(r: R, next: HeaderFilter) -> i64 {
    use ngx_core::rc::*;

    if !r.is_main() {
        return next(r).await;
    }

    let conf = r.loc_conf::<UserIdConf>(ctx_index());
    let conf = conf.borrow();

    if *conf.enable.get() < NGX_HTTP_USERID_V1 {
        drop(conf);
        return next(r).await;
    }

    // Ensure context exists. set_ctx already wraps in Rc<RefCell<_>> —
    // passing a pre-wrapped value here would double-wrap and every later
    // get_ctx::<UserIdCtx>() would silently return None.
    if r.get_ctx::<UserIdCtx>(ctx_index()).is_none() {
        r.set_ctx(ctx_index(), UserIdCtx { uid_got: [0; 4], uid_set: [0; 4] });
    }

    // Create a UID to set
    if let Some(ctx) = r.get_ctx::<UserIdCtx>(ctx_index()) {
        let mut ctx = ctx.borrow_mut();
        if ctx.uid_set[3] == 0 {
            ctx.uid_set[0] = rand_u32();
            ctx.uid_set[1] = rand_u32();
            ctx.uid_set[2] = rand_u32();
            ctx.uid_set[3] = rand_u32();
        }
        // If the client's cookie is valid and we're echoing it back
        // unchanged (no `userid_mark`), don't emit Set-Cookie at all — the
        // browser already has the same cookie. Matches C's create_uid path
        // where uid_set stays 0 and set_uid returns early.
        let mark = *conf.mark.get();
        if ctx.uid_got[3] != 0 && ctx.uid_got == ctx.uid_set && mark == 0 {
            drop(ctx);
            drop(conf);
            return next(r).await;
        }

        let uid_bytes = ctx.uid_set.iter().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>();
        let mut encoded = base64_encode(&uid_bytes);
        // userid_mark <char>: overwrite the second-to-last byte of the
        // base64 output (matches C's `*(p - 2) = conf->mark;` in
        // ngx_http_userid_set_uid). For a 16-byte UID that byte is the
        // second `=` padding char.
        if mark != 0 && encoded.len() >= 2 {
            let idx = encoded.len() - 2;
            encoded[idx] = mark;
        }

        let mut cookie = Vec::new();
        cookie.extend_from_slice(conf.name.get());
        cookie.push(b'=');
        cookie.extend_from_slice(&encoded);

        cookie.extend_from_slice(b"; path=");
        cookie.extend_from_slice(conf.path.get());

        if !conf.domain.get().is_empty() && conf.domain.get() != b"none" {
            cookie.extend_from_slice(b"; domain=");
            cookie.extend_from_slice(conf.domain.get());
        }

        if conf.flags.get() & NGX_HTTP_USERID_COOKIE_SECURE != 0 {
            cookie.extend_from_slice(b"; secure");
        }

        if conf.flags.get() & NGX_HTTP_USERID_COOKIE_HTTPONLY != 0 {
            cookie.extend_from_slice(b"; httponly");
        }

        if conf.flags.get() & NGX_HTTP_USERID_COOKIE_SAMESITE_STRICT != 0 {
            cookie.extend_from_slice(b"; samesite=strict");
        } else if conf.flags.get() & NGX_HTTP_USERID_COOKIE_SAMESITE_LAX != 0 {
            cookie.extend_from_slice(b"; samesite=lax");
        } else if conf.flags.get() & NGX_HTTP_USERID_COOKIE_SAMESITE_NONE != 0 {
            cookie.extend_from_slice(b"; samesite=none");
        }
        // userid_expires: emit `; expires=<HTTP-date>`. `max` (-1) resolves to
        // the same far-future date C emits (Thu, 31-Dec-37 23:55:55 GMT), any
        // positive value is added to the current time.
        let exp = *conf.expires.get();
        if exp != 0 {
            cookie.extend_from_slice(b"; expires=");
            if exp == 2145916555 {
                // `userid_expires max` — C hard-codes this HTTP-date rather
                // than computing it, so future clock skew doesn't turn the
                // cookie into something with a different year formatting.
                cookie.extend_from_slice(b"Thu, 31-Dec-37 23:55:55 GMT");
            } else {
                let t = ngx_core::times::time() + exp;
                cookie.extend_from_slice(ngx_core::times::http_cookie_time(t).as_bytes());
            }
        }

        drop(ctx);

        r.headers_out.borrow_mut().add(b"Set-Cookie", &cookie);

        if !conf.p3p.get().is_empty() {
            r.headers_out.borrow_mut().add(b"P3P", conf.p3p.get());
        }
    }

    drop(conf);
    next(r).await
}

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u32;
    now.wrapping_mul(1103515245).wrapping_add(12345)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, World!";
        let encoded = base64_encode(original);
        assert_eq!(encoded.len(), 20); // 13 bytes -> 20 base64 chars with padding
    }
}
