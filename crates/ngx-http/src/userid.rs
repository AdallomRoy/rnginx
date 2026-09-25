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
    c.service.merge(&p.service, 0);
    c.name.merge(&p.name, b"uid".to_vec());
    c.domain.merge(&p.domain, Vec::new());
    c.path.merge(&p.path, b"; path=/".to_vec());
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
            v.data = format_uid(&ctx.uid_got, *conf.enable.get() == NGX_HTTP_USERID_V1);
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
            v.data = format_uid(&ctx.uid_set, *conf.enable.get() == NGX_HTTP_USERID_V1);
            v.valid = true;
            return NGX_OK;
        }
    }

    v.not_found = true;
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
    install_header_filter(|r, next| async move { userid_header_filter(r, next).await });
    Ok(())
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

    // Ensure context exists
    if r.get_ctx::<UserIdCtx>(ctx_index()).is_none() {
        let ctx = UserIdCtx { uid_got: [0; 4], uid_set: [0; 4] };
        r.set_ctx(ctx_index(), Rc::new(std::cell::RefCell::new(ctx)));
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

        let uid_bytes = ctx.uid_set.iter().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>();
        let encoded = base64_encode(&uid_bytes);

        let mut cookie = Vec::new();
        cookie.extend_from_slice(conf.name.get());
        cookie.push(b'=');
        cookie.extend_from_slice(&encoded);

        if !conf.path.get().is_empty() {
            cookie.extend_from_slice(conf.path.get());
        } else {
            cookie.extend_from_slice(b"; path=/");
        }

        if !conf.domain.get().is_empty() {
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
