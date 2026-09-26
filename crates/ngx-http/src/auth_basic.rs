//! ngx_http_auth_basic_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::crypt;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::core::*;
use crate::core_rt::*;
use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_auth_basic_module");

pub struct AuthBasicLocConf {
    pub realm: Option<ComplexValue>,
    pub user_file: Option<ComplexValue>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AuthBasicLocConf {
        realm: None,
        user_file: None,
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AuthBasicLocConf>(prev).borrow();
    let mut c = conf_cell::<AuthBasicLocConf>(conf).borrow_mut();

    if c.realm.is_none() {
        c.realm = p.realm.clone();
    }
    if c.user_file.is_none() {
        c.user_file = p.user_file.clone();
    }

    Ok(())
}

fn set_realm(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AuthBasicLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    let cv = compile_complex_value(cf, &args[1], 0)?;
    cell.borrow_mut().realm = Some(cv);
    Ok(())
}

fn set_user_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AuthBasicLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    let cv = compile_complex_value(cf, &args[1], 0)?;
    cell.borrow_mut().user_file = Some(cv);
    Ok(())
}

pub fn auth_basic_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("auth_basic", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_realm),
        cmd_fn!("auth_basic_user_file", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_user_file),
    ];
    http_module_def("ngx_http_auth_basic_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_ACCESS_PHASE,
        Rc::new(|r| Box::pin(auth_basic_handler(r))),
    );
    Ok(())
}

async fn auth_basic_handler(r: R) -> i64 {
    let conf = r.loc_conf::<AuthBasicLocConf>(ctx_index());
    let conf = conf.borrow();

    // Check if auth_basic realm is configured
    if conf.realm.is_none() || conf.user_file.is_none() {
        return NGX_DECLINED;
    }

    let realm_bytes = match complex_value(&r, &conf.realm.as_ref().unwrap()) {
        Ok(v) => v,
        Err(_) => return NGX_ERROR,
    };

    // Check if realm is "off"
    if realm_bytes == b"off" {
        return NGX_DECLINED;
    }

    // Try to extract user/password from Authorization header
    let rc = auth_basic_user(&r);
    if rc == NGX_DECLINED {
        ngx_log_error!(
            NGX_LOG_INFO,
            r.connection.log,
            None,
            "no user/password was provided for basic authentication"
        );
        return set_www_authenticate(&r, &realm_bytes);
    }
    if rc != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Get user_file path. C compiles with conf_prefix=1 so relative paths get
    // the conf prefix prepended (compile-time for static values, runtime for
    // dynamic). Do the runtime version for both cases so `$arg_f` works.
    let user_file_bytes_raw = match complex_value(&r, &conf.user_file.as_ref().unwrap()) {
        Ok(v) => v,
        Err(_) => return NGX_ERROR,
    };
    let user_file_bytes: Vec<u8> = if user_file_bytes_raw.first() == Some(&b'/') {
        user_file_bytes_raw
    } else {
        let mut full = ngx_core::cycle::cycle().conf_prefix.clone();
        if !full.ends_with(b"/") { full.push(b'/'); }
        full.extend_from_slice(&user_file_bytes_raw);
        full
    };

    // Read the htpasswd file
    let file_path_str = std::str::from_utf8(&user_file_bytes).unwrap_or("");
    let contents = match std::fs::read_to_string(file_path_str) {
        Ok(c) => c,
        Err(e) => {
            let level = if e.kind() == std::io::ErrorKind::NotFound {
                NGX_LOG_ERR
            } else {
                NGX_LOG_CRIT
            };
            ngx_log_error!(
                level,
                r.connection.log,
                Some(e.raw_os_error().unwrap_or(0) as i32),
                "open \"{}\" failed",
                B(&user_file_bytes)
            );
            return if e.kind() == std::io::ErrorKind::NotFound {
                NGX_HTTP_FORBIDDEN
            } else {
                NGX_HTTP_INTERNAL_SERVER_ERROR
            };
        }
    };

    // Extract username and password from request
    let user = r.headers_in.borrow().user.clone();
    let passwd = r.headers_in.borrow().passwd.clone();

    // Search for the user in htpasswd file
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(colon_pos) = line.find(':') {
            let file_user = &line[..colon_pos];
            let file_passwd = &line[colon_pos + 1..];

            if std::str::from_utf8(&user).unwrap_or("") == file_user {
                // Found user, verify password
                let password_match = verify_password(&passwd, file_passwd.as_bytes());
                if password_match {
                    return NGX_OK;
                }
                // User found but password incorrect
                return set_www_authenticate(&r, &realm_bytes);
            }
        }
    }

    // User not found
    set_www_authenticate(&r, &realm_bytes)
}

fn verify_password(user_passwd: &[u8], file_passwd: &[u8]) -> bool {
    // Hash the user password using the stored hash as salt
    // The crypt function will extract the salt from the stored hash and hash the password
    match crypt::crypt(user_passwd, file_passwd) {
        Ok(hashed) => {
            // For all crypt schemes, the result should match the stored hash
            hashed == file_passwd
        }
        Err(_) => false,
    }
}

fn set_www_authenticate(r: &R, realm: &[u8]) -> i64 {
    let mut value = b"Basic realm=\"".to_vec();
    value.extend_from_slice(realm);
    value.extend_from_slice(b"\"");

    let mut hout = r.headers_out.borrow_mut();
    hout.status = NGX_HTTP_UNAUTHORIZED;
    hout.add(b"WWW-Authenticate", &value);

    NGX_HTTP_UNAUTHORIZED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_password_plain() {
        let password = b"test";
        let stored = b"{PLAIN}test";
        assert!(verify_password(password, stored));
    }
}
