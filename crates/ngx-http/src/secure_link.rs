//! ngx_http_secure_link_module: validate signed URIs

use std::any::Any;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use md5::Digest;
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request::VariableValue;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_secure_link_module");

pub struct SecureLinkConf {
    pub variable: Val<Option<ComplexValue>>,
    pub md5: Val<Option<ComplexValue>>,
    pub secret: Val<Vec<u8>>,
}

#[derive(Clone)]
struct SecureLinkCtx {
    expires: Vec<u8>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SecureLinkConf {
        variable: Val::unset(),
        md5: Val::unset(),
        secret: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<SecureLinkConf>(prev).borrow();
    let mut c = conf_cell::<SecureLinkConf>(conf).borrow_mut();
    c.variable.merge(&p.variable, None);
    c.md5.merge(&p.md5, None);
    c.secret.merge(&p.secret, Vec::new());
    Ok(())
}

pub fn secure_link_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("secure_link", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_variable),
        ngx_core::cmd_fn!("secure_link_md5", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_md5),
        ngx_core::cmd!("secure_link_secret", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, SecureLinkConf, secret, set_str),
    ];
    http_module_def("ngx_http_secure_link_module", def, commands)
}

fn set_variable(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let arg = cf.args[1].clone();
    let cell = conf_rc::<SecureLinkConf>(conf.as_ref().unwrap());
    let cv = compile_complex_value(cf, &arg, 0)?;
    cell.borrow_mut().variable = Val::set(Some(cv));
    Ok(())
}

fn set_md5(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let arg = cf.args[1].clone();
    let cell = conf_rc::<SecureLinkConf>(conf.as_ref().unwrap());
    let cv = compile_complex_value(cf, &arg, 0)?;
    cell.borrow_mut().md5 = Val::set(Some(cv));
    Ok(())
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = [
        VarDef {
            name: "secure_link",
            set: None,
            get: Some(var_secure_link),
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "secure_link_expires",
            set: None,
            get: Some(var_secure_link_expires),
            data: 0,
            flags: 0,
        },
    ];
    variables::add_variables(cf, &vars)
}

fn var_secure_link(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    use ngx_core::rc::*;

    let conf = r.loc_conf::<SecureLinkConf>(ctx_index());
    let conf = conf.borrow();

    // Check for legacy secure_link_secret mode
    if !conf.secret.get().is_empty() {
        // Match C ngx_http_secure_link_old_variable: URI /PREFIX/HASH/URL,
        // hash = md5(URL + secret) hex-encoded.
        let unparsed_uri = r.unparsed_uri.borrow();
        // First byte is '/' — find the next '/' (end of prefix segment,
        // start of hash) then the one after (end of hash, start of URL).
        let after_first = match unparsed_uri.iter().skip(1).position(|&b| b == b'/') {
            Some(p) => p + 1 + 1, // skip past prefix's trailing '/'
            None => {
                v.not_found = true;
                return NGX_OK;
            }
        };
        let hash_start = after_first;
        let after_hash = match unparsed_uri[hash_start..].iter().position(|&b| b == b'/') {
            Some(p) => hash_start + p,
            None => {
                v.not_found = true;
                return NGX_OK;
            }
        };
        let hash_end = after_hash;
        let url_start = after_hash + 1;
        if hash_end - hash_start != 32 || url_start >= unparsed_uri.len() {
            v.not_found = true;
            return NGX_OK;
        }
        let hash_part = &unparsed_uri[hash_start..hash_end];
        let url_part = &unparsed_uri[url_start..];

        use md5::Md5;
        let mut hasher = Md5::new();
        hasher.update(url_part);
        hasher.update(conf.secret.get());
        let digest = hasher.finalize();

        // Constant-time compare with hex-encoded hash.
        let mut mismatch = 0u8;
        for (i, byte) in digest.iter().enumerate() {
            let n = match hex_pair(&hash_part[i * 2..i * 2 + 2]) {
                Some(v) => v,
                None => {
                    v.not_found = true;
                    return NGX_OK;
                }
            };
            mismatch |= n ^ byte;
        }
        if mismatch != 0 {
            v.not_found = true;
            return NGX_OK;
        }
        v.data = url_part.to_vec();
        v.valid = true;
        return NGX_OK;
    }

    // New mode with secure_link + secure_link_md5
    if conf.variable.get().is_none() || conf.md5.get().is_none() {
        v.not_found = true;
        return NGX_OK;
    }

    let var_cv = conf.variable.get().as_ref().unwrap();
    let md5_cv = conf.md5.get().as_ref().unwrap();

    let val_result = match crate::script::complex_value(r, var_cv) {
        Ok(v) => v,
        Err(_) => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    // Parse expires if present (format: base64hash,timestamp)
    let (hash_part, expires_part) = if let Some(comma_pos) = val_result.iter().position(|&b| b == b',') {
        let hash = &val_result[..comma_pos];
        let expires_str = &val_result[comma_pos + 1..];
        (hash.to_vec(), Some(expires_str.to_vec()))
    } else {
        (val_result.clone(), None)
    };

    // Decode base64url hash
    if hash_part.len() > 24 {
        v.not_found = true;
        return NGX_OK;
    }

    let decoded = match base64url_decode(&hash_part) {
        Some(d) => d,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    if decoded.len() != 16 {
        v.not_found = true;
        return NGX_OK;
    }

    // Get MD5 input
    let md5_input = match crate::script::complex_value(r, md5_cv) {
        Ok(v) => v,
        Err(_) => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    // Compute MD5
    use md5::Md5;
    let mut hasher = Md5::new();
    hasher.update(&md5_input);
    let digest = hasher.finalize();

    // Constant-time compare
    let mut match_result = true;
    for i in 0..16 {
        if i < decoded.len() && digest[i] != decoded[i] {
            match_result = false;
        }
    }

    if !match_result {
        v.not_found = true;
        return NGX_OK;
    }

    // Check expiration if present
    if let Some(expires_bytes) = expires_part {
        let expires_str = String::from_utf8_lossy(&expires_bytes);
        if let Ok(expires) = expires_str.parse::<u64>() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if expires < now {
                v.data = b"0".to_vec();
                v.valid = true;
                if let Some(ctx) = r.get_ctx::<SecureLinkCtx>(ctx_index()) {
                    let mut ctx = ctx.borrow_mut();
                    ctx.expires = expires_bytes;
                }
                return NGX_OK;
            }
        }

        // Store expires for the expires variable
        if let Some(ctx) = r.get_ctx::<SecureLinkCtx>(ctx_index()) {
            let mut ctx = ctx.borrow_mut();
            ctx.expires = expires_bytes;
        } else {
            let ctx = SecureLinkCtx { expires: expires_bytes };
            r.set_ctx(ctx_index(), ctx);
        }
    }

    v.data = b"1".to_vec();
    v.valid = true;
    NGX_OK
}

fn var_secure_link_expires(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    use ngx_core::rc::*;

    if let Some(ctx) = r.get_ctx::<SecureLinkCtx>(ctx_index()) {
        let ctx = ctx.borrow();
        if !ctx.expires.is_empty() {
            v.data = ctx.expires.clone();
            v.valid = true;
            return NGX_OK;
        }
    }

    v.not_found = true;
    NGX_OK
}

fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = Vec::new();
    let mut i = 0;

    while i < input.len() {
        let mut ch0 = 255u8;
        let mut ch1 = 255u8;
        let mut ch2 = 255u8;
        let mut ch3 = 255u8;

        for (j, &c) in ALPHABET.iter().enumerate() {
            if input[i] == c {
                ch0 = j as u8;
                break;
            }
        }

        if i + 1 < input.len() {
            for (j, &c) in ALPHABET.iter().enumerate() {
                if input[i + 1] == c {
                    ch1 = j as u8;
                    break;
                }
            }
        }

        if ch0 == 255 || ch1 == 255 {
            return None;
        }

        result.push((ch0 << 2) | (ch1 >> 4));

        if i + 2 < input.len() && input[i + 2] != b'=' {
            for (j, &c) in ALPHABET.iter().enumerate() {
                if input[i + 2] == c {
                    ch2 = j as u8;
                    break;
                }
            }
            if ch2 == 255 {
                return None;
            }
            result.push(((ch1 & 0x0f) << 4) | (ch2 >> 2));

            if i + 3 < input.len() && input[i + 3] != b'=' {
                for (j, &c) in ALPHABET.iter().enumerate() {
                    if input[i + 3] == c {
                        ch3 = j as u8;
                        break;
                    }
                }
                if ch3 == 255 {
                    return None;
                }
                result.push(((ch2 & 0x03) << 6) | ch3);
            }
        }

        i += 4;
    }

    Some(result)
}

fn hex_pair(pair: &[u8]) -> Option<u8> {
    fn one(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    Some((one(pair[0])? << 4) | one(pair[1])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_decode() {
        let input = b"SGVsbG8";
        let decoded = base64url_decode(input);
        assert_eq!(decoded, Some(b"Hello".to_vec()));
    }
}
