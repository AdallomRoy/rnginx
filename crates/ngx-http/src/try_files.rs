//! ngx_http_try_files_module - try files with fallback

use std::any::Any;
use std::os::unix::ffi::OsStrExt;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::core::*;
use crate::core_rt::*;
use crate::request::*;
use crate::script::ComplexValue;
use crate::*;

crate::http_module_index!("ngx_http_try_files_module");

pub struct TryFilesConf {
    pub try_files: Option<Vec<TryFile>>,
}

#[derive(Clone)]
pub struct TryFile {
    /// Raw configured token (with $vars intact) — kept for @named etc.
    pub name: Vec<u8>,
    /// Compiled complex value; `None` means the name was a literal without vars.
    pub value: Option<ComplexValue>,
    pub test_dir: bool,
    pub code: i64, // For last entry: HTTP status code (e.g., 404)
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(TryFilesConf { try_files: None })
}

/// ngx_http_try_files directive handler
fn try_files_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<TryFilesConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() < 3 {
        return Err(cf.emerg(format_args!("try_files requires at least 2 arguments")));
    }

    let mut files = Vec::new();

    // Process all arguments except the first (directive name)
    for (i, arg) in args.iter().enumerate().skip(1) {
        if i == args.len() - 1 {
            // Last argument - can be =code or a path/named location
            let arg_str = std::str::from_utf8(arg).unwrap_or("");

            if arg_str.starts_with('=') {
                // Status code specification
                if let Ok(code_str) = std::str::from_utf8(&arg[1..]) {
                    if let Ok(code) = code_str.parse::<i64>() {
                        if code > 999 {
                            return Err(cf.emerg(format_args!("invalid code \"{}\"", B(arg))));
                        }
                        files.push(TryFile {
                            name: Vec::new(),
                            value: None,
                            test_dir: false,
                            code,
                        });
                        break;
                    }
                }
                return Err(cf.emerg(format_args!("invalid code \"{}\"", B(arg))));
            } else {
                // Fallback path or named location
                let value = if arg.contains(&b'$') {
                    Some(crate::script::compile_complex_value(cf, arg, 0)?)
                } else {
                    None
                };
                files.push(TryFile {
                    name: arg.clone(),
                    value,
                    test_dir: false,
                    code: 0,
                });
            }
        } else {
            // Not the last argument — non-terminal entries are file/dir tests.
            let mut name = arg.clone();
            let mut test_dir = false;

            // Check for trailing '/' indicating directory test. C only strips it
            // when the entry isn't the last (i + 2 < nelts); our loop already
            // handles the terminal separately, so any non-terminal '/' means
            // "test as directory".
            if name.ends_with(b"/") {
                name.pop();
                test_dir = true;
            }

            let value = if name.contains(&b'$') {
                Some(crate::script::compile_complex_value(cf, &name, 0)?)
            } else {
                None
            };
            files.push(TryFile { name, value, test_dir, code: 0 });
        }
    }

    if files.is_empty() {
        return Err(cf.emerg(format_args!("try_files has no files")));
    }

    cell.borrow_mut().try_files = Some(files);

    Ok(())
}

pub fn try_files_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        ..Default::default()
    };

    let commands = vec![ngx_core::cmd_fn!(
        "try_files",
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_2MORE,
        ConfLevel::Loc,
        try_files_directive
    )];

    http_module_def("ngx_http_try_files_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_PRECONTENT_PHASE,
        Rc::new(|r| Box::pin(try_files_handler(r))),
    );
    Ok(())
}

/// ngx_http_try_files_handler
async fn try_files_handler(r: R) -> i64 {
    let conf = r.loc_conf::<TryFilesConf>(ctx_index());
    let files = match &conf.borrow().try_files {
        Some(f) => f.clone(),
        None => return NGX_DECLINED,
    };
    if files.is_empty() {
        return NGX_DECLINED;
    }

    http_debug!(r, "try files handler");

    let clcf = r.clcf();
    let alias_len = clcf.borrow().alias;

    // Walk entries: for each non-terminal one, expand and stat; for the terminal
    // entry, dispatch (=code, @named, or /internal_redirect).
    for idx in 0..files.len() {
        let tf = &files[idx];
        let is_last = idx + 1 == files.len();

        // The terminal entry with empty name may be a =code fallback.
        if is_last && tf.name.is_empty() {
            if tf.code > 0 {
                return tf.code;
            }
        }

        // Expand the entry's name (may contain $vars).
        let expanded_name: Vec<u8> = if let Some(cv) = &tf.value {
            match crate::script::complex_value(&r, cv) {
                Ok(v) => v,
                Err(_) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
            }
        } else {
            tf.name.clone()
        };

        // Terminal entry with a name: internal redirect (either @name or /uri).
        if is_last {
            let name = &expanded_name;
            if name.first() == Some(&b'@') {
                let rc = crate::core_rt::named_location(&r, name).await;
                if rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE {
                    return rc;
                }
                return NGX_DONE;
            }
            // Split at '?' to detect args
            let (uri_part, args_part): (Vec<u8>, Option<Vec<u8>>) =
                if let Some(q) = name.iter().position(|&b| b == b'?') {
                    (name[..q].to_vec(), Some(name[q + 1..].to_vec()))
                } else {
                    (name.clone(), None)
                };
            let rc = crate::core_rt::internal_redirect(&r, &uri_part, args_part.as_deref()).await;
            if rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE {
                return rc;
            }
            return NGX_DONE;
        }

        // Middle entry: attempt to map this URI (relative-to-current-URI style)
        // to a filesystem path and stat it. C uses ngx_open_cached_file with
        // test_only=1. We use plain fs metadata.
        let candidate_uri = expanded_name.clone();
        if candidate_uri.is_empty() {
            continue;
        }

        // Temporarily replace r.uri to run map_uri_to_path against the candidate
        // (so alias/root apply), then restore.
        let saved_uri = r.uri.borrow().clone();
        *r.uri.borrow_mut() = candidate_uri.clone();
        let mapped = crate::core_rt::map_uri_to_path(&r, 0);
        *r.uri.borrow_mut() = saved_uri.clone();

        let (path, _root) = match mapped {
            Some(p) => p,
            None => continue,
        };

        // Stat the candidate. C uses open_file_cache; we simplify to std::fs.
        let os = std::ffi::OsStr::from_bytes(&path);
        let md = match std::fs::metadata(os) {
            Ok(m) => m,
            Err(e) => {
                if let Some(errno) = e.raw_os_error() {
                    if errno != libc::ENOENT && errno != libc::ENOTDIR && errno != libc::ENAMETOOLONG {
                        ngx_core::ngx_log_error!(
                            ngx_core::log::NGX_LOG_CRIT,
                            r.connection.log,
                            Some(errno),
                            "stat \"{}\" failed",
                            ngx_core::string::B(&path)
                        );
                    }
                }
                continue;
            }
        };
        let is_dir = md.is_dir();
        if is_dir != tf.test_dir {
            continue;
        }

        // Match found. Set r.uri per C:
        //   no alias        -> r.uri = candidate_uri
        //   alias==MAX (regex or exact-string alias):
        //     only if !test_dir; also set add_uri_to_alias
        //   alias>0         -> keep prefix of length alias, append candidate tail
        if alias_len == 0 {
            *r.uri.borrow_mut() = candidate_uri.clone();
        } else if alias_len == usize::MAX {
            if !tf.test_dir {
                *r.uri.borrow_mut() = candidate_uri.clone();
                // r.add_uri_to_alias.set(true) — TODO field not yet present
            }
        } else {
            let cur = r.uri.borrow().clone();
            let prefix = cur.get(..alias_len).unwrap_or(&cur[..]).to_vec();
            let mut new_uri = prefix;
            new_uri.extend_from_slice(&candidate_uri);
            *r.uri.borrow_mut() = new_uri;
        }
        crate::core_rt::set_exten(&r);
        return NGX_DECLINED;
    }

    NGX_DECLINED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_file_structure() {
        let tf = TryFile {
            name: b"/file.html".to_vec(),
            test_dir: false,
            code: 0,
        };
        assert!(!tf.test_dir);
    }
}
