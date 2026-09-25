//! ngx_http_try_files_module - try files with fallback

use std::any::Any;
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
    pub name: Vec<u8>,
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
                            test_dir: false,
                            code,
                        });
                        break;
                    }
                }
                return Err(cf.emerg(format_args!("invalid code \"{}\"", B(arg))));
            } else {
                // Fallback path or named location
                files.push(TryFile {
                    name: arg.clone(),
                    test_dir: false,
                    code: 0,
                });
            }
        } else {
            // Not the last argument
            let mut name = arg.clone();
            let mut test_dir = false;

            // Check for trailing '/' indicating directory test
            if name.ends_with(b"/") && args.len() > i + 2 {
                // Remove trailing '/' and set test_dir flag
                name.pop();
                test_dir = true;
            }

            files.push(TryFile { name, test_dir, code: 0 });
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

    http_debug!(r, "try_files handler");

    // TODO: Implement file checking using open_file_cache
    // For now, just accept the first URI and continue processing
    if !files.is_empty() {
        // Use the first file's path
        let first_file = &files[0];
        if !first_file.name.is_empty() {
            // Set the URI to the first file and continue
            *r.uri.borrow_mut() = first_file.name.clone();
            crate::core_rt::set_exten(&r);
        }
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
