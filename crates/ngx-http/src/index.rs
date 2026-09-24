//! ngx_http_index_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_index_module");

#[derive(Clone)]
pub struct IndexEntry {
    pub name: Vec<u8>,
    pub cv: Option<ComplexValue>,
}

pub struct IndexConf {
    pub indices: Option<Vec<IndexEntry>>,
    pub max_index_len: usize,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(IndexConf { indices: None, max_index_len: 0 })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<IndexConf>(prev).borrow();
    let mut c = conf_cell::<IndexConf>(conf).borrow_mut();
    if c.indices.is_none() {
        c.indices = p.indices.clone();
        c.max_index_len = p.max_index_len;
    }
    if c.indices.is_none() {
        c.indices = Some(vec![IndexEntry { name: b"index.html".to_vec(), cv: None }]);
        c.max_index_len = "index.html".len() + 1;
    }
    Ok(())
}

fn set_index(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<IndexConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    if cell.borrow().indices.is_some() {
        return Err(msg("is duplicate"));
    }
    let mut list = Vec::new();
    let mut max_len = 0;
    for (i, v) in args.iter().enumerate().skip(1) {
        if v.first() == Some(&b'/') && i != args.len() - 1 {
            cf.warn(format_args!("only the last index in \"index\" directive should be absolute"));
        }
        if v.is_empty() {
            return Err(cf.emerg(format_args!("index \"{}\" in \"index\" directive is invalid", B(&args[1]))));
        }
        let n = script_variables_count(v);
        if n == 0 {
            if max_len < v.len() + 1 {
                max_len = v.len() + 1;
            }
            list.push(IndexEntry { name: v.clone(), cv: None });
            continue;
        }
        let cv = compile_complex_value(cf, v, 0)?;
        list.push(IndexEntry { name: v.clone(), cv: Some(cv) });
    }
    let mut c = cell.borrow_mut();
    c.indices = Some(list);
    c.max_index_len = max_len;
    Ok(())
}

pub fn index_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), create_loc_conf: Some(create_conf), merge_loc_conf: Some(merge_conf), ..Default::default() };
    let commands = vec![ngx_core::cmd_fn!("index", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, set_index)];
    http_module_def("ngx_http_index_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(index_handler(r))));
    Ok(())
}

async fn index_handler(r: R) -> i64 {
    if r.uri.borrow().last() != Some(&b'/') {
        return NGX_DECLINED;
    }
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_POST) == 0 {
        return NGX_DECLINED;
    }
    let log = r.connection.log.clone();
    let conf = r.loc_conf::<IndexConf>(ctx_index());
    let indices = conf.borrow().indices.clone().unwrap_or_default();
    let clcf = r.clcf();
    let mut dir_tested = false;
    let mut root_len = 0usize;
    let mut path: Vec<u8> = Vec::new();
    for entry in indices.iter() {
        let name: Vec<u8>;
        if let Some(cv) = &entry.cv {
            name = match complex_value(&r, cv) {
                Ok(v) => v,
                Err(_) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
            };
            if name.is_empty() {
                continue;
            }
            if name[0] == b'/' {
                return internal_redirect(&r, &name, Some(&r.args.borrow().clone())).await;
            }
            match map_uri_to_path(&r, name.len() + 1) {
                Some((p, rl)) => {
                    path = p;
                    root_len = rl;
                }
                None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
            }
        } else {
            name = entry.name.clone();
            if path.is_empty() {
                match map_uri_to_path(&r, 0) {
                    Some((p, rl)) => {
                        path = p;
                        root_len = rl;
                    }
                    None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
                }
            }
        }
        let dir_len = path.len();
        let mut full = path.clone();
        full.extend_from_slice(&name);
        http_debug!(r, "open index \"{}\"", B(&full));
        let mut of = {
            let c = clcf.borrow();
            crate::static_module::open_file_info(&r, &c)
        };
        of.test_only = true;
        let cache = clcf.borrow().open_file_cache.get().clone();
        match open_cached_file(cache.as_ref(), &full, &mut of, &log) {
            Ok(_h) => {
                if of.is_dir {
                    continue;
                }
                // found
                let mut uri = r.uri.borrow().clone();
                uri.extend_from_slice(&name);
                let _ = dir_len;
                let _ = root_len;
                return internal_redirect(&r, &uri, Some(&r.args.borrow().clone())).await;
            }
            Err(()) => {
                http_debug!(r, "{} \"{}\" failed ({}: {})", of.failed, B(&full), of.err, ngx_core::log::strerror(of.err));
                if of.err == 0 {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if of.err == libc::EACCES {
                    // ngx_http_index_error
                    ngx_log_error!(NGX_LOG_ERR, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&full));
                    return NGX_HTTP_FORBIDDEN;
                }
                if !dir_tested {
                    let rc = test_dir(&r, &clcf, &path[..dir_len], root_len).await;
                    if rc != NGX_OK {
                        return rc;
                    }
                    dir_tested = true;
                }
                if of.err == libc::ENOENT {
                    continue;
                }
                ngx_log_error!(NGX_LOG_CRIT, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&full));
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    NGX_DECLINED
}

async fn test_dir(r: &R, clcf: &Rc<std::cell::RefCell<CoreLocConf>>, dir: &[u8], root_len: usize) -> i64 {
    let log = r.connection.log.clone();
    let mut d = dir.to_vec();
    if d.len() > 1 && d.last() == Some(&b'/') && d.len() > root_len {
        d.pop();
    }
    http_debug!(r, "http index check dir: \"{}\"", B(&d));
    let mut of = {
        let c = clcf.borrow();
        crate::static_module::open_file_info(r, &c)
    };
    of.test_dir = true;
    of.test_only = true;
    let cache = clcf.borrow().open_file_cache.get().clone();
    match open_cached_file(cache.as_ref(), &d, &mut of, &log) {
        Ok(_) => {
            if !of.is_dir {
                ngx_log_error!(NGX_LOG_ALERT, log, None, "\"{}\" is not a directory", B(&d));
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            NGX_OK
        }
        Err(()) => {
            if of.err == libc::ENOENT || of.err == libc::ENOTDIR {
                ngx_log_error!(NGX_LOG_ERR, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&d));
                return NGX_HTTP_NOT_FOUND;
            }
            if of.err == libc::EACCES {
                ngx_log_error!(NGX_LOG_ERR, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&d));
                return NGX_HTTP_FORBIDDEN;
            }
            ngx_log_error!(NGX_LOG_CRIT, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&d));
            NGX_HTTP_INTERNAL_SERVER_ERROR
        }
    }
}
