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
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, crate::core::phase_handler_fn(index_handler));
    Ok(())
}

/// ngx_http_index_handler: a plain call up to the internal redirect to
/// the index found
fn index_handler(r: R) -> Step {
    match index(&r) {
        Index::Done(rc) => Step::Ready(rc),
        Index::Redirect(uri) => Step::boxed(async move {
            let args = r.args.borrow().clone();
            internal_redirect(&r, &uri, Some(&args)).await
        }),
    }
}

/// What the index handler comes to
enum Index {
    Done(i64),
    /// the internal redirect to this URI, with the request's arguments
    Redirect(Vec<u8>),
}

fn index(r: &R) -> Index {
    if r.uri.borrow().last() != Some(&b'/') {
        return Index::Done(NGX_DECLINED);
    }
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_POST) == 0 {
        return Index::Done(NGX_DECLINED);
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
            name = match complex_value(r, cv) {
                Ok(v) => v,
                Err(_) => return Index::Done(NGX_HTTP_INTERNAL_SERVER_ERROR),
            };
            if name.is_empty() {
                continue;
            }
            if name[0] == b'/' {
                return Index::Redirect(name);
            }
            match map_uri_to_path(r, name.len() + 1) {
                Some((p, rl)) => {
                    path = p;
                    root_len = rl;
                }
                None => return Index::Done(NGX_HTTP_INTERNAL_SERVER_ERROR),
            }
        } else {
            name = entry.name.clone();
            // Absolute path: internal redirect (per C — only the last entry
            // is allowed to be absolute and it triggers redirect to that URI).
            if name.first() == Some(&b'/') {
                return Index::Redirect(name);
            }
            if path.is_empty() {
                match map_uri_to_path(r, 0) {
                    Some((p, rl)) => {
                        path = p;
                        root_len = rl;
                    }
                    None => return Index::Done(NGX_HTTP_INTERNAL_SERVER_ERROR),
                }
            }
        }
        let dir_len = path.len();
        let mut full = path.clone();
        full.extend_from_slice(&name);
        http_debug!(r, "open index \"{}\"", B(&full));
        let mut of = {
            let c = clcf.borrow();
            crate::static_module::open_file_info(r, &c)
        };
        of.test_only = true;
        if crate::core_rt::set_disable_symlinks(r, &clcf, &full, &mut of) != NGX_OK {
            return Index::Done(NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
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
                return Index::Redirect(uri);
            }
            Err(()) => {
                http_debug!(r, "{} \"{}\" failed ({}: {})", of.failed, B(&full), of.err, ngx_core::log::strerror(of.err));
                if of.err == 0 {
                    return Index::Done(NGX_HTTP_INTERNAL_SERVER_ERROR);
                }
                // NGX_HAVE_OPENAT
                if of.err == libc::EMLINK || of.err == libc::ELOOP {
                    return Index::Done(NGX_HTTP_FORBIDDEN);
                }
                if of.err == libc::ENOTDIR
                    || of.err == libc::ENAMETOOLONG
                    || of.err == libc::EACCES
                {
                    return Index::Done(index_error(r, &clcf, &full, of.err));
                }
                if !dir_tested {
                    let _ = root_len;
                    let rc = test_dir(r, &clcf, &full, dir_len);
                    if rc != NGX_OK {
                        return Index::Done(rc);
                    }
                    dir_tested = true;
                }
                if of.err == libc::ENOENT {
                    continue;
                }
                ngx_log_error!(NGX_LOG_CRIT, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&full));
                return Index::Done(NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }
    Index::Done(NGX_DECLINED)
}

fn index_error(r: &R, clcf: &Rc<std::cell::RefCell<CoreLocConf>>, file: &[u8], err: i32) -> i64 {
    // Match ngx_http_index_error: EACCES -> 403 with 'is forbidden' log;
    // otherwise 404, log conditionally on log_not_found.
    if err == libc::EACCES {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(err), "\"{}\" is forbidden", B(file));
        return NGX_HTTP_FORBIDDEN;
    }
    let log_nf = *clcf.borrow().log_not_found;
    if log_nf {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(err), "\"{}\" is not found", B(file));
    }
    NGX_HTTP_NOT_FOUND
}

/// ngx_http_index_test_dir: the directory of the index file `path` (the
/// name at `name`) exists. As in C, the "is not found" and "is not a
/// directory" messages show `path`: the directory name is terminated in
/// place, and the byte is restored before they are logged.
fn test_dir(r: &R, clcf: &Rc<std::cell::RefCell<CoreLocConf>>, path: &[u8], name: usize) -> i64 {
    let log = r.connection.log.clone();

    // c = *last; if (c != '/' || path == last) { /* "alias" without
    // trailing slash */ c = *(++last); } *last = '\0'
    let mut last = name - 1;

    if path[last] != b'/' || last == 0 {
        last += 1;
    }

    let dir = &path[..last];

    http_debug!(r, "http index check dir: \"{}\"", B(dir));

    let mut of = {
        let c = clcf.borrow();
        crate::static_module::open_file_info(r, &c)
    };
    of.test_dir = true;
    of.test_only = true;
    if crate::core_rt::set_disable_symlinks(r, clcf, dir, &mut of) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    let cache = clcf.borrow().open_file_cache.get().clone();
    match open_cached_file(cache.as_ref(), dir, &mut of, &log) {
        Ok(_) => {
            if of.is_dir {
                return NGX_OK;
            }
            ngx_log_error!(NGX_LOG_ALERT, log, None, "\"{}\" is not a directory", B(path));
            NGX_HTTP_INTERNAL_SERVER_ERROR
        }
        Err(()) => {
            if of.err != 0 {
                // NGX_HAVE_OPENAT
                if of.err == libc::EMLINK || of.err == libc::ELOOP {
                    return NGX_HTTP_FORBIDDEN;
                }
                if of.err == libc::ENOENT {
                    return index_error(r, clcf, path, libc::ENOENT);
                }
                if of.err == libc::EACCES {
                    // ngx_http_index_test_dir() is called after the first
                    // index file testing has returned an error distinct from
                    // NGX_EACCES. This means that directory searching is
                    // allowed.
                    return NGX_OK;
                }
                ngx_log_error!(NGX_LOG_CRIT, log, Some(of.err), "{} \"{}\" failed", of.failed, B(dir));
            }
            NGX_HTTP_INTERNAL_SERVER_ERROR
        }
    }
}
