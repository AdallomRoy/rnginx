//! ngx_http_static_module

use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::*;

pub fn static_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_static_module", def, Vec::new())
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(static_handler(r))));
    Ok(())
}

/// Fill an OpenFileInfo from the location config (ngx_http_set_disable_symlinks etc.).
pub fn open_file_info(r: &R, clcf: &CoreLocConf) -> OpenFileInfo {
    let mut of = OpenFileInfo::default();
    of.read_ahead = *clcf.read_ahead;
    of.directio = if *clcf.directio == NGX_OPEN_FILE_DIRECTIO_OFF { usize::MAX } else { *clcf.directio as usize };
    of.valid = *clcf.open_file_cache_valid;
    of.min_uses = *clcf.open_file_cache_min_uses as u32;
    of.errors = *clcf.open_file_cache_errors;
    of.events = *clcf.open_file_cache_events;
    of.disable_symlinks = *clcf.disable_symlinks as u8;
    let _ = r;
    of
}

pub async fn static_handler(r: R) -> i64 {
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_POST) == 0 {
        return NGX_HTTP_NOT_ALLOWED;
    }
    if r.uri.borrow().last() == Some(&b'/') {
        return NGX_DECLINED;
    }
    let log = r.connection.log.clone();
    let (path, root) = match map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    http_debug!(r, "http filename: \"{}\"", B(&path));
    let clcf = r.clcf();
    let mut of = {
        let c = clcf.borrow();
        open_file_info(&r, &c)
    };
    let cache = clcf.borrow().open_file_cache.get().clone();
    let handle = match open_cached_file(cache.as_ref(), &path, &mut of, &log) {
        Ok(h) => h,
        Err(()) => {
            let level;
            let rc;
            match of.err {
                libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG => {
                    level = NGX_LOG_ERR;
                    rc = NGX_HTTP_NOT_FOUND;
                }
                libc::EACCES | libc::EMLINK | libc::ELOOP => {
                    level = NGX_LOG_ERR;
                    rc = NGX_HTTP_FORBIDDEN;
                }
                _ => {
                    level = NGX_LOG_CRIT;
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            if rc != NGX_HTTP_NOT_FOUND || *clcf.borrow().log_not_found {
                ngx_log_error!(level, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&path));
            }
            return rc;
        }
    };
    r.root_tested.set(!r.error_page.get());
    http_debug!(r, "http static fd: {}", of.fd);
    if of.is_dir {
        http_debug!(r, "http dir");
        r.clear_location();
        let mut location = r.uri.borrow().clone();
        location.push(b'/');
        if !r.args.borrow().is_empty() {
            location.push(b'?');
            location.extend_from_slice(&r.args.borrow());
        }
        // ngx_http_static_handler: escape the URI when redirecting
        let esc = ngx_core::string::escape_uri(&r.uri.borrow(), ngx_core::string::NGX_ESCAPE_URI);
        let mut location = esc;
        location.push(b'/');
        if !r.args.borrow().is_empty() {
            location.push(b'?');
            location.extend_from_slice(&r.args.borrow());
        }
        let h = r.headers_out.borrow_mut().add(b"Location", &location);
        r.headers_out.borrow_mut().location = Some(h);
        return NGX_HTTP_MOVED_PERMANENTLY;
    }
    if !of.is_file {
        ngx_log_error!(NGX_LOG_CRIT, log, None, "\"{}\" is not a regular file", B(&path));
        return NGX_HTTP_NOT_FOUND;
    }
    if r.method.get() == NGX_HTTP_POST {
        return NGX_HTTP_NOT_ALLOWED;
    }
    let rc = crate::request_body::discard_request_body(&r).await;
    if rc != NGX_OK {
        return rc;
    }
    log.set_action(Some("sending response to client"));
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.content_length_n = of.size;
        ho.last_modified_time = of.mtime;
    }
    if set_etag(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if set_content_type(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r.allow_ranges.set(true);
    let rc = send_header(&r).await;
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return rc;
    }
    let file = Rc::new(BufFile { fd: of.fd, name: path.clone(), directio: of.is_directio });
    let mut b = Buf::file(file, 0, of.size);
    b.in_file = true;
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    let mut chain = Chain::new();
    chain.push_back(b);
    // keep the file handle alive until the body is sent
    let rc = output_filter(&r, chain).await;
    drop(handle);
    let _ = root;
    let _ = BufData::None;
    rc
}
