//! ngx_http_static_module

use std::rc::Rc;

use ngx_core::buf::{Buf, BufFile};
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
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, phase_handler_fn(static_handler));
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
    let _ = r;
    of
}

/// The file a response is sent from, open until the response is sent
struct StaticFile {
    path: Vec<u8>,
    fd: i32,
    size: i64,
    directio: bool,
    handle: Option<Rc<CachedFileHandle>>,
}

/// ngx_http_static_handler: a plain call while nothing waits (the request
/// body to discard, the client to take the output)
pub fn static_handler(r: R) -> Step {
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_POST) == 0 {
        return Step::Ready(NGX_HTTP_NOT_ALLOWED);
    }
    if r.uri.borrow().last() == Some(&b'/') {
        return Step::Ready(NGX_DECLINED);
    }
    let log = &r.connection.log;
    let (path, _root) = match map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return Step::Ready(NGX_HTTP_INTERNAL_SERVER_ERROR),
    };
    http_debug!(r, "http filename: \"{}\"", B(&path));
    let clcf = r.clcf();
    let mut of = {
        let c = clcf.borrow();
        open_file_info(&r, &c)
    };
    if crate::core_rt::set_disable_symlinks(&r, &clcf, &path, &mut of) != NGX_OK {
        return Step::Ready(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    let cache = clcf.borrow().open_file_cache.get().clone();
    let handle = match open_cached_file(cache.as_ref(), &path, &mut of, log) {
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
            return Step::Ready(rc);
        }
    };
    r.root_tested.set(!r.error_page.get());
    http_debug!(r, "http static fd: {}", of.fd);
    if of.is_dir {
        http_debug!(r, "http dir");
        r.clear_location();
        // ngx_http_static_handler: escape the URI when redirecting
        let mut location = ngx_core::string::escape_uri(&r.uri.borrow(), ngx_core::string::NGX_ESCAPE_URI);
        location.push(b'/');
        if !r.args.borrow().is_empty() {
            location.push(b'?');
            location.extend_from_slice(&r.args.borrow());
        }
        let h = r.headers_out.borrow_mut().add_generated(b"Location", location);
        r.headers_out.borrow_mut().location = Some(h);
        return Step::Ready(NGX_HTTP_MOVED_PERMANENTLY);
    }
    if !of.is_file {
        ngx_log_error!(NGX_LOG_CRIT, log, None, "\"{}\" is not a regular file", B(&path));
        return Step::Ready(NGX_HTTP_NOT_FOUND);
    }
    if r.method.get() == NGX_HTTP_POST {
        return Step::Ready(NGX_HTTP_NOT_ALLOWED);
    }
    drop(clcf);
    let mtime = of.mtime;
    let file = StaticFile { path, fd: of.fd, size: of.size, directio: of.is_directio, handle };
    match crate::request_body::discard_request_body_step(&r) {
        Step::Ready(rc) => static_send(r, rc, mtime, file),
        Step::Pending(fut) => Step::boxed(async move {
            let rc = fut.await;
            static_send(r, rc, mtime, file).await
        }),
    }
}

/// ngx_http_static_handler after the request body is discarded: the header
fn static_send(r: R, rc: i64, mtime: i64, file: StaticFile) -> Step {
    if rc != NGX_OK {
        return Step::Ready(rc);
    }
    r.connection.log.set_action(Some("sending response to client"));
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.content_length_n = file.size;
        ho.last_modified_time = mtime;
    }
    if set_etag(&r) != NGX_OK {
        return Step::Ready(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    if set_content_type(&r) != NGX_OK {
        return Step::Ready(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    r.allow_ranges.set(true);
    match send_header(&r) {
        Step::Ready(rc) => static_body(r, rc, file),
        Step::Pending(fut) => Step::boxed(async move {
            let rc = fut.await;
            static_body(r, rc, file).await
        }),
    }
}

/// ngx_http_static_handler after the header: the file, kept open until it
/// is sent
fn static_body(r: R, rc: i64, file: StaticFile) -> Step {
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return Step::Ready(rc);
    }
    let StaticFile { path, fd, size, directio, handle } = file;
    let mut b = Buf::file(Rc::new(BufFile { fd, name: path, directio }), 0, size);
    b.in_file = b.file_last != 0;
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    b.sync = !(b.last_buf || b.in_file);
    let mut chain = alloc_chain();
    chain.push_back(b);
    let out = output_filter(&r, chain);
    match out.done() {
        Some(rc) => {
            drop(handle);
            Step::Ready(rc)
        }
        None => Step::boxed(async move {
            let rc = out.await;
            drop(handle);
            rc
        }),
    }
}
