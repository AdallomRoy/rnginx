//! ngx_http_flv_module
//!
//! FLV pseudo-streaming: the "start" argument is the offset to send the
//! file from, after an FLV header.

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::*;
use ngx_core::rc::*;
use ngx_core::string::{atoof, B};
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::parse::arg;
use crate::*;

static NGX_FLV_HEADER: &[u8] = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00";

pub fn flv_module() -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![
        ngx_core::cmd_fn!("flv", NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, ConfLevel::None, flv),
    ];
    http_module_def("ngx_http_flv_module", def, commands)
}

/// ngx_http_flv
fn flv(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = crate::get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());
    clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(flv_handler(r))));
    Ok(())
}

/// ngx_http_flv_handler
pub async fn flv_handler(r: R) -> i64 {
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if r.uri.borrow().last() == Some(&b'/') {
        return NGX_DECLINED;
    }

    let rc = crate::request_body::discard_request_body(&r).await;

    if rc != NGX_OK {
        return rc;
    }

    let (path, root) = match map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let log = r.connection.log.clone();

    http_debug!(r, "http flv filename: \"{}\"", B(&path));

    let clcf = r.clcf();

    let mut of = {
        let c = clcf.borrow();
        crate::static_module::open_file_info(&r, &c)
    };

    if crate::core_rt::set_disable_symlinks(&r, &clcf, &path, &mut of) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let cache = clcf.borrow().open_file_cache.get().clone();
    let handle = match open_cached_file(cache.as_ref(), &path, &mut of, &log) {
        Ok(h) => h,
        Err(()) => {
            let (level, rc) = match of.err {
                0 => return NGX_HTTP_INTERNAL_SERVER_ERROR,
                libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG => (NGX_LOG_ERR, NGX_HTTP_NOT_FOUND),
                libc::EACCES | libc::EMLINK | libc::ELOOP => (NGX_LOG_ERR, NGX_HTTP_FORBIDDEN),
                _ => (NGX_LOG_CRIT, NGX_HTTP_INTERNAL_SERVER_ERROR),
            };

            if rc != NGX_HTTP_NOT_FOUND || *clcf.borrow().log_not_found {
                ngx_log_error!(level, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&path));
            }

            return rc;
        }
    };

    if !of.is_file {
        return NGX_DECLINED;
    }

    r.root_tested.set(!r.error_page.get());

    let mut start: i64 = 0;
    let mut len = of.size;
    let mut header = false;

    if !r.args.borrow().is_empty() {
        if let Some(value) = arg(&r.args.borrow(), b"start") {
            start = atoof(value).unwrap_or(NGX_ERROR);

            if start == NGX_ERROR || start >= len {
                start = 0;
            }

            if start != 0 {
                len = NGX_FLV_HEADER.len() as i64 + len - start;
                header = true;
            }
        }
    }

    log.set_action(Some("sending flv to client"));

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.content_length_n = len;
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

    let mut out = Chain::new();

    if header {
        out.push_back(Buf::from_static(NGX_FLV_HEADER));
    }

    let file = Rc::new(BufFile { fd: of.fd, name: path.clone(), directio: of.is_directio });
    let mut b = Buf::file(file, start, of.size);

    b.in_file = b.file_last != 0;
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    b.sync = !(b.last_buf || b.in_file);

    out.push_back(b);

    // the file stays open until the output is sent
    let rc = output_filter(&r, out).await;
    drop(handle);
    let _ = root;
    rc
}
