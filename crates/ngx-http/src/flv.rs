//! ngx_http_flv_module
//!
//! FLV (Flash Video) module. Serves FLV files with ?start=<offset> seeking support.
//! The handler prepends the FLV header and serves from the byte offset requested.

use std::rc::Rc;

use ngx_core::buf::{Buf, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::parse::arg;
use crate::*;

pub fn flv_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    let commands = vec![
        ngx_core::cmd_fn!("flv", NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, ConfLevel::None, flv_directive),
    ];
    http_module_def("ngx_http_flv_module", def, commands)
}

fn init(_cf: &mut Conf) -> ConfResult {
    // Handler is installed by the `flv;` directive, not globally, per C.
    Ok(())
}

fn flv_directive(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn std::any::Any>>) -> ConfResult {
    use crate::core::CoreLocConf;
    let loc_conf = crate::get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());
    loc_conf.borrow_mut().handler = Some(std::rc::Rc::new(|r| Box::pin(flv_handler(r))));
    Ok(())
}

/// The FLV file header signature
const FLV_HEADER: &[u8] = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00";

pub async fn flv_handler(r: R) -> i64 {
    // Only GET and HEAD methods allowed
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // Don't serve directories
    if r.uri.borrow().last() == Some(&b'/') {
        return NGX_DECLINED;
    }

    // Discard request body
    let rc = crate::request_body::discard_request_body(&r).await;
    if rc != NGX_OK {
        return rc;
    }

    let log = r.connection.log.clone();

    // Map URI to file path
    let (path, root) = match map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    http_debug!(r, "http flv filename: \"{}\"", B(&path));

    let clcf = r.clcf();
    let mut of = {
        let c = clcf.borrow();
        OpenFileInfo {
            read_ahead: *c.read_ahead,
            directio: usize::MAX,
            valid: *c.open_file_cache_valid,
            min_uses: *c.open_file_cache_min_uses as u32,
            errors: *c.open_file_cache_errors,
            events: *c.open_file_cache_events,
            disable_symlinks: *c.disable_symlinks as u8,
            ..Default::default()
        }
    };

    let cache = clcf.borrow().open_file_cache.get().clone();
    let handle = match open_cached_file(cache.as_ref(), &path, &mut of, &log) {
        Ok(h) => h,
        Err(()) => {
            let (level, rc) = match of.err {
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

    r.root_tested.set(!r.error_page.get());

    if of.is_dir {
        http_debug!(r, "http flv dir");
        r.clear_location();
        let mut location = r.uri.borrow().clone();
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

    log.set_action(Some("sending response to client"));

    // Parse the start offset from ?start=<offset> query string
    let start = if r.args.borrow().is_empty() {
        0i64
    } else {
        match arg(&r.args.borrow(), b"start") {
            Some(v) => parse_byte_offset(v),
            None => 0,
        }
    };

    let mut ho = r.headers_out.borrow_mut();
    ho.status = NGX_HTTP_OK;
    // Content length is FLV header + file from start offset to EOF
    ho.content_length_n = FLV_HEADER.len() as i64 + (of.size - start);
    ho.last_modified_time = of.mtime;
    drop(ho);

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

    // Create the output chain: FLV header + file buffer
    let mut chain = Chain::new();

    // Add FLV header as memory buffer
    let mut header_buf = Buf::from_vec(FLV_HEADER.to_vec());
    header_buf.temporary = true;
    chain.push_back(header_buf);

    // Add file buffer starting from the offset
    let file = Rc::new(BufFile {
        fd: of.fd,
        name: path.clone(),
        directio: of.is_directio,
    });
    let mut file_buf = Buf::file(file, start, of.size);
    file_buf.in_file = true;
    file_buf.last_buf = r.is_main();
    file_buf.last_in_chain = true;
    chain.push_back(file_buf);

    let rc = output_filter(&r, chain).await;
    drop(handle);
    let _ = root;
    rc
}

/// Parse a byte offset from the start query parameter
fn parse_byte_offset(value: &[u8]) -> i64 {
    let mut result = 0i64;
    for &b in value {
        if b >= b'0' && b <= b'9' {
            result = result * 10 + (b - b'0') as i64;
        } else {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_byte_offset() {
        assert_eq!(parse_byte_offset(b"0"), 0);
        assert_eq!(parse_byte_offset(b"100"), 100);
        assert_eq!(parse_byte_offset(b"12345"), 12345);
        assert_eq!(parse_byte_offset(b"123abc"), 123);
    }
}
