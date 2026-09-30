//! ngx_http_chunked_filter_module

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_chunked_filter_module");

pub fn chunked_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_chunked_filter_module", def, Vec::new())
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { chunked_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { chunked_body_filter(r, chain, next).await });
    Ok(())
}

async fn chunked_header_filter(r: R, next: HeaderFilter) -> i64 {
    let status = r.headers_out.borrow().status;
    if status == NGX_HTTP_NOT_MODIFIED
        || status == NGX_HTTP_NO_CONTENT
        || status < NGX_HTTP_OK
        || !r.is_main()
        || r.method.get() == NGX_HTTP_HEAD
        || (r.method.get() == NGX_HTTP_CONNECT && status < NGX_HTTP_SPECIAL_RESPONSE)
    {
        return next(r).await;
    }
    let cl = r.headers_out.borrow().content_length_n;
    if cl == -1 || r.expect_trailers.get() {
        let clcf = r.clcf();
        if r.http_version.get() >= NGX_HTTP_VERSION_11 && *clcf.borrow().chunked_transfer_encoding {
            if r.expect_trailers.get() {
                // trailers only allowed in chunked
                r.clear_content_length();
            }
            r.chunked.set(true);
            r.set_ctx(ctx_index(), ChunkedCtx { done: false });
        } else if r.headers_out.borrow().content_length_n == -1 {
            r.keepalive.set(false);
        }
    }
    next(r).await
}

pub struct ChunkedCtx {
    pub done: bool,
}

async fn chunked_body_filter(r: R, mut input: Chain, next: BodyFilter) -> i64 {
    if !r.chunked.get() || input.is_empty() {
        return next(r, input).await;
    }
    let ctx = r.get_ctx::<ChunkedCtx>(ctx_index());
    if ctx.is_none() {
        return next(r, input).await;
    }
    let mut out = Chain::new();
    let mut size: i64 = 0;
    let mut has_last = false;
    let mut flush_or_sync = false;
    for b in input.iter() {
        size += b.buf_size();
        if b.last_buf {
            has_last = true;
        }
        if b.flush || b.sync {
            flush_or_sync = true;
        }
    }
    if size > 0 {
        out.push_back(Buf::from_vec(format!("{:x}\r\n", size).into_bytes()));
        while let Some(mut b) = input.pop_front() {
            let was_last = b.last_buf;
            b.last_buf = false;
            if b.buf_size() > 0 {
                out.push_back(b);
            } else if !was_last && (b.flush || b.sync) {
                out.push_back(b);
            }
        }
        out.push_back(Buf::from_vec(b"\r\n".to_vec()));
    } else {
        while let Some(mut b) = input.pop_front() {
            let was_last = b.last_buf;
            b.last_buf = false;
            if !was_last {
                out.push_back(b);
            }
        }
    }
    if has_last {
        // If the upstream chunked response was itself truncated (no
        // 0-chunk seen), propagate that state to the client instead of
        // synthesising a terminator. proxy_unfinished.t "chunked no
        // final chunk" checks that the on-wire body ends mid-chunk.
        let mut tail: Vec<u8> = if r.upstream_response_incomplete.get() {
            Vec::new()
        } else {
            let mut t = b"0\r\n".to_vec();
            let trailers = r.headers_out.borrow().trailers.clone();
            for tr in trailers.iter() {
                if tr.hash.get() == 0 { continue; }
                t.extend_from_slice(&tr.key);
                t.extend_from_slice(b": ");
                t.extend_from_slice(&tr.value.borrow());
                t.extend_from_slice(b"\r\n");
            }
            t.extend_from_slice(b"\r\n");
            t
        };
        // Reference `r.headers_out.trailers` to keep the borrow shape;
        // real work happens in the tail construction above.
        let _ = &r.headers_out;
        let _ = &tail;
        let tail_bytes = std::mem::take(&mut tail);
        let mut b = Buf::from_vec(tail_bytes);
        b.last_buf = true;
        out.push_back(b);
    } else if flush_or_sync && size == 0 && out.is_empty() {
        out.push_back(Buf::special());
    }
    if out.is_empty() {
        return NGX_OK;
    }
    next(r, out).await
}
