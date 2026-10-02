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
    crate::install_header_filter_fn(chunked_header_filter);
    crate::install_body_filter_fn(chunked_body_filter);
    Ok(())
}

/// ngx_http_chunked_header_filter
fn chunked_header_filter(r: R, next: &HeaderFilter) -> Step {
    let status = r.headers_out.borrow().status;
    if status == NGX_HTTP_NOT_MODIFIED
        || status == NGX_HTTP_NO_CONTENT
        || status < NGX_HTTP_OK
        || !r.is_main()
        || r.method.get() == NGX_HTTP_HEAD
        || (r.method.get() == NGX_HTTP_CONNECT && status < NGX_HTTP_SPECIAL_RESPONSE)
    {
        return next(r);
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
    next(r)
}

pub struct ChunkedCtx {
    pub done: bool,
}

/// A chunk size or end, in a small buffer kept for reuse once sent (C
/// keeps its chunk buffers in ctx->free)
fn small_buf(len: usize, fill: impl FnOnce(&mut Vec<u8>)) -> Buf {
    let mut v = crate::header_filter::take_header_buf(len);
    fill(&mut v);
    let mut b = Buf::from_vec(v);
    b.tag = crate::header_filter::HEADER_BUF_TAG;
    b
}

/// ngx_http_chunked_body_filter
fn chunked_body_filter(r: R, mut input: Chain, next: &BodyFilter) -> Step {
    if !r.chunked.get() || input.is_empty() || !r.has_ctx(ctx_index()) {
        return next(r, input);
    }
    let mut out = alloc_chain();
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
        // "%xO" CRLF
        out.push_back(small_buf(16 + 2, |v| {
            crate::header_filter::write_hex(v, size);
            v.extend_from_slice(b"\r\n");
        }));
        while let Some(mut b) = input.pop_front() {
            let was_last = b.last_buf;
            b.last_buf = false;
            if b.buf_size() > 0 {
                out.push_back(b);
            } else if !was_last && (b.flush || b.sync) {
                out.push_back(b);
            }
        }
        out.push_back(small_buf(2, |v| v.extend_from_slice(b"\r\n")));
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
        let mut b = if r.upstream_response_incomplete.get() {
            Buf::from_vec(Vec::new())
        } else {
            let ho = r.headers_out.borrow();
            let trailers = ho.trailers.iter().filter(|tr| tr.hash.get() != 0);
            let len = 3 + trailers.clone().map(|tr| tr.key.len() + 2 + tr.value.borrow().len() + 2).sum::<usize>() + 2;
            small_buf(len, |t| {
                t.extend_from_slice(b"0\r\n");
                for tr in trailers {
                    t.extend_from_slice(&tr.key);
                    t.extend_from_slice(b": ");
                    t.extend_from_slice(&tr.value.borrow());
                    t.extend_from_slice(b"\r\n");
                }
                t.extend_from_slice(b"\r\n");
            })
        };
        b.last_buf = true;
        out.push_back(b);
    } else if flush_or_sync && size == 0 && out.is_empty() {
        out.push_back(Buf::special());
    }
    // the input's links are all taken
    free_chain(input);
    if out.is_empty() {
        free_chain(out);
        return Step::Ready(NGX_OK);
    }
    next(r, out)
}
