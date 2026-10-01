//! ngx_http_range_filter_module: ngx_http_range_header_filter_module and
//! ngx_http_range_body_filter_module

/*
 * the single part format:
 *
 * "HTTP/1.0 206 Partial Content" CRLF
 * ... header ...
 * "Content-Type: image/jpeg" CRLF
 * "Content-Length: SIZE" CRLF
 * "Content-Range: bytes START-END/SIZE" CRLF
 * CRLF
 * ... data ...
 *
 *
 * the multipart format:
 *
 * "HTTP/1.0 206 Partial Content" CRLF
 * ... header ...
 * "Content-Type: multipart/byteranges; boundary=0123456789" CRLF
 * CRLF
 * CRLF
 * "--0123456789" CRLF
 * "Content-Type: image/jpeg" CRLF
 * "Content-Range: bytes START0-END0/SIZE" CRLF
 * CRLF
 * ... data ...
 * CRLF
 * "--0123456789" CRLF
 * "Content-Type: image/jpeg" CRLF
 * "Content-Range: bytes START1-END1/SIZE" CRLF
 * CRLF
 * ... data ...
 * CRLF
 * "--0123456789--" CRLF
 */

use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::ngx_log_error;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::request::*;
use crate::*;

// the module ctx is that of ngx_http_range_body_filter_module
crate::http_module_index!("ngx_http_range_body_filter_module");

const NGX_MAX_OFF_T_VALUE: i64 = i64::MAX;
const NGX_MAX_INT32_VALUE: i64 = i32::MAX as i64;
const NGX_ATOMIC_T_LEN: usize = "-9223372036854775808".len();

/// ngx_http_range_t
#[derive(Clone)]
struct Range {
    start: i64,
    end: i64,
    content_range: Vec<u8>,
}

/// ngx_http_range_filter_ctx_t
struct RangeFilterCtx {
    offset: i64,
    boundary_header: Vec<u8>,
    ranges: Vec<Range>,
}

pub fn range_header_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(range_header_filter_init), ..Default::default() };
    http_module_def("ngx_http_range_header_filter_module", def, Vec::new())
}

pub fn range_body_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(range_body_filter_init), ..Default::default() };
    http_module_def("ngx_http_range_body_filter_module", def, Vec::new())
}

/// ngx_http_range_header_filter
async fn range_header_filter(r: R, next: HeaderFilter) -> i64 {
    let (status, content_length_n, content_offset) = {
        let ho = r.headers_out.borrow();
        (ho.status, ho.content_length_n, ho.content_offset)
    };

    if r.http_version.get() < NGX_HTTP_VERSION_10
        || status != NGX_HTTP_OK
        || (!r.is_main() && !r.subrequest_ranges.get())
        || content_length_n == -1
        || !r.allow_ranges.get()
    {
        return next(r).await;
    }

    let max_ranges = *r.clcf().borrow().max_ranges;

    if max_ranges == 0 {
        return next(r).await;
    }

    'next_filter: {
        let range = match r.headers_in.borrow().range.first() {
            Some(h) => h.value(),
            None => break 'next_filter,
        };

        if range.len() < 7 || !range[..6].eq_ignore_ascii_case(b"bytes=") {
            break 'next_filter;
        }

        let if_range = r.headers_in.borrow().if_range.as_ref().map(|h| h.value());

        if let Some(if_range) = if_range {
            if if_range.len() >= 2 && if_range[if_range.len() - 1] == b'"' {
                let etag = match r.headers_out.borrow().etag.as_ref() {
                    Some(h) => h.value(),
                    None => break 'next_filter,
                };

                http_debug!(r, "http ir:{} etag:{}", B(&if_range), B(&etag));

                if if_range != etag {
                    break 'next_filter;
                }

                // goto parse

            } else {
                let last_modified_time = r.headers_out.borrow().last_modified_time;

                if last_modified_time == -1 {
                    break 'next_filter;
                }

                let if_range_time = ngx_core::parse::parse_http_time(&if_range).unwrap_or(NGX_ERROR);

                http_debug!(r, "http ir:{} lm:{}", if_range_time, last_modified_time);

                if if_range_time != last_modified_time {
                    break 'next_filter;
                }
            }
        }

        // parse:

        let mut ctx = RangeFilterCtx { offset: content_offset, boundary_header: Vec::new(), ranges: Vec::new() };

        let ranges = if r.single_range.get() { 1 } else { max_ranges };

        match range_parse(&r, &mut ctx, &range, ranges) {
            NGX_OK => {
                let single = ctx.ranges.len() == 1;

                let ctx = r.set_ctx(ctx_index(), ctx);

                {
                    let mut ho = r.headers_out.borrow_mut();
                    ho.status = NGX_HTTP_PARTIAL_CONTENT;
                    ho.status_line.clear();
                }

                if single {
                    return range_singlepart_header(r, &ctx, next).await;
                }

                return range_multipart_header(r, &ctx, next).await;
            }

            NGX_HTTP_RANGE_NOT_SATISFIABLE => return range_not_satisfiable(&r),

            NGX_ERROR => return NGX_ERROR,

            _ => {} // NGX_DECLINED
        }
    }

    // next_filter:

    {
        let mut ho = r.headers_out.borrow_mut();
        let h = ho.add(b"Accept-Ranges", b"bytes");
        ho.accept_ranges = Some(h);
    }

    next(r).await
}

/// ngx_http_range_parse: `value` is the Range header, NUL-terminated in C
fn range_parse(r: &R, ctx: &mut RangeFilterCtx, value: &[u8], mut ranges: i64) -> i64 {
    if !r.is_main() {
        if let Some(mctx) = r.main().get_ctx::<RangeFilterCtx>(ctx_index()) {
            ctx.ranges = mctx.borrow().ranges.clone();
            return NGX_OK;
        }
    }

    let at = |p: usize| value.get(p).copied().unwrap_or(0);

    let mut p = 6;
    let mut size: i64 = 0;
    let max_ranges = ranges;

    let mut content_length = r.headers_out.borrow().content_length_n;

    let cutoff = NGX_MAX_OFF_T_VALUE / 10;
    let cutlim = NGX_MAX_OFF_T_VALUE % 10;

    loop {
        let mut start: i64 = 0;
        let mut end: i64 = 0;
        let mut suffix = false;

        while at(p) == b' ' {
            p += 1;
        }

        'found: {
            if at(p) != b'-' {
                if !at(p).is_ascii_digit() {
                    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
                }

                while at(p).is_ascii_digit() {
                    let d = (at(p) - b'0') as i64;

                    if start >= cutoff && (start > cutoff || d > cutlim) {
                        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
                    }

                    start = start * 10 + d;
                    p += 1;
                }

                while at(p) == b' ' {
                    p += 1;
                }

                if at(p) != b'-' {
                    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
                }

                p += 1;

                while at(p) == b' ' {
                    p += 1;
                }

                if at(p) == b',' || at(p) == 0 {
                    end = content_length;
                    break 'found;
                }

            } else {
                suffix = true;
                p += 1;
            }

            if !at(p).is_ascii_digit() {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            while at(p).is_ascii_digit() {
                let d = (at(p) - b'0') as i64;

                if end >= cutoff && (end > cutoff || d > cutlim) {
                    return NGX_HTTP_RANGE_NOT_SATISFIABLE;
                }

                end = end * 10 + d;
                p += 1;
            }

            while at(p) == b' ' {
                p += 1;
            }

            if at(p) != b',' && at(p) != 0 {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            if suffix {
                start = if end < content_length { content_length - end } else { 0 };
                end = content_length - 1;
            }

            if end >= content_length {
                end = content_length;

            } else {
                end += 1;
            }
        }

        // found:

        if start < end {
            ctx.ranges.push(Range { start, end, content_range: Vec::new() });

            if size > NGX_MAX_OFF_T_VALUE - (end - start) {
                return NGX_HTTP_RANGE_NOT_SATISFIABLE;
            }

            size += end - start;

            if ranges == 0 {
                return NGX_DECLINED;
            }

            ranges -= 1;

        } else if start == 0 {
            return NGX_DECLINED;
        }

        let c = at(p);
        p += 1;

        if c != b',' {
            break;
        }
    }

    if ctx.ranges.is_empty() {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if ctx.ranges.len() == 1 {
        return NGX_OK;
    }

    if size > content_length {
        return NGX_DECLINED;
    }

    if max_ranges == NGX_MAX_INT32_VALUE {
        size += ctx.ranges.len() as i64 * 256;
        content_length += 4096;

        if size > content_length {
            return NGX_DECLINED;
        }
    }

    NGX_OK
}

/// ngx_http_range_singlepart_header
async fn range_singlepart_header(r: R, ctx: &Rc<RefCell<RangeFilterCtx>>, next: HeaderFilter) -> i64 {
    if !r.is_main() {
        return next(r).await;
    }

    {
        let (start, end) = {
            let ctx = ctx.borrow();
            (ctx.ranges[0].start, ctx.ranges[0].end)
        };

        let mut ho = r.headers_out.borrow_mut();

        if let Some(h) = &ho.content_range {
            h.hash.set(0);
        }

        /* "Content-Range: bytes SSSS-EEEE/TTTT" header */

        let value = format!("bytes {}-{}/{}", start, end - 1, ho.content_length_n);

        let content_range = ho.add(b"Content-Range", value.as_bytes());
        ho.content_range = Some(content_range);

        ho.content_length_n = end - start;
        ho.content_offset = start;

        if let Some(h) = ho.content_length.take() {
            h.hash.set(0);
        }
    }

    next(r).await
}

/// ngx_http_range_multipart_header
async fn range_multipart_header(r: R, ctx: &Rc<RefCell<RangeFilterCtx>>, next: HeaderFilter) -> i64 {
    // ngx_next_temp_number(0)
    let boundary = ngx_core::connection::stats().temp_number.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let boundary = format!("{:0width$}", boundary, width = NGX_ATOMIC_T_LEN);

    {
        let mut ho = r.headers_out.borrow_mut();
        let mut ctx = ctx.borrow_mut();

        /*
         * The boundary header of the range:
         * CRLF
         * "--0123456789" CRLF
         * "Content-Type: image/jpeg" CRLF
         * "Content-Range: bytes "
         */

        let mut bh = Vec::new();

        bh.extend_from_slice(b"\r\n--");
        bh.extend_from_slice(boundary.as_bytes());
        bh.extend_from_slice(b"\r\n");

        if ho.content_type_len == ho.content_type.len() && !ho.charset.is_empty() {
            bh.extend_from_slice(b"Content-Type: ");
            bh.extend_from_slice(&ho.content_type);
            bh.extend_from_slice(b"; charset=");
            bh.extend_from_slice(&ho.charset);
            bh.extend_from_slice(b"\r\n");

        } else if !ho.content_type.is_empty() {
            bh.extend_from_slice(b"Content-Type: ");
            bh.extend_from_slice(&ho.content_type);
            bh.extend_from_slice(b"\r\n");
        }

        bh.extend_from_slice(b"Content-Range: bytes ");

        ctx.boundary_header = bh;

        /* "Content-Type: multipart/byteranges; boundary=0123456789" */

        ho.content_type = format!("multipart/byteranges; boundary={}", boundary).into_bytes();
        ho.content_type_lowcase = None;
        ho.content_type_len = ho.content_type.len();

        ho.charset.clear();

        /* the size of the last boundary CRLF "--0123456789--" CRLF */

        let mut len = ("\r\n--".len() + NGX_ATOMIC_T_LEN + "--\r\n".len()) as i64;

        let boundary_header_len = ctx.boundary_header.len() as i64;
        let content_length_n = ho.content_length_n;

        for range in ctx.ranges.iter_mut() {
            /* the size of the range: "SSSS-EEEE/TTTT" CRLF CRLF */

            range.content_range = format!("{}-{}/{}\r\n\r\n", range.start, range.end - 1, content_length_n).into_bytes();

            len += boundary_header_len + range.content_range.len() as i64 + (range.end - range.start);
        }

        ho.content_length_n = len;

        if let Some(h) = ho.content_length.take() {
            h.hash.set(0);
        }

        if let Some(h) = ho.content_range.take() {
            h.hash.set(0);
        }
    }

    next(r).await
}

/// ngx_http_range_not_satisfiable: the header is not sent, the request is
/// finalized with the status (a special response)
fn range_not_satisfiable(r: &R) -> i64 {
    {
        let mut ho = r.headers_out.borrow_mut();

        ho.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;

        if let Some(h) = &ho.content_range {
            h.hash.set(0);
        }

        let value = format!("bytes */{}", ho.content_length_n);

        let content_range = ho.add(b"Content-Range", value.as_bytes());
        ho.content_range = Some(content_range);
    }

    r.clear_content_length();

    NGX_HTTP_RANGE_NOT_SATISFIABLE
}

/// ngx_http_range_body_filter
async fn range_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    if input.is_empty() {
        return next(r, input).await;
    }

    let ctx = match r.get_ctx::<RangeFilterCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r, input).await,
    };

    if ctx.borrow().ranges.len() == 1 {
        return range_singlepart_body(r, &ctx, input, next).await;
    }

    /*
     * multipart ranges are supported only if whole body is in a single buffer
     */

    if input[0].special_buf() {
        return next(r, input).await;
    }

    if range_test_overlapped(&r, &ctx, &input) != NGX_OK {
        return NGX_ERROR;
    }

    range_multipart_body(r, &ctx, input, next).await
}

/// ngx_http_range_test_overlapped
fn range_test_overlapped(r: &R, ctx: &Rc<RefCell<RangeFilterCtx>>, input: &Chain) -> i64 {
    let mut ctx = ctx.borrow_mut();

    'overlapped: {
        if ctx.offset != 0 {
            break 'overlapped;
        }

        let buf = &input[0];

        if !buf.last_buf {
            let start = ctx.offset;
            let last = ctx.offset + buf.buf_size();

            for range in ctx.ranges.iter() {
                if start > range.start || last < range.end {
                    break 'overlapped;
                }
            }
        }

        ctx.offset = buf.buf_size();

        return NGX_OK;
    }

    ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "range in overlapped buffers");

    NGX_ERROR
}

/// ngx_http_range_singlepart_body
async fn range_singlepart_body(r: R, ctx: &Rc<RefCell<RangeFilterCtx>>, input: Chain, next: BodyFilter) -> i64 {
    let mut out = Chain::new();

    {
        let mut ctx = ctx.borrow_mut();

        let (range_start, range_end) = (ctx.ranges[0].start, ctx.ranges[0].end);

        for mut buf in input {
            let start = ctx.offset;
            let last = ctx.offset + buf.buf_size();

            ctx.offset = last;

            http_debug!(r, "http range body buf: {}-{}", start, last);

            if buf.special_buf() {
                if range_end <= start {
                    continue;
                }

                out.push_back(buf);

                continue;
            }

            if range_end <= start || range_start >= last {
                http_debug!(r, "http range body skip");

                if buf.in_file {
                    buf.file_pos = buf.file_last;
                }

                buf.pos = buf.last;
                buf.sync = true;

                continue;
            }

            if range_start > start {
                if buf.in_file {
                    buf.file_pos += range_start - start;
                }

                if buf.in_memory() {
                    buf.pos += (range_start - start) as usize;
                }
            }

            if range_end <= last {
                if buf.in_file {
                    buf.file_last -= last - range_end;
                }

                if buf.in_memory() {
                    buf.last -= (last - range_end) as usize;
                }

                buf.last_buf = r.is_main();
                buf.last_in_chain = true;

                out.push_back(buf);

                continue;
            }

            out.push_back(buf);
        }
    }

    next(r, out).await
}

/// ngx_http_range_multipart_body: the ranges of the single buffer in->buf
async fn range_multipart_body(r: R, ctx: &Rc<RefCell<RangeFilterCtx>>, input: Chain, next: BodyFilter) -> i64 {
    let buf = &input[0];

    let mut out = Chain::new();

    let last_boundary = {
        let ctx = ctx.borrow();

        for range in ctx.ranges.iter() {
            /*
             * The boundary header of the range:
             * CRLF
             * "--0123456789" CRLF
             * "Content-Type: image/jpeg" CRLF
             * "Content-Range: bytes "
             */

            let mut b = Buf::from_vec(ctx.boundary_header.clone());
            b.temporary = false;
            b.memory = true;

            out.push_back(b);

            /* "SSSS-EEEE/TTTT" CRLF CRLF */

            out.push_back(Buf::from_vec(range.content_range.clone()));

            /* the range data */

            let mut b = Buf {
                in_file: buf.in_file,
                temporary: buf.temporary,
                memory: buf.memory,
                mmap: buf.mmap,
                ..Default::default()
            };

            if buf.in_file {
                b.data = buf.data.clone();
                b.file_pos = buf.file_pos + range.start;
                b.file_last = buf.file_pos + range.end;
            }

            if buf.in_memory() {
                // the buffer memory is not shared here: the range of it
                let (pos, last) = (buf.pos + range.start as usize, buf.pos + range.end as usize);

                if let BufData::Memory(m) = &buf.data {
                    b.data = BufData::Memory(m[pos..last].to_vec());
                    b.pos = 0;
                    b.last = last - pos;
                }
            }

            out.push_back(b);
        }

        /* the last boundary CRLF "--0123456789--" CRLF  */

        let mut last = ctx.boundary_header[.."\r\n--".len() + NGX_ATOMIC_T_LEN].to_vec();
        last.extend_from_slice(b"--\r\n");

        last
    };

    let mut b = Buf::from_vec(last_boundary);
    b.last_buf = true;

    out.push_back(b);

    next(r, out).await
}

/// ngx_http_range_header_filter_init
fn range_header_filter_init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { range_header_filter(r, next).await });
    Ok(())
}

/// ngx_http_range_body_filter_init
fn range_body_filter_init(_cf: &mut Conf) -> ConfResult {
    install_body_filter(|r, chain, next| async move { range_body_filter(r, chain, next).await });
    Ok(())
}
