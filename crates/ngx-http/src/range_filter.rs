//! ngx_http_range_header_filter_module / ngx_http_range_body_filter_module

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::*;

crate::http_module_index!("ngx_http_range_body_filter_module");

/// Range info for a single range
#[derive(Clone)]
pub struct RangeInfo {
    pub start: i64,
    pub end: i64,
    pub content_range: Vec<u8>,
}

/// Context for range filter processing
pub struct RangeFilterCtx {
    pub offset: i64,
    pub boundary_header: Vec<u8>,
    pub ranges: Vec<RangeInfo>,
}

pub fn range_header_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init_header), ..Default::default() };
    http_module_def("ngx_http_range_header_filter_module", def, Vec::new())
}

pub fn range_body_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init_body), ..Default::default() };
    http_module_def("ngx_http_range_body_filter_module", def, Vec::new())
}

fn init_header(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move {
        range_header_filter(r, next).await
    });
    Ok(())
}

fn init_body(_cf: &mut Conf) -> ConfResult {
    install_body_filter(|r, chain, next| async move {
        range_body_filter(r, chain, next).await
    });
    Ok(())
}

async fn range_header_filter(r: R, next: HeaderFilter) -> i64 {
    let (version, status, has_range, is_subrequest, content_length_n, allow_ranges, clcf_max_ranges) = {
        let ho = r.headers_out.borrow();
        let hi = r.headers_in.borrow();
        let version = r.http_version.get();
        let status = ho.status;
        let has_range = !hi.range.is_empty();
        let content_length_n = ho.content_length_n;
        let allow_ranges = r.allow_ranges.get();
        (version, status, has_range, r != r.main && !r.subrequest_ranges.get(), content_length_n, allow_ranges, r.clcf().borrow().max_ranges.get())
    };

    if version < NGX_HTTP_VERSION_10 || status != NGX_HTTP_OK || is_subrequest || content_length_n == -1 || !allow_ranges {
        return next(r).await;
    }

    if clcf_max_ranges == 0 {
        return next(r).await;
    }

    if !has_range {
        // No range header, advertise Accept-Ranges: bytes
        let h = r.headers_out.borrow_mut().add(b"Accept-Ranges", b"bytes");
        r.headers_out.borrow_mut().accept_ranges = Some(h);
        return next(r).await;
    }

    // Check Range header format
    let range_value = {
        let hi = r.headers_in.borrow();
        hi.range.clone()
    };

    if range_value.len() < 7 || !range_value.starts_with(b"bytes=") {
        let h = r.headers_out.borrow_mut().add(b"Accept-Ranges", b"bytes");
        r.headers_out.borrow_mut().accept_ranges = Some(h);
        return next(r).await;
    }

    // Check if_range
    if !check_if_range(&r) {
        let h = r.headers_out.borrow_mut().add(b"Accept-Ranges", b"bytes");
        r.headers_out.borrow_mut().accept_ranges = Some(h);
        return next(r).await;
    }

    // Parse ranges
    let content_length = r.headers_out.borrow().content_length_n;
    let max_ranges = if r.single_range.get() { 1 } else { clcf_max_ranges as usize };

    let ranges = match parse_ranges(&range_value[6..], content_length, max_ranges) {
        Ok(ranges) if !ranges.is_empty() => ranges,
        Ok(_) => return range_not_satisfiable(&r, next).await,
        Err(RangeParseError::NotSatisfiable) => return range_not_satisfiable(&r, next).await,
        Err(RangeParseError::Declined) => {
            let h = r.headers_out.borrow_mut().add(b"Accept-Ranges", b"bytes");
            r.headers_out.borrow_mut().accept_ranges = Some(h);
            return next(r).await;
        }
        Err(RangeParseError::Error) => return NGX_ERROR,
    };

    // Set status to 206
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_PARTIAL_CONTENT;
        ho.status_line.clear();
    }

    // Handle single vs multipart
    if ranges.len() == 1 {
        singlepart_header(&r, &ranges, next).await
    } else {
        multipart_header(&r, &ranges, next).await
    }
}

fn check_if_range(r: &R) -> bool {
    let hi = r.headers_in.borrow();
    if let Some(if_range) = &hi.if_range {
        let if_range_val = if_range.value.borrow();
        let ho = r.headers_out.borrow();

        // Check if it's an ETag
        if if_range_val.len() >= 2 && if_range_val[if_range_val.len() - 1] == b'"' {
            if let Some(etag) = &ho.etag {
                let etag_val = etag.value.borrow();
                if if_range_val.len() == etag_val.len() && if_range_val.as_slice() == etag_val.as_slice() {
                    return true;
                }
            }
            return false;
        }

        // Check if it's a date
        let lm_time = ho.last_modified_time;
        if lm_time != -1 {
            if let Ok(if_range_time) = parse_http_time(&if_range_val) {
                if if_range_time == lm_time {
                    return true;
                }
            }
        }
        return false;
    }
    true
}

fn parse_http_time(s: &[u8]) -> Result<i64, ()> {
    ngx_core::parse::parse_http_time(s).ok_or(())
}

#[derive(Debug)]
enum RangeParseError {
    NotSatisfiable,
    Declined,
    Error,
}

fn parse_ranges(input: &[u8], content_length: i64, max_ranges: usize) -> Result<Vec<RangeInfo>, RangeParseError> {
    let mut ranges = Vec::new();
    let mut p = input;
    let mut total_size = 0i64;

    const CUTOFF: i64 = i64::MAX / 10;
    const CUTLIM: i64 = i64::MAX % 10;

    loop {
        let mut start = 0i64;
        let mut end = 0i64;
        let mut suffix = false;

        // Skip spaces
        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if p.is_empty() {
            break;
        }

        // Parse start or check for suffix
        if p[0] == b'-' {
            suffix = true;
            p = &p[1..];
        } else if p[0] >= b'0' && p[0] <= b'9' {
            // Parse start
            while !p.is_empty() && p[0] >= b'0' && p[0] <= b'9' {
                if start >= CUTOFF && (start > CUTOFF || p[0] as i64 - b'0' as i64 > CUTLIM) {
                    return Err(RangeParseError::NotSatisfiable);
                }
                start = start * 10 + (p[0] as i64 - b'0' as i64);
                p = &p[1..];
            }

            // Skip spaces
            while !p.is_empty() && p[0] == b' ' {
                p = &p[1..];
            }

            if p.is_empty() || p[0] != b'-' {
                return Err(RangeParseError::NotSatisfiable);
            }
            p = &p[1..];

            // Skip spaces
            while !p.is_empty() && p[0] == b' ' {
                p = &p[1..];
            }

            if p.is_empty() || (p[0] != b',' && p[0] != b'\0') {
                if !(p.is_empty() || (p[0] >= b'0' && p[0] <= b'9')) {
                    return Err(RangeParseError::NotSatisfiable);
                }
            }

            if p.is_empty() || (p[0] != b',' && p[0] != b'\0') {
                // Parse end
                while !p.is_empty() && p[0] >= b'0' && p[0] <= b'9' {
                    if end >= CUTOFF && (end > CUTOFF || p[0] as i64 - b'0' as i64 > CUTLIM) {
                        return Err(RangeParseError::NotSatisfiable);
                    }
                    end = end * 10 + (p[0] as i64 - b'0' as i64);
                    p = &p[1..];
                }
            } else {
                end = content_length;
            }
        } else {
            return Err(RangeParseError::NotSatisfiable);
        }

        // Skip spaces
        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if !p.is_empty() && p[0] != b',' && p[0] != b'\0' {
            return Err(RangeParseError::NotSatisfiable);
        }

        // Process the range
        if suffix {
            start = if end < content_length { content_length - end } else { 0 };
            end = content_length - 1;
        } else {
            if end >= content_length {
                end = content_length;
            } else {
                end += 1;
            }
        }

        if start < end {
            total_size += end - start;
            ranges.push(RangeInfo {
                start,
                end,
                content_range: Vec::new(),
            });
            if ranges.len() >= max_ranges {
                return Err(RangeParseError::Declined);
            }
        } else if start == 0 {
            return Err(RangeParseError::Declined);
        }

        if p.is_empty() || p[0] != b',' {
            break;
        }
        p = &p[1..];
    }

    if ranges.is_empty() {
        return Err(RangeParseError::NotSatisfiable);
    }

    // Check if total size exceeds content length
    if ranges.len() > 1 {
        if total_size > content_length {
            return Err(RangeParseError::Declined);
        }
        // Additional check: if size + overhead exceeds source, decline multipart
        let overhead = ranges.len() as i64 * 256 + 4096;
        if total_size + overhead > content_length {
            return Err(RangeParseError::Declined);
        }
    }

    Ok(ranges)
}

async fn singlepart_header(r: &R, ranges: &[RangeInfo], next: HeaderFilter) -> i64 {
    if r != r.main {
        return next(r.clone()).await;
    }

    let content_length_n = r.headers_out.borrow().content_length_n;
    let range = &ranges[0];

    let content_range_val = format!("bytes {}-{}/{}", range.start, range.end - 1, content_length_n);

    {
        let mut ho = r.headers_out.borrow_mut();
        let h = ho.add(b"Content-Range", content_range_val.as_bytes());
        ho.content_range = Some(h);
        ho.content_length_n = range.end - range.start;
        ho.content_offset = range.start;
        if let Some(cl) = &ho.content_length {
            cl.hash.set(0);
        }
        ho.content_length = None;
    }

    next(r.clone()).await
}

async fn multipart_header(r: &R, ranges: &[RangeInfo], next: HeaderFilter) -> i64 {
    let content_type = r.headers_out.borrow().content_type.clone();
    let charset = r.headers_out.borrow().charset.clone();
    let content_type_len = r.headers_out.borrow().content_type_len;
    let content_length_n = r.headers_out.borrow().content_length_n;

    // Generate boundary
    let boundary = (ngx_core::atomic::next_temp_number(0) as u64).to_string();

    // Build boundary header
    let mut boundary_header = Vec::new();
    boundary_header.extend_from_slice(b"\r\n--");
    boundary_header.extend_from_slice(boundary.as_bytes());
    boundary_header.extend_from_slice(b"\r\nContent-Type: ");
    boundary_header.extend_from_slice(&content_type);
    if content_type_len == content_type.len() && !charset.is_empty() {
        boundary_header.extend_from_slice(b"; charset=");
        boundary_header.extend_from_slice(&charset);
    }
    boundary_header.extend_from_slice(b"\r\nContent-Range: bytes ");

    // Build individual range content_range headers and calculate total size
    let mut total_len = 0i64;
    let mut updated_ranges = Vec::new();
    for range in ranges {
        let range_header = format!("{}-{}/{}\r\n\r\n", range.start, range.end - 1, content_length_n);
        total_len += boundary_header.len() as i64 + range_header.len() as i64 + (range.end - range.start);
        updated_ranges.push(RangeInfo {
            start: range.start,
            end: range.end,
            content_range: range_header.into_bytes(),
        });
    }

    // Add final boundary
    total_len += boundary_header.len() as i64 + 4; // CRLF--CRLF

    // Set multipart Content-Type
    let multipart_ct = format!("multipart/byteranges; boundary={}", boundary);
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.content_type = multipart_ct.into_bytes();
        ho.content_type_len = ho.content_type.len();
        ho.charset.clear();
        ho.content_length_n = total_len;
        if let Some(cl) = &ho.content_length {
            cl.hash.set(0);
        }
        ho.content_length = None;
        if let Some(cr) = &ho.content_range {
            cr.hash.set(0);
        }
        ho.content_range = None;
    }

    // Store context
    let ctx = RangeFilterCtx {
        offset: 0,
        boundary_header,
        ranges: updated_ranges,
    };
    r.set_ctx(ctx_index(), ctx);

    next(r.clone()).await
}

async fn range_not_satisfiable(r: &R, next: HeaderFilter) -> i64 {
    let content_length_n = r.headers_out.borrow().content_length_n;
    let content_range_val = format!("bytes */{}", content_length_n);

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_RANGE_NOT_SATISFIABLE;
        let h = ho.add(b"Content-Range", content_range_val.as_bytes());
        ho.content_range = Some(h);
        ho.clear_content_length();
    }

    next(r.clone()).await
}

async fn range_body_filter(r: R, mut chain: Chain, next: BodyFilter) -> i64 {
    if chain.is_empty() {
        return next(r, chain).await;
    }

    let ctx = match r.get_ctx::<RangeFilterCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r, chain).await,
    };

    if ctx.ranges.len() == 1 {
        singlepart_body(r, chain, ctx, next).await
    } else {
        multipart_body(r, chain, ctx, next).await
    }
}

async fn singlepart_body(r: R, mut chain: Chain, mut ctx: RangeFilterCtx, next: BodyFilter) -> i64 {
    let range = &ctx.ranges[0].clone();
    let mut out = Chain::new();

    while let Some(mut buf) = chain.pop_front() {
        let size = if buf.in_file {
            buf.file_last - buf.file_pos
        } else if !buf.is_special() {
            (buf.last as usize - buf.pos as usize) as i64
        } else {
            0
        };
        let start = ctx.offset;
        let last = ctx.offset + size;

        ctx.offset = last;

        if buf.is_special() {
            out.push_back(buf);
            continue;
        }

        if range.end <= start || range.start >= last {
            // Outside range, skip
            if buf.in_file {
                buf.file_pos = buf.file_last;
            }
            buf.pos = buf.last;
            buf.sync = true;
            continue;
        }

        // Adjust start of buffer
        if range.start > start {
            if buf.in_file {
                buf.file_pos += range.start - start;
            }
            if buf.pos < buf.last {
                let offset = ((range.start - start).min(last - start)) as usize;
                buf.pos = unsafe { buf.pos.add(offset) };
            }
        }

        // Adjust end of buffer
        if range.end <= last {
            if buf.in_file {
                buf.file_last -= last - range.end;
            }
            if buf.pos < buf.last {
                let offset = ((last - range.end).min(last - start)) as usize;
                buf.last = unsafe { buf.last.sub(offset) };
            }
            buf.last_buf = if r == r.main { true } else { false };
            buf.last_in_chain = true;

            out.push_back(buf);
            break;
        }

        out.push_back(buf);
    }

    r.set_ctx(ctx_index(), ctx);
    next(r, out).await
}

async fn multipart_body(r: R, chain: Chain, ctx: RangeFilterCtx, next: BodyFilter) -> i64 {
    let buf = match chain.front() {
        Some(b) => b.clone(),
        None => return next(r, chain).await,
    };

    let mut out = Chain::new();

    for (i, range) in ctx.ranges.iter().enumerate() {
        // Boundary header
        let boundary_copy = ctx.boundary_header.clone();
        let hbuf = Buf::from_vec(boundary_copy);
        out.push_back(hbuf);

        // Content-Range header
        let range_copy = range.content_range.clone();
        let rbuf = Buf::from_vec(range_copy);
        out.push_back(rbuf);

        // Data
        let mut dbuf = buf.clone();
        if buf.in_file {
            dbuf.file_pos = buf.file_pos + range.start;
            dbuf.file_last = buf.file_pos + range.end;
        } else if !buf.is_special() {
            let size = (buf.last as usize - buf.pos as usize) as i64;
            let start_off = range.start.min(size).max(0) as usize;
            let end_off = range.end.min(size).max(0) as usize;
            dbuf.pos = unsafe { buf.pos.add(start_off) };
            dbuf.last = unsafe { buf.pos.add(end_off) };
        }
        if i == ctx.ranges.len() - 1 {
            dbuf.last_in_chain = true;
        }
        out.push_back(dbuf);
    }

    // Final boundary
    let boundary_str = String::from_utf8_lossy(&ctx.boundary_header);
    let boundary_num = boundary_str.split("--").nth(1).unwrap_or("");
    let final_boundary = format!("\r\n--{}--\r\n", boundary_num);
    let fbuf = Buf::from_vec(final_boundary.into_bytes());
    out.push_back(fbuf);

    next(r, out).await
}
