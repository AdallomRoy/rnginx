//! ngx_http_range_filter_module - handles HTTP Range requests (206 Partial Content)

use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::request::*;
use crate::*;

// Use body filter module name for the shared context index
crate::http_module_index!("ngx_http_range_body_filter_module");

/// Range element: start-end (both inclusive for end in response, exclusive in code)
#[derive(Clone, Debug)]
struct Range {
    start: i64,
    end: i64,
    content_range: Vec<u8>,
}

/// Context for range filtering
struct RangeCtx {
    offset: i64,
    boundary_header: Vec<u8>,
    ranges: Vec<Range>,
}

pub fn range_header_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init_header),
        ..Default::default()
    };
    http_module_def("ngx_http_range_header_filter_module", def, Vec::new())
}

pub fn range_body_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init_body),
        ..Default::default()
    };
    http_module_def("ngx_http_range_body_filter_module", def, Vec::new())
}

fn init_header(cf: &mut Conf) -> ConfResult {
    ngx_core::ngx_log_error!(NGX_LOG_NOTICE, &cf.log, None, "range_header_filter_module init_header called");
    install_header_filter(|r, next| async move { range_header_filter(r, next).await });
    Ok(())
}

fn init_body(_cf: &mut Conf) -> ConfResult {
    install_body_filter(|r, chain, next| async move { range_body_filter(r, chain, next).await });
    Ok(())
}

async fn range_header_filter(r: R, next: HeaderFilter) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_header_filter called");

    // Check preconditions
    if r.http_version.get() < NGX_HTTP_VERSION_10 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_header_filter: http_version too old");
        return next(r).await;
    }

    let status = r.headers_out.borrow().status;
    let content_len_n = r.headers_out.borrow().content_length_n;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_header_filter: status={}, content_len_n={}, allow_ranges={}", status, content_len_n, r.allow_ranges.get());

    if status != NGX_HTTP_OK || content_len_n == -1 || !r.allow_ranges.get() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_header_filter: preconditions failed");
        return next(r).await;
    }

    if !r.is_main() && !r.subrequest_ranges.get() {
        return next(r).await;
    }

    let clcf = r.clcf();
    let max_ranges = *clcf.borrow().max_ranges;
    if max_ranges == 0 {
        return next(r).await;
    }

    // Extract range header and metadata
    let (range_header, if_range_val, content_length) = {
        let headers_in = r.headers_in.borrow();
        let rh = headers_in.range.first().map(|h| h.value());
        let ifr = headers_in.if_range.as_ref().map(|h| h.value());
        drop(headers_in);
        let cl = r.headers_out.borrow().content_length_n;
        (rh, ifr, cl)
    };

    let range_header = match range_header {
        Some(h) => h,
        None => return set_accept_ranges_and_pass(r, next).await,
    };

    if range_header.len() < 7 || &range_header[..6] != b"bytes=" {
        return set_accept_ranges_and_pass(r, next).await;
    }

    // Handle If-Range - check upfront
    if let Some(val) = &if_range_val {
        if val.len() >= 2 && val[val.len() - 1] == b'"' {
            // ETag comparison
            let etag_val = r.headers_out.borrow().etag.as_ref().map(|h| h.value());
            if etag_val.as_ref() != Some(val) {
                return set_accept_ranges_and_pass(r, next).await;
            }
        } else {
            // Date comparison against Last-Modified.
            let lm_time = r.headers_out.borrow().last_modified_time;
            match ngx_core::parse::parse_http_time(val) {
                Some(t) if t == lm_time => {}
                _ => return set_accept_ranges_and_pass(r, next).await,
            }
        }
    }
    let mut ctx = RangeCtx {
        offset: 0,
        boundary_header: Vec::new(),
        ranges: Vec::new(),
    };

    match parse_ranges(&range_header[6..], content_length, max_ranges, &mut ctx.ranges) {
        Ok(()) => {
            if ctx.ranges.is_empty() {
                return range_not_satisfiable(r, next).await;
            }

            // Set status to 206 Partial Content
            r.headers_out.borrow_mut().status = NGX_HTTP_PARTIAL_CONTENT;
            r.headers_out.borrow_mut().status_line.clear();

            if ctx.ranges.len() == 1 {
                // Single-part range
                let range = &ctx.ranges[0];
                r.headers_out.borrow_mut().content_length_n = range.end - range.start;
                r.headers_out.borrow_mut().content_offset = range.start;

                // Set Content-Range header
                let content_range_str = format!("bytes {}-{}/{}", range.start, range.end - 1, content_length);
                {
                    let mut ho = r.headers_out.borrow_mut();
                    if let Some(h) = ho.content_range.take() {
                        h.hash.set(0);
                    }
                    // Drop any Content-Range that the upstream response
                    // carried through into ho.headers so we don't emit
                    // both our fresh one and the stale one. Matches
                    // range_clearing.t.
                    ho.headers.retain(|h| !h.lowcase_key.eq_ignore_ascii_case(b"content-range"));
                }
                let cr_header = TableElt::new(b"Content-Range", content_range_str.as_bytes());
                {
                    let mut ho = r.headers_out.borrow_mut();
                    ho.headers.push(cr_header.clone());
                    ho.content_range = Some(cr_header);
                }

                // Remove Content-Length header from list (will be set by core)
                if let Some(h) = r.headers_out.borrow_mut().content_length.take() {
                    h.hash.set(0);
                }
            } else {
                // Multipart range - build boundary header
                let boundary = simple_random();
                ctx.boundary_header = format!("\r\n--{:x}\r\nContent-Type: ", boundary).into_bytes();

                // Compute total content length for multipart
                let mut total_len = 0i64;
                for range in &ctx.ranges {
                    total_len += ctx.boundary_header.len() as i64;
                    total_len += 100; // rough estimate for Content-Range header
                    total_len += range.end - range.start;
                    total_len += 2; // \r\n
                }
                total_len += 4 + format!("{:x}", boundary).len() as i64 + 4; // closing boundary

                r.headers_out.borrow_mut().content_length_n = total_len;

                // Set Content-Type to multipart
                let content_type = format!("multipart/byteranges; boundary={:x}", boundary);
                {
                    let mut ho = r.headers_out.borrow_mut();
                    ho.content_type = content_type.into_bytes();
                    // Strip any Content-Range the upstream carried
                    // through — each body part now carries its own.
                    ho.headers.retain(|h| !h.lowcase_key.eq_ignore_ascii_case(b"content-range"));
                    if let Some(h) = ho.content_range.take() {
                        h.hash.set(0);
                    }
                    if let Some(h) = ho.content_length.take() {
                        h.hash.set(0);
                    }
                }
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_header_filter: setting 206, ranges={}, first_range={:?}-{:?}",
                ctx.ranges.len(),
                if !ctx.ranges.is_empty() { ctx.ranges[0].start } else { 0 },
                if !ctx.ranges.is_empty() { ctx.ranges[0].end } else { 0 });
            r.set_ctx(ctx_index(), ctx);
            next(r).await
        }
        Err(NGX_HTTP_RANGE_NOT_SATISFIABLE) => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_header_filter: 416 not satisfiable");
            range_not_satisfiable(r, next).await
        },
        Err(_) => set_accept_ranges_and_pass(r, next).await,
    }
}

async fn set_accept_ranges_and_pass(r: R, next: HeaderFilter) -> i64 {
    let mut ho = r.headers_out.borrow_mut();
    if ho.accept_ranges.is_none() {
        let ar = TableElt::new(b"Accept-Ranges", b"bytes");
        // Also push into the general headers list so $sent_http_accept_ranges
        // can find it (C sets both r->headers_out.accept_ranges and the same
        // ngx_list_push entry in headers_out.headers).
        ho.headers.push(ar.clone());
        ho.accept_ranges = Some(ar);
    }
    drop(ho);
    next(r).await
}

async fn range_not_satisfiable(r: R, next: HeaderFilter) -> i64 {
    let content_len = r.headers_out.borrow().content_length_n;
    r.headers_out.borrow_mut().status = NGX_HTTP_RANGE_NOT_SATISFIABLE;

    let content_range_str = format!("bytes */{}", content_len);
    let cr_header = TableElt::new(b"Content-Range", content_range_str.as_bytes());

    let mut ho = r.headers_out.borrow_mut();
    if let Some(h) = ho.content_range.take() {
        h.hash.set(0);
    }
    ho.headers.retain(|h| !h.lowcase_key.eq_ignore_ascii_case(b"content-range"));
    ho.headers.push(cr_header.clone());
    ho.content_range = Some(cr_header);
    drop(ho);

    r.clear_content_length();
    next(r).await
}

async fn range_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx = match r.get_ctx::<RangeCtx>(ctx_index()) {
        Some(c) => c,
        None => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_body_filter: no context, passing through");
            return next(r, input).await;
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_body_filter: input_empty={}, input_chain_len={}", input.is_empty(), input.len());

    if input.is_empty() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_body_filter: empty input, passing through");
        return next(r, input).await;
    }

    let is_single = ctx.borrow().ranges.len() == 1;
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_body_filter: is_single={}", is_single);

    if is_single {
        range_singlepart_body(r, input, next, ctx).await
    } else {
        range_multipart_body(r, input, next, ctx).await
    }
}

async fn range_singlepart_body(r: R, mut input: Chain, next: BodyFilter, ctx: Rc<RefCell<RangeCtx>>) -> i64 {
    let (range, offset) = {
        let c = ctx.borrow();
        (c.ranges[0].clone(), c.offset)
    };
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_singlepart_body: range={}-{}, offset={}", range.start, range.end, offset);

    let mut output = Chain::new();
    let mut offset = offset;

    while let Some(mut buf) = input.pop_front() {
        let buf_size = buf.buf_size();
        let buf_end = offset + buf_size;
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_singlepart_body: buf offset={}-{}, size={}, in_file={}, last_buf={}",
            offset, buf_end, buf_size, buf.in_file, buf.last_buf);

        if buf_size == 0 || (buf.sync && !buf.in_memory() && !buf.in_file) {
            // Special buffer (flush, last, etc.)
            if range.end <= offset {
                // Skip special buffers before range
                continue;
            }
            output.push_back(buf);
        } else if buf_end <= range.start || offset >= range.end {
            // Buffer completely outside range - skip
            if buf.in_file {
                buf.file_pos = buf.file_last;
            }
            buf.pos = buf.last;
            buf.sync = true;
        } else {
            // Buffer overlaps range - trim it
            if offset < range.start {
                let skip = range.start - offset;
                if buf.in_memory() {
                    buf.pos += skip as usize;
                }
                if buf.in_file {
                    buf.file_pos += skip;
                }
            }

            if buf_end > range.end {
                let skip = buf_end - range.end;
                if buf.in_memory() {
                    buf.last -= skip as usize;
                }
                if buf.in_file {
                    buf.file_last -= skip;
                }
            }

            // Mark last buffer in range
            if buf_end >= range.end {
                buf.last_buf = r.is_main();
                buf.last_in_chain = true;
            }

            output.push_back(buf);
        }

        offset = buf_end;
    }

    // Update context offset for next call
    ctx.borrow_mut().offset = offset;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "range_singlepart_body: output {} buffers, total_offset={}", output.len(), offset);
    next(r, output).await
}

async fn range_multipart_body(r: R, mut input: Chain, next: BodyFilter, ctx: Rc<RefCell<RangeCtx>>) -> i64 {
    let mut output = Chain::new();
    let mut all_data = Vec::new();
    let mut has_file = false;

    // Collect all data
    while let Some(buf) = input.pop_front() {
        if buf.in_file {
            has_file = true;
            // For file buffers, read the data
            if let BufData::File(f) = &buf.data {
                let mut file_data = vec![0u8; (buf.file_last - buf.file_pos) as usize];
                let n = unsafe { libc::pread(f.fd, file_data.as_mut_ptr() as *mut libc::c_void, file_data.len(), buf.file_pos as libc::off_t) };
                if n > 0 {
                    all_data.extend_from_slice(&file_data[..n as usize]);
                }
            }
        } else if buf.in_memory() {
            if let BufData::Memory(m) = &buf.data {
                all_data.extend_from_slice(&m[buf.pos..buf.last]);
            }
        }
    }

    if all_data.is_empty() && !has_file {
        return next(r, output).await;
    }

    let boundary_header = {
        let c = ctx.borrow();
        c.boundary_header.clone()
    };
    let ranges = {
        let c = ctx.borrow();
        c.ranges.clone()
    };

    // Build multipart response
    for (i, range) in ranges.iter().enumerate() {
        if i > 0 {
            output.push_back(Buf::from_vec(b"\r\n".to_vec()));
        }

        // Boundary
        output.push_back(Buf::from_vec(boundary_header.clone()));

        // Content-Range
        output.push_back(Buf::from_vec(range.content_range.clone()));

        // Data slice
        if !all_data.is_empty() {
            let start = range.start as usize;
            let end = (range.end as usize).min(all_data.len());
            if start < end {
                output.push_back(Buf::from_vec(all_data[start..end].to_vec()));
            }
        }
    }

    // Final boundary
    let boundary_num = format!("{:x}", simple_random());
    let final_boundary = format!("\r\n--{}--\r\n", boundary_num);
    let mut final_buf = Buf::from_vec(final_boundary.into_bytes());
    final_buf.last_buf = r.is_main();
    final_buf.last_in_chain = true;
    output.push_back(final_buf);

    next(r, output).await
}

fn parse_ranges(range_str: &[u8], content_len: i64, max_ranges: i64, ranges: &mut Vec<Range>) -> Result<(), i64> {
    let s = String::from_utf8_lossy(range_str);
    let parts: Vec<&str> = s.split(',').collect();

    let mut total_size = 0i64;
    let mut remaining = max_ranges;

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let range_parts: Vec<&str> = part.split('-').collect();
        if range_parts.len() != 2 {
            return Err(NGX_HTTP_RANGE_NOT_SATISFIABLE);
        }

        let start: i64;
        let end: i64;

        if range_parts[0].is_empty() {
            // Suffix range: "-500"
            let suffix_len: i64 = range_parts[1].parse().map_err(|_| NGX_HTTP_RANGE_NOT_SATISFIABLE)?;
            start = (content_len - suffix_len).max(0);
            end = content_len;
        } else {
            start = range_parts[0].parse().map_err(|_| NGX_HTTP_RANGE_NOT_SATISFIABLE)?;
            if start < 0 || start >= content_len {
                continue;
            }

            end = if range_parts[1].is_empty() {
                content_len
            } else {
                let e: i64 = range_parts[1].parse().map_err(|_| NGX_HTTP_RANGE_NOT_SATISFIABLE)?;
                (e + 1).min(content_len)
            };
        }

        if start >= end {
            continue;
        }

        total_size += end - start;
        if total_size > content_len {
            return Err(NGX_DECLINED);
        }

        if remaining <= 0 {
            // Exceeded max_ranges — matches C: return NGX_DECLINED (serve full body).
            return Err(NGX_DECLINED);
        }
        remaining -= 1;

        let content_range = format!("bytes {}-{}/{}\r\n\r\n", start, end - 1, content_len);
        ranges.push(Range { start, end, content_range: content_range.into_bytes() });
    }

    if ranges.is_empty() {
        return Err(NGX_HTTP_RANGE_NOT_SATISFIABLE);
    }

    Ok(())
}

fn simple_random() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let nanos = dur.subsec_nanos();
    nanos ^ (nanos >> 16)
}
