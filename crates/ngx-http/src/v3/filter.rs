//! ngx_http_v3_filter_module (nginx-c/src/http/v3/ngx_http_v3_filter_module.c):
//! the response header as a HEADERS frame, the body in DATA frames, the
//! trailers.

use std::io::Write;

use ngx_core::buf::{Buf, Chain};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_debug;

use super::encode::*;
use super::*;
use crate::core::{NGX_HTTP_SERVER_TOKENS_BUILD, NGX_HTTP_SERVER_TOKENS_ON};
use crate::request::{Header, R};
use crate::*;

crate::http_module_index!("ngx_http_v3_filter_module");

/* static table indices */
const NGX_HTTP_V3_HEADER_AUTHORITY: u64 = 0;
const NGX_HTTP_V3_HEADER_PATH_ROOT: u64 = 1;
const NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO: u64 = 4;
const NGX_HTTP_V3_HEADER_DATE: u64 = 6;
const NGX_HTTP_V3_HEADER_LAST_MODIFIED: u64 = 10;
const NGX_HTTP_V3_HEADER_LOCATION: u64 = 12;
const NGX_HTTP_V3_HEADER_METHOD_GET: u64 = 17;
const NGX_HTTP_V3_HEADER_SCHEME_HTTP: u64 = 22;
const NGX_HTTP_V3_HEADER_SCHEME_HTTPS: u64 = 23;
const NGX_HTTP_V3_HEADER_STATUS_103: u64 = 24;
const NGX_HTTP_V3_HEADER_STATUS_200: u64 = 25;
const NGX_HTTP_V3_HEADER_ACCEPT_ENCODING: u64 = 31;
const NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN: u64 = 53;
const NGX_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING: u64 = 59;
const NGX_HTTP_V3_HEADER_ACCEPT_LANGUAGE: u64 = 72;
const NGX_HTTP_V3_HEADER_SERVER: u64 = 92;
const NGX_HTTP_V3_HEADER_USER_AGENT: u64 = 95;

const NGINX_VER: &[u8] = b"nginx/1.31.7";
const NGINX_VER_BUILD: &[u8] = NGINX_VER;

/// ngx_http_v3_filter_ctx_t: the request gets its body in DATA frames
pub struct FilterCtx;

pub fn v3_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(filter_init), ..Default::default() };
    http_module_def("ngx_http_v3_filter_module", def, Vec::new())
}

/// ngx_http_v3_filter_init
fn filter_init(_cf: &mut ngx_core::conf::Conf) -> ngx_core::conf::ConfResult {
    // not an HTTP/3 request: passed on as it is
    crate::install_header_filter_idle(
        |r| r.http_version.get() != NGX_HTTP_VERSION_30,
        |r: R, next: HeaderFilter| async move {
            if r.http_version.get() != NGX_HTTP_VERSION_30 {
                return next(r).await;
            }

            header_filter(&r).await
        },
    );

    install_early_hints_filter(|r: R, next: HeaderFilter| async move {
        if r.http_version.get() != NGX_HTTP_VERSION_30 {
            return next(r).await;
        }

        early_hints_filter(&r).await
    });

    crate::install_body_filter_idle(|r, chain| chain.is_empty() || !r.has_ctx(ctx_index()), body_filter);

    Ok(())
}

/// ngx_http_v3_header_filter
async fn header_filter(r: &R) -> i64 {
    if r.header_sent.get() {
        return NGX_OK;
    }

    r.header_sent.set(true);

    if !r.is_main() {
        return NGX_OK;
    }

    let c = r.connection.clone();

    let h3c = match get_session(&c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    if r.method.get() == NGX_HTTP_HEAD {
        r.header_only.set(true);
    }

    {
        let mut ho = r.headers_out.borrow_mut();

        if ho.last_modified_time != -1 && ho.status != NGX_HTTP_OK && ho.status != NGX_HTTP_PARTIAL_CONTENT && ho.status != NGX_HTTP_NOT_MODIFIED {
            ho.last_modified_time = -1;
            ho.last_modified = None;
        }

        if ho.status == NGX_HTTP_NO_CONTENT {
            r.header_only.set(true);
            ho.content_type.clear();
            ho.content_type_len = 0;
            ho.last_modified_time = -1;
            ho.last_modified = None;
            ho.content_length = None;
            ho.content_length_n = -1;
        }

        if ho.status == NGX_HTTP_NOT_MODIFIED {
            r.header_only.set(true);
        }
    }

    let clcf = r.clcf();

    let (server_tokens, absolute_redirect, server_name_in_redirect, port_in_redirect, gzip_vary) = {
        let cl = clcf.borrow();
        (*cl.server_tokens, *cl.absolute_redirect, *cl.server_name_in_redirect, *cl.port_in_redirect, *cl.gzip_vary)
    };

    // the location made absolute, as the length computation does it
    let location = r.headers_out.borrow().location.clone();

    if let Some(loc) = &location {
        let v = loc.value.borrow().clone();

        if !v.is_empty() {
            if v[0] == b'/' && absolute_redirect {
                let host: Vec<u8> = if server_name_in_redirect {
                    r.cscf().borrow().server_name.clone()
                } else {
                    let s = r.headers_in.borrow().server.clone();

                    if !s.is_empty() {
                        s
                    } else {
                        match c.local_sockaddr() {
                            Some(local) => local.addr_text(),
                            None => return NGX_ERROR,
                        }
                    }
                };

                let mut port = c.local_sockaddr().map(|a| a.port()).unwrap_or(0);

                if port_in_redirect {
                    if port == 443 {
                        port = 0;
                    }
                } else {
                    port = 0;
                }

                let mut value = b"https://".to_vec();
                value.extend_from_slice(&host);

                if port != 0 {
                    value.extend_from_slice(format!(":{}", port).as_bytes());
                }

                value.extend_from_slice(&v);

                /* update r->headers_out.location->value for possible logging */

                *loc.value.borrow_mut() = value;
            }

            loc.hash.set(0);
        }
    }

    if r.gzip_vary.get() && !gzip_vary {
        r.gzip_vary.set(false);
    }

    let (server, date) = {
        let ho = r.headers_out.borrow();
        (ho.server.is_none(), ho.date.is_none())
    };

    let len = header_len(r, &location, server, date);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 header len:{}", len);

    // one buffer: the HEADERS frame header goes in front of the field
    // section (room for it reserved), the DATA frame header of the body
    // behind it; C has three, with the same bytes
    const HEAD: usize = 2 * NGX_HTTP_V3_VARLEN_INT_LEN;

    let mut b: Vec<u8> = Vec::with_capacity(HEAD + len + HEAD);

    b.resize(HEAD, 0);

    encode_field_section_prefix(&mut b, 0, false, 0);

    let status = r.headers_out.borrow().status;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \":status: {:03}\"", status);

    if status == NGX_HTTP_OK {
        encode_field_ri(&mut b, false, NGX_HTTP_V3_HEADER_STATUS_200);
    } else {
        encode_field_lri(&mut b, false, NGX_HTTP_V3_HEADER_STATUS_200, None, 3);
        let _ = write!(b, "{:03}", status);
    }

    if server {
        let p: &[u8] = if server_tokens == NGX_HTTP_SERVER_TOKENS_ON {
            NGINX_VER
        } else if server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD {
            NGINX_VER_BUILD
        } else {
            b"nginx"
        };

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"server: {}\"", B(p));

        encode_field_lri(&mut b, false, NGX_HTTP_V3_HEADER_SERVER, Some(p), p.len());
    }

    if date {
        let t = ngx_core::times::cached_http_time();

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"date: {}\"", t);

        encode_field_lri(&mut b, false, NGX_HTTP_V3_HEADER_DATE, Some(t.as_bytes()), t.len());
    }

    {
        let mut ho = r.headers_out.borrow_mut();

        if !ho.content_type.is_empty() {
            if ho.content_type_len == ho.content_type.len() && !ho.charset.is_empty() {
                /* updated r->headers_out.content_type is also needed for logging */

                let charset = std::mem::take(&mut ho.charset);
                ho.content_type.extend_from_slice(b"; charset=");
                ho.content_type.extend_from_slice(&charset);
                ho.charset = charset;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"content-type: {}\"", B(&ho.content_type));

            encode_field_lri(&mut b, false, NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN, Some(&ho.content_type), ho.content_type.len());
        }

        if ho.content_length.is_none() && ho.content_length_n >= 0 {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"content-length: {}\"", ho.content_length_n);

            if ho.content_length_n > 0 {
                let mut v = [0u8; 20];
                let v = dec(&mut v, ho.content_length_n);

                encode_field_lri(&mut b, false, NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO, None, v.len());

                b.extend_from_slice(v);
            } else {
                encode_field_ri(&mut b, false, NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO);
            }
        }

        if ho.last_modified.is_none() && ho.last_modified_time != -1 {
            let tb = ngx_core::times::http_time_bytes(ho.last_modified_time);
            let t = &tb[..];

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"last-modified: {}\"", B(t));

            encode_field_lri(&mut b, false, NGX_HTTP_V3_HEADER_LAST_MODIFIED, Some(t), t.len());
        }
    }

    if let Some(loc) = &location {
        let v = loc.value.borrow();

        if !v.is_empty() {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"location: {}\"", B(&v));

            encode_field_lri(&mut b, false, NGX_HTTP_V3_HEADER_LOCATION, Some(&v), v.len());
        }
    }

    // NGX_HTTP_GZIP
    if r.gzip_vary.get() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"vary: Accept-Encoding\"");

        encode_field_ri(&mut b, false, NGX_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING);
    }

    for h in r.headers_out.borrow().headers.iter() {
        if h.hash.get() == 0 {
            continue;
        }

        let value = h.value.borrow();

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"{}: {}\"", B(&h.key), B(&value));

        encode_field_l(&mut b, &h.key, &value);
    }

    let n = b.len() - HEAD;

    h3c.payload_bytes.set(h3c.payload_bytes.get() + n as i64);

    // the HEADERS frame header, right before the field section
    let (hl, hn) = varlen_ints_bytes(NGX_HTTP_V3_FRAME_HEADERS, n as u64);
    let start = HEAD - hn;
    b[start..HEAD].copy_from_slice(&hl[..hn]);

    let content_length_n = r.headers_out.borrow().content_length_n;

    let data = content_length_n >= 0 && !r.header_only.get() && !r.expect_trailers.get();

    if data {
        encode_varlen_int(&mut b, NGX_HTTP_V3_FRAME_DATA);
        encode_varlen_int(&mut b, content_length_n as u64);

        h3c.payload_bytes.set(h3c.payload_bytes.get() + content_length_n);
        h3c.total_bytes.set(h3c.total_bytes.get() + content_length_n);
    } else {
        r.set_ctx(ctx_index(), FilterCtx);
    }

    let mut hb = Buf::from_vec(b);
    hb.pos = start;

    if r.header_only.get() {
        hb.last_buf = true;
    }

    let mut out = Chain::new();

    out.push_back(hb);

    for cl in out.iter() {
        let len = cl.last - cl.pos;
        h3c.total_bytes.set(h3c.total_bytes.get() + len as i64);
        r.header_size.set(r.header_size.get() + len);
    }

    crate::write_filter::write_filter(r.clone(), out).await
}

/// The len computed by ngx_http_v3_header_filter before it encodes the
/// header (for its debug message): the literal lengths, not the Huffman
/// coded ones.
fn header_len(r: &R, location: &Option<Header>, server: bool, date: bool) -> usize {
    let mut len = field_section_prefix_len(0, false, 0);

    let ho = r.headers_out.borrow();

    if ho.status == NGX_HTTP_OK {
        len += field_ri_len(false, NGX_HTTP_V3_HEADER_STATUS_200);
    } else {
        len += field_lri_len(false, NGX_HTTP_V3_HEADER_STATUS_200, 3);
    }

    if server {
        let clcf = r.clcf();
        let st = *clcf.borrow().server_tokens;

        let n = if st == NGX_HTTP_SERVER_TOKENS_ON {
            NGINX_VER.len()
        } else if st == NGX_HTTP_SERVER_TOKENS_BUILD {
            NGINX_VER_BUILD.len()
        } else {
            b"nginx".len()
        };

        len += field_lri_len(false, NGX_HTTP_V3_HEADER_SERVER, n);
    }

    if date {
        len += field_lri_len(false, NGX_HTTP_V3_HEADER_DATE, ngx_core::times::cached_http_time().len());
    }

    if !ho.content_type.is_empty() {
        let mut n = ho.content_type.len();

        if ho.content_type_len == ho.content_type.len() && !ho.charset.is_empty() {
            n += b"; charset=".len() + ho.charset.len();
        }

        len += field_lri_len(false, NGX_HTTP_V3_HEADER_CONTENT_TYPE_TEXT_PLAIN, n);
    }

    if ho.content_length.is_none() {
        if ho.content_length_n > 0 {
            // NGX_OFF_T_LEN
            len += field_lri_len(false, NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO, "-9223372036854775808".len());
        } else if ho.content_length_n == 0 {
            len += field_ri_len(false, NGX_HTTP_V3_HEADER_CONTENT_LENGTH_ZERO);
        }
    }

    if ho.last_modified.is_none() && ho.last_modified_time != -1 {
        len += field_lri_len(false, NGX_HTTP_V3_HEADER_LAST_MODIFIED, b"Mon, 28 Sep 1970 06:00:00 GMT".len());
    }

    if let Some(loc) = location {
        let v = loc.value.borrow();

        if !v.is_empty() {
            len += field_lri_len(false, NGX_HTTP_V3_HEADER_LOCATION, v.len());
        }
    }

    if r.gzip_vary.get() {
        len += field_ri_len(false, NGX_HTTP_V3_HEADER_VARY_ACCEPT_ENCODING);
    }

    for h in ho.headers.iter() {
        if h.hash.get() == 0 {
            continue;
        }

        len += field_l_len(&h.key, &h.value.borrow());
    }

    len
}

/// ngx_http_v3_early_hints_filter
async fn early_hints_filter(r: &R) -> i64 {
    if !r.is_main() {
        return NGX_OK;
    }

    let c = r.connection.clone();

    let headers: Vec<(Vec<u8>, Vec<u8>)> = r.headers_out.borrow().headers.iter().filter(|h| h.hash.get() != 0).map(|h| (h.key.clone(), h.value.borrow().clone())).collect();

    let mut len: usize = headers.iter().map(|(k, v)| field_l_len(k, v)).sum();

    if len == 0 {
        return NGX_OK;
    }

    len += field_section_prefix_len(0, false, 0);

    len += field_ri_len(false, NGX_HTTP_V3_HEADER_STATUS_103);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 header len:{}", len);

    let mut b: Vec<u8> = Vec::with_capacity(len);

    encode_field_section_prefix(&mut b, 0, false, 0);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \":status: {:03}\"", NGX_HTTP_EARLY_HINTS);

    encode_field_ri(&mut b, false, NGX_HTTP_V3_HEADER_STATUS_103);

    for (key, value) in headers.iter() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 output header: \"{}: {}\"", B(key), B(value));

        encode_field_l(&mut b, key, value);
    }

    let n = b.len();

    let h3c = match get_session(&c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    h3c.payload_bytes.set(h3c.payload_bytes.get() + n as i64);

    let mut hl = Vec::new();

    encode_varlen_int(&mut hl, NGX_HTTP_V3_FRAME_HEADERS);
    encode_varlen_int(&mut hl, n as u64);

    let mut out = Chain::new();

    out.push_back(Buf::from_vec(hl));

    let mut hb = Buf::from_vec(b);
    hb.flush = true;
    out.push_back(hb);

    for cl in out.iter() {
        let len = cl.last - cl.pos;
        h3c.total_bytes.set(h3c.total_bytes.get() + len as i64);
        r.header_size.set(r.header_size.get() + len);
    }

    crate::write_filter::write_filter(r.clone(), out).await
}

/// ngx_http_v3_body_filter
async fn body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    if input.is_empty() {
        return next(r, input).await;
    }

    if r.get_ctx::<FilterCtx>(ctx_index()).is_none() {
        return next(r, input).await;
    }

    let h3c = match get_session(&r.connection) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    let mut out = Chain::new();

    let mut size: i64 = 0;

    let mut last_buf = false;

    let n = input.len();

    for (i, b) in input.into_iter().enumerate() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 chunk: {}", b.buf_size());

        size += b.buf_size();

        if i == n - 1 && b.last_buf {
            last_buf = true;
        }

        if b.flush || b.sync || b.in_memory() || b.in_file {
            out.push_back(b);
        }
    }

    if size != 0 {
        let mut chunk = Vec::with_capacity(NGX_HTTP_V3_VARLEN_INT_LEN * 2);

        encode_varlen_int(&mut chunk, NGX_HTTP_V3_FRAME_DATA);
        encode_varlen_int(&mut chunk, size as u64);

        out.push_front(Buf::from_vec(chunk));

        h3c.payload_bytes.set(h3c.payload_bytes.get() + size);
    }

    if last_buf {
        // cl->buf->last_buf = 0: the trailers end the stream
        if let Some(b) = out.iter_mut().rev().find(|b| b.last_buf) {
            b.last_buf = false;
        }

        let tl = create_trailers(&r, &h3c);

        for b in tl {
            out.push_back(b);
        }
    }

    for b in out.iter() {
        h3c.total_bytes.set(h3c.total_bytes.get() + (b.last - b.pos) as i64);
    }

    next(r, out).await
}

/// ngx_http_v3_create_trailers: the trailers HEADERS frame (if any) and
/// the last buffer
fn create_trailers(r: &R, h3c: &H3Session) -> Vec<Buf> {
    let trailers: Vec<(Vec<u8>, Vec<u8>)> = r.headers_out.borrow().trailers.iter().filter(|h| h.hash.get() != 0).map(|h| (h.key.clone(), h.value.borrow().clone())).collect();

    let len: usize = trailers.iter().map(|(k, v)| field_l_len(k, v)).sum();

    let mut cl = Buf::default();
    cl.last_buf = true;

    if len == 0 {
        return vec![cl];
    }

    let mut b = Vec::with_capacity(len + field_section_prefix_len(0, false, 0));

    encode_field_section_prefix(&mut b, 0, false, 0);

    for (key, value) in trailers.iter() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 output trailer: \"{}: {}\"", B(key), B(value));

        encode_field_l(&mut b, key, value);
    }

    let n = b.len();

    h3c.payload_bytes.set(h3c.payload_bytes.get() + n as i64);

    cl = Buf::from_vec(b);
    cl.last_buf = true;

    let mut hl = Vec::with_capacity(NGX_HTTP_V3_VARLEN_INT_LEN * 2);

    encode_varlen_int(&mut hl, NGX_HTTP_V3_FRAME_HEADERS);
    encode_varlen_int(&mut hl, n as u64);

    vec![Buf::from_vec(hl), cl]
}

#[allow(dead_code)]
fn _unused() -> [u64; 9] {
    [
        NGX_HTTP_V3_HEADER_AUTHORITY,
        NGX_HTTP_V3_HEADER_PATH_ROOT,
        NGX_HTTP_V3_HEADER_METHOD_GET,
        NGX_HTTP_V3_HEADER_SCHEME_HTTP,
        NGX_HTTP_V3_HEADER_SCHEME_HTTPS,
        NGX_HTTP_V3_HEADER_ACCEPT_ENCODING,
        NGX_HTTP_V3_HEADER_ACCEPT_LANGUAGE,
        NGX_HTTP_V3_HEADER_USER_AGENT,
        NGX_HTTP_V3_HEADER_STATUS_103,
    ]
}
