//! ngx_http_header_filter_module

use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::core::*;
use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_header_filter_module");

pub fn header_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_header_filter_module", def, Vec::new())
}

fn init(_cf: &mut Conf) -> ConfResult {
    set_top_header_filter(Rc::new(|r| Box::pin(header_filter(r))));
    Ok(())
}

pub const SERVER_STRING: &[u8] = b"Server: nginx\r\n";
pub const SERVER_FULL_STRING: &[u8] = b"Server: nginx/1.31.7\r\n";
pub const SERVER_BUILD_STRING: &[u8] = b"Server: nginx/1.31.7\r\n";

static STATUS_LINES: &[(i64, &str)] = &[
    (200, "200 OK"),
    (201, "201 Created"),
    (202, "202 Accepted"),
    (204, "204 No Content"),
    (206, "206 Partial Content"),
    (301, "301 Moved Permanently"),
    (302, "302 Moved Temporarily"),
    (303, "303 See Other"),
    (304, "304 Not Modified"),
    (307, "307 Temporary Redirect"),
    (308, "308 Permanent Redirect"),
    (400, "400 Bad Request"),
    (401, "401 Unauthorized"),
    (402, "402 Payment Required"),
    (403, "403 Forbidden"),
    (404, "404 Not Found"),
    (405, "405 Not Allowed"),
    (406, "406 Not Acceptable"),
    (408, "408 Request Time-out"),
    (409, "409 Conflict"),
    (410, "410 Gone"),
    (411, "411 Length Required"),
    (412, "412 Precondition Failed"),
    (413, "413 Request Entity Too Large"),
    (414, "414 Request-URI Too Large"),
    (415, "415 Unsupported Media Type"),
    (416, "416 Requested Range Not Satisfiable"),
    (421, "421 Misdirected Request"),
    (429, "429 Too Many Requests"),
    (500, "500 Internal Server Error"),
    (501, "501 Not Implemented"),
    (502, "502 Bad Gateway"),
    (503, "503 Service Temporarily Unavailable"),
    (504, "504 Gateway Time-out"),
    (505, "505 HTTP Version Not Supported"),
    (507, "507 Insufficient Storage"),
];

pub fn status_line(status: i64) -> Option<&'static str> {
    STATUS_LINES.iter().find(|(s, _)| *s == status).map(|(_, l)| *l)
}

/// ngx_http_header_filter
pub async fn header_filter(r: R) -> i64 {
    if r.header_sent.get() {
        return NGX_OK;
    }
    r.header_sent.set(true);
    if !r.is_main() {
        return NGX_OK;
    }
    if r.http_version.get() < NGX_HTTP_VERSION_10 {
        return NGX_OK;
    }
    if r.method.get() == NGX_HTTP_HEAD {
        r.header_only.set(true);
    }
    let clcf = r.clcf();
    let mut out: Vec<u8> = Vec::with_capacity(512);
    {
        let mut ho = r.headers_out.borrow_mut();
        if ho.last_modified_time != -1 && ho.status != NGX_HTTP_OK && ho.status != NGX_HTTP_PARTIAL_CONTENT && ho.status != NGX_HTTP_NOT_MODIFIED {
            ho.last_modified_time = -1;
            if let Some(lm) = ho.last_modified.take() {
                lm.hash.set(0);
            }
        }
        if ho.status == NGX_HTTP_NO_CONTENT {
            r.header_only.set(true);
            ho.content_type_len = 0;
            ho.content_type.clear();
            ho.content_length_n = -1;
            if let Some(cl) = ho.content_length.take() {
                cl.hash.set(0);
            }
            if let Some(lm) = ho.last_modified.take() {
                lm.hash.set(0);
            }
            ho.last_modified_time = -1;
        }
        if ho.status == NGX_HTTP_NOT_MODIFIED {
            r.header_only.set(true);
        }
        out.extend_from_slice(b"HTTP/1.1 ");
        let status = ho.status;
        if !ho.status_line.is_empty() {
            out.extend_from_slice(&ho.status_line);
        } else if let Some(l) = status_line(status) {
            out.extend_from_slice(l.as_bytes());
        } else {
            out.extend_from_slice(format!("{} ", status).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }
    {
        let ho = r.headers_out.borrow();
        let cl = clcf.borrow();
        if ho.server.is_none() {
            match *cl.server_tokens {
                NGX_HTTP_SERVER_TOKENS_ON => out.extend_from_slice(SERVER_FULL_STRING),
                NGX_HTTP_SERVER_TOKENS_BUILD => out.extend_from_slice(SERVER_BUILD_STRING),
                _ => out.extend_from_slice(SERVER_STRING),
            }
        }
        if ho.date.is_none() {
            out.extend_from_slice(b"Date: ");
            out.extend_from_slice(ngx_core::times::cached_http_time().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if !ho.content_type.is_empty() {
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(&ho.content_type);
            if ho.content_type_len == ho.content_type.len() && !ho.charset.is_empty() {
                out.extend_from_slice(b"; charset=");
                out.extend_from_slice(&ho.charset);
            }
            out.extend_from_slice(b"\r\n");
        }
        if ho.content_length.is_none() && ho.content_length_n >= 0 {
            out.extend_from_slice(format!("Content-Length: {}\r\n", ho.content_length_n).as_bytes());
        }
        if let Some(cr) = &ho.content_range {
            out.extend_from_slice(b"Content-Range: ");
            out.extend_from_slice(&cr.value.borrow());
            out.extend_from_slice(b"\r\n");
            cr.hash.set(0);
        }
        if let Some(ce) = &ho.content_encoding {
            if ce.hash.get() != 0 {
                out.extend_from_slice(b"Content-Encoding: ");
                out.extend_from_slice(&ce.value.borrow());
                out.extend_from_slice(b"\r\n");
                ce.hash.set(0);
            }
        }
        if ho.last_modified.is_none() && ho.last_modified_time != -1 {
            out.extend_from_slice(b"Last-Modified: ");
            out.extend_from_slice(ngx_core::times::http_time(ho.last_modified_time).as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    // Location: make absolute for relative redirects
    {
        let ho = r.headers_out.borrow();
        let cl = clcf.borrow();
        if let Some(loc) = &ho.location {
            let v = loc.value.borrow().clone();
            if !v.is_empty() && v[0] == b'/' && *cl.absolute_redirect {
                loc.hash.set(0);
                out.extend_from_slice(b"Location: ");
                out.extend_from_slice(if r.connection.ssl.borrow().is_some() { b"https://" } else { b"http://" });
                let host = if *cl.server_name_in_redirect {
                    let cscf = r.cscf();
                    let n = cscf.borrow().server_name.clone();
                    n
                } else if let Some(h) = &r.headers_in.borrow().server.clone().into() {
                    let h: &Vec<u8> = h;
                    if h.is_empty() {
                        let cscf = r.cscf();
                        let n = cscf.borrow().server_name.clone();
                        n
                    } else {
                        h.clone()
                    }
                } else {
                    Vec::new()
                };
                out.extend_from_slice(&host);
                if *cl.port_in_redirect {
                    if let Some(local) = r.connection.local_sockaddr() {
                        let port = local.port();
                        let is_ssl = r.connection.ssl.borrow().is_some();
                        if port != 0 && port != if is_ssl { 443 } else { 80 } {
                            out.extend_from_slice(format!(":{}", port).as_bytes());
                        }
                    }
                }
                out.extend_from_slice(&v);
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    {
        let ho = r.headers_out.borrow();
        let cl = clcf.borrow();
        if r.chunked.get() {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        if ho.status == NGX_HTTP_SWITCHING_PROTOCOLS {
            out.extend_from_slice(b"Connection: upgrade\r\n");
        } else if r.keepalive.get() {
            out.extend_from_slice(b"Connection: keep-alive\r\n");
            if *cl.keepalive_header > 0 {
                out.extend_from_slice(format!("Keep-Alive: timeout={}\r\n", *cl.keepalive_header).as_bytes());
            }
        } else {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        for h in ho.headers.iter() {
            if h.hash.get() == 0 {
                continue;
            }
            out.extend_from_slice(&h.key);
            out.extend_from_slice(b": ");
            out.extend_from_slice(&h.value.borrow());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    http_debug!(r, "{}", B(&out).to_string().trim_end_matches("\r\n").replace("\r\n", "\n"));
    r.header_size.set(out.len());
    let mut b = Buf::from_vec(out);
    b.last_buf = r.header_only.get();
    b.flush = r.header_only.get();
    let mut chain = Chain::new();
    chain.push_back(b);
    // Header bytes go directly to the write filter (they bypass body filters like range/gzip/sub).
    crate::write_filter::write_filter(r.clone(), chain).await
}
