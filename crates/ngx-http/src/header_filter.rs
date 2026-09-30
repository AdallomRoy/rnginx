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

/// ngx_http_status_lines: the statuses without a line there are written as
/// their number
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
    (407, "407 Proxy Authentication Required"),
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
        // r->headers_out.last_modified = NULL: a header of the list stays
        if ho.last_modified_time != -1 && ho.status != NGX_HTTP_OK && ho.status != NGX_HTTP_PARTIAL_CONTENT && ho.status != NGX_HTTP_NOT_MODIFIED {
            ho.last_modified_time = -1;
            ho.last_modified = None;
        }
        if ho.status == NGX_HTTP_NO_CONTENT {
            r.header_only.set(true);
            ho.content_type_len = 0;
            ho.content_type.clear();
            ho.content_length_n = -1;
            if let Some(cl) = ho.content_length.take() {
                cl.hash.set(0);
            }
            ho.last_modified = None;
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
            out.extend_from_slice(format!("{:03} ", status).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }
    let mut content_type: Option<Vec<u8>> = None;
    // ngx_http_header_filter: "Server", "Date", "Content-Length" and
    // "Last-Modified" are written here only from the fields when there is
    // no header for them; the headers of r->headers_out.headers (typed
    // slots included) follow in their order after "Connection"
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
            let p = out.len();
            out.extend_from_slice(&ho.content_type);
            if ho.content_type_len == ho.content_type.len() && !ho.charset.is_empty() {
                out.extend_from_slice(b"; charset=");
                out.extend_from_slice(&ho.charset);
                // update r->headers_out.content_type for possible logging
                content_type = Some(out[p..].to_vec());
            }
            out.extend_from_slice(b"\r\n");
        }
        if ho.content_length.is_none() && ho.content_length_n >= 0 {
            out.extend_from_slice(format!("Content-Length: {}\r\n", ho.content_length_n).as_bytes());
        }
        if ho.last_modified.is_none() && ho.last_modified_time != -1 {
            out.extend_from_slice(b"Last-Modified: ");
            out.extend_from_slice(ngx_core::times::http_time(ho.last_modified_time).as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    if let Some(ct) = content_type {
        r.headers_out.borrow_mut().content_type = ct;
    }
    // Location: a relative one made absolute (absolute_redirect), its
    // header not written again from the list; any other stays in the list
    {
        let ho = r.headers_out.borrow();
        let cl = clcf.borrow();
        if let Some(loc) = &ho.location {
            let v = loc.value.borrow().clone();
            if !v.is_empty() && v[0] == b'/' && *cl.absolute_redirect {
                loc.hash.set(0);
                let p = out.len() + b"Location: ".len();
                out.extend_from_slice(b"Location: ");
                out.extend_from_slice(if r.connection.ssl.borrow().is_some() { b"https://" } else { b"http://" });
                // server_name_in_redirect on: the server name; else the
                // client's Host; else the local address
                let host: Vec<u8> = if *cl.server_name_in_redirect {
                    let cscf = r.cscf();
                    let n = cscf.borrow().server_name.clone();
                    n
                } else {
                    let hin_server = r.headers_in.borrow().server.clone();
                    if !hin_server.is_empty() {
                        hin_server
                    } else if let Some(local) = r.connection.local_sockaddr() {
                        match local {
                            ngx_core::inet::SockAddr::V4(a) => a.ip().to_string().into_bytes(),
                            ngx_core::inet::SockAddr::V6(a) => a.ip().to_string().into_bytes(),
                            ngx_core::inet::SockAddr::Unix(_) => Vec::new(),
                        }
                    } else {
                        let cscf = r.cscf();
                        let n = cscf.borrow().server_name.clone();
                        n
                    }
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
                // update r->headers_out.location->value for possible logging
                *loc.value.borrow_mut() = out[p..].to_vec();
                out.extend_from_slice(b"\r\n");
            }
        }
    }
    let _ = ();
    {
        let ho = r.headers_out.borrow();
        let cl = clcf.borrow();
        if r.chunked.get() {
            out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        // Suppress keep-alive during graceful shutdown so this response
        // signals to the client that no further requests should follow —
        // matches C's ngx_http_header_filter check of ngx_terminate /
        // ngx_exiting.
        let terminating = ngx_core::process::SIG_TERMINATE
            .load(std::sync::atomic::Ordering::SeqCst)
            || ngx_core::event::is_exiting();
        if ho.status == NGX_HTTP_SWITCHING_PROTOCOLS {
            out.extend_from_slice(b"Connection: upgrade\r\n");
        } else if r.keepalive.get() && !terminating {
            out.extend_from_slice(b"Connection: keep-alive\r\n");
            if *cl.keepalive_header > 0 {
                out.extend_from_slice(format!("Keep-Alive: timeout={}\r\n", *cl.keepalive_header).as_bytes());
            }
        } else {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        // NGX_HTTP_GZIP
        if r.gzip_vary.get() {
            if *cl.gzip_vary {
                out.extend_from_slice(b"Vary: Accept-Encoding\r\n");
            } else {
                r.gzip_vary.set(false);
            }
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
