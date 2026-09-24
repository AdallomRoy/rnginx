//! headers_in table and per-header handlers (ngx_http_request.c).

use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::string::{atoof, atotm, strcasestr, strstr, B};
use ngx_core::ngx_log_error;

use crate::core::HeaderInFn;
use crate::request::*;
use crate::*;

pub static HEADERS_IN: &[(&str, HeaderInFn)] = &[
    ("Host", process_host),
    ("Connection", process_connection),
    ("Proxy-Connection", process_proxy_connection),
    ("If-Modified-Since", |r, h| unique(r, h, |i| &mut i.if_modified_since)),
    ("If-Unmodified-Since", |r, h| unique(r, h, |i| &mut i.if_unmodified_since)),
    ("If-Match", |r, h| unique(r, h, |i| &mut i.if_match)),
    ("If-None-Match", |r, h| unique(r, h, |i| &mut i.if_none_match)),
    ("User-Agent", process_user_agent),
    ("Referer", |r, h| multi(r, h, |i| &mut i.referer)),
    ("Content-Length", |r, h| unique(r, h, |i| &mut i.content_length)),
    ("Content-Range", |r, h| unique(r, h, |i| &mut i.content_range)),
    ("Content-Type", |r, h| multi(r, h, |i| &mut i.content_type)),
    ("Range", |r, h| multi(r, h, |i| &mut i.range)),
    ("If-Range", |r, h| unique(r, h, |i| &mut i.if_range)),
    ("Transfer-Encoding", |r, h| unique(r, h, |i| &mut i.transfer_encoding)),
    ("TE", |r, h| multi(r, h, |i| &mut i.te)),
    ("Expect", |r, h| unique(r, h, |i| &mut i.expect)),
    ("Upgrade", |r, h| multi(r, h, |i| &mut i.upgrade)),
    ("Accept-Encoding", |r, h| multi(r, h, |i| &mut i.accept_encoding)),
    ("Via", |r, h| multi(r, h, |i| &mut i.via)),
    ("Authorization", |r, h| unique(r, h, |i| &mut i.authorization)),
    ("Proxy-Authorization", |r, h| unique(r, h, |i| &mut i.proxy_authorization)),
    ("Keep-Alive", |r, h| multi(r, h, |i| &mut i.keep_alive)),
    ("X-Forwarded-For", |r, h| multi(r, h, |i| &mut i.x_forwarded_for)),
    ("X-Real-IP", |r, h| multi(r, h, |i| &mut i.x_real_ip)),
    ("Accept", |r, h| multi(r, h, |i| &mut i.accept)),
    ("Accept-Language", |r, h| multi(r, h, |i| &mut i.accept_language)),
    ("Depth", |r, h| multi(r, h, |i| &mut i.depth)),
    ("Destination", |r, h| multi(r, h, |i| &mut i.destination)),
    ("Overwrite", |r, h| multi(r, h, |i| &mut i.overwrite)),
    ("Date", |r, h| multi(r, h, |i| &mut i.date)),
    ("Cookie", |r, h| multi(r, h, |i| &mut i.cookie)),
];

fn multi(r: &R, h: Header, f: fn(&mut HeadersIn) -> &mut Vec<Header>) -> i64 {
    let mut hin = r.headers_in.borrow_mut();
    f(&mut hin).push(h);
    NGX_OK
}

fn unique(r: &R, h: Header, f: fn(&mut HeadersIn) -> &mut Option<Header>) -> i64 {
    let mut hin = r.headers_in.borrow_mut();
    let slot = f(&mut hin);
    if slot.is_none() {
        *slot = Some(h);
        return NGX_OK;
    }
    let prev = slot.clone().unwrap();
    drop(hin);
    ngx_log_error!(
        NGX_LOG_INFO,
        r.connection.log,
        None,
        "client sent duplicate header line: \"{}: {}\", previous value: \"{}: {}\"",
        B(&h.key),
        B(&h.value.borrow()),
        B(&prev.key),
        B(&prev.value.borrow())
    );
    crate::request_rt::set_pending_finalize(r, NGX_HTTP_BAD_REQUEST);
    NGX_ERROR
}

fn process_host(r: &R, h: Header) -> i64 {
    {
        let hin = r.headers_in.borrow();
        if let Some(prev) = &hin.host {
            ngx_log_error!(
                NGX_LOG_INFO,
                r.connection.log,
                None,
                "client sent duplicate host header: \"{}: {}\", previous value: \"{}: {}\"",
                B(&h.key),
                B(&h.value.borrow()),
                B(&prev.key),
                B(&prev.value.borrow())
            );
            drop(hin);
            crate::request_rt::set_pending_finalize(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }
    }
    r.headers_in.borrow_mut().host = Some(h.clone());
    let value = h.value.borrow().clone();
    let (host, port) = match crate::request_rt::validate_host(&value, false) {
        Ok(v) => v,
        Err(_) => {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid host header");
            crate::request_rt::set_pending_finalize(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }
    };
    if !r.headers_in.borrow().server.is_empty() {
        return NGX_OK;
    }
    if crate::request_rt::set_virtual_server(r, &host) == NGX_ERROR {
        return NGX_ERROR;
    }
    r.headers_in.borrow_mut().server = host;
    r.port.set(port);
    NGX_OK
}

fn process_connection(r: &R, h: Header) -> i64 {
    let v = h.value.borrow().clone();
    multi(r, h, |i| &mut i.connection);
    if strcasestr(&v, b"close").is_some() {
        r.headers_in.borrow_mut().connection_type = NGX_HTTP_CONNECTION_CLOSE;
    } else if strcasestr(&v, b"keep-alive").is_some() {
        r.headers_in.borrow_mut().connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;
    }
    NGX_OK
}

fn process_proxy_connection(r: &R, h: Header) -> i64 {
    // Proxy-Connection is ignored (offset 0 handler in C just links it)
    let _ = (r, h);
    NGX_OK
}

fn process_user_agent(r: &R, h: Header) -> i64 {
    let ua = h.value.borrow().clone();
    multi(r, h, |i| &mut i.user_agent);
    let mut hin = r.headers_in.borrow_mut();
    if let Some(m) = strstr(&ua, b"MSIE ") {
        if m + 7 < ua.len() {
            hin.msie = true;
            if ua[m + 6] == b'.' {
                match ua[m + 5] {
                    b'4' | b'5' => hin.msie6 = true,
                    b'6' => {
                        if strstr(&ua[m + 8..], b"SV1").is_none() {
                            hin.msie6 = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if strstr(&ua, b"Opera").is_some() {
        hin.opera = true;
        hin.msie = false;
        hin.msie6 = false;
    }
    if !hin.msie && !hin.opera {
        if strstr(&ua, b"Gecko/").is_some() {
            hin.gecko = true;
        } else if strstr(&ua, b"Chrome/").is_some() {
            hin.chrome = true;
        } else if strstr(&ua, b"Safari/").is_some() && strstr(&ua, b"Mac OS X").is_some() {
            hin.safari = true;
        } else if strstr(&ua, b"Konqueror").is_some() {
            hin.konqueror = true;
        }
    }
    NGX_OK
}

/// ngx_http_process_request_header validations after all headers are read.
pub fn process_request_header(r: &R) -> i64 {
    if r.headers_in.borrow().server.is_empty() {
        let s = r.headers_in.borrow().server.clone();
        if crate::request_rt::set_virtual_server(r, &s) == NGX_ERROR {
            return NGX_ERROR;
        }
    }
    let hin = r.headers_in.borrow();
    if hin.host.is_none() && r.http_version.get() > NGX_HTTP_VERSION_10 {
        drop(hin);
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent HTTP/1.1 request without \"Host\" header");
        crate::request_rt::set_pending_finalize(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }
    if let Some(cl) = &hin.content_length {
        let v = cl.value.borrow().clone();
        drop(hin);
        match atoof(&v) {
            Some(n) => r.headers_in.borrow_mut().content_length_n = n,
            None => {
                ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid \"Content-Length\" header");
                crate::request_rt::set_pending_finalize(r, NGX_HTTP_BAD_REQUEST);
                return NGX_ERROR;
            }
        }
    } else {
        drop(hin);
    }
    let hin = r.headers_in.borrow();
    if let Some(te) = &hin.transfer_encoding {
        let v = te.value.borrow().clone();
        let has_cl = hin.content_length.is_some();
        drop(hin);
        if r.http_version.get() < NGX_HTTP_VERSION_11 {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent HTTP/1.0 request with \"Transfer-Encoding\" header");
            crate::request_rt::set_pending_finalize(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }
        if v.len() == 7 && ngx_core::string::eq_ignore_case(&v, b"chunked") {
            if has_cl {
                ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent \"Content-Length\" and \"Transfer-Encoding\" headers at the same time");
                crate::request_rt::set_pending_finalize(r, NGX_HTTP_BAD_REQUEST);
                return NGX_ERROR;
            }
            r.headers_in.borrow_mut().chunked = true;
        } else {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent unknown \"Transfer-Encoding\": \"{}\"", B(&v));
            crate::request_rt::set_pending_finalize(r, NGX_HTTP_NOT_IMPLEMENTED);
            return NGX_ERROR;
        }
    } else {
        drop(hin);
    }
    {
        let mut hin = r.headers_in.borrow_mut();
        if hin.connection_type == NGX_HTTP_CONNECTION_KEEP_ALIVE {
            if let Some(ka) = hin.keep_alive.first() {
                let v = ka.value.borrow().clone();
                hin.keep_alive_n = atotm(&v).unwrap_or(-1);
            }
        }
    }
    let cscf = r.cscf();
    if r.method.get() == NGX_HTTP_CONNECT {
        if r.http_version.get() != NGX_HTTP_VERSION_11 || !cscf.borrow().allow_connect {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent CONNECT method");
            crate::request_rt::set_pending_finalize(r, NGX_HTTP_NOT_ALLOWED);
            return NGX_ERROR;
        }
        let hin = r.headers_in.borrow();
        if hin.content_length_n > 0 || hin.chunked {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent CONNECT request with body");
            crate::request_rt::set_pending_finalize(r, NGX_HTTP_BAD_REQUEST);
            return NGX_ERROR;
        }
    }
    if r.method.get() == NGX_HTTP_TRACE {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent TRACE method");
        crate::request_rt::set_pending_finalize(r, NGX_HTTP_NOT_ALLOWED);
        return NGX_ERROR;
    }
    NGX_OK
}
