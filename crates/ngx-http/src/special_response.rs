//! ngx_http_special_response.c: error pages.

use ngx_core::buf::{Buf, Chain};
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::core::*;
use crate::request::*;
use crate::*;

const FULL_TAIL: &[u8] = b"<hr><center>nginx/1.31.7</center>\r\n</body>\r\n</html>\r\n";
const BUILD_TAIL: &[u8] = b"<hr><center>nginx/1.31.7</center>\r\n</body>\r\n</html>\r\n";
const TAIL: &[u8] = b"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
const MSIE_PADDING: &[u8] = b"<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n";
const MSIE_REFRESH_HEAD: &[u8] = b"<html><head><meta http-equiv=\"Refresh\" content=\"0; URL=";
const MSIE_REFRESH_TAIL: &[u8] = b"\"></head><body></body></html>\r\n";

fn page(title: &str) -> Vec<u8> {
    format!("<html>\r\n<head><title>{}</title></head>\r\n<body>\r\n<center><h1>{}</h1></center>\r\n", title, title).into_bytes()
}

fn page2(title: &str, h1: &str, sub: &str) -> Vec<u8> {
    format!("<html>\r\n<head><title>{}</title></head>\r\n<body>\r\n<center><h1>{}</h1></center>\r\n<center>{}</center>\r\n", title, h1, sub).into_bytes()
}

/// Body for a status code (None → empty body).
pub fn error_page_body(status: i64) -> Option<Vec<u8>> {
    let t = match status {
        301 => "301 Moved Permanently",
        302 => "302 Found",
        303 => "303 See Other",
        307 => "307 Temporary Redirect",
        308 => "308 Permanent Redirect",
        400 => "400 Bad Request",
        401 => "401 Authorization Required",
        402 => "402 Payment Required",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Not Allowed",
        406 => "406 Not Acceptable",
        407 => "407 Proxy Authentication Required",
        408 => "408 Request Time-out",
        409 => "409 Conflict",
        410 => "410 Gone",
        411 => "411 Length Required",
        412 => "412 Precondition Failed",
        413 => "413 Request Entity Too Large",
        414 => "414 Request-URI Too Large",
        415 => "415 Unsupported Media Type",
        416 => "416 Requested Range Not Satisfiable",
        421 => "421 Misdirected Request",
        429 => "429 Too Many Requests",
        494 => return Some(page2("400 Request Header Or Cookie Too Large", "400 Bad Request", "Request Header Or Cookie Too Large")),
        495 => return Some(page2("400 The SSL certificate error", "400 Bad Request", "The SSL certificate error")),
        496 => return Some(page2("400 No required SSL certificate was sent", "400 Bad Request", "No required SSL certificate was sent")),
        497 => return Some(page2("400 The plain HTTP request was sent to HTTPS port", "400 Bad Request", "The plain HTTP request was sent to HTTPS port")),
        500 => "500 Internal Server Error",
        501 => "501 Not Implemented",
        502 => "502 Bad Gateway",
        503 => "503 Service Temporarily Unavailable",
        504 => "504 Gateway Time-out",
        505 => "505 HTTP Version Not Supported",
        507 => "507 Insufficient Storage",
        _ => return None,
    };
    Some(page(t))
}

/// ngx_http_special_response_handler: returns rc for finalize_request.
pub async fn special_response_handler(r: &R, error: i64) -> i64 {
    http_debug!(r, "http special response: {}, \"{}?{}\"", error, B(&r.uri.borrow()), B(&r.args.borrow()));
    r.err_status.set(error);
    if r.keepalive.get() {
        match error {
            NGX_HTTP_BAD_REQUEST | NGX_HTTP_REQUEST_ENTITY_TOO_LARGE | NGX_HTTP_REQUEST_URI_TOO_LARGE | NGX_HTTP_TO_HTTPS | NGX_HTTPS_CERT_ERROR | NGX_HTTPS_NO_CERT | NGX_HTTP_INTERNAL_SERVER_ERROR | NGX_HTTP_NOT_IMPLEMENTED => r.keepalive.set(false),
            _ => {}
        }
    }
    if r.lingering_close.get() {
        match error {
            NGX_HTTP_BAD_REQUEST | NGX_HTTP_TO_HTTPS | NGX_HTTPS_CERT_ERROR | NGX_HTTPS_NO_CERT => r.lingering_close.set(false),
            _ => {}
        }
    }
    r.headers_out.borrow_mut().content_type.clear();
    r.headers_out.borrow_mut().content_type_len = 0;
    let clcf = r.clcf();
    let (error_pages, recursive) = {
        let c = clcf.borrow();
        (c.error_pages.clone(), *c.recursive_error_pages)
    };
    if !r.error_page.get() && error_pages.is_some() && r.uri_changes.get() != 0 {
        if !recursive {
            r.error_page.set(true);
        }
        let pages = error_pages.unwrap();
        for ep in pages.iter() {
            if ep.status == error {
                return send_error_page(r, ep).await;
            }
        }
    }
    r.expect_tested.set(true);
    if crate::request_body::discard_request_body(r).await != NGX_OK {
        r.keepalive.set(false);
    }
    let (msie_refresh, msie) = (*clcf.borrow().msie_refresh, r.headers_in.borrow().msie);
    if msie_refresh && msie && (error == NGX_HTTP_MOVED_PERMANENTLY || error == NGX_HTTP_MOVED_TEMPORARILY) {
        return send_refresh(r).await;
    }
    let mut code = error;
    match error {
        NGX_HTTP_TO_HTTPS | NGX_HTTPS_CERT_ERROR | NGX_HTTPS_NO_CERT | NGX_HTTP_REQUEST_HEADER_TOO_LARGE => r.err_status.set(NGX_HTTP_BAD_REQUEST),
        _ => {}
    }
    if error == NGX_HTTP_CREATED || error == NGX_HTTP_NO_CONTENT {
        code = 0;
    }
    if !(300..=308).contains(&error) && !(400..=429).contains(&error) && !(494..=507).contains(&error) {
        code = 0;
    }
    send_special_response(r, code).await
}

/// ngx_http_filter_finalize_request
pub async fn filter_finalize_request(r: &R, error: i64) -> i64 {
    clean_header(r);
    {
        let mut ctx = r.ctx.borrow_mut();
        for c in ctx.iter_mut() {
            *c = None;
        }
    }
    r.filter_finalize.set(true);
    let rc = Box::pin(special_response_handler(r, error)).await;
    match rc {
        NGX_OK | NGX_DONE => NGX_ERROR,
        _ => rc,
    }
}

/// ngx_http_clean_header
pub fn clean_header(r: &R) {
    let mut ho = r.headers_out.borrow_mut();
    *ho = HeadersOut::new();
}

async fn send_error_page(r: &R, ep: &ErrPage) -> i64 {
    let overwrite = ep.overwrite;
    if overwrite != 0 && overwrite != NGX_HTTP_OK {
        r.expect_tested.set(true);
    }
    if overwrite >= 0 {
        r.err_status.set(overwrite);
    }
    let uri = match crate::script::complex_value(r, &ep.value) {
        Ok(u) => u,
        Err(_) => return NGX_ERROR,
    };
    if !uri.is_empty() && uri[0] == b'/' {
        let (uri, args) = if !ep.value.is_constant() {
            let (u, a) = crate::parse::split_args(&uri);
            (u.to_vec(), a.to_vec())
        } else {
            (uri.clone(), ep.args.clone())
        };
        if r.method.get() != NGX_HTTP_HEAD {
            r.method.set(NGX_HTTP_GET);
            *r.method_name.borrow_mut() = b"GET".to_vec();
        }
        return internal_redirect(r, &uri, Some(&args)).await;
    }
    if !uri.is_empty() && uri[0] == b'@' {
        return named_location(r, &uri).await;
    }
    r.expect_tested.set(true);
    if crate::request_body::discard_request_body(r).await != NGX_OK {
        r.keepalive.set(false);
    }
    if overwrite != NGX_HTTP_MOVED_PERMANENTLY && overwrite != NGX_HTTP_MOVED_TEMPORARILY && overwrite != NGX_HTTP_SEE_OTHER && overwrite != NGX_HTTP_TEMPORARY_REDIRECT && overwrite != NGX_HTTP_PERMANENT_REDIRECT {
        r.err_status.set(NGX_HTTP_MOVED_TEMPORARILY);
    }
    r.clear_location();
    let h = r.headers_out.borrow_mut().add(b"Location", &uri);
    r.headers_out.borrow_mut().location = Some(h);
    let clcf = r.clcf();
    if *clcf.borrow().msie_refresh && r.headers_in.borrow().msie {
        return send_refresh(r).await;
    }
    let code = r.err_status.get();
    send_special_response(r, code).await
}

async fn send_special_response(r: &R, code: i64) -> i64 {
    let clcf = r.clcf();
    let (tokens, msie_padding_conf) = {
        let c = clcf.borrow();
        (*c.server_tokens, *c.msie_padding)
    };
    let tail: &[u8] = match tokens {
        NGX_HTTP_SERVER_TOKENS_ON => FULL_TAIL,
        NGX_HTTP_SERVER_TOKENS_BUILD => BUILD_TAIL,
        _ => TAIL,
    };
    let body = if code == 0 { None } else { error_page_body(code) };
    let mut msie_padding = false;
    {
        let mut ho = r.headers_out.borrow_mut();
        match &body {
            Some(b) => {
                ho.content_length_n = (b.len() + tail.len()) as i64;
                let hin = r.headers_in.borrow();
                if msie_padding_conf && (hin.msie || hin.chrome) && r.http_version.get() >= NGX_HTTP_VERSION_10 && code >= 400 {
                    ho.content_length_n += MSIE_PADDING.len() as i64;
                    msie_padding = true;
                }
                ho.content_type_len = 9;
                ho.content_type = b"text/html".to_vec();
                ho.content_type_lowcase = None;
            }
            None => ho.content_length_n = 0,
        }
        if let Some(cl) = ho.content_length.take() {
            cl.hash.set(0);
        }
    }
    r.clear_accept_ranges();
    r.clear_last_modified();
    r.clear_etag();
    let rc = send_header(r).await;
    if rc == NGX_ERROR || r.header_only.get() {
        return rc;
    }
    let body = match body {
        None => return send_special(r, true).await,
        Some(b) => b,
    };
    let mut chain = Chain::new();
    let mut b1 = Buf::from_vec(body);
    b1.memory = true;
    chain.push_back(b1);
    let mut b2 = Buf::from_vec(tail.to_vec());
    b2.memory = true;
    if msie_padding {
        chain.push_back(b2);
        let mut b3 = Buf::from_vec(MSIE_PADDING.to_vec());
        b3.memory = true;
        b3.last_buf = r.is_main();
        b3.last_in_chain = true;
        chain.push_back(b3);
    } else {
        b2.last_buf = r.is_main();
        b2.last_in_chain = true;
        chain.push_back(b2);
    }
    output_filter(r, chain).await
}

async fn send_refresh(r: &R) -> i64 {
    let location = match &r.headers_out.borrow().location {
        Some(l) => l.value.borrow().clone(),
        None => return NGX_ERROR,
    };
    let escaped = ngx_core::string::escape_uri(&location, ngx_core::string::NGX_ESCAPE_REFRESH);
    let size = MSIE_REFRESH_HEAD.len() + escaped.len() + MSIE_REFRESH_TAIL.len();
    r.err_status.set(NGX_HTTP_OK);
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.content_type_len = 9;
        ho.content_type = b"text/html".to_vec();
        ho.content_type_lowcase = None;
        if let Some(l) = ho.location.take() {
            l.hash.set(0);
        }
        ho.content_length_n = size as i64;
        if let Some(cl) = ho.content_length.take() {
            cl.hash.set(0);
        }
    }
    r.clear_accept_ranges();
    r.clear_last_modified();
    r.clear_etag();
    let rc = send_header(r).await;
    if rc == NGX_ERROR || r.header_only.get() {
        return rc;
    }
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(MSIE_REFRESH_HEAD);
    body.extend_from_slice(&escaped);
    body.extend_from_slice(MSIE_REFRESH_TAIL);
    let mut b = Buf::from_vec(body);
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    let mut chain = Chain::new();
    chain.push_back(b);
    output_filter(r, chain).await
}

/// ngx_http_send_special: send a last/flush marker through the filters.
pub async fn send_special(r: &R, last: bool) -> i64 {
    let mut b = Buf::special();
    if last {
        if r.is_main() && !r.post_action.get() {
            b.last_buf = true;
        } else {
            b.sync = true;
            b.last_in_chain = true;
        }
    } else {
        b.flush = true;
    }
    let mut chain = Chain::new();
    chain.push_back(b);
    output_filter(r, chain).await
}
