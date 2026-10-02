//! The response header of ngx_http_header_filter, byte for byte as the
//! header filter wrote it before it counted the size of its buffer first:
//! the old filter is kept here as the reference, both run on identical
//! requests.

#![forbid(unsafe_code)]

mod common;

use ngx_core::rc::*;
use ngx_core::string::B;

use ngx_http::core::*;
use ngx_http::header_filter::{status_line, SERVER_BUILD_STRING, SERVER_FULL_STRING, SERVER_STRING};
use ngx_http::request::TableElt;
use ngx_http::*;

use common::*;

/// The header filter before this change (its bytes and its changes to the
/// request), the write filter left out
fn old_header(r: &R) -> Vec<u8> {
    if r.header_sent.get() {
        return Vec::new();
    }
    r.header_sent.set(true);
    if r.method.get() == NGX_HTTP_HEAD {
        r.header_only.set(true);
    }
    let clcf = r.clcf();
    let mut out: Vec<u8> = Vec::with_capacity(512);
    {
        let mut ho = r.headers_out.borrow_mut();
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
                *loc.value.borrow_mut() = out[p..].to_vec();
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
        let terminating = ngx_core::process::SIG_TERMINATE.load(std::sync::atomic::Ordering::SeqCst) || ngx_core::event::is_exiting();
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
    r.header_size.set(out.len());
    out
}

/// The header the new filter wrote: kept in r->out (postponed), or sent
/// at once (header only)
fn new_header(r: &R, peer: &std::os::unix::net::UnixStream) -> Vec<u8> {
    let step = ngx_http::header_filter::header_filter(r.clone());
    assert!(matches!(step, Step::Ready(NGX_OK)), "header filter step");

    let out = r.out.borrow();
    match out.front() {
        Some(b) => match &b.data {
            ngx_core::buf::BufData::Memory(v) => v[b.pos..b.last].to_vec(),
            _ => panic!("header buffer"),
        },
        None => {
            drop(out);
            use std::io::Read;
            peer.set_nonblocking(true).unwrap();
            let mut got = vec![0u8; 65536];
            let n = (&*peer).read(&mut got).unwrap();
            got.truncate(n);
            got
        }
    }
}

/// What the header filter changes in the request, besides the header
fn effects(r: &R) -> String {
    let ho = r.headers_out.borrow();
    format!(
        "header_only={} gzip_vary={} header_size={} content_type={:?} content_type_len={} content_length_n={} last_modified_time={} last_modified={} content_length={} location={:?} hashes={:?}",
        r.header_only.get(),
        r.gzip_vary.get(),
        r.header_size.get(),
        B(&ho.content_type).to_string(),
        ho.content_type_len,
        ho.content_length_n,
        ho.last_modified_time,
        ho.last_modified.is_some(),
        ho.content_length.is_some(),
        ho.location.as_ref().map(|h| B(&h.value.borrow()).to_string()),
        ho.headers.iter().map(|h| h.hash.get()).collect::<Vec<_>>(),
    )
}

fn add(r: &R, key: &[u8], value: &[u8]) -> ngx_http::request::Header {
    r.headers_out.borrow_mut().add(key, value)
}

/// A response header case: its server block, and what the request has
struct Case {
    name: &'static str,
    server: &'static str,
    setup: fn(&R),
}

const SERVER: &str = "server { listen 127.0.0.1:8080; server_name example.org; location / { } }";

fn cases() -> Vec<Case> {
    vec![
        Case { name: "200", server: SERVER, setup: |r| {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 200;
            ho.content_length_n = 5;
        } },
        Case { name: "content type and charset", server: SERVER, setup: |r| {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 200;
            ho.content_type = b"text/plain".to_vec();
            ho.content_type_len = 10;
            ho.charset = b"utf-8".to_vec();
            ho.content_length_n = 0;
        } },
        Case { name: "content type with parameters, charset not added", server: SERVER, setup: |r| {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 200;
            ho.content_type = b"text/plain; x=y".to_vec();
            ho.content_type_len = 10;
            ho.charset = b"koi8-r".to_vec();
        } },
        Case { name: "404", server: SERVER, setup: |r| r.headers_out.borrow_mut().status = 404 },
        Case { name: "unknown status", server: SERVER, setup: |r| r.headers_out.borrow_mut().status = 299 },
        Case { name: "short status", server: SERVER, setup: |r| r.headers_out.borrow_mut().status = 5 },
        Case { name: "long status", server: SERVER, setup: |r| r.headers_out.borrow_mut().status = 12345 },
        Case { name: "status line", server: SERVER, setup: |r| {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 200;
            ho.status_line = b"299 Custom".to_vec();
        } },
        Case { name: "204", server: SERVER, setup: |r| {
            let h = add(r, b"Content-Length", b"10");
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 204;
            ho.content_length_n = 10;
            ho.content_length = Some(h);
            ho.content_type = b"text/html".to_vec();
            ho.content_type_len = 9;
            ho.last_modified_time = 784111777;
        } },
        Case { name: "304", server: SERVER, setup: |r| {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 304;
            ho.last_modified_time = 784111777;
        } },
        Case { name: "last modified of an error", server: SERVER, setup: |r| {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 500;
            ho.last_modified_time = 784111777;
        } },
        Case { name: "last modified, etag", server: SERVER, setup: |r| {
            {
                let mut ho = r.headers_out.borrow_mut();
                ho.status = 200;
                ho.content_length_n = 1024;
                ho.last_modified_time = 1_790_000_000;
            }
            assert_eq!(set_etag(r), NGX_OK);
        } },
        Case { name: "old last modified", server: SERVER, setup: |r| {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 206;
            ho.last_modified_time = 1;
        } },
        Case { name: "last modified header", server: SERVER, setup: |r| {
            let h = add(r, b"Last-Modified", b"Mon, 28 Sep 1970 06:00:00 GMT");
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 200;
            ho.last_modified = Some(h);
            ho.last_modified_time = 784111777;
        } },
        Case { name: "relative location, host", server: SERVER, setup: |r| {
            let h = add(r, b"Location", b"/foo?a=b");
            r.headers_out.borrow_mut().location = Some(h);
            r.headers_out.borrow_mut().status = 301;
            r.headers_in.borrow_mut().server = b"example.com".to_vec();
        } },
        Case { name: "relative location, local address and port", server: SERVER, setup: |r| {
            let h = add(r, b"Location", b"/bar/");
            r.headers_out.borrow_mut().location = Some(h);
            r.headers_out.borrow_mut().status = 302;
            *r.connection.local_sockaddr.borrow_mut() = Some(ngx_core::inet::SockAddr::v4(std::net::Ipv4Addr::new(127, 0, 0, 1), 8080));
        } },
        Case { name: "relative location, port 80", server: SERVER, setup: |r| {
            let h = add(r, b"Location", b"/bar/");
            r.headers_out.borrow_mut().location = Some(h);
            r.headers_out.borrow_mut().status = 302;
            r.headers_in.borrow_mut().server = b"example.com".to_vec();
            *r.connection.local_sockaddr.borrow_mut() = Some(ngx_core::inet::SockAddr::v4(std::net::Ipv4Addr::new(10, 0, 0, 1), 80));
        } },
        Case { name: "relative location, server name", server: "server { listen 127.0.0.1:8080; server_name example.org; server_name_in_redirect on; port_in_redirect off; location / { } }", setup: |r| {
            let h = add(r, b"Location", b"/x");
            r.headers_out.borrow_mut().location = Some(h);
            r.headers_out.borrow_mut().status = 307;
            r.headers_in.borrow_mut().server = b"example.com".to_vec();
        } },
        Case { name: "relative location, absolute_redirect off", server: "server { listen 127.0.0.1:8080; absolute_redirect off; location / { } }", setup: |r| {
            let h = add(r, b"Location", b"/x");
            r.headers_out.borrow_mut().location = Some(h);
            r.headers_out.borrow_mut().status = 302;
        } },
        Case { name: "absolute location", server: SERVER, setup: |r| {
            let h = add(r, b"Location", b"http://example.net/");
            r.headers_out.borrow_mut().location = Some(h);
            r.headers_out.borrow_mut().status = 302;
        } },
        Case { name: "keep-alive header", server: "server { listen 127.0.0.1:8080; keepalive_timeout 75s 60s; location / { } }", setup: |r| r.headers_out.borrow_mut().status = 200 },
        Case { name: "connection close", server: SERVER, setup: |r| {
            r.keepalive.set(false);
            r.headers_out.borrow_mut().status = 200;
        } },
        Case { name: "upgrade", server: SERVER, setup: |r| r.headers_out.borrow_mut().status = 101 },
        Case { name: "chunked", server: SERVER, setup: |r| {
            r.chunked.set(true);
            r.headers_out.borrow_mut().status = 200;
        } },
        Case { name: "gzip vary on", server: "server { listen 127.0.0.1:8080; gzip_vary on; location / { } }", setup: |r| {
            r.gzip_vary.set(true);
            r.headers_out.borrow_mut().status = 200;
        } },
        Case { name: "gzip vary off", server: SERVER, setup: |r| {
            r.gzip_vary.set(true);
            r.headers_out.borrow_mut().status = 200;
        } },
        Case { name: "server_tokens off", server: "server { listen 127.0.0.1:8080; server_tokens off; location / { } }", setup: |r| r.headers_out.borrow_mut().status = 200 },
        Case { name: "server_tokens build", server: "server { listen 127.0.0.1:8080; server_tokens build; location / { } }", setup: |r| r.headers_out.borrow_mut().status = 200 },
        Case { name: "server and date headers", server: SERVER, setup: |r| {
            let s = add(r, b"Server", b"custom");
            let d = add(r, b"Date", b"Thu, 01 Jan 1970 00:00:01 GMT");
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 200;
            ho.server = Some(s);
            ho.date = Some(d);
        } },
        Case { name: "headers, one removed", server: SERVER, setup: |r| {
            add(r, b"X-A", b"1");
            add(r, b"X-B", b"2").hash.set(0);
            add(r, b"X-Empty", b"");
            add(r, b"X-C", b"three");
            r.headers_out.borrow_mut().status = 200;
            r.headers_out.borrow_mut().content_length_n = 123456789012;
        } },
        Case { name: "head", server: SERVER, setup: |r| {
            r.method.set(NGX_HTTP_HEAD);
            let mut ho = r.headers_out.borrow_mut();
            ho.status = 200;
            ho.content_length_n = 1024;
        } },
    ]
}

#[test]
fn header_bytes_as_before() {
    let mut configured = "";

    for case in cases() {
        if case.server != configured {
            configure("golden", case.server);
            configured = case.server;
        }

        run(async {
            let (r_old, _peer_old) = request(b"/");
            (case.setup)(&r_old);
            let old = old_header(&r_old);

            let (r_new, peer_new) = request(b"/");
            r_new.connection.writable().await.unwrap();
            (case.setup)(&r_new);
            let new = new_header(&r_new, &peer_new);

            assert_eq!(B(&mask_date(&new)).to_string(), B(&mask_date(&old)).to_string(), "case {}", case.name);
            assert_eq!(effects(&r_new), effects(&r_old), "case {}", case.name);
        });
    }
}

#[test]
fn etag_value() {
    configure("etag", SERVER);

    run(async {
        for (lm, cl) in [(0i64, 0i64), (1_790_000_000, 1024), (1, -1), (-5, 7), (i64::MAX, i64::MIN)] {
            let (r, _peer) = request(b"/");
            {
                let mut ho = r.headers_out.borrow_mut();
                ho.last_modified_time = lm;
                ho.content_length_n = cl;
            }
            assert_eq!(set_etag(&r), NGX_OK);
            let etag = r.headers_out.borrow().etag.clone().unwrap();
            assert_eq!(etag.key, b"ETag".to_vec());
            assert_eq!(*etag.value.borrow(), format!("\"{:x}-{:x}\"", lm, cl).into_bytes());
        }
    });
}

#[test]
fn content_type_of_extension() {
    configure("types", "types { text/html html; image/gif gif GIF2; } default_type application/octet-stream; server { listen 127.0.0.1:8080; location / { } }");

    run(async {
        for (exten, ct) in [(&b"html"[..], &b"text/html"[..]), (b"HTML", b"text/html"), (b"Gif2", b"image/gif"), (b"bin", b"application/octet-stream"), (b"", b"application/octet-stream")] {
            let (r, _peer) = request(b"/");
            *r.exten.borrow_mut() = exten.to_vec();
            assert_eq!(set_content_type(&r), NGX_OK);
            let ho = r.headers_out.borrow();
            assert_eq!(ho.content_type, ct.to_vec(), "{}", B(exten));
            assert_eq!(ho.content_type_len, ct.len());
        }

        // a long extension
        let (r, _peer) = request(b"/");
        *r.exten.borrow_mut() = vec![b'X'; 100];
        assert_eq!(set_content_type(&r), NGX_OK);
        assert_eq!(r.headers_out.borrow().content_type, b"application/octet-stream".to_vec());

        let _ = TableElt::new(b"", b"");
    });
}
