//! The response path end to end: a configuration parsed as nginx does, a
//! request on one end of a socketpair, the header and body filters, and
//! the bytes read from the other end.

#![forbid(unsafe_code)]

mod common;

use std::time::Duration;

use ngx_core::buf::{Buf, Chain};
use ngx_core::rc::*;

use ngx_http::*;

use common::*;

#[test]
fn response_at_once() {
    configure("at-once", "server { listen 127.0.0.1:8080; location / { } }");

    run(async {
        let (r, peer) = request(b"/");

        r.connection.writable().await.unwrap();

        {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = NGX_HTTP_OK;
            ho.content_length_n = 5;
        }

        // sent with the body: below postpone_output
        let step = ngx_http::core_rt::send_header(&r);
        assert!(matches!(step, Step::Ready(NGX_OK)));

        let mut b = Buf::from_vec(b"hello".to_vec());
        b.last_buf = true;
        let mut chain = Chain::new();
        chain.push_back(b);

        let rc = ngx_http::core_rt::output_filter(&r, chain).await;
        assert_eq!(rc, NGX_OK);
        assert!(r.response_sent.get());
        assert!(r.out.borrow().is_empty());

        let got = read_all(&peer, Duration::ZERO).await;
        assert_eq!(
            mask_date(&got),
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.31.7\r\nDate: X\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello".to_vec()
        );
    });
}

#[test]
fn response_pending_on_full_socket() {
    configure("pending", "server { listen 127.0.0.1:8080; location / { } }");

    run(async {
        let (r, peer) = request(b"/");

        // a send buffer that a few KB fill
        let fd = ngx_core::fd::get(r.connection.fd.get()).unwrap();
        rustix::net::sockopt::set_socket_send_buffer_size(&fd, 4096).unwrap();
        drop(fd);

        r.connection.writable().await.unwrap();

        {
            let mut ho = r.headers_out.borrow_mut();
            ho.status = NGX_HTTP_OK;
            ho.content_length_n = 3 * 1024 * 1024;
        }

        assert!(matches!(ngx_http::core_rt::send_header(&r), Step::Ready(NGX_OK)));

        let mut body = Vec::new();
        let mut chain = Chain::new();
        for i in 0..3u8 {
            let part = vec![b'a' + i; 1024 * 1024];
            body.extend_from_slice(&part);
            let mut b = Buf::from_vec(part);
            b.last_buf = i == 2;
            chain.push_back(b);
        }

        let mut out = ngx_http::core_rt::output_filter(&r, chain);

        // the socket took part of it: the rest waits for the write event
        {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(std::pin::Pin::new(&mut out).poll(&mut cx).is_pending());
        }

        assert!(!r.response_sent.get());
        let sent = r.connection.sent.get();
        assert!(sent > 0 && sent < 3 * 1024 * 1024, "sent {}", sent);

        // the peer reads: the output goes on until it is all sent
        let reader = tokio::task::spawn_local(async move {
            let mut got = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                got.extend_from_slice(&read_all(&peer, Duration::ZERO).await);
                if got.len() >= 3 * 1024 * 1024 + 100 && got.ends_with(&[b'c'; 16]) {
                    let tail_start = got.len() - 3 * 1024 * 1024;
                    if got[..tail_start].ends_with(b"\r\n\r\n") {
                        return got;
                    }
                }
                assert!(tokio::time::Instant::now() < deadline, "timed out with {} bytes", got.len());
            }
        });

        let rc = tokio::time::timeout(Duration::from_secs(10), out).await.expect("output done");
        assert_eq!(rc, NGX_OK);
        assert!(r.response_sent.get());
        assert!(r.out.borrow().is_empty());

        let got = reader.await.unwrap();
        let header_end = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(mask_date(&got[..header_end]).starts_with(b"HTTP/1.1 200 OK\r\nServer: nginx/1.31.7\r\nDate: X\r\n"));
        assert_eq!(&got[header_end..], &body[..]);
        assert_eq!(r.connection.sent.get() as usize, got.len());
    });
}

/// A response of `size` bytes in 1 MB buffers, the header sent with it,
/// on a connection whose send buffer a few KB fill: the output filter's
/// future, which is pending
fn pending_response(r: &R, size: usize) -> ngx_http::core_rt::OutputFilter {
    let fd = ngx_core::fd::get(r.connection.fd.get()).unwrap();
    rustix::net::sockopt::set_socket_send_buffer_size(&fd, 4096).unwrap();
    drop(fd);

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.content_length_n = size as i64;
    }

    assert!(matches!(ngx_http::core_rt::send_header(r), Step::Ready(NGX_OK)));

    let mut chain = Chain::new();
    let mut left = size;
    while left > 0 {
        let n = left.min(1024 * 1024);
        left -= n;
        let mut b = Buf::from_vec(vec![b'x'; n]);
        b.last_buf = left == 0;
        chain.push_back(b);
    }

    let mut out = ngx_http::core_rt::output_filter(r, chain);

    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::pin::Pin::new(&mut out).poll(&mut cx).is_pending());

    out
}

#[test]
fn client_closes_during_blocked_write() {
    configure("closes", "server { listen 127.0.0.1:8080; location / { } }");

    run(async {
        let (r, peer) = request(b"/");

        r.connection.writable().await.unwrap();

        let out = pending_response(&r, 2 * 1024 * 1024);

        // ngx_http_test_reading: the client closed its side
        drop(peer);

        let rc = tokio::time::timeout(Duration::from_secs(10), out).await.expect("output done");
        assert_eq!(rc, NGX_ERROR);
        assert!(r.connection.error.get());
        assert!(r.connection.read_eof.get());
        assert!(!r.response_sent.get());
    });
}

#[test]
fn client_data_during_blocked_write() {
    configure("data", "server { listen 127.0.0.1:8080; location / { } }");

    run(async {
        let (r, peer) = request(b"/");

        r.connection.writable().await.unwrap();

        let size = 2 * 1024 * 1024;
        let mut out = pending_response(&r, size);

        // a pipelined request meanwhile: it stays to be read
        {
            use std::io::Write;
            (&peer).write_all(b"GET /next HTTP/1.1\r\n").unwrap();
        }

        // the output waits on, it is not ended by the data
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut out).await.is_err());
        assert!(!r.connection.error.get());

        let reader = tokio::task::spawn_local(async move {
            let mut got = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                got.extend_from_slice(&read_all(&peer, Duration::ZERO).await);
                if let Some(p) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                    if got.len() - (p + 4) >= size {
                        return peer;
                    }
                }
                assert!(tokio::time::Instant::now() < deadline, "timed out with {} bytes", got.len());
            }
        });

        let rc = tokio::time::timeout(Duration::from_secs(10), out).await.expect("output done");
        assert_eq!(rc, NGX_OK);
        assert!(r.response_sent.get());

        let _peer = reader.await.unwrap();

        // the pipelined request is still there for the connection to read
        let mut buf = [0u8; 64];
        let n = loop {
            match r.connection.try_recv(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => r.connection.readable().await.unwrap(),
                Err(e) => panic!("recv: {}", e),
            }
        };
        assert_eq!(&buf[..n], b"GET /next HTTP/1.1\r\n");
    });
}

use std::future::Future;
