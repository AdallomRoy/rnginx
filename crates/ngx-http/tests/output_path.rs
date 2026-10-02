//! The response path end to end: a configuration parsed as nginx does, a
//! request on one end of a socketpair, the header and body filters, and
//! the bytes read from the other end.

#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::{Conf, NGX_MAIN_CONF};
use ngx_core::connection::Connection;
use ngx_core::cycle::Cycle;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;

use ngx_http::core::{AddrConf, CoreMainConf};
use ngx_http::request::{HeaderBuf, HttpConnection, HttpLogCtx};
use ngx_http::*;

/// The configuration of `http` in a fresh cycle (the thread's), as the
/// master process parses it.
fn configure(name: &str, http: &str) {
    ngx_core::times::update();

    let dir = std::env::temp_dir().join(format!("rnginx-output-path-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).unwrap();

    let conf = dir.join("nginx.conf");
    std::fs::write(&conf, format!("http {{\n{}\n}}\n", http)).unwrap();

    let log = Log::stderr(NGX_LOG_EMERG);

    let mut defs = vec![
        ngx_core::core_module::core_module(),
        ngx_core::core_module::errlog_module(),
        ngx_core::regex::regex_module(),
        ngx_core::event::events_module(),
        ngx_core::event::event_core_module(),
    ];
    defs.extend(ngx_http::modules());

    let modules = Rc::new(build_modules(defs));
    let mut cycle = Cycle::init_cycle(log.clone(), modules.clone());

    let mut prefix = dir.to_str().unwrap().as_bytes().to_vec();
    prefix.push(b'/');
    cycle.prefix = prefix.clone();
    cycle.conf_prefix = prefix;
    cycle.conf_file = conf.to_str().unwrap().as_bytes().to_vec();

    for m in modules.iter() {
        if m.def.ty != NGX_CORE_MODULE {
            continue;
        }
        if let Some(ctx) = m.ctx::<CoreModuleCtx>() {
            if let Some(create) = ctx.create_conf {
                let c = create(&mut cycle);
                cycle.conf_ctx[m.index] = Some(c);
            }
        }
    }

    {
        let mut cf = Conf::new(&mut cycle, log.clone());
        cf.module_type = NGX_CORE_MODULE;
        cf.cmd_type = NGX_MAIN_CONF;
        let file = cf.cycle.conf_file.clone();
        cf.parse_file(&file).expect("configuration");
    }

    ngx_core::cycle::set_cycle(Rc::new(cycle));
}

/// A request of the first server on one end of a socketpair; the other
/// end is returned to read the response from.
fn request(uri: &[u8]) -> (R, std::os::unix::net::UnixStream) {
    let cycle = ngx_core::cycle::cycle();
    let cmcf = ngx_http::cycle_main_conf::<CoreMainConf>(&cycle, ngx_http::core::ctx_index).unwrap();
    let cscf = cmcf.borrow().servers[0].clone();

    let addr_conf = Rc::new(AddrConf { default_server: cscf.clone(), virtual_names: None, ssl: false, http2: false, quic: false, proxy_protocol: false });
    let conf_ctx = cscf.borrow().ctx.clone();

    let hc = Rc::new(HttpConnection {
        addr_conf,
        conf_ctx: RefCell::new(conf_ctx),
        ssl: Cell::new(false),
        proxy_protocol: Cell::new(false),
        ssl_servername: RefCell::new(None),
        ssl_servername_regex: RefCell::new(None),
        keepalive_timeout: Cell::new(0),
        buffer: RefCell::new(HeaderBuf::default()),
        nbusy: Cell::new(0),
        v3_session: RefCell::new(None),
    });

    let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    a.set_nonblocking(true).unwrap();

    let log = Log::stderr(NGX_LOG_EMERG);
    let fd = ngx_core::fd::register(std::os::fd::OwnedFd::from(a));
    let c = Connection::peer(fd, libc::SOCK_STREAM, ngx_core::inet::SockAddr::Unix(b"client".to_vec()), &log).unwrap();

    let log_ctx = Rc::new(HttpLogCtx { connection: Rc::downgrade(&c), request: RefCell::new(None), current_request: RefCell::new(None) });

    let r = ngx_http::request::alloc_request(&c, &hc, &log_ctx);

    r.method.set(NGX_HTTP_GET);
    r.http_version.set(NGX_HTTP_VERSION_11);
    *r.uri.borrow_mut() = uri.to_vec();
    r.keepalive.set(true);

    assert_ne!(ngx_http::core_rt::find_location(&r), NGX_ERROR);
    ngx_http::core_rt::update_location_config(&r);

    (r, b)
}

/// Everything readable from `s` until it would block for `idle`.
async fn read_all(s: &std::os::unix::net::UnixStream, idle: Duration) -> Vec<u8> {
    use std::io::Read;

    s.set_nonblocking(true).unwrap();

    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut s = s;

    loop {
        match s.read(&mut buf) {
            Ok(0) => return out,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if !out.is_empty() && idle.is_zero() {
                    return out;
                }
                tokio::time::sleep(if idle.is_zero() { Duration::from_millis(1) } else { idle }).await;
                if !idle.is_zero() {
                    match s.read(&mut buf) {
                        Ok(0) => return out,
                        Ok(n) => out.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return out,
                        Err(e) => panic!("read: {}", e),
                    }
                }
            }
            Err(e) => panic!("read: {}", e),
        }
    }
}

fn run(f: impl std::future::Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, f);
}

/// The Date header's value masked
fn mask_date(header: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in header.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b"Date: ") {
            out.extend_from_slice(b"Date: X\r\n");
        } else {
            out.extend_from_slice(line);
        }
    }
    out
}

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
