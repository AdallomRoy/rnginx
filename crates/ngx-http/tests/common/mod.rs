//! The test harness of the response path: a configuration parsed as
//! nginx does, a request on one end of a socketpair.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

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
pub fn configure(name: &str, http: &str) {
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
pub fn request(uri: &[u8]) -> (R, std::os::unix::net::UnixStream) {
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
pub async fn read_all(s: &std::os::unix::net::UnixStream, idle: Duration) -> Vec<u8> {
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

pub fn run(f: impl std::future::Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, f);
}

/// The Date header's value masked
pub fn mask_date(header: &[u8]) -> Vec<u8> {
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

