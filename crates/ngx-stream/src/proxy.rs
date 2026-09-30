//! ngx_stream_proxy_module.c: proxying a session to an upstream, TCP or
//! UDP.
//!
//! The C event handlers become one async task per session: the connect
//! (with the next upstream on failures), then the relay, where each
//! direction is ngx_stream_proxy_process (write what was read, read while
//! data is ready, then ngx_stream_proxy_test_finalize and the half close)
//! driven by the readiness of its source, and proxy_timeout is the timer of
//! the client's write event, re-armed after each step.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use tokio::time::Instant;

use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::event_connect::{event_connect_peer, LocalAddr, PeerConnect, PeerSocket};
use ngx_core::event_openssl::*;
use ngx_core::event_openssl_cache::*;
use ngx_core::inet::{Addr, Url};
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::resolver::{Resolved, Resolver};
use ngx_core::string::B;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::handler::finalize_session;
use crate::script::*;
use crate::upstream::*;
use crate::write_filter::top_filter;
use crate::*;

stream_module_index!("ngx_stream_proxy_module");

/// NGX_MAX_INT32_VALUE
const NGX_MAX_INT32_VALUE: i64 = 2147483647;

/// ngx_stream_upstream_local_t
pub struct UpstreamLocal {
    pub addr: Option<LocalAddr>,
    pub value: Option<ComplexValue>,
    pub transparent: bool,
}

/// ngx_stream_proxy_srv_conf_t
pub struct ProxySrvConf {
    pub connect_timeout: Val<u64>,
    pub timeout: Val<u64>,
    pub next_upstream_timeout: Val<u64>,
    pub buffer_size: Val<usize>,
    pub upload_rate: Option<ComplexValue>,
    pub download_rate: Option<ComplexValue>,
    pub requests: Val<i64>,
    pub responses: Val<i64>,
    pub next_upstream_tries: Val<i64>,
    pub next_upstream: Val<bool>,
    pub proxy_protocol: Val<u32>,
    pub half_close: Val<bool>,
    /// None: "off"
    pub local: Val<Option<Rc<UpstreamLocal>>>,
    pub socket_keepalive: Val<bool>,
    pub socket_rcvbuf: Val<usize>,
    pub socket_sndbuf: Val<usize>,

    pub ssl_enable: Val<bool>,
    pub ssl_session_reuse: Val<bool>,
    pub ssl_protocols: u32,
    pub ssl_ciphers: Val<Vec<u8>>,
    pub ssl_name: Val<Option<ComplexValue>>,
    pub ssl_server_name: Val<bool>,
    pub ssl_alpn: Val<Option<Vec<ComplexValue>>>,

    pub ssl_verify: Val<bool>,
    pub ssl_verify_depth: Val<i64>,
    pub ssl_trusted_certificate: Val<Vec<u8>>,
    pub ssl_crl: Val<Vec<u8>>,
    pub ssl_certificate: Val<Option<ComplexValue>>,
    pub ssl_certificate_key: Val<Option<ComplexValue>>,
    /// Some(None): "off"
    pub ssl_certificate_cache: Val<Option<Rc<RefCell<SslCache>>>>,
    pub ssl_passwords: Val<Option<Rc<SslPasswords>>>,
    pub ssl_conf_commands: Val<Option<Vec<(Vec<u8>, Vec<u8>)>>>,

    /// the context, shared with the stream{} level when no SSL directive
    /// is in the server (ngx_stream_proxy_merge_ssl)
    pub ssl: Option<Rc<RefCell<NgxSsl>>>,

    pub upstream: Option<Rc<UpstreamSrvConf>>,
    pub upstream_value: Option<ComplexValue>,
}

fn pscf_of(s: &Session) -> Rc<RefCell<ProxySrvConf>> {
    s.srv_conf::<ProxySrvConf>(ctx_index())
}

/// The values of the server's conf the relay works with.
struct ProxyConf {
    timeout: u64,
    buffer_size: usize,
    requests: i64,
    responses: i64,
    half_close: bool,
}

impl ProxyConf {
    fn of(pscf: &ProxySrvConf) -> ProxyConf {
        ProxyConf { timeout: *pscf.timeout, buffer_size: *pscf.buffer_size, requests: *pscf.requests, responses: *pscf.responses, half_close: *pscf.half_close }
    }
}

/// Log a message without the context of the session's log (C sets
/// c->log->handler to NULL around it).
fn log_no_handler(log: &Log, level: u32, args: std::fmt::Arguments<'_>) {
    let ctx = log.context();
    log.set_context(None);
    log.error(level, None, args);
    log.set_context(ctx);
}

fn upstream_of(s: &Session) -> Rc<StreamUpstream> {
    s.upstream.borrow().clone().expect("upstream")
}

/// ngx_stream_proxy_handler
async fn proxy_handler(s: S) {
    let c = s.connection.clone();

    let pscf = pscf_of(&s);

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "proxy connection handler");

    let u = Rc::new(StreamUpstream::new(&c.log));

    *s.upstream.borrow_mut() = Some(u.clone());

    *s.log_handler.borrow_mut() = Some(Rc::new(proxy_log_error));

    u.requests.set(1);

    let (local, socket_keepalive, socket_rcvbuf, socket_sndbuf, upstream_value, upstream) = {
        let p = pscf.borrow();
        (p.local.get_or(None), *p.socket_keepalive, *p.socket_rcvbuf, *p.socket_sndbuf, p.upstream_value.clone(), p.upstream.clone())
    };

    if set_local(&s, &u, local.as_deref()).is_err() {
        proxy_finalize(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return;
    }

    {
        let mut pc = u.peer.borrow_mut();

        if socket_keepalive {
            pc.so_keepalive = true;
        }

        if socket_rcvbuf != 0 {
            pc.rcvbuf = socket_rcvbuf as i32;
        }

        if socket_sndbuf != 0 {
            pc.sndbuf = socket_sndbuf as i32;
        }

        pc.ty = c.ty;
    }

    u.start_sec.set(ngx_core::times::time());

    s.upstream_states.borrow_mut().clear();

    if let Some(cv) = upstream_value {
        if proxy_eval(&s, &u, &cv).is_err() {
            proxy_finalize(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return;
        }
    }

    let resolved = u.resolved.borrow().clone();

    let uscf = match resolved {
        None => upstream,

        Some(ur) => {
            *u.ssl_name.borrow_mut() = ur.host.clone();

            let host = &ur.host;

            let umcf = s.main_conf::<UpstreamMainConf>(crate::upstream::ctx_index());

            let found = umcf
                .borrow()
                .upstreams
                .iter()
                .find(|uscf| uscf.host.len() == host.len() && ((uscf.port == 0 && ur.no_port) || uscf.port == ur.port) && uscf.host.eq_ignore_ascii_case(host))
                .cloned();

            match found {
                Some(uscf) => Some(uscf),

                None => {
                    if let Some(sa) = &ur.sockaddr {
                        if ur.port == 0 && !sa.is_unix() {
                            ngx_log_error!(NGX_LOG_ERR, c.log, None, "no port in upstream \"{}\"", B(host));
                            proxy_finalize(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
                            return;
                        }

                        let addrs = vec![Addr { sockaddr: sa.clone(), name: ur.name.clone() }];

                        create_round_robin_peer(&s, &u, host, addrs);

                        proxy_connect(&s).await;
                        return;
                    }

                    if ur.port == 0 {
                        ngx_log_error!(NGX_LOG_ERR, c.log, None, "no port in upstream \"{}\"", B(host));
                        proxy_finalize(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
                        return;
                    }

                    proxy_resolve(&s, &u, &ur).await;
                    return;
                }
            }
        }
    };

    // found:

    let uscf = match uscf {
        Some(u) => u,
        None => {
            ngx_log_error!(NGX_LOG_ALERT, c.log, None, "no upstream configuration");
            proxy_finalize(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return;
        }
    };

    *u.upstream.borrow_mut() = Some(uscf.clone());

    *u.ssl_name.borrow_mut() = uscf.host.clone();

    let balancer = match uscf.init_peer(&s) {
        Ok(b) => b,
        Err(()) => {
            proxy_finalize(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return;
        }
    };

    init_tries(&s, &u, balancer);

    proxy_connect(&s).await;
}

/// The balancer of the session, with u->peer.tries after peer.init and
/// proxy_next_upstream_tries.
fn init_tries(s: &Session, u: &StreamUpstream, balancer: Box<dyn PeerBalancer>) {
    let next_upstream_tries = *pscf_of(s).borrow().next_upstream_tries;

    {
        let mut pc = u.peer.borrow_mut();

        pc.tries = balancer.tries();
        pc.start_time = ngx_core::times::current_msec();

        if next_upstream_tries != 0 && pc.tries as i64 > next_upstream_tries {
            pc.tries = next_upstream_tries as u32;
        }
    }

    *u.balancer.borrow_mut() = Some(balancer);
}

/// ngx_stream_upstream_create_round_robin_peer
fn create_round_robin_peer(s: &Session, u: &StreamUpstream, host: &[u8], addrs: Vec<Addr>) {
    let rrp = crate::upstream_round_robin::create_round_robin_peer(host, addrs);

    let balancer: Box<dyn PeerBalancer> = Box::new(rrp);

    init_tries(s, u, balancer);
}

/// The resolving of a proxy_pass with variables (ngx_resolve_name with
/// ngx_stream_proxy_resolve_handler).
async fn proxy_resolve(s: &S, u: &Rc<StreamUpstream>, ur: &UpstreamResolved) {
    let c = s.connection.clone();

    let host = &ur.host;

    let (resolver, resolver_timeout): (Option<Rc<Resolver>>, u64) = {
        let cscf = s.cscf();
        let cscf = cscf.borrow();
        (cscf.resolver.clone(), *cscf.resolver_timeout)
    };

    let resolver = match resolver {
        Some(r) => r,
        None => {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "no resolver defined to resolve {}", B(host));
            proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return;
        }
    };

    // the client's read events are processed while the name is resolved
    let resolve = resolver.resolve_host(host, resolver_timeout);
    tokio::pin!(resolve);

    let res = loop {
        tokio::select! {
            biased;

            _ = downstream_event(s, u) => {}

            r = &mut resolve => break r,

            _ = c.close_notify.notified() => {
                if c.close.get() {
                    ngx_log_error!(NGX_LOG_INFO, c.log, None, "shutdown timeout");
                }
                proxy_finalize(s, NGX_STREAM_OK).await;
                return;
            }
        }
    };

    let guard = match res {
        Resolved::NoResolver => {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "no resolver defined to resolve {}", B(host));
            proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return;
        }
        Resolved::Error => {
            proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return;
        }
        Resolved::Done(g) => g,
    };

    // ngx_stream_proxy_resolve_handler

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream upstream resolve");

    let ctx = &guard.ctx;

    if ctx.state.get() != 0 {
        ngx_log_error!(NGX_LOG_ERR, c.log, None, "{} could not be resolved ({}: {})", B(&ctx.name.borrow()), ctx.state.get(), Resolver::strerror(ctx.state.get()));

        drop(guard);

        proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return;
    }

    let addrs: Vec<Addr> = ctx
        .addrs
        .borrow()
        .iter()
        .map(|a| {
            let mut sa = a.sockaddr.clone();
            sa.set_port(ur.port);
            let name = sa.to_text(true);
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "name was resolved to {}", B(&sa.to_text(false)));
            Addr { sockaddr: sa, name }
        })
        .collect();

    create_round_robin_peer(s, u, host, addrs);

    // ngx_resolve_name_done
    drop(guard);

    proxy_connect(s).await;
}

/// ngx_stream_proxy_eval
fn proxy_eval(s: &Session, u: &StreamUpstream, cv: &ComplexValue) -> Result<(), ()> {
    let host = complex_value(s, cv)?;

    let mut url = Url::new(&host);
    url.no_resolve = true;

    if ngx_core::inet::parse_url(&mut url).is_err() {
        if let Some(err) = url.err {
            ngx_log_error!(NGX_LOG_ERR, s.connection.log, None, "{} in upstream \"{}\"", err, B(&url.url));
        }

        return Err(());
    }

    let mut ur = UpstreamResolved { host: url.host.clone(), port: url.port, no_port: url.no_port, sockaddr: None, name: Vec::new() };

    if let Some(a) = url.addrs.first() {
        ur.sockaddr = Some(a.sockaddr.clone());
        ur.name = a.name.clone();
    }

    *u.resolved.borrow_mut() = Some(ur);

    Ok(())
}

/// ngx_stream_proxy_set_local
fn set_local(s: &Session, u: &StreamUpstream, local: Option<&UpstreamLocal>) -> Result<(), ()> {
    let mut pc = u.peer.borrow_mut();

    let local = match local {
        None => {
            pc.local = None;
            return Ok(());
        }
        Some(l) => l,
    };

    pc.transparent = local.transparent;

    let cv = match &local.value {
        None => {
            pc.local = local.addr.clone();
            return Ok(());
        }
        Some(cv) => cv,
    };

    drop(pc);

    let val = complex_value(s, cv)?;

    let mut pc = u.peer.borrow_mut();

    if val.is_empty() {
        pc.local = None;
        return Ok(());
    }

    match ngx_core::inet::parse_addr_port(&val) {
        Some(sa) => pc.local = Some(LocalAddr { sockaddr: sa, name: val }),
        None => {
            ngx_log_error!(NGX_LOG_ERR, s.connection.log, None, "invalid local address \"{}\"", B(&val));
            pc.local = None;
        }
    }

    Ok(())
}

/// What became of a connect attempt.
enum Connected {
    /// the relay can start
    Upstream(Rc<Connection>),
    /// try the next upstream
    Next,
    /// the session is finalized
    Done,
}

/// ngx_stream_proxy_connect, with ngx_stream_proxy_next_upstream: until a
/// peer is connected, then the relay.
async fn proxy_connect(s: &S) {
    loop {
        match connect_once(s).await {
            Connected::Done => return,

            Connected::Next => {
                if !next_upstream(s).await {
                    return;
                }
            }

            Connected::Upstream(pc) => {
                proxy_process(s, &pc).await;
                return;
            }
        }
    }
}

/// ngx_stream_proxy_connect, the connect handler and
/// ngx_stream_proxy_init_upstream up to the relay.
async fn connect_once(s: &S) -> Connected {
    let c = s.connection.clone();

    c.log.set_action(Some("connecting to upstream"));

    let pscf = pscf_of(s);
    let (proxy_protocol, connect_timeout) = {
        let p = pscf.borrow();
        (*p.proxy_protocol, *p.connect_timeout)
    };

    let u = upstream_of(s);

    u.connected.set(false);
    u.proxy_protocol.set(proxy_protocol);

    let now = ngx_core::times::current_msec();

    u.with_state(s, |st| st.response_time = (now - u.start_time.get()) as i64);

    let idx = {
        let mut states = s.upstream_states.borrow_mut();
        states.push(UpstreamState::default());
        states.len() - 1
    };

    u.state.set(Some(idx));

    u.start_time.set(now);

    // ngx_event_connect_peer

    let rc = u.peer_get();

    let res = if rc == NGX_OK {
        let pc = u.peer.borrow();

        let p = PeerSocket {
            sockaddr: pc.sockaddr.as_ref().expect("peer sockaddr"),
            name: pc.name.as_deref().unwrap_or(b""),
            ty: pc.ty,
            rcvbuf: pc.rcvbuf,
            sndbuf: pc.sndbuf,
            so_keepalive: pc.so_keepalive,
            local: pc.local.as_ref(),
            transparent: pc.transparent,
            log: &c.log,
            log_error: pc.log_error,
        };

        Some(event_connect_peer(&p))
    } else {
        None
    };

    let rc = match &res {
        None => rc,
        Some(PeerConnect::Ok(_)) => NGX_OK,
        Some(PeerConnect::Again(_)) => NGX_AGAIN,
        Some(PeerConnect::Declined) => NGX_DECLINED,
        Some(PeerConnect::Error) => NGX_ERROR,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "proxy connect: {}", rc);

    if rc == NGX_ERROR {
        proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return Connected::Done;
    }

    let name = u.name.borrow().clone();

    u.with_state(s, |st| st.peer = name);

    if rc == NGX_BUSY {
        ngx_log_error!(NGX_LOG_ERR, c.log, None, "no live upstreams");
        proxy_finalize(s, NGX_STREAM_BAD_GATEWAY).await;
        return Connected::Done;
    }

    if rc == NGX_DECLINED {
        return Connected::Next;
    }

    // rc == NGX_OK || rc == NGX_AGAIN

    let pc = match res {
        Some(PeerConnect::Ok(pc)) | Some(PeerConnect::Again(pc)) => pc,
        _ => unreachable!(),
    };

    *u.connection.borrow_mut() = Some(pc.clone());

    if rc == NGX_AGAIN {
        // ngx_stream_proxy_connect_handler, on the write event or its
        // timer. A timer of 0 expires at the end of the event loop
        // iteration it was added in, before the connection's events (and
        // the client's read event posted by ngx_stream_proxy_handler).

        let res = if connect_timeout == 0 {
            Err(())
        } else {
            let wait = tokio::time::timeout(Duration::from_millis(connect_timeout), pc.writable());
            tokio::pin!(wait);

            loop {
                tokio::select! {
                    biased;

                    _ = downstream_event(s, &u) => {}

                    r = &mut wait => break r.map(|_| ()).map_err(|_| ()),

                    _ = c.close_notify.notified() => {
                        if c.close.get() {
                            ngx_log_error!(NGX_LOG_INFO, c.log, None, "shutdown timeout");
                        }
                        proxy_finalize(s, NGX_STREAM_OK).await;
                        return Connected::Done;
                    }
                }
            }
        };

        if res.is_err() {
            ngx_log_error!(NGX_LOG_ERR, c.log, Some(libc::ETIMEDOUT), "upstream timed out");
            return Connected::Next;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream proxy connect upstream");

        // ngx_stream_proxy_test_connect

        let err = ngx_core::event_connect::connect_error(&pc);

        if err != 0 {
            pc.connection_error(err, "connect() failed");
            return Connected::Next;
        }
    }

    // ngx_stream_proxy_init_upstream

    let cscf = s.cscf();
    let tcp_nodelay = *cscf.borrow().tcp_nodelay;

    if pc.ty == libc::SOCK_STREAM && tcp_nodelay && !pc.set_tcp_nodelay() {
        return Connected::Next;
    }

    let ssl_enable = *pscf.borrow().ssl_enable;

    if pc.ty == libc::SOCK_STREAM && ssl_enable {
        if u.proxy_protocol.get() != 0 {
            match send_proxy_protocol(s, &u, &pc).await {
                Connected::Upstream(_) => {}
                other => return other,
            }

            u.proxy_protocol.set(0);
        }

        if pc.ssl.borrow().is_none() {
            match ssl_init_connection(s, &u, &pc, connect_timeout).await {
                Connected::Upstream(_) => {}
                other => return other,
            }
        }
    }

    if c.log.level() >= NGX_LOG_INFO {
        if let Some(local) = pc.local_sockaddr() {
            let name = u.name.borrow().clone().unwrap_or_default();

            log_no_handler(&c.log, NGX_LOG_INFO, format_args!("{}proxy {} connected to {}", if pc.ty == libc::SOCK_DGRAM { "udp " } else { "" }, B(&local.to_text(true)), B(&name)));
        }
    }

    let now = ngx_core::times::current_msec();

    u.with_state(s, |st| st.connect_time = (now - u.start_time.get()) as i64);

    u.peer_notify(s, pc.ty, NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);

    Connected::Upstream(pc)
}

/// The PROXY protocol header of the client connection (the TLS TLVs of an
/// SSL client with v2).
fn proxy_protocol_header(c: &Connection, version: u32) -> Option<Vec<u8>> {
    let local = c.local_sockaddr()?;

    let sockaddr = c.sockaddr.borrow().clone();

    if version == 2 {
        let (tlvs, ssl) = if c.ssl.borrow().is_some() {
            let (tlvs, ssl) = ngx_core::proxy_protocol::proxy_protocol_v2_eval_ssl(c).ok()?;
            (tlvs, Some(ssl))
        } else {
            (Vec::new(), None)
        };

        return Some(ngx_core::proxy_protocol::proxy_protocol_v2_write(&sockaddr, &local, c.ty, &tlvs, ssl.as_ref()));
    }

    Some(ngx_core::proxy_protocol::proxy_protocol_write(&sockaddr, &local))
}

/// ngx_stream_proxy_send_proxy_protocol: the header sent at once before
/// the TLS handshake
async fn send_proxy_protocol(s: &S, u: &Rc<StreamUpstream>, pc: &Rc<Connection>) -> Connected {
    let c = s.connection.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream proxy send PROXY protocol header");

    let header = match proxy_protocol_header(&c, u.proxy_protocol.get()) {
        Some(h) => h,
        None => {
            proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return Connected::Done;
        }
    };

    let timeout = *pscf_of(s).borrow().timeout;

    loop {
        let n = match pc.try_send(&header) {
            Ok(n) => n,

            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // NGX_AGAIN: ngx_stream_proxy_connect_handler on the write
                // event with proxy_timeout; the client's read events are
                // processed meanwhile
                let wait = tokio::time::timeout(Duration::from_millis(timeout), pc.writable());
                tokio::pin!(wait);

                let res = loop {
                    tokio::select! {
                        biased;

                        _ = downstream_event(s, u) => {}

                        r = &mut wait => break r,
                    }
                };

                match res {
                    Ok(_) => continue,
                    Err(_) => {
                        ngx_log_error!(NGX_LOG_ERR, c.log, Some(libc::ETIMEDOUT), "upstream timed out");
                        return Connected::Next;
                    }
                }
            }

            Err(e) => {
                pc.connection_error(e.raw_os_error().unwrap_or(0), "send() failed");
                proxy_finalize(s, NGX_STREAM_OK).await;
                return Connected::Done;
            }
        };

        if n != header.len() {
            // PROXY protocol specification:
            // The sender must always ensure that the header
            // is sent at once, so that the transport layer
            // maintains atomicity along the path to the receiver.

            ngx_log_error!(NGX_LOG_ERR, c.log, None, "could not send PROXY protocol header at once");

            proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return Connected::Done;
        }

        return Connected::Upstream(pc.clone());
    }
}

/// ngx_stream_proxy_ssl_init_connection and ngx_stream_proxy_ssl_handshake
async fn ssl_init_connection(s: &S, u: &Rc<StreamUpstream>, pc: &Rc<Connection>, connect_timeout: u64) -> Connected {
    let pscf = pscf_of(s);

    let (ssl, ssl_server_name, ssl_verify, has_alpn, dynamic_cert, session_reuse) = {
        let p = pscf.borrow();

        let cert = p.ssl_certificate.as_option().cloned().flatten();
        let key = p.ssl_certificate_key.as_option().cloned().flatten();

        let dynamic_cert = match (&cert, &key) {
            (Some(c), Some(k)) => !c.value.is_empty() && (!c.is_constant() || !k.is_constant()),
            _ => false,
        };

        (p.ssl.clone().expect("ssl"), *p.ssl_server_name, *p.ssl_verify, p.ssl_alpn.as_option().is_some_and(|a| a.is_some()), dynamic_cert, *p.ssl_session_reuse)
    };

    if ngx_ssl_create_connection(&ssl.borrow(), pc, NGX_SSL_BUFFER | NGX_SSL_CLIENT) != NGX_OK {
        proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return Connected::Done;
    }

    if (ssl_server_name || ssl_verify) && proxy_ssl_name(s, u, pc).is_err() {
        proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return Connected::Done;
    }

    if has_alpn && proxy_ssl_alpn(s, pc).is_err() {
        proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return Connected::Done;
    }

    if dynamic_cert && proxy_ssl_certificate(s, pc).is_err() {
        proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return Connected::Done;
    }

    if session_reuse {
        // ngx_stream_proxy_ssl_save_session
        let weak = Rc::downgrade(u);

        ngx_ssl_set_save_session(
            pc,
            Some(Rc::new(move |pc: &Connection| {
                let u = match weak.upgrade() {
                    Some(u) => u,
                    None => return,
                };

                let sess = ngx_ssl_get_session(pc);

                if sess.is_null() {
                    return;
                }

                // the reference of ngx_ssl_get_session() is the session's
                let session = unsafe { <openssl::ssl::SslSession as foreign_types::ForeignType>::from_ptr(sess) };

                let mut balancer = u.balancer.borrow_mut();

                if let Some(b) = balancer.as_mut() {
                    b.save_session(session);
                }
            })),
        );

        // u->peer.set_session
        let session = u.balancer.borrow_mut().as_mut().and_then(|b| b.set_session());

        if let Some(session) = session {
            let rc = ngx_ssl_set_session(pc, <openssl::ssl::SslSession as foreign_types::ForeignType>::as_ptr(&session));

            if rc != NGX_OK {
                proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
                return Connected::Done;
            }
        }
    }

    s.connection.log.set_action(Some("SSL handshaking to upstream"));

    let mut rc = ngx_ssl_handshake(pc);

    if rc == NGX_AGAIN {
        // the write timer (connect_timeout; one of 0 expires before the
        // connection's events), the client's read events processed
        // meanwhile
        rc = if connect_timeout == 0 {
            NGX_ERROR
        } else {
            let wait = tokio::time::timeout(Duration::from_millis(connect_timeout), ngx_ssl_handshake_wait(pc));
            tokio::pin!(wait);

            let res = loop {
                tokio::select! {
                    biased;

                    _ = downstream_event(s, u) => {}

                    r = &mut wait => break r,
                }
            };

            match res {
                Ok(rc) => rc,
                // the write timer: the handshake handler with the handshake
                // not done
                Err(_) => NGX_ERROR,
            }
        };
    }

    let _ = rc;

    // ngx_stream_proxy_ssl_handshake

    let handshaked = pc.ssl.borrow().as_ref().is_some_and(|sc| sc.handshaked.get());

    if handshaked {
        if ssl_verify {
            let rc = ngx_ssl_get_verify_result(pc);

            // X509_V_OK
            if rc != 0 {
                ngx_log_error!(NGX_LOG_ERR, pc.log, None, "upstream SSL certificate verify error: ({}:{})", rc, B(&ngx_ssl_verify_error_string(rc)));
                return Connected::Next;
            }

            let name = u.ssl_name.borrow().clone();

            if ngx_ssl_check_host(pc, &name) != NGX_OK {
                ngx_log_error!(NGX_LOG_ERR, pc.log, None, "upstream SSL certificate does not match \"{}\"", B(&name));
                return Connected::Next;
            }
        }

        return Connected::Upstream(pc.clone());
    }

    Connected::Next
}

/// ngx_stream_proxy_ssl_name: the server name (SNI) and the name verified
fn proxy_ssl_name(s: &S, u: &StreamUpstream, pc: &Connection) -> Result<(), ()> {
    let pscf = pscf_of(s);

    let (ssl_name, ssl_server_name) = {
        let p = pscf.borrow();
        (p.ssl_name.as_option().cloned().flatten(), *p.ssl_server_name)
    };

    let mut name = match ssl_name {
        Some(cv) => complex_value(s, &cv)?,
        None => u.ssl_name.borrow().clone(),
    };

    'done: {
        if name.is_empty() {
            break 'done;
        }

        // ssl name here may contain port, strip it for compatibility
        // with the http module

        let mut p = 0;

        if name[0] == b'[' {
            p = name.iter().position(|&c| c == b']').unwrap_or(0);
        }

        if let Some(colon) = name[p..].iter().position(|&c| c == b':') {
            name.truncate(p + colon);
        }

        if !ssl_server_name {
            break 'done;
        }

        // as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted

        if name.is_empty() || name[0] == b'[' {
            break 'done;
        }

        if ngx_core::inet::inet_addr(&name).is_some() {
            break 'done;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "upstream SSL server name: \"{}\"", B(&name));

        if !ngx_ssl_set_tlsext_host_name(pc, &name) {
            ngx_ssl_error(NGX_LOG_ERR, &s.connection.log, 0, format_args!("SSL_set_tlsext_host_name(\"{}\") failed", B(&name)));
            return Err(());
        }
    }

    *u.ssl_name.borrow_mut() = name;

    Ok(())
}

/// ngx_stream_proxy_ssl_alpn
fn proxy_ssl_alpn(s: &S, pc: &Connection) -> Result<(), ()> {
    let alpn = pscf_of(s).borrow().ssl_alpn.as_option().cloned().flatten().unwrap_or_default();

    let mut buf: Vec<u8> = Vec::new();

    for cv in alpn.iter() {
        let proto = complex_value(s, cv)?;

        if proto.is_empty() || proto.len() > 255 {
            continue;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "upstream SSL ALPN: \"{}\"", B(&proto));

        buf.push(proto.len() as u8);
        buf.extend_from_slice(&proto);
    }

    if buf.is_empty() {
        return Ok(());
    }

    if ngx_ssl_set_alpn_protos(pc, &buf) != 0 {
        ngx_ssl_error(NGX_LOG_ERR, &pc.log, 0, format_args!("SSL_set_alpn_protos() failed"));
        return Err(());
    }

    Ok(())
}

/// The value of a complex value compiled with "zero", without the NUL.
fn zero_value(s: &Session, cv: &ComplexValue) -> Result<Vec<u8>, ()> {
    let mut v = complex_value(s, cv)?;

    if v.last() == Some(&0) {
        v.pop();
    }

    Ok(v)
}

/// ngx_stream_proxy_ssl_certificate: a certificate with variables
fn proxy_ssl_certificate(s: &S, pc: &Connection) -> Result<(), ()> {
    let pscf = pscf_of(s);

    let (cert_cv, key_cv, cache, passwords) = {
        let p = pscf.borrow();
        (
            p.ssl_certificate.as_option().cloned().flatten().expect("certificate"),
            p.ssl_certificate_key.as_option().cloned().flatten().expect("certificate key"),
            p.ssl_certificate_cache.as_option().cloned().flatten(),
            p.ssl_passwords.as_option().cloned().flatten(),
        )
    };

    let mut cert = zero_value(s, &cert_cv)?;

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "stream upstream ssl cert: \"{}\"", B(&cert));

    if cert.is_empty() {
        return Ok(());
    }

    let mut key = zero_value(s, &key_cv)?;

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "stream upstream ssl key: \"{}\"", B(&key));

    if ngx_ssl_connection_certificate(pc, &mut cert, &mut key, cache.as_ref(), passwords.as_ref()) != NGX_OK {
        return Err(());
    }

    Ok(())
}

/// ngx_stream_proxy_next_upstream: false if the session is finalized
async fn next_upstream(s: &S) -> bool {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream proxy next upstream");

    let u = upstream_of(s);

    let pc = u.connection.borrow().clone();

    if u.peer.borrow().sockaddr.is_some() {
        u.peer_free(s, NGX_PEER_FAILED);
        u.peer.borrow_mut().sockaddr = None;
    }

    let pscf = pscf_of(s);
    let (timeout, next_upstream) = {
        let p = pscf.borrow();
        (*p.next_upstream_timeout, *p.next_upstream)
    };

    let (tries, start_time) = {
        let pc = u.peer.borrow();
        (pc.tries, pc.start_time)
    };

    if tries == 0 || !next_upstream || (timeout != 0 && ngx_core::times::current_msec() - start_time >= timeout) {
        proxy_finalize(s, NGX_STREAM_BAD_GATEWAY).await;
        return false;
    }

    if let Some(pc) = pc {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "close proxy upstream connection: {}", pc.fd.get());

        let received = u.received.get();
        let sent = pc.sent.get() as i64;

        u.with_state(s, |st| {
            st.bytes_received = received;
            st.bytes_sent = sent;
        });

        let sc = pc.ssl.borrow().clone();

        if let Some(sc) = sc {
            sc.no_wait_shutdown.set(true);
            sc.no_send_shutdown.set(true);

            let _ = ngx_ssl_shutdown(&pc);
        }

        pc.close();

        *u.connection.borrow_mut() = None;
    }

    true
}

/// ngx_stream_proxy_finalize
pub async fn proxy_finalize(s: &S, rc: i64) {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "finalize stream proxy: {}", rc);

    let u = s.upstream.borrow().clone();

    if let Some(u) = u {
        let pc = u.connection.borrow().clone();

        if u.state.get().is_some() {
            let now = ngx_core::times::current_msec();
            let start_time = u.start_time.get();
            let received = u.received.get();
            let sent = pc.as_ref().map(|pc| pc.sent.get() as i64);

            u.with_state(s, |st| {
                if st.response_time == -1 {
                    st.response_time = (now - start_time) as i64;
                }

                if let Some(sent) = sent {
                    st.bytes_received = received;
                    st.bytes_sent = sent;
                }
            });
        }

        if u.balancer.borrow().is_some() && u.peer.borrow().sockaddr.is_some() {
            let mut state = 0;

            if let Some(pc) = &pc {
                if pc.ty == libc::SOCK_DGRAM && pc.error.get() {
                    state = NGX_PEER_FAILED;
                }
            }

            u.peer_free(s, state);
            u.peer.borrow_mut().sockaddr = None;
        }

        if let Some(pc) = pc {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "close stream proxy upstream connection: {}", pc.fd.get());

            let sc = pc.ssl.borrow().clone();

            if let Some(sc) = sc {
                sc.no_wait_shutdown.set(true);

                let _ = ngx_ssl_shutdown(&pc);
            }

            pc.close();

            *u.connection.borrow_mut() = None;
        }
    }

    finalize_session(s, rc).await;
}

/// ngx_stream_proxy_log_error: the upstream and the bytes
fn proxy_log_error(s: &Session, buf: &mut Vec<u8>) {
    let u = match s.upstream.try_borrow().ok().and_then(|u| u.clone()) {
        Some(u) => u,
        None => return,
    };

    if let Ok(name) = u.name.try_borrow() {
        if let Some(name) = name.as_ref() {
            buf.extend_from_slice(b", upstream: \"");
            buf.extend_from_slice(name);
            buf.push(b'"');
        }
    }

    let pc_sent = u.connection.try_borrow().ok().and_then(|pc| pc.as_ref().map(|pc| pc.sent.get())).unwrap_or(0);

    buf.extend_from_slice(format!(", bytes from/to client:{}/{}, bytes from/to upstream:{}/{}", s.received.get(), s.connection.sent.get(), u.received.get(), pc_sent).as_bytes());
}

/// The client's read event while the upstream is not connected: it comes
/// with data, the end or an error (and the read event posted by
/// ngx_stream_proxy_handler is this with the data already there). There
/// is none if the read event is neither ready nor active yet (see
/// client_read_active); the datagrams of a UDP session are left to the
/// relay.
async fn downstream_event(s: &Session, u: &StreamUpstream) {
    if s.connection.ty != libc::SOCK_STREAM || !client_read_active(s) {
        std::future::pending::<()>().await;
    }

    let buffer_size = *pscf_of(s).borrow().buffer_size;

    loop {
        // no more events after the end; with no room left the data waits
        if u.client_eof.get() || u.downstream_size.get() >= buffer_size {
            std::future::pending::<()>().await;
        }

        if s.connection.readable().await.is_err() {
            std::future::pending::<()>().await;
        }

        if process_unconnected(s, u) {
            return;
        }
    }
}

/// c->read->ready or c->read->active at ngx_stream_proxy_handler: a phase
/// before read from the client (the preread phase of ssl_preread, the TLS
/// handshake, the PROXY protocol header). Otherwise the client's read
/// event is added by ngx_stream_proxy_process() once the upstream is
/// connected, and the data waits till then.
fn client_read_active(s: &Session) -> bool {
    let c = &s.connection;

    c.ssl.borrow().is_some() || c.proxy_protocol.borrow().is_some() || *s.srv_conf::<crate::ssl_preread::SslPrereadSrvConf>(crate::ssl_preread::ctx_index()).borrow().enabled
}

/// ngx_stream_proxy_process(s, 0, 0) with no upstream connection yet
/// (pc == NULL): the client's data is read into u->downstream_buf and
/// queued in u->upstream_out, to be sent once the upstream is connected.
/// False, with nothing changed, if there was nothing to read.
fn process_unconnected(s: &Session, u: &StreamUpstream) -> bool {
    let c = &s.connection;

    let buffer_size = *pscf_of(s).borrow().buffer_size;

    let action = c.log.action();

    let mut event = false;

    // for ( ;; ), with nothing to write to (dst == NULL); the rates are
    // set by ngx_stream_proxy_init_upstream

    loop {
        let size = buffer_size.saturating_sub(u.downstream_size.get());

        if size == 0 || u.client_eof.get() {
            break;
        }

        c.log.set_action(Some("proxying and reading from client"));

        let mut buf = vec![0u8; size];

        let n = match c.try_recv(&mut buf) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,

            Err(e) => {
                // NGX_ERROR: c->recv() logged it
                if !is_ssl_error_logged(&e) {
                    c.connection_error(e.raw_os_error().unwrap_or(0), "recv() failed");
                }
                c.error.set(true);
                u.client_eof.set(true);
                0
            }

            Ok(n) => {
                if n == 0 {
                    u.client_eof.set(true);
                }
                n
            }
        };

        event = true;

        // a buffer with last_buf and no data is not sent
        if n > 0 {
            u.upstream_out.borrow_mut().push_back(buf[..n].to_vec());
        }

        u.requests.set(u.requests.get() + 1);
        s.received.set(s.received.get() + n as i64);
        u.downstream_size.set(u.downstream_size.get() + n);
    }

    if !event {
        c.log.set_action(action);
        return false;
    }

    c.log.set_action(Some("proxying connection"));

    // ngx_stream_proxy_test_finalize: no upstream connection yet

    true
}

// --- the relay ---

/// The shared state of the two directions: c->read->eof, pc->read->eof,
/// c->buffered, pc->buffered, the delayed reads and the proxy_timeout timer
/// (c->write).
struct Relay {
    s: S,
    u: Rc<StreamUpstream>,
    c: Rc<Connection>,
    pc: Rc<Connection>,
    conf: ProxyConf,

    c_eof: Cell<bool>,
    pc_eof: Cell<bool>,
    c_buffered: Cell<bool>,
    pc_buffered: Cell<bool>,
    c_delayed: Cell<bool>,
    pc_delayed: Cell<bool>,

    deadline: Cell<Option<Instant>>,
    deadline_set: tokio::sync::Notify,
}

impl Relay {
    fn eof(&self, from_upstream: bool) -> &Cell<bool> {
        if from_upstream {
            &self.pc_eof
        } else {
            &self.c_eof
        }
    }

    /// the data to the destination is pending
    fn buffered(&self, from_upstream: bool) -> &Cell<bool> {
        if from_upstream {
            &self.c_buffered
        } else {
            &self.pc_buffered
        }
    }

    fn delayed(&self, from_upstream: bool) -> &Cell<bool> {
        if from_upstream {
            &self.pc_delayed
        } else {
            &self.c_delayed
        }
    }

    /// ngx_add_timer(c->write, pscf->timeout), or ngx_del_timer while a
    /// read is delayed
    fn update_timer(&self) {
        if !self.c_delayed.get() && !self.pc_delayed.get() {
            let was = self.deadline.get();
            self.deadline.set(Some(Instant::now() + Duration::from_millis(self.conf.timeout)));
            if was.is_none() {
                self.deadline_set.notify_one();
            }
        } else {
            self.deadline.set(None);
        }
    }

    /// The proxy_timeout timer expires.
    async fn timer(&self) {
        loop {
            match self.deadline.get() {
                None => self.deadline_set.notified().await,
                Some(d) => {
                    if Instant::now() >= d {
                        return;
                    }
                    tokio::time::sleep_until(d).await;
                }
            }
        }
    }
}

/// The end of a direction: the session is to be finalized with the code.
type Finalize = i64;

/// ngx_stream_proxy_init_upstream from the buffers on, and the relay until
/// the session is finalized.
async fn proxy_process(s: &S, pc: &Rc<Connection>) {
    let c = s.connection.clone();
    let u = upstream_of(s);

    let pscf = pscf_of(s);

    let conf = ProxyConf::of(&pscf.borrow());

    // the data to the upstream: the PROXY protocol header, then the
    // preread data (the first datagram of UDP)

    let mut upstream_out: VecDeque<Vec<u8>> = VecDeque::new();

    let preread = std::mem::take(&mut *c.buffer.borrow_mut());

    // c->buffer->pos <= c->buffer->last: the first datagram of UDP is sent
    // even if empty
    if !preread.is_empty() || c.ty == libc::SOCK_DGRAM {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream proxy add preread buffer: {}", preread.len());

        upstream_out.push_back(preread);
    }

    // u->upstream_out: what was read from the client meanwhile
    upstream_out.extend(u.upstream_out.borrow_mut().drain(..));

    if u.proxy_protocol.get() != 0 {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream proxy add PROXY protocol header");

        let local = match c.local_sockaddr() {
            Some(l) => l,
            None => {
                proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
                return;
            }
        };

        let sockaddr = c.sockaddr.borrow().clone();

        let header = if u.proxy_protocol.get() == 2 {
            ngx_core::proxy_protocol::proxy_protocol_v2_write(&sockaddr, &local, c.ty, &[], None)
        } else {
            ngx_core::proxy_protocol::proxy_protocol_write(&sockaddr, &local)
        };

        match upstream_out.front_mut() {
            // the header buffer is not flushed: on UDP it goes in one
            // datagram with the first one (ngx_udp_output_chain_to_iovec)
            Some(first) if c.ty == libc::SOCK_DGRAM => {
                let mut d = header;
                d.extend_from_slice(first);
                *first = d;
            }
            _ => upstream_out.push_front(header),
        }

        u.proxy_protocol.set(0);
    }

    let (upload_rate, download_rate) = {
        let p = pscf.borrow();
        (complex_value_size(s, p.upload_rate.as_ref(), 0), complex_value_size(s, p.download_rate.as_ref(), 0))
    };

    u.upload_rate.set(upload_rate);
    u.download_rate.set(download_rate);

    u.connected.set(true);

    let r = Relay {
        s: s.clone(),
        u: u.clone(),
        c: c.clone(),
        pc: pc.clone(),
        conf,
        c_eof: Cell::new(u.client_eof.get()),
        pc_eof: Cell::new(false),
        c_buffered: Cell::new(false),
        pc_buffered: Cell::new(false),
        c_delayed: Cell::new(false),
        pc_delayed: Cell::new(false),
        deadline: Cell::new(None),
        deadline_set: tokio::sync::Notify::new(),
    };

    let rc = {
        let downstream = relay(&r, false, upstream_out);
        let upstream = relay(&r, true, VecDeque::new());

        tokio::pin!(downstream);
        tokio::pin!(upstream);

        // ngx_stream_proxy_init_upstream runs ngx_stream_proxy_process(s,
        // 0, 1) before the posted read event of the upstream
        tokio::select! {
            biased;

            rc = &mut downstream => rc,
            rc = &mut upstream => rc,
            _ = r.timer() => proxy_timed_out(&r),
            _ = c.close_notify.notified() => shutdown_timeout(&r),
            _ = pc.close_notify.notified() => shutdown_timeout(&r),
        }
    };

    proxy_finalize(s, rc).await;
}

/// c->close: the worker shutdown timer
fn shutdown_timeout(r: &Relay) -> Finalize {
    ngx_log_error!(NGX_LOG_INFO, r.c.log, None, "shutdown timeout");
    NGX_STREAM_OK
}

/// ngx_stream_proxy_process_connection with the timer expired
fn proxy_timed_out(r: &Relay) -> Finalize {
    let (s, u, c, pc) = (&r.s, &r.u, &r.c, &r.pc);

    if c.ty == libc::SOCK_DGRAM {
        if r.conf.responses == NGX_MAX_INT32_VALUE || u.responses.get() as i64 >= r.conf.responses * u.requests.get() as i64 {
            // successfully terminate timed out UDP session
            // if expected number of responses was received

            log_no_handler(
                &c.log,
                NGX_LOG_INFO,
                format_args!(
                    "udp timed out, packets from/to client:{}/{}, bytes from/to client:{}/{}, bytes from/to upstream:{}/{}",
                    u.requests.get(),
                    u.responses.get(),
                    s.received.get(),
                    c.sent.get(),
                    u.received.get(),
                    pc.sent.get()
                ),
            );

            return NGX_STREAM_OK;
        }

        pc.connection_error(libc::ETIMEDOUT, "upstream timed out");

        pc.error.set(true);

        return NGX_STREAM_BAD_GATEWAY;
    }

    c.connection_error(libc::ETIMEDOUT, "connection timed out");

    NGX_STREAM_OK
}

/// ngx_stream_proxy_process for one direction, driven by the readiness of
/// its source, until the session is to be finalized.
async fn relay(r: &Relay, from_upstream: bool, mut out: VecDeque<Vec<u8>>) -> Finalize {
    let (s, u, c) = (&r.s, &r.u, &r.c);

    let (src, dst) = if from_upstream { (&r.pc, &r.c) } else { (&r.c, &r.pc) };

    let (recv_action, send_action) = if from_upstream {
        ("proxying and reading from upstream", "proxying and sending to client")
    } else {
        ("proxying and reading from client", "proxying and sending to upstream")
    };

    let limit_rate = if from_upstream { u.download_rate.get() } else { u.upload_rate.get() };

    let received = |add: i64| {
        if from_upstream {
            u.received.set(u.received.get() + add);
            u.received.get()
        } else {
            s.received.set(s.received.get() + add);
            s.received.get()
        }
    };

    let packets = || {
        if from_upstream {
            u.responses.set(u.responses.get() + 1);
        } else {
            u.requests.set(u.requests.get() + 1);
        }
    };

    let mut buf = vec![0u8; r.conf.buffer_size];

    // the downstream direction starts with ngx_stream_proxy_process(s, 0, 1)
    let mut do_write = !from_upstream;

    // the read delay of limit_rate (src->read->delayed with its timer)
    let mut delay_until: Option<Instant> = None;

    // src->read->ready of a client connection sharing a UDP listening
    // socket: one datagram per read event (ngx_udp_shared_recv), none
    // before the first event
    let udp_shared = src.is_udp_shared();
    let mut src_ready = !udp_shared;

    loop {
        if c.ty == libc::SOCK_DGRAM && (ngx_core::event::is_exiting() || ngx_core::cycle::globals(|g| g.terminate)) {
            // socket is already closed on worker shutdown

            log_no_handler(&c.log, NGX_LOG_INFO, format_args!("disconnected on shutdown"));

            return NGX_STREAM_OK;
        }

        // for ( ;; )

        loop {
            if do_write && !out.is_empty() {
                c.log.set_action(Some(send_action));

                let bufs: Vec<&[u8]> = out.iter().map(|b| b.as_slice()).collect();

                r.buffered(from_upstream).set(true);

                let rc = top_filter(s, dst, &bufs, from_upstream, None).await;

                r.buffered(from_upstream).set(false);

                if rc.is_err() {
                    return NGX_STREAM_OK;
                }

                out.clear();
            }

            if r.eof(from_upstream).get() || delay_until.is_some() || !src_ready {
                break;
            }

            let mut size = buf.len();

            if limit_rate != 0 {
                let limit = limit_rate as i64 * (ngx_core::times::time() - u.start_sec.get() + 1) - received(0);

                if limit <= 0 {
                    set_delayed(r, from_upstream, src, true);
                    let delay = (-limit * 1000 / limit_rate as i64 + 1) as u64;
                    delay_until = Some(Instant::now() + Duration::from_millis(delay));
                    break;
                }

                if c.ty == libc::SOCK_STREAM && size as i64 > limit {
                    size = limit as usize;
                }
            }

            c.log.set_action(Some(recv_action));

            let n = match src.try_recv(&mut buf[..size]) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,

                Err(e) => {
                    // NGX_ERROR: c->recv() logged it
                    if !is_ssl_error_logged(&e) {
                        src.connection_error(e.raw_os_error().unwrap_or(0), "recv() failed");
                    }
                    src.error.set(true);
                    r.eof(from_upstream).set(true);
                    0
                }

                Ok(n) => {
                    if n == 0 && src.ty == libc::SOCK_STREAM {
                        r.eof(from_upstream).set(true);
                    }
                    n
                }
            };

            if limit_rate != 0 {
                let delay = (n as u64) * 1000 / limit_rate as u64;

                if delay > 0 {
                    set_delayed(r, from_upstream, src, true);
                    delay_until = Some(Instant::now() + Duration::from_millis(delay));
                }
            }

            if from_upstream {
                let first = u.with_state(s, |st| st.first_byte_time == -1).unwrap_or(false);

                if first {
                    let now = ngx_core::times::current_msec();
                    let start_time = u.start_time.get();

                    u.with_state(s, |st| st.first_byte_time = (now - start_time) as i64);

                    u.peer_notify(s, r.pc.ty, NGX_STREAM_UPSTREAM_NOTIFY_FIRST_BYTE);
                }
            }

            // a buffer with last_buf and no data (the end, or an error) is
            // not sent: on UDP it is not a datagram
            if n > 0 || !r.eof(from_upstream).get() {
                out.push_back(buf[..n].to_vec());
            }

            packets();
            received(n as i64);

            if udp_shared {
                src_ready = false;
            }

            do_write = true;
        }

        c.log.set_action(Some("proxying connection"));

        if let Some(rc) = test_finalize(r, from_upstream) {
            return rc;
        }

        if dst.ty == libc::SOCK_STREAM && r.conf.half_close && r.eof(from_upstream).get() && !u.half_closed.get() && !r.buffered(from_upstream).get() {
            if let Err(e) = dst.shutdown_write() {
                c.connection_error(e.raw_os_error().unwrap_or(0), "shutdown() failed");
                return NGX_STREAM_INTERNAL_SERVER_ERROR;
            }

            u.half_closed.set(true);

            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream proxy {} socket shutdown", if from_upstream { "client" } else { "upstream" });
        }

        r.update_timer();

        // wait for the next event of this direction

        if r.eof(from_upstream).get() {
            std::future::pending::<()>().await;
        }

        if let Some(t) = delay_until.take() {
            tokio::time::sleep_until(t).await;

            set_delayed(r, from_upstream, src, false);

            // the delayed event: the proxy timer is back if nothing is
            // delayed
            r.update_timer();

            continue;
        }

        if src.readable().await.is_err() {
            // the socket is gone: the recv reports it
        }

        src_ready = true;
    }
}

/// src->read->delayed of limit_rate: while it is set, a datagram for a
/// client connection of a UDP listening socket is not read, and
/// ngx_event_recvmsg drops it (the read handler returns at once); those
/// already waiting to be read arrived after the read which started the
/// delay, and are dropped too.
fn set_delayed(r: &Relay, from_upstream: bool, src: &Connection, delayed: bool) {
    r.delayed(from_upstream).set(delayed);

    src.read_delayed.set(delayed);

    if delayed {
        if let Some(udp) = src.udp_conn() {
            udp.drop_unread(src);
        }
    }
}

/// ngx_stream_proxy_test_finalize: Some(rc) to finalize the session
fn test_finalize(r: &Relay, from_upstream: bool) -> Option<Finalize> {
    let (s, u, c, pc) = (&r.s, &r.u, &r.c, &r.pc);

    if c.ty == libc::SOCK_DGRAM {
        if r.conf.requests != 0 && (u.requests.get() as i64) < r.conf.requests {
            return None;
        }

        if r.conf.requests != 0 {
            delete_udp_connection(c);
        }

        if r.conf.responses == NGX_MAX_INT32_VALUE || (u.responses.get() as i64) < r.conf.responses * u.requests.get() as i64 {
            return None;
        }

        if r.c_buffered.get() || r.pc_buffered.get() {
            return None;
        }

        log_no_handler(
            &c.log,
            NGX_LOG_INFO,
            format_args!(
                "udp done, packets from/to client:{}/{}, bytes from/to client:{}/{}, bytes from/to upstream:{}/{}",
                u.requests.get(),
                u.responses.get(),
                s.received.get(),
                c.sent.get(),
                u.received.get(),
                pc.sent.get()
            ),
        );

        return Some(NGX_STREAM_OK);
    }

    // c->type == SOCK_STREAM

    let (c_eof, pc_eof) = (r.c_eof.get(), r.pc_eof.get());

    if (!c_eof && !pc_eof) || (!c_eof && r.c_buffered.get()) || (!pc_eof && r.pc_buffered.get()) {
        return None;
    }

    if r.conf.half_close {
        // avoid closing live connections until both read ends get EOF
        if !(c_eof && pc_eof && !r.c_buffered.get() && !r.pc_buffered.get()) {
            return None;
        }
    }

    log_no_handler(
        &c.log,
        NGX_LOG_INFO,
        format_args!(
            "{} disconnected, bytes from/to client:{}/{}, bytes from/to upstream:{}/{}",
            if from_upstream { "upstream" } else { "client" },
            s.received.get(),
            c.sent.get(),
            u.received.get(),
            pc.sent.get()
        ),
    );

    Some(NGX_STREAM_OK)
}

/// ngx_delete_udp_connection: the next datagram of the client starts a new
/// session.
fn delete_udp_connection(c: &Connection) {
    ngx_core::event_udp::delete_udp_connection(c);
}

// --- configuration ---

fn proxy_create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(ProxySrvConf {
        connect_timeout: Val::unset(),
        timeout: Val::unset(),
        next_upstream_timeout: Val::unset(),
        buffer_size: Val::unset(),
        upload_rate: None,
        download_rate: None,
        requests: Val::unset(),
        responses: Val::unset(),
        next_upstream_tries: Val::unset(),
        next_upstream: Val::unset(),
        proxy_protocol: Val::unset(),
        half_close: Val::unset(),
        local: Val::unset(),
        socket_keepalive: Val::unset(),
        socket_rcvbuf: Val::unset(),
        socket_sndbuf: Val::unset(),
        ssl_enable: Val::unset(),
        ssl_session_reuse: Val::unset(),
        ssl_protocols: 0,
        ssl_ciphers: Val::unset(),
        ssl_name: Val::unset(),
        ssl_server_name: Val::unset(),
        ssl_alpn: Val::unset(),
        ssl_verify: Val::unset(),
        ssl_verify_depth: Val::unset(),
        ssl_trusted_certificate: Val::unset(),
        ssl_crl: Val::unset(),
        ssl_certificate: Val::unset(),
        ssl_certificate_key: Val::unset(),
        ssl_certificate_cache: Val::unset(),
        ssl_passwords: Val::unset(),
        ssl_conf_commands: Val::unset(),
        ssl: None,
        upstream: None,
        upstream_value: None,
    })
}

fn proxy_merge_srv_conf(cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev_rc = conf_rc::<ProxySrvConf>(parent);
    let conf_rc = conf_rc::<ProxySrvConf>(child);

    merge_values(&prev_rc.borrow(), &mut conf_rc.borrow_mut());

    // ngx_stream_proxy_merge_ssl

    merge_ssl(&prev_rc, &conf_rc, &cf.log);

    let prev = prev_rc.borrow();
    let mut conf = conf_rc.borrow_mut();

    conf.ssl_enable.merge(&prev.ssl_enable, false);

    conf.ssl_session_reuse.merge(&prev.ssl_session_reuse, true);

    if conf.ssl_protocols == 0 {
        conf.ssl_protocols = if prev.ssl_protocols == 0 { NGX_CONF_BITMASK_SET | NGX_SSL_DEFAULT_PROTOCOLS } else { prev.ssl_protocols };
    }

    conf.ssl_ciphers.merge(&prev.ssl_ciphers, b"DEFAULT".to_vec());

    merge_ptr(&mut conf.ssl_name, &prev.ssl_name);

    conf.ssl_server_name.merge(&prev.ssl_server_name, false);

    merge_ptr(&mut conf.ssl_alpn, &prev.ssl_alpn);

    conf.ssl_verify.merge(&prev.ssl_verify, false);

    conf.ssl_verify_depth.merge(&prev.ssl_verify_depth, 1);

    conf.ssl_trusted_certificate.merge(&prev.ssl_trusted_certificate, Vec::new());

    conf.ssl_crl.merge(&prev.ssl_crl, Vec::new());

    merge_ptr(&mut conf.ssl_certificate, &prev.ssl_certificate);

    merge_ptr(&mut conf.ssl_certificate_key, &prev.ssl_certificate_key);

    merge_ptr(&mut conf.ssl_certificate_cache, &prev.ssl_certificate_cache);

    drop(prev);

    merge_ssl_passwords(cf, &prev_rc, &mut conf);

    let prev = prev_rc.borrow();

    merge_ptr(&mut conf.ssl_conf_commands, &prev.ssl_conf_commands);

    drop(prev);

    if *conf.ssl_enable {
        set_ssl(cf, &mut conf)?;
    }

    Ok(())
}

/// ngx_conf_merge_ptr_value(conf, prev, NULL)
fn merge_ptr<T: Clone>(conf: &mut Val<Option<T>>, prev: &Val<Option<T>>) {
    if !conf.is_set() {
        *conf = Val::set(prev.as_option().cloned().flatten());
    }
}

/// ngx_stream_proxy_merge_ssl: the context of the server, or the one of
/// stream{} when no SSL directive is in the server
fn merge_ssl(prev_rc: &Rc<RefCell<ProxySrvConf>>, conf_rc: &Rc<RefCell<ProxySrvConf>>, log: &Log) {
    let preserve = {
        let conf = conf_rc.borrow();

        let untouched = conf.ssl_protocols == 0
            && !conf.ssl_ciphers.is_set()
            && !conf.ssl_certificate.is_set()
            && !conf.ssl_certificate_key.is_set()
            && !conf.ssl_passwords.is_set()
            && !conf.ssl_verify.is_set()
            && !conf.ssl_verify_depth.is_set()
            && !conf.ssl_trusted_certificate.is_set()
            && !conf.ssl_crl.is_set()
            && !conf.ssl_session_reuse.is_set()
            && !conf.ssl_conf_commands.is_set();

        if untouched {
            let prev_ssl = prev_rc.borrow().ssl.clone();

            if let Some(ssl) = prev_ssl {
                drop(conf);
                conf_rc.borrow_mut().ssl = Some(ssl);
                return;
            }
        }

        untouched
    };

    let ssl = Rc::new(RefCell::new(NgxSsl::new(log.clone())));

    conf_rc.borrow_mut().ssl = Some(ssl.clone());

    // special handling to preserve conf->ssl in the "stream" section to
    // inherit it to all servers

    if preserve && !Rc::ptr_eq(prev_rc, conf_rc) {
        prev_rc.borrow_mut().ssl = Some(ssl);
    }
}

/// ngx_stream_proxy_merge_ssl_passwords: a certificate with variables
/// needs the passwords at run time
fn merge_ssl_passwords(cf: &mut Conf, prev_rc: &Rc<RefCell<ProxySrvConf>>, conf: &mut ProxySrvConf) {
    let prev_passwords = prev_rc.borrow().ssl_passwords.clone();

    merge_ptr(&mut conf.ssl_passwords, &prev_passwords);

    let (cert, key) = match (conf.ssl_certificate.as_option().cloned().flatten(), conf.ssl_certificate_key.as_option().cloned().flatten()) {
        (Some(c), Some(k)) if !c.value.is_empty() => (c, k),
        _ => return,
    };

    if cert.is_constant() && key.is_constant() {
        return;
    }

    let passwords = conf.ssl_passwords.as_option().cloned().flatten();

    let preserved = ngx_ssl_preserve_passwords(cf, passwords.as_ref());

    conf.ssl_passwords = Val::set(Some(preserved));
}

/// ngx_stream_proxy_set_ssl: the context of the upstream connections
fn set_ssl(cf: &mut Conf, pscf: &mut ProxySrvConf) -> ConfResult {
    let ssl = pscf.ssl.clone().expect("ssl");
    let mut ssl = ssl.borrow_mut();

    if !ssl.ctx.is_null() {
        return Ok(());
    }

    if ngx_ssl_create(&mut ssl, pscf.ssl_protocols, std::ptr::null_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    let ciphers = pscf.ssl_ciphers.get().clone();

    if ngx_ssl_ciphers(cf, &mut ssl, &ciphers, false) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if let Some(cert) = pscf.ssl_certificate.as_option().cloned().flatten() {
        if !cert.value.is_empty() {
            let key = match pscf.ssl_certificate_key.as_option().cloned().flatten() {
                Some(k) => k,
                None => {
                    ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"proxy_ssl_certificate_key\" is defined for certificate \"{}\"", B(&cert.value));
                    return Err(ConfError::Logged);
                }
            };

            if cert.is_constant() && key.is_constant() {
                let mut c = cert.value.clone();
                let mut k = key.value.clone();

                let passwords = pscf.ssl_passwords.as_option().cloned().flatten();

                if ngx_ssl_certificate(cf, &mut ssl, &mut c, &mut k, passwords.as_ref()) != NGX_OK {
                    return Err(ConfError::Logged);
                }
            }
        }
    }

    if *pscf.ssl_verify {
        if pscf.ssl_trusted_certificate.get().is_empty() {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return Err(ConfError::Logged);
        }

        let mut trusted = pscf.ssl_trusted_certificate.get().clone();

        if ngx_ssl_trusted_certificate(cf, &mut ssl, &mut trusted, *pscf.ssl_verify_depth) != NGX_OK {
            return Err(ConfError::Logged);
        }

        let mut crl = pscf.ssl_crl.get().clone();

        if ngx_ssl_crl(cf, &mut ssl, &mut crl) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    if ngx_ssl_client_session_cache(cf, &mut ssl, *pscf.ssl_session_reuse) != NGX_OK {
        return Err(ConfError::Logged);
    }

    let mut commands = pscf.ssl_conf_commands.as_option().cloned().flatten();

    if ngx_ssl_conf_commands(cf, &mut ssl, commands.as_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    Ok(())
}

/// The values of ngx_stream_proxy_merge_srv_conf before the SSL ones.
fn merge_values(prev: &ProxySrvConf, conf: &mut ProxySrvConf) {
    conf.connect_timeout.merge(&prev.connect_timeout, 60000);

    conf.timeout.merge(&prev.timeout, 10 * 60000);

    conf.next_upstream_timeout.merge(&prev.next_upstream_timeout, 0);

    conf.buffer_size.merge(&prev.buffer_size, 16384);

    if conf.upload_rate.is_none() {
        conf.upload_rate = prev.upload_rate.clone();
    }

    if conf.download_rate.is_none() {
        conf.download_rate = prev.download_rate.clone();
    }

    conf.requests.merge(&prev.requests, 0);

    conf.responses.merge(&prev.responses, NGX_MAX_INT32_VALUE);

    conf.next_upstream_tries.merge(&prev.next_upstream_tries, 0);

    conf.next_upstream.merge(&prev.next_upstream, true);

    conf.proxy_protocol.merge(&prev.proxy_protocol, 0);

    let prev_local = prev.local.clone();
    conf.local.merge(&prev_local, None);

    conf.socket_keepalive.merge(&prev.socket_keepalive, false);

    conf.socket_rcvbuf.merge(&prev.socket_rcvbuf, 0);

    conf.socket_sndbuf.merge(&prev.socket_sndbuf, 0);

    conf.half_close.merge(&prev.half_close, false);
}

/// ngx_stream_proxy_pass
fn proxy_pass(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    {
        let p = pscf.borrow();
        if p.upstream.is_some() || p.upstream_value.is_some() {
            return Err(msg("is duplicate"));
        }
    }

    let cscf = core_srv_conf(cf);
    cscf.borrow_mut().handler = Some(content_fn(proxy_handler));

    let url = cf.args[1].clone();

    let mut ccv = CompileComplexValue::default();
    let cv = compile_complex_value(cf, &url, &mut ccv)?;

    if !cv.is_constant() {
        pscf.borrow_mut().upstream_value = Some(cv);
        return Ok(());
    }

    let mut u = Url::new(&url);
    u.no_resolve = true;

    let uscf = upstream_add(cf, &mut u, 0)?;

    pscf.borrow_mut().upstream = Some(uscf);

    Ok(())
}

/// ngx_stream_proxy_bind
fn proxy_bind(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    if pscf.borrow().local.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    if value.len() == 2 && value[1] == b"off" {
        pscf.borrow_mut().local = Val::set(None);
        return Ok(());
    }

    let mut ccv = CompileComplexValue::default();
    let cv = compile_complex_value(cf, &value[1], &mut ccv)?;

    let mut local = UpstreamLocal { addr: None, value: None, transparent: false };

    if !cv.is_constant() {
        local.value = Some(cv);
    } else {
        match ngx_core::inet::parse_addr_port(&value[1]) {
            Some(sa) => local.addr = Some(LocalAddr { sockaddr: sa, name: value[1].clone() }),
            None => return Err(cf.emerg(format_args!("invalid address \"{}\"", B(&value[1])))),
        }
    }

    if value.len() > 2 {
        if value[2] == b"transparent" {
            // ccf->transparent keeps the capabilities of the workers when
            // they switch the user; the process layer has no such port yet
            local.transparent = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    pscf.borrow_mut().local = Val::set(Some(Rc::new(local)));

    Ok(())
}

/// proxy_downstream_buffer, proxy_upstream_buffer: deprecated
fn proxy_deprecated_buffer(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    set_size(cf, cmd, &mut pscf.borrow_mut().buffer_size)?;

    deprecated(cf, cmd.name, Some("proxy_buffer_size"));

    Ok(())
}

fn proxy_upload_rate(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));
    let mut slot = pscf.borrow().upload_rate.clone();
    set_complex_value_size_slot(cf, &mut slot)?;
    pscf.borrow_mut().upload_rate = slot;
    Ok(())
}

fn proxy_download_rate(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));
    let mut slot = pscf.borrow().download_rate.clone();
    set_complex_value_size_slot(cf, &mut slot)?;
    pscf.borrow_mut().download_rate = slot;
    Ok(())
}

static PROXY_PROTOCOL_VERSIONS: &[(&str, u32)] = &[("off", 0), ("on", 1), ("v2", 2)];

static PROXY_SSL_PROTOCOLS: &[(&str, u32)] = &[
    ("SSLv2", NGX_SSL_SSLV2),
    ("SSLv3", NGX_SSL_SSLV3),
    ("TLSv1", NGX_SSL_TLSV1),
    ("TLSv1.1", NGX_SSL_TLSV1_1),
    ("TLSv1.2", NGX_SSL_TLSV1_2),
    ("TLSv1.3", NGX_SSL_TLSV1_3),
];

fn proxy_ssl_protocols(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));
    let mut p = pscf.borrow_mut();
    set_bitmask(cf, cmd, &mut p.ssl_protocols, PROXY_SSL_PROTOCOLS)
}

/// proxy_ssl_name: ngx_stream_set_complex_value_slot
fn proxy_ssl_name_slot(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    if pscf.borrow().ssl_name.as_option().is_some_and(|v| v.is_some()) {
        return Err(msg("is duplicate"));
    }

    let mut slot = None;
    set_complex_value_slot(cf, &mut slot)?;

    pscf.borrow_mut().ssl_name = Val::set(slot);

    Ok(())
}

/// proxy_ssl_certificate, proxy_ssl_certificate_key:
/// ngx_stream_set_complex_value_zero_slot
fn proxy_ssl_certificate_slot(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    let mut slot = if cmd.name == "proxy_ssl_certificate" { pscf.borrow().ssl_certificate.clone() } else { pscf.borrow().ssl_certificate_key.clone() };

    set_complex_value_zero_slot(cf, &mut slot)?;

    let mut p = pscf.borrow_mut();

    if cmd.name == "proxy_ssl_certificate" {
        p.ssl_certificate = slot;
    } else {
        p.ssl_certificate_key = slot;
    }

    Ok(())
}

/// ngx_stream_proxy_ssl_alpn_set_slot
fn proxy_ssl_alpn_set_slot(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    if pscf.borrow().ssl_alpn.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let mut alpn = Vec::with_capacity(value.len() - 1);

    for v in &value[1..] {
        let mut ccv = CompileComplexValue::default();
        let cv = compile_complex_value(cf, v, &mut ccv)?;

        if cv.is_constant() && v.len() > 255 {
            return Err(msg("protocol too long"));
        }

        alpn.push(cv);
    }

    pscf.borrow_mut().ssl_alpn = Val::set(Some(alpn));

    Ok(())
}

/// ngx_stream_proxy_ssl_certificate_cache
fn proxy_ssl_certificate_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    if pscf.borrow().ssl_certificate_cache.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let mut max: i64 = 0;
    let mut inactive: i64 = 10;
    let mut valid: i64 = 60;
    let mut off = false;

    for v in &value[1..] {
        let failed = |cf: &Conf| cf.emerg(format_args!("invalid parameter \"{}\"", B(v)));

        if let Some(n) = v.strip_prefix(b"max=") {
            max = match ngx_core::string::atoi(n) {
                Some(m) if m > 0 => m,
                _ => return Err(failed(cf)),
            };
            continue;
        }

        if let Some(t) = v.strip_prefix(b"inactive=") {
            inactive = match ngx_core::parse::parse_time(t, true) {
                Some(t) => t,
                None => return Err(failed(cf)),
            };
            continue;
        }

        if let Some(t) = v.strip_prefix(b"valid=") {
            valid = match ngx_core::parse::parse_time(t, true) {
                Some(t) => t,
                None => return Err(failed(cf)),
            };
            continue;
        }

        if v == b"off" {
            off = true;
            continue;
        }

        return Err(failed(cf));
    }

    if off {
        pscf.borrow_mut().ssl_certificate_cache = Val::set(None);
        return Ok(());
    }

    if max == 0 {
        return Err(cf.emerg(format_args!("\"proxy_ssl_certificate_cache\" must have the \"max\" parameter")));
    }

    let cache = ngx_ssl_cache_init(max as usize, valid, inactive);

    pscf.borrow_mut().ssl_certificate_cache = Val::set(Some(Rc::new(RefCell::new(cache))));

    Ok(())
}

/// ngx_stream_proxy_ssl_password_file
fn proxy_ssl_password_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    if pscf.borrow().ssl_passwords.is_set() {
        return Err(msg("is duplicate"));
    }

    let file = cf.args[1].clone();

    match ngx_ssl_read_password_file(cf, &file) {
        Some(p) => {
            pscf.borrow_mut().ssl_passwords = Val::set(Some(p));
            Ok(())
        }
        None => Err(ConfError::Logged),
    }
}

/// proxy_ssl_conf_command: ngx_conf_set_keyval_slot with
/// ngx_stream_proxy_ssl_conf_command_check (SSL_CONF_cmd() is available)
fn proxy_ssl_conf_command(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));

    let mut p = pscf.borrow_mut();

    if !p.ssl_conf_commands.is_set() {
        p.ssl_conf_commands = Val::set(Some(Vec::new()));
    }

    p.ssl_conf_commands.0.as_mut().unwrap().as_mut().unwrap().push((cf.args[1].clone(), cf.args[2].clone()));

    Ok(())
}

fn proxy_protocol_directive(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<ProxySrvConf>(conf.as_ref().expect("conf"));
    let mut p = pscf.borrow_mut();
    set_enum(cf, cmd, &mut p.proxy_protocol, PROXY_PROTOCOL_VERSIONS)
}

pub fn proxy_module() -> ModuleDef {
    const SRV: u32 = NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF;

    stream_module_def(
        "ngx_stream_proxy_module",
        StreamModuleDef { create_srv_conf: Some(proxy_create_srv_conf), merge_srv_conf: Some(proxy_merge_srv_conf), ..Default::default() },
        vec![
            cmd_fn!("proxy_pass", NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_pass),
            cmd_fn!("proxy_bind", SRV | NGX_CONF_TAKE12, ConfLevel::Srv, proxy_bind),
            cmd!("proxy_socket_keepalive", SRV | NGX_CONF_FLAG, ConfLevel::Srv, ProxySrvConf, socket_keepalive, set_flag),
            cmd!("proxy_socket_rcvbuf", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, socket_rcvbuf, set_size),
            cmd!("proxy_socket_sndbuf", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, socket_sndbuf, set_size),
            cmd!("proxy_connect_timeout", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, connect_timeout, set_msec),
            cmd!("proxy_timeout", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, timeout, set_msec),
            cmd!("proxy_buffer_size", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, buffer_size, set_size),
            cmd_fn!("proxy_downstream_buffer", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_deprecated_buffer),
            cmd_fn!("proxy_upstream_buffer", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_deprecated_buffer),
            cmd_fn!("proxy_upload_rate", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_upload_rate),
            cmd_fn!("proxy_download_rate", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_download_rate),
            cmd!("proxy_requests", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, requests, set_num),
            cmd!("proxy_responses", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, responses, set_num),
            cmd!("proxy_next_upstream", SRV | NGX_CONF_FLAG, ConfLevel::Srv, ProxySrvConf, next_upstream, set_flag),
            cmd!("proxy_next_upstream_tries", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, next_upstream_tries, set_num),
            cmd!("proxy_next_upstream_timeout", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, next_upstream_timeout, set_msec),
            cmd_fn!("proxy_protocol", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_protocol_directive),
            cmd!("proxy_half_close", SRV | NGX_CONF_FLAG, ConfLevel::Srv, ProxySrvConf, half_close, set_flag),
            cmd!("proxy_ssl", SRV | NGX_CONF_FLAG, ConfLevel::Srv, ProxySrvConf, ssl_enable, set_flag),
            cmd!("proxy_ssl_session_reuse", SRV | NGX_CONF_FLAG, ConfLevel::Srv, ProxySrvConf, ssl_session_reuse, set_flag),
            cmd_fn!("proxy_ssl_protocols", SRV | NGX_CONF_1MORE, ConfLevel::Srv, proxy_ssl_protocols),
            cmd!("proxy_ssl_ciphers", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, ssl_ciphers, set_str),
            cmd_fn!("proxy_ssl_name", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_ssl_name_slot),
            cmd!("proxy_ssl_server_name", SRV | NGX_CONF_FLAG, ConfLevel::Srv, ProxySrvConf, ssl_server_name, set_flag),
            cmd_fn!("proxy_ssl_alpn", SRV | NGX_CONF_1MORE, ConfLevel::Srv, proxy_ssl_alpn_set_slot),
            cmd!("proxy_ssl_verify", SRV | NGX_CONF_FLAG, ConfLevel::Srv, ProxySrvConf, ssl_verify, set_flag),
            cmd!("proxy_ssl_verify_depth", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, ssl_verify_depth, set_num),
            cmd!("proxy_ssl_trusted_certificate", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, ssl_trusted_certificate, set_str),
            cmd!("proxy_ssl_crl", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, ProxySrvConf, ssl_crl, set_str),
            cmd_fn!("proxy_ssl_certificate", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_ssl_certificate_slot),
            cmd_fn!("proxy_ssl_certificate_key", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_ssl_certificate_slot),
            cmd_fn!("proxy_ssl_certificate_cache", SRV | NGX_CONF_TAKE123, ConfLevel::Srv, proxy_ssl_certificate_cache),
            cmd_fn!("proxy_ssl_password_file", SRV | NGX_CONF_TAKE1, ConfLevel::Srv, proxy_ssl_password_file),
            cmd_fn!("proxy_ssl_conf_command", SRV | NGX_CONF_TAKE2, ConfLevel::Srv, proxy_ssl_conf_command),
        ],
    )
}
