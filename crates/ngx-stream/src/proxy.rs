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

    let res = tokio::select! {
        r = resolver.resolve_host(host, resolver_timeout) => r,
        _ = c.close_notify.notified() => {
            if c.close.get() {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "shutdown timeout");
            }
            proxy_finalize(s, NGX_STREAM_OK).await;
            return;
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
        // ngx_stream_proxy_connect_handler

        let res = tokio::select! {
            r = tokio::time::timeout(Duration::from_millis(connect_timeout), pc.writable()) => r,
            _ = c.close_notify.notified() => {
                if c.close.get() {
                    ngx_log_error!(NGX_LOG_INFO, c.log, None, "shutdown timeout");
                }
                proxy_finalize(s, NGX_STREAM_OK).await;
                return Connected::Done;
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

    if !preread.is_empty() {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream proxy add preread buffer: {}", preread.len());

        upstream_out.push_back(preread);
    }

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

        upstream_out.push_front(header);

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
        c_eof: Cell::new(false),
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

        tokio::select! {
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

            if r.eof(from_upstream).get() || delay_until.is_some() {
                break;
            }

            let mut size = buf.len();

            if limit_rate != 0 {
                let limit = limit_rate as i64 * (ngx_core::times::time() - u.start_sec.get() + 1) - received(0);

                if limit <= 0 {
                    r.delayed(from_upstream).set(true);
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
                    src.connection_error(e.raw_os_error().unwrap_or(0), "recv() failed");
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
                    r.delayed(from_upstream).set(true);
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

            out.push_back(buf[..n].to_vec());

            packets();
            received(n as i64);

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

            r.delayed(from_upstream).set(false);

            // the delayed event: the proxy timer is back if nothing is
            // delayed
            r.update_timer();

            continue;
        }

        if src.readable().await.is_err() {
            // the socket is gone: the recv reports it
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
/// session. The UDP listening sockets (ngx_event_udp.c) are ported in the
/// connection layer separately; until then no UDP session exists.
fn delete_udp_connection(_c: &Connection) {}

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
        upstream: None,
        upstream_value: None,
    })
}

fn proxy_merge_srv_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<ProxySrvConf>(parent).borrow();
    let mut conf = conf_cell::<ProxySrvConf>(child).borrow_mut();

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

    Ok(())
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
        ],
    )
}
