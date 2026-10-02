//! ngx_http_upstream.c: the upstream{} configuration and the implicit
//! upstreams of proxy_pass and friends (ngx_http_upstream_add), the peer
//! interface balancers implement (ngx_peer_connection_t get/free), and
//! the peer side of a request's upstream: tries, next upstream
//! (ngx_http_upstream_next) and the free on finalization. The request path
//! itself lives in proxy.rs, fastcgi.rs and memcached.rs, which are not
//! ports of ngx_http_upstream.c.

use std::any::{Any, TypeId};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::conf::{NGX_CONF_BLOCK, NGX_CONF_TAKE1, NGX_CONF_1MORE};
use ngx_core::inet::{Addr, SockAddr, Url};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::resolver::Resolver;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::request::*;
use crate::upstream_round_robin::UpstreamPeers;
use crate::variables::{VarDef, NGX_HTTP_VAR_PREFIX, NGX_HTTP_VAR_NOCACHEABLE, prefix_var_name};
use crate::{NGX_HTTP_MAIN_CONF, NGX_HTTP_UPS_CONF, HttpModuleDef, http_module_def};

// ============================================================================
// CONSTANTS AND FLAGS
// ============================================================================

// Upstream failure flags (next_upstream bitmask)
pub const NGX_HTTP_UPSTREAM_FT_ERROR: u32 = 0x00000002;
pub const NGX_HTTP_UPSTREAM_FT_TIMEOUT: u32 = 0x00000004;
pub const NGX_HTTP_UPSTREAM_FT_INVALID_HEADER: u32 = 0x00000008;
pub const NGX_HTTP_UPSTREAM_FT_HTTP_500: u32 = 0x00000010;
pub const NGX_HTTP_UPSTREAM_FT_HTTP_502: u32 = 0x00000020;
pub const NGX_HTTP_UPSTREAM_FT_HTTP_503: u32 = 0x00000040;
pub const NGX_HTTP_UPSTREAM_FT_HTTP_504: u32 = 0x00000080;
pub const NGX_HTTP_UPSTREAM_FT_HTTP_403: u32 = 0x00000100;
pub const NGX_HTTP_UPSTREAM_FT_HTTP_404: u32 = 0x00000200;
pub const NGX_HTTP_UPSTREAM_FT_HTTP_429: u32 = 0x00000400;
pub const NGX_HTTP_UPSTREAM_FT_UPDATING: u32 = 0x00000800;
pub const NGX_HTTP_UPSTREAM_FT_BUSY_LOCK: u32 = 0x00001000;
pub const NGX_HTTP_UPSTREAM_FT_MAX_WAITING: u32 = 0x00002000;
pub const NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT: u32 = 0x00004000;
pub const NGX_HTTP_UPSTREAM_FT_NOLIVE: u32 = 0x40000000;
pub const NGX_HTTP_UPSTREAM_FT_OFF: u32 = 0x80000000;

pub const NGX_HTTP_UPSTREAM_FT_STATUS: u32 = NGX_HTTP_UPSTREAM_FT_HTTP_500
    | NGX_HTTP_UPSTREAM_FT_HTTP_502
    | NGX_HTTP_UPSTREAM_FT_HTTP_503
    | NGX_HTTP_UPSTREAM_FT_HTTP_504
    | NGX_HTTP_UPSTREAM_FT_HTTP_403
    | NGX_HTTP_UPSTREAM_FT_HTTP_404
    | NGX_HTTP_UPSTREAM_FT_HTTP_429;

// X-Accel-* header ignore flags
pub const NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT: u32 = 0x00000002;
pub const NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES: u32 = 0x00000004;
pub const NGX_HTTP_UPSTREAM_IGN_EXPIRES: u32 = 0x00000008;
pub const NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL: u32 = 0x00000010;
pub const NGX_HTTP_UPSTREAM_IGN_SET_COOKIE: u32 = 0x00000020;
pub const NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE: u32 = 0x00000040;
pub const NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING: u32 = 0x00000080;
pub const NGX_HTTP_UPSTREAM_IGN_XA_CHARSET: u32 = 0x00000100;
pub const NGX_HTTP_UPSTREAM_IGN_VARY: u32 = 0x00000200;

// Server flags
pub const NGX_HTTP_UPSTREAM_CREATE: u32 = 0x0001;
pub const NGX_HTTP_UPSTREAM_WEIGHT: u32 = 0x0002;
pub const NGX_HTTP_UPSTREAM_MAX_FAILS: u32 = 0x0004;
pub const NGX_HTTP_UPSTREAM_FAIL_TIMEOUT: u32 = 0x0008;
pub const NGX_HTTP_UPSTREAM_DOWN: u32 = 0x0010;
pub const NGX_HTTP_UPSTREAM_BACKUP: u32 = 0x0020;
pub const NGX_HTTP_UPSTREAM_MODIFY: u32 = 0x0040;
pub const NGX_HTTP_UPSTREAM_MAX_CONNS: u32 = 0x0100;

// ngx_event_connect.h: peer free states
pub const NGX_PEER_KEEPALIVE: u32 = 1;
pub const NGX_PEER_NEXT: u32 = 2;
pub const NGX_PEER_FAILED: u32 = 4;

// peer.notify types
pub const NGX_HTTP_UPSTREAM_NOTIFY_CONNECT: u32 = 0x1;
pub const NGX_HTTP_UPSTREAM_NOTIFY_HEADER: u32 = 0x2;

crate::http_module_index!("ngx_http_upstream_module");


// ============================================================================
// UPSTREAM CONNECTIONS
// ============================================================================

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Upstream connection — either TCP or UNIX so proxy_pass to
/// http://unix:/path.sock:/uri works, or a connection of
/// ngx_event_connect_peer with c->ssl (https upstreams).
pub enum UpstreamSock {
    Tcp(TcpStream),
    Unix(tokio::net::UnixStream),
    Conn(crate::upstream_ssl::PeerConn),
}


// the stream types are Unpin: Pin::new projects to them
impl AsyncRead for UpstreamSock {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamSock::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamSock::Unix(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamSock::Conn(c) => c.poll_read(cx, buf),
        }
    }
}
impl AsyncWrite for UpstreamSock {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpstreamSock::Tcp(s) => Pin::new(s).poll_write(cx, b),
            UpstreamSock::Unix(s) => Pin::new(s).poll_write(cx, b),
            UpstreamSock::Conn(c) => c.poll_write(cx, b),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamSock::Tcp(s) => Pin::new(s).poll_flush(cx),
            UpstreamSock::Unix(s) => Pin::new(s).poll_flush(cx),
            UpstreamSock::Conn(_) => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamSock::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            UpstreamSock::Unix(s) => Pin::new(s).poll_shutdown(cx),
            UpstreamSock::Conn(c) => c.poll_shutdown(cx),
        }
    }
}
impl UpstreamSock {
    /// The connection is closed as ngx_http_upstream_next does: an https
    /// one without "close notify".
    pub fn set_no_shutdown(&self) {
        if let UpstreamSock::Conn(c) = self {
            c.set_no_shutdown();
        }
    }

    /// Wait until the upstream has sent data or closed. The readiness is
    /// checked with a peek, so a stale one (a keepalive connection whose
    /// last response ended without EAGAIN) is cleared instead of reported.
    pub(crate) async fn wait_readable(&mut self) {
        use std::os::unix::io::AsRawFd;
        loop {
            let (ready, peek) = match self {
                UpstreamSock::Tcp(s) => (s.readable().await, s.try_io(tokio::io::Interest::READABLE, || peek_fd(s.as_raw_fd()))),
                UpstreamSock::Unix(s) => (s.readable().await, s.try_io(tokio::io::Interest::READABLE, || peek_fd(s.as_raw_fd()))),
                UpstreamSock::Conn(c) => return c.wait_readable().await,
            };
            if ready.is_err() {
                return;
            }
            match peek {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                _ => return,
            }
        }
    }
}

impl UpstreamSock {
    /// ngx_http_upstream_keepalive_close_handler on the read event of a
    /// cached connection, which keeps its own registration while cached as
    /// in C: Ready when the connection is to be closed (the upstream sent
    /// data or closed it, or an error), Pending until the next read event.
    /// A peek that finds nothing clears the readiness (ev->ready = 0).
    pub(crate) fn poll_idle_close(&self, cx: &mut Context<'_>) -> Poll<()> {
        use std::os::unix::io::AsRawFd;

        loop {
            let peek = match self {
                UpstreamSock::Tcp(s) => match s.poll_read_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Ready(Ok(())) => s.try_io(tokio::io::Interest::READABLE, || peek_fd(s.as_raw_fd())),
                },
                UpstreamSock::Unix(s) => match s.poll_read_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Ready(Ok(())) => s.try_io(tokio::io::Interest::READABLE, || peek_fd(s.as_raw_fd())),
                },
                UpstreamSock::Conn(c) => return c.c.poll_peek_close(cx),
            };

            match peek {
                // EAGAIN: try_io cleared the readiness, poll for the next event
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                _ => return Poll::Ready(()),
            }
        }
    }
}

fn peek_fd(fd: std::os::unix::io::RawFd) -> std::io::Result<usize> {
    let mut b = [0u8; 1];
    Ok(nix::sys::socket::recv(fd, &mut b, nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT)?)
}


// ============================================================================
// CONFIGURATION
// ============================================================================

/// ngx_http_upstream_server_t: a server of an upstream{} block (or the
/// single address of an implicit upstream).
#[derive(Clone, Default)]
pub struct UpstreamServer {
    pub name: Vec<u8>,
    pub addrs: Vec<Addr>,
    pub weight: u32,
    pub max_conns: u32,
    pub max_fails: u32,
    /// seconds
    pub fail_timeout: i64,
    pub slow_start: u64,
    /// 0, NGX_HTTP_UPSTREAM_FAILED ("down") or NGX_HTTP_UPSTREAM_DRAINING
    pub down: u32,
    pub backup: bool,
    /// resolve at run time (zone)
    pub host: Vec<u8>,
    pub service: Vec<u8>,
    /// route=
    pub sid: Vec<u8>,
}

/// Initializes the peers of an upstream at configuration time
/// (peer.init_upstream).
pub type InitUpstream = fn(&mut Conf, &Rc<UpstreamSrvConf>) -> ConfResult;

/// Initializes the balancer for a request (peer.init).
pub type InitPeer = Rc<dyn Fn(&R, &Rc<UpstreamSrvConf>) -> Result<Box<dyn PeerBalancer>, ()>>;

/// ngx_http_upstream_srv_conf_t
pub struct UpstreamSrvConf {
    pub host: Vec<u8>,
    pub file_name: Vec<u8>,
    pub line: usize,
    pub port: Cell<u16>,
    pub no_port: bool,
    pub flags: Cell<u32>,
    /// None for an implicit upstream of a name (resolved at init)
    pub servers: RefCell<Option<Vec<UpstreamServer>>>,
    /// defined by upstream{} (C: srv_conf != NULL)
    pub block: Cell<bool>,

    pub init_upstream: Cell<Option<InitUpstream>>,
    pub init: RefCell<Option<InitPeer>>,
    /// us->peer.data of the round-robin based balancers: the peers, in
    /// their memory
    pub peers: UpstreamPeers,

    pub shm_zone: RefCell<Option<Rc<ngx_core::shm::ShmZone>>>,
    pub resolver: RefCell<Option<Rc<Resolver>>>,
    /// msec; None until merged (NGX_CONF_UNSET_MSEC)
    pub resolver_timeout: Cell<Option<u64>>,

    /// the srv confs of the balancer modules, by type
    modules: RefCell<Vec<(TypeId, Rc<dyn Any>)>>,
}

impl UpstreamSrvConf {
    fn new(host: &[u8], port: u16, no_port: bool, flags: u32, file_name: Vec<u8>, line: usize) -> UpstreamSrvConf {
        UpstreamSrvConf {
            host: host.to_vec(),
            file_name,
            line,
            port: Cell::new(port),
            no_port,
            flags: Cell::new(flags),
            servers: RefCell::new(None),
            block: Cell::new(false),
            init_upstream: Cell::new(None),
            init: RefCell::new(None),
            peers: UpstreamPeers::default(),
            shm_zone: RefCell::new(None),
            resolver: RefCell::new(None),
            resolver_timeout: Cell::new(None),
            modules: RefCell::new(Vec::new()),
        }
    }

    /// The srv conf of a balancer module (ngx_http_conf_upstream_srv_conf).
    pub fn module_conf<T: 'static>(&self) -> Option<Rc<T>> {
        let id = TypeId::of::<T>();
        let m = self.modules.borrow();
        let c = m.iter().find(|(t, _)| *t == id)?.1.clone();
        c.downcast::<T>().ok()
    }

    pub fn set_module_conf<T: 'static>(&self, conf: Rc<T>) {
        let id = TypeId::of::<T>();
        let mut m = self.modules.borrow_mut();
        m.retain(|(t, _)| *t != id);
        m.push((id, conf));
    }

    /// The per-request balancer (uscf->peer.init).
    pub fn init_peer(self: &Rc<Self>, r: &R) -> Result<Box<dyn PeerBalancer>, ()> {
        let init = match self.init.borrow().clone() {
            Some(f) => f,
            None => return Err(()),
        };
        init(r, self)
    }
}

/// ngx_http_upstream_main_conf_t
pub struct UpstreamMainConf {
    pub upstreams: RefCell<Vec<Rc<UpstreamSrvConf>>>,
    /// the upstream{} being parsed (C: the block's srv_conf)
    pub current: RefCell<Option<Rc<UpstreamSrvConf>>>,
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(UpstreamMainConf { upstreams: RefCell::new(Vec::new()), current: RefCell::new(None) })
}

pub(crate) fn main_conf(cf: &Conf) -> Rc<RefCell<UpstreamMainConf>> {
    crate::get_main_conf::<UpstreamMainConf>(cf, ctx_index())
}

/// The upstream{} block whose directives are being parsed
/// (ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module)).
pub fn current_upstream(cf: &Conf) -> Option<Rc<UpstreamSrvConf>> {
    let umcf = main_conf(cf);
    let m = umcf.borrow();
    let c = m.current.borrow().clone();
    c
}

/// Warn about a second load balancing method in the block
/// ("load balancing method redefined"), and set it.
pub fn set_balancer(cf: &Conf, uscf: &UpstreamSrvConf, init: InitUpstream, flags: u32) {
    if uscf.init_upstream.get().is_some() {
        cf.warn(format_args!("load balancing method redefined"));
    }

    uscf.init_upstream.set(Some(init));
    uscf.flags.set(flags);
}

/// ngx_http_upstream_init_main_conf: initialize the peers of every upstream.
fn init_main_conf(cf: &mut Conf, _conf: &Rc<dyn Any>) -> ConfResult {
    let upstreams = main_conf(cf).borrow().upstreams.borrow().clone();

    for uscf in upstreams.iter() {
        let init = uscf.init_upstream.get().unwrap_or(crate::upstream_round_robin::init_round_robin);
        init(cf, uscf)?;
    }

    Ok(())
}

/// ngx_http_upstream: the upstream{} block.
fn upstream_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let mut u = Url::default();
    u.host = cf.args[1].clone();
    u.no_resolve = true;
    u.no_port = true;

    let uscf = upstream_add(
        cf,
        &mut u,
        NGX_HTTP_UPSTREAM_CREATE
            | NGX_HTTP_UPSTREAM_MODIFY
            | NGX_HTTP_UPSTREAM_WEIGHT
            | NGX_HTTP_UPSTREAM_MAX_CONNS
            | NGX_HTTP_UPSTREAM_MAX_FAILS
            | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
            | NGX_HTTP_UPSTREAM_DOWN
            | NGX_HTTP_UPSTREAM_BACKUP,
    )?;

    uscf.block.set(true);
    *uscf.servers.borrow_mut() = Some(Vec::new());

    let umcf = main_conf(cf);
    let prev = umcf.borrow().current.borrow_mut().replace(uscf.clone());

    let saved_ct = cf.cmd_type;
    cf.cmd_type = NGX_HTTP_UPS_CONF;
    let rv = cf.parse_block();
    cf.cmd_type = saved_ct;

    *umcf.borrow().current.borrow_mut() = prev;

    rv?;

    if uscf.servers.borrow().as_ref().is_none_or(|s| s.is_empty()) {
        return Err(cf.emerg(format_args!("no servers are inside upstream")));
    }

    Ok(())
}

/// ngx_http_upstream_server
fn server_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = match current_upstream(cf) {
        Some(u) => u,
        None => return Err(msg("\"server\" directive is not allowed here")),
    };

    let value = cf.args.clone();
    let flags = uscf.flags.get();

    let mut us = UpstreamServer::default();

    let mut weight: u32 = 1;
    let mut max_conns: u32 = 0;
    let mut max_fails: u32 = 1;
    let mut fail_timeout: i64 = 10;
    let mut resolve = false;

    let invalid = |cf: &Conf, v: &[u8]| cf.emerg(format_args!("invalid parameter \"{}\"", B(v)));
    let not_supported = |cf: &Conf, v: &[u8]| cf.emerg(format_args!("balancing method does not support parameter \"{}\"", B(v)));

    for v in value.iter().skip(2) {
        if let Some(n) = v.strip_prefix(b"weight=") {
            if flags & NGX_HTTP_UPSTREAM_WEIGHT == 0 {
                return Err(not_supported(cf, v));
            }
            weight = match ngx_core::string::atoi(n) {
                Some(w) if w > 0 => w as u32,
                _ => return Err(invalid(cf, v)),
            };
            continue;
        }

        if let Some(n) = v.strip_prefix(b"max_conns=") {
            if flags & NGX_HTTP_UPSTREAM_MAX_CONNS == 0 {
                return Err(not_supported(cf, v));
            }
            max_conns = match ngx_core::string::atoi(n) {
                Some(m) => m as u32,
                None => return Err(invalid(cf, v)),
            };
            continue;
        }

        if let Some(n) = v.strip_prefix(b"max_fails=") {
            if flags & NGX_HTTP_UPSTREAM_MAX_FAILS == 0 {
                return Err(not_supported(cf, v));
            }
            max_fails = match ngx_core::string::atoi(n) {
                Some(m) => m as u32,
                None => return Err(invalid(cf, v)),
            };
            continue;
        }

        if let Some(s) = v.strip_prefix(b"fail_timeout=") {
            if flags & NGX_HTTP_UPSTREAM_FAIL_TIMEOUT == 0 {
                return Err(not_supported(cf, v));
            }
            fail_timeout = match ngx_core::parse::parse_time(s, true) {
                Some(t) => t,
                None => return Err(invalid(cf, v)),
            };
            continue;
        }

        if v.as_slice() == b"backup" {
            if flags & NGX_HTTP_UPSTREAM_BACKUP == 0 {
                return Err(not_supported(cf, v));
            }
            us.backup = true;
            continue;
        }

        if v.as_slice() == b"down" {
            if flags & NGX_HTTP_UPSTREAM_DOWN == 0 {
                return Err(not_supported(cf, v));
            }
            us.down = crate::upstream_round_robin::NGX_HTTP_UPSTREAM_FAILED as u32;
            continue;
        }

        if v.as_slice() == b"drain" {
            if flags & NGX_HTTP_UPSTREAM_DOWN == 0 {
                return Err(not_supported(cf, v));
            }
            us.down = crate::upstream_round_robin::NGX_HTTP_UPSTREAM_DRAINING as u32;
            continue;
        }

        if let Some(route) = v.strip_prefix(b"route=") {
            if route.is_empty() {
                return Err(cf.emerg(format_args!("route is empty")));
            }
            if route.len() > crate::upstream_round_robin::NGX_HTTP_UPSTREAM_SID_LEN {
                return Err(cf.emerg(format_args!("route is longer than {}", crate::upstream_round_robin::NGX_HTTP_UPSTREAM_SID_LEN)));
            }
            us.sid = route.to_vec();
            continue;
        }

        if v.as_slice() == b"resolve" {
            resolve = true;
            continue;
        }

        if let Some(service) = v.strip_prefix(b"service=") {
            if service.is_empty() {
                return Err(cf.emerg(format_args!("service is empty")));
            }
            us.service = service.to_vec();
            continue;
        }

        return Err(invalid(cf, v));
    }

    let mut u = Url::new(&value[1]);
    u.default_port = 80;

    if resolve {
        // resolve at run time
        u.no_resolve = true;
    }

    if !us.service.is_empty() && !resolve {
        return Err(cf.emerg(format_args!("service upstream \"{}\" requires \"resolve\" parameter", B(&u.url))));
    }

    if ngx_core::inet::parse_url(&mut u).is_err() {
        if let Some(err) = u.err {
            return Err(cf.emerg(format_args!("{} in upstream \"{}\"", err, B(&u.url))));
        }
        return Err(ConfError::Logged);
    }

    us.name = u.url.clone();

    if !us.service.is_empty() && !u.no_port {
        return Err(cf.emerg(format_args!("service upstream \"{}\" may not have port", B(&us.name))));
    }

    if !us.service.is_empty() && !u.addrs.is_empty() {
        return Err(cf.emerg(format_args!("service upstream \"{}\" requires domain name", B(&us.name))));
    }

    if resolve && u.addrs.is_empty() {
        // save port
        let mut sa = SockAddr::v4(std::net::Ipv4Addr::UNSPECIFIED, u.port);
        sa.set_port(u.port);
        us.addrs = vec![Addr { sockaddr: sa, name: Vec::new() }];
        us.host = u.host.clone();
    } else {
        us.addrs = u.addrs.clone();
    }

    us.weight = weight;
    us.max_conns = max_conns;
    us.max_fails = max_fails;
    us.fail_timeout = fail_timeout;

    uscf.servers.borrow_mut().get_or_insert_with(Vec::new).push(us);

    Ok(())
}

/// ngx_http_upstream_resolver (in upstream{})
fn resolver_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"resolver\" directive is not allowed here"))?;

    if uscf.resolver.borrow().is_some() {
        return Err(msg("is duplicate"));
    }

    let args = cf.args[1..].to_vec();
    let r = Resolver::create(cf, &args)?;
    *uscf.resolver.borrow_mut() = Some(r);
    Ok(())
}

/// resolver_timeout in upstream{} (ngx_conf_set_msec_slot)
fn resolver_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"resolver_timeout\" directive is not allowed here"))?;

    if uscf.resolver_timeout.get().is_some() {
        return Err(msg("is duplicate"));
    }

    match ngx_core::parse::parse_time(&cf.args[1], false) {
        Some(t) => uscf.resolver_timeout.set(Some(t as u64)),
        None => return Err(msg("invalid value")),
    }
    Ok(())
}

/// ngx_http_upstream_add: the upstream of a proxy_pass-like URL (found by
/// host and port, or created: implicit), or of an upstream{} block
/// (NGX_HTTP_UPSTREAM_CREATE), which may complete one created earlier.
pub fn upstream_add(cf: &mut Conf, u: &mut Url, flags: u32) -> Result<Rc<UpstreamSrvConf>, ConfError> {
    if flags & NGX_HTTP_UPSTREAM_CREATE == 0 && ngx_core::inet::parse_url(u).is_err() {
        if let Some(err) = u.err {
            return Err(cf.emerg(format_args!("{} in upstream \"{}\"", err, B(&u.url))));
        }
        return Err(ConfError::Logged);
    }

    let umcf = main_conf(cf);
    let upstreams = umcf.borrow().upstreams.borrow().clone();

    for uscf in upstreams.iter() {
        if !uscf.host.eq_ignore_ascii_case(&u.host) {
            continue;
        }

        if flags & NGX_HTTP_UPSTREAM_CREATE != 0 && uscf.flags.get() & NGX_HTTP_UPSTREAM_CREATE != 0 {
            return Err(cf.emerg(format_args!("duplicate upstream \"{}\"", B(&u.host))));
        }

        if uscf.flags.get() & NGX_HTTP_UPSTREAM_CREATE != 0 && !u.no_port {
            return Err(cf.emerg(format_args!("upstream \"{}\" may not have port {}", B(&u.host), u.port)));
        }

        if flags & NGX_HTTP_UPSTREAM_CREATE != 0 && !uscf.no_port {
            ngx_log_error!(
                NGX_LOG_EMERG,
                cf.log,
                None,
                "upstream \"{}\" may not have port {} in {}:{}",
                B(&u.host),
                uscf.port.get(),
                B(&uscf.file_name),
                uscf.line
            );
            return Err(ConfError::Logged);
        }

        if uscf.port.get() != 0 && u.port != 0 && uscf.port.get() != u.port {
            continue;
        }

        if flags & NGX_HTTP_UPSTREAM_CREATE != 0 {
            uscf.flags.set(flags);
            uscf.port.set(0);
        }

        return Ok(uscf.clone());
    }

    let uscf = Rc::new(UpstreamSrvConf::new(&u.host, u.port, u.no_port, flags, cf.conf_file_name(), cf.conf_line()));

    if u.addrs.len() == 1 && (u.port != 0 || u.family == libc::AF_UNIX) {
        let us = UpstreamServer { addrs: vec![u.addrs[0].clone()], ..Default::default() };
        *uscf.servers.borrow_mut() = Some(vec![us]);
    }

    umcf.borrow().upstreams.borrow_mut().push(uscf.clone());

    Ok(uscf)
}

/// The upstream a host resolved per request names
/// (ngx_http_upstream_init_request: umcf->upstreams by host and port).
pub fn find_upstream(r: &R, host: &[u8], port: u16, no_port: bool) -> Option<Rc<UpstreamSrvConf>> {
    let umcf = r.main_conf::<UpstreamMainConf>(ctx_index());
    let m = umcf.borrow();
    let upstreams = m.upstreams.borrow();
    upstreams
        .iter()
        .find(|u| u.host.eq_ignore_ascii_case(host) && ((u.port.get() == 0 && no_port) || u.port.get() == port))
        .cloned()
}

/// The upstream{} block of a name.
pub fn get_upstream_by_name(r: &R, name: &[u8]) -> Option<Rc<UpstreamSrvConf>> {
    let umcf = r.main_conf::<UpstreamMainConf>(ctx_index());
    let m = umcf.borrow();
    let upstreams = m.upstreams.borrow();
    upstreams.iter().find(|u| u.block.get() && u.host.eq_ignore_ascii_case(name)).cloned()
}

// ============================================================================
// PEERS
// ============================================================================

/// An upstream connection with what the keepalive cache checks.
pub struct UpstreamConn {
    pub sock: UpstreamSock,
    /// requests served on the connection (c->requests)
    pub requests: u64,
    /// ngx_current_msec at connect (c->start_time)
    pub start_time: u64,
    /// the module's data of the connection, a cleanup of c->pool in C (the
    /// HTTP/2 state of a gRPC connection)
    pub data: Option<Rc<dyn std::any::Any>>,
}

/// ngx_peer_connection_t: the balancer's view of an upstream connection.
pub struct PeerConnection {
    pub sockaddr: Option<SockAddr>,
    /// pc->name: the peer's (shared with the memory of the peers, the
    /// upstream state and the error log), or the upstream's
    pub name: Rc<[u8]>,
    pub tries: u32,
    pub start_time: u64,
    pub cached: bool,
    /// a cached keepalive connection (get), or the one to keep (free)
    pub connection: Option<UpstreamConn>,
    /// sticky: the session id the client wants, and the chosen peer's
    pub hint: Option<Vec<u8>>,
    pub sid: Option<Rc<[u8]>>,
    pub log: Log,
    /// u->keepalive and u->request_body_sent, for the keepalive cache
    pub keepalive: bool,
    pub request_body_sent: bool,
    /// u->conf: the location, for "keepalive ... local"
    pub tag: usize,
}

/// A balancer's per-request state (peer.data with peer.get / peer.free).
pub trait PeerBalancer {
    /// peer.tries after peer.init
    fn tries(&self) -> u32;
    /// NGX_OK with pc.sockaddr set, NGX_DONE with a cached connection,
    /// NGX_BUSY when no peer is available (pc.name is the upstream's).
    fn get(&mut self, pc: &mut PeerConnection) -> i64;
    fn free(&mut self, pc: &mut PeerConnection, state: u32, us: &UpstreamState);
    fn notify(&mut self, _pc: &mut PeerConnection, _typ: u32, _us: &UpstreamState) {}
    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        None
    }
    fn save_session(&mut self, _session: openssl::ssl::SslSession) {}
    /// the round robin data under the balancer
    fn rr(&mut self) -> Option<&mut crate::upstream_round_robin::RrPeerData> {
        None
    }
}

/// The peer side of a request's upstream (ngx_http_upstream_t: peer,
/// the next upstream settings, request_sent).
pub struct UpstreamPeer {
    pub pc: PeerConnection,
    /// peer.data with its methods; shared with c->data of the upstream
    /// connection (ngx_http_upstream_ssl_save_session)
    pub balancer: Rc<RefCell<Box<dyn PeerBalancer>>>,
    pub next_upstream: u32,
    pub next_upstream_timeout: u64,
    pub request_sent: bool,
    /// ngx_current_msec at the start of the current try (u->start_time)
    pub start_time: u64,
    /// u->ssl_name: the host of the upstream (uscf->host, or
    /// u->resolved->host), the name ngx_http_upstream_ssl_name found
    pub ssl_name: Vec<u8>,
}

impl UpstreamPeer {
    fn new(r: &R, balancer: Box<dyn PeerBalancer>, ssl_name: Option<&[u8]>, next_upstream: u32, next_upstream_tries: u32, next_upstream_timeout: u64, tag: usize) -> UpstreamPeer {
        let mut tries = balancer.tries();

        // ngx_http_upstream_init_request
        if next_upstream_tries != 0 && tries > next_upstream_tries {
            tries = next_upstream_tries;
        }

        let now = ngx_core::times::current_msec();

        UpstreamPeer {
            pc: PeerConnection {
                sockaddr: None,
                name: crate::upstream_round_robin::no_name(),
                tries,
                start_time: now,
                cached: false,
                connection: None,
                hint: None,
                sid: None,
                log: r.connection.log.clone(),
                keepalive: false,
                request_body_sent: false,
                tag,
            },
            balancer: Rc::new(RefCell::new(balancer)),
            next_upstream,
            next_upstream_timeout,
            request_sent: false,
            start_time: now,
            ssl_name: ssl_name.map(|n| n.to_vec()).unwrap_or_default(),
        }
    }

    /// uscf->peer.init for the request's upstream.
    pub fn init(r: &R, uscf: &Rc<UpstreamSrvConf>, next_upstream: u32, next_upstream_tries: u32, next_upstream_timeout: u64, tag: usize, ssl: bool) -> Result<UpstreamPeer, i64> {
        let balancer = uscf.init_peer(r).map_err(|_| crate::NGX_HTTP_INTERNAL_SERVER_ERROR)?;
        Ok(UpstreamPeer::new(r, balancer, ssl.then_some(&uscf.host[..]), next_upstream, next_upstream_tries, next_upstream_timeout, tag))
    }

    /// ngx_http_upstream_create_round_robin_peer for addresses resolved for
    /// this request.
    pub fn resolved(r: &R, host: &[u8], addrs: Vec<Addr>, next_upstream: u32, next_upstream_tries: u32, next_upstream_timeout: u64, tag: usize, ssl: bool) -> UpstreamPeer {
        let balancer = Box::new(crate::upstream_round_robin::create_round_robin_peer(host, addrs));
        UpstreamPeer::new(r, balancer, ssl.then_some(host), next_upstream, next_upstream_tries, next_upstream_timeout, tag)
    }

    /// The start of ngx_http_upstream_connect: a new state, and the peer
    /// (ngx_event_connect_peer's pc->get). NGX_OK, NGX_DONE with a cached
    /// connection in pc.connection, NGX_ERROR, or NGX_BUSY (the caller logs
    /// "no live upstreams" with pc.name, the upstream's name, in the log
    /// context, and goes to next() with FT_NOLIVE).
    pub fn connect(&mut self, r: &R) -> i64 {
        let now = ngx_core::times::current_msec();

        {
            let mut states = r.upstream_states.borrow_mut();

            if let Some(last) = states.last_mut() {
                if last.response_time == u64::MAX {
                    last.response_time = now.saturating_sub(self.start_time);
                }
            }

            states.push(UpstreamState {
                response_time: u64::MAX,
                connect_time: u64::MAX,
                header_time: u64::MAX,
                ..Default::default()
            });
        }

        self.start_time = now;

        let rc = self.balancer.borrow_mut().get(&mut self.pc);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http upstream connect: {}", rc);

        if rc == NGX_ERROR {
            return rc;
        }

        if let Some(last) = r.upstream_states.borrow_mut().last_mut() {
            last.peer = Some(self.pc.name.clone());
        }

        rc
    }

    /// The balancer's call with u->state, lent (an empty state when there is
    /// none).
    fn with_state<T>(r: &R, f: impl FnOnce(&UpstreamState) -> T) -> T {
        let states = r.upstream_states.borrow();

        match states.last() {
            Some(us) => f(us),
            None => f(&UpstreamState::default()),
        }
    }

    /// peer.set_session: the session to resume with the peer
    pub fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        self.balancer.borrow_mut().set_session()
    }

    /// c->data = r (ngx_http_upstream_connect): the request's upstream
    /// uses the connection (its new TLS sessions go to peer.save_session).
    pub fn attach(&self, c: &ngx_core::connection::Connection) {
        let data = crate::upstream_ssl::UpstreamConnData { balancer: Rc::downgrade(&self.balancer) };
        *c.data.borrow_mut() = Some(Rc::new(data));
    }

    /// attach() for the connection of a socket, if it is an SSL one (only
    /// its sessions use c->data).
    pub fn attach_sock(&self, sock: &UpstreamSock) {
        if let UpstreamSock::Conn(c) = sock {
            if c.c.ssl.borrow().is_some() {
                self.attach(&c.c);
            }
        }
    }

    /// peer.notify
    pub fn notify(&mut self, r: &R, typ: u32) {
        let (balancer, pc) = (&self.balancer, &mut self.pc);

        UpstreamPeer::with_state(r, |us| balancer.borrow_mut().notify(pc, typ, us));
    }

    /// ngx_http_upstream_next: free the peer (NGX_PEER_NEXT for 403 and
    /// 404, NGX_PEER_FAILED otherwise), then Ok(()) to connect to the next
    /// one, or Err(status) to finalize with.
    pub fn next(&mut self, r: &R, ft: u32) -> Result<(), i64> {
        self.next_free(r, ft);
        self.next_decide(r, ft)
    }

    /// The start of ngx_http_upstream_next: the peer is freed
    /// (NGX_PEER_NEXT for 403 and 404, NGX_PEER_FAILED otherwise).
    pub fn next_free(&mut self, r: &R, ft: u32) {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http next upstream, {:x}", ft);

        if self.pc.sockaddr.is_some() {
            let state = if ft == NGX_HTTP_UPSTREAM_FT_HTTP_403 || ft == NGX_HTTP_UPSTREAM_FT_HTTP_404 {
                NGX_PEER_NEXT
            } else {
                NGX_PEER_FAILED
            };

            self.pc.connection = None;

            let (balancer, pc) = (&self.balancer, &mut self.pc);

            UpstreamPeer::with_state(r, |us| balancer.borrow_mut().free(pc, state, us));

            self.pc.sockaddr = None;
            self.pc.sid = None;
        }
    }

    /// The rest of ngx_http_upstream_next after the peer is freed: Ok(())
    /// to connect to the next one, or Err(status) to finalize with.
    pub fn next_decide(&mut self, r: &R, ft: u32) -> Result<(), i64> {
        if self.pc.cached && ft == NGX_HTTP_UPSTREAM_FT_ERROR {
            // TODO: inform balancer instead
            self.pc.tries += 1;
        }

        let status = match ft {
            NGX_HTTP_UPSTREAM_FT_TIMEOUT | NGX_HTTP_UPSTREAM_FT_HTTP_504 => crate::NGX_HTTP_GATEWAY_TIME_OUT,
            NGX_HTTP_UPSTREAM_FT_HTTP_500 => crate::NGX_HTTP_INTERNAL_SERVER_ERROR,
            NGX_HTTP_UPSTREAM_FT_HTTP_503 => crate::NGX_HTTP_SERVICE_UNAVAILABLE,
            NGX_HTTP_UPSTREAM_FT_HTTP_403 => crate::NGX_HTTP_FORBIDDEN,
            NGX_HTTP_UPSTREAM_FT_HTTP_404 => crate::NGX_HTTP_NOT_FOUND,
            NGX_HTTP_UPSTREAM_FT_HTTP_429 => crate::NGX_HTTP_TOO_MANY_REQUESTS,
            _ => crate::NGX_HTTP_BAD_GATEWAY,
        };

        if r.connection.error.get() {
            return Err(crate::NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        if let Some(last) = r.upstream_states.borrow_mut().last_mut() {
            last.status = status;
        }

        let mut ft = ft;

        if self.request_sent && matches!(r.method.get(), crate::NGX_HTTP_POST | crate::NGX_HTTP_LOCK | crate::NGX_HTTP_PATCH) {
            ft |= NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
        }

        let timeout = self.next_upstream_timeout;

        if self.pc.tries == 0
            || self.next_upstream & ft != ft
            || (self.request_sent && r.request_body_no_buffering.get())
            || (timeout != 0 && ngx_core::times::current_msec().saturating_sub(self.pc.start_time) >= timeout)
        {
            return Err(status);
        }

        Ok(())
    }

    /// The peer part of ngx_http_upstream_finalize_request: free the peer
    /// (state 0), offering the connection to the keepalive cache when the
    /// response allows (u->keepalive) and the request body was sent.
    pub fn finalize(&mut self, r: &R, conn: Option<UpstreamConn>, keepalive: bool, request_body_sent: bool) {
        if let Some(last) = r.upstream_states.borrow_mut().last_mut() {
            if last.response_time == u64::MAX {
                last.response_time = ngx_core::times::current_msec().saturating_sub(self.start_time);
            }
        }

        if self.pc.sockaddr.is_none() {
            return;
        }

        self.pc.connection = conn;
        self.pc.keepalive = keepalive;
        self.pc.request_body_sent = request_body_sent;

        let (balancer, pc) = (&self.balancer, &mut self.pc);

        UpstreamPeer::with_state(r, |us| balancer.borrow_mut().free(pc, 0, us));

        self.pc.sockaddr = None;
        self.pc.sid = None;

        // a connection the cache did not take is closed
        self.pc.connection = None;
    }
}

impl UpstreamPeer {
    /// The peers of a host resolved per request (u->resolved,
    /// ngx_http_upstream_init_request): the upstream it names, its address
    /// if it is one, or the addresses the resolver finds
    /// (ngx_http_upstream_resolve_handler).
    pub async fn resolve(r: &R, u: &Url, next_upstream: u32, next_upstream_tries: u32, next_upstream_timeout: u64, tag: usize, ssl: bool) -> Result<UpstreamPeer, i64> {
        if let Some(uscf) = find_upstream(r, &u.host, u.port, u.no_port) {
            return UpstreamPeer::init(r, &uscf, next_upstream, next_upstream_tries, next_upstream_timeout, tag, ssl);
        }

        if !u.addrs.is_empty() {
            if u.port == 0 && u.family != libc::AF_UNIX {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no port in upstream \"{}\"", B(&u.host));
                return Err(crate::NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
            let addrs = vec![u.addrs[0].clone()];
            return Ok(UpstreamPeer::resolved(r, &u.host, addrs, next_upstream, next_upstream_tries, next_upstream_timeout, tag, ssl));
        }

        if u.port == 0 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no port in upstream \"{}\"", B(&u.host));
            return Err(crate::NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        let (resolver, timeout) = {
            let clcf = r.clcf();
            let c = clcf.borrow();
            (c.resolver.clone(), *c.resolver_timeout.get())
        };

        let resolver = match resolver {
            Some(res) => res,
            None => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no resolver defined to resolve {}", B(&u.host));
                return Err(crate::NGX_HTTP_BAD_GATEWAY);
            }
        };

        let resolved = match resolver.resolve_host(&u.host, timeout).await {
            ngx_core::resolver::Resolved::NoResolver => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no resolver defined to resolve {}", B(&u.host));
                return Err(crate::NGX_HTTP_BAD_GATEWAY);
            }
            ngx_core::resolver::Resolved::Error => return Err(crate::NGX_HTTP_INTERNAL_SERVER_ERROR),
            ngx_core::resolver::Resolved::Done(g) => g,
        };

        // ngx_http_upstream_resolve_handler
        let ctx = &resolved.ctx;

        if ctx.state.get() != 0 {
            ngx_log_error!(
                NGX_LOG_ERR,
                r.connection.log,
                None,
                "{} could not be resolved ({}: {})",
                B(&ctx.name.borrow()),
                ctx.state.get(),
                Resolver::strerror(ctx.state.get())
            );
            return Err(crate::NGX_HTTP_BAD_GATEWAY);
        }

        let addrs: Vec<Addr> = ctx
            .addrs
            .borrow()
            .iter()
            .map(|a| {
                let mut sa = a.sockaddr.clone();
                sa.set_port(u.port);
                let name = sa.to_text(true);
                Addr { sockaddr: sa, name }
            })
            .collect();

        Ok(UpstreamPeer::resolved(r, &u.host, addrs, next_upstream, next_upstream_tries, next_upstream_timeout, tag, ssl))
    }
}

/// Frees the upstream peer when the request is done (the peer part of
/// ngx_http_upstream_finalize_request, run on every way out of the
/// handler), handing a connection that may be kept alive to the
/// keepalive cache.
pub struct PeerGuard {
    r: R,
    pub u: UpstreamPeer,
    pub conn: Option<UpstreamConn>,
    pub keepalive: bool,
}

impl PeerGuard {
    pub fn new(r: &R, u: UpstreamPeer) -> PeerGuard {
        PeerGuard { r: r.clone(), u, conn: None, keepalive: false }
    }

    pub fn finalize(&mut self) {
        let body_sent = !self.r.reading_body.get();
        self.u.finalize(&self.r, self.conn.take(), self.keepalive, body_sent);
    }
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        self.finalize();
    }
}

// ============================================================================
// VARIABLE GETTERS
// ============================================================================

/// The values of r->upstream_states as the $upstream_* variables join them:
/// ", " before the state of another try, " : " where the request went to
/// another upstream (a zeroed state, without a peer, which is skipped).
fn join_states(states: &[crate::request::UpstreamState], value: &dyn Fn(&crate::request::UpstreamState) -> Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;

    loop {
        out.extend_from_slice(&value(&states[i]));

        i += 1;

        if i == states.len() {
            break;
        }

        if states[i].peer.as_ref().is_some_and(|p| !p.is_empty()) {
            out.extend_from_slice(b", ");
        } else {
            out.extend_from_slice(b" : ");

            i += 1;

            if i == states.len() {
                break;
            }
        }
    }

    out
}

/// A $upstream_* variable of the states: not found without any.
fn states_variable(r: &R, v: &mut crate::request::VariableValue, value: &dyn Fn(&crate::request::UpstreamState) -> Vec<u8>) -> i64 {
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    let states = r.upstream_states.borrow();

    if states.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }

    v.data = join_states(&states, value);

    NGX_OK
}

/// ngx_http_upstream_addr_variable
fn upstream_addr_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    states_variable(r, v, &|s| s.peer.as_deref().unwrap_or(&[]).to_vec())
}

/// ngx_http_upstream_status_variable
fn upstream_status_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    states_variable(r, v, &|s| if s.status != 0 { s.status.to_string().into_bytes() } else { b"-".to_vec() })
}

/// ngx_http_upstream_response_time_variable: the time in seconds with
/// milliseconds, "-" if it was not measured (-1, here u64::MAX)
fn upstream_time(ms: u64) -> Vec<u8> {
    if ms == u64::MAX {
        b"-".to_vec()
    } else {
        format!("{}.{:03}", ms / 1000, ms % 1000).into_bytes()
    }
}

/// $upstream_connect_time
fn upstream_connect_time_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    states_variable(r, v, &|s| upstream_time(s.connect_time))
}

/// $upstream_header_time
fn upstream_header_time_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    states_variable(r, v, &|s| upstream_time(s.header_time))
}

/// $upstream_response_time
fn upstream_response_time_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    states_variable(r, v, &|s| upstream_time(s.response_time))
}

/// ngx_http_upstream_response_length_variable: `data` 0 the response
/// length, 1 the bytes received, 2 the bytes sent, of each state
fn upstream_response_length_variable(r: &R, v: &mut crate::request::VariableValue, data: usize) -> i64 {
    states_variable(r, v, &|s| {
        let n = match data {
            1 => s.bytes_received,
            2 => s.bytes_sent,
            _ => s.response_length,
        };

        n.to_string().into_bytes()
    })
}

// ============================================================================
// MODULE REGISTRATION
// ============================================================================

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    // Register upstream variables
    let vars = vec![
        VarDef {
            name: "upstream_addr",
            get: Some(upstream_addr_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_status",
            get: Some(upstream_status_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_connect_time",
            get: Some(upstream_connect_time_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_header_time",
            get: Some(upstream_header_time_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_response_time",
            get: Some(upstream_response_time_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_response_length",
            get: Some(upstream_response_length_variable),
            set: None,
            data: 0, // response body length
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_bytes_received",
            get: Some(upstream_response_length_variable),
            set: None,
            data: 1, // total bytes received from upstream
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_bytes_sent",
            get: Some(upstream_response_length_variable),
            set: None,
            data: 2, // total bytes sent to upstream
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
    ];

    crate::variables::add_variables(cf, &vars)?;

    // the NGX_HTTP_CACHE variables
    crate::upstream_cache::add_variables(cf)?;

    // Prefix variables: <name> reads from upstream response headers.
    // Registered separately because they use NGX_HTTP_VAR_PREFIX.
    let prefix_vars = vec![
        VarDef {
            name: "upstream_http_",
            get: Some(upstream_http_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_PREFIX | NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_trailer_",
            get: Some(upstream_trailer_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_PREFIX | NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "upstream_cookie_",
            get: Some(upstream_cookie_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_PREFIX | NGX_HTTP_VAR_NOCACHEABLE,
        },
    ];
    crate::variables::add_variables(cf, &prefix_vars)?;

    Ok(())
}

fn upstream_http_variable(r: &R, v: &mut crate::request::VariableValue, d: usize) -> i64 {
    let name = prefix_var_name(r, d);
    let want = &name["upstream_http_".len()..];
    let headers = r.upstream_headers_in.borrow();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for h in headers.iter() {
        if h.lowcase_key.len() != want.len() {
            continue;
        }
        let same = h.lowcase_key.iter().zip(want.iter()).all(|(a, b)| *a == *b || (*a == b'-' && *b == b'_'));
        if same {
            parts.push(h.value.borrow().clone());
        }
    }
    if parts.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    let joined = parts.join(&b", "[..]);
    v.data = joined;
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    NGX_OK
}

fn upstream_trailer_variable(_r: &R, v: &mut crate::request::VariableValue, _d: usize) -> i64 {
    // Trailers not currently captured; report not_found rather than error.
    v.not_found = true;
    NGX_OK
}

fn upstream_cookie_variable(r: &R, v: &mut crate::request::VariableValue, d: usize) -> i64 {
    // Port of ngx_http_parse_set_cookie_lines: for each Set-Cookie header,
    // require case-insensitive prefix `name`, skip spaces before/after '=',
    // then take up to the next ';'.
    let name = prefix_var_name(r, d);
    let want = &name["upstream_cookie_".len()..];
    let headers = r.upstream_headers_in.borrow();
    for h in headers.iter() {
        if h.lowcase_key.as_slice() != b"set-cookie" {
            continue;
        }
        let val = h.value.borrow();
        if want.len() >= val.len() {
            continue;
        }
        if !val[..want.len()].eq_ignore_ascii_case(want) {
            continue;
        }
        let mut i = want.len();
        while i < val.len() && val[i] == b' ' { i += 1; }
        if i == val.len() || val[i] != b'=' {
            continue;
        }
        i += 1;
        while i < val.len() && val[i] == b' ' { i += 1; }
        let mut j = i;
        while j < val.len() && val[j] != b';' { j += 1; }
        v.data = val[i..j].to_vec();
        v.valid = true;
        v.no_cacheable = false;
        v.not_found = false;
        return NGX_OK;
    }
    v.not_found = true;
    NGX_OK
}

pub fn upstream_module() -> ModuleDef {
    let commands = vec![
        cmd_fn!("upstream", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1, ConfLevel::Main, upstream_handler),
        cmd_fn!("server", NGX_HTTP_UPS_CONF | NGX_CONF_1MORE, ConfLevel::None, server_handler),
        cmd_fn!("resolver", NGX_HTTP_UPS_CONF | NGX_CONF_1MORE, ConfLevel::None, resolver_handler),
        cmd_fn!("resolver_timeout", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, resolver_timeout_handler),
    ];

    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        create_main_conf: Some(create_main_conf),
        init_main_conf: Some(init_main_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_upstream_module", def, commands)
}

// ============================================================================
// STUB: UPSTREAM LOG INFO
// ============================================================================

/// Return upstream log info for error logs (replaces stubs::upstream_log_info).
pub fn upstream_log_info(r: &Request) -> Option<Vec<u8>> {
    if let Some(state) = r.upstream_states.borrow().last() {
        if state.status > 0 {
            let peer = B(state.peer.as_deref().unwrap_or(&[])).to_string();
            let status = state.status;
            return Some(format!("upstream: {}, status: {}", peer, status).into_bytes());
        }
    }
    None
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn state(peer: &[u8], status: i64) -> crate::request::UpstreamState {
        crate::request::UpstreamState { peer: if peer.is_empty() { None } else { Some(peer.into()) }, status, ..Default::default() }
    }

    #[test]
    fn test_join_states() {
        let addr = |s: &crate::request::UpstreamState| s.peer.as_deref().unwrap_or(&[]).to_vec();
        let status = |s: &crate::request::UpstreamState| if s.status != 0 { s.status.to_string().into_bytes() } else { b"-".to_vec() };

        // the tries of an upstream
        let states = vec![state(b"a:1", 502), state(b"b:1", 200)];
        assert_eq!(join_states(&states, &addr), b"a:1, b:1");
        assert_eq!(join_states(&states, &status), b"502, 200");

        // another upstream: the zeroed state is " : "
        let states = vec![state(b"a:1", 200), state(b"", 0), state(b"c:1", 404)];
        assert_eq!(join_states(&states, &addr), b"a:1 : c:1");
        assert_eq!(join_states(&states, &status), b"200 : 404");

        // the other upstream never connected
        let states = vec![state(b"a:1", 200), state(b"", 0)];
        assert_eq!(join_states(&states, &status), b"200 : ");

        // two in a row: the second one is printed
        let states = vec![state(b"a:1", 200), state(b"", 0), state(b"", 0), state(b"c:1", 200)];
        assert_eq!(join_states(&states, &status), b"200 : -, 200");
    }

    #[test]
    fn test_upstream_flags() {
        assert_eq!(NGX_HTTP_UPSTREAM_FT_ERROR, 0x00000002);
        // NGX_HTTP_UPSTREAM_FT_STATUS of ngx_http_upstream.h
        assert_eq!(
            NGX_HTTP_UPSTREAM_FT_STATUS,
            NGX_HTTP_UPSTREAM_FT_HTTP_500
                | NGX_HTTP_UPSTREAM_FT_HTTP_502
                | NGX_HTTP_UPSTREAM_FT_HTTP_503
                | NGX_HTTP_UPSTREAM_FT_HTTP_504
                | NGX_HTTP_UPSTREAM_FT_HTTP_403
                | NGX_HTTP_UPSTREAM_FT_HTTP_404
                | NGX_HTTP_UPSTREAM_FT_HTTP_429
        );
    }

    #[test]
    fn copy_header_content_type_and_length() {
        let mut ho = crate::request::HeadersOut::new();
        let mut st = CopiedHeaders::default();

        // ngx_http_upstream_copy_content_type: the charset is split off
        copy_header(&mut ho, &mut st, 200, b"Content-Type", b"text/html; charset=\"utf-8\"");
        assert_eq!(&ho.content_type[..ho.content_type_len], b"text/html");
        assert_eq!(ho.charset, b"utf-8");

        copy_header(&mut ho, &mut st, 200, b"Content-Length", b"42");
        assert_eq!(ho.content_length_n, 42);
        assert!(!st.invalid);

        // a second Content-Length is an invalid header
        copy_header(&mut ho, &mut st, 200, b"Content-Length", b"42");
        assert!(st.invalid);

        // as is one that is not a number
        let mut st = CopiedHeaders::default();
        copy_header(&mut ho, &mut st, 200, b"Content-Length", b"4x");
        assert!(st.invalid);
    }
}

/// What copying an upstream's response headers found about the framing
/// (the checks of ngx_http_proxy_process_header and of the upstream
/// headers_in handlers).
#[derive(Default)]
pub struct CopiedHeaders {
    pub saw_content_length: bool,
    pub saw_transfer_encoding: bool,
    pub chunked: bool,
    pub invalid: bool,
    pub duplicate_expires: bool,
}

/// Copy one upstream response header to headers_out: those
/// ngx_http_upstream.c handles go to their slots, the rest are added.
pub fn copy_header(ho: &mut crate::request::HeadersOut, st: &mut CopiedHeaders, status: i64, name: &[u8], value: &[u8]) {
    let lc = name.to_ascii_lowercase();
    match lc.as_slice() {
        b"content-length" => {
            if st.saw_content_length {
                st.invalid = true;
            }
            st.saw_content_length = true;
            // Parse strictly: any non-digit → invalid. C sets
            // NGX_HTTP_UPSTREAM_INVALID_HEADER on parse failure.
            let vtrim = std::str::from_utf8(value).map(|s| s.trim()).unwrap_or("");
            match vtrim.parse::<i64>() {
                Ok(n) if n >= 0 => ho.content_length_n = n,
                _ => st.invalid = true,
            }
            let h = crate::request::TableElt::new(name, value);
            ho.content_length = Some(h);
        }
        b"content-type" => {
            // Mirror ngx_http_upstream_copy_content_type: split on
            // the first `;` that begins `; charset=…` and copy
            // the charset out to headers_out.charset so downstream
            // filters (e.g. charset_filter override) can find it.
            ho.content_type = value.to_vec();
            ho.content_type_len = value.len();
            let mut p = 0usize;
            while p < value.len() {
                if value[p] != b';' { p += 1; continue; }
                let semi = p;
                let mut q = p + 1;
                while q < value.len() && value[q] == b' ' { q += 1; }
                if q + 8 <= value.len() && value[q..q+8].eq_ignore_ascii_case(b"charset=") {
                    let mut cs_start = q + 8;
                    let mut cs_end = value.len();
                    if cs_start < cs_end && value[cs_start] == b'"' { cs_start += 1; }
                    if cs_end > cs_start && value[cs_end - 1] == b'"' { cs_end -= 1; }
                    ho.content_type_len = semi;
                    ho.charset = value[cs_start..cs_end].to_vec();
                    break;
                }
                p = q;
            }
        }
        b"transfer-encoding" => {
            // C rejects duplicate Transfer-Encoding, and any value
            // other than "chunked" or "identity".
            if st.saw_transfer_encoding {
                st.invalid = true;
            }
            st.saw_transfer_encoding = true;
            if value.eq_ignore_ascii_case(b"chunked") {
                st.chunked = true;
            } else if !value.eq_ignore_ascii_case(b"identity") {
                st.invalid = true;
            }
        }
        b"expires" => {
            // Only accept the first Expires; C's header handler for
            // Expires drops duplicates.
            if ho.expires.is_some() {
                st.duplicate_expires = true;
            } else {
                let h = crate::request::TableElt::new(name, value);
                ho.expires = Some(h.clone());
                ho.add(name, value);
            }
        }
        b"connection" | b"keep-alive" => {
            // Hop-by-hop headers: normally stripped to the
            // client — except 101 Switching Protocols, where
            // Connection: Upgrade is the negotiation the client
            // is waiting to see.
            if status == 101 {
                ho.add(name, value);
            }
        }
        b"date" => {
            // Only reached if not hidden (proxy_pass_header Date).
            // Populate the typed slot so header_filter's "if
            // ho.date.is_none()" branch does NOT then also emit
            // its own Date, which would give two Date lines.
            let h = ho.add(name, value);
            ho.date = Some(h);
        }
        b"server" => {
            let h = ho.add(name, value);
            ho.server = Some(h);
        }
        b"location" => {
            let h = crate::request::TableElt::new(name, value);
            ho.location = Some(h);
        }
        b"last-modified" => {
            let h = ho.add(name, value);
            ho.last_modified = Some(h);
            // Also parse into last_modified_time so If-Range and
            // If-Modified-Since date comparisons work.
            if let Some(t) = ngx_core::parse::parse_http_time(value) {
                ho.last_modified_time = t;
            }
        }
        b"etag" => {
            let h = ho.add(name, value);
            ho.etag = Some(h);
        }
        b"accept-ranges" => {
            // ngx_http_upstream_copy_allow_ranges: the copy is
            // r->headers_out.accept_ranges, which
            // ngx_http_clear_accept_ranges() removes
            let h = ho.add(name, value);
            ho.accept_ranges = Some(h);
        }
        b"content-range" => {
            // ngx_http_upstream_copy_header_line, offset of
            // r->headers_out.content_range
            let h = ho.add(name, value);
            ho.content_range = Some(h);
        }
        b"content-encoding" => {
            // Populate the typed slot so gunzip_filter can detect
            // upstream-gzipped responses (matches C's
            // ngx_http_upstream_process_header stash into
            // headers_in.content_encoding).
            let h = crate::request::TableElt::new(name, value);
            ho.content_encoding = Some(h.clone());
            ho.headers.push(h);
        }
        // ngx_http_upstream_copy_multi_header_lines
        b"cache-control" => {
            let h = ho.add(name, value);
            ho.cache_control.push(h);
        }
        b"link" => {
            let h = ho.add(name, value);
            ho.link.push(h);
        }
        _ => {
            ho.add(name, value);
        }
    }
}
