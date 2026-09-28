//! The DNS resolver (ngx_resolver.c).
//!
//! Names, services (SRV) and addresses (PTR) are looked up in a cache of
//! nodes; a node being resolved has the contexts waiting for it and is on
//! the resend queue, a resolved one stays cached while valid (the TTL or
//! "valid=") and on the expire queue until "expire" seconds pass unused.
//! Queries go round robin to the servers over UDP, or TCP when a response
//! is truncated; unanswered ones are resent every resend_timeout seconds.
//! A context's handler is called when its lookup is done or times out.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::{Rc, Weak};

use crate::conf::{Conf, ConfError};
use crate::inet::SockAddr;
use crate::log::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};

pub const NGX_RESOLVE_A: u16 = 1;
pub const NGX_RESOLVE_CNAME: u16 = 5;
pub const NGX_RESOLVE_PTR: u16 = 12;
pub const NGX_RESOLVE_MX: u16 = 15;
pub const NGX_RESOLVE_TXT: u16 = 16;
pub const NGX_RESOLVE_AAAA: u16 = 28;
pub const NGX_RESOLVE_SRV: u16 = 33;
pub const NGX_RESOLVE_DNAME: u16 = 39;

pub const NGX_RESOLVE_FORMERR: i64 = 1;
pub const NGX_RESOLVE_SERVFAIL: i64 = 2;
pub const NGX_RESOLVE_NXDOMAIN: i64 = 3;
pub const NGX_RESOLVE_NOTIMP: i64 = 4;
pub const NGX_RESOLVE_REFUSED: i64 = 5;
pub const NGX_RESOLVE_TIMEDOUT: i64 = libc::ETIMEDOUT as i64;

pub const NGX_RESOLVER_MAX_RECURSION: u32 = 50;

const NGX_OK: i64 = 0;
const NGX_ERROR: i64 = -1;
const NGX_AGAIN: i64 = -2;
const NGX_DECLINED: i64 = -5;

const NGX_RESOLVER_UDP_SIZE: usize = 4096;

const NGX_RESOLVER_TCP_RSIZE: usize = 2 + 65535;
const NGX_RESOLVER_TCP_WSIZE: usize = 8192;

/// ngx_resolver_hdr_t
const HDR_LEN: usize = 12;
/// ngx_resolver_qs_t
const QS_LEN: usize = 4;
/// ngx_resolver_an_t
const AN_LEN: usize = 10;

/// naddrs of a node whose query is not answered yet ((u_short) -1)
const PENDING: u16 = u16::MAX;

/// ngx_resolver_addr_t
#[derive(Clone, Debug)]
pub struct ResolverAddr {
    pub sockaddr: SockAddr,
    pub name: Vec<u8>,
    pub priority: u16,
    pub weight: u16,
}

/// ngx_resolver_srv_t
#[derive(Clone, Debug, Default)]
pub struct ResolverSrv {
    pub name: Vec<u8>,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
}

/// ngx_resolver_srv_name_t
#[derive(Default)]
pub struct ResolverSrvName {
    pub name: Vec<u8>,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,

    pub ctx: Option<Rc<ResolverCtx>>,
    pub state: i64,

    pub addrs: Vec<SockAddr>,
}

/// Which cache a node is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tree {
    Name,
    Srv,
    Addr,
    Addr6,
}

/// ngx_resolver_node_t
struct ResolverNode {
    /// PTR: resolved name, A: name to resolve
    name: Vec<u8>,

    /// PTR: the address to resolve
    addr: u32,
    addr6: [u8; 16],

    qlen: u16,

    query: Option<Vec<u8>>,
    query6: Option<Vec<u8>>,

    /// u.addr / u.addrs, in network order
    addrs: Vec<[u8; 4]>,
    /// u.cname
    cname: Vec<u8>,
    /// u.srvs
    srvs: Vec<ResolverSrv>,

    code: u8,
    naddrs: u16,
    nsrvs: u16,
    cnlen: u16,

    /// u6.addr6 / u6.addrs6
    addrs6: Vec<[u8; 16]>,
    naddrs6: u16,

    expire: i64,
    valid: i64,
    ttl: u32,

    tcp: bool,
    tcp6: bool,

    last_connection: usize,

    /// the contexts waiting for the node, the list head first
    waiting: Vec<Rc<ResolverCtx>>,
}

type NodeRef = Rc<RefCell<ResolverNode>>;

impl ResolverNode {
    fn new() -> ResolverNode {
        ResolverNode {
            name: Vec::new(),
            addr: 0,
            addr6: [0; 16],
            qlen: 0,
            query: None,
            query6: None,
            addrs: Vec::new(),
            cname: Vec::new(),
            srvs: Vec::new(),
            code: 0,
            naddrs: 0,
            nsrvs: 0,
            cnlen: 0,
            addrs6: Vec::new(),
            naddrs6: 0,
            expire: 0,
            valid: 0,
            ttl: 0,
            tcp: false,
            tcp6: false,
            last_connection: 0,
            waiting: Vec::new(),
        }
    }
}

/// The TCP connection to a server (rec->tcp with its buffers).
struct TcpConn {
    write_buf: RefCell<Vec<u8>>,
    wakeup: tokio::sync::Notify,
    task: RefCell<Option<tokio::task::JoinHandle<()>>>,
}

/// The UDP socket of a server (rec->udp).
struct UdpConn {
    sock: Rc<tokio::net::UdpSocket>,
    task: RefCell<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for UdpConn {
    fn drop(&mut self) {
        if let Some(t) = self.task.borrow_mut().take() {
            t.abort();
        }
    }
}

impl Drop for TcpConn {
    fn drop(&mut self) {
        if let Some(t) = self.task.borrow_mut().take() {
            t.abort();
        }
    }
}

/// ngx_resolver_connection_t
struct ResolverConnection {
    sockaddr: SockAddr,
    server: Vec<u8>,
    udp: RefCell<Option<Rc<UdpConn>>>,
    tcp: RefCell<Option<Rc<TcpConn>>>,
    /// rec->log: the resolver's, "while resolving, resolver: ..."
    log: RefCell<Option<Log>>,
}

/// ngx_resolver_log_error: the context of a server connection's log.
struct ResolverLogCtx {
    server: Vec<u8>,
    action: &'static str,
}

impl LogContext for ResolverLogCtx {
    fn write_context(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b" while ");
        buf.extend_from_slice(self.action.as_bytes());
        buf.extend_from_slice(b", resolver: ");
        buf.extend_from_slice(&self.server);
    }
}

/// ngx_resolver_t
pub struct Resolver {
    this: RefCell<Weak<Resolver>>,

    log: Log,

    /// simple round robin DNS peers balancer
    connections: Vec<ResolverConnection>,
    last_connection: Cell<usize>,

    name_tree: RefCell<HashMap<Vec<u8>, NodeRef>>,
    srv_tree: RefCell<HashMap<Vec<u8>, NodeRef>>,
    addr_tree: RefCell<HashMap<u32, NodeRef>>,
    addr6_tree: RefCell<HashMap<[u8; 16], NodeRef>>,

    name_resend_queue: RefCell<VecDeque<NodeRef>>,
    srv_resend_queue: RefCell<VecDeque<NodeRef>>,
    addr_resend_queue: RefCell<VecDeque<NodeRef>>,
    addr6_resend_queue: RefCell<VecDeque<NodeRef>>,

    name_expire_queue: RefCell<VecDeque<NodeRef>>,
    srv_expire_queue: RefCell<VecDeque<NodeRef>>,
    addr_expire_queue: RefCell<VecDeque<NodeRef>>,
    addr6_expire_queue: RefCell<VecDeque<NodeRef>>,

    ipv4: bool,
    ipv6: bool,

    resend_timeout: i64,
    tcp_timeout: i64,
    expire: i64,
    valid: i64,

    log_level: u32,

    /// r->event: the resend timer
    event: RefCell<Option<tokio::task::JoinHandle<()>>>,
}

/// ngx_resolver_ctx_t
pub struct ResolverCtx {
    pub resolver: Rc<Resolver>,
    node: RefCell<Option<NodeRef>>,

    pub state: Cell<i64>,
    pub name: RefCell<Vec<u8>>,
    pub service: RefCell<Vec<u8>>,

    pub valid: Cell<i64>,
    /// naddrs is addrs.len()
    pub addrs: RefCell<Vec<ResolverAddr>>,
    /// the address of ngx_resolve_addr
    pub addr: RefCell<Option<SockAddr>>,

    pub count: Cell<usize>,
    /// nsrvs is srvs.len()
    pub srvs: RefCell<Vec<ResolverSrvName>>,

    pub handler: RefCell<Option<Rc<dyn Fn(&Rc<ResolverCtx>)>>>,
    pub data: RefCell<Option<Rc<dyn Any>>>,
    pub timeout: Cell<u64>,

    pub quick: Cell<bool>,
    pub async_: Cell<bool>,
    pub cancelable: Cell<bool>,
    pub recursion: Cell<u32>,

    /// ctx->event: the timeout
    event: RefCell<Option<tokio::task::JoinHandle<()>>>,
    event_set: Cell<bool>,

    /// cctx->data and cctx->srvs of the name lookups of a service
    parent: RefCell<Option<Rc<ResolverCtx>>>,
    srv_index: Cell<usize>,
}

/// What ngx_resolve_start returns.
pub enum ResolveStart {
    Ctx(Rc<ResolverCtx>),
    /// NGX_NO_RESOLVER: no name servers
    NoResolver,
}

fn random() -> u64 {
    extern "C" {
        fn random() -> libc::c_long;
    }
    unsafe { random() as u64 }
}

fn now() -> i64 {
    crate::times::time()
}

impl Resolver {
    /// r->log: the cycle's log
    fn log(&self) -> Log {
        crate::cycle::try_cycle().map(|c| c.log.clone()).unwrap_or_else(|| self.log.clone())
    }

    /// ngx_resolver_create
    pub fn create(cf: &mut Conf, names: &[Vec<u8>]) -> Result<Rc<Resolver>, ConfError> {
        let mut ipv4 = true;
        let mut ipv6 = true;
        let mut valid: i64 = 0;
        let mut connections = Vec::new();

        for name in names {
            if let Some(s) = name.strip_prefix(b"valid=") {
                valid = match crate::parse::parse_time(s, true) {
                    Some(v) => v,
                    None => return Err(cf.emerg(format_args!("invalid parameter: {}", B(name)))),
                };
                continue;
            }

            if let Some(s) = name.strip_prefix(b"ipv4=") {
                if s == b"on" {
                    ipv4 = true;
                } else if s == b"off" {
                    ipv4 = false;
                } else {
                    return Err(cf.emerg(format_args!("invalid parameter: {}", B(name))));
                }
                continue;
            }

            if let Some(s) = name.strip_prefix(b"ipv6=") {
                if s == b"on" {
                    ipv6 = true;
                } else if s == b"off" {
                    ipv6 = false;
                } else {
                    return Err(cf.emerg(format_args!("invalid parameter: {}", B(name))));
                }
                continue;
            }

            let mut u = crate::inet::Url::new(name);
            u.default_port = 53;

            if crate::inet::parse_url(&mut u).is_err() {
                if let Some(err) = u.err {
                    return Err(cf.emerg(format_args!("{} in resolver \"{}\"", err, B(&u.url))));
                }
                return Err(ConfError::Logged);
            }

            for a in u.addrs.iter() {
                connections.push(ResolverConnection {
                    sockaddr: a.sockaddr.clone(),
                    server: a.name.clone(),
                    udp: RefCell::new(None),
                    tcp: RefCell::new(None),
                    log: RefCell::new(None),
                });
            }
        }

        if !ipv4 && !ipv6 {
            return Err(cf.emerg(format_args!("\"ipv4\" and \"ipv6\" cannot both be \"off\"")));
        }

        if !names.is_empty() && connections.is_empty() {
            return Err(cf.emerg(format_args!("no name servers defined")));
        }

        Ok(Resolver::new(Log::new(cf.cycle.new_log.clone()), connections, ipv4, ipv6, valid))
    }

    /// ngx_resolver_create(cf, NULL, 0): the dummy resolver of the http{}
    /// context, without name servers.
    pub fn empty() -> Rc<Resolver> {
        let log = crate::cycle::try_cycle().map(|c| c.log.clone()).unwrap_or_else(|| Log::stderr(NGX_LOG_ERR));
        Resolver::new(log, Vec::new(), true, true, 0)
    }

    fn new(log: Log, connections: Vec<ResolverConnection>, ipv4: bool, ipv6: bool, valid: i64) -> Rc<Resolver> {
        let r = Rc::new(Resolver {
            this: RefCell::new(Weak::new()),
            log,
            connections,
            last_connection: Cell::new(0),
            name_tree: RefCell::new(HashMap::new()),
            srv_tree: RefCell::new(HashMap::new()),
            addr_tree: RefCell::new(HashMap::new()),
            addr6_tree: RefCell::new(HashMap::new()),
            name_resend_queue: RefCell::new(VecDeque::new()),
            srv_resend_queue: RefCell::new(VecDeque::new()),
            addr_resend_queue: RefCell::new(VecDeque::new()),
            addr6_resend_queue: RefCell::new(VecDeque::new()),
            name_expire_queue: RefCell::new(VecDeque::new()),
            srv_expire_queue: RefCell::new(VecDeque::new()),
            addr_expire_queue: RefCell::new(VecDeque::new()),
            addr6_expire_queue: RefCell::new(VecDeque::new()),
            ipv4,
            ipv6,
            resend_timeout: 5,
            tcp_timeout: 5,
            expire: 30,
            valid,
            log_level: NGX_LOG_ERR,
            event: RefCell::new(None),
        });
        *r.this.borrow_mut() = Rc::downgrade(&r);
        r
    }

    /// There are name servers (r->connections.nelts).
    pub fn has_servers(&self) -> bool {
        !self.connections.is_empty()
    }

    fn resend_queue(&self, t: Tree) -> &RefCell<VecDeque<NodeRef>> {
        match t {
            Tree::Name => &self.name_resend_queue,
            Tree::Srv => &self.srv_resend_queue,
            Tree::Addr => &self.addr_resend_queue,
            Tree::Addr6 => &self.addr6_resend_queue,
        }
    }

    fn expire_queue(&self, t: Tree) -> &RefCell<VecDeque<NodeRef>> {
        match t {
            Tree::Name => &self.name_expire_queue,
            Tree::Srv => &self.srv_expire_queue,
            Tree::Addr => &self.addr_expire_queue,
            Tree::Addr6 => &self.addr6_expire_queue,
        }
    }

    /// ngx_queue_remove(&rn->queue): a node is on its tree's resend or
    /// expire queue
    fn queue_remove(&self, t: Tree, rn: &NodeRef) {
        self.resend_queue(t).borrow_mut().retain(|n| !Rc::ptr_eq(n, rn));
        self.expire_queue(t).borrow_mut().retain(|n| !Rc::ptr_eq(n, rn));
    }

    /// ngx_rbtree_delete of a node
    fn tree_delete(&self, t: Tree, rn: &NodeRef) {
        let n = rn.borrow();
        match t {
            Tree::Name => {
                self.name_tree.borrow_mut().remove(&n.name);
            }
            Tree::Srv => {
                self.srv_tree.borrow_mut().remove(&n.name);
            }
            Tree::Addr => {
                self.addr_tree.borrow_mut().remove(&n.addr);
            }
            Tree::Addr6 => {
                self.addr6_tree.borrow_mut().remove(&n.addr6);
            }
        }
    }

    /// ngx_resolve_start
    pub fn start(self: &Rc<Self>, temp: Option<&[u8]>) -> ResolveStart {
        if let Some(name) = temp {
            if let Some(addr) = inet_addr(name) {
                let ctx = ResolverCtx::new(self);
                ctx.state.set(NGX_OK);
                ctx.addrs.borrow_mut().push(ResolverAddr {
                    sockaddr: SockAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::from(addr), 0)),
                    name: Vec::new(),
                    priority: 0,
                    weight: 0,
                });
                ctx.quick.set(true);
                *ctx.name.borrow_mut() = name.to_vec();
                return ResolveStart::Ctx(ctx);
            }
        }

        if self.connections.is_empty() {
            return ResolveStart::NoResolver;
        }

        ResolveStart::Ctx(ResolverCtx::new(self))
    }

    /// ngx_resolver_strerror
    pub fn strerror(err: i64) -> &'static str {
        const ERRORS: [&str; 5] = [
            "Format error",      // FORMERR
            "Server failure",    // SERVFAIL
            "Host not found",    // NXDOMAIN
            "Unimplemented",     // NOTIMP
            "Operation refused", // REFUSED
        ];

        if err > 0 && err < 6 {
            return ERRORS[(err - 1) as usize];
        }

        if err == NGX_RESOLVE_TIMEDOUT {
            return "Operation timed out";
        }

        "Unknown error"
    }

    /// ngx_add_timer(r->event, timer)
    fn add_resend_timer(&self, timer: u64) {
        if let Some(t) = self.event.borrow_mut().take() {
            t.abort();
        }

        let r = self.this.borrow().clone();

        let task = crate::event::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(timer)).await;
            if let Some(r) = r.upgrade() {
                r.event.borrow_mut().take();
                r.resend_handler();
            }
        });

        *self.event.borrow_mut() = Some(task);
    }

    fn resend_timer_set(&self) -> bool {
        self.event.borrow().is_some()
    }

    /// ngx_del_timer(r->event)
    fn del_resend_timer(&self) {
        if let Some(t) = self.event.borrow_mut().take() {
            t.abort();
        }
    }
}

impl ResolverCtx {
    fn new(r: &Rc<Resolver>) -> Rc<ResolverCtx> {
        Rc::new(ResolverCtx {
            resolver: r.clone(),
            node: RefCell::new(None),
            state: Cell::new(0),
            name: RefCell::new(Vec::new()),
            service: RefCell::new(Vec::new()),
            valid: Cell::new(0),
            addrs: RefCell::new(Vec::new()),
            addr: RefCell::new(None),
            count: Cell::new(0),
            srvs: RefCell::new(Vec::new()),
            handler: RefCell::new(None),
            data: RefCell::new(None),
            timeout: Cell::new(0),
            quick: Cell::new(false),
            async_: Cell::new(false),
            cancelable: Cell::new(false),
            recursion: Cell::new(0),
            event: RefCell::new(None),
            event_set: Cell::new(false),
            parent: RefCell::new(None),
            srv_index: Cell::new(0),
        })
    }

    /// ctx->handler(ctx)
    fn call_handler(self: &Rc<Self>) {
        let h = self.handler.borrow().clone();
        if let Some(h) = h {
            h(self);
        }
    }

    /// ngx_del_timer(ctx->event)
    fn del_timer(&self) {
        if let Some(t) = self.event.borrow_mut().take() {
            t.abort();
        }
    }

    pub fn naddrs(&self) -> usize {
        self.addrs.borrow().len()
    }
}

/// ngx_inet_addr: a dotted IPv4 address
fn inet_addr(text: &[u8]) -> Option<u32> {
    let mut addr: u32 = 0;
    let mut octet: u32 = 0;
    let mut n = 0;

    for &c in text {
        if c.is_ascii_digit() {
            octet = octet * 10 + (c - b'0') as u32;
            if octet > 255 {
                return None;
            }
            continue;
        }

        if c == b'.' {
            addr = (addr << 8) + octet;
            octet = 0;
            n += 1;
            continue;
        }

        return None;
    }

    if n == 3 {
        addr = (addr << 8) + octet;
        return Some(addr);
    }

    None
}

/// ngx_resolve_name
pub fn resolve_name(ctx: &Rc<ResolverCtx>) -> i64 {
    let r = ctx.resolver.clone();

    {
        let mut name = ctx.name.borrow_mut();
        if name.last() == Some(&b'.') {
            name.pop();
        }
    }

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolve: \"{}\"", B(&ctx.name.borrow()));

    if ctx.quick.get() {
        ctx.call_handler();
        return NGX_OK;
    }

    let service = ctx.service.borrow().clone();

    let rc = if !service.is_empty() {
        let name = ctx.name.borrow().clone();

        let full = if !service.contains(&b'.') {
            [b"_".as_slice(), &service, b"._tcp.", &name].concat()
        } else {
            [service.as_slice(), b".", &name].concat()
        };

        // lock name mutex

        resolve_name_locked(&r, vec![ctx.clone()], &full)
    } else {
        let name = ctx.name.borrow().clone();

        // lock name mutex

        resolve_name_locked(&r, vec![ctx.clone()], &name)
    };

    if rc == NGX_OK || rc == NGX_AGAIN {
        return NGX_OK;
    }

    // NGX_ERROR

    ctx.del_timer();

    NGX_ERROR
}

/// ngx_resolve_name_done
pub fn resolve_name_done(ctx: &Rc<ResolverCtx>) {
    let r = ctx.resolver.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolve name done: {}", ctx.state.get());

    if ctx.quick.get() {
        return;
    }

    ctx.del_timer();

    // lock name mutex

    let srvs = std::mem::take(&mut *ctx.srvs.borrow_mut());

    for srv in srvs.iter() {
        if let Some(cctx) = &srv.ctx {
            resolve_name_done(cctx);
        }
    }

    if ctx.state.get() == NGX_AGAIN || ctx.state.get() == NGX_RESOLVE_TIMEDOUT {
        let rn = ctx.node.borrow().clone();

        if let Some(rn) = rn {
            let mut n = rn.borrow_mut();
            let before = n.waiting.len();
            n.waiting.retain(|w| !Rc::ptr_eq(w, ctx));

            if n.waiting.len() == before {
                ngx_log_error!(NGX_LOG_ALERT, r.log(), None, "could not cancel {} resolving", B(&ctx.name.borrow()));
            }
        }
    }

    *ctx.node.borrow_mut() = None;

    if !ctx.service.borrow().is_empty() {
        resolver_expire(&r, Tree::Srv);
    } else {
        resolver_expire(&r, Tree::Name);
    }

    // unlock name mutex

    *ctx.handler.borrow_mut() = None;
    *ctx.parent.borrow_mut() = None;

    if r.resend_timer_set() && resend_empty(&r) {
        r.del_resend_timer();
    }
}

/// ngx_resolve_name_locked; ctxs is the list of contexts (more than one
/// after a CNAME)
fn resolve_name_locked(r: &Rc<Resolver>, ctxs: Vec<Rc<ResolverCtx>>, name: &[u8]) -> i64 {
    let name = crate::string::to_lower_vec(name);

    let service = !ctxs[0].service.borrow().is_empty();

    let tree = if service { Tree::Srv } else { Tree::Name };

    let found = if service { r.srv_tree.borrow().get(&name).cloned() } else { r.name_tree.borrow().get(&name).cloned() };

    let rn = match found {
        Some(rn) => {
            if rn.borrow().valid >= now() {
                ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolve cached");

                r.queue_remove(tree, &rn);

                rn.borrow_mut().expire = now() + r.expire;

                r.expire_queue(tree).borrow_mut().push_front(rn.clone());

                let (naddrs, naddrs4) = {
                    let n = rn.borrow();
                    let mut naddrs = if n.naddrs == PENDING { 0 } else { n.naddrs as usize };
                    naddrs += if n.naddrs6 == PENDING { 0 } else { n.naddrs6 as usize };
                    (naddrs, n.naddrs)
                };

                if naddrs > 0 {
                    let addrs = if naddrs == 1 && naddrs4 == 1 { export(r, &rn, false) } else { export(r, &rn, true) };

                    // ctx can be a list after NGX_RESOLVE_CNAME
                    let mut list = ctxs;
                    list.extend(std::mem::take(&mut rn.borrow_mut().waiting));

                    // unlock name mutex

                    let valid = rn.borrow().valid;

                    for ctx in list {
                        ctx.state.set(NGX_OK);
                        ctx.valid.set(valid);
                        *ctx.addrs.borrow_mut() = addrs.clone();

                        ctx.call_handler();
                    }

                    return NGX_OK;
                }

                if rn.borrow().nsrvs > 0 {
                    let mut list = ctxs;
                    list.extend(std::mem::take(&mut rn.borrow_mut().waiting));

                    // unlock name mutex

                    for ctx in list {
                        resolve_srv_names(&ctx, &rn);
                    }

                    return NGX_OK;
                }

                // NGX_RESOLVE_CNAME

                let recursion = ctxs[0].recursion.get();
                ctxs[0].recursion.set(recursion + 1);

                if recursion < NGX_RESOLVER_MAX_RECURSION {
                    let cname = rn.borrow().cname.clone();

                    return resolve_name_locked(r, ctxs, &cname);
                }

                let mut list = ctxs;
                list.extend(std::mem::take(&mut rn.borrow_mut().waiting));

                // unlock name mutex

                for ctx in list {
                    ctx.state.set(NGX_RESOLVE_NXDOMAIN);
                    ctx.valid.set(now() + if r.valid != 0 { r.valid } else { 10 });

                    ctx.call_handler();
                }

                return NGX_OK;
            }

            if !rn.borrow().waiting.is_empty() {
                for ctx in ctxs.iter() {
                    if set_timeout(r, ctx) != NGX_OK {
                        return NGX_ERROR;
                    }
                }

                let mut n = rn.borrow_mut();
                let mut list = ctxs.clone();
                list.extend(std::mem::take(&mut n.waiting));
                n.waiting = list;
                drop(n);

                for ctx in ctxs.iter() {
                    ctx.state.set(NGX_AGAIN);
                    ctx.async_.set(true);
                    *ctx.node.borrow_mut() = Some(rn.clone());
                }

                return NGX_AGAIN;
            }

            r.queue_remove(tree, &rn);

            // lock alloc mutex

            {
                let mut n = rn.borrow_mut();
                n.query = None;
                n.query6 = None;
                n.cname.clear();
                n.cnlen = 0;
                n.addrs.clear();
                n.addrs6.clear();
                n.srvs.clear();
            }

            // unlock alloc mutex

            rn
        }

        None => {
            let rn = Rc::new(RefCell::new(ResolverNode::new()));

            rn.borrow_mut().name = name.clone();

            if service {
                r.srv_tree.borrow_mut().insert(name.clone(), rn.clone());
            } else {
                r.name_tree.borrow_mut().insert(name.clone(), rn.clone());
            }

            rn
        }
    };

    let rc = if service { create_srv_query(r, &rn, &name) } else { create_name_query(r, &rn, &name) };

    if rc == NGX_ERROR {
        r.tree_delete(tree, &rn);
        return NGX_ERROR;
    }

    if rc == NGX_DECLINED {
        r.tree_delete(tree, &rn);

        for ctx in ctxs {
            ctx.state.set(NGX_RESOLVE_NXDOMAIN);

            ctx.call_handler();
        }

        return NGX_OK;
    }

    {
        let mut n = rn.borrow_mut();

        n.last_connection = r.last_connection.get();
        r.last_connection.set(r.last_connection.get() + 1);
        if r.last_connection.get() == r.connections.len() {
            r.last_connection.set(0);
        }

        n.naddrs = if r.ipv4 { PENDING } else { 0 };
        n.tcp = false;
        n.naddrs6 = if r.ipv6 { PENDING } else { 0 };
        n.tcp6 = false;
        n.nsrvs = 0;
    }

    if send_query(r, &rn) != NGX_OK {
        // immediately retry once on failure

        {
            let mut n = rn.borrow_mut();
            n.last_connection += 1;
            if n.last_connection == r.connections.len() {
                n.last_connection = 0;
            }
        }

        let _ = send_query(r, &rn);
    }

    for ctx in ctxs.iter() {
        if set_timeout(r, ctx) != NGX_OK {
            r.tree_delete(tree, &rn);
            return NGX_ERROR;
        }
    }

    if resend_empty(r) {
        r.add_resend_timer((r.resend_timeout * 1000) as u64);
    }

    {
        let mut n = rn.borrow_mut();

        n.expire = now() + r.resend_timeout;
    }

    r.resend_queue(tree).borrow_mut().push_front(rn.clone());

    {
        let mut n = rn.borrow_mut();

        n.code = 0;
        n.cnlen = 0;
        n.valid = 0;
        n.ttl = u32::MAX;
        n.waiting = ctxs.clone();
    }

    for ctx in ctxs.iter() {
        ctx.state.set(NGX_AGAIN);
        ctx.async_.set(true);
        *ctx.node.borrow_mut() = Some(rn.clone());
    }

    NGX_AGAIN
}

/// ngx_resolve_addr
pub fn resolve_addr(ctx: &Rc<ResolverCtx>) -> i64 {
    let r = ctx.resolver.clone();

    let sa = match ctx.addr.borrow().clone() {
        Some(sa) => sa,
        None => return NGX_ERROR,
    };

    let (tree, found) = match &sa {
        SockAddr::V6(sin6) => {
            let a = sin6.ip().octets();

            // lock addr mutex

            (Tree::Addr6, r.addr6_tree.borrow().get(&a).cloned())
        }
        SockAddr::V4(sin) => {
            let a = u32::from(*sin.ip());

            // lock addr mutex

            (Tree::Addr, r.addr_tree.borrow().get(&a).cloned())
        }
        _ => return NGX_ERROR,
    };

    let rn = match found {
        Some(rn) => {
            if rn.borrow().valid >= now() {
                ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolve cached");

                r.queue_remove(tree, &rn);

                rn.borrow_mut().expire = now() + r.expire;

                r.expire_queue(tree).borrow_mut().push_front(rn.clone());

                *ctx.name.borrow_mut() = rn.borrow().name.clone();

                // unlock addr mutex

                ctx.state.set(NGX_OK);
                ctx.valid.set(rn.borrow().valid);

                ctx.call_handler();

                return NGX_OK;
            }

            if !rn.borrow().waiting.is_empty() {
                if set_timeout(&r, ctx) != NGX_OK {
                    return NGX_ERROR;
                }

                rn.borrow_mut().waiting.insert(0, ctx.clone());
                ctx.state.set(NGX_AGAIN);
                ctx.async_.set(true);
                *ctx.node.borrow_mut() = Some(rn.clone());

                // unlock addr mutex

                return NGX_OK;
            }

            r.queue_remove(tree, &rn);

            {
                let mut n = rn.borrow_mut();
                n.query = None;
                n.query6 = None;
            }

            rn
        }

        None => {
            let rn = Rc::new(RefCell::new(ResolverNode::new()));

            match &sa {
                SockAddr::V6(sin6) => {
                    let a = sin6.ip().octets();
                    rn.borrow_mut().addr6 = a;
                    r.addr6_tree.borrow_mut().insert(a, rn.clone());
                }
                SockAddr::V4(sin) => {
                    let a = u32::from(*sin.ip());
                    rn.borrow_mut().addr = a;
                    r.addr_tree.borrow_mut().insert(a, rn.clone());
                }
                _ => {}
            }

            rn
        }
    };

    create_addr_query(&rn, &sa);

    {
        let mut n = rn.borrow_mut();

        n.last_connection = r.last_connection.get();
        r.last_connection.set(r.last_connection.get() + 1);
        if r.last_connection.get() == r.connections.len() {
            r.last_connection.set(0);
        }

        n.naddrs = PENDING;
        n.tcp = false;
        n.naddrs6 = PENDING;
        n.tcp6 = false;
        n.nsrvs = 0;
    }

    if send_query(&r, &rn) != NGX_OK {
        // immediately retry once on failure

        {
            let mut n = rn.borrow_mut();
            n.last_connection += 1;
            if n.last_connection == r.connections.len() {
                n.last_connection = 0;
            }
        }

        let _ = send_query(&r, &rn);
    }

    if set_timeout(&r, ctx) != NGX_OK {
        r.tree_delete(tree, &rn);
        return NGX_ERROR;
    }

    if resend_empty(&r) {
        r.add_resend_timer((r.resend_timeout * 1000) as u64);
    }

    rn.borrow_mut().expire = now() + r.resend_timeout;

    r.resend_queue(tree).borrow_mut().push_front(rn.clone());

    {
        let mut n = rn.borrow_mut();

        n.code = 0;
        n.cnlen = 0;
        n.name.clear();
        n.valid = 0;
        n.ttl = u32::MAX;
        n.waiting = vec![ctx.clone()];
    }

    // unlock addr mutex

    ctx.state.set(NGX_AGAIN);
    ctx.async_.set(true);
    *ctx.node.borrow_mut() = Some(rn);

    NGX_OK
}

/// ngx_resolve_addr_done
pub fn resolve_addr_done(ctx: &Rc<ResolverCtx>) {
    let r = ctx.resolver.clone();

    let tree = match ctx.addr.borrow().as_ref() {
        Some(SockAddr::V6(_)) => Tree::Addr6,
        _ => Tree::Addr,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolve addr done: {}", ctx.state.get());

    ctx.del_timer();

    // lock addr mutex

    if ctx.state.get() == NGX_AGAIN || ctx.state.get() == NGX_RESOLVE_TIMEDOUT {
        let rn = ctx.node.borrow().clone();

        let mut cancelled = false;

        if let Some(rn) = rn {
            let mut n = rn.borrow_mut();
            let before = n.waiting.len();
            n.waiting.retain(|w| !Rc::ptr_eq(w, ctx));
            cancelled = n.waiting.len() != before;
        }

        if !cancelled {
            let text = ctx.addr.borrow().as_ref().map(|a| a.to_text(false)).unwrap_or_default();

            ngx_log_error!(NGX_LOG_ALERT, r.log(), None, "could not cancel {} resolving", B(&text));
        }
    }

    *ctx.node.borrow_mut() = None;

    resolver_expire(&r, tree);

    // unlock addr mutex

    *ctx.handler.borrow_mut() = None;

    if r.resend_timer_set() && resend_empty(&r) {
        r.del_resend_timer();
    }
}

/// ngx_resolver_expire
fn resolver_expire(r: &Rc<Resolver>, tree: Tree) {
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver expire");

    let now = now();

    for _ in 0..2 {
        let rn = match r.expire_queue(tree).borrow().back() {
            Some(rn) => rn.clone(),
            None => return,
        };

        if now <= rn.borrow().expire {
            return;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver expire \"{}\"", B(&rn.borrow().name));

        r.expire_queue(tree).borrow_mut().pop_back();

        r.tree_delete(tree, &rn);
    }
}

/// ngx_resolver_send_query
fn send_query(r: &Rc<Resolver>, rn: &NodeRef) -> i64 {
    let last_connection = rn.borrow().last_connection;

    let rec = &r.connections[last_connection];

    if rec.log.borrow().is_none() {
        let log = r.log().fork();
        log.set_context(Some(Rc::new(ResolverLogCtx { server: rec.server.clone(), action: "resolving" })));
        *rec.log.borrow_mut() = Some(log);
    }

    let (query, naddrs, tcp, query6, naddrs6, tcp6) = {
        let n = rn.borrow();
        (n.query.clone(), n.naddrs, n.tcp, n.query6.clone(), n.naddrs6, n.tcp6)
    };

    if let Some(q) = query {
        if naddrs == PENDING {
            let rc = if tcp { send_tcp_query(r, last_connection, &q) } else { send_udp_query(r, last_connection, &q) };

            if rc != NGX_OK {
                return rc;
            }
        }
    }

    if let Some(q) = query6 {
        if naddrs6 == PENDING {
            let rc = if tcp6 { send_tcp_query(r, last_connection, &q) } else { send_udp_query(r, last_connection, &q) };

            if rc != NGX_OK {
                return rc;
            }
        }
    }

    NGX_OK
}

/// The level ngx_connection_error logs an error with.
fn connection_error_level(err: i32) -> u32 {
    if [0, libc::ECONNRESET, libc::ENOTCONN, libc::ETIMEDOUT, libc::ECONNREFUSED, libc::ENETDOWN, libc::ENETUNREACH, libc::EHOSTDOWN, libc::EHOSTUNREACH]
        .contains(&err)
    {
        NGX_LOG_ERR
    } else {
        NGX_LOG_ALERT
    }
}

fn rec_log(r: &Resolver, i: usize) -> Log {
    r.connections[i].log.borrow().clone().unwrap_or_else(|| r.log())
}

/// ngx_resolver_send_udp_query
fn send_udp_query(r: &Rc<Resolver>, i: usize, query: &[u8]) -> i64 {
    let rec = &r.connections[i];

    if rec.udp.borrow().is_none() {
        if udp_connect(r, i) != NGX_OK {
            return NGX_ERROR;
        }
    }

    let udp = rec.udp.borrow().clone().expect("udp");

    // ngx_send: UDP sockets are always ready to write, the reactor has no
    // write readiness for a new one yet
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&*udp.sock);
    let rc = unsafe { libc::send(fd, query.as_ptr() as *const libc::c_void, query.len(), 0) };
    let sent = if rc == -1 { Err(std::io::Error::last_os_error()) } else { Ok(rc as usize) };

    match sent {
        Ok(n) if n == query.len() => NGX_OK,
        Ok(_) => {
            ngx_log_error!(NGX_LOG_CRIT, rec_log(r, i), None, "send() incomplete");
            *rec.udp.borrow_mut() = None;
            NGX_ERROR
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                ngx_log_error!(NGX_LOG_CRIT, rec_log(r, i), None, "send() incomplete");
            } else {
                let err = e.raw_os_error().unwrap_or(0);
                ngx_log_error!(connection_error_level(err), rec_log(r, i), Some(err), "send() failed");
            }
            *rec.udp.borrow_mut() = None;
            NGX_ERROR
        }
    }
}

/// ngx_resolver_send_tcp_query
fn send_tcp_query(r: &Rc<Resolver>, i: usize, query: &[u8]) -> i64 {
    let rec = &r.connections[i];

    if rec.tcp.borrow().is_none() && tcp_connect(r, i) == NGX_ERROR {
        return NGX_ERROR;
    }

    let tcp = rec.tcp.borrow().clone().expect("tcp");

    {
        let mut b = tcp.write_buf.borrow_mut();

        if NGX_RESOLVER_TCP_WSIZE - b.len() < 2 + query.len() {
            ngx_log_error!(NGX_LOG_CRIT, rec_log(r, i), None, "buffer overflow");
            return NGX_ERROR;
        }

        b.push((query.len() >> 8) as u8);
        b.push(query.len() as u8);
        b.extend_from_slice(query);
    }

    // ngx_resolver_tcp_write
    tcp.wakeup.notify_one();

    NGX_OK
}

/// ngx_resolver_resend_handler
impl Resolver {
    fn resend_handler(self: &Rc<Self>) {
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, self.log(), "resolver resend handler");

        // lock name mutex

        let ntimer = resend(self, Tree::Name);

        let stimer = resend(self, Tree::Srv);

        // unlock name mutex

        // lock addr mutex

        let atimer = resend(self, Tree::Addr);

        // unlock addr mutex

        // lock addr6 mutex

        let a6timer = resend(self, Tree::Addr6);

        // unlock addr6 mutex

        let mut timer = ntimer;

        if timer == 0 {
            timer = atimer;
        } else if atimer != 0 {
            timer = timer.min(atimer);
        }

        if timer == 0 {
            timer = stimer;
        } else if stimer != 0 {
            timer = timer.min(stimer);
        }

        if timer == 0 {
            timer = a6timer;
        } else if a6timer != 0 {
            timer = timer.min(a6timer);
        }

        if timer != 0 {
            self.add_resend_timer((timer * 1000) as u64);
        }
    }
}

/// ngx_resolver_resend
fn resend(r: &Rc<Resolver>, tree: Tree) -> i64 {
    let now = now();

    loop {
        let rn = match r.resend_queue(tree).borrow().back() {
            Some(rn) => rn.clone(),
            None => return 0,
        };

        {
            let n = rn.borrow();
            if now < n.expire {
                return n.expire - now;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver resend \"{}\" {:p}", B(&n.name), n.waiting.as_ptr());
        }

        r.resend_queue(tree).borrow_mut().pop_back();

        if !rn.borrow().waiting.is_empty() {
            {
                let mut n = rn.borrow_mut();
                n.last_connection += 1;
                if n.last_connection == r.connections.len() {
                    n.last_connection = 0;
                }
            }

            let _ = send_query(r, &rn);

            rn.borrow_mut().expire = now + r.resend_timeout;

            r.resend_queue(tree).borrow_mut().push_front(rn);

            continue;
        }

        r.tree_delete(tree, &rn);
    }
}

/// ngx_resolver_resend_empty
fn resend_empty(r: &Resolver) -> bool {
    r.name_resend_queue.borrow().is_empty()
        && r.srv_resend_queue.borrow().is_empty()
        && r.addr6_resend_queue.borrow().is_empty()
        && r.addr_resend_queue.borrow().is_empty()
}

/// ngx_udp_connect, with ngx_resolver_udp_read as the socket's reader
fn udp_connect(r: &Rc<Resolver>, i: usize) -> i64 {
    let rec = &r.connections[i];
    let log = rec_log(r, i);

    let (sa, len) = rec.sockaddr.to_libc();

    let s = unsafe { libc::socket(sa.ss_family as i32, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "UDP socket {}", s);

    if s == -1 {
        ngx_log_error!(NGX_LOG_ALERT, log, Some(errno()), "socket() failed");
        return NGX_ERROR;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "connect to {}, fd:{}", B(&rec.server), s);

    if unsafe { libc::connect(s, &sa as *const libc::sockaddr_storage as *const libc::sockaddr, len) } == -1 {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(errno()), "connect() failed");
        unsafe { libc::close(s) };
        return NGX_ERROR;
    }

    let std_sock = unsafe { <std::net::UdpSocket as std::os::unix::io::FromRawFd>::from_raw_fd(s) };

    let sock = match tokio::net::UdpSocket::from_std(std_sock) {
        Ok(s) => Rc::new(s),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, e.raw_os_error(), "epoll_ctl() failed");
            return NGX_ERROR;
        }
    };

    let wr = Rc::downgrade(r);
    let rsock = sock.clone();

    let task = crate::event::spawn(async move {
        let mut buf = vec![0u8; NGX_RESOLVER_UDP_SIZE];

        loop {
            let rc = rsock.recv(&mut buf).await;

            let r = match wr.upgrade() {
                Some(r) => r,
                None => return,
            };

            match rc {
                Ok(n) => {
                    crate::times::update();
                    process_response(&r, &buf[..n], false);
                }
                Err(e) => {
                    let err = e.raw_os_error().unwrap_or(0);
                    ngx_log_error!(connection_error_level(err), rec_log(&r, i), Some(err), "recv() failed");

                    // ngx_close_connection(rec->udp), unless it was replaced
                    let current = r.connections[i].udp.borrow().clone();
                    if let Some(u) = current {
                        if Rc::ptr_eq(&u.sock, &rsock) {
                            u.task.borrow_mut().take();
                            *r.connections[i].udp.borrow_mut() = None;
                        }
                    }
                    return;
                }
            }
        }
    });

    *rec.udp.borrow_mut() = Some(Rc::new(UdpConn { sock, task: RefCell::new(Some(task)) }));

    NGX_OK
}

/// ngx_tcp_connect, with ngx_resolver_tcp_write and ngx_resolver_tcp_read
/// as the connection's task: queries in write_buf are sent, responses are
/// read and processed; the connection is closed tcp_timeout seconds after
/// it last sent anything.
fn tcp_connect(r: &Rc<Resolver>, i: usize) -> i64 {
    let rec = &r.connections[i];

    let conn = Rc::new(TcpConn {
        write_buf: RefCell::new(Vec::with_capacity(NGX_RESOLVER_TCP_WSIZE)),
        wakeup: tokio::sync::Notify::new(),
        task: RefCell::new(None),
    });

    let wr = Rc::downgrade(r);
    let wconn = Rc::downgrade(&conn);
    let addr = match &rec.sockaddr {
        SockAddr::V4(a) => std::net::SocketAddr::V4(*a),
        SockAddr::V6(a) => std::net::SocketAddr::V6(*a),
        _ => return NGX_ERROR,
    };
    let server = rec.server.clone();
    let tcp_timeout = std::time::Duration::from_secs(r.tcp_timeout as u64);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, rec_log(r, i), "TCP socket to {}", B(&server));

    let task = crate::event::spawn(async move {
        let close = |r: &Rc<Resolver>| {
            let current = r.connections[i].tcp.borrow().clone();
            if let (Some(c), Some(me)) = (current, wconn.upgrade()) {
                if Rc::ptr_eq(&c, &me) {
                    c.task.borrow_mut().take();
                    *r.connections[i].tcp.borrow_mut() = None;
                }
            }
        };

        let stream = match tokio::time::timeout(tcp_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                if let Some(r) = wr.upgrade() {
                    let err = e.raw_os_error().unwrap_or(0);
                    let level = if [libc::ECONNREFUSED, libc::EAGAIN, libc::ECONNRESET, libc::ENETDOWN, libc::ENETUNREACH, libc::EHOSTDOWN, libc::EHOSTUNREACH].contains(&err) {
                        NGX_LOG_ERR
                    } else {
                        NGX_LOG_CRIT
                    };
                    ngx_log_error!(level, rec_log(&r, i), Some(err), "connect() to {} failed", B(&server));
                    close(&r);
                }
                return;
            }
            Err(_) => {
                if let Some(r) = wr.upgrade() {
                    close(&r);
                }
                return;
            }
        };

        let mut read_buf: Vec<u8> = Vec::with_capacity(NGX_RESOLVER_TCP_RSIZE);
        let mut chunk = vec![0u8; NGX_RESOLVER_TCP_RSIZE];
        let mut deadline = tokio::time::Instant::now() + tcp_timeout;

        loop {
            let conn = match wconn.upgrade() {
                Some(c) => c,
                None => return,
            };

            // ngx_resolver_tcp_write
            loop {
                let pending = conn.write_buf.borrow().clone();
                if pending.is_empty() {
                    break;
                }
                match stream.try_write(&pending) {
                    Ok(n) => {
                        conn.write_buf.borrow_mut().drain(..n);
                        deadline = tokio::time::Instant::now() + tcp_timeout;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        if let Some(r) = wr.upgrade() {
                            close(&r);
                        }
                        return;
                    }
                }
            }

            let want_write = !conn.write_buf.borrow().is_empty();

            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    // wev->timedout
                    if let Some(r) = wr.upgrade() {
                        close(&r);
                    }
                    return;
                }
                _ = conn.wakeup.notified() => {}
                rc = stream.writable(), if want_write => {
                    if rc.is_err() {
                        if let Some(r) = wr.upgrade() {
                            close(&r);
                        }
                        return;
                    }
                }
                rc = stream.readable() => {
                    if rc.is_err() {
                        if let Some(r) = wr.upgrade() {
                            close(&r);
                        }
                        return;
                    }

                    // ngx_resolver_tcp_read
                    let room = NGX_RESOLVER_TCP_RSIZE - read_buf.len();
                    match stream.try_read(&mut chunk[..room]) {
                        Ok(0) => {
                            if let Some(r) = wr.upgrade() {
                                close(&r);
                            }
                            return;
                        }
                        Ok(n) => {
                            read_buf.extend_from_slice(&chunk[..n]);

                            let r = match wr.upgrade() {
                                Some(r) => r,
                                None => return,
                            };

                            crate::times::update();

                            loop {
                                if read_buf.len() < 2 {
                                    break;
                                }

                                let qlen = ((read_buf[0] as usize) << 8) + read_buf[1] as usize;

                                if read_buf.len() < 2 + qlen {
                                    break;
                                }

                                let msg: Vec<u8> = read_buf[2..2 + qlen].to_vec();
                                read_buf.drain(..2 + qlen);

                                process_response(&r, &msg, true);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            if let Some(r) = wr.upgrade() {
                                close(&r);
                            }
                            return;
                        }
                    }
                }
            }
        }
    });

    *conn.task.borrow_mut() = Some(task);
    *rec.tcp.borrow_mut() = Some(conn);

    NGX_OK
}

/// ngx_resolver_process_response
fn process_response(r: &Rc<Resolver>, buf: &[u8], tcp: bool) {
    let n = buf.len();

    if n < HDR_LEN {
        ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
        return;
    }

    let ident = ((buf[0] as usize) << 8) + buf[1] as usize;
    let flags = ((buf[2] as usize) << 8) + buf[3] as usize;
    let nqs = ((buf[4] as usize) << 8) + buf[5] as usize;
    let nan = ((buf[6] as usize) << 8) + buf[7] as usize;
    let trunc = flags & 0x0200 != 0;

    ngx_log_debug!(
        NGX_LOG_DEBUG_CORE,
        r.log(),
        "resolver DNS response {} fl:{:04X} {}/{}/{}/{}",
        ident,
        flags,
        nqs,
        nan,
        ((buf[8] as usize) << 8) + buf[9] as usize,
        ((buf[10] as usize) << 8) + buf[11] as usize
    );

    // response to a standard query
    if (flags & 0xf870) != 0x8000 || (trunc && tcp) {
        ngx_log_error!(r.log_level, r.log(), None, "invalid {} DNS response {} fl:{:04X}", if tcp { "TCP" } else { "UDP" }, ident, flags);
        return;
    }

    let code = (flags & 0xf) as i64;

    if code == NGX_RESOLVE_FORMERR {
        let queue = r.name_resend_queue.borrow();

        for (times, rn) in queue.iter().enumerate() {
            if times >= 100 {
                break;
            }

            let n = rn.borrow();

            let q = n.query.as_ref().map(|q| ((q[0] as usize) << 8) + q[1] as usize);
            let q6 = n.query6.as_ref().map(|q| ((q[0] as usize) << 8) + q[1] as usize);

            if q == Some(ident) || q6 == Some(ident) {
                ngx_log_error!(
                    r.log_level,
                    r.log(),
                    None,
                    "DNS error ({}: {}), query id:{}, name:\"{}\"",
                    code,
                    Resolver::strerror(code),
                    ident,
                    B(&n.name)
                );
                return;
            }
        }

        ngx_log_error!(r.log_level, r.log(), None, "DNS error ({}: {}), query id:{}", code, Resolver::strerror(code), ident);
        return;
    }

    if code > NGX_RESOLVE_REFUSED {
        ngx_log_error!(r.log_level, r.log(), None, "DNS error ({}: {}), query id:{}", code, Resolver::strerror(code), ident);
        return;
    }

    if nqs != 1 {
        ngx_log_error!(r.log_level, r.log(), None, "invalid number of questions in DNS response");
        return;
    }

    let mut i = HDR_LEN;

    let found = loop {
        if i >= n {
            break false;
        }

        if buf[i] & 0xc0 != 0 {
            ngx_log_error!(r.log_level, r.log(), None, "unexpected compression pointer in DNS response");
            return;
        }

        if buf[i] == 0 {
            break true;
        }

        i += 1 + buf[i] as usize;
    };

    if !found {
        ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
        return;
    }

    // found:

    if i == HDR_LEN {
        ngx_log_error!(r.log_level, r.log(), None, "zero-length domain name in DNS response");
        return;
    }

    i += 1;

    if i + QS_LEN + nan * (2 + AN_LEN) > n {
        ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
        return;
    }

    let qtype = ((buf[i] as u16) << 8) + buf[i + 1] as u16;
    let qclass = ((buf[i + 2] as u16) << 8) + buf[i + 3] as u16;

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver DNS response qt:{} cl:{}", qtype, qclass);

    if qclass != 1 {
        ngx_log_error!(r.log_level, r.log(), None, "unknown query class {} in DNS response", qclass);
        return;
    }

    match qtype {
        NGX_RESOLVE_A | NGX_RESOLVE_AAAA => {
            process_a(r, buf, ident, code, qtype, nan, trunc, i + QS_LEN);
        }

        NGX_RESOLVE_SRV => {
            process_srv(r, buf, ident, code, nan, trunc, i + QS_LEN);
        }

        NGX_RESOLVE_PTR => {
            process_ptr(r, buf, ident, code, nan);
        }

        _ => {
            ngx_log_error!(r.log_level, r.log(), None, "unknown query type {} in DNS response", qtype);
        }
    }
}

/// An answer's type, class, ttl and data length after its name.
struct An {
    typ: u16,
    class: u16,
    ttl: i32,
    len: usize,
}

fn read_an(buf: &[u8], i: usize) -> An {
    An {
        typ: ((buf[i] as u16) << 8) + buf[i + 1] as u16,
        class: ((buf[i + 2] as u16) << 8) + buf[i + 3] as u16,
        ttl: (((buf[i + 4] as u32) << 24) + ((buf[i + 5] as u32) << 16) + ((buf[i + 6] as u32) << 8) + buf[i + 7] as u32) as i32,
        len: ((buf[i + 8] as usize) << 8) + buf[i + 9] as usize,
    }
}

/// Skip the name of an answer: Ok(position after it), or the error.
enum NameSkip {
    Ok(usize),
    Short,
    Invalid,
}

fn skip_an_name(buf: &[u8], mut i: usize) -> NameSkip {
    let n = buf.len();
    let start = i;

    while i < n {
        if buf[i] & 0xc0 != 0 {
            return NameSkip::Ok(i + 2);
        }

        if buf[i] == 0 {
            i += 1;

            // test_length
            if i - start < 2 {
                return NameSkip::Invalid;
            }

            return NameSkip::Ok(i);
        }

        i += 1 + buf[i] as usize;
    }

    NameSkip::Short
}

/// Skip a name known to be valid (the second pass over the answers).
fn skip_name(buf: &[u8], mut i: usize) -> usize {
    loop {
        if buf[i] & 0xc0 != 0 {
            return i + 2;
        }

        if buf[i] == 0 {
            return i + 1;
        }

        i += 1 + buf[i] as usize;
    }
}

/// ngx_resolver_process_a
#[allow(clippy::too_many_arguments)]
fn process_a(r: &Rc<Resolver>, buf: &[u8], ident: usize, code: i64, qtype: u16, nan: usize, trunc: bool, ans: usize) {
    let n = buf.len();

    let name = match copy_name(r, buf, HDR_LEN) {
        Some(name) => name,
        None => return,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver qs:{}", B(&name));

    // lock name mutex

    let rn = match r.name_tree.borrow().get(&name).cloned() {
        Some(rn) => rn,
        None => {
            ngx_log_error!(r.log_level, r.log(), None, "unexpected DNS response for {}", B(&name));
            return;
        }
    };

    let qident = {
        let node = rn.borrow();

        if qtype == NGX_RESOLVE_AAAA {
            if node.query6.is_none() || node.naddrs6 != PENDING {
                ngx_log_error!(r.log_level, r.log(), None, "unexpected DNS response for {}", B(&name));
                return;
            }

            if trunc && node.tcp6 {
                return;
            }

            let q = node.query6.as_ref().unwrap();
            ((q[0] as usize) << 8) + q[1] as usize
        } else {
            if node.query.is_none() || node.naddrs != PENDING {
                ngx_log_error!(r.log_level, r.log(), None, "unexpected DNS response for {}", B(&name));
                return;
            }

            if trunc && node.tcp {
                return;
            }

            let q = node.query.as_ref().unwrap();
            ((q[0] as usize) << 8) + q[1] as usize
        }
    };

    if ident != qident {
        ngx_log_error!(r.log_level, r.log(), None, "wrong ident {} in DNS response for {}, expect {}", ident, B(&name), qident);
        return;
    }

    if trunc {
        r.queue_remove(Tree::Name, &rn);

        if rn.borrow().waiting.is_empty() {
            r.tree_delete(Tree::Name, &rn);
            return;
        }

        let last_connection = rn.borrow().last_connection;

        if qtype == NGX_RESOLVE_AAAA {
            rn.borrow_mut().tcp6 = true;

            let q = rn.borrow().query6.clone().unwrap_or_default();
            let _ = send_tcp_query(r, last_connection, &q);
        } else {
            rn.borrow_mut().tcp = true;

            let q = rn.borrow().query.clone().unwrap_or_default();
            let _ = send_tcp_query(r, last_connection, &q);
        }

        rn.borrow_mut().expire = now() + r.resend_timeout;

        r.name_resend_queue.borrow_mut().push_front(rn);

        return;
    }

    let mut code = code;

    if code == 0 && rn.borrow().code != 0 {
        code = rn.borrow().code as i64;
    }

    let mut goto_export = false;

    if code == 0 && nan == 0 {
        let mut node = rn.borrow_mut();

        if qtype == NGX_RESOLVE_AAAA {
            node.naddrs6 = 0;

            if node.naddrs == PENDING {
                return;
            }

            if node.naddrs != 0 {
                goto_export = true;
            }
        } else {
            node.naddrs = 0;

            if node.naddrs6 == PENDING {
                return;
            }

            if node.naddrs6 != 0 {
                goto_export = true;
            }
        }

        if !goto_export {
            code = NGX_RESOLVE_NXDOMAIN;
        }
    }

    if !goto_export && code != 0 {
        {
            let mut node = rn.borrow_mut();

            if qtype == NGX_RESOLVE_AAAA {
                node.naddrs6 = 0;

                if node.naddrs == PENDING {
                    node.code = code as u8;
                    return;
                }
            } else {
                node.naddrs = 0;

                if node.naddrs6 == PENDING {
                    node.code = code as u8;
                    return;
                }
            }
        }

        let list = std::mem::take(&mut rn.borrow_mut().waiting);

        r.queue_remove(Tree::Name, &rn);

        r.tree_delete(Tree::Name, &rn);

        // unlock name mutex

        for ctx in list {
            ctx.state.set(code);
            ctx.valid.set(now() + if r.valid != 0 { r.valid } else { 10 });

            ctx.call_handler();
        }

        return;
    }

    let mut cname: Option<usize> = None;

    if !goto_export {
        let mut i = ans;
        let mut naddrs = 0usize;

        for _ in 0..nan {
            i = match skip_an_name(buf, i) {
                NameSkip::Ok(p) => p,
                NameSkip::Short => {
                    ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
                    return;
                }
                NameSkip::Invalid => {
                    ngx_log_error!(r.log_level, r.log(), None, "invalid name in DNS response");
                    return;
                }
            };

            // found:

            if i + AN_LEN >= n {
                ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
                return;
            }

            let an = read_an(buf, i);

            if an.class != 1 {
                ngx_log_error!(r.log_level, r.log(), None, "unexpected RR class {} in DNS response", an.class);
                return;
            }

            let ttl = an.ttl.max(0) as u32;

            {
                let mut node = rn.borrow_mut();
                node.ttl = node.ttl.min(ttl);
            }

            i += AN_LEN;

            match an.typ {
                NGX_RESOLVE_A => {
                    if qtype != NGX_RESOLVE_A {
                        ngx_log_error!(r.log_level, r.log(), None, "unexpected A record in DNS response");
                        return;
                    }

                    if an.len != 4 {
                        ngx_log_error!(r.log_level, r.log(), None, "invalid A record in DNS response");
                        return;
                    }

                    if i + 4 > n {
                        ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
                        return;
                    }

                    naddrs += 1;
                }

                NGX_RESOLVE_AAAA => {
                    if qtype != NGX_RESOLVE_AAAA {
                        ngx_log_error!(r.log_level, r.log(), None, "unexpected AAAA record in DNS response");
                        return;
                    }

                    if an.len != 16 {
                        ngx_log_error!(r.log_level, r.log(), None, "invalid AAAA record in DNS response");
                        return;
                    }

                    if i + 16 > n {
                        ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
                        return;
                    }

                    naddrs += 1;
                }

                NGX_RESOLVE_CNAME => {
                    cname = Some(i);
                }

                NGX_RESOLVE_DNAME => {}

                _ => {
                    ngx_log_error!(r.log_level, r.log(), None, "unexpected RR type {} in DNS response", an.typ);
                }
            }

            i += an.len;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver naddrs:{} cname:{:?} ttl:{}", naddrs, cname, rn.borrow().ttl);

        if naddrs > 0 {
            let mut addrs: Vec<[u8; 4]> = Vec::new();
            let mut addrs6: Vec<[u8; 16]> = Vec::new();

            let mut i = ans;

            for _ in 0..nan {
                i = skip_name(buf, i);

                let an = read_an(buf, i);

                i += AN_LEN;

                if an.typ == NGX_RESOLVE_A {
                    addrs.push([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);

                    if addrs.len() == naddrs {
                        break;
                    }
                } else if an.typ == NGX_RESOLVE_AAAA {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&buf[i..i + 16]);
                    addrs6.push(a);

                    if addrs6.len() == naddrs {
                        break;
                    }
                }

                i += an.len;
            }

            let mut node = rn.borrow_mut();

            if qtype == NGX_RESOLVE_AAAA {
                node.naddrs6 = naddrs as u16;
                node.addrs6 = addrs6;

                if node.naddrs == PENDING {
                    return;
                }
            } else {
                node.naddrs = naddrs as u16;
                node.addrs = addrs;

                if node.naddrs6 == PENDING {
                    return;
                }
            }
        }

        {
            let mut node = rn.borrow_mut();

            if qtype == NGX_RESOLVE_AAAA {
                if node.naddrs6 == PENDING {
                    node.naddrs6 = 0;
                }
            } else if node.naddrs == PENDING {
                node.naddrs = 0;
            }
        }
    }

    let (naddrs4, naddrs6) = {
        let node = rn.borrow();
        (node.naddrs, node.naddrs6)
    };

    if goto_export || (naddrs4 != PENDING && naddrs6 != PENDING && naddrs4 as usize + naddrs6 as usize > 0) {
        // export:

        let addrs = export(r, &rn, false);

        r.queue_remove(Tree::Name, &rn);

        {
            let mut node = rn.borrow_mut();
            node.valid = now() + if r.valid != 0 { r.valid } else { node.ttl as i64 };
            node.expire = now() + r.expire;
        }

        r.name_expire_queue.borrow_mut().push_front(rn.clone());

        let list = std::mem::take(&mut rn.borrow_mut().waiting);

        // unlock name mutex

        let valid = rn.borrow().valid;

        for ctx in list {
            ctx.state.set(NGX_OK);
            ctx.valid.set(valid);
            *ctx.addrs.borrow_mut() = addrs.clone();

            ctx.call_handler();
        }

        {
            let mut node = rn.borrow_mut();
            node.query = None;
            node.query6 = None;
        }

        return;
    }

    if let Some(cname) = cname {
        // CNAME only

        if naddrs4 == PENDING || naddrs6 == PENDING {
            return;
        }

        let name = match copy_name(r, buf, cname) {
            Some(name) => name,
            None => return,
        };

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver cname:\"{}\"", B(&name));

        r.queue_remove(Tree::Name, &rn);

        {
            let mut node = rn.borrow_mut();
            node.cnlen = name.len() as u16;
            node.cname = name.clone();

            node.valid = now() + if r.valid != 0 { r.valid } else { node.ttl as i64 };
            node.expire = now() + r.expire;
        }

        r.name_expire_queue.borrow_mut().push_front(rn.clone());

        {
            let mut node = rn.borrow_mut();
            node.query = None;
            node.query6 = None;
        }

        let list = std::mem::take(&mut rn.borrow_mut().waiting);

        if !list.is_empty() {
            let recursion = list[0].recursion.get();
            list[0].recursion.set(recursion + 1);

            if recursion >= NGX_RESOLVER_MAX_RECURSION {
                // unlock name mutex

                for ctx in list {
                    ctx.state.set(NGX_RESOLVE_NXDOMAIN);

                    ctx.call_handler();
                }

                return;
            }

            for ctx in list.iter() {
                *ctx.node.borrow_mut() = None;
            }

            let _ = resolve_name_locked(r, list, &name);
        }

        // unlock name mutex

        return;
    }

    ngx_log_error!(r.log_level, r.log(), None, "no A or CNAME types in DNS response");
}

/// ngx_resolver_process_srv
#[allow(clippy::too_many_arguments)]
fn process_srv(r: &Rc<Resolver>, buf: &[u8], ident: usize, code: i64, nan: usize, trunc: bool, ans: usize) {
    let n = buf.len();

    let name = match copy_name(r, buf, HDR_LEN) {
        Some(name) => name,
        None => return,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver qs:{}", B(&name));

    let rn = match r.srv_tree.borrow().get(&name).cloned() {
        Some(rn) if rn.borrow().query.is_some() => rn,
        _ => {
            ngx_log_error!(r.log_level, r.log(), None, "unexpected DNS response for {}", B(&name));
            return;
        }
    };

    if trunc && rn.borrow().tcp {
        return;
    }

    let qident = {
        let node = rn.borrow();
        let q = node.query.as_ref().unwrap();
        ((q[0] as usize) << 8) + q[1] as usize
    };

    if ident != qident {
        ngx_log_error!(r.log_level, r.log(), None, "wrong ident {} in DNS response for {}, expect {}", ident, B(&name), qident);
        return;
    }

    if trunc {
        r.queue_remove(Tree::Srv, &rn);

        if rn.borrow().waiting.is_empty() {
            r.tree_delete(Tree::Srv, &rn);
            return;
        }

        let last_connection = rn.borrow().last_connection;

        rn.borrow_mut().tcp = true;

        let q = rn.borrow().query.clone().unwrap_or_default();
        let _ = send_tcp_query(r, last_connection, &q);

        rn.borrow_mut().expire = now() + r.resend_timeout;

        r.srv_resend_queue.borrow_mut().push_front(rn);

        return;
    }

    let mut code = code;

    if code == 0 && rn.borrow().code != 0 {
        code = rn.borrow().code as i64;
    }

    if code == 0 && nan == 0 {
        code = NGX_RESOLVE_NXDOMAIN;
    }

    if code != 0 {
        let list = std::mem::take(&mut rn.borrow_mut().waiting);

        r.queue_remove(Tree::Srv, &rn);

        r.tree_delete(Tree::Srv, &rn);

        for ctx in list {
            ctx.state.set(code);
            ctx.valid.set(now() + if r.valid != 0 { r.valid } else { 10 });

            ctx.call_handler();
        }

        return;
    }

    let mut i = ans;
    let mut nsrvs = 0usize;
    let mut cname: Option<usize> = None;

    for _ in 0..nan {
        i = match skip_an_name(buf, i) {
            NameSkip::Ok(p) => p,
            NameSkip::Short => {
                ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
                return;
            }
            NameSkip::Invalid => {
                ngx_log_error!(r.log_level, r.log(), None, "invalid name DNS response");
                return;
            }
        };

        // found:

        if i + AN_LEN >= n {
            ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
            return;
        }

        let an = read_an(buf, i);

        if an.class != 1 {
            ngx_log_error!(r.log_level, r.log(), None, "unexpected RR class {} in DNS response", an.class);
            return;
        }

        let ttl = an.ttl.max(0) as u32;

        {
            let mut node = rn.borrow_mut();
            node.ttl = node.ttl.min(ttl);
        }

        i += AN_LEN;

        match an.typ {
            NGX_RESOLVE_SRV => {
                if i + 6 >= n {
                    ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
                    return;
                }

                if check_name(r, buf, i + 6).is_none() {
                    return;
                }

                nsrvs += 1;
            }

            NGX_RESOLVE_CNAME => {
                cname = Some(i);
            }

            NGX_RESOLVE_DNAME => {}

            _ => {
                ngx_log_error!(r.log_level, r.log(), None, "unexpected RR type {} in DNS response", an.typ);
            }
        }

        i += an.len;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver nsrvs:{} cname:{:?} ttl:{}", nsrvs, cname, rn.borrow().ttl);

    if nsrvs > 0 {
        let mut srvs: Vec<ResolverSrv> = Vec::with_capacity(nsrvs);

        let mut i = ans;

        for _ in 0..nan {
            i = skip_name(buf, i);

            let an = read_an(buf, i);

            i += AN_LEN;

            if an.typ == NGX_RESOLVE_SRV {
                let mut srv = ResolverSrv {
                    priority: ((buf[i] as u16) << 8) + buf[i + 1] as u16,
                    weight: ((buf[i + 2] as u16) << 8) + buf[i + 3] as u16,
                    port: ((buf[i + 4] as u16) << 8) + buf[i + 5] as u16,
                    name: Vec::new(),
                };

                if srv.weight == 0 {
                    srv.weight = 1;
                }

                srv.name = match copy_name(r, buf, i + 6) {
                    Some(name) => name,
                    None => return,
                };

                srvs.push(srv);
            }

            i += an.len;
        }

        // ngx_sort: an insertion sort, stable, by priority
        srvs.sort_by_key(|s| s.priority);

        {
            let mut node = rn.borrow_mut();
            node.nsrvs = srvs.len() as u16;
            node.srvs = srvs;
            node.query = None;
        }

        r.queue_remove(Tree::Srv, &rn);

        {
            let mut node = rn.borrow_mut();
            node.valid = now() + if r.valid != 0 { r.valid } else { node.ttl as i64 };
            node.expire = now() + r.expire;
        }

        r.srv_expire_queue.borrow_mut().push_front(rn.clone());

        let list = std::mem::take(&mut rn.borrow_mut().waiting);

        for ctx in list {
            resolve_srv_names(&ctx, &rn);
        }

        return;
    }

    rn.borrow_mut().nsrvs = 0;

    if let Some(cname) = cname {
        // CNAME only

        let name = match copy_name(r, buf, cname) {
            Some(name) => name,
            None => return,
        };

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver cname:\"{}\"", B(&name));

        r.queue_remove(Tree::Srv, &rn);

        {
            let mut node = rn.borrow_mut();
            node.cnlen = name.len() as u16;
            node.cname = name.clone();

            node.valid = now() + if r.valid != 0 { r.valid } else { node.ttl as i64 };
            node.expire = now() + r.expire;
        }

        r.srv_expire_queue.borrow_mut().push_front(rn.clone());

        {
            let mut node = rn.borrow_mut();
            node.query = None;
            node.query6 = None;
        }

        let list = std::mem::take(&mut rn.borrow_mut().waiting);

        if !list.is_empty() {
            let recursion = list[0].recursion.get();
            list[0].recursion.set(recursion + 1);

            if recursion >= NGX_RESOLVER_MAX_RECURSION {
                // unlock name mutex

                for ctx in list {
                    ctx.state.set(NGX_RESOLVE_NXDOMAIN);

                    ctx.call_handler();
                }

                return;
            }

            for ctx in list.iter() {
                *ctx.node.borrow_mut() = None;
            }

            let _ = resolve_name_locked(r, list, &name);
        }

        // unlock name mutex

        return;
    }

    ngx_log_error!(r.log_level, r.log(), None, "no SRV type in DNS response");
}

/// ngx_resolver_resolve_srv_names
fn resolve_srv_names(ctx: &Rc<ResolverCtx>, rn: &NodeRef) {
    let r = ctx.resolver.clone();

    *ctx.node.borrow_mut() = None;
    ctx.state.set(NGX_OK);
    ctx.valid.set(rn.borrow().valid);

    let srvs_of_node = rn.borrow().srvs.clone();

    ctx.count.set(srvs_of_node.len());

    *ctx.srvs.borrow_mut() = srvs_of_node
        .iter()
        .map(|s| ResolverSrvName { name: s.name.clone(), priority: s.priority, weight: s.weight, port: s.port, ..Default::default() })
        .collect();

    ctx.del_timer();

    for (i, srv) in srvs_of_node.iter().enumerate() {
        let cctx = match r.start(None) {
            ResolveStart::Ctx(c) => c,
            ResolveStart::NoResolver => {
                ctx.state.set(NGX_ERROR);
                ctx.valid.set(now() + if r.valid != 0 { r.valid } else { 10 });

                ctx.call_handler();
                return;
            }
        };

        *cctx.name.borrow_mut() = srv.name.clone();
        *cctx.handler.borrow_mut() = Some(Rc::new(srv_names_handler));
        *cctx.parent.borrow_mut() = Some(ctx.clone());
        cctx.srv_index.set(i);
        cctx.timeout.set(ctx.timeout.get());

        ctx.srvs.borrow_mut()[i].ctx = Some(cctx.clone());

        if resolve_name(&cctx) == NGX_ERROR {
            ctx.srvs.borrow_mut()[i].ctx = None;

            ctx.state.set(NGX_ERROR);
            ctx.valid.set(now() + if r.valid != 0 { r.valid } else { 10 });

            ctx.call_handler();
            return;
        }
    }
}

/// ngx_resolver_srv_names_handler
fn srv_names_handler(cctx: &Rc<ResolverCtx>) {
    let r = cctx.resolver.clone();

    let ctx = match cctx.parent.borrow().clone() {
        Some(c) => c,
        None => return,
    };

    let i = cctx.srv_index.get();

    ctx.count.set(ctx.count.get() - 1);
    ctx.async_.set(ctx.async_.get() | cctx.async_.get());

    {
        let mut srvs = ctx.srvs.borrow_mut();
        let srv = &mut srvs[i];

        srv.ctx = None;
        srv.state = cctx.state.get();

        let addrs = cctx.addrs.borrow();

        if !addrs.is_empty() {
            ctx.valid.set(ctx.valid.get().min(cctx.valid.get()));

            srv.addrs = addrs
                .iter()
                .map(|a| {
                    let mut sa = a.sockaddr.clone();
                    sa.set_port(srv.port);
                    sa
                })
                .collect();
        }
    }

    resolve_name_done(cctx);

    if ctx.count.get() == 0 {
        report_srv(&r, &ctx);
    }
}

/// ngx_resolver_process_ptr
fn process_ptr(r: &Rc<Resolver>, buf: &[u8], ident: usize, code: i64, nan: usize) {
    let n = buf.len();

    let name = match copy_name(r, buf, HDR_LEN) {
        Some(name) => name,
        None => return,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver qs:{}", B(&name));

    // AF_INET

    let parse_in_addr = || -> Option<(u32, usize)> {
        let mut addr: u32 = 0;
        let mut i = HDR_LEN;

        for mask in (0..32).step_by(8) {
            let len = *buf.get(i)? as usize;
            i += 1;

            let octet = crate::string::atoi(buf.get(i..i + len)?)?;
            if octet > 255 {
                return None;
            }

            addr += (octet as u32) << mask;
            i += len;
        }

        let tail = b"\x07in-addr\x04arpa\x00";

        if buf.get(i..i + tail.len()).is_some_and(|t| t.eq_ignore_ascii_case(tail)) {
            return Some((addr, i + tail.len()));
        }

        None
    };

    let parse_ip6_arpa = || -> Option<([u8; 16], usize)> {
        let mut addr6 = [0u8; 16];
        let mut i = HDR_LEN;

        for octet in (0..16).rev() {
            if *buf.get(i)? != 1 {
                return None;
            }
            i += 1;

            let digit = (*buf.get(i)? as char).to_digit(16)? as u8;
            i += 1;

            addr6[octet] = digit;

            if *buf.get(i)? != 1 {
                return None;
            }
            i += 1;

            let digit = (*buf.get(i)? as char).to_digit(16)? as u8;
            i += 1;

            addr6[octet] += digit * 16;
        }

        let tail = b"\x03ip6\x04arpa\x00";

        if buf.get(i..i + tail.len()).is_some_and(|t| t.eq_ignore_ascii_case(tail)) {
            return Some((addr6, i + tail.len()));
        }

        None
    };

    let (tree, rn, mut i) = if let Some((addr, i)) = parse_in_addr() {
        // lock addr mutex

        (Tree::Addr, r.addr_tree.borrow().get(&addr).cloned(), i)
    } else if let Some((addr6, i)) = parse_ip6_arpa() {
        // lock addr mutex

        (Tree::Addr6, r.addr6_tree.borrow().get(&addr6).cloned(), i)
    } else {
        ngx_log_error!(r.log_level, r.log(), None, "invalid in-addr.arpa or ip6.arpa name in DNS response");
        return;
    };

    // valid:

    let rn = match rn {
        Some(rn) if rn.borrow().query.is_some() => rn,
        _ => {
            ngx_log_error!(r.log_level, r.log(), None, "unexpected DNS response for {}", B(&name));
            return;
        }
    };

    let qident = {
        let node = rn.borrow();
        let q = node.query.as_ref().unwrap();
        ((q[0] as usize) << 8) + q[1] as usize
    };

    if ident != qident {
        ngx_log_error!(r.log_level, r.log(), None, "wrong ident {} in DNS response for {}, expect {}", ident, B(&name), qident);
        return;
    }

    let mut code = code;

    if code == 0 && nan == 0 {
        code = NGX_RESOLVE_NXDOMAIN;
    }

    if code != 0 {
        let list = std::mem::take(&mut rn.borrow_mut().waiting);

        r.queue_remove(tree, &rn);

        r.tree_delete(tree, &rn);

        // unlock addr mutex

        for ctx in list {
            ctx.state.set(code);
            ctx.valid.set(now() + if r.valid != 0 { r.valid } else { 10 });

            ctx.call_handler();
        }

        return;
    }

    i += QS_LEN;

    let mut ptr: Option<(usize, i32)> = None;

    for _ in 0..nan {
        i = match skip_an_name(buf, i) {
            NameSkip::Ok(p) => p,
            NameSkip::Short => {
                ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
                return;
            }
            NameSkip::Invalid => {
                ngx_log_error!(r.log_level, r.log(), None, "invalid name in DNS response");
                return;
            }
        };

        // found:

        if i + AN_LEN >= n {
            ngx_log_error!(r.log_level, r.log(), None, "short DNS response");
            return;
        }

        let an = read_an(buf, i);

        if an.class != 1 {
            ngx_log_error!(r.log_level, r.log(), None, "unexpected RR class {} in DNS response", an.class);
            return;
        }

        let ttl = an.ttl.max(0);

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver qt:{} cl:{} len:{}", an.typ, an.class, an.len);

        i += AN_LEN;

        match an.typ {
            NGX_RESOLVE_PTR => {
                ptr = Some((i, ttl));
                break;
            }

            NGX_RESOLVE_CNAME => {}

            _ => {
                ngx_log_error!(r.log_level, r.log(), None, "unexpected RR type {} in DNS response", an.typ);
            }
        }

        i += an.len;
    }

    let (i, ttl) = match ptr {
        Some(p) => p,
        None => {
            // unlock addr mutex

            ngx_log_error!(r.log_level, r.log(), None, "no PTR type in DNS response");
            return;
        }
    };

    // ptr:

    let name = match copy_name(r, buf, i) {
        Some(name) => name,
        None => return,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolver an:{}", B(&name));

    rn.borrow_mut().name = name.clone();

    r.queue_remove(tree, &rn);

    {
        let mut node = rn.borrow_mut();
        node.valid = now() + if r.valid != 0 { r.valid } else { ttl as i64 };
        node.expire = now() + r.expire;
    }

    r.expire_queue(tree).borrow_mut().push_front(rn.clone());

    let list = std::mem::take(&mut rn.borrow_mut().waiting);

    // unlock addr mutex

    let valid = rn.borrow().valid;

    for ctx in list {
        ctx.state.set(NGX_OK);
        ctx.valid.set(valid);
        *ctx.name.borrow_mut() = name.clone();

        ctx.call_handler();
    }
}

/// The DNS query header: an ident, recursion desired, one question.
fn query_header(ident: u64) -> [u8; HDR_LEN] {
    [((ident >> 8) & 0xff) as u8, (ident & 0xff) as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// Convert "www.example.com" to "\3www\7example\3com\0"; None as
/// NGX_DECLINED.
fn encode_name(name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(name.len() + 2);

    for label in name.split(|&c| c == b'.') {
        if label.is_empty() || label.len() > 255 {
            return None;
        }

        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }

    out.push(0);

    Some(out)
}

/// ngx_resolver_create_name_query
fn create_name_query(r: &Resolver, rn: &NodeRef, name: &[u8]) -> i64 {
    let labels = match encode_name(name) {
        Some(l) => l,
        None => return NGX_DECLINED,
    };

    let mut node = rn.borrow_mut();

    let qs = |typ: u16| [0u8, typ as u8, 0, 1];

    if r.ipv4 {
        let ident = random();

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolve: \"{}\" A {}", B(name), ident & 0xffff);

        let mut q = query_header(ident).to_vec();
        q.extend_from_slice(&labels);
        q.extend_from_slice(&qs(NGX_RESOLVE_A));

        node.qlen = q.len() as u16;
        node.query = Some(q);
    } else {
        node.query = None;
    }

    if r.ipv6 {
        let ident = random();

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolve: \"{}\" AAAA {}", B(name), ident & 0xffff);

        let mut q = query_header(ident).to_vec();
        q.extend_from_slice(&labels);
        q.extend_from_slice(&qs(NGX_RESOLVE_AAAA));

        node.qlen = q.len() as u16;

        if !r.ipv4 {
            // rn->query6 = rn->query: the same buffer
            node.query = Some(q.clone());
        }

        node.query6 = Some(q);
    } else {
        node.query6 = None;
    }

    NGX_OK
}

/// ngx_resolver_create_srv_query
fn create_srv_query(r: &Resolver, rn: &NodeRef, name: &[u8]) -> i64 {
    let labels = match encode_name(name) {
        Some(l) => l,
        None => return NGX_DECLINED,
    };

    let ident = random();

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, r.log(), "resolve: \"{}\" SRV {}", B(name), ident & 0xffff);

    let mut q = query_header(ident).to_vec();
    q.extend_from_slice(&labels);
    q.extend_from_slice(&[0, NGX_RESOLVE_SRV as u8, 0, 1]);

    let mut node = rn.borrow_mut();

    node.qlen = q.len() as u16;
    node.query = Some(q);
    node.query6 = None;

    NGX_OK
}

/// ngx_resolver_create_addr_query
fn create_addr_query(rn: &NodeRef, sa: &SockAddr) {
    let ident = random();

    let mut q = query_header(ident).to_vec();

    match sa {
        SockAddr::V6(sin6) => {
            let a = sin6.ip().octets();

            for n in (0..16).rev() {
                q.extend_from_slice(format!("\x01{:x}\x01{:x}", a[n] & 0xf, (a[n] >> 4) & 0xf).as_bytes());
            }

            q.extend_from_slice(b"\x03ip6\x04arpa\x00");
        }

        _ => {
            let inaddr = match sa {
                SockAddr::V4(sin) => u32::from(*sin.ip()),
                _ => 0,
            };

            for n in (0..32).step_by(8) {
                let d = format!("{}", (inaddr >> n) & 0xff);
                q.push(d.len() as u8);
                q.extend_from_slice(d.as_bytes());
            }

            q.extend_from_slice(b"\x07in-addr\x04arpa\x00");
        }
    }

    // query type "PTR", IN query class
    q.extend_from_slice(b"\x00\x0c\x00\x01");

    let mut node = rn.borrow_mut();

    node.qlen = q.len() as u16;
    node.query = Some(q);
    node.query6 = None;
}

/// ngx_resolver_copy(r, NULL, ...): only check the name
fn check_name(r: &Resolver, buf: &[u8], src: usize) -> Option<()> {
    copy_name_inner(r, buf, src, false).map(|_| ())
}

/// ngx_resolver_copy: the name at src, lowercased, dots between labels
fn copy_name(r: &Resolver, buf: &[u8], src: usize) -> Option<Vec<u8>> {
    copy_name_inner(r, buf, src, true)
}

fn copy_name_inner(r: &Resolver, buf: &[u8], src: usize, copy: bool) -> Option<Vec<u8>> {
    let last = buf.len();

    let mut p = src;
    let mut len = 0usize;

    // compression pointers allow to create endless loop, so we set limit;
    // 128 pointers should be enough to store 255-byte name

    let mut done = false;

    for _ in 0..128 {
        let n = *buf.get(p)? as usize;
        p += 1;

        if n == 0 {
            done = true;
            break;
        }

        if n & 0xc0 != 0 {
            if n & 0xc0 != 0xc0 {
                ngx_log_error!(r.log_level, r.log(), None, "invalid label type in DNS response");
                return None;
            }

            if p >= last {
                ngx_log_error!(r.log_level, r.log(), None, "name is out of DNS response");
                return None;
            }

            p = ((n & 0x3f) << 8) + buf[p] as usize;
        } else {
            len += 1 + n;
            p += n;
        }

        if p >= last {
            ngx_log_error!(r.log_level, r.log(), None, "name is out of DNS response");
            return None;
        }
    }

    if !done {
        ngx_log_error!(r.log_level, r.log(), None, "compression pointers loop in DNS response");
        return None;
    }

    if !copy || len == 0 {
        return Some(Vec::new());
    }

    let mut dst = Vec::with_capacity(len);
    let mut src = src;

    loop {
        let n = buf[src] as usize;
        src += 1;

        if n == 0 {
            dst.pop();
            return Some(dst);
        }

        if n & 0xc0 != 0 {
            src = ((n & 0x3f) << 8) + buf[src] as usize;
        } else {
            dst.extend(buf[src..src + n].iter().map(|c| c.to_ascii_lowercase()));
            src += n;
            dst.push(b'.');
        }
    }
}

/// ngx_resolver_set_timeout
fn set_timeout(_r: &Rc<Resolver>, ctx: &Rc<ResolverCtx>) -> i64 {
    if ctx.event_set.get() || ctx.timeout.get() == 0 {
        return NGX_OK;
    }

    ctx.event_set.set(true);

    let timeout = ctx.timeout.get();
    let wctx = Rc::downgrade(ctx);

    let task = crate::event::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(timeout)).await;
        if let Some(ctx) = wctx.upgrade() {
            ctx.event.borrow_mut().take();
            timeout_handler(&ctx);
        }
    });

    *ctx.event.borrow_mut() = Some(task);

    NGX_OK
}

/// ngx_resolver_timeout_handler
fn timeout_handler(ctx: &Rc<ResolverCtx>) {
    ctx.state.set(NGX_RESOLVE_TIMEDOUT);

    ctx.call_handler();
}

/// ngx_resolver_export: the addresses of a node, rotated for a cached one
fn export(_r: &Resolver, rn: &NodeRef, rotate: bool) -> Vec<ResolverAddr> {
    let node = rn.borrow();

    let n4 = if node.naddrs == PENDING { 0 } else { node.naddrs as usize };
    let n6 = if node.naddrs6 == PENDING { 0 } else { node.naddrs6 as usize };
    let n = n4 + n6;

    let mut dst: Vec<Option<ResolverAddr>> = vec![None; n];

    let mut d = if rotate { random() as usize % n } else { 0 };

    if n4 > 0 {
        let mut j = if rotate { random() as usize % n4 } else { 0 };

        for _ in 0..n4 {
            let a = node.addrs[j];
            j += 1;

            dst[d] = Some(ResolverAddr {
                sockaddr: SockAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::from(a), 0)),
                name: Vec::new(),
                priority: 0,
                weight: 0,
            });
            d += 1;

            if d == n {
                d = 0;
            }

            if j == n4 {
                j = 0;
            }
        }
    }

    if n6 > 0 {
        let mut j = if rotate { random() as usize % n6 } else { 0 };

        for _ in 0..n6 {
            let a = node.addrs6[j];
            j += 1;

            dst[d] = Some(ResolverAddr {
                sockaddr: SockAddr::V6(std::net::SocketAddrV6::new(std::net::Ipv6Addr::from(a), 0, 0, 0)),
                name: Vec::new(),
                priority: 0,
                weight: 0,
            });
            d += 1;

            if d == n {
                d = 0;
            }

            if j == n6 {
                j = 0;
            }
        }
    }

    dst.into_iter().flatten().collect()
}

/// ngx_resolver_report_srv
fn report_srv(r: &Rc<Resolver>, ctx: &Rc<ResolverCtx>) {
    let mut addrs: Vec<ResolverAddr> = Vec::new();

    {
        let srvs = ctx.srvs.borrow();

        let mut naddrs = 0usize;

        for srv in srvs.iter() {
            if srv.state == NGX_ERROR {
                drop(srvs);

                ctx.state.set(NGX_ERROR);
                ctx.valid.set(now() + if r.valid != 0 { r.valid } else { 10 });

                ctx.call_handler();
                return;
            }

            naddrs += srv.addrs.len();
        }

        if naddrs == 0 {
            let mut state = srvs[0].state;

            for srv in srvs.iter() {
                if srv.state == NGX_RESOLVE_NXDOMAIN {
                    state = NGX_RESOLVE_NXDOMAIN;
                    break;
                }
            }

            drop(srvs);

            ctx.state.set(state);
            ctx.valid.set(now() + if r.valid != 0 { r.valid } else { 10 });

            ctx.call_handler();
            return;
        }

        let nsrvs = srvs.len();
        let mut i = 0;

        loop {
            let mut nw = 0usize;

            let mut j = i;
            while j < nsrvs {
                if srvs[j].priority != srvs[i].priority {
                    break;
                }

                nw += srvs[j].addrs.len() * srvs[j].weight as usize;
                j += 1;
            }

            if nw > 0 {
                let mut w = random() as usize % nw;

                let mut k = i;
                while k < j {
                    if w < srvs[k].addrs.len() * srvs[k].weight as usize {
                        break;
                    }

                    w -= srvs[k].addrs.len() * srvs[k].weight as usize;
                    k += 1;
                }

                for _ in i..j {
                    for a in srvs[k].addrs.iter() {
                        addrs.push(ResolverAddr {
                            sockaddr: a.clone(),
                            name: srvs[k].name.clone(),
                            priority: srvs[k].priority,
                            weight: srvs[k].weight,
                        });
                    }

                    k += 1;
                    if k == j {
                        k = i;
                    }
                }
            }

            // next_srv:

            i = j;

            if i >= nsrvs {
                break;
            }
        }
    }

    ctx.state.set(NGX_OK);
    *ctx.addrs.borrow_mut() = addrs;

    ctx.call_handler();
}

/// A lookup with its handler waking the task (ngx_resolve_start and
/// ngx_resolve_name, the handler, then ngx_resolve_name_done when dropped).
pub struct ResolveGuard {
    pub ctx: Rc<ResolverCtx>,
    addr: bool,
}

impl Drop for ResolveGuard {
    fn drop(&mut self) {
        if self.addr {
            resolve_addr_done(&self.ctx);
        } else {
            resolve_name_done(&self.ctx);
        }
    }
}

/// How an awaited lookup ended.
pub enum Resolved {
    /// NGX_NO_RESOLVER
    NoResolver,
    /// NGX_ERROR from ngx_resolve_start or ngx_resolve_name
    Error,
    /// The handler was called: ctx.state, addrs, valid, srvs.
    Done(ResolveGuard),
}

struct Waker {
    notify: tokio::sync::Notify,
    done: Cell<bool>,
}

impl Resolver {
    /// Resolve a host name, an IPv4 address being its own result
    /// (ngx_resolve_start with temp), and wait for the result.
    pub async fn resolve_host(self: &Rc<Self>, name: &[u8], timeout: u64) -> Resolved {
        self.resolve_start(Some(name), name, b"", timeout).await
    }

    /// Resolve a name (or a service of it) and wait for the result.
    pub async fn resolve(self: &Rc<Self>, name: &[u8], service: &[u8], timeout: u64) -> Resolved {
        self.resolve_start(None, name, service, timeout).await
    }

    async fn resolve_start(self: &Rc<Self>, temp: Option<&[u8]>, name: &[u8], service: &[u8], timeout: u64) -> Resolved {
        let ctx = match self.start(temp) {
            ResolveStart::NoResolver => return Resolved::NoResolver,
            ResolveStart::Ctx(ctx) => ctx,
        };

        *ctx.name.borrow_mut() = name.to_vec();
        *ctx.service.borrow_mut() = service.to_vec();
        ctx.timeout.set(timeout);

        let waker = Rc::new(Waker { notify: tokio::sync::Notify::new(), done: Cell::new(false) });
        let w = waker.clone();

        *ctx.handler.borrow_mut() = Some(Rc::new(move |_ctx: &Rc<ResolverCtx>| {
            w.done.set(true);
            w.notify.notify_one();
        }));

        let guard = ResolveGuard { ctx: ctx.clone(), addr: false };

        if resolve_name(&ctx) != NGX_OK {
            std::mem::forget(guard);
            return Resolved::Error;
        }

        while !waker.done.get() {
            waker.notify.notified().await;
        }

        Resolved::Done(guard)
    }

    /// Resolve an address to a name (PTR) and wait for the result.
    pub async fn resolve_address(self: &Rc<Self>, addr: &SockAddr, timeout: u64) -> Resolved {
        let ctx = match self.start(None) {
            ResolveStart::NoResolver => return Resolved::NoResolver,
            ResolveStart::Ctx(ctx) => ctx,
        };

        *ctx.addr.borrow_mut() = Some(addr.clone());
        ctx.timeout.set(timeout);

        let waker = Rc::new(Waker { notify: tokio::sync::Notify::new(), done: Cell::new(false) });
        let w = waker.clone();

        *ctx.handler.borrow_mut() = Some(Rc::new(move |_ctx: &Rc<ResolverCtx>| {
            w.done.set(true);
            w.notify.notify_one();
        }));

        let guard = ResolveGuard { ctx: ctx.clone(), addr: true };

        if resolve_addr(&ctx) != NGX_OK {
            std::mem::forget(guard);
            return Resolved::Error;
        }

        while !waker.done.get() {
            waker.notify.notified().await;
        }

        Resolved::Done(guard)
    }
}
