//! ngx_stream_upstream.c: the upstream{} blocks, the servers, the
//! upstream variables; the peer connection a balancer works on
//! (ngx_peer_connection_t) and the session's upstream
//! (ngx_stream_upstream_t).

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::event_connect::LocalAddr;
use ngx_core::inet::{Addr, SockAddr, Url};
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::resolver::Resolver;
use ngx_core::shm::ShmZone;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::upstream_round_robin::{Arena, RrPeers};
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_upstream_module");

pub const NGX_STREAM_UPSTREAM_CREATE: u32 = 0x0001;
pub const NGX_STREAM_UPSTREAM_WEIGHT: u32 = 0x0002;
pub const NGX_STREAM_UPSTREAM_MAX_FAILS: u32 = 0x0004;
pub const NGX_STREAM_UPSTREAM_FAIL_TIMEOUT: u32 = 0x0008;
pub const NGX_STREAM_UPSTREAM_DOWN: u32 = 0x0010;
pub const NGX_STREAM_UPSTREAM_BACKUP: u32 = 0x0020;
pub const NGX_STREAM_UPSTREAM_MODIFY: u32 = 0x0040;
pub const NGX_STREAM_UPSTREAM_MAX_CONNS: u32 = 0x0100;

pub const NGX_STREAM_UPSTREAM_NOTIFY_CONNECT: u32 = 0x1;
pub const NGX_STREAM_UPSTREAM_NOTIFY_FIRST_BYTE: u32 = 0x2;

/// ngx_event_connect.h
pub const NGX_PEER_KEEPALIVE: u32 = 1;
pub const NGX_PEER_NEXT: u32 = 2;
pub const NGX_PEER_FAILED: u32 = 4;

/// ngx_stream_upstream_server_t
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
    /// 0 or NGX_STREAM_UPSTREAM_FAILED ("down")
    pub down: u32,
    pub backup: bool,
    /// resolve at run time (zone)
    pub host: Vec<u8>,
    pub service: Vec<u8>,
}

/// Initializes the peers of an upstream at configuration time
/// (peer.init_upstream).
pub type InitUpstream = fn(&mut Conf, &Rc<UpstreamSrvConf>) -> ConfResult;

/// Initializes the balancer for a session (peer.init).
pub type InitPeer = Rc<dyn Fn(&S, &Rc<UpstreamSrvConf>) -> Result<Box<dyn PeerBalancer>, ()>>;

/// ngx_stream_upstream_srv_conf_t
pub struct UpstreamSrvConf {
    pub host: Vec<u8>,
    pub file_name: Vec<u8>,
    pub line: usize,
    pub port: u16,
    pub no_port: bool,
    pub flags: Cell<u32>,
    /// None for an implicit upstream of a name (resolved at init)
    pub servers: RefCell<Option<Vec<UpstreamServer>>>,
    /// the srv_conf of the upstream{} block: the confs of the balancer
    /// modules (None for an implicit upstream)
    pub srv_conf: RefCell<Option<Rc<ConfSlots>>>,

    pub init_upstream: Cell<Option<InitUpstream>>,
    pub init: RefCell<Option<InitPeer>>,
    /// us->peer.data of the round-robin based balancers
    pub peers: Cell<*mut RrPeers>,
    /// the memory of the peers (cf->pool)
    pub arena: Arena,

    pub shm_zone: RefCell<Option<Rc<ShmZone>>>,
    pub resolver: RefCell<Option<Rc<Resolver>>>,
    /// msec; None until merged (NGX_CONF_UNSET_MSEC)
    pub resolver_timeout: Cell<Option<u64>>,
}

impl UpstreamSrvConf {
    fn new(host: &[u8], port: u16, no_port: bool, flags: u32, file_name: Vec<u8>, line: usize) -> UpstreamSrvConf {
        UpstreamSrvConf {
            host: host.to_vec(),
            file_name,
            line,
            port,
            no_port,
            flags: Cell::new(flags),
            servers: RefCell::new(None),
            srv_conf: RefCell::new(None),
            init_upstream: Cell::new(None),
            init: RefCell::new(None),
            peers: Cell::new(std::ptr::null_mut()),
            arena: Default::default(),
            shm_zone: RefCell::new(None),
            resolver: RefCell::new(None),
            resolver_timeout: Cell::new(None),
        }
    }

    /// ngx_stream_conf_upstream_srv_conf(uscf, module)
    pub fn module_srv_conf<T: 'static>(&self, idx: usize) -> Option<Rc<RefCell<T>>> {
        let slots = self.srv_conf.borrow().clone()?;
        let c = slots.borrow().get(idx).cloned().flatten()?;
        c.downcast::<RefCell<T>>().ok()
    }

    /// The per-session balancer (uscf->peer.init).
    pub fn init_peer(self: &Rc<Self>, s: &S) -> Result<Box<dyn PeerBalancer>, ()> {
        let init = match self.init.borrow().clone() {
            Some(f) => f,
            None => return Err(()),
        };
        init(s, self)
    }
}

/// ngx_stream_upstream_main_conf_t
pub struct UpstreamMainConf {
    pub upstreams: Vec<Rc<UpstreamSrvConf>>,
}

fn upstream_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(UpstreamMainConf { upstreams: Vec::new() })
}

pub fn main_conf(cf: &Conf) -> Rc<RefCell<UpstreamMainConf>> {
    get_main_conf::<UpstreamMainConf>(cf, ctx_index())
}

/// The upstream{} block whose directives are being parsed
/// (ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_upstream_module)).
pub fn conf_upstream(cf: &Conf) -> Option<Rc<UpstreamSrvConf>> {
    let slot = cf.ctx.get(ConfLevel::Srv, ctx_index())?;
    let c = slot.downcast::<RefCell<Rc<UpstreamSrvConf>>>().ok()?;
    let u = c.borrow().clone();
    Some(u)
}

fn uscf_of(conf: &Option<Rc<dyn Any>>) -> Rc<UpstreamSrvConf> {
    conf_rc::<Rc<UpstreamSrvConf>>(conf.as_ref().expect("upstream conf")).borrow().clone()
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

/// ngx_stream_upstream_init_main_conf
fn upstream_init_main_conf(cf: &mut Conf, conf: &Rc<dyn Any>) -> ConfResult {
    let upstreams = conf_cell::<UpstreamMainConf>(conf).borrow().upstreams.clone();

    for uscf in upstreams.iter() {
        let init = uscf.init_upstream.get().unwrap_or(crate::upstream_round_robin::init_round_robin);

        init(cf, uscf)?;
    }

    Ok(())
}

/// ngx_stream_upstream: the upstream{} block
fn upstream_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let mut u = Url::default();
    u.host = cf.args[1].clone();
    u.no_resolve = true;
    u.no_port = true;

    let uscf = upstream_add(
        cf,
        &mut u,
        NGX_STREAM_UPSTREAM_CREATE
            | NGX_STREAM_UPSTREAM_MODIFY
            | NGX_STREAM_UPSTREAM_WEIGHT
            | NGX_STREAM_UPSTREAM_MAX_CONNS
            | NGX_STREAM_UPSTREAM_MAX_FAILS
            | NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
            | NGX_STREAM_UPSTREAM_DOWN
            | NGX_STREAM_UPSTREAM_BACKUP,
    )?;

    let n = stream_max_module();

    let stream_ctx = cf.ctx.clone();
    let ctx = ConfCtx { main: stream_ctx.main.clone(), srv: Some(new_slots(n)), loc: None };

    // the upstream{}'s srv_conf

    let srv = ctx.srv.clone().unwrap();

    srv.borrow_mut()[ctx_index()] = Some(make_slot(uscf.clone()));

    *uscf.srv_conf.borrow_mut() = Some(srv.clone());

    let modules = cf.cycle.modules.clone();

    for m in modules.iter().filter(|m| m.def.ty == NGX_STREAM_MODULE) {
        if let Some(d) = m.ctx::<StreamModuleDef>() {
            if let Some(f) = d.create_srv_conf {
                let c = f(cf);
                srv.borrow_mut()[m.ctx_index] = Some(c);
            }
        }
    }

    *uscf.servers.borrow_mut() = Some(Vec::new());

    // parse inside upstream{}

    let saved_ctx = std::mem::replace(&mut cf.ctx, ctx);
    let saved_ct = cf.cmd_type;
    cf.cmd_type = NGX_STREAM_UPS_CONF;

    let rv = cf.parse_block();

    cf.ctx = saved_ctx;
    cf.cmd_type = saved_ct;

    rv?;

    if uscf.servers.borrow().as_ref().is_none_or(|s| s.is_empty()) {
        return Err(cf.emerg(format_args!("no servers are inside upstream")));
    }

    Ok(())
}

/// ngx_stream_upstream_server
fn upstream_server(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = uscf_of(&conf);

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
            if flags & NGX_STREAM_UPSTREAM_WEIGHT == 0 {
                return Err(not_supported(cf, v));
            }

            weight = match ngx_core::string::atoi(n) {
                Some(w) if w > 0 => w as u32,
                _ => return Err(invalid(cf, v)),
            };

            continue;
        }

        if let Some(n) = v.strip_prefix(b"max_conns=") {
            if flags & NGX_STREAM_UPSTREAM_MAX_CONNS == 0 {
                return Err(not_supported(cf, v));
            }

            max_conns = match ngx_core::string::atoi(n) {
                Some(m) => m as u32,
                None => return Err(invalid(cf, v)),
            };

            continue;
        }

        if let Some(n) = v.strip_prefix(b"max_fails=") {
            if flags & NGX_STREAM_UPSTREAM_MAX_FAILS == 0 {
                return Err(not_supported(cf, v));
            }

            max_fails = match ngx_core::string::atoi(n) {
                Some(m) => m as u32,
                None => return Err(invalid(cf, v)),
            };

            continue;
        }

        if let Some(s) = v.strip_prefix(b"fail_timeout=") {
            if flags & NGX_STREAM_UPSTREAM_FAIL_TIMEOUT == 0 {
                return Err(not_supported(cf, v));
            }

            fail_timeout = match ngx_core::parse::parse_time(s, true) {
                Some(t) => t,
                None => return Err(invalid(cf, v)),
            };

            continue;
        }

        if v.as_slice() == b"backup" {
            if flags & NGX_STREAM_UPSTREAM_BACKUP == 0 {
                return Err(not_supported(cf, v));
            }

            us.backup = true;

            continue;
        }

        if v.as_slice() == b"down" {
            if flags & NGX_STREAM_UPSTREAM_DOWN == 0 {
                return Err(not_supported(cf, v));
            }

            us.down = crate::upstream_round_robin::NGX_STREAM_UPSTREAM_FAILED as u32;

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

    if u.no_port && us.service.is_empty() {
        return Err(cf.emerg(format_args!("no port in upstream \"{}\"", B(&u.url))));
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

        let sa = SockAddr::v4(std::net::Ipv4Addr::UNSPECIFIED, u.port);

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

/// ngx_stream_upstream_resolver
fn upstream_resolver(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = uscf_of(&conf);

    if uscf.resolver.borrow().is_some() {
        return Err(msg("is duplicate"));
    }

    let args = cf.args[1..].to_vec();

    let r = Resolver::create(cf, &args)?;

    *uscf.resolver.borrow_mut() = Some(r);

    Ok(())
}

/// resolver_timeout in upstream{} (ngx_conf_set_msec_slot)
fn upstream_resolver_timeout(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = uscf_of(&conf);

    if uscf.resolver_timeout.get().is_some() {
        return Err(msg("is duplicate"));
    }

    match ngx_core::parse::parse_time(&cf.args[1], false) {
        Some(t) => uscf.resolver_timeout.set(Some(t as u64)),
        None => return Err(msg("invalid value")),
    }

    Ok(())
}

/// ngx_stream_upstream_add
pub fn upstream_add(cf: &mut Conf, u: &mut Url, flags: u32) -> Result<Rc<UpstreamSrvConf>, ConfError> {
    if flags & NGX_STREAM_UPSTREAM_CREATE == 0 && ngx_core::inet::parse_url(u).is_err() {
        if let Some(err) = u.err {
            return Err(cf.emerg(format_args!("{} in upstream \"{}\"", err, B(&u.url))));
        }

        return Err(ConfError::Logged);
    }

    let umcf = main_conf(cf);
    let upstreams = umcf.borrow().upstreams.clone();

    for uscf in upstreams.iter() {
        if !uscf.host.eq_ignore_ascii_case(&u.host) {
            continue;
        }

        if flags & NGX_STREAM_UPSTREAM_CREATE != 0 && uscf.flags.get() & NGX_STREAM_UPSTREAM_CREATE != 0 {
            return Err(cf.emerg(format_args!("duplicate upstream \"{}\"", B(&u.host))));
        }

        if uscf.flags.get() & NGX_STREAM_UPSTREAM_CREATE != 0 && !u.no_port {
            return Err(cf.emerg(format_args!("upstream \"{}\" may not have port {}", B(&u.host), u.port)));
        }

        if flags & NGX_STREAM_UPSTREAM_CREATE != 0 && !uscf.no_port {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "upstream \"{}\" may not have port {} in {}:{}", B(&u.host), uscf.port, B(&uscf.file_name), uscf.line);
            return Err(ConfError::Logged);
        }

        if uscf.port != u.port {
            continue;
        }

        if flags & NGX_STREAM_UPSTREAM_CREATE != 0 {
            uscf.flags.set(flags);
        }

        return Ok(uscf.clone());
    }

    let uscf = Rc::new(UpstreamSrvConf::new(&u.host, u.port, u.no_port, flags, cf.conf_file_name(), cf.conf_line()));

    if u.addrs.len() == 1 && (u.port != 0 || u.family == libc::AF_UNIX) {
        let us = UpstreamServer { addrs: vec![u.addrs[0].clone()], ..Default::default() };
        *uscf.servers.borrow_mut() = Some(vec![us]);
    }

    umcf.borrow_mut().upstreams.push(uscf.clone());

    Ok(uscf)
}

// --- variables ---

fn states_empty(s: &Session, v: &mut VariableValue) -> bool {
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    if s.upstream_states.borrow().is_empty() {
        v.not_found = true;
        return true;
    }

    false
}

/// ngx_stream_upstream_addr_variable
fn upstream_addr_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    if states_empty(s, v) {
        return NGX_OK;
    }

    let states = s.upstream_states.borrow();

    let mut p = Vec::new();

    for (i, state) in states.iter().enumerate() {
        if let Some(peer) = &state.peer {
            p.extend_from_slice(peer);
        }

        if i + 1 < states.len() {
            p.extend_from_slice(b", ");
        }
    }

    v.data = p;

    NGX_OK
}

/// ngx_stream_upstream_bytes_variable
fn upstream_bytes_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    if states_empty(s, v) {
        return NGX_OK;
    }

    let states = s.upstream_states.borrow();

    let mut p = Vec::new();

    for (i, state) in states.iter().enumerate() {
        let n = if data == 1 { state.bytes_received } else { state.bytes_sent };

        p.extend_from_slice(n.to_string().as_bytes());

        if i + 1 < states.len() {
            p.extend_from_slice(b", ");
        }
    }

    v.data = p;

    NGX_OK
}

/// ngx_stream_upstream_response_time_variable
fn upstream_response_time_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    if states_empty(s, v) {
        return NGX_OK;
    }

    let states = s.upstream_states.borrow();

    let mut p = Vec::new();

    for (i, state) in states.iter().enumerate() {
        let ms = if data == 1 {
            state.first_byte_time
        } else if data == 2 {
            state.connect_time
        } else {
            state.response_time
        };

        if ms != -1 {
            let ms = ms.max(0);
            p.extend_from_slice(format!("{}.{:03}", ms / 1000, ms % 1000).as_bytes());
        } else {
            p.push(b'-');
        }

        if i + 1 < states.len() {
            p.extend_from_slice(b", ");
        }
    }

    v.data = p;

    NGX_OK
}

static UPSTREAM_VARS: &[VarDef] = &[
    VarDef { name: "upstream_addr", set: None, get: Some(upstream_addr_variable), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "upstream_bytes_sent", set: None, get: Some(upstream_bytes_variable), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "upstream_connect_time", set: None, get: Some(upstream_response_time_variable), data: 2, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "upstream_first_byte_time", set: None, get: Some(upstream_response_time_variable), data: 1, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "upstream_session_time", set: None, get: Some(upstream_response_time_variable), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE },
    VarDef { name: "upstream_bytes_received", set: None, get: Some(upstream_bytes_variable), data: 1, flags: NGX_STREAM_VAR_NOCACHEABLE },
];

/// ngx_stream_upstream_add_variables
fn upstream_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, UPSTREAM_VARS)
}

pub fn upstream_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_upstream_module",
        StreamModuleDef {
            preconfiguration: Some(upstream_add_variables),
            create_main_conf: Some(upstream_create_main_conf),
            init_main_conf: Some(upstream_init_main_conf),
            ..Default::default()
        },
        vec![
            cmd_fn!("upstream", NGX_STREAM_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1, ConfLevel::None, upstream_block),
            cmd_fn!("server", NGX_STREAM_UPS_CONF | NGX_CONF_1MORE, ConfLevel::Srv, upstream_server),
            cmd_fn!("resolver", NGX_STREAM_UPS_CONF | NGX_CONF_1MORE, ConfLevel::Srv, upstream_resolver),
            cmd_fn!("resolver_timeout", NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, upstream_resolver_timeout),
        ],
    )
}

// --- the peer connection and the session's upstream ---

/// ngx_peer_connection_t: the balancer's view of an upstream connection.
pub struct PeerConnection {
    pub sockaddr: Option<SockAddr>,
    /// pc->name: the chosen peer, or the upstream when none is available
    pub name: Option<Vec<u8>>,
    pub tries: u32,
    pub start_time: u64,
    pub log: Log,
    pub log_error: u32,
    /// pc->type: SOCK_STREAM or SOCK_DGRAM
    pub ty: i32,
    pub local: Option<LocalAddr>,
    pub transparent: bool,
    pub so_keepalive: bool,
    pub rcvbuf: i32,
    pub sndbuf: i32,
}

/// A balancer's per-session state (peer.data with peer.get / peer.free
/// / peer.notify / peer.set_session / peer.save_session).
pub trait PeerBalancer {
    /// peer.tries after peer.init
    fn tries(&self) -> u32;

    /// NGX_OK with pc.sockaddr and pc.name set, NGX_BUSY when no peer is
    /// available (pc.name is the upstream's).
    fn get(&mut self, pc: &mut PeerConnection) -> i64;

    fn free(&mut self, pc: &mut PeerConnection, state: u32);

    /// `ty` is the type of the connection to the peer
    fn notify(&mut self, _pc: &mut PeerConnection, _ty: i32, _notify: u32) {}

    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        None
    }

    fn save_session(&mut self, _session: openssl::ssl::SslSession) {}
}

/// ngx_stream_upstream_state_t; the times are -1 when unknown
#[derive(Clone, Debug)]
pub struct UpstreamState {
    pub response_time: i64,
    pub connect_time: i64,
    pub first_byte_time: i64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub peer: Option<Vec<u8>>,
}

impl Default for UpstreamState {
    fn default() -> UpstreamState {
        UpstreamState { response_time: -1, connect_time: -1, first_byte_time: -1, bytes_sent: 0, bytes_received: 0, peer: None }
    }
}

/// ngx_stream_upstream_resolved_t
#[derive(Clone, Default)]
pub struct UpstreamResolved {
    pub host: Vec<u8>,
    pub port: u16,
    pub no_port: bool,
    /// an address given in proxy_pass itself
    pub sockaddr: Option<SockAddr>,
    pub name: Vec<u8>,
}

/// ngx_stream_upstream_t
pub struct StreamUpstream {
    pub peer: RefCell<PeerConnection>,
    pub balancer: RefCell<Option<Box<dyn PeerBalancer>>>,
    /// u->peer.connection
    pub connection: RefCell<Option<Rc<Connection>>>,
    /// u->peer.name, for the log handler (the peer is borrowed while the
    /// balancer logs)
    pub name: RefCell<Option<Vec<u8>>>,

    pub received: Cell<i64>,
    pub start_sec: Cell<i64>,
    pub requests: Cell<usize>,
    pub responses: Cell<usize>,
    pub start_time: Cell<u64>,

    pub upload_rate: Cell<usize>,
    pub download_rate: Cell<usize>,

    pub ssl_name: RefCell<Vec<u8>>,

    pub upstream: RefCell<Option<Rc<UpstreamSrvConf>>>,
    pub resolved: RefCell<Option<UpstreamResolved>>,
    /// the index of the current state in s.upstream_states
    pub state: Cell<Option<usize>>,

    pub connected: Cell<bool>,
    pub proxy_protocol: Cell<u32>,
    pub half_closed: Cell<bool>,
}

impl StreamUpstream {
    pub fn new(log: &Log) -> StreamUpstream {
        StreamUpstream {
            peer: RefCell::new(PeerConnection {
                sockaddr: None,
                name: None,
                tries: 0,
                start_time: 0,
                log: log.clone(),
                log_error: ngx_core::connection::NGX_ERROR_ERR,
                ty: libc::SOCK_STREAM,
                local: None,
                transparent: false,
                so_keepalive: false,
                rcvbuf: 0,
                sndbuf: 0,
            }),
            balancer: RefCell::new(None),
            connection: RefCell::new(None),
            name: RefCell::new(None),
            received: Cell::new(0),
            start_sec: Cell::new(0),
            requests: Cell::new(0),
            responses: Cell::new(0),
            start_time: Cell::new(0),
            upload_rate: Cell::new(0),
            download_rate: Cell::new(0),
            ssl_name: RefCell::new(Vec::new()),
            upstream: RefCell::new(None),
            resolved: RefCell::new(None),
            state: Cell::new(None),
            connected: Cell::new(false),
            proxy_protocol: Cell::new(0),
            half_closed: Cell::new(false),
        }
    }

    /// pc->get: the balancer chooses a peer
    pub fn peer_get(&self) -> i64 {
        let mut balancer = self.balancer.borrow_mut();
        let b = match balancer.as_mut() {
            Some(b) => b,
            None => return NGX_ERROR,
        };

        let mut pc = self.peer.borrow_mut();
        let rc = b.get(&mut pc);

        *self.name.borrow_mut() = pc.name.clone();

        rc
    }

    /// pc->free
    pub fn peer_free(&self, state: u32) {
        let mut balancer = self.balancer.borrow_mut();

        if let Some(b) = balancer.as_mut() {
            let mut pc = self.peer.borrow_mut();
            b.free(&mut pc, state);
        }
    }

    /// pc->notify
    pub fn peer_notify(&self, ty: i32, notify: u32) {
        let mut balancer = self.balancer.borrow_mut();

        if let Some(b) = balancer.as_mut() {
            let mut pc = self.peer.borrow_mut();
            b.notify(&mut pc, ty, notify);
        }
    }

    /// The current state (u->state).
    pub fn with_state<R>(&self, s: &Session, f: impl FnOnce(&mut UpstreamState) -> R) -> Option<R> {
        let i = self.state.get()?;
        let mut states = s.upstream_states.borrow_mut();
        states.get_mut(i).map(f)
    }
}
