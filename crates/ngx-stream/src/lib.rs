//! ngx-stream: the stream (TCP/UDP) modules (src/stream).
//!
//! ngx_stream.c: the stream{} block, the phase engine set up, and the
//! listening sockets of the servers' addresses.

use std::any::Any;
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::*;
use ngx_core::inet::SockAddr;
use ngx_core::listening::Listening;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

pub mod core;
pub mod handler;
pub mod session;
pub mod variables;
pub mod script;
pub mod write_filter;
pub mod proxy;
pub mod upstream;
pub mod upstream_round_robin;
pub mod access;
pub mod geo;
pub mod geoip;
pub mod log;
pub mod map;
pub mod split_clients;
pub mod limit_conn;
pub mod pass;
pub mod realip;
pub mod return_module;
pub mod set;
pub mod upstream_hash;
pub mod upstream_least_conn;
pub mod upstream_least_time;
pub mod upstream_random;
pub mod upstream_zone;
pub mod ssl;
pub mod ssl_preread;

pub use session::{Session, S};

pub const NGX_STREAM_OK: i64 = 200;
pub const NGX_STREAM_BAD_REQUEST: i64 = 400;
pub const NGX_STREAM_FORBIDDEN: i64 = 403;
pub const NGX_STREAM_INTERNAL_SERVER_ERROR: i64 = 500;
pub const NGX_STREAM_BAD_GATEWAY: i64 = 502;
pub const NGX_STREAM_SERVICE_UNAVAILABLE: i64 = 503;

pub const NGX_STREAM_MAIN_CONF: u32 = 0x02000000;
pub const NGX_STREAM_SRV_CONF: u32 = 0x04000000;
pub const NGX_STREAM_UPS_CONF: u32 = 0x08000000;

pub const NGX_STREAM_POST_ACCEPT_PHASE: usize = 0;
pub const NGX_STREAM_PREACCESS_PHASE: usize = 1;
pub const NGX_STREAM_ACCESS_PHASE: usize = 2;
pub const NGX_STREAM_SSL_PHASE: usize = 3;
pub const NGX_STREAM_PREREAD_PHASE: usize = 4;
pub const NGX_STREAM_CONTENT_PHASE: usize = 5;
pub const NGX_STREAM_LOG_PHASE: usize = 6;

pub const NGX_STREAM_WRITE_BUFFERED: u32 = 0x10;

pub const NGX_LISTEN_BACKLOG: i32 = 511;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T>>>;

/// ngx_stream_handler_pt of a phase
pub type PhaseFn = Rc<dyn Fn(S) -> BoxFut<i64>>;

/// ngx_stream_content_handler_pt
pub type ContentHandler = Rc<dyn Fn(S) -> BoxFut<()>>;

/// The checker of a phase handler.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Checker {
    Generic,
    Preread,
    Content,
}

/// ngx_stream_phase_handler_t
#[derive(Clone)]
pub struct PhaseHandler {
    pub checker: Checker,
    pub handler: Option<PhaseFn>,
    pub next: usize,
}

/// Make a phase handler of an async fn.
pub fn phase_fn<F, Fut>(f: F) -> PhaseFn
where
    F: Fn(S) -> Fut + 'static,
    Fut: Future<Output = i64> + 'static,
{
    Rc::new(move |s| Box::pin(f(s)))
}

/// Make a content handler of an async fn.
pub fn content_fn<F, Fut>(f: F) -> ContentHandler
where
    F: Fn(S) -> Fut + 'static,
    Fut: Future<Output = ()> + 'static,
{
    Rc::new(move |s| Box::pin(f(s)))
}

// --- stream module definition (ngx_stream_module_t) ---

pub type StreamConfCreate = fn(&mut Conf) -> Rc<dyn Any>;
pub type StreamConfInit = fn(&mut Conf, &Rc<dyn Any>) -> ConfResult;
pub type StreamConfMerge = fn(&mut Conf, &Rc<dyn Any>, &Rc<dyn Any>) -> ConfResult;
pub type StreamConfHook = fn(&mut Conf) -> ConfResult;

#[derive(Default)]
pub struct StreamModuleDef {
    pub preconfiguration: Option<StreamConfHook>,
    pub postconfiguration: Option<StreamConfHook>,
    pub create_main_conf: Option<StreamConfCreate>,
    pub init_main_conf: Option<StreamConfInit>,
    pub create_srv_conf: Option<StreamConfCreate>,
    pub merge_srv_conf: Option<StreamConfMerge>,
}

/// Build a stream ModuleDef.
pub fn stream_module_def(name: &'static str, def: StreamModuleDef, commands: Vec<Command>) -> ModuleDef {
    let mut m = ModuleDef::new(name, NGX_STREAM_MODULE);
    m.ctx = Some(Rc::new(def));
    m.commands = commands;
    m
}

// --- per-module ctx index registry ---

thread_local! {
    static MODULE_INDEX: RefCell<std::collections::HashMap<&'static str, usize>> = RefCell::new(std::collections::HashMap::new());
    static STREAM_MAX_MODULE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// ctx_index of a stream module by name
pub fn module_index(name: &'static str) -> usize {
    MODULE_INDEX.with(|m| *m.borrow().get(name).unwrap_or_else(|| panic!("unknown stream module {}", name)))
}

/// ngx_stream_max_module
pub fn stream_max_module() -> usize {
    STREAM_MAX_MODULE.with(|m| m.get())
}

fn init_module_indexes(modules: &[Module]) {
    MODULE_INDEX.with(|m| {
        let mut m = m.borrow_mut();
        m.clear();
        for md in modules.iter().filter(|m| m.def.ty == NGX_STREAM_MODULE) {
            m.insert(md.def.name, md.ctx_index);
        }
    });
    STREAM_MAX_MODULE.with(|m| m.set(count_modules(modules, NGX_STREAM_MODULE)));
}

/// Declares a `pub fn ctx_index() -> usize` for a stream module name.
#[macro_export]
macro_rules! stream_module_index {
    ($name:expr) => {
        thread_local! {
            static CTX_INDEX: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
        }
        pub fn ctx_index() -> usize {
            CTX_INDEX.with(|c| {
                let v = c.get();
                if v != usize::MAX {
                    return v;
                }
                let i = $crate::module_index($name);
                c.set(i);
                i
            })
        }
    };
}

// --- conf ctx helpers ---

/// Get module conf from a ConfCtx level as Rc<RefCell<T>>.
pub fn get_conf<T: 'static>(ctx: &ConfCtx, level: ConfLevel, idx: usize) -> Rc<RefCell<T>> {
    conf_rc::<T>(&ctx.get(level, idx).expect("stream conf slot missing"))
}

/// ngx_stream_conf_get_module_main_conf
pub fn get_main_conf<T: 'static>(cf: &Conf, idx: usize) -> Rc<RefCell<T>> {
    get_conf::<T>(&cf.ctx, ConfLevel::Main, idx)
}

/// ngx_stream_conf_get_module_srv_conf
pub fn get_srv_conf<T: 'static>(cf: &Conf, idx: usize) -> Rc<RefCell<T>> {
    get_conf::<T>(&cf.ctx, ConfLevel::Srv, idx)
}

/// A slot of conf slots.
pub fn slot<T: 'static>(slots: &Rc<ConfSlots>, idx: usize) -> Rc<RefCell<T>> {
    conf_rc::<T>(slots.borrow()[idx].as_ref().expect("stream conf slot missing"))
}

/// ngx_stream_cycle_get_module_main_conf
/// The module's ctx_index is taken only when the block exists: the module
/// indices are set up by the block.
pub fn cycle_main_conf<T: 'static>(cycle: &ngx_core::cycle::Cycle, idx: fn() -> usize) -> Option<Rc<RefCell<T>>> {
    let m = find_module(&cycle.modules, "ngx_stream_module")?;
    let holder = cycle.conf_ctx[m.index].as_ref()?;
    let ctx = holder.downcast_ref::<ConfCtx>()?;
    Some(get_conf::<T>(ctx, ConfLevel::Main, idx()))
}

fn stream_modules(modules: &Rc<Vec<Module>>) -> Vec<(usize, &'static StreamModuleDef)> {
    let mut v = Vec::new();
    for m in modules.iter().filter(|m| m.def.ty == NGX_STREAM_MODULE) {
        if let Some(d) = m.ctx::<StreamModuleDef>() {
            // modules live for the whole process (held by the cycle)
            let d: &'static StreamModuleDef = unsafe { &*(d as *const StreamModuleDef) };
            v.push((m.ctx_index, d));
        }
    }
    v
}

/// ngx_stream_block
fn stream_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let idx = cf.module_index;
    if cf.cycle.conf_ctx[idx].is_some() {
        return Err(msg("is duplicate"));
    }

    // count the number of the stream modules and set up their indices

    let modules = cf.cycle.modules.clone();
    init_module_indexes(&modules);
    let n = stream_max_module();

    // the stream main_conf context, it's the same in the all stream contexts;
    // the stream null srv_conf context, it is used to merge the server{}s'
    // srv_conf's

    let ctx = ConfCtx { main: Some(new_slots(n)), srv: Some(new_slots(n)), loc: None };
    cf.cycle.conf_ctx[idx] = Some(Rc::new(ctx.clone()));

    let saved_ctx = std::mem::replace(&mut cf.ctx, ctx.clone());
    let saved_mt = cf.module_type;
    let saved_ct = cf.cmd_type;

    let rv = stream_block_inner(cf, &modules, &ctx);

    cf.ctx = saved_ctx;
    cf.module_type = saved_mt;
    cf.cmd_type = saved_ct;

    rv?;

    // optimize the lists of ports, addresses and server names

    let cmcf = core::main_conf_from_ctx(&ctx);
    optimize_servers(cf, &cmcf)
}

fn stream_block_inner(cf: &mut Conf, modules: &Rc<Vec<Module>>, ctx: &ConfCtx) -> ConfResult {
    let mods = stream_modules(modules);

    // create the main_conf's and the null srv_conf's of the all stream
    // modules

    for (mi, d) in mods.iter() {
        if let Some(f) = d.create_main_conf {
            let c = f(cf);
            ctx.main.as_ref().unwrap().borrow_mut()[*mi] = Some(c);
        }

        if let Some(f) = d.create_srv_conf {
            let c = f(cf);
            ctx.srv.as_ref().unwrap().borrow_mut()[*mi] = Some(c);
        }
    }

    for (_, d) in mods.iter() {
        if let Some(f) = d.preconfiguration {
            f(cf)?;
        }
    }

    // parse inside the stream{} block

    cf.module_type = NGX_STREAM_MODULE;
    cf.cmd_type = NGX_STREAM_MAIN_CONF;
    cf.parse_block()?;

    // init stream{} main_conf's, merge the server{}s' srv_conf's

    let cmcf = core::main_conf_from_ctx(ctx);
    let servers = cmcf.borrow().servers.clone();

    for (mi, d) in mods.iter() {
        cf.ctx = ctx.clone();

        if let Some(f) = d.init_main_conf {
            let c = ctx.main.as_ref().unwrap().borrow()[*mi].clone().expect("main conf");
            f(cf, &c)?;
        }

        for cscf in servers.iter() {
            // merge the server{}s' srv_conf's

            let sctx = cscf.borrow().ctx.clone();
            cf.ctx = sctx.clone();

            if let Some(f) = d.merge_srv_conf {
                let prev = ctx.srv.as_ref().unwrap().borrow()[*mi].clone().expect("srv conf");
                let conf = sctx.srv.as_ref().unwrap().borrow()[*mi].clone().expect("srv conf");
                f(cf, &prev, &conf)?;
            }
        }
    }

    cf.ctx = ctx.clone();

    init_phases(&cmcf);

    for (_, d) in mods.iter() {
        if let Some(f) = d.postconfiguration {
            f(cf)?;
        }
    }

    variables::init_vars(cf)?;

    init_phase_handlers(&cmcf);

    Ok(())
}

/// ngx_stream_init_phases
fn init_phases(cmcf: &Rc<RefCell<core::CoreMainConf>>) {
    let mut m = cmcf.borrow_mut();
    for p in m.phases.iter_mut() {
        p.clear();
    }
}

/// ngx_stream_init_phase_handlers
fn init_phase_handlers(cmcf: &Rc<RefCell<core::CoreMainConf>>) {
    let mut m = cmcf.borrow_mut();

    let mut ph: Vec<PhaseHandler> = Vec::new();
    let mut n = 0;

    for i in 0..NGX_STREAM_LOG_PHASE {
        let checker = match i {
            NGX_STREAM_PREREAD_PHASE => Checker::Preread,

            NGX_STREAM_CONTENT_PHASE => {
                ph.push(PhaseHandler { checker: Checker::Content, handler: None, next: 0 });
                n += 1;
                continue;
            }

            _ => Checker::Generic,
        };

        let h = &m.phases[i];

        n += h.len();

        for j in (0..h.len()).rev() {
            ph.push(PhaseHandler { checker, handler: Some(h[j].clone()), next: n });
        }
    }

    m.phase_engine = Rc::new(ph);
}

// --- listening sockets ---

/// ngx_stream_listen_opt_t
#[derive(Clone)]
pub struct ListenOpt {
    pub sockaddr: SockAddr,
    pub addr_text: Vec<u8>,

    pub set: bool,
    pub default_server: bool,
    pub bind: bool,
    pub wildcard: bool,
    pub ssl: bool,
    pub ipv6only: bool,
    pub deferred_accept: bool,
    pub reuseport: bool,
    pub so_keepalive: u8,
    pub proxy_protocol: bool,

    pub backlog: i32,
    pub rcvbuf: i32,
    pub sndbuf: i32,
    pub ty: i32,
    pub protocol: i32,
    pub fastopen: i32,
    pub tcp_keepidle: i32,
    pub tcp_keepintvl: i32,
    pub tcp_keepcnt: i32,
}

/// ngx_stream_server_name_t
#[derive(Clone)]
pub struct ServerName {
    pub regex: Option<Rc<variables::StreamRegex>>,
    pub server: Rc<RefCell<core::CoreSrvConf>>,
    pub name: Vec<u8>,
}

/// ngx_stream_virtual_names_t
pub struct VirtualNames {
    pub names: HashCombined<Rc<RefCell<core::CoreSrvConf>>>,
    pub regex: Vec<ServerName>,
}

/// ngx_stream_addr_conf_t
pub struct AddrConf {
    /// the default server configuration for this address:port
    pub default_server: Rc<RefCell<core::CoreSrvConf>>,
    pub virtual_names: Option<Rc<VirtualNames>>,
    pub ssl: bool,
    pub proxy_protocol: bool,
}

/// ngx_stream_port_t: the address confs of a listening socket, the
/// address bytes (in_addr / in6_addr) with its conf.
pub struct StreamPort {
    pub naddrs: usize,
    pub addrs: Vec<(Vec<u8>, Rc<AddrConf>)>,
}

/// ngx_stream_conf_port_t
pub struct ConfPort {
    pub family: i32,
    pub ty: i32,
    pub port: u16,
    pub addrs: Vec<ConfAddr>,
}

/// ngx_stream_conf_addr_t
pub struct ConfAddr {
    pub opt: ListenOpt,

    pub protocols: u32,
    pub protocols_set: bool,
    pub protocols_changed: bool,

    pub hash: Option<Hash<Rc<RefCell<core::CoreSrvConf>>>>,
    pub wc_head: Option<HashWildcard<Rc<RefCell<core::CoreSrvConf>>>>,
    pub wc_tail: Option<HashWildcard<Rc<RefCell<core::CoreSrvConf>>>>,

    pub regex: Vec<ServerName>,

    /// the default server configuration for this address:port
    pub default_server: Rc<RefCell<core::CoreSrvConf>>,
    pub servers: Vec<Rc<RefCell<core::CoreSrvConf>>>,
}

/// ngx_cmp_sockaddr(.., 0): the same address, ignoring the port
fn cmp_sockaddr_noport(a: &SockAddr, b: &SockAddr) -> bool {
    match (a, b) {
        (SockAddr::V4(x), SockAddr::V4(y)) => x.ip() == y.ip() && x.port() == y.port(),
        (SockAddr::V6(x), SockAddr::V6(y)) => x.ip() == y.ip() && x.port() == y.port(),
        (SockAddr::Unix(x), SockAddr::Unix(y)) => x == y,
        _ => false,
    }
}

/// ngx_stream_add_listen
pub fn add_listen(cf: &mut Conf, cscf: &Rc<RefCell<core::CoreSrvConf>>, lsopt: &ListenOpt) -> ConfResult {
    let cmcf = get_main_conf::<core::CoreMainConf>(cf, core::ctx_index());

    let p = lsopt.sockaddr.port();
    let family = lsopt.sockaddr.family();

    let mut ports = std::mem::take(&mut cmcf.borrow_mut().ports);

    let rc = 'done: {
        for port in ports.iter_mut() {
            if p != port.port || lsopt.ty != port.ty || family != port.family {
                continue;
            }

            // a port is already in the port list

            break 'done add_addresses(cf, cscf, port, lsopt);
        }

        // add a port to the port list

        ports.push(ConfPort { family, ty: lsopt.ty, port: p, addrs: Vec::new() });

        let port = ports.last_mut().unwrap();

        add_address(cf, cscf, port, lsopt)
    };

    cmcf.borrow_mut().ports = ports;

    rc
}

/// ngx_stream_add_addresses
fn add_addresses(cf: &mut Conf, cscf: &Rc<RefCell<core::CoreSrvConf>>, port: &mut ConfPort, lsopt: &ListenOpt) -> ConfResult {
    // we cannot compare whole sockaddr struct's as kernel may fill some
    // fields in inherited sockaddr struct's

    for i in 0..port.addrs.len() {
        if !cmp_sockaddr_noport(&lsopt.sockaddr, &port.addrs[i].opt.sockaddr) {
            continue;
        }

        // the address is already in the address list

        add_server(cf, cscf, &mut port.addrs[i])?;

        let addr = &mut port.addrs[i];

        // preserve default_server bit during listen options overwriting
        let mut default_server = addr.opt.default_server;

        let proxy_protocol = lsopt.proxy_protocol || addr.opt.proxy_protocol;
        let mut protocols = lsopt.proxy_protocol as u32;
        let mut protocols_prev = addr.opt.proxy_protocol as u32;

        let ssl = lsopt.ssl || addr.opt.ssl;
        protocols |= (lsopt.ssl as u32) << 1;
        protocols_prev |= (addr.opt.ssl as u32) << 1;

        if lsopt.set {
            if addr.opt.set {
                return Err(cf.emerg(format_args!("duplicate listen options for {}", B(&addr.opt.addr_text))));
            }

            addr.opt = lsopt.clone();
        }

        // check the duplicate "default" server for this address:port

        if lsopt.default_server {
            if default_server {
                return Err(cf.emerg(format_args!("a duplicate default server for {}", B(&addr.opt.addr_text))));
            }

            default_server = true;
            addr.default_server = cscf.clone();
        }

        // check for conflicting protocol options

        if (protocols | protocols_prev) != protocols_prev {
            // options added

            if (addr.opt.set && !lsopt.set) || addr.protocols_changed || (protocols | protocols_prev) != protocols {
                cf.warn(format_args!("protocol options redefined for {}", B(&addr.opt.addr_text)));
            }

            addr.protocols = protocols_prev;
            addr.protocols_set = true;
            addr.protocols_changed = true;
        } else if (protocols_prev | protocols) != protocols {
            // options removed

            if lsopt.set || (addr.protocols_set && protocols != addr.protocols) {
                cf.warn(format_args!("protocol options redefined for {}", B(&addr.opt.addr_text)));
            }

            addr.protocols = protocols;
            addr.protocols_set = true;
            addr.protocols_changed = true;
        } else {
            // the same options

            if (lsopt.set && addr.protocols_changed) || (addr.protocols_set && protocols != addr.protocols) {
                cf.warn(format_args!("protocol options redefined for {}", B(&addr.opt.addr_text)));
            }

            addr.protocols = protocols;
            addr.protocols_set = true;
        }

        addr.opt.default_server = default_server;
        addr.opt.proxy_protocol = proxy_protocol;
        addr.opt.ssl = ssl;

        return Ok(());
    }

    // add the address to the addresses list that bound to this port

    add_address(cf, cscf, port, lsopt)
}

/// ngx_stream_add_address: the server address, the server names and the
/// server core module configurations to the port list
fn add_address(cf: &mut Conf, cscf: &Rc<RefCell<core::CoreSrvConf>>, port: &mut ConfPort, lsopt: &ListenOpt) -> ConfResult {
    port.addrs.push(ConfAddr {
        opt: lsopt.clone(),
        protocols: 0,
        protocols_set: false,
        protocols_changed: false,
        hash: None,
        wc_head: None,
        wc_tail: None,
        regex: Vec::new(),
        default_server: cscf.clone(),
        servers: Vec::new(),
    });

    let addr = port.addrs.last_mut().unwrap();

    add_server(cf, cscf, addr)
}

/// ngx_stream_add_server: the server core module configuration to the
/// address:port
fn add_server(cf: &mut Conf, cscf: &Rc<RefCell<core::CoreSrvConf>>, addr: &mut ConfAddr) -> ConfResult {
    for s in addr.servers.iter() {
        if Rc::ptr_eq(s, cscf) {
            return Err(cf.emerg(format_args!("a duplicate listen {}", B(&addr.opt.addr_text))));
        }
    }

    addr.servers.push(cscf.clone());

    Ok(())
}

/// ngx_stream_cmp_conf_addrs
fn cmp_conf_addrs(first: &ConfAddr, second: &ConfAddr) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    if first.opt.wildcard {
        // a wildcard address must be the last resort, shift it to the end
        return Ordering::Greater;
    }

    if second.opt.wildcard {
        // a wildcard address must be the last resort, shift it to the end
        return Ordering::Less;
    }

    if first.opt.bind && !second.opt.bind {
        // shift explicit bind()ed addresses to the start
        return Ordering::Less;
    }

    if !first.opt.bind && second.opt.bind {
        // shift explicit bind()ed addresses to the start
        return Ordering::Greater;
    }

    // do not sort by default

    Ordering::Equal
}

/// ngx_sort: an insertion sort (stable) with the C comparison.
fn insertion_sort(addrs: &mut [ConfAddr]) {
    for i in 1..addrs.len() {
        let mut j = i;
        while j > 0 && cmp_conf_addrs(&addrs[j - 1], &addrs[j]) == std::cmp::Ordering::Greater {
            addrs.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// ngx_stream_optimize_servers
fn optimize_servers(cf: &mut Conf, cmcf: &Rc<RefCell<core::CoreMainConf>>) -> ConfResult {
    let mut ports = std::mem::take(&mut cmcf.borrow_mut().ports);

    for port in ports.iter_mut() {
        insertion_sort(&mut port.addrs);

        // check whether all name-based servers have the same configuration
        // as a default server for given address:port

        for a in 0..port.addrs.len() {
            let need = port.addrs[a].servers.len() > 1 || port.addrs[a].default_server.borrow().captures;

            if need {
                server_names(cf, cmcf, &mut port.addrs[a])?;
            }
        }

        init_listening(cf, port)?;
    }

    Ok(())
}

/// ngx_stream_server_names
fn server_names(cf: &Conf, cmcf: &Rc<RefCell<core::CoreMainConf>>, addr: &mut ConfAddr) -> ConfResult {
    let mut ha: HashKeysArrays<Rc<RefCell<core::CoreSrvConf>>> = HashKeysArrays::new(HashKind::Large);
    let mut regex: Vec<ServerName> = Vec::new();

    for cscf in addr.servers.iter() {
        let c = cscf.borrow();

        for name in c.server_names.iter() {
            if name.regex.is_some() {
                regex.push(name.clone());
                continue;
            }

            let rc = ha.add_key(name.name.clone(), name.server.clone(), NGX_HASH_WILDCARD_KEY);

            if rc == NGX_ERROR {
                return Err(ConfError::Logged);
            }

            if rc == NGX_DECLINED {
                ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "invalid server name or wildcard \"{}\" on {}", B(&name.name), B(&addr.opt.addr_text));
                return Err(ConfError::Logged);
            }

            if rc == NGX_BUSY {
                ngx_log_error!(NGX_LOG_WARN, cf.log, None, "conflicting server name \"{}\" on {}, ignored", B(&name.name), B(&addr.opt.addr_text));
            }
        }
    }

    let (max_size, bucket_size) = {
        let m = cmcf.borrow();
        (*m.server_names_hash_max_size as usize, *m.server_names_hash_bucket_size as usize)
    };

    let hinit = HashInit { name: "server_names_hash", max_size, bucket_size, log: &cf.log };

    let fail = |e: String| {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
        ConfError::Logged
    };

    if !ha.keys().is_empty() {
        let keys: Vec<HashKey<Rc<RefCell<core::CoreSrvConf>>>> = ha.keys().iter().map(|k| HashKey { key: k.key.clone(), key_hash: k.key_hash, value: k.value.clone() }).collect();
        addr.hash = Some(Hash::init(&hinit, keys).map_err(fail)?);
    }

    if !ha.dns_wc_head().is_empty() {
        let mut keys: Vec<HashKey<Rc<RefCell<core::CoreSrvConf>>>> = ha.dns_wc_head().iter().map(|k| HashKey { key: k.key.clone(), key_hash: k.key_hash, value: k.value.clone() }).collect();
        keys.sort_by(|a, b| ngx_core::string::dns_strcmp(&a.key, &b.key).cmp(&0));
        addr.wc_head = Some(HashWildcard::init(&hinit, keys).map_err(fail)?);
    }

    if !ha.dns_wc_tail().is_empty() {
        let mut keys: Vec<HashKey<Rc<RefCell<core::CoreSrvConf>>>> = ha.dns_wc_tail().iter().map(|k| HashKey { key: k.key.clone(), key_hash: k.key_hash, value: k.value.clone() }).collect();
        keys.sort_by(|a, b| ngx_core::string::dns_strcmp(&a.key, &b.key).cmp(&0));
        addr.wc_tail = Some(HashWildcard::init(&hinit, keys).map_err(fail)?);
    }

    addr.regex = regex;

    Ok(())
}

/// ngx_stream_init_listening
fn init_listening(cf: &mut Conf, port: &mut ConfPort) -> ConfResult {
    let mut last = port.addrs.len();

    // If there is a binding to an "*:port" then we need to bind() to the
    // "*:port" only and ignore other implicit bindings. The bindings have
    // been already sorted: explicit bindings are on the start, then implicit
    // bindings go, and wildcard binding is in the end.

    let bind_wildcard = if port.addrs[last - 1].opt.wildcard {
        port.addrs[last - 1].opt.bind = true;
        true
    } else {
        false
    };

    let mut start = 0;
    let mut i = 0;

    while i < last {
        if bind_wildcard && !port.addrs[start + i].opt.bind {
            i += 1;
            continue;
        }

        let ls = add_listening(cf, &port.addrs[start + i]);

        let naddrs = i + 1;

        let mut addrs = Vec::with_capacity(naddrs);

        for a in port.addrs[start..start + naddrs].iter_mut() {
            let vn = if a.hash.is_some() || a.wc_head.is_some() || a.wc_tail.is_some() || !a.regex.is_empty() {
                let hash = match a.hash.take() {
                    Some(h) => h,
                    None => Hash::init(&HashInit { name: "server_names_hash", max_size: 1, bucket_size: 64, log: &cf.log }, Vec::new()).map_err(|e| {
                        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
                        ConfError::Logged
                    })?,
                };

                Some(Rc::new(VirtualNames { names: HashCombined { hash, wc_head: a.wc_head.take(), wc_tail: a.wc_tail.take() }, regex: a.regex.clone() }))
            } else {
                None
            };

            let conf = Rc::new(AddrConf { default_server: a.default_server.clone(), virtual_names: vn, ssl: a.opt.ssl, proxy_protocol: a.opt.proxy_protocol });

            addrs.push((a.opt.sockaddr.ip_bytes(), conf));
        }

        let stport: Rc<dyn Any> = Rc::new(StreamPort { naddrs, addrs });

        *ls.servers.borrow_mut() = Some(stport);

        cf.cycle.listening.push(ls);

        start += 1;
        last -= 1;
    }

    Ok(())
}

/// ngx_stream_add_listening
fn add_listening(cf: &mut Conf, addr: &ConfAddr) -> Rc<Listening> {
    let mut ls = Listening::new(addr.opt.sockaddr.clone(), cf.log.clone());

    ls.addr_ntop.set(true);

    let handler: ngx_core::connection::ListenHandler = Rc::new(handler::init_connection);
    *ls.handler.borrow_mut() = Some(handler);

    ls.pool_size.set(256);

    let cscf = addr.default_server.clone();

    let chain = cscf.borrow().error_log.clone().unwrap_or_else(|| cf.cycle.new_log.clone());
    *ls.log.borrow_mut() = Log::new(chain);

    ls.ty = addr.opt.ty;
    *ls.protocol.borrow_mut() = "stream";
    ls.backlog.set(addr.opt.backlog);
    ls.rcvbuf.set(addr.opt.rcvbuf);
    ls.sndbuf.set(addr.opt.sndbuf);

    ls.keepalive.set(addr.opt.so_keepalive);
    ls.keepidle.set(addr.opt.tcp_keepidle);
    ls.keepintvl.set(addr.opt.tcp_keepintvl);
    ls.keepcnt.set(addr.opt.tcp_keepcnt);

    ls.deferred_accept.set(addr.opt.deferred_accept);
    ls.ipv6only.set(addr.opt.ipv6only);
    ls.fastopen.set(addr.opt.fastopen);
    ls.reuseport.set(addr.opt.reuseport);

    ls.wildcard.set(addr.opt.wildcard);

    Rc::new(ls)
}

/// ngx_stream_module: the stream{} block
pub fn stream_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_stream_module", NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: "stream", create_conf: None, init_conf: None }));
    m.commands = vec![cmd_fn!("stream", NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS, ConfLevel::None, stream_block)];
    m
}

/// The stream modules, in the order of objs/ngx_modules.c.
pub fn modules() -> Vec<ModuleDef> {
    vec![
        stream_module(),
        core::core_module(),
        log::log_module(),
        proxy::proxy_module(),
        upstream::upstream_module(),
        write_filter::write_filter_module(),
        ssl::ssl_module(),
        realip::realip_module(),
        limit_conn::limit_conn_module(),
        access::access_module(),
        geo::geo_module(),
        geoip::geoip_module(),
        map::map_module(),
        split_clients::split_clients_module(),
        return_module::return_module(),
        pass::pass_module(),
        set::set_module(),
        upstream_hash::upstream_hash_module(),
        upstream_least_conn::upstream_least_conn_module(),
        upstream_least_time::upstream_least_time_module(),
        upstream_random::upstream_random_module(),
        upstream_zone::upstream_zone_module(),
        ssl_preread::ssl_preread_module(),
    ]
}

pub fn _unused(_: &dyn Any) {}
