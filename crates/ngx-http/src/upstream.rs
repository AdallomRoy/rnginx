//! HTTP Upstream Framework (ngx_http_upstream.{c,h})
//!
//! Implements peer selection, connection pooling, request forwarding, and response
//! processing for reverse proxy, fastcgi, uwsgi, scgi, grpc, memcached, etc.

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::Chain;
use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::cmd_fn;
use ngx_core::conf::{NGX_CONF_BLOCK, NGX_CONF_TAKE1, NGX_CONF_1MORE};

use crate::core::*;
use crate::request::*;
use crate::variables::{GetHandler, SetHandler, VarDef, NGX_HTTP_VAR_PREFIX, NGX_HTTP_VAR_NOCACHEABLE, prefix_var_name};
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

// ============================================================================
// PEER SELECTION TRAITS
// ============================================================================

/// Peer statistics for variables.
#[derive(Clone, Debug, Default)]
pub struct PeerStats {
    pub conns: u32,
    pub fails: u32,
    pub effective_weight: u32,
    pub current_weight: u32,
    pub total_weight: u32,
}

/// Trait for a peer (backend server) in an upstream.
/// Implementors handle connection pooling and load-balancer state per-peer.
pub trait Peer: Send {
    /// Return a connection to the pool after use.
    fn free(&self, r: &R, pc: &Rc<Connection>, state: u32);

    /// Number of tries remaining for this peer.
    fn tries(&self) -> u32;

    /// Peer name/address for logging.
    fn name(&self) -> Vec<u8>;

    /// Mark peer as down (failed).
    fn mark_down(&self);

    /// Get peer stats (for variables).
    fn stats(&self) -> PeerStats;
}

/// Trait for initializing load-balancer peers per-request.
/// Handles peer selection logic (round-robin, least_conn, ip_hash, etc).
pub trait PeerInit: Send {
    /// Initialize peer selection for this request.
    /// Returns a Peer to attempt connection to.
    fn init(&self, r: &R, upstream: &Upstream) -> Rc<dyn Peer>;
}

// ============================================================================
// UPSTREAM CONFIGURATION AND STATE
// ============================================================================

crate::http_module_index!("ngx_http_upstream_module");

/// Server entry in upstream { ... } block
#[derive(Clone)]
pub struct UpstreamServer {
    pub name: Vec<u8>,           // name as written
    pub addr: Vec<u8>,            // resolved address
    pub port: u16,
    pub weight: u32,
    pub max_conns: u32,
    pub max_fails: u32,
    pub fail_timeout: u64,        // milliseconds
    pub slow_start: u64,           // milliseconds
    pub backup: bool,
    pub down: bool,
    pub resolve: bool,
    pub service: Vec<u8>,
}

/// Per-upstream configuration: `upstream NAME { ... }`
pub struct UpstreamConf {
    pub name: Vec<u8>,
    pub servers: Vec<UpstreamServer>,
    pub backup_servers: Vec<UpstreamServer>,
    pub peer_init: Option<Rc<dyn PeerInit>>,
    pub keepalive: u32,           // # conns in keepalive pool
    pub keepalive_time: u64,      // milliseconds
    pub keepalive_timeout: u64,   // milliseconds
    pub keepalive_requests: u32,
}

/// Per-request upstream context: module-specific callbacks
pub struct UpstreamCtx {
    pub schema: Vec<u8>,          // "http", "https"
    pub uri: Vec<u8>,             // rewritten request URI
    pub host: Vec<u8>,            // rewritten Host header
    pub port: u16,

    /// Create upstream request from client request
    pub create_request: Box<dyn Fn(&R) -> Result<Chain, i64>>,

    /// Reinit request before retry
    pub reinit_request: Option<Box<dyn Fn(&R) -> i64>>,

    /// Process upstream response headers (returns NGX_OK or status code)
    pub process_header: Box<dyn Fn(&R, &[u8]) -> i64>,

    pub abort_request: Option<Box<dyn Fn(&R)>>,
    pub finalize_request: Option<Box<dyn Fn(&R, i64)>>,

    pub input_filter_init: Option<Box<dyn Fn(&R) -> i64>>,
    pub input_filter: Option<Box<dyn Fn(&R, usize) -> i64>>,

    pub buffering: bool,
    pub buffer_size: usize,
    pub bufs: (usize, usize),     // (count, size)

    pub read_timeout: u64,
    pub connect_timeout: u64,
    pub send_timeout: u64,
    pub next_upstream_timeout: u64,

    pub next_upstream_tries: u32,
    pub next_upstream: u32,       // bitmask of NGX_HTTP_UPSTREAM_FT_*

    pub temp_path: Option<Vec<u8>>,
    pub max_temp_file_size: usize,
    pub temp_file_write_size: usize,

    pub pass_headers: Vec<Vec<u8>>,
    pub hide_headers: Vec<Vec<u8>>,
    pub pass_request_headers: bool,
    pub pass_request_body: bool,

    pub intercept_errors: bool,
    pub ignore_client_abort: bool,
    pub cyclic_temp_file: bool,

    pub store: bool,
    pub store_access: u32,        // unix perms

    pub cookie_domains: Vec<Vec<u8>>,
    pub cookie_paths: Vec<Vec<u8>>,
    pub cookie_flags: Vec<Vec<u8>>,
    pub redirects: Vec<(Vec<u8>, Vec<u8>)>, // (from, to)
}

impl Default for UpstreamCtx {
    fn default() -> Self {
        UpstreamCtx {
            schema: b"http".to_vec(),
            uri: Vec::new(),
            host: Vec::new(),
            port: 80,
            create_request: Box::new(|_r| Err(NGX_ERROR)),
            reinit_request: None,
            process_header: Box::new(|_r, _h| NGX_ERROR),
            abort_request: None,
            finalize_request: None,
            input_filter_init: None,
            input_filter: None,
            buffering: true,
            buffer_size: 4096,
            bufs: (8, 4096),
            read_timeout: 60000,
            connect_timeout: 60000,
            send_timeout: 60000,
            next_upstream_timeout: 0,
            next_upstream_tries: 0,
            next_upstream: NGX_HTTP_UPSTREAM_FT_ERROR | NGX_HTTP_UPSTREAM_FT_TIMEOUT,
            temp_path: None,
            max_temp_file_size: 1024 * 1024 * 1024,
            temp_file_write_size: 16384,
            pass_headers: Vec::new(),
            hide_headers: Vec::new(),
            pass_request_headers: true,
            pass_request_body: true,
            intercept_errors: false,
            ignore_client_abort: false,
            cyclic_temp_file: false,
            store: false,
            store_access: 0o644,
            cookie_domains: Vec::new(),
            cookie_paths: Vec::new(),
            cookie_flags: Vec::new(),
            redirects: Vec::new(),
        }
    }
}

// Per-request upstream state (already declared in request.rs)
// pub struct UpstreamState {
//     pub bl_time: u64,
//     pub bl_state: u32,
//     pub status: i64,
//     pub response_time: u64,
//     pub connect_time: u64,
//     pub header_time: u64,
//     pub queue_time: u64,
//     pub response_length: i64,
//     pub bytes_received: i64,
//     pub bytes_sent: i64,
//     pub peer: Vec<u8>,
// }

/// Upstream structure: a group of backend servers
pub struct Upstream {
    pub name: Vec<u8>,
    pub peers: Vec<Rc<dyn Peer>>,
    pub backup_peers: Vec<Rc<dyn Peer>>,
    pub peer_init: Rc<dyn PeerInit>,
    pub keepalive: u32,
    pub keepalive_time: u64,
    pub keepalive_timeout: u64,
    pub keepalive_requests: u32,
}

impl Upstream {
    pub fn new(conf: &UpstreamConf, peer_init: Rc<dyn PeerInit>) -> Rc<Self> {
        Rc::new(Upstream {
            name: conf.name.clone(),
            peers: Vec::new(),
            backup_peers: Vec::new(),
            peer_init,
            keepalive: conf.keepalive,
            keepalive_time: conf.keepalive_time,
            keepalive_timeout: conf.keepalive_timeout,
            keepalive_requests: conf.keepalive_requests,
        })
    }
}

// ============================================================================
// MAIN CONFIGURATION STRUCT
// ============================================================================

pub struct UpstreamMainConf {
    pub upstreams: Vec<(Vec<u8>, Rc<Upstream>)>,
    /// Servers per upstream name, kept alongside the Rc<Upstream> so
    /// proxy_pass to a named upstream can pick a peer without going through
    /// the peer_init dance yet.
    pub server_lists: Vec<(Vec<u8>, std::cell::RefCell<PeerGroup>)>,
    /// While an `upstream NAME { ... }` block is being parsed, hold the pending
    /// server list here so server_handler knows where to append.
    pub current_builder: std::cell::RefCell<Option<UpstreamBuilder>>,
}

pub struct UpstreamBuilder {
    pub name: Vec<u8>,
    pub servers: Vec<UpstreamServer>,
    pub balancer: BalancerKind,
}

/// Smooth weighted round-robin state for a single upstream {} block.
/// Matches ngx_http_upstream_get_round_robin_peer.
pub struct PeerState {
    pub server: UpstreamServer,
    pub effective_weight: i32,
    pub current_weight: i32,
    pub weight: i32,
    /// Consecutive failure count. When >= max_fails, peer is considered
    /// down until `checked + fail_timeout` (see ngx_http_upstream_free_
    /// round_robin_peer / ngx_peer_get_round_robin).
    pub fails: u32,
    /// Wall-clock seconds when the peer was last "checked" (either used
    /// or its first failure since being healthy).
    pub checked: u64,
    pub accessed: u64,
    /// Currently in-flight requests against this peer. Incremented at
    /// pick time, decremented via LeaseHandle when the request drops.
    /// Least_conn reads this to pick the peer with the fewest inflight.
    pub active: u32,
}

#[derive(Clone)]
pub enum BalancerKind {
    RoundRobin,
    IpHash,
    /// nginx `hash $key` (non-consistent). Key is a ComplexValue evaluated
    /// per request; the CRC32 of the result picks the peer by weight.
    Hash(std::rc::Rc<crate::script::ComplexValue>),
    /// nginx `least_conn;` — pick the peer with the fewest in-flight
    /// requests, breaking ties with the normal smooth-WRR pass.
    LeastConn,
}

pub struct PeerGroup {
    pub peers: Vec<PeerState>,
    pub backup: Vec<PeerState>,
    /// Load-balancing algorithm chosen by the `ip_hash` / `hash` /
    /// `least_conn` / `random` directive inside the upstream {} block.
    pub balancer: BalancerKind,
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(UpstreamMainConf {
        upstreams: Vec::new(),
        server_lists: Vec::new(),
        current_builder: std::cell::RefCell::new(None),
    })
}

fn init_main_conf(_cf: &mut Conf, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

// ============================================================================
// DIRECTIVE HANDLERS
// ============================================================================

fn upstream_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // upstream name { ... } block handler
    if cf.args.len() < 2 {
        return Err(msg("no upstream name specified"));
    }

    let name = cf.args[1].clone();
    let umcf = crate::get_main_conf::<UpstreamMainConf>(cf, ctx_index());

    // Set up a builder that server_handler will push into.
    *umcf.borrow().current_builder.borrow_mut() = Some(UpstreamBuilder {
        name: name.clone(),
        servers: Vec::new(),
        balancer: BalancerKind::RoundRobin,
    });

    let saved_ct = cf.cmd_type;
    cf.cmd_type = NGX_HTTP_UPS_CONF;
    let rv = cf.parse_block();
    cf.cmd_type = saved_ct;

    // Take the builder back and finalize into an Upstream entry.
    let builder = umcf.borrow().current_builder.borrow_mut().take();
    if let Some(b) = builder {
        let servers = b.servers.clone();
        let balancer = b.balancer;
        let uconf = UpstreamConf {
            name: b.name.clone(),
            servers: b.servers,
            backup_servers: Vec::new(),
            peer_init: None,
            keepalive: 0,
            keepalive_time: 0,
            keepalive_timeout: 0,
            keepalive_requests: 0,
        };
        let peer_init: Rc<dyn PeerInit> = Rc::new(NoopPeerInit);
        let up = Upstream::new(&uconf, peer_init);
        let mut group = PeerGroup { peers: Vec::new(), backup: Vec::new(), balancer };
        for srv in servers.into_iter() {
            let w = if srv.weight == 0 { 1 } else { srv.weight as i32 };
            let ps = PeerState {
                server: srv.clone(),
                effective_weight: w,
                current_weight: 0,
                weight: w,
                fails: 0,
                checked: 0,
                accessed: 0,
                active: 0,
            };
            if srv.backup { group.backup.push(ps); } else { group.peers.push(ps); }
        }
        let mut m = umcf.borrow_mut();
        m.upstreams.push((name.clone(), up));
        m.server_lists.push((name, std::cell::RefCell::new(group)));
    }
    rv
}

/// Return (host, port) of the first usable server in the named upstream.
/// Currently just picks the first non-down, non-backup entry; TODO: real
/// round-robin with weights.
/// Pick a peer for the given named upstream using smooth weighted round-robin.
/// Mirrors ngx_http_upstream_get_round_robin_peer's inner loop.
pub fn first_server_for(r: &R, name: &[u8]) -> Option<(String, u16)> {
    let umcf = r.main_conf::<UpstreamMainConf>(ctx_index());
    // Do the pick with the main conf borrowed, then release before calling
    // incr_active_lease (which reacquires the same borrow chain).
    let (picked, is_least_conn) = {
        let m = umcf.borrow();
        let cell = m.server_lists.iter().find(|(n, _)| n.as_slice() == name).map(|(_, c)| c)?;
        let mut g = cell.borrow_mut();
        let is_lc = matches!(g.balancer, BalancerKind::LeastConn);
        let picked = match &g.balancer {
            BalancerKind::IpHash => {
                let addr_bytes = client_ip_bytes(r);
                pick_ip_hash(&mut g.peers, &addr_bytes)
                    .or_else(|| pick_wrr(&mut g.backup))
            }
            BalancerKind::Hash(cv) => {
                let key_cv = cv.clone();
                drop(g);
                let key = crate::script::complex_value(r, &key_cv).unwrap_or_default();
                let mut g = cell.borrow_mut();
                pick_hash(&mut g.peers, &key)
                    .or_else(|| pick_wrr(&mut g.backup))
            }
            BalancerKind::LeastConn => {
                pick_least_conn(&mut g.peers).or_else(|| pick_wrr(&mut g.backup))
            }
            BalancerKind::RoundRobin => {
                pick_wrr(&mut g.peers).or_else(|| pick_wrr(&mut g.backup))
            }
        };
        (picked, is_lc)
    };
    // Only least_conn needs a per-request active counter — for other
    // balancers the extra bookkeeping is dead weight and introduced
    // regressions in proxy_next_upstream around retry accounting.
    if is_least_conn {
        if let Some((h, port)) = &picked {
            incr_active_lease(r, name, h, *port);
        }
    }
    picked
}

/// Increment the `active` counter for a peer and register a cleanup on the
/// request that decrements it. Cheap enough to do for every balancer since
/// only least_conn actually reads the counter.
fn incr_active_lease(r: &R, name: &[u8], host: &str, port: u16) {
    let umcf = r.main_conf::<UpstreamMainConf>(ctx_index());
    let m = umcf.borrow();
    for (n, cell) in m.server_lists.iter() {
        if n.as_slice() != name { continue; }
        let mut g = cell.borrow_mut();
        let PeerGroup { peers, backup, .. } = &mut *g;
        for p in peers.iter_mut().chain(backup.iter_mut()) {
            let addr_matches = std::str::from_utf8(&p.server.addr).map(|a| a == host).unwrap_or(false);
            if addr_matches && p.server.port == port {
                p.active = p.active.saturating_add(1);
                let name_owned = name.to_vec();
                let host_owned = host.to_string();
                r.add_cleanup(Box::new(move || {
                    decr_active(&name_owned, &host_owned, port);
                }));
                return;
            }
        }
    }
}

fn decr_active(name: &[u8], host: &str, port: u16) {
    // We don't hold r here — reach into the thread-local main conf via
    // the http main conf slot. Simpler: iterate the cycle's server_lists
    // by walking upstream::main_conf() would require request context.
    // Instead, tests only ever have one HTTP main conf, so grab it via
    // the module registry. To keep this decoupled, thread_local a
    // pointer to the per-worker UpstreamMainConf populated at init time.
    ACTIVE_MAIN.with(|slot| {
        if let Some(umcf) = slot.borrow().as_ref() {
            let m = umcf.borrow();
            for (n, cell) in m.server_lists.iter() {
                if n.as_slice() != name { continue; }
                let mut g = cell.borrow_mut();
                let PeerGroup { peers, backup, .. } = &mut *g;
        for p in peers.iter_mut().chain(backup.iter_mut()) {
                    let addr_matches = std::str::from_utf8(&p.server.addr).map(|a| a == host).unwrap_or(false);
                    if addr_matches && p.server.port == port {
                        if p.active > 0 { p.active -= 1; }
                        return;
                    }
                }
            }
        }
    });
}

thread_local! {
    static ACTIVE_MAIN: std::cell::RefCell<Option<Rc<std::cell::RefCell<UpstreamMainConf>>>> = std::cell::RefCell::new(None);
}

/// Called from postconfiguration to give the decr_active cleanup a way
/// back to the main conf without a request handle.
pub fn set_active_main(umcf: Rc<std::cell::RefCell<UpstreamMainConf>>) {
    ACTIVE_MAIN.with(|slot| *slot.borrow_mut() = Some(umcf));
}

/// nginx least_conn: pick the peer with the smallest active/weight ratio,
/// falling through to WRR on ties.  Mirrors
/// ngx_http_upstream_get_least_conn_peer.
fn pick_least_conn(peers: &mut [PeerState]) -> Option<(String, u16)> {
    if peers.is_empty() { return None; }
    let now = ngx_core::times::time() as u64;

    // First pass: find the minimum active/weight among live peers.
    let mut best_ratio: Option<u64> = None;
    let mut candidates: Vec<usize> = Vec::new();
    for (i, p) in peers.iter().enumerate() {
        if p.server.down { continue; }
        if p.server.max_fails > 0 && p.fails >= p.server.max_fails {
            if now.saturating_sub(p.checked) < p.server.fail_timeout / 1000 { continue; }
        }
        let w = p.server.weight.max(1) as u64;
        // (active * scale) / weight — use *1000 to avoid integer trunc
        let ratio = (p.active as u64) * 1000 / w;
        match best_ratio {
            None => { best_ratio = Some(ratio); candidates.clear(); candidates.push(i); }
            Some(b) if ratio < b => { best_ratio = Some(ratio); candidates.clear(); candidates.push(i); }
            Some(b) if ratio == b => { candidates.push(i); }
            _ => {}
        }
    }
    if candidates.is_empty() { return None; }
    if candidates.len() == 1 {
        let p = &peers[candidates[0]];
        return Some((
            std::str::from_utf8(&p.server.addr).unwrap_or("").to_string(),
            p.server.port,
        ));
    }

    // Tie: run smooth-WRR restricted to the tied peers by weight.
    let mut best_idx: Option<usize> = None;
    let mut best_cw: i32 = i32::MIN;
    let mut total: i32 = 0;
    for &i in &candidates {
        let p = &mut peers[i];
        p.current_weight = p.current_weight.saturating_add(p.effective_weight);
        total = total.saturating_add(p.effective_weight);
        if p.effective_weight < p.weight { p.effective_weight += 1; }
        if p.current_weight > best_cw {
            best_cw = p.current_weight;
            best_idx = Some(i);
        }
    }
    let idx = best_idx?;
    peers[idx].current_weight -= total;
    let p = &peers[idx];
    Some((
        std::str::from_utf8(&p.server.addr).unwrap_or("").to_string(),
        p.server.port,
    ))
}

/// Client IP bytes for ip_hash. AF_UNIX and other non-IPv4/6 clients get
/// four 0xFF bytes so they all hash to the same peer (matches C's
/// ngx_http_upstream_init_ip_hash_peer default of INADDR_NONE).
fn client_ip_bytes(r: &R) -> Vec<u8> {
    use ngx_core::inet::SockAddr;
    let sa = r.connection.sockaddr.borrow();
    match &*sa {
        // C's ngx_http_upstream_init_ip_hash_peer hashes the /24 prefix
        // of the IPv4 address (first three octets); the last one is
        // dropped so an entire subnet lands on the same peer.
        SockAddr::V4(v4) => v4.ip().octets()[..3].to_vec(),
        SockAddr::V6(v6) => v6.ip().octets().to_vec(),
        // C uses a static-init "pseudo_addr" buffer of 3 zero bytes for
        // any address family that isn't inet/inet6 — unix connections
        // therefore all hash to the same key.
        SockAddr::Unix(_) => vec![0, 0, 0],
    }
}

/// nginx `hash $key` non-consistent picker: CRC32 of the key, then
/// `hash % total_weight` selects a peer.  Mirrors
/// ngx_http_upstream_get_hash_peer (non-consistent branch).
fn pick_hash(peers: &mut [PeerState], key: &[u8]) -> Option<(String, u16)> {
    if peers.is_empty() || key.is_empty() { return pick_wrr(peers); }
    let total: i32 = peers.iter()
        .filter(|p| !p.server.down)
        .map(|p| p.server.weight as i32)
        .sum();
    if total <= 0 { return None; }

    let mut hash = crc32fast::hash(key);
    for _try in 0..20 {
        let mut w = (hash % total as u32) as i32;
        for p in peers.iter() {
            if p.server.down { continue; }
            let peer_w = p.server.weight as i32;
            if w < peer_w {
                return Some((
                    std::str::from_utf8(&p.server.addr).unwrap_or("").to_string(),
                    p.server.port,
                ));
            }
            w -= peer_w;
        }
        // Rehash: (prev_hash bytes) CRC32'd again — same as C rehashing the
        // 4-byte previous hash value.
        hash = crc32fast::hash(&hash.to_be_bytes());
    }
    pick_wrr(peers)
}

/// nginx ip_hash algorithm: hash = 89; for byte in addr: hash = (hash*113 + byte) % 6271.
/// Then pick a peer whose cumulative weight covers `hash % total_weight`.
fn pick_ip_hash(peers: &mut [PeerState], addr: &[u8]) -> Option<(String, u16)> {
    if peers.is_empty() { return None; }
    // Sum of live peer weights.
    let total: i32 = peers.iter()
        .filter(|p| !p.server.down)
        .map(|p| p.server.weight as i32)
        .sum();
    if total <= 0 { return None; }

    let mut hash: u32 = 89;
    for &b in addr {
        hash = hash.wrapping_mul(113).wrapping_add(b as u32) % 6271;
    }

    // Try up to 20 rehashes so a downed peer doesn't stall the pick (C caps
    // at 20 as well before falling back to plain round-robin).
    for _try in 0..20 {
        let mut w = (hash % total as u32) as i32;
        for p in peers.iter() {
            if p.server.down { continue; }
            let peer_w = p.server.weight as i32;
            if w < peer_w {
                return Some((
                    std::str::from_utf8(&p.server.addr).unwrap_or("").to_string(),
                    p.server.port,
                ));
            }
            w -= peer_w;
        }
        hash = (hash.wrapping_mul(113).wrapping_add(113)) % 6271;
    }
    // Fall back to round-robin.
    pick_wrr(peers)
}

/// Number of non-down peers (main + backup) in the named upstream.
/// proxy_next_upstream uses this as its per-request retry ceiling: after
/// `peer_count` attempts we've cycled through every distinct peer entry
/// (even if two entries happen to share a host:port).
pub fn peer_count_for(r: &R, name: &[u8]) -> usize {
    let umcf = r.main_conf::<UpstreamMainConf>(ctx_index());
    let m = umcf.borrow();
    for (n, cell) in m.server_lists.iter() {
        if n.as_slice() != name { continue; }
        let g = cell.borrow();
        return g.peers.iter().filter(|p| !p.server.down).count()
             + g.backup.iter().filter(|p| !p.server.down).count();
    }
    0
}

/// Pick the next peer for a retry — just runs one more round of smooth WRR
/// (which naturally rotates among peers). The caller must enforce an
/// attempt ceiling via [`peer_count_for`] so we don't loop forever when
/// only one peer exists.
pub fn next_server_for(r: &R, name: &[u8]) -> Option<(String, u16)> {
    first_server_for(r, name)
}

fn pick_wrr(peers: &mut [PeerState]) -> Option<(String, u16)> {
    let now = ngx_core::times::time() as u64;
    let mut total: i32 = 0;
    let mut best_idx: Option<usize> = None;
    let mut best_cw: i32 = i32::MIN;
    for (i, p) in peers.iter_mut().enumerate() {
        if p.server.down { continue; }
        // max_fails / fail_timeout: skip peers whose consecutive-fail
        // count reached the ceiling until fail_timeout has elapsed since
        // the first failure of the current window. Matches ngx_http_
        // upstream_get_round_robin_peer's `if (peer->max_fails && …)`.
        if p.server.max_fails > 0 && p.fails >= p.server.max_fails {
            if now.saturating_sub(p.checked) < p.server.fail_timeout / 1000 {
                continue;
            }
            // Fail window elapsed — give the peer another chance.
            p.fails = 0;
            p.checked = now;
        }
        p.current_weight = p.current_weight.saturating_add(p.effective_weight);
        total = total.saturating_add(p.effective_weight);
        if p.effective_weight < p.weight {
            p.effective_weight += 1;
        }
        if p.current_weight > best_cw {
            best_cw = p.current_weight;
            best_idx = Some(i);
        }
    }
    let idx = best_idx?;
    peers[idx].current_weight -= total;
    peers[idx].checked = now;
    let s = &peers[idx].server;
    Some((String::from_utf8_lossy(&s.addr).into_owned(), s.port))
}

/// Record a connect/read failure against the peer identified by (addr,
/// port). Increments fails; on transition to failed, records `accessed`
/// timestamp so pick_wrr can respect fail_timeout. Mirrors
/// ngx_http_upstream_free_round_robin_peer(state=NGX_PEER_FAILED).
pub fn mark_bad_server(r: &R, name: &[u8], addr: &str, port: u16) {
    let now = ngx_core::times::time() as u64;
    let umcf = r.main_conf::<UpstreamMainConf>(ctx_index());
    let m = umcf.borrow();
    for (n, cell) in m.server_lists.iter() {
        if n.as_slice() != name { continue; }
        let mut g = cell.borrow_mut();
        let PeerGroup { peers, backup, .. } = &mut *g;
        for p in peers.iter_mut().chain(backup.iter_mut()) {
            let paddr = std::str::from_utf8(&p.server.addr).unwrap_or("");
            if paddr == addr && p.server.port == port {
                p.fails = p.fails.saturating_add(1);
                p.accessed = now;
                if p.fails == 1 {
                    p.checked = now;
                }
                // Penalise via effective_weight (matches C: peer->
                // effective_weight -= peer->weight / peer->max_fails).
                let per = if p.server.max_fails > 0 {
                    p.weight / p.server.max_fails as i32
                } else { p.weight };
                p.effective_weight = (p.effective_weight - per).max(0);
                return;
            }
        }
    }
}

/// Reset a peer's failure counter after a successful use. Called on the
/// happy path so a stray failure doesn't linger.
pub fn mark_good_server(r: &R, name: &[u8], addr: &str, port: u16) {
    let umcf = r.main_conf::<UpstreamMainConf>(ctx_index());
    let m = umcf.borrow();
    for (n, cell) in m.server_lists.iter() {
        if n.as_slice() != name { continue; }
        let mut g = cell.borrow_mut();
        let PeerGroup { peers, backup, .. } = &mut *g;
        for p in peers.iter_mut().chain(backup.iter_mut()) {
            let paddr = std::str::from_utf8(&p.server.addr).unwrap_or("");
            if paddr == addr && p.server.port == port {
                p.fails = 0;
                if p.effective_weight < p.weight {
                    p.effective_weight = p.weight;
                }
                return;
            }
        }
    }
}

struct NoopPeerInit;
impl PeerInit for NoopPeerInit {
    fn init(&self, _r: &R, _upstream: &Upstream) -> Rc<dyn Peer> {
        Rc::new(DummyPeer)
    }
}

fn server_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("no server address specified"));
    }
    // Parse host:port from args[1]. IPv6 [::1]:8080 and unix:/path supported.
    let addr = cf.args[1].clone();
    let addr_str = std::str::from_utf8(&addr).unwrap_or("");
    let (host, port) = if let Some(path) = addr_str.strip_prefix("unix:") {
        (format!("unix:{}", path), 0)
    } else if addr_str.starts_with('[') {
        // [ipv6]:port
        if let Some(end) = addr_str.find(']') {
            let host_part = &addr_str[..=end];
            let rest = &addr_str[end + 1..];
            let port = rest.strip_prefix(':').and_then(|s| s.parse::<u16>().ok()).unwrap_or(80);
            (host_part.to_string(), port)
        } else {
            (addr_str.to_string(), 80)
        }
    } else if let Some(colon) = addr_str.rfind(':') {
        let host_part = &addr_str[..colon];
        let port = addr_str[colon + 1..].parse::<u16>().unwrap_or(80);
        (host_part.to_string(), port)
    } else {
        (addr_str.to_string(), 80)
    };

    let mut server = UpstreamServer {
        name: addr.clone(),
        addr: host.as_bytes().to_vec(),
        port,
        weight: 1,
        max_conns: 0,
        max_fails: 1,
        fail_timeout: 10_000,
        slow_start: 0,
        backup: false,
        down: false,
        resolve: false,
        service: Vec::new(),
    };
    for arg in cf.args.iter().skip(2) {
        let s = std::str::from_utf8(arg).unwrap_or("");
        if s == "backup" { server.backup = true; }
        else if s == "down" { server.down = true; }
        else if s == "resolve" { server.resolve = true; }
        else if let Some(rest) = s.strip_prefix("weight=") {
            if let Ok(n) = rest.parse::<u32>() { server.weight = n; }
        } else if let Some(rest) = s.strip_prefix("max_conns=") {
            if let Ok(n) = rest.parse::<u32>() { server.max_conns = n; }
        } else if let Some(rest) = s.strip_prefix("max_fails=") {
            if let Ok(n) = rest.parse::<u32>() { server.max_fails = n; }
        } else if let Some(rest) = s.strip_prefix("fail_timeout=") {
            if let Some(ms) = ngx_core::parse::parse_time(rest.as_bytes(), false) {
                server.fail_timeout = ms as u64;
            }
        } else if let Some(rest) = s.strip_prefix("slow_start=") {
            if let Some(ms) = ngx_core::parse::parse_time(rest.as_bytes(), false) {
                server.slow_start = ms as u64;
            }
        } else if let Some(rest) = s.strip_prefix("service=") {
            server.service = rest.as_bytes().to_vec();
        }
    }
    let umcf = crate::get_main_conf::<UpstreamMainConf>(cf, ctx_index());
    let m = umcf.borrow();
    let mut b = m.current_builder.borrow_mut();
    if let Some(bld) = b.as_mut() {
        bld.servers.push(server);
    }
    Ok(())
}

fn resolver_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("no resolver address specified"));
    }
    // TODO: Parse resolver directive
    Ok(())
}

fn resolver_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("no timeout value specified"));
    }
    // TODO: Parse timeout
    Ok(())
}

// ============================================================================
// VARIABLE GETTERS
// ============================================================================

fn upstream_addr_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // Comma-separated peer addresses per try. Empty peer means the try wasn't
    // dispatched (matches C which emits "-" in that case).
    let states = r.upstream_states.borrow();
    if states.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    let parts: Vec<Vec<u8>> = states.iter().map(|s| {
        if s.peer.is_empty() { b"-".to_vec() } else { s.peer.clone() }
    }).collect();
    v.data = parts.join(&b", "[..]);
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    NGX_OK
}

fn upstream_status_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let states = r.upstream_states.borrow();
    if states.is_empty() {
        v.not_found = true;
        return NGX_OK;
    }
    let parts: Vec<Vec<u8>> = states.iter().map(|s| {
        if s.status == 0 { b"-".to_vec() } else { s.status.to_string().into_bytes() }
    }).collect();
    v.data = parts.join(&b", "[..]);
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    NGX_OK
}

fn format_upstream_times(r: &R, field: fn(&crate::request::UpstreamState) -> u64) -> Vec<u8> {
    let states = r.upstream_states.borrow();
    if states.is_empty() {
        return Vec::new();
    }
    // C's ngx_http_upstream_response_time_variable prints "-" when the state
    // was never measured (ms == -1). We use u64::MAX as the same sentinel;
    // any smaller value is a real millisecond count.
    let parts: Vec<Vec<u8>> = states.iter().map(|s| {
        let ms = field(s);
        if ms == u64::MAX {
            b"-".to_vec()
        } else {
            format!("{}.{:03}", ms / 1000, ms % 1000).into_bytes()
        }
    }).collect();
    parts.join(&b", "[..])
}

fn upstream_connect_time_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let data = format_upstream_times(r, |s| s.connect_time);
    if data.is_empty() { v.not_found = true; } else { v.data = data; v.valid = true; }
    NGX_OK
}

fn upstream_header_time_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let data = format_upstream_times(r, |s| s.header_time);
    if data.is_empty() { v.not_found = true; } else { v.data = data; v.valid = true; }
    NGX_OK
}

fn upstream_response_time_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let data = format_upstream_times(r, |s| s.response_time);
    if data.is_empty() { v.not_found = true; } else { v.data = data; v.valid = true; }
    NGX_OK
}

fn upstream_zero_variable(r: &R, v: &mut crate::request::VariableValue, data: usize) -> i64 {
    // Aggregate the requested counter across all upstream states. `data`
    // selects the field: 0=response_length, 1=bytes_received, 2=bytes_sent.
    let states = r.upstream_states.borrow();
    let sum: i64 = states.iter().map(|s| match data {
        0 => s.response_length,
        1 => s.bytes_received,
        2 => s.bytes_sent,
        _ => 0,
    }).sum();
    v.data = sum.to_string().into_bytes();
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    NGX_OK
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
            flags: 0,
        },
        VarDef {
            name: "upstream_status",
            get: Some(upstream_status_variable),
            set: None,
            data: 0,
            flags: 0,
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
            get: Some(upstream_zero_variable),
            set: None,
            data: 0, // response body length
            flags: 0,
        },
        VarDef {
            name: "upstream_bytes_received",
            get: Some(upstream_zero_variable),
            set: None,
            data: 1, // total bytes received from upstream
            flags: 0,
        },
        VarDef {
            name: "upstream_bytes_sent",
            get: Some(upstream_zero_variable),
            set: None,
            data: 2, // total bytes sent to upstream
            flags: 0,
        },
    ];

    crate::variables::add_variables(cf, &vars)?;

    // Prefix variables: $upstream_http_<name> reads from upstream response headers.
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
        postconfiguration: Some(register_active_main),
        ..Default::default()
    };

    http_module_def("ngx_http_upstream_module", def, commands)
}

fn register_active_main(cf: &mut Conf) -> ConfResult {
    let umcf = crate::get_main_conf::<UpstreamMainConf>(cf, ctx_index());
    set_active_main(umcf);
    Ok(())
}

// ============================================================================
// UPSTREAM INIT AND REQUEST PROCESSING
// ============================================================================

/// Initialize upstream request: create peer connection, send request, read response.
pub async fn upstream_init(_r: &R, _ctx: Rc<UpstreamCtx>) -> i64 {
    // Create upstream structure from configuration
    // Resolve upstream addresses (DNS if needed)
    // Select peer via load balancer
    // Connect with timeout
    // Send request body
    // Read response headers via process_header callback
    // Stream response body through output filters
    // Support buffering to disk on large responses
    // Handle next_upstream retries on error
    // Support keepalive pool

    NGX_OK
}

/// Get upstream by name from main config.
pub fn get_upstream_by_name(r: &R, name: &[u8]) -> Option<Rc<Upstream>> {
    let umcf = r.main_conf::<UpstreamMainConf>(ctx_index());
    let upstreams = umcf.borrow().upstreams.clone();
    upstreams.iter().find(|(n, _)| n == name).map(|(_, u)| u.clone())
}

/// Default round-robin peer initializer (placeholder).
pub struct RoundRobinInit;

impl PeerInit for RoundRobinInit {
    fn init(&self, _r: &R, _upstream: &Upstream) -> Rc<dyn Peer> {
        // TODO: Implement round-robin selection
        // - Distribute across peers with weight
        // - Track current_weight, effective_weight
        // - Mark down on failures
        // - Slow start ramp-up
        // - Backup peers fallback
        Rc::new(DummyPeer)
    }
}

/// Dummy peer for placeholder implementation
struct DummyPeer;

impl Peer for DummyPeer {
    fn free(&self, _r: &R, _pc: &Rc<Connection>, _state: u32) {}

    fn tries(&self) -> u32 {
        0
    }

    fn name(&self) -> Vec<u8> {
        b"dummy".to_vec()
    }

    fn mark_down(&self) {}

    fn stats(&self) -> PeerStats {
        Default::default()
    }
}

// ============================================================================
// STUB: UPSTREAM LOG INFO
// ============================================================================

/// Return upstream log info for error logs (replaces stubs::upstream_log_info).
pub fn upstream_log_info(r: &Request) -> Option<Vec<u8>> {
    if let Some(state) = r.upstream_states.borrow().last() {
        if state.status > 0 {
            let peer = B(&state.peer).to_string();
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

    #[test]
    fn test_upstream_flags() {
        assert_eq!(NGX_HTTP_UPSTREAM_FT_ERROR, 0x00000002);
        assert_eq!(
            NGX_HTTP_UPSTREAM_FT_STATUS,
            NGX_HTTP_UPSTREAM_FT_HTTP_500 | NGX_HTTP_UPSTREAM_FT_HTTP_502
        );
    }

    #[test]
    fn test_upstream_ctx_default() {
        let ctx = UpstreamCtx::default();
        assert_eq!(ctx.buffer_size, 4096);
        assert_eq!(ctx.buffering, true);
        assert!(ctx.pass_request_headers);
    }
}
