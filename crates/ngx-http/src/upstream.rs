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
use crate::variables::{GetHandler, SetHandler, VarDef};
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
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(UpstreamMainConf { upstreams: Vec::new() })
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

    // Parse the upstream { ... } block
    // Set command type to UPS_CONF so directives inside the block know we're in upstream context
    let saved_ct = cf.cmd_type;
    cf.cmd_type = NGX_HTTP_UPS_CONF;

    let rv = cf.parse_block();

    cf.cmd_type = saved_ct;

    // TODO: Register the upstream in main conf
    // For now, just accept any upstream block

    rv
}

fn server_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // server address [parameters]
    if cf.args.len() < 2 {
        return Err(msg("no server address specified"));
    }

    // TODO: Parse server directive parameters
    // address, weight=, max_conns=, max_fails=, fail_timeout=, backup, down, resolve, service=, slow_start=
    // cf.args[1] = address (host:port or unix socket path)
    // cf.args[2+] = parameters like "weight=5" "backup" "down" etc

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

fn upstream_addr_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return upstream server addresses
    // Format: comma-separated list of addrs
    v.not_found = true; NGX_OK
}

fn upstream_status_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return upstream response status codes
    // Format: comma-separated list of HTTP status codes (one per try)
    v.not_found = true; NGX_OK
}

fn upstream_connect_time_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return upstream connection time in milliseconds (first try)
    v.not_found = true; NGX_OK
}

fn upstream_header_time_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return time to receive upstream response headers
    v.not_found = true; NGX_OK
}

fn upstream_response_time_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return total upstream response time
    v.not_found = true; NGX_OK
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
            flags: 0,
        },
        VarDef {
            name: "upstream_header_time",
            get: Some(upstream_header_time_variable),
            set: None,
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "upstream_response_time",
            get: Some(upstream_response_time_variable),
            set: None,
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "upstream_response_length",
            get: None,
            set: None,
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "upstream_bytes_received",
            get: None,
            set: None,
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "upstream_bytes_sent",
            get: None,
            set: None,
            data: 0,
            flags: 0,
        },
    ];

    crate::variables::add_variables(cf, &vars)?;

    // TODO: Add upstream_http_* and upstream_trailer_* variables with getters
    Ok(())
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
