//! Per-worker idle-connection pool for upstream keepalive.
//!
//! Roughly ngx_http_upstream_keepalive_module's cache list, but keyed by
//! (upstream-name-or-addr, peer-addr) instead of a linked list attached to
//! the peer_data.  Simpler and enough for the tests: single-threaded tokio
//! runtime, so a thread_local RefCell<HashMap> is safe.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

use tokio::net::TcpStream;

/// Per-upstream cache limits parsed from the `keepalive N` directive.
#[derive(Clone, Copy)]
pub struct KeepaliveLimits {
    pub max_cached: u32,
    pub max_requests: u32,
    pub timeout_ms: u64,
    pub time_ms: u64,
}

impl Default for KeepaliveLimits {
    fn default() -> Self {
        KeepaliveLimits { max_cached: 0, max_requests: 1000, timeout_ms: 60_000, time_ms: 0 }
    }
}

thread_local! {
    /// Idle streams indexed by (upstream-name-or-addr, peer-addr string).
    static POOL: RefCell<HashMap<(Vec<u8>, String), VecDeque<TcpStream>>> = RefCell::new(HashMap::new());
    /// Per-upstream limits.  Empty entry means keepalive is off.
    static LIMITS: RefCell<HashMap<Vec<u8>, KeepaliveLimits>> = RefCell::new(HashMap::new());
}

/// Register keepalive limits for an upstream name.  Called at config time.
pub fn set_limits(name: &[u8], limits: KeepaliveLimits) {
    LIMITS.with(|m| { m.borrow_mut().insert(name.to_vec(), limits); });
}

/// Look up the limits for an upstream name (returns None if keepalive off).
pub fn get_limits(name: &[u8]) -> Option<KeepaliveLimits> {
    LIMITS.with(|m| m.borrow().get(name).copied())
}

/// Try to pop an idle stream for (upstream, peer).  Returns None on miss.
pub fn take(name: &[u8], addr: &str) -> Option<TcpStream> {
    POOL.with(|m| {
        let mut pool = m.borrow_mut();
        let key = (name.to_vec(), addr.to_string());
        let q = pool.get_mut(&key)?;
        q.pop_front()
    })
}

/// Return a stream to the pool.  Drops it if the pool is at capacity.
pub fn put(name: &[u8], addr: &str, stream: TcpStream) {
    let cap = match get_limits(name) {
        Some(l) => l.max_cached as usize,
        None => return,
    };
    if cap == 0 { return; }
    POOL.with(|m| {
        let mut pool = m.borrow_mut();
        let key = (name.to_vec(), addr.to_string());
        let q = pool.entry(key).or_insert_with(VecDeque::new);
        if q.len() >= cap {
            // At capacity — drop oldest (LRU) to make room, matching
            // ngx_http_upstream_free_keepalive_peer which evicts the tail.
            q.pop_back();
        }
        q.push_front(stream);
    });
}

/// How many streams currently cached for (name, addr).
#[allow(dead_code)]
pub fn len(name: &[u8], addr: &str) -> usize {
    POOL.with(|m| {
        let pool = m.borrow();
        let key = (name.to_vec(), addr.to_string());
        pool.get(&key).map(|q| q.len()).unwrap_or(0)
    })
}
