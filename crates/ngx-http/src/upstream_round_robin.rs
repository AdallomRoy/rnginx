//! ngx_http_upstream_round_robin.c: the peers of an upstream, the default
//! (smooth weighted) round robin balancer, and the per-peer failure and
//! connection accounting the other balancers build on.
//!
//! Peers are the C structures: in the upstream's memory, or, with "zone",
//! copied to shared memory (upstream_zone.rs), where the workers share
//! them under the peers' rwlock and each peer's lock, and where the
//! servers resolved at run time come and go.

use std::cell::RefCell;
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;

use ngx_core::conf::*;
use ngx_core::inet::{Addr, SockAddr, Url};
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::slab::SlabPool;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::request::*;
use crate::upstream::*;

/// NGX_HTTP_UPSTREAM_SID_LEN: md5 in hex.
pub const NGX_HTTP_UPSTREAM_SID_LEN: usize = 32;

/// peer->down values.
pub const NGX_HTTP_UPSTREAM_FAILED: usize = 1;
pub const NGX_HTTP_UPSTREAM_DRAINING: usize = 8;

/// NGX_SOCKADDR_STRLEN
pub const NGX_SOCKADDR_STRLEN: usize = 112;

/// NGX_SSL_MAX_SESSION_SIZE
pub const NGX_SSL_MAX_SESSION_SIZE: usize = 4096;

/// ngx_str_t in the peers' memory
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NgxStr {
    pub data: *mut u8,
    pub len: usize,
}

impl NgxStr {
    pub const NULL: NgxStr = NgxStr { data: null_mut(), len: 0 };

    /// The bytes; the memory outlives the borrow while the peers do.
    pub fn bytes<'a>(&self) -> &'a [u8] {
        if self.len == 0 || self.data.is_null() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }
}

/// ngx_http_upstream_host_t: a server resolved at run time; its resolve
/// timer is the worker's (upstream_zone.rs)
#[repr(C)]
pub struct UpstreamHost {
    pub worker: usize,
    pub name: NgxStr,
    pub service: NgxStr,
    pub valid: i64,
    pub peers: *mut RrPeers,
    pub peer: *mut RrPeer,
}

/// ngx_http_upstream_rr_peer_t
#[repr(C)]
pub struct RrPeer {
    pub sockaddr: *mut libc::sockaddr,
    pub socklen: libc::socklen_t,
    pub name: NgxStr,
    pub server: NgxStr,

    pub current_weight: isize,
    pub effective_weight: isize,
    pub weight: isize,

    pub conns: usize,
    pub max_conns: usize,

    pub fails: usize,
    pub accessed: i64,
    pub checked: i64,

    pub max_fails: usize,
    pub fail_timeout: i64,
    pub slow_start: u64,
    pub start_time: u64,

    pub down: usize,

    /// the saved session, DER
    pub ssl_session: *mut u8,
    pub ssl_session_len: i32,

    pub route: bool,

    pub zombie: bool,

    pub lock: AtomicUsize,
    pub refs: usize,
    pub host: *mut UpstreamHost,

    pub sid: NgxStr,

    pub next: *mut RrPeer,

    pub header_time: u64,
    pub response_time: u64,
    pub inflight_time: u64,
    pub inflight_last: u64,
    pub inflight_reqs_changed: u64,
    pub inflight_reqs: usize,
}

/// ngx_http_upstream_rr_peers_t
#[repr(C)]
pub struct RrPeers {
    pub number: usize,

    pub shpool: *mut SlabPool,
    pub rwlock: AtomicUsize,
    pub config: *mut usize,
    pub resolve: *mut RrPeer,
    pub zone_next: *mut RrPeers,

    pub total_weight: usize,
    pub tries: usize,

    pub single: bool,
    pub weighted: bool,

    pub name: *mut NgxStr,

    pub next: *mut RrPeers,

    pub peer: *mut RrPeer,
}

/// The process memory of peers (C allocates them from cf->pool or
/// r->pool): freed with its owner.
#[derive(Default)]
pub struct Arena {
    blocks: RefCell<Vec<*mut u8>>,
}

impl Arena {
    /// ngx_pcalloc
    pub fn calloc(&self, size: usize) -> *mut u8 {
        let p = unsafe { libc::calloc(1, size.max(1)) } as *mut u8;
        if p.is_null() {
            panic!("calloc({}) failed", size);
        }
        self.blocks.borrow_mut().push(p);
        p
    }

    pub fn alloc<T>(&self) -> *mut T {
        self.calloc(std::mem::size_of::<T>()) as *mut T
    }

    pub fn alloc_n<T>(&self, n: usize) -> *mut T {
        self.calloc(std::mem::size_of::<T>() * n) as *mut T
    }

    /// A copy of bytes.
    pub fn dup(&self, s: &[u8]) -> NgxStr {
        if s.is_empty() {
            return NgxStr::NULL;
        }
        let p = self.calloc(s.len());
        unsafe { std::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len()) };
        NgxStr { data: p, len: s.len() }
    }

    /// A copy of a socket address.
    pub fn sockaddr(&self, sa: &SockAddr) -> (*mut libc::sockaddr, libc::socklen_t) {
        let (ss, len) = sa.to_libc();
        let p = self.calloc(std::mem::size_of::<libc::sockaddr_storage>());
        unsafe { std::ptr::copy_nonoverlapping(&ss as *const libc::sockaddr_storage as *const u8, p, len as usize) };
        (p as *mut libc::sockaddr, len)
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        for p in self.blocks.borrow_mut().drain(..) {
            unsafe { libc::free(p as *mut libc::c_void) };
        }
    }
}

/// The address of a peer.
pub fn peer_sockaddr(peer: *const RrPeer) -> SockAddr {
    unsafe { SockAddr::from_libc((*peer).sockaddr, (*peer).socklen).expect("peer sockaddr") }
}

// ngx_http_upstream_rr_peers_rlock() and the like: no-ops unless the
// peers are in shared memory

#[inline]
pub unsafe fn peers_rlock(peers: *mut RrPeers) {
    if !(*peers).shpool.is_null() {
        ngx_core::rwlock::rlock(&(*peers).rwlock);
    }
}

#[inline]
pub unsafe fn peers_wlock(peers: *mut RrPeers) {
    if !(*peers).shpool.is_null() {
        ngx_core::rwlock::wlock(&(*peers).rwlock);
    }
}

#[inline]
pub unsafe fn peers_unlock(peers: *mut RrPeers) {
    if !(*peers).shpool.is_null() {
        ngx_core::rwlock::unlock(&(*peers).rwlock);
    }
}

#[inline]
pub unsafe fn peer_lock(peers: *mut RrPeers, peer: *mut RrPeer) {
    if !(*peers).shpool.is_null() {
        ngx_core::rwlock::wlock(&(*peer).lock);
    }
}

#[inline]
pub unsafe fn peer_unlock(peers: *mut RrPeers, peer: *mut RrPeer) {
    if !(*peers).shpool.is_null() {
        ngx_core::rwlock::unlock(&(*peer).lock);
    }
}

/// ngx_http_upstream_rr_peer_ref
#[inline]
pub unsafe fn peer_ref(_peers: *mut RrPeers, peer: *mut RrPeer) {
    (*peer).refs += 1;
}

/// ngx_http_upstream_rr_peer_free_locked
pub unsafe fn peer_free_locked(peers: *mut RrPeers, peer: *mut RrPeer) {
    if (*peer).refs != 0 {
        (*peer).zombie = true;
        return;
    }

    let pool = &*(*peers).shpool;

    pool.free_locked((*peer).sockaddr as *mut u8);
    pool.free_locked((*peer).name.data);
    pool.free_locked((*peer).sid.data);

    if !(*peer).server.data.is_null() {
        pool.free_locked((*peer).server.data);
    }

    if !(*peer).ssl_session.is_null() {
        pool.free_locked((*peer).ssl_session);
    }

    pool.free_locked(peer as *mut u8);
}

/// ngx_http_upstream_rr_peer_free
pub unsafe fn peer_free(peers: *mut RrPeers, peer: *mut RrPeer) {
    let pool = &*(*peers).shpool;
    pool.lock();
    peer_free_locked(peers, peer);
    pool.unlock();
}

/// ngx_http_upstream_rr_peer_unref
pub unsafe fn peer_unref(peers: *mut RrPeers, peer: *mut RrPeer) -> i64 {
    (*peer).refs -= 1;

    if (*peers).shpool.is_null() {
        return NGX_OK;
    }

    if (*peer).refs == 0 && (*peer).zombie {
        peer_free(peers, peer);
        return NGX_DONE;
    }

    NGX_OK
}

/// ngx_http_upstream_response_time_avg: exponential moving average with
/// rounding
pub fn response_time_avg(avg: &mut u64, v: u64) {
    *avg = if *avg != 0 { (0.5 + (v as f64 * 0.05 + *avg as f64 * 0.95)) as u64 } else { v };
}

/// ngx_http_upstream_tries
pub unsafe fn upstream_tries(p: *mut RrPeers) -> usize {
    (*p).tries + if (*p).next.is_null() { 0 } else { (*(*p).next).tries }
}

/// Fill a peer with the parameters of a server.
unsafe fn set_peer(peer: *mut RrPeer, arena: &Arena, addr: &Addr, s: &UpstreamServer) {
    let (sa, len) = arena.sockaddr(&addr.sockaddr);
    (*peer).sockaddr = sa;
    (*peer).socklen = len;
    (*peer).name = arena.dup(&addr.name);
    (*peer).weight = s.weight as isize;
    (*peer).effective_weight = s.weight as isize;
    (*peer).current_weight = 0;
    (*peer).max_conns = s.max_conns as usize;
    (*peer).max_fails = s.max_fails as usize;
    (*peer).fail_timeout = s.fail_timeout;
    (*peer).down = s.down as usize;
    (*peer).server = arena.dup(&s.name);

    create_sid(arena, peer, &s.sid);
}

/// The peers of the servers, backup or not, with the resolvable ones.
unsafe fn make_peers(arena: &Arena, servers: &[UpstreamServer], backup: bool, peers: *mut RrPeers, peer: *mut RrPeer) {
    let mut n = 0;

    let mut peerp: *mut *mut RrPeer = &mut (*peers).peer;
    let mut rpeerp: *mut *mut RrPeer = &mut (*peers).resolve;

    for s in servers.iter() {
        if s.backup != backup {
            continue;
        }

        if !s.host.is_empty() {
            let p = peer.add(n);

            let host = arena.alloc::<UpstreamHost>();
            (*host).name = arena.dup(&s.host);
            (*host).service = arena.dup(&s.service);
            (*p).host = host;

            set_peer(p, arena, &s.addrs[0], s);

            *rpeerp = p;
            rpeerp = &mut (*p).next;
            n += 1;

            continue;
        }

        for a in s.addrs.iter() {
            let p = peer.add(n);

            set_peer(p, arena, a, s);

            *peerp = p;
            peerp = &mut (*p).next;
            n += 1;
        }
    }
}

/// ngx_http_upstream_init_round_robin: the peers of the upstream's servers,
/// the backup ones in peers.next; or, for an upstream implicitly defined by
/// proxy_pass and the like, the addresses its host resolves to.
pub fn init_round_robin(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    *us.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_round_robin_peer(r, us)?))
    }));

    let arena = &us.arena;

    let servers = us.servers.borrow();

    if let Some(servers) = servers.as_ref() {
        let (mut n, mut r, mut w, mut t) = (0usize, 0usize, 0usize, 0usize);

        let mut resolve = false;

        for s in servers.iter() {
            if !s.host.is_empty() {
                resolve = true;
            }

            if s.backup {
                continue;
            }

            if !s.host.is_empty() {
                r += 1;
                continue;
            }

            n += s.addrs.len();
            w += s.addrs.len() * s.weight as usize;

            if s.down == 0 {
                t += s.addrs.len();
            }
        }

        if us.shm_zone.borrow().is_some() {
            if resolve && us.flags.get() & NGX_HTTP_UPSTREAM_MODIFY == 0 {
                return Err(cf.emerg(format_args!(
                    "load balancing method does not support resolving names at run time in upstream \"{}\" in {}:{}",
                    B(&us.host),
                    B(&us.file_name),
                    us.line
                )));
            }

            let (resolver, resolver_timeout) = crate::core::resolver_of(cf);

            if us.resolver.borrow().is_none() {
                *us.resolver.borrow_mut() = resolver;
            }

            // Without "resolver_timeout" in http{} the merged value is unset.
            if us.resolver_timeout.get().is_none() {
                us.resolver_timeout.set(Some(resolver_timeout.unwrap_or(30000)));
            }

            if resolve && !us.resolver.borrow().as_ref().is_some_and(|r| r.has_servers()) {
                return Err(cf.emerg(format_args!(
                    "no resolver defined to resolve names at run time in upstream \"{}\" in {}:{}",
                    B(&us.host),
                    B(&us.file_name),
                    us.line
                )));
            }
        } else if resolve {
            return Err(cf.emerg(format_args!(
                "resolving names at run time requires upstream \"{}\" in {}:{} to be in shared memory",
                B(&us.host),
                B(&us.file_name),
                us.line
            )));
        }

        if n + r == 0 {
            return Err(cf.emerg(format_args!("no servers in upstream \"{}\" in {}:{}", B(&us.host), B(&us.file_name), us.line)));
        }

        unsafe {
            let peers = arena.alloc::<RrPeers>();
            let peer = arena.alloc_n::<RrPeer>(n + r);

            let name = arena.alloc::<NgxStr>();
            *name = arena.dup(&us.host);

            (*peers).single = n == 1;
            (*peers).number = n;
            (*peers).weighted = w != n;
            (*peers).total_weight = w;
            (*peers).tries = t;
            (*peers).name = name;

            make_peers(arena, servers, false, peers, peer);

            us.peers.set(peers);

            // backup servers

            let (mut n, mut r, mut w, mut t) = (0usize, 0usize, 0usize, 0usize);

            for s in servers.iter() {
                if !s.backup {
                    continue;
                }

                if !s.host.is_empty() {
                    r += 1;
                    continue;
                }

                n += s.addrs.len();
                w += s.addrs.len() * s.weight as usize;

                if s.down == 0 {
                    t += s.addrs.len();
                }
            }

            if n == 0 && !resolve {
                return Ok(());
            }

            if n + r == 0 && us.flags.get() & NGX_HTTP_UPSTREAM_BACKUP == 0 {
                return Ok(());
            }

            let backup = arena.alloc::<RrPeers>();
            let peer = arena.alloc_n::<RrPeer>(n + r);

            if n > 0 {
                (*peers).single = false;
            }

            (*backup).single = false;
            (*backup).number = n;
            (*backup).weighted = w != n;
            (*backup).total_weight = w;
            (*backup).tries = t;
            (*backup).name = name;

            make_peers(arena, servers, true, backup, peer);

            (*peers).next = backup;
        }

        return Ok(());
    }

    drop(servers);

    // an upstream implicitly defined by proxy_pass, etc.

    if us.port.get() == 0 {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no port in upstream \"{}\" in {}:{}", B(&us.host), B(&us.file_name), us.line);
        return Err(ConfError::Logged);
    }

    let mut u = Url::default();
    u.host = us.host.clone();
    u.port = us.port.get();

    if ngx_core::inet::inet_resolve_host(&mut u).is_err() {
        if let Some(err) = u.err {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{} in upstream \"{}\" in {}:{}", err, B(&us.host), B(&us.file_name), us.line);
            return Err(ConfError::Logged);
        }
        return Err(ConfError::Logged);
    }

    let n = u.addrs.len();

    unsafe {
        let peers = arena.alloc::<RrPeers>();
        let peer = arena.alloc_n::<RrPeer>(n);

        let name = arena.alloc::<NgxStr>();
        *name = arena.dup(&us.host);

        (*peers).single = n == 1;
        (*peers).number = n;
        (*peers).weighted = false;
        (*peers).total_weight = n;
        (*peers).tries = n;
        (*peers).name = name;

        let mut peerp: *mut *mut RrPeer = &mut (*peers).peer;

        for (i, a) in u.addrs.iter().enumerate() {
            let p = peer.add(i);
            let (sa, len) = arena.sockaddr(&a.sockaddr);
            (*p).sockaddr = sa;
            (*p).socklen = len;
            (*p).name = arena.dup(&a.name);
            (*p).weight = 1;
            (*p).effective_weight = 1;
            (*p).current_weight = 0;
            (*p).max_conns = 0;
            (*p).max_fails = 1;
            (*p).fail_timeout = 10;
            *peerp = p;
            peerp = &mut (*p).next;
        }

        us.peers.set(peers);
    }

    // implicitly defined upstream has no backup servers

    Ok(())
}

/// ngx_http_upstream_create_sid
unsafe fn create_sid(arena: &Arena, peer: *mut RrPeer, route: &[u8]) {
    if !route.is_empty() {
        (*peer).route = true;
        (*peer).sid = arena.dup(route);
        return;
    }

    (*peer).sid.data = arena.calloc(NGX_HTTP_UPSTREAM_SID_LEN);

    init_round_robin_sid(peer, None);
}

/// ngx_http_upstream_init_round_robin_sid: the route, or the md5 of the
/// peer's printable address; sid.data has room for either.
pub unsafe fn init_round_robin_sid(peer: *mut RrPeer, route: Option<&[u8]>) {
    if let Some(route) = route.filter(|r| !r.is_empty()) {
        (*peer).route = true;
        (*peer).sid.len = route.len();
        std::ptr::copy_nonoverlapping(route.as_ptr(), (*peer).sid.data, route.len());
        return;
    }

    (*peer).route = false;

    // SID is the MD5 hash of a printable socket address

    if (*peer).name.len == 0 {
        (*peer).sid.len = 0;
        return;
    }

    use md5::{Digest, Md5};
    let hash = Md5::digest((*peer).name.bytes());
    let hex: Vec<u8> = hash.iter().flat_map(|b| format!("{:02x}", b).into_bytes()).collect();

    std::ptr::copy_nonoverlapping(hex.as_ptr(), (*peer).sid.data, NGX_HTTP_UPSTREAM_SID_LEN);
    (*peer).sid.len = NGX_HTTP_UPSTREAM_SID_LEN;
}

/// ngx_http_upstream_copy_round_robin_sid
pub unsafe fn copy_round_robin_sid(dst: *mut RrPeer, src: *mut RrPeer) {
    let route = if (*src).route { Some((*src).sid.bytes()) } else { None };
    init_round_robin_sid(dst, route);
}

/// ngx_http_upstream_rr_peer_data_t
pub struct RrPeerData {
    pub config: usize,
    pub peers: *mut RrPeers,
    pub current: *mut RrPeer,
    pub tried: Vec<usize>,
    /// keeps the peers alive: the upstream's, or the request's own
    pub upstream: Option<Rc<UpstreamSrvConf>>,
    pub arena: Option<Arena>,
}

const UINTPTR_BITS: usize = usize::BITS as usize;

impl RrPeerData {
    fn tried_bitmap(n: usize) -> Vec<usize> {
        vec![0; n.div_ceil(UINTPTR_BITS).max(1)]
    }

    pub fn is_tried(&self, i: usize) -> bool {
        self.tried.get(i / UINTPTR_BITS).is_some_and(|t| t & (1 << (i % UINTPTR_BITS)) != 0)
    }

    pub fn set_tried(&mut self, i: usize) {
        let n = i / UINTPTR_BITS;
        if n >= self.tried.len() {
            self.tried.resize(n + 1, 0);
        }
        self.tried[n] |= 1 << (i % UINTPTR_BITS);
    }

    /// The zone's peers changed since the request started.
    pub unsafe fn config_changed(&self) -> bool {
        !(*self.peers).config.is_null() && self.config != *(*self.peers).config
    }
}

/// ngx_http_upstream_init_round_robin_peer
pub fn init_round_robin_peer(_r: &R, us: &Rc<UpstreamSrvConf>) -> Result<RrPeerData, ()> {
    let peers = us.peers.get();

    if peers.is_null() {
        return Err(());
    }

    unsafe {
        peers_rlock(peers);

        let config = if (*peers).config.is_null() { 0 } else { *(*peers).config };

        let mut n = (*peers).number;

        if !(*peers).next.is_null() && (*(*peers).next).number > n {
            n = (*(*peers).next).number;
        }

        peers_unlock(peers);

        Ok(RrPeerData { config, peers, current: null_mut(), tried: RrPeerData::tried_bitmap(n), upstream: Some(us.clone()), arena: None })
    }
}

/// ngx_http_upstream_create_round_robin_peer: the peers of addresses
/// resolved for this request, in its memory.
pub fn create_round_robin_peer(host: &[u8], addrs: Vec<Addr>) -> RrPeerData {
    let arena = Arena::default();

    let n = addrs.len();

    unsafe {
        let peers = arena.alloc::<RrPeers>();
        let peer = arena.alloc_n::<RrPeer>(n);

        let name = arena.alloc::<NgxStr>();
        *name = arena.dup(host);

        (*peers).single = n == 1;
        (*peers).number = n;
        (*peers).tries = n;
        (*peers).name = name;

        let mut peerp: *mut *mut RrPeer = &mut (*peers).peer;

        for (i, a) in addrs.iter().enumerate() {
            let p = peer.add(i);
            let (sa, len) = arena.sockaddr(&a.sockaddr);
            (*p).sockaddr = sa;
            (*p).socklen = len;
            (*p).name = arena.dup(&a.name);
            (*p).weight = 1;
            (*p).effective_weight = 1;
            (*p).current_weight = 0;
            (*p).max_conns = 0;
            (*p).max_fails = 1;
            (*p).fail_timeout = 10;
            *peerp = p;
            peerp = &mut (*p).next;
        }

        RrPeerData { config: 0, peers, current: null_mut(), tried: RrPeerData::tried_bitmap(n), upstream: None, arena: Some(arena) }
    }
}

impl PeerBalancer for RrPeerData {
    fn tries(&self) -> u32 {
        unsafe { upstream_tries(self.peers) as u32 }
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_round_robin_peer(pc, self)
    }

    fn free(&mut self, pc: &mut PeerConnection, state: u32, _us: &UpstreamState) {
        free_round_robin_peer(pc, self, state);
    }

    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        set_round_robin_peer_session(self)
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        save_round_robin_peer_session(self, session)
    }

    fn rr(&mut self) -> Option<&mut RrPeerData> {
        Some(self)
    }
}

/// pc->sockaddr, pc->name and pc->sid of a chosen peer.
pub unsafe fn connect_peer(pc: &mut PeerConnection, peer: *mut RrPeer) {
    pc.sockaddr = Some(peer_sockaddr(peer));
    pc.name = (*peer).name.bytes().to_vec();
    pc.sid = Some((*peer).sid.bytes().to_vec());
}

/// ngx_http_upstream_get_round_robin_peer
pub fn get_round_robin_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get rr peer, try: {}", pc.tries);

    pc.cached = false;
    pc.connection = None;

    unsafe {
        let peers = rrp.peers;
        peers_wlock(peers);

        let failed = 'pick: {
            if rrp.config_changed() {
                // busy
                peers_unlock(peers);

                pc.name = (*(*peers).name).bytes().to_vec();

                return NGX_BUSY;
            }

            let peer = if (*peers).single {
                let mut i = 0;
                let mut peer = get_rr_peer_by_sid(rrp, pc.hint.as_deref(), &mut i, false);

                if peer.is_null() {
                    peer = (*peers).peer;

                    if (*peer).down != 0 {
                        break 'pick true;
                    }

                    if (*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns {
                        break 'pick true;
                    }
                }

                rrp.current = peer;
                peer_ref(peers, peer);

                peer
            } else {
                // there are several peers

                let peer = get_peer(rrp, pc);

                if peer.is_null() {
                    break 'pick true;
                }

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get rr peer, current: {:p} {}", peer, (*peer).current_weight);

                peer
            };

            connect_peer(pc, peer);

            (*peer).conns += 1;

            peers_unlock(peers);

            false
        };

        if !failed {
            return NGX_OK;
        }

        // failed:

        if !(*peers).next.is_null() {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "backup servers");

            rrp.peers = (*peers).next;

            let n = (*rrp.peers).number.div_ceil(UINTPTR_BITS);

            for i in 0..n.min(rrp.tried.len()) {
                rrp.tried[i] = 0;
            }

            peers_unlock(peers);

            let rc = get_round_robin_peer(pc, rrp);

            if rc != NGX_BUSY {
                return rc;
            }

            peers_wlock(peers);
        }

        // busy:

        peers_unlock(peers);

        pc.name = (*(*peers).name).bytes().to_vec();

        NGX_BUSY
    }
}

/// ngx_http_upstream_get_peer: smooth weighted round robin over the peers
/// not tried yet, not down, failed or at max_conns; a sticky peer is
/// preferred while its weight allows.
pub unsafe fn get_peer(rrp: &mut RrPeerData, pc: &mut PeerConnection) -> *mut RrPeer {
    let now = ngx_core::times::time();

    let mut best: *mut RrPeer = null_mut();
    let mut total: isize = 0;

    let mut p = 0usize;

    let st_peer = get_rr_peer_by_sid(rrp, pc.hint.as_deref(), &mut p, false);

    'best_chosen: {
        if !st_peer.is_null() {
            let low_limit = -(((*rrp.peers).total_weight as isize) - (*st_peer).weight);

            // note: current code accounts only one sticky request in a row,
            //       if it is required to account more, multiply low_limit
            //       by N below
            if (*st_peer).current_weight <= low_limit {
                // do not update weights if the limit exceeded
                best = st_peer;
                break 'best_chosen;
            }
            // else: proceed to reweight with existing st_peer
        }

        let st_p = p;

        let mut peer = (*rrp.peers).peer;
        let mut i = 0;

        while !peer.is_null() {
            if rrp.is_tried(i)
                || (*peer).down != 0
                || ((*peer).max_fails != 0 && (*peer).fails >= (*peer).max_fails && now - (*peer).checked <= (*peer).fail_timeout)
                || ((*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns)
            {
                peer = (*peer).next;
                i += 1;
                continue;
            }

            (*peer).current_weight += (*peer).effective_weight;
            total += (*peer).effective_weight;

            if (*peer).effective_weight < (*peer).weight {
                (*peer).effective_weight += 1;
            }

            if best.is_null() || (*peer).current_weight > (*best).current_weight {
                best = peer;
                p = i;
            }

            peer = (*peer).next;
            i += 1;
        }

        // prefer peer chosen by sticky to best from RR

        if !st_peer.is_null() {
            best = st_peer;
            p = st_p;
        }

        if best.is_null() {
            return null_mut();
        }

        (*best).current_weight -= total;
    }

    // best_chosen:

    rrp.current = best;
    peer_ref(rrp.peers, best);

    rrp.set_tried(p);

    if now - (*best).checked > (*best).fail_timeout {
        (*best).checked = now;
    }

    best
}

/// ngx_http_upstream_get_rr_peer_by_sid: the peer the sticky hint names,
/// if it is not tried yet and can take the request (a draining peer can);
/// locked if asked.
pub unsafe fn get_rr_peer_by_sid(rrp: &RrPeerData, hint: Option<&[u8]>, p: &mut usize, lock: bool) -> *mut RrPeer {
    let hint = match hint {
        Some(h) => h,
        None => return null_mut(),
    };

    let mut peer = (*rrp.peers).peer;
    let mut i = 0;

    while !peer.is_null() {
        if (*peer).sid.bytes() == hint {
            break;
        }

        peer = (*peer).next;
        i += 1;
    }

    if peer.is_null() {
        return null_mut();
    }

    // found:

    if rrp.is_tried(i) {
        return null_mut();
    }

    if lock {
        peer_lock(rrp.peers, peer);
    }

    let failed = (*peer).down & !NGX_HTTP_UPSTREAM_DRAINING != 0
        || ((*peer).max_fails != 0 && (*peer).fails >= (*peer).max_fails && ngx_core::times::time() - (*peer).checked <= (*peer).fail_timeout)
        || ((*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns);

    if failed {
        if lock {
            peer_unlock(rrp.peers, peer);
        }

        return null_mut();
    }

    *p = i;
    peer
}

/// ngx_http_upstream_free_round_robin_peer
pub fn free_round_robin_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData, state: u32) {
    unsafe {
        peers_rlock(rrp.peers);
        peer_lock(rrp.peers, rrp.current);
    }

    free_round_robin_peer_locked(pc, rrp, state);
}

/// ngx_http_upstream_free_round_robin_peer_locked: with the peers read
/// locked and the peer locked, which it unlocks
pub fn free_round_robin_peer_locked(pc: &mut PeerConnection, rrp: &mut RrPeerData, state: u32) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "free rr peer {} {}", pc.tries, state);

    // TODO: NGX_PEER_KEEPALIVE

    unsafe {
        let peer = rrp.current;

        if (*rrp.peers).single {
            if (*peer).fails != 0 {
                (*peer).fails = 0;
            }

            (*peer).conns -= 1;

            if peer_unref(rrp.peers, peer) == NGX_OK {
                peer_unlock(rrp.peers, peer);
            }

            peers_unlock(rrp.peers);

            pc.tries = 0;
            return;
        }

        if state & NGX_PEER_FAILED != 0 {
            let now = ngx_core::times::time();

            (*peer).fails += 1;
            (*peer).accessed = now;
            (*peer).checked = now;

            if (*peer).max_fails != 0 {
                (*peer).effective_weight -= (*peer).weight / (*peer).max_fails as isize;

                if (*peer).fails >= (*peer).max_fails {
                    ngx_log_error!(NGX_LOG_WARN, pc.log, None, "upstream server temporarily disabled");
                }
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "free rr peer failed: {:p} {}", peer, (*peer).effective_weight);

            if (*peer).effective_weight < 0 {
                (*peer).effective_weight = 0;
            }
        } else {
            // mark peer live if check passed

            if (*peer).accessed < (*peer).checked {
                (*peer).fails = 0;
            }
        }

        (*peer).conns -= 1;

        if peer_unref(rrp.peers, peer) == NGX_OK {
            peer_unlock(rrp.peers, peer);
        }

        peers_unlock(rrp.peers);
    }

    if pc.tries > 0 {
        pc.tries -= 1;
    }
}

/// ngx_http_upstream_set_round_robin_peer_session
pub fn set_round_robin_peer_session(rrp: &mut RrPeerData) -> Option<openssl::ssl::SslSession> {
    // per-request peers have no sessions (ngx_http_upstream_empty_set_session)
    if rrp.arena.is_some() || rrp.current.is_null() {
        return None;
    }

    unsafe {
        let peers = rrp.peers;
        let peer = rrp.current;

        peers_rlock(peers);
        peer_lock(peers, peer);

        if (*peer).ssl_session.is_null() {
            peer_unlock(peers, peer);
            peers_unlock(peers);
            return None;
        }

        let der = std::slice::from_raw_parts((*peer).ssl_session, (*peer).ssl_session_len as usize).to_vec();

        peer_unlock(peers, peer);
        peers_unlock(peers);

        openssl::ssl::SslSession::from_der(&der).ok()
    }
}

/// ngx_http_upstream_save_round_robin_peer_session
pub fn save_round_robin_peer_session(rrp: &mut RrPeerData, session: openssl::ssl::SslSession) {
    // ngx_http_upstream_empty_save_session
    if rrp.arena.is_some() || rrp.current.is_null() {
        return;
    }

    let der = match session.to_der() {
        Ok(d) => d,
        Err(_) => return,
    };

    let len = der.len();

    // do not cache too big session

    if len > NGX_SSL_MAX_SESSION_SIZE {
        return;
    }

    unsafe {
        let peers = rrp.peers;
        let peer = rrp.current;

        peers_rlock(peers);
        peer_lock(peers, peer);

        if len > (*peer).ssl_session_len as usize {
            if !(*peers).shpool.is_null() {
                let pool = &*(*peers).shpool;

                pool.lock();

                if !(*peer).ssl_session.is_null() {
                    pool.free_locked((*peer).ssl_session);
                }

                (*peer).ssl_session = pool.alloc_locked(len);

                pool.unlock();
            } else {
                // a process's peer: its own buffer
                if !(*peer).ssl_session.is_null() {
                    libc::free((*peer).ssl_session as *mut libc::c_void);
                }

                (*peer).ssl_session = libc::malloc(len) as *mut u8;
            }

            if (*peer).ssl_session.is_null() {
                (*peer).ssl_session_len = 0;

                peer_unlock(peers, peer);
                peers_unlock(peers);
                return;
            }
        }

        (*peer).ssl_session_len = len as i32;

        std::ptr::copy_nonoverlapping(der.as_ptr(), (*peer).ssl_session, len);

        peer_unlock(peers, peer);
        peers_unlock(peers);
    }
}
