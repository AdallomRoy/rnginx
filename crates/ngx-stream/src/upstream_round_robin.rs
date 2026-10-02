//! ngx_stream_upstream_round_robin.c: the peers of an upstream, the
//! default (smooth weighted) round robin balancer, and the per-peer failure
//! and connection accounting the other balancers build on.
//!
//! Peers are the C structures, laid out as C lays them out, in a ShmMem,
//! their "pointers" offsets in it (0 for NULL). With "zone" it is the
//! zone's memory (upstream_zone.rs copies the peers there), where the
//! workers share them under the peers' rwlock and each peer's lock, and
//! where the servers resolved at run time come and go. Without, it is a
//! memory of the process made for the peers of the upstream (C allocates
//! them from cf->pool), or for the addresses resolved for a session
//! (s->connection->pool).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::Ordering;

use ngx_core::conf::*;
use ngx_core::inet::{Addr, SockAddr, Url};
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::shmem::slab::SlabPool;
use ngx_core::shmem::ShmMem;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error, shm_struct};

use crate::upstream::*;
use crate::*;

/// peer->down values.
pub const NGX_STREAM_UPSTREAM_FAILED: usize = 1;

/// NGX_SOCKADDR_STRLEN
pub const NGX_SOCKADDR_STRLEN: usize = 112;

/// sizeof(ngx_sockaddr_t): the room of a peer's address in a zone
pub const NGX_SOCKADDRLEN: usize = 112;

/// NGX_SSL_MAX_SESSION_SIZE
pub const NGX_SSL_MAX_SESSION_SIZE: usize = 4096;

shm_struct! {
    /// ngx_str_t
    pub struct NgxStr {
        len: usize,
        data: usize,
    }
}

shm_struct! {
    /// ngx_stream_upstream_host_t: a server resolved at run time, in a
    /// zone; its resolve timer (the event C keeps first) is a task of the
    /// worker (upstream_zone.rs)
    pub struct UpstreamHost {
        worker: usize,
        name_len: usize,
        name_data: usize,
        service_len: usize,
        service_data: usize,
        valid: i64,
        peers: usize,
        peer: usize,
    }
}

shm_struct! {
    /// ngx_stream_upstream_rr_peer_t
    pub struct RrPeer {
        /// the address: a struct sockaddr of socklen bytes
        sockaddr: usize,
        socklen: u32,
        name_len: usize,
        name_data: usize,
        server_len: usize,
        server_data: usize,

        current_weight: isize,
        effective_weight: isize,
        weight: isize,

        conns: usize,
        max_conns: usize,

        fails: usize,
        accessed: i64,
        checked: i64,

        max_fails: usize,
        fail_timeout: i64,
        slow_start: u64,
        start_time: u64,

        down: usize,

        /// the saved session, DER, of a peer in a zone (one of the process
        /// keeps its session in PeerMem::sessions)
        ssl_session: usize,
        ssl_session_len: i32,

        /// zombie:1 (a bit of an unsigned in C)
        zombie: u8,

        lock: usize,
        refs: usize,
        host: usize,

        next: usize,

        connect_time: u64,
        first_byte_time: u64,
        response_time: u64,
        inflight_time: u64,
        inflight_last: u64,
        inflight_reqs_changed: u64,
        inflight_reqs: usize,
    }
}

shm_struct! {
    /// ngx_stream_upstream_rr_peers_t
    pub struct RrPeers {
        number: usize,

        /// peers->shpool: here a flag, the peers are in a zone (its slab
        /// pool is at its start)
        shpool: usize,
        rwlock: usize,
        /// the zone's counter of the changes of its peers
        config: usize,
        resolve: usize,
        zone_next: usize,

        total_weight: usize,
        tries: usize,

        /// single:1 and weighted:1 (bits of an unsigned in C)
        single: u8,
        weighted: u8,

        /// an ngx_str_t
        name: usize,

        next: usize,

        peer: usize,
    }
}

impl NgxStr<'_> {
    /// The bytes of the string.
    pub fn bytes(&self) -> Vec<u8> {
        self.mem.bytes(self.get(NgxStr::data), self.get(NgxStr::len))
    }
}

impl UpstreamHost<'_> {
    /// host->name
    pub fn name(&self) -> Vec<u8> {
        self.mem.bytes(self.get(UpstreamHost::name_data), self.get(UpstreamHost::name_len))
    }

    /// host->service
    pub fn service(&self) -> Vec<u8> {
        self.mem.bytes(self.get(UpstreamHost::service_data), self.get(UpstreamHost::service_len))
    }
}

impl RrPeer<'_> {
    /// peer->name
    pub fn name(&self) -> Vec<u8> {
        self.mem.bytes(self.get(RrPeer::name_data), self.get(RrPeer::name_len))
    }

    /// peer->server
    pub fn server(&self) -> Vec<u8> {
        self.mem.bytes(self.get(RrPeer::server_data), self.get(RrPeer::server_len))
    }

    /// peer->sockaddr: the address of the peer (a struct sockaddr as
    /// SockAddr::raw_bytes() lays it out).
    pub fn addr(&self) -> SockAddr {
        let sa = self.mem.bytes(self.get(RrPeer::sockaddr), self.get(RrPeer::socklen) as usize);
        SockAddr::from_raw_bytes(&sa).expect("peer sockaddr")
    }

    /// peer->max_fails && peer->fails >= peer->max_fails
    /// && now - peer->checked <= peer->fail_timeout
    pub fn failed(&self, now: i64) -> bool {
        let max_fails = self.get(RrPeer::max_fails);

        max_fails != 0 && self.get(RrPeer::fails) >= max_fails && now - self.get(RrPeer::checked) <= self.get(RrPeer::fail_timeout)
    }

    /// peer->max_conns && peer->conns >= peer->max_conns
    pub fn max_conns_reached(&self) -> bool {
        let max_conns = self.get(RrPeer::max_conns);

        max_conns != 0 && self.get(RrPeer::conns) >= max_conns
    }
}

impl RrPeers<'_> {
    /// *peers->name
    pub fn name_bytes(&self) -> Vec<u8> {
        NgxStr::at(self.mem, self.get(RrPeers::name)).bytes()
    }
}

/// The alignment of what is allocated in a memory of the process.
const ALIGN: usize = std::mem::size_of::<usize>();

#[inline]
fn align(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

/// The memory the peers of an upstream are in: a zone's (with its slab
/// pool), or one of the process, where the peers are allocated one after
/// another and stay as long as the memory.
pub struct PeerMem {
    pub mem: Rc<ShmMem>,
    /// the first free byte of a memory of the process
    next: Cell<usize>,
    /// The sessions saved with the peers of a memory of the process, by
    /// peer (C keeps the SSL_SESSION in peer->ssl_session).
    sessions: RefCell<HashMap<usize, openssl::ssl::SslSession>>,
}

impl PeerMem {
    /// The memory of a zone.
    pub fn zone(mem: Rc<ShmMem>) -> Rc<PeerMem> {
        Rc::new(PeerMem { mem, next: Cell::new(0), sessions: RefCell::new(HashMap::new()) })
    }

    /// A memory of the process with room for `size` bytes of peers.
    pub fn process(size: usize) -> std::io::Result<Rc<PeerMem>> {
        let ps = ngx_core::os::pagesize();
        let mem = ShmMem::private((ALIGN + size).div_ceil(ps) * ps)?;

        Ok(Rc::new(PeerMem { mem: Rc::new(mem), next: Cell::new(ALIGN), sessions: RefCell::new(HashMap::new()) }))
    }

    /// ngx_pcalloc() in a memory of the process: the offset of `size`
    /// bytes, zeroed as a new mapping is.
    pub fn alloc(&self, size: usize) -> usize {
        let p = self.next.get();
        let end = p + align(size.max(1));

        assert!(end <= self.mem.len(), "the {} bytes of the memory of peers are exhausted", self.mem.len());

        self.next.set(end);
        p
    }

    /// A copy of bytes in a memory of the process: the data of an
    /// ngx_str_t (NULL for an empty one).
    pub fn dup(&self, s: &[u8]) -> usize {
        if s.is_empty() {
            return 0;
        }

        let p = self.alloc(s.len());
        self.mem.write(p, s);
        p
    }

    /// An ngx_str_t in a memory of the process.
    fn str(&self, s: &[u8]) -> usize {
        let p = self.alloc(NgxStr::SIZE);
        let n = NgxStr::at(&self.mem, p);
        n.set(NgxStr::data, self.dup(s));
        n.set(NgxStr::len, s.len());
        p
    }
}

/// us->peer.data of the round robin based balancers: the peers of the
/// upstream (an ngx_stream_upstream_rr_peers_t) in their memory.
#[derive(Clone)]
pub struct Peers {
    pub mem: Rc<PeerMem>,
    pub off: usize,
}

/// The peers of an upstream (UpstreamSrvConf::peers), once initialized.
#[derive(Default)]
pub struct UpstreamPeers {
    peers: RefCell<Option<Peers>>,
}

impl UpstreamPeers {
    pub fn get(&self) -> Option<Peers> {
        self.peers.borrow().clone()
    }

    pub fn set(&self, peers: Peers) {
        *self.peers.borrow_mut() = Some(peers);
    }
}

// ngx_stream_upstream_rr_peers_rlock() and the like: no-ops unless the
// peers are in shared memory

#[inline]
fn in_zone(mem: &ShmMem, peers: usize) -> bool {
    RrPeers::at(mem, peers).get(RrPeers::shpool) != 0
}

#[inline]
pub fn peers_rlock(mem: &ShmMem, peers: usize) {
    if in_zone(mem, peers) {
        ngx_core::rwlock::rlock(mem.word(peers + RrPeers::rwlock.off));
    }
}

#[inline]
pub fn peers_wlock(mem: &ShmMem, peers: usize) {
    if in_zone(mem, peers) {
        ngx_core::rwlock::wlock(mem.word(peers + RrPeers::rwlock.off));
    }
}

#[inline]
pub fn peers_unlock(mem: &ShmMem, peers: usize) {
    if in_zone(mem, peers) {
        ngx_core::rwlock::unlock(mem.word(peers + RrPeers::rwlock.off));
    }
}

#[inline]
pub fn peer_lock(mem: &ShmMem, peers: usize, peer: usize) {
    if in_zone(mem, peers) {
        ngx_core::rwlock::wlock(mem.word(peer + RrPeer::lock.off));
    }
}

#[inline]
pub fn peer_unlock(mem: &ShmMem, peers: usize, peer: usize) {
    if in_zone(mem, peers) {
        ngx_core::rwlock::unlock(mem.word(peer + RrPeer::lock.off));
    }
}

/// ngx_stream_upstream_rr_peer_ref
#[inline]
pub fn peer_ref(mem: &ShmMem, peer: usize) {
    let p = RrPeer::at(mem, peer);
    p.set(RrPeer::refs, p.get(RrPeer::refs) + 1);
}

/// ngx_stream_upstream_rr_peer_free_locked
pub fn peer_free_locked(mem: &ShmMem, _peers: usize, peer: usize) {
    let p = RrPeer::at(mem, peer);

    if p.get(RrPeer::refs) != 0 {
        p.set(RrPeer::zombie, 1);
        return;
    }

    let pool = SlabPool::of(mem);

    pool.free_locked(p.get(RrPeer::sockaddr));
    pool.free_locked(p.get(RrPeer::name_data));

    if p.get(RrPeer::server_data) != 0 {
        pool.free_locked(p.get(RrPeer::server_data));
    }

    if p.get(RrPeer::ssl_session) != 0 {
        pool.free_locked(p.get(RrPeer::ssl_session));
    }

    pool.free_locked(peer);
}

/// ngx_stream_upstream_rr_peer_free
pub fn peer_free(mem: &ShmMem, peers: usize, peer: usize) {
    let pool = SlabPool::of(mem);
    pool.lock();
    peer_free_locked(mem, peers, peer);
    pool.unlock();
}

/// ngx_stream_upstream_rr_peer_unref
pub fn peer_unref(mem: &ShmMem, peers: usize, peer: usize) -> i64 {
    let p = RrPeer::at(mem, peer);

    p.set(RrPeer::refs, p.get(RrPeer::refs).wrapping_sub(1));

    if !in_zone(mem, peers) {
        return NGX_OK;
    }

    if p.get(RrPeer::refs) == 0 && p.get(RrPeer::zombie) != 0 {
        peer_free(mem, peers, peer);
        return NGX_DONE;
    }

    NGX_OK
}

/// ngx_stream_upstream_response_time_avg: exponential moving average with
/// rounding
pub fn response_time_avg(avg: u64, v: u64) -> u64 {
    if avg != 0 {
        (0.5 + (v as f64 * 0.05 + avg as f64 * 0.95)) as u64
    } else {
        v
    }
}

/// ngx_stream_upstream_tries
pub fn upstream_tries(mem: &ShmMem, peers: usize) -> usize {
    let p = RrPeers::at(mem, peers);
    let next = p.get(RrPeers::next);

    p.get(RrPeers::tries) + if next == 0 { 0 } else { RrPeers::at(mem, next).get(RrPeers::tries) }
}

/// (*peers->config)++: the zone's counter of the changes of its peers
pub fn config_inc(mem: &ShmMem, config: usize) {
    mem.word(config).fetch_add(1, Ordering::Relaxed);
}

/// The room the peers of `servers` take in a memory of the process, at
/// most: the peers of the servers and of the backup ones, their name, and
/// the peers with their strings.
fn servers_size(host: &[u8], servers: &[UpstreamServer]) -> usize {
    let mut size = 2 * align(RrPeers::SIZE) + align(NgxStr::SIZE) + align(host.len());

    for s in servers.iter() {
        let addrs = if s.host.is_empty() { &s.addrs[..] } else { &s.addrs[..1.min(s.addrs.len())] };

        for a in addrs.iter() {
            size += RrPeer::SIZE + align(NGX_SOCKADDRLEN) + align(a.name.len()) + align(s.name.len());
        }

        if !s.host.is_empty() {
            size += align(UpstreamHost::SIZE) + align(s.host.len()) + align(s.service.len());
        }
    }

    size
}

/// The room of the peers of addresses in a memory of the process.
fn addrs_size(host: &[u8], addrs: &[Addr]) -> usize {
    let mut size = align(RrPeers::SIZE) + align(NgxStr::SIZE) + align(host.len());

    for a in addrs.iter() {
        size += RrPeer::SIZE + align(NGX_SOCKADDRLEN) + align(a.name.len());
    }

    size
}

/// The address of a peer of a memory of the process.
fn set_peer_sockaddr(pm: &PeerMem, peer: usize, sa: &SockAddr) {
    let p = RrPeer::at(&pm.mem, peer);
    let bytes = sa.raw_bytes();

    p.set(RrPeer::sockaddr, pm.dup(&bytes));
    p.set(RrPeer::socklen, bytes.len() as u32);
}

/// Fill a peer with the parameters of a server.
fn set_peer(pm: &PeerMem, peer: usize, addr: &Addr, s: &UpstreamServer) {
    let p = RrPeer::at(&pm.mem, peer);

    set_peer_sockaddr(pm, peer, &addr.sockaddr);
    p.set(RrPeer::name_data, pm.dup(&addr.name));
    p.set(RrPeer::name_len, addr.name.len());
    p.set(RrPeer::weight, s.weight as isize);
    p.set(RrPeer::effective_weight, s.weight as isize);
    p.set(RrPeer::current_weight, 0);
    p.set(RrPeer::max_conns, s.max_conns as usize);
    p.set(RrPeer::max_fails, s.max_fails as usize);
    p.set(RrPeer::fail_timeout, s.fail_timeout);
    p.set(RrPeer::down, s.down as usize);
    p.set(RrPeer::server_data, pm.dup(&s.name));
    p.set(RrPeer::server_len, s.name.len());
}

/// The peers of the servers, backup or not, with the ones resolved at run
/// time, in an array of `number` peers.
fn make_peers(pm: &PeerMem, servers: &[UpstreamServer], backup: bool, peers: usize, number: usize) {
    let mem = &*pm.mem;

    let peer = pm.alloc(RrPeer::SIZE * number);

    let mut n = 0;

    let mut peerp = peers + RrPeers::peer.off;
    let mut rpeerp = peers + RrPeers::resolve.off;

    for s in servers.iter() {
        if s.backup != backup {
            continue;
        }

        if !s.host.is_empty() {
            let p = peer + n * RrPeer::SIZE;

            let host = pm.alloc(UpstreamHost::SIZE);
            let h = UpstreamHost::at(mem, host);
            h.set(UpstreamHost::name_data, pm.dup(&s.host));
            h.set(UpstreamHost::name_len, s.host.len());
            h.set(UpstreamHost::service_data, pm.dup(&s.service));
            h.set(UpstreamHost::service_len, s.service.len());
            RrPeer::at(mem, p).set(RrPeer::host, host);

            set_peer(pm, p, &s.addrs[0], s);

            mem.set(rpeerp, p);
            rpeerp = p + RrPeer::next.off;
            n += 1;

            continue;
        }

        for a in s.addrs.iter() {
            let p = peer + n * RrPeer::SIZE;

            set_peer(pm, p, a, s);

            mem.set(peerp, p);
            peerp = p + RrPeer::next.off;
            n += 1;
        }
    }
}

/// An ngx_stream_upstream_rr_peers_t of a memory of the process.
fn new_peers(pm: &PeerMem, name: usize, number: usize, total_weight: usize, tries: usize, single: bool, weighted: bool) -> usize {
    let peers = pm.alloc(RrPeers::SIZE);
    let ps = RrPeers::at(&pm.mem, peers);

    ps.set(RrPeers::single, single as u8);
    ps.set(RrPeers::number, number);
    ps.set(RrPeers::weighted, weighted as u8);
    ps.set(RrPeers::total_weight, total_weight);
    ps.set(RrPeers::tries, tries);
    ps.set(RrPeers::name, name);

    peers
}

fn mmap_failed(cf: &Conf, size: usize, e: std::io::Error) -> ConfError {
    ngx_log_error!(NGX_LOG_EMERG, cf.log, e.raw_os_error(), "mmap(MAP_ANON|MAP_PRIVATE, {}) failed", size);
    ConfError::Logged
}

/// ngx_stream_upstream_init_round_robin: the peers of the upstream's
/// servers, the backup ones in peers.next; or, for an upstream implicitly
/// defined by proxy_pass, the addresses its host resolves to.
pub fn init_round_robin(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    *us.init.borrow_mut() = Some(Rc::new(|s: &S, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_round_robin_peer(s, us)?))
    }));

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
            if resolve && us.flags.get() & NGX_STREAM_UPSTREAM_MODIFY == 0 {
                return Err(cf.emerg(format_args!(
                    "load balancing method does not support resolving names at run time in upstream \"{}\" in {}:{}",
                    B(&us.host),
                    B(&us.file_name),
                    us.line
                )));
            }

            let cscf = crate::core::core_srv_conf(cf);
            let (resolver, resolver_timeout) = {
                let cscf = cscf.borrow();
                (cscf.resolver.clone(), cscf.resolver_timeout.as_option().copied())
            };

            if us.resolver.borrow().is_none() {
                *us.resolver.borrow_mut() = resolver;
            }

            // Without "resolver_timeout" in stream{} the merged value is unset.
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

        let size = servers_size(&us.host, servers);

        let pm = PeerMem::process(size).map_err(|e| mmap_failed(cf, size, e))?;

        let name = pm.str(&us.host);

        let peers = new_peers(&pm, name, n, w, t, n == 1, w != n);

        make_peers(&pm, servers, false, peers, n + r);

        us.peers.set(Peers { mem: pm.clone(), off: peers });

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

        if n + r == 0 && us.flags.get() & NGX_STREAM_UPSTREAM_BACKUP == 0 {
            return Ok(());
        }

        let backup = new_peers(&pm, name, n, w, t, false, w != n);

        if n > 0 {
            RrPeers::at(&pm.mem, peers).set(RrPeers::single, 0);
        }

        make_peers(&pm, servers, true, backup, n + r);

        RrPeers::at(&pm.mem, peers).set(RrPeers::next, backup);

        return Ok(());
    }

    drop(servers);

    // an upstream implicitly defined by proxy_pass, etc.

    if us.port == 0 {
        return Err(cf.emerg(format_args!("no port in upstream \"{}\" in {}:{}", B(&us.host), B(&us.file_name), us.line)));
    }

    let mut u = Url::default();
    u.host = us.host.clone();
    u.port = us.port;

    if ngx_core::inet::inet_resolve_host(&mut u).is_err() {
        if let Some(err) = u.err {
            return Err(cf.emerg(format_args!("{} in upstream \"{}\" in {}:{}", err, B(&us.host), B(&us.file_name), us.line)));
        }
        return Err(ConfError::Logged);
    }

    let size = addrs_size(&us.host, &u.addrs);

    let pm = PeerMem::process(size).map_err(|e| mmap_failed(cf, size, e))?;

    let peers = addrs_peers(&pm, &us.host, &u.addrs, true);

    us.peers.set(Peers { mem: pm, off: peers });

    // implicitly defined upstream has no backup servers

    Ok(())
}

/// The peers of addresses, weight 1 each: of an implicitly defined
/// upstream, or resolved for a session (without total_weight).
fn addrs_peers(pm: &PeerMem, host: &[u8], addrs: &[Addr], weights: bool) -> usize {
    let mem = &*pm.mem;

    let n = addrs.len();

    let name = pm.str(host);

    let peers = new_peers(pm, name, n, if weights { n } else { 0 }, n, n == 1, false);

    let peer = pm.alloc(RrPeer::SIZE * n);

    let mut peerp = peers + RrPeers::peer.off;

    for (i, a) in addrs.iter().enumerate() {
        let p = peer + i * RrPeer::SIZE;
        let pp = RrPeer::at(mem, p);

        set_peer_sockaddr(pm, p, &a.sockaddr);
        pp.set(RrPeer::name_data, pm.dup(&a.name));
        pp.set(RrPeer::name_len, a.name.len());
        pp.set(RrPeer::weight, 1);
        pp.set(RrPeer::effective_weight, 1);
        pp.set(RrPeer::current_weight, 0);
        pp.set(RrPeer::max_conns, 0);
        pp.set(RrPeer::max_fails, 1);
        pp.set(RrPeer::fail_timeout, 10);

        mem.set(peerp, p);
        peerp = p + RrPeer::next.off;
    }

    peers
}

/// ngx_stream_upstream_rr_peer_data_t
pub struct RrPeerData {
    pub config: usize,
    /// the memory of the peers, which it keeps: the upstream's (its zone's)
    /// or the session's own
    pub mem: Rc<PeerMem>,
    /// the ngx_stream_upstream_rr_peers_t in use
    pub peers: usize,
    /// the peer chosen, 0 before
    pub current: usize,
    pub tried: Vec<usize>,
    /// the peers of addresses resolved for the session: they have no
    /// sessions (ngx_stream_upstream_empty_set_session)
    pub resolved: bool,
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

    /// The memory of the peers.
    pub fn m(&self) -> &ShmMem {
        &self.mem.mem
    }

    /// The zone's peers changed since the session started.
    pub fn config_changed(&self) -> bool {
        let config = RrPeers::at(self.m(), self.peers).get(RrPeers::config);
        config != 0 && self.config != self.m().get(config)
    }
}

/// ngx_stream_upstream_init_round_robin_peer
pub fn init_round_robin_peer(_s: &S, us: &Rc<UpstreamSrvConf>) -> Result<RrPeerData, ()> {
    let Peers { mem: pm, off: peers } = us.peers.get().ok_or(())?;
    let mem = &*pm.mem;

    let ps = RrPeers::at(mem, peers);

    peers_rlock(mem, peers);

    let config = ps.get(RrPeers::config);
    let config = if config == 0 { 0 } else { mem.get(config) };

    let mut n = ps.get(RrPeers::number);

    let next = ps.get(RrPeers::next);

    if next != 0 && RrPeers::at(mem, next).get(RrPeers::number) > n {
        n = RrPeers::at(mem, next).get(RrPeers::number);
    }

    peers_unlock(mem, peers);

    Ok(RrPeerData { config, mem: pm.clone(), peers, current: 0, tried: RrPeerData::tried_bitmap(n), resolved: false })
}

/// ngx_stream_upstream_create_round_robin_peer: the peers of addresses
/// resolved for this session, in its memory.
pub fn create_round_robin_peer(host: &[u8], addrs: Vec<Addr>) -> RrPeerData {
    let n = addrs.len();

    // the memory of the session: failing a page, the process is out of
    // memory as with any allocation
    let pm = PeerMem::process(addrs_size(host, &addrs)).expect("the memory of the peers of a session");

    let peers = addrs_peers(&pm, host, &addrs, false);

    RrPeerData { config: 0, mem: pm, peers, current: 0, tried: RrPeerData::tried_bitmap(n), resolved: true }
}

impl PeerBalancer for RrPeerData {
    fn tries(&self) -> u32 {
        upstream_tries(self.m(), self.peers) as u32
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_round_robin_peer(pc, self)
    }

    fn free(&mut self, pc: &mut PeerConnection, state: u32, _us: &UpstreamState) {
        free_round_robin_peer(pc, self, state);
    }

    fn notify(&mut self, pc: &mut PeerConnection, ty: i32, notify: u32, _us: &UpstreamState) {
        notify_round_robin_peer(pc, self, ty, notify);
    }

    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        set_round_robin_peer_session(self)
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        save_round_robin_peer_session(self, session)
    }
}

/// The address of a peer for messages (%p).
pub fn peer_ptr(mem: &ShmMem, peer: usize) -> usize {
    mem.addr() as usize + peer
}

/// pc->sockaddr and pc->name of a chosen peer.
pub fn connect_peer(pc: &mut PeerConnection, mem: &ShmMem, peer: usize) {
    let p = RrPeer::at(mem, peer);

    pc.sockaddr = Some(p.addr());
    pc.name = Some(p.name());
}

/// ngx_stream_upstream_get_round_robin_peer
pub fn get_round_robin_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "get rr peer, try: {}", pc.tries);

    let pm = rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = rrp.peers;
    let ps = RrPeers::at(mem, peers);

    peers_wlock(mem, peers);

    let failed = 'pick: {
        if rrp.config_changed() {
            // busy
            peers_unlock(mem, peers);

            pc.name = Some(ps.name_bytes());

            return NGX_BUSY;
        }

        let peer = if ps.get(RrPeers::single) != 0 {
            let peer = ps.get(RrPeers::peer);

            let p = RrPeer::at(mem, peer);

            if p.get(RrPeer::down) != 0 {
                break 'pick true;
            }

            if p.max_conns_reached() {
                break 'pick true;
            }

            rrp.current = peer;
            peer_ref(mem, peer);

            peer
        } else {
            // there are several peers

            let peer = get_peer(rrp);

            if peer == 0 {
                break 'pick true;
            }

            ngx_log_debug!(
                NGX_LOG_DEBUG_STREAM,
                pc.log,
                "get rr peer, current: {:#x} {}",
                peer_ptr(mem, peer),
                RrPeer::at(mem, peer).get(RrPeer::current_weight)
            );

            peer
        };

        connect_peer(pc, mem, peer);

        let p = RrPeer::at(mem, peer);
        p.set(RrPeer::conns, p.get(RrPeer::conns) + 1);

        peers_unlock(mem, peers);

        false
    };

    if !failed {
        return NGX_OK;
    }

    // failed:

    let next = ps.get(RrPeers::next);

    if next != 0 {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "backup servers");

        rrp.peers = next;

        let n = RrPeers::at(mem, next).get(RrPeers::number).div_ceil(UINTPTR_BITS);

        for i in 0..n.min(rrp.tried.len()) {
            rrp.tried[i] = 0;
        }

        peers_unlock(mem, peers);

        let rc = get_round_robin_peer(pc, rrp);

        if rc != NGX_BUSY {
            return rc;
        }

        peers_wlock(mem, peers);
    }

    // busy:

    peers_unlock(mem, peers);

    pc.name = Some(ps.name_bytes());

    NGX_BUSY
}

/// ngx_stream_upstream_get_peer: smooth weighted round robin over the
/// peers not tried yet, not down, failed or at max_conns
pub fn get_peer(rrp: &mut RrPeerData) -> usize {
    let pm = rrp.mem.clone();
    let mem = &*pm.mem;

    let now = ngx_core::times::time();

    let mut best = 0usize;
    let mut total: isize = 0;

    let mut p = 0usize;

    let mut peer = RrPeers::at(mem, rrp.peers).get(RrPeers::peer);
    let mut i = 0;

    while peer != 0 {
        let pp = RrPeer::at(mem, peer);

        if rrp.is_tried(i) || pp.get(RrPeer::down) != 0 || pp.failed(now) || pp.max_conns_reached() {
            peer = pp.get(RrPeer::next);
            i += 1;
            continue;
        }

        let effective_weight = pp.get(RrPeer::effective_weight);

        pp.set(RrPeer::current_weight, pp.get(RrPeer::current_weight) + effective_weight);
        total += effective_weight;

        if effective_weight < pp.get(RrPeer::weight) {
            pp.set(RrPeer::effective_weight, effective_weight + 1);
        }

        if best == 0 || pp.get(RrPeer::current_weight) > RrPeer::at(mem, best).get(RrPeer::current_weight) {
            best = peer;
            p = i;
        }

        peer = pp.get(RrPeer::next);
        i += 1;
    }

    if best == 0 {
        return 0;
    }

    rrp.current = best;
    peer_ref(mem, best);

    rrp.set_tried(p);

    let b = RrPeer::at(mem, best);

    b.set(RrPeer::current_weight, b.get(RrPeer::current_weight) - total);

    if now - b.get(RrPeer::checked) > b.get(RrPeer::fail_timeout) {
        b.set(RrPeer::checked, now);
    }

    best
}

/// ngx_stream_upstream_free_round_robin_peer
pub fn free_round_robin_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData, state: u32) {
    peers_rlock(rrp.m(), rrp.peers);
    peer_lock(rrp.m(), rrp.peers, rrp.current);

    free_round_robin_peer_locked(pc, rrp, state);
}

/// ngx_stream_upstream_free_round_robin_peer_locked: with the peers read
/// locked and the peer locked, which it unlocks
pub fn free_round_robin_peer_locked(pc: &mut PeerConnection, rrp: &mut RrPeerData, state: u32) {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "free rr peer {} {}", pc.tries, state);

    let mem = rrp.m();
    let peers = rrp.peers;
    let peer = rrp.current;
    let p = RrPeer::at(mem, peer);

    if RrPeers::at(mem, peers).get(RrPeers::single) != 0 {
        if p.get(RrPeer::fails) != 0 {
            p.set(RrPeer::fails, 0);
        }

        p.set(RrPeer::conns, p.get(RrPeer::conns).wrapping_sub(1));

        if peer_unref(mem, peers, peer) == NGX_OK {
            peer_unlock(mem, peers, peer);
        }

        peers_unlock(mem, peers);

        pc.tries = 0;
        return;
    }

    if state & NGX_PEER_FAILED != 0 {
        let now = ngx_core::times::time();

        p.set(RrPeer::fails, p.get(RrPeer::fails) + 1);
        p.set(RrPeer::accessed, now);
        p.set(RrPeer::checked, now);

        let max_fails = p.get(RrPeer::max_fails);

        if max_fails != 0 {
            p.set(RrPeer::effective_weight, p.get(RrPeer::effective_weight) - p.get(RrPeer::weight) / max_fails as isize);

            if p.get(RrPeer::fails) >= max_fails {
                ngx_log_error!(NGX_LOG_WARN, pc.log, None, "upstream server temporarily disabled");
            }
        }

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "free rr peer failed: {:#x} {}", peer_ptr(mem, peer), p.get(RrPeer::effective_weight));

        if p.get(RrPeer::effective_weight) < 0 {
            p.set(RrPeer::effective_weight, 0);
        }
    } else {
        // mark peer live if check passed

        if p.get(RrPeer::accessed) < p.get(RrPeer::checked) {
            p.set(RrPeer::fails, 0);
        }
    }

    p.set(RrPeer::conns, p.get(RrPeer::conns).wrapping_sub(1));

    if peer_unref(mem, peers, peer) == NGX_OK {
        peer_unlock(mem, peers, peer);
    }

    peers_unlock(mem, peers);

    if pc.tries > 0 {
        pc.tries -= 1;
    }
}

/// ngx_stream_upstream_notify_round_robin_peer
pub fn notify_round_robin_peer(_pc: &mut PeerConnection, rrp: &mut RrPeerData, ty: i32, notify: u32) {
    let mem = rrp.m();
    let peers = rrp.peers;
    let peer = rrp.current;

    if notify == NGX_STREAM_UPSTREAM_NOTIFY_CONNECT && ty == libc::SOCK_STREAM {
        peers_rlock(mem, peers);
        peer_lock(mem, peers, peer);

        let p = RrPeer::at(mem, peer);

        if p.get(RrPeer::accessed) < p.get(RrPeer::checked) {
            p.set(RrPeer::fails, 0);
        }

        peer_unlock(mem, peers, peer);
        peers_unlock(mem, peers);
    }
}

/// ngx_stream_upstream_notify_round_robin_peer_locked: with the peers read
/// locked and the peer locked, which it unlocks
pub fn notify_round_robin_peer_locked(_pc: &mut PeerConnection, rrp: &mut RrPeerData, ty: i32, notify: u32) {
    let mem = rrp.m();
    let peers = rrp.peers;
    let peer = rrp.current;

    let p = RrPeer::at(mem, peer);

    if notify == NGX_STREAM_UPSTREAM_NOTIFY_CONNECT && ty == libc::SOCK_STREAM && p.get(RrPeer::accessed) < p.get(RrPeer::checked) {
        p.set(RrPeer::fails, 0);
    }

    peer_unlock(mem, peers, peer);
    peers_unlock(mem, peers);
}

/// ngx_stream_upstream_set_round_robin_peer_session
pub fn set_round_robin_peer_session(rrp: &mut RrPeerData) -> Option<openssl::ssl::SslSession> {
    // per-session peers have no sessions (ngx_stream_upstream_empty_set_session)
    if rrp.resolved || rrp.current == 0 {
        return None;
    }

    let mem = rrp.m();
    let peers = rrp.peers;
    let peer = rrp.current;

    if in_zone(mem, peers) {
        peers_rlock(mem, peers);
        peer_lock(mem, peers, peer);

        let p = RrPeer::at(mem, peer);

        if p.get(RrPeer::ssl_session) == 0 {
            peer_unlock(mem, peers, peer);
            peers_unlock(mem, peers);
            return None;
        }

        let der = mem.bytes(p.get(RrPeer::ssl_session), p.get(RrPeer::ssl_session_len) as usize);

        peer_unlock(mem, peers, peer);
        peers_unlock(mem, peers);

        return openssl::ssl::SslSession::from_der(&der).ok();
    }

    rrp.mem.sessions.borrow().get(&peer).cloned()
}

/// ngx_stream_upstream_save_round_robin_peer_session
pub fn save_round_robin_peer_session(rrp: &mut RrPeerData, session: openssl::ssl::SslSession) {
    // ngx_stream_upstream_empty_save_session
    if rrp.resolved || rrp.current == 0 {
        return;
    }

    let mem = rrp.m();
    let peers = rrp.peers;
    let peer = rrp.current;

    if in_zone(mem, peers) {
        let der = match session.to_der() {
            Ok(d) => d,
            Err(_) => return,
        };

        let len = der.len();

        // do not cache too big session

        if len > NGX_SSL_MAX_SESSION_SIZE {
            return;
        }

        peers_rlock(mem, peers);
        peer_lock(mem, peers, peer);

        let p = RrPeer::at(mem, peer);

        if len > p.get(RrPeer::ssl_session_len) as usize {
            let pool = SlabPool::of(mem);

            pool.lock();

            if p.get(RrPeer::ssl_session) != 0 {
                pool.free_locked(p.get(RrPeer::ssl_session));
            }

            p.set(RrPeer::ssl_session, pool.alloc_locked(len));

            pool.unlock();

            if p.get(RrPeer::ssl_session) == 0 {
                p.set(RrPeer::ssl_session_len, 0);

                peer_unlock(mem, peers, peer);
                peers_unlock(mem, peers);
                return;
            }

            p.set(RrPeer::ssl_session_len, len as i32);
        }

        mem.write(p.get(RrPeer::ssl_session), &der);

        peer_unlock(mem, peers, peer);
        peers_unlock(mem, peers);

        return;
    }

    // a peer of the process keeps the session (ngx_ssl_get_session)
    rrp.mem.sessions.borrow_mut().insert(peer, session);
}

#[cfg(test)]
mod tests {
    use super::*;

    use ngx_core::log::LogChain;

    #[test]
    fn layouts_are_c() {
        // x86-64 Linux, as ngx_stream_upstream_round_robin.h lays them out
        assert_eq!(RrPeer::SIZE, 256);
        assert_eq!(RrPeer::ssl_session_len.off, 160);
        assert_eq!(RrPeer::zombie.off, 164);
        assert_eq!(RrPeer::lock.off, 168);
        assert_eq!(RrPeer::next.off, 192);
        assert_eq!(RrPeer::inflight_reqs.off, 248);
        assert_eq!(RrPeers::SIZE, 96);
        assert_eq!(UpstreamHost::SIZE, 64);
    }

    #[test]
    fn peer_addresses() {
        let pm = PeerMem::process(4096).unwrap();
        let addrs = [
            SockAddr::v4(std::net::Ipv4Addr::new(127, 0, 0, 1), 8081),
            SockAddr::V6(std::net::SocketAddrV6::new("::1".parse().unwrap(), 443, 0, 0)),
            SockAddr::Unix(b"/tmp/sock".to_vec()),
        ];

        for sa in addrs.iter() {
            let peer = pm.alloc(RrPeer::SIZE);
            set_peer_sockaddr(&pm, peer, sa);
            assert_eq!(&RrPeer::at(&pm.mem, peer).addr(), sa);
        }
    }

    fn server(name: &str, addrs: &[(&str, u16)], weight: u32) -> UpstreamServer {
        UpstreamServer {
            name: name.as_bytes().to_vec(),
            addrs: addrs
                .iter()
                .map(|(ip, port)| {
                    let sa = SockAddr::v4(ip.parse().unwrap(), *port);
                    Addr { name: sa.to_text(true), sockaddr: sa }
                })
                .collect(),
            weight,
            max_fails: 1,
            fail_timeout: 10,
            ..Default::default()
        }
    }

    fn pc() -> PeerConnection {
        PeerConnection {
            sockaddr: None,
            name: None,
            tries: 10,
            start_time: 0,
            log: Log::new(LogChain::new()),
            log_error: 0,
            ty: libc::SOCK_STREAM,
            local: None,
            transparent: false,
            so_keepalive: false,
            rcvbuf: 0,
            sndbuf: 0,
        }
    }

    #[test]
    fn smooth_weighted_round_robin() {
        let servers = [server("a", &[("10.0.0.1", 80)], 5), server("b", &[("10.0.0.2", 80)], 1), server("c", &[("10.0.0.3", 80)], 1)];

        let pm = PeerMem::process(servers_size(b"backend", &servers)).unwrap();
        let name = pm.str(b"backend");
        let peers = new_peers(&pm, name, 3, 7, 3, false, true);
        make_peers(&pm, &servers, false, peers, 3);

        let mut rrp = RrPeerData { config: 0, mem: pm.clone(), peers, current: 0, tried: RrPeerData::tried_bitmap(3), resolved: false };

        let mut got = Vec::new();
        for _ in 0..7 {
            let mut pc = pc();
            rrp.tried.iter_mut().for_each(|t| *t = 0);
            assert_eq!(get_round_robin_peer(&mut pc, &mut rrp), NGX_OK);
            got.push(String::from_utf8(pc.name.clone().unwrap()).unwrap());
            notify_round_robin_peer(&mut pc, &mut rrp, libc::SOCK_STREAM, NGX_STREAM_UPSTREAM_NOTIFY_CONNECT);
            free_round_robin_peer(&mut pc, &mut rrp, 0);
        }

        assert_eq!(got, ["10.0.0.1:80", "10.0.0.1:80", "10.0.0.2:80", "10.0.0.1:80", "10.0.0.3:80", "10.0.0.1:80", "10.0.0.1:80"]);
    }

    #[test]
    fn session_peers() {
        let addrs: Vec<Addr> = ["127.0.0.1:1", "[::1]:2"]
            .iter()
            .map(|t| {
                let sa = ngx_core::inet::parse_addr_port(t.as_bytes()).unwrap();
                Addr { name: sa.to_text(true), sockaddr: sa }
            })
            .collect();

        let mut rrp = create_round_robin_peer(b"example.com", addrs);
        assert_eq!(rrp.tries(), 2);

        let mut pc = pc();
        assert_eq!(get_round_robin_peer(&mut pc, &mut rrp), NGX_OK);
        assert_eq!(pc.name.as_deref(), Some(&b"127.0.0.1:1"[..]));
        free_round_robin_peer(&mut pc, &mut rrp, NGX_PEER_FAILED);

        assert_eq!(get_round_robin_peer(&mut pc, &mut rrp), NGX_OK);
        assert_eq!(pc.name.as_deref(), Some(&b"[::1]:2"[..]));
        assert_eq!(pc.sockaddr, ngx_core::inet::parse_addr_port(b"[::1]:2"));
    }
}
