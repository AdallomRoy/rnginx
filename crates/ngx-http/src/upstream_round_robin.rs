//! ngx_http_upstream_round_robin.c: the peers of an upstream, the default
//! (smooth weighted) round-robin balancer, and the per-peer failure and
//! connection accounting the other balancers build on.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::inet::{Addr, SockAddr, Url};
use ngx_core::log::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::request::*;
use crate::upstream::*;

/// NGX_HTTP_UPSTREAM_SID_LEN: md5 in hex.
pub const NGX_HTTP_UPSTREAM_SID_LEN: usize = 32;

/// peer->down values.
pub const NGX_HTTP_UPSTREAM_FAILED: u32 = 1;
pub const NGX_HTTP_UPSTREAM_DRAINING: u32 = 8;

/// A resolvable server of a zone upstream (ngx_http_upstream_host_t).
pub struct UpstreamHost {
    pub name: Vec<u8>,
    pub service: Vec<u8>,
    pub valid: Cell<i64>,
    /// The peers list the resolved peers go into.
    pub peers: RefCell<Option<std::rc::Weak<RrPeers>>>,
    /// The template peer (the server's parameters).
    pub peer: RefCell<Option<Rc<RrPeer>>>,
    /// The resolve task of the worker, while it runs.
    pub task: RefCell<Option<tokio::task::JoinHandle<()>>>,
}

/// ngx_http_upstream_rr_peer_t
pub struct RrPeer {
    pub sockaddr: SockAddr,
    pub name: Vec<u8>,
    pub server: Vec<u8>,

    pub current_weight: Cell<i64>,
    pub effective_weight: Cell<i64>,
    pub weight: i64,

    pub conns: Cell<u64>,
    pub max_conns: u64,

    pub fails: Cell<u64>,
    pub accessed: Cell<i64>,
    pub checked: Cell<i64>,

    pub max_fails: u64,
    pub fail_timeout: i64,
    pub slow_start: u64,
    pub start_time: Cell<u64>,

    pub down: Cell<u32>,

    pub ssl_session: RefCell<Option<openssl::ssl::SslSession>>,

    /// sticky: the route (route=), or the md5 of the name
    pub route: bool,
    pub sid: Vec<u8>,

    /// zone: removed while still referenced
    pub zombie: Cell<bool>,
    pub refs: Cell<u64>,
    pub host: Option<Rc<UpstreamHost>>,

    /// least_time
    pub header_time: Cell<u64>,
    pub response_time: Cell<u64>,
    pub inflight_time: Cell<u64>,
    pub inflight_last: Cell<u64>,
    pub inflight_reqs_changed: Cell<u64>,
    pub inflight_reqs: Cell<u64>,
}

impl RrPeer {
    /// A peer with the parameters of a server.
    pub fn new(addr: &Addr, s: &UpstreamServer) -> RrPeer {
        RrPeer {
            sockaddr: addr.sockaddr.clone(),
            name: addr.name.clone(),
            server: s.name.clone(),
            current_weight: Cell::new(0),
            effective_weight: Cell::new(s.weight as i64),
            weight: s.weight as i64,
            conns: Cell::new(0),
            max_conns: s.max_conns as u64,
            fails: Cell::new(0),
            accessed: Cell::new(0),
            checked: Cell::new(0),
            max_fails: s.max_fails as u64,
            fail_timeout: s.fail_timeout,
            slow_start: s.slow_start,
            start_time: Cell::new(0),
            down: Cell::new(s.down),
            ssl_session: RefCell::new(None),
            route: false,
            sid: Vec::new(),
            zombie: Cell::new(false),
            refs: Cell::new(0),
            host: None,
            header_time: Cell::new(0),
            response_time: Cell::new(0),
            inflight_time: Cell::new(0),
            inflight_last: Cell::new(0),
            inflight_reqs_changed: Cell::new(0),
            inflight_reqs: Cell::new(0),
        }
    }

    /// A peer of an implicit upstream or of per-request addresses.
    fn implicit(sockaddr: SockAddr, name: Vec<u8>) -> RrPeer {
        let s = UpstreamServer { weight: 1, max_fails: 1, fail_timeout: 10, ..Default::default() };
        let mut p = RrPeer::new(&Addr { sockaddr, name }, &s);
        p.server = Vec::new();
        p
    }

    /// The peer does not take requests now: down, failed within
    /// fail_timeout, or at max_conns.
    pub fn unavailable(&self, now: i64) -> bool {
        if self.down.get() != 0 {
            return true;
        }

        if self.max_fails != 0 && self.fails.get() >= self.max_fails && now - self.checked.get() <= self.fail_timeout {
            return true;
        }

        self.max_conns != 0 && self.conns.get() >= self.max_conns
    }
}

/// ngx_http_upstream_rr_peers_t
pub struct RrPeers {
    pub number: Cell<usize>,
    pub total_weight: Cell<i64>,
    pub tries: Cell<usize>,
    pub single: Cell<bool>,
    pub weighted: Cell<bool>,
    pub name: Vec<u8>,
    pub next: RefCell<Option<Rc<RrPeers>>>,
    pub peer: RefCell<Vec<Rc<RrPeer>>>,

    /// zone: the peers are shared, and changed by resolving
    pub shared: bool,
    pub config: Option<Rc<Cell<u64>>>,
    pub resolve: RefCell<Vec<Rc<RrPeer>>>,
}

impl RrPeers {
    fn new(name: &[u8], peers: Vec<Rc<RrPeer>>, tries: usize, total_weight: i64, weighted: bool) -> RrPeers {
        RrPeers {
            number: Cell::new(peers.len()),
            total_weight: Cell::new(total_weight),
            tries: Cell::new(tries),
            single: Cell::new(peers.len() == 1),
            weighted: Cell::new(weighted),
            name: name.to_vec(),
            next: RefCell::new(None),
            peer: RefCell::new(peers),
            shared: false,
            config: None,
            resolve: RefCell::new(Vec::new()),
        }
    }

    pub fn peers(&self) -> Vec<Rc<RrPeer>> {
        self.peer.borrow().clone()
    }
}

/// ngx_http_upstream_tries
pub fn upstream_tries(p: &RrPeers) -> usize {
    p.tries.get() + p.next.borrow().as_ref().map_or(0, |n| n.tries.get())
}

/// ngx_http_upstream_init_round_robin: the peers of the upstream's servers,
/// the backup ones in peers.next; or, for an upstream implicitly defined by
/// proxy_pass and the like, the addresses its host resolves to.
pub fn init_round_robin(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    *us.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_round_robin_peer(r, us)?))
    }));

    let servers = us.servers.borrow();

    if let Some(servers) = servers.as_ref() {
        let zone = us.zone.borrow().is_some();

        let mut resolve = false;

        let (mut n, mut r, mut w, mut t) = (0usize, 0usize, 0i64, 0usize);

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
            w += s.addrs.len() as i64 * s.weight as i64;

            if s.down == 0 {
                t += s.addrs.len();
            }
        }

        if zone {
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

        let (list, resolve_list) = make_peers(servers, false);

        let peers = Rc::new(RrPeers::new(&us.host, list, t, w, w != n as i64));
        peers.number.set(n);
        peers.single.set(n == 1);
        *peers.resolve.borrow_mut() = resolve_list;

        // backup servers

        let (mut bn, mut br, mut bw, mut bt) = (0usize, 0usize, 0i64, 0usize);

        for s in servers.iter() {
            if !s.backup {
                continue;
            }

            if !s.host.is_empty() {
                br += 1;
                continue;
            }

            bn += s.addrs.len();
            bw += s.addrs.len() as i64 * s.weight as i64;

            if s.down == 0 {
                bt += s.addrs.len();
            }
        }

        if bn == 0 && !resolve || bn + br == 0 && us.flags.get() & NGX_HTTP_UPSTREAM_BACKUP == 0 {
            *us.peers.borrow_mut() = Some(peers);
            return Ok(());
        }

        let (blist, bresolve) = make_peers(servers, true);

        if bn > 0 {
            peers.single.set(false);
        }

        let backup = Rc::new(RrPeers::new(&us.host, blist, bt, bw, bw != bn as i64));
        backup.number.set(bn);
        backup.single.set(false);
        *backup.resolve.borrow_mut() = bresolve;

        *peers.next.borrow_mut() = Some(backup);

        *us.peers.borrow_mut() = Some(peers);

        return Ok(());
    }

    drop(servers);

    // an upstream implicitly defined by proxy_pass, etc.

    if us.port.get() == 0 {
        return Err(cf.emerg(format_args!("no port in upstream \"{}\" in {}:{}", B(&us.host), B(&us.file_name), us.line)));
    }

    let mut u = Url::default();
    u.host = us.host.clone();
    u.port = us.port.get();

    if ngx_core::inet::inet_resolve_host(&mut u).is_err() {
        if let Some(err) = u.err {
            return Err(cf.emerg(format_args!("{} in upstream \"{}\" in {}:{}", err, B(&us.host), B(&us.file_name), us.line)));
        }
        return Err(ConfError::Logged);
    }

    let n = u.addrs.len();

    let list: Vec<Rc<RrPeer>> = u.addrs.iter().map(|a| Rc::new(RrPeer::implicit(a.sockaddr.clone(), a.name.clone()))).collect();

    let peers = Rc::new(RrPeers::new(&us.host, list, n, n as i64, false));

    *us.peers.borrow_mut() = Some(peers);

    // implicitly defined upstream has no backup servers

    Ok(())
}

/// The peers of the servers (backup or not), and the resolvable ones.
fn make_peers(servers: &[UpstreamServer], backup: bool) -> (Vec<Rc<RrPeer>>, Vec<Rc<RrPeer>>) {
    let mut list = Vec::new();
    let mut resolve = Vec::new();

    for s in servers.iter() {
        if s.backup != backup {
            continue;
        }

        if !s.host.is_empty() {
            let host = Rc::new(UpstreamHost {
                name: s.host.clone(),
                service: s.service.clone(),
                valid: Cell::new(0),
                peers: RefCell::new(None),
                peer: RefCell::new(None),
                task: RefCell::new(None),
            });

            let mut p = RrPeer::new(&s.addrs[0], s);
            create_sid(&mut p, &s.sid);
            p.host = Some(host);

            resolve.push(Rc::new(p));
            continue;
        }

        for a in s.addrs.iter() {
            let mut p = RrPeer::new(a, s);
            create_sid(&mut p, &s.sid);
            list.push(Rc::new(p));
        }
    }

    (list, resolve)
}

/// ngx_http_upstream_create_sid
fn create_sid(peer: &mut RrPeer, route: &[u8]) {
    init_round_robin_sid(peer, route);
}

/// ngx_http_upstream_init_round_robin_sid: the route, or the md5 of the
/// peer's printable address.
pub fn init_round_robin_sid(peer: &mut RrPeer, route: &[u8]) {
    if !route.is_empty() {
        peer.route = true;
        peer.sid = route.to_vec();
        return;
    }

    peer.route = false;

    if peer.name.is_empty() {
        peer.sid.clear();
        return;
    }

    use md5::{Digest, Md5};
    let hash = Md5::digest(&peer.name);
    peer.sid = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>().into_bytes();
}

/// ngx_http_upstream_rr_peer_data_t
pub struct RrPeerData {
    pub config: u64,
    pub peers: Rc<RrPeers>,
    pub current: Option<Rc<RrPeer>>,
    pub tried: Vec<u64>,
}

impl RrPeerData {
    fn tried_bitmap(n: usize) -> Vec<u64> {
        vec![0; n.div_ceil(64).max(1)]
    }

    pub fn is_tried(&self, i: usize) -> bool {
        self.tried[i / 64] & (1 << (i % 64)) != 0
    }

    pub fn set_tried(&mut self, i: usize) {
        self.tried[i / 64] |= 1 << (i % 64);
    }

    /// Clear the tried bits for the backup peers.
    pub fn clear_tried(&mut self) {
        let n = self.peers.number.get().div_ceil(64).max(1);
        if self.tried.len() < n {
            self.tried.resize(n, 0);
        }
        for t in self.tried.iter_mut() {
            *t = 0;
        }
    }

    /// The zone's peers changed since the request started.
    pub fn config_changed(&self) -> bool {
        self.peers.config.as_ref().is_some_and(|c| c.get() != self.config)
    }
}

/// ngx_http_upstream_init_round_robin_peer
pub fn init_round_robin_peer(r: &R, us: &Rc<UpstreamSrvConf>) -> Result<RrPeerData, ()> {
    let peers = match us.peers.borrow().clone() {
        Some(p) => p,
        None => return Err(()),
    };

    let mut n = peers.number.get();

    if let Some(next) = peers.next.borrow().as_ref() {
        if next.number.get() > n {
            n = next.number.get();
        }
    }

    let config = peers.config.as_ref().map_or(0, |c| c.get());

    let _ = r;

    Ok(RrPeerData { config, peers, current: None, tried: RrPeerData::tried_bitmap(n) })
}

/// ngx_http_upstream_create_round_robin_peer: the peers of addresses
/// resolved for this request.
pub fn create_round_robin_peer(host: &[u8], addrs: Vec<Addr>) -> RrPeerData {
    let n = addrs.len();

    let list: Vec<Rc<RrPeer>> = addrs.into_iter().map(|a| Rc::new(RrPeer::implicit(a.sockaddr, a.name))).collect();

    let mut peers = RrPeers::new(host, list, n, 0, false);
    peers.total_weight.set(0);
    let peers = Rc::new(peers);

    RrPeerData { config: 0, peers, current: None, tried: RrPeerData::tried_bitmap(n) }
}

impl PeerBalancer for RrPeerData {
    fn tries(&self) -> u32 {
        upstream_tries(&self.peers) as u32
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_round_robin_peer(pc, self)
    }

    fn free(&mut self, pc: &mut PeerConnection, state: u32, _us: &UpstreamState) {
        free_round_robin_peer(pc, self, state);
    }

    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        self.current.as_ref().and_then(|p| p.ssl_session.borrow().clone())
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        if let Some(p) = self.current.as_ref() {
            *p.ssl_session.borrow_mut() = Some(session);
        }
    }

    fn rr(&mut self) -> Option<&mut RrPeerData> {
        Some(self)
    }
}

/// ngx_http_upstream_get_round_robin_peer
pub fn get_round_robin_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get rr peer, try: {}", pc.tries);

    pc.cached = false;
    pc.connection = None;

    let peers = rrp.peers.clone();

    let failed = 'pick: {
        if rrp.config_changed() {
            // busy
            pc.name = peers.name.clone();
            return NGX_BUSY;
        }

        let peer = if peers.single.get() {
            let mut i = 0;
            let peer = match get_rr_peer_by_sid(rrp, pc.hint.as_deref(), &mut i) {
                Some(p) => p,
                None => {
                    let peer = match peers.peer.borrow().first().cloned() {
                        Some(p) => p,
                        None => break 'pick true,
                    };

                    if peer.down.get() != 0 {
                        break 'pick true;
                    }

                    if peer.max_conns != 0 && peer.conns.get() >= peer.max_conns {
                        break 'pick true;
                    }

                    peer
                }
            };

            rrp.current = Some(peer.clone());
            peer.refs.set(peer.refs.get() + 1);
            peer
        } else {
            // there are several peers
            match get_peer(rrp, pc) {
                Some(p) => {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get rr peer, current: {} {}", B(&p.name), p.current_weight.get());
                    p
                }
                None => break 'pick true,
            }
        };

        pc.sockaddr = Some(peer.sockaddr.clone());
        pc.name = peer.name.clone();
        pc.sid = Some(peer.sid.clone());

        peer.conns.set(peer.conns.get() + 1);

        false
    };

    if !failed {
        return NGX_OK;
    }

    let next = peers.next.borrow().clone();

    if let Some(next) = next {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "backup servers");

        rrp.peers = next;
        rrp.clear_tried();

        let rc = get_round_robin_peer(pc, rrp);

        if rc != NGX_BUSY {
            return rc;
        }
    }

    pc.name = peers.name.clone();

    NGX_BUSY
}

/// ngx_http_upstream_get_peer: smooth weighted round robin over the peers
/// not tried yet, not down, failed or at max_conns; a sticky peer is
/// preferred while its weight allows.
pub fn get_peer(rrp: &mut RrPeerData, pc: &mut PeerConnection) -> Option<Rc<RrPeer>> {
    let now = ngx_core::times::time();

    let mut best: Option<(Rc<RrPeer>, usize)> = None;
    let mut total = 0i64;

    let mut p = 0usize;
    let st_peer = get_rr_peer_by_sid(rrp, pc.hint.as_deref(), &mut p);

    if let Some(st) = st_peer.as_ref() {
        let low_limit = -(rrp.peers.total_weight.get() - st.weight);

        // note: current code accounts only one sticky request in a row, if it
        //       is required to account more, multiply low_limit by N below
        if st.current_weight.get() <= low_limit {
            // do not update weights if the limit exceeded
            return Some(chosen(rrp, st.clone(), p, now));
        }
    }

    let st_p = p;

    let list = rrp.peers.peers();

    for (i, peer) in list.iter().enumerate() {
        if rrp.is_tried(i) {
            continue;
        }

        if peer.unavailable(now) {
            continue;
        }

        peer.current_weight.set(peer.current_weight.get() + peer.effective_weight.get());
        total += peer.effective_weight.get();

        if peer.effective_weight.get() < peer.weight {
            peer.effective_weight.set(peer.effective_weight.get() + 1);
        }

        if best.as_ref().is_none_or(|(b, _)| peer.current_weight.get() > b.current_weight.get()) {
            best = Some((peer.clone(), i));
        }
    }

    // prefer peer chosen by sticky to best from RR
    if let Some(st) = st_peer {
        best = Some((st, st_p));
    }

    let (best, p) = best?;

    best.current_weight.set(best.current_weight.get() - total);

    Some(chosen(rrp, best, p, now))
}

fn chosen(rrp: &mut RrPeerData, best: Rc<RrPeer>, p: usize, now: i64) -> Rc<RrPeer> {
    rrp.current = Some(best.clone());
    best.refs.set(best.refs.get() + 1);

    rrp.set_tried(p);

    if now - best.checked.get() > best.fail_timeout {
        best.checked.set(now);
    }

    best
}

/// ngx_http_upstream_get_rr_peer_by_sid: the peer the sticky hint names,
/// if it is not tried yet and can take the request (a draining peer can).
pub fn get_rr_peer_by_sid(rrp: &RrPeerData, hint: Option<&[u8]>, p: &mut usize) -> Option<Rc<RrPeer>> {
    let hint = hint?;

    let list = rrp.peers.peers();

    let (i, peer) = list.iter().enumerate().find(|(_, peer)| peer.sid.as_slice() == hint)?;

    if rrp.is_tried(i) {
        return None;
    }

    if peer.down.get() & !NGX_HTTP_UPSTREAM_DRAINING != 0 {
        return None;
    }

    if peer.max_fails != 0 && peer.fails.get() >= peer.max_fails && ngx_core::times::time() - peer.checked.get() <= peer.fail_timeout {
        return None;
    }

    if peer.max_conns != 0 && peer.conns.get() >= peer.max_conns {
        return None;
    }

    *p = i;
    Some(peer.clone())
}

/// ngx_http_upstream_free_round_robin_peer
pub fn free_round_robin_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData, state: u32) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "free rr peer {} {}", pc.tries, state);

    let peer = match rrp.current.clone() {
        Some(p) => p,
        None => return,
    };

    if rrp.peers.single.get() {
        if peer.fails.get() != 0 {
            peer.fails.set(0);
        }

        peer.conns.set(peer.conns.get().saturating_sub(1));
        peer_unref(&peer);

        pc.tries = 0;
        return;
    }

    if state & NGX_PEER_FAILED != 0 {
        let now = ngx_core::times::time();

        peer.fails.set(peer.fails.get() + 1);
        peer.accessed.set(now);
        peer.checked.set(now);

        if peer.max_fails != 0 {
            peer.effective_weight.set(peer.effective_weight.get() - peer.weight / peer.max_fails as i64);

            if peer.fails.get() >= peer.max_fails {
                ngx_log_error!(NGX_LOG_WARN, pc.log, None, "upstream server temporarily disabled");
            }
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "free rr peer failed: {} {}", B(&peer.name), peer.effective_weight.get());

        if peer.effective_weight.get() < 0 {
            peer.effective_weight.set(0);
        }
    } else {
        // mark peer live if check passed
        if peer.accessed.get() < peer.checked.get() {
            peer.fails.set(0);
        }
    }

    peer.conns.set(peer.conns.get().saturating_sub(1));
    peer_unref(&peer);

    if pc.tries > 0 {
        pc.tries -= 1;
    }
}

/// ngx_http_upstream_rr_peer_unref
fn peer_unref(peer: &RrPeer) {
    peer.refs.set(peer.refs.get().saturating_sub(1));
}
