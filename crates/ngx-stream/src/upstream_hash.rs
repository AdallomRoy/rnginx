//! ngx_stream_upstream_hash_module: "hash key [consistent]".

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::script::ComplexValue;
use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::*;

stream_module_index!("ngx_stream_upstream_hash_module");

struct ChashPoint {
    hash: u32,
    server: Vec<u8>,
}

/// ngx_stream_upstream_hash_srv_conf_t
pub struct HashConf {
    key: ComplexValue,
    config: Cell<u64>,
    points: RefCell<Option<Rc<Vec<ChashPoint>>>>,
}

/// The srv conf of the module in the upstream{} block: set by the
/// directive.
#[derive(Default)]
pub struct HashConfSlot {
    pub conf: Option<Rc<HashConf>>,
}

fn create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(HashConfSlot::default())
}

/// ngx_stream_conf_upstream_srv_conf(us, module)
fn module_conf(us: &UpstreamSrvConf) -> Option<Rc<HashConf>> {
    us.module_srv_conf::<HashConfSlot>(ctx_index())?.borrow().conf.clone()
}

/// ngx_stream_upstream_hash_peer_data_t
struct HashPeerData {
    rrp: RrPeerData,
    conf: Rc<HashConf>,
    key: Vec<u8>,
    tries: u32,
    rehash: u32,
    hash: u32,
    consistent: bool,
}

impl PeerBalancer for HashPeerData {
    fn tries(&self) -> u32 {
        upstream_tries(self.rrp.m(), self.rrp.peers) as u32
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        if self.consistent {
            get_chash_peer(pc, self)
        } else {
            get_hash_peer(pc, self)
        }
    }

    fn free(&mut self, pc: &mut PeerConnection, state: u32, _us: &UpstreamState) {
        free_round_robin_peer(pc, &mut self.rrp, state);
    }

    fn notify(&mut self, pc: &mut PeerConnection, ty: i32, notify: u32, _us: &UpstreamState) {
        notify_round_robin_peer(pc, &mut self.rrp, ty, notify);
    }

    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        set_round_robin_peer_session(&mut self.rrp)
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        save_round_robin_peer_session(&mut self.rrp, session)
    }

}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// ngx_stream_upstream_init_hash
fn init_hash(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|s: &S, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_hash_peer(s, us)?))
    }));

    Ok(())
}

/// ngx_stream_upstream_init_hash_peer
fn init_hash_peer(s: &S, us: &Rc<UpstreamSrvConf>) -> Result<HashPeerData, ()> {
    let rrp = init_round_robin_peer(s, us)?;

    let hcf = module_conf(us).ok_or(())?;

    let key = crate::script::complex_value(s, &hcf.key).map_err(|_| ())?;

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "upstream hash key:\"{}\"", B(&key));

    Ok(HashPeerData { rrp, conf: hcf, key, tries: 0, rehash: 0, hash: 0, consistent: false })
}

/// ngx_stream_upstream_get_hash_peer
fn get_hash_peer(pc: &mut PeerConnection, hp: &mut HashPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "get hash peer, try: {}", pc.tries);

    let pm = hp.rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = hp.rrp.peers;
    let ps = RrPeers::at(mem, peers);

    peers_rlock(mem, peers);

    if hp.tries > 20 || ps.get(RrPeers::number) < 2 || hp.key.is_empty() {
        peers_unlock(mem, peers);
        return get_round_robin_peer(pc, &mut hp.rrp);
    }

    if hp.rrp.config_changed() {
        peers_unlock(mem, peers);
        return get_round_robin_peer(pc, &mut hp.rrp);
    }

    let now = ngx_core::times::time();

    let mut p;

    let mut peer: usize;

    {
        loop {
            // Hash expression is compatible with Cache::Memcached:
            // ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
            // with REHASH omitted at the first iteration.

            let mut h = crc32fast::Hasher::new();

            if hp.rehash > 0 {
                h.update(hp.rehash.to_string().as_bytes());
            }

            h.update(&hp.key);

            let hash = (h.finalize() >> 16) & 0x7fff;

            hp.hash = hp.hash.wrapping_add(hash);
            hp.rehash += 1;

            let mut w = (hp.hash as usize % ps.get(RrPeers::total_weight)) as isize;
            peer = ps.get(RrPeers::peer);
            p = 0;

            while w >= RrPeer::at(mem, peer).get(RrPeer::weight) {
                w -= RrPeer::at(mem, peer).get(RrPeer::weight);
                peer = RrPeer::at(mem, peer).get(RrPeer::next);
                p += 1;
            }

            let skip = if hp.rrp.is_tried(p) {
                true
            } else {
                peer_lock(mem, peers, peer);

                ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "get hash peer, value:{}, peer:{}", hp.hash, p);

                let pp = RrPeer::at(mem, peer);

                let unavailable = pp.get(RrPeer::down) != 0 || pp.failed(now) || pp.max_conns_reached();

                if unavailable {
                    peer_unlock(mem, peers, peer);
                }

                unavailable
            };

            if !skip {
                break;
            }

            // next:

            hp.tries += 1;
            if hp.tries > 20 {
                peers_unlock(mem, peers);
                return get_round_robin_peer(pc, &mut hp.rrp);
            }
        }
    }

    // found:

    hp.rrp.current = peer;
    peer_ref(mem, peer);

    connect_peer(pc, mem, peer);

    let pp = RrPeer::at(mem, peer);

    pp.set(RrPeer::conns, pp.get(RrPeer::conns) + 1);

    if now - pp.get(RrPeer::checked) > pp.get(RrPeer::fail_timeout) {
        pp.set(RrPeer::checked, now);
    }

    peer_unlock(mem, peers, peer);
    peers_unlock(mem, peers);

    hp.rrp.set_tried(p);

    NGX_OK
}

/// ngx_stream_upstream_init_chash
fn init_chash(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|s: &S, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_chash_peer(s, us)?))
    }));

    if us.shm_zone.borrow().is_some() {
        return Ok(());
    }

    update_chash(us);
    Ok(())
}

/// The host and the port of a server name, as the points are made of them.
fn host_port(server: &[u8]) -> (&[u8], &[u8]) {
    if server.len() >= 5 && server[..5].eq_ignore_ascii_case(b"unix:") {
        return (&server[5..], &[]);
    }

    for j in 0..server.len() {
        let c = server[server.len() - j - 1];

        if c == b':' {
            return (&server[..server.len() - j - 1], &server[server.len() - j..]);
        }

        if !c.is_ascii_digit() {
            break;
        }
    }

    (server, &[])
}

/// ngx_stream_upstream_update_chash: 160 points per weight unit and server,
/// compatible with Cache::Memcached::Fast: crc32(HOST \0 PORT PREV_HASH).
fn update_chash(us: &Rc<UpstreamSrvConf>) {
    let hcf = match module_conf(us) {
        Some(c) => c,
        None => return,
    };

    let Peers { mem: pm, off: peers } = match us.peers.get() {
        Some(p) => p,
        None => return,
    };
    let mem = &*pm.mem;

    let ps = RrPeers::at(mem, peers);

    let mut points: Vec<ChashPoint> = Vec::with_capacity(ps.get(RrPeers::total_weight) * 160);

    let mut peer = ps.get(RrPeers::peer);

    while peer != 0 {
        let pp = RrPeer::at(mem, peer);

        let server = pp.server();

        let (host, port) = host_port(&server);

        let mut base = crc32fast::Hasher::new();
        base.update(host);
        base.update(&[0]);
        base.update(port);

        let mut prev_hash: u32 = 0;
        let npoints = pp.get(RrPeer::weight) as usize * 160;

        for _ in 0..npoints {
            let mut h = base.clone();
            h.update(&prev_hash.to_le_bytes());
            let hash = h.finalize();

            points.push(ChashPoint { hash, server: server.clone() });

            prev_hash = hash;
        }

        peer = pp.get(RrPeer::next);
    }

    points.sort_by_key(|p| p.hash);
    points.dedup_by_key(|p| p.hash);

    *hcf.points.borrow_mut() = Some(Rc::new(points));
}

/// ngx_stream_upstream_find_chash_point: the first point >= hash.
fn find_chash_point(points: &[ChashPoint], hash: u32) -> u32 {
    let (mut i, mut j) = (0usize, points.len());

    while i < j {
        let k = (i + j) / 2;

        if hash > points[k].hash {
            i = k + 1;
        } else if hash < points[k].hash {
            j = k;
        } else {
            return k as u32;
        }
    }

    i as u32
}

/// ngx_stream_upstream_init_chash_peer
fn init_chash_peer(s: &S, us: &Rc<UpstreamSrvConf>) -> Result<HashPeerData, ()> {
    let mut hp = init_hash_peer(s, us)?;
    hp.consistent = true;

    let hash = crc32(&hp.key);

    let pm = hp.rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = hp.rrp.peers;

    peers_rlock(mem, peers);

    let config = RrPeers::at(mem, peers).get(RrPeers::config);

    if config != 0 && (hp.conf.points.borrow().is_none() || hp.conf.config.get() != mem.get(config) as u64) {
        update_chash(us);
        hp.conf.config.set(mem.get(config) as u64);
    }

    let points = hp.conf.points.borrow().clone();

    if let Some(points) = points {
        if !points.is_empty() {
            hp.hash = find_chash_point(&points, hash);
        }
    }

    peers_unlock(mem, peers);

    Ok(hp)
}

/// ngx_stream_upstream_get_chash_peer
fn get_chash_peer(pc: &mut PeerConnection, hp: &mut HashPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "get consistent hash peer, try: {}", pc.tries);

    let pm = hp.rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = hp.rrp.peers;
    let ps = RrPeers::at(mem, peers);

    peers_wlock(mem, peers);

    if hp.tries > 20 || ps.get(RrPeers::single) != 0 || hp.key.is_empty() {
        peers_unlock(mem, peers);
        return get_round_robin_peer(pc, &mut hp.rrp);
    }

    if ps.get(RrPeers::number) == 0 {
        pc.name = Some(ps.name_bytes());
        peers_unlock(mem, peers);
        return NGX_BUSY;
    }

    if hp.rrp.config_changed() {
        pc.name = Some(ps.name_bytes());
        peers_unlock(mem, peers);
        return NGX_BUSY;
    }

    let now = ngx_core::times::time();

    let points = hp.conf.points.borrow().clone().unwrap_or_default();

    if points.is_empty() {
        peers_unlock(mem, peers);
        return get_round_robin_peer(pc, &mut hp.rrp);
    }

    let mut best_i;

    let mut best: usize;

    {
        loop {
            let server = &points[hp.hash as usize % points.len()].server;

            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "consistent hash peer:{}, server:\"{}\"", hp.hash, B(server));

            best = 0;
            best_i = 0;
            let mut total: isize = 0;

            let mut peer = ps.get(RrPeers::peer);
            let mut i = 0;

            while peer != 0 {
                let pp = RrPeer::at(mem, peer);

                let skip = hp.rrp.is_tried(i)
                    || pp.get(RrPeer::down) != 0
                    || pp.failed(now)
                    || pp.max_conns_reached()
                    || pp.get(RrPeer::server_len) != server.len()
                    || !mem.eq_bytes(pp.get(RrPeer::server_data), server);

                if !skip {
                    let effective_weight = pp.get(RrPeer::effective_weight);

                    pp.set(RrPeer::current_weight, pp.get(RrPeer::current_weight) + effective_weight);
                    total += effective_weight;

                    if effective_weight < pp.get(RrPeer::weight) {
                        pp.set(RrPeer::effective_weight, effective_weight + 1);
                    }

                    if best == 0 || pp.get(RrPeer::current_weight) > RrPeer::at(mem, best).get(RrPeer::current_weight) {
                        best = peer;
                        best_i = i;
                    }
                }

                peer = pp.get(RrPeer::next);
                i += 1;
            }

            if best != 0 {
                let b = RrPeer::at(mem, best);
                b.set(RrPeer::current_weight, b.get(RrPeer::current_weight) - total);
                break;
            }

            hp.hash = hp.hash.wrapping_add(1);
            hp.tries += 1;

            if hp.tries > 20 {
                peers_unlock(mem, peers);
                return get_round_robin_peer(pc, &mut hp.rrp);
            }
        }
    }

    // found:

    hp.rrp.current = best;
    peer_ref(mem, best);

    connect_peer(pc, mem, best);

    let b = RrPeer::at(mem, best);

    b.set(RrPeer::conns, b.get(RrPeer::conns) + 1);

    if now - b.get(RrPeer::checked) > b.get(RrPeer::fail_timeout) {
        b.set(RrPeer::checked, now);
    }

    peers_unlock(mem, peers);

    hp.rrp.set_tried(best_i);

    NGX_OK
}

/// ngx_stream_upstream_hash
fn hash_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = conf_upstream(cf).ok_or_else(|| msg("\"hash\" directive is not allowed here"))?;

    let value = cf.args.clone();

    let key = crate::script::compile_complex_value(cf, &value[1], &mut crate::script::CompileComplexValue::default())?;

    conf_rc::<HashConfSlot>(conf.as_ref().expect("conf")).borrow_mut().conf = Some(Rc::new(HashConf { key, config: Cell::new(0), points: RefCell::new(None) }));

    let flags = NGX_STREAM_UPSTREAM_CREATE
        | NGX_STREAM_UPSTREAM_MODIFY
        | NGX_STREAM_UPSTREAM_WEIGHT
        | NGX_STREAM_UPSTREAM_MAX_CONNS
        | NGX_STREAM_UPSTREAM_MAX_FAILS
        | NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
        | NGX_STREAM_UPSTREAM_DOWN;

    if value.len() == 2 {
        set_balancer(cf, &uscf, init_hash, flags);
    } else if value[2] == b"consistent" {
        set_balancer(cf, &uscf, init_chash, flags);
    } else {
        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
    }

    Ok(())
}

pub fn upstream_hash_module() -> ModuleDef {
    let commands = vec![cmd_fn!("hash", NGX_STREAM_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::Srv, hash_handler)];
    stream_module_def("ngx_stream_upstream_hash_module", StreamModuleDef { create_srv_conf: Some(create_srv_conf), ..Default::default() }, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_host_and_port() {
        assert_eq!(host_port(b"127.0.0.1:8080"), (&b"127.0.0.1"[..], &b"8080"[..]));
        assert_eq!(host_port(b"unix:/tmp/sock"), (&b"/tmp/sock"[..], &b""[..]));
        assert_eq!(host_port(b"example.com"), (&b"example.com"[..], &b""[..]));
    }

    #[test]
    fn chash_points() {
        let points: Vec<ChashPoint> = [10u32, 20, 30].iter().map(|&hash| ChashPoint { hash, server: Vec::new() }).collect();
        assert_eq!(find_chash_point(&points, 5), 0);
        assert_eq!(find_chash_point(&points, 20), 1);
        assert_eq!(find_chash_point(&points, 31), 3);
    }
}
