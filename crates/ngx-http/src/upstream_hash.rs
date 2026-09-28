//! ngx_http_upstream_hash_module: "hash key [consistent]".

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::request::*;
use crate::script::ComplexValue;
use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_TAKE12, NGX_HTTP_UPS_CONF};

struct ChashPoint {
    hash: u32,
    server: Vec<u8>,
}

/// ngx_http_upstream_hash_srv_conf_t
pub struct HashConf {
    key: ComplexValue,
    config: Cell<u64>,
    points: RefCell<Option<Rc<Vec<ChashPoint>>>>,
}

/// ngx_http_upstream_hash_peer_data_t
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
        unsafe { upstream_tries(self.rrp.peers) as u32 }
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

    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        set_round_robin_peer_session(&mut self.rrp)
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        save_round_robin_peer_session(&mut self.rrp, session)
    }

    fn rr(&mut self) -> Option<&mut RrPeerData> {
        Some(&mut self.rrp)
    }
}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// ngx_http_upstream_init_hash
fn init_hash(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_hash_peer(r, us)?))
    }));

    Ok(())
}

/// ngx_http_upstream_init_hash_peer
fn init_hash_peer(r: &R, us: &Rc<UpstreamSrvConf>) -> Result<HashPeerData, ()> {
    let rrp = init_round_robin_peer(r, us)?;

    let hcf = us.module_conf::<HashConf>().ok_or(())?;

    let key = crate::script::complex_value(r, &hcf.key).map_err(|_| ())?;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "upstream hash key:\"{}\"", B(&key));

    Ok(HashPeerData { rrp, conf: hcf, key, tries: 0, rehash: 0, hash: 0, consistent: false })
}

/// ngx_http_upstream_get_hash_peer
fn get_hash_peer(pc: &mut PeerConnection, hp: &mut HashPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get hash peer, try: {}", pc.tries);

    unsafe {
        let peers = hp.rrp.peers;

        peers_rlock(peers);

        if hp.tries > 20 || (*peers).number < 2 || hp.key.is_empty() {
            peers_unlock(peers);
            return get_round_robin_peer(pc, &mut hp.rrp);
        }

        if hp.rrp.config_changed() {
            peers_unlock(peers);
            return get_round_robin_peer(pc, &mut hp.rrp);
        }

        let now = ngx_core::times::time();

        pc.cached = false;
        pc.connection = None;

        let mut p = 0usize;

        let mut peer = get_rr_peer_by_sid(&hp.rrp, pc.hint.as_deref(), &mut p, true);

        if peer.is_null() {
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

                let mut w = (hp.hash as usize % (*peers).total_weight) as isize;
                peer = (*peers).peer;
                p = 0;

                while w >= (*peer).weight {
                    w -= (*peer).weight;
                    peer = (*peer).next;
                    p += 1;
                }

                let skip = if hp.rrp.is_tried(p) {
                    true
                } else {
                    peer_lock(peers, peer);

                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get hash peer, value:{}, peer:{}", hp.hash, p);

                    let unavailable = (*peer).down != 0
                        || ((*peer).max_fails != 0 && (*peer).fails >= (*peer).max_fails && now - (*peer).checked <= (*peer).fail_timeout)
                        || ((*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns);

                    if unavailable {
                        peer_unlock(peers, peer);
                    }

                    unavailable
                };

                if !skip {
                    break;
                }

                // next:

                hp.tries += 1;
                if hp.tries > 20 {
                    peers_unlock(peers);
                    return get_round_robin_peer(pc, &mut hp.rrp);
                }
            }
        }

        // found:

        hp.rrp.current = peer;
        peer_ref(peers, peer);

        connect_peer(pc, peer);

        (*peer).conns += 1;

        if now - (*peer).checked > (*peer).fail_timeout {
            (*peer).checked = now;
        }

        peer_unlock(peers, peer);
        peers_unlock(peers);

        hp.rrp.set_tried(p);
    }

    NGX_OK
}

/// ngx_http_upstream_init_chash
fn init_chash(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_chash_peer(r, us)?))
    }));

    if us.shm_zone.borrow().is_some() {
        return Ok(());
    }

    update_chash(us);
    Ok(())
}

/// ngx_http_upstream_update_chash: 160 points per weight unit and server,
/// compatible with Cache::Memcached::Fast: crc32(HOST \0 PORT PREV_HASH).
fn update_chash(us: &Rc<UpstreamSrvConf>) {
    let hcf = match us.module_conf::<HashConf>() {
        Some(c) => c,
        None => return,
    };

    let peers = us.peers.get();

    if peers.is_null() {
        return;
    }

    unsafe {
        let mut points: Vec<ChashPoint> = Vec::with_capacity((*peers).total_weight * 160);

        let mut peer = (*peers).peer;

        while !peer.is_null() {
            let server = (*peer).server.bytes();

            let (host, port): (&[u8], &[u8]) = if server.len() >= 5 && server[..5].eq_ignore_ascii_case(b"unix:") {
                (&server[5..], &[])
            } else {
                let mut split = None;
                for j in 0..server.len() {
                    let c = server[server.len() - j - 1];
                    if c == b':' {
                        split = Some((&server[..server.len() - j - 1], &server[server.len() - j..]));
                        break;
                    }
                    if !c.is_ascii_digit() {
                        break;
                    }
                }
                split.unwrap_or((server, &[]))
            };

            let mut base = crc32fast::Hasher::new();
            base.update(host);
            base.update(&[0]);
            base.update(port);

            let mut prev_hash: u32 = 0;
            let npoints = (*peer).weight as usize * 160;

            for _ in 0..npoints {
                let mut h = base.clone();
                h.update(&prev_hash.to_le_bytes());
                let hash = h.finalize();

                points.push(ChashPoint { hash, server: server.to_vec() });

                prev_hash = hash;
            }

            peer = (*peer).next;
        }

        points.sort_by_key(|p| p.hash);
        points.dedup_by_key(|p| p.hash);

        *hcf.points.borrow_mut() = Some(Rc::new(points));
    }
}

/// ngx_http_upstream_find_chash_point: the first point >= hash.
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

/// ngx_http_upstream_init_chash_peer
fn init_chash_peer(r: &R, us: &Rc<UpstreamSrvConf>) -> Result<HashPeerData, ()> {
    let mut hp = init_hash_peer(r, us)?;
    hp.consistent = true;

    let hash = crc32(&hp.key);

    unsafe {
        let peers = hp.rrp.peers;

        peers_rlock(peers);

        if !(*peers).config.is_null() && (hp.conf.points.borrow().is_none() || hp.conf.config.get() != *(*peers).config as u64) {
            update_chash(us);
            hp.conf.config.set(*(*peers).config as u64);
        }

        let points = hp.conf.points.borrow().clone();

        if let Some(points) = points {
            if !points.is_empty() {
                hp.hash = find_chash_point(&points, hash);
            }
        }

        peers_unlock(peers);
    }

    Ok(hp)
}

/// ngx_http_upstream_get_chash_peer
fn get_chash_peer(pc: &mut PeerConnection, hp: &mut HashPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get consistent hash peer, try: {}", pc.tries);

    unsafe {
        let peers = hp.rrp.peers;

        peers_wlock(peers);

        if hp.tries > 20 || (*peers).single || hp.key.is_empty() {
            peers_unlock(peers);
            return get_round_robin_peer(pc, &mut hp.rrp);
        }

        pc.cached = false;
        pc.connection = None;

        if (*peers).number == 0 {
            pc.name = (*(*peers).name).bytes().to_vec();
            peers_unlock(peers);
            return NGX_BUSY;
        }

        if hp.rrp.config_changed() {
            pc.name = (*(*peers).name).bytes().to_vec();
            peers_unlock(peers);
            return NGX_BUSY;
        }

        let now = ngx_core::times::time();

        let points = hp.conf.points.borrow().clone().unwrap_or_default();

        if points.is_empty() {
            peers_unlock(peers);
            return get_round_robin_peer(pc, &mut hp.rrp);
        }

        let mut best_i = 0usize;

        let mut best = get_rr_peer_by_sid(&hp.rrp, pc.hint.as_deref(), &mut best_i, false);

        if best.is_null() {
            loop {
                let server = &points[hp.hash as usize % points.len()].server;

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "consistent hash peer:{}, server:\"{}\"", hp.hash, B(server));

                best = std::ptr::null_mut();
                best_i = 0;
                let mut total: isize = 0;

                let mut peer = (*peers).peer;
                let mut i = 0;

                while !peer.is_null() {
                    let skip = hp.rrp.is_tried(i)
                        || (*peer).down != 0
                        || ((*peer).max_fails != 0 && (*peer).fails >= (*peer).max_fails && now - (*peer).checked <= (*peer).fail_timeout)
                        || ((*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns)
                        || (*peer).server.bytes() != server.as_slice();

                    if !skip {
                        (*peer).current_weight += (*peer).effective_weight;
                        total += (*peer).effective_weight;

                        if (*peer).effective_weight < (*peer).weight {
                            (*peer).effective_weight += 1;
                        }

                        if best.is_null() || (*peer).current_weight > (*best).current_weight {
                            best = peer;
                            best_i = i;
                        }
                    }

                    peer = (*peer).next;
                    i += 1;
                }

                if !best.is_null() {
                    (*best).current_weight -= total;
                    break;
                }

                hp.hash = hp.hash.wrapping_add(1);
                hp.tries += 1;

                if hp.tries > 20 {
                    peers_unlock(peers);
                    return get_round_robin_peer(pc, &mut hp.rrp);
                }
            }
        }

        // found:

        hp.rrp.current = best;
        peer_ref(peers, best);

        connect_peer(pc, best);

        (*best).conns += 1;

        if now - (*best).checked > (*best).fail_timeout {
            (*best).checked = now;
        }

        peers_unlock(peers);

        hp.rrp.set_tried(best_i);
    }

    NGX_OK
}

/// ngx_http_upstream_hash
fn hash_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"hash\" directive is not allowed here"))?;

    let value = cf.args.clone();

    let key = crate::script::compile_complex_value(cf, &value[1], 0)?;

    uscf.set_module_conf(Rc::new(HashConf { key, config: Cell::new(0), points: RefCell::new(None) }));

    let flags = NGX_HTTP_UPSTREAM_CREATE
        | NGX_HTTP_UPSTREAM_MODIFY
        | NGX_HTTP_UPSTREAM_WEIGHT
        | NGX_HTTP_UPSTREAM_MAX_CONNS
        | NGX_HTTP_UPSTREAM_MAX_FAILS
        | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
        | NGX_HTTP_UPSTREAM_DOWN;

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
    let commands = vec![cmd_fn!("hash", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::None, hash_handler)];
    http_module_def("ngx_http_upstream_hash_module", HttpModuleDef::default(), commands)
}
