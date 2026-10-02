//! ngx_http_upstream_random_module: "random [two [least_conn]]".

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::random::random;
use ngx_core::shmem::ShmMem;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::request::*;
use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_NOARGS, NGX_CONF_TAKE12, NGX_HTTP_UPS_CONF};

/// ngx_http_upstream_random_srv_conf_t: the peers (offsets in their
/// memory) with the start of their weight range.
pub struct RandomConf {
    two: bool,
    config: Cell<u64>,
    ranges: RefCell<Option<Rc<Vec<(usize, usize)>>>>,
}

struct RandomPeerData {
    rrp: RrPeerData,
    conf: Rc<RandomConf>,
    tries: u32,
}

impl PeerBalancer for RandomPeerData {
    fn tries(&self) -> u32 {
        upstream_tries(self.rrp.m(), self.rrp.peers) as u32
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        if self.conf.two {
            get_random2_peer(pc, self)
        } else {
            get_random_peer(pc, self)
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

/// ngx_http_upstream_init_random
fn init_random(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, cf.log, "init random");

    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_random_peer(r, us)?))
    }));

    if us.shm_zone.borrow().is_some() {
        return Ok(());
    }

    update_random(us);
    Ok(())
}

/// ngx_http_upstream_update_random
fn update_random(us: &Rc<UpstreamSrvConf>) {
    let rcf = match us.module_conf::<RandomConf>() {
        Some(c) => c,
        None => return,
    };

    let Peers { mem: pm, off: peers } = match us.peers.get() {
        Some(p) => p,
        None => return,
    };
    let mem = &*pm.mem;

    let mut ranges: Vec<(usize, usize)> = Vec::new();

    let mut total_weight = 0usize;

    let mut peer = RrPeers::at(mem, peers).get(RrPeers::peer);

    while peer != 0 {
        let p = RrPeer::at(mem, peer);

        ranges.push((peer, total_weight));
        total_weight += p.get(RrPeer::weight) as usize;
        peer = p.get(RrPeer::next);
    }

    *rcf.ranges.borrow_mut() = Some(Rc::new(ranges));
}

/// ngx_http_upstream_init_random_peer
fn init_random_peer(r: &R, us: &Rc<UpstreamSrvConf>) -> Result<RandomPeerData, ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "init random peer");

    let rcf = us.module_conf::<RandomConf>().ok_or(())?;

    let rrp = init_round_robin_peer(r, us)?;

    let mem = rrp.m();
    let peers = rrp.peers;

    peers_rlock(mem, peers);

    let config = RrPeers::at(mem, peers).get(RrPeers::config);

    if config != 0 && (rcf.ranges.borrow().is_none() || rcf.config.get() != mem.get(config) as u64) {
        update_random(us);
        rcf.config.set(mem.get(config) as u64);
    }

    peers_unlock(mem, peers);

    Ok(RandomPeerData { rrp, conf: rcf, tries: 0 })
}

/// ngx_http_upstream_peek_random_peer
fn peek_random_peer(mem: &ShmMem, peers: usize, ranges: &[(usize, usize)]) -> usize {
    let ps = RrPeers::at(mem, peers);

    let x = (random() as usize) % ps.get(RrPeers::total_weight);

    let (mut i, mut j) = (0usize, ps.get(RrPeers::number));

    while j - i > 1 {
        let k = (i + j) / 2;

        if x < ranges[k].1 {
            j = k;
        } else {
            i = k;
        }
    }

    i
}

/// ngx_http_upstream_get_random_peer
fn get_random_peer(pc: &mut PeerConnection, rp: &mut RandomPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get random peer, try: {}", pc.tries);

    let pm = rp.rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = rp.rrp.peers;

    peers_rlock(mem, peers);

    if rp.tries > 20 || RrPeers::at(mem, peers).get(RrPeers::number) < 2 {
        peers_unlock(mem, peers);
        return get_round_robin_peer(pc, &mut rp.rrp);
    }

    if rp.rrp.config_changed() {
        peers_unlock(mem, peers);
        return get_round_robin_peer(pc, &mut rp.rrp);
    }

    pc.cached = false;
    pc.connection = None;

    let now = ngx_core::times::time();

    let ranges = rp.conf.ranges.borrow().clone().unwrap_or_default();

    let mut i = 0usize;

    let mut peer = get_rr_peer_by_sid(&rp.rrp, pc.hint.as_deref(), &mut i, true);

    if peer == 0 {
        loop {
            i = peek_random_peer(mem, peers, &ranges);

            peer = ranges[i].0;

            let skip = if rp.rrp.is_tried(i) {
                true
            } else {
                peer_lock(mem, peers, peer);

                let p = RrPeer::at(mem, peer);

                let unavailable = p.get(RrPeer::down) != 0 || p.failed(now) || p.max_conns_reached();

                if unavailable {
                    peer_unlock(mem, peers, peer);
                }

                unavailable
            };

            if !skip {
                break;
            }

            // next:

            rp.tries += 1;
            if rp.tries > 20 {
                peers_unlock(mem, peers);
                return get_round_robin_peer(pc, &mut rp.rrp);
            }
        }
    }

    // found:

    rp.rrp.current = peer;
    peer_ref(mem, peer);

    let p = RrPeer::at(mem, peer);

    if now - p.get(RrPeer::checked) > p.get(RrPeer::fail_timeout) {
        p.set(RrPeer::checked, now);
    }

    connect_peer(pc, mem, peer);

    p.set(RrPeer::conns, p.get(RrPeer::conns) + 1);

    peer_unlock(mem, peers, peer);
    peers_unlock(mem, peers);

    rp.rrp.set_tried(i);

    NGX_OK
}

/// ngx_http_upstream_get_random2_peer: of two random peers, the one with
/// less connections per weight.
fn get_random2_peer(pc: &mut PeerConnection, rp: &mut RandomPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get random2 peer, try: {}", pc.tries);

    let pm = rp.rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = rp.rrp.peers;

    peers_wlock(mem, peers);

    if rp.tries > 20 || RrPeers::at(mem, peers).get(RrPeers::number) < 2 {
        peers_unlock(mem, peers);
        return get_round_robin_peer(pc, &mut rp.rrp);
    }

    if rp.rrp.config_changed() {
        peers_unlock(mem, peers);
        return get_round_robin_peer(pc, &mut rp.rrp);
    }

    pc.cached = false;
    pc.connection = None;

    let now = ngx_core::times::time();

    let ranges = rp.conf.ranges.borrow().clone().unwrap_or_default();

    let mut prev = 0usize;
    let mut p = 0usize;

    let mut i = 0usize;

    let mut peer = get_rr_peer_by_sid(&rp.rrp, pc.hint.as_deref(), &mut i, false);

    if peer == 0 {
        loop {
            i = peek_random_peer(mem, peers, &ranges);

            peer = ranges[i].0;

            let pp = RrPeer::at(mem, peer);

            let skip = peer == prev || rp.rrp.is_tried(i) || pp.get(RrPeer::down) != 0 || pp.failed(now) || pp.max_conns_reached();

            if !skip {
                if prev != 0 {
                    let pv = RrPeer::at(mem, prev);

                    if (pp.get(RrPeer::conns) as isize) * pv.get(RrPeer::weight) > (pv.get(RrPeer::conns) as isize) * pp.get(RrPeer::weight) {
                        peer = prev;
                        i = p;
                    }

                    break;
                }

                prev = peer;
                p = i;
            }

            // next:

            rp.tries += 1;
            if rp.tries > 20 {
                peers_unlock(mem, peers);
                return get_round_robin_peer(pc, &mut rp.rrp);
            }
        }
    }

    // found:

    rp.rrp.current = peer;
    peer_ref(mem, peer);

    let pp = RrPeer::at(mem, peer);

    if now - pp.get(RrPeer::checked) > pp.get(RrPeer::fail_timeout) {
        pp.set(RrPeer::checked, now);
    }

    connect_peer(pc, mem, peer);

    pp.set(RrPeer::conns, pp.get(RrPeer::conns) + 1);

    peers_unlock(mem, peers);

    rp.rrp.set_tried(i);

    NGX_OK
}

/// ngx_http_upstream_random
fn random_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"random\" directive is not allowed here"))?;

    set_balancer(
        cf,
        &uscf,
        init_random,
        NGX_HTTP_UPSTREAM_CREATE
            | NGX_HTTP_UPSTREAM_MODIFY
            | NGX_HTTP_UPSTREAM_WEIGHT
            | NGX_HTTP_UPSTREAM_MAX_CONNS
            | NGX_HTTP_UPSTREAM_MAX_FAILS
            | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
            | NGX_HTTP_UPSTREAM_DOWN,
    );

    let value = cf.args.clone();
    let mut two = false;

    if value.len() > 1 {
        if value[1] == b"two" {
            two = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[1]))));
        }

        if value.len() > 2 && value[2] != b"least_conn" {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    uscf.set_module_conf(Rc::new(RandomConf { two, config: Cell::new(0), ranges: RefCell::new(None) }));

    Ok(())
}

pub fn upstream_random_module() -> ModuleDef {
    let commands = vec![cmd_fn!("random", NGX_HTTP_UPS_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE12, ConfLevel::None, random_handler)];
    http_module_def("ngx_http_upstream_random_module", HttpModuleDef::default(), commands)
}
