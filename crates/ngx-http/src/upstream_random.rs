//! ngx_http_upstream_random_module: "random [two [least_conn]]".

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
use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_NOARGS, NGX_CONF_TAKE12, NGX_HTTP_UPS_CONF};

/// ngx_http_upstream_random_srv_conf_t: the peers with the start of their
/// weight range.
pub struct RandomConf {
    two: bool,
    config: Cell<u64>,
    ranges: RefCell<Option<Rc<Vec<(Rc<RrPeer>, i64)>>>>,
}

struct RandomPeerData {
    rrp: RrPeerData,
    conf: Rc<RandomConf>,
    tries: u32,
}

impl PeerBalancer for RandomPeerData {
    fn tries(&self) -> u32 {
        upstream_tries(&self.rrp.peers) as u32
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
        self.rrp.set_session()
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        self.rrp.save_session(session)
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

    if us.zone.borrow().is_some() {
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

    let peers = match us.peers.borrow().clone() {
        Some(p) => p,
        None => return,
    };

    let mut total_weight = 0i64;

    let ranges: Vec<(Rc<RrPeer>, i64)> = peers
        .peers()
        .into_iter()
        .map(|peer| {
            let range = total_weight;
            total_weight += peer.weight;
            (peer, range)
        })
        .collect();

    *rcf.ranges.borrow_mut() = Some(Rc::new(ranges));
}

/// ngx_http_upstream_init_random_peer
fn init_random_peer(r: &R, us: &Rc<UpstreamSrvConf>) -> Result<RandomPeerData, ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "init random peer");

    let rcf = us.module_conf::<RandomConf>().ok_or(())?;

    let rrp = init_round_robin_peer(r, us)?;

    if let Some(config) = rrp.peers.config.clone() {
        if rcf.ranges.borrow().is_none() || rcf.config.get() != config.get() {
            update_random(us);
            rcf.config.set(config.get());
        }
    }

    Ok(RandomPeerData { rrp, conf: rcf, tries: 0 })
}

/// ngx_http_upstream_peek_random_peer
fn peek_random_peer(peers: &RrPeers, ranges: &[(Rc<RrPeer>, i64)]) -> usize {
    let x = (unsafe { random() } as i64) % peers.total_weight.get();

    let (mut i, mut j) = (0usize, peers.number.get());

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

    let peers = rp.rrp.peers.clone();

    if rp.tries > 20 || peers.number.get() < 2 {
        return get_round_robin_peer(pc, &mut rp.rrp);
    }

    if rp.rrp.config_changed() {
        return get_round_robin_peer(pc, &mut rp.rrp);
    }

    pc.cached = false;
    pc.connection = None;

    let now = ngx_core::times::time();

    let ranges = match rp.conf.ranges.borrow().clone() {
        Some(r) => r,
        None => return get_round_robin_peer(pc, &mut rp.rrp),
    };

    let mut i = 0usize;
    let peer = match get_rr_peer_by_sid(&rp.rrp, pc.hint.as_deref(), &mut i) {
        Some(p) => p,
        None => loop {
            i = peek_random_peer(&peers, &ranges);

            let peer = &ranges[i].0;

            if !rp.rrp.is_tried(i) && !peer.unavailable(now) {
                break peer.clone();
            }

            rp.tries += 1;
            if rp.tries > 20 {
                return get_round_robin_peer(pc, &mut rp.rrp);
            }
        },
    };

    chosen(pc, &mut rp.rrp, peer, i, now)
}

/// ngx_http_upstream_get_random2_peer: of two random peers, the one with
/// less connections per weight.
fn get_random2_peer(pc: &mut PeerConnection, rp: &mut RandomPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get random2 peer, try: {}", pc.tries);

    let peers = rp.rrp.peers.clone();

    if rp.tries > 20 || peers.number.get() < 2 {
        return get_round_robin_peer(pc, &mut rp.rrp);
    }

    if rp.rrp.config_changed() {
        return get_round_robin_peer(pc, &mut rp.rrp);
    }

    pc.cached = false;
    pc.connection = None;

    let now = ngx_core::times::time();

    let ranges = match rp.conf.ranges.borrow().clone() {
        Some(r) => r,
        None => return get_round_robin_peer(pc, &mut rp.rrp),
    };

    let mut i = 0usize;
    let (peer, i) = match get_rr_peer_by_sid(&rp.rrp, pc.hint.as_deref(), &mut i) {
        Some(p) => (p, i),
        None => {
            let mut prev: Option<(Rc<RrPeer>, usize)> = None;

            loop {
                let i = peek_random_peer(&peers, &ranges);

                let peer = ranges[i].0.clone();

                let same = prev.as_ref().is_some_and(|(p, _)| Rc::ptr_eq(p, &peer));

                if !same && !rp.rrp.is_tried(i) && !peer.unavailable(now) {
                    match prev {
                        Some((p, pi)) => {
                            if peer.conns.get() as i64 * p.weight > p.conns.get() as i64 * peer.weight {
                                break (p, pi);
                            }
                            break (peer, i);
                        }
                        None => {
                            prev = Some((peer, i));
                        }
                    }
                }

                rp.tries += 1;
                if rp.tries > 20 {
                    return get_round_robin_peer(pc, &mut rp.rrp);
                }
            }
        }
    };

    chosen(pc, &mut rp.rrp, peer, i, now)
}

fn chosen(pc: &mut PeerConnection, rrp: &mut RrPeerData, peer: Rc<RrPeer>, i: usize, now: i64) -> i64 {
    rrp.current = Some(peer.clone());
    peer.refs.set(peer.refs.get() + 1);

    if now - peer.checked.get() > peer.fail_timeout {
        peer.checked.set(now);
    }

    pc.sockaddr = Some(peer.sockaddr.clone());
    pc.name = peer.name.clone();
    pc.sid = Some(peer.sid.clone());

    peer.conns.set(peer.conns.get() + 1);

    rrp.set_tried(i);

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

extern "C" {
    /// ngx_random
    fn random() -> libc::c_long;
}
