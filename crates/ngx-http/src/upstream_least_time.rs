//! ngx_http_upstream_least_time_module: "least_time header|last_byte
//! [inflight]".

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::shmem::ShmMem;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::request::*;
use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_TAKE12, NGX_HTTP_UPS_CONF};

const NGX_HTTP_UPSTREAM_LT_HEADER: u32 = 1;
const NGX_HTTP_UPSTREAM_LT_LAST_BYTE: u32 = 2;

/// ngx_http_upstream_lt_conf_t
pub struct LeastTimeConf {
    mode: u32,
    use_inflight: bool,
}

/// ngx_http_upstream_lt_peer_data_t
struct LeastTimePeerData {
    rrp: RrPeerData,
    conf: Rc<LeastTimeConf>,
    inflight: bool,
}

impl PeerBalancer for LeastTimePeerData {
    fn tries(&self) -> u32 {
        upstream_tries(self.rrp.m(), self.rrp.peers) as u32
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_least_time_peer(pc, self)
    }

    fn free(&mut self, pc: &mut PeerConnection, state: u32, us: &UpstreamState) {
        free_least_time_peer(pc, self, state, us);
    }

    fn notify(&mut self, _pc: &mut PeerConnection, typ: u32, us: &UpstreamState) {
        if !self.conf.use_inflight {
            return;
        }
        least_time_notify(self, typ, us);
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

/// ngx_http_upstream_init_least_time
fn init_least_time(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, cf.log, "init least time");

    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "init least time peer");
        let conf = us.module_conf::<LeastTimeConf>().ok_or(())?;
        Ok(Box::new(LeastTimePeerData { rrp: init_round_robin_peer(r, us)?, conf, inflight: false }))
    }));

    Ok(())
}

/// eta * best->weight and best_eta * peer->weight: the estimated times
/// per weight of two peers, compared
fn eta_weight(mem: &ShmMem, peer: usize, eta: usize, best: usize, best_eta: usize) -> (usize, usize) {
    let (p, b) = (RrPeer::at(mem, peer), RrPeer::at(mem, best));

    (eta.wrapping_mul(b.get(RrPeer::weight) as usize), best_eta.wrapping_mul(p.get(RrPeer::weight) as usize))
}

/// ngx_http_upstream_get_least_time_peer: the peer with the least estimated
/// time to process its current requests, per weight; round robin among
/// equal ones.
fn get_least_time_peer(pc: &mut PeerConnection, ltp: &mut LeastTimePeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least time peer, try: {}", pc.tries);

    let pm = ltp.rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = ltp.rrp.peers;
    let ps = RrPeers::at(mem, peers);

    if ps.get(RrPeers::single) != 0 {
        return get_round_robin_peer(pc, &mut ltp.rrp);
    }

    pc.cached = false;
    pc.connection = None;

    let now = ngx_core::times::time();

    peers_wlock(mem, peers);

    let failed = 'pick: {
        if ltp.rrp.config_changed() {
            // busy
            peers_unlock(mem, peers);

            pc.name = ps.name_bytes();

            return NGX_BUSY;
        }

        let mut total: isize = 0;
        let mut many = false;
        let mut p = 0usize;
        let mut best_eta: usize = 0;

        let mut best = get_rr_peer_by_sid(&ltp.rrp, pc.hint.as_deref(), &mut p, false);

        if best == 0 {
            let mut peer = ps.get(RrPeers::peer);
            let mut i = 0;

            while peer != 0 {
                let pp = RrPeer::at(mem, peer);

                let skip = ltp.rrp.is_tried(i) || pp.get(RrPeer::down) != 0 || pp.failed(now) || pp.max_conns_reached();

                if !skip {
                    let inflight_reqs = pp.get(RrPeer::inflight_reqs);

                    if inflight_reqs > 0 {
                        let ift = pp.get(RrPeer::inflight_last) / inflight_reqs as u64
                            + ngx_core::times::current_msec().wrapping_sub(pp.get(RrPeer::inflight_reqs_changed));

                        pp.set(RrPeer::inflight_time, response_time_avg(pp.get(RrPeer::inflight_time), ift));
                    }

                    // select peer with least estimated time of processing;
                    // if there are multiple peers with the same time,
                    // select based on round-robin

                    let eta = least_time_eta(&ltp.conf, mem, peer);

                    let (lt, eq) = if best == 0 {
                        (true, false)
                    } else {
                        let (a, b) = eta_weight(mem, peer, eta, best, best_eta);
                        (a < b, a == b)
                    };

                    if lt {
                        best = peer;
                        best_eta = eta;
                        many = false;
                        p = i;
                    } else if eq {
                        many = true;
                    }
                }

                peer = pp.get(RrPeer::next);
                i += 1;
            }

            if best == 0 {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least time peer, no peer found");

                break 'pick true;
            }

            if many {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least time peer, many");

                let mut peer = best;
                let mut i = p;

                while peer != 0 {
                    let pp = RrPeer::at(mem, peer);

                    let mut skip = ltp.rrp.is_tried(i) || pp.get(RrPeer::down) != 0;

                    if !skip {
                        let eta = least_time_eta(&ltp.conf, mem, peer);

                        let (a, b) = eta_weight(mem, peer, eta, best, best_eta);

                        skip = a != b || pp.failed(now) || pp.max_conns_reached();
                    }

                    if !skip {
                        let effective_weight = pp.get(RrPeer::effective_weight);

                        pp.set(RrPeer::current_weight, pp.get(RrPeer::current_weight) + effective_weight);
                        total += effective_weight;

                        if effective_weight < pp.get(RrPeer::weight) {
                            pp.set(RrPeer::effective_weight, effective_weight + 1);
                        }

                        if pp.get(RrPeer::current_weight) > RrPeer::at(mem, best).get(RrPeer::current_weight) {
                            best = peer;
                            p = i;
                        }
                    }

                    peer = pp.get(RrPeer::next);
                    i += 1;
                }
            }

            let b = RrPeer::at(mem, best);
            b.set(RrPeer::current_weight, b.get(RrPeer::current_weight) - total);
        }

        // best_chosen:

        let b = RrPeer::at(mem, best);

        if ltp.conf.use_inflight {
            let now_ms = ngx_core::times::current_msec();

            let inflight_reqs = b.get(RrPeer::inflight_reqs);

            if inflight_reqs > 0 {
                // account time spent by inflight requests
                b.set(
                    RrPeer::inflight_last,
                    b.get(RrPeer::inflight_last) + now_ms.wrapping_sub(b.get(RrPeer::inflight_reqs_changed)) * inflight_reqs as u64,
                );
            }

            b.set(RrPeer::inflight_reqs_changed, now_ms);
            b.set(RrPeer::inflight_reqs, inflight_reqs + 1);

            ltp.inflight = true;
        }

        if now - b.get(RrPeer::checked) > b.get(RrPeer::fail_timeout) {
            b.set(RrPeer::checked, now);
        }

        connect_peer(pc, mem, best);

        b.set(RrPeer::conns, b.get(RrPeer::conns) + 1);

        ltp.rrp.current = best;
        peer_ref(mem, best);

        ltp.rrp.set_tried(p);

        peers_unlock(mem, peers);

        false
    };

    if !failed {
        return NGX_OK;
    }

    // failed:

    let next = ps.get(RrPeers::next);

    if next != 0 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least time peer, backup servers");

        ltp.rrp.peers = next;

        for t in ltp.rrp.tried.iter_mut() {
            *t = 0;
        }

        peers_unlock(mem, peers);

        let rc = get_least_time_peer(pc, ltp);

        if rc != NGX_BUSY {
            return rc;
        }

        peers_wlock(mem, peers);
    }

    // busy:

    peers_unlock(mem, peers);

    pc.name = ps.name_bytes();

    NGX_BUSY
}

/// ngx_http_upstream_least_time_eta
fn least_time_eta(conf: &LeastTimeConf, mem: &ShmMem, peer: usize) -> usize {
    let p = RrPeer::at(mem, peer);

    let mut rt = match conf.mode {
        NGX_HTTP_UPSTREAM_LT_HEADER => p.get(RrPeer::header_time),
        _ => p.get(RrPeer::response_time),
    };

    let now = ngx_core::times::time();

    let (checked, fail_timeout) = (p.get(RrPeer::checked), p.get(RrPeer::fail_timeout));

    if now - checked > fail_timeout {
        // once in fail_timeout make response time of a peer 2 times
        // lower to give chances to slow peers
        let shift = (now - checked) / (fail_timeout + 1);
        rt = if shift >= 64 { 0 } else { rt >> shift };
    }

    if p.get(RrPeer::inflight_reqs) > 0 {
        // average inflight time exceeding average response time indicates
        // bad (low priority) peer
        rt = rt.max(p.get(RrPeer::inflight_time));
    }

    if rt > 5000 {
        // consider peers with response time greater than max equally bad
        // and thus fallback to least_conns
        rt = 5000;
    } else {
        // divide response times into clusters to allow round-robin for
        // peers with close response times
        rt += 20 - rt % 20;
    }

    // estimated time peer has to spend to finish processing current requests
    rt as usize * (1 + p.get(RrPeer::conns))
}

/// ngx_http_upstream_least_time_notify
fn least_time_notify(ltp: &mut LeastTimePeerData, typ: u32, us: &UpstreamState) {
    let pm = ltp.rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = ltp.rrp.peers;
    let peer = ltp.rrp.current;

    if peer == 0 {
        return;
    }

    // Only update average time here if needed for balancing.
    // Otherwise, it will be updated in peer.free().

    if typ != NGX_HTTP_UPSTREAM_NOTIFY_HEADER || ltp.conf.mode != NGX_HTTP_UPSTREAM_LT_HEADER {
        return;
    }

    let last = us.header_time;

    peers_rlock(mem, peers);
    peer_lock(mem, peers, peer);

    let p = RrPeer::at(mem, peer);

    p.set(RrPeer::header_time, response_time_avg(p.get(RrPeer::header_time), last));

    if ltp.inflight {
        inflight_done(ltp, mem, peer, last);
    }

    peer_unlock(mem, peers, peer);
    peers_unlock(mem, peers);
}

/// ngx_http_upstream_least_time_inflight_done
fn inflight_done(ltp: &mut LeastTimePeerData, mem: &ShmMem, peer: usize, last: u64) {
    let p = RrPeer::at(mem, peer);

    let inflight_reqs = p.get(RrPeer::inflight_reqs);

    if inflight_reqs == 1 {
        // no more inflight requests
        p.set(RrPeer::inflight_last, 0);
    } else {
        // account time spent by inflight requests and forget about
        // request "completed" right now
        let now_ms = ngx_core::times::current_msec();
        p.set(
            RrPeer::inflight_last,
            p.get(RrPeer::inflight_last)
                .wrapping_add(now_ms.wrapping_sub(p.get(RrPeer::inflight_reqs_changed)) * inflight_reqs as u64)
                .wrapping_sub(last),
        );
        p.set(RrPeer::inflight_reqs_changed, now_ms);
    }

    p.set(RrPeer::inflight_reqs, inflight_reqs.wrapping_sub(1));
    ltp.inflight = false;
}

/// ngx_http_upstream_free_least_time_peer: only successful attempts update
/// the averages.
fn free_least_time_peer(pc: &mut PeerConnection, ltp: &mut LeastTimePeerData, state: u32, us: &UpstreamState) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "free least time peer");

    let pm = ltp.rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = ltp.rrp.peers;
    let peer = ltp.rrp.current;

    peers_rlock(mem, peers);
    peer_lock(mem, peers, peer);

    if ltp.inflight {
        inflight_done(ltp, mem, peer, us.response_time);
    }

    // only successful attempts are accounted to mitigate preferring
    // of failing peers
    if state & (NGX_PEER_FAILED | NGX_PEER_NEXT) == 0 && us.header_time != u64::MAX {
        let p = RrPeer::at(mem, peer);

        p.set(RrPeer::response_time, response_time_avg(p.get(RrPeer::response_time), us.response_time));

        if !(ltp.conf.use_inflight && ltp.conf.mode == NGX_HTTP_UPSTREAM_LT_HEADER) {
            p.set(RrPeer::header_time, response_time_avg(p.get(RrPeer::header_time), us.header_time));
        }
    }

    // done:

    free_round_robin_peer_locked(pc, &mut ltp.rrp, state);
}

/// ngx_http_upstream_least_time
fn least_time_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"least_time\" directive is not allowed here"))?;

    set_balancer(
        cf,
        &uscf,
        init_least_time,
        NGX_HTTP_UPSTREAM_CREATE
            | NGX_HTTP_UPSTREAM_MODIFY
            | NGX_HTTP_UPSTREAM_WEIGHT
            | NGX_HTTP_UPSTREAM_MAX_CONNS
            | NGX_HTTP_UPSTREAM_MAX_FAILS
            | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
            | NGX_HTTP_UPSTREAM_DOWN
            | NGX_HTTP_UPSTREAM_BACKUP,
    );

    let value = cf.args.clone();

    let mut use_inflight = false;

    if value.len() == 3 {
        if value[2] == b"inflight" {
            use_inflight = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    // ngx_conf_set_enum_slot
    if uscf.module_conf::<LeastTimeConf>().is_some() {
        return Err(msg("is duplicate"));
    }

    let mode = match value[1].as_slice() {
        b"header" => NGX_HTTP_UPSTREAM_LT_HEADER,
        b"last_byte" => NGX_HTTP_UPSTREAM_LT_LAST_BYTE,
        v => return Err(cf.emerg(format_args!("invalid value \"{}\"", B(v)))),
    };

    uscf.set_module_conf(Rc::new(LeastTimeConf { mode, use_inflight }));

    Ok(())
}

pub fn upstream_least_time_module() -> ModuleDef {
    let commands = vec![cmd_fn!("least_time", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::None, least_time_handler)];
    http_module_def("ngx_http_upstream_least_time_module", HttpModuleDef::default(), commands)
}
