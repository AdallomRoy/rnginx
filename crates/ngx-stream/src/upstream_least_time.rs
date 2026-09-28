//! ngx_stream_upstream_least_time_module: "least_time
//! connect|first_byte|last_byte [inflight]".

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::*;

stream_module_index!("ngx_stream_upstream_least_time_module");

const NGX_STREAM_UPSTREAM_LT_CONNECT: u32 = 0;
const NGX_STREAM_UPSTREAM_LT_FIRST_BYTE: u32 = 1;
const NGX_STREAM_UPSTREAM_LT_LAST_BYTE: u32 = 2;

/// ngx_stream_upstream_lt_conf_t
#[derive(Clone)]
pub struct LeastTimeConf {
    mode: Val<u32>,
    use_inflight: bool,
}

fn create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LeastTimeConf { mode: Val::unset(), use_inflight: false })
}

/// ngx_stream_upstream_lt_peer_data_t
struct LeastTimePeerData {
    rrp: RrPeerData,
    conf: LeastTimeConf,
    inflight: bool,
}

impl PeerBalancer for LeastTimePeerData {
    fn tries(&self) -> u32 {
        unsafe { upstream_tries(self.rrp.peers) as u32 }
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_least_time_peer(pc, self)
    }

    fn free(&mut self, pc: &mut PeerConnection, state: u32, us: &UpstreamState) {
        free_least_time_peer(pc, self, state, us);
    }

    fn notify(&mut self, pc: &mut PeerConnection, ty: i32, notify: u32, us: &UpstreamState) {
        if !self.conf.use_inflight {
            notify_round_robin_peer(pc, &mut self.rrp, ty, notify);
            return;
        }
        least_time_notify(pc, self, ty, notify, us);
    }

    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        set_round_robin_peer_session(&mut self.rrp)
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        save_round_robin_peer_session(&mut self.rrp, session)
    }

}

/// ngx_stream_upstream_init_least_time
fn init_least_time(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, cf.log, "init least time");

    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|s: &S, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "init least time peer");
        let conf = us.module_srv_conf::<LeastTimeConf>(ctx_index()).ok_or(())?.borrow().clone();
        Ok(Box::new(LeastTimePeerData { rrp: init_round_robin_peer(s, us)?, conf, inflight: false }))
    }));

    Ok(())
}

/// ngx_stream_upstream_get_least_time_peer: the peer with the least estimated
/// time to process its current requests, per weight; round robin among
/// equal ones.
fn get_least_time_peer(pc: &mut PeerConnection, ltp: &mut LeastTimePeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "get least time peer, try: {}", pc.tries);

    unsafe {
        if (*ltp.rrp.peers).single {
            return get_round_robin_peer(pc, &mut ltp.rrp);
        }

        let now = ngx_core::times::time();

        let peers = ltp.rrp.peers;

        peers_wlock(peers);

        let failed = 'pick: {
            if ltp.rrp.config_changed() {
                // busy
                peers_unlock(peers);

                pc.name = Some((*(*peers).name).bytes().to_vec());

                return NGX_BUSY;
            }

            let mut total: isize = 0;
            let mut many = false;
            let mut p = 0usize;
            let mut best_eta: usize = 0;

            let mut best: *mut RrPeer = std::ptr::null_mut();

            {
                let mut peer = (*peers).peer;
                let mut i = 0;

                while !peer.is_null() {
                    let skip = ltp.rrp.is_tried(i)
                        || (*peer).down != 0
                        || ((*peer).max_fails != 0 && (*peer).fails >= (*peer).max_fails && now - (*peer).checked <= (*peer).fail_timeout)
                        || ((*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns);

                    if !skip {
                        if (*peer).inflight_reqs > 0 {
                            let ift = (*peer).inflight_last / (*peer).inflight_reqs as u64
                                + ngx_core::times::current_msec().wrapping_sub((*peer).inflight_reqs_changed);

                            response_time_avg(&mut (*peer).inflight_time, ift);
                        }

                        // select peer with least estimated time of processing;
                        // if there are multiple peers with the same time,
                        // select based on round-robin

                        let eta = least_time_eta(&ltp.conf, peer);

                        if best.is_null() || eta.wrapping_mul((*best).weight as usize) < best_eta.wrapping_mul((*peer).weight as usize) {
                            best = peer;
                            best_eta = eta;
                            many = false;
                            p = i;
                        } else if eta.wrapping_mul((*best).weight as usize) == best_eta.wrapping_mul((*peer).weight as usize) {
                            many = true;
                        }
                    }

                    peer = (*peer).next;
                    i += 1;
                }

                if best.is_null() {
                    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "get least time peer, no peer found");

                    break 'pick true;
                }

                if many {
                    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "get least time peer, many");

                    let mut peer = best;
                    let mut i = p;

                    while !peer.is_null() {
                        let mut skip = ltp.rrp.is_tried(i) || (*peer).down != 0;

                        if !skip {
                            let eta = least_time_eta(&ltp.conf, peer);

                            skip = eta.wrapping_mul((*best).weight as usize) != best_eta.wrapping_mul((*peer).weight as usize)
                                || ((*peer).max_fails != 0 && (*peer).fails >= (*peer).max_fails && now - (*peer).checked <= (*peer).fail_timeout)
                                || ((*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns);
                        }

                        if !skip {
                            (*peer).current_weight += (*peer).effective_weight;
                            total += (*peer).effective_weight;

                            if (*peer).effective_weight < (*peer).weight {
                                (*peer).effective_weight += 1;
                            }

                            if (*peer).current_weight > (*best).current_weight {
                                best = peer;
                                p = i;
                            }
                        }

                        peer = (*peer).next;
                        i += 1;
                    }
                }

                (*best).current_weight -= total;
            }

            if ltp.conf.use_inflight {
                let now_ms = ngx_core::times::current_msec();

                if (*best).inflight_reqs > 0 {
                    // account time spent by inflight requests
                    (*best).inflight_last += now_ms.wrapping_sub((*best).inflight_reqs_changed) * (*best).inflight_reqs as u64;
                }

                (*best).inflight_reqs_changed = now_ms;
                (*best).inflight_reqs += 1;

                ltp.inflight = true;
            }

            if now - (*best).checked > (*best).fail_timeout {
                (*best).checked = now;
            }

            connect_peer(pc, best);

            (*best).conns += 1;

            ltp.rrp.current = best;
            peer_ref(peers, best);

            ltp.rrp.set_tried(p);

            peers_unlock(peers);

            false
        };

        if !failed {
            return NGX_OK;
        }

        // failed:

        if !(*peers).next.is_null() {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "get least time peer, backup servers");

            ltp.rrp.peers = (*peers).next;

            for t in ltp.rrp.tried.iter_mut() {
                *t = 0;
            }

            peers_unlock(peers);

            let rc = get_least_time_peer(pc, ltp);

            if rc != NGX_BUSY {
                return rc;
            }

            peers_wlock(peers);
        }

        // busy:

        peers_unlock(peers);

        pc.name = Some((*(*peers).name).bytes().to_vec());

        NGX_BUSY
    }
}

/// ngx_stream_upstream_least_time_eta
unsafe fn least_time_eta(conf: &LeastTimeConf, peer: *mut RrPeer) -> usize {
    let mut rt = match *conf.mode {
        NGX_STREAM_UPSTREAM_LT_FIRST_BYTE => (*peer).first_byte_time,
        NGX_STREAM_UPSTREAM_LT_CONNECT => (*peer).connect_time,
        // NGX_STREAM_UPSTREAM_LT_LAST_BYTE
        _ => (*peer).response_time,
    };

    let now = ngx_core::times::time();

    if now - (*peer).checked > (*peer).fail_timeout {
        // once in fail_timeout make response time of a peer 2 times
        // lower to give chances to slow peers
        let shift = (now - (*peer).checked) / ((*peer).fail_timeout + 1);
        rt = if shift >= 64 { 0 } else { rt >> shift };
    }

    if (*peer).inflight_reqs > 0 {
        // average inflight time exceeding average response time indicates
        // bad (low priority) peer
        rt = rt.max((*peer).inflight_time);
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
    rt as usize * (1 + (*peer).conns)
}

/// ngx_stream_upstream_least_time_notify
fn least_time_notify(pc: &mut PeerConnection, ltp: &mut LeastTimePeerData, ty: i32, notify: u32, us: &UpstreamState) {
    let peers = ltp.rrp.peers;
    let peer = ltp.rrp.current;

    // Only update average time here if needed for balancing.
    // Otherwise, it will be updated in peer.free().

    let mut metric: Option<(*mut u64, i64)> = None;

    unsafe {
        match notify {
            NGX_STREAM_UPSTREAM_NOTIFY_CONNECT => {
                if *ltp.conf.mode == NGX_STREAM_UPSTREAM_LT_CONNECT {
                    metric = Some((&mut (*peer).connect_time, us.connect_time));
                }
            }

            NGX_STREAM_UPSTREAM_NOTIFY_FIRST_BYTE => {
                if *ltp.conf.mode == NGX_STREAM_UPSTREAM_LT_FIRST_BYTE {
                    metric = Some((&mut (*peer).first_byte_time, us.first_byte_time));
                }
            }

            _ => {}
        }

        peers_rlock(peers);
        peer_lock(peers, peer);

        if let Some((metric, last)) = metric {
            let last = last as u64;

            response_time_avg(&mut *metric, last);

            if ltp.inflight {
                inflight_done(ltp, peer, last);
            }
        }
    }

    notify_round_robin_peer_locked(pc, &mut ltp.rrp, ty, notify);
}

/// ngx_stream_upstream_least_time_inflight_done
unsafe fn inflight_done(ltp: &mut LeastTimePeerData, peer: *mut RrPeer, last: u64) {
    if (*peer).inflight_reqs == 1 {
        // no more inflight requests
        (*peer).inflight_last = 0;
    } else {
        // account time spent by inflight requests and forget about
        // request "completed" right now
        let now_ms = ngx_core::times::current_msec();
        (*peer).inflight_last = (*peer).inflight_last.wrapping_add(now_ms.wrapping_sub((*peer).inflight_reqs_changed) * (*peer).inflight_reqs as u64).wrapping_sub(last);
        (*peer).inflight_reqs_changed = now_ms;
    }

    (*peer).inflight_reqs -= 1;
    ltp.inflight = false;
}

/// ngx_stream_upstream_free_least_time_peer: only successful attempts
/// update the averages.
fn free_least_time_peer(pc: &mut PeerConnection, ltp: &mut LeastTimePeerData, state: u32, us: &UpstreamState) {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, pc.log, "free least time peer");

    let peers = ltp.rrp.peers;
    let peer = ltp.rrp.current;

    unsafe {
        peers_rlock(peers);
        peer_lock(peers, peer);

        if ltp.inflight {
            inflight_done(ltp, peer, us.response_time as u64);
        }

        // only successful attempts are accounted to mitigate preferring
        // of failing peers
        if state & (NGX_PEER_FAILED | NGX_PEER_NEXT) == 0 {
            response_time_avg(&mut (*peer).response_time, us.response_time as u64);

            if !ltp.conf.use_inflight || *ltp.conf.mode != NGX_STREAM_UPSTREAM_LT_CONNECT {
                response_time_avg(&mut (*peer).connect_time, us.connect_time as u64);
            }

            if us.first_byte_time != -1 && (!ltp.conf.use_inflight || *ltp.conf.mode != NGX_STREAM_UPSTREAM_LT_FIRST_BYTE) {
                response_time_avg(&mut (*peer).first_byte_time, us.first_byte_time as u64);
            }
        }
    }

    free_round_robin_peer_locked(pc, &mut ltp.rrp, state);
}

/// ngx_stream_upstream_least_time
fn least_time_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = conf_upstream(cf).ok_or_else(|| msg("\"least_time\" directive is not allowed here"))?;

    set_balancer(
        cf,
        &uscf,
        init_least_time,
        NGX_STREAM_UPSTREAM_CREATE
            | NGX_STREAM_UPSTREAM_MODIFY
            | NGX_STREAM_UPSTREAM_WEIGHT
            | NGX_STREAM_UPSTREAM_MAX_CONNS
            | NGX_STREAM_UPSTREAM_MAX_FAILS
            | NGX_STREAM_UPSTREAM_FAIL_TIMEOUT
            | NGX_STREAM_UPSTREAM_DOWN
            | NGX_STREAM_UPSTREAM_BACKUP,
    );

    let ltcf = conf_rc::<LeastTimeConf>(conf.as_ref().expect("conf"));

    let value = cf.args.clone();

    if value.len() == 3 {
        if value[2] == b"inflight" {
            ltcf.borrow_mut().use_inflight = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    let mut c = ltcf.borrow_mut();
    set_enum(cf, cmd, &mut c.mode, &[("connect", NGX_STREAM_UPSTREAM_LT_CONNECT), ("first_byte", NGX_STREAM_UPSTREAM_LT_FIRST_BYTE), ("last_byte", NGX_STREAM_UPSTREAM_LT_LAST_BYTE)])
}

pub fn upstream_least_time_module() -> ModuleDef {
    let commands = vec![cmd_fn!("least_time", NGX_STREAM_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::Srv, least_time_handler)];
    stream_module_def("ngx_stream_upstream_least_time_module", StreamModuleDef { create_srv_conf: Some(create_srv_conf), ..Default::default() }, commands)
}
