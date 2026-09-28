//! ngx_http_upstream_least_time_module: "least_time header|last_byte
//! [inflight]".

use std::any::Any;
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

/// ngx_http_upstream_response_time_avg: exponential moving average with
/// rounding.
fn response_time_avg(avg: &std::cell::Cell<u64>, v: u64) {
    let a = avg.get();
    avg.set(if a != 0 { (0.5 + (v as f64 * 0.05 + a as f64 * 0.95)) as u64 } else { v });
}

impl PeerBalancer for LeastTimePeerData {
    fn tries(&self) -> u32 {
        upstream_tries(&self.rrp.peers) as u32
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
        self.rrp.set_session()
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        self.rrp.save_session(session)
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

/// ngx_http_upstream_get_least_time_peer: the peer with the least estimated
/// time to process its current requests, per weight; round robin among
/// equal ones.
fn get_least_time_peer(pc: &mut PeerConnection, ltp: &mut LeastTimePeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least time peer, try: {}", pc.tries);

    if ltp.rrp.peers.single.get() {
        return get_round_robin_peer(pc, &mut ltp.rrp);
    }

    pc.cached = false;
    pc.connection = None;

    let now = ngx_core::times::time();

    let peers = ltp.rrp.peers.clone();

    if ltp.rrp.config_changed() {
        pc.name = peers.name.clone();
        return NGX_BUSY;
    }

    let list = peers.peers();

    let mut p = 0usize;
    let mut chosen = get_rr_peer_by_sid(&ltp.rrp, pc.hint.as_deref(), &mut p);

    if chosen.is_none() {
        let mut best: Option<(Rc<RrPeer>, u64)> = None;
        let mut many = false;

        for (i, peer) in list.iter().enumerate() {
            if ltp.rrp.is_tried(i) {
                continue;
            }

            if peer.unavailable(now) {
                continue;
            }

            if peer.inflight_reqs.get() > 0 {
                let ift = peer.inflight_last.get() / peer.inflight_reqs.get()
                    + ngx_core::times::current_msec().saturating_sub(peer.inflight_reqs_changed.get());

                response_time_avg(&peer.inflight_time, ift);
            }

            // select peer with least estimated time of processing; if there
            // are multiple peers with the same time, select based on
            // round-robin

            let eta = least_time_eta(&ltp.conf, peer);

            match best.as_ref() {
                None => {
                    best = Some((peer.clone(), eta));
                    many = false;
                    p = i;
                }
                Some((b, best_eta)) => {
                    let (x, y) = (eta as i128 * b.weight as i128, *best_eta as i128 * peer.weight as i128);
                    if x < y {
                        best = Some((peer.clone(), eta));
                        many = false;
                        p = i;
                    } else if x == y {
                        many = true;
                    }
                }
            }
        }

        let (mut best, best_eta) = match best {
            Some(b) => b,
            None => {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least time peer, no peer found");

                let next = peers.next.borrow().clone();

                if let Some(next) = next {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least time peer, backup servers");

                    ltp.rrp.peers = next;
                    ltp.rrp.clear_tried();

                    let rc = get_least_time_peer(pc, ltp);

                    if rc != NGX_BUSY {
                        return rc;
                    }
                }

                pc.name = peers.name.clone();
                return NGX_BUSY;
            }
        };

        let mut total = 0i64;

        if many {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least time peer, many");

            let first = p;

            for (i, peer) in list.iter().enumerate().skip(first) {
                if ltp.rrp.is_tried(i) {
                    continue;
                }

                if peer.down.get() != 0 {
                    continue;
                }

                let eta = least_time_eta(&ltp.conf, peer);

                if eta as i128 * best.weight as i128 != best_eta as i128 * peer.weight as i128 {
                    continue;
                }

                if peer.max_fails != 0 && peer.fails.get() >= peer.max_fails && now - peer.checked.get() <= peer.fail_timeout {
                    continue;
                }

                if peer.max_conns != 0 && peer.conns.get() >= peer.max_conns {
                    continue;
                }

                peer.current_weight.set(peer.current_weight.get() + peer.effective_weight.get());
                total += peer.effective_weight.get();

                if peer.effective_weight.get() < peer.weight {
                    peer.effective_weight.set(peer.effective_weight.get() + 1);
                }

                if peer.current_weight.get() > best.current_weight.get() {
                    best = peer.clone();
                    p = i;
                }
            }
        }

        best.current_weight.set(best.current_weight.get() - total);

        chosen = Some(best);
    }

    let best = chosen.unwrap();

    if ltp.conf.use_inflight {
        let now_ms = ngx_core::times::current_msec();

        if best.inflight_reqs.get() > 0 {
            // account time spent by inflight requests
            best.inflight_last
                .set(best.inflight_last.get() + now_ms.saturating_sub(best.inflight_reqs_changed.get()) * best.inflight_reqs.get());
        }

        best.inflight_reqs_changed.set(now_ms);
        best.inflight_reqs.set(best.inflight_reqs.get() + 1);

        ltp.inflight = true;
    }

    if now - best.checked.get() > best.fail_timeout {
        best.checked.set(now);
    }

    pc.sockaddr = Some(best.sockaddr.clone());
    pc.name = best.name.clone();
    pc.sid = Some(best.sid.clone());

    best.conns.set(best.conns.get() + 1);

    ltp.rrp.current = Some(best.clone());
    best.refs.set(best.refs.get() + 1);

    ltp.rrp.set_tried(p);

    NGX_OK
}

/// ngx_http_upstream_least_time_eta
fn least_time_eta(conf: &LeastTimeConf, peer: &RrPeer) -> u64 {
    let mut rt = match conf.mode {
        NGX_HTTP_UPSTREAM_LT_HEADER => peer.header_time.get(),
        _ => peer.response_time.get(),
    };

    let now = ngx_core::times::time();

    if now - peer.checked.get() > peer.fail_timeout {
        // once in fail_timeout make response time of a peer 2 times
        // lower to give chances to slow peers
        let shift = (now - peer.checked.get()) / (peer.fail_timeout + 1);
        rt = if shift >= 64 { 0 } else { rt >> shift };
    }

    if peer.inflight_reqs.get() > 0 {
        // average inflight time exceeding average response time indicates
        // bad (low priority) peer
        rt = rt.max(peer.inflight_time.get());
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
    rt * (1 + peer.conns.get())
}

/// ngx_http_upstream_least_time_notify
fn least_time_notify(ltp: &mut LeastTimePeerData, typ: u32, us: &UpstreamState) {
    let peer = match ltp.rrp.current.clone() {
        Some(p) => p,
        None => return,
    };

    // Only update average time here if needed for balancing.
    // Otherwise, it will be updated in peer.free().

    if typ != NGX_HTTP_UPSTREAM_NOTIFY_HEADER || ltp.conf.mode != NGX_HTTP_UPSTREAM_LT_HEADER {
        return;
    }

    let last = us.header_time;

    response_time_avg(&peer.header_time, last);

    if ltp.inflight {
        inflight_done(ltp, &peer, last);
    }
}

/// ngx_http_upstream_least_time_inflight_done
fn inflight_done(ltp: &mut LeastTimePeerData, peer: &RrPeer, last: u64) {
    if peer.inflight_reqs.get() == 1 {
        // no more inflight requests
        peer.inflight_last.set(0);
    } else {
        // account time spent by inflight requests and forget about
        // request "completed" right now
        let now_ms = ngx_core::times::current_msec();
        let spent = now_ms.saturating_sub(peer.inflight_reqs_changed.get()) * peer.inflight_reqs.get();
        peer.inflight_last.set((peer.inflight_last.get() + spent).saturating_sub(last));
        peer.inflight_reqs_changed.set(now_ms);
    }

    peer.inflight_reqs.set(peer.inflight_reqs.get().saturating_sub(1));
    ltp.inflight = false;
}

/// ngx_http_upstream_free_least_time_peer: only successful attempts update
/// the averages.
fn free_least_time_peer(pc: &mut PeerConnection, ltp: &mut LeastTimePeerData, state: u32, us: &UpstreamState) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "free least time peer");

    if let Some(peer) = ltp.rrp.current.clone() {
        if ltp.inflight {
            inflight_done(ltp, &peer, us.response_time);
        }

        // only successful attempts are accounted to mitigate preferring
        // of failing peers
        if state & (NGX_PEER_FAILED | NGX_PEER_NEXT) == 0 && us.header_time != u64::MAX {
            response_time_avg(&peer.response_time, us.response_time);

            if !(ltp.conf.use_inflight && ltp.conf.mode == NGX_HTTP_UPSTREAM_LT_HEADER) {
                response_time_avg(&peer.header_time, us.header_time);
            }
        }
    }

    free_round_robin_peer(pc, &mut ltp.rrp, state);
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
