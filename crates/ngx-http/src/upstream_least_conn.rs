//! ngx_http_upstream_least_conn_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::request::*;
use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_NOARGS, NGX_HTTP_UPS_CONF};

struct LeastConnPeerData {
    rrp: RrPeerData,
}

impl PeerBalancer for LeastConnPeerData {
    fn tries(&self) -> u32 {
        upstream_tries(&self.rrp.peers) as u32
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_least_conn_peer(pc, &mut self.rrp)
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

/// ngx_http_upstream_init_least_conn
fn init_least_conn(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, cf.log, "init least conn");

    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "init least conn peer");
        Ok(Box::new(LeastConnPeerData { rrp: init_round_robin_peer(r, us)? }))
    }));

    Ok(())
}

/// ngx_http_upstream_get_least_conn_peer: the peer with the least
/// connections per weight; round robin among equal ones.
fn get_least_conn_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, try: {}", pc.tries);

    if rrp.peers.single.get() {
        return get_round_robin_peer(pc, rrp);
    }

    pc.cached = false;
    pc.connection = None;

    let now = ngx_core::times::time();

    let peers = rrp.peers.clone();

    if rrp.config_changed() {
        pc.name = peers.name.clone();
        return NGX_BUSY;
    }

    let list = peers.peers();

    let mut p = 0usize;
    let mut chosen = get_rr_peer_by_sid(rrp, pc.hint.as_deref(), &mut p);

    if chosen.is_none() {
        let mut best: Option<std::rc::Rc<RrPeer>> = None;
        let mut many = false;

        for (i, peer) in list.iter().enumerate() {
            if rrp.is_tried(i) {
                continue;
            }

            if peer.unavailable(now) {
                continue;
            }

            // select peer with least number of connections; if there are
            // multiple peers with the same number of connections, select
            // based on round-robin

            match best.as_ref() {
                None => {
                    best = Some(peer.clone());
                    many = false;
                    p = i;
                }
                Some(b) => {
                    let (pc_w, bc_w) = (peer.conns.get() as i64 * b.weight, b.conns.get() as i64 * peer.weight);
                    if pc_w < bc_w {
                        best = Some(peer.clone());
                        many = false;
                        p = i;
                    } else if pc_w == bc_w {
                        many = true;
                    }
                }
            }
        }

        let mut best = match best {
            Some(b) => b,
            None => {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, no peer found");

                let next = peers.next.borrow().clone();

                if let Some(next) = next {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, backup servers");

                    rrp.peers = next;
                    rrp.clear_tried();

                    let rc = get_least_conn_peer(pc, rrp);

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
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, many");

            let first = p;

            for (i, peer) in list.iter().enumerate().skip(first) {
                if rrp.is_tried(i) {
                    continue;
                }

                if peer.down.get() != 0 {
                    continue;
                }

                if peer.conns.get() as i64 * best.weight != best.conns.get() as i64 * peer.weight {
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

    if now - best.checked.get() > best.fail_timeout {
        best.checked.set(now);
    }

    pc.sockaddr = Some(best.sockaddr.clone());
    pc.name = best.name.clone();
    pc.sid = Some(best.sid.clone());

    best.conns.set(best.conns.get() + 1);

    rrp.current = Some(best.clone());
    best.refs.set(best.refs.get() + 1);

    rrp.set_tried(p);

    NGX_OK
}

/// ngx_http_upstream_least_conn
fn least_conn_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"least_conn\" directive is not allowed here"))?;

    set_balancer(
        cf,
        &uscf,
        init_least_conn,
        NGX_HTTP_UPSTREAM_CREATE
            | NGX_HTTP_UPSTREAM_MODIFY
            | NGX_HTTP_UPSTREAM_WEIGHT
            | NGX_HTTP_UPSTREAM_MAX_CONNS
            | NGX_HTTP_UPSTREAM_MAX_FAILS
            | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
            | NGX_HTTP_UPSTREAM_DOWN
            | NGX_HTTP_UPSTREAM_BACKUP,
    );

    Ok(())
}

pub fn upstream_least_conn_module() -> ModuleDef {
    let commands = vec![cmd_fn!("least_conn", NGX_HTTP_UPS_CONF | NGX_CONF_NOARGS, ConfLevel::None, least_conn_handler)];
    http_module_def("ngx_http_upstream_least_conn_module", HttpModuleDef::default(), commands)
}
