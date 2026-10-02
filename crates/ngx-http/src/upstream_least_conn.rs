//! ngx_http_upstream_least_conn_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::shmem::ShmMem;
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
        upstream_tries(self.rrp.m(), self.rrp.peers) as u32
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_least_conn_peer(pc, &mut self.rrp)
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

/// peer->conns * best->weight and best->conns * peer->weight: the
/// connections per weight of two peers, compared
fn conns_weight(mem: &ShmMem, peer: usize, best: usize) -> (isize, isize) {
    let (p, b) = (RrPeer::at(mem, peer), RrPeer::at(mem, best));

    (p.get(RrPeer::conns) as isize * b.get(RrPeer::weight), b.get(RrPeer::conns) as isize * p.get(RrPeer::weight))
}

/// ngx_http_upstream_get_least_conn_peer: the peer with the least
/// connections per weight; round robin among equal ones.
fn get_least_conn_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, try: {}", pc.tries);

    let pm = rrp.mem.clone();
    let mem = &*pm.mem;

    let peers = rrp.peers;
    let ps = RrPeers::at(mem, peers);

    if ps.get(RrPeers::single) != 0 {
        return get_round_robin_peer(pc, rrp);
    }

    pc.cached = false;
    pc.connection = None;

    let now = ngx_core::times::time();

    peers_wlock(mem, peers);

    let failed = 'pick: {
        if rrp.config_changed() {
            // busy
            peers_unlock(mem, peers);

            pc.name = ps.name_bytes();

            return NGX_BUSY;
        }

        let mut total: isize = 0;
        let mut many = false;
        let mut p = 0usize;

        let mut best = get_rr_peer_by_sid(rrp, pc.hint.as_deref(), &mut p, false);

        if best == 0 {
            let mut peer = ps.get(RrPeers::peer);
            let mut i = 0;

            while peer != 0 {
                let pp = RrPeer::at(mem, peer);

                let skip = rrp.is_tried(i) || pp.get(RrPeer::down) != 0 || pp.failed(now) || pp.max_conns_reached();

                if !skip {
                    // select peer with least number of connections; if
                    // there are multiple peers with the same number of
                    // connections, select based on round-robin

                    let (lt, eq) = if best == 0 {
                        (true, false)
                    } else {
                        let (a, b) = conns_weight(mem, peer, best);
                        (a < b, a == b)
                    };

                    if lt {
                        best = peer;
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
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, no peer found");

                break 'pick true;
            }

            if many {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, many");

                let mut peer = best;
                let mut i = p;

                while peer != 0 {
                    let pp = RrPeer::at(mem, peer);

                    let skip = rrp.is_tried(i)
                        || pp.get(RrPeer::down) != 0
                        || {
                            let (a, b) = conns_weight(mem, peer, best);
                            a != b
                        }
                        || pp.failed(now)
                        || pp.max_conns_reached();

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

        if now - b.get(RrPeer::checked) > b.get(RrPeer::fail_timeout) {
            b.set(RrPeer::checked, now);
        }

        connect_rr_peer(pc, rrp, best);

        b.set(RrPeer::conns, b.get(RrPeer::conns) + 1);

        rrp.current = best;
        peer_ref(mem, best);

        rrp.set_tried(p);

        peers_unlock(mem, peers);

        false
    };

    if !failed {
        return NGX_OK;
    }

    // failed:

    let next = ps.get(RrPeers::next);

    if next != 0 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, backup servers");

        rrp.peers = next;

        for t in rrp.tried.iter_mut() {
            *t = 0;
        }

        peers_unlock(mem, peers);

        let rc = get_least_conn_peer(pc, rrp);

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
