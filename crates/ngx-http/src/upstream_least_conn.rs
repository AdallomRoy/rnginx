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
        unsafe { upstream_tries(self.rrp.peers) as u32 }
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

/// ngx_http_upstream_get_least_conn_peer: the peer with the least
/// connections per weight; round robin among equal ones.
fn get_least_conn_peer(pc: &mut PeerConnection, rrp: &mut RrPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, try: {}", pc.tries);

    unsafe {
        if (*rrp.peers).single {
            return get_round_robin_peer(pc, rrp);
        }

        pc.cached = false;
        pc.connection = None;

        let now = ngx_core::times::time();

        let peers = rrp.peers;

        peers_wlock(peers);

        let failed = 'pick: {
            if rrp.config_changed() {
                // busy
                peers_unlock(peers);

                pc.name = (*(*peers).name).bytes().to_vec();

                return NGX_BUSY;
            }

            let mut total: isize = 0;
            let mut many = false;
            let mut p = 0usize;

            let mut best = get_rr_peer_by_sid(rrp, pc.hint.as_deref(), &mut p, false);

            if best.is_null() {
                let mut peer = (*peers).peer;
                let mut i = 0;

                while !peer.is_null() {
                    let skip = rrp.is_tried(i)
                        || (*peer).down != 0
                        || ((*peer).max_fails != 0 && (*peer).fails >= (*peer).max_fails && now - (*peer).checked <= (*peer).fail_timeout)
                        || ((*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns);

                    if !skip {
                        // select peer with least number of connections; if
                        // there are multiple peers with the same number of
                        // connections, select based on round-robin

                        if best.is_null() || ((*peer).conns as isize) * (*best).weight < ((*best).conns as isize) * (*peer).weight {
                            best = peer;
                            many = false;
                            p = i;
                        } else if ((*peer).conns as isize) * (*best).weight == ((*best).conns as isize) * (*peer).weight {
                            many = true;
                        }
                    }

                    peer = (*peer).next;
                    i += 1;
                }

                if best.is_null() {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, no peer found");

                    break 'pick true;
                }

                if many {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, many");

                    let mut peer = best;
                    let mut i = p;

                    while !peer.is_null() {
                        let skip = rrp.is_tried(i)
                            || (*peer).down != 0
                            || ((*peer).conns as isize) * (*best).weight != ((*best).conns as isize) * (*peer).weight
                            || ((*peer).max_fails != 0 && (*peer).fails >= (*peer).max_fails && now - (*peer).checked <= (*peer).fail_timeout)
                            || ((*peer).max_conns != 0 && (*peer).conns >= (*peer).max_conns);

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

            // best_chosen:

            if now - (*best).checked > (*best).fail_timeout {
                (*best).checked = now;
            }

            connect_peer(pc, best);

            (*best).conns += 1;

            rrp.current = best;
            peer_ref(peers, best);

            rrp.set_tried(p);

            peers_unlock(peers);

            false
        };

        if !failed {
            return NGX_OK;
        }

        // failed:

        if !(*peers).next.is_null() {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get least conn peer, backup servers");

            rrp.peers = (*peers).next;

            for t in rrp.tried.iter_mut() {
                *t = 0;
            }

            peers_unlock(peers);

            let rc = get_least_conn_peer(pc, rrp);

            if rc != NGX_BUSY {
                return rc;
            }

            peers_wlock(peers);
        }

        // busy:

        peers_unlock(peers);

        pc.name = (*(*peers).name).bytes().to_vec();

        NGX_BUSY
    }
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
