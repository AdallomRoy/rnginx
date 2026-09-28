//! ngx_http_upstream_ip_hash_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::inet::SockAddr;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::request::*;
use crate::upstream::*;
use crate::upstream_round_robin::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_NOARGS, NGX_HTTP_UPS_CONF};

/// ngx_http_upstream_ip_hash_peer_data_t
struct IpHashPeerData {
    rrp: RrPeerData,
    hash: u64,
    addr: Vec<u8>,
    tries: u32,
}

impl PeerBalancer for IpHashPeerData {
    fn tries(&self) -> u32 {
        upstream_tries(&self.rrp.peers) as u32
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_ip_hash_peer(pc, self)
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

/// ngx_http_upstream_init_ip_hash
fn init_ip_hash(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    init_round_robin(cf, us)?;

    *us.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
        Ok(Box::new(init_ip_hash_peer(r, us)?))
    }));

    Ok(())
}

/// ngx_http_upstream_init_ip_hash_peer: the first three octets of an IPv4
/// client, all of an IPv6 one, and ngx_http_upstream_ip_hash_pseudo_addr
/// (three zero bytes) for others.
fn init_ip_hash_peer(r: &R, us: &Rc<UpstreamSrvConf>) -> Result<IpHashPeerData, ()> {
    let rrp = init_round_robin_peer(r, us)?;

    let addr = match &*r.connection.sockaddr.borrow() {
        SockAddr::V4(v4) => v4.ip().octets()[..3].to_vec(),
        SockAddr::V6(v6) => v6.ip().octets().to_vec(),
        _ => vec![0, 0, 0],
    };

    Ok(IpHashPeerData { rrp, hash: 89, addr, tries: 0 })
}

/// ngx_http_upstream_get_ip_hash_peer
fn get_ip_hash_peer(pc: &mut PeerConnection, iphp: &mut IpHashPeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get ip hash peer, try: {}", pc.tries);

    // TODO: cached

    let peers = iphp.rrp.peers.clone();

    if iphp.tries > 20 || peers.number.get() < 2 {
        return get_round_robin_peer(pc, &mut iphp.rrp);
    }

    if iphp.rrp.config_changed() {
        return get_round_robin_peer(pc, &mut iphp.rrp);
    }

    let now = ngx_core::times::time();

    pc.cached = false;
    pc.connection = None;

    let mut hash = iphp.hash;

    let list = peers.peers();

    let mut p = 0usize;
    let peer = match get_rr_peer_by_sid(&iphp.rrp, pc.hint.as_deref(), &mut p) {
        Some(peer) => peer,
        None => loop {
            for &b in iphp.addr.iter() {
                hash = (hash * 113 + b as u64) % 6271;
            }

            let mut w = (hash % peers.total_weight.get() as u64) as i64;
            p = 0;

            while w >= list[p].weight {
                w -= list[p].weight;
                p += 1;
            }

            let peer = &list[p];

            let skip = if iphp.rrp.is_tried(p) {
                true
            } else {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get ip hash peer, hash: {} {:04X}", p, 1u64 << (p % 64));
                peer.unavailable(now)
            };

            if !skip {
                break peer.clone();
            }

            iphp.tries += 1;
            if iphp.tries > 20 {
                return get_round_robin_peer(pc, &mut iphp.rrp);
            }
        },
    };

    iphp.rrp.current = Some(peer.clone());
    peer.refs.set(peer.refs.get() + 1);

    pc.sockaddr = Some(peer.sockaddr.clone());
    pc.name = peer.name.clone();
    pc.sid = Some(peer.sid.clone());

    peer.conns.set(peer.conns.get() + 1);

    if now - peer.checked.get() > peer.fail_timeout {
        peer.checked.set(now);
    }

    iphp.rrp.set_tried(p);
    iphp.hash = hash;

    NGX_OK
}

/// ngx_http_upstream_ip_hash
fn ip_hash_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"ip_hash\" directive is not allowed here"))?;

    set_balancer(
        cf,
        &uscf,
        init_ip_hash,
        NGX_HTTP_UPSTREAM_CREATE
            | NGX_HTTP_UPSTREAM_MODIFY
            | NGX_HTTP_UPSTREAM_WEIGHT
            | NGX_HTTP_UPSTREAM_MAX_CONNS
            | NGX_HTTP_UPSTREAM_MAX_FAILS
            | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
            | NGX_HTTP_UPSTREAM_DOWN,
    );

    Ok(())
}

pub fn upstream_ip_hash_module() -> ModuleDef {
    let commands = vec![cmd_fn!("ip_hash", NGX_HTTP_UPS_CONF | NGX_CONF_NOARGS, ConfLevel::None, ip_hash_handler)];
    http_module_def("ngx_http_upstream_ip_hash_module", HttpModuleDef::default(), commands)
}
