//! ngx_http_upstream_round_robin_module
//! Implements the default round-robin load balancing for upstream servers

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::*;
use crate::request::*;
use crate::upstream::*;
use crate::{NGX_HTTP_UPS_CONF, HttpModuleDef, http_module_def};

crate::http_module_index!("ngx_http_upstream_round_robin_module");

/// Round-robin peer per-request state
pub struct RoundRobinPeer {
    pub name: Vec<u8>,
    pub addr: Vec<u8>,
    pub port: u16,
    pub weight: u32,
    pub current_weight: u32,
    pub effective_weight: u32,
    pub total_weight: u32,
    pub down: bool,
    pub backup: bool,
    pub conns: u32,
    pub fails: u32,
}

impl Peer for RoundRobinPeer {
    fn free(&self, _r: &R, _pc: &Rc<ngx_core::connection::Connection>, _state: u32) {
        // TODO: Return connection to keepalive pool or close
    }

    fn tries(&self) -> u32 {
        1
    }

    fn name(&self) -> Vec<u8> {
        self.name.clone()
    }

    fn mark_down(&self) {
        // TODO: Track failures with timeout
    }

    fn stats(&self) -> PeerStats {
        PeerStats {
            conns: self.conns,
            fails: self.fails,
            effective_weight: self.effective_weight,
            current_weight: self.current_weight,
            total_weight: self.total_weight,
        }
    }
}

pub struct RoundRobinInit;

impl PeerInit for RoundRobinInit {
    fn init(&self, _r: &R, _upstream: &Upstream) -> Rc<dyn Peer> {
        // TODO: Implement round-robin selection
        // - Select peer with highest current_weight
        // - Decrease current_weight, increase by effective_weight
        // - Skip down/backup/maxconns peers
        // - Return Rc<RoundRobinPeer>
        Rc::new(RoundRobinPeer {
            name: b"127.0.0.1:8080".to_vec(),
            addr: b"127.0.0.1".to_vec(),
            port: 8080,
            weight: 1,
            current_weight: 1,
            effective_weight: 1,
            total_weight: 1,
            down: false,
            backup: false,
            conns: 0,
            fails: 0,
        })
    }
}

fn init(_cf: &mut Conf) -> ConfResult {
    // TODO: Initialize round-robin module
    Ok(())
}

pub fn upstream_round_robin_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        ..Default::default()
    };

    http_module_def("ngx_http_upstream_round_robin_module", def, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin_peer_creation() {
        let peer = RoundRobinPeer {
            name: b"127.0.0.1:8080".to_vec(),
            addr: b"127.0.0.1".to_vec(),
            port: 8080,
            weight: 1,
            current_weight: 1,
            effective_weight: 1,
            total_weight: 1,
            down: false,
            backup: false,
            conns: 0,
            fails: 0,
        };
        assert_eq!(peer.weight, 1);
        assert!(!peer.down);
    }
}
