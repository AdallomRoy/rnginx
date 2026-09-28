//! Listening sockets (ngx_listening_t).

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::os::unix::io::RawFd;
use std::rc::Rc;

use crate::inet::SockAddr;
use crate::log::Log;

pub struct Listening {
    pub fd: Cell<RawFd>,
    pub sockaddr: SockAddr,
    pub addr_text: Vec<u8>,
    pub ty: i32, // SOCK_STREAM / SOCK_DGRAM
    pub backlog: Cell<i32>,
    pub rcvbuf: Cell<i32>,
    pub sndbuf: Cell<i32>,
    pub keepidle: Cell<i32>,
    pub keepintvl: Cell<i32>,
    pub keepcnt: Cell<i32>,
    /// Protocol handler installed by http/stream/mail.
    pub handler: RefCell<Option<crate::connection::ListenHandler>>,
    /// Per-address protocol data (e.g. ngx_http_port_t).
    pub servers: RefCell<Option<Rc<dyn Any>>>,
    pub log: RefCell<Log>,
    pub pool_size: Cell<usize>,
    pub previous: RefCell<Option<Rc<Listening>>>,
    pub worker: Cell<usize>,

    pub open: Cell<bool>,
    pub remain: Cell<bool>,
    pub ignore: Cell<bool>,
    pub bound: Cell<bool>,
    pub inherited: Cell<bool>,
    pub nonblocking_accept: Cell<bool>,
    pub listen: Cell<bool>,
    pub nonblocking: Cell<bool>,
    pub shared: Cell<bool>,
    pub addr_ntop: Cell<bool>,
    pub wildcard: Cell<bool>,
    pub ipv6only: Cell<bool>,
    pub reuseport: Cell<bool>,
    pub add_reuseport: Cell<bool>,
    pub keepalive: Cell<u8>,
    pub quic: Cell<bool>,
    pub deferred_accept: Cell<bool>,
    pub delete_deferred: Cell<bool>,
    pub add_deferred: Cell<bool>,
    pub fastopen: Cell<i32>,
    /// protocol identifier (e.g. "http", "stream", "mail", "quic") used to detect changes on reload
    pub protocol: RefCell<&'static str>,
    pub change_protocol: Cell<bool>,
}

impl Listening {
    pub fn new(sockaddr: SockAddr, log: Log) -> Listening {
        let addr_text = sockaddr.to_text(true);
        Listening {
            fd: Cell::new(-1),
            addr_text,
            ty: libc::SOCK_STREAM,
            sockaddr,
            backlog: Cell::new(511),
            rcvbuf: Cell::new(-1),
            sndbuf: Cell::new(-1),
            keepidle: Cell::new(0),
            keepintvl: Cell::new(0),
            keepcnt: Cell::new(0),
            handler: RefCell::new(None),
            servers: RefCell::new(None),
            log: RefCell::new(log),
            pool_size: Cell::new(256),
            previous: RefCell::new(None),
            worker: Cell::new(0),
            open: Cell::new(false),
            remain: Cell::new(false),
            ignore: Cell::new(false),
            bound: Cell::new(false),
            inherited: Cell::new(false),
            nonblocking_accept: Cell::new(false),
            listen: Cell::new(false),
            nonblocking: Cell::new(false),
            shared: Cell::new(false),
            addr_ntop: Cell::new(false),
            wildcard: Cell::new(false),
            ipv6only: Cell::new(false),
            reuseport: Cell::new(false),
            add_reuseport: Cell::new(false),
            keepalive: Cell::new(0),
            quic: Cell::new(false),
            deferred_accept: Cell::new(false),
            delete_deferred: Cell::new(false),
            add_deferred: Cell::new(false),
            fastopen: Cell::new(-1),
            protocol: RefCell::new(""),
            change_protocol: Cell::new(false),
        }
    }

    pub fn is_unix(&self) -> bool {
        matches!(self.sockaddr, SockAddr::Unix(_))
    }

    /// Create a per-worker copy of this listening for SO_REUSEPORT fanout.
    /// Ported from ngx_clone_listening: same address + options, fresh fd/state,
    /// bound to the given `worker` index.
    pub fn clone_for_worker(&self, worker: usize) -> Listening {
        Listening {
            fd: Cell::new(-1),
            sockaddr: self.sockaddr.clone(),
            addr_text: self.addr_text.clone(),
            ty: self.ty,
            backlog: Cell::new(self.backlog.get()),
            rcvbuf: Cell::new(self.rcvbuf.get()),
            sndbuf: Cell::new(self.sndbuf.get()),
            keepidle: Cell::new(self.keepidle.get()),
            keepintvl: Cell::new(self.keepintvl.get()),
            keepcnt: Cell::new(self.keepcnt.get()),
            handler: RefCell::new(self.handler.borrow().clone()),
            servers: RefCell::new(self.servers.borrow().clone()),
            log: RefCell::new(self.log.borrow().clone()),
            pool_size: Cell::new(self.pool_size.get()),
            previous: RefCell::new(None),
            worker: Cell::new(worker),
            open: Cell::new(false),
            remain: Cell::new(false),
            ignore: Cell::new(false),
            bound: Cell::new(false),
            inherited: Cell::new(false),
            nonblocking_accept: Cell::new(self.nonblocking_accept.get()),
            listen: Cell::new(false),
            nonblocking: Cell::new(self.nonblocking.get()),
            shared: Cell::new(self.shared.get()),
            addr_ntop: Cell::new(self.addr_ntop.get()),
            wildcard: Cell::new(self.wildcard.get()),
            ipv6only: Cell::new(self.ipv6only.get()),
            reuseport: Cell::new(true),
            add_reuseport: Cell::new(false),
            keepalive: Cell::new(self.keepalive.get()),
            quic: Cell::new(self.quic.get()),
            deferred_accept: Cell::new(self.deferred_accept.get()),
            delete_deferred: Cell::new(false),
            add_deferred: Cell::new(false),
            fastopen: Cell::new(self.fastopen.get()),
            protocol: RefCell::new(*self.protocol.borrow()),
            change_protocol: Cell::new(false),
        }
    }
}
