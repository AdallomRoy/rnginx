//! ngx_event_quic_udp.c: the datagrams of a QUIC listening socket, read
//! by the listening's recvmsg task (event_udp.rs), go to the connection
//! listening at their destination connection id (ls->rbtree of the
//! sockets, here a map by the id and, for a wildcard listening, the local
//! address), or start a connection.

use std::cell::RefCell;
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::rc::{Rc, Weak};
use std::sync::atomic::Ordering;

use crate::connection::{stats, Connection, ListenHandler};
use crate::inet::SockAddr;
use crate::listening::Listening;
use crate::log::*;
use crate::string::B;
use crate::ngx_log_debug;

use super::transport::ngx_quic_get_packet_dcid;
use super::{ngx_quic_input, QuicSocket};

/// The key of a socket in the lookup of its listening.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct QuicKey {
    id: Vec<u8>,
    local: Option<SockAddr>,
}

/// ls->rbtree of a QUIC listening socket in a worker.
pub struct QuicListening {
    wildcard: bool,
    tree: RefCell<HashMap<QuicKey, Weak<QuicSocket>>>,
}

thread_local! {
    /// The lookups of the QUIC listening sockets, by listening socket.
    static LISTENINGS: RefCell<HashMap<RawFd, Rc<QuicListening>>> = RefCell::new(HashMap::new());
}

/// The lookup of a listening socket.
fn quic_listening(ls: &Listening) -> Rc<QuicListening> {
    let fd = ls.fd.get();

    LISTENINGS.with(|m| {
        m.borrow_mut().entry(fd).or_insert_with(|| Rc::new(QuicListening { wildcard: ls.wildcard.get(), tree: RefCell::new(HashMap::new()) })).clone()
    })
}

/// The listening socket closed: its lookup goes.
pub fn ngx_quic_close_listening(ls: &Listening) {
    let fd = ls.fd.get();

    LISTENINGS.with(|m| m.borrow_mut().remove(&fd));
}

/// The key of a socket of the connection.
fn socket_key(ql: &QuicListening, c: &Connection, id: &[u8]) -> QuicKey {
    let local = if ql.wildcard { c.local_sockaddr.borrow().clone() } else { None };

    QuicKey { id: id.to_vec(), local }
}

/// ngx_rbtree_insert(&c->listening->rbtree, &qsock->udp.node)
pub fn ngx_quic_insert_socket(c: &Connection, qsock: &Rc<QuicSocket>) {
    let ls = match c.listening() {
        Some(ls) => ls,
        None => return,
    };

    let ql = quic_listening(&ls);

    let key = socket_key(&ql, c, &qsock.sid.borrow().id);

    ql.tree.borrow_mut().insert(key.clone(), Rc::downgrade(qsock));

    *qsock.key.borrow_mut() = Some(key);
}

/// ngx_rbtree_delete(&c->listening->rbtree, &qsock->udp.node)
pub fn ngx_quic_unlisten(c: &Connection, qsock: &Rc<QuicSocket>) {
    let key = match qsock.key.borrow_mut().take() {
        Some(key) => key,
        None => return,
    };

    let ql = match c.listening() {
        Some(ls) => quic_listening(&ls),
        None => return,
    };

    let mut tree = ql.tree.borrow_mut();

    let ours = tree.get(&key).is_some_and(|w| std::ptr::eq(w.as_ptr(), Rc::as_ptr(qsock)));

    if ours {
        tree.remove(&key);
    }
}

/// ngx_quic_lookup_connection
fn ngx_quic_lookup_connection(ql: &QuicListening, key: &[u8], local_sockaddr: &SockAddr) -> Option<(Rc<Connection>, Rc<QuicSocket>)> {
    if key.is_empty() {
        return None;
    }

    let key = QuicKey { id: key.to_vec(), local: if ql.wildcard { Some(local_sockaddr.clone()) } else { None } };

    let qsock = ql.tree.borrow().get(&key).and_then(|w| w.upgrade())?;

    let c = qsock.connection.borrow().upgrade()?;

    Some((c, qsock))
}

/// The part of ngx_quic_recvmsg after a datagram is read: to the
/// connection of its destination connection id, or to a new connection.
/// false if the handler would return (the connection could not be
/// created).
pub fn ngx_quic_dispatch(ls: &Rc<Listening>, handler: &ListenHandler, log: &Log, sockaddr: SockAddr, local_sockaddr: SockAddr, data: &[u8]) -> bool {
    let n = data.len();

    crate::times::update_event_msec();

    if let SockAddr::Unix(path) = &sockaddr {
        if path.is_empty() {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "unbound unix socket");
            return true;
        }
    }

    let key = match ngx_quic_get_packet_dcid(log, data) {
        Some((start, end)) => &data[start..end],
        None => return true,
    };

    let ql = quic_listening(ls);

    if let Some((c, qsock)) = ngx_quic_lookup_connection(&ql, key, &local_sockaddr) {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic recvmsg: fd:{} n:{}", c.fd.get(), n);

        *qsock.sockaddr.borrow_mut() = sockaddr;

        *c.quic_sock.borrow_mut() = Some(qsock);

        ngx_quic_input(&c, data);

        return true;
    }

    stats().accepted.fetch_add(1, Ordering::Relaxed);

    crate::event::update_accept_disabled();

    let c = match Connection::accepted(ls.fd.get(), ls, sockaddr, log) {
        Some(c) => c,
        None => return false,
    };

    c.shared.set(true);

    // *log = ls->log: no connection number in the log lines yet
    c.log.set_connection(0);

    stats().active.fetch_add(1, Ordering::Relaxed);

    *c.local_sockaddr.borrow_mut() = Some(local_sockaddr);

    *c.buffer.borrow_mut() = data.to_vec();

    stats().handled.fetch_add(1, Ordering::Relaxed);

    crate::event_udp::debug_accepted_connection(&c, log);

    if c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
        let addr = c.sockaddr.borrow().to_text(true);
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "*{} quic recvmsg: {} fd:{} n:{}", c.number, B(&addr), c.fd.get(), n);
    }

    c.log.set_context(None);

    handler(c);

    true
}
