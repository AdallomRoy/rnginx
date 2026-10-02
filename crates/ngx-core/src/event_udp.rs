//! UDP listening sockets (src/event/ngx_event_udp.c): datagrams are read
//! with recvmsg() and dispatched to "pseudo" connections, one per client
//! (its address, and the local address for a wildcard listening), which
//! share the listening socket (ngx_event_recvmsg, ngx_udp_shared_recv, the
//! per-listening lookup of ngx_insert_udp_connection /
//! ngx_lookup_udp_connection / ngx_delete_udp_connection); a datagram is
//! sent on such a connection with sendmsg() and, for a wildcard listening,
//! the source address of the client's datagrams (ngx_udp_sendmsg_chain.c:
//! ngx_sendmsg_vec, ngx_sendmsg, ngx_set_srcaddr_cmsg,
//! ngx_get_srcaddr_cmsg).
//!
//! The async model. In C the listening socket's read handler reads a
//! datagram and, when the client has a connection already, calls the
//! connection's read handler synchronously with the datagram in
//! c->udp->buffer; the datagram is lost unless the handler reads it. Here
//! sessions are tasks, so:
//! - a datagram for an existing connection is appended to the
//!   connection's queue of unread datagrams (c->udp->buffer) and a task
//!   awaiting Connection::recv() is woken; recv() returns the datagrams in
//!   order, each truncated to the caller's buffer as ngx_udp_shared_recv
//!   does;
//! - after each datagram the recvmsg task yields, so the session runs
//!   (reads the datagram, or finishes and closes) before the next datagram
//!   is read, as with the synchronous handler call;
//! - datagrams a connection has not read when it leaves the lookup
//!   (ngx_delete_udp_connection, closing) are handed back to the listening
//!   and dispatched again: in C they would only have arrived after the
//!   connection was gone, so they start a new connection;
//! - a connection keeps at most NGX_UDP_MAX_UNREAD datagrams it does not
//!   read; more are dropped, as C drops a datagram the session does not
//!   read;
//! - a datagram for a connection whose read is delayed (c->read->delayed:
//!   the stream proxy's limit rate) is dropped, as the read handler
//!   returns without reading it in C.
//!
//! The listening socket is registered in the reactor as a dup() of the
//! listening descriptor owned by the listening's UDP state: the pseudo
//! connections send on it while the listening is open, and the
//! registration never outlives the descriptor it was made for, whenever
//! the listening socket itself is closed (ngx_close_listening_sockets).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::{Rc, Weak};
use std::sync::atomic::Ordering;

use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, SockaddrLike, SockaddrStorage, UnixAddr};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::connection::{stats, Connection, ListenHandler};
use crate::inet::{NixSockAddr, SockAddr};
use crate::listen_event::ListenEvent;
use crate::listening::Listening;
use crate::log::*;
use crate::rc::*;
use crate::string::B;
use crate::{fd, ngx_log_debug, ngx_log_error};

/// The most datagrams kept for a connection which does not read them.
pub const NGX_UDP_MAX_UNREAD: usize = 64;

/// The static buffer of ngx_event_recvmsg.
const NGX_UDP_BUFFER_SIZE: usize = 65535;

/// ngx_log_debug with an error number, e.g. "recvmsg() not ready (11: ...)"
macro_rules! udp_debug_err {
    ($log:expr, $err:expr, $($arg:tt)*) => {
        if $log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
            $log.error(NGX_LOG_DEBUG, Some($err), format_args!($($arg)*));
        }
    };
}

/// A dup() of a listening socket, closed on drop (after the AsyncFd owning
/// it has removed it from the reactor).
pub struct DupFd(OwnedFd);

impl AsRawFd for DupFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// The key of a connection in the lookup of its listening: the client
/// address and, for a wildcard listening, the local address (the bytes
/// hashed and compared by ngx_insert_udp_connection and
/// ngx_lookup_udp_connection).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct UdpKey {
    sockaddr: SockAddr,
    local: Option<SockAddr>,
}

/// The UDP state of a listening socket in a worker: ls->rbtree, the
/// pseudo connections of the clients by address, and the socket they
/// share.
pub struct UdpListening {
    /// the listening socket (c->fd of the pseudo connections)
    fd: RawFd,
    wildcard: bool,
    /// the dup() of the listening socket registered in the reactor for
    /// writing; taken when the listening socket is closed
    sock: RefCell<Option<Rc<AsyncFd<DupFd>>>>,
    /// the read event of the listening socket
    read_event: RefCell<Option<Rc<ListenEvent>>>,
    /// ls->rbtree
    tree: RefCell<HashMap<UdpKey, Weak<Connection>>>,
    /// the datagrams of connections which left the lookup before reading
    /// them, to dispatch again
    pending: RefCell<VecDeque<(UdpKey, Vec<u8>)>>,
    /// wakes the recvmsg task: pending datagrams, or the listening stopped
    wake: tokio::sync::Notify,
    stopped: Cell<bool>,
}

/// ngx_udp_connection_t: the state of a pseudo connection.
pub struct UdpConnection {
    listening: Rc<UdpListening>,
    key: UdpKey,
    /// c->udp->buffer: the datagrams received and not read yet
    buffer: RefCell<VecDeque<Vec<u8>>>,
    /// wakes a task waiting for a datagram
    notify: tokio::sync::Notify,
}

thread_local! {
    /// The UDP state of the listening sockets read in this process, by
    /// listening socket.
    static LISTENINGS: RefCell<HashMap<RawFd, Rc<UdpListening>>> = RefCell::new(HashMap::new());
}

impl UdpListening {
    /// Register a dup() of the listening socket in the reactor for writing;
    /// it is read on its read event.
    fn open(ls: &Listening, log: &Log, read_event: Rc<ListenEvent>) -> Option<Rc<UdpListening>> {
        let fd = ls.fd.get();

        let s = match fd::get(fd).and_then(|l| rustix::io::fcntl_dupfd_cloexec(&l, 0).map_err(io::Error::from)) {
            Ok(s) => s,
            Err(e) => {
                ngx_log_error!(NGX_LOG_ALERT, log, e.raw_os_error(), "fcntl(F_DUPFD_CLOEXEC) {} failed", B(&ls.addr_text));
                return None;
            }
        };

        let afd = match AsyncFd::with_interest(DupFd(s), Interest::WRITABLE) {
            Ok(a) => a,
            Err(e) => {
                ngx_log_error!(NGX_LOG_ALERT, log, e.raw_os_error(), "epoll_ctl() failed for {}", B(&ls.addr_text));
                return None;
            }
        };

        let ul = Rc::new(UdpListening {
            fd,
            wildcard: ls.wildcard.get(),
            sock: RefCell::new(Some(Rc::new(afd))),
            read_event: RefCell::new(Some(read_event)),
            tree: RefCell::new(HashMap::new()),
            pending: RefCell::new(VecDeque::new()),
            wake: tokio::sync::Notify::new(),
            stopped: Cell::new(false),
        });

        // the reading of a previous cycle's listening on the same socket
        // stops (ngx_event_process_init deletes the old accept events);
        // its connections still send on its socket

        let old = LISTENINGS.with(|m| m.borrow_mut().insert(fd, ul.clone()));

        if let Some(old) = old {
            old.stopped.set(true);
            old.wake.notify_one();
        }

        Some(ul)
    }

    fn sock(&self) -> Option<Rc<AsyncFd<DupFd>>> {
        self.sock.borrow().clone()
    }

    fn key(&self, sockaddr: &SockAddr, local_sockaddr: &SockAddr) -> UdpKey {
        UdpKey { sockaddr: sockaddr.clone(), local: if self.wildcard { Some(local_sockaddr.clone()) } else { None } }
    }

    /// The number of connections in the lookup.
    pub fn connections(&self) -> usize {
        self.tree.borrow().len()
    }
}

/// Stop reading datagrams on a listening socket which is being closed
/// (ngx_close_listening_sockets): its connections can no longer send, as
/// the descriptor they use is closed in C.
pub fn stop_recvmsg(ls: &Listening) {
    let fd = ls.fd.get();

    if ls.quic.get() {
        crate::quic::udp::ngx_quic_close_listening(ls);
    }

    let ul = LISTENINGS.with(|m| m.borrow_mut().remove(&fd));

    if let Some(ul) = ul {
        ul.stopped.set(true);
        ul.read_event.borrow_mut().take();
        ul.sock.borrow_mut().take();
        ul.wake.notify_one();
    }
}

/// ngx_event_recvmsg: the read handler of a UDP listening socket, as the
/// task reading its datagrams (instead of the accept loop of a TCP one).
pub async fn recvmsg_loop(ls: Rc<Listening>, ev: Rc<ListenEvent>) {
    let log = ls.log.borrow().clone();

    let handler = match ls.handler.borrow().clone() {
        Some(h) => h,
        None => return,
    };

    let ul = match UdpListening::open(&ls, &log, ev) {
        Some(ul) => ul,
        None => return,
    };

    // ngx_quic_recvmsg for a QUIC listening socket
    let quic = ls.quic.get();

    let mut buffer = vec![0u8; if quic { crate::quic::NGX_QUIC_MAX_UDP_PAYLOAD_SIZE } else { NGX_UDP_BUFFER_SIZE }];

    // the control buffer of recvmsg(), CMSG_SPACE(sizeof(ngx_addrinfo_t)),
    // made once (nix fills a Vec of that room)
    let mut control = nix::cmsg_space!(libc::in6_pktinfo);

    loop {
        // the datagrams of the connections which left the lookup unread

        loop {
            if ul.stopped.get() {
                return;
            }

            let next = ul.pending.borrow_mut().pop_front();

            let (key, data) = match next {
                Some(p) => p,
                None => break,
            };

            let local_sockaddr = key.local.clone().unwrap_or_else(|| ls.sockaddr.clone());

            if quic {
                crate::quic::udp::ngx_quic_dispatch(&ls, &handler, &log, key.sockaddr, local_sockaddr, &data);
            } else {
                dispatch(&ul, &ls, &handler, &log, key.sockaddr, local_sockaddr, &data);
            }

            tokio::task::yield_now().await;
        }

        let sock = match ul.sock() {
            Some(s) => s,
            None => return,
        };

        let ev = match ul.read_event.borrow().clone() {
            Some(ev) => ev,
            None => return,
        };

        let mut guard = tokio::select! {
            r = ev.wait() => match r {
                Ok(g) => g,
                Err(e) => {
                    ngx_log_error!(NGX_LOG_ALERT, log, e.raw_os_error(), "epoll_wait() failed for {}", B(&ls.addr_text));
                    return;
                }
            },
            _ = ul.wake.notified() => continue,
        };

        let available = crate::event::event_conf().map(|c| *c.borrow().multi_accept).unwrap_or(false);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "{}recvmsg on {}, ready: {}", if quic { "quic " } else { "" }, B(&ls.addr_text), available as i32);

        let mut again = false;

        loop {
            if !ul.pending.borrow().is_empty() {
                // older than the datagrams in the socket
                break;
            }

            let r = recvmsg(sock.get_ref().as_raw_fd(), &ls, &mut buffer, &mut control, &log);

            let (n, sockaddr, local_sockaddr) = match r {
                Recvmsg::Again => {
                    again = true;
                    break;
                }

                Recvmsg::Error => break,

                Recvmsg::Truncated => {
                    if !available {
                        break;
                    }
                    continue;
                }

                Recvmsg::Datagram(n, sockaddr, local_sockaddr) => (n, sockaddr, local_sockaddr),
            };

            let more = if quic { crate::quic::udp::ngx_quic_dispatch(&ls, &handler, &log, sockaddr, local_sockaddr, &buffer[..n]) } else { dispatch(&ul, &ls, &handler, &log, sockaddr, local_sockaddr, &buffer[..n]) };

            // the session handles the datagram before the next one is read

            tokio::task::yield_now().await;

            if ul.stopped.get() {
                return;
            }

            if !more || !available {
                break;
            }
        }

        ev.handled(&mut guard, again);
        drop(guard);
    }
}

/// The result of one recvmsg() on a listening socket.
enum Recvmsg {
    /// the datagram size, the client address, the local address
    Datagram(usize, SockAddr, SockAddr),
    /// EAGAIN
    Again,
    /// the error is logged
    Error,
    /// MSG_TRUNC or MSG_CTRUNC, logged
    Truncated,
}

/// The client address of a datagram.
enum Peer {
    Addr(SockAddr),
    /// msg_namelen 0
    Unnamed,
    /// another family than the listening socket's
    Unsupported(i32),
}

/// The recvmsg() of ngx_event_recvmsg, with the client address and the
/// local address (from IP_PKTINFO / IPV6_PKTINFO on a wildcard listening).
///
/// The address buffer is sizeof(ngx_sockaddr_t) for a unix listening (the
/// address length, 0 from an unbound socket, is kept in the UnixAddr),
/// sizeof(sockaddr_storage) otherwise (the kernel always writes an inet
/// address); the control buffer is CMSG_SPACE(sizeof(ngx_addrinfo_t)).
fn recvmsg(fd: RawFd, ls: &Listening, buffer: &mut [u8], control: &mut Vec<u8>, log: &Log) -> Recvmsg {
    let wildcard = ls.wildcard.get();

    let mut local_sockaddr = ls.sockaddr.clone();

    let mut iov = [IoSliceMut::new(buffer)];

    let r = if ls.sockaddr.is_unix() {
        nix::sys::socket::recvmsg::<UnixAddr>(fd, &mut iov, None, MsgFlags::empty()).map(|msg| {
            let peer = match &msg.address {
                Some(a) if a.len() != 0 => Peer::Addr(SockAddr::from_unix_addr(a)),
                _ => Peer::Unnamed,
            };

            (msg.bytes, msg.flags, peer)
        })
    } else {
        nix::sys::socket::recvmsg::<SockaddrStorage>(fd, &mut iov, wildcard.then_some(control), MsgFlags::empty()).map(|msg| {
            let peer = match &msg.address {
                Some(ss) => match SockAddr::from_nix(ss) {
                    Some(sa) => Peer::Addr(sa),
                    None => Peer::Unsupported(ss.family().map_or(0, |f| f as i32)),
                },
                None => Peer::Unnamed,
            };

            // the control data of a datagram not truncated (cmsgs() refuses
            // truncated control data)
            if wildcard && !msg.flags.contains(MsgFlags::MSG_TRUNC) {
                if let Ok(cmsgs) = msg.cmsgs() {
                    for cmsg in cmsgs {
                        if get_srcaddr_cmsg(&cmsg, &mut local_sockaddr) == NGX_OK {
                            break;
                        }
                    }
                }
            }

            (msg.bytes, msg.flags, peer)
        })
    };

    let quic = if ls.quic.get() { "quic " } else { "" };

    let (n, flags, peer) = match r {
        Ok(r) => r,

        Err(Errno::EAGAIN) => {
            udp_debug_err!(log, libc::EAGAIN, "{}recvmsg() not ready", quic);
            return Recvmsg::Again;
        }

        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e as i32), "{}recvmsg() failed", quic);
            return Recvmsg::Error;
        }
    };

    if flags.intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC) {
        ngx_log_error!(NGX_LOG_ALERT, log, None, "{}recvmsg() truncated data", quic);
        return Recvmsg::Truncated;
    }

    let sockaddr = match peer {
        Peer::Addr(sa) => sa,

        // on Linux recvmsg() returns zero msg_namelen
        // when receiving packets from unbound AF_UNIX sockets:
        // a zeroed sockaddr of the listening's family
        Peer::Unnamed => match ls.sockaddr.family() {
            libc::AF_INET => SockAddr::v4(Ipv4Addr::UNSPECIFIED, 0),
            libc::AF_INET6 => SockAddr::v6(Ipv6Addr::UNSPECIFIED, 0),
            _ => SockAddr::Unix(Vec::new()),
        },

        Peer::Unsupported(family) => {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "recvmsg() returned an unsupported address family {}", family);
            return Recvmsg::Error;
        }
    };

    Recvmsg::Datagram(n, sockaddr, local_sockaddr)
}

/// The part of ngx_event_recvmsg after a datagram is read: give it to the
/// client's connection, or start one. false if the handler would return
/// (the connection could not be created).
fn dispatch(ul: &Rc<UdpListening>, ls: &Rc<Listening>, handler: &ListenHandler, log: &Log, sockaddr: SockAddr, local_sockaddr: SockAddr, data: &[u8]) -> bool {
    let n = data.len();

    if let Some(c) = lookup_udp_connection(ul, &sockaddr, &local_sockaddr, log) {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "recvmsg: fd:{} n:{}", c.fd.get(), n);

        if let Some(udp) = c.udp_conn() {
            udp.add_datagram(&c, data);
        }

        return true;
    }

    stats().accepted.fetch_add(1, Ordering::Relaxed);

    crate::event::update_accept_disabled();

    // ngx_get_connection (worker_connections), c->sockaddr, c->log (a copy
    // of ls->log), c->listening, c->type, c->number, c->start_time,
    // c->addr_text

    let c = match Connection::accepted(ul.fd, ls, sockaddr, log) {
        Some(c) => c,
        None => return false,
    };

    c.shared.set(true);

    // *log = ls->log: no connection number in the log lines yet
    c.log.set_connection(0);

    stats().active.fetch_add(1, Ordering::Relaxed);

    c.need_flush_buf.set(true);

    *c.local_sockaddr.borrow_mut() = Some(local_sockaddr);

    *c.buffer.borrow_mut() = data.to_vec();

    stats().handled.fetch_add(1, Ordering::Relaxed);

    debug_accepted_connection(&c, log);

    if c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
        let addr = c.sockaddr.borrow().to_text(true);
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "*{} recvmsg: {} fd:{} n:{}", c.number, B(&addr), c.fd.get(), n);
    }

    insert_udp_connection(&c, ul);

    c.log.set_context(None);

    handler(c);

    true
}

/// ngx_debug_accepted_connection
pub(crate) fn debug_accepted_connection(c: &Connection, log: &Log) {
    if log.level() & NGX_LOG_DEBUG_CONNECTION != 0 {
        return;
    }

    let cidrs = crate::event::debug_connection_cidrs();

    if cidrs.is_empty() {
        return;
    }

    let peer = c.sockaddr.borrow().clone();

    if cidrs.iter().any(|ci| crate::event::debug_connection_match(ci, &peer)) {
        c.log.set_level(NGX_LOG_DEBUG_CONNECTION | NGX_LOG_DEBUG_ALL);
    }
}

/// ngx_insert_udp_connection
fn insert_udp_connection(c: &Rc<Connection>, ul: &Rc<UdpListening>) {
    if c.udp_conn().is_some() {
        return;
    }

    let local_sockaddr = c.local_sockaddr.borrow().clone().unwrap_or_else(|| c.sockaddr.borrow().clone());
    let key = ul.key(&c.sockaddr.borrow(), &local_sockaddr);

    let udp = Rc::new(UdpConnection { listening: ul.clone(), key: key.clone(), buffer: RefCell::new(VecDeque::new()), notify: tokio::sync::Notify::new() });

    ul.tree.borrow_mut().insert(key, Rc::downgrade(c));

    c.set_udp_conn(udp);
    c.udp.set(true);
}

/// ngx_delete_udp_connection: remove a pseudo connection from the lookup
/// of its listening socket, so that the next datagram of the client
/// starts a new connection; the connection reads no more datagrams
/// (Connection::recv() waits forever, as ngx_udp_shared_recv returns
/// NGX_AGAIN for c->udp == NULL) but can still send. Datagrams it has not
/// read are dispatched again by the listening. Called on close (the pool
/// cleanup in C), and by the stream proxy once a session has its requests
/// (proxy_requests).
pub fn delete_udp_connection(c: &Connection) {
    if !c.udp.get() {
        return;
    }

    let udp = match c.udp_conn() {
        Some(u) => u,
        None => return,
    };

    c.udp.set(false);

    let ul = &udp.listening;

    {
        let mut tree = ul.tree.borrow_mut();

        let ours = tree.get(&udp.key).is_some_and(|w| std::ptr::eq(w.as_ptr(), c));

        if ours {
            tree.remove(&udp.key);
        }
    }

    let unread: Vec<Vec<u8>> = udp.buffer.borrow_mut().drain(..).collect();

    if unread.is_empty() || ul.stopped.get() {
        return;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "udp connection deleted with {} unread datagrams", unread.len());

    {
        let mut pending = ul.pending.borrow_mut();

        for d in unread {
            pending.push_back((udp.key.clone(), d));
        }
    }

    ul.wake.notify_one();
}

/// ngx_lookup_udp_connection
fn lookup_udp_connection(ul: &UdpListening, sockaddr: &SockAddr, local_sockaddr: &SockAddr, log: &Log) -> Option<Rc<Connection>> {
    if let SockAddr::Unix(path) = sockaddr {
        if path.is_empty() {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "unbound unix socket");
            return None;
        }
    }

    let key = ul.key(sockaddr, local_sockaddr);

    let c = ul.tree.borrow().get(&key).and_then(|w| w.upgrade())?;

    if !c.udp.get() {
        return None;
    }

    Some(c)
}

impl UdpConnection {
    /// A datagram for the connection (ngx_event_recvmsg: c->udp->buffer
    /// and the read handler).
    fn add_datagram(&self, c: &Connection, data: &[u8]) {
        if c.read_delayed.get() {
            // the read handler is called with the read event delayed: it
            // returns at once, and the datagram is lost
            return;
        }

        let mut buffer = self.buffer.borrow_mut();

        if buffer.len() >= NGX_UDP_MAX_UNREAD {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "recvmsg: datagram dropped, {} unread", buffer.len());
            return;
        }

        buffer.push_back(data.to_vec());

        drop(buffer);

        self.notify.notify_one();
    }

    /// Drop the datagrams not read yet (a delayed read event).
    pub fn drop_unread(&self, c: &Connection) {
        let n = {
            let mut buffer = self.buffer.borrow_mut();
            let n = buffer.len();
            buffer.clear();
            n
        };

        if n > 0 {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "recvmsg: {} datagrams dropped, the read is delayed", n);
        }
    }

    /// There is a datagram to read (c->read->ready).
    pub fn ready(&self, c: &Connection) -> bool {
        c.udp.get() && !self.buffer.borrow().is_empty()
    }

    /// The number of datagrams received and not read yet.
    pub fn unread(&self) -> usize {
        self.buffer.borrow().len()
    }

    /// ngx_udp_shared_recv: the next datagram, truncated to the buffer, or
    /// None (NGX_AGAIN).
    pub fn try_recv(&self, c: &Connection, buf: &mut [u8]) -> Option<usize> {
        if !c.udp.get() {
            return None;
        }

        let b = self.buffer.borrow_mut().pop_front()?;

        let n = b.len().min(buf.len());

        buf[..n].copy_from_slice(&b[..n]);

        Some(n)
    }

    /// Wait for the next datagram (Connection::recv).
    pub async fn recv(&self, c: &Connection, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if c.is_closed() {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }

            if let Some(n) = self.try_recv(c, buf) {
                return Ok(n);
            }

            self.notify.notified().await;
        }
    }

    /// Wait until there is a datagram to read (Connection::readable).
    pub async fn readable(&self, c: &Connection) -> io::Result<()> {
        loop {
            if c.is_closed() {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }

            if self.ready(c) {
                return Ok(());
            }

            self.notify.notified().await;
        }
    }

    /// The next datagram without reading it (Connection::peek), truncated
    /// to the buffer.
    pub async fn peek(&self, c: &Connection, buf: &mut [u8]) -> io::Result<usize> {
        self.readable(c).await?;

        let buffer = self.buffer.borrow();
        let b = buffer.front().expect("udp datagram");

        let n = b.len().min(buf.len());

        buf[..n].copy_from_slice(&b[..n]);

        Ok(n)
    }

    /// Connection::peek_more: a datagram does not grow, so when the next
    /// datagram has no more than `have` bytes it is reported as the end of
    /// the data.
    pub async fn peek_more(&self, c: &Connection, buf: &mut [u8], have: usize) -> io::Result<(usize, bool)> {
        let n = self.peek(c, buf).await?;
        Ok((n, n <= have))
    }

    /// One sendmsg() attempt: WouldBlock if the socket cannot take the
    /// datagram now.
    pub fn try_send(&self, c: &Connection, iov: &[&[u8]]) -> io::Result<usize> {
        self.sendmsg_vec(c, iov)
    }

    /// Send the buffers as one datagram to the client, waiting for the
    /// socket if needed (ngx_udp_unix_sendmsg_chain).
    pub async fn send(&self, c: &Connection, iov: &[&[u8]]) -> io::Result<usize> {
        loop {
            match self.sendmsg_vec(c, iov) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                r => return r,
            }

            let sock = match self.listening.sock() {
                Some(s) => s,
                None => return Err(io::Error::from_raw_os_error(libc::EBADF)),
            };

            let mut guard = sock.writable().await?;

            match self.sendmsg_vec(c, iov) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                r => return r,
            }
        }
    }

    /// Wait until the socket can take a datagram (Connection::writable).
    pub async fn writable(&self) -> io::Result<()> {
        let sock = match self.listening.sock() {
            Some(s) => s,
            None => return Err(io::Error::from_raw_os_error(libc::EBADF)),
        };

        let _g = sock.writable().await?;

        Ok(())
    }

    /// ngx_sendmsg_vec: the buffers as one datagram to c->sockaddr, from
    /// c->local_sockaddr on a wildcard listening.
    fn sendmsg_vec(&self, c: &Connection, iov: &[&[u8]]) -> io::Result<usize> {
        if c.is_closed() {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }

        let sock = match self.listening.sock() {
            Some(s) => s,
            None => return Err(io::Error::from_raw_os_error(libc::EBADF)),
        };

        // the iovecs on the stack (NGX_IOVS_PREALLOCATE), the empty buffers
        // left out
        let mut stack = [IoSlice::new(&[]); NGX_IOVS_PREALLOCATE];
        let mut heap = Vec::new();
        let mut nio = 0;

        for s in iov.iter().filter(|s| !s.is_empty()) {
            if nio < NGX_IOVS_PREALLOCATE {
                stack[nio] = IoSlice::new(s);
            } else {
                if heap.is_empty() {
                    heap.extend_from_slice(&stack);
                }

                heap.push(IoSlice::new(s));
            }

            nio += 1;
        }

        // zero-sized datagram; pretend to have at least 1 iov

        let iovs: &[IoSlice<'_>] = if nio > NGX_IOVS_PREALLOCATE { &heap } else { &stack[..nio.max(1)] };

        let addr = c.sockaddr.borrow().clone();

        // the source address on a wildcard listening (none for a unix one)
        let local = if self.listening.wildcard { c.local_sockaddr.borrow().clone() } else { None };

        let n = sendmsg(c, sock.get_ref().0.as_fd(), iovs, &addr, None, local.as_ref())?;

        c.sent.set(c.sent.get() + n as u64);

        Ok(n)
    }
}

/// NGX_IOVS_PREALLOCATE
const NGX_IOVS_PREALLOCATE: usize = 64;

/// sendmsg() of the buffers as one datagram to the address (or, with
/// `segment`, as datagrams of that size), from the source address `src`
/// (a wildcard listening's local address): the control messages of
/// ngx_set_srcaddr_cmsg() and UDP_SEGMENT built on the stack
/// (ngx_sys::os::sendmsg_udp) for an inet address; a unix one has none,
/// and goes with nix.
pub(crate) fn sendmsg_udp(fd: BorrowedFd<'_>, iov: &[IoSlice<'_>], addr: &SockAddr, segment: Option<u16>, src: Option<&SockAddr>) -> nix::Result<usize> {
    let dest = match addr {
        SockAddr::V4(a) => std::net::SocketAddr::V4(*a),
        SockAddr::V6(a) => std::net::SocketAddr::V6(*a),
        SockAddr::Unix(_) => return sendmsg_to(fd.as_raw_fd(), iov, &[], &addr.to_nix()),
    };

    let src = match src {
        Some(SockAddr::V4(a)) => Some(ngx_sys::os::UdpSrcAddr::V4(*a.ip())),
        Some(SockAddr::V6(a)) => Some(ngx_sys::os::UdpSrcAddr::V6(*a.ip())),
        _ => None,
    };

    ngx_sys::os::sendmsg_udp(fd, iov, &dest, segment, src).map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(libc::EINVAL)))
}

/// sendmsg() of the buffers as one datagram to the address, with the
/// control messages (nix wants the address as its own type).
pub(crate) fn sendmsg_to(fd: RawFd, iov: &[IoSlice<'_>], cmsgs: &[ControlMessage<'_>], addr: &NixSockAddr) -> nix::Result<usize> {
    let flags = MsgFlags::empty();

    match addr {
        NixSockAddr::V4(a) => nix::sys::socket::sendmsg(fd, iov, cmsgs, flags, Some(a)),
        NixSockAddr::V6(a) => nix::sys::socket::sendmsg(fd, iov, cmsgs, flags, Some(a)),
        NixSockAddr::Unix(a) => nix::sys::socket::sendmsg(fd, iov, cmsgs, flags, Some(a)),
    }
}

/// ngx_sendmsg: EAGAIN is WouldBlock; other errors are returned to the
/// caller, which logs "sendmsg() failed" (ngx_connection_error).
fn sendmsg(c: &Connection, fd: BorrowedFd<'_>, iov: &[IoSlice<'_>], addr: &SockAddr, segment: Option<u16>, src: Option<&SockAddr>) -> io::Result<usize> {
    loop {
        let n = match sendmsg_udp(fd, iov, addr, segment, src) {
            Ok(n) => n,

            Err(Errno::EAGAIN) => {
                udp_debug_err!(c.log, libc::EAGAIN, "sendmsg() not ready");
                return Err(io::ErrorKind::WouldBlock.into());
            }

            Err(Errno::EINTR) => {
                udp_debug_err!(c.log, libc::EINTR, "sendmsg() was interrupted");
                continue;
            }

            Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
        };

        if c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
            let size: usize = iov.iter().map(|v| v.len()).sum();
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "sendmsg: {} of {}", n, size);
        }

        return Ok(n);
    }
}

/// The control message of ngx_set_srcaddr_cmsg: IP_PKTINFO with the source
/// address in ipi_spec_dst, or IPV6_PKTINFO with it in ipi6_addr.
pub enum SrcAddrCmsg {
    V4(libc::in_pktinfo),
    V6(libc::in6_pktinfo),
}

impl SrcAddrCmsg {
    /// The message for sendmsg(): CMSG_SPACE(sizeof(struct in_pktinfo)) or
    /// CMSG_SPACE(sizeof(struct in6_pktinfo)) bytes of control data.
    pub fn cmsg(&self) -> ControlMessage<'_> {
        match self {
            SrcAddrCmsg::V4(pkt) => ControlMessage::Ipv4PacketInfo(pkt),
            SrcAddrCmsg::V6(pkt6) => ControlMessage::Ipv6PacketInfo(pkt6),
        }
    }
}

/// ngx_set_srcaddr_cmsg: the control message with the source address of a
/// datagram; None, no control data, for a unix socket.
pub fn set_srcaddr_cmsg(local_sockaddr: &SockAddr) -> Option<SrcAddrCmsg> {
    match local_sockaddr {
        SockAddr::V4(sin) => Some(SrcAddrCmsg::V4(libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr { s_addr: u32::from(*sin.ip()).to_be() },
            ipi_addr: libc::in_addr { s_addr: 0 },
        })),

        SockAddr::V6(sin6) => Some(SrcAddrCmsg::V6(libc::in6_pktinfo { ipi6_addr: libc::in6_addr { s6_addr: sin6.ip().octets() }, ipi6_ifindex: 0 })),

        SockAddr::Unix(_) => None,
    }
}

/// ngx_get_srcaddr_cmsg: the local address of a received datagram.
pub fn get_srcaddr_cmsg(cmsg: &ControlMessageOwned, local_sockaddr: &mut SockAddr) -> i64 {
    match (cmsg, local_sockaddr) {
        (ControlMessageOwned::Ipv4PacketInfo(pkt), SockAddr::V4(sin)) => {
            sin.set_ip(Ipv4Addr::from(u32::from_be(pkt.ipi_addr.s_addr)));
            NGX_OK
        }

        (ControlMessageOwned::Ipv6PacketInfo(pkt6), SockAddr::V6(sin6)) => {
            sin6.set_ip(Ipv6Addr::from(pkt6.ipi6_addr.s6_addr));
            NGX_OK
        }

        _ => NGX_DECLINED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogChain;
    use std::future::Future;
    use crate::os;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// A socket of the descriptor table, by its number (the listening
    /// sockets and the peers are registered).
    fn registered(s: impl Into<OwnedFd>) -> RawFd {
        fd::register(s.into())
    }

    /// the read event of the listening socket, added
    fn read_event(ls: &Listening) -> Rc<ListenEvent> {
        let ev = ListenEvent::new(ls.fd.get()).unwrap();
        ev.add(false).unwrap();
        Rc::new(ev)
    }

    type Conns = Rc<RefCell<Vec<Rc<Connection>>>>;

    fn run<F: Future<Output = ()>>(f: F) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, f);
    }

    fn sockaddr(a: SocketAddr) -> SockAddr {
        match a {
            SocketAddr::V4(a) => SockAddr::V4(a),
            SocketAddr::V6(a) => SockAddr::V6(a),
        }
    }

    /// A UDP listening socket as ngx_open_listening_sockets and
    /// ngx_configure_listening_sockets make it, whose handler keeps the
    /// connections.
    fn udp_listening(addr: &str) -> (Rc<Listening>, SocketAddr, Conns) {
        let sock = std::net::UdpSocket::bind(addr).unwrap();
        sock.set_nonblocking(true).unwrap();
        let bound = sock.local_addr().unwrap();

        let sa = sockaddr(bound);
        let wildcard = sa.is_wildcard();

        if wildcard {
            nix::sys::socket::setsockopt(&sock, nix::sys::socket::sockopt::Ipv4PacketInfo, &true).unwrap();
        }

        let fd = registered(sock);

        let mut ls = Listening::new(sa, Log::new(LogChain::new()));
        ls.ty = libc::SOCK_DGRAM;
        ls.fd.set(fd);
        ls.wildcard.set(wildcard);
        ls.addr_ntop.set(true);

        let conns: Conns = Rc::new(RefCell::new(Vec::new()));
        let cc = conns.clone();
        let handler: ListenHandler = Rc::new(move |c: Rc<Connection>| cc.borrow_mut().push(c));
        *ls.handler.borrow_mut() = Some(handler);

        (Rc::new(ls), bound, conns)
    }

    async fn wait_for(f: impl Fn() -> bool) {
        for _ in 0..400 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out");
    }

    async fn client(addr: &str) -> tokio::net::UdpSocket {
        tokio::net::UdpSocket::bind(addr).await.unwrap()
    }

    async fn read_from(s: &tokio::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 1024];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), s.recv_from(&mut buf)).await.expect("datagram").unwrap();
        (buf[..n].to_vec(), from)
    }

    async fn recv(c: &Connection, buf: &mut [u8]) -> usize {
        tokio::time::timeout(Duration::from_secs(2), c.recv(buf)).await.expect("datagram").unwrap()
    }

    /// The number of connections in the lookup of a listening being read.
    fn lookup_size(ls: &Listening) -> usize {
        LISTENINGS.with(|m| m.borrow().get(&ls.fd.get()).cloned()).expect("udp listening").connections()
    }

    #[test]
    fn datagrams_of_a_client_go_to_its_connection() {
        run(async {
            let (ls, addr, conns) = udp_listening("127.0.0.1:0");
            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let a = client("127.0.0.1:0").await;
            let b = client("127.0.0.1:0").await;

            // a new client: a new connection with the datagram in c.buffer

            a.send_to(b"a1", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;

            let c = conns.borrow()[0].clone();
            assert_eq!(c.ty, libc::SOCK_DGRAM);
            assert!(c.shared.get());
            assert!(c.udp.get());
            assert!(c.is_udp_shared());
            assert!(c.need_flush_buf.get());
            assert_eq!(c.fd.get(), ls.fd.get());
            assert_eq!(&*c.buffer.borrow(), b"a1");
            assert_eq!(*c.sockaddr.borrow(), sockaddr(a.local_addr().unwrap()));
            assert_eq!(&*c.addr_text.borrow(), b"127.0.0.1");
            assert_eq!(c.local_sockaddr(), Some(sockaddr(addr)));

            // the next datagrams of the client are read from the connection,
            // each truncated to the buffer (ngx_udp_shared_recv)

            let mut buf = [0u8; 16];

            a.send_to(b"a2", addr).await.unwrap();
            let n = recv(&c, &mut buf).await;
            assert_eq!(&buf[..n], b"a2");

            a.send_to(b"hello", addr).await.unwrap();
            let mut small = [0u8; 3];
            let n = recv(&c, &mut small).await;
            assert_eq!(&small[..n], b"hel");
            assert_eq!(c.try_recv(&mut buf).unwrap_err().kind(), io::ErrorKind::WouldBlock);

            // peek does not read

            a.send_to(b"pk", addr).await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(2), c.peek(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..n], b"pk");
            tokio::time::timeout(Duration::from_secs(2), c.readable()).await.unwrap().unwrap();
            assert_eq!(c.try_recv(&mut buf).unwrap(), 2);

            // an empty datagram is not the end of the data

            a.send_to(b"", addr).await.unwrap();
            let n = recv(&c, &mut buf).await;
            assert_eq!(n, 0);
            assert!(!c.read_eof.get());
            assert_eq!(conns.borrow().len(), 1);

            // replies are datagrams to the client from the listening address

            assert_eq!(c.send(b"reply").await.unwrap(), 5);
            assert_eq!(read_from(&a).await, (b"reply".to_vec(), addr));

            assert_eq!(c.writev(&[b"ab", b"", b"cd"]).await.unwrap(), 4);
            assert_eq!(read_from(&a).await, (b"abcd".to_vec(), addr));

            assert_eq!(c.send(b"").await.unwrap(), 0);
            assert_eq!(read_from(&a).await, (Vec::new(), addr));

            assert_eq!(c.try_send(b"t").unwrap(), 1);
            assert_eq!(read_from(&a).await, (b"t".to_vec(), addr));

            assert_eq!(c.sent.get(), 10);

            // another client, another connection

            b.send_to(b"b1", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 2).await;
            let c2 = conns.borrow()[1].clone();
            assert_eq!(&*c2.buffer.borrow(), b"b1");
            assert_eq!(*c2.sockaddr.borrow(), sockaddr(b.local_addr().unwrap()));
            assert!(c.number != c2.number);
            assert_eq!(lookup_size(&ls), 2);

            // closing removes the connection from the lookup: the next
            // datagram of the client starts a new connection; the
            // listening socket stays open

            c.close();
            assert!(!c.udp.get());
            assert!(c.is_closed());
            assert!(c.recv(&mut buf).await.is_err());
            assert_eq!(lookup_size(&ls), 1);

            a.send_to(b"a3", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 3).await;
            let c3 = conns.borrow()[2].clone();
            assert_eq!(&*c3.buffer.borrow(), b"a3");
            assert_eq!(lookup_size(&ls), 2);

            // dropping the last reference closes it too
            conns.borrow_mut().remove(1);
            drop(c2);
            assert_eq!(lookup_size(&ls), 1);

            c3.send(b"again").await.unwrap();
            assert_eq!(read_from(&a).await, (b"again".to_vec(), addr));

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
        });
    }

    #[test]
    fn delete_dispatches_unread_datagrams_again() {
        run(async {
            let (ls, addr, conns) = udp_listening("127.0.0.1:0");
            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let a = client("127.0.0.1:0").await;

            a.send_to(b"x1", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;
            let x = conns.borrow()[0].clone();
            let udp = x.udp_conn().unwrap();

            a.send_to(b"x2", addr).await.unwrap();
            a.send_to(b"x3", addr).await.unwrap();
            wait_for(|| udp.unread() == 2).await;
            assert!(udp.ready(&x));

            // ngx_delete_udp_connection (proxy_requests): the unread
            // datagrams start a new connection

            delete_udp_connection(&x);
            assert!(!x.udp.get());
            assert!(!udp.ready(&x));

            wait_for(|| conns.borrow().len() == 2).await;
            let y = conns.borrow()[1].clone();
            assert_eq!(&*y.buffer.borrow(), b"x2");
            assert_eq!(lookup_size(&ls), 1);

            let mut buf = [0u8; 16];
            let n = recv(&y, &mut buf).await;
            assert_eq!(&buf[..n], b"x3");

            // the deleted connection reads nothing more, but still sends

            assert_eq!(x.try_recv(&mut buf).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            assert!(tokio::time::timeout(Duration::from_millis(50), x.recv(&mut buf)).await.is_err());

            x.send(b"late").await.unwrap();
            assert_eq!(read_from(&a).await, (b"late".to_vec(), addr));

            // and its close does not remove the new connection

            x.close();
            assert_eq!(lookup_size(&ls), 1);
            a.send_to(b"y2", addr).await.unwrap();
            let n = recv(&y, &mut buf).await;
            assert_eq!(&buf[..n], b"y2");
            assert_eq!(conns.borrow().len(), 2);

            // a connection closed with unread datagrams: they start a new one

            a.send_to(b"y3", addr).await.unwrap();
            let yu = y.udp_conn().unwrap();
            wait_for(|| yu.unread() == 1).await;
            y.close();
            wait_for(|| conns.borrow().len() == 3).await;
            assert_eq!(&*conns.borrow()[2].buffer.borrow(), b"y3");

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
        });
    }

    #[test]
    fn unread_datagrams_are_limited() {
        run(async {
            let (ls, addr, conns) = udp_listening("127.0.0.1:0");
            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let a = client("127.0.0.1:0").await;

            a.send_to(b"first", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;
            let c = conns.borrow()[0].clone();
            let udp = c.udp_conn().unwrap();

            for i in 0..NGX_UDP_MAX_UNREAD + 8 {
                a.send_to(format!("{}", i).as_bytes(), addr).await.unwrap();
            }

            // the queue gets full, then the datagrams are dropped
            wait_for(|| udp.unread() == NGX_UDP_MAX_UNREAD).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(udp.unread(), NGX_UDP_MAX_UNREAD);
            assert_eq!(conns.borrow().len(), 1);

            let mut buf = [0u8; 16];
            let n = recv(&c, &mut buf).await;
            assert_eq!(&buf[..n], b"0");

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
        });
    }

    #[test]
    fn delayed_read_drops_datagrams() {
        run(async {
            let (ls, addr, conns) = udp_listening("127.0.0.1:0");
            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let a = client("127.0.0.1:0").await;

            a.send_to(b"first", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;
            let c = conns.borrow()[0].clone();
            let udp = c.udp_conn().unwrap();

            // queued, then dropped when the read gets delayed

            a.send_to(b"q", addr).await.unwrap();
            wait_for(|| udp.unread() == 1).await;
            c.read_delayed.set(true);
            udp.drop_unread(&c);
            assert_eq!(udp.unread(), 0);

            // lost while the read is delayed (the read handler returns)

            a.send_to(b"lost", addr).await.unwrap();
            a.send_to(b"lost2", addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(udp.unread(), 0);
            assert_eq!(conns.borrow().len(), 1);

            // read again once the delay is over

            c.read_delayed.set(false);
            a.send_to(b"next", addr).await.unwrap();
            let mut buf = [0u8; 16];
            let n = recv(&c, &mut buf).await;
            assert_eq!(&buf[..n], b"next");

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
        });
    }

    #[test]
    fn worker_connections_are_not_enough() {
        run(async {
            crate::connection::set_connection_n(crate::connection::active_connections() + 1);

            let (ls, addr, conns) = udp_listening("127.0.0.1:0");
            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let a = client("127.0.0.1:0").await;
            let b = client("127.0.0.1:0").await;

            a.send_to(b"a", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;

            // no connection for b: the datagram is dropped
            b.send_to(b"b", addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(conns.borrow().len(), 1);

            // the connection of a still gets its datagrams
            a.send_to(b"a2", addr).await.unwrap();
            let c = conns.borrow()[0].clone();
            let mut buf = [0u8; 16];
            let n = recv(&c, &mut buf).await;
            assert_eq!(&buf[..n], b"a2");

            // once it is gone, b gets one
            c.close();
            drop(c);
            conns.borrow_mut().clear();
            b.send_to(b"b2", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;
            assert_eq!(&*conns.borrow()[0].buffer.borrow(), b"b2");

            crate::connection::set_connection_n(512);
            stop_recvmsg(&ls);
            os::close(ls.fd.get());
        });
    }

    #[test]
    fn wildcard_listening_uses_the_datagram_destination() {
        // 127.0.0.2 is local on Linux (127.0.0.0/8 on lo)
        if std::net::UdpSocket::bind("127.0.0.2:0").is_err() {
            return;
        }

        run(async {
            let (ls, bound, conns) = udp_listening("0.0.0.0:0");
            assert!(ls.wildcard.get());
            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let port = bound.port();
            let to2: SocketAddr = format!("127.0.0.2:{}", port).parse().unwrap();
            let to1: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

            let a = client("127.0.0.1:0").await;

            a.send_to(b"t", to2).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;
            let c = conns.borrow()[0].clone();
            assert_eq!(c.local_sockaddr(), Some(sockaddr(to2)));

            // the reply comes from the address the client sent to
            c.send(b"r").await.unwrap();
            assert_eq!(read_from(&a).await, (b"r".to_vec(), to2));

            // the same client to another local address: another connection
            a.send_to(b"u", to1).await.unwrap();
            wait_for(|| conns.borrow().len() == 2).await;
            let c1 = conns.borrow()[1].clone();
            assert_eq!(c1.local_sockaddr(), Some(sockaddr(to1)));
            c1.send(b"s").await.unwrap();
            assert_eq!(read_from(&a).await, (b"s".to_vec(), to1));

            // and to the first one again: the first connection
            a.send_to(b"t2", to2).await.unwrap();
            let mut buf = [0u8; 16];
            let n = recv(&c, &mut buf).await;
            assert_eq!(&buf[..n], b"t2");
            assert_eq!(conns.borrow().len(), 2);

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
        });
    }

    #[test]
    fn wildcard_listening_inet6() {
        let probe = match std::net::UdpSocket::bind("[::1]:0") {
            Ok(s) => s,
            Err(_) => return,
        };
        drop(probe);

        run(async {
            let sock = std::net::UdpSocket::bind("[::]:0").unwrap();
            sock.set_nonblocking(true).unwrap();
            let bound = sock.local_addr().unwrap();

            nix::sys::socket::setsockopt(&sock, nix::sys::socket::sockopt::Ipv6RecvPacketInfo, &true).unwrap();

            let fd = registered(sock);

            let mut ls = Listening::new(sockaddr(bound), Log::new(LogChain::new()));
            ls.ty = libc::SOCK_DGRAM;
            ls.fd.set(fd);
            ls.wildcard.set(true);

            let conns: Conns = Rc::new(RefCell::new(Vec::new()));
            let cc = conns.clone();
            let handler: ListenHandler = Rc::new(move |c: Rc<Connection>| cc.borrow_mut().push(c));
            *ls.handler.borrow_mut() = Some(handler);
            let ls = Rc::new(ls);

            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let to: SocketAddr = format!("[::1]:{}", bound.port()).parse().unwrap();
            let a = client("[::1]:0").await;

            a.send_to(b"six", to).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;
            let c = conns.borrow()[0].clone();
            assert_eq!(c.local_sockaddr(), Some(sockaddr(to)));
            assert_eq!(&*c.addr_text.borrow(), b"::1");

            c.send(b"r6").await.unwrap();
            assert_eq!(read_from(&a).await, (b"r6".to_vec(), to));

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
        });
    }

    #[test]
    fn unix_datagram_listening() {
        run(async {
            let dir = std::env::temp_dir().join(format!("ngx-udp-test-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("listen.sock");
            let cpath = dir.join("client.sock");

            let sock = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
            sock.set_nonblocking(true).unwrap();
            let fd = registered(sock);

            let spath = path.to_str().unwrap().as_bytes().to_vec();
            let mut ls = Listening::new(SockAddr::Unix(spath.clone()), Log::new(LogChain::new()));
            ls.ty = libc::SOCK_DGRAM;
            ls.fd.set(fd);
            ls.addr_ntop.set(true);

            let conns: Conns = Rc::new(RefCell::new(Vec::new()));
            let cc = conns.clone();
            let handler: ListenHandler = Rc::new(move |c: Rc<Connection>| cc.borrow_mut().push(c));
            *ls.handler.borrow_mut() = Some(handler);
            let ls = Rc::new(ls);

            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            // a bound client: its connection gets its next datagrams, and
            // replies reach it

            let a = tokio::net::UnixDatagram::bind(&cpath).unwrap();
            a.send_to(b"u1", &path).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;
            let c = conns.borrow()[0].clone();
            assert_eq!(*c.sockaddr.borrow(), SockAddr::Unix(cpath.to_str().unwrap().as_bytes().to_vec()));
            assert_eq!(c.local_sockaddr(), Some(SockAddr::Unix(spath.clone())));

            a.send_to(b"u2", &path).await.unwrap();
            let mut buf = [0u8; 16];
            let n = recv(&c, &mut buf).await;
            assert_eq!(&buf[..n], b"u2");

            c.send(b"ur").await.unwrap();
            let n = tokio::time::timeout(Duration::from_secs(2), a.recv(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..n], b"ur");

            // an unbound client: a new connection for each datagram
            // ("unbound unix socket")

            let u = tokio::net::UnixDatagram::unbound().unwrap();
            u.send_to(b"n1", &path).await.unwrap();
            wait_for(|| conns.borrow().len() == 2).await;
            u.send_to(b"n2", &path).await.unwrap();
            wait_for(|| conns.borrow().len() == 3).await;
            assert_eq!(*conns.borrow()[2].sockaddr.borrow(), SockAddr::Unix(Vec::new()));
            assert_eq!(&*conns.borrow()[2].buffer.borrow(), b"n2");
            assert_eq!(&*conns.borrow()[2].addr_text.borrow(), b"unix:");

            // closing one of them does not remove the other
            conns.borrow()[1].close();
            assert!(conns.borrow()[2].udp.get());

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn unix_client_with_a_path_filling_sun_path() {
        run(async {
            let dir = std::env::temp_dir().join(format!("ngx-udp-sun-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("listen.sock");

            let sock = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
            sock.set_nonblocking(true).unwrap();
            let fd = registered(sock);

            let mut ls = Listening::new(SockAddr::Unix(path.to_str().unwrap().as_bytes().to_vec()), Log::new(LogChain::new()));
            ls.ty = libc::SOCK_DGRAM;
            ls.fd.set(fd);

            let conns: Conns = Rc::new(RefCell::new(Vec::new()));
            let cc = conns.clone();
            let handler: ListenHandler = Rc::new(move |c: Rc<Connection>| cc.borrow_mut().push(c));
            *ls.handler.borrow_mut() = Some(handler);
            let ls = Rc::new(ls);

            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            // a client bound to a path of all 108 bytes of sun_path: the
            // kernel returns it without a NUL
            let mut name = dir.to_str().unwrap().as_bytes().to_vec();
            name.push(b'/');
            name.resize(108, b'c');
            let client = rustix::net::socket(rustix::net::AddressFamily::UNIX, rustix::net::SocketType::DGRAM, None).unwrap();
            rustix::net::bind(&client, &rustix::net::SocketAddrUnix::new(name.as_slice()).unwrap()).unwrap();
            rustix::net::sendto(&client, b"full", rustix::net::SendFlags::empty(), &rustix::net::SocketAddrUnix::new(path.as_path()).unwrap()).unwrap();

            wait_for(|| conns.borrow().len() == 1).await;
            assert_eq!(*conns.borrow()[0].sockaddr.borrow(), SockAddr::Unix(name.clone()));
            assert_eq!(&*conns.borrow()[0].buffer.borrow(), b"full");

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn truncated_datagram_is_dropped() {
        run(async {
            let dir = std::env::temp_dir().join(format!("ngx-udp-trunc-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("listen.sock");
            let cpath = dir.join("client.sock");

            let sock = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
            sock.set_nonblocking(true).unwrap();
            let fd = registered(sock);

            // the listening's log, kept

            let logged: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
            let lg = logged.clone();
            let chain = LogChain::new();
            chain.insert(LogEntry::new(NGX_LOG_INFO, LogWriter::Custom(Rc::new(move |_, line: &[u8]| lg.borrow_mut().extend_from_slice(line)))));

            let mut ls = Listening::new(SockAddr::Unix(path.to_str().unwrap().as_bytes().to_vec()), Log::new(chain));
            ls.ty = libc::SOCK_DGRAM;
            ls.fd.set(fd);

            let conns: Conns = Rc::new(RefCell::new(Vec::new()));
            let cc = conns.clone();
            let handler: ListenHandler = Rc::new(move |c: Rc<Connection>| cc.borrow_mut().push(c));
            *ls.handler.borrow_mut() = Some(handler);
            let ls = Rc::new(ls);

            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let a = tokio::net::UnixDatagram::bind(&cpath).unwrap();

            let big = vec![b'x'; NGX_UDP_BUFFER_SIZE + 10];
            a.send_to(&big, &path).await.unwrap();
            a.send_to(b"small", &path).await.unwrap();

            wait_for(|| conns.borrow().len() == 1).await;
            assert_eq!(&*conns.borrow()[0].buffer.borrow(), b"small");

            let log = String::from_utf8_lossy(&logged.borrow()).into_owned();
            assert!(log.contains("[alert]"), "{}", log);
            assert!(log.contains("recvmsg() truncated data"), "{}", log);

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn stopped_listening_connections_cannot_send() {
        run(async {
            let (ls, addr, conns) = udp_listening("127.0.0.1:0");
            let h = crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            let a = client("127.0.0.1:0").await;
            a.send_to(b"a", addr).await.unwrap();
            wait_for(|| conns.borrow().len() == 1).await;
            let c = conns.borrow()[0].clone();

            // ngx_close_listening_sockets
            stop_recvmsg(&ls);
            os::close(ls.fd.get());

            let e = c.send(b"x").await.unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EBADF));

            // the recvmsg task ends
            tokio::time::timeout(Duration::from_secs(2), h).await.unwrap().unwrap();

            c.close();
        });
    }

    /// A relay of a client connection to a connected UDP upstream as the
    /// stream proxy does it with "proxy_requests 2": the connection leaves
    /// the lookup after its second datagram, and ends once it has the
    /// responses.
    async fn relay(c: Rc<Connection>, backend: SocketAddr) {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect(backend).unwrap();
        s.set_nonblocking(true).unwrap();

        let pc = Connection::peer(registered(s), libc::SOCK_DGRAM, sockaddr(backend), &c.log).unwrap();

        let mut requests = 1;
        let mut responses = 0;

        let first = c.buffer.borrow().clone();
        pc.send(&first).await.unwrap();

        let mut down = [0u8; 1024];
        let mut up = [0u8; 1024];

        loop {
            tokio::select! {
                r = c.recv(&mut down) => {
                    let n = r.unwrap();
                    requests += 1;
                    pc.send(&down[..n]).await.unwrap();
                    if requests == 2 {
                        delete_udp_connection(&c);
                    }
                }
                r = pc.recv(&mut up) => {
                    let n = r.unwrap();
                    c.send(&up[..n]).await.unwrap();
                    responses += 1;
                    if !c.udp.get() && responses == requests {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(2)) => break,
            }
        }

        pc.close();
        c.close();
    }

    #[test]
    fn relay_with_requests_limit() {
        run(async {
            // the backend answers "<relay port> <datagram>", the first one late

            let backend = Rc::new(client("127.0.0.1:0").await);
            let baddr = backend.local_addr().unwrap();

            let b = backend.clone();
            crate::event::spawn(async move {
                let mut buf = [0u8; 64];
                let mut first = true;
                loop {
                    let (n, from) = b.recv_from(&mut buf).await.unwrap();
                    if first {
                        first = false;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    let reply = format!("{} {}", from.port(), String::from_utf8_lossy(&buf[..n]));
                    b.send_to(reply.as_bytes(), from).await.unwrap();
                }
            });

            let (ls, addr, _) = udp_listening("127.0.0.1:0");

            let handler: ListenHandler = Rc::new(move |c: Rc<Connection>| {
                crate::event::spawn(relay(c, baddr));
            });
            *ls.handler.borrow_mut() = Some(handler);

            crate::event::spawn(recvmsg_loop(ls.clone(), read_event(&ls)));

            // 5 datagrams at once: sessions of 1-2, 3-4 and 5

            let a = client("127.0.0.1:0").await;
            for i in 1..=5 {
                a.send_to(format!("{}", i).as_bytes(), addr).await.unwrap();
            }

            let mut got: Vec<(u16, u32)> = Vec::new();
            for _ in 0..5 {
                let (d, from) = read_from(&a).await;
                assert_eq!(from, addr);
                let s = String::from_utf8(d).unwrap();
                let mut it = s.split(' ');
                let port: u16 = it.next().unwrap().parse().unwrap();
                let n: u32 = it.next().unwrap().parse().unwrap();
                got.push((port, n));
            }

            got.sort_by_key(|g| g.1);

            let ports: Vec<u16> = got.iter().map(|g| g.0).collect();
            assert_eq!(got.iter().map(|g| g.1).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5]);
            assert_eq!(ports[0], ports[1]);
            assert_eq!(ports[2], ports[3]);
            assert!(ports[1] != ports[2]);
            assert!(ports[3] != ports[4]);
            assert!(ports[0] != ports[4]);

            stop_recvmsg(&ls);
            os::close(ls.fd.get());
        });
    }

    #[test]
    fn connected_udp_socket() {
        run(async {
            let server = client("127.0.0.1:0").await;
            let saddr = server.local_addr().unwrap();

            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.connect(saddr).unwrap();
            s.set_nonblocking(true).unwrap();
            let caddr = s.local_addr().unwrap();

            let log = Log::new(LogChain::new());
            let c = Connection::peer(registered(s), libc::SOCK_DGRAM, sockaddr(saddr), &log).unwrap();
            assert_eq!(c.ty, libc::SOCK_DGRAM);
            assert!(!c.is_udp_shared());

            c.send(b"ping").await.unwrap();
            c.writev(&[b"a", b"b"]).await.unwrap();
            assert_eq!(read_from(&server).await, (b"ping".to_vec(), caddr));
            assert_eq!(read_from(&server).await, (b"ab".to_vec(), caddr));

            server.send_to(b"", caddr).await.unwrap();
            server.send_to(b"pong", caddr).await.unwrap();

            let mut buf = [0u8; 16];
            let n = recv(&c, &mut buf).await;
            assert_eq!(n, 0);
            assert!(!c.read_eof.get());
            let n = recv(&c, &mut buf).await;
            assert_eq!(&buf[..n], b"pong");

            c.close();
        });
    }

    #[test]
    fn connected_udp_socket_icmp_error() {
        run(async {
            // a port nobody listens on: the datagram brings ICMP port
            // unreachable, reported as EPOLLERR alone

            let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let dead = probe.local_addr().unwrap();
            drop(probe);

            let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            s.connect(dead).unwrap();
            s.set_nonblocking(true).unwrap();

            let log = Log::new(LogChain::new());
            let c = Connection::peer(registered(s), libc::SOCK_DGRAM, sockaddr(dead), &log).unwrap();

            c.send(b"x").await.unwrap();

            // readable() wakes up, and recv() returns the error

            tokio::time::timeout(Duration::from_secs(2), c.readable()).await.expect("error event").unwrap();

            let mut buf = [0u8; 16];
            let e = c.try_recv(&mut buf).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::ECONNREFUSED));

            // the error is reported once
            assert_eq!(c.try_recv(&mut buf).unwrap_err().kind(), io::ErrorKind::WouldBlock);
            assert!(tokio::time::timeout(Duration::from_millis(50), c.readable()).await.is_err());

            // and recv() waiting for it gets it too
            c.send(b"y").await.unwrap();
            let e = tokio::time::timeout(Duration::from_secs(2), c.recv(&mut buf)).await.expect("error").unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::ECONNREFUSED));

            c.close();
        });
    }

    #[test]
    fn srcaddr_cmsg() {
        // ngx_set_srcaddr_cmsg: IP_PKTINFO with ipi_spec_dst

        let local = SockAddr::v4(Ipv4Addr::new(127, 0, 0, 2), 8999);

        match set_srcaddr_cmsg(&local) {
            Some(m @ SrcAddrCmsg::V4(pkt)) => {
                assert_eq!(u32::from_be(pkt.ipi_spec_dst.s_addr), u32::from(Ipv4Addr::new(127, 0, 0, 2)));
                assert_eq!(pkt.ipi_addr.s_addr, 0);
                assert_eq!(pkt.ipi_ifindex, 0);
                assert!(matches!(m.cmsg(), ControlMessage::Ipv4PacketInfo(_)));
            }
            _ => panic!("IP_PKTINFO"),
        }

        // ngx_get_srcaddr_cmsg: ipi_addr into the local address, the port kept

        let pkt = libc::in_pktinfo { ipi_ifindex: 0, ipi_spec_dst: libc::in_addr { s_addr: 0 }, ipi_addr: libc::in_addr { s_addr: u32::from(Ipv4Addr::new(10, 1, 2, 3)).to_be() } };
        let cmsg = ControlMessageOwned::Ipv4PacketInfo(pkt);

        let mut l = SockAddr::v4(Ipv4Addr::UNSPECIFIED, 53);
        assert_eq!(get_srcaddr_cmsg(&cmsg, &mut l), NGX_OK);
        assert_eq!(l, SockAddr::v4(Ipv4Addr::new(10, 1, 2, 3), 53));

        // another family: declined
        let mut l6 = SockAddr::v6(Ipv6Addr::UNSPECIFIED, 53);
        assert_eq!(get_srcaddr_cmsg(&cmsg, &mut l6), NGX_DECLINED);
        assert_eq!(l6, SockAddr::v6(Ipv6Addr::UNSPECIFIED, 53));

        // IPv6: IPV6_PKTINFO both ways

        let ip6: Ipv6Addr = "2001:db8::1".parse().unwrap();

        let pkt6 = match set_srcaddr_cmsg(&SockAddr::v6(ip6, 8999)) {
            Some(m @ SrcAddrCmsg::V6(pkt6)) => {
                assert_eq!(pkt6.ipi6_addr.s6_addr, ip6.octets());
                assert_eq!(pkt6.ipi6_ifindex, 0);
                assert!(matches!(m.cmsg(), ControlMessage::Ipv6PacketInfo(_)));
                pkt6
            }
            _ => panic!("IPV6_PKTINFO"),
        };

        let cmsg6 = ControlMessageOwned::Ipv6PacketInfo(pkt6);

        let mut l = SockAddr::v6(Ipv6Addr::UNSPECIFIED, 8999);
        assert_eq!(get_srcaddr_cmsg(&cmsg6, &mut l), NGX_OK);
        assert_eq!(l, SockAddr::v6(ip6, 8999));

        let mut l4 = SockAddr::v4(Ipv4Addr::UNSPECIFIED, 1);
        assert_eq!(get_srcaddr_cmsg(&cmsg6, &mut l4), NGX_DECLINED);

        // no source address for a unix socket
        assert!(set_srcaddr_cmsg(&SockAddr::Unix(b"/tmp/x".to_vec())).is_none());
    }

    #[test]
    fn datagrams_with_control_data() {
        use std::os::fd::AsFd;

        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let tx = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();

        let dest = match rx.local_addr().unwrap() {
            SocketAddr::V4(a) => SockAddr::V4(a),
            SocketAddr::V6(a) => SockAddr::V6(a),
        };

        // the source address of a wildcard listening, from two buffers
        let src = SockAddr::v4(Ipv4Addr::LOCALHOST, 8999);
        let n = sendmsg_udp(tx.as_fd(), &[IoSlice::new(b"one "), IoSlice::new(b"datagram")], &dest, None, Some(&src)).unwrap();
        assert_eq!(n, 12);

        let mut buf = [0u8; 64];
        let (n, from) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"one datagram");
        assert_eq!(from.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));

        // a unix datagram socket: no control data, through nix
        let dir = std::env::temp_dir().join(format!("ngx-udp-test-{}", std::process::id()));
        let _ = std::fs::create_dir(&dir);
        let path = dir.join("rx.sock");
        let _ = std::fs::remove_file(&path);

        let urx = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        urx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let utx = std::os::unix::net::UnixDatagram::unbound().unwrap();

        let dest = SockAddr::Unix(path.as_os_str().as_encoded_bytes().to_vec());
        let n = sendmsg_udp(utx.as_fd(), &[IoSlice::new(b"unix")], &dest, None, Some(&src)).unwrap();
        assert_eq!(n, 4);
        let n = urx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"unix");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
