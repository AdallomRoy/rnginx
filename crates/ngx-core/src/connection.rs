//! Connections and listening sockets (ngx_connection.c) on top of tokio's AsyncFd.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::io::IoSlice;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::{Rc, Weak};

use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, SockaddrStorage};
use rustix::net::sockopt;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::cycle::*;
use crate::fd;
use crate::inet::SockAddr;
use crate::listening::Listening;
use crate::log::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error, os};

pub type ListenHandler = Rc<dyn Fn(Rc<Connection>)>;

/// The read handler of a connection run with c->close set.
pub type CloseHandler = Rc<dyn Fn(&Rc<Connection>)>;

/// ngx_pool_cleanup_t of a connection's pool
pub struct PoolCleanup {
    /// the module that added it (the cleanup handler compared in C)
    pub tag: &'static str,
    /// cln->data
    pub data: Option<Rc<dyn Any>>,
    pub handler: Option<Box<dyn FnOnce()>>,
}

/// ngx_connection_log_error_e
pub const NGX_ERROR_ALERT: u32 = 0;
pub const NGX_ERROR_ERR: u32 = 1;
pub const NGX_ERROR_INFO: u32 = 2;
pub const NGX_ERROR_IGNORE_ECONNRESET: u32 = 3;
pub const NGX_ERROR_IGNORE_EINVAL: u32 = 4;
pub const NGX_ERROR_IGNORE_EMSGSIZE: u32 = 5;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcpNodelay {
    Unset,
    Set,
    Disabled,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcpNopush {
    Unset,
    Set,
    Disabled,
}

/// Outcome of one attempt of an operation driven by Connection::drive_io
/// (SSL_ERROR_WANT_READ / SSL_ERROR_WANT_WRITE map to WantRead / WantWrite).
pub enum IoStep<T> {
    Done(T),
    WantRead,
    WantWrite,
}

pub struct Fd(pub RawFd);

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Shared statistics (in shared memory when workers > 1).
#[repr(C)]
#[derive(zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout)]
pub struct Stats {
    pub connection_counter: std::sync::atomic::AtomicU64,
    pub accepted: std::sync::atomic::AtomicU64,
    pub handled: std::sync::atomic::AtomicU64,
    pub requests: std::sync::atomic::AtomicU64,
    pub active: std::sync::atomic::AtomicI64,
    pub reading: std::sync::atomic::AtomicI64,
    pub writing: std::sync::atomic::AtomicI64,
    pub waiting: std::sync::atomic::AtomicI64,
    pub temp_number: std::sync::atomic::AtomicU64,
    /// ngx_accept_mutex: the pid of the worker holding it, or 0
    pub accept_mutex: std::sync::atomic::AtomicI64,
}

/// The stats block in shared memory, once init_shared_stats() mapped it.
static STATS_SHARED: std::sync::OnceLock<&'static Stats> = std::sync::OnceLock::new();
static STATS_LOCAL: Stats = Stats {
    connection_counter: std::sync::atomic::AtomicU64::new(0),
    accepted: std::sync::atomic::AtomicU64::new(0),
    handled: std::sync::atomic::AtomicU64::new(0),
    requests: std::sync::atomic::AtomicU64::new(0),
    active: std::sync::atomic::AtomicI64::new(0),
    reading: std::sync::atomic::AtomicI64::new(0),
    writing: std::sync::atomic::AtomicI64::new(0),
    waiting: std::sync::atomic::AtomicI64::new(0),
    temp_number: std::sync::atomic::AtomicU64::new(0),
    accept_mutex: std::sync::atomic::AtomicI64::new(0),
};

pub fn stats() -> &'static Stats {
    match STATS_SHARED.get() {
        Some(s) => s,
        None => &STATS_LOCAL,
    }
}

/// Allocate the shared stats block (called once in the master before forking).
pub fn init_shared_stats(log: &Log) {
    if STATS_SHARED.get().is_some() {
        return;
    }

    let size = std::mem::size_of::<Stats>().max(4096);

    // an anonymous shared mapping (zero-filled), inherited by the workers
    let map = match mmap_rs::MmapOptions::new(size).and_then(|o| o.with_flags(mmap_rs::MmapFlags::SHARED).map_mut()) {
        Ok(m) => m,
        Err(e) => {
            let err = match &e {
                mmap_rs::Error::Nix(errno) => Some(*errno as i32),
                mmap_rs::Error::Io(e) => e.raw_os_error(),
                _ => None,
            };
            ngx_log_error!(NGX_LOG_ALERT, log, err, "mmap(MAP_ANON|MAP_SHARED, {}) failed", size);
            return;
        }
    };

    // mapped for the life of the process, as the C shared memory is
    let map: &'static mut mmap_rs::MmapMut = Box::leak(Box::new(map));

    // a page-aligned mapping larger than the block: the cast succeeds
    if let Ok((shared, _)) = <Stats as zerocopy::FromBytes>::mut_from_prefix(map.as_mut_slice()) {
        let _ = STATS_SHARED.set(shared);
    }
}

thread_local! {
    static CONNECTIONS: RefCell<HashMap<u64, Weak<Connection>>> = RefCell::new(HashMap::new());
    static ACTIVE: Cell<usize> = const { Cell::new(0) };
    /// the connections taken of connection_n, from ngx_get_connection() to
    /// ngx_free_connection() (cycle->free_connection_n is what is left)
    static USED: Cell<usize> = const { Cell::new(0) };
    static CONNECTION_N: Cell<usize> = const { Cell::new(512) };
    /// cycle->reusable_connections_queue: the reusable connections, the
    /// last one reusable for the longest time
    static REUSABLE: RefCell<LinkedSlab<Weak<Connection>>> = const { RefCell::new(LinkedSlab::new()) };
    /// cycle->connections_reuse_time
    static REUSE_TIME: Cell<i64> = const { Cell::new(0) };
    static CLOSE_NOTIFY: Rc<tokio::sync::Notify> = Rc::new(tokio::sync::Notify::new());
}

pub fn set_connection_n(n: usize) {
    CONNECTION_N.with(|c| c.set(n));
}

pub fn connection_n() -> usize {
    CONNECTION_N.with(|c| c.get())
}

/// The connection objects alive.
pub fn active_connections() -> usize {
    ACTIVE.with(|a| a.get())
}

/// cycle->free_connection_n
pub fn free_connections() -> usize {
    connection_n().saturating_sub(USED.with(|u| u.get()))
}

/// ngx_get_connection() for what has no connection object here: the
/// listening sockets of a worker (ngx_event_process_init) and its channel
/// (ngx_add_channel_event) take a connection each for good.
pub fn reserve_connections(n: usize) {
    USED.with(|u| u.set(u.get() + n));
}

/// ngx_drain_connections: when the free connections run low, the oldest
/// reusable ones are closed, their read handlers called with c->close.
fn drain_connections() {
    let reusable_n = REUSABLE.with(|q| q.borrow().len());

    if free_connections() > connection_n() / 16 || reusable_n == 0 {
        return;
    }

    let now = crate::times::cached().sec;

    if REUSE_TIME.with(|t| t.replace(now)) != now {
        if let Some(cycle) = crate::cycle::try_cycle() {
            ngx_log_error!(NGX_LOG_WARN, cycle.log, None, "{} worker_connections are not enough, reusing connections", connection_n());
        }
    }

    let mut c: Option<Rc<Connection>> = None;
    let n = (reusable_n / 8).clamp(1, 32);

    for _ in 0..n {
        // ngx_queue_last(): the connection reusable for the longest time
        let last = REUSABLE.with(|q| q.borrow().last().map(|(k, w)| (k, w.upgrade())));

        let rc = match last {
            Some((_, Some(rc))) => rc,
            Some((key, None)) => {
                REUSABLE.with(|q| q.borrow_mut().remove(key));
                continue;
            }
            None => break,
        };

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, rc.log, "reusing connection");

        rc.close.set(true);
        rc.close_read_handler();

        c = Some(rc);
    }

    if free_connections() == 0 {
        if let Some(c) = c.filter(|c| c.reusable.get()) {
            // if no connections were freed, try to reuse the last
            // connection again: this should free it as long as
            // previous reuse moved it to lingering close

            ngx_log_debug!(NGX_LOG_DEBUG_CORE, c.log, "reusing connection again");

            c.close.set(true);
            c.close_read_handler();
        }
    }
}

/// Notified, while the worker is exiting, whenever a connection or other
/// pending work is gone (graceful shutdown waits for the last one).
pub fn close_notify() -> Rc<tokio::sync::Notify> {
    CLOSE_NOTIFY.with(|n| n.clone())
}

pub fn for_each_connection(mut f: impl FnMut(&Rc<Connection>)) {
    let conns: Vec<Rc<Connection>> = CONNECTIONS.with(|c| c.borrow().values().filter_map(|w| w.upgrade()).collect());
    for c in conns {
        f(&c);
    }
}

/// The Rc of a connection known by reference only (the OpenSSL callbacks
/// find the connection by a pointer, ngx_ssl_get_connection()); None for a
/// per-stream copy of an HTTP/2 connection.
pub fn connection_rc(c: &Connection) -> Option<Rc<Connection>> {
    if c.fake {
        return None;
    }

    c.this.upgrade()
}

/// Nodes in a slab linked by index, for the queues C links through the
/// objects themselves (ngx_queue_t): inserting at the head, removing an
/// item by its key and finding the last one take constant time, the order
/// is the insertion order, and nothing is allocated once the slab is as
/// large as the queue has been. A key is a node's index plus one; 0 is no
/// key (an item not in the queue).
struct LinkedSlab<T> {
    nodes: Vec<SlabNode<T>>,
    /// the first node (the last inserted), the last one, the first free one
    head: u32,
    tail: u32,
    free: u32,
    len: usize,
}

struct SlabNode<T> {
    prev: u32,
    next: u32,
    /// None in a free node
    item: Option<T>,
}

impl<T> LinkedSlab<T> {
    const fn new() -> LinkedSlab<T> {
        LinkedSlab { nodes: Vec::new(), head: 0, tail: 0, free: 0, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    /// ngx_queue_insert_head: the key of the item's node.
    fn insert_head(&mut self, item: T) -> u32 {
        let node = SlabNode { prev: 0, next: self.head, item: Some(item) };

        let key = if self.free != 0 {
            let key = self.free;
            self.free = self.nodes[key as usize - 1].next;
            self.nodes[key as usize - 1] = node;
            key
        } else {
            self.nodes.push(node);
            self.nodes.len() as u32
        };

        if self.head != 0 {
            self.nodes[self.head as usize - 1].prev = key;
        } else {
            self.tail = key;
        }

        self.head = key;
        self.len += 1;

        key
    }

    /// ngx_queue_remove of the item of `key`, which is returned; None for a
    /// key of no item.
    fn remove(&mut self, key: u32) -> Option<T> {
        let i = (key as usize).checked_sub(1)?;
        let node = self.nodes.get_mut(i)?;
        let item = node.item.take()?;
        let (prev, next) = (node.prev, node.next);

        node.next = self.free;
        self.free = key;

        if prev != 0 {
            self.nodes[prev as usize - 1].next = next;
        } else {
            self.head = next;
        }

        if next != 0 {
            self.nodes[next as usize - 1].prev = prev;
        } else {
            self.tail = prev;
        }

        self.len -= 1;

        Some(item)
    }

    /// ngx_queue_last: the key and the item inserted first of those left.
    fn last(&self) -> Option<(u32, &T)> {
        if self.tail == 0 {
            return None;
        }

        self.nodes[self.tail as usize - 1].item.as_ref().map(|item| (self.tail, item))
    }
}

pub struct Connection {
    pub fd: Cell<RawFd>,
    afd: RefCell<Option<Rc<AsyncFd<fd::Fd>>>>,
    pub number: u64,
    pub log: Log,
    pub listening: Option<Rc<Listening>>,
    pub ty: i32,
    pub sockaddr: RefCell<SockAddr>,
    pub addr_text: RefCell<Vec<u8>>,
    /// Client's original (pre-realip) address, populated once by
    /// ngx_http_realip so $realip_remote_addr/$realip_remote_port survive
    /// after set_real_ip_from rewrites addr_text/sockaddr and across
    /// internal redirects (which clear per-request ctx).
    pub original_sockaddr: RefCell<Option<SockAddr>>,
    pub original_addr_text: RefCell<Option<Vec<u8>>>,
    pub local_sockaddr: RefCell<Option<SockAddr>>,
    pub proxy_protocol: RefCell<Option<Rc<dyn Any>>>,
    pub ssl: RefCell<Option<Rc<crate::ssl::SslConnection>>>,
    /// Preread buffer (bytes read before protocol handling took over).
    pub buffer: RefCell<Vec<u8>>,
    pub sent: Cell<u64>,
    pub requests: Cell<u64>,
    pub start_time: Cell<i64>,
    pub start_msec: Cell<u64>,
    pub timedout: Cell<bool>,
    pub error: Cell<bool>,
    pub destroyed: Cell<bool>,
    pub idle: Cell<bool>,
    pub close: Cell<bool>,
    pub shared: Cell<bool>,
    pub tcp_nodelay: Cell<TcpNodelay>,
    pub tcp_nopush: Cell<TcpNopush>,
    pub need_last_buf: Cell<bool>,
    pub need_flush_buf: Cell<bool>,
    pub sendfile: Cell<bool>,
    pub udp: Cell<bool>,
    /// Signalled to wake an idle (keepalive) connection so it closes itself.
    pub close_notify: tokio::sync::Notify,
    /// Protocol-specific context (http connection, stream session, mail session).
    pub data: RefCell<Option<Rc<dyn Any>>>,
    /// Set while the connection is in a reusable (idle) state.
    pub reusable: Cell<bool>,
    /// c->queue: the key of the connection in the reusable connections
    /// queue, 0 if not there
    queue: Cell<u32>,
    /// the connection's own Rc, weak (none for a per-stream copy of an
    /// HTTP/2 connection)
    this: Weak<Connection>,
    /// the connection holds one of connection_n (ngx_free_connection()
    /// not called yet)
    slot: Cell<bool>,
    /// c->read->handler for those who call it at once with c->close set
    /// (ngx_drain_connections, ngx_quic_close_streams): the connection is
    /// closed then. A connection run by a task has none: the task is
    /// woken to close it, as its socket can't be closed under the I/O the
    /// task waits for (the QUIC connections and streams have no socket of
    /// their own).
    pub close_handler: RefCell<Option<CloseHandler>>,
    pub pipeline: Cell<bool>,
    pub read_delayed: Cell<bool>,
    pub write_delayed: Cell<bool>,
    /// the timer of a delayed write event: the output waits until then
    /// (ngx_http_write_filter's limit_rate delay after a send)
    pub write_delay_until: Cell<Option<std::time::Instant>>,
    pub unexpected_eof: Cell<bool>,
    pub write_ready: Cell<bool>,
    pub read_eof: Cell<bool>,
    pub read_pending_eof: Cell<bool>,
    /// c->log_error: the level of ngx_connection_error() messages
    pub log_error: Cell<u32>,
    /// the cleanups of the connection's pool (ngx_pool_cleanup_add), run
    /// when the connection is closed, the last added first
    pub cleanups: RefCell<Vec<PoolCleanup>>,
    /// a connection passed to another listening socket (the stream pass
    /// module sets c->listening)
    pub passed_listening: RefCell<Option<Rc<Listening>>>,
    /// A per-stream copy of an HTTP/2 connection (C's fake connection, see
    /// Connection::new_fake). It never owns the socket or the SSL object,
    /// is not counted as a connection, and refuses socket I/O.
    pub fake: bool,
    /// c->udp of a "pseudo" connection sharing a UDP listening socket
    /// (event_udp.rs); kept after ngx_delete_udp_connection (then c.udp is
    /// false) so that the connection can still send.
    udp_conn: RefCell<Option<Rc<crate::event_udp::UdpConnection>>>,
    /// the QUIC connection of a QUIC connection (ngx_quic_get_connection:
    /// set while c->udp is its socket)
    pub quic_conn: RefCell<Option<Rc<crate::quic::QuicConnection>>>,
    /// c->udp of a QUIC connection: the socket the last datagram came to
    pub quic_sock: RefCell<Option<Rc<crate::quic::QuicSocket>>>,
    /// c->quic: the stream of a QUIC stream connection, whose I/O goes
    /// through the stream's buffers (quic/streams.rs)
    pub quic_stream: RefCell<Option<Rc<crate::quic::QuicStream>>>,
}

impl Connection {
    /// ngx_get_connection: allocate a connection object, enforcing worker_connections.
    pub fn get(fd: RawFd, log: &Log) -> Option<Rc<Connection>> {
        Connection::create(fd, log, None, libc::SOCK_STREAM, SockAddr::v4(std::net::Ipv4Addr::UNSPECIFIED, 0))
    }

    fn create(fd: RawFd, log: &Log, listening: Option<Rc<Listening>>, ty: i32, sockaddr: SockAddr) -> Option<Rc<Connection>> {
        Connection::create_log(fd, log, false, listening, ty, sockaddr)
    }

    /// ngx_get_connection for ngx_event_connect_peer: a connection of an
    /// outgoing socket, logging to pc->log (the log is shared, not copied:
    /// its messages carry the context of the connection it belongs to).
    pub fn peer(fd: RawFd, ty: i32, sockaddr: SockAddr, log: &Log) -> Option<Rc<Connection>> {
        Connection::create_log(fd, log, true, None, ty, sockaddr)
    }

    fn create_log(fd: RawFd, log: &Log, shared_log: bool, listening: Option<Rc<Listening>>, ty: i32, sockaddr: SockAddr) -> Option<Rc<Connection>> {
        drain_connections();

        if free_connections() == 0 {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "{} worker_connections are not enough", connection_n());
            return None;
        }
        let number = stats().connection_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let clog = if shared_log {
            log.clone()
        } else {
            let clog = log.fork();
            clog.set_connection(number);
            clog
        };
        let now = crate::times::cached();
        let c = Rc::new_cyclic(|this| Connection {
            fd: Cell::new(fd),
            afd: RefCell::new(None),
            number,
            log: clog,
            listening,
            ty,
            addr_text: RefCell::new(sockaddr.addr_text()),
            sockaddr: RefCell::new(sockaddr),
            original_sockaddr: RefCell::new(None),
            original_addr_text: RefCell::new(None),
            local_sockaddr: RefCell::new(None),
            proxy_protocol: RefCell::new(None),
            ssl: RefCell::new(None),
            buffer: RefCell::new(Vec::new()),
            sent: Cell::new(0),
            requests: Cell::new(0),
            start_time: Cell::new(now.sec),
            start_msec: Cell::new(now.sec as u64 * 1000 + now.msec),
            timedout: Cell::new(false),
            error: Cell::new(false),
            destroyed: Cell::new(false),
            idle: Cell::new(false),
            close: Cell::new(false),
            shared: Cell::new(false),
            tcp_nodelay: Cell::new(TcpNodelay::Unset),
            tcp_nopush: Cell::new(TcpNopush::Unset),
            need_last_buf: Cell::new(false),
            need_flush_buf: Cell::new(false),
            sendfile: Cell::new(false),
            udp: Cell::new(false),
            close_notify: tokio::sync::Notify::new(),
            data: RefCell::new(None),
            reusable: Cell::new(false),
            queue: Cell::new(0),
            this: this.clone(),
            slot: Cell::new(true),
            close_handler: RefCell::new(None),
            pipeline: Cell::new(false),
            read_delayed: Cell::new(false),
            write_delayed: Cell::new(false),
            write_delay_until: Cell::new(None),
            unexpected_eof: Cell::new(false),
            write_ready: Cell::new(false),
            read_eof: Cell::new(false),
            read_pending_eof: Cell::new(false),
            log_error: Cell::new(NGX_ERROR_ALERT),
            cleanups: RefCell::new(Vec::new()),
            passed_listening: RefCell::new(None),
            fake: false,
            udp_conn: RefCell::new(None),
            quic_conn: RefCell::new(None),
            quic_sock: RefCell::new(None),
            quic_stream: RefCell::new(None),
        });
        USED.with(|u| u.set(u.get() + 1));
        ACTIVE.with(|a| a.set(a.get() + 1));
        CONNECTIONS.with(|m| m.borrow_mut().insert(number, Rc::downgrade(&c)));
        Some(c)
    }

    /// Build a connection for an accepted socket.
    pub fn accepted(fd: RawFd, ls: &Rc<Listening>, sockaddr: SockAddr, log: &Log) -> Option<Rc<Connection>> {
        let unix = sockaddr.is_unix();
        let c = Connection::create(fd, log, Some(ls.clone()), ls.ty, sockaddr)?;
        // ngx_event_accept
        if unix {
            c.tcp_nopush.set(TcpNopush::Disabled);
            c.tcp_nodelay.set(TcpNodelay::Disabled);
        }
        if !ls.wildcard.get() {
            *c.local_sockaddr.borrow_mut() = Some(ls.sockaddr.clone());
        }
        Some(c)
    }

    /// The UDP state of a pseudo connection sharing a UDP listening socket
    /// (made by the listening's recvmsg task, event_udp.rs); None for other
    /// connections, including connected UDP sockets.
    pub fn udp_conn(&self) -> Option<Rc<crate::event_udp::UdpConnection>> {
        self.udp_conn.borrow().clone()
    }

    pub(crate) fn set_udp_conn(&self, udp: Rc<crate::event_udp::UdpConnection>) {
        *self.udp_conn.borrow_mut() = Some(udp);
    }

    /// A pseudo connection of a UDP listening socket (c->shared with
    /// c->type SOCK_DGRAM in C).
    pub fn is_udp_shared(&self) -> bool {
        self.udp_conn.borrow().is_some()
    }

    /// The per-stream "fake" connection of ngx_http_v2_create_stream: a copy
    /// of the HTTP/2 connection (addresses, SSL state, PROXY header, log
    /// chain and number) with its own request-level state (sent, error,
    /// timedout, requests, ...). Output goes through the HTTP/2 layer; socket
    /// I/O on it fails with EBADF, and dropping it never touches the real
    /// socket, the SSL object or the connection counters.
    pub fn new_fake(c: &Rc<Connection>) -> Rc<Connection> {
        let log = c.log.fork();
        log.set_connection(c.number);
        Rc::new(Connection {
            fd: Cell::new(-1),
            afd: RefCell::new(None),
            number: c.number,
            log,
            listening: c.listening.clone(),
            ty: c.ty,
            sockaddr: RefCell::new(c.sockaddr.borrow().clone()),
            addr_text: RefCell::new(c.addr_text.borrow().clone()),
            original_sockaddr: RefCell::new(c.original_sockaddr.borrow().clone()),
            original_addr_text: RefCell::new(c.original_addr_text.borrow().clone()),
            local_sockaddr: RefCell::new(c.local_sockaddr()),
            proxy_protocol: RefCell::new(c.proxy_protocol.borrow().clone()),
            ssl: RefCell::new(c.ssl.borrow().clone()),
            buffer: RefCell::new(Vec::new()),
            sent: Cell::new(0),
            requests: Cell::new(c.requests.get()),
            start_time: Cell::new(c.start_time.get()),
            start_msec: Cell::new(c.start_msec.get()),
            timedout: Cell::new(false),
            error: Cell::new(false),
            destroyed: Cell::new(false),
            idle: Cell::new(false),
            close: Cell::new(false),
            shared: Cell::new(true),
            tcp_nodelay: Cell::new(TcpNodelay::Disabled),
            tcp_nopush: Cell::new(c.tcp_nopush.get()),
            need_last_buf: Cell::new(false),
            need_flush_buf: Cell::new(false),
            sendfile: Cell::new(c.sendfile.get()),
            udp: Cell::new(false),
            close_notify: tokio::sync::Notify::new(),
            data: RefCell::new(c.data.borrow().clone()),
            reusable: Cell::new(false),
            queue: Cell::new(0),
            this: Weak::new(),
            slot: Cell::new(false),
            close_handler: RefCell::new(None),
            pipeline: Cell::new(false),
            read_delayed: Cell::new(false),
            write_delayed: Cell::new(false),
            write_delay_until: Cell::new(None),
            unexpected_eof: Cell::new(false),
            write_ready: Cell::new(false),
            read_eof: Cell::new(false),
            read_pending_eof: Cell::new(false),
            log_error: Cell::new(c.log_error.get()),
            cleanups: RefCell::new(Vec::new()),
            passed_listening: RefCell::new(None),
            fake: true,
            udp_conn: RefCell::new(None),
            quic_conn: RefCell::new(None),
            quic_sock: RefCell::new(None),
            quic_stream: RefCell::new(None),
        })
    }

    /// ngx_get_connection for a QUIC stream (ngx_quic_create_stream): the
    /// stream's connection has the addresses, the listening and the SSL
    /// object of the QUIC connection, a copy of its log, and a number of
    /// its own; it shares the QUIC connection's socket (sc->shared).
    pub fn quic_stream_connection(c: &Rc<Connection>) -> Option<Rc<Connection>> {
        let sc = Connection::create_log(c.fd.get(), &c.log, false, c.listening.clone(), libc::SOCK_STREAM, c.sockaddr.borrow().clone())?;

        // *log = *c->log
        sc.log.set_level(c.log.level());
        sc.log.set_action(c.log.action());
        sc.log.set_context(c.log.context());

        sc.shared.set(true);
        *sc.ssl.borrow_mut() = c.ssl.borrow().clone();
        *sc.addr_text.borrow_mut() = c.addr_text.borrow().clone();
        *sc.local_sockaddr.borrow_mut() = c.local_sockaddr.borrow().clone();
        sc.start_time.set(c.start_time.get());
        sc.start_msec.set(c.start_msec.get());
        sc.tcp_nodelay.set(TcpNodelay::Disabled);

        Some(sc)
    }

    /// A QUIC stream connection.
    pub fn is_quic_stream(&self) -> bool {
        self.quic_stream.borrow().is_some()
    }

    /// ngx_reusable_connection: the reusable connections queue and
    /// $connections_waiting, c->idle left as it is (a QUIC connection
    /// stays idle for ngx_close_idle_connections() with streams)
    pub fn reusable_connection(&self, reusable: bool) {
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, self.log, "reusable connection: {}", reusable as u32);

        if self.reusable.get() {
            self.unqueue();

            stats().waiting.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }

        self.reusable.set(reusable);

        if reusable {
            self.enqueue();

            stats().waiting.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// ngx_queue_insert_head(&cycle->reusable_connections_queue, &c->queue)
    fn enqueue(&self) {
        // not a per-stream copy of an HTTP/2 connection
        if self.fd.get() == -1 || self.fake {
            return;
        }

        let key = REUSABLE.with(|q| q.borrow_mut().insert_head(self.this.clone()));
        self.queue.set(key);
    }

    /// ngx_queue_remove(&c->queue) of a reusable connection
    fn unqueue(&self) {
        let key = self.queue.replace(0);

        if key != 0 {
            REUSABLE.with(|q| q.borrow_mut().remove(key));
        }
    }

    /// c->read->handler(c->read) with c->close set (ngx_drain_connections):
    /// the close handler of the connection, or else its task woken. The
    /// task closes the connection as soon as it runs (a reusable state
    /// waits for c->close), so the connection is taken off the reusable
    /// queue and gives its connection back at once, as closed.
    fn close_read_handler(self: &Rc<Self>) {
        let handler = self.close_handler.borrow().clone();

        if let Some(handler) = handler {
            handler(self);
            return;
        }

        self.unqueue();
        self.free_connection();

        if let Some(qs) = self.quic_stream.borrow().clone() {
            qs.notify.notify_waiters();
        }

        self.close_notify.notify_waiters();
        self.close_notify.notify_one();
    }

    /// ngx_free_connection
    fn free_connection(&self) {
        if self.slot.replace(false) {
            USED.with(|u| u.set(u.get() - 1));
        }
    }

    fn fake_io_error(&self) -> io::Result<()> {
        if self.fake {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        Ok(())
    }

    fn afd(&self) -> io::Result<Rc<AsyncFd<fd::Fd>>> {
        if let Some(a) = self.afd.borrow().as_ref() {
            return Ok(a.clone());
        }
        let fd = self.fd.get();
        if fd < 0 || self.is_udp_shared() {
            // the socket of a pseudo connection is the listening's, read
            // and written through its UDP state (event_udp.rs)
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        // the registration holds the connection's handle of its socket:
        // the I/O borrows it without a lookup in the descriptor table, and
        // the socket stays open until the registration is gone, so a late
        // deregistration cannot hit a number given to another descriptor
        let a = Rc::new(AsyncFd::with_interest(fd::get(fd)?, Interest::READABLE | Interest::WRITABLE)?);
        *self.afd.borrow_mut() = Some(a.clone());
        Ok(a)
    }

    /// Wait until the socket is readable.
    pub async fn readable(&self) -> io::Result<()> {
        if self.is_quic_stream() {
            return crate::quic::streams::readable(self).await;
        }
        if let Some(udp) = self.udp_conn() {
            return udp.readable(self).await;
        }
        let afd = self.afd()?;
        if self.ty == libc::SOCK_DGRAM {
            // a connected UDP socket: an ICMP error (ECONNREFUSED) comes as
            // EPOLLERR alone, which ngx_epoll_process_events handles as
            // EPOLLIN|EPOLLOUT; the next recv() returns the error
            let mut g = afd.ready(Interest::READABLE | Interest::ERROR).await?;
            if g.ready().is_error() {
                g.clear_ready_matching(tokio::io::Ready::ERROR);
            }
            return Ok(());
        }
        let _g = afd.readable().await?;
        Ok(())
    }

    /// c->read->ready = 0: a read found the socket drained, either a read
    /// shorter than asked (ngx_unix_recv with EPOLLRDHUP) or EAGAIN inside
    /// OpenSSL (SSL_ERROR_WANT_READ). The readiness kept since the last
    /// event is cleared, so the next wait blocks for a new event instead of
    /// trying a recv() that fails with EAGAIN. An operation that reports
    /// WouldBlock clears the readiness it was tried under; nothing is read,
    /// and tokio keeps the closed bits, so a pending EOF still wakes the
    /// reader.
    pub fn read_drained(&self) {
        if let Some(afd) = self.afd.borrow().as_ref() {
            let _ = afd.try_io(Interest::READABLE, |_| Err::<(), _>(io::ErrorKind::WouldBlock.into()));
        }
    }

    /// c->read->ready: a read event came since a read last found the socket
    /// drained (see read_drained()), tested without touching the socket. A
    /// pending EOF keeps it, as rev->pending_eof keeps rev->ready in
    /// ngx_unix_recv. False for a socket never waited for.
    pub fn read_ready(&self) -> bool {
        match self.afd.borrow().as_ref() {
            Some(afd) => afd.try_io(Interest::READABLE, |_| Ok(())).is_ok(),
            None => false,
        }
    }

    /// Wait for a read event (data or the end of the stream) and return
    /// what it reports, leaving the readiness to the connection's readers:
    /// a handler that only looks at the event, as
    /// ngx_http_upstream_check_broken_connection does at rev->pending_eof
    pub async fn read_event(&self) -> io::Result<tokio::io::Ready> {
        let afd = self.afd()?;
        let guard = afd.readable().await?;
        Ok(guard.ready())
    }

    /// Wait until the socket is writable.
    pub async fn writable(&self) -> io::Result<()> {
        if self.is_quic_stream() {
            return crate::quic::streams::writable(self).await;
        }
        if let Some(udp) = self.udp_conn() {
            return udp.writable().await;
        }
        let afd = self.afd()?;
        let _g = afd.writable().await?;
        Ok(())
    }

    /// One non-blocking send attempt (plain or TLS), without waiting:
    /// WouldBlock when the socket (or OpenSSL) can't take data now. A TLS
    /// retry must pass the same bytes again.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        if self.is_quic_stream() {
            return crate::quic::streams::try_send(self, &[buf]);
        }
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.try_send(self, &[buf]);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(ssl) = self.ssl.borrow().clone() {
            return ssl.try_send(self, buf);
        }
        let n = nix::sys::socket::send(self.fd.get(), buf, MsgFlags::MSG_NOSIGNAL | MsgFlags::MSG_DONTWAIT)?;
        self.sent.set(self.sent.get() + n as u64);
        Ok(n)
    }

    /// Drive a non-blocking operation that does its own socket I/O (an
    /// OpenSSL call) until it completes. The first attempt runs at once.
    /// An attempt that wants reading found the socket drained (EAGAIN), so
    /// the readiness kept since the last event is cleared, as C sets
    /// c->read->ready = 0, and the next attempt waits for a new event. On
    /// WantWrite it is retried after the socket becomes writable, while the
    /// readiness guard is held; if the retry still wants writing, the
    /// retained readiness is cleared and the next wait blocks for a new
    /// event, as epoll ET re-arming does after NGX_AGAIN in C. Waiting with
    /// readable() / writable() alone keeps the stale readiness and spins.
    pub async fn drive_io<T>(&self, mut op: impl FnMut() -> IoStep<T>) -> io::Result<T> {
        let mut step = op();
        loop {
            match step {
                IoStep::Done(v) => return Ok(v),
                IoStep::WantRead => {
                    // WantRead is EAGAIN on the socket: c->read->ready = 0,
                    // whether this was the first attempt or a retry
                    self.read_drained();
                    let afd = self.afd()?;
                    let _guard = afd.readable().await?;
                    step = op();
                }
                IoStep::WantWrite => {
                    let afd = self.afd()?;
                    let mut guard = afd.writable().await?;
                    step = op();
                    if matches!(step, IoStep::WantWrite) {
                        guard.clear_ready();
                    }
                }
            }
        }
    }

    /// drive_io() continuing an operation whose last attempt returned
    /// `step` (WantRead / WantWrite: NGX_AGAIN): waits for the readiness
    /// first, as a C event handler runs only on the event.  The attempt
    /// found the socket drained, so the retained readiness is cleared
    /// (c->read->ready = 0).
    pub async fn drive_io_from<T>(&self, mut step: IoStep<T>, mut op: impl FnMut() -> IoStep<T>) -> io::Result<T> {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());

        // (the read side is cleared in the loop)
        if let IoStep::WantWrite = step {
            if let std::task::Poll::Ready(Ok(mut guard)) = self.afd()?.poll_write_ready(&mut cx) {
                guard.clear_ready();
            }
        }

        loop {
            match step {
                IoStep::Done(v) => return Ok(v),
                IoStep::WantRead => {
                    self.read_drained();
                    let afd = self.afd()?;
                    let _guard = afd.readable().await?;
                    step = op();
                }
                IoStep::WantWrite => {
                    let afd = self.afd()?;
                    let mut guard = afd.writable().await?;
                    step = op();
                    if matches!(step, IoStep::WantWrite) {
                        guard.clear_ready();
                    }
                }
            }
        }
    }

    /// The poll form of drive_io(), for AsyncRead / AsyncWrite adapters of
    /// a connection: attempts until the operation completes or waits for
    /// the socket. An attempt that wants reading, or a write attempt made
    /// under the readiness that still wants it, found the socket drained,
    /// so the retained readiness is cleared and the task is woken by the
    /// next event (as drive_io does).
    pub fn poll_io<T>(&self, cx: &mut std::task::Context<'_>, mut op: impl FnMut() -> IoStep<T>) -> std::task::Poll<io::Result<T>> {
        use std::task::Poll;

        let mut step = op();

        loop {
            match step {
                IoStep::Done(v) => return Poll::Ready(Ok(v)),
                IoStep::WantRead => {
                    self.read_drained();
                    let afd = match self.afd() {
                        Ok(a) => a,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    let _guard = match afd.poll_read_ready(cx) {
                        Poll::Ready(Ok(g)) => g,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    step = op();
                }
                IoStep::WantWrite => {
                    let afd = match self.afd() {
                        Ok(a) => a,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    let mut guard = match afd.poll_write_ready(cx) {
                        Poll::Ready(Ok(g)) => g,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    step = op();
                    if matches!(step, IoStep::WantWrite) {
                        guard.clear_ready();
                    }
                }
            }
        }
    }

    /// poll_io() of a read that is attempted only while the socket is
    /// read-ready, as C reads only when c->read->ready (and
    /// ngx_http_upstream_send_request processes the response at once only
    /// then): after a read that found the socket drained, the next one
    /// waits for an event instead of trying a recv() that fails with EAGAIN.
    /// For TLS only after a read that ended with SSL_ERROR_WANT_READ: else
    /// OpenSSL may hold records the socket no longer shows.
    pub fn poll_read_io<T>(&self, cx: &mut std::task::Context<'_>, op: impl FnMut() -> IoStep<T>) -> std::task::Poll<io::Result<T>> {
        use std::task::Poll;

        let afd = match self.afd() {
            Ok(a) => a,
            Err(e) => return Poll::Ready(Err(e)),
        };

        match afd.poll_read_ready(cx) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        self.poll_io(cx, op)
    }

    /// One non-blocking recv attempt (plain or TLS), without waiting:
    /// WouldBlock when no data can be read now. OpenSSL may hold decrypted
    /// data the socket no longer shows, so TLS is always tried first. A
    /// drained socket clears the retained readiness, as in drive_io, so a
    /// later readable() waits for a new event.
    ///
    /// The readiness is checked and cleared with AsyncFd::try_io, not
    /// poll_read_ready(): that one counts against the task's coop budget
    /// and, once the budget is spent, reports even a ready socket as
    /// Pending (deferring a wakeup of the waker passed, a no-op one here).
    /// readable() is not budgeted, so a caller alternating readable() and
    /// try_recv() would then loop forever without yielding to the runtime.
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.is_quic_stream() {
            return crate::quic::streams::try_recv(self, buf);
        }
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.try_recv(self, buf).ok_or_else(|| io::ErrorKind::WouldBlock.into());
        }
        let afd = self.afd()?;
        if let Some(ssl) = self.ssl.borrow().clone() {
            // OpenSSL may hold records the socket no longer shows, unless
            // its last read found the socket drained (c->read->ready = 0)
            if !(ssl.state.recv_drained.get() && ssl.state.ngx.get() && !ssl.state.in_early.get()) {
                match ssl.try_recv(self, buf) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    r => return r,
                }
            }
            // retried while the socket is read-ready: nothing again clears
            // the readiness
            return afd.try_io(Interest::READABLE, |_| ssl.try_recv(self, buf));
        }
        let fd = self.fd.get();
        let mut recv = || nix::sys::socket::recv(fd, buf, MsgFlags::empty()).map_err(io::Error::from);
        if self.ty == libc::SOCK_DGRAM {
            // recv() whatever the read readiness: the error of a connected
            // UDP socket comes without it (see readable())
            let mut attempted = false;
            return match afd.try_io(Interest::READABLE, |_| {
                attempted = true;
                recv()
            }) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && !attempted => recv(),
                r => r,
            };
        }
        let n = afd.try_io(Interest::READABLE, |_| recv())?;
        if n == 0 {
            self.read_eof.set(true);
        } else if n < buf.len() {
            // ngx_unix_recv: a short read emptied the socket
            self.read_drained();
        }
        Ok(n)
    }

    /// SSL_want_write(): the last TLS operation could not write. A read
    /// that returned WouldBlock this way continues on the write event
    /// (ngx_ssl_handle_recv's SSL_ERROR_WANT_WRITE: ngx_ssl_write_handler).
    pub fn ssl_want_write(&self) -> bool {
        match self.ssl.borrow().as_ref() {
            Some(sc) => sc.want_write(),
            None => false,
        }
    }

    /// Non-blocking recv (plain sockets). Returns WouldBlock as an error.
    pub fn try_recv_raw(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.is_quic_stream() {
            return crate::quic::streams::try_recv(self, buf);
        }
        if let Some(udp) = self.udp_conn() {
            return udp.try_recv(self, buf).ok_or_else(|| io::ErrorKind::WouldBlock.into());
        }
        Ok(nix::sys::socket::recv(self.fd.get(), buf, MsgFlags::empty())?)
    }

    pub fn try_send_raw(&self, buf: &[u8]) -> io::Result<usize> {
        if self.is_quic_stream() {
            return crate::quic::streams::try_send(self, &[buf]);
        }
        if let Some(udp) = self.udp_conn() {
            return udp.try_send(self, &[buf]);
        }
        Ok(nix::sys::socket::send(self.fd.get(), buf, MsgFlags::MSG_NOSIGNAL)?)
    }

    /// ngx_unix_recv equivalent: read some bytes, awaiting readiness. Ok(0) is EOF.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.is_quic_stream() {
            return crate::quic::streams::recv(self, buf).await;
        }
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.recv(self, buf).await;
        }
        if let Some(ssl) = self.ssl.borrow().clone() {
            return ssl.recv(self, buf).await;
        }
        if self.ty == libc::SOCK_DGRAM {
            loop {
                match self.try_recv(buf) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.readable().await?,
                    r => return r,
                }
            }
        }
        let afd = self.afd()?;
        loop {
            let mut guard = afd.readable().await?;
            match guard.try_io(|inner| nix::sys::socket::recv(inner.get_ref().as_raw_fd(), buf, MsgFlags::empty()).map_err(io::Error::from)) {
                Ok(r) => {
                    let r = r?;
                    if r == 0 && self.ty != libc::SOCK_DGRAM {
                        self.read_eof.set(true);
                    } else if r < buf.len() {
                        // ngx_unix_recv: with EPOLLRDHUP a read shorter than
                        // asked emptied the socket (rev->ready = 0; the
                        // closed bits stay for a pending EOF)
                        guard.clear_ready();
                    }
                    return Ok(r);
                }
                Err(_) => continue,
            }
        }
    }

    /// The close handler of an idle connection (as
    /// ngx_http_upstream_keepalive_close_handler) on the read event of the
    /// connection's own registration: Ready when a peek at the socket finds
    /// data, the end of the stream or an error, Pending until the next read
    /// event. A peek that finds nothing clears the readiness (ev->ready = 0).
    pub fn poll_peek_close(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        use std::task::Poll;

        let afd = match self.afd() {
            Ok(a) => a,
            Err(_) => return Poll::Ready(()),
        };

        loop {
            let mut guard = match afd.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return Poll::Ready(()),
                Poll::Ready(Ok(g)) => g,
            };

            let peek = guard.try_io(|inner| {
                let mut b = [0u8; 1];
                nix::sys::socket::recv(inner.get_ref().as_raw_fd(), &mut b, MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT).map_err(io::Error::from)
            });

            match peek {
                // EAGAIN: the readiness was cleared, wait for the next event
                Err(_) => continue,
                Ok(_) => return Poll::Ready(()),
            }
        }
    }

    /// Peek without consuming.
    pub async fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.peek(self, buf).await;
        }
        let afd = self.afd()?;
        loop {
            let mut guard = afd.readable().await?;
            match guard.try_io(|inner| nix::sys::socket::recv(inner.get_ref().as_raw_fd(), buf, MsgFlags::MSG_PEEK).map_err(io::Error::from)) {
                Ok(r) => return r,
                Err(_) => continue,
            }
        }
    }

    /// recv(MSG_PEEK) of the stream preread phase (ngx_stream_preread_peek):
    /// waits until more than `have` bytes can be peeked, the peer closes its
    /// side, or an error. Returns the number of bytes peeked and whether the
    /// peer has closed its side (c->read->pending_eof, from EPOLLRDHUP).
    /// Readiness is cleared when there is nothing new, so the next wait
    /// blocks for a new event, as the edge-triggered epoll does in C.
    pub async fn peek_more(&self, buf: &mut [u8], have: usize) -> io::Result<(usize, bool)> {
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.peek_more(self, buf, have).await;
        }
        let afd = self.afd()?;
        loop {
            let mut guard = afd.readable().await?;
            let n = match nix::sys::socket::recv(self.fd.get(), buf, MsgFlags::MSG_PEEK) {
                Ok(n) => n,
                Err(Errno::EAGAIN) => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let eof = guard.ready().is_read_closed();
            if n == 0 || n > have || eof {
                return Ok((n, eof || n == 0));
            }
            guard.clear_ready();
        }
    }

    /// ngx_unix_send equivalent: write some bytes, awaiting writability.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if self.is_quic_stream() {
            return crate::quic::streams::send(self, &[buf]).await;
        }
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.send(self, &[buf]).await;
        }
        if let Some(ssl) = self.ssl.borrow().clone() {
            return ssl.send(self, buf).await;
        }
        let afd = self.afd()?;
        loop {
            let mut guard = afd.writable().await?;
            match guard.try_io(|inner| nix::sys::socket::send(inner.get_ref().as_raw_fd(), buf, MsgFlags::MSG_NOSIGNAL).map_err(io::Error::from)) {
                Ok(r) => {
                    let n = r?;
                    self.sent.set(self.sent.get() + n as u64);
                    return Ok(n);
                }
                Err(_) => continue,
            }
        }
    }

    /// writev over the given slices.
    pub async fn writev(&self, iov: &[&[u8]]) -> io::Result<usize> {
        if self.is_quic_stream() {
            return crate::quic::streams::send(self, iov).await;
        }
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.send(self, iov).await;
        }
        if let Some(ssl) = self.ssl.borrow().clone() {
            // SSL: write the first non-empty slice
            for s in iov {
                if !s.is_empty() {
                    return ssl.send(self, s).await;
                }
            }
            return Ok(0);
        }
        let afd = self.afd()?;
        let iovs: Vec<IoSlice<'_>> = iov.iter().filter(|s| !s.is_empty()).map(|s| IoSlice::new(s)).collect();
        if iovs.is_empty() {
            return Ok(0);
        }
        let iovs = &iovs[..iovs.len().min(1024)];
        loop {
            let mut guard = afd.writable().await?;
            match guard.try_io(|inner| nix::sys::uio::writev(inner.get_ref(), iovs).map_err(io::Error::from)) {
                Ok(r) => {
                    let n = r?;
                    self.sent.set(self.sent.get() + n as u64);
                    return Ok(n);
                }
                Err(_) => continue,
            }
        }
    }

    /// sendfile(2) from `file_fd` at `offset` for up to `count` bytes.
    pub async fn sendfile(&self, file_fd: RawFd, offset: i64, count: usize) -> io::Result<usize> {
        self.fake_io_error()?;
        let afd = self.afd()?;
        loop {
            let mut guard = afd.writable().await?;
            match guard.try_io(|inner| {
                let file = fd::get(file_fd)?;
                // the off_t of the kernel, as unsigned
                let mut off = offset as u64;
                rustix::fs::sendfile(inner.get_ref(), &file, Some(&mut off), count).map_err(io::Error::from)
            }) {
                Ok(r) => {
                    let n = r?;
                    self.sent.set(self.sent.get() + n as u64);
                    return Ok(n);
                }
                Err(_) => continue,
            }
        }
    }

    /// Write everything in `buf`: c->send (ngx_unix_send) until all is
    /// sent, as ngx_http_upstream_process_upgraded does. A send shorter
    /// than asked found the socket full and sets wev->ready = 0 there: the
    /// next one waits for a write event instead of failing with EAGAIN (an
    /// SSL write, ngx_ssl_write, keeps the readiness).
    pub async fn send_all(&self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.send(buf).await?;
            if n < buf.len() && self.plain_stream() {
                self.write_drained();
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    /// A TCP or unix stream socket read and written directly (not SSL, not
    /// a QUIC stream, not UDP).
    fn plain_stream(&self) -> bool {
        self.ty == libc::SOCK_STREAM && !self.fake && !self.is_quic_stream() && self.ssl.borrow().is_none() && !self.is_udp_shared()
    }

    /// c->write->ready = 0: a write found the socket full (a send shorter
    /// than asked, ngx_unix_send). The write readiness kept since the last
    /// event is cleared, so the next wait blocks for a new event instead of
    /// trying a write that fails with EAGAIN; tokio keeps the closed bits,
    /// so an error or a reset still wakes the writer. (ngx_linux_sendfile_chain
    /// clears it only on EAGAIN: it retries a short writev() or sendfile().)
    pub fn write_drained(&self) {
        if let Some(afd) = self.afd.borrow().as_ref() {
            let _ = afd.try_io(Interest::WRITABLE, |_| Err::<(), _>(io::ErrorKind::WouldBlock.into()));
        }
    }

    pub fn setsockopt_int(&self, level: i32, name: i32, value: i32) -> io::Result<()> {
        self.with_socket(|s| ngx_sys::os::setsockopt_int(s, level, name, value))
    }

    /// An operation on the connection's socket (an option set, a system
    /// call the connection has no method for), the error as io::Error. The
    /// socket is borrowed from the connection's own handle once it waited
    /// for an event, else from the descriptor table; EBADF for a closed
    /// connection.
    pub fn with_socket<T, E: Into<io::Error>>(&self, op: impl FnOnce(BorrowedFd<'_>) -> Result<T, E>) -> io::Result<T> {
        if let Some(afd) = self.afd.borrow().as_ref() {
            return op(afd.get_ref().as_fd()).map_err(Into::into);
        }
        let s = fd::get(self.fd.get())?;
        op(s.as_fd()).map_err(Into::into)
    }

    /// ngx_connection_error: log a socket error with the level of
    /// c->log_error; returns false for the ignored errors
    pub fn connection_error(&self, err: i32, text: &str) -> bool {
        let log_error = self.log_error.get();

        if err == libc::ECONNRESET && log_error == NGX_ERROR_IGNORE_ECONNRESET {
            return false;
        }

        if err == libc::EMSGSIZE && log_error == NGX_ERROR_IGNORE_EMSGSIZE {
            return false;
        }

        let level = if [0, libc::ECONNRESET, libc::EPIPE, libc::ENOTCONN, libc::ETIMEDOUT, libc::ECONNREFUSED, libc::ENETDOWN, libc::ENETUNREACH, libc::EHOSTDOWN, libc::EHOSTUNREACH].contains(&err) {
            match log_error {
                NGX_ERROR_IGNORE_EMSGSIZE | NGX_ERROR_IGNORE_EINVAL | NGX_ERROR_IGNORE_ECONNRESET | NGX_ERROR_INFO => NGX_LOG_INFO,
                _ => NGX_LOG_ERR,
            }
        } else {
            NGX_LOG_ALERT
        };

        ngx_log_error!(level, self.log, Some(err), "{}", text);

        true
    }

    /// ngx_tcp_nodelay
    pub fn set_tcp_nodelay(&self) -> bool {
        if self.tcp_nodelay.get() != TcpNodelay::Unset {
            return true;
        }
        if self.ty != libc::SOCK_STREAM || self.sockaddr.borrow().is_unix() {
            return true;
        }
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, self.log, "tcp_nodelay");
        if let Err(e) = self.with_socket(|s| sockopt::set_tcp_nodelay(s, true)) {
            ngx_log_error!(NGX_LOG_ALERT, self.log, e.raw_os_error(), "setsockopt(TCP_NODELAY) failed");
            return false;
        }
        self.tcp_nodelay.set(TcpNodelay::Set);
        true
    }

    /// TCP_CORK on
    pub fn tcp_push_on(&self) -> io::Result<()> {
        self.with_socket(|s| sockopt::set_tcp_cork(s, true))
    }

    /// TCP_CORK off
    pub fn tcp_push_off(&self) -> io::Result<()> {
        self.with_socket(|s| sockopt::set_tcp_cork(s, false))
    }

    /// SO_LINGER {1, 0}: reset on close (reset_timedout_connection).
    pub fn set_linger_reset(&self) {
        if let Err(e) = self.with_socket(|s| sockopt::set_socket_linger(s, Some(std::time::Duration::ZERO))) {
            ngx_log_error!(NGX_LOG_ALERT, self.log, e.raw_os_error(), "setsockopt(SO_LINGER) failed");
        }
    }

    /// shutdown(SHUT_WR)
    pub fn shutdown_write(&self) -> io::Result<()> {
        Ok(nix::sys::socket::shutdown(self.fd.get(), nix::sys::socket::Shutdown::Write)?)
    }

    /// Fetch and cache the local address (ngx_connection_local_sockaddr).
    pub fn local_sockaddr(&self) -> Option<SockAddr> {
        if let Some(a) = self.local_sockaddr.borrow().as_ref() {
            return Some(a.clone());
        }
        let ss: SockaddrStorage = match nix::sys::socket::getsockname(self.fd.get()) {
            Ok(ss) => ss,
            Err(e) => {
                ngx_log_error!(NGX_LOG_CRIT, self.log, Some(e as i32), "getsockname() failed");
                return None;
            }
        };
        let sa = SockAddr::from_nix(&ss)?;
        *self.local_sockaddr.borrow_mut() = Some(sa.clone());
        Some(sa)
    }

    /// Mark connection reusable/idle (ngx_reusable_connection).
    pub fn set_reusable(&self, reusable: bool) {
        // Mirror ngx_reusable_connection's queue and $connections_waiting
        // on a transition (the connection keeps its place in the queue
        // while it stays reusable). The idle flag doubles as our "am I on
        // the reusable queue" bit.
        let was = self.reusable.replace(reusable);
        self.idle.set(reusable);
        if was && !reusable {
            self.unqueue();
            stats().waiting.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        } else if !was && reusable {
            self.enqueue();
            stats().waiting.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// c->listening: the listening socket the connection was accepted on,
    /// or passed to
    pub fn listening(&self) -> Option<Rc<Listening>> {
        if let Some(ls) = self.passed_listening.borrow().as_ref() {
            return Some(ls.clone());
        }
        self.listening.clone()
    }

    /// ngx_pool_cleanup_add on the connection's pool
    pub fn add_cleanup(&self, cln: PoolCleanup) {
        self.cleanups.borrow_mut().push(cln);
    }

    /// The pool's cleanups, the last added first (ngx_destroy_pool).
    pub fn run_cleanups(&self) {
        loop {
            let cln = self.cleanups.borrow_mut().pop();

            match cln {
                Some(cln) => {
                    if let Some(h) = cln.handler {
                        h();
                    }
                }
                None => break,
            }
        }
    }

    /// ngx_close_connection
    pub fn close(&self) {
        if self.fd.get() == -1 {
            return;
        }
        // the pool cleanup of a pseudo connection: ngx_delete_udp_connection
        crate::event_udp::delete_udp_connection(self);
        // Use try_borrow_mut: on the h2 dispatch path a stale future
        // may still hold a shared borrow on self.ssl at close time.
        // In that case, defer the ssl drop to Connection Drop; there's
        // nothing meaningful for free_on_close to do here anyway.
        if let Ok(mut slot) = self.ssl.try_borrow_mut() {
            if let Some(ssl) = slot.take() {
                // QUIC streams inherit the SSL object of their connection
                if !self.is_quic_stream() {
                    ssl.free_on_close(self);
                }
            }
        }
        // deregister from reactor before closing
        self.afd.borrow_mut().take();
        self.reusable_connection(false);
        // the connection is free for others at once, even if the Rust
        // Rc<Connection> is dropped later
        self.free_connection();
        let fd = self.fd.replace(-1);
        if !self.shared.get() {
            if let Err(e) = os::close_fd(fd) {
                ngx_log_error!(NGX_LOG_ALERT, self.log, Some(e), "close() socket failed");
            }
        }
        // Mirror ngx_close_connection: decrement $connections_active as soon
        // as the socket is torn down, not when the Rust Rc<Connection> is
        // finally dropped (stray Rcs on request tasks would otherwise inflate
        // the gauge for the lifetime of the response). Only the accepted
        // connections are counted (ngx_stat_active in ngx_event_accept);
        // outgoing ones (ngx_event_connect_peer) are not.
        // (that of an HTTP/3 stream, by ngx_http_close_connection)
        if self.listening.is_some() && !self.is_quic_stream() {
            stats().active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.destroyed.set(true);
        // an outgoing connection shares the log of the connection it
        // belongs to (pc->log): its context stays
        if self.listening.is_some() {
            self.log.set_context(None);
        }
        // ngx_destroy_pool
        self.run_cleanups();
    }

    pub fn is_closed(&self) -> bool {
        self.fd.get() == -1
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if self.fake {
            return;
        }
        if self.fd.get() != -1 {
            self.close();
        }
        self.unqueue();
        self.free_connection();
        ACTIVE.with(|a| a.set(a.get().saturating_sub(1)));
        CONNECTIONS.with(|m| m.borrow_mut().remove(&self.number));
        wake_exiting_cycle();
    }
}

/// A connection or other work is gone: an exiting worker cycle is woken to
/// check whether it is the last (C checks ngx_exiting once per iteration of
/// the cycle). A worker not exiting waits for no connection to go: it is
/// not woken, which would make it re-arm its waits for nothing.
pub(crate) fn wake_exiting_cycle() {
    if crate::event::is_exiting() {
        CLOSE_NOTIFY.with(|n| n.notify_waiters());
    }
}

/// ngx_close_idle_connections: wake idle connections so they close.
pub fn close_idle_connections() {
    for_each_connection(|c| {
        if c.idle.get() {
            c.close.set(true);
            c.close_notify.notify_waiters();
            c.close_notify.notify_one();
        }
    });
}

/// Force-close all connections (worker_shutdown_timeout expiry):
/// ngx_shutdown_timer_handler sets both c->close and c->error.
pub fn close_all_connections() {
    for_each_connection(|c| {
        ngx_log_debug!(crate::log::NGX_LOG_DEBUG_CORE, c.log, "*{} shutdown timeout", c.number);
        c.close.set(true);
        c.error.set(true);
        c.close_notify.notify_waiters();
        c.close_notify.notify_one();
    });
}

// ---------------------------------------------------------------------------
// listening sockets

pub fn cmp_listening(a: &Listening, b: &Listening) -> bool {
    a.sockaddr.cmp(&b.sockaddr, true)
}

/// An operation on the open descriptor `fd`; Err(errno) if it fails (or
/// the descriptor is not open: EBADF, as the system call would fail).
fn with_fd<T, E: Into<io::Error>>(fd: RawFd, op: impl FnOnce(BorrowedFd<'_>) -> Result<T, E>) -> Result<T, i32> {
    let errno = |e: io::Error| e.raw_os_error().unwrap_or(libc::EIO);
    let s = fd::get(fd).map_err(errno)?;
    op(s.as_fd()).map_err(|e| errno(e.into()))
}

/// ngx_set_inherited_sockets: the listening entries pushed by
/// ngx_add_inherited_sockets (fd and inherited set) get the address and
/// options of their socket.
pub fn set_inherited_sockets(cycle: &mut Cycle) -> Result<(), ()> {
    for i in 0..cycle.listening.len() {
        let fd = cycle.listening[i].fd.get();

        // ngx_sockaddr_t
        let ss: SockaddrStorage = match nix::sys::socket::getsockname(fd) {
            Ok(ss) => ss,
            Err(e) => {
                ngx_log_error!(NGX_LOG_CRIT, cycle.log, Some(e as i32), "getsockname() of the inherited socket #{} failed", fd);
                cycle.listening[i].ignore.set(true);
                continue;
            }
        };

        // AF_INET6, AF_UNIX and AF_INET; None for the other families
        let sockaddr = SockAddr::from_nix(&ss);

        let sockaddr = match sockaddr {
            Some(sa) => sa,
            None => {
                ngx_log_error!(NGX_LOG_CRIT, cycle.log, Some(os::errno()), "the inherited socket #{} has an unsupported protocol family", fd);
                cycle.listening[i].ignore.set(true);
                continue;
            }
        };

        let mut ls = Listening::new(sockaddr, cycle.log.clone());
        ls.fd.set(fd);
        ls.inherited.set(cycle.listening[i].inherited.get());
        ls.backlog.set(crate::listening::NGX_LISTEN_BACKLOG);

        get_inherited_socket_options(&mut ls, &cycle.log);

        cycle.listening[i] = Rc::new(ls);
    }

    Ok(())
}

/// The socket options part of the ngx_set_inherited_sockets loop; a return
/// is a "continue" there.
fn get_inherited_socket_options(ls: &mut Listening, log: &Log) {
    let fd = ls.fd.get();

    match with_fd(fd, |s| sockopt::socket_type(s)) {
        Ok(ty) => ls.ty = ty.as_raw() as i32,
        Err(e) => {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "getsockopt(SO_TYPE) {} failed", B(&ls.addr_text));
            ls.ignore.set(true);
            return;
        }
    }

    match with_fd(fd, |s| sockopt::socket_recv_buffer_size(s)) {
        Ok(value) => ls.rcvbuf.set(value as i32),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "getsockopt(SO_RCVBUF) {} failed, ignored", B(&ls.addr_text));
            ls.rcvbuf.set(-1);
        }
    }

    match with_fd(fd, |s| sockopt::socket_send_buffer_size(s)) {
        Ok(value) => ls.sndbuf.set(value as i32),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "getsockopt(SO_SNDBUF) {} failed, ignored", B(&ls.addr_text));
            ls.sndbuf.set(-1);
        }
    }

    match with_fd(fd, |s| sockopt::socket_reuseport(s)) {
        Ok(reuseport) => ls.reuseport.set(reuseport),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "getsockopt(SO_REUSEPORT) {} failed, ignored", B(&ls.addr_text));
        }
    }

    if ls.ty != libc::SOCK_STREAM {
        return;
    }

    match with_fd(fd, |s| sockopt::socket_protocol(s)) {
        Ok(protocol) => {
            let value = protocol.map_or(0, |p| p.as_raw().get() as i32);
            ls.protocol.set(if value == libc::IPPROTO_TCP { 0 } else { value });
        }
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "getsockopt(SO_PROTOCOL) {} failed, ignored", B(&ls.addr_text));
            ls.protocol.set(0);
        }
    }

    match with_fd(fd, |s| ngx_sys::os::getsockopt_int(s, libc::IPPROTO_TCP, libc::TCP_FASTOPEN)) {
        Ok(value) => ls.fastopen.set(value),
        Err(err) => {
            if err != libc::EOPNOTSUPP && err != libc::ENOPROTOOPT && err != libc::EINVAL {
                ngx_log_error!(NGX_LOG_NOTICE, log, Some(err), "getsockopt(TCP_FASTOPEN) {} failed, ignored", B(&ls.addr_text));
            }
            ls.fastopen.set(-1);
        }
    }

    // the option is an int: the kernel returns all of its length (the olen
    // < sizeof(int) test of C)
    match with_fd(fd, |s| ngx_sys::os::getsockopt_int(s, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT)) {
        Ok(timeout) => {
            if timeout == 0 {
                return;
            }
        }
        Err(err) => {
            if err == libc::EOPNOTSUPP {
                return;
            }
            ngx_log_error!(NGX_LOG_NOTICE, log, Some(err), "getsockopt(TCP_DEFER_ACCEPT) for {} failed, ignored", B(&ls.addr_text));
            return;
        }
    }

    ls.deferred_accept.set(true);
}

/// ngx_open_listening_sockets
pub fn open_listening_sockets(cycle: &mut Cycle) -> Result<(), ()> {
    let log = cycle.log.clone();
    let test = is_test_config();
    let mut failed = false;
    for _tries in 0..5 {
        failed = false;
        for ls in cycle.listening.iter() {
            if ls.ignore.get() {
                continue;
            }
            if ls.add_reuseport.get() || ls.change_protocol.get() {
                if let Err(e) = with_fd(ls.fd.get(), |s| sockopt::set_socket_reuseport(s, true)) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(SO_REUSEPORT) {} failed, ignored", B(&ls.addr_text));
                }
                ls.add_reuseport.set(false);
            }
            if ls.fd.get() != -1 && !ls.change_protocol.get() {
                continue;
            }
            if ls.inherited.get() {
                continue;
            }
            let socket = rustix::net::socket_with(
                rustix::net::AddressFamily::from_raw(ls.sockaddr.family() as rustix::net::RawAddressFamily),
                rustix::net::SocketType::from_raw(ls.ty as rustix::net::RawSocketType),
                rustix::net::SocketFlags::CLOEXEC,
                std::num::NonZeroU32::new(ls.protocol.get() as u32).map(rustix::net::Protocol::from_raw),
            );
            // closed when dropped on an error, registered once listening
            let s = match socket {
                Ok(s) => s,
                Err(e) => {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "socket() {} failed", B(&ls.addr_text));
                    return Err(());
                }
            };
            if ls.ty != libc::SOCK_DGRAM || !test {
                if let Err(e) = sockopt::set_socket_reuseaddr(&s, true) {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "setsockopt(SO_REUSEADDR) {} failed", B(&ls.addr_text));
                    return Err(());
                }
            }
            if (ls.reuseport.get() || ls.change_protocol.get()) && !test {
                if let Err(e) = sockopt::set_socket_reuseport(&s, true) {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "setsockopt(SO_REUSEPORT) {} failed", B(&ls.addr_text));
                    return Err(());
                }
            }
            if ls.sockaddr.family() == libc::AF_INET6 {
                if let Err(e) = sockopt::set_ipv6_v6only(&s, ls.ipv6only.get()) {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "setsockopt(IPV6_V6ONLY) {} failed, ignored", B(&ls.addr_text));
                }
            }
            if let Err(e) = rustix::io::ioctl_fionbio(&s, true) {
                ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "ioctl(FIONBIO) {} failed", B(&ls.addr_text));
                return Err(());
            }
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "bind() {} #{} ", B(&ls.addr_text), s.as_raw_fd());
            if let Err(e) = nix::sys::socket::bind(s.as_raw_fd(), ls.sockaddr.to_nix().as_dyn()) {
                let err = e as i32;
                if err != libc::EADDRINUSE || !test {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(err), "bind() to {} failed", B(&ls.addr_text));
                }
                drop(s);
                if err != libc::EADDRINUSE {
                    return Err(());
                }
                if !test {
                    failed = true;
                }
                continue;
            }
            if let SockAddr::Unix(path) = &ls.sockaddr {
                if let Err(e) = rustix::fs::chmod(os::cstr(path).as_c_str(), rustix::fs::Mode::from_raw_mode(0o666)) {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(e.raw_os_error()), "chmod() \"{}\" failed", B(path));
                }
                if test {
                    if let Err(e) = os::unlink(path) {
                        ngx_log_error!(NGX_LOG_EMERG, log, Some(e), "unlink() {} failed", B(path));
                    }
                }
            }
            if ls.ty != libc::SOCK_STREAM {
                ls.fd.set(fd::register(s));
                ls.open.set(true);
                continue;
            }
            if let Err(e) = rustix::net::listen(&s, ls.backlog.get()) {
                let err = e.raw_os_error();
                if err != libc::EADDRINUSE || !test {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(err), "listen() to {}, backlog {} failed", B(&ls.addr_text), ls.backlog.get());
                }
                drop(s);
                if err != libc::EADDRINUSE {
                    return Err(());
                }
                if !test {
                    failed = true;
                }
                continue;
            }
            ls.listen.set(true);
            ls.fd.set(fd::register(s));
            ls.open.set(true);
        }
        if !failed {
            break;
        }
        ngx_log_error!(NGX_LOG_NOTICE, log, None, "try again to bind() after 500ms");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if failed {
        ngx_log_error!(NGX_LOG_EMERG, log, None, "still could not bind()");
        return Err(());
    }
    Ok(())
}

/// ngx_configure_listening_sockets
pub fn configure_listening_sockets(cycle: &mut Cycle) {
    let log = cycle.log.clone();
    for ls in cycle.listening.iter() {
        let fd = ls.fd.get();
        if fd == -1 {
            continue;
        }
        if ls.rcvbuf.get() != -1 {
            // the int as is (socket2 passes `size as c_int`)
            if let Err(e) = with_fd(fd, |s| socket2::SockRef::from(&s).set_recv_buffer_size(ls.rcvbuf.get() as usize)) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(SO_RCVBUF, {}) {} failed, ignored", ls.rcvbuf.get(), B(&ls.addr_text));
            }
        }
        if ls.sndbuf.get() != -1 {
            if let Err(e) = with_fd(fd, |s| socket2::SockRef::from(&s).set_send_buffer_size(ls.sndbuf.get() as usize)) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(SO_SNDBUF, {}) {} failed, ignored", ls.sndbuf.get(), B(&ls.addr_text));
            }
        }
        if ls.keepalive.get() != 0 {
            let value = if ls.keepalive.get() == 1 { 1 } else { 0 };
            if let Err(e) = with_fd(fd, |s| sockopt::set_socket_keepalive(s, value == 1)) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(SO_KEEPALIVE, {}) {} failed, ignored", value, B(&ls.addr_text));
            }
        }
        // the seconds and the count are positive: rustix passes them as is
        if ls.keepidle.get() != 0 {
            if let Err(e) = with_fd(fd, |s| sockopt::set_tcp_keepidle(s, std::time::Duration::from_secs(ls.keepidle.get() as u64))) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_KEEPIDLE, {}) {} failed, ignored", ls.keepidle.get(), B(&ls.addr_text));
            }
        }
        if ls.keepintvl.get() != 0 {
            if let Err(e) = with_fd(fd, |s| sockopt::set_tcp_keepintvl(s, std::time::Duration::from_secs(ls.keepintvl.get() as u64))) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_KEEPINTVL, {}) {} failed, ignored", ls.keepintvl.get(), B(&ls.addr_text));
            }
        }
        if ls.keepcnt.get() != 0 {
            if let Err(e) = with_fd(fd, |s| sockopt::set_tcp_keepcnt(s, ls.keepcnt.get() as u32)) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_KEEPCNT, {}) {} failed, ignored", ls.keepcnt.get(), B(&ls.addr_text));
            }
        }
        if ls.fastopen.get() != -1 {
            if let Err(e) = with_fd(fd, |s| ngx_sys::os::setsockopt_int(s, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, ls.fastopen.get())) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_FASTOPEN, {}) {} failed, ignored", ls.fastopen.get(), B(&ls.addr_text));
            }
        }
        if ls.listen.get() {
            if let Err(e) = with_fd(fd, |s| rustix::net::listen(s, ls.backlog.get())) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "listen() to {}, backlog {} failed, ignored", B(&ls.addr_text), ls.backlog.get());
            }
        }
        if ls.add_deferred.get() || ls.delete_deferred.get() {
            let value = if ls.add_deferred.get() { 1 } else { 0 };
            if let Err(e) = with_fd(fd, |s| ngx_sys::os::setsockopt_int(s, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, value)) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_DEFER_ACCEPT, {}) for {} failed, ignored", value, B(&ls.addr_text));
                continue;
            }
        }
        if ls.add_deferred.get() {
            ls.deferred_accept.set(true);
        }
        if ls.wildcard.get() && ls.ty == libc::SOCK_DGRAM {
            if ls.sockaddr.family() == libc::AF_INET {
                if let Err(e) = with_fd(fd, |s| nix::sys::socket::setsockopt(&s, nix::sys::socket::sockopt::Ipv4PacketInfo, &true)) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(IP_PKTINFO) for {} failed, ignored", B(&ls.addr_text));
                }
            } else if ls.sockaddr.family() == libc::AF_INET6 {
                if let Err(e) = with_fd(fd, |s| nix::sys::socket::setsockopt(&s, nix::sys::socket::sockopt::Ipv6RecvPacketInfo, &true)) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(IPV6_RECVPKTINFO) for {} failed, ignored", B(&ls.addr_text));
                }
            }
        }
        if ls.quic.get() {
            if ls.sockaddr.family() == libc::AF_INET {
                if let Err(e) = with_fd(fd, |s| sockopt::set_ip_mtu_discover(s, sockopt::Ipv4PathMtuDiscovery::DO)) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(IP_MTU_DISCOVER) for {} failed, ignored", B(&ls.addr_text));
                }
            } else if ls.sockaddr.family() == libc::AF_INET6 {
                if let Err(e) = with_fd(fd, |s| sockopt::set_ipv6_mtu_discover(s, sockopt::Ipv6PathMtuDiscovery::DO)) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(IPV6_MTU_DISCOVER) for {} failed, ignored", B(&ls.addr_text));
                }
            }
        }
    }
}

/// ngx_close_listening_sockets
pub fn close_listening_sockets(cycle: &Cycle) {
    crate::event::close_accept_mutex();

    for ls in cycle.listening.iter() {
        // the QUIC connections go on with their listening sockets
        if ls.quic.get() {
            continue;
        }
        let fd = ls.fd.get();
        if fd == -1 {
            continue;
        }
        crate::event::stop_accepting(ls);
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, cycle.log, "close listening {} #{} ", B(&ls.addr_text), fd);
        if let Err(e) = os::close_fd(fd) {
            ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(e), "close() socket {} failed", B(&ls.addr_text));
        }
        if let SockAddr::Unix(path) = &ls.sockaddr {
            let pt = process_type();
            if (pt == ProcessType::Master || pt == ProcessType::Single)
                && !globals(|g| g.new_binary != 0)
                && (!ls.inherited.get() || os::getppid() != crate::process::parent_pid())
            {
                if let Err(e) = os::unlink(path) {
                    ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(e), "unlink() {} failed", B(path));
                }
            }
        }
        ls.fd.set(-1);
    }
}

pub fn init_hooks() -> InitHooks {
    InitHooks {
        open_listening_sockets,
        configure_listening_sockets,
        init_zone_pool: crate::shm::init_zone_pool,
        cmp_sockaddr: cmp_listening,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::fd::OwnedFd;

    fn capture() -> (Log, Rc<RefCell<Vec<u8>>>) {
        let logged: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let lg = logged.clone();
        let chain = LogChain::new();
        chain.insert(LogEntry::new(NGX_LOG_INFO, LogWriter::Custom(Rc::new(move |_, line: &[u8]| lg.borrow_mut().extend_from_slice(line)))));
        (Log::new(chain), logged)
    }

    fn logged(l: &RefCell<Vec<u8>>) -> String {
        String::from_utf8_lossy(&l.borrow()).into_owned()
    }

    /// the listening entries of ngx_add_inherited_sockets
    fn inherited_cycle(log: &Log, fds: &[RawFd]) -> Cycle {
        let mut cycle = Cycle::init_cycle(log.clone(), Rc::new(Vec::new()));
        for &fd in fds {
            let mut ls = Listening::new(SockAddr::v4(Ipv4Addr::UNSPECIFIED, 0), log.clone());
            ls.addr_text = Vec::new();
            ls.fd.set(fd);
            ls.inherited.set(true);
            cycle.listening.push(Rc::new(ls));
        }
        cycle
    }

    /// A descriptor of the table, as ngx_add_inherited_sockets finds them.
    fn registered(s: impl Into<OwnedFd>) -> RawFd {
        fd::register(s.into())
    }

    fn tcp_socket(protocol: i32, reuseport: bool, defer: bool) -> Option<RawFd> {
        let s = rustix::net::socket_with(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            std::num::NonZeroU32::new(protocol as u32).map(rustix::net::Protocol::from_raw),
        )
        .ok()?;
        if reuseport {
            sockopt::set_socket_reuseport(&s, true).unwrap();
        }
        if defer {
            ngx_sys::os::setsockopt_int(s.as_fd(), libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, 1).unwrap();
        }
        nix::sys::socket::bind(s.as_raw_fd(), SockAddr::v4(Ipv4Addr::LOCALHOST, 0).to_nix().as_dyn()).unwrap();
        rustix::net::listen(&s, 16).unwrap();
        Some(registered(s))
    }

    fn local_port(fd: RawFd) -> u16 {
        let ss: SockaddrStorage = nix::sys::socket::getsockname(fd).unwrap();
        SockAddr::from_nix(&ss).unwrap().port()
    }

    #[test]
    fn inherited_unix_socket() {
        let path = std::env::temp_dir().join(format!("ngx-inherited-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let fd = registered(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let name = path.to_str().unwrap().as_bytes().to_vec();

        let (log, l) = capture();
        let mut cycle = inherited_cycle(&log, &[fd]);
        assert!(set_inherited_sockets(&mut cycle).is_ok());

        // no SO_REUSEPORT, SO_PROTOCOL, TCP_FASTOPEN or TCP_DEFER_ACCEPT messages
        assert_eq!(logged(&l), "");

        let ls = &cycle.listening[0];
        assert!(!ls.ignore.get());
        assert!(ls.inherited.get());
        assert_eq!(ls.fd.get(), fd);
        assert_eq!(ls.sockaddr, SockAddr::Unix(name.clone()));
        assert_eq!(ls.addr_text, [b"unix:".as_slice(), &name].concat());
        assert_eq!(ls.ty, libc::SOCK_STREAM);
        assert_eq!(ls.backlog.get(), crate::listening::NGX_LISTEN_BACKLOG);
        assert!(ls.rcvbuf.get() > 0 && ls.sndbuf.get() > 0);
        assert!(!ls.reuseport.get());
        assert_eq!(ls.protocol.get(), 0);
        assert_eq!(ls.fastopen.get(), -1);
        assert!(!ls.deferred_accept.get());

        // matches the "listen unix:" of a new configuration as is
        let nls = Listening::new(SockAddr::Unix(name), log.clone());
        assert!(cmp_listening(&nls, ls));
        assert_eq!(nls.protocol.get(), ls.protocol.get());
        assert!(!(nls.reuseport.get() && !ls.reuseport.get()));
        assert_eq!(nls.backlog.get(), ls.backlog.get());

        os::close(fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inherited_tcp_sockets() {
        let plain = tcp_socket(0, false, false).unwrap();
        let reuseport = tcp_socket(0, true, true).unwrap();

        let (log, l) = capture();
        let mut cycle = inherited_cycle(&log, &[plain, reuseport]);
        assert!(set_inherited_sockets(&mut cycle).is_ok());
        assert_eq!(logged(&l), "");

        let ls = &cycle.listening[0];
        assert!(!ls.ignore.get());
        assert_eq!(ls.sockaddr, SockAddr::v4(Ipv4Addr::LOCALHOST, local_port(plain)));
        assert_eq!(ls.addr_text, format!("127.0.0.1:{}", local_port(plain)).into_bytes());
        assert_eq!(ls.ty, libc::SOCK_STREAM);
        assert!(!ls.reuseport.get());
        // IPPROTO_TCP is 0
        assert_eq!(ls.protocol.get(), 0);
        assert!(ls.fastopen.get() >= 0);
        assert!(!ls.deferred_accept.get());

        let ls = &cycle.listening[1];
        assert!(!ls.ignore.get());
        assert!(ls.reuseport.get());
        assert_eq!(ls.protocol.get(), 0);
        assert!(ls.deferred_accept.get());

        os::close(plain);
        os::close(reuseport);
    }

    #[test]
    fn inherited_mptcp_socket() {
        // not every kernel has MPTCP
        let fd = match tcp_socket(libc::IPPROTO_MPTCP, false, false) {
            Some(fd) => fd,
            None => return,
        };

        let (log, _l) = capture();
        let mut cycle = inherited_cycle(&log, &[fd]);
        assert!(set_inherited_sockets(&mut cycle).is_ok());
        assert_eq!(cycle.listening[0].protocol.get(), libc::IPPROTO_MPTCP);

        os::close(fd);
    }

    #[test]
    fn inherited_udp_socket() {
        let fd = registered(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());

        let (log, l) = capture();
        let mut cycle = inherited_cycle(&log, &[fd]);
        assert!(set_inherited_sockets(&mut cycle).is_ok());
        assert_eq!(logged(&l), "");

        let ls = &cycle.listening[0];
        assert!(!ls.ignore.get());
        assert_eq!(ls.ty, libc::SOCK_DGRAM);
        assert_eq!(ls.addr_text, format!("127.0.0.1:{}", local_port(fd)).into_bytes());
        // not read for a datagram socket
        assert_eq!(ls.fastopen.get(), -1);
        assert!(!ls.deferred_accept.get());

        os::close(fd);
    }

    #[test]
    fn inherited_not_listening_sockets() {
        let (r, w) = nix::unistd::pipe().unwrap();
        let pipe = [registered(r), registered(w)];
        // NETLINK_ROUTE is protocol 0
        let netlink = registered(rustix::net::socket_with(rustix::net::AddressFamily::NETLINK, rustix::net::SocketType::RAW, rustix::net::SocketFlags::CLOEXEC, None).unwrap());
        let tcp = tcp_socket(0, false, false).unwrap();

        let (log, l) = capture();
        let mut cycle = inherited_cycle(&log, &[pipe[0], netlink, tcp]);
        assert!(set_inherited_sockets(&mut cycle).is_ok());

        let text = logged(&l);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{}", text);
        assert!(lines[0].contains("[crit] ") && lines[0].contains(&format!("getsockname() of the inherited socket #{} failed (88: Socket operation on non-socket)", pipe[0])), "{}", text);
        assert!(lines[1].contains("[crit] ") && lines[1].contains(&format!("the inherited socket #{} has an unsupported protocol family", netlink)), "{}", text);

        assert!(cycle.listening[0].ignore.get());
        assert!(cycle.listening[1].ignore.get());
        assert!(!cycle.listening[2].ignore.get());

        // the socket still gets closed with the old cycle
        assert_eq!(cycle.listening[1].fd.get(), netlink);
        assert!(cycle.listening[1].addr_text.is_empty());

        os::close(pipe[0]);
        os::close(pipe[1]);
        os::close(netlink);
        os::close(tcp);
    }

    fn run_local<F: std::future::Future<Output = ()>>(f: F) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        tokio::task::LocalSet::new().block_on(&rt, f);
    }

    /// A connection of the accepted end of a TCP pair (non-blocking, in
    /// the descriptor table), and the other end.
    fn tcp_pair(sndbuf: Option<usize>) -> (Rc<Connection>, std::net::TcpStream) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        if let Some(n) = sndbuf {
            socket2::SockRef::from(&s).set_send_buffer_size(n).unwrap();
        }
        let (log, _) = capture();
        let c = Connection::get(fd::register(OwnedFd::from(s)), &log).unwrap();
        (c, peer)
    }

    /// c->write->ready
    fn write_ready(c: &Connection) -> bool {
        c.afd.borrow().as_ref().is_some_and(|a| a.try_io(Interest::WRITABLE, |_| Ok(())).is_ok())
    }

    #[test]
    fn read_ready_is_the_kept_readiness() {
        run_local(async {
            let (c, mut peer) = tcp_pair(None);

            // never waited for
            assert!(!c.read_ready());

            c.writable().await.unwrap();
            assert!(!c.read_ready());

            std::io::Write::write_all(&mut peer, b"abc").unwrap();
            c.readable().await.unwrap();
            assert!(c.read_ready());
            assert!(c.read_ready(), "testing does not clear it");

            // a short read drained the socket
            let mut buf = [0u8; 16];
            assert_eq!(c.try_recv(&mut buf).unwrap(), 3);
            assert!(!c.read_ready());

            // the data of a new event, then the end of the stream: a
            // pending EOF stays ready after a read drained the data
            std::io::Write::write_all(&mut peer, b"de").unwrap();
            peer.shutdown(std::net::Shutdown::Write).unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            c.readable().await.unwrap();
            assert_eq!(c.try_recv(&mut buf).unwrap(), 2);
            assert!(c.read_ready());
            assert_eq!(c.try_recv(&mut buf).unwrap(), 0);

            c.close();
        });
    }

    #[test]
    fn write_drained_waits_for_a_new_event() {
        run_local(async {
            let (c, _peer) = tcp_pair(None);

            c.writable().await.unwrap();
            assert!(write_ready(&c));

            c.write_drained();
            assert!(!write_ready(&c));

            // the socket is still writable, but no new event comes
            assert!(tokio::time::timeout(std::time::Duration::from_millis(50), c.writable()).await.is_err());
            assert_eq!(c.try_send(b"x").unwrap(), 1, "the socket itself is untouched");

            c.close();
        });
    }

    #[test]
    fn linked_slab_queue() {
        let mut q: LinkedSlab<u32> = LinkedSlab::new();
        assert!(q.last().is_none());

        let a = q.insert_head(1);
        let b = q.insert_head(2);
        let c = q.insert_head(3);
        assert_eq!(q.len(), 3);
        assert_eq!(q.last(), Some((a, &1)));

        // the middle one
        assert_eq!(q.remove(b), Some(2));
        assert_eq!(q.remove(b), None, "removed already");
        assert_eq!(q.last(), Some((a, &1)));

        // the last one, then the first one
        assert_eq!(q.remove(a), Some(1));
        assert_eq!(q.last(), Some((c, &3)));
        let d = q.insert_head(4);
        assert!(d == a || d == b, "a free node is used again");
        assert_eq!(q.last(), Some((c, &3)));
        assert_eq!(q.remove(d), Some(4));
        assert_eq!(q.last(), Some((c, &3)));
        assert_eq!(q.remove(c), Some(3));
        assert!(q.last().is_none());
        assert_eq!(q.len(), 0);

        assert_eq!(q.remove(0), None);
        assert_eq!(q.remove(99), None);

        // in and out: the slab does not grow
        for i in 0..1000 {
            let k = q.insert_head(i);
            assert_eq!(q.remove(k), Some(i));
        }
        assert!(q.nodes.len() <= 3);
    }

    #[test]
    fn linked_slab_as_a_deque() {
        // against a model: insert at the front, remove anywhere, the last
        // one at the back
        let mut q: LinkedSlab<u64> = LinkedSlab::new();
        let mut model: std::collections::VecDeque<(u32, u64)> = std::collections::VecDeque::new();
        let mut seed: u64 = 0x2545f4914f6cdd1d;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for i in 0..20000u64 {
            let r = next();
            if model.is_empty() || r % 3 != 0 {
                let k = q.insert_head(i);
                model.push_front((k, i));
            } else {
                let at = (next() % model.len() as u64) as usize;
                let (k, v) = model.remove(at).unwrap();
                assert_eq!(q.remove(k), Some(v));
            }
            assert_eq!(q.len(), model.len());
            assert_eq!(q.last(), model.back().map(|(k, v)| (*k, v)));
        }

        assert!(q.nodes.len() <= model.len() + 64);
    }

    #[test]
    fn drain_takes_the_oldest_reusable() {
        run_local(async {
            let saved = connection_n();
            set_connection_n(connection_n() - free_connections() + 4);

            let pairs: Vec<_> = (0..4).map(|_| tcp_pair(None)).collect();
            assert_eq!(free_connections(), 0);

            for i in [2, 0, 3, 1] {
                pairs[i].0.set_reusable(true);
            }

            // no longer reusable, then again: the newest
            pairs[2].0.set_reusable(false);
            pairs[2].0.set_reusable(true);

            // oldest first: 0, 3, 1, 2; one of 4 is closed (n = 4 / 8,
            // at least 1)
            let (c4, _p4) = tcp_pair(None);
            let closed: Vec<bool> = pairs.iter().map(|(c, _)| c.close.get()).collect();
            assert_eq!(closed, [true, false, false, false]);
            assert_eq!(free_connections(), 0);

            let (c5, _p5) = tcp_pair(None);
            let closed: Vec<bool> = pairs.iter().map(|(c, _)| c.close.get()).collect();
            assert_eq!(closed, [true, false, false, true]);

            // the per-stream copies of HTTP/2 are never queued
            let fake = Connection::new_fake(&pairs[1].0);
            fake.set_reusable(true);
            assert_eq!(fake.queue.get(), 0);
            assert!(connection_rc(&fake).is_none());
            assert!(Rc::ptr_eq(&connection_rc(&pairs[1].0).unwrap(), &pairs[1].0));

            for (c, _) in &pairs {
                c.close();
            }
            c4.close();
            c5.close();
            assert_eq!(REUSABLE.with(|q| q.borrow().len()), 0);
            set_connection_n(saved);
        });
    }

    #[test]
    fn registration_holds_the_socket() {
        run_local(async {
            let (c, peer) = tcp_pair(None);
            let n = c.fd.get();

            c.writable().await.unwrap();
            assert!(c.with_socket(|s| rustix::net::sockopt::set_tcp_nodelay(s, true)).is_ok());
            assert!(c.set_tcp_nodelay());

            // a wait still holding the registration when the connection
            // is closed (a task not yet dropped)
            let late = c.afd().unwrap();
            c.close();
            assert!(!fd::contains(n));
            assert_eq!(c.with_socket(|_| Ok::<(), io::Error>(())).err().and_then(|e| e.raw_os_error()), Some(libc::EBADF));

            // the socket stays open until the registration goes
            peer.set_read_timeout(Some(std::time::Duration::from_millis(50))).unwrap();
            let mut b = [0u8; 1];
            assert!(std::io::Read::read(&mut &peer, &mut b).is_err(), "no end of stream yet");

            drop(late);
            peer.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            assert_eq!(std::io::Read::read(&mut &peer, &mut b).unwrap(), 0, "closed with the registration");
        });
    }

    #[test]
    fn send_all_through_short_sends() {
        run_local(async {
            let (c, peer) = tcp_pair(Some(4096));
            peer.set_nonblocking(true).unwrap();
            let mut peer = tokio::net::TcpStream::from_std(peer).unwrap();

            let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();

            let reader = async {
                let mut got = Vec::new();
                let mut buf = vec![0u8; 8192];
                while got.len() < data.len() {
                    let n = tokio::io::AsyncReadExt::read(&mut peer, &mut buf).await.unwrap();
                    assert!(n > 0);
                    got.extend_from_slice(&buf[..n]);
                    tokio::time::sleep(std::time::Duration::from_micros(200)).await;
                }
                got
            };

            let (sent, got) = tokio::join!(c.send_all(&data), reader);
            sent.unwrap();
            assert!(got == data);
            assert_eq!(c.sent.get(), data.len() as u64);

            c.close();
        });
    }
}
