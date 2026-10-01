//! Connections and listening sockets (ngx_connection.c) on top of tokio's AsyncFd.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::{Rc, Weak};

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use crate::cycle::*;
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

static mut STATS_PTR: *const Stats = std::ptr::null();
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
    unsafe {
        if STATS_PTR.is_null() {
            &STATS_LOCAL
        } else {
            &*STATS_PTR
        }
    }
}

/// Allocate the shared stats block (called once in the master before forking).
pub fn init_shared_stats(log: &Log) {
    unsafe {
        if !STATS_PTR.is_null() {
            return;
        }
        let size = std::mem::size_of::<Stats>().max(4096);
        let p = libc::mmap(std::ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANON | libc::MAP_SHARED, -1, 0);
        if p == libc::MAP_FAILED {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "mmap(MAP_ANON|MAP_SHARED, {}) failed", size);
            return;
        }
        std::ptr::write_bytes(p as *mut u8, 0, size);
        STATS_PTR = p as *const Stats;
    }
}

thread_local! {
    static CONNECTIONS: RefCell<HashMap<u64, Weak<Connection>>> = RefCell::new(HashMap::new());
    static ACTIVE: Cell<usize> = const { Cell::new(0) };
    /// the connections taken of connection_n, from ngx_get_connection() to
    /// ngx_free_connection() (cycle->free_connection_n is what is left)
    static USED: Cell<usize> = const { Cell::new(0) };
    static CONNECTION_N: Cell<usize> = const { Cell::new(512) };
    /// cycle->reusable_connections_queue: the reusable connections by the
    /// time they became reusable, the first one first
    static REUSABLE: RefCell<BTreeMap<u64, Weak<Connection>>> = const { RefCell::new(BTreeMap::new()) };
    static REUSABLE_SEQ: Cell<u64> = const { Cell::new(0) };
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
        let last = REUSABLE.with(|q| q.borrow().first_key_value().map(|(k, w)| (*k, w.upgrade())));

        let rc = match last {
            Some((_, Some(rc))) => rc,
            Some((key, None)) => {
                REUSABLE.with(|q| q.borrow_mut().remove(&key));
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

/// Notified whenever a connection is closed (used by graceful shutdown).
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
/// find the connection by a pointer, ngx_ssl_get_connection()).
pub fn connection_rc(c: &Connection) -> Option<Rc<Connection>> {
    CONNECTIONS
        .with(|m| m.borrow().get(&c.number).and_then(|w| w.upgrade()))
        .filter(|rc| std::ptr::eq(Rc::as_ptr(rc), c))
}

pub struct Connection {
    pub fd: Cell<RawFd>,
    afd: RefCell<Option<Rc<AsyncFd<Fd>>>>,
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
    queue: Cell<u64>,
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
        let c = Rc::new(Connection {
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
        if self.fd.get() == -1 {
            return;
        }

        // not a per-stream copy of an HTTP/2 connection
        if let Some(rc) = connection_rc(self) {
            let key = REUSABLE_SEQ.with(|s| {
                s.set(s.get() + 1);
                s.get()
            });

            REUSABLE.with(|q| q.borrow_mut().insert(key, Rc::downgrade(&rc)));
            self.queue.set(key);
        }
    }

    /// ngx_queue_remove(&c->queue) of a reusable connection
    fn unqueue(&self) {
        let key = self.queue.replace(0);

        if key != 0 {
            REUSABLE.with(|q| q.borrow_mut().remove(&key));
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

    fn afd(&self) -> io::Result<Rc<AsyncFd<Fd>>> {
        if let Some(a) = self.afd.borrow().as_ref() {
            return Ok(a.clone());
        }
        let fd = self.fd.get();
        if fd < 0 || self.is_udp_shared() {
            // the socket of a pseudo connection is the listening's, read
            // and written through its UDP state (event_udp.rs)
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        let a = Rc::new(AsyncFd::with_interest(Fd(fd), Interest::READABLE | Interest::WRITABLE)?);
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
        let n = unsafe {
            libc::send(self.fd.get(), buf.as_ptr() as *const libc::c_void, buf.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT)
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        self.sent.set(self.sent.get() + n as u64);
        Ok(n as usize)
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
            match ssl.try_recv(self, buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                r => return r,
            }
            // retried while the socket is read-ready: nothing again clears
            // the readiness
            return afd.try_io(Interest::READABLE, |_| ssl.try_recv(self, buf));
        }
        let fd = self.fd.get();
        let mut recv = || {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        };
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
            Some(sc) => {
                let ssl = crate::event_openssl::ssl_ptr(sc);
                !ssl.is_null() && unsafe { crate::openssl_ffi::SSL_want(ssl) } == crate::openssl_ffi::SSL_WRITING
            }
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
        let n = unsafe { libc::recv(self.fd.get(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    pub fn try_send_raw(&self, buf: &[u8]) -> io::Result<usize> {
        if self.is_quic_stream() {
            return crate::quic::streams::try_send(self, &[buf]);
        }
        if let Some(udp) = self.udp_conn() {
            return udp.try_send(self, &[buf]);
        }
        let n = unsafe { libc::send(self.fd.get(), buf.as_ptr() as *const libc::c_void, buf.len(), libc::MSG_NOSIGNAL) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
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
            match guard.try_io(|inner| {
                let n = unsafe { libc::recv(inner.get_ref().0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
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

    /// Peek without consuming.
    pub async fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.peek(self, buf).await;
        }
        let afd = self.afd()?;
        loop {
            let mut guard = afd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe { libc::recv(inner.get_ref().0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_PEEK) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
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
            let n = unsafe { libc::recv(self.fd.get(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_PEEK) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(e);
            }
            let n = n as usize;
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
            match guard.try_io(|inner| {
                let n = unsafe { libc::send(inner.get_ref().0, buf.as_ptr() as *const libc::c_void, buf.len(), libc::MSG_NOSIGNAL) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
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
        let iovs: Vec<libc::iovec> = iov.iter().filter(|s| !s.is_empty()).map(|s| libc::iovec { iov_base: s.as_ptr() as *mut libc::c_void, iov_len: s.len() }).collect();
        if iovs.is_empty() {
            return Ok(0);
        }
        loop {
            let mut guard = afd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe { libc::writev(inner.get_ref().0, iovs.as_ptr(), iovs.len().min(1024) as i32) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
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

    /// sendfile(2) from `file_fd` at `offset` for up to `count` bytes.
    pub async fn sendfile(&self, file_fd: RawFd, offset: i64, count: usize) -> io::Result<usize> {
        self.fake_io_error()?;
        let afd = self.afd()?;
        loop {
            let mut guard = afd.writable().await?;
            match guard.try_io(|inner| {
                let mut off: libc::off_t = offset as libc::off_t;
                let n = unsafe { libc::sendfile(inner.get_ref().0, file_fd, &mut off, count) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
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

    /// Write everything in `buf`.
    pub async fn send_all(&self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.send(buf).await?;
            buf = &buf[n..];
        }
        Ok(())
    }

    pub fn setsockopt_int(&self, level: i32, name: i32, value: i32) -> io::Result<()> {
        let r = unsafe { libc::setsockopt(self.fd.get(), level, name, &value as *const i32 as *const libc::c_void, std::mem::size_of::<i32>() as libc::socklen_t) };
        if r == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
        if let Err(e) = self.setsockopt_int(libc::IPPROTO_TCP, libc::TCP_NODELAY, 1) {
            ngx_log_error!(NGX_LOG_ALERT, self.log, e.raw_os_error(), "setsockopt(TCP_NODELAY) failed");
            return false;
        }
        self.tcp_nodelay.set(TcpNodelay::Set);
        true
    }

    /// TCP_CORK on
    pub fn tcp_push_on(&self) -> io::Result<()> {
        self.setsockopt_int(libc::IPPROTO_TCP, libc::TCP_CORK, 1)
    }

    /// TCP_CORK off
    pub fn tcp_push_off(&self) -> io::Result<()> {
        self.setsockopt_int(libc::IPPROTO_TCP, libc::TCP_CORK, 0)
    }

    /// SO_LINGER {1, 0}: reset on close (reset_timedout_connection).
    pub fn set_linger_reset(&self) {
        let l = libc::linger { l_onoff: 1, l_linger: 0 };
        unsafe {
            if libc::setsockopt(self.fd.get(), libc::SOL_SOCKET, libc::SO_LINGER, &l as *const _ as *const libc::c_void, std::mem::size_of::<libc::linger>() as libc::socklen_t) == -1 {
                ngx_log_error!(NGX_LOG_ALERT, self.log, Some(os::errno()), "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /// shutdown(SHUT_WR)
    pub fn shutdown_write(&self) -> io::Result<()> {
        if unsafe { libc::shutdown(self.fd.get(), libc::SHUT_WR) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Fetch and cache the local address (ngx_connection_local_sockaddr).
    pub fn local_sockaddr(&self) -> Option<SockAddr> {
        if let Some(a) = self.local_sockaddr.borrow().as_ref() {
            return Some(a.clone());
        }
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if unsafe { libc::getsockname(self.fd.get(), &mut ss as *mut _ as *mut libc::sockaddr, &mut len) } == -1 {
            ngx_log_error!(NGX_LOG_CRIT, self.log, Some(os::errno()), "getsockname() failed");
            return None;
        }
        let sa = SockAddr::from_libc(&ss as *const _ as *const libc::sockaddr, len)?;
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
            if unsafe { libc::close(fd) } == -1 {
                ngx_log_error!(NGX_LOG_ALERT, self.log, Some(os::errno()), "close() socket failed");
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

fn setsockopt_int(fd: RawFd, level: i32, name: i32, value: i32) -> Result<(), i32> {
    let r = unsafe { libc::setsockopt(fd, level, name, &value as *const i32 as *const libc::c_void, std::mem::size_of::<i32>() as libc::socklen_t) };
    if r == -1 {
        return Err(os::errno());
    }
    Ok(())
}

/// getsockopt() of an int option; returns the option length
fn getsockopt_int(fd: RawFd, level: i32, name: i32, value: &mut i32) -> Result<libc::socklen_t, i32> {
    let mut olen = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: value points to an i32 of olen bytes
    let r = unsafe { libc::getsockopt(fd, level, name, value as *mut i32 as *mut libc::c_void, &mut olen) };
    if r == -1 {
        return Err(os::errno());
    }
    Ok(olen)
}

/// ngx_set_inherited_sockets: the listening entries pushed by
/// ngx_add_inherited_sockets (fd and inherited set) get the address and
/// options of their socket.
pub fn set_inherited_sockets(cycle: &mut Cycle) -> Result<(), ()> {
    for i in 0..cycle.listening.len() {
        let fd = cycle.listening[i].fd.get();

        // ngx_sockaddr_t
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut socklen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: ss is a sockaddr_storage of socklen bytes
        if unsafe { libc::getsockname(fd, &mut ss as *mut libc::sockaddr_storage as *mut libc::sockaddr, &mut socklen) } == -1 {
            ngx_log_error!(NGX_LOG_CRIT, cycle.log, Some(os::errno()), "getsockname() of the inherited socket #{} failed", fd);
            cycle.listening[i].ignore.set(true);
            continue;
        }

        if socklen > std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t {
            socklen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        }

        let sockaddr = match ss.ss_family as i32 {
            libc::AF_INET6 | libc::AF_UNIX | libc::AF_INET => SockAddr::from_libc(&ss as *const libc::sockaddr_storage as *const libc::sockaddr, socklen),
            _ => None,
        };

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
    let mut value = 0;

    if let Err(e) = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_TYPE, &mut ls.ty) {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "getsockopt(SO_TYPE) {} failed", B(&ls.addr_text));
        ls.ignore.set(true);
        return;
    }

    match getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &mut value) {
        Ok(_) => ls.rcvbuf.set(value),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "getsockopt(SO_RCVBUF) {} failed, ignored", B(&ls.addr_text));
            ls.rcvbuf.set(-1);
        }
    }

    match getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &mut value) {
        Ok(_) => ls.sndbuf.set(value),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "getsockopt(SO_SNDBUF) {} failed, ignored", B(&ls.addr_text));
            ls.sndbuf.set(-1);
        }
    }

    let mut reuseport = 0;

    match getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &mut reuseport) {
        Ok(_) => ls.reuseport.set(reuseport != 0),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "getsockopt(SO_REUSEPORT) {} failed, ignored", B(&ls.addr_text));
        }
    }

    if ls.ty != libc::SOCK_STREAM {
        return;
    }

    match getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_PROTOCOL, &mut value) {
        Ok(_) => ls.protocol.set(if value == libc::IPPROTO_TCP { 0 } else { value }),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "getsockopt(SO_PROTOCOL) {} failed, ignored", B(&ls.addr_text));
            ls.protocol.set(0);
        }
    }

    match getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, &mut value) {
        Ok(_) => ls.fastopen.set(value),
        Err(err) => {
            if err != libc::EOPNOTSUPP && err != libc::ENOPROTOOPT && err != libc::EINVAL {
                ngx_log_error!(NGX_LOG_NOTICE, log, Some(err), "getsockopt(TCP_FASTOPEN) {} failed, ignored", B(&ls.addr_text));
            }
            ls.fastopen.set(-1);
        }
    }

    let mut timeout = 0;

    match getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, &mut timeout) {
        Ok(olen) => {
            if (olen as usize) < std::mem::size_of::<i32>() || timeout == 0 {
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
                if let Err(e) = setsockopt_int(ls.fd.get(), libc::SOL_SOCKET, libc::SO_REUSEPORT, 1) {
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
            let s = unsafe { libc::socket(ls.sockaddr.family(), ls.ty | libc::SOCK_CLOEXEC, ls.protocol.get()) };
            if s == -1 {
                ngx_log_error!(NGX_LOG_EMERG, log, Some(os::errno()), "socket() {} failed", B(&ls.addr_text));
                return Err(());
            }
            if ls.ty != libc::SOCK_DGRAM || !test {
                if let Err(e) = setsockopt_int(s, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1) {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(e), "setsockopt(SO_REUSEADDR) {} failed", B(&ls.addr_text));
                    os::close(s);
                    return Err(());
                }
            }
            if (ls.reuseport.get() || ls.change_protocol.get()) && !test {
                if let Err(e) = setsockopt_int(s, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1) {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(e), "setsockopt(SO_REUSEPORT) {} failed", B(&ls.addr_text));
                    os::close(s);
                    return Err(());
                }
            }
            if ls.sockaddr.family() == libc::AF_INET6 {
                if let Err(e) = setsockopt_int(s, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, ls.ipv6only.get() as i32) {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(e), "setsockopt(IPV6_V6ONLY) {} failed, ignored", B(&ls.addr_text));
                }
            }
            if let Err(e) = os::set_nonblocking(s) {
                ngx_log_error!(NGX_LOG_EMERG, log, Some(e), "ioctl(FIONBIO) {} failed", B(&ls.addr_text));
                os::close(s);
                return Err(());
            }
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "bind() {} #{} ", B(&ls.addr_text), s);
            let (ss, slen) = ls.sockaddr.to_libc();
            if unsafe { libc::bind(s, &ss as *const _ as *const libc::sockaddr, slen) } == -1 {
                let err = os::errno();
                if err != libc::EADDRINUSE || !test {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(err), "bind() to {} failed", B(&ls.addr_text));
                }
                os::close(s);
                if err != libc::EADDRINUSE {
                    return Err(());
                }
                if !test {
                    failed = true;
                }
                continue;
            }
            if let SockAddr::Unix(path) = &ls.sockaddr {
                let c = os::cstr(path);
                if unsafe { libc::chmod(c.as_ptr(), 0o666) } == -1 {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(os::errno()), "chmod() \"{}\" failed", B(path));
                }
                if test {
                    if let Err(e) = os::unlink(path) {
                        ngx_log_error!(NGX_LOG_EMERG, log, Some(e), "unlink() {} failed", B(path));
                    }
                }
            }
            if ls.ty != libc::SOCK_STREAM {
                ls.fd.set(s);
                ls.open.set(true);
                continue;
            }
            if unsafe { libc::listen(s, ls.backlog.get()) } == -1 {
                let err = os::errno();
                if err != libc::EADDRINUSE || !test {
                    ngx_log_error!(NGX_LOG_EMERG, log, Some(err), "listen() to {}, backlog {} failed", B(&ls.addr_text), ls.backlog.get());
                }
                os::close(s);
                if err != libc::EADDRINUSE {
                    return Err(());
                }
                if !test {
                    failed = true;
                }
                continue;
            }
            ls.listen.set(true);
            ls.fd.set(s);
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
            if let Err(e) = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, ls.rcvbuf.get()) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(SO_RCVBUF, {}) {} failed, ignored", ls.rcvbuf.get(), B(&ls.addr_text));
            }
        }
        if ls.sndbuf.get() != -1 {
            if let Err(e) = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, ls.sndbuf.get()) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(SO_SNDBUF, {}) {} failed, ignored", ls.sndbuf.get(), B(&ls.addr_text));
            }
        }
        if ls.keepalive.get() != 0 {
            let value = if ls.keepalive.get() == 1 { 1 } else { 0 };
            if let Err(e) = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, value) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(SO_KEEPALIVE, {}) {} failed, ignored", value, B(&ls.addr_text));
            }
        }
        if ls.keepidle.get() != 0 {
            if let Err(e) = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, ls.keepidle.get()) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_KEEPIDLE, {}) {} failed, ignored", ls.keepidle.get(), B(&ls.addr_text));
            }
        }
        if ls.keepintvl.get() != 0 {
            if let Err(e) = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, ls.keepintvl.get()) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_KEEPINTVL, {}) {} failed, ignored", ls.keepintvl.get(), B(&ls.addr_text));
            }
        }
        if ls.keepcnt.get() != 0 {
            if let Err(e) = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, ls.keepcnt.get()) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_KEEPCNT, {}) {} failed, ignored", ls.keepcnt.get(), B(&ls.addr_text));
            }
        }
        if ls.fastopen.get() != -1 {
            if let Err(e) = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, ls.fastopen.get()) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_FASTOPEN, {}) {} failed, ignored", ls.fastopen.get(), B(&ls.addr_text));
            }
        }
        if ls.listen.get() && unsafe { libc::listen(fd, ls.backlog.get()) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "listen() to {}, backlog {} failed, ignored", B(&ls.addr_text), ls.backlog.get());
        }
        if ls.add_deferred.get() || ls.delete_deferred.get() {
            let value = if ls.add_deferred.get() { 1 } else { 0 };
            if let Err(e) = setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, value) {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(TCP_DEFER_ACCEPT, {}) for {} failed, ignored", value, B(&ls.addr_text));
                continue;
            }
        }
        if ls.add_deferred.get() {
            ls.deferred_accept.set(true);
        }
        if ls.wildcard.get() && ls.ty == libc::SOCK_DGRAM {
            if ls.sockaddr.family() == libc::AF_INET {
                if let Err(e) = setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(IP_PKTINFO) for {} failed, ignored", B(&ls.addr_text));
                }
            } else if ls.sockaddr.family() == libc::AF_INET6 {
                if let Err(e) = setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(IPV6_RECVPKTINFO) for {} failed, ignored", B(&ls.addr_text));
                }
            }
        }
        if ls.quic.get() {
            if ls.sockaddr.family() == libc::AF_INET {
                if let Err(e) = setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DO) {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(e), "setsockopt(IP_MTU_DISCOVER) for {} failed, ignored", B(&ls.addr_text));
                }
            } else if ls.sockaddr.family() == libc::AF_INET6 {
                if let Err(e) = setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, libc::IPV6_PMTUDISC_DO) {
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
        if unsafe { libc::close(fd) } == -1 {
            ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(os::errno()), "close() socket {} failed", B(&ls.addr_text));
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
        init_zone_pool: crate::slab::init_zone_pool,
        cmp_sockaddr: cmp_listening,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::os::unix::io::IntoRawFd;

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

    fn tcp_socket(protocol: i32, reuseport: bool, defer: bool) -> Option<RawFd> {
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, protocol) };
        if s == -1 {
            return None;
        }
        if reuseport {
            setsockopt_int(s, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1).unwrap();
        }
        if defer {
            setsockopt_int(s, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, 1).unwrap();
        }
        let (ss, len) = SockAddr::v4(Ipv4Addr::LOCALHOST, 0).to_libc();
        assert_eq!(unsafe { libc::bind(s, &ss as *const _ as *const libc::sockaddr, len) }, 0);
        assert_eq!(unsafe { libc::listen(s, 16) }, 0);
        Some(s)
    }

    fn local_port(fd: RawFd) -> u16 {
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        assert_eq!(unsafe { libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) }, 0);
        SockAddr::from_libc(&ss as *const _ as *const libc::sockaddr, len).unwrap().port()
    }

    #[test]
    fn inherited_unix_socket() {
        let path = std::env::temp_dir().join(format!("ngx-inherited-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let fd = std::os::unix::net::UnixListener::bind(&path).unwrap().into_raw_fd();
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
        let fd = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into_raw_fd();

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
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let netlink = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        assert!(netlink != -1);
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
}
