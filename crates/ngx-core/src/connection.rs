//! Connections and listening sockets (ngx_connection.c) on top of tokio's AsyncFd.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
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
    static CONNECTION_N: Cell<usize> = const { Cell::new(512) };
    static CLOSE_NOTIFY: Rc<tokio::sync::Notify> = Rc::new(tokio::sync::Notify::new());
}

pub fn set_connection_n(n: usize) {
    CONNECTION_N.with(|c| c.set(n));
}

pub fn connection_n() -> usize {
    CONNECTION_N.with(|c| c.get())
}

pub fn active_connections() -> usize {
    ACTIVE.with(|a| a.get())
}

pub fn free_connections() -> usize {
    connection_n().saturating_sub(active_connections())
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
    pub pipeline: Cell<bool>,
    pub read_delayed: Cell<bool>,
    pub write_delayed: Cell<bool>,
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
        if active_connections() >= connection_n() {
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
            pipeline: Cell::new(false),
            read_delayed: Cell::new(false),
            write_delayed: Cell::new(false),
            unexpected_eof: Cell::new(false),
            write_ready: Cell::new(false),
            read_eof: Cell::new(false),
            read_pending_eof: Cell::new(false),
            log_error: Cell::new(NGX_ERROR_ALERT),
            cleanups: RefCell::new(Vec::new()),
            passed_listening: RefCell::new(None),
            fake: false,
            udp_conn: RefCell::new(None),
        });
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
            pipeline: Cell::new(false),
            read_delayed: Cell::new(false),
            write_delayed: Cell::new(false),
            unexpected_eof: Cell::new(false),
            write_ready: Cell::new(false),
            read_eof: Cell::new(false),
            read_pending_eof: Cell::new(false),
            log_error: Cell::new(c.log_error.get()),
            cleanups: RefCell::new(Vec::new()),
            passed_listening: RefCell::new(None),
            fake: true,
            udp_conn: RefCell::new(None),
        })
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

    /// Wait until the socket is writable.
    pub async fn writable(&self) -> io::Result<()> {
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
    /// OpenSSL call) until it completes. The first attempt runs at once; on
    /// WantRead/WantWrite it is retried after the socket becomes ready, while
    /// the readiness guard is held. If the retry still wants the same
    /// readiness, the socket was drained (EAGAIN), so the retained readiness
    /// is cleared and the next wait blocks for a new event, as epoll ET
    /// re-arming does after NGX_AGAIN in C. Waiting with readable() /
    /// writable() instead keeps the stale readiness and spins.
    pub async fn drive_io<T>(&self, mut op: impl FnMut() -> IoStep<T>) -> io::Result<T> {
        let mut step = op();
        loop {
            match step {
                IoStep::Done(v) => return Ok(v),
                IoStep::WantRead => {
                    let afd = self.afd()?;
                    let mut guard = afd.readable().await?;
                    step = op();
                    if matches!(step, IoStep::WantRead) {
                        guard.clear_ready();
                    }
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

        match step {
            IoStep::WantRead => {
                if let std::task::Poll::Ready(Ok(mut guard)) = self.afd()?.poll_read_ready(&mut cx) {
                    guard.clear_ready();
                }
            }
            IoStep::WantWrite => {
                if let std::task::Poll::Ready(Ok(mut guard)) = self.afd()?.poll_write_ready(&mut cx) {
                    guard.clear_ready();
                }
            }
            IoStep::Done(_) => {}
        }

        loop {
            match step {
                IoStep::Done(v) => return Ok(v),
                IoStep::WantRead => {
                    let afd = self.afd()?;
                    let mut guard = afd.readable().await?;
                    step = op();
                    if matches!(step, IoStep::WantRead) {
                        guard.clear_ready();
                    }
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
    /// the socket. An attempt made under the readiness that still wants it
    /// found the socket drained, so the retained readiness is cleared and
    /// the task is woken by the next event (as drive_io does).
    pub fn poll_io<T>(&self, cx: &mut std::task::Context<'_>, mut op: impl FnMut() -> IoStep<T>) -> std::task::Poll<io::Result<T>> {
        use std::task::Poll;

        let mut step = op();

        loop {
            match step {
                IoStep::Done(v) => return Poll::Ready(Ok(v)),
                IoStep::WantRead => {
                    let afd = match self.afd() {
                        Ok(a) => a,
                        Err(e) => return Poll::Ready(Err(e)),
                    };
                    let mut guard = match afd.poll_read_ready(cx) {
                        Poll::Ready(Ok(g)) => g,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    };
                    step = op();
                    if matches!(step, IoStep::WantRead) {
                        guard.clear_ready();
                    }
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
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.fake_io_error()?;
        if let Some(udp) = self.udp_conn() {
            return udp.try_recv(self, buf).ok_or_else(|| io::ErrorKind::WouldBlock.into());
        }
        let afd = self.afd()?;
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let Some(ssl) = self.ssl.borrow().clone() {
            match ssl.try_recv(self, buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                r => return r,
            }
            if let std::task::Poll::Ready(Ok(mut guard)) = afd.poll_read_ready(&mut cx) {
                match ssl.try_recv(self, buf) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                    r => return r,
                }
            }
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.ty == libc::SOCK_DGRAM {
            // recv() whatever the read readiness: the error of a connected
            // UDP socket comes without it (see readable())
            let mut guard = match afd.poll_read_ready(&mut cx) {
                std::task::Poll::Ready(Ok(g)) => Some(g),
                std::task::Poll::Ready(Err(e)) => return Err(e),
                std::task::Poll::Pending => None,
            };
            let n = unsafe { libc::recv(self.fd.get(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                if let Some(g) = guard.as_mut() {
                    g.clear_ready();
                }
            }
            return Err(e);
        }
        match afd.poll_read_ready(&mut cx) {
            std::task::Poll::Ready(Ok(mut guard)) => match guard.try_io(|inner| {
                let n = unsafe { libc::recv(inner.get_ref().0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => {
                    let n = r?;
                    if n == 0 && self.ty != libc::SOCK_DGRAM {
                        self.read_eof.set(true);
                    }
                    Ok(n)
                }
                Err(_) => Err(io::ErrorKind::WouldBlock.into()),
            },
            std::task::Poll::Ready(Err(e)) => Err(e),
            std::task::Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// Non-blocking recv (plain sockets). Returns WouldBlock as an error.
    pub fn try_recv_raw(&self, buf: &mut [u8]) -> io::Result<usize> {
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
        // Mirror ngx_reusable_connection's $connections_waiting side effect:
        // transitioning off ⇒ decrement, transitioning on ⇒ increment. The
        // idle flag doubles as our "am I on the reusable queue" bit.
        let was = self.reusable.replace(reusable);
        self.idle.set(reusable);
        if was && !reusable {
            stats().waiting.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        } else if !was && reusable {
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
                ssl.free_on_close(self);
            }
        }
        // deregister from reactor before closing
        self.afd.borrow_mut().take();
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
        if self.listening.is_some() {
            stats().active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        // If we were on the reusable queue (waiting for a request), pull
        // ourselves off it before dropping the connection so
        // $connections_waiting stays consistent.
        if self.reusable.replace(false) {
            stats().waiting.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
            let s = unsafe { libc::socket(ls.sockaddr.family(), ls.ty | libc::SOCK_CLOEXEC, 0) };
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
        let fd = ls.fd.get();
        if fd == -1 {
            continue;
        }
        crate::event::stop_accepting(ls);
        if unsafe { libc::close(fd) } == -1 {
            ngx_log_error!(NGX_LOG_EMERG, cycle.log, Some(os::errno()), "close() socket {} failed", B(&ls.addr_text));
        }
        if let SockAddr::Unix(path) = &ls.sockaddr {
            let pt = process_type();
            if (pt == ProcessType::Master || pt == ProcessType::Single) && !globals(|g| g.new_binary != 0) && !ls.inherited.get() {
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
