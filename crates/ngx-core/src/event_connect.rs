//! ngx_event_connect.c: the socket of an outgoing connection to a peer
//! (ngx_event_connect_peer after pc->get chose the peer).

use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::rc::Rc;

use nix::fcntl::{FcntlArg, OFlag};

use crate::connection::Connection;
use crate::fd;
use crate::inet::SockAddr;
use crate::log::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error, os};

/// ngx_addr_t of proxy_bind and the like
#[derive(Clone, Debug)]
pub struct LocalAddr {
    pub sockaddr: SockAddr,
    pub name: Vec<u8>,
}

/// The parameters of ngx_peer_connection_t the socket is made with.
pub struct PeerSocket<'a> {
    pub sockaddr: &'a SockAddr,
    pub name: &'a [u8],
    /// SOCK_STREAM or SOCK_DGRAM (pc->type)
    pub ty: i32,
    pub rcvbuf: i32,
    pub sndbuf: i32,
    pub so_keepalive: bool,
    pub local: Option<&'a LocalAddr>,
    pub transparent: bool,
    pub log: &'a Log,
    pub log_error: u32,
}

/// The result of ngx_event_connect_peer.
pub enum PeerConnect {
    /// connected at once (NGX_OK)
    Ok(Rc<Connection>),
    /// connect() in progress (NGX_AGAIN): wait until writable, then test
    Again(Rc<Connection>),
    /// connect() failed, logged (NGX_DECLINED)
    Declined,
    /// NGX_ERROR
    Error,
}

/// An option of the socket `s`; Err(errno).
fn sockopt<E: Into<io::Error>>(s: i32, op: impl FnOnce(BorrowedFd<'_>) -> Result<(), E>) -> Result<(), i32> {
    let errno = |e: io::Error| e.raw_os_error().unwrap_or(libc::EIO);
    let f = fd::get(s).map_err(errno)?;
    op(f.as_fd()).map_err(|e| errno(e.into()))
}

/// ngx_event_connect_set_transparent
fn set_transparent(p: &PeerSocket, s: i32) -> Result<(), ()> {
    let local = p.local.expect("local");

    match local.sockaddr {
        SockAddr::V4(_) => {
            if let Err(e) = sockopt(s, |f| socket2::SockRef::from(&f).set_ip_transparent_v4(true)) {
                ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e), "setsockopt(IP_TRANSPARENT) failed");
                return Err(());
            }
        }
        SockAddr::V6(_) => {
            if let Err(e) = sockopt(s, |f| socket2::SockRef::from(&f).set_ip_transparent_v6(true)) {
                ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e), "setsockopt(IPV6_TRANSPARENT) failed");
                return Err(());
            }
        }
        SockAddr::Unix(_) => {}
    }

    Ok(())
}

/// ngx_event_connect_peer, from the socket on: the peer is chosen
/// (pc->sockaddr, pc->name).
pub fn event_connect_peer(p: &PeerSocket) -> PeerConnect {
    let ty = if p.ty != 0 { p.ty } else { libc::SOCK_STREAM };

    let family = p.sockaddr.family();

    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::from_raw(family as rustix::net::RawAddressFamily),
        rustix::net::SocketType::from_raw(ty as rustix::net::RawSocketType),
        rustix::net::SocketFlags::CLOEXEC,
        None,
    );

    let s = match &socket {
        Ok(s) => std::os::fd::AsRawFd::as_raw_fd(s),
        Err(_) => -1,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, p.log, "{} socket {}", if ty == libc::SOCK_STREAM { "stream" } else { "dgram" }, s);

    let s = match socket {
        Ok(s) => fd::register(s),
        Err(e) => {
            ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e.raw_os_error()), "socket() failed");
            return PeerConnect::Error;
        }
    };

    let c = match Connection::peer(s, ty, p.sockaddr.clone(), p.log) {
        Some(c) => c,
        None => {
            if let Err(e) = os::close_fd(s) {
                ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e), "close() socket failed");
            }
            return PeerConnect::Error;
        }
    };

    // the int as is (socket2 passes `size as c_int`)
    if p.rcvbuf != 0 {
        if let Err(e) = sockopt(s, |f| socket2::SockRef::from(&f).set_recv_buffer_size(p.rcvbuf as usize)) {
            ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e), "setsockopt(SO_RCVBUF, {}) failed, ignored", p.rcvbuf);
        }
    }

    if p.sndbuf != 0 {
        if let Err(e) = sockopt(s, |f| socket2::SockRef::from(&f).set_send_buffer_size(p.sndbuf as usize)) {
            ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e), "setsockopt(SO_SNDBUF, {}) failed, ignored", p.sndbuf);
        }
    }

    if p.so_keepalive {
        if let Err(e) = sockopt(s, |f| rustix::net::sockopt::set_socket_keepalive(f, true)) {
            ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e), "setsockopt(SO_KEEPALIVE) failed, ignored");
        }
    }

    let failed = |c: &Rc<Connection>| {
        c.close();
        PeerConnect::Error
    };

    let nonblocking = fd::get(s).map_err(|e| e.raw_os_error().unwrap_or(libc::EBADF)).and_then(|f| {
        nix::fcntl::fcntl(&f, FcntlArg::F_GETFL)
            .and_then(|flags| nix::fcntl::fcntl(&f, FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK)))
            .map_err(|e| e as i32)
    });

    if let Err(e) = nonblocking {
        ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e), "fcntl(O_NONBLOCK) failed");
        return failed(&c);
    }

    if let Some(local) = p.local {
        if p.transparent && set_transparent(p, s).is_err() {
            return failed(&c);
        }

        let port = local.sockaddr.port();

        if !p.sockaddr.is_unix() && port == 0 {
            // IP_BIND_ADDRESS_NO_PORT
            if let Err(err) = sockopt(s, |f| nix::sys::socket::setsockopt(&f, nix::sys::socket::sockopt::IpBindAddressNoPort, &true)) {
                if err != libc::EOPNOTSUPP && err != libc::ENOPROTOOPT {
                    ngx_log_error!(NGX_LOG_ALERT, p.log, Some(err), "setsockopt(IP_BIND_ADDRESS_NO_PORT) failed, ignored");
                }
            }
        }

        if p.ty == libc::SOCK_DGRAM && port != 0 {
            if let Err(e) = sockopt(s, |f| rustix::net::sockopt::set_socket_reuseaddr(f, true)) {
                ngx_log_error!(NGX_LOG_ALERT, p.log, Some(e), "setsockopt(SO_REUSEADDR) failed");
                return failed(&c);
            }
        }

        if let Err(e) = nix::sys::socket::bind(s, local.sockaddr.to_nix().as_dyn()) {
            ngx_log_error!(NGX_LOG_CRIT, p.log, Some(e as i32), "bind({}) failed", B(&local.name));
            return failed(&c);
        }
    }

    if ty == libc::SOCK_STREAM && p.sockaddr.is_unix() {
        c.tcp_nopush.set(crate::connection::TcpNopush::Disabled);
        c.tcp_nodelay.set(crate::connection::TcpNodelay::Disabled);
    }

    c.log_error.set(p.log_error);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, p.log, "connect to {}, fd:{} #{}", B(p.name), s, c.number);

    if let Err(e) = nix::sys::socket::connect(s, p.sockaddr.to_nix().as_dyn()) {
        let err = e as i32;

        if err != libc::EINPROGRESS {
            let level = if [libc::ECONNREFUSED, libc::EAGAIN, libc::ECONNRESET, libc::ENETDOWN, libc::ENETUNREACH, libc::EHOSTDOWN, libc::EHOSTUNREACH].contains(&err) {
                NGX_LOG_ERR
            } else {
                NGX_LOG_CRIT
            };

            ngx_log_error!(level, c.log, Some(err), "connect() to {} failed", B(p.name));

            c.close();

            return PeerConnect::Declined;
        }

        // NGX_EINPROGRESS

        return PeerConnect::Again(c);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, p.log, "connected");

    PeerConnect::Ok(c)
}

/// The pending error of a connect() in progress (SO_ERROR), 0 if connected;
/// the error of getsockopt() if it fails.
pub fn connect_error(c: &Connection) -> i32 {
    let s = match fd::get(c.fd.get()) {
        Ok(s) => s,
        Err(e) => return e.raw_os_error().unwrap_or(libc::EBADF),
    };

    match rustix::net::sockopt::socket_error(&s) {
        Ok(Ok(())) => 0,
        Ok(Err(err)) => err.raw_os_error(),
        Err(e) => e.raw_os_error(),
    }
}
