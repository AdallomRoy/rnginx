//! ngx_event_connect.c: the socket of an outgoing connection to a peer
//! (ngx_event_connect_peer after pc->get chose the peer).

use std::io;
use std::rc::Rc;

use crate::connection::Connection;
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

fn setsockopt_int(s: i32, level: i32, name: i32, value: i32) -> io::Result<()> {
    let r = unsafe { libc::setsockopt(s, level, name, &value as *const i32 as *const libc::c_void, std::mem::size_of::<i32>() as libc::socklen_t) };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// ngx_event_connect_set_transparent
fn set_transparent(p: &PeerSocket, s: i32) -> Result<(), ()> {
    let local = p.local.expect("local");

    match local.sockaddr {
        SockAddr::V4(_) => {
            if setsockopt_int(s, libc::IPPROTO_IP, libc::IP_TRANSPARENT, 1).is_err() {
                ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "setsockopt(IP_TRANSPARENT) failed");
                return Err(());
            }
        }
        SockAddr::V6(_) => {
            if setsockopt_int(s, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT, 1).is_err() {
                ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "setsockopt(IPV6_TRANSPARENT) failed");
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

    let s = unsafe { libc::socket(family, ty | libc::SOCK_CLOEXEC, 0) };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, p.log, "{} socket {}", if ty == libc::SOCK_STREAM { "stream" } else { "dgram" }, s);

    if s == -1 {
        ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "socket() failed");
        return PeerConnect::Error;
    }

    let c = match Connection::peer(s, ty, p.sockaddr.clone(), p.log) {
        Some(c) => c,
        None => {
            if unsafe { libc::close(s) } == -1 {
                ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "close() socket failed");
            }
            return PeerConnect::Error;
        }
    };

    if p.rcvbuf != 0 && setsockopt_int(s, libc::SOL_SOCKET, libc::SO_RCVBUF, p.rcvbuf).is_err() {
        ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "setsockopt(SO_RCVBUF, {}) failed, ignored", p.rcvbuf);
    }

    if p.sndbuf != 0 && setsockopt_int(s, libc::SOL_SOCKET, libc::SO_SNDBUF, p.sndbuf).is_err() {
        ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "setsockopt(SO_SNDBUF, {}) failed, ignored", p.sndbuf);
    }

    if p.so_keepalive && setsockopt_int(s, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1).is_err() {
        ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "setsockopt(SO_KEEPALIVE) failed, ignored");
    }

    let failed = |c: &Rc<Connection>| {
        c.close();
        PeerConnect::Error
    };

    let flags = unsafe { libc::fcntl(s, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(s, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "fcntl(O_NONBLOCK) failed");
        return failed(&c);
    }

    if let Some(local) = p.local {
        if p.transparent && set_transparent(p, s).is_err() {
            return failed(&c);
        }

        let port = local.sockaddr.port();

        if !p.sockaddr.is_unix() && port == 0 {
            // IP_BIND_ADDRESS_NO_PORT
            if let Err(e) = setsockopt_int(s, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT, 1) {
                let err = e.raw_os_error().unwrap_or(0);
                if err != libc::EOPNOTSUPP && err != libc::ENOPROTOOPT {
                    ngx_log_error!(NGX_LOG_ALERT, p.log, Some(err), "setsockopt(IP_BIND_ADDRESS_NO_PORT) failed, ignored");
                }
            }
        }

        if p.ty == libc::SOCK_DGRAM && port != 0 && setsockopt_int(s, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1).is_err() {
            ngx_log_error!(NGX_LOG_ALERT, p.log, Some(os::errno()), "setsockopt(SO_REUSEADDR) failed");
            return failed(&c);
        }

        let (ss, len) = local.sockaddr.to_libc();

        if unsafe { libc::bind(s, &ss as *const libc::sockaddr_storage as *const libc::sockaddr, len) } == -1 {
            ngx_log_error!(NGX_LOG_CRIT, p.log, Some(os::errno()), "bind({}) failed", B(&local.name));
            return failed(&c);
        }
    }

    if ty == libc::SOCK_STREAM && p.sockaddr.is_unix() {
        c.tcp_nopush.set(crate::connection::TcpNopush::Disabled);
        c.tcp_nodelay.set(crate::connection::TcpNodelay::Disabled);
    }

    c.log_error.set(p.log_error);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, p.log, "connect to {}, fd:{} #{}", B(p.name), s, c.number);

    let (ss, len) = p.sockaddr.to_libc();

    let rc = unsafe { libc::connect(s, &ss as *const libc::sockaddr_storage as *const libc::sockaddr, len) };

    if rc == -1 {
        let err = os::errno();

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

/// The pending error of a connect() in progress (SO_ERROR), 0 if connected.
pub fn connect_error(c: &Connection) -> i32 {
    let mut err: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    if unsafe { libc::getsockopt(c.fd.get(), libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut libc::c_int as *mut libc::c_void, &mut len) } == -1 {
        err = os::errno();
    }

    err
}
