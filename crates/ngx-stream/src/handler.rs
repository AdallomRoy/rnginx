//! ngx_stream_handler.c: a new connection, the session, its end.

use std::rc::{Rc, Weak};
use std::time::Duration;

use ngx_core::connection::{Connection, NGX_ERROR_INFO};
use ngx_core::log::*;
use ngx_core::proxy_protocol::NGX_PROXY_PROTOCOL_MAX_HEADER;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::*;

/// The address configuration of a listening socket for the connection's
/// local address.
fn find_addr_conf(c: &Rc<Connection>) -> Option<Rc<AddrConf>> {
    let ls = c.listening.clone()?;
    let servers = ls.servers.borrow().clone()?;
    let port = servers.downcast::<StreamPort>().ok()?;

    if port.naddrs > 1 {
        // There are several addresses on this port and one of them
        // is the "*:port" wildcard so getsockname() is needed to determine
        // the server address.

        let sa = c.local_sockaddr()?;
        let ip = sa.ip_bytes();

        // the last address is "*"

        let mut i = 0;
        while i < port.naddrs - 1 {
            if port.addrs[i].0 == ip {
                break;
            }
            i += 1;
        }

        return Some(port.addrs[i].1.clone());
    }

    port.addrs.first().map(|(_, conf)| conf.clone())
}

/// ngx_stream_init_connection
pub fn init_connection(c: Rc<Connection>) {
    // find the server configuration for the address:port

    let addr_conf = match find_addr_conf(&c) {
        Some(a) => a,
        None => {
            close_connection(&c);
            return;
        }
    };

    let ctx = addr_conf.default_server.borrow().ctx.clone();

    let s = Session::new(&c, ctx.main.clone().expect("main conf"), ctx.srv.clone().expect("srv conf"), addr_conf.virtual_names.clone());

    s.ssl.set(addr_conf.ssl);

    let buffered = c.buffer.borrow().len();
    if buffered > 0 {
        s.received.set(s.received.get() + buffered as i64);
    }

    let data: Rc<dyn std::any::Any> = Rc::new(Rc::downgrade(&s));
    *c.data.borrow_mut() = Some(data);

    let cscf = s.cscf();

    let (error_log, proxy_protocol_timeout) = {
        let cscf = cscf.borrow();
        (cscf.error_log.clone(), *cscf.proxy_protocol_timeout)
    };

    if let Some(chain) = error_log {
        c.log.set_chain(chain);
    }

    // the accepted connection's log has no number yet (ngx_event_accept)
    c.log.set_connection(0);

    let text = c.sockaddr.borrow().to_text(true);
    let ls_text = c.listening.as_ref().map(|ls| ls.addr_text.clone()).unwrap_or_default();

    ngx_log_error!(NGX_LOG_INFO, c.log, None, "*{} {}client {} connected to {}", c.number, if c.ty == libc::SOCK_DGRAM { "udp " } else { "" }, B(&text), B(&ls_text));

    c.log.set_connection(c.number);
    c.log.set_context(Some(Rc::new(StreamLogCtx { session: Rc::downgrade(&s) })));
    c.log.set_action(Some("initializing session"));
    c.log_error.set(NGX_ERROR_INFO);

    let nvars = s.cmcf().borrow().variables.len();
    s.variables.borrow_mut().resize(nvars, crate::variables::VariableValue::default());

    let tp = ngx_core::times::cached();
    s.start_sec.set(tp.sec);
    s.start_msec.set(tp.msec);

    let proxy_protocol = addr_conf.proxy_protocol;

    ngx_core::event::spawn(async move {
        if proxy_protocol {
            c.log.set_action(Some("reading PROXY protocol"));

            if !proxy_protocol_handler(&s, proxy_protocol_timeout).await {
                return;
            }
        }

        session_handler(&s).await;
    });
}

/// ngx_stream_proxy_protocol_handler: false if the session is finalized
async fn proxy_protocol_handler(s: &S, timeout: u64) -> bool {
    let c = s.connection.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream PROXY protocol handler");

    let mut buf = vec![0u8; NGX_PROXY_PROTOCOL_MAX_HEADER];

    let res = tokio::select! {
        r = tokio::time::timeout(Duration::from_millis(timeout), c.peek(&mut buf)) => r,
        _ = c.close_notify.notified() => {
            finalize_session(s, NGX_STREAM_OK).await;
            return false;
        }
    };

    let n = match res {
        Err(_) => {
            ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
            finalize_session(s, NGX_STREAM_OK).await;
            return false;
        }
        Ok(Err(e)) => {
            c.connection_error(e.raw_os_error().unwrap_or(0), "recv() failed");
            finalize_session(s, NGX_STREAM_OK).await;
            return false;
        }
        Ok(Ok(n)) => n,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "recv(): {}", n);

    let size = match ngx_core::proxy_protocol::read(&c.log, &buf[..n]) {
        Ok((pp, size)) => {
            if let Some(pp) = pp {
                *c.proxy_protocol.borrow_mut() = Some(Rc::new(pp));
            }
            size
        }
        Err(()) => {
            finalize_session(s, NGX_STREAM_BAD_REQUEST).await;
            return false;
        }
    };

    // the header is in the socket buffer already

    let mut hdr = vec![0u8; size];

    match c.recv(&mut hdr).await {
        Ok(m) if m == size => {}
        _ => {
            finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return false;
        }
    }

    c.log.set_action(Some("initializing session"));

    true
}

/// ngx_stream_session_handler
pub async fn session_handler(s: &S) {
    run_phases(s).await;
}

/// ngx_stream_finalize_session
pub async fn finalize_session(s: &S, rc: i64) {
    if s.finalized.replace(true) {
        return;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "finalize stream session: {}", rc);

    s.status.set(rc);

    log_session(s).await;

    close_connection(&s.connection);
}

/// ngx_stream_log_session
async fn log_session(s: &S) {
    let handlers = s.cmcf().borrow().phases[NGX_STREAM_LOG_PHASE].clone();

    for h in handlers.iter() {
        h(s.clone()).await;
    }
}

/// ngx_stream_close_connection
pub fn close_connection(c: &Rc<Connection>) {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "close stream connection: {}", c.fd.get());

    c.data.borrow_mut().take();

    c.close();
}

/// ngx_stream_log_error: the context of the connection's log messages
pub struct StreamLogCtx {
    pub session: Weak<Session>,
}

impl LogContext for StreamLogCtx {
    fn write_context(&self, buf: &mut Vec<u8>) {
        let s = match self.session.upgrade() {
            Some(s) => s,
            None => return,
        };

        let c = &s.connection;

        if let Some(action) = c.log.action() {
            buf.extend_from_slice(b" while ");
            buf.extend_from_slice(action.as_bytes());
        }

        buf.extend_from_slice(b", ");

        if c.ty == libc::SOCK_DGRAM {
            buf.extend_from_slice(b"udp ");
        }

        buf.extend_from_slice(b"client: ");
        buf.extend_from_slice(&c.addr_text.borrow());
        buf.extend_from_slice(b", server: ");

        if let Some(ls) = c.listening.as_ref() {
            buf.extend_from_slice(&ls.addr_text);
        }

        let h = s.log_handler.borrow().clone();

        if let Some(h) = h {
            h(&s, buf);
        }
    }
}

/// The session of a connection (c->data).
pub fn session_of(c: &Connection) -> Option<S> {
    let data = c.data.borrow().clone()?;
    data.downcast::<Weak<Session>>().ok()?.upgrade()
}
