//! TLS to upstreams: the SSL parts of ngx_http_upstream.c
//! (ngx_http_upstream_ssl_init_connection,
//! ngx_http_upstream_ssl_handshake_handler, ngx_http_upstream_ssl_handshake,
//! ngx_http_upstream_ssl_save_session, ngx_http_upstream_ssl_name,
//! ngx_http_upstream_ssl_certificate, ngx_http_upstream_merge_ssl_passwords)
//! on the port of ngx_event_openssl.c.
//!
//! An https upstream connection is a connection of ngx_event_connect_peer
//! (u->peer.connection) with c->ssl of ngx_ssl_create_connection(); the
//! proxy reads and writes it through AsyncRead / AsyncWrite
//! (UpstreamSock::Conn), which run ngx_ssl_recv() / ngx_ssl_write().

use std::cell::RefCell;
use std::io;
use std::os::raw::c_void;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use foreign_types::ForeignType;
use tokio::io::ReadBuf;
use tokio::time::Instant;

use ngx_core::conf::*;
use ngx_core::connection::{Connection, IoStep};
use ngx_core::event_openssl::*;
use ngx_core::event_openssl_cache::SslCache;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::ssl::SslConnection;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::proxy::ConnectError;
use crate::request::R;
use crate::script::ComplexValue;
use crate::upstream::{PeerBalancer, UpstreamPeer};

/// The SSL fields of ngx_http_upstream_conf_t.
#[derive(Clone, Default)]
pub struct UpstreamSslConf {
    /// u->conf->ssl: the context (ngx_ssl_t), shared with the parent level
    /// when the level sets no SSL directive (ngx_http_proxy_merge_ssl)
    pub ssl: Option<Rc<RefCell<NgxSsl>>>,
    pub ssl_session_reuse: Val<bool>,
    pub ssl_name: Val<Option<Rc<ComplexValue>>>,
    pub ssl_server_name: Val<bool>,
    pub ssl_verify: Val<bool>,
    pub ssl_certificate: Val<Option<Rc<ComplexValue>>>,
    pub ssl_certificate_key: Val<Option<Rc<ComplexValue>>>,
    pub ssl_certificate_cache: Val<Option<Rc<RefCell<SslCache>>>>,
    pub ssl_passwords: Val<Option<Rc<SslPasswords>>>,
}

impl UpstreamSslConf {
    /// The certificate and its key, if a certificate is set.
    fn certificate(&self) -> Option<(Rc<ComplexValue>, Option<Rc<ComplexValue>>)> {
        let cert = self.ssl_certificate.as_option().cloned().flatten()?;
        let key = self.ssl_certificate_key.as_option().cloned().flatten();
        Some((cert, key))
    }
}

/// ngx_conf_merge_ptr_value(conf, prev, NULL)
pub fn merge_ptr<T: Clone>(conf: &mut Val<Option<T>>, prev: &Val<Option<T>>) {
    if !conf.is_set() {
        *conf = Val::set(prev.as_option().cloned().flatten());
    }
}

/// ngx_http_upstream_merge_ssl_passwords: a certificate with variables
/// needs the passwords at run time.
///
/// Passwords read by ngx_ssl_read_password_file() are not cleared after
/// the configuration is read in this port, so a list is "preserved" as it
/// is; only the empty list of ngx_ssl_preserve_passwords() (no password
/// file) is created, and removed again for a certificate without
/// variables.
pub fn merge_ssl_passwords(cf: &mut Conf, conf: &mut UpstreamSslConf, prev: &mut UpstreamSslConf) -> ConfResult {
    merge_passwords(conf, prev, |p| ngx_ssl_preserve_passwords(cf, p));
    Ok(())
}

/// The body of merge_ssl_passwords, with ngx_ssl_preserve_passwords().
fn merge_passwords(conf: &mut UpstreamSslConf, prev: &mut UpstreamSslConf, preserve_passwords: impl FnOnce(Option<&Rc<SslPasswords>>) -> Rc<SslPasswords>) {
    // the previous level is unset only if it is not merged itself (the
    // http{} level): NGX_CONF_UNSET_PTR is not NULL
    let prev_null = prev.ssl_passwords.is_set() && prev.ssl_passwords.get().is_none();

    merge_ptr(&mut conf.ssl_passwords, &prev.ssl_passwords);

    let (cert, key) = match conf.certificate() {
        Some((cert, Some(key))) if !cert.value.is_empty() => (cert, key),
        _ => return,
    };

    let passwords = conf.ssl_passwords.as_option().cloned().flatten();

    if cert.is_constant() && key.is_constant() {
        if passwords.as_ref().is_some_and(|p| p.0.is_empty()) {
            // un-preserve empty password list
            conf.ssl_passwords = Val::set(None);
        }

        return;
    }

    if passwords.is_some() {
        // already preserved
        return;
    }

    let preserve = prev_null;

    let preserved = preserve_passwords(None);

    conf.ssl_passwords = Val::set(Some(preserved.clone()));

    // special handling to keep a preserved ssl_passwords copy
    // in the previous configuration to inherit it to all children

    if preserve {
        prev.ssl_passwords = Val::set(Some(preserved));
    }
}

/// What ngx_http_upstream_ssl_init_connection uses of a request: u->conf's
/// SSL fields and u->ssl_alpn_protocol.
#[derive(Clone)]
pub struct SslSetup {
    pub conf: UpstreamSslConf,
    /// u->ssl_alpn_protocol, in the wire format (empty: none)
    pub alpn: Vec<u8>,
}

/// c->data of an upstream connection: the upstream of the request it
/// serves (c->data = r in ngx_http_upstream_connect), for
/// ngx_http_upstream_ssl_save_session.
pub struct UpstreamConnData {
    pub balancer: Weak<RefCell<Box<dyn PeerBalancer>>>,
}

/// u->peer.connection of an https upstream: a connection of
/// ngx_event_connect_peer with c->ssl. Dropping it closes the connection
/// as ngx_http_upstream_finalize_request does: the "close notify" alert is
/// sent to the upstream, without waiting for its own.
pub struct PeerConn {
    pub c: Rc<Connection>,
}

impl PeerConn {
    /// The connection is closed as ngx_http_upstream_next and
    /// ngx_http_upstream_keepalive_close do: without "close notify".
    pub fn set_no_shutdown(&self) {
        if let Some(sc) = self.c.ssl.borrow().as_ref() {
            sc.no_wait_shutdown.set(true);
            sc.no_send_shutdown.set(true);
        }
    }

    /// The socket, for the close handler of the keepalive cache.
    pub fn fd(&self) -> std::os::unix::io::RawFd {
        self.c.fd.get()
    }

    /// The keepalive cache takes the connection (c->idle = 1) or gives it
    /// to a request (c->idle = 0, c->sent = 0, c->data = NULL).
    pub fn set_idle(&self, idle: bool) {
        self.c.idle.set(idle);

        if !idle {
            self.c.sent.set(0);
        }

        *self.c.data.borrow_mut() = None;
    }

    /// ngx_ssl_recv() (a plain recv() without c->ssl): Ok with nothing
    /// read is the end of the stream.
    pub fn poll_read(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let c = &self.c;
        let sc = c.ssl.borrow().clone();
        let dst = buf.initialize_unfilled();

        let rc = match sc {
            // OpenSSL may hold records the socket no longer shows, unless its
            // last read found the socket drained (c->read->ready = 0)
            Some(sc) if sc.state.recv_drained.get() && !sc.state.in_early.get() => c.poll_read_io(cx, || ngx_ssl_recv_step(c, &sc, &mut *dst)),
            Some(sc) => c.poll_io(cx, || ngx_ssl_recv_step(c, &sc, &mut *dst)),
            None => c.poll_read_io(cx, || recv_step(c, &mut *dst)),
        };

        match rc {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) | Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(Ok(n))) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
        }
    }

    /// ngx_ssl_write() (a plain send() without c->ssl)
    pub fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let c = &self.c;
        let sc = c.ssl.borrow().clone();

        let rc = match sc {
            Some(sc) => c.poll_io(cx, || ngx_ssl_write_step(c, &sc, data)),
            None => c.poll_io(cx, || send_step(c, data)),
        };

        match rc {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) | Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(Ok(n))) => Poll::Ready(Ok(n)),
        }
    }

    /// The write side is done (the other side of an upgraded connection
    /// closed): the "close notify" alert is sent, the upstream's data is
    /// still read.
    pub fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let c = &self.c;
        let sc = c.ssl.borrow().clone();

        match sc {
            Some(sc) => {
                let ssl = ssl_ptr(&sc);

                if !ssl.is_null() && sc.handshaked.get() {
                    // SAFETY: the SSL object is alive while c->ssl holds it
                    unsafe {
                        if openssl_sys::SSL_get_shutdown(ssl) & openssl_sys::SSL_SENT_SHUTDOWN == 0 {
                            ngx_ssl_clear_error(&c.log);

                            let n = openssl_sys::SSL_shutdown(ssl);

                            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_shutdown: {}", n);

                            openssl_sys::ERR_clear_error();
                        }
                    }
                }
            }

            None => {
                let _ = c.shutdown_write();
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Wait until the upstream has sent data or closed the connection. TLS
    /// records without application data (the session tickets of TLS 1.3)
    /// are processed on the way; the data stays for the next read.
    pub async fn wait_readable(&self) {
        let c = &self.c;
        let sc = c.ssl.borrow().clone();

        match sc {
            Some(sc) => {
                let _ = c.drive_io(|| ssl_peek_step(c, &sc)).await;
            }

            None => {
                let _ = c.readable().await;
            }
        }
    }
}

impl Drop for PeerConn {
    fn drop(&mut self) {
        let c = &self.c;

        if c.is_closed() {
            return;
        }

        let sc = c.ssl.borrow().clone();

        if let Some(sc) = sc {
            // We send the "close notify" shutdown alert to the upstream only
            // and do not wait its "close notify" shutdown alert.
            // It is acceptable according to the TLS standard.

            sc.no_wait_shutdown.set(true);

            let _ = ngx_ssl_shutdown(c);
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "close http upstream connection: {}", c.fd.get());

        c.close();
    }
}

/// A recv() attempt on a connection without c->ssl.
fn recv_step(c: &Connection, buf: &mut [u8]) -> IoStep<io::Result<usize>> {
    match c.try_recv_raw(buf) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => IoStep::WantRead,
        Ok(0) => {
            c.read_eof.set(true);
            IoStep::Done(Ok(0))
        }
        Ok(n) => {
            // ngx_unix_recv: a short read emptied the socket
            if n < buf.len() {
                c.read_drained();
            }
            IoStep::Done(Ok(n))
        }
        r => IoStep::Done(r),
    }
}

/// A send() attempt on a connection without c->ssl.
fn send_step(c: &Connection, data: &[u8]) -> IoStep<io::Result<usize>> {
    let n = unsafe { libc::send(c.fd.get(), data.as_ptr() as *const c_void, data.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };

    if n < 0 {
        let e = io::Error::last_os_error();

        if e.kind() == io::ErrorKind::WouldBlock {
            return IoStep::WantWrite;
        }

        return IoStep::Done(Err(e));
    }

    c.sent.set(c.sent.get() + n as u64);

    IoStep::Done(Ok(n as usize))
}

/// SSL_peek() for a byte: done when application data is there, the
/// stream ended or failed (the next ngx_ssl_recv() reports it).
fn ssl_peek_step(c: &Connection, sc: &SslConnection) -> IoStep<()> {
    if sc.state.last.get() != NGX_OK {
        return IoStep::Done(());
    }

    let ssl = ssl_ptr(sc);

    if ssl.is_null() {
        return IoStep::Done(());
    }

    ngx_ssl_clear_error(&c.log);

    let mut b = [0u8; 1];

    // SAFETY: the SSL object is alive while c->ssl holds it
    unsafe {
        let n = openssl_sys::SSL_peek(ssl, b.as_mut_ptr() as *mut c_void, 1);

        if n > 0 {
            return IoStep::Done(());
        }

        match openssl_sys::SSL_get_error(ssl, n) {
            openssl_sys::SSL_ERROR_WANT_READ => IoStep::WantRead,
            openssl_sys::SSL_ERROR_WANT_WRITE => IoStep::WantWrite,
            _ => {
                openssl_sys::ERR_clear_error();
                IoStep::Done(())
            }
        }
    }
}

/// ngx_http_upstream_test_connect: the result of a connect() in progress
/// (NGX_OK, or NGX_ERROR logged).
pub fn test_connect(c: &Connection) -> i64 {
    let err = ngx_core::event_connect::connect_error(c);

    if err != 0 {
        c.log.set_action(Some("connecting to upstream"));
        let _ = c.connection_error(err, "connect() failed");
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_http_upstream_ssl_init_connection, and ngx_http_upstream_ssl_handshake
/// when the handshake is done or failed (from
/// ngx_http_upstream_ssl_handshake_handler if it waited): Ok when the
/// request may be sent (ngx_http_upstream_send_request).
///
/// The handshake waits until `deadline` (the timer of the connect still
/// set), or proxy_connect_timeout.
pub(crate) async fn ssl_init_connection(r: &R, u: &mut UpstreamPeer, c: &Rc<Connection>, ssl: &SslSetup, deadline: Option<Instant>, connect_timeout: u64) -> Result<(), ConnectError> {
    let conf = &ssl.conf;

    if test_connect(c) != NGX_OK {
        return Err(ConnectError::Error);
    }

    // the context of the location (ngx_http_proxy_set_ssl)
    let ctx = match conf.ssl.as_ref() {
        Some(s) if !s.borrow().ctx.is_null() => s.clone(),
        _ => {
            ngx_log_error!(NGX_LOG_ALERT, c.log, None, "no SSL context for the upstream");
            return Err(ConnectError::Internal);
        }
    };

    if ngx_ssl_create_connection(&ctx.borrow(), c, NGX_SSL_BUFFER | NGX_SSL_CLIENT) != NGX_OK {
        return Err(ConnectError::Internal);
    }

    if (*conf.ssl_server_name || *conf.ssl_verify) && ssl_name(r, u, c, conf).is_err() {
        return Err(ConnectError::Internal);
    }

    if let Some((cert, Some(key))) = conf.certificate() {
        if !cert.value.is_empty() && (!cert.is_constant() || !key.is_constant()) && ssl_certificate(r, c, conf).is_err() {
            return Err(ConnectError::Internal);
        }
    }

    if !ssl.alpn.is_empty() && ngx_ssl_set_alpn_protos(c, &ssl.alpn) != 0 {
        ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("SSL_set_alpn_protos() failed"));
        return Err(ConnectError::Internal);
    }

    if *conf.ssl_session_reuse {
        ngx_ssl_set_save_session(c, Some(Rc::new(ssl_save_session)));

        // u->peer.set_session

        if let Some(session) = u.set_session() {
            let rc = ngx_ssl_set_session(c, session.as_ptr());

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, u.pc.log, "set session: {:p}", session.as_ptr());

            if rc != NGX_OK {
                return Err(ConnectError::Internal);
            }
        }

        // abbreviated SSL handshake may interact badly with Nagle

        let tcp_nodelay = *r.clcf().borrow().tcp_nodelay;

        if tcp_nodelay && !c.set_tcp_nodelay() {
            return Err(ConnectError::Internal);
        }
    }

    r.connection.log.set_action(Some("SSL handshaking to upstream"));

    let mut rc = ngx_ssl_handshake(c);

    let mut timedout = false;

    if rc == NGX_AGAIN {
        // if (!c->write->timer_set) ngx_add_timer(c->write, connect_timeout)
        let deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_millis(connect_timeout));

        // c->ssl->handler = ngx_http_upstream_ssl_handshake_handler
        rc = match tokio::time::timeout_at(deadline, ngx_ssl_handshake_wait(c)).await {
            Ok(rc) => rc,
            Err(_) => {
                timedout = true;
                NGX_ERROR
            }
        };

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http upstream ssl handshake: \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));
    }

    let _ = rc;

    ssl_handshake(r, u, c, conf, timedout)
}

/// ngx_http_upstream_ssl_handshake
fn ssl_handshake(r: &R, u: &mut UpstreamPeer, c: &Connection, conf: &UpstreamSslConf, timedout: bool) -> Result<(), ConnectError> {
    let handshaked = c.ssl.borrow().as_ref().is_some_and(|sc| sc.handshaked.get());

    if handshaked {
        if *conf.ssl_verify {
            let rc = ngx_ssl_get_verify_result(c);

            // X509_V_OK
            if rc != 0 {
                ngx_log_error!(NGX_LOG_ERR, c.log, None, "upstream SSL certificate verify error: ({}:{})", rc, B(&ngx_ssl_verify_error_string(rc)));
                return Err(ConnectError::Error);
            }

            if ngx_ssl_check_host(c, &u.ssl_name) != NGX_OK {
                ngx_log_error!(NGX_LOG_ERR, c.log, None, "upstream SSL certificate does not match \"{}\"", B(&u.ssl_name));
                return Err(ConnectError::Error);
            }
        }

        let sendfile = c.ssl.borrow().as_ref().is_some_and(|sc| sc.state.sendfile.get());

        if !sendfile {
            c.sendfile.set(false);
        }

        return Ok(());
    }

    if timedout {
        // ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT)
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
        return Err(ConnectError::Timeout);
    }

    // failed:

    Err(ConnectError::Error)
}

/// ngx_http_upstream_ssl_save_session: a new session of the connection goes
/// to the peer of the request using it (u->peer.save_session).
fn ssl_save_session(c: &Connection) {
    if c.idle.get() {
        return;
    }

    // r = c->data; u = r->upstream

    let data = c.data.borrow().clone();

    let data = match data.and_then(|d| d.downcast::<UpstreamConnData>().ok()) {
        Some(d) => d,
        None => return,
    };

    let balancer = match data.balancer.upgrade() {
        Some(b) => b,
        None => return,
    };

    let sess = ngx_ssl_get_session(c);

    if sess.is_null() {
        return;
    }

    // SAFETY: ngx_ssl_get_session() returned a reference of the session,
    // which the SslSession owns from now on
    let session = unsafe { openssl::ssl::SslSession::from_ptr(sess) };

    let mut b = match balancer.try_borrow_mut() {
        Ok(b) => b,
        Err(_) => return,
    };

    b.save_session(session);
}

/// ngx_http_upstream_ssl_name: the name sent as SNI, and verified
/// (u->ssl_name).
fn ssl_name(r: &R, u: &mut UpstreamPeer, c: &Connection, conf: &UpstreamSslConf) -> Result<(), ()> {
    let mut name = match conf.ssl_name.as_option().cloned().flatten() {
        Some(cv) => crate::script::complex_value(r, &cv).map_err(|_| ())?,
        None => u.ssl_name.clone(),
    };

    'done: {
        if name.is_empty() {
            break 'done;
        }

        // ssl name here may contain port, notably if derived from $proxy_host
        // or $http_host; we have to strip it

        let mut p = 0;

        if name[0] == b'[' {
            p = name.iter().position(|&ch| ch == b']').unwrap_or(0);
        }

        if let Some(i) = name[p..].iter().position(|&ch| ch == b':') {
            name.truncate(p + i);
        }

        if !*conf.ssl_server_name {
            break 'done;
        }

        // as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted

        if name.is_empty() || name[0] == b'[' {
            break 'done;
        }

        if ngx_core::inet::inet_addr(&name).is_some() {
            break 'done;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "upstream SSL server name: \"{}\"", B(&name));

        if !ngx_ssl_set_tlsext_host_name(c, &name) {
            ngx_ssl_error(NGX_LOG_ERR, &r.connection.log, 0, format_args!("SSL_set_tlsext_host_name(\"{}\") failed", B(&name)));
            return Err(());
        }
    }

    u.ssl_name = name;

    Ok(())
}

/// ngx_http_upstream_ssl_certificate: a certificate with variables
fn ssl_certificate(r: &R, c: &Connection, conf: &UpstreamSslConf) -> Result<(), ()> {
    let (cert_cv, key_cv) = match conf.certificate() {
        Some((cert, Some(key))) => (cert, key),
        _ => return Err(()),
    };

    let mut cert = crate::script::complex_value(r, &cert_cv).map_err(|_| ())?;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http upstream ssl cert: \"{}\"", B(&cert));

    if cert.is_empty() {
        return Ok(());
    }

    let mut key = crate::script::complex_value(r, &key_cv).map_err(|_| ())?;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http upstream ssl key: \"{}\"", B(&key));

    let cache = conf.ssl_certificate_cache.as_option().cloned().flatten();
    let passwords = conf.ssl_passwords.as_option().cloned().flatten();

    if ngx_ssl_connection_certificate(c, &mut cert, &mut key, cache.as_ref(), passwords.as_ref()) != NGX_OK {
        return Err(());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cv(v: &[u8]) -> Option<Rc<ComplexValue>> {
        Some(Rc::new(ComplexValue::constant(v)))
    }

    #[test]
    fn merge_ptr_takes_prev_only_when_unset() {
        let mut conf: Val<Option<u32>> = Val::unset();
        merge_ptr(&mut conf, &Val::set(Some(5)));
        assert_eq!(conf, Val::set(Some(5)));

        let mut conf: Val<Option<u32>> = Val::set(None);
        merge_ptr(&mut conf, &Val::set(Some(5)));
        assert_eq!(conf, Val::set(None));

        let mut conf: Val<Option<u32>> = Val::unset();
        merge_ptr(&mut conf, &Val::unset());
        assert_eq!(conf, Val::set(None));
    }

    fn preserve(_: Option<&Rc<SslPasswords>>) -> Rc<SslPasswords> {
        Rc::new(SslPasswords::default())
    }

    #[test]
    fn passwords_without_certificate_are_merged_only() {
        let mut prev = UpstreamSslConf::default();
        let mut conf = UpstreamSslConf::default();

        prev.ssl_passwords = Val::set(Some(Rc::new(SslPasswords(vec![b"x".to_vec()]))));

        merge_passwords(&mut conf, &mut prev, preserve);

        assert_eq!(conf.ssl_passwords.get().as_ref().unwrap().0, vec![b"x".to_vec()]);
    }

    #[test]
    fn empty_passwords_unpreserved_for_constant_certificate() {
        let mut prev = UpstreamSslConf::default();
        let mut conf = UpstreamSslConf::default();

        prev.ssl_passwords = Val::set(Some(Rc::new(SslPasswords::default())));
        conf.ssl_certificate = Val::set(cv(b"a.crt"));
        conf.ssl_certificate_key = Val::set(cv(b"a.key"));

        merge_passwords(&mut conf, &mut prev, preserve);

        assert!(conf.ssl_passwords.get().is_none());
    }

    #[test]
    fn variable_certificate_gets_preserved_passwords() {
        let mut prev = UpstreamSslConf::default();
        let mut conf = UpstreamSslConf::default();

        prev.ssl_passwords = Val::set(None);

        let var = ComplexValue { value: b"$x".to_vec(), parts: Some(Vec::new()), flags: 0 };
        conf.ssl_certificate = Val::set(Some(Rc::new(var.clone())));
        conf.ssl_certificate_key = Val::set(Some(Rc::new(var)));

        merge_passwords(&mut conf, &mut prev, preserve);

        let p = conf.ssl_passwords.get().clone().unwrap();
        assert!(p.0.is_empty());

        // the previous level keeps the preserved list for its children
        assert!(Rc::ptr_eq(prev.ssl_passwords.get().as_ref().unwrap(), &p));
    }
}
