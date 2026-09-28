//! TLS to upstreams: the client side of ngx_ssl_handshake, the upstream
//! parts of ngx_http_upstream.c (ngx_http_upstream_ssl_init_connection,
//! ngx_http_upstream_ssl_handshake, ngx_http_upstream_ssl_name) and the
//! context of ngx_http_proxy_set_ssl.
//!
//! OpenSSL runs over the tokio socket through non-blocking try_read /
//! try_write, so WANT_READ / WANT_WRITE wait for the socket readiness the
//! failed attempt cleared.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use openssl::ssl::{ErrorCode, Ssl, SslContext, SslContextBuilder, SslMethod, SslSession, SslSessionCacheMode, SslStream, SslVerifyMode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};

/// The upstream socket as OpenSSL's BIO: never blocks.
pub enum SockIo {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl SockIo {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            SockIo::Tcp(s) => s.poll_read_ready(cx),
            SockIo::Unix(s) => s.poll_read_ready(cx),
        }
    }

    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            SockIo::Tcp(s) => s.poll_write_ready(cx),
            SockIo::Unix(s) => s.poll_write_ready(cx),
        }
    }
}

impl Read for SockIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            SockIo::Tcp(s) => s.try_read(buf),
            SockIo::Unix(s) => s.try_read(buf),
        }
    }
}

impl Write for SockIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            SockIo::Tcp(s) => s.try_write(buf),
            SockIo::Unix(s) => s.try_write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An upstream connection over TLS.
pub struct UpstreamSsl {
    stream: SslStream<SockIo>,
    /// the connection's key for sessions OpenSSL hands over
    session_key: u64,
    /// Application data read while waiting for the upstream to answer.
    peeked: Vec<u8>,
    eof: bool,
    error: Option<io::Error>,
}

/// NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3, the default of proxy_ssl_protocols.
pub const DEFAULT_PROTOCOLS: u32 = 0x0020 | 0x0040;

/// The SSL context of a location that proxies over TLS
/// (ngx_http_proxy_set_ssl): protocols, ciphers, verification against
/// trusted certificates, and the client session cache when sessions are
/// reused.
pub fn create_ctx(
    protocols: u32,
    ciphers: &[u8],
    verify: Option<(&[u8], u32)>,
    session_reuse: bool,
) -> Result<SslContext, String> {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).map_err(|e| format!("SSL_CTX_new() failed ({})", e))?;

    // ngx_ssl_create
    let mut opts = openssl_sys::SSL_OP_NO_COMPRESSION as u64;
    if protocols & 0x0002 == 0 {
        opts |= openssl_sys::SSL_OP_NO_SSLv2 as u64;
    }
    if protocols & 0x0004 == 0 {
        opts |= openssl_sys::SSL_OP_NO_SSLv3 as u64;
    }
    if protocols & 0x0008 == 0 {
        opts |= openssl_sys::SSL_OP_NO_TLSv1 as u64;
    }
    if protocols & 0x0010 == 0 {
        opts |= openssl_sys::SSL_OP_NO_TLSv1_1 as u64;
    }
    if protocols & 0x0020 == 0 {
        opts |= openssl_sys::SSL_OP_NO_TLSv1_2 as u64;
    }
    if protocols & 0x0040 == 0 {
        opts |= openssl_sys::SSL_OP_NO_TLSv1_3 as u64;
    }
    opts |= openssl_sys::SSL_OP_IGNORE_UNEXPECTED_EOF as u64;
    unsafe {
        openssl_sys::SSL_CTX_set_options(builder.as_ptr(), opts as _);
        openssl_sys::SSL_CTX_set_mode(builder.as_ptr(), (openssl_sys::SSL_MODE_RELEASE_BUFFERS | openssl_sys::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER) as _);
    }

    // ngx_ssl_ciphers
    let list = String::from_utf8_lossy(ciphers).into_owned();
    builder
        .set_cipher_list(&list)
        .map_err(|e| format!("SSL_CTX_set_cipher_list(\"{}\") failed ({})", list, e))?;

    // ngx_ssl_trusted_certificate: the result is checked after the
    // handshake (ngx_http_upstream_ssl_handshake)
    if let Some((trusted, depth)) = verify {
        builder.set_verify_callback(SslVerifyMode::NONE, |_, _| true);
        builder.set_verify_depth(depth);
        let file = String::from_utf8_lossy(trusted).into_owned();
        builder
            .set_ca_file(&file)
            .map_err(|e| format!("SSL_CTX_load_verify_locations(\"{}\") failed ({})", file, e))?;
    }

    // ngx_ssl_client_session_cache
    if session_reuse {
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
        builder.set_new_session_callback(|ssl, session| {
            // ngx_ssl_new_client_session: kept for c->ssl->save_session,
            // the peer's save_session of the request using the connection
            let key = match ssl.ex_data(session_key_index()) {
                Some(k) => *k,
                None => return,
            };
            NEW_SESSIONS.with(|s| {
                s.borrow_mut().insert(key, session);
            });
        });
    }

    Ok(builder.build())
}

thread_local! {
    /// Sessions of connections not yet given to their peers, by
    /// connection key.
    static NEW_SESSIONS: RefCell<HashMap<u64, SslSession>> = RefCell::new(HashMap::new());
    static SESSION_KEY: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn session_key_index() -> openssl::ex_data::Index<Ssl, u64> {
    use std::sync::OnceLock;
    static INDEX: OnceLock<openssl::ex_data::Index<Ssl, u64>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("SSL_get_ex_new_index() failed"))
}

/// How the handshake failed: the upstream is tried as after a connect error.
pub enum HandshakeError {
    /// SSL_do_handshake() failed, or the certificate did not verify.
    Failed(String),
    /// The connection could not be set up (NGX_HTTP_INTERNAL_SERVER_ERROR).
    Internal(String),
}

/// What ngx_http_upstream_ssl_init_connection needs of the location.
pub struct Params<'a> {
    pub ctx: &'a SslContext,
    /// Sessions are reused: the peer's session (peer.set_session), and new
    /// ones are kept for peer.save_session.
    pub session_reuse: bool,
    pub session: Option<SslSession>,
    /// ngx_http_upstream_ssl_name, when proxy_ssl_server_name or
    /// proxy_ssl_verify is on: the name, and whether to send it (SNI).
    pub name: Option<(&'a [u8], bool)>,
    pub verify: bool,
}

/// ngx_http_upstream_ssl_init_connection and ngx_http_upstream_ssl_handshake.
pub async fn handshake(sock: SockIo, p: Params<'_>) -> Result<UpstreamSsl, HandshakeError> {
    let mut ssl = Ssl::new(p.ctx).map_err(|e| HandshakeError::Internal(format!("SSL_new() failed ({})", e)))?;
    ssl.set_connect_state();

    let mut check_name: Option<Vec<u8>> = None;

    if let Some((name, server_name)) = p.name {
        // the name may contain a port, notably if derived from $proxy_host or
        // $http_host; strip it
        let mut end = name.len();
        let mut from = 0;
        if name.first() == Some(&b'[') {
            if let Some(i) = name.iter().position(|&c| c == b']') {
                from = i;
            }
        }
        if let Some(i) = name[from..].iter().position(|&c| c == b':') {
            end = from + i;
        }
        let name = &name[..end];

        // as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted
        if server_name && !name.is_empty() && name[0] != b'[' && std::str::from_utf8(name).map_or(true, |s| s.parse::<std::net::Ipv4Addr>().is_err()) {
            let host = String::from_utf8_lossy(name).into_owned();
            ssl.set_hostname(&host)
                .map_err(|e| HandshakeError::Internal(format!("SSL_set_tlsext_host_name(\"{}\") failed ({})", host, e)))?;
        }

        check_name = Some(name.to_vec());
    }

    let session_key = SESSION_KEY.with(|k| {
        k.set(k.get() + 1);
        k.get()
    });

    if p.session_reuse {
        if let Some(session) = &p.session {
            // a session of another context is refused by the server, as in C
            unsafe {
                let _ = ssl.set_session(session);
            }
        }
        ssl.set_ex_data(session_key_index(), session_key);
    }

    let stream = SslStream::new(ssl, sock).map_err(|e| HandshakeError::Internal(format!("SSL_new() failed ({})", e)))?;

    let mut s = UpstreamSsl { stream, session_key, peeked: Vec::new(), eof: false, error: None };

    match std::future::poll_fn(|cx| s.poll_io(cx, |st| st.connect())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(HandshakeError::Failed(format!("SSL_do_handshake() failed ({})", e))),
        Err(e) => return Err(HandshakeError::Failed(format!("SSL_do_handshake() failed ({})", e))),
    }

    if p.verify {
        let rc = s.stream.ssl().verify_result();

        if rc != openssl::x509::X509VerifyResult::OK {
            return Err(HandshakeError::Failed(format!(
                "upstream SSL certificate verify error: ({}:{})",
                rc.as_raw(),
                rc.error_string()
            )));
        }

        let name = check_name.unwrap_or_default();

        if !check_host(&s, &name) {
            return Err(HandshakeError::Failed(format!(
                "upstream SSL certificate does not match \"{}\"",
                String::from_utf8_lossy(&name)
            )));
        }
    }

    Ok(s)
}

/// ngx_ssl_check_host
fn check_host(s: &UpstreamSsl, name: &[u8]) -> bool {
    let cert = match s.stream.ssl().peer_certificate() {
        Some(c) => c,
        None => return false,
    };

    use foreign_types::ForeignTypeRef;

    let rc = unsafe {
        openssl_sys::X509_check_host(cert.as_ptr(), name.as_ptr() as *const _, name.len(), 0, std::ptr::null_mut())
    };

    rc == 1
}

impl UpstreamSsl {
    /// Run an SSL operation until it completes, waiting for the socket
    /// when OpenSSL wants to read or write. The outer error is the
    /// socket's, the inner one OpenSSL's.
    fn poll_io<T>(
        &mut self,
        cx: &mut Context<'_>,
        mut op: impl FnMut(&mut SslStream<SockIo>) -> Result<T, openssl::ssl::Error>,
    ) -> Poll<io::Result<Result<T, openssl::ssl::Error>>> {
        loop {
            let e = match op(&mut self.stream) {
                Ok(v) => return Poll::Ready(Ok(Ok(v))),
                Err(e) => e,
            };

            let ready = match e.code() {
                ErrorCode::WANT_READ => self.stream.get_ref().poll_read_ready(cx),
                ErrorCode::WANT_WRITE => self.stream.get_ref().poll_write_ready(cx),
                _ => return Poll::Ready(Ok(Err(e))),
            };

            match ready {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(io)) => return Poll::Ready(Err(io)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// ngx_ssl_recv: 0 at the end of the stream (close_notify, or the
    /// connection closed without it: SSL_OP_IGNORE_UNEXPECTED_EOF).
    fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.poll_io(cx, |st| st.ssl_read(buf)) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(Ok(n))) => Poll::Ready(Ok(n)),
            Poll::Ready(Ok(Err(e))) => {
                if e.code() == ErrorCode::ZERO_RETURN || (e.code() == ErrorCode::SYSCALL && e.io_error().is_none()) {
                    return Poll::Ready(Ok(0));
                }
                Poll::Ready(Err(ssl_io_error(e)))
            }
        }
    }

    /// The socket descriptor, for the keepalive cache's close handler.
    pub fn raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::AsRawFd;
        match self.stream.get_ref() {
            SockIo::Tcp(s) => Some(s.as_raw_fd()),
            SockIo::Unix(s) => Some(s.as_raw_fd()),
        }
    }

    /// Wait until the upstream has sent application data or closed. TLS
    /// records without data, like TLS 1.3 session tickets, are processed
    /// on the way; the data read is returned by the next read.
    pub async fn wait_readable(&mut self) {
        if !self.peeked.is_empty() || self.eof || self.error.is_some() {
            return;
        }

        let mut buf = vec![0u8; 16384];

        match std::future::poll_fn(|cx| self.poll_recv(cx, &mut buf)).await {
            Ok(0) => self.eof = true,
            Ok(n) => self.peeked.extend_from_slice(&buf[..n]),
            Err(e) => self.error = Some(e),
        }
    }
}

/// ngx_ssl_shutdown as ngx_http_upstream_finalize_request calls it: send
/// close_notify once, without waiting for the upstream's
/// (no_wait_shutdown). SSL_free after an unfinished shutdown would also
/// mark the session as not resumable (ssl_clear_bad_session), and it is
/// shared with the saved one.
impl UpstreamSsl {
    /// The session OpenSSL handed over since the last call, for the peer's
    /// save_session (ngx_http_upstream_ssl_save_session).
    pub fn take_session(&self) -> Option<SslSession> {
        NEW_SESSIONS.with(|s| s.borrow_mut().remove(&self.session_key))
    }
}

impl Drop for UpstreamSsl {
    fn drop(&mut self) {
        use foreign_types::ForeignTypeRef;

        NEW_SESSIONS.with(|s| s.borrow_mut().remove(&self.session_key));

        let ssl = self.stream.ssl().as_ptr();

        unsafe {
            if SSL_in_init(ssl) != 0 {
                return;
            }

            let mode = openssl_sys::SSL_get_shutdown(ssl) | openssl_sys::SSL_RECEIVED_SHUTDOWN;
            openssl_sys::SSL_set_shutdown(ssl, mode);
            openssl_sys::SSL_shutdown(ssl);
            openssl_sys::ERR_clear_error();
        }
    }
}

extern "C" {
    fn SSL_in_init(s: *const openssl_sys::SSL) -> std::os::raw::c_int;
}

fn ssl_io_error(e: openssl::ssl::Error) -> io::Error {
    match e.into_io_error() {
        Ok(io) => io,
        Err(e) => io::Error::other(e),
    }
}

impl AsyncRead for UpstreamSsl {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.peeked.is_empty() {
            let n = this.peeked.len().min(buf.remaining());
            buf.put_slice(&this.peeked[..n]);
            this.peeked.drain(..n);
            return Poll::Ready(Ok(()));
        }

        if let Some(e) = this.error.take() {
            return Poll::Ready(Err(e));
        }

        if this.eof {
            return Poll::Ready(Ok(()));
        }

        match this.poll_recv(cx, buf.initialize_unfilled()) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    this.eof = true;
                }
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for UpstreamSsl {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match this.poll_io(cx, |st| st.ssl_write(buf)) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(Ok(n))) => Poll::Ready(Ok(n)),
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err(ssl_io_error(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// ngx_ssl_shutdown: send close_notify, without waiting for the peer's.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.poll_io(cx, |st| st.shutdown()) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => Poll::Ready(Ok(())),
        }
    }
}

