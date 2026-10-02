//! OpenSSL integration (ngx_event_openssl.c): the SSL state of a
//! connection (c->ssl) and its I/O.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;

use ngx_sys::ssl as sys;
use openssl::ssl::{Ssl, SslRef};

use crate::cmd_fn;
use crate::conf::*;
use crate::connection::{Connection, IoStep};
use crate::log::Log;
use crate::module::*;

/// Per-connection SSL state.
pub struct SslConnection {
    /// c->ssl->connection: borrowed mutably by the SSL calls (the OpenSSL
    /// callbacks they run get the object from OpenSSL), shared by the
    /// getters; see with() and with_mut()
    pub inner: RefCell<Option<Ssl>>,
    pub handshaked: Cell<bool>,
    pub no_wait_shutdown: Cell<bool>,
    pub no_send_shutdown: Cell<bool>,
    pub shutdown_without_free: Cell<bool>,
    pub buffer_size: Cell<usize>,
    pub data: RefCell<Option<Rc<dyn Any>>>,
    /// the rest of ngx_ssl_connection_t (ngx_ssl_create_connection())
    pub state: crate::event_openssl::SslConnState,
}

impl Default for SslConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl SslConnection {
    pub fn new() -> Self {
        SslConnection {
            inner: RefCell::new(None),
            handshaked: Cell::new(false),
            no_wait_shutdown: Cell::new(false),
            no_send_shutdown: Cell::new(false),
            shutdown_without_free: Cell::new(false),
            buffer_size: Cell::new(16384),
            data: RefCell::new(None),
            state: crate::event_openssl::SslConnState::default(),
        }
    }

    /// The SSL object, shared: c->ssl->connection of the getters. While an
    /// SSL call of the connection is in progress (its callbacks evaluating
    /// variables, as the certificate callback does), the object is the one
    /// the callback lent with ngx_sys::ssl::with_current().
    pub fn with<R>(&self, f: impl FnOnce(&SslRef) -> R) -> Option<R> {
        match self.inner.try_borrow() {
            Ok(ssl) => ssl.as_ref().map(|s| f(s)),
            Err(_) => sys::current(|cur| match cur {
                Some(s) if crate::event_openssl::ngx_ssl_connection_id(s) == self.state.id.get() => Some(f(s)),
                _ => None,
            }),
        }
    }

    /// The SSL object, for an SSL call or a setting (None without one, or
    /// in a callback of an SSL call of the connection).
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut SslRef) -> R) -> Option<R> {
        let mut ssl = self.inner.try_borrow_mut().ok()?;
        ssl.as_mut().map(|s| f(s))
    }

    /// SSL_want_write(): the last TLS operation could not write.
    pub fn want_write(&self) -> bool {
        self.with(|ssl| sys::want(ssl) == sys::SSL_WRITING).unwrap_or(false)
    }

    /// One SSL_read attempt of a connection not made by
    /// ngx_ssl_create_connection().
    fn read_step(&self, c: &Connection, buf: &mut [u8]) -> IoStep<io::Result<usize>> {
        let io = match self.with_mut(|ssl| sys::read(ssl, buf)) {
            Some(io) => io,
            None => return IoStep::Done(Err(io::Error::new(io::ErrorKind::Other, "SSL not initialized"))),
        };

        if io.rc > 0 {
            return IoStep::Done(Ok(io.rc as usize));
        }

        match io.error {
            sys::SSL_ERROR_WANT_READ => IoStep::WantRead,
            sys::SSL_ERROR_WANT_WRITE => IoStep::WantWrite,
            sys::SSL_ERROR_ZERO_RETURN => {
                c.read_eof.set(true);
                IoStep::Done(Ok(0))
            }
            sys::SSL_ERROR_SYSCALL => {
                if io.errno == 0 {
                    c.read_eof.set(true);
                    return IoStep::Done(Ok(0));
                }
                IoStep::Done(Err(io::Error::from_raw_os_error(io.errno)))
            }
            _ => {
                let msg = ssl_error_string();
                // OpenSSL 3.x reports "unexpected eof while reading"
                // when the peer closes without close_notify. HTTP/2
                // clients (curl etc.) do this routinely; treat as
                // clean EOF so callers see Ok(0).
                if msg.contains("unexpected eof") {
                    c.read_eof.set(true);
                    return IoStep::Done(Ok(0));
                }
                IoStep::Done(Err(io::Error::new(io::ErrorKind::Other, format!("SSL_read failed: {}", msg))))
            }
        }
    }

    /// One SSL_write attempt of a connection not made by
    /// ngx_ssl_create_connection().
    fn write_step(&self, c: &Connection, buf: &[u8]) -> IoStep<io::Result<usize>> {
        let io = match self.with_mut(|ssl| sys::write(ssl, buf)) {
            Some(io) => io,
            None => return IoStep::Done(Err(io::Error::new(io::ErrorKind::Other, "SSL not initialized"))),
        };

        if io.rc > 0 {
            c.sent.set(c.sent.get() + io.rc as u64);
            return IoStep::Done(Ok(io.rc as usize));
        }

        match io.error {
            sys::SSL_ERROR_WANT_READ => IoStep::WantRead,
            sys::SSL_ERROR_WANT_WRITE => IoStep::WantWrite,
            sys::SSL_ERROR_SYSCALL => IoStep::Done(Err(io::Error::from_raw_os_error(io.errno))),
            _ => IoStep::Done(Err(io::Error::new(io::ErrorKind::Other, format!("SSL_write failed: {}", ssl_error_string())))),
        }
    }

    pub async fn recv(&self, c: &Connection, buf: &mut [u8]) -> io::Result<usize> {
        if self.state.ngx.get() {
            if self.state.recv_drained.get() && !self.state.in_early.get() {
                // c->read->ready = 0 since the last SSL_read(): nothing is
                // buffered, the read runs on the read event, as in C
                c.readable().await?;
            }
            return c.drive_io(|| crate::event_openssl::ngx_ssl_recv_step(c, self, buf)).await?;
        }
        c.drive_io(|| self.read_step(c, buf)).await?
    }

    /// A single SSL_read attempt; WANT_READ / WANT_WRITE map to WouldBlock.
    pub fn try_recv(&self, c: &Connection, buf: &mut [u8]) -> io::Result<usize> {
        let step = if self.state.ngx.get() { crate::event_openssl::ngx_ssl_recv_step(c, self, buf) } else { self.read_step(c, buf) };
        match step {
            IoStep::Done(r) => r,
            IoStep::WantRead | IoStep::WantWrite => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    pub async fn send(&self, c: &Connection, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.state.ngx.get() {
            return c.drive_io(|| crate::event_openssl::ngx_ssl_write_step(c, self, buf)).await?;
        }
        c.drive_io(|| self.write_step(c, buf)).await?
    }

    /// A single SSL_write attempt; WANT_READ / WANT_WRITE map to WouldBlock.
    pub fn try_send(&self, c: &Connection, buf: &[u8]) -> io::Result<usize> {
        let step = if self.state.ngx.get() { crate::event_openssl::ngx_ssl_write_step(c, self, buf) } else { self.write_step(c, buf) };
        match step {
            IoStep::Done(r) => r,
            IoStep::WantRead | IoStep::WantWrite => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    pub fn free_on_close(&self, _c: &Connection) {
        // Ssl is dropped when SslConnection is dropped.
    }

    /// Selected ALPN protocol after handshake (e.g. b"h2", b"http/1.1").
    /// Returns None if ALPN wasn't negotiated.
    pub fn alpn_selected(&self) -> Option<Vec<u8>> {
        if !self.handshaked.get() {
            return None;
        }
        self.with(|ssl| ssl.selected_alpn_protocol().filter(|p| !p.is_empty()).map(|p| p.to_vec())).flatten()
    }
}

/// The reasons of the OpenSSL error queue, which is emptied.
pub fn ssl_error_string() -> String {
    let stack = openssl::error::ErrorStack::get();

    let msg = stack.errors().iter().filter_map(|e| e.reason()).collect::<Vec<_>>().join("; ");

    if msg.is_empty() {
        "unknown".to_string()
    } else {
        msg
    }
}

pub fn openssl_version_text() -> String {
    openssl::version::version().to_string()
}

pub fn ssl_init(_log: &Log) {
    openssl::init();
    crate::event_openssl::ngx_ssl_init(_log);
}

fn ssl_engine(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Err(cf.emerg(format_args!("\"ssl_engine\" directive is not supported in this build")))
}

pub fn openssl_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_openssl_module", NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: "openssl", create_conf: None, init_conf: None }));
    m.commands = vec![cmd_fn!("ssl_engine", NGX_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::None, ssl_engine)];
    m
}
