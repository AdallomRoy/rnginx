//! OpenSSL integration (ngx_event_openssl.c). Connection-level I/O via openssl-sys FFI.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::io;
use std::os::raw::c_void;
use std::rc::Rc;

use foreign_types::ForeignType;
use openssl::ssl::Ssl;

use crate::conf::*;
use crate::connection::{Connection, IoStep};
use crate::log::Log;
use crate::module::*;
use crate::cmd_fn;

/// Per-connection SSL state.
pub struct SslConnection {
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

    /// Get the raw SSL* pointer. Panics if handshake hasn't started.
    fn ssl_ptr(&self) -> *mut openssl_sys::SSL {
        let b = self.inner.borrow();
        b.as_ref().expect("SSL not initialized").as_ptr()
    }

    /// One SSL_read attempt (the body of ngx_ssl_recv).
    fn read_step(&self, c: &Connection, buf: &mut [u8]) -> IoStep<io::Result<usize>> {
        let rc = unsafe {
            openssl_sys::SSL_read(self.ssl_ptr(), buf.as_mut_ptr() as *mut c_void, buf.len() as i32)
        };
        if rc > 0 {
            return IoStep::Done(Ok(rc as usize));
        }
        let err = unsafe { openssl_sys::SSL_get_error(self.ssl_ptr(), rc) };
        match err {
            openssl_sys::SSL_ERROR_WANT_READ => IoStep::WantRead,
            openssl_sys::SSL_ERROR_WANT_WRITE => IoStep::WantWrite,
            openssl_sys::SSL_ERROR_ZERO_RETURN => {
                c.read_eof.set(true);
                IoStep::Done(Ok(0))
            }
            openssl_sys::SSL_ERROR_SYSCALL => {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(0) {
                    c.read_eof.set(true);
                    return IoStep::Done(Ok(0));
                }
                IoStep::Done(Err(e))
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
        c.drive_io(|| {
            let rc = unsafe {
                openssl_sys::SSL_write(self.ssl_ptr(), buf.as_ptr() as *const c_void, buf.len() as i32)
            };
            if rc > 0 {
                c.sent.set(c.sent.get() + rc as u64);
                return IoStep::Done(Ok(rc as usize));
            }
            let err = unsafe { openssl_sys::SSL_get_error(self.ssl_ptr(), rc) };
            match err {
                openssl_sys::SSL_ERROR_WANT_READ => IoStep::WantRead,
                openssl_sys::SSL_ERROR_WANT_WRITE => IoStep::WantWrite,
                openssl_sys::SSL_ERROR_SYSCALL => IoStep::Done(Err(io::Error::last_os_error())),
                _ => IoStep::Done(Err(io::Error::new(io::ErrorKind::Other, format!("SSL_write failed: {}", ssl_error_string())))),
            }
        })
        .await?
    }

    /// A single SSL_write attempt; WANT_READ / WANT_WRITE map to WouldBlock.
    pub fn try_send(&self, c: &Connection, buf: &[u8]) -> io::Result<usize> {
        if self.state.ngx.get() {
            return match crate::event_openssl::ngx_ssl_write_step(c, self, buf) {
                IoStep::Done(r) => r,
                IoStep::WantRead | IoStep::WantWrite => Err(io::ErrorKind::WouldBlock.into()),
            };
        }
        let rc = unsafe { openssl_sys::SSL_write(self.ssl_ptr(), buf.as_ptr() as *const c_void, buf.len() as i32) };
        if rc > 0 {
            c.sent.set(c.sent.get() + rc as u64);
            return Ok(rc as usize);
        }
        match unsafe { openssl_sys::SSL_get_error(self.ssl_ptr(), rc) } {
            openssl_sys::SSL_ERROR_WANT_READ | openssl_sys::SSL_ERROR_WANT_WRITE => Err(io::ErrorKind::WouldBlock.into()),
            openssl_sys::SSL_ERROR_SYSCALL => Err(io::Error::last_os_error()),
            _ => Err(io::Error::new(io::ErrorKind::Other, format!("SSL_write failed: {}", ssl_error_string()))),
        }
    }

    pub fn free_on_close(&self, _c: &Connection) {
        // Ssl is dropped when SslConnection is dropped.
    }

    /// Selected ALPN protocol after handshake (e.g. b"h2", b"http/1.1").
    /// Returns None if ALPN wasn't negotiated.
    pub fn alpn_selected(&self) -> Option<Vec<u8>> {
        if !self.handshaked.get() { return None; }
        let ssl = self.ssl_ptr();
        let mut data: *const u8 = std::ptr::null();
        let mut len: u32 = 0;
        unsafe {
            openssl_sys::SSL_get0_alpn_selected(ssl, &mut data, &mut len);
            if data.is_null() || len == 0 { return None; }
            Some(std::slice::from_raw_parts(data, len as usize).to_vec())
        }
    }
}

/// Read the top of the OpenSSL error queue into a string.
pub fn ssl_error_string() -> String {
    unsafe {
        let mut msg = String::new();
        loop {
            let e = openssl_sys::ERR_get_error();
            if e == 0 {
                break;
            }
            let cptr = openssl_sys::ERR_reason_error_string(e);
            if cptr.is_null() { continue; }
            let s = std::ffi::CStr::from_ptr(cptr).to_string_lossy();
            if !msg.is_empty() {
                msg.push_str("; ");
            }
            msg.push_str(&s);
        }
        if msg.is_empty() { "unknown".to_string() } else { msg }
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
