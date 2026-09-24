//! OpenSSL integration (ngx_event_openssl.c). Connection-level pieces; contexts come later.

use std::any::Any;
use std::io;
use std::rc::Rc;

use crate::conf::*;
use crate::connection::Connection;
use crate::log::Log;
use crate::module::*;
use crate::{cmd_fn};

/// Per-connection SSL state (filled in by the ssl module port).
pub struct SslConnection {
    pub inner: std::cell::RefCell<Option<openssl::ssl::Ssl>>,
    pub handshaked: std::cell::Cell<bool>,
    pub no_wait_shutdown: std::cell::Cell<bool>,
    pub no_send_shutdown: std::cell::Cell<bool>,
    pub shutdown_without_free: std::cell::Cell<bool>,
    pub buffer_size: std::cell::Cell<usize>,
    pub data: std::cell::RefCell<Option<Rc<dyn Any>>>,
}

impl SslConnection {
    pub async fn recv(&self, c: &Connection, buf: &mut [u8]) -> io::Result<usize> {
        let _ = (c, buf);
        Err(io::Error::new(io::ErrorKind::Other, "ssl not implemented"))
    }

    pub async fn send(&self, c: &Connection, buf: &[u8]) -> io::Result<usize> {
        let _ = (c, buf);
        Err(io::Error::new(io::ErrorKind::Other, "ssl not implemented"))
    }

    pub fn free_on_close(&self, _c: &Connection) {}
}

pub fn openssl_version_text() -> String {
    // OPENSSL_VERSION_TEXT of the linked library, e.g. "OpenSSL 3.0.2 15 Mar 2022"
    openssl::version::version().to_string()
}

pub fn ssl_init(_log: &Log) {
    openssl::init();
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
