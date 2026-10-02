//! ngx_event_openssl.c: OpenSSL contexts (ngx_ssl_t), connections
//! (ngx_ssl_connection_t: handshake, I/O, shutdown), the session caches,
//! session tickets, the connection variables and the SSL error logging.
//!
//! The C event handlers become async loops: ngx_ssl_handshake() and
//! ngx_ssl_shutdown() keep their synchronous one-step form (returning
//! NGX_AGAIN) and get `_wait` companions which retry on socket readiness
//! (Connection::drive_io), as ngx_ssl_handshake_handler() and
//! ngx_ssl_shutdown_handler() do on events.
//!
//! The OpenSSL objects are the openssl crate's. A context is configured as
//! an SslContextBuilder and built into the SslContext the connections are
//! made of when the first connection needs it (SslCtx). The SSL object of a
//! connection is the Ssl of c->ssl, driven through ngx_sys::ssl (SSL_read()
//! and the others on the socket bound with SSL_set_fd(), as in C).
//!
//! OpenSSL callbacks find the connection by the key the SSL object keeps in
//! its ex_data (SSL_CONNECTIONS, ngx_ssl_get_connection()), and the data
//! nginx keeps in the ex_data of a context (its server configuration,
//! session cache, ticket keys, OCSP configuration and staples) by the key
//! of its SslCtxData (CTX_DATA).

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::fd::AsFd;
use std::rc::{Rc, Weak};
use std::sync::OnceLock;
use std::time::Duration;

use ngx_sys::ssl as sys;
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::ssl::{NameType, Ssl, SslContext, SslContextBuilder, SslContextRef, SslMethod, SslMode, SslOptions, SslRef, SslSession, SslSessionCacheMode, SslSessionRef, SslVersion};
use openssl::stack::Stack;
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509Name, X509StoreContext, X509StoreContextRef, X509};

use crate::conf::Conf;
use crate::connection::{Connection, IoStep, NGX_ERROR_ERR, NGX_ERROR_IGNORE_ECONNRESET, NGX_ERROR_INFO};
use crate::event_openssl_cache::*;
use crate::event_openssl_stapling::{SslOcsp, SslOcspConf, SslStapling};
use crate::log::*;
use crate::rc::*;
use crate::shm::ShmZone;
use crate::shmem::rbtree::{self as rb, RbTree, ShmRbtree};
use crate::shmem::slab::SlabPool;
use crate::shmem::{queue, ShmMem};
use crate::ssl::SslConnection;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error, shm_struct};

pub use sys::{X509_V_OK, SSL_ERROR_SSL, SSL_ERROR_SYSCALL, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, SSL_ERROR_ZERO_RETURN};

pub const NGX_SSL_NAME: &str = "OpenSSL";

pub const NGX_SSL_SSLV2: u32 = 0x0002;
pub const NGX_SSL_SSLV3: u32 = 0x0004;
pub const NGX_SSL_TLSV1: u32 = 0x0008;
pub const NGX_SSL_TLSV1_1: u32 = 0x0010;
pub const NGX_SSL_TLSV1_2: u32 = 0x0020;
pub const NGX_SSL_TLSV1_3: u32 = 0x0040;

pub const NGX_SSL_DEFAULT_PROTOCOLS: u32 = NGX_SSL_TLSV1_2 | NGX_SSL_TLSV1_3;

/// NGX_CONF_BITMASK_SET
pub const NGX_CONF_BITMASK_SET: u32 = 1;

pub const NGX_SSL_BUFFER: u32 = 1;
pub const NGX_SSL_CLIENT: u32 = 2;

pub const NGX_SSL_BUFSIZE: usize = 16384;

pub const NGX_SSL_NO_SCACHE: isize = -2;
pub const NGX_SSL_NONE_SCACHE: isize = -3;
pub const NGX_SSL_NO_BUILTIN_SCACHE: isize = -4;
pub const NGX_SSL_DFLT_BUILTIN_SCACHE: isize = -5;

pub const NGX_SSL_MAX_SESSION_SIZE: usize = 8192;

const NGX_SSL_PASSWORD_BUFFER_SIZE: usize = 4096;

/// NGX_MAX_CONF_ERRSTR: the size of the ngx_ssl_error() buffer
const NGX_MAX_CONF_ERRSTR: usize = 1024;

// --- the ex_data indices (ngx_ssl_init) ---

/// ngx_ssl_connection_index: the key of the connection of an SSL object
static CONNECTION_INDEX: OnceLock<Index<Ssl, u64>> = OnceLock::new();

/// The key of the SslCtxData of a context (ngx_ssl_server_conf_index,
/// ngx_ssl_session_cache_index, ngx_ssl_ticket_keys_index,
/// ngx_ssl_ocsp_index, ngx_ssl_index and ngx_ssl_client_hello_arg_index
/// of C).
static CTX_INDEX: OnceLock<Index<SslContext, u64>> = OnceLock::new();

fn connection_index() -> Index<Ssl, u64> {
    if CONNECTION_INDEX.get().is_none() {
        // not initialized at startup (unit tests): do it now
        ngx_ssl_init(&Log::stderr(NGX_LOG_NOTICE));
    }
    *CONNECTION_INDEX.get().expect("SSL ex_data index")
}

fn ctx_index() -> Index<SslContext, u64> {
    if CTX_INDEX.get().is_none() {
        ngx_ssl_init(&Log::stderr(NGX_LOG_NOTICE));
    }
    *CTX_INDEX.get().expect("SSL_CTX ex_data index")
}

/// ngx_ssl_init: the library was initialized by openssl::init(); this
/// loads its configuration file (OPENSSL_init_ssl() with
/// OPENSSL_INIT_LOAD_CONFIG, its default) and allocates the ex_data
/// indices.
pub fn ngx_ssl_init(log: &Log) -> i64 {
    if CONNECTION_INDEX.get().is_some() && CTX_INDEX.get().is_some() {
        return NGX_OK;
    }

    sys::init_ssl();

    /*
     * OPENSSL_init_ssl() may leave errors in the error queue
     * while returning success
     */

    sys::err_clear_error();

    if CONNECTION_INDEX.get().is_none() {
        match Ssl::new_ex_index::<u64>() {
            Ok(i) => {
                let _ = CONNECTION_INDEX.set(i);
            }
            Err(e) => {
                e.put();
                ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("SSL_get_ex_new_index() failed"));
                return NGX_ERROR;
            }
        }
    }

    if CTX_INDEX.get().is_none() {
        match SslContext::new_ex_index::<u64>() {
            Ok(i) => {
                let _ = CTX_INDEX.set(i);
            }
            Err(e) => {
                e.put();
                ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("SSL_CTX_get_ex_new_index() failed"));
                return NGX_ERROR;
            }
        }
    }

    NGX_OK
}

// --- the tables of the process: connections and contexts by their keys ---

thread_local! {
    /// The connections of the SSL objects, by the key in their ex_data.
    static SSL_CONNECTIONS: RefCell<HashMap<u64, Weak<Connection>>> = RefCell::new(HashMap::new());

    /// The data of the contexts, by the key in their ex_data.
    static CTX_DATA: RefCell<HashMap<u64, Weak<SslCtxData>>> = RefCell::new(HashMap::new());

    static NEXT_KEY: Cell<u64> = const { Cell::new(1) };
}

fn next_key() -> u64 {
    NEXT_KEY.with(|k| {
        let n = k.get();
        k.set(n + 1);
        n
    })
}

/// The servername callback of a context, as ngx_ssl_client_hello_callback()
/// calls it (ngx_ssl_client_hello_arg's servername) and as the tlsext
/// servername callback: returns an SSL_TLSEXT_ERR_* code, the alert is set
/// with SSL_TLSEXT_ERR_ALERT_FATAL.
pub type ServernameFn = fn(c: &Rc<Connection>, ssl: &mut SslRef, ad: &mut i32, host: SniArg<'_>) -> i32;

/// The server name a servername callback is called with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniArg<'a> {
    /// as the tlsext servername callback: SSL_get_servername() has it
    Callback,
    /// from ngx_ssl_client_hello_callback(): the name in the ClientHello,
    /// if any (NULL data in C)
    Hello(Option<&'a [u8]>),
}

/// ngx_ssl_client_hello_arg
pub struct SslClientHelloArg {
    pub servername: ServernameFn,
}

/// The certificate callback of a context (ssl_certificate with variables):
/// 1, or 0 on errors; conf is the configuration given to ngx_ssl_create()
/// for the context (its arg in C).
pub type CertFn = fn(c: &Rc<Connection>, ssl: &mut SslRef, conf: Option<Rc<dyn Any>>) -> i32;

/// The data nginx keeps in the ex_data of a context.
pub struct SslCtxData {
    key: u64,
    /// ngx_ssl_server_conf_index: the configuration given to ngx_ssl_create()
    server_conf: RefCell<Option<Weak<dyn Any>>>,
    /// ngx_ssl_session_cache_index: the shared session cache zone
    pub session_cache: RefCell<Option<Rc<ShmZone>>>,
    /// ngx_ssl_ticket_keys_index: the session ticket keys
    ticket_keys: RefCell<Option<SslTicketKeys>>,
    /// ngx_ssl_ocsp_index: the OCSP configuration (ngx_ssl_ocsp_conf_t)
    pub ocsp_conf: RefCell<Option<Rc<SslOcspConf>>>,
    /// ssl->staple_rbtree: the stapling data of the certificates
    pub staples: RefCell<Vec<Rc<SslStapling>>>,
    /// ngx_ssl_client_hello_arg_index
    client_hello: Cell<Option<ServernameFn>>,
    /// the tlsext servername callback
    servername: Cell<Option<ServernameFn>>,
    /// the certificate callback
    cert_cb: Cell<Option<CertFn>>,
}

impl SslCtxData {
    fn new() -> Rc<SslCtxData> {
        let data = Rc::new(SslCtxData {
            key: next_key(),
            server_conf: RefCell::new(None),
            session_cache: RefCell::new(None),
            ticket_keys: RefCell::new(None),
            ocsp_conf: RefCell::new(None),
            staples: RefCell::new(Vec::new()),
            client_hello: Cell::new(None),
            servername: Cell::new(None),
            cert_cb: Cell::new(None),
        });

        CTX_DATA.with(|m| m.borrow_mut().insert(data.key, Rc::downgrade(&data)));

        data
    }
}

impl Drop for SslCtxData {
    fn drop(&mut self) {
        let key = self.key;
        let _ = CTX_DATA.try_with(|m| {
            if let Ok(mut m) = m.try_borrow_mut() {
                m.remove(&key);
            }
        });
    }
}

/// The data of a context.
pub fn ngx_ssl_ctx_data(ctx: &SslContextRef) -> Option<Rc<SslCtxData>> {
    let key = *ctx.ex_data(ctx_index())?;
    CTX_DATA.with(|m| m.borrow().get(&key).and_then(|w| w.upgrade()))
}

/// ngx_ssl_get_server_conf(ssl_ctx)
pub fn ngx_ssl_get_server_conf(ctx: &SslContextRef) -> Option<Rc<dyn Any>> {
    let data = ngx_ssl_ctx_data(ctx)?;
    let conf = data.server_conf.borrow().as_ref().and_then(|w| w.upgrade());
    conf
}

/// ngx_ssl_ticket_key_t
#[derive(Clone, Copy)]
pub struct SslTicketKey {
    pub name: [u8; 16],
    pub hmac_key: [u8; 32],
    pub aes_key: [u8; 32],
    pub expire: i64,
    pub size: u8,
    pub shared: bool,
}

impl SslTicketKey {
    fn zeroed() -> SslTicketKey {
        SslTicketKey { name: [0; 16], hmac_key: [0; 32], aes_key: [0; 32], expire: 0, size: 0, shared: false }
    }
}

/// The ticket keys array of a context; its contents are cleared when it
/// is freed (ngx_ssl_ticket_keys_cleanup).
pub struct SslTicketKeys {
    pub keys: Vec<SslTicketKey>,
}

impl Drop for SslTicketKeys {
    fn drop(&mut self) {
        for k in self.keys.iter_mut() {
            explicit_memzero(&mut k.name);
            explicit_memzero(&mut k.hmac_key);
            explicit_memzero(&mut k.aes_key);
        }
    }
}

/// ngx_explicit_memzero
pub fn explicit_memzero(buf: &mut [u8]) {
    buf.fill(0);

    // the buffer is "used" after the clearing, which can't be optimized out
    std::hint::black_box(&mut *buf);
}

/// The passwords of ssl_password_file (an ngx_array_t of ngx_str_t),
/// cleared when freed (ngx_ssl_passwords_cleanup).
#[derive(Default)]
pub struct SslPasswords(pub Vec<Vec<u8>>);

impl Drop for SslPasswords {
    fn drop(&mut self) {
        for p in self.0.iter_mut() {
            explicit_memzero(p);
        }
    }
}

/// ssl->ctx: a context being configured, then, from the first connection,
/// the built context the connections are made of (SSL_new() wants a context
/// which is not changed anymore).
pub struct SslCtx(RefCell<SslCtxState>);

enum SslCtxState {
    None,
    Builder(SslContextBuilder),
    Built(SslContext),
}

impl SslCtx {
    fn new() -> SslCtx {
        SslCtx(RefCell::new(SslCtxState::None))
    }

    /// ssl->ctx == NULL
    pub fn is_null(&self) -> bool {
        matches!(*self.0.borrow(), SslCtxState::None)
    }

    /// The context being configured; None without a context, or once the
    /// connections use it.
    pub fn builder_mut(&mut self) -> Option<&mut SslContextBuilder> {
        match self.0.get_mut() {
            SslCtxState::Builder(b) => Some(b),
            _ => None,
        }
    }

    /// The context of the connections (a reference): the configuration of
    /// the context is over at the first call.
    pub fn get(&self) -> Option<SslContext> {
        let mut st = self.0.borrow_mut();

        let ctx = match std::mem::replace(&mut *st, SslCtxState::None) {
            SslCtxState::None => return None,
            SslCtxState::Builder(b) => b.build(),
            SslCtxState::Built(c) => c,
        };

        *st = SslCtxState::Built(ctx.clone());

        Some(ctx)
    }
}

/// ngx_ssl_t
pub struct NgxSsl {
    /// the first field, dropped first: the remove session callback, which
    /// the internal session cache calls when the context is freed, finds
    /// its data
    pub ctx: SslCtx,
    pub log: Log,
    pub buffer_size: usize,

    /// ssl->certs: the certificates of the context
    pub certs: Vec<X509>,
    /// the names of the certificates (the X509 ex_data at
    /// ngx_ssl_certificate_name_index of C)
    pub cert_names: Vec<Vec<u8>>,

    /// the data of the ex_data of the context
    pub data: Rc<SslCtxData>,

    /// SSL_CTX_get_client_CA_list(): the list set by
    /// ngx_ssl_client_certificate()
    client_ca: Option<Vec<X509Name>>,

    /// SSL_CTX_has_client_custom_ext(): the QUIC transport parameters
    /// extension was added (ngx_quic_compat_ext_init())
    pub quic_compat_ext: bool,
}

impl NgxSsl {
    pub fn new(log: Log) -> NgxSsl {
        NgxSsl {
            ctx: SslCtx::new(),
            log,
            buffer_size: NGX_SSL_BUFSIZE,
            certs: Vec::new(),
            cert_names: Vec::new(),
            data: SslCtxData::new(),
            client_ca: None,
            quic_compat_ext: false,
        }
    }
}

/// The state of ngx_ssl_connection_t beyond the fields of SslConnection
/// (a connection created by ngx_ssl_create_connection()).
pub struct SslConnState {
    /// created by ngx_ssl_create_connection(): the I/O follows
    /// ngx_ssl_recv() / ngx_ssl_write()
    pub ngx: Cell<bool>,
    /// c->ssl->session_ctx
    pub session_ctx: RefCell<Option<SslContext>>,
    /// the data of the session context
    pub session_data: RefCell<Option<Rc<SslCtxData>>>,
    /// the key of the connection in SSL_CONNECTIONS (the SSL's ex_data)
    pub id: Cell<u64>,
    /// c->ssl->last: the result of the last ngx_ssl_handle_recv()
    pub last: Cell<i64>,
    /// the last ngx_ssl_recv() ended with SSL_ERROR_WANT_READ, which left
    /// c->read->ready = 0: OpenSSL holds no records, so the next read waits
    /// for a read event first
    pub recv_drained: Cell<bool>,
    /// NGX_SSL_BUFFER
    pub buffer: Cell<bool>,
    /// the session being saved (ngx_ssl_new_client_session())
    pub session: RefCell<Option<SslSession>>,
    /// c->ssl->save_session
    pub save_session: RefCell<Option<Rc<dyn Fn(&Connection)>>>,
    pub handshake_rejected: Cell<bool>,
    pub renegotiation: Cell<bool>,
    pub handshake_buffer_set: Cell<bool>,
    pub session_timeout_set: Cell<bool>,
    pub try_early_data: Cell<bool>,
    pub in_early: Cell<bool>,
    pub in_ocsp: Cell<bool>,
    pub early_preread: Cell<bool>,
    pub early_buf: Cell<u8>,
    pub write_blocked: Cell<bool>,
    pub sni_accepted: Cell<bool>,
    pub sendfile: Cell<bool>,
    /// the readiness the last NGX_AGAIN of ngx_ssl_handshake() or
    /// ngx_ssl_shutdown() waits for (1: read, 2: write)
    pub want: Cell<u8>,
    /// ngx_ssl_ocsp_t of the connection
    pub ocsp: RefCell<Option<Rc<SslOcsp>>>,
    /// c->ssl->buf
    pub buf: RefCell<SslBuf>,
}

impl Default for SslConnState {
    fn default() -> Self {
        SslConnState {
            ngx: Cell::new(false),
            session_ctx: RefCell::new(None),
            session_data: RefCell::new(None),
            id: Cell::new(0),
            last: Cell::new(NGX_OK),
            recv_drained: Cell::new(false),
            buffer: Cell::new(false),
            session: RefCell::new(None),
            save_session: RefCell::new(None),
            handshake_rejected: Cell::new(false),
            renegotiation: Cell::new(false),
            handshake_buffer_set: Cell::new(false),
            session_timeout_set: Cell::new(false),
            try_early_data: Cell::new(false),
            in_early: Cell::new(false),
            in_ocsp: Cell::new(false),
            early_preread: Cell::new(false),
            early_buf: Cell::new(0),
            write_blocked: Cell::new(false),
            sni_accepted: Cell::new(false),
            sendfile: Cell::new(false),
            want: Cell::new(0),
            ocsp: RefCell::new(None),
            buf: RefCell::new(SslBuf::default()),
        }
    }
}

impl Drop for SslConnState {
    fn drop(&mut self) {
        let id = self.id.get();

        if id == 0 {
            return;
        }

        let _ = SSL_CONNECTIONS.try_with(|m| {
            if let Ok(mut m) = m.try_borrow_mut() {
                m.remove(&id);
            }
        });
    }
}

/// The error of an SSL I/O function which has been logged already with
/// ngx_ssl_connection_error(), as the C functions do: callers must not log
/// it again.
#[derive(Debug)]
pub struct SslErrorLogged;

impl std::fmt::Display for SslErrorLogged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SSL error")
    }
}

impl std::error::Error for SslErrorLogged {}

pub fn ssl_error_logged() -> io::Error {
    io::Error::new(io::ErrorKind::Other, SslErrorLogged)
}

/// The error was logged by the SSL layer.
pub fn is_ssl_error_logged(e: &io::Error) -> bool {
    e.get_ref().map(|i| i.is::<SslErrorLogged>()).unwrap_or(false)
}

// --- helpers ---

fn cstring(v: &[u8]) -> CString {
    // configuration strings have no NUL bytes; cut at one if there is
    let n = v.iter().position(|&c| c == 0).unwrap_or(v.len());
    CString::new(&v[..n]).unwrap_or_default()
}

/// ngx_hex_dump (lowercase)
fn hex_dump(dst: &mut Vec<u8>, src: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in src {
        dst.push(HEX[(b >> 4) as usize]);
        dst.push(HEX[(b & 0xf) as usize]);
    }
}

/// c->ssl
pub fn ngx_ssl_sc(c: &Connection) -> Option<Rc<SslConnection>> {
    c.ssl.borrow().clone()
}

/// The SSL object of c->ssl, for a read: c->ssl->connection of the getters
/// (None without SSL).
pub fn ngx_ssl_with<R>(c: &Connection, f: impl FnOnce(&SslRef) -> R) -> Option<R> {
    let sc = c.ssl.borrow().clone()?;
    sc.with(f)
}

/// The key of the connection of an SSL object (0: none).
pub fn ngx_ssl_connection_id(ssl: &SslRef) -> u64 {
    ssl.ex_data(connection_index()).copied().unwrap_or(0)
}

/// ngx_ssl_get_connection(ssl_conn)
pub fn ngx_ssl_get_connection(ssl: &SslRef) -> Option<Rc<Connection>> {
    let id = *ssl.ex_data(connection_index())?;
    SSL_CONNECTIONS.with(|m| m.borrow().get(&id).and_then(|w| w.upgrade()))
}

/// ngx_ssl_verify_error_optional()
pub fn ngx_ssl_verify_error_optional(n: i64) -> bool {
    n == sys::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        || n == sys::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        || n == sys::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        || n == sys::X509_V_ERR_CERT_UNTRUSTED
        || n == sys::X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
}

/// An openssl crate call failed: its errors go back to the queue, which
/// ngx_ssl_error() prints, as after the failed OpenSSL call in C.
fn put(e: ErrorStack) {
    e.put();
}

/// SSL_CTX_set_options()
fn ctx_set_options(ctx: &mut SslContextBuilder, op: u64) {
    ctx.set_options(SslOptions::from_bits_retain(op as _));
}

/// SSL_CTX_clear_options()
fn ctx_clear_options(ctx: &mut SslContextBuilder, op: u64) {
    ctx.clear_options(SslOptions::from_bits_retain(op as _));
}

/// SSL_CTX_set_options() of a context being configured (e.g.
/// SSL_OP_NO_TICKET for "ssl_session_tickets off")
pub fn ngx_ssl_set_options(ssl: &mut NgxSsl, op: u64) {
    if let Some(ctx) = ssl.ctx.builder_mut() {
        ctx_set_options(ctx, op);
    }
}

// --- contexts ---

/// The handlers of the callbacks of the contexts (ngx_sys::ssl trampolines).
struct InfoCb;
struct VerifyCb;
struct ClientHelloCb;
struct ServernameCb;
struct CertCb;
struct TicketKeyCb;
struct GetSessionCb;

impl sys::InfoCallback for InfoCb {
    fn info(ssl: &mut SslRef, where_: i32, ret: i32) {
        ngx_ssl_info_callback(ssl, where_, ret);
    }
}

impl sys::VerifyCallback for VerifyCb {
    fn verify(ok: bool, ctx: &mut X509StoreContextRef) -> bool {
        ngx_ssl_verify_callback(ok, ctx)
    }
}

impl sys::ClientHelloCallback for ClientHelloCb {
    fn client_hello(ssl: &mut SslRef, alert: &mut i32) -> i32 {
        ngx_ssl_client_hello_callback(ssl, alert)
    }
}

impl sys::ServernameCallback for ServernameCb {
    /// the servername function of the context of the connection (the
    /// one the callback is called for)
    fn servername(ssl: &mut SslRef, alert: &mut i32) -> i32 {
        let f = match ngx_ssl_ctx_data(ssl.ssl_context()).and_then(|d| d.servername.get()) {
            Some(f) => f,
            None => return sys::SSL_TLSEXT_ERR_OK,
        };

        let c = match ngx_ssl_get_connection(ssl) {
            Some(c) => c,
            None => return sys::SSL_TLSEXT_ERR_OK,
        };

        f(&c, ssl, alert, SniArg::Callback)
    }
}

impl sys::CertCallback for CertCb {
    /// the certificate function and the configuration of the context of
    /// the connection: OpenSSL calls the callback (with its arg) of the
    /// certificates of that context
    fn cert(ssl: &mut SslRef) -> i32 {
        let data = match ngx_ssl_ctx_data(ssl.ssl_context()) {
            Some(d) => d,
            None => return 0,
        };

        let f = match data.cert_cb.get() {
            Some(f) => f,
            None => return 0,
        };

        let conf = data.server_conf.borrow().as_ref().and_then(|w| w.upgrade());

        let c = match ngx_ssl_get_connection(ssl) {
            Some(c) => c,
            None => return 0,
        };

        f(&c, ssl, conf)
    }
}

impl sys::TicketKeyCallback for TicketKeyCb {
    fn ticket_key(ssl: &mut SslRef, keys: &mut sys::TicketKeyCtx<'_>, enc: bool) -> i32 {
        ngx_ssl_ticket_key_callback(ssl, keys, enc)
    }
}

impl sys::GetSessionCallback for GetSessionCb {
    fn get_session(ssl: &mut SslRef, id: &[u8]) -> Option<Vec<u8>> {
        ngx_ssl_get_cached_session(ssl, id)
    }
}

/// ngx_ssl_create: `data` is the configuration of the server the context
/// is for (ngx_ssl_get_server_conf())
pub fn ngx_ssl_create(ssl: &mut NgxSsl, protocols: u32, data: Option<Rc<dyn Any>>) -> i64 {
    let mut ctx = match SslContextBuilder::new(SslMethod::tls()) {
        Ok(b) => b,
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_new() failed"));
            return NGX_ERROR;
        }
    };

    // SSL_CTX_set_ex_data(ctx, ngx_ssl_server_conf_index, data) and
    // SSL_CTX_set_ex_data(ctx, ngx_ssl_index, ssl)

    ctx.set_ex_data(ctx_index(), ssl.data.key);

    *ssl.data.server_conf.borrow_mut() = data.map(|d| Rc::downgrade(&d));

    ssl.data.staples.borrow_mut().clear();

    ssl.buffer_size = NGX_SSL_BUFSIZE;

    /* client side options */

    ctx_set_options(&mut ctx, sys::SSL_OP_MICROSOFT_SESS_ID_BUG);
    ctx_set_options(&mut ctx, sys::SSL_OP_NETSCAPE_CHALLENGE_BUG);

    /* server side options */

    ctx_set_options(&mut ctx, sys::SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    ctx_set_options(&mut ctx, sys::SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
    ctx_set_options(&mut ctx, sys::SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    ctx_set_options(&mut ctx, sys::SSL_OP_TLS_D5_BUG);
    ctx_set_options(&mut ctx, sys::SSL_OP_TLS_BLOCK_PADDING_BUG);
    ctx_set_options(&mut ctx, sys::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

    ctx_set_options(&mut ctx, sys::SSL_OP_SINGLE_DH_USE);

    ctx_clear_options(&mut ctx, sys::SSL_OP_NO_SSLv2 | sys::SSL_OP_NO_SSLv3 | sys::SSL_OP_NO_TLSv1);

    if protocols & NGX_SSL_SSLV2 == 0 {
        ctx_set_options(&mut ctx, sys::SSL_OP_NO_SSLv2);
    }
    if protocols & NGX_SSL_SSLV3 == 0 {
        ctx_set_options(&mut ctx, sys::SSL_OP_NO_SSLv3);
    }
    if protocols & NGX_SSL_TLSV1 == 0 {
        ctx_set_options(&mut ctx, sys::SSL_OP_NO_TLSv1);
    }

    ctx_clear_options(&mut ctx, sys::SSL_OP_NO_TLSv1_1);
    if protocols & NGX_SSL_TLSV1_1 == 0 {
        ctx_set_options(&mut ctx, sys::SSL_OP_NO_TLSv1_1);
    }

    ctx_clear_options(&mut ctx, sys::SSL_OP_NO_TLSv1_2);
    if protocols & NGX_SSL_TLSV1_2 == 0 {
        ctx_set_options(&mut ctx, sys::SSL_OP_NO_TLSv1_2);
    }

    ctx_clear_options(&mut ctx, sys::SSL_OP_NO_TLSv1_3);
    if protocols & NGX_SSL_TLSV1_3 == 0 {
        ctx_set_options(&mut ctx, sys::SSL_OP_NO_TLSv1_3);
    }

    let _ = ctx.set_min_proto_version(None);
    let _ = ctx.set_max_proto_version(Some(SslVersion::TLS1_2));

    let _ = ctx.set_min_proto_version(None);
    let _ = ctx.set_max_proto_version(Some(SslVersion::TLS1_3));

    ctx_set_options(&mut ctx, sys::SSL_OP_NO_COMPRESSION);

    ctx_set_options(&mut ctx, sys::SSL_OP_NO_ANTI_REPLAY);

    ctx_set_options(&mut ctx, sys::SSL_OP_IGNORE_UNEXPECTED_EOF);

    ctx.set_mode(SslMode::from_bits_retain(sys::SSL_MODE_RELEASE_BUFFERS as _));

    ctx.set_mode(SslMode::from_bits_retain(sys::SSL_MODE_NO_AUTO_CHAIN as _));

    ctx.set_read_ahead(true);

    sys::ctx_set_info_callback::<InfoCb>(&mut ctx);

    ssl.ctx = SslCtx(RefCell::new(SslCtxState::Builder(ctx)));

    NGX_OK
}

/// ngx_ssl_certificates
pub fn ngx_ssl_certificates(cf: &mut Conf, ssl: &mut NgxSsl, certs: &mut [Vec<u8>], keys: &mut [Vec<u8>], passwords: Option<&Rc<SslPasswords>>) -> i64 {
    for i in 0..certs.len() {
        if ngx_ssl_certificate(cf, ssl, &mut certs[i], &mut keys[i], passwords) != NGX_OK {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// The certificates of a chain after the first one, as a stack of
/// references (sk_X509_shift() leaving the rest of the chain).
fn chain_rest(chain: &[X509]) -> Option<Stack<X509>> {
    let mut rest = Stack::new().ok()?;

    for x in chain.iter().skip(1) {
        rest.push(x.clone()).ok()?;
    }

    Some(rest)
}

/// The key does not match the certificate (the last error of the queue is
/// X509_R_KEY_VALUES_MISMATCH), as ngx_ssl_certificate() checks it.
fn key_values_mismatch(e: &ErrorStack) -> bool {
    match e.errors().last() {
        Some(err) => {
            let n = err.code() as u64;
            sys::err_get_lib(n) == sys::ERR_LIB_X509 && sys::err_get_reason(n) == sys::X509_R_KEY_VALUES_MISMATCH
        }
        None => false,
    }
}

/// ngx_ssl_certificate
pub fn ngx_ssl_certificate(cf: &mut Conf, ssl: &mut NgxSsl, cert: &mut Vec<u8>, key: &mut Vec<u8>, passwords: Option<&Rc<SslPasswords>>) -> i64 {
    let mut mask = 0;
    let mut elm: Option<usize> = None;

    let log = ssl.log.clone();

    loop {
        // retry:

        let mut err: Option<&'static str> = None;

        let chain = match ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CERT | mask, &mut err, cert, None) {
            Some(SslObject::Certs(chain)) if !chain.is_empty() => chain,
            _ => {
                if let Some(err) = err {
                    ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("cannot load certificate \"{}\": {}", B(cert), err));
                }

                return NGX_ERROR;
            }
        };

        let x509 = chain[0].clone();

        let ctx = match ssl.ctx.builder_mut() {
            Some(ctx) => ctx,
            None => return NGX_ERROR,
        };

        if let Err(e) = ctx.set_certificate(&x509) {
            put(e);
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CTX_use_certificate(\"{}\") failed", B(cert)));
            return NGX_ERROR;
        }

        /*
         * Note that x509 is kept in ssl->certs: we need to preserve all
         * certificates to be able to iterate all of them through
         * ssl->certs, while OpenSSL can free a certificate if it is
         * replaced with another certificate of the same type.
         */

        let rest = match chain_rest(&chain) {
            Some(r) => r,
            None => return NGX_ERROR,
        };

        if sys::ctx_set0_chain(ctx, rest).is_err() {
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CTX_set0_chain(\"{}\") failed", B(cert)));
            return NGX_ERROR;
        }

        match elm {
            None => {
                ssl.certs.push(x509);
                ssl.cert_names.push(cert.clone());
                elm = Some(ssl.certs.len() - 1);
            }
            Some(i) => {
                ssl.certs[i] = x509;
                ssl.cert_names[i] = cert.clone();
            }
        }

        let mut err: Option<&'static str> = None;

        let pkey = match ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_PKEY | mask, &mut err, key, passwords) {
            Some(SslObject::Pkey(p)) => p,
            _ => {
                if let Some(err) = err {
                    ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("cannot load certificate key \"{}\": {}", B(key), err));
                }

                return NGX_ERROR;
            }
        };

        let ctx = match ssl.ctx.builder_mut() {
            Some(ctx) => ctx,
            None => return NGX_ERROR,
        };

        if let Err(e) = ctx.set_private_key(&pkey) {
            /* there can be mismatched pairs on uneven cache update */

            if key_values_mismatch(&e) && mask == 0 {
                // ERR_clear_error(): the errors were taken
                mask = NGX_SSL_CACHE_INVALIDATE;
                continue;
            }

            put(e);
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CTX_use_PrivateKey(\"{}\") failed", B(key)));
            return NGX_ERROR;
        }

        return NGX_OK;
    }
}

/// ngx_ssl_connection_certificate: the certificate and key of a
/// connection (ssl_certificate with variables: of the upstream
/// connections, before the handshake)
pub fn ngx_ssl_connection_certificate(c: &Connection, cert: &mut Vec<u8>, key: &mut Vec<u8>, cache: Option<&Rc<RefCell<SslCache>>>, passwords: Option<&Rc<SslPasswords>>) -> i64 {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return NGX_ERROR,
    };

    sc.with_mut(|ssl| ngx_ssl_connection_certificate_ssl(c, ssl, cert, key, cache, passwords)).unwrap_or(NGX_ERROR)
}

/// ngx_ssl_connection_certificate on the SSL object given (from the
/// certificate callback, which has it)
pub fn ngx_ssl_connection_certificate_ssl(c: &Connection, ssl: &mut SslRef, cert: &mut Vec<u8>, key: &mut Vec<u8>, cache: Option<&Rc<RefCell<SslCache>>>, passwords: Option<&Rc<SslPasswords>>) -> i64 {
    let mut mask = 0;

    loop {
        // retry:

        let mut err: Option<&'static str> = None;

        let chain = match ngx_ssl_cache_connection_fetch(cache, &c.log, NGX_SSL_CACHE_CERT | mask, &mut err, cert, None) {
            Some(SslObject::Certs(chain)) if !chain.is_empty() => chain,
            _ => {
                if let Some(err) = err {
                    ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("cannot load certificate \"{}\": {}", B(cert), err));
                }

                return NGX_ERROR;
            }
        };

        if let Err(e) = ssl.set_certificate(&chain[0]) {
            put(e);
            ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("SSL_use_certificate(\"{}\") failed", B(cert)));
            return NGX_ERROR;
        }

        /*
         * SSL_set0_chain() is only available in OpenSSL 1.0.2+,
         * but this function is only called via certificate callback,
         * which is only available in OpenSSL 1.0.2+ as well
         */

        let rest = match chain_rest(&chain) {
            Some(r) => r,
            None => return NGX_ERROR,
        };

        if sys::set0_chain(ssl, rest).is_err() {
            ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("SSL_set0_chain(\"{}\") failed", B(cert)));
            return NGX_ERROR;
        }

        let mut err: Option<&'static str> = None;

        let pkey = match ngx_ssl_cache_connection_fetch(cache, &c.log, NGX_SSL_CACHE_PKEY | mask, &mut err, key, passwords) {
            Some(SslObject::Pkey(p)) => p,
            _ => {
                if let Some(err) = err {
                    ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("cannot load certificate key \"{}\": {}", B(key), err));
                }

                return NGX_ERROR;
            }
        };

        if let Err(e) = ssl.set_private_key(&pkey) {
            /* there can be mismatched pairs on uneven cache update */

            if key_values_mismatch(&e) && mask == 0 {
                mask = NGX_SSL_CACHE_INVALIDATE;
                continue;
            }

            put(e);
            ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("SSL_use_PrivateKey(\"{}\") failed", B(key)));
            return NGX_ERROR;
        }

        return NGX_OK;
    }
}

/// ngx_ssl_certificate_compression: neither SSL_CTX_compress_certs()
/// (OpenSSL 3.2+) nor the BoringSSL zlib callback are available with this
/// OpenSSL
pub fn ngx_ssl_certificate_compression(_cf: &mut Conf, ssl: &mut NgxSsl, enable: bool) -> i64 {
    if !enable {
        return NGX_OK;
    }

    ngx_log_error!(NGX_LOG_WARN, ssl.log, None, "\"ssl_certificate_compression\" is not supported on this platform, ignored");

    NGX_OK
}

/// ngx_ssl_ciphers
pub fn ngx_ssl_ciphers(_cf: &mut Conf, ssl: &mut NgxSsl, ciphers: &[u8], prefer_server_ciphers: bool) -> i64 {
    let log = ssl.log.clone();

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    if !sys::ctx_set_cipher_list(ctx, &cstring(ciphers)) {
        ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CTX_set_cipher_list(\"{}\") failed", B(ciphers)));
        return NGX_ERROR;
    }

    if prefer_server_ciphers {
        ctx_set_options(ctx, sys::SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    NGX_OK
}

/// X509_NAME_cmp() as an ordering (ngx_ssl_cmp_x509_name)
fn cmp_x509_name(a: &X509Name, b: &X509Name) -> std::cmp::Ordering {
    a.try_cmp(b).unwrap_or(std::cmp::Ordering::Less)
}

/// ngx_ssl_client_certificate
pub fn ngx_ssl_client_certificate(cf: &mut Conf, ssl: &mut NgxSsl, cert: &mut Vec<u8>, depth: i64) -> i64 {
    let log = ssl.log.clone();

    {
        let ctx = match ssl.ctx.builder_mut() {
            Some(ctx) => ctx,
            None => return NGX_ERROR,
        };

        sys::ctx_set_verify::<VerifyCb>(ctx, sys::SSL_VERIFY_PEER);

        ctx.set_verify_depth(depth as u32);
    }

    if cert.is_empty() {
        return NGX_OK;
    }

    // sk_X509_NAME_new(ngx_ssl_cmp_x509_name): the stack is sorted by each
    // sk_X509_NAME_find(), names pushed after a find go at its end
    let mut list: Vec<X509Name> = Vec::new();

    let mut err: Option<&'static str> = None;

    let chain = match ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CA, &mut err, cert, None) {
        Some(SslObject::Certs(chain)) => chain,
        _ => {
            if let Some(err) = err {
                ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("cannot load certificate \"{}\": {}", B(cert), err));
            }

            return NGX_ERROR;
        }
    };

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    for x509 in chain.iter() {
        if let Err(e) = ctx.cert_store_mut().add_cert(x509.clone()) {
            if ngx_ssl_cert_already_in_hash() {
                continue;
            }

            put(e);
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("X509_STORE_add_cert(\"{}\") failed", B(cert)));
            return NGX_ERROR;
        }

        let name = match x509.subject_name().to_owned() {
            Ok(n) => n,
            Err(_) => return NGX_ERROR,
        };

        if list.len() > 1 {
            list.sort_by(cmp_x509_name);
        }

        if list.iter().any(|n| cmp_x509_name(n, &name) == std::cmp::Ordering::Equal) {
            continue;
        }

        list.push(name);
    }

    let mut stack = match Stack::<X509Name>::new() {
        Ok(s) => s,
        Err(_) => return NGX_ERROR,
    };

    let mut copy = Vec::with_capacity(list.len());

    for name in list {
        match name.to_owned() {
            Ok(n) => copy.push(n),
            Err(_) => return NGX_ERROR,
        }

        if stack.push(name).is_err() {
            return NGX_ERROR;
        }
    }

    ctx.set_client_ca_list(stack);

    ssl.client_ca = Some(copy);

    NGX_OK
}

/// ngx_ssl_trusted_certificate
pub fn ngx_ssl_trusted_certificate(cf: &mut Conf, ssl: &mut NgxSsl, cert: &mut Vec<u8>, depth: i64) -> i64 {
    let log = ssl.log.clone();

    {
        let ctx = match ssl.ctx.builder_mut() {
            Some(ctx) => ctx,
            None => return NGX_ERROR,
        };

        let mode = sys::ctx_verify_mode(ctx);

        sys::ctx_set_verify::<VerifyCb>(ctx, mode);

        ctx.set_verify_depth(depth as u32);
    }

    if cert.is_empty() {
        return NGX_OK;
    }

    let mut err: Option<&'static str> = None;

    let chain = match ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CA, &mut err, cert, None) {
        Some(SslObject::Certs(chain)) => chain,
        _ => {
            if let Some(err) = err {
                ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("cannot load certificate \"{}\": {}", B(cert), err));
            }

            return NGX_ERROR;
        }
    };

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    for x509 in chain.iter() {
        if let Err(e) = ctx.cert_store_mut().add_cert(x509.clone()) {
            if ngx_ssl_cert_already_in_hash() {
                continue;
            }

            put(e);
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("X509_STORE_add_cert(\"{}\") failed", B(cert)));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_crl
pub fn ngx_ssl_crl(cf: &mut Conf, ssl: &mut NgxSsl, crl: &mut Vec<u8>) -> i64 {
    if crl.is_empty() {
        return NGX_OK;
    }

    let log = ssl.log.clone();

    let mut err: Option<&'static str> = None;

    let chain = match ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CRL, &mut err, crl, None) {
        Some(SslObject::Crls(chain)) => chain,
        _ => {
            if let Some(err) = err {
                ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("cannot load CRL \"{}\": {}", B(crl), err));
            }

            return NGX_ERROR;
        }
    };

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    for x509 in chain.iter() {
        if !sys::store_add_crl(ctx.cert_store_mut(), x509) {
            if ngx_ssl_cert_already_in_hash() {
                continue;
            }

            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("X509_STORE_add_crl(\"{}\") failed", B(crl)));
            return NGX_ERROR;
        }
    }

    let _ = ctx.cert_store_mut().set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL);

    NGX_OK
}

/// ngx_ssl_cert_already_in_hash: OpenSSL 1.1.0i+ ignores duplicates
fn ngx_ssl_cert_already_in_hash() -> bool {
    false
}

/// ngx_ssl_verify_callback: logs the verification at debug_event; the
/// verification goes on (its result is checked after the handshake)
fn ngx_ssl_verify_callback(ok: bool, x509_store: &mut X509StoreContextRef) -> bool {
    let ssl_conn = match X509StoreContext::ssl_idx().ok().and_then(|i| x509_store.ex_data(i)) {
        Some(s) => s,
        None => return true,
    };

    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return true,
    };

    if !c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
        return true;
    }

    let err = x509_store.error().as_raw();
    let depth = x509_store.error_depth();

    let (subject, issuer) = match x509_store.current_cert() {
        Some(cert) => {
            let subject = sys::x509_name_oneline(cert.subject_name());
            if subject.is_none() {
                ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_NAME_oneline() failed"));
            }

            let issuer = sys::x509_name_oneline(cert.issuer_name());
            if issuer.is_none() {
                ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_NAME_oneline() failed"));
            }

            (subject, issuer)
        }
        None => (None, None),
    };

    ngx_log_debug!(
        NGX_LOG_DEBUG_EVENT,
        c.log,
        "verify:{}, error:{}, depth:{}, subject:\"{}\", issuer:\"{}\"",
        ok as i32,
        err,
        depth,
        B(subject.as_deref().unwrap_or(b"(none)")),
        B(issuer.as_deref().unwrap_or(b"(none)"))
    );

    true
}

/// ngx_ssl_info_callback
fn ngx_ssl_info_callback(ssl_conn: &mut SslRef, where_: i32, _ret: i32) {
    // SSL_OP_NO_RENEGOTIATION is available: no renegotiation detection

    if (where_ & sys::SSL_CB_ACCEPT_LOOP) == sys::SSL_CB_ACCEPT_LOOP && ssl_conn.version2() == Some(SslVersion::TLS1_3) {
        /*
         * OpenSSL with TLSv1.3 updates the session creation time on
         * session resumption and keeps the session timeout unmodified,
         * making it possible to maintain the session forever, bypassing
         * client certificate expiration and revocation.  To make sure
         * session timeouts are actually used, we now update the session
         * creation time and reduce the session timeout accordingly.
         */

        if let Some(c) = ngx_ssl_get_connection(ssl_conn) {
            if let Some(sc) = c.ssl.borrow().clone() {
                let sess = ssl_conn.session().map(|s| (s.time() as i64, s.timeout()));

                if let (false, Some((time, timeout))) = (sc.state.session_timeout_set.get(), sess) {
                    sc.state.session_timeout_set.set(true);

                    let now = crate::times::time();
                    let conf_timeout = sc.state.session_ctx.borrow().as_ref().map(|ctx| sys::ctx_timeout(ctx)).unwrap_or(0);

                    let timeout = timeout.min(conf_timeout);

                    if now - time >= timeout {
                        sys::session_clear_id_context(ssl_conn);
                    } else {
                        sys::session_set_time(ssl_conn, now);
                        sys::session_set_timeout(ssl_conn, timeout - (now - time));
                    }
                }
            }
        }
    }

    if (where_ & sys::SSL_CB_ACCEPT_LOOP) == sys::SSL_CB_ACCEPT_LOOP {
        if let Some(c) = ngx_ssl_get_connection(ssl_conn) {
            if let Some(sc) = c.ssl.borrow().clone() {
                if !sc.state.handshake_buffer_set.get() {
                    /*
                     * By default OpenSSL uses 4k buffer during a handshake,
                     * which is too low for long certificate chains and might
                     * result in extra round-trips.
                     *
                     * To adjust a buffer size we detect that buffering was added
                     * to write side of the connection by comparing rbio and wbio.
                     * If they are different, we assume that it's due to buffering
                     * added to wbio, and set buffer size.
                     */

                    if sys::set_handshake_buffer_size(ssl_conn, NGX_SSL_BUFSIZE as i64) {
                        sc.state.handshake_buffer_set.set(true);
                    }
                }
            }
        }
    }
}

/// ngx_ssl_read_password_file
pub fn ngx_ssl_read_password_file(cf: &mut Conf, file: &[u8]) -> Option<Rc<SslPasswords>> {
    let file = cf.full_name(file, true);

    let mut passwords = SslPasswords::default();

    let fd = match crate::os::open(&file, libc::O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(e) => {
            cf.log_error(NGX_LOG_EMERG, Some(e), format_args!("open() \"{}\" failed", B(&file)));
            return None;
        }
    };

    let mut buf = [0u8; NGX_SSL_PASSWORD_BUFFER_SIZE + 1];
    let mut len = 0usize;
    let mut last = 0usize;

    let result = 'cleanup: loop {
        let n = match crate::os::read(fd, &mut buf[last..last + (NGX_SSL_PASSWORD_BUFFER_SIZE - len)]) {
            Ok(n) => n,
            Err(e) => {
                cf.log_error(NGX_LOG_EMERG, Some(e), format_args!("read() \"{}\" failed", B(&file)));
                break 'cleanup false;
            }
        };

        let mut end = last + n;

        if len != 0 && n == 0 {
            buf[end] = b'\n';
            end += 1;
        }

        let mut p = 0usize;

        loop {
            match buf[last..end].iter().position(|&ch| ch == b'\n') {
                None => break,
                Some(i) => last += i,
            }

            let mut l = last - p;
            last += 1;

            if l != 0 && buf[p + l - 1] == b'\r' {
                l -= 1;
            }

            if l != 0 {
                passwords.0.push(buf[p..p + l].to_vec());
            }

            p = last;
        }

        len = end - p;

        if len == NGX_SSL_PASSWORD_BUFFER_SIZE {
            cf.log_error(NGX_LOG_EMERG, None, format_args!("too long line in \"{}\"", B(&file)));
            break 'cleanup false;
        }

        buf.copy_within(p..p + len, 0);
        last = len;

        if n == 0 {
            break 'cleanup true;
        }
    };

    if let Err(e) = crate::os::close_fd(fd) {
        cf.log_error(NGX_LOG_ALERT, Some(e), format_args!("close() \"{}\" failed", B(&file)));
    }

    explicit_memzero(&mut buf);

    if !result {
        return None;
    }

    if passwords.0.is_empty() {
        passwords.0.push(Vec::new());
    }

    Some(Rc::new(passwords))
}

/// ngx_ssl_preserve_passwords: without passwords an empty array is used,
/// to make sure OpenSSL's default password callback won't block on reading
/// from stdin
pub fn ngx_ssl_preserve_passwords(_cf: &mut Conf, passwords: Option<&Rc<SslPasswords>>) -> Rc<SslPasswords> {
    match passwords {
        None => Rc::new(SslPasswords::default()),
        Some(p) => Rc::new(SslPasswords(p.0.clone())),
    }
}

/// ngx_ssl_dhparam
pub fn ngx_ssl_dhparam(cf: &mut Conf, ssl: &mut NgxSsl, file: &mut Vec<u8>) -> i64 {
    if file.is_empty() {
        return NGX_OK;
    }

    *file = cf.full_name(file, true);

    let log = ssl.log.clone();

    let mut bio = match sys::Bio::new_file(&cstring(file), c"r") {
        Some(b) => b,
        None => {
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("BIO_new_file(\"{}\") failed", B(file)));
            return NGX_ERROR;
        }
    };

    let dh = match sys::pem_read_dhparams(&mut bio) {
        Some(dh) => dh,
        None => {
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("PEM_read_bio_DHparams(\"{}\") failed", B(file)));
            return NGX_ERROR;
        }
    };

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    if let Err(e) = ctx.set_tmp_dh(&dh) {
        put(e);
        ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CTX_set_tmp_dh(\"{}\") failed", B(file)));
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_ssl_ech_files: ECH (SSL_OP_ECH_GREASE) is not available with this
/// OpenSSL
pub fn ngx_ssl_ech_files(_cf: &mut Conf, ssl: &mut NgxSsl, filenames: Option<&Vec<Vec<u8>>>) -> i64 {
    if filenames.is_some() {
        ngx_log_error!(NGX_LOG_WARN, ssl.log, None, "\"ssl_ech_file\" is not supported on this platform, ignored");
    }

    NGX_OK
}

/// ngx_ssl_ecdh_curve
pub fn ngx_ssl_ecdh_curve(_cf: &mut Conf, ssl: &mut NgxSsl, name: &[u8]) -> i64 {
    /*
     * OpenSSL 1.0.2+ allows configuring a curve list instead of a single
     * curve previously supported.  By default an internal list is used,
     * with prime256v1 being preferred by server in OpenSSL 1.0.2b+
     * and X25519 in OpenSSL 1.1.0+.
     *
     * By default a curve preferred by the client will be used for
     * key exchange.  The SSL_OP_CIPHER_SERVER_PREFERENCE option can
     * be used to prefer server curves instead, similar to what it
     * does for ciphers.
     */

    let log = ssl.log.clone();

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    ctx_set_options(ctx, sys::SSL_OP_SINGLE_ECDH_USE);

    if name == b"auto" {
        return NGX_OK;
    }

    if !sys::ctx_set1_curves_list(ctx, &cstring(name)) {
        ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CTX_set1_curves_list(\"{}\") failed", B(name)));
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_ssl_early_data
pub fn ngx_ssl_early_data(_cf: &mut Conf, ssl: &mut NgxSsl, enable: bool) -> i64 {
    if !enable {
        return NGX_OK;
    }

    /* OpenSSL */

    if let Some(ctx) = ssl.ctx.builder_mut() {
        let _ = ctx.set_max_early_data(NGX_SSL_BUFSIZE as u32);
    }

    NGX_OK
}

/// ngx_ssl_conf_commands
pub fn ngx_ssl_conf_commands(cf: &mut Conf, ssl: &mut NgxSsl, commands: Option<&mut Vec<(Vec<u8>, Vec<u8>)>>) -> i64 {
    let commands = match commands {
        None => return NGX_OK,
        Some(c) => c,
    };

    let log = ssl.log.clone();

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    let flags = sys::SSL_CONF_FLAG_FILE | sys::SSL_CONF_FLAG_SERVER | sys::SSL_CONF_FLAG_CLIENT | sys::SSL_CONF_FLAG_CERTIFICATE | sys::SSL_CONF_FLAG_SHOW_ERRORS;

    let mut cctx = match sys::SslConf::new(ctx, flags) {
        Some(c) => c,
        None => {
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CONF_CTX_new() failed"));
            return NGX_ERROR;
        }
    };

    for (key, value) in commands.iter_mut() {
        let k = cstring(key);

        let ty = cctx.value_type(&k);

        if ty == sys::SSL_CONF_TYPE_FILE || ty == sys::SSL_CONF_TYPE_DIR {
            *value = cf.full_name(value, true);
        }

        if cctx.cmd(&k, &cstring(value)) <= 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CONF_cmd(\"{}\", \"{}\") failed", B(key), B(value)));
            return NGX_ERROR;
        }
    }

    if cctx.finish() != 1 {
        ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("SSL_CONF_finish() failed"));
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_ssl_client_session_cache
pub fn ngx_ssl_client_session_cache(_cf: &mut Conf, ssl: &mut NgxSsl, enable: bool) -> i64 {
    if !enable {
        return NGX_OK;
    }

    if let Some(ctx) = ssl.ctx.builder_mut() {
        ctx.set_session_cache_mode(SslSessionCacheMode::from_bits_retain((sys::SSL_SESS_CACHE_CLIENT | sys::SSL_SESS_CACHE_NO_INTERNAL) as _));

        ctx.set_new_session_callback(ngx_ssl_new_client_session);
    }

    NGX_OK
}

/// ngx_ssl_new_client_session: hands the new session to
/// c->ssl->save_session
fn ngx_ssl_new_client_session(ssl_conn: &mut SslRef, sess: SslSession) {
    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return,
    };

    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return,
    };

    let save = sc.state.save_session.borrow().clone();

    if let Some(save) = save {
        *sc.state.session.borrow_mut() = Some(sess);

        save(&c);

        *sc.state.session.borrow_mut() = None;
    }
}

/// ngx_ssl_set_client_hello_callback
pub fn ngx_ssl_set_client_hello_callback(ssl: &mut NgxSsl, cb: &'static SslClientHelloArg) -> i64 {
    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    sys::ctx_set_client_hello_callback::<ClientHelloCb>(ctx);

    ssl.data.client_hello.set(Some(cb.servername));

    NGX_OK
}

/// SSL_CTX_set_tlsext_servername_callback(): false if the library has no
/// SNI support
pub fn ngx_ssl_set_servername_callback(ssl: &mut NgxSsl, servername: ServernameFn) -> bool {
    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return false,
    };

    ssl.data.servername.set(Some(servername));

    sys::ctx_set_servername_callback::<ServernameCb>(ctx)
}

/// SSL_CTX_set_cert_cb(): the certificate callback of the context, called
/// with the configuration given to ngx_ssl_create()
pub fn ngx_ssl_set_cert_callback(ssl: &mut NgxSsl, cb: CertFn) {
    if let Some(ctx) = ssl.ctx.builder_mut() {
        sys::ctx_set_cert_callback::<CertCb>(ctx);
        ssl.data.cert_cb.set(Some(cb));
    }
}

/// SSL_set_SSL_CTX() and what nginx adjusts after it in the servername
/// callbacks (verification, options): false if SSL_set_SSL_CTX() failed
pub fn ngx_ssl_set_ssl_ctx(ssl_conn: &mut SslRef, ctx: &SslContextRef) -> bool {
    if let Err(e) = ssl_conn.set_ssl_context(ctx) {
        put(e);
        return false;
    }

    /*
     * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
     * adjust other things we care about
     */

    sys::copy_verify(ssl_conn, ctx);

    let options = sys::ctx_options(ctx);

    let cur = sys::options(ssl_conn);
    sys::clear_options(ssl_conn, cur & !options);

    sys::set_options(ssl_conn, options);

    sys::set_options(ssl_conn, sys::SSL_OP_NO_RENEGOTIATION);

    true
}

/// ngx_ssl_client_hello_callback: the server name of the ClientHello for
/// the servername callback, before the protocol version is negotiated
fn ngx_ssl_client_hello_callback(ssl_conn: &mut SslRef, ad: &mut i32) -> i32 {
    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return sys::SSL_CLIENT_HELLO_SUCCESS,
    };

    let servername = match c.ssl.borrow().as_ref() {
        Some(sc) => sc.state.session_data.borrow().as_ref().and_then(|d| d.client_hello.get()),
        None => return sys::SSL_CLIENT_HELLO_SUCCESS,
    };

    let mut host: Option<Vec<u8>> = None;

    if let Some(d) = sys::client_hello_ext(ssl_conn, sys::TLSEXT_TYPE_server_name) {
        let len = d.len();

        /*
         * RFC 6066 mandates non-zero HostName length, we follow OpenSSL.
         * No more than one ServerName is expected.
         */

        if len < 5 || ((d[0] as usize) << 8) + d[1] as usize + 2 != len || d[2] as i32 != sys::TLSEXT_NAMETYPE_host_name || ((d[3] as usize) << 8) + d[4] as usize + 2 + 3 != len {
            *ad = sys::SSL_AD_DECODE_ERROR;
            return sys::SSL_CLIENT_HELLO_ERROR;
        }

        let name = &d[5..];

        if name.len() > sys::TLSEXT_MAXLEN_host_name || name.contains(&0) {
            *ad = sys::SSL_AD_UNRECOGNIZED_NAME;
            return sys::SSL_CLIENT_HELLO_ERROR;
        }

        host = Some(name.to_vec());
    }

    // done:

    let f = match servername {
        Some(f) => f,
        None => return sys::SSL_CLIENT_HELLO_SUCCESS,
    };

    let rc = f(&c, ssl_conn, ad, SniArg::Hello(host.as_deref()));

    if rc == sys::SSL_TLSEXT_ERR_ALERT_FATAL {
        return sys::SSL_CLIENT_HELLO_ERROR;
    }

    sys::SSL_CLIENT_HELLO_SUCCESS
}

// --- connections ---

/// ngx_ssl_create_connection: c->ssl for the context
pub fn ngx_ssl_create_connection(ssl: &NgxSsl, c: &Connection, flags: u32) -> i64 {
    let sc = SslConnection::new();

    sc.state.buffer.set(flags & NGX_SSL_BUFFER != 0);
    sc.buffer_size.set(ssl.buffer_size);

    let ctx = match ssl.ctx.get() {
        Some(ctx) => ctx,
        None => {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("SSL_new() failed"));
            return NGX_ERROR;
        }
    };

    if ctx.max_early_data() != 0 {
        sc.state.try_early_data.set(true);
    }

    let mut conn = match Ssl::new(&ctx) {
        Ok(s) => s,
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("SSL_new() failed"));
            return NGX_ERROR;
        }
    };

    *sc.state.session_ctx.borrow_mut() = Some(ctx);
    *sc.state.session_data.borrow_mut() = Some(ssl.data.clone());

    if !sys::set_fd(&mut conn, c.fd.get()) {
        ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("SSL_set_fd() failed"));
        return NGX_ERROR;
    }

    if flags & NGX_SSL_CLIENT != 0 {
        conn.set_connect_state();
    } else {
        conn.set_accept_state();

        sys::set_options(&mut conn, sys::SSL_OP_NO_RENEGOTIATION);
    }

    // SSL_set_ex_data(conn, ngx_ssl_connection_index, c)

    let id = next_key();

    conn.set_ex_data(connection_index(), id);
    sc.state.id.set(id);

    if let Some(rc) = crate::connection::connection_rc(c) {
        SSL_CONNECTIONS.with(|m| m.borrow_mut().insert(id, Rc::downgrade(&rc)));
    }

    // the SSL object is freed with the SslConnection
    *sc.inner.borrow_mut() = Some(conn);

    sc.state.ngx.set(true);

    *c.ssl.borrow_mut() = Some(Rc::new(sc));

    NGX_OK
}

/// ngx_ssl_get_session: a reference to the session to be saved
pub fn ngx_ssl_get_session(c: &Connection) -> Option<SslSession> {
    let sc = c.ssl.borrow().clone()?;

    if let Some(sess) = sc.state.session.borrow().as_ref() {
        return Some(sess.clone());
    }

    sc.with(|ssl| ssl.session().map(|s| s.to_owned())).flatten()
}

/// ngx_ssl_set_session
pub fn ngx_ssl_set_session(c: &Connection, session: Option<&SslSessionRef>) -> i64 {
    let session = match session {
        Some(s) => s,
        None => return NGX_OK,
    };

    let ok = c.ssl.borrow().clone().and_then(|sc| sc.with_mut(|ssl| sys::set_session(ssl, session))).unwrap_or(false);

    if !ok {
        ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("SSL_set_session() failed"));
        return NGX_ERROR;
    }

    NGX_OK
}

/// c->ssl->save_session: called with the new sessions of a client
/// connection (ngx_ssl_client_session_cache() enabled); ngx_ssl_get_session()
/// in it returns the new session
pub fn ngx_ssl_set_save_session(c: &Connection, save: Option<Rc<dyn Fn(&Connection)>>) {
    if let Some(sc) = c.ssl.borrow().as_ref() {
        *sc.state.save_session.borrow_mut() = save;
    }
}

/// SSL_set_tlsext_host_name(): the server name of a client connection (the
/// caller logs the failure, as ngx_stream_proxy_ssl_name() does)
pub fn ngx_ssl_set_tlsext_host_name(c: &Connection, name: &[u8]) -> bool {
    let n = cstring(name);
    c.ssl.borrow().clone().and_then(|sc| sc.with_mut(|ssl| sys::set_tlsext_host_name(ssl, &n))).unwrap_or(false)
}

/// SSL_set_alpn_protos(): the ALPN protocols of a client connection, in
/// the wire format (0 on success, as in OpenSSL)
pub fn ngx_ssl_set_alpn_protos(c: &Connection, protos: &[u8]) -> i32 {
    let r = c.ssl.borrow().clone().and_then(|sc| sc.with_mut(|ssl| ssl.set_alpn_protos(protos)));

    match r {
        Some(Ok(())) => 0,
        Some(Err(e)) => {
            put(e);
            1
        }
        None => 1,
    }
}

/// SSL_get_verify_result()
pub fn ngx_ssl_get_verify_result(c: &Connection) -> i64 {
    // X509_V_ERR_UNSPECIFIED without an SSL object
    ngx_ssl_with(c, |ssl| ssl.verify_result().as_raw() as i64).unwrap_or(1)
}

/// X509_verify_cert_error_string()
pub fn ngx_ssl_verify_error_string(rc: i64) -> Vec<u8> {
    sys::x509_verify_cert_error_string(rc)
}

/// SSL_session_reused()
pub fn ngx_ssl_session_reused(c: &Connection) -> bool {
    ngx_ssl_with(c, |ssl| ssl.session_reused()).unwrap_or(false)
}

/// ngx_ssl_handshake: one SSL_do_handshake() attempt; NGX_AGAIN when it
/// waits for the socket (ngx_ssl_handshake_wait() continues it)
pub fn ngx_ssl_handshake(c: &Connection) -> i64 {
    let step = ngx_ssl_handshake_step(c);

    remember_want(c, &step);

    match step {
        IoStep::Done(rc) => rc,
        IoStep::WantRead | IoStep::WantWrite => NGX_AGAIN,
    }
}

/// The readiness the last attempt of an operation waits for.
fn remember_want<T>(c: &Connection, step: &IoStep<T>) {
    if let Some(sc) = c.ssl.borrow().as_ref() {
        sc.state.want.set(match step {
            IoStep::WantRead => 1,
            IoStep::WantWrite => 2,
            IoStep::Done(_) => 0,
        });
    }
}

/// The continuation of the operation which returned NGX_AGAIN (or an
/// attempt now if there was none).
fn take_want<T>(c: &Connection, op: impl FnOnce() -> IoStep<T>) -> IoStep<T> {
    let want = c.ssl.borrow().as_ref().map(|sc| sc.state.want.replace(0)).unwrap_or(0);

    match want {
        1 => IoStep::WantRead,
        2 => IoStep::WantWrite,
        _ => op(),
    }
}

/// ngx_ssl_handshake_handler: ngx_ssl_handshake() on the events until it
/// completes: NGX_OK or NGX_ERROR.  The caller sets the timer (the
/// handshake timeout).
pub async fn ngx_ssl_handshake_wait(c: &Connection) -> i64 {
    let step = take_want(c, || ngx_ssl_handshake_step(c));

    let write = Cell::new(matches!(step, IoStep::WantWrite));

    let rc = match c
        .drive_io_from(step, || {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL handshake handler: {}", write.get() as i32);

            let s = ngx_ssl_handshake_step(c);
            write.set(matches!(s, IoStep::WantWrite));
            s
        })
        .await
    {
        Ok(rc) => rc,
        Err(_) => return NGX_ERROR,
    };

    if rc != NGX_AGAIN {
        return rc;
    }

    // the OCSP validation is in progress (ngx_ssl_ocsp_validate()
    // returned NGX_AGAIN): its requests, then the handshake handler

    crate::event_openssl_stapling::ngx_ssl_ocsp_run(c).await;

    let handshaked = c.ssl.borrow().as_ref().map(|sc| sc.handshaked.get()).unwrap_or(false);

    if handshaked {
        NGX_OK
    } else {
        NGX_ERROR
    }
}

/// The kernel TLS of the connection for sending, as ngx_ssl_handshake()
/// checks it.
fn check_ktls(c: &Connection, sc: &SslConnection) {
    if sc.with(sys::ktls_send).unwrap_or(false) {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "BIO_get_ktls_send(): 1");
        sc.state.sendfile.set(true);
    }
}

/// The body of ngx_ssl_handshake().
pub fn ngx_ssl_handshake_step(c: &Connection) -> IoStep<i64> {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return IoStep::Done(NGX_ERROR),
    };

    if sc.state.try_early_data.get() {
        return ngx_ssl_try_early_data(c, &sc);
    }

    if sc.state.in_ocsp.get() {
        return IoStep::Done(crate::event_openssl_stapling::ngx_ssl_ocsp_validate(c));
    }

    ngx_ssl_clear_error(&c.log);

    let io = match sc.with_mut(sys::do_handshake) {
        Some(io) => io,
        None => return IoStep::Done(NGX_ERROR),
    };

    let n = io.rc;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_do_handshake: {}", n);

    if n == 1 {
        ngx_ssl_handshake_log(c);

        check_ktls(c, &sc);

        let rc = crate::event_openssl_stapling::ngx_ssl_ocsp_validate(c);

        if rc == NGX_ERROR {
            return IoStep::Done(NGX_ERROR);
        }

        if rc == NGX_AGAIN {
            return IoStep::Done(NGX_AGAIN);
        }

        sc.handshaked.set(true);

        return IoStep::Done(NGX_OK);
    }

    let sslerr = io.error;
    let mut err = if sslerr == SSL_ERROR_SYSCALL { io.errno } else { 0 };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

    if sslerr == SSL_ERROR_WANT_READ {
        return IoStep::WantRead;
    }

    if sslerr == SSL_ERROR_WANT_WRITE {
        return IoStep::WantWrite;
    }

    if sslerr != SSL_ERROR_SYSCALL {
        err = 0;
    }

    let mut sslerr = sslerr;

    if sslerr == SSL_ERROR_SYSCALL && sys::err_peek_error() == 0 && err == 0 {
        /*
         * OpenSSL up to 3.0 returns SSL_ERROR_SYSCALL
         * without an error queue and with errno set to 0
         * if connection is closed cleanly
         */

        sslerr = SSL_ERROR_ZERO_RETURN;
    }

    sc.no_wait_shutdown.set(true);
    sc.no_send_shutdown.set(true);
    c.read_eof.set(true);

    if sslerr == SSL_ERROR_ZERO_RETURN {
        c.connection_error(err, "peer closed connection in SSL handshake");

        return IoStep::Done(NGX_ERROR);
    }

    if sc.state.handshake_rejected.get() {
        c.connection_error(err, "handshake rejected");
        sys::err_clear_error();

        return IoStep::Done(NGX_ERROR);
    }

    ngx_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

    IoStep::Done(NGX_ERROR)
}

/// ngx_ssl_try_early_data
fn ngx_ssl_try_early_data(c: &Connection, sc: &SslConnection) -> IoStep<i64> {
    ngx_ssl_clear_error(&c.log);

    let mut buf = [0u8; 1];

    let io = match sc.with_mut(|ssl| sys::read_early_data(ssl, &mut buf)) {
        Some(io) => io,
        None => return IoStep::Done(NGX_ERROR),
    };

    let n = io.rc as i32;
    let readbytes = io.n;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_read_early_data: {}, {}", n, readbytes);

    if n == sys::SSL_READ_EARLY_DATA_FINISH {
        sc.state.try_early_data.set(false);
        return ngx_ssl_handshake_step(c);
    }

    if n == sys::SSL_READ_EARLY_DATA_SUCCESS {
        ngx_ssl_handshake_log(c);

        sc.state.try_early_data.set(false);

        sc.state.early_buf.set(buf[0]);
        sc.state.early_preread.set(true);

        sc.state.in_early.set(true);

        check_ktls(c, sc);

        let rc = crate::event_openssl_stapling::ngx_ssl_ocsp_validate(c);

        if rc == NGX_ERROR {
            return IoStep::Done(NGX_ERROR);
        }

        if rc == NGX_AGAIN {
            return IoStep::Done(NGX_AGAIN);
        }

        sc.handshaked.set(true);

        return IoStep::Done(NGX_OK);
    }

    /* SSL_READ_EARLY_DATA_ERROR */

    let sslerr = io.error;
    let err = if sslerr == SSL_ERROR_SYSCALL { io.errno } else { 0 };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

    if sslerr == SSL_ERROR_WANT_READ {
        return IoStep::WantRead;
    }

    if sslerr == SSL_ERROR_WANT_WRITE {
        return IoStep::WantWrite;
    }

    let mut sslerr = sslerr;

    if sslerr == SSL_ERROR_SYSCALL && sys::err_peek_error() == 0 && err == 0 {
        sslerr = SSL_ERROR_ZERO_RETURN;
    }

    sc.no_wait_shutdown.set(true);
    sc.no_send_shutdown.set(true);
    c.read_eof.set(true);

    if sslerr == SSL_ERROR_ZERO_RETURN {
        c.connection_error(err, "peer closed connection in SSL handshake");

        return IoStep::Done(NGX_ERROR);
    }

    ngx_ssl_connection_error(c, sslerr, err, "SSL_read_early_data() failed");

    IoStep::Done(NGX_ERROR)
}

/// ngx_ssl_handshake_log
pub fn ngx_ssl_handshake_log(c: &Connection) {
    if !c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
        return;
    }

    ngx_ssl_with(c, |ssl| match ssl.current_cipher() {
        Some(cipher) => {
            let src = cipher.description().into_bytes();

            let mut d: Vec<u8> = Vec::with_capacity(src.len());
            let mut last = b'\0';

            for &s in src.iter() {
                if s == b' ' && last == b' ' {
                    continue;
                }

                if s == b'\n' || s == b'\r' {
                    continue;
                }

                d.push(s);
                last = s;
            }

            if d.last() == Some(&b' ') {
                d.pop();
            }

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL: {}, cipher: \"{}\"", ssl.version_str(), B(&d));

            if ssl.session_reused() {
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL reused session");
            }
        }

        None => {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL no shared ciphers");
        }
    });
}

/// ngx_ssl_recv: reads until the buffer is full or no more data is
/// available now; WantRead/WantWrite when nothing could be read (NGX_AGAIN)
pub fn ngx_ssl_recv_step(c: &Connection, sc: &SslConnection, buf: &mut [u8]) -> IoStep<io::Result<usize>> {
    if sc.state.in_early.get() {
        return ngx_ssl_recv_early(c, sc, buf);
    }

    if sc.state.last.get() == NGX_ERROR {
        return IoStep::Done(Err(ssl_error_logged()));
    }

    if sc.state.last.get() == NGX_DONE {
        c.read_eof.set(true);
        return IoStep::Done(Ok(0));
    }

    let mut bytes = 0usize;
    let mut size = buf.len();

    sc.state.recv_drained.set(false);

    ngx_ssl_clear_error(&c.log);

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    loop {
        let io = match sc.with_mut(|ssl| sys::read(ssl, &mut buf[bytes..])) {
            Some(io) => io,
            None => return IoStep::Done(Err(ssl_error_logged())),
        };

        let n = io.rc;

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_read: {}", n);

        if n > 0 {
            bytes += n as usize;
        }

        let (last, want_write) = ngx_ssl_handle_recv(c, sc, n, io.error, io.errno);

        sc.state.last.set(last);

        if last == NGX_OK {
            size -= n as usize;

            if size == 0 {
                return IoStep::Done(Ok(bytes));
            }

            continue;
        }

        if bytes != 0 {
            return IoStep::Done(Ok(bytes));
        }

        match last {
            NGX_DONE => {
                c.read_eof.set(true);
                return IoStep::Done(Ok(0));
            }

            NGX_ERROR => return IoStep::Done(Err(ssl_error_logged())),

            _ => {
                /* NGX_AGAIN */
                return if want_write { IoStep::WantWrite } else { IoStep::WantRead };
            }
        }
    }
}

/// ngx_ssl_recv_early
fn ngx_ssl_recv_early(c: &Connection, sc: &SslConnection, buf: &mut [u8]) -> IoStep<io::Result<usize>> {
    if sc.state.last.get() == NGX_ERROR {
        return IoStep::Done(Err(ssl_error_logged()));
    }

    if sc.state.last.get() == NGX_DONE {
        c.read_eof.set(true);
        return IoStep::Done(Ok(0));
    }

    let mut bytes = 0usize;
    let mut size = buf.len();

    ngx_ssl_clear_error(&c.log);

    if sc.state.early_preread.get() {
        if size == 0 {
            c.read_eof.set(true);
            return IoStep::Done(Ok(0));
        }

        buf[0] = sc.state.early_buf.get();

        sc.state.early_preread.set(false);

        bytes = 1;
        size -= 1;
    }

    if sc.state.write_blocked.get() {
        if bytes != 0 {
            return IoStep::Done(Ok(bytes));
        }
        return IoStep::WantWrite;
    }

    /*
     * SSL_read_early_data() may return data in parts, so try to read
     * until SSL_read_early_data() would return no data
     */

    loop {
        let io = match sc.with_mut(|ssl| sys::read_early_data(ssl, &mut buf[bytes..bytes + size])) {
            Some(io) => io,
            None => return IoStep::Done(Err(ssl_error_logged())),
        };

        let n = io.rc as i32;
        let readbytes = io.n;

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_read_early_data: {}, {}", n, readbytes);

        if n == sys::SSL_READ_EARLY_DATA_SUCCESS {
            let (last, _) = ngx_ssl_handle_recv(c, sc, 1, sys::SSL_ERROR_NONE, 0);
            sc.state.last.set(last);

            bytes += readbytes;
            size -= readbytes;

            if size == 0 {
                return IoStep::Done(Ok(bytes));
            }

            continue;
        }

        if n == sys::SSL_READ_EARLY_DATA_FINISH {
            let (last, _) = ngx_ssl_handle_recv(c, sc, 1, sys::SSL_ERROR_NONE, 0);
            sc.state.last.set(last);
            sc.state.in_early.set(false);

            if bytes != 0 {
                return IoStep::Done(Ok(bytes));
            }

            return ngx_ssl_recv_step(c, sc, &mut buf[bytes..]);
        }

        /* SSL_READ_EARLY_DATA_ERROR */

        let (last, want_write) = ngx_ssl_handle_recv(c, sc, 0, io.error, io.errno);
        sc.state.last.set(last);

        if bytes != 0 {
            return IoStep::Done(Ok(bytes));
        }

        match last {
            NGX_DONE => {
                c.read_eof.set(true);
                return IoStep::Done(Ok(0));
            }

            NGX_ERROR => return IoStep::Done(Err(ssl_error_logged())),

            _ => return if want_write { IoStep::WantWrite } else { IoStep::WantRead },
        }
    }
}

/// ngx_ssl_handle_recv: (rc, the read waits for writing); `sslerr` and
/// `errno` are SSL_get_error() of the call that returned n and errno
fn ngx_ssl_handle_recv(c: &Connection, sc: &SslConnection, n: i64, sslerr: i32, errno: i32) -> (i64, bool) {
    if n > 0 {
        return (NGX_OK, false);
    }

    let err = if sslerr == SSL_ERROR_SYSCALL { errno } else { 0 };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

    if sslerr == SSL_ERROR_WANT_READ {
        // c->read->ready = 0: OpenSSL's read found the socket drained, also
        // when ngx_ssl_recv returns the data read before
        c.read_drained();
        sc.state.recv_drained.set(true);
        return (NGX_AGAIN, false);
    }

    if sslerr == SSL_ERROR_WANT_WRITE {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_read: want write");

        return (NGX_AGAIN, true);
    }

    let mut sslerr = sslerr;

    if sslerr == SSL_ERROR_SYSCALL && sys::err_peek_error() == 0 && err == 0 {
        /*
         * OpenSSL up to 3.0 returns SSL_ERROR_SYSCALL
         * without an error queue and with errno set to 0
         * if connection is closed cleanly
         */

        sslerr = SSL_ERROR_ZERO_RETURN;
    }

    sc.no_wait_shutdown.set(true);
    sc.no_send_shutdown.set(true);

    if sslerr == SSL_ERROR_ZERO_RETURN {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "peer shutdown SSL cleanly");
        return (NGX_DONE, false);
    }

    ngx_ssl_connection_error(c, sslerr, err, "SSL_read() failed");

    (NGX_ERROR, false)
}

/// ngx_ssl_write: one SSL_write(); WantRead/WantWrite is NGX_AGAIN (the
/// same data must be passed again)
pub fn ngx_ssl_write_step(c: &Connection, sc: &SslConnection, data: &[u8]) -> IoStep<io::Result<usize>> {
    if sc.state.last.get() == NGX_ERROR {
        return IoStep::Done(Err(ssl_error_logged()));
    }

    if sc.state.in_early.get() {
        return ngx_ssl_write_early(c, sc, data);
    }

    ngx_ssl_clear_error(&c.log);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL to write: {}", data.len());

    let io = match sc.with_mut(|ssl| sys::write(ssl, data)) {
        Some(io) => io,
        None => return IoStep::Done(Err(ssl_error_logged())),
    };

    let n = io.rc;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_write: {}", n);

    if n > 0 {
        c.sent.set(c.sent.get() + n as u64);

        return IoStep::Done(Ok(n as usize));
    }

    let mut sslerr = io.error;

    if sslerr == SSL_ERROR_ZERO_RETURN {
        /*
         * OpenSSL 1.1.1 fails to return SSL_ERROR_SYSCALL if an error
         * happens during SSL_write() after close_notify alert from the
         * peer, and returns SSL_ERROR_ZERO_RETURN instead,
         * see https://github.com/openssl/openssl/commit/8051ab2
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    let err = if sslerr == SSL_ERROR_SYSCALL { io.errno } else { 0 };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

    if sslerr == SSL_ERROR_WANT_WRITE {
        return IoStep::WantWrite;
    }

    if sslerr == SSL_ERROR_WANT_READ {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_write: want read");

        return IoStep::WantRead;
    }

    sc.no_wait_shutdown.set(true);
    sc.no_send_shutdown.set(true);

    ngx_ssl_connection_error(c, sslerr, err, "SSL_write() failed");

    IoStep::Done(Err(ssl_error_logged()))
}

/// ngx_ssl_write_early
fn ngx_ssl_write_early(c: &Connection, sc: &SslConnection, data: &[u8]) -> IoStep<io::Result<usize>> {
    ngx_ssl_clear_error(&c.log);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL to write: {}", data.len());

    let io = match sc.with_mut(|ssl| sys::write_early_data(ssl, data)) {
        Some(io) => io,
        None => return IoStep::Done(Err(ssl_error_logged())),
    };

    let n = io.rc;
    let written = io.n;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_write_early_data: {}, {}", n, written);

    if n > 0 {
        sc.state.write_blocked.set(false);

        c.sent.set(c.sent.get() + written as u64);

        return IoStep::Done(Ok(written));
    }

    let sslerr = io.error;

    let err = if sslerr == SSL_ERROR_SYSCALL { io.errno } else { 0 };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

    if sslerr == SSL_ERROR_WANT_WRITE {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_write_early_data: want write");

        /*
         * OpenSSL 1.1.1a fails to handle SSL_read_early_data()
         * if an SSL_write_early_data() call blocked on writing,
         * see https://github.com/openssl/openssl/issues/7757
         */

        sc.state.write_blocked.set(true);

        return IoStep::WantWrite;
    }

    if sslerr == SSL_ERROR_WANT_READ {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_write_early_data: want read");

        return IoStep::WantRead;
    }

    sc.no_wait_shutdown.set(true);
    sc.no_send_shutdown.set(true);

    ngx_ssl_connection_error(c, sslerr, err, "SSL_write_early_data() failed");

    IoStep::Done(Err(ssl_error_logged()))
}

/// A buffer of the chain passed to ngx_ssl_send_chain(): pos..last of a
/// buffer in memory, or file_pos..file_last of a buffer in a file
/// (in_file); a buffer with neither is special (flush, last_buf, sync).
#[derive(Clone, Copy)]
pub struct SslChainBuf<'a> {
    pub mem: &'a [u8],
    pub file: Option<SslChainFile<'a>>,
    pub flush: bool,
    pub last_buf: bool,
}

/// The chain ngx_ssl_send_chain() walks: its buffers by position, each
/// made when it is looked at, as C follows the links of the chain, so no
/// list of them is built per send.
pub trait SslChainLinks {
    /// the number of buffers
    fn links(&self) -> usize;
    /// the buffer at `i`
    fn link(&self, i: usize) -> SslChainBuf<'_>;
}

impl SslChainLinks for [SslChainBuf<'_>] {
    fn links(&self) -> usize {
        self.len()
    }

    fn link(&self, i: usize) -> SslChainBuf<'_> {
        self[i]
    }
}

/// Buffers in memory, each with the flush flag (the buffers of a read the
/// stream proxy sends).
pub struct SslFlushedBufs<'a>(pub &'a [&'a [u8]]);

impl SslChainLinks for SslFlushedBufs<'_> {
    fn links(&self) -> usize {
        self.0.len()
    }

    fn link(&self, i: usize) -> SslChainBuf<'_> {
        SslChainBuf { mem: self.0[i], file: None, flush: true, last_buf: false }
    }
}

/// A chain of buffers: in memory (pos..last), in a file (file_pos..
/// file_last), or special.
impl SslChainLinks for crate::buf::Chain {
    fn links(&self) -> usize {
        self.len()
    }

    fn link(&self, i: usize) -> SslChainBuf<'_> {
        let b = &self[i];

        let (mem, file): (&[u8], Option<SslChainFile>) = match &b.data {
            crate::buf::BufData::Memory(v) if b.in_memory() => (&v[b.pos..b.last], None),
            crate::buf::BufData::File(f) if b.in_file => (&[], Some(SslChainFile { fd: f.fd, name: &f.name, pos: b.file_pos, last: b.file_last })),
            _ => (&[], None),
        };

        SslChainBuf { mem, file, flush: b.flush, last_buf: b.last_buf }
    }
}

/// file->fd, file->name, file_pos, file_last
#[derive(Clone, Copy)]
pub struct SslChainFile<'a> {
    pub fd: i32,
    pub name: &'a [u8],
    pub pos: i64,
    pub last: i64,
}

impl SslChainBuf<'_> {
    /// ngx_buf_special()
    fn special(&self) -> bool {
        self.mem.is_empty() && self.file.is_none()
    }

    /// ngx_buf_size() less the part already taken
    fn rest(&self, off: i64) -> i64 {
        match &self.file {
            Some(f) => f.last - f.pos - off,
            None => self.mem.len() as i64 - off,
        }
    }
}

/// The position of ngx_ssl_send_chain() in the chain (the "in" it
/// returns): a buffer, and the part of it taken (in->buf->pos, file_pos).
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SslChainPos {
    pub link: usize,
    pub off: i64,
}

/// c->ssl->buf of NGX_SSL_BUFFER: memory taken on the first use (C
/// allocates it, uninitialised, from the connection's pool) and given
/// back by ngx_ssl_free_buffer() or with the connection, so an idle
/// connection holds none. The data not written yet are data[pos..]:
/// data.len() is buf->last, as the copies append to it, so the memory is
/// never zero-filled; `end` is buf->end, the buffer size it was taken for.
#[derive(Default)]
pub struct SslBuf {
    data: Vec<u8>,
    pos: usize,
    end: usize,
    flush: bool,
}

impl SslBuf {
    /// buf->last - buf->pos
    fn pending(&self) -> usize {
        self.data.len() - self.pos
    }
}

impl Drop for SslBuf {
    fn drop(&mut self) {
        ssl_buf_free(std::mem::take(&mut self.data));
    }
}

/// The most free c->ssl->buf memory a worker keeps.
const SSL_BUFS_MAX: usize = 16;

thread_local! {
    /// The free c->ssl->buf memory of the worker, empty Vecs with their
    /// capacity: what C's ngx_pfree() gives back to malloc for the next
    /// connection that sends.
    static SSL_BUFS: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// An empty Vec of at least `size` bytes of capacity for c->ssl->buf.
fn ssl_buf_alloc(size: usize) -> Vec<u8> {
    let free = SSL_BUFS
        .try_with(|bufs| {
            let mut bufs = bufs.try_borrow_mut().ok()?;
            let i = bufs.iter().rposition(|b| b.capacity() >= size)?;
            Some(bufs.swap_remove(i))
        })
        .ok()
        .flatten();

    free.unwrap_or_else(|| Vec::with_capacity(size))
}

/// c->ssl->buf memory back to the worker's free list.
fn ssl_buf_free(mut data: Vec<u8>) {
    if data.capacity() == 0 {
        return;
    }

    data.clear();

    let _ = SSL_BUFS.try_with(|bufs| {
        if let Ok(mut bufs) = bufs.try_borrow_mut() {
            if bufs.len() < SSL_BUFS_MAX {
                bufs.push(data);
            }
        }
    });
}

/// NGX_SSL_BUFFERED in c->buffered: data not written from c->ssl->buf.
pub fn ngx_ssl_buffered(sc: &SslConnection) -> bool {
    sc.state.buf.borrow().pending() != 0
}

/// ngx_ssl_send_chain: one pass over the chain from `pos`, moving it past
/// the buffers taken. Without NGX_SSL_BUFFER each buffer is written by
/// ngx_ssl_write(). With it the buffers are copied to c->ssl->buf, which
/// is written when full or on flush (a flush or last buffer, or the end of
/// the chain passed after a flush); a file buffer of a connection with
/// kernel TLS flushes it and goes with SSL_sendfile(). WantRead /
/// WantWrite is NGX_AGAIN; the chain is not all taken, or c->ssl->buf not
/// all written, on Done when `limit` is reached or a write was partial.
pub fn ngx_ssl_send_chain(c: &Connection, links: &[SslChainBuf<'_>], pos: &mut SslChainPos, limit: i64) -> IoStep<Result<(), ()>> {
    ngx_ssl_send_chain_links(c, links, pos, limit)
}

/// ngx_ssl_send_chain() of a chain of buffers, walked in place.
pub fn ngx_ssl_send_chain_chain(c: &Connection, chain: &crate::buf::Chain, pos: &mut SslChainPos, limit: i64) -> IoStep<Result<(), ()>> {
    ngx_ssl_send_chain_links(c, chain, pos, limit)
}

/// ngx_ssl_send_chain() over any chain.
pub fn ngx_ssl_send_chain_links<L: SslChainLinks + ?Sized>(c: &Connection, links: &L, pos: &mut SslChainPos, limit: i64) -> IoStep<Result<(), ()>> {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return IoStep::Done(Err(())),
    };

    let nlinks = links.links();

    if !sc.state.buffer.get() {
        while pos.link < nlinks {
            let b = &links.link(pos.link);

            if b.special() || b.mem.is_empty() {
                pos.link += 1;
                pos.off = 0;
                continue;
            }

            match ngx_ssl_write_step(c, &sc, &b.mem[pos.off as usize..]) {
                IoStep::Done(Err(_)) => return IoStep::Done(Err(())),
                IoStep::WantWrite => return IoStep::WantWrite,
                IoStep::WantRead => return IoStep::WantRead,
                IoStep::Done(Ok(n)) => {
                    pos.off += n as i64;

                    if pos.off as usize == b.mem.len() {
                        pos.link += 1;
                        pos.off = 0;
                    }
                }
            }
        }

        return IoStep::Done(Ok(()));
    }

    /* the maximum limit size is the maximum int32_t value - the page size */

    let max = i32::MAX as i64 - crate::os::pagesize() as i64;

    let limit = if limit == 0 || limit > max { max } else { limit };

    let mut buf = sc.state.buf.borrow_mut();

    if buf.data.capacity() == 0 {
        let size = sc.buffer_size.get();

        buf.data = ssl_buf_alloc(size);
        buf.pos = 0;
        buf.end = size;
    }

    let end = buf.end;

    let mut send = buf.pending() as i64;
    let mut flush = pos.link >= nlinks || buf.flush;

    let mut again = None;

    loop {
        while pos.link < nlinks && buf.data.len() < end && send < limit {
            let b = &links.link(pos.link);

            if b.last_buf || b.flush {
                flush = true;
            }

            if b.special() {
                pos.link += 1;
                pos.off = 0;
                continue;
            }

            if b.file.is_some() && sc.state.sendfile.get() {
                flush = true;
                break;
            }

            let rest = &b.mem[pos.off as usize..];

            let mut size = rest.len().min(end - buf.data.len());

            if send + size as i64 > limit {
                size = (limit - send) as usize;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL buf copy: {}", size);

            buf.data.extend_from_slice(&rest[..size]);

            pos.off += size as i64;
            send += size as i64;

            if pos.off as usize == b.mem.len() {
                pos.link += 1;
                pos.off = 0;
            }
        }

        if !flush && send < limit && buf.data.len() < end {
            break;
        }

        let size = buf.pending();

        if size == 0 {
            if pos.link < nlinks && links.link(pos.link).file.is_some() && send < limit {
                /* coalesce the neighbouring file bufs */

                let file_size = ngx_ssl_chain_coalesce_file(links, *pos, limit - send);

                match ngx_ssl_sendfile(c, &sc, &links.link(pos.link), pos.off, file_size) {
                    IoStep::Done(Err(())) => return IoStep::Done(Err(())),
                    IoStep::WantWrite => {
                        again = Some(IoStep::WantWrite);
                        break;
                    }
                    IoStep::WantRead => {
                        again = Some(IoStep::WantRead);
                        break;
                    }
                    IoStep::Done(Ok(n)) => {
                        ngx_ssl_chain_update_sent(links, pos, n);

                        send += n;
                        flush = false;

                        continue;
                    }
                }
            }

            buf.flush = false;

            return IoStep::Done(Ok(()));
        }

        let p = buf.pos;

        match ngx_ssl_write_step(c, &sc, &buf.data[p..]) {
            IoStep::Done(Err(_)) => return IoStep::Done(Err(())),
            IoStep::WantWrite => {
                again = Some(IoStep::WantWrite);
                break;
            }
            IoStep::WantRead => {
                again = Some(IoStep::WantRead);
                break;
            }
            IoStep::Done(Ok(n)) => {
                buf.pos += n;

                if n < size {
                    break;
                }

                flush = false;

                buf.pos = 0;
                buf.data.clear();

                if pos.link >= nlinks || send >= limit {
                    break;
                }
            }
        }
    }

    buf.flush = flush;

    match again {
        Some(step) => step,
        None => IoStep::Done(Ok(())),
    }
}

/// ngx_chain_coalesce_file: the size of the file buffer at `pos` and of
/// the following buffers of the same file which continue it, up to `limit`.
fn ngx_ssl_chain_coalesce_file<L: SslChainLinks + ?Sized>(links: &L, pos: SslChainPos, limit: i64) -> i64 {
    let first = links.link(pos.link).file.expect("file buf");

    let fd = first.fd;
    let mut fprev = first.pos + pos.off;
    let mut total = 0i64;
    let mut i = pos.link;
    let mut off = pos.off;

    while i < links.links() {
        let f = match links.link(i).file {
            Some(f) => f,
            None => break,
        };

        if f.fd != fd || f.pos + off != fprev {
            break;
        }

        let mut size = f.last - f.pos - off;

        if size > limit - total {
            size = limit - total;

            let aligned = (f.pos + off + size + crate::os::pagesize() as i64 - 1) & !(crate::os::pagesize() as i64 - 1);

            if aligned <= f.last {
                size = aligned - (f.pos + off);
            }

            total += size;
            break;
        }

        total += size;
        fprev = f.pos + off + size;
        off = 0;
        i += 1;
    }

    total
}

/// ngx_chain_update_sent: `sent` bytes of the chain from `pos` are taken;
/// the special buffers after them too.
fn ngx_ssl_chain_update_sent<L: SslChainLinks + ?Sized>(links: &L, pos: &mut SslChainPos, mut sent: i64) {
    while pos.link < links.links() {
        let b = links.link(pos.link);

        if b.special() {
            pos.link += 1;
            pos.off = 0;
            continue;
        }

        if sent == 0 {
            break;
        }

        let size = b.rest(pos.off);

        if sent >= size {
            sent -= size;
            pos.link += 1;
            pos.off = 0;
            continue;
        }

        pos.off += sent;

        break;
    }
}

/// ngx_ssl_sendfile: SSL_sendfile() of `size` bytes of the file buffer
/// `b` from `off` into it (kernel TLS).
fn ngx_ssl_sendfile(c: &Connection, sc: &SslConnection, b: &SslChainBuf<'_>, off: i64, size: i64) -> IoStep<Result<i64, ()>> {
    let file = b.file.as_ref().expect("file buf");

    if sc.state.last.get() == NGX_ERROR {
        c.error.set(true);
        return IoStep::Done(Err(()));
    }

    ngx_ssl_clear_error(&c.log);

    let file_pos = file.pos + off;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL to sendfile: @{} {}", file_pos, size);

    let io = match crate::fd::get(file.fd) {
        Ok(fd) => sc.with_mut(|ssl| sys::sendfile(ssl, fd.as_fd(), file_pos, size as usize)),
        // sendfile() of a descriptor not open
        Err(_) => Some(sys::SslIo { rc: -1, n: 0, error: SSL_ERROR_SYSCALL, errno: libc::EBADF }),
    };

    let io = match io {
        Some(io) => io,
        None => return IoStep::Done(Err(())),
    };

    let n = io.rc;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_sendfile: {}", n);

    if n > 0 {
        c.sent.set(c.sent.get() + n as u64);

        return IoStep::Done(Ok(n));
    }

    if n == 0 {
        /*
         * if sendfile returns zero, then someone has truncated the file,
         * so the offset became beyond the end of the file
         */

        ngx_log_error!(NGX_LOG_ALERT, c.log, None, "SSL_sendfile() reported that \"{}\" was truncated at {}", B(file.name), file_pos);

        return IoStep::Done(Err(()));
    }

    let mut sslerr = io.error;

    if sslerr == SSL_ERROR_ZERO_RETURN {
        /*
         * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
         * happens during writing after close_notify alert from the
         * peer, and returns SSL_ERROR_ZERO_RETURN instead
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    if sslerr == SSL_ERROR_SSL && sys::err_get_reason(sys::err_peek_error()) == sys::SSL_R_UNINITIALIZED && io.errno != 0 {
        /*
         * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
         * happens in sendfile(), and returns SSL_ERROR_SSL with
         * SSL_R_UNINITIALIZED reason instead
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    let err = if sslerr == SSL_ERROR_SYSCALL { io.errno } else { 0 };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

    if sslerr == SSL_ERROR_WANT_WRITE {
        return IoStep::WantWrite;
    }

    if sslerr == SSL_ERROR_WANT_READ {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_sendfile: want read");

        return IoStep::WantRead;
    }

    sc.no_wait_shutdown.set(true);
    sc.no_send_shutdown.set(true);
    c.error.set(true);

    ngx_ssl_connection_error(c, sslerr, err, "SSL_sendfile() failed");

    IoStep::Done(Err(()))
}

/// ngx_ssl_send_chain() with the waiting of its callers (the write event
/// handlers): the chain is taken until it all is and, when flushing,
/// c->ssl->buf is written, or until `limit` bytes of it are taken (the
/// limit of a pass counts the data it finds in c->ssl->buf, which a pass
/// after NGX_AGAIN finds again). Returns the bytes of the chain taken.
pub async fn ngx_ssl_send_chain_wait(c: &Connection, links: &[SslChainBuf<'_>], limit: i64) -> io::Result<i64> {
    ngx_ssl_send_chain_wait_links(c, links, limit).await
}

/// ngx_ssl_send_chain_wait() of a chain of buffers, walked in place.
pub async fn ngx_ssl_send_chain_wait_chain(c: &Connection, chain: &crate::buf::Chain, limit: i64) -> io::Result<i64> {
    ngx_ssl_send_chain_wait_links(c, chain, limit).await
}

/// ngx_ssl_send_chain_wait() of any chain.
pub async fn ngx_ssl_send_chain_wait_links<L: SslChainLinks + ?Sized>(c: &Connection, links: &L, limit: i64) -> io::Result<i64> {
    let mut pos = SslChainPos::default();

    let r = c.drive_io(|| ngx_ssl_send_chain_wait_step(c, links, &mut pos, limit)).await?;

    match r {
        Ok(()) => Ok(ngx_ssl_chain_taken(links, pos)),
        Err(()) => Err(ssl_error_logged()),
    }
}

/// One pass of ngx_ssl_send_chain_wait() from `pos` (started at
/// SslChainPos::default()): ngx_ssl_send_chain() up to what is left of
/// `limit` (0: none) besides the data in c->ssl->buf. After Done the bytes
/// of the chain taken are ngx_ssl_chain_taken(); WantRead / WantWrite are
/// to be followed by the same pass with the same `pos` on the event.
pub fn ngx_ssl_send_chain_wait_step<L: SslChainLinks + ?Sized>(c: &Connection, links: &L, pos: &mut SslChainPos, limit: i64) -> IoStep<Result<(), ()>> {
    if limit <= 0 {
        return ngx_ssl_send_chain_links(c, links, pos, 0);
    }

    let left = limit - ngx_ssl_chain_taken(links, *pos);

    let buffered = match c.ssl.borrow().as_ref() {
        Some(sc) => sc.state.buf.borrow().pending() as i64,
        None => 0,
    };

    if left <= 0 && buffered == 0 {
        return IoStep::Done(Ok(()));
    }

    ngx_ssl_send_chain_links(c, links, pos, left.max(0) + buffered)
}

/// The bytes of the chain before `pos` (the buffers passed and the part
/// of the one at `pos` taken).
pub fn ngx_ssl_chain_taken<L: SslChainLinks + ?Sized>(links: &L, pos: SslChainPos) -> i64 {
    (0..pos.link.min(links.links())).map(|i| links.link(i).rest(0)).sum::<i64>() + pos.off
}

/// ngx_ssl_free_buffer: c->ssl->buf of an idle connection is freed (its
/// memory goes back to the worker's free list).
pub fn ngx_ssl_free_buffer(c: &Connection) {
    if let Some(sc) = c.ssl.borrow().as_ref() {
        let mut buf = sc.state.buf.borrow_mut();

        if buf.pending() == 0 {
            *buf = SslBuf::default();
        }
    }
}

/// ngx_ssl_shutdown: NGX_AGAIN when waiting for the peer
/// (ngx_ssl_shutdown_wait() continues it); otherwise the SSL object is
/// freed (unless shutdown_without_free) and c.ssl is reset
pub fn ngx_ssl_shutdown(c: &Connection) -> i64 {
    let step = ngx_ssl_shutdown_step(c);

    remember_want(c, &step);

    match step {
        IoStep::Done(rc) => rc,
        IoStep::WantRead | IoStep::WantWrite => NGX_AGAIN,
    }
}

/// ngx_ssl_shutdown_handler: ngx_ssl_shutdown() on the events until it
/// completes, with the 3s timer (on which the shutdown is not waited for
/// anymore): NGX_OK or NGX_ERROR
pub async fn ngx_ssl_shutdown_wait(c: &Connection) -> i64 {
    let mut step = take_want(c, || ngx_ssl_shutdown_step(c));

    loop {
        let wait = c.drive_io_from(step, || {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL shutdown handler");
            ngx_ssl_shutdown_step(c)
        });

        match tokio::time::timeout(Duration::from_millis(3000), wait).await {
            Ok(Ok(rc)) => return rc,

            Ok(Err(_)) | Err(_) => {
                // ev->timedout (or the socket is gone)

                c.timedout.set(true);

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL shutdown handler");

                step = ngx_ssl_shutdown_step(c);
            }
        }
    }
}

/// The body of ngx_ssl_shutdown().
pub fn ngx_ssl_shutdown_step(c: &Connection) -> IoStep<i64> {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return IoStep::Done(NGX_OK),
    };

    crate::event_openssl_stapling::ngx_ssl_ocsp_cleanup(c);

    let rc = 'done: {
        if sc.with(sys::in_init).unwrap_or(true) {
            /*
             * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
             * an SSL handshake, while previous versions always return 0.
             * Avoid calling SSL_shutdown() if handshake wasn't completed.
             */

            break 'done NGX_OK;
        }

        let quiet_all = c.timedout.get() || c.error.get() || ngx_ssl_buffered(&sc);

        sc.with_mut(|ssl| {
            let mode;

            if quiet_all {
                mode = sys::SSL_RECEIVED_SHUTDOWN | sys::SSL_SENT_SHUTDOWN;
                sys::set_quiet_shutdown(ssl, true);
            } else {
                let mut m = sys::get_shutdown(ssl);

                if sc.no_wait_shutdown.get() {
                    m |= sys::SSL_RECEIVED_SHUTDOWN;
                }

                if sc.no_send_shutdown.get() {
                    m |= sys::SSL_SENT_SHUTDOWN;
                }

                if sc.no_wait_shutdown.get() && sc.no_send_shutdown.get() {
                    sys::set_quiet_shutdown(ssl, true);
                }

                mode = m;
            }

            sys::set_shutdown(ssl, mode);
        });

        ngx_ssl_clear_error(&c.log);

        let mut tries = 2;

        loop {
            /*
             * For bidirectional shutdown, SSL_shutdown() needs to be called
             * twice: first call sends the "close notify" alert and returns 0,
             * second call waits for the peer's "close notify" alert.
             */

            let io = match sc.with_mut(sys::shutdown) {
                Some(io) => io,
                None => break,
            };

            let n = io.rc;

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_shutdown: {}", n);

            if n == 1 {
                break 'done NGX_OK;
            }

            if n == 0 && tries > 1 {
                tries -= 1;
                continue;
            }

            /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */

            let sslerr = io.error;
            let err = if sslerr == SSL_ERROR_SYSCALL { io.errno } else { 0 };

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

            if sslerr == SSL_ERROR_WANT_READ {
                return IoStep::WantRead;
            }

            if sslerr == SSL_ERROR_WANT_WRITE {
                return IoStep::WantWrite;
            }

            let mut sslerr = sslerr;

            if sslerr == SSL_ERROR_SYSCALL && sys::err_peek_error() == 0 && err == 0 {
                /*
                 * OpenSSL up to 3.0 returns SSL_ERROR_SYSCALL
                 * without an error queue and with errno set to 0
                 * if connection is closed cleanly
                 */

                sslerr = SSL_ERROR_ZERO_RETURN;
            }

            if sslerr == SSL_ERROR_ZERO_RETURN {
                break 'done NGX_OK;
            }

            ngx_ssl_connection_error(c, sslerr, err, "SSL_shutdown() failed");

            break;
        }

        // failed:

        NGX_ERROR
    };

    // done:

    if sc.shutdown_without_free.get() {
        sc.shutdown_without_free.set(false);
        return IoStep::Done(rc);
    }

    drop(sc);

    // SSL_free(c->ssl->connection): the SSL object goes with c->ssl
    *c.ssl.borrow_mut() = None;

    IoStep::Done(rc)
}

/// ngx_ssl_connection_error: the level of SSL errors of a connection
/// follows c->log_error for the errors caused by the peer
pub fn ngx_ssl_connection_error(c: &Connection, sslerr: i32, err: i32, text: &str) {
    let mut level = NGX_LOG_CRIT;

    let peer_error = if sslerr == SSL_ERROR_SYSCALL {
        [libc::ECONNRESET, libc::EPIPE, libc::ENOTCONN, libc::ETIMEDOUT, libc::ECONNREFUSED, libc::ENETDOWN, libc::ENETUNREACH, libc::EHOSTDOWN, libc::EHOSTUNREACH].contains(&err)
    } else if sslerr == SSL_ERROR_SSL {
        let n = sys::err_get_reason(sys::err_peek_last_error());

        /* handshake failures */
        const HANDSHAKE_FAILURES: &[i32] = &[
            103, /* SSL_R_BAD_CHANGE_CIPHER_SPEC */
            101, /* SSL_R_NO_SUITABLE_KEY_SHARE */
            108, /* SSL_R_BAD_KEY_SHARE */
            110, /* SSL_R_BAD_EXTENSION */
            111, /* SSL_R_BAD_DIGEST_LENGTH */
            112, /* SSL_R_MISSING_SIGALGS_EXTENSION */
            115, /* SSL_R_BAD_PACKET_LENGTH */
            118, /* SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM */
            122, /* SSL_R_BAD_KEY_UPDATE */
            129, /* SSL_R_BLOCK_CIPHER_PAD_IS_WRONG */
            133, /* SSL_R_CCS_RECEIVED_EARLY */
            145, /* SSL_R_DATA_BETWEEN_CCS_AND_FINISHED */
            146, /* SSL_R_DATA_LENGTH_TOO_LONG */
            149, /* SSL_R_DIGEST_CHECK_FAILED */
            150, /* SSL_R_ENCRYPTED_LENGTH_TOO_LONG */
            151, /* SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST */
            152, /* SSL_R_EXCESSIVE_MESSAGE_SIZE */
            154, /* SSL_R_GOT_A_FIN_BEFORE_A_CCS */
            155, /* SSL_R_HTTPS_PROXY_REQUEST */
            156, /* SSL_R_HTTP_REQUEST */
            159, /* SSL_R_LENGTH_MISMATCH */
            160, /* SSL_R_LENGTH_TOO_SHORT */
            339, /* SSL_R_NO_RENEGOTIATION */
            183, /* SSL_R_NO_CIPHERS_SPECIFIED */
            186, /* SSL_R_BAD_CIPHER */
            187, /* SSL_R_NO_COMPRESSION_SPECIFIED */
            193, /* SSL_R_NO_SHARED_CIPHER */
            198, /* SSL_R_PACKET_LENGTH_TOO_LONG */
            205, /* SSL_R_INVALID_ALERT */
            213, /* SSL_R_RECORD_LENGTH_MISMATCH */
            226, /* SSL_R_CLIENTHELLO_TLSEXT */
            227, /* SSL_R_PARSE_TLSEXT */
            234, /* SSL_R_CALLBACK_FAILED */
            235, /* SSL_R_NO_APPLICATION_PROTOCOL */
            244, /* SSL_R_UNEXPECTED_MESSAGE */
            245, /* SSL_R_UNEXPECTED_RECORD */
            246, /* SSL_R_UNKNOWN_ALERT_TYPE */
            252, /* SSL_R_UNKNOWN_PROTOCOL */
            258, /* SSL_R_UNSUPPORTED_PROTOCOL */
            267, /* SSL_R_WRONG_VERSION_NUMBER */
            271, /* SSL_R_BAD_LENGTH */
            281, /* SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC */
            291, /* SSL_R_APPLICATION_DATA_AFTER_CLOSE_NOTIFY */
            292, /* SSL_R_BAD_LEGACY_VERSION */
            293, /* SSL_R_MIXED_HANDSHAKE_AND_NON_HANDSHAKE_DATA */
            298, /* SSL_R_RECORD_TOO_SMALL */
            300, /* SSL_R_SSL3_SESSION_ID_TOO_LONG */
            306, /* SSL_R_BAD_ECPOINT */
            335, /* SSL_R_RENEGOTIATE_EXT_TOO_LONG */
            336, /* SSL_R_RENEGOTIATION_ENCODING_ERR */
            337, /* SSL_R_RENEGOTIATION_MISMATCH */
            338, /* SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED */
            345, /* SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING */
            373, /* SSL_R_INAPPROPRIATE_FALLBACK */
            376, /* SSL_R_NO_SHARED_SIGNATURE_ALGORITHMS */
            377, /* SSL_R_CERT_CB_ERROR */
            396, /* SSL_R_VERSION_TOO_LOW */
            409, /* SSL_R_TOO_MANY_WARN_ALERTS */
            443, /* SSL_R_BAD_RECORD_TYPE */
        ];

        HANDSHAKE_FAILURES.contains(&n) || (sys::SSL_AD_REASON_OFFSET..=sys::SSL_AD_REASON_OFFSET + 255).contains(&n)
    } else {
        false
    };

    if peer_error {
        match c.log_error.get() {
            NGX_ERROR_IGNORE_ECONNRESET | NGX_ERROR_INFO => level = NGX_LOG_INFO,
            NGX_ERROR_ERR => level = NGX_LOG_ERR,
            _ => {}
        }
    }

    ngx_ssl_error(level, &c.log, err, format_args!("{}", text));
}

/// ngx_ssl_clear_error
pub fn ngx_ssl_clear_error(log: &Log) {
    while sys::err_peek_error() != 0 {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("ignoring stale global SSL error"));
    }

    sys::err_clear_error();
}

/// ngx_ssl_error: the message with the OpenSSL error queue appended
/// (the queue is emptied)
pub fn ngx_ssl_error(level: u32, log: &Log, err: i32, args: std::fmt::Arguments<'_>) {
    let last = NGX_MAX_CONF_ERRSTR;

    let mut errstr: Vec<u8> = Vec::with_capacity(256);
    {
        use std::io::Write;
        let _ = errstr.write_fmt(args);
    }
    errstr.truncate(last - 1);

    if sys::err_peek_error() != 0 {
        let pfx = b" (SSL:";
        let room = last.saturating_sub(errstr.len() + 1);
        errstr.extend_from_slice(&pfx[..pfx.len().min(room)]);

        loop {
            let (n, data) = sys::err_peek_error_data();

            if n == 0 {
                break;
            }

            /* ERR_error_string_n() requires at least one byte */

            if errstr.len() < last - 1 {
                errstr.push(b' ');

                let room = last - errstr.len();

                errstr.extend_from_slice(&sys::err_error_string_n(n, room));

                if let Some(d) = data.filter(|d| !d.is_empty()) {
                    if errstr.len() < last {
                        errstr.push(b':');

                        let room = (last - errstr.len()).saturating_sub(1);
                        errstr.extend_from_slice(&d[..d.len().min(room)]);
                    }
                }
            }

            // next:

            sys::err_get_error();
        }

        if errstr.len() < last {
            errstr.push(b')');
        }
    }

    ngx_log_error!(level, log, Some(err), "{}", B(&errstr));
}

// --- the session cache ---

/// ngx_ssl_session_cache
pub fn ngx_ssl_session_cache(ssl: &mut NgxSsl, sess_ctx: &[u8], certificates: Option<&Vec<Vec<u8>>>, builtin_session_cache: isize, shm_zone: Option<&Rc<ShmZone>>, timeout: i64) -> i64 {
    match ssl.ctx.builder_mut() {
        Some(ctx) => {
            sys::ctx_set_timeout(ctx, timeout);
        }
        None => return NGX_ERROR,
    }

    if ngx_ssl_session_id_context(ssl, sess_ctx, certificates) != NGX_OK {
        return NGX_ERROR;
    }

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    let mode = |m: i64| SslSessionCacheMode::from_bits_retain(m as _);

    if builtin_session_cache == NGX_SSL_NO_SCACHE {
        ctx.set_session_cache_mode(mode(sys::SSL_SESS_CACHE_OFF));
        return NGX_OK;
    }

    if builtin_session_cache == NGX_SSL_NONE_SCACHE {
        /*
         * If the server explicitly says that it does not support
         * session reuse (see SSL_SESS_CACHE_OFF above), then
         * Outlook Express fails to upload a sent email to
         * the Sent Items folder on the IMAP server via a separate IMAP
         * connection in the background.  Therefore we have a special
         * mode (SSL_SESS_CACHE_SERVER|SSL_SESS_CACHE_NO_INTERNAL_STORE)
         * where the server pretends that it supports session reuse,
         * but it does not actually store any session.
         */

        ctx.set_session_cache_mode(mode(sys::SSL_SESS_CACHE_SERVER | sys::SSL_SESS_CACHE_NO_AUTO_CLEAR | sys::SSL_SESS_CACHE_NO_INTERNAL_STORE));

        ctx.set_session_cache_size(1);

        return NGX_OK;
    }

    let mut cache_mode = sys::SSL_SESS_CACHE_SERVER;

    if shm_zone.is_some() && builtin_session_cache == NGX_SSL_NO_BUILTIN_SCACHE {
        cache_mode |= sys::SSL_SESS_CACHE_NO_INTERNAL;
    }

    ctx.set_session_cache_mode(mode(cache_mode));

    if builtin_session_cache != NGX_SSL_NO_BUILTIN_SCACHE && builtin_session_cache != NGX_SSL_DFLT_BUILTIN_SCACHE {
        ctx.set_session_cache_size(builtin_session_cache as i32);
    }

    if let Some(zone) = shm_zone {
        ctx.set_new_session_callback(ngx_ssl_new_session);
        sys::ctx_set_get_session_callback::<GetSessionCb>(ctx);
        ctx.set_remove_session_callback(ngx_ssl_remove_session);

        // SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_session_cache_index, shm_zone)
        *ssl.data.session_cache.borrow_mut() = Some(zone.clone());
    }

    NGX_OK
}

/// ngx_ssl_session_id_context: the string, the server certificates and
/// the client CA list
fn ngx_ssl_session_id_context(ssl: &mut NgxSsl, sess_ctx: &[u8], certificates: Option<&Vec<Vec<u8>>>) -> i64 {
    let log = ssl.log.clone();

    let failed = |e: Option<ErrorStack>, what: &str| -> i64 {
        if let Some(e) = e {
            put(e);
        }
        ngx_ssl_error(NGX_LOG_EMERG, &log, 0, format_args!("{}", what));
        NGX_ERROR
    };

    let mut md = match Hasher::new(MessageDigest::sha1()) {
        Ok(h) => h,
        Err(e) => return failed(Some(e), "EVP_DigestInit_ex() failed"),
    };

    if let Err(e) = md.update(sess_ctx) {
        return failed(Some(e), "EVP_DigestUpdate() failed");
    }

    for cert in ssl.certs.iter() {
        let buf = match cert.digest(MessageDigest::sha1()) {
            Ok(d) => d,
            Err(e) => return failed(Some(e), "X509_digest() failed"),
        };

        if let Err(e) = md.update(&buf) {
            return failed(Some(e), "EVP_DigestUpdate() failed");
        }
    }

    if ssl.certs.is_empty() {
        if let Some(certs) = certificates {
            /*
             * If certificates are loaded dynamically, we use certificate
             * names as specified in the configuration (with variables).
             */

            for cert in certs.iter() {
                if let Err(e) = md.update(cert) {
                    return failed(Some(e), "EVP_DigestUpdate() failed");
                }
            }
        }
    }

    if let Some(list) = ssl.client_ca.as_ref() {
        for name in list.iter() {
            let buf = match sys::x509_name_digest(name, MessageDigest::sha1()) {
                Some(d) => d,
                None => return failed(None, "X509_NAME_digest() failed"),
            };

            if let Err(e) = md.update(&buf) {
                return failed(Some(e), "EVP_DigestUpdate() failed");
            }
        }
    }

    let buf = match md.finish() {
        Ok(d) => d,
        Err(e) => return failed(Some(e), "EVP_DigestFinal_ex() failed"),
    };

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    if let Err(e) = ctx.set_session_id_context(&buf) {
        return failed(Some(e), "SSL_CTX_set_session_id_context() failed");
    }

    NGX_OK
}

shm_struct! {
    /// ngx_ssl_sess_id_t (the ASN1 representation of the session is
    /// allocated apart, NGX_PTR_SIZE == 8)
    struct SessId {
        key: usize,
        left: usize,
        right: usize,
        parent: usize,
        color: u8,
        data: u8,
        len: usize,
        queue_prev: usize,
        queue_next: usize,
        expire: i64,
        id0: u64,
        id1: u64,
        id2: u64,
        id3: u64,
        session: usize,
    }
}

shm_struct! {
    /// ngx_ssl_session_cache_t up to its ticket keys: the rbtree, its
    /// sentinel node and the expire queue
    struct SessCache {
        rbtree_root: usize,
        rbtree_sentinel: usize,
        rbtree_insert: usize,
        sentinel_key: usize,
        sentinel_left: usize,
        sentinel_right: usize,
        sentinel_parent: usize,
        sentinel_color: u8,
        sentinel_data: u8,
        queue_prev: usize,
        queue_next: usize,
    }
}

shm_struct! {
    /// ngx_ssl_ticket_key_t (name[16], hmac_key[32], aes_key[32], expire,
    /// and the size:8 and shared:1 bit fields in an unsigned)
    struct ShmTicketKey {
        name0: u64,
        name1: u64,
        hmac0: u64,
        hmac1: u64,
        hmac2: u64,
        hmac3: u64,
        aes0: u64,
        aes1: u64,
        aes2: u64,
        aes3: u64,
        expire: i64,
        bits: u32,
    }
}

/// cache->ticket_keys
const TICKET_KEYS_OFF: usize = SessCache::SIZE;

/// cache->fail_time
const FAIL_TIME_OFF: usize = TICKET_KEYS_OFF + 3 * ShmTicketKey::SIZE;

/// sizeof(ngx_ssl_session_cache_t)
const SESSION_CACHE_SIZE: usize = FAIL_TIME_OFF + 8;

fn ticket_key_off(cache: usize, i: usize) -> usize {
    cache + TICKET_KEYS_OFF + i * ShmTicketKey::SIZE
}

fn ticket_key_read(mem: &ShmMem, off: usize) -> SslTicketKey {
    let k = ShmTicketKey::at(mem, off);
    let mut key = SslTicketKey::zeroed();

    mem.read(k.field(ShmTicketKey::name0), &mut key.name);
    mem.read(k.field(ShmTicketKey::hmac0), &mut key.hmac_key);
    mem.read(k.field(ShmTicketKey::aes0), &mut key.aes_key);

    key.expire = k.get(ShmTicketKey::expire);

    let bits = k.get(ShmTicketKey::bits);
    key.size = (bits & 0xff) as u8;
    key.shared = bits & 0x100 != 0;

    key
}

fn ticket_key_write(mem: &ShmMem, off: usize, key: &SslTicketKey) {
    let k = ShmTicketKey::at(mem, off);

    mem.write(k.field(ShmTicketKey::name0), &key.name);
    mem.write(k.field(ShmTicketKey::hmac0), &key.hmac_key);
    mem.write(k.field(ShmTicketKey::aes0), &key.aes_key);

    k.set(ShmTicketKey::expire, key.expire);
    k.set(ShmTicketKey::bits, key.size as u32 | (key.shared as u32) << 8);
}

/// shm_zone->data of a session cache zone: the zone's memory and the
/// offset of its ngx_ssl_session_cache_t
pub struct SslSessionCacheData {
    mem: RefCell<Option<Rc<ShmMem>>>,
    cache: Cell<usize>,
}

/// ngx_ssl_session_cache_init
pub fn ngx_ssl_session_cache_init(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn Any>>) -> Result<(), ()> {
    if let Some(d) = data {
        *shm_zone.data.borrow_mut() = Some(d);
        return Ok(());
    }

    let mem = shm_zone.mem();
    let shpool = SlabPool::of(&mem);

    if shm_zone.shm.exists.get() {
        let d: Rc<dyn Any> = Rc::new(SslSessionCacheData { mem: RefCell::new(Some(mem.clone())), cache: Cell::new(shpool.data()) });
        *shm_zone.data.borrow_mut() = Some(d);
        return Ok(());
    }

    let cache = shpool.alloc(SESSION_CACHE_SIZE);
    if cache == 0 {
        return Err(());
    }

    shpool.set_data(cache);

    let d: Rc<dyn Any> = Rc::new(SslSessionCacheData { mem: RefCell::new(Some(mem.clone())), cache: Cell::new(cache) });
    *shm_zone.data.borrow_mut() = Some(d);

    let c = SessCache::at(&mem, cache);

    ShmRbtree::at(&mem, c.field(SessCache::rbtree_root)).init(c.field(SessCache::sentinel_key));

    queue::init(&mem, c.field(SessCache::queue_prev));

    for i in 0..3 {
        ticket_key_write(&mem, ticket_key_off(cache, i), &SslTicketKey::zeroed());
    }

    mem.store::<i64>(cache + FAIL_TIME_OFF, 0);

    let ctx = format!(" in SSL session shared cache \"{}\"", B(shm_zone.name()));

    shpool.set_log_ctx(ctx.as_bytes())?;

    shpool.set_log_nomem(false);

    Ok(())
}

/// The memory and the offset of the session cache of a zone.
fn session_cache_of(zone: &ShmZone) -> Option<(Rc<ShmMem>, usize)> {
    let d = zone.data::<SslSessionCacheData>()?;
    let mem = d.mem.borrow().clone()?;
    Some((mem, d.cache.get()))
}

/// The session cache zone of the session context of a connection.
fn connection_session_cache(c: &Connection) -> Option<Rc<ShmZone>> {
    let sc = c.ssl.borrow().clone()?;
    let data = sc.state.session_data.borrow().clone()?;
    let zone = data.session_cache.borrow().clone();
    zone
}

/// &cache->session_rbtree
fn session_rbtree(mem: &ShmMem, cache: usize) -> ShmRbtree<'_> {
    ShmRbtree::at(mem, SessCache::at(mem, cache).field(SessCache::rbtree_root))
}

/// The session id of a node (sess_id->id, node->data bytes).
fn sess_id_bytes(tree: &ShmRbtree<'_>, node: usize) -> Vec<u8> {
    let s = SessId::at(tree.mem, node);
    tree.mem.bytes(s.field(SessId::id0), (tree.data(node) as usize).min(32))
}

/// ngx_memn2cmp
fn memn2cmp(s1: &[u8], s2: &[u8]) -> i32 {
    let n = s1.len().min(s2.len());
    for i in 0..n {
        if s1[i] != s2[i] {
            return s1[i] as i32 - s2[i] as i32;
        }
    }
    if s1.len() == s2.len() {
        0
    } else if s1.len() < s2.len() {
        -1
    } else {
        1
    }
}

/*
 * The length of the session id is 16 bytes for SSLv2 sessions and
 * between 1 and 32 bytes for SSLv3 and TLS, typically 32 bytes.
 * Typical length of the external ASN1 representation of a session
 * is about 150 bytes plus SNI server name.
 *
 * On 64-bit platforms we allocate separately an rbtree node + session_id,
 * and an ASN1 representation, they take accordingly 128 and 256 bytes.
 *
 * OpenSSL's i2d_SSL_SESSION() and d2i_SSL_SESSION are slow,
 * so they are outside the code locked by shared pool mutex
 */

/// ngx_ssl_new_session
fn ngx_ssl_new_session(ssl_conn: &mut SslRef, sess: SslSession) {
    /*
     * OpenSSL tries to save TLSv1.3 sessions into session cache
     * even when using tickets for stateless session resumption,
     * "because some applications just want to know about the creation
     * of a session"; do not cache such sessions
     */

    if ssl_conn.version2() == Some(SslVersion::TLS1_3) && (sys::options(ssl_conn) & sys::SSL_OP_NO_TICKET) == 0 {
        return;
    }

    let mut buffer = match sess.to_der() {
        Ok(b) => b,
        Err(e) => {
            put(e);
            return;
        }
    };

    /* do not cache too big session */

    if buffer.len() > NGX_SSL_MAX_SESSION_SIZE || buffer.is_empty() {
        return;
    }

    let len = buffer.len();

    let session_id = sess.id();

    /* do not cache sessions with too long session id */

    if session_id.len() > 32 {
        return;
    }

    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return,
    };

    let ssl_ctx = match c.ssl.borrow().as_ref().and_then(|sc| sc.state.session_ctx.borrow().clone()) {
        Some(ctx) => ctx,
        None => return,
    };

    let zone = match connection_session_cache(&c) {
        Some(z) => z,
        None => return,
    };

    let (mem, cache) = match session_cache_of(&zone) {
        Some(m) => m,
        None => return,
    };

    let shpool = SlabPool::of(&mem);

    shpool.lock();

    /* drop one or two expired sessions */
    ngx_ssl_expire_sessions(&mem, &shpool, cache, 1);

    let n = SessId::SIZE;

    let failed = 'failed: {
        let mut sess_id = shpool.alloc_locked(n);

        if sess_id == 0 {
            /* drop the oldest non-expired session and try once more */

            ngx_ssl_expire_sessions(&mem, &shpool, cache, 0);

            sess_id = shpool.alloc_locked(n);

            if sess_id == 0 {
                break 'failed Some(0);
            }
        }

        let s = SessId::at(&mem, sess_id);

        let mut session = shpool.alloc_locked(len);

        if session == 0 {
            /* drop the oldest non-expired session and try once more */

            ngx_ssl_expire_sessions(&mem, &shpool, cache, 0);

            session = shpool.alloc_locked(len);

            if session == 0 {
                break 'failed Some(sess_id);
            }
        }

        s.set(SessId::session, session);

        mem.write(session, &buffer);
        mem.write(s.field(SessId::id0), session_id);

        let hash = crc32fast::hash(session_id);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl new session: {:08X}:{}:{}", hash, session_id.len(), len);

        let tree = session_rbtree(&mem, cache);

        tree.set_key(sess_id, hash as usize);
        tree.set_data(sess_id, session_id.len() as u8);
        s.set(SessId::len, len);

        s.set(SessId::expire, crate::times::time() + sys::ctx_timeout(&ssl_ctx));

        queue::insert_head(&mem, SessCache::at(&mem, cache).field(SessCache::queue_prev), s.field(SessId::queue_prev));

        rb::insert(&tree, sess_id, ngx_ssl_session_rbtree_insert_value);

        None
    };

    if let Some(sess_id) = failed {
        if sess_id != 0 {
            shpool.free_locked(sess_id);
        }

        shpool.unlock();

        let now = crate::times::time();

        if mem.load::<i64>(cache + FAIL_TIME_OFF) != now {
            mem.store::<i64>(cache + FAIL_TIME_OFF, now);
            ngx_log_error!(NGX_LOG_WARN, c.log, None, "could not allocate new session{}", B(&shpool.log_ctx()));
        }

        return;
    }

    shpool.unlock();

    explicit_memzero(&mut buffer);
}

/// ngx_ssl_get_cached_session: the DER form of the session
fn ngx_ssl_get_cached_session(ssl_conn: &mut SslRef, id: &[u8]) -> Option<Vec<u8>> {
    let hash = crc32fast::hash(id);

    let c = ngx_ssl_get_connection(ssl_conn)?;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl get session: {:08X}:{}", hash, id.len());

    let zone = connection_session_cache(&c)?;
    let (mem, cache) = session_cache_of(&zone)?;

    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let tree = session_rbtree(&mem, cache);

    let mut node = tree.root();
    let sentinel = tree.sentinel();

    while node != sentinel {
        let key = tree.key(node);

        if (hash as usize) < key {
            node = tree.left(node);
            continue;
        }

        if (hash as usize) > key {
            node = tree.right(node);
            continue;
        }

        /* hash == node->key */

        let s = SessId::at(&mem, node);

        let rc = memn2cmp(id, &sess_id_bytes(&tree, node));

        if rc == 0 {
            if s.get(SessId::expire) > crate::times::time() {
                let buffer = mem.bytes(s.get(SessId::session), s.get(SessId::len));

                shpool.unlock();

                return Some(buffer);
            }

            queue::remove(&mem, s.field(SessId::queue_prev));

            rb::delete(&tree, node);

            mem.fill(s.get(SessId::session), s.get(SessId::len), 0);

            shpool.free_locked(s.get(SessId::session));
            shpool.free_locked(node);

            break;
        }

        node = if rc < 0 { tree.left(node) } else { tree.right(node) };
    }

    // done:

    shpool.unlock();

    None
}

/// ngx_ssl_remove_cached_session(c->ssl->session_ctx,
/// SSL_get0_session(c->ssl->connection)): the session of the connection
/// can't be resumed
pub fn ngx_ssl_remove_cached_session(c: &Connection) {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return,
    };

    let ctx = match sc.state.session_ctx.borrow().clone() {
        Some(ctx) => ctx,
        None => return,
    };

    let sess = match sc.with(|ssl| ssl.session().map(|s| s.to_owned())).flatten() {
        Some(s) => s,
        None => return,
    };

    sys::ctx_remove_session(&ctx, &sess);

    ngx_ssl_remove_session(&ctx, &sess);
}

/// ngx_ssl_remove_session
fn ngx_ssl_remove_session(ssl: &SslContextRef, sess: &SslSessionRef) {
    let zone = match ngx_ssl_ctx_data(ssl).and_then(|d| d.session_cache.borrow().clone()) {
        Some(z) => z,
        None => return,
    };

    let (mem, cache) = match session_cache_of(&zone) {
        Some(m) => m,
        None => return,
    };

    let id = sess.id();

    let hash = crc32fast::hash(id);

    if let Some(c) = crate::cycle::try_cycle() {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl remove session: {:08X}:{}", hash, id.len());
    }

    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let tree = session_rbtree(&mem, cache);

    let mut node = tree.root();
    let sentinel = tree.sentinel();

    while node != sentinel {
        let key = tree.key(node);

        if (hash as usize) < key {
            node = tree.left(node);
            continue;
        }

        if (hash as usize) > key {
            node = tree.right(node);
            continue;
        }

        /* hash == node->key */

        let s = SessId::at(&mem, node);

        let rc = memn2cmp(id, &sess_id_bytes(&tree, node));

        if rc == 0 {
            queue::remove(&mem, s.field(SessId::queue_prev));

            rb::delete(&tree, node);

            mem.fill(s.get(SessId::session), s.get(SessId::len), 0);

            shpool.free_locked(s.get(SessId::session));
            shpool.free_locked(node);

            break;
        }

        node = if rc < 0 { tree.left(node) } else { tree.right(node) };
    }

    // done:

    shpool.unlock();
}

/// ngx_ssl_expire_sessions
fn ngx_ssl_expire_sessions(mem: &ShmMem, shpool: &SlabPool<'_>, cache: usize, mut n: usize) {
    let now = crate::times::time();

    let head = SessCache::at(mem, cache).field(SessCache::queue_prev);
    let tree = session_rbtree(mem, cache);

    while n < 3 {
        if queue::empty(mem, head) {
            return;
        }

        let q = queue::last(mem, head);

        let node = q - SessId::queue_prev.off;
        let s = SessId::at(mem, node);

        let first = n == 0;
        n += 1;

        if !first && s.get(SessId::expire) > now {
            return;
        }

        queue::remove(mem, q);

        if let Some(c) = crate::cycle::try_cycle() {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "expire session: {:08X}", tree.key(node));
        }

        rb::delete(&tree, node);

        mem.fill(s.get(SessId::session), s.get(SessId::len), 0);

        shpool.free_locked(s.get(SessId::session));
        shpool.free_locked(node);
    }
}

/// ngx_ssl_session_rbtree_insert_value
fn ngx_ssl_session_rbtree_insert_value(tree: &ShmRbtree<'_>, temp: usize, node: usize, sentinel: usize) {
    rb::insert_by(tree, temp, node, sentinel, |t, node, temp| {
        let (nk, tk) = (t.key(node), t.key(temp));

        if nk != tk {
            return nk < tk;
        }

        /* node->key == temp->key */

        memn2cmp(&sess_id_bytes(t, node), &sess_id_bytes(t, temp)) < 0
    });
}

// --- session tickets ---

/// ngx_ssl_session_ticket_keys
pub fn ngx_ssl_session_ticket_keys(cf: &mut Conf, ssl: &mut NgxSsl, paths: Option<&mut Vec<Vec<u8>>>) -> i64 {
    if paths.is_none() && ssl.data.session_cache.borrow().is_none() {
        return NGX_OK;
    }

    // SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_ticket_keys_index, keys)
    *ssl.data.ticket_keys.borrow_mut() = Some(SslTicketKeys { keys: Vec::with_capacity(paths.as_ref().map(|p| p.len()).unwrap_or(3)) });

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    if !sys::ctx_set_ticket_key_callback::<TicketKeyCb>(ctx) {
        ngx_log_error!(
            NGX_LOG_WARN,
            cf.log,
            None,
            "nginx was built with Session Tickets support, however, now it is linked dynamically to an OpenSSL library which has no tlsext support, therefore Session Tickets are not available"
        );
        return NGX_OK;
    }

    let paths = match paths {
        None => {
            /* placeholder for keys in shared memory */

            if let Some(keys) = ssl.data.ticket_keys.borrow_mut().as_mut() {
                for _ in 0..3 {
                    let mut key = SslTicketKey::zeroed();
                    key.shared = true;
                    key.expire = 0;
                    keys.keys.push(key);
                }
            }

            return NGX_OK;
        }
        Some(p) => p,
    };

    for path in paths.iter_mut() {
        *path = cf.full_name(path, true);

        let fd = match crate::os::open(path, libc::O_RDONLY, 0) {
            Ok(fd) => fd,
            Err(e) => {
                cf.log_error(NGX_LOG_EMERG, Some(e), format_args!("open() \"{}\" failed", B(path)));
                return NGX_ERROR;
            }
        };

        let mut buf = [0u8; 80];

        let ok = 'failed: {
            let st = match crate::os::fstat(fd) {
                Ok(st) => st,
                Err(e) => {
                    cf.log_error(NGX_LOG_CRIT, Some(e), format_args!("fstat() \"{}\" failed", B(path)));
                    break 'failed false;
                }
            };

            let size = st.st_size as usize;

            if size != 48 && size != 80 {
                cf.log_error(NGX_LOG_EMERG, None, format_args!("\"{}\" must be 48 or 80 bytes", B(path)));
                break 'failed false;
            }

            let n = match crate::os::pread(fd, &mut buf[..size], 0) {
                Ok(n) => n,
                Err(e) => {
                    cf.log_error(NGX_LOG_CRIT, Some(e), format_args!("pread() \"{}\" failed", B(path)));
                    break 'failed false;
                }
            };

            if n != size {
                cf.log_error(NGX_LOG_CRIT, None, format_args!("pread() \"{}\" returned only {} bytes instead of {}", B(path), n, size));
                break 'failed false;
            }

            let mut key = SslTicketKey::zeroed();

            key.shared = false;
            key.expire = 1;

            if size == 48 {
                key.size = 48;
                key.name.copy_from_slice(&buf[0..16]);
                key.aes_key[..16].copy_from_slice(&buf[16..32]);
                key.hmac_key[..16].copy_from_slice(&buf[32..48]);
            } else {
                key.size = 80;
                key.name.copy_from_slice(&buf[0..16]);
                key.hmac_key.copy_from_slice(&buf[16..48]);
                key.aes_key.copy_from_slice(&buf[48..80]);
            }

            if let Some(keys) = ssl.data.ticket_keys.borrow_mut().as_mut() {
                keys.keys.push(key);
            }

            true
        };

        if let Err(e) = crate::os::close_fd(fd) {
            ngx_log_error!(NGX_LOG_ALERT, cf.log, Some(e), "close() \"{}\" failed", B(path));
        }

        explicit_memzero(&mut buf);

        if !ok {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_ticket_key_callback
fn ngx_ssl_ticket_key_callback(ssl_conn: &mut SslRef, tk: &mut sys::TicketKeyCtx<'_>, enc: bool) -> i32 {
    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return -1,
    };

    let (ssl_ctx, data) = match c.ssl.borrow().as_ref() {
        Some(sc) => match (sc.state.session_ctx.borrow().clone(), sc.state.session_data.borrow().clone()) {
            (Some(ctx), Some(data)) => (ctx, data),
            _ => return -1,
        },
        None => return -1,
    };

    if ngx_ssl_rotate_ticket_keys(&ssl_ctx, &data, &c.log) != NGX_OK {
        return -1;
    }

    let digest = openssl::md::Md::sha256();

    let keys = data.ticket_keys.borrow();

    let keys = match keys.as_ref() {
        Some(k) if !k.keys.is_empty() => &k.keys,
        _ => return -1,
    };

    if enc {
        /* encrypt session ticket */

        let mut hex = Vec::new();
        hex_dump(&mut hex, &keys[0].name);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ticket encrypt, key: \"{}\" ({} session)", B(&hex), if ssl_conn.session_reused() { "reused" } else { "new" });

        let (cipher, size) = if keys[0].size == 48 { (openssl::cipher::Cipher::aes_128_cbc(), 16) } else { (openssl::cipher::Cipher::aes_256_cbc(), 32) };

        let mut iv = [0u8; 16];
        let iv_len = cipher.iv_length().min(16);

        if let Err(e) = openssl::rand::rand_bytes(&mut iv[..iv_len]) {
            put(e);
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("RAND_bytes() failed"));
            return -1;
        }

        tk.set_iv(&iv[..iv_len]);

        if !tk.cipher_init(cipher, &keys[0].aes_key, true) {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("EVP_EncryptInit_ex() failed"));
            return -1;
        }

        if !tk.hmac_init(&keys[0].hmac_key[..size], digest) {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("HMAC_Init_ex() failed"));
            return -1;
        }

        tk.set_name(&keys[0].name);

        1
    } else {
        /* decrypt session ticket */

        let tname = tk.name();

        let i = match keys.iter().position(|k| k.name == tname) {
            Some(i) => i,
            None => {
                let mut hex = Vec::new();
                hex_dump(&mut hex, &tname);

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ticket decrypt, key: \"{}\" not found", B(&hex));

                return 0;
            }
        };

        // found:

        let mut hex = Vec::new();
        hex_dump(&mut hex, &keys[i].name);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ticket decrypt, key: \"{}\"{}", B(&hex), if i == 0 { " (default)" } else { "" });

        let (cipher, size) = if keys[i].size == 48 { (openssl::cipher::Cipher::aes_128_cbc(), 16) } else { (openssl::cipher::Cipher::aes_256_cbc(), 32) };

        if !tk.hmac_init(&keys[i].hmac_key[..size], digest) {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("HMAC_Init_ex() failed"));
            return -1;
        }

        if !tk.cipher_init(cipher, &keys[i].aes_key, false) {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("EVP_DecryptInit_ex() failed"));
            return -1;
        }

        /* renew if TLSv1.3 */

        if ssl_conn.version2() == Some(SslVersion::TLS1_3) {
            return 2;
        }

        /* renew if non-default key */

        if i != 0 && keys[i].expire != 0 {
            return 2;
        }

        1
    }
}

/// ngx_ssl_rotate_ticket_keys: the keys in the shared memory of the
/// session cache
fn ngx_ssl_rotate_ticket_keys(ssl_ctx: &SslContextRef, data: &SslCtxData, log: &Log) -> i64 {
    let mut keys_ref = data.ticket_keys.borrow_mut();

    let keys = match keys_ref.as_mut() {
        Some(k) => &mut k.keys,
        None => return NGX_OK,
    };

    if keys.len() < 2 || !keys[0].shared {
        return NGX_OK;
    }

    /*
     * if we don't need to update expiration of the current key
     * and the previous key is still needed, don't sync with shared
     * memory to save some work; in the worst case other worker process
     * will switch to the next key, but this process will still be able
     * to decrypt tickets encrypted with it
     */

    let now = crate::times::time();
    let expire = now + sys::ctx_timeout(ssl_ctx);

    if keys[0].expire >= expire && keys[1].expire >= now {
        return NGX_OK;
    }

    let zone = match data.session_cache.borrow().clone() {
        Some(z) => z,
        None => return NGX_OK,
    };

    let (mem, cache) = match session_cache_of(&zone) {
        Some(m) => m,
        None => return NGX_OK,
    };

    let shpool = SlabPool::of(&mem);

    shpool.lock();

    let mut key = [ticket_key_read(&mem, ticket_key_off(cache, 0)), ticket_key_read(&mem, ticket_key_off(cache, 1)), ticket_key_read(&mem, ticket_key_off(cache, 2))];

    let mut buf = [0u8; 80];

    let rc = 'done: {
        if key[0].expire == 0 {
            /* initialize the current key */

            if let Err(e) = openssl::rand::rand_bytes(&mut buf) {
                put(e);
                ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("RAND_bytes() failed"));
                break 'done NGX_ERROR;
            }

            key[0].shared = true;
            key[0].expire = expire;
            key[0].size = 80;
            key[0].name.copy_from_slice(&buf[0..16]);
            key[0].hmac_key.copy_from_slice(&buf[16..48]);
            key[0].aes_key.copy_from_slice(&buf[48..80]);

            explicit_memzero(&mut buf);

            let mut hex = Vec::new();
            hex_dump(&mut hex, &key[0].name);

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "ssl ticket key: \"{}\"", B(&hex));

            /*
             * copy the current key to the next key, as initialization of
             * the previous key will replace the current key with the next
             * key
             */

            key[2] = key[0];
        }

        if key[1].expire < now {
            /*
             * if the previous key is no longer needed (or not initialized),
             * replace it with the current key, replace the current key with
             * the next key, and generate new next key
             */

            key[1] = key[0];
            key[0] = key[2];

            if let Err(e) = openssl::rand::rand_bytes(&mut buf) {
                put(e);
                ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("RAND_bytes() failed"));
                break 'done NGX_ERROR;
            }

            key[2].shared = true;
            key[2].expire = 0;
            key[2].size = 80;
            key[2].name.copy_from_slice(&buf[0..16]);
            key[2].hmac_key.copy_from_slice(&buf[16..48]);
            key[2].aes_key.copy_from_slice(&buf[48..80]);

            explicit_memzero(&mut buf);

            let mut hex = Vec::new();
            hex_dump(&mut hex, &key[2].name);

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "ssl ticket key: \"{}\"", B(&hex));
        }

        /*
         * update expiration of the current key: it is going to be needed
         * at least till the session being created expires
         */

        if expire > key[0].expire {
            key[0].expire = expire;
        }

        /* sync keys to the worker process memory */

        keys[0] = key[0];
        keys[1] = key[1];

        NGX_OK
    };

    // the keys of the zone as C leaves them (changed in place up to an
    // error)
    for (i, k) in key.iter().enumerate() {
        ticket_key_write(&mem, ticket_key_off(cache, i), k);
    }

    shpool.unlock();

    for k in key.iter_mut() {
        explicit_memzero(&mut k.name);
        explicit_memzero(&mut k.hmac_key);
        explicit_memzero(&mut k.aes_key);
    }

    rc
}

/// ngx_ssl_cleanup_ctx
pub fn ngx_ssl_cleanup_ctx(ssl: &mut NgxSsl) {
    ssl.certs.clear();
    ssl.ctx = SslCtx::new();
}

/// ngx_ssl_check_host: the certificate of the peer matches the name
pub fn ngx_ssl_check_host(c: &Connection, name: &[u8]) -> i64 {
    let cert = match ngx_ssl_with(c, |ssl| ssl.peer_certificate()).flatten() {
        Some(cert) => cert,
        None => return NGX_ERROR,
    };

    /* X509_check_host() is only available in OpenSSL 1.0.2+ */

    if name.is_empty() {
        return NGX_ERROR;
    }

    if sys::x509_check_host(&cert, name) != 1 {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "X509_check_host(): no match");
        return NGX_ERROR;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "X509_check_host(): match");

    NGX_OK
}

// --- the connection variables ---

/// ngx_ssl_variable_handler_pt: the value of an SSL variable of a
/// connection with SSL
pub type SslVariableHandler = fn(c: &Connection, s: &mut Vec<u8>) -> i64;

/// ngx_ssl_get_protocol
pub fn ngx_ssl_get_protocol(c: &Connection, s: &mut Vec<u8>) -> i64 {
    *s = ngx_ssl_with(c, |ssl| ssl.version_str().as_bytes().to_vec()).unwrap_or_default();
    NGX_OK
}

/// ngx_ssl_get_cipher_name
pub fn ngx_ssl_get_cipher_name(c: &Connection, s: &mut Vec<u8>) -> i64 {
    // SSL_get_cipher_name(): "(NONE)" without a cipher
    *s = ngx_ssl_with(c, |ssl| ssl.current_cipher().map(|cipher| cipher.name()).unwrap_or("(NONE)").as_bytes().to_vec()).unwrap_or_default();
    NGX_OK
}

/// ngx_ssl_get_ciphers
pub fn ngx_ssl_get_ciphers(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    ngx_ssl_with(c, |ssl| {
        let (bytes, ciphers) = match sys::raw_cipherlist(ssl) {
            Some(l) => l,
            None => return,
        };

        let n = ciphers.len() / bytes;

        for i in 0..n {
            let p = &ciphers[i * bytes..(i + 1) * bytes];

            match sys::cipher_find(ssl, p) {
                Some(cipher) => s.extend_from_slice(cipher.name().as_bytes()),
                None => {
                    s.extend_from_slice(b"0x");
                    hex_dump(s, p);
                }
            }

            s.push(b':');
        }

        s.pop();
    });

    NGX_OK
}

/// OBJ_nid2sn()
fn nid_short_name(nid: i32) -> &'static str {
    Nid::from_raw(nid).short_name().unwrap_or("")
}

fn group_name(ssl: &SslRef, nid: i32, s: &mut Vec<u8>) {
    match sys::group_to_name(ssl, nid) {
        Some(name) => s.extend_from_slice(&name),
        None => s.extend_from_slice(format!("0x{:04x}", nid & 0xffff).as_bytes()),
    }
}

/// ngx_ssl_get_curve
pub fn ngx_ssl_get_curve(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    ngx_ssl_with(c, |ssl| {
        let nid = sys::negotiated_group(ssl);

        if nid != sys::NID_undef {
            if (nid & sys::TLSEXT_nid_unknown) == 0 {
                s.extend_from_slice(nid_short_name(nid).as_bytes());
                return;
            }

            group_name(ssl, nid, s);
        }
    });

    NGX_OK
}

/// ngx_ssl_get_curves
pub fn ngx_ssl_get_curves(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    ngx_ssl_with(c, |ssl| {
        let curves = sys::peer_curves(ssl);

        if curves.is_empty() {
            return;
        }

        for &nid in curves.iter() {
            if nid & sys::TLSEXT_nid_unknown != 0 {
                group_name(ssl, nid, s);
            } else {
                s.extend_from_slice(nid_short_name(nid).as_bytes());
            }

            s.push(b':');
        }

        s.pop();
    });

    NGX_OK
}

/// ngx_ssl_get_sigalg: SSL_get0_signature_name() is not available with
/// this OpenSSL, the value is empty as in C
pub fn ngx_ssl_get_sigalg(_c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();
    NGX_OK
}

/// ngx_ssl_get_sigalgs: SSL_get_sigalgs() uses a different naming, so
/// the raw codes are emitted
pub fn ngx_ssl_get_sigalgs(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    ngx_ssl_with(c, |ssl| {
        let sigalgs = sys::peer_sigalgs(ssl);

        if sigalgs.is_empty() {
            return;
        }

        for (rsig, rhash) in sigalgs {
            s.extend_from_slice(format!("0x{:04x}", ((rhash as u32) << 8) | rsig as u32).as_bytes());
            s.push(b':');
        }

        s.pop();
    });

    NGX_OK
}

/// ngx_ssl_get_session_id
pub fn ngx_ssl_get_session_id(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    ngx_ssl_with(c, |ssl| {
        if let Some(sess) = ssl.session() {
            hex_dump(s, sess.id());
        }
    });

    NGX_OK
}

/// ngx_ssl_get_session_reused
pub fn ngx_ssl_get_session_reused(c: &Connection, s: &mut Vec<u8>) -> i64 {
    *s = if ngx_ssl_session_reused(c) { b"r".to_vec() } else { b".".to_vec() };
    NGX_OK
}

/// ngx_ssl_get_early_data
pub fn ngx_ssl_get_early_data(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    /* OpenSSL */

    if ngx_ssl_with(c, |ssl| !ssl.is_init_finished()).unwrap_or(false) {
        s.extend_from_slice(b"1");
    }

    NGX_OK
}

/// ngx_ssl_get_server_name
pub fn ngx_ssl_get_server_name(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    ngx_ssl_with(c, |ssl| {
        if let Some(name) = ssl.servername_raw(NameType::HOST_NAME) {
            s.extend_from_slice(name);
        }
    });

    NGX_OK
}

/// ngx_ssl_get_ech_status: ECH is not available with this OpenSSL
pub fn ngx_ssl_get_ech_status(_c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();
    NGX_OK
}

/// ngx_ssl_get_ech_outer_server_name: ECH is not available with this
/// OpenSSL
pub fn ngx_ssl_get_ech_outer_server_name(_c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();
    NGX_OK
}

/// ngx_ssl_get_alpn_protocol
pub fn ngx_ssl_get_alpn_protocol(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    ngx_ssl_with(c, |ssl| {
        if let Some(p) = ssl.selected_alpn_protocol() {
            s.extend_from_slice(p);
        }
    });

    NGX_OK
}

/// SSL_get_peer_certificate()
fn peer_certificate(c: &Connection) -> Option<X509> {
    ngx_ssl_with(c, |ssl| ssl.peer_certificate()).flatten()
}

/// ngx_ssl_get_raw_certificate
pub fn ngx_ssl_get_raw_certificate(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    let cert = match peer_certificate(c) {
        Some(cert) => cert,
        None => return NGX_OK,
    };

    match cert.to_pem() {
        Ok(pem) => *s = pem,
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("PEM_write_bio_X509() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_get_certificate: the PEM certificate with the lines after the
/// first one prefixed with a tab
pub fn ngx_ssl_get_certificate(c: &Connection, s: &mut Vec<u8>) -> i64 {
    let mut cert = Vec::new();

    if ngx_ssl_get_raw_certificate(c, &mut cert) != NGX_OK {
        return NGX_ERROR;
    }

    s.clear();

    if cert.is_empty() {
        return NGX_OK;
    }

    for &ch in cert[..cert.len() - 1].iter() {
        s.push(ch);
        if ch == b'\n' {
            s.push(b'\t');
        }
    }

    NGX_OK
}

/// ngx_ssl_get_escaped_certificate
pub fn ngx_ssl_get_escaped_certificate(c: &Connection, s: &mut Vec<u8>) -> i64 {
    let mut cert = Vec::new();

    if ngx_ssl_get_raw_certificate(c, &mut cert) != NGX_OK {
        return NGX_ERROR;
    }

    s.clear();

    if cert.is_empty() {
        return NGX_OK;
    }

    *s = crate::string::escape_uri(&cert, crate::string::NGX_ESCAPE_URI_COMPONENT);

    NGX_OK
}

fn get_dn(c: &Connection, s: &mut Vec<u8>, issuer: bool) -> i64 {
    s.clear();

    let cert = match peer_certificate(c) {
        Some(cert) => cert,
        None => return NGX_OK,
    };

    let name = if issuer { cert.issuer_name() } else { cert.subject_name() };

    match sys::x509_name_print_ex(name, sys::XN_FLAG_RFC2253) {
        Ok(v) => *s = v,
        Err(sys::PrintError::Bio) => {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("BIO_new() failed"));
            return NGX_ERROR;
        }
        Err(sys::PrintError::Print) => {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_NAME_print_ex() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_get_subject_dn
pub fn ngx_ssl_get_subject_dn(c: &Connection, s: &mut Vec<u8>) -> i64 {
    get_dn(c, s, false)
}

/// ngx_ssl_get_issuer_dn
pub fn ngx_ssl_get_issuer_dn(c: &Connection, s: &mut Vec<u8>) -> i64 {
    get_dn(c, s, true)
}

fn get_dn_legacy(c: &Connection, s: &mut Vec<u8>, issuer: bool) -> i64 {
    s.clear();

    let cert = match peer_certificate(c) {
        Some(cert) => cert,
        None => return NGX_OK,
    };

    let name = if issuer { cert.issuer_name() } else { cert.subject_name() };

    match sys::x509_name_oneline(name) {
        Some(v) => *s = v,
        None => {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_NAME_oneline() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_get_subject_dn_legacy
pub fn ngx_ssl_get_subject_dn_legacy(c: &Connection, s: &mut Vec<u8>) -> i64 {
    get_dn_legacy(c, s, false)
}

/// ngx_ssl_get_issuer_dn_legacy
pub fn ngx_ssl_get_issuer_dn_legacy(c: &Connection, s: &mut Vec<u8>) -> i64 {
    get_dn_legacy(c, s, true)
}

/// ngx_ssl_get_serial_number
pub fn ngx_ssl_get_serial_number(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    let cert = match peer_certificate(c) {
        Some(cert) => cert,
        None => return NGX_OK,
    };

    match sys::asn1_integer_print(cert.serial_number()) {
        Some(v) => *s = v,
        None => {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("BIO_new() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_get_fingerprint
pub fn ngx_ssl_get_fingerprint(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    let cert = match peer_certificate(c) {
        Some(cert) => cert,
        None => return NGX_OK,
    };

    match cert.digest(MessageDigest::sha1()) {
        Ok(d) => hex_dump(s, &d),
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_digest() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_get_client_verify
pub fn ngx_ssl_get_client_verify(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    if peer_certificate(c).is_none() {
        s.extend_from_slice(b"NONE");
        return NGX_OK;
    }

    let rc = match ngx_ssl_with(c, |ssl| ssl.verify_result()) {
        Some(rc) => rc,
        None => return NGX_OK,
    };

    let str: Vec<u8>;

    if rc.as_raw() as i64 == X509_V_OK {
        match crate::event_openssl_stapling::ngx_ssl_ocsp_get_status(c) {
            Ok(()) => {
                s.extend_from_slice(b"SUCCESS");
                return NGX_OK;
            }
            Err(e) => str = e.as_bytes().to_vec(),
        }
    } else {
        str = rc.error_string().as_bytes().to_vec();
    }

    s.extend_from_slice(b"FAILED:");
    s.extend_from_slice(&str);

    NGX_OK
}

fn get_validity(c: &Connection, s: &mut Vec<u8>, end: bool) -> i64 {
    s.clear();

    let cert = match peer_certificate(c) {
        Some(cert) => cert,
        None => return NGX_OK,
    };

    match sys::asn1_time_print(if end { cert.not_after() } else { cert.not_before() }) {
        Some(v) => *s = v,
        None => {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("BIO_new() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_get_client_v_start
pub fn ngx_ssl_get_client_v_start(c: &Connection, s: &mut Vec<u8>) -> i64 {
    get_validity(c, s, false)
}

/// ngx_ssl_get_client_v_end
pub fn ngx_ssl_get_client_v_end(c: &Connection, s: &mut Vec<u8>) -> i64 {
    get_validity(c, s, true)
}

/// ngx_ssl_get_client_v_remain
pub fn ngx_ssl_get_client_v_remain(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    let cert = match peer_certificate(c) {
        Some(cert) => cert,
        None => return NGX_OK,
    };

    let end = match ngx_ssl_parse_time(cert.not_after(), &c.log) {
        Some(e) => e,
        None => return NGX_OK,
    };

    let now = crate::times::time();

    if end < now + 86400 {
        s.extend_from_slice(b"0");
        return NGX_OK;
    }

    s.extend_from_slice(((end - now) / 86400).to_string().as_bytes());

    NGX_OK
}

/// ngx_ssl_parse_time: ASN1_TIME_print() output ("MMM DD HH:MM:SS YYYY
/// [GMT]") parsed as an asctime() date
fn ngx_ssl_parse_time(asn1time: &openssl::asn1::Asn1TimeRef, log: &Log) -> Option<i64> {
    let printed = match sys::asn1_time_print(asn1time) {
        Some(v) => v,
        None => {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("BIO_new() failed"));
            return None;
        }
    };

    /* fake weekday prepended to match C asctime() format */

    let mut value = b"Tue ".to_vec();
    value.extend_from_slice(&printed);

    crate::parse::parse_http_time(&value)
}

/// ngx_ssl_get_client_sigalg: SSL_get0_peer_signature_name() is not
/// available with this OpenSSL, the value is empty as in C
pub fn ngx_ssl_get_client_sigalg(_c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();
    NGX_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_queue_is_formatted_and_emptied() {
        ngx_ssl_init(&Log::stderr(NGX_LOG_NOTICE));

        assert!(sys::Bio::new_file(c"/nonexistent/file.pem", c"r").is_none());
        assert!(sys::err_peek_error() != 0);

        let log = Log::stderr(NGX_LOG_EMERG);
        ngx_ssl_error(NGX_LOG_DEBUG, &log, 0, format_args!("test"));

        assert_eq!(sys::err_peek_error(), 0);
    }

    #[test]
    fn memn2cmp_orders_as_c() {
        assert_eq!(memn2cmp(b"abc", b"abc"), 0);
        assert!(memn2cmp(b"ab", b"abc") < 0);
        assert!(memn2cmp(b"abd", b"abc") > 0);
    }

    #[test]
    fn verify_error_optional() {
        assert!(ngx_ssl_verify_error_optional(sys::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT));
        assert!(!ngx_ssl_verify_error_optional(X509_V_OK));
    }

    #[test]
    fn hex_is_lowercase() {
        let mut v = Vec::new();
        hex_dump(&mut v, &[0xab, 0x01]);
        assert_eq!(v, b"ab01");
    }

    #[test]
    fn ticket_key_layout() {
        // sizeof of the C structures (64-bit)
        assert_eq!(SessId::SIZE, 112);
        assert_eq!(SessCache::SIZE, 80);
        assert_eq!(ShmTicketKey::SIZE, 96);
        assert_eq!(SESSION_CACHE_SIZE, 376);

        let mem = ShmMem::private(4096).unwrap();

        let mut key = SslTicketKey::zeroed();
        key.name = [1; 16];
        key.hmac_key = [2; 32];
        key.aes_key = [3; 32];
        key.expire = 12345;
        key.size = 80;
        key.shared = true;

        ticket_key_write(&mem, 256, &key);

        let k = ticket_key_read(&mem, 256);
        assert_eq!(k.name, key.name);
        assert_eq!(k.hmac_key, key.hmac_key);
        assert_eq!(k.aes_key, key.aes_key);
        assert_eq!(k.expire, 12345);
        assert_eq!(k.size, 80);
        assert!(k.shared);
    }

    /// A context with a self-signed EC certificate for "localhost".
    fn server_ssl(log: &Log) -> NgxSsl {
        server_ssl_with(log, NGX_SSL_DEFAULT_PROTOCOLS, NGX_SSL_DFLT_BUILTIN_SCACHE, None)
    }

    /// The same, with the protocols and session cache given.
    fn server_ssl_with(log: &Log, protocols: u32, builtin: isize, zone: Option<&Rc<ShmZone>>) -> NgxSsl {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let mut ssl = NgxSsl::new(log.clone());
        assert_eq!(ngx_ssl_create(&mut ssl, protocols, None), NGX_OK);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "localhost").unwrap();
        let name = name.build();

        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap()).unwrap();
        b.sign(&key, openssl::hash::MessageDigest::sha256()).unwrap();
        let cert = b.build();

        {
            let ctx = ssl.ctx.builder_mut().unwrap();
            ctx.set_certificate(&cert).unwrap();
            ctx.set_private_key(&key).unwrap();
        }

        assert_eq!(ngx_ssl_session_cache(&mut ssl, b"TEST", None, builtin, zone, 300), NGX_OK);

        ssl
    }

    /// A session cache zone, its slab pool initialized and the cache made
    /// by the zone init.
    fn session_zone() -> Rc<ShmZone> {
        let mem = Rc::new(ShmMem::private(1 << 19).unwrap());
        SlabPool::init_zone(&mem);

        let zone = ShmZone::new(b"SSL".to_vec(), mem.len(), "ngx_http_ssl_module");
        zone.shm.attach(mem);

        ngx_ssl_session_cache_init(&zone, None).unwrap();

        zone
    }

    /// The sessions in the cache of the zone.
    fn cached_sessions(zone: &ShmZone) -> usize {
        let (mem, cache) = session_cache_of(zone).unwrap();
        rb::walk(&session_rbtree(&mem, cache)).len()
    }

    #[test]
    fn shared_session_cache() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();

        local.block_on(&rt, async {
            let log = Log::stderr(NGX_LOG_EMERG);

            let zone = session_zone();

            // TLSv1.2 sessions resumed by their id: in the shared cache only
            let mut server = server_ssl_with(&log, NGX_SSL_TLSV1_2, NGX_SSL_NO_BUILTIN_SCACHE, Some(&zone));
            ngx_ssl_set_options(&mut server, sys::SSL_OP_NO_TICKET);

            let mut client = NgxSsl::new(log.clone());
            assert_eq!(ngx_ssl_create(&mut client, NGX_SSL_TLSV1_2, None), NGX_OK);

            {
                let ctx = client.ctx.builder_mut().unwrap();
                ctx.set_session_cache_mode(SslSessionCacheMode::from_bits_retain((sys::SSL_SESS_CACHE_CLIENT | sys::SSL_SESS_CACHE_NO_INTERNAL) as _));
                ctx.set_new_session_callback(ngx_ssl_new_client_session);
            }

            let saved: Rc<RefCell<Option<SslSession>>> = Rc::new(RefCell::new(None));

            for round in 0..3 {
                let (s, c) = pair(&log);

                assert_eq!(ngx_ssl_create_connection(&server, &s, 0), NGX_OK);
                assert_eq!(ngx_ssl_create_connection(&client, &c, NGX_SSL_CLIENT), NGX_OK);

                assert_eq!(ngx_ssl_set_session(&c, saved.borrow().as_deref()), NGX_OK);

                let save = saved.clone();
                ngx_ssl_set_save_session(&c, Some(Rc::new(move |c: &Connection| *save.borrow_mut() = ngx_ssl_get_session(c))));

                let (rs, rc) = tokio::join!(handshake(&s), handshake(&c));
                assert_eq!((rs, rc), (NGX_OK, NGX_OK));

                // found in the shared cache the second time, removed then
                assert_eq!(ngx_ssl_session_reused(&s), round == 1, "round {}", round);
                assert_eq!(ngx_ssl_session_reused(&c), round == 1, "round {}", round);

                assert_eq!(cached_sessions(&zone), 1);

                if round == 1 {
                    // a client certificate failed: the session can't be
                    // resumed
                    ngx_ssl_remove_cached_session(&s);
                    assert_eq!(cached_sessions(&zone), 0);
                }

                if round == 2 {
                    // a new session was cached instead
                    assert_eq!(cached_sessions(&zone), 1);
                }

                c.ssl.borrow().as_ref().unwrap().no_wait_shutdown.set(true);
                assert_eq!(ngx_ssl_shutdown(&c), NGX_OK);
                s.ssl.borrow().as_ref().unwrap().no_wait_shutdown.set(true);
                assert_eq!(ngx_ssl_shutdown(&s), NGX_OK);
            }
        });
    }

    fn pair(log: &Log) -> (Rc<Connection>, Rc<Connection>) {
        let (a, b) = rustix::net::socketpair(rustix::net::AddressFamily::UNIX, rustix::net::SocketType::STREAM, rustix::net::SocketFlags::NONBLOCK, None).unwrap();

        let a = Connection::peer(crate::fd::register(a), libc::SOCK_STREAM, crate::inet::SockAddr::Unix(b"a".to_vec()), log).unwrap();
        let b = Connection::peer(crate::fd::register(b), libc::SOCK_STREAM, crate::inet::SockAddr::Unix(b"b".to_vec()), log).unwrap();

        (a, b)
    }

    async fn handshake(c: &Connection) -> i64 {
        let rc = ngx_ssl_handshake(c);
        if rc != NGX_AGAIN {
            return rc;
        }
        ngx_ssl_handshake_wait(c).await
    }

    #[test]
    fn client_server() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();

        local.block_on(&rt, async {
            let log = Log::stderr(NGX_LOG_EMERG);

            let server = server_ssl(&log);

            let mut client = NgxSsl::new(log.clone());
            assert_eq!(ngx_ssl_create(&mut client, NGX_SSL_DEFAULT_PROTOCOLS, None), NGX_OK);

            // the sessions are saved by the new session callback
            // (ngx_ssl_client_session_cache())
            {
                let ctx = client.ctx.builder_mut().unwrap();
                ctx.set_session_cache_mode(SslSessionCacheMode::from_bits_retain((sys::SSL_SESS_CACHE_CLIENT | sys::SSL_SESS_CACHE_NO_INTERNAL) as _));
                ctx.set_new_session_callback(ngx_ssl_new_client_session);
            }

            let saved: Rc<RefCell<Option<SslSession>>> = Rc::new(RefCell::new(None));

            for round in 0..2 {
                let (s, c) = pair(&log);

                assert_eq!(ngx_ssl_create_connection(&server, &s, 0), NGX_OK);
                assert_eq!(ngx_ssl_create_connection(&client, &c, NGX_SSL_BUFFER | NGX_SSL_CLIENT), NGX_OK);

                assert!(ngx_ssl_set_tlsext_host_name(&c, b"localhost"));
                assert_eq!(ngx_ssl_set_session(&c, saved.borrow().as_deref()), NGX_OK);

                let save = saved.clone();
                ngx_ssl_set_save_session(&c, Some(Rc::new(move |c: &Connection| *save.borrow_mut() = ngx_ssl_get_session(c))));

                let (rs, rc) = tokio::join!(handshake(&s), handshake(&c));
                assert_eq!((rs, rc), (NGX_OK, NGX_OK));

                let mut v = Vec::new();
                ngx_ssl_get_server_name(&s, &mut v);
                assert_eq!(v, b"localhost");

                ngx_ssl_get_protocol(&s, &mut v);
                assert_eq!(v, b"TLSv1.3");

                // not trusted, but the name matches
                assert_ne!(ngx_ssl_get_verify_result(&c), X509_V_OK);
                assert_eq!(ngx_ssl_check_host(&c, b"localhost"), NGX_OK);
                assert_eq!(ngx_ssl_check_host(&c, b"example.com"), NGX_ERROR);

                c.send_all(b"hello").await.unwrap();

                let mut buf = [0u8; 16];
                let n = s.recv(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"hello");

                s.send_all(b"world").await.unwrap();

                // the TLSv1.3 tickets come with the data
                let n = c.recv(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"world");

                if round == 1 {
                    assert!(ngx_ssl_session_reused(&c));
                }

                assert!(saved.borrow().is_some());

                // the client sends close_notify without waiting for the
                // server's (as the proxy does), the server sees the end
                c.ssl.borrow().as_ref().unwrap().no_wait_shutdown.set(true);
                assert_eq!(ngx_ssl_shutdown(&c), NGX_OK);

                let n = s.recv(&mut buf).await.unwrap();
                assert_eq!(n, 0);

                // a received close_notify is not answered
                assert_eq!(ngx_ssl_shutdown(&s), NGX_OK);

                assert!(s.ssl.borrow().is_none());
                assert!(c.ssl.borrow().is_none());
            }
        });
    }

    /// The lengths of the TLS records waiting on the socket of `c`.
    async fn records(c: &Connection) -> Vec<usize> {
        let mut buf = vec![0u8; 65536];

        for _ in 0..100 {
            let n = match crate::fd::get(c.fd.get()) {
                Ok(fd) => rustix::net::recv(&fd, &mut buf, rustix::net::RecvFlags::PEEK).map(|(n, _)| n).unwrap_or(0),
                Err(_) => 0,
            };

            if n > 0 {
                let mut v = Vec::new();
                let mut p = 0usize;

                while p + 5 <= n {
                    let len = ((buf[p + 3] as usize) << 8) | buf[p + 4] as usize;
                    v.push(len);
                    p += 5 + len;
                }

                if p == n {
                    return v;
                }
            }

            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        Vec::new()
    }

    async fn recv_all(c: &Connection, want: usize) -> Vec<u8> {
        let mut v = Vec::new();
        let mut buf = vec![0u8; 65536];

        while v.len() < want {
            let n = c.recv(&mut buf).await.unwrap();
            assert!(n > 0);
            v.extend_from_slice(&buf[..n]);
        }

        v
    }

    fn mem(data: &[u8], flush: bool) -> SslChainBuf<'_> {
        SslChainBuf { mem: data, file: None, flush, last_buf: false }
    }

    #[test]
    fn send_chain_buffers_until_flush() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();

        local.block_on(&rt, async {
            let log = Log::stderr(NGX_LOG_EMERG);

            let server = server_ssl(&log);

            let mut client = NgxSsl::new(log.clone());
            assert_eq!(ngx_ssl_create(&mut client, NGX_SSL_DEFAULT_PROTOCOLS, None), NGX_OK);

            let (s, c) = pair(&log);

            assert_eq!(ngx_ssl_create_connection(&server, &s, 0), NGX_OK);
            assert_eq!(ngx_ssl_create_connection(&client, &c, NGX_SSL_BUFFER | NGX_SSL_CLIENT), NGX_OK);

            let (rs, rc) = tokio::join!(handshake(&s), handshake(&c));
            assert_eq!((rs, rc), (NGX_OK, NGX_OK));

            // the server's session tickets
            s.send_all(b"x").await.unwrap();
            assert_eq!(recv_all(&c, 1).await, b"x");

            // NGX_SSL_BUFFER: kept until a flush, then one record

            let a = vec![b'a'; 100];
            let b = vec![b'b'; 200];

            assert_eq!(ngx_ssl_send_chain_wait(&c, &[mem(&a, false), mem(&b, false)], 0).await.unwrap(), 300);
            assert!(ngx_ssl_buffered(c.ssl.borrow().as_ref().unwrap()));
            assert!(records(&s).await.is_empty());

            let flush = SslChainBuf { mem: b"", file: None, flush: true, last_buf: false };
            assert_eq!(ngx_ssl_send_chain_wait(&c, &[flush], 0).await.unwrap(), 0);
            assert!(!ngx_ssl_buffered(c.ssl.borrow().as_ref().unwrap()));

            let r = records(&s).await;
            assert_eq!(r.len(), 1);
            assert!(r[0] > 300 && r[0] < 340, "{:?}", r);

            let got = recv_all(&s, 300).await;
            assert_eq!(&got[..100], &a[..]);
            assert_eq!(&got[100..], &b[..]);

            // records of the buffer size

            let big = vec![b'c'; 40000];
            assert_eq!(ngx_ssl_send_chain_wait(&c, &[mem(&big[..10000], false), mem(&big[10000..], true)], 0).await.unwrap(), 40000);

            let r = records(&s).await;
            assert_eq!(r.len(), 3, "{:?}", r);
            assert!(r[0] > 16384 && r[1] > 16384 && r[2] < 16384 - 9000, "{:?}", r);
            assert_eq!(recv_all(&s, 40000).await, big);

            // the limit: taken up to it, and written

            assert_eq!(ngx_ssl_send_chain_wait(&c, &[mem(&big[..20000], false)], 5000).await.unwrap(), 5000);
            assert!(!ngx_ssl_buffered(c.ssl.borrow().as_ref().unwrap()));
            assert_eq!(recv_all(&s, 5000).await, &big[..5000]);

            // without NGX_SSL_BUFFER: a record per buffer

            assert_eq!(ngx_ssl_send_chain_wait(&s, &[mem(b"one", false), mem(b"two", false)], 0).await.unwrap(), 6);
            assert_eq!(records(&c).await.len(), 2);
            assert_eq!(recv_all(&c, 6).await, b"onetwo");
        });
    }

    fn free_bufs() -> Vec<usize> {
        SSL_BUFS.with(|b| b.borrow().iter().map(|v| v.capacity()).collect())
    }

    #[test]
    fn ssl_buf_free_list() {
        SSL_BUFS.with(|b| b.borrow_mut().clear());

        let a = ssl_buf_alloc(100);
        assert!(a.is_empty() && a.capacity() >= 100);
        let p = a.as_ptr();

        // given back empty, reused for a size it holds
        let mut a = a;
        a.extend_from_slice(b"data");
        ssl_buf_free(a);
        assert_eq!(free_bufs().len(), 1);

        let b = ssl_buf_alloc(50);
        assert!(b.is_empty());
        assert_eq!(b.as_ptr(), p);
        assert!(free_bufs().is_empty());

        // a larger size is not taken from smaller memory
        ssl_buf_free(b);
        let c = ssl_buf_alloc(1000);
        assert!(c.capacity() >= 1000);
        assert_eq!(free_bufs().len(), 1);
        drop(c);

        // bounded
        let all: Vec<Vec<u8>> = (0..SSL_BUFS_MAX + 5).map(|_| ssl_buf_alloc(10)).collect();
        all.into_iter().for_each(ssl_buf_free);
        assert_eq!(free_bufs().len(), SSL_BUFS_MAX);

        // an SslBuf gives its memory back when dropped, an unused one none
        SSL_BUFS.with(|b| b.borrow_mut().clear());
        drop(SslBuf::default());
        assert!(free_bufs().is_empty());
        drop(SslBuf { data: ssl_buf_alloc(64), pos: 0, end: 64, flush: false });
        assert_eq!(free_bufs().len(), 1);
    }

    #[test]
    fn send_chain_of_bufs() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let local = tokio::task::LocalSet::new();

        local.block_on(&rt, async {
            let log = Log::stderr(NGX_LOG_EMERG);

            let server = server_ssl(&log);

            let mut client = NgxSsl::new(log.clone());
            assert_eq!(ngx_ssl_create(&mut client, NGX_SSL_DEFAULT_PROTOCOLS, None), NGX_OK);

            let (s, c) = pair(&log);

            assert_eq!(ngx_ssl_create_connection(&server, &s, 0), NGX_OK);
            assert_eq!(ngx_ssl_create_connection(&client, &c, NGX_SSL_BUFFER | NGX_SSL_CLIENT), NGX_OK);

            let (rs, rc) = tokio::join!(handshake(&s), handshake(&c));
            assert_eq!((rs, rc), (NGX_OK, NGX_OK));

            s.send_all(b"x").await.unwrap();
            assert_eq!(recv_all(&c, 1).await, b"x");

            SSL_BUFS.with(|b| b.borrow_mut().clear());

            // the buffers of a chain, pos..last of each, kept until the
            // flush buffer, then one record

            let mut chain = crate::buf::Chain::new();
            let mut b = crate::buf::Buf::from_vec(b"--head--".to_vec());
            b.pos = 2;
            b.last = 6;
            chain.push_back(b);
            chain.push_back(crate::buf::Buf::from_vec(b"body".to_vec()));

            assert_eq!(ngx_ssl_send_chain_wait_chain(&c, &chain, 0).await.unwrap(), 8);
            assert!(ngx_ssl_buffered(c.ssl.borrow().as_ref().unwrap()));
            assert!(records(&s).await.is_empty());

            let mut flush = crate::buf::Buf::special();
            flush.flush = true;
            let chain: crate::buf::Chain = [flush].into_iter().collect();

            assert_eq!(ngx_ssl_send_chain_wait_chain(&c, &chain, 0).await.unwrap(), 0);
            assert!(!ngx_ssl_buffered(c.ssl.borrow().as_ref().unwrap()));
            assert_eq!(records(&s).await.len(), 1);
            assert_eq!(recv_all(&s, 8).await, b"headbody");

            // an idle connection gives the buffer back, the next send
            // takes it again

            assert!(free_bufs().is_empty());
            ngx_ssl_free_buffer(&c);
            let free = free_bufs();
            assert!(free.len() == 1 && free[0] >= 16384, "{:?}", free);

            let bufs: [&[u8]; 2] = [b"one", b"two"];
            assert_eq!(ngx_ssl_send_chain_wait_links(&c, &SslFlushedBufs(&bufs), 0).await.unwrap(), 6);
            assert!(free_bufs().is_empty());
            assert_eq!(records(&s).await.len(), 1);
            assert_eq!(recv_all(&s, 6).await, b"onetwo");
        });
    }
}
