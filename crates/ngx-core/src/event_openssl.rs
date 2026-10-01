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
//! OpenSSL callbacks find the connection through the SSL ex_data at
//! ngx_ssl_connection_index (a pointer to the Connection, which owns the
//! SSL object through c.ssl and so outlives it), as in C.

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString};
use std::io;
use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};
use std::rc::Rc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use foreign_types::ForeignType;

use crate::conf::Conf;
use crate::connection::{Connection, IoStep, NGX_ERROR_ERR, NGX_ERROR_IGNORE_ECONNRESET, NGX_ERROR_INFO};
use crate::event_openssl_cache::*;
use crate::log::*;
use crate::openssl_ffi::*;
use crate::rbtree::*;
use crate::queue::Queue;
use crate::rc::*;
use crate::shm::ShmZone;
use crate::slab::SlabPool;
use crate::ssl::SslConnection;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};

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

static NGX_SSL_CONNECTION_INDEX: AtomicI32 = AtomicI32::new(-1);
static NGX_SSL_SERVER_CONF_INDEX: AtomicI32 = AtomicI32::new(-1);
static NGX_SSL_SESSION_CACHE_INDEX: AtomicI32 = AtomicI32::new(-1);
static NGX_SSL_TICKET_KEYS_INDEX: AtomicI32 = AtomicI32::new(-1);
static NGX_SSL_OCSP_INDEX: AtomicI32 = AtomicI32::new(-1);
static NGX_SSL_INDEX: AtomicI32 = AtomicI32::new(-1);
static NGX_SSL_CERTIFICATE_NAME_INDEX: AtomicI32 = AtomicI32::new(-1);
static NGX_SSL_CERTIFICATE_COMP_INDEX: AtomicI32 = AtomicI32::new(-1);
static NGX_SSL_CLIENT_HELLO_ARG_INDEX: AtomicI32 = AtomicI32::new(-1);

fn index(i: &AtomicI32) -> c_int {
    if NGX_SSL_CONNECTION_INDEX.load(Ordering::Relaxed) == -1 {
        // not initialized at startup (unit tests): do it now
        ngx_ssl_init(&Log::stderr(NGX_LOG_NOTICE));
    }
    i.load(Ordering::Relaxed)
}

pub fn ngx_ssl_connection_index() -> c_int {
    index(&NGX_SSL_CONNECTION_INDEX)
}

pub fn ngx_ssl_server_conf_index() -> c_int {
    index(&NGX_SSL_SERVER_CONF_INDEX)
}

pub fn ngx_ssl_session_cache_index() -> c_int {
    index(&NGX_SSL_SESSION_CACHE_INDEX)
}

pub fn ngx_ssl_ticket_keys_index() -> c_int {
    index(&NGX_SSL_TICKET_KEYS_INDEX)
}

pub fn ngx_ssl_ocsp_index() -> c_int {
    index(&NGX_SSL_OCSP_INDEX)
}

pub fn ngx_ssl_index() -> c_int {
    index(&NGX_SSL_INDEX)
}

pub fn ngx_ssl_certificate_name_index() -> c_int {
    index(&NGX_SSL_CERTIFICATE_NAME_INDEX)
}

pub fn ngx_ssl_certificate_comp_index() -> c_int {
    index(&NGX_SSL_CERTIFICATE_COMP_INDEX)
}

pub fn ngx_ssl_client_hello_arg_index() -> c_int {
    index(&NGX_SSL_CLIENT_HELLO_ARG_INDEX)
}

/// ngx_ssl_init: the library was initialized by openssl::init() (with the
/// configuration file loaded, OPENSSL_INIT_LOAD_CONFIG being the default
/// of OPENSSL_init_ssl()); this allocates the ex_data indices.
pub fn ngx_ssl_init(log: &Log) -> i64 {
    unsafe {
        if NGX_SSL_CONNECTION_INDEX.load(Ordering::Relaxed) != -1 {
            return NGX_OK;
        }

        OPENSSL_init_ssl(0, std::ptr::null());

        /*
         * OPENSSL_init_ssl() may leave errors in the error queue
         * while returning success
         */

        ERR_clear_error();

        let n = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), None);

        if n == -1 {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("SSL_get_ex_new_index() failed"));
            return NGX_ERROR;
        }

        NGX_SSL_CONNECTION_INDEX.store(n, Ordering::Relaxed);

        for i in [&NGX_SSL_SERVER_CONF_INDEX, &NGX_SSL_SESSION_CACHE_INDEX, &NGX_SSL_TICKET_KEYS_INDEX, &NGX_SSL_OCSP_INDEX, &NGX_SSL_INDEX] {
            let n = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), None);

            if n == -1 {
                ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("SSL_CTX_get_ex_new_index() failed"));
                return NGX_ERROR;
            }

            i.store(n, Ordering::Relaxed);
        }

        for i in [&NGX_SSL_CERTIFICATE_NAME_INDEX, &NGX_SSL_CERTIFICATE_COMP_INDEX] {
            let n = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509, 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), None);

            if n == -1 {
                ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("X509_get_ex_new_index() failed"));
                return NGX_ERROR;
            }

            i.store(n, Ordering::Relaxed);
        }

        let n = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), None);

        if n == -1 {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("SSL_CTX_get_ex_new_index() failed"));
            return NGX_ERROR;
        }

        NGX_SSL_CLIENT_HELLO_ARG_INDEX.store(n, Ordering::Relaxed);
    }

    NGX_OK
}

/// ngx_str_t as passed to the servername callbacks by
/// ngx_ssl_client_hello_callback() (data NULL: no server name)
#[repr(C)]
pub struct SslStr {
    pub data: *const u8,
    pub len: usize,
}

/// ngx_ssl_client_hello_arg
pub struct SslClientHelloArg {
    pub servername: SSL_servername_cb,
}

/// ngx_ssl_ticket_key_t
#[repr(C)]
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

/// The ticket keys array of a context (at ngx_ssl_ticket_keys_index); its
/// contents are cleared when it is freed (ngx_ssl_ticket_keys_cleanup).
pub struct SslTicketKeys {
    pub keys: RefCell<Vec<SslTicketKey>>,
}

impl Drop for SslTicketKeys {
    fn drop(&mut self) {
        for k in self.keys.borrow_mut().iter_mut() {
            explicit_memzero(&mut k.name);
            explicit_memzero(&mut k.hmac_key);
            explicit_memzero(&mut k.aes_key);
        }
    }
}

/// ngx_explicit_memzero
pub fn explicit_memzero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // volatile, so the clearing is not optimized out
        unsafe { std::ptr::write_volatile(b, 0) };
    }
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

/// ngx_ssl_t
pub struct NgxSsl {
    pub ctx: *mut SSL_CTX,
    pub log: Log,
    pub buffer_size: usize,

    /// ssl->certs: the certificates of the context, freed with it
    pub certs: Vec<*mut X509>,
    /// the names of the certificates (X509 ex_data at
    /// ngx_ssl_certificate_name_index points to them)
    pub cert_names: Vec<CString>,

    /// the session ticket keys (SSL_CTX ex_data)
    pub ticket_keys: Option<Box<SslTicketKeys>>,

    /// ssl->staple_rbtree: the stapling data of the certificates
    pub staples: RefCell<Vec<Rc<crate::event_openssl_stapling::SslStapling>>>,
    /// the OCSP configuration (ngx_ssl_ocsp_conf_t at ngx_ssl_ocsp_index)
    pub ocsp_conf: RefCell<Option<Box<crate::event_openssl_stapling::SslOcspConf>>>,
}

impl NgxSsl {
    pub fn new(log: Log) -> NgxSsl {
        NgxSsl {
            ctx: std::ptr::null_mut(),
            log,
            buffer_size: NGX_SSL_BUFSIZE,
            certs: Vec::new(),
            cert_names: Vec::new(),
            ticket_keys: None,
            staples: RefCell::new(Vec::new()),
            ocsp_conf: RefCell::new(None),
        }
    }
}

impl Drop for NgxSsl {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            ngx_ssl_cleanup_ctx(self);
        }
    }
}

/// The state of ngx_ssl_connection_t beyond the fields of SslConnection
/// (a connection created by ngx_ssl_create_connection()).
pub struct SslConnState {
    /// created by ngx_ssl_create_connection(): the I/O follows
    /// ngx_ssl_recv() / ngx_ssl_write()
    pub ngx: Cell<bool>,
    pub session_ctx: Cell<*mut SSL_CTX>,
    /// c->ssl->last: the result of the last ngx_ssl_handle_recv()
    pub last: Cell<i64>,
    /// NGX_SSL_BUFFER
    pub buffer: Cell<bool>,
    /// the session being saved (ngx_ssl_new_client_session())
    pub session: Cell<*mut SSL_SESSION>,
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
    pub ocsp: RefCell<Option<Rc<crate::event_openssl_stapling::SslOcsp>>>,
    /// c->ssl->buf
    pub buf: RefCell<SslBuf>,
}

impl Default for SslConnState {
    fn default() -> Self {
        SslConnState {
            ngx: Cell::new(false),
            session_ctx: Cell::new(std::ptr::null_mut()),
            last: Cell::new(NGX_OK),
            buffer: Cell::new(false),
            session: Cell::new(std::ptr::null_mut()),
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

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return b"";
    }
    CStr::from_ptr(p).to_bytes()
}

fn cstring(v: &[u8]) -> CString {
    // configuration strings have no NUL bytes; cut at one if there is
    let n = v.iter().position(|&c| c == 0).unwrap_or(v.len());
    CString::new(&v[..n]).unwrap()
}

/// ngx_hex_dump (lowercase)
fn hex_dump(dst: &mut Vec<u8>, src: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in src {
        dst.push(HEX[(b >> 4) as usize]);
        dst.push(HEX[(b & 0xf) as usize]);
    }
}

/// The SSL object of an SSL connection.
pub fn ssl_ptr(sc: &SslConnection) -> *mut SSL {
    match sc.inner.borrow().as_ref() {
        Some(s) => s.as_ptr(),
        None => std::ptr::null_mut(),
    }
}

/// The SSL object of c->ssl (NULL without SSL).
pub fn ngx_ssl_conn(c: &Connection) -> *mut SSL {
    match c.ssl.borrow().as_ref() {
        Some(sc) => ssl_ptr(sc),
        None => std::ptr::null_mut(),
    }
}

/// c->ssl
pub fn ngx_ssl_sc(c: &Connection) -> Option<Rc<SslConnection>> {
    c.ssl.borrow().clone()
}

/// ngx_ssl_get_connection(ssl_conn)
///
/// # Safety
/// `ssl` must be an SSL object of a connection created by
/// ngx_ssl_create_connection(); the connection outlives its SSL object.
pub unsafe fn ngx_ssl_get_connection<'a>(ssl: *const SSL) -> Option<&'a Connection> {
    let p = SSL_get_ex_data(ssl, ngx_ssl_connection_index()) as *const Connection;
    if p.is_null() {
        return None;
    }
    Some(&*p)
}

/// ngx_ssl_get_server_conf(ssl_ctx)
pub unsafe fn ngx_ssl_get_server_conf(ctx: *const SSL_CTX) -> *mut c_void {
    SSL_CTX_get_ex_data(ctx, ngx_ssl_server_conf_index())
}

/// ngx_ssl_verify_error_optional()
pub fn ngx_ssl_verify_error_optional(n: c_long) -> bool {
    n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        || n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        || n == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        || n == X509_V_ERR_CERT_UNTRUSTED
        || n == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
}

// --- contexts ---

/// ngx_ssl_create
pub fn ngx_ssl_create(ssl: &mut NgxSsl, protocols: u32, data: *mut c_void) -> i64 {
    unsafe {
        ssl.ctx = SSL_CTX_new(TLS_method());

        if ssl.ctx.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_new() failed"));
            return NGX_ERROR;
        }

        if SSL_CTX_set_ex_data(ssl.ctx, ngx_ssl_server_conf_index(), data) == 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_ex_data() failed"));
            return NGX_ERROR;
        }

        if SSL_CTX_set_ex_data(ssl.ctx, ngx_ssl_index(), ssl as *mut NgxSsl as *mut c_void) == 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_ex_data() failed"));
            return NGX_ERROR;
        }

        ssl.staples.borrow_mut().clear();

        ssl.buffer_size = NGX_SSL_BUFSIZE;

        let ctx = ssl.ctx;

        /* client side options */

        SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
        SSL_CTX_set_options(ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);

        /* server side options */

        SSL_CTX_set_options(ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
        SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
        SSL_CTX_set_options(ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
        SSL_CTX_set_options(ctx, SSL_OP_TLS_D5_BUG);
        SSL_CTX_set_options(ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);
        SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

        SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);

        SSL_CTX_clear_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1);

        if protocols & NGX_SSL_SSLV2 == 0 {
            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
        }
        if protocols & NGX_SSL_SSLV3 == 0 {
            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
        }
        if protocols & NGX_SSL_TLSV1 == 0 {
            SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
        }

        SSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1_1);
        if protocols & NGX_SSL_TLSV1_1 == 0 {
            SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
        }

        SSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1_2);
        if protocols & NGX_SSL_TLSV1_2 == 0 {
            SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
        }

        SSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1_3);
        if protocols & NGX_SSL_TLSV1_3 == 0 {
            SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
        }

        SSL_CTX_set_min_proto_version(ctx, 0);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

        SSL_CTX_set_min_proto_version(ctx, 0);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

        SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);

        SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);

        SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

        SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN);

        SSL_CTX_set_read_ahead(ctx, 1);

        SSL_CTX_set_info_callback(ctx, Some(ngx_ssl_info_callback));
    }

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

/// ngx_ssl_certificate
pub fn ngx_ssl_certificate(cf: &mut Conf, ssl: &mut NgxSsl, cert: &mut Vec<u8>, key: &mut Vec<u8>, passwords: Option<&Rc<SslPasswords>>) -> i64 {
    let mut mask = 0;
    let mut elm: Option<usize> = None;

    unsafe {
        loop {
            // retry:

            let mut err: Option<&'static str> = None;

            let chain = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CERT | mask, &mut err, cert, None) as *mut OPENSSL_STACK;
            if chain.is_null() {
                if let Some(err) = err {
                    ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("cannot load certificate \"{}\": {}", B(cert), err));
                }

                return NGX_ERROR;
            }

            let x509 = OPENSSL_sk_shift(chain) as *mut X509;

            if SSL_CTX_use_certificate(ssl.ctx, x509) == 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_use_certificate(\"{}\") failed", B(cert)));
                X509_free(x509);
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }

            let name = cstring(cert);

            if X509_set_ex_data(x509, ngx_ssl_certificate_name_index(), name.as_ptr() as *mut c_void) == 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_set_ex_data() failed"));
                X509_free(x509);
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }

            match elm {
                None => {
                    ssl.certs.push(x509);
                    ssl.cert_names.push(name);
                    elm = Some(ssl.certs.len() - 1);
                }
                Some(i) => {
                    X509_free(ssl.certs[i]);
                    ssl.certs[i] = x509;
                    ssl.cert_names[i] = name;
                }
            }

            /*
             * Note that x509 is not freed here, but will be instead freed in
             * ngx_ssl_cleanup_ctx().  This is because we need to preserve all
             * certificates to be able to iterate all of them through ssl->certs,
             * while OpenSSL can free a certificate if it is replaced with another
             * certificate of the same type.
             */

            if SSL_CTX_set0_chain(ssl.ctx, chain) == 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set0_chain(\"{}\") failed", B(cert)));
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }

            let mut err: Option<&'static str> = None;

            let pkey = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_PKEY | mask, &mut err, key, passwords) as *mut EVP_PKEY;
            if pkey.is_null() {
                if let Some(err) = err {
                    ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("cannot load certificate key \"{}\": {}", B(key), err));
                }

                return NGX_ERROR;
            }

            if SSL_CTX_use_PrivateKey(ssl.ctx, pkey) == 0 {
                EVP_PKEY_free(pkey);

                /* there can be mismatched pairs on uneven cache update */

                let n = ERR_peek_last_error();

                if ERR_GET_LIB(n) == ERR_LIB_X509 && ERR_GET_REASON(n) == X509_R_KEY_VALUES_MISMATCH && mask == 0 {
                    ERR_clear_error();
                    mask = NGX_SSL_CACHE_INVALIDATE;
                    continue;
                }

                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_use_PrivateKey(\"{}\") failed", B(key)));
                return NGX_ERROR;
            }

            EVP_PKEY_free(pkey);

            return NGX_OK;
        }
    }
}

/// ngx_ssl_connection_certificate: the certificate and key of a
/// connection (ssl_certificate with variables, from the certificate
/// callback)
pub fn ngx_ssl_connection_certificate(c: &Connection, cert: &mut Vec<u8>, key: &mut Vec<u8>, cache: Option<&Rc<RefCell<SslCache>>>, passwords: Option<&Rc<SslPasswords>>) -> i64 {
    let ssl = ngx_ssl_conn(c);
    let mut mask = 0;

    unsafe {
        loop {
            // retry:

            let mut err: Option<&'static str> = None;

            let chain = ngx_ssl_cache_connection_fetch(cache, &c.log, NGX_SSL_CACHE_CERT | mask, &mut err, cert, None) as *mut OPENSSL_STACK;
            if chain.is_null() {
                if let Some(err) = err {
                    ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("cannot load certificate \"{}\": {}", B(cert), err));
                }

                return NGX_ERROR;
            }

            let x509 = OPENSSL_sk_shift(chain) as *mut X509;

            if SSL_use_certificate(ssl, x509) == 0 {
                ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("SSL_use_certificate(\"{}\") failed", B(cert)));
                X509_free(x509);
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }

            X509_free(x509);

            /*
             * SSL_set0_chain() is only available in OpenSSL 1.0.2+,
             * but this function is only called via certificate callback,
             * which is only available in OpenSSL 1.0.2+ as well
             */

            if SSL_set0_chain(ssl, chain) == 0 {
                ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("SSL_set0_chain(\"{}\") failed", B(cert)));
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }

            let mut err: Option<&'static str> = None;

            let pkey = ngx_ssl_cache_connection_fetch(cache, &c.log, NGX_SSL_CACHE_PKEY | mask, &mut err, key, passwords) as *mut EVP_PKEY;
            if pkey.is_null() {
                if let Some(err) = err {
                    ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("cannot load certificate key \"{}\": {}", B(key), err));
                }

                return NGX_ERROR;
            }

            if SSL_use_PrivateKey(ssl, pkey) == 0 {
                EVP_PKEY_free(pkey);

                /* there can be mismatched pairs on uneven cache update */

                let n = ERR_peek_last_error();

                if ERR_GET_LIB(n) == ERR_LIB_X509 && ERR_GET_REASON(n) == X509_R_KEY_VALUES_MISMATCH && mask == 0 {
                    ERR_clear_error();
                    mask = NGX_SSL_CACHE_INVALIDATE;
                    continue;
                }

                ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("SSL_use_PrivateKey(\"{}\") failed", B(key)));
                return NGX_ERROR;
            }

            EVP_PKEY_free(pkey);

            return NGX_OK;
        }
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
    unsafe {
        let s = cstring(ciphers);

        if SSL_CTX_set_cipher_list(ssl.ctx, s.as_ptr()) == 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_cipher_list(\"{}\") failed", B(ciphers)));
            return NGX_ERROR;
        }

        if prefer_server_ciphers {
            SSL_CTX_set_options(ssl.ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
        }
    }

    NGX_OK
}

unsafe extern "C" fn ngx_ssl_cmp_x509_name(a: *const c_void, b: *const c_void) -> c_int {
    X509_NAME_cmp(*(a as *const *const X509_NAME), *(b as *const *const X509_NAME))
}

/// ngx_ssl_client_certificate
pub fn ngx_ssl_client_certificate(cf: &mut Conf, ssl: &mut NgxSsl, cert: &mut Vec<u8>, depth: i64) -> i64 {
    unsafe {
        SSL_CTX_set_verify(ssl.ctx, SSL_VERIFY_PEER, Some(ngx_ssl_verify_callback));

        SSL_CTX_set_verify_depth(ssl.ctx, depth as c_int);

        if cert.is_empty() {
            return NGX_OK;
        }

        let list = OPENSSL_sk_new(Some(ngx_ssl_cmp_x509_name));
        if list.is_null() {
            return NGX_ERROR;
        }

        let store = SSL_CTX_get_cert_store(ssl.ctx);

        if store.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_get_cert_store() failed"));
            return NGX_ERROR;
        }

        let mut err: Option<&'static str> = None;

        let chain = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CA, &mut err, cert, None) as *mut OPENSSL_STACK;
        if chain.is_null() {
            if let Some(err) = err {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("cannot load certificate \"{}\": {}", B(cert), err));
            }

            sk_X509_NAME_pop_free(list);
            return NGX_ERROR;
        }

        let n = OPENSSL_sk_num(chain);

        for i in 0..n {
            let x509 = OPENSSL_sk_value(chain, i) as *mut X509;

            if X509_STORE_add_cert(store, x509) != 1 {
                if ngx_ssl_cert_already_in_hash() {
                    continue;
                }

                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_STORE_add_cert(\"{}\") failed", B(cert)));
                sk_X509_NAME_pop_free(list);
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }

            let sname = X509_get_subject_name(x509);
            if sname.is_null() {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_get_subject_name(\"{}\") failed", B(cert)));
                sk_X509_NAME_pop_free(list);
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }

            let name = X509_NAME_dup(sname);
            if name.is_null() {
                sk_X509_NAME_pop_free(list);
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }

            if OPENSSL_sk_find(list, name as *const c_void) >= 0 {
                X509_NAME_free(name);
                continue;
            }

            if OPENSSL_sk_push(list, name as *const c_void) == 0 {
                sk_X509_NAME_pop_free(list);
                sk_X509_pop_free(chain);
                X509_NAME_free(name);
                return NGX_ERROR;
            }
        }

        sk_X509_pop_free(chain);

        SSL_CTX_set_client_CA_list(ssl.ctx, list);
    }

    NGX_OK
}

/// ngx_ssl_trusted_certificate
pub fn ngx_ssl_trusted_certificate(cf: &mut Conf, ssl: &mut NgxSsl, cert: &mut Vec<u8>, depth: i64) -> i64 {
    unsafe {
        SSL_CTX_set_verify(ssl.ctx, SSL_CTX_get_verify_mode(ssl.ctx), Some(ngx_ssl_verify_callback));

        SSL_CTX_set_verify_depth(ssl.ctx, depth as c_int);

        if cert.is_empty() {
            return NGX_OK;
        }

        let store = SSL_CTX_get_cert_store(ssl.ctx);

        if store.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_get_cert_store() failed"));
            return NGX_ERROR;
        }

        let mut err: Option<&'static str> = None;

        let chain = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CA, &mut err, cert, None) as *mut OPENSSL_STACK;
        if chain.is_null() {
            if let Some(err) = err {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("cannot load certificate \"{}\": {}", B(cert), err));
            }

            return NGX_ERROR;
        }

        let n = OPENSSL_sk_num(chain);

        for i in 0..n {
            let x509 = OPENSSL_sk_value(chain, i) as *mut X509;

            if X509_STORE_add_cert(store, x509) != 1 {
                if ngx_ssl_cert_already_in_hash() {
                    continue;
                }

                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_STORE_add_cert(\"{}\") failed", B(cert)));
                sk_X509_pop_free(chain);
                return NGX_ERROR;
            }
        }

        sk_X509_pop_free(chain);
    }

    NGX_OK
}

/// ngx_ssl_crl
pub fn ngx_ssl_crl(cf: &mut Conf, ssl: &mut NgxSsl, crl: &mut Vec<u8>) -> i64 {
    if crl.is_empty() {
        return NGX_OK;
    }

    unsafe {
        let store = SSL_CTX_get_cert_store(ssl.ctx);

        if store.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_get_cert_store() failed"));
            return NGX_ERROR;
        }

        let mut err: Option<&'static str> = None;

        let chain = ngx_ssl_cache_fetch(cf, NGX_SSL_CACHE_CRL, &mut err, crl, None) as *mut OPENSSL_STACK;
        if chain.is_null() {
            if let Some(err) = err {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("cannot load CRL \"{}\": {}", B(crl), err));
            }

            return NGX_ERROR;
        }

        let n = OPENSSL_sk_num(chain);

        for i in 0..n {
            let x509 = OPENSSL_sk_value(chain, i) as *mut X509_CRL;

            if X509_STORE_add_crl(store, x509) != 1 {
                if ngx_ssl_cert_already_in_hash() {
                    continue;
                }

                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_STORE_add_crl(\"{}\") failed", B(crl)));
                sk_X509_CRL_pop_free(chain);
                return NGX_ERROR;
            }
        }

        sk_X509_CRL_pop_free(chain);

        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }

    NGX_OK
}

/// ngx_ssl_cert_already_in_hash: OpenSSL 1.1.0i+ ignores duplicates
fn ngx_ssl_cert_already_in_hash() -> bool {
    false
}

/// ngx_ssl_verify_callback: logs the verification at debug_event
unsafe extern "C" fn ngx_ssl_verify_callback(ok: c_int, x509_store: *mut X509_STORE_CTX) -> c_int {
    let ssl_conn = X509_STORE_CTX_get_ex_data(x509_store, SSL_get_ex_data_X509_STORE_CTX_idx()) as *const SSL;

    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return 1,
    };

    if !c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
        return 1;
    }

    let cert = X509_STORE_CTX_get_current_cert(x509_store);
    let err = X509_STORE_CTX_get_error(x509_store);
    let depth = X509_STORE_CTX_get_error_depth(x509_store);

    let sname = X509_get_subject_name(cert);

    let subject = if !sname.is_null() {
        let s = X509_NAME_oneline(sname, std::ptr::null_mut(), 0);
        if s.is_null() {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_NAME_oneline() failed"));
        }
        s
    } else {
        std::ptr::null_mut()
    };

    let iname = X509_get_issuer_name(cert);

    let issuer = if !iname.is_null() {
        let s = X509_NAME_oneline(iname, std::ptr::null_mut(), 0);
        if s.is_null() {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_NAME_oneline() failed"));
        }
        s
    } else {
        std::ptr::null_mut()
    };

    ngx_log_debug!(
        NGX_LOG_DEBUG_EVENT,
        c.log,
        "verify:{}, error:{}, depth:{}, subject:\"{}\", issuer:\"{}\"",
        ok,
        err,
        depth,
        if subject.is_null() { B(b"(none)") } else { B(cstr(subject)) },
        if issuer.is_null() { B(b"(none)") } else { B(cstr(issuer)) }
    );

    if !subject.is_null() {
        OPENSSL_free(subject as *mut c_void);
    }

    if !issuer.is_null() {
        OPENSSL_free(issuer as *mut c_void);
    }

    1
}

/// ngx_ssl_info_callback
unsafe extern "C" fn ngx_ssl_info_callback(ssl_conn: *const SSL, where_: c_int, _ret: c_int) {
    // SSL_OP_NO_RENEGOTIATION is available: no renegotiation detection

    if (where_ & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP && SSL_version(ssl_conn) == TLS1_3_VERSION {
        /*
         * OpenSSL with TLSv1.3 updates the session creation time on
         * session resumption and keeps the session timeout unmodified,
         * making it possible to maintain the session forever, bypassing
         * client certificate expiration and revocation.  To make sure
         * session timeouts are actually used, we now update the session
         * creation time and reduce the session timeout accordingly.
         */

        if let Some(c) = ngx_ssl_get_connection(ssl_conn) {
            if let Some(sc) = c.ssl.borrow().as_ref() {
                let sess = SSL_get0_session(ssl_conn);

                if !sc.state.session_timeout_set.get() && !sess.is_null() {
                    sc.state.session_timeout_set.set(true);

                    let now = crate::times::time();
                    let time = SSL_SESSION_get_time(sess) as i64;
                    let timeout = SSL_SESSION_get_timeout(sess) as i64;
                    let conf_timeout = SSL_CTX_get_timeout(sc.state.session_ctx.get()) as i64;

                    let timeout = timeout.min(conf_timeout);

                    if now - time >= timeout {
                        SSL_SESSION_set1_id_context(sess, b"".as_ptr(), 0);
                    } else {
                        SSL_SESSION_set_time(sess, now as c_long);
                        SSL_SESSION_set_timeout(sess, (timeout - (now - time)) as c_long);
                    }
                }
            }
        }
    }

    if (where_ & SSL_CB_ACCEPT_LOOP) == SSL_CB_ACCEPT_LOOP {
        if let Some(c) = ngx_ssl_get_connection(ssl_conn) {
            if let Some(sc) = c.ssl.borrow().as_ref() {
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

                    let rbio = SSL_get_rbio(ssl_conn);
                    let wbio = SSL_get_wbio(ssl_conn);

                    if rbio != wbio {
                        BIO_set_write_buffer_size(wbio, NGX_SSL_BUFSIZE as c_long);
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

    let name = cstring(&file);

    let fd = unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };

    if fd == -1 {
        cf.log_error(NGX_LOG_EMERG, Some(errno()), format_args!("open() \"{}\" failed", B(&file)));
        return None;
    }

    let mut buf = [0u8; NGX_SSL_PASSWORD_BUFFER_SIZE + 1];
    let mut len = 0usize;
    let mut last = 0usize;

    let result = 'cleanup: loop {
        let n = unsafe { libc::read(fd, buf[last..].as_mut_ptr() as *mut c_void, NGX_SSL_PASSWORD_BUFFER_SIZE - len) };

        if n == -1 {
            cf.log_error(NGX_LOG_EMERG, Some(errno()), format_args!("read() \"{}\" failed", B(&file)));
            break 'cleanup false;
        }

        let n = n as usize;

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

    if unsafe { libc::close(fd) } == -1 {
        cf.log_error(NGX_LOG_ALERT, Some(errno()), format_args!("close() \"{}\" failed", B(&file)));
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

    unsafe {
        let name = cstring(file);

        let bio = BIO_new_file(name.as_ptr(), b"r\0".as_ptr() as *const c_char);
        if bio.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("BIO_new_file(\"{}\") failed", B(file)));
            return NGX_ERROR;
        }

        let dh = PEM_read_bio_DHparams(bio, std::ptr::null_mut(), None, std::ptr::null_mut());
        if dh.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("PEM_read_bio_DHparams(\"{}\") failed", B(file)));
            BIO_free(bio);
            return NGX_ERROR;
        }

        if SSL_CTX_set_tmp_dh(ssl.ctx, dh) != 1 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_tmp_dh(\"{}\") failed", B(file)));
            DH_free(dh);
            BIO_free(bio);
            return NGX_ERROR;
        }

        DH_free(dh);

        BIO_free(bio);
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

    unsafe {
        SSL_CTX_set_options(ssl.ctx, SSL_OP_SINGLE_ECDH_USE);

        if name == b"auto" {
            return NGX_OK;
        }

        let s = cstring(name);

        if SSL_CTX_set1_curves_list(ssl.ctx, s.as_ptr()) == 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set1_curves_list(\"{}\") failed", B(name)));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_early_data
pub fn ngx_ssl_early_data(_cf: &mut Conf, ssl: &mut NgxSsl, enable: bool) -> i64 {
    if !enable {
        return NGX_OK;
    }

    /* OpenSSL */

    unsafe { SSL_CTX_set_max_early_data(ssl.ctx, NGX_SSL_BUFSIZE as u32) };

    NGX_OK
}

/// ngx_ssl_conf_commands
pub fn ngx_ssl_conf_commands(cf: &mut Conf, ssl: &mut NgxSsl, commands: Option<&mut Vec<(Vec<u8>, Vec<u8>)>>) -> i64 {
    let commands = match commands {
        None => return NGX_OK,
        Some(c) => c,
    };

    unsafe {
        let cctx = SSL_CONF_CTX_new();
        if cctx.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CONF_CTX_new() failed"));
            return NGX_ERROR;
        }

        SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE);
        SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SERVER);
        SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT);
        SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CERTIFICATE);
        SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_SHOW_ERRORS);

        SSL_CONF_CTX_set_ssl_ctx(cctx, ssl.ctx);

        for (key, value) in commands.iter_mut() {
            let k = cstring(key);

            let ty = SSL_CONF_cmd_value_type(cctx, k.as_ptr());

            if ty == SSL_CONF_TYPE_FILE || ty == SSL_CONF_TYPE_DIR {
                *value = cf.full_name(value, true);
            }

            let v = cstring(value);

            if SSL_CONF_cmd(cctx, k.as_ptr(), v.as_ptr()) <= 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CONF_cmd(\"{}\", \"{}\") failed", B(key), B(value)));
                SSL_CONF_CTX_free(cctx);
                return NGX_ERROR;
            }
        }

        if SSL_CONF_CTX_finish(cctx) != 1 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CONF_finish() failed"));
            SSL_CONF_CTX_free(cctx);
            return NGX_ERROR;
        }

        SSL_CONF_CTX_free(cctx);
    }

    NGX_OK
}

/// ngx_ssl_client_session_cache
pub fn ngx_ssl_client_session_cache(_cf: &mut Conf, ssl: &mut NgxSsl, enable: bool) -> i64 {
    if !enable {
        return NGX_OK;
    }

    unsafe {
        SSL_CTX_set_session_cache_mode(ssl.ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);

        SSL_CTX_sess_set_new_cb(ssl.ctx, Some(ngx_ssl_new_client_session));
    }

    NGX_OK
}

/// ngx_ssl_new_client_session: hands the new session to
/// c->ssl->save_session
unsafe extern "C" fn ngx_ssl_new_client_session(ssl_conn: *mut SSL, sess: *mut SSL_SESSION) -> c_int {
    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return 0,
    };

    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return 0,
    };

    let save = sc.state.save_session.borrow().clone();

    if let Some(save) = save {
        sc.state.session.set(sess);

        save(c);

        sc.state.session.set(std::ptr::null_mut());
    }

    0
}

/// ngx_ssl_set_client_hello_callback
pub fn ngx_ssl_set_client_hello_callback(ssl: &mut NgxSsl, cb: &'static SslClientHelloArg) -> i64 {
    unsafe {
        SSL_CTX_set_client_hello_cb(ssl.ctx, Some(ngx_ssl_client_hello_callback), std::ptr::null_mut());

        if SSL_CTX_set_ex_data(ssl.ctx, ngx_ssl_client_hello_arg_index(), cb as *const SslClientHelloArg as *mut c_void) == 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_ex_data() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_client_hello_callback: the server name of the ClientHello for
/// the servername callback, before the protocol version is negotiated
pub unsafe extern "C" fn ngx_ssl_client_hello_callback(ssl_conn: *mut SSL, ad: *mut c_int, _arg: *mut c_void) -> c_int {
    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return SSL_CLIENT_HELLO_SUCCESS,
    };

    let session_ctx = match c.ssl.borrow().as_ref() {
        Some(sc) => sc.state.session_ctx.get(),
        None => return SSL_CLIENT_HELLO_SUCCESS,
    };

    let cb = SSL_CTX_get_ex_data(session_ctx, ngx_ssl_client_hello_arg_index()) as *const SslClientHelloArg;

    let mut p: *const u8 = std::ptr::null();
    let mut len: usize = 0;

    let mut host = SslStr { data: std::ptr::null(), len: 0 };

    if SSL_client_hello_get0_ext(ssl_conn, TLSEXT_TYPE_server_name, &mut p, &mut len) != 0 {
        let d = std::slice::from_raw_parts(p, len);

        /*
         * RFC 6066 mandates non-zero HostName length, we follow OpenSSL.
         * No more than one ServerName is expected.
         */

        if len < 5 || ((d[0] as usize) << 8) + d[1] as usize + 2 != len || d[2] as c_int != TLSEXT_NAMETYPE_host_name || ((d[3] as usize) << 8) + d[4] as usize + 2 + 3 != len {
            *ad = SSL_AD_DECODE_ERROR;
            return SSL_CLIENT_HELLO_ERROR;
        }

        let name = &d[5..];

        if name.len() > TLSEXT_MAXLEN_host_name || name.contains(&0) {
            *ad = SSL_AD_UNRECOGNIZED_NAME;
            return SSL_CLIENT_HELLO_ERROR;
        }

        host.len = name.len();
        host.data = name.as_ptr();
    }

    // done:

    if cb.is_null() {
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    let rc = ((*cb).servername)(ssl_conn, ad, &mut host as *mut SslStr as *mut c_void);

    if rc == SSL_TLSEXT_ERR_ALERT_FATAL {
        return SSL_CLIENT_HELLO_ERROR;
    }

    SSL_CLIENT_HELLO_SUCCESS
}

// --- connections ---

/// ngx_ssl_create_connection: c->ssl for the context
pub fn ngx_ssl_create_connection(ssl: &NgxSsl, c: &Connection, flags: u32) -> i64 {
    let sc = SslConnection::new();

    sc.state.buffer.set(flags & NGX_SSL_BUFFER != 0);
    sc.buffer_size.set(ssl.buffer_size);

    sc.state.session_ctx.set(ssl.ctx);

    unsafe {
        if SSL_CTX_get_max_early_data(ssl.ctx) != 0 {
            sc.state.try_early_data.set(true);
        }

        let conn = SSL_new(ssl.ctx);

        if conn.is_null() {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("SSL_new() failed"));
            return NGX_ERROR;
        }

        // the SSL object is freed with the SslConnection
        *sc.inner.borrow_mut() = Some(openssl::ssl::Ssl::from_ptr(conn));

        if SSL_set_fd(conn, c.fd.get()) == 0 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("SSL_set_fd() failed"));
            return NGX_ERROR;
        }

        if flags & NGX_SSL_CLIENT != 0 {
            SSL_set_connect_state(conn);
        } else {
            SSL_set_accept_state(conn);

            SSL_set_options(conn, SSL_OP_NO_RENEGOTIATION);
        }

        if SSL_set_ex_data(conn, ngx_ssl_connection_index(), c as *const Connection as *mut c_void) == 0 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("SSL_set_ex_data() failed"));
            return NGX_ERROR;
        }
    }

    sc.state.ngx.set(true);

    *c.ssl.borrow_mut() = Some(Rc::new(sc));

    NGX_OK
}

/// ngx_ssl_get_session: a reference to the session to be saved (freed
/// with ngx_ssl_free_session())
pub fn ngx_ssl_get_session(c: &Connection) -> *mut SSL_SESSION {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return std::ptr::null_mut(),
    };

    unsafe {
        let sess = sc.state.session.get();

        if !sess.is_null() {
            SSL_SESSION_up_ref(sess);
            return sess;
        }

        SSL_get1_session(ssl_ptr(&sc))
    }
}

/// ngx_ssl_get0_session
pub fn ngx_ssl_get0_session(c: &Connection) -> *mut SSL_SESSION {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return std::ptr::null_mut(),
    };

    let sess = sc.state.session.get();

    if !sess.is_null() {
        return sess;
    }

    unsafe { SSL_get0_session(ssl_ptr(&sc)) }
}

/// ngx_ssl_free_session
pub fn ngx_ssl_free_session(sess: *mut SSL_SESSION) {
    if !sess.is_null() {
        unsafe { SSL_SESSION_free(sess) };
    }
}

/// ngx_ssl_set_session
pub fn ngx_ssl_set_session(c: &Connection, session: *mut SSL_SESSION) -> i64 {
    if !session.is_null() && unsafe { SSL_set_session(ngx_ssl_conn(c), session) } == 0 {
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
    unsafe { SSL_set_tlsext_host_name(ngx_ssl_conn(c), n.as_ptr()) != 0 }
}

/// SSL_set_alpn_protos(): the ALPN protocols of a client connection, in
/// the wire format (0 on success, as in OpenSSL)
pub fn ngx_ssl_set_alpn_protos(c: &Connection, protos: &[u8]) -> c_int {
    unsafe { SSL_set_alpn_protos(ngx_ssl_conn(c), protos.as_ptr(), protos.len() as c_uint) }
}

/// SSL_get_verify_result()
pub fn ngx_ssl_get_verify_result(c: &Connection) -> c_long {
    unsafe { SSL_get_verify_result(ngx_ssl_conn(c)) }
}

/// X509_verify_cert_error_string()
pub fn ngx_ssl_verify_error_string(rc: c_long) -> Vec<u8> {
    unsafe { cstr(X509_verify_cert_error_string(rc)).to_vec() }
}

/// SSL_session_reused()
pub fn ngx_ssl_session_reused(c: &Connection) -> bool {
    unsafe { SSL_session_reused(ngx_ssl_conn(c)) != 0 }
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

    let ssl = ssl_ptr(&sc);

    let n = unsafe { SSL_do_handshake(ssl) };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_do_handshake: {}", n);

    if n == 1 {
        ngx_ssl_handshake_log(c);

        unsafe {
            if BIO_get_ktls_send(SSL_get_wbio(ssl)) == 1 {
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "BIO_get_ktls_send(): 1");
                sc.state.sendfile.set(true);
            }
        }

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

    let sslerr = unsafe { SSL_get_error(ssl, n) };
    let mut err = if sslerr == SSL_ERROR_SYSCALL { errno() } else { 0 };

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

    if sslerr == SSL_ERROR_SYSCALL && unsafe { ERR_peek_error() } == 0 && err == 0 {
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
        unsafe { ERR_clear_error() };

        return IoStep::Done(NGX_ERROR);
    }

    ngx_ssl_connection_error(c, sslerr, err, "SSL_do_handshake() failed");

    IoStep::Done(NGX_ERROR)
}

/// ngx_ssl_try_early_data
fn ngx_ssl_try_early_data(c: &Connection, sc: &SslConnection) -> IoStep<i64> {
    ngx_ssl_clear_error(&c.log);

    let ssl = ssl_ptr(sc);

    let mut buf: u8 = 0;
    let mut readbytes: usize = 0;

    let n = unsafe { SSL_read_early_data(ssl, &mut buf as *mut u8 as *mut c_void, 1, &mut readbytes) };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_read_early_data: {}, {}", n, readbytes);

    if n == SSL_READ_EARLY_DATA_FINISH {
        sc.state.try_early_data.set(false);
        return ngx_ssl_handshake_step(c);
    }

    if n == SSL_READ_EARLY_DATA_SUCCESS {
        ngx_ssl_handshake_log(c);

        sc.state.try_early_data.set(false);

        sc.state.early_buf.set(buf);
        sc.state.early_preread.set(true);

        sc.state.in_early.set(true);

        unsafe {
            if BIO_get_ktls_send(SSL_get_wbio(ssl)) == 1 {
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "BIO_get_ktls_send(): 1");
                sc.state.sendfile.set(true);
            }
        }

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

    let sslerr = unsafe { SSL_get_error(ssl, n) };
    let err = if sslerr == SSL_ERROR_SYSCALL { errno() } else { 0 };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

    if sslerr == SSL_ERROR_WANT_READ {
        return IoStep::WantRead;
    }

    if sslerr == SSL_ERROR_WANT_WRITE {
        return IoStep::WantWrite;
    }

    let mut sslerr = sslerr;

    if sslerr == SSL_ERROR_SYSCALL && unsafe { ERR_peek_error() } == 0 && err == 0 {
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

    let ssl = ngx_ssl_conn(c);

    unsafe {
        let cipher = SSL_get_current_cipher(ssl);

        if !cipher.is_null() {
            let mut buf = [0u8; 129];

            SSL_CIPHER_description(cipher, buf[1..].as_mut_ptr() as *mut c_char, 128);

            let src = cstr(buf[1..].as_ptr() as *const c_char).to_vec();

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

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL: {}, cipher: \"{}\"", B(cstr(SSL_get_version(ssl))), B(&d));

            if SSL_session_reused(ssl) != 0 {
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL reused session");
            }
        } else {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL no shared ciphers");
        }
    }
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

    let ssl = ssl_ptr(sc);

    let mut bytes = 0usize;
    let mut size = buf.len();

    ngx_ssl_clear_error(&c.log);

    /*
     * SSL_read() may return data in parts, so try to read
     * until SSL_read() would return no data
     */

    loop {
        let n = unsafe { SSL_read(ssl, buf[bytes..].as_mut_ptr() as *mut c_void, size.min(c_int::MAX as usize) as c_int) };

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_read: {}", n);

        if n > 0 {
            bytes += n as usize;
        }

        let (last, want_write) = ngx_ssl_handle_recv(c, sc, n);

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

    let ssl = ssl_ptr(sc);

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
        let mut readbytes = 0usize;

        let n = unsafe { SSL_read_early_data(ssl, buf[bytes..].as_mut_ptr() as *mut c_void, size, &mut readbytes) };

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_read_early_data: {}, {}", n, readbytes);

        if n == SSL_READ_EARLY_DATA_SUCCESS {
            let (last, _) = ngx_ssl_handle_recv(c, sc, 1);
            sc.state.last.set(last);

            bytes += readbytes;
            size -= readbytes;

            if size == 0 {
                return IoStep::Done(Ok(bytes));
            }

            continue;
        }

        if n == SSL_READ_EARLY_DATA_FINISH {
            let (last, _) = ngx_ssl_handle_recv(c, sc, 1);
            sc.state.last.set(last);
            sc.state.in_early.set(false);

            if bytes != 0 {
                return IoStep::Done(Ok(bytes));
            }

            return ngx_ssl_recv_step(c, sc, &mut buf[bytes..]);
        }

        /* SSL_READ_EARLY_DATA_ERROR */

        let (last, want_write) = ngx_ssl_handle_recv(c, sc, 0);
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

/// ngx_ssl_handle_recv: (rc, the read waits for writing)
fn ngx_ssl_handle_recv(c: &Connection, sc: &SslConnection, n: c_int) -> (i64, bool) {
    if n > 0 {
        return (NGX_OK, false);
    }

    let ssl = ssl_ptr(sc);

    let sslerr = unsafe { SSL_get_error(ssl, n) };

    let err = if sslerr == SSL_ERROR_SYSCALL { errno() } else { 0 };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

    if sslerr == SSL_ERROR_WANT_READ {
        // c->read->ready = 0: OpenSSL's read found the socket drained, also
        // when ngx_ssl_recv returns the data read before
        c.read_drained();
        return (NGX_AGAIN, false);
    }

    if sslerr == SSL_ERROR_WANT_WRITE {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_read: want write");

        return (NGX_AGAIN, true);
    }

    let mut sslerr = sslerr;

    if sslerr == SSL_ERROR_SYSCALL && unsafe { ERR_peek_error() } == 0 && err == 0 {
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

    let ssl = ssl_ptr(sc);

    let n = unsafe { SSL_write(ssl, data.as_ptr() as *const c_void, data.len().min(c_int::MAX as usize) as c_int) };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_write: {}", n);

    if n > 0 {
        c.sent.set(c.sent.get() + n as u64);

        return IoStep::Done(Ok(n as usize));
    }

    let mut sslerr = unsafe { SSL_get_error(ssl, n) };

    if sslerr == SSL_ERROR_ZERO_RETURN {
        /*
         * OpenSSL 1.1.1 fails to return SSL_ERROR_SYSCALL if an error
         * happens during SSL_write() after close_notify alert from the
         * peer, and returns SSL_ERROR_ZERO_RETURN instead,
         * see https://github.com/openssl/openssl/commit/8051ab2
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    let err = if sslerr == SSL_ERROR_SYSCALL { errno() } else { 0 };

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

    let ssl = ssl_ptr(sc);

    let mut written = 0usize;

    let n = unsafe { SSL_write_early_data(ssl, data.as_ptr() as *const c_void, data.len(), &mut written) };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_write_early_data: {}, {}", n, written);

    if n > 0 {
        sc.state.write_blocked.set(false);

        c.sent.set(c.sent.get() + written as u64);

        return IoStep::Done(Ok(written));
    }

    let sslerr = unsafe { SSL_get_error(ssl, n) };

    let err = if sslerr == SSL_ERROR_SYSCALL { errno() } else { 0 };

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

extern "C" {
    fn SSL_write_early_data(ssl: *mut SSL, buf: *const c_void, num: usize, written: *mut usize) -> c_int;
}

/// A buffer of the chain passed to ngx_ssl_send_chain(): pos..last of a
/// buffer in memory, or file_pos..file_last of a buffer in a file
/// (in_file); a buffer with neither is special (flush, last_buf, sync).
pub struct SslChainBuf<'a> {
    pub mem: &'a [u8],
    pub file: Option<SslChainFile<'a>>,
    pub flush: bool,
    pub last_buf: bool,
}

/// file->fd, file->name, file_pos, file_last
pub struct SslChainFile<'a> {
    pub fd: c_int,
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

/// c->ssl->buf of NGX_SSL_BUFFER: allocated on the first use, freed by
/// ngx_ssl_free_buffer().
#[derive(Default)]
pub struct SslBuf {
    data: Vec<u8>,
    pos: usize,
    last: usize,
    flush: bool,
}

/// NGX_SSL_BUFFERED in c->buffered: data not written from c->ssl->buf.
pub fn ngx_ssl_buffered(sc: &SslConnection) -> bool {
    let buf = sc.state.buf.borrow();
    buf.pos < buf.last
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
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return IoStep::Done(Err(())),
    };

    if !sc.state.buffer.get() {
        while pos.link < links.len() {
            let b = &links[pos.link];

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

    if buf.data.is_empty() {
        buf.data = vec![0; sc.buffer_size.get()];
        buf.pos = 0;
        buf.last = 0;
    }

    let end = buf.data.len();

    let mut send = (buf.last - buf.pos) as i64;
    let mut flush = pos.link >= links.len() || buf.flush;

    let mut again = None;

    loop {
        while pos.link < links.len() && buf.last < end && send < limit {
            let b = &links[pos.link];

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

            let mut size = rest.len().min(end - buf.last);

            if send + size as i64 > limit {
                size = (limit - send) as usize;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL buf copy: {}", size);

            let last = buf.last;
            buf.data[last..last + size].copy_from_slice(&rest[..size]);

            buf.last += size;
            pos.off += size as i64;
            send += size as i64;

            if pos.off as usize == b.mem.len() {
                pos.link += 1;
                pos.off = 0;
            }
        }

        if !flush && send < limit && buf.last < end {
            break;
        }

        let size = buf.last - buf.pos;

        if size == 0 {
            if pos.link < links.len() && links[pos.link].file.is_some() && send < limit {
                /* coalesce the neighbouring file bufs */

                let file_size = ngx_ssl_chain_coalesce_file(links, *pos, limit - send);

                match ngx_ssl_sendfile(c, &sc, &links[pos.link], pos.off, file_size) {
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

        let (p, l) = (buf.pos, buf.last);

        match ngx_ssl_write_step(c, &sc, &buf.data[p..l]) {
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
                buf.last = 0;

                if pos.link >= links.len() || send >= limit {
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
fn ngx_ssl_chain_coalesce_file(links: &[SslChainBuf<'_>], pos: SslChainPos, limit: i64) -> i64 {
    let first = links[pos.link].file.as_ref().expect("file buf");

    let fd = first.fd;
    let mut fprev = first.pos + pos.off;
    let mut total = 0i64;
    let mut i = pos.link;
    let mut off = pos.off;

    while i < links.len() {
        let f = match &links[i].file {
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
fn ngx_ssl_chain_update_sent(links: &[SslChainBuf<'_>], pos: &mut SslChainPos, mut sent: i64) {
    while pos.link < links.len() {
        let b = &links[pos.link];

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

    unsafe { *libc::__errno_location() = 0 };

    let ssl = ssl_ptr(sc);

    let n = unsafe { SSL_sendfile(ssl, file.fd, file_pos as libc::off_t, size as usize, 0) };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_sendfile: {}", n);

    if n > 0 {
        c.sent.set(c.sent.get() + n as u64);

        return IoStep::Done(Ok(n as i64));
    }

    if n == 0 {
        /*
         * if sendfile returns zero, then someone has truncated the file,
         * so the offset became beyond the end of the file
         */

        ngx_log_error!(NGX_LOG_ALERT, c.log, None, "SSL_sendfile() reported that \"{}\" was truncated at {}", B(file.name), file_pos);

        return IoStep::Done(Err(()));
    }

    let mut sslerr = unsafe { SSL_get_error(ssl, n as c_int) };

    if sslerr == SSL_ERROR_ZERO_RETURN {
        /*
         * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
         * happens during writing after close_notify alert from the
         * peer, and returns SSL_ERROR_ZERO_RETURN instead
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    if sslerr == SSL_ERROR_SSL && ERR_GET_REASON(unsafe { ERR_peek_error() }) == SSL_R_UNINITIALIZED && errno() != 0 {
        /*
         * OpenSSL fails to return SSL_ERROR_SYSCALL if an error
         * happens in sendfile(), and returns SSL_ERROR_SSL with
         * SSL_R_UNINITIALIZED reason instead
         */

        sslerr = SSL_ERROR_SYSCALL;
    }

    let err = if sslerr == SSL_ERROR_SYSCALL { errno() } else { 0 };

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

extern "C" {
    fn SSL_sendfile(s: *mut SSL, fd: c_int, offset: libc::off_t, size: usize, flags: c_int) -> isize;
}

/// ngx_ssl_send_chain() with the waiting of its callers (the write event
/// handlers): the chain is taken until it all is and, when flushing,
/// c->ssl->buf is written, or until `limit` bytes of it are taken (the
/// limit of a pass counts the data it finds in c->ssl->buf, which a pass
/// after NGX_AGAIN finds again). Returns the bytes of the chain taken.
pub async fn ngx_ssl_send_chain_wait(c: &Connection, links: &[SslChainBuf<'_>], limit: i64) -> io::Result<i64> {
    let taken = |pos: SslChainPos| -> i64 { links[..pos.link.min(links.len())].iter().map(|b| b.rest(0)).sum::<i64>() + pos.off };

    let mut pos = SslChainPos::default();

    let r = c
        .drive_io(|| {
            if limit <= 0 {
                return ngx_ssl_send_chain(c, links, &mut pos, 0);
            }

            let left = limit - taken(pos);

            let buffered = match c.ssl.borrow().as_ref() {
                Some(sc) => {
                    let buf = sc.state.buf.borrow();
                    (buf.last - buf.pos) as i64
                }
                None => 0,
            };

            if left <= 0 && buffered == 0 {
                return IoStep::Done(Ok(()));
            }

            ngx_ssl_send_chain(c, links, &mut pos, left.max(0) + buffered)
        })
        .await?;

    match r {
        Ok(()) => Ok(taken(pos)),
        Err(()) => Err(ssl_error_logged()),
    }
}

/// ngx_ssl_free_buffer: c->ssl->buf of an idle connection is freed.
pub fn ngx_ssl_free_buffer(c: &Connection) {
    if let Some(sc) = c.ssl.borrow().as_ref() {
        let mut buf = sc.state.buf.borrow_mut();

        if buf.pos == buf.last {
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

    let ssl = ssl_ptr(&sc);

    crate::event_openssl_stapling::ngx_ssl_ocsp_cleanup(c);

    let rc = 'done: {
        if ssl.is_null() || unsafe { SSL_in_init(ssl) } != 0 {
            /*
             * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
             * an SSL handshake, while previous versions always return 0.
             * Avoid calling SSL_shutdown() if handshake wasn't completed.
             */

            break 'done NGX_OK;
        }

        unsafe {
            let mode;

            if c.timedout.get() || c.error.get() || ngx_ssl_buffered(&sc) {
                mode = SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN;
                SSL_set_quiet_shutdown(ssl, 1);
            } else {
                let mut m = SSL_get_shutdown(ssl);

                if sc.no_wait_shutdown.get() {
                    m |= SSL_RECEIVED_SHUTDOWN;
                }

                if sc.no_send_shutdown.get() {
                    m |= SSL_SENT_SHUTDOWN;
                }

                if sc.no_wait_shutdown.get() && sc.no_send_shutdown.get() {
                    SSL_set_quiet_shutdown(ssl, 1);
                }

                mode = m;
            }

            SSL_set_shutdown(ssl, mode);
        }

        ngx_ssl_clear_error(&c.log);

        let mut tries = 2;

        loop {
            /*
             * For bidirectional shutdown, SSL_shutdown() needs to be called
             * twice: first call sends the "close notify" alert and returns 0,
             * second call waits for the peer's "close notify" alert.
             */

            let n = unsafe { SSL_shutdown(ssl) };

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_shutdown: {}", n);

            if n == 1 {
                break 'done NGX_OK;
            }

            if n == 0 && tries > 1 {
                tries -= 1;
                continue;
            }

            /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */

            let sslerr = unsafe { SSL_get_error(ssl, n) };
            let err = if sslerr == SSL_ERROR_SYSCALL { errno() } else { 0 };

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

            if sslerr == SSL_ERROR_WANT_READ {
                return IoStep::WantRead;
            }

            if sslerr == SSL_ERROR_WANT_WRITE {
                return IoStep::WantWrite;
            }

            let mut sslerr = sslerr;

            if sslerr == SSL_ERROR_SYSCALL && unsafe { ERR_peek_error() } == 0 && err == 0 {
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
pub fn ngx_ssl_connection_error(c: &Connection, sslerr: c_int, err: i32, text: &str) {
    let mut level = NGX_LOG_CRIT;

    let peer_error = if sslerr == SSL_ERROR_SYSCALL {
        [libc::ECONNRESET, libc::EPIPE, libc::ENOTCONN, libc::ETIMEDOUT, libc::ECONNREFUSED, libc::ENETDOWN, libc::ENETUNREACH, libc::EHOSTDOWN, libc::EHOSTUNREACH].contains(&err)
    } else if sslerr == SSL_ERROR_SSL {
        let n = ERR_GET_REASON(unsafe { ERR_peek_last_error() });

        /* handshake failures */
        const HANDSHAKE_FAILURES: &[c_int] = &[
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

        HANDSHAKE_FAILURES.contains(&n) || (SSL_AD_REASON_OFFSET..=SSL_AD_REASON_OFFSET + 255).contains(&n)
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
    unsafe {
        while ERR_peek_error() != 0 {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("ignoring stale global SSL error"));
        }

        ERR_clear_error();
    }
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

    unsafe {
        if ERR_peek_error() != 0 {
            let pfx = b" (SSL:";
            let room = last.saturating_sub(errstr.len() + 1);
            errstr.extend_from_slice(&pfx[..pfx.len().min(room)]);

            loop {
                let mut data: *const c_char = std::ptr::null();
                let mut flags: c_int = 0;

                let n = ERR_peek_error_data(&mut data, &mut flags);

                if n == 0 {
                    break;
                }

                /* ERR_error_string_n() requires at least one byte */

                if errstr.len() < last - 1 {
                    errstr.push(b' ');

                    let mut buf = [0u8; NGX_MAX_CONF_ERRSTR];
                    let room = last - errstr.len();

                    ERR_error_string_n(n, buf.as_mut_ptr() as *mut c_char, room);

                    errstr.extend_from_slice(cstr(buf.as_ptr() as *const c_char));

                    if errstr.len() < last && !data.is_null() && *data != 0 && (flags & ERR_TXT_STRING) != 0 {
                        errstr.push(b':');

                        let d = cstr(data);
                        let room = (last - errstr.len()).saturating_sub(1);
                        errstr.extend_from_slice(&d[..d.len().min(room)]);
                    }
                }

                // next:

                ERR_get_error();
            }

            if errstr.len() < last {
                errstr.push(b')');
            }
        }
    }

    ngx_log_error!(level, log, Some(err), "{}", B(&errstr));
}

// --- the session cache ---

/// ngx_ssl_session_cache
pub fn ngx_ssl_session_cache(ssl: &mut NgxSsl, sess_ctx: &[u8], certificates: Option<&Vec<Vec<u8>>>, builtin_session_cache: isize, shm_zone: Option<&Rc<ShmZone>>, timeout: i64) -> i64 {
    unsafe {
        SSL_CTX_set_timeout(ssl.ctx, timeout as c_long);

        if ngx_ssl_session_id_context(ssl, sess_ctx, certificates) != NGX_OK {
            return NGX_ERROR;
        }

        if builtin_session_cache == NGX_SSL_NO_SCACHE {
            SSL_CTX_set_session_cache_mode(ssl.ctx, SSL_SESS_CACHE_OFF);
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

            SSL_CTX_set_session_cache_mode(ssl.ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR | SSL_SESS_CACHE_NO_INTERNAL_STORE);

            SSL_CTX_sess_set_cache_size(ssl.ctx, 1);

            return NGX_OK;
        }

        let mut cache_mode = SSL_SESS_CACHE_SERVER;

        if shm_zone.is_some() && builtin_session_cache == NGX_SSL_NO_BUILTIN_SCACHE {
            cache_mode |= SSL_SESS_CACHE_NO_INTERNAL;
        }

        SSL_CTX_set_session_cache_mode(ssl.ctx, cache_mode);

        if builtin_session_cache != NGX_SSL_NO_BUILTIN_SCACHE && builtin_session_cache != NGX_SSL_DFLT_BUILTIN_SCACHE {
            SSL_CTX_sess_set_cache_size(ssl.ctx, builtin_session_cache as c_long);
        }

        if let Some(zone) = shm_zone {
            SSL_CTX_sess_set_new_cb(ssl.ctx, Some(ngx_ssl_new_session));
            SSL_CTX_sess_set_get_cb(ssl.ctx, Some(ngx_ssl_get_cached_session));
            SSL_CTX_sess_set_remove_cb(ssl.ctx, Some(ngx_ssl_remove_session));

            // the zone is referenced by the configuration as long as the
            // context exists
            if SSL_CTX_set_ex_data(ssl.ctx, ngx_ssl_session_cache_index(), Rc::as_ptr(zone) as *mut c_void) == 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_ex_data() failed"));
                return NGX_ERROR;
            }
        }
    }

    NGX_OK
}

/// ngx_ssl_session_id_context: the string, the server certificates and
/// the client CA list
fn ngx_ssl_session_id_context(ssl: &mut NgxSsl, sess_ctx: &[u8], certificates: Option<&Vec<Vec<u8>>>) -> i64 {
    unsafe {
        let md = EVP_MD_CTX_new();
        if md.is_null() {
            return NGX_ERROR;
        }

        let mut buf = [0u8; EVP_MAX_MD_SIZE];
        let mut len: c_uint = 0;

        let ok = 'failed: {
            if EVP_DigestInit_ex(md, EVP_sha1(), std::ptr::null_mut()) == 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("EVP_DigestInit_ex() failed"));
                break 'failed false;
            }

            if EVP_DigestUpdate(md, sess_ctx.as_ptr() as *const c_void, sess_ctx.len()) == 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("EVP_DigestUpdate() failed"));
                break 'failed false;
            }

            for &cert in ssl.certs.iter() {
                if X509_digest(cert, EVP_sha1(), buf.as_mut_ptr(), &mut len) == 0 {
                    ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_digest() failed"));
                    break 'failed false;
                }

                if EVP_DigestUpdate(md, buf.as_ptr() as *const c_void, len as usize) == 0 {
                    ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("EVP_DigestUpdate() failed"));
                    break 'failed false;
                }
            }

            if ssl.certs.is_empty() {
                if let Some(certs) = certificates {
                    /*
                     * If certificates are loaded dynamically, we use certificate
                     * names as specified in the configuration (with variables).
                     */

                    for cert in certs.iter() {
                        if EVP_DigestUpdate(md, cert.as_ptr() as *const c_void, cert.len()) == 0 {
                            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("EVP_DigestUpdate() failed"));
                            break 'failed false;
                        }
                    }
                }
            }

            let list = SSL_CTX_get_client_CA_list(ssl.ctx);

            if !list.is_null() {
                let n = OPENSSL_sk_num(list);

                for i in 0..n {
                    let name = OPENSSL_sk_value(list, i) as *const X509_NAME;

                    if X509_NAME_digest(name, EVP_sha1(), buf.as_mut_ptr(), &mut len) == 0 {
                        ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_NAME_digest() failed"));
                        break 'failed false;
                    }

                    if EVP_DigestUpdate(md, buf.as_ptr() as *const c_void, len as usize) == 0 {
                        ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("EVP_DigestUpdate() failed"));
                        break 'failed false;
                    }
                }
            }

            if EVP_DigestFinal_ex(md, buf.as_mut_ptr(), &mut len) == 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("EVP_DigestFinal_ex() failed"));
                break 'failed false;
            }

            true
        };

        EVP_MD_CTX_free(md);

        if !ok {
            return NGX_ERROR;
        }

        if SSL_CTX_set_session_id_context(ssl.ctx, buf.as_ptr(), len) == 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_session_id_context() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_sess_id_t
#[repr(C)]
struct SslSessId {
    node: RbtreeNode,
    len: usize,
    queue: Queue,
    expire: i64,
    id: [u8; 32],
    session: *mut u8,
}

/// ngx_ssl_session_cache_t (in the shared memory zone)
#[repr(C)]
pub struct SslSessionCache {
    session_rbtree: Rbtree,
    sentinel: RbtreeNode,
    expire_queue: Queue,
    ticket_keys: [SslTicketKey; 3],
    fail_time: i64,
}

/// shm_zone->data of a session cache zone
pub struct SslSessionCacheData {
    pub cache: Cell<*mut SslSessionCache>,
}

/// ngx_ssl_session_cache_init
pub fn ngx_ssl_session_cache_init(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn std::any::Any>>) -> Result<(), ()> {
    if let Some(d) = data {
        *shm_zone.data.borrow_mut() = Some(d);
        return Ok(());
    }

    let shpool = shm_zone.shm.addr.get() as *mut SlabPool;

    unsafe {
        if shm_zone.shm.exists.get() {
            let d: Rc<dyn std::any::Any> = Rc::new(SslSessionCacheData { cache: Cell::new((*shpool).data as *mut SslSessionCache) });
            *shm_zone.data.borrow_mut() = Some(d);
            return Ok(());
        }

        let cache = (*shpool).alloc(std::mem::size_of::<SslSessionCache>()) as *mut SslSessionCache;
        if cache.is_null() {
            return Err(());
        }

        (*shpool).data = cache as *mut u8;

        let d: Rc<dyn std::any::Any> = Rc::new(SslSessionCacheData { cache: Cell::new(cache) });
        *shm_zone.data.borrow_mut() = Some(d);

        (*cache).session_rbtree.init(&mut (*cache).sentinel, ngx_ssl_session_rbtree_insert_value);

        crate::queue::queue_init(std::ptr::addr_of_mut!((*cache).expire_queue));

        (*cache).ticket_keys[0] = SslTicketKey::zeroed();
        (*cache).ticket_keys[1] = SslTicketKey::zeroed();
        (*cache).ticket_keys[2] = SslTicketKey::zeroed();

        (*cache).fail_time = 0;

        let ctx = format!(" in SSL session shared cache \"{}\"", B(&shm_zone.shm.name));

        (*shpool).set_log_ctx(ctx.as_bytes())?;

        (*shpool).log_nomem = false;
    }

    Ok(())
}

/// The session cache zone of a context and its cache.
unsafe fn session_cache_of(ssl_ctx: *const SSL_CTX) -> Option<(&'static ShmZone, *mut SslSessionCache, *mut SlabPool)> {
    let p = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_session_cache_index()) as *const ShmZone;

    if p.is_null() {
        return None;
    }

    let zone = &*p;

    let cache = zone.data::<SslSessionCacheData>()?.cache.get();

    Some((zone, cache, zone.shm.addr.get() as *mut SlabPool))
}

unsafe fn sess_id_of(node: *mut RbtreeNode) -> *mut SslSessId {
    // the node is the first field of ngx_ssl_sess_id_t
    node as *mut SslSessId
}

unsafe fn sess_id_of_queue(q: *mut Queue) -> *mut SslSessId {
    (q as *mut u8).sub(std::mem::offset_of!(SslSessId, queue)) as *mut SslSessId
}

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

unsafe extern "C" fn ngx_ssl_new_session(ssl_conn: *mut SSL, sess: *mut SSL_SESSION) -> c_int {
    /*
     * OpenSSL tries to save TLSv1.3 sessions into session cache
     * even when using tickets for stateless session resumption,
     * "because some applications just want to know about the creation
     * of a session"; do not cache such sessions
     */

    if SSL_version(ssl_conn) == TLS1_3_VERSION && (SSL_get_options(ssl_conn) & SSL_OP_NO_TICKET) == 0 {
        return 0;
    }

    let len = i2d_SSL_SESSION(sess, std::ptr::null_mut());

    /* do not cache too big session */

    if len as usize > NGX_SSL_MAX_SESSION_SIZE || len <= 0 {
        return 0;
    }

    let mut buffer = vec![0u8; len as usize];
    let mut p = buffer.as_mut_ptr();
    i2d_SSL_SESSION(sess, &mut p);

    let mut session_id_length: c_uint = 0;
    let session_id = SSL_SESSION_get_id(sess, &mut session_id_length);

    /* do not cache sessions with too long session id */

    if session_id_length > 32 {
        return 0;
    }

    let session_id = std::slice::from_raw_parts(session_id, session_id_length as usize);

    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return 0,
    };

    let ssl_ctx = match c.ssl.borrow().as_ref() {
        Some(sc) => sc.state.session_ctx.get(),
        None => return 0,
    };

    let (_zone, cache, shpool) = match session_cache_of(ssl_ctx) {
        Some(z) => z,
        None => return 0,
    };

    (*shpool).lock();

    /* drop one or two expired sessions */
    ngx_ssl_expire_sessions(cache, shpool, 1);

    let n = std::mem::size_of::<SslSessId>();

    let failed = 'failed: {
        let mut sess_id = (*shpool).alloc_locked(n) as *mut SslSessId;

        if sess_id.is_null() {
            /* drop the oldest non-expired session and try once more */

            ngx_ssl_expire_sessions(cache, shpool, 0);

            sess_id = (*shpool).alloc_locked(n) as *mut SslSessId;

            if sess_id.is_null() {
                break 'failed Some(std::ptr::null_mut());
            }
        }

        (*sess_id).session = (*shpool).alloc_locked(len as usize);

        if (*sess_id).session.is_null() {
            /* drop the oldest non-expired session and try once more */

            ngx_ssl_expire_sessions(cache, shpool, 0);

            (*sess_id).session = (*shpool).alloc_locked(len as usize);

            if (*sess_id).session.is_null() {
                break 'failed Some(sess_id);
            }
        }

        std::ptr::copy_nonoverlapping(buffer.as_ptr(), (*sess_id).session, len as usize);
        (&mut (*sess_id).id)[..session_id.len()].copy_from_slice(session_id);

        let hash = crc32fast::hash(session_id);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl new session: {:08X}:{}:{}", hash, session_id_length, len);

        (*sess_id).node.key = hash as usize;
        (*sess_id).node.data = session_id_length as u8;
        (*sess_id).len = len as usize;

        (*sess_id).expire = crate::times::time() + SSL_CTX_get_timeout(ssl_ctx) as i64;

        crate::queue::queue_insert_head(std::ptr::addr_of_mut!((*cache).expire_queue), std::ptr::addr_of_mut!((*sess_id).queue));

        (*cache).session_rbtree.insert(&mut (*sess_id).node);

        None
    };

    if let Some(sess_id) = failed {
        if !sess_id.is_null() {
            (*shpool).free_locked(sess_id as *mut u8);
        }

        (*shpool).unlock();

        if (*cache).fail_time != crate::times::time() {
            (*cache).fail_time = crate::times::time();
            ngx_log_error!(NGX_LOG_WARN, c.log, None, "could not allocate new session{}", B((*shpool).log_ctx()));
        }

        return 0;
    }

    (*shpool).unlock();

    explicit_memzero(&mut buffer);

    0
}

unsafe extern "C" fn ngx_ssl_get_cached_session(ssl_conn: *mut SSL, id: *const u8, len: c_int, copy: *mut c_int) -> *mut SSL_SESSION {
    let id = std::slice::from_raw_parts(id, len.max(0) as usize);

    let hash = crc32fast::hash(id);
    *copy = 0;

    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return std::ptr::null_mut(),
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl get session: {:08X}:{}", hash, len);

    let ssl_ctx = match c.ssl.borrow().as_ref() {
        Some(sc) => sc.state.session_ctx.get(),
        None => return std::ptr::null_mut(),
    };

    let (_zone, cache, shpool) = match session_cache_of(ssl_ctx) {
        Some(z) => z,
        None => return std::ptr::null_mut(),
    };

    (*shpool).lock();

    let mut node = (*cache).session_rbtree.root;
    let sentinel = (*cache).session_rbtree.sentinel;

    while node != sentinel {
        if (hash as usize) < (*node).key {
            node = (*node).left;
            continue;
        }

        if (hash as usize) > (*node).key {
            node = (*node).right;
            continue;
        }

        /* hash == node->key */

        let sess_id = sess_id_of(node);

        let rc = memn2cmp(id, &(&(*sess_id).id)[..(*node).data as usize]);

        if rc == 0 {
            if (*sess_id).expire > crate::times::time() {
                let slen = (*sess_id).len;

                let buffer = std::slice::from_raw_parts((*sess_id).session, slen).to_vec();

                (*shpool).unlock();

                let mut p = buffer.as_ptr();

                return d2i_SSL_SESSION(std::ptr::null_mut(), &mut p, slen as c_long);
            }

            crate::queue::queue_remove(std::ptr::addr_of_mut!((*sess_id).queue));

            (*cache).session_rbtree.delete(node);

            explicit_memzero(std::slice::from_raw_parts_mut((*sess_id).session, (*sess_id).len));

            (*shpool).free_locked((*sess_id).session);
            (*shpool).free_locked(sess_id as *mut u8);

            break;
        }

        node = if rc < 0 { (*node).left } else { (*node).right };
    }

    // done:

    (*shpool).unlock();

    std::ptr::null_mut()
}

/// ngx_ssl_remove_cached_session
pub fn ngx_ssl_remove_cached_session(ssl: *mut SSL_CTX, sess: *mut SSL_SESSION) {
    if sess.is_null() {
        return;
    }

    unsafe {
        SSL_CTX_remove_session(ssl, sess);

        ngx_ssl_remove_session(ssl, sess);
    }
}

unsafe extern "C" fn ngx_ssl_remove_session(ssl: *mut SSL_CTX, sess: *mut SSL_SESSION) {
    let (_zone, cache, shpool) = match session_cache_of(ssl) {
        Some(z) => z,
        None => return,
    };

    let mut len: c_uint = 0;
    let id = SSL_SESSION_get_id(sess, &mut len);
    let id = std::slice::from_raw_parts(id, len as usize);

    let hash = crc32fast::hash(id);

    if let Some(c) = crate::cycle::try_cycle() {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl remove session: {:08X}:{}", hash, len);
    }

    (*shpool).lock();

    let mut node = (*cache).session_rbtree.root;
    let sentinel = (*cache).session_rbtree.sentinel;

    while node != sentinel {
        if (hash as usize) < (*node).key {
            node = (*node).left;
            continue;
        }

        if (hash as usize) > (*node).key {
            node = (*node).right;
            continue;
        }

        /* hash == node->key */

        let sess_id = sess_id_of(node);

        let rc = memn2cmp(id, &(&(*sess_id).id)[..(*node).data as usize]);

        if rc == 0 {
            crate::queue::queue_remove(std::ptr::addr_of_mut!((*sess_id).queue));

            (*cache).session_rbtree.delete(node);

            explicit_memzero(std::slice::from_raw_parts_mut((*sess_id).session, (*sess_id).len));

            (*shpool).free_locked((*sess_id).session);
            (*shpool).free_locked(sess_id as *mut u8);

            break;
        }

        node = if rc < 0 { (*node).left } else { (*node).right };
    }

    // done:

    (*shpool).unlock();
}

/// ngx_ssl_expire_sessions
unsafe fn ngx_ssl_expire_sessions(cache: *mut SslSessionCache, shpool: *mut SlabPool, mut n: usize) {
    let now = crate::times::time();

    while n < 3 {
        if crate::queue::queue_empty(std::ptr::addr_of!((*cache).expire_queue)) {
            return;
        }

        let q = crate::queue::queue_last(std::ptr::addr_of!((*cache).expire_queue));

        let sess_id = sess_id_of_queue(q);

        let first = n == 0;
        n += 1;

        if !first && (*sess_id).expire > now {
            return;
        }

        crate::queue::queue_remove(q);

        if let Some(c) = crate::cycle::try_cycle() {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "expire session: {:08X}", (*sess_id).node.key);
        }

        (*cache).session_rbtree.delete(&mut (*sess_id).node);

        explicit_memzero(std::slice::from_raw_parts_mut((*sess_id).session, (*sess_id).len));

        (*shpool).free_locked((*sess_id).session);
        (*shpool).free_locked(sess_id as *mut u8);
    }
}

/// ngx_ssl_session_rbtree_insert_value
unsafe fn ngx_ssl_session_rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let mut p: *mut *mut RbtreeNode;

    loop {
        if (*node).key < (*temp).key {
            p = &mut (*temp).left;
        } else if (*node).key > (*temp).key {
            p = &mut (*temp).right;
        } else {
            /* node->key == temp->key */

            let sess_id = sess_id_of(node);
            let sess_id_temp = sess_id_of(temp);

            p = if memn2cmp(&(&(*sess_id).id)[..(*node).data as usize], &(&(*sess_id_temp).id)[..(*temp).data as usize]) < 0 { &mut (*temp).left } else { &mut (*temp).right };
        }

        if *p == sentinel {
            break;
        }

        temp = *p;
    }

    *p = node;
    (*node).parent = temp;
    (*node).left = sentinel;
    (*node).right = sentinel;
    rbt_red(node);
}

// --- session tickets ---

/// ngx_ssl_session_ticket_keys
pub fn ngx_ssl_session_ticket_keys(cf: &mut Conf, ssl: &mut NgxSsl, paths: Option<&mut Vec<Vec<u8>>>) -> i64 {
    unsafe {
        if paths.is_none() && SSL_CTX_get_ex_data(ssl.ctx, ngx_ssl_session_cache_index()).is_null() {
            return NGX_OK;
        }

        let keys = Box::new(SslTicketKeys { keys: RefCell::new(Vec::with_capacity(paths.as_ref().map(|p| p.len()).unwrap_or(3))) });

        let kp = &*keys as *const SslTicketKeys as *mut c_void;

        ssl.ticket_keys = Some(keys);

        if SSL_CTX_set_ex_data(ssl.ctx, ngx_ssl_ticket_keys_index(), kp) == 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_ex_data() failed"));
            return NGX_ERROR;
        }

        if SSL_CTX_set_tlsext_ticket_key_cb(ssl.ctx, ngx_ssl_ticket_key_callback) == 0 {
            ngx_log_error!(
                NGX_LOG_WARN,
                cf.log,
                None,
                "nginx was built with Session Tickets support, however, now it is linked dynamically to an OpenSSL library which has no tlsext support, therefore Session Tickets are not available"
            );
            return NGX_OK;
        }

        let keys = ssl.ticket_keys.as_ref().unwrap();

        let paths = match paths {
            None => {
                /* placeholder for keys in shared memory */

                let mut k = keys.keys.borrow_mut();

                for _ in 0..3 {
                    let mut key = SslTicketKey::zeroed();
                    key.shared = true;
                    key.expire = 0;
                    k.push(key);
                }

                return NGX_OK;
            }
            Some(p) => p,
        };

        for path in paths.iter_mut() {
            *path = cf.full_name(path, true);

            let name = cstring(path);

            let fd = libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);

            if fd == -1 {
                cf.log_error(NGX_LOG_EMERG, Some(errno()), format_args!("open() \"{}\" failed", B(path)));
                return NGX_ERROR;
            }

            let mut buf = [0u8; 80];

            let ok = 'failed: {
                let mut st: libc::stat = std::mem::zeroed();

                if libc::fstat(fd, &mut st) == -1 {
                    cf.log_error(NGX_LOG_CRIT, Some(errno()), format_args!("fstat() \"{}\" failed", B(path)));
                    break 'failed false;
                }

                let size = st.st_size as usize;

                if size != 48 && size != 80 {
                    cf.log_error(NGX_LOG_EMERG, None, format_args!("\"{}\" must be 48 or 80 bytes", B(path)));
                    break 'failed false;
                }

                let n = libc::pread(fd, buf.as_mut_ptr() as *mut c_void, size, 0);

                if n == -1 {
                    cf.log_error(NGX_LOG_CRIT, Some(errno()), format_args!("pread() \"{}\" failed", B(path)));
                    break 'failed false;
                }

                if n as usize != size {
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

                keys.keys.borrow_mut().push(key);

                true
            };

            if libc::close(fd) == -1 {
                ngx_log_error!(NGX_LOG_ALERT, cf.log, Some(errno()), "close() \"{}\" failed", B(path));
            }

            explicit_memzero(&mut buf);

            if !ok {
                return NGX_ERROR;
            }
        }
    }

    NGX_OK
}

unsafe extern "C" fn ngx_ssl_ticket_key_callback(ssl_conn: *mut SSL, name: *mut u8, iv: *mut u8, ectx: *mut EVP_CIPHER_CTX, hctx: *mut HMAC_CTX, enc: c_int) -> c_int {
    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return -1,
    };

    let ssl_ctx = match c.ssl.borrow().as_ref() {
        Some(sc) => sc.state.session_ctx.get(),
        None => return -1,
    };

    if ngx_ssl_rotate_ticket_keys(ssl_ctx, &c.log) != NGX_OK {
        return -1;
    }

    let digest = EVP_sha256();

    let kp = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ticket_keys_index()) as *const SslTicketKeys;
    if kp.is_null() {
        return -1;
    }

    let keys = (*kp).keys.borrow();

    if keys.is_empty() {
        return -1;
    }

    if enc == 1 {
        /* encrypt session ticket */

        let mut hex = Vec::new();
        hex_dump(&mut hex, &keys[0].name);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ticket encrypt, key: \"{}\" ({} session)", B(&hex), if SSL_session_reused(ssl_conn) != 0 { "reused" } else { "new" });

        let (cipher, size) = if keys[0].size == 48 { (EVP_aes_128_cbc(), 16) } else { (EVP_aes_256_cbc(), 32) };

        if RAND_bytes(iv, EVP_CIPHER_get_iv_length(cipher)) != 1 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("RAND_bytes() failed"));
            return -1;
        }

        if EVP_EncryptInit_ex(ectx, cipher, std::ptr::null_mut(), keys[0].aes_key.as_ptr(), iv) != 1 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("EVP_EncryptInit_ex() failed"));
            return -1;
        }

        if HMAC_Init_ex(hctx, keys[0].hmac_key.as_ptr() as *const c_void, size, digest, std::ptr::null_mut()) != 1 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("HMAC_Init_ex() failed"));
            return -1;
        }

        std::ptr::copy_nonoverlapping(keys[0].name.as_ptr(), name, 16);

        1
    } else {
        /* decrypt session ticket */

        let tname = std::slice::from_raw_parts(name, 16);

        let i = match keys.iter().position(|k| k.name == tname) {
            Some(i) => i,
            None => {
                let mut hex = Vec::new();
                hex_dump(&mut hex, tname);

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ticket decrypt, key: \"{}\" not found", B(&hex));

                return 0;
            }
        };

        // found:

        let mut hex = Vec::new();
        hex_dump(&mut hex, &keys[i].name);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ticket decrypt, key: \"{}\"{}", B(&hex), if i == 0 { " (default)" } else { "" });

        let (cipher, size) = if keys[i].size == 48 { (EVP_aes_128_cbc(), 16) } else { (EVP_aes_256_cbc(), 32) };

        if HMAC_Init_ex(hctx, keys[i].hmac_key.as_ptr() as *const c_void, size, digest, std::ptr::null_mut()) != 1 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("HMAC_Init_ex() failed"));
            return -1;
        }

        if EVP_DecryptInit_ex(ectx, cipher, std::ptr::null_mut(), keys[i].aes_key.as_ptr(), iv) != 1 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("EVP_DecryptInit_ex() failed"));
            return -1;
        }

        /* renew if TLSv1.3 */

        if SSL_version(ssl_conn) == TLS1_3_VERSION {
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
unsafe fn ngx_ssl_rotate_ticket_keys(ssl_ctx: *mut SSL_CTX, log: &Log) -> i64 {
    let kp = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ticket_keys_index()) as *const SslTicketKeys;
    if kp.is_null() {
        return NGX_OK;
    }

    let mut keys = (*kp).keys.borrow_mut();

    if keys.is_empty() || !keys[0].shared {
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
    let expire = now + SSL_CTX_get_timeout(ssl_ctx) as i64;

    if keys[0].expire >= expire && keys[1].expire >= now {
        return NGX_OK;
    }

    let (_zone, cache, shpool) = match session_cache_of(ssl_ctx) {
        Some(z) => z,
        None => return NGX_OK,
    };

    (*shpool).lock();

    let key = &mut (*cache).ticket_keys;

    let mut buf = [0u8; 80];

    if key[0].expire == 0 {
        /* initialize the current key */

        if RAND_bytes(buf.as_mut_ptr(), 80) != 1 {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("RAND_bytes() failed"));
            (*shpool).unlock();
            return NGX_ERROR;
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

        if RAND_bytes(buf.as_mut_ptr(), 80) != 1 {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("RAND_bytes() failed"));
            (*shpool).unlock();
            return NGX_ERROR;
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

    (*shpool).unlock();

    NGX_OK
}

/// ngx_ssl_cleanup_ctx
pub fn ngx_ssl_cleanup_ctx(ssl: &mut NgxSsl) {
    unsafe {
        for &cert in ssl.certs.iter() {
            X509_free(cert);
        }

        ssl.certs.clear();

        SSL_CTX_free(ssl.ctx);
    }

    ssl.ctx = std::ptr::null_mut();
}

/// ngx_ssl_check_host: the certificate of the peer matches the name
pub fn ngx_ssl_check_host(c: &Connection, name: &[u8]) -> i64 {
    unsafe {
        let cert = SSL_get1_peer_certificate(ngx_ssl_conn(c));
        if cert.is_null() {
            return NGX_ERROR;
        }

        /* X509_check_host() is only available in OpenSSL 1.0.2+ */

        let rc = if name.is_empty() {
            NGX_ERROR
        } else if X509_check_host(cert, name.as_ptr() as *const c_char, name.len(), 0, std::ptr::null_mut()) != 1 {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "X509_check_host(): no match");
            NGX_ERROR
        } else {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "X509_check_host(): match");
            NGX_OK
        };

        X509_free(cert);

        rc
    }
}

// --- the connection variables ---

/// ngx_ssl_variable_handler_pt: the value of an SSL variable of a
/// connection with SSL
pub type SslVariableHandler = fn(c: &Connection, s: &mut Vec<u8>) -> i64;

/// ngx_ssl_get_protocol
pub fn ngx_ssl_get_protocol(c: &Connection, s: &mut Vec<u8>) -> i64 {
    *s = unsafe { cstr(SSL_get_version(ngx_ssl_conn(c))).to_vec() };
    NGX_OK
}

/// ngx_ssl_get_cipher_name
pub fn ngx_ssl_get_cipher_name(c: &Connection, s: &mut Vec<u8>) -> i64 {
    *s = unsafe { cstr(SSL_get_cipher_name(ngx_ssl_conn(c))).to_vec() };
    NGX_OK
}

/// ngx_ssl_get_ciphers
pub fn ngx_ssl_get_ciphers(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    unsafe {
        let ssl = ngx_ssl_conn(c);

        let bytes = SSL_get0_raw_cipherlist(ssl, std::ptr::null_mut());

        let mut ciphers: *const u8 = std::ptr::null();
        let n = SSL_get0_raw_cipherlist(ssl, &mut ciphers);

        if n <= 0 || bytes <= 0 {
            return NGX_OK;
        }

        let n = n / bytes;

        for i in 0..n {
            let p = ciphers.add((i * bytes) as usize);

            let cipher = SSL_CIPHER_find(ssl, p);

            if !cipher.is_null() {
                s.extend_from_slice(cstr(SSL_CIPHER_get_name(cipher)));
            } else {
                s.extend_from_slice(b"0x");
                hex_dump(s, std::slice::from_raw_parts(p, bytes as usize));
            }

            s.push(b':');
        }

        s.pop();
    }

    NGX_OK
}

fn group_name(ssl: *mut SSL, nid: c_int, s: &mut Vec<u8>) {
    unsafe {
        let name = SSL_group_to_name(ssl, nid);

        if !name.is_null() {
            s.extend_from_slice(cstr(name));
        } else {
            s.extend_from_slice(format!("0x{:04x}", nid & 0xffff).as_bytes());
        }
    }
}

/// ngx_ssl_get_curve
pub fn ngx_ssl_get_curve(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    unsafe {
        let ssl = ngx_ssl_conn(c);

        let nid = SSL_get_negotiated_group(ssl);

        if nid != NID_undef {
            if (nid & TLSEXT_nid_unknown) == 0 {
                s.extend_from_slice(cstr(OBJ_nid2sn(nid)));
                return NGX_OK;
            }

            group_name(ssl, nid, s);

            return NGX_OK;
        }
    }

    NGX_OK
}

/// ngx_ssl_get_curves
pub fn ngx_ssl_get_curves(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    unsafe {
        let ssl = ngx_ssl_conn(c);

        let n = SSL_get1_curves(ssl, std::ptr::null_mut());

        if n <= 0 {
            return NGX_OK;
        }

        let mut curves = vec![0 as c_int; n as usize];

        let n = SSL_get1_curves(ssl, curves.as_mut_ptr());

        for &nid in curves.iter().take(n.max(0) as usize) {
            if nid & TLSEXT_nid_unknown != 0 {
                group_name(ssl, nid, s);
            } else {
                s.extend_from_slice(cstr(OBJ_nid2sn(nid)));
            }

            s.push(b':');
        }

        s.pop();
    }

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

    unsafe {
        let ssl = ngx_ssl_conn(c);

        let n = SSL_get_sigalgs(ssl, -1, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());

        if n <= 0 {
            return NGX_OK;
        }

        for i in 0..n {
            let mut rsig: u8 = 0;
            let mut rhash: u8 = 0;

            SSL_get_sigalgs(ssl, i, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut rsig, &mut rhash);

            s.extend_from_slice(format!("0x{:04x}", ((rhash as u32) << 8) | rsig as u32).as_bytes());
            s.push(b':');
        }

        s.pop();
    }

    NGX_OK
}

/// ngx_ssl_get_session_id
pub fn ngx_ssl_get_session_id(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    unsafe {
        let sess = SSL_get0_session(ngx_ssl_conn(c));
        if sess.is_null() {
            return NGX_OK;
        }

        let mut len: c_uint = 0;
        let buf = SSL_SESSION_get_id(sess, &mut len);

        hex_dump(s, std::slice::from_raw_parts(buf, len as usize));
    }

    NGX_OK
}

/// ngx_ssl_get_session_reused
pub fn ngx_ssl_get_session_reused(c: &Connection, s: &mut Vec<u8>) -> i64 {
    *s = if unsafe { SSL_session_reused(ngx_ssl_conn(c)) } != 0 { b"r".to_vec() } else { b".".to_vec() };
    NGX_OK
}

/// ngx_ssl_get_early_data
pub fn ngx_ssl_get_early_data(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    /* OpenSSL */

    if unsafe { SSL_is_init_finished(ngx_ssl_conn(c)) } == 0 {
        s.extend_from_slice(b"1");
    }

    NGX_OK
}

/// ngx_ssl_get_server_name
pub fn ngx_ssl_get_server_name(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    unsafe {
        let name = SSL_get_servername(ngx_ssl_conn(c), TLSEXT_NAMETYPE_host_name);

        if !name.is_null() {
            s.extend_from_slice(cstr(name));
        }
    }

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

    unsafe {
        let mut data: *const u8 = std::ptr::null();
        let mut len: c_uint = 0;

        SSL_get0_alpn_selected(ngx_ssl_conn(c), &mut data, &mut len);

        if len > 0 {
            s.extend_from_slice(std::slice::from_raw_parts(data, len as usize));
        }
    }

    NGX_OK
}

/// The contents of a memory BIO.
unsafe fn bio_contents(bio: *mut BIO) -> Vec<u8> {
    let len = BIO_pending(bio).max(0) as usize;
    let mut v = vec![0u8; len];
    if len > 0 {
        BIO_read(bio, v.as_mut_ptr() as *mut c_void, len as c_int);
    }
    v
}

/// ngx_ssl_get_raw_certificate
pub fn ngx_ssl_get_raw_certificate(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    unsafe {
        let cert = SSL_get1_peer_certificate(ngx_ssl_conn(c));
        if cert.is_null() {
            return NGX_OK;
        }

        let bio = BIO_new(BIO_s_mem());
        if bio.is_null() {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("BIO_new() failed"));
            X509_free(cert);
            return NGX_ERROR;
        }

        if PEM_write_bio_X509(bio, cert) == 0 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("PEM_write_bio_X509() failed"));
            BIO_free(bio);
            X509_free(cert);
            return NGX_ERROR;
        }

        *s = bio_contents(bio);

        BIO_free(bio);
        X509_free(cert);
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

    unsafe {
        let cert = SSL_get1_peer_certificate(ngx_ssl_conn(c));
        if cert.is_null() {
            return NGX_OK;
        }

        let name = if issuer { X509_get_issuer_name(cert) } else { X509_get_subject_name(cert) };
        if name.is_null() {
            X509_free(cert);
            return NGX_ERROR;
        }

        let bio = BIO_new(BIO_s_mem());
        if bio.is_null() {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("BIO_new() failed"));
            X509_free(cert);
            return NGX_ERROR;
        }

        if X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_NAME_print_ex() failed"));
            BIO_free(bio);
            X509_free(cert);
            return NGX_ERROR;
        }

        *s = bio_contents(bio);

        BIO_free(bio);
        X509_free(cert);
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

    unsafe {
        let cert = SSL_get1_peer_certificate(ngx_ssl_conn(c));
        if cert.is_null() {
            return NGX_OK;
        }

        let name = if issuer { X509_get_issuer_name(cert) } else { X509_get_subject_name(cert) };
        if name.is_null() {
            X509_free(cert);
            return NGX_ERROR;
        }

        let p = X509_NAME_oneline(name, std::ptr::null_mut(), 0);
        if p.is_null() {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_NAME_oneline() failed"));
            X509_free(cert);
            return NGX_ERROR;
        }

        s.extend_from_slice(cstr(p));

        OPENSSL_free(p as *mut c_void);
        X509_free(cert);
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

    unsafe {
        let cert = SSL_get1_peer_certificate(ngx_ssl_conn(c));
        if cert.is_null() {
            return NGX_OK;
        }

        let bio = BIO_new(BIO_s_mem());
        if bio.is_null() {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("BIO_new() failed"));
            X509_free(cert);
            return NGX_ERROR;
        }

        i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert));

        *s = bio_contents(bio);

        BIO_free(bio);
        X509_free(cert);
    }

    NGX_OK
}

/// ngx_ssl_get_fingerprint
pub fn ngx_ssl_get_fingerprint(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    unsafe {
        let cert = SSL_get1_peer_certificate(ngx_ssl_conn(c));
        if cert.is_null() {
            return NGX_OK;
        }

        let mut buf = [0u8; EVP_MAX_MD_SIZE];
        let mut len: c_uint = 0;

        if X509_digest(cert, EVP_sha1(), buf.as_mut_ptr(), &mut len) == 0 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("X509_digest() failed"));
            X509_free(cert);
            return NGX_ERROR;
        }

        hex_dump(s, &buf[..len as usize]);

        X509_free(cert);
    }

    NGX_OK
}

/// ngx_ssl_get_client_verify
pub fn ngx_ssl_get_client_verify(c: &Connection, s: &mut Vec<u8>) -> i64 {
    s.clear();

    unsafe {
        let ssl = ngx_ssl_conn(c);

        let cert = SSL_get1_peer_certificate(ssl);
        if cert.is_null() {
            s.extend_from_slice(b"NONE");
            return NGX_OK;
        }

        X509_free(cert);

        let rc = SSL_get_verify_result(ssl);

        let str: Vec<u8>;

        if rc == X509_V_OK {
            match crate::event_openssl_stapling::ngx_ssl_ocsp_get_status(c) {
                Ok(()) => {
                    s.extend_from_slice(b"SUCCESS");
                    return NGX_OK;
                }
                Err(e) => str = e.as_bytes().to_vec(),
            }
        } else {
            str = cstr(X509_verify_cert_error_string(rc)).to_vec();
        }

        s.extend_from_slice(b"FAILED:");
        s.extend_from_slice(&str);
    }

    NGX_OK
}

fn get_validity(c: &Connection, s: &mut Vec<u8>, end: bool) -> i64 {
    s.clear();

    unsafe {
        let cert = SSL_get1_peer_certificate(ngx_ssl_conn(c));
        if cert.is_null() {
            return NGX_OK;
        }

        let bio = BIO_new(BIO_s_mem());
        if bio.is_null() {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("BIO_new() failed"));
            X509_free(cert);
            return NGX_ERROR;
        }

        ASN1_TIME_print(bio, if end { X509_get0_notAfter(cert) } else { X509_get0_notBefore(cert) });

        *s = bio_contents(bio);

        BIO_free(bio);
        X509_free(cert);
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

    unsafe {
        let cert = SSL_get1_peer_certificate(ngx_ssl_conn(c));
        if cert.is_null() {
            return NGX_OK;
        }

        let end = ngx_ssl_parse_time(X509_get0_notAfter(cert), &c.log);

        X509_free(cert);

        let end = match end {
            Some(e) => e,
            None => return NGX_OK,
        };

        let now = crate::times::time();

        if end < now + 86400 {
            s.extend_from_slice(b"0");
            return NGX_OK;
        }

        s.extend_from_slice(((end - now) / 86400).to_string().as_bytes());
    }

    NGX_OK
}

/// ngx_ssl_parse_time: ASN1_TIME_print() output ("MMM DD HH:MM:SS YYYY
/// [GMT]") parsed as an asctime() date
unsafe fn ngx_ssl_parse_time(asn1time: *const ASN1_TIME, log: &Log) -> Option<i64> {
    let bio = BIO_new(BIO_s_mem());
    if bio.is_null() {
        ngx_ssl_error(NGX_LOG_ALERT, log, 0, format_args!("BIO_new() failed"));
        return None;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, b"Tue ".as_ptr() as *const c_void, 4);
    ASN1_TIME_print(bio, asn1time);

    let mut value: *mut c_char = std::ptr::null_mut();
    let len = BIO_get_mem_data(bio, &mut value);

    let time = if value.is_null() || len <= 0 { None } else { crate::parse::parse_http_time(std::slice::from_raw_parts(value as *const u8, len as usize)) };

    BIO_free(bio);

    time
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

        unsafe {
            let f = CString::new("/nonexistent/file.pem").unwrap();
            let bio = BIO_new_file(f.as_ptr(), b"r\0".as_ptr() as *const c_char);
            assert!(bio.is_null());
            assert!(ERR_peek_error() != 0);
        }

        let log = Log::stderr(NGX_LOG_EMERG);
        ngx_ssl_error(NGX_LOG_DEBUG, &log, 0, format_args!("test"));

        assert_eq!(unsafe { ERR_peek_error() }, 0);
    }

    #[test]
    fn memn2cmp_orders_as_c() {
        assert_eq!(memn2cmp(b"abc", b"abc"), 0);
        assert!(memn2cmp(b"ab", b"abc") < 0);
        assert!(memn2cmp(b"abd", b"abc") > 0);
    }

    #[test]
    fn verify_error_optional() {
        assert!(ngx_ssl_verify_error_optional(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT));
        assert!(!ngx_ssl_verify_error_optional(X509_V_OK));
    }

    #[test]
    fn hex_is_lowercase() {
        let mut v = Vec::new();
        hex_dump(&mut v, &[0xab, 0x01]);
        assert_eq!(v, b"ab01");
    }

    /// A context with a self-signed EC certificate for "localhost".
    fn server_ssl(log: &Log) -> NgxSsl {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let mut ssl = NgxSsl::new(log.clone());
        assert_eq!(ngx_ssl_create(&mut ssl, NGX_SSL_DEFAULT_PROTOCOLS, std::ptr::null_mut()), NGX_OK);

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

        unsafe {
            assert_eq!(SSL_CTX_use_certificate(ssl.ctx, cert.as_ptr()), 1);
            assert_eq!(SSL_CTX_use_PrivateKey(ssl.ctx, key.as_ptr()), 1);
        }

        assert_eq!(ngx_ssl_session_cache(&mut ssl, b"TEST", None, NGX_SSL_DFLT_BUILTIN_SCACHE, None, 300), NGX_OK);

        ssl
    }

    fn pair(log: &Log) -> (Rc<Connection>, Rc<Connection>) {
        let mut fds = [0 as c_int; 2];
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0, fds.as_mut_ptr()) }, 0);

        let a = Connection::peer(fds[0], libc::SOCK_STREAM, crate::inet::SockAddr::Unix(b"a".to_vec()), log).unwrap();
        let b = Connection::peer(fds[1], libc::SOCK_STREAM, crate::inet::SockAddr::Unix(b"b".to_vec()), log).unwrap();

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
            assert_eq!(ngx_ssl_create(&mut client, NGX_SSL_DEFAULT_PROTOCOLS, std::ptr::null_mut()), NGX_OK);

            let mut saved: *mut SSL_SESSION = std::ptr::null_mut();

            for round in 0..2 {
                let (s, c) = pair(&log);

                assert_eq!(ngx_ssl_create_connection(&server, &s, 0), NGX_OK);
                assert_eq!(ngx_ssl_create_connection(&client, &c, NGX_SSL_BUFFER | NGX_SSL_CLIENT), NGX_OK);

                assert!(ngx_ssl_set_tlsext_host_name(&c, b"localhost"));
                assert_eq!(ngx_ssl_set_session(&c, saved), NGX_OK);

                let (rs, rc) = tokio::join!(handshake(&s), handshake(&c));
                assert_eq!((rs, rc), (NGX_OK, NGX_OK));

                let mut v = Vec::new();
                ngx_ssl_get_server_name(&s, &mut v);
                assert_eq!(v, b"localhost");

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

                ngx_ssl_free_session(saved);
                saved = ngx_ssl_get_session(&c);
                assert!(!saved.is_null());

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

            ngx_ssl_free_session(saved);
        });
    }

    /// The lengths of the TLS records waiting on the socket of `c`.
    async fn records(c: &Connection) -> Vec<usize> {
        let mut buf = vec![0u8; 65536];

        for _ in 0..100 {
            let n = unsafe { libc::recv(c.fd.get(), buf.as_mut_ptr() as *mut c_void, buf.len(), libc::MSG_PEEK) };

            if n > 0 {
                let mut v = Vec::new();
                let mut p = 0usize;

                while p + 5 <= n as usize {
                    let len = ((buf[p + 3] as usize) << 8) | buf[p + 4] as usize;
                    v.push(len);
                    p += 5 + len;
                }

                if p == n as usize {
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
            assert_eq!(ngx_ssl_create(&mut client, NGX_SSL_DEFAULT_PROTOCOLS, std::ptr::null_mut()), NGX_OK);

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
}
