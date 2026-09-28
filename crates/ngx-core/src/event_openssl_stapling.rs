//! ngx_event_openssl_stapling.c: OCSP stapling (ssl_stapling) and the OCSP
//! validation of client certificates (ssl_ocsp), with the OCSP requests
//! to the responders and the OCSP cache in shared memory.
//!
//! The OCSP requests (ngx_ssl_ocsp_request() .. the handler) are async
//! functions: the handler of the C context is the code run after the
//! request is done.  A stapling update runs as a task of its own; the
//! validation of a client certificate runs in the handshake
//! (ngx_ssl_handshake_wait()).

use std::cell::{Cell, RefCell};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_long, c_ulong, c_void};
use std::rc::Rc;
use std::time::Duration;

use crate::conf::Conf;
use crate::connection::{Connection, NGX_ERROR_ERR};
use crate::event_connect::{event_connect_peer, PeerConnect, PeerSocket};
use crate::event_openssl::*;
use crate::inet::{parse_url, Addr, Url};
use crate::log::*;
use crate::openssl_ffi::*;
use crate::queue::Queue;
use crate::rbtree::*;
use crate::rc::*;
use crate::resolver::{Resolved, Resolver};
use crate::shm::ShmZone;
use crate::slab::SlabPool;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};

const NGX_MAX_TIME_T_VALUE: i64 = i64::MAX;

const V_OCSP_CERTSTATUS_GOOD: c_int = 0;
const V_OCSP_CERTSTATUS_REVOKED: c_int = 1;

const OCSP_RESPONSE_STATUS_SUCCESSFUL: c_int = 0;

const OCSP_NOVERIFY: c_ulong = 0x10;
const OCSP_TRUSTOTHER: c_ulong = 0x200;

unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    if p.is_null() {
        return b"";
    }
    std::ffi::CStr::from_ptr(p).to_bytes()
}

fn status_str(s: c_int) -> &'static str {
    // OCSP_cert_status_str()
    unsafe {
        let p = OCSP_cert_status_str(s as c_long);
        std::str::from_utf8(cstr(p)).unwrap_or("")
    }
}

/// ngx_ssl_stapling_t
pub struct SslStapling {
    /// the OCSP response to staple (empty: none)
    staple: RefCell<Vec<u8>>,
    timeout: u64,

    resolver: RefCell<Option<Rc<Resolver>>>,
    resolver_timeout: Cell<u64>,

    addrs: RefCell<Vec<Addr>>,
    host: RefCell<Vec<u8>>,
    uri: RefCell<Vec<u8>>,
    port: Cell<u16>,

    ssl_ctx: *mut SSL_CTX,

    /// the certificate of the context (key of the lookup)
    cert: *mut X509,
    issuer: Cell<*mut X509>,
    chain: Cell<*mut OPENSSL_STACK>,

    name: Vec<u8>,

    valid: Cell<i64>,
    refresh: Cell<i64>,

    verify: bool,
    loading: Cell<bool>,
}

impl Drop for SslStapling {
    /// ngx_ssl_stapling_cleanup
    fn drop(&mut self) {
        let issuer = self.issuer.get();

        if !issuer.is_null() {
            unsafe { X509_free(issuer) };
        }
    }
}

/// ngx_ssl_ocsp_conf_t
pub struct SslOcspConf {
    addrs: Vec<Addr>,

    host: Vec<u8>,
    uri: Vec<u8>,
    port: u16,
    depth: usize,

    shm_zone: Option<Rc<ShmZone>>,

    resolver: RefCell<Option<Rc<Resolver>>>,
    resolver_timeout: Cell<u64>,
}

/// ngx_ssl_ocsp_t: the OCSP validation of a connection
pub struct SslOcsp {
    certs: Cell<*mut OPENSSL_STACK>,
    ncert: Cell<usize>,

    cert_status: Cell<c_int>,
    status: Cell<i64>,

    conf: *const SslOcspConf,

    /// the request in progress
    ctx: RefCell<Option<Box<OcspCtx>>>,
}

impl Drop for SslOcsp {
    fn drop(&mut self) {
        let certs = self.certs.replace(std::ptr::null_mut());

        if !certs.is_null() {
            unsafe { sk_X509_pop_free(certs) };
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Process {
    StatusLine,
    Headers,
    Body,
}

/// The context of the log messages of a request (ngx_ssl_ocsp_log_error).
struct OcspLogCtx {
    host: RefCell<Vec<u8>>,
    peer: RefCell<Option<Vec<u8>>>,
    name: RefCell<Option<Vec<u8>>>,
}

impl LogContext for OcspLogCtx {
    fn write_context(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b" while requesting certificate status");

        buf.extend_from_slice(b", responder: ");
        buf.extend_from_slice(&self.host.borrow());

        if let Some(peer) = self.peer.borrow().as_ref() {
            buf.extend_from_slice(b", peer: ");
            buf.extend_from_slice(peer);
        }

        if let Some(name) = self.name.borrow().as_ref() {
            buf.extend_from_slice(b", certificate: \"");
            buf.extend_from_slice(name);
            buf.push(b'"');
        }
    }
}

/// ngx_ssl_ocsp_ctx_t
pub struct OcspCtx {
    ssl_ctx: *mut SSL_CTX,

    cert: *mut X509,
    issuer: *mut X509,
    chain: *mut OPENSSL_STACK,

    status: c_int,
    valid: i64,

    naddr: usize,

    addrs: Vec<Addr>,
    host: Vec<u8>,
    uri: Vec<u8>,
    port: u16,

    resolver: Option<Rc<Resolver>>,
    resolver_timeout: u64,

    timeout: u64,

    key: Vec<u8>,
    request: Vec<u8>,
    request_pos: usize,
    /// the response buffer (16k): [pos..last] not processed yet
    response: Option<Vec<u8>>,
    response_pos: usize,
    response_last: usize,

    shm_zone: Option<Rc<ShmZone>>,

    process: Process,

    state: u32,

    code: u32,
    count: u32,
    flags: c_ulong,
    done: bool,

    header_name_start: usize,
    header_name_end: usize,
    header_start: usize,
    header_end: usize,

    log: Log,
    logctx: Rc<OcspLogCtx>,
}

impl Drop for OcspCtx {
    /// ngx_ssl_ocsp_done: the resolution and the connection of a request
    /// end with its future
    fn drop(&mut self) {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, self.log, "ssl ocsp done");
    }
}

/// ngx_ssl_stapling
pub fn ngx_ssl_stapling(cf: &mut Conf, ssl: &mut NgxSsl, file: &mut Vec<u8>, responder: &mut Vec<u8>, verify: bool) -> i64 {
    let certs = ssl.certs.clone();

    for cert in certs {
        if ngx_ssl_stapling_certificate(cf, ssl, cert, file, responder, verify) != NGX_OK {
            return NGX_ERROR;
        }
    }

    unsafe {
        SSL_CTX_set_tlsext_status_cb(ssl.ctx, ngx_ssl_certificate_status_callback);
    }

    NGX_OK
}

const SSL_CTRL_SELECT_CURRENT_CERT_: c_int = SSL_CTRL_SELECT_CURRENT_CERT;

/// ngx_ssl_stapling_certificate
fn ngx_ssl_stapling_certificate(cf: &mut Conf, ssl: &mut NgxSsl, cert: *mut X509, file: &mut Vec<u8>, responder: &mut Vec<u8>, verify: bool) -> i64 {
    let mut chain: *mut OPENSSL_STACK = std::ptr::null_mut();

    unsafe {
        /* OpenSSL 1.0.2+ */
        SSL_CTX_ctrl(ssl.ctx, SSL_CTRL_SELECT_CURRENT_CERT_, 0, cert as *mut c_void);

        /* OpenSSL 1.0.1+ */
        SSL_CTX_ctrl(ssl.ctx, SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 0, &mut chain as *mut *mut OPENSSL_STACK as *mut c_void);
    }

    let name = unsafe { cstr(X509_get_ex_data(cert, ngx_ssl_certificate_name_index()) as *const c_char).to_vec() };

    let staple = Rc::new(SslStapling {
        staple: RefCell::new(Vec::new()),
        timeout: 60000,
        resolver: RefCell::new(None),
        resolver_timeout: Cell::new(0),
        addrs: RefCell::new(Vec::new()),
        host: RefCell::new(Vec::new()),
        uri: RefCell::new(Vec::new()),
        port: Cell::new(0),
        ssl_ctx: ssl.ctx,
        cert,
        issuer: Cell::new(std::ptr::null_mut()),
        chain: Cell::new(chain),
        name,
        valid: Cell::new(0),
        refresh: Cell::new(0),
        verify,
        loading: Cell::new(false),
    });

    ssl.staples.borrow_mut().push(staple.clone());

    if !file.is_empty() {
        /* use OCSP response from the file */

        if ngx_ssl_stapling_file(cf, ssl, &staple, file) != NGX_OK {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    let rc = ngx_ssl_stapling_issuer(cf, ssl, &staple);

    if rc == NGX_DECLINED {
        return NGX_OK;
    }

    if rc != NGX_OK {
        return NGX_ERROR;
    }

    let rc = ngx_ssl_stapling_responder(cf, ssl, &staple, responder);

    if rc == NGX_DECLINED {
        return NGX_OK;
    }

    if rc != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_ssl_stapling_file
fn ngx_ssl_stapling_file(cf: &mut Conf, ssl: &mut NgxSsl, staple: &SslStapling, file: &mut Vec<u8>) -> i64 {
    *file = cf.full_name(file, true);

    unsafe {
        let name = CString::new(file.clone()).unwrap_or_default();

        let bio = BIO_new_file(name.as_ptr(), b"rb\0".as_ptr() as *const c_char);
        if bio.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("BIO_new_file(\"{}\") failed", B(file)));
            return NGX_ERROR;
        }

        /* d2i_OCSP_RESPONSE_bio() */
        let response = ASN1_d2i_bio(OCSP_RESPONSE_new, d2i_OCSP_RESPONSE as *const c_void, bio, std::ptr::null_mut());
        if response.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("d2i_OCSP_RESPONSE_bio(\"{}\") failed", B(file)));
            BIO_free(bio);
            return NGX_ERROR;
        }

        let len = i2d_OCSP_RESPONSE(response, std::ptr::null_mut());
        if len <= 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("i2d_OCSP_RESPONSE(\"{}\") failed", B(file)));
            OCSP_RESPONSE_free(response);
            BIO_free(bio);
            return NGX_ERROR;
        }

        let mut buf = vec![0u8; len as usize];

        let mut p = buf.as_mut_ptr();
        let len = i2d_OCSP_RESPONSE(response, &mut p);
        if len <= 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("i2d_OCSP_RESPONSE(\"{}\") failed", B(file)));
            OCSP_RESPONSE_free(response);
            BIO_free(bio);
            return NGX_ERROR;
        }

        OCSP_RESPONSE_free(response);
        BIO_free(bio);

        buf.truncate(len as usize);

        *staple.staple.borrow_mut() = buf;
        staple.valid.set(NGX_MAX_TIME_T_VALUE);
    }

    NGX_OK
}

/// ngx_ssl_stapling_issuer
fn ngx_ssl_stapling_issuer(_cf: &mut Conf, ssl: &mut NgxSsl, staple: &SslStapling) -> i64 {
    let cert = staple.cert;

    unsafe {
        let chain = staple.chain.get();

        let n = if chain.is_null() { 0 } else { OPENSSL_sk_num(chain) };

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ssl.log, "SSL get issuer: {} extra certs", n);

        for i in 0..n {
            let issuer = OPENSSL_sk_value(chain, i) as *mut X509;

            if X509_check_issued(issuer, cert) == X509_V_OK as c_int {
                X509_up_ref(issuer);

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ssl.log, "SSL get issuer: found {:p} in extra certs", issuer);

                staple.issuer.set(issuer);

                return NGX_OK;
            }
        }

        let store = SSL_CTX_get_cert_store(ssl.ctx);
        if store.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_get_cert_store() failed"));
            return NGX_ERROR;
        }

        let store_ctx = X509_STORE_CTX_new();
        if store_ctx.is_null() {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_STORE_CTX_new() failed"));
            return NGX_ERROR;
        }

        if X509_STORE_CTX_init(store_ctx, store, std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_STORE_CTX_init() failed"));
            X509_STORE_CTX_free(store_ctx);
            return NGX_ERROR;
        }

        let mut issuer: *mut X509 = std::ptr::null_mut();

        let rc = X509_STORE_CTX_get1_issuer(&mut issuer, store_ctx, cert);

        if rc == -1 {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("X509_STORE_CTX_get1_issuer() failed"));
            X509_STORE_CTX_free(store_ctx);
            return NGX_ERROR;
        }

        if rc == 0 {
            ngx_log_error!(NGX_LOG_WARN, ssl.log, None, "\"ssl_stapling\" ignored, issuer certificate not found for certificate \"{}\"", B(&staple.name));
            X509_STORE_CTX_free(store_ctx);
            return NGX_DECLINED;
        }

        X509_STORE_CTX_free(store_ctx);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ssl.log, "SSL get issuer: found {:p} in cert store", issuer);

        staple.issuer.set(issuer);
    }

    NGX_OK
}

/// The first OCSP responder URL of a certificate (X509_get1_ocsp()).
unsafe fn cert_ocsp_url(cert: *mut X509) -> Option<Vec<u8>> {
    let aia = X509_get1_ocsp(cert);
    if aia.is_null() {
        return None;
    }

    let s = OPENSSL_sk_value(aia, 0) as *const c_char;

    let url = if s.is_null() { None } else { Some(cstr(s).to_vec()) };

    X509_email_free(aia);

    url
}

/// ngx_ssl_stapling_responder
fn ngx_ssl_stapling_responder(_cf: &mut Conf, ssl: &mut NgxSsl, staple: &SslStapling, responder: &[u8]) -> i64 {
    let responder = if responder.is_empty() {
        /* extract OCSP responder URL from certificate */

        match unsafe { cert_ocsp_url(staple.cert) } {
            Some(url) => url,
            None => {
                ngx_log_error!(NGX_LOG_WARN, ssl.log, None, "\"ssl_stapling\" ignored, no OCSP responder URL in the certificate \"{}\"", B(&staple.name));
                return NGX_DECLINED;
            }
        }
    } else {
        responder.to_vec()
    };

    let mut u = Url::new(&responder);
    u.default_port = 80;
    u.uri_part = true;

    if u.url.len() > 7 && crate::string::strncasecmp(&u.url, b"http://", 7) == 0 {
        u.url.drain(..7);
    } else {
        ngx_log_error!(NGX_LOG_WARN, ssl.log, None, "\"ssl_stapling\" ignored, invalid URL prefix in OCSP responder \"{}\" in the certificate \"{}\"", B(&u.url), B(&staple.name));
        return NGX_DECLINED;
    }

    if parse_url(&mut u).is_err() {
        if let Some(err) = u.err {
            ngx_log_error!(NGX_LOG_WARN, ssl.log, None, "\"ssl_stapling\" ignored, {} in OCSP responder \"{}\" in the certificate \"{}\"", err, B(&u.url), B(&staple.name));
            return NGX_DECLINED;
        }

        return NGX_ERROR;
    }

    *staple.addrs.borrow_mut() = u.addrs;
    *staple.host.borrow_mut() = u.host;
    *staple.uri.borrow_mut() = if u.uri.is_empty() { b"/".to_vec() } else { u.uri };
    staple.port.set(u.port);

    NGX_OK
}

/// ngx_ssl_stapling_resolver
pub fn ngx_ssl_stapling_resolver(_cf: &mut Conf, ssl: &mut NgxSsl, resolver: Option<Rc<Resolver>>, resolver_timeout: u64) -> i64 {
    for staple in ssl.staples.borrow().iter() {
        *staple.resolver.borrow_mut() = resolver.clone();
        staple.resolver_timeout.set(resolver_timeout);
    }

    NGX_OK
}

/// ngx_ssl_certificate_status_callback: the staple of the certificate
unsafe extern "C" fn ngx_ssl_certificate_status_callback(ssl_conn: *mut SSL, _data: *mut c_void) -> c_int {
    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return SSL_TLSEXT_ERR_NOACK,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL certificate status callback");

    let mut rc = SSL_TLSEXT_ERR_NOACK;

    let cert = SSL_get_certificate(ssl_conn);

    if cert.is_null() {
        return rc;
    }

    let ssl_ctx = SSL_get_SSL_CTX(ssl_conn);
    let ssl = SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_index()) as *const NgxSsl;

    if ssl.is_null() {
        return rc;
    }

    let staple = match ngx_ssl_stapling_lookup(&*ssl, cert) {
        Some(s) => s,
        None => return rc,
    };

    {
        let data = staple.staple.borrow();

        if !data.is_empty() && staple.valid.get() >= crate::times::time() {
            /* we have to copy ocsp response as OpenSSL will free it by itself */

            let p = CRYPTO_malloc(data.len(), std::ptr::null(), 0) as *mut u8;
            if p.is_null() {
                ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("OPENSSL_malloc() failed"));
                return SSL_TLSEXT_ERR_NOACK;
            }

            std::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());

            SSL_ctrl(ssl_conn, SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP, data.len() as c_long, p as *mut c_void);

            rc = SSL_TLSEXT_ERR_OK;
        }
    }

    ngx_ssl_stapling_update(&staple);

    rc
}

/// ngx_ssl_stapling_lookup
fn ngx_ssl_stapling_lookup(ssl: &NgxSsl, cert: *mut X509) -> Option<Rc<SslStapling>> {
    ssl.staples.borrow().iter().find(|s| s.cert == cert).cloned()
}

/// ngx_ssl_stapling_update: a new OCSP response, in the background
fn ngx_ssl_stapling_update(staple: &Rc<SslStapling>) {
    if staple.host.borrow().is_empty() || staple.loading.get() || staple.refresh.get() >= crate::times::time() {
        return;
    }

    staple.loading.set(true);

    let log = match crate::cycle::try_cycle() {
        Some(c) => c.log.clone(),
        None => return,
    };

    let mut ctx = ngx_ssl_ocsp_start(&log);

    ctx.ssl_ctx = staple.ssl_ctx;
    ctx.cert = staple.cert;
    ctx.issuer = staple.issuer.get();
    ctx.chain = staple.chain.get();
    *ctx.logctx.name.borrow_mut() = Some(staple.name.clone());
    ctx.flags = if staple.verify { OCSP_TRUSTOTHER } else { OCSP_NOVERIFY };

    ctx.addrs = staple.addrs.borrow().clone();
    ctx.set_host(staple.host.borrow().clone());
    ctx.uri = staple.uri.borrow().clone();
    ctx.port = staple.port.get();
    ctx.timeout = staple.timeout;

    ctx.resolver = staple.resolver.borrow().clone();
    ctx.resolver_timeout = staple.resolver_timeout.get();

    let staple = staple.clone();

    crate::event::spawn(async move {
        ngx_ssl_ocsp_request(&mut ctx).await;

        ngx_ssl_stapling_ocsp_handler(&mut ctx, &staple);
    });
}

/// ngx_ssl_stapling_ocsp_handler
fn ngx_ssl_stapling_ocsp_handler(ctx: &mut OcspCtx, staple: &SslStapling) {
    let now = crate::times::time();

    let ok = 'error: {
        if ngx_ssl_ocsp_verify(ctx) != NGX_OK {
            break 'error false;
        }

        if ctx.status != V_OCSP_CERTSTATUS_GOOD {
            ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "certificate status \"{}\" in the OCSP response", status_str(ctx.status));
            break 'error false;
        }

        true
    };

    if !ok {
        staple.loading.set(false);
        staple.refresh.set(now + 300);

        return;
    }

    /* copy the response to memory not in ctx->pool */

    let response = ctx.response.as_ref().map(|r| r[ctx.response_pos..ctx.response_last].to_vec()).unwrap_or_default();

    *staple.staple.borrow_mut() = response;
    staple.valid.set(ctx.valid);

    /*
     * refresh before the response expires,
     * but not earlier than in 5 minutes, and at least in an hour
     */

    staple.loading.set(false);
    staple.refresh.set((ctx.valid.saturating_sub(300)).min(now + 3600).max(now + 300));
}

/// ngx_ssl_stapling_time: ASN1_GENERALIZEDTIME_print() parsed as an
/// asctime() date
unsafe fn ngx_ssl_stapling_time(asn1time: *mut ASN1_GENERALIZEDTIME) -> Option<i64> {
    let bio = BIO_new(BIO_s_mem());
    if bio.is_null() {
        return None;
    }

    /* fake weekday prepended to match C asctime() format */

    BIO_write(bio, b"Tue ".as_ptr() as *const c_void, 4);
    ASN1_GENERALIZEDTIME_print(bio, asn1time);

    let mut value: *mut c_char = std::ptr::null_mut();
    let len = BIO_get_mem_data(bio, &mut value);

    let time = if value.is_null() || len <= 0 { None } else { crate::parse::parse_http_time(std::slice::from_raw_parts(value as *const u8, len as usize)) };

    BIO_free(bio);

    time
}

/// ngx_ssl_ocsp
pub fn ngx_ssl_ocsp(cf: &mut Conf, ssl: &mut NgxSsl, responder: &[u8], depth: usize, shm_zone: Option<Rc<ShmZone>>) -> i64 {
    let mut ocf = SslOcspConf {
        addrs: Vec::new(),
        host: Vec::new(),
        uri: Vec::new(),
        port: 0,
        depth,
        shm_zone,
        resolver: RefCell::new(None),
        resolver_timeout: Cell::new(0),
    };

    if !responder.is_empty() {
        let mut u = Url::new(responder);
        u.default_port = 80;
        u.uri_part = true;

        if u.url.len() > 7 && crate::string::strncasecmp(&u.url, b"http://", 7) == 0 {
            u.url.drain(..7);
        } else {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "invalid URL prefix in OCSP responder \"{}\" in \"ssl_ocsp_responder\"", B(&u.url));
            return NGX_ERROR;
        }

        if parse_url(&mut u).is_err() {
            if let Some(err) = u.err {
                ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{} in OCSP responder \"{}\" in \"ssl_ocsp_responder\"", err, B(&u.url));
            }

            return NGX_ERROR;
        }

        ocf.addrs = u.addrs;
        ocf.host = u.host;
        ocf.uri = u.uri;
        ocf.port = u.port;
    }

    let ocf = Box::new(ocf);
    let p = &*ocf as *const SslOcspConf as *mut c_void;

    *ssl.ocsp_conf.borrow_mut() = Some(ocf);

    if unsafe { SSL_CTX_set_ex_data(ssl.ctx, ngx_ssl_ocsp_index(), p) } == 0 {
        ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("SSL_CTX_set_ex_data() failed"));
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_ssl_ocsp_resolver
pub fn ngx_ssl_ocsp_resolver(_cf: &mut Conf, ssl: &mut NgxSsl, resolver: Option<Rc<Resolver>>, resolver_timeout: u64) -> i64 {
    if let Some(ocf) = ssl.ocsp_conf.borrow().as_ref() {
        *ocf.resolver.borrow_mut() = resolver;
        ocf.resolver_timeout.set(resolver_timeout);
    }

    NGX_OK
}

/// The OCSP configuration of the context of a connection.
unsafe fn ocsp_conf_of(ssl_ctx: *const SSL_CTX) -> *const SslOcspConf {
    SSL_CTX_get_ex_data(ssl_ctx, ngx_ssl_ocsp_index()) as *const SslOcspConf
}

/// ngx_ssl_ocsp_validate: NGX_AGAIN when requests to the responders are
/// needed (ngx_ssl_ocsp_run() makes them)
pub fn ngx_ssl_ocsp_validate(c: &Connection) -> i64 {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return NGX_OK,
    };

    if sc.state.in_ocsp.get() {
        return NGX_AGAIN;
    }

    let ssl = ssl_ptr(&sc);

    unsafe {
        let ssl_ctx = SSL_get_SSL_CTX(ssl);

        let ocf = ocsp_conf_of(ssl_ctx);
        if ocf.is_null() {
            return NGX_OK;
        }

        if SSL_get_verify_result(ssl) != X509_V_OK {
            return NGX_OK;
        }

        let cert = SSL_get1_peer_certificate(ssl);
        if cert.is_null() {
            return NGX_OK;
        }

        let ocsp = Rc::new(SslOcsp { certs: Cell::new(std::ptr::null_mut()), ncert: Cell::new(0), cert_status: Cell::new(V_OCSP_CERTSTATUS_GOOD), status: Cell::new(NGX_AGAIN), conf: ocf, ctx: RefCell::new(None) });

        *sc.state.ocsp.borrow_mut() = Some(ocsp.clone());

        let mut certs = SSL_get0_verified_chain(ssl);

        if !certs.is_null() {
            certs = X509_chain_up_ref(certs);
            if certs.is_null() {
                X509_free(cert);
                return NGX_ERROR;
            }
        }

        if certs.is_null() {
            let store = SSL_CTX_get_cert_store(ssl_ctx);
            if store.is_null() {
                ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("SSL_CTX_get_cert_store() failed"));
                X509_free(cert);
                return NGX_ERROR;
            }

            let store_ctx = X509_STORE_CTX_new();
            if store_ctx.is_null() {
                ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("X509_STORE_CTX_new() failed"));
                X509_free(cert);
                return NGX_ERROR;
            }

            let chain = SSL_get_peer_cert_chain(ssl);

            if X509_STORE_CTX_init(store_ctx, store, cert, chain) == 0 {
                ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("X509_STORE_CTX_init() failed"));
                X509_STORE_CTX_free(store_ctx);
                X509_free(cert);
                return NGX_ERROR;
            }

            let rc = X509_verify_cert(store_ctx);
            if rc <= 0 {
                ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("X509_verify_cert() failed"));
                X509_STORE_CTX_free(store_ctx);
                X509_free(cert);
                return NGX_ERROR;
            }

            certs = X509_STORE_CTX_get1_chain(store_ctx);
            if certs.is_null() {
                ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("X509_STORE_CTX_get1_chain() failed"));
                X509_STORE_CTX_free(store_ctx);
                X509_free(cert);
                return NGX_ERROR;
            }

            X509_STORE_CTX_free(store_ctx);
        }

        ocsp.certs.set(certs);

        X509_free(cert);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ocsp validate, certs:{}", OPENSSL_sk_num(certs));

        ngx_ssl_ocsp_validate_next(c, &ocsp);

        if ocsp.status.get() == NGX_AGAIN {
            sc.state.in_ocsp.set(true);
            return NGX_AGAIN;
        }
    }

    NGX_OK
}

/// ngx_ssl_ocsp_validate_next: the certificates of the chain found in the
/// cache; the context of the request needed for the next one is left in
/// ocsp->ctx
fn ngx_ssl_ocsp_validate_next(c: &Connection, ocsp: &Rc<SslOcsp>) {
    let ocf = unsafe { &*ocsp.conf };

    let certs = ocsp.certs.get();
    let n = unsafe { OPENSSL_sk_num(certs) } as usize;

    let rc = 'done: loop {
        let ncert = ocsp.ncert.get();

        if ncert == n.wrapping_sub(1) || (ocf.depth == 2 && ncert == 1) {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ocsp validated, certs:{}", ncert);
            break 'done NGX_OK;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ocsp validate cert:{}", ncert);

        let mut ctx = ngx_ssl_ocsp_start(&c.log);

        unsafe {
            ctx.ssl_ctx = SSL_get_SSL_CTX(ngx_ssl_conn(c));
            ctx.cert = OPENSSL_sk_value(certs, ncert as c_int) as *mut X509;
            ctx.issuer = OPENSSL_sk_value(certs, ncert as c_int + 1) as *mut X509;
        }
        ctx.chain = certs;

        ctx.resolver = ocf.resolver.borrow().clone();
        ctx.resolver_timeout = ocf.resolver_timeout.get();

        ctx.shm_zone = ocf.shm_zone.clone();

        ctx.addrs = ocf.addrs.clone();
        ctx.set_host(ocf.host.clone());
        ctx.uri = ocf.uri.clone();
        ctx.port = ocf.port;

        let rc = ngx_ssl_ocsp_responder(c, &mut ctx);
        if rc != NGX_OK {
            *ocsp.ctx.borrow_mut() = Some(ctx);
            break 'done rc;
        }

        if ctx.uri.is_empty() {
            ctx.uri = b"/".to_vec();
        }

        ocsp.ncert.set(ncert + 1);

        let rc = ngx_ssl_ocsp_cache_lookup(&mut ctx);

        if rc == NGX_ERROR {
            *ocsp.ctx.borrow_mut() = Some(ctx);
            break 'done rc;
        }

        if rc == NGX_DECLINED {
            // the request is needed: ngx_ssl_ocsp_request(ctx)
            *ocsp.ctx.borrow_mut() = Some(ctx);
            return;
        }

        /* rc == NGX_OK */

        if ctx.status != V_OCSP_CERTSTATUS_GOOD {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp cached status \"{}\"", status_str(ctx.status));
            ocsp.cert_status.set(ctx.status);
            *ocsp.ctx.borrow_mut() = Some(ctx);
            break 'done NGX_OK;
        }

        drop(ctx);
    };

    // done:

    ocsp.status.set(rc);

    if let Some(sc) = c.ssl.borrow().as_ref() {
        if sc.state.in_ocsp.get() {
            sc.handshaked.set(true);
        }
    }
}

/// The requests of the OCSP validation of a connection after
/// ngx_ssl_ocsp_validate() returned NGX_AGAIN, as ngx_ssl_ocsp_handler()
/// runs them one after another; the handshake is done at the end.
pub async fn ngx_ssl_ocsp_run(c: &Connection) {
    let ocsp = match c.ssl.borrow().as_ref().and_then(|sc| sc.state.ocsp.borrow().clone()) {
        Some(o) => o,
        None => return,
    };

    'next: while ocsp.status.get() == NGX_AGAIN {
        let mut ctx = match ocsp.ctx.borrow_mut().take() {
            Some(ctx) => ctx,
            None => break,
        };

        ngx_ssl_ocsp_request(&mut ctx).await;

        // ngx_ssl_ocsp_handler

        let rc = 'done: {
            let rc = ngx_ssl_ocsp_verify(&mut ctx);
            if rc != NGX_OK {
                break 'done rc;
            }

            let rc = ngx_ssl_ocsp_cache_store(&mut ctx);
            if rc != NGX_OK {
                break 'done rc;
            }

            if ctx.status != V_OCSP_CERTSTATUS_GOOD {
                ocsp.cert_status.set(ctx.status);
                break 'done NGX_OK;
            }

            drop(ctx);

            ngx_ssl_ocsp_validate_next(c, &ocsp);

            continue 'next;
        };

        // done:

        ocsp.status.set(rc);
        drop(ctx);

        if let Some(sc) = c.ssl.borrow().as_ref() {
            if sc.state.in_ocsp.get() {
                sc.handshaked.set(true);
            }
        }
    }
}

/// ngx_ssl_ocsp_responder: the responder from the certificate, unless
/// configured
fn ngx_ssl_ocsp_responder(c: &Connection, ctx: &mut OcspCtx) -> i64 {
    if !ctx.host.is_empty() {
        return NGX_OK;
    }

    /* extract OCSP responder URL from certificate */

    let responder = match unsafe { cert_ocsp_url(ctx.cert) } {
        Some(url) => url,
        None => {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "no OCSP responder URL in certificate");
            return NGX_ERROR;
        }
    };

    let mut u = Url::new(&responder);
    u.default_port = 80;
    u.uri_part = true;
    u.no_resolve = true;

    if u.url.len() > 7 && crate::string::strncasecmp(&u.url, b"http://", 7) == 0 {
        u.url.drain(..7);
    } else {
        ngx_log_error!(NGX_LOG_ERR, c.log, None, "invalid URL prefix in OCSP responder \"{}\" in certificate", B(&u.url));
        return NGX_ERROR;
    }

    if parse_url(&mut u).is_err() {
        if let Some(err) = u.err {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "{} in OCSP responder \"{}\" in certificate", err, B(&u.url));
        }

        return NGX_ERROR;
    }

    if u.host.is_empty() {
        ngx_log_error!(NGX_LOG_ERR, c.log, None, "empty host in OCSP responder in certificate");
        return NGX_ERROR;
    }

    ctx.addrs = u.addrs;
    ctx.set_host(u.host);
    ctx.uri = u.uri;
    ctx.port = u.port;

    NGX_OK
}

/// ngx_ssl_ocsp_get_status: the error of the OCSP validation, if any
pub fn ngx_ssl_ocsp_get_status(c: &Connection) -> Result<(), &'static str> {
    let ocsp = match c.ssl.borrow().as_ref().and_then(|sc| sc.state.ocsp.borrow().clone()) {
        Some(o) => o,
        None => return Ok(()),
    };

    if ocsp.status.get() == NGX_ERROR {
        return Err("certificate status request failed");
    }

    match ocsp.cert_status.get() {
        V_OCSP_CERTSTATUS_GOOD => Ok(()),

        V_OCSP_CERTSTATUS_REVOKED => Err("certificate revoked"),

        /* V_OCSP_CERTSTATUS_UNKNOWN */
        _ => Err("certificate status unknown"),
    }
}

/// ngx_ssl_ocsp_cleanup
pub fn ngx_ssl_ocsp_cleanup(c: &Connection) {
    let ocsp = match c.ssl.borrow().as_ref().and_then(|sc| sc.state.ocsp.borrow().clone()) {
        Some(o) => o,
        None => return,
    };

    // ngx_ssl_ocsp_done()
    ocsp.ctx.borrow_mut().take();

    let certs = ocsp.certs.replace(std::ptr::null_mut());

    if !certs.is_null() {
        unsafe { sk_X509_pop_free(certs) };
    }
}

impl OcspCtx {
    fn set_host(&mut self, host: Vec<u8>) {
        *self.logctx.host.borrow_mut() = host.clone();
        self.host = host;
    }
}

/// ngx_ssl_ocsp_start: a request context with its log
fn ngx_ssl_ocsp_start(log: &Log) -> Box<OcspCtx> {
    let l = log.fork();
    l.set_connection(log.connection());
    l.set_action(Some("requesting certificate status"));

    let logctx = Rc::new(OcspLogCtx { host: RefCell::new(Vec::new()), peer: RefCell::new(None), name: RefCell::new(None) });

    l.set_context(Some(logctx.clone()));

    Box::new(OcspCtx {
        ssl_ctx: std::ptr::null_mut(),
        cert: std::ptr::null_mut(),
        issuer: std::ptr::null_mut(),
        chain: std::ptr::null_mut(),
        status: 0,
        valid: 0,
        naddr: 0,
        addrs: Vec::new(),
        host: Vec::new(),
        uri: Vec::new(),
        port: 0,
        resolver: None,
        resolver_timeout: 0,
        timeout: 0,
        key: Vec::new(),
        request: Vec::new(),
        request_pos: 0,
        response: None,
        response_pos: 0,
        response_last: 0,
        shm_zone: None,
        process: Process::StatusLine,
        state: 0,
        code: 0,
        count: 0,
        flags: 0,
        done: false,
        header_name_start: 0,
        header_name_end: 0,
        header_start: 0,
        header_end: 0,
        log: l,
        logctx,
    })
}

/// ngx_ssl_ocsp_error: the handler is called with code 0
fn ngx_ssl_ocsp_error(ctx: &mut OcspCtx) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp error");

    ctx.code = 0;
}

/// ngx_ssl_ocsp_next: false when there are no more addresses (the handler
/// is called with an error)
fn ngx_ssl_ocsp_next(ctx: &mut OcspCtx) -> bool {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp next");

    ctx.naddr += 1;

    if ctx.naddr >= ctx.addrs.len() {
        ngx_ssl_ocsp_error(ctx);
        return false;
    }

    ctx.request_pos = 0;

    if ctx.response.is_some() {
        ctx.response_last = ctx.response_pos;
    }

    ctx.state = 0;
    ctx.count = 0;
    ctx.done = false;

    true
}

/// ngx_ssl_ocsp_request .. ngx_ssl_ocsp_process_body: returns when the C
/// handler would be called (ctx.code 0 on errors)
async fn ngx_ssl_ocsp_request(ctx: &mut OcspCtx) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp request");

    if ngx_ssl_ocsp_create_request(ctx) != NGX_OK {
        ngx_ssl_ocsp_error(ctx);
        return;
    }

    if let Some(resolver) = ctx.resolver.clone() {
        /* resolve OCSP responder hostname */

        let host = ctx.host.clone();

        match resolver.resolve_host(&host, ctx.resolver_timeout).await {
            Resolved::Error => {
                ngx_ssl_ocsp_error(ctx);
                return;
            }

            Resolved::NoResolver => {
                if ctx.addrs.is_empty() {
                    ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "no resolver defined to resolve {}", B(&ctx.host));

                    ngx_ssl_ocsp_error(ctx);
                    return;
                }

                ngx_log_error!(NGX_LOG_WARN, ctx.log, None, "no resolver defined to resolve {}", B(&ctx.host));
            }

            Resolved::Done(guard) => {
                // ngx_ssl_ocsp_resolve_handler

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp resolve handler");

                let resolve = &guard.ctx;

                let state = resolve.state.get();

                if state != 0 {
                    ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "{} could not be resolved ({}: {})", B(&resolve.name.borrow()), state, Resolver::strerror(state));

                    drop(guard);

                    ngx_ssl_ocsp_error(ctx);
                    return;
                }

                let mut addrs = Vec::new();

                for a in resolve.addrs.borrow().iter() {
                    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "name was resolved to {}", B(&a.sockaddr.to_text(false)));

                    let mut sockaddr = a.sockaddr.clone();
                    sockaddr.set_port(ctx.port);

                    let name = sockaddr.to_text(true);

                    addrs.push(Addr { sockaddr, name });
                }

                ctx.addrs = addrs;

                drop(guard);
            }
        }
    }

    // connect:

    ngx_ssl_ocsp_connect(ctx).await;
}

/// How an exchange with a responder address ended.
enum Exchange {
    /// the response was read (the handler is called)
    Done,
    /// ngx_ssl_ocsp_next()
    Next,
}

/// ngx_ssl_ocsp_connect: the addresses one after another
async fn ngx_ssl_ocsp_connect(ctx: &mut OcspCtx) {
    loop {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp connect {}/{}", ctx.naddr, ctx.addrs.len());

        let addr = match ctx.addrs.get(ctx.naddr) {
            Some(a) => a.clone(),
            None => {
                ngx_ssl_ocsp_error(ctx);
                return;
            }
        };

        *ctx.logctx.peer.borrow_mut() = Some(addr.name.clone());

        let rc = event_connect_peer(&PeerSocket {
            sockaddr: &addr.sockaddr,
            name: &addr.name,
            ty: libc::SOCK_STREAM,
            rcvbuf: 0,
            sndbuf: 0,
            so_keepalive: false,
            local: None,
            transparent: false,
            log: &ctx.log,
            log_error: NGX_ERROR_ERR,
        });

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp connect peer done");

        let c = match rc {
            PeerConnect::Error => {
                ngx_ssl_ocsp_error(ctx);
                return;
            }

            PeerConnect::Declined => {
                if ngx_ssl_ocsp_next(ctx) {
                    continue;
                }
                return;
            }

            PeerConnect::Ok(c) | PeerConnect::Again(c) => c,
        };

        ctx.process = Process::StatusLine;

        let deadline = if ctx.timeout != 0 { Some(tokio::time::Instant::now() + Duration::from_millis(ctx.timeout)) } else { None };

        let r = ngx_ssl_ocsp_exchange(ctx, &c, deadline).await;

        c.close();

        match r {
            Exchange::Done => return,

            Exchange::Next => {
                if ngx_ssl_ocsp_next(ctx) {
                    continue;
                }
                return;
            }
        }
    }
}

/// Wait until the deadline (the timers of the connection), if any: false
/// on the timeout.
async fn until<F: std::future::Future>(deadline: Option<tokio::time::Instant>, f: F) -> Option<F::Output> {
    match deadline {
        Some(d) => tokio::time::timeout_at(d, f).await.ok(),
        None => Some(f.await),
    }
}

/// ngx_ssl_ocsp_write_handler and ngx_ssl_ocsp_read_handler on a
/// connection
async fn ngx_ssl_ocsp_exchange(ctx: &mut OcspCtx, c: &Rc<Connection>, deadline: Option<tokio::time::Instant>) -> Exchange {
    // ngx_ssl_ocsp_write_handler

    while ctx.request_pos < ctx.request.len() {
        let r = until(deadline, c.send(&ctx.request[ctx.request_pos..])).await;

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp write handler");

        match r {
            None => {
                ngx_log_error!(NGX_LOG_ERR, ctx.log, Some(libc::ETIMEDOUT), "OCSP responder timed out");
                return Exchange::Next;
            }

            Some(Err(e)) => {
                // ngx_send(): NGX_ERROR, logged
                c.connection_error(e.raw_os_error().unwrap_or(0), "send() failed");
                return Exchange::Next;
            }

            Some(Ok(n)) => ctx.request_pos += n,
        }
    }

    // ngx_ssl_ocsp_read_handler

    loop {
        if ctx.response.is_none() {
            ctx.response = Some(vec![0u8; 16384]);
            ctx.response_pos = 0;
            ctx.response_last = 0;
        }

        let mut eof = false;

        loop {
            let last = ctx.response_last;

            let r = {
                let buf = ctx.response.as_mut().unwrap();

                if last == buf.len() {
                    Ok(0)
                } else {
                    c.try_recv(&mut buf[last..])
                }
            };

            match r {
                Ok(n) if n > 0 => {
                    ctx.response_last += n;

                    let rc = ngx_ssl_ocsp_process(ctx);

                    if rc == NGX_ERROR {
                        return Exchange::Next;
                    }

                    continue;
                }

                Ok(_) => {
                    eof = true;
                    break;
                }

                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // NGX_AGAIN: wait for the read event

                    match until(deadline, c.readable()).await {
                        None => {
                            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp read handler");
                            ngx_log_error!(NGX_LOG_ERR, ctx.log, Some(libc::ETIMEDOUT), "OCSP responder timed out");
                            return Exchange::Next;
                        }

                        Some(Err(_)) => break,

                        Some(Ok(())) => {
                            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp read handler");
                            continue;
                        }
                    }
                }

                Err(e) => {
                    // ngx_recv(): NGX_ERROR, logged
                    c.connection_error(e.raw_os_error().unwrap_or(0), "recv() failed");
                    break;
                }
            }
        }

        let _ = eof;

        ctx.done = true;

        let rc = ngx_ssl_ocsp_process(ctx);

        if rc == NGX_DONE {
            /* ctx->handler() was called */
            return Exchange::Done;
        }

        ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "OCSP responder prematurely closed connection");

        return Exchange::Next;
    }
}

/// ctx->process()
fn ngx_ssl_ocsp_process(ctx: &mut OcspCtx) -> i64 {
    match ctx.process {
        Process::StatusLine => ngx_ssl_ocsp_process_status_line(ctx),
        Process::Headers => ngx_ssl_ocsp_process_headers(ctx),
        Process::Body => ngx_ssl_ocsp_process_body(ctx),
    }
}

/// ngx_ssl_ocsp_create_request: "GET <uri>/<base64 request> HTTP/1.0"
fn ngx_ssl_ocsp_create_request(ctx: &mut OcspCtx) -> i64 {
    unsafe {
        let ocsp = OCSP_REQUEST_new();
        if ocsp.is_null() {
            ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("OCSP_REQUEST_new() failed"));
            return NGX_ERROR;
        }

        let rc = 'failed: {
            let id = OCSP_cert_to_id(std::ptr::null(), ctx.cert, ctx.issuer);
            if id.is_null() {
                ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("OCSP_cert_to_id() failed"));
                break 'failed NGX_ERROR;
            }

            if OCSP_request_add0_id(ocsp, id).is_null() {
                ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("OCSP_request_add0_id() failed"));
                OCSP_CERTID_free(id);
                break 'failed NGX_ERROR;
            }

            let len = i2d_OCSP_REQUEST(ocsp, std::ptr::null_mut());
            if len <= 0 {
                ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("i2d_OCSP_REQUEST() failed"));
                break 'failed NGX_ERROR;
            }

            let mut binary = vec![0u8; len as usize];

            let mut p = binary.as_mut_ptr();
            let len = i2d_OCSP_REQUEST(ocsp, &mut p);
            if len <= 0 {
                ngx_ssl_error(NGX_LOG_EMERG, &ctx.log, 0, format_args!("i2d_OCSP_REQUEST() failed"));
                break 'failed NGX_ERROR;
            }

            binary.truncate(len as usize);

            let base64 = crate::string::encode_base64(&binary);

            let escape = crate::string::escape_uri_count(&base64, crate::string::NGX_ESCAPE_URI_COMPONENT);

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp request length {}, escape {}", base64.len(), escape);

            let mut b = Vec::with_capacity(4 + ctx.uri.len() + 1 + base64.len() + 2 * escape + 11 + 6 + ctx.host.len() + 4);

            b.extend_from_slice(b"GET ");
            b.extend_from_slice(&ctx.uri);

            if ctx.uri.last() != Some(&b'/') {
                b.push(b'/');
            }

            if escape == 0 {
                b.extend_from_slice(&base64);
            } else {
                crate::string::escape_uri_into(&mut b, &base64, crate::string::NGX_ESCAPE_URI_COMPONENT);
            }

            b.extend_from_slice(b" HTTP/1.0\r\n");
            b.extend_from_slice(b"Host: ");
            b.extend_from_slice(&ctx.host);
            b.extend_from_slice(b"\r\n");

            /* add "\r\n" at the header end */
            b.extend_from_slice(b"\r\n");

            ctx.request = b;
            ctx.request_pos = 0;

            NGX_OK
        };

        OCSP_REQUEST_free(ocsp);

        rc
    }
}

/// ngx_ssl_ocsp_process_status_line
fn ngx_ssl_ocsp_process_status_line(ctx: &mut OcspCtx) -> i64 {
    let rc = ngx_ssl_ocsp_parse_status_line(ctx);

    if rc == NGX_OK {
        {
            let b = ctx.response.as_ref().unwrap();
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp status {} \"{}\"", ctx.code, B(&b[ctx.header_start..ctx.header_end]));
        }

        ctx.process = Process::Headers;
        return ngx_ssl_ocsp_process(ctx);
    }

    if rc == NGX_AGAIN {
        return NGX_AGAIN;
    }

    /* rc == NGX_ERROR */

    ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "OCSP responder sent invalid response");

    NGX_ERROR
}

/// ngx_ssl_ocsp_parse_status_line
fn ngx_ssl_ocsp_parse_status_line(ctx: &mut OcspCtx) -> i64 {
    const SW_START: u32 = 0;
    const SW_H: u32 = 1;
    const SW_HT: u32 = 2;
    const SW_HTT: u32 = 3;
    const SW_HTTP: u32 = 4;
    const SW_FIRST_MAJOR_DIGIT: u32 = 5;
    const SW_MAJOR_DIGIT: u32 = 6;
    const SW_FIRST_MINOR_DIGIT: u32 = 7;
    const SW_MINOR_DIGIT: u32 = 8;
    const SW_STATUS: u32 = 9;
    const SW_SPACE_AFTER_STATUS: u32 = 10;
    const SW_STATUS_TEXT: u32 = 11;
    const SW_ALMOST_DONE: u32 = 12;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp process status line");

    let mut state = ctx.state;

    let last = ctx.response_last;
    let mut p = ctx.response_pos;

    let b = ctx.response.as_ref().unwrap();

    while p < last {
        let ch = b[p];

        match state {
            /* "HTTP/" */
            SW_START => match ch {
                b'H' => state = SW_H,
                _ => return NGX_ERROR,
            },

            SW_H => match ch {
                b'T' => state = SW_HT,
                _ => return NGX_ERROR,
            },

            SW_HT => match ch {
                b'T' => state = SW_HTT,
                _ => return NGX_ERROR,
            },

            SW_HTT => match ch {
                b'P' => state = SW_HTTP,
                _ => return NGX_ERROR,
            },

            SW_HTTP => match ch {
                b'/' => state = SW_FIRST_MAJOR_DIGIT,
                _ => return NGX_ERROR,
            },

            /* the first digit of major HTTP version */
            SW_FIRST_MAJOR_DIGIT => {
                if !(b'1'..=b'9').contains(&ch) {
                    return NGX_ERROR;
                }

                state = SW_MAJOR_DIGIT;
            }

            /* the major HTTP version or dot */
            SW_MAJOR_DIGIT => {
                if ch == b'.' {
                    state = SW_FIRST_MINOR_DIGIT;
                } else if !ch.is_ascii_digit() {
                    return NGX_ERROR;
                }
            }

            /* the first digit of minor HTTP version */
            SW_FIRST_MINOR_DIGIT => {
                if !ch.is_ascii_digit() {
                    return NGX_ERROR;
                }

                state = SW_MINOR_DIGIT;
            }

            /* the minor HTTP version or the end of the request line */
            SW_MINOR_DIGIT => {
                if ch == b' ' {
                    state = SW_STATUS;
                } else if !ch.is_ascii_digit() {
                    return NGX_ERROR;
                }
            }

            /* HTTP status code */
            SW_STATUS => {
                if ch != b' ' {
                    if !ch.is_ascii_digit() {
                        return NGX_ERROR;
                    }

                    ctx.code = ctx.code.wrapping_mul(10).wrapping_add((ch - b'0') as u32);

                    ctx.count += 1;

                    if ctx.count == 3 {
                        state = SW_SPACE_AFTER_STATUS;
                        ctx.header_start = p - 2;
                    }
                }
            }

            /* space or end of line */
            SW_SPACE_AFTER_STATUS => match ch {
                b' ' => state = SW_STATUS_TEXT,
                b'.' => state = SW_STATUS_TEXT, /* IIS may send 403.1, 403.2, etc */
                b'\r' => state = SW_ALMOST_DONE,
                b'\n' => {
                    ctx.header_end = p;
                    ctx.response_pos = p + 1;
                    ctx.state = SW_START;
                    return NGX_OK;
                }
                _ => return NGX_ERROR,
            },

            /* any text until end of line */
            SW_STATUS_TEXT => match ch {
                b'\r' => state = SW_ALMOST_DONE,
                b'\n' => {
                    ctx.header_end = p;
                    ctx.response_pos = p + 1;
                    ctx.state = SW_START;
                    return NGX_OK;
                }
                _ => {}
            },

            /* end of status line */
            _ => match ch {
                b'\n' => {
                    ctx.header_end = p - 1;
                    ctx.response_pos = p + 1;
                    ctx.state = SW_START;
                    return NGX_OK;
                }
                _ => return NGX_ERROR,
            },
        }

        p += 1;
    }

    ctx.response_pos = p;
    ctx.state = state;

    NGX_AGAIN
}

/// ngx_ssl_ocsp_process_headers
fn ngx_ssl_ocsp_process_headers(ctx: &mut OcspCtx) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp process headers");

    loop {
        let rc = ngx_ssl_ocsp_parse_header_line(ctx);

        if rc == NGX_OK {
            let b = ctx.response.as_ref().unwrap();

            let name = &b[ctx.header_name_start..ctx.header_name_end];
            let value = &b[ctx.header_start..ctx.header_end];

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp header \"{}: {}\"", B(name), B(value));

            if name.len() == b"Content-Type".len() && crate::string::strncasecmp(name, b"Content-Type", name.len()) == 0 {
                let ty = b"application/ocsp-response";

                if value.len() != ty.len() || crate::string::strncasecmp(value, ty, ty.len()) != 0 {
                    ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "OCSP responder sent invalid \"Content-Type\" header: \"{}\"", B(value));
                    return NGX_ERROR;
                }

                continue;
            }

            /* TODO: honor Content-Length */

            continue;
        }

        if rc == NGX_DONE {
            break;
        }

        if rc == NGX_AGAIN {
            return NGX_AGAIN;
        }

        /* rc == NGX_ERROR */

        ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "OCSP responder sent invalid response");

        return NGX_ERROR;
    }

    ctx.process = Process::Body;
    ngx_ssl_ocsp_process(ctx)
}

/// ngx_ssl_ocsp_parse_header_line
fn ngx_ssl_ocsp_parse_header_line(ctx: &mut OcspCtx) -> i64 {
    const SW_START: u32 = 0;
    const SW_NAME: u32 = 1;
    const SW_SPACE_BEFORE_VALUE: u32 = 2;
    const SW_VALUE: u32 = 3;
    const SW_SPACE_AFTER_VALUE: u32 = 4;
    const SW_ALMOST_DONE: u32 = 5;
    const SW_HEADER_ALMOST_DONE: u32 = 6;

    let mut state = ctx.state;

    let last = ctx.response_last;
    let mut p = ctx.response_pos;

    let b = ctx.response.as_ref().unwrap();

    // the ends: done (NGX_OK) or header_done (NGX_DONE)
    let finish = |ctx: &mut OcspCtx, p: usize, rc: i64| -> i64 {
        ctx.response_pos = p + 1;
        ctx.state = SW_START;
        rc
    };

    while p < last {
        let ch = b[p];

        match state {
            /* first char */
            SW_START => match ch {
                b'\r' => {
                    ctx.header_end = p;
                    state = SW_HEADER_ALMOST_DONE;
                }
                b'\n' => {
                    ctx.header_end = p;
                    return finish(ctx, p, NGX_DONE);
                }
                _ => {
                    state = SW_NAME;
                    ctx.header_name_start = p;

                    let c = ch | 0x20;
                    if !c.is_ascii_lowercase() && !ch.is_ascii_digit() {
                        return NGX_ERROR;
                    }
                }
            },

            /* header name */
            SW_NAME => {
                let c = ch | 0x20;

                if c.is_ascii_lowercase() {
                    // continue
                } else if ch == b':' {
                    ctx.header_name_end = p;
                    state = SW_SPACE_BEFORE_VALUE;
                } else if ch == b'-' || ch.is_ascii_digit() {
                    // continue
                } else if ch == b'\r' {
                    ctx.header_name_end = p;
                    ctx.header_start = p;
                    ctx.header_end = p;
                    state = SW_ALMOST_DONE;
                } else if ch == b'\n' {
                    ctx.header_name_end = p;
                    ctx.header_start = p;
                    ctx.header_end = p;
                    return finish(ctx, p, NGX_OK);
                } else {
                    return NGX_ERROR;
                }
            }

            /* space* before header value */
            SW_SPACE_BEFORE_VALUE => match ch {
                b' ' => {}
                b'\r' => {
                    ctx.header_start = p;
                    ctx.header_end = p;
                    state = SW_ALMOST_DONE;
                }
                b'\n' => {
                    ctx.header_start = p;
                    ctx.header_end = p;
                    return finish(ctx, p, NGX_OK);
                }
                _ => {
                    ctx.header_start = p;
                    state = SW_VALUE;
                }
            },

            /* header value */
            SW_VALUE => match ch {
                b' ' => {
                    ctx.header_end = p;
                    state = SW_SPACE_AFTER_VALUE;
                }
                b'\r' => {
                    ctx.header_end = p;
                    state = SW_ALMOST_DONE;
                }
                b'\n' => {
                    ctx.header_end = p;
                    return finish(ctx, p, NGX_OK);
                }
                _ => {}
            },

            /* space* before end of header line */
            SW_SPACE_AFTER_VALUE => match ch {
                b' ' => {}
                b'\r' => state = SW_ALMOST_DONE,
                b'\n' => return finish(ctx, p, NGX_OK),
                _ => state = SW_VALUE,
            },

            /* end of header line */
            SW_ALMOST_DONE => match ch {
                b'\n' => return finish(ctx, p, NGX_OK),
                _ => return NGX_ERROR,
            },

            /* end of header */
            _ => match ch {
                b'\n' => return finish(ctx, p, NGX_DONE),
                _ => return NGX_ERROR,
            },
        }

        p += 1;
    }

    ctx.response_pos = p;
    ctx.state = state;

    NGX_AGAIN
}

/// ngx_ssl_ocsp_process_body
fn ngx_ssl_ocsp_process_body(ctx: &mut OcspCtx) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp process body");

    if ctx.done {
        return NGX_DONE;
    }

    NGX_AGAIN
}

/// ngx_ssl_ocsp_verify: the status of the certificate in the response
fn ngx_ssl_ocsp_verify(ctx: &mut OcspCtx) -> i64 {
    let mut ocsp: *mut OCSP_RESPONSE = std::ptr::null_mut();
    let mut basic: *mut OCSP_BASICRESP = std::ptr::null_mut();
    let mut id: *mut OCSP_CERTID = std::ptr::null_mut();

    let rc = 'error: {
        if ctx.code != 200 {
            break 'error NGX_ERROR;
        }

        unsafe {
            /* check the response */

            let data = match ctx.response.as_ref() {
                Some(r) => &r[ctx.response_pos..ctx.response_last],
                None => break 'error NGX_ERROR,
            };

            let len = data.len();
            let mut p = data.as_ptr();

            ocsp = d2i_OCSP_RESPONSE(std::ptr::null_mut(), &mut p, len as c_long);
            if ocsp.is_null() {
                ngx_ssl_error(NGX_LOG_ERR, &ctx.log, 0, format_args!("d2i_OCSP_RESPONSE() failed"));
                break 'error NGX_ERROR;
            }

            let n = OCSP_response_status(ocsp);

            if n != OCSP_RESPONSE_STATUS_SUCCESSFUL {
                ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "OCSP response not successful ({}: {})", n, B(cstr(OCSP_response_status_str(n as c_long))));
                break 'error NGX_ERROR;
            }

            basic = OCSP_response_get1_basic(ocsp);
            if basic.is_null() {
                ngx_ssl_error(NGX_LOG_ERR, &ctx.log, 0, format_args!("OCSP_response_get1_basic() failed"));
                break 'error NGX_ERROR;
            }

            let store = SSL_CTX_get_cert_store(ctx.ssl_ctx);
            if store.is_null() {
                ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("SSL_CTX_get_cert_store() failed"));
                break 'error NGX_ERROR;
            }

            if OCSP_basic_verify(basic, ctx.chain, store, ctx.flags) != 1 {
                ngx_ssl_error(NGX_LOG_ERR, &ctx.log, 0, format_args!("OCSP_basic_verify() failed"));
                break 'error NGX_ERROR;
            }

            id = OCSP_cert_to_id(std::ptr::null(), ctx.cert, ctx.issuer);
            if id.is_null() {
                ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("OCSP_cert_to_id() failed"));
                break 'error NGX_ERROR;
            }

            let mut thisupdate: *mut ASN1_GENERALIZEDTIME = std::ptr::null_mut();
            let mut nextupdate: *mut ASN1_GENERALIZEDTIME = std::ptr::null_mut();

            if OCSP_resp_find_status(basic, id, &mut ctx.status, std::ptr::null_mut(), std::ptr::null_mut(), &mut thisupdate, &mut nextupdate) != 1 {
                ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "certificate status not found in the OCSP response");
                break 'error NGX_ERROR;
            }

            if OCSP_check_validity(thisupdate, nextupdate, 300, -1) != 1 {
                ngx_ssl_error(NGX_LOG_ERR, &ctx.log, 0, format_args!("OCSP_check_validity() failed"));
                break 'error NGX_ERROR;
            }

            if !nextupdate.is_null() {
                match ngx_ssl_stapling_time(nextupdate) {
                    Some(t) => ctx.valid = t,
                    None => {
                        ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "invalid nextUpdate time in certificate status");
                        break 'error NGX_ERROR;
                    }
                }
            } else {
                ctx.valid = NGX_MAX_TIME_T_VALUE;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp response, {}, {}", status_str(ctx.status), len);
        }

        NGX_OK
    };

    unsafe {
        if !id.is_null() {
            OCSP_CERTID_free(id);
        }

        if !basic.is_null() {
            OCSP_BASICRESP_free(basic);
        }

        if !ocsp.is_null() {
            OCSP_RESPONSE_free(ocsp);
        }
    }

    rc
}

// --- the OCSP cache ---

/// ngx_ssl_ocsp_cache_t
#[repr(C)]
struct SslOcspCache {
    rbtree: Rbtree,
    sentinel: RbtreeNode,
    expire_queue: Queue,
}

/// ngx_ssl_ocsp_cache_node_t (ngx_str_node_t, then the key)
#[repr(C)]
struct SslOcspCacheNode {
    node: RbtreeNode,
    str_len: usize,
    str_data: *mut u8,
    queue: Queue,
    status: c_int,
    valid: i64,
}

/// shm_zone->data of an OCSP cache zone
pub struct SslOcspCacheData {
    cache: Cell<*mut SslOcspCache>,
}

unsafe fn node_str<'a>(node: *const RbtreeNode) -> &'a [u8] {
    let n = node as *const SslOcspCacheNode;
    std::slice::from_raw_parts((*n).str_data, (*n).str_len)
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

/// ngx_str_rbtree_insert_value
unsafe fn str_rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let mut p: *mut *mut RbtreeNode;

    loop {
        if (*node).key != (*temp).key {
            p = if (*node).key < (*temp).key { &mut (*temp).left } else { &mut (*temp).right };
        } else {
            let a = node_str(node);
            let b = node_str(temp);
            p = if memn2cmp(a, b) < 0 { &mut (*temp).left } else { &mut (*temp).right };
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

/// ngx_str_rbtree_lookup
unsafe fn str_rbtree_lookup(rbtree: &Rbtree, name: &[u8], hash: u32) -> *mut SslOcspCacheNode {
    let mut node = rbtree.root;
    let sentinel = rbtree.sentinel;

    while node != sentinel {
        let n = node as *mut SslOcspCacheNode;

        if (hash as usize) != (*node).key {
            node = if (hash as usize) < (*node).key { (*node).left } else { (*node).right };
            continue;
        }

        let rc = memn2cmp(name, node_str(node));

        if rc < 0 {
            node = (*node).left;
            continue;
        }

        if rc > 0 {
            node = (*node).right;
            continue;
        }

        return n;
    }

    std::ptr::null_mut()
}

/// ngx_ssl_ocsp_cache_init
pub fn ngx_ssl_ocsp_cache_init(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn std::any::Any>>) -> Result<(), ()> {
    if let Some(d) = data {
        *shm_zone.data.borrow_mut() = Some(d);
        return Ok(());
    }

    let shpool = shm_zone.shm.addr.get() as *mut SlabPool;

    unsafe {
        if shm_zone.shm.exists.get() {
            let d: Rc<dyn std::any::Any> = Rc::new(SslOcspCacheData { cache: Cell::new((*shpool).data as *mut SslOcspCache) });
            *shm_zone.data.borrow_mut() = Some(d);
            return Ok(());
        }

        let cache = (*shpool).alloc(std::mem::size_of::<SslOcspCache>()) as *mut SslOcspCache;
        if cache.is_null() {
            return Err(());
        }

        (*shpool).data = cache as *mut u8;

        let d: Rc<dyn std::any::Any> = Rc::new(SslOcspCacheData { cache: Cell::new(cache) });
        *shm_zone.data.borrow_mut() = Some(d);

        (*cache).rbtree.init(&mut (*cache).sentinel, str_rbtree_insert_value);

        (*cache).expire_queue.init();

        let ctx = format!(" in OCSP cache \"{}\"", B(&shm_zone.shm.name));

        (*shpool).set_log_ctx(ctx.as_bytes())?;

        (*shpool).log_nomem = false;
    }

    Ok(())
}

fn cache_of(zone: &ShmZone) -> Option<(*mut SslOcspCache, *mut SlabPool)> {
    let cache = zone.data::<SslOcspCacheData>()?.cache.get();
    Some((cache, zone.shm.addr.get() as *mut SlabPool))
}

unsafe fn cache_node_of_queue(q: *mut Queue) -> *mut SslOcspCacheNode {
    (q as *mut u8).sub(std::mem::offset_of!(SslOcspCacheNode, queue)) as *mut SslOcspCacheNode
}

/// ngx_ssl_ocsp_cache_lookup
fn ngx_ssl_ocsp_cache_lookup(ctx: &mut OcspCtx) -> i64 {
    let shm_zone = match ctx.shm_zone.clone() {
        None => return NGX_DECLINED,
        Some(z) => z,
    };

    if ngx_ssl_ocsp_create_key(ctx) != NGX_OK {
        return NGX_ERROR;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp cache lookup");

    let (cache, shpool) = match cache_of(&shm_zone) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    let hash = crate::hash::hash_key(&ctx.key);

    unsafe {
        (*shpool).lock();

        let node = str_rbtree_lookup(&(*cache).rbtree, &ctx.key, hash);

        if !node.is_null() {
            if (*node).valid > crate::times::time() {
                ctx.status = (*node).status;
                (*shpool).unlock();

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp cache hit, {}", status_str(ctx.status));

                return NGX_OK;
            }

            (*node).queue.remove();
            (*cache).rbtree.delete(&mut (*node).node);
            (*shpool).free_locked(node as *mut u8);

            (*shpool).unlock();

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp cache expired");

            return NGX_DECLINED;
        }

        (*shpool).unlock();
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp cache miss");

    NGX_DECLINED
}

/// ngx_ssl_ocsp_cache_store
fn ngx_ssl_ocsp_cache_store(ctx: &mut OcspCtx) -> i64 {
    let shm_zone = match ctx.shm_zone.clone() {
        None => return NGX_OK,
        Some(z) => z,
    };

    let mut valid = ctx.valid;

    let now = crate::times::time();

    if valid < now {
        return NGX_OK;
    }

    if valid == NGX_MAX_TIME_T_VALUE {
        valid = now + 3600;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp cache store, valid:{}", valid - now);

    let (cache, shpool) = match cache_of(&shm_zone) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    let hash = crate::hash::hash_key(&ctx.key);

    let size = std::mem::size_of::<SslOcspCacheNode>() + ctx.key.len();

    unsafe {
        (*shpool).lock();

        let mut node = (*shpool).calloc_locked(size) as *mut SslOcspCacheNode;

        if node.is_null() {
            if !(*cache).expire_queue.is_empty() {
                let q = (*cache).expire_queue.last();
                let old = cache_node_of_queue(q);

                (*cache).rbtree.delete(&mut (*old).node);
                (*q).remove();
                (*shpool).free_locked(old as *mut u8);

                node = (*shpool).alloc_locked(size) as *mut SslOcspCacheNode;
            }

            if node.is_null() {
                (*shpool).unlock();
                ngx_log_error!(NGX_LOG_ALERT, ctx.log, None, "could not allocate new entry{}", B((*shpool).log_ctx()));
                return NGX_ERROR;
            }
        }

        (*node).str_len = ctx.key.len();
        (*node).str_data = (node as *mut u8).add(std::mem::size_of::<SslOcspCacheNode>());
        std::ptr::copy_nonoverlapping(ctx.key.as_ptr(), (*node).str_data, ctx.key.len());
        (*node).node.key = hash as usize;
        (*node).status = ctx.status;
        (*node).valid = valid;

        (*cache).rbtree.insert(&mut (*node).node);
        (*cache).expire_queue.insert_head(&mut (*node).queue);

        (*shpool).unlock();
    }

    NGX_OK
}

/// ngx_ssl_ocsp_create_key: the issuer name and key hashes and the serial
/// number of the certificate
fn ngx_ssl_ocsp_create_key(ctx: &mut OcspCtx) -> i64 {
    let mut key = vec![0u8; 60];

    unsafe {
        let name = X509_get_subject_name(ctx.issuer);
        if X509_NAME_digest(name, EVP_sha1(), key.as_mut_ptr(), std::ptr::null_mut()) == 0 {
            return NGX_ERROR;
        }

        if X509_pubkey_digest(ctx.issuer, EVP_sha1(), key[20..].as_mut_ptr(), std::ptr::null_mut()) == 0 {
            return NGX_ERROR;
        }

        let serial = X509_get_serialNumber(ctx.cert) as *const c_void;
        let length = ASN1_STRING_length(serial);

        if length > 20 || length < 0 {
            return NGX_ERROR;
        }

        let data = std::slice::from_raw_parts(ASN1_STRING_get0_data(serial), length as usize);

        key[40..40 + data.len()].copy_from_slice(data);
    }

    if ctx.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
        let mut hex = Vec::new();
        for b in key.iter() {
            hex.extend_from_slice(format!("{:02x}", b).as_bytes());
        }
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp key {}", B(&hex));
    }

    ctx.key = key;

    NGX_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(data: &[u8]) -> Box<OcspCtx> {
        let mut ctx = ngx_ssl_ocsp_start(&Log::stderr(NGX_LOG_EMERG));
        let mut buf = vec![0u8; 16384];
        buf[..data.len()].copy_from_slice(data);
        ctx.response = Some(buf);
        ctx.response_last = data.len();
        ctx
    }

    #[test]
    fn status_line_and_headers() {
        let mut ctx = ctx_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\nConnection: close\r\n\r\nBODY");

        assert_eq!(ngx_ssl_ocsp_process(&mut ctx), NGX_AGAIN);
        assert_eq!(ctx.code, 200);
        assert!(ctx.process == Process::Body);

        let b = ctx.response.as_ref().unwrap();
        assert_eq!(&b[ctx.response_pos..ctx.response_last], b"BODY");

        ctx.done = true;
        assert_eq!(ngx_ssl_ocsp_process(&mut ctx), NGX_DONE);
    }

    #[test]
    fn invalid_content_type() {
        let mut ctx = ctx_with(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n");
        assert_eq!(ngx_ssl_ocsp_process(&mut ctx), NGX_ERROR);
    }

    #[test]
    fn invalid_status_line() {
        let mut ctx = ctx_with(b"XTTP/1.0 200 OK\r\n");
        assert_eq!(ngx_ssl_ocsp_process(&mut ctx), NGX_ERROR);
    }

    #[test]
    fn partial_status_line() {
        let mut ctx = ctx_with(b"HTTP/1.0 2");
        assert_eq!(ngx_ssl_ocsp_process(&mut ctx), NGX_AGAIN);
        assert_eq!(ctx.code, 2);
    }
}
