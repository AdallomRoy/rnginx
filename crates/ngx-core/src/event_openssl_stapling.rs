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
use std::rc::Rc;
use std::time::Duration;

use ngx_sys::ssl as sys;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspFlag, OcspRequest, OcspResponse};
use openssl::ssl::{SslContext, SslRef};
use openssl::stack::Stack;
use openssl::x509::{X509Ref, X509StoreContext, X509};

use crate::conf::Conf;
use crate::connection::{Connection, NGX_ERROR_ERR};
use crate::event_connect::{event_connect_peer, PeerConnect, PeerSocket};
use crate::event_openssl::*;
use crate::inet::{parse_url, Addr, Url};
use crate::log::*;
use crate::rc::*;
use crate::resolver::{Resolved, Resolver};
use crate::shm::ShmZone;
use crate::shmem::rbtree::{self as rb, RbTree, ShmRbtree};
use crate::shmem::slab::SlabPool;
use crate::shmem::{queue, ShmMem};
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error, shm_struct};

const NGX_MAX_TIME_T_VALUE: i64 = i64::MAX;

const V_OCSP_CERTSTATUS_GOOD: i32 = 0;
const V_OCSP_CERTSTATUS_REVOKED: i32 = 1;

const OCSP_RESPONSE_STATUS_SUCCESSFUL: i32 = 0;

const OCSP_NOVERIFY: u64 = 0x10;
const OCSP_TRUSTOTHER: u64 = 0x200;

/// OCSP_cert_status_str()
fn status_str(s: i32) -> &'static str {
    match s {
        0 => "good",
        1 => "revoked",
        2 => "unknown",
        _ => "(UNKNOWN)",
    }
}

/// OCSP_response_status_str()
fn response_status_str(s: i32) -> &'static str {
    match s {
        0 => "successful",
        1 => "malformedrequest",
        2 => "internalerror",
        3 => "trylater",
        5 => "sigrequired",
        6 => "unauthorized",
        _ => "(UNKNOWN)",
    }
}

/// An openssl crate call failed: its errors go back to the queue, which
/// ngx_ssl_error() prints.
fn put(e: ErrorStack) {
    e.put();
}

/// A stack of references to the certificates.
fn stack_of(certs: &[X509]) -> Option<Stack<X509>> {
    let mut s = Stack::new().ok()?;

    for x in certs {
        s.push(x.clone()).ok()?;
    }

    Some(s)
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

    /// the certificate of the context (the key of the lookup: the same
    /// object as SSL_get_certificate() gives)
    cert: X509,
    issuer: RefCell<Option<X509>>,
    /// SSL_CTX_get_extra_chain_certs() of the certificate
    chain: Vec<X509>,

    name: Vec<u8>,

    valid: Cell<i64>,
    refresh: Cell<i64>,

    verify: bool,
    loading: Cell<bool>,
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
    /// the verified chain of the peer
    certs: RefCell<Vec<X509>>,
    ncert: Cell<usize>,

    cert_status: Cell<i32>,
    status: Cell<i64>,

    conf: Rc<SslOcspConf>,

    /// the context of the connection (SSL_get_SSL_CTX())
    ssl_ctx: SslContext,

    /// the request in progress
    ctx: RefCell<Option<Box<OcspCtx>>>,
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
    ssl_ctx: Option<SslContext>,

    cert: Option<X509>,
    issuer: Option<X509>,
    chain: Vec<X509>,

    status: i32,
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
    flags: u64,
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
    let certs: Vec<(X509, Vec<u8>)> = ssl.certs.iter().cloned().zip(ssl.cert_names.iter().cloned()).collect();

    for (cert, name) in certs {
        if ngx_ssl_stapling_certificate(cf, ssl, cert, name, file, responder, verify) != NGX_OK {
            return NGX_ERROR;
        }
    }

    if let Some(ctx) = ssl.ctx.builder_mut() {
        let _ = ctx.set_status_callback(ngx_ssl_certificate_status_callback);
    }

    NGX_OK
}

/// ngx_ssl_stapling_certificate
fn ngx_ssl_stapling_certificate(cf: &mut Conf, ssl: &mut NgxSsl, cert: X509, name: Vec<u8>, file: &mut Vec<u8>, responder: &mut Vec<u8>, verify: bool) -> i64 {
    // SSL_CTX_select_current_cert() and SSL_CTX_get_extra_chain_certs()
    let chain = match ssl.ctx.builder_mut() {
        Some(ctx) => sys::ctx_select_cert_chain(ctx, &cert).map(|s| s.iter().map(|x| x.to_owned()).collect()).unwrap_or_default(),
        None => return NGX_ERROR,
    };

    let mut staple = SslStapling {
        staple: RefCell::new(Vec::new()),
        timeout: 60000,
        resolver: RefCell::new(None),
        resolver_timeout: Cell::new(0),
        addrs: RefCell::new(Vec::new()),
        host: RefCell::new(Vec::new()),
        uri: RefCell::new(Vec::new()),
        port: Cell::new(0),
        cert,
        issuer: RefCell::new(None),
        chain,
        name,
        valid: Cell::new(0),
        refresh: Cell::new(0),
        verify,
        loading: Cell::new(false),
    };

    let rc = 'done: {
        if !file.is_empty() {
            /* use OCSP response from the file */

            break 'done ngx_ssl_stapling_file(cf, ssl, &mut staple, file);
        }

        let rc = ngx_ssl_stapling_issuer(cf, ssl, &mut staple);

        if rc == NGX_DECLINED {
            break 'done NGX_OK;
        }

        if rc != NGX_OK {
            break 'done NGX_ERROR;
        }

        let rc = ngx_ssl_stapling_responder(cf, ssl, &mut staple, responder);

        if rc == NGX_DECLINED {
            break 'done NGX_OK;
        }

        if rc != NGX_OK {
            break 'done NGX_ERROR;
        }

        NGX_OK
    };

    // the staple is in ssl->staple_rbtree from its creation on
    ssl.data.staples.borrow_mut().push(Rc::new(staple));

    rc
}

/// ngx_ssl_stapling_file
fn ngx_ssl_stapling_file(cf: &mut Conf, ssl: &mut NgxSsl, staple: &mut SslStapling, file: &mut Vec<u8>) -> i64 {
    *file = cf.full_name(file, true);

    let name = CString::new(file.clone()).unwrap_or_default();

    let mut bio = match sys::Bio::new_file(&name, c"rb") {
        Some(b) => b,
        None => {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("BIO_new_file(\"{}\") failed", B(file)));
            return NGX_ERROR;
        }
    };

    let response = match sys::d2i_ocsp_response_bio(&mut bio) {
        Some(r) => r,
        None => {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("d2i_OCSP_RESPONSE_bio(\"{}\") failed", B(file)));
            return NGX_ERROR;
        }
    };

    let buf = match response.to_der() {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => {
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("i2d_OCSP_RESPONSE(\"{}\") failed", B(file)));
            return NGX_ERROR;
        }
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("i2d_OCSP_RESPONSE(\"{}\") failed", B(file)));
            return NGX_ERROR;
        }
    };

    *staple.staple.borrow_mut() = buf;
    staple.valid.set(NGX_MAX_TIME_T_VALUE);

    NGX_OK
}

/// ngx_ssl_stapling_issuer
fn ngx_ssl_stapling_issuer(_cf: &mut Conf, ssl: &mut NgxSsl, staple: &mut SslStapling) -> i64 {
    let cert = &staple.cert;

    let n = staple.chain.len();

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ssl.log, "SSL get issuer: {} extra certs", n);

    for issuer in staple.chain.iter() {
        if issuer.issued(cert).as_raw() as i64 == X509_V_OK {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ssl.log, "SSL get issuer: found {:p} in extra certs", &**issuer);

            *staple.issuer.borrow_mut() = Some(issuer.clone());

            return NGX_OK;
        }
    }

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    let issuer = match sys::store_get1_issuer(ctx.cert_store(), cert) {
        Ok(Some(issuer)) => issuer,

        Ok(None) => {
            ngx_log_error!(NGX_LOG_WARN, ssl.log, None, "\"ssl_stapling\" ignored, issuer certificate not found for certificate \"{}\"", B(&staple.name));
            return NGX_DECLINED;
        }

        Err(e) => {
            let what = match e {
                sys::IssuerError::New => "X509_STORE_CTX_new() failed",
                sys::IssuerError::Init => "X509_STORE_CTX_init() failed",
                sys::IssuerError::Get => "X509_STORE_CTX_get1_issuer() failed",
            };

            ngx_ssl_error(NGX_LOG_EMERG, &ssl.log, 0, format_args!("{}", what));
            return NGX_ERROR;
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ssl.log, "SSL get issuer: found {:p} in cert store", &*issuer);

    *staple.issuer.borrow_mut() = Some(issuer);

    NGX_OK
}

/// ngx_ssl_stapling_responder
fn ngx_ssl_stapling_responder(_cf: &mut Conf, ssl: &mut NgxSsl, staple: &mut SslStapling, responder: &[u8]) -> i64 {
    let responder = if responder.is_empty() {
        /* extract OCSP responder URL from certificate */

        match sys::x509_ocsp_url(&staple.cert) {
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
    for staple in ssl.data.staples.borrow().iter() {
        *staple.resolver.borrow_mut() = resolver.clone();
        staple.resolver_timeout.set(resolver_timeout);
    }

    NGX_OK
}

/// ngx_ssl_certificate_status_callback: the staple of the certificate
/// (Ok(true): SSL_TLSEXT_ERR_OK, Ok(false): SSL_TLSEXT_ERR_NOACK)
fn ngx_ssl_certificate_status_callback(ssl_conn: &mut SslRef) -> Result<bool, ErrorStack> {
    let c = match ngx_ssl_get_connection(ssl_conn) {
        Some(c) => c,
        None => return Ok(false),
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL certificate status callback");

    let ssl_ctx = ssl_conn.ssl_context().to_owned();

    let staple = {
        let cert = match ssl_conn.certificate() {
            Some(cert) => cert,
            None => return Ok(false),
        };

        match ngx_ssl_ctx_data(&ssl_ctx).and_then(|d| ngx_ssl_stapling_lookup(&d, cert)) {
            Some(s) => s,
            None => return Ok(false),
        }
    };

    let mut rc = false;

    let data = staple.staple.borrow().clone();

    if !data.is_empty() && staple.valid.get() >= crate::times::time() {
        /* we have to copy ocsp response as OpenSSL will free it by itself */

        if let Err(e) = ssl_conn.set_ocsp_status(&data) {
            put(e);
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("OPENSSL_malloc() failed"));
            return Ok(false);
        }

        rc = true;
    }

    ngx_ssl_stapling_update(&staple, ssl_ctx);

    Ok(rc)
}

/// ngx_ssl_stapling_lookup: the staple of the certificate object
fn ngx_ssl_stapling_lookup(data: &SslCtxData, cert: &X509Ref) -> Option<Rc<SslStapling>> {
    data.staples.borrow().iter().find(|s| std::ptr::eq::<X509Ref>(&*s.cert, cert)).cloned()
}

/// ngx_ssl_stapling_update: a new OCSP response, in the background
fn ngx_ssl_stapling_update(staple: &Rc<SslStapling>, ssl_ctx: SslContext) {
    if staple.host.borrow().is_empty() || staple.loading.get() || staple.refresh.get() >= crate::times::time() {
        return;
    }

    staple.loading.set(true);

    let log = match crate::cycle::try_cycle() {
        Some(c) => c.log.clone(),
        None => return,
    };

    let mut ctx = ngx_ssl_ocsp_start(&log);

    ctx.ssl_ctx = Some(ssl_ctx);
    ctx.cert = Some(staple.cert.clone());
    ctx.issuer = staple.issuer.borrow().clone();
    ctx.chain = staple.chain.clone();
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
fn ngx_ssl_stapling_time(asn1time: &openssl::asn1::Asn1GeneralizedTimeRef) -> Option<i64> {
    let printed = sys::asn1_generalizedtime_print(asn1time)?;

    /* fake weekday prepended to match C asctime() format */

    let mut value = b"Tue ".to_vec();
    value.extend_from_slice(&printed);

    crate::parse::parse_http_time(&value)
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

    // SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_ocsp_index, ocf)
    *ssl.data.ocsp_conf.borrow_mut() = Some(Rc::new(ocf));

    NGX_OK
}

/// ngx_ssl_ocsp_resolver
pub fn ngx_ssl_ocsp_resolver(_cf: &mut Conf, ssl: &mut NgxSsl, resolver: Option<Rc<Resolver>>, resolver_timeout: u64) -> i64 {
    if let Some(ocf) = ssl.data.ocsp_conf.borrow().as_ref() {
        *ocf.resolver.borrow_mut() = resolver;
        ocf.resolver_timeout.set(resolver_timeout);
    }

    NGX_OK
}

/// What ngx_ssl_ocsp_validate() needs of the SSL object.
struct PeerChain {
    ssl_ctx: SslContext,
    ocf: Option<Rc<SslOcspConf>>,
    verify_ok: bool,
    cert: Option<X509>,
    verified: Option<Vec<X509>>,
    peer_chain: Vec<X509>,
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

    let p = match sc.with(|ssl| {
        let ssl_ctx = ssl.ssl_context().to_owned();
        let ocf = ngx_ssl_ctx_data(&ssl_ctx).and_then(|d| d.ocsp_conf.borrow().clone());

        PeerChain {
            ocf,
            verify_ok: ssl.verify_result().as_raw() as i64 == X509_V_OK,
            cert: ssl.peer_certificate(),
            verified: ssl.verified_chain().map(|s| s.iter().map(|x| x.to_owned()).collect()),
            peer_chain: ssl.peer_cert_chain().map(|s| s.iter().map(|x| x.to_owned()).collect()).unwrap_or_default(),
            ssl_ctx,
        }
    }) {
        Some(p) => p,
        None => return NGX_OK,
    };

    let ocf = match p.ocf {
        Some(ocf) => ocf,
        None => return NGX_OK,
    };

    if !p.verify_ok {
        return NGX_OK;
    }

    let cert = match p.cert {
        Some(cert) => cert,
        None => return NGX_OK,
    };

    let ocsp = Rc::new(SslOcsp {
        certs: RefCell::new(Vec::new()),
        ncert: Cell::new(0),
        cert_status: Cell::new(V_OCSP_CERTSTATUS_GOOD),
        status: Cell::new(NGX_AGAIN),
        conf: ocf,
        ssl_ctx: p.ssl_ctx.clone(),
        ctx: RefCell::new(None),
    });

    *sc.state.ocsp.borrow_mut() = Some(ocsp.clone());

    // SSL_get0_verified_chain(), X509_chain_up_ref()
    let certs = match p.verified {
        Some(certs) => certs,

        None => {
            let store = p.ssl_ctx.cert_store();

            let mut store_ctx = match X509StoreContext::new() {
                Ok(s) => s,
                Err(e) => {
                    put(e);
                    ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("X509_STORE_CTX_new() failed"));
                    return NGX_ERROR;
                }
            };

            let chain = match stack_of(&p.peer_chain) {
                Some(s) => s,
                None => return NGX_ERROR,
            };

            // the failed call, and its errors
            let mut failed: Option<(&'static str, Option<ErrorStack>)> = Some(("X509_STORE_CTX_init() failed", None));

            let r = store_ctx.init(store, &cert, &chain, |ctx| {
                match ctx.verify_cert() {
                    Ok(true) => {}
                    Ok(false) => {
                        failed = Some(("X509_verify_cert() failed", None));
                        return Ok(None);
                    }
                    Err(e) => {
                        failed = Some(("X509_verify_cert() failed", Some(e)));
                        return Ok(None);
                    }
                }

                // X509_STORE_CTX_get1_chain()
                match ctx.chain() {
                    Some(chain) => {
                        failed = None;
                        Ok(Some(chain.iter().map(|x| x.to_owned()).collect::<Vec<X509>>()))
                    }
                    None => {
                        failed = Some(("X509_STORE_CTX_get1_chain() failed", None));
                        Ok(None)
                    }
                }
            });

            match (r, failed) {
                (Ok(Some(certs)), None) => certs,

                (Err(e), Some((what, _))) => {
                    put(e);
                    ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("{}", what));
                    return NGX_ERROR;
                }

                (_, Some((what, e))) => {
                    if let Some(e) = e {
                        put(e);
                    }
                    ngx_ssl_error(NGX_LOG_ERR, &c.log, 0, format_args!("{}", what));
                    return NGX_ERROR;
                }

                (_, None) => return NGX_ERROR,
            }
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ocsp validate, certs:{}", certs.len());

    *ocsp.certs.borrow_mut() = certs;

    ngx_ssl_ocsp_validate_next(c, &ocsp);

    if ocsp.status.get() == NGX_AGAIN {
        sc.state.in_ocsp.set(true);
        return NGX_AGAIN;
    }

    NGX_OK
}

/// ngx_ssl_ocsp_validate_next: the certificates of the chain found in the
/// cache; the context of the request needed for the next one is left in
/// ocsp->ctx
fn ngx_ssl_ocsp_validate_next(c: &Connection, ocsp: &Rc<SslOcsp>) {
    let ocf = ocsp.conf.clone();

    let certs = ocsp.certs.borrow().clone();
    let n = certs.len();

    let rc = 'done: loop {
        let ncert = ocsp.ncert.get();

        if ncert == n.wrapping_sub(1) || (ocf.depth == 2 && ncert == 1) {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ocsp validated, certs:{}", ncert);
            break 'done NGX_OK;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "ssl ocsp validate cert:{}", ncert);

        let mut ctx = ngx_ssl_ocsp_start(&c.log);

        ctx.ssl_ctx = Some(ocsp.ssl_ctx.clone());
        ctx.cert = certs.get(ncert).cloned();
        ctx.issuer = certs.get(ncert + 1).cloned();
        ctx.chain = certs.clone();

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

    let responder = match ctx.cert.as_ref().and_then(|cert| sys::x509_ocsp_url(cert)) {
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

    // sk_X509_pop_free(ocsp->certs, X509_free)
    ocsp.certs.borrow_mut().clear();
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
        ssl_ctx: None,
        cert: None,
        issuer: None,
        chain: Vec::new(),
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
    let mut ocsp = match OcspRequest::new() {
        Ok(r) => r,
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("OCSP_REQUEST_new() failed"));
            return NGX_ERROR;
        }
    };

    let id = match (ctx.cert.as_ref(), ctx.issuer.as_ref()) {
        (Some(cert), Some(issuer)) => OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer),
        _ => Err(ErrorStack::get()),
    };

    let id = match id {
        Ok(id) => id,
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("OCSP_cert_to_id() failed"));
            return NGX_ERROR;
        }
    };

    if let Err(e) = ocsp.add_id(id) {
        put(e);
        ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("OCSP_request_add0_id() failed"));
        return NGX_ERROR;
    }

    let binary = match ocsp.to_der() {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => {
            ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("i2d_OCSP_REQUEST() failed"));
            return NGX_ERROR;
        }
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("i2d_OCSP_REQUEST() failed"));
            return NGX_ERROR;
        }
    };

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
    if ctx.code != 200 {
        return NGX_ERROR;
    }

    /* check the response */

    let data = match ctx.response.as_ref() {
        Some(r) => r[ctx.response_pos..ctx.response_last].to_vec(),
        None => return NGX_ERROR,
    };

    let len = data.len();

    let ocsp = match OcspResponse::from_der(&data) {
        Ok(o) => o,
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_ERR, &ctx.log, 0, format_args!("d2i_OCSP_RESPONSE() failed"));
            return NGX_ERROR;
        }
    };

    let n = ocsp.status().as_raw();

    if n != OCSP_RESPONSE_STATUS_SUCCESSFUL {
        ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "OCSP response not successful ({}: {})", n, response_status_str(n));
        return NGX_ERROR;
    }

    let basic = match ocsp.basic() {
        Ok(b) => b,
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_ERR, &ctx.log, 0, format_args!("OCSP_response_get1_basic() failed"));
            return NGX_ERROR;
        }
    };

    let ssl_ctx = match ctx.ssl_ctx.clone() {
        Some(c) => c,
        None => {
            ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("SSL_CTX_get_cert_store() failed"));
            return NGX_ERROR;
        }
    };

    let chain = match stack_of(&ctx.chain) {
        Some(s) => s,
        None => return NGX_ERROR,
    };

    if let Err(e) = basic.verify(&chain, ssl_ctx.cert_store(), OcspFlag::from_bits_retain(ctx.flags as _)) {
        put(e);
        ngx_ssl_error(NGX_LOG_ERR, &ctx.log, 0, format_args!("OCSP_basic_verify() failed"));
        return NGX_ERROR;
    }

    let id = match (ctx.cert.as_ref(), ctx.issuer.as_ref()) {
        (Some(cert), Some(issuer)) => OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer),
        _ => Err(ErrorStack::get()),
    };

    let id = match id {
        Ok(id) => id,
        Err(e) => {
            put(e);
            ngx_ssl_error(NGX_LOG_CRIT, &ctx.log, 0, format_args!("OCSP_cert_to_id() failed"));
            return NGX_ERROR;
        }
    };

    let status = match basic.find_status(&id) {
        Some(s) => s,
        None => {
            ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "certificate status not found in the OCSP response");
            return NGX_ERROR;
        }
    };

    ctx.status = status.status.as_raw();

    if let Err(e) = status.check_validity(300, None) {
        put(e);
        ngx_ssl_error(NGX_LOG_ERR, &ctx.log, 0, format_args!("OCSP_check_validity() failed"));
        return NGX_ERROR;
    }

    match status.next_update() {
        Some(nextupdate) => match ngx_ssl_stapling_time(nextupdate) {
            Some(t) => ctx.valid = t,
            None => {
                ngx_log_error!(NGX_LOG_ERR, ctx.log, None, "invalid nextUpdate time in certificate status");
                return NGX_ERROR;
            }
        },

        None => ctx.valid = NGX_MAX_TIME_T_VALUE,
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp response, {}, {}", status_str(ctx.status), len);

    NGX_OK
}

// --- the OCSP cache ---

shm_struct! {
    /// ngx_ssl_ocsp_cache_t: the rbtree, its sentinel node and the expire
    /// queue
    struct OcspCache {
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
    /// ngx_ssl_ocsp_cache_node_t: an ngx_str_node_t, then its queue link,
    /// status and validity; the key follows it
    struct OcspCacheNode {
        key: usize,
        left: usize,
        right: usize,
        parent: usize,
        color: u8,
        data: u8,
        str_len: usize,
        str_data: usize,
        queue_prev: usize,
        queue_next: usize,
        status: i32,
        valid: i64,
    }
}

/// shm_zone->data of an OCSP cache zone: the zone's memory and the offset
/// of its ngx_ssl_ocsp_cache_t
pub struct SslOcspCacheData {
    mem: RefCell<Option<Rc<ShmMem>>>,
    cache: Cell<usize>,
}

/// ngx_ssl_ocsp_cache_init
pub fn ngx_ssl_ocsp_cache_init(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn std::any::Any>>) -> Result<(), ()> {
    if let Some(d) = data {
        *shm_zone.data.borrow_mut() = Some(d);
        return Ok(());
    }

    let mem = shm_zone.mem();
    let shpool = SlabPool::of(&mem);

    if shm_zone.shm.exists.get() {
        let d: Rc<dyn std::any::Any> = Rc::new(SslOcspCacheData { mem: RefCell::new(Some(mem.clone())), cache: Cell::new(shpool.data()) });
        *shm_zone.data.borrow_mut() = Some(d);
        return Ok(());
    }

    let cache = shpool.alloc(OcspCache::SIZE);
    if cache == 0 {
        return Err(());
    }

    shpool.set_data(cache);

    let d: Rc<dyn std::any::Any> = Rc::new(SslOcspCacheData { mem: RefCell::new(Some(mem.clone())), cache: Cell::new(cache) });
    *shm_zone.data.borrow_mut() = Some(d);

    let c = OcspCache::at(&mem, cache);

    ShmRbtree::at(&mem, c.field(OcspCache::rbtree_root)).init(c.field(OcspCache::sentinel_key));

    queue::init(&mem, c.field(OcspCache::queue_prev));

    let ctx = format!(" in OCSP cache \"{}\"", B(shm_zone.name()));

    shpool.set_log_ctx(ctx.as_bytes())?;

    shpool.set_log_nomem(false);

    Ok(())
}

/// The memory and the offset of the OCSP cache of a zone.
fn cache_of(zone: &ShmZone) -> Option<(Rc<ShmMem>, usize)> {
    let d = zone.data::<SslOcspCacheData>()?;
    let mem = d.mem.borrow().clone()?;
    Some((mem, d.cache.get()))
}

/// &cache->rbtree
fn ocsp_rbtree(mem: &ShmMem, cache: usize) -> ShmRbtree<'_> {
    ShmRbtree::at(mem, OcspCache::at(mem, cache).field(OcspCache::rbtree_root))
}

/// ngx_str_rbtree_insert_value
fn str_rbtree_insert_value(tree: &ShmRbtree<'_>, temp: usize, node: usize, sentinel: usize) {
    tree.str_insert_value(temp, node, sentinel);
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

    let (mem, cache) = match cache_of(&shm_zone) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    let shpool = SlabPool::of(&mem);

    let hash = crate::hash::hash_key(&ctx.key) as u32;

    shpool.lock();

    let tree = ocsp_rbtree(&mem, cache);

    let node = tree.str_lookup(&ctx.key, hash as usize);

    if node != 0 {
        let n = OcspCacheNode::at(&mem, node);

        if n.get(OcspCacheNode::valid) > crate::times::time() {
            ctx.status = n.get(OcspCacheNode::status);
            shpool.unlock();

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp cache hit, {}", status_str(ctx.status));

            return NGX_OK;
        }

        queue::remove(&mem, n.field(OcspCacheNode::queue_prev));
        rb::delete(&tree, node);
        shpool.free_locked(node);

        shpool.unlock();

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, ctx.log, "ssl ocsp cache expired");

        return NGX_DECLINED;
    }

    shpool.unlock();

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

    let (mem, cache) = match cache_of(&shm_zone) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    let shpool = SlabPool::of(&mem);

    let hash = crate::hash::hash_key(&ctx.key) as u32;

    let size = OcspCacheNode::SIZE + ctx.key.len();

    let head = OcspCache::at(&mem, cache).field(OcspCache::queue_prev);
    let tree = ocsp_rbtree(&mem, cache);

    shpool.lock();

    let mut node = shpool.calloc_locked(size);

    if node == 0 {
        if !queue::empty(&mem, head) {
            let q = queue::last(&mem, head);
            let old = q - OcspCacheNode::queue_prev.off;

            rb::delete(&tree, old);
            queue::remove(&mem, q);
            shpool.free_locked(old);

            node = shpool.alloc_locked(size);
        }

        if node == 0 {
            shpool.unlock();
            ngx_log_error!(NGX_LOG_ALERT, ctx.log, None, "could not allocate new entry{}", B(&shpool.log_ctx()));
            return NGX_ERROR;
        }
    }

    let n = OcspCacheNode::at(&mem, node);

    n.set(OcspCacheNode::str_len, ctx.key.len());
    n.set(OcspCacheNode::str_data, node + OcspCacheNode::SIZE);
    mem.write(node + OcspCacheNode::SIZE, &ctx.key);
    tree.set_key(node, hash as usize);
    n.set(OcspCacheNode::status, ctx.status);
    n.set(OcspCacheNode::valid, valid);

    rb::insert(&tree, node, str_rbtree_insert_value);
    queue::insert_head(&mem, head, n.field(OcspCacheNode::queue_prev));

    shpool.unlock();

    NGX_OK
}

/// ngx_ssl_ocsp_create_key: the issuer name and key hashes and the serial
/// number of the certificate
fn ngx_ssl_ocsp_create_key(ctx: &mut OcspCtx) -> i64 {
    let (cert, issuer) = match (ctx.cert.as_ref(), ctx.issuer.as_ref()) {
        (Some(c), Some(i)) => (c, i),
        _ => return NGX_ERROR,
    };

    let mut key = vec![0u8; 60];

    match sys::x509_name_digest(issuer.subject_name(), MessageDigest::sha1()) {
        Some(d) if d.len() == 20 => key[..20].copy_from_slice(&d),
        _ => return NGX_ERROR,
    }

    match sys::x509_pubkey_digest(issuer, MessageDigest::sha1()) {
        Some(d) if d.len() == 20 => key[20..40].copy_from_slice(&d),
        _ => return NGX_ERROR,
    }

    // ASN1_STRING_get0_data() of the serial number: the bytes of its value
    let serial = match cert.serial_number().to_bn() {
        Ok(bn) => bn.to_vec(),
        Err(_) => return NGX_ERROR,
    };

    if serial.len() > 20 {
        return NGX_ERROR;
    }

    key[40..40 + serial.len()].copy_from_slice(&serial);

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

    /// A certificate of the name, signed by the issuer's key (self-signed
    /// without), with the serial given.
    fn cert(name: &str, serial: u32, issuer: Option<(&X509, &openssl::pkey::PKey<openssl::pkey::Private>)>) -> (X509, openssl::pkey::PKey<openssl::pkey::Private>) {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

        let mut n = X509NameBuilder::new().unwrap();
        n.append_entry_by_text("CN", name).unwrap();
        let n = n.build();

        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&openssl::bn::BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap()).unwrap();
        b.set_subject_name(&n).unwrap();
        b.set_issuer_name(issuer.map(|(c, _)| c.subject_name()).unwrap_or(&n)).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap()).unwrap();
        b.sign(issuer.map(|(_, k)| k).unwrap_or(&key), openssl::hash::MessageDigest::sha256()).unwrap();

        (b.build(), key)
    }

    /// An OCSP cache zone, its slab pool initialized and the cache made by
    /// the zone init.
    fn ocsp_zone() -> Rc<ShmZone> {
        let mem = Rc::new(ShmMem::private(1 << 19).unwrap());
        SlabPool::init_zone(&mem);

        let zone = ShmZone::new(b"OCSP".to_vec(), mem.len(), "ngx_http_ssl_module_ctx");
        zone.shm.attach(mem);

        ngx_ssl_ocsp_cache_init(&zone, None).unwrap();

        zone
    }

    #[test]
    fn ocsp_cache() {
        let (ca, ca_key) = cert("CA", 1, None);
        let (leaf, _) = cert("leaf", 0x1234, Some((&ca, &ca_key)));
        let (other, _) = cert("other", 0x1235, Some((&ca, &ca_key)));

        let zone = ocsp_zone();

        let mut ctx = ngx_ssl_ocsp_start(&Log::stderr(NGX_LOG_EMERG));
        ctx.cert = Some(leaf.clone());
        ctx.issuer = Some(ca.clone());
        ctx.shm_zone = Some(zone.clone());

        // the key: the issuer name and key hashes, the serial
        assert_eq!(ngx_ssl_ocsp_cache_lookup(&mut ctx), NGX_DECLINED);
        assert_eq!(ctx.key.len(), 60);
        assert_eq!(&ctx.key[40..42], &[0x12, 0x34]);
        assert!(ctx.key[42..].iter().all(|&b| b == 0));

        ctx.status = V_OCSP_CERTSTATUS_REVOKED;
        ctx.valid = crate::times::time() + 100;
        assert_eq!(ngx_ssl_ocsp_cache_store(&mut ctx), NGX_OK);

        ctx.status = V_OCSP_CERTSTATUS_GOOD;
        assert_eq!(ngx_ssl_ocsp_cache_lookup(&mut ctx), NGX_OK);
        assert_eq!(ctx.status, V_OCSP_CERTSTATUS_REVOKED);

        // another certificate of the issuer
        let mut ctx2 = ngx_ssl_ocsp_start(&Log::stderr(NGX_LOG_EMERG));
        ctx2.cert = Some(other);
        ctx2.issuer = Some(ca);
        ctx2.shm_zone = Some(zone.clone());
        assert_eq!(ngx_ssl_ocsp_cache_lookup(&mut ctx2), NGX_DECLINED);

        // an expired entry is removed
        ctx2.status = V_OCSP_CERTSTATUS_GOOD;
        ctx2.valid = crate::times::time();
        assert_eq!(ngx_ssl_ocsp_cache_store(&mut ctx2), NGX_OK);
        assert_eq!(ngx_ssl_ocsp_cache_lookup(&mut ctx2), NGX_DECLINED);

        let (mem, cache) = cache_of(&zone).unwrap();
        assert_eq!(rb::walk(&ocsp_rbtree(&mem, cache)).len(), 1);

        // still found
        assert_eq!(ngx_ssl_ocsp_cache_lookup(&mut ctx), NGX_OK);

        // past responses are not stored
        ctx2.valid = crate::times::time() - 1;
        assert_eq!(ngx_ssl_ocsp_cache_store(&mut ctx2), NGX_OK);
        assert_eq!(rb::walk(&ocsp_rbtree(&mem, cache)).len(), 1);
    }

    #[test]
    fn status_strings() {
        assert_eq!(status_str(0), "good");
        assert_eq!(status_str(1), "revoked");
        assert_eq!(status_str(2), "unknown");
        assert_eq!(status_str(7), "(UNKNOWN)");
        assert_eq!(response_status_str(5), "sigrequired");
        assert_eq!(response_status_str(4), "(UNKNOWN)");
    }

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
