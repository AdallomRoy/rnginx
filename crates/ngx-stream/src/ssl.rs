//! ngx_stream_ssl_module.c: TLS on the client connections of the stream
//! servers ("listen ... ssl"), the SSL phase, the SNI server selection and
//! the $ssl_* variables.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::event_openssl::*;
use ngx_core::event_openssl_cache::*;
use ngx_core::event_openssl_stapling::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_sys::ssl as sys;
use openssl::ssl::{AlpnError, NameType, SslRef};
use ngx_core::shm::ShmZone;
use ngx_core::string::B;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::handler::{finalize_session, session_of};
use crate::script::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_ssl_module");

const NGX_DEFAULT_CIPHERS: &[u8] = b"HIGH:!aNULL:!MD5";
const NGX_DEFAULT_ECDH_CURVE: &[u8] = b"auto";

/// ngx_stream_ssl_srv_conf_t
pub struct SslSrvConf {
    pub handshake_timeout: Val<u64>,

    pub prefer_server_ciphers: Val<bool>,
    pub certificate_compression: Val<bool>,
    pub reject_handshake: Val<bool>,

    /// the context; declared before shm_zone, which its session cache
    /// callbacks use until it is freed
    pub ssl: NgxSsl,

    pub protocols: u32,

    pub verify: Val<u32>,
    pub verify_depth: Val<i64>,

    pub builtin_session_cache: Val<isize>,

    pub session_timeout: Val<i64>,

    pub certificates: Val<Vec<Vec<u8>>>,
    pub certificate_keys: Val<Vec<Vec<u8>>>,

    pub certificate_values: Option<Vec<ComplexValue>>,
    pub certificate_key_values: Option<Vec<ComplexValue>>,

    /// NGX_CONF_UNSET_PTR: unset, Some(None): off
    pub certificate_cache: Val<Option<Rc<RefCell<SslCache>>>>,

    pub dhparam: Val<Vec<u8>>,
    pub ecdh_curve: Val<Vec<u8>>,
    pub client_certificate: Val<Vec<u8>>,
    pub trusted_certificate: Val<Vec<u8>>,
    pub crl: Val<Vec<u8>>,
    pub alpn: Val<Vec<u8>>,

    pub ciphers: Val<Vec<u8>>,

    pub ech_files: Val<Option<Vec<Vec<u8>>>>,
    pub passwords: Val<Option<Rc<SslPasswords>>>,
    pub conf_commands: Val<Option<Vec<(Vec<u8>, Vec<u8>)>>>,

    pub shm_zone: Option<Rc<ShmZone>>,

    pub session_tickets: Val<bool>,
    pub session_ticket_keys: Val<Option<Vec<Vec<u8>>>>,

    pub ocsp: Val<u32>,
    pub ocsp_responder: Val<Vec<u8>>,
    pub ocsp_cache_zone: Val<Option<Rc<ShmZone>>>,

    pub stapling: Val<bool>,
    pub stapling_verify: Val<bool>,
    pub stapling_file: Val<Vec<u8>>,
    pub stapling_responder: Val<Vec<u8>>,
}

static NGX_STREAM_SSL_PROTOCOLS: &[(&str, u32)] = &[
    ("SSLv2", NGX_SSL_SSLV2),
    ("SSLv3", NGX_SSL_SSLV3),
    ("TLSv1", NGX_SSL_TLSV1),
    ("TLSv1.1", NGX_SSL_TLSV1_1),
    ("TLSv1.2", NGX_SSL_TLSV1_2),
    ("TLSv1.3", NGX_SSL_TLSV1_3),
];

static NGX_STREAM_SSL_VERIFY: &[(&str, u32)] = &[("off", 0), ("on", 1), ("optional", 2), ("optional_no_ca", 3)];

static NGX_STREAM_SSL_OCSP: &[(&str, u32)] = &[("off", 0), ("on", 1), ("leaf", 2)];

/// The handlers of the variables (the data of the variables is the index).
static NGX_STREAM_SSL_HANDLERS: &[SslVariableHandler] = &[
    ngx_ssl_get_protocol,
    ngx_ssl_get_cipher_name,
    ngx_ssl_get_ciphers,
    ngx_ssl_get_curve,
    ngx_ssl_get_curves,
    ngx_ssl_get_sigalg,
    ngx_ssl_get_sigalgs,
    ngx_ssl_get_session_id,
    ngx_ssl_get_session_reused,
    ngx_ssl_get_server_name,
    ngx_ssl_get_alpn_protocol,
    ngx_ssl_get_ech_status,
    ngx_ssl_get_ech_outer_server_name,
    ngx_ssl_get_certificate,
    ngx_ssl_get_raw_certificate,
    ngx_ssl_get_escaped_certificate,
    ngx_ssl_get_subject_dn,
    ngx_ssl_get_issuer_dn,
    ngx_ssl_get_serial_number,
    ngx_ssl_get_fingerprint,
    ngx_ssl_get_client_verify,
    ngx_ssl_get_client_v_start,
    ngx_ssl_get_client_v_end,
    ngx_ssl_get_client_v_remain,
    ngx_ssl_get_client_sigalg,
];

static NGX_STREAM_SSL_VARS: &[VarDef] = &[
    VarDef { name: "ssl_protocol", set: None, get: Some(ngx_stream_ssl_static_variable), data: 0, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_cipher", set: None, get: Some(ngx_stream_ssl_static_variable), data: 1, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_ciphers", set: None, get: Some(ngx_stream_ssl_variable), data: 2, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_curve", set: None, get: Some(ngx_stream_ssl_variable), data: 3, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_curves", set: None, get: Some(ngx_stream_ssl_variable), data: 4, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_sigalg", set: None, get: Some(ngx_stream_ssl_variable), data: 5, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_sigalgs", set: None, get: Some(ngx_stream_ssl_variable), data: 6, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_session_id", set: None, get: Some(ngx_stream_ssl_variable), data: 7, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_session_reused", set: None, get: Some(ngx_stream_ssl_variable), data: 8, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_server_name", set: None, get: Some(ngx_stream_ssl_variable), data: 9, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_alpn_protocol", set: None, get: Some(ngx_stream_ssl_variable), data: 10, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_ech_status", set: None, get: Some(ngx_stream_ssl_variable), data: 11, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_ech_outer_server_name", set: None, get: Some(ngx_stream_ssl_variable), data: 12, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_cert", set: None, get: Some(ngx_stream_ssl_variable), data: 13, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_raw_cert", set: None, get: Some(ngx_stream_ssl_variable), data: 14, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_escaped_cert", set: None, get: Some(ngx_stream_ssl_variable), data: 15, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_s_dn", set: None, get: Some(ngx_stream_ssl_variable), data: 16, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_i_dn", set: None, get: Some(ngx_stream_ssl_variable), data: 17, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_serial", set: None, get: Some(ngx_stream_ssl_variable), data: 18, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_fingerprint", set: None, get: Some(ngx_stream_ssl_variable), data: 19, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_verify", set: None, get: Some(ngx_stream_ssl_variable), data: 20, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_v_start", set: None, get: Some(ngx_stream_ssl_variable), data: 21, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_v_end", set: None, get: Some(ngx_stream_ssl_variable), data: 22, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_v_remain", set: None, get: Some(ngx_stream_ssl_variable), data: 23, flags: NGX_STREAM_VAR_CHANGEABLE },
    VarDef { name: "ssl_client_sigalg", set: None, get: Some(ngx_stream_ssl_variable), data: 24, flags: NGX_STREAM_VAR_CHANGEABLE },
];

const NGX_STREAM_SSL_SESS_ID_CTX: &[u8] = b"STREAM";

/// The srv_conf of the module in a server's slots.
fn sscf_of(slots: &Rc<ConfSlots>) -> Rc<RefCell<SslSrvConf>> {
    slot::<SslSrvConf>(slots, ctx_index())
}

/// ngx_stream_ssl_handler: the SSL phase
async fn ngx_stream_ssl_handler(s: S) -> i64 {
    if !s.ssl.get() {
        return NGX_OK;
    }

    let c = s.connection.clone();

    let mut sscf = s.srv_conf::<SslSrvConf>(ctx_index());

    if c.ssl.borrow().is_none() {
        c.log.set_action(Some("SSL handshaking"));

        let (rv, again) = ngx_stream_ssl_init_connection(&s, &c).await;

        if rv != NGX_OK {
            return rv;
        }

        if again {
            // ngx_stream_ssl_handshake_handler() runs the phases again:
            // the server may have been changed by SNI
            sscf = s.srv_conf::<SslSrvConf>(ctx_index());
        }
    }

    let verify = *sscf.borrow().verify;

    if verify != 0 {
        let rc = ngx_ssl_get_verify_result(&c);

        if rc != X509_V_OK && (verify != 3 || !ngx_ssl_verify_error_optional(rc)) {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client SSL certificate verify error: ({}:{})", rc, B(&ngx_ssl_verify_error_string(rc)));

            remove_cached_session(&c);
            return NGX_ERROR;
        }

        if verify == 1 && ngx_ssl_with(&c, |ssl| ssl.peer_certificate().is_none()).unwrap_or(true) {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent no required SSL certificate");

            remove_cached_session(&c);
            return NGX_ERROR;
        }

        if let Err(str) = ngx_ssl_ocsp_get_status(&c) {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client SSL certificate verify error: {}", str);

            remove_cached_session(&c);
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_ssl_remove_cached_session(c->ssl->session_ctx, SSL_get0_session())
fn remove_cached_session(c: &Connection) {
    ngx_ssl_remove_cached_session(c);
}

/// ngx_stream_ssl_init_connection: the handshake; (rc, whether it did not
/// complete at once)
async fn ngx_stream_ssl_init_connection(s: &S, c: &Rc<Connection>) -> (i64, bool) {
    let tcp_nodelay = *s.cscf().borrow().tcp_nodelay;

    if tcp_nodelay && !c.set_tcp_nodelay() {
        return (NGX_ERROR, false);
    }

    {
        let sscf = s.srv_conf::<SslSrvConf>(ctx_index());
        let sscf = sscf.borrow();

        if ngx_ssl_create_connection(&sscf.ssl, c, 0) != NGX_OK {
            return (NGX_ERROR, false);
        }
    }

    // no configuration is borrowed during the handshake: the callbacks
    // change the server of the session

    let rc = ngx_ssl_handshake(c);

    if rc == NGX_ERROR {
        return (NGX_ERROR, false);
    }

    if rc == NGX_AGAIN {
        let timeout = *s.srv_conf::<SslSrvConf>(ctx_index()).borrow().handshake_timeout;

        // ngx_add_timer(c->read, sscf->handshake_timeout);
        // c->ssl->handler = ngx_stream_ssl_handshake_handler;

        let _ = tokio::time::timeout(Duration::from_millis(timeout), ngx_ssl_handshake_wait(c)).await;

        // ngx_stream_ssl_handshake_handler

        let handshaked = c.ssl.borrow().as_ref().map(|sc| sc.handshaked.get()).unwrap_or(false);

        if !handshaked {
            finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return (NGX_DONE, true);
        }

        return (NGX_OK, true);
    }

    /* rc == NGX_OK */

    (NGX_OK, false)
}

static NGX_STREAM_SSL_CLIENT_HELLO_ARG: SslClientHelloArg = SslClientHelloArg { servername: ngx_stream_ssl_servername };

/// ngx_stream_ssl_servername: the server of the session by the server name
/// (from ngx_ssl_client_hello_callback() with the name, or as the tlsext
/// servername callback)
fn ngx_stream_ssl_servername(c: &Rc<Connection>, ssl_conn: &mut SslRef, ad: &mut i32, arg: SniArg<'_>) -> i32 {
    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return sys::SSL_TLSEXT_ERR_OK,
    };

    if sc.handshaked.get() {
        *ad = sys::SSL_AD_NO_RENEGOTIATION;
        return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if sc.state.sni_accepted.get() {
        return sys::SSL_TLSEXT_ERR_OK;
    }

    if sc.state.handshake_rejected.get() {
        *ad = sys::SSL_AD_UNRECOGNIZED_NAME;
        return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    let s = match session_of(c) {
        Some(s) => s,
        None => {
            *ad = sys::SSL_AD_INTERNAL_ERROR;
            return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    };

    let error = 'done: {
        let host: Vec<u8> = match arg {
            SniArg::Hello(Some(h)) => h.to_vec(),

            SniArg::Hello(None) => {
                ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "SSL server name: null");
                break 'done false;
            }

            SniArg::Callback => match ssl_conn.servername_raw(NameType::HOST_NAME) {
                Some(name) => name.to_vec(),
                None => {
                    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "SSL server name: null");
                    break 'done false;
                }
            },
        };

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "SSL server name: \"{}\"", B(&host));

        if host.is_empty() {
            break 'done false;
        }

        let host = match validate_host(&host) {
            Ok(h) => h,
            Err(rc) if rc == NGX_DECLINED => break 'done false,
            Err(_) => break 'done true,
        };

        let cscf = match find_virtual_server(&s, &host) {
            Ok(cscf) => cscf,
            Err(rc) if rc == NGX_DECLINED => break 'done false,
            Err(_) => break 'done true,
        };

        let (srv, error_log) = {
            let cscf = cscf.borrow();
            (cscf.ctx.srv.clone().expect("srv conf"), cscf.error_log.clone())
        };

        *s.srv_conf.borrow_mut() = srv.clone();

        if let Some(chain) = error_log {
            c.log.set_chain(chain);
        }

        let ctx = sscf_of(&srv).borrow().ssl.ctx.get();

        if let Some(ctx) = ctx {
            /*
             * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
             * adjust other things we care about
             */

            if !ngx_ssl_set_ssl_ctx(ssl_conn, &ctx) {
                break 'done true;
            }
        }

        false
    };

    if error {
        *ad = sys::SSL_AD_INTERNAL_ERROR;
        return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    // done:

    let reject = *s.srv_conf::<SslSrvConf>(ctx_index()).borrow().reject_handshake;

    if reject {
        sc.state.handshake_rejected.set(true);
        *ad = sys::SSL_AD_UNRECOGNIZED_NAME;
        return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    sc.state.sni_accepted.set(true);

    sys::SSL_TLSEXT_ERR_OK
}

/// The protocol of the client's list equal to `proto`.
fn client_proto<'a>(client: &'a [u8], proto: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;

    while i < client.len() {
        let l = client[i] as usize;
        let end = (i + 1 + l).min(client.len());

        if &client[i + 1..end] == proto {
            return Some(&client[i + 1..end]);
        }

        i += l + 1;
    }

    None
}

/// ngx_stream_ssl_alpn_select: `alpn` is the list of the server of the
/// context
fn ngx_stream_ssl_alpn_select<'a>(ssl_conn: &mut SslRef, client: &'a [u8], alpn: &[u8]) -> Result<&'a [u8], AlpnError> {
    let c = ngx_ssl_get_connection(ssl_conn);

    if let Some(c) = c.as_ref() {
        if c.log.debug_enabled(NGX_LOG_DEBUG_STREAM) {
            let mut i = 0;

            while i < client.len() {
                let l = client[i] as usize;
                let end = (i + 1 + l).min(client.len());

                ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "SSL ALPN supported by client: {}", B(&client[i + 1..end]));

                i += l + 1;
            }
        }
    }

    // SSL_select_next_proto(): the protocol of the server's list, which
    // OpenSSL copies (the same bytes are taken in the client's list)
    let out = match openssl::ssl::select_next_proto(alpn, client).and_then(|p| client_proto(client, p)) {
        Some(out) => out,
        None => return Err(AlpnError::ALERT_FATAL),
    };

    if let Some(c) = c.as_ref() {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "SSL ALPN selected: {}", B(out));
    }

    Ok(out)
}

/// The value of a complex value compiled with "zero" (ends with a NUL,
/// which is not part of the path).
fn zero_value(s: &Session, cv: &ComplexValue) -> Result<Vec<u8>, ()> {
    let mut v = complex_value(s, cv)?;

    if v.last() == Some(&0) {
        v.pop();
    }

    Ok(v)
}

/// ngx_stream_ssl_certificate: the certificate callback loading the
/// certificates with variables; conf is the configuration of the server of
/// the context
fn ngx_stream_ssl_certificate(c: &Rc<Connection>, ssl_conn: &mut SslRef, conf: Option<Rc<dyn Any>>) -> i32 {
    let handshaked = c.ssl.borrow().as_ref().map(|sc| sc.handshaked.get()).unwrap_or(true);

    if handshaked {
        return 0;
    }

    let s = match session_of(c) {
        Some(s) => s,
        None => return 0,
    };

    let sscf = match conf.and_then(|conf| conf.downcast::<RefCell<SslSrvConf>>().ok()) {
        Some(sscf) => sscf,
        None => return 0,
    };

    let (certs, keys, cache, passwords) = {
        let sscf = sscf.borrow();
        (
            sscf.certificate_values.clone().unwrap_or_default(),
            sscf.certificate_key_values.clone().unwrap_or_default(),
            sscf.certificate_cache.as_option().cloned().flatten(),
            sscf.passwords.as_option().cloned().flatten(),
        )
    };

    for i in 0..certs.len() {
        // the variables read the SSL object of the connection, which the
        // callback has
        let mut cert = match sys::with_current(ssl_conn, || zero_value(&s, &certs[i])) {
            Ok(v) => v,
            Err(()) => return 0,
        };

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "ssl cert: \"{}\"", B(&cert));

        let mut key = match sys::with_current(ssl_conn, || zero_value(&s, &keys[i])) {
            Ok(v) => v,
            Err(()) => return 0,
        };

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "ssl key: \"{}\"", B(&key));

        if ngx_ssl_connection_certificate_ssl(c, ssl_conn, &mut cert, &mut key, cache.as_ref(), passwords.as_ref()) != NGX_OK {
            return 0;
        }
    }

    1
}

/// ngx_stream_ssl_static_variable: the value of a handler returning a
/// static string
fn ngx_stream_ssl_static_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let handler = NGX_STREAM_SSL_HANDLERS[data];

    if s.connection.ssl.borrow().is_some() {
        let mut str = Vec::new();

        let _ = handler(&s.connection, &mut str);

        let len = str.iter().position(|&ch| ch == 0).unwrap_or(str.len());
        str.truncate(len);

        v.data = str;
        v.valid = true;
        v.no_cacheable = false;
        v.not_found = false;

        return NGX_OK;
    }

    v.not_found = true;

    NGX_OK
}

/// ngx_stream_ssl_variable
fn ngx_stream_ssl_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let handler = NGX_STREAM_SSL_HANDLERS[data];

    if s.connection.ssl.borrow().is_some() {
        let mut str = Vec::new();

        if handler(&s.connection, &mut str) != NGX_OK {
            return NGX_ERROR;
        }

        if !str.is_empty() {
            v.data = str;
            v.valid = true;
            v.no_cacheable = false;
            v.not_found = false;

            return NGX_OK;
        }
    }

    v.not_found = true;

    NGX_OK
}

/// ngx_stream_ssl_add_variables
fn ngx_stream_ssl_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, NGX_STREAM_SSL_VARS)
}

/// ngx_stream_ssl_create_srv_conf
fn ngx_stream_ssl_create_srv_conf(cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SslSrvConf {
        handshake_timeout: Val::unset(),
        prefer_server_ciphers: Val::unset(),
        certificate_compression: Val::unset(),
        reject_handshake: Val::unset(),
        ssl: NgxSsl::new(cf.log.clone()),
        protocols: 0,
        verify: Val::unset(),
        verify_depth: Val::unset(),
        builtin_session_cache: Val::unset(),
        session_timeout: Val::unset(),
        certificates: Val::unset(),
        certificate_keys: Val::unset(),
        certificate_values: None,
        certificate_key_values: None,
        certificate_cache: Val::unset(),
        dhparam: Val::unset(),
        ecdh_curve: Val::unset(),
        client_certificate: Val::unset(),
        trusted_certificate: Val::unset(),
        crl: Val::unset(),
        alpn: Val::unset(),
        ciphers: Val::unset(),
        ech_files: Val::unset(),
        passwords: Val::unset(),
        conf_commands: Val::unset(),
        shm_zone: None,
        session_tickets: Val::unset(),
        session_ticket_keys: Val::unset(),
        ocsp: Val::unset(),
        ocsp_responder: Val::unset(),
        ocsp_cache_zone: Val::unset(),
        stapling: Val::unset(),
        stapling_verify: Val::unset(),
        stapling_file: Val::unset(),
        stapling_responder: Val::unset(),
    })
}

/// ngx_conf_merge_ptr_value() of an array (unset stays NULL)
fn merge_ptr<T: Clone>(conf: &mut Val<Option<T>>, prev: &Val<Option<T>>) {
    if !conf.is_set() {
        *conf = Val::set(prev.as_option().cloned().flatten());
    }
}

/// ngx_stream_ssl_merge_srv_conf
fn ngx_stream_ssl_merge_srv_conf(cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev_rc = conf_rc::<SslSrvConf>(parent);
    let conf_rc = conf_rc::<SslSrvConf>(child);

    let conf_any: Rc<dyn Any> = conf_rc.clone();

    let prev = prev_rc.borrow();
    let mut conf_ref = conf_rc.borrow_mut();
    let conf = &mut *conf_ref;

    conf.handshake_timeout.merge(&prev.handshake_timeout, 60000);

    conf.session_timeout.merge(&prev.session_timeout, 300);

    conf.prefer_server_ciphers.merge(&prev.prefer_server_ciphers, false);

    conf.certificate_compression.merge(&prev.certificate_compression, false);

    conf.reject_handshake.merge(&prev.reject_handshake, false);

    if conf.protocols == 0 {
        conf.protocols = if prev.protocols == 0 { NGX_CONF_BITMASK_SET | NGX_SSL_DEFAULT_PROTOCOLS } else { prev.protocols };
    }

    conf.verify.merge(&prev.verify, 0);
    conf.verify_depth.merge(&prev.verify_depth, 1);

    conf.certificates.merge_opt(&prev.certificates);
    conf.certificate_keys.merge_opt(&prev.certificate_keys);

    merge_ptr(&mut conf.certificate_cache, &prev.certificate_cache);

    merge_ptr(&mut conf.ech_files, &prev.ech_files);

    merge_ptr(&mut conf.passwords, &prev.passwords);

    conf.dhparam.merge(&prev.dhparam, Vec::new());

    conf.client_certificate.merge(&prev.client_certificate, Vec::new());
    conf.trusted_certificate.merge(&prev.trusted_certificate, Vec::new());
    conf.crl.merge(&prev.crl, Vec::new());
    conf.alpn.merge(&prev.alpn, Vec::new());

    conf.ecdh_curve.merge(&prev.ecdh_curve, NGX_DEFAULT_ECDH_CURVE.to_vec());

    conf.ciphers.merge(&prev.ciphers, NGX_DEFAULT_CIPHERS.to_vec());

    merge_ptr(&mut conf.conf_commands, &prev.conf_commands);

    conf.ocsp.merge(&prev.ocsp, 0);
    conf.ocsp_responder.merge(&prev.ocsp_responder, Vec::new());
    merge_ptr(&mut conf.ocsp_cache_zone, &prev.ocsp_cache_zone);

    conf.stapling.merge(&prev.stapling, false);
    conf.stapling_verify.merge(&prev.stapling_verify, false);
    conf.stapling_file.merge(&prev.stapling_file, Vec::new());
    conf.stapling_responder.merge(&prev.stapling_responder, Vec::new());

    conf.ssl.log = cf.log.clone();

    if let Some(certs) = conf.certificates.as_option() {
        let nkeys = conf.certificate_keys.as_option().map(|k| k.len());

        if nkeys.is_none() || nkeys.unwrap() < certs.len() {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"ssl_certificate_key\" is defined for certificate \"{}\"", B(certs.last().unwrap()));
            return Err(ConfError::Logged);
        }
    } else if !*conf.reject_handshake {
        return Ok(());
    }

    if ngx_ssl_create(&mut conf.ssl, conf.protocols, Some(conf_any)) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if ngx_ssl_set_client_hello_callback(&mut conf.ssl, &NGX_STREAM_SSL_CLIENT_HELLO_ARG) != NGX_OK {
        return Err(ConfError::Logged);
    }

    ngx_ssl_set_servername_callback(&mut conf.ssl, ngx_stream_ssl_servername);

    if conf.alpn.as_option().map(|a| !a.is_empty()).unwrap_or(false) {
        let alpn = conf.alpn.as_option().cloned().unwrap_or_default();

        if let Some(ctx) = conf.ssl.ctx.builder_mut() {
            ctx.set_alpn_select_callback(move |ssl, client| ngx_stream_ssl_alpn_select(ssl, client, &alpn));
        }
    }

    if ngx_ssl_ciphers(cf, &mut conf.ssl, &conf.ciphers, *conf.prefer_server_ciphers) != NGX_OK {
        return Err(ConfError::Logged);
    }

    ngx_stream_ssl_compile_certificates(cf, conf)?;

    if conf.certificate_values.is_some() {
        /* install callback to lookup certificates */

        ngx_ssl_set_cert_callback(&mut conf.ssl, ngx_stream_ssl_certificate);
    } else if conf.certificates.is_set() {
        /* configure certificates */

        let passwords = conf.passwords.as_option().cloned().flatten();

        let certs = conf.certificates.0.as_mut().unwrap();
        let keys = conf.certificate_keys.0.as_mut().unwrap();

        if ngx_ssl_certificates(cf, &mut conf.ssl, certs, keys, passwords.as_ref()) != NGX_OK {
            return Err(ConfError::Logged);
        }

        if ngx_ssl_certificate_compression(cf, &mut conf.ssl, *conf.certificate_compression) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    let verify = *conf.verify;
    let verify_depth = *conf.verify_depth;

    if verify != 0 {
        if verify != 3 && conf.client_certificate.is_empty() && conf.trusted_certificate.is_empty() {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no ssl_client_certificate or ssl_trusted_certificate for ssl_verify_client");
            return Err(ConfError::Logged);
        }

        if ngx_ssl_client_certificate(cf, &mut conf.ssl, conf.client_certificate.0.as_mut().unwrap(), verify_depth) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    if ngx_ssl_trusted_certificate(cf, &mut conf.ssl, conf.trusted_certificate.0.as_mut().unwrap(), verify_depth) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if ngx_ssl_crl(cf, &mut conf.ssl, conf.crl.0.as_mut().unwrap()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if *conf.ocsp != 0 {
        if verify == 3 {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "\"ssl_ocsp\" is incompatible with \"ssl_verify_client optional_no_ca\"");
            return Err(ConfError::Logged);
        }

        let zone = conf.ocsp_cache_zone.as_option().cloned().flatten();

        if ngx_ssl_ocsp(cf, &mut conf.ssl, &conf.ocsp_responder, *conf.ocsp as usize, zone) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    if ngx_ssl_dhparam(cf, &mut conf.ssl, conf.dhparam.0.as_mut().unwrap()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if ngx_ssl_ech_files(cf, &mut conf.ssl, conf.ech_files.as_option().and_then(|e| e.as_ref())) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if ngx_ssl_ecdh_curve(cf, &mut conf.ssl, &conf.ecdh_curve) != NGX_OK {
        return Err(ConfError::Logged);
    }

    conf.builtin_session_cache.merge(&prev.builtin_session_cache, NGX_SSL_NONE_SCACHE);

    if conf.shm_zone.is_none() {
        conf.shm_zone = prev.shm_zone.clone();
    }

    let shm_zone = conf.shm_zone.clone();

    if ngx_ssl_session_cache(&mut conf.ssl, NGX_STREAM_SSL_SESS_ID_CTX, conf.certificates.as_option(), *conf.builtin_session_cache, shm_zone.as_ref(), *conf.session_timeout) != NGX_OK {
        return Err(ConfError::Logged);
    }

    conf.session_tickets.merge(&prev.session_tickets, true);

    if !*conf.session_tickets {
        ngx_ssl_set_options(&mut conf.ssl, sys::SSL_OP_NO_TICKET);
    }

    merge_ptr(&mut conf.session_ticket_keys, &prev.session_ticket_keys);

    if ngx_ssl_session_ticket_keys(cf, &mut conf.ssl, conf.session_ticket_keys.0.as_mut().unwrap().as_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if *conf.stapling {
        if *conf.certificate_compression {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "\"ssl_stapling\" is incompatible with \"ssl_certificate_compression\"");
            return Err(ConfError::Logged);
        }

        let verify = *conf.stapling_verify;

        if ngx_ssl_stapling(cf, &mut conf.ssl, conf.stapling_file.0.as_mut().unwrap(), conf.stapling_responder.0.as_mut().unwrap(), verify) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    if ngx_ssl_conf_commands(cf, &mut conf.ssl, conf.conf_commands.0.as_mut().unwrap().as_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    Ok(())
}

/// ngx_stream_ssl_compile_certificates: the certificates with variables
fn ngx_stream_ssl_compile_certificates(cf: &mut Conf, conf: &mut SslSrvConf) -> ConfResult {
    let (certs, keys) = match (conf.certificates.as_option(), conf.certificate_keys.as_option()) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => return Ok(()),
    };

    let nelts = certs.len();

    let found = (0..nelts).any(|i| script_variables_count(&certs[i]) != 0 || script_variables_count(&keys[i]) != 0);

    if !found {
        return Ok(());
    }

    let mut cert_values = Vec::with_capacity(nelts);
    let mut key_values = Vec::with_capacity(nelts);

    for i in 0..nelts {
        let mut ccv = CompileComplexValue { zero: true, ..Default::default() };

        cert_values.push(compile_complex_value(cf, &certs[i], &mut ccv)?);

        let mut ccv = CompileComplexValue { zero: true, ..Default::default() };

        key_values.push(compile_complex_value(cf, &keys[i], &mut ccv)?);
    }

    conf.certificate_values = Some(cert_values);
    conf.certificate_key_values = Some(key_values);

    let passwords = conf.passwords.as_option().cloned().flatten();

    conf.passwords = Val::set(Some(ngx_ssl_preserve_passwords(cf, passwords.as_ref())));

    Ok(())
}

/// ngx_stream_ssl_certificate_cache
fn ngx_stream_ssl_certificate_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));

    if sscf.borrow().certificate_cache.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let mut max: i64 = 0;
    let mut inactive: i64 = 10;
    let mut valid: i64 = 60;

    let mut off = false;

    for v in &value[1..] {
        let ok = if let Some(rest) = v.strip_prefix(b"max=") {
            match ngx_core::string::atoi(rest) {
                Some(n) if n > 0 => {
                    max = n;
                    true
                }
                _ => false,
            }
        } else if let Some(rest) = v.strip_prefix(b"inactive=") {
            match ngx_core::parse::parse_time(rest, true) {
                Some(t) => {
                    inactive = t;
                    true
                }
                None => false,
            }
        } else if let Some(rest) = v.strip_prefix(b"valid=") {
            match ngx_core::parse::parse_time(rest, true) {
                Some(t) => {
                    valid = t;
                    true
                }
                None => false,
            }
        } else if v.as_slice() == b"off" {
            off = true;
            true
        } else {
            false
        };

        if !ok {
            // failed:
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(v))));
        }
    }

    if off {
        sscf.borrow_mut().certificate_cache = Val::set(None);
        return Ok(());
    }

    if max == 0 {
        return Err(cf.emerg(format_args!("\"ssl_certificate_cache\" must have the \"max\" parameter")));
    }

    let cache = ngx_ssl_cache_init(max as usize, valid, inactive);

    sscf.borrow_mut().certificate_cache = Val::set(Some(Rc::new(RefCell::new(cache))));

    Ok(())
}

/// ngx_stream_ssl_password_file
fn ngx_stream_ssl_password_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));

    if sscf.borrow().passwords.is_set() {
        return Err(msg("is duplicate"));
    }

    let file = cf.args[1].clone();

    match ngx_ssl_read_password_file(cf, &file) {
        Some(p) => {
            sscf.borrow_mut().passwords = Val::set(Some(p));
            Ok(())
        }
        None => Err(ConfError::Logged),
    }
}

/// "shared:name:size" of the cache directives: the name and the size
fn parse_shared(v: &[u8]) -> Option<(Vec<u8>, Option<usize>)> {
    let prefix = b"shared:";

    if v.len() <= prefix.len() || !v.starts_with(prefix) {
        return None;
    }

    let mut len = 0;
    let mut j = prefix.len();

    while j < v.len() {
        if v[j] == b':' {
            break;
        }

        len += 1;
        j += 1;
    }

    if len == 0 || j == v.len() {
        return Some((Vec::new(), None));
    }

    let name = v[prefix.len()..prefix.len() + len].to_vec();

    Some((name, ngx_core::parse::parse_size(&v[j + 1..])))
}

/// ngx_stream_ssl_session_cache
fn ngx_stream_ssl_session_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));

    let value = cf.args.clone();

    for v in &value[1..] {
        if v.as_slice() == b"off" {
            sscf.borrow_mut().builtin_session_cache = Val::set(NGX_SSL_NO_SCACHE);
            continue;
        }

        if v.as_slice() == b"none" {
            sscf.borrow_mut().builtin_session_cache = Val::set(NGX_SSL_NONE_SCACHE);
            continue;
        }

        if v.as_slice() == b"builtin" {
            sscf.borrow_mut().builtin_session_cache = Val::set(NGX_SSL_DFLT_BUILTIN_SCACHE);
            continue;
        }

        if v.len() > b"builtin:".len() && v.starts_with(b"builtin:") {
            match ngx_core::string::atoi(&v[b"builtin:".len()..]) {
                Some(n) => {
                    sscf.borrow_mut().builtin_session_cache = Val::set(n as isize);
                    continue;
                }
                None => return Err(cf.emerg(format_args!("invalid session cache \"{}\"", B(v)))),
            }
        }

        if let Some((name, size)) = parse_shared(v) {
            let n = match size {
                Some(n) if !name.is_empty() => n,
                _ => return Err(cf.emerg(format_args!("invalid session cache \"{}\"", B(v)))),
            };

            if n < 8 * ngx_core::os::pagesize() {
                return Err(cf.emerg(format_args!("session cache \"{}\" is too small", B(v))));
            }

            let zone = ngx_core::cycle::shared_memory_add(cf, &name, n, "ngx_stream_ssl_module")?;

            *zone.init.borrow_mut() = Some(Rc::new(ngx_ssl_session_cache_init));

            sscf.borrow_mut().shm_zone = Some(zone);

            continue;
        }

        return Err(cf.emerg(format_args!("invalid session cache \"{}\"", B(v))));
    }

    let mut c = sscf.borrow_mut();

    if c.shm_zone.is_some() && !c.builtin_session_cache.is_set() {
        c.builtin_session_cache = Val::set(NGX_SSL_NO_BUILTIN_SCACHE);
    }

    Ok(())
}

/// ngx_stream_ssl_ocsp_cache
fn ngx_stream_ssl_ocsp_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));

    if sscf.borrow().ocsp_cache_zone.is_set() {
        return Err(msg("is duplicate"));
    }

    let v = cf.args[1].clone();

    if v.as_slice() == b"off" {
        sscf.borrow_mut().ocsp_cache_zone = Val::set(None);
        return Ok(());
    }

    let (name, n) = match parse_shared(&v) {
        Some((name, Some(n))) if !name.is_empty() => (name, n),
        _ => return Err(cf.emerg(format_args!("invalid OCSP cache \"{}\"", B(&v)))),
    };

    if n < 8 * ngx_core::os::pagesize() {
        return Err(cf.emerg(format_args!("OCSP cache \"{}\" is too small", B(&v))));
    }

    let zone = ngx_core::cycle::shared_memory_add(cf, &name, n, "ngx_stream_ssl_module_ctx")?;

    *zone.init.borrow_mut() = Some(Rc::new(ngx_ssl_ocsp_cache_init));

    sscf.borrow_mut().ocsp_cache_zone = Val::set(Some(zone));

    Ok(())
}

/// ngx_stream_ssl_alpn: the protocols in the wire format
fn ngx_stream_ssl_alpn(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));

    if sscf.borrow().alpn.as_option().map(|a| !a.is_empty()).unwrap_or(false) {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let mut alpn = Vec::new();

    for v in &value[1..] {
        if v.len() > 255 {
            return Err(msg("protocol too long"));
        }
    }

    for v in &value[1..] {
        alpn.push(v.len() as u8);
        alpn.extend_from_slice(v);
    }

    sscf.borrow_mut().alpn = Val::set(alpn);

    Ok(())
}

/// ssl_conf_command: ngx_conf_set_keyval_slot with
/// ngx_stream_ssl_conf_command_check (SSL_CONF_cmd() is available)
fn ngx_stream_ssl_conf_command(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));

    let mut c = sscf.borrow_mut();

    if !c.conf_commands.is_set() {
        c.conf_commands = Val::set(Some(Vec::new()));
    }

    c.conf_commands.0.as_mut().unwrap().as_mut().unwrap().push((cf.args[1].clone(), cf.args[2].clone()));

    Ok(())
}

/// ngx_conf_set_str_array_slot() on an optional array
fn set_array(cf: &mut Conf, slot: &mut Val<Option<Vec<Vec<u8>>>>) -> ConfResult {
    if !slot.is_set() {
        *slot = Val::set(Some(Vec::new()));
    }

    slot.0.as_mut().unwrap().as_mut().unwrap().push(cf.args[1].clone());

    Ok(())
}

fn ngx_stream_ssl_ech_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));
    let mut c = sscf.borrow_mut();
    set_array(cf, &mut c.ech_files)
}

fn ngx_stream_ssl_session_ticket_key(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));
    let mut c = sscf.borrow_mut();
    set_array(cf, &mut c.session_ticket_keys)
}

fn ngx_stream_ssl_protocols(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<SslSrvConf>(conf.as_ref().expect("conf"));
    let mut c = sscf.borrow_mut();
    set_bitmask(cf, cmd, &mut c.protocols, NGX_STREAM_SSL_PROTOCOLS)
}

/// ngx_stream_ssl_init: the SSL phase handler, the resolvers of OCSP, the
/// certificates of "listen ... ssl"
fn ngx_stream_ssl_init(cf: &mut Conf) -> ConfResult {
    let cmcf = core_main_conf(cf);

    let servers = cmcf.borrow().servers.clone();

    for cscf in servers.iter() {
        let srv = cscf.borrow().ctx.srv.clone().expect("srv conf");

        let sscf = sscf_of(&srv);

        if sscf.borrow().ssl.ctx.is_null() {
            continue;
        }

        let (resolver, resolver_timeout) = {
            let c = cscf.borrow();
            (c.resolver.clone(), *c.resolver_timeout)
        };

        let (stapling, ocsp) = {
            let s = sscf.borrow();
            (*s.stapling, *s.ocsp)
        };

        if stapling && ngx_ssl_stapling_resolver(cf, &mut sscf.borrow_mut().ssl, resolver.clone(), resolver_timeout) != NGX_OK {
            return Err(ConfError::Logged);
        }

        if ocsp != 0 && ngx_ssl_ocsp_resolver(cf, &mut sscf.borrow_mut().ssl, resolver, resolver_timeout) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    add_phase_handler(cf, NGX_STREAM_SSL_PHASE, phase_fn(ngx_stream_ssl_handler));

    let m = cmcf.borrow();

    for port in m.ports.iter() {
        for addr in port.addrs.iter() {
            if !addr.opt.ssl {
                continue;
            }

            let cscf = addr.default_server.clone();
            let sscf = sscf_of(&cscf.borrow().ctx.srv.clone().expect("srv conf"));

            if sscf.borrow().certificates.is_set() {
                continue;
            }

            if !*sscf.borrow().reject_handshake {
                let c = cscf.borrow();
                ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive in {}:{}", B(&c.file_name), c.line);
                return Err(ConfError::Logged);
            }

            /*
             * if no certificates are defined in the default server,
             * check all non-default server blocks
             */

            for cscf in addr.servers.iter() {
                let sscf = sscf_of(&cscf.borrow().ctx.srv.clone().expect("srv conf"));

                let s = sscf.borrow();

                if s.certificates.is_set() || *s.reject_handshake {
                    continue;
                }

                let c = cscf.borrow();
                ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive in {}:{}", B(&c.file_name), c.line);
                return Err(ConfError::Logged);
            }
        }
    }

    Ok(())
}

pub fn ssl_module() -> ModuleDef {
    const CONF: u32 = NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF;

    stream_module_def(
        "ngx_stream_ssl_module",
        StreamModuleDef {
            preconfiguration: Some(ngx_stream_ssl_add_variables),
            postconfiguration: Some(ngx_stream_ssl_init),
            create_main_conf: None,
            init_main_conf: None,
            create_srv_conf: Some(ngx_stream_ssl_create_srv_conf),
            merge_srv_conf: Some(ngx_stream_ssl_merge_srv_conf),
        },
        vec![
            cmd!("ssl_handshake_timeout", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, handshake_timeout, set_msec),
            cmd!("ssl_certificate", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, certificates, set_str_array),
            cmd!("ssl_certificate_key", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, certificate_keys, set_str_array),
            cmd_fn!("ssl_certificate_cache", CONF | NGX_CONF_TAKE123, ConfLevel::Srv, ngx_stream_ssl_certificate_cache),
            cmd_fn!("ssl_ech_file", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ngx_stream_ssl_ech_file),
            cmd_fn!("ssl_password_file", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ngx_stream_ssl_password_file),
            cmd!("ssl_certificate_compression", CONF | NGX_CONF_FLAG, ConfLevel::Srv, SslSrvConf, certificate_compression, set_flag),
            cmd!("ssl_dhparam", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, dhparam, set_str),
            cmd!("ssl_ecdh_curve", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, ecdh_curve, set_str),
            cmd_fn!("ssl_protocols", CONF | NGX_CONF_1MORE, ConfLevel::Srv, ngx_stream_ssl_protocols),
            cmd!("ssl_ciphers", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, ciphers, set_str),
            cmd!("ssl_verify_client", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, verify, set_enum, NGX_STREAM_SSL_VERIFY),
            cmd!("ssl_verify_depth", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, verify_depth, set_num),
            cmd!("ssl_client_certificate", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, client_certificate, set_str),
            cmd!("ssl_trusted_certificate", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, trusted_certificate, set_str),
            cmd!("ssl_prefer_server_ciphers", CONF | NGX_CONF_FLAG, ConfLevel::Srv, SslSrvConf, prefer_server_ciphers, set_flag),
            cmd_fn!("ssl_session_cache", CONF | NGX_CONF_TAKE12, ConfLevel::Srv, ngx_stream_ssl_session_cache),
            cmd!("ssl_session_tickets", CONF | NGX_CONF_FLAG, ConfLevel::Srv, SslSrvConf, session_tickets, set_flag),
            cmd_fn!("ssl_session_ticket_key", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ngx_stream_ssl_session_ticket_key),
            cmd!("ssl_session_timeout", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, session_timeout, set_sec),
            cmd!("ssl_crl", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, crl, set_str),
            cmd!("ssl_ocsp", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, ocsp, set_enum, NGX_STREAM_SSL_OCSP),
            cmd!("ssl_ocsp_responder", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, ocsp_responder, set_str),
            cmd_fn!("ssl_ocsp_cache", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ngx_stream_ssl_ocsp_cache),
            cmd!("ssl_stapling", CONF | NGX_CONF_FLAG, ConfLevel::Srv, SslSrvConf, stapling, set_flag),
            cmd!("ssl_stapling_file", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, stapling_file, set_str),
            cmd!("ssl_stapling_responder", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, SslSrvConf, stapling_responder, set_str),
            cmd!("ssl_stapling_verify", CONF | NGX_CONF_FLAG, ConfLevel::Srv, SslSrvConf, stapling_verify, set_flag),
            cmd_fn!("ssl_conf_command", CONF | NGX_CONF_TAKE2, ConfLevel::Srv, ngx_stream_ssl_conf_command),
            cmd!("ssl_reject_handshake", CONF | NGX_CONF_FLAG, ConfLevel::Srv, SslSrvConf, reject_handshake, set_flag),
            cmd_fn!("ssl_alpn", CONF | NGX_CONF_1MORE, ConfLevel::Srv, ngx_stream_ssl_alpn),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_cache_parameter() {
        assert_eq!(parse_shared(b"shared:SSL:1m"), Some((b"SSL".to_vec(), Some(1024 * 1024))));
        assert_eq!(parse_shared(b"shared:SSL"), Some((Vec::new(), None)));
        assert_eq!(parse_shared(b"shared::1m"), Some((Vec::new(), None)));
        assert_eq!(parse_shared(b"shared:"), None);
        assert_eq!(parse_shared(b"builtin"), None);
    }

    #[test]
    fn handlers_match_variables() {
        assert_eq!(NGX_STREAM_SSL_HANDLERS.len(), NGX_STREAM_SSL_VARS.len());
        for (i, v) in NGX_STREAM_SSL_VARS.iter().enumerate() {
            assert_eq!(v.data, i);
        }
    }
}
