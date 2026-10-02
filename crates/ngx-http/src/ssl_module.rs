//! ngx_http_ssl_module.c: TLS on the client connections of the http servers
//! ("listen ... ssl"): the directives, the contexts and the $ssl_*
//! variables; and the TLS parts of ngx_http_request.c:
//! ngx_http_ssl_handshake(), ngx_http_ssl_handshake_handler(),
//! ngx_http_ssl_servername(), ngx_http_ssl_certificate(), the SSL checks of
//! ngx_http_process_request() and ngx_http_set_virtual_server(), and the SSL
//! shutdown of ngx_http_close_connection() and of the lingering close.

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
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_sys::ssl as sys;
use openssl::ssl::{AlpnError, NameType, SslRef};
use ngx_core::shm::ShmZone;
use ngx_core::string::B;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::{core_main_conf, loc_conf_from_ctx, srv_conf_from_ctx, CoreSrvConf};
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_ssl_module");

const NGX_DEFAULT_CIPHERS: &[u8] = b"HIGH:!aNULL:!MD5";
const NGX_DEFAULT_ECDH_CURVE: &[u8] = b"auto";

const NGX_HTTP_ALPN_PROTOS: &[u8] = b"\x08http/1.1\x08http/1.0\x08http/0.9";

/// NGX_HTTP_V2_ALPN_PROTO NGX_HTTP_ALPN_PROTOS
const NGX_HTTP_V2_ALPN_PROTOS: &[u8] = b"\x02h2\x08http/1.1\x08http/1.0\x08http/0.9";

/// NGX_HTTP_V3_ALPN_PROTO NGX_HTTP_V3_HQ_ALPN_PROTO
const NGX_HTTP_V3_ALPN_PROTOS: &[u8] = b"\x02h3\x0Ahq-interop";

/// ngx_http_ssl_srv_conf_t
pub struct HttpSslSrvConf {
    pub prefer_server_ciphers: Val<bool>,
    pub certificate_compression: Val<bool>,
    pub early_data: Val<bool>,
    pub reject_handshake: Val<bool>,

    /// the context; declared before shm_zone, which its session cache
    /// callbacks use until it is freed
    pub ssl: NgxSsl,

    pub protocols: u32,

    pub verify: Val<u32>,
    pub verify_depth: Val<i64>,

    pub buffer_size: Val<usize>,

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

static NGX_HTTP_SSL_PROTOCOLS: &[(&str, u32)] = &[
    ("SSLv2", NGX_SSL_SSLV2),
    ("SSLv3", NGX_SSL_SSLV3),
    ("TLSv1", NGX_SSL_TLSV1),
    ("TLSv1.1", NGX_SSL_TLSV1_1),
    ("TLSv1.2", NGX_SSL_TLSV1_2),
    ("TLSv1.3", NGX_SSL_TLSV1_3),
];

static NGX_HTTP_SSL_VERIFY: &[(&str, u32)] = &[("off", 0), ("on", 1), ("optional", 2), ("optional_no_ca", 3)];

static NGX_HTTP_SSL_OCSP: &[(&str, u32)] = &[("off", 0), ("on", 1), ("leaf", 2)];

/// The handlers of the variables (the data of the variables is the index).
static NGX_HTTP_SSL_HANDLERS: &[SslVariableHandler] = &[
    ngx_ssl_get_protocol,
    ngx_ssl_get_cipher_name,
    ngx_ssl_get_ciphers,
    ngx_ssl_get_curve,
    ngx_ssl_get_curves,
    ngx_ssl_get_sigalg,
    ngx_ssl_get_sigalgs,
    ngx_ssl_get_session_id,
    ngx_ssl_get_session_reused,
    ngx_ssl_get_early_data,
    ngx_ssl_get_server_name,
    ngx_ssl_get_alpn_protocol,
    ngx_ssl_get_ech_status,
    ngx_ssl_get_ech_outer_server_name,
    ngx_ssl_get_certificate,
    ngx_ssl_get_raw_certificate,
    ngx_ssl_get_escaped_certificate,
    ngx_ssl_get_subject_dn,
    ngx_ssl_get_issuer_dn,
    ngx_ssl_get_subject_dn_legacy,
    ngx_ssl_get_issuer_dn_legacy,
    ngx_ssl_get_serial_number,
    ngx_ssl_get_fingerprint,
    ngx_ssl_get_client_verify,
    ngx_ssl_get_client_v_start,
    ngx_ssl_get_client_v_end,
    ngx_ssl_get_client_v_remain,
    ngx_ssl_get_client_sigalg,
];

const CH: u32 = NGX_HTTP_VAR_CHANGEABLE;

static NGX_HTTP_SSL_VARS: &[VarDef] = &[
    VarDef { name: "ssl_protocol", set: None, get: Some(ngx_http_ssl_static_variable), data: 0, flags: CH },
    VarDef { name: "ssl_cipher", set: None, get: Some(ngx_http_ssl_static_variable), data: 1, flags: CH },
    VarDef { name: "ssl_ciphers", set: None, get: Some(ngx_http_ssl_variable), data: 2, flags: CH },
    VarDef { name: "ssl_curve", set: None, get: Some(ngx_http_ssl_variable), data: 3, flags: CH },
    VarDef { name: "ssl_curves", set: None, get: Some(ngx_http_ssl_variable), data: 4, flags: CH },
    VarDef { name: "ssl_sigalg", set: None, get: Some(ngx_http_ssl_variable), data: 5, flags: CH },
    VarDef { name: "ssl_sigalgs", set: None, get: Some(ngx_http_ssl_variable), data: 6, flags: CH },
    VarDef { name: "ssl_session_id", set: None, get: Some(ngx_http_ssl_variable), data: 7, flags: CH },
    VarDef { name: "ssl_session_reused", set: None, get: Some(ngx_http_ssl_variable), data: 8, flags: CH },
    VarDef { name: "ssl_early_data", set: None, get: Some(ngx_http_ssl_variable), data: 9, flags: CH | NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "ssl_server_name", set: None, get: Some(ngx_http_ssl_variable), data: 10, flags: CH },
    VarDef { name: "ssl_alpn_protocol", set: None, get: Some(ngx_http_ssl_variable), data: 11, flags: CH },
    VarDef { name: "ssl_ech_status", set: None, get: Some(ngx_http_ssl_variable), data: 12, flags: CH },
    VarDef { name: "ssl_ech_outer_server_name", set: None, get: Some(ngx_http_ssl_variable), data: 13, flags: CH },
    VarDef { name: "ssl_client_cert", set: None, get: Some(ngx_http_ssl_variable), data: 14, flags: CH },
    VarDef { name: "ssl_client_raw_cert", set: None, get: Some(ngx_http_ssl_variable), data: 15, flags: CH },
    VarDef { name: "ssl_client_escaped_cert", set: None, get: Some(ngx_http_ssl_variable), data: 16, flags: CH },
    VarDef { name: "ssl_client_s_dn", set: None, get: Some(ngx_http_ssl_variable), data: 17, flags: CH },
    VarDef { name: "ssl_client_i_dn", set: None, get: Some(ngx_http_ssl_variable), data: 18, flags: CH },
    VarDef { name: "ssl_client_s_dn_legacy", set: None, get: Some(ngx_http_ssl_variable), data: 19, flags: CH },
    VarDef { name: "ssl_client_i_dn_legacy", set: None, get: Some(ngx_http_ssl_variable), data: 20, flags: CH },
    VarDef { name: "ssl_client_serial", set: None, get: Some(ngx_http_ssl_variable), data: 21, flags: CH },
    VarDef { name: "ssl_client_fingerprint", set: None, get: Some(ngx_http_ssl_variable), data: 22, flags: CH },
    VarDef { name: "ssl_client_verify", set: None, get: Some(ngx_http_ssl_variable), data: 23, flags: CH },
    VarDef { name: "ssl_client_v_start", set: None, get: Some(ngx_http_ssl_variable), data: 24, flags: CH },
    VarDef { name: "ssl_client_v_end", set: None, get: Some(ngx_http_ssl_variable), data: 25, flags: CH },
    VarDef { name: "ssl_client_v_remain", set: None, get: Some(ngx_http_ssl_variable), data: 26, flags: CH },
    VarDef { name: "ssl_client_sigalg", set: None, get: Some(ngx_http_ssl_variable), data: 27, flags: CH },
];

const NGX_HTTP_SSL_SESS_ID_CTX: &[u8] = b"HTTP";

/// The srv_conf of the module in a server's slots.
fn sscf_of(slots: &Rc<ConfSlots>) -> Rc<RefCell<HttpSslSrvConf>> {
    slot_of::<HttpSslSrvConf>(slots, ctx_index())
}

/// ngx_http_get_module_srv_conf(conf_ctx, ngx_http_ssl_module)
fn sscf_of_ctx(ctx: &ConfCtx) -> Rc<RefCell<HttpSslSrvConf>> {
    sscf_of(ctx.srv.as_ref().expect("srv conf"))
}

/// c->data of an http connection
fn http_connection_of(c: &Connection) -> Option<Rc<HttpConnection>> {
    let data = c.data.borrow().clone()?;
    data.downcast::<HttpConnection>().ok()
}

// --- ngx_http_ssl_module.c ---

/// ngx_http_ssl_alpn_select
fn ngx_http_ssl_alpn_select<'a>(ssl_conn: &mut SslRef, client: &'a [u8]) -> Result<&'a [u8], AlpnError> {
    let c = ngx_ssl_get_connection(ssl_conn);

    if let Some(c) = c.as_ref() {
        if c.log.debug_enabled(NGX_LOG_DEBUG_HTTP) {
            let mut i = 0;

            while i < client.len() {
                let l = client[i] as usize;
                let end = (i + 1 + l).min(client.len());

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "SSL ALPN supported by client: {}", B(&client[i + 1..end]));

                i += l + 1;
            }
        }
    }

    let hc = c.as_deref().and_then(http_connection_of);

    let srv: &'static [u8] = match hc {
        Some(hc) if hc.addr_conf.quic => {
            let h3scf = crate::v3::module::srv_conf_of(&hc);

            if h3scf.enable && h3scf.enable_hq {
                NGX_HTTP_V3_ALPN_PROTOS
            } else if h3scf.enable_hq {
                crate::v3::NGX_HTTP_V3_HQ_ALPN_PROTO
            } else if h3scf.enable {
                crate::v3::NGX_HTTP_V3_ALPN_PROTO
            } else {
                return Err(AlpnError::ALERT_FATAL);
            }
        }
        Some(hc) if crate::v2::module::srv_enabled(&hc.conf_ctx.borrow()) || hc.addr_conf.http2 => NGX_HTTP_V2_ALPN_PROTOS,
        _ => NGX_HTTP_ALPN_PROTOS,
    };

    // SSL_select_next_proto()
    let out = match openssl::ssl::select_next_proto(srv, client) {
        Some(out) => out,
        None => return Err(AlpnError::ALERT_FATAL),
    };

    if let Some(c) = c.as_ref() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "SSL ALPN selected: {}", B(out));
    }

    Ok(out)
}

/// ngx_http_ssl_static_variable: the value of a handler returning a static
/// string
fn ngx_http_ssl_static_variable(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    let handler = NGX_HTTP_SSL_HANDLERS[data];

    if r.connection.ssl.borrow().is_some() {
        let mut s = Vec::new();

        let _ = handler(&r.connection, &mut s);

        let len = s.iter().position(|&ch| ch == 0).unwrap_or(s.len());
        s.truncate(len);

        v.data = s;
        v.valid = true;
        v.no_cacheable = false;
        v.not_found = false;

        return NGX_OK;
    }

    v.not_found = true;

    NGX_OK
}

/// ngx_http_ssl_variable
fn ngx_http_ssl_variable(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    let handler = NGX_HTTP_SSL_HANDLERS[data];

    if r.connection.ssl.borrow().is_some() {
        let mut s = Vec::new();

        if handler(&r.connection, &mut s) != NGX_OK {
            return NGX_ERROR;
        }

        if !s.is_empty() {
            v.data = s;
            v.valid = true;
            v.no_cacheable = false;
            v.not_found = false;

            return NGX_OK;
        }
    }

    v.not_found = true;

    NGX_OK
}

/// ngx_http_ssl_add_variables
fn ngx_http_ssl_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, NGX_HTTP_SSL_VARS)
}

/// ngx_http_ssl_create_srv_conf
fn ngx_http_ssl_create_srv_conf(cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(HttpSslSrvConf {
        prefer_server_ciphers: Val::unset(),
        certificate_compression: Val::unset(),
        early_data: Val::unset(),
        reject_handshake: Val::unset(),
        ssl: NgxSsl::new(cf.log.clone()),
        protocols: 0,
        verify: Val::unset(),
        verify_depth: Val::unset(),
        buffer_size: Val::unset(),
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

static NGX_HTTP_SSL_CLIENT_HELLO_ARG: SslClientHelloArg = SslClientHelloArg { servername: ngx_http_ssl_servername };

/// ngx_http_ssl_merge_srv_conf
fn ngx_http_ssl_merge_srv_conf(cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev_rc = conf_rc::<HttpSslSrvConf>(parent);
    let conf_rc = conf_rc::<HttpSslSrvConf>(child);

    let conf_any: Rc<dyn Any> = conf_rc.clone();

    let prev = prev_rc.borrow();
    let mut conf_ref = conf_rc.borrow_mut();
    let conf = &mut *conf_ref;

    conf.session_timeout.merge(&prev.session_timeout, 300);

    conf.prefer_server_ciphers.merge(&prev.prefer_server_ciphers, false);

    conf.certificate_compression.merge(&prev.certificate_compression, false);

    conf.early_data.merge(&prev.early_data, false);
    conf.reject_handshake.merge(&prev.reject_handshake, false);

    if conf.protocols == 0 {
        conf.protocols = if prev.protocols == 0 { NGX_CONF_BITMASK_SET | NGX_SSL_DEFAULT_PROTOCOLS } else { prev.protocols };
    }

    conf.buffer_size.merge(&prev.buffer_size, NGX_SSL_BUFSIZE);

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

    // the cleanup of the context (ngx_ssl_cleanup_ctx) is the drop of conf.ssl

    if ngx_ssl_set_client_hello_callback(&mut conf.ssl, &NGX_HTTP_SSL_CLIENT_HELLO_ARG) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if !ngx_ssl_set_servername_callback(&mut conf.ssl, ngx_http_ssl_servername) {
        ngx_log_error!(
            NGX_LOG_WARN,
            cf.log,
            None,
            "nginx was built with SNI support, however, now it is linked dynamically to an OpenSSL library which has no tlsext support, therefore SNI is not available"
        );
    }

    if let Some(ctx) = conf.ssl.ctx.builder_mut() {
        ctx.set_alpn_select_callback(ngx_http_ssl_alpn_select);
    }

    if ngx_ssl_ciphers(cf, &mut conf.ssl, &conf.ciphers, *conf.prefer_server_ciphers) != NGX_OK {
        return Err(ConfError::Logged);
    }

    ngx_http_ssl_compile_certificates(cf, conf)?;

    if conf.certificate_values.is_some() {
        /* install callback to lookup certificates */

        ngx_ssl_set_cert_callback(&mut conf.ssl, ngx_http_ssl_certificate);
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

    conf.ssl.buffer_size = *conf.buffer_size;

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

    if ngx_ssl_session_cache(&mut conf.ssl, NGX_HTTP_SSL_SESS_ID_CTX, conf.certificates.as_option(), *conf.builtin_session_cache, shm_zone.as_ref(), *conf.session_timeout) != NGX_OK {
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

    if ngx_ssl_early_data(cf, &mut conf.ssl, *conf.early_data) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if ngx_ssl_conf_commands(cf, &mut conf.ssl, conf.conf_commands.0.as_mut().unwrap().as_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    Ok(())
}

/// ngx_http_ssl_compile_certificates: the certificates with variables
fn ngx_http_ssl_compile_certificates(cf: &mut Conf, conf: &mut HttpSslSrvConf) -> ConfResult {
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
        cert_values.push(compile_complex_value(cf, &certs[i], NGX_HTTP_COMPLEX_VALUE_ZERO)?);

        key_values.push(compile_complex_value(cf, &keys[i], NGX_HTTP_COMPLEX_VALUE_ZERO)?);
    }

    conf.certificate_values = Some(cert_values);
    conf.certificate_key_values = Some(key_values);

    let passwords = conf.passwords.as_option().cloned().flatten();

    conf.passwords = Val::set(Some(ngx_ssl_preserve_passwords(cf, passwords.as_ref())));

    Ok(())
}

/// ngx_http_ssl_certificate_cache
fn ngx_http_ssl_certificate_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<HttpSslSrvConf>(conf.as_ref().expect("conf"));

    if sscf.borrow().certificate_cache.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let mut max: i64 = 0;
    let mut inactive: i64 = 10;
    let mut valid: i64 = 60;

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
            sscf.borrow_mut().certificate_cache = Val::set(None);
            true
        } else {
            false
        };

        if !ok {
            // failed:
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(v))));
        }
    }

    if sscf.borrow().certificate_cache.is_set() {
        // "off"
        return Ok(());
    }

    if max == 0 {
        return Err(cf.emerg(format_args!("\"ssl_certificate_cache\" must have the \"max\" parameter")));
    }

    let cache = ngx_ssl_cache_init(max as usize, valid, inactive);

    sscf.borrow_mut().certificate_cache = Val::set(Some(Rc::new(RefCell::new(cache))));

    Ok(())
}

/// ngx_http_ssl_password_file
fn ngx_http_ssl_password_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<HttpSslSrvConf>(conf.as_ref().expect("conf"));

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
/// (an empty name when the value is invalid)
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

/// ngx_http_ssl_session_cache
fn ngx_http_ssl_session_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<HttpSslSrvConf>(conf.as_ref().expect("conf"));

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

            let zone = ngx_core::cycle::shared_memory_add(cf, &name, n, "ngx_http_ssl_module")?;

            zone.safe_pool.set(true);
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

/// ngx_http_ssl_ocsp_cache
fn ngx_http_ssl_ocsp_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<HttpSslSrvConf>(conf.as_ref().expect("conf"));

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

    let zone = ngx_core::cycle::shared_memory_add(cf, &name, n, "ngx_http_ssl_module_ctx")?;

    zone.safe_pool.set(true);
    *zone.init.borrow_mut() = Some(Rc::new(ngx_ssl_ocsp_cache_init));

    sscf.borrow_mut().ocsp_cache_zone = Val::set(Some(zone));

    Ok(())
}

/// ssl_conf_command: ngx_conf_set_keyval_slot with
/// ngx_http_ssl_conf_command_check (SSL_CONF_cmd() is available)
fn ngx_http_ssl_conf_command(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<HttpSslSrvConf>(conf.as_ref().expect("conf"));

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

fn ngx_http_ssl_ech_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<HttpSslSrvConf>(conf.as_ref().expect("conf"));
    let mut c = sscf.borrow_mut();
    set_array(cf, &mut c.ech_files)
}

fn ngx_http_ssl_session_ticket_key(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<HttpSslSrvConf>(conf.as_ref().expect("conf"));
    let mut c = sscf.borrow_mut();
    set_array(cf, &mut c.session_ticket_keys)
}

fn ngx_http_ssl_protocols(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let sscf = conf_rc::<HttpSslSrvConf>(conf.as_ref().expect("conf"));
    let mut c = sscf.borrow_mut();
    set_bitmask(cf, cmd, &mut c.protocols, NGX_HTTP_SSL_PROTOCOLS)
}

/// ngx_http_ssl_init: the resolvers of OCSP and stapling, the certificates
/// of "listen ... ssl"
fn ngx_http_ssl_init(cf: &mut Conf) -> ConfResult {
    let cmcf = core_main_conf(cf);

    let servers = cmcf.borrow().servers.clone();

    for cscf in servers.iter() {
        let ctx = cscf.borrow().ctx.clone();

        let sscf = sscf_of_ctx(&ctx);

        if sscf.borrow().ssl.ctx.is_null() {
            continue;
        }

        let clcf = loc_conf_from_ctx(&ctx);

        let (resolver, resolver_timeout) = {
            let l = clcf.borrow();
            (l.resolver.clone(), *l.resolver_timeout)
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

    let m = cmcf.borrow();

    // NGX_QUIC_OPENSSL_COMPAT

    let compat = m.ports.iter().any(|port| port.addrs.iter().any(|addr| addr.opt.quic));

    for port in m.ports.iter() {
        for addr in port.addrs.iter() {
            if !addr.opt.ssl && !addr.opt.quic {
                continue;
            }

            if compat {
                ngx_http_ssl_quic_compat_init(cf, addr)?;
            }

            let name = if addr.opt.quic { "quic" } else { "ssl" };

            let cscf = addr.default_server.clone();
            let sscf = sscf_of_ctx(&cscf.borrow().ctx);

            if sscf.borrow().certificates.is_set() {
                if addr.opt.quic && sscf.borrow().protocols & NGX_SSL_TLSV1_3 == 0 {
                    let c = cscf.borrow();
                    ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "\"ssl_protocols\" must enable TLSv1.3 for the \"listen ... {}\" directive in {}:{}", name, B(&c.file_name), c.line);
                    return Err(ConfError::Logged);
                }

                continue;
            }

            if !*sscf.borrow().reject_handshake {
                let c = cscf.borrow();
                ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"ssl_certificate\" is defined for the \"listen ... {}\" directive in {}:{}", name, B(&c.file_name), c.line);
                return Err(ConfError::Logged);
            }

            /*
             * if no certificates are defined in the default server,
             * check all non-default server blocks
             */

            for cscf in addr.servers.iter() {
                let sscf = sscf_of_ctx(&cscf.borrow().ctx);

                let s = sscf.borrow();

                if s.certificates.is_set() || *s.reject_handshake {
                    continue;
                }

                let c = cscf.borrow();
                ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"ssl_certificate\" is defined for the \"listen ... {}\" directive in {}:{}", name, B(&c.file_name), c.line);
                return Err(ConfError::Logged);
            }
        }
    }

    Ok(())
}

/// ngx_http_ssl_quic_compat_init
fn ngx_http_ssl_quic_compat_init(cf: &mut Conf, addr: &crate::core::ConfAddr) -> ConfResult {
    for cscf in addr.servers.iter() {
        let sscf = sscf_of_ctx(&cscf.borrow().ctx);

        let (certificates, reject_handshake) = {
            let s = sscf.borrow();
            (s.certificates.is_set(), s.reject_handshake.as_option().copied().unwrap_or(false))
        };

        if certificates || reject_handshake {
            let mut s = sscf.borrow_mut();

            if ngx_core::quic::openssl_compat::ngx_quic_compat_ext_init(&cf.log, &mut s.ssl) != NGX_OK {
                return Err(ConfError::Logged);
            }

            if addr.opt.quic {
                ngx_core::quic::openssl_compat::ngx_quic_compat_keylog_init(&mut s.ssl);
            }
        }
    }

    Ok(())
}

pub fn ssl_module() -> ModuleDef {
    const CONF: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF;

    let def = HttpModuleDef {
        preconfiguration: Some(ngx_http_ssl_add_variables),
        postconfiguration: Some(ngx_http_ssl_init),
        create_srv_conf: Some(ngx_http_ssl_create_srv_conf),
        merge_srv_conf: Some(ngx_http_ssl_merge_srv_conf),
        ..Default::default()
    };

    http_module_def(
        "ngx_http_ssl_module",
        def,
        vec![
            cmd!("ssl_certificate", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, certificates, set_str_array),
            cmd!("ssl_certificate_key", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, certificate_keys, set_str_array),
            cmd_fn!("ssl_certificate_cache", CONF | NGX_CONF_TAKE123, ConfLevel::Srv, ngx_http_ssl_certificate_cache),
            cmd_fn!("ssl_ech_file", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ngx_http_ssl_ech_file),
            cmd_fn!("ssl_password_file", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ngx_http_ssl_password_file),
            cmd!("ssl_certificate_compression", CONF | NGX_CONF_FLAG, ConfLevel::Srv, HttpSslSrvConf, certificate_compression, set_flag),
            cmd!("ssl_dhparam", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, dhparam, set_str),
            cmd!("ssl_ecdh_curve", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, ecdh_curve, set_str),
            cmd_fn!("ssl_protocols", CONF | NGX_CONF_1MORE, ConfLevel::Srv, ngx_http_ssl_protocols),
            cmd!("ssl_ciphers", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, ciphers, set_str),
            cmd!("ssl_buffer_size", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, buffer_size, set_size),
            cmd!("ssl_verify_client", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, verify, set_enum, NGX_HTTP_SSL_VERIFY),
            cmd!("ssl_verify_depth", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, verify_depth, set_num),
            cmd!("ssl_client_certificate", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, client_certificate, set_str),
            cmd!("ssl_trusted_certificate", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, trusted_certificate, set_str),
            cmd!("ssl_prefer_server_ciphers", CONF | NGX_CONF_FLAG, ConfLevel::Srv, HttpSslSrvConf, prefer_server_ciphers, set_flag),
            cmd_fn!("ssl_session_cache", CONF | NGX_CONF_TAKE12, ConfLevel::Srv, ngx_http_ssl_session_cache),
            cmd!("ssl_session_tickets", CONF | NGX_CONF_FLAG, ConfLevel::Srv, HttpSslSrvConf, session_tickets, set_flag),
            cmd_fn!("ssl_session_ticket_key", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ngx_http_ssl_session_ticket_key),
            cmd!("ssl_session_timeout", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, session_timeout, set_sec),
            cmd!("ssl_crl", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, crl, set_str),
            cmd!("ssl_ocsp", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, ocsp, set_enum, NGX_HTTP_SSL_OCSP),
            cmd!("ssl_ocsp_responder", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, ocsp_responder, set_str),
            cmd_fn!("ssl_ocsp_cache", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ngx_http_ssl_ocsp_cache),
            cmd!("ssl_stapling", CONF | NGX_CONF_FLAG, ConfLevel::Srv, HttpSslSrvConf, stapling, set_flag),
            cmd!("ssl_stapling_file", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, stapling_file, set_str),
            cmd!("ssl_stapling_responder", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, HttpSslSrvConf, stapling_responder, set_str),
            cmd!("ssl_stapling_verify", CONF | NGX_CONF_FLAG, ConfLevel::Srv, HttpSslSrvConf, stapling_verify, set_flag),
            cmd!("ssl_early_data", CONF | NGX_CONF_FLAG, ConfLevel::Srv, HttpSslSrvConf, early_data, set_flag),
            cmd_fn!("ssl_conf_command", CONF | NGX_CONF_TAKE2, ConfLevel::Srv, ngx_http_ssl_conf_command),
            cmd!("ssl_reject_handshake", CONF | NGX_CONF_FLAG, ConfLevel::Srv, HttpSslSrvConf, reject_handshake, set_flag),
        ],
    )
}

// --- the TLS parts of ngx_http_request.c ---

/// What the connection does after ngx_http_ssl_handshake() and
/// ngx_http_ssl_handshake_handler().
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SslHandshakeNext {
    /// ngx_http_close_connection()
    Close,
    /// ngx_http_wait_request_handler(): plain HTTP sent to the SSL port, or
    /// HTTP/1.x over TLS
    WaitRequest,
    /// ngx_http_v2_init(): "h2" was selected by ALPN
    Http2,
}

/// ngx_http_ssl_handshake: the first byte of a connection to a
/// "listen ... ssl" socket (after the PROXY protocol header): a TLS
/// handshake, which is run, or plain HTTP.  The read timer of
/// ngx_http_init_connection() (client_header_timeout of the default server)
/// bounds the whole of it.
pub async fn ngx_http_ssl_handshake(c: &Rc<Connection>, hc: &Rc<HttpConnection>) -> SslHandshakeNext {
    let timeout = {
        let cscf = srv_conf_from_ctx(&hc.conf_ctx.borrow());
        let t = *cscf.borrow().client_header_timeout;
        t
    };

    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout);

    c.set_reusable(true);

    loop {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http check ssl handshake");

        let size = if hc.proxy_protocol.get() { ngx_core::proxy_protocol::NGX_PROXY_PROTOCOL_MAX_HEADER + 1 } else { 1 };
        let mut buf = vec![0u8; size];

        let res = tokio::select! {
            r = tokio::time::timeout_at(deadline, c.peek(&mut buf)) => r,
            // c->close
            _ = c.close_notify.notified() => return SslHandshakeNext::Close,
        };

        let mut n = match res {
            Err(_) => {
                ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
                return SslHandshakeNext::Close;
            }
            Ok(Err(e)) => {
                c.connection_error(e.raw_os_error().unwrap_or(0), "recv() failed");
                return SslHandshakeNext::Close;
            }
            Ok(Ok(n)) => n,
        };

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http recv(): {}", n);

        let mut first = buf[0];

        if hc.proxy_protocol.get() {
            hc.proxy_protocol.set(false);

            let (pp, size) = match ngx_core::proxy_protocol::read(&c.log, &buf[..n]) {
                Ok(v) => v,
                Err(()) => return SslHandshakeNext::Close,
            };

            if let Some(pp) = pp {
                *c.proxy_protocol.borrow_mut() = Some(Rc::new(pp));
            }

            // the header is in the socket buffer already
            let mut hdr = vec![0u8; size];

            match c.recv(&mut hdr).await {
                Ok(m) if m == size => {}
                _ => return SslHandshakeNext::Close,
            }

            c.log.set_action(Some("SSL handshaking"));

            if n == size {
                // ngx_post_event(rev, &ngx_posted_events)
                continue;
            }

            n = 1;
            first = buf[size];
        }

        if n == 1 {
            if first & 0x80 != 0 /* SSLv2 */ || first == 0x16
            /* SSLv3/TLSv1 */
            {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "https ssl handshake: 0x{:02X}", first);

                let tcp_nodelay = {
                    let clcf = loc_conf_from_ctx(&hc.conf_ctx.borrow());
                    let v = *clcf.borrow().tcp_nodelay;
                    v
                };

                if tcp_nodelay && !c.set_tcp_nodelay() {
                    return SslHandshakeNext::Close;
                }

                {
                    let sscf = sscf_of_ctx(&hc.conf_ctx.borrow());
                    let sscf = sscf.borrow();

                    if ngx_ssl_create_connection(&sscf.ssl, c, NGX_SSL_BUFFER) != NGX_OK {
                        return SslHandshakeNext::Close;
                    }
                }

                c.set_reusable(false);

                // no configuration is borrowed during the handshake: the
                // callbacks change the server of the connection

                let rc = ngx_ssl_handshake(c);

                let mut timedout = false;

                if rc == NGX_AGAIN {
                    // c->ssl->handler = ngx_http_ssl_handshake_handler, on
                    // the read timer

                    if tokio::time::timeout_at(deadline, ngx_ssl_handshake_wait(c)).await.is_err() {
                        timedout = true;
                    }
                }

                return ngx_http_ssl_handshake_handler(c, hc, timedout);
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "plain http");

            c.log.set_action(Some("waiting for request"));

            return SslHandshakeNext::WaitRequest;
        }

        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client closed connection");

        return SslHandshakeNext::Close;
    }
}

/// ngx_http_ssl_handshake_handler
fn ngx_http_ssl_handshake_handler(c: &Rc<Connection>, hc: &Rc<HttpConnection>, timedout: bool) -> SslHandshakeNext {
    let sc = c.ssl.borrow().clone();

    if let Some(sc) = sc.filter(|sc| sc.handshaked.get()) {
        /*
         * The majority of browsers do not send the "close notify" alert.
         * Among them are MSIE, old Mozilla, Netscape 4, Konqueror,
         * and Links.  And what is more, MSIE ignores the server's alert.
         *
         * Opera and recent Mozilla send the alert.
         */

        sc.no_wait_shutdown.set(true);

        let h2 = crate::v2::module::srv_enabled(&hc.conf_ctx.borrow()) || hc.addr_conf.http2;

        if h2 && sc.with(|ssl| ssl.selected_alpn_protocol() == Some(&b"h2"[..])).unwrap_or(false) {
            return SslHandshakeNext::Http2;
        }

        c.log.set_action(Some("waiting for request"));

        c.set_reusable(true);

        return SslHandshakeNext::WaitRequest;
    }

    if timedout {
        ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
    }

    SslHandshakeNext::Close
}

/// ngx_http_find_virtual_server() without a request (from the servername
/// callback): a server found by a regex is remembered in
/// hc->ssl_servername_regex; NGX_DECLINED when there is none
fn ngx_http_find_virtual_server_ssl(c: &Connection, hc: &HttpConnection, host: &[u8]) -> Result<Rc<RefCell<CoreSrvConf>>, i64> {
    let vn = match hc.addr_conf.virtual_names.as_ref() {
        Some(v) => v,
        None => return Err(NGX_DECLINED),
    };

    if let Some(cscf) = vn.names.find(ngx_core::hash::hash_key(host), host) {
        return Ok(cscf.clone());
    }

    if !host.is_empty() && !vn.regex.is_empty() {
        for sn in vn.regex.iter() {
            match sn.regex.regex.re.is_match(host) {
                Ok(false) => continue,
                Ok(true) => {
                    *hc.ssl_servername_regex.borrow_mut() = Some(sn.regex.clone());

                    return Ok(sn.server.clone());
                }
                Err(e) => {
                    ngx_log_error!(NGX_LOG_ALERT, c.log, None, "pcre2_match() failed: {} on \"{}\" using \"{}\"", e, B(host), B(&sn.regex.name));

                    return Err(NGX_ERROR);
                }
            }
        }
    }

    Err(NGX_DECLINED)
}

/// ngx_http_ssl_servername: the server of the connection by the server name
/// (from ngx_ssl_client_hello_callback() with the name, or as the tlsext
/// servername callback)
fn ngx_http_ssl_servername(c: &Rc<Connection>, ssl_conn: &mut SslRef, ad: &mut i32, arg: SniArg<'_>) -> i32 {
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

    let hc = match http_connection_of(c) {
        Some(hc) => hc,
        None => {
            *ad = sys::SSL_AD_INTERNAL_ERROR;
            return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    };

    let error = 'done: {
        let host: Vec<u8> = match arg {
            SniArg::Hello(Some(h)) => h.to_vec(),

            SniArg::Hello(None) => {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "SSL server name: null");
                break 'done false;
            }

            SniArg::Callback => match ssl_conn.servername_raw(NameType::HOST_NAME) {
                Some(name) => name.to_vec(),
                None => {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "SSL server name: null");
                    break 'done false;
                }
            },
        };

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "SSL server name: \"{}\"", B(&host));

        if host.is_empty() {
            break 'done false;
        }

        // ngx_http_validate_host(): NGX_DECLINED on an invalid name
        let host = match crate::request_rt::validate_host(&host, true) {
            Ok((h, _)) => h,
            Err(()) => break 'done false,
        };

        let cscf = match ngx_http_find_virtual_server_ssl(c, &hc, &host) {
            Ok(cscf) => cscf,
            Err(rc) if rc == NGX_DECLINED => break 'done false,
            Err(_) => break 'done true,
        };

        *hc.ssl_servername.borrow_mut() = Some(host);

        let ctx = cscf.borrow().ctx.clone();

        *hc.conf_ctx.borrow_mut() = ctx.clone();

        let clcf = loc_conf_from_ctx(&ctx);

        if let Some(chain) = clcf.borrow().error_log.clone() {
            c.log.set_chain(chain);
        }

        let sscf = sscf_of_ctx(&ctx);

        let (buffer_size, sctx) = {
            let s = sscf.borrow();
            (s.buffer_size.as_option().copied().unwrap_or(NGX_SSL_BUFSIZE), s.ssl.ctx.get())
        };

        sc.buffer_size.set(buffer_size);

        if let Some(sctx) = sctx {
            /*
             * SSL_set_SSL_CTX() only changes certs as of 1.0.0d
             * adjust other things we care about
             */

            if !ngx_ssl_set_ssl_ctx(ssl_conn, &sctx) {
                break 'done true;
            }

            if c.listening().is_some_and(|ls| ls.quic.get()) {
                sys::clear_options(ssl_conn, sys::SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
            }
        }

        false
    };

    if error {
        *ad = sys::SSL_AD_INTERNAL_ERROR;
        return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    // done:

    let reject = {
        let sscf = sscf_of_ctx(&hc.conf_ctx.borrow());
        let r = sscf.borrow().reject_handshake.as_option().copied().unwrap_or(false);
        r
    };

    if reject {
        sc.state.handshake_rejected.set(true);
        *ad = sys::SSL_AD_UNRECOGNIZED_NAME;
        return sys::SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    sc.state.sni_accepted.set(true);

    sys::SSL_TLSEXT_ERR_OK
}

/// ngx_http_ssl_certificate: the certificate callback loading the
/// certificates with variables, evaluated in a request made for it; conf
/// is the configuration of the server of the context
fn ngx_http_ssl_certificate(c: &Rc<Connection>, ssl_conn: &mut SslRef, conf: Option<Rc<dyn Any>>) -> i32 {
    let handshaked = c.ssl.borrow().as_ref().map(|sc| sc.handshaked.get()).unwrap_or(true);

    if handshaked {
        return 0;
    }

    // r = ngx_http_alloc_request(c)

    let hc = match http_connection_of(c) {
        Some(hc) => hc,
        None => return 0,
    };

    let sscf = match conf.and_then(|conf| conf.downcast::<RefCell<HttpSslSrvConf>>().ok()) {
        Some(s) => s,
        None => return 0,
    };

    let log_ctx = Rc::new(HttpLogCtx { connection: Rc::downgrade(c), request: RefCell::new(None), current_request: RefCell::new(None) });

    let r = alloc_request(c, &hc, &log_ctx);

    r.logged.set(true);

    let (certs, keys, cache, passwords) = {
        let sscf = sscf.borrow();
        (
            sscf.certificate_values.clone().unwrap_or_default(),
            sscf.certificate_key_values.clone().unwrap_or_default(),
            sscf.certificate_cache.as_option().cloned().flatten(),
            sscf.passwords.as_option().cloned().flatten(),
        )
    };

    let mut rc = 1;

    for i in 0..certs.len() {
        // the variables read the SSL object of the connection, which the
        // callback has
        let mut cert = match sys::with_current(ssl_conn, || complex_value(&r, &certs[i])) {
            Ok(v) => v,
            Err(_) => {
                rc = 0;
                break;
            }
        };

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "ssl cert: \"{}\"", B(&cert));

        let mut key = match sys::with_current(ssl_conn, || complex_value(&r, &keys[i])) {
            Ok(v) => v,
            Err(_) => {
                rc = 0;
                break;
            }
        };

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "ssl key: \"{}\"", B(&key));

        if ngx_ssl_connection_certificate_ssl(c, ssl_conn, &mut cert, &mut key, cache.as_ref(), passwords.as_ref()) != NGX_OK {
            rc = 0;
            break;
        }
    }

    crate::request_rt::free_request(&r, 0);
    c.log.set_action(Some("SSL handshaking"));
    c.destroyed.set(false);

    rc
}

/// ngx_ssl_remove_cached_session(c->ssl->session_ctx, SSL_get0_session())
fn remove_cached_session(c: &Connection) {
    ngx_ssl_remove_cached_session(c);
}

/// The SSL checks of ngx_http_process_request(): NGX_OK, or the status the
/// request is to be finalized with.
pub fn ngx_http_process_request_ssl(r: &R) -> i64 {
    if !r.http_connection.ssl.get() {
        return NGX_OK;
    }

    let c = &r.connection;

    if c.ssl.borrow().is_none() {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent plain HTTP request to HTTPS port");
        return NGX_HTTP_TO_HTTPS;
    }

    let verify = {
        let sscf = r.srv_conf::<HttpSslSrvConf>(ctx_index());
        let v = sscf.borrow().verify.as_option().copied().unwrap_or(0);
        v
    };

    if verify != 0 {
        let rc = ngx_ssl_get_verify_result(c);

        if rc != X509_V_OK && (verify != 3 || !ngx_ssl_verify_error_optional(rc)) {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client SSL certificate verify error: ({}:{})", rc, B(&ngx_ssl_verify_error_string(rc)));

            remove_cached_session(c);

            return NGX_HTTPS_CERT_ERROR;
        }

        if verify == 1 && ngx_ssl_with(c, |ssl| ssl.peer_certificate().is_none()).unwrap_or(true) {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent no required SSL certificate");

            remove_cached_session(c);

            return NGX_HTTPS_NO_CERT;
        }

        if let Err(s) = ngx_ssl_ocsp_get_status(c) {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client SSL certificate verify error: {}", s);

            remove_cached_session(c);

            return NGX_HTTPS_CERT_ERROR;
        }
    }

    NGX_OK
}

/// sscf->verify of a server, as ngx_http_set_virtual_server() checks it
/// when the name of the request differs from the one negotiated by SNI.
pub fn ngx_http_ssl_verify_enabled(cscf: &Rc<RefCell<CoreSrvConf>>) -> bool {
    let sscf = sscf_of_ctx(&cscf.borrow().ctx);
    let v = sscf.borrow().verify.as_option().copied().unwrap_or(0);
    v != 0
}

/// The SSL part of ngx_http_close_connection(): false when the connection
/// is closed later, after ngx_ssl_shutdown() completes (c->ssl->handler =
/// ngx_http_close_connection).
pub fn ngx_http_ssl_close_connection(c: &Rc<Connection>, close: fn(&Rc<Connection>)) -> bool {
    if c.ssl.borrow().is_some() && ngx_ssl_shutdown(c) == NGX_AGAIN {
        let c = c.clone();

        ngx_core::event::spawn(async move {
            ngx_ssl_shutdown_wait(&c).await;
            close(&c);
        });

        return false;
    }

    true
}

/// The SSL shutdown of ngx_http_set_lingering_close() and
/// ngx_http_v2_lingering_close(): c->ssl is kept (shutdown_without_free)
/// for the variables of the log; NGX_ERROR closes the connection.
pub async fn ngx_http_ssl_lingering_shutdown(c: &Connection) -> i64 {
    loop {
        let sc = match c.ssl.borrow().clone() {
            Some(sc) => sc,
            None => return NGX_OK,
        };

        sc.shutdown_without_free.set(true);

        let rc = ngx_ssl_shutdown(c);

        if rc == NGX_ERROR {
            return NGX_ERROR;
        }

        if rc == NGX_AGAIN {
            // c->ssl->handler = ngx_http_set_lingering_close: called again
            // once the shutdown is done
            ngx_ssl_shutdown_wait(c).await;
            continue;
        }

        return NGX_OK;
    }
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
        assert_eq!(NGX_HTTP_SSL_HANDLERS.len(), NGX_HTTP_SSL_VARS.len());
        for (i, v) in NGX_HTTP_SSL_VARS.iter().enumerate() {
            assert_eq!(v.data, i);
        }
    }

    #[test]
    fn alpn_protocols() {
        // NGX_HTTP_V2_ALPN_PROTO NGX_HTTP_ALPN_PROTOS
        assert!(NGX_HTTP_V2_ALPN_PROTOS.starts_with(crate::v2::NGX_HTTP_V2_ALPN_PROTO));
        assert_eq!(&NGX_HTTP_V2_ALPN_PROTOS[crate::v2::NGX_HTTP_V2_ALPN_PROTO.len()..], NGX_HTTP_ALPN_PROTOS);
    }
}
