//! ngx_http_v3_module (nginx-c/src/http/v3/ngx_http_v3_module.c): the
//! directives, the QUIC configuration of the servers, $http3.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use openssl::rand::rand_bytes;

use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::quic::protection::ngx_quic_derive_key;
use ngx_core::quic::{QuicConf, NGX_QUIC_AV_KEY_LEN, NGX_QUIC_DEFAULT_HOST_KEY_LEN, NGX_QUIC_SR_KEY_LEN};
use ngx_core::rc::*;
use ngx_core::string::B;

use super::*;
use crate::request::{HttpConnection, VariableValue, R};
use crate::*;

crate::http_module_index!("ngx_http_v3_module");

/// ngx_http_quic_salt
const NGX_HTTP_QUIC_SALT: &[u8] = b"ngx_quic";

/// ngx_http_v3_srv_conf_t; `quic` is the ngx_quic_conf_t made at merge
pub struct H3SrvConf {
    pub enable: Val<bool>,
    pub enable_hq: Val<bool>,
    pub max_table_capacity: usize,
    pub max_blocked_streams: usize,
    pub max_concurrent_streams: Val<i64>,

    pub stream_buffer_size: Val<usize>,
    pub retry: Val<bool>,
    pub gso_enabled: Val<bool>,
    pub host_key: Option<Vec<u8>>,
    pub active_connection_id_limit: Val<i64>,

    pub quic: Option<Rc<QuicConf>>,
}

/// What the connections use of ngx_http_v3_srv_conf_t.
#[derive(Clone)]
pub struct H3Conf {
    pub enable: bool,
    pub enable_hq: bool,
    pub max_table_capacity: usize,
    pub max_blocked_streams: usize,
    pub max_concurrent_streams: i64,
    pub quic: Option<Rc<QuicConf>>,
}

fn snapshot(h3scf: &Rc<RefCell<H3SrvConf>>) -> H3Conf {
    let s = h3scf.borrow();

    H3Conf {
        enable: s.enable.as_option().copied().unwrap_or(true),
        enable_hq: s.enable_hq.as_option().copied().unwrap_or(false),
        max_table_capacity: s.max_table_capacity,
        max_blocked_streams: s.max_blocked_streams,
        max_concurrent_streams: s.max_concurrent_streams.as_option().copied().unwrap_or(128),
        quic: s.quic.clone(),
    }
}

/// ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v3_module)
pub fn srv_conf_of(hc: &HttpConnection) -> H3Conf {
    let ctx = hc.conf_ctx.borrow();
    let slots = ctx.srv.as_ref().expect("srv conf");

    snapshot(&slot_of::<H3SrvConf>(slots, ctx_index()))
}

/// ngx_http_get_module_srv_conf(r, ngx_http_v3_module)
pub fn srv_conf_of_request(r: &R) -> H3Conf {
    let slots = r.srv_conf.borrow().clone();

    snapshot(&slot_of::<H3SrvConf>(&slots, ctx_index()))
}

/// ngx_http_v3_add_variables
fn add_variables(cf: &mut Conf) -> ConfResult {
    use crate::variables::{add_variables, VarDef};

    add_variables(cf, &[VarDef { name: "http3", set: None, get: Some(variable), data: 0, flags: 0 }])
}

/// ngx_http_v3_variable
fn variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    if r.connection.is_quic_stream() {
        let hq = get_session(&r.connection).is_some_and(|h3c| h3c.hq.get());

        v.data = if hq { b"hq".to_vec() } else { b"h3".to_vec() };
        v.valid = true;
        v.no_cacheable = false;
        v.not_found = false;

        return NGX_OK;
    }

    // ngx_http_variable_null_value
    *v = VariableValue { valid: true, ..Default::default() };

    NGX_OK
}

/// ngx_http_v3_create_srv_conf
fn create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    // set by ngx_pcalloc():
    //
    //     h3scf->quic.host_key = { 0, NULL }
    //     h3scf->quic.stream_reject_code_uni = 0;
    //     h3scf->quic.disable_active_migration = 0;
    //     h3scf->quic.idle_timeout = 0;
    //     h3scf->max_blocked_streams = 0;

    make_slot(H3SrvConf {
        enable: Val::unset(),
        enable_hq: Val::unset(),
        max_table_capacity: NGX_HTTP_V3_MAX_TABLE_CAPACITY,
        max_blocked_streams: 0,
        max_concurrent_streams: Val::unset(),
        stream_buffer_size: Val::unset(),
        retry: Val::unset(),
        gso_enabled: Val::unset(),
        host_key: None,
        active_connection_id_limit: Val::unset(),
        quic: None,
    })
}

/// ngx_http_v3_merge_srv_conf
fn merge_srv_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<H3SrvConf>(prev).borrow();
    let mut c = conf_cell::<H3SrvConf>(conf).borrow_mut();

    c.enable.merge(&p.enable, true);

    c.enable_hq.merge(&p.enable_hq, false);

    c.max_concurrent_streams.merge(&p.max_concurrent_streams, 128);

    c.max_blocked_streams = *c.max_concurrent_streams as usize;

    c.stream_buffer_size.merge(&p.stream_buffer_size, 65536);

    c.retry.merge(&p.retry, false);
    c.gso_enabled.merge(&p.gso_enabled, false);

    if c.host_key.is_none() {
        c.host_key = p.host_key.clone();
    }

    c.active_connection_id_limit.merge(&p.active_connection_id_limit, 2);

    let host_key = match c.host_key.clone() {
        Some(k) if !k.is_empty() => k,
        _ => {
            let mut k = vec![0u8; NGX_QUIC_DEFAULT_HOST_KEY_LEN];

            if let Err(e) = rand_bytes(&mut k) {
                /* the C leaves the errors on OpenSSL's queue */
                e.put();
                return Err(ConfError::Logged);
            }

            k
        }
    };

    let mut av_token_key = [0u8; NGX_QUIC_AV_KEY_LEN];
    let mut sr_token_key = [0u8; NGX_QUIC_SR_KEY_LEN];

    if ngx_quic_derive_key(&cf.log, "av_token_key", &host_key, NGX_HTTP_QUIC_SALT, &mut av_token_key) != NGX_OK {
        return Err(ConfError::Logged);
    }

    if ngx_quic_derive_key(&cf.log, "sr_token_key", &host_key, NGX_HTTP_QUIC_SALT, &mut sr_token_key) != NGX_OK {
        return Err(ConfError::Logged);
    }

    let cscf = crate::core::core_srv_conf(cf);
    let handshake_timeout = *cscf.borrow().client_header_timeout;

    let sscf = crate::get_srv_conf::<crate::ssl_module::HttpSslSrvConf>(cf, crate::ssl_module::ctx_index());

    let create_ssl: Rc<dyn Fn(&Connection) -> i64> = Rc::new(move |c: &Connection| ngx_core::event_openssl::ngx_ssl_create_connection(&sscf.borrow().ssl, c, 0));

    let quic = QuicConf {
        create_ssl: Some(create_ssl),
        retry: *c.retry,
        gso_enabled: *c.gso_enabled,
        disable_active_migration: false,
        handshake_timeout,
        idle_timeout: std::cell::Cell::new(0),
        host_key: host_key.clone(),
        stream_buffer_size: *c.stream_buffer_size,
        max_concurrent_streams_bidi: *c.max_concurrent_streams as u64,
        max_concurrent_streams_uni: NGX_HTTP_V3_MAX_UNI_STREAMS,
        active_connection_id_limit: *c.active_connection_id_limit as u64,
        stream_close_code: NGX_HTTP_V3_ERR_NO_ERROR,
        stream_reject_code_uni: 0,
        stream_reject_code_bidi: NGX_HTTP_V3_ERR_REQUEST_REJECTED,
        init: Some(Rc::new(super::request::init)),
        shutdown: Some(Rc::new(super::request::shutdown)),
        av_token_key,
        sr_token_key,
    };

    c.host_key = Some(host_key);
    c.quic = Some(Rc::new(quic));

    Ok(())
}

/// ngx_http_quic_host_key
fn quic_host_key(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.expect("srv conf");
    let mut h3scf = conf_cell::<H3SrvConf>(&conf).borrow_mut();

    if h3scf.host_key.is_some() {
        return Err(msg("is duplicate"));
    }

    let name = cf.full_name(&cf.args[1].clone(), true);

    let path = std::ffi::OsStr::new(std::str::from_utf8(&name).unwrap_or(""));

    let data = match std::fs::File::open(path) {
        Ok(mut f) => {
            use std::io::Read;

            let size = match f.metadata() {
                Ok(m) => m.len() as usize,
                Err(e) => {
                    cf.log_error(NGX_LOG_CRIT, e.raw_os_error(), format_args!("fstat() \"{}\" failed", B(&name)));
                    return Err(ConfError::Logged);
                }
            };

            if size == 0 {
                cf.log_error(NGX_LOG_EMERG, None, format_args!("\"{}\" zero key size", B(&name)));
                return Err(ConfError::Logged);
            }

            let mut buf = vec![0u8; size];

            let n = match f.read(&mut buf) {
                Ok(n) => n,
                Err(e) => {
                    cf.log_error(NGX_LOG_CRIT, e.raw_os_error(), format_args!("pread() \"{}\" failed", B(&name)));
                    return Err(ConfError::Logged);
                }
            };

            if n != size {
                cf.log_error(NGX_LOG_CRIT, None, format_args!("pread() \"{}\" returned only {} bytes instead of {}", B(&name), n, size));
                ngx_core::event_openssl::explicit_memzero(&mut buf);
                return Err(ConfError::Logged);
            }

            buf
        }

        Err(e) => {
            cf.log_error(NGX_LOG_EMERG, e.raw_os_error(), format_args!("open() \"{}\" failed", B(&name)));
            return Err(ConfError::Logged);
        }
    };

    h3scf.host_key = Some(data);

    Ok(())
}

pub fn v3_module() -> ModuleDef {
    let def = HttpModuleDef { preconfiguration: Some(add_variables), create_srv_conf: Some(create_srv_conf), merge_srv_conf: Some(merge_srv_conf), ..Default::default() };

    const CONF: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF;

    let commands = vec![
        ngx_core::cmd!("http3", CONF | NGX_CONF_FLAG, ConfLevel::Srv, H3SrvConf, enable, set_flag),
        ngx_core::cmd!("http3_hq", CONF | NGX_CONF_FLAG, ConfLevel::Srv, H3SrvConf, enable_hq, set_flag),
        ngx_core::cmd!("http3_max_concurrent_streams", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, H3SrvConf, max_concurrent_streams, set_num),
        ngx_core::cmd!("http3_stream_buffer_size", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, H3SrvConf, stream_buffer_size, set_size),
        ngx_core::cmd!("quic_retry", CONF | NGX_CONF_FLAG, ConfLevel::Srv, H3SrvConf, retry, set_flag),
        ngx_core::cmd!("quic_gso", CONF | NGX_CONF_FLAG, ConfLevel::Srv, H3SrvConf, gso_enabled, set_flag),
        Command::new("quic_host_key", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, quic_host_key),
        ngx_core::cmd!("quic_active_connection_id_limit", CONF | NGX_CONF_TAKE1, ConfLevel::Srv, H3SrvConf, active_connection_id_limit, set_num),
    ];

    http_module_def("ngx_http_v3_module", def, commands)
}
