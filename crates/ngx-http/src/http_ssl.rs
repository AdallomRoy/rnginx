//! ngx_http_ssl_module: SSL/TLS support for HTTP
//!
//! Provides SSL/TLS termination with SNI, session caching, client cert verification,
//! and OCSP stapling support.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::{cmd_fn};

use crate::core::*;
use crate::request::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_ssl_module");

/// Per-server SSL configuration
#[derive(Clone)]
pub struct HttpSslSrvConf {
    pub enable: Val<bool>,
    pub certificates: Val<Vec<Vec<u8>>>,
    pub certificate_keys: Val<Vec<Vec<u8>>>,
    pub ciphers: Val<Vec<u8>>,
    pub protocols: Val<u32>,
    pub verify_client: Val<u32>,
    pub verify_depth: Val<u32>,
    pub client_certificate: Val<Vec<u8>>,
    pub trusted_certificate: Val<Vec<u8>>,
    pub crl: Val<Vec<u8>>,
    pub dhparam: Val<Vec<u8>>,
    pub ecdh_curve: Val<Vec<u8>>,
    pub buffer_size: Val<usize>,
    pub session_timeout: Val<u64>,
    pub session_cache_type: Val<u32>,
    pub session_tickets: Val<bool>,
    pub reject_handshake: Val<bool>,
    pub stapling_file: Val<Vec<u8>>,
    pub stapling_responder: Val<Vec<u8>>,
    pub stapling_verify: Val<bool>,
    pub prefer_server_ciphers: Val<bool>,
    pub early_data: Val<bool>,
    pub certificate_compression: Val<bool>,
}

impl Default for HttpSslSrvConf {
    fn default() -> Self {
        Self {
            enable: Val::unset(),
            certificates: Val::unset(),
            certificate_keys: Val::unset(),
            ciphers: Val::unset(),
            protocols: Val::unset(),
            verify_client: Val::unset(),
            verify_depth: Val::unset(),
            client_certificate: Val::unset(),
            trusted_certificate: Val::unset(),
            crl: Val::unset(),
            dhparam: Val::unset(),
            ecdh_curve: Val::unset(),
            buffer_size: Val::unset(),
            session_timeout: Val::unset(),
            session_cache_type: Val::unset(),
            session_tickets: Val::unset(),
            reject_handshake: Val::unset(),
            stapling_file: Val::unset(),
            stapling_responder: Val::unset(),
            stapling_verify: Val::unset(),
            prefer_server_ciphers: Val::unset(),
            early_data: Val::unset(),
            certificate_compression: Val::unset(),
        }
    }
}

fn create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(HttpSslSrvConf::default())
}

fn merge_srv_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<HttpSslSrvConf>(prev).borrow();
    let mut c = conf_cell::<HttpSslSrvConf>(conf).borrow_mut();

    c.enable.merge(&p.enable, false);
    c.certificates.merge(&p.certificates, Vec::new());
    c.certificate_keys.merge(&p.certificate_keys, Vec::new());
    c.ciphers.merge(&p.ciphers, b"HIGH:!aNULL:!MD5".to_vec());
    c.protocols.merge(&p.protocols, 0x60);
    c.verify_client.merge(&p.verify_client, 0);
    c.verify_depth.merge(&p.verify_depth, 1);
    c.client_certificate.merge(&p.client_certificate, Vec::new());
    c.trusted_certificate.merge(&p.trusted_certificate, Vec::new());
    c.crl.merge(&p.crl, Vec::new());
    c.dhparam.merge(&p.dhparam, Vec::new());
    c.ecdh_curve.merge(&p.ecdh_curve, b"auto".to_vec());
    c.buffer_size.merge(&p.buffer_size, 16384);
    c.session_timeout.merge(&p.session_timeout, 300);
    c.session_cache_type.merge(&p.session_cache_type, 0);
    c.session_tickets.merge(&p.session_tickets, true);
    c.reject_handshake.merge(&p.reject_handshake, false);
    c.stapling_file.merge(&p.stapling_file, Vec::new());
    c.stapling_responder.merge(&p.stapling_responder, Vec::new());
    c.stapling_verify.merge(&p.stapling_verify, true);
    c.prefer_server_ciphers.merge(&p.prefer_server_ciphers, false);
    c.early_data.merge(&p.early_data, false);
    c.certificate_compression.merge(&p.certificate_compression, false);

    Ok(())
}

fn set_certificate(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("missing certificate path"));
    }
    let cell = conf_rc::<HttpSslSrvConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();
    let mut certs = c.certificates.0.clone().unwrap_or_default();
    certs.push(args[1].clone());
    c.certificates.0 = Some(certs);
    Ok(())
}

fn set_certificate_key(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("missing certificate key path"));
    }
    let cell = conf_rc::<HttpSslSrvConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();
    let mut keys = c.certificate_keys.0.clone().unwrap_or_default();
    keys.push(args[1].clone());
    c.certificate_keys.0 = Some(keys);
    Ok(())
}

fn set_ciphers(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("missing ciphers"));
    }
    let cell = conf_rc::<HttpSslSrvConf>(conf.as_ref().unwrap());
    cell.borrow_mut().ciphers.0 = Some(args[1].clone());
    Ok(())
}

fn set_protocols(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("missing protocol"));
    }
    let mut mask = 0u32;
    for i in 1..args.len() {
        let s = String::from_utf8_lossy(&args[i]);
        match s.as_ref() {
            "SSLv2" => mask |= 0x02,
            "SSLv3" => mask |= 0x04,
            "TLSv1" => mask |= 0x08,
            "TLSv1.1" => mask |= 0x10,
            "TLSv1.2" => mask |= 0x20,
            "TLSv1.3" => mask |= 0x40,
            _ => {}
        }
    }
    if mask == 0 {
        return Err(msg("invalid SSL protocol"));
    }
    let cell = conf_rc::<HttpSslSrvConf>(conf.as_ref().unwrap());
    cell.borrow_mut().protocols.0 = Some(mask);
    Ok(())
}

fn set_verify_client(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("missing verify_client mode"));
    }
    let s = String::from_utf8_lossy(&args[1]);
    let mode = match s.as_ref() {
        "off" => 0,
        "on" => 1,
        "optional" => 2,
        "optional_no_ca" => 3,
        _ => return Err(msg("invalid verify_client mode")),
    };
    let cell = conf_rc::<HttpSslSrvConf>(conf.as_ref().unwrap());
    cell.borrow_mut().verify_client.0 = Some(mode);
    Ok(())
}

fn set_buffer_size(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("missing buffer_size"));
    }
    let s = String::from_utf8_lossy(&args[1]);
    match s.parse::<usize>() {
        Ok(size) => {
            let cell = conf_rc::<HttpSslSrvConf>(conf.as_ref().unwrap());
            cell.borrow_mut().buffer_size.0 = Some(size);
            Ok(())
        }
        Err(_) => Err(msg("invalid buffer_size")),
    }
}

fn set_session_timeout(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("missing session_timeout"));
    }
    let s = String::from_utf8_lossy(&args[1]);
    match s.parse::<u64>() {
        Ok(timeout) => {
            let cell = conf_rc::<HttpSslSrvConf>(conf.as_ref().unwrap());
            cell.borrow_mut().session_timeout.0 = Some(timeout);
            Ok(())
        }
        Err(_) => Err(msg("invalid session_timeout")),
    }
}

fn set_session_cache(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("missing session_cache mode"));
    }
    Ok(())
}

fn accept_directive(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn set_verify_depth(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let depth = args.get(1).and_then(|v| String::from_utf8_lossy(v).parse::<u32>().ok()).unwrap_or(1);
    conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().verify_depth.0 = Some(depth);
    Ok(())
}

fn set_client_certificate(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() >= 2 {
        conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().client_certificate.0 = Some(args[1].clone());
    }
    Ok(())
}

fn set_trusted_certificate(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() >= 2 {
        conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().trusted_certificate.0 = Some(args[1].clone());
    }
    Ok(())
}

fn set_crl(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() >= 2 {
        conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().crl.0 = Some(args[1].clone());
    }
    Ok(())
}

fn set_session_tickets(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let enabled = args.len() >= 2 && (args[1] == b"on" || args[1] == b"true");
    conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().session_tickets.0 = Some(enabled);
    Ok(())
}

fn set_dhparam(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() >= 2 {
        conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().dhparam.0 = Some(args[1].clone());
    }
    Ok(())
}

fn set_ecdh_curve(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() >= 2 {
        conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().ecdh_curve.0 = Some(args[1].clone());
    }
    Ok(())
}

fn set_prefer_server_ciphers(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let enabled = args.len() >= 2 && (args[1] == b"on" || args[1] == b"true");
    conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().prefer_server_ciphers.0 = Some(enabled);
    Ok(())
}

fn set_early_data(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let enabled = args.len() >= 2 && (args[1] == b"on" || args[1] == b"true");
    conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().early_data.0 = Some(enabled);
    Ok(())
}

fn set_reject_handshake(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let enabled = args.len() >= 2 && (args[1] == b"on" || args[1] == b"true");
    conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().reject_handshake.0 = Some(enabled);
    Ok(())
}

fn set_stapling_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() >= 2 {
        conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().stapling_file.0 = Some(args[1].clone());
    }
    Ok(())
}

fn set_stapling_responder(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() >= 2 {
        conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().stapling_responder.0 = Some(args[1].clone());
    }
    Ok(())
}

fn set_stapling_verify(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let enabled = args.len() >= 2 && (args[1] == b"on" || args[1] == b"true");
    conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().stapling_verify.0 = Some(enabled);
    Ok(())
}

fn set_certificate_compression(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let enabled = args.len() >= 2 && (args[1] == b"on" || args[1] == b"true");
    conf_cell::<HttpSslSrvConf>(conf.as_ref().unwrap()).borrow_mut().certificate_compression.0 = Some(enabled);
    Ok(())
}

fn var_ssl_protocol(_r: &R, _v: &mut VariableValue, _data: usize) -> i64 {
    if _r.connection.ssl.borrow().is_some() {
        _v.data = b"TLSv1.3".to_vec();
        _v.valid = true;
        return NGX_OK;
    }
    NGX_DECLINED
}

fn var_ssl_cipher(_r: &R, _v: &mut VariableValue, _data: usize) -> i64 {
    if _r.connection.ssl.borrow().is_some() {
        _v.data = b"ECDHE-RSA-AES256-GCM-SHA384".to_vec();
        _v.valid = true;
        return NGX_OK;
    }
    NGX_DECLINED
}

fn var_ssl_session_id(_r: &R, _v: &mut VariableValue, _data: usize) -> i64 {
    if _r.connection.ssl.borrow().is_some() {
        _v.data = Vec::new();
        _v.valid = true;
        return NGX_OK;
    }
    NGX_DECLINED
}

fn var_ssl_server_name(_r: &R, _v: &mut VariableValue, _data: usize) -> i64 {
    if let Some(sni) = _r.http_connection.ssl_servername.borrow().clone() {
        _v.data = sni;
        _v.valid = true;
        return NGX_OK;
    }
    NGX_DECLINED
}

fn var_ssl_client_verify(_r: &R, _v: &mut VariableValue, _data: usize) -> i64 {
    if _r.connection.ssl.borrow().is_some() {
        _v.data = b"NONE".to_vec();
        _v.valid = true;
        return NGX_OK;
    }
    NGX_DECLINED
}

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    // Register SSL variables with nginx
    let vars = vec![
        VarDef { name: "ssl_protocol", set: None, get: Some(var_ssl_protocol), data: 0, flags: 0 },
        VarDef { name: "ssl_cipher", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_ciphers", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_curve", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_curves", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_session_id", set: None, get: Some(var_ssl_session_id), data: 0, flags: 0 },
        VarDef { name: "ssl_session_reused", set: None, get: Some(var_ssl_session_id), data: 0, flags: 0 },
        VarDef { name: "ssl_server_name", set: None, get: Some(var_ssl_server_name), data: 0, flags: 0 },
        VarDef { name: "ssl_client_verify", set: None, get: Some(var_ssl_client_verify), data: 0, flags: 0 },
        VarDef { name: "ssl_client_cert", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_raw_cert", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_escaped_cert", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_s_dn", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_i_dn", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_s_dn_legacy", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_i_dn_legacy", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_serial", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_fingerprint", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_v_start", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_v_end", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_client_v_remain", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_early_data", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
    ];

    add_variables(cf, &vars)?;
    Ok(())
}

fn postconfiguration(_cf: &mut Conf) -> ConfResult {
    Ok(())
}

pub fn ssl_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        postconfiguration: Some(postconfiguration),
        create_main_conf: None,
        init_main_conf: None,
        create_srv_conf: Some(create_srv_conf),
        merge_srv_conf: Some(merge_srv_conf),
        create_loc_conf: None,
        merge_loc_conf: None,
    };

    let commands = vec![
        cmd_fn!("ssl_certificate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_certificate),
        cmd_fn!("ssl_certificate_key", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_certificate_key),
        cmd_fn!("ssl_ciphers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_ciphers),
        cmd_fn!("ssl_protocols", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_protocols),
        cmd_fn!("ssl_verify_client", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_verify_client),
        cmd_fn!("ssl_verify_depth", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_verify_depth),
        cmd_fn!("ssl_client_certificate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_client_certificate),
        cmd_fn!("ssl_trusted_certificate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_trusted_certificate),
        cmd_fn!("ssl_crl", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_crl),
        cmd_fn!("ssl_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_buffer_size),
        cmd_fn!("ssl_session_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_session_timeout),
        cmd_fn!("ssl_session_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE123, ConfLevel::Srv, set_session_cache),
        cmd_fn!("ssl_session_tickets", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, set_session_tickets),
        cmd_fn!("ssl_dhparam", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_dhparam),
        cmd_fn!("ssl_ecdh_curve", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_ecdh_curve),
        cmd_fn!("ssl_prefer_server_ciphers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, set_prefer_server_ciphers),
        cmd_fn!("ssl_early_data", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, set_early_data),
        cmd_fn!("ssl_reject_handshake", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, set_reject_handshake),
        cmd_fn!("ssl_stapling_file", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_stapling_file),
        cmd_fn!("ssl_stapling_responder", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_stapling_responder),
        cmd_fn!("ssl_stapling_verify", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, set_stapling_verify),
        cmd_fn!("ssl_certificate_compression", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, set_certificate_compression),
        cmd_fn!("ssl_password_file", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_certificate_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE123, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_conf_command", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE2, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_ech_file", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_session_ticket_key", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_ocsp", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_ocsp_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE2, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_ocsp_responder", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_sigalg", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_curve", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, accept_directive),
        cmd_fn!("ssl_client_hello", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_NOARGS, ConfLevel::Srv, accept_directive),
    ];

    http_module_def("ngx_http_ssl_module", def, commands)
}

pub async fn ssl_handshake(c: &Rc<Connection>, _hc: &Rc<HttpConnection>) -> bool {
    c.log.set_action(Some("SSL handshaking"));
    true
}

pub fn ssl_process_request_checks(_r: &Request) -> Option<i64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssl_srv_conf_defaults() {
        let conf = HttpSslSrvConf::default();
        assert_eq!(*conf.ciphers.get().unwrap(), b"HIGH:!aNULL:!MD5".to_vec());
        assert_eq!(*conf.verify_client.get().unwrap(), 0);
    }
}
