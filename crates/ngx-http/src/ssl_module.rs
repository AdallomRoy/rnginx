//! ngx_http_ssl_module — HTTP TLS server support via openssl-sys FFI.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::os::raw::c_void;
use std::rc::Rc;

use foreign_types::ForeignType;
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::ssl::{SslConnection, ssl_error_string};
use ngx_core::connection::Connection;
use ngx_core::cmd_fn;
use ngx_core::ngx_log_error;
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslFiletype, SslVerifyMode};
extern "C" {
    fn SSL_set_fd(s: *mut openssl_sys::SSL, fd: std::os::raw::c_int) -> std::os::raw::c_int;
}



use crate::core::*;
use crate::request::*;
use crate::variables::VarDef;
use crate::{NGX_HTTP_MAIN_CONF, NGX_HTTP_SRV_CONF, HttpModuleDef, http_module_def};

// ---------------------------------------------------------------------
// SNI cert selection: swap SSL_CTX to the matched server's context in
// the servername callback. Registry maps a small integer stashed on
// each SSL as ex_data back to the addr_conf so the callback can walk
// virtual_names[hostname] without any thread/global synchronization.
// ---------------------------------------------------------------------
thread_local! {
    static SNI_REGISTRY: RefCell<Vec<Option<Rc<AddrConf>>>> = const { RefCell::new(Vec::new()) };
    static SNI_EX_INDEX: Cell<i32> = const { Cell::new(-1) };
}

unsafe extern "C" fn sni_free_cb(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut openssl_sys::CRYPTO_EX_DATA,
    _idx: std::os::raw::c_int,
    _argl: std::os::raw::c_long,
    _argp: *mut c_void,
) {
    if ptr.is_null() { return; }
    let idx = ptr as usize;
    if idx == 0 { return; } // sentinel-shifted, 0 is the "unset" marker
    SNI_REGISTRY.with(|r| {
        let mut v = r.borrow_mut();
        let real = idx - 1;
        if real < v.len() { v[real] = None; }
    });
}

fn sni_ex_index() -> i32 {
    let cur = SNI_EX_INDEX.with(|c| c.get());
    if cur >= 0 { return cur; }
    let idx = unsafe {
        openssl_sys::SSL_get_ex_new_index(0, std::ptr::null_mut(), None, None, Some(sni_free_cb))
    };
    SNI_EX_INDEX.with(|c| c.set(idx));
    idx
}

fn sni_register(addr: Rc<AddrConf>) -> usize {
    SNI_REGISTRY.with(|r| {
        let mut v = r.borrow_mut();
        // Reuse a hole left by a freed connection if we have one — this
        // keeps the vector bounded across a long-running worker's
        // lifetime instead of leaking a slot per handshake.
        for (i, slot) in v.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(addr);
                return i;
            }
        }
        v.push(Some(addr));
        v.len() - 1
    })
}

fn sni_lookup(idx: usize) -> Option<Rc<AddrConf>> {
    SNI_REGISTRY.with(|r| r.borrow().get(idx).and_then(|o| o.clone()))
}

unsafe extern "C" fn sni_servername_cb(
    ssl: *mut openssl_sys::SSL,
    _ad: *mut std::os::raw::c_int,
    _arg: *mut c_void,
) -> std::os::raw::c_int {
    // SSL_TLSEXT_ERR_OK = 0, SSL_TLSEXT_ERR_ALERT_FATAL = 2, SSL_TLSEXT_ERR_NOACK = 3
    let ok: std::os::raw::c_int = 0;
    let fatal: std::os::raw::c_int = 2;
    let idx_ptr = openssl_sys::SSL_get_ex_data(ssl, sni_ex_index());
    if idx_ptr.is_null() { return ok; }
    let idx = idx_ptr as usize - 1; // sentinel-shift so NULL != index 0
    let addr = match sni_lookup(idx) { Some(a) => a, None => return ok };
    let name_c = openssl_sys::SSL_get_servername(ssl, 0 /* TLSEXT_NAMETYPE_host_name */);
    if name_c.is_null() {
        // No SNI. If reject_handshake is on for the default server, refuse.
        if reject_handshake_for(&addr.default_server) {
            return fatal;
        }
        return ok;
    }
    let name = std::ffi::CStr::from_ptr(name_c).to_bytes();
    // Lowercase copy so hash lookup matches.
    let host: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
    let cscf = find_server_by_name(&addr, &host);
    let cscf = match cscf {
        Some(c) => c,
        None => {
            // No matching virtual server. If default has reject_handshake
            // on, refuse; else fall through with the default cert.
            if reject_handshake_for(&addr.default_server) {
                return fatal;
            }
            return ok;
        }
    };
    // Fetch the target server's SslContext and swap.
    let sctx = cscf.borrow().ctx.clone();
    let srv_slots = match &sctx.srv { Some(s) => s.clone(), None => return ok };
    let ssl_conf = slot_of::<HttpSslSrvConf>(&srv_slots, ctx_index());
    if reject_handshake_for(&cscf) {
        return fatal;
    }
    let target = ssl_conf.borrow().ssl_ctx.borrow().clone();
    if let Some(target) = target {
        let raw = target.as_ptr() as *mut openssl_sys::SSL_CTX;
        if openssl_sys::SSL_set_SSL_CTX(ssl, raw).is_null() {
            return ok;
        }
        // Match C's post-SSL_set_SSL_CTX adjustments so verify from the
        // target ctx actually takes effect for this handshake.
        let mode = openssl_sys::SSL_CTX_get_verify_mode(raw);
        openssl_sys::SSL_set_verify(ssl, mode, None);
        // SSL_CTRL_OPTIONS=32 — set options via SSL_ctrl since 0.9.117
        // doesn't expose SSL_set_options as a direct FFI symbol.
        let opts = openssl_sys::SSL_CTX_get_options(raw);
        openssl_sys::SSL_ctrl(ssl, 32, opts as std::os::raw::c_long, std::ptr::null_mut());
    }
    ok
}

fn reject_handshake_for(cscf: &Rc<RefCell<CoreSrvConf>>) -> bool {
    let sctx = cscf.borrow().ctx.clone();
    let srv_slots = match &sctx.srv { Some(s) => s.clone(), None => return false };
    let ssl_conf = slot_of::<HttpSslSrvConf>(&srv_slots, ctx_index());
    let v = ssl_conf.borrow().reject_handshake.get_or(false);
    v
}

fn find_server_by_name(addr: &AddrConf, host: &[u8]) -> Option<Rc<RefCell<CoreSrvConf>>> {
    let vn = addr.virtual_names.as_ref()?;
    vn.names.find(ngx_core::hash::hash_key(host), host).cloned()
}

crate::http_module_index!("ngx_http_ssl_module");

pub struct HttpSslSrvConf {
    pub certificate: Val<Vec<u8>>,
    pub certificate_key: Val<Vec<u8>>,
    pub ciphers: Val<Vec<u8>>,
    pub client_certificate: Val<Vec<u8>>,
    pub trusted_certificate: Val<Vec<u8>>,
    pub crl: Val<Vec<u8>>,
    pub dhparam: Val<Vec<u8>>,
    pub ecdh_curve: Val<Vec<u8>>,
    pub password_file: Val<Vec<u8>>,
    pub protocols: Val<u32>,
    pub verify: Val<u32>,
    pub verify_depth: Val<i64>,
    pub buffer_size: Val<usize>,
    pub session_timeout: Val<u64>,
    pub session_cache: Val<Vec<u8>>,
    pub session_tickets: Val<bool>,
    pub prefer_server_ciphers: Val<bool>,
    pub reject_handshake: Val<bool>,
    pub ssl_ctx: RefCell<Option<Rc<SslContext>>>,
}

impl Default for HttpSslSrvConf {
    fn default() -> Self {
        HttpSslSrvConf {
            certificate: Val::unset(),
            certificate_key: Val::unset(),
            ciphers: Val::unset(),
            client_certificate: Val::unset(),
            trusted_certificate: Val::unset(),
            crl: Val::unset(),
            dhparam: Val::unset(),
            ecdh_curve: Val::unset(),
            password_file: Val::unset(),
            protocols: Val::unset(),
            verify: Val::unset(),
            verify_depth: Val::unset(),
            buffer_size: Val::unset(),
            session_timeout: Val::unset(),
            session_cache: Val::unset(),
            session_tickets: Val::unset(),
            prefer_server_ciphers: Val::unset(),
            reject_handshake: Val::unset(),
            ssl_ctx: RefCell::new(None),
        }
    }
}

fn create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(HttpSslSrvConf::default())
}

fn merge_srv_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<HttpSslSrvConf>(prev).borrow();
    let mut c = conf_cell::<HttpSslSrvConf>(conf).borrow_mut();
    c.certificate.merge_opt(&p.certificate);
    c.certificate_key.merge_opt(&p.certificate_key);
    c.ciphers.merge(&p.ciphers, b"HIGH:!aNULL:!MD5".to_vec());
    c.client_certificate.merge_opt(&p.client_certificate);
    c.trusted_certificate.merge_opt(&p.trusted_certificate);
    c.crl.merge_opt(&p.crl);
    c.dhparam.merge_opt(&p.dhparam);
    c.ecdh_curve.merge(&p.ecdh_curve, b"auto".to_vec());
    c.password_file.merge_opt(&p.password_file);
    c.protocols.merge(&p.protocols, 0);
    c.verify.merge(&p.verify, 0);
    c.verify_depth.merge(&p.verify_depth, 1);
    c.buffer_size.merge(&p.buffer_size, 16384);
    c.session_timeout.merge(&p.session_timeout, 300);
    c.session_cache.merge_opt(&p.session_cache);
    c.session_tickets.merge(&p.session_tickets, true);
    c.prefer_server_ciphers.merge(&p.prefer_server_ciphers, false);
    c.reject_handshake.merge(&p.reject_handshake, false);
    if c.ssl_ctx.borrow().is_none() {
        *c.ssl_ctx.borrow_mut() = p.ssl_ctx.borrow().clone();
    }
    Ok(())
}

fn set_str_slot<F>(cf: &mut Conf, get: F) -> ConfResult
where F: FnOnce(&mut HttpSslSrvConf) -> &mut Val<Vec<u8>>
{
    let conf = core_srv_ssl_conf(cf);
    let arg = cf.args[1].clone();
    let mut c = conf.borrow_mut();
    let slot = get(&mut *c);
    if !slot.is_set() {
        *slot = Val::set(arg);
    }
    Ok(())
}

fn core_srv_ssl_conf(cf: &Conf) -> Rc<RefCell<HttpSslSrvConf>> {
    let slots = cf.ctx.srv.as_ref().expect("srv slots");
    slot_of::<HttpSslSrvConf>(slots, ctx_index())
}

fn set_certificate(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    set_str_slot(cf, |c| &mut c.certificate)
}
fn set_certificate_key(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    set_str_slot(cf, |c| &mut c.certificate_key)
}
fn set_ciphers(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    set_str_slot(cf, |c| &mut c.ciphers)
}
fn set_protocols(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = core_srv_ssl_conf(cf);
    let mut mask = 0u32;
    for a in cf.args.iter().skip(1) {
        match a.as_slice() {
            b"SSLv2" => mask |= 0x0002,
            b"SSLv3" => mask |= 0x0004,
            b"TLSv1" => mask |= 0x0008,
            b"TLSv1.1" => mask |= 0x0010,
            b"TLSv1.2" => mask |= 0x0020,
            b"TLSv1.3" => mask |= 0x0040,
            _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", ngx_core::string::B(a)))),
        }
    }
    conf.borrow_mut().protocols = Val::set(mask);
    Ok(())
}
fn set_verify(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = core_srv_ssl_conf(cf);
    let v = match cf.args[1].as_slice() {
        b"off" => 0,
        b"on" => 1,
        b"optional" => 2,
        b"optional_no_ca" => 3,
        _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", ngx_core::string::B(&cf.args[1])))),
    };
    conf.borrow_mut().verify = Val::set(v);
    Ok(())
}
fn set_verify_depth(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = core_srv_ssl_conf(cf);
    let n = ngx_core::string::atoi(&cf.args[1]).ok_or(msg("invalid number"))?;
    conf.borrow_mut().verify_depth = Val::set(n);
    Ok(())
}
fn set_client_cert(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { set_str_slot(cf, |c| &mut c.client_certificate) }
fn set_trusted_cert(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { set_str_slot(cf, |c| &mut c.trusted_certificate) }
fn set_crl(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { set_str_slot(cf, |c| &mut c.crl) }
fn set_dhparam(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { set_str_slot(cf, |c| &mut c.dhparam) }
fn set_ecdh_curve(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { set_str_slot(cf, |c| &mut c.ecdh_curve) }
fn set_password_file(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { set_str_slot(cf, |c| &mut c.password_file) }
fn set_session_cache(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { set_str_slot(cf, |c| &mut c.session_cache) }
fn set_buffer_size(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = core_srv_ssl_conf(cf);
    let n = ngx_core::string::atoi(&cf.args[1]).ok_or(msg("invalid size"))?;
    conf.borrow_mut().buffer_size = Val::set(n as usize);
    Ok(())
}
fn set_session_timeout(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = core_srv_ssl_conf(cf);
    let n = ngx_core::string::atoi(&cf.args[1]).ok_or(msg("invalid time"))?;
    conf.borrow_mut().session_timeout = Val::set(n as u64);
    Ok(())
}
fn set_session_tickets(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let v = match cf.args[1].as_slice() { b"on" => true, b"off" => false, _ => return Err(msg("invalid value")) };
    core_srv_ssl_conf(cf).borrow_mut().session_tickets = Val::set(v); Ok(())
}
fn set_prefer_server_ciphers(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let v = match cf.args[1].as_slice() { b"on" => true, b"off" => false, _ => return Err(msg("invalid value")) };
    core_srv_ssl_conf(cf).borrow_mut().prefer_server_ciphers = Val::set(v); Ok(())
}
fn set_reject_handshake(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let v = match cf.args[1].as_slice() { b"on" => true, b"off" => false, _ => return Err(msg("invalid value")) };
    core_srv_ssl_conf(cf).borrow_mut().reject_handshake = Val::set(v); Ok(())
}
fn accept_any(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { Ok(()) }

pub fn ssl_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(postconfiguration),
        create_srv_conf: Some(create_srv_conf),
        merge_srv_conf: Some(merge_srv_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("ssl_certificate", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_certificate),
        cmd_fn!("ssl_certificate_key", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_certificate_key),
        cmd_fn!("ssl_ciphers", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_ciphers),
        cmd_fn!("ssl_protocols", F | NGX_CONF_1MORE, ConfLevel::Srv, set_protocols),
        cmd_fn!("ssl_verify_client", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_verify),
        cmd_fn!("ssl_verify_depth", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_verify_depth),
        cmd_fn!("ssl_client_certificate", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_client_cert),
        cmd_fn!("ssl_trusted_certificate", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_trusted_cert),
        cmd_fn!("ssl_crl", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_crl),
        cmd_fn!("ssl_dhparam", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_dhparam),
        cmd_fn!("ssl_ecdh_curve", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_ecdh_curve),
        cmd_fn!("ssl_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_buffer_size),
        cmd_fn!("ssl_session_timeout", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_session_timeout),
        cmd_fn!("ssl_session_cache", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_session_cache),
        cmd_fn!("ssl_session_tickets", F | NGX_CONF_FLAG, ConfLevel::Srv, set_session_tickets),
        cmd_fn!("ssl_session_ticket_key", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_password_file", F | NGX_CONF_TAKE1, ConfLevel::Srv, set_password_file),
        cmd_fn!("ssl_reject_handshake", F | NGX_CONF_FLAG, ConfLevel::Srv, set_reject_handshake),
        cmd_fn!("ssl_prefer_server_ciphers", F | NGX_CONF_FLAG, ConfLevel::Srv, set_prefer_server_ciphers),
        cmd_fn!("ssl_conf_command", F | NGX_CONF_TAKE2, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_early_data", F | NGX_CONF_FLAG, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_stapling", F | NGX_CONF_FLAG, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_stapling_file", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_stapling_responder", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_stapling_verify", F | NGX_CONF_FLAG, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_ocsp", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_ocsp_responder", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_ocsp_cache", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_client_hello_cb", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_certificate_cache", F | NGX_CONF_1MORE, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_object_cache", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_alpn", F | NGX_CONF_1MORE, ConfLevel::Srv, accept_any),
        cmd_fn!("ssl_key_log", F | NGX_CONF_TAKE1, ConfLevel::Srv, accept_any),
    ];
    http_module_def("ngx_http_ssl_module", def, commands)
}

fn postconfiguration(cf: &mut Conf) -> ConfResult {
    // Register SSL variables
    let vars = [
        VarDef { name: "ssl_protocol", set: None, get: Some(var_ssl_protocol), data: 0, flags: 0 },
        VarDef { name: "ssl_cipher", set: None, get: Some(var_ssl_cipher), data: 0, flags: 0 },
        VarDef { name: "ssl_ciphers", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_session_id", set: None, get: Some(var_ssl_session_id), data: 0, flags: 0 },
        VarDef { name: "ssl_session_reused", set: None, get: Some(var_ssl_session_reused), data: 0, flags: 0 },
        VarDef { name: "ssl_server_name", set: None, get: Some(var_ssl_server_name), data: 0, flags: 0 },
        VarDef { name: "ssl_client_verify", set: None, get: Some(var_ssl_client_verify), data: 0, flags: 0 },
        VarDef { name: "ssl_client_cert", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_raw_cert", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_escaped_cert", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_s_dn", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_i_dn", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_s_dn_legacy", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_i_dn_legacy", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_serial_number", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_fingerprint", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_v_start", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_v_end", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_client_v_remain", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_alpn_protocol", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_early_data", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_curve", set: None, get: Some(var_notfound), data: 0, flags: 0 },
        VarDef { name: "ssl_curves", set: None, get: Some(var_notfound), data: 0, flags: 0 },
    ];
    crate::variables::add_variables(cf, &vars)?;

    // Build SSL contexts for every server whose ssl_certificate is set.
    let cmcf = core_main_conf(cf);
    let servers = cmcf.borrow().servers.clone();
    for cscf in servers.iter() {
        let sctx = cscf.borrow().ctx.clone();
        let srv_slots = match &sctx.srv { Some(s) => s.clone(), None => continue };
        let ssl_conf = slot_of::<HttpSslSrvConf>(&srv_slots, ctx_index());
        let has_cert = ssl_conf.borrow().certificate.is_set();
        let reject_only = !has_cert && ssl_conf.borrow().reject_handshake.get_or(false);
        if !has_cert && !reject_only { continue; }
        let (cert, key, ciphers, protocols, verify_mode, client_ca, verify_depth,
             prefer_server_ciphers, session_tickets) = {
            let s = ssl_conf.borrow();
            (s.certificate.as_option().cloned().unwrap_or_default(),
             s.certificate_key.as_option().cloned().unwrap_or_default(),
             s.ciphers.get_or(b"HIGH:!aNULL:!MD5".to_vec()),
             s.protocols.get_or(0),
             s.verify.get_or(0),
             s.client_certificate.as_option().cloned(),
             s.verify_depth.get_or(1) as u32,
             s.prefer_server_ciphers.get_or(false),
             s.session_tickets.get_or(true))
        };
        let mut builder = SslContext::builder(SslMethod::tls_server())
            .map_err(|e| cf.emerg(format_args!("SSL_CTX_new() failed: {}", e)))?;
        if has_cert {
            let cert_full = cf.cycle.full_name(&cert, true);
            let key_full = cf.cycle.full_name(&key, true);
            let cert_str = std::str::from_utf8(&cert_full)
                .map_err(|_| cf.emerg(format_args!("ssl_certificate path is not UTF-8")))?;
            let key_str = std::str::from_utf8(&key_full)
                .map_err(|_| cf.emerg(format_args!("ssl_certificate_key path is not UTF-8")))?;
            builder.set_certificate_chain_file(cert_str)
                .map_err(|e| cf.emerg(format_args!("SSL_CTX_use_certificate_chain_file(\"{}\") failed: {}", cert_str, e)))?;
            builder.set_private_key_file(key_str, SslFiletype::PEM)
                .map_err(|e| cf.emerg(format_args!("SSL_CTX_use_PrivateKey_file(\"{}\") failed: {}", key_str, e)))?;
            builder.check_private_key()
                .map_err(|e| cf.emerg(format_args!("SSL: certificate and key mismatch: {}", e)))?;
        }
        let ciph_str = std::str::from_utf8(&ciphers)
            .map_err(|_| cf.emerg(format_args!("ssl_ciphers is not UTF-8")))?;
        let _ = builder.set_cipher_list(ciph_str);
        // Protocol version limits
        set_protocols_on_builder(&mut builder, protocols);
        if verify_mode != 0 {
            let mode = match verify_mode {
                1 => SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                2 | 3 => SslVerifyMode::PEER,
                _ => SslVerifyMode::NONE,
            };
            builder.set_verify(mode);
            if let Some(ca) = client_ca {
                let ca_full = cf.cycle.full_name(&ca, true);
                if let Ok(s) = std::str::from_utf8(&ca_full) {
                    let _ = builder.set_ca_file(s);
                }
            }
            builder.set_verify_depth(verify_depth);
        }
        if prefer_server_ciphers {
            unsafe {
                openssl_sys::SSL_CTX_set_options(builder.as_ptr() as *mut _, openssl_sys::SSL_OP_CIPHER_SERVER_PREFERENCE);
            }
        }
        if !session_tickets {
            unsafe {
                openssl_sys::SSL_CTX_set_options(builder.as_ptr() as *mut _, openssl_sys::SSL_OP_NO_TICKET);
            }
        }
        // ALPN: advertise http/1.1
        static ALPN: &[u8] = b"\x08http/1.1";
        unsafe extern "C" fn alpn_select_cb(
            _ssl: *mut openssl_sys::SSL,
            out: *mut *const u8,
            outlen: *mut u8,
            client: *const u8,
            client_len: u32,
            _arg: *mut c_void,
        ) -> i32 {
            let client_slice = std::slice::from_raw_parts(client, client_len as usize);
            // Look for "http/1.1" in the client-offered protocols.
            let mut i = 0usize;
            while i < client_slice.len() {
                let l = client_slice[i] as usize;
                if i + 1 + l > client_slice.len() { break; }
                let proto = &client_slice[i+1..i+1+l];
                if proto == b"http/1.1" {
                    *out = client_slice[i+1..].as_ptr();
                    *outlen = l as u8;
                    return 0; // SSL_TLSEXT_ERR_OK
                }
                i += 1 + l;
            }
            3 // SSL_TLSEXT_ERR_NOACK
        }
        unsafe {
            openssl_sys::SSL_CTX_set_alpn_select_cb__fixed_rust(
                builder.as_ptr() as *mut _,
                Some(alpn_select_cb),
                std::ptr::null_mut(),
            );
            let _ = ALPN;
            // Install the SNI callback so a hostname-directed handshake
            // can swap SSL_CTX to another server's cert. The callback
            // reads addr_conf out of per-SSL ex_data — set from
            // ssl_handshake — so a single global callback works for all
            // listens.
            openssl_sys::SSL_CTX_set_tlsext_servername_callback__fixed_rust(
                builder.as_ptr() as *mut _,
                Some(sni_servername_cb),
            );
        }
        let ctx = builder.build();
        *ssl_conf.borrow_mut().ssl_ctx.borrow_mut() = Some(Rc::new(ctx));
    }
    Ok(())
}

fn set_protocols_on_builder(builder: &mut SslContextBuilder, mask: u32) {
    if mask == 0 { return; }
    // Disable any not-selected protocol via SSL_CTX_set_options
    let mut opts: u64 = 0;
    if mask & 0x0002 == 0 { opts |= openssl_sys::SSL_OP_NO_SSLv2 as u64; }
    if mask & 0x0004 == 0 { opts |= openssl_sys::SSL_OP_NO_SSLv3 as u64; }
    if mask & 0x0008 == 0 { opts |= openssl_sys::SSL_OP_NO_TLSv1 as u64; }
    if mask & 0x0010 == 0 { opts |= openssl_sys::SSL_OP_NO_TLSv1_1 as u64; }
    if mask & 0x0020 == 0 { opts |= openssl_sys::SSL_OP_NO_TLSv1_2 as u64; }
    if mask & 0x0040 == 0 { opts |= openssl_sys::SSL_OP_NO_TLSv1_3 as u64; }
    unsafe { openssl_sys::SSL_CTX_set_options(builder.as_ptr() as *mut _, opts); }
}

pub async fn ssl_handshake(c: &Rc<Connection>, hc: &Rc<HttpConnection>) -> bool {
    let cscf = hc.addr_conf.default_server.clone();
    let sctx = cscf.borrow().ctx.clone();
    let srv_slots = match &sctx.srv { Some(s) => s.clone(), None => return false };
    let ssl_conf = slot_of::<HttpSslSrvConf>(&srv_slots, ctx_index());
    let ctx = match ssl_conf.borrow().ssl_ctx.borrow().clone() {
        Some(c) => c,
        None => {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "no SSL context configured");
            return false;
        }
    };
    let ssl = match openssl::ssl::Ssl::new(&ctx) {
        Ok(s) => s,
        Err(e) => {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "SSL_new() failed: {}", e);
            return false;
        }
    };
    let fd = c.fd.get();
    unsafe {
        SSL_set_fd(ssl.as_ptr(), fd);
        openssl_sys::SSL_set_accept_state(ssl.as_ptr());
        // Attach addr_conf so the SNI callback can find the matching
        // virtual server and swap SSL_CTX. Store idx+1 so a NULL
        // ex_data (unset) is distinguishable from index 0.
        let idx = sni_register(hc.addr_conf.clone());
        openssl_sys::SSL_set_ex_data(ssl.as_ptr(), sni_ex_index(), (idx + 1) as *mut c_void);
    }
    // Wrap and stash into the connection so recv/send route through TLS.
    let ssl_conn = Rc::new(SslConnection::new());
    *ssl_conn.inner.borrow_mut() = Some(ssl);
    *c.ssl.borrow_mut() = Some(ssl_conn.clone());
    // Drive the handshake.
    let ssl_ptr = ssl_conn.inner.borrow().as_ref().unwrap().as_ptr();
    loop {
        let rc = unsafe { openssl_sys::SSL_do_handshake(ssl_ptr) };
        if rc == 1 {
            ssl_conn.handshaked.set(true);
            return true;
        }
        let err = unsafe { openssl_sys::SSL_get_error(ssl_ptr, rc) };
        match err {
            openssl_sys::SSL_ERROR_WANT_READ => {
                if c.readable().await.is_err() {
                    return false;
                }
            }
            openssl_sys::SSL_ERROR_WANT_WRITE => {
                if c.writable().await.is_err() {
                    return false;
                }
            }
            _ => {
                let msg = ssl_error_string();
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "SSL_do_handshake() failed (SSL: {}) while SSL handshaking", msg);
                *c.ssl.borrow_mut() = None;
                return false;
            }
        }
    }
}

pub fn ssl_verify_enabled(_cscf: &Rc<RefCell<CoreSrvConf>>) -> bool { false }
pub fn ssl_process_request_checks(_r: &R) -> Option<i64> { None }

pub async fn ssl_shutdown(c: &Rc<Connection>) {
    if let Some(ssl) = c.ssl.borrow().clone() {
        if let Some(s) = ssl.inner.borrow().as_ref() {
            unsafe {
                let ptr = s.as_ptr();
                let _ = openssl_sys::SSL_shutdown(ptr);
            }
        }
    }
}

// Variable getters — return not_found for stubs so complex_value doesn't fail.
fn var_notfound(_r: &R, v: &mut VariableValue, _data: usize) -> i64 { v.not_found = true; NGX_OK }
fn ssl_conn(r: &R) -> Option<Rc<SslConnection>> {
    r.connection.ssl.borrow().clone()
}
fn set_var(v: &mut VariableValue, data: Vec<u8>) -> i64 {
    v.data = data; v.valid = true; v.not_found = false; NGX_OK
}
fn var_ssl_protocol(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    match ssl_conn(r) {
        Some(sc) if sc.handshaked.get() => {
            let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
            unsafe {
                let vp = openssl_sys::SSL_get_version(ptr);
                if vp.is_null() { v.not_found = true; return NGX_OK; }
                let s = std::ffi::CStr::from_ptr(vp).to_bytes().to_vec();
                set_var(v, s)
            }
        }
        _ => { v.not_found = true; NGX_OK }
    }
}
fn var_ssl_cipher(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    match ssl_conn(r) {
        Some(sc) if sc.handshaked.get() => {
            let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
            unsafe {
                let cip = openssl_sys::SSL_get_current_cipher(ptr);
                if cip.is_null() { v.not_found = true; return NGX_OK; }
                let name = openssl_sys::SSL_CIPHER_get_name(cip);
                if name.is_null() { v.not_found = true; return NGX_OK; }
                let s = std::ffi::CStr::from_ptr(name).to_bytes().to_vec();
                set_var(v, s)
            }
        }
        _ => { v.not_found = true; NGX_OK }
    }
}
fn var_ssl_session_id(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    match ssl_conn(r) {
        Some(sc) if sc.handshaked.get() => {
            let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
            unsafe {
                let sess = openssl_sys::SSL_get_session(ptr);
                if sess.is_null() { v.not_found = true; return NGX_OK; }
                let mut len = 0u32;
                let idp = openssl_sys::SSL_SESSION_get_id(sess, &mut len);
                if idp.is_null() || len == 0 { v.not_found = true; return NGX_OK; }
                let bytes = std::slice::from_raw_parts(idp, len as usize);
                let hex: Vec<u8> = bytes.iter().flat_map(|b| format!("{:02x}", b).into_bytes()).collect();
                set_var(v, hex)
            }
        }
        _ => { v.not_found = true; NGX_OK }
    }
}
fn var_ssl_session_reused(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    match ssl_conn(r) {
        Some(sc) if sc.handshaked.get() => {
            let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
            let reused = unsafe { openssl_sys::SSL_session_reused(ptr) };
            set_var(v, if reused != 0 { b"r".to_vec() } else { b".".to_vec() })
        }
        _ => { v.not_found = true; NGX_OK }
    }
}
fn var_ssl_server_name(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    match ssl_conn(r) {
        Some(sc) if sc.handshaked.get() => {
            let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
            unsafe {
                let name = openssl_sys::SSL_get_servername(ptr, 0 /* TLSEXT_NAMETYPE_host_name */);
                if name.is_null() { v.not_found = true; return NGX_OK; }
                let s = std::ffi::CStr::from_ptr(name).to_bytes().to_vec();
                set_var(v, s)
            }
        }
        _ => { v.not_found = true; NGX_OK }
    }
}
fn var_ssl_client_verify(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    set_var(v, b"NONE".to_vec())
}

// Keep the Cell/Ssl unused-import placeholder silenced for now.
#[allow(dead_code)]
fn _unused(_c: Cell<u32>) {}
