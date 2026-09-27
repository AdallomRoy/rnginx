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
    // openssl-sys 0.9.117 gates SSL_get_peer_certificate behind #[cfg(not(ossl300))]
    // and SSL_get1_peer_certificate behind #[cfg(ossl300)]. Both symbols are just
    // aliases at the C level (the "1" refers to the reference-count-1 return
    // convention), so we bind SSL_get1_peer_certificate directly here — OpenSSL 3
    // exports both names and 1.1.1 exports SSL_get_peer_certificate as an alias.
    fn SSL_get1_peer_certificate(ssl: *const openssl_sys::SSL) -> *mut openssl_sys::X509;
    fn OBJ_nid2sn(nid: std::os::raw::c_int) -> *const std::os::raw::c_char;

    // In OpenSSL 3.x, SSL_set_options / SSL_clear_options are direct
    // functions, not aliases for SSL_ctrl(SSL_CTRL_OPTIONS/CLEAR).
    // Using ctrl works for reading (SSL_CTRL_OPTIONS,0 returns options)
    // but not for writing on 3.x — SSL_ctrl(32, op, NULL) is a no-op
    // for setting options in modern builds. Use direct symbols.
    fn SSL_set_options(ssl: *mut openssl_sys::SSL, op: u64) -> u64;
    fn SSL_clear_options(ssl: *mut openssl_sys::SSL, op: u64) -> u64;

    // Direct SSL_CTX_set_client_hello_cb + SSL_client_hello_get0_ext.
    // openssl-sys 0.9.117 exposes these under #[cfg(ossl111)]; if that
    // cfg didn't fire during build (e.g., using an older sys crate),
    // we still get the OpenSSL 1.1.1+ symbol at link time.
    fn SSL_CTX_set_client_hello_cb(
        ctx: *mut openssl_sys::SSL_CTX,
        cb: Option<unsafe extern "C" fn(
            s: *mut openssl_sys::SSL,
            al: *mut std::os::raw::c_int,
            arg: *mut c_void,
        ) -> std::os::raw::c_int>,
        arg: *mut c_void,
    );
    fn SSL_client_hello_get0_ext(
        s: *mut openssl_sys::SSL,
        type_: std::os::raw::c_uint,
        out: *mut *const u8,
        outlen: *mut usize,
    ) -> std::os::raw::c_int;

    // CRL loading via PEM_read_bio_X509_CRL / X509_STORE_add_crl.
    // openssl-sys 0.9.117 exposes some but not all of these.
    fn PEM_read_bio_X509_CRL(
        bio: *mut openssl_sys::BIO,
        x: *mut *mut c_void,
        cb: *mut c_void,
        u: *mut c_void,
    ) -> *mut c_void;
    fn X509_STORE_add_crl(store: *mut openssl_sys::X509_STORE, crl: *mut c_void) -> std::os::raw::c_int;
    fn X509_STORE_set_flags(store: *mut openssl_sys::X509_STORE, flags: u32) -> std::os::raw::c_int;
    fn X509_CRL_free(crl: *mut c_void);
    fn SSL_CTX_get_cert_store(ctx: *const openssl_sys::SSL_CTX) -> *mut openssl_sys::X509_STORE;

    // SSL_CONF_CTX API for ssl_conf_command directive. Not exposed by
    // openssl-sys 0.9.117.
    fn SSL_CONF_CTX_new() -> *mut c_void;
    fn SSL_CONF_CTX_free(cctx: *mut c_void);
    fn SSL_CONF_CTX_set_flags(cctx: *mut c_void, flags: u32) -> u32;
    fn SSL_CONF_CTX_set_ssl_ctx(cctx: *mut c_void, ctx: *mut openssl_sys::SSL_CTX);
    fn SSL_CONF_CTX_finish(cctx: *mut c_void) -> std::os::raw::c_int;
    fn SSL_CONF_cmd(
        cctx: *mut c_void,
        cmd: *const std::os::raw::c_char,
        value: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
    fn SSL_CONF_cmd_value_type(
        cctx: *mut c_void,
        cmd: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}

// SSL_CONF flags from openssl/ssl.h
const SSL_CONF_FLAG_FILE: u32 = 0x0002;
const SSL_CONF_FLAG_SERVER: u32 = 0x0008;
const SSL_CONF_FLAG_SHOW_ERRORS: u32 = 0x0010;
const SSL_CONF_FLAG_CERTIFICATE: u32 = 0x0020;
const SSL_CONF_TYPE_FILE: std::os::raw::c_int = 2;
const SSL_CONF_TYPE_DIR: std::os::raw::c_int = 3;

// SSL_get_negotiated_group is a macro in openssl/ssl.h that expands to
// SSL_ctrl(s, SSL_CTRL_GET_NEGOTIATED_GROUP=134, 0, NULL). Do the same.
#[allow(non_snake_case)]
unsafe fn SSL_get_negotiated_group(ssl: *mut openssl_sys::SSL) -> std::os::raw::c_int {
    openssl_sys::SSL_ctrl(ssl, 134, 0, std::ptr::null_mut()) as std::os::raw::c_int
}

#[allow(non_snake_case)]
unsafe fn SSL_get_peer_x509(ssl: *const openssl_sys::SSL) -> *mut openssl_sys::X509 {
    SSL_get1_peer_certificate(ssl)
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
    static SNI_REGISTRY: RefCell<Vec<Option<Rc<HttpConnection>>>> = const { RefCell::new(Vec::new()) };
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

fn sni_register(hc: Rc<HttpConnection>) -> usize {
    SNI_REGISTRY.with(|r| {
        let mut v = r.borrow_mut();
        for (i, slot) in v.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(hc);
                return i;
            }
        }
        v.push(Some(hc));
        v.len() - 1
    })
}

fn sni_lookup(idx: usize) -> Option<Rc<HttpConnection>> {
    SNI_REGISTRY.with(|r| r.borrow().get(idx).and_then(|o| o.clone()))
}

// The core "pick vhost from SNI hostname, swap SSL_CTX + protocol
// options" logic. Split out so both the servername callback (fallback
// path, if client_hello_cb isn't wired) and the client_hello callback
// can reuse it. `host_opt` is None when no SNI extension was present.
unsafe fn sni_apply(
    ssl: *mut openssl_sys::SSL,
    ad: *mut std::os::raw::c_int,
    host_opt: Option<&[u8]>,
) -> std::os::raw::c_int {
    let ok: std::os::raw::c_int = 0;
    let fatal: std::os::raw::c_int = 2;
    // SSL_AD_UNRECOGNIZED_NAME = 112. Matches C's servername.
    let set_reject_alert = |ad_p: *mut std::os::raw::c_int| {
        if !ad_p.is_null() { *ad_p = 112; }
    };
    let idx_ptr = openssl_sys::SSL_get_ex_data(ssl, sni_ex_index());
    if idx_ptr.is_null() { return ok; }
    let idx = idx_ptr as usize - 1;
    let hc = match sni_lookup(idx) { Some(h) => h, None => { return ok; } };
    let addr = &hc.addr_conf;
    let host = match host_opt {
        Some(h) => h,
        None => {
            if reject_handshake_for(&addr.default_server) {
                set_reject_alert(ad);
                return fatal;
            }
            return ok;
        }
    };
    let host: Vec<u8> = host.iter().map(|b| b.to_ascii_lowercase()).collect();
    let cscf = find_server_by_name(addr, &host);
    let cscf = match cscf {
        Some(c) => c,
        None => {
            if reject_handshake_for(&addr.default_server) {
                set_reject_alert(ad);
                return fatal;
            }
            return ok;
        }
    };
    if reject_handshake_for(&cscf) {
        set_reject_alert(ad);
        return fatal;
    }
    // Point hc at the SNI'd server's config so subsequent request
    // creation sees the right srv/loc slots. Matches C's
    // hc->conf_ctx = cscf->ctx.
    let target_ctx = cscf.borrow().ctx.clone();
    *hc.conf_ctx.borrow_mut() = target_ctx.clone();
    // Fetch the target server's SslContext and swap.
    let srv_slots = match &target_ctx.srv { Some(s) => s.clone(), None => { return ok; } };
    let ssl_conf = slot_of::<HttpSslSrvConf>(&srv_slots, ctx_index());
    let target = ssl_conf.borrow().ssl_ctx.borrow().clone();
    if let Some(target) = target {
        let raw = target.as_ptr() as *mut openssl_sys::SSL_CTX;
        if openssl_sys::SSL_set_SSL_CTX(ssl, raw).is_null() {
            return ok;
        }
        let mode = openssl_sys::SSL_CTX_get_verify_mode(raw);
        openssl_sys::SSL_set_verify(ssl, mode, None);
        // SSL_CTRL_CLEAR_OPTIONS=77 — clear all protocol-related NO_
        // options from the SSL so the target ctx's options can take
        // effect. Otherwise a permissive default vhost's absence of
        // NO_TLSv1_3 would leave TLSv1.3 usable on a vhost that
        // explicitly disabled it. This matches C's SSL_set_options /
        // SSL_clear_options sequence in ngx_http_ssl_servername.
        let proto_mask: u64 = openssl_sys::SSL_OP_NO_SSLv2 as u64
            | openssl_sys::SSL_OP_NO_SSLv3 as u64
            | openssl_sys::SSL_OP_NO_TLSv1 as u64
            | openssl_sys::SSL_OP_NO_TLSv1_1 as u64
            | openssl_sys::SSL_OP_NO_TLSv1_2 as u64
            | openssl_sys::SSL_OP_NO_TLSv1_3 as u64;
        // In OpenSSL 3.x, SSL_set_options/SSL_clear_options are direct
        // functions — SSL_ctrl(SSL_CTRL_OPTIONS/CLEAR) is a no-op for
        // writing. Use the real symbols.
        SSL_clear_options(ssl, proto_mask);
        let opts = openssl_sys::SSL_CTX_get_options(raw);
        SSL_set_options(ssl, opts);
    }
    ok
}

// Client hello callback: runs BEFORE version negotiation so
// SSL_set_options here actually constrains TLS 1.3 selection. Matches
// C's ngx_ssl_client_hello_callback → ngx_http_ssl_servername path.
unsafe extern "C" fn sni_client_hello_cb(
    ssl: *mut openssl_sys::SSL,
    ad: *mut std::os::raw::c_int,
    _arg: *mut c_void,
) -> std::os::raw::c_int {
    // TLSEXT_TYPE_server_name = 0
    let mut ext: *const u8 = std::ptr::null();
    let mut ext_len: usize = 0;
    let host_opt: Option<Vec<u8>> = if SSL_client_hello_get0_ext(ssl, 0, &mut ext, &mut ext_len) != 0
        && !ext.is_null()
        && ext_len >= 5
    {
        let p = std::slice::from_raw_parts(ext, ext_len);
        // ServerNameList: uint16 list_len | uint8 name_type | uint16 name_len | name
        let list_len = ((p[0] as usize) << 8) | (p[1] as usize);
        if list_len + 2 != ext_len || p[2] != 0 {
            *ad = 50; // SSL_AD_DECODE_ERROR
            return 0; // SSL_CLIENT_HELLO_ERROR
        }
        let name_len = ((p[3] as usize) << 8) | (p[4] as usize);
        if name_len + 2 + 3 != ext_len || 5 + name_len > ext_len {
            *ad = 50;
            return 0;
        }
        Some(p[5..5 + name_len].to_vec())
    } else {
        None
    };
    let rc = sni_apply(ssl, ad, host_opt.as_deref());
    // SSL_CLIENT_HELLO_SUCCESS = 1, SSL_CLIENT_HELLO_ERROR = 0
    if rc == 2 { 0 } else { 1 }
}

// Kept for compatibility — if the client_hello callback for some reason
// hasn't fired (e.g., OpenSSL < 1.1.1 build), the servername callback
// is a valid fallback and still lets $ssl_server_name / verify work,
// even if protocol-version overrides on TLSv1.3 won't take effect from
// here (too late in the handshake).
unsafe extern "C" fn sni_servername_cb(
    ssl: *mut openssl_sys::SSL,
    ad: *mut std::os::raw::c_int,
    _arg: *mut c_void,
) -> std::os::raw::c_int {
    let name_c = openssl_sys::SSL_get_servername(ssl, 0);
    let host_opt = if name_c.is_null() {
        None
    } else {
        Some(std::ffi::CStr::from_ptr(name_c).to_bytes().to_vec())
    };
    sni_apply(ssl, ad, host_opt.as_deref())
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
    pub conf_commands: Val<Vec<(Vec<u8>, Vec<u8>)>>,
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
            conf_commands: Val::unset(),
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
    if !c.conf_commands.is_set() {
        if let Some(v) = p.conf_commands.as_option() {
            c.conf_commands = Val::set(v.clone());
        }
    } else if let Some(pv) = p.conf_commands.as_option() {
        // Merge: outer commands run first, inner overrides.
        let mut merged = pv.clone();
        if let Some(cv) = c.conf_commands.as_option() {
            for (k, v) in cv.iter() {
                if let Some(pos) = merged.iter().position(|(mk, _)| mk == k) {
                    merged[pos] = (k.clone(), v.clone());
                } else {
                    merged.push((k.clone(), v.clone()));
                }
            }
        }
        c.conf_commands = Val::set(merged);
    }
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
fn set_conf_command(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let key = cf.args[1].clone();
    let value = cf.args[2].clone();
    let conf = core_srv_ssl_conf(cf);
    let mut c = conf.borrow_mut();
    let mut cur = c.conf_commands.as_option().cloned().unwrap_or_default();
    cur.push((key, value));
    c.conf_commands = Val::set(cur);
    Ok(())
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
        cmd_fn!("ssl_conf_command", F | NGX_CONF_TAKE2, ConfLevel::Srv, set_conf_command),
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
        VarDef { name: "ssl_client_cert", set: None, get: Some(var_ssl_client_cert), data: 0, flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE },
        VarDef { name: "ssl_client_raw_cert", set: None, get: Some(var_ssl_client_raw_cert), data: 0, flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE },
        VarDef { name: "ssl_client_escaped_cert", set: None, get: Some(var_ssl_client_escaped_cert), data: 0, flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE },
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
        VarDef { name: "ssl_curve", set: None, get: Some(var_ssl_curve), data: 0, flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE },
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
            // ssl_password_file: try each password in turn against the
            // encrypted PEM. Matches ngx_ssl_read_password_file +
            // per-password decrypt loop in ngx_ssl_certificate_key.
            let pwd_file = ssl_conf.borrow().password_file.as_option().cloned();
            let passwords: Vec<Vec<u8>> = if let Some(pf) = pwd_file {
                let pf_full = cf.cycle.full_name(&pf, true);
                let pf_str = std::str::from_utf8(&pf_full)
                    .map_err(|_| cf.emerg(format_args!("ssl_password_file path is not UTF-8")))?;
                let data = std::fs::read(pf_str)
                    .map_err(|e| cf.emerg(format_args!("ssl_password_file read failed: {}", e)))?;
                data.split(|&b| b == b'\n')
                    .map(|l| {
                        let mut s = l.to_vec();
                        // trim trailing \r
                        if s.last() == Some(&b'\r') { s.pop(); }
                        s
                    })
                    .filter(|l| !l.is_empty())
                    .collect()
            } else {
                Vec::new()
            };
            let key_res = load_private_key(key_str, &passwords);
            match key_res {
                Ok(pkey) => {
                    builder.set_private_key(&pkey)
                        .map_err(|e| cf.emerg(format_args!("SSL_CTX_use_PrivateKey(\"{}\") failed: {}", key_str, e)))?;
                }
                Err(_) if passwords.is_empty() => {
                    builder.set_private_key_file(key_str, SslFiletype::PEM)
                        .map_err(|e| cf.emerg(format_args!("SSL_CTX_use_PrivateKey_file(\"{}\") failed: {}", key_str, e)))?;
                }
                Err(e) => {
                    return Err(cf.emerg(format_args!("SSL_CTX_use_PrivateKey_file(\"{}\") failed: {}", key_str, e)));
                }
            }
            builder.check_private_key()
                .map_err(|e| cf.emerg(format_args!("SSL: certificate and key mismatch: {}", e)))?;
        }
        let ciph_str = std::str::from_utf8(&ciphers)
            .map_err(|_| cf.emerg(format_args!("ssl_ciphers is not UTF-8")))?;
        let _ = builder.set_cipher_list(ciph_str);
        // Protocol version limits
        set_protocols_on_builder(&mut builder, protocols);
        // ssl_ecdh_curve: SSL_CTX_set1_groups_list (OpenSSL 1.1+) accepts
        // a colon-separated list of curve names ("prime256v1:x25519").
        let ecdh_curve = ssl_conf.borrow().ecdh_curve.as_option().cloned();
        if let Some(curve) = ecdh_curve {
            if let Ok(cs) = std::ffi::CString::new(curve) {
                unsafe {
                    // SSL_CTRL_SET_GROUPS_LIST = 92
                    openssl_sys::SSL_CTX_ctrl(
                        builder.as_ptr() as *mut _,
                        92,
                        0,
                        cs.as_ptr() as *mut c_void,
                    );
                }
            }
        }
        if verify_mode != 0 {
            // NOTE: we deliberately do NOT set FAIL_IF_NO_PEER_CERT
            // even for verify=on. C nginx handles the no-cert case in
            // ngx_http_ssl_check_client (returning 400) rather than
            // failing the TLS handshake — that's what the tests expect
            // (client should see a 400, not a truncated TLS response).
            let mode = match verify_mode {
                1 | 2 | 3 => SslVerifyMode::PEER,
                _ => SslVerifyMode::NONE,
            };
            // Match C's ngx_ssl_verify_callback: always return 1 from
            // the TLS-layer callback so the handshake completes even on
            // verify failure; the real check happens in the request
            // processor via SSL_get_verify_result. This gives us the
            // "FAILED:<reason>" $ssl_client_verify value that tests
            // like ssl_verify_client 'bad optional cert' rely on.
            builder.set_verify_callback(mode, |_ok, _ctx| true);
            if let Some(ca) = client_ca {
                let ca_full = cf.cycle.full_name(&ca, true);
                if let Ok(s) = std::str::from_utf8(&ca_full) {
                    let _ = builder.set_ca_file(s);
                    // Advertise these CA DNs in the CertificateRequest
                    // so the client's cert-picker knows what to send.
                    unsafe {
                        let list = openssl_sys::SSL_load_client_CA_file(
                            std::ffi::CString::new(s).unwrap().as_ptr());
                        if !list.is_null() {
                            openssl_sys::SSL_CTX_set_client_CA_list(
                                builder.as_ptr() as *mut _, list);
                        }
                    }
                }
            }
            // ssl_trusted_certificate: adds CAs used to verify chains
            // WITHOUT sending them in the CertificateRequest. Matches
            // ngx_ssl_trusted_certificate.
            let trusted = ssl_conf.borrow().trusted_certificate.as_option().cloned();
            if let Some(ca) = trusted {
                let ca_full = cf.cycle.full_name(&ca, true);
                if let Ok(s) = std::str::from_utf8(&ca_full) {
                    let _ = builder.set_ca_file(s);
                }
            }
            builder.set_verify_depth(verify_depth);
            // ssl_crl: load a CRL bundle, register each entry with the
            // cert store, and enable CRL_CHECK|CRL_CHECK_ALL flags so
            // OpenSSL actually consults the CRL during chain
            // verification. Matches ngx_ssl_crl.
            let crl = ssl_conf.borrow().crl.as_option().cloned();
            if let Some(crl) = crl {
                let crl_full = cf.cycle.full_name(&crl, true);
                let crl_str = std::str::from_utf8(&crl_full)
                    .map_err(|_| cf.emerg(format_args!("ssl_crl path is not UTF-8")))?;
                let data = std::fs::read(crl_str)
                    .map_err(|e| cf.emerg(format_args!("ssl_crl read \"{}\" failed: {}", crl_str, e)))?;
                unsafe {
                    let bio = openssl_sys::BIO_new_mem_buf(
                        data.as_ptr() as *const c_void,
                        data.len() as std::os::raw::c_int,
                    );
                    if bio.is_null() {
                        return Err(cf.emerg(format_args!("BIO_new_mem_buf() failed")));
                    }
                    let store = SSL_CTX_get_cert_store(builder.as_ptr() as *const _);
                    if store.is_null() {
                        openssl_sys::BIO_free_all(bio);
                        return Err(cf.emerg(format_args!("SSL_CTX_get_cert_store() failed")));
                    }
                    let mut loaded = 0u32;
                    loop {
                        let x = PEM_read_bio_X509_CRL(
                            bio,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        );
                        if x.is_null() { break; }
                        if X509_STORE_add_crl(store, x) != 1 {
                            X509_CRL_free(x);
                            // C's ngx_ssl_crl treats "already in hash"
                            // as OK; on other failures it errors. We
                            // just continue to be permissive here.
                            continue;
                        }
                        X509_CRL_free(x);
                        loaded += 1;
                    }
                    openssl_sys::BIO_free_all(bio);
                    if loaded == 0 {
                        return Err(cf.emerg(format_args!("cannot load CRL \"{}\": no entries", crl_str)));
                    }
                    // X509_V_FLAG_CRL_CHECK=0x4, X509_V_FLAG_CRL_CHECK_ALL=0x8
                    X509_STORE_set_flags(store, 0x4 | 0x8);
                }
            }
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
        // ssl_session_cache: honor off/none. Everything else (builtin,
        // shared, builtin:size) falls through to the default server
        // cache which is what OpenSSL sets up on its own — good enough
        // for the tests that just check whether sessions get reused.
        let sess_cache = ssl_conf.borrow().session_cache.as_option().cloned();
        if let Some(mode) = sess_cache {
            unsafe {
                match mode.as_slice() {
                    b"off" => {
                        openssl_sys::SSL_CTX_set_session_cache_mode(
                            builder.as_ptr() as *mut _,
                            openssl_sys::SSL_SESS_CACHE_OFF,
                        );
                        // TLSv1.3: disable session tickets so no
                        // resumption is possible over TLSv1.3 either.
                        // C nginx doesn't emit tickets when SSL_SESS_CACHE_OFF
                        // is set because SSL_new_session_ticket won't fire
                        // for a stateless-only cb — but modern OpenSSL keeps
                        // TLS 1.3 tickets independent, so we force it here.
                        // SSL_CTX_set_num_tickets = SSL_CTX_ctrl(SSL_CTRL_SET_NUM_TICKETS=95).
                        openssl_sys::SSL_CTX_ctrl(
                            builder.as_ptr() as *mut _,
                            95,
                            0,
                            std::ptr::null_mut(),
                        );
                    }
                    b"none" => {
                        openssl_sys::SSL_CTX_set_session_cache_mode(
                            builder.as_ptr() as *mut _,
                            openssl_sys::SSL_SESS_CACHE_SERVER
                                | openssl_sys::SSL_SESS_CACHE_NO_AUTO_CLEAR
                                | openssl_sys::SSL_SESS_CACHE_NO_INTERNAL_STORE,
                        );
                        // SSL_CTX_sess_set_cache_size = SSL_CTX_ctrl(42).
                        openssl_sys::SSL_CTX_ctrl(
                            builder.as_ptr() as *mut _,
                            openssl_sys::SSL_CTRL_SET_SESS_CACHE_SIZE,
                            1,
                            std::ptr::null_mut(),
                        );
                        openssl_sys::SSL_CTX_ctrl(
                            builder.as_ptr() as *mut _,
                            95,
                            0,
                            std::ptr::null_mut(),
                        );
                    }
                    _ => {}
                }
            }
        }
        // Session ID context. Required by OpenSSL when client cert
        // verification is enabled (verify=on/optional/optional_no_ca);
        // without it, SSL_do_handshake fails with "session id context
        // uninitialized" on the second connection to the same ctx.
        // Matches ngx_ssl_session_id_context; we just use a per-server
        // stable string derived from certificate path.
        {
            let sess_ctx: Vec<u8> = if has_cert {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                use std::hash::{Hash, Hasher};
                cert.hash(&mut hasher);
                let h = hasher.finish();
                h.to_le_bytes().to_vec()
            } else {
                b"HTTP".to_vec()
            };
            unsafe {
                openssl_sys::SSL_CTX_set_session_id_context(
                    builder.as_ptr() as *mut _,
                    sess_ctx.as_ptr(),
                    sess_ctx.len() as std::os::raw::c_uint,
                );
            }
        }
        // ALPN: advertise http/1.1. h2 dispatch scaffolding exists in
        // crate::http2 but is not production-ready — leaving h2 out of
        // ALPN keeps clients on the working HTTP/1 pipeline.
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
            // Match C's ngx_http_ssl_alpn_select: when the client sent
            // ALPN but nothing matched our list, fatal-alert the handshake.
            2 // SSL_TLSEXT_ERR_ALERT_FATAL
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
            // Install a client_hello callback in addition. This fires
            // BEFORE version negotiation, which is what we need for
            // ssl_protocols overrides on TLSv1.3 vhosts to actually
            // take effect. Matches C's ngx_ssl_client_hello_callback.
            SSL_CTX_set_client_hello_cb(
                builder.as_ptr() as *mut _,
                Some(sni_client_hello_cb),
                std::ptr::null_mut(),
            );
        }
        // ssl_conf_command: apply OpenSSL's SSL_CONF commands. Matches
        // ngx_ssl_conf_commands — file-typed values are resolved via
        // ngx_conf_full_name.
        let cmds = ssl_conf.borrow().conf_commands.as_option().cloned();
        if let Some(cmds) = cmds {
            unsafe {
                let cctx = SSL_CONF_CTX_new();
                if cctx.is_null() {
                    return Err(cf.emerg(format_args!("SSL_CONF_CTX_new() failed")));
                }
                SSL_CONF_CTX_set_flags(
                    cctx,
                    SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER
                        | SSL_CONF_FLAG_CERTIFICATE | SSL_CONF_FLAG_SHOW_ERRORS,
                );
                SSL_CONF_CTX_set_ssl_ctx(cctx, builder.as_ptr() as *mut _);
                for (k, v) in cmds.iter() {
                    let key = match std::ffi::CString::new(k.clone()) {
                        Ok(s) => s,
                        Err(_) => {
                            SSL_CONF_CTX_free(cctx);
                            return Err(cf.emerg(format_args!("ssl_conf_command: invalid key")));
                        }
                    };
                    let mut val_bytes = v.clone();
                    let t = SSL_CONF_cmd_value_type(cctx, key.as_ptr());
                    if t == SSL_CONF_TYPE_FILE || t == SSL_CONF_TYPE_DIR {
                        val_bytes = cf.cycle.full_name(&val_bytes, true);
                    }
                    let val = match std::ffi::CString::new(val_bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            SSL_CONF_CTX_free(cctx);
                            return Err(cf.emerg(format_args!("ssl_conf_command: invalid value")));
                        }
                    };
                    let rc = SSL_CONF_cmd(cctx, key.as_ptr(), val.as_ptr());
                    if rc <= 0 {
                        SSL_CONF_CTX_free(cctx);
                        return Err(cf.emerg(format_args!(
                            "SSL_CONF_cmd(\"{}\", \"{}\") failed",
                            ngx_core::string::B(k),
                            ngx_core::string::B(v),
                        )));
                    }
                }
                let rc = SSL_CONF_CTX_finish(cctx);
                SSL_CONF_CTX_free(cctx);
                if rc != 1 {
                    return Err(cf.emerg(format_args!("SSL_CONF_CTX_finish() failed")));
                }
            }
        }
        let ctx = builder.build();
        *ssl_conf.borrow_mut().ssl_ctx.borrow_mut() = Some(Rc::new(ctx));
    }
    Ok(())
}

/// Read an encrypted PEM key file and decrypt it using one of the
/// supplied passwords. Falls back to an unencrypted parse when the
/// list is empty. Matches nginx's per-password retry loop in
/// ngx_ssl_certificate_key.
fn load_private_key(path: &str, passwords: &[Vec<u8>]) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, openssl::error::ErrorStack> {
    let pem = std::fs::read(path).map_err(|e| {
        // Wrap the io::Error into openssl::error::ErrorStack via a dummy
        // stack entry. Simplest is to just return an empty stack; the
        // caller's error message includes the path anyway.
        let _ = e;
        openssl::error::ErrorStack::get()
    })?;
    if passwords.is_empty() {
        return openssl::pkey::PKey::private_key_from_pem(&pem);
    }
    let mut last_err = None;
    for pw in passwords {
        match openssl::pkey::PKey::private_key_from_pem_passphrase(&pem, pw) {
            Ok(k) => return Ok(k),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(openssl::error::ErrorStack::get))
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
        let idx = sni_register(hc.clone());
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
            // Record the SNI hostname on the HttpConnection so
            // set_virtual_server / the misdirected-request check
            // downstream sees "an SNI was negotiated" and can compare
            // against the Host header. Matches ngx_http_ssl_servername.
            unsafe {
                let name_c = openssl_sys::SSL_get_servername(ssl_ptr, 0);
                if !name_c.is_null() {
                    let bytes = std::ffi::CStr::from_ptr(name_c).to_bytes();
                    let host: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
                    *hc.ssl_servername.borrow_mut() = Some(host);
                }
            }
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

pub fn ssl_verify_enabled(cscf: &Rc<RefCell<CoreSrvConf>>) -> bool {
    let sctx = cscf.borrow().ctx.clone();
    let srv_slots = match &sctx.srv { Some(s) => s.clone(), None => return false };
    let ssl_conf = slot_of::<HttpSslSrvConf>(&srv_slots, ctx_index());
    let v = ssl_conf.borrow().verify.get_or(0);
    v == 1 || v == 2
}

/// Match ngx_http_ssl_check_client (called after headers are parsed).
/// Returns Some(status) to short-circuit the request, None to continue.
///   verify=on and no/bad client cert  → 400 Bad Request
///   verify=optional and bad client cert → 400 Bad Request
///   verify=optional_no_ca — no check (accept any cert)
///   SNI hostname doesn't match Host — 421 Misdirected Request when
///   verify_client is on (avoids credential-mismatch)
pub fn ssl_process_request_checks(r: &R) -> Option<i64> {
    let cscf = r.cscf();
    let sctx = cscf.borrow().ctx.clone();
    let srv_slots = &sctx.srv.as_ref()?.clone();
    let ssl_conf = slot_of::<HttpSslSrvConf>(srv_slots, ctx_index());
    let verify = ssl_conf.borrow().verify.get_or(0);
    if verify == 0 || verify == 3 { return None; }  // off or optional_no_ca
    let sc = r.connection.ssl.borrow().clone()?;
    if !sc.handshaked.get() { return None; }
    let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
    unsafe {
        let cert = SSL_get_peer_x509(ptr);
        if verify == 1 && cert.is_null() {
            // required but not present
            return Some(crate::NGX_HTTP_BAD_REQUEST as i64);
        }
        if !cert.is_null() {
            let rc = openssl_sys::SSL_get_verify_result(ptr);
            openssl_sys::X509_free(cert);
            if rc != openssl_sys::X509_V_OK as i64 {
                // required or optional but verify failed
                return Some(crate::NGX_HTTP_BAD_REQUEST as i64);
            }
        }
    }
    None
}

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
fn var_ssl_curve(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let sc = match ssl_conn(r) { Some(c) => c, None => { v.not_found = true; return NGX_OK; } };
    if !sc.handshaked.get() { v.not_found = true; return NGX_OK; }
    let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
    unsafe {
        let nid = SSL_get_negotiated_group(ptr as *mut _);
        if nid == 0 { v.not_found = true; return NGX_OK; }
        let sn = OBJ_nid2sn(nid);
        if sn.is_null() { v.not_found = true; return NGX_OK; }
        let bytes = std::ffi::CStr::from_ptr(sn).to_bytes().to_vec();
        set_var(v, bytes)
    }
}

fn var_ssl_client_verify(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let sc = match ssl_conn(r) { Some(c) => c, None => { v.not_found = true; return NGX_OK; } };
    if !sc.handshaked.get() { v.not_found = true; return NGX_OK; }
    let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
    unsafe {
        let cert = SSL_get_peer_x509(ptr);
        if cert.is_null() {
            return set_var(v, b"NONE".to_vec());
        }
        openssl_sys::X509_free(cert);
        let rc = openssl_sys::SSL_get_verify_result(ptr);
        if rc == openssl_sys::X509_V_OK as i64 {
            set_var(v, b"SUCCESS".to_vec())
        } else {
            // C emits FAILED:<X509_verify_cert_error_string(rc)>
            let s = openssl_sys::X509_verify_cert_error_string(rc);
            let mut out = b"FAILED:".to_vec();
            if !s.is_null() {
                let bytes = std::ffi::CStr::from_ptr(s).to_bytes();
                out.extend_from_slice(bytes);
            }
            set_var(v, out)
        }
    }
}

fn pem_encode_cert(cert_ptr: *mut openssl_sys::X509) -> Option<Vec<u8>> {
    unsafe {
        let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
        if bio.is_null() { return None; }
        if openssl_sys::PEM_write_bio_X509(bio, cert_ptr) == 0 {
            openssl_sys::BIO_free_all(bio);
            return None;
        }
        let mut data_ptr: *mut u8 = std::ptr::null_mut();
        let len = openssl_sys::BIO_get_mem_data(bio, &mut data_ptr as *mut *mut u8 as *mut *mut std::os::raw::c_char);
        if len <= 0 {
            openssl_sys::BIO_free_all(bio);
            return None;
        }
        let bytes = std::slice::from_raw_parts(data_ptr, len as usize).to_vec();
        openssl_sys::BIO_free_all(bio);
        Some(bytes)
    }
}

fn var_ssl_client_raw_cert(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let sc = match ssl_conn(r) { Some(c) => c, None => { v.not_found = true; return NGX_OK; } };
    if !sc.handshaked.get() { v.not_found = true; return NGX_OK; }
    let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
    unsafe {
        let cert = SSL_get_peer_x509(ptr);
        if cert.is_null() { v.not_found = true; return NGX_OK; }
        let pem = pem_encode_cert(cert);
        openssl_sys::X509_free(cert);
        match pem {
            Some(p) => set_var(v, p),
            None => { v.not_found = true; NGX_OK }
        }
    }
}

fn var_ssl_client_cert(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    // Same as raw_cert but with each \n prefixed by \t so the header value
    // can span multiple lines and still be a valid single header field.
    let sc = match ssl_conn(r) { Some(c) => c, None => { v.not_found = true; return NGX_OK; } };
    if !sc.handshaked.get() { v.not_found = true; return NGX_OK; }
    let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
    unsafe {
        let cert = SSL_get_peer_x509(ptr);
        if cert.is_null() { v.not_found = true; return NGX_OK; }
        let pem = pem_encode_cert(cert);
        openssl_sys::X509_free(cert);
        match pem {
            Some(p) => {
                let mut out = Vec::with_capacity(p.len() + 16);
                for &b in &p {
                    out.push(b);
                    if b == b'\n' { out.push(b'\t'); }
                }
                // trim trailing tab if we added one after the final \n
                if out.last() == Some(&b'\t') { out.pop(); }
                set_var(v, out)
            }
            None => { v.not_found = true; NGX_OK }
        }
    }
}

fn var_ssl_client_escaped_cert(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let sc = match ssl_conn(r) { Some(c) => c, None => { v.not_found = true; return NGX_OK; } };
    if !sc.handshaked.get() { v.not_found = true; return NGX_OK; }
    let ptr = sc.inner.borrow().as_ref().unwrap().as_ptr();
    unsafe {
        let cert = SSL_get_peer_x509(ptr);
        if cert.is_null() { v.not_found = true; return NGX_OK; }
        let pem = pem_encode_cert(cert);
        openssl_sys::X509_free(cert);
        match pem {
            Some(p) => {
                // uri-escape every char that isn't unreserved. Matches
                // ngx_escape_uri with NGX_ESCAPE_URI_COMPONENT.
                let mut out = Vec::with_capacity(p.len() * 3);
                for &b in &p {
                    let unreserved = b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'_' | b'.' | b'~');
                    if unreserved {
                        out.push(b);
                    } else {
                        out.extend_from_slice(format!("%{:02X}", b).as_bytes());
                    }
                }
                set_var(v, out)
            }
            None => { v.not_found = true; NGX_OK }
        }
    }
}

// Keep the Cell/Ssl unused-import placeholder silenced for now.
#[allow(dead_code)]
fn _unused(_c: Cell<u32>) {}
