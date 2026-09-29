//! ngx_http_proxy_module - HTTP proxy with upstream framework

use std::any::Any;
use std::rc::Rc;
use std::io::Write;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::cmd_fn;
use ngx_core::conf::{NGX_CONF_TAKE1, NGX_CONF_TAKE2, NGX_CONF_TAKE3, NGX_CONF_TAKE4, NGX_CONF_TAKE12, NGX_CONF_TAKE123, NGX_CONF_TAKE1234, NGX_CONF_1MORE, NGX_CONF_2MORE};
use tokio::net::TcpStream;

pub use crate::upstream::UpstreamSock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::cell::RefCell;

use ngx_core::event_openssl::{
    ngx_ssl_certificate, ngx_ssl_ciphers, ngx_ssl_client_session_cache, ngx_ssl_conf_commands, ngx_ssl_create, ngx_ssl_crl, ngx_ssl_read_password_file,
    ngx_ssl_trusted_certificate, NgxSsl, NGX_SSL_DEFAULT_PROTOCOLS,
};

use crate::core::*;
use crate::request::*;
use crate::upstream::*;
use crate::variables::VarDef;
use crate::get_loc_conf;
use crate::{NGX_HTTP_MAIN_CONF, NGX_HTTP_SRV_CONF, NGX_HTTP_LOC_CONF, NGX_HTTP_LIF_CONF, NGX_HTTP_LMT_CONF, NGX_HTTP_BAD_GATEWAY, NGX_HTTP_OK, NGX_HTTP_HEAD, HttpModuleDef, http_module_def};

crate::http_module_index!("ngx_http_proxy_module");

/// Proxy location configuration
pub struct NgxHttpProxyLocConf {
    pub upstream_uri: Option<Vec<u8>>,  // proxy_pass URL (literal, for static parsing)
    /// If the proxy_pass URI contains `$variable` references, we compile it
    /// as a ComplexValue at config time and expand at request time. Matches
    /// C's ngx_http_proxy_eval path: parse the expanded string as a URL,
    /// resolve host/port, and forward the rest as the upstream path.
    pub upstream_uri_cv: Option<crate::script::ComplexValue>,
    /// proxy_method: overrides the request method sent to upstream. Supports
    /// variable interpolation via ComplexValue. Defaults to forwarding the
    /// client's method.
    pub method: Option<crate::script::ComplexValue>,
    /// proxy_intercept_errors: if on, upstream >= 400 responses are handled by
    /// the local error_page instead of being forwarded to the client.
    pub intercept_errors: Val<bool>,
    /// proxy_pass_request_headers: forward client headers to upstream (default on).
    pub pass_request_headers: Val<bool>,
    /// proxy_pass_request_body: forward client body to upstream (default on).
    pub pass_request_body: Val<bool>,
    /// proxy_request_buffering (default on).
    pub request_buffering: Val<bool>,
    /// proxy_buffering (default on): u->buffering
    pub buffering: Val<bool>,
    /// proxy_connect_timeout (default 60s): connecting, and the TLS
    /// handshake.
    pub connect_timeout: Val<u64>,
    /// plcf->ssl: proxy_pass to https, or with variables (the location
    /// needs the SSL context, ngx_http_proxy_set_ssl).
    pub ssl: bool,
    /// proxy_ssl_protocols (a bitmask, 0 when not set).
    pub ssl_protocols: u32,
    /// proxy_ssl_ciphers (default "DEFAULT").
    pub ssl_ciphers: Val<Vec<u8>>,
    /// proxy_ssl_verify_depth (default 1).
    pub ssl_verify_depth: Val<i64>,
    /// proxy_ssl_trusted_certificate.
    pub ssl_trusted_certificate: Val<Vec<u8>>,
    /// proxy_ssl_crl.
    pub ssl_crl: Val<Vec<u8>>,
    /// proxy_ssl_conf_command.
    pub ssl_conf_commands: Val<Option<Vec<(Vec<u8>, Vec<u8>)>>>,
    /// The SSL fields of plcf->upstream: proxy_ssl_session_reuse,
    /// proxy_ssl_name, proxy_ssl_server_name, proxy_ssl_verify,
    /// proxy_ssl_certificate, proxy_ssl_certificate_key,
    /// proxy_ssl_certificate_cache, proxy_ssl_password_file, and the context.
    pub upstream_ssl: crate::upstream_ssl::UpstreamSslConf,
    /// proxy_set_body: overrides the request body sent upstream (complex value).
    pub set_body: Option<crate::script::ComplexValue>,
    /// proxy_set_header entries: (name, complex value). Empty value drops the
    /// header. Overrides same-name client headers. Matches C's list-of-entries
    /// semantic though we keep it simple (no upstream defaults inheritance).
    pub set_headers: Vec<(Vec<u8>, crate::script::ComplexValue)>,
    /// proxy_force_ranges: force range processing on non-file proxy responses.
    pub force_ranges: Val<bool>,
    /// proxy_cookie_domain rewrites (applied to Domain= attributes of Set-Cookie).
    pub cookie_domains: Vec<CookieRewrite>,
    /// proxy_cookie_path rewrites (applied to Path= attributes of Set-Cookie).
    pub cookie_paths: Vec<CookieRewrite>,
    /// proxy_bind: local address to bind the upstream socket to. `None` means
    /// unset (inherit); Some(LocalBind::Off) means explicitly disabled;
    /// Some(LocalBind::Addr(cv)) means bind to the evaluated ComplexValue.
    pub local_bind: Option<LocalBind>,
    /// proxy_store: write successful upstream responses to disk.
    /// `None` = inherit; Some(ProxyStore::Off/On/Path(cv)).
    pub store: Option<ProxyStore>,
    /// proxy_next_upstream: bitmask of conditions that trigger a retry.
    /// See NGX_HTTP_UPSTREAM_FT_* below. `Val::unset()` means inherit.
    pub next_upstream_mask: Val<u32>,
    /// proxy_next_upstream_tries: 0 = no limit.
    pub next_upstream_tries: Val<u32>,
    /// proxy_next_upstream_timeout: 0 = no limit.
    pub next_upstream_timeout: Val<u64>,
    /// proxy_read_timeout (default 60s)
    pub read_timeout: Val<u64>,
    /// the upstream of a proxy_pass URL without variables
    /// (ngx_http_upstream_add)
    pub upstream: Option<Rc<crate::upstream::UpstreamSrvConf>>,
    /// plcf->vars.uri: the URI part of a proxy_pass URL without variables
    pub vars_uri: Vec<u8>,
    /// proxy_redirect entries. Reuses CookieRewrite because the substitution
    /// machinery is the same (literal, complex or regex pattern → replacement).
    pub redirects: Vec<CookieRewrite>,
    /// Set by `proxy_redirect off;` to disable inheritance and any rewrites.
    pub redirect_off: bool,
    /// Set by `proxy_redirect default` — resolved at first-request time by
    /// combining the proxy_pass URL and the location name.
    pub redirect_default: bool,
    /// proxy_cookie_flags entries.
    pub cookie_flags: Vec<CookieFlagsRule>,
    /// proxy_http_version: 0 = 1.0 (default), 1 = 1.1.
    pub http_version: Val<u32>,
    /// proxy_hide_header entries (lowercase). `None` = inherit from parent;
    /// `Some(list)` = explicit local list (still merged with defaults).
    pub hide_headers: Option<Vec<Vec<u8>>>,
    /// proxy_pass_header entries (lowercase). Same inheritance rule as
    /// hide_headers. Pass overrides any hide (default or explicit) for the
    /// named header.
    pub pass_headers: Option<Vec<Vec<u8>>>,
    /// proxy_cache*: nested container so cache directives don't push the
    /// per-request runtime through the whole conf when caching is off.
    pub cache: crate::proxy_cache::ProxyCacheConf,
}

/// Default list of upstream response headers that nginx hides. See
/// ngx_http_proxy_hide_headers in C.
pub const PROXY_HIDE_HEADERS: &[&[u8]] = &[
    b"date",
    b"server",
    b"x-pad",
    b"x-accel-expires",
    b"x-accel-redirect",
    b"x-accel-limit-rate",
    b"x-accel-buffering",
    b"x-accel-charset",
];

// Cookie flag bits (matches ngx_http_proxy_module NGX_HTTP_PROXY_COOKIE_*).
pub const CF_SECURE_ON: u32          = 0x0001;
pub const CF_SECURE_OFF: u32         = 0x0002;
pub const CF_HTTPONLY_ON: u32        = 0x0004;
pub const CF_HTTPONLY_OFF: u32       = 0x0008;
pub const CF_SAMESITE_STRICT: u32    = 0x0010;
pub const CF_SAMESITE_LAX: u32       = 0x0020;
pub const CF_SAMESITE_NONE: u32      = 0x0040;
pub const CF_SAMESITE_OFF: u32       = 0x0080;

#[derive(Clone)]
pub struct CookieFlagsRule {
    pub matcher: CookieMatcher,
    pub flags: u32,
    /// Complex-value flag tokens whose text is evaluated per request.
    pub complex_flags: Vec<crate::script::ComplexValue>,
}

#[derive(Clone)]
pub enum CookieMatcher {
    /// Off sentinel (from `proxy_cookie_flags off`).
    Off,
    /// Complex value matched exactly against the cookie's Name attribute.
    Name(crate::script::ComplexValue),
    /// Regex against cookie Name (case-sensitive or insensitive).
    Regex(Rc<ngx_core::regex::Regex>),
}

// Retry condition flags (ngx_http_upstream.h NGX_HTTP_UPSTREAM_FT_*).
pub const FT_ERROR: u32          = 0x00000002;
pub const FT_TIMEOUT: u32        = 0x00000004;
pub const FT_INVALID_HEADER: u32 = 0x00000008;
pub const FT_HTTP_500: u32       = 0x00000010;
pub const FT_HTTP_502: u32       = 0x00000020;
pub const FT_HTTP_503: u32       = 0x00000040;
pub const FT_HTTP_504: u32       = 0x00000080;
pub const FT_HTTP_403: u32       = 0x00000100;
pub const FT_HTTP_404: u32       = 0x00000200;
pub const FT_HTTP_429: u32       = 0x00000400;
pub const FT_UPDATING: u32       = 0x00000800;
pub const FT_BUSY_LOCK: u32      = 0x00001000;
pub const FT_MAX_WAITING: u32    = 0x00002000;
pub const FT_NON_IDEMPOTENT: u32 = 0x00004000;
pub const FT_NOLIVE: u32         = 0x40000000;
pub const FT_OFF: u32            = 0x80000000;


#[derive(Clone)]
pub enum ProxyStore {
    Off,
    /// Path derived from map_uri_to_path (root/alias).
    On,
    /// Explicit script-evaluated path (may include $vars).
    Path(crate::script::ComplexValue),
}

#[derive(Clone)]
pub enum LocalBind {
    Off,
    Addr(crate::script::ComplexValue),
}

/// A single proxy_cookie_domain / proxy_cookie_path rewrite entry.
/// Matches ngx_http_proxy_rewrite_t.
#[derive(Clone)]
pub enum CookieRewritePattern {
    /// Domain literal or complex value (matches full attribute value,
    /// case-insensitively, with an optional leading '.' stripped).
    Domain(crate::script::ComplexValue),
    /// Path literal or complex value (prefix match).
    Path(crate::script::ComplexValue),
    /// Regex match (case-sensitive or insensitive).
    Regex(Rc<ngx_core::regex::Regex>),
}

#[derive(Clone)]
pub struct CookieRewrite {
    pub pattern: CookieRewritePattern,
    pub replacement: crate::script::ComplexValue,
}

impl Default for NgxHttpProxyLocConf {
    fn default() -> Self {
        NgxHttpProxyLocConf {
            upstream_uri: None,
            upstream_uri_cv: None,
            method: None,
            intercept_errors: Val::unset(),
            pass_request_headers: Val::unset(),
            pass_request_body: Val::unset(),
            request_buffering: Val::unset(),
            buffering: Val::unset(),
            connect_timeout: Val::unset(),
            ssl: false,
            ssl_protocols: 0,
            ssl_ciphers: Val::unset(),
            ssl_verify_depth: Val::unset(),
            ssl_trusted_certificate: Val::unset(),
            ssl_crl: Val::unset(),
            ssl_conf_commands: Val::unset(),
            upstream_ssl: crate::upstream_ssl::UpstreamSslConf::default(),
            set_body: None,
            set_headers: Vec::new(),
            force_ranges: Val::unset(),
            cookie_domains: Vec::new(),
            cookie_paths: Vec::new(),
            local_bind: None,
            store: None,
            next_upstream_mask: Val::unset(),
            next_upstream_tries: Val::unset(),
            next_upstream_timeout: Val::unset(),
            read_timeout: Val::unset(),
            upstream: None,
            vars_uri: Vec::new(),
            redirects: Vec::new(),
            redirect_off: false,
            redirect_default: false,
            cookie_flags: Vec::new(),
            http_version: Val::unset(),
            hide_headers: None,
            pass_headers: None,
            cache: crate::proxy_cache::ProxyCacheConf::new(),
        }
    }
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(NgxHttpProxyLocConf::default())
}

fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let mut p = conf_cell::<NgxHttpProxyLocConf>(prev).borrow_mut();
    let mut c = conf_cell::<NgxHttpProxyLocConf>(conf).borrow_mut();
    merge_ssl(cf, &mut p, &mut c)?;
    if c.method.is_none() {
        c.method = p.method.clone();
    }
    c.intercept_errors.merge(&p.intercept_errors, false);
    c.pass_request_headers.merge(&p.pass_request_headers, true);
    c.pass_request_body.merge(&p.pass_request_body, true);
    c.request_buffering.merge(&p.request_buffering, true);
    c.buffering.merge(&p.buffering, true);
    c.connect_timeout.merge(&p.connect_timeout, 60000);
    if c.set_body.is_none() {
        c.set_body = p.set_body.clone();
    }
    if c.set_headers.is_empty() {
        c.set_headers = p.set_headers.clone();
    }
    c.force_ranges.merge(&p.force_ranges, false);
    if c.cookie_domains.is_empty() {
        c.cookie_domains = p.cookie_domains.clone();
    }
    if c.cookie_paths.is_empty() {
        c.cookie_paths = p.cookie_paths.clone();
    }
    if c.local_bind.is_none() {
        c.local_bind = p.local_bind.clone();
    }
    if c.store.is_none() {
        c.store = p.store.clone();
    }
    // FT_ERROR | FT_TIMEOUT is the C default (see ngx_http_proxy_module.c).
    c.next_upstream_mask.merge(&p.next_upstream_mask, FT_ERROR | FT_TIMEOUT);
    if c.next_upstream_mask.is_set() && *c.next_upstream_mask.get() & FT_OFF != 0 {
        c.next_upstream_mask = Val::set(0);
    }
    c.next_upstream_tries.merge(&p.next_upstream_tries, 0);
    c.next_upstream_timeout.merge(&p.next_upstream_timeout, 0);
    c.read_timeout.merge(&p.read_timeout, 60000);
    // Inherit redirect rules unless this location explicitly disabled them
    // with `proxy_redirect off;` or already set its own rules.
    if !c.redirect_off && c.redirects.is_empty() && !c.redirect_default {
        c.redirects = p.redirects.clone();
        c.redirect_default = p.redirect_default;
    }
    // Match ngx_http_proxy_module: with no proxy_redirect directive at all,
    // the effective mode is `default` (implicit). We only turn it off if the
    // user explicitly wrote `proxy_redirect off;`.
    if !c.redirect_off && c.redirects.is_empty() && !c.redirect_default {
        c.redirect_default = true;
    }
    // Inherit cookie_flags unless this location listed its own.
    if c.cookie_flags.is_empty() {
        c.cookie_flags = p.cookie_flags.clone();
    }
    c.http_version.merge(&p.http_version, 0);
    // Inherit hide/pass lists independently: if child didn't set its own,
    // inherit from parent. Matches ngx_http_upstream_hide_headers_hash
    // which pulls each list from prev when NGX_CONF_UNSET_PTR.
    if c.hide_headers.is_none() { c.hide_headers = p.hide_headers.clone(); }
    if c.pass_headers.is_none() { c.pass_headers = p.pass_headers.clone(); }

    // the proxy_pass of the enclosing location is inherited by the "if"
    // and "limit_except" blocks only (conf->upstream.upstream, location,
    // vars, proxy_lengths/values and ssl), not by nested locations
    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    if clcf.borrow().noname && c.upstream.is_none() && c.upstream_uri_cv.is_none() {
        c.upstream = p.upstream.clone();
        c.upstream_uri = p.upstream_uri.clone();
        c.vars_uri = p.vars_uri.clone();

        c.upstream_uri_cv = p.upstream_uri_cv.clone();

        c.ssl = p.ssl;
    }

    let lmt_excpt_no_handler = {
        let l = clcf.borrow();
        l.lmt_excpt && l.handler.is_none()
    };

    if lmt_excpt_no_handler && (c.upstream.is_some() || c.upstream_uri_cv.is_some()) {
        clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(proxy_handler(r))));
    }

    // proxy_cache_* inheritance — location-level overrides win, otherwise
    // pull each field from the parent (matches C's per-field
    // ngx_conf_merge_ptr_value / merge_str_value pattern).
    if c.cache.zone.is_none() && !c.cache.explicitly_off {
        c.cache.zone = p.cache.zone.clone();
        c.cache.zone_cv = p.cache.zone_cv.clone();
    }
    if c.cache.key.is_none() { c.cache.key = p.cache.key.clone(); }
    if c.cache.valid.is_empty() { c.cache.valid = p.cache.valid.clone(); }
    if c.cache.bypass.is_empty() { c.cache.bypass = p.cache.bypass.clone(); }
    if c.cache.no_cache.is_empty() { c.cache.no_cache = p.cache.no_cache.clone(); }
    if c.cache.ignore_headers.is_empty() { c.cache.ignore_headers = p.cache.ignore_headers.clone(); }
    if !c.cache.lock { c.cache.lock = p.cache.lock; }
    if c.cache.lock_timeout_ms == 5000 { c.cache.lock_timeout_ms = p.cache.lock_timeout_ms; }
    if c.cache.lock_age_ms == 5000 { c.cache.lock_age_ms = p.cache.lock_age_ms; }
    if !c.cache.revalidate { c.cache.revalidate = p.cache.revalidate; }
    if c.cache.use_stale == 0 { c.cache.use_stale = p.cache.use_stale; }
    if !c.cache.background_update { c.cache.background_update = p.cache.background_update; }
    if c.cache.max_range_offset.is_none() { c.cache.max_range_offset = p.cache.max_range_offset; }
    if c.cache.min_uses == 1 { c.cache.min_uses = p.cache.min_uses; }
    Ok(())
}

/// The proxy_ssl_* part of ngx_http_proxy_merge_loc_conf, with
/// ngx_http_proxy_merge_ssl, ngx_http_upstream_merge_ssl_passwords and
/// ngx_http_proxy_set_ssl.
fn merge_ssl(cf: &mut Conf, prev: &mut NgxHttpProxyLocConf, conf: &mut NgxHttpProxyLocConf) -> ConfResult {
    use crate::upstream_ssl::merge_ptr;

    proxy_merge_ssl(cf, conf, prev);

    conf.upstream_ssl.ssl_session_reuse.merge(&prev.upstream_ssl.ssl_session_reuse, true);

    // ngx_conf_merge_bitmask_value
    if conf.ssl_protocols == 0 {
        conf.ssl_protocols = if prev.ssl_protocols == 0 { NGX_CONF_BITMASK_SET | NGX_SSL_DEFAULT_PROTOCOLS } else { prev.ssl_protocols };
    }

    conf.ssl_ciphers.merge(&prev.ssl_ciphers, b"DEFAULT".to_vec());

    merge_ptr(&mut conf.upstream_ssl.ssl_name, &prev.upstream_ssl.ssl_name);
    conf.upstream_ssl.ssl_server_name.merge(&prev.upstream_ssl.ssl_server_name, false);
    conf.upstream_ssl.ssl_verify.merge(&prev.upstream_ssl.ssl_verify, false);
    conf.ssl_verify_depth.merge(&prev.ssl_verify_depth, 1);
    conf.ssl_trusted_certificate.merge(&prev.ssl_trusted_certificate, Vec::new());
    conf.ssl_crl.merge(&prev.ssl_crl, Vec::new());

    merge_ptr(&mut conf.upstream_ssl.ssl_certificate, &prev.upstream_ssl.ssl_certificate);
    merge_ptr(&mut conf.upstream_ssl.ssl_certificate_key, &prev.upstream_ssl.ssl_certificate_key);
    merge_ptr(&mut conf.upstream_ssl.ssl_certificate_cache, &prev.upstream_ssl.ssl_certificate_cache);

    crate::upstream_ssl::merge_ssl_passwords(cf, &mut conf.upstream_ssl, &mut prev.upstream_ssl)?;

    merge_ptr(&mut conf.ssl_conf_commands, &prev.ssl_conf_commands);

    if conf.ssl {
        proxy_set_ssl(cf, conf)?;
    }

    Ok(())
}

/// ngx_http_proxy_merge_ssl: the context of the parent level when the
/// level has no SSL directive, else a new one.
fn proxy_merge_ssl(cf: &mut Conf, conf: &mut NgxHttpProxyLocConf, prev: &mut NgxHttpProxyLocConf) {
    let u = &conf.upstream_ssl;

    let preserve = if conf.ssl_protocols == 0
        && !conf.ssl_ciphers.is_set()
        && !u.ssl_certificate.is_set()
        && !u.ssl_certificate_key.is_set()
        && !u.ssl_passwords.is_set()
        && !u.ssl_verify.is_set()
        && !conf.ssl_verify_depth.is_set()
        && !conf.ssl_trusted_certificate.is_set()
        && !conf.ssl_crl.is_set()
        && !u.ssl_session_reuse.is_set()
        && !conf.ssl_conf_commands.is_set()
    {
        if let Some(ssl) = prev.upstream_ssl.ssl.clone() {
            conf.upstream_ssl.ssl = Some(ssl);
            return;
        }

        true
    } else {
        false
    };

    let ssl = Rc::new(RefCell::new(NgxSsl::new(cf.log.clone())));

    conf.upstream_ssl.ssl = Some(ssl.clone());

    // special handling to preserve conf->upstream.ssl
    // in the "http" section to inherit it to all servers

    if preserve {
        prev.upstream_ssl.ssl = Some(ssl);
    }
}

/// ngx_http_proxy_set_ssl: the context of the upstream connections
fn proxy_set_ssl(cf: &mut Conf, plcf: &mut NgxHttpProxyLocConf) -> ConfResult {
    let ssl = plcf.upstream_ssl.ssl.clone().expect("ssl");
    let mut ssl = ssl.borrow_mut();

    if !ssl.ctx.is_null() {
        return Ok(());
    }

    if ngx_ssl_create(&mut ssl, plcf.ssl_protocols, std::ptr::null_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    // the context is freed with the ngx_ssl_t (ngx_ssl_cleanup_ctx)

    let ciphers = plcf.ssl_ciphers.get().clone();

    if ngx_ssl_ciphers(cf, &mut ssl, &ciphers, false) != NGX_OK {
        return Err(ConfError::Logged);
    }

    let u = &plcf.upstream_ssl;

    if let Some(cert) = u.ssl_certificate.as_option().cloned().flatten() {
        if !cert.value.is_empty() {
            let key = match u.ssl_certificate_key.as_option().cloned().flatten() {
                Some(k) => k,
                None => {
                    ngx_core::ngx_log_error!(
                        ngx_core::log::NGX_LOG_EMERG,
                        cf.log,
                        None,
                        "no \"proxy_ssl_certificate_key\" is defined for certificate \"{}\"",
                        ngx_core::string::B(&cert.value)
                    );
                    return Err(ConfError::Logged);
                }
            };

            if cert.is_constant() && key.is_constant() {
                let mut c = cert.value.clone();
                let mut k = key.value.clone();

                let passwords = u.ssl_passwords.as_option().cloned().flatten();

                if ngx_ssl_certificate(cf, &mut ssl, &mut c, &mut k, passwords.as_ref()) != NGX_OK {
                    return Err(ConfError::Logged);
                }
            }
        }
    }

    if *u.ssl_verify {
        if plcf.ssl_trusted_certificate.get().is_empty() {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_EMERG, cf.log, None, "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return Err(ConfError::Logged);
        }

        let mut trusted = plcf.ssl_trusted_certificate.get().clone();

        if ngx_ssl_trusted_certificate(cf, &mut ssl, &mut trusted, *plcf.ssl_verify_depth) != NGX_OK {
            return Err(ConfError::Logged);
        }

        let mut crl = plcf.ssl_crl.get().clone();

        if ngx_ssl_crl(cf, &mut ssl, &mut crl) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    if ngx_ssl_client_session_cache(cf, &mut ssl, *u.ssl_session_reuse) != NGX_OK {
        return Err(ConfError::Logged);
    }

    let mut commands = plcf.ssl_conf_commands.as_option().cloned().flatten();

    if ngx_ssl_conf_commands(cf, &mut ssl, commands.as_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    Ok(())
}

/// proxy_ssl_name: ngx_http_set_complex_value_slot
fn proxy_ssl_name_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut slot = cell.borrow().upstream_ssl.ssl_name.clone();
    crate::script::set_complex_value_slot(cf, cmd, &mut slot)?;
    cell.borrow_mut().upstream_ssl.ssl_name = slot;
    Ok(())
}

/// proxy_ssl_certificate, proxy_ssl_certificate_key:
/// ngx_http_set_complex_value_zero_slot
fn proxy_ssl_certificate_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let key = cmd.name == "proxy_ssl_certificate_key";

    let mut slot = {
        let c = cell.borrow();
        if key { c.upstream_ssl.ssl_certificate_key.clone() } else { c.upstream_ssl.ssl_certificate.clone() }
    };

    crate::script::set_complex_value_zero_slot(cf, cmd, &mut slot)?;

    let mut c = cell.borrow_mut();

    if key {
        c.upstream_ssl.ssl_certificate_key = slot;
    } else {
        c.upstream_ssl.ssl_certificate = slot;
    }

    Ok(())
}

/// ngx_http_proxy_ssl_certificate_cache
fn proxy_ssl_certificate_cache_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());

    if cell.borrow().upstream_ssl.ssl_certificate_cache.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let mut max: i64 = 0;
    let mut inactive: i64 = 10;
    let mut valid: i64 = 60;
    let mut off = false;

    for v in &value[1..] {
        let failed = |cf: &Conf| cf.emerg(format_args!("invalid parameter \"{}\"", ngx_core::string::B(v)));

        if let Some(n) = v.strip_prefix(b"max=") {
            max = match ngx_core::string::atoi(n) {
                Some(m) if m > 0 => m,
                _ => return Err(failed(cf)),
            };
            continue;
        }

        if let Some(t) = v.strip_prefix(b"inactive=") {
            inactive = match ngx_core::parse::parse_time(t, true) {
                Some(t) => t,
                None => return Err(failed(cf)),
            };
            continue;
        }

        if let Some(t) = v.strip_prefix(b"valid=") {
            valid = match ngx_core::parse::parse_time(t, true) {
                Some(t) => t,
                None => return Err(failed(cf)),
            };
            continue;
        }

        if v == b"off" {
            off = true;
            continue;
        }

        return Err(failed(cf));
    }

    if off {
        cell.borrow_mut().upstream_ssl.ssl_certificate_cache = Val::set(None);
        return Ok(());
    }

    if max == 0 {
        return Err(cf.emerg(format_args!("\"proxy_ssl_certificate_cache\" must have the \"max\" parameter")));
    }

    let cache = ngx_core::event_openssl_cache::ngx_ssl_cache_init(max as usize, valid, inactive);

    cell.borrow_mut().upstream_ssl.ssl_certificate_cache = Val::set(Some(Rc::new(RefCell::new(cache))));

    Ok(())
}

/// ngx_http_proxy_ssl_password_file
fn proxy_ssl_password_file_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());

    if cell.borrow().upstream_ssl.ssl_passwords.is_set() {
        return Err(msg("is duplicate"));
    }

    let file = cf.args[1].clone();

    match ngx_ssl_read_password_file(cf, &file) {
        Some(p) => {
            cell.borrow_mut().upstream_ssl.ssl_passwords = Val::set(Some(p));
            Ok(())
        }
        None => Err(ConfError::Logged),
    }
}

/// proxy_ssl_conf_command: ngx_conf_set_keyval_slot with
/// ngx_http_proxy_ssl_conf_command_check (SSL_CONF_cmd() is available)
fn proxy_ssl_conf_command_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    if !c.ssl_conf_commands.is_set() {
        c.ssl_conf_commands = Val::set(Some(Vec::new()));
    }

    c.ssl_conf_commands.0.as_mut().unwrap().as_mut().unwrap().push((cf.args[1].clone(), cf.args[2].clone()));

    Ok(())
}

/// proxy_ssl_protocols: ngx_conf_set_bitmask_slot
fn proxy_ssl_protocols_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();
    set_bitmask(cf, cmd, &mut c.ssl_protocols, SSL_PROTOCOLS)
}

/// proxy_ssl_session_reuse, proxy_ssl_server_name, proxy_ssl_verify:
/// ngx_conf_set_flag_slot
fn proxy_ssl_flag_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    let slot = match cmd.name {
        "proxy_ssl_session_reuse" => &mut c.upstream_ssl.ssl_session_reuse,
        "proxy_ssl_server_name" => &mut c.upstream_ssl.ssl_server_name,
        _ => &mut c.upstream_ssl.ssl_verify,
    };

    set_flag(cf, cmd, slot)
}

fn proxy_set_body_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let cv = crate::script::compile_complex_value(cf, &args[1], 0)?;
    cell.borrow_mut().set_body = Some(cv);
    Ok(())
}

fn proxy_method_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let cv = crate::script::compile_complex_value(cf, &args[1], 0)?;
    cell.borrow_mut().method = Some(cv);
    Ok(())
}

fn proxy_pass_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("no proxy_pass URI specified"));
    }

    if let Some(c) = conf {
        let conf = conf_rc::<NgxHttpProxyLocConf>(&c);
        let uri = cf.args[1].clone();
        // If it contains a `$`, compile as ComplexValue for per-request
        // expansion. Otherwise keep the literal (fast path — matches C
        // where only URLs with variables go through the eval branch).
        if uri.contains(&b'$') {
            let cv = crate::script::compile_complex_value(cf, &uri, 0)?;
            conf.borrow_mut().upstream_uri_cv = Some(cv);
            conf.borrow_mut().ssl = true;
        } else {
            // ngx_http_proxy_pass: the upstream of the URL
            let add = if uri.len() >= 7 && uri[..7].eq_ignore_ascii_case(b"http://") {
                (7, 80)
            } else if uri.len() >= 8 && uri[..8].eq_ignore_ascii_case(b"https://") {
                conf.borrow_mut().ssl = true;
                (8, 443)
            } else {
                return Err(cf.emerg(format_args!("invalid URL prefix in \"{}\"", ngx_core::string::B(&uri))));
            };
            let mut u = ngx_core::inet::Url::new(&uri[add.0..]);
            u.default_port = add.1;
            u.uri_part = true;
            u.no_resolve = true;
            let uscf = crate::upstream::upstream_add(cf, &mut u, 0)?;
            conf.borrow_mut().upstream = Some(uscf);
            conf.borrow_mut().vars_uri = u.uri.clone();

            let clcf = get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());
            let no_location = {
                let l = clcf.borrow();
                l.named || l.regex.is_some() || l.predicate != 0 || l.noname
            };

            if no_location && !u.uri.is_empty() {
                return Err(cf.emerg(format_args!(
                    "\"proxy_pass\" cannot have URI part in \
                     location given by regular expression, \
                     or inside predicate location, \
                     or inside named location, \
                     or inside \"if\" statement, \
                     or inside \"limit_except\" block"
                )));
            }
        }
        conf.borrow_mut().upstream_uri = Some(uri);
    }

    // Set the location handler to our proxy_handler and mark auto_redirect for `/xxx/` locs.
    let loc_conf = get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());
    let mut lc = loc_conf.borrow_mut();
    lc.handler = Some(Rc::new(|r| Box::pin(proxy_handler(r))));
    if lc.name.last() == Some(&b'/') {
        lc.auto_redirect = true;
    }

    Ok(())
}

fn proxy_redirect_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    if args.len() == 2 {
        if args[1] == b"off" {
            let mut c = cell.borrow_mut();
            c.redirect_off = true;
            c.redirects.clear();
            c.redirect_default = false;
            return Ok(());
        }
        if args[1] == b"default" {
            cell.borrow_mut().redirect_default = true;
            return Ok(());
        }
        return Err(cf.emerg(format_args!("invalid parameter \"{}\"",
            ngx_core::string::B(&args[1]))));
    }
    if args.len() != 3 {
        return Err(msg("invalid number of arguments"));
    }
    let pattern_src = &args[1];
    let replacement_src = &args[2];
    let (pattern, replacement) = if !pattern_src.is_empty() && pattern_src[0] == b'~' {
        let (caseless, body) = if pattern_src.len() >= 2 && pattern_src[1] == b'*' {
            (true, &pattern_src[2..])
        } else {
            (false, &pattern_src[1..])
        };
        let flags = if caseless { ngx_core::regex::NGX_REGEX_CASELESS } else { 0 };
        let re = ngx_core::regex::Regex::compile(body, flags)
            .map_err(|e| cf.emerg(format_args!("regex error: {}", e)))?;
        let repl = crate::script::compile_complex_value(cf, replacement_src, 0)?;
        (CookieRewritePattern::Regex(re), repl)
    } else {
        // proxy_redirect uses a plain string-prefix substitution — matches
        // ngx_http_proxy_rewrite_complex_handler which compares
        // `value + prefix` against `pattern` and replaces on match.
        let pat = crate::script::compile_complex_value(cf, pattern_src, 0)?;
        let repl = crate::script::compile_complex_value(cf, replacement_src, 0)?;
        (CookieRewritePattern::Path(pat), repl)
    };
    cell.borrow_mut().redirects.push(CookieRewrite { pattern, replacement });
    Ok(())
}

fn proxy_bind_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    if args.len() < 2 || args.len() > 3 {
        return Err(msg("invalid number of arguments"));
    }
    if args[1] == b"off" {
        cell.borrow_mut().local_bind = Some(LocalBind::Off);
        return Ok(());
    }
    let cv = crate::script::compile_complex_value(cf, &args[1], 0)?;
    cell.borrow_mut().local_bind = Some(LocalBind::Addr(cv));
    Ok(())
}

fn proxy_send_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_set_header_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 3 {
        return Err(cf.emerg(format_args!("invalid number of arguments")));
    }
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let name = args[1].clone();
    let cv = crate::script::compile_complex_value(cf, &args[2], 0)?;
    cell.borrow_mut().set_headers.push((name, cv));
    Ok(())
}

fn proxy_target_hostport(r: &R) -> Option<(String, u16)> {
    let conf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let uri = conf.borrow().upstream_uri.clone()?;
    let s = std::str::from_utf8(&uri).ok()?;
    parse_upstream_uri(s).map(|(h, p, _)| (h, p))
}

fn proxy_host_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // C: $proxy_host = ctx->vars.host_header. When the URL uses an explicit
    // non-default port, host_header includes ":<port>"; else just the hostname.
    // See ngx_http_proxy_set_vars.
    let hp = proxy_target_hostport(r);
    let scheme_is_https = {
        let conf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        let uri = conf.borrow().upstream_uri.clone();
        uri.as_deref().map(|u| u.starts_with(b"https://")).unwrap_or(false)
    };
    match hp {
        Some((h, p)) => {
            let default = if scheme_is_https { 443 } else { 80 };
            let out = if p == default { h } else { format!("{}:{}", h, p) };
            v.data = out.into_bytes();
            v.valid = true;
        }
        None => { v.not_found = true; }
    }
    NGX_OK
}

fn proxy_port_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let hp = proxy_target_hostport(r);
    let scheme_is_https = {
        let conf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        let uri = conf.borrow().upstream_uri.clone();
        uri.as_deref().map(|u| u.starts_with(b"https://")).unwrap_or(false)
    };
    match hp {
        Some((_, p)) => {
            // C behavior: if no explicit port or port==default, return "80"/"443"
            // depending on scheme. My parse_upstream_uri always returns a port,
            // so we can't tell "no port" from "port explicitly = default". Since
            // the emitted value is the same either way (default-string), no bug.
            v.data = p.to_string().into_bytes();
            v.valid = true;
            let _ = scheme_is_https;
        }
        None => { v.not_found = true; }
    }
    NGX_OK
}

fn proxy_add_x_forwarded_for_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // C: if the client sent X-Forwarded-For, append ", $remote_addr"; else just
    // $remote_addr. Multi-value X-Forwarded-For entries are comma-joined.
    let existing: Vec<u8> = {
        let hin = r.headers_in.borrow();
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for h in hin.x_forwarded_for.iter() {
            parts.push(h.value.borrow().clone());
        }
        parts.join(&b", "[..])
    };
    let remote = r.connection.addr_text.borrow().clone();
    let mut out = Vec::new();
    if !existing.is_empty() {
        out.extend_from_slice(&existing);
        out.extend_from_slice(b", ");
    }
    out.extend_from_slice(&remote);
    v.data = out;
    v.valid = true;
    NGX_OK
}

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    let vars = vec![
        VarDef {
            name: "proxy_host",
            get: Some(proxy_host_variable),
            set: None,
            data: 0,
            flags: crate::variables::NGX_HTTP_VAR_CHANGEABLE | crate::variables::NGX_HTTP_VAR_NOCACHEABLE | crate::variables::NGX_HTTP_VAR_NOHASH,
        },
        VarDef {
            name: "proxy_port",
            get: Some(proxy_port_variable),
            set: None,
            data: 0,
            flags: crate::variables::NGX_HTTP_VAR_CHANGEABLE | crate::variables::NGX_HTTP_VAR_NOCACHEABLE | crate::variables::NGX_HTTP_VAR_NOHASH,
        },
        VarDef {
            name: "proxy_add_x_forwarded_for",
            get: Some(proxy_add_x_forwarded_for_variable),
            set: None,
            data: 0,
            flags: crate::variables::NGX_HTTP_VAR_NOHASH,
        },
    ];

    crate::variables::add_variables(cf, &vars)?;

    // $upstream_cache_status is defined by the proxy_cache module so it lives
    // wherever caching does — register it during proxy preconfiguration so
    // access_log and rewrite scripts can see it.
    crate::proxy_cache::add_variables(cf)?;

    Ok(())
}

async fn proxy_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let conf_borrowed = lcf.borrow();

    // ngx_http_proxy_handler: read the client request body before the
    // upstream is set up; unbuffered, only what is there now, and the rest
    // is sent on as it arrives (send_request_body).
    if !conf_borrowed.request_buffering.get_or(true)
        && conf_borrowed.set_body.is_none()
        && conf_borrowed.pass_request_body.get_or(true)
        && (!r.headers_in.borrow().chunked || *conf_borrowed.http_version == 1)
    {
        r.request_body_no_buffering.set(true);
    }
    drop(conf_borrowed);
    let rc = crate::request_body::read_client_request_body(&r).await;
    if rc >= crate::NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let conf_borrowed = lcf.borrow();

    // Check if this location has proxy_pass configured
    let upstream_uri = if let Some(cv) = &conf_borrowed.upstream_uri_cv {
        // Variable-based proxy_pass: expand per request. Fallback to the
        // stored literal on failure so a bad variable expansion doesn't
        // panic — matches C's fallback of returning NGX_ERROR from
        // ngx_http_proxy_eval on complex_value failure.
        let cv_cloned = cv.clone();
        drop(conf_borrowed);
        let expanded = match crate::script::complex_value(&r, &cv_cloned) {
            Ok(v) => v,
            Err(_) => return return_error(&r, crate::NGX_HTTP_INTERNAL_SERVER_ERROR as i64).await,
        };
        // Prepend scheme if missing: `$arg_b` typically expands to host:port.
        let mut u = if expanded.starts_with(b"http://") || expanded.starts_with(b"https://") {
            expanded
        } else {
            let mut prefixed = b"http://".to_vec();
            prefixed.extend_from_slice(&expanded);
            prefixed
        };
        // Ensure a trailing slash for path so parse_upstream_uri finds "/".
        if !u.contains(&b'/') || (u.starts_with(b"http://") && !u[7..].contains(&b'/')) || (u.starts_with(b"https://") && !u[8..].contains(&b'/')) {
            u.push(b'/');
        }
        u
    } else {
        match &conf_borrowed.upstream_uri {
            Some(uri) => uri.clone(),
            None => {
                // ngx_http_upstream_init_request: no u->conf->upstream,
                // e.g. the proxy_pass handler of an "if" block used with
                // the configuration of another "if" block
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ALERT, r.connection.log, None, "no upstream configuration");
                return crate::NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    };
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let conf_borrowed = lcf.borrow();

    // proxy_cache lookup — happens *before* we open the upstream. `try_serve`
    // returns `Some(rc)` for a hit (already sent to client) or a bypass
    // decision; `None` means MISS/EXPIRED and we continue to upstream.
    if conf_borrowed.cache.zone.is_some() {
        let cache_conf = conf_borrowed.cache.clone();
        let upstream_uri_snap = upstream_uri.clone();
        drop(conf_borrowed);
        if let Some(rc) = crate::proxy_cache::try_serve(&r, &cache_conf, &upstream_uri_snap).await {
            return rc;
        }
        let _ = lcf.borrow();
    }
    let conf_borrowed = lcf.borrow();

    // Parse upstream URI
    let upstream_uri_str = match std::str::from_utf8(&upstream_uri) {
        Ok(s) => s,
        Err(_) => {
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    let (mut host, mut port, upstream_path) = match parse_upstream_uri(upstream_uri_str) {
        Some(p) => p,
        None => {
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    // If proxy_pass URL includes a URI (e.g. "http://backend/local/"), rewrite:
    //   forwarded = upstream_path + (request_uri - location_prefix)
    // Else forward the request URI as-is.
    let clcf = r.clcf();
    let loc_name = clcf.borrow().name.clone();
    let request_uri = r.uri.borrow().clone();
    // Variable-based proxy_pass: use the expanded URL's URI verbatim,
    // matching C's `if (proxy_lengths && vars.uri.len) u->uri = vars.uri;`
    // — the client's request URI is NOT appended.
    let is_variable_pass = conf_borrowed.upstream_uri_cv.is_some();
    let forwarded_uri: Vec<u8> = if is_variable_pass {
        upstream_path.as_bytes().to_vec()
    } else if !conf_borrowed.vars_uri.is_empty() {
        // ngx_http_proxy_create_request: vars.uri (unless the URI was
        // rewritten with "break", r->valid_location reset), then the
        // request URI past the location
        let mut u = if r.valid_location.get() { conf_borrowed.vars_uri.clone() } else { Vec::new() };
        let loc_len = if r.valid_location.get() && request_uri.starts_with(loc_name.as_slice()) { loc_name.len() } else { 0 };
        u.extend_from_slice(&request_uri[loc_len..]);
        u
    } else {
        request_uri.clone()
    };
    // For byte-preservation in the request line below.
    let request_uri_bytes = forwarded_uri;

    // proxy_next_upstream state.
    let next_upstream_mask = conf_borrowed.next_upstream_mask.get_or(FT_ERROR | FT_TIMEOUT);
    let next_upstream_tries = conf_borrowed.next_upstream_tries.get_or(0);
    let next_upstream_timeout = conf_borrowed.next_upstream_timeout.get_or(0);
    let static_upstream = conf_borrowed.upstream.clone();

    let bind_addr: Option<std::net::SocketAddr> = match &conf_borrowed.local_bind {
        None | Some(LocalBind::Off) => None,
        Some(LocalBind::Addr(cv)) => {
            let evaluated = crate::script::complex_value(&r, cv).unwrap_or_default();
            let s = String::from_utf8_lossy(&evaluated).into_owned();
            parse_bind_addr(&s)
        }
    };



    // Build request line. proxy_method overrides the client method if set.
    let convert_head_active = conf_borrowed.cache.zone.is_some()
        && conf_borrowed.cache.convert_head
        && conf_borrowed.method.is_none()
        && r.method.get() == NGX_HTTP_HEAD;
    let method_owned: Vec<u8> = if let Some(mcv) = conf_borrowed.method.clone() {
        drop(conf_borrowed);
        let m = crate::script::complex_value(&r, &mcv).unwrap_or_default();
        m
    } else if convert_head_active {
        drop(conf_borrowed);
        // proxy_cache_convert_head: fetch the full body from the upstream
        // via GET so the cache stores a body a later GET can HIT, then
        // let head_only trim the body before sending to the client.
        b"GET".to_vec()
    } else {
        drop(conf_borrowed);
        r.method_name.borrow().clone()
    };
    let method = std::str::from_utf8(&method_owned).unwrap_or("GET");

    let uri_path = std::str::from_utf8(&request_uri_bytes).unwrap_or("/").to_string();
    // Include query string if present. Clone into a Vec so we don't hold a
    // Ref on r.args across the many awaits that follow — a live Ref would
    // panic when e.g. an X-Accel-Redirect internal_redirect tries to
    // borrow_mut() the same cell, silently killing the request task.
    let uri_with_args = {
        let args = r.args.borrow().clone();
        // Variable-based proxy_pass: args are dropped — the expanded URL is
        // used verbatim as the upstream URI. Matches C's proxy_lengths path.
        if !args.is_empty() && !is_variable_pass {
            format!("{}?{}", uri_path, std::str::from_utf8(&args).unwrap_or(""))
        } else {
            uri_path
        }
    };

    // Read pass_request_headers/body, set_body, and set_headers configs.
    let (pass_headers_flag, pass_body_flag, set_body_cv, set_headers_list) = {
        let lcf3 = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        let b = lcf3.borrow();
        (
            b.pass_request_headers.get_or(true),
            b.pass_request_body.get_or(true),
            b.set_body.clone(),
            b.set_headers.clone(),
        )
    };
    // Names that proxy_set_header overrides (case-insensitive). Also used to
    // suppress the corresponding client header from the pass-through loop.
    let overridden_names: Vec<Vec<u8>> = set_headers_list
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();

    // An unbuffered body still being read goes as it arrives: what was read
    // so far follows the header, with Content-Length, or chunked when the
    // client's body is (ngx_http_proxy_create_request, internal_chunked).
    let unbuffered = r.request_body_no_buffering.get();
    let internal_chunked = unbuffered && r.headers_in.borrow().chunked && r.reading_body.get();
    // Collect request body (if any) into a Vec. proxy_set_body wins over the
    // client body when configured; otherwise honour proxy_pass_request_body.
    let body_bytes: Vec<u8> = if unbuffered {
        let bufs = take_request_body_bufs(&r);
        let mut out = Vec::new();
        body_output_filter(&mut out, &bufs, internal_chunked);
        out
    } else if let Some(cv) = set_body_cv {
        crate::script::complex_value(&r, &cv).unwrap_or_default()
    } else if !pass_body_flag { Vec::new() } else {
        let rb = r.request_body.borrow();
        let mut out = Vec::new();
        if let Some(body) = rb.as_ref() {
            let bod = body.borrow();
            for b in bod.bufs.iter() {
                if let ngx_core::buf::BufData::Memory(m) = &b.data {
                    let end = b.last.min(m.len());
                    if b.pos < end { out.extend_from_slice(&m[b.pos..end]); }
                }
                if b.in_file {
                    if let ngx_core::buf::BufData::File(f) = &b.data {
                        let sz = (b.file_last - b.file_pos) as usize;
                        let mut buf = vec![0u8; sz];
                        let mut off = 0usize;
                        while off < sz {
                            let n = unsafe { libc::pread(f.fd, buf[off..].as_mut_ptr() as *mut _, sz - off, b.file_pos + off as i64) };
                            if n <= 0 { break; }
                            off += n as usize;
                        }
                        out.extend_from_slice(&buf[..off]);
                    }
                }
            }
        }
        out
    };
    // "Content-Length: $proxy_internal_body_length" and "Transfer-Encoding:
    // $proxy_internal_chunked" are default headers: proxy_set_header of the
    // same name replaces them (an empty value drops them).
    let cl_overridden = overridden_names.iter().any(|n| n.as_slice() == b"content-length");
    let te_overridden = overridden_names.iter().any(|n| n.as_slice() == b"transfer-encoding");
    let content_length_hdr = if internal_chunked {
        if te_overridden { String::new() } else { "Transfer-Encoding: chunked\r\n".to_string() }
    } else if cl_overridden {
        String::new()
    } else if unbuffered {
        format!("Content-Length: {}\r\n", r.headers_in.borrow().content_length_n)
    } else if !body_bytes.is_empty() {
        format!("Content-Length: {}\r\n", body_bytes.len())
    } else if r.headers_in.borrow().content_length_n > 0 || r.headers_in.borrow().chunked {
        format!("Content-Length: 0\r\n")
    } else {
        String::new()
    };
    let content_type_hdr = {
        let hin = r.headers_in.borrow();
        if let Some(ct) = hin.content_type.first() {
            format!("Content-Type: {}\r\n", std::str::from_utf8(&ct.value.borrow()).unwrap_or(""))
        } else { String::new() }
    };
    // proxy_cache_max_range_offset: when the client's Range starts at or
    // below the offset, strip Range from the upstream request so the
    // whole entry lands in cache and the range_filter serves the subrange
    // from a memory buf. Matches ngx_http_upstream_cache_check_range.
    // proxy_cache implies we want the FULL upstream response so we can
    // cache it, so strip client conditional headers unless the location
    // has proxy_cache_revalidate on (which needs its own IMS/INM built
    // from the cached response). Matches C's
    // ngx_http_upstream_process_conditional_headers behavior.
    let strip_conditional = {
        let lcf_c = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        let c = lcf_c.borrow();
        c.cache.zone.is_some()
    };
    let strip_range = {
        let lcf_mro = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        let c = lcf_mro.borrow();
        match (c.cache.zone.as_ref(), c.cache.max_range_offset) {
            (Some(_zone), Some(off)) => {
                let hin = r.headers_in.borrow();
                let range_ok = hin.range.first()
                    .map(|h| crate::proxy_cache::range_below_offset(&h.value.borrow(), off))
                    .unwrap_or(false);
                if range_ok && c.cache.min_uses > 1 {
                    // Gate on min_uses hits: if this key hasn't been
                    // requested min_uses times yet, don't do the range-strip
                    // optimization — matches C's cache_min_uses interaction
                    // with cache_check_range.
                    if let Some(Ok(zn)) = crate::proxy_cache::resolve_zone_name(&r, &c.cache) {
                        let base_key = match &c.cache.key {
                            Some(cv) => crate::script::complex_value(&r, cv).unwrap_or_default(),
                            None => crate::proxy_cache::default_cache_key(&r, &upstream_uri),
                        };
                        crate::proxy_cache::get_hits(&zn, &base_key) >= c.cache.min_uses
                    } else {
                        false
                    }
                } else {
                    range_ok
                }
            }
            _ => false,
        }
    };
    if strip_range {
        r.allow_ranges.set(true);
    }
    // Forward client request headers that aren't the ones we synthesize ourselves.
    // C proxies most client headers by default; the exact list is governed by
    // proxy_set_header, hide_headers, etc.  We don't implement those yet, so this
    // is a subset: pass everything except headers that would conflict with the
    // synthesized request line, hop-by-hop headers, and things upstream shouldn't
    // trust from the client.
    let mut forward_headers: String = if !pass_headers_flag { String::new() } else {
        let hin = r.headers_in.borrow();
        let mut s = String::new();
        for h in hin.headers.iter() {
            if h.hash.get() == 0 { continue; }
            let lc = &h.lowcase_key;
            if matches!(lc.as_slice(),
                b"host" | b"connection" | b"keep-alive" |
                b"transfer-encoding" | b"te" | b"upgrade" |
                b"content-length" | b"content-type" |
                b"expect" | b"proxy-connection")
            {
                continue;
            }
            if strip_range && lc.as_slice() == b"range" {
                continue;
            }
            if strip_conditional && matches!(lc.as_slice(),
                b"if-modified-since" | b"if-unmodified-since" |
                b"if-none-match" | b"if-match" | b"if-range")
            {
                continue;
            }
            if overridden_names.iter().any(|n| n.as_slice() == lc.as_slice()) {
                continue; // proxy_set_header will emit (or drop) this one
            }
            let key = match std::str::from_utf8(&h.key) { Ok(s) => s, Err(_) => continue };
            let val = h.value.borrow();
            let val = match std::str::from_utf8(&val) { Ok(s) => s, Err(_) => continue };
            s.push_str(key);
            s.push_str(": ");
            s.push_str(val);
            s.push_str("\r\n");
        }
        s
    };
    // Append proxy_set_header emissions (skip empty-valued ones to drop them).
    for (name, cv) in &set_headers_list {
        let val = crate::script::complex_value(&r, cv).unwrap_or_default();
        if val.is_empty() {
            continue;
        }
        if let (Ok(k), Ok(v)) = (std::str::from_utf8(name), std::str::from_utf8(&val)) {
            forward_headers.push_str(k);
            forward_headers.push_str(": ");
            forward_headers.push_str(v);
            forward_headers.push_str("\r\n");
        }
    }

    let http_version = {
        let c = lcf.borrow();
        *c.http_version
    };
    let ver_str = if http_version == 1 { "HTTP/1.1" } else { "HTTP/1.0" };
    // Only synthesize a `Connection: close` line if the user's config didn't
    // set Connection via proxy_set_header (in which case its value — possibly
    // empty to drop the header — lives in forward_headers already). This lets
    // `proxy_set_header Connection ""` + `proxy_http_version 1.1` produce a
    // keep-alive request suitable for an upstream {} block with `keepalive N;`.
    let connection_overridden = overridden_names.iter().any(|n| n.as_slice() == b"connection");
    let conn_line = if connection_overridden { "" } else { "Connection: close\r\n" };
    // proxy_cache_revalidate: if the cached response had Last-Modified /
    // ETag and the cache has expired, add If-Modified-Since /
    // If-None-Match so the upstream can 304 us and reuse the entry.
    let reval_hdrs: String = match crate::proxy_cache::get_revalidate(&r) {
        Some(h) => {
            let mut s = String::new();
            if let Some(ims) = &h.if_modified_since {
                s.push_str("If-Modified-Since: ");
                s.push_str(std::str::from_utf8(ims).unwrap_or(""));
                s.push_str("\r\n");
            }
            if let Some(inm) = &h.if_none_match {
                s.push_str("If-None-Match: ");
                s.push_str(std::str::from_utf8(inm).unwrap_or(""));
                s.push_str("\r\n");
            }
            s
        }
        None => String::new(),
    };
    // IPv6 literal hostnames need bracket-quoting in the Host header.
    // For unix upstreams C sends "unix:<path>:" — copy that.
    let host_hdr: String = if let Some(path) = host.strip_prefix("unix:") {
        format!("unix:{}:", path)
    } else if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    let request = format!(
        "{} {} {}\r\n\
         Host: {}\r\n\
         {}{}{}{}{}\r\n",
        method, uri_with_args, ver_str, host_hdr, conn_line, content_length_hdr, content_type_hdr, reval_hdrs, forward_headers
    );

    // u->ssl (the URL is https): ngx_http_upstream_ssl_init_connection
    // after connecting, with u->conf's SSL fields
    let connect_timeout = *lcf.borrow().connect_timeout.get();
    let ssl_setup = if upstream_uri.len() >= 8 && upstream_uri[..8].eq_ignore_ascii_case(b"https://") {
        let conf = lcf.borrow().upstream_ssl.clone();
        Some(crate::upstream_ssl::SslSetup { conf, alpn: Vec::new() })
    } else {
        None
    };

    // ngx_http_upstream_init_request: the peers of the upstream{} or
    // implicit upstream of proxy_pass, of the upstream a variable URL's
    // host names, or of the addresses it resolves to
    let tag = Rc::as_ptr(&lcf) as *const () as usize;
    let peer = if let Some(uscf) = static_upstream.as_ref().filter(|_| !is_variable_pass) {
        crate::upstream::UpstreamPeer::init(&r, uscf, next_upstream_mask, next_upstream_tries, next_upstream_timeout, tag)
    } else {
        resolved_peer(&r, &upstream_uri, next_upstream_mask, next_upstream_tries, next_upstream_timeout, tag).await
    };
    let peer = match peer {
        Ok(p) => p,
        Err(rc) => return return_error(&r, rc).await,
    };
    // the peer is freed when the request is done
    let mut g = crate::upstream::PeerGuard::new(&r, peer);

    // proxy_next_upstream retry loop: on connect error / matching HTTP status,
    // free the peer and connect to the next one (ngx_http_upstream_next).
    let mut upstream: Option<UpstreamSock> = None;
    let mut upstream_requests: u64;
    let mut upstream_start_time: u64;
    let mut addr: String;
    let mut response: Vec<u8>;
    let mut status: i64;
    let mut status_line_end: usize;
    let mut body_start: usize;
    let mut bytes_received_from_upstream: i64;
    let mut bytes_sent_to_upstream: i64;
    let mut response_keepalive: bool;
    // u->buffering, which "X-Accel-Buffering" may change
    let (conf_buffering, change_buffering) = {
        let c = lcf.borrow();
        (c.buffering.get_or(true), !c.cache.ignore_headers.iter().any(|h| h == b"x-accel-buffering"))
    };
    let mut u_buffering: bool;
    // the body framing of the response: Content-Length, chunked
    let mut u_expected_body_len: Option<usize>;
    let mut u_is_chunked: bool;
    let mut u_upstream_wants_close: bool;
    'retry: loop {
        u_buffering = conf_buffering;

        // ngx_http_upstream_connect
        let rc = g.u.connect(&r);

        if rc == NGX_ERROR {
            return return_error(&r, crate::NGX_HTTP_INTERNAL_SERVER_ERROR).await;
        }

        if rc == NGX_BUSY {
            match g.u.next(&r, crate::upstream::NGX_HTTP_UPSTREAM_FT_NOLIVE) {
                Ok(()) => continue 'retry,
                Err(st) => return return_error(&r, st).await,
            }
        }

        let try_started_ms = g.u.start_time;
        addr = String::from_utf8_lossy(&g.u.pc.name).into_owned();

        upstream = Some(if rc == NGX_DONE {
            // a cached keepalive connection
            let c = g.u.pc.connection.take().unwrap();
            upstream_requests = c.requests;
            upstream_start_time = c.start_time;
            // c->data = r
            g.u.attach_sock(&c.sock);
            c.sock
        } else {
            let sockaddr = match g.u.pc.sockaddr.clone() {
                Some(sa) => sa,
                None => return return_error(&r, crate::NGX_HTTP_INTERNAL_SERVER_ERROR).await,
            };
            match connect_upstream(&r, &sockaddr, bind_addr, ssl_setup.as_ref(), Some(&mut g.u), connect_timeout).await {
                Ok(s) => {
                    upstream_requests = 0;
                    upstream_start_time = ngx_core::times::current_msec();
                    s
                }
                Err(e) => {
                    let ft = match e {
                        ConnectError::Error => FT_ERROR,
                        ConnectError::Timeout => FT_TIMEOUT,
                        ConnectError::Internal => return crate::NGX_HTTP_INTERNAL_SERVER_ERROR,
                    };
                    match g.u.next(&r, ft) {
                        Ok(()) => continue 'retry,
                        Err(st) => return return_error(&r, st).await,
                    }
                }
            }
        });
        upstream_requests += 1;

        // ngx_http_upstream_send_request: the connection is established
        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            if st.connect_time == u64::MAX {
                st.connect_time = ngx_core::times::current_msec().saturating_sub(try_started_ms);
            }
        }

        // Send request + body in one write so a fast upstream that reads once and
        // closes (e.g. Test::Nginx daemons calling sysread) sees the body too.
        let mut wire: Vec<u8> = Vec::with_capacity(request.len() + body_bytes.len());
        wire.extend_from_slice(request.as_bytes());
        if !body_bytes.is_empty() {
            wire.extend_from_slice(&body_bytes);
        }
        g.u.request_sent = true;
        if let Err(_) = upstream.as_mut().unwrap().write_all(&wire).await {
            upstream = None;
            match g.u.next(&r, FT_ERROR) {
                Ok(()) => continue 'retry,
                Err(st) => return return_error(&r, st).await,
            }
        }
        bytes_sent_to_upstream = wire.len() as i64;
        if r.reading_body.get() {
            let output = |out: &mut Vec<u8>, bufs: &ngx_core::buf::Chain| body_output_filter(out, bufs, internal_chunked);
            match send_request_body(&r, upstream.as_mut().unwrap(), &output).await {
                Ok(n) => bytes_sent_to_upstream += n,
                Err(rc) => {
                    upstream = None;
                    if rc == NGX_HTTP_BAD_GATEWAY as i64 {
                        // the upstream write failed
                        match g.u.next(&r, FT_ERROR) {
                            Ok(()) => continue 'retry,
                            Err(st) => return return_error(&r, st).await,
                        }
                    }
                    return return_error(&r, rc).await;
                }
            }
        }
        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.bytes_sent = bytes_sent_to_upstream;
        }

        response = Vec::new();
        // Read headers first so header_time is separate from response_time.
        // read_to_end waits for EOF (proxy Connection: close), so we can't
        // isolate the moment headers arrive without switching to a chunked
        // reader. Approximate with two timestamps: read once to grab
        // whatever the kernel has (that's usually the whole small
        // response), record header_ms, then continue reading.
        let mut buf = [0u8; 4096];
        let mut got_header = false;
        // Once we see the terminating CRLF pair we parse Content-Length so
        // we can stop reading at body_start + content_length instead of
        // waiting for EOF. Without this, upstreams that leave the socket
        // open after sending the full response (proxy_noclose case) hang
        // us until the socket is closed by them or the read timeout fires.
        let mut header_end: Option<usize> = None;
        let mut expected_body_len: Option<usize> = None;
        let mut is_chunked = false;
        let mut upstream_wants_close = false;
        let mut has_xar = false;
        let read_timeout = lcf.borrow().read_timeout.get_or(60000);
        loop {
            let rd = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), upstream.as_mut().unwrap().read(&mut buf)).await;
            let rd = match rd {
                Ok(rd) => rd,
                Err(_) => {
                    let log = &r.connection.log;
                    let action = log.action();
                    if !got_header {
                        // ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT)
                        log.set_action(Some("reading response header from upstream"));
                        ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, log, Some(libc::ETIMEDOUT), "upstream timed out");
                        log.set_action(action);
                        upstream = None;
                        match g.u.next(&r, FT_TIMEOUT) {
                            Ok(()) => continue 'retry,
                            Err(st) => return return_error(&r, st).await,
                        }
                    }
                    log.set_action(Some("reading upstream"));
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, log, Some(libc::ETIMEDOUT), "upstream timed out");
                    log.set_action(action);
                    break;
                }
            };
            match rd {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if !got_header {
                        let end = find_header_end(&response).map(|(_, bs)| bs);
                        if let Some(e) = end {
                            let header_ms = ngx_core::times::current_msec().saturating_sub(try_started_ms);
                            if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
                                st.header_time = header_ms;
                            }
                            // u->headers_in of this response, for the
                            // balancer's notify ($upstream_cookie_*)
                            set_upstream_headers_in(&r, &response[..e]);
                            g.u.notify(&r, crate::upstream::NGX_HTTP_UPSTREAM_NOTIFY_HEADER);
                            got_header = true;
                            header_end = Some(e);
                            // Parse Content-Length from the header block.
                            let headers = &response[..e];
                            for line in headers.split(|&b| b == b'\n') {
                                let line = if line.last() == Some(&b'\r') { &line[..line.len()-1] } else { line };
                                if line.len() > 15 && line[..15].eq_ignore_ascii_case(b"content-length:") {
                                    let v = &line[15..];
                                    let v = v.iter().position(|&b| b != b' ' && b != b'\t')
                                        .map(|s| &v[s..])
                                        .unwrap_or(v);
                                    if let Ok(s) = std::str::from_utf8(v) {
                                        if let Ok(n) = s.trim().parse::<usize>() {
                                            expected_body_len = Some(n);
                                        }
                                    }
                                }
                                // Transfer-Encoding: chunked ⇒ still need to
                                // read until 0-length terminator, which
                                // signals the same as EOF here. Keep the
                                // EOF-driven loop for chunked.
                                if line.len() > 18 && line[..18].eq_ignore_ascii_case(b"transfer-encoding:")
                                    && line[18..].to_ascii_lowercase().contains(&b'c')
                                {
                                    expected_body_len = None;
                                    is_chunked = true;
                                }
                                if line.len() > 11 && line[..11].eq_ignore_ascii_case(b"connection:") {
                                    if line[11..].to_ascii_lowercase().windows(5).any(|w| w == b"close") {
                                        upstream_wants_close = true;
                                    }
                                }
                                // ngx_http_upstream_process_buffering
                                if change_buffering && line.len() > 18 && line[..18].eq_ignore_ascii_case(b"x-accel-buffering:") {
                                    let v = line[18..].trim_ascii();
                                    if v.eq_ignore_ascii_case(b"no") {
                                        u_buffering = false;
                                    } else if v.eq_ignore_ascii_case(b"yes") {
                                        u_buffering = true;
                                    }
                                }
                                if line.len() > 17 && line[..17].eq_ignore_ascii_case(b"x-accel-redirect:") {
                                    // C aborts the upstream request as soon as
                                    // the header block is processed and issues
                                    // the internal redirect; the response body
                                    // never reaches this proxy. Follow suit so
                                    // an upstream rate-limiter doesn't gate
                                    // our first byte to the redirected
                                    // location.
                                    if !line[17..].iter().all(|&b| b == b' ' || b == b'\t') {
                                        has_xar = true;
                                    }
                                }
                            }
                        }
                    }
                    // Status codes 204 / 304 / 1xx carry no body per RFC,
                    // and neither does a HEAD response — even if the upstream
                    // sent Content-Length. Break as soon as we have the
                    // headers so a persistent (keepalive) upstream isn't
                    // read-blocked waiting for body bytes it will never send.
                    let bodyless = if got_header {
                        if r.method.get() == crate::NGX_HTTP_HEAD {
                            true
                        } else if let Some(e) = header_end {
                            let sl = &response[..e.min(response.len())];
                            let nl = sl.iter().position(|&b| b == b'\n').unwrap_or(sl.len());
                            let sl = &sl[..nl];
                            let sl = if sl.last() == Some(&b'\r') { &sl[..sl.len()-1] } else { sl };
                            let parts: Vec<&[u8]> = sl.splitn(3, |&b| b == b' ').collect();
                            parts.get(1)
                                .and_then(|p| std::str::from_utf8(p).ok())
                                .and_then(|s| s.parse::<u32>().ok())
                                .map(|c| c == 204 || c == 304 || ((100..200).contains(&c) && c != 101))
                                .unwrap_or(false)
                        } else { false }
                    } else { false };
                    if bodyless || has_xar {
                        break;
                    }
                    // 101 Switching Protocols: stop as soon as headers land so
                    // the tunnel takes ownership of the socket. The trailing
                    // bytes (if the upstream started the upgraded protocol
                    // in the same packet as the headers) get forwarded below.
                    if got_header {
                        if let Some(e) = header_end {
                            let sl = &response[..e.min(response.len())];
                            let nl = sl.iter().position(|&b| b == b'\n').unwrap_or(sl.len());
                            let sl = &sl[..nl];
                            let sl = if sl.last() == Some(&b'\r') { &sl[..sl.len()-1] } else { sl };
                            let parts: Vec<&[u8]> = sl.splitn(3, |&b| b == b' ').collect();
                            let is_101 = parts.get(1)
                                .and_then(|p| std::str::from_utf8(p).ok())
                                .and_then(|s| s.parse::<u32>().ok())
                                .map(|c| c == 101).unwrap_or(false);
                            if is_101 { break; }
                        }
                    }
                    // the body of an unbuffered response goes to the client
                    // as it arrives (ngx_http_upstream_send_response)
                    if got_header && !u_buffering {
                        break;
                    }
                    if let (Some(e), Some(cl)) = (header_end, expected_body_len) {
                        if response.len() >= e + cl {
                            break;
                        }
                    }
                    if is_chunked {
                        if let Some(e) = header_end {
                            let body = &response[e..];
                            if chunked_complete(body) {
                                break;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let read_ok = true;
        // If we finished this read cleanly (framing terminated: known
        // Content-Length reached, or chunked-complete saw the 0-chunk),
        // and the upstream didn't send Connection: close, hand the socket
        // back to the keepalive pool for the next request to reuse.
        //
        // Note: `upstream` is only read from below when we're in an error
        // path (empty response, retry). On the success path it's simply
        // dropped when the enclosing scope ends — so it's safe to take it
        // out here via std::io before we hit that drop.
        // Compute framing completeness for BOTH the keepalive decision
        // AND the "should this get cached" check below.
        let (framing_complete, is_head_g, is_bodyless_g) = if got_header {
            let is_head = r.method.get() == crate::NGX_HTTP_HEAD;
            let is_bodyless = if let Some(e) = header_end {
                let sl = &response[..e.min(response.len())];
                if let Some(nl) = sl.iter().position(|&b| b == b'\n') {
                    let sl = &sl[..nl];
                    let sl = if sl.last() == Some(&b'\r') { &sl[..sl.len()-1] } else { sl };
                    let parts: Vec<&[u8]> = sl.splitn(3, |&b| b == b' ').collect();
                    parts.get(1)
                        .and_then(|p| std::str::from_utf8(p).ok())
                        .and_then(|s| s.parse::<u32>().ok())
                        .map(|c| c == 204 || c == 304 || ((100..200).contains(&c) && c != 101))
                        .unwrap_or(false)
                } else { false }
            } else { false };
            let fc = if is_head || is_bodyless {
                true
            } else if let Some(cl) = expected_body_len {
                header_end.map(|e| response.len() >= e + cl).unwrap_or(false)
            } else if is_chunked {
                header_end.map(|e| chunked_complete(&response[e..])).unwrap_or(false)
            } else {
                false
            };
            (fc, is_head, is_bodyless)
        } else {
            (false, false, false)
        };
        // Signal to proxy_cache::maybe_save that we shouldn't persist
        // a truncated response. C nginx checks u->length via
        // ngx_http_upstream_process_non_buffered_downstream and skips
        // ngx_http_file_cache_update when the response is short.
        if !framing_complete && got_header && !is_head_g && !is_bodyless_g {
            // Only mark incomplete when the response HAS a framing
            // mechanism (Content-Length or chunked). EOF-framed (no
            // CL, no TE:chunked) is inherently "complete-on-close"
            // so don't taint the cache path for it.
            if expected_body_len.is_some() || is_chunked {
                r.upstream_response_incomplete.set(true);
            }
        }
        u_expected_body_len = expected_body_len;
        u_is_chunked = is_chunked;
        u_upstream_wants_close = upstream_wants_close;
        // u->keepalive: an HTTP/1.1 response without "Connection: close",
        // read in full, on a request that did not ask to close
        response_keepalive = got_header
            && framing_complete
            && !upstream_wants_close
            && conn_line.is_empty()
            && response.starts_with(b"HTTP/1.1");
        if !read_ok || response.is_empty() {
            // the upstream closed the connection without a response:
            // "upstream prematurely closed connection" (ft error)
            upstream = None;
            match g.u.next(&r, FT_ERROR) {
                Ok(()) => continue 'retry,
                Err(st) => return return_error(&r, st).await,
            }
        }
        bytes_received_from_upstream = response.len() as i64;

        // Parse status line. Pick the earliest header/body separator.
        let (sle, bs) = match find_header_end(&response) {
            Some(e) => e,
            None => return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await,
        };
        status_line_end = sle;
        body_start = bs;
        let headers_section_local = &response[..status_line_end];
        // Status line ends at the first \n. When the response has zero headers
        // (`HTTP/1.0 200 OK\r\n\r\n`) status_line_end sits at the start of that
        // trailing CRLF pair, so headers_section_local is exactly the status
        // line with no LF in it — fall back to the full header separator index
        // rather than 502ing on a syntactically valid empty-header response.
        let status_line_end_nl = headers_section_local
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(headers_section_local.len());
        let status_line = &headers_section_local[..status_line_end_nl];
        let status_line = if status_line.last() == Some(&b'\r') { &status_line[..status_line.len()-1] } else { status_line };
        let status_line_str = std::str::from_utf8(status_line).unwrap_or("HTTP/1.0 500 Internal Server Error");
        let parts: Vec<&str> = status_line_str.split_whitespace().collect();
        status = if parts.len() >= 2 { parts[1].parse().unwrap_or(502) } else { 502 };

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            if st.status == 0 {
                st.status = status;
            }
            st.bytes_received = bytes_received_from_upstream;
            st.response_length = (bytes_received_from_upstream - body_start as i64).max(0);
        }

        // ngx_http_upstream_test_next: a status proxy_next_upstream names,
        // with tries left
        let ft = match status {
            500 => FT_HTTP_500,
            502 => FT_HTTP_502,
            503 => FT_HTTP_503,
            504 => FT_HTTP_504,
            403 => FT_HTTP_403,
            404 => FT_HTTP_404,
            429 => FT_HTTP_429,
            _ => 0,
        };
        if ft != 0 {
            let mut mask = ft;
            if g.u.request_sent && matches!(r.method.get(), crate::NGX_HTTP_POST | crate::NGX_HTTP_LOCK | crate::NGX_HTTP_PATCH) {
                mask |= FT_NON_IDEMPOTENT;
            }
            let timeout = next_upstream_timeout;
            if g.u.pc.tries > 1
                && next_upstream_mask & mask == mask
                && !(g.u.request_sent && r.request_body_no_buffering.get())
                && !(timeout != 0 && ngx_core::times::current_msec().saturating_sub(g.u.pc.start_time) >= timeout)
            {
                upstream = None;
                match g.u.next(&r, ft) {
                    Ok(()) => continue 'retry,
                    Err(st) => return return_error(&r, st).await,
                }
            }
        }
        break 'retry;
    }
    // an unbuffered response body is read while it is sent (below)
    let stream_body = !u_buffering
        && !(r.method.get() == NGX_HTTP_HEAD || r.header_only.get())
        && status != 204
        && status != 304;
    // the connection goes back to the keepalive cache when the request is
    // done, if the response allows
    if response_keepalive && status != 101 && !stream_body {
        g.conn = upstream.take().map(|sock| crate::upstream::UpstreamConn {
            sock,
            requests: upstream_requests,
            start_time: upstream_start_time,
        });
        g.keepalive = true;
    }
    // proxy_cache_revalidate: on 304 the upstream is telling us the cached
    // entry is still fresh — repush it with a new expiry and serve HIT so
    // the client sees REVALIDATED. Matches C's ngx_http_upstream_process_headers
    // 304-branch.
    if status == 304 {
        if let Some(hints) = crate::proxy_cache::get_revalidate(&r) {
            if let Some(mut cached) = hints.cached.clone() {
                let cache_conf = {
                    let lcf_c = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
                    let c = lcf_c.borrow();
                    c.cache.clone()
                };
                // Compute new expires from the SAME headers already on the
                // cached entry (upstream only signals freshness; the TTL
                // comes from the response's Cache-Control / Expires /
                // X-Accel-Expires / proxy_cache_valid, same precedence
                // as the initial save).
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                cached.expires_epoch = crate::proxy_cache::compute_expires_from_cached(&cache_conf, &cached, now)
                    .unwrap_or(now);
                crate::proxy_cache::save(&hints.zone, &hints.key, &cached);
                crate::proxy_cache::set_status(&r, crate::proxy_cache::CacheStatus::Revalidated);
                return crate::proxy_cache::serve_hit(&r, cached).await;
            }
        }
    }
    // stale-if-error: upstream returned 5xx but the cached response had
    // Cache-Control: stale-if-error=N and we're still within [expires,
    // expires+N]. Serve the cached body as STALE — matches C's
    // ngx_http_upstream_cache_send returning STALE on ngx_http_upstream_next
    // when u->cache_status is EXPIRED and the entry is stale-if-error-ok.
    if status >= 400 {
        if let Some(hints) = crate::proxy_cache::get_revalidate(&r) {
            if let Some(cached) = hints.cached.clone() {
                let lcf_c = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
                let cache_conf = lcf_c.borrow().cache.clone();
                // For status-based failures (5xx / 4xx from upstream) C's
                // ngx_http_upstream_test_next only serves stale when
                // cache_use_stale matches the specific status bit —
                // stale-if-error from Cache-Control alone does not apply
                // (that's for connection-level errors only).
                let bit = crate::proxy_cache::use_stale_status_bit(status as u16);
                if bit != 0 && cache_conf.use_stale & bit != 0 {
                    crate::proxy_cache::set_status(&r, crate::proxy_cache::CacheStatus::Stale);
                    return crate::proxy_cache::serve_hit(&r, cached).await;
                }
            }
        }
    }
    let headers_section = &response[..status_line_end];
    let status_line_end_nl = headers_section.iter().position(|&b| b == b'\n').unwrap_or(headers_section.len());
    let _ = status_line_end_nl;

    // Fresh upstream request: any $upstream_http_* headers left over from a
    // previous proxy round (e.g. X-Accel-Redirect that triggered this one)
    // must not leak into the new stash — that would cause a redirect loop
    // when the second upstream returns without X-Accel-Redirect.
    r.upstream_headers_in.borrow_mut().clear();

    // Set status in response headers and copy upstream headers
    let mut copied = crate::upstream::CopiedHeaders::default();
    // Effective hide list: default PROXY_HIDE_HEADERS + user's hide_headers,
    // minus user's pass_headers (pass wins over hide). Precompute once so the
    // per-header check is a linear scan on a short vec.
    let effective_hide: Vec<Vec<u8>> = {
        let lcf_h = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        let c = lcf_h.borrow();
        let mut set: Vec<Vec<u8>> = PROXY_HIDE_HEADERS.iter().map(|s| s.to_vec()).collect();
        if let Some(hide) = &c.hide_headers {
            for h in hide {
                if !set.iter().any(|x| x == h) { set.push(h.clone()); }
            }
        }
        if let Some(pass) = &c.pass_headers {
            set.retain(|h| !pass.iter().any(|p| p == h));
        }
        set
    };
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = status;
        // Parse and copy headers from headers_section
        let mut pos = status_line_end_nl + 1;
        while pos < headers_section.len() {
            let line_end = headers_section[pos..].iter().position(|&b| b == b'\n').map(|i| pos + i).unwrap_or(headers_section.len());
            let line = &headers_section[pos..line_end];
            let line = if line.last() == Some(&b'\r') { &line[..line.len()-1] } else { line };
            if line.is_empty() { break; }
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                let name = &line[..colon];
                let mut vstart = colon + 1;
                while vstart < line.len() && (line[vstart] == b' ' || line[vstart] == b'\t') { vstart += 1; }
                let value = &line[vstart..];
                // Stash into upstream_headers_in so $upstream_http_* can read them.
                r.upstream_headers_in.borrow_mut().push(crate::request::TableElt::new(name, value));
                let lc = name.to_ascii_lowercase();
                // proxy_hide_header / default hide: skip emission entirely.
                // upstream_headers_in above already captured it for
                // $upstream_http_* variables.
                if effective_hide.iter().any(|h| h == &lc) {
                    pos = line_end + 1;
                    continue;
                }
                crate::upstream::copy_header(&mut ho, &mut copied, status, name, value);
            }
            pos = line_end + 1;
        }
    }

    // If the upstream sent malformed / duplicate framing headers per C
    // ngx_http_proxy_process_header semantics, bail with 502 before we send
    // anything to the client.
    if copied.invalid
        || (copied.chunked && copied.saw_content_length)
    {
        return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
    }
    // Suppress duplicate Expires (silently drop the second occurrence).
    let _ = copied.duplicate_expires;

    // X-Accel-Limit-Rate: bytes-per-second cap on the response, matching
    // ngx_http_upstream_process_limit_rate. Applied to r.limit_rate BEFORE
    // X-Accel-Redirect so the header survives the internal redirect
    // (C's upstream_process_headers assigns u->headers_in.x_accel_limit_rate
    // which propagates via r->limit_rate to the redirected request).
    {
        let xal_val = r.upstream_headers_in.borrow().iter()
            .find(|h| h.lowcase_key.eq_ignore_ascii_case(b"x-accel-limit-rate"))
            .map(|h| h.value.borrow().clone());
        if let Some(v) = xal_val {
            if let Ok(s) = std::str::from_utf8(&v) {
                if let Ok(n) = s.trim().parse::<i64>() {
                    if n >= 0 {
                        r.limit_rate.set(n as usize);
                        r.limit_rate_set.set(true);
                    }
                }
            }
        }
    }

    // X-Accel-Redirect: if the upstream response carries this header, discard
    // the response body (we've already read it) and internally redirect. Keep
    // only the small allow-list of upstream headers marked `redirect=1` in
    // ngx_http_upstream.c (Content-Type, Set-Cookie, Cache-Control, Expires,
    // Accept-Ranges, Content-Disposition). Method coerces to GET (unless HEAD).
    let xar_val = r.upstream_headers_in.borrow().iter()
        .find(|h| h.lowcase_key.eq_ignore_ascii_case(b"x-accel-redirect"))
        .map(|h| h.value.borrow().clone());
    if let Some(xar) = xar_val {
        if !xar.is_empty() {
            const KEEP_LC: &[&[u8]] = &[
                b"content-type", b"set-cookie", b"content-disposition",
                b"cache-control", b"expires", b"accept-ranges",
            ];
            {
                let mut ho = r.headers_out.borrow_mut();
                ho.status = 0;
                ho.content_length_n = -1;
                ho.content_length = None;
                ho.headers.retain(|h| {
                    KEEP_LC.iter().any(|k| h.lowcase_key.eq_ignore_ascii_case(k))
                });
                ho.etag = None;
                ho.last_modified = None;
                ho.location = None;
                ho.content_encoding = None;
            }
            // ngx_http_upstream_finalize_request(r, u, NGX_DECLINED)
            g.finalize();
            r.upstream_states.borrow_mut().clear();
            if xar.first() == Some(&b'@') {
                let _ = crate::core_rt::named_location(&r, &xar).await;
                return NGX_DONE;
            }
            // Non-named: unescape the URI (splitting off any query at '?'),
            // then reject unsafe paths (../ etc.) with 404, matching the
            // ngx_http_parse_unsafe_uri gate C runs before internal_redirect.
            let (decoded, _) = ngx_core::string::unescape_uri(&xar, ngx_core::string::NGX_UNESCAPE_URI);
            // Split at first '?' (unescape stops at '?', so it's the last byte if present).
            let (uri_bytes, args_opt): (Vec<u8>, Option<Vec<u8>>) =
                if let Some(q) = decoded.iter().position(|&b| b == b'?') {
                    (decoded[..q].to_vec(), Some(decoded[q + 1..].to_vec()))
                } else {
                    (decoded, None)
                };
            let mut flags = 0u32;
            let empty: [u8; 0] = [];
            if crate::parse::parse_unsafe_uri(&uri_bytes, &empty, &mut flags) != NGX_OK {
                return return_error(&r, crate::NGX_HTTP_NOT_FOUND).await;
            }
            if r.method.get() != crate::NGX_HTTP_HEAD {
                r.method.set(crate::NGX_HTTP_GET);
                *r.method_name.borrow_mut() = b"GET".to_vec();
            }
            let _ = crate::core_rt::internal_redirect(&r, &uri_bytes, args_opt.as_deref()).await;
            return NGX_DONE;
        }
    }

    // Snapshot upstream Content-Length before send_header runs — filters like
    // addition_filter / sub_filter / gzip clear ho.content_length_n during
    // their header pass.
    let upstream_content_length = r.headers_out.borrow().content_length_n;


    // Proxied responses (uncacheable) must skip the not_modified filter —
    // the backend is responsible for handling If-Modified-Since / If-None-Match.
    // C sets this to `!u->cacheable` in ngx_http_upstream_send_response.
    r.disable_not_modified.set(true);

    // proxy_force_ranges: opt in to server-side range processing even though
    // the upstream response isn't file-backed. Matches C's `u->conf->force_ranges`
    // setting `r->allow_ranges = 1; r->single_range = 1;`.
    {
        let lcf_fr = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        if lcf_fr.borrow().force_ranges.get_or(false) {
            r.allow_ranges.set(true);
            r.single_range.set(true);
        }
        // Cached/cacheable responses go through range_filter regardless
        // of the upstream's Accept-Ranges — C's ngx_http_upstream_send_response
        // sets r->allow_ranges = 1 when u->cacheable is set.
        if lcf_fr.borrow().cache.zone.is_some() {
            r.allow_ranges.set(true);
        }
    }

    // Reject 101 Switching Protocols the client didn't ask for BEFORE we
    // send any headers — an upstream that unilaterally decides to switch
    // protocols on a plain request must not take over the client's socket.
    // Matches ngx_http_upstream_process_upgrade's headers_in.upgrade
    // check.
    if status == 101 {
        let client_wanted_upgrade = r.headers_in.borrow().headers.iter()
            .any(|h| h.hash.get() != 0 && h.lowcase_key == b"upgrade");
        if !client_wanted_upgrade {
            // Send a bare 502 status line with no body — matches C's
            // NGX_HTTP_UPSTREAM_INVALID_HEADER path where the response
            // is closed without an error page (test expects
            // body_bytes_sent == 0). Setting header_only makes the
            // header_filter skip body emission and the default 502
            // error_page.
            r.headers_out.borrow_mut().status = NGX_HTTP_BAD_GATEWAY as i64;
            r.header_only.set(true);
            r.keepalive.set(false);
            let _ = crate::core_rt::send_header(&r).await;
            return crate::NGX_DONE;
        }
    }
    // proxy_intercept_errors: hand off to error_page instead of forwarding the
    // upstream body — but only if the location actually has an error_page
    // configured for this status. Matches ngx_http_upstream_intercept_errors.
    {
        let lcf2 = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        let intercept = lcf2.borrow().intercept_errors.get_or(false);
        if intercept && status >= crate::NGX_HTTP_SPECIAL_RESPONSE {
            let clcf = r.clcf();
            let has_page = clcf
                .borrow()
                .error_pages
                .as_ref()
                .map(|pages| pages.iter().any(|p| p.status == status))
                .unwrap_or(false);
            if has_page {
                // Cache the upstream error before handing off to error_page,
                // so subsequent requests hit the cached error status and
                // trigger the same intercept path — matches C's behavior
                // where u->cache is populated even on intercept.
                let cache_conf = lcf2.borrow().cache.clone();
                if cache_conf.zone.is_some() {
                    let body = if body_start < response.len() {
                        response[body_start..].to_vec()
                    } else {
                        Vec::new()
                    };
                    let mut hdrs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
                    let ho = r.headers_out.borrow();
                    if !ho.content_type.is_empty() {
                        hdrs.push((b"Content-Type".to_vec(), ho.content_type.clone()));
                    }
                    for h in &ho.headers {
                        if h.hash.get() == 0 { continue; }
                        hdrs.push((h.key.clone(), h.value.borrow().clone()));
                    }
                    drop(ho);
                    crate::proxy_cache::maybe_save(
                        &r, &cache_conf, &upstream_uri,
                        status as u16, hdrs, body,
                    );
                }
                return status;
            }
        }
    }

    // proxy_cookie_domain / proxy_cookie_path: rewrite Set-Cookie Domain=
    // and Path= attributes before the header filter serializes them.
    rewrite_set_cookies(&r);

    // proxy_redirect: rewrite Location / Refresh (url=...) headers.
    rewrite_redirect_headers(&r, &upstream_uri);

    // Snapshot cached headers *before* send_header runs — filters
    // (addition_filter, sub_filter, gzip) rewrite headers_out during the
    // header pass, and we want the pre-filter view on disk so a later HIT
    // replays the same response the origin sent.
    let cache_snapshot_headers: Option<Vec<(Vec<u8>, Vec<u8>)>> = {
        let lcf_c = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        if lcf_c.borrow().cache.zone.is_some() {
            // Snapshot the raw upstream headers — including the ones the
            // proxy_hide list keeps from the client (X-Accel-Expires,
            // Set-Cookie, ...) — so cache TTL decisions and cache_control
            // parsing see the same view the C code does. `upstream_headers_in`
            // is populated before the hide filter runs.
            let uh = r.upstream_headers_in.borrow();
            let hdrs: Vec<(Vec<u8>, Vec<u8>)> = uh.iter()
                .map(|h| (h.key.clone(), h.value.borrow().clone()))
                .collect();
            Some(hdrs)
        } else {
            None
        }
    };

    // Send status and headers to client
    let send_hdr_rc = crate::core_rt::send_header(&r).await;
    if send_hdr_rc != NGX_OK {
        return NGX_ERROR;
    }

    // 101 Switching Protocols: the client and upstream now speak whatever
    // protocol the Upgrade negotiation settled on. Copy bytes both ways
    // until either side closes. This is the minimum implementation
    // proxy_upgrade.t / proxy_websocket.t / tunnel*.t need — no fancy
    // half-close handling, no chunked framing.
    if status == 101 {
        // The client-wanted-upgrade gate ran before send_header above, so
        // reaching here always means the client did ask for an upgrade.
        {
            if let Some(upstream_stream) = upstream.take() {
                // Force headers out through the write filter — postpone_output
                // would otherwise keep the 101 line buffered until the "last"
                // signal, which never arrives in an upgrade.
                let mut b = ngx_core::buf::Buf::from_vec(Vec::new());
                b.flush = true;
                b.sync = true;
                let mut chain = ngx_core::buf::Chain::new();
                chain.push_back(b);
                let _ = crate::core_rt::output_filter(&r, chain).await;

                // Anything past the header block was already sent by upstream
                // as part of the upgraded protocol (e.g. a WebSocket server
                // that started sending frames immediately). Forward that
                // trailing tail to the client before entering the read loop.
                if body_start < response.len() {
                    let tail = &response[body_start..];
                    let _ = r.connection.send_all(tail).await;
                }
                let _ = proxy_upgrade_tunnel(r.clone(), upstream_stream).await;
                return crate::NGX_DONE;
            }
            return crate::NGX_DONE;
        }
        return crate::NGX_DONE;
    }

    // Forward response body. Respect HEAD (no body) and Content-Length (truncate
    // any extra bytes upstream sent past the declared length — matches C which
    // reads exactly content_length_n bytes and logs "upstream sent more data
    // than specified in Content-Length"). We captured upstream_content_length
    // above BEFORE send_header, because some filters (e.g. addition_filter,
    // sub_filter, gzip) clear r.headers_out.content_length_n.
    let head_only = r.method.get() == NGX_HTTP_HEAD || r.header_only.get();
    if head_only {
        // Cache HEAD responses too, so a later request (HEAD or GET) can
        // HIT. In the convert_head=on path we sent GET upstream, so the
        // real body is in `response`. Skip caching if the upstream sent
        // fewer bytes than Content-Length declared — matches the
        // short_response guard on the GET path.
        if let Some(hdrs) = cache_snapshot_headers {
            // If we forwarded HEAD → GET upstream (convert_head=on), a
            // real GET body should be present; treat a partial body as
            // "short" and skip caching. If the client sent HEAD and we
            // stayed HEAD upstream, Content-Length describes the notional
            // GET body — there's no upstream body to be short.
            let head_upstream = method == "HEAD";
            let tail_len = response.len().saturating_sub(body_start);
            let short_response = !head_upstream
                && upstream_content_length >= 0
                && (upstream_content_length as usize) > tail_len;
            if !short_response {
                let lcf_s = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
                let cache_conf = lcf_s.borrow().cache.clone();
                let body = if body_start < response.len() {
                    let tail = &response[body_start..];
                    let end = if upstream_content_length >= 0 {
                        (upstream_content_length as usize).min(tail.len())
                    } else {
                        tail.len()
                    };
                    tail[..end].to_vec()
                } else {
                    Vec::new()
                };
                crate::proxy_cache::maybe_save(
                    &r, &cache_conf, &upstream_uri,
                    status as u16, hdrs, body,
                );
            }
        }
        return NGX_OK;
    }
    if stream_body {
        let mut sock = match upstream.take() {
            Some(s) => s,
            None => return NGX_ERROR,
        };

        let initial = if body_start < response.len() { response[body_start..].to_vec() } else { Vec::new() };

        let conn_close = u_upstream_wants_close || !conn_line.is_empty() || !response.starts_with(b"HTTP/1.1");

        let (rc, keepalive) = send_non_buffered(&r, &mut sock, &initial, status, u_expected_body_len, u_is_chunked, conn_close).await;

        if keepalive {
            g.conn = Some(crate::upstream::UpstreamConn { sock, requests: upstream_requests, start_time: upstream_start_time });
            g.keepalive = true;
        }

        return rc;
    }

    // proxy_store: if configured, buffer the whole body and write it out
    // once we know the final decoded length.
    let body_snapshot_for_store: Vec<u8>;
    if body_start < response.len() {
        let mut short_response = false;
        let body_owned: Vec<u8>;
        let body: &[u8] = if copied.chunked {
            body_owned = decode_chunked(&response[body_start..]);
            &body_owned
        } else {
            let end = if upstream_content_length >= 0 {
                let want = body_start + upstream_content_length as usize;
                if want > response.len() {
                    // Upstream sent fewer bytes than Content-Length promised.
                    short_response = true;
                    response.len()
                } else {
                    want
                }
            } else {
                response.len()
            };
            &response[body_start..end]
        };

        // Create a buffer chain for the body
        use ngx_core::buf::{Buf, BufData, Chain};
        use std::collections::VecDeque;

        let mut chain: Chain = VecDeque::new();

        // Only mark as last_buf when the response is well-formed. A short
        // response (fewer bytes than Content-Length) has to signal "no more
        // data" without triggering downstream last_buf handlers like
        // addition_filter's after_body. C achieves this by never delivering
        // last_buf to the filter chain in the short case; the client sees the
        // truncated body via connection close.
        let final_buf = !short_response;

        let buf = Buf {
            pos: 0,
            last: body.len(),
            file_pos: 0,
            file_last: 0,
            tag: 0,
            num: 0,
            data: BufData::Memory(body.to_vec()),
            temporary: true,
            memory: false,
            mmap: false,
            recycled: false,
            in_file: false,
            flush: !final_buf,
            sync: false,
            last_buf: final_buf,
            last_in_chain: true,
            temp_file: false,
        };

        chain.push_back(buf);

        body_snapshot_for_store = body.to_vec();
        if crate::core_rt::output_filter(&r, chain).await != NGX_OK {
            return NGX_ERROR;
        }
        if !short_response {
            maybe_store_body(&r, &body_snapshot_for_store);
            if let Some(hdrs) = cache_snapshot_headers {
                let lcf_s = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
                let cache_conf = lcf_s.borrow().cache.clone();
                crate::proxy_cache::maybe_save(
                    &r, &cache_conf, &upstream_uri,
                    status as u16, hdrs, body_snapshot_for_store,
                );
            }
        }
    } else {
        // Empty 200 response — still honor proxy_store (writes an empty file).
        maybe_store_body(&r, &[]);
        if let Some(hdrs) = cache_snapshot_headers {
            let lcf_s = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
            let cache_conf = lcf_s.borrow().cache.clone();
            crate::proxy_cache::maybe_save(
                &r, &cache_conf, &upstream_uri,
                status as u16, hdrs, Vec::new(),
            );
        }
    }

    NGX_OK
}

/// The peers of a proxy_pass URL with variables (u->resolved,
/// ngx_http_upstream_init_request): the upstream its host names, its
/// address if it is one, or the addresses the resolver finds.
async fn resolved_peer(
    r: &R,
    url: &[u8],
    next_upstream: u32,
    next_upstream_tries: u32,
    next_upstream_timeout: u64,
    tag: usize,
) -> Result<crate::upstream::UpstreamPeer, i64> {
    let (add, port) = if url.len() >= 8 && url[..8].eq_ignore_ascii_case(b"https://") { (8, 443) } else { (7, 80) };

    let mut u = ngx_core::inet::Url::new(&url[add.min(url.len())..]);
    u.default_port = port;
    u.uri_part = true;
    u.no_resolve = true;

    if ngx_core::inet::parse_url(&mut u).is_err() {
        if let Some(err) = u.err {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "{} in upstream \"{}\"", err, ngx_core::string::B(&u.url));
        }
        return Err(crate::NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    crate::upstream::UpstreamPeer::resolve(r, &u, next_upstream, next_upstream_tries, next_upstream_timeout, tag).await
}

/// The request body buffers read so far (rb->bufs), taken to be sent.
fn take_request_body_bufs(r: &R) -> ngx_core::buf::Chain {
    match r.request_body.borrow().as_ref() {
        Some(rb) => std::mem::take(&mut rb.borrow_mut().bufs),
        None => ngx_core::buf::Chain::new(),
    }
}

/// The data of unbuffered request body buffers as sent to the upstream:
/// as is, or, when chunked, ngx_http_proxy_body_output_filter: one chunk
/// for all the buffers ("%xO" CRLF ... CRLF), and the last chunk after the
/// last buffer.
fn body_output_filter(out: &mut Vec<u8>, bufs: &ngx_core::buf::Chain, chunked: bool) {
    let size: usize = bufs.iter().map(|b| b.buf_size() as usize).sum();
    if chunked && size > 0 {
        out.extend_from_slice(format!("{:x}\r\n", size).as_bytes());
    }
    for b in bufs.iter() {
        if let ngx_core::buf::BufData::Memory(m) = &b.data {
            let end = b.last.min(m.len());
            if b.pos < end {
                out.extend_from_slice(&m[b.pos..end]);
            }
        }
    }
    if !chunked {
        return;
    }
    if bufs.back().is_some_and(|b| b.last_buf) {
        out.extend_from_slice(if size == 0 { b"0\r\n\r\n" } else { b"\r\n0\r\n\r\n" });
    } else if size > 0 {
        out.extend_from_slice(b"\r\n");
    }
}

/// ngx_http_upstream_send_request_body for an unbuffered body, once the
/// header and the body read so far are sent: read the rest of the body as
/// the client sends it (ngx_http_read_unbuffered_request_body) and send it
/// on, framed by the module's `output` filter, until it is complete. Returns the bytes sent, or the status to
/// finalize with: a client body error, 408 when the client times out
/// (ngx_http_upstream_read_request_handler), 502 when the upstream write
/// fails. Returns early if the upstream responds (or closes) first.
pub(crate) async fn send_request_body(r: &R, upstream: &mut UpstreamSock, output: &dyn Fn(&mut Vec<u8>, &ngx_core::buf::Chain)) -> Result<i64, i64> {
    let timeout = *r.clcf().borrow().client_body_timeout;
    let mut sent = 0i64;
    loop {
        let rc = crate::request_body::read_unbuffered_request_body(r).await;
        if rc >= crate::NGX_HTTP_SPECIAL_RESPONSE {
            return Err(rc);
        }
        let bufs = take_request_body_bufs(r);
        if !bufs.is_empty() {
            let mut out = Vec::new();
            output(&mut out, &bufs);
            if !out.is_empty() {
                if upstream.write_all(&out).await.is_err() {
                    return Err(NGX_HTTP_BAD_GATEWAY as i64);
                }
                sent += out.len() as i64;
            }
            if !r.reading_body.get() {
                return Ok(sent);
            }
            continue;
        }
        if !r.reading_body.get() {
            return Ok(sent);
        }
        tokio::select! {
            res = tokio::time::timeout(std::time::Duration::from_millis(timeout), crate::request_body::wait_request_body(r)) => {
                if res.is_err() {
                    r.connection.timedout.set(true);
                    return Err(crate::NGX_HTTP_REQUEST_TIME_OUT);
                }
            }
            _ = upstream.wait_readable() => return Ok(sent),
        }
    }
}

async fn return_error(r: &R, status: i64) -> i64 {
    // Populate a synthetic upstream state so $upstream_addr / $upstream_status
    // in add_header 'always' show the failed peer(s) — otherwise the client's
    // error response has no way to reflect which upstream was tried.
    if r.upstream_states.borrow().is_empty() {
        r.upstream_states.borrow_mut().push(crate::request::UpstreamState {
            status,
            response_length: 0,
            bytes_received: 0,
            bytes_sent: 0,
            peer: Vec::new(),
            ..Default::default()
        });
    }
    // Return the status; finalize_request will invoke special_response_handler
    // which builds the default error body AND runs the header filter chain
    // (so headers_more / add_header 'always' apply).
    status
}

/// Returns true when `input` contains a fully-terminated HTTP/1.1 chunked
/// body — i.e. the size-zero chunk followed by a terminating CRLF.
/// Bidirectional pipe between the client (r.connection) and the upstream
/// TcpStream after a 101 Switching Protocols response. Mirrors what
/// ngx_http_upstream_upgrade sets up for WebSocket / HTTP upgrade paths.
async fn proxy_upgrade_tunnel(r: R, upstream: UpstreamSock) -> i64 {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    let (mut up_r, mut up_w) = tokio::io::split(upstream);
    let client = r.connection.clone();

    // Push any bytes the client sent past the request headers to upstream
    // before we start the recv/send loop. Without this, a client that
    // pipelined data on top of the Upgrade request (e.g. the tests'
    // upgrade_connect message => 'foo') loses that data — the tunnel
    // only sees new bytes read from the socket after headers were
    // consumed by the header parser.
    let pipelined = {
        let mut hb = r.http_connection.buffer.borrow_mut();
        let tail = hb.unread().to_vec();
        hb.pos = hb.last;
        tail
    };
    if !pipelined.is_empty() {
        if up_w.write_all(&pipelined).await.is_err() {
            let _ = up_w.shutdown().await;
            return NGX_OK;
        }
    }

    // Two forwarding tasks — one per direction. Whichever finishes first
    // closes the tunnel by cancelling the other via drop.
    let client_to_up = {
        let client = client.clone();
        async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match client.recv(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if up_w.write_all(&buf[..n]).await.is_err() { break; }
                    }
                }
            }
            let _ = up_w.shutdown().await;
        }
    };
    let up_to_client = {
        let client = client.clone();
        async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match up_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if client.send_all(&buf[..n]).await.is_err() { break; }
                    }
                }
            }
        }
    };
    tokio::join!(client_to_up, up_to_client);
    NGX_OK
}

fn chunked_complete(input: &[u8]) -> bool {
    let mut i = 0;
    while i < input.len() {
        let line_end = match input[i..].iter().position(|&b| b == b'\n') {
            Some(p) => i + p,
            None => return false,
        };
        let mut size_end = line_end;
        if size_end > i && input[size_end - 1] == b'\r' {
            size_end -= 1;
        }
        let hex_end = input[i..size_end]
            .iter()
            .position(|&b| b == b';' || b == b' ' || b == b'\t')
            .map(|p| i + p)
            .unwrap_or(size_end);
        let hex_str = match std::str::from_utf8(&input[i..hex_end]) {
            Ok(s) => s.trim(),
            Err(_) => return false,
        };
        let size = match usize::from_str_radix(hex_str, 16) {
            Ok(n) => n,
            Err(_) => return false,
        };
        i = line_end + 1;
        if size == 0 {
            // Consume trailer headers (if any) up to the final CRLF/blank line.
            loop {
                let end = match input[i..].iter().position(|&b| b == b'\n') {
                    Some(p) => i + p,
                    None => return false,
                };
                let line = &input[i..end];
                let line = if line.last() == Some(&b'\r') { &line[..line.len()-1] } else { line };
                i = end + 1;
                if line.is_empty() {
                    return true;
                }
            }
        }
        if i + size > input.len() { return false; }
        i += size;
        if i < input.len() && input[i] == b'\r' { i += 1; }
        if i < input.len() && input[i] == b'\n' { i += 1; }
    }
    false
}

/// Parse upstream URL of form "http://host:port/path" or "http://host/path" (assumes port 80)
/// Decode HTTP/1.1 chunked transfer encoding. Malformed input truncates the
/// output at the first bad chunk rather than erroring — mirrors what a
/// buffering proxy tends to do when the upstream is misbehaving.
fn decode_chunked(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        // Find end of chunk size line
        let line_end = match input[i..].iter().position(|&b| b == b'\n') {
            Some(p) => i + p,
            None => break,
        };
        let mut size_end = line_end;
        // Strip trailing \r
        if size_end > i && input[size_end - 1] == b'\r' {
            size_end -= 1;
        }
        // Chunk size stops at ';' (chunk extension) or whitespace
        let hex_end = input[i..size_end]
            .iter()
            .position(|&b| b == b';' || b == b' ' || b == b'\t')
            .map(|p| i + p)
            .unwrap_or(size_end);
        let hex_str = match std::str::from_utf8(&input[i..hex_end]) {
            Ok(s) => s.trim(),
            Err(_) => break,
        };
        let size = match usize::from_str_radix(hex_str, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        i = line_end + 1; // move past \n
        if size == 0 {
            break;
        }
        if i + size > input.len() {
            out.extend_from_slice(&input[i..]);
            break;
        }
        out.extend_from_slice(&input[i..i + size]);
        i += size;
        // Skip trailing \r\n after chunk data
        if i < input.len() && input[i] == b'\r' { i += 1; }
        if i < input.len() && input[i] == b'\n' { i += 1; }
    }
    out
}

/// The length of the "http://" or "https://" prefix of a proxy_pass URL.
fn scheme_len(uri: &str) -> usize {
    if uri.len() >= 8 && uri[..8].eq_ignore_ascii_case("https://") {
        8
    } else {
        7
    }
}

fn parse_upstream_uri(uri: &str) -> Option<(String, u16, String)> {
    let (rest, default_port) = if let Some(r) = uri.strip_prefix("http://") {
        (r, 80u16)
    } else if let Some(r) = uri.strip_prefix("https://") {
        (r, 443u16)
    } else {
        return None;
    };

    // Unix socket form: "unix:/path/to.sock" or "unix:/path/to.sock:/uri"
    if let Some(rest) = rest.strip_prefix("unix:") {
        // Sock path ends at the LAST ":" before the URI (which starts with '/').
        // Simple heuristic: split on ":/", treating everything before as the sock
        // path and everything from '/' as the URI. If no ":/" found, the whole
        // rest is the sock path and URI is "/".
        let (sock, path) = match rest.rfind(":/") {
            Some(p) => (&rest[..p], rest[p + 1..].to_string()),
            None => (rest, "/".to_string()),
        };
        // Encode "unix:<path>" as the host and return sentinel port 0 so
        // the caller uses UnixStream rather than TcpStream.
        return Some((format!("unix:{}", sock), 0, path));
    }

    // IPv6 form: [addr]:port/path or [addr]/path
    if let Some(r) = rest.strip_prefix('[') {
        let end = r.find(']')?;
        let host = r[..end].to_string();
        let after = &r[end + 1..];
        let (port, path) = if let Some(p) = after.strip_prefix(':') {
            let slash = p.find('/').unwrap_or(p.len());
            let port: u16 = p[..slash].parse().ok()?;
            let path = if slash == p.len() { "/".to_string() } else { p[slash..].to_string() };
            (port, path)
        } else if after.is_empty() || after.starts_with('/') {
            let path = if after.is_empty() { "/".to_string() } else { after.to_string() };
            (default_port, path)
        } else {
            return None;
        };
        return Some((host, port, path));
    }

    // Find host:port or just host
    let (host_port, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], rest[pos..].to_string())
    } else {
        (rest, "/".to_string())
    };

    // Parse host and port
    let (host, port) = if let Some(pos) = host_port.find(':') {
        let h = &host_port[..pos];
        let p: u16 = host_port[pos+1..].parse().ok()?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), default_port)
    };

    Some((host, port, path))
}

/// The values of proxy_ssl_protocols (ngx_http_proxy_ssl_protocols).
const SSL_PROTOCOLS: &[(&str, u32)] = &[
    ("SSLv2", 0x0002),
    ("SSLv3", 0x0004),
    ("TLSv1", 0x0008),
    ("TLSv1.1", 0x0010),
    ("TLSv1.2", 0x0020),
    ("TLSv1.3", 0x0040),
];

pub fn proxy_module() -> ModuleDef {
    let commands = vec![
        cmd_fn!("proxy_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_pass_handler),
        cmd_fn!("proxy_redirect", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_redirect_handler),
        ngx_core::cmd!("proxy_buffering", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, buffering, set_flag),
        ngx_core::cmd!("proxy_request_buffering", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, request_buffering, set_flag),
        cmd_fn!("proxy_bind", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_bind_handler),
        ngx_core::cmd!("proxy_connect_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, connect_timeout, set_msec),
        cmd_fn!("proxy_send_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_send_timeout_handler),
        ngx_core::cmd!("proxy_read_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, read_timeout, set_msec),
        cmd_fn!("proxy_set_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_set_header_handler),
        // Additional proxy directives that tests need
        cmd_fn!("proxy_temp_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_busy_buffers_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_max_temp_file_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_next_upstream", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, proxy_next_upstream_handler),
        cmd_fn!("proxy_next_upstream_tries", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_next_upstream_tries_handler),
        ngx_core::cmd!("proxy_next_upstream_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, next_upstream_timeout, set_msec),
        ngx_core::cmd!("proxy_pass_request_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, pass_request_headers, set_flag),
        ngx_core::cmd!("proxy_pass_request_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, pass_request_body, set_flag),
        cmd_fn!("proxy_method", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_method_handler),
        cmd_fn!("proxy_http_version", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let v = match cf.args[1].as_slice() {
                b"1.0" => 0u32,
                b"1.1" => 1,
                _ => return Err(msg("invalid version")),
            };
            cell.borrow_mut().http_version = Val::set(v);
            Ok(())
        }),
        cmd_fn!("proxy_socket_keepalive", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cookie_domain", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_cookie_domain_handler),
        cmd_fn!("proxy_cookie_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_cookie_path_handler),
        cmd_fn!("proxy_cookie_flags", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, proxy_cookie_flags_handler),
        cmd_fn!("proxy_set_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_set_body_handler),
        cmd_fn!("proxy_pass_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let name = cf.args[1].to_ascii_lowercase();
            let mut c = cell.borrow_mut();
            let list = c.pass_headers.get_or_insert_with(Vec::new);
            if !list.iter().any(|x| x == &name) { list.push(name); }
            Ok(())
        }),
        cmd_fn!("proxy_hide_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let name = cf.args[1].to_ascii_lowercase();
            let mut c = cell.borrow_mut();
            let list = c.hide_headers.get_or_insert_with(Vec::new);
            if !list.iter().any(|x| x == &name) { list.push(name); }
            Ok(())
        }),
        cmd_fn!("proxy_ignore_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            for a in cf.args[1..].to_vec() {
                cell.borrow_mut().cache.ignore_headers.push(a.to_ascii_lowercase());
            }
            Ok(())
        }),
        ngx_core::cmd!("proxy_intercept_errors", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, intercept_errors, set_flag),
        cmd_fn!("proxy_ignore_client_abort", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_store", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_store_handler),
        cmd_fn!("proxy_store_access", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_limit_rate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd!("proxy_force_ranges", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, force_ranges, set_flag),
        cmd_fn!("proxy_headers_hash_max_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_headers_hash_bucket_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_path", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::None, |cf, _cmd, _conf| crate::proxy_cache::parse_proxy_cache_path(cf)),
        cmd_fn!("proxy_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            if cf.args[1] == b"off" {
                let mut c = cell.borrow_mut();
                c.cache.zone = None;
                c.cache.zone_cv = None;
                c.cache.explicitly_off = true;
            } else if cf.args[1].contains(&b'$') {
                let cv = crate::script::compile_complex_value(cf, &cf.args[1].clone(), 0)?;
                let mut c = cell.borrow_mut();
                c.cache.zone = Some(cf.args[1].clone());
                c.cache.zone_cv = Some(Rc::new(cv));
            } else {
                let mut c = cell.borrow_mut();
                c.cache.zone = Some(cf.args[1].clone());
                c.cache.zone_cv = None;
            }
            Ok(())
        }),
        cmd_fn!("proxy_cache_key", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let cv = crate::script::compile_complex_value(cf, &cf.args[1].clone(), 0)?;
            cell.borrow_mut().cache.key = Some(Rc::new(cv));
            Ok(())
        }),
        cmd_fn!("proxy_cache_valid", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let cv = crate::proxy_cache::parse_cache_valid(&cf.args[1..])?;
            cell.borrow_mut().cache.valid.push(cv);
            Ok(())
        }),
        cmd_fn!("proxy_cache_bypass", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            for a in cf.args[1..].to_vec() {
                let cv = crate::script::compile_complex_value(cf, &a, 0)?;
                cell.borrow_mut().cache.bypass.push(Rc::new(cv));
            }
            Ok(())
        }),
        cmd_fn!("proxy_cache_use_stale", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let bits = crate::proxy_cache::parse_use_stale_flags(&cf.args[1..].to_vec())?;
            cell.borrow_mut().cache.use_stale = bits;
            Ok(())
        }),
        cmd_fn!("proxy_cache_lock", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            cell.borrow_mut().cache.lock = cf.args[1] == b"on";
            Ok(())
        }),
        cmd_fn!("proxy_cache_lock_age", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let t = ngx_core::parse::parse_time(&cf.args[1], false).ok_or_else(|| ngx_core::conf::msg("invalid time"))?;
            cell.borrow_mut().cache.lock_age_ms = t as u64;
            Ok(())
        }),
        cmd_fn!("proxy_cache_lock_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let t = ngx_core::parse::parse_time(&cf.args[1], false).ok_or_else(|| ngx_core::conf::msg("invalid time"))?;
            cell.borrow_mut().cache.lock_timeout_ms = t as u64;
            Ok(())
        }),
        cmd_fn!("proxy_cache_min_uses", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let n = ngx_core::string::atoi(&cf.args[1]).ok_or_else(|| ngx_core::conf::msg("invalid number"))?;
            cell.borrow_mut().cache.min_uses = n as u32;
            Ok(())
        }),
        cmd_fn!("proxy_cache_revalidate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            cell.borrow_mut().cache.revalidate = cf.args[1] == b"on";
            Ok(())
        }),
        cmd_fn!("proxy_cache_max_range_offset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let n = ngx_core::string::atoi(&cf.args[1]).ok_or_else(|| ngx_core::conf::msg("invalid number"))?;
            cell.borrow_mut().cache.max_range_offset = Some(n as u64);
            Ok(())
        }),
        cmd_fn!("proxy_cache_methods", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_purge", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cache_convert_head", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let v = &cf.args[1];
            cell.borrow_mut().cache.convert_head = v == b"on";
            Ok(())
        }),
        cmd_fn!("proxy_cache_background_update", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            cell.borrow_mut().cache.background_update = cf.args[1] == b"on";
            Ok(())
        }),
        cmd_fn!("proxy_no_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            for a in cf.args[1..].to_vec() {
                let cv = crate::script::compile_complex_value(cf, &a, 0)?;
                cell.borrow_mut().cache.no_cache.push(Rc::new(cv));
            }
            Ok(())
        }),
        cmd_fn!("proxy_ssl_session_reuse", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, proxy_ssl_flag_handler),
        cmd_fn!("proxy_ssl_protocols", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, proxy_ssl_protocols_handler),
        ngx_core::cmd!("proxy_ssl_ciphers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, ssl_ciphers, set_str),
        cmd_fn!("proxy_ssl_name", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_ssl_name_handler),
        cmd_fn!("proxy_ssl_server_name", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, proxy_ssl_flag_handler),
        cmd_fn!("proxy_ssl_verify", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, proxy_ssl_flag_handler),
        ngx_core::cmd!("proxy_ssl_verify_depth", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, ssl_verify_depth, set_num),
        ngx_core::cmd!("proxy_ssl_trusted_certificate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, ssl_trusted_certificate, set_str),
        ngx_core::cmd!("proxy_ssl_crl", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, ssl_crl, set_str),
        cmd_fn!("proxy_ssl_certificate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_ssl_certificate_handler),
        cmd_fn!("proxy_ssl_certificate_key", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_ssl_certificate_handler),
        cmd_fn!("proxy_ssl_certificate_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::Loc, proxy_ssl_certificate_cache_handler),
        cmd_fn!("proxy_ssl_password_file", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_ssl_password_file_handler),
        cmd_fn!("proxy_ssl_conf_command", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, proxy_ssl_conf_command_handler),
    ];

    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_proxy_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_proxy_conf() {
        let mut cf = Conf::default();
        let _slot = create_loc_conf(&mut cf);
    }
}


fn proxy_cookie_domain_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    parse_cookie_rewrite(cf, conf, /*is_domain=*/true)
}

fn proxy_cookie_path_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    parse_cookie_rewrite(cf, conf, /*is_domain=*/false)
}

fn parse_cookie_rewrite(cf: &mut Conf, conf: Option<Rc<dyn Any>>, is_domain: bool) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    // Special forms: `off` and `<flag>`. `off` clears (we take the single-arg
    // shape as a signal to disable inherited rewrites — matches C which
    // pushes a sentinel; here we just no-op by not appending).
    if args.len() == 2 {
        if args[1] == b"off" {
            // Mark as intentionally-empty by pushing nothing but blocking
            // inheritance: we set a sentinel field so merge knows. For now
            // simulate by clearing (parent inheritance already gated on
            // is_empty()).
            let mut c = cell.borrow_mut();
            if is_domain { c.cookie_domains.clear(); c.cookie_domains.push(cookie_rewrite_off()); }
            else { c.cookie_paths.clear(); c.cookie_paths.push(cookie_rewrite_off()); }
            return Ok(());
        }
        return Err(msg("invalid number of arguments"));
    }
    if args.len() != 3 {
        return Err(msg("invalid number of arguments"));
    }

    let pattern_src = &args[1];
    let replacement_src = &args[2];

    let (pattern, replacement) = if !pattern_src.is_empty() && pattern_src[0] == b'~' {
        // Regex form: ~PATTERN  or  ~*PATTERN (case-insensitive).
        // Note: for proxy_cookie_domain, ~ itself is *always* caseless in C
        // (see ngx_http_proxy_cookie_domain: caseless=1). For cookie_path,
        // only ~* is caseless.
        let (mut caseless, body) = if pattern_src.len() >= 2 && pattern_src[1] == b'*' {
            (true, &pattern_src[2..])
        } else {
            (false, &pattern_src[1..])
        };
        if is_domain { caseless = true; }
        let flags = if caseless { ngx_core::regex::NGX_REGEX_CASELESS } else { 0 };
        let re = ngx_core::regex::Regex::compile(body, flags)
            .map_err(|e| cf.emerg(format_args!("regex error: {}", e)))?;
        let repl = crate::script::compile_complex_value(cf, replacement_src, 0)?;
        (CookieRewritePattern::Regex(re), repl)
    } else if is_domain {
        // Domain: strip leading '.' from both pattern and replacement (C does this).
        let mut p = pattern_src.clone();
        if !p.is_empty() && p[0] == b'.' { p.remove(0); }
        let mut r = replacement_src.clone();
        if !r.is_empty() && r[0] == b'.' { r.remove(0); }
        let pat = crate::script::compile_complex_value(cf, &p, 0)?;
        let repl = crate::script::compile_complex_value(cf, &r, 0)?;
        (CookieRewritePattern::Domain(pat), repl)
    } else {
        let pat = crate::script::compile_complex_value(cf, pattern_src, 0)?;
        let repl = crate::script::compile_complex_value(cf, replacement_src, 0)?;
        (CookieRewritePattern::Path(pat), repl)
    };

    let entry = CookieRewrite { pattern, replacement };
    let mut c = cell.borrow_mut();
    if is_domain { c.cookie_domains.push(entry); }
    else { c.cookie_paths.push(entry); }
    Ok(())
}

fn cookie_rewrite_off() -> CookieRewrite {
    CookieRewrite {
        pattern: CookieRewritePattern::Domain(crate::script::ComplexValue::constant(b"")),
        replacement: crate::script::ComplexValue::constant(b""),
    }
}

/// Rewrite Set-Cookie headers on r.headers_out per proxy_cookie_domain /
/// proxy_cookie_path. Called after the upstream header pass, before
/// send_header. Returns Ok(()) on success or NGX_ERROR on complex-value
/// evaluation failure (which we translate to 502 upstream).
pub fn rewrite_set_cookies(r: &R) {
    let plcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let plcf = plcf.borrow();
    let need_domain_or_path = !plcf.cookie_domains.is_empty() || !plcf.cookie_paths.is_empty();
    let need_flags = !plcf.cookie_flags.is_empty();
    drop(plcf);
    if !need_domain_or_path && !need_flags {
        return;
    }
    if need_flags {
        apply_cookie_flags(r);
    }
    if !need_domain_or_path {
        return;
    }
    let plcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let plcf = plcf.borrow();

    let mut ho = r.headers_out.borrow_mut();
    for h in ho.headers.iter() {
        if !h.lowcase_key.eq_ignore_ascii_case(b"set-cookie") { continue; }
        if h.hash.get() == 0 { continue; }
        let mut current = h.value.borrow().clone();
        let attrs = parse_cookie(&current);
        if attrs.is_empty() { continue; }

        let mut changed = false;
        // Skip attrs[0]: it's the "name=value" pair, not an attribute.
        // Build new value from attrs.
        let mut new_attrs: Vec<(Vec<u8>, Option<Vec<u8>>)> = attrs.clone();
        for i in 1..new_attrs.len() {
            let (ref k, ref v_opt) = new_attrs[i].clone();
            let v = match v_opt { Some(x) => x.clone(), None => continue };
            let k_lc = k.to_ascii_lowercase();
            let rewrites = if k_lc == b"domain" { &plcf.cookie_domains }
                           else if k_lc == b"path" { &plcf.cookie_paths }
                           else { continue };
            if let Some(new_v) = try_rewrite(r, &v, rewrites) {
                if new_v != v {
                    new_attrs[i].1 = Some(new_v);
                    changed = true;
                }
            }
        }
        if changed {
            let mut out = Vec::new();
            for (i, (k, v)) in new_attrs.iter().enumerate() {
                if i > 0 { out.extend_from_slice(b"; "); }
                out.extend_from_slice(k);
                if let Some(val) = v {
                    out.push(b'=');
                    out.extend_from_slice(val);
                }
            }
            current = out;
            *h.value.borrow_mut() = current;
        }
    }
    let _ = ho;
}

fn try_rewrite(r: &R, value: &[u8], rewrites: &[CookieRewrite]) -> Option<Vec<u8>> {
    for pr in rewrites.iter() {
        match &pr.pattern {
            CookieRewritePattern::Domain(pat) => {
                let pattern = crate::script::complex_value(r, pat).ok()?;
                let mut v = value;
                let mut lead_dot = false;
                if !v.is_empty() && v[0] == b'.' { v = &v[1..]; lead_dot = true; }
                if pattern.len() == v.len() && pattern.eq_ignore_ascii_case(v) {
                    let repl = crate::script::complex_value(r, &pr.replacement).ok()?;
                    let mut out = Vec::new();
                    if lead_dot { out.push(b'.'); }
                    out.extend_from_slice(&repl);
                    return Some(out);
                }
            }
            CookieRewritePattern::Path(pat) => {
                let pattern = crate::script::complex_value(r, pat).ok()?;
                if pattern.len() <= value.len() && value[..pattern.len()] == pattern[..] {
                    let repl = crate::script::complex_value(r, &pr.replacement).ok()?;
                    let mut out = Vec::with_capacity(value.len() - pattern.len() + repl.len());
                    out.extend_from_slice(&repl);
                    out.extend_from_slice(&value[pattern.len()..]);
                    return Some(out);
                }
            }
            CookieRewritePattern::Regex(re) => {
                // C uses ngx_http_regex_exec which returns capture info
                // for later interpolation. Our Regex.replace supports
                // $1..$9 in the replacement literal but we only have the
                // ComplexValue's raw string form.
                let re_body = &pr.replacement.value;
                if let Some(new_val) = re.replace(value, re_body) {
                    return Some(new_val);
                }
            }
        }
    }
    None
}

fn parse_cookie(value: &[u8]) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut attrs = Vec::new();
    let mut start = 0;
    while start <= value.len() {
        // Find next ';' or end
        let last = value[start..].iter().position(|&b| b == b';')
            .map(|p| start + p)
            .unwrap_or(value.len());
        let mut s = start;
        while s < last && value[s] == b' ' { s += 1; }
        // Find '=' in [s..last)
        let eq = value[s..last].iter().position(|&b| b == b'=');
        let (name, val) = match eq {
            Some(pos) => {
                let name_end = s + pos;
                let mut n_end = name_end;
                while n_end > s && value[n_end - 1] == b' ' { n_end -= 1; }
                let mut v_start = name_end + 1;
                while v_start < last && value[v_start] == b' ' { v_start += 1; }
                let mut v_end = last;
                while v_end > v_start && value[v_end - 1] == b' ' { v_end -= 1; }
                (value[s..n_end].to_vec(), Some(value[v_start..v_end].to_vec()))
            }
            None => {
                let mut n_end = last;
                while n_end > s && value[n_end - 1] == b' ' { n_end -= 1; }
                (value[s..n_end].to_vec(), None)
            }
        };
        attrs.push((name, val));
        if last == value.len() { break; }
        start = last + 1;
    }
    attrs
}

/// Parse an `addr` or `addr:port` string into a SocketAddr.
/// Handles `[::1]:8080` IPv6 form via std parser fallbacks.
fn parse_bind_addr(s: &str) -> Option<std::net::SocketAddr> {
    if s.is_empty() { return None; }
    // If already host:port form, try direct parse.
    if let Ok(a) = s.parse::<std::net::SocketAddr>() {
        return Some(a);
    }
    // Otherwise assume it's an IP with implicit port 0.
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Some(std::net::SocketAddr::new(ip, 0));
    }
    None
}

/// Connect to `addr`, optionally binding the local endpoint to `bind` first.
/// `bind` with port 0 lets the kernel pick the source port; a nonzero port
/// (from `proxy_bind 127.0.0.1:$remote_port` style) will be used verbatim,
/// with SO_REUSEADDR to allow rebinding TIME_WAIT sockets.
/// How connecting to the upstream failed (ngx_http_upstream_next).
pub(crate) enum ConnectError {
    /// NGX_HTTP_UPSTREAM_FT_ERROR: 502, unless another upstream is tried.
    Error,
    /// NGX_HTTP_UPSTREAM_FT_TIMEOUT: 504, unless another upstream is tried.
    Timeout,
    /// The TLS connection could not be set up: 500.
    Internal,
}


/// ngx_http_upstream_process_non_buffered_request with the proxy's input
/// filters (ngx_http_proxy_input_filter_init, the non-buffered copy and
/// chunked filters): the body is passed to the client, flushed, as it is
/// read from the upstream. Returns the request's rc and whether the
/// connection may be kept alive (u->keepalive).
async fn send_non_buffered(
    r: &R,
    upstream: &mut UpstreamSock,
    initial: &[u8],
    status: i64,
    content_length: Option<usize>,
    chunked: bool,
    connection_close: bool,
) -> (i64, bool) {
    use ngx_core::buf::{Buf, Chain};

    // non-buffered responses are not rate limited
    r.limit_rate.set(0);
    r.limit_rate_set.set(true);

    // ngx_http_proxy_input_filter_init: u->length
    let mut length: i64 = if status == 204 || status == 304 {
        0
    } else if chunked {
        1
    } else if content_length == Some(0) {
        0
    } else {
        content_length.map_or(-1, |l| l as i64)
    };

    let mut keepalive = length == 0 && !connection_close;

    let mut chunked_state = crate::parse::ChunkedState::default();

    let read_timeout = {
        let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
        let t = lcf.borrow().read_timeout.get_or(60000);
        t
    };

    let mut data: Vec<u8> = initial.to_vec();
    let mut eof = false;
    let mut buf = vec![0u8; 16384];

    loop {
        // u->input_filter
        let mut out: Vec<u8> = Vec::new();

        if !data.is_empty() {
            if length == 0 {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
            } else if chunked {
                // ngx_http_proxy_non_buffered_chunked_filter
                let mut pos = 0usize;

                loop {
                    let rc = crate::parse::parse_chunked(&mut chunked_state, &data, &mut pos, false);

                    if rc == NGX_OK {
                        // a chunk
                        let take = (chunked_state.size as usize).min(data.len() - pos);
                        out.extend_from_slice(&data[pos..pos + take]);
                        pos += take;
                        chunked_state.size -= take as i64;
                        continue;
                    }

                    if rc == NGX_DONE {
                        // a whole response has been parsed successfully
                        keepalive = !connection_close;
                        length = 0;

                        if pos < data.len() {
                            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_WARN, r.connection.log, None, "upstream sent data after final chunk");
                            keepalive = false;
                        }

                        break;
                    }

                    if rc == NGX_AGAIN {
                        break;
                    }

                    // invalid response
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid chunked response");

                    return (NGX_ERROR, false);
                }
            } else if length == -1 {
                out.extend_from_slice(&data);
            } else if data.len() as i64 > length {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
                out.extend_from_slice(&data[..length as usize]);
                length = 0;
                keepalive = false;
            } else {
                out.extend_from_slice(&data);
                length -= data.len() as i64;
                if length == 0 {
                    keepalive = !connection_close;
                }
            }

            data.clear();
        }

        if !out.is_empty() {
            let mut b = Buf::from_vec(out);
            b.memory = true;
            b.flush = true;
            let mut chain = Chain::new();
            chain.push_back(b);

            if crate::core_rt::output_filter(r, chain).await == NGX_ERROR {
                return (NGX_ERROR, false);
            }
        } else if length != 0 && !eof {
            // ngx_http_send_special(r, NGX_HTTP_FLUSH)
            let mut b = Buf::special();
            b.flush = true;
            let mut chain = Chain::new();
            chain.push_back(b);
            let _ = crate::core_rt::output_filter(r, chain).await;
        }

        if length == 0 || (eof && length == -1) {
            // ngx_http_upstream_finalize_request(r, u, 0): the last buffer
            let mut b = Buf::special();
            b.last_buf = r.is_main();
            b.last_in_chain = true;
            let mut chain = Chain::new();
            chain.push_back(b);
            let rc = crate::core_rt::output_filter(r, chain).await;

            return (if rc == NGX_ERROR { NGX_ERROR } else { NGX_OK }, keepalive && rc != NGX_ERROR);
        }

        if eof {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection while reading upstream");

            return (NGX_ERROR, false);
        }

        let n = match tokio::time::timeout(std::time::Duration::from_millis(read_timeout), upstream.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => {
                return (NGX_ERROR, false);
            }
            Err(_) => {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out while reading upstream");
                return (NGX_ERROR, false);
            }
        };

        if n == 0 {
            eof = true;
            continue;
        }

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.bytes_received += n as i64;
            st.response_length += n as i64;
        }

        data.extend_from_slice(&buf[..n]);
    }
}

/// The end of a response header: the empty line after it, as
/// ngx_http_parse_header_line sees lines ending in LF or CRLF. Returns the
/// end of the last header line (before its line terminator) and the start
/// of the body.
fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while let Some(p) = buf[i..].iter().position(|&b| b == b'\n').map(|p| p + i) {
        let line_end = if p > 0 && buf[p - 1] == b'\r' { p - 1 } else { p };
        match buf.get(p + 1) {
            Some(b'\n') => return Some((line_end, p + 2)),
            Some(b'\r') if buf.get(p + 2) == Some(&b'\n') => return Some((line_end, p + 3)),
            _ => {}
        }
        i = p + 1;
    }
    None
}

/// u->headers_in: the header lines of an upstream response header block
/// (after the status line).
fn set_upstream_headers_in(r: &R, block: &[u8]) {
    let mut h = r.upstream_headers_in.borrow_mut();
    h.clear();
    for line in block.split(|&b| b == b'\n').skip(1) {
        let line = if line.last() == Some(&b'\r') { &line[..line.len() - 1] } else { line };
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let mut vstart = colon + 1;
            while vstart < line.len() && (line[vstart] == b' ' || line[vstart] == b'\t') {
                vstart += 1;
            }
            h.push(crate::request::TableElt::new(&line[..colon], &line[vstart..]));
        }
    }
}

/// Connect to the upstream within proxy_connect_timeout; for https (`ssl`,
/// with the request's upstream `u`) ngx_event_connect_peer and
/// ngx_http_upstream_ssl_init_connection (upstream_ssl::connect).
pub(crate) async fn connect_upstream(
    r: &R,
    sockaddr: &ngx_core::inet::SockAddr,
    bind: Option<std::net::SocketAddr>,
    ssl: Option<&crate::upstream_ssl::SslSetup>,
    u: Option<&mut crate::upstream::UpstreamPeer>,
    timeout: u64,
) -> Result<UpstreamSock, ConnectError> {
    let log = r.connection.log.clone();
    let action = log.action();

    if let (Some(ssl), Some(u)) = (ssl, u) {
        // proxy_bind
        let local = bind.map(|a| ngx_core::event_connect::LocalAddr {
            sockaddr: match a {
                std::net::SocketAddr::V4(a) => ngx_core::inet::SockAddr::V4(a),
                std::net::SocketAddr::V6(a) => ngx_core::inet::SockAddr::V6(a),
            },
            name: a.to_string().into_bytes(),
        });

        return crate::upstream_ssl::connect(r, u, sockaddr, local.as_ref(), ssl, timeout).await.map(UpstreamSock::Conn);
    }

    let connect = async {
        connect_with_optional_bind(sockaddr, bind).await.map_err(|e| {
            let action = log.action();
            log.set_action(Some("connecting to upstream"));
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, log, e.raw_os_error(), "connect() failed");
            log.set_action(action);
            ConnectError::Error
        })
    };

    match tokio::time::timeout(std::time::Duration::from_millis(timeout), connect).await {
        Ok(rc) => rc,
        Err(_) => {
            log.set_action(Some("connecting to upstream"));
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, log, Some(libc::ETIMEDOUT), "upstream timed out");
            log.set_action(action);
            Err(ConnectError::Timeout)
        }
    }
}

async fn connect_with_optional_bind(
    sockaddr: &ngx_core::inet::SockAddr,
    bind: Option<std::net::SocketAddr>,
) -> std::io::Result<UpstreamSock> {
    let remote = match sockaddr {
        ngx_core::inet::SockAddr::Unix(path) => {
            let path = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(path);
            return tokio::net::UnixStream::connect(path).await.map(UpstreamSock::Unix);
        }
        ngx_core::inet::SockAddr::V4(a) => std::net::SocketAddr::V4(*a),
        ngx_core::inet::SockAddr::V6(a) => std::net::SocketAddr::V6(*a),
    };
    match bind {
        None => TcpStream::connect(remote).await.map(UpstreamSock::Tcp),
        Some(local) => {
            let sock = match local {
                std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
            };
            let _ = sock.set_reuseaddr(true);
            sock.bind(local)?;
            sock.connect(remote).await.map(UpstreamSock::Tcp)
        }
    }
}

fn proxy_store_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    if args.len() != 2 {
        return Err(msg("invalid number of arguments"));
    }
    let store = if args[1] == b"on" {
        ProxyStore::On
    } else if args[1] == b"off" {
        ProxyStore::Off
    } else {
        let cv = crate::script::compile_complex_value(cf, &args[1], 0)?;
        ProxyStore::Path(cv)
    };
    cell.borrow_mut().store = Some(store);
    Ok(())
}

/// Write the just-received upstream body to disk as configured by proxy_store.
/// Called after we've fully consumed the upstream (status is finalized and
/// body bytes are known). Skips non-2xx responses to match C behavior.
fn maybe_store_body(r: &R, body: &[u8]) {
    let plcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let plcf = plcf.borrow();
    let mode = match &plcf.store {
        Some(ProxyStore::Off) | None => return,
        Some(m) => m.clone(),
    };
    let status = r.headers_out.borrow().status;
    if !(200..300).contains(&status) {
        return;
    }
    let path: Vec<u8> = match mode {
        ProxyStore::Off => return,
        ProxyStore::On => {
            match crate::core_rt::map_uri_to_path(r, 0) {
                Some((p, _)) => p,
                None => return,
            }
        }
        ProxyStore::Path(cv) => match crate::script::complex_value(r, &cv) {
            Ok(v) => v,
            Err(_) => return,
        },
    };
    if path.is_empty() { return; }
    use std::os::unix::ffi::OsStrExt;
    let os = std::ffi::OsStr::from_bytes(&path);
    // Write to a temporary sibling then rename atomically. C uses
    // proxy_temp_path; we settle for `<target>.tmp` for now — it's on the
    // same filesystem so rename is atomic.
    let mut tmp = path.clone();
    tmp.extend_from_slice(b".tmp");
    let tmp_os = std::ffi::OsStr::from_bytes(&tmp);
    // Ensure parent exists.
    if let Some(parent) = std::path::Path::new(os).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::write(tmp_os, body).is_err() {
        return;
    }
    let _ = std::fs::rename(tmp_os, os);
}


fn proxy_next_upstream_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut mask = 0u32;
    for arg in cf.args.iter().skip(1) {
        let v = arg.as_slice();
        let bit = match v {
            b"off"            => { mask = FT_OFF; break; }
            b"error"          => FT_ERROR,
            b"timeout"        => FT_TIMEOUT,
            b"invalid_header" => FT_INVALID_HEADER,
            b"http_500"       => FT_HTTP_500,
            b"http_502"       => FT_HTTP_502,
            b"http_503"       => FT_HTTP_503,
            b"http_504"       => FT_HTTP_504,
            b"http_403"       => FT_HTTP_403,
            b"http_404"       => FT_HTTP_404,
            b"http_429"       => FT_HTTP_429,
            b"updating"       => FT_UPDATING,
            b"non_idempotent" => FT_NON_IDEMPOTENT,
            _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", ngx_core::string::B(v)))),
        };
        mask |= bit;
    }
    cell.borrow_mut().next_upstream_mask = Val::set(mask);
    Ok(())
}

fn proxy_next_upstream_tries_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let n = std::str::from_utf8(&cf.args[1]).ok()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| msg("invalid number"))?;
    cell.borrow_mut().next_upstream_tries = Val::set(n);
    Ok(())
}

/// proxy_redirect: rewrite ho.location and any Refresh header per configured
/// rules. Called after upstream headers have been parsed into ho.
///
/// `upstream_uri` is the raw proxy_pass URL (for `proxy_redirect default`).
pub fn rewrite_redirect_headers(r: &R, upstream_uri: &[u8]) {
    let plcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let plcf_ref = plcf.borrow();
    if plcf_ref.redirect_off {
        return;
    }
    let mut effective: Vec<CookieRewrite> = plcf_ref.redirects.clone();
    if plcf_ref.redirect_default {
        // `default`: pattern = proxy_pass URL, replacement = location name.
        let clcf = r.clcf();
        let loc_name = clcf.borrow().name.clone();
        effective.insert(0, CookieRewrite {
            pattern: CookieRewritePattern::Path(crate::script::ComplexValue::constant(upstream_uri)),
            replacement: crate::script::ComplexValue::constant(&loc_name),
        });
    }
    if effective.is_empty() {
        return;
    }
    drop(plcf_ref);

    // Location: rewrite via header value.
    {
        let ho = r.headers_out.borrow();
        if let Some(loc) = ho.location.clone() {
            let orig = loc.value.borrow().clone();
            drop(ho);
            if let Some(new_val) = try_redirect_rewrite(r, &orig, 0, &effective) {
                let ho = r.headers_out.borrow();
                *ho.location.as_ref().unwrap().value.borrow_mut() = new_val;
                drop(ho);
                let _ = loc; // keep clippy quiet
            }
        }
    }

    // Refresh: value is like "7; url=<url>"; find "url=" and rewrite what's after.
    {
        let ho = r.headers_out.borrow();
        let mut refresh_hdrs: Vec<crate::request::Header> = Vec::new();
        for h in ho.headers.iter() {
            if h.hash.get() == 0 { continue; }
            if h.lowcase_key.eq_ignore_ascii_case(b"refresh") {
                refresh_hdrs.push(h.clone());
            }
        }
        drop(ho);
        for h in refresh_hdrs {
            let v = h.value.borrow().clone();
            // Find "url=" case-insensitively.
            let mut idx = None;
            for i in 0..v.len().saturating_sub(3) {
                if v[i..i+4].eq_ignore_ascii_case(b"url=") {
                    idx = Some(i + 4);
                    break;
                }
            }
            let prefix = match idx { Some(i) => i, None => continue };
            if let Some(new_val) = try_redirect_rewrite(r, &v, prefix, &effective) {
                *h.value.borrow_mut() = new_val;
            }
        }
    }
}

fn try_redirect_rewrite(r: &R, value: &[u8], prefix: usize, rewrites: &[CookieRewrite]) -> Option<Vec<u8>> {
    if prefix > value.len() { return None; }
    let target = &value[prefix..];
    for pr in rewrites.iter() {
        match &pr.pattern {
            CookieRewritePattern::Path(pat) => {
                // Prefix match (matches ngx_http_proxy_rewrite_complex_handler).
                let pattern = crate::script::complex_value(r, pat).ok()?;
                if pattern.is_empty() || target.len() < pattern.len() { continue; }
                if target[..pattern.len()] != pattern[..] { continue; }
                let repl = crate::script::complex_value(r, &pr.replacement).ok()?;
                let mut out = Vec::with_capacity(prefix + repl.len() + target.len() - pattern.len());
                out.extend_from_slice(&value[..prefix]);
                out.extend_from_slice(&repl);
                out.extend_from_slice(&target[pattern.len()..]);
                return Some(out);
            }
            CookieRewritePattern::Domain(_) => continue, // not used for redirect
            CookieRewritePattern::Regex(re) => {
                // Regex-based: match against post-prefix portion; regex handler
                // returns replacement with $N captures interpolated.
                let re_body = &pr.replacement.value;
                if let Some(new_tail) = re.replace(target, re_body) {
                    let mut out = Vec::with_capacity(prefix + new_tail.len());
                    out.extend_from_slice(&value[..prefix]);
                    out.extend_from_slice(&new_tail);
                    return Some(out);
                }
            }
        }
    }
    None
}

fn proxy_cookie_flags_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    // `proxy_cookie_flags off;` (2 args, no cookie name)
    if args.len() == 2 && args[1] == b"off" {
        let mut c = cell.borrow_mut();
        c.cookie_flags.clear();
        c.cookie_flags.push(CookieFlagsRule { matcher: CookieMatcher::Off, flags: 0, complex_flags: Vec::new() });
        return Ok(());
    }
    if args.len() < 3 {
        return Err(msg("invalid number of arguments"));
    }
    let cookie_arg = &args[1];
    // Parse flag tokens. Literal tokens set a bit immediately; tokens that
    // contain a `$` are stored as complex values and re-parsed per request.
    let mut flags: u32 = 0;
    let mut complex_flags: Vec<crate::script::ComplexValue> = Vec::new();
    for tok in args.iter().skip(2) {
        if tok.iter().any(|&b| b == b'$') {
            let cv = crate::script::compile_complex_value(cf, tok, 0)?;
            complex_flags.push(cv);
            continue;
        }
        let bit = flag_bit_for(tok.as_slice())
            .ok_or_else(|| cf.emerg(format_args!("invalid parameter \"{}\"",
                ngx_core::string::B(tok))))?;
        flags |= bit;
    }
    let matcher = if !cookie_arg.is_empty() && cookie_arg[0] == b'~' {
        // ngx_http_proxy_cookie_flags compiles the ~pattern with
        // NGX_REGEX_CASELESS unconditionally (there's no ~* variant here).
        let body = &cookie_arg[1..];
        let re = ngx_core::regex::Regex::compile(body, ngx_core::regex::NGX_REGEX_CASELESS)
            .map_err(|e| cf.emerg(format_args!("regex error: {}", e)))?;
        CookieMatcher::Regex(re)
    } else {
        let cv = crate::script::compile_complex_value(cf, cookie_arg, 0)?;
        CookieMatcher::Name(cv)
    };
    cell.borrow_mut().cookie_flags.push(CookieFlagsRule { matcher, flags, complex_flags });
    Ok(())
}

fn flag_bit_for(tok: &[u8]) -> Option<u32> {
    let lower = tok.to_ascii_lowercase();
    Some(match lower.as_slice() {
        b"secure"          => CF_SECURE_ON,
        b"nosecure"        => CF_SECURE_OFF,
        b"httponly"        => CF_HTTPONLY_ON,
        b"nohttponly"      => CF_HTTPONLY_OFF,
        b"samesite=strict" => CF_SAMESITE_STRICT,
        b"samesite=lax"    => CF_SAMESITE_LAX,
        b"samesite=none"   => CF_SAMESITE_NONE,
        b"nosamesite"      => CF_SAMESITE_OFF,
        _ => return None,
    })
}

/// Apply proxy_cookie_flags to Set-Cookie headers. Called from rewrite_set_cookies
/// after Domain/Path substitution so both effects compose.
fn apply_cookie_flags(r: &R) {
    let plcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let plcf = plcf.borrow();
    let rules: Vec<CookieFlagsRule> = plcf.cookie_flags.iter()
        .filter(|r| !matches!(r.matcher, CookieMatcher::Off))
        .cloned()
        .collect();
    if rules.is_empty() { return; }
    drop(plcf);

    let ho = r.headers_out.borrow();
    let mut cookies: Vec<crate::request::Header> = Vec::new();
    for h in ho.headers.iter() {
        if h.hash.get() == 0 { continue; }
        if h.lowcase_key.eq_ignore_ascii_case(b"set-cookie") {
            cookies.push(h.clone());
        }
    }
    drop(ho);

    for h in cookies {
        let value = h.value.borrow().clone();
        let attrs = parse_cookie(&value);
        if attrs.is_empty() { continue; }
        // attrs[0].0 is the cookie name (part before '=' of the name=value pair).
        let cookie_name = attrs[0].0.clone();
        // Compute effective flag mask for this cookie by ORing all matching rules.
        let mut mask: u32 = 0;
        for rule in rules.iter() {
            let matched = match &rule.matcher {
                CookieMatcher::Off => false,
                CookieMatcher::Name(cv) => {
                    let pattern = match crate::script::complex_value(r, cv) { Ok(v) => v, Err(_) => continue };
                    pattern.eq_ignore_ascii_case(&cookie_name)
                }
                CookieMatcher::Regex(re) => re.is_match(&cookie_name),
            };
            if !matched { continue; }
            mask |= rule.flags;
            // Evaluate complex-value flag tokens now.
            for cv in &rule.complex_flags {
                let v = match crate::script::complex_value(r, cv) { Ok(v) => v, Err(_) => continue };
                if v.is_empty() { continue; }
                if let Some(bit) = flag_bit_for(&v) { mask |= bit; }
            }
        }
        if mask == 0 { continue; }

        // Edit existing attrs; drop those key.data==NULL analogues (we use retain).
        let mut new_attrs: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(attrs.len() + 3);
        let mut remaining = mask;
        let mut have_secure = false;
        let mut have_httponly = false;
        let mut have_samesite = false;
        for (i, (k, v)) in attrs.iter().enumerate() {
            if i == 0 { new_attrs.push((k.clone(), v.clone())); continue; }
            let kl = k.to_ascii_lowercase();
            if kl == b"secure" {
                have_secure = true;
                if remaining & CF_SECURE_ON != 0 { remaining &= !CF_SECURE_ON; new_attrs.push((k.clone(), v.clone())); continue; }
                if remaining & CF_SECURE_OFF != 0 { continue; } // drop
                new_attrs.push((k.clone(), v.clone()));
                continue;
            }
            if kl == b"httponly" {
                have_httponly = true;
                if remaining & CF_HTTPONLY_ON != 0 { remaining &= !CF_HTTPONLY_ON; new_attrs.push((k.clone(), v.clone())); continue; }
                if remaining & CF_HTTPONLY_OFF != 0 { continue; }
                new_attrs.push((k.clone(), v.clone()));
                continue;
            }
            if kl == b"samesite" {
                have_samesite = true;
                if remaining & CF_SAMESITE_STRICT != 0 {
                    remaining &= !CF_SAMESITE_STRICT;
                    new_attrs.push((b"SameSite".to_vec(), Some(b"Strict".to_vec()))); continue;
                }
                if remaining & CF_SAMESITE_LAX != 0 {
                    remaining &= !CF_SAMESITE_LAX;
                    new_attrs.push((b"SameSite".to_vec(), Some(b"Lax".to_vec()))); continue;
                }
                if remaining & CF_SAMESITE_NONE != 0 {
                    remaining &= !CF_SAMESITE_NONE;
                    new_attrs.push((b"SameSite".to_vec(), Some(b"None".to_vec()))); continue;
                }
                if remaining & CF_SAMESITE_OFF != 0 { continue; }
                new_attrs.push((k.clone(), v.clone()));
                continue;
            }
            new_attrs.push((k.clone(), v.clone()));
        }
        // Append any *_ON flags still not consumed.
        if remaining & CF_SECURE_ON != 0 && !have_secure {
            new_attrs.push((b"Secure".to_vec(), None));
        }
        if remaining & CF_HTTPONLY_ON != 0 && !have_httponly {
            new_attrs.push((b"HttpOnly".to_vec(), None));
        }
        if !have_samesite {
            if remaining & CF_SAMESITE_STRICT != 0 {
                new_attrs.push((b"SameSite".to_vec(), Some(b"Strict".to_vec())));
            } else if remaining & CF_SAMESITE_LAX != 0 {
                new_attrs.push((b"SameSite".to_vec(), Some(b"Lax".to_vec())));
            } else if remaining & CF_SAMESITE_NONE != 0 {
                new_attrs.push((b"SameSite".to_vec(), Some(b"None".to_vec())));
            }
        }
        let mut out = Vec::new();
        for (i, (k, v)) in new_attrs.iter().enumerate() {
            if i > 0 { out.extend_from_slice(b"; "); }
            out.extend_from_slice(k);
            if let Some(val) = v { out.push(b'='); out.extend_from_slice(val); }
        }
        *h.value.borrow_mut() = out;
    }
}
