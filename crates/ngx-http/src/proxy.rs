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

/// ngx_http_proxy_vars_t
#[derive(Clone, Default, Debug)]
pub struct ProxyVars {
    pub key_start: Vec<u8>,
    pub schema: Vec<u8>,
    pub host_header: Vec<u8>,
    pub port: Vec<u8>,
    pub uri: Vec<u8>,
}

/// ngx_http_proxy_headers_t: the request headers of proxy_set_header and
/// the defaults, as ngx_http_proxy_init_headers() compiles them.
pub struct ProxyHeaders {
    /// headers->flushes: the variables of the values
    pub flushes: Vec<usize>,
    /// headers->lengths and headers->values: the name and the value codes
    /// of each header with a value that is not empty in the configuration
    pub lines: Vec<(Vec<u8>, Vec<crate::script::Part>)>,
    /// headers->hash: the names of all of them (the client's headers of
    /// these names are not passed)
    pub hash: ngx_core::hash::Hash<()>,
}

/// ngx_http_proxy_ctx_t
#[derive(Default)]
pub struct ProxyCtx {
    pub vars: ProxyVars,
    pub internal_body_length: i64,
    /// the request sent is a HEAD one
    pub head: bool,
    pub internal_chunked: bool,
    /// ngx_http_proxy_body_output_filter: the header was sent
    pub header_sent: bool,
}

/// Proxy location configuration
pub struct NgxHttpProxyLocConf {
    /// plcf->url: the URL of proxy_pass without variables
    pub url: Vec<u8>,
    /// plcf->location
    pub location: Vec<u8>,
    /// plcf->vars
    pub vars: ProxyVars,
    /// plcf->proxy_lengths / proxy_values: the codes of a proxy_pass URL
    /// with variables (ngx_http_proxy_eval)
    pub proxy_values: Option<Rc<Vec<crate::script::Part>>>,
    /// proxy_method (ngx_http_set_complex_value_slot)
    pub method: Val<Option<Rc<crate::script::ComplexValue>>>,
    /// proxy_set_body (ngx_conf_set_str_slot)
    pub body_source: Option<Vec<u8>>,
    /// plcf->body_lengths / body_values, and body_flushes
    pub body_values: Option<Rc<Vec<crate::script::Part>>>,
    pub body_flushes: Rc<Vec<usize>>,
    /// proxy_set_header (ngx_conf_set_keyval_slot): unset, NULL or the list
    pub headers_source: Val<Option<Rc<Vec<(Vec<u8>, Vec<u8>)>>>>,
    /// plcf->headers and plcf->headers_cache, once built (hash.buckets)
    pub headers: Option<Rc<ProxyHeaders>>,
    pub headers_cache: Option<Rc<ProxyHeaders>>,
    /// plcf->host_value: the value of "proxy_set_header Host"
    pub host_value: Option<Rc<crate::script::ComplexValue>>,
    /// proxy_headers_hash_max_size, proxy_headers_hash_bucket_size
    pub headers_hash_max_size: Val<i64>,
    pub headers_hash_bucket_size: Val<i64>,
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
    /// plcf->redirects: the proxy_redirect entries (NULL when None). Reuses
    /// CookieRewrite because the substitution machinery is the same
    /// (literal, complex or regex pattern → replacement).
    pub redirects: Option<Vec<CookieRewrite>>,
    /// plcf->redirect: "proxy_redirect off" sets it to 0
    pub redirect: Val<bool>,
    /// proxy_cookie_flags entries.
    pub cookie_flags: Vec<CookieFlagsRule>,
    /// proxy_http_version: NGX_HTTP_VERSION_10 or NGX_HTTP_VERSION_11
    /// (the default).
    pub http_version: Val<u32>,
    /// proxy_pass_trailers (upstream.pass_trailers)
    pub pass_trailers: Val<bool>,
    /// proxy_buffer_size (upstream.buffer_size): the most of a response
    /// header, and of trailers
    pub buffer_size: Val<usize>,
    /// proxy_limit_rate (upstream.limit_rate): a complex value size
    pub limit_rate: Val<Option<Rc<crate::script::ComplexValue>>>,
    /// proxy_ignore_client_abort
    pub ignore_client_abort: Val<bool>,
    /// proxy_hide_header entries (lowercase). `None` = inherit from parent;
    /// `Some(list)` = explicit local list (still merged with defaults).
    pub hide_headers: Option<Vec<Vec<u8>>>,
    /// proxy_pass_header entries (lowercase). Same inheritance rule as
    /// hide_headers. Pass overrides any hide (default or explicit) for the
    /// named header.
    pub pass_headers: Option<Vec<Vec<u8>>>,
    /// The cache fields of plcf->upstream (proxy_cache, proxy_cache_*,
    /// proxy_no_cache, proxy_ignore_headers) and plcf->cache_key.
    pub cache: crate::upstream_cache::UpstreamCacheConf,
    /// proxy_temp_path (upstream.temp_path)
    pub temp_path: Val<Rc<PathConf>>,
}

impl crate::upstream_cache::UpstreamCacheLocConf for NgxHttpProxyLocConf {
    fn upstream_cache(&mut self) -> &mut crate::upstream_cache::UpstreamCacheConf {
        &mut self.cache
    }
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

/// ngx_http_proxy_next_upstream_masks
const PROXY_NEXT_UPSTREAM_MASKS: &[(&str, u32)] = &[
    ("error", FT_ERROR),
    ("timeout", FT_TIMEOUT),
    ("invalid_header", FT_INVALID_HEADER),
    ("non_idempotent", FT_NON_IDEMPOTENT),
    ("http_500", FT_HTTP_500),
    ("http_502", FT_HTTP_502),
    ("http_503", FT_HTTP_503),
    ("http_504", FT_HTTP_504),
    ("http_403", FT_HTTP_403),
    ("http_404", FT_HTTP_404),
    ("http_429", FT_HTTP_429),
    ("updating", FT_UPDATING),
    ("off", FT_OFF),
];


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
            url: Vec::new(),
            location: Vec::new(),
            vars: ProxyVars::default(),
            proxy_values: None,
            method: Val::unset(),
            body_source: None,
            body_values: None,
            body_flushes: Rc::new(Vec::new()),
            headers_source: Val::unset(),
            headers: None,
            headers_cache: None,
            host_value: None,
            headers_hash_max_size: Val::unset(),
            headers_hash_bucket_size: Val::unset(),
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
            redirects: None,
            redirect: Val::unset(),
            cookie_flags: Vec::new(),
            http_version: Val::unset(),
            pass_trailers: Val::unset(),
            buffer_size: Val::unset(),
            limit_rate: Val::unset(),
            ignore_client_abort: Val::unset(),
            hide_headers: None,
            pass_headers: None,
            cache: crate::upstream_cache::UpstreamCacheConf::default(),
            temp_path: Val::unset(),
        }
    }
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(NgxHttpProxyLocConf::default())
}

fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let mut p = conf_cell::<NgxHttpProxyLocConf>(prev).borrow_mut();
    let mut c = conf_cell::<NgxHttpProxyLocConf>(conf).borrow_mut();
    c.intercept_errors.merge(&p.intercept_errors, false);
    c.pass_request_headers.merge(&p.pass_request_headers, true);
    c.pass_request_body.merge(&p.pass_request_body, true);
    c.pass_trailers.merge(&p.pass_trailers, false);
    c.ignore_client_abort.merge(&p.ignore_client_abort, false);
    c.buffer_size.merge(&p.buffer_size, PROXY_BUFFER_SIZE);
    crate::upstream_ssl::merge_ptr(&mut c.limit_rate, &p.limit_rate);
    c.request_buffering.merge(&p.request_buffering, true);
    c.buffering.merge(&p.buffering, true);
    c.connect_timeout.merge(&p.connect_timeout, 60000);
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
    if matches!(c.store, Some(ProxyStore::On) | Some(ProxyStore::Path(_))) {
        c.cache.cache = Val::set(false);
    }
    if c.cache.cache.get_or(false) {
        c.store = Some(ProxyStore::Off);
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
    {
        let mut slot = std::mem::take(&mut c.temp_path);
        merge_path_value(cf, &mut slot, &p.temp_path, ngx_core::NGX_HTTP_PROXY_TEMP_PATH, [1, 2, 0])?;
        c.temp_path = slot;
    }

    c.cache.merge(cf, &p.cache, "proxy", true)?;

    merge_ssl(cf, &mut p, &mut c)?;

    crate::upstream_ssl::merge_ptr(&mut c.method, &p.method);

    c.redirect.merge(&p.redirect, true);

    if *c.redirect.get() {
        if c.redirects.is_none() {
            c.redirects = p.redirects.clone();
        }

        if c.redirects.is_none() && !c.url.is_empty() {
            let pr = default_redirect(&c);
            c.redirects = Some(vec![pr]);
        }
    }

    // Inherit cookie_flags unless this location listed its own.
    if c.cookie_flags.is_empty() {
        c.cookie_flags = p.cookie_flags.clone();
    }

    c.http_version.merge(&p.http_version, crate::NGX_HTTP_VERSION_11);

    c.headers_hash_max_size.merge(&p.headers_hash_max_size, 512);
    c.headers_hash_bucket_size.merge(&p.headers_hash_bucket_size, 64);

    // ngx_align(conf->headers_hash_bucket_size, ngx_cacheline_size)
    let bucket_size = *c.headers_hash_bucket_size.get();
    c.headers_hash_bucket_size = Val::set((bucket_size + 63) & !63);

    // Inherit hide/pass lists independently: if child didn't set its own,
    // inherit from parent. Matches ngx_http_upstream_hide_headers_hash
    // which pulls each list from prev when NGX_CONF_UNSET_PTR.
    if c.hide_headers.is_none() { c.hide_headers = p.hide_headers.clone(); }
    if c.pass_headers.is_none() { c.pass_headers = p.pass_headers.clone(); }

    let clcf = get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());

    let (noname, lmt_excpt, has_handler) = {
        let l = clcf.borrow();
        (l.noname, l.lmt_excpt, l.handler.is_some())
    };

    if noname && c.upstream.is_none() && c.proxy_values.is_none() {
        c.upstream = p.upstream.clone();
        c.location = p.location.clone();
        c.vars = p.vars.clone();

        c.proxy_values = p.proxy_values.clone();

        c.ssl = p.ssl;
    }

    if lmt_excpt && !has_handler && (c.upstream.is_some() || c.proxy_values.is_some()) {
        clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(proxy_handler(r))));
    }

    if c.body_source.is_none() {
        c.body_flushes = p.body_flushes.clone();
        c.body_source = p.body_source.clone();
        c.body_values = p.body_values.clone();
    }

    if c.body_values.is_none() {
        if let Some(source) = c.body_source.clone() {
            let codes = crate::script::script_compile(cf, &source)?;
            c.body_flushes = Rc::new(script_flushes(&codes));
            c.body_values = Some(Rc::new(codes));
        }
    }

    crate::upstream_ssl::merge_ptr(&mut c.headers_source, &p.headers_source);

    let same_source = same_headers_source(&c.headers_source, &p.headers_source);

    if same_source {
        c.headers = p.headers.clone();
        c.headers_cache = p.headers_cache.clone();
        c.host_value = p.host_value.clone();
    }

    init_headers(cf, &mut c, false, PROXY_HEADERS)?;

    if c.cache.enabled() {
        init_headers(cf, &mut c, true, PROXY_CACHE_HEADERS)?;
    }

    // special handling to preserve conf->headers in the "http" section
    // to inherit it to all servers

    if p.headers.is_none() && same_source {
        p.headers = c.headers.clone();
        p.headers_cache = c.headers_cache.clone();
        p.host_value = c.host_value.clone();
    }

    Ok(())
}

/// ngx_http_proxy_headers: the request headers set by default.
const PROXY_HEADERS: &[(&[u8], &[u8])] = &[
    (b"Host", b""),
    (b"Connection", b""),
    (b"Proxy-Connection", b""),
    (b"Content-Length", b"$proxy_internal_body_length"),
    (b"Transfer-Encoding", b"$proxy_internal_chunked"),
    (b"TE", b""),
    (b"Keep-Alive", b""),
    (b"Expect", b""),
    (b"Upgrade", b""),
];

/// ngx_http_proxy_cache_headers: the defaults of a cacheable request.
const PROXY_CACHE_HEADERS: &[(&[u8], &[u8])] = &[
    (b"Host", b""),
    (b"Connection", b""),
    (b"Proxy-Connection", b""),
    (b"Content-Length", b"$proxy_internal_body_length"),
    (b"Transfer-Encoding", b"$proxy_internal_chunked"),
    (b"TE", b""),
    (b"Keep-Alive", b""),
    (b"Expect", b""),
    (b"Upgrade", b""),
    (b"If-Modified-Since", b"$upstream_cache_last_modified"),
    (b"If-Unmodified-Since", b""),
    (b"If-None-Match", b"$upstream_cache_etag"),
    (b"If-Match", b""),
    (b"Range", b""),
    (b"If-Range", b""),
];

/// sc->flushes of ngx_http_script_compile(): the variables of the codes.
fn script_flushes(codes: &[crate::script::Part]) -> Vec<usize> {
    codes
        .iter()
        .filter_map(|c| match c {
            crate::script::Part::Var(index) => Some(*index),
            _ => None,
        })
        .collect()
}

/// conf->headers_source == prev->headers_source after
/// ngx_conf_merge_ptr_value(): both NULL (or unset), or the same list.
fn same_headers_source(a: &Val<Option<Rc<Vec<(Vec<u8>, Vec<u8>)>>>>, b: &Val<Option<Rc<Vec<(Vec<u8>, Vec<u8>)>>>>) -> bool {
    match (&a.0, &b.0) {
        (None, None) => true,
        (Some(None), Some(None)) => true,
        (Some(Some(x)), Some(Some(y))) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

/// ngx_http_proxy_init_headers: the headers of proxy_set_header (all but
/// Host, whose value becomes conf->host_value), then the defaults the
/// configuration does not set; the names go to the hash, the headers with
/// a value are compiled.
fn init_headers(cf: &mut Conf, conf: &mut NgxHttpProxyLocConf, cache: bool, default_headers: &[(&[u8], &[u8])]) -> ConfResult {
    let built = if cache { conf.headers_cache.is_some() } else { conf.headers.is_some() };

    if built {
        return Ok(());
    }

    let mut headers_merged: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    if let Some(src) = conf.headers_source.as_option().cloned().flatten() {
        for (key, value) in src.iter() {
            if key.len() == 4 && key.eq_ignore_ascii_case(b"Host") {
                let cv = crate::script::compile_complex_value(cf, value, 0)?;
                conf.host_value = Some(Rc::new(cv));
                continue;
            }

            headers_merged.push((key.clone(), value.clone()));
        }
    }

    for (key, value) in default_headers {
        if headers_merged.iter().any(|(k, _)| k.eq_ignore_ascii_case(key)) {
            continue;
        }

        headers_merged.push((key.to_vec(), value.to_vec()));
    }

    let mut headers_names = Vec::with_capacity(headers_merged.len());
    let mut flushes = Vec::new();
    let mut lines = Vec::new();

    for (key, value) in headers_merged {
        // the hash keys are lowercased by ngx_hash_init()
        headers_names.push(ngx_core::hash::HashKey { key: key.to_ascii_lowercase(), key_hash: ngx_core::hash::hash_key_lc(&key), value: () });

        if value.is_empty() {
            continue;
        }

        let codes = crate::script::script_compile(cf, &value)?;

        flushes.extend(script_flushes(&codes));

        lines.push((key, codes));
    }

    let hinit = ngx_core::hash::HashInit {
        name: "proxy_headers_hash",
        max_size: *conf.headers_hash_max_size.get() as usize,
        bucket_size: *conf.headers_hash_bucket_size.get() as usize,
        log: &cf.log,
    };

    let hash = match ngx_core::hash::Hash::init(&hinit, headers_names) {
        Ok(h) => h,
        Err(e) => {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_EMERG, cf.log, None, "{}", e);
            return Err(ConfError::Logged);
        }
    };

    let headers = Some(Rc::new(ProxyHeaders { flushes, lines, hash }));

    if cache {
        conf.headers_cache = headers;
    } else {
        conf.headers = headers;
    }

    Ok(())
}

/// The redirect of "proxy_redirect default", and of no proxy_redirect
/// (ngx_http_proxy_redirect, ngx_http_proxy_merge_loc_conf): the URL of
/// proxy_pass to the location, or the URL with "/" to "/" when the URL has
/// no URI part.
fn default_redirect(plcf: &NgxHttpProxyLocConf) -> CookieRewrite {
    if !plcf.vars.uri.is_empty() {
        CookieRewrite {
            pattern: CookieRewritePattern::Path(crate::script::ComplexValue::constant(&plcf.url)),
            replacement: crate::script::ComplexValue::constant(&plcf.location),
        }
    } else {
        let mut pattern = plcf.url.clone();
        pattern.push(b'/');

        CookieRewrite {
            pattern: CookieRewritePattern::Path(crate::script::ComplexValue::constant(&pattern)),
            replacement: crate::script::ComplexValue::constant(b"/"),
        }
    }
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

/// proxy_set_body: ngx_conf_set_str_slot
fn proxy_set_body_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    if c.body_source.is_some() {
        return Err(msg("is duplicate"));
    }

    c.body_source = Some(cf.args[1].clone());

    Ok(())
}

/// proxy_method: ngx_http_set_complex_value_slot
fn proxy_method_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut slot = cell.borrow().method.clone();
    crate::script::set_complex_value_slot(cf, cmd, &mut slot)?;
    cell.borrow_mut().method = slot;
    Ok(())
}

/// proxy_limit_rate: ngx_http_set_complex_value_size_slot
fn proxy_limit_rate_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut slot = cell.borrow().limit_rate.clone();
    crate::script::set_complex_value_size_slot(cf, cmd, &mut slot)?;
    cell.borrow_mut().limit_rate = slot;
    Ok(())
}

/// ngx_http_proxy_pass
fn proxy_pass_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());

    {
        let plcf = cell.borrow();

        if plcf.upstream.is_some() || plcf.proxy_values.is_some() {
            return Err(msg("is duplicate"));
        }
    }

    let clcf = get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());

    {
        let mut lc = clcf.borrow_mut();

        lc.handler = Some(Rc::new(|r| Box::pin(proxy_handler(r))));

        if lc.name.last() == Some(&b'/') {
            lc.auto_redirect = true;
        }
    }

    let url = cf.args[1].clone();

    let n = crate::script::script_variables_count(&url);

    if n != 0 {
        let codes = crate::script::script_compile(cf, &url)?;

        let mut plcf = cell.borrow_mut();
        plcf.proxy_values = Some(Rc::new(codes));
        plcf.ssl = true;

        return Ok(());
    }

    let (add, port) = if url.len() >= 7 && url[..7].eq_ignore_ascii_case(b"http://") {
        (7, 80)
    } else if url.len() >= 8 && url[..8].eq_ignore_ascii_case(b"https://") {
        cell.borrow_mut().ssl = true;
        (8, 443)
    } else {
        return Err(cf.emerg(format_args!("invalid URL prefix")));
    };

    let mut u = ngx_core::inet::Url::new(&url[add..]);
    u.default_port = port;
    u.uri_part = true;
    u.no_resolve = true;

    let uscf = crate::upstream::upstream_add(cf, &mut u, 0)?;

    let mut plcf = cell.borrow_mut();

    plcf.upstream = Some(uscf);

    plcf.vars.schema = url[..add].to_vec();
    plcf.vars.key_start = plcf.vars.schema.clone();

    set_vars(&u, &mut plcf.vars, &url);

    let lc = clcf.borrow();

    plcf.location = lc.name.clone();

    if lc.named || lc.regex.is_some() || lc.predicate != 0 || lc.noname {
        if !plcf.vars.uri.is_empty() {
            return Err(cf.emerg(format_args!(
                "\"proxy_pass\" cannot have URI part in location given by regular expression, or inside predicate location, or inside named location, or inside \"if\" statement, or inside \"limit_except\" block"
            )));
        }

        plcf.location.clear();
    }

    plcf.url = url;

    Ok(())
}

/// ngx_http_proxy_set_vars: the Host header and $proxy_port of the parsed
/// URL `u` of `url`, the start of the cache key (v->key_start, the schema
/// on entry), and the URI part.
fn set_vars(u: &ngx_core::inet::Url, v: &mut ProxyVars, url: &[u8]) {
    let key_start_len;

    if u.family != libc::AF_UNIX {
        if u.no_port || u.port == u.default_port {
            v.host_header = u.host.clone();

            v.port = if u.default_port == 80 { b"80".to_vec() } else { b"443".to_vec() };
        } else {
            let mut h = u.host.clone();
            h.push(b':');
            h.extend_from_slice(&u.port_text);
            v.host_header = h;
            v.port = u.port_text.clone();
        }

        key_start_len = v.key_start.len() + v.host_header.len();
    } else {
        v.host_header = b"localhost".to_vec();
        v.port = Vec::new();
        key_start_len = v.key_start.len() + "unix:".len() + u.host.len() + 1;
    }

    // the key starts at the URL: the schema, then the host part
    v.key_start = url[..key_start_len.min(url.len())].to_vec();

    v.uri = u.uri.clone();
}

/// proxy_set_header: ngx_conf_set_keyval_slot
fn proxy_set_header_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    let mut list: Vec<(Vec<u8>, Vec<u8>)> = match c.headers_source.as_option() {
        Some(Some(a)) => a.as_ref().clone(),
        _ => Vec::new(),
    };

    list.push((cf.args[1].clone(), cf.args[2].clone()));

    c.headers_source = Val::set(Some(Rc::new(list)));

    Ok(())
}

/// ngx_http_proxy_redirect
fn proxy_redirect_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());

    if cell.borrow().redirect.as_option() == Some(&false) {
        return Ok(());
    }

    cell.borrow_mut().redirect = Val::set(true);

    let args = cf.args.clone();

    if args.len() == 2 {
        if args[1] == b"off" {
            let mut c = cell.borrow_mut();

            if c.redirects.is_some() {
                return Err(msg("is duplicate"));
            }

            c.redirect = Val::set(false);
            return Ok(());
        }

        if args[1] != b"default" {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", ngx_core::string::B(&args[1]))));
        }

        let mut c = cell.borrow_mut();

        if c.proxy_values.is_some() {
            return Err(cf.emerg(format_args!("\"proxy_redirect default\" cannot be used with \"proxy_pass\" directive with variables")));
        }

        if c.url.is_empty() {
            return Err(cf.emerg(format_args!("\"proxy_redirect default\" should be placed after the \"proxy_pass\" directive")));
        }

        let pr = default_redirect(&c);
        c.redirects.get_or_insert_with(Vec::new).push(pr);

        return Ok(());
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
    cell.borrow_mut().redirects.get_or_insert_with(Vec::new).push(CookieRewrite { pattern, replacement });
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

/// The request's ngx_http_proxy_ctx_t, if the proxy handles it.
fn proxy_ctx(r: &R) -> Option<Rc<RefCell<ProxyCtx>>> {
    r.get_ctx::<ProxyCtx>(ctx_index())
}

/// ngx_http_proxy_host_variable
fn proxy_host_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let ctx = match proxy_ctx(r) {
        Some(c) => c,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    v.data = ctx.borrow().vars.host_header.clone();
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    NGX_OK
}

/// ngx_http_proxy_port_variable
fn proxy_port_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let ctx = match proxy_ctx(r) {
        Some(c) => c,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    v.data = ctx.borrow().vars.port.clone();
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    NGX_OK
}

/// ngx_http_proxy_add_x_forwarded_for_variable
fn proxy_add_x_forwarded_for_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    let hin = r.headers_in.borrow();
    let addr_text = r.connection.addr_text.borrow();

    let mut len = 0;

    for h in hin.x_forwarded_for.iter() {
        len += h.value.borrow().len() + ", ".len();
    }

    if len == 0 {
        v.data = addr_text.clone();
        return NGX_OK;
    }

    let mut p = Vec::with_capacity(len + addr_text.len());

    for h in hin.x_forwarded_for.iter() {
        p.extend_from_slice(&h.value.borrow());
        p.extend_from_slice(b", ");
    }

    p.extend_from_slice(&addr_text);

    v.data = p;

    NGX_OK
}

/// ngx_http_proxy_internal_body_length_variable
fn proxy_internal_body_length_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let ctx = proxy_ctx(r);
    let length = ctx.as_ref().map(|c| c.borrow().internal_body_length);

    let length = match length {
        Some(l) if l >= 0 => l,
        _ => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    v.data = length.to_string().into_bytes();

    NGX_OK
}

/// ngx_http_proxy_internal_chunked_variable
fn proxy_internal_chunked_variable(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    let chunked = proxy_ctx(r).map(|c| c.borrow().internal_chunked).unwrap_or(false);

    if !chunked {
        v.not_found = true;
        return NGX_OK;
    }

    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    v.data = b"chunked".to_vec();

    NGX_OK
}

/// ngx_http_proxy_add_variables
fn preconfiguration(cf: &mut Conf) -> ConfResult {
    use crate::variables::{NGX_HTTP_VAR_CHANGEABLE, NGX_HTTP_VAR_NOCACHEABLE, NGX_HTTP_VAR_NOHASH};

    let vars = vec![
        VarDef {
            name: "proxy_host",
            get: Some(proxy_host_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
        },
        VarDef {
            name: "proxy_port",
            get: Some(proxy_port_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
        },
        VarDef {
            name: "proxy_add_x_forwarded_for",
            get: Some(proxy_add_x_forwarded_for_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_NOHASH,
        },
        VarDef {
            name: "proxy_internal_body_length",
            get: Some(proxy_internal_body_length_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
        },
        VarDef {
            name: "proxy_internal_chunked",
            get: Some(proxy_internal_chunked_variable),
            set: None,
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
        },
    ];

    crate::variables::add_variables(cf, &vars)?;

    Ok(())
}

/// u->ssl and u->resolved of the request's upstream, with the URL of
/// proxy_pass (as configured, or evaluated) the proxy_cache code keys on.
#[derive(Default)]
struct ProxyUpstream {
    ssl: bool,
    resolved: Option<ngx_core::inet::Url>,
    url: Vec<u8>,
}

/// ngx_http_proxy_handler
async fn proxy_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());

    // ngx_http_upstream_create, the ctx; u->conf (the cache fields), and
    // u->caches of the main configuration

    {
        let plcf = lcf.borrow();
        let pmcf = r.main_conf::<crate::upstream_cache::UpstreamCacheMainConf>(ctx_index());
        let caches = Rc::new(pmcf.borrow().caches.clone());
        crate::upstream_cache::upstream_create(&r, plcf.cache.clone(), caches, "proxy", plcf.buffer_size.get_or(PROXY_BUFFER_SIZE));
    }

    let ctx = r.set_ctx(ctx_index(), ProxyCtx::default());

    let mut u = ProxyUpstream::default();

    let proxy_values = lcf.borrow().proxy_values.clone();

    match proxy_values {
        None => {
            let plcf = lcf.borrow();
            ctx.borrow_mut().vars = plcf.vars.clone();
            u.ssl = plcf.ssl;
            u.url = plcf.url.clone();
        }
        Some(codes) => {
            if proxy_eval(&r, &ctx, &codes, &mut u) != NGX_OK {
                return crate::NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    {
        let plcf = lcf.borrow();

        if !plcf.request_buffering.get_or(true)
            && plcf.body_values.is_none()
            && plcf.pass_request_body.get_or(true)
            && (!r.headers_in.borrow().chunked || plcf.http_version.get_or(crate::NGX_HTTP_VERSION_11) == crate::NGX_HTTP_VERSION_11)
        {
            r.request_body_no_buffering.set(true);
        }
    }

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init):
    // unbuffered, only what is there now, and the rest is sent on as it
    // arrives (send_request_body)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= crate::NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    upstream_init_request(r, lcf, ctx, u).await
}

/// ngx_http_proxy_eval: the URL of proxy_pass with variables, its vars and
/// the upstream it names (u->resolved).
fn proxy_eval(r: &R, ctx: &Rc<RefCell<ProxyCtx>>, codes: &[crate::script::Part], u: &mut ProxyUpstream) -> i64 {
    let proxy = match crate::script::script_run(r, codes) {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    let (add, port) = if proxy.len() > 7 && proxy[..7].eq_ignore_ascii_case(b"http://") {
        (7, 80)
    } else if proxy.len() > 8 && proxy[..8].eq_ignore_ascii_case(b"https://") {
        u.ssl = true;
        (8, 443)
    } else {
        ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "invalid URL prefix in \"{}\"", ngx_core::string::B(&proxy));
        return NGX_ERROR;
    };

    let mut url = ngx_core::inet::Url::new(&proxy[add..]);
    url.default_port = port;
    url.uri_part = true;
    url.no_resolve = true;

    if ngx_core::inet::parse_url(&mut url).is_err() {
        if let Some(err) = url.err {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "{} in upstream \"{}\"", err, ngx_core::string::B(&url.url));
        }

        return NGX_ERROR;
    }

    if url.uri.first() == Some(&b'?') {
        url.uri.insert(0, b'/');
    }

    {
        let mut c = ctx.borrow_mut();

        // ctx->vars.key_start = u->schema
        c.vars.key_start = proxy[..add].to_vec();

        set_vars(&url, &mut c.vars, &proxy);
    }

    u.url = proxy;
    u.resolved = Some(url);

    NGX_OK
}

/// The values of header or body codes compiled by ngx_http_script_compile()
/// as ngx_http_proxy_create_request() runs them: the variables with
/// ngx_http_get_indexed_variable() (e.flushed = 1), the no cacheable ones
/// having been flushed.
fn run_codes(r: &R, codes: &[crate::script::Part]) -> Vec<u8> {
    let mut value = Vec::new();

    for code in codes {
        match code {
            crate::script::Part::Literal(data) => value.extend_from_slice(data),

            crate::script::Part::Var(index) => {
                if let Some(v) = crate::variables::get_indexed_variable(r, *index) {
                    if !v.not_found {
                        value.extend_from_slice(&v.data);
                    }
                }
            }

            crate::script::Part::Capture(n) => {
                let n = *n;

                if n < r.ncaptures.get() {
                    let cap = r.captures.borrow();

                    if n + 1 < cap.len() {
                        let (a, b) = (cap[n], cap[n + 1]);

                        if a >= 0 && b >= a {
                            let data = r.captures_data.borrow();

                            if (b as usize) <= data.len() {
                                value.extend_from_slice(&data[a as usize..b as usize]);
                            }
                        }
                    }
                }
            }
        }
    }

    value
}

/// ngx_http_proxy_create_request: the request line, the Host header, the
/// headers of proxy_set_header and the defaults with a value, the client's
/// headers not among them, and the body of proxy_set_body. Returns the
/// header buffer and u->uri.
fn create_request(r: &R, plcf: &NgxHttpProxyLocConf, ctx: &Rc<RefCell<ProxyCtx>>, cacheable: bool, u_method: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let headers = if cacheable { plcf.headers_cache.clone() } else { plcf.headers.clone() };

    let headers = match headers {
        Some(h) => h,
        None => return Err(()),
    };

    let method: Vec<u8> = if let Some(m) = u_method {
        // HEAD was changed to GET to cache response
        m.to_vec()
    } else if let Some(Some(cv)) = plcf.method.as_option() {
        crate::script::complex_value(r, cv).map_err(|_| ())?
    } else {
        r.method_name.borrow().clone()
    };

    let http_version = plcf.http_version.get_or(crate::NGX_HTTP_VERSION_11);

    let mut host: Vec<u8> = Vec::new();

    if let Some(hv) = &plcf.host_value {
        host = crate::script::complex_value(r, hv).map_err(|_| ())?;
    }

    if plcf.host_value.is_none() || (host.is_empty() && http_version == crate::NGX_HTTP_VERSION_11) {
        host = ctx.borrow().vars.host_header.clone();
    }

    if method.len() == 4 && method.eq_ignore_ascii_case(b"HEAD") {
        ctx.borrow_mut().head = true;
    }

    let vars_uri = ctx.borrow().vars.uri.clone();

    let mut escape = false;
    let mut loc_len = 0;
    let mut unparsed_uri = false;

    let uri_len = if plcf.proxy_values.is_some() && !vars_uri.is_empty() {
        vars_uri.len()
    } else if vars_uri.is_empty() && r.valid_unparsed_uri.get() {
        unparsed_uri = true;
        r.unparsed_uri.borrow().len()
    } else {
        let r_uri = r.uri.borrow();

        loc_len = if r.valid_location.get() && !vars_uri.is_empty() { plcf.location.len().min(r_uri.len()) } else { 0 };

        let mut n = 0;

        if r.quoted_uri.get() || r.internal.get() {
            n = 2 * ngx_core::string::escape_uri_count(&r_uri[loc_len..], ngx_core::string::NGX_ESCAPE_URI);
            escape = n != 0;
        }

        vars_uri.len() + r_uri.len() - loc_len + n + "?".len() + r.args.borrow().len()
    };

    if uri_len == 0 {
        ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "zero length URI to proxy");
        return Err(());
    }

    crate::script::script_flush_no_cacheable_variables(r, Some(&plcf.body_flushes));
    crate::script::script_flush_no_cacheable_variables(r, Some(&headers.flushes));

    let mut body: Option<Vec<u8>> = None;

    if let Some(codes) = &plcf.body_values {
        let b = run_codes(r, codes);
        ctx.borrow_mut().internal_body_length = b.len() as i64;
        body = Some(b);
    } else if r.headers_in.borrow().chunked && r.reading_body.get() {
        let mut c = ctx.borrow_mut();
        c.internal_body_length = -1;
        c.internal_chunked = true;
    } else {
        ctx.borrow_mut().internal_body_length = r.headers_in.borrow().content_length_n;
    }

    let mut b: Vec<u8> = Vec::with_capacity(method.len() + uri_len + 256);

    // the request line

    b.extend_from_slice(&method);
    b.push(b' ');

    let uri_start = b.len();

    if plcf.proxy_values.is_some() && !vars_uri.is_empty() {
        b.extend_from_slice(&vars_uri);
    } else if unparsed_uri {
        b.extend_from_slice(&r.unparsed_uri.borrow());
    } else {
        if r.valid_location.get() {
            b.extend_from_slice(&vars_uri);
        }

        let r_uri = r.uri.borrow();

        if escape {
            ngx_core::string::escape_uri_into(&mut b, &r_uri[loc_len..], ngx_core::string::NGX_ESCAPE_URI);
        } else {
            b.extend_from_slice(&r_uri[loc_len..]);
        }

        let args = r.args.borrow();

        if !args.is_empty() {
            b.push(b'?');
            b.extend_from_slice(&args);
        }
    }

    let u_uri = b[uri_start..].to_vec();

    if http_version == crate::NGX_HTTP_VERSION_11 {
        b.extend_from_slice(b" HTTP/1.1\r\n");
    } else {
        b.extend_from_slice(b" HTTP/1.0\r\n");
    }

    if !host.is_empty() {
        b.extend_from_slice(b"Host: ");
        b.extend_from_slice(&host);
        b.extend_from_slice(b"\r\n");
    }

    for (key, codes) in headers.lines.iter() {
        let value = run_codes(r, codes);

        if value.is_empty() {
            continue;
        }

        b.extend_from_slice(key);
        b.extend_from_slice(b": ");
        b.extend_from_slice(&value);
        b.extend_from_slice(b"\r\n");
    }

    if plcf.pass_request_headers.get_or(true) {
        let hin = r.headers_in.borrow();

        for h in hin.headers.iter() {
            if headers.hash.find(ngx_core::hash::hash_key(&h.lowcase_key), &h.lowcase_key).is_some() {
                continue;
            }

            let value = h.value.borrow();

            b.extend_from_slice(&h.key);
            b.extend_from_slice(b": ");
            b.extend_from_slice(&value);
            b.extend_from_slice(b"\r\n");

            ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy header: \"{}: {}\"", ngx_core::string::B(&h.key), ngx_core::string::B(&value));
        }
    }

    // add "\r\n" at the header end
    b.extend_from_slice(b"\r\n");

    if let Some(body) = body {
        b.extend_from_slice(&body);
    }

    ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy header:\n\"{}\"", ngx_core::string::B(&b));

    Ok((b, u_uri))
}

/// The request body that follows the header when the request is sent
/// first (u->request_bufs after ngx_http_proxy_create_request): the client
/// body read so far, as the output filter sends it (unbuffered), the
/// client body (buffered, if passed), or nothing (proxy_set_body, or
/// proxy_pass_request_body off).
fn request_body_bytes(r: &R, plcf: &NgxHttpProxyLocConf, internal_chunked: bool) -> Vec<u8> {
    if r.request_body_no_buffering.get() {
        let bufs = take_request_body_bufs(r);
        let mut out = Vec::new();
        body_output_filter(&mut out, &bufs, internal_chunked);
        return out;
    }

    if plcf.body_values.is_some() || !plcf.pass_request_body.get_or(true) {
        return Vec::new();
    }

    let rb = r.request_body.borrow();
    let mut out = Vec::new();

    if let Some(body) = rb.as_ref() {
        let bod = body.borrow();

        for b in bod.bufs.iter() {
            if let ngx_core::buf::BufData::Memory(m) = &b.data {
                let end = b.last.min(m.len());
                if b.pos < end {
                    out.extend_from_slice(&m[b.pos..end]);
                }
            }

            if b.in_file {
                if let ngx_core::buf::BufData::File(f) = &b.data {
                    let sz = (b.file_last - b.file_pos) as usize;
                    let mut buf = vec![0u8; sz];
                    let mut off = 0usize;

                    while off < sz {
                        // SAFETY: buf has sz bytes, off < sz, and f.fd is
                        // the open temporary file of the request body.
                        let n = unsafe { libc::pread(f.fd, buf[off..].as_mut_ptr() as *mut _, sz - off, b.file_pos + off as i64) };
                        if n <= 0 {
                            break;
                        }
                        off += n as usize;
                    }

                    out.extend_from_slice(&buf[..off]);
                }
            }
        }
    }

    out
}

/// ngx_http_proxy_create_key: proxy_cache_key, or the URL of proxy_pass
/// (ctx->vars.key_start) and the URI of the request as the upstream
/// request has it.
fn create_key(r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let plcf = lcf.borrow();

    let ctx = match proxy_ctx(r) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    let ctx = ctx.borrow();

    if let Some(cv) = &plcf.cache.cache_key {
        match crate::script::complex_value(r, cv) {
            Ok(k) => keys.push(k),
            Err(_) => return NGX_ERROR,
        }

        return NGX_OK;
    }

    keys.push(ctx.vars.key_start.clone());

    if plcf.proxy_values.is_some() && !ctx.vars.uri.is_empty() {
        keys.push(ctx.vars.uri.clone());

        return NGX_OK;
    } else if ctx.vars.uri.is_empty() && r.valid_unparsed_uri.get() {
        keys.push(r.unparsed_uri.borrow().clone());

        return NGX_OK;
    }

    let uri = r.uri.borrow();

    let loc_len = if r.valid_location.get() && !ctx.vars.uri.is_empty() { plcf.location.len().min(uri.len()) } else { 0 };

    let mut key = ctx.vars.uri.clone();

    if r.quoted_uri.get() || r.internal.get() {
        ngx_core::string::escape_uri_into(&mut key, &uri[loc_len..], ngx_core::string::NGX_ESCAPE_URI);
    } else {
        key.extend_from_slice(&uri[loc_len..]);
    }

    let args = r.args.borrow();

    if !args.is_empty() {
        key.push(b'?');
        key.extend_from_slice(&args);
    }

    keys.push(key);

    NGX_OK
}

/// ngx_http_upstream_cache_send with ngx_http_proxy_process_status_line,
/// ngx_http_proxy_process_header and ngx_http_upstream_process_headers:
/// the response from the cache.
async fn cache_send(r: &R, lcf: &Rc<RefCell<NgxHttpProxyLocConf>>, ctx: &Rc<RefCell<ProxyCtx>>) -> i64 {
    crate::upstream_cache::upstream_cache_send(r, |buf| async move {
        let mut resp = UpstreamResponse::new();

        resp.buf = buf;

        let mut state = HeaderParse::default();

        match parse_header(r, ctx, &mut resp, &mut state, true) {
            Ok(true) => {}
            Ok(false) => return NGX_AGAIN,
            Err(_) => return crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER,
        }

        // u->headers_in, for $upstream_http_*
        *r.upstream_headers_in.borrow_mut() = resp.headers.iter().filter(|h| h.hash.get() != 0).cloned().collect();

        match process_headers(r, lcf, &resp).await {
            Processed::Ok(_) => NGX_OK,
            Processed::Redirect(xar) => {
                // ngx_http_upstream_finalize_request(r, u, NGX_DECLINED)
                crate::upstream_cache::finalize(r, NGX_DECLINED, None);
                accel_redirect(r, &xar).await
            }
            Processed::Finalize(rc) => {
                crate::upstream_cache::finalize(r, rc, None);
                rc
            }
        }
    })
    .await
}

/// The stale response of ngx_http_upstream_next, when there is no next
/// upstream to try, or the error status the request is finalized with.
async fn next_failed(r: &R, lcf: &Rc<RefCell<NgxHttpProxyLocConf>>, ctx: &Rc<RefCell<ProxyCtx>>, ft_type: u32, status: i64) -> i64 {
    if crate::upstream_cache::next_stale(r, ft_type) {
        // u->reinit_request(r): the status line and chunked state are
        // parsed anew

        if let Some(u) = crate::upstream_cache::upstream_of(r) {
            u.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_STALE);
        }

        let mut rc = cache_send(r, lcf, ctx).await;

        if rc == NGX_DONE {
            return NGX_DONE;
        }

        if rc == crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER {
            rc = crate::NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        crate::upstream_cache::finalize(r, rc, None);

        return rc;
    }

    return_error(r, status).await
}


/// ngx_http_upstream_init_request with the proxy module's callbacks, and
/// what follows up to the response.
async fn upstream_init_request(r: R, lcf: Rc<RefCell<NgxHttpProxyLocConf>>, ctx: Rc<RefCell<ProxyCtx>>, u: ProxyUpstream) -> i64 {
    let _ = &u.url;

    // ngx_http_upstream_init_request: ngx_http_upstream_cache, then
    // ngx_http_upstream_cache_send for a response from the cache

    let ucache = match crate::upstream_cache::upstream_of(&r) {
        Some(uc) => uc,
        None => return crate::NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    if ucache.conf.enabled() {
        let mut rc = crate::upstream_cache::upstream_cache_wait(&r, &ucache, &create_key).await;

        if rc == NGX_ERROR {
            return crate::NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if rc == NGX_OK {
            rc = cache_send(&r, &lcf, &ctx).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_DECLINED;
                r.cached.set(false);
                ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_MISS);
            }
        }

        if rc != NGX_DECLINED {
            return rc;
        }
    }

    // the cache is freed when the upstream is done (finalize_request)
    let _cache_guard = crate::upstream_cache::CacheGuard::new(&r);

    // u->cacheable, and the HEAD method changed to GET (u->method)
    let cacheable = ucache.cacheable.get();
    let u_method: Option<&'static [u8]> = *ucache.method.borrow();

    // u->create_request

    let (request, _u_uri) = {
        let plcf = lcf.borrow();

        match create_request(&r, &plcf, &ctx, cacheable, u_method) {
            Ok(x) => x,
            Err(()) => return crate::NGX_HTTP_INTERNAL_SERVER_ERROR,
        }
    };

    let internal_chunked = ctx.borrow().internal_chunked;
    let head = ctx.borrow().head;

    let body_bytes = {
        let plcf = lcf.borrow();
        request_body_bytes(&r, &plcf, internal_chunked)
    };

    let conf_borrowed = lcf.borrow();

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

    drop(conf_borrowed);

    // u->ssl: ngx_http_upstream_ssl_init_connection after connecting, with
    // u->conf's SSL fields
    let connect_timeout = *lcf.borrow().connect_timeout.get();
    let ssl_setup = if u.ssl {
        let conf = lcf.borrow().upstream_ssl.clone();
        Some(crate::upstream_ssl::SslSetup { conf, alpn: Vec::new() })
    } else {
        None
    };

    // the peers of the upstream{} or implicit upstream of proxy_pass, of
    // the upstream a variable URL's host names, or of the addresses it
    // resolves to
    let tag = Rc::as_ptr(&lcf) as *const () as usize;
    let peer = match (&u.resolved, static_upstream.as_ref()) {
        (Some(url), _) => crate::upstream::UpstreamPeer::resolve(&r, url, next_upstream_mask, next_upstream_tries, next_upstream_timeout, tag).await,
        (None, Some(uscf)) => crate::upstream::UpstreamPeer::init(&r, uscf, next_upstream_mask, next_upstream_tries, next_upstream_timeout, tag),
        (None, None) => {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ALERT, r.connection.log, None, "no upstream configuration");
            Err(crate::NGX_HTTP_INTERNAL_SERVER_ERROR)
        }
    };
    let peer = match peer {
        Ok(p) => p,
        Err(rc) => return return_error(&r, rc).await,
    };
    // the peer is freed when the request is done
    let mut g = crate::upstream::PeerGuard::new(&r, peer);

    // u->buffering, which "X-Accel-Buffering" may change
    let (conf_buffering, change_buffering, read_timeout, store, ignore_client_abort, buffer_size) = {
        let c = lcf.borrow();
        (
            c.buffering.get_or(true),
            !c.cache.ignores(crate::upstream::NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING),
            c.read_timeout.get_or(60000),
            matches!(c.store, Some(ProxyStore::On) | Some(ProxyStore::Path(_))),
            c.ignore_client_abort.get_or(false),
            c.buffer_size.get_or(PROXY_BUFFER_SIZE),
        )
    };

    // ngx_http_upstream_rd_check_broken_connection: a request that is not
    // cached is finalized with 499 when the client closes the connection
    let watch = if !store && !r.post_action.get() && !ignore_client_abort && !cacheable { Some(ClientWatch::new(&r)) } else { None };
    let watch = watch.as_ref();

    // u->buffer.pos += r->cache->header_start: the header of the cache file
    // goes before the response header in u->buffer
    let header_buffer_size = match crate::file_cache::cache_of(&r) {
        Some(c) => buffer_size.saturating_sub(c.borrow().header_start),
        None => buffer_size,
    };

    // proxy_next_upstream retry loop: on connect error / matching HTTP status,
    // free the peer and connect to the next one (ngx_http_upstream_next).
    let mut sock: UpstreamSock;
    let mut upstream_requests: u64;
    let mut upstream_start_time: u64;
    let mut resp: UpstreamResponse;

    'retry: loop {
        // ngx_http_upstream_connect
        let rc = g.u.connect(&r);

        if rc == NGX_ERROR {
            return return_error(&r, crate::NGX_HTTP_INTERNAL_SERVER_ERROR).await;
        }

        if rc == NGX_BUSY {
            match g.u.next(&r, crate::upstream::NGX_HTTP_UPSTREAM_FT_NOLIVE) {
                Ok(()) => continue 'retry,
                Err(st) => return next_failed(&r, &lcf, &ctx, crate::upstream::NGX_HTTP_UPSTREAM_FT_NOLIVE, st).await,
            }
        }

        let try_started_ms = g.u.start_time;

        sock = if rc == NGX_DONE {
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

            let connected = {
                let connect = connect_upstream(&r, &sockaddr, bind_addr, ssl_setup.as_ref(), Some(&mut g.u), connect_timeout);

                tokio::select! {
                    res = connect => res,
                    err = client_closed(watch) => return client_closed_request(&r, err),
                }
            };

            match connected {
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
                        Err(st) => return next_failed(&r, &lcf, &ctx, ft, st).await,
                    }
                }
            }
        };

        upstream_requests += 1;

        // ngx_http_upstream_send_request: the connection is established
        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            if st.connect_time == u64::MAX {
                st.connect_time = ngx_core::times::current_msec().saturating_sub(try_started_ms);
            }
        }

        // the request (u->request_bufs) and, unbuffered, what was read of
        // the body so far, in one write so a fast upstream that reads once
        // and closes (e.g. Test::Nginx daemons calling sysread) sees it all
        let mut wire: Vec<u8> = Vec::with_capacity(request.len() + body_bytes.len());
        wire.extend_from_slice(&request);
        wire.extend_from_slice(&body_bytes);

        g.u.request_sent = true;

        let sent = {
            let write = sock.write_all(&wire);

            tokio::select! {
                res = write => res,
                err = client_closed(watch) => return client_closed_request(&r, err),
            }
        };

        if sent.is_err() {
            match g.u.next(&r, FT_ERROR) {
                Ok(()) => continue 'retry,
                Err(st) => return next_failed(&r, &lcf, &ctx, FT_ERROR, st).await,
            }
        }

        let mut bytes_sent = wire.len() as i64;

        if r.reading_body.get() {
            let output = |out: &mut Vec<u8>, bufs: &ngx_core::buf::Chain| body_output_filter(out, bufs, internal_chunked);

            match send_request_body(&r, &mut sock, &output).await {
                Ok(n) => bytes_sent += n,
                Err(rc) => {
                    if rc == NGX_HTTP_BAD_GATEWAY as i64 {
                        // the upstream write failed
                        match g.u.next(&r, FT_ERROR) {
                            Ok(()) => continue 'retry,
                            Err(st) => return next_failed(&r, &lcf, &ctx, FT_ERROR, st).await,
                        }
                    }
                    return return_error(&r, rc).await;
                }
            }
        }

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.bytes_sent = bytes_sent;
        }

        // ngx_http_upstream_process_header
        resp = match process_header(&r, &mut sock, &ctx, header_buffer_size, read_timeout, watch).await {
            Ok(h) => h,
            Err(HeaderError::Next(ft)) => match g.u.next(&r, ft) {
                Ok(()) => continue 'retry,
                Err(st) => return next_failed(&r, &lcf, &ctx, ft, st).await,
            },
            Err(HeaderError::ClientClosed(err)) => return client_closed_request(&r, err),
        };

        // u->state->header_time
        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.header_time = ngx_core::times::current_msec().saturating_sub(try_started_ms);
        }

        // u->headers_in, for $upstream_http_* and the balancer's notify
        *r.upstream_headers_in.borrow_mut() = resp.headers.iter().filter(|h| h.hash.get() != 0).cloned().collect();

        // ngx_http_upstream_test_next: a status proxy_next_upstream names,
        // with tries left
        if resp.status_n >= crate::NGX_HTTP_SPECIAL_RESPONSE {
            let ft = match resp.status_n {
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
                    match g.u.next(&r, ft) {
                        Ok(()) => continue 'retry,
                        Err(st) => return next_failed(&r, &lcf, &ctx, ft, st).await,
                    }
                }
            }
        }

        break 'retry;
    }

    let status = resp.status_n;

    // the connection goes back to the keepalive cache if the response
    // allows it (u->keepalive set by the filters), when the request is done
    let keep = |g: &mut crate::upstream::PeerGuard, sock: UpstreamSock, keepalive: bool| {
        if keepalive {
            g.conn = Some(crate::upstream::UpstreamConn { sock, requests: upstream_requests, start_time: upstream_start_time });
            g.keepalive = true;
        }
    };

    if status >= crate::NGX_HTTP_SPECIAL_RESPONSE {
        // ngx_http_upstream_test_next: the stale response instead of the
        // status *_cache_use_stale names

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

        if ft != 0 && crate::upstream_cache::test_next_stale(&r, ft) {
            // u->reinit_request(r)

            keep(&mut g, sock, resp.keepalive);
            g.finalize();

            ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_STALE);

            let mut rc = cache_send(&r, &lcf, &ctx).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = crate::NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            crate::upstream_cache::finalize(&r, rc, None);

            return rc;
        }

        // the expired response was revalidated

        if crate::upstream_cache::test_next_not_modified(&r, status) {
            let saved = crate::upstream_cache::not_modified_start(&r);

            // u->reinit_request(r)

            keep(&mut g, sock, resp.keepalive);
            g.finalize();

            let mut rc = cache_send(&r, &lcf, &ctx).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = crate::NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            // u->headers_in.status_n: that of the cached response now
            let cached_status = r.headers_out.borrow().status;

            crate::upstream_cache::not_modified_finish(&r, saved, cached_status);

            crate::upstream_cache::finalize(&r, rc, None);

            return rc;
        }

        // ngx_http_upstream_intercept_errors: the error_page of the status
        // instead of the response

        let intercept = lcf.borrow().intercept_errors.get_or(false);

        let has_page = intercept && r.clcf().borrow().error_pages.as_ref().map(|pages| pages.iter().any(|p| p.status == status)).unwrap_or(false);

        if has_page {
            if status == crate::NGX_HTTP_UNAUTHORIZED {
                // the WWW-Authenticate of the upstream goes with the error page
                let mut ho = r.headers_out.borrow_mut();
                for h in resp.headers.iter().filter(|h| h.hash.get() != 0 && h.lowcase_key == b"www-authenticate") {
                    let ho_h = crate::request::TableElt::new(&h.key, &h.value.borrow());
                    ho.headers.push(ho_h.clone());
                    ho.www_authenticate.push(ho_h);
                }
            }

            // the status is cached as an error of the keys zone
            crate::upstream_cache::intercept_errors(&r, status, &resp.cache);

            keep(&mut g, sock, resp.keepalive);
            g.finalize();

            return status;
        }
    }

    // peer.notify(NGX_HTTP_UPSTREAM_NOTIFY_HEADER)
    g.u.notify(&r, crate::upstream::NGX_HTTP_UPSTREAM_NOTIFY_HEADER);

    // ngx_http_upstream_process_headers

    let mut u_buffering = conf_buffering;

    match process_headers(&r, &lcf, &resp).await {
        Processed::Ok(buffering) => {
            if change_buffering {
                if let Some(b) = buffering {
                    u_buffering = b;
                }
            }
        }

        Processed::Redirect(xar) => {
            // ngx_http_upstream_finalize_request(r, u, NGX_DECLINED)
            keep(&mut g, sock, resp.keepalive);
            g.finalize();
            crate::upstream_cache::finalize(&r, NGX_DECLINED, None);
            r.upstream_states.borrow_mut().clear();

            return accel_redirect(&r, &xar).await;
        }

        Processed::Finalize(rc) => {
            crate::upstream_cache::finalize(&r, rc, None);
            return rc;
        }
    }

    // 101 Switching Protocols the client did not ask for: rejected before
    // any header is sent (ngx_http_proxy_process_header: u->upgrade only
    // with r->headers_in.upgrade)
    if status == 101 && !resp.upgrade {
        // Send a bare 502 status line with no body — the response is closed
        // without an error page (test expects body_bytes_sent == 0).
        r.headers_out.borrow_mut().status = NGX_HTTP_BAD_GATEWAY as i64;
        r.header_only.set(true);
        r.keepalive.set(false);
        let _ = crate::core_rt::send_header(&r).await;
        crate::upstream_cache::free(&r, None);
        return crate::NGX_DONE;
    }

    // ngx_http_upstream_send_response

    let rc = crate::core_rt::send_header(&r).await;

    if rc == NGX_ERROR || rc > NGX_OK || r.post_action.get() {
        crate::upstream_cache::finalize(&r, rc, None);
        return rc;
    }

    if resp.upgrade {
        crate::upstream_cache::free(&r, None);

        // ngx_http_upstream_upgrade
        if !r.is_main() {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "connection upgrade in subrequest");
            return NGX_ERROR;
        }

        r.keepalive.set(false);

        // Force headers out through the write filter — postpone_output
        // would otherwise keep the 101 line buffered until the "last"
        // signal, which never arrives in an upgrade.
        let mut b = ngx_core::buf::Buf::from_vec(Vec::new());
        b.flush = true;
        b.sync = true;
        let mut chain = ngx_core::buf::Chain::new();
        chain.push_back(b);
        let _ = crate::core_rt::output_filter(&r, chain).await;

        // Anything past the header block was already sent by upstream as
        // part of the upgraded protocol: forwarded first.
        if resp.pos < resp.buf.len() {
            let _ = r.connection.send_all(&resp.buf[resp.pos..]).await;
        }

        let _ = proxy_upgrade_tunnel(r.clone(), sock).await;
        return crate::NGX_DONE;
    }

    let header_only = r.header_only.get();

    if header_only {
        if !u_buffering || (!ucache.cacheable.get() && !store) {
            // ngx_http_upstream_finalize_request(r, u, rc)
            keep(&mut g, sock, resp.keepalive);
            crate::upstream_cache::finalize(&r, rc, None);
            return rc;
        }
    }

    // the cache: *_no_cache, the valid time, the header of the cache file;
    // p->temp_file with it (p->buf_to_file)

    let mut writer: Option<crate::upstream_cache::CacheWriter> = None;

    if !u_buffering {
        crate::upstream_cache::free(&r, None);
    } else {
        match crate::upstream_cache::send_response(&r, status, &resp.cache, resp.pos) {
            Err(()) => {
                crate::upstream_cache::finalize(&r, NGX_ERROR, None);
                return NGX_ERROR;
            }

            Ok(Some(header)) => {
                let temp_path = lcf.borrow().temp_path.as_option().cloned();

                writer = crate::upstream_cache::CacheWriter::new(&r, temp_path.as_deref(), &header, &resp.buf[..resp.pos]);

                if writer.is_none() {
                    crate::upstream_cache::finalize(&r, NGX_ERROR, None);
                    return NGX_ERROR;
                }
            }

            Ok(None) => {}
        }

        if header_only && !ucache.cacheable.get() && !store {
            keep(&mut g, sock, resp.keepalive);
            crate::upstream_cache::finalize(&r, 0, None);
            return 0;
        }
    }

    let cacheable = ucache.cacheable.get();

    // p->limit_rate = ngx_http_complex_value_size(r, u->conf->limit_rate, 0)
    let (limit_rate, capture) = if u_buffering {
        let lr = lcf.borrow().limit_rate.as_option().cloned().flatten();
        (crate::script::complex_value_size(&r, &lr, 0), cacheable || store)
    } else {
        (0, false)
    };

    let pass_trailers = lcf.borrow().pass_trailers.get_or(false);

    let hide = hide_headers(&lcf);

    let body = send_response_body(
        &r,
        &mut sock,
        &mut resp,
        head,
        BodyParams { buffering: u_buffering, limit_rate, downstream: !header_only, capture, store, read_timeout, pass_trailers, buffer_size },
        watch,
        &hide,
        &mut writer,
    )
    .await;

    if body.keepalive {
        keep(&mut g, sock, true);
    }

    // ngx_http_upstream_process_request: ngx_http_upstream_store() for a
    // 200 whose body is as long as its "Content-Length" says, and the
    // cache file
    if body.rc == NGX_OK && body.complete && store && status == crate::NGX_HTTP_OK && (resp.content_length_n == -1 || resp.content_length_n == body.data.len() as i64) {
        maybe_store_body(&r, &body.data);
    }

    if let Some(w) = writer {
        let tf_done = body.complete;
        w.finish(&r, tf_done, false, resp.content_length_n);
    }

    // ngx_http_upstream_finalize_request
    crate::upstream_cache::finalize(&r, body.rc, None);

    body.rc
}

/// The hide headers of the location (ngx_http_upstream_hide_headers_hash):
/// ngx_http_proxy_hide_headers and proxy_hide_header, but proxy_pass_header.
fn hide_headers(lcf: &Rc<RefCell<NgxHttpProxyLocConf>>) -> Vec<Vec<u8>> {
    let c = lcf.borrow();
    let mut set: Vec<Vec<u8>> = PROXY_HIDE_HEADERS.iter().map(|s| s.to_vec()).collect();
    if let Some(hide) = &c.hide_headers {
        for h in hide {
            if !set.iter().any(|x| x == h) {
                set.push(h.clone());
            }
        }
    }
    if let Some(pass) = &c.pass_headers {
        set.retain(|h| !pass.iter().any(|p| p == h));
    }
    set
}

/// What ngx_http_upstream_process_headers ends with.
enum Processed {
    /// the headers are in headers_out, with u->buffering as X-Accel-Buffering
    /// set it, if it did
    Ok(Option<bool>),
    /// X-Accel-Redirect: the upstream is finalized (NGX_DECLINED), then the
    /// request redirected
    Redirect(Vec<u8>),
    /// the request is finalized with the status
    Finalize(i64),
}

/// ngx_http_upstream_process_headers, with the headers_in handlers of the
/// X-Accel-* headers (ngx_http_upstream_process_buffering, _limit_rate,
/// _charset) and the copy handlers of the proxy (proxy_redirect,
/// proxy_cookie_*): for a response of the upstream and for one from the
/// cache.
async fn process_headers(r: &R, lcf: &Rc<RefCell<NgxHttpProxyLocConf>>, resp: &UpstreamResponse) -> Processed {
    let status = resp.status_n;

    // u->headers_in.no_cache || u->headers_in.expired
    crate::upstream_cache::process_headers_cacheable(r, &resp.cache);

    let (ignore_xa_buffering, ignore_xa_limit_rate, ignore_xa_charset, ignore_xa_redirect, force_ranges) = {
        let c = lcf.borrow();
        (
            c.cache.ignores(crate::upstream::NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING),
            c.cache.ignores(crate::upstream::NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE),
            c.cache.ignores(crate::upstream::NGX_HTTP_UPSTREAM_IGN_XA_CHARSET),
            c.cache.ignores(crate::upstream::NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT),
            c.force_ranges.get_or(false),
        )
    };

    // Effective hide list: default PROXY_HIDE_HEADERS + user's hide_headers,
    // minus user's pass_headers (pass wins over hide).
    let effective_hide = hide_headers(lcf);

    // X-Accel-Buffering (ngx_http_upstream_process_buffering, for each)
    let mut u_buffering = None;

    if !ignore_xa_buffering {
        for h in resp.headers.iter().filter(|h| h.hash.get() != 0 && h.lowcase_key == b"x-accel-buffering") {
            let v = h.value.borrow();
            if v.eq_ignore_ascii_case(b"yes") {
                u_buffering = Some(true);
            } else if v.eq_ignore_ascii_case(b"no") {
                u_buffering = Some(false);
            }
        }
    }

    // X-Accel-Limit-Rate: bytes-per-second cap on the response, matching
    // ngx_http_upstream_process_limit_rate. Applied to r.limit_rate BEFORE
    // X-Accel-Redirect so the header survives the internal redirect.
    if !ignore_xa_limit_rate {
        let xal_val = resp.headers.iter().find(|h| h.hash.get() != 0 && h.lowcase_key == b"x-accel-limit-rate").map(|h| h.value.borrow().clone());
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

    // X-Accel-Charset (ngx_http_upstream_process_charset, for each):
    // r->headers_out.override_charset, unless ignored
    if !ignore_xa_charset {
        let xac = resp.headers.iter().filter(|h| h.hash.get() != 0 && h.lowcase_key == b"x-accel-charset").last().map(|h| h.value.borrow().clone());

        if let Some(v) = xac {
            r.headers_out.borrow_mut().override_charset = Some(v);
        }
    }

    // X-Accel-Redirect: finalize the upstream (NGX_DECLINED) and redirect
    // internally, keeping only the headers marked `redirect=1` in
    // ngx_http_upstream.c. The method becomes GET (unless HEAD).
    let xar_val = resp.headers.iter().find(|h| h.hash.get() != 0 && h.lowcase_key == b"x-accel-redirect").map(|h| h.value.borrow().clone()).filter(|_| !ignore_xa_redirect);

    if let Some(xar) = xar_val {
        if !xar.is_empty() {
            // the headers of ngx_http_upstream_headers_in[] with "redirect"
            const KEEP_LC: &[&[u8]] = &[b"content-type", b"set-cookie", b"content-disposition", b"cache-control", b"expires", b"accept-ranges"];
            {
                let mut ho = r.headers_out.borrow_mut();
                for h in resp.headers.iter() {
                    if h.hash.get() == 0 || !KEEP_LC.iter().any(|k| h.lowcase_key == *k) {
                        continue;
                    }
                    let mut copied = crate::upstream::CopiedHeaders::default();
                    crate::upstream::copy_header(&mut ho, &mut copied, status, &h.key, &h.value.borrow());
                }
                ho.status = 0;
                ho.content_length_n = -1;
                ho.content_length = None;
            }

            return Processed::Redirect(xar);
        }
    }

    let cacheable = crate::upstream_cache::cacheable(r);

    // the headers not hidden go to headers_out
    let mut copied = crate::upstream::CopiedHeaders::default();
    {
        let mut ho = r.headers_out.borrow_mut();

        for h in resp.headers.iter() {
            if h.hash.get() == 0 {
                continue;
            }

            if effective_hide.iter().any(|x| x == &h.lowcase_key) {
                continue;
            }

            // ngx_http_upstream_copy_upgrade: not to HTTP/2 and HTTP/3
            // clients
            if h.lowcase_key == b"upgrade" && r.http_version.get() >= crate::NGX_HTTP_VERSION_20 {
                continue;
            }

            // ngx_http_upstream_copy_allow_ranges
            if h.lowcase_key == b"accept-ranges" {
                if force_ranges {
                    continue;
                }

                if r.cached.get() {
                    r.allow_ranges.set(true);
                    continue;
                }

                if cacheable {
                    r.allow_ranges.set(true);
                    r.single_range.set(true);
                    continue;
                }
            }

            crate::upstream::copy_header(&mut ho, &mut copied, status, &h.key, &h.value.borrow());
        }

        // the special empty "Server" and "Date" of
        // ngx_http_proxy_process_header, passed with proxy_pass_header:
        // no header of the upstream's nor the server's own
        if !resp.server && !effective_hide.iter().any(|x| x == b"server") {
            let h = crate::request::TableElt::new(b"Server", b"");
            h.hash.set(0);
            ho.server = Some(h);
        }

        if !resp.date && !effective_hide.iter().any(|x| x == b"date") {
            let h = crate::request::TableElt::new(b"Date", b"");
            h.hash.set(0);
            ho.date = Some(h);
        }

        // "Content-Length" is not copied (ngx_http_upstream_ignore_header_line)
        ho.content_length = None;

        ho.status = status;
        ho.status_line = resp.status_line.clone();
        ho.content_length_n = resp.content_length_n;
    }

    r.disable_not_modified.set(!cacheable);

    if force_ranges {
        r.allow_ranges.set(true);
        r.single_range.set(true);

        if r.cached.get() {
            r.single_range.set(false);
        }
    }

    // proxy_cookie_domain / proxy_cookie_path: rewrite Set-Cookie Domain=
    // and Path= attributes before the header filter serializes them.
    rewrite_set_cookies(r);

    // proxy_redirect: rewrite Location / Refresh (url=...) headers.
    rewrite_redirect_headers(r);

    Processed::Ok(u_buffering)
}

/// The X-Accel-Redirect of ngx_http_upstream_process_headers: a named
/// location, or the URI (with its arguments) for an internal redirect.
async fn accel_redirect(r: &R, xar: &[u8]) -> i64 {
    if xar.first() == Some(&b'@') {
        let _ = crate::core_rt::named_location(r, xar).await;
        return NGX_DONE;
    }

    // Non-named: unescape the URI (splitting off any query at '?'),
    // then reject unsafe paths (../ etc.) with 404, matching the
    // ngx_http_parse_unsafe_uri gate C runs before internal_redirect.
    let (decoded, _) = ngx_core::string::unescape_uri(xar, ngx_core::string::NGX_UNESCAPE_URI);
    let (uri_bytes, args_opt): (Vec<u8>, Option<Vec<u8>>) = if let Some(q) = decoded.iter().position(|&b| b == b'?') { (decoded[..q].to_vec(), Some(decoded[q + 1..].to_vec())) } else { (decoded, None) };
    let mut flags = 0u32;
    let empty: [u8; 0] = [];
    if crate::parse::parse_unsafe_uri(&uri_bytes, &empty, &mut flags) != NGX_OK {
        return return_error(r, crate::NGX_HTTP_NOT_FOUND).await;
    }
    if r.method.get() != crate::NGX_HTTP_HEAD {
        r.method.set(crate::NGX_HTTP_GET);
        *r.method_name.borrow_mut() = b"GET".to_vec();
    }
    let _ = crate::core_rt::internal_redirect(r, &uri_bytes, args_opt.as_deref()).await;
    NGX_DONE
}

/// u->headers_in and u->buffer of an upstream response
/// (ngx_http_upstream_headers_in_t): what ngx_http_proxy_process_status_line
/// and ngx_http_proxy_process_header found, the body starting at `pos`.
struct UpstreamResponse {
    buf: Vec<u8>,
    pos: usize,
    status_n: i64,
    status_line: Vec<u8>,
    headers: Vec<crate::request::Header>,
    content_length: Option<crate::request::Header>,
    transfer_encoding: Option<crate::request::Header>,
    content_length_n: i64,
    chunked: bool,
    connection_close: bool,
    /// headers_in.server and headers_in.date were sent
    server: bool,
    date: bool,
    /// u->keepalive, set for a response without a body
    keepalive: bool,
    /// u->upgrade
    upgrade: bool,
    /// u->headers_in.trailers
    trailers: Vec<crate::request::Header>,
    /// the fields of u->headers_in the cache handlers set
    cache: crate::upstream_cache::CacheHeadersIn,
}

impl UpstreamResponse {
    fn new() -> UpstreamResponse {
        UpstreamResponse {
            buf: Vec::new(),
            pos: 0,
            status_n: 0,
            status_line: Vec::new(),
            headers: Vec::new(),
            content_length: None,
            transfer_encoding: None,
            content_length_n: -1,
            chunked: false,
            connection_close: false,
            server: false,
            date: false,
            keepalive: false,
            upgrade: false,
            trailers: Vec::new(),
            cache: crate::upstream_cache::CacheHeadersIn::new(),
        }
    }

    /// ngx_memzero(&u->headers_in) of ngx_http_upstream_process_early_hints
    fn clear_headers(&mut self) {
        self.status_n = 0;
        self.status_line.clear();
        self.headers.clear();
        self.content_length = None;
        self.transfer_encoding = None;
        self.content_length_n = -1;
        self.chunked = false;
        self.connection_close = false;
        self.server = false;
        self.date = false;
        self.cache = crate::upstream_cache::CacheHeadersIn::new();
    }
}

/// How reading a response header failed.
enum HeaderError {
    /// ngx_http_upstream_next() with this failure type
    Next(u32),
    /// the client closed the connection (ngx_http_upstream_check_broken_connection)
    ClientClosed(i32),
}

/// The default proxy_buffer_size: ngx_pagesize.
const PROXY_BUFFER_SIZE: usize = 4096;

/// ngx_http_upstream_process_header with ngx_http_proxy_process_status_line
/// and ngx_http_proxy_process_header: the response header read from the
/// upstream, the headers checked by the upstream's headers_in handlers.
async fn process_header(r: &R, sock: &mut UpstreamSock, ctx: &Rc<RefCell<ProxyCtx>>, buffer_size: usize, read_timeout: u64, watch: Option<&ClientWatch>) -> Result<UpstreamResponse, HeaderError> {
    let log = r.connection.log.clone();
    let action = log.action();

    log.set_action(Some("reading response header from upstream"));

    let rc = read_header(r, sock, ctx, buffer_size, read_timeout, watch).await;

    log.set_action(action);

    rc
}

async fn read_header(r: &R, sock: &mut UpstreamSock, ctx: &Rc<RefCell<ProxyCtx>>, buffer_size: usize, read_timeout: u64, watch: Option<&ClientWatch>) -> Result<UpstreamResponse, HeaderError> {
    let mut u = UpstreamResponse::new();

    let mut state = HeaderParse::default();
    let mut chunk = vec![0u8; buffer_size.max(1)];

    loop {
        // c->recv() into what is left of u->buffer
        let room = buffer_size.saturating_sub(u.buf.len()).clamp(1, chunk.len());

        let res = {
            let read = tokio::time::timeout(std::time::Duration::from_millis(read_timeout), sock.read(&mut chunk[..room]));

            tokio::select! {
                res = read => res,
                err = client_closed(watch) => return Err(HeaderError::ClientClosed(err)),
            }
        };

        let n = match res {
            Err(_) => {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
                return Err(HeaderError::Next(FT_TIMEOUT));
            }
            Ok(Err(e)) => {
                if let Some(errno) = e.raw_os_error() {
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, Some(errno), "recv() failed");
                }
                return Err(HeaderError::Next(FT_ERROR));
            }
            Ok(Ok(0)) => {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection");
                return Err(HeaderError::Next(FT_ERROR));
            }
            Ok(Ok(n)) => n,
        };

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.bytes_received += n as i64;
        }

        u.buf.extend_from_slice(&chunk[..n]);

        // rc = u->process_header(r)

        match parse_header(r, ctx, &mut u, &mut state, false) {
            Ok(true) => return Ok(u),

            Ok(false) => {
                // NGX_AGAIN
                if u.buf.len() >= buffer_size {
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent too big header");
                    return Err(HeaderError::Next(crate::upstream::NGX_HTTP_UPSTREAM_FT_INVALID_HEADER));
                }
            }

            Err(ft) => return Err(HeaderError::Next(ft)),
        }
    }
}

/// The state of ngx_http_proxy_process_status_line and
/// ngx_http_proxy_process_header between reads: whether the status line
/// was parsed, the header line parser, and where parsing goes on in
/// u->buffer.
struct HeaderParse {
    status_done: bool,
    pr: crate::parse::ParseRequest,
    pos: usize,
}

impl Default for HeaderParse {
    fn default() -> HeaderParse {
        HeaderParse { status_done: false, pr: crate::parse::ParseRequest { upstream: true, ..Default::default() }, pos: 0 }
    }
}

/// u->process_header on what u->buffer has: ngx_http_proxy_process_status_line,
/// then ngx_http_proxy_process_header with the headers_in handlers.
/// Ok(true) when the header is done (the body from u.pos), Ok(false) when
/// more is needed (NGX_AGAIN), Err with the failure of
/// NGX_HTTP_UPSTREAM_INVALID_HEADER otherwise. `cached` is a header of a
/// cache file (ngx_http_upstream_cache_send): early hints are an invalid
/// header there.
fn parse_header(r: &R, ctx: &Rc<RefCell<ProxyCtx>>, u: &mut UpstreamResponse, st: &mut HeaderParse, cached: bool) -> Result<bool, u32> {
    use crate::parse::{NGX_HTTP_PARSE_HEADER_DONE, NGX_HTTP_PARSE_INVALID_HEADER};

    loop {
        if !st.status_done {
            // ngx_http_proxy_process_status_line

            let mut p = st.pos;
            let mut status = crate::parse::Status::default();

            let rc = crate::parse::parse_status_line(&u.buf, &mut p, &mut status);

            if rc == NGX_AGAIN {
                return Ok(false);
            }

            if rc == NGX_ERROR {
                if r.cache.borrow().is_some() {
                    r.http_version.set(crate::NGX_HTTP_VERSION_9);

                    // u->buffer.pos = ctx->status.line_start
                    u.pos = st.pos;

                    return Ok(true);
                }

                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent no valid HTTP/1.0 header");

                r.http_version.set(crate::NGX_HTTP_VERSION_9);

                if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
                    state.status = crate::NGX_HTTP_OK;
                }

                u.status_n = crate::NGX_HTTP_OK;
                u.connection_close = true;

                // u->buffer.pos = ctx->status.line_start
                u.pos = st.pos;

                return Ok(true);
            }

            if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
                if state.status == 0 {
                    state.status = status.code as i64;
                }
            }

            u.status_n = status.code as i64;
            u.status_line = u.buf[status.start..status.end].to_vec();

            ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy status {} \"{}\"", u.status_n, ngx_core::string::B(&u.status_line));

            if status.http_version < crate::NGX_HTTP_VERSION_11 {
                if status.code == 103 {
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent HTTP/1.0 response with early hints");
                    return Err(crate::upstream::NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
                }

                u.connection_close = true;
            }

            st.pos = p;
            st.status_done = true;
        }

        // ngx_http_proxy_process_header

        loop {
            let rc = crate::parse::parse_header_line(&mut st.pr, &u.buf, &mut st.pos, true);

            if rc == NGX_OK {
                // a header line has been parsed successfully

                let pr = &st.pr;

                let key = u.buf[pr.header_name_start..pr.header_name_end].to_vec();
                let value = u.buf[pr.header_start..pr.header_end].to_vec();

                let lowcase = if key.len() == pr.lowcase_index { pr.lowcase_header[..key.len()].to_vec() } else { key.to_ascii_lowercase() };

                ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy header: \"{}: {}\"", ngx_core::string::B(&key), ngx_core::string::B(&value));

                let h = crate::request::TableElt::with_hash(&key, &value, pr.header_hash, lowcase);

                u.headers.push(h.clone());

                if u.status_n == 103 {
                    continue;
                }

                upstream_process_header_line(r, u, &h)?;

                continue;
            }

            if rc == NGX_HTTP_PARSE_HEADER_DONE {
                // a whole header has been parsed successfully

                ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy header done");

                if u.status_n == 103 {
                    if cached {
                        // NGX_HTTP_UPSTREAM_EARLY_HINTS
                        return Err(crate::upstream::NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
                    }

                    // ngx_http_upstream_process_early_hints: the early
                    // hints filters of ngx_http_send_early_hints() are
                    // not ported, so the 103 goes nowhere, as without
                    // the "early_hints" directive
                    ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http upstream early hints");

                    u.clear_headers();
                    st.status_done = false;
                    st.pr = crate::parse::ParseRequest { upstream: true, ..Default::default() };

                    break;
                }

                // clear content length if response is chunked

                if u.chunked {
                    u.content_length_n = -1;
                }

                // set u->keepalive if response has no body; this
                // allows to keep connections alive in case of
                // r->header_only or X-Accel-Redirect

                let head = ctx.borrow().head;

                if u.status_n == crate::NGX_HTTP_NO_CONTENT as i64 || u.status_n == crate::NGX_HTTP_NOT_MODIFIED as i64 || head || (!u.chunked && u.content_length_n == 0) {
                    u.keepalive = !u.connection_close;
                }

                if u.status_n == 101 {
                    u.keepalive = false;

                    if !r.headers_in.borrow().upgrade.is_empty() {
                        u.upgrade = true;
                    }
                }

                u.pos = st.pos;

                return Ok(true);
            }

            if rc == NGX_AGAIN {
                return Ok(false);
            }

            // rc == NGX_HTTP_PARSE_INVALID_HEADER
            debug_assert_eq!(rc, NGX_HTTP_PARSE_INVALID_HEADER);

            let pr = &st.pr;

            let end = pr.header_end.min(u.buf.len());
            let start = pr.header_name_start.min(end);
            let ch = u.buf.get(end).copied().unwrap_or(0);

            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid header: \"{}\\x{:02x}...\"", ngx_core::string::B(&u.buf[start..end]), ch);

            return Err(crate::upstream::NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
        }
    }
}

/// The handlers of ngx_http_upstream_headers_in[] (process, not copy) of
/// the headers a response is read with, and of the ones only the first of
/// which counts (a duplicate is ignored: hash 0). Err is the failure of
/// NGX_HTTP_UPSTREAM_INVALID_HEADER.
fn upstream_process_header_line(r: &R, u: &mut UpstreamResponse, h: &crate::request::Header) -> Result<(), u32> {
    let invalid = crate::upstream::NGX_HTTP_UPSTREAM_FT_INVALID_HEADER;

    match h.lowcase_key.as_slice() {
        b"content-length" => {
            // ngx_http_upstream_process_content_length
            if let Some(prev) = &u.content_length {
                ngx_core::ngx_log_error!(
                    ngx_core::log::NGX_LOG_ERR,
                    r.connection.log,
                    None,
                    "upstream sent duplicate header line: \"{}: {}\", previous value: \"{}: {}\"",
                    ngx_core::string::B(&h.key),
                    ngx_core::string::B(&h.value.borrow()),
                    ngx_core::string::B(&prev.key),
                    ngx_core::string::B(&prev.value.borrow())
                );
                return Err(invalid);
            }

            if u.transfer_encoding.is_some() {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent \"Content-Length\" and \"Transfer-Encoding\" headers at the same time");
                return Err(invalid);
            }

            u.content_length = Some(h.clone());
            u.content_length_n = atoof(&h.value.borrow());

            if u.content_length_n == NGX_ERROR {
                ngx_core::ngx_log_error!(
                    ngx_core::log::NGX_LOG_ERR,
                    r.connection.log,
                    None,
                    "upstream sent invalid \"Content-Length\" header: \"{}: {}\"",
                    ngx_core::string::B(&h.key),
                    ngx_core::string::B(&h.value.borrow())
                );
                return Err(invalid);
            }
        }

        b"transfer-encoding" => {
            // ngx_http_upstream_process_transfer_encoding
            if let Some(prev) = &u.transfer_encoding {
                ngx_core::ngx_log_error!(
                    ngx_core::log::NGX_LOG_ERR,
                    r.connection.log,
                    None,
                    "upstream sent duplicate header line: \"{}: {}\", previous value: \"{}: {}\"",
                    ngx_core::string::B(&h.key),
                    ngx_core::string::B(&h.value.borrow()),
                    ngx_core::string::B(&prev.key),
                    ngx_core::string::B(&prev.value.borrow())
                );
                return Err(invalid);
            }

            if u.content_length.is_some() {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent \"Content-Length\" and \"Transfer-Encoding\" headers at the same time");
                return Err(invalid);
            }

            u.transfer_encoding = Some(h.clone());

            let v = h.value.borrow();

            if v.len() == 7 && v.eq_ignore_ascii_case(b"chunked") {
                u.chunked = true;
            } else {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent unknown \"Transfer-Encoding\": \"{}\"", ngx_core::string::B(&v));
                return Err(invalid);
            }
        }

        b"connection" => {
            // ngx_http_upstream_process_connection
            if ngx_core::string::strcasestr(&h.value.borrow(), b"close").is_some() {
                u.connection_close = true;
            }
        }

        b"status" | b"content-type" | b"date" | b"last-modified" | b"etag" | b"server" | b"location" | b"refresh" | b"expires" | b"x-accel-expires" | b"x-accel-redirect"
        | b"x-accel-limit-rate" => {
            // ngx_http_upstream_process_header_line and the like: the
            // first one, a duplicate is ignored
            let prev = u.headers.iter().find(|p| !Rc::ptr_eq(p, h) && p.hash.get() != 0 && p.lowcase_key == h.lowcase_key).cloned();

            if let Some(prev) = prev {
                ngx_core::ngx_log_error!(
                    ngx_core::log::NGX_LOG_WARN,
                    r.connection.log,
                    None,
                    "upstream sent duplicate header line: \"{}: {}\", previous value: \"{}: {}\", ignored",
                    ngx_core::string::B(&h.key),
                    ngx_core::string::B(&h.value.borrow()),
                    ngx_core::string::B(&prev.key),
                    ngx_core::string::B(&prev.value.borrow())
                );
                h.hash.set(0);
                return Ok(());
            }

            if h.lowcase_key == b"server" {
                u.server = true;
            } else if h.lowcase_key == b"date" {
                u.date = true;
            }

            // the cache handlers: ngx_http_upstream_process_expires,
            // _accel_expires, _last_modified, and the etag
            crate::upstream_cache::process_header_line(r, &mut u.cache, &h.lowcase_key, &h.value.borrow());
        }

        b"set-cookie" | b"cache-control" | b"vary" => {
            // ngx_http_upstream_process_set_cookie, _cache_control, _vary
            crate::upstream_cache::process_header_line(r, &mut u.cache, &h.lowcase_key, &h.value.borrow());
        }

        _ => {}
    }

    Ok(())
}

/// ngx_atoof: a non-negative decimal number, NGX_ERROR otherwise.
fn atoof(v: &[u8]) -> i64 {
    if v.is_empty() {
        return NGX_ERROR;
    }

    let mut n: i64 = 0;

    for &c in v {
        if !c.is_ascii_digit() {
            return NGX_ERROR;
        }

        let d = (c - b'0') as i64;

        if n > (i64::MAX - d) / 10 {
            return NGX_ERROR;
        }

        n = n * 10 + d;
    }

    n
}

/// ngx_http_upstream_check_broken_connection, as the Linux build runs it
/// (epoll with EPOLLRDHUP), on a duplicate of the client socket: its
/// readiness is its own, so the request's reading of the body and of
/// pipelined requests is not disturbed. An HTTP/2 or HTTP/3 stream is not
/// checked.
struct ClientWatch {
    afd: Option<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
}

impl ClientWatch {
    fn new(r: &R) -> ClientWatch {
        use std::os::fd::FromRawFd;

        if r.stream.borrow().is_some() || r.http_version.get() >= crate::NGX_HTTP_VERSION_20 {
            return ClientWatch { afd: None };
        }

        // SAFETY: dup() of the connection's open socket; the duplicate is
        // owned (and closed) by the OwnedFd.
        let dup = unsafe { libc::dup(r.connection.fd.get()) };

        if dup < 0 {
            return ClientWatch { afd: None };
        }

        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup) };

        ClientWatch { afd: tokio::io::unix::AsyncFd::with_interest(owned, tokio::io::Interest::READABLE).ok() }
    }

    /// Resolves with the pending socket error (0 if none) when the client
    /// closes the connection; data it sends is left to be read.
    async fn closed(&self) -> i32 {
        use std::os::fd::AsRawFd;

        let afd = match &self.afd {
            Some(a) => a,
            None => return std::future::pending().await,
        };

        loop {
            let mut guard = match afd.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            // EPOLLRDHUP: ev->pending_eof
            if guard.ready().is_read_closed() {
                break;
            }

            let mut b = [0u8; 1];
            // SAFETY: a one byte peek into b on the duplicate socket.
            let n = unsafe { libc::recv(afd.as_raw_fd(), b.as_mut_ptr() as *mut libc::c_void, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };

            if n == 0 {
                break;
            }

            if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock {
                break;
            }

            guard.clear_ready();
        }

        // getsockopt(SO_ERROR): the pending error, if any
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

        // SAFETY: err and len are valid for getsockopt to write an int into.
        unsafe {
            libc::getsockopt(afd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut libc::c_int as *mut libc::c_void, &mut len);
        }

        err
    }
}

/// The client's close if watched, else never.
async fn client_closed(watch: Option<&ClientWatch>) -> i32 {
    match watch {
        Some(w) => w.closed().await,
        None => std::future::pending().await,
    }
}

/// The end of ngx_http_upstream_check_broken_connection when the client
/// closed the connection of a request that is not cached: the upstream
/// connection is closed too, and the request is finalized with 499.
fn client_closed_request(r: &R, err: i32) -> i64 {
    r.connection.error.set(true);

    ngx_core::ngx_log_error!(
        ngx_core::log::NGX_LOG_INFO,
        r.connection.log,
        if err != 0 { Some(err) } else { None },
        "epoll_wait() reported that client prematurely closed connection, so upstream connection is closed too"
    );

    crate::NGX_HTTP_CLIENT_CLOSED_REQUEST
}

/// What send_response_body needs of the upstream configuration.
struct BodyParams {
    /// u->buffering
    buffering: bool,
    /// p->limit_rate (proxy_limit_rate), buffered only
    limit_rate: usize,
    /// the body goes to the client (not r->header_only)
    downstream: bool,
    /// the response is read in full for the cache or proxy_store
    /// (p->cacheable)
    capture: bool,
    /// the body is kept for proxy_store
    store: bool,
    read_timeout: u64,
    pass_trailers: bool,
    /// proxy_buffer_size, the most of trailers kept
    buffer_size: usize,
}

/// The end of a response body (ngx_http_upstream_finalize_request).
struct BodyResult {
    /// the rc to finalize the request with
    rc: i64,
    /// u->keepalive
    keepalive: bool,
    /// the body was read in full
    complete: bool,
    /// the body, when kept
    data: Vec<u8>,
}

/// ngx_http_upstream_send_response after the header is sent: the body read
/// with the proxy's input filters (ngx_http_proxy_input_filter_init, then
/// the copy or chunked filter of the event pipe, or their non-buffered
/// versions) and passed to the client as it arrives, with
/// proxy_limit_rate on the reading when buffered; then what
/// ngx_http_upstream_finalize_request sends: the trailers and the last
/// buffer, or, for a body the upstream cut short, a flush and no keepalive.
async fn send_response_body(r: &R, sock: &mut UpstreamSock, u: &mut UpstreamResponse, head: bool, p: BodyParams, watch: Option<&ClientWatch>, hide: &[Vec<u8>], cache: &mut Option<crate::upstream_cache::CacheWriter>) -> BodyResult {
    let log = r.connection.log.clone();
    let action = log.action();

    log.set_action(Some("reading upstream"));

    let res = read_body(r, sock, u, head, &p, watch, hide, cache).await;

    log.set_action(action);

    res
}

async fn read_body(r: &R, sock: &mut UpstreamSock, u: &mut UpstreamResponse, head: bool, p: &BodyParams, watch: Option<&ClientWatch>, hide: &[Vec<u8>], cache: &mut Option<crate::upstream_cache::CacheWriter>) -> BodyResult {
    use ngx_core::buf::{Buf, Chain};

    if !p.buffering {
        // non-buffered responses are not rate limited
        r.limit_rate.set(0);
        r.limit_rate_set.set(true);
    }

    let mut keepalive = u.keepalive;

    // ngx_http_proxy_input_filter_init: u->length and p->length

    ngx_core::ngx_log_debug!(
        ngx_core::log::NGX_LOG_DEBUG_HTTP,
        r.connection.log,
        "http proxy filter init s:{} h:{} c:{} l:{}",
        u.status_n,
        head as i32,
        u.chunked as i32,
        u.content_length_n
    );

    let mut length: i64 = if u.status_n == crate::NGX_HTTP_NO_CONTENT as i64 || u.status_n == crate::NGX_HTTP_NOT_MODIFIED as i64 || head {
        // 1xx, 204, and 304 and replies to HEAD requests
        keepalive = !u.connection_close;
        0
    } else if u.chunked {
        1
    } else if u.content_length_n == 0 {
        // empty body: special case as filter won't be called
        keepalive = !u.connection_close;
        0
    } else {
        // content length or connection close
        u.content_length_n
    };

    let mut chunked = crate::parse::ChunkedState::default();

    // ctx->trailers: the trailer part being read, with its parse state
    let mut trailers: Option<(Vec<u8>, crate::parse::ParseRequest, usize)> = None;

    let mut downstream = p.downstream;
    let mut upstream_done = false;
    let mut eof = false;
    let mut timedout = false;
    let mut error = false;

    let mut captured: Vec<u8> = Vec::new();

    // the pre-read part of the body, then what is read
    let mut data: Vec<u8> = u.buf[u.pos..].to_vec();
    let preread = !data.is_empty();

    if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
        st.response_length += data.len() as i64;
    }

    if !p.buffering && !preread && downstream {
        // ngx_http_send_special(r, NGX_HTTP_FLUSH): the header goes now
        let mut b = Buf::special();
        b.flush = true;
        let mut chain = Chain::new();
        chain.push_back(b);

        if crate::core_rt::output_filter(r, chain).await == NGX_ERROR {
            return BodyResult { rc: NGX_ERROR, keepalive: false, complete: false, data: captured };
        }
    }

    // p->read_length and p->start_sec of proxy_limit_rate
    let start_sec = ngx_core::times::cached().sec;
    let mut read_length: i64 = 0;

    let mut chunk = vec![0u8; 16384];
    let mut delay: u64 = 0;

    if p.limit_rate > 0 && preread {
        read_length += data.len() as i64;
        delay = data.len() as u64 * 1000 / p.limit_rate as u64;
    }

    loop {
        // u->input_filter / p->input_filter

        let mut out: Vec<u8> = Vec::new();

        if !data.is_empty() && !upstream_done {
            if !u.chunked {
                // ngx_http_proxy_copy_filter,
                // ngx_http_proxy_non_buffered_copy_filter
                if length == 0 {
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
                    keepalive = false;
                    upstream_done = true;
                } else if length == -1 {
                    out.extend_from_slice(&data);
                } else if data.len() as i64 > length {
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
                    out.extend_from_slice(&data[..length as usize]);
                    length = 0;
                    upstream_done = true;
                } else {
                    out.extend_from_slice(&data);
                    length -= data.len() as i64;

                    if length == 0 {
                        keepalive = !u.connection_close;
                    }
                }
            } else {
                // ngx_http_proxy_chunked_filter,
                // ngx_http_proxy_non_buffered_chunked_filter
                let mut pos = 0usize;

                if length == 0 {
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_WARN, r.connection.log, None, "upstream sent data after final chunk");
                    keepalive = false;
                    upstream_done = true;
                } else if trailers.is_some() {
                    match process_trailer(r, &mut trailers, &data, &mut pos, p.buffer_size, &mut u.trailers) {
                        NGX_OK => {
                            // a whole response has been parsed successfully
                            length = 0;
                            keepalive = !u.connection_close;

                            if pos != data.len() {
                                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_WARN, r.connection.log, None, "upstream sent data after trailers");
                                keepalive = false;
                            }
                        }
                        NGX_AGAIN => {}
                        _ => error = true,
                    }
                } else {
                    loop {
                        let rc = crate::parse::parse_chunked(&mut chunked, &data, &mut pos, p.pass_trailers);

                        if rc == NGX_OK {
                            // a chunk has been parsed successfully
                            let take = (chunked.size as usize).min(data.len() - pos);
                            out.extend_from_slice(&data[pos..pos + take]);
                            pos += take;
                            chunked.size -= take as i64;
                            continue;
                        }

                        if rc == NGX_DONE {
                            if p.pass_trailers {
                                match process_trailer(r, &mut trailers, &data, &mut pos, p.buffer_size, &mut u.trailers) {
                                    NGX_OK => {}
                                    NGX_AGAIN => {
                                        length = 1;
                                        break;
                                    }
                                    _ => {
                                        error = true;
                                        break;
                                    }
                                }
                            }

                            // a whole response has been parsed successfully
                            length = 0;
                            keepalive = !u.connection_close;

                            if pos != data.len() {
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

                        error = true;
                        break;
                    }
                }
            }
        }

        data.clear();

        if !out.is_empty() {
            if p.store {
                captured.extend_from_slice(&out);
            }

            // ngx_event_pipe_write_chain_to_temp_file()
            if let Some(w) = cache.as_mut() {
                w.write(r, &out);
            }

            if downstream {
                let mut b = Buf::from_vec(out);
                b.memory = true;
                b.flush = !p.buffering;
                let mut chain = Chain::new();
                chain.push_back(b);

                if crate::core_rt::output_filter(r, chain).await == NGX_ERROR {
                    // p->downstream_error: the upstream is read to the end
                    // only for the cache or proxy_store
                    if !p.capture {
                        return BodyResult { rc: NGX_ERROR, keepalive: false, complete: false, data: captured };
                    }

                    downstream = false;
                }
            }
        }

        if error {
            // NGX_ERROR of the filter: ngx_http_upstream_finalize_request
            // with 502 (buffered) or NGX_ERROR, after the header
            return BodyResult { rc: finalize_after_header(r, downstream).await, keepalive: false, complete: false, data: captured };
        }

        if length == 0 {
            upstream_done = true;
        }

        if upstream_done || (eof && length == -1) {
            // ngx_http_upstream_finalize_request(r, u, 0): the trailers
            // (ngx_http_upstream_process_trailers) and the last buffer
            if p.pass_trailers {
                let mut ho = r.headers_out.borrow_mut();

                for h in u.trailers.iter() {
                    if hide.iter().any(|x| x == &h.lowcase_key) {
                        continue;
                    }

                    ho.trailers.push(h.clone());
                }
            }

            let mut rc = NGX_OK;

            if downstream {
                let mut b = Buf::special();
                b.last_buf = r.is_main();
                b.last_in_chain = true;
                let mut chain = Chain::new();
                chain.push_back(b);

                if crate::core_rt::output_filter(r, chain).await == NGX_ERROR {
                    rc = NGX_ERROR;
                }
            }

            return BodyResult { rc, keepalive: keepalive && rc != NGX_ERROR, complete: true, data: captured };
        }

        if eof || timedout {
            if eof {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection");
            }

            return BodyResult { rc: finalize_after_header(r, downstream).await, keepalive: false, complete: false, data: captured };
        }

        // p->limit_rate: the read is delayed by the time the last one
        // took at the rate, and limited to what the rate allows so far
        if delay > 0 {
            if !sleep_or_client_closed(delay, watch).await {
                return BodyResult { rc: client_closed_request(r, 0), keepalive: false, complete: false, data: captured };
            }

            delay = 0;
        }

        let mut limit = chunk.len();

        if p.limit_rate > 0 {
            let now = ngx_core::times::cached().sec;
            let allowed = p.limit_rate as i64 * (now - start_sec + 1) - read_length;

            if allowed <= 0 {
                delay = (-allowed * 1000 / p.limit_rate as i64 + 1) as u64;
                continue;
            }

            limit = limit.min(allowed as usize);
        }

        let res = {
            let read = tokio::time::timeout(std::time::Duration::from_millis(p.read_timeout), sock.read(&mut chunk[..limit]));

            tokio::select! {
                res = read => res,
                err = client_closed(watch) => {
                    return BodyResult { rc: client_closed_request(r, err), keepalive: false, complete: false, data: captured };
                }
            }
        };

        match res {
            Err(_) => {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
                timedout = true;
            }
            Ok(Err(e)) => {
                if let Some(errno) = e.raw_os_error() {
                    ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, Some(errno), "recv() failed");
                }
                return BodyResult { rc: finalize_after_header(r, downstream).await, keepalive: false, complete: false, data: captured };
            }
            Ok(Ok(0)) => eof = true,
            Ok(Ok(n)) => {
                if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
                    st.bytes_received += n as i64;
                    st.response_length += n as i64;
                }

                if p.limit_rate > 0 {
                    read_length += n as i64;
                    delay = n as u64 * 1000 / p.limit_rate as u64;
                }

                data.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

/// ngx_http_upstream_finalize_request with an error after the header was
/// sent: rc becomes NGX_ERROR with a flush, no last buffer, and the client
/// connection is not kept alive.
async fn finalize_after_header(r: &R, downstream: bool) -> i64 {
    r.keepalive.set(false);

    if downstream {
        let mut b = ngx_core::buf::Buf::special();
        b.flush = true;
        let mut chain = ngx_core::buf::Chain::new();
        chain.push_back(b);

        if crate::core_rt::output_filter(r, chain).await == NGX_ERROR {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// A proxy_limit_rate delay, false if the client closed the connection
/// (ngx_http_upstream_check_broken_connection) meanwhile.
async fn sleep_or_client_closed(delay: u64, watch: Option<&ClientWatch>) -> bool {
    let sleep = tokio::time::sleep(std::time::Duration::from_millis(delay));

    tokio::select! {
        _ = sleep => true,
        _ = client_closed(watch) => false,
    }
}

/// ngx_http_proxy_process_trailer: the trailer header lines after the last
/// chunk, kept in ctx->trailers (at most proxy_buffer_size of them).
/// NGX_OK with `pos` past them, NGX_AGAIN for more, NGX_ERROR.
fn process_trailer(
    r: &R,
    state: &mut Option<(Vec<u8>, crate::parse::ParseRequest, usize)>,
    buf: &[u8],
    pos: &mut usize,
    buffer_size: usize,
    trailers: &mut Vec<crate::request::Header>,
) -> i64 {
    use crate::parse::{NGX_HTTP_PARSE_HEADER_DONE, ParseRequest};

    let (b, pr, bpos) = state.get_or_insert_with(|| (Vec::with_capacity(buffer_size), ParseRequest { upstream: true, ..Default::default() }, 0));

    let len = (buf.len() - *pos).min(buffer_size - b.len());

    b.extend_from_slice(&buf[*pos..*pos + len]);

    loop {
        let rc = crate::parse::parse_header_line(pr, b, bpos, true);

        if rc == NGX_OK {
            // a header line has been parsed successfully

            let key = b[pr.header_name_start..pr.header_name_end].to_vec();
            let value = b[pr.header_start..pr.header_end].to_vec();

            let lowcase = if key.len() == pr.lowcase_index {
                pr.lowcase_header[..key.len()].to_vec()
            } else {
                key.to_ascii_lowercase()
            };

            ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy trailer: \"{}: {}\"", ngx_core::string::B(&key), ngx_core::string::B(&value));

            trailers.push(crate::request::TableElt::with_hash(&key, &value, pr.header_hash, lowcase));

            continue;
        }

        if rc == NGX_HTTP_PARSE_HEADER_DONE {
            // a whole header has been parsed successfully

            *pos += len - (b.len() - *bpos);

            ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy trailer done");

            return NGX_OK;
        }

        if rc == NGX_AGAIN {
            *pos += len;

            if b.len() == buffer_size {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent too big trailers");
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        // rc == NGX_HTTP_PARSE_INVALID_HEADER

        let end = pr.header_end.min(b.len());
        let start = pr.header_name_start.min(end);
        let ch = b.get(end).copied().unwrap_or(0);

        ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid trailer: \"{}\\x{:02x}...\"", ngx_core::string::B(&b[start..end]), ch);

        return NGX_ERROR;
    }
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
    // ngx_http_upstream_finalize_request: a 502 or 504 of the upstream is
    // cached for its proxy_cache_valid time
    crate::upstream_cache::finalize(r, status, None);

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

    // ngx_http_upstream_process_upgraded: the data of each side is passed
    // to the other; the tunnel is done (and both connections closed) when
    // either side's end is read and what it sent was passed on, or on an
    // error; proxy_read_timeout without activity: "upstream timed out"
    let read_timeout = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index()).borrow().read_timeout.get_or(60000);
    let activity = Rc::new(std::cell::Cell::new(ngx_core::times::current_msec()));

    let client_to_up = {
        let client = client.clone();
        let activity = activity.clone();
        async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match client.recv(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        activity.set(ngx_core::times::current_msec());
                        if up_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    };

    let up_to_client = {
        let client = client.clone();
        let activity = activity.clone();
        async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match up_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        activity.set(ngx_core::times::current_msec());
                        if client.send_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    };

    let timer = async {
        loop {
            let idle = ngx_core::times::current_msec().saturating_sub(activity.get());

            if idle >= read_timeout {
                return;
            }

            tokio::time::sleep(std::time::Duration::from_millis(read_timeout - idle)).await;
        }
    };

    let log = r.connection.log.clone();
    let action = log.action();
    log.set_action(Some("proxying upgraded connection"));

    tokio::select! {
        _ = client_to_up => {}
        _ = up_to_client => {}
        _ = timer => {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
        }
    }

    log.set_action(action);

    NGX_OK
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
        cmd_fn!("proxy_set_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, proxy_set_header_handler),
        // Additional proxy directives that tests need
        cmd_fn!("proxy_temp_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::Loc, |cf: &mut Conf, cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let mut slot = std::mem::take(&mut cell.borrow_mut().temp_path);
            let rc = set_path(cf, cmd, &mut slot);
            cell.borrow_mut().temp_path = slot;
            rc
        }),
        ngx_core::cmd!("proxy_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, buffer_size, set_size),
        cmd_fn!("proxy_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_busy_buffers_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_max_temp_file_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_next_upstream", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, proxy_next_upstream_handler),
        cmd_fn!("proxy_next_upstream_tries", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_next_upstream_tries_handler),
        ngx_core::cmd!("proxy_next_upstream_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, next_upstream_timeout, set_msec),
        ngx_core::cmd!("proxy_pass_request_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, pass_request_headers, set_flag),
        ngx_core::cmd!("proxy_pass_request_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, pass_request_body, set_flag),
        cmd_fn!("proxy_method", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_method_handler),
        cmd_fn!("proxy_http_version", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, cmd, conf: Option<Rc<dyn Any>>| {
            // ngx_conf_set_enum_slot with ngx_http_proxy_http_version
            // ("2" is ngx_http_proxy_v2_module, not ported)
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let mut c = cell.borrow_mut();
            set_enum(cf, cmd, &mut c.http_version, &[("1.0", crate::NGX_HTTP_VERSION_10), ("1.1", crate::NGX_HTTP_VERSION_11)])
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
        cmd_fn!("proxy_ignore_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::ignore_headers_slot::<NgxHttpProxyLocConf>),
        ngx_core::cmd!("proxy_pass_trailers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, pass_trailers, set_flag),
        ngx_core::cmd!("proxy_intercept_errors", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, intercept_errors, set_flag),
        ngx_core::cmd!("proxy_ignore_client_abort", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, ignore_client_abort, set_flag),
        cmd_fn!("proxy_store", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_store_handler),
        cmd_fn!("proxy_store_access", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_limit_rate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_limit_rate_handler),
        ngx_core::cmd!("proxy_force_ranges", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, force_ranges, set_flag),
        ngx_core::cmd!("proxy_headers_hash_max_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, headers_hash_max_size, set_num),
        ngx_core::cmd!("proxy_headers_hash_bucket_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, headers_hash_bucket_size, set_num),
        cmd_fn!("proxy_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_cache_handler),
        cmd_fn!("proxy_cache_key", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_key_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_path", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, |cf, cmd, conf| crate::upstream_cache::cache_path_slot(cf, cmd, conf, "ngx_http_proxy_module")),
        cmd_fn!("proxy_cache_bypass", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::cache_bypass_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_no_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::no_cache_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_valid", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::cache_valid_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_min_uses", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_min_uses_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_max_range_offset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_max_range_offset_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_use_stale", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, |cf: &mut Conf, cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let mut c = cell.borrow_mut();
            crate::upstream_cache::cache_use_stale_slot(cf, cmd, &mut c.cache, PROXY_NEXT_UPSTREAM_MASKS)
        }),
        cmd_fn!("proxy_cache_methods", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::cache_methods_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_lock", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, crate::upstream_cache::cache_lock_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_lock_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_lock_timeout_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_lock_age", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, crate::upstream_cache::cache_lock_age_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_revalidate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, crate::upstream_cache::cache_revalidate_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_convert_head", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, crate::upstream_cache::cache_convert_head_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_background_update", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, crate::upstream_cache::cache_background_update_slot::<NgxHttpProxyLocConf>),
        cmd_fn!("proxy_cache_purge", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
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
        create_main_conf: Some(crate::upstream_cache::create_main_conf),
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
        // ngx_http_proxy_create_loc_conf: unset until merged
        let c = NgxHttpProxyLocConf::default();
        assert!(!c.http_version.is_set());
        assert!(!c.headers_source.is_set());
        assert!(c.headers.is_none() && c.headers_cache.is_none());
        assert!(c.proxy_values.is_none() && c.upstream.is_none());
    }

    fn vars_of(url: &[u8]) -> ProxyVars {
        let (add, port) = if url.starts_with(b"https://") { (8, 443) } else { (7, 80) };
        let mut u = ngx_core::inet::Url::new(&url[add..]);
        u.default_port = port;
        u.uri_part = true;
        u.no_resolve = true;
        ngx_core::inet::parse_url(&mut u).unwrap();
        let mut v = ProxyVars { schema: url[..add].to_vec(), key_start: url[..add].to_vec(), ..Default::default() };
        set_vars(&u, &mut v, url);
        v
    }

    #[test]
    fn test_set_vars() {
        // ngx_http_proxy_set_vars: the port only when not the default
        let v = vars_of(b"http://127.0.0.1:8080/x/");
        assert_eq!(v.host_header, b"127.0.0.1:8080");
        assert_eq!(v.port, b"8080");
        assert_eq!(v.uri, b"/x/");
        assert_eq!(v.key_start, b"http://127.0.0.1:8080");

        let v = vars_of(b"http://backend");
        assert_eq!(v.host_header, b"backend");
        assert_eq!(v.port, b"80");
        assert_eq!(v.uri, b"");

        let v = vars_of(b"https://example.com:443/");
        assert_eq!(v.host_header, b"example.com");
        assert_eq!(v.port, b"443");

        let v = vars_of(b"http://[::1]:8081");
        assert_eq!(v.host_header, b"[::1]:8081");
        assert_eq!(v.key_start, b"http://[::1]:8081");

        let v = vars_of(b"http://unix:/tmp/s.sock:/p");
        assert_eq!(v.host_header, b"localhost");
        assert_eq!(v.port, b"");
        assert_eq!(v.uri, b"/p");
        assert_eq!(v.key_start, b"http://unix:/tmp/s.sock:");
    }

    #[test]
    fn test_atoof() {
        assert_eq!(atoof(b"0"), 0);
        assert_eq!(atoof(b"12345"), 12345);
        assert_eq!(atoof(b""), NGX_ERROR);
        assert_eq!(atoof(b"12a"), NGX_ERROR);
        assert_eq!(atoof(b" 1"), NGX_ERROR);
        assert_eq!(atoof(b"99999999999999999999"), NGX_ERROR);
    }

    fn chain_of(parts: &[&[u8]], last: bool) -> ngx_core::buf::Chain {
        let mut c = ngx_core::buf::Chain::new();
        for p in parts {
            c.push_back(ngx_core::buf::Buf::from_vec(p.to_vec()));
        }
        if last {
            if let Some(b) = c.back_mut() {
                b.last_buf = true;
            } else {
                let mut b = ngx_core::buf::Buf::special();
                b.last_buf = true;
                c.push_back(b);
            }
        }
        c
    }

    #[test]
    fn test_body_output_filter() {
        // ngx_http_proxy_body_output_filter: one chunk for the buffers
        let mut out = Vec::new();
        body_output_filter(&mut out, &chain_of(&[b"abc", b"de"], false), true);
        assert_eq!(out, b"5\r\nabcde\r\n");

        let mut out = Vec::new();
        body_output_filter(&mut out, &chain_of(&[b"0123456789abcdef"], true), true);
        assert_eq!(out, b"10\r\n0123456789abcdef\r\n0\r\n\r\n");

        let mut out = Vec::new();
        body_output_filter(&mut out, &chain_of(&[], true), true);
        assert_eq!(out, b"0\r\n\r\n");

        let mut out = Vec::new();
        body_output_filter(&mut out, &chain_of(&[b"abc"], true), false);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn test_same_headers_source() {
        let a: Val<Option<Rc<Vec<(Vec<u8>, Vec<u8>)>>>> = Val::set(Some(Rc::new(vec![(b"X".to_vec(), b"1".to_vec())])));
        let b = a.clone();
        let c: Val<Option<Rc<Vec<(Vec<u8>, Vec<u8>)>>>> = Val::set(Some(Rc::new(vec![(b"X".to_vec(), b"1".to_vec())])));
        let null: Val<Option<Rc<Vec<(Vec<u8>, Vec<u8>)>>>> = Val::set(None);
        let unset: Val<Option<Rc<Vec<(Vec<u8>, Vec<u8>)>>>> = Val::unset();

        assert!(same_headers_source(&a, &b));
        assert!(!same_headers_source(&a, &c));
        assert!(same_headers_source(&null, &null.clone()));
        assert!(!same_headers_source(&null, &unset));
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
    if args[1] != b"off" && cell.borrow().cache.cache.get_or(false) {
        return Err(msg("is incompatible with \"proxy_cache\""));
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

/// ngx_http_proxy_cache: "proxy_cache zone | off"
fn proxy_cache_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());

    if cell.borrow().cache.cache.is_set() {
        return Err(msg("is duplicate"));
    }

    if cf.args[1] == b"off" {
        cell.borrow_mut().cache.cache = Val::set(false);
        return Ok(());
    }

    if matches!(cell.borrow().store, Some(ProxyStore::On) | Some(ProxyStore::Path(_))) {
        return Err(msg("is incompatible with \"proxy_store\""));
    }

    let mut ucf = std::mem::take(&mut cell.borrow_mut().cache);
    let rc = crate::upstream_cache::cache_slot(cf, &mut ucf, "ngx_http_proxy_module");
    cell.borrow_mut().cache = ucf;
    rc
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
/// rules (u->rewrite_redirect, set when plcf->redirects is not NULL).
/// Called after upstream headers have been parsed into ho.
pub fn rewrite_redirect_headers(r: &R) {
    let plcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let effective: Vec<CookieRewrite> = match &plcf.borrow().redirects {
        Some(redirects) => redirects.clone(),
        None => return,
    };

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
                if target.len() < pattern.len() { continue; }
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
