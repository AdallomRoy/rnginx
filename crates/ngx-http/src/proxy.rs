//! ngx_http_proxy_module - HTTP proxy with upstream framework

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::cmd_fn;
use ngx_core::conf::{NGX_CONF_TAKE1, NGX_CONF_TAKE2, NGX_CONF_TAKE12, NGX_CONF_TAKE123, NGX_CONF_TAKE1234, NGX_CONF_1MORE, NGX_CONF_2MORE};

pub use crate::upstream::UpstreamSock;

use std::cell::RefCell;

use ngx_core::event_openssl::{
    ngx_ssl_certificate, ngx_ssl_ciphers, ngx_ssl_client_session_cache, ngx_ssl_conf_commands, ngx_ssl_create, ngx_ssl_crl, ngx_ssl_read_password_file,
    ngx_ssl_trusted_certificate, NgxSsl, NGX_SSL_DEFAULT_PROTOCOLS,
};

use crate::core::*;
use crate::request::*;
use crate::variables::VarDef;
use crate::get_loc_conf;
use crate::{NGX_HTTP_MAIN_CONF, NGX_HTTP_SRV_CONF, NGX_HTTP_LOC_CONF, NGX_HTTP_LIF_CONF, NGX_HTTP_LMT_CONF, HttpModuleDef, http_module_def};

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
pub struct ProxyCtx {
    /// ctx->vars: those of the location, or of a proxy_pass with variables
    pub vars: Rc<ProxyVars>,
    pub internal_body_length: i64,
    /// the request sent is a HEAD one
    pub head: bool,
    pub internal_chunked: bool,
    /// ngx_http_proxy_body_output_filter: the header was sent
    pub header_sent: bool,
}

impl ProxyCtx {
    /// The context of a request with these vars.
    pub fn new(vars: Rc<ProxyVars>) -> ProxyCtx {
        ProxyCtx { vars, internal_body_length: 0, head: false, internal_chunked: false, header_sent: false }
    }
}

/// Empty vars, shared: those of the context before ngx_http_proxy_eval
/// sets them (ngx_pcalloc).
pub fn no_vars() -> Rc<ProxyVars> {
    thread_local! {
        static NONE: Rc<ProxyVars> = Rc::new(ProxyVars::default());
    }

    NONE.with(|v| v.clone())
}

/// Proxy location configuration
pub struct NgxHttpProxyLocConf {
    /// plcf->url: the URL of proxy_pass without variables
    pub url: Vec<u8>,
    /// plcf->location
    pub location: Vec<u8>,
    /// plcf->vars (shared with the contexts of the requests)
    pub vars: Rc<ProxyVars>,
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
    /// upstream.local: proxy_bind (unset, NULL for "off", or the address)
    pub local: Val<Option<Rc<crate::upstream_rt::UpstreamLocal>>>,
    /// upstream.store (unset, 0 or 1) and store_values: proxy_store
    pub store: Val<bool>,
    pub store_values: Option<Rc<Vec<crate::script::Part>>>,
    pub store_access: Val<u32>,
    pub send_timeout: Val<u64>,
    pub send_lowat: Val<usize>,
    pub socket_keepalive: Val<bool>,
    pub socket_rcvbuf: Val<usize>,
    pub socket_sndbuf: Val<usize>,
    pub bufs: Bufs,
    pub busy_buffers_size_conf: Val<usize>,
    pub busy_buffers_size: usize,
    pub max_temp_file_size_conf: Val<usize>,
    pub max_temp_file_size: usize,
    pub temp_file_write_size_conf: Val<usize>,
    pub temp_file_write_size: usize,
    /// upstream.hide_headers_hash once built
    pub hide_headers_hash: Option<Rc<ngx_core::hash::Hash<()>>>,
    /// plcf->upstream as a request uses it, once merged
    pub upstream_conf: Option<Rc<crate::upstream_rt::UpstreamConf>>,
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
    /// upstream.hide_headers and pass_headers: proxy_hide_header and
    /// proxy_pass_header (NGX_CONF_UNSET_PTR or the list)
    pub hide_headers: Val<Rc<Vec<Vec<u8>>>>,
    pub pass_headers: Val<Rc<Vec<Vec<u8>>>>,
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
            vars: Rc::new(ProxyVars::default()),
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
            local: Val::unset(),
            store: Val::unset(),
            store_values: None,
            store_access: Val::unset(),
            send_timeout: Val::unset(),
            send_lowat: Val::unset(),
            socket_keepalive: Val::unset(),
            socket_rcvbuf: Val::unset(),
            socket_sndbuf: Val::unset(),
            bufs: Bufs::default(),
            busy_buffers_size_conf: Val::unset(),
            busy_buffers_size: 0,
            max_temp_file_size_conf: Val::unset(),
            max_temp_file_size: 0,
            temp_file_write_size_conf: Val::unset(),
            temp_file_write_size: 0,
            hide_headers_hash: None,
            upstream_conf: None,
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
            hide_headers: Val::unset(),
            pass_headers: Val::unset(),
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
    if c.store.get_or(false) {
        c.cache.cache = Val::set(false);
    }
    if c.cache.cache.get_or(false) {
        c.store = Val::set(false);
    }
    if !c.store.is_set() {
        c.store.merge(&p.store, false);
        c.store_values = p.store_values.clone();
    }
    c.store_access.merge(&p.store_access, 0o600);
    crate::upstream_ssl::merge_ptr(&mut c.local, &p.local);
    c.socket_keepalive.merge(&p.socket_keepalive, false);
    c.socket_rcvbuf.merge(&p.socket_rcvbuf, 0);
    c.socket_sndbuf.merge(&p.socket_sndbuf, 0);
    c.send_timeout.merge(&p.send_timeout, 60000);
    c.send_lowat.merge(&p.send_lowat, 0);
    {
        let prev_bufs = p.bufs;
        let pagesize = ngx_core::os::pagesize();
        c.bufs.merge(&prev_bufs, 8, pagesize);
    }
    if c.bufs.num < 2 {
        return Err(cf.emerg(format_args!("there must be at least 2 \"proxy_buffers\"")));
    }
    {
        let mut size = *c.buffer_size.get();
        if size < c.bufs.size {
            size = c.bufs.size;
        }

        if !c.busy_buffers_size_conf.is_set() {
            c.busy_buffers_size_conf = p.busy_buffers_size_conf.clone();
        }
        c.busy_buffers_size = match c.busy_buffers_size_conf.as_option() {
            None => 2 * size,
            Some(&v) => v,
        };
        if c.busy_buffers_size < size {
            return Err(cf.emerg(format_args!(
                "\"proxy_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"proxy_buffer_size\" and one of the \"proxy_buffers\""
            )));
        }
        if c.busy_buffers_size > (c.bufs.num - 1) * c.bufs.size {
            return Err(cf.emerg(format_args!("\"proxy_busy_buffers_size\" must be less than the size of all \"proxy_buffers\" minus one buffer")));
        }

        if !c.temp_file_write_size_conf.is_set() {
            c.temp_file_write_size_conf = p.temp_file_write_size_conf.clone();
        }
        c.temp_file_write_size = match c.temp_file_write_size_conf.as_option() {
            None => 2 * size,
            Some(&v) => v,
        };
        if c.temp_file_write_size < size {
            return Err(cf.emerg(format_args!(
                "\"proxy_temp_file_write_size\" must be equal to or greater than the maximum of the value of \"proxy_buffer_size\" and one of the \"proxy_buffers\""
            )));
        }

        if !c.max_temp_file_size_conf.is_set() {
            c.max_temp_file_size_conf = p.max_temp_file_size_conf.clone();
        }
        c.max_temp_file_size = match c.max_temp_file_size_conf.as_option() {
            None => 1024 * 1024 * 1024,
            Some(&v) => v,
        };
        if c.max_temp_file_size != 0 && c.max_temp_file_size < size {
            return Err(cf.emerg(format_args!(
                "\"proxy_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"proxy_buffer_size\" and one of the \"proxy_buffers\""
            )));
        }
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
    {
        let (cc, pp) = (&mut *c, &mut *p);
        crate::upstream_rt::hide_headers_hash(
            cf,
            crate::upstream_rt::HideHeaders { hide: &mut cc.hide_headers, pass: &mut cc.pass_headers, hash: &mut cc.hide_headers_hash },
            crate::upstream_rt::HideHeaders { hide: &mut pp.hide_headers, pass: &mut pp.pass_headers, hash: &mut pp.hide_headers_hash },
            PROXY_HIDE_HEADERS,
            "proxy_headers_hash",
            64,
        )?;
    }

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

    c.upstream_conf = Some(Rc::new(upstream_conf(&c)));

    Ok(())
}

/// plcf->upstream, the ngx_http_upstream_conf_t of the location, as merged
fn upstream_conf(c: &NgxHttpProxyLocConf) -> crate::upstream_rt::UpstreamConf {
    let next_upstream = c.next_upstream_mask.get_or(FT_ERROR | FT_TIMEOUT);

    crate::upstream_rt::UpstreamConf {
        upstream: c.upstream.clone(),
        connect_timeout: c.connect_timeout.get_or(60000),
        send_timeout: c.send_timeout.get_or(60000),
        read_timeout: c.read_timeout.get_or(60000),
        next_upstream_timeout: c.next_upstream_timeout.get_or(0),
        send_lowat: c.send_lowat.get_or(0),
        buffer_size: c.buffer_size.get_or(PROXY_BUFFER_SIZE),
        limit_rate: c.limit_rate.as_option().cloned().flatten(),
        busy_buffers_size: c.busy_buffers_size,
        max_temp_file_size: c.max_temp_file_size,
        temp_file_write_size: c.temp_file_write_size,
        bufs: c.bufs,
        next_upstream: if next_upstream & FT_OFF != 0 { 0 } else { next_upstream },
        store_access: c.store_access.get_or(0o600),
        next_upstream_tries: c.next_upstream_tries.get_or(0),
        buffering: c.buffering.get_or(true),
        request_buffering: c.request_buffering.get_or(true),
        pass_request_headers: c.pass_request_headers.get_or(true),
        pass_request_body: c.pass_request_body.get_or(true),
        pass_trailers: c.pass_trailers.get_or(false),
        pass_early_hints: true,
        ignore_client_abort: c.ignore_client_abort.get_or(false),
        intercept_errors: c.intercept_errors.get_or(false),
        cyclic_temp_file: false,
        force_ranges: c.force_ranges.get_or(false),
        temp_path: c.temp_path.as_option().cloned(),
        hide_headers_hash: c.hide_headers_hash.clone(),
        local: c.local.as_option().cloned().flatten(),
        socket_keepalive: c.socket_keepalive.get_or(false),
        socket_rcvbuf: c.socket_rcvbuf.get_or(0),
        socket_sndbuf: c.socket_sndbuf.get_or(0),
        cache: c.cache.clone(),
        store: c.store.get_or(false),
        store_values: c.store_values.clone(),
        intercept_404: false,
        change_buffering: true,
        // plcf->upstream.preserve_output, set by ngx_http_proxy_v2_handler
        preserve_output: c.http_version.get_or(crate::NGX_HTTP_VERSION_11) == crate::NGX_HTTP_VERSION_20,
        ignore_input: false,
        ssl: c.upstream_ssl.clone(),
        module: "proxy",
    }
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
pub(crate) fn script_flushes(codes: &[crate::script::Part]) -> Vec<usize> {
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

    if ngx_ssl_create(&mut ssl, plcf.ssl_protocols, None) != NGX_OK {
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

    let mut vars = ProxyVars { schema: url[..add].to_vec(), key_start: url[..add].to_vec(), ..Default::default() };

    set_vars(&u, &mut vars, &url);

    plcf.vars = Rc::new(vars);

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

/// ngx_http_proxy_lowat_check: SO_SNDLOWAT is not supported on Linux.
fn proxy_send_lowat_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
    let mut slot = std::mem::take(&mut cell.borrow_mut().send_lowat);
    let rc = set_size(cf, cmd, &mut slot);

    // ngx_http_proxy_lowat_check without NGX_HAVE_SO_SNDLOWAT
    if rc.is_ok() {
        cf.warn(format_args!("\"proxy_send_lowat\" is not supported, ignored"));
        slot = Val::set(0);
    }

    cell.borrow_mut().send_lowat = slot;
    rc
}

/// ngx_http_proxy_rewrite_redirect: a "Location" or "Refresh" header of the
/// response by the rules of proxy_redirect
pub(crate) fn rewrite_redirect(r: &R, lcf: &Rc<RefCell<NgxHttpProxyLocConf>>, h: &Header, prefix: usize) -> i64 {
    let redirects = match lcf.borrow().redirects.clone() {
        Some(v) if !v.is_empty() => v,
        _ => return NGX_DECLINED,
    };

    let value = h.value.borrow().clone();

    match try_redirect_rewrite(r, &value, prefix, &redirects) {
        Some(v) => {
            *h.value.borrow_mut() = v;
            NGX_OK
        }
        None => NGX_DECLINED,
    }
}

/// u->rewrite_cookie is set: plcf->cookie_domains, cookie_paths or
/// cookie_flags
pub(crate) fn has_rewrite_cookie(c: &NgxHttpProxyLocConf) -> bool {
    !c.cookie_domains.is_empty() || !c.cookie_paths.is_empty() || c.cookie_flags.iter().any(|r| !matches!(r.matcher, CookieMatcher::Off))
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

/// The context of the module for a request: ngx_http_proxy_ctx_t (its
/// vars, the head, internal_chunked and header_sent fields are ProxyCtx,
/// the variables see it), the status line and header parser, the chunked
/// parser and the trailers, with the callbacks of ngx_http_proxy_handler.
struct ProxyModule {
    lcf: Rc<RefCell<NgxHttpProxyLocConf>>,
    ctx: Rc<RefCell<ProxyCtx>>,
    /// ctx->status and r->state
    st: HeaderParse,
    /// u->input_filter and p->input_filter are the chunked ones
    /// (ngx_http_proxy_input_filter_init)
    chunked_filters: bool,
    /// ctx->chunked
    chunked: crate::parse::ChunkedState,
    /// ctx->trailers: the trailer part being read, with its parse state
    trailers: Option<(Vec<u8>, crate::parse::ParseRequest, usize)>,
}

/// ngx_http_proxy_handler
async fn proxy_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());

    if lcf.borrow().http_version.get_or(crate::NGX_HTTP_VERSION_11) == crate::NGX_HTTP_VERSION_20 {
        return crate::proxy_v2::proxy_v2_handler(r).await;
    }

    let conf = match lcf.borrow().upstream_conf.clone() {
        Some(c) => c,
        None => return crate::NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let caches = {
        let pmcf = r.main_conf::<crate::upstream_cache::UpstreamCacheMainConf>(ctx_index());
        let caches = pmcf.borrow().caches.clone();
        caches
    };

    // ngx_http_upstream_create; u->conf and u->caches

    let mut u = crate::upstream_rt::Upstream::create(&r, conf, caches, b"");

    let proxy_values = lcf.borrow().proxy_values.clone();

    let ctx = match proxy_values {
        None => {
            let plcf = lcf.borrow();
            let ctx = r.set_ctx(ctx_index(), ProxyCtx::new(plcf.vars.clone()));
            u.set_schema(&plcf.vars.schema);
            u.ssl = plcf.ssl;
            ctx
        }
        Some(codes) => {
            let ctx = r.set_ctx(ctx_index(), ProxyCtx::new(no_vars()));

            if proxy_eval(&r, &ctx, &codes, &mut u) != NGX_OK {
                return crate::NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ctx
        }
    };

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

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= crate::NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    let mut m = ProxyModule { lcf, ctx, st: HeaderParse::default(), chunked_filters: false, chunked: crate::parse::ChunkedState::default(), trailers: None };

    crate::upstream_rt::init(r, u, &mut m).await
}

/// ngx_http_proxy_eval: the URL of proxy_pass with variables, its vars and
/// the upstream it names (u->resolved).
pub(crate) fn proxy_eval(r: &R, ctx: &Rc<RefCell<ProxyCtx>>, codes: &[crate::script::Part], u: &mut crate::upstream_rt::Upstream) -> i64 {
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
        // ctx->vars.key_start = u->schema
        let mut vars = ProxyVars { key_start: proxy[..add].to_vec(), schema: ctx.borrow().vars.schema.clone(), ..Default::default() };

        set_vars(&url, &mut vars, &proxy);

        ctx.borrow_mut().vars = Rc::new(vars);
    }

    // u->schema
    u.set_schema(&proxy[..add]);

    u.resolved = Some(url);

    NGX_OK
}

/// The values of header or body codes compiled by ngx_http_script_compile()
/// as ngx_http_proxy_create_request() runs them: the variables with
/// ngx_http_get_indexed_variable() (e.flushed = 1), the no cacheable ones
/// having been flushed.
pub(crate) fn run_codes(r: &R, codes: &[crate::script::Part]) -> Vec<u8> {
    let mut value = Vec::with_capacity(codes_len(r, codes));

    append_codes(r, codes, &mut value);

    value
}

/// The bytes of a variable for the codes of ngx_http_proxy_create_request
/// and of the params (e->flushed: the value cached in r->variables, else
/// evaluated and cached by ngx_http_get_indexed_variable()), lent to `f`;
/// empty if not found. `f` must not evaluate variables.
fn with_var<T>(r: &R, index: usize, f: impl FnOnce(&[u8]) -> T) -> T {
    crate::variables::with_indexed_variable(r, index, |v| match v {
        Some(v) if !v.not_found => f(&v.data),
        _ => f(&[]),
    })
}

/// A regex capture of the codes, lent to `f` (empty if not set).
fn with_capture<T>(r: &R, n: usize, f: impl FnOnce(&[u8]) -> T) -> T {
    if n < r.ncaptures.get() {
        let cap = r.captures.borrow();

        if n + 1 < cap.len() {
            let (a, b) = (cap[n], cap[n + 1]);

            if a >= 0 && b >= a {
                let data = r.captures_data.borrow();

                if (b as usize) <= data.len() {
                    return f(&data[a as usize..b as usize]);
                }
            }
        }
    }

    f(&[])
}

/// The length of the value of codes (the lengths codes of C).
pub(crate) fn codes_len(r: &R, codes: &[crate::script::Part]) -> usize {
    codes
        .iter()
        .map(|code| match code {
            crate::script::Part::Literal(data) => data.len(),
            crate::script::Part::Var(index) => with_var(r, *index, |v| v.len()),
            crate::script::Part::Capture(n) => with_capture(r, *n, |c| c.len()),
        })
        .sum()
}

/// The value of codes appended to `out` (the values codes of C).
pub(crate) fn append_codes(r: &R, codes: &[crate::script::Part], out: &mut Vec<u8>) {
    for code in codes {
        match code {
            crate::script::Part::Literal(data) => out.extend_from_slice(data),
            crate::script::Part::Var(index) => with_var(r, *index, |v| out.extend_from_slice(v)),
            crate::script::Part::Capture(n) => with_capture(r, *n, |c| out.extend_from_slice(c)),
        }
    }
}

/// ngx_http_proxy_create_request: the request line, the Host header, the
/// headers of proxy_set_header and the defaults with a value, the client's
/// headers not among them, and the body of proxy_set_body, in one buffer of
/// the length computed first. Returns the buffer and u->uri.
fn create_request(r: &R, plcf: &NgxHttpProxyLocConf, ctx: &Rc<RefCell<ProxyCtx>>, cacheable: bool, u_method: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let headers = match if cacheable { plcf.headers_cache.as_ref() } else { plcf.headers.as_ref() } {
        Some(h) => h,
        None => return Err(()),
    };

    // u->method (HEAD was changed to GET to cache response), proxy_method,
    // or r->method_name
    let method_value = match (u_method, plcf.method.as_option()) {
        (None, Some(Some(cv))) => Some(crate::script::complex_value_cow(r, cv).map_err(|_| ())?),
        _ => None,
    };

    let method_name;

    let method: &[u8] = match (u_method, &method_value) {
        (Some(m), _) => m,
        (None, Some(m)) => m,
        (None, None) => {
            method_name = r.method_name.borrow();
            &method_name
        }
    };

    let http_version = plcf.http_version.get_or(crate::NGX_HTTP_VERSION_11);

    let vars = ctx.borrow().vars.clone();

    let host_value = match &plcf.host_value {
        Some(hv) => Some(crate::script::complex_value_cow(r, hv).map_err(|_| ())?),
        None => None,
    };

    let host: &[u8] = match &host_value {
        Some(h) if !(h.is_empty() && http_version == crate::NGX_HTTP_VERSION_11) => h,
        _ => &vars.host_header,
    };

    if method.len() == 4 && method.eq_ignore_ascii_case(b"HEAD") {
        ctx.borrow_mut().head = true;
    }

    let vars_uri = &vars.uri;

    let mut len = method.len() + " ".len() + " HTTP/1.0\r\n".len() + "\r\n".len();

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

    len += uri_len;

    crate::script::script_flush_no_cacheable_variables(r, Some(&plcf.body_flushes));
    crate::script::script_flush_no_cacheable_variables(r, Some(&headers.flushes));

    // the lengths: of the body, the Host header, the headers with a value
    // and the client's headers passed

    if let Some(codes) = &plcf.body_values {
        let body_len = codes_len(r, codes);
        ctx.borrow_mut().internal_body_length = body_len as i64;
        len += body_len;
    } else if r.headers_in.borrow().chunked && r.reading_body.get() {
        let mut c = ctx.borrow_mut();
        c.internal_body_length = -1;
        c.internal_chunked = true;
    } else {
        ctx.borrow_mut().internal_body_length = r.headers_in.borrow().content_length_n;
    }

    if !host.is_empty() {
        len += "Host: ".len() + host.len() + "\r\n".len();
    }

    for (key, codes) in headers.lines.iter() {
        let val_len = codes_len(r, codes);

        if val_len == 0 {
            continue;
        }

        len += key.len() + ": ".len() + val_len + "\r\n".len();
    }

    let pass_request_headers = plcf.pass_request_headers.get_or(true);

    if pass_request_headers {
        let hin = r.headers_in.borrow();

        for h in hin.headers.iter() {
            if headers.hash.find(ngx_core::hash::hash_key(&h.lowcase_key), &h.lowcase_key).is_some() {
                continue;
            }

            len += h.key.len() + ": ".len() + h.value.borrow().len() + "\r\n".len();
        }
    }

    let mut b: Vec<u8> = Vec::with_capacity(len);

    // the request line

    b.extend_from_slice(method);
    b.push(b' ');

    let uri_start = b.len();

    if plcf.proxy_values.is_some() && !vars_uri.is_empty() {
        b.extend_from_slice(vars_uri);
    } else if unparsed_uri {
        b.extend_from_slice(&r.unparsed_uri.borrow());
    } else {
        if r.valid_location.get() {
            b.extend_from_slice(vars_uri);
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
        b.extend_from_slice(host);
        b.extend_from_slice(b"\r\n");
    }

    // the values (e.flushed: those the lengths evaluated)
    for (key, codes) in headers.lines.iter() {
        if codes_len(r, codes) == 0 {
            continue;
        }

        b.extend_from_slice(key);
        b.extend_from_slice(b": ");
        append_codes(r, codes, &mut b);
        b.extend_from_slice(b"\r\n");
    }

    if pass_request_headers {
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

    if let Some(codes) = &plcf.body_values {
        append_codes(r, codes, &mut b);
    }

    ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy header:\n\"{}\"", ngx_core::string::B(&b));

    Ok((b, u_uri))
}

/// ngx_http_proxy_create_key: proxy_cache_key, or the URL of proxy_pass
/// (ctx->vars.key_start) and the URI of the request as the upstream
/// request has it.
pub(crate) fn create_key(r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
    let mut k = crate::file_cache::CacheKeys::new();

    let rc = create_keys(r, &mut k);

    keys.extend(k.iter().map(|part| part.to_vec()));

    rc
}

/// create_key() into c->keys, the parts written in place.
pub(crate) fn create_keys(r: &R, keys: &mut crate::file_cache::CacheKeys) -> i64 {
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let plcf = lcf.borrow();

    let ctx = match proxy_ctx(r) {
        Some(c) => c,
        None => return NGX_ERROR,
    };

    let vars = ctx.borrow().vars.clone();

    if let Some(cv) = &plcf.cache.cache_key {
        return crate::upstream_cache::push_key_value(r, cv, keys);
    }

    // room for the URL and the URI (escaped, at most 3 bytes a byte)
    let room = vars.key_start.len() + vars.uri.len() + (3 * r.uri.borrow().len()).max(r.unparsed_uri.borrow().len()) + "?".len() + r.args.borrow().len();

    keys.data_mut().reserve(room);

    keys.push(&vars.key_start);

    if plcf.proxy_values.is_some() && !vars.uri.is_empty() {
        keys.push(&vars.uri);

        return NGX_OK;
    } else if vars.uri.is_empty() && r.valid_unparsed_uri.get() {
        keys.push(&r.unparsed_uri.borrow());

        return NGX_OK;
    }

    let uri = r.uri.borrow();

    let loc_len = if r.valid_location.get() && !vars.uri.is_empty() { plcf.location.len().min(uri.len()) } else { 0 };

    let key = keys.data_mut();

    key.extend_from_slice(&vars.uri);

    if r.quoted_uri.get() || r.internal.get() {
        ngx_core::string::escape_uri_into(key, &uri[loc_len..], ngx_core::string::NGX_ESCAPE_URI);
    } else {
        key.extend_from_slice(&uri[loc_len..]);
    }

    let args = r.args.borrow();

    if !args.is_empty() {
        key.push(b'?');
        key.extend_from_slice(&args);
    }

    keys.end();

    NGX_OK
}

/// The default proxy_buffer_size: ngx_pagesize.
const PROXY_BUFFER_SIZE: usize = 4096;

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

impl crate::upstream_rt::UpstreamModule for ProxyModule {
    fn create_key(&self, r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
        create_key(r, keys)
    }

    fn create_keys(&self, r: &R, keys: &mut crate::file_cache::CacheKeys) -> i64 {
        create_keys(r, keys)
    }

    /// ngx_http_proxy_create_request: the request (with the body of
    /// proxy_set_body), then the buffers of a buffered body; an unbuffered
    /// one is sent after it by ngx_http_upstream_send_request_body, through
    /// ngx_http_proxy_body_output_filter when chunked.
    fn create_request(&mut self, r: &R, u: &mut crate::upstream_rt::Upstream) -> i64 {
        let plcf = self.lcf.borrow();

        let u_method: Option<&'static [u8]> = *u.ucache.method.borrow();

        let (header, uri) = match create_request(r, &plcf, &self.ctx, u.cacheable(), u_method) {
            Ok(x) => x,
            Err(()) => return NGX_ERROR,
        };

        u.set_uri_owned(uri);

        let mut b = ngx_core::buf::Buf::from_vec(header);
        b.flush = true;

        let mut bufs = ngx_core::buf::Chain::new();
        bufs.push_back(b);

        // the buffers of the body follow, linked
        u.request_body_link = !r.request_body_no_buffering.get() && plcf.body_values.is_none() && plcf.pass_request_body.get_or(true);

        u.request_bufs = bufs;

        NGX_OK
    }

    /// ngx_http_proxy_reinit_request
    fn reinit_request(&mut self, _r: &R, _u: &mut crate::upstream_rt::Upstream) -> i64 {
        self.st = HeaderParse::default();
        self.chunked.state = 0;
        self.chunked_filters = false;
        NGX_OK
    }

    /// ngx_http_proxy_process_status_line, then ngx_http_proxy_process_header
    fn process_header(&mut self, r: &R, u: &mut crate::upstream_rt::Upstream) -> i64 {
        process_status_line(r, &self.ctx, u, &mut self.st)
    }

    /// ngx_http_proxy_input_filter_init: u->length and p->length (as per
    /// RFC2616, 4.4 Message Length), and the chunked filters
    fn input_filter_init(&mut self, r: &R, u: &mut crate::upstream_rt::Upstream, p: Option<&mut crate::event_pipe::EventPipe>) -> i64 {
        let head = self.ctx.borrow().head;

        ngx_core::ngx_log_debug!(
            ngx_core::log::NGX_LOG_DEBUG_HTTP,
            r.connection.log,
            "http proxy filter init s:{} h:{} c:{} l:{}",
            u.resp.status_n,
            head as i32,
            u.resp.chunked as i32,
            u.resp.content_length_n
        );

        let (p_length, u_length) = if u.resp.status_n == crate::NGX_HTTP_NO_CONTENT || u.resp.status_n == crate::NGX_HTTP_NOT_MODIFIED || head {
            // 1xx, 204, and 304 and replies to HEAD requests
            u.keepalive = !u.resp.connection_close;
            (0, 0)
        } else if u.resp.chunked {
            // chunked: "0" CRLF CRLF
            self.chunked_filters = true;
            (5, 1)
        } else if u.resp.content_length_n == 0 {
            // empty body: special case as filter won't be called
            u.keepalive = !u.resp.connection_close;
            (0, 0)
        } else {
            // content length or connection close
            (u.resp.content_length_n, u.resp.content_length_n)
        };

        if let Some(p) = p {
            p.length = p_length;
        }

        u.length = u_length;

        NGX_OK
    }

    /// ngx_http_proxy_non_buffered_copy_filter or
    /// ngx_http_proxy_non_buffered_chunked_filter
    fn input_filter(&mut self, r: &R, u: &mut crate::upstream_rt::Upstream, data: &[u8]) -> i64 {
        if self.chunked_filters {
            return self.non_buffered_chunked_filter(r, u, data);
        }

        non_buffered_copy_filter(r, u, data)
    }

    /// ngx_http_proxy_copy_filter or ngx_http_proxy_chunked_filter
    fn pipe_input_filter(&mut self, r: &R, u: &mut crate::upstream_rt::Upstream, p: &mut crate::event_pipe::EventPipe, buf: crate::event_pipe::RawBuf) -> i64 {
        if self.chunked_filters {
            return self.chunked_filter(r, u, p, buf);
        }

        copy_filter(u, p, buf)
    }

    /// ngx_http_proxy_finalize_request
    fn finalize_request(&mut self, r: &R, _u: &mut crate::upstream_rt::Upstream, _rc: i64) {
        ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "finalize http proxy request");
    }

    /// ngx_http_proxy_body_output_filter, set when the unbuffered body is
    /// sent chunked: the first buffer (the request) as it is, then each
    /// output a chunk, with the last chunk after the last buffer.
    fn body_output_filter(&mut self, r: &R, _u: &mut crate::upstream_rt::Upstream, bufs: ngx_core::buf::Chain) -> ngx_core::buf::Chain {
        if !self.ctx.borrow().internal_chunked {
            return bufs;
        }

        let mut header_sent = self.ctx.borrow().header_sent;

        let out = chunked_body_output(&r.connection.log, &mut header_sent, bufs);

        self.ctx.borrow_mut().header_sent = header_sent;

        out
    }

    fn has_rewrite_redirect(&self) -> bool {
        self.lcf.borrow().redirects.is_some()
    }

    /// ngx_http_proxy_rewrite_redirect
    fn rewrite_redirect(&mut self, r: &R, h: &Header, prefix: usize) -> i64 {
        rewrite_redirect(r, &self.lcf, h, prefix)
    }

    fn has_rewrite_cookie(&self) -> bool {
        has_rewrite_cookie(&self.lcf.borrow())
    }

    /// ngx_http_proxy_rewrite_cookie
    fn rewrite_cookie(&mut self, r: &R, h: &Header) -> i64 {
        rewrite_cookie(r, &self.lcf, h)
    }
}

impl ProxyModule {
    /// ngx_http_proxy_chunked_filter: the chunks of a raw buffer to p->in,
    /// p->length the least the parser wants to see next.
    fn chunked_filter(&mut self, r: &R, u: &mut crate::upstream_rt::Upstream, p: &mut crate::event_pipe::EventPipe, buf: crate::event_pipe::RawBuf) -> i64 {
        use ngx_core::log::*;

        if buf.is_empty() {
            p.release_raw(buf.slot);
            return NGX_OK;
        }

        if p.upstream_done {
            ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy data after close");
            p.release_raw(buf.slot);
            return NGX_OK;
        }

        if p.length == 0 {
            ngx_core::ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent data after final chunk");

            u.keepalive = false;
            p.upstream_done = true;

            p.release_raw(buf.slot);
            return NGX_OK;
        }

        let (pass_trailers, buffer_size) = (u.conf.pass_trailers, u.conf.buffer_size);

        let slot = buf.slot;
        let mut pos = buf.pos;
        let data = buf.data;
        let mut produced = false;

        if self.trailers.is_some() {
            match process_trailer(r, &mut self.trailers, &data, &mut pos, buffer_size, &mut u.resp.trailers) {
                NGX_ERROR => return NGX_ERROR,

                NGX_OK => {
                    // a whole response has been parsed successfully
                    p.length = 0;
                    u.keepalive = !u.resp.connection_close;

                    if pos != data.len() {
                        ngx_core::ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent data after trailers");
                        u.keepalive = false;
                    }
                }

                _ => {}
            }
        } else {
            loop {
                let rc = crate::parse::parse_chunked(&mut self.chunked, &data, &mut pos, pass_trailers);

                if rc == NGX_OK {
                    // a chunk has been parsed successfully
                    let take = (self.chunked.size.max(0) as usize).min(data.len() - pos);

                    let b = ngx_core::buf::Buf::from_vec(data[pos..pos + take].to_vec());

                    ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_EVENT, r.connection.log, "input buf #{} {:p}", slot, data[pos..].as_ptr());

                    p.push_in(b, slot);
                    produced = true;

                    pos += take;
                    self.chunked.size -= take as i64;

                    continue;
                }

                if rc == NGX_DONE {
                    if pass_trailers {
                        match process_trailer(r, &mut self.trailers, &data, &mut pos, buffer_size, &mut u.resp.trailers) {
                            NGX_ERROR => return NGX_ERROR,
                            NGX_AGAIN => {
                                p.length = 1;
                                break;
                            }
                            _ => {}
                        }
                    }

                    // a whole response has been parsed successfully
                    p.length = 0;
                    u.keepalive = !u.resp.connection_close;

                    if pos != data.len() {
                        ngx_core::ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent data after final chunk");
                        u.keepalive = false;
                    }

                    break;
                }

                if rc == NGX_AGAIN {
                    // set p->length, minimal amount of data we want to see
                    p.length = self.chunked.length;
                    break;
                }

                // invalid response
                ngx_core::ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid chunked response");

                return NGX_ERROR;
            }
        }

        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy chunked state {}, length {}", self.chunked.state, p.length);

        if !produced {
            // there is no data record in the buf, add it to free chain
            p.release_raw(slot);
        }

        NGX_OK
    }

    /// ngx_http_proxy_non_buffered_chunked_filter
    fn non_buffered_chunked_filter(&mut self, r: &R, u: &mut crate::upstream_rt::Upstream, data: &[u8]) -> i64 {
        use ngx_core::log::*;

        let (pass_trailers, buffer_size) = (u.conf.pass_trailers, u.conf.buffer_size);

        let mut pos = 0usize;

        if self.trailers.is_some() {
            match process_trailer(r, &mut self.trailers, data, &mut pos, buffer_size, &mut u.resp.trailers) {
                NGX_ERROR => return NGX_ERROR,

                NGX_OK => {
                    // a whole response has been parsed successfully
                    u.keepalive = !u.resp.connection_close;
                    u.length = 0;

                    if pos != data.len() {
                        ngx_core::ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent data after trailers");
                        u.keepalive = false;
                    }
                }

                _ => {}
            }

            return NGX_OK;
        }

        loop {
            let rc = crate::parse::parse_chunked(&mut self.chunked, data, &mut pos, pass_trailers);

            if rc == NGX_OK {
                // a chunk has been parsed successfully
                let take = (self.chunked.size.max(0) as usize).min(data.len() - pos);

                let mut b = ngx_core::buf::Buf::from_vec(data[pos..pos + take].to_vec());
                b.flush = true;
                b.memory = true;

                ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy out buf {:p} {}", data[pos..].as_ptr(), take);

                u.out_bufs.push_back(b);

                pos += take;
                self.chunked.size -= take as i64;

                continue;
            }

            if rc == NGX_DONE {
                if pass_trailers {
                    match process_trailer(r, &mut self.trailers, data, &mut pos, buffer_size, &mut u.resp.trailers) {
                        NGX_ERROR => return NGX_ERROR,
                        NGX_AGAIN => {
                            u.length = 1;
                            break;
                        }
                        _ => {}
                    }
                }

                // a whole response has been parsed successfully
                u.keepalive = !u.resp.connection_close;
                u.length = 0;

                if pos != data.len() {
                    ngx_core::ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent data after final chunk");
                    u.keepalive = false;
                }

                break;
            }

            if rc == NGX_AGAIN {
                break;
            }

            // invalid response
            ngx_core::ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid chunked response");

            return NGX_ERROR;
        }

        NGX_OK
    }
}

/// ngx_http_proxy_copy_filter: ngx_event_pipe_copy_input_filter, and
/// u->keepalive when the body is read in full.
fn copy_filter(u: &mut crate::upstream_rt::Upstream, p: &mut crate::event_pipe::EventPipe, buf: crate::event_pipe::RawBuf) -> i64 {
    if !buf.data.is_empty() && !p.upstream_done && p.length == 0 {
        // "upstream sent more data than specified in "Content-Length" header"
        u.keepalive = false;
    }

    let rc = crate::event_pipe::copy_input_filter(p, buf);

    if p.length == 0 && !p.upstream_done {
        u.keepalive = !u.resp.connection_close;
    }

    rc
}

/// ngx_http_proxy_non_buffered_copy_filter: the non-buffered filter of the
/// upstream, and u->keepalive when the body is read in full.
fn non_buffered_copy_filter(r: &R, u: &mut crate::upstream_rt::Upstream, data: &[u8]) -> i64 {
    if u.length == 0 {
        ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
        u.keepalive = false;
        return NGX_OK;
    }

    let rc = crate::upstream_rt::non_buffered_filter(r, u, data);

    if u.length == 0 {
        u.keepalive = !u.resp.connection_close;
    }

    rc
}

/// ngx_http_proxy_process_status_line: the status line, then the header
/// of ngx_http_proxy_process_header. NGX_OK, NGX_AGAIN,
/// NGX_HTTP_UPSTREAM_INVALID_HEADER or NGX_HTTP_UPSTREAM_EARLY_HINTS.
fn process_status_line(r: &R, ctx: &Rc<RefCell<ProxyCtx>>, up: &mut crate::upstream_rt::Upstream, st: &mut HeaderParse) -> i64 {
    use crate::upstream_cache::NGX_HTTP_UPSTREAM_INVALID_HEADER;

    if !st.status_done {
        let u = &mut up.resp;

        let mut p = st.pos;
        let mut status = crate::parse::Status::default();

        let rc = crate::parse::parse_status_line(&u.buf, &mut p, &mut status);

        if rc == NGX_AGAIN {
            return NGX_AGAIN;
        }

        if rc == NGX_ERROR {
            // u->buffer.pos = ctx->status.line_start
            u.pos = st.pos;

            if r.cache.borrow().is_some() {
                r.http_version.set(crate::NGX_HTTP_VERSION_9);
                return NGX_OK;
            }

            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent no valid HTTP/1.0 header");

            r.http_version.set(crate::NGX_HTTP_VERSION_9);

            if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
                state.status = crate::NGX_HTTP_OK;
            }

            u.connection_close = true;

            return NGX_OK;
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
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            u.connection_close = true;
        }

        st.pos = p;
        st.status_done = true;
    }

    process_header(r, ctx, up, st)
}

/// ngx_http_proxy_process_header: the header lines, each with the handler
/// of ngx_http_upstream_headers_in[]; at the end the special empty
/// "Server" and "Date", u->keepalive for a response without a body, and
/// u->upgrade.
fn process_header(r: &R, ctx: &Rc<RefCell<ProxyCtx>>, up: &mut crate::upstream_rt::Upstream, st: &mut HeaderParse) -> i64 {
    use crate::parse::NGX_HTTP_PARSE_HEADER_DONE;
    use crate::upstream_cache::{NGX_HTTP_UPSTREAM_EARLY_HINTS, NGX_HTTP_UPSTREAM_INVALID_HEADER};

    loop {
        let rc = crate::parse::parse_header_line(&mut st.pr, &up.resp.buf, &mut st.pos, true);

        if rc == NGX_OK {
            // a header line has been parsed successfully

            let pr = &st.pr;

            let key = up.resp.buf[pr.header_name_start..pr.header_name_end].to_vec();
            let value = up.resp.buf[pr.header_start..pr.header_end].to_vec();

            let lowcase = if key.len() == pr.lowcase_index { pr.lowcase_header[..key.len()].to_vec() } else { key.to_ascii_lowercase() };

            ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy header: \"{}: {}\"", ngx_core::string::B(&key), ngx_core::string::B(&value));

            let h = crate::upstream_rt::upstream_header(key, value, pr.header_hash, lowcase);

            up.resp.push_header(h.clone());

            if up.resp.status_n == crate::NGX_HTTP_EARLY_HINTS {
                continue;
            }

            if crate::upstream_rt::process_header_line(r, up, &h).is_err() {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            continue;
        }

        if rc == NGX_HTTP_PARSE_HEADER_DONE {
            // a whole header has been parsed successfully

            ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http proxy header done");

            if up.resp.status_n == crate::NGX_HTTP_EARLY_HINTS {
                // the parsers anew, u->buffer.pos after the early hints
                up.resp.pos = st.pos;
                *st = HeaderParse::default();

                return NGX_HTTP_UPSTREAM_EARLY_HINTS;
            }

            // if no "Server" and "Date" in header line, then add the
            // special empty headers

            if !up.resp.server {
                let h = crate::upstream_rt::upstream_header(b"Server".to_vec(), Vec::new(), ngx_core::hash::hash_key(b"server"), b"server".to_vec());
                h.null.set(true);
                up.resp.headers.push(h);
            }

            if !up.resp.date {
                let h = crate::upstream_rt::upstream_header(b"Date".to_vec(), Vec::new(), ngx_core::hash::hash_key(b"date"), b"date".to_vec());
                h.null.set(true);
                up.resp.headers.push(h);
            }

            // clear content length if response is chunked

            if up.resp.chunked {
                up.resp.content_length_n = -1;
            }

            // set u->keepalive if response has no body; this allows to keep
            // connections alive in case of r->header_only or X-Accel-Redirect

            let head = ctx.borrow().head;
            let status = up.resp.status_n;

            if status == crate::NGX_HTTP_NO_CONTENT || status == crate::NGX_HTTP_NOT_MODIFIED || head || (!up.resp.chunked && up.resp.content_length_n == 0) {
                up.keepalive = !up.resp.connection_close;
            }

            if status == crate::NGX_HTTP_SWITCHING_PROTOCOLS {
                up.keepalive = false;

                if !r.headers_in.borrow().upgrade.is_empty() {
                    up.upgrade = true;
                }
            }

            up.resp.pos = st.pos;

            return NGX_OK;
        }

        if rc == NGX_AGAIN {
            return NGX_AGAIN;
        }

        // rc == NGX_HTTP_PARSE_INVALID_HEADER

        let pr = &st.pr;

        let end = pr.header_end.min(up.resp.buf.len());
        let start = pr.header_name_start.min(end);
        let ch = up.resp.buf.get(end).copied().unwrap_or(0);

        ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid header: \"{}\\x{:02x}...\"", ngx_core::string::B(&up.resp.buf[start..end]), ch);

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
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

            trailers.push(crate::upstream_rt::upstream_header(key, value, pr.header_hash, lowcase));

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
        cmd_fn!("proxy_bind", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let mut local = std::mem::take(&mut cell.borrow_mut().local);
            let rc = crate::upstream_rt::bind_set_slot(cf, &mut local);
            cell.borrow_mut().local = local;
            rc
        }),
        ngx_core::cmd!("proxy_socket_rcvbuf", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, socket_rcvbuf, set_size),
        ngx_core::cmd!("proxy_socket_sndbuf", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, socket_sndbuf, set_size),
        cmd_fn!("proxy_send_lowat", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_send_lowat_handler),
        ngx_core::cmd!("proxy_connect_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, connect_timeout, set_msec),
        ngx_core::cmd!("proxy_send_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, send_timeout, set_msec),
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
        ngx_core::cmd!("proxy_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, NgxHttpProxyLocConf, bufs, set_bufs),
        ngx_core::cmd!("proxy_busy_buffers_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, busy_buffers_size_conf, set_size),
        ngx_core::cmd!("proxy_max_temp_file_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, max_temp_file_size_conf, set_size),
        ngx_core::cmd!("proxy_temp_file_write_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, temp_file_write_size_conf, set_size),
        cmd_fn!("proxy_next_upstream", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, proxy_next_upstream_handler),
        cmd_fn!("proxy_next_upstream_tries", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_next_upstream_tries_handler),
        ngx_core::cmd!("proxy_next_upstream_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, NgxHttpProxyLocConf, next_upstream_timeout, set_msec),
        ngx_core::cmd!("proxy_pass_request_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, pass_request_headers, set_flag),
        ngx_core::cmd!("proxy_pass_request_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, pass_request_body, set_flag),
        cmd_fn!("proxy_method", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_method_handler),
        cmd_fn!("proxy_http_version", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, cmd, conf: Option<Rc<dyn Any>>| {
            // ngx_conf_set_enum_slot with ngx_http_proxy_http_version ("2"
            // is ngx_http_proxy_v2_module)
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            let mut c = cell.borrow_mut();
            set_enum(cf, cmd, &mut c.http_version, &[("1.0", crate::NGX_HTTP_VERSION_10), ("1.1", crate::NGX_HTTP_VERSION_11), ("2", crate::NGX_HTTP_VERSION_20)])
        }),
        ngx_core::cmd!("proxy_socket_keepalive", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, socket_keepalive, set_flag),
        cmd_fn!("proxy_cookie_domain", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_cookie_domain_handler),
        cmd_fn!("proxy_cookie_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_cookie_path_handler),
        cmd_fn!("proxy_cookie_flags", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, proxy_cookie_flags_handler),
        cmd_fn!("proxy_set_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_set_body_handler),
        cmd_fn!("proxy_pass_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            crate::upstream_rt::str_array_push(&mut cell.borrow_mut().pass_headers, &cf.args[1]);
            Ok(())
        }),
        cmd_fn!("proxy_hide_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |cf: &mut Conf, _cmd, conf: Option<Rc<dyn Any>>| {
            let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());
            crate::upstream_rt::str_array_push(&mut cell.borrow_mut().hide_headers, &cf.args[1]);
            Ok(())
        }),
        cmd_fn!("proxy_ignore_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, crate::upstream_cache::ignore_headers_slot::<NgxHttpProxyLocConf>),
        ngx_core::cmd!("proxy_pass_trailers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, pass_trailers, set_flag),
        ngx_core::cmd!("proxy_intercept_errors", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, intercept_errors, set_flag),
        ngx_core::cmd!("proxy_ignore_client_abort", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, NgxHttpProxyLocConf, ignore_client_abort, set_flag),
        cmd_fn!("proxy_store", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_store_handler),
        ngx_core::cmd!("proxy_store_access", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::Loc, NgxHttpProxyLocConf, store_access, set_access),
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

/// The chunks of ngx_http_proxy_body_output_filter: unless `header_sent`,
/// the first buffer (the request header) as it is; then the size of the
/// buffers as a chunk header, the buffers (the special ones but flush and
/// sync dropped), and "CRLF 0 CRLF CRLF" after the last buffer (without the
/// leading CRLF for no data), or the CRLF of the chunk.
fn chunked_body_output(log: &ngx_core::log::Log, header_sent: &mut bool, bufs: ngx_core::buf::Chain) -> ngx_core::buf::Chain {
    ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, log, "proxy output filter");

    let mut out = ngx_core::buf::Chain::new();
    let mut rest = bufs;

    if rest.is_empty() {
        return out;
    }

    if !*header_sent {
        // first buffer contains headers, pass it unmodified
        ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, log, "proxy output header");

        *header_sent = true;

        if let Some(b) = rest.pop_front() {
            out.push_back(b);
        }

        if rest.is_empty() {
            return out;
        }
    }

    let last_buf = rest.back().is_some_and(|b| b.last_buf);

    let mut size: i64 = 0;
    let mut data = ngx_core::buf::Chain::new();

    for mut b in rest.into_iter() {
        ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, log, "proxy output chunk: {}", b.buf_size());

        size += b.buf_size();

        b.last_buf = false;

        if b.flush || b.sync || b.in_memory() || b.in_file {
            data.push_back(b);
        }
    }

    if size > 0 {
        out.push_back(ngx_core::buf::Buf::from_vec(format!("{:x}\r\n", size).into_bytes()));
    }

    out.extend(data);

    if last_buf {
        let mut b = ngx_core::buf::Buf::from_static(if size == 0 { b"0\r\n\r\n" } else { b"\r\n0\r\n\r\n" });
        b.last_buf = true;
        out.push_back(b);
    } else if size > 0 {
        out.push_back(ngx_core::buf::Buf::from_static(b"\r\n"));
    }

    out
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

    fn chain_of(parts: &[&[u8]], last: bool) -> ngx_core::buf::Chain {
        let mut c = ngx_core::buf::Chain::new();
        for p in parts {
            c.push_back(ngx_core::buf::Buf::from_vec(p.to_vec()));
        }
        if last {
            let mut b = ngx_core::buf::Buf::special();
            b.last_buf = true;
            c.push_back(b);
        }
        c
    }

    fn bytes(chain: &ngx_core::buf::Chain) -> Vec<u8> {
        crate::upstream_rt::chain_bytes(chain)
    }

    #[test]
    fn test_chunked_body_output() {
        let log = ngx_core::log::Log::stderr(ngx_core::log::NGX_LOG_ERR);

        // ngx_http_proxy_body_output_filter: one chunk for the buffers
        let mut sent = true;
        assert_eq!(bytes(&chunked_body_output(&log, &mut sent, chain_of(&[b"abc", b"de"], false))), b"5\r\nabcde\r\n");

        let out = chunked_body_output(&log, &mut sent, chain_of(&[b"0123456789abcdef"], true));
        assert_eq!(bytes(&out), b"10\r\n0123456789abcdef\r\n0\r\n\r\n");
        assert!(out.back().unwrap().last_buf);

        assert_eq!(bytes(&chunked_body_output(&log, &mut sent, chain_of(&[], true))), b"0\r\n\r\n");

        // the first buffer is the header
        let mut sent = false;
        assert_eq!(bytes(&chunked_body_output(&log, &mut sent, chain_of(&[b"GET / HTTP/1.1\r\n\r\n"], false))), b"GET / HTTP/1.1\r\n\r\n");
        assert!(sent);
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
/// ngx_http_proxy_rewrite_cookie: the Domain and Path attributes of a
/// "Set-Cookie" rewritten with proxy_cookie_domain and proxy_cookie_path,
/// then its flags with proxy_cookie_flags; the value made anew if any was
/// changed. NGX_OK, or NGX_DECLINED if not rewritten.
pub(crate) fn rewrite_cookie(r: &R, lcf: &Rc<RefCell<NgxHttpProxyLocConf>>, h: &Header) -> i64 {
    let value = h.value.borrow().clone();

    let mut attrs = parse_cookie(&value);

    if attrs.is_empty() || attrs[0].1.is_none() {
        return NGX_DECLINED;
    }

    let plcf = lcf.borrow();

    let mut changed = false;

    for i in 1..attrs.len() {
        let v = match &attrs[i].1 {
            Some(v) => v.clone(),
            None => continue,
        };

        let k = attrs[i].0.to_ascii_lowercase();

        let rewrites = if k == b"domain" && !plcf.cookie_domains.is_empty() {
            &plcf.cookie_domains
        } else if k == b"path" && !plcf.cookie_paths.is_empty() {
            &plcf.cookie_paths
        } else {
            continue;
        };

        if let Some(new_v) = try_rewrite(r, &v, rewrites) {
            attrs[i].1 = Some(new_v);
            changed = true;
        }
    }

    let rules: Vec<CookieFlagsRule> = plcf.cookie_flags.iter().filter(|r| !matches!(r.matcher, CookieMatcher::Off)).cloned().collect();

    drop(plcf);

    if !rules.is_empty() {
        if let Some(new_attrs) = rewrite_cookie_flags(r, &rules, &attrs) {
            attrs = new_attrs;
            changed = true;
        }
    }

    if !changed {
        return NGX_DECLINED;
    }

    let mut out = Vec::new();

    for (i, (k, v)) in attrs.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(b"; ");
        }

        out.extend_from_slice(k);

        if let Some(val) = v {
            out.push(b'=');
            out.extend_from_slice(val);
        }
    }

    *h.value.borrow_mut() = out;

    NGX_OK
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


/// ngx_http_proxy_store
fn proxy_store_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<NgxHttpProxyLocConf>(conf.as_ref().unwrap());

    if cell.borrow().store.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args[1].clone();

    if value == b"off" {
        cell.borrow_mut().store = Val::set(false);
        return Ok(());
    }

    if cell.borrow().cache.cache.get_or(false) {
        return Err(msg("is incompatible with \"proxy_cache\""));
    }

    cell.borrow_mut().store = Val::set(true);

    if value == b"on" {
        return Ok(());
    }

    // the terminating '\0' the C script includes is of no use here
    let codes = crate::script::script_compile(cf, &value)?;

    cell.borrow_mut().store_values = Some(Rc::new(codes));

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

    if cell.borrow().store.get_or(false) {
        return Err(msg("is incompatible with \"proxy_store\""));
    }

    let mut ucf = std::mem::take(&mut cell.borrow_mut().cache);
    let rc = crate::upstream_cache::cache_slot(cf, &mut ucf, "ngx_http_proxy_module");
    cell.borrow_mut().cache = ucf;
    rc
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
/// ngx_http_proxy_rewrite_cookie_flags: the attributes of a cookie with
/// the flags of the proxy_cookie_flags rules its name matches; None if no
/// rule matches.
fn rewrite_cookie_flags(r: &R, rules: &[CookieFlagsRule], attrs: &[(Vec<u8>, Option<Vec<u8>>)]) -> Option<Vec<(Vec<u8>, Option<Vec<u8>>)>> {
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
    if mask == 0 { return None; }

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
    Some(new_attrs)
}
