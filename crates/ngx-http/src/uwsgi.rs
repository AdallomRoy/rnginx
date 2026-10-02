//! ngx_http_uwsgi_module
//!
//! The request is a uwsgi packet: modifier1, the 16-bit little-endian size
//! of the data, modifier2, then the params, each a 16-bit length and the
//! key, a 16-bit length and the value (ngx_http_uwsgi_create_request); the
//! request body follows the packet. The response is an HTTP status line and
//! header (ngx_http_uwsgi_process_status_line), or a CGI style header with
//! a "Status" line (ngx_http_uwsgi_process_header), then the body as the
//! upstream sends it (ngx_http_uwsgi_input_filter_init and the copy input
//! filters).
//!
//! The parts of ngx_http_upstream.c the module relies on (init_request,
//! connect, send_request, process_header, test_next, intercept_errors,
//! process_headers, send_response, the event pipe copy filter and the non
//! buffered filter, store, next and finalize_request) are driven here as
//! proxy.rs does it for the proxy module, with the uwsgi callbacks.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::event_openssl::{
    ngx_ssl_certificate, ngx_ssl_ciphers, ngx_ssl_client_session_cache, ngx_ssl_conf_commands, ngx_ssl_create, ngx_ssl_crl, ngx_ssl_read_password_file,
    ngx_ssl_trusted_certificate, NgxSsl, NGX_SSL_DEFAULT_PROTOCOLS,
};
use ngx_core::event_connect::LocalAddr;
use ngx_core::hash::{hash_key_lc, Hash, HashInit, HashKey};
use ngx_core::inet::Url;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::core::CoreLocConf;
use crate::event_pipe::EventPipe;
use crate::request::*;
use crate::script::{ComplexValue, Part};
use crate::upstream::*;
use crate::upstream_cache::{UpstreamCacheConf, UpstreamCacheLocConf, UpstreamCacheMainConf, NGX_CONF_BITMASK_SET, NGX_HTTP_UPSTREAM_INVALID_HEADER};
use crate::upstream_rt::{Upstream, UpstreamConf, UpstreamModule};
use crate::upstream_ssl::UpstreamSslConf;
use crate::*;

crate::http_module_index!("ngx_http_uwsgi_module");

/// ngx_http_uwsgi_next_upstream_masks
const UWSGI_NEXT_UPSTREAM_MASKS: &[(&str, u32)] = &[
    ("error", NGX_HTTP_UPSTREAM_FT_ERROR),
    ("timeout", NGX_HTTP_UPSTREAM_FT_TIMEOUT),
    ("invalid_header", NGX_HTTP_UPSTREAM_FT_INVALID_HEADER),
    ("non_idempotent", NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT),
    ("http_500", NGX_HTTP_UPSTREAM_FT_HTTP_500),
    ("http_503", NGX_HTTP_UPSTREAM_FT_HTTP_503),
    ("http_403", NGX_HTTP_UPSTREAM_FT_HTTP_403),
    ("http_404", NGX_HTTP_UPSTREAM_FT_HTTP_404),
    ("http_429", NGX_HTTP_UPSTREAM_FT_HTTP_429),
    ("updating", NGX_HTTP_UPSTREAM_FT_UPDATING),
    ("off", NGX_HTTP_UPSTREAM_FT_OFF),
];

/// ngx_http_uwsgi_ssl_protocols
const UWSGI_SSL_PROTOCOLS: &[(&str, u32)] = &[
    ("SSLv2", 0x0002),
    ("SSLv3", 0x0004),
    ("TLSv1", 0x0008),
    ("TLSv1.1", 0x0010),
    ("TLSv1.2", 0x0020),
    ("TLSv1.3", 0x0040),
];

/// ngx_http_uwsgi_hide_headers
const UWSGI_HIDE_HEADERS: &[&[u8]] = &[b"X-Accel-Expires", b"X-Accel-Redirect", b"X-Accel-Limit-Rate", b"X-Accel-Buffering", b"X-Accel-Charset"];

/// ngx_http_uwsgi_headers
const UWSGI_HEADERS: &[(&[u8], &[u8])] = &[(b"HTTP_HOST", b"$host$is_request_port$request_port")];

/// ngx_http_uwsgi_cache_headers
const UWSGI_CACHE_HEADERS: &[(&[u8], &[u8])] = &[
    (b"HTTP_HOST", b"$host$is_request_port$request_port"),
    (b"HTTP_IF_MODIFIED_SINCE", b"$upstream_cache_last_modified"),
    (b"HTTP_IF_UNMODIFIED_SINCE", b""),
    (b"HTTP_IF_NONE_MATCH", b"$upstream_cache_etag"),
    (b"HTTP_IF_MATCH", b""),
    (b"HTTP_RANGE", b""),
    (b"HTTP_IF_RANGE", b""),
];

pub use crate::upstream_rt::{Param as UwsgiParam, ParamSource, Params as UwsgiParams, UpstreamLocal};

/// ngx_http_uwsgi_loc_conf_t, with the fields of ngx_http_upstream_conf_t
/// the module uses.
pub struct NgxHttpUwsgiLocConf {
    /// upstream.upstream: the upstream of uwsgi_pass without variables
    pub upstream: Option<Rc<UpstreamSrvConf>>,

    /// upstream.store: unset, 0 or 1
    pub store: Val<bool>,
    /// upstream.store_lengths and store_values: the path of uwsgi_store
    pub store_values: Option<Rc<Vec<Part>>>,
    pub store_access: Val<u32>,

    pub next_upstream_tries: Val<i64>,
    pub buffering: Val<bool>,
    pub request_buffering: Val<bool>,
    pub ignore_client_abort: Val<bool>,
    pub force_ranges: Val<bool>,

    /// upstream.local: unset, NULL ("off") or the address
    pub local: Val<Option<Rc<UpstreamLocal>>>,
    pub socket_keepalive: Val<bool>,
    pub socket_rcvbuf: Val<usize>,
    pub socket_sndbuf: Val<usize>,

    pub connect_timeout: Val<u64>,
    pub send_timeout: Val<u64>,
    pub read_timeout: Val<u64>,
    pub next_upstream_timeout: Val<u64>,

    pub send_lowat: Val<usize>,
    pub buffer_size: Val<usize>,
    pub limit_rate: Val<Option<Rc<ComplexValue>>>,

    pub bufs: Bufs,
    pub busy_buffers_size_conf: Val<usize>,
    pub busy_buffers_size: usize,
    pub max_temp_file_size_conf: Val<usize>,
    pub max_temp_file_size: usize,
    pub temp_file_write_size_conf: Val<usize>,
    pub temp_file_write_size: usize,

    /// upstream.next_upstream: a bitmask, 0 when not set
    pub next_upstream: u32,
    pub temp_path: Val<Rc<PathConf>>,

    pub pass_request_headers: Val<bool>,
    pub pass_request_body: Val<bool>,
    pub intercept_errors: Val<bool>,

    /// upstream.hide_headers and pass_headers (NGX_CONF_UNSET_PTR or the
    /// list), and hide_headers_hash once built
    pub hide_headers: Val<Rc<Vec<Vec<u8>>>>,
    pub pass_headers: Val<Rc<Vec<Vec<u8>>>>,
    pub hide_headers_hash: Option<Rc<Hash<()>>>,

    /// The cache fields of upstream (uwsgi_cache, uwsgi_cache_*,
    /// uwsgi_no_cache, uwsgi_ignore_headers) and cache_key.
    pub cache: UpstreamCacheConf,

    /// The SSL fields of upstream: uwsgi_ssl_session_reuse, uwsgi_ssl_name,
    /// uwsgi_ssl_server_name, uwsgi_ssl_verify, uwsgi_ssl_certificate,
    /// uwsgi_ssl_certificate_key, uwsgi_ssl_certificate_cache,
    /// uwsgi_ssl_password_file, and the context.
    pub upstream_ssl: UpstreamSslConf,

    /// params and params_cache once built (params->hash.buckets)
    pub params: Option<Rc<UwsgiParams>>,
    pub params_cache: Option<Rc<UwsgiParams>>,
    /// params_source: the uwsgi_param of the level (NULL: none)
    pub params_source: Option<Rc<Vec<ParamSource>>>,

    /// uwsgi_lengths and uwsgi_values: the codes of a uwsgi_pass with
    /// variables
    pub uwsgi_values: Option<Rc<Vec<Part>>>,

    pub uwsgi_string: Val<Vec<u8>>,

    pub modifier1: Val<i64>,
    pub modifier2: Val<i64>,

    /// suwsgi, or uwsgi_pass with variables: the location needs the SSL
    /// context (ngx_http_uwsgi_set_ssl)
    pub ssl: bool,
    /// a bitmask, 0 when not set
    pub ssl_protocols: u32,
    pub ssl_ciphers: Val<Vec<u8>>,
    pub ssl_verify_depth: Val<i64>,
    pub ssl_trusted_certificate: Val<Vec<u8>>,
    pub ssl_crl: Val<Vec<u8>>,
    pub ssl_conf_commands: Val<Option<Vec<(Vec<u8>, Vec<u8>)>>>,

    /// uwcf->upstream as a request uses it, once merged
    pub upstream_conf: Option<Rc<UpstreamConf>>,
}

impl UpstreamCacheLocConf for NgxHttpUwsgiLocConf {
    fn upstream_cache(&mut self) -> &mut UpstreamCacheConf {
        &mut self.cache
    }
}

/// ngx_http_uwsgi_create_loc_conf
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(new_loc_conf())
}

/// The location configuration of ngx_http_uwsgi_create_loc_conf.
fn new_loc_conf() -> NgxHttpUwsgiLocConf {
    // set by ngx_pcalloc(): bufs.num = 0, ignore_headers = 0,
    // next_upstream = 0, cache_zone = NULL, cache_use_stale = 0,
    // cache_methods = 0, temp_path = NULL, hide_headers_hash = { NULL, 0 },
    // store_lengths = NULL, store_values = NULL, uwsgi_string = { 0, NULL },
    // ssl = 0, ssl_protocols = 0, ssl_ciphers = { 0, NULL },
    // ssl_trusted_certificate = { 0, NULL }, ssl_crl = { 0, NULL }
    //
    // "uwsgi_cyclic_temp_file" is disabled: upstream.cyclic_temp_file = 0,
    // upstream.change_buffering = 1, upstream.module = "uwsgi"
    NgxHttpUwsgiLocConf {
        upstream: None,
        store: Val::unset(),
        store_values: None,
        store_access: Val::unset(),
        next_upstream_tries: Val::unset(),
        buffering: Val::unset(),
        request_buffering: Val::unset(),
        ignore_client_abort: Val::unset(),
        force_ranges: Val::unset(),
        local: Val::unset(),
        socket_keepalive: Val::unset(),
        socket_rcvbuf: Val::unset(),
        socket_sndbuf: Val::unset(),
        connect_timeout: Val::unset(),
        send_timeout: Val::unset(),
        read_timeout: Val::unset(),
        next_upstream_timeout: Val::unset(),
        send_lowat: Val::unset(),
        buffer_size: Val::unset(),
        limit_rate: Val::unset(),
        bufs: Bufs::default(),
        busy_buffers_size_conf: Val::unset(),
        busy_buffers_size: 0,
        max_temp_file_size_conf: Val::unset(),
        max_temp_file_size: 0,
        temp_file_write_size_conf: Val::unset(),
        temp_file_write_size: 0,
        next_upstream: 0,
        temp_path: Val::unset(),
        pass_request_headers: Val::unset(),
        pass_request_body: Val::unset(),
        intercept_errors: Val::unset(),
        hide_headers: Val::unset(),
        pass_headers: Val::unset(),
        hide_headers_hash: None,
        cache: UpstreamCacheConf::default(),
        upstream_ssl: UpstreamSslConf::default(),
        params: None,
        params_cache: None,
        params_source: None,
        uwsgi_values: None,
        uwsgi_string: Val::unset(),
        modifier1: Val::unset(),
        modifier2: Val::unset(),
        ssl: false,
        ssl_protocols: 0,
        ssl_ciphers: Val::unset(),
        ssl_verify_depth: Val::unset(),
        ssl_trusted_certificate: Val::unset(),
        ssl_crl: Val::unset(),
        ssl_conf_commands: Val::unset(),
        upstream_conf: None,
    }
}

// ---------------------------------------------------------------------------
// the request
// ---------------------------------------------------------------------------

/// The context of the module for a request: the location's
/// configuration, ngx_http_status_t and r->state of the header parser.
struct UwsgiModule {
    lcf: Rc<RefCell<NgxHttpUwsgiLocConf>>,
    st: crate::upstream_rt::CgiHeaderParse,
}

/// ngx_http_uwsgi_handler
async fn uwsgi_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpUwsgiLocConf>(ctx_index());

    // ngx_http_upstream_create, with u->conf and u->caches of the main
    // configuration

    let (conf, uwsgi_values, ssl) = {
        let c = lcf.borrow();
        (c.upstream_conf.clone(), c.uwsgi_values.clone(), c.ssl)
    };

    let conf = match conf {
        Some(c) => c,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let caches = {
        let uwmcf = r.main_conf::<UpstreamCacheMainConf>(ctx_index());
        let caches = uwmcf.borrow().caches.clone();
        Rc::new(caches)
    };

    let mut u = Upstream::create(&r, conf, caches, b"uwsgi://");

    match uwsgi_values {
        None => {
            u.ssl = ssl;

            if ssl {
                u.set_schema(b"suwsgi://");
            }
        }

        Some(codes) => {
            if uwsgi_eval(&r, &codes, &mut u) != NGX_OK {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    {
        let uwcf = lcf.borrow();

        if !*uwcf.request_buffering && *uwcf.pass_request_body && !r.headers_in.borrow().chunked {
            r.request_body_no_buffering.set(true);
        }
    }

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    let mut m = UwsgiModule { lcf, st: crate::upstream_rt::CgiHeaderParse::new("uwsgi") };

    crate::upstream_rt::init(r, u, &mut m).await
}

/// ngx_http_uwsgi_eval: the URL of uwsgi_pass with variables, its scheme,
/// and the upstream it names (u->resolved).
fn uwsgi_eval(r: &R, codes: &[Part], u: &mut Upstream) -> i64 {
    let url = match crate::script::script_run(r, codes) {
        Some(v) => v,
        None => return NGX_ERROR,
    };

    let add = if url.len() > 8 && url[..8].eq_ignore_ascii_case(b"uwsgi://") {
        8
    } else if url.len() > 9 && url[..9].eq_ignore_ascii_case(b"suwsgi://") {
        u.ssl = true;
        9
    } else {
        0
    };

    if add > 0 {
        u.set_schema(&url[..add]);
    } else {
        u.set_schema(b"uwsgi://");
    }

    let mut url = Url::new(&url[add..]);
    url.no_resolve = true;

    if ngx_core::inet::parse_url(&mut url).is_err() {
        if let Some(err) = url.err {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "{} in upstream \"{}\"", err, B(&url.url));
        }

        return NGX_ERROR;
    }

    // u->resolved: the first address, the host, the port and no_port
    u.resolved = Some(url);

    NGX_OK
}

impl UpstreamModule for UwsgiModule {
    fn create_key(&self, r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
        create_key(r, keys)
    }

    /// ngx_http_uwsgi_create_request: the packet, then, with
    /// uwsgi_pass_request_body, the buffers of a buffered body (an
    /// unbuffered one is sent after it by ngx_http_upstream_send_request_body)
    fn create_request(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let uwcf = self.lcf.borrow();

        let packet = match create_request(r, &uwcf, u.cacheable()) {
            Ok(b) => b,
            Err(()) => return NGX_ERROR,
        };

        let mut b = Buf::from_vec(packet);
        b.flush = true;

        let mut bufs = Chain::new();
        bufs.push_back(b);

        if !r.request_body_no_buffering.get() && *uwcf.pass_request_body {
            bufs.extend(crate::upstream_rt::request_body_bufs(r));
        }

        u.request_bufs = bufs;

        NGX_OK
    }

    /// ngx_http_uwsgi_reinit_request
    fn reinit_request(&mut self, _r: &R, _u: &mut Upstream) -> i64 {
        self.st = crate::upstream_rt::CgiHeaderParse::new("uwsgi");
        NGX_OK
    }

    /// ngx_http_uwsgi_process_status_line, then ngx_http_uwsgi_process_header
    fn process_header(&mut self, r: &R, u: &mut Upstream) -> i64 {
        match crate::upstream_rt::cgi_process_status_line(r, u, &mut self.st) {
            Ok(true) => NGX_OK,
            Ok(false) => NGX_AGAIN,
            Err(_) => NGX_HTTP_UPSTREAM_INVALID_HEADER,
        }
    }

    /// ngx_http_uwsgi_input_filter_init: u->length and p->length
    fn input_filter_init(&mut self, r: &R, u: &mut Upstream, p: Option<&mut EventPipe>) -> i64 {
        http_debug!(r, "http uwsgi filter init s:{} l:{}", u.resp.status_n, u.resp.content_length_n);

        let length = crate::upstream_rt::cgi_input_length(u.resp.status_n, r.method.get() == NGX_HTTP_HEAD, u.resp.content_length_n);

        if let Some(p) = p {
            p.length = length;
        }

        u.length = length;

        NGX_OK
    }

    /// ngx_http_uwsgi_finalize_request
    fn finalize_request(&mut self, r: &R, _u: &mut Upstream, _rc: i64) {
        http_debug!(r, "finalize http uwsgi request");
    }
}

/// ngx_http_uwsgi_create_key: uwsgi_cache_key
fn create_key(r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
    let lcf = r.loc_conf::<NgxHttpUwsgiLocConf>(ctx_index());

    let cv = lcf.borrow().cache.cache_key.clone();

    let key = match cv {
        Some(cv) => match crate::script::complex_value(r, &cv) {
            Ok(k) => k,
            Err(_) => return NGX_ERROR,
        },
        None => Vec::new(),
    };

    keys.push(key);

    NGX_OK
}

/// The start of the packet: modifier1, the 16-bit little-endian size of
/// the data, modifier2.
fn packet_header(modifier1: i64, len: usize, modifier2: i64) -> [u8; 4] {
    [modifier1 as u8, (len & 0xff) as u8, ((len >> 8) & 0xff) as u8, modifier2 as u8]
}

/// A param as the packet has it: the 16-bit little-endian length and the
/// key, the 16-bit little-endian length and the value.
fn push_param(b: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    b.push((key.len() & 0xff) as u8);
    b.push(((key.len() >> 8) & 0xff) as u8);
    b.extend_from_slice(key);
    b.push((value.len() & 0xff) as u8);
    b.push(((value.len() >> 8) & 0xff) as u8);
    b.extend_from_slice(value);
}

/// ngx_http_uwsgi_create_request: the packet (u->request_bufs without the
/// body): modifier1, the size, modifier2, the params of uwsgi_param and
/// the defaults (the values of the lengths pass: the variables are cached,
/// e.flushed = 1), the request headers as HTTP_* params unless a HTTP_*
/// param of that name exists (the headers of a name are sent as one, the
/// values joined), and uwsgi_string.
fn create_request(r: &R, uwcf: &NgxHttpUwsgiLocConf, cacheable: bool) -> Result<Vec<u8>, ()> {
    let params = if cacheable { uwcf.params_cache.as_ref() } else { uwcf.params.as_ref() };

    let params = match params {
        Some(p) => p.clone(),
        None => return Err(()),
    };

    let mut len: usize = 0;
    let mut params_len: usize = 0;

    // the lengths of the params

    crate::script::script_flush_no_cacheable_variables(r, Some(&params.flushes));

    let mut values: Vec<Option<Vec<u8>>> = Vec::with_capacity(params.params.len());

    for p in params.params.iter() {
        let value = crate::proxy::run_codes(r, &p.codes);

        if p.skip_empty && value.is_empty() {
            values.push(None);
            continue;
        }

        params_len += 2 + p.key.len() + 2 + value.len();

        values.push(Some(value));
    }

    len += params_len;

    let header_params = if *uwcf.pass_request_headers {
        let headers = r.headers_in.borrow().headers.clone();

        let hidden = |lowcase_key: &[u8]| params.hides(lowcase_key);

        crate::upstream_rt::header_params(&headers, &hidden)
    } else {
        Vec::new()
    };

    for (key, value) in header_params.iter() {
        len += 2 + key.len() + 2 + value.len();
    }

    let uwsgi_string = uwcf.uwsgi_string.get();

    len += uwsgi_string.len();

    if len > 65535 {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "uwsgi request is too big: {}", len);
        return Err(());
    }

    let mut b: Vec<u8> = Vec::with_capacity(len + 4);

    b.extend_from_slice(&packet_header(*uwcf.modifier1, len, *uwcf.modifier2));

    // the values of the params (the lengths were those of these values:
    // "uwsgi request length mismatch" cannot happen)

    for (p, value) in params.params.iter().zip(values.iter()) {
        let value = match value {
            Some(v) => v,
            None => continue,
        };

        push_param(&mut b, &p.key, value);

        http_debug!(r, "uwsgi param: \"{}: {}\"", B(&p.key), B(value));
    }

    for (key, value) in header_params.iter() {
        push_param(&mut b, key, value);

        http_debug!(r, "uwsgi param: \"{}: {}\"", B(key), B(value));
    }

    b.extend_from_slice(uwsgi_string);

    Ok(b)
}

// ---------------------------------------------------------------------------
// the configuration
// ---------------------------------------------------------------------------

/// ngx_conf_merge_size_value(conf, prev, NGX_CONF_UNSET_SIZE)
fn merge_unset(conf: &mut Val<usize>, prev: &Val<usize>) {
    if !conf.is_set() {
        *conf = prev.clone();
    }
}

/// ngx_http_uwsgi_merge_loc_conf
fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let mut p = conf_cell::<NgxHttpUwsgiLocConf>(prev).borrow_mut();
    let mut c = conf_cell::<NgxHttpUwsgiLocConf>(conf).borrow_mut();

    let pagesize = ngx_core::os::pagesize();

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

    c.next_upstream_tries.merge(&p.next_upstream_tries, 0);

    c.buffering.merge(&p.buffering, true);

    c.request_buffering.merge(&p.request_buffering, true);

    c.ignore_client_abort.merge(&p.ignore_client_abort, false);

    c.force_ranges.merge(&p.force_ranges, false);

    crate::upstream_ssl::merge_ptr(&mut c.local, &p.local);

    c.socket_keepalive.merge(&p.socket_keepalive, false);

    c.socket_rcvbuf.merge(&p.socket_rcvbuf, 0);

    c.socket_sndbuf.merge(&p.socket_sndbuf, 0);

    c.connect_timeout.merge(&p.connect_timeout, 60000);

    c.send_timeout.merge(&p.send_timeout, 60000);

    c.read_timeout.merge(&p.read_timeout, 60000);

    c.next_upstream_timeout.merge(&p.next_upstream_timeout, 0);

    c.send_lowat.merge(&p.send_lowat, 0);

    c.buffer_size.merge(&p.buffer_size, pagesize);

    crate::upstream_ssl::merge_ptr(&mut c.limit_rate, &p.limit_rate);

    let prev_bufs = p.bufs;
    c.bufs.merge(&prev_bufs, 8, pagesize);

    if c.bufs.num < 2 {
        return Err(cf.emerg(format_args!("there must be at least 2 \"uwsgi_buffers\"")));
    }

    let mut size = *c.buffer_size;

    if size < c.bufs.size {
        size = c.bufs.size;
    }

    merge_unset(&mut c.busy_buffers_size_conf, &p.busy_buffers_size_conf);

    c.busy_buffers_size = match c.busy_buffers_size_conf.as_option() {
        None => 2 * size,
        Some(&s) => s,
    };

    if c.busy_buffers_size < size {
        return Err(cf.emerg(format_args!(
            "\"uwsgi_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"uwsgi_buffer_size\" and one of the \"uwsgi_buffers\""
        )));
    }

    if c.busy_buffers_size > (c.bufs.num - 1) * c.bufs.size {
        return Err(cf.emerg(format_args!("\"uwsgi_busy_buffers_size\" must be less than the size of all \"uwsgi_buffers\" minus one buffer")));
    }

    merge_unset(&mut c.temp_file_write_size_conf, &p.temp_file_write_size_conf);

    c.temp_file_write_size = match c.temp_file_write_size_conf.as_option() {
        None => 2 * size,
        Some(&s) => s,
    };

    if c.temp_file_write_size < size {
        return Err(cf.emerg(format_args!(
            "\"uwsgi_temp_file_write_size\" must be equal to or greater than the maximum of the value of \"uwsgi_buffer_size\" and one of the \"uwsgi_buffers\""
        )));
    }

    merge_unset(&mut c.max_temp_file_size_conf, &p.max_temp_file_size_conf);

    c.max_temp_file_size = match c.max_temp_file_size_conf.as_option() {
        None => 1024 * 1024 * 1024,
        Some(&s) => s,
    };

    if c.max_temp_file_size != 0 && c.max_temp_file_size < size {
        return Err(cf.emerg(format_args!(
            "\"uwsgi_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"uwsgi_buffer_size\" and one of the \"uwsgi_buffers\""
        )));
    }

    // ngx_conf_merge_bitmask_value(ignore_headers): in the cache merge below

    if c.next_upstream == 0 {
        c.next_upstream = if p.next_upstream == 0 { NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_ERROR | NGX_HTTP_UPSTREAM_FT_TIMEOUT } else { p.next_upstream };
    }

    if c.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF != 0 {
        c.next_upstream = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
    }

    {
        let mut slot = std::mem::take(&mut c.temp_path);
        merge_path_value(cf, &mut slot, &p.temp_path, ngx_core::NGX_HTTP_UWSGI_TEMP_PATH, [1, 2, 0])?;
        c.temp_path = slot;
    }

    // NGX_HTTP_CACHE: uwsgi_cache, the "zone is unknown" check and the
    // "no uwsgi_cache_key" warning, uwsgi_cache_*, uwsgi_no_cache,
    // uwsgi_cache_key (and uwsgi_ignore_headers)
    let prev_cache = p.cache.clone();
    c.cache.merge(cf, &prev_cache, "uwsgi", false)?;

    c.pass_request_headers.merge(&p.pass_request_headers, true);
    c.pass_request_body.merge(&p.pass_request_body, true);

    c.intercept_errors.merge(&p.intercept_errors, false);

    // NGX_HTTP_SSL

    uwsgi_merge_ssl(cf, &mut c, &mut p);

    c.upstream_ssl.ssl_session_reuse.merge(&p.upstream_ssl.ssl_session_reuse, true);

    if c.ssl_protocols == 0 {
        c.ssl_protocols = if p.ssl_protocols == 0 { NGX_CONF_BITMASK_SET | NGX_SSL_DEFAULT_PROTOCOLS } else { p.ssl_protocols };
    }

    c.ssl_ciphers.merge(&p.ssl_ciphers, b"DEFAULT".to_vec());

    crate::upstream_ssl::merge_ptr(&mut c.upstream_ssl.ssl_name, &p.upstream_ssl.ssl_name);
    c.upstream_ssl.ssl_server_name.merge(&p.upstream_ssl.ssl_server_name, false);
    c.upstream_ssl.ssl_verify.merge(&p.upstream_ssl.ssl_verify, false);
    c.ssl_verify_depth.merge(&p.ssl_verify_depth, 1);
    c.ssl_trusted_certificate.merge(&p.ssl_trusted_certificate, Vec::new());
    c.ssl_crl.merge(&p.ssl_crl, Vec::new());

    crate::upstream_ssl::merge_ptr(&mut c.upstream_ssl.ssl_certificate, &p.upstream_ssl.ssl_certificate);
    crate::upstream_ssl::merge_ptr(&mut c.upstream_ssl.ssl_certificate_key, &p.upstream_ssl.ssl_certificate_key);
    crate::upstream_ssl::merge_ptr(&mut c.upstream_ssl.ssl_certificate_cache, &p.upstream_ssl.ssl_certificate_cache);

    {
        let (cu, pu) = (&mut c.upstream_ssl, &mut p.upstream_ssl);
        crate::upstream_ssl::merge_ssl_passwords(cf, cu, pu)?;
    }

    crate::upstream_ssl::merge_ptr(&mut c.ssl_conf_commands, &p.ssl_conf_commands);

    if c.ssl {
        uwsgi_set_ssl(cf, &mut c)?;
    }

    c.uwsgi_string.merge(&p.uwsgi_string, Vec::new());

    hide_headers_hash(cf, &mut c, &mut p, UWSGI_HIDE_HEADERS)?;

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    let (noname, lmt_excpt, has_handler) = {
        let l = clcf.borrow();
        (l.noname, l.lmt_excpt, l.handler.is_some())
    };

    if noname && c.upstream.is_none() && c.uwsgi_values.is_none() {
        c.upstream = p.upstream.clone();

        c.uwsgi_values = p.uwsgi_values.clone();

        c.ssl = p.ssl;
    }

    if lmt_excpt && !has_handler && (c.upstream.is_some() || c.uwsgi_values.is_some()) {
        clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(uwsgi_handler(r))));
    }

    c.modifier1.merge(&p.modifier1, 0);
    c.modifier2.merge(&p.modifier2, 0);

    if c.params_source.is_none() {
        c.params = p.params.clone();
        c.params_cache = p.params_cache.clone();
        c.params_source = p.params_source.clone();
    }

    if c.params.is_none() {
        let params = crate::upstream_rt::init_params(cf, c.params_source.as_ref(), UWSGI_HEADERS, "uwsgi_params_hash")?;
        c.params = Some(params);
    }

    if c.cache.enabled() && c.params_cache.is_none() {
        let params = crate::upstream_rt::init_params(cf, c.params_source.as_ref(), UWSGI_CACHE_HEADERS, "uwsgi_params_hash")?;
        c.params_cache = Some(params);
    }

    // special handling to preserve conf->params in the "http" section to
    // inherit it to all servers

    let same_source = match (&c.params_source, &p.params_source) {
        (None, None) => true,
        (Some(a), Some(b)) => Rc::ptr_eq(a, b),
        _ => false,
    };

    if p.params.is_none() && same_source {
        p.params = c.params.clone();
        p.params_cache = c.params_cache.clone();
    }

    c.upstream_conf = Some(Rc::new(upstream_conf(&c)));

    Ok(())
}

/// uwcf->upstream, the ngx_http_upstream_conf_t of the location, as merged
fn upstream_conf(c: &NgxHttpUwsgiLocConf) -> UpstreamConf {
    UpstreamConf {
        upstream: c.upstream.clone(),
        connect_timeout: *c.connect_timeout,
        send_timeout: *c.send_timeout,
        read_timeout: *c.read_timeout,
        next_upstream_timeout: *c.next_upstream_timeout,
        send_lowat: *c.send_lowat,
        buffer_size: *c.buffer_size,
        limit_rate: c.limit_rate.as_option().cloned().flatten(),
        busy_buffers_size: c.busy_buffers_size,
        max_temp_file_size: c.max_temp_file_size,
        temp_file_write_size: c.temp_file_write_size,
        bufs: c.bufs,
        next_upstream: c.next_upstream,
        store_access: *c.store_access,
        next_upstream_tries: *c.next_upstream_tries as u32,
        buffering: *c.buffering,
        request_buffering: *c.request_buffering,
        pass_request_headers: *c.pass_request_headers,
        pass_request_body: *c.pass_request_body,
        pass_trailers: false,
        pass_early_hints: false,
        ignore_client_abort: *c.ignore_client_abort,
        intercept_errors: *c.intercept_errors,
        cyclic_temp_file: false,
        force_ranges: *c.force_ranges,
        temp_path: c.temp_path.as_option().cloned(),
        hide_headers_hash: c.hide_headers_hash.clone(),
        local: c.local.as_option().cloned().flatten(),
        socket_keepalive: *c.socket_keepalive,
        socket_rcvbuf: *c.socket_rcvbuf,
        socket_sndbuf: *c.socket_sndbuf,
        cache: c.cache.clone(),
        store: c.store.get_or(false),
        store_values: c.store_values.clone(),
        intercept_404: false,
        change_buffering: true,
        preserve_output: false,
        ignore_input: false,
        ssl: c.upstream_ssl.clone(),
        module: "uwsgi",
    }
}

/// Two lists of upstream.hide_headers or pass_headers are the same one
/// (both NGX_CONF_UNSET_PTR, or the same array).
fn same_list(a: &Val<Rc<Vec<Vec<u8>>>>, b: &Val<Rc<Vec<Vec<u8>>>>) -> bool {
    match (a.as_option(), b.as_option()) {
        (None, None) => true,
        (Some(x), Some(y)) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

/// The names of the hide headers hash: the default hide headers, those of
/// uwsgi_hide_header not among them, then for each uwsgi_pass_header the
/// first of them of its name removed (the names compare
/// case-insensitively).
fn hide_headers_names(default_hide_headers: &[&[u8]], hide: &[Vec<u8>], pass: &[Vec<u8>]) -> Vec<Vec<u8>> {
    // None for the names of uwsgi_pass_header (key.data = NULL)
    let mut hide_headers: Vec<Option<Vec<u8>>> = default_hide_headers.iter().map(|h| Some(h.to_vec())).collect();

    for h in hide.iter() {
        if hide_headers.iter().flatten().any(|k| k.eq_ignore_ascii_case(h)) {
            continue;
        }

        hide_headers.push(Some(h.clone()));
    }

    for h in pass.iter() {
        for k in hide_headers.iter_mut() {
            if k.as_ref().is_some_and(|k| k.eq_ignore_ascii_case(h)) {
                *k = None;
                break;
            }
        }
    }

    hide_headers.into_iter().flatten().collect()
}

/// ngx_http_upstream_hide_headers_hash: the default hide headers and those
/// of uwsgi_hide_header, but those of uwsgi_pass_header; inherited as a
/// whole when the level has neither directive.
fn hide_headers_hash(cf: &mut Conf, conf: &mut NgxHttpUwsgiLocConf, prev: &mut NgxHttpUwsgiLocConf, default_hide_headers: &[&[u8]]) -> ConfResult {
    if !conf.hide_headers.is_set() && !conf.pass_headers.is_set() {
        conf.hide_headers = prev.hide_headers.clone();
        conf.pass_headers = prev.pass_headers.clone();

        conf.hide_headers_hash = prev.hide_headers_hash.clone();

        if conf.hide_headers_hash.is_some() {
            return Ok(());
        }
    } else {
        if !conf.hide_headers.is_set() {
            conf.hide_headers = prev.hide_headers.clone();
        }

        if !conf.pass_headers.is_set() {
            conf.pass_headers = prev.pass_headers.clone();
        }
    }

    let hide = conf.hide_headers.as_option().map(|l| l.as_slice()).unwrap_or(&[]);
    let pass = conf.pass_headers.as_option().map(|l| l.as_slice()).unwrap_or(&[]);

    let names: Vec<HashKey<()>> = hide_headers_names(default_hide_headers, hide, pass)
        .into_iter()
        .map(|k| HashKey { key_hash: hash_key_lc(&k), key: k.to_ascii_lowercase(), value: () })
        .collect();

    let hinit = HashInit { name: "uwsgi_hide_headers_hash", max_size: 512, bucket_size: 64, log: &cf.log };

    let hash = match Hash::init(&hinit, names) {
        Ok(h) => h,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
            return Err(ConfError::Logged);
        }
    };

    conf.hide_headers_hash = Some(Rc::new(hash));

    // special handling to preserve conf->hide_headers_hash in the "http"
    // section to inherit it to all servers

    if prev.hide_headers_hash.is_none() && same_list(&conf.hide_headers, &prev.hide_headers) && same_list(&conf.pass_headers, &prev.pass_headers) {
        prev.hide_headers_hash = conf.hide_headers_hash.clone();
    }

    Ok(())
}

/// ngx_http_uwsgi_merge_ssl: the context of the parent level when the
/// level has no SSL directive, else a new one.
fn uwsgi_merge_ssl(cf: &mut Conf, conf: &mut NgxHttpUwsgiLocConf, prev: &mut NgxHttpUwsgiLocConf) {
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

    // special handling to preserve conf->upstream.ssl in the "http" section
    // to inherit it to all servers

    if preserve {
        prev.upstream_ssl.ssl = Some(ssl);
    }
}

/// ngx_http_uwsgi_set_ssl: the context of the upstream connections
fn uwsgi_set_ssl(cf: &mut Conf, uwcf: &mut NgxHttpUwsgiLocConf) -> ConfResult {
    let ssl = uwcf.upstream_ssl.ssl.clone().expect("ssl");
    let mut ssl = ssl.borrow_mut();

    if !ssl.ctx.is_null() {
        return Ok(());
    }

    if ngx_ssl_create(&mut ssl, uwcf.ssl_protocols, None) != NGX_OK {
        return Err(ConfError::Logged);
    }

    // the context is freed with the ngx_ssl_t (ngx_ssl_cleanup_ctx)

    let ciphers = uwcf.ssl_ciphers.get().clone();

    if ngx_ssl_ciphers(cf, &mut ssl, &ciphers, false) != NGX_OK {
        return Err(ConfError::Logged);
    }

    let u = &uwcf.upstream_ssl;

    if let Some(cert) = u.ssl_certificate.as_option().cloned().flatten() {
        if !cert.value.is_empty() {
            let key = match u.ssl_certificate_key.as_option().cloned().flatten() {
                Some(k) => k,
                None => {
                    ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"uwsgi_ssl_certificate_key\" is defined for certificate \"{}\"", B(&cert.value));
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
        if uwcf.ssl_trusted_certificate.get().is_empty() {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no uwsgi_ssl_trusted_certificate for uwsgi_ssl_verify");
            return Err(ConfError::Logged);
        }

        let mut trusted = uwcf.ssl_trusted_certificate.get().clone();

        if ngx_ssl_trusted_certificate(cf, &mut ssl, &mut trusted, *uwcf.ssl_verify_depth) != NGX_OK {
            return Err(ConfError::Logged);
        }

        let mut crl = uwcf.ssl_crl.get().clone();

        if ngx_ssl_crl(cf, &mut ssl, &mut crl) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    if ngx_ssl_client_session_cache(cf, &mut ssl, *u.ssl_session_reuse) != NGX_OK {
        return Err(ConfError::Logged);
    }

    let mut commands = uwcf.ssl_conf_commands.as_option().cloned().flatten();

    if ngx_ssl_conf_commands(cf, &mut ssl, commands.as_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// the directives
// ---------------------------------------------------------------------------

fn uwcf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<NgxHttpUwsgiLocConf>> {
    conf_rc::<NgxHttpUwsgiLocConf>(conf.as_ref().expect("conf"))
}

/// ngx_http_uwsgi_pass
fn uwsgi_pass(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);

    {
        let uwcf = cell.borrow();

        if uwcf.upstream.is_some() || uwcf.uwsgi_values.is_some() {
            return Err(msg("is duplicate"));
        }
    }

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(uwsgi_handler(r))));

    let url = cf.args[1].clone();

    let n = crate::script::script_variables_count(&url);

    if n != 0 {
        let codes = crate::script::script_compile(cf, &url)?;

        let mut uwcf = cell.borrow_mut();

        uwcf.uwsgi_values = Some(Rc::new(codes));
        uwcf.ssl = true;

        return Ok(());
    }

    let add = if url.len() >= 8 && url[..8].eq_ignore_ascii_case(b"uwsgi://") {
        8
    } else if url.len() >= 9 && url[..9].eq_ignore_ascii_case(b"suwsgi://") {
        cell.borrow_mut().ssl = true;
        9
    } else {
        0
    };

    let mut u = Url::new(&url[add..]);
    u.no_resolve = true;

    let uscf = upstream_add(cf, &mut u, 0)?;

    cell.borrow_mut().upstream = Some(uscf);

    let mut lc = clcf.borrow_mut();

    if lc.name.last() == Some(&b'/') {
        lc.auto_redirect = true;
    }

    Ok(())
}

/// ngx_http_uwsgi_store
fn uwsgi_store(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);

    if cell.borrow().store.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args[1].clone();

    if value == b"off" {
        cell.borrow_mut().store = Val::set(false);
        return Ok(());
    }

    if value.is_empty() {
        return Err(cf.emerg(format_args!("empty path")));
    }

    if cell.borrow().cache.cache.get_or(false) {
        return Err(msg("is incompatible with \"uwsgi_cache\""));
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

/// ngx_http_uwsgi_cache
fn uwsgi_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);

    if cell.borrow().cache.cache.is_set() {
        return Err(msg("is duplicate"));
    }

    if cf.args[1] == b"off" {
        cell.borrow_mut().cache.cache = Val::set(false);
        return Ok(());
    }

    if cell.borrow().store.get_or(false) {
        return Err(msg("is incompatible with \"uwsgi_store\""));
    }

    let mut ucf = std::mem::take(&mut cell.borrow_mut().cache);
    let rc = crate::upstream_cache::cache_slot(cf, &mut ucf, "ngx_http_uwsgi_module");
    cell.borrow_mut().cache = ucf;
    rc
}

/// ngx_http_uwsgi_ssl_certificate_cache
fn uwsgi_ssl_certificate_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);

    if cell.borrow().upstream_ssl.ssl_certificate_cache.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let mut max: i64 = 0;
    let mut inactive: i64 = 10;
    let mut valid: i64 = 60;

    for v in &value[1..] {
        let failed = |cf: &Conf| cf.emerg(format_args!("invalid parameter \"{}\"", B(v)));

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
            cell.borrow_mut().upstream_ssl.ssl_certificate_cache = Val::set(None);
            continue;
        }

        return Err(failed(cf));
    }

    if cell.borrow().upstream_ssl.ssl_certificate_cache.is_set() {
        // "off": plcf->upstream.ssl_certificate_cache == NULL
        return Ok(());
    }

    if max == 0 {
        return Err(cf.emerg(format_args!("\"uwsgi_ssl_certificate_cache\" must have the \"max\" parameter")));
    }

    let cache = ngx_core::event_openssl_cache::ngx_ssl_cache_init(max as usize, valid, inactive);

    cell.borrow_mut().upstream_ssl.ssl_certificate_cache = Val::set(Some(Rc::new(RefCell::new(cache))));

    Ok(())
}

/// ngx_http_uwsgi_ssl_password_file
fn uwsgi_ssl_password_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);

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

/// uwsgi_ssl_conf_command: ngx_conf_set_keyval_slot with
/// ngx_http_uwsgi_ssl_conf_command_check (SSL_CONF_FLAG_FILE is defined:
/// NGX_CONF_OK)
fn uwsgi_ssl_conf_command(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);
    let mut c = cell.borrow_mut();

    if !c.ssl_conf_commands.is_set() {
        c.ssl_conf_commands = Val::set(Some(Vec::new()));
    }

    c.ssl_conf_commands.0.as_mut().unwrap().as_mut().unwrap().push((cf.args[1].clone(), cf.args[2].clone()));

    Ok(())
}

/// uwsgi_modifier1, uwsgi_modifier2: ngx_conf_set_num_slot with
/// ngx_http_uwsgi_modifier_bounds (ngx_conf_check_num_bounds, 0..255)
fn uwsgi_modifier(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);
    let mut c = cell.borrow_mut();

    let slot = if cmd.name == "uwsgi_modifier1" { &mut c.modifier1 } else { &mut c.modifier2 };

    set_num(cf, cmd, slot)?;

    check_num_bounds(cf, *slot.get(), 0, 255)
}

/// uwsgi_pass_header, uwsgi_hide_header: ngx_conf_set_str_array_slot
fn uwsgi_str_array(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);
    let mut c = cell.borrow_mut();

    let slot = if cmd.name == "uwsgi_pass_header" { &mut c.pass_headers } else { &mut c.hide_headers };

    let mut list: Vec<Vec<u8>> = match slot.as_option() {
        Some(l) => l.as_ref().clone(),
        None => Vec::new(),
    };

    list.push(cf.args[1].clone());

    *slot = Val::set(Rc::new(list));

    Ok(())
}

/// uwsgi_param: ngx_http_upstream_param_set_slot
fn uwsgi_param(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);
    let mut list = cell.borrow_mut().params_source.take();
    let rc = crate::upstream_rt::param_set_slot(cf, &mut list);
    cell.borrow_mut().params_source = list;
    rc
}

/// uwsgi_bind: ngx_http_upstream_bind_set_slot
fn uwsgi_bind(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);

    if cell.borrow().local.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    if value.len() == 2 && value[1] == b"off" {
        cell.borrow_mut().local = Val::set(None);
        return Ok(());
    }

    let cv = crate::script::compile_complex_value(cf, &value[1], 0)?;

    let mut local = UpstreamLocal { addr: None, value: None, transparent: false };

    if !cv.is_constant() {
        local.value = Some(cv);
    } else {
        match ngx_core::inet::parse_addr_port(&value[1]) {
            Some(sa) => local.addr = Some(LocalAddr { sockaddr: sa, name: value[1].clone() }),
            None => return Err(cf.emerg(format_args!("invalid address \"{}\"", B(&value[1])))),
        }
    }

    if value.len() > 2 {
        if value[2] == b"transparent" {
            // NGX_HAVE_TRANSPARENT_PROXY: ccf->transparent = 1 (the worker
            // keeps CAP_NET_RAW), local->transparent = 1
            local.transparent = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    cell.borrow_mut().local = Val::set(Some(Rc::new(local)));

    Ok(())
}

/// uwsgi_ssl_protocols, uwsgi_next_upstream: ngx_conf_set_bitmask_slot
fn uwsgi_bitmask(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);
    let mut c = cell.borrow_mut();

    if cmd.name == "uwsgi_ssl_protocols" {
        set_bitmask(cf, cmd, &mut c.ssl_protocols, UWSGI_SSL_PROTOCOLS)
    } else {
        set_bitmask(cf, cmd, &mut c.next_upstream, UWSGI_NEXT_UPSTREAM_MASKS)
    }
}

/// uwsgi_ssl_session_reuse, uwsgi_ssl_server_name, uwsgi_ssl_verify:
/// ngx_conf_set_flag_slot
fn uwsgi_ssl_flag(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);
    let mut c = cell.borrow_mut();

    let slot = match cmd.name {
        "uwsgi_ssl_session_reuse" => &mut c.upstream_ssl.ssl_session_reuse,
        "uwsgi_ssl_server_name" => &mut c.upstream_ssl.ssl_server_name,
        _ => &mut c.upstream_ssl.ssl_verify,
    };

    set_flag(cf, cmd, slot)
}

/// uwsgi_ssl_name: ngx_http_set_complex_value_slot; uwsgi_ssl_certificate,
/// uwsgi_ssl_certificate_key: ngx_http_set_complex_value_zero_slot;
/// uwsgi_limit_rate: ngx_http_set_complex_value_size_slot
fn uwsgi_complex_value(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);

    let mut slot = {
        let c = cell.borrow();

        match cmd.name {
            "uwsgi_ssl_name" => c.upstream_ssl.ssl_name.clone(),
            "uwsgi_ssl_certificate" => c.upstream_ssl.ssl_certificate.clone(),
            "uwsgi_ssl_certificate_key" => c.upstream_ssl.ssl_certificate_key.clone(),
            _ => c.limit_rate.clone(),
        }
    };

    match cmd.name {
        "uwsgi_ssl_name" => crate::script::set_complex_value_slot(cf, cmd, &mut slot)?,
        "uwsgi_ssl_certificate" | "uwsgi_ssl_certificate_key" => crate::script::set_complex_value_zero_slot(cf, cmd, &mut slot)?,
        _ => crate::script::set_complex_value_size_slot(cf, cmd, &mut slot)?,
    }

    let mut c = cell.borrow_mut();

    match cmd.name {
        "uwsgi_ssl_name" => c.upstream_ssl.ssl_name = slot,
        "uwsgi_ssl_certificate" => c.upstream_ssl.ssl_certificate = slot,
        "uwsgi_ssl_certificate_key" => c.upstream_ssl.ssl_certificate_key = slot,
        _ => c.limit_rate = slot,
    }

    Ok(())
}

/// uwsgi_temp_path: ngx_conf_set_path_slot
fn uwsgi_temp_path(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);
    let mut slot = std::mem::take(&mut cell.borrow_mut().temp_path);
    let rc = set_path(cf, cmd, &mut slot);
    cell.borrow_mut().temp_path = slot;
    rc
}

/// uwsgi_cache_use_stale: ngx_conf_set_bitmask_slot with
/// ngx_http_uwsgi_next_upstream_masks
fn uwsgi_cache_use_stale(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = uwcf_of(&conf);
    let mut c = cell.borrow_mut();
    crate::upstream_cache::cache_use_stale_slot(cf, cmd, &mut c.cache, UWSGI_NEXT_UPSTREAM_MASKS)
}

pub fn uwsgi_module() -> ModuleDef {
    use crate::upstream_cache as uc;
    use ngx_core::cmd;

    type C = NgxHttpUwsgiLocConf;

    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd_fn!("uwsgi_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_pass),
        cmd_fn!("uwsgi_modifier1", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_modifier),
        cmd_fn!("uwsgi_modifier2", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_modifier),
        cmd_fn!("uwsgi_store", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_store),
        cmd!("uwsgi_store_access", F | NGX_CONF_TAKE123, ConfLevel::Loc, C, store_access, set_access),
        cmd!("uwsgi_buffering", F | NGX_CONF_FLAG, ConfLevel::Loc, C, buffering, set_flag),
        cmd!("uwsgi_request_buffering", F | NGX_CONF_FLAG, ConfLevel::Loc, C, request_buffering, set_flag),
        cmd!("uwsgi_ignore_client_abort", F | NGX_CONF_FLAG, ConfLevel::Loc, C, ignore_client_abort, set_flag),
        cmd_fn!("uwsgi_bind", F | NGX_CONF_TAKE12, ConfLevel::Loc, uwsgi_bind),
        cmd!("uwsgi_socket_keepalive", F | NGX_CONF_FLAG, ConfLevel::Loc, C, socket_keepalive, set_flag),
        cmd!("uwsgi_socket_rcvbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_rcvbuf, set_size),
        cmd!("uwsgi_socket_sndbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_sndbuf, set_size),
        cmd!("uwsgi_connect_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, connect_timeout, set_msec),
        cmd!("uwsgi_send_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, send_timeout, set_msec),
        cmd!("uwsgi_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, buffer_size, set_size),
        cmd!("uwsgi_pass_request_headers", F | NGX_CONF_FLAG, ConfLevel::Loc, C, pass_request_headers, set_flag),
        cmd!("uwsgi_pass_request_body", F | NGX_CONF_FLAG, ConfLevel::Loc, C, pass_request_body, set_flag),
        cmd!("uwsgi_intercept_errors", F | NGX_CONF_FLAG, ConfLevel::Loc, C, intercept_errors, set_flag),
        cmd!("uwsgi_read_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, read_timeout, set_msec),
        cmd!("uwsgi_buffers", F | NGX_CONF_TAKE2, ConfLevel::Loc, C, bufs, set_bufs),
        cmd!("uwsgi_busy_buffers_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, busy_buffers_size_conf, set_size),
        cmd!("uwsgi_force_ranges", F | NGX_CONF_FLAG, ConfLevel::Loc, C, force_ranges, set_flag),
        cmd_fn!("uwsgi_limit_rate", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_complex_value),
        cmd_fn!("uwsgi_cache", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_cache),
        cmd_fn!("uwsgi_cache_key", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_key_slot::<C>),
        cmd_fn!("uwsgi_cache_path", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, |cf, cmd, conf| uc::cache_path_slot(cf, cmd, conf, "ngx_http_uwsgi_module")),
        cmd_fn!("uwsgi_cache_bypass", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_bypass_slot::<C>),
        cmd_fn!("uwsgi_no_cache", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::no_cache_slot::<C>),
        cmd_fn!("uwsgi_cache_valid", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_valid_slot::<C>),
        cmd_fn!("uwsgi_cache_min_uses", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_min_uses_slot::<C>),
        cmd_fn!("uwsgi_cache_max_range_offset", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_max_range_offset_slot::<C>),
        cmd_fn!("uwsgi_cache_use_stale", F | NGX_CONF_1MORE, ConfLevel::Loc, uwsgi_cache_use_stale),
        cmd_fn!("uwsgi_cache_methods", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_methods_slot::<C>),
        cmd_fn!("uwsgi_cache_lock", F | NGX_CONF_FLAG, ConfLevel::Loc, uc::cache_lock_slot::<C>),
        cmd_fn!("uwsgi_cache_lock_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_lock_timeout_slot::<C>),
        cmd_fn!("uwsgi_cache_lock_age", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_lock_age_slot::<C>),
        cmd_fn!("uwsgi_cache_revalidate", F | NGX_CONF_FLAG, ConfLevel::Loc, uc::cache_revalidate_slot::<C>),
        cmd_fn!("uwsgi_cache_background_update", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_background_update_slot::<C>),
        cmd_fn!("uwsgi_temp_path", F | NGX_CONF_TAKE1234, ConfLevel::Loc, uwsgi_temp_path),
        cmd!("uwsgi_max_temp_file_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, max_temp_file_size_conf, set_size),
        cmd!("uwsgi_temp_file_write_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, temp_file_write_size_conf, set_size),
        cmd_fn!("uwsgi_next_upstream", F | NGX_CONF_1MORE, ConfLevel::Loc, uwsgi_bitmask),
        cmd!("uwsgi_next_upstream_tries", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_tries, set_num),
        cmd!("uwsgi_next_upstream_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_timeout, set_msec),
        cmd_fn!("uwsgi_param", F | NGX_CONF_TAKE23, ConfLevel::Loc, uwsgi_param),
        cmd!("uwsgi_string", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, uwsgi_string, set_str),
        cmd_fn!("uwsgi_pass_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_str_array),
        cmd_fn!("uwsgi_hide_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_str_array),
        cmd_fn!("uwsgi_ignore_headers", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::ignore_headers_slot::<C>),
        cmd_fn!("uwsgi_ssl_session_reuse", F | NGX_CONF_FLAG, ConfLevel::Loc, uwsgi_ssl_flag),
        cmd_fn!("uwsgi_ssl_protocols", F | NGX_CONF_1MORE, ConfLevel::Loc, uwsgi_bitmask),
        cmd!("uwsgi_ssl_ciphers", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, ssl_ciphers, set_str),
        cmd_fn!("uwsgi_ssl_name", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_complex_value),
        cmd_fn!("uwsgi_ssl_server_name", F | NGX_CONF_FLAG, ConfLevel::Loc, uwsgi_ssl_flag),
        cmd_fn!("uwsgi_ssl_verify", F | NGX_CONF_FLAG, ConfLevel::Loc, uwsgi_ssl_flag),
        cmd!("uwsgi_ssl_verify_depth", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, ssl_verify_depth, set_num),
        cmd!("uwsgi_ssl_trusted_certificate", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, ssl_trusted_certificate, set_str),
        cmd!("uwsgi_ssl_crl", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, ssl_crl, set_str),
        cmd_fn!("uwsgi_ssl_certificate", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_complex_value),
        cmd_fn!("uwsgi_ssl_certificate_key", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_complex_value),
        cmd_fn!("uwsgi_ssl_certificate_cache", F | NGX_CONF_TAKE123, ConfLevel::Loc, uwsgi_ssl_certificate_cache),
        cmd_fn!("uwsgi_ssl_password_file", F | NGX_CONF_TAKE1, ConfLevel::Loc, uwsgi_ssl_password_file),
        cmd_fn!("uwsgi_ssl_conf_command", F | NGX_CONF_TAKE2, ConfLevel::Loc, uwsgi_ssl_conf_command),
    ];

    let def = HttpModuleDef {
        create_main_conf: Some(crate::upstream_cache::create_main_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_uwsgi_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream_rt::{cgi_input_length as input_length, cgi_status, content_type_charset, header_hash_key, header_param_key, header_params, merge_params, status_failure};

    #[test]
    fn test_packet_header() {
        // modifier1, the size little-endian, modifier2
        assert_eq!(packet_header(5, 0x1234, 255), [5, 0x34, 0x12, 255]);
        assert_eq!(packet_header(0, 0, 0), [0, 0, 0, 0]);
        assert_eq!(packet_header(0, 65535, 0), [0, 0xff, 0xff, 0]);
    }

    #[test]
    fn test_push_param() {
        let mut b = Vec::new();
        push_param(&mut b, b"AB", b"xyz");
        assert_eq!(b, b"\x02\x00AB\x03\x00xyz");

        // 16-bit little-endian lengths
        let key = vec![b'K'; 300];
        let mut b = Vec::new();
        push_param(&mut b, &key, b"");
        assert_eq!(&b[..2], &[44, 1]);
        assert_eq!(&b[302..], &[0, 0]);
    }

    #[test]
    fn test_header_keys() {
        // "HTTP_" and the name in upper case with '-' as '_', other bytes
        // as they are
        assert_eq!(header_param_key(b"x-foo.Bar"), b"HTTP_X_FOO.BAR");
        assert_eq!(header_param_key(b"Cookie"), b"HTTP_COOKIE");

        // the params hash: lower case, '-' as '_'
        assert_eq!(header_hash_key(b"X-Foo_Bar"), b"x_foo_bar");
    }

    #[test]
    fn test_header_params() {
        let headers = vec![
            TableElt::new(b"Host", b"a"),
            TableElt::new(b"Cookie", b"a=1"),
            TableElt::new(b"X-Foo", b"1"),
            TableElt::new(b"cookie", b"b=2"),
            TableElt::new(b"X-Blah", b"hidden"),
            TableElt::new(b"x-foo", b"2"),
            TableElt::new(b"X-blah", b"hidden too"),
        ];

        let hidden = |k: &[u8]| k == b"x_blah";

        let params = header_params(&headers, &hidden);

        // the headers of a name are sent as the first one, "; " joins
        // cookies and ", " the others; those of the hash are not sent
        assert_eq!(
            params,
            vec![
                (b"HTTP_HOST".to_vec(), b"a".to_vec()),
                (b"HTTP_COOKIE".to_vec(), b"a=1; b=2".to_vec()),
                (b"HTTP_X_FOO".to_vec(), b"1, 2".to_vec()),
            ]
        );

        let none = |_: &[u8]| false;
        assert_eq!(header_params(&headers, &none).len(), 4);
    }

    #[test]
    fn test_cgi_status() {
        assert_eq!(cgi_status(b"200 OK"), Some(200));
        assert_eq!(cgi_status(b"404"), Some(404));
        // only the first 3 characters count
        assert_eq!(cgi_status(b"2000"), Some(200));
        // shorter than 3, or not digits: "upstream sent invalid status"
        assert_eq!(cgi_status(b"20"), None);
        assert_eq!(cgi_status(b"abc"), None);
        assert_eq!(cgi_status(b" 200"), None);
    }

    #[test]
    fn test_input_length() {
        assert_eq!(input_length(204, false, 5), 0);
        assert_eq!(input_length(304, true, 5), 0);
        // HEAD: up to the end of the connection
        assert_eq!(input_length(200, true, 5), -1);
        assert_eq!(input_length(200, false, 5), 5);
        assert_eq!(input_length(200, false, -1), -1);
    }

    #[test]
    fn test_content_type_charset() {
        assert_eq!(content_type_charset(b"text/html; charset=utf-8"), Some((9, b"utf-8".to_vec())));
        assert_eq!(content_type_charset(b"text/html;charset=\"koi8-r\""), Some((9, b"koi8-r".to_vec())));
        assert_eq!(content_type_charset(b"text/html; CHARSET=x"), Some((9, b"x".to_vec())));
        assert_eq!(content_type_charset(b"text/html; foo=bar"), None);
        assert_eq!(content_type_charset(b"text/html;   "), None);
        assert_eq!(content_type_charset(b"text/plain"), None);
        // the ";" after another parameter is found
        assert_eq!(content_type_charset(b"a; x; charset=y"), Some((4, b"y".to_vec())));
        // the character after the spaces is not looked at as a ";"
        assert_eq!(content_type_charset(b"text/html; ;charset=x"), None);
    }

    #[test]
    fn test_merge_params() {
        let source = vec![ParamSource { key: b"http_host".to_vec(), value: b"override".to_vec(), skip_empty: false }];

        let merged = merge_params(&source, UWSGI_CACHE_HEADERS);

        // uwsgi_param first, then the defaults it does not set
        assert_eq!(merged.len(), UWSGI_CACHE_HEADERS.len());
        assert_eq!(merged[0].key, b"http_host");
        assert!(!merged[0].skip_empty);
        assert_eq!(merged[1].key, b"HTTP_IF_MODIFIED_SINCE");
        assert!(merged[1..].iter().all(|p| p.skip_empty));

        let merged = merge_params(&[], UWSGI_HEADERS);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].value, b"$host$is_request_port$request_port");
    }

    #[test]
    fn test_hide_headers_names() {
        let hide = vec![b"X-Other".to_vec(), b"x-accel-expires".to_vec()];
        let pass = vec![b"X-Accel-Charset".to_vec(), b"X-Unknown".to_vec()];

        let names = hide_headers_names(UWSGI_HIDE_HEADERS, &hide, &pass);

        assert_eq!(names, vec![b"X-Accel-Expires".to_vec(), b"X-Accel-Redirect".to_vec(), b"X-Accel-Limit-Rate".to_vec(), b"X-Accel-Buffering".to_vec(), b"X-Other".to_vec()]);
    }

    #[test]
    fn test_status_failure() {
        assert_eq!(status_failure(500), NGX_HTTP_UPSTREAM_FT_HTTP_500);
        assert_eq!(status_failure(404), NGX_HTTP_UPSTREAM_FT_HTTP_404);
        assert_eq!(status_failure(429), NGX_HTTP_UPSTREAM_FT_HTTP_429);
        assert_eq!(status_failure(501), 0);
    }

    #[test]
    fn test_new_loc_conf_unset() {
        // ngx_http_uwsgi_create_loc_conf: all unset until merged
        let c = new_loc_conf();

        assert!(!c.modifier1.is_set() && !c.modifier2.is_set());
        assert!(!c.store.is_set() && !c.buffering.is_set());
        assert!(c.params_source.is_none() && c.params.is_none());
        assert!(!c.local.is_set() && !c.hide_headers.is_set());
        assert_eq!(c.next_upstream, 0);
        assert_eq!(c.bufs.num, 0);
        assert!(!c.ssl);
    }
}
