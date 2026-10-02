//! ngx_http_scgi_module
//!
//! The request is a netstring: the length of the headers, ":", the headers
//! as NUL-terminated names and values ("CONTENT_LENGTH" first, then the
//! params of scgi_param and the request headers as HTTP_* params), and ","
//! (ngx_http_scgi_create_request); the request body follows it. The
//! response is an HTTP status line and header, or a CGI style header with
//! a "Status" line (ngx_http_scgi_process_status_line and
//! ngx_http_scgi_process_header), then the body as the upstream sends it
//! (ngx_http_scgi_input_filter_init and the copy input filters). The
//! request lifecycle is that of crate::upstream_rt.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::hash::Hash;
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
use crate::upstream_rt::{CgiHeaderParse, ParamSource, Params, Upstream, UpstreamConf, UpstreamLocal, UpstreamModule};
use crate::upstream_ssl::UpstreamSslConf;
use crate::*;

crate::http_module_index!("ngx_http_scgi_module");

/// ngx_http_scgi_next_upstream_masks
const SCGI_NEXT_UPSTREAM_MASKS: &[(&str, u32)] = &[
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

/// ngx_http_scgi_hide_headers
const SCGI_HIDE_HEADERS: &[&[u8]] = &[b"Status", b"X-Accel-Expires", b"X-Accel-Redirect", b"X-Accel-Limit-Rate", b"X-Accel-Buffering", b"X-Accel-Charset"];

/// ngx_http_scgi_headers
const SCGI_HEADERS: &[(&[u8], &[u8])] = &[(b"HTTP_HOST", b"$host$is_request_port$request_port")];

/// ngx_http_scgi_cache_headers
const SCGI_CACHE_HEADERS: &[(&[u8], &[u8])] = &[
    (b"HTTP_HOST", b"$host$is_request_port$request_port"),
    (b"HTTP_IF_MODIFIED_SINCE", b"$upstream_cache_last_modified"),
    (b"HTTP_IF_UNMODIFIED_SINCE", b""),
    (b"HTTP_IF_NONE_MATCH", b"$upstream_cache_etag"),
    (b"HTTP_IF_MATCH", b""),
    (b"HTTP_RANGE", b""),
    (b"HTTP_IF_RANGE", b""),
];

/// ngx_http_scgi_loc_conf_t, with the fields of ngx_http_upstream_conf_t
/// the module uses.
pub struct NgxHttpScgiLocConf {
    /// upstream.upstream: the upstream of scgi_pass without variables
    pub upstream: Option<Rc<UpstreamSrvConf>>,

    /// upstream.store: unset, 0 or 1
    pub store: Val<bool>,
    /// upstream.store_lengths and store_values: the path of scgi_store
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

    /// The cache fields of upstream (scgi_cache, scgi_cache_*,
    /// scgi_no_cache, scgi_ignore_headers) and cache_key.
    pub cache: UpstreamCacheConf,

    /// params and params_cache once built (params->hash.buckets)
    pub params: Option<Rc<Params>>,
    pub params_cache: Option<Rc<Params>>,
    /// params_source: the scgi_param of the level (NULL: none)
    pub params_source: Option<Rc<Vec<ParamSource>>>,

    /// scgi_lengths and scgi_values: the codes of a scgi_pass with
    /// variables
    pub scgi_values: Option<Rc<Vec<Part>>>,

    /// scf->upstream as a request uses it, once merged
    pub upstream_conf: Option<Rc<UpstreamConf>>,
}

impl UpstreamCacheLocConf for NgxHttpScgiLocConf {
    fn upstream_cache(&mut self) -> &mut UpstreamCacheConf {
        &mut self.cache
    }
}

/// ngx_http_scgi_create_loc_conf
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(new_loc_conf())
}

/// The location configuration of ngx_http_scgi_create_loc_conf.
fn new_loc_conf() -> NgxHttpScgiLocConf {
    // set by ngx_pcalloc(): bufs.num = 0, ignore_headers = 0,
    // next_upstream = 0, cache_zone = NULL, cache_use_stale = 0,
    // cache_methods = 0, temp_path = NULL, hide_headers_hash = { NULL, 0 },
    // store_lengths = NULL, store_values = NULL
    //
    // "scgi_cyclic_temp_file" is disabled: upstream.cyclic_temp_file = 0,
    // upstream.change_buffering = 1, upstream.module = "scgi"
    NgxHttpScgiLocConf {
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
        params: None,
        params_cache: None,
        params_source: None,
        scgi_values: None,
        upstream_conf: None,
    }
}

// ---------------------------------------------------------------------------
// the request
// ---------------------------------------------------------------------------

/// The context of the module for a request: the location's configuration,
/// ngx_http_status_t and r->state of the header parser.
struct ScgiModule {
    lcf: Rc<RefCell<NgxHttpScgiLocConf>>,
    st: CgiHeaderParse,
}

/// ngx_http_scgi_handler
async fn scgi_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpScgiLocConf>(ctx_index());

    // ngx_http_upstream_create, with u->conf and u->caches of the main
    // configuration

    let (conf, scgi_values) = {
        let c = lcf.borrow();
        (c.upstream_conf.clone(), c.scgi_values.clone())
    };

    let conf = match conf {
        Some(c) => c,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let caches = {
        let smcf = r.main_conf::<UpstreamCacheMainConf>(ctx_index());
        let caches = smcf.borrow().caches.clone();
        caches
    };

    let mut u = Upstream::create(&r, conf, caches, b"scgi://");

    if let Some(codes) = scgi_values {
        if scgi_eval(&r, &codes, &mut u) != NGX_OK {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    {
        let scf = lcf.borrow();

        if !*scf.request_buffering && *scf.pass_request_body && !r.headers_in.borrow().chunked {
            r.request_body_no_buffering.set(true);
        }
    }

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    let mut m = ScgiModule { lcf, st: CgiHeaderParse::new("scgi") };

    crate::upstream_rt::init(r, u, &mut m).await
}

/// ngx_http_scgi_eval: the address of scgi_pass with variables, and the
/// upstream it names (u->resolved).
fn scgi_eval(r: &R, codes: &[Part], u: &mut Upstream) -> i64 {
    let url = match crate::script::script_run(r, codes) {
        Some(v) => v,
        None => return NGX_ERROR,
    };

    let mut url = Url::new(&url);
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

impl UpstreamModule for ScgiModule {
    fn create_key(&self, r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
        create_key(r, keys)
    }

    /// ngx_http_scgi_create_request: the netstring, then, with
    /// scgi_pass_request_body, the buffers of a buffered body (an
    /// unbuffered one is sent after it by ngx_http_upstream_send_request_body)
    fn create_request(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let scf = self.lcf.borrow();

        let packet = match create_request(r, &scf, u.cacheable()) {
            Ok(b) => b,
            Err(()) => return NGX_ERROR,
        };

        let mut bufs = Chain::new();
        bufs.push_back(Buf::from_vec(packet));

        // the buffers of the body follow, linked
        u.request_body_link = !r.request_body_no_buffering.get() && *scf.pass_request_body;

        u.request_bufs = bufs;

        NGX_OK
    }

    /// ngx_http_scgi_reinit_request
    fn reinit_request(&mut self, _r: &R, _u: &mut Upstream) -> i64 {
        self.st = CgiHeaderParse::new("scgi");
        NGX_OK
    }

    /// ngx_http_scgi_process_status_line, then ngx_http_scgi_process_header
    fn process_header(&mut self, r: &R, u: &mut Upstream) -> i64 {
        match crate::upstream_rt::cgi_process_status_line(r, u, &mut self.st) {
            Ok(true) => NGX_OK,
            Ok(false) => NGX_AGAIN,
            Err(_) => NGX_HTTP_UPSTREAM_INVALID_HEADER,
        }
    }

    /// ngx_http_scgi_input_filter_init: u->length and p->length
    fn input_filter_init(&mut self, r: &R, u: &mut Upstream, p: Option<&mut EventPipe>) -> i64 {
        http_debug!(r, "http scgi filter init s:{} l:{}", u.resp.status_n, u.resp.content_length_n);

        let length = crate::upstream_rt::cgi_input_length(u.resp.status_n, r.method.get() == NGX_HTTP_HEAD, u.resp.content_length_n);

        if let Some(p) = p {
            p.length = length;
        }

        u.length = length;

        NGX_OK
    }

    /// ngx_http_scgi_finalize_request
    fn finalize_request(&mut self, r: &R, _u: &mut Upstream, _rc: i64) {
        http_debug!(r, "finalize http scgi request");
    }
}

/// ngx_http_scgi_create_key: scgi_cache_key
fn create_key(r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
    let lcf = r.loc_conf::<NgxHttpScgiLocConf>(ctx_index());

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

/// ngx_http_scgi_create_request: the netstring of the request: the length
/// of the headers, ":", "CONTENT_LENGTH" and the length of the body, the
/// params of scgi_param and the defaults (the values of the lengths pass:
/// the variables are cached, e.flushed = 1), the request headers as HTTP_*
/// params unless a HTTP_* param of that name exists (the headers of a name
/// sent as one, the values joined), each name and value NUL-terminated,
/// and ",".
fn create_request(r: &R, scf: &NgxHttpScgiLocConf, cacheable: bool) -> Result<Vec<u8>, ()> {
    let content_length_n = r.headers_in.borrow().content_length_n.max(0);

    let content_length = content_length_n.to_string().into_bytes();

    let mut len = "CONTENT_LENGTH".len() + 1 + content_length.len() + 1;

    let params = if cacheable { scf.params_cache.as_ref() } else { scf.params.as_ref() };

    let params = match params {
        Some(p) => p,
        None => return Err(()),
    };

    // the lengths of the params (e.flushed: the values are evaluated once,
    // the values pass reads them)

    crate::script::script_flush_no_cacheable_variables(r, Some(&params.flushes));

    for p in params.params.iter() {
        let val_len = crate::proxy::codes_len(r, &p.codes);

        if p.skip_empty && val_len == 0 {
            continue;
        }

        len += p.key.len() + 1 + val_len + 1;
    }

    let pass_request_headers = *scf.pass_request_headers;
    let hides = |lowcase_key: &[u8]| params.hides(lowcase_key);

    if pass_request_headers {
        let hin = r.headers_in.borrow();

        crate::upstream_rt::for_each_header_param(&hin.headers, &hides, |_, key_len, val_len| {
            len += key_len + 1 + val_len + 1;
        });
    }

    // netstring: "length:" + packet + ","

    let mut b: Vec<u8> = Vec::with_capacity(20 + 1 + len + 1);

    b.extend_from_slice(len.to_string().as_bytes());
    b.extend_from_slice(b":CONTENT_LENGTH\0");
    b.extend_from_slice(&content_length);
    b.push(0);

    // the values of the params (the lengths were those of these values:
    // "scgi request length mismatch" cannot happen)

    for p in params.params.iter() {
        if p.skip_empty && crate::proxy::codes_len(r, &p.codes) == 0 {
            continue;
        }

        b.extend_from_slice(&p.key);
        b.push(0);

        let value = b.len();

        crate::proxy::append_codes(r, &p.codes, &mut b);

        http_debug!(r, "scgi param: \"{}: {}\"", B(&p.key), B(&b[value..]));

        b.push(0);
    }

    if pass_request_headers {
        let hin = r.headers_in.borrow();
        let headers = &hin.headers;

        crate::upstream_rt::for_each_header_param(headers, &hides, |i, _, _| {
            let key = b.len();

            crate::upstream_rt::push_header_param_key(&mut b, headers, i);

            let key_end = b.len();

            b.push(0);

            let value = b.len();

            crate::upstream_rt::push_header_param_value(&mut b, headers, i);

            http_debug!(r, "scgi param: \"{}: {}\"", B(&b[key..key_end]), B(&b[value..]));

            b.push(0);
        });
    }

    b.push(b',');

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

/// ngx_http_scgi_merge_loc_conf
fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let mut p = conf_cell::<NgxHttpScgiLocConf>(prev).borrow_mut();
    let mut c = conf_cell::<NgxHttpScgiLocConf>(conf).borrow_mut();

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
        return Err(cf.emerg(format_args!("there must be at least 2 \"scgi_buffers\"")));
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
            "\"scgi_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"scgi_buffer_size\" and one of the \"scgi_buffers\""
        )));
    }

    if c.busy_buffers_size > (c.bufs.num - 1) * c.bufs.size {
        return Err(cf.emerg(format_args!("\"scgi_busy_buffers_size\" must be less than the size of all \"scgi_buffers\" minus one buffer")));
    }

    merge_unset(&mut c.temp_file_write_size_conf, &p.temp_file_write_size_conf);

    c.temp_file_write_size = match c.temp_file_write_size_conf.as_option() {
        None => 2 * size,
        Some(&s) => s,
    };

    if c.temp_file_write_size < size {
        return Err(cf.emerg(format_args!(
            "\"scgi_temp_file_write_size\" must be equal to or greater than the maximum of the value of \"scgi_buffer_size\" and one of the \"scgi_buffers\""
        )));
    }

    merge_unset(&mut c.max_temp_file_size_conf, &p.max_temp_file_size_conf);

    c.max_temp_file_size = match c.max_temp_file_size_conf.as_option() {
        None => 1024 * 1024 * 1024,
        Some(&s) => s,
    };

    if c.max_temp_file_size != 0 && c.max_temp_file_size < size {
        return Err(cf.emerg(format_args!(
            "\"scgi_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"scgi_buffer_size\" and one of the \"scgi_buffers\""
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
        merge_path_value(cf, &mut slot, &p.temp_path, ngx_core::NGX_HTTP_SCGI_TEMP_PATH, [1, 2, 0])?;
        c.temp_path = slot;
    }

    // NGX_HTTP_CACHE: scgi_cache, the "zone is unknown" check and the
    // "no scgi_cache_key" warning, scgi_cache_*, scgi_no_cache,
    // scgi_cache_key (and scgi_ignore_headers)
    let prev_cache = p.cache.clone();
    c.cache.merge(cf, &prev_cache, "scgi", false)?;

    c.pass_request_headers.merge(&p.pass_request_headers, true);
    c.pass_request_body.merge(&p.pass_request_body, true);

    c.intercept_errors.merge(&p.intercept_errors, false);

    {
        let (cc, pp) = (&mut *c, &mut *p);

        crate::upstream_rt::hide_headers_hash(
            cf,
            crate::upstream_rt::HideHeaders { hide: &mut cc.hide_headers, pass: &mut cc.pass_headers, hash: &mut cc.hide_headers_hash },
            crate::upstream_rt::HideHeaders { hide: &mut pp.hide_headers, pass: &mut pp.pass_headers, hash: &mut pp.hide_headers_hash },
            SCGI_HIDE_HEADERS,
            "scgi_hide_headers_hash",
            64,
        )?;
    }

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    let (noname, lmt_excpt, has_handler) = {
        let l = clcf.borrow();
        (l.noname, l.lmt_excpt, l.handler.is_some())
    };

    if noname && c.upstream.is_none() && c.scgi_values.is_none() {
        c.upstream = p.upstream.clone();

        c.scgi_values = p.scgi_values.clone();
    }

    if lmt_excpt && !has_handler && (c.upstream.is_some() || c.scgi_values.is_some()) {
        clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(scgi_handler(r))));
    }

    if c.params_source.is_none() {
        c.params = p.params.clone();
        c.params_cache = p.params_cache.clone();
        c.params_source = p.params_source.clone();
    }

    if c.params.is_none() {
        let params = crate::upstream_rt::init_params(cf, c.params_source.as_ref(), SCGI_HEADERS, "scgi_params_hash")?;
        c.params = Some(params);
    }

    if c.cache.enabled() && c.params_cache.is_none() {
        let params = crate::upstream_rt::init_params(cf, c.params_source.as_ref(), SCGI_CACHE_HEADERS, "scgi_params_hash")?;
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

/// scf->upstream, the ngx_http_upstream_conf_t of the location, as merged
fn upstream_conf(c: &NgxHttpScgiLocConf) -> UpstreamConf {
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
        ssl: UpstreamSslConf::default(),
        module: "scgi",
    }
}

// ---------------------------------------------------------------------------
// the directives
// ---------------------------------------------------------------------------

fn scf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<NgxHttpScgiLocConf>> {
    conf_rc::<NgxHttpScgiLocConf>(conf.as_ref().expect("conf"))
}

/// ngx_http_scgi_pass
fn scgi_pass(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);

    {
        let scf = cell.borrow();

        if scf.upstream.is_some() || scf.scgi_values.is_some() {
            return Err(msg("is duplicate"));
        }
    }

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    {
        let mut lc = clcf.borrow_mut();

        lc.handler = Some(Rc::new(|r| Box::pin(scgi_handler(r))));

        if lc.name.last() == Some(&b'/') {
            lc.auto_redirect = true;
        }
    }

    let url = cf.args[1].clone();

    let n = crate::script::script_variables_count(&url);

    if n != 0 {
        let codes = crate::script::script_compile(cf, &url)?;

        cell.borrow_mut().scgi_values = Some(Rc::new(codes));

        return Ok(());
    }

    let mut u = Url::new(&url);
    u.no_resolve = true;

    let uscf = upstream_add(cf, &mut u, 0)?;

    cell.borrow_mut().upstream = Some(uscf);

    Ok(())
}

/// ngx_http_scgi_store
fn scgi_store(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);

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
        return Err(msg("is incompatible with \"scgi_cache\""));
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

/// ngx_http_scgi_cache
fn scgi_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);

    if cell.borrow().cache.cache.is_set() {
        return Err(msg("is duplicate"));
    }

    if cf.args[1] == b"off" {
        cell.borrow_mut().cache.cache = Val::set(false);
        return Ok(());
    }

    if cell.borrow().store.get_or(false) {
        return Err(msg("is incompatible with \"scgi_store\""));
    }

    let mut ucf = std::mem::take(&mut cell.borrow_mut().cache);
    let rc = crate::upstream_cache::cache_slot(cf, &mut ucf, "ngx_http_scgi_module");
    cell.borrow_mut().cache = ucf;
    rc
}

/// scgi_pass_header, scgi_hide_header: ngx_conf_set_str_array_slot
fn scgi_str_array(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);
    let mut c = cell.borrow_mut();

    let slot = if cmd.name == "scgi_pass_header" { &mut c.pass_headers } else { &mut c.hide_headers };

    crate::upstream_rt::str_array_push(slot, &cf.args[1]);

    Ok(())
}

/// scgi_param: ngx_http_upstream_param_set_slot
fn scgi_param(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);
    let mut list = cell.borrow_mut().params_source.take();
    let rc = crate::upstream_rt::param_set_slot(cf, &mut list);
    cell.borrow_mut().params_source = list;
    rc
}

/// scgi_bind: ngx_http_upstream_bind_set_slot
fn scgi_bind(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);
    let mut local = std::mem::take(&mut cell.borrow_mut().local);
    let rc = crate::upstream_rt::bind_set_slot(cf, &mut local);
    cell.borrow_mut().local = local;
    rc
}

/// scgi_next_upstream: ngx_conf_set_bitmask_slot
fn scgi_next_upstream(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);
    let mut c = cell.borrow_mut();
    set_bitmask(cf, cmd, &mut c.next_upstream, SCGI_NEXT_UPSTREAM_MASKS)
}

/// scgi_limit_rate: ngx_http_set_complex_value_size_slot
fn scgi_limit_rate(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);
    let mut slot = cell.borrow().limit_rate.clone();
    crate::script::set_complex_value_size_slot(cf, cmd, &mut slot)?;
    cell.borrow_mut().limit_rate = slot;
    Ok(())
}

/// scgi_temp_path: ngx_conf_set_path_slot
fn scgi_temp_path(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);
    let mut slot = std::mem::take(&mut cell.borrow_mut().temp_path);
    let rc = set_path(cf, cmd, &mut slot);
    cell.borrow_mut().temp_path = slot;
    rc
}

/// scgi_cache_use_stale: ngx_conf_set_bitmask_slot with
/// ngx_http_scgi_next_upstream_masks
fn scgi_cache_use_stale(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = scf_of(&conf);
    let mut c = cell.borrow_mut();
    crate::upstream_cache::cache_use_stale_slot(cf, cmd, &mut c.cache, SCGI_NEXT_UPSTREAM_MASKS)
}

pub fn scgi_module() -> ModuleDef {
    use crate::upstream_cache as uc;
    use ngx_core::cmd;

    type C = NgxHttpScgiLocConf;

    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd_fn!("scgi_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, scgi_pass),
        cmd_fn!("scgi_store", F | NGX_CONF_TAKE1, ConfLevel::Loc, scgi_store),
        cmd!("scgi_store_access", F | NGX_CONF_TAKE123, ConfLevel::Loc, C, store_access, set_access),
        cmd!("scgi_buffering", F | NGX_CONF_FLAG, ConfLevel::Loc, C, buffering, set_flag),
        cmd!("scgi_request_buffering", F | NGX_CONF_FLAG, ConfLevel::Loc, C, request_buffering, set_flag),
        cmd!("scgi_ignore_client_abort", F | NGX_CONF_FLAG, ConfLevel::Loc, C, ignore_client_abort, set_flag),
        cmd_fn!("scgi_bind", F | NGX_CONF_TAKE12, ConfLevel::Loc, scgi_bind),
        cmd!("scgi_socket_keepalive", F | NGX_CONF_FLAG, ConfLevel::Loc, C, socket_keepalive, set_flag),
        cmd!("scgi_socket_rcvbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_rcvbuf, set_size),
        cmd!("scgi_socket_sndbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_sndbuf, set_size),
        cmd!("scgi_connect_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, connect_timeout, set_msec),
        cmd!("scgi_send_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, send_timeout, set_msec),
        cmd!("scgi_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, buffer_size, set_size),
        cmd!("scgi_pass_request_headers", F | NGX_CONF_FLAG, ConfLevel::Loc, C, pass_request_headers, set_flag),
        cmd!("scgi_pass_request_body", F | NGX_CONF_FLAG, ConfLevel::Loc, C, pass_request_body, set_flag),
        cmd!("scgi_intercept_errors", F | NGX_CONF_FLAG, ConfLevel::Loc, C, intercept_errors, set_flag),
        cmd!("scgi_read_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, read_timeout, set_msec),
        cmd!("scgi_buffers", F | NGX_CONF_TAKE2, ConfLevel::Loc, C, bufs, set_bufs),
        cmd!("scgi_busy_buffers_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, busy_buffers_size_conf, set_size),
        cmd!("scgi_force_ranges", F | NGX_CONF_FLAG, ConfLevel::Loc, C, force_ranges, set_flag),
        cmd_fn!("scgi_limit_rate", F | NGX_CONF_TAKE1, ConfLevel::Loc, scgi_limit_rate),
        cmd_fn!("scgi_cache", F | NGX_CONF_TAKE1, ConfLevel::Loc, scgi_cache),
        cmd_fn!("scgi_cache_key", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_key_slot::<C>),
        cmd_fn!("scgi_cache_path", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, |cf, cmd, conf| uc::cache_path_slot(cf, cmd, conf, "ngx_http_scgi_module")),
        cmd_fn!("scgi_cache_bypass", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_bypass_slot::<C>),
        cmd_fn!("scgi_no_cache", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::no_cache_slot::<C>),
        cmd_fn!("scgi_cache_valid", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_valid_slot::<C>),
        cmd_fn!("scgi_cache_min_uses", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_min_uses_slot::<C>),
        cmd_fn!("scgi_cache_max_range_offset", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_max_range_offset_slot::<C>),
        cmd_fn!("scgi_cache_use_stale", F | NGX_CONF_1MORE, ConfLevel::Loc, scgi_cache_use_stale),
        cmd_fn!("scgi_cache_methods", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_methods_slot::<C>),
        cmd_fn!("scgi_cache_lock", F | NGX_CONF_FLAG, ConfLevel::Loc, uc::cache_lock_slot::<C>),
        cmd_fn!("scgi_cache_lock_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_lock_timeout_slot::<C>),
        cmd_fn!("scgi_cache_lock_age", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_lock_age_slot::<C>),
        cmd_fn!("scgi_cache_revalidate", F | NGX_CONF_FLAG, ConfLevel::Loc, uc::cache_revalidate_slot::<C>),
        cmd_fn!("scgi_cache_background_update", F | NGX_CONF_FLAG, ConfLevel::Loc, uc::cache_background_update_slot::<C>),
        cmd_fn!("scgi_temp_path", F | NGX_CONF_TAKE1234, ConfLevel::Loc, scgi_temp_path),
        cmd!("scgi_max_temp_file_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, max_temp_file_size_conf, set_size),
        cmd!("scgi_temp_file_write_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, temp_file_write_size_conf, set_size),
        cmd_fn!("scgi_next_upstream", F | NGX_CONF_1MORE, ConfLevel::Loc, scgi_next_upstream),
        cmd!("scgi_next_upstream_tries", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_tries, set_num),
        cmd!("scgi_next_upstream_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_timeout, set_msec),
        cmd_fn!("scgi_param", F | NGX_CONF_TAKE23, ConfLevel::Loc, scgi_param),
        cmd_fn!("scgi_pass_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, scgi_str_array),
        cmd_fn!("scgi_hide_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, scgi_str_array),
        cmd_fn!("scgi_ignore_headers", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::ignore_headers_slot::<C>),
    ];

    let def = HttpModuleDef {
        create_main_conf: Some(crate::upstream_cache::create_main_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_scgi_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_loc_conf_unset() {
        let c = new_loc_conf();
        assert!(!c.store.is_set());
        assert!(c.params_source.is_none());
        assert_eq!(c.next_upstream, 0);
    }
}
