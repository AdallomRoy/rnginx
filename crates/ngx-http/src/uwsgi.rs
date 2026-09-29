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
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::connection::NGX_ERROR_ERR;
use ngx_core::event_connect::{event_connect_peer, LocalAddr, PeerConnect, PeerSocket};
use ngx_core::event_openssl::{
    ngx_ssl_certificate, ngx_ssl_ciphers, ngx_ssl_client_session_cache, ngx_ssl_conf_commands, ngx_ssl_create, ngx_ssl_crl, ngx_ssl_read_password_file,
    ngx_ssl_trusted_certificate, NgxSsl, NGX_SSL_DEFAULT_PROTOCOLS,
};
use ngx_core::hash::{hash_key, hash_key_lc, Hash, HashInit, HashKey};
use ngx_core::inet::{SockAddr, Url};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::core::CoreLocConf;
use crate::parse::{ParseRequest, Status, NGX_HTTP_PARSE_HEADER_DONE};
use crate::proxy::{ClientWatch, ConnectError, UpstreamResponse};
use crate::request::*;
use crate::script::{ComplexValue, Part};
use crate::upstream::*;
use crate::upstream_cache::{UpstreamCacheConf, UpstreamCacheLocConf, UpstreamCacheMainConf, NGX_CONF_BITMASK_SET, NGX_HTTP_UPSTREAM_INVALID_HEADER};
use crate::upstream_ssl::{PeerConn, SslSetup, UpstreamSslConf};
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

/// ngx_http_upstream_param_t: a uwsgi_param
#[derive(Clone, Debug)]
pub struct ParamSource {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub skip_empty: bool,
}

/// A param of params->lengths and params->values: the key, "if_not_empty"
/// and the codes of the value.
pub struct UwsgiParam {
    pub key: Vec<u8>,
    pub skip_empty: bool,
    pub codes: Vec<Part>,
}

/// ngx_http_uwsgi_params_t
pub struct UwsgiParams {
    /// params->flushes: the variables of the values
    pub flushes: Vec<usize>,
    /// params->lengths and params->values
    pub params: Vec<UwsgiParam>,
    /// params->number: the HTTP_* params
    pub number: usize,
    /// params->hash: the names of the HTTP_* params after "HTTP_",
    /// lowercase; the request headers of these names are not sent
    pub hash: Hash<()>,
}

/// ngx_http_upstream_local_t: uwsgi_bind
pub struct UpstreamLocal {
    /// local->addr: the address without variables
    pub addr: Option<LocalAddr>,
    /// local->value: the address with variables
    pub value: Option<ComplexValue>,
    pub transparent: bool,
}

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
    }
}

// ---------------------------------------------------------------------------
// the request
// ---------------------------------------------------------------------------

/// u->ssl and u->resolved of the request's upstream (the schema,
/// "uwsgi://" or "suwsgi://", is only of use to the error log's upstream
/// part, which the port does not have).
#[derive(Default)]
struct UwsgiUpstream {
    ssl: bool,
    resolved: Option<Url>,
}

/// ngx_http_uwsgi_handler
async fn uwsgi_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpUwsgiLocConf>(ctx_index());

    // ngx_http_upstream_create; u->conf (the cache fields), u->caches of
    // the main configuration and u->create_key

    {
        let uwcf = lcf.borrow();
        let uwmcf = r.main_conf::<UpstreamCacheMainConf>(ctx_index());
        let caches = Rc::new(uwmcf.borrow().caches.clone());
        crate::upstream_cache::upstream_create(&r, uwcf.cache.clone(), caches, "uwsgi", uwcf.buffer_size.get_or(ngx_core::os::pagesize()));
    }

    let mut u = UwsgiUpstream::default();

    let uwsgi_values = lcf.borrow().uwsgi_values.clone();

    match uwsgi_values {
        None => {
            u.ssl = lcf.borrow().ssl;
        }
        Some(codes) => {
            if uwsgi_eval(&r, &codes, &mut u) != NGX_OK {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    // u->create_request = ngx_http_uwsgi_create_request,
    // u->reinit_request, u->process_header =
    // ngx_http_uwsgi_process_status_line, u->abort_request,
    // u->finalize_request, u->buffering, the pipe with
    // ngx_event_pipe_copy_input_filter, u->input_filter_init =
    // ngx_http_uwsgi_input_filter_init and u->input_filter =
    // ngx_http_upstream_non_buffered_filter: upstream_init_request

    {
        let uwcf = lcf.borrow();

        if !*uwcf.request_buffering && *uwcf.pass_request_body && !r.headers_in.borrow().chunked {
            r.request_body_no_buffering.set(true);
        }
    }

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init):
    // unbuffered, only what is there now, the rest is sent on as it
    // arrives (send_request_body)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    upstream_init_request(r, lcf, u).await
}

/// ngx_http_uwsgi_eval: the URL of uwsgi_pass with variables, its scheme,
/// and the upstream it names (u->resolved).
fn uwsgi_eval(r: &R, codes: &[Part], u: &mut UwsgiUpstream) -> i64 {
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

/// The key of a request header as a param: "HTTP_" and the name in upper
/// case, '-' as '_'.
fn header_param_key(name: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity("HTTP_".len() + name.len());

    key.extend_from_slice(b"HTTP_");

    for &ch in name {
        let ch = if ch.is_ascii_lowercase() {
            ch & !0x20
        } else if ch == b'-' {
            b'_'
        } else {
            ch
        };

        key.push(ch);
    }

    key
}

/// The name of a request header as the params hash has it: lower case,
/// '-' as '_'.
fn header_hash_key(name: &[u8]) -> Vec<u8> {
    name.iter()
        .map(|&ch| {
            if ch.is_ascii_uppercase() {
                ch | 0x20
            } else if ch == b'-' {
                b'_'
            } else {
                ch
            }
        })
        .collect()
}

/// The start of the packet: modifier1, the 16-bit little-endian size of
/// the data, modifier2.
fn packet_header(modifier1: i64, len: usize, modifier2: i64) -> [u8; 4] {
    [modifier1 as u8, (len & 0xff) as u8, ((len >> 8) & 0xff) as u8, modifier2 as u8]
}

/// The request headers as params: ngx_http_link_multi_headers() links the
/// headers of a name (compared case-insensitively) to the first one, which
/// is sent with the values of all, joined with "; " for "Cookie" and ", "
/// otherwise; a header is not sent when `hidden` says so of its name in
/// lower case with '-' as '_' (the params hash).
fn header_params(headers: &[Header], hidden: &dyn Fn(&[u8]) -> bool) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();

    // the headers of the params hash, and the linked ones
    let mut ignored = vec![false; headers.len()];

    for i in 0..headers.len() {
        if ignored[i] {
            continue;
        }

        let h = &headers[i];

        if hidden(&header_hash_key(&h.key)) {
            ignored[i] = true;
            continue;
        }

        let mut value = h.value.borrow().clone();

        let sep = if h.key.len() == "Cookie".len() && h.key.eq_ignore_ascii_case(b"Cookie") { b';' } else { b',' };

        for j in i + 1..headers.len() {
            let hn = &headers[j];

            if hn.key.len() == h.key.len() && hn.key.eq_ignore_ascii_case(&h.key) {
                ignored[j] = true;

                value.push(sep);
                value.push(b' ');
                value.extend_from_slice(&hn.value.borrow());
            }
        }

        out.push((header_param_key(&h.key), value));
    }

    out
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

        let hidden = |lowcase_key: &[u8]| params.number != 0 && params.hash.find(hash_key(lowcase_key), lowcase_key).is_some();

        header_params(&headers, &hidden)
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

/// The data of the memory buffers of a chain.
fn chain_data(out: &mut Vec<u8>, bufs: &Chain) {
    for b in bufs.iter() {
        if let BufData::Memory(m) = &b.data {
            let end = b.last.min(m.len());

            if b.pos < end {
                out.extend_from_slice(&m[b.pos..end]);
            }
        }
    }
}

/// The body in u->request_bufs after the packet: the request body buffers
/// (in memory or in the temporary file) with uwsgi_pass_request_body; for
/// an unbuffered body, what was read of it so far, which
/// ngx_http_upstream_send_request_body sends after the packet.
fn request_body_bytes(r: &R, uwcf: &NgxHttpUwsgiLocConf) -> Vec<u8> {
    let mut out = Vec::new();

    if r.request_body_no_buffering.get() {
        let bufs = crate::proxy::take_request_body_bufs(r);
        chain_data(&mut out, &bufs);
        return out;
    }

    if !*uwcf.pass_request_body {
        return out;
    }

    let rb = r.request_body.borrow();

    let body = match rb.as_ref() {
        Some(b) => b.clone(),
        None => return out,
    };

    let body = body.borrow();

    for b in body.bufs.iter() {
        if b.in_file {
            if let BufData::File(f) = &b.data {
                let size = (b.file_last - b.file_pos).max(0) as usize;
                let mut buf = vec![0u8; size];
                let mut off = 0usize;

                while off < size {
                    // SAFETY: buf has size bytes, off < size, and f.fd is
                    // the open temporary file of the request body.
                    let n = unsafe { libc::pread(f.fd, buf[off..].as_mut_ptr() as *mut libc::c_void, size - off, b.file_pos + off as i64) };

                    if n <= 0 {
                        break;
                    }

                    off += n as usize;
                }

                out.extend_from_slice(&buf[..off]);
            }

            continue;
        }

        if let BufData::Memory(m) = &b.data {
            let end = b.last.min(m.len());

            if b.pos < end {
                out.extend_from_slice(&m[b.pos..end]);
            }
        }
    }

    out
}

/// ngx_http_uwsgi_reinit_request and the rest of
/// ngx_http_upstream_reinit: the status and the header parser anew,
/// u->process_header = ngx_http_uwsgi_process_status_line.
struct HeaderParse {
    /// u->process_header is ngx_http_uwsgi_process_header
    status_done: bool,
    /// r->state and the header parser
    pr: ParseRequest,
    /// u->buffer.pos
    pos: usize,
}

impl HeaderParse {
    fn new() -> HeaderParse {
        HeaderParse { status_done: false, pr: ParseRequest { upstream: true, ..Default::default() }, pos: 0 }
    }
}

/// What the header parser of the response found, beyond u->headers_in:
/// X-Accel-Buffering (ngx_http_upstream_process_buffering changes
/// u->buffering).
#[derive(Default)]
struct HeaderFlags {
    buffering: Option<bool>,
}

/// ngx_http_uwsgi_process_status_line: an HTTP status line, or, if there is
/// none, the CGI style header of ngx_http_uwsgi_process_header from the
/// start. Ok(true) when the header is done, Ok(false) for more
/// (NGX_AGAIN), Err with the failure type of
/// NGX_HTTP_UPSTREAM_INVALID_HEADER.
fn process_status_line(r: &R, u: &mut UpstreamResponse, st: &mut HeaderParse, flags: &mut HeaderFlags) -> Result<bool, u32> {
    if st.status_done {
        return process_header(r, u, st, flags);
    }

    let mut p = st.pos;
    let mut status = Status::default();

    let rc = crate::parse::parse_status_line(&u.buf, &mut p, &mut status);

    if rc == NGX_AGAIN {
        return Ok(false);
    }

    if rc == NGX_ERROR {
        // u->process_header = ngx_http_uwsgi_process_header;
        // u->buffer.pos = status->line_start; r->state = 0
        st.status_done = true;
        st.pr = ParseRequest { upstream: true, ..Default::default() };

        return process_header(r, u, st, flags);
    }

    if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
        if state.status == 0 {
            state.status = status.code as i64;
        }
    }

    u.status_n = status.code as i64;
    u.status_line = u.buf[status.start..status.end].to_vec();

    http_debug!(r, "http uwsgi status {} \"{}\"", u.status_n, B(&u.status_line));

    st.pos = p;
    st.status_done = true;

    process_header(r, u, st, flags)
}

/// The first header of a name that counts (a duplicate of the headers only
/// the first of which is processed has hash 0): u->headers_in.status,
/// u->headers_in.location and the like.
fn headers_in(u: &UpstreamResponse, lowcase_key: &[u8]) -> Option<Header> {
    u.headers.iter().find(|h| h.hash.get() != 0 && h.lowcase_key == lowcase_key).cloned()
}

/// ngx_http_uwsgi_process_header: the header lines, each with the handler
/// of ngx_http_upstream_headers_in[]; when the header is done, the status
/// of the status line, of "Status", 302 with "Location", or 200.
fn process_header(r: &R, u: &mut UpstreamResponse, st: &mut HeaderParse, flags: &mut HeaderFlags) -> Result<bool, u32> {
    let invalid = NGX_HTTP_UPSTREAM_FT_INVALID_HEADER;

    loop {
        let rc = crate::parse::parse_header_line(&mut st.pr, &u.buf, &mut st.pos, true);

        if rc == NGX_OK {
            // a header line has been parsed successfully

            let pr = &st.pr;

            let key = u.buf[pr.header_name_start..pr.header_name_end].to_vec();
            let value = u.buf[pr.header_start..pr.header_end].to_vec();

            let lowcase_key = if key.len() == pr.lowcase_index { pr.lowcase_header[..key.len()].to_vec() } else { key.to_ascii_lowercase() };

            let h = TableElt::with_hash(&key, &value, pr.header_hash, lowcase_key);

            u.headers.push(h.clone());

            // hh->handler(r, h, hh->offset)
            crate::proxy::upstream_process_header_line(r, u, &h)?;

            upstream_process_accel(r, &h, flags);

            http_debug!(r, "http uwsgi header: \"{}: {}\"", B(&h.key), B(&h.value.borrow()));

            continue;
        }

        if rc == NGX_HTTP_PARSE_HEADER_DONE {
            // a whole header has been parsed successfully

            http_debug!(r, "http uwsgi header done");

            if u.status_n == 0 {
                if let Some(status) = headers_in(u, b"status") {
                    let status_line = status.value.borrow().clone();

                    // ngx_atoi(status_line->data, 3): the value is
                    // null-terminated
                    let status = match cgi_status(&status_line) {
                        Some(s) => s,
                        None => {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid status \"{}\"", B(&status_line));
                            return Err(invalid);
                        }
                    };

                    u.status_n = status;

                    if status_line.len() > 3 {
                        u.status_line = status_line;
                    }
                } else if headers_in(u, b"location").is_some() {
                    u.status_n = 302;
                    u.status_line = b"302 Moved Temporarily".to_vec();
                } else {
                    u.status_n = 200;
                    u.status_line = b"200 OK".to_vec();
                }

                if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
                    if state.status == 0 {
                        state.status = u.status_n;
                    }
                }
            }

            // done:

            if u.status_n == NGX_HTTP_SWITCHING_PROTOCOLS && !r.headers_in.borrow().upgrade.is_empty() {
                u.upgrade = true;
            }

            u.pos = st.pos;

            return Ok(true);
        }

        if rc == NGX_AGAIN {
            return Ok(false);
        }

        // rc == NGX_HTTP_PARSE_INVALID_HEADER

        let pr = &st.pr;

        let end = pr.header_end.min(u.buf.len());
        let start = pr.header_name_start.min(end);
        let ch = u.buf.get(end).copied().unwrap_or(0);

        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid header: \"{}\\x{:02x}...\"", B(&u.buf[start..end]), ch);

        return Err(invalid);
    }
}

/// The handlers of ngx_http_upstream_headers_in[] which proxy.rs applies in
/// its process_headers: ngx_http_upstream_process_limit_rate (after the
/// duplicate check, which left the hash of a duplicate 0),
/// ngx_http_upstream_process_buffering and ngx_http_upstream_process_charset.
fn upstream_process_accel(r: &R, h: &Header, flags: &mut HeaderFlags) {
    let ignores = |mask: u32| crate::upstream_cache::upstream_of(r).map(|u| u.conf.ignores(mask)).unwrap_or(false);

    match h.lowcase_key.as_slice() {
        b"x-accel-limit-rate" => {
            if h.hash.get() == 0 || ignores(NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE) {
                return;
            }

            if let Some(n) = ngx_core::string::atoi(&h.value.borrow()) {
                r.limit_rate.set(n as usize);
                r.limit_rate_set.set(true);
            }
        }

        b"x-accel-buffering" => {
            if ignores(NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING) {
                return;
            }

            // u->conf->change_buffering is set
            let v = h.value.borrow();

            if v.len() == 2 && v.eq_ignore_ascii_case(b"no") {
                flags.buffering = Some(false);
            } else if v.len() == 3 && v.eq_ignore_ascii_case(b"yes") {
                flags.buffering = Some(true);
            }
        }

        b"x-accel-charset" => {
            if ignores(NGX_HTTP_UPSTREAM_IGN_XA_CHARSET) {
                return;
            }

            r.headers_out.borrow_mut().override_charset = Some(h.value.borrow().clone());
        }

        _ => {}
    }
}

/// ngx_http_uwsgi_input_filter_init: u->length and p->length.
fn input_filter_init(r: &R, u: &UpstreamResponse) -> i64 {
    http_debug!(r, "http uwsgi filter init s:{} l:{}", u.status_n, u.content_length_n);

    input_length(u.status_n, r.method.get() == NGX_HTTP_HEAD, u.content_length_n)
}

/// The length of ngx_http_uwsgi_input_filter_init: none for 204 and 304,
/// up to the end of the connection for HEAD, else the "Content-Length"
/// (-1 if none).
fn input_length(status_n: i64, head: bool, content_length_n: i64) -> i64 {
    if status_n == NGX_HTTP_NO_CONTENT || status_n == NGX_HTTP_NOT_MODIFIED {
        0
    } else if head {
        -1
    } else {
        content_length_n
    }
}

/// The status of a "Status" header: ngx_atoi() of its first 3 characters
/// (the value is null-terminated: a shorter one is invalid).
fn cgi_status(value: &[u8]) -> Option<i64> {
    if value.len() < 3 {
        return None;
    }

    ngx_core::string::atoi(&value[..3])
}

// ngx_http_uwsgi_abort_request is not ported: ngx_http_upstream.c never
// calls u->abort_request.

/// ngx_http_uwsgi_finalize_request
fn finalize_request(r: &R, _rc: i64) {
    http_debug!(r, "finalize http uwsgi request");
}

// ---------------------------------------------------------------------------
// the upstream: ngx_http_upstream_init_request and what follows
// ---------------------------------------------------------------------------

/// How reading the response header failed.
enum HeaderError {
    /// ngx_http_upstream_next() with this failure type
    Next(u32),
    /// the client closed the connection (ngx_http_upstream_check_broken_connection)
    ClientClosed(i32),
}

/// The socket options of u->conf and u->peer.local for
/// ngx_event_connect_peer, and u->conf->connect_timeout.
struct PeerOpts {
    rcvbuf: i32,
    sndbuf: i32,
    so_keepalive: bool,
    local: Option<LocalAddr>,
    transparent: bool,
    connect_timeout: u64,
}

/// Whether a socket is a plain connection: its errors are not logged by
/// the SSL layer.
fn plain(sock: &UpstreamSock) -> bool {
    match sock {
        UpstreamSock::Conn(pc) => pc.c.ssl.borrow().is_none(),
        _ => true,
    }
}

/// ngx_http_upstream_finalize_request before the header is sent (or with
/// an rc ngx_http_finalize_request takes as it is): u->finalize_request,
/// the cache of a 502 or 504 for its uwsgi_cache_valid time; the peer and
/// the connection are freed when the handler returns.
fn finalize(r: &R, rc: i64) -> i64 {
    http_debug!(r, "finalize http upstream request: {}", rc);

    finalize_request(r, rc);

    crate::upstream_cache::finalize(r, rc, None);

    if rc != NGX_DECLINED {
        r.connection.log.set_action(Some("sending to client"));
    }

    rc
}

/// ngx_http_upstream_connect after the peer is chosen:
/// ngx_event_connect_peer, the connect timer, and on the connection
/// ngx_http_upstream_ssl_init_connection for suwsgi, or the test of the
/// connect of ngx_http_upstream_send_request. The errors are those of
/// ngx_http_upstream_next (FT_ERROR, FT_TIMEOUT: the connection is closed
/// without "close notify") or 500.
async fn connect_peer(r: &R, u: &mut UpstreamPeer, sockaddr: &SockAddr, opts: &PeerOpts, ssl: Option<&SslSetup>) -> Result<UpstreamSock, ConnectError> {
    // the action is "connecting to upstream" (ngx_http_upstream_connect)
    let log = r.connection.log.clone();

    let name = u.pc.name.clone();

    let res = event_connect_peer(&PeerSocket {
        sockaddr,
        name: &name,
        ty: libc::SOCK_STREAM,
        rcvbuf: opts.rcvbuf,
        sndbuf: opts.sndbuf,
        so_keepalive: opts.so_keepalive,
        local: opts.local.as_ref(),
        transparent: opts.transparent,
        log: &log,
        log_error: NGX_ERROR_ERR,
    });

    let (c, again) = match res {
        PeerConnect::Ok(c) => (c, false),
        PeerConnect::Again(c) => (c, true),
        PeerConnect::Declined => return Err(ConnectError::Error),
        PeerConnect::Error => return Err(ConnectError::Internal),
    };

    let pc = PeerConn { c: c.clone() };

    // c->data = r
    u.attach(&c);

    let mut deadline = None;

    if again {
        // ngx_add_timer(c->write, u->conf->connect_timeout)
        let d = Instant::now() + Duration::from_millis(opts.connect_timeout);

        if tokio::time::timeout_at(d, c.writable()).await.is_err() {
            // ngx_http_upstream_send_request_handler: c->write->timedout,
            // ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT)
            ngx_log_error!(NGX_LOG_ERR, log, Some(libc::ETIMEDOUT), "upstream timed out");
            pc.set_no_shutdown();
            return Err(ConnectError::Timeout);
        }

        deadline = Some(d);
    }

    let rc = match ssl {
        Some(ssl) => crate::upstream_ssl::ssl_init_connection(r, u, &c, ssl, deadline, opts.connect_timeout).await,

        None => {
            // ngx_http_upstream_send_request: ngx_http_upstream_test_connect
            if crate::upstream_ssl::test_connect(&c) != NGX_OK {
                Err(ConnectError::Error)
            } else {
                Ok(())
            }
        }
    };

    match rc {
        Ok(()) => Ok(UpstreamSock::Conn(pc)),
        Err(e) => {
            if !matches!(e, ConnectError::Internal) {
                pc.set_no_shutdown();
            }
            Err(e)
        }
    }
}

/// ngx_http_upstream_set_local: the address of uwsgi_bind, evaluated if it
/// has variables (an empty or invalid value: none). Err for NGX_ERROR.
fn set_local(r: &R, local: Option<&Rc<UpstreamLocal>>) -> Result<(Option<LocalAddr>, bool), ()> {
    let local = match local {
        Some(l) => l,
        None => return Ok((None, false)),
    };

    let value = match &local.value {
        None => return Ok((local.addr.clone(), local.transparent)),
        Some(cv) => cv,
    };

    let val = crate::script::complex_value(r, value).map_err(|_| ())?;

    if val.is_empty() {
        return Ok((None, local.transparent));
    }

    match ngx_core::inet::parse_addr_port(&val) {
        Some(sa) => Ok((Some(LocalAddr { sockaddr: sa, name: val }), local.transparent)),
        None => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid local address \"{}\"", B(&val));
            Ok((None, local.transparent))
        }
    }
}

/// ngx_http_upstream_init_request with the uwsgi module's callbacks, and
/// what follows up to the end of the response.
async fn upstream_init_request(r: R, lcf: Rc<RefCell<NgxHttpUwsgiLocConf>>, u: UwsgiUpstream) -> i64 {
    let ucache = match crate::upstream_cache::upstream_of(&r) {
        Some(uc) => uc,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // ngx_http_upstream_cache, then ngx_http_upstream_cache_send for a
    // response from the cache

    if ucache.conf.enabled() {
        let mut rc = crate::upstream_cache::upstream_cache_wait(&r, &ucache, &create_key).await;

        if rc == NGX_ERROR {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if rc == NGX_OK {
            rc = cache_send(&r, &lcf).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_DECLINED;
                r.cached.set(false);
                ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_MISS);
            }
        }

        if rc != NGX_DECLINED {
            return rc;
        }
    }

    // the cache is freed when the upstream is done (finalize)
    let _cache_guard = crate::upstream_cache::CacheGuard::new(&r);

    // u->store = u->conf->store
    let (store, ignore_client_abort) = {
        let c = lcf.borrow();
        (*c.store, *c.ignore_client_abort)
    };

    let cacheable = ucache.cacheable.get();

    // ngx_http_upstream_rd_check_broken_connection: a request that is not
    // cached is finalized with 499 when the client closes the connection
    let watch = if !store && !r.post_action.get() && !ignore_client_abort && !cacheable { Some(ClientWatch::new(&r)) } else { None };
    let watch = watch.as_ref();

    // u->request_bufs = r->request_body->bufs; u->create_request(r)

    let (request, body) = {
        let c = lcf.borrow();

        let request = match create_request(&r, &c, cacheable) {
            Ok(b) => b,
            Err(()) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
        };

        (request, request_body_bytes(&r, &c))
    };

    // ngx_http_upstream_set_local, the socket options

    let local = lcf.borrow().local.as_option().cloned().flatten();

    let (local, transparent) = match set_local(&r, local.as_ref()) {
        Ok(l) => l,
        Err(()) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let (opts, ssl_setup, next_upstream, next_upstream_tries, next_upstream_timeout, static_upstream) = {
        let c = lcf.borrow();

        let opts = PeerOpts {
            rcvbuf: *c.socket_rcvbuf as i32,
            sndbuf: *c.socket_sndbuf as i32,
            so_keepalive: *c.socket_keepalive,
            local,
            transparent,
            connect_timeout: *c.connect_timeout,
        };

        // u->ssl: ngx_http_upstream_ssl_init_connection after connecting,
        // with u->conf's SSL fields
        let ssl_setup = if u.ssl { Some(SslSetup { conf: c.upstream_ssl.clone(), alpn: Vec::new() }) } else { None };

        (opts, ssl_setup, c.next_upstream, *c.next_upstream_tries as u32, *c.next_upstream_timeout, c.upstream.clone())
    };

    // the upstream of u->resolved (by host and port), its address, or the
    // addresses the resolver finds; or u->conf->upstream

    let tag = Rc::as_ptr(&lcf) as *const () as usize;

    let peer = match (&u.resolved, static_upstream.as_ref()) {
        (Some(url), _) => UpstreamPeer::resolve(&r, url, next_upstream, next_upstream_tries, next_upstream_timeout, tag).await,
        (None, Some(uscf)) => UpstreamPeer::init(&r, uscf, next_upstream, next_upstream_tries, next_upstream_timeout, tag),
        (None, None) => {
            ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "no upstream configuration");
            Err(NGX_HTTP_INTERNAL_SERVER_ERROR)
        }
    };

    let peer = match peer {
        Ok(p) => p,
        Err(rc) => return finalize(&r, rc),
    };

    // the peer is freed when the request is done
    let mut g = PeerGuard::new(&r, peer);

    let (conf_buffering, read_timeout, send_timeout, buffer_size, tcp_nodelay) = {
        let c = lcf.borrow();
        (*c.buffering, *c.read_timeout, *c.send_timeout, *c.buffer_size, *r.clcf().borrow().tcp_nodelay)
    };

    // u->buffer.pos += r->cache->header_start: the header of the cache file
    // goes before the response header in u->buffer
    let header_buffer_size = match crate::file_cache::cache_of(&r) {
        Some(c) => buffer_size.saturating_sub(c.borrow().header_start),
        None => buffer_size,
    };

    let mut sock: UpstreamSock;
    let mut resp: UpstreamResponse;
    let mut flags: HeaderFlags;

    'retry: loop {
        // ngx_http_upstream_connect

        r.connection.log.set_action(Some("connecting to upstream"));

        let rc = g.u.connect(&r);

        if rc == NGX_ERROR {
            return finalize(&r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        if rc == NGX_BUSY {
            match g.u.next(&r, NGX_HTTP_UPSTREAM_FT_NOLIVE) {
                Ok(()) => continue 'retry,
                Err(st) => return next_failed(&r, &lcf, NGX_HTTP_UPSTREAM_FT_NOLIVE, st).await,
            }
        }

        let try_started = g.u.start_time;

        sock = if rc == NGX_DONE {
            // a cached keepalive connection; c->data = r
            let c = g.u.pc.connection.take().unwrap();
            g.u.attach_sock(&c.sock);
            c.sock
        } else {
            let sockaddr = match g.u.pc.sockaddr.clone() {
                Some(sa) => sa,
                None => return finalize(&r, NGX_HTTP_INTERNAL_SERVER_ERROR),
            };

            let connected = {
                let connect = connect_peer(&r, &mut g.u, &sockaddr, &opts, ssl_setup.as_ref());

                tokio::select! {
                    res = connect => res,
                    err = crate::proxy::client_closed(watch) => return finalize(&r, crate::proxy::client_closed_request(&r, err)),
                }
            };

            match connected {
                Ok(s) => s,
                Err(e) => {
                    let ft = match e {
                        ConnectError::Error => NGX_HTTP_UPSTREAM_FT_ERROR,
                        ConnectError::Timeout => NGX_HTTP_UPSTREAM_FT_TIMEOUT,
                        ConnectError::Internal => return finalize(&r, NGX_HTTP_INTERNAL_SERVER_ERROR),
                    };

                    match g.u.next(&r, ft) {
                        Ok(()) => continue 'retry,
                        Err(st) => return next_failed(&r, &lcf, ft, st).await,
                    }
                }
            }
        };

        // ngx_http_upstream_send_request

        http_debug!(r, "http upstream send request");

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            if st.connect_time == u64::MAX {
                st.connect_time = ngx_core::times::current_msec().saturating_sub(try_started);
            }
        }

        // the packet (u->request_bufs) and the body that goes with it, in
        // one write

        let mut wire: Vec<u8> = Vec::with_capacity(request.len() + body.len());
        wire.extend_from_slice(&request);
        wire.extend_from_slice(&body);

        g.u.request_sent = true;

        if r.request_body_no_buffering.get() && tcp_nodelay {
            // ngx_http_upstream_send_request_body: ngx_tcp_nodelay(c)
            if let UpstreamSock::Conn(pc) = &sock {
                if !pc.c.set_tcp_nodelay() {
                    match g.u.next(&r, NGX_HTTP_UPSTREAM_FT_ERROR) {
                        Ok(()) => continue 'retry,
                        Err(st) => return next_failed(&r, &lcf, NGX_HTTP_UPSTREAM_FT_ERROR, st).await,
                    }
                }
            }
        }

        r.connection.log.set_action(Some("sending request to upstream"));

        let written = {
            let write = write_request(&mut sock, &wire, send_timeout);

            tokio::select! {
                res = write => res,
                err = crate::proxy::client_closed(watch) => return finalize(&r, crate::proxy::client_closed_request(&r, err)),
            }
        };

        let failure: Option<u32> = match written {
            Ok(()) => None,
            Err(Some(e)) => {
                if plain(&sock) {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, e.raw_os_error(), "writev() failed");
                }
                Some(NGX_HTTP_UPSTREAM_FT_ERROR)
            }
            Err(None) => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
                Some(NGX_HTTP_UPSTREAM_FT_TIMEOUT)
            }
        };

        if let Some(ft) = failure {
            match g.u.next(&r, ft) {
                Ok(()) => continue 'retry,
                Err(st) => return next_failed(&r, &lcf, ft, st).await,
            }
        }

        let mut bytes_sent = wire.len() as i64;

        if r.reading_body.get() {
            // the rest of an unbuffered body as it arrives
            match crate::proxy::send_request_body(&r, &mut sock, &chain_data).await {
                Ok(n) => bytes_sent += n,
                Err(rc) => {
                    if rc == NGX_HTTP_BAD_GATEWAY {
                        // the upstream write failed
                        match g.u.next(&r, NGX_HTTP_UPSTREAM_FT_ERROR) {
                            Ok(()) => continue 'retry,
                            Err(st) => return next_failed(&r, &lcf, NGX_HTTP_UPSTREAM_FT_ERROR, st).await,
                        }
                    }

                    return finalize(&r, rc);
                }
            }
        }

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.bytes_sent = bytes_sent;
        }

        // ngx_http_upstream_process_header

        flags = HeaderFlags::default();

        resp = match read_header(&r, &mut sock, header_buffer_size, read_timeout, watch, &mut flags).await {
            Ok(h) => h,
            Err(HeaderError::Next(ft)) => match g.u.next(&r, ft) {
                Ok(()) => continue 'retry,
                Err(st) => return next_failed(&r, &lcf, ft, st).await,
            },
            Err(HeaderError::ClientClosed(err)) => return finalize(&r, crate::proxy::client_closed_request(&r, err)),
        };

        // u->state->header_time
        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.header_time = ngx_core::times::current_msec().saturating_sub(try_started);
        }

        // u->headers_in, for $upstream_http_* and the balancer's notify
        *r.upstream_headers_in.borrow_mut() = resp.headers.iter().filter(|h| h.hash.get() != 0).cloned().collect();

        // ngx_http_upstream_test_next: a status uwsgi_next_upstream names,
        // with tries left

        if resp.status_n >= NGX_HTTP_SPECIAL_RESPONSE {
            let ft = status_failure(resp.status_n);

            if ft != 0 {
                let mut mask = ft;

                if g.u.request_sent && matches!(r.method.get(), NGX_HTTP_POST | NGX_HTTP_LOCK | NGX_HTTP_PATCH) {
                    mask |= NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
                }

                if g.u.pc.tries > 1
                    && next_upstream & mask == mask
                    && !(g.u.request_sent && r.request_body_no_buffering.get())
                    && !(next_upstream_timeout != 0 && ngx_core::times::current_msec().saturating_sub(g.u.pc.start_time) >= next_upstream_timeout)
                {
                    match g.u.next(&r, ft) {
                        Ok(()) => continue 'retry,
                        Err(st) => return next_failed(&r, &lcf, ft, st).await,
                    }
                }
            }
        }

        break 'retry;
    }

    let status = resp.status_n;

    if status >= NGX_HTTP_SPECIAL_RESPONSE {
        // ngx_http_upstream_test_next: the stale response instead of the
        // status uwsgi_cache_use_stale names

        let ft = status_failure(status);

        if ft != 0 && crate::upstream_cache::test_next_stale(&r, ft) {
            // u->reinit_request(r)

            drop(sock);
            g.finalize();

            ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_STALE);

            let mut rc = cache_send(&r, &lcf).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return finalize(&r, rc);
        }

        // the expired response was revalidated

        if crate::upstream_cache::test_next_not_modified(&r, status) {
            let saved = crate::upstream_cache::not_modified_start(&r);

            // u->reinit_request(r)

            drop(sock);
            g.finalize();

            let mut rc = cache_send(&r, &lcf).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            // u->headers_in.status_n: that of the cached response now
            let cached_status = r.headers_out.borrow().status;

            crate::upstream_cache::not_modified_finish(&r, saved, cached_status);

            return finalize(&r, rc);
        }

        // ngx_http_upstream_intercept_errors: the error_page of the status
        // instead of the response

        let intercept = *lcf.borrow().intercept_errors;

        let has_page = intercept && r.clcf().borrow().error_pages.as_ref().map(|pages| pages.iter().any(|p| p.status == status)).unwrap_or(false);

        if has_page {
            if status == NGX_HTTP_UNAUTHORIZED {
                // the WWW-Authenticate of the upstream goes with the error page
                let mut ho = r.headers_out.borrow_mut();

                for h in resp.headers.iter().filter(|h| h.hash.get() != 0 && h.lowcase_key == b"www-authenticate") {
                    let ho_h = TableElt::new(&h.key, &h.value.borrow());
                    ho.headers.push(ho_h.clone());
                    ho.www_authenticate.push(ho_h);
                }
            }

            // the status is cached as an error of the keys zone
            crate::upstream_cache::intercept_errors(&r, status, &resp.cache);

            drop(sock);
            g.finalize();

            return finalize(&r, status);
        }
    }

    // peer.notify(NGX_HTTP_UPSTREAM_NOTIFY_HEADER)
    g.u.notify(&r, NGX_HTTP_UPSTREAM_NOTIFY_HEADER);

    // ngx_http_upstream_process_headers

    if let Processed::Redirect(xar) = process_headers(&r, &lcf, &resp) {
        // ngx_http_upstream_finalize_request(r, u, NGX_DECLINED), then the
        // redirect
        drop(sock);
        g.finalize();
        finalize(&r, NGX_DECLINED);

        return accel_redirect(&r, &xar).await;
    }

    // u->buffering, as X-Accel-Buffering left it
    let buffering = flags.buffering.unwrap_or(conf_buffering);

    // ngx_http_upstream_send_response

    let rc = crate::core_rt::send_header(&r).await;

    if rc == NGX_ERROR || rc > NGX_OK || r.post_action.get() {
        return finalize(&r, rc);
    }

    if resp.upgrade {
        crate::upstream_cache::free(&r, None);

        return upgrade(&r, sock, &resp, read_timeout).await;
    }

    let header_only = r.header_only.get();

    // p->downstream_error of a header only response read for the cache
    // or uwsgi_store
    let mut downstream = true;

    if header_only {
        if !buffering {
            return finalize(&r, rc);
        }

        if !ucache.cacheable.get() && !store {
            return finalize(&r, rc);
        }

        downstream = false;
    }

    let mut writer: Option<crate::upstream_cache::CacheWriter> = None;

    let (limit_rate, capture) = if !buffering {
        crate::upstream_cache::free(&r, None);

        // ngx_tcp_nodelay(c) of the client connection
        if tcp_nodelay && r.stream.borrow().is_none() && !r.connection.set_tcp_nodelay() {
            return finalize(&r, NGX_ERROR);
        }

        (0, false)
    } else {
        // the cache: uwsgi_no_cache, the valid time, the header of the cache
        // file; p->temp_file with it (p->buf_to_file)

        match crate::upstream_cache::send_response(&r, status, &resp.cache, resp.pos) {
            Err(()) => return finalize(&r, NGX_ERROR),

            Ok(Some(header)) => {
                let temp_path = lcf.borrow().temp_path.as_option().cloned();

                writer = crate::upstream_cache::CacheWriter::new(&r, temp_path.as_deref(), &header, &resp.buf[..resp.pos]);

                if writer.is_none() {
                    return finalize(&r, NGX_ERROR);
                }
            }

            Ok(None) => {}
        }

        if header_only && !ucache.cacheable.get() && !store {
            return finalize(&r, 0);
        }

        // p->limit_rate = ngx_http_complex_value_size(r, u->conf->limit_rate, 0)
        let lr = lcf.borrow().limit_rate.as_option().cloned().flatten();

        (crate::script::complex_value_size(&r, &lr, 0), ucache.cacheable.get() || store)
    };

    // u->input_filter_init(): p->length, u->length
    let length = input_filter_init(&r, &resp);

    // uwsgi_store is of the pipe of a buffered response
    let store = store && buffering;

    let body = send_response_body(
        &r,
        &mut sock,
        &resp,
        length,
        BodyParams { buffering, limit_rate, downstream, capture, store, read_timeout, buffer_size },
        watch,
        &mut writer,
    )
    .await;

    // ngx_http_upstream_process_request: ngx_http_upstream_store() and the
    // cache file

    if store && (body.upstream_done || body.eof) && status == NGX_HTTP_OK && (body.upstream_done || length == -1) && (resp.content_length_n == -1 || resp.content_length_n == body.data.len() as i64) {
        upstream_store(&r, &lcf, &resp, &body.data);
    }

    if let Some(w) = writer {
        w.finish(&r, body.upstream_done, body.eof && length == -1, resp.content_length_n);
    }

    // ngx_http_upstream_finalize_request
    let rc = finalize_body(&r, &body).await;

    finalize(&r, rc)
}

/// The end of ngx_http_upstream_finalize_request after the header was sent,
/// while "sending to client": the last buffer of a complete response; for
/// an error of the upstream (rc >= NGX_HTTP_SPECIAL_RESPONSE) NGX_ERROR,
/// with a flush and no keepalive; nothing more when the client connection
/// failed (p->downstream_error) or for a header only response.
async fn finalize_body(r: &R, body: &BodyResult) -> i64 {
    r.connection.log.set_action(Some("sending to client"));

    match body.end {
        BodyEnd::Done => {
            if r.header_only.get() || !body.downstream {
                return NGX_OK;
            }

            // ngx_http_upstream_process_trailers: uwsgi passes none
            crate::special_response::send_special(r, true).await
        }

        BodyEnd::UpstreamError => {
            if r.header_only.get() || !body.downstream {
                return NGX_ERROR;
            }

            r.keepalive.set(false);

            crate::special_response::send_special(r, false).await
        }

        BodyEnd::Error => NGX_ERROR,

        BodyEnd::Status(rc) => rc,
    }
}

/// The request written as ngx_http_upstream_send_request writes it: the
/// uwsgi_send_timeout timer is armed while a write waits, and again after
/// each write that made progress. Err(None) when it expires.
async fn write_request(sock: &mut UpstreamSock, data: &[u8], send_timeout: u64) -> Result<(), Option<std::io::Error>> {
    let mut off = 0;

    while off < data.len() {
        match tokio::time::timeout(Duration::from_millis(send_timeout), sock.write(&data[off..])).await {
            Err(_) => return Err(None),
            Ok(Err(e)) => return Err(Some(e)),
            Ok(Ok(0)) => return Err(Some(std::io::Error::from(std::io::ErrorKind::WriteZero))),
            Ok(Ok(n)) => off += n,
        }
    }

    Ok(())
}

/// The failure type of ngx_http_upstream_next_errors[] for a status.
fn status_failure(status: i64) -> u32 {
    match status {
        500 => NGX_HTTP_UPSTREAM_FT_HTTP_500,
        502 => NGX_HTTP_UPSTREAM_FT_HTTP_502,
        503 => NGX_HTTP_UPSTREAM_FT_HTTP_503,
        504 => NGX_HTTP_UPSTREAM_FT_HTTP_504,
        403 => NGX_HTTP_UPSTREAM_FT_HTTP_403,
        404 => NGX_HTTP_UPSTREAM_FT_HTTP_404,
        429 => NGX_HTTP_UPSTREAM_FT_HTTP_429,
        _ => 0,
    }
}

/// ngx_http_upstream_process_header: the response header read into
/// u->buffer and parsed by u->process_header. The action stays "reading
/// response header from upstream" while the response is processed. The
/// uwsgi_read_timeout timer is that ngx_http_upstream_send_request armed
/// once the request was sent: the reads of the header do not arm it again.
async fn read_header(r: &R, sock: &mut UpstreamSock, buffer_size: usize, read_timeout: u64, watch: Option<&ClientWatch>, flags: &mut HeaderFlags) -> Result<UpstreamResponse, HeaderError> {
    http_debug!(r, "http upstream process header");

    r.connection.log.set_action(Some("reading response header from upstream"));

    let deadline = Instant::now() + Duration::from_millis(read_timeout);

    let mut u = UpstreamResponse::new();

    // u->process_header = ngx_http_uwsgi_process_status_line, r->state = 0
    let mut st = HeaderParse::new();

    let mut chunk = vec![0u8; buffer_size.max(1)];

    loop {
        // c->recv() into what is left of u->buffer
        let room = buffer_size.saturating_sub(u.buf.len()).clamp(1, chunk.len());

        let res = {
            let read = tokio::time::timeout_at(deadline, sock.read(&mut chunk[..room]));

            tokio::select! {
                res = read => res,
                err = crate::proxy::client_closed(watch) => return Err(HeaderError::ClientClosed(err)),
            }
        };

        let n = match res {
            Err(_) => {
                // c->read->timedout: ngx_http_upstream_next(FT_TIMEOUT)
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
                return Err(HeaderError::Next(NGX_HTTP_UPSTREAM_FT_TIMEOUT));
            }
            Ok(Err(e)) => {
                if plain(sock) {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, e.raw_os_error(), "recv() failed");
                }
                return Err(HeaderError::Next(NGX_HTTP_UPSTREAM_FT_ERROR));
            }
            Ok(Ok(0)) => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection");
                return Err(HeaderError::Next(NGX_HTTP_UPSTREAM_FT_ERROR));
            }
            Ok(Ok(n)) => n,
        };

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.bytes_received += n as i64;
        }

        u.buf.extend_from_slice(&chunk[..n]);

        // rc = u->process_header(r)

        match process_status_line(r, &mut u, &mut st, flags) {
            Ok(true) => return Ok(u),

            Ok(false) => {
                // NGX_AGAIN
                if u.buf.len() >= buffer_size {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent too big header");
                    return Err(HeaderError::Next(NGX_HTTP_UPSTREAM_FT_INVALID_HEADER));
                }
            }

            Err(ft) => return Err(HeaderError::Next(ft)),
        }
    }
}

/// What ngx_http_upstream_process_headers ends with.
enum Processed {
    /// the headers are in headers_out
    Ok,
    /// X-Accel-Redirect: the upstream is finalized (NGX_DECLINED), then the
    /// request redirected
    Redirect(Vec<u8>),
}

/// The headers of ngx_http_upstream_headers_in[] with "redirect": copied
/// before an X-Accel-Redirect.
const REDIRECT_HEADERS: &[&[u8]] = &[b"content-type", b"set-cookie", b"content-disposition", b"cache-control", b"expires", b"accept-ranges"];

/// The charset of ngx_http_upstream_copy_content_type: the length of the
/// type before the ";" of a "charset=" parameter, and the charset without
/// quotes. As the C loop does, the character after the spaces that follow
/// a ";" is not looked at as a ";" again.
fn content_type_charset(value: &[u8]) -> Option<(usize, Vec<u8>)> {
    let mut p = 0;

    while p < value.len() {
        if value[p] != b';' {
            p += 1;
            continue;
        }

        let last = p;

        p += 1;

        while p < value.len() && value[p] == b' ' {
            p += 1;
        }

        if p == value.len() {
            return None;
        }

        if value.len() - p < 8 || !value[p..p + 8].eq_ignore_ascii_case(b"charset=") {
            // the p++ of the for loop
            p += 1;
            continue;
        }

        p += 8;

        if p < value.len() && value[p] == b'"' {
            p += 1;
        }

        let mut end = value.len();

        if end > p && value[end - 1] == b'"' {
            end -= 1;
        }

        let charset = if end > p { value[p..end].to_vec() } else { Vec::new() };

        return Some((last, charset));
    }

    None
}

/// The copy handlers of ngx_http_upstream_headers_in[] (of a module
/// without u->rewrite_redirect and u->rewrite_cookie), and
/// ngx_http_upstream_copy_header_line for the other headers: the header
/// goes to r->headers_out.
fn copy_header(r: &R, u: &UpstreamResponse, h: &Header, force_ranges: bool) {
    let value = h.value.borrow();

    let mut ho = r.headers_out.borrow_mut();

    match h.lowcase_key.as_slice() {
        b"content-type" => {
            // ngx_http_upstream_copy_content_type
            ho.content_type_len = value.len();
            ho.content_type = value.clone();
            ho.content_type_lowcase = None;

            if let Some((len, charset)) = content_type_charset(&value) {
                ho.content_type_len = len;
                ho.charset = charset;
            }
        }

        // ngx_http_upstream_ignore_header_line
        b"content-length" | b"connection" | b"keep-alive" | b"transfer-encoding" => {}

        b"date" => {
            let o = ho.add(&h.key, &value);
            ho.date = Some(o);
        }

        b"last-modified" => {
            // ngx_http_upstream_copy_last_modified
            let o = ho.add(&h.key, &value);
            ho.last_modified = Some(o);
            ho.last_modified_time = u.cache.last_modified_time;
        }

        b"etag" => {
            let o = ho.add(&h.key, &value);
            ho.etag = Some(o);
        }

        b"server" => {
            let o = ho.add(&h.key, &value);
            ho.server = Some(o);
        }

        b"location" => {
            // ngx_http_upstream_rewrite_location: a relative location is
            // not r->headers_out.location, not to be made absolute by the
            // header filter
            let o = ho.add(&h.key, &value);

            if value.first() != Some(&b'/') {
                ho.location = Some(o);
            }
        }

        b"refresh" => {
            // ngx_http_upstream_rewrite_refresh
            let o = ho.add(&h.key, &value);
            ho.refresh = Some(o);
        }

        b"cache-control" => {
            // ngx_http_upstream_copy_multi_header_lines
            let o = ho.add(&h.key, &value);
            ho.cache_control.push(o);
        }

        b"link" => {
            let o = ho.add(&h.key, &value);
            ho.link.push(o);
        }

        b"expires" => {
            let o = ho.add(&h.key, &value);
            ho.expires = Some(o);
        }

        b"accept-ranges" => {
            // ngx_http_upstream_copy_allow_ranges
            if force_ranges {
                return;
            }

            if r.cached.get() {
                r.allow_ranges.set(true);
                return;
            }

            if crate::upstream_cache::cacheable(r) {
                r.allow_ranges.set(true);
                r.single_range.set(true);
                return;
            }

            let o = ho.add(&h.key, &value);
            ho.accept_ranges = Some(o);
        }

        b"upgrade" => {
            // ngx_http_upstream_copy_upgrade
            if r.http_version.get() >= NGX_HTTP_VERSION_20 {
                return;
            }

            ho.add(&h.key, &value);
        }

        b"content-range" => {
            let o = ho.add(&h.key, &value);
            ho.content_range = Some(o);
        }

        b"content-encoding" => {
            let o = ho.add(&h.key, &value);
            ho.content_encoding = Some(o);
        }

        // "Status", "WWW-Authenticate", "Set-Cookie", "Content-Disposition",
        // "Vary", "X-Accel-*" and the headers without a handler:
        // ngx_http_upstream_copy_header_line
        _ => {
            ho.add(&h.key, &value);
        }
    }
}

/// ngx_http_upstream_process_headers: the headers not hidden go to
/// r->headers_out; for X-Accel-Redirect, only those with "redirect".
fn process_headers(r: &R, lcf: &Rc<RefCell<NgxHttpUwsgiLocConf>>, u: &UpstreamResponse) -> Processed {
    // u->headers_in.no_cache || u->headers_in.expired
    crate::upstream_cache::process_headers_cacheable(r, &u.cache);

    let (hide, ignore_xa_redirect, force_ranges) = {
        let c = lcf.borrow();
        (c.hide_headers_hash.clone(), c.cache.ignores(NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT), *c.force_ranges)
    };

    if let Some(xar) = headers_in(u, b"x-accel-redirect") {
        if !ignore_xa_redirect {
            for h in u.headers.iter() {
                if h.hash.get() == 0 {
                    continue;
                }

                if REDIRECT_HEADERS.iter().any(|k| h.lowcase_key == *k) {
                    copy_header(r, u, h, force_ranges);
                }
            }

            let uri = xar.value.borrow().clone();

            return Processed::Redirect(uri);
        }
    }

    for h in u.headers.iter() {
        if h.hash.get() == 0 {
            continue;
        }

        if let Some(hide) = &hide {
            if hide.find(hash_key(&h.lowcase_key), &h.lowcase_key).is_some() {
                continue;
            }
        }

        copy_header(r, u, h, force_ranges);
    }

    {
        let mut ho = r.headers_out.borrow_mut();

        ho.status = u.status_n;
        ho.status_line = u.status_line.clone();

        ho.content_length_n = u.content_length_n;
    }

    r.disable_not_modified.set(!crate::upstream_cache::cacheable(r));

    if force_ranges {
        r.allow_ranges.set(true);
        r.single_range.set(true);

        if r.cached.get() {
            r.single_range.set(false);
        }
    }

    // u->length = -1

    Processed::Ok
}

/// The X-Accel-Redirect of ngx_http_upstream_process_headers: a named
/// location, or the URI (with its arguments) for an internal redirect,
/// with the method GET unless HEAD.
async fn accel_redirect(r: &R, xar: &[u8]) -> i64 {
    if xar.first() == Some(&b'@') {
        crate::core_rt::named_location(r, xar).await;

        // ngx_http_finalize_request(r, NGX_DONE)
        return NGX_DONE;
    }

    let mut uri = xar.to_vec();
    let mut args = Vec::new();

    if crate::parse::parse_unsafe_uri_args(&r.connection.log, &mut uri, &mut args, crate::parse::NGX_HTTP_LOG_UNSAFE) != NGX_OK {
        return NGX_HTTP_NOT_FOUND;
    }

    if r.method.get() != NGX_HTTP_HEAD {
        r.method.set(NGX_HTTP_GET);
        *r.method_name.borrow_mut() = b"GET".to_vec();
    }

    crate::core_rt::internal_redirect(r, &uri, Some(&args)).await;

    NGX_DONE
}

/// ngx_http_upstream_upgrade: the header is out, what the upstream sent
/// after it goes to the client, then the data of each side is passed to
/// the other (ngx_http_upstream_process_upgraded).
async fn upgrade(r: &R, sock: UpstreamSock, u: &UpstreamResponse, read_timeout: u64) -> i64 {
    if !r.is_main() {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "connection upgrade in subrequest");
        return finalize(r, NGX_ERROR);
    }

    r.keepalive.set(false);

    // the header goes out now, not with the "last" buffer that never comes
    let mut b = Buf::from_vec(Vec::new());
    b.flush = true;
    b.sync = true;
    let mut chain = Chain::new();
    chain.push_back(b);
    let _ = crate::core_rt::output_filter(r, chain).await;

    if u.pos < u.buf.len() {
        let _ = r.connection.send_all(&u.buf[u.pos..]).await;
    }

    let _ = crate::proxy::upgrade_tunnel(r.clone(), sock, read_timeout).await;

    // ngx_http_upstream_finalize_request(r, u, 0) when the tunnel is done
    finalize(r, 0);

    NGX_DONE
}

/// What reading the response body needs of the upstream configuration.
struct BodyParams {
    /// u->buffering
    buffering: bool,
    /// p->limit_rate (uwsgi_limit_rate), buffered only
    limit_rate: usize,
    /// the body goes to the client (not p->downstream_error)
    downstream: bool,
    /// the response is read in full for the cache or uwsgi_store
    /// (p->cacheable)
    capture: bool,
    /// the body is kept for uwsgi_store
    store: bool,
    read_timeout: u64,
    /// uwsgi_buffer_size: the reads of an unbuffered response
    buffer_size: usize,
}

/// How the body of a response ended.
enum BodyEnd {
    /// p->upstream_done, or the end of a response without a length
    /// (ngx_http_upstream_finalize_request(r, u, 0))
    Done,
    /// the upstream closed the connection early, timed out or failed: 502
    /// or 504 after the header
    UpstreamError,
    /// the client connection failed and the response is not read for the
    /// cache or uwsgi_store (NGX_ERROR)
    Error,
    /// the request is finalized with this status (499: the client closed
    /// the connection)
    Status(i64),
}

/// The end of a response body.
struct BodyResult {
    end: BodyEnd,
    /// p->upstream_done (u->length reached 0)
    upstream_done: bool,
    /// p->upstream_eof: the upstream closed the connection
    eof: bool,
    /// the body goes to the client (no p->downstream_error)
    downstream: bool,
    /// the body, kept for uwsgi_store
    data: Vec<u8>,
}

/// ngx_http_upstream_send_response after the header is sent: the body read
/// with ngx_event_pipe_copy_input_filter (buffered, with uwsgi_limit_rate)
/// or ngx_http_upstream_non_buffered_filter and passed to the client, up
/// to what ngx_http_upstream_process_request finds at its end.
///
/// The actions are those of C: "reading upstream" for the pipe
/// (ngx_http_upstream_process_upstream) and the reads of an unbuffered
/// response; the preread part of an unbuffered response is filtered while
/// "reading response header from upstream" and sent while "sending to
/// client" (ngx_http_upstream_process_non_buffered_downstream).
async fn send_response_body(r: &R, sock: &mut UpstreamSock, u: &UpstreamResponse, length: i64, p: BodyParams, watch: Option<&ClientWatch>, cache: &mut Option<crate::upstream_cache::CacheWriter>) -> BodyResult {
    if p.buffering {
        r.connection.log.set_action(Some("reading upstream"));
    }

    read_body(r, sock, u, length, &p, watch, cache).await
}

async fn read_body(r: &R, sock: &mut UpstreamSock, u: &UpstreamResponse, length: i64, p: &BodyParams, watch: Option<&ClientWatch>, cache: &mut Option<crate::upstream_cache::CacheWriter>) -> BodyResult {
    let log = r.connection.log.clone();

    let mut length = length;

    if !p.buffering {
        r.limit_rate.set(0);
        r.limit_rate_set.set(true);
    }

    let mut downstream = p.downstream;
    let mut upstream_done = false;
    let mut eof = false;
    let mut timedout = false;

    let mut captured: Vec<u8> = Vec::new();

    macro_rules! end {
        ($end:expr) => {
            return BodyResult { end: $end, upstream_done, eof, downstream, data: captured }
        };
    }

    // the preread part of the body in u->buffer, then what is read
    let mut data: Vec<u8> = u.buf[u.pos..].to_vec();
    let preread = !data.is_empty();

    if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
        st.response_length += data.len() as i64;
    }

    if !p.buffering && !preread && downstream {
        // ngx_http_send_special(r, NGX_HTTP_FLUSH): the header goes now
        if crate::special_response::send_special(r, false).await == NGX_ERROR {
            end!(BodyEnd::Error);
        }
    }

    // p->read_length and p->start_sec of uwsgi_limit_rate
    let start_sec = ngx_core::times::cached().sec;
    let mut read_length: i64 = 0;
    let mut delay: u64 = 0;

    if p.limit_rate > 0 && preread {
        read_length += data.len() as i64;
        delay = data.len() as u64 * 1000 / p.limit_rate as u64;
    }

    let read_size = if p.buffering { 16384 } else { p.buffer_size.max(1) };
    let mut chunk = vec![0u8; read_size];

    // the preread part of an unbuffered response is sent by
    // ngx_http_upstream_process_non_buffered_downstream
    let mut sending_preread = !p.buffering && preread;

    loop {
        // u->input_filter / p->input_filter

        let mut out: Vec<u8> = Vec::new();

        if !data.is_empty() && !upstream_done {
            if length == 0 {
                // the copy filters: the data after the length is dropped
                ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
                upstream_done = true;
            } else if length == -1 {
                out.extend_from_slice(&data);
            } else if data.len() as i64 > length {
                ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
                out.extend_from_slice(&data[..length as usize]);
                length = 0;
                upstream_done = true;
            } else {
                out.extend_from_slice(&data);
                length -= data.len() as i64;
            }
        }

        data.clear();

        if sending_preread {
            log.set_action(Some("sending to client"));
            sending_preread = false;
        }

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
                    // only for the cache or uwsgi_store
                    downstream = false;

                    if !p.capture {
                        end!(BodyEnd::Error);
                    }
                }
            }
        }

        if length == 0 {
            upstream_done = true;
        }

        if upstream_done || (eof && length == -1) {
            end!(BodyEnd::Done);
        }

        if eof || timedout {
            if eof {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection");
            }

            end!(BodyEnd::UpstreamError);
        }

        // p->limit_rate: the read is delayed by the time the last one
        // took at the rate, and limited to what the rate allows so far
        if delay > 0 {
            if !crate::proxy::sleep_or_client_closed(delay, watch).await {
                end!(BodyEnd::Status(crate::proxy::client_closed_request(r, 0)));
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

        // ngx_http_upstream_process_non_buffered_upstream, and the pipe
        log.set_action(Some("reading upstream"));

        let res = {
            let read = tokio::time::timeout(Duration::from_millis(p.read_timeout), sock.read(&mut chunk[..limit]));

            tokio::select! {
                res = read => res,
                err = crate::proxy::client_closed(watch) => end!(BodyEnd::Status(crate::proxy::client_closed_request(r, err))),
            }
        };

        match res {
            Err(_) => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
                timedout = true;
            }
            Ok(Err(e)) => {
                if plain(sock) {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, e.raw_os_error(), "recv() failed");
                }

                // upstream->read->error, p->upstream_error
                end!(BodyEnd::UpstreamError);
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

/// ngx_http_upstream_store: the body in a temporary file of uwsgi_temp_path
/// renamed to the path of uwsgi_store (the location's file with "on"),
/// with uwsgi_store_access and the time of "Last-Modified".
fn upstream_store(r: &R, lcf: &Rc<RefCell<NgxHttpUwsgiLocConf>>, u: &UpstreamResponse, body: &[u8]) {
    let (temp_path, store_access, store_values) = {
        let c = lcf.borrow();
        (c.temp_path.get().clone(), *c.store_access, c.store_values.clone())
    };

    let log = r.connection.log.clone();

    let mut tf = match crate::file_cache::CacheTempFile::create(r, &temp_path, None) {
        Ok(tf) => tf,
        Err(()) => return,
    };

    if tf.write(body, &log).is_err() {
        let _ = ngx_core::os::unlink(&tf.name);
        return;
    }

    // ext.time: the time of "Last-Modified"
    let mut time = -1;

    if let Some(lm) = headers_in(u, b"last-modified") {
        if let Some(t) = ngx_core::parse::parse_http_time(&lm.value.borrow()) {
            time = t;
        }
    }

    let path = match &store_values {
        None => match crate::core_rt::map_uri_to_path(r, 0) {
            Some((p, _)) => p,
            None => {
                let _ = ngx_core::os::unlink(&tf.name);
                return;
            }
        },
        Some(codes) => match crate::script::script_run(r, codes) {
            Some(p) => p,
            None => {
                let _ = ngx_core::os::unlink(&tf.name);
                return;
            }
        },
    };

    http_debug!(r, "upstream stores \"{}\" to \"{}\"", B(&tf.name), B(&path));

    if path.is_empty() {
        let _ = ngx_core::os::unlink(&tf.name);
        return;
    }

    if time != -1 {
        // ngx_set_file_time(): the times of the temporary file
        let tv = [libc::timeval { tv_sec: time as libc::time_t, tv_usec: 0 }, libc::timeval { tv_sec: time as libc::time_t, tv_usec: 0 }];

        // SAFETY: tf.fd is the open temporary file, tv two timevals.
        if unsafe { libc::futimes(tf.fd, tv.as_ptr()) } == -1 {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(ngx_core::os::errno()), "futimes() \"{}\" failed", B(&tf.name));
            let _ = ngx_core::os::unlink(&tf.name);
            return;
        }
    }

    let _ = crate::file_cache::ext_rename_file(&tf.name, &path, store_access, store_access, true, true, &log);
}

/// ngx_http_upstream_cache_send with ngx_http_uwsgi_process_status_line,
/// ngx_http_uwsgi_process_header and ngx_http_upstream_process_headers:
/// the response from the cache.
async fn cache_send(r: &R, lcf: &Rc<RefCell<NgxHttpUwsgiLocConf>>) -> i64 {
    crate::upstream_cache::upstream_cache_send(r, |buf| async move {
        let mut resp = UpstreamResponse::new();

        resp.buf = buf;

        let mut st = HeaderParse::new();
        let mut flags = HeaderFlags::default();

        match process_status_line(r, &mut resp, &mut st, &mut flags) {
            Ok(true) => {}
            Ok(false) => return NGX_AGAIN,
            Err(_) => return NGX_HTTP_UPSTREAM_INVALID_HEADER,
        }

        // u->headers_in, for $upstream_http_*
        *r.upstream_headers_in.borrow_mut() = resp.headers.iter().filter(|h| h.hash.get() != 0).cloned().collect();

        match process_headers(r, lcf, &resp) {
            Processed::Ok => NGX_OK,
            Processed::Redirect(xar) => {
                // ngx_http_upstream_finalize_request(r, u, NGX_DECLINED)
                finalize(r, NGX_DECLINED);
                accel_redirect(r, &xar).await
            }
        }
    })
    .await
}

/// The stale response of ngx_http_upstream_next, when there is no next
/// upstream to try, or the status the request is finalized with.
async fn next_failed(r: &R, lcf: &Rc<RefCell<NgxHttpUwsgiLocConf>>, ft_type: u32, status: i64) -> i64 {
    if crate::upstream_cache::next_stale(r, ft_type) {
        // u->reinit_request(r)

        if let Some(u) = crate::upstream_cache::upstream_of(r) {
            u.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_STALE);
        }

        let mut rc = cache_send(r, lcf).await;

        if rc == NGX_DONE {
            return NGX_DONE;
        }

        if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return finalize(r, rc);
    }

    finalize(r, status)
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
        let params = init_params(cf, c.params_source.as_ref(), UWSGI_HEADERS)?;
        c.params = Some(params);
    }

    if c.cache.enabled() && c.params_cache.is_none() {
        let params = init_params(cf, c.params_source.as_ref(), UWSGI_CACHE_HEADERS)?;
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

    Ok(())
}

/// ngx_http_uwsgi_init_params: the params of uwsgi_param, then those of
/// `default_params` it does not set (sent only if not empty); the names of
/// the HTTP_* ones go to the hash (the request headers of these names are
/// not sent), and the params with a value are compiled.
fn init_params(cf: &mut Conf, params_source: Option<&Rc<Vec<ParamSource>>>, default_params: &[(&[u8], &[u8])]) -> Result<Rc<UwsgiParams>, ConfError> {
    let src = merge_params(params_source.map(|s| s.as_slice()).unwrap_or(&[]), default_params);

    let mut headers_names: Vec<HashKey<()>> = Vec::new();
    let mut params: Vec<UwsgiParam> = Vec::new();
    let mut flushes: Vec<usize> = Vec::new();

    for s in src {
        if s.key.len() > "HTTP_".len() && s.key.starts_with(b"HTTP_") {
            let name = &s.key[5..];

            // the hash keys are lowercased by ngx_hash_init()
            headers_names.push(HashKey { key: name.to_ascii_lowercase(), key_hash: hash_key_lc(name), value: () });

            if s.value.is_empty() {
                continue;
            }
        }

        let codes = crate::script::script_compile(cf, &s.value)?;

        flushes.extend(crate::proxy::script_flushes(&codes));

        params.push(UwsgiParam { key: s.key, skip_empty: s.skip_empty, codes });
    }

    let number = headers_names.len();

    let hinit = HashInit { name: "uwsgi_params_hash", max_size: 512, bucket_size: 64, log: &cf.log };

    let hash = match Hash::init(&hinit, headers_names) {
        Ok(h) => h,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
            return Err(ConfError::Logged);
        }
    };

    Ok(Rc::new(UwsgiParams { flushes, params, number, hash }))
}

/// params_merged of ngx_http_uwsgi_init_params: the params of uwsgi_param,
/// then the default params of names they do not have (compared
/// case-insensitively), sent only if not empty.
fn merge_params(source: &[ParamSource], default_params: &[(&[u8], &[u8])]) -> Vec<ParamSource> {
    let mut src: Vec<ParamSource> = source.to_vec();

    for (key, value) in default_params {
        if src.iter().any(|s| s.key.eq_ignore_ascii_case(key)) {
            continue;
        }

        src.push(ParamSource { key: key.to_vec(), value: value.to_vec(), skip_empty: true });
    }

    src
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

    if ngx_ssl_create(&mut ssl, uwcf.ssl_protocols, std::ptr::null_mut()) != NGX_OK {
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

    let value = cf.args.clone();

    let mut param = ParamSource { key: value[1].clone(), value: value[2].clone(), skip_empty: false };

    if value.len() == 4 {
        if value[3] != b"if_not_empty" {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[3]))));
        }

        param.skip_empty = true;
    }

    let mut c = cell.borrow_mut();

    let mut list: Vec<ParamSource> = match c.params_source.take() {
        Some(l) => Rc::try_unwrap(l).unwrap_or_else(|l| l.as_ref().clone()),
        None => Vec::new(),
    };

    list.push(param);

    c.params_source = Some(Rc::new(list));

    Ok(())
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
