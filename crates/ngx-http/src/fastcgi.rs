//! ngx_http_fastcgi_module
//!
//! The request is a BEGIN_REQUEST record, the params (those of
//! fastcgi_param, then the request headers as HTTP_* params) in a PARAMS
//! record and an empty one, and the body in STDIN records of up to 32K, the
//! last one empty (ngx_http_fastcgi_create_request, and for a body read
//! after the header, ngx_http_fastcgi_body_output_filter). The response is
//! STDOUT and STDERR records up to END_REQUEST: the header in the first
//! STDOUT records (ngx_http_fastcgi_process_header, a header line split
//! across records joined), what the application wrote to stderr logged, and
//! the body in the data of the STDOUT records that follow
//! (ngx_http_fastcgi_input_filter for the event pipe,
//! ngx_http_fastcgi_non_buffered_filter otherwise). The request lifecycle is
//! that of crate::upstream_rt.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::hash::Hash;
use ngx_core::inet::Url;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::core::CoreLocConf;
use crate::event_pipe::{EventPipe, RawBuf};
use crate::parse::{ParseRequest, NGX_HTTP_PARSE_HEADER_DONE};
use crate::request::*;
use crate::script::{ComplexValue, Part};
use crate::upstream::*;
use crate::upstream_cache::{UpstreamCacheConf, UpstreamCacheLocConf, UpstreamCacheMainConf, NGX_CONF_BITMASK_SET, NGX_HTTP_UPSTREAM_INVALID_HEADER};
use crate::upstream_rt::{cgi_status, ParamSource, Params, Upstream, UpstreamConf, UpstreamLocal, UpstreamModule};
use crate::upstream_ssl::UpstreamSslConf;
use crate::variables::VarDef;
use crate::*;

crate::http_module_index!("ngx_http_fastcgi_module");

const NGX_HTTP_FASTCGI_RESPONDER: u8 = 1;

const NGX_HTTP_FASTCGI_KEEP_CONN: u8 = 1;

const NGX_HTTP_FASTCGI_BEGIN_REQUEST: u8 = 1;
const NGX_HTTP_FASTCGI_END_REQUEST: u8 = 3;
const NGX_HTTP_FASTCGI_PARAMS: u8 = 4;
const NGX_HTTP_FASTCGI_STDIN: u8 = 5;
const NGX_HTTP_FASTCGI_STDOUT: u8 = 6;
const NGX_HTTP_FASTCGI_STDERR: u8 = 7;

/// sizeof(ngx_http_fastcgi_header_t)
const HEADER_SIZE: usize = 8;

const CR: u8 = b'\r';
const LF: u8 = b'\n';

/// The data of a STDIN record of the request body: up to 32K
const STDIN_DATA_SIZE: usize = 32 * 1024;

/// ngx_http_fastcgi_next_upstream_masks
const FASTCGI_NEXT_UPSTREAM_MASKS: &[(&str, u32)] = &[
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

/// ngx_http_fastcgi_hide_headers
const FASTCGI_HIDE_HEADERS: &[&[u8]] = &[b"Status", b"X-Accel-Expires", b"X-Accel-Redirect", b"X-Accel-Limit-Rate", b"X-Accel-Buffering", b"X-Accel-Charset"];

/// ngx_http_fastcgi_headers
const FASTCGI_HEADERS: &[(&[u8], &[u8])] = &[(b"HTTP_HOST", b"$host$is_request_port$request_port")];

/// ngx_http_fastcgi_cache_headers
const FASTCGI_CACHE_HEADERS: &[(&[u8], &[u8])] = &[
    (b"HTTP_HOST", b"$host$is_request_port$request_port"),
    (b"HTTP_IF_MODIFIED_SINCE", b"$upstream_cache_last_modified"),
    (b"HTTP_IF_UNMODIFIED_SINCE", b""),
    (b"HTTP_IF_NONE_MATCH", b"$upstream_cache_etag"),
    (b"HTTP_IF_MATCH", b""),
    (b"HTTP_RANGE", b""),
    (b"HTTP_IF_RANGE", b""),
];

/// ngx_http_fastcgi_loc_conf_t, with the fields of ngx_http_upstream_conf_t
/// the module uses.
pub struct NgxHttpFastcgiLocConf {
    /// upstream.upstream: the upstream of fastcgi_pass without variables
    pub upstream: Option<Rc<UpstreamSrvConf>>,

    /// upstream.store: unset, 0 or 1
    pub store: Val<bool>,
    /// upstream.store_lengths and store_values: the path of fastcgi_store
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

    /// The cache fields of upstream (fastcgi_cache, fastcgi_cache_*,
    /// fastcgi_no_cache, fastcgi_ignore_headers) and cache_key.
    pub cache: UpstreamCacheConf,

    pub index: Val<Vec<u8>>,

    /// params and params_cache once built (params->hash.buckets)
    pub params: Option<Rc<Params>>,
    pub params_cache: Option<Rc<Params>>,
    /// params_source: the fastcgi_param of the level (NULL: none)
    pub params_source: Option<Rc<Vec<ParamSource>>>,

    /// catch_stderr: NGX_CONF_UNSET_PTR or the list
    pub catch_stderr: Val<Rc<Vec<Vec<u8>>>>,

    /// fastcgi_lengths and fastcgi_values: the codes of a fastcgi_pass with
    /// variables
    pub fastcgi_values: Option<Rc<Vec<Part>>>,

    pub keep_conn: Val<bool>,

    /// fastcgi_split_path_info
    pub split_regex: Option<Rc<Regex>>,
    pub split_name: Vec<u8>,

    /// flcf->upstream as a request uses it, once merged
    pub upstream_conf: Option<Rc<UpstreamConf>>,
}

impl UpstreamCacheLocConf for NgxHttpFastcgiLocConf {
    fn upstream_cache(&mut self) -> &mut UpstreamCacheConf {
        &mut self.cache
    }
}

/// ngx_http_fastcgi_create_loc_conf
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(new_loc_conf())
}

/// The location configuration of ngx_http_fastcgi_create_loc_conf.
fn new_loc_conf() -> NgxHttpFastcgiLocConf {
    // set by ngx_pcalloc(): bufs.num = 0, ignore_headers = 0,
    // next_upstream = 0, cache_zone = NULL, cache_use_stale = 0,
    // cache_methods = 0, temp_path = NULL, hide_headers_hash = { NULL, 0 },
    // store_lengths = NULL, store_values = NULL, index = { 0, NULL }
    //
    // "fastcgi_cyclic_temp_file" is disabled: upstream.cyclic_temp_file = 0,
    // upstream.change_buffering = 1, upstream.module = "fastcgi"
    NgxHttpFastcgiLocConf {
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
        index: Val::unset(),
        params: None,
        params_cache: None,
        params_source: None,
        catch_stderr: Val::unset(),
        fastcgi_values: None,
        keep_conn: Val::unset(),
        split_regex: None,
        split_name: Vec::new(),
        upstream_conf: None,
    }
}

// ---------------------------------------------------------------------------
// the request
// ---------------------------------------------------------------------------

/// ngx_http_fastcgi_state_e
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum State {
    Version,
    Type,
    RequestIdHi,
    RequestIdLo,
    ContentLengthHi,
    ContentLengthLo,
    PaddingLength,
    Reserved,
    Data,
    Padding,
}

/// ngx_http_fastcgi_ctx_t as the variables use it: the script name and the
/// path info of the URI, once ngx_http_fastcgi_split made them.
#[derive(Default)]
pub struct FastcgiCtx {
    script_name: Vec<u8>,
    path_info: Vec<u8>,
}

/// The rest of ngx_http_fastcgi_ctx_t, the module's context for the
/// callbacks of the request: the record of the response being read, and
/// r->state of the header parser.
struct FastcgiModule {
    lcf: Rc<RefCell<NgxHttpFastcgiLocConf>>,
    keep_conn: bool,

    /// f->state
    state: State,
    /// f->type, f->length and f->padding of the record
    ty: u8,
    length: usize,
    padding: usize,
    /// f->rest: what is left of the body by the "Content-Length" (-1: no
    /// limit; -2: a HEAD request, the limit taken with the first data)
    rest: i64,

    fastcgi_stdout: bool,
    large_stderr: bool,
    /// f->header_sent: the first buffer (the request) went through the body
    /// output filter
    header_sent: bool,
    closed: bool,

    /// f->split_parts: the parts of a header line split across records
    split_parts: Vec<Vec<u8>>,

    /// u->buffer.pos while the header is processed
    pos: usize,
    /// r->state and the header parser
    pr: ParseRequest,
}

impl FastcgiModule {
    fn new(lcf: Rc<RefCell<NgxHttpFastcgiLocConf>>) -> FastcgiModule {
        let keep_conn = *lcf.borrow().keep_conn;

        FastcgiModule {
            lcf,
            keep_conn,
            state: State::Version,
            ty: 0,
            length: 0,
            padding: 0,
            rest: 0,
            fastcgi_stdout: false,
            large_stderr: false,
            header_sent: false,
            closed: false,
            split_parts: Vec::new(),
            pos: 0,
            pr: ParseRequest { upstream: true, ..Default::default() },
        }
    }

    /// ngx_http_fastcgi_process_record: the header of a record from f->pos
    /// (`pos`) to f->last (the end of `buf`). NGX_OK with `pos` at the data,
    /// NGX_AGAIN for more, NGX_ERROR for an invalid header.
    fn process_record(&mut self, log: &Log, buf: &[u8], pos: &mut usize) -> i64 {
        let mut state = self.state;
        let mut p = *pos;

        while p < buf.len() {
            let ch = buf[p];

            ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http fastcgi record byte: {:02X}", ch);

            match state {
                State::Version => {
                    if ch != 1 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent unsupported FastCGI protocol version: {}", ch);
                        return NGX_ERROR;
                    }

                    state = State::Type;
                }

                State::Type => {
                    match ch {
                        NGX_HTTP_FASTCGI_STDOUT | NGX_HTTP_FASTCGI_STDERR | NGX_HTTP_FASTCGI_END_REQUEST => self.ty = ch,
                        _ => {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid FastCGI record type: {}", ch);
                            return NGX_ERROR;
                        }
                    }

                    state = State::RequestIdHi;
                }

                // we support the single request per connection

                State::RequestIdHi => {
                    if ch != 0 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent unexpected FastCGI request id high byte: {}", ch);
                        return NGX_ERROR;
                    }

                    state = State::RequestIdLo;
                }

                State::RequestIdLo => {
                    if ch != 1 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent unexpected FastCGI request id low byte: {}", ch);
                        return NGX_ERROR;
                    }

                    state = State::ContentLengthHi;
                }

                State::ContentLengthHi => {
                    self.length = (ch as usize) << 8;
                    state = State::ContentLengthLo;
                }

                State::ContentLengthLo => {
                    self.length |= ch as usize;
                    state = State::PaddingLength;
                }

                State::PaddingLength => {
                    self.padding = ch as usize;
                    state = State::Reserved;
                }

                State::Reserved => {
                    state = State::Data;

                    ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http fastcgi record length: {}", self.length);

                    *pos = p + 1;
                    self.state = state;

                    return NGX_OK;
                }

                // suppress warning
                State::Data | State::Padding => {}
            }

            p += 1;
        }

        *pos = p;
        self.state = state;

        NGX_AGAIN
    }

    /// The data of a STDERR record from f->pos to f->last (as much of it as
    /// there is) logged; with `msg` where it starts, `pos` after it.
    fn log_stderr(&mut self, r: &R, buf: &[u8], pos: &mut usize) -> (usize, usize) {
        let last = buf.len();
        let msg = *pos;

        if *pos + self.length <= last {
            *pos += self.length;
            self.length = 0;
            self.state = State::Padding;
        } else {
            self.length -= last - *pos;
            *pos = last;
        }

        let end = stderr_end(buf, msg, *pos);

        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "FastCGI sent in stderr: \"{}\"", B(&buf[msg..end]));

        (msg, end)
    }

    /// The header line parsed by `self.pr` in u->buffer from `part_start`
    /// (after the parts of it in the records before, if any) to u->buffer.pos
    /// as a header of the response, with the handler of
    /// ngx_http_upstream_headers_in[]; NGX_OK, NGX_ERROR, or
    /// NGX_HTTP_UPSTREAM_INVALID_HEADER.
    fn header_line(&mut self, r: &R, u: &mut Upstream, part_start: usize) -> i64 {
        let (key, value, hash, lowcase_key);

        if !self.split_parts.is_empty() {
            let mut joined: Vec<u8> = Vec::new();

            for part in self.split_parts.drain(..) {
                joined.extend_from_slice(&part);
            }

            joined.extend_from_slice(&u.resp.buf[part_start..self.pos]);

            let mut p = 0;

            if crate::parse::parse_header_line(&mut self.pr, &joined, &mut p, true) != NGX_OK {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "invalid header after joining FastCGI records");
                return NGX_ERROR;
            }

            let pr = &self.pr;

            key = joined[pr.header_name_start..pr.header_name_end].to_vec();
            value = joined[pr.header_start..pr.header_end].to_vec();
            hash = pr.header_hash;
        } else {
            let pr = &self.pr;

            key = u.resp.buf[pr.header_name_start..pr.header_name_end].to_vec();
            value = u.resp.buf[pr.header_start..pr.header_end].to_vec();
            hash = pr.header_hash;
        }

        lowcase_key = if key.len() == self.pr.lowcase_index { self.pr.lowcase_header[..key.len()].to_vec() } else { key.to_ascii_lowercase() };

        let h = crate::upstream_rt::upstream_header(key, value, hash, lowcase_key);

        u.resp.push_header(h.clone());

        // hh->handler(r, h, hh->offset)
        if crate::upstream_rt::process_header_line(r, u, &h).is_err() {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        http_debug!(r, "http fastcgi header: \"{}: {}\"", B(&h.key), B(&h.value.borrow()));

        NGX_OK
    }

    /// The status of the header: of "Status", 302 with "Location", or 200.
    fn header_done(&mut self, r: &R, u: &mut Upstream) -> i64 {
        http_debug!(r, "http fastcgi header done");

        let resp = &mut u.resp;

        if let Some(status) = resp.header(b"status") {
            let status_line = status.value.borrow().clone();

            // ngx_atoi(status_line->data, 3): the value is null-terminated
            let status = match cgi_status(&status_line) {
                Some(s) => s,
                None => {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid status \"{}\"", B(&status_line));
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }
            };

            resp.status_n = status;

            if status_line.len() > 3 {
                resp.status_line = status_line;
            }
        } else if resp.header(b"location").is_some() {
            resp.status_n = 302;
            resp.status_line = b"302 Moved Temporarily".to_vec();
        } else {
            resp.status_n = 200;
            resp.status_line = b"200 OK".to_vec();
        }

        if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
            if state.status == 0 {
                state.status = resp.status_n;
            }
        }

        NGX_OK
    }
}

/// ngx_http_fastcgi_handler
async fn fastcgi_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());

    // ngx_http_upstream_create, with u->conf and u->caches of the main
    // configuration

    let (conf, fastcgi_values) = {
        let c = lcf.borrow();
        (c.upstream_conf.clone(), c.fastcgi_values.clone())
    };

    let conf = match conf {
        Some(c) => c,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let caches = {
        let fmcf = r.main_conf::<UpstreamCacheMainConf>(ctx_index());
        let caches = fmcf.borrow().caches.clone();
        caches
    };

    let mut u = Upstream::create(&r, conf, caches, b"fastcgi://");

    // f = ngx_pcalloc(); ngx_http_set_ctx(r, f, ngx_http_fastcgi_module)
    r.set_ctx(ctx_index(), FastcgiCtx::default());

    if let Some(codes) = fastcgi_values {
        if fastcgi_eval(&r, &codes, &mut u) != NGX_OK {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    {
        let flcf = lcf.borrow();

        if !*flcf.request_buffering && *flcf.pass_request_body {
            r.request_body_no_buffering.set(true);
        }
    }

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    let mut m = FastcgiModule::new(lcf);

    crate::upstream_rt::init(r, u, &mut m).await
}

/// ngx_http_fastcgi_eval: the address of fastcgi_pass with variables, and
/// the upstream it names (u->resolved).
fn fastcgi_eval(r: &R, codes: &[Part], u: &mut Upstream) -> i64 {
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

impl UpstreamModule for FastcgiModule {
    fn create_key(&self, r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
        let mut k = crate::file_cache::CacheKeys::new();
        let rc = create_keys(r, &mut k);
        keys.extend(k.iter().map(|part| part.to_vec()));
        rc
    }

    fn create_keys(&self, r: &R, keys: &mut crate::file_cache::CacheKeys) -> i64 {
        create_keys(r, keys)
    }

    fn create_request(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let flcf = self.lcf.borrow();

        match create_request(r, &flcf, u.cacheable()) {
            Ok(bufs) => {
                u.request_bufs = bufs;
                NGX_OK
            }
            Err(()) => NGX_ERROR,
        }
    }

    /// ngx_http_fastcgi_reinit_request, and u->buffer.pos anew
    fn reinit_request(&mut self, _r: &R, _u: &mut Upstream) -> i64 {
        self.state = State::Version;
        self.fastcgi_stdout = false;
        self.large_stderr = false;

        self.split_parts.clear();

        self.pr = ParseRequest { upstream: true, ..Default::default() };

        self.pos = 0;

        NGX_OK
    }

    /// ngx_http_fastcgi_process_header
    fn process_header(&mut self, r: &R, u: &mut Upstream) -> i64 {
        loop {
            if self.state < State::Data {
                // f->pos = u->buffer.pos; f->last = u->buffer.last
                let mut pos = self.pos;

                let rc = self.process_record(&r.connection.log, &u.resp.buf, &mut pos);

                self.pos = pos;

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                if self.ty != NGX_HTTP_FASTCGI_STDOUT && self.ty != NGX_HTTP_FASTCGI_STDERR {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected FastCGI record: {}", self.ty);
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                if self.ty == NGX_HTTP_FASTCGI_STDOUT && self.length == 0 {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed FastCGI stdout");
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }
            }

            let last = u.resp.buf.len();

            if self.state == State::Padding {
                if self.pos + self.padding < last {
                    self.state = State::Version;
                    self.pos += self.padding;

                    continue;
                }

                if self.pos + self.padding == last {
                    self.state = State::Version;
                    self.pos = last;

                    return NGX_AGAIN;
                }

                self.padding -= last - self.pos;
                self.pos = last;

                return NGX_AGAIN;
            }

            // f->state == ngx_http_fastcgi_st_data

            if self.ty == NGX_HTTP_FASTCGI_STDERR {
                if self.length > 0 {
                    let mut pos = self.pos;

                    let (msg, end) = self.log_stderr(r, &u.resp.buf, &mut pos);

                    self.pos = pos;

                    let catch_stderr = self.lcf.borrow().catch_stderr.as_option().cloned();

                    if let Some(patterns) = catch_stderr {
                        for pattern in patterns.iter() {
                            if strnstr(&u.resp.buf[msg..end], pattern) {
                                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                            }
                        }
                    }

                    if self.pos == last {
                        if !self.fastcgi_stdout {
                            // the special handling the large number of the
                            // PHP warnings to not allocate memory: u->buffer
                            // from its start (after the cache header) again
                            u.resp.buf.clear();
                            self.pos = 0;
                            self.large_stderr = true;
                        }

                        return NGX_AGAIN;
                    }
                } else {
                    self.state = State::Padding;
                }

                continue;
            }

            // f->type == NGX_HTTP_FASTCGI_STDOUT

            if self.large_stderr && crate::file_cache::cache_of(r).is_some() {
                // A tail of large stderr output before HTTP header is placed
                // in a cache file without a FastCGI record header. To
                // workaround it we put a dummy FastCGI record header at the
                // start of the stderr output, or skip to the record header
                // of the stdout if there is no enough place for it (the
                // raw header in the cache file starts after what is skipped,
                // where C moves r->cache->header_start).
                let len = self.pos as isize - 2 * HEADER_SIZE as isize;

                if len >= 0 {
                    let len = len as usize;

                    u.resp.buf[..HEADER_SIZE].copy_from_slice(&[1, NGX_HTTP_FASTCGI_STDERR, 0, 1, ((len >> 8) & 0xff) as u8, (len & 0xff) as u8, 0, 0]);
                } else {
                    let skip = self.pos - HEADER_SIZE;

                    u.resp.buf.drain(..skip);
                    self.pos -= skip;
                }

                self.large_stderr = false;
            }

            self.fastcgi_stdout = true;

            let last = u.resp.buf.len();

            let start = self.pos;

            // set u->buffer.last to the end of the FastCGI record data for
            // ngx_http_parse_header_line()
            let record_last = if self.pos + self.length < last { self.pos + self.length } else { last };

            let mut part_start;
            let mut part_end;

            let rc = loop {
                part_start = self.pos;
                part_end = record_last;

                let rc = crate::parse::parse_header_line(&mut self.pr, &u.resp.buf[..record_last], &mut self.pos, true);

                http_debug!(r, "http fastcgi parser: {}", rc);

                if rc == NGX_AGAIN {
                    break rc;
                }

                if rc == NGX_OK {
                    // a header line has been parsed successfully

                    let hrc = self.header_line(r, u, part_start);

                    if hrc != NGX_OK {
                        return hrc;
                    }

                    if self.pos < record_last {
                        continue;
                    }

                    // the end of the FastCGI record

                    break rc;
                }

                if rc == NGX_HTTP_PARSE_HEADER_DONE {
                    // a whole header has been parsed successfully

                    let hrc = self.header_done(r, u);

                    if hrc != NGX_OK {
                        return hrc;
                    }

                    break rc;
                }

                // rc == NGX_HTTP_PARSE_INVALID_HEADER

                let pr = &self.pr;

                let end = pr.header_end.min(u.resp.buf.len());
                let hstart = pr.header_name_start.min(end);
                let ch = u.resp.buf.get(end).copied().unwrap_or(0);

                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid header: \"{}\\x{:02x}...\"", B(&u.resp.buf[hstart..end]), ch);

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            };

            self.length -= self.pos - start;

            if self.length == 0 {
                self.state = State::Padding;
            }

            if rc == NGX_HTTP_PARSE_HEADER_DONE {
                u.resp.pos = self.pos;
                return NGX_OK;
            }

            if rc == NGX_OK {
                continue;
            }

            // rc == NGX_AGAIN

            http_debug!(r, "upstream split a header line in FastCGI records");

            self.split_parts.push(u.resp.buf[part_start..part_end].to_vec());

            if self.pos < u.resp.buf.len() {
                continue;
            }

            return NGX_AGAIN;
        }
    }

    /// ngx_http_fastcgi_input_filter_init
    fn input_filter_init(&mut self, r: &R, u: &mut Upstream, p: Option<&mut EventPipe>) -> i64 {
        if let Some(p) = p {
            p.length = if self.keep_conn { HEADER_SIZE as i64 } else { -1 };
        }

        let status = u.resp.status_n;

        if status == NGX_HTTP_NO_CONTENT || status == NGX_HTTP_NOT_MODIFIED {
            self.rest = 0;
        } else if r.method.get() == NGX_HTTP_HEAD {
            self.rest = -2;
        } else {
            self.rest = u.resp.content_length_n;
        }

        NGX_OK
    }

    /// ngx_http_fastcgi_non_buffered_filter: the data of the STDOUT records
    /// to u->out_bufs, u->length 0 at the end of the request.
    fn input_filter(&mut self, r: &R, u: &mut Upstream, data: &[u8]) -> i64 {
        let last = data.len();

        // f->pos
        let mut pos = 0usize;

        loop {
            if self.state < State::Data {
                let rc = self.process_record(&r.connection.log, data, &mut pos);

                if rc == NGX_AGAIN {
                    break;
                }

                if rc == NGX_ERROR {
                    return NGX_ERROR;
                }

                if self.ty == NGX_HTTP_FASTCGI_STDOUT && self.length == 0 {
                    self.state = State::Padding;

                    http_debug!(r, "http fastcgi closed stdout");

                    continue;
                }
            }

            if self.state == State::Padding {
                if self.ty == NGX_HTTP_FASTCGI_END_REQUEST {
                    if self.rest > 0 {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed FastCGI request");
                        u.error = true;
                        break;
                    }

                    if pos + self.padding < last {
                        u.length = 0;
                        break;
                    }

                    if pos + self.padding == last {
                        u.length = 0;
                        u.keepalive = true;
                        break;
                    }

                    self.padding -= last - pos;

                    break;
                }

                if pos + self.padding < last {
                    self.state = State::Version;
                    pos += self.padding;

                    continue;
                }

                if pos + self.padding == last {
                    self.state = State::Version;

                    break;
                }

                self.padding -= last - pos;

                break;
            }

            // f->state == ngx_http_fastcgi_st_data

            if self.ty == NGX_HTTP_FASTCGI_STDERR {
                if self.length > 0 {
                    if pos == last {
                        break;
                    }

                    self.log_stderr(r, data, &mut pos);
                } else {
                    self.state = State::Padding;
                }

                continue;
            }

            if self.ty == NGX_HTTP_FASTCGI_END_REQUEST {
                if pos + self.length <= last {
                    self.state = State::Padding;
                    pos += self.length;

                    continue;
                }

                self.length -= last - pos;

                break;
            }

            // f->type == NGX_HTTP_FASTCGI_STDOUT

            if pos == last {
                break;
            }

            if self.rest == 0 {
                ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
                u.length = 0;
                break;
            }

            http_debug!(r, "http fastcgi output buf {}", pos);

            let b_pos = pos;
            let mut b_last;

            if pos + self.length <= last {
                self.state = State::Padding;
                pos += self.length;
                b_last = pos;
            } else {
                self.length -= last - pos;
                pos = last;
                b_last = last;
            }

            let mut done = false;

            if self.rest > 0 {
                if (b_last - b_pos) as i64 > self.rest {
                    ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");

                    b_last = b_pos + self.rest as usize;
                    u.length = 0;

                    done = true;
                } else {
                    self.rest -= (b_last - b_pos) as i64;
                }
            }

            let mut b = Buf::from_vec(data[b_pos..b_last].to_vec());
            b.flush = true;
            b.memory = true;
            b.temporary = false;

            u.out_bufs.push_back(b);

            if done {
                break;
            }
        }

        NGX_OK
    }

    /// ngx_http_fastcgi_input_filter: the data of the STDOUT records of a raw
    /// buffer to p->in, as its shadows; the end of the request, and with
    /// fastcgi_keep_conn, p->length for the rest of the record.
    fn pipe_input_filter(&mut self, r: &R, u: &mut Upstream, p: &mut EventPipe, buf: RawBuf) -> i64 {
        if buf.is_empty() {
            p.release_raw(buf.slot);
            return NGX_OK;
        }

        if p.upstream_done || self.closed {
            u.keepalive = false;

            http_debug!(r, "http fastcgi data after close");

            p.release_raw(buf.slot);
            return NGX_OK;
        }

        let data = buf.bytes();
        let last = data.len();

        // f->pos, and the last shadow made (b)
        let mut pos = 0usize;
        let mut shadow: Option<(usize, usize)> = None;

        loop {
            if self.state < State::Data {
                let rc = self.process_record(&r.connection.log, data, &mut pos);

                if rc == NGX_AGAIN {
                    break;
                }

                if rc == NGX_ERROR {
                    return NGX_ERROR;
                }

                if self.ty == NGX_HTTP_FASTCGI_STDOUT && self.length == 0 {
                    self.state = State::Padding;

                    http_debug!(r, "http fastcgi closed stdout");

                    if self.rest > 0 {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed FastCGI stdout");

                        p.upstream_error = true;
                        p.upstream_eof = false;
                        self.closed = true;

                        break;
                    }

                    if !self.keep_conn {
                        p.upstream_done = true;
                    }

                    continue;
                }

                if self.ty == NGX_HTTP_FASTCGI_END_REQUEST {
                    http_debug!(r, "http fastcgi sent end request");

                    if self.rest > 0 {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed FastCGI request");

                        p.upstream_error = true;
                        p.upstream_eof = false;
                        self.closed = true;

                        break;
                    }

                    if !self.keep_conn {
                        p.upstream_done = true;
                        break;
                    }

                    continue;
                }
            }

            if self.state == State::Padding {
                if self.ty == NGX_HTTP_FASTCGI_END_REQUEST {
                    if pos + self.padding < last {
                        p.upstream_done = true;
                        break;
                    }

                    if pos + self.padding == last {
                        p.upstream_done = true;
                        u.keepalive = true;
                        break;
                    }

                    self.padding -= last - pos;

                    break;
                }

                if pos + self.padding < last {
                    self.state = State::Version;
                    pos += self.padding;

                    continue;
                }

                if pos + self.padding == last {
                    self.state = State::Version;

                    break;
                }

                self.padding -= last - pos;

                break;
            }

            // f->state == ngx_http_fastcgi_st_data

            if self.ty == NGX_HTTP_FASTCGI_STDERR {
                if self.length > 0 {
                    if pos == last {
                        break;
                    }

                    self.log_stderr(r, data, &mut pos);
                } else {
                    self.state = State::Padding;
                }

                continue;
            }

            if self.ty == NGX_HTTP_FASTCGI_END_REQUEST {
                if pos + self.length <= last {
                    self.state = State::Padding;
                    pos += self.length;

                    continue;
                }

                self.length -= last - pos;

                break;
            }

            // f->type == NGX_HTTP_FASTCGI_STDOUT

            if pos == last {
                break;
            }

            if self.rest == -2 {
                self.rest = u.resp.content_length_n;
            }

            if self.rest == 0 {
                ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
                p.upstream_done = true;
                break;
            }

            http_debug!(r, "input buf #{} {}", buf.slot, pos);

            let b_pos = pos;
            let mut b_last;

            if pos + self.length <= last {
                self.state = State::Padding;
                pos += self.length;
                b_last = pos;
            } else {
                self.length -= last - pos;
                pos = last;
                b_last = last;
            }

            let mut done = false;

            if self.rest > 0 {
                if (b_last - b_pos) as i64 > self.rest {
                    ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");

                    b_last = b_pos + self.rest as usize;
                    p.upstream_done = true;

                    done = true;
                } else {
                    self.rest -= (b_last - b_pos) as i64;
                }
            }

            p.push_in(Buf::from_vec(data[b_pos..b_last].to_vec()), buf.slot);

            shadow = Some((b_pos, b_last));

            if done {
                break;
            }
        }

        if self.keep_conn {
            // set p->length, minimal amount of data we want to see
            p.length = match self.state {
                s if s < State::Data => 1,
                State::Padding => self.padding as i64,
                // ngx_http_fastcgi_st_data
                _ => self.length as i64,
            };
        }

        if let Some((b_pos, b_last)) = shadow {
            http_debug!(r, "input buf {} {}", b_pos, b_last - b_pos);
            return NGX_OK;
        }

        // there is no data record in the buf, add it to free chain
        p.release_raw(buf.slot);

        NGX_OK
    }

    /// ngx_http_fastcgi_finalize_request
    fn finalize_request(&mut self, r: &R, _u: &mut Upstream, _rc: i64) {
        http_debug!(r, "finalize http fastcgi request");
    }

    /// ngx_http_fastcgi_body_output_filter: the first buffer (the request)
    /// as it is, then the buffers of the body read after it in STDIN records
    /// of up to 32K, with the empty STDIN record after the last buffer.
    fn body_output_filter(&mut self, r: &R, _u: &mut Upstream, bufs: Chain) -> Chain {
        http_debug!(r, "fastcgi output filter");

        body_output(&r.connection.log, &mut self.header_sent, bufs)
    }
}

/// ngx_http_fastcgi_create_key: fastcgi_cache_key
fn create_keys(r: &R, keys: &mut crate::file_cache::CacheKeys) -> i64 {
    let lcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());

    let cv = lcf.borrow().cache.cache_key.clone();

    match cv {
        Some(cv) => crate::upstream_cache::push_key_value(r, &cv, keys),
        None => {
            keys.push(b"");
            NGX_OK
        }
    }
}

/// A record header (ngx_http_fastcgi_header_t) of the request, request id 1.
fn record_header(out: &mut Vec<u8>, ty: u8, len: usize, padding: usize) {
    out.extend_from_slice(&[1, ty, 0, 1, ((len >> 8) & 0xff) as u8, (len & 0xff) as u8, padding as u8, 0]);
}

/// The size of the length of a name or value of a param: 4 bytes for more
/// than 127, else 1.
fn nv_len_size(len: usize) -> usize {
    if len > 127 {
        4
    } else {
        1
    }
}

/// The length of a name or value of a param: 4 bytes, the high bit set,
/// for more than 127, else 1.
fn push_nv_len(out: &mut Vec<u8>, len: usize) {
    if len > 127 {
        out.push((((len >> 24) & 0x7f) | 0x80) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    } else {
        out.push(len as u8);
    }
}

/// A param: the length of the name, the length of the value, the name, the
/// value (create_request writes the value in place).
#[cfg(test)]
fn push_param(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    push_nv_len(out, key.len());
    push_nv_len(out, value.len());
    out.extend_from_slice(key);
    out.extend_from_slice(value);
}

/// The data of a buffer of the body in STDIN records of up to 32K: each
/// record header goes to `cl` (the buffer with the padding of the record
/// before), the data after it as a buffer of its own, and `cl` becomes the
/// buffer with the padding of the record. Returns that padding.
fn stdin_records(out: &mut Chain, cl: &mut Vec<u8>, b: &Buf) -> usize {
    let mut padding;

    if b.in_file {
        let mut file_pos = b.file_pos;

        loop {
            let start = file_pos;

            file_pos += STDIN_DATA_SIZE as i64;

            let next = file_pos >= b.file_last;

            if next {
                file_pos = b.file_last;
            }

            let len = (file_pos - start) as usize;

            padding = (8 - len % 8) % 8;

            record_header(cl, NGX_HTTP_FASTCGI_STDIN, len, padding);
            out.push_back(Buf::from_vec(std::mem::take(cl)));

            let mut nb = b.clone();
            nb.file_pos = start;
            nb.file_last = file_pos;
            nb.last_buf = false;
            nb.last_in_chain = false;
            out.push_back(nb);

            *cl = vec![0u8; padding];

            if next {
                break;
            }
        }
    } else {
        let data: &[u8] = match &b.data {
            BufData::Memory(v) => &v[b.pos.min(v.len())..b.last.min(v.len())],
            _ => &[],
        };

        let mut pos = 0usize;

        loop {
            let start = pos;

            pos += STDIN_DATA_SIZE;

            let next = pos >= data.len();

            if next {
                pos = data.len();
            }

            let len = pos - start;

            padding = (8 - len % 8) % 8;

            record_header(cl, NGX_HTTP_FASTCGI_STDIN, len, padding);
            out.push_back(Buf::from_vec(std::mem::take(cl)));

            let mut nb = Buf::from_vec(data[start..pos].to_vec());
            nb.flush = b.flush;
            out.push_back(nb);

            *cl = vec![0u8; padding];

            if next {
                break;
            }
        }
    }

    padding
}

/// ngx_http_fastcgi_create_request: u->request_bufs: the BEGIN_REQUEST
/// record, the PARAMS record (the params of fastcgi_param and the defaults,
/// the values of the lengths pass: the variables are cached, e.flushed = 1;
/// then the request headers as HTTP_* params unless a HTTP_* param of that
/// name exists, the headers of a name sent as one with the values joined),
/// the empty PARAMS record, and, the body buffered, its STDIN records and
/// the empty one.
fn create_request(r: &R, flcf: &NgxHttpFastcgiLocConf, cacheable: bool) -> Result<Chain, ()> {
    let params = if cacheable { flcf.params_cache.as_ref() } else { flcf.params.as_ref() };

    let params = match params {
        Some(p) => p,
        None => return Err(()),
    };

    let mut len: usize = 0;

    // the lengths of the params (e.flushed: the values are evaluated once,
    // the values pass reads them)

    crate::script::script_flush_no_cacheable_variables(r, Some(&params.flushes));

    for p in params.params.iter() {
        let val_len = crate::proxy::codes_len(r, &p.codes);

        if p.skip_empty && val_len == 0 {
            continue;
        }

        len += nv_len_size(p.key.len()) + p.key.len() + nv_len_size(val_len) + val_len;
    }

    let pass_request_headers = *flcf.pass_request_headers;
    let hides = |lowcase_key: &[u8]| params.hides(lowcase_key);

    if pass_request_headers {
        let hin = r.headers_in.borrow();

        crate::upstream_rt::for_each_header_param(&hin.headers, &hides, |_, key_len, val_len| {
            len += nv_len_size(key_len) + key_len + nv_len_size(val_len) + val_len;
        });
    }

    if len > 65535 {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "fastcgi request record is too big: {}", len);
        return Err(());
    }

    let padding = (8 - len % 8) % 8;

    let mut b: Vec<u8> = Vec::with_capacity(HEADER_SIZE + 8 + HEADER_SIZE + len + padding + HEADER_SIZE + HEADER_SIZE);

    // ngx_http_fastcgi_request_start
    let flags = if *flcf.keep_conn { NGX_HTTP_FASTCGI_KEEP_CONN } else { 0 };

    record_header(&mut b, NGX_HTTP_FASTCGI_BEGIN_REQUEST, 8, 0);
    b.extend_from_slice(&[0, NGX_HTTP_FASTCGI_RESPONDER, flags, 0, 0, 0, 0, 0]);
    record_header(&mut b, NGX_HTTP_FASTCGI_PARAMS, len, padding);

    // the values of the params (the lengths were those of these values:
    // "fastcgi request length mismatch" cannot happen)

    for p in params.params.iter() {
        let val_len = crate::proxy::codes_len(r, &p.codes);

        if p.skip_empty && val_len == 0 {
            continue;
        }

        push_nv_len(&mut b, p.key.len());
        push_nv_len(&mut b, val_len);
        b.extend_from_slice(&p.key);

        let value = b.len();

        crate::proxy::append_codes(r, &p.codes, &mut b);

        http_debug!(r, "fastcgi param: \"{}: {}\"", B(&p.key), B(&b[value..]));
    }

    if pass_request_headers {
        let hin = r.headers_in.borrow();
        let headers = &hin.headers;

        crate::upstream_rt::for_each_header_param(headers, &hides, |i, key_len, val_len| {
            push_nv_len(&mut b, key_len);
            push_nv_len(&mut b, val_len);

            let key = b.len();

            crate::upstream_rt::push_header_param_key(&mut b, headers, i);

            let value = b.len();

            crate::upstream_rt::push_header_param_value(&mut b, headers, i);

            http_debug!(r, "fastcgi param: \"{}: {}\"", B(&b[key..value]), B(&b[value..]));
        });
    }

    b.resize(b.len() + padding, 0);

    record_header(&mut b, NGX_HTTP_FASTCGI_PARAMS, 0, 0);

    let mut bufs = Chain::new();

    if r.request_body_no_buffering.get() {
        // the body follows through ngx_http_fastcgi_body_output_filter
        bufs.push_back(Buf::from_vec(b));

        return Ok(bufs);
    }

    // the buffer the next record header goes to
    let mut cl = b;

    if *flcf.pass_request_body {
        crate::upstream_rt::with_request_body_bufs(r, |bodies| {
            for body in bodies {
                if body.special_buf() {
                    continue;
                }

                stdin_records(&mut bufs, &mut cl, body);
            }
        });
    }

    record_header(&mut cl, NGX_HTTP_FASTCGI_STDIN, 0, 0);

    bufs.push_back(Buf::from_vec(cl));

    Ok(bufs)
}

/// ngx_http_fastcgi_body_output_filter: unless `header_sent`, the first
/// buffer (the request header) as it is; then the buffers in STDIN records
/// (the special ones but for last_buf dropped), and after the last buffer
/// the empty STDIN record; the padding buffer of the last record, or a
/// sync buffer if it has none.
fn body_output(log: &Log, header_sent: &mut bool, bufs: Chain) -> Chain {
    let mut out = Chain::new();
    let mut input = bufs;

    if input.is_empty() {
        return out;
    }

    if !*header_sent {
        // first buffer contains headers, pass it unmodified

        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "fastcgi output header");

        *header_sent = true;

        if let Some(b) = input.pop_front() {
            out.push_back(b);
        }

        if input.is_empty() {
            return out;
        }
    }

    // the buffer of the next record header: with room for the padding of
    // the record before
    let mut cl: Vec<u8> = Vec::with_capacity(HEADER_SIZE + 7);

    let mut last = false;
    let mut padding = 0;

    for b in input.iter() {
        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "fastcgi output in  l:{} f:{} size: {} file: {}, size: {}", b.last_buf as i32, b.in_file as i32, if b.in_file { 0 } else { b.buf_size() }, b.file_pos, if b.in_file { b.buf_size() } else { 0 });

        if b.last_buf {
            last = true;
        }

        if b.special_buf() {
            continue;
        }

        padding = stdin_records(&mut out, &mut cl, b);
    }

    if last {
        record_header(&mut cl, NGX_HTTP_FASTCGI_STDIN, 0, 0);

        let mut b = Buf::from_vec(cl);
        b.last_buf = true;

        out.push_back(b);
    } else if padding == 0 {
        // TODO: do not allocate buffers instead
        out.push_back(Buf::special());
    } else {
        out.push_back(Buf::from_vec(cl));
    }

    for b in out.iter() {
        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "fastcgi output out l:{} f:{} size: {} file: {}, size: {}", b.last_buf as i32, b.in_file as i32, if b.in_file { 0 } else { b.buf_size() }, b.file_pos, if b.in_file { b.buf_size() } else { 0 });
    }

    out
}

/// The end of the stderr message from `msg` to `pos`: the trailing LF, CR,
/// '.' and ' ' dropped, but the first byte.
fn stderr_end(data: &[u8], msg: usize, pos: usize) -> usize {
    // for (p = pos - 1; msg < p; p--)
    let mut p = pos as isize - 1;

    while (msg as isize) < p {
        let ch = data[p as usize];

        if ch != LF && ch != CR && ch != b'.' && ch != b' ' {
            break;
        }

        p -= 1;
    }

    (p + 1) as usize
}

/// ngx_strnstr(s, pattern, len): the pattern in `s` (up to a NUL byte); an
/// empty one is never found.
fn strnstr(s: &[u8], pattern: &[u8]) -> bool {
    let s = match s.iter().position(|&c| c == 0) {
        Some(n) => &s[..n],
        None => s,
    };

    if pattern.is_empty() || pattern.len() > s.len() {
        return false;
    }

    s.windows(pattern.len()).any(|w| w == pattern)
}

// ---------------------------------------------------------------------------
// the variables
// ---------------------------------------------------------------------------

/// ngx_http_fastcgi_split: the script name and the path info of the URI by
/// fastcgi_split_path_info, once for the request.
fn split(r: &R, flcf: &NgxHttpFastcgiLocConf) -> Rc<RefCell<FastcgiCtx>> {
    let f = match r.get_ctx::<FastcgiCtx>(ctx_index()) {
        Some(f) => f,
        None => r.set_ctx(ctx_index(), FastcgiCtx::default()),
    };

    if !f.borrow().script_name.is_empty() {
        return f;
    }

    let uri = r.uri.borrow().clone();

    let re = match &flcf.split_regex {
        Some(re) => re.clone(),
        None => {
            f.borrow_mut().script_name = uri;
            return f;
        }
    };

    match re.exec(&uri) {
        Some(captures) => {
            let capture = |n: usize| match captures.get(n) {
                Some(&(s, e)) if s >= 0 && e >= s => uri[s as usize..e as usize].to_vec(),
                _ => Vec::new(),
            };

            let mut fc = f.borrow_mut();

            fc.script_name = capture(1);
            fc.path_info = capture(2);
        }

        None => f.borrow_mut().script_name = uri,
    }

    f
}

/// ngx_http_fastcgi_script_name_variable: with fastcgi_index after a "/"
fn script_name_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let lcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());
    let flcf = lcf.borrow();

    let f = split(r, &flcf);

    let mut script_name = f.borrow().script_name.clone();

    if script_name.last() == Some(&b'/') {
        script_name.extend_from_slice(flcf.index.get());
    }

    v.data = script_name;
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    NGX_OK
}

/// ngx_http_fastcgi_path_info_variable
fn path_info_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let lcf = r.loc_conf::<NgxHttpFastcgiLocConf>(ctx_index());
    let flcf = lcf.borrow();

    let f = split(r, &flcf);

    v.data = f.borrow().path_info.clone();
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    NGX_OK
}

/// ngx_http_fastcgi_add_variables
fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = vec![
        VarDef { name: "fastcgi_script_name", get: Some(script_name_variable), set: None, data: 0, flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE | crate::variables::NGX_HTTP_VAR_NOHASH },
        VarDef { name: "fastcgi_path_info", get: Some(path_info_variable), set: None, data: 0, flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE | crate::variables::NGX_HTTP_VAR_NOHASH },
    ];

    crate::variables::add_variables(cf, &vars)
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

/// ngx_http_fastcgi_merge_loc_conf
fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let mut p = conf_cell::<NgxHttpFastcgiLocConf>(prev).borrow_mut();
    let mut c = conf_cell::<NgxHttpFastcgiLocConf>(conf).borrow_mut();

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
        return Err(cf.emerg(format_args!("there must be at least 2 \"fastcgi_buffers\"")));
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
            "\"fastcgi_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"fastcgi_buffer_size\" and one of the \"fastcgi_buffers\""
        )));
    }

    if c.busy_buffers_size > (c.bufs.num - 1) * c.bufs.size {
        return Err(cf.emerg(format_args!("\"fastcgi_busy_buffers_size\" must be less than the size of all \"fastcgi_buffers\" minus one buffer")));
    }

    merge_unset(&mut c.temp_file_write_size_conf, &p.temp_file_write_size_conf);

    c.temp_file_write_size = match c.temp_file_write_size_conf.as_option() {
        None => 2 * size,
        Some(&s) => s,
    };

    if c.temp_file_write_size < size {
        return Err(cf.emerg(format_args!(
            "\"fastcgi_temp_file_write_size\" must be equal to or greater than the maximum of the value of \"fastcgi_buffer_size\" and one of the \"fastcgi_buffers\""
        )));
    }

    merge_unset(&mut c.max_temp_file_size_conf, &p.max_temp_file_size_conf);

    c.max_temp_file_size = match c.max_temp_file_size_conf.as_option() {
        None => 1024 * 1024 * 1024,
        Some(&s) => s,
    };

    if c.max_temp_file_size != 0 && c.max_temp_file_size < size {
        return Err(cf.emerg(format_args!(
            "\"fastcgi_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"fastcgi_buffer_size\" and one of the \"fastcgi_buffers\""
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
        merge_path_value(cf, &mut slot, &p.temp_path, ngx_core::NGX_HTTP_FASTCGI_TEMP_PATH, [1, 2, 0])?;
        c.temp_path = slot;
    }

    // NGX_HTTP_CACHE: fastcgi_cache, the "zone is unknown" check and the
    // "no fastcgi_cache_key" warning, fastcgi_cache_*, fastcgi_no_cache,
    // fastcgi_cache_key (and fastcgi_ignore_headers)
    let prev_cache = p.cache.clone();
    c.cache.merge(cf, &prev_cache, "fastcgi", false)?;

    c.pass_request_headers.merge(&p.pass_request_headers, true);
    c.pass_request_body.merge(&p.pass_request_body, true);

    c.intercept_errors.merge(&p.intercept_errors, false);

    if !c.catch_stderr.is_set() {
        c.catch_stderr = p.catch_stderr.clone();
    }

    c.keep_conn.merge(&p.keep_conn, false);

    c.index.merge(&p.index, Vec::new());

    {
        let (cc, pp) = (&mut *c, &mut *p);

        crate::upstream_rt::hide_headers_hash(
            cf,
            crate::upstream_rt::HideHeaders { hide: &mut cc.hide_headers, pass: &mut cc.pass_headers, hash: &mut cc.hide_headers_hash },
            crate::upstream_rt::HideHeaders { hide: &mut pp.hide_headers, pass: &mut pp.pass_headers, hash: &mut pp.hide_headers_hash },
            FASTCGI_HIDE_HEADERS,
            "fastcgi_hide_headers_hash",
            64,
        )?;
    }

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    let (noname, lmt_excpt, has_handler) = {
        let l = clcf.borrow();
        (l.noname, l.lmt_excpt, l.handler.is_some())
    };

    if noname && c.upstream.is_none() && c.fastcgi_values.is_none() {
        c.upstream = p.upstream.clone();

        c.fastcgi_values = p.fastcgi_values.clone();
    }

    if lmt_excpt && !has_handler && (c.upstream.is_some() || c.fastcgi_values.is_some()) {
        clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(fastcgi_handler(r))));
    }

    if c.split_regex.is_none() {
        c.split_regex = p.split_regex.clone();
        c.split_name = p.split_name.clone();
    }

    if c.params_source.is_none() {
        c.params = p.params.clone();
        c.params_cache = p.params_cache.clone();
        c.params_source = p.params_source.clone();
    }

    if c.params.is_none() {
        let params = crate::upstream_rt::init_params(cf, c.params_source.as_ref(), FASTCGI_HEADERS, "fastcgi_params_hash")?;
        c.params = Some(params);
    }

    if c.cache.enabled() && c.params_cache.is_none() {
        let params = crate::upstream_rt::init_params(cf, c.params_source.as_ref(), FASTCGI_CACHE_HEADERS, "fastcgi_params_hash")?;
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

/// flcf->upstream, the ngx_http_upstream_conf_t of the location, as merged
fn upstream_conf(c: &NgxHttpFastcgiLocConf) -> UpstreamConf {
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
        module: "fastcgi",
    }
}

// ---------------------------------------------------------------------------
// the directives
// ---------------------------------------------------------------------------

fn flcf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<NgxHttpFastcgiLocConf>> {
    conf_rc::<NgxHttpFastcgiLocConf>(conf.as_ref().expect("conf"))
}

/// ngx_http_fastcgi_pass
fn fastcgi_pass(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);

    {
        let flcf = cell.borrow();

        if flcf.upstream.is_some() || flcf.fastcgi_values.is_some() {
            return Err(msg("is duplicate"));
        }
    }

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    {
        let mut lc = clcf.borrow_mut();

        lc.handler = Some(Rc::new(|r| Box::pin(fastcgi_handler(r))));

        if lc.name.last() == Some(&b'/') {
            lc.auto_redirect = true;
        }
    }

    let url = cf.args[1].clone();

    let n = crate::script::script_variables_count(&url);

    if n != 0 {
        let codes = crate::script::script_compile(cf, &url)?;

        cell.borrow_mut().fastcgi_values = Some(Rc::new(codes));

        return Ok(());
    }

    let mut u = Url::new(&url);
    u.no_resolve = true;

    let uscf = upstream_add(cf, &mut u, 0)?;

    cell.borrow_mut().upstream = Some(uscf);

    Ok(())
}

/// ngx_http_fastcgi_split_path_info
fn fastcgi_split_path_info(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);

    let pattern = cf.args[1].clone();

    cell.borrow_mut().split_name = pattern.clone();

    let re = match Regex::compile(&pattern, 0) {
        Ok(re) => re,
        Err(e) => return Err(cf.emerg(format_args!("{}", e))),
    };

    if re.captures != 2 {
        return Err(cf.emerg(format_args!("pattern \"{}\" must have 2 captures", B(&pattern))));
    }

    cell.borrow_mut().split_regex = Some(re);

    Ok(())
}

/// ngx_http_fastcgi_store
fn fastcgi_store(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);

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
        return Err(msg("is incompatible with \"fastcgi_cache\""));
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

/// ngx_http_fastcgi_cache
fn fastcgi_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);

    if cell.borrow().cache.cache.is_set() {
        return Err(msg("is duplicate"));
    }

    if cf.args[1] == b"off" {
        cell.borrow_mut().cache.cache = Val::set(false);
        return Ok(());
    }

    if cell.borrow().store.get_or(false) {
        return Err(msg("is incompatible with \"fastcgi_store\""));
    }

    let mut ucf = std::mem::take(&mut cell.borrow_mut().cache);
    let rc = crate::upstream_cache::cache_slot(cf, &mut ucf, "ngx_http_fastcgi_module");
    cell.borrow_mut().cache = ucf;
    rc
}

/// fastcgi_send_lowat: ngx_conf_set_size_slot with
/// ngx_http_fastcgi_lowat_check (no NGX_HAVE_SO_SNDLOWAT: ignored)
fn fastcgi_send_lowat(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);
    let mut slot = std::mem::take(&mut cell.borrow_mut().send_lowat);

    let rc = set_size(cf, cmd, &mut slot);

    if rc.is_ok() {
        cf.warn(format_args!("\"fastcgi_send_lowat\" is not supported, ignored"));
        slot = Val::set(0);
    }

    cell.borrow_mut().send_lowat = slot;
    rc
}

/// fastcgi_pass_header, fastcgi_hide_header, fastcgi_catch_stderr:
/// ngx_conf_set_str_array_slot
fn fastcgi_str_array(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);
    let mut c = cell.borrow_mut();

    let slot = match cmd.name {
        "fastcgi_pass_header" => &mut c.pass_headers,
        "fastcgi_hide_header" => &mut c.hide_headers,
        _ => &mut c.catch_stderr,
    };

    crate::upstream_rt::str_array_push(slot, &cf.args[1]);

    Ok(())
}

/// fastcgi_param: ngx_http_upstream_param_set_slot
fn fastcgi_param(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);
    let mut list = cell.borrow_mut().params_source.take();
    let rc = crate::upstream_rt::param_set_slot(cf, &mut list);
    cell.borrow_mut().params_source = list;
    rc
}

/// fastcgi_bind: ngx_http_upstream_bind_set_slot
fn fastcgi_bind(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);
    let mut local = std::mem::take(&mut cell.borrow_mut().local);
    let rc = crate::upstream_rt::bind_set_slot(cf, &mut local);
    cell.borrow_mut().local = local;
    rc
}

/// fastcgi_next_upstream: ngx_conf_set_bitmask_slot
fn fastcgi_next_upstream(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);
    let mut c = cell.borrow_mut();
    set_bitmask(cf, cmd, &mut c.next_upstream, FASTCGI_NEXT_UPSTREAM_MASKS)
}

/// fastcgi_limit_rate: ngx_http_set_complex_value_size_slot
fn fastcgi_limit_rate(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);
    let mut slot = cell.borrow().limit_rate.clone();
    crate::script::set_complex_value_size_slot(cf, cmd, &mut slot)?;
    cell.borrow_mut().limit_rate = slot;
    Ok(())
}

/// fastcgi_temp_path: ngx_conf_set_path_slot
fn fastcgi_temp_path(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);
    let mut slot = std::mem::take(&mut cell.borrow_mut().temp_path);
    let rc = set_path(cf, cmd, &mut slot);
    cell.borrow_mut().temp_path = slot;
    rc
}

/// fastcgi_cache_use_stale: ngx_conf_set_bitmask_slot with
/// ngx_http_fastcgi_next_upstream_masks
fn fastcgi_cache_use_stale(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = flcf_of(&conf);
    let mut c = cell.borrow_mut();
    crate::upstream_cache::cache_use_stale_slot(cf, cmd, &mut c.cache, FASTCGI_NEXT_UPSTREAM_MASKS)
}

pub fn fastcgi_module() -> ModuleDef {
    use crate::upstream_cache as uc;
    use ngx_core::cmd;

    type C = NgxHttpFastcgiLocConf;

    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd_fn!("fastcgi_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_pass),
        cmd!("fastcgi_index", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, index, set_str),
        cmd_fn!("fastcgi_split_path_info", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_split_path_info),
        cmd_fn!("fastcgi_store", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_store),
        cmd!("fastcgi_store_access", F | NGX_CONF_TAKE123, ConfLevel::Loc, C, store_access, set_access),
        cmd!("fastcgi_buffering", F | NGX_CONF_FLAG, ConfLevel::Loc, C, buffering, set_flag),
        cmd!("fastcgi_request_buffering", F | NGX_CONF_FLAG, ConfLevel::Loc, C, request_buffering, set_flag),
        cmd!("fastcgi_ignore_client_abort", F | NGX_CONF_FLAG, ConfLevel::Loc, C, ignore_client_abort, set_flag),
        cmd_fn!("fastcgi_bind", F | NGX_CONF_TAKE12, ConfLevel::Loc, fastcgi_bind),
        cmd!("fastcgi_socket_keepalive", F | NGX_CONF_FLAG, ConfLevel::Loc, C, socket_keepalive, set_flag),
        cmd!("fastcgi_socket_rcvbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_rcvbuf, set_size),
        cmd!("fastcgi_socket_sndbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_sndbuf, set_size),
        cmd!("fastcgi_connect_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, connect_timeout, set_msec),
        cmd!("fastcgi_send_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, send_timeout, set_msec),
        cmd_fn!("fastcgi_send_lowat", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_send_lowat),
        cmd!("fastcgi_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, buffer_size, set_size),
        cmd!("fastcgi_pass_request_headers", F | NGX_CONF_FLAG, ConfLevel::Loc, C, pass_request_headers, set_flag),
        cmd!("fastcgi_pass_request_body", F | NGX_CONF_FLAG, ConfLevel::Loc, C, pass_request_body, set_flag),
        cmd!("fastcgi_intercept_errors", F | NGX_CONF_FLAG, ConfLevel::Loc, C, intercept_errors, set_flag),
        cmd!("fastcgi_read_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, read_timeout, set_msec),
        cmd!("fastcgi_buffers", F | NGX_CONF_TAKE2, ConfLevel::Loc, C, bufs, set_bufs),
        cmd!("fastcgi_busy_buffers_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, busy_buffers_size_conf, set_size),
        cmd!("fastcgi_force_ranges", F | NGX_CONF_FLAG, ConfLevel::Loc, C, force_ranges, set_flag),
        cmd_fn!("fastcgi_limit_rate", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_limit_rate),
        cmd_fn!("fastcgi_cache", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_cache),
        cmd_fn!("fastcgi_cache_key", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_key_slot::<C>),
        cmd_fn!("fastcgi_cache_path", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, |cf, cmd, conf| uc::cache_path_slot(cf, cmd, conf, "ngx_http_fastcgi_module")),
        cmd_fn!("fastcgi_cache_bypass", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_bypass_slot::<C>),
        cmd_fn!("fastcgi_no_cache", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::no_cache_slot::<C>),
        cmd_fn!("fastcgi_cache_valid", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_valid_slot::<C>),
        cmd_fn!("fastcgi_cache_min_uses", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_min_uses_slot::<C>),
        cmd_fn!("fastcgi_cache_max_range_offset", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_max_range_offset_slot::<C>),
        cmd_fn!("fastcgi_cache_use_stale", F | NGX_CONF_1MORE, ConfLevel::Loc, fastcgi_cache_use_stale),
        cmd_fn!("fastcgi_cache_methods", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::cache_methods_slot::<C>),
        cmd_fn!("fastcgi_cache_lock", F | NGX_CONF_FLAG, ConfLevel::Loc, uc::cache_lock_slot::<C>),
        cmd_fn!("fastcgi_cache_lock_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_lock_timeout_slot::<C>),
        cmd_fn!("fastcgi_cache_lock_age", F | NGX_CONF_TAKE1, ConfLevel::Loc, uc::cache_lock_age_slot::<C>),
        cmd_fn!("fastcgi_cache_revalidate", F | NGX_CONF_FLAG, ConfLevel::Loc, uc::cache_revalidate_slot::<C>),
        cmd_fn!("fastcgi_cache_background_update", F | NGX_CONF_FLAG, ConfLevel::Loc, uc::cache_background_update_slot::<C>),
        cmd_fn!("fastcgi_temp_path", F | NGX_CONF_TAKE1234, ConfLevel::Loc, fastcgi_temp_path),
        cmd!("fastcgi_max_temp_file_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, max_temp_file_size_conf, set_size),
        cmd!("fastcgi_temp_file_write_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, temp_file_write_size_conf, set_size),
        cmd_fn!("fastcgi_next_upstream", F | NGX_CONF_1MORE, ConfLevel::Loc, fastcgi_next_upstream),
        cmd!("fastcgi_next_upstream_tries", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_tries, set_num),
        cmd!("fastcgi_next_upstream_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_timeout, set_msec),
        cmd_fn!("fastcgi_param", F | NGX_CONF_TAKE23, ConfLevel::Loc, fastcgi_param),
        cmd_fn!("fastcgi_pass_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_str_array),
        cmd_fn!("fastcgi_hide_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_str_array),
        cmd_fn!("fastcgi_ignore_headers", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::ignore_headers_slot::<C>),
        cmd_fn!("fastcgi_catch_stderr", F | NGX_CONF_TAKE1, ConfLevel::Loc, fastcgi_str_array),
        cmd!("fastcgi_keep_conn", F | NGX_CONF_FLAG, ConfLevel::Loc, C, keep_conn, set_flag),
    ];

    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        create_main_conf: Some(crate::upstream_cache::create_main_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_fastcgi_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> Log {
        Log::stderr(NGX_LOG_ERR)
    }

    fn records(bufs: &Chain) -> Vec<u8> {
        crate::upstream_rt::chain_bytes(bufs)
    }

    #[test]
    fn test_record_header() {
        let mut b = Vec::new();
        record_header(&mut b, NGX_HTTP_FASTCGI_STDIN, 0x1234, 4);
        assert_eq!(b, [1, 5, 0, 1, 0x12, 0x34, 4, 0]);
    }

    #[test]
    fn test_push_param() {
        let mut b = Vec::new();
        push_param(&mut b, b"AB", b"xyz");
        assert_eq!(b, b"\x02\x03ABxyz");

        let value = vec![b'v'; 200];
        let mut b = Vec::new();
        push_param(&mut b, b"K", &value);
        assert_eq!(&b[..5], &[1, 0x80, 0, 0, 200]);
        assert_eq!(nv_len_size(127), 1);
        assert_eq!(nv_len_size(128), 4);
    }

    #[test]
    fn test_stderr_end() {
        assert_eq!(stderr_end(b"abc\r\n", 0, 5), 3);
        assert_eq!(stderr_end(b"abc. .", 0, 6), 3);
        // the first byte stays
        assert_eq!(stderr_end(b"\n\n", 0, 2), 1);
        // nothing
        assert_eq!(stderr_end(b"xyz", 3, 3), 3);
    }

    #[test]
    fn test_strnstr() {
        assert!(strnstr(b"sample stderr text", b"sample"));
        assert!(strnstr(b"sample stderr text", b"text"));
        assert!(!strnstr(b"sample stderr text", b"texts"));
        assert!(!strnstr(b"sam\0ple", b"ple"));
        assert!(!strnstr(b"sample", b""));
    }

    #[test]
    fn test_stdin_records() {
        // a buffer in records of up to 32K, the padding with the next header
        let data = vec![b'x'; STDIN_DATA_SIZE + 3];
        let b = Buf::from_vec(data);

        let mut out = Chain::new();
        let mut cl = Vec::new();
        let padding = stdin_records(&mut out, &mut cl, &b);

        assert_eq!(padding, 5);
        assert_eq!(out.len(), 4);
        assert_eq!(records(&out)[..8], [1, 5, 0, 1, 0x80, 0, 0, 0]);
        assert_eq!(cl, vec![0u8; 5]);
    }

    #[test]
    fn test_body_output() {
        let log = log();

        let mut chain = Chain::new();
        chain.push_back(Buf::from_vec(b"REQUEST".to_vec()));
        chain.push_back(Buf::from_vec(b"abc".to_vec()));

        // the request header as it is, then a record for the body with its
        // padding
        let mut sent = false;
        let out = body_output(&log, &mut sent, chain);
        assert!(sent);
        assert_eq!(records(&out), b"REQUEST\x01\x05\x00\x01\x00\x03\x05\x00abc\x00\x00\x00\x00\x00");

        // the last buffer: the empty STDIN record after the padding
        let mut chain = Chain::new();
        chain.push_back(Buf::from_vec(b"12345678".to_vec()));
        let mut lb = Buf::special();
        lb.last_buf = true;
        chain.push_back(lb);

        let out = body_output(&log, &mut sent, chain);
        assert_eq!(records(&out), b"\x01\x05\x00\x01\x00\x08\x00\x0012345678\x01\x05\x00\x01\x00\x00\x00\x00");
        assert!(out.back().unwrap().last_buf);

        // no padding: a sync buffer at the end
        let mut chain = Chain::new();
        chain.push_back(Buf::from_vec(b"12345678".to_vec()));
        let out = body_output(&log, &mut sent, chain);
        assert!(out.back().unwrap().special_buf());
    }

    #[test]
    fn test_process_record() {
        let log = log();

        let conf = || {
            let mut c = new_loc_conf();
            c.keep_conn = Val::set(false);
            Rc::new(RefCell::new(c))
        };

        let mut m = FastcgiModule::new(conf());

        // a STDOUT record header in two parts
        let mut pos = 0;
        assert_eq!(m.process_record(&log, &[1, 6, 0], &mut pos), NGX_AGAIN);
        assert_eq!(pos, 3);

        let mut pos = 0;
        assert_eq!(m.process_record(&log, &[1, 0x01, 0x02, 3, 0, b'x'], &mut pos), NGX_OK);
        assert_eq!(pos, 5);
        assert_eq!(m.ty, NGX_HTTP_FASTCGI_STDOUT);
        assert_eq!(m.length, 0x0102);
        assert_eq!(m.padding, 3);
        assert_eq!(m.state, State::Data);

        // an invalid version
        let mut m = FastcgiModule::new(conf());
        let mut pos = 0;
        assert_eq!(m.process_record(&log, &[2], &mut pos), NGX_ERROR);
    }

    #[test]
    fn test_new_loc_conf_unset() {
        let c = new_loc_conf();
        assert!(!c.keep_conn.is_set());
        assert!(!c.catch_stderr.is_set());
        assert!(c.params_source.is_none());
    }
}
