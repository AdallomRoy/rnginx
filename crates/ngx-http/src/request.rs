//! HTTP request object (ngx_http_request.h) and connection handling (ngx_http_request.c).

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use ngx_core::buf::Chain;
use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::parse::ParseRequest;
use crate::*;

pub type R = Rc<Request>;

/// ngx_table_elt_t
pub struct TableElt {
    pub hash: Cell<u32>,
    pub key: Vec<u8>,
    pub value: RefCell<Vec<u8>>,
    pub lowcase_key: Vec<u8>,
}

pub type Header = Rc<TableElt>;

impl TableElt {
    pub fn new(key: &[u8], value: &[u8]) -> Header {
        Rc::new(TableElt {
            hash: Cell::new(1),
            key: key.to_vec(),
            value: RefCell::new(value.to_vec()),
            lowcase_key: ngx_core::string::to_lower_vec(key),
        })
    }

    pub fn with_hash(key: &[u8], value: &[u8], hash: u32, lowcase_key: Vec<u8>) -> Header {
        Rc::new(TableElt { hash: Cell::new(hash), key: key.to_vec(), value: RefCell::new(value.to_vec()), lowcase_key })
    }

    pub fn value(&self) -> Vec<u8> {
        self.value.borrow().clone()
    }

    pub fn set_value(&self, v: &[u8]) {
        *self.value.borrow_mut() = v.to_vec();
    }

    pub fn is_removed(&self) -> bool {
        self.hash.get() == 0
    }
}

#[derive(Default)]
pub struct HeadersIn {
    pub headers: Vec<Header>,
    pub count: usize,
    pub host: Option<Header>,
    pub connection: Vec<Header>,
    pub if_modified_since: Option<Header>,
    pub if_unmodified_since: Option<Header>,
    pub if_match: Option<Header>,
    pub if_none_match: Option<Header>,
    pub user_agent: Vec<Header>,
    pub referer: Vec<Header>,
    pub content_length: Option<Header>,
    pub content_range: Option<Header>,
    pub content_type: Vec<Header>,
    pub range: Vec<Header>,
    pub if_range: Option<Header>,
    pub transfer_encoding: Option<Header>,
    pub te: Vec<Header>,
    pub expect: Option<Header>,
    pub upgrade: Vec<Header>,
    pub accept_encoding: Vec<Header>,
    pub via: Vec<Header>,
    pub authorization: Option<Header>,
    pub proxy_authorization: Option<Header>,
    pub keep_alive: Vec<Header>,
    pub x_forwarded_for: Vec<Header>,
    pub x_real_ip: Vec<Header>,
    pub accept: Vec<Header>,
    pub accept_language: Vec<Header>,
    pub depth: Vec<Header>,
    pub destination: Vec<Header>,
    pub overwrite: Vec<Header>,
    pub date: Vec<Header>,
    pub cookie: Vec<Header>,
    pub user: Vec<u8>,
    /// Some("") means "tested, none" (C: user.data != NULL && len == 0)
    pub user_tested: bool,
    pub passwd: Vec<u8>,
    pub server: Vec<u8>,
    pub content_length_n: i64,
    pub keep_alive_n: i64,
    pub connection_type: u32,
    pub chunked: bool,
    pub multi: bool,
    pub multi_linked: bool,
    pub msie: bool,
    pub msie6: bool,
    pub opera: bool,
    pub gecko: bool,
    pub chrome: bool,
    pub safari: bool,
    pub konqueror: bool,
}

impl HeadersIn {
    pub fn new() -> HeadersIn {
        HeadersIn { content_length_n: -1, keep_alive_n: -1, ..Default::default() }
    }

    /// Find first header by lowercase name.
    pub fn find(&self, lowcase: &[u8]) -> Option<&Header> {
        self.headers.iter().find(|h| h.lowcase_key == lowcase)
    }
}

pub struct HeadersOut {
    pub headers: Vec<Header>,
    pub trailers: Vec<Header>,
    pub status: i64,
    pub status_line: Vec<u8>,
    pub server: Option<Header>,
    pub date: Option<Header>,
    pub content_length: Option<Header>,
    pub content_encoding: Option<Header>,
    pub location: Option<Header>,
    pub refresh: Option<Header>,
    pub last_modified: Option<Header>,
    pub content_range: Option<Header>,
    pub accept_ranges: Option<Header>,
    pub www_authenticate: Vec<Header>,
    pub proxy_authenticate: Vec<Header>,
    pub expires: Option<Header>,
    pub etag: Option<Header>,
    pub cache_control: Vec<Header>,
    pub link: Vec<Header>,
    pub override_charset: Option<Vec<u8>>,
    pub content_type_len: usize,
    pub content_type: Vec<u8>,
    pub charset: Vec<u8>,
    pub content_type_lowcase: Option<Vec<u8>>,
    pub content_type_hash: u32,
    pub content_length_n: i64,
    pub content_offset: i64,
    pub date_time: i64,
    pub last_modified_time: i64,
}

impl HeadersOut {
    pub fn new() -> HeadersOut {
        HeadersOut {
            headers: Vec::new(),
            trailers: Vec::new(),
            status: 0,
            status_line: Vec::new(),
            server: None,
            date: None,
            content_length: None,
            content_encoding: None,
            location: None,
            refresh: None,
            last_modified: None,
            content_range: None,
            accept_ranges: None,
            www_authenticate: Vec::new(),
            proxy_authenticate: Vec::new(),
            expires: None,
            etag: None,
            cache_control: Vec::new(),
            link: Vec::new(),
            override_charset: None,
            content_type_len: 0,
            content_type: Vec::new(),
            charset: Vec::new(),
            content_type_lowcase: None,
            content_type_hash: 0,
            content_length_n: -1,
            content_offset: 0,
            date_time: 0,
            last_modified_time: -1,
        }
    }

    /// Push a header into the list and return it (ngx_list_push + setup).
    pub fn add(&mut self, key: &[u8], value: &[u8]) -> Header {
        let h = TableElt::new(key, value);
        self.headers.push(h.clone());
        h
    }

    /// Find first non-removed header by lowercase key.
    pub fn find(&self, lowcase: &[u8]) -> Option<&Header> {
        self.headers.iter().find(|h| h.hash.get() != 0 && h.lowcase_key == lowcase)
    }
}

/// ngx_http_request_body_t
pub struct RequestBody {
    pub temp_file: Option<ngx_core::buf::TempFile>,
    pub bufs: Chain,
    pub buf: Option<ngx_core::buf::Buf>,
    pub rest: i64,
    pub received: i64,
    pub chunked: Option<crate::parse::ChunkedState>,
    pub filter_need_buffering: bool,
    pub last_sent: bool,
    pub last_saved: bool,
    /// rb->buf of an unbuffered HTTP/1 body as its size and fill level
    /// (buf->last - buf->start); the data read is passed on at once.
    pub buf_size: usize,
    pub buf_last: usize,
}

/// Variable value cache entry (ngx_http_variable_value_t).
#[derive(Clone, Default, Debug)]
pub struct VariableValue {
    pub data: Vec<u8>,
    pub valid: bool,
    pub no_cacheable: bool,
    pub not_found: bool,
    pub escape: bool,
}

/// ngx_http_upstream_state_t
#[derive(Clone, Default, Debug)]
pub struct UpstreamState {
    pub bl_time: u64,
    pub bl_state: u32,
    pub status: i64,
    pub response_time: u64,
    pub connect_time: u64,
    pub header_time: u64,
    pub queue_time: u64,
    pub response_length: i64,
    pub bytes_received: i64,
    pub bytes_sent: i64,
    pub peer: Vec<u8>,
}

pub type ContentHandler = Rc<dyn Fn(R) -> BoxFut<i64>>;
pub type PostSubrequest = Rc<dyn Fn(&R, i64) -> i64>;
pub type CleanupFn = Box<dyn FnOnce()>;

/// ngx_http_connection_t
pub struct HttpConnection {
    pub addr_conf: Rc<AddrConf>,
    pub conf_ctx: RefCell<ConfCtx>,
    pub ssl: Cell<bool>,
    pub proxy_protocol: Cell<bool>,
    pub ssl_servername: RefCell<Option<Vec<u8>>>,
    pub ssl_servername_regex: RefCell<Option<Rc<crate::variables::HttpRegex>>>,
    pub keepalive_timeout: Cell<u64>,
    /// Client header buffer shared by pipelined requests.
    pub buffer: RefCell<HeaderBuf>,
    pub nbusy: Cell<usize>,
}

/// In-memory header buffer: data[pos..last] unread.
#[derive(Default)]
pub struct HeaderBuf {
    pub data: Vec<u8>,
    pub pos: usize,
    pub last: usize,
    /// Capacity per large buffer / small buffer semantic bookkeeping.
    pub allocated: bool,
    pub cap: usize,
    pub nbusy: usize,
}

impl HeaderBuf {
    pub fn unread(&self) -> &[u8] {
        &self.data[self.pos..self.last]
    }
    pub fn compact(&mut self) {
        if self.pos == self.last {
            self.pos = 0;
            self.last = 0;
        } else if self.pos > 0 {
            self.data.copy_within(self.pos..self.last, 0);
            self.last -= self.pos;
            self.pos = 0;
        }
    }
}

/// Log context for a connection: ", client: ..., server: ..., request: ..."
pub struct HttpLogCtx {
    pub connection: Weak<Connection>,
    pub request: RefCell<Option<Weak<Request>>>,
    pub current_request: RefCell<Option<Weak<Request>>>,
}

impl LogContext for HttpLogCtx {
    fn write_context(&self, buf: &mut Vec<u8>) {
        let c = match self.connection.upgrade() {
            Some(c) => c,
            None => return,
        };
        if let Some(a) = c.log.action() {
            buf.extend_from_slice(b" while ");
            buf.extend_from_slice(a.as_bytes());
        }
        buf.extend_from_slice(b", client: ");
        buf.extend_from_slice(&c.addr_text.borrow());
        let r = self.request.borrow().as_ref().and_then(|w| w.upgrade());
        match r {
            Some(r) => {
                let sr = self.current_request.borrow().as_ref().and_then(|w| w.upgrade()).unwrap_or_else(|| r.clone());
                log_error_handler(&r, &sr, buf);
            }
            None => {
                if let Some(ls) = c.listening() {
                    buf.extend_from_slice(b", server: ");
                    buf.extend_from_slice(&ls.addr_text);
                }
            }
        }
    }
}

/// ngx_http_log_error_handler
pub fn log_error_handler(r: &R, sr: &R, buf: &mut Vec<u8>) {
    let cscf = r.srv_conf::<CoreSrvConf>(core::ctx_index());
    buf.extend_from_slice(b", server: ");
    buf.extend_from_slice(&cscf.borrow().server_name);
    let rl = r.request_line.borrow();
    if !rl.is_empty() {
        buf.extend_from_slice(b", request: \"");
        buf.extend_from_slice(&rl);
        buf.push(b'"');
    } else if let Some(line) = r.partial_request_line() {
        buf.extend_from_slice(b", request: \"");
        buf.extend_from_slice(&line);
        buf.push(b'"');
    }
    if !Rc::ptr_eq(r, sr) {
        buf.extend_from_slice(b", subrequest: \"");
        buf.extend_from_slice(&sr.uri.borrow());
        buf.push(b'"');
    }
    if let Some(u) = sr.upstream_log_info() {
        buf.extend_from_slice(b", upstream: \"");
        buf.extend_from_slice(&u);
        buf.push(b'"');
    }
    let hin = r.headers_in.borrow();
    if let Some(h) = &hin.host {
        buf.extend_from_slice(b", host: \"");
        buf.extend_from_slice(&h.value.borrow());
        buf.push(b'"');
    }
    if let Some(h) = hin.referer.first() {
        buf.extend_from_slice(b", referrer: \"");
        buf.extend_from_slice(&h.value.borrow());
        buf.push(b'"');
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HttpState {
    InitializingRequest = 0,
    ReadingRequest,
    ProcessRequest,
    ConnectUpstream,
    WritingUpstream,
    ReadingUpstream,
    WritingRequest,
    LingeringClose,
    Keepalive,
}

pub struct Request {
    pub connection: Rc<Connection>,
    pub http_connection: Rc<HttpConnection>,
    pub ctx: RefCell<Vec<Option<Rc<dyn Any>>>>,
    pub main_conf: RefCell<Rc<ConfSlots>>,
    pub srv_conf: RefCell<Rc<ConfSlots>>,
    pub loc_conf: RefCell<Rc<ConfSlots>>,

    pub upstream: RefCell<Option<Rc<dyn Any>>>,
    /// Upstream response headers, populated by proxy/fastcgi/etc. Read by $upstream_http_* variables.
    pub upstream_headers_in: RefCell<Vec<Header>>,
    pub upstream_states: RefCell<Vec<UpstreamState>>,
    pub cache: RefCell<Option<Rc<dyn Any>>>,

    pub headers_in: RefCell<HeadersIn>,
    pub headers_out: RefCell<HeadersOut>,
    pub request_body: RefCell<Option<Rc<RefCell<RequestBody>>>>,

    pub lingering_time: Cell<i64>,
    pub start_sec: Cell<i64>,
    pub start_msec: Cell<u64>,

    pub method: Cell<u32>,
    pub http_version: Cell<u32>,
    pub request_line: RefCell<Vec<u8>>,
    pub uri: RefCell<Vec<u8>>,
    pub args: RefCell<Vec<u8>>,
    pub exten: RefCell<Vec<u8>>,
    pub unparsed_uri: RefCell<Vec<u8>>,
    pub method_name: RefCell<Vec<u8>>,
    pub http_protocol: RefCell<Vec<u8>>,
    pub schema: RefCell<Vec<u8>>,
    pub host_in_request_line: RefCell<Vec<u8>>,

    /// Pending output chain of the write filter.
    pub out: RefCell<Chain>,

    pub main: RefCell<Option<Weak<Request>>>,
    pub parent: RefCell<Option<Weak<Request>>>,
    pub post_subrequest: RefCell<Option<PostSubrequest>>,

    pub phase_handler: Cell<usize>,
    pub content_handler: RefCell<Option<ContentHandler>>,
    pub access_code: Cell<i64>,

    pub variables: RefCell<Vec<VariableValue>>,
    pub ncaptures: Cell<usize>,
    pub captures: RefCell<Vec<i32>>,
    pub captures_data: RefCell<Vec<u8>>,

    pub limit_rate: Cell<usize>,
    pub limit_rate_after: Cell<usize>,
    pub header_size: Cell<usize>,
    pub request_length: Cell<i64>,
    pub err_status: Cell<i64>,

    pub cleanup: RefCell<Vec<CleanupFn>>,
    pub port: Cell<u16>,

    pub count: Cell<u32>,
    pub subrequests: Cell<u32>,
    pub blocked: Cell<u32>,
    pub http_state: Cell<HttpState>,

    // flags
    pub complex_uri: Cell<bool>,
    pub quoted_uri: Cell<bool>,
    pub plus_in_uri: Cell<bool>,
    pub empty_path_in_uri: Cell<bool>,
    pub invalid_header: Cell<bool>,
    pub add_uri_to_alias: Cell<bool>,
    pub valid_location: Cell<bool>,
    pub valid_unparsed_uri: Cell<bool>,
    pub uri_changed: Cell<bool>,
    pub uri_changes: Cell<u32>,
    pub request_body_in_single_buf: Cell<bool>,
    pub request_body_in_file_only: Cell<bool>,
    pub request_body_in_persistent_file: Cell<bool>,
    pub request_body_in_clean_file: Cell<bool>,
    pub request_body_file_group_access: Cell<bool>,
    pub request_body_file_log_level: Cell<u32>,
    pub request_body_no_buffering: Cell<bool>,
    pub subrequest_in_memory: Cell<bool>,
    pub waited: Cell<bool>,
    pub cached: Cell<bool>,
    /// Set when the upstream response did not reach its framing terminator
    /// (no 0-chunk for chunked, or Content-Length short). Prevents
    /// proxy_cache from persisting truncated responses.
    pub upstream_response_incomplete: Cell<bool>,
    pub gzip_tested: Cell<bool>,
    pub gzip_ok: Cell<bool>,
    pub gzip_vary: Cell<bool>,
    pub realloc_captures: Cell<bool>,
    pub proxy: Cell<bool>,
    pub bypass_cache: Cell<bool>,
    pub no_cache: Cell<bool>,
    pub limit_conn_status: Cell<u32>,
    pub limit_req_status: Cell<u32>,
    pub limit_rate_set: Cell<bool>,
    pub limit_rate_after_set: Cell<bool>,
    pub cacheable: Cell<bool>,
    pub pipeline: Cell<bool>,
    pub chunked: Cell<bool>,
    pub header_only: Cell<bool>,
    pub expect_trailers: Cell<bool>,
    pub keepalive: Cell<bool>,
    pub lingering_close: Cell<bool>,
    pub discard_body: Cell<bool>,
    pub reading_body: Cell<bool>,
    pub internal: Cell<bool>,
    pub error_page: Cell<bool>,
    pub filter_finalize: Cell<bool>,
    pub post_action: Cell<bool>,
    pub request_complete: Cell<bool>,
    pub request_output: Cell<bool>,
    pub header_sent: Cell<bool>,
    pub response_sent: Cell<bool>,
    pub expect_tested: Cell<bool>,
    pub root_tested: Cell<bool>,
    pub done: Cell<bool>,
    pub logged: Cell<bool>,
    pub terminated: Cell<bool>,
    pub buffered: Cell<u32>,
    pub main_filter_need_in_memory: Cell<bool>,
    pub filter_need_in_memory: Cell<bool>,
    pub filter_need_temporary: Cell<bool>,
    pub preserve_body: Cell<bool>,
    pub allow_ranges: Cell<bool>,
    pub subrequest_ranges: Cell<bool>,
    pub single_range: Cell<bool>,
    pub disable_not_modified: Cell<bool>,
    pub stat_reading: Cell<bool>,
    pub stat_writing: Cell<bool>,
    pub stat_processing: Cell<bool>,
    pub background: Cell<bool>,
    pub health_check: Cell<bool>,
    /// Set when the request is a subrequest run in the main request's task.
    pub discard_body_done: Cell<bool>,

    /// Parser state for request line / headers (offsets into the header buffer).
    pub parse: RefCell<ParseRequest>,
    /// The HTTP/2 or /3 stream, if any.
    pub stream: RefCell<Option<Rc<dyn Any>>>,
    /// Trailer state etc.
    pub log_ctx: Rc<HttpLogCtx>,
    /// Signalled when a subrequest waiting on this request completes (unused in sequential model).
    pub weak_self: RefCell<Weak<Request>>,
}

impl Request {
    pub fn is_main(&self) -> bool {
        self.main.borrow().is_none()
    }

    pub fn main(self: &Rc<Self>) -> R {
        match self.main.borrow().as_ref().and_then(|w| w.upgrade()) {
            Some(m) => m,
            None => self.clone(),
        }
    }

    pub fn parent(&self) -> Option<R> {
        self.parent.borrow().as_ref().and_then(|w| w.upgrade())
    }

    pub fn me(&self) -> R {
        self.weak_self.borrow().upgrade().expect("request dropped")
    }

    pub fn log(&self) -> &Log {
        &self.connection.log
    }

    pub fn main_conf<T: 'static>(&self, idx: usize) -> Rc<RefCell<T>> {
        slot_of::<T>(&self.main_conf.borrow(), idx)
    }

    pub fn srv_conf<T: 'static>(&self, idx: usize) -> Rc<RefCell<T>> {
        slot_of::<T>(&self.srv_conf.borrow(), idx)
    }

    pub fn loc_conf<T: 'static>(&self, idx: usize) -> Rc<RefCell<T>> {
        slot_of::<T>(&self.loc_conf.borrow(), idx)
    }

    pub fn clcf(&self) -> Rc<RefCell<CoreLocConf>> {
        self.loc_conf::<CoreLocConf>(core::ctx_index())
    }

    pub fn cscf(&self) -> Rc<RefCell<CoreSrvConf>> {
        self.srv_conf::<CoreSrvConf>(core::ctx_index())
    }

    pub fn cmcf(&self) -> Rc<RefCell<CoreMainConf>> {
        self.main_conf::<CoreMainConf>(core::ctx_index())
    }

    pub fn get_ctx<T: 'static>(&self, idx: usize) -> Option<Rc<RefCell<T>>> {
        self.ctx.borrow()[idx].clone().and_then(|c| c.downcast::<RefCell<T>>().ok())
    }

    pub fn set_ctx<T: 'static>(&self, idx: usize, v: T) -> Rc<RefCell<T>> {
        let c = Rc::new(RefCell::new(v));
        self.ctx.borrow_mut()[idx] = Some(c.clone());
        c
    }

    pub fn clear_ctx(&self, idx: usize) {
        self.ctx.borrow_mut()[idx] = None;
    }

    pub fn add_cleanup(&self, f: CleanupFn) {
        self.cleanup.borrow_mut().push(f);
    }

    pub fn run_cleanups(&self) {
        let v: Vec<CleanupFn> = std::mem::take(&mut *self.cleanup.borrow_mut());
        for f in v {
            f();
        }
    }

    pub fn partial_request_line(&self) -> Option<Vec<u8>> {
        let p = self.parse.borrow();
        if p.uri_start.is_some() || p.method_end != 0 {
            let hb = self.http_connection.buffer.borrow();
            let start = p.request_start.min(hb.last);
            let mut end = start;
            while end < hb.last && hb.data[end] != b'\r' && hb.data[end] != b'\n' {
                end += 1;
            }
            return Some(hb.data[start..end].to_vec());
        }
        None
    }

    /// ", upstream: "schema peer uri"" contribution supplied by the upstream module.
    pub fn upstream_log_info(&self) -> Option<Vec<u8>> {
        crate::stubs::upstream_log_info(self)
    }

    /// ngx_http_set_log_request: mark current request for log context.
    pub fn set_log_request(self: &Rc<Self>) {
        *self.log_ctx.current_request.borrow_mut() = Some(Rc::downgrade(self));
    }

    pub fn is_proxy_auth(&self) -> bool {
        self.method.get() == NGX_HTTP_CONNECT
    }

    // header helpers (ngx_http_clear_*)
    pub fn clear_content_length(&self) {
        let mut h = self.headers_out.borrow_mut();
        h.content_length_n = -1;
        if let Some(cl) = h.content_length.take() {
            cl.hash.set(0);
        }
    }

    pub fn clear_accept_ranges(&self) {
        let mut h = self.headers_out.borrow_mut();
        if let Some(x) = h.accept_ranges.take() {
            x.hash.set(0);
        }
        self.allow_ranges.set(false);
    }

    pub fn clear_last_modified(&self) {
        let mut h = self.headers_out.borrow_mut();
        h.last_modified_time = -1;
        if let Some(x) = h.last_modified.take() {
            x.hash.set(0);
        }
    }

    pub fn clear_location(&self) {
        let mut h = self.headers_out.borrow_mut();
        if let Some(x) = h.location.take() {
            x.hash.set(0);
        }
    }

    pub fn clear_etag(&self) {
        let mut h = self.headers_out.borrow_mut();
        if let Some(x) = h.etag.take() {
            x.hash.set(0);
        }
    }

    pub fn clear_content_encoding(&self) {
        let mut h = self.headers_out.borrow_mut();
        if let Some(x) = h.content_encoding.take() {
            x.hash.set(0);
        }
    }
}

/// Allocate a new main request on a connection (ngx_http_alloc_request + create_request).
pub fn alloc_request(c: &Rc<Connection>, hc: &Rc<HttpConnection>, log_ctx: &Rc<HttpLogCtx>) -> R {
    let ctx = hc.conf_ctx.borrow().clone();
    let cmcf = get_conf::<CoreMainConf>(&ctx, ConfLevel::Main, core::ctx_index());
    let nvars = cmcf.borrow().variables.len();
    let now = ngx_core::times::cached();
    let r = Rc::new(Request {
        connection: c.clone(),
        http_connection: hc.clone(),
        ctx: RefCell::new(vec![None; http_max_module()]),
        main_conf: RefCell::new(ctx.main.clone().unwrap()),
        srv_conf: RefCell::new(ctx.srv.clone().unwrap()),
        loc_conf: RefCell::new(ctx.loc.clone().unwrap()),
        upstream: RefCell::new(None),
        upstream_headers_in: RefCell::new(Vec::new()),
        upstream_states: RefCell::new(Vec::new()),
        cache: RefCell::new(None),
        headers_in: RefCell::new(HeadersIn::new()),
        headers_out: RefCell::new(HeadersOut::new()),
        request_body: RefCell::new(None),
        lingering_time: Cell::new(0),
        start_sec: Cell::new(now.sec),
        start_msec: Cell::new(now.msec),
        method: Cell::new(NGX_HTTP_UNKNOWN),
        http_version: Cell::new(NGX_HTTP_VERSION_10),
        request_line: RefCell::new(Vec::new()),
        uri: RefCell::new(Vec::new()),
        args: RefCell::new(Vec::new()),
        exten: RefCell::new(Vec::new()),
        unparsed_uri: RefCell::new(Vec::new()),
        method_name: RefCell::new(Vec::new()),
        http_protocol: RefCell::new(Vec::new()),
        schema: RefCell::new(Vec::new()),
        host_in_request_line: RefCell::new(Vec::new()),
        out: RefCell::new(Chain::new()),
        main: RefCell::new(None),
        parent: RefCell::new(None),
        post_subrequest: RefCell::new(None),
        phase_handler: Cell::new(0),
        content_handler: RefCell::new(None),
        access_code: Cell::new(0),
        variables: RefCell::new(vec![VariableValue::default(); nvars]),
        ncaptures: Cell::new(0),
        captures: RefCell::new(Vec::new()),
        captures_data: RefCell::new(Vec::new()),
        limit_rate: Cell::new(0),
        limit_rate_after: Cell::new(0),
        header_size: Cell::new(0),
        request_length: Cell::new(0),
        err_status: Cell::new(0),
        cleanup: RefCell::new(Vec::new()),
        port: Cell::new(0),
        count: Cell::new(1),
        subrequests: Cell::new(NGX_HTTP_MAX_SUBREQUESTS + 1),
        blocked: Cell::new(0),
        http_state: Cell::new(HttpState::ReadingRequest),
        complex_uri: Cell::new(false),
        quoted_uri: Cell::new(false),
        plus_in_uri: Cell::new(false),
        empty_path_in_uri: Cell::new(false),
        invalid_header: Cell::new(false),
        add_uri_to_alias: Cell::new(false),
        valid_location: Cell::new(false),
        valid_unparsed_uri: Cell::new(false),
        uri_changed: Cell::new(false),
        uri_changes: Cell::new(NGX_HTTP_MAX_URI_CHANGES + 1),
        request_body_in_single_buf: Cell::new(false),
        request_body_in_file_only: Cell::new(false),
        request_body_in_persistent_file: Cell::new(false),
        request_body_in_clean_file: Cell::new(false),
        request_body_file_group_access: Cell::new(false),
        request_body_file_log_level: Cell::new(NGX_LOG_WARN),
        request_body_no_buffering: Cell::new(false),
        subrequest_in_memory: Cell::new(false),
        waited: Cell::new(false),
        cached: Cell::new(false),
        upstream_response_incomplete: Cell::new(false),
        gzip_tested: Cell::new(false),
        gzip_ok: Cell::new(false),
        gzip_vary: Cell::new(false),
        realloc_captures: Cell::new(false),
        proxy: Cell::new(false),
        bypass_cache: Cell::new(false),
        no_cache: Cell::new(false),
        limit_conn_status: Cell::new(0),
        limit_req_status: Cell::new(0),
        limit_rate_set: Cell::new(false),
        limit_rate_after_set: Cell::new(false),
        cacheable: Cell::new(false),
        pipeline: Cell::new(false),
        chunked: Cell::new(false),
        header_only: Cell::new(false),
        expect_trailers: Cell::new(false),
        keepalive: Cell::new(false),
        lingering_close: Cell::new(false),
        discard_body: Cell::new(false),
        reading_body: Cell::new(false),
        internal: Cell::new(false),
        error_page: Cell::new(false),
        filter_finalize: Cell::new(false),
        post_action: Cell::new(false),
        request_complete: Cell::new(false),
        request_output: Cell::new(false),
        header_sent: Cell::new(false),
        response_sent: Cell::new(false),
        expect_tested: Cell::new(false),
        root_tested: Cell::new(false),
        done: Cell::new(false),
        logged: Cell::new(false),
        terminated: Cell::new(false),
        buffered: Cell::new(0),
        main_filter_need_in_memory: Cell::new(false),
        filter_need_in_memory: Cell::new(false),
        filter_need_temporary: Cell::new(false),
        preserve_body: Cell::new(false),
        allow_ranges: Cell::new(false),
        subrequest_ranges: Cell::new(false),
        single_range: Cell::new(false),
        disable_not_modified: Cell::new(false),
        stat_reading: Cell::new(false),
        stat_writing: Cell::new(false),
        stat_processing: Cell::new(false),
        background: Cell::new(false),
        health_check: Cell::new(false),
        discard_body_done: Cell::new(false),
        parse: RefCell::new(ParseRequest::default()),
        stream: RefCell::new(None),
        log_ctx: log_ctx.clone(),
        weak_self: RefCell::new(Weak::new()),
    });
    *r.weak_self.borrow_mut() = Rc::downgrade(&r);
    if c.ssl.borrow().is_some() {
        r.main_filter_need_in_memory.set(true);
    }
    r
}

/// ngx_http_create_request: allocate and attach to the log context.
pub fn create_request(c: &Rc<Connection>, hc: &Rc<HttpConnection>, log_ctx: &Rc<HttpLogCtx>) -> R {
    let r = alloc_request(c, hc, log_ctx);
    c.requests.set(c.requests.get() + 1);
    // Propagate the connection's pipelined flag onto the request so
    // $pipe evaluates to "p" for pipelined requests (matches C where
    // c->pipeline drives r->pipeline).
    r.pipeline.set(c.pipeline.get());
    let clcf = r.clcf();
    c.log.set_chain(clcf.borrow().error_log.clone().expect("error_log"));
    *log_ctx.request.borrow_mut() = Some(Rc::downgrade(&r));
    *log_ctx.current_request.borrow_mut() = Some(Rc::downgrade(&r));
    ngx_core::connection::stats().reading.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    r.stat_reading.set(true);
    ngx_core::connection::stats().requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    r
}

/// Helper: debug logging with request context.
pub fn debug_http(r: &Request, args: std::fmt::Arguments<'_>) {
    if r.connection.log.debug_enabled(NGX_LOG_DEBUG_HTTP) {
        r.connection.log.error(NGX_LOG_DEBUG, None, args);
    }
}

#[macro_export]
macro_rules! http_debug {
    ($r:expr, $($arg:tt)*) => {
        if $r.connection.log.debug_enabled(ngx_core::log::NGX_LOG_DEBUG_HTTP) {
            $r.connection.log.error(ngx_core::log::NGX_LOG_DEBUG, None, format_args!($($arg)*));
        }
    };
}

pub(crate) fn _silence(log: &Log) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{}", B(b""));
    ngx_log_error!(NGX_LOG_DEBUG, log, None, "{}", NGX_OK);
}
