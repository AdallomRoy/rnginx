//! ngx_http_upstream.c: the request to an upstream server.
//!
//! ngx_http_upstream_init_request and what follows it: the connection to the
//! peer (ngx_http_upstream_connect), the request (send_request and
//! send_request_body), the response header (process_header, test_next,
//! intercept_errors, process_headers), the response (send_response: the
//! upgraded connection, the non-buffered filter, or the event pipe),
//! ngx_http_upstream_next and ngx_http_upstream_finalize_request. The
//! callbacks of the module (u->create_request, u->process_header, the input
//! filters, u->finalize_request, ...) are the methods of UpstreamModule, and
//! the module's context is the object that implements them.
//!
//! The event handlers of C are the await points of the request's task: the
//! request is sent while the response header is waited for, then the body
//! is passed to the client; each wait is also one for the client closing the
//! connection (ngx_http_upstream_check_broken_connection). The log action is
//! set where C sets it and left as it is afterwards.

use std::rc::Rc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::Instant;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::{Bufs, PathConf};
use ngx_core::connection::NGX_ERROR_ERR;
use ngx_core::event_connect::{event_connect_peer, LocalAddr, PeerConnect, PeerSocket};
use ngx_core::hash::{hash_key, Hash};
use ngx_core::inet::{SockAddr, Url};
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::request::*;
use crate::script::{ComplexValue, Part};
use crate::upstream::*;
use crate::upstream_cache::{UpstreamCache, UpstreamCacheConf, NGX_HTTP_UPSTREAM_EARLY_HINTS, NGX_HTTP_UPSTREAM_INVALID_HEADER};
use crate::upstream_ssl::{PeerConn, SslSetup, UpstreamSslConf};
use crate::*;

// ---------------------------------------------------------------------------
// the configuration
// ---------------------------------------------------------------------------

/// ngx_http_upstream_local_t: *_bind
pub struct UpstreamLocal {
    /// local->addr: the address without variables
    pub addr: Option<LocalAddr>,
    /// local->value: the address with variables
    pub value: Option<ComplexValue>,
    pub transparent: bool,
}

/// ngx_http_upstream_conf_t: the fields of the location's upstream
/// configuration a request uses, as the module's merge left them.
pub struct UpstreamConf {
    /// upstream: the upstream{} of *_pass without variables
    pub upstream: Option<Rc<UpstreamSrvConf>>,

    pub connect_timeout: u64,
    pub send_timeout: u64,
    pub read_timeout: u64,
    pub next_upstream_timeout: u64,

    pub send_lowat: usize,
    pub buffer_size: usize,
    pub limit_rate: Option<Rc<ComplexValue>>,

    pub busy_buffers_size: usize,
    pub max_temp_file_size: usize,
    pub temp_file_write_size: usize,

    pub bufs: Bufs,

    /// a bitmask of NGX_HTTP_UPSTREAM_FT_*
    pub next_upstream: u32,
    pub store_access: u32,
    pub next_upstream_tries: u32,
    pub buffering: bool,
    pub request_buffering: bool,
    pub pass_request_headers: bool,
    pub pass_request_body: bool,
    pub pass_trailers: bool,
    pub pass_early_hints: bool,

    pub ignore_client_abort: bool,
    pub intercept_errors: bool,
    pub cyclic_temp_file: bool,
    pub force_ranges: bool,

    pub temp_path: Option<Rc<PathConf>>,

    /// hide_headers_hash: the default hide headers of the module and those
    /// of *_hide_header, but *_pass_header (lower case)
    pub hide_headers_hash: Option<Rc<Hash<()>>>,

    pub local: Option<Rc<UpstreamLocal>>,
    pub socket_keepalive: bool,
    pub socket_rcvbuf: usize,
    pub socket_sndbuf: usize,

    /// the cache fields (and ignore_headers)
    pub cache: UpstreamCacheConf,

    /// store and store_values: *_store on, or its path
    pub store: bool,
    pub store_values: Option<Rc<Vec<Part>>>,

    pub intercept_404: bool,
    pub change_buffering: bool,
    pub preserve_output: bool,
    pub ignore_input: bool,

    /// the SSL fields
    pub ssl: UpstreamSslConf,

    /// module: "proxy", "fastcgi", ...
    pub module: &'static str,
}

impl UpstreamConf {
    /// u->conf->ignore_headers & mask
    pub fn ignores(&self, mask: u32) -> bool {
        self.cache.ignores(mask)
    }

    /// ngx_hash_find(&u->conf->hide_headers_hash, ...)
    pub fn hidden(&self, lowcase_key: &[u8]) -> bool {
        match &self.hide_headers_hash {
            Some(h) => h.find(hash_key(lowcase_key), lowcase_key).is_some(),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// the upstream of a request
// ---------------------------------------------------------------------------

/// u->headers_in and u->buffer of an upstream response
/// (ngx_http_upstream_headers_in_t): what the module's process_header found,
/// the body starting at `pos` in `buf`.
pub struct UpstreamResponse {
    /// u->buffer from start to last
    pub buf: Vec<u8>,
    /// u->buffer.pos once the header is processed
    pub pos: usize,
    pub status_n: i64,
    pub status_line: Vec<u8>,
    pub headers: Vec<Header>,
    pub content_length: Option<Header>,
    pub transfer_encoding: Option<Header>,
    pub content_length_n: i64,
    pub chunked: bool,
    pub connection_close: bool,
    /// headers_in.server and headers_in.date were sent
    pub server: bool,
    pub date: bool,
    /// u->keepalive, set by the module for a response without a body
    pub keepalive: bool,
    /// u->upgrade
    pub upgrade: bool,
    /// u->headers_in.trailers
    pub trailers: Vec<Header>,
    /// the fields of u->headers_in the cache handlers set
    pub cache: crate::upstream_cache::CacheHeadersIn,
}

impl UpstreamResponse {
    pub fn new() -> UpstreamResponse {
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

    /// ngx_memzero(&u->headers_in): the header fields anew, the buffer kept
    pub fn clear_headers(&mut self) {
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
        self.trailers.clear();
        self.cache = crate::upstream_cache::CacheHeadersIn::new();
    }

    /// The first header of a name that counts (a duplicate of those only
    /// the first of which is processed has hash 0): u->headers_in.status,
    /// u->headers_in.location and the like.
    pub fn header(&self, lowcase_key: &[u8]) -> Option<Header> {
        self.headers.iter().find(|h| h.hash.get() != 0 && h.lowcase_key == lowcase_key).cloned()
    }
}

impl Default for UpstreamResponse {
    fn default() -> Self {
        UpstreamResponse::new()
    }
}

/// ngx_http_upstream_t: what the request's upstream is and has of the
/// response, for the module's callbacks and the upstream functions.
pub struct Upstream {
    pub conf: Rc<UpstreamConf>,
    /// r->upstream as the other modules see it: the cache fields, and the
    /// schema, uri and peer name of the error log
    pub ucache: Rc<UpstreamCache>,

    /// u->schema: "http://", "fastcgi://", ... (the error log's upstream)
    pub schema: Vec<u8>,
    /// u->uri: the URI of the request line to the upstream, if any
    pub uri: Vec<u8>,
    /// u->ssl
    pub ssl: bool,
    /// the ALPN protocols of the SSL connection (gRPC)
    pub ssl_alpn: Vec<u8>,
    /// u->resolved: the host of a *_pass with variables
    pub resolved: Option<Url>,

    /// u->request_bufs: the request u->create_request made, with the body
    pub request_bufs: Chain,

    /// u->headers_in and u->buffer
    pub resp: UpstreamResponse,
    /// u->length: what is left of the body (-1: up to the end of the
    /// connection) for the non-buffered filter
    pub length: i64,
    /// u->out_bufs: the body the non-buffered filter passes on
    pub out_bufs: Chain,

    pub buffering: bool,
    pub store: bool,
    pub keepalive: bool,
    pub upgrade: bool,
    pub error: bool,
    pub request_sent: bool,
    pub request_body_sent: bool,
    pub header_sent: bool,
    pub response_received: bool,
    pub early_hints_length: i64,

    /// the peer (u->peer) and its connection (u->peer.connection)
    peer: Option<PeerGuard>,
    sock: Option<UpstreamSock>,
    /// *u->cleanup is set: the upstream was not finalized yet
    cleanup: bool,
    /// u->pipe->downstream_error of a header only response read for the
    /// cache or *_store, or of a failed client connection
    pipe_downstream_error: bool,
    /// ngx_http_upstream_rd_check_broken_connection is the read handler
    watch: Option<Rc<ClientWatch>>,
    /// c->requests and c->start_time of the connection, for the keepalive
    /// cache
    conn_requests: u64,
    conn_start_time: u64,
}

impl Upstream {
    /// ngx_http_upstream_create with the module's u->conf, u->schema and
    /// u->caches: r->upstream anew, r->cache NULL.
    pub fn create(r: &R, conf: Rc<UpstreamConf>, caches: Rc<Vec<Rc<crate::file_cache::FileCache>>>, schema: &[u8]) -> Upstream {
        let ucache = crate::upstream_cache::upstream_create(r, conf.cache.clone(), caches, conf.module, conf.buffer_size);

        *ucache.schema.borrow_mut() = schema.to_vec();

        Upstream {
            buffering: conf.buffering,
            conf,
            ucache,
            schema: schema.to_vec(),
            uri: Vec::new(),
            ssl: false,
            ssl_alpn: Vec::new(),
            resolved: None,
            request_bufs: Chain::new(),
            resp: UpstreamResponse::new(),
            length: -1,
            out_bufs: Chain::new(),
            store: false,
            keepalive: false,
            upgrade: false,
            error: false,
            request_sent: false,
            request_body_sent: false,
            header_sent: false,
            response_received: false,
            early_hints_length: 0,
            peer: None,
            sock: None,
            cleanup: false,
            pipe_downstream_error: false,
            watch: None,
            conn_requests: 0,
            conn_start_time: 0,
        }
    }

    /// u->cacheable
    pub fn cacheable(&self) -> bool {
        self.ucache.cacheable.get()
    }

    /// u->peer.connection is set
    pub fn connected(&self) -> bool {
        self.sock.is_some()
    }

    /// u->state
    fn with_state<F: FnOnce(&mut UpstreamState)>(r: &R, f: F) {
        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            f(st);
        }
    }

    /// u->schema
    pub fn set_schema(&mut self, schema: &[u8]) {
        self.schema = schema.to_vec();
        *self.ucache.schema.borrow_mut() = schema.to_vec();
    }

    /// u->uri for the error log
    pub fn set_uri(&mut self, uri: &[u8]) {
        self.uri = uri.to_vec();
        *self.ucache.uri.borrow_mut() = uri.to_vec();
    }
}

/// The callbacks of the module (those of ngx_http_upstream_t), on the
/// module's context of the request.
pub trait UpstreamModule {
    /// u->create_key: the keys of the cache
    fn create_key(&self, r: &R, keys: &mut Vec<Vec<u8>>) -> i64;

    /// u->create_request: u->request_bufs (and u->uri)
    fn create_request(&mut self, r: &R, u: &mut Upstream) -> i64;

    /// u->reinit_request: the module's state for the response anew
    fn reinit_request(&mut self, r: &R, u: &mut Upstream) -> i64;

    /// u->process_header on u->resp.buf: NGX_OK with u->resp.pos at the
    /// body, NGX_AGAIN for more, NGX_HTTP_UPSTREAM_INVALID_HEADER,
    /// NGX_HTTP_UPSTREAM_EARLY_HINTS, or NGX_ERROR.
    fn process_header(&mut self, r: &R, u: &mut Upstream) -> i64;

    /// u->input_filter_init: u->length, and p->length for the event pipe
    fn input_filter_init(&mut self, r: &R, u: &mut Upstream, p: Option<&mut crate::event_pipe::EventPipe>) -> i64;

    /// u->input_filter of a non-buffered response: `data`, read into
    /// u->buffer, goes to u->out_bufs.
    fn input_filter(&mut self, r: &R, u: &mut Upstream, data: &[u8]) -> i64 {
        non_buffered_filter(r, u, data)
    }

    /// p->input_filter: a raw buffer of the event pipe goes to p->in.
    fn pipe_input_filter(&mut self, r: &R, u: &mut Upstream, p: &mut crate::event_pipe::EventPipe, buf: crate::event_pipe::RawBuf) -> i64 {
        let _ = (r, u);
        crate::event_pipe::copy_input_filter(p, buf)
    }

    /// u->finalize_request
    fn finalize_request(&mut self, r: &R, u: &mut Upstream, rc: i64);

    /// u->output.output_filter for the request body read after the header
    /// (an unbuffered body): the buffers as they are sent.
    fn body_output_filter(&mut self, r: &R, u: &mut Upstream, bufs: Chain) -> Chain {
        let _ = (r, u);
        bufs
    }

    /// u->rewrite_redirect: the "Location" or "Refresh" header copied to
    /// r->headers_out, from `prefix`; NGX_DECLINED if not rewritten.
    fn rewrite_redirect(&mut self, r: &R, h: &Header, prefix: usize) -> i64 {
        let _ = (r, h, prefix);
        NGX_DECLINED
    }

    /// u->rewrite_cookie: a "Set-Cookie" header copied to r->headers_out
    fn rewrite_cookie(&mut self, r: &R, h: &Header) -> i64 {
        let _ = (r, h);
        NGX_DECLINED
    }

    /// whether the module has u->rewrite_redirect / u->rewrite_cookie
    fn has_rewrite_redirect(&self) -> bool {
        false
    }

    fn has_rewrite_cookie(&self) -> bool {
        false
    }
}

/// ngx_http_upstream_non_buffered_filter: the data up to u->length.
pub fn non_buffered_filter(r: &R, u: &mut Upstream, data: &[u8]) -> i64 {
    if u.length == 0 {
        ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");
        return NGX_OK;
    }

    let mut len = data.len();

    if u.length != -1 {
        if len as i64 > u.length {
            ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "upstream sent more data than specified in \"Content-Length\" header");

            len = u.length as usize;
            u.length = 0;
        } else {
            u.length -= len as i64;
        }
    }

    let mut b = Buf::from_vec(data[..len].to_vec());
    b.flush = true;
    b.memory = true;
    b.temporary = false;
    u.out_bufs.push_back(b);

    NGX_OK
}

// ---------------------------------------------------------------------------
// the headers of the response (ngx_http_upstream_headers_in[])
// ---------------------------------------------------------------------------

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

/// The "handler" of ngx_http_upstream_headers_in[] for a header line the
/// module's process_header parsed: ngx_http_upstream_process_header_line
/// and the like (the first of a name counts, a duplicate is ignored with
/// hash 0), content_length, transfer_encoding, connection, the X-Accel-*
/// and the cache handlers. Err is the failure of
/// NGX_HTTP_UPSTREAM_INVALID_HEADER.
pub fn process_header_line(r: &R, u: &mut Upstream, h: &Header) -> Result<(), u32> {
    let invalid = NGX_HTTP_UPSTREAM_FT_INVALID_HEADER;

    let conf = u.conf.clone();
    let resp = &mut u.resp;

    match h.lowcase_key.as_slice() {
        b"content-length" => {
            // ngx_http_upstream_process_content_length
            if let Some(prev) = &resp.content_length {
                ngx_log_error!(
                    NGX_LOG_ERR,
                    r.connection.log,
                    None,
                    "upstream sent duplicate header line: \"{}: {}\", previous value: \"{}: {}\"",
                    B(&h.key),
                    B(&h.value.borrow()),
                    B(&prev.key),
                    B(&prev.value.borrow())
                );
                return Err(invalid);
            }

            if resp.transfer_encoding.is_some() {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent \"Content-Length\" and \"Transfer-Encoding\" headers at the same time");
                return Err(invalid);
            }

            resp.content_length = Some(h.clone());
            resp.content_length_n = atoof(&h.value.borrow());

            if resp.content_length_n == NGX_ERROR {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid \"Content-Length\" header: \"{}: {}\"", B(&h.key), B(&h.value.borrow()));
                return Err(invalid);
            }
        }

        b"transfer-encoding" => {
            // ngx_http_upstream_process_transfer_encoding
            if let Some(prev) = &resp.transfer_encoding {
                ngx_log_error!(
                    NGX_LOG_ERR,
                    r.connection.log,
                    None,
                    "upstream sent duplicate header line: \"{}: {}\", previous value: \"{}: {}\"",
                    B(&h.key),
                    B(&h.value.borrow()),
                    B(&prev.key),
                    B(&prev.value.borrow())
                );
                return Err(invalid);
            }

            if resp.content_length.is_some() {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent \"Content-Length\" and \"Transfer-Encoding\" headers at the same time");
                return Err(invalid);
            }

            resp.transfer_encoding = Some(h.clone());

            let v = h.value.borrow();

            if v.len() == 7 && v.eq_ignore_ascii_case(b"chunked") {
                resp.chunked = true;
            } else {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unknown \"Transfer-Encoding\": \"{}\"", B(&v));
                return Err(invalid);
            }
        }

        b"connection" => {
            // ngx_http_upstream_process_connection
            if ngx_core::string::strcasestr(&h.value.borrow(), b"close").is_some() {
                resp.connection_close = true;
            }
        }

        b"status" | b"content-type" | b"date" | b"last-modified" | b"etag" | b"server" | b"location" | b"refresh" | b"expires" | b"x-accel-expires" | b"x-accel-redirect"
        | b"x-accel-limit-rate" | b"www-authenticate" => {
            // ngx_http_upstream_process_header_line and the like: the
            // first one, a duplicate is ignored
            let prev = resp.headers.iter().find(|p| !Rc::ptr_eq(p, h) && p.hash.get() != 0 && p.lowcase_key == h.lowcase_key).cloned();

            if let Some(prev) = prev {
                if h.lowcase_key == b"www-authenticate" {
                    // ngx_http_upstream_process_multi_header_lines
                    return Ok(());
                }

                ngx_log_error!(
                    NGX_LOG_WARN,
                    r.connection.log,
                    None,
                    "upstream sent duplicate header line: \"{}: {}\", previous value: \"{}: {}\", ignored",
                    B(&h.key),
                    B(&h.value.borrow()),
                    B(&prev.key),
                    B(&prev.value.borrow())
                );
                h.hash.set(0);
                return Ok(());
            }

            match h.lowcase_key.as_slice() {
                b"server" => resp.server = true,
                b"date" => resp.date = true,

                b"x-accel-limit-rate" => {
                    // ngx_http_upstream_process_limit_rate
                    if !conf.ignores(NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE) {
                        if let Some(n) = ngx_core::string::atoi(&h.value.borrow()) {
                            r.limit_rate.set(n as usize);
                            r.limit_rate_set.set(true);
                        }
                    }
                }

                _ => {}
            }

            // the cache handlers: ngx_http_upstream_process_expires,
            // _accel_expires, _last_modified, and the etag
            crate::upstream_cache::process_header_line(r, &mut resp.cache, &h.lowcase_key, &h.value.borrow());
        }

        b"x-accel-buffering" => {
            // ngx_http_upstream_process_buffering
            if !conf.ignores(NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING) && conf.change_buffering {
                let v = h.value.borrow();

                if v.len() == 2 && v.eq_ignore_ascii_case(b"no") {
                    u.buffering = false;
                } else if v.len() == 3 && v.eq_ignore_ascii_case(b"yes") {
                    u.buffering = true;
                }
            }
        }

        b"x-accel-charset" => {
            // ngx_http_upstream_process_charset
            if !conf.ignores(NGX_HTTP_UPSTREAM_IGN_XA_CHARSET) {
                r.headers_out.borrow_mut().override_charset = Some(h.value.borrow().clone());
            }
        }

        b"set-cookie" | b"cache-control" | b"vary" => {
            // ngx_http_upstream_process_set_cookie, _cache_control, _vary
            crate::upstream_cache::process_header_line(r, &mut resp.cache, &h.lowcase_key, &h.value.borrow());
        }

        _ => {}
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ngx_http_upstream_check_broken_connection
// ---------------------------------------------------------------------------

/// ngx_http_upstream_rd_check_broken_connection as the Linux build runs it
/// (epoll with EPOLLRDHUP), on a duplicate of the client socket: its
/// readiness is its own, so the request's reading of the body and of
/// pipelined requests is not disturbed. An HTTP/2 or HTTP/3 stream is not
/// checked.
pub struct ClientWatch {
    afd: Option<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
}

impl ClientWatch {
    pub fn new(r: &R) -> ClientWatch {
        use std::os::fd::FromRawFd;

        if r.stream.borrow().is_some() || r.http_version.get() >= NGX_HTTP_VERSION_20 || r.connection.fd.get() < 0 {
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
    /// closes the connection (rev->pending_eof); data it sends is left to
    /// be read.
    pub async fn closed(&self) -> i32 {
        use std::os::fd::AsRawFd;

        let afd = match &self.afd {
            Some(a) => a,
            None => return std::future::pending().await,
        };

        loop {
            let mut guard = match afd.readable().await {
                Ok(g) => g,
                Err(_) => return std::future::pending().await,
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
pub async fn client_closed(watch: Option<&ClientWatch>) -> i32 {
    match watch {
        Some(w) => w.closed().await,
        None => std::future::pending().await,
    }
}

/// What ngx_http_upstream_check_broken_connection decides when the client
/// closed the connection: Some(499) to finalize the upstream request with,
/// or None to go on (a cacheable response still read from the upstream).
fn check_broken_connection(r: &R, u: &Upstream, err: i32) -> Option<i64> {
    let c = &r.connection;

    c.read_eof.set(true);
    c.error.set(true);

    let err = if err != 0 { Some(err) } else { None };

    if !u.cacheable() && u.connected() {
        ngx_log_error!(NGX_LOG_INFO, c.log, err, "epoll_wait() reported that client prematurely closed connection, so upstream connection is closed too");
        return Some(NGX_HTTP_CLIENT_CLOSED_REQUEST);
    }

    ngx_log_error!(NGX_LOG_INFO, c.log, err, "epoll_wait() reported that client prematurely closed connection");

    if !u.connected() {
        return Some(NGX_HTTP_CLIENT_CLOSED_REQUEST);
    }

    None
}

// ---------------------------------------------------------------------------
// the connection to the peer
// ---------------------------------------------------------------------------

/// How the attempt to a peer failed.
pub(crate) enum Failure {
    /// ngx_http_upstream_next() with this failure type
    Next(u32),
    /// ngx_http_upstream_finalize_request() with this status
    Finalize(i64),
    /// the request was finalized (a stale response sent): the rc
    Done(i64),
}

/// ngx_http_upstream_set_local: the address of *_bind, evaluated if it has
/// variables (an empty or invalid value: none). Err for NGX_ERROR.
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

/// The socket options of u->conf and u->peer.local for
/// ngx_event_connect_peer.
struct PeerOpts {
    rcvbuf: i32,
    sndbuf: i32,
    so_keepalive: bool,
    local: Option<LocalAddr>,
    transparent: bool,
}

/// Whether a socket is a plain connection: its errors are not logged by
/// the SSL layer.
fn plain(sock: &UpstreamSock) -> bool {
    match sock {
        UpstreamSock::Conn(pc) => pc.c.ssl.borrow().is_none(),
        _ => true,
    }
}

/// The connection of an upstream socket.
fn sock_conn(sock: &UpstreamSock) -> Option<&Rc<ngx_core::connection::Connection>> {
    match sock {
        UpstreamSock::Conn(pc) => Some(&pc.c),
        _ => None,
    }
}

/// ngx_event_connect_peer to the chosen peer, the connect timer
/// (u->conf->connect_timeout) and, on the connection,
/// ngx_http_upstream_ssl_init_connection, or the ngx_http_upstream_test_connect
/// of ngx_http_upstream_send_request.
async fn connect_peer(r: &R, u: &mut Upstream, sockaddr: &SockAddr, opts: &PeerOpts, ssl: Option<&SslSetup>) -> Result<UpstreamSock, Failure> {
    let log = r.connection.log.clone();

    let g = u.peer.as_mut().expect("peer");

    let name = g.u.pc.name.clone();

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
        PeerConnect::Declined => return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_ERROR)),
        PeerConnect::Error => return Err(Failure::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR)),
    };

    let pc = PeerConn { c: c.clone() };

    // c->data = r
    g.u.attach(&c);

    let mut deadline = None;

    if again {
        // ngx_add_timer(c->write, u->conf->connect_timeout); on its expiry
        // ngx_http_upstream_send_request_handler calls
        // ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT)
        let d = Instant::now() + Duration::from_millis(u.conf.connect_timeout);

        if tokio::time::timeout_at(d, c.writable()).await.is_err() {
            pc.set_no_shutdown();
            u.sock = Some(UpstreamSock::Conn(pc));
            return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_TIMEOUT));
        }

        deadline = Some(d);
    }

    let rc = match ssl {
        Some(ssl) => {
            let g = u.peer.as_mut().expect("peer");
            crate::upstream_ssl::ssl_init_connection(r, &mut g.u, &c, ssl, deadline, u.conf.connect_timeout).await
        }

        None => {
            // ngx_http_upstream_send_request: ngx_http_upstream_test_connect
            if crate::upstream_ssl::test_connect(&c) != NGX_OK {
                Err(crate::proxy::ConnectError::Error)
            } else {
                Ok(())
            }
        }
    };

    match rc {
        Ok(()) => Ok(UpstreamSock::Conn(pc)),
        Err(e) => {
            if !matches!(e, crate::proxy::ConnectError::Internal) {
                pc.set_no_shutdown();
            }

            // the connection is closed by ngx_http_upstream_next
            u.sock = Some(UpstreamSock::Conn(pc));

            Err(match e {
                crate::proxy::ConnectError::Error => Failure::Next(NGX_HTTP_UPSTREAM_FT_ERROR),
                crate::proxy::ConnectError::Timeout => Failure::Next(NGX_HTTP_UPSTREAM_FT_TIMEOUT),
                crate::proxy::ConnectError::Internal => Failure::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// the request
// ---------------------------------------------------------------------------

/// The part of a request buffer's data sent at most in one write, so that
/// the send timer is armed anew after each write that made progress, as
/// ngx_http_upstream_send_request does.
const SEND_CHUNK: i64 = 65536;

/// The chain written to the upstream connection with its send timer
/// (u->conf->send_timeout, armed while a write waits). Err(None) when it
/// expires, Err(Some(e)) for an error.
async fn write_chain(sock: &mut UpstreamSock, chain: &mut Chain, send_timeout: u64) -> Result<i64, Option<std::io::Error>> {
    let mut sent = 0i64;

    match sock {
        UpstreamSock::Conn(pc) => {
            while chain.iter().any(|b| b.buf_size() > 0) {
                let n = match tokio::time::timeout(Duration::from_millis(send_timeout), crate::output::send_chain(&pc.c, chain, SEND_CHUNK)).await {
                    Err(_) => return Err(None),
                    Ok(Err(e)) => return Err(Some(e)),
                    Ok(Ok(n)) => n,
                };

                sent += n;
            }

            chain.clear();
        }

        _ => {
            // a connection of the keepalive cache made by the other
            // upstream code
            use tokio::io::AsyncWriteExt;

            let data = chain_bytes(chain);

            let mut off = 0;

            while off < data.len() {
                match tokio::time::timeout(Duration::from_millis(send_timeout), sock.write(&data[off..])).await {
                    Err(_) => return Err(None),
                    Ok(Err(e)) => return Err(Some(e)),
                    Ok(Ok(0)) => return Err(Some(std::io::Error::from(std::io::ErrorKind::WriteZero))),
                    Ok(Ok(n)) => off += n,
                }
            }

            sent = data.len() as i64;
            chain.clear();
        }
    }

    Ok(sent)
}

/// The data of a chain: memory buffers as they are, file buffers read.
pub fn chain_bytes(chain: &Chain) -> Vec<u8> {
    let mut out = Vec::new();

    for b in chain.iter() {
        if b.in_file {
            if let BufData::File(f) = &b.data {
                let size = (b.file_last - b.file_pos).max(0) as usize;
                let mut buf = vec![0u8; size];
                let mut off = 0usize;

                while off < size {
                    // SAFETY: buf has size bytes, off < size, and f.fd is an
                    // open file.
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
            if b.in_memory() {
                let end = b.last.min(m.len());

                if b.pos < end {
                    out.extend_from_slice(&m[b.pos..end]);
                }
            }
        }
    }

    out
}

/// The request body buffers read so far (rb->bufs), taken to be sent.
pub fn take_request_body_bufs(r: &R) -> Chain {
    match r.request_body.borrow().as_ref() {
        Some(rb) => std::mem::take(&mut rb.borrow_mut().bufs),
        None => Chain::new(),
    }
}

/// The request body buffers (r->request_body->bufs) as u->request_bufs
/// links them after the module's buffers: memory and file buffers of a
/// buffered body.
pub fn request_body_bufs(r: &R) -> Chain {
    match r.request_body.borrow().as_ref() {
        Some(rb) => rb.borrow().bufs.iter().filter(|b| b.buf_size() > 0).cloned().collect(),
        None => Chain::new(),
    }
}

// ---------------------------------------------------------------------------
// ngx_http_upstream_init_request
// ---------------------------------------------------------------------------

/// ngx_http_upstream_init: the request to the upstream, once the request
/// body is read (or, unbuffered, what is there of it). The return value is
/// the rc of ngx_http_finalize_request.
pub async fn init(r: R, mut u: Upstream, m: &mut dyn UpstreamModule) -> i64 {
    http_debug!(r, "http init upstream, client timer: 0");

    let rc = init_request(&r, &mut u, m).await;

    // r->read_event_handler = ngx_http_block_reading
    u.watch = None;

    rc
}

async fn init_request(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> i64 {
    // ngx_http_upstream_cache, then ngx_http_upstream_cache_send for a
    // response from the cache

    if u.conf.cache.enabled() {
        let ucache = u.ucache.clone();

        let mut rc = {
            let mm: &dyn UpstreamModule = &*m;
            crate::upstream_cache::upstream_cache_wait(r, &ucache, &|r, keys| mm.create_key(r, keys)).await
        };

        if rc == NGX_ERROR {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if rc == NGX_OK {
            rc = cache_send(r, u, m).await;

            if rc == NGX_DONE {
                return NGX_DONE;
            }

            if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_DECLINED;
                r.cached.set(false);
                u.resp = UpstreamResponse::new();
                ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_MISS);
                u.request_sent = true;
            }
        }

        if rc != NGX_DECLINED {
            return rc;
        }
    }

    // the cache is freed when the upstream is done
    let _cache_guard = crate::upstream_cache::CacheGuard::new(r);

    u.store = u.conf.store;

    if !u.store && !r.post_action.get() && !u.conf.ignore_client_abort {
        // ngx_http_upstream_rd_check_broken_connection
        u.watch = Some(Rc::new(ClientWatch::new(r)));
    }

    // u->request_bufs = r->request_body->bufs; u->create_request(r)
    if m.create_request(r, u) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let (local, transparent) = match set_local(r, u.conf.local.as_ref()) {
        Ok(l) => l,
        Err(()) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let opts = PeerOpts {
        rcvbuf: u.conf.socket_rcvbuf as i32,
        sndbuf: u.conf.socket_sndbuf as i32,
        so_keepalive: u.conf.socket_keepalive,
        local,
        transparent,
    };

    // r->upstream_states: a new state for the next upstream of the request
    if r.upstream_states_init.get() {
        r.upstream_states.borrow_mut().push(UpstreamState::default());
    }

    r.upstream_states_init.set(true);

    // u->cleanup
    u.cleanup = true;

    let ssl = if u.ssl { Some(SslSetup { conf: u.conf.ssl.clone(), alpn: u.ssl_alpn.clone() }) } else { None };

    // the peers of u->resolved (the upstream of its host, its address, or
    // the addresses the resolver finds), or of u->conf->upstream

    let conf = u.conf.clone();
    let tag = Rc::as_ptr(&conf) as *const () as usize;

    let watch = u.watch.clone();

    let peer = match u.resolved.clone() {
        Some(url) => {
            let resolve = UpstreamPeer::resolve(r, &url, conf.next_upstream, conf.next_upstream_tries, conf.next_upstream_timeout, tag);

            tokio::select! {
                res = resolve => res,
                err = client_closed(watch.as_deref()) => {
                    let rc = check_broken_connection(r, u, err).unwrap_or(NGX_HTTP_CLIENT_CLOSED_REQUEST);
                    return finalize(r, u, m, rc).await;
                }
            }
        }

        None => match &conf.upstream {
            Some(uscf) => UpstreamPeer::init(r, uscf, conf.next_upstream, conf.next_upstream_tries, conf.next_upstream_timeout, tag),
            None => {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "no upstream configuration");
                Err(NGX_HTTP_INTERNAL_SERVER_ERROR)
            }
        },
    };

    let peer = match peer {
        Ok(p) => p,
        Err(rc) => return finalize(r, u, m, rc).await,
    };

    u.peer = Some(PeerGuard::new(r, peer));

    // ngx_http_upstream_connect, and ngx_http_upstream_next until a
    // response header to send is there
    loop {
        match connect(r, u, m, &opts, ssl.as_ref()).await {
            Ok(()) => break,

            Err(Failure::Next(ft)) => {
                if let Some(rc) = next(r, u, m, ft).await {
                    return rc;
                }
            }

            Err(Failure::Finalize(rc)) => return finalize(r, u, m, rc).await,

            Err(Failure::Done(rc)) => return rc,
        }
    }

    // peer.notify(NGX_HTTP_UPSTREAM_NOTIFY_HEADER)
    if let Some(g) = u.peer.as_mut() {
        g.u.notify(r, NGX_HTTP_UPSTREAM_NOTIFY_HEADER);
    }

    match process_headers(r, u, m).await {
        Processed::Ok => {}
        Processed::Done(rc) => return rc,
    }

    send_response(r, u, m).await
}

/// ngx_http_upstream_connect, ngx_http_upstream_send_request and
/// ngx_http_upstream_process_header up to a response header that
/// ngx_http_upstream_test_next and ngx_http_upstream_intercept_errors let
/// through.
async fn connect(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule, opts: &PeerOpts, ssl: Option<&SslSetup>) -> Result<(), Failure> {
    r.connection.log.set_action(Some("connecting to upstream"));

    let (rc, start_time) = {
        let g = u.peer.as_mut().expect("peer");

        // a new state, and the peer (ngx_event_connect_peer's pc->get)
        let rc = g.u.connect(r);

        (rc, g.u.start_time)
    };

    // u->peer.name for the error log: the peer, or the upstream's name
    // when there is none (NGX_BUSY)
    set_log_peer(u);

    if rc == NGX_ERROR {
        return Err(Failure::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR));
    }

    if rc == NGX_BUSY {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no live upstreams");
        return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_NOLIVE));
    }

    let sock = if rc == NGX_DONE {
        // a cached keepalive connection; c->data = r
        let g = u.peer.as_mut().expect("peer");
        let c = g.u.pc.connection.take().expect("cached connection");
        g.u.attach_sock(&c.sock);
        u.conn_requests = c.requests;
        u.conn_start_time = c.start_time;
        c.sock
    } else {
        let sockaddr = match u.peer.as_ref().and_then(|g| g.u.pc.sockaddr.clone()) {
            Some(sa) => sa,
            None => return Err(Failure::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR)),
        };

        let watch = u.watch.clone();

        let connected = {
            let connect = connect_peer(r, u, &sockaddr, opts, ssl);

            tokio::select! {
                res = connect => Some(res),
                err = client_closed(watch.as_deref()) => {
                    // no connection yet: 499
                    let _ = err;
                    None
                }
            }
        };

        match connected {
            None => {
                let rc = check_broken_connection(r, u, 0).unwrap_or(NGX_HTTP_CLIENT_CLOSED_REQUEST);
                return Err(Failure::Finalize(rc));
            }
            Some(Err(f)) => return Err(f),
            Some(Ok(s)) => {
                u.conn_requests = 0;
                u.conn_start_time = ngx_core::times::current_msec();
                s
            }
        }
    };

    u.sock = Some(sock);

    // c->requests++
    u.conn_requests += 1;

    if u.request_sent || u.response_received {
        // ngx_http_upstream_reinit
        if reinit(r, u, m) != NGX_OK {
            return Err(Failure::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR));
        }
    }

    u.request_sent = false;
    u.request_body_sent = false;
    u.response_received = false;

    if let Some(g) = u.peer.as_mut() {
        g.u.request_sent = false;
    }

    send_request(r, u, m, start_time).await
}

/// u->peer.name and whether u->peer.sockaddr is a unix socket, for the
/// upstream part of the error log
fn set_log_peer(u: &Upstream) {
    if let Some(g) = u.peer.as_ref() {
        *u.ucache.peer_name.borrow_mut() = Some(g.u.pc.name.clone());
        u.ucache.peer_unix.set(matches!(g.u.pc.sockaddr, Some(SockAddr::Unix(_))));
    }
}

/// ngx_http_upstream_reinit
fn reinit(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> i64 {
    if m.reinit_request(r, u) != NGX_OK {
        return NGX_ERROR;
    }

    u.early_hints_length = 0;
    u.keepalive = false;
    u.upgrade = false;
    u.error = false;

    // u->headers_in anew, u->buffer emptied
    u.resp = UpstreamResponse::new();

    NGX_OK
}

/// ngx_http_upstream_send_request and ngx_http_upstream_send_request_body,
/// then ngx_http_upstream_process_header when the request is sent.
async fn send_request(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule, start_time: u64) -> Result<(), Failure> {
    http_debug!(r, "http upstream send request");

    Upstream::with_state(r, |st| {
        if st.connect_time == u64::MAX {
            st.connect_time = ngx_core::times::current_msec().saturating_sub(start_time);
        }
    });

    r.connection.log.set_action(Some("sending request to upstream"));

    http_debug!(r, "http upstream send request body");

    // u->request_sent = 1; out = u->request_bufs (and for an unbuffered
    // body the part of it read so far, through u->output.output_filter)

    let mut out = u.request_bufs.clone();

    let no_buffering = r.request_body_no_buffering.get();

    if no_buffering {
        out.extend(take_request_body_bufs(r));
    }

    u.request_sent = true;

    if let Some(g) = u.peer.as_mut() {
        g.u.request_sent = true;
    }

    if no_buffering {
        out = m.body_output_filter(r, u, out);

        // ngx_tcp_nodelay(c)
        if *r.clcf().borrow().tcp_nodelay {
            if let Some(c) = u.sock.as_ref().and_then(sock_conn) {
                if !c.set_tcp_nodelay() {
                    return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_ERROR));
                }
            }
        }
    }

    let send_timeout = u.conf.send_timeout;
    let watch = u.watch.clone();

    let mut bytes_sent: i64;

    {
        let sock = u.sock.as_mut().expect("connection");
        let is_plain = plain(sock);

        let written = {
            let write = write_chain(sock, &mut out, send_timeout);

            tokio::select! {
                res = write => Some(res),
                err = client_closed(if no_buffering { None } else { watch.as_deref() }) => {
                    let _ = err;
                    None
                }
            }
        };

        match written {
            None => {
                if let Some(rc) = check_broken_connection(r, u, 0) {
                    return Err(Failure::Finalize(rc));
                }

                return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_ERROR));
            }

            Some(Ok(n)) => bytes_sent = n,

            Some(Err(Some(e))) => {
                if is_plain {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, e.raw_os_error(), "writev() failed");
                }

                return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_ERROR));
            }

            Some(Err(None)) => {
                // c->write->timedout: ngx_http_upstream_send_request_handler
                return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_TIMEOUT));
            }
        }
    }

    // the rest of an unbuffered body as the client sends it, until the
    // upstream responds

    let mut responded = false;

    if no_buffering && r.reading_body.get() {
        let timeout = *r.clcf().borrow().client_body_timeout;

        loop {
            let rc = crate::request_body::read_unbuffered_request_body(r).await;

            if rc >= NGX_HTTP_SPECIAL_RESPONSE {
                return Err(Failure::Finalize(rc));
            }

            let bufs = take_request_body_bufs(r);

            if !bufs.is_empty() {
                let mut out = m.body_output_filter(r, u, bufs);

                let sock = u.sock.as_mut().expect("connection");

                match write_chain(sock, &mut out, send_timeout).await {
                    Ok(n) => bytes_sent += n,
                    Err(Some(_)) => return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_ERROR)),
                    Err(None) => return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_TIMEOUT)),
                }

                if !r.reading_body.get() {
                    break;
                }

                continue;
            }

            if !r.reading_body.get() {
                break;
            }

            let sock = u.sock.as_mut().expect("connection");

            tokio::select! {
                res = tokio::time::timeout(Duration::from_millis(timeout), crate::request_body::wait_request_body(r)) => {
                    if res.is_err() {
                        // ngx_http_upstream_read_request_handler
                        r.connection.timedout.set(true);
                        return Err(Failure::Finalize(NGX_HTTP_REQUEST_TIME_OUT));
                    }
                }

                _ = sock.wait_readable() => {
                    responded = true;
                    break;
                }
            }
        }
    }

    Upstream::with_state(r, |st| st.bytes_sent = bytes_sent);

    if !responded {
        // rc == NGX_OK
        u.request_body_sent = true;
    }

    if u.header_sent {
        return Ok(());
    }

    // ngx_add_timer(c->read, u->conf->read_timeout)
    let deadline = Instant::now() + Duration::from_millis(u.conf.read_timeout);

    process_header(r, u, m, deadline).await?;

    test_next_and_intercept(r, u, m).await
}

/// ngx_http_upstream_process_header: the response header read into
/// u->buffer and parsed by u->process_header. The read timer is the one
/// ngx_http_upstream_send_request armed: the reads do not arm it again.
async fn process_header(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule, deadline: Instant) -> Result<(), Failure> {
    http_debug!(r, "http upstream process header");

    // u->buffer: u->conf->buffer_size, from r->cache->header_start
    let header_start = crate::file_cache::cache_of(r).map(|c| c.borrow().header_start).unwrap_or(0);
    let buffer_size = u.conf.buffer_size.saturating_sub(header_start).max(1);

    let rc;

    if u.conf.ignore_input {
        r.connection.log.set_action(Some("reading response header from upstream"));

        rc = m.process_header(r, u);
    } else {
        let mut chunk = vec![0u8; buffer_size];
        let watch = u.watch.clone();

        // the action is set when the upstream's read event (data, the end
        // or the read timer) runs ngx_http_upstream_process_header; the
        // client's events checking the connection before see the one of
        // ngx_http_upstream_send_request
        let mut action = false;

        'read: loop {
            let room = buffer_size.saturating_sub(u.resp.buf.len()).clamp(1, chunk.len());

            let res = {
                let sock = u.sock.as_mut().expect("connection");
                let read = tokio::time::timeout_at(deadline, sock.read(&mut chunk[..room]));

                tokio::select! {
                    res = read => Some(res),
                    err = client_closed(watch.as_deref()) => {
                        let _ = err;
                        None
                    }
                }
            };

            if res.is_some() && !action {
                r.connection.log.set_action(Some("reading response header from upstream"));
                action = true;
            }

            let n = match res {
                None => {
                    if let Some(rc) = check_broken_connection(r, u, 0) {
                        return Err(Failure::Finalize(rc));
                    }

                    // a cacheable response: read on without the watch
                    u.watch = None;
                    continue;
                }

                Some(Err(_)) => {
                    // c->read->timedout
                    return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_TIMEOUT));
                }

                Some(Ok(Err(e))) => {
                    if plain(u.sock.as_ref().expect("connection")) {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, e.raw_os_error(), "recv() failed");
                    }

                    return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_ERROR));
                }

                Some(Ok(Ok(0))) => {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection");
                    return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_ERROR));
                }

                Some(Ok(Ok(n))) => n,
            };

            Upstream::with_state(r, |st| st.bytes_received += n as i64);

            u.resp.buf.extend_from_slice(&chunk[..n]);

            u.response_received = true;

            loop {
                // again:
                let prc = m.process_header(r, u);

                if prc == NGX_AGAIN {
                    if u.resp.buf.len() >= buffer_size {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent too big header");
                        return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_INVALID_HEADER));
                    }

                    continue 'read;
                }

                if prc == NGX_HTTP_UPSTREAM_EARLY_HINTS {
                    if process_early_hints(r, u) == NGX_OK {
                        continue;
                    }

                    rc = NGX_ERROR;
                    break 'read;
                }

                rc = prc;
                break 'read;
            }
        }
    }

    // done:

    if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
        return Err(Failure::Next(NGX_HTTP_UPSTREAM_FT_INVALID_HEADER));
    }

    if rc == NGX_ERROR {
        return Err(Failure::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR));
    }

    // rc == NGX_OK

    let start_time = u.peer.as_ref().map(|g| g.u.start_time).unwrap_or(0);

    Upstream::with_state(r, |st| st.header_time = ngx_core::times::current_msec().saturating_sub(start_time));

    // u->headers_in, for $upstream_http_* and the balancer's notify
    *r.upstream_headers_in.borrow_mut() = u.resp.headers.iter().filter(|h| h.hash.get() != 0).cloned().collect();

    Ok(())
}

/// ngx_http_upstream_process_early_hints. The early hints filters of
/// ngx_http_send_early_hints() are not ported: the 103 is sent to the
/// client only with the "early_hints" directive, and without it nothing is
/// sent, so the headers are dropped as C drops them then.
fn process_early_hints(r: &R, u: &mut Upstream) -> i64 {
    http_debug!(r, "http upstream early hints");

    if u.conf.pass_early_hints {
        u.early_hints_length += u.resp.pos as i64;

        if u.early_hints_length > u.conf.buffer_size as i64 {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "upstream sent too big early hints");
        }
    }

    // ngx_http_clean_header(r); u->headers_in anew; the rest of the buffer
    // moved to its start
    let rest = u.resp.buf.split_off(u.resp.pos.min(u.resp.buf.len()));

    u.resp.clear_headers();
    u.resp.buf = rest;
    u.resp.pos = 0;

    NGX_OK
}

/// ngx_http_upstream_next_errors: the failure type of a status
pub fn status_failure(status: i64) -> u32 {
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

/// ngx_http_upstream_test_next and ngx_http_upstream_intercept_errors for a
/// response header with an error status.
async fn test_next_and_intercept(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> Result<(), Failure> {
    let status = u.resp.status_n;

    if status < NGX_HTTP_SPECIAL_RESPONSE {
        return Ok(());
    }

    // ngx_http_upstream_test_next

    let ft = status_failure(status);

    if ft != 0 {
        let mut mask = ft;

        if u.request_sent && matches!(r.method.get(), NGX_HTTP_POST | NGX_HTTP_LOCK | NGX_HTTP_PATCH) {
            mask |= NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
        }

        let timeout = u.conf.next_upstream_timeout;
        let (tries, start_time) = u.peer.as_ref().map(|g| (g.u.pc.tries, g.u.pc.start_time)).unwrap_or((0, 0));

        if tries > 1
            && u.conf.next_upstream & mask == mask
            && !(u.request_sent && r.request_body_no_buffering.get())
            && !(timeout != 0 && ngx_core::times::current_msec().saturating_sub(start_time) >= timeout)
        {
            return Err(Failure::Next(ft));
        }

        if crate::upstream_cache::test_next_stale(r, ft) {
            let rc = m.reinit_request(r, u);

            if rc != NGX_OK {
                return Err(Failure::Finalize(rc));
            }

            u.ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_STALE);

            let mut rc = cache_send(r, u, m).await;

            if rc == NGX_DONE {
                return Err(Failure::Done(NGX_DONE));
            }

            if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return Err(Failure::Finalize(rc));
        }
    }

    if crate::upstream_cache::test_next_not_modified(r, status) {
        http_debug!(r, "http upstream not modified");

        let saved = crate::upstream_cache::not_modified_start(r);

        let rc = m.reinit_request(r, u);

        if rc != NGX_OK {
            return Err(Failure::Finalize(rc));
        }

        u.ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_REVALIDATED);

        let mut rc = cache_send(r, u, m).await;

        if rc == NGX_DONE {
            return Err(Failure::Done(NGX_DONE));
        }

        if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        // the status of the cached response now
        let cached_status = r.headers_out.borrow().status;

        crate::upstream_cache::not_modified_finish(r, saved, cached_status);

        return Err(Failure::Finalize(rc));
    }

    // ngx_http_upstream_intercept_errors

    if status == NGX_HTTP_NOT_FOUND && u.conf.intercept_404 {
        return Err(Failure::Finalize(NGX_HTTP_NOT_FOUND));
    }

    if !u.conf.intercept_errors {
        return Ok(());
    }

    let has_page = r.clcf().borrow().error_pages.as_ref().map(|pages| pages.iter().any(|p| p.status == status)).unwrap_or(false);

    if !has_page {
        return Ok(());
    }

    if status == NGX_HTTP_UNAUTHORIZED {
        // the WWW-Authenticate of the upstream goes with the error page
        let mut ho = r.headers_out.borrow_mut();

        for h in u.resp.headers.iter().filter(|h| h.hash.get() != 0 && h.lowcase_key == b"www-authenticate") {
            let o = TableElt::new(&h.key, &h.value.borrow());
            ho.headers.push(o.clone());
            ho.www_authenticate.push(o);
        }
    }

    // the status is cached as an error of the keys zone
    crate::upstream_cache::intercept_errors(r, status, &u.resp.cache);

    Err(Failure::Finalize(status))
}

/// ngx_http_upstream_next: the peer is freed, then the next one is tried
/// (None), or the request finalized (Some(rc)).
async fn next(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule, ft: u32) -> Option<i64> {
    http_debug!(r, "http next upstream, {:x}", ft);

    if let Some(c) = u.sock.as_ref().and_then(sock_conn) {
        let sent = c.sent.get() as i64;
        Upstream::with_state(r, |st| st.bytes_sent = sent);
    }

    if let Some(g) = u.peer.as_mut() {
        g.u.next_free(r, ft);
    }

    // u->peer.sockaddr = NULL
    u.ucache.peer_unix.set(false);

    if ft == NGX_HTTP_UPSTREAM_FT_TIMEOUT {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
    }

    let decision = match u.peer.as_mut() {
        Some(g) => g.u.next_decide(r, ft),
        None => Err(NGX_HTTP_BAD_GATEWAY),
    };

    let status = match decision {
        Ok(()) => {
            // close http upstream connection
            if let Some(sock) = u.sock.take() {
                sock.set_no_shutdown();
                http_debug!(r, "close http upstream connection");
                drop(sock);
            }

            return None;
        }

        Err(status) => status,
    };

    if status == NGX_HTTP_CLIENT_CLOSED_REQUEST {
        return Some(finalize(r, u, m, status).await);
    }

    if crate::upstream_cache::next_stale(r, ft) {
        let rc = m.reinit_request(r, u);

        if rc != NGX_OK {
            return Some(finalize(r, u, m, rc).await);
        }

        u.ucache.cache_status.set(crate::file_cache::NGX_HTTP_CACHE_STALE);

        let mut rc = cache_send(r, u, m).await;

        if rc == NGX_DONE {
            return Some(NGX_DONE);
        }

        if rc == NGX_HTTP_UPSTREAM_INVALID_HEADER {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return Some(finalize(r, u, m, rc).await);
    }

    Some(finalize(r, u, m, status).await)
}

/// ngx_http_upstream_finalize_request: the module's finalize_request, the
/// peer freed (the connection to the keepalive cache if the response
/// allows), the connection closed, the cache of an error status; then what
/// ngx_http_finalize_request gets: the status itself before the header was
/// sent, or after it the trailers and the last buffer (rc 0), or a flush
/// for an error (NGX_ERROR).
pub async fn finalize(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule, rc: i64) -> i64 {
    http_debug!(r, "finalize http upstream request: {}", rc);

    if !u.cleanup {
        // the request was already finalized
        return NGX_DONE;
    }

    u.cleanup = false;

    finalize_peer(r, u, m, rc);

    // r->read_event_handler = ngx_http_block_reading
    u.watch = None;

    if rc == NGX_DECLINED {
        return NGX_DECLINED;
    }

    r.connection.log.set_action(Some("sending to client"));

    if !u.header_sent || rc == NGX_HTTP_REQUEST_TIME_OUT || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST {
        return rc;
    }

    let mut rc = rc;
    let mut flush = false;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        rc = NGX_ERROR;
        flush = true;
    }

    if r.header_only.get() || u.pipe_downstream_error {
        return rc;
    }

    if rc == 0 {
        process_trailers(r, u);

        rc = crate::special_response::send_special(r, true).await;
    } else if flush {
        r.keepalive.set(false);

        rc = crate::special_response::send_special(r, false).await;
    }

    rc
}

/// The part of ngx_http_upstream_finalize_request up to the closing of the
/// connection: the state's times, u->finalize_request, the peer freed, and
/// the cache of a 502 or 504.
fn finalize_peer(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule, rc: i64) {
    let sent = u.sock.as_ref().and_then(sock_conn).map(|c| c.sent.get() as i64);

    let start_time = u.peer.as_ref().map(|g| g.u.start_time).unwrap_or(0);

    Upstream::with_state(r, |st| {
        if st.response_time == u64::MAX {
            st.response_time = ngx_core::times::current_msec().saturating_sub(start_time);

            if let Some(sent) = sent {
                st.bytes_sent = sent;
            }
        }
    });

    m.finalize_request(r, u, rc);

    // u->peer.free(&u->peer, u->peer.data, 0): the keepalive cache may
    // take the connection
    if let Some(mut g) = u.peer.take() {
        if u.keepalive {
            if let Some(sock) = u.sock.take() {
                g.conn = Some(UpstreamConn { sock, requests: u.conn_requests, start_time: u.conn_start_time });
                g.keepalive = true;
            }
        }

        g.finalize();
    }

    u.ucache.peer_unix.set(false);

    if let Some(sock) = u.sock.take() {
        // "close notify" to the upstream, without waiting for its own
        http_debug!(r, "close http upstream connection");
        drop(sock);
    }

    // the cache: an error of the upstream is cached for its *_cache_valid
    // time
    crate::upstream_cache::finalize(r, rc, None);
}

/// ngx_http_upstream_process_trailers
fn process_trailers(r: &R, u: &Upstream) {
    if !u.conf.pass_trailers {
        return;
    }

    let mut ho = r.headers_out.borrow_mut();

    for h in u.resp.trailers.iter() {
        if u.conf.hidden(&h.lowcase_key) {
            continue;
        }

        ho.trailers.push(h.clone());
    }
}

// ---------------------------------------------------------------------------
// ngx_http_upstream_process_headers
// ---------------------------------------------------------------------------

/// What ngx_http_upstream_process_headers ends with.
enum Processed {
    /// the headers are in r->headers_out
    Ok,
    /// the request was finalized (X-Accel-Redirect): the rc
    Done(i64),
}

/// The headers of ngx_http_upstream_headers_in[] with "redirect": copied
/// before an X-Accel-Redirect.
const REDIRECT_HEADERS: &[&[u8]] = &[b"content-type", b"set-cookie", b"content-disposition", b"cache-control", b"expires", b"accept-ranges"];

/// The charset of ngx_http_upstream_copy_content_type: the length of the
/// type before the ";" of a "charset=" parameter, and the charset without
/// quotes. As the C loop does, the character after the spaces that follow
/// a ";" is not looked at as a ";" again.
pub fn content_type_charset(value: &[u8]) -> Option<(usize, Vec<u8>)> {
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

/// A copy of an upstream header in r->headers_out (*ho = *h).
fn push_copy(ho: &mut HeadersOut, h: &Header) -> Header {
    let o = ho.add(&h.key, &h.value.borrow());
    o.null.set(h.null.get());
    o
}

/// The copy handlers of ngx_http_upstream_headers_in[], and
/// ngx_http_upstream_copy_header_line for the other headers: the header
/// goes to r->headers_out. NGX_OK, or NGX_ERROR from a rewrite.
fn copy_header(r: &R, u: &Upstream, m: &mut dyn UpstreamModule, h: &Header) -> i64 {
    let force_ranges = u.conf.force_ranges;

    match h.lowcase_key.as_slice() {
        b"content-type" => {
            // ngx_http_upstream_copy_content_type
            let value = h.value.borrow();
            let mut ho = r.headers_out.borrow_mut();

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
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.date = Some(o);
        }

        b"last-modified" => {
            // ngx_http_upstream_copy_last_modified
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.last_modified = Some(o);
            ho.last_modified_time = u.resp.cache.last_modified_time;
        }

        b"etag" => {
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.etag = Some(o);
        }

        b"server" => {
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.server = Some(o);
        }

        b"location" => {
            // ngx_http_upstream_rewrite_location
            let o = push_copy(&mut r.headers_out.borrow_mut(), h);

            if m.has_rewrite_redirect() {
                let rc = m.rewrite_redirect(r, &o, 0);

                if rc == NGX_DECLINED {
                    return NGX_OK;
                }

                if rc == NGX_OK {
                    r.headers_out.borrow_mut().location = Some(o.clone());

                    http_debug!(r, "rewritten location: \"{}\"", B(&o.value.borrow()));
                }

                return rc;
            }

            // a relative location is not r->headers_out.location, not to be
            // made absolute by the header filter
            if o.value.borrow().first() != Some(&b'/') {
                r.headers_out.borrow_mut().location = Some(o);
            }
        }

        b"refresh" => {
            // ngx_http_upstream_rewrite_refresh
            let o = push_copy(&mut r.headers_out.borrow_mut(), h);

            if m.has_rewrite_redirect() {
                let pos = ngx_core::string::strcasestr(&o.value.borrow(), b"url=");

                let rc = match pos {
                    Some(p) => m.rewrite_redirect(r, &o, p + 4),
                    None => return NGX_OK,
                };

                if rc == NGX_DECLINED {
                    return NGX_OK;
                }

                if rc == NGX_OK {
                    r.headers_out.borrow_mut().refresh = Some(o.clone());

                    http_debug!(r, "rewritten refresh: \"{}\"", B(&o.value.borrow()));
                }

                return rc;
            }

            r.headers_out.borrow_mut().refresh = Some(o);
        }

        b"set-cookie" => {
            // ngx_http_upstream_rewrite_set_cookie
            let o = push_copy(&mut r.headers_out.borrow_mut(), h);

            if m.has_rewrite_cookie() {
                let rc = m.rewrite_cookie(r, &o);

                if rc == NGX_DECLINED {
                    return NGX_OK;
                }

                if rc == NGX_OK {
                    http_debug!(r, "rewritten cookie: \"{}\"", B(&o.value.borrow()));
                }

                return rc;
            }
        }

        b"cache-control" => {
            // ngx_http_upstream_copy_multi_header_lines
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.cache_control.push(o);
        }

        b"link" => {
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.link.push(o);
        }

        b"expires" => {
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.expires = Some(o);
        }

        b"accept-ranges" => {
            // ngx_http_upstream_copy_allow_ranges
            if force_ranges {
                return NGX_OK;
            }

            if r.cached.get() {
                r.allow_ranges.set(true);
                return NGX_OK;
            }

            if u.cacheable() {
                r.allow_ranges.set(true);
                r.single_range.set(true);
                return NGX_OK;
            }

            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.accept_ranges = Some(o);
        }

        b"upgrade" => {
            // ngx_http_upstream_copy_upgrade
            if r.http_version.get() >= NGX_HTTP_VERSION_20 {
                return NGX_OK;
            }

            push_copy(&mut r.headers_out.borrow_mut(), h);
        }

        b"content-range" => {
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.content_range = Some(o);
        }

        b"content-encoding" => {
            let mut ho = r.headers_out.borrow_mut();
            let o = push_copy(&mut ho, h);
            ho.content_encoding = Some(o);
        }

        // "Status", "WWW-Authenticate", "Content-Disposition", "Vary",
        // "X-Accel-*" and the headers without a handler:
        // ngx_http_upstream_copy_header_line
        _ => {
            push_copy(&mut r.headers_out.borrow_mut(), h);
        }
    }

    NGX_OK
}

/// ngx_http_upstream_process_headers: the headers not hidden go to
/// r->headers_out; for X-Accel-Redirect the upstream is finalized and the
/// request redirected.
async fn process_headers(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> Processed {
    // u->headers_in.no_cache || u->headers_in.expired
    crate::upstream_cache::process_headers_cacheable(r, &u.resp.cache);

    if let Some(xar) = u.resp.header(b"x-accel-redirect") {
        if !u.conf.ignores(NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT) {
            finalize(r, u, m, NGX_DECLINED).await;

            let headers: Vec<Header> = u.resp.headers.clone();

            for h in headers.iter() {
                if h.hash.get() == 0 {
                    continue;
                }

                if REDIRECT_HEADERS.iter().any(|k| h.lowcase_key == *k) && copy_header(r, u, m, h) != NGX_OK {
                    return Processed::Done(NGX_HTTP_INTERNAL_SERVER_ERROR);
                }
            }

            let uri = xar.value.borrow().clone();

            return Processed::Done(accel_redirect(r, &uri).await);
        }
    }

    let headers: Vec<Header> = u.resp.headers.clone();

    for h in headers.iter() {
        if h.hash.get() == 0 {
            continue;
        }

        if u.conf.hidden(&h.lowcase_key) {
            continue;
        }

        if copy_header(r, u, m, h) != NGX_OK {
            return Processed::Done(finalize(r, u, m, NGX_HTTP_INTERNAL_SERVER_ERROR).await);
        }
    }

    {
        let mut ho = r.headers_out.borrow_mut();

        // the special empty "Server" and "Date" of a module
        if let Some(s) = &ho.server {
            if s.null.get() {
                s.hash.set(0);
            }
        }

        if let Some(d) = &ho.date {
            if d.null.get() {
                d.hash.set(0);
            }
        }

        ho.status = u.resp.status_n;
        ho.status_line = u.resp.status_line.clone();

        ho.content_length_n = u.resp.content_length_n;
    }

    r.disable_not_modified.set(!u.cacheable());

    if u.conf.force_ranges {
        r.allow_ranges.set(true);
        r.single_range.set(true);

        if r.cached.get() {
            r.single_range.set(false);
        }
    }

    u.length = -1;

    Processed::Ok
}

/// The X-Accel-Redirect of ngx_http_upstream_process_headers: a named
/// location, or the URI (with its arguments) for an internal redirect, with
/// the method GET unless HEAD.
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

/// ngx_http_upstream_cache_send with the module's process_header and
/// ngx_http_upstream_process_headers: the response from the cache.
async fn cache_send(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> i64 {
    crate::upstream_cache::upstream_cache_send(r, |buf| async move {
        u.resp = UpstreamResponse::new();
        u.resp.buf = buf;

        let rc = m.process_header(r, u);

        if rc != NGX_OK {
            return rc;
        }

        // u->headers_in, for $upstream_http_*
        *r.upstream_headers_in.borrow_mut() = u.resp.headers.iter().filter(|h| h.hash.get() != 0).cloned().collect();

        match process_headers(r, u, m).await {
            Processed::Ok => NGX_OK,
            Processed::Done(_) => NGX_DONE,
        }
    })
    .await
}

// ---------------------------------------------------------------------------
// ngx_http_upstream_send_response
// ---------------------------------------------------------------------------

/// ngx_http_upstream_send_response: the header, then the upgraded
/// connection, the non-buffered response, or the event pipe.
async fn send_response(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> i64 {
    let rc = crate::core_rt::send_header(r).await;

    if rc == NGX_ERROR || rc > NGX_OK || r.post_action.get() {
        return finalize(r, u, m, rc).await;
    }

    u.header_sent = true;

    if u.upgrade {
        crate::upstream_cache::free(r, None);

        return upgrade(r, u, m).await;
    }

    if r.header_only.get() {
        if !u.buffering {
            return finalize(r, u, m, rc).await;
        }

        if !u.cacheable() && !u.store {
            return finalize(r, u, m, rc).await;
        }

        u.pipe_downstream_error = true;
    }

    // ngx_pool_run_cleanup_file() of the request body's temporary file
    if r.is_main() && !r.preserve_body.get() && !u.conf.preserve_output {
        if let Some(rb) = r.request_body.borrow().as_ref() {
            if let Some(tf) = rb.borrow_mut().temp_file.as_mut() {
                tf.close();
            }
        }
    }

    if !u.buffering {
        return send_non_buffered(r, u, m).await;
    }

    send_buffered(r, u, m).await
}

/// The non-buffered response of ngx_http_upstream_send_response.
async fn send_non_buffered(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> i64 {
    crate::upstream_cache::free(r, None);

    r.limit_rate.set(0);
    r.limit_rate_set.set(true);

    if m.input_filter_init(r, u, None) == NGX_ERROR {
        return finalize(r, u, m, NGX_ERROR).await;
    }

    if *r.clcf().borrow().tcp_nodelay && r.stream.borrow().is_none() && !r.connection.set_tcp_nodelay() {
        return finalize(r, u, m, NGX_ERROR).await;
    }

    let pos = u.resp.pos.min(u.resp.buf.len());
    let preread: Vec<u8> = u.resp.buf[pos..].to_vec();

    let do_write;

    if !preread.is_empty() {
        u.resp.buf.truncate(pos);

        Upstream::with_state(r, |st| st.response_length += preread.len() as i64);

        if m.input_filter(r, u, &preread) == NGX_ERROR {
            return finalize(r, u, m, NGX_ERROR).await;
        }

        // ngx_http_upstream_process_non_buffered_downstream
        r.connection.log.set_action(Some("sending to client"));

        do_write = true;
    } else {
        u.resp.buf.clear();
        u.resp.pos = 0;

        if crate::special_response::send_special(r, false).await == NGX_ERROR {
            return finalize(r, u, m, NGX_ERROR).await;
        }

        // ngx_http_upstream_process_non_buffered_upstream
        r.connection.log.set_action(Some("reading upstream"));

        do_write = false;
    }

    process_non_buffered_request(r, u, m, do_write).await
}

/// "upstream timed out" as ngx_connection_error() logs it for the upstream
/// connection.
fn upstream_timed_out(r: &R, u: &Upstream) {
    match u.sock.as_ref().and_then(sock_conn) {
        Some(c) => {
            let _ = c.connection_error(libc::ETIMEDOUT, "upstream timed out");
        }
        None => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::ETIMEDOUT), "upstream timed out");
        }
    }
}

/// ngx_http_upstream_process_non_buffered_request: what the input filter
/// made of the data read goes to the client, until the upstream is done.
async fn process_non_buffered_request(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule, do_write: bool) -> i64 {
    let buffer_size = u.conf.buffer_size.max(1);
    let read_timeout = u.conf.read_timeout;

    let mut chunk = vec![0u8; buffer_size];

    let mut eof = false;
    let mut read_error = false;

    let mut do_write = do_write || u.length == 0;

    loop {
        if do_write {
            if !u.out_bufs.is_empty() {
                let out = std::mem::take(&mut u.out_bufs);

                if crate::core_rt::output_filter(r, out).await == NGX_ERROR {
                    return finalize(r, u, m, NGX_ERROR).await;
                }
            }

            // u->busy_bufs == NULL

            if u.length == 0 || (eof && u.length == -1) {
                return finalize(r, u, m, 0).await;
            }

            if eof {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection");

                return finalize(r, u, m, NGX_HTTP_BAD_GATEWAY).await;
            }

            if read_error || u.error {
                return finalize(r, u, m, NGX_HTTP_BAD_GATEWAY).await;
            }
        }

        let watch = u.watch.clone();

        let res = {
            let sock = u.sock.as_mut().expect("connection");
            let read = tokio::time::timeout(Duration::from_millis(read_timeout), sock.read(&mut chunk));

            tokio::select! {
                res = read => Some(res),
                err = client_closed(watch.as_deref()) => {
                    let _ = err;
                    None
                }
            }
        };

        let res = match res {
            None => {
                if let Some(rc) = check_broken_connection(r, u, 0) {
                    return finalize(r, u, m, rc).await;
                }

                u.watch = None;
                continue;
            }

            Some(res) => res,
        };

        // ngx_http_upstream_process_non_buffered_upstream: the read event
        r.connection.log.set_action(Some("reading upstream"));

        match res {
            Err(_) => {
                // c->read->timedout
                upstream_timed_out(r, u);

                return finalize(r, u, m, NGX_HTTP_GATEWAY_TIME_OUT).await;
            }

            Ok(Err(e)) => {
                if plain(u.sock.as_ref().expect("connection")) {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, e.raw_os_error(), "recv() failed");
                }

                read_error = true;
            }

            Ok(Ok(0)) => eof = true,

            Ok(Ok(n)) => {
                Upstream::with_state(r, |st| {
                    st.bytes_received += n as i64;
                    st.response_length += n as i64;
                });

                if m.input_filter(r, u, &chunk[..n]) == NGX_ERROR {
                    return finalize(r, u, m, NGX_ERROR).await;
                }
            }
        }

        do_write = true;
    }
}

/// The in-flight output of the event pipe: the output filter's future and
/// the raw buffers of its memory buffers.
type PipeWriter<'a> = (std::pin::Pin<Box<dyn std::future::Future<Output = i64> + 'a>>, Vec<i32>);

/// How the event pipe stopped.
enum PipeEnd {
    /// p->upstream_done, p->upstream_eof or p->upstream_error
    Upstream,
    /// p->upstream_error on the upstream read timeout
    TimedOut,
    /// ngx_http_upstream_finalize_request with this rc
    Finalize(i64),
}

/// The event pipe of ngx_http_upstream_send_response, and
/// ngx_http_upstream_process_request at its end.
async fn send_buffered(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> i64 {
    let status = u.resp.status_n;

    // the cache: *_no_cache, the valid time, the header of the cache file
    let mut writer: Option<crate::upstream_cache::CacheWriter> = None;

    match crate::upstream_cache::send_response(r, status, &u.resp.cache, u.resp.pos) {
        Err(()) => return finalize(r, u, m, NGX_ERROR).await,

        Ok(Some(header)) => {
            let raw_header = u.resp.buf[..u.resp.pos.min(u.resp.buf.len())].to_vec();

            writer = crate::upstream_cache::CacheWriter::new(r, u.conf.temp_path.as_deref(), &header, &raw_header);

            if writer.is_none() {
                return finalize(r, u, m, NGX_ERROR).await;
            }
        }

        Ok(None) => {}
    }

    if r.header_only.get() && !u.cacheable() && !u.store {
        return finalize(r, u, m, 0).await;
    }

    let log = r.connection.log.clone();

    let cacheable = u.cacheable() || u.store;

    // p->temp_file
    let temp_file = match writer {
        Some(w) => crate::event_pipe::PipeTempFile::Cache(w),
        None => {
            let path = match u.conf.temp_path.clone() {
                Some(p) => p,
                None => Rc::new(PathConf::new(Vec::new(), [0, 0, 0])),
            };

            let mut tf = ngx_core::file::TempFile::new(path, &log);

            if cacheable {
                tf.persistent = true;
            } else {
                tf.log_level = NGX_LOG_WARN;
                tf.warn = "an upstream response is buffered to a temporary file";
            }

            crate::event_pipe::PipeTempFile::Plain(tf)
        }
    };

    let header_start = crate::file_cache::cache_of(r).map(|c| c.borrow().header_start).unwrap_or(0);
    let pos = u.resp.pos.min(u.resp.buf.len());
    let preread = u.resp.buf[pos..].to_vec();
    let room = u.conf.buffer_size.saturating_sub(header_start).saturating_sub(pos);

    let mut p = crate::event_pipe::EventPipe::new(u.conf.bufs, u.conf.busy_buffers_size, temp_file, preread, room, &log);

    p.limit_rate = crate::script::complex_value_size(r, &u.conf.limit_rate, 0);
    p.start_sec = ngx_core::times::time();
    p.cacheable = cacheable;
    p.max_temp_file_size = u.conf.max_temp_file_size as i64;
    p.temp_file_write_size = u.conf.temp_file_write_size as i64;
    p.read_timeout = u.conf.read_timeout;
    p.downstream_error = u.pipe_downstream_error;

    p.length = -1;

    if m.input_filter_init(r, u, Some(&mut p)) != NGX_OK {
        return finalize(r, u, m, NGX_ERROR).await;
    }

    // ngx_http_upstream_process_upstream: the pipe until the upstream is done

    r.connection.log.set_action(Some("reading upstream"));

    let (end, inflight) = pipe_run(r, u, m, &mut p).await;

    let timed_out = matches!(end, PipeEnd::TimedOut);

    if let PipeEnd::Finalize(rc) = end {
        drop(inflight);

        if let crate::event_pipe::PipeTempFile::Cache(w) = &p.temp_file {
            crate::upstream_cache::free(r, Some(&w.tf));
        }

        u.pipe_downstream_error = p.downstream_error;

        return finalize(r, u, m, rc).await;
    }

    // ngx_http_upstream_finalize_request's u->state: the bytes of the body
    let (read_length, preread_size) = (p.read_length, p.preread_size);

    Upstream::with_state(r, |st| {
        st.bytes_received += read_length - preread_size;
        st.response_length = read_length;
    });

    // ngx_http_upstream_process_request

    let content_length_n = u.resp.content_length_n;

    if u.store && (p.upstream_eof || p.upstream_done) && status == NGX_HTTP_OK && (p.upstream_done || p.length == -1) && (content_length_n == -1 || content_length_n == p.temp_file.offset()) {
        store(r, u, &mut p);
    }

    let (done, eof_whole) = (p.upstream_done, p.upstream_eof && p.length == -1);

    match &mut p.temp_file {
        crate::event_pipe::PipeTempFile::Cache(w) => {
            // the file stays open for the rest to be sent
            w.finish_ref(r, done, eof_whole, content_length_n);
        }

        crate::event_pipe::PipeTempFile::Plain(tf) => {
            if u.store && tf.fd != -1 {
                // ngx_http_upstream_finalize_request: the temporary file of
                // a response not stored
                if let Err(err) = ngx_core::os::unlink(&tf.name) {
                    ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "unlink() \"{}\" failed", B(&tf.name));
                }
            }
        }
    }

    let rc = if p.upstream_done || (p.upstream_eof && p.length == -1) {
        0
    } else {
        if p.upstream_eof {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed connection");
        }

        NGX_HTTP_BAD_GATEWAY
    };

    http_debug!(r, "http upstream exit");

    // ngx_http_upstream_finalize_request: the peer is freed before the
    // rest of the response goes to the client
    if !u.cleanup {
        return NGX_DONE;
    }

    u.cleanup = false;

    finalize_peer(r, u, m, rc);

    u.watch = None;

    // the rest of p->out and p->in (ngx_event_pipe_write_to_downstream when
    // the upstream is done)
    r.connection.log.set_action(Some("sending to client"));

    if let Some((fut, slots)) = inflight {
        if fut.await == NGX_ERROR {
            p.downstream_error = true;
        }

        p.sent(&slots);
    }

    if !p.downstream_error && !timed_out {
        if let Some(batch) = p.write_batch() {
            if crate::core_rt::output_filter(r, batch).await == NGX_ERROR {
                p.downstream_error = true;
            }
        }
    }

    p.downstream_done = true;

    u.pipe_downstream_error = p.downstream_error;

    finalize_tail(r, u, rc).await
}

/// The end of ngx_http_upstream_finalize_request after the peer is freed.
async fn finalize_tail(r: &R, u: &mut Upstream, rc: i64) -> i64 {
    r.connection.log.set_action(Some("sending to client"));

    if !u.header_sent || rc == NGX_HTTP_REQUEST_TIME_OUT || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST {
        return rc;
    }

    let mut rc = rc;
    let mut flush = false;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        rc = NGX_ERROR;
        flush = true;
    }

    if r.header_only.get() || u.pipe_downstream_error {
        return rc;
    }

    if rc == 0 {
        process_trailers(r, u);

        rc = crate::special_response::send_special(r, true).await;
    } else if flush {
        r.keepalive.set(false);

        rc = crate::special_response::send_special(r, false).await;
    }

    rc
}

/// ngx_event_pipe() and ngx_http_upstream_process_request up to the end of
/// the upstream's response: the upstream is read into the raw buffers
/// (with p->limit_rate), what the input filter made of them passed to the
/// client as it can take it, or written to the temporary file while it
/// cannot (and, cacheable, all of it). Returns the output still being
/// sent when the upstream is done.
async fn pipe_run<'a>(r: &'a R, u: &mut Upstream, m: &mut dyn UpstreamModule, p: &mut crate::event_pipe::EventPipe) -> (PipeEnd, Option<PipeWriter<'a>>) {
    let mut writer: Option<PipeWriter<'a>> = None;
    let mut delayed: Option<Instant> = None;

    // the pre-read part of the body (p->preread_bufs)
    if let Some(raw) = p.take_preread() {
        let n = raw.data.len();

        if n > 0 {
            http_debug!(r, "pipe preread: {}", n);
        }

        p.read_length += n as i64;

        if raw.full() {
            if m.pipe_input_filter(r, u, p, raw) == NGX_ERROR {
                return (PipeEnd::Finalize(NGX_ERROR), None);
            }
        } else {
            p.put_back(raw);
        }

        if let Some(rc) = pipe_after_read(r, u, m, p) {
            return (PipeEnd::Finalize(rc), None);
        }
    }

    loop {
        // ngx_event_pipe_write_to_downstream
        if writer.is_none() && !p.upstream_finished() {
            if let Some(batch) = p.write_batch() {
                let slots = crate::event_pipe::batch_slots(&batch);
                writer = Some((Box::pin(crate::core_rt::output_filter(r, batch)), slots));
            }
        }

        if p.upstream_finished() {
            return (PipeEnd::Upstream, writer);
        }

        // ngx_http_upstream_process_request: a client error, the response
        // not read for the cache or *_store
        if p.downstream_error && !u.cacheable() && !u.store && u.connected() {
            http_debug!(r, "http upstream downstream error");
            return (PipeEnd::Finalize(NGX_ERROR), None);
        }

        // the raw buffer to read into (ngx_event_pipe_read_upstream)
        let mut raw = None;
        let mut limit = 0usize;

        if delayed.is_none() {
            if p.limit_rate > 0 {
                let allowed = p.limit_rate as i64 * (ngx_core::times::time() - p.start_sec + 1) - p.read_length;

                if allowed <= 0 {
                    let delay = (-allowed * 1000 / p.limit_rate as i64 + 1) as u64;
                    delayed = Some(Instant::now() + Duration::from_millis(delay));
                } else {
                    limit = allowed as usize;
                }
            }

            if delayed.is_none() {
                raw = match p.raw_buf(writer.is_none()) {
                    Ok(b) => b,
                    Err(()) => return (PipeEnd::Finalize(NGX_ERROR), None),
                };
            }
        }

        let watch = u.watch.clone();

        enum Ev {
            Written(i64),
            Read(Option<Result<std::io::Result<usize>, tokio::time::error::Elapsed>>),
            Delayed,
            ClientClosed(i32),
        }

        let room = match &raw {
            Some(b) => {
                let room = b.size.saturating_sub(b.data.len()).max(1);
                if limit > 0 { room.min(limit) } else { room }
            }
            None => 0,
        };

        let mut rbuf = vec![0u8; room];

        let ev = {
            let sock = u.sock.as_mut().expect("connection");
            let read_timeout = p.read_timeout;
            let reading = raw.is_some();

            let read = async {
                if reading {
                    Ev::Read(Some(tokio::time::timeout(Duration::from_millis(read_timeout), sock.read(&mut rbuf)).await))
                } else {
                    std::future::pending().await
                }
            };

            let write = async {
                match writer.as_mut() {
                    Some((fut, _)) => Ev::Written(fut.as_mut().await),
                    None => std::future::pending().await,
                }
            };

            let delay = async {
                match delayed {
                    Some(t) => {
                        tokio::time::sleep_until(t).await;
                        Ev::Delayed
                    }
                    None => std::future::pending().await,
                }
            };

            tokio::select! {
                ev = write => ev,
                ev = read => ev,
                ev = delay => ev,
                err = client_closed(watch.as_deref()) => Ev::ClientClosed(err),
            }
        };

        // a raw buffer not read into goes back to p->free_raw_bufs
        let b = match (&ev, raw) {
            (Ev::Read(_), Some(b)) => Some(b),
            (_, Some(b)) => {
                p.put_back(b);
                None
            }
            (_, None) => None,
        };

        match ev {
            Ev::Written(rc) => {
                let (_, slots) = writer.take().expect("writer");

                p.sent(&slots);

                if rc == NGX_ERROR {
                    p.downstream_error = true;
                    p.drain_chains();
                }
            }

            Ev::Delayed => delayed = None,

            Ev::ClientClosed(err) => {
                if let Some(rc) = check_broken_connection(r, u, err) {
                    return (PipeEnd::Finalize(rc), None);
                }

                u.watch = None;
            }

            Ev::Read(res) => {
                r.connection.log.set_action(Some("reading upstream"));

                let mut b = b.expect("raw buffer");

                match res {
                    None => p.put_back(b),

                    Some(Err(_)) => {
                        // rev->timedout: ngx_http_upstream_process_upstream
                        // goes on to ngx_http_upstream_process_request
                        // without the pipe, the partly filled raw buffer and
                        // p->in are not sent
                        p.put_back(b);
                        p.upstream_error = true;
                        upstream_timed_out(r, u);

                        return (PipeEnd::TimedOut, writer);
                    }

                    Some(Ok(Err(e))) => {
                        p.put_back(b);

                        if plain(u.sock.as_ref().expect("connection")) {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, e.raw_os_error(), "readv() failed");
                        }

                        p.upstream_error = true;
                    }

                    Some(Ok(Ok(0))) => {
                        p.put_back(b);
                        p.upstream_eof = true;
                    }

                    Some(Ok(Ok(n))) => {
                        b.data.extend_from_slice(&rbuf[..n]);

                        p.read_length += n as i64;

                        if b.full() {
                            if m.pipe_input_filter(r, u, p, b) == NGX_ERROR {
                                return (PipeEnd::Finalize(NGX_ERROR), None);
                            }
                        } else {
                            p.put_back(b);
                        }

                        if p.limit_rate > 0 {
                            let delay = n as u64 * 1000 / p.limit_rate as u64;

                            if delay > 0 {
                                delayed = Some(Instant::now() + Duration::from_millis(delay));
                            }
                        }
                    }
                }

                if let Some(rc) = pipe_after_read(r, u, m, p) {
                    return (PipeEnd::Finalize(rc), None);
                }
            }
        }
    }
}

/// The end of ngx_event_pipe_read_upstream: the partly filled raw buffer
/// with the rest of the body (or at the end of the connection) to the input
/// filter, p->upstream_done when p->length is 0, and all of p->in to the
/// temporary file when cacheable. Some(rc) on an error.
fn pipe_after_read(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule, p: &mut crate::event_pipe::EventPipe) -> Option<i64> {
    if p.length != -1 || p.upstream_eof || p.upstream_error {
        if let Some(b) = p.take_partial() {
            if m.pipe_input_filter(r, u, p, b) == NGX_ERROR {
                return Some(NGX_ERROR);
            }
        }
    }

    if p.length == 0 {
        p.upstream_done = true;
    }

    if p.cacheable && !p.in_bufs.is_empty() {
        http_debug!(r, "pipe write chain");

        if p.write_chain_to_temp_file().is_err() {
            return Some(NGX_ERROR);
        }
    }

    None
}

/// ngx_http_upstream_store: the temporary file of the response (or a new
/// one for an empty response) renamed to the path of *_store, with
/// *_store_access and the time of "Last-Modified".
fn store(r: &R, u: &mut Upstream, p: &mut crate::event_pipe::EventPipe) {
    let log = r.connection.log.clone();

    let (fd, name) = match &mut p.temp_file {
        crate::event_pipe::PipeTempFile::Plain(tf) => {
            if tf.fd == -1 {
                // create file for empty 200 response
                tf.persistent = true;
                tf.log_level = 0;

                if tf.create().is_err() {
                    return;
                }
            }

            (tf.fd, tf.name.clone())
        }

        crate::event_pipe::PipeTempFile::Cache(_) => return,
    };

    // ext.time: the time of "Last-Modified"
    let mut time = -1;

    if let Some(lm) = u.resp.header(b"last-modified") {
        if let Some(t) = ngx_core::parse::parse_http_time(&lm.value.borrow()) {
            time = t;
        }
    }

    let path = match &u.conf.store_values {
        None => match crate::core_rt::map_uri_to_path(r, 0) {
            Some((p, _)) => p,
            None => return,
        },
        Some(codes) => match crate::script::script_run(r, codes) {
            Some(p) => p,
            None => return,
        },
    };

    http_debug!(r, "upstream stores \"{}\" to \"{}\"", B(&name), B(&path));

    if path.is_empty() {
        return;
    }

    if time != -1 {
        // ngx_set_file_time(): the times of the temporary file
        let tv = [libc::timeval { tv_sec: time as libc::time_t, tv_usec: 0 }, libc::timeval { tv_sec: time as libc::time_t, tv_usec: 0 }];

        // SAFETY: fd is the open temporary file, tv two timevals.
        if unsafe { libc::futimes(fd, tv.as_ptr()) } == -1 {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(ngx_core::os::errno()), "futimes() \"{}\" failed", B(&name));
        }
    }

    let access = u.conf.store_access;

    let _ = crate::file_cache::ext_rename_file(&name, &path, access, access, true, true, &log);

    u.store = false;
}

// ---------------------------------------------------------------------------
// ngx_http_upstream_upgrade
// ---------------------------------------------------------------------------

/// ngx_http_upstream_upgrade: the header is out, what the upstream sent
/// after it goes to the client and what the client sent after its request
/// to the upstream, then the data of each side is passed to the other
/// (ngx_http_upstream_process_upgraded).
async fn upgrade(r: &R, u: &mut Upstream, m: &mut dyn UpstreamModule) -> i64 {
    if !r.is_main() {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "connection upgrade in subrequest");
        return finalize(r, u, m, NGX_ERROR).await;
    }

    r.keepalive.set(false);

    r.connection.log.set_action(Some("proxying upgraded connection"));

    if *r.clcf().borrow().tcp_nodelay {
        if !r.connection.set_tcp_nodelay() {
            return finalize(r, u, m, NGX_ERROR).await;
        }

        if let Some(c) = u.sock.as_ref().and_then(sock_conn) {
            if !c.set_tcp_nodelay() {
                return finalize(r, u, m, NGX_ERROR).await;
            }
        }
    }

    if crate::special_response::send_special(r, false).await == NGX_ERROR {
        return finalize(r, u, m, NGX_ERROR).await;
    }

    let rc = process_upgraded(r, u).await;

    finalize(r, u, m, rc).await
}

/// ngx_http_upstream_process_upgraded until one side is done: 0, or 504
/// ("upstream timed out"), 408 ("client timed out"), NGX_ERROR.
async fn process_upgraded(r: &R, u: &mut Upstream) -> i64 {
    use tokio::io::AsyncWriteExt;

    let read_timeout = u.conf.read_timeout;
    let send_timeout = u.conf.send_timeout;
    let client_send_timeout = *r.clcf().borrow().send_timeout;
    let buffer_size = u.conf.buffer_size.max(1);

    let client = r.connection.clone();

    // what the upstream sent after the header, and what the client sent
    // after its request (r->header_in)
    let from_upstream: Vec<u8> = u.resp.buf[u.resp.pos.min(u.resp.buf.len())..].to_vec();

    let from_client = {
        let mut hb = r.http_connection.buffer.borrow_mut();
        let tail = hb.unread().to_vec();
        hb.pos = hb.last;
        tail
    };

    let sock = u.sock.as_mut().expect("connection");

    if !from_upstream.is_empty() {
        match tokio::time::timeout(Duration::from_millis(client_send_timeout), client.send_all(&from_upstream)).await {
            Err(_) => {
                client.timedout.set(true);
                let _ = client.connection_error(libc::ETIMEDOUT, "client timed out");
                return NGX_HTTP_REQUEST_TIME_OUT;
            }
            Ok(Err(_)) => return NGX_ERROR,
            Ok(Ok(())) => {}
        }
    }

    if !from_client.is_empty() {
        match tokio::time::timeout(Duration::from_millis(send_timeout), sock.write_all(&from_client)).await {
            Err(_) => {
                let _ = client.connection_error(libc::ETIMEDOUT, "upstream timed out");
                return NGX_HTTP_GATEWAY_TIME_OUT;
            }
            Ok(Err(_)) => return NGX_ERROR,
            Ok(Ok(())) => {}
        }
    }

    let (mut up_r, mut up_w) = tokio::io::split(sock);

    // the timer of the upstream read, armed again on each event
    let activity = Rc::new(std::cell::Cell::new(ngx_core::times::current_msec()));

    enum End {
        Done,
        UpstreamTimeout,
        ClientTimeout,
        Error,
    }

    let client_to_up = {
        let client = client.clone();
        let activity = activity.clone();

        async move {
            let mut buf = vec![0u8; buffer_size];

            loop {
                let n = match client.recv(&mut buf).await {
                    Ok(0) => return End::Done,
                    Err(_) => return End::Done,
                    Ok(n) => n,
                };

                activity.set(ngx_core::times::current_msec());

                match tokio::time::timeout(Duration::from_millis(send_timeout), up_w.write_all(&buf[..n])).await {
                    Err(_) => return End::UpstreamTimeout,
                    Ok(Err(_)) => return End::Error,
                    Ok(Ok(())) => activity.set(ngx_core::times::current_msec()),
                }
            }
        }
    };

    let up_to_client = {
        let client = client.clone();
        let activity = activity.clone();

        async move {
            let mut buf = vec![0u8; buffer_size];

            loop {
                let n = match up_r.read(&mut buf).await {
                    Ok(0) => return End::Done,
                    Err(_) => return End::Done,
                    Ok(n) => n,
                };

                activity.set(ngx_core::times::current_msec());

                if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
                    st.bytes_received += n as i64;
                }

                match tokio::time::timeout(Duration::from_millis(client_send_timeout), client.send_all(&buf[..n])).await {
                    Err(_) => return End::ClientTimeout,
                    Ok(Err(_)) => return End::Error,
                    Ok(Ok(())) => activity.set(ngx_core::times::current_msec()),
                }
            }
        }
    };

    let timer = async {
        loop {
            let idle = ngx_core::times::current_msec().saturating_sub(activity.get());

            if idle >= read_timeout {
                return End::UpstreamTimeout;
            }

            tokio::time::sleep(Duration::from_millis(read_timeout - idle)).await;
        }
    };

    let end = tokio::select! {
        e = client_to_up => e,
        e = up_to_client => e,
        e = timer => e,
    };

    match end {
        End::Done => {
            http_debug!(r, "http upstream upgraded done");
            0
        }
        End::UpstreamTimeout => {
            let _ = client.connection_error(libc::ETIMEDOUT, "upstream timed out");
            NGX_HTTP_GATEWAY_TIME_OUT
        }
        End::ClientTimeout => {
            client.timedout.set(true);
            let _ = client.connection_error(libc::ETIMEDOUT, "client timed out");
            NGX_HTTP_REQUEST_TIME_OUT
        }
        End::Error => NGX_ERROR,
    }
}

// ---------------------------------------------------------------------------
// the error log
// ---------------------------------------------------------------------------

/// The upstream part of ngx_http_log_error_handler: "schema peer uri", with
/// ":" before the uri for a unix socket, once a peer is chosen.
pub fn log_info(r: &Request) -> Option<Vec<u8>> {
    let u = crate::upstream_cache::upstream_of(r)?;

    let name = u.peer_name.try_borrow().ok()?;
    let name = name.as_ref()?;

    let mut v = u.schema.try_borrow().ok()?.clone();

    v.extend_from_slice(name);

    if u.peer_unix.get() {
        v.push(b':');
    }

    v.extend_from_slice(&u.uri.try_borrow().ok()?);

    Some(v)
}

// ---------------------------------------------------------------------------
// the configuration functions of ngx_http_upstream.c
// ---------------------------------------------------------------------------

/// ngx_http_upstream_bind_set_slot: "*_bind address [transparent] | off"
pub fn bind_set_slot(cf: &mut ngx_core::conf::Conf, local: &mut ngx_core::conf::Val<Option<Rc<UpstreamLocal>>>) -> ngx_core::conf::ConfResult {
    use ngx_core::conf::{msg, Val};

    if local.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    if value.len() == 2 && value[1] == b"off" {
        *local = Val::set(None);
        return Ok(());
    }

    let cv = crate::script::compile_complex_value(cf, &value[1], 0)?;

    let mut l = UpstreamLocal { addr: None, value: None, transparent: false };

    if !cv.is_constant() {
        l.value = Some(cv);
    } else {
        match ngx_core::inet::parse_addr_port(&value[1]) {
            Some(sa) => l.addr = Some(LocalAddr { sockaddr: sa, name: value[1].clone() }),
            None => return Err(cf.emerg(format_args!("invalid address \"{}\"", B(&value[1])))),
        }
    }

    if value.len() > 2 {
        if value[2] == b"transparent" {
            // NGX_HAVE_TRANSPARENT_PROXY: ccf->transparent = 1 (the worker
            // keeps CAP_NET_RAW), local->transparent = 1
            l.transparent = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    *local = Val::set(Some(Rc::new(l)));

    Ok(())
}

/// ngx_conf_set_str_array_slot of *_hide_header and *_pass_header
pub fn str_array_push(list: &mut ngx_core::conf::Val<Rc<Vec<Vec<u8>>>>, value: &[u8]) {
    let mut v: Vec<Vec<u8>> = match list.as_option() {
        Some(l) => l.as_ref().clone(),
        None => Vec::new(),
    };

    v.push(value.to_vec());

    *list = ngx_core::conf::Val::set(Rc::new(v));
}

/// The names of the hide headers of ngx_http_upstream_hide_headers_hash:
/// the module's defaults and those of *_hide_header, but *_pass_header.
pub fn hide_headers_names(default_hide_headers: &[&[u8]], hide: &[Vec<u8>], pass: &[Vec<u8>]) -> Vec<Vec<u8>> {
    // None for the names of *_pass_header (key.data = NULL)
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

fn same_list(a: &ngx_core::conf::Val<Rc<Vec<Vec<u8>>>>, b: &ngx_core::conf::Val<Rc<Vec<Vec<u8>>>>) -> bool {
    match (a.as_option(), b.as_option()) {
        (None, None) => true,
        (Some(x), Some(y)) => Rc::ptr_eq(x, y),
        _ => false,
    }
}

/// The hide and pass headers of a level of ngx_http_upstream_conf_t.
pub struct HideHeaders<'a> {
    pub hide: &'a mut ngx_core::conf::Val<Rc<Vec<Vec<u8>>>>,
    pub pass: &'a mut ngx_core::conf::Val<Rc<Vec<Vec<u8>>>>,
    pub hash: &'a mut Option<Rc<Hash<()>>>,
}

/// ngx_http_upstream_hide_headers_hash
pub fn hide_headers_hash(cf: &mut ngx_core::conf::Conf, conf: HideHeaders, prev: HideHeaders, default_hide_headers: &[&[u8]], name: &'static str, bucket_size: usize) -> ngx_core::conf::ConfResult {
    use ngx_core::hash::{hash_key_lc, HashInit, HashKey};

    if !conf.hide.is_set() && !conf.pass.is_set() {
        *conf.hide = prev.hide.clone();
        *conf.pass = prev.pass.clone();

        *conf.hash = prev.hash.clone();

        if conf.hash.is_some() {
            return Ok(());
        }
    } else {
        if !conf.hide.is_set() {
            *conf.hide = prev.hide.clone();
        }

        if !conf.pass.is_set() {
            *conf.pass = prev.pass.clone();
        }
    }

    let hide = conf.hide.as_option().map(|l| l.as_slice()).unwrap_or(&[]);
    let pass = conf.pass.as_option().map(|l| l.as_slice()).unwrap_or(&[]);

    let names: Vec<HashKey<()>> = hide_headers_names(default_hide_headers, hide, pass)
        .into_iter()
        .map(|k| HashKey { key_hash: hash_key_lc(&k), key: k.to_ascii_lowercase(), value: () })
        .collect();

    let hinit = HashInit { name, max_size: 512, bucket_size, log: &cf.log };

    let hash = match Hash::init(&hinit, names) {
        Ok(h) => h,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
            return Err(ngx_core::conf::ConfError::Logged);
        }
    };

    *conf.hash = Some(Rc::new(hash));

    // special handling to preserve conf->hide_headers_hash in the "http"
    // section to inherit it to all servers

    if prev.hash.is_none() && same_list(conf.hide, prev.hide) && same_list(conf.pass, prev.pass) {
        *prev.hash = conf.hash.clone();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// the params of the CGI-like modules (fastcgi, scgi, uwsgi)
// ---------------------------------------------------------------------------

/// ngx_http_upstream_param_t: a *_param
#[derive(Clone, Debug)]
pub struct ParamSource {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub skip_empty: bool,
}

/// A param of params->lengths and params->values: the key, "if_not_empty"
/// and the codes of the value.
pub struct Param {
    pub key: Vec<u8>,
    pub skip_empty: bool,
    pub codes: Vec<Part>,
}

/// ngx_http_fastcgi_params_t, ngx_http_scgi_params_t, ngx_http_uwsgi_params_t
pub struct Params {
    /// params->flushes: the variables of the values
    pub flushes: Vec<usize>,
    /// params->lengths and params->values
    pub params: Vec<Param>,
    /// params->number: the HTTP_* params
    pub number: usize,
    /// params->hash: the names of the HTTP_* params after "HTTP_",
    /// lowercase; the request headers of these names are not sent
    pub hash: Hash<()>,
}

impl Params {
    /// params->number && ngx_hash_find(&params->hash, ...): the request
    /// header of this name (lower case, '-' as '_') is not sent, a HTTP_*
    /// param of the name is.
    pub fn hides(&self, lowcase_key: &[u8]) -> bool {
        self.number != 0 && self.hash.find(hash_key(lowcase_key), lowcase_key).is_some()
    }
}

/// ngx_http_upstream_param_set_slot: "*_param key value [if_not_empty]"
pub fn param_set_slot(cf: &mut ngx_core::conf::Conf, list: &mut Option<Rc<Vec<ParamSource>>>) -> ngx_core::conf::ConfResult {
    let value = cf.args.clone();

    let mut param = ParamSource { key: value[1].clone(), value: value[2].clone(), skip_empty: false };

    if value.len() == 4 {
        if value[3] != b"if_not_empty" {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[3]))));
        }

        param.skip_empty = true;
    }

    let mut v: Vec<ParamSource> = match list.take() {
        Some(l) => Rc::try_unwrap(l).unwrap_or_else(|l| l.as_ref().clone()),
        None => Vec::new(),
    };

    v.push(param);

    *list = Some(Rc::new(v));

    Ok(())
}

/// The init_params of the modules (ngx_http_fastcgi_init_params and the
/// like): the params of *_param, then those of
/// `default_params` it does not set (sent only if not empty); the names of
/// the HTTP_* ones go to the hash (the request headers of these names are
/// not sent), and the params with a value are compiled.
pub fn init_params(cf: &mut ngx_core::conf::Conf, params_source: Option<&Rc<Vec<ParamSource>>>, default_params: &[(&[u8], &[u8])], name: &'static str) -> Result<Rc<Params>, ngx_core::conf::ConfError> {
    use ngx_core::hash::{hash_key_lc, HashInit, HashKey};

    let src = merge_params(params_source.map(|s| s.as_slice()).unwrap_or(&[]), default_params);

    let mut headers_names: Vec<HashKey<()>> = Vec::new();
    let mut params: Vec<Param> = Vec::new();
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

        params.push(Param { key: s.key, skip_empty: s.skip_empty, codes });
    }

    let number = headers_names.len();

    let hinit = HashInit { name, max_size: 512, bucket_size: 64, log: &cf.log };

    let hash = match Hash::init(&hinit, headers_names) {
        Ok(h) => h,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
            return Err(ngx_core::conf::ConfError::Logged);
        }
    };

    Ok(Rc::new(Params { flushes, params, number, hash }))
}

/// params_merged of the init_params: the params of *_param,
/// then the default params of names they do not have (compared
/// case-insensitively), sent only if not empty.
pub fn merge_params(source: &[ParamSource], default_params: &[(&[u8], &[u8])]) -> Vec<ParamSource> {
    let mut src: Vec<ParamSource> = source.to_vec();

    for (key, value) in default_params {
        if src.iter().any(|s| s.key.eq_ignore_ascii_case(key)) {
            continue;
        }

        src.push(ParamSource { key: key.to_vec(), value: value.to_vec(), skip_empty: true });
    }

    src
}

/// The status of a "Status" header: ngx_atoi() of its first 3 characters
/// (the value is null-terminated: a shorter one is invalid).
pub fn cgi_status(value: &[u8]) -> Option<i64> {
    if value.len() < 3 {
        return None;
    }

    ngx_core::string::atoi(&value[..3])
}

/// The key of a request header as a param: "HTTP_" and the name in upper
/// case, '-' as '_'.
pub fn header_param_key(name: &[u8]) -> Vec<u8> {
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
pub fn header_hash_key(name: &[u8]) -> Vec<u8> {
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

/// The request headers as params: ngx_http_link_multi_headers() links the
/// headers of a name (compared case-insensitively) to the first one, which
/// is sent with the values of all, joined with "; " for "Cookie" and ", "
/// otherwise; a header is not sent when `hidden` says so of its name in
/// lower case with '-' as '_' (the params hash).
pub fn header_params(headers: &[Header], hidden: &dyn Fn(&[u8]) -> bool) -> Vec<(Vec<u8>, Vec<u8>)> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atoof() {
        assert_eq!(atoof(b"0"), 0);
        assert_eq!(atoof(b"12345"), 12345);
        assert_eq!(atoof(b""), NGX_ERROR);
        assert_eq!(atoof(b"12a"), NGX_ERROR);
        assert_eq!(atoof(b" 1"), NGX_ERROR);
        assert_eq!(atoof(b"99999999999999999999"), NGX_ERROR);
    }
}
