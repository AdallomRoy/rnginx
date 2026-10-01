//! ngx_http_grpc_module
//!
//! The request goes to the upstream as a stream of an HTTP/2 connection:
//! the connection preface with the SETTINGS and WINDOW_UPDATE frames of a
//! new connection, then the HEADERS frame (and CONTINUATION frames) of the
//! request (ngx_http_grpc_create_request), and the body as DATA frames
//! within the upstream's flow control windows
//! (ngx_http_grpc_body_output_filter). The response frames are parsed by
//! ngx_http_grpc_process_header (the header) and ngx_http_grpc_filter (the
//! body and the trailers); the SETTINGS and PING frames are acknowledged and
//! the windows the upstream uses are updated as they come.
//!
//! The body and the module's frames keep going to the upstream after the
//! response header (u->conf->preserve_output, the duplex part of the
//! upstream core in upstream_rt.rs), and a connection whose stream ended
//! cleanly is kept for the next request with a keepalive upstream: the
//! HTTP/2 state of the connection (ngx_http_grpc_conn_t, a cleanup of
//! c->pool in C) goes with it.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::event_connect::LocalAddr;
use ngx_core::event_openssl::{
    ngx_ssl_certificate, ngx_ssl_ciphers, ngx_ssl_client_session_cache, ngx_ssl_conf_commands, ngx_ssl_create, ngx_ssl_crl, ngx_ssl_read_password_file,
    ngx_ssl_trusted_certificate, NgxSsl, NGX_SSL_DEFAULT_PROTOCOLS,
};
use ngx_core::hash::{hash_key, hash_key_lc, Hash, HashInit, HashKey};
use ngx_core::inet::Url;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::core::CoreLocConf;
use crate::request::*;
use crate::script::{ComplexValue, Part};
use crate::upstream::*;
use crate::upstream_cache::{UpstreamCacheConf, NGX_CONF_BITMASK_SET, NGX_HTTP_UPSTREAM_EARLY_HINTS, NGX_HTTP_UPSTREAM_INVALID_HEADER};
use crate::upstream_rt::{Upstream, UpstreamConf, UpstreamLocal, UpstreamModule};
use crate::upstream_ssl::UpstreamSslConf;
use crate::upstream_h2::*;
use crate::v2::encode::{inc_indexed, indexed, write_name, write_value};
use crate::v2::*;
use crate::variables::{add_variables, VarDef, NGX_HTTP_VAR_NOCACHEABLE, NGX_HTTP_VAR_NOHASH};
use crate::*;

crate::http_module_index!("ngx_http_grpc_module");

/// ngx_http_grpc_next_upstream_masks
const GRPC_NEXT_UPSTREAM_MASKS: &[(&str, u32)] = &[
    ("error", NGX_HTTP_UPSTREAM_FT_ERROR),
    ("timeout", NGX_HTTP_UPSTREAM_FT_TIMEOUT),
    ("invalid_header", NGX_HTTP_UPSTREAM_FT_INVALID_HEADER),
    ("non_idempotent", NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT),
    ("http_500", NGX_HTTP_UPSTREAM_FT_HTTP_500),
    ("http_502", NGX_HTTP_UPSTREAM_FT_HTTP_502),
    ("http_503", NGX_HTTP_UPSTREAM_FT_HTTP_503),
    ("http_504", NGX_HTTP_UPSTREAM_FT_HTTP_504),
    ("http_403", NGX_HTTP_UPSTREAM_FT_HTTP_403),
    ("http_404", NGX_HTTP_UPSTREAM_FT_HTTP_404),
    ("http_429", NGX_HTTP_UPSTREAM_FT_HTTP_429),
    ("off", NGX_HTTP_UPSTREAM_FT_OFF),
];

/// ngx_http_grpc_ssl_protocols
const GRPC_SSL_PROTOCOLS: &[(&str, u32)] = &[
    ("SSLv2", 0x0002),
    ("SSLv3", 0x0004),
    ("TLSv1", 0x0008),
    ("TLSv1.1", 0x0010),
    ("TLSv1.2", 0x0020),
    ("TLSv1.3", 0x0040),
];

/// ngx_http_grpc_headers
const GRPC_HEADERS: &[(&[u8], &[u8])] = &[
    (b"Content-Length", b"$content_length"),
    (b"TE", b"$grpc_internal_trailers"),
    (b"Host", b""),
    (b"Connection", b""),
    (b"Proxy-Connection", b""),
    (b"Transfer-Encoding", b""),
    (b"Keep-Alive", b""),
    (b"Expect", b""),
    (b"Upgrade", b""),
];

/// ngx_http_grpc_hide_headers
const GRPC_HIDE_HEADERS: &[&[u8]] = &[b"Date", b"Server", b"X-Accel-Expires", b"X-Accel-Redirect", b"X-Accel-Limit-Rate", b"X-Accel-Buffering", b"X-Accel-Charset"];


/// The tag of the module's buffers
/// (ngx_http_grpc_body_output_filter as the tag)
const GRPC_TAG: usize = 0x6772_7063;


/// ngx_http_grpc_headers_t: the request headers of grpc_set_header and the
/// defaults, as ngx_http_grpc_init_headers() compiles them.
pub struct GrpcHeaders {
    /// headers->flushes: the variables of the values
    pub flushes: Vec<usize>,
    /// headers->lengths and headers->values: the name and the value codes
    /// of each header with a value in the configuration
    pub lines: Vec<(Vec<u8>, Vec<Part>)>,
    /// headers->hash: the names of all of them
    pub hash: Hash<()>,
}

/// ngx_http_grpc_loc_conf_t, with the fields of ngx_http_upstream_conf_t
/// the module uses.
pub struct NgxHttpGrpcLocConf {
    /// upstream.upstream: the upstream of grpc_pass without variables
    pub upstream: Option<Rc<UpstreamSrvConf>>,

    /// upstream.local: unset, NULL ("off") or the address
    pub local: Val<Option<Rc<UpstreamLocal>>>,
    pub socket_keepalive: Val<bool>,
    pub socket_rcvbuf: Val<usize>,
    pub socket_sndbuf: Val<usize>,

    pub next_upstream_tries: Val<i64>,
    pub connect_timeout: Val<u64>,
    pub send_timeout: Val<u64>,
    pub read_timeout: Val<u64>,
    pub next_upstream_timeout: Val<u64>,

    pub buffer_size: Val<usize>,

    /// upstream.next_upstream: a bitmask, 0 when not set
    pub next_upstream: u32,

    pub intercept_errors: Val<bool>,

    /// upstream.hide_headers and pass_headers (NGX_CONF_UNSET_PTR or the
    /// list), and hide_headers_hash once built
    pub hide_headers: Val<Rc<Vec<Vec<u8>>>>,
    pub pass_headers: Val<Rc<Vec<Vec<u8>>>>,
    pub hide_headers_hash: Option<Rc<Hash<()>>>,

    /// upstream.ignore_headers (the cache is off: only that field is used)
    pub cache: UpstreamCacheConf,

    /// headers once built (headers.hash.buckets), and headers_source: the
    /// grpc_set_header of the level (unset, NULL or the list)
    pub headers: Option<Rc<GrpcHeaders>>,
    pub headers_source: Val<Option<Rc<Vec<(Vec<u8>, Vec<u8>)>>>>,

    /// glcf->host: the :authority of grpc_pass without variables
    pub host: Vec<u8>,
    /// glcf->host_value: the value of "grpc_set_header Host"
    pub host_value: Option<Rc<ComplexValue>>,

    /// grpc_lengths and grpc_values: the codes of a grpc_pass with
    /// variables
    pub grpc_values: Option<Rc<Vec<Part>>>,

    /// The SSL fields of upstream: grpc_ssl_session_reuse, grpc_ssl_name,
    /// grpc_ssl_server_name, grpc_ssl_verify, grpc_ssl_certificate,
    /// grpc_ssl_certificate_key, grpc_ssl_certificate_cache,
    /// grpc_ssl_password_file, and the context.
    pub upstream_ssl: UpstreamSslConf,

    /// grpcs, or grpc_pass with variables: the location needs the SSL
    /// context (ngx_http_grpc_set_ssl)
    pub ssl: bool,
    /// a bitmask, 0 when not set
    pub ssl_protocols: u32,
    pub ssl_ciphers: Val<Vec<u8>>,
    pub ssl_verify_depth: Val<i64>,
    pub ssl_trusted_certificate: Val<Vec<u8>>,
    pub ssl_crl: Val<Vec<u8>>,
    pub ssl_conf_commands: Val<Option<Vec<(Vec<u8>, Vec<u8>)>>>,

    /// glcf->upstream as a request uses it, once merged
    pub upstream_conf: Option<Rc<UpstreamConf>>,
}

impl crate::upstream_cache::UpstreamCacheLocConf for NgxHttpGrpcLocConf {
    fn upstream_cache(&mut self) -> &mut UpstreamCacheConf {
        &mut self.cache
    }
}

/// ngx_http_grpc_create_loc_conf
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(new_loc_conf())
}

/// The location configuration of ngx_http_grpc_create_loc_conf.
fn new_loc_conf() -> NgxHttpGrpcLocConf {
    // set by ngx_pcalloc(): ignore_headers = 0, next_upstream = 0,
    // hide_headers_hash = { NULL, 0 }, headers = { NULL }, host = { 0,
    // NULL }, host_value = NULL, ssl = 0, ssl_protocols = 0, ssl_ciphers,
    // ssl_trusted_certificate and ssl_crl = { 0, NULL }
    //
    // the hardcoded values: cyclic_temp_file = 0, buffering = 0,
    // ignore_client_abort = 0, send_lowat = 0, bufs.num = 0,
    // busy_buffers_size = 0, max_temp_file_size = 0,
    // temp_file_write_size = 0, pass_request_headers = 1,
    // pass_request_body = 1, force_ranges = 0, pass_trailers = 1,
    // pass_early_hints = 1, preserve_output = 1, module = "grpc"
    NgxHttpGrpcLocConf {
        upstream: None,
        local: Val::unset(),
        socket_keepalive: Val::unset(),
        socket_rcvbuf: Val::unset(),
        socket_sndbuf: Val::unset(),
        next_upstream_tries: Val::unset(),
        connect_timeout: Val::unset(),
        send_timeout: Val::unset(),
        read_timeout: Val::unset(),
        next_upstream_timeout: Val::unset(),
        buffer_size: Val::unset(),
        next_upstream: 0,
        intercept_errors: Val::unset(),
        hide_headers: Val::unset(),
        pass_headers: Val::unset(),
        hide_headers_hash: None,
        cache: UpstreamCacheConf::default(),
        headers: None,
        headers_source: Val::unset(),
        host: Vec::new(),
        host_value: None,
        grpc_values: None,
        upstream_ssl: UpstreamSslConf::default(),
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



/// The context of the module for a request: the location's configuration,
/// ngx_http_grpc_ctx_t (the stream) and the :authority of the request.
struct GrpcModule {
    lcf: Rc<RefCell<NgxHttpGrpcLocConf>>,
    ctx: H2Ctx,
    host: Vec<u8>,
}

/// ngx_http_grpc_handler
async fn grpc_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpGrpcLocConf>(ctx_index());

    let (conf, grpc_values, ssl, host) = {
        let c = lcf.borrow();
        (c.upstream_conf.clone(), c.grpc_values.clone(), c.ssl, c.host.clone())
    };

    let conf = match conf {
        Some(c) => c,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // ngx_http_upstream_create

    let mut u = Upstream::create(&r, conf, Rc::new(Vec::new()), b"grpc://");

    let ctx = H2Ctx::new("grpc", GRPC_TAG);

    let mut authority_host = Vec::new();

    match grpc_values {
        None => {
            authority_host = host;

            u.ssl = ssl;

            if ssl {
                u.set_schema(b"grpcs://");
            } else {
                u.set_schema(b"grpc://");
            }
        }

        Some(codes) => {
            if grpc_eval(&r, &mut authority_host, &codes, &mut u) != NGX_OK {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    r.request_body_no_buffering.set(true);

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    let mut m = GrpcModule { lcf, ctx, host: authority_host };

    crate::upstream_rt::init(r, u, &mut m).await
}

/// ngx_http_grpc_eval: the URL of grpc_pass with variables, its scheme,
/// the upstream it names (u->resolved) and the :authority.
fn grpc_eval(r: &R, host: &mut Vec<u8>, codes: &[Part], u: &mut Upstream) -> i64 {
    let url = match crate::script::script_run(r, codes) {
        Some(v) => v,
        None => return NGX_ERROR,
    };

    let add = if url.len() > 7 && url[..7].eq_ignore_ascii_case(b"grpc://") {
        7
    } else if url.len() > 8 && url[..8].eq_ignore_ascii_case(b"grpcs://") {
        u.ssl = true;
        8
    } else {
        0
    };

    if add > 0 {
        u.set_schema(&url[..add]);
    } else {
        u.set_schema(b"grpc://");
    }

    let mut url = Url::new(&url[add..]);
    url.no_resolve = true;

    if ngx_core::inet::parse_url(&mut url).is_err() {
        if let Some(err) = url.err {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "{} in upstream \"{}\"", err, B(&url.url));
        }

        return NGX_ERROR;
    }

    *host = authority(&url);

    // u->resolved: the first address, the host, the port and no_port
    u.resolved = Some(url);

    NGX_OK
}

/// The :authority of a URL: the host with the port as it was written, or
/// "localhost" for a unix socket.
fn authority(u: &Url) -> Vec<u8> {
    if u.family == libc::AF_UNIX {
        return b"localhost".to_vec();
    }

    if u.no_port {
        return u.host.clone();
    }

    let mut host = u.host.clone();
    host.push(b':');
    host.extend_from_slice(&u.port_text);

    host
}





impl GrpcModule {
    /// ngx_http_grpc_get_ctx: the connection's HTTP/2 state, found once
    /// per connection (ngx_http_grpc_get_connection_data)
    fn get_ctx(&mut self, r: &R, u: &mut Upstream) -> Result<(), ()> {
        if self.ctx.connection.is_some() {
            return Ok(());
        }

        let ctx = &mut self.ctx;

        if u.peer_cached {
            // for cached connections, connection data can be found in the
            // cleanup handler
            let conn = u.conn_data.clone().and_then(|d| d.downcast::<RefCell<H2Conn>>().ok()).filter(|c| c.borrow().tag == GRPC_TAG);

            let conn = match conn {
                Some(c) => c,
                None => {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no connection data found for keepalive http2 connection");
                    return Err(());
                }
            };

            {
                let mut c = conn.borrow_mut();

                ctx.send_window = c.init_window as isize;
                ctx.recv_window = NGX_HTTP_V2_MAX_WINDOW;

                c.last_stream_id += 2;
                ctx.id = c.last_stream_id;
            }

            ctx.connection = Some(conn);

            return Ok(());
        }

        let conn = Rc::new(RefCell::new(H2Conn {
            init_window: NGX_HTTP_V2_DEFAULT_WINDOW,
            send_window: NGX_HTTP_V2_DEFAULT_WINDOW,
            recv_window: NGX_HTTP_V2_MAX_WINDOW,
            last_stream_id: 1,
            tag: GRPC_TAG,
        }));

        ctx.send_window = NGX_HTTP_V2_DEFAULT_WINDOW as isize;
        ctx.recv_window = NGX_HTTP_V2_MAX_WINDOW;

        ctx.id = 1;

        let data: Rc<dyn Any> = conn.clone();
        u.conn_data = Some(data);

        ctx.connection = Some(conn);

        Ok(())
    }






}

impl UpstreamModule for GrpcModule {
    fn create_key(&self, _r: &R, _keys: &mut Vec<Vec<u8>>) -> i64 {
        NGX_OK
    }

    /// ngx_http_grpc_create_request
    fn create_request(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let glcf = self.lcf.borrow();

        let b = match create_request(r, &glcf, &self.host, u.ssl) {
            Ok(b) => b,
            Err(()) => return NGX_ERROR,
        };

        let headers_frame = CONNECTION_START.len();

        let mut hb = Buf::from_vec(b);

        let mut bufs = Chain::new();

        if r.request_body_no_buffering.get() {
            hb.flush = true;
            bufs.push_back(hb);
        } else {
            let body = crate::upstream_rt::request_body_bufs(r);

            if body.is_empty() {
                // f->flags |= NGX_HTTP_V2_END_STREAM_FLAG
                if let BufData::Memory(v) = &mut hb.data {
                    v[headers_frame + 4] |= NGX_HTTP_V2_END_STREAM_FLAG;
                }
            }

            bufs.push_back(hb);

            bufs.extend(body);

            let last = bufs.back_mut().expect("buffer");
            last.last_buf = true;
            last.flush = true;
        }

        u.request_bufs = bufs;

        NGX_OK
    }

    /// ngx_http_grpc_reinit_request
    fn reinit_request(&mut self, _r: &R, _u: &mut Upstream) -> i64 {
        let ctx = &mut self.ctx;

        ctx.state = ST_START;
        ctx.header_sent = false;
        ctx.output_closed = false;
        ctx.output_blocked = false;
        ctx.parsing_headers = false;
        ctx.end_stream = false;
        ctx.done = false;
        ctx.status = false;
        ctx.rst = false;
        ctx.goaway = false;
        ctx.connection = None;
        ctx.input.clear();
        ctx.out.clear();

        NGX_OK
    }

    /// ngx_http_grpc_process_header
    fn process_header(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let buf = std::mem::take(&mut u.resp.buf);
        let mut pos = u.resp.pos.min(buf.len());

        http_debug!(r, "grpc response: {}, len: {}", hex_head(&buf[pos..]), buf.len() - pos);

        if self.get_ctx(r, u).is_err() {
            u.resp.buf = buf;
            return NGX_ERROR;
        }

        let mut reset = false;

        let rc = self.process_header_frames(r, u, &buf, &mut pos, &mut reset);

        if reset {
            // there can be a lot of window update frames, so the buffer is
            // reset if it is empty and the headers are not parsed yet
            u.resp.buf = Vec::new();
            u.resp.pos = 0;
        } else {
            u.resp.buf = buf;
            u.resp.pos = pos;
        }

        rc
    }

    /// ngx_http_grpc_filter_init
    fn input_filter_init(&mut self, r: &R, u: &mut Upstream, _p: Option<&mut crate::event_pipe::EventPipe>) -> i64 {
        let ctx = &mut self.ctx;

        let status = u.resp.status_n;

        if status == NGX_HTTP_NO_CONTENT || status == NGX_HTTP_NOT_MODIFIED || r.method.get() == NGX_HTTP_HEAD {
            ctx.length = 0;
        } else {
            ctx.length = u.resp.content_length_n;
        }

        if ctx.end_stream {
            if ctx.length > 0 {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed stream");
                return NGX_ERROR;
            }

            u.length = 0;
            ctx.done = true;
        } else {
            u.length = 1;
        }

        NGX_OK
    }

    /// ngx_http_grpc_filter
    fn input_filter(&mut self, r: &R, u: &mut Upstream, data: &[u8]) -> i64 {
        http_debug!(r, "grpc filter bytes:{}", data.len());

        self.filter(r, u, data)
    }

    /// ngx_http_grpc_finalize_request
    fn finalize_request(&mut self, r: &R, _u: &mut Upstream, _rc: i64) {
        http_debug!(r, "finalize grpc request");
    }

    /// ngx_http_grpc_body_output_filter
    fn output_filter(&mut self, r: &R, u: &mut Upstream, input: Option<Chain>) -> i64 {
        http_debug!(r, "grpc output filter");

        if self.get_ctx(r, u).is_err() {
            return NGX_ERROR;
        }

        if let Some(input) = input {
            self.ctx.input.extend(input);
        }

        let mut out = Chain::new();

        if !self.ctx.header_sent {
            // first buffer contains headers

            http_debug!(r, "grpc output header");

            self.ctx.header_sent = true;

            let id = self.ctx.id;

            let mut b = match self.ctx.input.pop_front() {
                Some(b) => b,
                None => return NGX_ERROR,
            };

            if id != 1 {
                // keepalive connection: skip connection preface, update
                // stream identifiers

                keepalive_header(&mut b, id);
            }

            if b.last_buf {
                self.ctx.output_closed = true;
            }

            out.push_back(b);
        }

        if !self.ctx.out.is_empty() {
            // queued control frames
            out.extend(std::mem::take(&mut self.ctx.out));
        }

        let limit = self.ctx.body_frames(&r.connection.log, &mut out);

        for b in out.iter() {
            ngx_core::ngx_log_debug!(
                NGX_LOG_DEBUG_EVENT,
                r.connection.log,
                "grpc output out l:{} f:{} size: {} file: {}, size: {}",
                b.last_buf as i32,
                b.in_file as i32,
                if b.in_memory() { b.last - b.pos } else { 0 },
                b.file_pos,
                b.file_last - b.file_pos
            );
        }

        http_debug!(r, "grpc output limit: {} w:{}:{}", limit, self.ctx.send_window, self.ctx.conn().send_window);

        let queued = u.writer.len() + out.len();

        let mut rc = u.chain_writer(r, out);

        // the buffers written out are free again
        self.ctx.free += queued.saturating_sub(u.writer.len());

        if rc == NGX_OK && !self.ctx.input.is_empty() {
            rc = NGX_AGAIN;
        }

        self.ctx.output_blocked = rc == NGX_AGAIN;

        if self.ctx.done {
            // We have already got the response and were sending some
            // additional control frames.  Even if there is still something
            // unsent, stop here anyway.

            u.length = 0;

            let ctx = &self.ctx;

            if ctx.input.is_empty() && ctx.out.is_empty() && ctx.output_closed && !ctx.output_blocked && !ctx.goaway && ctx.state == ST_START {
                u.keepalive = true;
            }

            u.post_read = true;
        }

        rc
    }
}

/// ngx_http_grpc_create_request: the connection preface, the SETTINGS and
/// WINDOW_UPDATE frames, then the HEADERS frame of the request and the
/// CONTINUATION frames the header block needs.
fn create_request(r: &R, glcf: &NgxHttpGrpcLocConf, authority: &[u8], ssl: bool) -> Result<Vec<u8>, ()> {
    let headers = match glcf.headers.clone() {
        Some(h) => h,
        None => return Err(()),
    };

    let method = r.method.get();
    let method_name = r.method_name.borrow().clone();

    // :method header

    if method != NGX_HTTP_GET && method != NGX_HTTP_POST && method_name.len() > NGX_HTTP_V2_MAX_FIELD {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 method: \"{}\"", B(&method_name));
        return Err(());
    }

    // :path header

    let valid_unparsed_uri = r.valid_unparsed_uri.get();

    let (escape, uri_len) = if valid_unparsed_uri {
        (0, r.unparsed_uri.borrow().len())
    } else {
        let uri = r.uri.borrow();
        let escape = 2 * ngx_core::string::escape_uri_count(&uri, ngx_core::string::NGX_ESCAPE_URI);
        (escape, uri.len() + escape + "?".len() + r.args.borrow().len())
    };

    if uri_len > NGX_HTTP_V2_MAX_FIELD {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 URI");
        return Err(());
    }

    // :authority header

    let mut host: Vec<u8> = Vec::new();

    if let Some(hv) = &glcf.host_value {
        host = crate::script::complex_value(r, hv).map_err(|_| ())?;
    }

    if host.is_empty() {
        host = authority.to_vec();
    }

    if host.len() > NGX_HTTP_V2_MAX_FIELD {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 host: \"{}\"", B(&host));
        return Err(());
    }

    // other headers

    crate::script::script_flush_no_cacheable_variables(r, Some(&headers.flushes));

    let mut lines: Vec<(&[u8], Vec<u8>)> = Vec::new();

    for (key, codes) in headers.lines.iter() {
        let value = crate::proxy::run_codes(r, codes);

        if value.is_empty() {
            continue;
        }

        if key.len() > NGX_HTTP_V2_MAX_FIELD {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 header name");
            return Err(());
        }

        if value.len() > NGX_HTTP_V2_MAX_FIELD {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 header value");
            return Err(());
        }

        lines.push((key, value));
    }

    let mut request_headers: Vec<Header> = Vec::new();

    if glcf.upstream_conf.as_ref().map(|c| c.pass_request_headers).unwrap_or(true) {
        for h in r.headers_in.borrow().headers.iter() {
            if headers.hash.find(hash_key(&h.lowcase_key), &h.lowcase_key).is_some() {
                continue;
            }

            let value = h.value.borrow();

            if h.key.len() > NGX_HTTP_V2_MAX_FIELD {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 header name: \"{}\"", B(&h.key));
                return Err(());
            }

            if value.len() > NGX_HTTP_V2_MAX_FIELD {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 header value: \"{}: {}\"", B(&h.key), B(&value));
                return Err(());
            }

            request_headers.push(h.clone());
        }
    }

    let mut b: Vec<u8> = Vec::with_capacity(CONNECTION_START.len() + FRAME_SIZE + uri_len + host.len() + 256);

    // connection preface

    b.extend_from_slice(CONNECTION_START);

    // headers frame

    let headers_frame = b.len();

    b.extend_from_slice(&frame_header(0, NGX_HTTP_V2_HEADERS_FRAME, 0, 1));

    if method == NGX_HTTP_GET {
        b.push(indexed(NGX_HTTP_V2_METHOD_GET_INDEX));

        http_debug!(r, "grpc header: \":method: GET\"");
    } else if method == NGX_HTTP_POST {
        b.push(indexed(NGX_HTTP_V2_METHOD_POST_INDEX));

        http_debug!(r, "grpc header: \":method: POST\"");
    } else {
        b.push(inc_indexed(NGX_HTTP_V2_METHOD_INDEX));
        write_value(&mut b, &method_name);

        http_debug!(r, "grpc header: \":method: {}\"", B(&method_name));
    }

    if ssl {
        b.push(indexed(NGX_HTTP_V2_SCHEME_HTTPS_INDEX));

        http_debug!(r, "grpc header: \":scheme: https\"");
    } else {
        b.push(indexed(NGX_HTTP_V2_SCHEME_HTTP_INDEX));

        http_debug!(r, "grpc header: \":scheme: http\"");
    }

    if valid_unparsed_uri {
        let unparsed_uri = r.unparsed_uri.borrow();

        if unparsed_uri.as_slice() == b"/" {
            b.push(indexed(NGX_HTTP_V2_PATH_ROOT_INDEX));
        } else {
            b.push(inc_indexed(NGX_HTTP_V2_PATH_INDEX));
            write_value(&mut b, &unparsed_uri);
        }

        http_debug!(r, "grpc header: \":path: {}\"", B(&unparsed_uri));
    } else if escape != 0 || !r.args.borrow().is_empty() {
        let uri = r.uri.borrow();
        let args = r.args.borrow();

        let mut p: Vec<u8> = Vec::with_capacity(uri_len);

        if escape != 0 {
            ngx_core::string::escape_uri_into(&mut p, &uri, ngx_core::string::NGX_ESCAPE_URI);
        } else {
            p.extend_from_slice(&uri);
        }

        if !args.is_empty() {
            p.push(b'?');
            p.extend_from_slice(&args);
        }

        b.push(inc_indexed(NGX_HTTP_V2_PATH_INDEX));
        write_value(&mut b, &p);

        http_debug!(r, "grpc header: \":path: {}\"", B(&p));
    } else {
        let uri = r.uri.borrow();

        b.push(inc_indexed(NGX_HTTP_V2_PATH_INDEX));
        write_value(&mut b, &uri);

        http_debug!(r, "grpc header: \":path: {}\"", B(&uri));
    }

    b.push(inc_indexed(NGX_HTTP_V2_AUTHORITY_INDEX));
    write_value(&mut b, &host);

    http_debug!(r, "grpc header: \":authority: {}\"", B(&host));

    for (key, value) in lines.iter() {
        b.push(0);

        write_name(&mut b, key);
        write_value(&mut b, value);

        http_debug!(r, "grpc header: \"{}: {}\"", B(&key.to_ascii_lowercase()), B(value));
    }

    for h in request_headers.iter() {
        let value = h.value.borrow();

        b.push(0);

        write_name(&mut b, &h.key);
        write_value(&mut b, &value);

        http_debug!(r, "grpc header: \"{}: {}\"", B(&h.key.to_ascii_lowercase()), B(&value));
    }

    header_frames(&mut b, headers_frame);

    http_debug!(r, "grpc header: {}, len: {}", hex_head(&b), b.len());

    Ok(b)
}


impl GrpcModule {
    /// The loop of ngx_http_grpc_process_header over the frames of the
    /// buffer.
    fn process_header_frames(&mut self, r: &R, u: &mut Upstream, buf: &[u8], pos: &mut usize, reset: &mut bool) -> i64 {
        loop {
            if self.ctx.state < ST_PAYLOAD {
                let rc = self.ctx.parse_frame(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    // there can be a lot of window update frames, so we
                    // reset buffer if it is empty and we haven't started
                    // parsing headers yet
                    if !self.ctx.parsing_headers {
                        *reset = true;
                    }

                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                // RFC 7540 says that implementations MUST discard frames
                // that have unknown or unsupported types.  However,
                // extension frames that appear in the middle of a header
                // block are not permitted.  Also, for obvious reasons
                // CONTINUATION frames cannot appear before headers, and
                // DATA frames are not expected to appear before all headers
                // are parsed.

                let ctx = &self.ctx;

                if ctx.ty == NGX_HTTP_V2_DATA_FRAME
                    || (ctx.ty == NGX_HTTP_V2_CONTINUATION_FRAME && !ctx.parsing_headers)
                    || (ctx.ty != NGX_HTTP_V2_CONTINUATION_FRAME && ctx.parsing_headers)
                {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected http2 frame: {}", ctx.ty);
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                if ctx.stream_id != 0 && ctx.stream_id != ctx.id {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent frame for unknown stream {}", ctx.stream_id);
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }
            }

            // frame payload

            let ty = self.ctx.ty;

            if ty == NGX_HTTP_V2_RST_STREAM_FRAME {
                let rc = self.ctx.parse_rst_stream(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream rejected request with error {}", self.ctx.error);

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if ty == NGX_HTTP_V2_GOAWAY_FRAME {
                let rc = self.ctx.parse_goaway(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                // If stream_id is lower than one we use, our request won't
                // be processed and needs to be retried.  If stream_id is
                // greater or equal to the one we use, we can continue
                // normally (except we can't use this connection for
                // additional requests).  If there is a real error, the
                // connection will be closed.

                if self.ctx.stream_id < self.ctx.id {
                    // TODO: we can retry non-idempotent requests

                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent goaway with error {}", self.ctx.error);

                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                self.ctx.goaway = true;

                continue;
            }

            if ty == NGX_HTTP_V2_WINDOW_UPDATE_FRAME {
                let rc = self.ctx.parse_window_update(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                if !self.ctx.input.is_empty() {
                    u.post_write = true;
                }

                continue;
            }

            if ty == NGX_HTTP_V2_SETTINGS_FRAME {
                let rc = self.ctx.parse_settings(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                if !self.ctx.input.is_empty() {
                    u.post_write = true;
                }

                continue;
            }

            if ty == NGX_HTTP_V2_PING_FRAME {
                let rc = self.ctx.parse_ping(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                u.post_write = true;
                continue;
            }

            if ty == NGX_HTTP_V2_PUSH_PROMISE_FRAME {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected push promise frame");
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if ty != NGX_HTTP_V2_HEADERS_FRAME && ty != NGX_HTTP_V2_CONTINUATION_FRAME {
                // priority, unknown frames

                if buf.len() - *pos < self.ctx.rest {
                    self.ctx.rest -= buf.len() - *pos;
                    *pos = buf.len();
                    return NGX_AGAIN;
                }

                *pos += self.ctx.rest;
                self.ctx.rest = 0;
                self.ctx.state = ST_START;

                continue;
            }

            // headers

            let rc = loop {
                let rc = self.ctx.parse_header(&r.connection.log, u.conf.buffer_size, buf, pos);

                if rc == NGX_AGAIN {
                    break rc;
                }

                if rc == NGX_OK {
                    // a header line has been parsed successfully

                    let name = std::mem::take(&mut self.ctx.name);
                    let value = std::mem::take(&mut self.ctx.value);

                    http_debug!(r, "grpc header: \"{}: {}\"", B(&name), B(&value));

                    if name.first() == Some(&b':') {
                        if name.as_slice() != b":status" {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid header \"{}: {}\"", B(&name), B(&value));
                            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                        }

                        if self.ctx.status {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent duplicate :status header");
                            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                        }

                        if value.len() != 3 {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid :status \"{}\"", B(&value));
                            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                        }

                        let status = match ngx_core::string::atoi(&value) {
                            Some(s) => s,
                            None => {
                                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid :status \"{}\"", B(&value));
                                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                            }
                        };

                        if status < NGX_HTTP_OK && status != NGX_HTTP_EARLY_HINTS {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected :status \"{}\"", B(&value));
                            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                        }

                        u.resp.status_n = status;

                        if let Some(state) = r.upstream_states.borrow_mut().last_mut() {
                            if state.status == 0 {
                                state.status = status;
                            }
                        }

                        self.ctx.status = true;

                        continue;
                    } else if !self.ctx.status {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent no :status header");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    let h = TableElt::with_hash(&name, &value, hash_key(&name), name.clone());

                    u.resp.headers.push(h.clone());

                    if u.resp.status_n == NGX_HTTP_EARLY_HINTS {
                        continue;
                    }

                    if crate::upstream_rt::process_header_line(r, u, &h).is_err() {
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    continue;
                }

                if rc == NGX_HTTP_PARSE_HEADER_DONE {
                    // a whole header has been parsed successfully

                    http_debug!(r, "grpc header done");

                    if u.resp.status_n == NGX_HTTP_EARLY_HINTS {
                        if self.ctx.end_stream {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed stream");
                            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                        }

                        self.ctx.status = false;
                        return NGX_HTTP_UPSTREAM_EARLY_HINTS;
                    }

                    if self.ctx.end_stream {
                        if u.resp.content_length_n == -1 {
                            u.resp.content_length_n = 0;
                        }

                        let ctx = &self.ctx;

                        if ctx.input.is_empty() && ctx.out.is_empty() && ctx.output_closed && !ctx.output_blocked && !ctx.goaway && *pos == buf.len() {
                            u.keepalive = true;
                        }
                    }

                    return NGX_OK;
                }

                // there was error while a header line parsing

                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid header");

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            };

            // rc == NGX_AGAIN
            let _ = rc;

            if self.ctx.rest == 0 {
                self.ctx.state = ST_START;
                continue;
            }

            return NGX_AGAIN;
        }
    }

    /// The loop of ngx_http_grpc_filter over the frames of the data read.
    fn filter(&mut self, r: &R, u: &mut Upstream, buf: &[u8]) -> i64 {
        let mut pos = 0usize;
        let pos = &mut pos;

        loop {
            if self.ctx.state < ST_PAYLOAD {
                let rc = self.ctx.parse_frame(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    if self.ctx.done {
                        if self.ctx.length > 0 {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed stream");
                            return NGX_ERROR;
                        }

                        // We have finished parsing the response and the
                        // remaining control frames.  If there are unsent
                        // control frames, post a write event to send them.

                        if !self.ctx.out.is_empty() {
                            u.post_write = true;
                            return NGX_AGAIN;
                        }

                        u.length = 0;

                        let ctx = &self.ctx;

                        if ctx.input.is_empty() && ctx.output_closed && !ctx.output_blocked && !ctx.goaway && ctx.state == ST_START {
                            u.keepalive = true;
                        }

                        break;
                    }

                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_ERROR;
                }

                let (ty, parsing_headers) = (self.ctx.ty, self.ctx.parsing_headers);

                if (ty == NGX_HTTP_V2_CONTINUATION_FRAME && !parsing_headers) || (ty != NGX_HTTP_V2_CONTINUATION_FRAME && parsing_headers) {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected http2 frame: {}", ty);
                    return NGX_ERROR;
                }

                if ty == NGX_HTTP_V2_DATA_FRAME {
                    if self.ctx.stream_id != self.ctx.id {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent data frame for unknown stream {}", self.ctx.stream_id);
                        return NGX_ERROR;
                    }

                    if self.ctx.rest > self.ctx.recv_window {
                        ngx_log_error!(
                            NGX_LOG_ERR,
                            r.connection.log,
                            None,
                            "upstream violated stream flow control, received {} data frame with window {}",
                            self.ctx.rest,
                            self.ctx.recv_window
                        );
                        return NGX_ERROR;
                    }

                    let conn_window = self.ctx.conn().recv_window;

                    if self.ctx.rest > conn_window {
                        ngx_log_error!(
                            NGX_LOG_ERR,
                            r.connection.log,
                            None,
                            "upstream violated connection flow control, received {} data frame with window {}",
                            self.ctx.rest,
                            conn_window
                        );
                        return NGX_ERROR;
                    }

                    let rest = self.ctx.rest;

                    self.ctx.recv_window -= rest;

                    let conn_window = {
                        let mut conn = self.ctx.conn();
                        conn.recv_window -= rest;
                        conn.recv_window
                    };

                    if conn_window < NGX_HTTP_V2_MAX_WINDOW / 4 || self.ctx.recv_window < NGX_HTTP_V2_MAX_WINDOW / 4 {
                        if self.ctx.send_window_update(&r.connection.log) != NGX_OK {
                            return NGX_ERROR;
                        }

                        u.post_write = true;
                    }
                }

                let ctx = &self.ctx;

                if ctx.stream_id != 0 && ctx.stream_id != ctx.id {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent frame for unknown stream {}", ctx.stream_id);
                    return NGX_ERROR;
                }

                if ctx.stream_id != 0 && ctx.done && ctx.ty != NGX_HTTP_V2_RST_STREAM_FRAME && ctx.ty != NGX_HTTP_V2_WINDOW_UPDATE_FRAME {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent frame for closed stream {}", ctx.stream_id);
                    return NGX_ERROR;
                }

                self.ctx.padding = 0;
            }

            if self.ctx.state == ST_PADDING {
                if buf.len() - *pos < self.ctx.rest {
                    self.ctx.rest -= buf.len() - *pos;
                    *pos = buf.len();
                    return NGX_AGAIN;
                }

                *pos += self.ctx.rest;
                self.ctx.rest = 0;
                self.ctx.state = ST_START;

                if self.ctx.flags & NGX_HTTP_V2_END_STREAM_FLAG != 0 {
                    self.ctx.done = true;
                }

                continue;
            }

            // frame payload

            let ty = self.ctx.ty;

            if ty == NGX_HTTP_V2_RST_STREAM_FRAME {
                let rc = self.ctx.parse_rst_stream(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_ERROR;
                }

                if self.ctx.error != 0 || !self.ctx.done {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream rejected request with error {}", self.ctx.error);
                    return NGX_ERROR;
                }

                if self.ctx.rst {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent frame for closed stream {}", self.ctx.stream_id);
                    return NGX_ERROR;
                }

                self.ctx.rst = true;

                continue;
            }

            if ty == NGX_HTTP_V2_GOAWAY_FRAME {
                let rc = self.ctx.parse_goaway(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_ERROR;
                }

                // If stream_id is lower than one we use, our request won't
                // be processed and needs to be retried.  If stream_id is
                // greater or equal to the one we use, we can continue
                // normally (except we can't use this connection for
                // additional requests).  If there is a real error, the
                // connection will be closed.

                if self.ctx.stream_id < self.ctx.id {
                    // TODO: we can retry non-idempotent requests

                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent goaway with error {}", self.ctx.error);

                    return NGX_ERROR;
                }

                self.ctx.goaway = true;

                continue;
            }

            if ty == NGX_HTTP_V2_WINDOW_UPDATE_FRAME {
                let rc = self.ctx.parse_window_update(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_ERROR;
                }

                if !self.ctx.input.is_empty() {
                    u.post_write = true;
                }

                continue;
            }

            if ty == NGX_HTTP_V2_SETTINGS_FRAME {
                let rc = self.ctx.parse_settings(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_ERROR;
                }

                if !self.ctx.input.is_empty() {
                    u.post_write = true;
                }

                continue;
            }

            if ty == NGX_HTTP_V2_PING_FRAME {
                let rc = self.ctx.parse_ping(&r.connection.log, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_ERROR;
                }

                u.post_write = true;
                continue;
            }

            if ty == NGX_HTTP_V2_PUSH_PROMISE_FRAME {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent unexpected push promise frame");
                return NGX_ERROR;
            }

            if ty == NGX_HTTP_V2_HEADERS_FRAME || ty == NGX_HTTP_V2_CONTINUATION_FRAME {
                let rc = loop {
                    let rc = self.ctx.parse_header(&r.connection.log, u.conf.buffer_size, buf, pos);

                    if rc == NGX_AGAIN {
                        break rc;
                    }

                    if rc == NGX_OK {
                        // a header line has been parsed successfully

                        let name = std::mem::take(&mut self.ctx.name);
                        let value = std::mem::take(&mut self.ctx.value);

                        http_debug!(r, "grpc trailer: \"{}: {}\"", B(&name), B(&value));

                        if name.first() == Some(&b':') {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid trailer \"{}: {}\"", B(&name), B(&value));
                            return NGX_ERROR;
                        }

                        let h = TableElt::with_hash(&name, &value, hash_key(&name), name.clone());

                        u.resp.trailers.push(h);

                        continue;
                    }

                    if rc == NGX_HTTP_PARSE_HEADER_DONE {
                        // a whole header has been parsed successfully

                        http_debug!(r, "grpc trailer done");

                        if self.ctx.end_stream {
                            self.ctx.done = true;
                            break rc;
                        }

                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent trailer without end stream flag");
                        return NGX_ERROR;
                    }

                    // there was error while a header line parsing

                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid trailer");

                    return NGX_ERROR;
                };

                if rc == NGX_HTTP_PARSE_HEADER_DONE {
                    continue;
                }

                // rc == NGX_AGAIN

                if self.ctx.rest == 0 {
                    self.ctx.state = ST_START;
                    continue;
                }

                return NGX_AGAIN;
            }

            if ty != NGX_HTTP_V2_DATA_FRAME {
                // priority, unknown frames

                if buf.len() - *pos < self.ctx.rest {
                    self.ctx.rest -= buf.len() - *pos;
                    *pos = buf.len();
                    return NGX_AGAIN;
                }

                *pos += self.ctx.rest;
                self.ctx.rest = 0;
                self.ctx.state = ST_START;

                continue;
            }

            // data frame:
            //
            // +---------------+
            // |Pad Length? (8)|
            // +---------------+-----------------------------------------------+
            // |                            Data (*)                         ...
            // +---------------------------------------------------------------+
            // |                           Padding (*)                       ...
            // +---------------------------------------------------------------+

            if self.ctx.flags & NGX_HTTP_V2_PADDED_FLAG != 0 {
                if self.ctx.rest == 0 {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent too short http2 frame");
                    return NGX_ERROR;
                }

                if *pos == buf.len() {
                    return NGX_AGAIN;
                }

                self.ctx.flags &= !NGX_HTTP_V2_PADDED_FLAG;
                self.ctx.padding = buf[*pos];
                *pos += 1;
                self.ctx.rest -= 1;

                if self.ctx.padding as usize > self.ctx.rest {
                    ngx_log_error!(
                        NGX_LOG_ERR,
                        r.connection.log,
                        None,
                        "upstream sent http2 frame with too long padding: {} in frame {}",
                        self.ctx.padding,
                        self.ctx.rest
                    );
                    return NGX_ERROR;
                }

                continue;
            }

            let padding = self.ctx.padding as usize;

            if self.ctx.rest != padding {
                if *pos == buf.len() {
                    return NGX_AGAIN;
                }

                let start = *pos;

                http_debug!(r, "grpc output buf {}", start);

                let end;

                if buf.len() - *pos < self.ctx.rest - padding {
                    self.ctx.rest -= buf.len() - *pos;
                    *pos = buf.len();
                    end = *pos;

                    if self.data_buf(r, u, &buf[start..end]) != NGX_OK {
                        return NGX_ERROR;
                    }

                    return NGX_AGAIN;
                }

                *pos += self.ctx.rest - padding;
                end = *pos;
                self.ctx.rest = padding;

                if self.data_buf(r, u, &buf[start..end]) != NGX_OK {
                    return NGX_ERROR;
                }
            }

            // done:

            if self.ctx.padding != 0 {
                self.ctx.state = ST_PADDING;
                continue;
            }

            self.ctx.state = ST_START;

            if self.ctx.flags & NGX_HTTP_V2_END_STREAM_FLAG != 0 {
                self.ctx.done = true;
            }
        }

        NGX_OK
    }

    /// A part of the body of a DATA frame to u->out_bufs, within the
    /// content length.
    fn data_buf(&mut self, r: &R, u: &mut Upstream, data: &[u8]) -> i64 {
        let mut b = Buf::from_vec(data.to_vec());

        b.flush = true;
        b.memory = true;
        b.temporary = false;

        if self.ctx.length != -1 {
            if data.len() as i64 > self.ctx.length {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent response body larger than indicated content length");
                return NGX_ERROR;
            }

            self.ctx.length -= data.len() as i64;
        }

        u.out_bufs.push_back(b);

        NGX_OK
    }








}



// ---------------------------------------------------------------------------
// the variables
// ---------------------------------------------------------------------------

/// ngx_http_grpc_add_variables
fn grpc_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(
        cf,
        &[VarDef {
            name: "grpc_internal_trailers",
            set: None,
            get: Some(grpc_internal_trailers_variable),
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
        }],
    )
}

/// ngx_http_grpc_internal_trailers_variable: "trailers" when the client
/// takes them (its TE)
fn grpc_internal_trailers_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let te = match r.headers_in.borrow().te.first() {
        Some(te) => te.value.borrow().clone(),
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    if ngx_core::string::strcasestr(&te, b"trailers").is_none() {
        v.not_found = true;
        return NGX_OK;
    }

    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    v.data = b"trailers".to_vec();

    NGX_OK
}

// ---------------------------------------------------------------------------
// the configuration
// ---------------------------------------------------------------------------

/// ngx_http_grpc_merge_loc_conf
fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let mut p = conf_cell::<NgxHttpGrpcLocConf>(prev).borrow_mut();
    let mut c = conf_cell::<NgxHttpGrpcLocConf>(conf).borrow_mut();

    let pagesize = ngx_core::os::pagesize();

    crate::upstream_ssl::merge_ptr(&mut c.local, &p.local);

    c.socket_keepalive.merge(&p.socket_keepalive, false);

    c.socket_rcvbuf.merge(&p.socket_rcvbuf, 0);

    c.socket_sndbuf.merge(&p.socket_sndbuf, 0);

    c.next_upstream_tries.merge(&p.next_upstream_tries, 0);

    c.connect_timeout.merge(&p.connect_timeout, 60000);

    c.send_timeout.merge(&p.send_timeout, 60000);

    c.read_timeout.merge(&p.read_timeout, 60000);

    c.next_upstream_timeout.merge(&p.next_upstream_timeout, 0);

    c.buffer_size.merge(&p.buffer_size, pagesize);

    // ngx_conf_merge_bitmask_value(ignore_headers, NGX_CONF_BITMASK_SET)
    if c.cache.ignore_headers == 0 {
        c.cache.ignore_headers = if p.cache.ignore_headers == 0 { NGX_CONF_BITMASK_SET } else { p.cache.ignore_headers };
    }

    if c.next_upstream == 0 {
        c.next_upstream = if p.next_upstream == 0 { NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_ERROR | NGX_HTTP_UPSTREAM_FT_TIMEOUT } else { p.next_upstream };
    }

    if c.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF != 0 {
        c.next_upstream = NGX_CONF_BITMASK_SET | NGX_HTTP_UPSTREAM_FT_OFF;
    }

    c.intercept_errors.merge(&p.intercept_errors, false);

    // NGX_HTTP_SSL

    grpc_merge_ssl(cf, &mut c, &mut p);

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
        grpc_set_ssl(cf, &mut c)?;
    }

    hide_headers_hash(cf, &mut c, &mut p, GRPC_HIDE_HEADERS)?;

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    let (noname, lmt_excpt, has_handler) = {
        let l = clcf.borrow();
        (l.noname, l.lmt_excpt, l.handler.is_some())
    };

    if noname && c.upstream.is_none() && c.grpc_values.is_none() {
        c.upstream = p.upstream.clone();
        c.host = p.host.clone();

        c.grpc_values = p.grpc_values.clone();

        c.ssl = p.ssl;
    }

    if lmt_excpt && !has_handler && (c.upstream.is_some() || c.grpc_values.is_some()) {
        clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(grpc_handler(r))));
    }

    crate::upstream_ssl::merge_ptr(&mut c.headers_source, &p.headers_source);

    let same_source = same_headers_source(&c.headers_source, &p.headers_source);

    if same_source {
        c.headers = p.headers.clone();
        c.host_value = p.host_value.clone();
    }

    init_headers(cf, &mut c, GRPC_HEADERS)?;

    // special handling to preserve conf->headers in the "http" section to
    // inherit it to all servers

    if p.headers.is_none() && same_source {
        p.headers = c.headers.clone();
        p.host_value = c.host_value.clone();
    }

    c.upstream_conf = Some(Rc::new(upstream_conf(&c)));

    Ok(())
}

/// glcf->upstream, the ngx_http_upstream_conf_t of the location, as merged
fn upstream_conf(c: &NgxHttpGrpcLocConf) -> UpstreamConf {
    UpstreamConf {
        upstream: c.upstream.clone(),
        connect_timeout: *c.connect_timeout,
        send_timeout: *c.send_timeout,
        read_timeout: *c.read_timeout,
        next_upstream_timeout: *c.next_upstream_timeout,
        send_lowat: 0,
        buffer_size: *c.buffer_size,
        limit_rate: None,
        busy_buffers_size: 0,
        max_temp_file_size: 0,
        temp_file_write_size: 0,
        bufs: Bufs::default(),
        next_upstream: c.next_upstream,
        store_access: 0,
        next_upstream_tries: *c.next_upstream_tries as u32,
        buffering: false,
        request_buffering: true,
        pass_request_headers: true,
        pass_request_body: true,
        pass_trailers: true,
        pass_early_hints: true,
        ignore_client_abort: false,
        intercept_errors: *c.intercept_errors,
        cyclic_temp_file: false,
        force_ranges: false,
        temp_path: None,
        hide_headers_hash: c.hide_headers_hash.clone(),
        local: c.local.as_option().cloned().flatten(),
        socket_keepalive: *c.socket_keepalive,
        socket_rcvbuf: *c.socket_rcvbuf,
        socket_sndbuf: *c.socket_sndbuf,
        cache: c.cache.clone(),
        store: false,
        store_values: None,
        intercept_404: false,
        change_buffering: false,
        preserve_output: true,
        ignore_input: false,
        ssl: c.upstream_ssl.clone(),
        module: "grpc",
    }
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

/// ngx_http_grpc_init_headers: the headers of grpc_set_header (all but
/// Host, whose value becomes conf->host_value), then the defaults the
/// configuration does not set; the names go to the hash, the headers with
/// a value are compiled.
fn init_headers(cf: &mut Conf, conf: &mut NgxHttpGrpcLocConf, default_headers: &[(&[u8], &[u8])]) -> ConfResult {
    if conf.headers.is_some() {
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
        headers_names.push(HashKey { key: key.to_ascii_lowercase(), key_hash: hash_key_lc(&key), value: () });

        if value.is_empty() {
            continue;
        }

        let codes = crate::script::script_compile(cf, &value)?;

        flushes.extend(crate::proxy::script_flushes(&codes));

        lines.push((key, codes));
    }

    let hinit = HashInit { name: "grpc_headers_hash", max_size: 512, bucket_size: 64, log: &cf.log };

    let hash = match Hash::init(&hinit, headers_names) {
        Ok(h) => h,
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
            return Err(ConfError::Logged);
        }
    };

    conf.headers = Some(Rc::new(GrpcHeaders { flushes, lines, hash }));

    Ok(())
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

/// ngx_http_upstream_hide_headers_hash: the default hide headers and those
/// of grpc_hide_header, but those of grpc_pass_header; inherited as a
/// whole when the level has neither directive.
fn hide_headers_hash(cf: &mut Conf, conf: &mut NgxHttpGrpcLocConf, prev: &mut NgxHttpGrpcLocConf, default_hide_headers: &[&[u8]]) -> ConfResult {
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

    let names: Vec<HashKey<()>> = crate::upstream_rt::hide_headers_names(default_hide_headers, hide, pass)
        .into_iter()
        .map(|k| HashKey { key_hash: hash_key_lc(&k), key: k.to_ascii_lowercase(), value: () })
        .collect();

    let hinit = HashInit { name: "grpc_headers_hash", max_size: 512, bucket_size: 64, log: &cf.log };

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

/// ngx_http_grpc_merge_ssl: the context of the parent level when the level
/// has no SSL directive, else a new one.
fn grpc_merge_ssl(cf: &mut Conf, conf: &mut NgxHttpGrpcLocConf, prev: &mut NgxHttpGrpcLocConf) {
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

/// ngx_http_grpc_set_ssl: the context of the upstream connections, with the
/// "h2" ALPN protocol
fn grpc_set_ssl(cf: &mut Conf, glcf: &mut NgxHttpGrpcLocConf) -> ConfResult {
    let ssl = glcf.upstream_ssl.ssl.clone().expect("ssl");
    let mut ssl = ssl.borrow_mut();

    if !ssl.ctx.is_null() {
        return Ok(());
    }

    if ngx_ssl_create(&mut ssl, glcf.ssl_protocols, std::ptr::null_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    // the context is freed with the ngx_ssl_t (ngx_ssl_cleanup_ctx)

    let ciphers = glcf.ssl_ciphers.get().clone();

    if ngx_ssl_ciphers(cf, &mut ssl, &ciphers, false) != NGX_OK {
        return Err(ConfError::Logged);
    }

    let u = &glcf.upstream_ssl;

    if let Some(cert) = u.ssl_certificate.as_option().cloned().flatten() {
        if !cert.value.is_empty() {
            let key = match u.ssl_certificate_key.as_option().cloned().flatten() {
                Some(k) => k,
                None => {
                    ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"grpc_ssl_certificate_key\" is defined for certificate \"{}\"", B(&cert.value));
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
        if glcf.ssl_trusted_certificate.get().is_empty() {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no grpc_ssl_trusted_certificate for grpc_ssl_verify");
            return Err(ConfError::Logged);
        }

        let mut trusted = glcf.ssl_trusted_certificate.get().clone();

        if ngx_ssl_trusted_certificate(cf, &mut ssl, &mut trusted, *glcf.ssl_verify_depth) != NGX_OK {
            return Err(ConfError::Logged);
        }

        let mut crl = glcf.ssl_crl.get().clone();

        if ngx_ssl_crl(cf, &mut ssl, &mut crl) != NGX_OK {
            return Err(ConfError::Logged);
        }
    }

    if ngx_ssl_client_session_cache(cf, &mut ssl, *u.ssl_session_reuse) != NGX_OK {
        return Err(ConfError::Logged);
    }

    // TLSEXT_TYPE_application_layer_protocol_negotiation

    // SAFETY: the context was created above; the protocol list is copied
    // by OpenSSL
    if unsafe { openssl_sys::SSL_CTX_set_alpn_protos(ssl.ctx, NGX_HTTP_V2_ALPN_PROTO.as_ptr(), NGX_HTTP_V2_ALPN_PROTO.len() as u32) } != 0 {
        ngx_core::event_openssl::ngx_ssl_error(NGX_LOG_EMERG, &cf.log, 0, format_args!("SSL_CTX_set_alpn_protos() failed"));
        return Err(ConfError::Logged);
    }

    let mut commands = glcf.ssl_conf_commands.as_option().cloned().flatten();

    if ngx_ssl_conf_commands(cf, &mut ssl, commands.as_mut()) != NGX_OK {
        return Err(ConfError::Logged);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// the directives
// ---------------------------------------------------------------------------

fn glcf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<NgxHttpGrpcLocConf>> {
    conf_rc::<NgxHttpGrpcLocConf>(conf.as_ref().expect("conf"))
}

/// ngx_http_grpc_pass
fn grpc_pass(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);

    {
        let glcf = cell.borrow();

        if glcf.upstream.is_some() || glcf.grpc_values.is_some() {
            return Err(msg("is duplicate"));
        }
    }

    let clcf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());

    {
        let mut lc = clcf.borrow_mut();

        lc.handler = Some(Rc::new(|r| Box::pin(grpc_handler(r))));

        if lc.name.last() == Some(&b'/') {
            lc.auto_redirect = true;
        }
    }

    let url = cf.args[1].clone();

    let n = crate::script::script_variables_count(&url);

    if n != 0 {
        let codes = crate::script::script_compile(cf, &url)?;

        let mut glcf = cell.borrow_mut();

        glcf.grpc_values = Some(Rc::new(codes));
        glcf.ssl = true;

        return Ok(());
    }

    let add = if url.len() >= 7 && url[..7].eq_ignore_ascii_case(b"grpc://") {
        7
    } else if url.len() >= 8 && url[..8].eq_ignore_ascii_case(b"grpcs://") {
        cell.borrow_mut().ssl = true;
        8
    } else {
        0
    };

    let mut u = Url::new(&url[add..]);
    u.no_resolve = true;

    let uscf = upstream_add(cf, &mut u, 0)?;

    let mut glcf = cell.borrow_mut();

    glcf.upstream = Some(uscf);

    glcf.host = authority(&u);

    Ok(())
}

/// ngx_http_grpc_ssl_certificate_cache
fn grpc_ssl_certificate_cache(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);

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
        // "off": the certificate cache is NULL
        return Ok(());
    }

    if max == 0 {
        return Err(cf.emerg(format_args!("\"grpc_ssl_certificate_cache\" must have the \"max\" parameter")));
    }

    let cache = ngx_core::event_openssl_cache::ngx_ssl_cache_init(max as usize, valid, inactive);

    cell.borrow_mut().upstream_ssl.ssl_certificate_cache = Val::set(Some(Rc::new(RefCell::new(cache))));

    Ok(())
}

/// ngx_http_grpc_ssl_password_file
fn grpc_ssl_password_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);

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

/// grpc_ssl_conf_command: ngx_conf_set_keyval_slot with
/// ngx_http_grpc_ssl_conf_command_check (SSL_CONF_FLAG_FILE is defined:
/// NGX_CONF_OK)
fn grpc_ssl_conf_command(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);
    let mut c = cell.borrow_mut();

    if !c.ssl_conf_commands.is_set() {
        c.ssl_conf_commands = Val::set(Some(Vec::new()));
    }

    c.ssl_conf_commands.0.as_mut().unwrap().as_mut().unwrap().push((cf.args[1].clone(), cf.args[2].clone()));

    Ok(())
}

/// grpc_set_header: ngx_conf_set_keyval_slot
fn grpc_set_header(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);
    let mut c = cell.borrow_mut();

    let mut list: Vec<(Vec<u8>, Vec<u8>)> = match c.headers_source.as_option() {
        Some(Some(l)) => l.as_ref().clone(),
        _ => Vec::new(),
    };

    list.push((cf.args[1].clone(), cf.args[2].clone()));

    c.headers_source = Val::set(Some(Rc::new(list)));

    Ok(())
}

/// grpc_pass_header, grpc_hide_header: ngx_conf_set_str_array_slot
fn grpc_str_array(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);
    let mut c = cell.borrow_mut();

    let slot = if cmd.name == "grpc_pass_header" { &mut c.pass_headers } else { &mut c.hide_headers };

    let mut list: Vec<Vec<u8>> = match slot.as_option() {
        Some(l) => l.as_ref().clone(),
        None => Vec::new(),
    };

    list.push(cf.args[1].clone());

    *slot = Val::set(Rc::new(list));

    Ok(())
}

/// grpc_bind: ngx_http_upstream_bind_set_slot
fn grpc_bind(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);

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
            local.transparent = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    cell.borrow_mut().local = Val::set(Some(Rc::new(local)));

    Ok(())
}

/// grpc_ssl_protocols, grpc_next_upstream: ngx_conf_set_bitmask_slot
fn grpc_bitmask(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);
    let mut c = cell.borrow_mut();

    if cmd.name == "grpc_ssl_protocols" {
        set_bitmask(cf, cmd, &mut c.ssl_protocols, GRPC_SSL_PROTOCOLS)
    } else {
        set_bitmask(cf, cmd, &mut c.next_upstream, GRPC_NEXT_UPSTREAM_MASKS)
    }
}

/// grpc_ssl_session_reuse, grpc_ssl_server_name, grpc_ssl_verify:
/// ngx_conf_set_flag_slot
fn grpc_ssl_flag(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);
    let mut c = cell.borrow_mut();

    let slot = match cmd.name {
        "grpc_ssl_session_reuse" => &mut c.upstream_ssl.ssl_session_reuse,
        "grpc_ssl_server_name" => &mut c.upstream_ssl.ssl_server_name,
        _ => &mut c.upstream_ssl.ssl_verify,
    };

    set_flag(cf, cmd, slot)
}

/// grpc_ssl_name: ngx_http_set_complex_value_slot; grpc_ssl_certificate,
/// grpc_ssl_certificate_key: ngx_http_set_complex_value_zero_slot
fn grpc_complex_value(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = glcf_of(&conf);

    let mut slot = {
        let c = cell.borrow();

        match cmd.name {
            "grpc_ssl_name" => c.upstream_ssl.ssl_name.clone(),
            "grpc_ssl_certificate" => c.upstream_ssl.ssl_certificate.clone(),
            _ => c.upstream_ssl.ssl_certificate_key.clone(),
        }
    };

    match cmd.name {
        "grpc_ssl_name" => crate::script::set_complex_value_slot(cf, cmd, &mut slot)?,
        _ => crate::script::set_complex_value_zero_slot(cf, cmd, &mut slot)?,
    }

    let mut c = cell.borrow_mut();

    match cmd.name {
        "grpc_ssl_name" => c.upstream_ssl.ssl_name = slot,
        "grpc_ssl_certificate" => c.upstream_ssl.ssl_certificate = slot,
        _ => c.upstream_ssl.ssl_certificate_key = slot,
    }

    Ok(())
}

pub fn grpc_module() -> ModuleDef {
    use crate::upstream_cache as uc;
    use ngx_core::cmd;

    type C = NgxHttpGrpcLocConf;

    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd_fn!("grpc_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, grpc_pass),
        cmd_fn!("grpc_bind", F | NGX_CONF_TAKE12, ConfLevel::Loc, grpc_bind),
        cmd!("grpc_socket_keepalive", F | NGX_CONF_FLAG, ConfLevel::Loc, C, socket_keepalive, set_flag),
        cmd!("grpc_socket_rcvbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_rcvbuf, set_size),
        cmd!("grpc_socket_sndbuf", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, socket_sndbuf, set_size),
        cmd!("grpc_connect_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, connect_timeout, set_msec),
        cmd!("grpc_send_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, send_timeout, set_msec),
        cmd!("grpc_intercept_errors", F | NGX_CONF_FLAG, ConfLevel::Loc, C, intercept_errors, set_flag),
        cmd!("grpc_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, buffer_size, set_size),
        cmd!("grpc_read_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, read_timeout, set_msec),
        cmd_fn!("grpc_next_upstream", F | NGX_CONF_1MORE, ConfLevel::Loc, grpc_bitmask),
        cmd!("grpc_next_upstream_tries", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_tries, set_num),
        cmd!("grpc_next_upstream_timeout", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, next_upstream_timeout, set_msec),
        cmd_fn!("grpc_set_header", F | NGX_CONF_TAKE2, ConfLevel::Loc, grpc_set_header),
        cmd_fn!("grpc_pass_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, grpc_str_array),
        cmd_fn!("grpc_hide_header", F | NGX_CONF_TAKE1, ConfLevel::Loc, grpc_str_array),
        cmd_fn!("grpc_ignore_headers", F | NGX_CONF_1MORE, ConfLevel::Loc, uc::ignore_headers_slot::<C>),
        cmd_fn!("grpc_ssl_session_reuse", F | NGX_CONF_FLAG, ConfLevel::Loc, grpc_ssl_flag),
        cmd_fn!("grpc_ssl_protocols", F | NGX_CONF_1MORE, ConfLevel::Loc, grpc_bitmask),
        cmd!("grpc_ssl_ciphers", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, ssl_ciphers, set_str),
        cmd_fn!("grpc_ssl_name", F | NGX_CONF_TAKE1, ConfLevel::Loc, grpc_complex_value),
        cmd_fn!("grpc_ssl_server_name", F | NGX_CONF_FLAG, ConfLevel::Loc, grpc_ssl_flag),
        cmd_fn!("grpc_ssl_verify", F | NGX_CONF_FLAG, ConfLevel::Loc, grpc_ssl_flag),
        cmd!("grpc_ssl_verify_depth", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, ssl_verify_depth, set_num),
        cmd!("grpc_ssl_trusted_certificate", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, ssl_trusted_certificate, set_str),
        cmd!("grpc_ssl_crl", F | NGX_CONF_TAKE1, ConfLevel::Loc, C, ssl_crl, set_str),
        cmd_fn!("grpc_ssl_certificate", F | NGX_CONF_TAKE1, ConfLevel::Loc, grpc_complex_value),
        cmd_fn!("grpc_ssl_certificate_key", F | NGX_CONF_TAKE1, ConfLevel::Loc, grpc_complex_value),
        cmd_fn!("grpc_ssl_certificate_cache", F | NGX_CONF_TAKE123, ConfLevel::Loc, grpc_ssl_certificate_cache),
        cmd_fn!("grpc_ssl_password_file", F | NGX_CONF_TAKE1, ConfLevel::Loc, grpc_ssl_password_file),
        cmd_fn!("grpc_ssl_conf_command", F | NGX_CONF_TAKE2, ConfLevel::Loc, grpc_ssl_conf_command),
    ];

    let def = HttpModuleDef {
        preconfiguration: Some(grpc_add_variables),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_grpc_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority() {
        let parsed = |s: &[u8]| {
            let mut u = Url::new(s);
            u.no_resolve = true;
            ngx_core::inet::parse_url(&mut u).expect("url");
            authority(&u)
        };

        assert_eq!(parsed(b"127.0.0.1:8081"), b"127.0.0.1:8081");
        assert_eq!(parsed(b"[::1]:8081"), b"[::1]:8081");
        assert_eq!(parsed(b"backend"), b"backend");
        assert_eq!(parsed(b"unix:/tmp/grpc.sock"), b"localhost");
    }
}
