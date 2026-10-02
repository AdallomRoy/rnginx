//! ngx_http_proxy_v2_module: "proxy_http_version 2". The request goes to the
//! upstream as an HTTP/2 stream (the client of crate::upstream_h2) with the
//! configuration, the variables and the cache key of the proxy module, the
//! request body as DATA frames as the flow control windows let it go, and
//! the response header and body parsed out of the frames: the body buffered
//! through the event pipe (ngx_http_proxy_v2_body_filter) or not
//! (ngx_http_proxy_v2_non_buffered_filter), the trailers kept. A response
//! from the cache has the frames of its header parsed again.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::hash::hash_key;
use ngx_core::log::*;
use ngx_core::ngx_log_error;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::event_pipe::{EventPipe, RawBuf};
use crate::proxy::{NgxHttpProxyLocConf, ProxyCtx};
use crate::request::*;
use crate::upstream_cache::{NGX_HTTP_UPSTREAM_EARLY_HINTS, NGX_HTTP_UPSTREAM_INVALID_HEADER};
use crate::upstream_h2::*;
use crate::upstream_rt::{Upstream, UpstreamModule};
use crate::v2::encode::{inc_indexed, indexed, write_name, write_value};
use crate::v2::*;
use crate::*;

/// The tag of the module's buffers
/// (ngx_http_proxy_v2_body_output_filter as the tag)
const PROXY_V2_TAG: usize = 0x7078_7632;

/// The context of the module for a request: ngx_http_proxy_v2_ctx_t (the
/// context of the proxy module, which the variables see, and the stream)
/// with the location's configuration.
struct ProxyV2Module {
    lcf: Rc<RefCell<NgxHttpProxyLocConf>>,
    /// ctx->ctx
    pctx: Rc<RefCell<ProxyCtx>>,
    ctx: H2Ctx,
}

/// ngx_http_proxy_v2_handler
pub async fn proxy_v2_handler(r: R) -> i64 {
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(crate::proxy::ctx_index());

    // plcf->upstream.preserve_output is set by the merge of
    // "proxy_http_version 2"

    let conf = match lcf.borrow().upstream_conf.clone() {
        Some(c) => c,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let caches = {
        let pmcf = r.main_conf::<crate::upstream_cache::UpstreamCacheMainConf>(crate::proxy::ctx_index());
        let caches = pmcf.borrow().caches.clone();
        caches
    };

    // ngx_http_upstream_create

    let mut u = Upstream::create(&r, conf, caches, b"");

    let proxy_values = lcf.borrow().proxy_values.clone();

    let pctx = match proxy_values {
        None => {
            let plcf = lcf.borrow();
            let pctx = r.set_ctx(crate::proxy::ctx_index(), ProxyCtx::new(plcf.vars.clone()));
            u.set_schema(&plcf.vars.schema);
            u.ssl = plcf.ssl;
            pctx
        }

        Some(codes) => {
            let pctx = r.set_ctx(crate::proxy::ctx_index(), ProxyCtx::new(crate::proxy::no_vars()));

            if crate::proxy::proxy_eval(&r, &pctx, &codes, &mut u) != NGX_OK {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            pctx
        }
    };

    // NGX_HTTP_V2_ALPN_PROTO
    u.ssl_alpn = b"\x02h2".to_vec();

    {
        let plcf = lcf.borrow();

        if !plcf.request_buffering.get_or(true) && plcf.body_values.is_none() && plcf.pass_request_body.get_or(true) {
            r.request_body_no_buffering.set(true);
        }
    }

    // ngx_http_read_client_request_body(r, ngx_http_upstream_init)

    let rc = crate::request_body::read_client_request_body(&r).await;

    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    let mut m = ProxyV2Module { lcf, pctx, ctx: H2Ctx::new("http proxy", PROXY_V2_TAG) };

    crate::upstream_rt::init(r, u, &mut m).await
}

impl ProxyV2Module {
    /// ngx_http_proxy_v2_get_ctx and ngx_http_proxy_v2_get_connection_data:
    /// the HTTP/2 state of the connection, found once per request (a new
    /// one for a response from the cache, stream 0)
    fn get_ctx(&mut self, r: &R, u: &mut Upstream) -> Result<(), ()> {
        if self.ctx.connection.is_some() {
            return Ok(());
        }

        let ctx = &mut self.ctx;

        let conn = if r.cached.get() {
            ctx.id = 0;

            Rc::new(RefCell::new(H2Conn { init_window: 0, send_window: 0, recv_window: 0, last_stream_id: 0, tag: PROXY_V2_TAG }))
        } else if u.peer_cached {
            // for cached connections, connection data can be found in the
            // cleanup handler

            let conn = u.conn_data.clone().and_then(|d| d.downcast::<RefCell<H2Conn>>().ok()).filter(|c| c.borrow().tag == PROXY_V2_TAG);

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
        } else {
            let conn = Rc::new(RefCell::new(H2Conn { init_window: 0, send_window: 0, recv_window: 0, last_stream_id: 0, tag: PROXY_V2_TAG }));

            let data: Rc<dyn Any> = conn.clone();
            u.conn_data = Some(data);

            ctx.id = 1;

            conn
        };

        // done:

        {
            let mut c = conn.borrow_mut();

            c.init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
            c.send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
            c.recv_window = NGX_HTTP_V2_MAX_WINDOW;

            c.last_stream_id = 1;
        }

        ctx.send_window = NGX_HTTP_V2_DEFAULT_WINDOW as isize;
        ctx.recv_window = NGX_HTTP_V2_MAX_WINDOW;

        ctx.connection = Some(conn);

        Ok(())
    }
}

impl UpstreamModule for ProxyV2Module {
    /// ngx_http_proxy_create_key
    fn create_key(&self, r: &R, keys: &mut Vec<Vec<u8>>) -> i64 {
        crate::proxy::create_key(r, keys)
    }

    fn create_keys(&self, r: &R, keys: &mut crate::file_cache::CacheKeys) -> i64 {
        crate::proxy::create_keys(r, keys)
    }

    /// ngx_http_proxy_v2_create_request
    fn create_request(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let plcf = self.lcf.borrow();

        let u_method: Option<&'static [u8]> = *u.ucache.method.borrow();

        let (header, headers_frame, body) = match create_request(r, &plcf, &self.pctx, u.cacheable(), u.ssl, u_method) {
            Ok(x) => x,
            Err(()) => return NGX_ERROR,
        };

        let mut hb = Buf::from_vec(header);

        let mut bufs = Chain::new();

        let end_stream = |hb: &mut Buf| {
            // f->flags |= NGX_HTTP_V2_END_STREAM_FLAG
            if let BufData::Memory(v) = &mut hb.data {
                v[headers_frame + 4] |= NGX_HTTP_V2_END_STREAM_FLAG;
            }
        };

        if r.request_body_no_buffering.get() {
            bufs.push_back(hb);
        } else if plcf.body_values.is_none() && plcf.pass_request_body.get_or(true) {
            let body = crate::upstream_rt::request_body_bufs(r);

            if body.is_empty() {
                end_stream(&mut hb);
            }

            bufs.push_back(hb);

            bufs.extend(body);

            bufs.back_mut().expect("buffer").last_buf = true;
        } else if let Some(body) = body {
            bufs.push_back(hb);

            let mut b = Buf::from_vec(body);
            b.last_buf = true;
            bufs.push_back(b);
        } else {
            end_stream(&mut hb);

            hb.last_buf = true;
            bufs.push_back(hb);
        }

        bufs.back_mut().expect("buffer").flush = true;

        u.request_bufs = bufs;

        NGX_OK
    }

    /// ngx_http_proxy_v2_reinit_request
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

    /// ngx_http_proxy_v2_process_header
    fn process_header(&mut self, r: &R, u: &mut Upstream) -> i64 {
        let buf = std::mem::take(&mut u.resp.buf);
        let start = u.resp.pos.min(buf.len());
        let mut pos = start;

        http_debug!(r, "http proxy response: {}, len: {}", hex_head(&buf[pos..]), buf.len() - pos);

        if self.get_ctx(r, u).is_err() {
            u.resp.buf = buf;
            return NGX_ERROR;
        }

        let mut reset = false;

        let rc = self.process_header_frames(r, u, &buf, &mut pos, &mut reset);

        if reset {
            // there can be a lot of window update frames, so we reset
            // buffer if it is empty and we haven't started parsing headers
            // yet
            let mut buf = buf;
            buf.truncate(start);
            u.resp.buf = buf;
            u.resp.pos = start;
        } else {
            u.resp.buf = buf;
            u.resp.pos = pos;
        }

        rc
    }

    /// ngx_http_proxy_v2_filter_init
    fn input_filter_init(&mut self, r: &R, u: &mut Upstream, p: Option<&mut EventPipe>) -> i64 {
        let ctx = &mut self.ctx;

        let status = u.resp.status_n;

        if status == NGX_HTTP_NO_CONTENT || status == NGX_HTTP_NOT_MODIFIED || self.pctx.borrow().head {
            ctx.length = 0;
        } else {
            ctx.length = u.resp.content_length_n;
        }

        let length = if ctx.end_stream {
            if ctx.length > 0 {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed stream");
                return NGX_ERROR;
            }

            ctx.done = true;

            0
        } else {
            1
        };

        u.length = length;

        if let Some(p) = p {
            p.length = length;
        }

        NGX_OK
    }

    /// ngx_http_proxy_v2_non_buffered_filter
    fn input_filter(&mut self, r: &R, u: &mut Upstream, data: &[u8]) -> i64 {
        http_debug!(r, "http proxy filter bytes:{}", data.len());

        if self.ctx.connection.is_none() {
            return NGX_ERROR;
        }

        let mut pos = 0;

        loop {
            let rc = self.process_frames(r, u, data, &mut pos);

            if rc == NGX_OK {
                let len = self.payload(data.len() - pos);

                let mut b = Buf::from_vec(data[pos..pos + len].to_vec());
                b.flush = true;
                b.memory = true;
                b.tag = PROXY_V2_TAG;

                pos += len;

                http_debug!(r, "http proxy output buf {}", len);

                if self.ctx.length != -1 {
                    if len as i64 > self.ctx.length {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent response body larger than indicated content length");
                        return NGX_ERROR;
                    }

                    self.ctx.length -= len as i64;
                }

                u.out_bufs.push_back(b);

                continue;
            }

            if rc == NGX_DONE {
                u.length = 0;
                break;
            }

            if rc == NGX_AGAIN {
                return NGX_AGAIN;
            }

            // invalid response

            return NGX_ERROR;
        }

        NGX_OK
    }

    /// ngx_http_proxy_v2_body_filter: the DATA payloads of a raw buffer to
    /// p->in
    fn pipe_input_filter(&mut self, r: &R, u: &mut Upstream, p: &mut EventPipe, raw: RawBuf) -> i64 {
        if raw.is_empty() {
            p.release_raw_buf(raw);
            return NGX_OK;
        }

        if self.ctx.connection.is_none() {
            return NGX_ERROR;
        }

        http_debug!(r, "http proxy filter bytes:{}", raw.len());

        let data = raw.bytes();
        let mut pos = 0;
        let mut copied = false;

        loop {
            let rc = self.process_frames(r, u, data, &mut pos);

            if rc == NGX_OK {
                // copy data frame payload for buffering

                let len = self.payload(data.len() - pos);

                let mut b = Buf::from_vec(data[pos..pos + len].to_vec());
                b.tag = PROXY_V2_TAG;

                pos += len;

                http_debug!(r, "http proxy copy buf {}", len);

                if self.ctx.length != -1 {
                    if len as i64 > self.ctx.length {
                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent response body larger than indicated content length");
                        return NGX_ERROR;
                    }

                    self.ctx.length -= len as i64;
                }

                p.push_in(b, raw.slot);
                copied = true;

                continue;
            }

            if rc == NGX_DONE {
                p.length = 0;
                break;
            }

            if rc == NGX_AGAIN {
                break;
            }

            // invalid response

            return NGX_ERROR;
        }

        // the payloads were copied: the memory of the raw buffer is kept for
        // its next use
        if copied {
            ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_EVENT, r.connection.log, "input buf #{}", raw.slot);
            p.recycle(raw);
            return NGX_OK;
        }

        // there is no data record in the buf, add it to free chain

        p.release_raw_buf(raw);

        NGX_OK
    }

    /// ngx_http_proxy_v2_finalize_request
    fn finalize_request(&mut self, r: &R, _u: &mut Upstream, _rc: i64) {
        http_debug!(r, "finalize proxy http2 request");
    }

    /// ngx_http_proxy_v2_body_output_filter
    fn output_filter(&mut self, r: &R, u: &mut Upstream, input: Option<Chain>) -> i64 {
        http_debug!(r, "http proxy output filter");

        if self.get_ctx(r, u).is_err() {
            return NGX_ERROR;
        }

        if let Some(input) = input {
            self.ctx.input.extend(input);
        }

        let mut out = Chain::new();

        if !self.ctx.header_sent {
            // first buffer contains headers

            http_debug!(r, "http proxy output header");

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
                "http proxy output out l:{} f:{} size: {} file: {}, size: {}",
                b.last_buf as i32,
                b.in_file as i32,
                if b.in_memory() { b.last - b.pos } else { 0 },
                b.file_pos,
                b.file_last - b.file_pos
            );
        }

        http_debug!(r, "http proxy output limit: {} w:{}:{}", limit, self.ctx.send_window, self.ctx.conn().send_window);

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

            // u->length and u->pipe->length
            u.length = 0;

            let ctx = &self.ctx;

            if ctx.input.is_empty() && ctx.out.is_empty() && ctx.output_closed && !ctx.output_blocked && !ctx.goaway && ctx.state == ST_START {
                u.keepalive = true;
            }

            u.post_read = true;
        }

        rc
    }

    fn has_rewrite_redirect(&self) -> bool {
        self.lcf.borrow().redirects.is_some()
    }

    /// ngx_http_proxy_rewrite_redirect
    fn rewrite_redirect(&mut self, r: &R, h: &Header, prefix: usize) -> i64 {
        crate::proxy::rewrite_redirect(r, &self.lcf, h, prefix)
    }

    fn has_rewrite_cookie(&self) -> bool {
        crate::proxy::has_rewrite_cookie(&self.lcf.borrow())
    }

    /// ngx_http_proxy_rewrite_cookie
    fn rewrite_cookie(&mut self, r: &R, h: &Header) -> i64 {
        crate::proxy::rewrite_cookie(r, &self.lcf, h)
    }
}

/// ngx_http_proxy_v2_create_request: the connection preface, the HEADERS
/// frame of the request (and the CONTINUATION frames the header block
/// needs), and the body of proxy_set_body. Returns the header buffer, the
/// offset of the HEADERS frame in it and the body.
fn create_request(r: &R, plcf: &NgxHttpProxyLocConf, pctx: &Rc<RefCell<ProxyCtx>>, cacheable: bool, ssl: bool, u_method: Option<&[u8]>) -> Result<(Vec<u8>, usize, Option<Vec<u8>>), ()> {
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

    if method.len() == 4 && method.eq_ignore_ascii_case(b"HEAD") {
        pctx.borrow_mut().head = true;
    }

    // :method header

    if method.as_slice() != b"GET" && method.as_slice() != b"POST" && method.len() > NGX_HTTP_V2_MAX_FIELD {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 method: \"{}\"", B(&method));
        return Err(());
    }

    // :path header

    let vars_uri = pctx.borrow().vars.uri.clone();

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
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "zero length URI to proxy");
        return Err(());
    }

    if uri_len > NGX_HTTP_V2_MAX_FIELD {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 URI");
        return Err(());
    }

    // :authority header

    let mut host: Vec<u8> = Vec::new();

    if let Some(hv) = &plcf.host_value {
        host = crate::script::complex_value(r, hv).map_err(|_| ())?;
    }

    if host.is_empty() {
        host = pctx.borrow().vars.host_header.clone();
    }

    if host.len() > NGX_HTTP_V2_MAX_FIELD {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too long http2 host: \"{}\"", B(&host));
        return Err(());
    }

    // other headers

    crate::script::script_flush_no_cacheable_variables(r, Some(&plcf.body_flushes));
    crate::script::script_flush_no_cacheable_variables(r, Some(&headers.flushes));

    let mut body: Option<Vec<u8>> = None;

    if let Some(codes) = &plcf.body_values {
        let b = crate::proxy::run_codes(r, codes);
        pctx.borrow_mut().internal_body_length = b.len() as i64;
        body = Some(b);
    } else if r.headers_in.borrow().chunked && r.reading_body.get() {
        pctx.borrow_mut().internal_body_length = -1;
    } else {
        pctx.borrow_mut().internal_body_length = r.headers_in.borrow().content_length_n;
    }

    let mut lines: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

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

        lines.push((key.clone(), value));
    }

    let mut request_headers: Vec<Header> = Vec::new();

    if plcf.pass_request_headers.get_or(true) {
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

    if method.as_slice() == b"GET" {
        b.push(indexed(NGX_HTTP_V2_METHOD_GET_INDEX));

        http_debug!(r, "http proxy header: \":method: GET\"");
    } else if method.as_slice() == b"POST" {
        b.push(indexed(NGX_HTTP_V2_METHOD_POST_INDEX));

        http_debug!(r, "http proxy header: \":method: POST\"");
    } else {
        b.push(inc_indexed(NGX_HTTP_V2_METHOD_INDEX));
        write_value(&mut b, &method);

        http_debug!(r, "http proxy header: \":method: {}\"", B(&method));
    }

    if ssl {
        b.push(indexed(NGX_HTTP_V2_SCHEME_HTTPS_INDEX));

        http_debug!(r, "http proxy header: \":scheme: https\"");
    } else {
        b.push(indexed(NGX_HTTP_V2_SCHEME_HTTP_INDEX));

        http_debug!(r, "http proxy header: \":scheme: http\"");
    }

    if plcf.proxy_values.is_some() && !vars_uri.is_empty() {
        b.push(inc_indexed(NGX_HTTP_V2_PATH_INDEX));
        write_value(&mut b, &vars_uri);

        http_debug!(r, "http proxy header: \":path: {}\"", B(&vars_uri));
    } else if unparsed_uri {
        let unparsed = r.unparsed_uri.borrow();

        if unparsed.as_slice() == b"/" {
            b.push(indexed(NGX_HTTP_V2_PATH_ROOT_INDEX));
        } else {
            b.push(inc_indexed(NGX_HTTP_V2_PATH_INDEX));
            write_value(&mut b, &unparsed);
        }

        http_debug!(r, "http proxy header: \":path: {}\"", B(&unparsed));
    } else {
        let mut p: Vec<u8> = Vec::with_capacity(uri_len);

        if r.valid_location.get() {
            p.extend_from_slice(&vars_uri);
        }

        {
            let r_uri = r.uri.borrow();

            if escape {
                ngx_core::string::escape_uri_into(&mut p, &r_uri[loc_len..], ngx_core::string::NGX_ESCAPE_URI);
            } else {
                p.extend_from_slice(&r_uri[loc_len..]);
            }
        }

        let args = r.args.borrow();

        if !args.is_empty() {
            p.push(b'?');
            p.extend_from_slice(&args);
        }

        b.push(inc_indexed(NGX_HTTP_V2_PATH_INDEX));
        write_value(&mut b, &p);

        http_debug!(r, "http proxy header: \":path: {}\"", B(&p));
    }

    b.push(inc_indexed(NGX_HTTP_V2_AUTHORITY_INDEX));
    write_value(&mut b, &host);

    http_debug!(r, "http proxy header: \":authority: {}\"", B(&host));

    for (key, value) in lines.iter() {
        b.push(0);

        write_name(&mut b, key);
        write_value(&mut b, value);

        http_debug!(r, "http proxy header: \"{}: {}\"", B(&key.to_ascii_lowercase()), B(value));
    }

    for h in request_headers.iter() {
        let value = h.value.borrow();

        b.push(0);

        write_name(&mut b, &h.key);
        write_value(&mut b, &value);

        http_debug!(r, "http proxy header: \"{}: {}\"", B(&h.key.to_ascii_lowercase()), B(&value));
    }

    // update headers frame length, and create additional continuation
    // frames

    header_frames(&mut b, headers_frame);

    http_debug!(r, "http proxy header: {}, len: {}", hex_head(&b), b.len());

    Ok((b, headers_frame, body.filter(|b| !b.is_empty())))
}

impl ProxyV2Module {
    /// The loop of ngx_http_proxy_v2_process_header over the frames of the
    /// buffer.
    fn process_header_frames(&mut self, r: &R, u: &mut Upstream, buf: &[u8], pos: &mut usize, reset: &mut bool) -> i64 {
        let cached = r.cached.get();

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

                if ctx.id != 0 && ctx.stream_id != 0 && ctx.stream_id != ctx.id {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent frame for unknown stream {}", ctx.stream_id);
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }
            }

            // frame payload

            if !cached {
                if self.ctx.ty == NGX_HTTP_V2_RST_STREAM_FRAME {
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

                let rc = self.process_control_frame(r, u, buf, pos);

                if rc == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                if rc == NGX_ERROR {
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                if rc == NGX_OK {
                    continue;
                }
            }

            let ty = self.ctx.ty;

            if ty != NGX_HTTP_V2_HEADERS_FRAME && ty != NGX_HTTP_V2_CONTINUATION_FRAME {
                // priority, unknown frames

                if self.skip_frame(buf, pos) == NGX_AGAIN {
                    return NGX_AGAIN;
                }

                continue;
            }

            // headers

            loop {
                let rc = self.ctx.parse_header(&r.connection.log, u.conf.buffer_size, buf, pos);

                if rc == NGX_AGAIN {
                    break;
                }

                if rc == NGX_OK {
                    // a header line has been parsed successfully

                    let name = std::mem::take(&mut self.ctx.name);
                    let value = std::mem::take(&mut self.ctx.value);

                    http_debug!(r, "http proxy header: \"{}: {}\"", B(&name), B(&value));

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

                    let hash = hash_key(&name);
                    let h = crate::upstream_rt::upstream_header(name.clone(), value, hash, name);

                    u.resp.push_header(h.clone());

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

                    http_debug!(r, "http proxy header done");

                    if u.resp.status_n == NGX_HTTP_EARLY_HINTS {
                        if self.ctx.end_stream {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream prematurely closed stream");
                            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                        }

                        self.ctx.status = false;
                        return NGX_HTTP_UPSTREAM_EARLY_HINTS;
                    }

                    let ctx = &self.ctx;

                    if ctx.end_stream && ctx.input.is_empty() && ctx.out.is_empty() && ctx.output_closed && !ctx.output_blocked && !ctx.goaway && *pos == buf.len() {
                        u.keepalive = true;
                    }

                    return NGX_OK;
                }

                // there was error while a header line parsing

                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid header");

                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            // rc == NGX_AGAIN

            if self.ctx.rest == 0 {
                self.ctx.state = ST_START;
                continue;
            }

            return NGX_AGAIN;
        }
    }

    /// ngx_http_proxy_v2_process_control_frame: GOAWAY, WINDOW_UPDATE,
    /// SETTINGS and PING; NGX_DECLINED for other frames
    fn process_control_frame(&mut self, r: &R, u: &mut Upstream, buf: &[u8], pos: &mut usize) -> i64 {
        let log = r.connection.log.clone();

        let ty = self.ctx.ty;

        if ty == NGX_HTTP_V2_GOAWAY_FRAME {
            let rc = self.ctx.parse_goaway(&log, buf, pos);

            if rc == NGX_AGAIN {
                return NGX_AGAIN;
            }

            if rc == NGX_ERROR {
                return NGX_ERROR;
            }

            // If stream_id is lower than one we use, our request won't be
            // processed and needs to be retried.  If stream_id is greater or
            // equal to the one we use, we can continue normally (except we
            // can't use this connection for additional requests).  If there
            // is a real error, the connection will be closed.

            if self.ctx.stream_id < self.ctx.id {
                // TODO: we can retry non-idempotent requests

                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent goaway with error {}", self.ctx.error);

                return NGX_ERROR;
            }

            self.ctx.goaway = true;

            return NGX_OK;
        }

        if ty == NGX_HTTP_V2_WINDOW_UPDATE_FRAME {
            let rc = self.ctx.parse_window_update(&log, buf, pos);

            if rc == NGX_AGAIN {
                return NGX_AGAIN;
            }

            if rc == NGX_ERROR {
                return NGX_ERROR;
            }

            if !self.ctx.input.is_empty() {
                u.post_write = true;
            }

            return NGX_OK;
        }

        if ty == NGX_HTTP_V2_SETTINGS_FRAME {
            let rc = self.ctx.parse_settings(&log, buf, pos);

            if rc == NGX_AGAIN {
                return NGX_AGAIN;
            }

            if rc == NGX_ERROR {
                return NGX_ERROR;
            }

            if !self.ctx.input.is_empty() {
                u.post_write = true;
            }

            return NGX_OK;
        }

        if ty == NGX_HTTP_V2_PING_FRAME {
            let rc = self.ctx.parse_ping(&log, buf, pos);

            if rc == NGX_AGAIN {
                return NGX_AGAIN;
            }

            if rc == NGX_ERROR {
                return NGX_ERROR;
            }

            u.post_write = true;

            return NGX_OK;
        }

        if ty == NGX_HTTP_V2_PUSH_PROMISE_FRAME {
            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent unexpected push promise frame");
            return NGX_ERROR;
        }

        NGX_DECLINED
    }

    /// ngx_http_proxy_v2_skip_frame
    fn skip_frame(&mut self, buf: &[u8], pos: &mut usize) -> i64 {
        let ctx = &mut self.ctx;

        if buf.len() - *pos < ctx.rest {
            ctx.rest -= buf.len() - *pos;
            *pos = buf.len();
            return NGX_AGAIN;
        }

        *pos += ctx.rest;
        ctx.rest = 0;
        ctx.state = ST_START;

        NGX_OK
    }

    /// The payload of the DATA frame at hand in the `available` bytes: all
    /// of it but the padding, or what there is (ctx->rest the rest of it)
    fn payload(&mut self, available: usize) -> usize {
        let ctx = &mut self.ctx;
        let want = ctx.rest - ctx.padding as usize;

        if available >= want {
            ctx.rest = ctx.padding as usize;
            want
        } else {
            ctx.rest -= available;
            available
        }
    }

    /// ngx_http_proxy_v2_process_frames: the frames of the response body
    /// and the trailers. NGX_OK at the payload of a DATA frame (from *pos),
    /// NGX_AGAIN for more, NGX_DONE at the end of the stream, NGX_ERROR.
    fn process_frames(&mut self, r: &R, u: &mut Upstream, buf: &[u8], pos: &mut usize) -> i64 {
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

                        let ctx = &self.ctx;

                        if ctx.input.is_empty() && ctx.output_closed && !ctx.output_blocked && !ctx.goaway && ctx.state == ST_START {
                            u.keepalive = true;
                        }

                        return NGX_DONE;
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

            let rc = self.process_control_frame(r, u, buf, pos);

            if rc == NGX_AGAIN {
                return NGX_AGAIN;
            }

            if rc == NGX_ERROR {
                return NGX_ERROR;
            }

            if rc == NGX_OK {
                continue;
            }

            if ty == NGX_HTTP_V2_HEADERS_FRAME || ty == NGX_HTTP_V2_CONTINUATION_FRAME {
                let mut done = false;

                loop {
                    let rc = self.ctx.parse_header(&r.connection.log, u.conf.buffer_size, buf, pos);

                    if rc == NGX_AGAIN {
                        break;
                    }

                    if rc == NGX_OK {
                        // a header line has been parsed successfully

                        let name = std::mem::take(&mut self.ctx.name);
                        let value = std::mem::take(&mut self.ctx.value);

                        http_debug!(r, "http proxy trailer: \"{}: {}\"", B(&name), B(&value));

                        if name.first() == Some(&b':') {
                            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid trailer \"{}: {}\"", B(&name), B(&value));
                            return NGX_ERROR;
                        }

                        let hash = hash_key(&name);
                        let h = crate::upstream_rt::upstream_header(name.clone(), value, hash, name);

                        u.resp.trailers.push(h);

                        continue;
                    }

                    if rc == NGX_HTTP_PARSE_HEADER_DONE {
                        // a whole header has been parsed successfully

                        http_debug!(r, "http proxy trailer done");

                        if self.ctx.end_stream {
                            self.ctx.done = true;
                            done = true;
                            break;
                        }

                        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent trailer without end stream flag");
                        return NGX_ERROR;
                    }

                    // there was error while a header line parsing

                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent invalid trailer");

                    return NGX_ERROR;
                }

                if done {
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

                if self.skip_frame(buf, pos) == NGX_AGAIN {
                    return NGX_AGAIN;
                }

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

                let ctx = &mut self.ctx;

                ctx.flags &= !NGX_HTTP_V2_PADDED_FLAG;
                ctx.padding = buf[*pos];
                *pos += 1;
                ctx.rest -= 1;

                if ctx.padding as usize > ctx.rest {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "upstream sent http2 frame with too long padding: {} in frame {}", ctx.padding, ctx.rest);
                    return NGX_ERROR;
                }

                continue;
            }

            if self.ctx.padding as usize == self.ctx.rest {
                let ctx = &mut self.ctx;

                if ctx.padding != 0 {
                    ctx.state = ST_PADDING;
                } else {
                    ctx.state = ST_START;

                    if ctx.flags & NGX_HTTP_V2_END_STREAM_FLAG != 0 {
                        ctx.done = true;
                    }
                }

                continue;
            }

            if *pos == buf.len() {
                return NGX_AGAIN;
            }

            return NGX_OK;
        }
    }
}
