//! ngx_http_v3_request.c: the streams of a QUIC connection given to the
//! http module, the request streams, their headers and request bodies.
//!
//! A request stream runs in its task: ngx_http_v3_init_request_stream,
//! then its read handlers (ngx_http_v3_wait_request_handler and
//! ngx_http_v3_process_request) until the headers are in, and the request
//! (ngx_http_process_request) with the pipeline of request_rt.rs. The
//! waits for the read event are those of Connection::recv() on the stream
//! connection, with the read timer as their timeout.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::buf::{Buf, Chain};
use ngx_core::connection::{stats, Connection, PoolCleanup};
use ngx_core::log::*;
use ngx_core::quic::streams::{ngx_quic_reset_stream, ngx_quic_stream, ngx_quic_stream_recv, wait_stream};
use ngx_core::quic::QuicStream;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use super::encode::field_l_len;
use super::module::srv_conf_of;
use super::parse::{parse_data, parse_headers, PBuf, ParseData, ParseHeaders};
use super::uni::{init_uni_stream, send_cancel_stream, send_goaway};
use super::*;
use crate::core::{loc_conf_from_ctx, srv_conf_from_ctx};
use crate::request::*;
use crate::request_rt::{self, End};
use crate::*;

/// ngx_http_v3_parse_s (r->v3_parse); the :path and :authority values are
/// kept here (r->uri_start and r->host_start point into them in C)
#[derive(Default)]
pub struct V3Parse {
    pub header_limit: usize,
    pub headers: ParseHeaders,
    pub body: ParseData,
    pub cookies: Option<Vec<Vec<u8>>>,
    pub path: Option<Vec<u8>>,
    pub authority: Option<Vec<u8>>,
}

/// r->v3_parse
fn v3_parse(r: &R) -> Rc<RefCell<V3Parse>> {
    let p = r.v3_parse.borrow().clone();

    match p {
        Some(p) => p,
        None => {
            let p = Rc::new(RefCell::new(V3Parse::default()));
            *r.v3_parse.borrow_mut() = Some(p.clone());
            p
        }
    }
}

/// How a request ended in the header phase: ngx_http_finalize_request()
/// or ngx_http_close_request().
enum Fin {
    Finalize(i64),
    Close(i64),
}

/// ngx_http_v3_methods
static METHODS: [(&[u8], u32); 16] = [
    (b"GET", NGX_HTTP_GET),
    (b"POST", NGX_HTTP_POST),
    (b"HEAD", NGX_HTTP_HEAD),
    (b"OPTIONS", NGX_HTTP_OPTIONS),
    (b"PROPFIND", NGX_HTTP_PROPFIND),
    (b"PUT", NGX_HTTP_PUT),
    (b"MKCOL", NGX_HTTP_MKCOL),
    (b"DELETE", NGX_HTTP_DELETE),
    (b"COPY", NGX_HTTP_COPY),
    (b"MOVE", NGX_HTTP_MOVE),
    (b"PROPPATCH", NGX_HTTP_PROPPATCH),
    (b"LOCK", NGX_HTTP_LOCK),
    (b"UNLOCK", NGX_HTTP_UNLOCK),
    (b"PATCH", NGX_HTTP_PATCH),
    (b"TRACE", NGX_HTTP_TRACE),
    (b"CONNECT", NGX_HTTP_CONNECT),
];

/// ngx_http_v3_init_stream for the QUIC connection: ngx_quic_run()
pub fn init_quic_connection(c: &Rc<Connection>, hc: &Rc<HttpConnection>) {
    hc.ssl.set(true);

    let clcf = loc_conf_from_ctx(&hc.conf_ctx.borrow());

    let quic = srv_conf_of(hc).quic.clone();

    let quic = match quic {
        Some(q) => q,
        None => {
            c.close();
            return;
        }
    };

    quic.idle_timeout.set(*clcf.borrow().keepalive_timeout);

    ngx_core::quic::ngx_quic_run(c, &quic);
}

/// ngx_http_v3_init_stream for a stream
pub async fn init_stream(c: &Rc<Connection>, hc: &Rc<HttpConnection>, log_ctx: &Rc<HttpLogCtx>) {
    hc.ssl.set(true);

    let clcf = loc_conf_from_ctx(&hc.conf_ctx.borrow());

    if let Some(phc) = quic_get_connection(c) {
        let servername = phc.ssl_servername.borrow().clone();

        if servername.is_some() {
            *hc.ssl_servername.borrow_mut() = servername;
            *hc.ssl_servername_regex.borrow_mut() = phc.ssl_servername_regex.borrow().clone();
            *hc.conf_ctx.borrow_mut() = phc.conf_ctx.borrow().clone();

            if let Some(chain) = clcf.borrow().error_log.clone() {
                c.log.set_chain(chain);
            }
        }
    }

    let id = ngx_quic_stream(c).map(|qs| qs.id).unwrap_or(0);

    if id & ngx_core::quic::NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 {
        init_uni_stream(c).await;
    } else {
        init_request_stream(c, hc, log_ctx).await;
    }
}

/// ngx_http_v3_init: the init handler of the QUIC connection
pub fn init(c: &Rc<Connection>) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 init");

    if init_session(c) != NGX_OK {
        return NGX_ERROR;
    }

    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    let hc = h3c.http_connection.clone();

    let clcf = loc_conf_from_ctx(&hc.conf_ctx.borrow());
    h3c.keepalive.add_timer(*clcf.borrow().keepalive_timeout);

    let h3scf = srv_conf_of(&hc);

    if h3scf.enable_hq {
        if !h3scf.enable {
            h3c.hq.set(true);
            return NGX_OK;
        }

        if alpn_selected(c) == NGX_HTTP_V3_HQ_PROTO {
            h3c.hq.set(true);
            return NGX_OK;
        }
    }

    if super::uni::send_settings(c) != NGX_OK {
        return NGX_ERROR;
    }

    if h3scf.max_table_capacity > 0 && super::uni::get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER).is_none() {
        return NGX_ERROR;
    }

    NGX_OK
}

/// SSL_get0_alpn_selected()
fn alpn_selected(c: &Connection) -> Vec<u8> {
    ngx_core::event_openssl::ngx_ssl_with(c, |ssl| ssl.selected_alpn_protocol().map(|p| p.to_vec())).flatten().unwrap_or_default()
}

/// ngx_http_v3_shutdown: the shutdown handler of the QUIC connection
pub fn shutdown(c: &Rc<Connection>) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 shutdown");

    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => {
            ngx_core::quic::ngx_quic_finalize_connection(c, NGX_HTTP_V3_ERR_NO_ERROR, Some("connection shutdown"));
            return;
        }
    };

    if !h3c.goaway.get() {
        h3c.goaway.set(true);

        if !h3c.hq.get() {
            let _ = send_goaway(c, h3c.next_request_id.get());
        }

        shutdown_connection(c, NGX_HTTP_V3_ERR_NO_ERROR, Some("connection shutdown"));
    }
}

/// ngx_http_v3_init_request_stream, and the stream's read handlers until
/// the request is done
async fn init_request_stream(c: &Rc<Connection>, hc: &Rc<HttpConnection>, log_ctx: &Rc<HttpLogCtx>) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 init request stream");

    stats().active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return,
    };

    let clcf = loc_conf_from_ctx(&hc.conf_ctx.borrow());

    let (keepalive_requests, keepalive_time) = {
        let cl = clcf.borrow();
        (*cl.keepalive_requests as u64, *cl.keepalive_time)
    };

    let n = qs.id >> 2;

    if n >= keepalive_requests * 2 {
        finalize_connection(c, NGX_HTTP_V3_ERR_EXCESSIVE_LOAD, Some("too many requests per connection"));
        request_rt::close_connection(c);
        return;
    }

    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => {
            request_rt::close_connection(c);
            return;
        }
    };

    if h3c.goaway.get() {
        c.close.set(true);
        request_rt::close_connection(c);
        return;
    }

    h3c.next_request_id.set(qs.id + 0x04);

    if n + 1 == keepalive_requests || ngx_core::times::msec().wrapping_sub(c.start_msec.get()) > keepalive_time {
        h3c.goaway.set(true);

        if !h3c.hq.get() && send_goaway(c, h3c.next_request_id.get()) != NGX_OK {
            request_rt::close_connection(c);
            return;
        }

        shutdown_connection(c, NGX_HTTP_V3_ERR_NO_ERROR, Some("reached maximum number of requests"));
    }

    let wc = Rc::downgrade(c);

    c.add_cleanup(PoolCleanup {
        tag: "ngx_http_v3_cleanup_connection",
        data: None,
        handler: Some(Box::new(move || {
            if let Some(c) = wc.upgrade() {
                cleanup_connection(&c);
            }
        })),
    });

    h3c.nrequests.set(h3c.nrequests.get() + 1);

    if h3c.keepalive.timer_set() {
        h3c.keepalive.del_timer();
    }

    if h3c.hq.get() {
        // the read handler stays ngx_http_wait_request_handler: an
        // HTTP/0.9 request (hq-interop)
        request_rt::hq_request_stream(c.clone(), hc.clone(), log_ctx.clone()).await;
        return;
    }

    // rev->handler = ngx_http_v3_wait_request_handler

    let cscf = srv_conf_from_ctx(&hc.conf_ctx.borrow());
    let timeout = *cscf.borrow().client_header_timeout;

    // the read timer: added here unless the stream is readable, then kept
    // until the request headers are in

    let mut deadline: Option<tokio::time::Instant> = None;

    if !qs.read_ready.get() {
        deadline = Some(tokio::time::Instant::now() + Duration::from_millis(timeout));
        c.reusable_connection(true);
    }

    let r = match wait_request_handler(c, hc, log_ctx, &qs, &mut deadline).await {
        Some(r) => r,
        None => return,
    };

    // rev->handler = ngx_http_v3_process_request

    let end = tokio::select! {
        end = process_request(&r, &qs, &mut deadline) => end,
        _ = stream_close(c, &qs) => {
            // ngx_http_request_handler: c->close terminates the request
            request_rt::terminate_request(&r, 0);
            End::Close
        }
    };

    let _ = end;

    // ngx_http_finalize_connection: ngx_http_close_request(r, 0)
    request_rt::close_request_final(&r);
    request_rt::close_connection(c);
}

/// The stream's c->close set (ngx_quic_close_streams), with its read event.
async fn stream_close(c: &Connection, qs: &QuicStream) {
    wait_stream(qs, || c.close.get()).await
}

/// Wait for the read event of the stream until the read timer: false if
/// the timer expired (rev->timedout). With `next`, the next read event
/// (a stream blocked on the dynamic table), else the stream readable.
async fn wait_read(c: &Connection, qs: &QuicStream, deadline: &mut Option<tokio::time::Instant>, timeout: u64, next: bool) -> bool {
    let dl = *deadline.get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_millis(timeout));

    if next {
        return tokio::time::timeout_at(dl, qs.notify.notified()).await.is_ok();
    }

    let ready = || qs.read_ready.get() || qs.read_error.get() || c.close.get();

    tokio::time::timeout_at(dl, wait_stream(qs, ready)).await.is_ok()
}

/// ngx_http_v3_wait_request_handler: the first data of the stream; the
/// request, or None when the stream is closed
async fn wait_request_handler(c: &Rc<Connection>, hc: &Rc<HttpConnection>, log_ctx: &Rc<HttpLogCtx>, qs: &Rc<QuicStream>, deadline: &mut Option<tokio::time::Instant>) -> Option<R> {
    let cscf = srv_conf_from_ctx(&hc.conf_ctx.borrow());
    let (size, timeout) = {
        let s = cscf.borrow();
        (*s.client_header_buffer_size, *s.client_header_timeout)
    };

    let mut timedout = false;

    loop {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 wait request handler");

        if timedout {
            ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
            c.timedout.set(true);
            request_rt::close_connection(c);
            return None;
        }

        if c.close.get() {
            request_rt::close_connection(c);
            return None;
        }

        {
            let mut b = hc.buffer.borrow_mut();

            if b.data.len() < size {
                b.data.resize(size, 0);
            }

            b.cap = size;
        }

        let mut buf = vec![0u8; size];

        let n = ngx_quic_stream_recv(c, &mut buf);

        if n == NGX_AGAIN as isize {
            if deadline.is_none() {
                *deadline = Some(tokio::time::Instant::now() + Duration::from_millis(timeout));
                c.reusable_connection(true);
            }

            // ngx_pfree(c->pool, b->start): the buffer is not held while
            // the stream is idle
            {
                let mut b = hc.buffer.borrow_mut();
                b.data = Vec::new();
                b.pos = 0;
                b.last = 0;
            }

            if !wait_read(c, qs, deadline, timeout, false).await {
                timedout = true;
            }

            continue;
        }

        if n == NGX_ERROR as isize {
            request_rt::close_connection(c);
            return None;
        }

        if n == 0 {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client closed connection");
            request_rt::close_connection(c);
            return None;
        }

        {
            let mut b = hc.buffer.borrow_mut();
            b.data.resize(size, 0);
            let last = b.last;
            b.data[last..last + n as usize].copy_from_slice(&buf[..n as usize]);
            b.last += n as usize;
        }

        break;
    }

    c.log.set_action(Some("reading client request"));

    c.reusable_connection(false);

    let r = create_request(c, hc, log_ctx);

    r.http_version.set(NGX_HTTP_VERSION_30);

    {
        let p = v3_parse(&r);
        let large = cscf.borrow().large_client_header_buffers;
        p.borrow_mut().header_limit = large.size * large.num;
    }

    c.requests.set((qs.id >> 2) + 1);

    let wr = Rc::downgrade(&r);

    r.add_pool_cleanup(Box::new(move || {
        if let Some(r) = wr.upgrade() {
            cleanup_request(&r);
        }
    }));

    Some(r)
}

/// ngx_http_v3_reset_stream
pub fn reset_stream(c: &Rc<Connection>) {
    let h3c = get_session(c);
    let qs = ngx_quic_stream(c);

    if let (Some(h3c), Some(qs)) = (&h3c, &qs) {
        if !qs.read_eof.get() && !h3c.hq.get() && h3c.known_stream(NGX_HTTP_V3_STREAM_SERVER_DECODER).is_some() && qs.id & ngx_core::quic::NGX_QUIC_STREAM_UNIDIRECTIONAL == 0 {
            let _ = send_cancel_stream(c, qs.id);
        }
    }

    if c.timedout.get() {
        ngx_quic_reset_stream(c, NGX_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR);
    } else if c.close.get() {
        ngx_quic_reset_stream(c, NGX_HTTP_V3_ERR_REQUEST_REJECTED);
    } else if c.requests.get() == 0 || c.error.get() {
        ngx_quic_reset_stream(c, NGX_HTTP_V3_ERR_INTERNAL_ERROR);
    }
}

/// ngx_http_v3_cleanup_connection
fn cleanup_connection(c: &Rc<Connection>) {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return,
    };

    h3c.nrequests.set(h3c.nrequests.get() - 1);

    if h3c.nrequests.get() == 0 {
        let clcf = loc_conf_from_ctx(&h3c.http_connection.conf_ctx.borrow());
        h3c.keepalive.add_timer(*clcf.borrow().keepalive_timeout);
    }
}

/// ngx_http_v3_cleanup_request
fn cleanup_request(r: &R) {
    if !r.response_sent.get() {
        r.connection.error.set(true);
    }
}

/// ngx_http_v3_process_request, on each read event until the request is
/// processed
async fn process_request(r: &R, qs: &Rc<QuicStream>, deadline: &mut Option<tokio::time::Instant>) -> End {
    let c = r.connection.clone();
    let hc = r.http_connection.clone();

    let timeout = *r.cscf().borrow().client_header_timeout;

    let mut timedout = false;

    let fin = 'fin: loop {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 process request");

        if timedout {
            ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
            c.timedout.set(true);
            break Fin::Close(NGX_HTTP_REQUEST_TIME_OUT);
        }

        let h3c = match get_session(&c) {
            Some(h3c) => h3c,
            None => break Fin::Close(NGX_HTTP_INTERNAL_SERVER_ERROR),
        };

        // Ok(true): the headers are in; Ok(false): the stream waits for
        // the next read event (blocked on the dynamic table: for the event
        // itself, not for data)
        let mut blocked = false;

        let st_rc: Result<bool, Fin> = 'inner: loop {
            let empty = {
                let b = hc.buffer.borrow();
                b.pos == b.last
            };

            if empty {
                let cap = hc.buffer.borrow().cap;

                let mut buf = vec![0u8; cap];

                let n = if qs.read_ready.get() { ngx_quic_stream_recv(&c, &mut buf) } else { NGX_AGAIN as isize };

                if n == NGX_AGAIN as isize {
                    // the read timer, and the next read event
                    break 'inner Ok(false);
                }

                if n == 0 {
                    ngx_log_error!(NGX_LOG_INFO, c.log, None, "client prematurely closed connection");
                }

                if n == 0 || n == NGX_ERROR as isize {
                    c.error.set(true);
                    c.log.set_action(Some("reading client request"));

                    break 'inner Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
                }

                let mut b = hc.buffer.borrow_mut();
                if b.data.len() < cap {
                    b.data.resize(cap, 0);
                }
                b.data[..n as usize].copy_from_slice(&buf[..n as usize]);
                b.pos = 0;
                b.last = n as usize;
            }

            let (data, pos, last) = {
                let b = hc.buffer.borrow();
                (b.data.clone(), b.pos, b.last)
            };

            let p = pos;

            let mut pb = PBuf { data: &data, pos, last };

            let rc = {
                let v3p = v3_parse(r);
                let mut st = std::mem::take(&mut v3p.borrow_mut().headers);
                let rc = parse_headers(&c, &mut st, &mut pb);
                v3p.borrow_mut().headers = st;
                rc
            };

            hc.buffer.borrow_mut().pos = pb.pos;

            if rc > 0 {
                ngx_quic_reset_stream(&c, rc as u64);
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client sent invalid header");
                break 'inner Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
            }

            if rc == NGX_ERROR {
                break 'inner Err(Fin::Close(NGX_HTTP_INTERNAL_SERVER_ERROR));
            }

            r.request_length.set(r.request_length.get() + (pb.pos - p) as i64);
            h3c.total_bytes.set(h3c.total_bytes.get() + (pb.pos - p) as i64);

            if check_flood(&c) != NGX_OK {
                break 'inner Err(Fin::Close(NGX_HTTP_CLOSE));
            }

            if rc == NGX_BUSY {
                if qs.read_error.get() {
                    break 'inner Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
                }

                blocked = true;

                break 'inner Ok(false);
            }

            if rc == NGX_AGAIN {
                continue;
            }

            /* rc == NGX_OK || rc == NGX_DONE */

            let (name, value) = {
                let v3p = v3_parse(r);
                let p = v3p.borrow();
                (p.headers.field_rep.field.name.clone(), p.headers.field_rep.field.value.clone())
            };

            h3c.payload_bytes.set(h3c.payload_bytes.get() + field_l_len(&name, &value) as i64);

            if let Err(f) = process_header(r, &name, &value) {
                break 'inner Err(f);
            }

            if rc == NGX_DONE {
                if let Err(f) = process_request_header(r).await {
                    break 'inner Err(f);
                }

                break 'inner Ok(true);
            }
        };

        match st_rc {
            Ok(true) => {
                // ngx_http_process_request()
                return request_rt::process_request(r).await;
            }

            Ok(false) => {
                if !wait_read(&c, qs, deadline, timeout, blocked).await {
                    timedout = true;
                }
            }

            Err(f) => break 'fin f,
        }
    };

    match fin {
        Fin::Finalize(rc) => {
            request_rt::finalize_request(r, rc).await;
        }

        Fin::Close(rc) => {
            // ngx_http_close_request(r, rc)
            if rc > 0 {
                let mut ho = r.headers_out.borrow_mut();
                if ho.status == 0 || r.connection.sent.get() == 0 {
                    ho.status = rc;
                }
            }
        }
    }

    End::Close
}

/// ngx_http_v3_process_header
fn process_header(r: &R, name: &[u8], value: &[u8]) -> Result<(), Fin> {
    let len = name.len() + value.len();

    let v3p = v3_parse(r);

    if len > v3p.borrow().header_limit {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent too large header");
        return Err(Fin::Finalize(NGX_HTTP_REQUEST_HEADER_TOO_LARGE));
    }

    v3p.borrow_mut().header_limit -= len;

    if validate_header(r, name, value).is_err() {
        return Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
    }

    if r.invalid_header.get() && *r.cscf().borrow().ignore_invalid_headers {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid header: \"{}\"", B(name));

        return Ok(());
    }

    if !name.is_empty() && name[0] == b':' {
        return process_pseudo_header(r, name, value);
    }

    init_pseudo_headers(r)?;

    if name == b"cookie" {
        // ngx_http_v3_cookie
        let v3p = v3_parse(r);
        v3p.borrow_mut().cookies.get_or_insert_with(Vec::new).push(value.to_vec());
    } else {
        let max_headers = *r.cscf().borrow().max_headers;

        let count = {
            let mut hin = r.headers_in.borrow_mut();
            let n = hin.count;
            hin.count += 1;
            n
        };

        if count as i64 >= max_headers {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent too many header lines");
            return Err(Fin::Finalize(NGX_HTTP_REQUEST_HEADER_TOO_LARGE));
        }

        process_header_line(r, name, value)?;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 header: \"{}: {}\"", B(name), B(value));

    Ok(())
}

/// The header added to headers_in and its headers_in_hash handler run.
fn process_header_line(r: &R, name: &[u8], value: &[u8]) -> Result<(), Fin> {
    let hash = ngx_core::hash::hash_key(name);
    let h = TableElt::with_hash(name, value, hash, name.to_vec());

    r.headers_in.borrow_mut().headers.push(h.clone());

    let handler = {
        let cmcf = r.cmcf();
        let m = cmcf.borrow();
        m.headers_in_hash.as_ref().and_then(|hh| hh.find(hash, name).copied())
    };

    if let Some(f) = handler {
        if f(r, h) != NGX_OK {
            // the handler has finalized the request
            let pending = request_rt::take_pending_finalize();
            return Err(Fin::Finalize(if pending != 0 { pending } else { NGX_HTTP_INTERNAL_SERVER_ERROR }));
        }
    }

    Ok(())
}

/// ngx_http_v3_validate_header
fn validate_header(r: &R, name: &[u8], value: &[u8]) -> Result<(), ()> {
    r.invalid_header.set(false);

    let underscores = *r.cscf().borrow().underscores_in_headers;

    let start = (!name.is_empty() && name[0] == b':') as usize;

    for &ch in &name[start..] {
        if ch.is_ascii_lowercase() || ch == b'-' || ch.is_ascii_digit() || (ch == b'_' && underscores) {
            continue;
        }

        if ch <= 0x20 || ch == 0x7f || ch == b':' || ch.is_ascii_uppercase() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid header name: \"{}\"", B(name));

            return Err(());
        }

        r.invalid_header.set(true);
    }

    for &ch in value {
        if ch == b'\0' || ch == b'\n' || ch == b'\r' {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent header \"{}\" with invalid value: \"{}\"", B(name), B(value));

            return Err(());
        }
    }

    Ok(())
}

/// ngx_http_v3_process_pseudo_header
fn process_pseudo_header(r: &R, name: &[u8], value: &[u8]) -> Result<(), Fin> {
    let failed = Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));

    if !r.request_line.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent out of order pseudo-headers");
        return failed;
    }

    let v3p = v3_parse(r);

    if name == b":method" {
        if !r.method_name.borrow().is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent duplicate \":method\" header");
            return failed;
        }

        if value.is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent empty \":method\" header");
            return failed;
        }

        *r.method_name.borrow_mut() = value.to_vec();

        if let Some((_, m)) = METHODS.iter().find(|(n, _)| *n == value) {
            r.method.set(*m);
        }

        for &ch in value {
            if !ch.is_ascii_uppercase() && ch != b'_' && ch != b'-' {
                ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid method: \"{}\"", B(value));
                return failed;
            }
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 method \"{}\" {}", B(value), r.method.get());
        return Ok(());
    }

    if name == b":path" {
        if v3p.borrow().path.is_some() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent duplicate \":path\" header");
            return failed;
        }

        if value.is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent empty \":path\" header");
            return failed;
        }

        v3p.borrow_mut().path = Some(value.to_vec());

        let rc = {
            let mut p = r.parse.borrow_mut();
            *p = crate::parse::ParseRequest::default();
            p.uri_start = Some(0);
            p.uri_end = Some(value.len());
            crate::parse::parse_uri(&mut p, value)
        };

        if rc != NGX_OK {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid \":path\" header: \"{}\"", B(value));
            return failed;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 path \"{}\"", B(value));
        return Ok(());
    }

    if name == b":scheme" {
        if !r.schema.borrow().is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent duplicate \":scheme\" header");
            return failed;
        }

        if value.is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent empty \":scheme\" header");
            return failed;
        }

        for (i, &ch) in value.iter().enumerate() {
            let c = ch | 0x20;
            if c.is_ascii_lowercase() {
                continue;
            }

            if (ch.is_ascii_digit() || ch == b'+' || ch == b'-' || ch == b'.') && i > 0 {
                continue;
            }

            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid \":scheme\" header: \"{}\"", B(value));
            return failed;
        }

        *r.schema.borrow_mut() = value.to_vec();

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 schema \"{}\"", B(value));
        return Ok(());
    }

    if name == b":authority" {
        if v3p.borrow().authority.is_some() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent duplicate \":authority\" header");
            return failed;
        }

        v3p.borrow_mut().authority = Some(value.to_vec());

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 authority \"{}\"", B(value));
        return Ok(());
    }

    ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent unknown pseudo-header \"{}\"", B(name));

    failed
}

/// ngx_http_v3_init_pseudo_headers
fn init_pseudo_headers(r: &R) -> Result<(), Fin> {
    let failed = Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));

    if !r.request_line.borrow().is_empty() {
        return Ok(());
    }

    let v3p = v3_parse(r);

    if r.method_name.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no \":method\" header");
        return failed;
    }

    if r.schema.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no \":scheme\" header");
        return failed;
    }

    let path = match v3p.borrow().path.clone() {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no \":path\" header");
            return failed;
        }
    };

    let mut line = r.method_name.borrow().clone();
    line.push(b' ');
    line.extend_from_slice(&path);
    line.push(b' ');
    line.extend_from_slice(b"HTTP/3.0");

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 request line: \"{}\"", B(&line));

    *r.request_line.borrow_mut() = line;

    *r.http_protocol.borrow_mut() = b"HTTP/3.0".to_vec();

    if request_rt::process_request_uri_data(r, &path).is_err() {
        // ngx_http_process_request_uri() finalizes the request
        return Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
    }

    let authority = v3p.borrow().authority.clone();

    if let Some(host) = authority {
        let (host, port) = match request_rt::validate_host(&host, false) {
            Ok(v) => v,
            Err(()) => {
                ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid \":authority\" header");
                return failed;
            }
        };

        if request_rt::set_virtual_server(r, &host) == NGX_ERROR {
            // ngx_http_set_virtual_server() has finalized the request
            let pending = request_rt::take_pending_finalize();
            return Err(if pending != 0 { Fin::Finalize(pending) } else { Fin::Close(NGX_HTTP_INTERNAL_SERVER_ERROR) });
        }

        r.headers_in.borrow_mut().server = host;
        r.port.set(port);
    }

    Ok(())
}

/// ngx_http_v3_process_request_header
async fn process_request_header(r: &R) -> Result<(), Fin> {
    let c = r.connection.clone();

    {
        let hin = r.headers_in.borrow();

        if !hin.connection.is_empty() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent \"Connection\" header");
            return Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
        }

        if !hin.keep_alive.is_empty() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent \"Keep-Alive\" header");
            return Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
        }

        if hin.transfer_encoding.is_some() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent \"Transfer-Encoding\" header");
            return Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
        }

        if !hin.upgrade.is_empty() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent \"Upgrade\" header");
            return Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
        }

        if !hin.te.is_empty() && (hin.te.len() > 1 || !hin.te[0].value.borrow().eq_ignore_ascii_case(b"trailers")) {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent invalid \"TE\" header");
            return Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));
        }
    }

    init_pseudo_headers(r)?;

    let h3c = match get_session(&c) {
        Some(h3c) => h3c,
        None => return Err(Fin::Close(NGX_HTTP_INTERNAL_SERVER_ERROR)),
    };

    let (enable, enable_hq) = {
        let h3scf = super::module::srv_conf_of_request(r);
        (h3scf.enable, h3scf.enable_hq)
    };

    if (h3c.hq.get() && !enable_hq) || (!h3c.hq.get() && !enable) {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client attempted to request the server name for which the negotiated protocol is disabled");
        return Err(Fin::Finalize(NGX_HTTP_MISDIRECTED_REQUEST));
    }

    construct_cookie_header(r)?;

    let failed = Err(Fin::Finalize(NGX_HTTP_BAD_REQUEST));

    if r.headers_in.borrow().server.is_empty() {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent neither \":authority\" nor \"Host\" header");
        return failed;
    }

    let authority = v3_parse(r).borrow().authority.clone();

    if let Some(host) = authority {
        let host_header = r.headers_in.borrow().host.as_ref().map(|h| h.value.borrow().clone());

        if let Some(h) = host_header {
            if h != host {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent \":authority\" and \"Host\" headers with different values");
                return failed;
            }
        }
    }

    let content_length = r.headers_in.borrow().content_length.as_ref().map(|h| h.value.borrow().clone());

    if let Some(cl) = content_length {
        let n = ngx_core::string::atoof(&cl).unwrap_or(-1);

        r.headers_in.borrow_mut().content_length_n = n;

        if n == -1 {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent invalid \"Content-Length\" header");
            return failed;
        }
    } else {
        let hc = r.http_connection.clone();

        let mut n = {
            let b = hc.buffer.borrow();
            (b.last - b.pos) as isize
        };

        if n == 0 {
            let cap = hc.buffer.borrow().cap;
            let mut buf = vec![0u8; cap];

            n = ngx_quic_stream_recv(&c, &mut buf);

            if n == NGX_ERROR as isize {
                return Err(Fin::Close(NGX_HTTP_INTERNAL_SERVER_ERROR));
            }

            if n > 0 {
                let mut b = hc.buffer.borrow_mut();
                if b.data.len() < cap {
                    b.data.resize(cap, 0);
                }
                b.data[..n as usize].copy_from_slice(&buf[..n as usize]);
                b.pos = 0;
                b.last = n as usize;
            }
        }

        if n != 0 {
            r.headers_in.borrow_mut().chunked = true;
        }
    }

    if r.method.get() == NGX_HTTP_CONNECT {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent CONNECT method");
        return Err(Fin::Finalize(NGX_HTTP_NOT_ALLOWED));
    }

    if r.method.get() == NGX_HTTP_TRACE {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent TRACE method");
        return Err(Fin::Finalize(NGX_HTTP_NOT_ALLOWED));
    }

    Ok(())
}

/// ngx_http_v3_construct_cookie_header
fn construct_cookie_header(r: &R) -> Result<(), Fin> {
    let cookies = v3_parse(r).borrow_mut().cookies.take();

    let cookies = match cookies {
        Some(c) => c,
        None => return Ok(()),
    };

    let value = cookies.join(&b"; "[..]);

    let hash = ngx_core::hash::hash_key(b"cookie");
    let h = TableElt::with_hash(b"cookie", &value, hash, b"cookie".to_vec());

    r.headers_in.borrow_mut().headers.push(h.clone());

    let handler = {
        let cmcf = r.cmcf();
        let m = cmcf.borrow();
        m.headers_in_hash.as_ref().and_then(|hh| hh.find(hash, b"cookie").copied())
    };

    let f = match handler {
        Some(f) => f,
        None => return Err(Fin::Close(NGX_HTTP_INTERNAL_SERVER_ERROR)),
    };

    if f(r, h) != NGX_OK {
        // request has been finalized already
        // in ngx_http_process_header_line()
        let pending = request_rt::take_pending_finalize();
        return Err(Fin::Finalize(if pending != 0 { pending } else { NGX_HTTP_INTERNAL_SERVER_ERROR }));
    }

    Ok(())
}

/// ngx_http_v3_read_request_body: the body read (buffered: all of it;
/// unbuffered: NGX_AGAIN once set up, the rest read by
/// read_unbuffered_request_body())
pub async fn read_request_body(r: &R, rb: &Rc<RefCell<RequestBody>>) -> i64 {
    let hc = r.http_connection.clone();

    let preread: Vec<u8> = hc.buffer.borrow().unread().to_vec();

    let rc = if !preread.is_empty() {
        /* there is the pre-read part of the request body */

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 client request body preread {}", preread.len());

        let (rc, consumed) = request_body_filter(r, rb, Some((&preread, false))).await;

        hc.buffer.borrow_mut().pos += consumed;

        rc
    } else {
        request_body_filter(r, rb, None).await.0
    };

    if rc != NGX_OK {
        return rc;
    }

    {
        let b = rb.borrow();

        if b.rest == 0 && b.last_saved {
            /* the whole request body was pre-read */
            drop(b);
            r.request_body_no_buffering.set(false);
            return NGX_OK;
        }

        if b.rest < 0 {
            drop(b);
            ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "negative request body rest");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // rb->buf
    let size = *r.clcf().borrow().client_body_buffer_size;

    {
        let mut b = rb.borrow_mut();
        b.buf_size = size;
        b.buf_last = 0;
    }

    do_read_client_request_body(r, rb, !r.request_body_no_buffering.get()).await
}

/// ngx_http_v3_read_unbuffered_request_body
pub async fn read_unbuffered_request_body(r: &R) -> i64 {
    let rb = match r.request_body.borrow().clone() {
        Some(rb) => rb,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let rc = do_read_client_request_body(r, &rb, false).await;

    if rc == NGX_OK {
        r.reading_body.set(false);
    }

    rc
}

/// Wait for the read event of an unbuffered body.
pub async fn wait_request_body(r: &R) {
    if let Some(qs) = ngx_quic_stream(&r.connection) {
        let c = r.connection.clone();
        wait_stream(&qs, || qs.read_ready.get() || qs.read_error.get() || c.close.get()).await;
    }
}

/// ngx_http_v3_do_read_client_request_body, with the read handler's
/// waits for the read event when `wait` (a buffered body)
async fn do_read_client_request_body(r: &R, rb: &Rc<RefCell<RequestBody>>, wait: bool) -> i64 {
    let c = r.connection.clone();

    let qs = match ngx_quic_stream(&c) {
        Some(qs) => qs,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let timeout = *r.clcf().borrow().client_body_timeout;

    loop {
        let mut flush = true;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 read client request body");

        let done = 'outer: loop {
            loop {
                let (rest, buf_size, buf_last) = {
                    let b = rb.borrow();
                    (b.rest, b.buf_size, b.buf_last)
                };

                if rest == 0 {
                    break;
                }

                if buf_last == buf_size {
                    /* update chains */

                    let (rc, _) = request_body_filter(r, rb, None).await;

                    if rc != NGX_OK {
                        return rc;
                    }

                    // rb->busy: data of rb->buf still used
                    if !rb.borrow().bufs.is_empty() && rb.borrow().bufs.iter().any(|b| b.in_memory() && b.buf_size() > 0) {
                        if r.request_body_no_buffering.get() {
                            return NGX_AGAIN;
                        }

                        if rb.borrow().filter_need_buffering {
                            if !wait {
                                return NGX_AGAIN;
                            }

                            break 'outer false;
                        }

                        ngx_log_error!(NGX_LOG_ALERT, c.log, None, "busy buffers after request body flush");

                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    flush = false;
                    rb.borrow_mut().buf_last = 0;
                }

                // rest - (rb->buf->last - rb->buf->pos): the body filter has
                // parsed all the data of rb->buf
                let (size, rest) = {
                    let b = rb.borrow();
                    (b.buf_size - b.buf_last, b.rest)
                };

                let size = if size as i64 > rest { rest as usize } else { size };

                if size == 0 {
                    break;
                }

                let mut buf = vec![0u8; size];

                let n = ngx_quic_stream_recv(&c, &mut buf);

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 client request body recv {}", n);

                if n == NGX_AGAIN as isize {
                    break;
                }

                let last = n == 0;

                if n == NGX_ERROR as isize {
                    c.error.set(true);
                    return NGX_HTTP_BAD_REQUEST;
                }

                rb.borrow_mut().buf_last += n as usize;

                /* pass buffer to request body filter chain */

                flush = false;

                let (rc, _) = request_body_filter(r, rb, Some((&buf[..n as usize], last))).await;

                if rc != NGX_OK {
                    return rc;
                }

                let b = rb.borrow();

                if b.rest == 0 {
                    break;
                }

                if b.buf_last < b.buf_size {
                    break;
                }
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 client request body rest {}", rb.borrow().rest);

            if flush {
                let (rc, _) = request_body_filter(r, rb, None).await;

                if rc != NGX_OK {
                    return rc;
                }
            }

            {
                let b = rb.borrow();

                if b.rest == 0 && b.last_saved {
                    break 'outer true;
                }
            }

            if !qs.read_ready.get() || rb.borrow().rest == 0 {
                if !wait {
                    return NGX_AGAIN;
                }

                break 'outer false;
            }
        };

        if done {
            break;
        }

        // the read timer (client_body_timeout) and the next read event:
        // ngx_http_v3_read_client_request_body_handler

        let ready = || qs.read_ready.get() || qs.read_error.get() || c.close.get();

        if tokio::time::timeout(Duration::from_millis(timeout), wait_stream(&qs, ready)).await.is_err() {
            c.timedout.set(true);
            return NGX_HTTP_REQUEST_TIME_OUT;
        }
    }

    if !r.request_body_no_buffering.get() {
        // r->read_event_handler = ngx_http_block_reading; rb->post_handler(r)
    }

    NGX_OK
}

/// ngx_http_v3_request_body_filter: the DATA frames of `input` (the data
/// and whether it ends the stream) to the request body filters; the rc,
/// and how much of the input was parsed
async fn request_body_filter(r: &R, rb: &Rc<RefCell<RequestBody>>, input: Option<(&[u8], bool)>) -> (i64, usize) {
    let c = r.connection.clone();

    let h3c = match get_session(&c) {
        Some(h3c) => h3c,
        None => return (NGX_HTTP_INTERNAL_SERVER_ERROR, 0),
    };

    let v3p = v3_parse(r);

    if rb.borrow().rest == -1 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http3 request body filter");

        rb.borrow_mut().rest = r.cscf().borrow().large_client_header_buffers.size as i64;
    }

    let mut max = r.headers_in.borrow().content_length_n;

    let client_max_body_size = *r.clcf().borrow().client_max_body_size;

    if max == -1 && client_max_body_size != 0 {
        max = client_max_body_size;
    }

    let mut out = Chain::new();
    let mut last = false;
    let mut consumed = 0usize;

    let rc: Option<i64> = 'done: {
        let (data, last_buf) = match input {
            Some(i) => i,
            None => break 'done None,
        };

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, r.connection.log, "http3 body buf t:1 f:0 {:p}, pos {:p}, size: {} file: 0, size: 0", data.as_ptr(), data.as_ptr(), data.len());

        if last_buf {
            last = true;
        }

        // b: the last buffer made for this input
        let mut b: Option<usize> = None;

        let mut pos = 0usize;

        while pos < data.len() {
            let length = v3p.borrow().body.length;

            if length == 0 {
                let p = pos;

                let mut pb = PBuf { data, pos, last: data.len() };

                let rc = {
                    let mut st = std::mem::take(&mut v3p.borrow_mut().body);
                    let rc = parse_data(&c, &mut st, &mut pb);
                    v3p.borrow_mut().body = st;
                    rc
                };

                pos = pb.pos;
                consumed = pos;

                r.request_length.set(r.request_length.get() + (pos - p) as i64);
                h3c.total_bytes.set(h3c.total_bytes.get() + (pos - p) as i64);

                if check_flood(&c) != NGX_OK {
                    return (NGX_HTTP_CLOSE, consumed);
                }

                if rc == NGX_AGAIN {
                    continue;
                }

                if rc == NGX_DONE {
                    last = true;
                    break 'done None;
                }

                if rc > 0 {
                    ngx_quic_reset_stream(&c, rc as u64);
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client sent invalid body");
                    return (NGX_HTTP_BAD_REQUEST, consumed);
                }

                if rc == NGX_ERROR {
                    return (NGX_HTTP_INTERNAL_SERVER_ERROR, consumed);
                }

                /* rc == NGX_OK */

                let length = v3p.borrow().body.length;
                let received = rb.borrow().received;

                if max != -1 && ((max - received) as u64) < length {
                    if r.headers_in.borrow().content_length_n != -1 {
                        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client intended to send body data larger than declared");

                        return (NGX_HTTP_BAD_REQUEST, consumed);
                    }

                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client intended to send too large body: {}+{} bytes", received, length);

                    return (NGX_HTTP_REQUEST_ENTITY_TOO_LARGE, consumed);
                }

                continue;
            }

            let avail = (data.len() - pos) as u64;

            if let Some(bi) = b {
                if length <= 128 && avail >= length {
                    let n = length as usize;

                    rb.borrow_mut().received += n as i64;
                    r.request_length.set(r.request_length.get() + n as i64);
                    h3c.total_bytes.set(h3c.total_bytes.get() + n as i64);
                    h3c.payload_bytes.set(h3c.payload_bytes.get() + n as i64);

                    if let Some(buf) = out.iter_mut().nth(bi) {
                        if let ngx_core::buf::BufData::Memory(v) = &mut buf.data {
                            v.extend_from_slice(&data[pos..pos + n]);
                            buf.last = v.len();
                        }
                    }

                    pos += n;
                    consumed = pos;
                    v3p.borrow_mut().body.length = 0;

                    continue;
                }
            }

            let n = if avail > length { length as usize } else { avail as usize };

            let mut nb = Buf::from_vec(data[pos..pos + n].to_vec());
            nb.temporary = true;
            nb.flush = r.request_body_no_buffering.get();

            out.push_back(nb);
            b = Some(out.len() - 1);

            rb.borrow_mut().received += n as i64;
            r.request_length.set(r.request_length.get() + n as i64);
            h3c.total_bytes.set(h3c.total_bytes.get() + n as i64);
            h3c.payload_bytes.set(h3c.payload_bytes.get() + n as i64);

            v3p.borrow_mut().body.length -= n as u64;

            pos += n;
            consumed = pos;
        }

        None
    };

    if let Some(rc) = rc {
        return (rc, consumed);
    }

    // done:

    if last {
        if v3p.borrow().body.length > 0 {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client prematurely closed stream");
            r.connection.error.set(true);
            return (NGX_HTTP_BAD_REQUEST, consumed);
        }

        let received = rb.borrow().received;
        let content_length_n = r.headers_in.borrow().content_length_n;

        if content_length_n == -1 {
            r.headers_in.borrow_mut().content_length_n = received;
        } else if content_length_n != received {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent less body data than expected: {} out of {} bytes of request body received", received, content_length_n);
            return (NGX_HTTP_BAD_REQUEST, consumed);
        }

        rb.borrow_mut().rest = 0;

        let mut lb = Buf::default();
        lb.last_buf = true;

        out.push_back(lb);
    } else {
        /* set rb->rest, amount of data we want to see next time */

        rb.borrow_mut().rest = r.cscf().borrow().large_client_header_buffers.size as i64;
    }

    let f = top_request_body_filter();
    let rc = f(r.clone(), out).await;

    (rc, consumed)
}
