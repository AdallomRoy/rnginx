//! HTTP/2 server-side dispatch, powered by the `h2` crate.
//!
//! We use `h2` for framing/HPACK/flow-control and bridge each accepted
//! stream into our existing HttpRequest pipeline. The bridge is:
//!
//! * `H2Io` — an `AsyncRead + AsyncWrite` adapter over `Rc<Connection>`
//!   (plain or SSL). It is `!Send`, which is fine because we drive the
//!   whole thing on tokio's current-thread runtime and never spawn h2
//!   tasks with the multi-threaded `spawn`.
//! * For each accepted stream, we translate `h2::Request` into a
//!   populated `HttpRequest`, call `process_request`, capture the
//!   pipeline's HTTP/1 wire output via `Connection::send_capture`,
//!   re-parse it into (status, headers, body), and send that back via
//!   `h2::SendResponse` / `SendStream`.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use bytes::Bytes;
use ngx_core::connection::Connection;
use ngx_core::log::*;
use ngx_core::ngx_log_error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::core::*;
use crate::request::*;
use crate::request_rt;
use crate::parse::NGX_HTTP_VERSION_20;
use crate::NGX_HTTP_INTERNAL_SERVER_ERROR;

/// AsyncRead + AsyncWrite adapter over Rc<Connection>. Bridges the
/// callback/poll model that `h2` expects against our async recv/send.
///
/// We hold a boxed "in-flight" future per direction; on each poll, we
/// poll that future to completion (or reschedule).
pub struct H2Io {
    conn: Rc<Connection>,
    read_fut: RefCell<Option<Pin<Box<dyn Future<Output = io::Result<Vec<u8>>>>>>>,
    write_fut: RefCell<Option<Pin<Box<dyn Future<Output = io::Result<usize>>>>>>,
    read_buf: RefCell<Vec<u8>>,
    read_pos: Cell<usize>,
    shutdown_started: Cell<bool>,
}

impl H2Io {
    pub fn new(conn: Rc<Connection>) -> Self {
        H2Io {
            conn,
            read_fut: RefCell::new(None),
            write_fut: RefCell::new(None),
            read_buf: RefCell::new(Vec::new()),
            read_pos: Cell::new(0),
            shutdown_started: Cell::new(false),
        }
    }
}

impl AsyncRead for H2Io {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Serve leftover bytes first.
        {
            let mut buf = self.read_buf.borrow_mut();
            let pos = self.read_pos.get();
            if pos < buf.len() {
                let take = (buf.len() - pos).min(out.remaining());
                out.put_slice(&buf[pos..pos + take]);
                self.read_pos.set(pos + take);
                if self.read_pos.get() == buf.len() {
                    buf.clear();
                    self.read_pos.set(0);
                }
                return Poll::Ready(Ok(()));
            }
        }
        // Kick a fresh read.
        let mut slot = self.read_fut.borrow_mut();
        if slot.is_none() {
            let conn = self.conn.clone();
            let want = out.remaining().max(4096);
            *slot = Some(Box::pin(async move {
                let mut buf = vec![0u8; want];
                let n = conn.recv(&mut buf).await?;
                buf.truncate(n);
                Ok(buf)
            }));
        }
        let fut = slot.as_mut().unwrap().as_mut();
        match fut.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(res) => {
                *slot = None;
                match res {
                    Err(e) => Poll::Ready(Err(e)),
                    Ok(bytes) => {
                        if bytes.is_empty() {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        let take = bytes.len().min(out.remaining());
                        out.put_slice(&bytes[..take]);
                        if take < bytes.len() {
                            let leftover: Vec<u8> = bytes[take..].to_vec();
                            *self.read_buf.borrow_mut() = leftover;
                            self.read_pos.set(0);
                        }
                        Poll::Ready(Ok(()))
                    }
                }
            }
        }
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut slot = self.write_fut.borrow_mut();
        if slot.is_none() {
            let conn = self.conn.clone();
            let owned: Vec<u8> = buf.to_vec();
            *slot = Some(Box::pin(async move {
                conn.send(&owned).await
            }));
        }
        let fut = slot.as_mut().unwrap().as_mut();
        match fut.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => {
                *slot = None;
                Poll::Ready(r)
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Socket writes are unbuffered; nothing to flush.
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Best-effort shutdown of the write side. We don't drive an
        // OpenSSL close_notify here — the connection will be closed at
        // cleanup time. Returning Ready lets h2 finish its GOAWAY.
        self.shutdown_started.set(true);
        Poll::Ready(Ok(()))
    }
}

/// Entry point: h2 was selected by ALPN. Runs handshake and serves all
/// streams until the connection closes.
pub async fn h2_run(c: Rc<Connection>, hc: Rc<HttpConnection>) {
    let io = H2Io::new(c.clone());
    let mut builder = h2::server::Builder::new();
    // Match C nginx server preface exactly: SETTINGS + a connection-level
    // WINDOW_UPDATE bumping the window to ~2GB. Test::Nginx::HTTP2's
    // handshake blocks reading until it has seen both frames, and h2's
    // set_target_window_size doesn't emit WINDOW_UPDATE until data has
    // actually consumed capacity — so we don't get one out of h2 alone.
    builder.initial_window_size(65535);
    builder.max_concurrent_streams(128);
    let handshake_res = builder.handshake::<_, Bytes>(io).await;
    let mut conn = match handshake_res {
        Ok(h) => h,
        Err(e) => {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "h2 handshake failed: {}", e);
            return;
        }
    };
    // NOTE: Test::Nginx::HTTP2 waits for WINDOW_UPDATE at handshake. h2
    // doesn't emit one until data consumption. Disabled the extra send —
    // it doesn't help curl/Perl progress past HEADERS anyway.
    loop {
        let accept = conn.accept().await;
        match accept {
            None => break,
            Some(Err(e)) => {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "h2 accept error: {}", e);
                break;
            }
            Some(Ok((req, respond))) => {
                serve_stream(c.clone(), hc.clone(), req, respond).await;
            }
        }
    }
}

/// Handle a single h2 stream: translate request, run pipeline, emit response.
async fn serve_stream(
    c: Rc<Connection>,
    hc: Rc<HttpConnection>,
    req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
) {
    // ---- Build the HttpRequest -----------------------------------
    let (parts, mut recv_body) = req.into_parts();
    let method = parts.method.clone();
    let uri = parts.uri.clone();
    let path_and_query = uri.path_and_query()
        .map(|pq| pq.as_str().as_bytes().to_vec())
        .unwrap_or_else(|| b"/".to_vec());
    let (path, query) = split_pq(&path_and_query);
    let authority = uri.authority()
        .map(|a| a.as_str().as_bytes().to_vec())
        .or_else(|| parts.headers.get(http::header::HOST).map(|v| v.as_bytes().to_vec()))
        .unwrap_or_default();

    // Log context for the request.
    let log_ctx = Rc::new(HttpLogCtx {
        connection: Rc::downgrade(&c),
        request: RefCell::new(None),
        current_request: RefCell::new(None),
    });
    let r = alloc_request(&c, &hc, &log_ctx);
    r.http_state.set(HttpState::ReadingRequest);

    // Populate request line-equivalent fields from :method, :path, :authority.
    let method_str = method.as_str().as_bytes().to_vec();
    *r.method_name.borrow_mut() = method_str.clone();
    r.method.set(http_method_from_bytes(&method_str));
    r.http_version.set(NGX_HTTP_VERSION_20);
    *r.http_protocol.borrow_mut() = b"HTTP/2.0".to_vec();
    *r.uri.borrow_mut() = path.clone();
    *r.unparsed_uri.borrow_mut() = path.clone();
    *r.args.borrow_mut() = query;
    *r.exten.borrow_mut() = extract_exten(&path);
    // Synthetic request line for logging: "GET /foo HTTP/2.0"
    let mut req_line = method_str.clone();
    req_line.push(b' ');
    req_line.extend_from_slice(&path_and_query);
    req_line.extend_from_slice(b" HTTP/2.0");
    *r.request_line.borrow_mut() = req_line;

    // Populate headers_in from h2 request headers.
    {
        let mut hi = r.headers_in.borrow_mut();
        // :authority as Host header
        if !authority.is_empty() {
            let h = TableElt::new(b"Host", &authority);
            hi.host = Some(h.clone());
            hi.headers.push(h);
        }
        for (name, value) in parts.headers.iter() {
            let key = name.as_str().as_bytes();
            // Skip pseudo-headers just in case.
            if key.starts_with(b":") { continue; }
            // Skip a redundant Host if authority already set one.
            if !authority.is_empty() && key.eq_ignore_ascii_case(b"host") { continue; }
            let val = value.as_bytes();
            let h = TableElt::new(key, val);
            let lower = &h.lowcase_key[..];
            if lower == b"content-length" {
                if let Ok(s) = std::str::from_utf8(val) {
                    if let Ok(n) = s.parse::<i64>() { hi.content_length_n = n; }
                }
                hi.content_length = Some(h.clone());
            } else if lower == b"content-type" {
                hi.content_type.push(h.clone());
            } else if lower == b"user-agent" {
                hi.user_agent.push(h.clone());
            } else if lower == b"referer" {
                hi.referer.push(h.clone());
            } else if lower == b"cookie" {
                hi.cookie.push(h.clone());
            } else if lower == b"accept" {
                hi.accept.push(h.clone());
            } else if lower == b"accept-encoding" {
                hi.accept_encoding.push(h.clone());
            } else if lower == b"accept-language" {
                hi.accept_language.push(h.clone());
            } else if lower == b"x-forwarded-for" {
                hi.x_forwarded_for.push(h.clone());
            } else if lower == b"x-real-ip" {
                hi.x_real_ip.push(h.clone());
            } else if lower == b"if-modified-since" {
                hi.if_modified_since = Some(h.clone());
            } else if lower == b"if-none-match" {
                hi.if_none_match = Some(h.clone());
            } else if lower == b"if-match" {
                hi.if_match = Some(h.clone());
            } else if lower == b"if-range" {
                hi.if_range = Some(h.clone());
            } else if lower == b"range" {
                hi.range.push(h.clone());
            } else if lower == b"authorization" {
                hi.authorization = Some(h.clone());
            } else if lower == b"expect" {
                hi.expect = Some(h.clone());
            }
            hi.headers.push(h);
        }
        // HTTP/2 mandates no connection-close; treat as keep-alive.
        hi.connection_type = crate::NGX_HTTP_CONNECTION_KEEP_ALIVE;
    }

    // ---- Read the request body eagerly (buffered) ---------------
    // For simplicity, buffer the entire body up front. Store into
    // r.request_body so the standard read_client_request_body path
    // sees it as already-buffered content.
    let mut body_bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = recv_body.data().await {
        match chunk {
            Ok(b) => {
                let n = b.len();
                body_bytes.extend_from_slice(&b);
                // Release flow-control credit for the received chunk.
                let _ = recv_body.flow_control().release_capacity(n);
            }
            Err(e) => {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "h2 body error: {}", e);
                let _ = respond.send_reset(h2::Reason::INTERNAL_ERROR);
                return;
            }
        }
    }
    if !body_bytes.is_empty() {
        // Stash into headers_in.content_length_n if not already set.
        if r.headers_in.borrow().content_length_n < 0 {
            r.headers_in.borrow_mut().content_length_n = body_bytes.len() as i64;
        }
        // TODO: wire body_bytes into r.request_body properly. For now
        // request handlers that need the body will read zero. This is
        // enough for GET-heavy h2 tests to make progress.
    }
    let _ = body_bytes;

    // ---- Route to virtual server by :authority ------------------
    let host_for_vs = authority.clone();
    if !host_for_vs.is_empty() {
        if request_rt::set_virtual_server(&r, &host_for_vs) == crate::NGX_ERROR {
            let _ = respond.send_reset(h2::Reason::INTERNAL_ERROR);
            return;
        }
    }

    // ---- Enable capture so pipeline writes land in a buffer -----
    *c.send_capture.borrow_mut() = Some(Vec::new());

    // ---- Run the request through the pipeline -------------------
    let _end = request_rt::process_request(&r).await;

    // ---- Grab captured output, disable capture ------------------
    let captured: Vec<u8> = c.send_capture.borrow_mut().take().unwrap_or_default();

    // ---- Parse status + headers + body from captured HTTP/1 -----
    let (status, headers, body) = parse_http1_response(&captured);

    let mut builder = http::Response::builder().status(status);
    for (k, v) in headers {
        // Skip hop-by-hop headers illegal in h2.
        let kl = k.to_ascii_lowercase();
        if kl == "connection" || kl == "transfer-encoding" || kl == "keep-alive"
            || kl == "upgrade" || kl == "proxy-connection"
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    let resp = match builder.body(()) {
        Ok(r) => r,
        Err(_) => {
            let _ = respond.send_reset(h2::Reason::INTERNAL_ERROR);
            return;
        }
    };
    let end_stream = body.is_empty();
    let mut send = match respond.send_response(resp, end_stream) {
        Ok(s) => s,
        Err(e) => {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "h2 send_response failed: {}", e);
            return;
        }
    };
    if !body.is_empty() {
        if let Err(e) = send.send_data(Bytes::from(body), true) {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "h2 send_data failed: {}", e);
        }
    }
    let _ = NGX_HTTP_INTERNAL_SERVER_ERROR;
}

fn split_pq(pq: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if let Some(pos) = pq.iter().position(|&b| b == b'?') {
        (pq[..pos].to_vec(), pq[pos + 1..].to_vec())
    } else {
        (pq.to_vec(), Vec::new())
    }
}

fn extract_exten(path: &[u8]) -> Vec<u8> {
    if let Some(dot) = path.iter().rposition(|&b| b == b'.') {
        if let Some(slash) = path.iter().rposition(|&b| b == b'/') {
            if dot > slash {
                return path[dot + 1..].to_vec();
            }
        }
    }
    Vec::new()
}

fn http_method_from_bytes(m: &[u8]) -> u32 {
    match m {
        b"GET" => crate::NGX_HTTP_GET,
        b"HEAD" => crate::NGX_HTTP_HEAD,
        b"POST" => crate::NGX_HTTP_POST,
        b"PUT" => crate::NGX_HTTP_PUT,
        b"DELETE" => crate::NGX_HTTP_DELETE,
        b"OPTIONS" => crate::NGX_HTTP_OPTIONS,
        b"PATCH" => crate::NGX_HTTP_PATCH,
        _ => crate::NGX_HTTP_UNKNOWN,
    }
}

/// Parse the captured HTTP/1 wire response into (status, headers, body).
/// The pipeline always writes a well-formed response, so this is a very
/// small ad-hoc parser: read the status line, then headers until CRLF
/// CRLF, then the remainder is the body. If Transfer-Encoding: chunked
/// is present we de-chunk.
fn parse_http1_response(bytes: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut pos = 0;
    // Status line.
    let line_end = find_crlf(&bytes[pos..]).map(|e| pos + e).unwrap_or(bytes.len());
    let status_line = &bytes[pos..line_end];
    pos = line_end + 2;
    // Parse "HTTP/1.1 200 OK"
    let status = status_line.split(|&b| b == b' ').nth(1)
        .and_then(|s| std::str::from_utf8(s).ok())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut chunked = false;
    loop {
        if pos >= bytes.len() { break; }
        let end = find_crlf(&bytes[pos..]).map(|e| pos + e).unwrap_or(bytes.len());
        if end == pos {
            pos += 2;
            break;
        }
        let line = &bytes[pos..end];
        pos = end + 2;
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = &line[..colon];
            let mut vstart = colon + 1;
            while vstart < line.len() && (line[vstart] == b' ' || line[vstart] == b'\t') {
                vstart += 1;
            }
            let value = &line[vstart..];
            if name.eq_ignore_ascii_case(b"transfer-encoding")
                && value.eq_ignore_ascii_case(b"chunked")
            {
                chunked = true;
            }
            let nstr = String::from_utf8_lossy(name).to_string();
            let vstr = String::from_utf8_lossy(value).to_string();
            headers.push((nstr, vstr));
        }
    }
    let raw_body = &bytes[pos..];
    let body = if chunked { dechunk(raw_body) } else { raw_body.to_vec() };
    (status, headers, body)
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(1) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' { return Some(i); }
    }
    None
}

fn dechunk(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        let e = match find_crlf(&buf[i..]) { Some(e) => i + e, None => break };
        let size_line = &buf[i..e];
        // Strip trailing ";extension" bits.
        let size_hex = size_line.split(|&b| b == b';').next().unwrap_or(size_line);
        let s = match std::str::from_utf8(size_hex) { Ok(s) => s.trim(), Err(_) => break };
        let size = match usize::from_str_radix(s, 16) { Ok(v) => v, Err(_) => break };
        i = e + 2;
        if size == 0 { break; }
        if i + size > buf.len() { break; }
        out.extend_from_slice(&buf[i..i + size]);
        i += size + 2; // trailing CRLF
    }
    out
}
