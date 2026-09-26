//! HTTP connection and request lifecycle (ngx_http_request.c), async style.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::connection::{Connection, TcpNopush};
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_error};

use crate::core::*;
use crate::parse;
use crate::request::*;
use crate::*;

static CLIENT_ERRORS: [&str; 4] = ["client sent invalid method", "client sent invalid request", "client sent invalid version", "client sent invalid method in HTTP/0.9 request"];

thread_local! {
    static PENDING_FINALIZE: Cell<i64> = const { Cell::new(0) };
}

/// Header handlers can't finalize directly; they record the status here.
pub fn set_pending_finalize(_r: &R, rc: i64) {
    PENDING_FINALIZE.with(|p| p.set(rc));
}

fn take_pending_finalize() -> i64 {
    PENDING_FINALIZE.with(|p| p.replace(0))
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum End {
    Keepalive,
    Lingering,
    Close,
}

/// Listening socket handler: start the connection task.
pub fn init_connection(c: Rc<Connection>) {
    ngx_core::event::spawn(async move {
        connection_task(c).await;
    });
}

fn addr_conf_for(c: &Rc<Connection>) -> Option<Rc<AddrConf>> {
    let ls = c.listening.clone()?;
    let servers = ls.servers.borrow().clone()?;
    let port = servers.downcast::<HttpPort>().ok()?;
    if port.naddrs > 1 {
        let local = c.local_sockaddr()?;
        let ip = local.ip_bytes();
        for (i, (addr, conf)) in port.addrs.iter().enumerate() {
            if i == port.naddrs - 1 || *addr == ip {
                return Some(conf.clone());
            }
        }
        return port.addrs.last().map(|(_, c)| c.clone());
    }
    port.addrs.first().map(|(_, c)| c.clone())
}

async fn connection_task(c: Rc<Connection>) {
    let addr_conf = match addr_conf_for(&c) {
        Some(a) => a,
        None => {
            c.close();
            return;
        }
    };
    let conf_ctx = addr_conf.default_server.borrow().ctx.clone();
    let cscf = srv_conf_from_ctx(&conf_ctx);
    let hb_size = *cscf.borrow().client_header_buffer_size;
    let hc = Rc::new(HttpConnection {
        addr_conf: addr_conf.clone(),
        conf_ctx: std::cell::RefCell::new(conf_ctx),
        ssl: Cell::new(false),
        proxy_protocol: Cell::new(false),
        ssl_servername: std::cell::RefCell::new(None),
        ssl_servername_regex: std::cell::RefCell::new(None),
        keepalive_timeout: Cell::new(0),
        buffer: std::cell::RefCell::new(HeaderBuf { data: Vec::new(), pos: 0, last: 0, allocated: false, cap: hb_size, nbusy: 0 }),
        nbusy: Cell::new(0),
    });
    let log_ctx = Rc::new(HttpLogCtx { connection: Rc::downgrade(&c), request: std::cell::RefCell::new(None), current_request: std::cell::RefCell::new(None) });
    c.log.set_context(Some(log_ctx.clone()));
    c.log.set_action(Some("waiting for request"));
    let hc_any: Rc<dyn std::any::Any> = hc.clone();
    *c.data.borrow_mut() = Some(hc_any);

    if addr_conf.ssl {
        hc.ssl.set(true);
        c.log.set_action(Some("SSL handshaking"));
        if !crate::stubs::ssl_handshake(&c, &hc).await {
            close_connection(&c);
            return;
        }
    }
    if addr_conf.proxy_protocol {
        hc.proxy_protocol.set(true);
        c.log.set_action(Some("reading PROXY protocol"));
    }

    let mut first = true;
    loop {
        if first {
            first = false;
            if wait_request(&c, &hc).await.is_err() {
                close_connection(&c);
                return;
            }
        }
        c.log.set_action(Some("reading client request line"));
        c.set_reusable(false);
        let r = create_request(&c, &hc, &log_ctx);
        let end = run_request(&r).await;
        match end {
            End::Keepalive => {
                if keepalive(&r, &hc).await.is_err() {
                    close_connection(&c);
                    return;
                }
                // next request: either pipelined data or freshly read data is in the buffer
            }
            End::Lingering => {
                lingering_close(&r).await;
                close_request_final(&r);
                close_connection(&c);
                return;
            }
            End::Close => {
                close_request_final(&r);
                close_connection(&c);
                return;
            }
        }
    }
}

/// ngx_http_close_connection
pub fn close_connection(c: &Rc<Connection>) {
    http_debug_c(c, "close http connection");
    c.close();
}

fn http_debug_c(c: &Connection, msg: &str) {
    if c.log.debug_enabled(NGX_LOG_DEBUG_HTTP) {
        c.log.error(NGX_LOG_DEBUG, None, format_args!("{}", msg));
    }
}

/// ngx_http_wait_request_handler: read the first bytes of a connection.
async fn wait_request(c: &Rc<Connection>, hc: &Rc<HttpConnection>) -> Result<(), ()> {
    let cscf = srv_conf_from_ctx(&hc.conf_ctx.borrow());
    let timeout = *cscf.borrow().client_header_timeout;
    let size = *cscf.borrow().client_header_buffer_size;
    loop {
        http_debug_c(c, "http wait request handler");
        {
            let mut b = hc.buffer.borrow_mut();
            if b.data.len() < size {
                b.data.resize(size, 0);
            }
            b.cap = size;
        }
        c.set_reusable(true);
        let n = {
            let mut buf = vec![0u8; size];
            let res = tokio::select! {
                r = tokio::time::timeout(Duration::from_millis(timeout), c.recv(&mut buf)) => r,
                _ = c.close_notify.notified() => {
                    close_connection(c);
                    return Err(());
                }
            };
            match res {
                Err(_) => {
                    ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
                    return Err(());
                }
                Ok(Err(_)) => return Err(()),
                Ok(Ok(0)) => {
                    ngx_log_error!(NGX_LOG_INFO, c.log, None, "client closed connection");
                    return Err(());
                }
                Ok(Ok(n)) => {
                    let mut b = hc.buffer.borrow_mut();
                    let last = b.last;
                    b.data[last..last + n].copy_from_slice(&buf[..n]);
                    b.last += n;
                    n
                }
            }
        };
        let _ = n;
        if c.close.get() {
            return Err(());
        }
        if hc.proxy_protocol.get() {
            hc.proxy_protocol.set(false);
            let data = hc.buffer.borrow().unread().to_vec();
            match ngx_core::proxy_protocol::read(&c.log, &data) {
                Err(()) => return Err(()),
                Ok((pp, consumed)) => {
                    *c.proxy_protocol.borrow_mut() = Some(Rc::new(pp));
                    let mut b = hc.buffer.borrow_mut();
                    b.pos += consumed;
                    if b.pos == b.last {
                        c.log.set_action(Some("waiting for request"));
                        b.pos = 0;
                        b.last = 0;
                        drop(b);
                        continue;
                    }
                }
            }
        }
        return Ok(());
    }
}

// ---------------------------------------------------------------------------
// reading the request line and headers

/// Ensure unread data exists in the header buffer, reading more if needed.
/// Returns Ok(true) when data is available, Ok(false) if the buffer is full (caller must grow).
async fn read_request_header(r: &R, deadline: &mut Option<tokio::time::Instant>) -> Result<bool, i64> {
    let c = &r.connection;
    let hc = &r.http_connection;
    {
        let b = hc.buffer.borrow();
        if b.pos < b.last {
            return Ok(true);
        }
        if b.last >= b.cap {
            return Ok(false);
        }
    }
    let cscf = r.cscf();
    let timeout = *cscf.borrow().client_header_timeout;
    if deadline.is_none() {
        *deadline = Some(tokio::time::Instant::now() + Duration::from_millis(timeout));
    }
    let dl = deadline.unwrap();
    let cap = hc.buffer.borrow().cap;
    let last = hc.buffer.borrow().last;
    let mut tmp = vec![0u8; cap - last];
    let res = tokio::time::timeout_at(dl, c.recv(&mut tmp)).await;
    match res {
        Err(_) => {
            ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
            c.timedout.set(true);
            Err(NGX_HTTP_REQUEST_TIME_OUT)
        }
        Ok(Ok(0)) => {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client prematurely closed connection");
            c.error.set(true);
            c.log.set_action(Some("reading client request headers"));
            Err(NGX_HTTP_BAD_REQUEST)
        }
        Ok(Err(_)) => {
            c.error.set(true);
            c.log.set_action(Some("reading client request headers"));
            Err(NGX_HTTP_BAD_REQUEST)
        }
        Ok(Ok(n)) => {
            let mut b = hc.buffer.borrow_mut();
            let last = b.last;
            b.data[last..last + n].copy_from_slice(&tmp[..n]);
            b.last += n;
            r.request_length.set(r.request_length.get());
            Ok(true)
        }
    }
}

/// ngx_http_alloc_large_header_buffer: returns OK, DECLINED (too large) or ERROR.
fn alloc_large_header_buffer(r: &R, request_line: bool) -> i64 {
    http_debug!(r, "http alloc large header buffer");
    let hc = &r.http_connection;
    let mut b = hc.buffer.borrow_mut();
    let mut p = r.parse.borrow_mut();
    if request_line && p.state == 0 {
        b.pos = 0;
        b.last = 0;
        return NGX_OK;
    }
    let old = if request_line { p.request_start } else { p.header_name_start };
    let cscf = r.cscf();
    let large = cscf.borrow().large_client_header_buffers;
    if p.state != 0 && b.pos - old >= large.size {
        return NGX_DECLINED;
    }
    if b.nbusy >= large.num {
        return NGX_DECLINED;
    }
    b.nbusy += 1;
    if p.state == 0 {
        // new empty large buffer
        b.data = vec![0u8; large.size];
        b.cap = large.size;
        b.pos = 0;
        b.last = 0;
        return NGX_OK;
    }
    let len = b.last - old;
    http_debug!(r, "http large header copy: {}", b.pos - old);
    if len > large.size {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "too large header to copy");
        return NGX_ERROR;
    }
    let mut nd = vec![0u8; large.size];
    nd[..len].copy_from_slice(&b.data[old..b.last]);
    let newpos = b.pos - old;
    b.data = nd;
    b.cap = large.size;
    b.pos = newpos;
    b.last = len;
    // rebase parser offsets
    let rb = |v: &mut usize| {
        if *v >= old {
            *v -= old;
        } else {
            *v = 0;
        }
    };
    let rbo = |v: &mut Option<usize>| {
        if let Some(x) = v {
            if *x >= old {
                *x -= old;
            }
        }
    };
    if request_line {
        rb(&mut p.request_start);
        rb(&mut p.request_end);
        rb(&mut p.method_end);
        rbo(&mut p.uri_start);
        rbo(&mut p.uri_end);
        rbo(&mut p.schema_start);
        rbo(&mut p.schema_end);
        rbo(&mut p.host_start);
        rbo(&mut p.host_end);
        rbo(&mut p.port_start);
        rbo(&mut p.port_end);
        rbo(&mut p.uri_ext);
        rbo(&mut p.args_start);
        rbo(&mut p.http_protocol_start);
    } else {
        rb(&mut p.header_name_start);
        rb(&mut p.header_name_end);
        rb(&mut p.header_start);
        rb(&mut p.header_end);
    }
    NGX_OK
}

/// Runs a whole request: parse, phases, finalize. Returns how the connection continues.
async fn run_request(r: &R) -> End {
    let c = r.connection.clone();
    let hc = r.http_connection.clone();
    let mut deadline: Option<tokio::time::Instant> = None;

    // --- request line ---
    http_debug!(r, "http process request line");
    let mut rc = NGX_AGAIN;
    loop {
        if rc == NGX_AGAIN {
            match read_request_header(r, &mut deadline).await {
                Ok(true) => {}
                Ok(false) => {
                    let rv = alloc_large_header_buffer(r, true);
                    if rv == NGX_ERROR {
                        return close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR).await;
                    }
                    if rv == NGX_DECLINED {
                        let line = {
                            let b = hc.buffer.borrow();
                            let p = r.parse.borrow();
                            b.data[p.request_start..b.last.min(b.cap)].to_vec()
                        };
                        *r.request_line.borrow_mut() = line;
                        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent too long URI");
                        return finalize_and_end(r, NGX_HTTP_REQUEST_URI_TOO_LARGE).await;
                    }
                    continue;
                }
                Err(status) => {
                    if status == NGX_HTTP_REQUEST_TIME_OUT {
                        return close_request(r, status).await;
                    }
                    return finalize_and_end(r, status).await;
                }
            }
        }
        rc = {
            let mut b = hc.buffer.borrow_mut();
            let mut p = r.parse.borrow_mut();
            let mut pos = b.pos;
            let data = std::mem::take(&mut b.data);
            let last = b.last;
            let rc = parse::parse_request_line(&mut p, &data[..last], &mut pos);
            b.data = data;
            b.pos = pos;
            rc
        };
        if rc == NGX_OK {
            {
                let b = hc.buffer.borrow();
                let p = r.parse.borrow();
                let line = b.data[p.request_start..p.request_end].to_vec();
                r.request_length.set((b.pos - p.request_start) as i64);
                http_debug!(r, "http request line: \"{}\"", B(&line));
                *r.method_name.borrow_mut() = b.data[p.request_start..p.method_end + 1].to_vec();
                if let Some(hp) = p.http_protocol_start {
                    *r.http_protocol.borrow_mut() = b.data[hp..p.request_end].to_vec();
                }
                r.method.set(p.method);
                r.http_version.set(p.http_version);
                *r.request_line.borrow_mut() = line;
            }
            if process_request_uri(r).await.is_err() {
                return finalize_and_end(r, NGX_HTTP_BAD_REQUEST).await;
            }
            let (schema, host) = {
                let b = hc.buffer.borrow();
                let p = r.parse.borrow();
                let schema = match (p.schema_start, p.schema_end) {
                    (Some(s), Some(e)) => Some(b.data[s..e].to_vec()),
                    _ => None,
                };
                let host = match (p.host_start, p.host_end) {
                    (Some(s), Some(e)) => Some(b.data[s..e].to_vec()),
                    _ => None,
                };
                (schema, host)
            };
            if let Some(s) = schema {
                *r.schema.borrow_mut() = s;
            }
            if let Some(h) = host {
                match validate_host(&h, false) {
                    Ok((host, port)) => {
                        if set_virtual_server(r, &host) == NGX_ERROR {
                            return close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR).await;
                        }
                        r.headers_in.borrow_mut().server = host;
                        r.port.set(port);
                    }
                    Err(_) => {
                        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent invalid host in request line");
                        return finalize_and_end(r, NGX_HTTP_BAD_REQUEST).await;
                    }
                }
            }
            if r.http_version.get() < NGX_HTTP_VERSION_10 {
                if r.headers_in.borrow().server.is_empty() {
                    let s = Vec::new();
                    if set_virtual_server(r, &s) == NGX_ERROR {
                        return close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR).await;
                    }
                }
                return process_request(r).await;
            }
            c.log.set_action(Some("reading client request headers"));
            break;
        }
        if rc != NGX_AGAIN {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "{}", CLIENT_ERRORS[(rc - NGX_HTTP_CLIENT_ERROR) as usize]);
            if rc == NGX_HTTP_PARSE_INVALID_VERSION {
                return finalize_and_end(r, NGX_HTTP_VERSION_NOT_SUPPORTED).await;
            }
            return finalize_and_end(r, NGX_HTTP_BAD_REQUEST).await;
        }
    }

    // --- headers ---
    let cscf = r.cscf();
    let (underscores, ignore_invalid, max_headers) = {
        let s = cscf.borrow();
        (*s.underscores_in_headers, *s.ignore_invalid_headers, *s.max_headers)
    };
    let cmcf = r.cmcf();
    let mut rc = NGX_AGAIN;
    loop {
        if rc == NGX_AGAIN {
            match read_request_header(r, &mut deadline).await {
                Ok(true) => {}
                Ok(false) => {
                    let rv = alloc_large_header_buffer(r, false);
                    if rv == NGX_ERROR {
                        return close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR).await;
                    }
                    if rv == NGX_DECLINED {
                        r.lingering_close.set(true);
                        let (start, data) = {
                            let b = hc.buffer.borrow();
                            let p = r.parse.borrow();
                            (p.header_name_start, b.data[..b.last].to_vec())
                        };
                        if r.parse.borrow().state == 0 {
                            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent too large request");
                            return finalize_and_end(r, NGX_HTTP_REQUEST_HEADER_TOO_LARGE).await;
                        }
                        let mut len = data.len() - start;
                        if len > NGX_MAX_ERROR_STR - 300 {
                            len = NGX_MAX_ERROR_STR - 300;
                        }
                        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent too long header line: \"{}...\"", B(&data[start..start + len]));
                        return finalize_and_end(r, NGX_HTTP_REQUEST_HEADER_TOO_LARGE).await;
                    }
                    continue;
                }
                Err(status) => {
                    if status == NGX_HTTP_REQUEST_TIME_OUT {
                        return close_request(r, status).await;
                    }
                    return finalize_and_end(r, status).await;
                }
            }
        }
        rc = {
            let mut b = hc.buffer.borrow_mut();
            let mut p = r.parse.borrow_mut();
            let mut pos = b.pos;
            let data = std::mem::take(&mut b.data);
            let last = b.last;
            let rc = parse::parse_header_line(&mut p, &data[..last], &mut pos, underscores);
            b.data = data;
            b.pos = pos;
            rc
        };
        if rc == NGX_OK {
            let (key, value, hash, lowcase, invalid, name_start, header_end) = {
                let b = hc.buffer.borrow();
                let p = r.parse.borrow();
                r.request_length.set(r.request_length.get() + (b.pos - p.header_name_start) as i64);
                let key = b.data[p.header_name_start..p.header_name_end].to_vec();
                let value = b.data[p.header_start..p.header_end].to_vec();
                let lowcase = if key.len() == p.lowcase_index { p.lowcase_header[..key.len()].to_vec() } else { ngx_core::string::to_lower_vec(&key) };
                (key, value, p.header_hash, lowcase, p.invalid_header, p.header_name_start, p.header_end)
            };
            if invalid && ignore_invalid {
                let b = hc.buffer.borrow();
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent invalid header line: \"{}\"", B(&b.data[name_start..header_end]));
                continue;
            }
            let count = {
                let mut hin = r.headers_in.borrow_mut();
                let cnt = hin.count;
                hin.count += 1;
                cnt
            };
            if count as i64 >= max_headers {
                r.lingering_close.set(true);
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent too many header lines");
                return finalize_and_end(r, NGX_HTTP_REQUEST_HEADER_TOO_LARGE).await;
            }
            let h = TableElt::with_hash(&key, &value, hash, lowcase.clone());
            r.headers_in.borrow_mut().headers.push(h.clone());
            let handler = {
                let m = cmcf.borrow();
                m.headers_in_hash.as_ref().and_then(|hh| hh.find(hash, &lowcase).copied())
            };
            if let Some(f) = handler {
                if f(r, h.clone()) != NGX_OK {
                    let pending = take_pending_finalize();
                    if pending != 0 {
                        return finalize_and_end(r, pending).await;
                    }
                    return close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR).await;
                }
            }
            http_debug!(r, "http header: \"{}: {}\"", B(&h.key), B(&h.value.borrow()));
            continue;
        }
        if rc == NGX_HTTP_PARSE_HEADER_DONE {
            http_debug!(r, "http header done");
            {
                let b = hc.buffer.borrow();
                let p = r.parse.borrow();
                r.request_length.set(r.request_length.get() + (b.pos - p.header_name_start) as i64);
            }
            r.http_state.set(HttpState::ProcessRequest);
            let rc = crate::request_headers::process_request_header(r);
            if rc != NGX_OK {
                let pending = take_pending_finalize();
                if pending != 0 {
                    return finalize_and_end(r, pending).await;
                }
                return close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR).await;
            }
            return process_request(r).await;
        }
        if rc == NGX_AGAIN {
            continue;
        }
        {
            let b = hc.buffer.borrow();
            let p = r.parse.borrow();
            let end = p.header_end.min(b.last);
            let ch = b.data.get(end).copied().unwrap_or(0);
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent invalid header line: \"{}\\x{:02X}...\"", B(&b.data[p.header_name_start..end]), ch);
        }
        return finalize_and_end(r, NGX_HTTP_BAD_REQUEST).await;
    }
}

/// ngx_http_process_request_uri
async fn process_request_uri(r: &R) -> Result<(), ()> {
    let hc = &r.http_connection;
    let (uri, unparsed, exten, args, complex, merge_slashes) = {
        let b = hc.buffer.borrow();
        let p = r.parse.borrow();
        let us = p.uri_start.unwrap_or(0);
        let ue = p.uri_end.unwrap_or(us);
        let uri_len = match p.args_start {
            Some(a) => a - 1 - us,
            None => ue - us,
        };
        let unparsed = b.data[us..ue].to_vec();
        let exten = p.uri_ext.map(|x| match p.args_start {
            Some(a) => b.data[x..a - 1].to_vec(),
            None => b.data[x..ue].to_vec(),
        });
        let args = match p.args_start {
            Some(a) if ue > a => b.data[a..ue].to_vec(),
            _ => Vec::new(),
        };
        let complex = p.complex_uri || p.quoted_uri || p.empty_path_in_uri;
        let cscf = r.cscf();
        let ms = *cscf.borrow().merge_slashes;
        (b.data[us..us + uri_len].to_vec(), unparsed, exten, args, complex, ms)
    };
    if complex {
        let res = {
            let b = hc.buffer.borrow();
            let p = r.parse.borrow();
            parse::parse_complex_uri(&p, &b.data[..b.last], merge_slashes)
        };
        match res {
            Ok(cu) => {
                *r.uri.borrow_mut() = cu.uri;
                *r.args.borrow_mut() = cu.args.unwrap_or_default();
                *r.exten.borrow_mut() = cu.exten.unwrap_or_default();
            }
            Err(_) => {
                r.uri.borrow_mut().clear();
                ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid request");
                return Err(());
            }
        }
    } else {
        *r.uri.borrow_mut() = uri;
        *r.exten.borrow_mut() = exten.unwrap_or_default();
        *r.args.borrow_mut() = args;
    }
    let p = r.parse.borrow();
    r.complex_uri.set(p.complex_uri);
    r.quoted_uri.set(p.quoted_uri);
    r.plus_in_uri.set(p.plus_in_uri);
    r.empty_path_in_uri.set(p.empty_path_in_uri);
    drop(p);
    *r.unparsed_uri.borrow_mut() = unparsed;
    r.valid_unparsed_uri.set(!r.empty_path_in_uri.get());
    http_debug!(r, "http uri: \"{}\"", B(&r.uri.borrow()));
    http_debug!(r, "http args: \"{}\"", B(&r.args.borrow()));
    http_debug!(r, "http exten: \"{}\"", B(&r.exten.borrow()));
    Ok(())
}

/// ngx_http_validate_host: returns (lowercased host without port, port).
pub fn validate_host(host: &[u8], _alloc: bool) -> Result<(Vec<u8>, u16), ()> {
    #[derive(PartialEq, Clone, Copy)]
    enum St {
        HostStart,
        Host,
        IpLiteral,
        HostEnd,
        Port,
    }
    let mut dot_pos = host.len();
    let mut host_len = host.len();
    let mut port: u32 = 0;
    let mut state = St::HostStart;
    let mut need_lower = false;
    for (i, &ch) in host.iter().enumerate() {
        match state {
            St::HostStart | St::Host => {
                if state == St::HostStart {
                    if ch == b'[' {
                        state = St::IpLiteral;
                        continue;
                    }
                    state = St::Host;
                }
                if ch.is_ascii_uppercase() {
                    need_lower = true;
                    continue;
                }
                if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                    continue;
                }
                match ch {
                    b':' => {
                        host_len = i;
                        state = St::Port;
                    }
                    b'-' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b'%' => {}
                    b'.' => {
                        if dot_pos + 1 == i {
                            return Err(());
                        }
                        dot_pos = i;
                    }
                    _ => return Err(()),
                }
            }
            St::IpLiteral => {
                if ch.is_ascii_uppercase() {
                    need_lower = true;
                    continue;
                }
                if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                    continue;
                }
                match ch {
                    b':' => {}
                    b']' => {
                        host_len = i + 1;
                        state = St::HostEnd;
                    }
                    b'-' | b'_' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' => {}
                    b'.' => {
                        if dot_pos + 1 == i {
                            return Err(());
                        }
                        dot_pos = i;
                    }
                    _ => return Err(()),
                }
            }
            St::HostEnd => {
                if ch == b':' {
                    state = St::Port;
                    continue;
                }
                return Err(());
            }
            St::Port => {
                if ch.is_ascii_digit() {
                    let d = (ch - b'0') as u32;
                    if port >= 6553 && (port > 6553 || d > 5) {
                        return Err(());
                    }
                    port = port * 10 + d;
                    continue;
                }
                return Err(());
            }
        }
    }
    if state == St::IpLiteral {
        return Err(());
    }
    if dot_pos + 1 == host_len {
        host_len -= 1;
    }
    if host_len == 0 {
        return Err(());
    }
    let h = if need_lower { ngx_core::string::to_lower_vec(&host[..host_len]) } else { host[..host_len].to_vec() };
    Ok((h, port as u16))
}

/// ngx_http_set_virtual_server
pub fn set_virtual_server(r: &R, host: &[u8]) -> i64 {
    let hc = r.http_connection.clone();
    if let Some(sn) = hc.ssl_servername.borrow().as_ref() {
        if sn == host {
            if let Some(re) = hc.ssl_servername_regex.borrow().as_ref() {
                if crate::variables::regex_exec(r, re, sn) != NGX_OK {
                    return NGX_ERROR;
                }
            }
            return NGX_OK;
        }
    }
    let vn = hc.addr_conf.virtual_names.clone();
    let (rc, cscf) = find_virtual_server(r, vn.as_ref(), host);
    if rc == NGX_ERROR {
        return NGX_ERROR;
    }
    let mut cscf = cscf;
    let mut rc = rc;
    if hc.ssl_servername.borrow().is_some() {
        if rc == NGX_DECLINED {
            cscf = Some(hc.addr_conf.default_server.clone());
            rc = NGX_OK;
        }
        if crate::stubs::ssl_verify_enabled(cscf.as_ref().unwrap()) {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client attempted to request the server name different from the one that was negotiated");
            set_pending_finalize(r, NGX_HTTP_MISDIRECTED_REQUEST);
            return NGX_ERROR;
        }
    }
    if rc == NGX_DECLINED {
        return NGX_OK;
    }
    let cscf = cscf.unwrap();
    let ctx = cscf.borrow().ctx.clone();
    *r.srv_conf.borrow_mut() = ctx.srv.clone().unwrap();
    *r.loc_conf.borrow_mut() = ctx.loc.clone().unwrap();
    let clcf = r.clcf();
    r.connection.log.set_chain(clcf.borrow().error_log.clone().unwrap());
    NGX_OK
}

/// ngx_http_find_virtual_server
pub fn find_virtual_server(r: &R, vn: Option<&Rc<VirtualNames>>, host: &[u8]) -> (i64, Option<Rc<std::cell::RefCell<CoreSrvConf>>>) {
    let vn = match vn {
        Some(v) => v,
        None => return (NGX_DECLINED, None),
    };
    if let Some(c) = vn.names.find(ngx_core::hash::hash_key(host), host) {
        return (NGX_OK, Some(c.clone()));
    }
    if !host.is_empty() && !vn.regex.is_empty() {
        for sn in vn.regex.iter() {
            let n = crate::variables::regex_exec(r, &sn.regex, host);
            if n == NGX_DECLINED {
                continue;
            }
            if n == NGX_OK {
                return (NGX_OK, Some(sn.server.clone()));
            }
            return (NGX_ERROR, None);
        }
    }
    (NGX_DECLINED, None)
}

/// ngx_http_process_request: run the request after headers are complete.
async fn process_request(r: &R) -> End {
    let c = r.connection.clone();
    if r.http_connection.ssl.get() {
        if let Some(rc) = crate::stubs::ssl_process_request_checks(r) {
            return finalize_and_end(r, rc).await;
        }
    }
    ngx_core::connection::stats().reading.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    r.stat_reading.set(false);
    ngx_core::connection::stats().writing.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    r.stat_writing.set(true);
    if crate::request_body::read_early_body(r).await != NGX_OK {
        return finalize_connection(r).await;
    }
    let rc = handler(r.clone()).await;
    finalize_request(r, rc).await;
    let _ = c;
    finalize_connection(r).await
}

async fn finalize_and_end(r: &R, rc: i64) -> End {
    finalize_request(r, rc).await;
    finalize_connection(r).await
}

/// ngx_http_finalize_request
pub async fn finalize_request(r: &R, mut rc: i64) {
    let c = r.connection.clone();
    http_debug!(r, "http finalize request: {}, \"{}?{}\" a:{}, c:{}", rc, B(&r.uri.borrow()), B(&r.args.borrow()), 1, r.count.get());
    if rc == NGX_DONE {
        return;
    }
    if rc == NGX_OK && r.filter_finalize.get() {
        c.error.set(true);
    }
    if rc == NGX_DECLINED {
        *r.content_handler.borrow_mut() = None;
        let rc2 = Box::pin(run_phases(r.clone())).await;
        return Box::pin(finalize_request(r, rc2)).await;
    }
    if !r.is_main() {
        if let Some(ps) = r.post_subrequest.borrow().clone() {
            rc = ps(r, rc);
        }
    }
    if rc == NGX_ERROR || rc == NGX_HTTP_REQUEST_TIME_OUT || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST || c.error.get() {
        if post_action(r).await == NGX_OK {
            return;
        }
        terminate_request(r, rc);
        return;
    }
    if rc >= NGX_HTTP_SPECIAL_RESPONSE || rc == NGX_HTTP_CREATED || rc == NGX_HTTP_NO_CONTENT {
        if rc == NGX_HTTP_CLOSE {
            c.timedout.set(true);
            terminate_request(r, rc);
            return;
        }
        let rc2 = crate::special_response::special_response_handler(r, rc).await;
        return Box::pin(finalize_request(r, rc2)).await;
    }
    if !r.is_main() {
        // subrequest completion
        if !r.logged.get() {
            let clcf = r.clcf();
            if *clcf.borrow().log_subrequest {
                log_request(r);
            }
            r.logged.set(true);
        } else {
            ngx_log_error!(NGX_LOG_ALERT, c.log, None, "subrequest: \"{}?{}\" logged again", B(&r.uri.borrow()), B(&r.args.borrow()));
        }
        r.done.set(true);
        return;
    }
    r.done.set(true);
    if !r.post_action.get() {
        r.request_complete.set(true);
    }
    if post_action(r).await == NGX_OK {
        return;
    }
    // flush anything still buffered in the write filter
    if r.buffered.get() != 0 || !r.out.borrow().is_empty() {
        let _ = crate::write_filter::flush(r).await;
    }
}

/// ngx_http_terminate_request
pub fn terminate_request(r: &R, rc: i64) {
    let mr = r.main();
    http_debug!(r, "http terminate request count:{}", mr.count.get());
    mr.terminated.set(true);
    if rc > 0 {
        let mut ho = mr.headers_out.borrow_mut();
        if ho.status == 0 || mr.connection.sent.get() == 0 {
            ho.status = rc;
        }
    }
    mr.run_cleanups();
    http_debug!(r, "http terminate cleanup count:{} blk:{}", mr.count.get(), mr.blocked.get());
    mr.connection.error.set(true);
}

/// ngx_http_post_action
async fn post_action(r: &R) -> i64 {
    let clcf = r.clcf();
    let pa = clcf.borrow().post_action.clone();
    if pa.is_empty() {
        return NGX_DECLINED;
    }
    if r.post_action.get() && r.uri_changes.get() == 0 {
        return NGX_DECLINED;
    }
    http_debug!(r, "post action: \"{}\"", B(&pa));
    r.http_version.set(NGX_HTTP_VERSION_9);
    r.header_only.set(true);
    r.post_action.set(true);
    if pa[0] == b'/' {
        internal_redirect(r, &pa, None).await;
    } else {
        named_location(r, &pa).await;
    }
    NGX_OK
}

/// ngx_http_finalize_connection: decide what happens to the connection.
async fn finalize_connection(r: &R) -> End {
    let c = r.connection.clone();
    if r.terminated.get() || c.error.get() {
        return End::Close;
    }
    let clcf = r.clcf();
    if r.discard_body.get() && !r.discard_body_done.get() {
        // finish discarding the body with lingering limits
        if crate::request_body::discard_remaining_body(r).await.is_err() {
            return End::Close;
        }
    }
    if c.read_eof.get() {
        return End::Close;
    }
    if r.reading_body.get() {
        r.keepalive.set(false);
        r.lingering_close.set(true);
    }
    let (min_to, ka_to, lc) = {
        let cl = clcf.borrow();
        (*cl.keepalive_min_timeout, *cl.keepalive_timeout, *cl.lingering_close)
    };
    if r.keepalive.get() && min_to > 0 {
        return End::Keepalive;
    }
    let terminating = ngx_core::process::SIG_TERMINATE.load(std::sync::atomic::Ordering::SeqCst) || ngx_core::event::is_exiting();
    if !terminating && r.keepalive.get() && ka_to > 0 {
        return End::Keepalive;
    }
    let has_unread = {
        let b = r.http_connection.buffer.borrow();
        b.pos < b.last
    };
    if lc == NGX_HTTP_LINGERING_ALWAYS || (lc == NGX_HTTP_LINGERING_ON && (r.lingering_close.get() || has_unread || socket_has_data(&c) || c.pipeline.get())) {
        return End::Lingering;
    }
    End::Close
}

fn socket_has_data(c: &Connection) -> bool {
    let mut b = [0u8; 1];
    let n = unsafe { libc::recv(c.fd.get(), b.as_mut_ptr() as *mut libc::c_void, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
    n > 0
}

/// ngx_http_close_request for fatal paths before a response is produced.
async fn close_request(r: &R, rc: i64) -> End {
    if rc > 0 {
        let mut ho = r.headers_out.borrow_mut();
        if ho.status == 0 || r.connection.sent.get() == 0 {
            ho.status = rc;
        }
    }
    End::Close
}

/// ngx_http_free_request: log and release (called when the connection ends).
pub fn close_request_final(r: &R) {
    free_request(r, 0);
}

/// ngx_http_free_request
pub fn free_request(r: &R, rc: i64) {
    let log = r.connection.log.clone();
    http_debug!(r, "http close request");
    r.run_cleanups();
    if r.stat_reading.get() {
        ngx_core::connection::stats().reading.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        r.stat_reading.set(false);
    }
    if r.stat_writing.get() {
        ngx_core::connection::stats().writing.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        r.stat_writing.set(false);
    }
    if rc > 0 {
        let mut ho = r.headers_out.borrow_mut();
        if ho.status == 0 || r.connection.sent.get() == 0 {
            ho.status = rc;
        }
    }
    if !r.logged.get() {
        log.set_action(Some("logging request"));
        log_request(r);
        r.logged.set(true);
    }
    log.set_action(Some("closing request"));
    if r.connection.timedout.get() {
        let clcf = r.clcf();
        if *clcf.borrow().reset_timedout_connection {
            r.connection.set_linger_reset();
        }
    }
    *r.log_ctx.request.borrow_mut() = None;
    *r.log_ctx.current_request.borrow_mut() = None;
    r.request_line.borrow_mut().clear();
    r.connection.destroyed.set(true);
}

/// ngx_http_log_request: run log phase handlers.
pub fn log_request(r: &R) {
    // Finalize any upstream_states whose response_time we deliberately left
    // as u64::MAX at header-emit time. C's ngx_http_upstream_finalize_request
    // sets state->response_time = ngx_current_msec - u->start_time if it's
    // still -1, and that runs BEFORE the log phase — so $upstream_response_time
    // in access_log sees the real duration while an add_header referencing the
    // same variable saw "-". Approximate the same behavior by using
    // request-lifetime elapsed for the last state at log time.
    {
        let mut states = r.upstream_states.borrow_mut();
        if let Some(last) = states.last_mut() {
            if last.response_time == u64::MAX {
                // r.start_sec / start_msec store WALL-clock time (msec is
                // 0-999 subsecond portion). Compute elapsed against wall time
                // in the same way $request_time does.
                let now = ngx_core::times::cached();
                let elapsed_ms =
                    (now.sec - r.start_sec.get()) * 1000
                    + (now.msec as i64 - r.start_msec.get() as i64);
                last.response_time = elapsed_ms.max(0) as u64;
            }
        }
    }
    let cmcf = r.cmcf();
    let handlers = cmcf.borrow().log_handlers.clone();
    for h in handlers.iter() {
        h(r);
    }
}

/// ngx_http_set_keepalive + ngx_http_keepalive_handler: wait for the next request.
async fn keepalive(r: &R, hc: &Rc<HttpConnection>) -> Result<(), ()> {
    let c = r.connection.clone();
    let clcf = r.clcf();
    http_debug!(r, "set http keepalive handler");
    c.log.set_action(Some("closing request"));
    r.keepalive.set(false);
    free_request(r, 0);
    c.destroyed.set(false);
    {
        let b = hc.buffer.borrow();
        if b.pos < b.last {
            http_debug!(r, "pipelined request");
            drop(b);
            c.log.set_action(Some("reading client pipelined request line"));
            c.sent.set(0);
            c.pipeline.set(true);
            // compact and keep the leftover bytes for the next request
            let mut b = hc.buffer.borrow_mut();
            b.compact();
            b.nbusy = 0;
            return Ok(());
        }
    }
    {
        let mut b = hc.buffer.borrow_mut();
        b.pos = 0;
        b.last = 0;
        b.nbusy = 0;
        let cscf = srv_conf_from_ctx(&hc.conf_ctx.borrow());
        b.cap = *cscf.borrow().client_header_buffer_size;
        b.data.clear();
    }
    c.log.set_action(Some("keepalive"));
    if c.tcp_nopush.get() == TcpNopush::Set {
        if let Err(e) = c.tcp_push_off() {
            ngx_log_error!(NGX_LOG_CRIT, c.log, e.raw_os_error(), "tcp_push failed");
            return Err(());
        }
        c.tcp_nopush.set(TcpNopush::Unset);
    }
    if *clcf.borrow().tcp_nodelay && !c.set_tcp_nodelay() {
        return Err(());
    }
    let (min_to, ka_to) = {
        let cl = clcf.borrow();
        (*cl.keepalive_min_timeout, *cl.keepalive_timeout)
    };
    let (first, rest) = if min_to > 0 && ka_to > min_to { (min_to, ka_to - min_to) } else { (ka_to, 0) };
    if min_to == 0 {
        c.idle.set(true);
        c.set_reusable(true);
    }
    let size = hc.buffer.borrow().cap;
    let mut buf = vec![0u8; size];
    let mut n: usize;
    let mut idle_phase = min_to == 0;
    let mut remaining = first;
    loop {
        http_debug!(r, "http keepalive handler");
        let res = tokio::select! {
            r = tokio::time::timeout(Duration::from_millis(remaining), c.recv(&mut buf)) => Some(r),
            _ = c.close_notify.notified(), if idle_phase => None,
        };
        match res {
            None => return Err(()),
            Some(Err(_)) => {
                // timed out
                if !idle_phase && rest > 0 && !ngx_core::event::is_exiting() {
                    c.idle.set(true);
                    c.set_reusable(true);
                    idle_phase = true;
                    remaining = rest;
                    continue;
                }
                return Err(());
            }
            Some(Ok(Err(_))) => return Err(()),
            Some(Ok(Ok(0))) => {
                c.log.set_context(None);
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "client {} closed keepalive connection", B(&c.addr_text.borrow()));
                return Err(());
            }
            Some(Ok(Ok(m))) => {
                n = m;
                break;
            }
        }
    }
    if c.close.get() {
        return Err(());
    }
    {
        let mut b = hc.buffer.borrow_mut();
        b.data = vec![0u8; size];
        b.data[..n].copy_from_slice(&buf[..n]);
        b.pos = 0;
        b.last = n;
    }
    c.idle.set(false);
    c.set_reusable(false);
    c.sent.set(0);
    Ok(())
}

/// ngx_http_set_lingering_close + handler
async fn lingering_close(r: &R) {
    let c = r.connection.clone();
    let clcf = r.clcf();
    let (ltime, ltimeout) = {
        let cl = clcf.borrow();
        (*cl.lingering_time, *cl.lingering_timeout)
    };
    if r.lingering_time.get() == 0 {
        r.lingering_time.set(ngx_core::times::time() + (ltime / 1000) as i64);
    }
    if let Some(ssl) = c.ssl.borrow().clone() {
        ssl.shutdown_without_free.set(true);
        crate::stubs::ssl_shutdown(&c).await;
    }
    if let Err(e) = c.shutdown_write() {
        ngx_log_error!(NGX_LOG_INFO, c.log, e.raw_os_error(), "shutdown() failed");
        return;
    }
    c.close.set(false);
    c.set_reusable(true);
    let mut buf = vec![0u8; NGX_HTTP_LINGERING_BUFFER_SIZE];
    loop {
        http_debug!(r, "http lingering close handler");
        let timer = r.lingering_time.get() - ngx_core::times::time();
        if timer <= 0 {
            return;
        }
        let mut t = timer as u64 * 1000;
        if t > ltimeout {
            t = ltimeout;
        }
        let res = tokio::select! {
            r = tokio::time::timeout(Duration::from_millis(t), c.recv(&mut buf)) => r,
            _ = c.close_notify.notified() => return,
        };
        match res {
            Err(_) => return,
            Ok(Err(_)) | Ok(Ok(0)) => return,
            Ok(Ok(n)) => {
                http_debug!(r, "lingering read: {}", n);
            }
        }
    }
}

/// Wait `delay` ms unless the client closes the connection first (auth_delay).
pub async fn wait_delay_or_close(r: &R, delay: u64) -> bool {
    let c = r.connection.clone();
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(delay)) => false,
        closed = async {
            loop {
                if c.readable().await.is_err() { return true; }
                let mut b = [0u8;1];
                let n = unsafe { libc::recv(c.fd.get(), b.as_mut_ptr() as *mut libc::c_void, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
                if n == 0 { return true; }
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::WouldBlock { tokio::time::sleep(Duration::from_millis(10)).await; continue; }
                    return true;
                }
                // data is pending (pipelined); keep waiting
                tokio::time::sleep(Duration::from_millis(delay)).await;
                return false;
            }
        } => {
            if closed {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "client prematurely closed connection");
                c.error.set(true);
            }
            closed
        }
    }
}

/// ngx_http_subrequest: create and run a subrequest to completion.
/// Returns (rc, subrequest) — the subrequest's output has been passed through the filters.
pub async fn subrequest(r: &R, uri: &[u8], args: Option<&[u8]>, flags: u32, ps: Option<PostSubrequest>) -> Result<(R, i64), ()> {
    if r.subrequests.get() == 0 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "subrequests cycle while processing \"{}\"", B(uri));
        return Err(());
    }
    if r.subrequest_in_memory.get() {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "nested in-memory subrequest \"{}\"", B(uri));
        return Err(());
    }
    let c = r.connection.clone();
    let sr = alloc_request(&c, &r.http_connection, &r.log_ctx);
    let cscf = r.cscf();
    let ctx = cscf.borrow().ctx.clone();
    *sr.main_conf.borrow_mut() = ctx.main.clone().unwrap();
    *sr.srv_conf.borrow_mut() = ctx.srv.clone().unwrap();
    *sr.loc_conf.borrow_mut() = ctx.loc.clone().unwrap();
    // share headers_in
    {
        let hin = r.headers_in.borrow();
        let mut shin = sr.headers_in.borrow_mut();
        shin.headers = hin.headers.clone();
        shin.host = hin.host.clone();
        shin.connection = hin.connection.clone();
        shin.if_modified_since = hin.if_modified_since.clone();
        shin.if_unmodified_since = hin.if_unmodified_since.clone();
        shin.if_match = hin.if_match.clone();
        shin.if_none_match = hin.if_none_match.clone();
        shin.user_agent = hin.user_agent.clone();
        shin.referer = hin.referer.clone();
        shin.content_length = hin.content_length.clone();
        shin.content_range = hin.content_range.clone();
        shin.content_type = hin.content_type.clone();
        shin.range = hin.range.clone();
        shin.if_range = hin.if_range.clone();
        shin.transfer_encoding = hin.transfer_encoding.clone();
        shin.te = hin.te.clone();
        shin.expect = hin.expect.clone();
        shin.upgrade = hin.upgrade.clone();
        shin.accept_encoding = hin.accept_encoding.clone();
        shin.via = hin.via.clone();
        shin.authorization = hin.authorization.clone();
        shin.proxy_authorization = hin.proxy_authorization.clone();
        shin.keep_alive = hin.keep_alive.clone();
        shin.x_forwarded_for = hin.x_forwarded_for.clone();
        shin.x_real_ip = hin.x_real_ip.clone();
        shin.accept = hin.accept.clone();
        shin.accept_language = hin.accept_language.clone();
        shin.depth = hin.depth.clone();
        shin.destination = hin.destination.clone();
        shin.overwrite = hin.overwrite.clone();
        shin.date = hin.date.clone();
        shin.cookie = hin.cookie.clone();
        shin.user = hin.user.clone();
        shin.user_tested = hin.user_tested;
        shin.passwd = hin.passwd.clone();
        shin.server = hin.server.clone();
        shin.content_length_n = hin.content_length_n;
        shin.keep_alive_n = hin.keep_alive_n;
        shin.connection_type = hin.connection_type;
        shin.chunked = hin.chunked;
        shin.msie = hin.msie;
        shin.msie6 = hin.msie6;
        shin.opera = hin.opera;
        shin.gecko = hin.gecko;
        shin.chrome = hin.chrome;
        shin.safari = hin.safari;
        shin.konqueror = hin.konqueror;
        shin.count = hin.count;
    }
    sr.clear_content_length();
    sr.clear_accept_ranges();
    sr.clear_last_modified();
    *sr.request_body.borrow_mut() = r.request_body.borrow().clone();
    *sr.stream.borrow_mut() = r.stream.borrow().clone();
    sr.method.set(NGX_HTTP_GET);
    sr.http_version.set(r.http_version.get());
    sr.port.set(r.port.get());
    *sr.request_line.borrow_mut() = r.request_line.borrow().clone();
    *sr.uri.borrow_mut() = uri.to_vec();
    if let Some(a) = args {
        *sr.args.borrow_mut() = a.to_vec();
    }
    http_debug!(r, "http subrequest \"{}?{}\"", B(uri), B(&sr.args.borrow()));
    sr.subrequest_in_memory.set(flags & NGX_HTTP_SUBREQUEST_IN_MEMORY != 0);
    sr.waited.set(flags & NGX_HTTP_SUBREQUEST_WAITED != 0);
    sr.background.set(flags & NGX_HTTP_SUBREQUEST_BACKGROUND != 0);
    *sr.unparsed_uri.borrow_mut() = r.unparsed_uri.borrow().clone();
    *sr.method_name.borrow_mut() = b"GET".to_vec();
    *sr.http_protocol.borrow_mut() = r.http_protocol.borrow().clone();
    *sr.schema.borrow_mut() = r.schema.borrow().clone();
    set_exten(&sr);
    *sr.main.borrow_mut() = Some(Rc::downgrade(&r.main()));
    *sr.parent.borrow_mut() = Some(Rc::downgrade(r));
    *sr.post_subrequest.borrow_mut() = ps;
    *sr.variables.borrow_mut() = r.variables.borrow().clone();
    if sr.subrequest_in_memory.get() {
        sr.filter_need_in_memory.set(true);
    }
    sr.internal.set(true);
    sr.discard_body.set(r.discard_body.get());
    sr.expect_tested.set(true);
    sr.main_filter_need_in_memory.set(r.main_filter_need_in_memory.get());
    sr.uri_changes.set(NGX_HTTP_MAX_URI_CHANGES + 1);
    sr.subrequests.set(r.subrequests.get() - 1);
    let now = ngx_core::times::cached();
    sr.start_sec.set(now.sec);
    sr.start_msec.set(now.msec);
    if flags & NGX_HTTP_SUBREQUEST_CLONE != 0 {
        sr.method.set(r.method.get());
        *sr.method_name.borrow_mut() = r.method_name.borrow().clone();
        *sr.loc_conf.borrow_mut() = r.loc_conf.borrow().clone();
        sr.valid_location.set(r.valid_location.get());
        sr.valid_unparsed_uri.set(r.valid_unparsed_uri.get());
        *sr.content_handler.borrow_mut() = r.content_handler.borrow().clone();
        sr.phase_handler.set(r.phase_handler.get());
        sr.ncaptures.set(r.ncaptures.get());
        *sr.captures.borrow_mut() = r.captures.borrow().clone();
        *sr.captures_data.borrow_mut() = r.captures_data.borrow().clone();
        update_location_config(&sr);
    }
    // run it
    sr.set_log_request();
    let rc = if flags & NGX_HTTP_SUBREQUEST_CLONE != 0 { Box::pin(run_phases(sr.clone())).await } else { Box::pin(handler(sr.clone())).await };
    Box::pin(finalize_request(&sr, rc)).await;
    // copy back variables cache produced by the subrequest (shared in C)
    *r.variables.borrow_mut() = sr.variables.borrow().clone();
    r.set_log_request();
    Ok((sr, rc))
}
