//! Client request body reading and discarding (ngx_http_request_body.c).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::buf::{Buf, BufData, BufFile, Chain};
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::ngx_log_error;

use crate::parse::{self, ChunkedState};
use crate::request::*;
use crate::*;

fn new_body() -> RequestBody {
    RequestBody { temp_file: None, bufs: Chain::new(), buf: None, rest: -1, received: 0, chunked: None, filter_need_buffering: false, last_sent: false, last_saved: false, buf_size: 0, buf_last: 0 }
}

/// ngx_http_test_expect: send "100 Continue" if requested.
pub async fn test_expect(r: &R) -> i64 {
    if r.expect_tested.get() || r.http_version.get() < NGX_HTTP_VERSION_11 || r.stream.borrow().is_some() {
        return NGX_OK;
    }
    let expect = match &r.headers_in.borrow().expect {
        Some(e) => e.value.borrow().clone(),
        None => return NGX_OK,
    };
    r.expect_tested.set(true);
    if !ngx_core::string::eq_ignore_case(&expect, b"100-continue") {
        return NGX_OK;
    }
    http_debug!(r, "send 100 Continue");
    match r.connection.send_all(b"HTTP/1.1 100 Continue\r\n\r\n").await {
        Ok(()) => NGX_OK,
        Err(_) => {
            r.connection.error.set(true);
            NGX_ERROR
        }
    }
}

/// ngx_http_read_early_body (client_body_early_read)
pub async fn read_early_body(r: &R) -> i64 {
    let cscf = r.cscf();
    let preds = cscf.borrow().client_body_early_read.get().clone();
    if preds.is_none() {
        return NGX_OK;
    }
    {
        let hin = r.headers_in.borrow();
        if hin.content_length_n <= 0 && !hin.chunked {
            return NGX_OK;
        }
    }
    let rc = crate::script::test_predicates(r, &preds);
    if rc == NGX_ERROR {
        crate::request_rt::finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR).await;
        return NGX_ERROR;
    }
    if rc == NGX_OK {
        // Predicates all false: the directive did NOT ask for early read;
        // let the handler chain do it later.
        return NGX_OK;
    }
    // rc == NGX_DECLINED (a predicate is truthy). Enforce the SERVER-level
    // client_max_body_size before we spend memory buffering the request —
    // clcf here is the initial server default location (find_config hasn't
    // matched a nested location yet), so its limit is what applies. Matches
    // C's ngx_http_read_early_body which uses the loc_conf at this point.
    {
        let clcf = r.clcf();
        let c = clcf.borrow();
        let max = *c.client_max_body_size;
        let cl = r.headers_in.borrow().content_length_n;
        if cl != -1 && !r.discard_body.get() && max != 0 && max < cl {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client intended to send too large body: {} bytes", cl);
            r.expect_tested.set(true);
            let _ = discard_request_body(r).await;
            crate::request_rt::finalize_request(r, NGX_HTTP_REQUEST_ENTITY_TOO_LARGE).await;
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }
    }
    let rc = read_client_request_body(r).await;
    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        crate::request_rt::finalize_request(r, rc).await;
        return rc;
    }
    NGX_OK
}

/// ngx_http_read_client_request_body: read the whole body, or, with
/// r.request_body_no_buffering, what is there now: NGX_AGAIN sets
/// r.reading_body, and the caller reads the rest with
/// read_unbuffered_request_body() (the post_handler call in C).
pub async fn read_client_request_body(r: &R) -> i64 {
    if !r.is_main() || r.request_body.borrow().is_some() || r.discard_body.get() {
        r.request_body_no_buffering.set(false);
        return NGX_OK;
    }
    let rc = start_read_client_request_body(r).await;

    // done:
    if r.request_body_no_buffering.get() && (rc == NGX_OK || rc == NGX_AGAIN) {
        if rc == NGX_OK {
            r.request_body_no_buffering.set(false);
        } else {
            r.reading_body.set(true);
        }
    }
    rc
}

async fn start_read_client_request_body(r: &R) -> i64 {
    if test_expect(r).await != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    let rb = Rc::new(RefCell::new(new_body()));
    *r.request_body.borrow_mut() = Some(rb.clone());
    {
        let hin = r.headers_in.borrow();
        if hin.content_length_n < 0 && !hin.chunked {
            r.request_body_no_buffering.set(false);
            return NGX_OK;
        }
    }
    if r.stream.borrow().is_some() {
        return crate::v2::request_body::read_request_body(r, &rb).await;
    }
    let hc = r.http_connection.clone();
    // preread bytes already in the header buffer
    let preread: Vec<u8> = {
        let b = hc.buffer.borrow();
        b.unread().to_vec()
    };
    if !preread.is_empty() {
        http_debug!(r, "http client request body preread {}", preread.len());
        let mut chain = Chain::new();
        chain.push_back(Buf::from_vec(preread.clone()));
        let (rc, consumed) = request_body_filter(r, &rb, chain).await;
        {
            let mut b = hc.buffer.borrow_mut();
            b.pos += consumed;
        }
        r.request_length.set(r.request_length.get() + consumed as i64);
        if rc != NGX_OK {
            return rc;
        }
    } else {
        let (rc, _) = request_body_filter(r, &rb, Chain::new()).await;
        if rc != NGX_OK {
            return rc;
        }
    }
    {
        let b = rb.borrow();
        if b.rest == 0 && b.last_saved {
            drop(b);
            r.request_body_no_buffering.set(false);
            return NGX_OK;
        }
        if b.rest < 0 {
            ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "negative request body rest");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    if r.request_body_no_buffering.get() {
        let clcf = r.clcf();
        let buffer_size = *clcf.borrow().client_body_buffer_size;
        let chunked = r.headers_in.borrow().chunked;
        let mut b = rb.borrow_mut();
        let mut size = buffer_size as i64 + (buffer_size as i64 >> 2);
        if !chunked && b.rest < size {
            size = b.rest;
            if r.request_body_in_single_buf.get() {
                size += preread.len() as i64;
            }
            if size == 0 {
                size = 1;
            }
        } else {
            size = buffer_size as i64;
        }
        b.buf_size = size as usize;
        b.buf_last = 0;
        drop(b);
        return do_read_unbuffered_request_body(r, &rb).await;
    }
    let rc = do_read_client_request_body(r, &rb).await;
    if rc != NGX_OK {
        return rc;
    }
    r.request_body_no_buffering.set(false);
    NGX_OK
}

/// ngx_http_read_unbuffered_request_body: read what the client has sent
/// since the last call, without waiting; the data is appended to
/// rb.bufs for the caller to send on. NGX_OK when the body is complete
/// (r.reading_body is cleared), NGX_AGAIN for more, or an HTTP status.
pub async fn read_unbuffered_request_body(r: &R) -> i64 {
    if r.stream.borrow().is_some() {
        let rc = crate::v2::request_body::read_unbuffered_request_body(r).await;
        if rc == NGX_OK {
            r.reading_body.set(false);
        }
        return rc;
    }
    let rb = match r.request_body.borrow().clone() {
        Some(rb) => rb,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    let rc = do_read_unbuffered_request_body(r, &rb).await;
    if rc == NGX_OK {
        r.reading_body.set(false);
    }
    rc
}

/// Wait for the read event of an unbuffered body: more DATA on an HTTP/2
/// stream, or the client socket becoming readable.
pub async fn wait_request_body(r: &R) {
    if let Some(stream) = crate::v2::stream::request_stream(r) {
        stream.notify.notified().await;
        return;
    }
    // an error is reported by the next read
    let _ = r.connection.readable().await;
}

/// ngx_http_do_read_client_request_body for an unbuffered body: read while
/// the socket has data, passing each read to the request body filters
/// (which append to rb.bufs). When rb->buf is full and what was passed
/// on is not sent yet (rb->busy), reading stops until the next call.
async fn do_read_unbuffered_request_body(r: &R, rb: &Rc<RefCell<RequestBody>>) -> i64 {
    let c = r.connection.clone();
    http_debug!(r, "http read client request body");
    let mut flush = true;
    let mut ready = true;
    loop {
        loop {
            let (rest, buf_size, buf_last) = {
                let b = rb.borrow();
                (b.rest, b.buf_size, b.buf_last)
            };
            if rest == 0 {
                break;
            }
            if buf_last == buf_size {
                // update chains
                let (rc, _) = request_body_filter(r, rb, Chain::new()).await;
                if rc != NGX_OK {
                    return rc;
                }
                if !rb.borrow().bufs.is_empty() {
                    return NGX_AGAIN;
                }
                flush = false;
                rb.borrow_mut().buf_last = 0;
            }
            let (size, rest) = {
                let b = rb.borrow();
                (b.buf_size - b.buf_last, b.rest)
            };
            let size = if size as i64 > rest { rest as usize } else { size };
            if size == 0 {
                break;
            }
            let mut buf = vec![0u8; size];
            let n = match c.try_recv(&mut buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    ready = false;
                    break;
                }
                Ok(0) => {
                    ngx_log_error!(NGX_LOG_INFO, c.log, None, "client prematurely closed connection");
                    c.error.set(true);
                    return NGX_HTTP_BAD_REQUEST;
                }
                Err(_) => {
                    c.error.set(true);
                    return NGX_HTTP_BAD_REQUEST;
                }
                Ok(n) => n,
            };
            http_debug!(r, "http client request body recv {}", n);
            buf.truncate(n);
            rb.borrow_mut().buf_last += n;
            r.request_length.set(r.request_length.get() + n as i64);
            flush = false;
            let mut chain = Chain::new();
            chain.push_back(Buf::from_vec(buf));
            let (rc, _) = request_body_filter(r, rb, chain).await;
            if rc != NGX_OK {
                return rc;
            }
            let b = rb.borrow();
            if b.rest == 0 || b.buf_last < b.buf_size {
                break;
            }
        }
        http_debug!(r, "http client request body rest {}", rb.borrow().rest);
        if flush {
            let (rc, _) = request_body_filter(r, rb, Chain::new()).await;
            if rc != NGX_OK {
                return rc;
            }
        }
        {
            let b = rb.borrow();
            if b.rest == 0 && b.last_saved {
                break;
            }
            if !ready || b.rest == 0 {
                return NGX_AGAIN;
            }
        }
    }
    NGX_OK
}

async fn do_read_client_request_body(r: &R, rb: &Rc<RefCell<RequestBody>>) -> i64 {
    let c = r.connection.clone();
    http_debug!(r, "http read client request body");
    let clcf = r.clcf();
    let (buf_size, timeout) = {
        let cl = clcf.borrow();
        (*cl.client_body_buffer_size, *cl.client_body_timeout)
    };
    loop {
        let rest = rb.borrow().rest;
        if rest == 0 {
            break;
        }
        let chunked = r.headers_in.borrow().chunked;
        let mut size = buf_size;
        if !chunked && rest < size as i64 {
            size = rest as usize;
        }
        if size == 0 {
            size = 1;
        }
        let mut buf = vec![0u8; size];
        let n = match tokio::time::timeout(Duration::from_millis(timeout), c.recv(&mut buf)).await {
            Err(_) => {
                c.timedout.set(true);
                return NGX_HTTP_REQUEST_TIME_OUT;
            }
            Ok(Ok(0)) => {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "client prematurely closed connection");
                c.error.set(true);
                return NGX_HTTP_BAD_REQUEST;
            }
            Ok(Err(_)) => {
                c.error.set(true);
                return NGX_HTTP_BAD_REQUEST;
            }
            Ok(Ok(n)) => n,
        };
        http_debug!(r, "http client request body recv {}", n);
        buf.truncate(n);
        r.request_length.set(r.request_length.get() + n as i64);
        let mut chain = Chain::new();
        chain.push_back(Buf::from_vec(buf));
        let (rc, consumed) = request_body_filter(r, rb, chain).await;
        if rc != NGX_OK {
            return rc;
        }
        let _ = consumed;
        http_debug!(r, "http client request body rest {}", rb.borrow().rest);
    }
    let b = rb.borrow();
    if b.rest == 0 && b.last_saved {
        return NGX_OK;
    }
    drop(b);
    // flush filter
    let (rc, _) = request_body_filter(r, rb, Chain::new()).await;
    rc
}

/// ngx_http_request_body_filter: returns (rc, bytes consumed from input).
/// Leftover bytes (pipelined requests) are appended back to the connection buffer.
async fn request_body_filter(r: &R, rb: &Rc<RefCell<RequestBody>>, input: Chain) -> (i64, usize) {
    let chunked = r.headers_in.borrow().chunked;
    let data: Vec<u8> = input.iter().filter_map(|b| if let BufData::Memory(v) = &b.data { Some(&v[b.pos..b.last]) } else { None }).flatten().copied().collect();
    let total = data.len();
    let mut out = Chain::new();
    let mut consumed = 0usize;
    if !chunked {
        let mut b = rb.borrow_mut();
        if b.rest == -1 {
            http_debug!(r, "http request body content length filter");
            b.rest = r.headers_in.borrow().content_length_n;
            if b.rest == 0 {
                let mut lb = Buf::special();
                lb.last_buf = true;
                out.push_back(lb);
            }
        }
        if b.rest > 0 && total > 0 {
            let take = (b.rest as usize).min(total);
            let mut nb = Buf::from_vec(data[..take].to_vec());
            nb.temporary = true;
            nb.flush = r.request_body_no_buffering.get();
            b.rest -= take as i64;
            consumed = take;
            if b.rest == 0 {
                nb.last_buf = true;
            }
            out.push_back(nb);
        }
    } else {
        let mut b = rb.borrow_mut();
        if b.rest == -1 {
            http_debug!(r, "http request body chunked filter");
            b.chunked = Some(ChunkedState { state: 0, size: 0, length: 0 });
            r.headers_in.borrow_mut().content_length_n = 0;
            let cscf = r.cscf();
            b.rest = cscf.borrow().large_client_header_buffers.size as i64;
        }
        let mut pos = 0usize;
        let mut cur: Option<Vec<u8>> = None;
        loop {
            let mut st = b.chunked.take().unwrap();
            let rc = parse::parse_chunked(&mut st, &data, &mut pos, false);
            if rc == NGX_OK {
                let clcf = r.clcf();
                let max = *clcf.borrow().client_max_body_size;
                let cl = r.headers_in.borrow().content_length_n;
                if max != 0 && max - cl < st.size {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client intended to send too large chunked body: {}+{} bytes", cl, st.size);
                    r.lingering_close.set(true);
                    b.chunked = Some(st);
                    return (NGX_HTTP_REQUEST_ENTITY_TOO_LARGE, pos);
                }
                let avail = total - pos;
                let take = (st.size as usize).min(avail);
                let piece = &data[pos..pos + take];
                cur.get_or_insert_with(Vec::new).extend_from_slice(piece);
                pos += take;
                st.size -= take as i64;
                r.headers_in.borrow_mut().content_length_n += take as i64;
                b.chunked = Some(st);
                continue;
            }
            if rc == NGX_DONE {
                b.rest = 0;
                b.chunked = Some(st);
                if let Some(v) = cur.take() {
                    let mut nb = Buf::from_vec(v);
                    nb.temporary = true;
                    nb.flush = r.request_body_no_buffering.get();
                    out.push_back(nb);
                }
                let mut lb = Buf::special();
                lb.last_buf = true;
                out.push_back(lb);
                break;
            }
            if rc == NGX_AGAIN {
                let cscf = r.cscf();
                b.rest = st.length.max(cscf.borrow().large_client_header_buffers.size as i64);
                b.chunked = Some(st);
                if let Some(v) = cur.take() {
                    let mut nb = Buf::from_vec(v);
                    nb.temporary = true;
                    nb.flush = r.request_body_no_buffering.get();
                    out.push_back(nb);
                }
                break;
            }
            b.chunked = Some(st);
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client sent invalid chunked body");
            return (NGX_HTTP_BAD_REQUEST, pos);
        }
        consumed = pos;
    }
    // leftover (pipelined) bytes go back to the header buffer
    if consumed < total {
        let hc = r.http_connection.clone();
        let mut hb = hc.buffer.borrow_mut();
        let extra = &data[consumed..];
        // The input was taken from the buffer already; only append when it came from the socket
        if hb.pos == hb.last {
            hb.pos = 0;
            hb.last = 0;
            if hb.data.len() < extra.len() {
                hb.data.resize(extra.len(), 0);
            }
            hb.data[..extra.len()].copy_from_slice(extra);
            hb.last = extra.len();
        }
    }
    let f = top_request_body_filter();
    let rc = f(r.clone(), out).await;
    (rc, consumed)
}

/// ngx_http_request_body_save_filter
pub async fn request_body_save_filter(r: R, input: Chain) -> i64 {
    let rb = match r.request_body.borrow().clone() {
        Some(rb) => rb,
        None => return NGX_OK,
    };
    let mut b = rb.borrow_mut();
    for buf in input.into_iter() {
        if buf.last_buf {
            if b.last_saved {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "duplicate last buf in save filter");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            b.last_saved = true;
        }
        b.bufs.push_back(buf);
    }
    if r.request_body_no_buffering.get() {
        return NGX_OK;
    }
    let clcf = r.clcf();
    let buffer_size = *clcf.borrow().client_body_buffer_size;
    let in_mem: usize = b.bufs.iter().map(|x| x.buf_size() as usize).sum();
    if b.rest > 0 {
        if (in_mem >= buffer_size && !b.bufs.is_empty()) || r.request_body_in_file_only.get() {
            if write_request_body(&r, &mut b) != NGX_OK {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        return NGX_OK;
    }
    if !b.last_saved {
        return NGX_OK;
    }
    if b.temp_file.is_some() || r.request_body_in_file_only.get() {
        if write_request_body(&r, &mut b) != NGX_OK {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        let tf = b.temp_file.as_ref().unwrap();
        if tf.offset != 0 {
            let file = Rc::new(BufFile { fd: tf.fd, name: tf.name.clone(), directio: false });
            let mut fb = Buf::file(file, 0, tf.offset);
            fb.in_file = true;
            b.bufs.clear();
            b.bufs.push_back(fb);
        }
    }
    NGX_OK
}

fn write_request_body(r: &R, b: &mut RequestBody) -> i64 {
    http_debug!(r, "http write client request body, bufs {}", b.bufs.len());
    if b.temp_file.is_none() {
        let clcf = r.clcf();
        let path = clcf.borrow().client_body_temp_path.get().clone();
        let access = if r.request_body_file_group_access.get() { 0o660 } else { 0 };
        match ngx_core::buf::create_temp_file(&path, r.request_body_in_persistent_file.get(), r.request_body_in_clean_file.get(), access, &r.connection.log) {
            Ok(tf) => {
                let level = r.request_body_file_log_level.get();
                if level != 0 {
                    ngx_log_error!(level, r.connection.log, None, "a client request body is buffered to a temporary file {}", ngx_core::string::B(&tf.name));
                }
                b.temp_file = Some(tf);
            }
            Err(_) => return NGX_ERROR,
        }
    }
    let mem: Chain = b.bufs.drain(..).filter(|x| x.in_memory()).collect();
    if mem.is_empty() {
        return NGX_OK;
    }
    let tf = b.temp_file.as_mut().unwrap();
    match ngx_core::buf::write_chain_to_temp_file(tf, &mem, &r.connection.log) {
        Ok(_) => NGX_OK,
        Err(_) => NGX_ERROR,
    }
}

/// ngx_http_discard_request_body: start discarding; may complete later.
pub async fn discard_request_body(r: &R) -> i64 {
    if !r.is_main() || r.discard_body.get() || r.request_body.borrow().is_some() {
        return NGX_OK;
    }
    if let Some(stream) = crate::v2::stream::request_stream(r) {
        stream.skip_data.set(true);
        return NGX_OK;
    }
    if test_expect(r).await != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    http_debug!(r, "http set discard body");
    {
        let hin = r.headers_in.borrow();
        if hin.content_length_n <= 0 && !hin.chunked {
            return NGX_OK;
        }
    }
    let hc = r.http_connection.clone();
    let preread: Vec<u8> = hc.buffer.borrow().unread().to_vec();
    if !preread.is_empty() || r.headers_in.borrow().chunked {
        let (rc, consumed) = discard_request_body_filter(r, &preread);
        hc.buffer.borrow_mut().pos += consumed;
        if rc != NGX_OK {
            return rc;
        }
        if r.headers_in.borrow().content_length_n == 0 {
            return NGX_OK;
        }
    }
    let rc = read_discarded_request_body(r, false).await;
    if rc == NGX_OK {
        r.lingering_close.set(false);
        return NGX_OK;
    }
    if rc >= NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }
    r.discard_body.set(true);
    NGX_OK
}

/// Reads and discards; `wait` = block for data (with lingering limits) or only drain what is ready.
async fn read_discarded_request_body(r: &R, wait: bool) -> i64 {
    http_debug!(r, "http read discarded body");
    let c = r.connection.clone();
    let mut buffer = vec![0u8; NGX_HTTP_DISCARD_BUFFER_SIZE];
    loop {
        let cl = r.headers_in.borrow().content_length_n;
        if cl == 0 {
            break;
        }
        let size = (cl as usize).min(NGX_HTTP_DISCARD_BUFFER_SIZE);
        let n = if wait {
            let clcf = r.clcf();
            let ltimeout = *clcf.borrow().lingering_timeout;
            let mut t = ltimeout;
            if r.lingering_time.get() != 0 {
                let rem = r.lingering_time.get() - ngx_core::times::time();
                if rem <= 0 {
                    r.discard_body.set(false);
                    r.lingering_close.set(false);
                    return NGX_ERROR;
                }
                t = t.min(rem as u64 * 1000);
            }
            match tokio::time::timeout(Duration::from_millis(t), c.recv(&mut buffer[..size])).await {
                Err(_) => {
                    c.timedout.set(true);
                    c.error.set(true);
                    return NGX_ERROR;
                }
                Ok(Err(_)) => {
                    c.error.set(true);
                    return NGX_OK;
                }
                Ok(Ok(0)) => return NGX_OK,
                Ok(Ok(n)) => n,
            }
        } else {
            match c.try_recv_raw(&mut buffer[..size]) {
                Ok(0) => return NGX_OK,
                Ok(n) => n,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        return NGX_AGAIN;
                    }
                    c.error.set(true);
                    return NGX_OK;
                }
            }
        };
        let (rc, consumed) = discard_request_body_filter(r, &buffer[..n]);
        if rc != NGX_OK {
            return rc;
        }
        if consumed < n {
            // pipelined data after the body
            let hc = r.http_connection.clone();
            let mut hb = hc.buffer.borrow_mut();
            hb.pos = 0;
            hb.last = 0;
            let extra = &buffer[consumed..n];
            if hb.data.len() < extra.len() {
                hb.data.resize(extra.len(), 0);
            }
            hb.data[..extra.len()].copy_from_slice(extra);
            hb.last = extra.len();
        }
    }
    NGX_OK
}

/// Finish discarding the body before keepalive (ngx_http_discarded_request_body_handler).
pub async fn discard_remaining_body(r: &R) -> Result<(), ()> {
    let clcf = r.clcf();
    let ltime = *clcf.borrow().lingering_time;
    if r.lingering_time.get() == 0 {
        r.lingering_time.set(ngx_core::times::time() + (ltime / 1000) as i64);
    }
    let rc = read_discarded_request_body(r, true).await;
    if rc == NGX_OK {
        r.discard_body.set(false);
        r.discard_body_done.set(true);
        r.lingering_close.set(false);
        r.lingering_time.set(0);
        return Ok(());
    }
    r.connection.error.set(true);
    Err(())
}

/// ngx_http_discard_request_body_filter: returns (rc, consumed)
fn discard_request_body_filter(r: &R, data: &[u8]) -> (i64, usize) {
    if r.headers_in.borrow().chunked {
        let rb = {
            let mut slot = r.request_body.borrow_mut();
            if slot.is_none() {
                let mut b = new_body();
                b.chunked = Some(ChunkedState { state: 0, size: 0, length: 0 });
                *slot = Some(Rc::new(RefCell::new(b)));
            }
            slot.clone().unwrap()
        };
        let mut b = rb.borrow_mut();
        let mut pos = 0usize;
        loop {
            let mut st = b.chunked.take().unwrap_or(ChunkedState { state: 0, size: 0, length: 0 });
            let rc = parse::parse_chunked(&mut st, data, &mut pos, false);
            if rc == NGX_OK {
                let avail = data.len() - pos;
                if avail as i64 > st.size {
                    pos += st.size as usize;
                    st.size = 0;
                } else {
                    st.size -= avail as i64;
                    pos = data.len();
                }
                b.chunked = Some(st);
                continue;
            }
            if rc == NGX_DONE {
                r.headers_in.borrow_mut().content_length_n = 0;
                b.chunked = Some(st);
                return (NGX_OK, pos);
            }
            if rc == NGX_AGAIN {
                let cscf = r.cscf();
                r.headers_in.borrow_mut().content_length_n = st.length.max(cscf.borrow().large_client_header_buffers.size as i64);
                b.chunked = Some(st);
                return (NGX_OK, pos);
            }
            b.chunked = Some(st);
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client sent invalid chunked body");
            return (NGX_HTTP_BAD_REQUEST, pos);
        }
    }
    let mut hin = r.headers_in.borrow_mut();
    let size = data.len() as i64;
    if size > hin.content_length_n {
        let consumed = hin.content_length_n as usize;
        hin.content_length_n = 0;
        (NGX_OK, consumed)
    } else {
        hin.content_length_n -= size;
        (NGX_OK, data.len())
    }
}
