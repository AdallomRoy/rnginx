//! ngx_http_v2_filter_module (nginx-c/src/http/v2/ngx_http_v2_filter_module.c):
//! the HTTP/2 header filter, DATA framing with flow control (send_chain),
//! trailers, and the output frame handlers.
//!
//! C swaps the fake connection's send_chain; here write_filter calls
//! send_chain() for stream requests. C's writer resumes on the fake
//! connection's write event; send_chain() waits on the stream's notify.

use std::io;
use std::io::Write;
use std::rc::Rc;

use ngx_core::buf::{BufData, Chain};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use super::encode::{inc_indexed, indexed, write_name, write_value, NGX_HTTP_V2_ENCODE_RAW};
use super::stream::request_stream;
use super::*;
use crate::core::CoreLocConf;
use crate::core::{NGX_HTTP_SERVER_TOKENS_BUILD, NGX_HTTP_SERVER_TOKENS_ON};
use crate::request::{Header, R};
use crate::*;

crate::http_module_index!("ngx_http_v2_filter_module");

const NGINX_VER: &[u8] = b"nginx/1.31.7";
const NGINX_VER_BUILD: &[u8] = NGINX_VER;

/// "nginx", Huffman-coded, with its length prefix.
const NGINX: [u8; 5] = [0x84, 0xaa, 0x63, 0x55, 0xe7];

/// "Accept-Encoding", Huffman-coded, with its length prefix.
const ACCEPT_ENCODING: [u8; 12] = [0x8b, 0x84, 0x84, 0x2d, 0x69, 0x5b, 0x05, 0x44, 0x3c, 0x86, 0xaa, 0x6f];

pub fn v2_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(filter_init), ..Default::default() };
    http_module_def("ngx_http_v2_filter_module", def, Vec::new())
}

/// ngx_http_v2_filter_init
fn filter_init(_cf: &mut ngx_core::conf::Conf) -> ngx_core::conf::ConfResult {
    // not an HTTP/2 stream: passed on as it is
    crate::install_header_filter_idle(
        |r| r.stream.borrow().is_none(),
        |r: R, next: HeaderFilter| async move {
            if request_stream(&r).is_none() {
                return next(r).await;
            }
            header_filter(&r).await
        },
    );
    install_early_hints_filter(|r: R, next: HeaderFilter| async move {
        if request_stream(&r).is_none() {
            return next(r).await;
        }
        early_hints_filter(&r).await
    });
    Ok(())
}

/// ngx_http_v2_early_hints_filter: a HEADERS frame of ":status: 103" and
/// the headers of r->headers_out
async fn early_hints_filter(r: &R) -> i64 {
    let stream = match request_stream(r) {
        Some(s) => s,
        None => return NGX_ERROR,
    };

    if !r.is_main() {
        return NGX_OK;
    }

    let fc = stream.fc.clone();

    if fc.error.get() {
        return NGX_ERROR;
    }

    let headers: Vec<(Vec<u8>, Vec<u8>)> = r.headers_out.borrow().headers.iter().filter(|h| h.hash.get() != 0).map(|h| (h.key.clone(), h.value.borrow().clone())).collect();

    for (key, value) in headers.iter() {
        if key.len() > NGX_HTTP_V2_MAX_FIELD {
            ngx_log_error!(NGX_LOG_CRIT, fc.log, None, "too long response header name: \"{}\"", B(key));
            return NGX_ERROR;
        }

        if value.len() > NGX_HTTP_V2_MAX_FIELD {
            ngx_log_error!(NGX_LOG_CRIT, fc.log, None, "too long response header value: \"{}: {}\"", B(key), B(value));
            return NGX_ERROR;
        }
    }

    if headers.is_empty() {
        return NGX_OK;
    }

    let h2c = stream.connection.clone();

    let mut pos = frame_buf_with_head(256);

    if h2c.table_update.get() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 table size update: 0");
        pos.push((1 << 5) | 0);
        h2c.table_update.set(false);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \":status: {:03}\"", NGX_HTTP_EARLY_HINTS);

    pos.push(inc_indexed(NGX_HTTP_V2_STATUS_INDEX));
    pos.push(NGX_HTTP_V2_ENCODE_RAW | 3);
    let _ = write!(pos, "{:03}", NGX_HTTP_EARLY_HINTS);

    for (key, value) in headers.iter() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"{}: {}\"", B(&ngx_core::string::to_lower_vec(key)), B(value));

        pos.push(0);

        write_name(&mut pos, key);

        write_value(&mut pos, value);
    }

    let frame = create_headers_frame(&stream, pos, false);

    h2c.queue_blocked_frame(frame);

    stream.queued.set(stream.queued.get() + 1);

    init_stream(r, &stream);

    match filter_send(&stream).await {
        Ok(()) => NGX_OK,
        Err(()) => NGX_ERROR,
    }
}

/// ngx_http_v2_header_filter
async fn header_filter(r: &R) -> i64 {
    let stream = match request_stream(r) {
        Some(s) => s,
        None => return NGX_ERROR,
    };

    let fc = stream.fc.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 header filter");

    if r.header_sent.get() {
        return NGX_OK;
    }

    r.header_sent.set(true);

    if !r.is_main() {
        return NGX_OK;
    }

    if fc.error.get() {
        return NGX_ERROR;
    }

    if r.method.get() == NGX_HTTP_HEAD {
        r.header_only.set(true);
    }

    let h2c = stream.connection.clone();
    let clcf = r.clcf();

    let status: u8;
    let status_code;

    {
        let mut ho = r.headers_out.borrow_mut();
        status_code = ho.status;

        match ho.status {
            NGX_HTTP_OK => status = indexed(NGX_HTTP_V2_STATUS_200_INDEX),

            NGX_HTTP_NO_CONTENT => {
                r.header_only.set(true);

                ho.content_type.clear();
                ho.content_type_len = 0;

                if let Some(cl) = ho.content_length.take() {
                    cl.hash.set(0);
                }
                ho.content_length_n = -1;

                ho.last_modified_time = -1;
                ho.last_modified = None;

                status = indexed(NGX_HTTP_V2_STATUS_204_INDEX);
            }

            NGX_HTTP_PARTIAL_CONTENT => status = indexed(NGX_HTTP_V2_STATUS_206_INDEX),

            NGX_HTTP_NOT_MODIFIED => {
                r.header_only.set(true);
                status = indexed(NGX_HTTP_V2_STATUS_304_INDEX);
            }

            _ => {
                ho.last_modified_time = -1;
                ho.last_modified = None;

                status = match ho.status {
                    NGX_HTTP_BAD_REQUEST => indexed(NGX_HTTP_V2_STATUS_400_INDEX),
                    NGX_HTTP_NOT_FOUND => indexed(NGX_HTTP_V2_STATUS_404_INDEX),
                    NGX_HTTP_INTERNAL_SERVER_ERROR => indexed(NGX_HTTP_V2_STATUS_500_INDEX),
                    _ => 0,
                };
            }
        }
    }

    let mut pos = frame_buf_with_head(256);

    if h2c.table_update.get() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 table size update: 0");
        pos.push((1 << 5) | 0);
        h2c.table_update.set(false);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \":status: {:03}\"", status_code);

    if status != 0 {
        pos.push(status);
    } else {
        pos.push(inc_indexed(NGX_HTTP_V2_STATUS_INDEX));
        pos.push(NGX_HTTP_V2_ENCODE_RAW | 3);
        let _ = write!(pos, "{:03}", status_code);
    }

    let (server_tokens, absolute_redirect, server_name_in_redirect, port_in_redirect) = {
        let cl = clcf.borrow();
        (*cl.server_tokens, *cl.absolute_redirect, *cl.server_name_in_redirect, *cl.port_in_redirect)
    };
    let _: Option<&CoreLocConf> = None;

    let (server, date) = {
        let ho = r.headers_out.borrow();
        (ho.server.clone(), ho.date.clone())
    };

    if server.is_none() {
        pos.push(inc_indexed(NGX_HTTP_V2_SERVER_INDEX));

        if server_tokens == NGX_HTTP_SERVER_TOKENS_ON {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"server: {}\"", B(NGINX_VER));
            write_value(&mut pos, NGINX_VER);
        } else if server_tokens == NGX_HTTP_SERVER_TOKENS_BUILD {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"server: {}\"", B(NGINX_VER_BUILD));
            write_value(&mut pos, NGINX_VER_BUILD);
        } else {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"server: nginx\"");
            pos.extend_from_slice(&NGINX);
        }
    }

    if date.is_none() {
        let t = ngx_core::times::cached_http_time();
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"date: {}\"", t);
        pos.push(inc_indexed(NGX_HTTP_V2_DATE_INDEX));
        write_value(&mut pos, t.as_bytes());
    }

    {
        let mut ho = r.headers_out.borrow_mut();

        if !ho.content_type.is_empty() {
            if ho.content_type.len() > NGX_HTTP_V2_MAX_FIELD {
                ngx_log_error!(NGX_LOG_CRIT, fc.log, None, "too long response header value: \"Content-Type: {}\"", B(&ho.content_type));
                return NGX_ERROR;
            }

            pos.push(inc_indexed(NGX_HTTP_V2_CONTENT_TYPE_INDEX));

            if ho.content_type_len == ho.content_type.len() && !ho.charset.is_empty() {
                // updated content_type is also needed for logging
                let charset = ho.charset.clone();
                ho.content_type.extend_from_slice(b"; charset=");
                ho.content_type.extend_from_slice(&charset);
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"content-type: {}\"", B(&ho.content_type));

            write_value(&mut pos, &ho.content_type);
        }

        if ho.content_length.is_none() && ho.content_length_n >= 0 {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"content-length: {}\"", ho.content_length_n);

            pos.push(inc_indexed(NGX_HTTP_V2_CONTENT_LENGTH_INDEX));

            let p = pos.len();
            pos.push(0);
            let _ = write!(pos, "{}", ho.content_length_n);
            pos[p] = NGX_HTTP_V2_ENCODE_RAW | (pos.len() - p - 1) as u8;
        }

        if ho.last_modified.is_none() && ho.last_modified_time != -1 {
            pos.push(inc_indexed(NGX_HTTP_V2_LAST_MODIFIED_INDEX));

            let tb = ngx_core::times::http_time_bytes(ho.last_modified_time);
            let t = &tb[..];

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"last-modified: {}\"", B(t));

            write_value(&mut pos, t);
        }
    }

    // Location, made absolute as in ngx_http_header_filter
    let location = r.headers_out.borrow().location.clone();

    if let Some(loc) = location {
        let v = loc.value.borrow().clone();

        if !v.is_empty() {
            if v.len() > NGX_HTTP_V2_MAX_FIELD {
                ngx_log_error!(NGX_LOG_CRIT, fc.log, None, "too long response header value: \"Location: {}\"", B(&v));
                return NGX_ERROR;
            }

            let mut value = v.clone();

            if v[0] == b'/' && absolute_redirect {
                let host: Vec<u8> = if server_name_in_redirect {
                    r.cscf().borrow().server_name.clone()
                } else {
                    let s = r.headers_in.borrow().server.clone();
                    if !s.is_empty() {
                        s
                    } else {
                        match fc.local_sockaddr() {
                            Some(local) => local.addr_text(),
                            None => return NGX_ERROR,
                        }
                    }
                };

                let ssl = fc.ssl.borrow().is_some();

                let mut port = fc.local_sockaddr().map(|a| a.port()).unwrap_or(0);

                if port_in_redirect {
                    if ssl {
                        if port == 443 {
                            port = 0;
                        }
                    } else if port == 80 {
                        port = 0;
                    }
                } else {
                    port = 0;
                }

                value = if ssl { b"https://".to_vec() } else { b"http://".to_vec() };
                value.extend_from_slice(&host);

                if port != 0 {
                    value.extend_from_slice(format!(":{}", port).as_bytes());
                }

                value.extend_from_slice(&v);

                // update the location value for possible logging
                *loc.value.borrow_mut() = value.clone();
            }

            loc.hash.set(0);

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"location: {}\"", B(&value));

            pos.push(inc_indexed(NGX_HTTP_V2_LOCATION_INDEX));
            write_value(&mut pos, &value);
        }
    }

    // NGX_HTTP_GZIP
    if r.gzip_vary.get() {
        if *clcf.borrow().gzip_vary {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 output header: \"vary: Accept-Encoding\"");

            pos.push(inc_indexed(NGX_HTTP_V2_VARY_INDEX));
            pos.extend_from_slice(&ACCEPT_ENCODING);
        } else {
            r.gzip_vary.set(false);
        }
    }

    // the headers of the list, in their order: the typed slots (an
    // upstream's Server and Date, ETag, Content-Encoding, ...) are in it
    for h in r.headers_out.borrow().headers.iter() {
        if h.hash.get() == 0 {
            continue;
        }

        let value = h.value.borrow();

        if h.key.len() > NGX_HTTP_V2_MAX_FIELD {
            ngx_log_error!(NGX_LOG_CRIT, fc.log, None, "too long response header name: \"{}\"", B(&h.key));
            return NGX_ERROR;
        }

        if value.len() > NGX_HTTP_V2_MAX_FIELD {
            ngx_log_error!(NGX_LOG_CRIT, fc.log, None, "too long response header value: \"{}: {}\"", B(&h.key), B(&value));
            return NGX_ERROR;
        }

        ngx_log_debug!(
            NGX_LOG_DEBUG_HTTP,
            fc.log,
            "http2 output header: \"{}: {}\"",
            B(&ngx_core::string::to_lower_vec(&h.key)),
            B(&value)
        );

        pos.push(0);

        write_name(&mut pos, &h.key);

        write_value(&mut pos, &value);
    }

    let fin = r.header_only.get() || (r.headers_out.borrow().content_length_n == 0 && !r.expect_trailers.get());

    let frame = create_headers_frame(&stream, pos, fin);

    h2c.queue_blocked_frame(frame);

    stream.queued.set(stream.queued.get() + 1);

    init_stream(r, &stream);

    match filter_send(&stream).await {
        Ok(()) => NGX_OK,
        Err(()) => NGX_ERROR,
    }
}

/// ngx_http_v2_init_stream
fn init_stream(_r: &R, stream: &Rc<H2Stream>) {
    if stream.initialized.get() {
        return;
    }

    stream.initialized.set(true);

    // the cleanup (ngx_http_v2_filter_cleanup) runs from close_stream

    stream.fc.need_last_buf.set(true);
    stream.fc.need_flush_buf.set(true);
}

/// ngx_http_v2_create_headers_frame: a HEADERS frame and as many
/// CONTINUATION frames as the peer's frame size requires, as one output
/// frame. `buf` holds the header block behind the room left for a frame
/// header (frame_buf_with_head()): a block that fits one frame goes out in
/// it, a longer one is copied into the frames.
fn create_headers_frame(stream: &Rc<H2Stream>, mut buf: Vec<u8>, fin: bool) -> OutFrame {
    let block_len = buf.len() - NGX_HTTP_V2_FRAME_HEADER_SIZE;

    let flags = if fin { NGX_HTTP_V2_END_STREAM_FLAG } else { NGX_HTTP_V2_NO_FLAG };

    if block_len <= stream.connection.frame_size.get() {
        let id = stream.node.borrow().id.get();

        set_frame_head(&mut buf, block_len, NGX_HTTP_V2_HEADERS_FRAME, flags | NGX_HTTP_V2_END_HEADERS_FLAG, id);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, stream.fc.log, "http2:{} create HEADERS frame: len:{} fin:{}", id, block_len, fin as u32);

        return OutFrame {
            data: buf,
            sent: 0,
            handler: FrameHandler::Headers,
            stream: Some(stream.clone()),
            length: block_len,
            blocked: true,
            fin,
        };
    }

    create_headers_frames(stream, &buf[NGX_HTTP_V2_FRAME_HEADER_SIZE..], fin)
}

/// create_headers_frame() of a block longer than a frame.
fn create_headers_frames(stream: &Rc<H2Stream>, block: &[u8], fin: bool) -> OutFrame {
    let mut rest = block.len();
    let mut length = rest;

    let mut ty = NGX_HTTP_V2_HEADERS_FRAME;
    let mut flags = if fin { NGX_HTTP_V2_END_STREAM_FLAG } else { NGX_HTTP_V2_NO_FLAG };
    let mut frame_size = stream.connection.frame_size.get();
    let id = stream.node.borrow().id.get();

    let mut data = frame_buf(block.len() + NGX_HTTP_V2_FRAME_HEADER_SIZE * 2);
    let mut pos = 0;

    loop {
        if rest <= frame_size {
            frame_size = rest;
            flags |= NGX_HTTP_V2_END_HEADERS_FLAG;
        }

        write_frame_head(&mut data, frame_size, ty, flags, id);

        data.extend_from_slice(&block[pos..pos + frame_size]);
        pos += frame_size;

        rest -= frame_size;

        if rest > 0 {
            length += NGX_HTTP_V2_FRAME_HEADER_SIZE;

            ty = NGX_HTTP_V2_CONTINUATION_FRAME;
            flags = NGX_HTTP_V2_NO_FLAG;
            continue;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, stream.fc.log, "http2:{} create HEADERS frame: len:{} fin:{}", id, length, fin as u32);

        return OutFrame {
            data,
            sent: 0,
            handler: FrameHandler::Headers,
            stream: Some(stream.clone()),
            length,
            blocked: true,
            fin,
        };
    }
}

/// ngx_http_v2_create_trailers_frame: None when there are no trailers
/// (NGX_HTTP_V2_NO_TRAILERS); Err on a too long trailer.
fn create_trailers_frame(r: &R, stream: &Rc<H2Stream>) -> Result<Option<OutFrame>, ()> {
    let fc = &stream.fc;
    let trailers: Vec<Header> = r.headers_out.borrow().trailers.clone();

    let mut block = frame_buf_with_head(0);

    for h in trailers.iter() {
        if h.hash.get() == 0 {
            continue;
        }

        let value = h.value.borrow();

        if h.key.len() > NGX_HTTP_V2_MAX_FIELD {
            ngx_log_error!(NGX_LOG_CRIT, fc.log, None, "too long response trailer name: \"{}\"", B(&h.key));
            return Err(());
        }

        if value.len() > NGX_HTTP_V2_MAX_FIELD {
            ngx_log_error!(NGX_LOG_CRIT, fc.log, None, "too long response trailer value: \"{}: {}\"", B(&h.key), B(&value));
            return Err(());
        }

        ngx_log_debug!(
            NGX_LOG_DEBUG_HTTP,
            fc.log,
            "http2 output trailer: \"{}: {}\"",
            B(&ngx_core::string::to_lower_vec(&h.key)),
            B(&value)
        );

        block.push(0);
        write_name(&mut block, &h.key);
        write_value(&mut block, &value);
    }

    if block.len() == NGX_HTTP_V2_FRAME_HEADER_SIZE {
        return Ok(None);
    }

    Ok(Some(create_headers_frame(stream, block, true)))
}

/// ngx_http_v2_send_chain, the stream's output: DATA frames of at most
/// min(http2_chunk_size, peer frame size) within the flow control windows.
/// Returns once the chain (up to `limit` bytes, 0 for no limit) is framed
/// and the stream's frames are out, waiting for window updates as needed.
pub async fn send_chain(r: &R, chain: &mut Chain, limit: i64) -> io::Result<i64> {
    let stream = match request_stream(r) {
        Some(s) => s,
        None => return Err(io::Error::from_raw_os_error(libc::EBADF)),
    };

    let mut total: i64 = 0;

    loop {
        let budget = if limit > 0 { limit - total } else { 0 };

        let n = match send_chain_once(r, &stream, chain, budget) {
            Ok(n) => n,
            Err(()) => return Err(io::Error::new(io::ErrorKind::Other, "http2 send chain failed")),
        };

        total += n;

        let done = chain_empty(chain) || limit > 0 && total >= limit;

        if done {
            // ngx_http_v2_filter_send: stay buffered until the frames are out
            return match filter_send(&stream).await {
                Ok(()) => Ok(total),
                Err(()) => Err(io::Error::new(io::ErrorKind::Other, "http2 stream error")),
            };
        }

        // blocked by flow control: wait for the write event
        stream.connection.out_notify.notify_one();
        if wait_write(&stream).await.is_err() {
            return Err(io::Error::new(io::ErrorKind::Other, "http2 stream error"));
        }
    }
}

/// ngx_http_v2_send_chain without waiting for the windows: frame what they
/// allow now, leaving the rest in r.out (C returns it to the write filter,
/// which keeps it in r->out), and let the connection write the frames out
/// (ngx_http_v2_filter_send). Returns the output still in flight, the
/// remainder plus queued DATA, which the write filter bounds as C's busy
/// output buffers do.
pub async fn send_nowait(r: &R) -> Result<usize, ()> {
    let stream = request_stream(r).ok_or(())?;

    let mut out = std::mem::take(&mut *r.out.borrow_mut());
    let res = send_chain_once(r, &stream, &mut out, 0);
    *r.out.borrow_mut() = out;
    res?;

    stream.connection.out_notify.notify_one();
    tokio::task::yield_now().await;

    if stream.fc.error.get() {
        return Err(());
    }

    let rest: usize = r.out.borrow().iter().map(buf_size).sum();

    Ok(rest + stream.queued_bytes.get())
}

fn chain_empty(chain: &Chain) -> bool {
    chain.iter().all(|b| buf_size(b) == 0 && !b.last_buf)
}

/// ngx_buf_size: memory takes precedence, as in C.
fn buf_size(b: &ngx_core::buf::Buf) -> usize {
    if b.in_memory() {
        if let BufData::Memory(_) = &b.data {
            return b.last - b.pos;
        }
    }
    if b.in_file {
        return (b.file_last - b.file_pos).max(0) as usize;
    }
    0
}

/// Copy `n` bytes from the front of `b`, advancing it.
fn take_from(b: &mut ngx_core::buf::Buf, n: usize, out: &mut Vec<u8>) -> Result<(), ()> {
    if n == 0 {
        return Ok(());
    }
    if b.in_memory() {
        if let BufData::Memory(v) = &b.data {
            out.extend_from_slice(&v[b.pos..b.pos + n]);
            b.pos += n;
            if b.in_file {
                b.file_pos += n as i64;
            }
            return Ok(());
        }
    }
    if let BufData::File(f) = &b.data {
        let start = out.len();
        out.resize(start + n, 0);
        let mut done = 0;
        while done < n {
            match ngx_core::os::pread(f.fd, &mut out[start + done..start + n], b.file_pos + done as i64) {
                Ok(rc) if rc > 0 => done += rc,
                _ => return Err(()),
            }
        }
        b.file_pos += n as i64;
        return Ok(());
    }
    Err(())
}

/// One run of ngx_http_v2_send_chain: frame and queue as much of the chain
/// as limit and the windows allow. Returns the payload bytes queued.
fn send_chain_once(r: &R, stream: &Rc<H2Stream>, chain: &mut Chain, limit: i64) -> Result<i64, ()> {
    let fc = &stream.fc;
    let h2c = stream.connection.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 send chain");

    // skip empty buffers
    while let Some(b) = chain.front() {
        if buf_size(b) > 0 || b.last_buf {
            break;
        }
        chain.pop_front();
    }

    let size = chain.front().map(buf_size).unwrap_or(0);

    if chain.is_empty() || stream.out_closed.get() {
        if size > 0 {
            ngx_log_error!(NGX_LOG_ERR, fc.log, None, "output on closed stream");
            return Err(());
        }

        chain.clear();
        return Ok(0);
    }

    if size > 0 && !flow_control(&h2c, stream) {
        return Ok(0);
    }

    let mut limit = if limit == 0 || limit > h2c.send_window.get() as i64 { h2c.send_window.get() as i64 } else { limit };

    if limit > stream.send_window.get() as i64 {
        limit = stream.send_window.get().max(0) as i64;
    }

    let chunk_size = {
        let lcf = r.loc_conf::<super::module::Http2LocConf>(super::module::ctx_index());
        let v = *lcf.borrow().chunk_size;
        v
    };

    let mut frame_size = chunk_size.min(h2c.frame_size.get());

    let mut queued_total: i64 = 0;

    loop {
        if frame_size as i64 > limit {
            frame_size = limit as usize;
        }

        // the frame: its header, then the payload read behind it
        let mut payload = frame_buf_with_head(frame_size);
        let mut rest = frame_size;
        let mut last_buf = false;
        let mut chain_done = false;

        loop {
            let b = match chain.front_mut() {
                Some(b) => b,
                None => {
                    chain_done = true;
                    break;
                }
            };

            let size = buf_size(b);

            if rest >= size {
                // the whole buffer
                take_from(b, size, &mut payload)?;
                last_buf = b.last_buf;
                chain.pop_front();
                rest -= size;

                if chain.is_empty() {
                    frame_size -= rest;
                    rest = 0;
                    chain_done = true;
                    break;
                }

                continue;
            }

            // part of it (a shadow buffer in C: no flush, no last_buf)
            take_from(b, rest, &mut payload)?;
            last_buf = false;
            rest = 0;
            break;
        }

        let _ = rest;

        let mut trailers = None;

        if last_buf {
            trailers = create_trailers_frame(r, stream)?;

            if trailers.is_some() {
                last_buf = false;
            }
        }

        if frame_size > 0 || last_buf {
            let frame = get_data_frame(stream, payload, last_buf)?;

            h2c.queue_frame(frame);

            h2c.send_window.set(h2c.send_window.get() - frame_size);

            stream.send_window.set(stream.send_window.get() - frame_size as isize);
            stream.queued.set(stream.queued.get() + 1);
            stream.queued_bytes.set(stream.queued_bytes.get() + frame_size);

            queued_total += frame_size as i64;
        } else {
            free_frame_buf(payload);
        }

        if chain_done {
            if let Some(t) = trailers {
                h2c.queue_frame(t);
                stream.queued.set(stream.queued.get() + 1);
            }

            break;
        }

        limit -= frame_size as i64;

        if limit == 0 {
            break;
        }
    }

    h2c.out_notify.notify_one();

    if !chain_empty(chain) {
        let _ = flow_control(&h2c, stream);
    }

    Ok(queued_total)
}

/// ngx_http_v2_filter_get_data_frame: `data` holds the payload behind the
/// room left for the frame header
fn get_data_frame(stream: &Rc<H2Stream>, mut data: Vec<u8>, last_buf: bool) -> Result<OutFrame, ()> {
    let h2c = &stream.connection;

    if stream.free_frames.get() > 0 {
        stream.free_frames.set(stream.free_frames.get() - 1);
    } else if h2c.frames.get() < 10000 {
        stream.frames.set(stream.frames.get() + 1);
        h2c.frames.set(h2c.frames.get() + 1);
    } else {
        ngx_log_error!(NGX_LOG_INFO, h2c.connection.log, None, "http2 flood detected");
        h2c.connection.error.set(true);
        return Err(());
    }

    let flags = if last_buf { NGX_HTTP_V2_END_STREAM_FLAG } else { 0 };
    let len = data.len() - NGX_HTTP_V2_FRAME_HEADER_SIZE;
    let id = stream.node.borrow().id.get();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, stream.fc.log, "http2:{} create DATA frame: len:{} flags:{}", id, len, flags);

    set_frame_head(&mut data, len, NGX_HTTP_V2_DATA_FRAME, flags, id);

    Ok(OutFrame {
        data,
        sent: 0,
        handler: FrameHandler::Data,
        stream: Some(stream.clone()),
        length: len,
        blocked: false,
        fin: last_buf,
    })
}

/// ngx_http_v2_flow_control: false when a window is exhausted (the stream
/// is marked exhausted or joins the connection's waiting queue).
fn flow_control(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>) -> bool {
    ngx_log_debug!(
        NGX_LOG_DEBUG_HTTP,
        h2c.connection.log,
        "http2:{} windows: conn:{} stream:{}",
        stream.node.borrow().id.get(),
        h2c.send_window.get(),
        stream.send_window.get()
    );

    if stream.send_window.get() <= 0 {
        stream.exhausted.set(true);
        return false;
    }

    if h2c.send_window.get() == 0 {
        waiting_queue(h2c, stream);
        return false;
    }

    true
}

/// ngx_http_v2_waiting_queue: ordered by rank, then weight.
fn waiting_queue(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>) {
    if stream.waiting.get() {
        return;
    }

    stream.waiting.set(true);

    let (rank, rel_weight) = {
        let n = stream.node.borrow();
        (n.rank.get(), n.rel_weight.get())
    };

    let mut waiting = h2c.waiting.borrow_mut();

    // from the tail: insert after the last stream that goes before us
    let mut at = 0;
    for i in (0..waiting.len()).rev() {
        let n = waiting[i].node.borrow();
        if n.rank.get() < rank || (n.rank.get() == rank && n.rel_weight.get() >= rel_weight) {
            at = i + 1;
            break;
        }
    }

    waiting.insert(at, stream.clone());
}

/// ngx_http_v2_filter_send: stay (fc->buffered) until the stream's queued
/// frames are out.
async fn filter_send(stream: &Rc<H2Stream>) -> Result<(), ()> {
    stream.connection.out_notify.notify_one();

    loop {
        if stream.fc.error.get() {
            return Err(());
        }

        if stream.queued.get() == 0 {
            return Ok(());
        }

        stream.notify.notified().await;
    }
}

/// Wait for the stream's write event (a window update or sent frames).
async fn wait_write(stream: &Rc<H2Stream>) -> Result<(), ()> {
    if stream.fc.error.get() {
        return Err(());
    }

    stream.notify.notified().await;

    if stream.fc.error.get() {
        return Err(());
    }

    Ok(())
}

/// ngx_http_v2_headers_frame_handler / ngx_http_v2_data_frame_handler, once
/// the frame has been written out.
pub fn stream_frame_sent(h2c: &Rc<H2Connection>, frame: OutFrame) {
    let stream = match frame.stream.clone() {
        Some(s) => s,
        None => return,
    };

    let id = stream.node.borrow().id.get();

    if let Some(r) = stream.request.borrow().as_ref() {
        let size = match frame.handler {
            FrameHandler::Headers => {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2:{} HEADERS frame was sent", id);
                NGX_HTTP_V2_FRAME_HEADER_SIZE + frame.length
            }
            _ => {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2:{} DATA frame was sent", id);
                NGX_HTTP_V2_FRAME_HEADER_SIZE
            }
        };
        r.header_size.set(r.header_size.get() + size);
    }

    if frame.handler == FrameHandler::Data {
        stream.free_frames.set(stream.free_frames.get() + 1);
    }

    h2c.payload_bytes.set(h2c.payload_bytes.get() + frame.length as i64);

    handle_frame(&stream, &frame);

    handle_stream(h2c, &stream);
}

/// ngx_http_v2_handle_frame
fn handle_frame(stream: &Rc<H2Stream>, frame: &OutFrame) {
    let fc = &stream.fc;

    fc.sent.set(fc.sent.get() + (NGX_HTTP_V2_FRAME_HEADER_SIZE + frame.length) as u64);

    let h2c = &stream.connection;

    h2c.total_bytes.set(h2c.total_bytes.get() + (NGX_HTTP_V2_FRAME_HEADER_SIZE + frame.length) as i64);

    if frame.fin {
        stream.out_closed.set(true);
    }

    if frame.handler == FrameHandler::Data {
        stream.queued_bytes.set(stream.queued_bytes.get().saturating_sub(frame.length));
    }

    stream.queued.set(stream.queued.get().saturating_sub(1));
}

/// ngx_http_v2_handle_stream: post the stream's write event.
fn handle_stream(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>) {
    if stream.waiting.get() || stream.blocked.get() {
        return;
    }

    if !stream.fc.error.get() && stream.exhausted.get() {
        return;
    }

    stream.notify.notify_one();

    h2c.streams_posted.set(true);
}

/// ngx_http_v2_filter_cleanup: drop the stream's frames not yet started
/// and give their bytes back to the connection window.
pub fn filter_cleanup(stream: &Rc<H2Stream>) {
    let h2c = stream.connection.clone();

    if stream.waiting.get() {
        stream.waiting.set(false);
    }
    h2c.waiting.borrow_mut().retain(|s| !Rc::ptr_eq(s, stream));

    if stream.queued.get() == 0 {
        return;
    }

    let mut window = 0;

    {
        let mut out = h2c.last_out.borrow_mut();
        let mut i = 0;
        while i < out.len() {
            let mine = out[i].stream.as_ref().map(|s| Rc::ptr_eq(s, stream)).unwrap_or(false);
            if mine && !out[i].blocked {
                let f = out.remove(i).expect("queued frame");
                if f.handler == FrameHandler::Data {
                    window += f.length;
                    stream.queued_bytes.set(stream.queued_bytes.get().saturating_sub(f.length));
                }
                stream.queued.set(stream.queued.get() - 1);
                if stream.queued.get() == 0 {
                    break;
                }
                continue;
            }
            i += 1;
        }
    }

    if h2c.send_window.get() == 0 && window > 0 {
        let waiting: Vec<Rc<H2Stream>> = h2c.waiting.borrow_mut().drain(..).collect();
        for s in waiting {
            s.waiting.set(false);
            s.notify.notify_one();
        }
    }

    h2c.send_window.set(h2c.send_window.get() + window);
}
