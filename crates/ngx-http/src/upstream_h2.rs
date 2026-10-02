//! The HTTP/2 client of the upstream modules gRPC and proxy_http_version 2
//! (ngx_http_grpc_module.c and ngx_http_proxy_v2_module.c have the same
//! code for it): the connection preface, the frames of the request, the
//! parser of the frames of the response with its HPACK decoder (the static
//! table only), the control frames sent back, and the request body as DATA
//! frames within the flow control windows. The state is H2Ctx
//! (ngx_http_grpc_ctx_t, ngx_http_proxy_v2_ctx_t) and H2Conn, kept with the
//! connection in the keepalive cache; the debug messages have the module's
//! prefix ("grpc", "http proxy").

use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::log::*;
use ngx_core::ngx_log_error;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::v2::*;
use crate::NGX_HTTP_PARSE_HEADER_DONE;

/// ngx_http_{grpc,proxy_v2}_connection_start: the connection preface, a
/// SETTINGS frame (header table size 0, no push, the largest initial
/// window) and a WINDOW_UPDATE frame opening the connection's window as
/// much
pub const CONNECTION_START: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\
\x00\x00\x12\x04\x00\x00\x00\x00\x00\
\x00\x01\x00\x00\x00\x00\
\x00\x02\x00\x00\x00\x00\
\x00\x04\x7f\xff\xff\xff\
\x00\x00\x04\x08\x00\x00\x00\x00\x00\
\x7f\xff\x00\x00";

/// sizeof(ngx_http_{grpc,proxy_v2}_frame_t)
pub const FRAME_SIZE: usize = 9;

/// ngx_http_{grpc,proxy_v2}_state_e
pub const ST_START: u8 = 0;
pub const ST_LENGTH_2: u8 = 1;
pub const ST_LENGTH_3: u8 = 2;
pub const ST_TYPE: u8 = 3;
pub const ST_FLAGS: u8 = 4;
pub const ST_STREAM_ID: u8 = 5;
pub const ST_STREAM_ID_2: u8 = 6;
pub const ST_STREAM_ID_3: u8 = 7;
pub const ST_STREAM_ID_4: u8 = 8;
pub const ST_PAYLOAD: u8 = 9;
pub const ST_PADDING: u8 = 10;

/// ngx_http_{grpc,proxy_v2}_conn_t: the HTTP/2 state of the upstream
/// connection, kept with it in the keepalive cache.
pub struct H2Conn {
    pub(crate) init_window: usize,
    pub(crate) send_window: usize,
    pub(crate) recv_window: usize,
    pub(crate) last_stream_id: usize,
    /// the module whose connection it is (the cleanup handler of its data
    /// in C)
    pub(crate) tag: usize,
}

/// ngx_http_{grpc,proxy_v2}_ctx_t: the stream of the request
#[derive(Default)]
pub struct H2Ctx {
    /// the prefix of the debug messages
    pub(crate) prefix: &'static str,
    /// the tag of the module's buffers
    pub(crate) tag: usize,

    pub(crate) state: u8,
    pub(crate) frame_state: u8,
    pub(crate) fragment_state: u8,

    /// ctx->in: the request not sent yet (the header buffer first)
    pub(crate) input: Chain,
    /// ctx->out: the control frames queued
    pub(crate) out: Chain,
    /// the buffers of ctx->free: frames written out, for the flood checks
    pub(crate) free: usize,

    pub(crate) connection: Option<Rc<RefCell<H2Conn>>>,

    pub(crate) id: usize,

    pub(crate) pings: usize,
    pub(crate) settings: usize,

    pub(crate) length: i64,

    pub(crate) send_window: isize,
    pub(crate) recv_window: usize,

    pub(crate) rest: usize,
    pub(crate) stream_id: usize,
    pub(crate) ty: u8,
    pub(crate) flags: u8,
    pub(crate) padding: u8,

    pub(crate) error: usize,
    pub(crate) window_update: usize,

    pub(crate) setting_id: usize,
    pub(crate) setting_value: usize,

    pub(crate) ping_data: [u8; 8],

    pub(crate) index: usize,
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,

    pub(crate) header_limit: usize,
    pub(crate) field_length: usize,
    pub(crate) field_rest: usize,
    pub(crate) field_state: u8,

    pub(crate) literal: bool,
    pub(crate) field_huffman: bool,

    pub(crate) header_sent: bool,
    pub(crate) output_closed: bool,
    pub(crate) output_blocked: bool,
    pub(crate) parsing_headers: bool,
    pub(crate) end_stream: bool,
    pub(crate) done: bool,
    pub(crate) status: bool,
    pub(crate) rst: bool,
    pub(crate) goaway: bool,
}

impl H2Ctx {
    pub fn new(prefix: &'static str, tag: usize) -> H2Ctx {
        H2Ctx { prefix, tag, ..Default::default() }
    }
}

/// A frame header: length, type, flags and stream identifier.
pub fn frame_header(len: usize, ty: u8, flags: u8, sid: usize) -> [u8; FRAME_SIZE] {
    [(len >> 16) as u8, (len >> 8) as u8, len as u8, ty, flags, (sid >> 24) as u8 & 0x7f, (sid >> 16) as u8, (sid >> 8) as u8, sid as u8]
}

/// The header buffer of a request on a keepalive connection: the
/// connection preface skipped, the stream identifiers of the frames updated.
pub fn keepalive_header(b: &mut Buf, id: usize) {
    b.pos += CONNECTION_START.len();

    let (pos, last) = (b.pos, b.last);

    if let BufData::Memory(v) = &mut b.data {
        let mut p = pos;

        while p + FRAME_SIZE <= last {
            let len = ((v[p] as usize) << 16) + ((v[p + 1] as usize) << 8) + v[p + 2] as usize;

            v[p + 5] = (id >> 24) as u8;
            v[p + 6] = (id >> 16) as u8;
            v[p + 7] = (id >> 8) as u8;
            v[p + 8] = id as u8;

            p += FRAME_SIZE + len;
        }
    }
}

/// The hex dump of the debug log: up to 256 bytes, "..." after more.
pub fn hex_head(data: &[u8]) -> String {
    let n = data.len().min(256);
    let mut s: String = data[..n].iter().map(|b| format!("{:02x}", b)).collect();

    if data.len() > 256 {
        s.push_str("...");
    }

    s
}

/// Updates the length of the HEADERS frame at `headers_frame`, the header
/// block following it, and creates additional CONTINUATION frames for the
/// part of the block over the frame size.
pub fn header_frames(b: &mut Vec<u8>, headers_frame: usize) {
    let start = headers_frame + FRAME_SIZE;
    let len = b.len() - start;

    if len <= NGX_HTTP_V2_DEFAULT_FRAME_SIZE {
        // the block fits in the HEADERS frame: its header written in place
        b[headers_frame..start].copy_from_slice(&frame_header(len, NGX_HTTP_V2_HEADERS_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 1));
        return;
    }

    let block = b.split_off(start);

    let mut chunks = block.chunks(NGX_HTTP_V2_DEFAULT_FRAME_SIZE).peekable();

    let first = chunks.next().unwrap_or(&[]);

    b.truncate(headers_frame);

    let flags = if chunks.peek().is_none() { NGX_HTTP_V2_END_HEADERS_FLAG } else { 0 };

    b.extend_from_slice(&frame_header(first.len(), NGX_HTTP_V2_HEADERS_FRAME, flags, 1));
    b.extend_from_slice(first);

    while let Some(chunk) = chunks.next() {
        let flags = if chunks.peek().is_none() { NGX_HTTP_V2_END_HEADERS_FLAG } else { 0 };

        b.extend_from_slice(&frame_header(chunk.len(), NGX_HTTP_V2_CONTINUATION_FRAME, flags, 1));
        b.extend_from_slice(chunk);
    }
}

/// A buffer of the module (ngx_http_{grpc,proxy_v2}_get_buf and the like).
pub fn buf(data: Vec<u8>, tag: usize) -> Buf {
    let mut b = Buf::from_vec(data);
    b.tag = tag;
    b.temporary = true;
    b.flush = true;
    b
}

impl H2Ctx {
    pub(crate) fn conn(&self) -> std::cell::RefMut<'_, H2Conn> {
        self.connection.as_ref().expect("connection data").borrow_mut()
    }

    /// ngx_http_{grpc,proxy_v2}_get_buf: a buffer of ctx->free, or a new one
    pub(crate) fn get_buf(&mut self, data: Vec<u8>) -> Buf {
        if self.free > 0 {
            self.free -= 1;
        }

        buf(data, self.tag)
    }

    /// The DATA frames of ngx_http_{grpc,proxy_v2}_body_output_filter: the buffers of
    /// ctx->in as far as the flow control windows allow, END_STREAM with the
    /// last one.  Returns the limit left.
    pub(crate) fn body_frames(&mut self, log: &Log, out: &mut Chain) -> usize {
        let prefix = self.prefix;

        let mut f: Option<usize> = None;
        let mut last = false;

        let conn_window = self.conn().send_window;

        let mut limit = self.send_window.max(0) as usize;

        if limit > conn_window {
            limit = conn_window;
        }

        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} output limit: {} w:{}:{}", prefix, limit, self.send_window, conn_window);

        while !self.input.is_empty() && limit > 0 {
            let id = self.id;

            let mut next = false;

            {
                let b = self.input.front().expect("buffer");

                ngx_core::ngx_log_debug!(
                    NGX_LOG_DEBUG_EVENT,
                    log,
                    "{} output in  l:{} f:{} size: {} file: {}, size: {}", prefix,
                    b.last_buf as i32,
                    b.in_file as i32,
                    if b.in_memory() { b.last - b.pos } else { 0 },
                    b.file_pos,
                    b.file_last - b.file_pos
                );

                if b.special_buf() {
                    next = true;
                }
            }

            if !next {
                loop {
                    let (frame, len) = {
                        let b = self.input.front_mut().expect("buffer");

                        let mut nb = Buf::default();

                        let len;

                        if b.in_file && !b.in_memory() {
                            let file_pos = b.file_pos;
                            let mut end = file_pos + NGX_HTTP_V2_DEFAULT_FRAME_SIZE.min(limit) as i64;

                            if end >= b.file_last {
                                end = b.file_last;
                                next = true;
                            }

                            nb.in_file = true;
                            nb.data = b.data.clone();
                            nb.file_pos = file_pos;
                            nb.file_last = end;

                            len = (end - file_pos) as usize;

                            b.file_pos = end;
                        } else {
                            let pos = b.pos;
                            let mut end = pos + NGX_HTTP_V2_DEFAULT_FRAME_SIZE.min(limit);

                            if end >= b.last {
                                end = b.last;
                                next = true;
                            }

                            let data = match &b.data {
                                BufData::Memory(v) => v[pos..end].to_vec(),
                                _ => Vec::new(),
                            };

                            nb = Buf::from_vec(data);

                            len = end - pos;

                            b.pos = end;
                        }

                        nb.tag = self.tag;
                        nb.flush = b.flush;

                        (nb, len)
                    };

                    let hdr = self.get_buf(frame_header(len, NGX_HTTP_V2_DATA_FRAME, 0, id).to_vec());

                    f = Some(out.len());
                    out.push_back(hdr);

                    let _ = self.get_buf(Vec::new());
                    out.push_back(frame);

                    limit -= len;
                    self.send_window -= len as isize;
                    self.conn().send_window -= len;

                    if next || limit == 0 {
                        break;
                    }
                }

                if !next {
                    // the buffer wasn't fully sent due to flow control
                    // limits: its position is kept for future use
                    break;
                }
            }

            // next:

            let b = self.input.pop_front().expect("buffer");

            if b.last_buf {
                last = true;
            }
        }

        if last {
            ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} output last", prefix);

            self.output_closed = true;

            match f {
                Some(i) => {
                    let b = &mut out[i];
                    let p = b.pos;

                    if let BufData::Memory(v) = &mut b.data {
                        v[p + 4] |= NGX_HTTP_V2_END_STREAM_FLAG;
                    }
                }

                None => {
                    let id = self.id;
                    let hdr = self.get_buf(frame_header(0, NGX_HTTP_V2_DATA_FRAME, NGX_HTTP_V2_END_STREAM_FLAG, id).to_vec());
                    out.push_back(hdr);
                }
            }

            if let Some(b) = out.back_mut() {
                b.last_buf = true;
            }
        }

        limit
    }

    /// ngx_http_{grpc,proxy_v2}_send_settings_ack
    pub(crate) fn send_settings_ack(&mut self, log: &Log) -> i64 {
        let prefix = self.prefix;

        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} send settings ack", prefix);

        let b = self.get_buf(frame_header(0, NGX_HTTP_V2_SETTINGS_FRAME, NGX_HTTP_V2_ACK_FLAG, 0).to_vec());

        self.out.push_back(b);

        NGX_OK
    }

    /// ngx_http_{grpc,proxy_v2}_send_ping_ack
    pub(crate) fn send_ping_ack(&mut self, log: &Log) -> i64 {
        let prefix = self.prefix;

        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} send ping ack", prefix);

        let mut data = frame_header(8, NGX_HTTP_V2_PING_FRAME, NGX_HTTP_V2_ACK_FLAG, 0).to_vec();
        data.extend_from_slice(&self.ping_data);

        let b = self.get_buf(data);

        self.out.push_back(b);

        NGX_OK
    }

    /// ngx_http_{grpc,proxy_v2}_send_window_update: the windows of the connection and
    /// of the stream opened as much as possible again
    pub(crate) fn send_window_update(&mut self, log: &Log) -> i64 {
        let prefix = self.prefix;

        {
            let conn = self.conn();

            ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} send window update: {} {}", prefix, conn.recv_window, self.recv_window);
        }

        let mut data = frame_header(4, NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 0).to_vec();

        let n = {
            let mut conn = self.conn();
            let n = NGX_HTTP_V2_MAX_WINDOW - conn.recv_window;
            conn.recv_window = NGX_HTTP_V2_MAX_WINDOW;
            n
        };

        data.extend_from_slice(&(n as u32).to_be_bytes());

        data.extend_from_slice(&frame_header(4, NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, self.id));

        let n = NGX_HTTP_V2_MAX_WINDOW - self.recv_window;
        self.recv_window = NGX_HTTP_V2_MAX_WINDOW;

        data.extend_from_slice(&(n as u32).to_be_bytes());

        let b = self.get_buf(data);

        self.out.push_back(b);

        NGX_OK
    }

    /// ngx_http_{grpc,proxy_v2}_parse_frame: the frame header
    pub(crate) fn parse_frame(&mut self, log: &Log, buf: &[u8], pos: &mut usize) -> i64 {
        let prefix = self.prefix;

        let ctx = &mut *self;

        let mut state = ctx.state;
        let mut p = *pos;

        while p < buf.len() {
            let ch = buf[p];

            match state {
                ST_START => {
                    ctx.rest = (ch as usize) << 16;
                    state = ST_LENGTH_2;
                }

                ST_LENGTH_2 => {
                    ctx.rest |= (ch as usize) << 8;
                    state = ST_LENGTH_3;
                }

                ST_LENGTH_3 => {
                    ctx.rest |= ch as usize;

                    if ctx.rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too large http2 frame: {}", ctx.rest);
                        return NGX_ERROR;
                    }

                    state = ST_TYPE;
                }

                ST_TYPE => {
                    ctx.ty = ch;
                    state = ST_FLAGS;
                }

                ST_FLAGS => {
                    ctx.flags = ch;
                    state = ST_STREAM_ID;
                }

                ST_STREAM_ID => {
                    ctx.stream_id = ((ch & 0x7f) as usize) << 24;
                    state = ST_STREAM_ID_2;
                }

                ST_STREAM_ID_2 => {
                    ctx.stream_id |= (ch as usize) << 16;
                    state = ST_STREAM_ID_3;
                }

                ST_STREAM_ID_3 => {
                    ctx.stream_id |= (ch as usize) << 8;
                    state = ST_STREAM_ID_4;
                }

                ST_STREAM_ID_4 => {
                    ctx.stream_id |= ch as usize;

                    ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} frame: {}, len: {}, f:{}, i:{}", prefix, ctx.ty, ctx.rest, ctx.flags, ctx.stream_id);

                    *pos = p + 1;

                    ctx.state = ST_PAYLOAD;
                    ctx.frame_state = 0;

                    return NGX_OK;
                }

                _ => {}
            }

            p += 1;
        }

        *pos = p;
        ctx.state = state;

        NGX_AGAIN
    }

    /// ngx_http_{grpc,proxy_v2}_parse_header: the HEADERS and CONTINUATION frames
    /// around the header block fragment
    pub(crate) fn parse_header(&mut self, log: &Log, buffer_size: usize, buf: &[u8], pos: &mut usize) -> i64 {
        let prefix = self.prefix;

        const SW_START: u8 = 0;
        const SW_PADDING_LENGTH: u8 = 1;
        const SW_DEPENDENCY: u8 = 2;
        const SW_DEPENDENCY_2: u8 = 3;
        const SW_DEPENDENCY_3: u8 = 4;
        const SW_DEPENDENCY_4: u8 = 5;
        const SW_WEIGHT: u8 = 6;
        const SW_FRAGMENT: u8 = 7;
        const SW_PADDING: u8 = 8;

        let mut state = self.frame_state;

        if state == SW_START {
            ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} parse header: start", prefix);

            let ctx = &mut *self;

            if ctx.ty == NGX_HTTP_V2_HEADERS_FRAME {
                ctx.parsing_headers = true;
                ctx.fragment_state = 0;
                ctx.header_limit = buffer_size;

                let min = (if ctx.flags & NGX_HTTP_V2_PADDED_FLAG != 0 { 1 } else { 0 }) + (if ctx.flags & NGX_HTTP_V2_PRIORITY_FLAG != 0 { 5 } else { 0 });

                if ctx.rest < min {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent headers frame with invalid length: {}", ctx.rest);
                    return NGX_ERROR;
                }

                if ctx.flags & NGX_HTTP_V2_END_STREAM_FLAG != 0 {
                    ctx.end_stream = true;
                }

                if ctx.flags & NGX_HTTP_V2_PADDED_FLAG != 0 {
                    state = SW_PADDING_LENGTH;
                } else if ctx.flags & NGX_HTTP_V2_PRIORITY_FLAG != 0 {
                    state = SW_DEPENDENCY;
                } else {
                    state = SW_FRAGMENT;
                }
            } else if ctx.ty == NGX_HTTP_V2_CONTINUATION_FRAME {
                state = SW_FRAGMENT;
            }

            ctx.padding = 0;
            ctx.frame_state = state;
        }

        if state < SW_FRAGMENT {
            let ctx = &mut *self;

            let last = if buf.len() - *pos < ctx.rest { buf.len() } else { *pos + ctx.rest };

            let mut p = *pos;
            let mut fragment = false;

            // headers frame:
            //
            // +---------------+
            // |Pad Length? (8)|
            // +-+-------------+----------------------------------------------+
            // |E|                 Stream Dependency? (31)                    |
            // +-+-------------+----------------------------------------------+
            // |  Weight? (8)  |
            // +-+-------------+----------------------------------------------+
            // |                   Header Block Fragment (*)                ...
            // +--------------------------------------------------------------+
            // |                           Padding (*)                      ...
            // +--------------------------------------------------------------+

            while p < last {
                let ch = buf[p];

                match state {
                    SW_PADDING_LENGTH => {
                        ctx.padding = ch;

                        if ctx.flags & NGX_HTTP_V2_PRIORITY_FLAG != 0 {
                            state = SW_DEPENDENCY;
                        } else {
                            fragment = true;
                            break;
                        }
                    }

                    SW_DEPENDENCY => state = SW_DEPENDENCY_2,
                    SW_DEPENDENCY_2 => state = SW_DEPENDENCY_3,
                    SW_DEPENDENCY_3 => state = SW_DEPENDENCY_4,
                    SW_DEPENDENCY_4 => state = SW_WEIGHT,

                    SW_WEIGHT => {
                        fragment = true;
                        break;
                    }

                    _ => {}
                }

                p += 1;
            }

            if !fragment {
                ctx.rest -= p - *pos;
                *pos = p;

                ctx.frame_state = state;
                return NGX_AGAIN;
            }

            // fragment:

            p += 1;
            ctx.rest -= p - *pos;
            *pos = p;

            if ctx.padding as usize > ctx.rest {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent http2 frame with too long padding: {} in frame {}", ctx.padding, ctx.rest);
                return NGX_ERROR;
            }

            state = SW_FRAGMENT;
            ctx.frame_state = state;
        }

        if state == SW_FRAGMENT {
            let rc = self.parse_fragment(log, buf, pos);

            if rc == NGX_AGAIN {
                return NGX_AGAIN;
            }

            if rc == NGX_ERROR {
                return NGX_ERROR;
            }

            if rc == NGX_OK {
                return NGX_OK;
            }

            // rc == NGX_DONE

            state = SW_PADDING;
            self.frame_state = state;
        }

        if state == SW_PADDING {
            let ctx = &mut *self;

            if buf.len() - *pos < ctx.rest {
                ctx.rest -= buf.len() - *pos;
                *pos = buf.len();

                return NGX_AGAIN;
            }

            *pos += ctx.rest;
            ctx.rest = 0;

            ctx.state = ST_START;

            if ctx.flags & NGX_HTTP_V2_END_HEADERS_FLAG != 0 {
                if ctx.fragment_state != 0 {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent truncated http2 header");
                    return NGX_ERROR;
                }

                ctx.parsing_headers = false;

                return NGX_HTTP_PARSE_HEADER_DONE;
            }

            return NGX_AGAIN;
        }

        // unreachable

        NGX_ERROR
    }

    /// ngx_http_{grpc,proxy_v2}_parse_fragment: the header block (HPACK, with the
    /// static table only and no dynamic table size)
    pub(crate) fn parse_fragment(&mut self, log: &Log, buf: &[u8], pos: &mut usize) -> i64 {
        let prefix = self.prefix;

        const SW_START: u8 = 0;
        const SW_INDEX: u8 = 1;
        const SW_NAME_LENGTH: u8 = 2;
        const SW_NAME_LENGTH_2: u8 = 3;
        const SW_NAME_LENGTH_3: u8 = 4;
        const SW_NAME_LENGTH_4: u8 = 5;
        const SW_NAME: u8 = 6;
        const SW_NAME_BYTES: u8 = 7;
        const SW_VALUE_LENGTH: u8 = 8;
        const SW_VALUE_LENGTH_2: u8 = 9;
        const SW_VALUE_LENGTH_3: u8 = 10;
        const SW_VALUE_LENGTH_4: u8 = 11;
        const SW_VALUE: u8 = 12;
        const SW_VALUE_BYTES: u8 = 13;

        let ctx = &mut *self;

        // header block fragment

        let padding = ctx.padding as usize;

        let last = if buf.len() - *pos < ctx.rest - padding { buf.len() } else { *pos + ctx.rest - padding };

        let mut state = ctx.fragment_state;

        let mut p = *pos;

        while p < last {
            let ch = buf[p];

            let mut done = false;

            match state {
                SW_START => {
                    ctx.index = 0;

                    if ch & 0x80 == 0x80 {
                        // indexed header:
                        //
                        //   0   1   2   3   4   5   6   7
                        // +---+---+---+---+---+---+---+---+
                        // | 1 |        Index (7+)         |
                        // +---+---------------------------+

                        let index = (ch & !0x80) as usize;

                        if index == 0 || index > 61 {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid http2 table index: {}", index);
                            return NGX_ERROR;
                        }

                        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} indexed header: {}", prefix, index);

                        ctx.index = index;
                        ctx.literal = false;

                        done = true;
                    } else if ch & 0xc0 == 0x40 {
                        // literal header with incremental indexing:
                        //
                        //   0   1   2   3   4   5   6   7
                        // +---+---+---+---+---+---+---+---+
                        // | 0 | 1 |      Index (6+)       |
                        // +---+---+-----------------------+
                        // | H |     Value Length (7+)     |
                        // +---+---------------------------+
                        // | Value String (Length octets)  |
                        // +-------------------------------+
                        //
                        //   0   1   2   3   4   5   6   7
                        // +---+---+---+---+---+---+---+---+
                        // | 0 | 1 |           0           |
                        // +---+---+-----------------------+
                        // | H |     Name Length (7+)      |
                        // +---+---------------------------+
                        // |  Name String (Length octets)  |
                        // +---+---------------------------+
                        // | H |     Value Length (7+)     |
                        // +---+---------------------------+
                        // | Value String (Length octets)  |
                        // +-------------------------------+

                        let index = (ch & !0xc0) as usize;

                        if index > 61 {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid http2 table index: {}", index);
                            return NGX_ERROR;
                        }

                        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} literal header: {}", prefix, index);

                        if index == 0 {
                            state = SW_NAME_LENGTH;
                        } else {
                            ctx.index = index;
                            ctx.literal = true;

                            state = SW_VALUE_LENGTH;
                        }
                    } else if ch & 0xe0 == 0x20 {
                        // dynamic table size update:
                        //
                        //   0   1   2   3   4   5   6   7
                        // +---+---+---+---+---+---+---+---+
                        // | 0 | 0 | 1 |   Max size (5+)   |
                        // +---+---------------------------+

                        let size_update = (ch & !0xe0) as usize;

                        if size_update > 0 {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid http2 dynamic table size update: {}", size_update);
                            return NGX_ERROR;
                        }

                        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} table size update: {}", prefix, size_update);
                    } else if ch & 0xf0 == 0x10 || ch & 0xf0 == 0x00 {
                        //  literal header field never indexed (0001) and
                        //  literal header field without indexing (0000):
                        //
                        //   0   1   2   3   4   5   6   7
                        // +---+---+---+---+---+---+---+---+
                        // | 0 | 0 | 0 | ? |  Index (4+)   |
                        // +---+---+-----------------------+
                        // | H |     Value Length (7+)     |
                        // +---+---------------------------+
                        // | Value String (Length octets)  |
                        // +-------------------------------+
                        //
                        //   0   1   2   3   4   5   6   7
                        // +---+---+---+---+---+---+---+---+
                        // | 0 | 0 | 0 | ? |       0       |
                        // +---+---+-----------------------+
                        // | H |     Name Length (7+)      |
                        // +---+---------------------------+
                        // |  Name String (Length octets)  |
                        // +---+---------------------------+
                        // | H |     Value Length (7+)     |
                        // +---+---------------------------+
                        // | Value String (Length octets)  |
                        // +-------------------------------+

                        let index = (ch & !0xf0) as usize;

                        if index == 0x0f {
                            ctx.index = index;
                            ctx.literal = true;
                            state = SW_INDEX;
                        } else if index == 0 {
                            state = SW_NAME_LENGTH;
                        } else {
                            if ch & 0xf0 == 0x10 {
                                ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} literal header never indexed: {}", prefix, index);
                            } else {
                                ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} literal header without indexing: {}", prefix, index);
                            }

                            ctx.index = index;
                            ctx.literal = true;

                            state = SW_VALUE_LENGTH;
                        }
                    } else {
                        // not reached
                        return NGX_ERROR;
                    }
                }

                SW_INDEX => {
                    ctx.index += (ch & !0x80) as usize;

                    if ch & 0x80 != 0 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent http2 table index with continuation flag");
                        return NGX_ERROR;
                    }

                    if ctx.index > 61 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid http2 table index: {}", ctx.index);
                        return NGX_ERROR;
                    }

                    ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} header index: {}", prefix, ctx.index);

                    state = SW_VALUE_LENGTH;
                }

                SW_NAME_LENGTH => {
                    ctx.field_huffman = ch & 0x80 != 0;
                    ctx.field_length = (ch & !0x80) as usize;

                    if ctx.field_length == 0x7f {
                        state = SW_NAME_LENGTH_2;
                    } else if ctx.field_length == 0 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent zero http2 header name length");
                        return NGX_ERROR;
                    } else {
                        state = SW_NAME;
                    }
                }

                SW_NAME_LENGTH_2 => {
                    ctx.field_length += (ch & !0x80) as usize;

                    state = if ch & 0x80 != 0 { SW_NAME_LENGTH_3 } else { SW_NAME };
                }

                SW_NAME_LENGTH_3 => {
                    ctx.field_length += ((ch & !0x80) as usize) << 7;

                    state = if ch & 0x80 != 0 { SW_NAME_LENGTH_4 } else { SW_NAME };
                }

                SW_NAME_LENGTH_4 => {
                    ctx.field_length += ((ch & !0x80) as usize) << 14;

                    if ch & 0x80 != 0 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too large http2 header name length");
                        return NGX_ERROR;
                    }

                    state = SW_NAME;
                }

                SW_NAME | SW_NAME_BYTES => {
                    if state == SW_NAME {
                        let len = if ctx.field_huffman { ctx.field_length * 8 / 5 } else { ctx.field_length };

                        if len > ctx.header_limit {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too large http2 header name length: {}", len);
                            return NGX_ERROR;
                        }

                        ctx.name = Vec::with_capacity(len);

                        ctx.field_rest = ctx.field_length;
                        ctx.field_state = 0;

                        state = SW_NAME_BYTES;
                    }

                    // sw_name_bytes

                    ngx_core::ngx_log_debug!(
                        NGX_LOG_DEBUG_HTTP,
                        log,
                        "{} name: len:{} h:{} last:{}, rest:{}", prefix,
                        ctx.field_length,
                        ctx.field_huffman as i32,
                        last - p,
                        ctx.rest - (p - *pos)
                    );

                    let size = (last - p).min(ctx.field_rest);
                    ctx.field_rest -= size;

                    if ctx.field_huffman {
                        if crate::huff_decode::huff_decode(&mut ctx.field_state, &buf[p..p + size], &mut ctx.name, ctx.field_rest == 0, &log).is_err() {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid encoded header");
                            return NGX_ERROR;
                        }
                    } else {
                        ctx.name.extend_from_slice(&buf[p..p + size]);
                    }

                    p += size - 1;

                    if ctx.field_rest == 0 {
                        state = SW_VALUE_LENGTH;
                    }
                }

                SW_VALUE_LENGTH => {
                    ctx.field_huffman = ch & 0x80 != 0;
                    ctx.field_length = (ch & !0x80) as usize;

                    if ctx.field_length == 0x7f {
                        state = SW_VALUE_LENGTH_2;
                    } else if ctx.field_length == 0 {
                        ctx.value = Vec::new();
                        done = true;
                    } else {
                        state = SW_VALUE;
                    }
                }

                SW_VALUE_LENGTH_2 => {
                    ctx.field_length += (ch & !0x80) as usize;

                    state = if ch & 0x80 != 0 { SW_VALUE_LENGTH_3 } else { SW_VALUE };
                }

                SW_VALUE_LENGTH_3 => {
                    ctx.field_length += ((ch & !0x80) as usize) << 7;

                    state = if ch & 0x80 != 0 { SW_VALUE_LENGTH_4 } else { SW_VALUE };
                }

                SW_VALUE_LENGTH_4 => {
                    ctx.field_length += ((ch & !0x80) as usize) << 14;

                    if ch & 0x80 != 0 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too large http2 header value length");
                        return NGX_ERROR;
                    }

                    state = SW_VALUE;
                }

                _ => {
                    // SW_VALUE, SW_VALUE_BYTES

                    if state == SW_VALUE {
                        let len = if ctx.field_huffman { ctx.field_length * 8 / 5 } else { ctx.field_length };

                        if len > ctx.header_limit {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too large http2 header value length: {}", len);
                            return NGX_ERROR;
                        }

                        ctx.value = Vec::with_capacity(len);

                        ctx.field_rest = ctx.field_length;
                        ctx.field_state = 0;

                        state = SW_VALUE_BYTES;
                    }

                    // sw_value_bytes

                    ngx_core::ngx_log_debug!(
                        NGX_LOG_DEBUG_HTTP,
                        log,
                        "{} value: len:{} h:{} last:{}, rest:{}", prefix,
                        ctx.field_length,
                        ctx.field_huffman as i32,
                        last - p,
                        ctx.rest - (p - *pos)
                    );

                    let size = (last - p).min(ctx.field_rest);
                    ctx.field_rest -= size;

                    if ctx.field_huffman {
                        if crate::huff_decode::huff_decode(&mut ctx.field_state, &buf[p..p + size], &mut ctx.value, ctx.field_rest == 0, &log).is_err() {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid encoded header");
                            return NGX_ERROR;
                        }
                    } else {
                        ctx.value.extend_from_slice(&buf[p..p + size]);
                    }

                    p += size - 1;

                    if ctx.field_rest == 0 {
                        done = true;
                    }
                }
            }

            if !done {
                p += 1;
                continue;
            }

            // done:

            p += 1;
            ctx.rest -= p - *pos;
            ctx.fragment_state = SW_START;
            *pos = p;

            if ctx.index != 0 {
                ctx.name = crate::v2::table::get_static_name(ctx.index).to_vec();
            }

            if ctx.index != 0 && !ctx.literal {
                ctx.value = crate::v2::table::get_static_value(ctx.index).to_vec();
            }

            if ctx.index == 0 && validate_header_name(&ctx.name).is_err() {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid header: \"{}: {}\"", B(&ctx.name), B(&ctx.value));
                return NGX_ERROR;
            }

            if (ctx.index == 0 || ctx.literal) && validate_header_value(&ctx.value).is_err() {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent invalid header: \"{}: {}\"", B(&ctx.name), B(&ctx.value));
                return NGX_ERROR;
            }

            let len = ctx.name.len() + ctx.value.len();

            if len > ctx.header_limit {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too large http2 header");
                return NGX_ERROR;
            }

            ctx.header_limit -= len;

            return NGX_OK;
        }

        ctx.rest -= p - *pos;
        ctx.fragment_state = state;
        *pos = p;

        if ctx.rest > padding {
            return NGX_AGAIN;
        }

        NGX_DONE
    }

    /// ngx_http_{grpc,proxy_v2}_parse_rst_stream
    pub(crate) fn parse_rst_stream(&mut self, log: &Log, buf: &[u8], pos: &mut usize) -> i64 {
        let prefix = self.prefix;

        let ctx = &mut *self;

        let last = if buf.len() - *pos < ctx.rest { buf.len() } else { *pos + ctx.rest };

        let mut state = ctx.frame_state;

        if state == 0 && ctx.rest != 4 {
            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent rst stream frame with invalid length: {}", ctx.rest);
            return NGX_ERROR;
        }

        let mut p = *pos;

        while p < last {
            let ch = buf[p] as usize;

            match state {
                0 => {
                    ctx.error = ch << 24;
                    state = 1;
                }
                1 => {
                    ctx.error |= ch << 16;
                    state = 2;
                }
                2 => {
                    ctx.error |= ch << 8;
                    state = 3;
                }
                _ => {
                    ctx.error |= ch;
                    state = 0;

                    ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} error: {}", prefix, ctx.error);
                }
            }

            p += 1;
        }

        ctx.rest -= p - *pos;
        ctx.frame_state = state;
        *pos = p;

        if ctx.rest > 0 {
            return NGX_AGAIN;
        }

        ctx.state = ST_START;

        NGX_OK
    }

    /// ngx_http_{grpc,proxy_v2}_parse_goaway
    pub(crate) fn parse_goaway(&mut self, log: &Log, buf: &[u8], pos: &mut usize) -> i64 {
        let prefix = self.prefix;

        let ctx = &mut *self;

        let last = if buf.len() - *pos < ctx.rest { buf.len() } else { *pos + ctx.rest };

        let mut state = ctx.frame_state;

        if state == 0 {
            if ctx.stream_id != 0 {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent goaway frame with non-zero stream id: {}", ctx.stream_id);
                return NGX_ERROR;
            }

            if ctx.rest < 8 {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent goaway frame with invalid length: {}", ctx.rest);
                return NGX_ERROR;
            }
        }

        let mut p = *pos;

        while p < last {
            let ch = buf[p] as usize;

            match state {
                0 => {
                    ctx.stream_id = (ch & 0x7f) << 24;
                    state = 1;
                }
                1 => {
                    ctx.stream_id |= ch << 16;
                    state = 2;
                }
                2 => {
                    ctx.stream_id |= ch << 8;
                    state = 3;
                }
                3 => {
                    ctx.stream_id |= ch;
                    state = 4;
                }
                4 => {
                    ctx.error = ch << 24;
                    state = 5;
                }
                5 => {
                    ctx.error |= ch << 16;
                    state = 6;
                }
                6 => {
                    ctx.error |= ch << 8;
                    state = 7;
                }
                7 => {
                    ctx.error |= ch;
                    state = 8;
                }
                _ => {}
            }

            p += 1;
        }

        ctx.rest -= p - *pos;
        ctx.frame_state = state;
        *pos = p;

        if ctx.rest > 0 {
            return NGX_AGAIN;
        }

        ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} goaway: {}, stream {}", prefix, ctx.error, ctx.stream_id);

        ctx.state = ST_START;

        NGX_OK
    }

    /// ngx_http_{grpc,proxy_v2}_parse_window_update
    pub(crate) fn parse_window_update(&mut self, log: &Log, buf: &[u8], pos: &mut usize) -> i64 {
        let prefix = self.prefix;

        {
            let ctx = &mut *self;

            let last = if buf.len() - *pos < ctx.rest { buf.len() } else { *pos + ctx.rest };

            let mut state = ctx.frame_state;

            if state == 0 && ctx.rest != 4 {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent window update frame with invalid length: {}", ctx.rest);
                return NGX_ERROR;
            }

            let mut p = *pos;

            while p < last {
                let ch = buf[p] as usize;

                match state {
                    0 => {
                        ctx.window_update = (ch & 0x7f) << 24;
                        state = 1;
                    }
                    1 => {
                        ctx.window_update |= ch << 16;
                        state = 2;
                    }
                    2 => {
                        ctx.window_update |= ch << 8;
                        state = 3;
                    }
                    _ => {
                        ctx.window_update |= ch;
                        state = 0;
                    }
                }

                p += 1;
            }

            ctx.rest -= p - *pos;
            ctx.frame_state = state;
            *pos = p;

            if ctx.rest > 0 {
                return NGX_AGAIN;
            }

            ctx.state = ST_START;

            ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} window update: {}", prefix, ctx.window_update);

            if ctx.window_update == 0 {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent zero window update");
                return NGX_ERROR;
            }
        }

        let window_update = self.window_update;

        if self.stream_id != 0 {
            if window_update as i64 > NGX_HTTP_V2_MAX_WINDOW as i64 - self.send_window as i64 {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too large window update");
                return NGX_ERROR;
            }

            self.send_window += window_update as isize;
        } else {
            let mut conn = self.conn();

            if window_update > NGX_HTTP_V2_MAX_WINDOW - conn.send_window {
                drop(conn);
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too large window update");
                return NGX_ERROR;
            }

            conn.send_window += window_update;
        }

        NGX_OK
    }

    /// ngx_http_{grpc,proxy_v2}_parse_settings
    pub(crate) fn parse_settings(&mut self, log: &Log, buf: &[u8], pos: &mut usize) -> i64 {
        let prefix = self.prefix;

        const SW_START: u8 = 0;
        const SW_ID: u8 = 1;
        const SW_ID_2: u8 = 2;
        const SW_VALUE: u8 = 3;
        const SW_VALUE_2: u8 = 4;
        const SW_VALUE_3: u8 = 5;
        const SW_VALUE_4: u8 = 6;

        let last = if buf.len() - *pos < self.rest { buf.len() } else { *pos + self.rest };

        let mut state = self.frame_state;

        if state == SW_START {
            let ctx = &mut *self;

            if ctx.stream_id != 0 {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent settings frame with non-zero stream id: {}", ctx.stream_id);
                return NGX_ERROR;
            }

            if ctx.flags & NGX_HTTP_V2_ACK_FLAG != 0 {
                ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} settings ack", prefix);

                if ctx.rest != 0 {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent settings frame with ack flag and non-zero length: {}", ctx.rest);
                    return NGX_ERROR;
                }

                ctx.state = ST_START;

                return NGX_OK;
            }

            if ctx.rest % 6 != 0 {
                ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent settings frame with invalid length: {}", ctx.rest);
                return NGX_ERROR;
            }

            if ctx.free == 0 {
                let settings = ctx.settings;
                ctx.settings += 1;

                if settings > 1000 {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too many settings frames");
                    return NGX_ERROR;
                }
            }
        }

        let mut p = *pos;

        while p < last {
            let ch = buf[p] as usize;

            match state {
                SW_START | SW_ID => {
                    self.setting_id = ch << 8;
                    state = SW_ID_2;
                }

                SW_ID_2 => {
                    self.setting_id |= ch;
                    state = SW_VALUE;
                }

                SW_VALUE => {
                    self.setting_value = ch << 24;
                    state = SW_VALUE_2;
                }

                SW_VALUE_2 => {
                    self.setting_value |= ch << 16;
                    state = SW_VALUE_3;
                }

                SW_VALUE_3 => {
                    self.setting_value |= ch << 8;
                    state = SW_VALUE_4;
                }

                _ => {
                    self.setting_value |= ch;
                    state = SW_ID;

                    ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} setting: {} {}", prefix, self.setting_id, self.setting_value);

                    // The following settings are defined by the protocol:
                    //
                    // SETTINGS_HEADER_TABLE_SIZE, SETTINGS_ENABLE_PUSH,
                    // SETTINGS_MAX_CONCURRENT_STREAMS,
                    // SETTINGS_INITIAL_WINDOW_SIZE, SETTINGS_MAX_FRAME_SIZE,
                    // SETTINGS_MAX_HEADER_LIST_SIZE
                    //
                    // Only SETTINGS_INITIAL_WINDOW_SIZE seems to be needed
                    // in a simple client.

                    if self.setting_id == 0x04 {
                        // SETTINGS_INITIAL_WINDOW_SIZE

                        let value = self.setting_value;

                        if value > NGX_HTTP_V2_MAX_WINDOW {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent settings frame with too large initial window size: {}", value);
                            return NGX_ERROR;
                        }

                        let window_update = {
                            let mut conn = self.conn();
                            let w = value as isize - conn.init_window as isize;
                            conn.init_window = value;
                            w
                        };

                        if self.send_window > 0 && window_update > NGX_HTTP_V2_MAX_WINDOW as isize - self.send_window {
                            ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent settings frame with too large initial window size: {}", value);
                            return NGX_ERROR;
                        }

                        self.send_window += window_update;
                    }
                }
            }

            p += 1;
        }

        self.rest -= p - *pos;
        self.frame_state = state;
        *pos = p;

        if self.rest > 0 {
            return NGX_AGAIN;
        }

        self.state = ST_START;

        self.send_settings_ack(log)
    }

    /// ngx_http_{grpc,proxy_v2}_parse_ping
    pub(crate) fn parse_ping(&mut self, log: &Log, buf: &[u8], pos: &mut usize) -> i64 {
        let prefix = self.prefix;

        {
            let ctx = &mut *self;

            let last = if buf.len() - *pos < ctx.rest { buf.len() } else { *pos + ctx.rest };

            let mut state = ctx.frame_state;

            if state == 0 {
                if ctx.stream_id != 0 {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent ping frame with non-zero stream id: {}", ctx.stream_id);
                    return NGX_ERROR;
                }

                if ctx.rest != 8 {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent ping frame with invalid length: {}", ctx.rest);
                    return NGX_ERROR;
                }

                if ctx.flags & NGX_HTTP_V2_ACK_FLAG != 0 {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent ping frame with ack flag");
                    return NGX_ERROR;
                }

                if ctx.free == 0 {
                    let pings = ctx.pings;
                    ctx.pings += 1;

                    if pings > 1000 {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "upstream sent too many ping frames");
                        return NGX_ERROR;
                    }
                }
            }

            let mut p = *pos;

            while p < last {
                let ch = buf[p];

                if state < 7 {
                    ctx.ping_data[state as usize] = ch;
                    state += 1;
                } else {
                    ctx.ping_data[7] = ch;
                    state = 0;

                    ngx_core::ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "{} ping", prefix);
                }

                p += 1;
            }

            ctx.rest -= p - *pos;
            ctx.frame_state = state;
            *pos = p;

            if ctx.rest > 0 {
                return NGX_AGAIN;
            }

            ctx.state = ST_START;
        }

        self.send_ping_ack(log)
    }
}

/// ngx_http_{grpc,proxy_v2}_validate_header_name
pub fn validate_header_name(s: &[u8]) -> Result<(), ()> {
    for (i, &ch) in s.iter().enumerate() {
        if ch == b':' && i > 0 {
            return Err(());
        }

        if ch.is_ascii_uppercase() {
            return Err(());
        }

        if ch <= 0x20 || ch == 0x7f {
            return Err(());
        }
    }

    Ok(())
}

/// ngx_http_{grpc,proxy_v2}_validate_header_value
pub fn validate_header_value(s: &[u8]) -> Result<(), ()> {
    if s.iter().any(|&ch| ch == 0 || ch == b'\r' || ch == b'\n') {
        return Err(());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::encode::{indexed, write_name, write_value};

    fn capture() -> (Log, Rc<RefCell<Vec<u8>>>) {
        let logged: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let lg = logged.clone();
        let chain = LogChain::new();
        chain.insert(LogEntry::new(NGX_LOG_INFO, LogWriter::Custom(Rc::new(move |_, line: &[u8]| lg.borrow_mut().extend_from_slice(line)))));
        (Log::new(chain), logged)
    }

    fn text(l: &RefCell<Vec<u8>>) -> String {
        String::from_utf8_lossy(&l.borrow()).into_owned()
    }

    /// the stream of a new connection, as ngx_http_grpc_get_ctx sets it up
    fn module() -> H2Ctx {
        let mut m = H2Ctx::new("grpc", 1);

        m.connection = Some(Rc::new(RefCell::new(H2Conn {
            init_window: NGX_HTTP_V2_DEFAULT_WINDOW,
            send_window: NGX_HTTP_V2_DEFAULT_WINDOW,
            recv_window: NGX_HTTP_V2_MAX_WINDOW,
            last_stream_id: 1,
            tag: 1,
        })));
        m.send_window = NGX_HTTP_V2_DEFAULT_WINDOW as isize;
        m.recv_window = NGX_HTTP_V2_MAX_WINDOW;
        m.id = 1;

        m
    }

    fn frame(ty: u8, flags: u8, sid: usize, payload: &[u8]) -> Vec<u8> {
        let mut v = frame_header(payload.len(), ty, flags, sid).to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// (type, flags, stream id, payload) of the frames in `data`
    fn split_frames(data: &[u8]) -> Vec<(u8, u8, usize, Vec<u8>)> {
        let mut v = Vec::new();
        let mut p = 0;

        while p < data.len() {
            let len = ((data[p] as usize) << 16) | ((data[p + 1] as usize) << 8) | data[p + 2] as usize;
            let sid = u32::from_be_bytes([data[p + 5], data[p + 6], data[p + 7], data[p + 8]]) as usize & 0x7fff_ffff;

            v.push((data[p + 3], data[p + 4], sid, data[p + FRAME_SIZE..p + FRAME_SIZE + len].to_vec()));

            p += FRAME_SIZE + len;
        }

        v
    }

    fn lens(f: &[(u8, u8, usize, Vec<u8>)]) -> Vec<(u8, u8, usize, usize)> {
        f.iter().map(|(t, fl, id, p)| (*t, *fl, *id, p.len())).collect()
    }

    fn bytes(out: &Chain) -> Vec<u8> {
        let mut v = Vec::new();

        for b in out.iter() {
            if let BufData::Memory(d) = &b.data {
                v.extend_from_slice(&d[b.pos..b.last]);
            }
        }

        v
    }

    type Fields = Vec<(Vec<u8>, Vec<u8>)>;

    /// The loop of ngx_http_grpc_process_header over the HEADERS and
    /// CONTINUATION frames in `buf`, the header fields parsed added to
    /// `fields`.
    fn parse_headers(m: &mut H2Ctx, log: &Log, buffer_size: usize, buf: &[u8], fields: &mut Fields) -> i64 {
        let mut pos = 0;

        loop {
            if m.state < ST_PAYLOAD {
                let rc = m.parse_frame(log, buf, &mut pos);

                if rc != NGX_OK {
                    return rc;
                }
            }

            let rc = m.parse_header(log, buffer_size, buf, &mut pos);

            if rc == NGX_OK {
                fields.push((m.name.clone(), m.value.clone()));
                continue;
            }

            if rc == NGX_AGAIN && m.rest == 0 {
                m.state = ST_START;
                continue;
            }

            return rc;
        }
    }

    /// `data` given to parse_headers in pieces of `step` bytes
    fn parse_headers_split(data: &[u8], step: usize) -> (i64, Fields, H2Ctx) {
        let (log, _) = capture();
        let mut m = module();
        let mut fields = Vec::new();
        let mut rc = NGX_AGAIN;

        for chunk in data.chunks(step) {
            rc = parse_headers(&mut m, &log, 4096, chunk, &mut fields);

            if rc != NGX_AGAIN {
                break;
            }
        }

        (rc, fields, m)
    }

    /// the error logged for a HEADERS frame
    fn header_error(flags: u8, payload: &[u8], buffer_size: usize) -> String {
        let (log, logged) = capture();
        let mut m = module();
        let mut fields = Vec::new();

        let rc = parse_headers(&mut m, &log, buffer_size, &frame(NGX_HTTP_V2_HEADERS_FRAME, flags, 1, payload), &mut fields);

        assert_eq!(rc, NGX_ERROR, "{:?}", fields);

        text(&logged)
    }

    /// The dispatch of ngx_http_grpc_process_header for a control frame,
    /// `data` given in pieces of `step` bytes.
    fn control(m: &mut H2Ctx, log: &Log, data: &[u8], step: usize) -> i64 {
        let mut rc = NGX_AGAIN;

        for chunk in data.chunks(step) {
            let mut pos = 0;

            if m.state < ST_PAYLOAD {
                rc = m.parse_frame(log, chunk, &mut pos);

                if rc == NGX_AGAIN {
                    continue;
                }

                if rc == NGX_ERROR {
                    return rc;
                }
            }

            rc = match m.ty {
                NGX_HTTP_V2_RST_STREAM_FRAME => m.parse_rst_stream(log, chunk, &mut pos),
                NGX_HTTP_V2_GOAWAY_FRAME => m.parse_goaway(log, chunk, &mut pos),
                NGX_HTTP_V2_WINDOW_UPDATE_FRAME => m.parse_window_update(log, chunk, &mut pos),
                NGX_HTTP_V2_SETTINGS_FRAME => m.parse_settings(log, chunk, &mut pos),
                NGX_HTTP_V2_PING_FRAME => m.parse_ping(log, chunk, &mut pos),
                ty => panic!("frame type {}", ty),
            };

            if rc == NGX_ERROR {
                return rc;
            }

            assert_eq!(pos, chunk.len());

            if rc != NGX_AGAIN {
                return rc;
            }
        }

        rc
    }

    /// the error logged for a control frame
    fn control_error(m: &mut H2Ctx, data: &[u8]) -> String {
        let (log, logged) = capture();

        assert_eq!(control(m, &log, data, data.len()), NGX_ERROR);

        text(&logged)
    }

    fn f(name: &str, value: &str) -> (Vec<u8>, Vec<u8>) {
        (name.as_bytes().to_vec(), value.as_bytes().to_vec())
    }

    /// a header block with each kind of representation
    fn header_block() -> (Vec<u8>, Fields) {
        let mut block = vec![0x88];

        // literal header with incremental indexing, indexed name
        block.extend_from_slice(b"\x5f\x0atext/plain");

        // literal header without indexing, new name
        block.extend_from_slice(b"\x00\x03foo\x03bar");

        // literal header never indexed, the index in two octets
        block.extend_from_slice(b"\x1f\x12\x01x");

        // dynamic table size update to zero
        block.push(0x20);

        // huffman encoded value (RFC 7541, C.4.1)
        block.extend_from_slice(b"\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff");

        // huffman encoded name and value (RFC 7541, C.4.3)
        block.extend_from_slice(b"\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf");

        // empty value
        block.extend_from_slice(b"\x10\x01y\x00");

        let fields = vec![
            f(":status", "200"),
            f("content-type", "text/plain"),
            f("foo", "bar"),
            f("date", "x"),
            f(":authority", "www.example.com"),
            f("custom-key", "custom-value"),
            f("y", ""),
        ];

        (block, fields)
    }

    #[test]
    fn test_frame_header() {
        assert_eq!(frame_header(0x012345, NGX_HTTP_V2_HEADERS_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 0x8000_0103), [0x01, 0x23, 0x45, 0x01, 0x04, 0x00, 0x00, 0x01, 0x03]);
    }

    #[test]
    fn test_parse_frame() {
        let (log, _) = capture();
        let mut m = module();

        let buf = b"\x00\x00\x08\x06\x00\x80\x00\x00\x05\xff";
        let mut pos = 0;

        assert_eq!(m.parse_frame(&log, buf, &mut pos), NGX_OK);
        assert_eq!(pos, FRAME_SIZE);
        assert_eq!((m.rest, m.ty, m.flags, m.stream_id), (8, NGX_HTTP_V2_PING_FRAME, 0, 5));
        assert_eq!(m.state, ST_PAYLOAD);
    }

    #[test]
    fn test_parse_frame_split() {
        let (log, _) = capture();
        let mut m = module();

        let hdr = frame_header(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, NGX_HTTP_V2_DATA_FRAME, NGX_HTTP_V2_END_STREAM_FLAG, 7);

        for (i, ch) in hdr.iter().enumerate() {
            let mut pos = 0;

            let rc = m.parse_frame(&log, &[*ch], &mut pos);

            assert_eq!(pos, 1);
            assert_eq!(rc, if i == FRAME_SIZE - 1 { NGX_OK } else { NGX_AGAIN });
        }

        assert_eq!((m.rest, m.ty, m.flags, m.stream_id), (NGX_HTTP_V2_DEFAULT_FRAME_SIZE, NGX_HTTP_V2_DATA_FRAME, NGX_HTTP_V2_END_STREAM_FLAG, 7));
    }

    #[test]
    fn test_parse_frame_too_large() {
        let (log, logged) = capture();
        let mut m = module();

        let hdr = frame_header(NGX_HTTP_V2_DEFAULT_FRAME_SIZE + 1, NGX_HTTP_V2_DATA_FRAME, 0, 1);
        let mut pos = 0;

        assert_eq!(m.parse_frame(&log, &hdr, &mut pos), NGX_ERROR);
        assert!(text(&logged).contains("upstream sent too large http2 frame: 16385"));
    }

    #[test]
    fn test_parse_header_fields() {
        let (block, expected) = header_block();

        let data = frame(NGX_HTTP_V2_HEADERS_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG | NGX_HTTP_V2_END_STREAM_FLAG, 1, &block);

        // every split of the frame between reads

        for step in 1..=data.len() {
            let (rc, fields, m) = parse_headers_split(&data, step);

            assert_eq!(rc, NGX_HTTP_PARSE_HEADER_DONE, "step {}", step);
            assert_eq!(fields, expected, "step {}", step);
            assert!(m.end_stream);
            assert!(!m.parsing_headers);
            assert_eq!(m.state, ST_START);
        }
    }

    #[test]
    fn test_parse_header_padding_priority_continuation() {
        let (block, expected) = header_block();

        // the block split in the middle of "text/plain", the HEADERS frame
        // with padding and priority

        let at = 6;

        let mut payload = vec![3];
        payload.extend_from_slice(b"\x80\x00\x00\x03\x10");
        payload.extend_from_slice(&block[..at]);
        payload.extend_from_slice(b"\x00\x00\x00");

        let mut data = frame(NGX_HTTP_V2_HEADERS_FRAME, NGX_HTTP_V2_PADDED_FLAG | NGX_HTTP_V2_PRIORITY_FLAG, 1, &payload);
        data.extend(frame(NGX_HTTP_V2_CONTINUATION_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 1, &block[at..]));

        for step in 1..=data.len() {
            let (rc, fields, m) = parse_headers_split(&data, step);

            assert_eq!(rc, NGX_HTTP_PARSE_HEADER_DONE, "step {}", step);
            assert_eq!(fields, expected, "step {}", step);
            assert!(!m.end_stream);
        }
    }

    #[test]
    fn test_parse_header_roundtrip() {
        // the encoding of ngx_http_grpc_create_request, CONTINUATION frames
        // included, decoded

        let long = "v".repeat(20000);
        let fields = vec![f("x-short", "1"), f("x-mixed", "Some Value; q=0.5"), f("x-long", &long), f("x-bin", "\u{1}\u{7f}~")];

        let mut b = frame_header(0, NGX_HTTP_V2_HEADERS_FRAME, 0, 1).to_vec();

        b.push(indexed(NGX_HTTP_V2_STATUS_200_INDEX));

        for (name, value) in fields.iter() {
            b.push(0);
            write_name(&mut b, &name.to_ascii_uppercase());
            write_value(&mut b, value);
        }

        header_frames(&mut b, 0);

        assert_eq!(lens(&split_frames(&b)).iter().map(|x| (x.0, x.1)).collect::<Vec<_>>(), vec![(NGX_HTTP_V2_HEADERS_FRAME, 0), (NGX_HTTP_V2_CONTINUATION_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG)]);

        let (log, _) = capture();
        let mut m = module();
        let mut parsed = Vec::new();

        assert_eq!(parse_headers(&mut m, &log, 65536, &b, &mut parsed), NGX_HTTP_PARSE_HEADER_DONE);

        let mut expected = vec![f(":status", "200")];
        expected.extend(fields);

        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_parse_header_errors() {
        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x80", 4096);
        assert!(e.contains("upstream sent invalid http2 table index: 0"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\xbe", 4096);
        assert!(e.contains("upstream sent invalid http2 table index: 62"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x7f", 4096);
        assert!(e.contains("upstream sent invalid http2 table index: 63"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x1f\x30", 4096);
        assert!(e.contains("upstream sent invalid http2 table index: 63"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x1f\x80", 4096);
        assert!(e.contains("upstream sent http2 table index with continuation flag"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x21", 4096);
        assert!(e.contains("upstream sent invalid http2 dynamic table size update: 1"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x00", 4096);
        assert!(e.contains("upstream sent zero http2 header name length"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x7f\x80\x80\x80", 4096);
        assert!(e.contains("upstream sent too large http2 header name length"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x01a\x7f\x80\x80\x80", 4096);
        assert!(e.contains("upstream sent too large http2 header value length"), "{}", e);

        // 127 + 1 + (1 << 7) octets, and huffman encoded 8 / 5 of 100

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x7f\x81\x01a", 100);
        assert!(e.contains("upstream sent too large http2 header name length: 256"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\xe4a", 150);
        assert!(e.contains("upstream sent too large http2 header name length: 160"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x01a\x7f\x26b", 100);
        assert!(e.contains("upstream sent too large http2 header value length: 165"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x03Foo\x03bar", 4096);
        assert!(e.contains("upstream sent invalid header: \"Foo: bar\""), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x03a:b\x01c", 4096);
        assert!(e.contains("upstream sent invalid header: \"a:b: c\""), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x03foo\x03b\x00r", 4096);
        assert!(e.contains("upstream sent invalid header: \"foo: b"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x5f\x03b\nr", 4096);
        assert!(e.contains("upstream sent invalid header: \"content-type: b"), "{}", e);

        // an incomplete code; a padding of 8 bits and more is accepted as
        // by ngx_http_huff_decode

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x81\xfe\x01a", 4096);
        assert!(e.contains("upstream sent invalid encoded header"), "{}", e);

        // the name and the value within the limit each, but not together

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x06abcdef\x06ghijkl", 10);
        assert!(e.contains("upstream sent too large http2 header"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG, b"\x00\x03fo", 4096);
        assert!(e.contains("upstream sent truncated http2 header"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG | NGX_HTTP_V2_PADDED_FLAG | NGX_HTTP_V2_PRIORITY_FLAG, b"\x00\x00\x00\x00\x00", 4096);
        assert!(e.contains("upstream sent headers frame with invalid length: 5"), "{}", e);

        let e = header_error(NGX_HTTP_V2_END_HEADERS_FLAG | NGX_HTTP_V2_PADDED_FLAG, b"\x0a\x88\x00\x00\x00", 4096);
        assert!(e.contains("upstream sent http2 frame with too long padding: 10 in frame 4"), "{}", e);
    }

    #[test]
    fn test_header_limit() {
        // the limit is the buffer size for all the header fields

        let (log, logged) = capture();
        let mut m = module();
        let mut fields = Vec::new();

        let data = frame(NGX_HTTP_V2_HEADERS_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 1, b"\x00\x03foo\x03bar\x00\x03baz\x03qux");

        assert_eq!(parse_headers(&mut m, &log, 11, &data, &mut fields), NGX_ERROR);
        assert_eq!(fields, vec![f("foo", "bar")]);
        assert!(text(&logged).contains("upstream sent too large http2 header"));

        let mut m = module();
        let mut fields = Vec::new();

        assert_eq!(parse_headers(&mut m, &log, 12, &data, &mut fields), NGX_HTTP_PARSE_HEADER_DONE);
        assert_eq!(fields, vec![f("foo", "bar"), f("baz", "qux")]);
    }

    #[test]
    fn test_parse_rst_stream() {
        let (log, _) = capture();

        let data = frame(NGX_HTTP_V2_RST_STREAM_FRAME, 0, 1, b"\x00\x00\x00\x08");

        for step in 1..=data.len() {
            let mut m = module();

            assert_eq!(control(&mut m, &log, &data, step), NGX_OK);
            assert_eq!(m.error, 8);
            assert_eq!(m.state, ST_START);
        }

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_RST_STREAM_FRAME, 0, 1, b"\x00\x00\x00"));
        assert!(e.contains("upstream sent rst stream frame with invalid length: 3"), "{}", e);
    }

    #[test]
    fn test_parse_goaway() {
        let (log, _) = capture();

        let data = frame(NGX_HTTP_V2_GOAWAY_FRAME, 0, 0, b"\x80\x00\x01\x03\x00\x00\x00\x02debug data");

        for step in 1..=data.len() {
            let mut m = module();

            assert_eq!(control(&mut m, &log, &data, step), NGX_OK);
            assert_eq!((m.stream_id, m.error), (0x103, 2));
            assert_eq!(m.state, ST_START);
        }

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_GOAWAY_FRAME, 0, 1, b"\x00\x00\x00\x00\x00\x00\x00\x00"));
        assert!(e.contains("upstream sent goaway frame with non-zero stream id: 1"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_GOAWAY_FRAME, 0, 0, b"\x00\x00\x00\x00\x00\x00\x00"));
        assert!(e.contains("upstream sent goaway frame with invalid length: 7"), "{}", e);
    }

    #[test]
    fn test_parse_window_update() {
        let (log, _) = capture();

        // the stream's window, the reserved bit ignored

        let data = frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 1, b"\x80\x00\x01\x00");

        for step in 1..=data.len() {
            let mut m = module();

            assert_eq!(control(&mut m, &log, &data, step), NGX_OK);
            assert_eq!(m.send_window, 65535 + 256);
            assert_eq!(m.conn().send_window, 65535);
            assert_eq!(m.state, ST_START);
        }

        // the connection's window

        let mut m = module();

        assert_eq!(control(&mut m, &log, &frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 0, b"\x00\x00\x03\xe8"), 13), NGX_OK);
        assert_eq!(m.send_window, 65535);
        assert_eq!(m.conn().send_window, 65535 + 1000);

        // a window up to 2^31 - 1, from below zero too

        let mut m = module();
        m.send_window = -65535;

        assert_eq!(control(&mut m, &log, &frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 1, b"\x7f\xff\xff\xff"), 13), NGX_OK);
        assert_eq!(m.send_window, NGX_HTTP_V2_MAX_WINDOW as isize - 65535);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 1, b"\x00\x00\x00\x00"));
        assert!(e.contains("upstream sent zero window update"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 1, b"\x7f\xff\x00\x01"));
        assert!(e.contains("upstream sent too large window update"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 0, b"\x7f\xff\x00\x01"));
        assert!(e.contains("upstream sent too large window update"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 1, b"\x00\x00\x00\x00\x01"));
        assert!(e.contains("upstream sent window update frame with invalid length: 5"), "{}", e);
    }

    #[test]
    fn test_parse_settings() {
        let (log, _) = capture();

        // SETTINGS_INITIAL_WINDOW_SIZE and SETTINGS_MAX_CONCURRENT_STREAMS

        let data = frame(NGX_HTTP_V2_SETTINGS_FRAME, 0, 0, b"\x00\x04\x00\x01\x00\x00\x00\x03\x00\x00\x00\x64");

        for step in 1..=data.len() {
            let mut m = module();

            assert_eq!(control(&mut m, &log, &data, step), NGX_OK);
            assert_eq!(m.conn().init_window, 65536);
            assert_eq!(m.send_window, 65536);
            assert_eq!(m.state, ST_START);
            assert_eq!(bytes(&m.out), frame_header(0, NGX_HTTP_V2_SETTINGS_FRAME, NGX_HTTP_V2_ACK_FLAG, 0));
        }

        // a smaller initial window than the part of the window used

        let mut m = module();
        m.send_window = 10;

        assert_eq!(control(&mut m, &log, &frame(NGX_HTTP_V2_SETTINGS_FRAME, 0, 0, b"\x00\x04\x00\x00\x00\x00"), 15), NGX_OK);
        assert_eq!(m.send_window, 10 - 65535);
        assert_eq!(m.conn().init_window, 0);

        // an ack is not acknowledged

        let mut m = module();

        assert_eq!(control(&mut m, &log, &frame(NGX_HTTP_V2_SETTINGS_FRAME, NGX_HTTP_V2_ACK_FLAG, 0, b""), 9), NGX_OK);
        assert!(m.out.is_empty());
        assert_eq!(m.state, ST_START);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_SETTINGS_FRAME, NGX_HTTP_V2_ACK_FLAG, 0, b"\x00\x03\x00\x00\x00\x64"));
        assert!(e.contains("upstream sent settings frame with ack flag and non-zero length: 6"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_SETTINGS_FRAME, 0, 0, b"\x00\x03\x00\x00\x00"));
        assert!(e.contains("upstream sent settings frame with invalid length: 5"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_SETTINGS_FRAME, 0, 1, b""));
        assert!(e.contains("upstream sent settings frame with non-zero stream id: 1"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_SETTINGS_FRAME, 0, 0, b"\x00\x04\x80\x00\x00\x00"));
        assert!(e.contains("upstream sent settings frame with too large initial window size: 2147483648"), "{}", e);

        let mut m = module();
        m.send_window = NGX_HTTP_V2_MAX_WINDOW as isize - 10;

        let e = control_error(&mut m, &frame(NGX_HTTP_V2_SETTINGS_FRAME, 0, 0, b"\x00\x04\x00\x01\x01\x00"));
        assert!(e.contains("upstream sent settings frame with too large initial window size: 65792"), "{}", e);
    }

    #[test]
    fn test_settings_flood() {
        let (log, logged) = capture();
        let mut m = module();

        let data = frame(NGX_HTTP_V2_SETTINGS_FRAME, 0, 0, b"");

        for _ in 0..1001 {
            assert_eq!(control(&mut m, &log, &data, data.len()), NGX_OK);
        }

        assert_eq!(control(&mut m, &log, &data, data.len()), NGX_ERROR);
        assert!(text(&logged).contains("upstream sent too many settings frames"));

        // not counted while the frames sent are written out

        let mut m = module();
        m.free = 1;

        for _ in 0..2000 {
            m.free = 1;
            assert_eq!(control(&mut m, &log, &data, data.len()), NGX_OK);
        }
    }

    #[test]
    fn test_parse_ping() {
        let (log, _) = capture();

        let data = frame(NGX_HTTP_V2_PING_FRAME, 0, 0, b"\x01\x02\x03\x04\x05\x06\x07\x08");

        for step in 1..=data.len() {
            let mut m = module();

            assert_eq!(control(&mut m, &log, &data, step), NGX_OK);
            assert_eq!(m.state, ST_START);
            assert_eq!(bytes(&m.out), frame(NGX_HTTP_V2_PING_FRAME, NGX_HTTP_V2_ACK_FLAG, 0, b"\x01\x02\x03\x04\x05\x06\x07\x08"));
        }

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_PING_FRAME, NGX_HTTP_V2_ACK_FLAG, 0, b"\x00\x00\x00\x00\x00\x00\x00\x00"));
        assert!(e.contains("upstream sent ping frame with ack flag"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_PING_FRAME, 0, 0, b"\x00\x00\x00\x00\x00\x00\x00"));
        assert!(e.contains("upstream sent ping frame with invalid length: 7"), "{}", e);

        let e = control_error(&mut module(), &frame(NGX_HTTP_V2_PING_FRAME, 0, 1, b"\x00\x00\x00\x00\x00\x00\x00\x00"));
        assert!(e.contains("upstream sent ping frame with non-zero stream id: 1"), "{}", e);

        let mut m = module();
        let data = frame(NGX_HTTP_V2_PING_FRAME, 0, 0, b"\x00\x00\x00\x00\x00\x00\x00\x00");

        for _ in 0..1001 {
            assert_eq!(control(&mut m, &log, &data, data.len()), NGX_OK);
        }

        let e = control_error(&mut m, &data);
        assert!(e.contains("upstream sent too many ping frames"), "{}", e);
    }

    #[test]
    fn test_send_window_update() {
        let (log, _) = capture();
        let mut m = module();

        m.id = 3;
        m.recv_window = NGX_HTTP_V2_MAX_WINDOW - 500;
        m.conn().recv_window = NGX_HTTP_V2_MAX_WINDOW - 1000;

        assert_eq!(m.send_window_update(&log), NGX_OK);

        let mut expected = frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 0, &1000u32.to_be_bytes());
        expected.extend(frame(NGX_HTTP_V2_WINDOW_UPDATE_FRAME, 0, 3, &500u32.to_be_bytes()));

        assert_eq!(bytes(&m.out), expected);
        assert_eq!(m.recv_window, NGX_HTTP_V2_MAX_WINDOW);
        assert_eq!(m.conn().recv_window, NGX_HTTP_V2_MAX_WINDOW);
    }

    #[test]
    fn test_header_frames() {
        for (len, expected) in [
            (0, vec![(NGX_HTTP_V2_HEADERS_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 1, 0)]),
            (10, vec![(NGX_HTTP_V2_HEADERS_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 1, 10)]),
            (16384, vec![(NGX_HTTP_V2_HEADERS_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 1, 16384)]),
            (16385, vec![(NGX_HTTP_V2_HEADERS_FRAME, 0, 1, 16384), (NGX_HTTP_V2_CONTINUATION_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 1, 1)]),
            (
                40000,
                vec![
                    (NGX_HTTP_V2_HEADERS_FRAME, 0, 1, 16384),
                    (NGX_HTTP_V2_CONTINUATION_FRAME, 0, 1, 16384),
                    (NGX_HTTP_V2_CONTINUATION_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 1, 7232),
                ],
            ),
        ] {
            let block: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

            let mut b = b"preface".to_vec();
            b.extend_from_slice(&frame_header(0, NGX_HTTP_V2_HEADERS_FRAME, 0, 1));
            b.extend_from_slice(&block);

            header_frames(&mut b, 7);

            assert_eq!(&b[..7], b"preface");

            let frames = split_frames(&b[7..]);

            assert_eq!(lens(&frames), expected, "len {}", len);
            assert_eq!(frames.iter().flat_map(|x| x.3.clone()).collect::<Vec<u8>>(), block);
        }
    }

    #[test]
    fn test_keepalive_header() {
        let mut b = CONNECTION_START.to_vec();
        b.extend_from_slice(&frame_header(0, NGX_HTTP_V2_HEADERS_FRAME, 0, 1));
        b.extend(std::iter::repeat(0x88).take(20000));

        header_frames(&mut b, CONNECTION_START.len());

        let mut hb = Buf::from_vec(b);

        keepalive_header(&mut hb, 0x0102_0305);

        let frames = split_frames(&bytes(&Chain::from(vec![hb])));

        assert_eq!(
            lens(&frames),
            vec![(NGX_HTTP_V2_HEADERS_FRAME, 0, 0x0102_0305, 16384), (NGX_HTTP_V2_CONTINUATION_FRAME, NGX_HTTP_V2_END_HEADERS_FLAG, 0x0102_0305, 3616)]
        );
    }

    #[test]
    fn test_body_frames() {
        let (log, _) = capture();
        let mut m = module();

        m.id = 3;

        let body: Vec<u8> = (0..40000u32).map(|i| i as u8).collect();

        let mut b = Buf::from_vec(body.clone());
        b.last_buf = true;
        m.input.push_back(b);

        let mut out = Chain::new();

        assert_eq!(m.body_frames(&log, &mut out), 65535 - 40000);

        let frames = split_frames(&bytes(&out));

        assert_eq!(lens(&frames), vec![(0, 0, 3, 16384), (0, 0, 3, 16384), (0, NGX_HTTP_V2_END_STREAM_FLAG, 3, 7232)]);
        assert_eq!(frames.iter().flat_map(|x| x.3.clone()).collect::<Vec<u8>>(), body);
        assert!(out.back().expect("buffer").last_buf);
        assert!(m.output_closed);
        assert!(m.input.is_empty());
        assert_eq!(m.send_window, 65535 - 40000);
        assert_eq!(m.conn().send_window, 65535 - 40000);
    }

    #[test]
    fn test_body_frames_buffers() {
        let (log, _) = capture();
        let mut m = module();

        m.input.push_back(Buf::from_vec(vec![b'a'; 100]));

        let mut b = Buf::from_vec(vec![b'b'; 200]);
        b.last_buf = true;
        m.input.push_back(b);

        let mut out = Chain::new();

        assert_eq!(m.body_frames(&log, &mut out), 65535 - 300);
        assert_eq!(lens(&split_frames(&bytes(&out))), vec![(0, 0, 1, 100), (0, NGX_HTTP_V2_END_STREAM_FLAG, 1, 200)]);
        assert!(m.output_closed);
    }

    #[test]
    fn test_body_frames_flow_control() {
        let (log, _) = capture();
        let mut m = module();

        m.send_window = 20000;

        let mut b = Buf::from_vec(vec![b'x'; 40000]);
        b.last_buf = true;
        m.input.push_back(b);

        let mut out = Chain::new();

        assert_eq!(m.body_frames(&log, &mut out), 0);
        assert_eq!(lens(&split_frames(&bytes(&out))), vec![(0, 0, 1, 16384), (0, 0, 1, 3616)]);
        assert!(!m.output_closed);
        assert_eq!(m.input.len(), 1);
        assert_eq!(m.input[0].pos, 20000);
        assert_eq!(m.send_window, 0);
        assert_eq!(m.conn().send_window, 65535 - 20000);

        // nothing until a window update

        let mut out = Chain::new();

        assert_eq!(m.body_frames(&log, &mut out), 0);
        assert!(out.is_empty());

        m.send_window += 30000;

        let mut out = Chain::new();

        assert_eq!(m.body_frames(&log, &mut out), 10000);
        assert_eq!(lens(&split_frames(&bytes(&out))), vec![(0, 0, 1, 16384), (0, NGX_HTTP_V2_END_STREAM_FLAG, 1, 3616)]);
        assert!(m.output_closed);
        assert!(m.input.is_empty());

        // the connection's window, and a stream window below zero

        let mut m = module();
        m.conn().send_window = 1000;
        m.input.push_back(Buf::from_vec(vec![b'x'; 5000]));

        let mut out = Chain::new();

        assert_eq!(m.body_frames(&log, &mut out), 0);
        assert_eq!(lens(&split_frames(&bytes(&out))), vec![(0, 0, 1, 1000)]);
        assert_eq!(m.input[0].pos, 1000);

        let mut m = module();
        m.send_window = -100;
        m.input.push_back(Buf::from_vec(vec![b'x'; 5000]));

        let mut out = Chain::new();

        assert_eq!(m.body_frames(&log, &mut out), 0);
        assert!(out.is_empty());
    }

    #[test]
    fn test_body_frames_end_stream() {
        // the last buffer empty: END_STREAM on a DATA frame of its own

        let (log, _) = capture();
        let mut m = module();

        m.input.push_back(Buf { last_buf: true, ..Default::default() });

        let mut out = Chain::new();

        assert_eq!(m.body_frames(&log, &mut out), 65535);
        assert_eq!(bytes(&out), frame_header(0, NGX_HTTP_V2_DATA_FRAME, NGX_HTTP_V2_END_STREAM_FLAG, 1));
        assert!(out.back().expect("buffer").last_buf);
        assert!(m.output_closed);
        assert!(m.input.is_empty());
    }

    #[test]
    fn test_validate_header() {
        assert!(validate_header_name(b":status").is_ok());
        assert!(validate_header_name(b"x-foo_bar!").is_ok());
        assert!(validate_header_name(b"").is_ok());
        assert!(validate_header_name(b"a:b").is_err());
        assert!(validate_header_name(b"Foo").is_err());
        assert!(validate_header_name(b"a b").is_err());
        assert!(validate_header_name(b"a\x7f").is_err());
        assert!(validate_header_name(b"a\x01").is_err());

        assert!(validate_header_value(b"a b\t\x7f\xff").is_ok());
        assert!(validate_header_value(b"a\rb").is_err());
        assert!(validate_header_value(b"a\nb").is_err());
        assert!(validate_header_value(b"a\x00b").is_err());
    }

    #[test]
    fn test_hex_head() {
        assert_eq!(hex_head(b"\x00\x0a\xff"), "000aff");
        assert_eq!(hex_head(&[0xab; 256]), "ab".repeat(256));
        assert_eq!(hex_head(&[0xab; 300]), "ab".repeat(256) + "...");
    }
}
