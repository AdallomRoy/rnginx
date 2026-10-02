//! The HTTP/2 frame state machine (the ngx_http_v2_state_* functions of
//! nginx-c/src/http/v2/ngx_http_v2.c).
//!
//! Handlers consume bytes from the receive buffer and return the new
//! position; a handler that needs more input saves the unconsumed tail in
//! state.buffer (state_save) and returns the end of the buffer. They run
//! synchronously inside the connection driver's read handler; effects that
//! C performs by calling a stream's event handler inline are posted to the
//! driver, which runs them before parsing the next frame.

use std::rc::Rc;

use ngx_core::log::*;
use ngx_core::{ngx_log_debug, ngx_log_error};

use super::connection::{connection_error, get_frame, send_goaway, send_rst_stream, send_window_update};
use super::stream::{
    adjust_windows, create_stream, get_node_by_id, header_request, post_drain_waiting, post_write, run_request,
    set_dependency, stream_rst_received, terminate_stream,
};
use super::*;
use crate::core::CoreLocConf;

/// ngx_http_v2_frame_states
fn frame_state(ty: u8) -> Option<Handler> {
    Some(match ty {
        NGX_HTTP_V2_DATA_FRAME => state_data,
        NGX_HTTP_V2_HEADERS_FRAME => state_headers,
        NGX_HTTP_V2_PRIORITY_FRAME => state_priority,
        NGX_HTTP_V2_RST_STREAM_FRAME => state_rst_stream,
        NGX_HTTP_V2_SETTINGS_FRAME => state_settings,
        NGX_HTTP_V2_PUSH_PROMISE_FRAME => state_push_promise,
        NGX_HTTP_V2_PING_FRAME => state_ping,
        NGX_HTTP_V2_GOAWAY_FRAME => state_goaway,
        NGX_HTTP_V2_WINDOW_UPDATE_FRAME => state_window_update,
        NGX_HTTP_V2_CONTINUATION_FRAME => state_continuation,
        _ => return None,
    })
}

pub fn state_preface(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let end = buf.len();

    if end - pos < NGX_HTTP_V2_PREFACE_START.len() {
        return state_save(h2c, buf, pos, state_preface);
    }

    if &buf[pos..pos + NGX_HTTP_V2_PREFACE_START.len()] != NGX_HTTP_V2_PREFACE_START {
        ngx_log_error!(NGX_LOG_INFO, h2c.connection.log, None, "invalid connection preface");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    state_preface_end(h2c, buf, pos + NGX_HTTP_V2_PREFACE_START.len())
}

pub fn state_preface_end(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let end = buf.len();

    if end - pos < NGX_HTTP_V2_PREFACE_END.len() {
        return state_save(h2c, buf, pos, state_preface_end);
    }

    if &buf[pos..pos + NGX_HTTP_V2_PREFACE_END.len()] != NGX_HTTP_V2_PREFACE_END {
        ngx_log_error!(NGX_LOG_INFO, h2c.connection.log, None, "invalid connection preface");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 preface verified");

    state_head(h2c, buf, pos + NGX_HTTP_V2_PREFACE_END.len())
}

pub fn state_head(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let end = buf.len();

    if end - pos < NGX_HTTP_V2_FRAME_HEADER_SIZE {
        return state_save(h2c, buf, pos, state_head);
    }

    let head = parse_uint32(&buf[pos..]);
    let st = &h2c.state;

    st.length.set(parse_length(head));
    st.flags.set(buf[pos + 4]);
    st.sid.set(parse_sid(&buf[pos + 5..]));

    let pos = pos + NGX_HTTP_V2_FRAME_HEADER_SIZE;

    let ty = parse_type(head);

    ngx_log_debug!(
        NGX_LOG_DEBUG_HTTP,
        h2c.connection.log,
        "http2 frame type:{} f:{:X} l:{} sid:{}",
        ty,
        st.flags.get(),
        st.length.get(),
        st.sid.get()
    );

    match frame_state(ty) {
        Some(handler) => handler(h2c, buf, pos),
        None => {
            ngx_log_error!(NGX_LOG_INFO, h2c.connection.log, None, "client sent frame with unknown type {}", ty);
            state_skip(h2c, buf, pos)
        }
    }
}

fn state_data(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    let size = st.length.get();

    if st.flags.get() & NGX_HTTP_V2_PADDED_FLAG != 0 {
        if st.length.get() == 0 {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent padded DATA frame with incorrect length: 0");
            return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
        }

        if end - pos == 0 {
            return state_save(h2c, buf, pos, state_data);
        }

        st.padding.set(buf[pos] as usize);
        pos += 1;

        if st.padding.get() >= size {
            ngx_log_error!(
                NGX_LOG_INFO,
                log,
                None,
                "client sent padded DATA frame with incorrect length: {}, padding: {}",
                size,
                st.padding.get()
            );
            return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
        }

        st.length.set(st.length.get() - 1 - st.padding.get());
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 DATA frame");

    if st.sid.get() == 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent DATA frame with incorrect identifier");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if size > h2c.recv_window.get() {
        ngx_log_error!(
            NGX_LOG_INFO,
            log,
            None,
            "client violated connection flow control: received DATA frame length {}, available window {}",
            size,
            h2c.recv_window.get()
        );
        return connection_error(h2c, NGX_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c.recv_window.set(h2c.recv_window.get() - size);

    if h2c.recv_window.get() < NGX_HTTP_V2_MAX_WINDOW / 4 {
        if send_window_update(h2c, 0, NGX_HTTP_V2_MAX_WINDOW - h2c.recv_window.get()).is_err() {
            return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
        }

        h2c.recv_window.set(NGX_HTTP_V2_MAX_WINDOW);
    }

    let stream = match get_node_by_id(h2c, st.sid.get(), false).and_then(|n| n.stream.borrow().clone()) {
        Some(s) => s,
        None => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "unknown http2 stream");
            return state_skip_padded(h2c, buf, pos);
        }
    };

    let id = stream.node.borrow().id.get();

    if size > stream.recv_window.get() {
        ngx_log_error!(
            NGX_LOG_INFO,
            log,
            None,
            "client violated flow control for stream {}: received DATA frame length {}, available window {}",
            id,
            size,
            stream.recv_window.get()
        );

        if terminate_stream(h2c, &stream, NGX_HTTP_V2_FLOW_CTRL_ERROR).is_err() {
            return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
        }

        return state_skip_padded(h2c, buf, pos);
    }

    stream.recv_window.set(stream.recv_window.get() - size);

    if stream.no_flow_control.get() && stream.recv_window.get() < NGX_HTTP_V2_MAX_WINDOW / 4 {
        if send_window_update(h2c, id, NGX_HTTP_V2_MAX_WINDOW - stream.recv_window.get()).is_err() {
            return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
        }

        stream.recv_window.set(NGX_HTTP_V2_MAX_WINDOW);
    }

    if stream.in_closed.get() {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent DATA frame for half-closed stream {}", id);

        if terminate_stream(h2c, &stream, NGX_HTTP_V2_STREAM_CLOSED).is_err() {
            return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
        }

        return state_skip_padded(h2c, buf, pos);
    }

    *st.stream.borrow_mut() = Some(stream);

    state_read_data(h2c, buf, pos)
}

fn state_read_data(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;

    let stream = st.stream.borrow().clone();
    let stream = match stream {
        Some(s) => s,
        None => return state_skip_padded(h2c, buf, pos),
    };

    if stream.skip_data.get() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "skipping http2 DATA frame");
        return state_skip_padded(h2c, buf, pos);
    }

    let r = stream.request.borrow().clone();
    let r = match r {
        Some(r) => r,
        None => return state_skip_padded(h2c, buf, pos),
    };

    if r.reading_body.get() && !r.request_body_no_buffering.get() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "skipping http2 DATA frame");
        return state_skip_padded(h2c, buf, pos);
    }

    {
        let hin = r.headers_in.borrow();
        if hin.content_length_n < 0 && !hin.chunked {
            drop(hin);
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "skipping http2 DATA frame");
            return state_skip_padded(h2c, buf, pos);
        }
    }

    let mut size = end - pos;

    if size >= st.length.get() {
        size = st.length.get();
        stream.in_closed.set(st.flags.get() & NGX_HTTP_V2_END_STREAM_FLAG != 0);
    }

    h2c.payload_bytes.set(h2c.payload_bytes.get() + size as i64);

    if r.request_body.borrow().is_some() {
        super::request_body::process_request_body(&stream, &r, &buf[pos..pos + size], stream.in_closed.get());
    } else if size > 0 {
        let preread_size = super::stream::srv_conf(&r).preread_size;
        let mut preread = stream.preread.borrow_mut();
        let b = preread.get_or_insert_with(|| Vec::with_capacity(preread_size));

        if size > preread_size - b.len() {
            drop(preread);
            ngx_log_error!(NGX_LOG_ALERT, h2c.connection.log, None, "http2 preread buffer overflow");
            return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
        }

        b.extend_from_slice(&buf[pos..pos + size]);
    }

    pos += size;
    st.length.set(st.length.get() - size);

    if st.length.get() > 0 {
        return state_save(h2c, buf, pos, state_read_data);
    }

    if st.padding.get() > 0 {
        return state_skip_padded(h2c, buf, pos);
    }

    state_complete(h2c, buf, pos)
}

fn state_headers(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    let padded = st.flags.get() & NGX_HTTP_V2_PADDED_FLAG != 0;
    let priority = st.flags.get() & NGX_HTTP_V2_PRIORITY_FLAG != 0;

    let mut size = 0;

    if padded {
        size += 1;
    }

    if priority {
        size += 4 + 1;
    }

    if st.length.get() < size {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent HEADERS frame with incorrect length {}", st.length.get());
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if st.length.get() == size {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent HEADERS frame with empty header block");
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if h2c.goaway.get() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "skipping http2 HEADERS frame");
        return state_skip(h2c, buf, pos);
    }

    if end - pos < size {
        return state_save(h2c, buf, pos, state_headers);
    }

    st.length.set(st.length.get() - size);

    if padded {
        st.padding.set(buf[pos] as usize);
        pos += 1;

        if st.padding.get() > st.length.get() {
            ngx_log_error!(
                NGX_LOG_INFO,
                log,
                None,
                "client sent padded HEADERS frame with incorrect length: {}, padding: {}",
                st.length.get(),
                st.padding.get()
            );
            return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
        }

        st.length.set(st.length.get() - st.padding.get());
    }

    let mut depend = 0u32;
    let mut excl = false;
    let mut weight = NGX_HTTP_V2_DEFAULT_WEIGHT;

    if priority {
        let dependency = parse_uint32(&buf[pos..]);

        depend = dependency & 0x7fffffff;
        excl = dependency >> 31 != 0;
        weight = buf[pos + 4] as usize + 1;

        pos += 4 + 1;
    }

    ngx_log_debug!(
        NGX_LOG_DEBUG_HTTP,
        log,
        "http2 HEADERS frame sid:{} depends on {} excl:{} weight:{}",
        st.sid.get(),
        depend,
        excl as u32,
        weight
    );

    if st.sid.get() % 2 == 0 || st.sid.get() <= h2c.last_sid.get() {
        ngx_log_error!(
            NGX_LOG_INFO,
            log,
            None,
            "client sent HEADERS frame with incorrect identifier {}, the last was {}",
            st.sid.get(),
            h2c.last_sid.get()
        );
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if depend == st.sid.get() {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent HEADERS frame for stream {} with incorrect dependency", st.sid.get());
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    h2c.last_sid.set(st.sid.get());

    let (lchb_size, lchb_num) = {
        let cscf = crate::core::srv_conf_from_ctx(&h2c.http_connection.conf_ctx.borrow());
        let c = cscf.borrow();
        (c.large_client_header_buffers.size, c.large_client_header_buffers.num)
    };
    st.header_limit.set(lchb_size * lchb_num);

    let h2scf = super::stream::h2c_srv_conf(h2c);

    let status;

    'rst: {
        if h2c.processing.get() >= h2scf.concurrent_streams {
            ngx_log_error!(NGX_LOG_INFO, log, None, "concurrent streams exceeded {}", h2c.processing.get());
            status = NGX_HTTP_V2_REFUSED_STREAM;
            break 'rst;
        }

        let new_streams = h2c.new_streams.get();
        h2c.new_streams.set(new_streams + 1);
        if new_streams >= 2 * h2scf.concurrent_streams {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent too many streams at once");
            status = NGX_HTTP_V2_REFUSED_STREAM;
            break 'rst;
        }

        if !h2c.settings_ack.get()
            && st.flags.get() & NGX_HTTP_V2_END_STREAM_FLAG == 0
            && h2scf.preread_size < NGX_HTTP_V2_DEFAULT_WINDOW
        {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent stream with data before settings were acknowledged");
            status = NGX_HTTP_V2_REFUSED_STREAM;
            break 'rst;
        }

        let node = get_node_by_id(h2c, st.sid.get(), true).expect("allocated node");

        if !node.parent.borrow().is_none() {
            super::stream::closed_remove(h2c, &node);
            h2c.closed_nodes.set(h2c.closed_nodes.get() - 1);
        }

        let stream = create_stream(h2c, &node);

        *st.stream.borrow_mut() = Some(stream.clone());

        if let Some(r) = stream.request.borrow().as_ref() {
            r.request_length.set(st.length.get() as i64);
        }

        stream.in_closed.set(st.flags.get() & NGX_HTTP_V2_END_STREAM_FLAG != 0);

        *node.stream.borrow_mut() = Some(stream.clone());

        if priority || node.parent.borrow().is_none() {
            node.weight.set(weight);
            set_dependency(h2c, &node, depend, excl);
        }

        let (keepalive_timeout, keepalive_requests, keepalive_time) = {
            let clcf = crate::core::loc_conf_from_ctx(&h2c.http_connection.conf_ctx.borrow());
            let c = clcf.borrow();
            (*c.keepalive_timeout, *c.keepalive_requests, *c.keepalive_time)
        };
        let _: &CoreLocConf;

        if keepalive_timeout == 0
            || h2c.connection.requests.get() >= keepalive_requests as u64
            || super::connection::connection_age_msec(h2c) > keepalive_time
        {
            h2c.goaway.set(true);

            if send_goaway(h2c, NGX_HTTP_V2_NO_ERROR).is_err() {
                return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
            }
        }

        return state_header_block(h2c, buf, pos);
    }

    let refused = h2c.refused_streams.get();
    h2c.refused_streams.set(refused + 1);
    if refused > h2scf.concurrent_streams.max(100) {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent too many refused streams");
        return connection_error(h2c, NGX_HTTP_V2_NO_ERROR);
    }

    if send_rst_stream(h2c, st.sid.get(), status).is_err() {
        return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    state_header_block(h2c, buf, pos)
}

fn state_header_block(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    if end - pos < 1 {
        return state_headers_save(h2c, buf, pos, state_header_block);
    }

    if st.flags.get() & NGX_HTTP_V2_END_HEADERS_FLAG == 0 && st.length.get() < NGX_HTTP_V2_INT_OCTETS {
        return handle_continuation(h2c, buf, pos, state_header_block);
    }

    let mut size_update = false;
    let mut indexed = false;

    let ch = buf[pos];

    let prefix = if ch >= (1 << 7) {
        // indexed header field
        indexed = true;
        encode::prefix(7)
    } else if ch >= (1 << 6) {
        // literal header field with incremental indexing
        st.index.set(true);
        encode::prefix(6)
    } else if ch >= (1 << 5) {
        // dynamic table size update
        size_update = true;
        encode::prefix(5)
    } else {
        // literal header field never indexed / without indexing
        encode::prefix(4)
    };

    let value = match parse_int(h2c, buf, &mut pos, prefix) {
        Ok(v) => v,
        Err(ParseInt::Again) => return state_headers_save(h2c, buf, pos, state_header_block),
        Err(ParseInt::Declined) => {
            ngx_log_error!(
                NGX_LOG_INFO,
                log,
                None,
                "client sent header block with too long {} value",
                if size_update { "size update" } else { "header index" }
            );
            return connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
        }
        Err(ParseInt::Error) => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent header block with incorrect length");
            return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
        }
    };

    if indexed {
        if get_indexed_header(h2c, value, false).is_err() {
            return connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
        }

        return state_process_header(h2c, buf, pos);
    }

    if size_update {
        if h2c.hpack.borrow_mut().table_size(value, log).is_err() {
            return connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
        }

        return state_header_complete(h2c, buf, pos);
    }

    if value == 0 {
        st.parse_name.set(true);
    } else if get_indexed_header(h2c, value, true).is_err() {
        return connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
    }

    st.parse_value.set(true);

    state_field_len(h2c, buf, pos)
}

/// ngx_http_v2_get_indexed_header into state.header.
fn get_indexed_header(h2c: &Rc<H2Connection>, index: usize, name_only: bool) -> Result<(), ()> {
    let st = &h2c.state;

    st.keep_field(name_only);

    let hpack = h2c.hpack.borrow();
    let mut name = st.header_name.borrow_mut();
    let mut value = st.header_value.borrow_mut();

    hpack.get_indexed_header_into(index, name_only, &h2c.connection.log, &mut name, &mut value)
}

fn state_field_len(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    if st.flags.get() & NGX_HTTP_V2_END_HEADERS_FLAG == 0 && st.length.get() < NGX_HTTP_V2_INT_OCTETS {
        return handle_continuation(h2c, buf, pos, state_field_len);
    }

    if st.length.get() < 1 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent header block with incorrect length");
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if end - pos < 1 {
        return state_headers_save(h2c, buf, pos, state_field_len);
    }

    let huff = buf[pos] >> 7 != 0;

    let len = match parse_int(h2c, buf, &mut pos, encode::prefix(7)) {
        Ok(v) => v,
        Err(ParseInt::Again) => return state_headers_save(h2c, buf, pos, state_field_len),
        Err(ParseInt::Declined) => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent header field with too long length value");
            return connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
        }
        Err(ParseInt::Error) => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent header block with incorrect length");
            return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 {} string, len:{}", if huff { "encoded" } else { "raw" }, len);

    let lchb_size = {
        let cscf = crate::core::srv_conf_from_ctx(&h2c.http_connection.conf_ctx.borrow());
        let size = cscf.borrow().large_client_header_buffers.size;
        size
    };

    if len > lchb_size {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent too large header field");
        return connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    st.field_rest.set(len);

    if st.stream.borrow().is_none() && !st.index.get() {
        return state_field_skip(h2c, buf, pos);
    }

    st.new_field(if huff { len * 8 / 5 } else { len } + 1);

    if huff {
        return state_field_huff(h2c, buf, pos);
    }

    state_field_raw(h2c, buf, pos)
}

fn state_field_huff(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    let size = (end - pos).min(st.field_rest.get()).min(st.length.get());

    st.length.set(st.length.get() - size);
    st.field_rest.set(st.field_rest.get() - size);

    let mut fs = st.field_state.get();
    let rc = crate::huff_decode::huff_decode(&mut fs, &buf[pos..pos + size], &mut st.field.borrow_mut(), st.field_rest.get() == 0, log);
    st.field_state.set(fs);

    if rc.is_err() {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent invalid encoded header field");
        return connection_error(h2c, NGX_HTTP_V2_COMP_ERROR);
    }

    pos += size;

    if st.field_rest.get() == 0 {
        return state_process_header(h2c, buf, pos);
    }

    if st.length.get() > 0 {
        return state_headers_save(h2c, buf, pos, state_field_huff);
    }

    if st.flags.get() & NGX_HTTP_V2_END_HEADERS_FLAG != 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent header field with incorrect length");
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    handle_continuation(h2c, buf, pos, state_field_huff)
}

fn state_field_raw(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    let size = (end - pos).min(st.field_rest.get()).min(st.length.get());

    st.length.set(st.length.get() - size);
    st.field_rest.set(st.field_rest.get() - size);

    st.field.borrow_mut().extend_from_slice(&buf[pos..pos + size]);

    pos += size;

    if st.field_rest.get() == 0 {
        return state_process_header(h2c, buf, pos);
    }

    if st.length.get() > 0 {
        return state_headers_save(h2c, buf, pos, state_field_raw);
    }

    if st.flags.get() & NGX_HTTP_V2_END_HEADERS_FLAG != 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent header field with incorrect length");
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    handle_continuation(h2c, buf, pos, state_field_raw)
}

fn state_field_skip(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;

    let size = (end - pos).min(st.field_rest.get()).min(st.length.get());

    st.length.set(st.length.get() - size);
    st.field_rest.set(st.field_rest.get() - size);

    pos += size;

    if st.field_rest.get() == 0 {
        return state_process_header(h2c, buf, pos);
    }

    if st.length.get() > 0 {
        return state_save(h2c, buf, pos, state_field_skip);
    }

    if st.flags.get() & NGX_HTTP_V2_END_HEADERS_FLAG != 0 {
        ngx_log_error!(NGX_LOG_INFO, h2c.connection.log, None, "client sent header field with incorrect length");
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    handle_continuation(h2c, buf, pos, state_field_skip)
}

fn state_process_header(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let st = &h2c.state;
    let log = &h2c.connection.log;

    // field_start..field_end stays on the last field read: a skipped field
    // (a refused stream's literal that is not indexed) leaves it as it was
    if st.parse_name.get() {
        st.parse_name.set(false);

        st.take_field(false);

        if st.header_name.borrow().is_empty() {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent zero header name length");
            return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
        }

        return state_field_len(h2c, buf, pos);
    }

    if st.parse_value.get() {
        st.parse_value.set(false);

        st.take_field(true);
    }

    let len = st.header_name.borrow().len() + st.header_value.borrow().len();

    if len > st.header_limit.get() {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent too large header");
        return connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    st.header_limit.set(st.header_limit.get() - len);

    if st.index.get() {
        h2c.hpack.borrow_mut().add_header(&st.header_name.borrow(), &st.header_value.borrow(), log);
        st.index.set(false);
    }

    let stream = st.stream.borrow().clone();
    let stream = match stream {
        None => return state_header_complete(h2c, buf, pos),
        Some(s) => s,
    };

    // lent to the request side, then put back with their capacity
    let name = std::mem::take(&mut *st.header_name.borrow_mut());
    let value = std::mem::take(&mut *st.header_value.borrow_mut());

    let rc = header_request(h2c, &stream, &name, &value);

    *st.header_name.borrow_mut() = name;
    *st.header_value.borrow_mut() = value;

    match rc {
        Ok(()) => {}
        // the request was finalized (or failed): stop feeding it headers
        Err(Some(())) => {
            *st.stream.borrow_mut() = None;
        }
        Err(None) => return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR),
    }

    state_header_complete(h2c, buf, pos)
}

fn state_header_complete(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;

    if st.length.get() > 0 {
        if end - pos > 0 {
            st.handler.set(state_header_block);
            return Some(pos);
        }

        return state_headers_save(h2c, buf, pos, state_header_block);
    }

    if st.flags.get() & NGX_HTTP_V2_END_HEADERS_FLAG == 0 {
        return handle_continuation(h2c, buf, pos, state_header_complete);
    }

    let stream = st.stream.borrow().clone();

    if let Some(stream) = stream {
        run_request(h2c, &stream);
    }

    if st.padding.get() > 0 {
        return state_skip_padded(h2c, buf, pos);
    }

    state_complete(h2c, buf, pos)
}

/// ngx_http_v2_handle_continuation: splice the next CONTINUATION frame's
/// header (and the preceding frame's padding) out of the buffer so the
/// header block stays contiguous.
fn handle_continuation(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize, handler: Handler) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    let len = st.length.get();

    if st.padding.get() > 0 && end - pos > len {
        let skip = st.padding.get().min((end - pos) - len);

        st.padding.set(st.padding.get() - skip);

        buf.copy_within(pos..pos + len, pos + skip);
        pos += skip;
    }

    if end - pos < len + NGX_HTTP_V2_FRAME_HEADER_SIZE {
        return state_headers_save(h2c, buf, pos, handler);
    }

    let p = pos + len;

    let head = parse_uint32(&buf[p..]);

    if parse_type(head) != NGX_HTTP_V2_CONTINUATION_FRAME {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent inappropriate frame while CONTINUATION was expected");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    st.flags.set(st.flags.get() | buf[p + 4]);

    if st.sid.get() != parse_sid(&buf[p + 5..]) {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent CONTINUATION frame with incorrect identifier");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    buf.copy_within(pos..pos + len, pos + NGX_HTTP_V2_FRAME_HEADER_SIZE);
    pos += NGX_HTTP_V2_FRAME_HEADER_SIZE;

    let len = parse_length(head);

    st.length.set(st.length.get() + len);

    if let Some(stream) = st.stream.borrow().as_ref() {
        if let Some(r) = stream.request.borrow().as_ref() {
            r.request_length.set(r.request_length.get() + len as i64);
        }
    }

    st.handler.set(handler);
    Some(pos)
}

fn state_priority(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    if st.length.get() != NGX_HTTP_V2_PRIORITY_SIZE {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent PRIORITY frame with incorrect length {}", st.length.get());
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    h2c.priority_limit.set(h2c.priority_limit.get().saturating_sub(1));
    if h2c.priority_limit.get() == 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent too many PRIORITY frames");
        return connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
    }

    if end - pos < NGX_HTTP_V2_PRIORITY_SIZE {
        return state_save(h2c, buf, pos, state_priority);
    }

    let dependency = parse_uint32(&buf[pos..]);

    let depend = dependency & 0x7fffffff;
    let excl = dependency >> 31 != 0;
    let weight = buf[pos + 4] as usize + 1;

    pos += NGX_HTTP_V2_PRIORITY_SIZE;

    ngx_log_debug!(
        NGX_LOG_DEBUG_HTTP,
        log,
        "http2 PRIORITY frame sid:{} depends on {} excl:{} weight:{}",
        st.sid.get(),
        depend,
        excl as u32,
        weight
    );

    if st.sid.get() == 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent PRIORITY frame with incorrect identifier");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if depend == st.sid.get() {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent PRIORITY frame for stream {} with incorrect dependency", st.sid.get());
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    let node = get_node_by_id(h2c, st.sid.get(), true).expect("allocated node");

    node.weight.set(weight);

    if node.stream.borrow().is_none() {
        if node.parent.borrow().is_none() {
            h2c.closed_nodes.set(h2c.closed_nodes.get() + 1);
        } else {
            super::stream::closed_remove(h2c, &node);
        }

        h2c.closed.borrow_mut().push_back(node.clone());
    }

    set_dependency(h2c, &node, depend, excl);

    state_complete(h2c, buf, pos)
}

fn state_rst_stream(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    if st.length.get() != NGX_HTTP_V2_RST_STREAM_SIZE {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent RST_STREAM frame with incorrect length {}", st.length.get());
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if end - pos < NGX_HTTP_V2_RST_STREAM_SIZE {
        return state_save(h2c, buf, pos, state_rst_stream);
    }

    let status = parse_uint32(&buf[pos..]);

    pos += NGX_HTTP_V2_RST_STREAM_SIZE;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 RST_STREAM frame, sid:{} status:{}", st.sid.get(), status);

    if st.sid.get() == 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent RST_STREAM frame with incorrect identifier");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    let stream = match get_node_by_id(h2c, st.sid.get(), false).and_then(|n| n.stream.borrow().clone()) {
        Some(s) => s,
        None => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "unknown http2 stream");
            return state_complete(h2c, buf, pos);
        }
    };

    stream.in_closed.set(true);
    stream.out_closed.set(true);

    let fc = stream.fc.clone();
    fc.error.set(true);

    match status {
        NGX_HTTP_V2_CANCEL => {
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client canceled stream {}", st.sid.get());
        }
        NGX_HTTP_V2_INTERNAL_ERROR => {
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client terminated stream {} due to internal error", st.sid.get());
        }
        _ => {
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client terminated stream {} with status {}", st.sid.get(), status);
        }
    }

    // ev = fc->read; ev->handler(ev);
    stream_rst_received(h2c, &stream);

    state_complete(h2c, buf, pos)
}

fn state_settings(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let st = &h2c.state;
    let log = &h2c.connection.log;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 SETTINGS frame");

    if st.sid.get() != 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent SETTINGS frame with incorrect identifier");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if st.flags.get() == NGX_HTTP_V2_ACK_FLAG {
        if st.length.get() != 0 {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent SETTINGS frame with the ACK flag and nonzero length");
            return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
        }

        h2c.settings_ack.set(true);

        return state_complete(h2c, buf, pos);
    }

    if st.length.get() % NGX_HTTP_V2_SETTINGS_PARAM_SIZE != 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent SETTINGS frame with incorrect length {}", st.length.get());
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    st.window_delta.set(0);

    state_settings_params(h2c, buf, pos)
}

fn state_settings_params(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    while st.length.get() > 0 {
        if end - pos < NGX_HTTP_V2_SETTINGS_PARAM_SIZE {
            return state_save(h2c, buf, pos, state_settings_params);
        }

        st.length.set(st.length.get() - NGX_HTTP_V2_SETTINGS_PARAM_SIZE);

        let id = parse_uint16(&buf[pos..]);
        let value = parse_uint32(&buf[pos + 2..]) as usize;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 setting {}:{}", id, value);

        match id {
            NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING => {
                if value > NGX_HTTP_V2_MAX_WINDOW {
                    ngx_log_error!(NGX_LOG_INFO, log, None, "client sent SETTINGS frame with incorrect INITIAL_WINDOW_SIZE value {}", value);
                    return connection_error(h2c, NGX_HTTP_V2_FLOW_CTRL_ERROR);
                }

                st.window_delta.set(value as isize - h2c.init_window.get() as isize);
            }

            NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING => {
                if value > NGX_HTTP_V2_MAX_FRAME_SIZE || value < NGX_HTTP_V2_DEFAULT_FRAME_SIZE {
                    ngx_log_error!(NGX_LOG_INFO, log, None, "client sent SETTINGS frame with incorrect MAX_FRAME_SIZE value {}", value);
                    return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
                }

                h2c.frame_size.set(value);
            }

            NGX_HTTP_V2_ENABLE_PUSH_SETTING => {
                if value > 1 {
                    ngx_log_error!(NGX_LOG_INFO, log, None, "client sent SETTINGS frame with incorrect ENABLE_PUSH value {}", value);
                    return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
                }
            }

            NGX_HTTP_V2_HEADER_TABLE_SIZE_SETTING => {
                h2c.table_update.set(true);
            }

            _ => {}
        }

        pos += NGX_HTTP_V2_SETTINGS_PARAM_SIZE;
    }

    let frame = match get_frame(h2c, NGX_HTTP_V2_SETTINGS_ACK_SIZE, NGX_HTTP_V2_SETTINGS_FRAME, NGX_HTTP_V2_ACK_FLAG, 0) {
        Some(f) => f,
        None => return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR),
    };

    h2c.queue_ordered_frame(frame);

    if st.window_delta.get() != 0 {
        h2c.init_window.set((h2c.init_window.get() as isize + st.window_delta.get()) as usize);

        if adjust_windows(h2c, st.window_delta.get()).is_err() {
            return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
        }

        st.window_delta.set(0);
    }

    state_complete(h2c, buf, pos)
}

fn state_push_promise(h2c: &Rc<H2Connection>, _buf: &mut [u8], _pos: usize) -> Option<usize> {
    ngx_log_error!(NGX_LOG_INFO, h2c.connection.log, None, "client sent PUSH_PROMISE frame");
    connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR)
}

fn state_ping(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    if st.length.get() != NGX_HTTP_V2_PING_SIZE {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent PING frame with incorrect length {}", st.length.get());
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if end - pos < NGX_HTTP_V2_PING_SIZE {
        return state_save(h2c, buf, pos, state_ping);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 PING frame");

    if st.sid.get() != 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent PING frame with incorrect identifier");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if st.flags.get() & NGX_HTTP_V2_ACK_FLAG != 0 {
        return state_skip(h2c, buf, pos);
    }

    let mut frame = match get_frame(h2c, NGX_HTTP_V2_PING_SIZE, NGX_HTTP_V2_PING_FRAME, NGX_HTTP_V2_ACK_FLAG, 0) {
        Some(f) => f,
        None => return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR),
    };

    frame.data.extend_from_slice(&buf[pos..pos + NGX_HTTP_V2_PING_SIZE]);

    h2c.queue_blocked_frame(frame);

    state_complete(h2c, buf, pos + NGX_HTTP_V2_PING_SIZE)
}

fn state_goaway(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    if st.length.get() < NGX_HTTP_V2_GOAWAY_SIZE {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent GOAWAY frame with incorrect length {}", st.length.get());
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if end - pos < NGX_HTTP_V2_GOAWAY_SIZE {
        return state_save(h2c, buf, pos, state_goaway);
    }

    if st.sid.get() != 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent GOAWAY frame with incorrect identifier");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    // C consumes the fixed part only in debug builds, for the log line; the
    // skip below covers it either way.
    if log.debug_enabled(NGX_LOG_DEBUG_HTTP) {
        st.length.set(st.length.get() - NGX_HTTP_V2_GOAWAY_SIZE);

        let last_sid = parse_sid(&buf[pos..]);
        let error = parse_uint32(&buf[pos + 4..]);

        pos += NGX_HTTP_V2_GOAWAY_SIZE;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 GOAWAY frame: last sid {}, error {}", last_sid, error);
    }

    state_skip(h2c, buf, pos)
}

fn state_window_update(h2c: &Rc<H2Connection>, buf: &mut [u8], mut pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;
    let log = &h2c.connection.log;

    if st.length.get() != NGX_HTTP_V2_WINDOW_UPDATE_SIZE {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent WINDOW_UPDATE frame with incorrect length {}", st.length.get());
        return connection_error(h2c, NGX_HTTP_V2_SIZE_ERROR);
    }

    if end - pos < NGX_HTTP_V2_WINDOW_UPDATE_SIZE {
        return state_save(h2c, buf, pos, state_window_update);
    }

    let window = parse_window(&buf[pos..]) as usize;

    pos += NGX_HTTP_V2_WINDOW_UPDATE_SIZE;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 WINDOW_UPDATE frame sid:{} window:{}", st.sid.get(), window);

    if window == 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent WINDOW_UPDATE frame with incorrect window increment 0");
        return connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
    }

    if st.sid.get() != 0 {
        let stream = match get_node_by_id(h2c, st.sid.get(), false).and_then(|n| n.stream.borrow().clone()) {
            Some(s) => s,
            None => {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "unknown http2 stream");
                return state_complete(h2c, buf, pos);
            }
        };

        if window as isize > NGX_HTTP_V2_MAX_WINDOW as isize - stream.send_window.get() {
            ngx_log_error!(
                NGX_LOG_INFO,
                log,
                None,
                "client violated flow control for stream {}: received WINDOW_UPDATE frame with window increment {} not allowed for window {}",
                st.sid.get(),
                window,
                stream.send_window.get()
            );

            if terminate_stream(h2c, &stream, NGX_HTTP_V2_FLOW_CTRL_ERROR).is_err() {
                return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
            }

            return state_complete(h2c, buf, pos);
        }

        stream.send_window.set(stream.send_window.get() + window as isize);

        if stream.exhausted.get() {
            stream.exhausted.set(false);
            post_write(h2c, &stream);
        }

        return state_complete(h2c, buf, pos);
    }

    if window > NGX_HTTP_V2_MAX_WINDOW - h2c.send_window.get() {
        ngx_log_error!(
            NGX_LOG_INFO,
            log,
            None,
            "client violated connection flow control: received WINDOW_UPDATE frame with window increment {} not allowed for window {}",
            window,
            h2c.send_window.get()
        );
        return connection_error(h2c, NGX_HTTP_V2_FLOW_CTRL_ERROR);
    }

    h2c.send_window.set(h2c.send_window.get() + window);

    post_drain_waiting(h2c);

    state_complete(h2c, buf, pos)
}

fn state_continuation(h2c: &Rc<H2Connection>, _buf: &mut [u8], _pos: usize) -> Option<usize> {
    ngx_log_error!(NGX_LOG_INFO, h2c.connection.log, None, "client sent unexpected CONTINUATION frame");
    connection_error(h2c, NGX_HTTP_V2_PROTOCOL_ERROR)
}

pub fn state_complete(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let end = buf.len();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 frame complete pos:{} end:{}", pos, end);

    if pos > end {
        ngx_log_error!(NGX_LOG_ALERT, h2c.connection.log, None, "receive buffer overrun");
        return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    *h2c.state.stream.borrow_mut() = None;
    h2c.state.handler.set(state_head);

    Some(pos)
}

fn state_skip_padded(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let st = &h2c.state;
    st.length.set(st.length.get() + st.padding.get());
    st.padding.set(0);

    state_skip(h2c, buf, pos)
}

fn state_skip(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;

    let size = end - pos;

    if size < st.length.get() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 frame skip {} of {}", size, st.length.get());

        st.length.set(st.length.get() - size);
        return state_save(h2c, buf, end, state_skip);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 frame skip {}", st.length.get());

    let length = st.length.get();
    state_complete(h2c, buf, pos + length)
}

fn state_save(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize, handler: Handler) -> Option<usize> {
    let end = buf.len();
    let st = &h2c.state;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 frame state save pos:{} end:{}", pos, end);

    let size = end - pos;

    if size > NGX_HTTP_V2_STATE_BUFFER_SIZE {
        ngx_log_error!(NGX_LOG_ALERT, h2c.connection.log, None, "state buffer overflow: {} bytes required", size);
        return connection_error(h2c, NGX_HTTP_V2_INTERNAL_ERROR);
    }

    st.buffer.borrow_mut()[..size].copy_from_slice(&buf[pos..end]);

    st.buffer_used.set(size);
    st.handler.set(handler);
    st.incomplete.set(true);

    Some(end)
}

fn state_headers_save(h2c: &Rc<H2Connection>, buf: &mut [u8], pos: usize, handler: Handler) -> Option<usize> {
    if let Some(stream) = h2c.state.stream.borrow().as_ref() {
        super::stream::arm_header_timer(stream);
    }

    state_save(h2c, buf, pos, handler)
}

pub enum ParseInt {
    /// NGX_ERROR: the integer runs past the frame.
    Error,
    /// NGX_DECLINED: longer than NGX_HTTP_V2_INT_OCTETS.
    Declined,
    /// NGX_AGAIN: more input needed.
    Again,
}

/// ngx_http_v2_parse_int
fn parse_int(h2c: &Rc<H2Connection>, buf: &[u8], pos: &mut usize, prefix: usize) -> Result<usize, ParseInt> {
    let st = &h2c.state;
    let start = *pos;
    let mut end = buf.len();
    let mut p = start;

    let mut value = buf[p] as usize & prefix;
    p += 1;

    if value != prefix {
        if st.length.get() == 0 {
            return Err(ParseInt::Error);
        }

        st.length.set(st.length.get() - 1);

        *pos = p;
        return Ok(value);
    }

    if end - start > NGX_HTTP_V2_INT_OCTETS {
        end = start + NGX_HTTP_V2_INT_OCTETS;
    }

    let mut shift = 0;
    while p != end {
        let octet = buf[p] as usize;
        p += 1;

        value += (octet & 0x7f) << shift;

        if octet < 128 {
            if p - start > st.length.get() {
                return Err(ParseInt::Error);
            }

            st.length.set(st.length.get() - (p - start));

            *pos = p;
            return Ok(value);
        }

        shift += 7;
    }

    if end - start >= st.length.get() {
        return Err(ParseInt::Error);
    }

    if end == start + NGX_HTTP_V2_INT_OCTETS {
        return Err(ParseInt::Declined);
    }

    Err(ParseInt::Again)
}
