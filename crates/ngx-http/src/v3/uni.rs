//! ngx_http_v3_uni.c: the unidirectional streams: those of the client run
//! their read handler (the instructions parsed) in a task; those of the
//! server (control, encoder, decoder) carry what is sent on them.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use ngx_core::connection::Connection;
use ngx_core::log::*;
use ngx_core::quic::streams::{ngx_quic_cancelable_stream, ngx_quic_open_stream, ngx_quic_stream, wait_stream};
use ngx_core::rc::*;
use ngx_core::{ngx_log_debug, ngx_log_error};

use super::encode::*;
use super::module::srv_conf_of;
use super::parse::{parse_uni, PBuf, ParseUni};
use super::*;

/// ngx_http_v3_uni_stream_t
#[derive(Default)]
struct UniStream {
    parse: ParseUni,
    index: i64,
}

/// sc->send: the bytes taken, NGX_AGAIN or NGX_ERROR
pub fn stream_send(c: &Connection, buf: &[u8]) -> isize {
    match ngx_core::quic::streams::try_send(c, &[buf]) {
        Ok(n) => n as isize,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => NGX_AGAIN as isize,
        Err(_) => NGX_ERROR as isize,
    }
}

/// ngx_http_v3_init_uni_stream, then the read handler of the stream until
/// it is closed
pub async fn init_uni_stream(c: &Rc<Connection>) {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => {
            close_uni_stream(c, -1);
            return;
        }
    };

    if h3c.hq.get() {
        finalize_connection(c, NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR, Some("uni stream in hq mode"));
        close_uni_stream(c, -1);
        return;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 init uni stream");

    let n = ngx_quic_stream(c).map(|qs| qs.id >> 2).unwrap_or(0);

    if n >= NGX_HTTP_V3_MAX_UNI_STREAMS {
        finalize_connection(c, NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR, Some("reached maximum number of uni streams"));
        close_uni_stream(c, -1);
        return;
    }

    ngx_quic_cancelable_stream(c);

    let us = Rc::new(RefCell::new(UniStream { index: -1, ..Default::default() }));

    // c->read->handler = ngx_http_v3_uni_read_handler, run at once with
    // c->close set

    let hus = us.clone();

    *c.close_handler.borrow_mut() = Some(Rc::new(move |c: &Rc<Connection>| {
        uni_read_handler(c, &mut hus.borrow_mut());
    }));

    uni_read_events(c, &us).await;
}

/// The read handler of a stream of the client, called at once, then on
/// each read event, until the stream is closed.
async fn uni_read_events(c: &Rc<Connection>, us: &RefCell<UniStream>) {
    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return,
    };

    loop {
        if !uni_read_handler(c, &mut us.borrow_mut()) {
            return;
        }

        wait_stream(&qs, || qs.read_ready.get() || c.close.get()).await;

        // closed by the read handler run at once (ngx_quic_close_streams)
        if c.is_closed() {
            return;
        }
    }
}

/// ngx_http_v3_close_uni_stream
fn close_uni_stream(c: &Rc<Connection>, index: i64) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 close stream");

    if index >= 0 {
        if let Some(h3c) = get_session(c) {
            h3c.known_streams.borrow_mut()[index as usize] = None;
        }
    }

    c.destroyed.set(true);

    c.close();
}

/// ngx_http_v3_register_uni_stream
pub fn register_uni_stream(c: &Rc<Connection>, us_index: &mut i64, ty: u64) -> i64 {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    let index: i64 = match ty {
        NGX_HTTP_V3_STREAM_ENCODER => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 encoder stream");
            NGX_HTTP_V3_STREAM_CLIENT_ENCODER as i64
        }

        NGX_HTTP_V3_STREAM_DECODER => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 decoder stream");
            NGX_HTTP_V3_STREAM_CLIENT_DECODER as i64
        }

        NGX_HTTP_V3_STREAM_CONTROL => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 control stream");
            NGX_HTTP_V3_STREAM_CLIENT_CONTROL as i64
        }

        _ => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 stream 0x{:02x}", ty);

            let streams = (1 << NGX_HTTP_V3_STREAM_CLIENT_ENCODER) | (1 << NGX_HTTP_V3_STREAM_CLIENT_DECODER) | (1 << NGX_HTTP_V3_STREAM_CLIENT_CONTROL);

            if h3c.created_streams.get() & streams != streams {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "missing mandatory stream");
                return NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR as i64;
            }

            -1
        }
    };

    if index >= 0 {
        if h3c.created_streams.get() & (1 << index) != 0 {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "stream already created");
            return NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR as i64;
        }

        h3c.known_streams.borrow_mut()[index as usize] = Some(Rc::downgrade(c));
        h3c.created_streams.set(h3c.created_streams.get() | (1 << index));

        *us_index = index;
    }

    NGX_OK
}

/// ngx_http_v3_uni_read_handler: false once the stream is closed
fn uni_read_handler(c: &Rc<Connection>, us: &mut UniStream) -> bool {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 read handler");

    if c.close.get() {
        close_uni_stream(c, us.index);
        return false;
    }

    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return false,
    };

    let rc: i64 = 'failed: {
        let mut buf = [0u8; 128];

        while qs.read_ready.get() {
            let n = ngx_core::quic::streams::ngx_quic_stream_recv(c, &mut buf);

            if n == NGX_ERROR as isize {
                break 'failed NGX_HTTP_V3_ERR_INTERNAL_ERROR as i64;
            }

            if n == 0 {
                if us.index >= 0 {
                    break 'failed NGX_HTTP_V3_ERR_CLOSED_CRITICAL_STREAM as i64;
                }

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 read eof");
                close_uni_stream(c, us.index);
                return false;
            }

            if n == NGX_AGAIN as isize {
                break;
            }

            let mut b = PBuf::new(&buf[..n as usize]);

            if let Some(h3c) = get_session(c) {
                h3c.total_bytes.set(h3c.total_bytes.get() + n as i64);
            }

            if check_flood(c) != NGX_OK {
                close_uni_stream(c, us.index);
                return false;
            }

            let rc = parse_uni(c, &mut us.parse, &mut us.index, &mut b);

            if rc == NGX_DONE {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 read done");
                close_uni_stream(c, us.index);
                return false;
            }

            if rc > 0 {
                break 'failed rc;
            }

            if rc != NGX_AGAIN {
                break 'failed NGX_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR as i64;
            }
        }

        // ngx_handle_read_event(): nothing to do for a stream

        return true;
    };

    // failed:

    finalize_connection(c, rc as u64, Some("stream error"));
    close_uni_stream(c, us.index);

    false
}

/// ngx_http_v3_uni_dummy_read_handler: false once the stream is closed
fn uni_dummy_read_handler(c: &Rc<Connection>, index: i64) -> bool {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 dummy read handler");

    if c.close.get() {
        close_uni_stream(c, index);
        return false;
    }

    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return false,
    };

    if qs.read_ready.get() {
        let mut ch = [0u8; 1];

        if ngx_core::quic::streams::ngx_quic_stream_recv(c, &mut ch) != 0 {
            finalize_connection(c, NGX_HTTP_V3_ERR_NO_ERROR, None);
            close_uni_stream(c, index);
            return false;
        }
    }

    true
}

/// The task of a stream of the server: there is nothing to read, the
/// stream ends with the connection.
async fn uni_dummy_task(c: Rc<Connection>, index: i64) {
    let qs = match ngx_quic_stream(&c) {
        Some(qs) => qs,
        None => return,
    };

    loop {
        if !uni_dummy_read_handler(&c, index) {
            return;
        }

        wait_stream(&qs, || qs.read_ready.get() || c.close.get() || c.is_closed()).await;

        // closed meanwhile, as by the read handler run at once
        // (ngx_quic_close_streams)
        if c.is_closed() {
            return;
        }
    }
}

/// ngx_http_v3_get_uni_stream
pub fn get_uni_stream(c: &Rc<Connection>, ty: u64) -> Option<Rc<Connection>> {
    let index: i64 = match ty {
        NGX_HTTP_V3_STREAM_ENCODER => NGX_HTTP_V3_STREAM_SERVER_ENCODER as i64,
        NGX_HTTP_V3_STREAM_DECODER => NGX_HTTP_V3_STREAM_SERVER_DECODER as i64,
        NGX_HTTP_V3_STREAM_CONTROL => NGX_HTTP_V3_STREAM_SERVER_CONTROL as i64,
        _ => -1,
    };

    let h3c = get_session(c)?;

    if index >= 0 {
        if let Some(sc) = h3c.known_stream(index as usize) {
            return Some(sc);
        }
    }

    let sc = 'failed: {
        let sc = match ngx_quic_open_stream(c, false) {
            Some(sc) => sc,
            None => break 'failed None,
        };

        ngx_quic_cancelable_stream(&sc);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 create uni stream, type:{}", ty);

        if index >= 0 {
            h3c.known_streams.borrow_mut()[index as usize] = Some(Rc::downgrade(&sc));
        }

        let mut buf = Vec::with_capacity(NGX_HTTP_V3_VARLEN_INT_LEN);
        encode_varlen_int(&mut buf, ty);

        h3c.total_bytes.set(h3c.total_bytes.get() + buf.len() as i64);

        if stream_send(&sc, &buf) != buf.len() as isize {
            break 'failed Some(sc);
        }

        // sc->read->handler = ngx_http_v3_uni_dummy_read_handler, run at
        // once with sc->close set

        *sc.close_handler.borrow_mut() = Some(Rc::new(move |sc: &Rc<Connection>| {
            uni_dummy_read_handler(sc, index);
        }));

        // ngx_post_event(sc->read, &ngx_posted_events): the dummy read
        // handler runs in its task

        let sc2 = sc.clone();

        ngx_core::event::spawn(async move {
            uni_dummy_task(sc2, index).await;
        });

        return Some(sc);
    };

    // failed:

    ngx_log_error!(NGX_LOG_ERR, c.log, None, "failed to create server stream");

    finalize_connection(c, NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR, Some("failed to create server stream"));

    if let Some(sc) = sc {
        close_uni_stream(&sc, index);
    }

    None
}

/// The index of a known stream, for close_uni_stream().
fn known_index(h3c: &H3Session, sc: &Connection) -> i64 {
    let known = h3c.known_streams.borrow();

    for (i, w) in known.iter().enumerate() {
        if w.as_ref().and_then(|w| w.upgrade()).is_some_and(|k| std::ptr::eq(Rc::as_ptr(&k), sc)) {
            return i as i64;
        }
    }

    -1
}

/// Send on a stream of the server; the failure is logged as `what`
/// (the failed: part of the send functions).
fn uni_send(c: &Rc<Connection>, sc: &Rc<Connection>, buf: &[u8], what: &'static str, reason: &'static str) -> i64 {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    h3c.total_bytes.set(h3c.total_bytes.get() + buf.len() as i64);

    if stream_send(sc, buf) == buf.len() as isize {
        return NGX_OK;
    }

    ngx_log_error!(NGX_LOG_ERR, c.log, None, "{}", what);

    finalize_connection(c, NGX_HTTP_V3_ERR_EXCESSIVE_LOAD, Some(reason));

    let index = known_index(&h3c, sc);
    close_uni_stream(sc, index);

    NGX_ERROR
}

/// ngx_http_v3_send_settings
pub fn send_settings(c: &Rc<Connection>) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 send settings");

    let cc = match get_uni_stream(c, NGX_HTTP_V3_STREAM_CONTROL) {
        Some(cc) => cc,
        None => return NGX_ERROR,
    };

    let h3scf = match quic_get_connection(c) {
        Some(hc) => srv_conf_of(&hc),
        None => return NGX_ERROR,
    };

    let mut n = varlen_int_len(NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY);
    n += varlen_int_len(h3scf.max_table_capacity as u64);
    n += varlen_int_len(NGX_HTTP_V3_PARAM_BLOCKED_STREAMS);
    n += varlen_int_len(h3scf.max_blocked_streams as u64);

    let mut buf = Vec::with_capacity(NGX_HTTP_V3_VARLEN_INT_LEN * 6);

    encode_varlen_int(&mut buf, NGX_HTTP_V3_FRAME_SETTINGS);
    encode_varlen_int(&mut buf, n as u64);
    encode_varlen_int(&mut buf, NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY);
    encode_varlen_int(&mut buf, h3scf.max_table_capacity as u64);
    encode_varlen_int(&mut buf, NGX_HTTP_V3_PARAM_BLOCKED_STREAMS);
    encode_varlen_int(&mut buf, h3scf.max_blocked_streams as u64);

    uni_send(c, &cc, &buf, "failed to send settings", "failed to send settings")
}

/// ngx_http_v3_send_goaway
pub fn send_goaway(c: &Rc<Connection>, id: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 send goaway {}", id);

    let cc = match get_uni_stream(c, NGX_HTTP_V3_STREAM_CONTROL) {
        Some(cc) => cc,
        None => return NGX_ERROR,
    };

    let n = varlen_int_len(id);

    let mut buf = Vec::with_capacity(NGX_HTTP_V3_VARLEN_INT_LEN * 3);

    encode_varlen_int(&mut buf, NGX_HTTP_V3_FRAME_GOAWAY);
    encode_varlen_int(&mut buf, n as u64);
    encode_varlen_int(&mut buf, id);

    uni_send(c, &cc, &buf, "failed to send goaway", "failed to send goaway")
}

/// ngx_http_v3_send_ack_section
pub fn send_ack_section(c: &Rc<Connection>, stream_id: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 send section acknowledgement {}", stream_id);

    let dc = match get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER) {
        Some(dc) => dc,
        None => return NGX_ERROR,
    };

    let mut buf = Vec::with_capacity(NGX_HTTP_V3_PREFIX_INT_LEN);
    encode_prefix_int(&mut buf, 0x80, stream_id, 7);

    uni_send(c, &dc, &buf, "failed to send section acknowledgement", "failed to send section acknowledgement")
}

/// ngx_http_v3_send_cancel_stream
pub fn send_cancel_stream(c: &Rc<Connection>, stream_id: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 send stream cancellation {}", stream_id);

    let dc = match get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER) {
        Some(dc) => dc,
        None => return NGX_ERROR,
    };

    let mut buf = Vec::with_capacity(NGX_HTTP_V3_PREFIX_INT_LEN);
    encode_prefix_int(&mut buf, 0x40, stream_id, 6);

    uni_send(c, &dc, &buf, "failed to send stream cancellation", "failed to send stream cancellation")
}

/// ngx_http_v3_send_inc_insert_count
pub fn send_inc_insert_count(c: &Rc<Connection>, inc: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 send insert count increment {}", inc);

    let dc = match get_uni_stream(c, NGX_HTTP_V3_STREAM_DECODER) {
        Some(dc) => dc,
        None => return NGX_ERROR,
    };

    let mut buf = Vec::with_capacity(NGX_HTTP_V3_PREFIX_INT_LEN);
    encode_prefix_int(&mut buf, 0, inc, 6);

    uni_send(c, &dc, &buf, "failed to send insert count increment", "failed to send insert count increment")
}

/// ngx_http_v3_cancel_stream
pub fn cancel_stream(c: &Connection, stream_id: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 cancel stream {}", stream_id);

    /* we do not use dynamic tables */

    NGX_OK
}
