//! ngx_event_quic_streams.c: streams.
//!
//! A stream is a connection of its own (c->quic, Connection::quic_stream),
//! read and written through the stream's buffers: stream_recv() and
//! stream_send_chain() are C's sc->recv and sc->send_chain. The stream's
//! events (sc->read and sc->write) are posted events of the QUIC
//! connection; the application runs the stream in a task, which the
//! events wake (Connection::recv() and the send functions wait for them).
//! The first read event of a stream the client opened is
//! ngx_quic_init_stream_handler: it gives the stream to the listening's
//! handler, which starts the task.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::rc::{Rc, Weak};

use crate::connection::{Connection, PoolCleanup};
use crate::log::*;
use crate::rc::*;
use crate::ngx_log_debug;

use super::frames::*;
use super::transport::*;
use super::{ngx_quic_get_connection, ngx_quic_shutdown_quic, QEvent, QEventKind, QuicConnection, QuicStream, QuicStreamRecvState, QuicStreamSendState, NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_STREAM_SERVER_INITIATED, NGX_QUIC_STREAM_UNIDIRECTIONAL};

/// NGX_READ_SHUTDOWN, NGX_WRITE_SHUTDOWN, NGX_RDWR_SHUTDOWN
pub const NGX_READ_SHUTDOWN: i32 = libc::SHUT_RD;
pub const NGX_WRITE_SHUTDOWN: i32 = libc::SHUT_WR;
pub const NGX_RDWR_SHUTDOWN: i32 = libc::SHUT_RDWR;

/// The result of ngx_quic_get_stream()
enum GetStream {
    Stream(Rc<QuicStream>),
    /// NGX_QUIC_STREAM_GONE
    Gone,
    /// NULL
    Error,
}

/// c->quic
pub fn ngx_quic_stream(c: &Connection) -> Option<Rc<QuicStream>> {
    c.quic_stream.borrow().clone()
}

/// qs->parent and its QUIC connection
fn parent(qs: &QuicStream) -> Option<(Rc<Connection>, Rc<QuicConnection>)> {
    let pc = qs.parent.upgrade()?;
    let qc = ngx_quic_get_connection(&pc)?;

    Some((pc, qc))
}

/// ngx_quic_open_stream
pub fn ngx_quic_open_stream(c: &Rc<Connection>, bidi: bool) -> Option<Rc<Connection>> {
    let pc = match ngx_quic_stream(c) {
        Some(qs) => qs.parent.upgrade()?,
        None => c.clone(),
    };

    let qc = ngx_quic_get_connection(&pc)?;

    if qc.closing.get() {
        return None;
    }

    let streams = &qc.streams;

    let id = if bidi {
        if streams.server_streams_bidi.get() >= streams.server_max_streams_bidi.get() {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic too many server bidi streams:{}", streams.server_streams_bidi.get());
            return None;
        }

        let id = (streams.server_streams_bidi.get() << 2) | NGX_QUIC_STREAM_SERVER_INITIATED;

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic creating server bidi stream streams:{} max:{} id:0x{:x}", streams.server_streams_bidi.get(), streams.server_max_streams_bidi.get(), id);

        streams.server_streams_bidi.set(streams.server_streams_bidi.get() + 1);

        id
    } else {
        if streams.server_streams_uni.get() >= streams.server_max_streams_uni.get() {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic too many server uni streams:{}", streams.server_streams_uni.get());
            return None;
        }

        let id = (streams.server_streams_uni.get() << 2) | NGX_QUIC_STREAM_SERVER_INITIATED | NGX_QUIC_STREAM_UNIDIRECTIONAL;

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic creating server uni stream streams:{} max:{} id:0x{:x}", streams.server_streams_uni.get(), streams.server_max_streams_uni.get(), id);

        streams.server_streams_uni.set(streams.server_streams_uni.get() + 1);

        id
    };

    let qs = ngx_quic_create_stream(&pc, &qc, id)?;

    let sc = qs.connection.borrow().clone()?;

    qs.write_active.set(true);
    qs.write_ready.set(true);

    if bidi {
        qs.read_active.set(true);
    }

    Some(sc)
}

/// ngx_quic_find_stream
pub fn ngx_quic_find_stream(qc: &QuicConnection, id: u64) -> Option<Rc<QuicStream>> {
    qc.streams.tree.borrow().get(&id).cloned()
}

/// ngx_quic_close_streams: the streams are reset; those with a connection
/// are closed by its read handler with sc->close set, at once if it has a
/// close handler, or else in its task, woken
pub fn ngx_quic_close_streams(c: &Connection, qc: &QuicConnection) -> i64 {
    loop {
        let qs = qc.streams.uninitialized.borrow_mut().pop_front();

        let qs = match qs {
            Some(qs) => qs,
            None => break,
        };

        qs.init_handler.set(false);

        let sc = qs.connection.borrow().clone();

        if let Some(sc) = sc {
            sc.close();
        }
    }

    if qc.streams.tree.borrow().is_empty() {
        return NGX_OK;
    }

    let streams: Vec<Rc<QuicStream>> = qc.streams.tree.borrow().values().cloned().collect();

    let mut posted = Vec::new();

    for qs in streams {
        qs.recv_state.set(QuicStreamRecvState::ResetRecvd);
        qs.send_state.set(QuicStreamSendState::ResetSent);

        let sc = qs.connection.borrow().clone();

        let sc = match sc {
            Some(sc) => sc,
            None => {
                let _ = ngx_quic_close_stream(&qs);
                continue;
            }
        };

        qs.read_error.set(true);
        qs.read_ready.set(true);
        qs.write_error.set(true);
        qs.write_ready.set(true);

        sc.close.set(true);

        if qs.read.posted.get() {
            qs.read.delete_posted();
        }

        posted.push((qs, sc));
    }

    // ngx_event_process_posted(): the read handlers of the streams, in
    // order; once one has to run in its task, those of the next streams
    // run in theirs, after it. A task is woken to close its stream, or to
    // end once its stream is closed.

    let mut deferred = false;

    for (qs, sc) in posted {
        let handler = if deferred { None } else { sc.close_handler.borrow().clone() };

        match handler {
            Some(handler) => handler(&sc),
            None => deferred = true,
        }

        qs.notify.notify_waiters();
    }

    if qc.streams.tree.borrow().is_empty() {
        return NGX_OK;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic connection has active streams");

    NGX_AGAIN
}

/// ngx_quic_reset_stream
pub fn ngx_quic_reset_stream(c: &Connection, err: u64) -> i64 {
    match ngx_quic_stream(c) {
        Some(qs) => ngx_quic_do_reset_stream(&qs, err),
        None => NGX_ERROR,
    }
}

/// ngx_quic_do_reset_stream
fn ngx_quic_do_reset_stream(qs: &Rc<QuicStream>, err: u64) -> i64 {
    if matches!(qs.send_state.get(), QuicStreamSendState::DataRecvd | QuicStreamSendState::ResetSent | QuicStreamSendState::ResetRecvd) {
        return NGX_OK;
    }

    qs.send_state.set(QuicStreamSendState::ResetSent);
    qs.send_final_size.set(qs.send_offset.get());

    if qs.connection.borrow().is_some() {
        qs.write_error.set(true);
    }

    let (pc, qc) = match parent(qs) {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} reset", qs.id);

    let mut frame = match ngx_quic_alloc_frame(&pc) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_RESET_STREAM;
    frame.u.reset_stream.id = qs.id;
    frame.u.reset_stream.error_code = err;
    frame.u.reset_stream.final_size = qs.send_offset.get();

    ngx_quic_queue_frame(&qc, frame);

    ngx_quic_free_buffer(&pc, &mut qs.send.borrow_mut());

    NGX_OK
}

/// ngx_quic_shutdown_stream
pub fn ngx_quic_shutdown_stream(c: &Connection, how: i32) -> i64 {
    if (how == NGX_RDWR_SHUTDOWN || how == NGX_WRITE_SHUTDOWN) && ngx_quic_shutdown_stream_send(c) != NGX_OK {
        return NGX_ERROR;
    }

    if (how == NGX_RDWR_SHUTDOWN || how == NGX_READ_SHUTDOWN) && ngx_quic_shutdown_stream_recv(c) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_shutdown_stream_send
fn ngx_quic_shutdown_stream_send(c: &Connection) -> i64 {
    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return NGX_ERROR,
    };

    if !matches!(qs.send_state.get(), QuicStreamSendState::Ready | QuicStreamSendState::Send) {
        return NGX_OK;
    }

    qs.send_state.set(QuicStreamSendState::Send);
    qs.send_final_size.set(c.sent.get());

    if let Some(pc) = qs.parent.upgrade() {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} send shutdown", qs.id);
    }

    ngx_quic_stream_flush(&qs)
}

/// ngx_quic_shutdown_stream_recv
fn ngx_quic_shutdown_stream_recv(c: &Connection) -> i64 {
    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return NGX_ERROR,
    };

    if !matches!(qs.recv_state.get(), QuicStreamRecvState::Recv | QuicStreamRecvState::SizeKnown) {
        return NGX_OK;
    }

    let (pc, qc) = match parent(&qs) {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    if qc.conf.stream_close_code == 0 {
        return NGX_OK;
    }

    let mut frame = match ngx_quic_alloc_frame(&pc) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} recv shutdown", qs.id);

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_STOP_SENDING;
    frame.u.stop_sending.id = qs.id;
    frame.u.stop_sending.error_code = qc.conf.stream_close_code;

    ngx_quic_queue_frame(&qc, frame);

    NGX_OK
}

/// ngx_quic_get_stream
fn ngx_quic_get_stream(c: &Rc<Connection>, id: u64) -> GetStream {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return GetStream::Error,
    };

    if let Some(qs) = ngx_quic_find_stream(&qc, id) {
        return GetStream::Stream(qs);
    }

    if qc.shutdown.get() || qc.closing.get() {
        return GetStream::Gone;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stream id:0x{:x} is missing", id);

    let streams = &qc.streams;

    let mut min_id;

    if id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 {
        if id & NGX_QUIC_STREAM_SERVER_INITIATED != 0 {
            if (id >> 2) < streams.server_streams_uni.get() {
                return GetStream::Gone;
            }

            qc.error.set(NGX_QUIC_ERR_STREAM_STATE_ERROR);
            return GetStream::Error;
        }

        if (id >> 2) < streams.client_streams_uni.get() {
            return GetStream::Gone;
        }

        if (id >> 2) >= streams.client_max_streams_uni.get() {
            qc.error.set(NGX_QUIC_ERR_STREAM_LIMIT_ERROR);
            return GetStream::Error;
        }

        min_id = (streams.client_streams_uni.get() << 2) | NGX_QUIC_STREAM_UNIDIRECTIONAL;
        streams.client_streams_uni.set((id >> 2) + 1);
    } else {
        if id & NGX_QUIC_STREAM_SERVER_INITIATED != 0 {
            if (id >> 2) < streams.server_streams_bidi.get() {
                return GetStream::Gone;
            }

            qc.error.set(NGX_QUIC_ERR_STREAM_STATE_ERROR);
            return GetStream::Error;
        }

        if (id >> 2) < streams.client_streams_bidi.get() {
            return GetStream::Gone;
        }

        if (id >> 2) >= streams.client_max_streams_bidi.get() {
            qc.error.set(NGX_QUIC_ERR_STREAM_LIMIT_ERROR);
            return GetStream::Error;
        }

        min_id = streams.client_streams_bidi.get() << 2;
        streams.client_streams_bidi.set((id >> 2) + 1);
    }

    // RFC 9000, 2.1.  Stream Types and Identifiers
    //
    // successive streams of each type are created with numerically increasing
    // stream IDs.  A stream ID that is used out of order results in all
    // streams of that type with lower-numbered stream IDs also being opened.

    let mut qs = None;

    while min_id <= id {
        qs = ngx_quic_create_stream(c, &qc, min_id);

        let s = match &qs {
            Some(s) => s.clone(),
            None => {
                if ngx_quic_reject_stream(c, min_id) != NGX_OK {
                    return GetStream::Error;
                }

                min_id += 0x04;
                continue;
            }
        };

        streams.uninitialized.borrow_mut().push_back(s.clone());

        s.init_handler.set(true);

        if streams.initialized.get() {
            s.read.post();

            if qc.push.posted.get() {
                // The posted stream can produce output immediately.
                // By postponing the push event, we coalesce the stream
                // output with queued frames in one UDP datagram.

                qc.push.delete_posted();
                qc.push.post();
            }
        }

        min_id += 0x04;
    }

    match qs {
        Some(qs) => GetStream::Stream(qs),
        None => GetStream::Gone,
    }
}

/// ngx_quic_reject_stream
fn ngx_quic_reject_stream(c: &Connection, id: u64) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let code = if id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 { qc.conf.stream_reject_code_uni } else { qc.conf.stream_reject_code_bidi };

    if code == 0 {
        return NGX_DECLINED;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stream id:0x{:x} reject err:0x{:x}", id, code);

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_RESET_STREAM;
    frame.u.reset_stream.id = id;
    frame.u.reset_stream.error_code = code;
    frame.u.reset_stream.final_size = 0;

    ngx_quic_queue_frame(&qc, frame);

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_STOP_SENDING;
    frame.u.stop_sending.id = id;
    frame.u.stop_sending.error_code = code;

    ngx_quic_queue_frame(&qc, frame);

    NGX_OK
}

/// The read event of a stream: ngx_quic_init_stream_handler for a stream
/// not given to the application yet, else the stream's task is woken.
pub fn ngx_quic_stream_read_event(qs: &Rc<QuicStream>) {
    if qs.init_handler.get() {
        ngx_quic_init_stream_handler(qs);
        return;
    }

    qs.notify.notify_waiters();
}

/// The write event of a stream: its task is woken.
pub fn ngx_quic_stream_write_event(qs: &Rc<QuicStream>) {
    qs.notify.notify_waiters();
}

/// Wait until `ready()` holds, woken by the events of the stream.
pub async fn wait_stream(qs: &QuicStream, ready: impl Fn() -> bool) {
    loop {
        let notified = qs.notify.notified();
        tokio::pin!(notified);

        // the events from now on wake the task
        notified.as_mut().enable();

        if ready() {
            return;
        }

        notified.await;
    }
}

/// ngx_quic_init_stream_handler
fn ngx_quic_init_stream_handler(qs: &Rc<QuicStream>) {
    let c = match qs.connection.borrow().clone() {
        Some(c) => c,
        None => return,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic init stream");

    if qs.id & NGX_QUIC_STREAM_UNIDIRECTIONAL == 0 {
        qs.write_active.set(true);
        qs.write_ready.set(true);
    }

    qs.read_active.set(true);

    qs.init_handler.set(false);

    if let Some((_, qc)) = parent(qs) {
        qc.streams.uninitialized.borrow_mut().retain(|s| !Rc::ptr_eq(s, qs));
    }

    let handler = c.listening().and_then(|ls| ls.handler.borrow().clone());

    if let Some(handler) = handler {
        handler(c);
    }
}

/// ngx_quic_init_streams
pub fn ngx_quic_init_streams(c: &Rc<Connection>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if qc.streams.initialized.get() {
        return NGX_OK;
    }

    // ngx_ssl_ocsp_validate(): no OCSP validation of client certificates
    // over QUIC

    ngx_quic_do_init_streams(c)
}

/// ngx_quic_do_init_streams
fn ngx_quic_do_init_streams(c: &Rc<Connection>) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic init streams");

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if let Some(init) = qc.conf.init.clone() {
        if init(c) != NGX_OK {
            return NGX_ERROR;
        }
    }

    let uninitialized: Vec<Rc<QuicStream>> = qc.streams.uninitialized.borrow().iter().cloned().collect();

    for qs in uninitialized {
        qs.read.post();
    }

    qc.streams.initialized.set(true);

    if !qc.closing.get() && qc.close.timer_set() {
        qc.close.del_timer();
    }

    NGX_OK
}

/// ngx_quic_create_stream
fn ngx_quic_create_stream(c: &Rc<Connection>, qc: &Rc<QuicConnection>, id: u64) -> Option<Rc<QuicStream>> {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stream id:0x{:x} create", id);

    let reusable = c.reusable.get();
    c.reusable_connection(false);

    let sc = match Connection::quic_stream_connection(c) {
        Some(sc) => sc,
        None => {
            c.reusable_connection(reusable);
            return None;
        }
    };

    let (send_max_data, recv_max_data, recv_state, send_state) = {
        let tp = qc.tp.borrow();
        let ctp = qc.ctp.borrow();

        if id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 {
            if id & NGX_QUIC_STREAM_SERVER_INITIATED != 0 {
                (ctp.initial_max_stream_data_uni, 0, QuicStreamRecvState::DataRead, QuicStreamSendState::Ready)
            } else {
                (0, tp.initial_max_stream_data_uni, QuicStreamRecvState::Recv, QuicStreamSendState::DataRecvd)
            }
        } else if id & NGX_QUIC_STREAM_SERVER_INITIATED != 0 {
            (ctp.initial_max_stream_data_bidi_remote, tp.initial_max_stream_data_bidi_local, QuicStreamRecvState::Recv, QuicStreamSendState::Ready)
        } else {
            (ctp.initial_max_stream_data_bidi_local, tp.initial_max_stream_data_bidi_remote, QuicStreamRecvState::Recv, QuicStreamSendState::Ready)
        }
    };

    let qs = Rc::new_cyclic(|w: &Weak<QuicStream>| QuicStream {
        parent: Rc::downgrade(c),
        connection: RefCell::new(Some(sc.clone())),
        id,
        sent: Cell::new(0),
        acked: Cell::new(0),
        send_max_data: Cell::new(send_max_data),
        send_offset: Cell::new(0),
        send_final_size: Cell::new(u64::MAX),
        recv_max_data: Cell::new(recv_max_data),
        recv_offset: Cell::new(0),
        recv_window: Cell::new(recv_max_data),
        recv_last: Cell::new(0),
        recv_final_size: Cell::new(u64::MAX),
        send: RefCell::new(QuicBuffer::default()),
        recv: RefCell::new(QuicBuffer::default()),
        send_state: Cell::new(send_state),
        recv_state: Cell::new(recv_state),
        cancelable: Cell::new(false),
        fin_acked: Cell::new(false),
        read: QEvent::new(QEventKind::StreamRead(w.clone()), qc),
        write: QEvent::new(QEventKind::StreamWrite(w.clone()), qc),
        read_ready: Cell::new(false),
        read_active: Cell::new(false),
        read_error: Cell::new(false),
        read_eof: Cell::new(false),
        write_ready: Cell::new(false),
        write_active: Cell::new(false),
        write_error: Cell::new(false),
        init_handler: Cell::new(false),
        notify: tokio::sync::Notify::new(),
    });

    *sc.quic_stream.borrow_mut() = Some(qs.clone());

    let wsc = Rc::downgrade(&sc);

    sc.add_cleanup(PoolCleanup {
        tag: "ngx_quic_stream_cleanup_handler",
        data: None,
        handler: Some(Box::new(move || {
            if let Some(sc) = wsc.upgrade() {
                ngx_quic_stream_cleanup_handler(&sc);
            }
        })),
    });

    qc.streams.tree.borrow_mut().insert(id, qs.clone());

    Some(qs)
}

/// ngx_quic_cancelable_stream
pub fn ngx_quic_cancelable_stream(c: &Connection) {
    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return,
    };

    let (pc, qc) = match parent(&qs) {
        Some(p) => p,
        None => return,
    };

    if !qs.cancelable.get() {
        qs.cancelable.set(true);

        if ngx_quic_can_shutdown(&qc) == NGX_OK {
            pc.reusable_connection(true);

            if qc.shutdown.get() {
                ngx_quic_shutdown_quic(&pc);
            }
        }
    }
}

/// ngx_quic_stream_recv: the bytes read, 0 at the end of the stream,
/// NGX_AGAIN or NGX_ERROR
pub fn ngx_quic_stream_recv(c: &Connection, buf: &mut [u8]) -> isize {
    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return NGX_ERROR as isize,
    };

    let pc = match qs.parent.upgrade() {
        Some(pc) => pc,
        None => return NGX_ERROR as isize,
    };

    if matches!(qs.recv_state.get(), QuicStreamRecvState::ResetRecvd | QuicStreamRecvState::ResetRead) {
        qs.recv_state.set(QuicStreamRecvState::ResetRead);
        return NGX_ERROR as isize;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} recv buf:{}", qs.id, buf.len());

    if buf.is_empty() {
        return 0;
    }

    let input = ngx_quic_read_buffer(&pc, &mut qs.recv.borrow_mut(), buf.len() as u64);

    let mut len = 0usize;

    for b in input.iter() {
        let n = b.len();
        buf[len..len + n].copy_from_slice(&b.block.borrow()[b.pos..b.last]);
        len += n;
    }

    ngx_quic_free_chain(&pc, input);

    if len == 0 {
        qs.read_ready.set(false);

        if qs.recv_state.get() == QuicStreamRecvState::DataRecvd && qs.recv_offset.get() == qs.recv_final_size.get() {
            qs.recv_state.set(QuicStreamRecvState::DataRead);
        }

        if qs.recv_state.get() == QuicStreamRecvState::DataRead {
            qs.read_eof.set(true);
            return 0;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stream id:0x{:x} recv() not ready", qs.id);
        return NGX_AGAIN as isize;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stream id:0x{:x} recv len:{}", qs.id, len);

    if ngx_quic_update_flow(&qs, qs.recv_offset.get() + len as u64) != NGX_OK {
        return NGX_ERROR as isize;
    }

    len as isize
}

/// ngx_quic_stream_send_chain: the input (its slices advance as they are
/// taken) written to the stream, up to `limit` bytes (0: no limit) and
/// the flow control window; Err is NGX_CHAIN_ERROR
pub fn ngx_quic_stream_send_chain(c: &Connection, input: &mut [&[u8]], limit: u64) -> Result<(), ()> {
    let qs = ngx_quic_stream(c).ok_or(())?;
    let (pc, qc) = parent(&qs).ok_or(())?;

    if !matches!(qs.send_state.get(), QuicStreamSendState::Ready | QuicStreamSendState::Send) {
        qs.write_error.set(true);
        return Err(());
    }

    qs.send_state.set(QuicStreamSendState::Send);

    let flow = qs.acked.get().wrapping_add(qc.conf.stream_buffer_size as u64).wrapping_sub(qs.sent.get());

    if flow == 0 {
        qs.write_ready.set(false);
        return Ok(());
    }

    let limit = if limit == 0 || limit > flow { flow } else { limit };

    let n = qs.send.borrow().size;

    ngx_quic_write_buffer(&pc, &mut qs.send.borrow_mut(), input, limit, qs.sent.get());

    let n = qs.send.borrow().size - n;
    c.sent.set(c.sent.get() + n);
    qs.sent.set(qs.sent.get() + n);
    qc.streams.sent.set(qc.streams.sent.get() + n);

    if flow == n {
        qs.write_ready.set(false);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic send_chain sent:{}", n);

    if ngx_quic_stream_flush(&qs) != NGX_OK {
        return Err(());
    }

    Ok(())
}

/// ngx_quic_stream_flush
fn ngx_quic_stream_flush(qs: &Rc<QuicStream>) -> i64 {
    if qs.send_state.get() != QuicStreamSendState::Send {
        return NGX_OK;
    }

    let (pc, qc) = match parent(qs) {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    let streams = &qc.streams;

    if streams.send_max_data.get() == 0 {
        streams.send_max_data.set(qc.ctp.borrow().initial_max_data);
    }

    let limit = (streams.send_max_data.get().wrapping_sub(streams.send_offset.get()) as i64).min(qs.send_max_data.get().wrapping_sub(qs.send_offset.get()) as i64);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} flush limit:{}", qs.id, limit);

    let len = qs.send.borrow().offset;

    let out = ngx_quic_read_buffer(&pc, &mut qs.send.borrow_mut(), limit as u64);

    let len = qs.send.borrow().offset - len;
    let mut last = false;

    if qs.send_final_size.get() != u64::MAX && qs.send_final_size.get() == qs.send.borrow().offset {
        qs.send_state.set(QuicStreamSendState::DataSent);
        last = true;
    }

    if len == 0 && !last {
        return NGX_OK;
    }

    let mut frame = match ngx_quic_alloc_frame(&pc) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_STREAM;
    frame.data = out;

    frame.u.stream.off = true;
    frame.u.stream.len = true;
    frame.u.stream.fin = last;

    frame.u.stream.stream_id = qs.id;
    frame.u.ord.offset = qs.send_offset.get();
    frame.u.ord.length = len;

    ngx_quic_queue_frame(&qc, frame);

    qs.send_offset.set(qs.send_offset.get() + len);
    streams.send_offset.set(streams.send_offset.get() + len);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} flush len:{} last:{}", qs.id, len, last as u32);

    if qs.connection.borrow().is_none() {
        return ngx_quic_close_stream(qs);
    }

    NGX_OK
}

/// ngx_quic_stream_cleanup_handler
fn ngx_quic_stream_cleanup_handler(c: &Connection) {
    let qs = match ngx_quic_stream(c) {
        Some(qs) => qs,
        None => return,
    };

    if let Some(pc) = qs.parent.upgrade() {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} cleanup", qs.id);
    }

    let failed = 'failed: {
        if ngx_quic_shutdown_stream(c, NGX_RDWR_SHUTDOWN) != NGX_OK {
            *qs.connection.borrow_mut() = None;
            break 'failed true;
        }

        *qs.connection.borrow_mut() = None;

        if ngx_quic_close_stream(&qs) != NGX_OK {
            break 'failed true;
        }

        false
    };

    // the events of the stream end with its connection
    qs.read.delete_posted();
    qs.write.delete_posted();

    if !failed {
        return;
    }

    if let Some((_, qc)) = parent(&qs) {
        qc.error.set(NGX_QUIC_ERR_INTERNAL_ERROR);

        qc.close.post();
    }
}

/// ngx_quic_close_stream
fn ngx_quic_close_stream(qs: &Rc<QuicStream>) -> i64 {
    let (pc, qc) = match parent(qs) {
        Some(p) => p,
        None => return NGX_OK,
    };

    if !qc.closing.get() {
        /* make sure everything is sent and final size is received */

        if qs.recv_state.get() == QuicStreamRecvState::Recv {
            return NGX_OK;
        }

        if !matches!(qs.send_state.get(), QuicStreamSendState::DataRecvd | QuicStreamSendState::ResetRecvd) {
            return NGX_OK;
        }
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} close", qs.id);

    ngx_quic_free_buffer(&pc, &mut qs.send.borrow_mut());
    ngx_quic_free_buffer(&pc, &mut qs.recv.borrow_mut());

    qc.streams.tree.borrow_mut().remove(&qs.id);

    if qc.closing.get() {
        /* schedule handler call to continue ngx_quic_close_connection() */
        qc.close.post();
        return NGX_OK;
    }

    if !pc.reusable.get() && ngx_quic_can_shutdown(&qc) == NGX_OK {
        pc.reusable_connection(true);
    }

    if qc.shutdown.get() {
        ngx_quic_shutdown_quic(&pc);
        return NGX_OK;
    }

    if qs.id & NGX_QUIC_STREAM_SERVER_INITIATED == 0 {
        let mut frame = match ngx_quic_alloc_frame(&pc) {
            Some(f) => f,
            None => return NGX_ERROR,
        };

        frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
        frame.ty = NGX_QUIC_FT_MAX_STREAMS;

        let streams = &qc.streams;

        if qs.id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 {
            streams.client_max_streams_uni.set(streams.client_max_streams_uni.get() + 1);
            frame.u.max_streams.limit = streams.client_max_streams_uni.get();
            frame.u.max_streams.bidi = false;
        } else {
            streams.client_max_streams_bidi.set(streams.client_max_streams_bidi.get() + 1);
            frame.u.max_streams.limit = streams.client_max_streams_bidi.get();
            frame.u.max_streams.bidi = true;
        }

        ngx_quic_queue_frame(&qc, frame);
    }

    NGX_OK
}

/// ngx_quic_can_shutdown
fn ngx_quic_can_shutdown(qc: &QuicConnection) -> i64 {
    if qc.streams.tree.borrow().values().any(|qs| !qs.cancelable.get()) {
        return NGX_DECLINED;
    }

    NGX_OK
}

/// ngx_quic_handle_stream_frame
pub fn ngx_quic_handle_stream_frame(c: &Rc<Connection>, _pkt: &QuicHeader<'_>, frame: &QuicFrame, data: &[u8]) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let f = &frame.u.stream;
    let ord = &frame.u.ord;

    if f.stream_id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 && f.stream_id & NGX_QUIC_STREAM_SERVER_INITIATED != 0 {
        qc.error.set(NGX_QUIC_ERR_STREAM_STATE_ERROR);
        return NGX_ERROR;
    }

    /* no overflow since both values are 62-bit */
    let last = ord.offset + ord.length;

    let qs = match ngx_quic_get_stream(c, f.stream_id) {
        GetStream::Stream(qs) => qs,
        GetStream::Gone => return NGX_OK,
        GetStream::Error => return NGX_ERROR,
    };

    if qs.recv_final_size.get() != u64::MAX && (qs.recv_final_size.get() < last || (qs.recv_final_size.get() > last && f.fin)) {
        qc.error.set(NGX_QUIC_ERR_FINAL_SIZE_ERROR);
        return NGX_ERROR;
    }

    if qs.recv_last.get() > last && f.fin {
        qc.error.set(NGX_QUIC_ERR_FINAL_SIZE_ERROR);
        return NGX_ERROR;
    }

    if !matches!(qs.recv_state.get(), QuicStreamRecvState::Recv | QuicStreamRecvState::SizeKnown) {
        return NGX_OK;
    }

    if ngx_quic_control_flow(&qs, last) != NGX_OK {
        return NGX_ERROR;
    }

    if last < qs.recv_offset.get() {
        return NGX_OK;
    }

    if f.fin {
        qs.recv_final_size.set(last);
        qs.recv_state.set(QuicStreamRecvState::SizeKnown);
    }

    let mut input = [data];

    ngx_quic_write_buffer(c, &mut qs.recv.borrow_mut(), &mut input, ord.length, ord.offset);

    if qs.recv_state.get() == QuicStreamRecvState::SizeKnown && qs.recv.borrow().size == qs.recv_final_size.get() {
        qs.recv_state.set(QuicStreamRecvState::DataRecvd);
    }

    if qs.connection.borrow().is_none() {
        return ngx_quic_close_stream(&qs);
    }

    if ord.offset <= qs.recv_offset.get() {
        ngx_quic_set_read_event(&qs);
    }

    NGX_OK
}

/// ngx_quic_handle_max_data_frame
pub fn ngx_quic_handle_max_data_frame(c: &Rc<Connection>, f: &QuicMaxDataFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let streams = &qc.streams;

    if f.max_data <= streams.send_max_data.get() {
        return NGX_OK;
    }

    if streams.tree.borrow().is_empty() || streams.send_offset.get() < streams.send_max_data.get() {
        /* not blocked on MAX_DATA */
        streams.send_max_data.set(f.max_data);
        return NGX_OK;
    }

    streams.send_max_data.set(f.max_data);

    let all: Vec<Rc<QuicStream>> = streams.tree.borrow().values().cloned().collect();

    for qs in all {
        if streams.send_offset.get() >= streams.send_max_data.get() {
            break;
        }

        if ngx_quic_stream_flush(&qs) != NGX_OK {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_quic_handle_streams_blocked_frame
pub fn ngx_quic_handle_streams_blocked_frame(_c: &Rc<Connection>, _pkt: &QuicHeader<'_>, _f: &QuicStreamsBlockedFrame) -> i64 {
    NGX_OK
}

/// ngx_quic_handle_data_blocked_frame
pub fn ngx_quic_handle_data_blocked_frame(c: &Rc<Connection>, _pkt: &QuicHeader<'_>, _f: &QuicDataBlockedFrame) -> i64 {
    ngx_quic_update_max_data(c)
}

/// ngx_quic_handle_stream_data_blocked_frame
pub fn ngx_quic_handle_stream_data_blocked_frame(c: &Rc<Connection>, _pkt: &QuicHeader<'_>, f: &QuicStreamDataBlockedFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if f.id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 && f.id & NGX_QUIC_STREAM_SERVER_INITIATED != 0 {
        qc.error.set(NGX_QUIC_ERR_STREAM_STATE_ERROR);
        return NGX_ERROR;
    }

    match ngx_quic_get_stream(c, f.id) {
        GetStream::Stream(qs) => ngx_quic_update_max_stream_data(&qs),
        GetStream::Gone => NGX_OK,
        GetStream::Error => NGX_ERROR,
    }
}

/// ngx_quic_handle_max_stream_data_frame
pub fn ngx_quic_handle_max_stream_data_frame(c: &Rc<Connection>, _pkt: &QuicHeader<'_>, f: &QuicMaxStreamDataFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if f.id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 && f.id & NGX_QUIC_STREAM_SERVER_INITIATED == 0 {
        qc.error.set(NGX_QUIC_ERR_STREAM_STATE_ERROR);
        return NGX_ERROR;
    }

    let qs = match ngx_quic_get_stream(c, f.id) {
        GetStream::Stream(qs) => qs,
        GetStream::Gone => return NGX_OK,
        GetStream::Error => return NGX_ERROR,
    };

    if f.limit <= qs.send_max_data.get() {
        return NGX_OK;
    }

    if qs.send_offset.get() < qs.send_max_data.get() {
        /* not blocked on MAX_STREAM_DATA */
        qs.send_max_data.set(f.limit);
        return NGX_OK;
    }

    qs.send_max_data.set(f.limit);

    ngx_quic_stream_flush(&qs)
}

/// ngx_quic_handle_reset_stream_frame
pub fn ngx_quic_handle_reset_stream_frame(c: &Rc<Connection>, _pkt: &QuicHeader<'_>, f: &QuicResetStreamFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if f.id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 && f.id & NGX_QUIC_STREAM_SERVER_INITIATED != 0 {
        qc.error.set(NGX_QUIC_ERR_STREAM_STATE_ERROR);
        return NGX_ERROR;
    }

    let qs = match ngx_quic_get_stream(c, f.id) {
        GetStream::Stream(qs) => qs,
        GetStream::Gone => return NGX_OK,
        GetStream::Error => return NGX_ERROR,
    };

    if qs.recv_final_size.get() != u64::MAX && qs.recv_final_size.get() != f.final_size {
        qc.error.set(NGX_QUIC_ERR_FINAL_SIZE_ERROR);
        return NGX_ERROR;
    }

    if qs.recv_last.get() > f.final_size {
        qc.error.set(NGX_QUIC_ERR_FINAL_SIZE_ERROR);
        return NGX_ERROR;
    }

    if matches!(qs.recv_state.get(), QuicStreamRecvState::ResetRecvd | QuicStreamRecvState::ResetRead) {
        return NGX_OK;
    }

    if ngx_quic_control_flow(&qs, f.final_size) != NGX_OK {
        return NGX_ERROR;
    }

    qs.recv_final_size.set(f.final_size);
    qs.recv_state.set(QuicStreamRecvState::ResetRecvd);

    if ngx_quic_update_flow(&qs, qs.recv_final_size.get()) != NGX_OK {
        return NGX_ERROR;
    }

    if qs.connection.borrow().is_none() {
        return ngx_quic_close_stream(&qs);
    }

    qs.read_error.set(true);

    ngx_quic_set_read_event(&qs);

    NGX_OK
}

/// ngx_quic_handle_stop_sending_frame
pub fn ngx_quic_handle_stop_sending_frame(c: &Rc<Connection>, _pkt: &QuicHeader<'_>, f: &QuicStopSendingFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if f.id & NGX_QUIC_STREAM_UNIDIRECTIONAL != 0 && f.id & NGX_QUIC_STREAM_SERVER_INITIATED == 0 {
        qc.error.set(NGX_QUIC_ERR_STREAM_STATE_ERROR);
        return NGX_ERROR;
    }

    let qs = match ngx_quic_get_stream(c, f.id) {
        GetStream::Stream(qs) => qs,
        GetStream::Gone => return NGX_OK,
        GetStream::Error => return NGX_ERROR,
    };

    if ngx_quic_do_reset_stream(&qs, f.error_code) != NGX_OK {
        return NGX_ERROR;
    }

    if qs.connection.borrow().is_none() {
        return ngx_quic_close_stream(&qs);
    }

    ngx_quic_set_write_event(&qs);

    NGX_OK
}

/// ngx_quic_handle_max_streams_frame
pub fn ngx_quic_handle_max_streams_frame(c: &Rc<Connection>, _pkt: &QuicHeader<'_>, f: &QuicMaxStreamsFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let streams = &qc.streams;

    if f.bidi {
        if streams.server_max_streams_bidi.get() < f.limit {
            streams.server_max_streams_bidi.set(f.limit);

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic max_streams_bidi:{}", f.limit);
        }
    } else if streams.server_max_streams_uni.get() < f.limit {
        streams.server_max_streams_uni.set(f.limit);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic max_streams_uni:{}", f.limit);
    }

    NGX_OK
}

/// ngx_quic_handle_stream_ack
pub fn ngx_quic_handle_stream_ack(c: &Rc<Connection>, f: &QuicFrame) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let qs = match f.ty {
        NGX_QUIC_FT_RESET_STREAM => {
            let qs = match ngx_quic_find_stream(&qc, f.u.reset_stream.id) {
                Some(qs) => qs,
                None => return,
            };

            qs.send_state.set(QuicStreamSendState::ResetRecvd);

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stream id:0x{:x} ack reset final_size:{}", qs.id, f.u.reset_stream.final_size);

            qs
        }

        NGX_QUIC_FT_STREAM => {
            let qs = match ngx_quic_find_stream(&qc, f.u.stream.stream_id) {
                Some(qs) => qs,
                None => return,
            };

            let acked = qs.acked.get();
            qs.acked.set(acked + f.u.ord.length);

            if f.u.stream.fin {
                qs.fin_acked.set(true);
            }

            if qs.send_state.get() == QuicStreamSendState::DataSent && qs.acked.get() == qs.sent.get() && qs.fin_acked.get() {
                qs.send_state.set(QuicStreamSendState::DataRecvd);
            }

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stream id:0x{:x} ack len:{} fin:{} unacked:{}", qs.id, f.u.ord.length, f.u.stream.fin as i32, qs.sent.get() - qs.acked.get());

            if qs.connection.borrow().is_some() && qs.sent.get() - acked == qc.conf.stream_buffer_size as u64 && f.u.ord.length > 0 {
                ngx_quic_set_write_event(&qs);
            }

            qs
        }

        _ => return,
    };

    if qs.connection.borrow().is_none() {
        let _ = ngx_quic_close_stream(&qs);
    }
}

/// ngx_quic_control_flow
fn ngx_quic_control_flow(qs: &QuicStream, last: u64) -> i64 {
    let (pc, qc) = match parent(qs) {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    if last <= qs.recv_last.get() {
        return NGX_OK;
    }

    let len = last - qs.recv_last.get();

    let streams = &qc.streams;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} flow control msd:{}/{} md:{}/{}", qs.id, last, qs.recv_max_data.get(), streams.recv_last.get() + len, streams.recv_max_data.get());

    qs.recv_last.set(qs.recv_last.get() + len);

    if qs.recv_state.get() == QuicStreamRecvState::Recv && qs.recv_last.get() > qs.recv_max_data.get() {
        qc.error.set(NGX_QUIC_ERR_FLOW_CONTROL_ERROR);
        return NGX_ERROR;
    }

    streams.recv_last.set(streams.recv_last.get() + len);

    if streams.recv_last.get() > streams.recv_max_data.get() {
        qc.error.set(NGX_QUIC_ERR_FLOW_CONTROL_ERROR);
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_update_flow
fn ngx_quic_update_flow(qs: &QuicStream, last: u64) -> i64 {
    let (pc, qc) = match parent(qs) {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    if last <= qs.recv_offset.get() {
        return NGX_OK;
    }

    let len = last - qs.recv_offset.get();

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} flow update {}", qs.id, last);

    qs.recv_offset.set(qs.recv_offset.get() + len);

    if qs.recv_max_data.get() <= qs.recv_offset.get() + qs.recv_window.get() / 2 && ngx_quic_update_max_stream_data(qs) != NGX_OK {
        return NGX_ERROR;
    }

    let streams = &qc.streams;

    streams.recv_offset.set(streams.recv_offset.get() + len);

    if streams.recv_max_data.get() <= streams.recv_offset.get() + streams.recv_window.get() / 2 && ngx_quic_update_max_data(&pc) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_update_max_stream_data
fn ngx_quic_update_max_stream_data(qs: &QuicStream) -> i64 {
    let (pc, qc) = match parent(qs) {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    if qs.recv_state.get() != QuicStreamRecvState::Recv {
        return NGX_OK;
    }

    let recv_max_data = qs.recv_offset.get() + qs.recv_window.get();

    if qs.recv_max_data.get() == recv_max_data {
        return NGX_OK;
    }

    qs.recv_max_data.set(recv_max_data);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, pc.log, "quic stream id:0x{:x} flow update msd:{}", qs.id, qs.recv_max_data.get());

    let mut frame = match ngx_quic_alloc_frame(&pc) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_MAX_STREAM_DATA;
    frame.u.max_stream_data.id = qs.id;
    frame.u.max_stream_data.limit = qs.recv_max_data.get();

    ngx_quic_queue_frame(&qc, frame);

    NGX_OK
}

/// ngx_quic_update_max_data
fn ngx_quic_update_max_data(c: &Connection) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let streams = &qc.streams;

    let recv_max_data = streams.recv_offset.get() + streams.recv_window.get();

    if streams.recv_max_data.get() == recv_max_data {
        return NGX_OK;
    }

    streams.recv_max_data.set(recv_max_data);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic flow update md:{}", streams.recv_max_data.get());

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_MAX_DATA;
    frame.u.max_data.max_data = streams.recv_max_data.get();

    ngx_quic_queue_frame(&qc, frame);

    NGX_OK
}

/// ngx_quic_set_event(sc->read)
fn ngx_quic_set_read_event(qs: &QuicStream) {
    qs.read_ready.set(true);

    if qs.read_active.get() {
        qs.read.post();
    }
}

/// ngx_quic_set_event(sc->write)
fn ngx_quic_set_write_event(qs: &QuicStream) {
    qs.write_ready.set(true);

    if qs.write_active.get() {
        qs.write.post();
    }
}

// The stream connection's I/O (Connection::recv, send, writev), waiting
// for the stream's events.

/// The error of a stream reset or closed.
fn stream_error() -> io::Error {
    io::Error::other("quic stream error")
}

/// One read: WouldBlock when there is nothing to read now.
pub fn try_recv(c: &Connection, buf: &mut [u8]) -> io::Result<usize> {
    match ngx_quic_stream_recv(c, buf) {
        n if n >= 0 => Ok(n as usize),
        n if n == NGX_AGAIN as isize => Err(io::ErrorKind::WouldBlock.into()),
        _ => Err(stream_error()),
    }
}

/// sc->recv, waiting for the read event when there is nothing to read.
pub async fn recv(c: &Connection, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match try_recv(c, buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => readable(c).await?,
            r => return r,
        }
    }
}

/// Wait for the read event of the stream (its data, its end, or an error).
pub async fn readable(c: &Connection) -> io::Result<()> {
    let qs = ngx_quic_stream(c).ok_or_else(stream_error)?;

    wait_stream(&qs, || qs.read_ready.get() || qs.read_error.get() || c.close.get() || c.is_closed()).await;

    if c.is_closed() {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }

    Ok(())
}

/// sc->send_chain of the buffers, all of them, waiting for the write event
/// while the flow control window is closed; the bytes sent.
pub async fn send(c: &Connection, iov: &[&[u8]]) -> io::Result<usize> {
    let qs = ngx_quic_stream(c).ok_or_else(stream_error)?;

    let total: usize = iov.iter().map(|s| s.len()).sum();

    let mut input: Vec<&[u8]> = iov.to_vec();

    loop {
        if ngx_quic_stream_send_chain(c, &mut input, 0).is_err() {
            return Err(stream_error());
        }

        let left: usize = input.iter().map(|s| s.len()).sum();

        if left == 0 {
            return Ok(total);
        }

        wait_stream(&qs, || qs.write_ready.get() || qs.write_error.get() || c.is_closed()).await;

        if !qs.write_ready.get() {
            return Err(stream_error());
        }
    }
}

/// One sc->send_chain without waiting: the bytes taken, WouldBlock when
/// the window is closed.
pub fn try_send(c: &Connection, iov: &[&[u8]]) -> io::Result<usize> {
    let total: usize = iov.iter().map(|s| s.len()).sum();

    let mut input: Vec<&[u8]> = iov.to_vec();

    if ngx_quic_stream_send_chain(c, &mut input, 0).is_err() {
        return Err(stream_error());
    }

    let left: usize = input.iter().map(|s| s.len()).sum();

    if left == total && total != 0 {
        return Err(io::ErrorKind::WouldBlock.into());
    }

    Ok(total - left)
}

/// Wait until the stream can take data (the write event).
pub async fn writable(c: &Connection) -> io::Result<()> {
    let qs = ngx_quic_stream(c).ok_or_else(stream_error)?;

    wait_stream(&qs, || qs.write_ready.get() || qs.write_error.get() || c.is_closed()).await;

    if !qs.write_ready.get() {
        return Err(stream_error());
    }

    Ok(())
}

#[allow(dead_code)]
fn _unused(_: VecDeque<u8>) {}
