//! The connection half of nginx-c/src/http/v2/ngx_http_v2.c: init, the read
//! and write handlers (as one async driver per connection), the output
//! queue, the frame senders, and the idle / lingering close / finalize paths.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::connection::Connection;
use ngx_core::log::*;
use ngx_core::{ngx_log_debug, ngx_log_error};
use tokio::time::Instant;

use super::module::{Http2MainConf, Http2SrvConf};
use super::state::state_preface;
use super::stream::{finalize_streams, run_posted};
use super::*;
use crate::core::{loc_conf_from_ctx, CoreLocConf};
use crate::request::HttpConnection;
use crate::core::NGX_HTTP_LINGERING_OFF;

/// What the driver waits for next (the handlers C installs on the
/// connection's read event).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// ngx_http_v2_read_handler
    Read,
    /// ngx_http_v2_idle_handler: no streams, waiting for the next frame.
    Idle,
    /// ngx_http_v2_lingering_close_handler
    Lingering,
    /// The connection is to be closed.
    Close,
}

/// Driver-owned connection state that C keeps in the connection's events.
pub struct Driver {
    mode: Cell<Mode>,
    write_timer: Cell<Option<Instant>>,
    /// Output moved out of the frame queue and not yet written. Like the
    /// SSL buffer ngx_ssl_send_chain fills, frames count as sent once
    /// copied here, and a partial write is retried with the same bytes (as
    /// OpenSSL requires after SSL_ERROR_WANT_WRITE).
    wbuf: RefCell<Vec<u8>>,
    wpos: Cell<usize>,
}

const WBUF_SIZE: usize = 64 * 1024;

impl Driver {
    fn new() -> Driver {
        Driver {
            mode: Cell::new(Mode::Read),
            write_timer: Cell::new(None),
            wbuf: RefCell::new(Vec::with_capacity(WBUF_SIZE)),
            wpos: Cell::new(0),
        }
    }

    fn buffered(&self) -> bool {
        self.wpos.get() < self.wbuf.borrow().len()
    }
}

fn has_output(h2c: &H2Connection, d: &Driver) -> bool {
    d.buffered() || !h2c.last_out.borrow().is_empty()
}

fn clcf(h2c: &H2Connection) -> Rc<RefCell<CoreLocConf>> {
    loc_conf_from_ctx(&h2c.http_connection.conf_ctx.borrow())
}

/// Keep c->idle set for the whole life of an HTTP/2 connection (C sets it
/// once in ngx_http_v2_init); ngx_close_idle_connections finds it by that.
fn reusable(c: &Connection, reusable: bool) {
    c.set_reusable(reusable);
    c.idle.set(true);
}

/// Milliseconds since the connection was accepted, as C's
/// ngx_current_msec - c->start_time (start_msec is wall-clock here).
pub fn connection_age_msec(h2c: &H2Connection) -> u64 {
    let now = ngx_core::times::cached();
    let now_ms = now.sec as u64 * 1000 + now.msec;
    now_ms.saturating_sub(h2c.connection.start_msec.get())
}

/// ngx_http_v2_init: set up the HTTP/2 connection and run it until it is
/// closed. `preread` holds bytes already read from the socket (c->buffer).
pub async fn init(c: Rc<Connection>, hc: Rc<HttpConnection>, preread: Vec<u8>) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "init http2 connection");

    c.log.set_action(Some("processing HTTP/2 connection"));

    let conf_ctx = hc.conf_ctx.borrow().clone();
    let recv_buffer_size = {
        let h2mcf = crate::get_conf::<Http2MainConf>(&conf_ctx, ngx_core::conf::ConfLevel::Main, super::module::ctx_index());
        let size = *h2mcf.borrow().recv_buffer_size;
        size
    };
    let (concurrent_streams, streams_index_mask) = {
        let h2scf = crate::get_conf::<Http2SrvConf>(&conf_ctx, ngx_core::conf::ConfLevel::Srv, super::module::ctx_index());
        let s = h2scf.borrow();
        (*s.concurrent_streams as usize, *s.streams_index_mask as usize)
    };

    let h2c = Rc::new(H2Connection {
        connection: c.clone(),
        http_connection: hc.clone(),
        total_bytes: Cell::new(0),
        payload_bytes: Cell::new(0),
        processing: Cell::new(0),
        frames: Cell::new(0),
        free_frames: Cell::new(0),
        idle: Cell::new(0),
        new_streams: Cell::new(0),
        refused_streams: Cell::new(0),
        priority_limit: Cell::new(concurrent_streams.max(100)),
        send_window: Cell::new(NGX_HTTP_V2_DEFAULT_WINDOW),
        recv_window: Cell::new(NGX_HTTP_V2_MAX_WINDOW),
        init_window: Cell::new(NGX_HTTP_V2_DEFAULT_WINDOW),
        frame_size: Cell::new(NGX_HTTP_V2_DEFAULT_FRAME_SIZE),
        waiting: RefCell::new(VecDeque::new()),
        state: State::new(state_preface),
        hpack: RefCell::new(table::Hpack::new()),
        streams_index: RefCell::new(vec![Vec::new(); streams_index_mask + 1]),
        streams_index_mask,
        last_out: RefCell::new(Vec::new()),
        dependencies: RefCell::new(Vec::new()),
        closed: RefCell::new(VecDeque::new()),
        closed_nodes: Cell::new(0),
        last_sid: Cell::new(0),
        lingering_time: Cell::new(0),
        settings_ack: Cell::new(false),
        table_update: Cell::new(false),
        blocked: Cell::new(false),
        goaway: Cell::new(false),
        out_notify: tokio::sync::Notify::new(),
        posted: RefCell::new(VecDeque::new()),
        posted_reads: RefCell::new(Vec::new()),
        finalized: Cell::new(false),
        read_timer: Cell::new(None),
    });

    let driver = Driver::new();

    if send_settings(&h2c).is_err() {
        c.close();
        return;
    }

    if send_window_update(&h2c, 0, NGX_HTTP_V2_MAX_WINDOW - NGX_HTTP_V2_DEFAULT_WINDOW).is_err() {
        c.close();
        return;
    }

    if ngx_core::event::is_exiting() {
        finalize_connection(&h2c, NGX_HTTP_V2_NO_ERROR);
        finish(&h2c, &driver).await;
        return;
    }

    {
        let cscf = crate::core::srv_conf_from_ctx(&conf_ctx);
        let timeout = *cscf.borrow().client_header_timeout;
        h2c.read_timer.set(Some(Instant::now() + Duration::from_millis(timeout)));
    }

    reusable(&c, false);

    let mut rbuf = vec![0u8; recv_buffer_size];

    if !preread.is_empty() {
        let n = preread.len();
        rbuf[..n].copy_from_slice(&preread);
        if !process_batch(&h2c, &mut rbuf, n).await {
            finish(&h2c, &driver).await;
            return;
        }
        h2c.total_bytes.set(h2c.total_bytes.get() + n as i64);
    }

    // the first read handler run
    after_read(&h2c, &driver).await;

    run(&h2c, &driver, &mut rbuf).await;
}

enum Ev {
    Close,
    Read(io::Result<usize>),
    Written(io::Result<usize>),
    Queued,
    ReadTimeout,
    WriteTimeout,
}

/// The event loop standing in for the read and write handlers.
async fn run(h2c: &Rc<H2Connection>, d: &Driver, rbuf: &mut Vec<u8>) {
    let c = h2c.connection.clone();

    loop {
        if d.mode.get() == Mode::Close || h2c.finalized.get() && h2c.processing.get() == 0 && d.mode.get() != Mode::Lingering {
            finish(h2c, d).await;
            return;
        }

        if d.mode.get() == Mode::Lingering {
            lingering_close_handler(h2c, d, rbuf).await;
            finish(h2c, d).await;
            return;
        }

        fill_wbuf(h2c, d);

        let used = h2c.state.buffer_used.get();
        let available = rbuf.len() - NGX_HTTP_V2_STATE_BUFFER_SIZE;
        let has_output = d.buffered();
        let read_timer = h2c.read_timer.get();
        let write_timer = d.write_timer.get();

        let ev = {
            let (_, tail) = rbuf.split_at_mut(used);
            let rslice = &mut tail[..available];
            tokio::select! {
                biased;
                _ = c.close_notify.notified() => Ev::Close,
                r = c.recv(rslice), if !h2c.finalized.get() => Ev::Read(r),
                w = write_output(h2c, d), if has_output => Ev::Written(w),
                _ = h2c.out_notify.notified(), if !has_output => Ev::Queued,
                _ = sleep_opt(read_timer), if read_timer.is_some() => Ev::ReadTimeout,
                _ = sleep_opt(write_timer), if write_timer.is_some() => Ev::WriteTimeout,
            }
        };

        match ev {
            Ev::Close => {
                if !c.close.get() {
                    // a stray wakeup (not ngx_close_idle_connections)
                    continue;
                }
                on_close_event(h2c, d);
            }

            Ev::Read(res) => {
                if d.mode.get() == Mode::Idle && !idle_handler(h2c, d) {
                    continue;
                }
                read_handler(h2c, d, rbuf, used, res).await;
            }

            Ev::Written(res) => {
                write_handler(h2c, d, res);
            }

            Ev::Queued => {}

            Ev::ReadTimeout => {
                h2c.read_timer.set(None);
                if d.mode.get() == Mode::Idle {
                    // ngx_http_v2_idle_handler: rev->timedout
                    finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
                } else {
                    ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
                    finalize_connection(h2c, NGX_HTTP_V2_PROTOCOL_ERROR);
                }
                decide_after_finalize(h2c, d);
            }

            Ev::WriteTimeout => {
                // ngx_http_v2_write_handler: wev->timedout
                d.write_timer.set(None);
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http2 write event timed out");
                c.error.set(true);
                c.timedout.set(true);
                finalize_connection(h2c, 0);
                decide_after_finalize(h2c, d);
            }
        }
    }
}

async fn sleep_opt(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// The c->close branch of ngx_http_v2_read_handler (and of the idle handler):
/// graceful shutdown.
fn on_close_event(h2c: &Rc<H2Connection>, d: &Driver) {
    let c = &h2c.connection;

    match d.mode.get() {
        Mode::Idle => {
            finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
            decide_after_finalize(h2c, d);
        }
        Mode::Lingering => {
            d.mode.set(Mode::Close);
        }
        Mode::Close => {}
        Mode::Read => {
            c.close.set(false);

            if c.error.get() {
                finalize_connection(h2c, 0);
                decide_after_finalize(h2c, d);
                return;
            }

            if h2c.processing.get() == 0 {
                finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
                decide_after_finalize(h2c, d);
                return;
            }

            if !h2c.goaway.get() {
                h2c.goaway.set(true);

                if send_goaway(h2c, NGX_HTTP_V2_NO_ERROR).is_err() {
                    finalize_connection(h2c, 0);
                    decide_after_finalize(h2c, d);
                }
            }
        }
    }
}

/// ngx_http_v2_idle_handler, on input while idle. False if the connection
/// was finalized.
fn idle_handler(h2c: &Rc<H2Connection>, d: &Driver) -> bool {
    let c = &h2c.connection;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http2 idle handler");

    let keepalive_requests = *clcf(h2c).borrow().keepalive_requests;

    let idle = h2c.idle.get();
    h2c.idle.set(idle + 1);
    if idle > 10 * keepalive_requests as usize {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "http2 flood detected");
        finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
        decide_after_finalize(h2c, d);
        return false;
    }

    c.destroyed.set(false);
    reusable(c, false);

    d.mode.set(Mode::Read);

    true
}

/// ngx_http_v2_read_handler for one completed recv().
async fn read_handler(h2c: &Rc<H2Connection>, d: &Driver, rbuf: &mut Vec<u8>, used: usize, res: io::Result<usize>) {
    let c = h2c.connection.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http2 read handler");

    h2c.blocked.set(true);
    h2c.new_streams.set(0);

    let n = match res {
        Ok(n) if n > 0 => n,
        Ok(_) | Err(_) => {
            if h2c.state.incomplete.get() || h2c.processing.get() > 0 {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "client prematurely closed connection");
            }
            c.error.set(true);
            finalize_connection(h2c, 0);
            decide_after_finalize(h2c, d);
            return;
        }
    };

    // the saved partial frame goes in front of the new data
    {
        let saved = *h2c.state.buffer.borrow();
        rbuf[..used].copy_from_slice(&saved[..used]);
    }

    let end = used + n;

    h2c.state.buffer_used.set(0);
    h2c.state.incomplete.set(false);

    if !process_batch(h2c, rbuf, end).await {
        decide_after_finalize(h2c, d);
        return;
    }

    h2c.total_bytes.set(h2c.total_bytes.get() + n as i64);

    if h2c.total_bytes.get() / 8 > h2c.payload_bytes.get() + 1048576 {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "http2 flood detected");
        finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
        decide_after_finalize(h2c, d);
        return;
    }

    after_read(h2c, d).await;
}

/// The tail of ngx_http_v2_read_handler: flush, unblock, handle_connection.
async fn after_read(h2c: &Rc<H2Connection>, d: &Driver) {
    if has_output(h2c, d) && send_output_queue(h2c, d).is_err() {
        finalize_connection(h2c, 0);
        decide_after_finalize(h2c, d);
        return;
    }

    h2c.blocked.set(false);

    handle_connection(h2c, d);
}

/// Run the state machine over rbuf[..end]. Effects C performs inline
/// (starting a request, waking a stream) are posted by the handlers and run
/// here after each frame; read events posted for request bodies run after
/// the batch. False once the connection has been finalized.
async fn process_batch(h2c: &Rc<H2Connection>, rbuf: &mut [u8], end: usize) -> bool {
    let ok = run_batch(h2c, rbuf, end).await;

    let posted = std::mem::take(&mut *h2c.posted_reads.borrow_mut());
    for stream in posted {
        stream.notify.notify_one();
    }

    ok
}

async fn run_batch(h2c: &Rc<H2Connection>, rbuf: &mut [u8], end: usize) -> bool {
    let mut p = 0;

    loop {
        let handler = h2c.state.handler.get();

        match handler(h2c, &mut rbuf[..end], p) {
            None => return false,
            Some(np) => p = np,
        }

        run_posted(h2c).await;

        if h2c.finalized.get() {
            return false;
        }

        if p == end {
            return true;
        }
    }
}

/// Move queued frames into the write buffer in send order, as
/// c->send_chain consumes the frames' buffers, and run the handlers of the
/// frames copied out completely. A frame copied in part is blocked: nothing
/// is queued ahead of it (ngx_http_v2_queue_frame stops at blocked frames).
fn fill_wbuf(h2c: &Rc<H2Connection>, d: &Driver) {
    if d.buffered() {
        return;
    }

    let mut done: Vec<OutFrame> = Vec::new();
    {
        let mut wbuf = d.wbuf.borrow_mut();
        wbuf.clear();
        d.wpos.set(0);

        let mut out = h2c.last_out.borrow_mut();
        while let Some(f) = out.last_mut() {
            let room = WBUF_SIZE.saturating_sub(wbuf.len());
            if room == 0 {
                break;
            }
            let take = (f.data.len() - f.sent).min(room);
            wbuf.extend_from_slice(&f.data[f.sent..f.sent + take]);
            f.sent += take;
            if f.sent < f.data.len() {
                f.blocked = true;
                break;
            }
            done.push(out.pop().unwrap());
        }
    }

    if done.is_empty() {
        return;
    }

    let c = &h2c.connection;
    let tcp_nodelay = *clcf(h2c).borrow().tcp_nodelay;
    if tcp_nodelay && !c.set_tcp_nodelay() {
        c.error.set(true);
    }

    for frame in done {
        ngx_log_debug!(
            NGX_LOG_DEBUG_HTTP,
            c.log,
            "http2 frame sent: sid:{} len:{}",
            frame.stream.as_ref().map(|s| s.node.borrow().id.get()).unwrap_or(0),
            frame.length
        );
        frame_sent(h2c, frame);
    }
}

/// Write the write buffer out, waiting for writability. Cancel safe: the
/// bytes stay in the buffer until a write reports them taken.
async fn write_output(h2c: &Rc<H2Connection>, d: &Driver) -> io::Result<usize> {
    let wbuf = d.wbuf.borrow();
    let pending = &wbuf[d.wpos.get()..];
    if pending.is_empty() {
        return Ok(0);
    }
    h2c.connection.send(pending).await
}

/// Account `n` bytes of the write buffer as written; arm or clear the send
/// timer as C does in ngx_http_v2_send_output_queue.
fn written(h2c: &Rc<H2Connection>, d: &Driver, n: usize) {
    d.wpos.set(d.wpos.get() + n);
    if !d.buffered() {
        d.wbuf.borrow_mut().clear();
        d.wpos.set(0);
        fill_wbuf(h2c, d);
    }

    if !has_output(h2c, d) {
        d.write_timer.set(None);
    } else if d.write_timer.get().is_none() {
        let send_timeout = *clcf(h2c).borrow().send_timeout;
        d.write_timer.set(Some(Instant::now() + Duration::from_millis(send_timeout)));
    }
}

/// ngx_http_v2_write_handler after write_output completed.
fn write_handler(h2c: &Rc<H2Connection>, d: &Driver, res: io::Result<usize>) {
    let c = &h2c.connection;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http2 write handler");

    h2c.blocked.set(true);

    match res {
        Err(e) => {
            let en = e.raw_os_error().unwrap_or(0);
            if en != 0 {
                ngx_log_error!(NGX_LOG_INFO, c.log, Some(en), "writev() failed");
            }
            c.error.set(true);
            finalize_connection(h2c, 0);
            decide_after_finalize(h2c, d);
            return;
        }
        Ok(n) => written(h2c, d, n),
    }

    if c.error.get() {
        finalize_connection(h2c, 0);
        decide_after_finalize(h2c, d);
        return;
    }

    h2c.blocked.set(false);

    if !has_output(h2c, d) {
        handle_connection(h2c, d);
    }
}

/// ngx_http_v2_send_output_queue: move frames to the write buffer and write
/// what the socket takes right now, without waiting; the rest is left to
/// the write handler.
fn send_output_queue(h2c: &Rc<H2Connection>, d: &Driver) -> Result<(), ()> {
    let c = &h2c.connection;

    if c.error.get() {
        return Err(());
    }

    loop {
        fill_wbuf(h2c, d);

        if !d.buffered() {
            break;
        }

        let res = {
            let wbuf = d.wbuf.borrow();
            c.try_send(&wbuf[d.wpos.get()..])
        };

        match res {
            Ok(n) => {
                written(h2c, d, n);
                if d.buffered() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => {
                let en = e.raw_os_error().unwrap_or(0);
                if en != 0 {
                    ngx_log_error!(NGX_LOG_INFO, c.log, Some(en), "writev() failed");
                }
                c.error.set(true);
                return Err(());
            }
        }
    }

    if has_output(h2c, d) && d.write_timer.get().is_none() {
        let send_timeout = *clcf(h2c).borrow().send_timeout;
        d.write_timer.set(Some(Instant::now() + Duration::from_millis(send_timeout)));
    }

    if c.error.get() {
        return Err(());
    }

    Ok(())
}

/// Run a written frame's handler (out->handler).
fn frame_sent(h2c: &Rc<H2Connection>, frame: OutFrame) {
    match frame.handler {
        FrameHandler::Control => {
            // ngx_http_v2_frame_handler
            h2c.free_frames.set(h2c.free_frames.get() + 1);
            h2c.total_bytes.set(h2c.total_bytes.get() + (NGX_HTTP_V2_FRAME_HEADER_SIZE + frame.length) as i64);
        }
        FrameHandler::Settings => {
            // ngx_http_v2_settings_frame_handler
        }
        FrameHandler::Headers | FrameHandler::Data => {
            super::filter::stream_frame_sent(h2c, frame);
        }
    }
}

/// ngx_http_v2_handle_connection
fn handle_connection(h2c: &Rc<H2Connection>, d: &Driver) {
    let c = &h2c.connection;

    if has_output(h2c, d) || h2c.processing.get() > 0 {
        return;
    }

    if c.error.get() {
        d.mode.set(Mode::Close);
        return;
    }

    if h2c.goaway.get() {
        lingering_close(h2c, d);
        return;
    }

    if h2c.read_timer.get().is_none() {
        let keepalive_timeout = *clcf(h2c).borrow().keepalive_timeout;
        h2c.read_timer.set(Some(Instant::now() + Duration::from_millis(keepalive_timeout)));
    }

    reusable(c, true);

    if h2c.state.incomplete.get() {
        return;
    }

    h2c.free_frames.set(0);
    h2c.frames.set(0);

    c.destroyed.set(true);

    d.mode.set(Mode::Idle);
}

/// After finalize_connection: close now, linger, or keep running until the
/// remaining streams close.
fn decide_after_finalize(h2c: &Rc<H2Connection>, d: &Driver) {
    if h2c.processing.get() > 0 {
        return;
    }

    if h2c.connection.error.get() {
        d.mode.set(Mode::Close);
        return;
    }

    lingering_close(h2c, d);
}

/// ngx_http_v2_lingering_close
fn lingering_close(h2c: &Rc<H2Connection>, d: &Driver) {
    let lingering = *clcf(h2c).borrow().lingering_close;

    if lingering == NGX_HTTP_LINGERING_OFF {
        d.mode.set(Mode::Close);
        return;
    }

    d.mode.set(Mode::Lingering);
}

/// ngx_http_v2_lingering_close + ngx_http_v2_lingering_close_handler: shut
/// down the write side and drain input until the client closes, the
/// lingering timeout or lingering time expires, or on shutdown.
async fn lingering_close_handler(h2c: &Rc<H2Connection>, d: &Driver, rbuf: &mut Vec<u8>) {
    let c = h2c.connection.clone();
    let (lingering_time, lingering_timeout) = {
        let cl = clcf(h2c);
        let cl = cl.borrow();
        (*cl.lingering_time, *cl.lingering_timeout)
    };

    // flush what is still queued (the final GOAWAY)
    fill_wbuf(h2c, d);
    while d.buffered() && !c.error.get() {
        let send_timeout = *clcf(h2c).borrow().send_timeout;
        let res = tokio::select! {
            w = write_output(h2c, d) => Some(w),
            _ = tokio::time::sleep(Duration::from_millis(send_timeout)) => None,
        };
        match res {
            Some(Ok(n)) => written(h2c, d, n),
            _ => return,
        }
    }

    if h2c.lingering_time.get() == 0 {
        h2c.lingering_time.set(ngx_core::times::time() + (lingering_time / 1000) as i64);
    }

    if c.ssl.borrow().is_some() && crate::ssl_module::ngx_http_ssl_lingering_shutdown(&c).await == ngx_core::rc::NGX_ERROR {
        // ngx_http_close_connection(c)
        return;
    }

    if let Err(e) = c.shutdown_write() {
        ngx_log_error!(NGX_LOG_INFO, c.log, e.raw_os_error(), "shutdown() failed");
        return;
    }

    c.close.set(false);
    reusable(&c, true);

    loop {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http2 lingering close handler");

        let timer = h2c.lingering_time.get() - ngx_core::times::time();
        if timer <= 0 {
            return;
        }

        let t = (timer as u64 * 1000).min(lingering_timeout);

        let res = tokio::select! {
            r = tokio::time::timeout(Duration::from_millis(t), c.recv(&mut rbuf[..NGX_HTTP_LINGERING_BUFFER_SIZE])) => r,
            _ = c.close_notify.notified() => {
                // ngx_http_v2_lingering_close_handler closes on c->close,
                // which lingering reset: ignore an earlier shutdown wakeup
                if c.close.get() {
                    return;
                }
                continue;
            }
        };

        match res {
            Err(_) => return,
            Ok(Err(_)) | Ok(Ok(0)) => return,
            Ok(Ok(n)) => {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "lingering read: {}", n);
            }
        }
    }
}

const NGX_HTTP_LINGERING_BUFFER_SIZE: usize = 4096;

/// ngx_http_close_connection for the HTTP/2 connection, once the driver is
/// done: all streams have been closed by now.
async fn finish(h2c: &Rc<H2Connection>, d: &Driver) {
    let c = &h2c.connection;

    h2c.finalized.set(true);

    if !c.error.get() {
        let _ = send_output_queue(h2c, d);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "close http connection");

    // Break the reference cycles through the tree and the output queue.
    h2c.last_out.borrow_mut().clear();
    h2c.waiting.borrow_mut().clear();
    h2c.posted.borrow_mut().clear();
    *h2c.state.stream.borrow_mut() = None;
    for bucket in h2c.streams_index.borrow().iter() {
        for node in bucket {
            node.children.borrow_mut().clear();
            *node.stream.borrow_mut() = None;
        }
    }
    h2c.streams_index.borrow_mut().clear();
    h2c.dependencies.borrow_mut().clear();
    h2c.closed.borrow_mut().clear();

    // ngx_http_close_connection: the SSL shutdown, then the close
    if !crate::ssl_module::ngx_http_ssl_close_connection(c, crate::request_rt::close_connection) {
        return;
    }

    c.close();
}

/// ngx_http_v2_connection_error: finalize the connection; the state machine
/// stops (NULL in C).
pub fn connection_error(h2c: &Rc<H2Connection>, err: u32) -> Option<usize> {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 state connection error");

    finalize_connection(h2c, err);

    None
}

/// ngx_http_v2_finalize_connection: send GOAWAY (unless the connection
/// failed), then terminate every stream. The driver closes or lingers once
/// no stream is left.
pub fn finalize_connection(h2c: &Rc<H2Connection>, status: u32) {
    let c = &h2c.connection;

    if h2c.finalized.get() {
        return;
    }

    h2c.finalized.set(true);
    h2c.blocked.set(true);

    if !c.error.get() && !h2c.goaway.get() {
        h2c.goaway.set(true);

        // the driver writes it out before closing or lingering
        let _ = send_goaway(h2c, status);
    }

    if h2c.processing.get() > 0 {
        h2c.last_out.borrow_mut().retain(|f| f.stream.is_none() || f.blocked);

        finalize_streams(h2c);
    }

    h2c.blocked.set(false);

    if h2c.processing.get() > 0 {
        c.error.set(true);
    }
}

/// ngx_http_v2_send_settings
fn send_settings(h2c: &Rc<H2Connection>) -> Result<(), ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 send SETTINGS frame");

    let len = NGX_HTTP_V2_SETTINGS_PARAM_SIZE * 3;

    let (concurrent_streams, preread_size) = {
        let s = super::stream::h2c_srv_conf(h2c);
        (s.concurrent_streams, s.preread_size)
    };

    let mut data = Vec::with_capacity(NGX_HTTP_V2_FRAME_HEADER_SIZE + len);
    write_frame_head(&mut data, len, NGX_HTTP_V2_SETTINGS_FRAME, NGX_HTTP_V2_NO_FLAG, 0);

    write_uint16(&mut data, NGX_HTTP_V2_MAX_STREAMS_SETTING);
    write_uint32(&mut data, concurrent_streams as u32);

    write_uint16(&mut data, NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING);
    write_uint32(&mut data, preread_size as u32);

    write_uint16(&mut data, NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING);
    write_uint32(&mut data, NGX_HTTP_V2_MAX_FRAME_SIZE as u32);

    h2c.queue_blocked_frame(OutFrame {
        data,
        sent: 0,
        handler: FrameHandler::Settings,
        stream: None,
        length: len,
        blocked: false,
        fin: false,
    });

    Ok(())
}

/// ngx_http_v2_send_window_update
pub fn send_window_update(h2c: &Rc<H2Connection>, sid: u32, window: usize) -> Result<(), ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 send WINDOW_UPDATE frame sid:{}, window:{}", sid, window);

    let mut frame = get_frame(h2c, NGX_HTTP_V2_WINDOW_UPDATE_SIZE, NGX_HTTP_V2_WINDOW_UPDATE_FRAME, NGX_HTTP_V2_NO_FLAG, sid).ok_or(())?;

    write_uint32(&mut frame.data, window as u32);

    h2c.queue_blocked_frame(frame);
    h2c.out_notify.notify_one();

    Ok(())
}

/// ngx_http_v2_send_rst_stream
pub fn send_rst_stream(h2c: &Rc<H2Connection>, sid: u32, status: u32) -> Result<(), ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 send RST_STREAM frame sid:{}, status:{}", sid, status);

    let mut frame = get_frame(h2c, NGX_HTTP_V2_RST_STREAM_SIZE, NGX_HTTP_V2_RST_STREAM_FRAME, NGX_HTTP_V2_NO_FLAG, sid).ok_or(())?;

    write_uint32(&mut frame.data, status);

    h2c.queue_blocked_frame(frame);
    h2c.out_notify.notify_one();

    Ok(())
}

/// ngx_http_v2_send_goaway
pub fn send_goaway(h2c: &Rc<H2Connection>, status: u32) -> Result<(), ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2 send GOAWAY frame: last sid {}, error {}", h2c.last_sid.get(), status);

    let mut frame = get_frame(h2c, NGX_HTTP_V2_GOAWAY_SIZE, NGX_HTTP_V2_GOAWAY_FRAME, NGX_HTTP_V2_NO_FLAG, 0).ok_or(())?;

    write_uint32(&mut frame.data, h2c.last_sid.get() & 0x7fffffff);
    write_uint32(&mut frame.data, status);

    h2c.queue_blocked_frame(frame);
    h2c.out_notify.notify_one();

    Ok(())
}

/// ngx_http_v2_get_frame: a control frame with its header written. C caps
/// the number of control frames alive at once (reused through a free
/// list) at 10000; beyond that the client is flooding us.
pub fn get_frame(h2c: &Rc<H2Connection>, length: usize, ty: u8, flags: u8, sid: u32) -> Option<OutFrame> {
    if h2c.free_frames.get() > 0 {
        h2c.free_frames.set(h2c.free_frames.get() - 1);
    } else if h2c.frames.get() < 10000 {
        h2c.frames.set(h2c.frames.get() + 1);
    } else {
        ngx_log_error!(NGX_LOG_INFO, h2c.connection.log, None, "http2 flood detected");
        h2c.connection.error.set(true);
        return None;
    }

    let mut data = Vec::with_capacity(NGX_HTTP_V2_FRAME_BUFFER_SIZE);
    write_frame_head(&mut data, length, ty, flags, sid);

    Some(OutFrame { data, sent: 0, handler: FrameHandler::Control, stream: None, length, blocked: false, fin: false })
}
