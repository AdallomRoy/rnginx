//! ngx_http_write_filter_module

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use ngx_core::buf::{Buf, Chain};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::ngx_log_error;

use crate::output::Pass;
use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_write_filter_module");

pub fn write_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_write_filter_module", def, Vec::new())
}

fn init(_cf: &mut Conf) -> ConfResult {
    set_top_body_filter(Rc::new(write_filter));
    Ok(())
}

/// What the sending of r->out goes by, taken once per call
struct Send {
    last: bool,
    limit_rate: usize,
    limit_rate_after: usize,
    sendfile_max_chunk: usize,
    send_timeout: u64,
}

/// ngx_http_write_filter: the output is sent at once, as far as the
/// connection takes it; only output that has to wait for the connection
/// (or for limit_rate) goes on in a boxed future, which sends the rest
/// before it returns.
pub fn write_filter(r: R, mut input: Chain) -> Step {
    let c = &r.connection;
    if c.error.get() {
        return Step::Ready(NGX_ERROR);
    }
    let mut size: i64 = 0;
    let mut flush = false;
    // a flush asked for, not that of a recycled buffer
    let mut flush_buf = false;
    let mut sync = false;
    let mut last = false;
    {
        let out = r.out.borrow();
        for b in out.iter() {
            size += b.buf_size();
            if b.flush || b.recycled {
                flush = true;
            }
            if b.flush {
                flush_buf = true;
            }
            if b.sync {
                sync = true;
            }
            if b.last_buf {
                last = true;
            }
        }
    }
    for b in input.iter() {
        size += b.buf_size();
        if b.flush || b.recycled {
            flush = true;
        }
        if b.flush {
            flush_buf = true;
        }
        if b.sync {
            sync = true;
        }
        if b.last_buf {
            last = true;
        }
    }
    {
        let mut out = r.out.borrow_mut();
        if out.is_empty() {
            // the input's links become r->out
            std::mem::swap(&mut *out, &mut input);
        } else {
            out.append(&mut input);
        }
    }
    free_chain(input);
    http_debug!(r, "http write filter: l:{} f:{} s:{}", last as i32, flush as i32, size);
    let clcf = r.clcf();
    let postpone = *clcf.borrow().postpone_output;
    if !last && !flush && size < postpone as i64 {
        return Step::Ready(NGX_OK);
    }
    if c.write_delayed.get() {
        r.buffered.set(r.buffered.get() | NGX_HTTP_WRITE_BUFFERED);
        return Step::Ready(NGX_AGAIN);
    }
    // an HTTP/2 stream's connection wants empty last/flush chains too
    // (c->need_last_buf / c->need_flush_buf): they end the stream
    let pass_empty = (last && c.need_last_buf.get()) || (flush && c.need_flush_buf.get());
    if size == 0 && !flush && !sync && !pass_empty {
        if last || r.out.borrow().iter().any(|b| b.last_buf) {
            free_out(&r);
            r.buffered.set(r.buffered.get() & !NGX_HTTP_WRITE_BUFFERED);
            r.response_sent.set(true);
            return Step::Ready(NGX_OK);
        }
        if r.out.borrow().is_empty() {
            return Step::Ready(NGX_OK);
        }
    }
    if size == 0 && !flush && sync && !pass_empty {
        // only sync bufs: drop them
        r.out.borrow_mut().retain(|b| b.buf_size() > 0 || b.flush || b.last_buf);
    }
    if size == 0 && !flush && !pass_empty {
        // last_buf only: nothing to write
        if !last {
            return Step::Ready(NGX_OK);
        }
    }

    // limit rate — the _set flag flips on only when someone explicitly
    // sets $limit_rate / $limit_rate_after (rewrite or X-Accel-Limit-Rate).
    // Don't flip it on for a plain config read: after an internal redirect
    // the new location's limit_rate needs to take effect, and caching the
    // old location's value here freezes the wrong value for the rest of
    // the response — see the X-Accel-Redirect check in limit_rate.t.
    let s = {
        let cl = clcf.borrow();
        let limit_rate = if r.limit_rate_set.get() { r.limit_rate.get() } else { crate::script::complex_value_size(&r, &cl.limit_rate, 0) };
        let limit_rate_after = if r.limit_rate_after_set.get() { r.limit_rate_after.get() } else { crate::script::complex_value_size(&r, &cl.limit_rate_after, 0) };
        Send { last, limit_rate, limit_rate_after, sendfile_max_chunk: *cl.sendfile_max_chunk, send_timeout: *cl.send_timeout }
    };
    drop(clcf);
    r.limit_rate.set(s.limit_rate);
    r.limit_rate_after.set(s.limit_rate_after);

    // HTTP/2: queue what the flow control windows allow and let the body
    // producer go on while the output in flight stays below the output
    // buffers, as C does when ngx_http_v2_send_chain returns the rest to
    // r->out and the copy filter reads its next buffer (a recycled buffer
    // flushes, but does not stop it). The remainder joins later output in
    // the same DATA frame. The last buffer, flushes and rate limited output
    // are sent in full below.
    if r.stream.borrow().is_some() && !last && !flush_buf && !sync && s.limit_rate == 0 {
        return Step::boxed(async move {
            match crate::v2::filter::send_nowait(&r).await {
                Err(()) => {
                    r.connection.error.set(true);
                    return NGX_ERROR;
                }
                Ok(unsent) => {
                    if unsent < crate::copy_filter::output_buffers_size(&r) {
                        if r.out.borrow().is_empty() {
                            r.buffered.set(r.buffered.get() & !NGX_HTTP_WRITE_BUFFERED);
                        } else {
                            r.buffered.set(r.buffered.get() | NGX_HTTP_WRITE_BUFFERED);
                        }
                        return NGX_OK;
                    }
                }
            }

            write_loop(r, s, Resume::Iteration).await
        });
    }

    loop {
        match iteration(&r, &s) {
            Iteration::Done(rc) => return Step::Ready(rc),
            Iteration::Next => continue,
            Iteration::Wait(resume) => return Step::boxed(write_loop(r, s, resume)),
        }
    }
}

/// What an iteration of the sending of r->out came to
enum Iteration {
    /// the result of the write filter
    Done(i64),
    /// the output is sent up to the limit of the iteration: the next one
    Next,
    /// it has to wait
    Wait(Resume),
}

/// What the sending of r->out waits for, and goes on with
enum Resume {
    /// nothing: an iteration
    Iteration,
    /// the timer of the write delayed by the last send (c->write->delayed),
    /// then the iteration
    Delayed(Instant),
    /// the limit_rate delay of an iteration, in ms, then the next one
    RateLimited(u64),
    /// the write event: the send of the iteration goes on, `limit` bytes
    /// of it left (0: no limit), `before` the c->sent before it; on TLS
    /// from the pass's result and position, with the iteration's limit
    Send { limit: i64, before: u64, ssl: Option<(bool, ngx_core::event_openssl::SslChainPos)> },
}

/// An iteration of the sending of r->out, without waiting
fn iteration(r: &R, s: &Send) -> Iteration {
    let c = &r.connection;

    // c->write->delayed by the last send: the output waits for the timer
    // (the read event is ngx_http_test_reading meanwhile)
    if let Some(until) = c.write_delay_until.get() {
        if Instant::now() < until {
            return Iteration::Wait(Resume::Delayed(until));
        }

        c.write_delay_until.set(None);
    }

    let mut limit: i64;
    if s.limit_rate > 0 {
        let now = ngx_core::times::time();
        limit = s.limit_rate as i64 * (now - r.start_sec.get() + 1) - (c.sent.get() as i64 - s.limit_rate_after as i64);
        if limit <= 0 {
            c.write_delayed.set(true);
            let delay = (-limit) as u64 * 1000 / s.limit_rate as u64 + 1;
            http_debug!(r, "delayed for {}ms", delay);
            return Iteration::Wait(Resume::RateLimited(delay));
        }
        if s.sendfile_max_chunk > 0 && limit > s.sendfile_max_chunk as i64 {
            limit = s.sendfile_max_chunk as i64;
        }
    } else {
        limit = s.sendfile_max_chunk as i64;
    }

    // c->send_chain(), as far as the connection takes the output now (an
    // HTTP/2 stream's send_chain waits on the stream)
    let before = c.sent.get();
    let mut total: i64 = 0;
    let pass = if r.stream.borrow().is_some() {
        Ok(Pass::Async)
    } else {
        let mut out = std::mem::take(&mut *r.out.borrow_mut());
        let pass = crate::output::send_chain_pass(c, &mut out, limit, &mut total);
        *r.out.borrow_mut() = out;
        pass
    };

    match pass {
        Ok(Pass::Done) => {}
        Ok(Pass::Again) | Ok(Pass::Async) => {
            // what the pass sent counts against the limit of the send
            // (less than the limit here)
            let limit = if limit <= 0 { 0 } else { limit - total };
            return Iteration::Wait(Resume::Send { limit, before, ssl: None });
        }
        Ok(Pass::SslAgain { want_read, pos }) => {
            return Iteration::Wait(Resume::Send { limit, before, ssl: Some((want_read, pos)) });
        }
        Err(e) => return Iteration::Done(send_failed(r, e)),
    }

    match sent(r, s, before) {
        Some(rc) => Iteration::Done(rc),
        None => Iteration::Next,
    }
}

/// After the send of an iteration: the limit_rate delay of the write
/// event, and the result once r->out is all sent (None: the next iteration)
fn sent(r: &R, s: &Send, before: u64) -> Option<i64> {
    let c = &r.connection;

    if s.limit_rate > 0 {
        // delay = (nsent - sent) * 1000 / r->limit_rate, the counts
        // past limit_rate_after
        let lra = s.limit_rate_after as u64;
        let sent = before.saturating_sub(lra);
        let nsent = c.sent.get().saturating_sub(lra);
        let delay = (nsent - sent) * 1000 / s.limit_rate as u64;

        if delay > 0 {
            c.write_delay_until.set(Some(Instant::now() + Duration::from_millis(delay)));
        }
    }
    let remaining: i64 = r.out.borrow().iter().map(|b| b.buf_size()).sum();
    if remaining == 0 {
        // drop special (sync/flush/last) buffers as sent
        free_out(r);
        r.buffered.set(r.buffered.get() & !NGX_HTTP_WRITE_BUFFERED);
        if s.last {
            r.response_sent.set(true);
        }
        return Some(NGX_OK);
    }
    // partial due to sendfile_max_chunk or limit_rate: the next iteration
    None
}

/// r->out sent: its buffers are free (the memory of copy buffers for the
/// next copies)
fn free_out(r: &R) {
    let mut out = std::mem::take(&mut *r.out.borrow_mut());
    for b in out.drain(..) {
        crate::copy_filter::recycle(b);
    }
    free_chain(out);
}

/// The send failed (ngx_writev() and others log the error)
fn send_failed(r: &R, e: std::io::Error) -> i64 {
    let c = &r.connection;
    let en = e.raw_os_error().unwrap_or(0);
    if en == libc::EPIPE || en == libc::ECONNRESET || en == libc::ENOTCONN {
        ngx_log_error!(NGX_LOG_INFO, c.log, Some(en), "writev() failed");
    } else if en != 0 {
        ngx_log_error!(NGX_LOG_ALERT, c.log, Some(en), "writev() failed");
    }
    c.error.set(true);
    NGX_ERROR
}

/// The sending of r->out once it has to wait: the waits, each followed by
/// iterations as long as they need none.
async fn write_loop(r: R, s: Send, mut resume: Resume) -> i64 {
    let c = r.connection.clone();

    loop {
        match resume {
            Resume::Iteration => {}

            Resume::Delayed(until) => {
                c.write_delayed.set(true);

                let closed = {
                    let watch = TestReading::new(&r);
                    tokio::select! {
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(until)) => None,
                        err = watch.closed() => Some(err),
                    }
                };

                c.write_delayed.set(false);

                if let Some(err) = closed {
                    return test_reading_closed(&r, err);
                }

                c.write_delay_until.set(None);
            }

            Resume::RateLimited(delay) => {
                // the write event timer; meanwhile the read event handler is
                // ngx_http_test_reading (ngx_http_set_write_handler)
                let closed = if test_reading_on(&r) {
                    let watch = TestReading::new(&r);
                    let _stream = StreamTestReading::new(&r);

                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(delay)) => None,
                        err = watch.closed() => Some(err),
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    None
                };

                c.write_delayed.set(false);

                if let Some(err) = closed {
                    return test_reading_closed(&r, err);
                }
            }

            Resume::Send { limit, before, ssl } => {
                let mut out = std::mem::take(&mut *r.out.borrow_mut());
                let sent_out = send_out(&r, &mut out, limit, s.send_timeout, ssl).await;
                *r.out.borrow_mut() = out;
                let res = match sent_out {
                    Sent::Done(res) => res,
                    Sent::Closed(err) => return test_reading_closed(&r, err),
                };
                match res {
                    Err(_) => {
                        ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
                        c.timedout.set(true);
                        c.error.set(true);
                        return NGX_ERROR;
                    }
                    Ok(Err(e)) => return send_failed(&r, e),
                    Ok(Ok(_)) => {}
                }
                if let Some(rc) = sent(&r, &s, before) {
                    return rc;
                }
            }
        }

        resume = loop {
            match iteration(&r, &s) {
                Iteration::Done(rc) => return rc,
                Iteration::Next => continue,
                Iteration::Wait(resume) => break resume,
            }
        };
    }
}

/// What c->send_chain() came to.
enum Sent {
    Done(Result<std::io::Result<i64>, tokio::time::error::Elapsed>),
    /// ngx_http_test_reading: the client closed the connection meanwhile,
    /// with this pending socket error
    Closed(i32),
}

/// c->send_chain() within send_timeout. If the write would block, the
/// request waits for the write event (ngx_http_set_write_handler), with
/// ngx_http_test_reading as its read event handler if test_reading_on():
/// the client closing the connection ends the request, before the write
/// fails, as epoll reports the read event of a connection first.
async fn send_out(r: &R, out: &mut Chain, limit: i64, send_timeout: u64, ssl: Option<(bool, ngx_core::event_openssl::SslChainPos)>) -> Sent {
    let h2 = r.stream.borrow().is_some();

    let chain = async {
        if h2 {
            // fc->send_chain = ngx_http_v2_send_chain
            crate::v2::filter::send_chain(r, out, limit).await
        } else if let Some((want_read, pos)) = ssl {
            // the TLS pass made at once goes on
            crate::output::ssl_send_chain_from(&r.connection, out, limit, want_read, pos).await
        } else {
            crate::output::send_chain(&r.connection, out, limit).await
        }
    };

    let send = tokio::time::timeout(Duration::from_millis(send_timeout), chain);
    tokio::pin!(send);

    if let Some(res) = poll_once(&mut send).await {
        return Sent::Done(res);
    }

    if !test_reading_on(r) {
        return Sent::Done(send.await);
    }

    if h2 {
        let _stream = StreamTestReading::new(r);
        return Sent::Done(send.await);
    }

    let watch = TestReading::new(r);

    tokio::select! {
        biased;
        err = watch.closed() => Sent::Closed(err),
        res = &mut send => Sent::Done(res),
    }
}

/// The output of the future if it is ready without waiting.
async fn poll_once<F: std::future::Future + Unpin>(f: &mut F) -> Option<F::Output> {
    std::future::poll_fn(|cx| match std::pin::Pin::new(&mut *f).poll(cx) {
        std::task::Poll::Ready(v) => std::task::Poll::Ready(Some(v)),
        std::task::Poll::Pending => std::task::Poll::Ready(None),
    })
    .await
}

/// While its output waits, the read event handler of the request the
/// connection's events go to (c->data) is ngx_http_test_reading
/// (ngx_http_set_write_handler), unless it discards the request body
/// (ngx_http_discarded_request_body_handler), or its upstream has the
/// handler until it is finalized (ngx_http_upstream_rd_check_broken_connection,
/// or none).
fn test_reading_on(r: &R) -> bool {
    let a = crate::postpone_filter::connection_data(r);

    !a.discard_body.get() && !a.upstream_handler.get()
}

/// r->read_event_handler = ngx_http_test_reading on an HTTP/2 stream, for
/// as long as it lives: the fake connection's read event runs it (see
/// crate::v2::stream::terminate_request_now).
pub(crate) struct StreamTestReading(Option<Rc<crate::v2::H2Stream>>);

impl StreamTestReading {
    pub(crate) fn new(r: &R) -> StreamTestReading {
        let stream = crate::v2::stream::request_stream(r);

        if let Some(s) = &stream {
            *s.test_reading.borrow_mut() = Some(Rc::downgrade(r));
        }

        StreamTestReading(stream)
    }
}

impl Drop for StreamTestReading {
    fn drop(&mut self) {
        if let Some(s) = &self.0 {
            s.test_reading.borrow_mut().take();
        }
    }
}

/// ngx_http_test_reading, as the Linux build runs it (epoll with
/// EPOLLRDHUP): the client closed its side of an HTTP/1.x connection
/// (rev->pending_eof), on the read event of the connection, as in C. Its
/// readiness is shared with the request's readers (of pipelined requests),
/// so it is not cleared while there is data to read: once the client sends
/// data meanwhile, a duplicate of the client socket, whose readiness is its
/// own, waits for the end of the stream. An HTTP/2 stream is not tested.
pub(crate) struct TestReading {
    /// the connection of an HTTP/1.x request
    conn: Option<Rc<ngx_core::connection::Connection>>,
    /// the duplicate, made when data came from the client
    dup: RefCell<Option<Rc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>>>,
    /// the stream of an HTTP/3 request: ngx_http_test_reading tests
    /// rev->error
    quic: Option<(Rc<ngx_core::connection::Connection>, Rc<ngx_core::quic::QuicStream>)>,
}

impl TestReading {
    pub(crate) fn new(r: &R) -> TestReading {
        if let Some(qs) = ngx_core::quic::streams::ngx_quic_stream(&r.connection) {
            return TestReading { conn: None, dup: RefCell::new(None), quic: Some((r.connection.clone(), qs)) };
        }

        if r.stream.borrow().is_some() || r.connection.fd.get() < 0 {
            return TestReading { conn: None, dup: RefCell::new(None), quic: None };
        }

        TestReading { conn: Some(r.connection.clone()), dup: RefCell::new(None), quic: None }
    }

    /// Resolves with the pending socket error (0 if none) when the client
    /// has closed the connection (rev->pending_eof).
    pub(crate) async fn closed(&self) -> i32 {
        if let Some((c, qs)) = &self.quic {
            ngx_core::quic::streams::wait_stream(qs, || qs.read_error.get()).await;
            c.error.set(true);
            return 0;
        }

        let c = match &self.conn {
            Some(c) => c,
            None => return std::future::pending().await,
        };

        if self.dup.borrow().is_none() {
            loop {
                match c.read_event().await {
                    // EPOLLRDHUP: ev->pending_eof
                    Ok(ready) if ready.is_read_closed() => return conn_so_error(c),
                    Ok(_) => {}
                    Err(_) => return std::future::pending().await,
                }

                // a read event without the end of the stream: data from the
                // client, or the readiness a read of a whole buffer left
                match peek(c.fd.get()) {
                    // nothing to read: the readiness is cleared, as a read
                    // that finds the socket drained does (rev->ready = 0)
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => c.read_drained(),
                    Ok(n) if n > 0 => break,
                    _ => return conn_so_error(c),
                }
            }

            // data from the client: the readiness stays for its readers,
            // the end of the stream is waited for on a duplicate (owned, and
            // closed, by the OwnedFd)
            let owned = match ngx_core::fd::get(c.fd.get()).map(|s| rustix::io::fcntl_dupfd_cloexec(&s, 0)) {
                Ok(Ok(owned)) => owned,
                _ => return std::future::pending().await,
            };

            match tokio::io::unix::AsyncFd::with_interest(owned, tokio::io::Interest::READABLE) {
                Ok(a) => *self.dup.borrow_mut() = Some(Rc::new(a)),
                Err(_) => return std::future::pending().await,
            }
        }

        let afd = match self.dup.borrow().clone() {
            Some(a) => a,
            None => return std::future::pending().await,
        };

        loop {
            let mut guard = match afd.readable().await {
                Ok(g) => g,
                Err(_) => return std::future::pending().await,
            };

            if guard.ready().is_read_closed() {
                break;
            }

            guard.clear_ready();
        }

        so_error(afd.get_ref())
    }
}

/// recv(MSG_PEEK) of a byte, without waiting
fn peek(fd: std::os::fd::RawFd) -> std::io::Result<usize> {
    let mut b = [0u8; 1];

    nix::sys::socket::recv(fd, &mut b, nix::sys::socket::MsgFlags::MSG_PEEK | nix::sys::socket::MsgFlags::MSG_DONTWAIT).map_err(std::io::Error::from)
}

/// getsockopt(SO_ERROR): the pending error of the socket, if any
fn so_error(fd: impl std::os::fd::AsFd) -> i32 {
    match rustix::net::sockopt::socket_error(fd) {
        Ok(Err(err)) => err.raw_os_error(),
        _ => 0,
    }
}

/// so_error() of a connection's socket
fn conn_so_error(c: &ngx_core::connection::Connection) -> i32 {
    ngx_core::fd::get(c.fd.get()).map(so_error).unwrap_or(0)
}

/// The "closed:" part of ngx_http_test_reading: the request is finalized
/// with NGX_HTTP_CLIENT_CLOSED_REQUEST (ngx_http_terminate_request sets
/// the status if nothing was sent).
pub(crate) fn test_reading_closed(r: &R, err: i32) -> i64 {
    let c = &r.connection;

    c.read_eof.set(true);
    c.error.set(true);

    if let Some(sc) = c.ssl.borrow().as_ref() {
        sc.no_send_shutdown.set(true);
    }

    ngx_log_error!(NGX_LOG_INFO, c.log, if err != 0 { Some(err) } else { None }, "client prematurely closed connection");

    let m = r.main();

    if m.headers_out.borrow().status == 0 || m.connection.sent.get() == 0 {
        m.headers_out.borrow_mut().status = NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }

    NGX_ERROR
}

/// Force out any pending buffered output (called at request end).
pub fn flush(r: &R) -> Step {
    let mut chain = alloc_chain();
    let mut b = Buf::special();
    b.flush = true;
    chain.push_back(b);
    write_filter(r.clone(), chain)
}

use ngx_core::conf::{Conf, ConfResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poll_once() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

        rt.block_on(async {
            let mut ready = std::pin::pin!(async { 7 });
            assert_eq!(poll_once(&mut ready).await, Some(7));

            // a write that would block: polled again later
            let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
            let mut pending = std::pin::pin!(rx);
            assert!(poll_once(&mut pending).await.is_none());
            tx.send(3).unwrap();
            assert_eq!(pending.await.unwrap(), 3);
        });
    }
}
