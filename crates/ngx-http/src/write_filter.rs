//! ngx_http_write_filter_module

use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::ngx_log_error;

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_write_filter_module");

pub fn write_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_write_filter_module", def, Vec::new())
}

fn init(_cf: &mut Conf) -> ConfResult {
    set_top_body_filter(Rc::new(|r, chain| Box::pin(write_filter(r, chain))));
    Ok(())
}

/// ngx_http_write_filter
pub async fn write_filter(r: R, mut input: Chain) -> i64 {
    let c = r.connection.clone();
    if c.error.get() {
        return NGX_ERROR;
    }
    let mut size: i64 = 0;
    let mut flush = false;
    let mut sync = false;
    let mut last = false;
    {
        let out = r.out.borrow();
        for b in out.iter() {
            size += b.buf_size();
            if b.flush || b.recycled {
                flush = true;
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
        if b.in_memory() && b.last > b.pos && b.pos > 0 {
            // fine
        }
        size += b.buf_size();
        if b.flush || b.recycled {
            flush = true;
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
        out.append(&mut input);
    }
    http_debug!(r, "http write filter: l:{} f:{} s:{}", last as i32, flush as i32, size);
    let clcf = r.clcf();
    let postpone = *clcf.borrow().postpone_output;
    if !last && !flush && size < postpone as i64 {
        return NGX_OK;
    }
    if c.write_delayed.get() {
        r.buffered.set(r.buffered.get() | NGX_HTTP_WRITE_BUFFERED);
        return NGX_AGAIN;
    }
    if size == 0 && !(c.buffer.borrow().is_empty() == false) && !flush && !sync {
        // nothing to send
    }
    // an HTTP/2 stream's connection wants empty last/flush chains too
    // (c->need_last_buf / c->need_flush_buf): they end the stream
    let pass_empty = (last && c.need_last_buf.get()) || (flush && c.need_flush_buf.get());
    if size == 0 && !flush && !sync && !pass_empty {
        if last || r.out.borrow().iter().any(|b| b.last_buf) {
            r.out.borrow_mut().clear();
            r.buffered.set(r.buffered.get() & !NGX_HTTP_WRITE_BUFFERED);
            return NGX_OK;
        }
        if r.out.borrow().is_empty() {
            return NGX_OK;
        }
    }
    if size == 0 && !flush && sync && !pass_empty {
        // only sync bufs: drop them
        r.out.borrow_mut().retain(|b| b.buf_size() > 0 || b.flush || b.last_buf);
    }
    if size == 0 && !flush && !pass_empty {
        // last_buf only: nothing to write
        if !last {
            return NGX_OK;
        }
    }

    // limit rate — the _set flag flips on only when someone explicitly
    // sets $limit_rate / $limit_rate_after (rewrite or X-Accel-Limit-Rate).
    // Don't flip it on for a plain config read: after an internal redirect
    // the new location's limit_rate needs to take effect, and caching the
    // old location's value here freezes the wrong value for the rest of
    // the response — see the X-Accel-Redirect check in limit_rate.t.
    let (limit_rate, limit_rate_after) = {
        let cl = clcf.borrow();
        let lr = if r.limit_rate_set.get() { r.limit_rate.get() } else { crate::script::complex_value_size(&r, &cl.limit_rate, 0) };
        let lra = if r.limit_rate_after_set.get() { r.limit_rate_after.get() } else { crate::script::complex_value_size(&r, &cl.limit_rate_after, 0) };
        (lr, lra)
    };
    r.limit_rate.set(limit_rate);
    r.limit_rate_after.set(limit_rate_after);
    let sendfile_max_chunk = *clcf.borrow().sendfile_max_chunk;
    let send_timeout = *clcf.borrow().send_timeout;

    // HTTP/2: queue what the flow control windows allow and let the body
    // producer go on while the output in flight stays below the output
    // buffers, as C does when ngx_http_v2_send_chain returns the rest to
    // r->out and the copy filter reads its next buffer. The remainder joins
    // later output in the same DATA frame. The last buffer, flushes and
    // rate limited output are sent in full below.
    if r.stream.borrow().is_some() && !last && !flush && !sync && limit_rate == 0 {
        match crate::v2::filter::send_nowait(&r).await {
            Err(()) => {
                c.error.set(true);
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
    }

    loop {
        // c->write->delayed by the last send: the output waits for the
        // timer (the read event is ngx_http_test_reading meanwhile)
        if let Some(until) = c.write_delay_until.get() {
            if std::time::Instant::now() < until {
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
            }

            c.write_delay_until.set(None);
        }

        let mut limit: i64;
        if limit_rate > 0 {
            let now = ngx_core::times::time();
            limit = limit_rate as i64 * (now - r.start_sec.get() + 1) - (c.sent.get() as i64 - limit_rate_after as i64);
            if limit <= 0 {
                c.write_delayed.set(true);
                let delay = (-limit) as u64 * 1000 / limit_rate as u64 + 1;
                http_debug!(r, "delayed for {}ms", delay);

                // the write event timer; meanwhile the read event handler is
                // ngx_http_test_reading (ngx_http_set_write_handler)
                let closed = {
                    let watch = TestReading::new(&r);
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(delay)) => None,
                        err = watch.closed() => Some(err),
                    }
                };

                c.write_delayed.set(false);

                if let Some(err) = closed {
                    return test_reading_closed(&r, err);
                }

                continue;
            }
            if sendfile_max_chunk > 0 && limit > sendfile_max_chunk as i64 {
                limit = sendfile_max_chunk as i64;
            }
        } else {
            limit = sendfile_max_chunk as i64;
        }
        let mut out = std::mem::take(&mut *r.out.borrow_mut());
        let before = c.sent.get();
        let res = if r.stream.borrow().is_some() {
            // fc->send_chain = ngx_http_v2_send_chain
            tokio::time::timeout(std::time::Duration::from_millis(send_timeout), crate::v2::filter::send_chain(&r, &mut out, limit)).await
        } else {
            tokio::time::timeout(std::time::Duration::from_millis(send_timeout), crate::output::send_chain(&c, &mut out, limit)).await
        };
        let sent_now = c.sent.get() - before;
        *r.out.borrow_mut() = out;
        match res {
            Err(_) => {
                ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "client timed out");
                c.timedout.set(true);
                c.error.set(true);
                return NGX_ERROR;
            }
            Ok(Err(e)) => {
                let en = e.raw_os_error().unwrap_or(0);
                if en == libc::EPIPE || en == libc::ECONNRESET || en == libc::ENOTCONN {
                    ngx_log_error!(NGX_LOG_INFO, c.log, Some(en), "writev() failed");
                } else if en != 0 {
                    ngx_log_error!(NGX_LOG_ALERT, c.log, Some(en), "writev() failed");
                }
                c.error.set(true);
                return NGX_ERROR;
            }
            Ok(Ok(_)) => {}
        }
        if limit_rate > 0 {
            // delay = (nsent - sent) * 1000 / r->limit_rate, the counts
            // past limit_rate_after
            let lra = limit_rate_after as u64;
            let sent = before.saturating_sub(lra);
            let nsent = (before + sent_now).saturating_sub(lra);
            let delay = (nsent - sent) * 1000 / limit_rate as u64;

            if delay > 0 {
                c.write_delay_until.set(Some(std::time::Instant::now() + std::time::Duration::from_millis(delay)));
            }
        }
        let remaining: i64 = r.out.borrow().iter().map(|b| b.buf_size()).sum();
        if remaining == 0 {
            // drop special (sync/flush/last) buffers as sent
            r.out.borrow_mut().clear();
            r.buffered.set(r.buffered.get() & !NGX_HTTP_WRITE_BUFFERED);
            return NGX_OK;
        }
        if limit_rate > 0 {
            continue;
        }
        // partial due to sendfile_max_chunk: keep looping
    }
}

/// ngx_http_test_reading, as the Linux build runs it (epoll with
/// EPOLLRDHUP), on a duplicate of the client socket, so that the readiness
/// of the connection itself (pipelined requests) is not disturbed: the
/// client closed its side of an HTTP/1.x connection. An HTTP/2 stream is
/// not tested.
pub(crate) struct TestReading {
    afd: Option<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
}

impl TestReading {
    pub(crate) fn new(r: &R) -> TestReading {
        use std::os::fd::FromRawFd;

        if r.stream.borrow().is_some() || r.connection.fd.get() < 0 {
            return TestReading { afd: None };
        }

        // SAFETY: dup() of the connection's open socket, owned (and
        // closed) by the OwnedFd
        let dup = unsafe { libc::dup(r.connection.fd.get()) };

        if dup < 0 {
            return TestReading { afd: None };
        }

        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup) };

        TestReading { afd: tokio::io::unix::AsyncFd::with_interest(owned, tokio::io::Interest::READABLE).ok() }
    }

    /// Resolves with the pending socket error (0 if none) when the client
    /// has closed the connection (rev->pending_eof).
    pub(crate) async fn closed(&self) -> i32 {
        use std::os::fd::AsRawFd;

        let afd = match &self.afd {
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

        // getsockopt(SO_ERROR): a pending error, if any
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

        // SAFETY: err and len are valid for an int to be written
        unsafe {
            libc::getsockopt(afd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut libc::c_int as *mut libc::c_void, &mut len);
        }

        err
    }
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
pub async fn flush(r: &R) -> i64 {
    let mut chain = Chain::new();
    let mut b = Buf::special();
    b.flush = true;
    chain.push_back(b);
    write_filter(r.clone(), chain).await
}

use ngx_core::conf::{Conf, ConfResult};
