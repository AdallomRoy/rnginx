//! HTTP/2 request bodies (the request body half of
//! nginx-c/src/http/v2/ngx_http_v2.c).
//!
//! The state machine hands DATA of a stream whose body is being read to
//! process_request_body(), which queues it on the stream and posts a read
//! event, delivered after the read batch as C posts fc->read. The request's
//! task then runs ngx_http_v2_read_request_body and, on each read event,
//! ngx_http_v2_read_client_request_body_handler: the data goes through
//! rb->buf (ngx_http_v2_process_request_body) and into the request body
//! filters (ngx_http_v2_filter_request_body). An unbuffered body is set up
//! the same way; then the upstream calls read_unbuffered_request_body()
//! whenever it can take more data.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::buf::{Buf, Chain};
use ngx_core::log::*;
use ngx_core::{ngx_log_debug, ngx_log_error};

use super::connection::send_window_update;
use super::stream::{request_stream, srv_conf};
use super::*;
use crate::request::{RequestBody, R};
use crate::*;

/// ngx_http_v2_process_request_body as called from ngx_http_v2_state_read_data:
/// queue the DATA payload for the request and post its read event.
pub fn process_request_body(stream: &Rc<H2Stream>, _r: &R, data: &[u8], _last: bool) {
    stream.body_pending.borrow_mut().extend_from_slice(data);
    post_read(&stream.connection, stream);
}

/// ngx_post_event(fc->read): run once the current read batch is processed.
fn post_read(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>) {
    let mut posted = h2c.posted_reads.borrow_mut();
    if !posted.iter().any(|s| Rc::ptr_eq(s, stream)) {
        posted.push(stream.clone());
    }
}

/// ngx_http_v2_read_request_body, then the read event handler until the
/// body is complete (NGX_OK) or failed (an HTTP status). An unbuffered body
/// returns NGX_AGAIN once set up.
pub async fn read_request_body(r: &R, rb: &Rc<RefCell<RequestBody>>) -> i64 {
    let stream = match request_stream(r) {
        Some(s) => s,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    let h2c = stream.connection.clone();

    if stream.skip_data.get() {
        r.request_body_no_buffering.set(false);
        return NGX_OK;
    }

    rb.borrow_mut().rest = 1;

    let h2scf = srv_conf(r);
    let (client_body_buffer_size, client_body_timeout) = {
        let clcf = r.clcf();
        let c = clcf.borrow();
        (*c.client_body_buffer_size, *c.client_body_timeout)
    };

    let content_length = r.headers_in.borrow().content_length_n;

    let mut len = if content_length < 0 || content_length > client_body_buffer_size as i64 {
        client_body_buffer_size
    } else {
        content_length as usize + 1
    };

    let filter_need_buffering = rb.borrow().filter_need_buffering;

    if r.request_body_no_buffering.get() || filter_need_buffering {
        // room for data up to the stream's initial window, at least until
        // that window is exhausted
        if len < h2scf.preread_size {
            len = h2scf.preread_size;
        }

        if len > NGX_HTTP_V2_MAX_WINDOW {
            len = NGX_HTTP_V2_MAX_WINDOW;
        }
    }

    // rb->buf
    stream.body_cap.set(len);
    rb.borrow_mut().buf_size = len;
    stream.body_buf.borrow_mut().clear();
    stream.body_last.set(0);
    rb.borrow_mut().buf_last = stream.body_last.get();

    let preread = stream.preread.borrow_mut().take();

    let rc;

    if stream.in_closed.get() {
        if !filter_need_buffering {
            r.request_body_no_buffering.set(false);
        }

        let data = preread.unwrap_or_default();
        rc = process(r, &stream, rb, &data, true, false).await;

        if rc != NGX_AGAIN {
            return finish(r, rb, rc);
        }
    } else {
        let had_preread = preread.is_some();

        if let Some(data) = preread {
            let rc = process(r, &stream, rb, &data, false, false).await;

            if rc != NGX_OK && rc != NGX_AGAIN {
                stream.skip_data.set(true);
                return rc;
            }
        }

        let size = if r.request_body_no_buffering.get() || filter_need_buffering {
            len.saturating_sub(h2scf.preread_size)
        } else {
            stream.no_flow_control.set(true);
            NGX_HTTP_V2_MAX_WINDOW - stream.recv_window.get()
        };

        if size > 0 {
            if send_window_update(&h2c, stream.node.borrow().id.get(), size).is_err() {
                stream.skip_data.set(true);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            stream.recv_window.set(stream.recv_window.get() + size);
        }

        let _ = had_preread;
    }

    if r.request_body_no_buffering.get() {
        // the upstream reads the rest: ngx_http_read_unbuffered_request_body
        return NGX_AGAIN;
    }

    // ngx_http_v2_read_client_request_body_handler on each read event
    loop {
        let pending = std::mem::take(&mut *stream.body_pending.borrow_mut());

        if !pending.is_empty() || stream.in_closed.get() || !stream.body_buf.borrow().is_empty() {
            let rc = process(r, &stream, rb, &pending, stream.in_closed.get(), true).await;

            if rc != NGX_OK && rc != NGX_AGAIN {
                stream.skip_data.set(true);
                return rc;
            }

            if rc == NGX_OK {
                return finish(r, rb, rc);
            }
        }

        let fc = stream.fc.clone();

        let woken = tokio::time::timeout(Duration::from_millis(client_body_timeout), stream.notify.notified()).await;

        if woken.is_err() {
            ngx_log_error!(NGX_LOG_INFO, fc.log, Some(libc::ETIMEDOUT), "client timed out");

            fc.timedout.set(true);
            stream.skip_data.set(true);

            return NGX_HTTP_REQUEST_TIME_OUT;
        }

        if fc.error.get() {
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client prematurely closed stream");

            stream.skip_data.set(true);

            return NGX_HTTP_CLIENT_CLOSED_REQUEST;
        }
    }
}

/// A complete body (NGX_OK) is read as buffered: the caller gets all of
/// it in rb->bufs (ngx_http_read_client_request_body at done).
fn finish(r: &R, _rb: &Rc<RefCell<RequestBody>>, rc: i64) -> i64 {
    if rc != NGX_OK {
        return rc;
    }

    r.request_body_no_buffering.set(false);

    NGX_OK
}

/// ngx_http_v2_process_request_body: copy `data` into rb->buf, passing the
/// buffer to the request body filters when it fills up (and at the end or
/// on `flush`). NGX_AGAIN until the body is complete.
async fn process(r: &R, stream: &Rc<H2Stream>, rb: &Rc<RefCell<RequestBody>>, data: &[u8], last: bool, flush: bool) -> i64 {
    let fc = &stream.fc;

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 process request body");

    if data.is_empty() && !last && !flush {
        return NGX_AGAIN;
    }

    let cap = stream.body_cap.get();
    let mut pos = 0;
    let mut size = data.len();

    loop {
        loop {
            if stream.body_last.get() == cap && size > 0 {
                if r.request_body_no_buffering.get() {
                    // should never happen due to flow control
                    ngx_log_error!(NGX_LOG_ALERT, fc.log, None, "no space in http2 body buffer");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                // update chains
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 body update chains");

                let rc = filter_request_body(r, stream, rb).await;

                if rc != NGX_OK {
                    return rc;
                }

                stream.body_last.set(0);
                rb.borrow_mut().buf_last = stream.body_last.get();
            }

            // copy body data to the buffer
            let n = (cap - stream.body_last.get()).min(size);

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 request body recv {}", n);

            if n > 0 {
                stream.body_buf.borrow_mut().extend_from_slice(&data[pos..pos + n]);
                stream.body_last.set(stream.body_last.get() + n);
                rb.borrow_mut().buf_last = stream.body_last.get();
                pos += n;
                size -= n;
            }

            if size == 0 && last {
                rb.borrow_mut().rest = 0;
            }

            if size == 0 {
                break;
            }
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 request body rest {}", rb.borrow().rest);

        if flush {
            let rc = filter_request_body(r, stream, rb).await;

            if rc != NGX_OK {
                return rc;
            }
        }

        {
            let b = rb.borrow();
            if b.rest == 0 && b.last_saved {
                break;
            }
        }

        if size == 0 {
            return NGX_AGAIN;
        }
    }

    if r.request_body_no_buffering.get() {
        return NGX_OK;
    }

    if r.headers_in.borrow().chunked {
        let received = rb.borrow().received;
        r.headers_in.borrow_mut().content_length_n = received;
    }

    NGX_OK
}

/// ngx_http_v2_read_unbuffered_request_body: pass on the DATA received so
/// far and, once the upstream has written out everything passed before (the
/// caller sends rb->bufs before it calls again: rb->busy is what this call
/// passed on), rewind rb->buf and open the stream window to its size.
/// NGX_OK when the body is complete, NGX_AGAIN for more.
pub async fn read_unbuffered_request_body(r: &R) -> i64 {
    let stream = match request_stream(r) {
        Some(s) => s,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    let rb = match r.request_body.borrow().clone() {
        Some(rb) => rb,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    let fc = stream.fc.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, fc.log, "http2 read unbuffered request body");

    if fc.error.get() {
        stream.skip_data.set(true);
        return NGX_HTTP_BAD_REQUEST;
    }

    let pending = std::mem::take(&mut *stream.body_pending.borrow_mut());

    let rc = process(r, &stream, &rb, &pending, stream.in_closed.get(), true).await;

    if rc != NGX_OK && rc != NGX_AGAIN {
        stream.skip_data.set(true);
        return rc;
    }

    if rc == NGX_OK {
        return NGX_OK;
    }

    if rb.borrow().rest == 0 {
        return NGX_AGAIN;
    }

    if !rb.borrow().bufs.is_empty() {
        return NGX_AGAIN;
    }

    stream.body_last.set(0);
    rb.borrow_mut().buf_last = stream.body_last.get();

    let h2c = stream.connection.clone();

    let mut window = stream.body_cap.get();

    let current = h2c.state.stream.borrow().as_ref().is_some_and(|s| Rc::ptr_eq(s, &stream));
    if current {
        window -= h2c.state.length.get();
    }

    let recv_window = stream.recv_window.get();

    if window <= recv_window {
        if window < recv_window {
            ngx_log_error!(NGX_LOG_ALERT, fc.log, None, "http2 negative window update");
            stream.skip_data.set(true);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_AGAIN;
    }

    // queued for the driver, which sends it (ngx_http_v2_send_output_queue)
    if send_window_update(&h2c, stream.node.borrow().id.get(), window - recv_window).is_err() {
        stream.skip_data.set(true);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    stream.recv_window.set(window);

    NGX_AGAIN
}

/// ngx_http_v2_filter_request_body: pass rb->buf to the request body
/// filters, checking the received length against Content-Length or
/// client_max_body_size, and marking the last buffer.
async fn filter_request_body(r: &R, stream: &Rc<H2Stream>, rb: &Rc<RefCell<RequestBody>>) -> i64 {
    let data = std::mem::take(&mut *stream.body_buf.borrow_mut());

    let mut chain = Chain::new();

    let skip_buf = {
        let b = rb.borrow();
        data.is_empty() && (b.rest != 0 || b.last_sent)
    };

    if !skip_buf {
        let mut b = Buf::special();
        b.sync = false;

        if !data.is_empty() {
            r.request_length.set(r.request_length.get() + data.len() as i64);

            let received = {
                let mut rbm = rb.borrow_mut();
                rbm.received += data.len() as i64;
                rbm.received
            };

            let content_length = r.headers_in.borrow().content_length_n;

            if content_length != -1 {
                if received > content_length {
                    ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client intended to send body data larger than declared");
                    return NGX_HTTP_BAD_REQUEST;
                }
            } else {
                let max = *r.clcf().borrow().client_max_body_size;

                if max != 0 && received > max {
                    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client intended to send too large chunked body: {} bytes", received);
                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }
            }

            b = Buf::from_vec(data);
            b.temporary = true;
        }

        let rest = rb.borrow().rest;

        if rest == 0 {
            let (received, content_length) = (rb.borrow().received, r.headers_in.borrow().content_length_n);

            if content_length != -1 && content_length != received {
                ngx_log_error!(
                    NGX_LOG_INFO,
                    r.connection.log,
                    None,
                    "client prematurely closed stream: only {} out of {} bytes of request body received",
                    received,
                    content_length
                );
                return NGX_HTTP_BAD_REQUEST;
            }

            b.last_buf = true;
            rb.borrow_mut().last_sent = true;
        }

        b.flush = r.request_body_no_buffering.get();

        chain.push_back(b);
    }

    let f = top_request_body_filter();
    f(r.clone(), chain).await
}
