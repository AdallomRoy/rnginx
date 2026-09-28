//! HTTP/2 request bodies (the request body half of
//! nginx-c/src/http/v2/ngx_http_v2.c).
//!
//! Phase 3 of docs/HTTP2_PLAN.md ports ngx_http_v2_read_request_body,
//! ngx_http_v2_process_request_body and ngx_http_v2_filter_request_body.
//! Until then DATA for a stream whose body is being read is kept with the
//! stream's preread data, so nothing is lost.

use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::log::*;
use ngx_core::ngx_log_error;

use super::*;
use crate::request::{RequestBody, R};

/// ngx_http_v2_process_request_body, called by the state machine for DATA
/// arriving while the request reads its body.
pub fn process_request_body(stream: &Rc<H2Stream>, _r: &R, data: &[u8], _last: bool) {
    stream.preread.borrow_mut().get_or_insert_with(Vec::new).extend_from_slice(data);
    stream.notify.notify_one();
}

/// ngx_http_v2_read_request_body (Phase 3 of docs/HTTP2_PLAN.md).
pub async fn read_request_body(r: &R, _rb: &Rc<RefCell<RequestBody>>) -> i64 {
    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "http2 request bodies are not supported yet");
    crate::NGX_HTTP_INTERNAL_SERVER_ERROR
}
