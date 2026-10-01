//! HTTP/3 — port of nginx-c/src/http/v3/.
//!
//! This file holds ngx_http_v3.h and ngx_http_v3.c (the session of a QUIC
//! connection). The QUIC connection runs in ngx_core::quic; its streams
//! are connections of their own, and each runs in a task: the request
//! streams (request.rs) through the HTTP request pipeline, the
//! unidirectional ones (uni.rs) parsing their instructions. The session
//! (ngx_http_v3_session_t) is kept with the http connection of the QUIC
//! connection (c->data in C).

pub mod encode;
pub mod filter;
pub mod module;
pub mod parse;
pub mod request;
pub mod table;
pub mod uni;

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use ngx_core::connection::{Connection, PoolCleanup};
use ngx_core::log::*;
use ngx_core::quic::QEvent;
use ngx_core::rc::*;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::request::HttpConnection;

pub const NGX_HTTP_V3_ALPN_PROTO: &[u8] = b"\x02h3";
pub const NGX_HTTP_V3_HQ_ALPN_PROTO: &[u8] = b"\x0Ahq-interop";
pub const NGX_HTTP_V3_HQ_PROTO: &[u8] = b"hq-interop";

pub const NGX_HTTP_V3_VARLEN_INT_LEN: usize = 8;
pub const NGX_HTTP_V3_PREFIX_INT_LEN: usize = 11;

pub const NGX_HTTP_V3_STREAM_CONTROL: u64 = 0x00;
pub const NGX_HTTP_V3_STREAM_PUSH: u64 = 0x01;
pub const NGX_HTTP_V3_STREAM_ENCODER: u64 = 0x02;
pub const NGX_HTTP_V3_STREAM_DECODER: u64 = 0x03;

pub const NGX_HTTP_V3_FRAME_DATA: u64 = 0x00;
pub const NGX_HTTP_V3_FRAME_HEADERS: u64 = 0x01;
pub const NGX_HTTP_V3_FRAME_CANCEL_PUSH: u64 = 0x03;
pub const NGX_HTTP_V3_FRAME_SETTINGS: u64 = 0x04;
pub const NGX_HTTP_V3_FRAME_PUSH_PROMISE: u64 = 0x05;
pub const NGX_HTTP_V3_FRAME_GOAWAY: u64 = 0x07;
pub const NGX_HTTP_V3_FRAME_MAX_PUSH_ID: u64 = 0x0d;

pub const NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const NGX_HTTP_V3_PARAM_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const NGX_HTTP_V3_PARAM_BLOCKED_STREAMS: u64 = 0x07;

pub const NGX_HTTP_V3_MAX_TABLE_CAPACITY: usize = 4096;

pub const NGX_HTTP_V3_STREAM_CLIENT_CONTROL: usize = 0;
pub const NGX_HTTP_V3_STREAM_SERVER_CONTROL: usize = 1;
pub const NGX_HTTP_V3_STREAM_CLIENT_ENCODER: usize = 2;
pub const NGX_HTTP_V3_STREAM_SERVER_ENCODER: usize = 3;
pub const NGX_HTTP_V3_STREAM_CLIENT_DECODER: usize = 4;
pub const NGX_HTTP_V3_STREAM_SERVER_DECODER: usize = 5;
pub const NGX_HTTP_V3_MAX_KNOWN_STREAM: usize = 6;
pub const NGX_HTTP_V3_MAX_UNI_STREAMS: u64 = 3;

/* HTTP/3 errors */
pub const NGX_HTTP_V3_ERR_NO_ERROR: u64 = 0x100;
pub const NGX_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
pub const NGX_HTTP_V3_ERR_INTERNAL_ERROR: u64 = 0x102;
pub const NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR: u64 = 0x103;
pub const NGX_HTTP_V3_ERR_CLOSED_CRITICAL_STREAM: u64 = 0x104;
pub const NGX_HTTP_V3_ERR_FRAME_UNEXPECTED: u64 = 0x105;
pub const NGX_HTTP_V3_ERR_FRAME_ERROR: u64 = 0x106;
pub const NGX_HTTP_V3_ERR_EXCESSIVE_LOAD: u64 = 0x107;
pub const NGX_HTTP_V3_ERR_ID_ERROR: u64 = 0x108;
pub const NGX_HTTP_V3_ERR_SETTINGS_ERROR: u64 = 0x109;
pub const NGX_HTTP_V3_ERR_MISSING_SETTINGS: u64 = 0x10a;
pub const NGX_HTTP_V3_ERR_REQUEST_REJECTED: u64 = 0x10b;
pub const NGX_HTTP_V3_ERR_REQUEST_CANCELLED: u64 = 0x10c;
pub const NGX_HTTP_V3_ERR_REQUEST_INCOMPLETE: u64 = 0x10d;
pub const NGX_HTTP_V3_ERR_CONNECT_ERROR: u64 = 0x10f;
pub const NGX_HTTP_V3_ERR_VERSION_FALLBACK: u64 = 0x110;

/* QPACK errors */
pub const NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED: u64 = 0x200;
pub const NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR: u64 = 0x201;
pub const NGX_HTTP_V3_ERR_DECODER_STREAM_ERROR: u64 = 0x202;

/// ngx_http_v3_session_t
pub struct H3Session {
    pub http_connection: Rc<HttpConnection>,
    /// the QUIC connection
    pub connection: Weak<Connection>,

    pub table: RefCell<table::DynamicTable>,
    /// table.send_insert_count
    pub send_insert_count: Rc<QEvent>,

    pub keepalive: Rc<QEvent>,
    pub nrequests: Cell<u64>,

    /// the streams blocked on the dynamic table (their connections)
    pub blocked: RefCell<Vec<Weak<Connection>>>,
    pub nblocked: Cell<u64>,

    pub next_request_id: Cell<u64>,

    pub total_bytes: Cell<i64>,
    pub payload_bytes: Cell<i64>,

    pub goaway: Cell<bool>,
    pub hq: Cell<bool>,
    pub created_streams: Cell<u32>,

    pub known_streams: RefCell<[Option<Weak<Connection>>; NGX_HTTP_V3_MAX_KNOWN_STREAM]>,
}

impl H3Session {
    /// h3c->known_streams[index]
    pub fn known_stream(&self, index: usize) -> Option<Rc<Connection>> {
        self.known_streams.borrow()[index].as_ref().and_then(|w| w.upgrade())
    }
}

/// c->data of an http connection
pub fn http_connection_of(c: &Connection) -> Option<Rc<HttpConnection>> {
    let data = c.data.borrow().clone()?;
    data.downcast::<HttpConnection>().ok()
}

/// c->quic ? c->quic->parent : c
pub fn quic_parent(c: &Rc<Connection>) -> Option<Rc<Connection>> {
    match ngx_core::quic::streams::ngx_quic_stream(c) {
        Some(qs) => qs.parent.upgrade(),
        None => Some(c.clone()),
    }
}

/// ngx_http_v3_get_session
pub fn get_session(c: &Rc<Connection>) -> Option<Rc<H3Session>> {
    let pc = quic_parent(c)?;
    let hc = http_connection_of(&pc)?;

    let h3c = hc.v3_session.borrow().clone();

    h3c
}

/// ngx_http_quic_get_connection
pub fn quic_get_connection(c: &Rc<Connection>) -> Option<Rc<HttpConnection>> {
    match get_session(c) {
        Some(h3c) => Some(h3c.http_connection.clone()),
        None => quic_parent(c).and_then(|pc| http_connection_of(&pc)),
    }
}

/// ngx_http_v3_finalize_connection
pub fn finalize_connection(c: &Rc<Connection>, code: u64, reason: Option<&'static str>) {
    if let Some(pc) = quic_parent(c) {
        ngx_core::quic::ngx_quic_finalize_connection(&pc, code, reason);
    }
}

/// ngx_http_v3_shutdown_connection
pub fn shutdown_connection(c: &Rc<Connection>, code: u64, reason: Option<&'static str>) {
    if let Some(pc) = quic_parent(c) {
        ngx_core::quic::ngx_quic_shutdown_connection(&pc, code, reason);
    }
}

/// ngx_http_v3_init_session
pub fn init_session(c: &Rc<Connection>) -> i64 {
    let hc = match http_connection_of(c) {
        Some(hc) => hc,
        None => {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "failed to create http3 session");
            return NGX_ERROR;
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 init session");

    let qc = match ngx_core::quic::ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "failed to create http3 session");
            return NGX_ERROR;
        }
    };

    let wc = Rc::downgrade(c);

    let keepalive = qc.app_event(Box::new(move || {
        if let Some(c) = wc.upgrade() {
            keepalive_handler(&c);
        }
    }));

    let wc = Rc::downgrade(c);

    let send_insert_count = qc.app_event(Box::new(move || {
        if let Some(c) = wc.upgrade() {
            table::inc_insert_count_handler(&c);
        }
    }));

    let h3c = Rc::new(H3Session {
        http_connection: hc.clone(),
        connection: Rc::downgrade(c),
        table: RefCell::new(table::DynamicTable::default()),
        send_insert_count,
        keepalive,
        nrequests: Cell::new(0),
        blocked: RefCell::new(Vec::new()),
        nblocked: Cell::new(0),
        next_request_id: Cell::new(0),
        total_bytes: Cell::new(0),
        payload_bytes: Cell::new(0),
        goaway: Cell::new(false),
        hq: Cell::new(false),
        created_streams: Cell::new(0),
        known_streams: RefCell::new(Default::default()),
    });

    let wh3c = Rc::downgrade(&h3c);

    c.add_cleanup(PoolCleanup {
        tag: "ngx_http_v3_cleanup_session",
        data: None,
        handler: Some(Box::new(move || {
            if let Some(h3c) = wh3c.upgrade() {
                cleanup_session(&h3c);
            }
        })),
    });

    *hc.v3_session.borrow_mut() = Some(h3c);

    NGX_OK
}

/// ngx_http_v3_keepalive_handler
fn keepalive_handler(c: &Rc<Connection>) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 keepalive handler");

    shutdown_connection(c, NGX_HTTP_V3_ERR_NO_ERROR, Some("keepalive timeout"));
}

/// ngx_http_v3_cleanup_session
fn cleanup_session(h3c: &H3Session) {
    table::cleanup_table(h3c);

    if h3c.keepalive.timer_set() {
        h3c.keepalive.del_timer();
    }

    if h3c.send_insert_count.posted.get() {
        h3c.send_insert_count.delete_posted();
    }
}

/// ngx_http_v3_check_flood
pub fn check_flood(c: &Rc<Connection>) -> i64 {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    if h3c.total_bytes.get() / 8 > h3c.payload_bytes.get() + 1048576 {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "http3 flood detected");

        finalize_connection(c, NGX_HTTP_V3_ERR_NO_ERROR, Some("HTTP/3 flood detected"));
        return NGX_ERROR;
    }

    NGX_OK
}
