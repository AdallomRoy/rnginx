//! HTTP/2 — port of `nginx-c/src/http/v2/`.
//!
//! - `module`: ngx_http_v2_module.c (directives, configuration, `$http2`)
//! - `table`, `encode`: ngx_http_v2_table.c, ngx_http_v2_encode.c (HPACK)
//!
//! This file holds what ngx_http_v2.h defines: constants, the connection,
//! stream, node, state and output frame types, and the frame queue helpers.
//!
//! Runtime model (see docs/HTTP2_PLAN.md): one driver task per connection
//! owns all socket I/O and runs the state machine synchronously, as C's
//! event handlers do; each stream's request runs in its own task, talking to
//! the driver through the shared `H2Connection` / `H2Stream` state and
//! `Notify` wakeups.

pub mod connection;
pub mod encode;
pub mod filter;
pub mod module;
pub mod request_body;
pub mod state;
pub mod stream;
pub mod table;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::{Rc, Weak};

use ngx_core::connection::Connection;

use crate::request::{HttpConnection, R};

pub const NGX_HTTP_V2_ALPN_PROTO: &[u8] = b"\x02h2";

pub const NGX_HTTP_V2_STATE_BUFFER_SIZE: usize = 16;

pub const NGX_HTTP_V2_DEFAULT_FRAME_SIZE: usize = 1 << 14;
pub const NGX_HTTP_V2_MAX_FRAME_SIZE: usize = (1 << 24) - 1;

pub const NGX_HTTP_V2_INT_OCTETS: usize = 4;
pub const NGX_HTTP_V2_MAX_FIELD: usize = 127 + (1 << ((NGX_HTTP_V2_INT_OCTETS - 1) * 7)) - 1;

pub const NGX_HTTP_V2_FRAME_HEADER_SIZE: usize = 9;

// frame types
pub const NGX_HTTP_V2_DATA_FRAME: u8 = 0x0;
pub const NGX_HTTP_V2_HEADERS_FRAME: u8 = 0x1;
pub const NGX_HTTP_V2_PRIORITY_FRAME: u8 = 0x2;
pub const NGX_HTTP_V2_RST_STREAM_FRAME: u8 = 0x3;
pub const NGX_HTTP_V2_SETTINGS_FRAME: u8 = 0x4;
pub const NGX_HTTP_V2_PUSH_PROMISE_FRAME: u8 = 0x5;
pub const NGX_HTTP_V2_PING_FRAME: u8 = 0x6;
pub const NGX_HTTP_V2_GOAWAY_FRAME: u8 = 0x7;
pub const NGX_HTTP_V2_WINDOW_UPDATE_FRAME: u8 = 0x8;
pub const NGX_HTTP_V2_CONTINUATION_FRAME: u8 = 0x9;

// frame flags
pub const NGX_HTTP_V2_NO_FLAG: u8 = 0x00;
pub const NGX_HTTP_V2_ACK_FLAG: u8 = 0x01;
pub const NGX_HTTP_V2_END_STREAM_FLAG: u8 = 0x01;
pub const NGX_HTTP_V2_END_HEADERS_FLAG: u8 = 0x04;
pub const NGX_HTTP_V2_PADDED_FLAG: u8 = 0x08;
pub const NGX_HTTP_V2_PRIORITY_FLAG: u8 = 0x20;

pub const NGX_HTTP_V2_MAX_WINDOW: usize = (1 << 31) - 1;
pub const NGX_HTTP_V2_DEFAULT_WINDOW: usize = 65535;

pub const NGX_HTTP_V2_DEFAULT_WEIGHT: usize = 16;

// errors (ngx_http_v2.c)
pub const NGX_HTTP_V2_NO_ERROR: u32 = 0x0;
pub const NGX_HTTP_V2_PROTOCOL_ERROR: u32 = 0x1;
pub const NGX_HTTP_V2_INTERNAL_ERROR: u32 = 0x2;
pub const NGX_HTTP_V2_FLOW_CTRL_ERROR: u32 = 0x3;
pub const NGX_HTTP_V2_SETTINGS_TIMEOUT: u32 = 0x4;
pub const NGX_HTTP_V2_STREAM_CLOSED: u32 = 0x5;
pub const NGX_HTTP_V2_SIZE_ERROR: u32 = 0x6;
pub const NGX_HTTP_V2_REFUSED_STREAM: u32 = 0x7;
pub const NGX_HTTP_V2_CANCEL: u32 = 0x8;
pub const NGX_HTTP_V2_COMP_ERROR: u32 = 0x9;
pub const NGX_HTTP_V2_CONNECT_ERROR: u32 = 0xa;
pub const NGX_HTTP_V2_ENHANCE_YOUR_CALM: u32 = 0xb;
pub const NGX_HTTP_V2_INADEQUATE_SECURITY: u32 = 0xc;
pub const NGX_HTTP_V2_HTTP_1_1_REQUIRED: u32 = 0xd;

// frame sizes
pub const NGX_HTTP_V2_SETTINGS_ACK_SIZE: usize = 0;
pub const NGX_HTTP_V2_RST_STREAM_SIZE: usize = 4;
pub const NGX_HTTP_V2_PRIORITY_SIZE: usize = 5;
pub const NGX_HTTP_V2_PING_SIZE: usize = 8;
pub const NGX_HTTP_V2_GOAWAY_SIZE: usize = 8;
pub const NGX_HTTP_V2_WINDOW_UPDATE_SIZE: usize = 4;

pub const NGX_HTTP_V2_SETTINGS_PARAM_SIZE: usize = 6;

// settings fields
pub const NGX_HTTP_V2_HEADER_TABLE_SIZE_SETTING: u16 = 0x1;
pub const NGX_HTTP_V2_ENABLE_PUSH_SETTING: u16 = 0x2;
pub const NGX_HTTP_V2_MAX_STREAMS_SETTING: u16 = 0x3;
pub const NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING: u16 = 0x4;
pub const NGX_HTTP_V2_MAX_FRAME_SIZE_SETTING: u16 = 0x5;

pub const NGX_HTTP_V2_FRAME_BUFFER_SIZE: usize = 24;

pub const NGX_HTTP_V2_PREFACE_START: &[u8] = b"PRI * HTTP/2.0\r\n";
pub const NGX_HTTP_V2_PREFACE_END: &[u8] = b"\r\nSM\r\n\r\n";
pub const NGX_HTTP_V2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// HPACK static table indexes used by the encoder
pub const NGX_HTTP_V2_AUTHORITY_INDEX: u8 = 1;
pub const NGX_HTTP_V2_METHOD_INDEX: u8 = 2;
pub const NGX_HTTP_V2_METHOD_GET_INDEX: u8 = 2;
pub const NGX_HTTP_V2_METHOD_POST_INDEX: u8 = 3;
pub const NGX_HTTP_V2_PATH_INDEX: u8 = 4;
pub const NGX_HTTP_V2_PATH_ROOT_INDEX: u8 = 4;
pub const NGX_HTTP_V2_SCHEME_HTTP_INDEX: u8 = 6;
pub const NGX_HTTP_V2_SCHEME_HTTPS_INDEX: u8 = 7;
pub const NGX_HTTP_V2_STATUS_INDEX: u8 = 8;
pub const NGX_HTTP_V2_STATUS_200_INDEX: u8 = 8;
pub const NGX_HTTP_V2_STATUS_204_INDEX: u8 = 9;
pub const NGX_HTTP_V2_STATUS_206_INDEX: u8 = 10;
pub const NGX_HTTP_V2_STATUS_304_INDEX: u8 = 11;
pub const NGX_HTTP_V2_STATUS_400_INDEX: u8 = 12;
pub const NGX_HTTP_V2_STATUS_404_INDEX: u8 = 13;
pub const NGX_HTTP_V2_STATUS_500_INDEX: u8 = 14;
pub const NGX_HTTP_V2_CONTENT_LENGTH_INDEX: u8 = 28;
pub const NGX_HTTP_V2_CONTENT_TYPE_INDEX: u8 = 31;
pub const NGX_HTTP_V2_DATE_INDEX: u8 = 33;
pub const NGX_HTTP_V2_LAST_MODIFIED_INDEX: u8 = 44;
pub const NGX_HTTP_V2_LOCATION_INDEX: u8 = 46;
pub const NGX_HTTP_V2_SERVER_INDEX: u8 = 54;
pub const NGX_HTTP_V2_VARY_INDEX: u8 = 59;

/// A state machine handler (ngx_http_v2_handler_pt): consumes input from
/// `buf[pos..]` and returns the new position, or None once the connection
/// has been finalized (C returns NULL). The buffer is mutable because
/// ngx_http_v2_handle_continuation splices CONTINUATION frame headers out of
/// it in place.
pub type Handler = fn(&Rc<H2Connection>, &mut [u8], usize) -> Option<usize>;

/// ngx_http_v2_state_t
pub struct State {
    pub sid: Cell<u32>,
    pub length: Cell<usize>,
    pub padding: Cell<usize>,
    pub window_delta: Cell<isize>,
    pub flags: Cell<u8>,

    pub incomplete: Cell<bool>,

    // HPACK
    pub parse_name: Cell<bool>,
    pub parse_value: Cell<bool>,
    pub index: Cell<bool>,
    pub header_name: RefCell<Vec<u8>>,
    pub header_value: RefCell<Vec<u8>>,
    pub header_limit: Cell<usize>,
    pub field_state: Cell<u8>,
    /// The field being collected (C: field_start..field_end).
    pub field: RefCell<Vec<u8>>,
    pub field_rest: Cell<usize>,

    pub stream: RefCell<Option<Rc<H2Stream>>>,

    pub buffer: RefCell<[u8; NGX_HTTP_V2_STATE_BUFFER_SIZE]>,
    pub buffer_used: Cell<usize>,
    pub handler: Cell<Handler>,
}

/// A node's place in the priority tree (node->parent in C).
#[derive(Clone)]
pub enum Parent {
    /// Not in the tree yet (NULL).
    None,
    /// A root node, in H2Connection.dependencies (NGX_HTTP_V2_ROOT).
    Root,
    Node(Weak<H2Node>),
}

impl Parent {
    pub fn is_none(&self) -> bool {
        matches!(self, Parent::None)
    }

    pub fn node(&self) -> Option<Rc<H2Node>> {
        match self {
            Parent::Node(w) => w.upgrade(),
            _ => None,
        }
    }
}

impl State {
    pub fn new(handler: Handler) -> State {
        State {
            sid: Cell::new(0),
            length: Cell::new(0),
            padding: Cell::new(0),
            window_delta: Cell::new(0),
            flags: Cell::new(0),
            incomplete: Cell::new(false),
            parse_name: Cell::new(false),
            parse_value: Cell::new(false),
            index: Cell::new(false),
            header_name: RefCell::new(Vec::new()),
            header_value: RefCell::new(Vec::new()),
            header_limit: Cell::new(0),
            field_state: Cell::new(0),
            field: RefCell::new(Vec::new()),
            field_rest: Cell::new(0),
            stream: RefCell::new(None),
            buffer: RefCell::new([0; NGX_HTTP_V2_STATE_BUFFER_SIZE]),
            buffer_used: Cell::new(0),
            handler: Cell::new(handler),
        }
    }
}

/// ngx_http_v2_node_t: a node of the priority tree. Nodes outlive their
/// streams (closed nodes keep their place in the tree until reused).
pub struct H2Node {
    pub id: Cell<u32>,
    pub parent: RefCell<Parent>,
    pub children: RefCell<Vec<Rc<H2Node>>>,
    pub rank: Cell<usize>,
    pub weight: Cell<usize>,
    pub rel_weight: Cell<f64>,
    pub stream: RefCell<Option<Rc<H2Stream>>>,
}

/// ngx_http_v2_stream_t
pub struct H2Stream {
    /// Cleared when the stream is closed, breaking the request <-> stream
    /// reference cycle.
    pub request: RefCell<Option<R>>,
    pub connection: Rc<H2Connection>,
    pub node: RefCell<Rc<H2Node>>,
    /// The stream's fake connection (the request's r.connection).
    pub fc: Rc<Connection>,

    pub queued: Cell<usize>,
    /// Payload bytes of the stream's DATA frames queued and not yet written.
    pub queued_bytes: Cell<usize>,

    /// Signed: a SETTINGS_INITIAL_WINDOW_SIZE change can make it negative.
    pub send_window: Cell<isize>,
    pub recv_window: Cell<usize>,

    /// DATA received before the request started reading the body.
    pub preread: RefCell<Option<Vec<u8>>>,
    /// DATA received while the request reads the body, not yet processed.
    pub body_pending: RefCell<Vec<u8>>,
    /// rb->buf: the data not passed on yet (buf->pos..buf->last), the
    /// buffer size, and its fill level since the last rewind
    /// (buf->last - buf->start).
    pub body_buf: RefCell<Vec<u8>>,
    pub body_cap: Cell<usize>,
    pub body_last: Cell<usize>,

    /// DATA frame structures allocated by this stream (counted in
    /// H2Connection.frames) and how many of them are free for reuse.
    pub frames: Cell<usize>,
    pub free_frames: Cell<usize>,

    pub cookies: RefCell<Vec<Vec<u8>>>,

    pub initialized: Cell<bool>,
    pub waiting: Cell<bool>,
    pub blocked: Cell<bool>,
    pub exhausted: Cell<bool>,
    pub in_closed: Cell<bool>,
    pub out_closed: Cell<bool>,
    pub rst_sent: Cell<bool>,
    pub no_flow_control: Cell<bool>,
    pub skip_data: Cell<bool>,

    /// Wakes the request task: a window update, sent frames, request body
    /// data, or an error on the stream (the fake connection's read/write
    /// events in C).
    pub notify: tokio::sync::Notify,
    /// The request task, aborted when the stream is torn down under it.
    pub task: RefCell<Option<tokio::task::JoinHandle<()>>>,
    /// The request has returned; the stream is closing (waiting for its
    /// queued frames).
    pub request_done: Cell<bool>,
    /// Set once the request has been freed (ngx_http_v2_close_stream ran).
    pub closed: Cell<bool>,
    /// The :authority value (r->host_start..host_end in C).
    pub authority: RefCell<Option<Vec<u8>>>,
    /// The request waiting with ngx_http_test_reading as its read event
    /// handler (a limit_req delay): the fake connection's read event runs
    /// it, and it tests c->error.
    pub test_reading: RefCell<Option<Weak<crate::request::Request>>>,
    /// The main request's upstream as its read event handler: the fake
    /// connection's read event goes to it.
    pub upstream_watch: RefCell<Option<Weak<StreamWatch>>>,
}

/// The read event handler of a request that its upstream sets
/// (H2Stream.upstream_watch).
pub struct StreamWatch {
    /// ngx_http_upstream_rd_check_broken_connection with c->error: the
    /// upstream request ends unless its response is cacheable (u->cacheable
    /// then); None for ngx_http_block_reading, when the upstream does not
    /// check the client (ignore_client_abort, store, post_action)
    pub cacheable: Option<Box<dyn Fn() -> bool>>,
    /// fc->error has been set (RST_STREAM, the end of the connection)
    pub closed: Cell<bool>,
    pub notify: tokio::sync::Notify,
}

impl StreamWatch {
    /// The event: false if the request ends (the upstream would finalize it
    /// with 499 right away), true if it goes on and the upstream is told.
    pub fn read_event(&self) -> bool {
        if let Some(cacheable) = &self.cacheable {
            if !cacheable() {
                return false;
            }
        }

        self.closed.set(true);
        self.notify.notify_one();

        true
    }

    /// Resolves once fc->error has been set.
    pub async fn closed(&self) {
        while !self.closed.get() {
            self.notify.notified().await;
        }
    }
}

/// What to do when an output frame has been written out
/// (ngx_http_v2_out_frame_t.handler).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameHandler {
    /// ngx_http_v2_frame_handler: control frames.
    Control,
    /// ngx_http_v2_settings_frame_handler
    Settings,
    /// ngx_http_v2_headers_frame_handler
    Headers,
    /// ngx_http_v2_data_frame_handler
    Data,
}

/// ngx_http_v2_out_frame_t. The frame's bytes (header and payload) are
/// materialized; `sent` tracks partial writes.
pub struct OutFrame {
    pub data: Vec<u8>,
    pub sent: usize,
    pub handler: FrameHandler,
    pub stream: Option<Rc<H2Stream>>,
    /// Payload length.
    pub length: usize,
    pub blocked: bool,
    pub fin: bool,
}

/// ngx_http_v2_connection_t
pub struct H2Connection {
    pub connection: Rc<Connection>,
    pub http_connection: Rc<HttpConnection>,

    pub total_bytes: Cell<i64>,
    pub payload_bytes: Cell<i64>,

    pub processing: Cell<usize>,
    /// Control frames allocated (C caps them at 10000) and how many of them
    /// sit on the free list.
    pub frames: Cell<usize>,
    pub free_frames: Cell<usize>,
    pub idle: Cell<usize>,
    pub new_streams: Cell<usize>,
    pub refused_streams: Cell<usize>,
    pub priority_limit: Cell<usize>,

    pub send_window: Cell<usize>,
    pub recv_window: Cell<usize>,
    pub init_window: Cell<usize>,

    pub frame_size: Cell<usize>,

    /// Streams waiting for the connection send window (ngx_queue_t waiting).
    pub waiting: RefCell<VecDeque<Rc<H2Stream>>>,

    pub state: State,

    pub hpack: RefCell<table::Hpack>,

    /// streams_index: hash buckets of nodes by (sid >> 1) & mask, the most
    /// recently added node first, as C chains them.
    pub streams_index: RefCell<Vec<Vec<Rc<H2Node>>>>,
    pub streams_index_mask: usize,

    /// The output queue; index 0 is C's last_out and each next element is
    /// its ->next, so frames go out in reverse order.
    pub last_out: RefCell<Vec<OutFrame>>,

    /// Root nodes of the priority tree (ngx_queue_t dependencies).
    pub dependencies: RefCell<Vec<Rc<H2Node>>>,
    /// Closed nodes, oldest first (ngx_queue_t closed).
    pub closed: RefCell<VecDeque<Rc<H2Node>>>,

    pub closed_nodes: Cell<usize>,
    pub last_sid: Cell<u32>,

    pub lingering_time: Cell<i64>,

    pub settings_ack: Cell<bool>,
    pub table_update: Cell<bool>,
    pub blocked: Cell<bool>,
    pub goaway: Cell<bool>,

    // Async driver state (C keeps these in the connection's events).
    /// Stream tasks queued output (the connection's write event).
    pub out_notify: tokio::sync::Notify,
    /// Effects of the frame just parsed that C runs inline; the driver runs
    /// them before parsing the next frame.
    pub posted: RefCell<VecDeque<Posted>>,
    /// Streams whose read event was posted during the read batch (DATA
    /// for a body being read); woken once the batch is processed.
    pub posted_reads: RefCell<Vec<Rc<H2Stream>>>,
    /// Set once ngx_http_v2_finalize_connection ran.
    pub finalized: Cell<bool>,
    /// The connection's read timer (client_header_timeout, then
    /// keepalive_timeout while idle); streams delete it when created.
    pub read_timer: Cell<Option<tokio::time::Instant>>,
}

/// An effect of a state handler that C performs by calling into a stream
/// synchronously (see stream::run_posted).
pub enum Posted {
    /// A stream task was spawned: let it run to its first wait, as C runs
    /// the request inline (ngx_http_v2_run_request).
    Run,
    /// The stream's write event (window opened): let it send.
    Write(Rc<H2Stream>),
    /// ngx_http_v2_state_window_update on the connection: wake waiting
    /// streams in order while the connection window lasts.
    DrainWaiting,
}

impl H2Connection {
    /// ngx_http_v2_queue_frame: insert a stream frame by priority.
    pub fn queue_frame(&self, frame: OutFrame) {
        let mut out = self.last_out.borrow_mut();
        let stream = frame.stream.as_ref().expect("stream frame");
        let (rank, rel_weight) = {
            let node = stream.node.borrow();
            (node.rank.get(), node.rel_weight.get())
        };
        let mut i = 0;
        while i < out.len() {
            let f = &out[i];
            if f.blocked {
                break;
            }
            let s = match &f.stream {
                None => break,
                Some(s) => s,
            };
            let node = s.node.borrow();
            if node.rank.get() < rank || (node.rank.get() == rank && node.rel_weight.get() >= rel_weight) {
                break;
            }
            i += 1;
        }
        out.insert(i, frame);
    }

    /// ngx_http_v2_queue_blocked_frame: insert a control frame ahead of the
    /// unblocked stream frames.
    pub fn queue_blocked_frame(&self, frame: OutFrame) {
        let mut out = self.last_out.borrow_mut();
        let mut i = 0;
        while i < out.len() {
            if out[i].blocked || out[i].stream.is_none() {
                break;
            }
            i += 1;
        }
        out.insert(i, frame);
    }

    /// ngx_http_v2_queue_ordered_frame
    pub fn queue_ordered_frame(&self, frame: OutFrame) {
        self.last_out.borrow_mut().insert(0, frame);
    }
}

// Frame field helpers (the ngx_http_v2_parse_* / ngx_http_v2_write_* macros).

pub fn parse_uint16(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[0], p[1]])
}

pub fn parse_uint32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

pub fn parse_length(head: u32) -> usize {
    (head >> 8) as usize
}

pub fn parse_type(head: u32) -> u8 {
    (head & 0xff) as u8
}

pub fn parse_sid(p: &[u8]) -> u32 {
    parse_uint32(p) & 0x7fffffff
}

pub fn parse_window(p: &[u8]) -> u32 {
    parse_uint32(p) & 0x7fffffff
}

pub fn write_uint16(dst: &mut Vec<u8>, v: u16) {
    dst.extend_from_slice(&v.to_be_bytes());
}

pub fn write_uint32(dst: &mut Vec<u8>, v: u32) {
    dst.extend_from_slice(&v.to_be_bytes());
}

/// ngx_http_v2_write_len_and_type
pub fn write_len_and_type(dst: &mut Vec<u8>, len: usize, ty: u8) {
    write_uint32(dst, ((len as u32) << 8) | ty as u32);
}

/// A frame header: length, type, flags and stream id.
pub fn write_frame_head(dst: &mut Vec<u8>, len: usize, ty: u8, flags: u8, sid: u32) {
    write_len_and_type(dst, len, ty);
    dst.push(flags);
    write_uint32(dst, sid);
}
