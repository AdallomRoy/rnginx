//! QUIC — port of nginx-c/src/event/quic/.
//!
//! This file holds ngx_event_quic.h and ngx_event_quic_connection.h (the
//! configuration, the connection, stream, path, socket and connection id
//! types) and ngx_event_quic.c (the connection: packets in, closing).
//!
//! Runtime model. A QUIC connection is a connection sharing the UDP
//! listening socket (udp.rs dispatches the datagrams to it by their
//! destination connection id, as ngx_quic_recvmsg does). Its events are
//! QEvents: C's ngx_event_t, with a timer and a place in the posted
//! events queue of the connection. One driver task per connection
//! (ngx_quic_drive) runs what C runs on its events: the datagrams through
//! ngx_quic_input_handler, the expired timers, then the posted events in
//! order, as ngx_process_events_and_timers does. The streams are
//! connections of their own (fake ones, c.quic_stream set) whose I/O goes
//! through the stream buffers (streams.rs); the application runs them in
//! tasks, which their read and write events wake: the driver lets a woken
//! task run before the next posted event, as C runs the stream's handler
//! from the posted events.

pub mod ack;
pub mod connid;
pub mod frames;
pub mod migration;
pub mod openssl_compat;
pub mod output;
pub mod protection;
pub mod socket;
pub mod ssl;
pub mod streams;
pub mod tokens;
pub mod transport;
pub mod udp;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::{Rc, Weak};

use crate::connection::Connection;
use crate::inet::SockAddr;
use crate::log::*;
use crate::rc::*;
use crate::string::B;
use crate::times;
use crate::{ngx_log_debug, ngx_log_error};

use frames::{QuicBuffer, ngx_quic_free_buffer, ngx_quic_free_frame, ngx_quic_free_frames};
use protection::*;
use transport::*;

pub const NGX_QUIC_MAX_UDP_PAYLOAD_SIZE: usize = 65527;

pub const NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT: u64 = 3;
pub const NGX_QUIC_DEFAULT_MAX_ACK_DELAY: u64 = 25;
pub const NGX_QUIC_DEFAULT_HOST_KEY_LEN: usize = 32;
pub const NGX_QUIC_SR_KEY_LEN: usize = 32;
pub const NGX_QUIC_AV_KEY_LEN: usize = 32;

pub const NGX_QUIC_SR_TOKEN_LEN: usize = 16;

pub const NGX_QUIC_MIN_INITIAL_SIZE: usize = 1200;

pub const NGX_QUIC_STREAM_SERVER_INITIATED: u64 = 0x01;
pub const NGX_QUIC_STREAM_UNIDIRECTIONAL: u64 = 0x02;

pub const NGX_QUIC_ENCRYPTION_INITIAL: usize = 0;
pub const NGX_QUIC_ENCRYPTION_EARLY_DATA: usize = 1;
pub const NGX_QUIC_ENCRYPTION_HANDSHAKE: usize = 2;
pub const NGX_QUIC_ENCRYPTION_APPLICATION: usize = 3;
pub const NGX_QUIC_ENCRYPTION_LAST: usize = 4;

pub const NGX_QUIC_SEND_CTX_LAST: usize = NGX_QUIC_ENCRYPTION_LAST - 1;

/* RFC 9002, 6.2.2.  Handshakes and New Paths: kInitialRtt */
pub const NGX_QUIC_INITIAL_RTT: u64 = 333; /* ms */

pub const NGX_QUIC_UNSET_PN: u64 = u64::MAX;

/// NGX_TIMER_INFINITE
pub const NGX_TIMER_INFINITE: u64 = u64::MAX;

/// NGX_TIMER_LAZY_DELAY
const NGX_TIMER_LAZY_DELAY: i64 = 300;

/// ngx_quic_stream_send_state_e
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuicStreamSendState {
    Ready,
    Send,
    DataSent,
    DataRecvd,
    ResetSent,
    ResetRecvd,
}

/// ngx_quic_stream_recv_state_e
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuicStreamRecvState {
    Recv,
    SizeKnown,
    DataRecvd,
    DataRead,
    ResetRecvd,
    ResetRead,
}

/// ngx_quic_init_pt
pub type QuicInitHandler = Rc<dyn Fn(&Rc<Connection>) -> i64>;
/// ngx_quic_shutdown_pt
pub type QuicShutdownHandler = Rc<dyn Fn(&Rc<Connection>)>;

/// ngx_quic_conf_t. `create_ssl` is ngx_ssl_create_connection() with the
/// server's ngx_ssl_t (conf->ssl).
pub struct QuicConf {
    pub create_ssl: Option<Rc<dyn Fn(&Connection) -> i64>>,

    pub retry: bool,
    pub gso_enabled: bool,
    pub disable_active_migration: bool,
    pub handshake_timeout: u64,
    /// set when a connection starts (the keepalive_timeout of the server)
    pub idle_timeout: Cell<u64>,
    pub host_key: Vec<u8>,
    pub stream_buffer_size: usize,
    pub max_concurrent_streams_bidi: u64,
    pub max_concurrent_streams_uni: u64,
    pub active_connection_id_limit: u64,
    pub stream_close_code: u64,
    pub stream_reject_code_uni: u64,
    pub stream_reject_code_bidi: u64,

    pub init: Option<QuicInitHandler>,
    pub shutdown: Option<QuicShutdownHandler>,

    pub av_token_key: [u8; NGX_QUIC_AV_KEY_LEN],
    pub sr_token_key: [u8; NGX_QUIC_SR_KEY_LEN],
}

impl Default for QuicConf {
    fn default() -> Self {
        QuicConf {
            create_ssl: None,
            retry: false,
            gso_enabled: false,
            disable_active_migration: false,
            handshake_timeout: 0,
            idle_timeout: Cell::new(0),
            host_key: Vec::new(),
            stream_buffer_size: 0,
            max_concurrent_streams_bidi: 0,
            max_concurrent_streams_uni: 0,
            active_connection_id_limit: 0,
            stream_close_code: 0,
            stream_reject_code_uni: 0,
            stream_reject_code_bidi: 0,
            init: None,
            shutdown: None,
            av_token_key: [0; NGX_QUIC_AV_KEY_LEN],
            sr_token_key: [0; NGX_QUIC_SR_KEY_LEN],
        }
    }
}

/// What an event does (its handler in C).
pub enum QEventKind {
    /// c->read of the QUIC connection: ngx_quic_input_handler
    Read,
    /// qc->push: ngx_quic_push_handler
    Push,
    /// qc->pto: ngx_quic_pto_handler or ngx_quic_lost_handler (qc.pto_lost)
    Pto,
    /// qc->close: ngx_quic_close_handler
    Close,
    /// qc->path_validation: ngx_quic_path_handler
    PathValidation,
    /// qc->key_update: ngx_quic_keys_update
    KeyUpdate,
    /// sc->read and sc->write of a stream
    StreamRead(Weak<QuicStream>),
    StreamWrite(Weak<QuicStream>),
    /// an event of the application (HTTP/3)
    App(Box<dyn Fn()>),
}

/// ngx_event_t of a QUIC connection: the timer (its expiry time, in the
/// msec of times::event_msec(); timer_set is Some), whether it is
/// posted, and the driver to wake when either changes.
pub struct QEvent {
    pub timer: Cell<Option<u64>>,
    pub posted: Cell<bool>,
    pub timedout: Cell<bool>,
    pub kind: QEventKind,
    /// the driver's wakeup (qc.wake)
    wake: Rc<tokio::sync::Notify>,
    /// the posted events queue of the connection
    queue: Weak<RefCell<VecDeque<Rc<QEvent>>>>,
}

impl QEvent {
    pub fn new(kind: QEventKind, qc: &QuicConnection) -> Rc<QEvent> {
        Rc::new(QEvent { timer: Cell::new(None), posted: Cell::new(false), timedout: Cell::new(false), kind, wake: qc.wake.clone(), queue: Rc::downgrade(&qc.posted) })
    }

    pub fn timer_set(&self) -> bool {
        self.timer.get().is_some()
    }

    /// ngx_add_timer
    pub fn add_timer(&self, timer: u64) {
        let key = times::event_msec().saturating_add(timer);

        if let Some(old) = self.timer.get() {
            // Use a previous timer value if difference between it and a new
            // value is less than NGX_TIMER_LAZY_DELAY milliseconds: this allows
            // to minimize the rbtree operations for fast connections.

            let diff = key as i64 - old as i64;

            if diff.abs() < NGX_TIMER_LAZY_DELAY {
                return;
            }
        }

        self.timer.set(Some(key));
        self.wake.notify_one();
    }

    /// ngx_del_timer
    pub fn del_timer(&self) {
        self.timer.set(None);
    }

    /// ngx_post_event(ev, &ngx_posted_events)
    pub fn post(self: &Rc<Self>) {
        if self.posted.get() {
            return;
        }

        if let Some(q) = self.queue.upgrade() {
            self.posted.set(true);
            q.borrow_mut().push_back(self.clone());
            self.wake.notify_one();
        }
    }

    /// ngx_delete_posted_event
    pub fn delete_posted(&self) {
        if !self.posted.get() {
            return;
        }

        self.posted.set(false);

        if let Some(q) = self.queue.upgrade() {
            q.borrow_mut().retain(|e| !std::ptr::eq(Rc::as_ptr(e), self));
        }
    }
}

/// ngx_quic_stream_t with the state of the stream connection's events
/// (sc->read, sc->write).
pub struct QuicStream {
    pub parent: Weak<Connection>,
    pub connection: RefCell<Option<Rc<Connection>>>,
    pub id: u64,
    pub sent: Cell<u64>,
    pub acked: Cell<u64>,
    pub send_max_data: Cell<u64>,
    pub send_offset: Cell<u64>,
    pub send_final_size: Cell<u64>,
    pub recv_max_data: Cell<u64>,
    pub recv_offset: Cell<u64>,
    pub recv_window: Cell<u64>,
    pub recv_last: Cell<u64>,
    pub recv_final_size: Cell<u64>,
    pub send: RefCell<QuicBuffer>,
    pub recv: RefCell<QuicBuffer>,
    pub send_state: Cell<QuicStreamSendState>,
    pub recv_state: Cell<QuicStreamRecvState>,
    pub cancelable: Cell<bool>,
    pub fin_acked: Cell<bool>,

    /// sc->read and sc->write
    pub read: Rc<QEvent>,
    pub write: Rc<QEvent>,
    pub read_ready: Cell<bool>,
    pub read_active: Cell<bool>,
    pub read_error: Cell<bool>,
    pub read_eof: Cell<bool>,
    pub write_ready: Cell<bool>,
    pub write_active: Cell<bool>,
    pub write_error: Cell<bool>,
    /// the read handler is ngx_quic_init_stream_handler (the stream is in
    /// qc->streams.uninitialized)
    pub init_handler: Cell<bool>,
    /// wakes the task of the stream on its read or write event
    pub notify: tokio::sync::Notify,
}

/// ngx_quic_client_id_t
#[derive(Debug)]
pub struct QuicClientId {
    pub seqnum: Cell<u64>,
    pub id: RefCell<Vec<u8>>,
    pub sr_token: RefCell<[u8; NGX_QUIC_SR_TOKEN_LEN]>,
    pub used: Cell<bool>,
}

/// ngx_quic_server_id_t
#[derive(Clone, Default, Debug)]
pub struct QuicServerId {
    pub seqnum: u64,
    pub id: Vec<u8>,
}

/// ngx_quic_path_state_e
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuicPathState {
    Idle,
    Validating,
    Waiting,
    Mtud,
}

/// ngx_quic_path_t
pub struct QuicPath {
    pub sockaddr: RefCell<SockAddr>,
    pub cid: RefCell<Option<Rc<QuicClientId>>>,
    pub state: Cell<QuicPathState>,
    pub expires: Cell<u64>,
    pub tries: Cell<u64>,
    pub tag: Cell<u64>,
    pub mtu: Cell<usize>,
    pub mtud: Cell<usize>,
    pub max_mtu: Cell<usize>,
    pub sent: Cell<i64>,
    pub received: Cell<i64>,
    pub challenge: RefCell<[[u8; 8]; 2]>,
    pub seqnum: Cell<u64>,
    pub mtu_pnum: RefCell<[u64; migration::NGX_QUIC_PATH_RETRIES as usize]>,
    pub addr_text: RefCell<Vec<u8>>,
    pub validated: Cell<bool>,
    pub mtu_unvalidated: Cell<bool>,
}

/// ngx_quic_socket_t: a server connection id the connection listens at.
/// `sockaddr` is the source address of the datagram being handled which
/// came with it.
pub struct QuicSocket {
    pub quic: RefCell<Weak<QuicConnection>>,
    pub connection: RefCell<Weak<Connection>>,
    pub sid: RefCell<QuicServerId>,
    pub sockaddr: RefCell<SockAddr>,
    pub used: Cell<bool>,
    /// the key it is found by in the listening's lookup
    pub key: RefCell<Option<udp::QuicKey>>,
}

/// ngx_quic_streams_t
#[derive(Default)]
pub struct QuicStreams {
    pub tree: RefCell<BTreeMap<u64, Rc<QuicStream>>>,

    pub uninitialized: RefCell<VecDeque<Rc<QuicStream>>>,

    pub sent: Cell<u64>,
    pub recv_offset: Cell<u64>,
    pub recv_window: Cell<u64>,
    pub recv_last: Cell<u64>,
    pub recv_max_data: Cell<u64>,
    pub send_offset: Cell<u64>,
    pub send_max_data: Cell<u64>,

    pub server_max_streams_uni: Cell<u64>,
    pub server_max_streams_bidi: Cell<u64>,
    pub server_streams_uni: Cell<u64>,
    pub server_streams_bidi: Cell<u64>,

    pub client_max_streams_uni: Cell<u64>,
    pub client_max_streams_bidi: Cell<u64>,
    pub client_streams_uni: Cell<u64>,
    pub client_streams_bidi: Cell<u64>,

    pub initialized: Cell<bool>,
}

/// ngx_quic_congestion_t
#[derive(Default)]
pub struct QuicCongestion {
    pub in_flight: Cell<usize>,
    pub window: Cell<usize>,
    pub ssthresh: Cell<usize>,
    pub w_max: Cell<usize>,
    pub w_est: Cell<usize>,
    pub w_prior: Cell<usize>,
    pub mtu: Cell<usize>,
    pub recovery_start: Cell<u64>,
    pub idle_start: Cell<u64>,
    pub k: Cell<u64>,
    pub idle: Cell<bool>,
}

impl QuicCongestion {
    /// ngx_memzero(&qc->congestion)
    pub fn reset(&self) {
        self.in_flight.set(0);
        self.window.set(0);
        self.ssthresh.set(0);
        self.w_max.set(0);
        self.w_est.set(0);
        self.w_prior.set(0);
        self.mtu.set(0);
        self.recovery_start.set(0);
        self.idle_start.set(0);
        self.k.set(0);
        self.idle.set(false);
    }
}

/// ngx_quic_send_ctx_t: a packet number space.
///
/// RFC 9000, 12.3.  Packet Numbers
///
///  Conceptually, a packet number space is the context in which a packet
///  can be processed and acknowledged.  Initial packets can only be sent
///  with Initial packet protection keys and acknowledged in packets that
///  are also Initial packets.
pub struct QuicSendCtx {
    pub level: usize,

    pub crypto: QuicBuffer,
    pub crypto_sent: u64,

    pub pnum: u64,        /* to be sent */
    pub largest_ack: u64, /* received from peer */
    pub largest_pn: u64,  /* received from peer */

    pub frames: VecDeque<Box<QuicFrame>>,  /* generated frames */
    pub sending: VecDeque<Box<QuicFrame>>, /* frames assigned to pkt */
    pub sent: VecDeque<Box<QuicFrame>>,    /* frames waiting ACK */

    pub pending_ack: u64, /* non sent ack-eliciting */
    pub largest_range: u64,
    pub first_range: u64,
    pub largest_received: u64,
    pub ack_delay_start: u64,
    pub nranges: usize,
    pub ranges: [QuicAckRange; NGX_QUIC_MAX_RANGES],
    pub send_ack: u64,
}

impl QuicSendCtx {
    fn new(level: usize) -> QuicSendCtx {
        QuicSendCtx {
            level,
            crypto: QuicBuffer::default(),
            crypto_sent: 0,
            pnum: 0,
            largest_ack: NGX_QUIC_UNSET_PN,
            largest_pn: NGX_QUIC_UNSET_PN,
            frames: VecDeque::new(),
            sending: VecDeque::new(),
            sent: VecDeque::new(),
            pending_ack: NGX_QUIC_UNSET_PN,
            largest_range: NGX_QUIC_UNSET_PN,
            first_range: 0,
            largest_received: 0,
            ack_delay_start: 0,
            nranges: 0,
            ranges: [QuicAckRange::default(); NGX_QUIC_MAX_RANGES],
            send_ack: 0,
        }
    }
}

/// ngx_quic_connection_t
pub struct QuicConnection {
    pub version: Cell<u32>,

    pub path: RefCell<Option<Rc<QuicPath>>>,

    pub sockets: RefCell<Vec<Rc<QuicSocket>>>,
    pub paths: RefCell<Vec<Rc<QuicPath>>>,
    pub client_ids: RefCell<Vec<Rc<QuicClientId>>>,

    pub nsockets: Cell<usize>,
    pub nclient_ids: Cell<u64>,
    pub max_retired_seqnum: Cell<u64>,
    pub client_seqnum: Cell<u64>,
    pub server_seqnum: Cell<u64>,
    pub path_seqnum: Cell<u64>,

    pub tp: RefCell<QuicTp>,
    pub ctp: RefCell<QuicTp>,

    pub send_ctx: [RefCell<QuicSendCtx>; NGX_QUIC_SEND_CTX_LAST],

    pub keys: Rc<RefCell<QuicKeys>>,

    pub conf: Rc<QuicConf>,

    /// c->read of the connection
    pub read: Rc<QEvent>,
    pub push: Rc<QEvent>,
    pub pto: Rc<QEvent>,
    pub close: Rc<QEvent>,
    pub path_validation: Rc<QEvent>,
    pub key_update: Rc<QEvent>,
    /// qc->pto.handler is ngx_quic_lost_handler (else ngx_quic_pto_handler)
    pub pto_lost: Cell<bool>,

    pub last_cc: Cell<u64>,

    pub first_rtt: Cell<u64>,
    pub latest_rtt: Cell<u64>,
    pub avg_rtt: Cell<u64>,
    pub min_rtt: Cell<u64>,
    pub rttvar: Cell<u64>,

    pub pto_count: Cell<u64>,

    /// the frames allocated (qc->nframes), those on the free list, and the
    /// limit
    pub nframes: Cell<usize>,
    pub free_frames: Cell<usize>,
    pub max_frames: Cell<usize>,

    pub compat: RefCell<Option<openssl_compat::QuicCompat>>,

    pub streams: QuicStreams,
    pub congestion: QuicCongestion,

    pub rst_pnum: Cell<u64>, /* first on validated path */

    pub received: Cell<i64>,

    pub error: Cell<u64>,
    pub error_level: Cell<usize>,
    pub error_ftype: Cell<u64>,
    pub error_reason: Cell<Option<&'static str>>,

    pub shutdown_code: Cell<u64>,
    pub shutdown_reason: Cell<Option<&'static str>>,

    pub error_app: Cell<bool>,
    pub send_timer_set: Cell<bool>,
    pub closing: Cell<bool>,
    pub shutdown: Cell<bool>,
    pub draining: Cell<bool>,
    pub key_phase: Cell<bool>,
    pub validated: Cell<bool>,
    pub client_tp_done: Cell<bool>,

    /// c->udp->buffer is set: a datagram from the listening (not the
    /// first one, c->buffer)
    pub udp_buffer: Cell<bool>,
    /// c->write->error: sendmsg() failed
    pub write_error: Cell<bool>,

    // the driver
    /// ngx_posted_events of the connection
    pub posted: Rc<RefCell<VecDeque<Rc<QEvent>>>>,
    /// wakes the driver: an event posted or a timer set
    pub wake: Rc<tokio::sync::Notify>,
    /// the events of the application with timers
    pub app_events: RefCell<Vec<Weak<QEvent>>>,
}

impl QuicConnection {
    /// ngx_quic_get_send_ctx
    pub fn send_ctx(&self, level: usize) -> &RefCell<QuicSendCtx> {
        if level == NGX_QUIC_ENCRYPTION_INITIAL {
            &self.send_ctx[0]
        } else if level == NGX_QUIC_ENCRYPTION_HANDSHAKE {
            &self.send_ctx[1]
        } else {
            &self.send_ctx[2]
        }
    }

    /// ngx_quic_init_rtt
    pub fn init_rtt(&self) {
        self.avg_rtt.set(NGX_QUIC_INITIAL_RTT);
        self.rttvar.set(NGX_QUIC_INITIAL_RTT / 2);
        self.min_rtt.set(NGX_TIMER_INFINITE);
        self.first_rtt.set(NGX_TIMER_INFINITE);
        self.latest_rtt.set(0);
    }

    pub fn path(&self) -> Rc<QuicPath> {
        self.path.borrow().clone().expect("qc->path")
    }

    /// An event of the application whose timer the driver keeps.
    pub fn app_event(&self, handler: Box<dyn Fn()>) -> Rc<QEvent> {
        let ev = QEvent::new(QEventKind::App(handler), self);
        self.app_events.borrow_mut().push(Rc::downgrade(&ev));
        ev
    }
}

/// ngx_quic_get_connection
pub fn ngx_quic_get_connection(c: &Connection) -> Option<Rc<QuicConnection>> {
    c.quic_conn.borrow().clone()
}

/// ngx_quic_get_socket
pub fn ngx_quic_get_socket(c: &Connection) -> Option<Rc<QuicSocket>> {
    c.quic_sock.borrow().clone()
}

/// ngx_quic_connstate_dbg
pub fn ngx_quic_connstate_dbg(c: &Connection) {
    if !c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
        return;
    }

    let mut p = String::from("state:");

    let qc = ngx_quic_get_connection(c);
    let now = times::event_msec();

    if let Some(qc) = &qc {
        if qc.error.get() != 0 {
            p.push_str(if qc.error_app.get() { " app" } else { "" });
            p.push_str(&format!(" error:{}", qc.error.get()));

            if let Some(reason) = qc.error_reason.get() {
                p.push_str(&format!(" \"{}\"", reason));
            }
        }

        p.push_str(if qc.shutdown.get() { " shutdown" } else { "" });
        p.push_str(if qc.closing.get() { " closing" } else { "" });
        p.push_str(if qc.draining.get() { " draining" } else { "" });
        p.push_str(if qc.key_phase.get() { " kp" } else { "" });

        if let Some(key) = qc.read.timer.get() {
            p.push_str(&format!("{}{}", if qc.send_timer_set.get() { " send:" } else { " read:" }, key as i64 - now as i64));
        }

        if let Some(key) = qc.push.timer.get() {
            p.push_str(&format!(" push:{}", key as i64 - now as i64));
        }

        if let Some(key) = qc.pto.timer.get() {
            p.push_str(&format!(" pto:{}", key as i64 - now as i64));
        }

        if let Some(key) = qc.close.timer.get() {
            p.push_str(&format!(" close:{}", key as i64 - now as i64));
        }
    } else {
        p.push_str(" early");
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic {}", p);
}

/// ngx_quic_apply_transport_params
pub fn ngx_quic_apply_transport_params(c: &Connection, ctp: &QuicTp) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let scid = qc.path().cid.borrow().as_ref().map(|cid| cid.id.borrow().clone()).unwrap_or_default();

    if scid != ctp.initial_scid {
        qc.error.set(NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR);
        qc.error_reason.set(Some("invalid initial_source_connection_id"));

        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic client initial_source_connection_id mismatch");
        return NGX_ERROR;
    }

    if ctp.max_udp_payload_size < NGX_QUIC_MIN_INITIAL_SIZE as u64 || ctp.max_udp_payload_size > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE as u64 {
        qc.error.set(NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR);
        qc.error_reason.set(Some("invalid maximum packet size"));

        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic maximum packet size is invalid");
        return NGX_ERROR;
    }

    if ctp.active_connection_id_limit < 2 {
        qc.error.set(NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR);
        qc.error_reason.set(Some("invalid active_connection_id_limit"));

        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic active_connection_id_limit is invalid");
        return NGX_ERROR;
    }

    if ctp.ack_delay_exponent > 20 {
        qc.error.set(NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR);
        qc.error_reason.set(Some("invalid ack_delay_exponent"));

        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic ack_delay_exponent is invalid");
        return NGX_ERROR;
    }

    if ctp.max_ack_delay >= 16384 {
        qc.error.set(NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR);
        qc.error_reason.set(Some("invalid max_ack_delay"));

        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic max_ack_delay is invalid");
        return NGX_ERROR;
    }

    {
        let mut tp = qc.tp.borrow_mut();

        if ctp.max_idle_timeout > 0 && ctp.max_idle_timeout < tp.max_idle_timeout {
            tp.max_idle_timeout = ctp.max_idle_timeout;
        }
    }

    qc.streams.server_max_streams_bidi.set(ctp.initial_max_streams_bidi);
    qc.streams.server_max_streams_uni.set(ctp.initial_max_streams_uni);

    *qc.ctp.borrow_mut() = ctp.clone();

    NGX_OK
}

/// ngx_quic_run: the first datagram of the connection (c->buffer); the
/// driver runs the connection then
pub fn ngx_quic_run(c: &Rc<Connection>, conf: &Rc<QuicConf>) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic run");

    let data = std::mem::take(&mut *c.buffer.borrow_mut());

    let rc = ngx_quic_handle_datagram(c, &data, Some(conf));

    if rc != NGX_OK {
        ngx_quic_close_connection(c, rc);
        return;
    }

    /* quic connection is now created */
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let idle = qc.tp.borrow().max_idle_timeout;
    qc.read.add_timer(idle);

    if !qc.streams.initialized.get() {
        qc.close.add_timer(qc.conf.handshake_timeout);
    }

    ngx_quic_connstate_dbg(c);

    // c->read->handler = ngx_quic_input_handler

    *c.close_handler.borrow_mut() = Some(Rc::new(|c: &Rc<Connection>| ngx_quic_input_handler(c, None)));

    let c2 = c.clone();
    crate::event::spawn(async move {
        ngx_quic_drive(c2).await;
    });
}

/// ngx_quic_new_connection
fn ngx_quic_new_connection(c: &Rc<Connection>, conf: &Rc<QuicConf>, pkt: &QuicHeader<'_>) -> Option<Rc<QuicConnection>> {
    let posted = Rc::new(RefCell::new(VecDeque::new()));
    let wake = Rc::new(tokio::sync::Notify::new());

    let ev = |kind: QEventKind| Rc::new(QEvent { timer: Cell::new(None), posted: Cell::new(false), timedout: Cell::new(false), kind, wake: wake.clone(), queue: Rc::downgrade(&posted) });

    let qc = Rc::new(QuicConnection {
        version: Cell::new(pkt.version),
        path: RefCell::new(None),
        sockets: RefCell::new(Vec::new()),
        paths: RefCell::new(Vec::new()),
        client_ids: RefCell::new(Vec::new()),
        nsockets: Cell::new(0),
        nclient_ids: Cell::new(0),
        max_retired_seqnum: Cell::new(0),
        client_seqnum: Cell::new(0),
        server_seqnum: Cell::new(0),
        path_seqnum: Cell::new(0),
        tp: RefCell::new(QuicTp::default()),
        ctp: RefCell::new(QuicTp::default()),
        send_ctx: [RefCell::new(QuicSendCtx::new(NGX_QUIC_ENCRYPTION_INITIAL)), RefCell::new(QuicSendCtx::new(NGX_QUIC_ENCRYPTION_HANDSHAKE)), RefCell::new(QuicSendCtx::new(NGX_QUIC_ENCRYPTION_APPLICATION))],
        keys: Rc::new(RefCell::new(QuicKeys::default())),
        conf: conf.clone(),
        read: ev(QEventKind::Read),
        push: ev(QEventKind::Push),
        pto: ev(QEventKind::Pto),
        close: ev(QEventKind::Close),
        path_validation: ev(QEventKind::PathValidation),
        key_update: ev(QEventKind::KeyUpdate),
        pto_lost: Cell::new(false),
        last_cc: Cell::new(0),
        first_rtt: Cell::new(0),
        latest_rtt: Cell::new(0),
        avg_rtt: Cell::new(0),
        min_rtt: Cell::new(0),
        rttvar: Cell::new(0),
        pto_count: Cell::new(0),
        nframes: Cell::new(0),
        free_frames: Cell::new(0),
        max_frames: Cell::new(0),
        compat: RefCell::new(None),
        streams: QuicStreams::default(),
        congestion: QuicCongestion::default(),
        rst_pnum: Cell::new(0),
        received: Cell::new(0),
        error: Cell::new(0),
        error_level: Cell::new(0),
        error_ftype: Cell::new(0),
        error_reason: Cell::new(None),
        shutdown_code: Cell::new(0),
        shutdown_reason: Cell::new(None),
        error_app: Cell::new(false),
        send_timer_set: Cell::new(false),
        closing: Cell::new(false),
        shutdown: Cell::new(false),
        draining: Cell::new(false),
        key_phase: Cell::new(false),
        validated: Cell::new(false),
        client_tp_done: Cell::new(false),
        udp_buffer: Cell::new(false),
        write_error: Cell::new(false),
        posted,
        wake,
        app_events: RefCell::new(Vec::new()),
    });

    qc.init_rtt();

    if ngx_quic_init_transport_params(&mut qc.tp.borrow_mut(), conf) != NGX_OK {
        return None;
    }

    {
        let mut ctp = qc.ctp.borrow_mut();

        /* defaults to be used before actual client parameters are received */
        ctp.max_udp_payload_size = NGX_QUIC_MAX_UDP_PAYLOAD_SIZE as u64;
        ctp.ack_delay_exponent = NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT;
        ctp.max_ack_delay = NGX_QUIC_DEFAULT_MAX_ACK_DELAY;
        ctp.active_connection_id_limit = 2;
    }

    {
        let tp = qc.tp.borrow();

        qc.streams.recv_max_data.set(tp.initial_max_data);
        qc.streams.recv_window.set(qc.streams.recv_max_data.get());

        qc.streams.client_max_streams_uni.set(tp.initial_max_streams_uni);
        qc.streams.client_max_streams_bidi.set(tp.initial_max_streams_bidi);
    }

    qc.congestion.window.set((10 * NGX_QUIC_MIN_INITIAL_SIZE).min((2 * NGX_QUIC_MIN_INITIAL_SIZE).max(14720)));
    qc.congestion.ssthresh.set(usize::MAX);
    qc.congestion.mtu.set(NGX_QUIC_MIN_INITIAL_SIZE);
    qc.congestion.recovery_start.set(times::event_msec().wrapping_sub(1));

    qc.max_frames.set(((conf.max_concurrent_streams_uni + conf.max_concurrent_streams_bidi) as usize * conf.stream_buffer_size) / 2000);

    if pkt.validated && pkt.retried {
        qc.tp.borrow_mut().retry_scid = pkt.dcid.clone();
    }

    if ngx_quic_keys_set_initial_secret(&mut qc.keys.borrow_mut(), &pkt.dcid, &c.log) != NGX_OK {
        return None;
    }

    qc.validated.set(pkt.validated);

    if socket::ngx_quic_open_sockets(c, &qc, pkt) != NGX_OK {
        ngx_quic_keys_cleanup(&mut qc.keys.borrow_mut());
        return None;
    }

    c.idle.set(true);
    c.reusable_connection(true);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic connection created");

    Some(qc)
}

/// ngx_quic_handle_stateless_reset
fn ngx_quic_handle_stateless_reset(c: &Connection, pkt: &QuicHeader<'_>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_DECLINED,
    };

    /* A stateless reset uses an entire UDP datagram */
    if !pkt.first {
        return NGX_DECLINED;
    }

    if pkt.raw.len() < NGX_QUIC_SR_TOKEN_LEN {
        return NGX_DECLINED;
    }

    let tail = &pkt.raw[pkt.raw.len() - NGX_QUIC_SR_TOKEN_LEN..];

    for cid in qc.client_ids.borrow().iter() {
        if cid.seqnum.get() == 0 || !cid.used.get() {
            // No stateless reset token in initial connection id.
            // Don't accept a token from an unused connection id.
            continue;
        }

        /* constant time comparison */

        let token = cid.sr_token.borrow();
        let mut ch = 0u8;

        for i in 0..NGX_QUIC_SR_TOKEN_LEN {
            ch |= tail[i] ^ token[i];
        }

        if ch == 0 {
            return NGX_OK;
        }
    }

    NGX_DECLINED
}

/// ngx_quic_input_handler: a datagram (c->udp->buffer), the timeout of the
/// connection, or c->close
fn ngx_quic_input_handler(c: &Rc<Connection>, datagram: Option<&[u8]>) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic input handler");

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    c.log.set_action(Some("handling quic input"));

    if qc.read.timedout.get() {
        ngx_log_error!(NGX_LOG_INFO, c.log, Some(libc::ETIMEDOUT), "quic client timed out");
        ngx_quic_close_connection(c, NGX_DONE);
        return;
    }

    if c.close.get() {
        c.close.set(false);

        if !crate::event::is_exiting() || !qc.streams.initialized.get() {
            qc.error.set(NGX_QUIC_ERR_NO_ERROR);
            qc.error_reason.set(Some("graceful shutdown"));
            ngx_quic_close_connection(c, NGX_ERROR);
            return;
        }

        if !qc.closing.get() {
            if let Some(shutdown) = qc.conf.shutdown.clone() {
                shutdown(c);
            }
        }

        return;
    }

    let b = match datagram {
        Some(b) => b,
        None => return,
    };

    let rc = ngx_quic_handle_datagram(c, b, None);

    if rc == NGX_ERROR {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    if rc == NGX_DONE {
        return;
    }

    /* rc == NGX_OK */

    qc.send_timer_set.set(false);
    let idle = qc.tp.borrow().max_idle_timeout;
    qc.read.add_timer(idle);

    ngx_quic_connstate_dbg(c);
}

/// ngx_quic_close_connection
pub fn ngx_quic_close_connection(c: &Rc<Connection>, rc: i64) {
    let qc = ngx_quic_get_connection(c);

    let qc = match qc {
        None => {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic packet rejected rc:{}, cleanup connection", rc);
            quic_done(c, None);
            return;
        }

        Some(qc) => qc,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic close {} rc:{}", if qc.closing.get() { "resumed" } else { "initiated" }, rc);

    if !qc.closing.get() {
        /* drop packets from retransmit queues, no ack is expected */
        for i in 0..NGX_QUIC_SEND_CTX_LAST {
            let (frames, sent) = {
                let mut ctx = qc.send_ctx[i].borrow_mut();
                (std::mem::take(&mut ctx.frames), std::mem::take(&mut ctx.sent))
            };

            ngx_quic_free_frames(c, frames);
            ngx_quic_free_frames(c, sent);
        }

        if qc.close.timer_set() {
            qc.close.del_timer();
        }

        if rc == NGX_DONE {
            // RFC 9000, 10.1.  Idle Timeout
            //
            //  If a max_idle_timeout is specified by either endpoint in its
            //  transport parameters (Section 18.2), the connection is silently
            //  closed and its state is discarded when it remains idle

            /* this case also handles some errors from ngx_quic_run() */

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic close silent drain:{} timedout:{}", qc.draining.get() as u32, qc.read.timedout.get() as u32);
        } else {
            // RFC 9000, 10.2.  Immediate Close
            //
            //  An endpoint sends a CONNECTION_CLOSE frame (Section 19.19)
            //  to terminate the connection immediately.

            if qc.error.get() == 0 && rc == NGX_ERROR {
                qc.error.set(NGX_QUIC_ERR_INTERNAL_ERROR);
                qc.error_app.set(false);
            }

            ngx_log_debug!(
                NGX_LOG_DEBUG_EVENT,
                c.log,
                "quic close immediate term:{} drain:{} {}error:{} \"{}\"",
                if rc == NGX_ERROR { 1 } else { 0 },
                qc.draining.get() as u32,
                if qc.error_app.get() { "app " } else { "" },
                qc.error.get(),
                qc.error_reason.get().unwrap_or("")
            );

            for i in 0..NGX_QUIC_SEND_CTX_LAST {
                let level = qc.send_ctx[i].borrow().level;

                if !ngx_quic_keys_available(&qc.keys.borrow(), level, true) {
                    continue;
                }

                qc.error_level.set(level);
                let _ = output::ngx_quic_send_cc(c);

                if rc == NGX_OK {
                    let pto = ack::ngx_quic_pto(c, level);
                    qc.close.add_timer(3 * pto);
                }
            }
        }

        qc.closing.set(true);
    }

    if rc == NGX_ERROR && qc.close.timer_set() {
        /* do not wait for timer in case of fatal error */
        qc.close.del_timer();
    }

    if streams::ngx_quic_close_streams(c, &qc) == NGX_AGAIN {
        return;
    }

    if qc.push.timer_set() {
        qc.push.del_timer();
    }

    if qc.pto.timer_set() {
        qc.pto.del_timer();
    }

    if qc.path_validation.timer_set() {
        qc.path_validation.del_timer();
    }

    if qc.push.posted.get() {
        qc.push.delete_posted();
    }

    if qc.key_update.posted.get() {
        qc.key_update.delete_posted();
    }

    if qc.close.timer_set() {
        return;
    }

    if qc.close.posted.get() {
        qc.close.delete_posted();
    }

    socket::ngx_quic_close_sockets(c);

    ngx_quic_keys_cleanup(&mut qc.keys.borrow_mut());

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic close completed");

    /* may be tested from SSL callback during SSL shutdown */
    *c.quic_conn.borrow_mut() = None;
    *c.quic_sock.borrow_mut() = None;

    // the application's events end with the connection
    qc.app_events.borrow_mut().clear();
    qc.posted.borrow_mut().clear();
    qc.wake.notify_one();

    quic_done(c, Some(&qc));
}

/// quic_done: the end of ngx_quic_close_connection
fn quic_done(c: &Rc<Connection>, qc: Option<&QuicConnection>) {
    if c.ssl.borrow().is_some() {
        let _ = crate::event_openssl::ngx_ssl_shutdown(c);
    }

    if let Some(qc) = qc {
        if qc.read.timer_set() {
            qc.read.del_timer();
        }
    }

    // ngx_stat_active is decremented by ngx_close_connection() here

    c.destroyed.set(true);

    c.close();
}

/// ngx_quic_finalize_connection
pub fn ngx_quic_finalize_connection(c: &Connection, err: u64, reason: Option<&'static str>) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    if qc.closing.get() {
        return;
    }

    qc.error.set(err);
    qc.error_reason.set(reason);
    qc.error_app.set(true);
    qc.error_ftype.set(0);

    qc.close.post();
}

/// ngx_quic_shutdown_connection
pub fn ngx_quic_shutdown_connection(c: &Connection, err: u64, reason: Option<&'static str>) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    qc.shutdown.set(true);
    qc.shutdown_code.set(err);
    qc.shutdown_reason.set(reason);

    ngx_quic_shutdown_quic(c);
}

/// ngx_quic_close_handler
fn ngx_quic_close_handler(c: &Rc<Connection>) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic close handler");

    ngx_quic_close_connection(c, NGX_OK);
}

/// ngx_quic_handle_datagram
fn ngx_quic_handle_datagram(c: &Rc<Connection>, b: &[u8], conf: Option<&Rc<QuicConf>>) -> i64 {
    let mut good = false;
    let mut path: Option<Rc<QuicPath>> = None;

    let size = b.len();

    let mut p = 0usize;

    while p < b.len() {
        let mut pkt = QuicHeader {
            raw: b,
            data: p,
            len: b.len() - p,
            log: Some(c.log.clone()),
            first: p == 0,
            path: path.clone(),
            flags: b[p],
            raw_pos: p + 1,
            ..Default::default()
        };

        let rc = ngx_quic_handle_packet(c, conf, &mut pkt);

        if pkt.parsed {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic packet done rc:{} level:{} decr:{} pn:{} perr:{}", rc, ngx_quic_level_name(pkt.level), pkt.decrypted as u32, pkt.pn as i64, pkt.error);
        } else {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic packet done rc:{} parse failed", rc);
        }

        if rc == NGX_ERROR || rc == NGX_DONE {
            return rc;
        }

        if rc == NGX_OK {
            good = true;
        }

        path = pkt.path.clone(); /* preserve packet path from 1st packet */

        /* NGX_OK || NGX_DECLINED */

        // we get NGX_DECLINED when there are no keys [yet] available
        // to decrypt packet.
        // Instead of queueing it, we ignore it and rely on the sender's
        // retransmission:
        //
        // RFC 9000, 12.2.  Coalescing Packets
        //
        // For example, if decryption fails (because the keys are
        // not available or for any other reason), the receiver MAY either
        // discard or buffer the packet for later processing and MUST
        // attempt to process the remaining packets.
        //
        // We also skip packets that don't match connection state
        // or cannot be parsed properly.

        /* b->pos is at header end, adjust by actual packet length */
        p = pkt.data + pkt.len;
    }

    if !good {
        return NGX_DONE;
    }

    if let Some(qc) = ngx_quic_get_connection(c) {
        qc.received.set(qc.received.get() + size as i64);

        if (c.sent.get() + qc.received.get() as u64) / 8 > (qc.streams.sent.get() + qc.streams.recv_last.get()) + 1048576 {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic flood detected");

            qc.error.set(NGX_QUIC_ERR_NO_ERROR);
            qc.error_reason.set(Some("QUIC flood detected"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_quic_handle_packet
fn ngx_quic_handle_packet(c: &Rc<Connection>, conf: Option<&Rc<QuicConf>>, pkt: &mut QuicHeader<'_>) -> i64 {
    c.log.set_action(Some("parsing quic packet"));

    let rc = ngx_quic_parse_packet(pkt);

    if rc == NGX_ERROR {
        return NGX_DECLINED;
    }

    pkt.parsed = true;

    c.log.set_action(Some("handling quic packet"));

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic packet rx dcid len:{} {}", pkt.dcid.len(), hex(&pkt.dcid));

    if pkt.level != NGX_QUIC_ENCRYPTION_APPLICATION {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic packet rx scid len:{} {}", pkt.scid.len(), hex(&pkt.scid));
    }

    if pkt.level == NGX_QUIC_ENCRYPTION_INITIAL {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic address validation token len:{} {}", pkt.token.len(), hex(&pkt.token));
    }

    if let Some(qc) = ngx_quic_get_connection(c) {
        if rc == NGX_ABORT {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic unsupported version: 0x{:x}", pkt.version);
            return NGX_DECLINED;
        }

        if pkt.level != NGX_QUIC_ENCRYPTION_APPLICATION {
            if pkt.version != qc.version.get() {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic version mismatch: 0x{:x}", pkt.version);
                return NGX_DECLINED;
            }

            if pkt.first {
                if let Some(qsock) = ngx_quic_get_socket(c) {
                    let path = qc.path();

                    if crate::inet::cmp_sockaddr(&qsock.sockaddr.borrow(), &path.sockaddr.borrow(), true) != NGX_OK {
                        /* packet comes from unknown path, possibly migration */
                        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic too early migration attempt");
                        return NGX_DONE;
                    }
                }
            }

            if ngx_quic_check_csid(&qc, pkt) != NGX_OK {
                return NGX_DECLINED;
            }
        }

        let rc = ngx_quic_handle_payload(c, pkt);

        if rc == NGX_DECLINED && pkt.level == NGX_QUIC_ENCRYPTION_APPLICATION && ngx_quic_handle_stateless_reset(c, pkt) == NGX_OK {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic stateless reset packet detected");

            qc.draining.set(true);
            qc.close.post();

            return NGX_OK;
        }

        return rc;
    }

    /* packet does not belong to a connection */

    let conf = match conf {
        Some(conf) => conf.clone(),
        None => return NGX_DECLINED,
    };

    if rc == NGX_ABORT {
        return output::ngx_quic_negotiate_version(c, pkt);
    }

    if pkt.level == NGX_QUIC_ENCRYPTION_APPLICATION {
        return output::ngx_quic_send_stateless_reset(c, &conf, pkt);
    }

    if pkt.level != NGX_QUIC_ENCRYPTION_INITIAL {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic expected initial, got handshake");
        return NGX_ERROR;
    }

    c.log.set_action(Some("handling initial packet"));

    if pkt.dcid.len() < NGX_QUIC_CID_LEN_MIN {
        /* RFC 9000, 7.2.  Negotiating Connection IDs */
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic too short dcid in initial packet: len:{}", pkt.dcid.len());
        return NGX_ERROR;
    }

    /* process retry and initialize connection IDs */

    if !pkt.token.is_empty() {
        let rc = tokens::ngx_quic_validate_token(c, &conf.av_token_key, pkt);

        if rc == NGX_ERROR {
            /* internal error */
            return NGX_ERROR;
        } else if rc == NGX_ABORT {
            /* token cannot be decrypted */
            return output::ngx_quic_send_early_cc(c, pkt, NGX_QUIC_ERR_INVALID_TOKEN, "cannot decrypt token");
        } else if rc == NGX_DECLINED {
            /* token is invalid */

            if pkt.retried {
                /* invalid address validation token */
                return output::ngx_quic_send_early_cc(c, pkt, NGX_QUIC_ERR_INVALID_TOKEN, "invalid address validation token");
            } else if conf.retry {
                /* invalid NEW_TOKEN */
                return output::ngx_quic_send_retry(c, &conf, pkt);
            }
        }

        /* NGX_OK */
    } else if conf.retry {
        return output::ngx_quic_send_retry(c, &conf, pkt);
    } else {
        pkt.odcid = pkt.dcid.clone();
    }

    if crate::process::SIG_TERMINATE.load(std::sync::atomic::Ordering::SeqCst) || crate::event::is_exiting() {
        if conf.retry {
            return output::ngx_quic_send_retry(c, &conf, pkt);
        }

        return NGX_ERROR;
    }

    c.log.set_action(Some("creating quic connection"));

    if ngx_quic_new_connection(c, &conf, pkt).is_none() {
        return NGX_ERROR;
    }

    ngx_quic_handle_payload(c, pkt)
}

/// ngx_quic_handle_payload
fn ngx_quic_handle_payload(c: &Rc<Connection>, pkt: &mut QuicHeader<'_>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    qc.error.set(0);
    qc.error_reason.set(None);

    c.log.set_action(Some("decrypting packet"));

    if !ngx_quic_keys_available(&qc.keys.borrow(), pkt.level, false) {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic no {} keys, ignoring packet", ngx_quic_level_name(pkt.level));
        return NGX_DECLINED;
    }

    pkt.keys = Some(qc.keys.clone());
    pkt.key_phase = qc.key_phase.get();

    let mut largest_pn = qc.send_ctx(pkt.level).borrow().largest_pn;

    let rc = ngx_quic_decrypt(pkt, &mut largest_pn);

    qc.send_ctx(pkt.level).borrow_mut().largest_pn = largest_pn;

    if rc != NGX_OK {
        qc.error.set(pkt.error);
        qc.error_reason.set(Some("failed to decrypt packet"));
        return rc;
    }

    pkt.decrypted = true;

    c.log.set_action(Some("handling decrypted packet"));

    if pkt.path.is_none() {
        let rc = migration::ngx_quic_set_path(c, pkt);
        if rc != NGX_OK {
            return rc;
        }
    }

    if c.ssl.borrow().is_none() && ssl::ngx_quic_init_connection(c) != NGX_OK {
        return NGX_ERROR;
    }

    if pkt.level == NGX_QUIC_ENCRYPTION_HANDSHAKE {
        // RFC 9001, 4.9.1.  Discarding Initial Keys
        //
        // The successful use of Handshake packets indicates
        // that no more Initial packets need to be exchanged
        ngx_quic_discard_ctx(c, NGX_QUIC_ENCRYPTION_INITIAL);

        let path = qc.path();

        if !path.validated.get() {
            path.validated.set(true);
            migration::ngx_quic_path_dbg(c, "in handshake", &path);
            qc.push.post();
        }
    }

    if pkt.level == NGX_QUIC_ENCRYPTION_APPLICATION {
        // RFC 9001, 4.9.3.  Discarding 0-RTT Keys
        //
        // After receiving a 1-RTT packet, servers MUST discard
        // 0-RTT keys within a short time
        ngx_quic_keys_discard(&mut qc.keys.borrow_mut(), NGX_QUIC_ENCRYPTION_EARLY_DATA);
    }

    if qc.closing.get() {
        // RFC 9000, 10.2.  Immediate Close
        //
        // ... delayed or reordered packets are properly discarded.
        //
        //  In the closing state, an endpoint retains only enough information
        //  to generate a packet containing a CONNECTION_CLOSE frame and to
        //  identify packets as belonging to the connection.

        qc.error_level.set(pkt.level);
        qc.error.set(NGX_QUIC_ERR_NO_ERROR);
        qc.error_reason.set(Some("connection is closing, packet discarded"));
        qc.error_ftype.set(0);
        qc.error_app.set(false);

        return output::ngx_quic_send_cc(c);
    }

    pkt.received = times::event_msec();

    c.log.set_action(Some("handling payload"));

    if pkt.level != NGX_QUIC_ENCRYPTION_APPLICATION {
        return ngx_quic_handle_frames(c, pkt);
    }

    if !pkt.key_update {
        return ngx_quic_handle_frames(c, pkt);
    }

    /* switch keys and generate next on Key Phase change */

    qc.key_phase.set(!qc.key_phase.get());
    ngx_quic_keys_switch(c, &mut qc.keys.borrow_mut());

    let rc = ngx_quic_handle_frames(c, pkt);
    if rc != NGX_OK {
        return rc;
    }

    qc.key_update.post();

    NGX_OK
}

/// ngx_quic_discard_ctx
pub fn ngx_quic_discard_ctx(c: &Rc<Connection>, level: usize) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    {
        let keys = qc.keys.borrow();

        if !ngx_quic_keys_available(&keys, level, false) && !ngx_quic_keys_available(&keys, level, true) {
            return;
        }
    }

    ngx_quic_keys_discard(&mut qc.keys.borrow_mut(), level);

    qc.pto_count.set(0);

    let (sent, frames) = {
        let mut ctx = qc.send_ctx(level).borrow_mut();

        ngx_quic_free_buffer(c, &mut ctx.crypto);

        (std::mem::take(&mut ctx.sent), std::mem::take(&mut ctx.frames))
    };

    for f in sent {
        ack::ngx_quic_congestion_ack(c, &f);
        ngx_quic_free_frame(c, f);
    }

    for f in frames {
        ngx_quic_free_frame(c, f);
    }

    if level == NGX_QUIC_ENCRYPTION_INITIAL {
        /* close temporary listener with initial dcid */
        if let Some(qsock) = socket::ngx_quic_find_socket(c, NGX_QUIC_UNSET_PN) {
            socket::ngx_quic_close_socket(c, &qsock);
        }
    }

    qc.send_ctx(level).borrow_mut().send_ack = 0;

    ack::ngx_quic_set_lost_timer(c);
}

/// ngx_quic_check_csid
fn ngx_quic_check_csid(qc: &QuicConnection, pkt: &QuicHeader<'_>) -> i64 {
    for cid in qc.client_ids.borrow().iter() {
        if pkt.scid == *cid.id.borrow() {
            return NGX_OK;
        }
    }

    ngx_log_error!(NGX_LOG_INFO, pkt.log(), None, "quic unexpected quic scid");
    NGX_ERROR
}

/// ngx_quic_handle_frames
fn ngx_quic_handle_frames(c: &Rc<Connection>, pkt: &mut QuicHeader<'_>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let payload = std::mem::take(&mut pkt.payload);

    let mut p = 0usize;
    let end = payload.len();

    let mut do_close = false;
    let mut nonprobing = false;

    while p < end {
        c.log.set_action(Some("parsing frames"));

        let mut frame = QuicFrame::default();
        let mut data = (0usize, 0usize);

        let len = ngx_quic_parse_frame(pkt, &payload, p, end, &mut frame, &mut data);

        if len < 0 {
            qc.error.set(pkt.error);
            pkt.payload = payload;
            return NGX_ERROR;
        }

        let data = &payload[data.0..data.1];

        frames::ngx_quic_log_frame(&c.log, &frame, data, false);

        c.log.set_action(Some("handling frames"));

        p += len as usize;

        match frame.ty {
            /* probing frames */
            NGX_QUIC_FT_PADDING | NGX_QUIC_FT_PATH_CHALLENGE | NGX_QUIC_FT_PATH_RESPONSE | NGX_QUIC_FT_NEW_CONNECTION_ID => {}

            /* non-probing frames */
            _ => nonprobing = true,
        }

        match frame.ty {
            NGX_QUIC_FT_ACK => {
                if ack::ngx_quic_handle_ack_frame(c, pkt, &frame, data) != NGX_OK {
                    return NGX_ERROR;
                }

                continue;
            }

            NGX_QUIC_FT_PADDING => {
                /* no action required */
                continue;
            }

            NGX_QUIC_FT_CONNECTION_CLOSE | NGX_QUIC_FT_CONNECTION_CLOSE_APP => {
                do_close = true;
                continue;
            }

            _ => {}
        }

        /* got there with ack-eliciting packet */
        pkt.need_ack = true;

        let rc = match frame.ty {
            NGX_QUIC_FT_CRYPTO => ssl::ngx_quic_handle_crypto_frame(c, pkt, &frame, data),

            NGX_QUIC_FT_PING => NGX_OK,

            NGX_QUIC_FT_STREAM => streams::ngx_quic_handle_stream_frame(c, pkt, &frame, data),

            NGX_QUIC_FT_MAX_DATA => streams::ngx_quic_handle_max_data_frame(c, &frame.u.max_data),

            NGX_QUIC_FT_STREAMS_BLOCKED | NGX_QUIC_FT_STREAMS_BLOCKED2 => streams::ngx_quic_handle_streams_blocked_frame(c, pkt, &frame.u.streams_blocked),

            NGX_QUIC_FT_DATA_BLOCKED => streams::ngx_quic_handle_data_blocked_frame(c, pkt, &frame.u.data_blocked),

            NGX_QUIC_FT_STREAM_DATA_BLOCKED => streams::ngx_quic_handle_stream_data_blocked_frame(c, pkt, &frame.u.stream_data_blocked),

            NGX_QUIC_FT_MAX_STREAM_DATA => streams::ngx_quic_handle_max_stream_data_frame(c, pkt, &frame.u.max_stream_data),

            NGX_QUIC_FT_RESET_STREAM => streams::ngx_quic_handle_reset_stream_frame(c, pkt, &frame.u.reset_stream),

            NGX_QUIC_FT_STOP_SENDING => streams::ngx_quic_handle_stop_sending_frame(c, pkt, &frame.u.stop_sending),

            NGX_QUIC_FT_MAX_STREAMS | NGX_QUIC_FT_MAX_STREAMS2 => streams::ngx_quic_handle_max_streams_frame(c, pkt, &frame.u.max_streams),

            NGX_QUIC_FT_PATH_CHALLENGE => migration::ngx_quic_handle_path_challenge_frame(c, pkt, &frame.u.path_challenge),

            NGX_QUIC_FT_PATH_RESPONSE => migration::ngx_quic_handle_path_response_frame(c, &frame.u.path_challenge),

            NGX_QUIC_FT_NEW_CONNECTION_ID => connid::ngx_quic_handle_new_connection_id_frame(c, &frame.u.ncid),

            NGX_QUIC_FT_RETIRE_CONNECTION_ID => connid::ngx_quic_handle_retire_connection_id_frame(c, &frame.u.retire_cid),

            _ => {
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic missing frame handler");
                return NGX_ERROR;
            }
        };

        if rc != NGX_OK {
            return NGX_ERROR;
        }
    }

    if p != end {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic trailing garbage in payload:{} bytes", end - p);

        qc.error.set(NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
        return NGX_ERROR;
    }

    if do_close {
        qc.draining.set(true);
        qc.close.post();
    }

    let on_path = match (&pkt.path, qc.path.borrow().as_ref()) {
        (Some(a), Some(b)) => Rc::ptr_eq(a, b),
        _ => false,
    };

    if !on_path && nonprobing {
        // RFC 9000, 9.2.  Initiating Connection Migration
        //
        // An endpoint can migrate a connection to a new local
        // address by sending packets containing non-probing frames
        // from that address.
        if migration::ngx_quic_handle_migration(c, pkt) != NGX_OK {
            return NGX_ERROR;
        }
    }

    if ack::ngx_quic_ack_packet(c, pkt) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_push_handler
fn ngx_quic_push_handler(c: &Rc<Connection>) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic push handler");

    if output::ngx_quic_output(c) != NGX_OK {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    ngx_quic_connstate_dbg(c);
}

/// ngx_quic_shutdown_quic
pub fn ngx_quic_shutdown_quic(c: &Connection) {
    if c.reusable.get() {
        if let Some(qc) = ngx_quic_get_connection(c) {
            ngx_quic_finalize_connection(c, qc.shutdown_code.get(), qc.shutdown_reason.get());
        }
    }
}

/// ngx_quic_address_hash
pub fn ngx_quic_address_hash(sockaddr: &SockAddr, no_port: bool, salt: Option<&[u8]>) -> [u8; 20] {
    use sha1::{Digest, Sha1};

    // the address without the port, or the sockaddr of c->socklen bytes
    let data: Vec<u8> = match sockaddr {
        SockAddr::V6(sin6) if no_port => sin6.ip().octets().to_vec(),
        SockAddr::V4(sin) if no_port => sin.ip().octets().to_vec(),
        _ => sockaddr.raw_bytes(),
    };

    let mut sha1 = Sha1::new();
    sha1.update(&data);

    if let Some(salt) = salt {
        sha1.update(salt);
    }

    sha1.finalize().into()
}

/// ngx_quic_get_send_ctx as an index of qc->send_ctx
pub fn ngx_quic_send_ctx_index(level: usize) -> usize {
    if level == NGX_QUIC_ENCRYPTION_INITIAL {
        0
    } else if level == NGX_QUIC_ENCRYPTION_HANDSHAKE {
        1
    } else {
        2
    }
}

/// A datagram of the connection from the listening (ngx_quic_recvmsg):
/// the read handler with c->udp->buffer set.
pub fn ngx_quic_input(c: &Rc<Connection>, data: &[u8]) {
    let qc = ngx_quic_get_connection(c);

    if let Some(qc) = &qc {
        qc.udp_buffer.set(true);
    }

    ngx_quic_input_handler(c, Some(data));

    if let Some(qc) = &qc {
        qc.udp_buffer.set(false);
    }
}

/// The driver of a QUIC connection: the expired timers, then the posted
/// events, as an iteration of ngx_process_events_and_timers() (the
/// datagrams are handled when they are read, see udp.rs).
async fn ngx_quic_drive(c: Rc<Connection>) {
    loop {
        let qc = match ngx_quic_get_connection(&c) {
            Some(qc) => qc,
            None => return,
        };

        // ngx_close_idle_connections(): c->close and the read handler

        if c.close.get() {
            drop(qc);
            ngx_quic_input_handler(&c, None);
            continue;
        }

        // the expired timers, in the order of their expiry

        let now = times::event_msec();
        let mut expired: Vec<(u64, Rc<QEvent>)> = Vec::new();

        let app: Vec<Rc<QEvent>> = {
            let mut events = qc.app_events.borrow_mut();
            events.retain(|w| w.strong_count() > 0);
            events.iter().filter_map(|w| w.upgrade()).collect()
        };

        for ev in [&qc.read, &qc.push, &qc.pto, &qc.close, &qc.path_validation].into_iter().chain(app.iter()) {
            if let Some(key) = ev.timer.get() {
                if key <= now {
                    expired.push((key, ev.clone()));
                }
            }
        }

        drop(app);
        drop(qc);

        expired.sort_by_key(|(k, _)| *k);

        for (_, ev) in expired {
            if ngx_quic_get_connection(&c).is_none() {
                return;
            }

            if ev.timer.get().is_none_or(|k| k > now) {
                continue;
            }

            ev.timer.set(None);
            ev.timedout.set(true);

            run_event(&c, &ev);

            ev.timedout.set(false);
        }

        run_posted(&c).await;

        let qc = match ngx_quic_get_connection(&c) {
            Some(qc) => qc,
            None => return,
        };

        if !qc.posted.borrow().is_empty() || c.close.get() {
            continue;
        }

        // the next timer

        let mut next: Option<u64> = None;

        let app: Vec<Rc<QEvent>> = qc.app_events.borrow().iter().filter_map(|w| w.upgrade()).collect();

        for ev in [&qc.read, &qc.push, &qc.pto, &qc.close, &qc.path_validation].into_iter().chain(app.iter()) {
            if let Some(key) = ev.timer.get() {
                next = Some(next.map_or(key, |n: u64| n.min(key)));
            }
        }

        drop(app);

        let wake = qc.wake.clone();

        drop(qc);

        let notified = wake.notified();
        let close = c.close_notify.notified();

        tokio::pin!(notified);
        tokio::pin!(close);

        // the notifications from now on wake the driver
        notified.as_mut().enable();
        close.as_mut().enable();

        let posted = ngx_quic_get_connection(&c).is_some_and(|qc| !qc.posted.borrow().is_empty());

        if posted || c.close.get() {
            continue;
        }

        if let Some(key) = next {
            if key <= times::current_msec() {
                // the timer is due, with the time of the next iteration
                times::update_event_msec();
                continue;
            }
        }

        let sleep = async {
            match next {
                Some(key) => {
                    let delay = key.saturating_sub(times::current_msec());
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            _ = notified => {}
            _ = close => {}
            _ = sleep => {}
        }
    }
}

/// The posted events of the connection, in order; a stream's event wakes
/// its task, which runs before the next event (ngx_event_process_posted).
async fn run_posted(c: &Rc<Connection>) {
    loop {
        let qc = match ngx_quic_get_connection(c) {
            Some(qc) => qc,
            None => return,
        };

        let ev = qc.posted.borrow_mut().pop_front();

        let ev = match ev {
            Some(ev) => ev,
            None => return,
        };

        if !ev.posted.get() {
            continue;
        }

        ev.posted.set(false);

        drop(qc);

        let stream_event = matches!(ev.kind, QEventKind::StreamRead(_) | QEventKind::StreamWrite(_));

        run_event(c, &ev);

        if stream_event {
            yield_to_tasks().await;
        }
    }
}

/// Let the tasks woken so far run to their next wait.
pub async fn yield_to_tasks() {
    let mut yielded = false;

    std::future::poll_fn(|cx| {
        if yielded {
            return std::task::Poll::Ready(());
        }

        yielded = true;
        cx.waker().wake_by_ref();

        std::task::Poll::Pending
    })
    .await
}

/// The handler of an event.
fn run_event(c: &Rc<Connection>, ev: &Rc<QEvent>) {
    match &ev.kind {
        QEventKind::Read => ngx_quic_input_handler(c, None),

        QEventKind::Push => ngx_quic_push_handler(c),

        QEventKind::Pto => {
            let lost = ngx_quic_get_connection(c).is_some_and(|qc| qc.pto_lost.get());

            if lost {
                ack::ngx_quic_lost_handler(c);
            } else {
                ack::ngx_quic_pto_handler(c);
            }
        }

        QEventKind::Close => ngx_quic_close_handler(c),

        QEventKind::PathValidation => migration::ngx_quic_path_handler(c),

        QEventKind::KeyUpdate => ngx_quic_keys_update(c),

        QEventKind::StreamRead(qs) => {
            if let Some(qs) = qs.upgrade() {
                streams::ngx_quic_stream_read_event(&qs);
            }
        }

        QEventKind::StreamWrite(qs) => {
            if let Some(qs) = qs.upgrade() {
                streams::ngx_quic_stream_write_event(&qs);
            }
        }

        QEventKind::App(handler) => handler(),
    }
}

#[allow(dead_code)]
fn _silence(log: &Log) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "{}", B(b""));
}
