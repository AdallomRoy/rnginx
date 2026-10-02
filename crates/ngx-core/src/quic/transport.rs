//! ngx_event_quic_transport.c/.h: QUIC packets and frames, transport
//! parameters.
//!
//! A parsed frame keeps its data (CRYPTO and STREAM frame data, the ACK
//! ranges) as a range of the payload: parse_frame() returns it, and the
//! handlers get the bytes with the frame, as C passes frame->data pointing
//! into the payload. Frames to send own their data (QuicFrame::data).

use std::rc::Rc;

use crate::log::*;
use crate::rc::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};

use super::frames::QChain;
use super::protection::{NGX_QUIC_TAG_LEN, QuicKeys};
use super::{QuicConf, QuicPath, NGX_QUIC_MAX_UDP_PAYLOAD_SIZE, NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT, NGX_QUIC_DEFAULT_MAX_ACK_DELAY, NGX_QUIC_SR_TOKEN_LEN, NGX_QUIC_MIN_INITIAL_SIZE};
use super::{NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_ENCRYPTION_EARLY_DATA, NGX_QUIC_ENCRYPTION_HANDSHAKE, NGX_QUIC_ENCRYPTION_INITIAL};

// RFC 9000, 17.2.  Long Header Packets
//           17.3.  Short Header Packets
//
// QUIC flags in first byte
pub const NGX_QUIC_PKT_LONG: u8 = 0x80; /* header form */
pub const NGX_QUIC_PKT_FIXED_BIT: u8 = 0x40;
pub const NGX_QUIC_PKT_TYPE: u8 = 0x30; /* in long packet */
pub const NGX_QUIC_PKT_KPHASE: u8 = 0x04; /* in short packet */

/* Long packet types */
pub const NGX_QUIC_PKT_INITIAL: u8 = 0x00;
pub const NGX_QUIC_PKT_ZRTT: u8 = 0x10;
pub const NGX_QUIC_PKT_HANDSHAKE: u8 = 0x20;
pub const NGX_QUIC_PKT_RETRY: u8 = 0x30;

pub fn ngx_quic_long_pkt(flags: u8) -> bool {
    flags & NGX_QUIC_PKT_LONG != 0
}

pub fn ngx_quic_short_pkt(flags: u8) -> bool {
    flags & NGX_QUIC_PKT_LONG == 0
}

pub fn ngx_quic_pkt_in(flags: u8) -> bool {
    flags & NGX_QUIC_PKT_TYPE == NGX_QUIC_PKT_INITIAL
}

pub fn ngx_quic_pkt_zrtt(flags: u8) -> bool {
    flags & NGX_QUIC_PKT_TYPE == NGX_QUIC_PKT_ZRTT
}

pub fn ngx_quic_pkt_hs(flags: u8) -> bool {
    flags & NGX_QUIC_PKT_TYPE == NGX_QUIC_PKT_HANDSHAKE
}

pub fn ngx_quic_pkt_retry(flags: u8) -> bool {
    flags & NGX_QUIC_PKT_TYPE == NGX_QUIC_PKT_RETRY
}

pub fn ngx_quic_pkt_rb_mask(flags: u8) -> u8 {
    if ngx_quic_long_pkt(flags) {
        0x0C
    } else {
        0x18
    }
}

pub fn ngx_quic_pkt_hp_mask(flags: u8) -> u8 {
    if ngx_quic_long_pkt(flags) {
        0x0F
    } else {
        0x1F
    }
}

pub fn ngx_quic_level_name(lvl: usize) -> &'static str {
    if lvl == NGX_QUIC_ENCRYPTION_APPLICATION {
        "app"
    } else if lvl == NGX_QUIC_ENCRYPTION_INITIAL {
        "init"
    } else if lvl == NGX_QUIC_ENCRYPTION_HANDSHAKE {
        "hs"
    } else {
        "early"
    }
}

pub const NGX_QUIC_MAX_CID_LEN: usize = 20;
pub const NGX_QUIC_SERVER_CID_LEN: usize = NGX_QUIC_MAX_CID_LEN;

/* 12.4.  Frames and Frame Types */
pub const NGX_QUIC_FT_PADDING: u64 = 0x00;
pub const NGX_QUIC_FT_PING: u64 = 0x01;
pub const NGX_QUIC_FT_ACK: u64 = 0x02;
pub const NGX_QUIC_FT_ACK_ECN: u64 = 0x03;
pub const NGX_QUIC_FT_RESET_STREAM: u64 = 0x04;
pub const NGX_QUIC_FT_STOP_SENDING: u64 = 0x05;
pub const NGX_QUIC_FT_CRYPTO: u64 = 0x06;
pub const NGX_QUIC_FT_NEW_TOKEN: u64 = 0x07;
pub const NGX_QUIC_FT_STREAM: u64 = 0x08;
pub const NGX_QUIC_FT_STREAM1: u64 = 0x09;
pub const NGX_QUIC_FT_STREAM2: u64 = 0x0A;
pub const NGX_QUIC_FT_STREAM3: u64 = 0x0B;
pub const NGX_QUIC_FT_STREAM4: u64 = 0x0C;
pub const NGX_QUIC_FT_STREAM5: u64 = 0x0D;
pub const NGX_QUIC_FT_STREAM6: u64 = 0x0E;
pub const NGX_QUIC_FT_STREAM7: u64 = 0x0F;
pub const NGX_QUIC_FT_MAX_DATA: u64 = 0x10;
pub const NGX_QUIC_FT_MAX_STREAM_DATA: u64 = 0x11;
pub const NGX_QUIC_FT_MAX_STREAMS: u64 = 0x12;
pub const NGX_QUIC_FT_MAX_STREAMS2: u64 = 0x13;
pub const NGX_QUIC_FT_DATA_BLOCKED: u64 = 0x14;
pub const NGX_QUIC_FT_STREAM_DATA_BLOCKED: u64 = 0x15;
pub const NGX_QUIC_FT_STREAMS_BLOCKED: u64 = 0x16;
pub const NGX_QUIC_FT_STREAMS_BLOCKED2: u64 = 0x17;
pub const NGX_QUIC_FT_NEW_CONNECTION_ID: u64 = 0x18;
pub const NGX_QUIC_FT_RETIRE_CONNECTION_ID: u64 = 0x19;
pub const NGX_QUIC_FT_PATH_CHALLENGE: u64 = 0x1A;
pub const NGX_QUIC_FT_PATH_RESPONSE: u64 = 0x1B;
pub const NGX_QUIC_FT_CONNECTION_CLOSE: u64 = 0x1C;
pub const NGX_QUIC_FT_CONNECTION_CLOSE_APP: u64 = 0x1D;
pub const NGX_QUIC_FT_HANDSHAKE_DONE: u64 = 0x1E;

pub const NGX_QUIC_FT_LAST: u64 = NGX_QUIC_FT_HANDSHAKE_DONE;

/* 22.5.  QUIC Transport Error Codes Registry */
pub const NGX_QUIC_ERR_NO_ERROR: u64 = 0x00;
pub const NGX_QUIC_ERR_INTERNAL_ERROR: u64 = 0x01;
pub const NGX_QUIC_ERR_CONNECTION_REFUSED: u64 = 0x02;
pub const NGX_QUIC_ERR_FLOW_CONTROL_ERROR: u64 = 0x03;
pub const NGX_QUIC_ERR_STREAM_LIMIT_ERROR: u64 = 0x04;
pub const NGX_QUIC_ERR_STREAM_STATE_ERROR: u64 = 0x05;
pub const NGX_QUIC_ERR_FINAL_SIZE_ERROR: u64 = 0x06;
pub const NGX_QUIC_ERR_FRAME_ENCODING_ERROR: u64 = 0x07;
pub const NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR: u64 = 0x08;
pub const NGX_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR: u64 = 0x09;
pub const NGX_QUIC_ERR_PROTOCOL_VIOLATION: u64 = 0x0A;
pub const NGX_QUIC_ERR_INVALID_TOKEN: u64 = 0x0B;
pub const NGX_QUIC_ERR_APPLICATION_ERROR: u64 = 0x0C;
pub const NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED: u64 = 0x0D;
pub const NGX_QUIC_ERR_KEY_UPDATE_ERROR: u64 = 0x0E;
pub const NGX_QUIC_ERR_AEAD_LIMIT_REACHED: u64 = 0x0F;
pub const NGX_QUIC_ERR_NO_VIABLE_PATH: u64 = 0x10;

pub const NGX_QUIC_ERR_CRYPTO_ERROR: u64 = 0x100;

pub const fn ngx_quic_err_crypto(e: u64) -> u64 {
    NGX_QUIC_ERR_CRYPTO_ERROR + e
}

/* 22.3.  QUIC Transport Parameters Registry */
pub const NGX_QUIC_TP_ORIGINAL_DCID: u64 = 0x00;
pub const NGX_QUIC_TP_MAX_IDLE_TIMEOUT: u64 = 0x01;
pub const NGX_QUIC_TP_SR_TOKEN: u64 = 0x02;
pub const NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
pub const NGX_QUIC_TP_INITIAL_MAX_DATA: u64 = 0x04;
pub const NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
pub const NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
pub const NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
pub const NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
pub const NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
pub const NGX_QUIC_TP_ACK_DELAY_EXPONENT: u64 = 0x0A;
pub const NGX_QUIC_TP_MAX_ACK_DELAY: u64 = 0x0B;
pub const NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION: u64 = 0x0C;
pub const NGX_QUIC_TP_PREFERRED_ADDRESS: u64 = 0x0D;
pub const NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0E;
pub const NGX_QUIC_TP_INITIAL_SCID: u64 = 0x0F;
pub const NGX_QUIC_TP_RETRY_SCID: u64 = 0x10;

pub const NGX_QUIC_CID_LEN_MIN: usize = 8;
pub const NGX_QUIC_CID_LEN_MAX: usize = 20;

pub const NGX_QUIC_MAX_RANGES: usize = 10;

const NGX_QUIC_LONG_DCID_LEN_OFFSET: usize = 5;
const NGX_QUIC_LONG_DCID_OFFSET: usize = 6;
const NGX_QUIC_SHORT_DCID_OFFSET: usize = 1;

const NGX_QUIC_STREAM_FRAME_FIN: u64 = 0x01;
const NGX_QUIC_STREAM_FRAME_LEN: u64 = 0x02;
const NGX_QUIC_STREAM_FRAME_OFF: u64 = 0x04;

/// ngx_quic_versions
pub const NGX_QUIC_VERSIONS: [u32; 1] = [
    /* QUICv1 */
    0x00000001,
];

/// ngx_quic_ack_range_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicAckRange {
    pub gap: u64,
    pub range: u64,
}

/// ngx_quic_ack_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicAckFrame {
    pub largest: u64,
    pub delay: u64,
    pub range_count: u64,
    pub first_range: u64,
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
    pub ranges_length: u64,
}

/// ngx_quic_new_conn_id_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicNewConnIdFrame {
    pub seqnum: u64,
    pub retire: u64,
    pub len: u8,
    pub cid: [u8; NGX_QUIC_CID_LEN_MAX],
    pub srt: [u8; NGX_QUIC_SR_TOKEN_LEN],
}

/// ngx_quic_new_token_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicNewTokenFrame {
    pub length: u64,
}

/// ngx_quic_ordered_frame_t: the common layout for CRYPTO and STREAM
/// frames; conceptually, CRYPTO frame is also a stream frame lacking some
/// properties. It holds the offset and length of both (f->u.crypto,
/// f->u.ord and the first fields of f->u.stream in C).
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicOrderedFrame {
    pub offset: u64,
    pub length: u64,
}

/// ngx_quic_stream_frame_t, but for the offset and length (in u.ord)
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicStreamFrame {
    pub stream_id: u64,
    pub off: bool,
    pub len: bool,
    pub fin: bool,
}

/// ngx_quic_max_data_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicMaxDataFrame {
    pub max_data: u64,
}

/// ngx_quic_close_frame_t
#[derive(Clone, Default, Debug)]
pub struct QuicCloseFrame {
    pub error_code: u64,
    pub frame_type: u64,
    pub reason: Vec<u8>,
}

/// ngx_quic_reset_stream_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicResetStreamFrame {
    pub id: u64,
    pub error_code: u64,
    pub final_size: u64,
}

/// ngx_quic_stop_sending_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicStopSendingFrame {
    pub id: u64,
    pub error_code: u64,
}

/// ngx_quic_streams_blocked_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicStreamsBlockedFrame {
    pub limit: u64,
    pub bidi: bool,
}

/// ngx_quic_max_streams_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicMaxStreamsFrame {
    pub limit: u64,
    pub bidi: bool,
}

/// ngx_quic_max_stream_data_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicMaxStreamDataFrame {
    pub id: u64,
    pub limit: u64,
}

/// ngx_quic_data_blocked_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicDataBlockedFrame {
    pub limit: u64,
}

/// ngx_quic_stream_data_blocked_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicStreamDataBlockedFrame {
    pub id: u64,
    pub limit: u64,
}

/// ngx_quic_retire_cid_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicRetireCidFrame {
    pub sequence_number: u64,
}

/// ngx_quic_path_challenge_frame_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicPathChallengeFrame {
    pub data: [u8; 8],
}

/// The union of ngx_quic_frame_t. The members are kept apart but for
/// those C reads through another member: u.crypto, u.ord and the offset
/// and length of u.stream are `ord`, u.path_challenge and u.path_response
/// are `path_challenge`.
#[derive(Clone, Default, Debug)]
pub struct QuicFrameU {
    pub ack: QuicAckFrame,
    pub ord: QuicOrderedFrame,
    pub ncid: QuicNewConnIdFrame,
    pub token: QuicNewTokenFrame,
    pub stream: QuicStreamFrame,
    pub max_data: QuicMaxDataFrame,
    pub close: QuicCloseFrame,
    pub reset_stream: QuicResetStreamFrame,
    pub stop_sending: QuicStopSendingFrame,
    pub streams_blocked: QuicStreamsBlockedFrame,
    pub max_streams: QuicMaxStreamsFrame,
    pub max_stream_data: QuicMaxStreamDataFrame,
    pub data_blocked: QuicDataBlockedFrame,
    pub stream_data_blocked: QuicStreamDataBlockedFrame,
    pub retire_cid: QuicRetireCidFrame,
    pub path_challenge: QuicPathChallengeFrame,
}

/// ngx_quic_frame_t
#[derive(Clone, Default, Debug)]
pub struct QuicFrame {
    pub ty: u64,
    pub level: usize,
    pub pnum: u64,
    pub plen: usize,
    pub send_time: u64,
    pub len: isize,
    pub need_ack: bool,
    pub pkt_need_ack: bool,
    pub ignore_congestion: bool,
    pub ignore_loss: bool,

    pub data: QChain,
    pub u: QuicFrameU,
}

/// A connection id, at most NGX_QUIC_CID_LEN_MAX bytes, held inline (C
/// points to it): copied without an allocation, compared and hashed as its
/// bytes.
#[derive(Clone, Copy, Default)]
pub struct QuicCid {
    len: u8,
    data: [u8; NGX_QUIC_CID_LEN_MAX],
}

impl QuicCid {
    /// The id of these bytes; longer ones (never parsed: the parsers
    /// reject them) are cut at NGX_QUIC_CID_LEN_MAX.
    pub fn new(id: &[u8]) -> QuicCid {
        let len = id.len().min(NGX_QUIC_CID_LEN_MAX);
        let mut data = [0u8; NGX_QUIC_CID_LEN_MAX];

        data[..len].copy_from_slice(&id[..len]);

        QuicCid { len: len as u8, data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

impl std::ops::Deref for QuicCid {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for QuicCid {
    fn eq(&self, other: &QuicCid) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for QuicCid {}

impl PartialEq<[u8]> for QuicCid {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<Vec<u8>> for QuicCid {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl std::hash::Hash for QuicCid {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl std::fmt::Debug for QuicCid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_slice())
    }
}

/// ngx_quic_header_t. The packet read is `raw` (the UDP datagram) from
/// `data` for `len` bytes; the parser moves `raw_pos` (pkt->raw->pos)
/// along it. The connection ids are held inline, the token is a copy.
#[derive(Default)]
pub struct QuicHeader<'a> {
    pub log: Option<Log>,
    pub path: Option<Rc<QuicPath>>,

    pub keys: Option<Rc<std::cell::RefCell<QuicKeys>>>,

    pub received: u64,
    pub number: u64,
    pub num_len: u8,
    pub trunc: u32,
    pub flags: u8,
    pub version: u32,
    pub token: Vec<u8>,
    pub level: usize,
    pub error: u64,

    /* filled in by parser */
    pub raw: &'a [u8], /* udp datagram */
    pub raw_pos: usize,

    pub data: usize, /* quic packet */
    pub len: usize,

    /* cleartext fields */
    pub odcid: QuicCid, /* retry packet tag */
    pub dcid: QuicCid,
    pub scid: QuicCid,
    pub pn: u64,
    pub payload: Vec<u8>, /* decrypted data */
    /// the part of `payload` which is the payload, if not all of it (the
    /// plaintext buffer of a packet read holds its header before it)
    pub payload_range: Option<(usize, usize)>,

    pub need_ack: bool,
    pub key_phase: bool,
    pub key_update: bool,
    pub parsed: bool,
    pub decrypted: bool,
    pub validated: bool,
    pub retried: bool,
    pub first: bool,
    pub rebound: bool,
    pub path_challenged: bool,
}

impl<'a> QuicHeader<'a> {
    pub fn log(&self) -> &Log {
        self.log.as_ref().expect("pkt log")
    }

    /// pkt->payload
    pub fn payload(&self) -> &[u8] {
        match self.payload_range {
            Some((pos, end)) => &self.payload[pos..end],
            None => &self.payload,
        }
    }
}

/// ngx_quic_tp_t
#[derive(Clone, Default, Debug)]
pub struct QuicTp {
    pub max_idle_timeout: u64,
    pub max_ack_delay: u64,

    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub active_connection_id_limit: u64,
    pub disable_active_migration: bool,

    pub original_dcid: Vec<u8>,
    pub initial_scid: Vec<u8>,
    pub retry_scid: Vec<u8>,
    pub sr_token: [u8; NGX_QUIC_SR_TOKEN_LEN],
}

/// ngx_quic_parse_int: a variable-length integer from `buf` at `pos`; the
/// position after it, or None.
pub fn ngx_quic_parse_int(buf: &[u8], pos: usize, end: usize, out: &mut u64) -> Option<usize> {
    if pos >= end {
        return None;
    }

    let mut p = pos;
    let mut len = 1usize << (buf[p] >> 6);

    let mut value = (buf[p] & 0x3f) as u64;
    p += 1;

    if end - p < len - 1 {
        return None;
    }

    while {
        len -= 1;
        len > 0
    } {
        value = (value << 8) + buf[p] as u64;
        p += 1;
    }

    *out = value;

    Some(p)
}

/// ngx_quic_read_uint8
fn ngx_quic_read_uint8(buf: &[u8], pos: usize, end: usize, value: &mut u8) -> Option<usize> {
    if end.saturating_sub(pos) < 1 {
        return None;
    }

    *value = buf[pos];

    Some(pos + 1)
}

/// ngx_quic_read_uint32
fn ngx_quic_read_uint32(buf: &[u8], pos: usize, end: usize, value: &mut u32) -> Option<usize> {
    if end.saturating_sub(pos) < 4 {
        return None;
    }

    *value = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);

    Some(pos + 4)
}

/// ngx_quic_read_bytes: the range of `len` bytes at `pos`.
fn ngx_quic_read_bytes(pos: usize, end: usize, len: u64, out: &mut (usize, usize)) -> Option<usize> {
    if (end.saturating_sub(pos) as u64) < len {
        return None;
    }

    *out = (pos, pos + len as usize);

    Some(pos + len as usize)
}

/// ngx_quic_copy_bytes
fn ngx_quic_copy_bytes(buf: &[u8], pos: usize, end: usize, len: usize, dst: &mut [u8]) -> Option<usize> {
    if end.saturating_sub(pos) < len {
        return None;
    }

    dst[..len].copy_from_slice(&buf[pos..pos + len]);

    Some(pos + len)
}

/// ngx_quic_varint_len
pub fn ngx_quic_varint_len(value: u64) -> usize {
    if value < (1 << 6) {
        return 1;
    }

    if value < (1 << 14) {
        return 2;
    }

    if value < (1 << 30) {
        return 4;
    }

    8
}

/// ngx_quic_build_int
pub fn ngx_quic_build_int(out: &mut Vec<u8>, value: u64) {
    let (len, bits) = if value < (1 << 6) {
        (1, 0u8)
    } else if value < (1 << 14) {
        (2, 1)
    } else if value < (1 << 30) {
        (4, 2)
    } else {
        (8, 3)
    };

    for i in (0..len).rev() {
        let mut b = ((value >> (i * 8)) & 0xff) as u8;

        if i == len - 1 {
            b |= bits << 6;
        }

        out.push(b);
    }
}

/// ngx_quic_parse_packet
pub fn ngx_quic_parse_packet(pkt: &mut QuicHeader<'_>) -> i64 {
    if !ngx_quic_long_pkt(pkt.flags) {
        pkt.level = NGX_QUIC_ENCRYPTION_APPLICATION;

        if ngx_quic_parse_short_header(pkt, NGX_QUIC_SERVER_CID_LEN) != NGX_OK {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if ngx_quic_parse_long_header(pkt) != NGX_OK {
        return NGX_ERROR;
    }

    if pkt.version == 0 {
        /* version negotiation */
        return NGX_ERROR;
    }

    if !ngx_quic_supported_version(pkt.version) {
        return NGX_ABORT;
    }

    if ngx_quic_parse_long_header_v1(pkt) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_parse_short_header
fn ngx_quic_parse_short_header(pkt: &mut QuicHeader<'_>, dcid_len: usize) -> i64 {
    let log = pkt.log().clone();
    let p = pkt.raw_pos;
    let end = pkt.data + pkt.len;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic packet rx short flags:{:x}", pkt.flags);

    if pkt.flags & NGX_QUIC_PKT_FIXED_BIT == 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic fixed bit is not set");
        return NGX_ERROR;
    }

    let mut r = (0, 0);

    let p = match ngx_quic_read_bytes(p, end, dcid_len as u64, &mut r) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet is too small to read dcid");
            return NGX_ERROR;
        }
    };

    pkt.dcid = QuicCid::new(&pkt.raw[r.0..r.1]);

    pkt.raw_pos = p;

    NGX_OK
}

/// ngx_quic_parse_long_header
fn ngx_quic_parse_long_header(pkt: &mut QuicHeader<'_>) -> i64 {
    let log = pkt.log().clone();
    let raw = pkt.raw;
    let p = pkt.raw_pos;
    let end = pkt.data + pkt.len;

    let mut version = 0u32;

    let p = match ngx_quic_read_uint32(raw, p, end, &mut version) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet is too small to read version");
            return NGX_ERROR;
        }
    };

    pkt.version = version;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic packet rx long flags:{:x} version:{:x}", pkt.flags, pkt.version);

    if pkt.flags & NGX_QUIC_PKT_FIXED_BIT == 0 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic fixed bit is not set");
        return NGX_ERROR;
    }

    let mut idlen = 0u8;

    let p = match ngx_quic_read_uint8(raw, p, end, &mut idlen) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet is too small to read dcid len");
            return NGX_ERROR;
        }
    };

    if idlen as usize > NGX_QUIC_CID_LEN_MAX {
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet dcid is too long");
        return NGX_ERROR;
    }

    let mut r = (0, 0);

    let p = match ngx_quic_read_bytes(p, end, idlen as u64, &mut r) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet is too small to read dcid");
            return NGX_ERROR;
        }
    };

    pkt.dcid = QuicCid::new(&raw[r.0..r.1]);

    let p = match ngx_quic_read_uint8(raw, p, end, &mut idlen) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet is too small to read scid len");
            return NGX_ERROR;
        }
    };

    if idlen as usize > NGX_QUIC_CID_LEN_MAX {
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet scid is too long");
        return NGX_ERROR;
    }

    let p = match ngx_quic_read_bytes(p, end, idlen as u64, &mut r) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet is too small to read scid");
            return NGX_ERROR;
        }
    };

    pkt.scid = QuicCid::new(&raw[r.0..r.1]);

    pkt.raw_pos = p;

    NGX_OK
}

/// ngx_quic_supported_version
fn ngx_quic_supported_version(version: u32) -> bool {
    NGX_QUIC_VERSIONS.contains(&version)
}

/// ngx_quic_parse_long_header_v1
fn ngx_quic_parse_long_header_v1(pkt: &mut QuicHeader<'_>) -> i64 {
    let log = pkt.log().clone();
    let raw = pkt.raw;
    let mut p = pkt.raw_pos;
    let end = raw.len();

    let mut varint = 0u64;

    log.set_action(Some("parsing quic long header"));

    if ngx_quic_pkt_in(pkt.flags) {
        if pkt.len < NGX_QUIC_MIN_INITIAL_SIZE {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic UDP datagram is too small for initial packet");
            return NGX_DECLINED;
        }

        p = match ngx_quic_parse_int(raw, p, end, &mut varint) {
            Some(p) => p,
            None => {
                ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to parse token length");
                return NGX_ERROR;
            }
        };

        let mut r = (0, 0);

        p = match ngx_quic_read_bytes(p, end, varint, &mut r) {
            Some(p) => p,
            None => {
                ngx_log_error!(NGX_LOG_INFO, log, None, "quic packet too small to read token data");
                return NGX_ERROR;
            }
        };

        pkt.token = raw[r.0..r.1].to_vec();

        pkt.level = NGX_QUIC_ENCRYPTION_INITIAL;
    } else if ngx_quic_pkt_zrtt(pkt.flags) {
        pkt.level = NGX_QUIC_ENCRYPTION_EARLY_DATA;
    } else if ngx_quic_pkt_hs(pkt.flags) {
        pkt.level = NGX_QUIC_ENCRYPTION_HANDSHAKE;
    } else {
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic bad packet type");
        return NGX_DECLINED;
    }

    p = match ngx_quic_parse_int(raw, p, end, &mut varint) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic bad packet length");
            return NGX_ERROR;
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic packet rx {} len:{}", ngx_quic_level_name(pkt.level), varint);

    if varint > ((pkt.data + pkt.len) - p) as u64 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic truncated {} packet", ngx_quic_level_name(pkt.level));
        return NGX_ERROR;
    }

    pkt.raw_pos = p;
    pkt.len = p + varint as usize - pkt.data;

    NGX_OK
}

/// ngx_quic_get_packet_dcid: the destination connection id of a datagram
/// (a range of it).
pub fn ngx_quic_get_packet_dcid(log: &Log, data: &[u8]) -> Option<(usize, usize)> {
    let n = data.len();

    let failed = || {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic malformed packet");
        None
    };

    if n == 0 {
        return failed();
    }

    let (len, offset) = if ngx_quic_long_pkt(data[0]) {
        if n < NGX_QUIC_LONG_DCID_LEN_OFFSET + 1 {
            return failed();
        }

        (data[NGX_QUIC_LONG_DCID_LEN_OFFSET] as usize, NGX_QUIC_LONG_DCID_OFFSET)
    } else {
        (NGX_QUIC_SERVER_CID_LEN, NGX_QUIC_SHORT_DCID_OFFSET)
    };

    if n < len + offset {
        return failed();
    }

    Some((offset, offset + len))
}

/// ngx_quic_create_version_negotiation
pub fn ngx_quic_create_version_negotiation(pkt: &QuicHeader<'_>, out: &mut Vec<u8>) -> usize {
    let start = out.len();

    out.push(pkt.flags);

    // The Version field of a Version Negotiation packet
    // MUST be set to 0x00000000
    out.extend_from_slice(&0u32.to_be_bytes());

    out.push(pkt.dcid.len() as u8);
    out.extend_from_slice(&pkt.dcid);

    out.push(pkt.scid.len() as u8);
    out.extend_from_slice(&pkt.scid);

    for v in NGX_QUIC_VERSIONS {
        out.extend_from_slice(&v.to_be_bytes());
    }

    out.len() - start
}

/// ngx_quic_payload_size: the amount of payload a packet of "pkt_len"
/// size may fit, or 0
pub fn ngx_quic_payload_size(pkt: &QuicHeader<'_>, pkt_len: usize) -> usize {
    if ngx_quic_short_pkt(pkt.flags) {
        let len = 1 + pkt.dcid.len() + pkt.num_len as usize + NGX_QUIC_TAG_LEN;
        if len > pkt_len {
            return 0;
        }

        return pkt_len - len;
    }

    /* flags, version, dcid and scid with lengths and zero-length token */
    let mut len = 5 + 2 + pkt.dcid.len() + pkt.scid.len() + if pkt.level == NGX_QUIC_ENCRYPTION_INITIAL { 1 } else { 0 };

    if len > pkt_len {
        return 0;
    }

    /* (pkt_len - len) is 'remainder' packet length (see RFC 9000, 17.2) */
    len += ngx_quic_varint_len((pkt_len - len) as u64) + pkt.num_len as usize + NGX_QUIC_TAG_LEN;

    if len > pkt_len {
        return 0;
    }

    pkt_len - len
}

/// ngx_quic_create_header of a packet of `payload_len` bytes of payload,
/// written at the start of `out` (which has room for it, see
/// ngx_quic_header_len()); the length and the offset of the packet number
/// in it
pub fn ngx_quic_create_header_into(pkt: &QuicHeader<'_>, payload_len: usize, out: &mut [u8]) -> (usize, usize) {
    let mut w = SliceWriter { buf: out, pos: 0 };

    w.push(pkt.flags);

    if !ngx_quic_short_pkt(pkt.flags) {
        let rem_len = pkt.num_len as usize + payload_len + NGX_QUIC_TAG_LEN;

        w.extend(&pkt.version.to_be_bytes());

        w.push(pkt.dcid.len() as u8);
        w.extend(&pkt.dcid);

        w.push(pkt.scid.len() as u8);
        w.extend(&pkt.scid);

        if pkt.level == NGX_QUIC_ENCRYPTION_INITIAL {
            w.varint(0);
        }

        w.varint(rem_len as u64);
    } else {
        w.extend(&pkt.dcid);
    }

    let pnp = w.pos;

    let trunc = pkt.trunc.to_be_bytes();

    match pkt.num_len {
        1..=4 => w.extend(&trunc[4 - pkt.num_len as usize..]),
        _ => {}
    }

    (w.pos, pnp)
}

/// A cursor writing into a slice (C's u_char *p over a buffer).
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl SliceWriter<'_> {
    fn push(&mut self, b: u8) {
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn extend(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }

    /// ngx_quic_build_int
    fn varint(&mut self, value: u64) {
        let (len, bits) = if value < (1 << 6) {
            (1, 0u64)
        } else if value < (1 << 14) {
            (2, 1)
        } else if value < (1 << 30) {
            (4, 2)
        } else {
            (8, 3)
        };

        let v = (value | bits << (len * 8 - 2)).to_be_bytes();

        self.extend(&v[8 - len..]);
    }
}

/// ngx_quic_create_header: the header into `out`; the length and the
/// offset of the packet number in it
pub fn ngx_quic_create_header(pkt: &QuicHeader<'_>, out: &mut Vec<u8>) -> (usize, usize) {
    if ngx_quic_short_pkt(pkt.flags) {
        ngx_quic_create_short_header(pkt, out)
    } else {
        ngx_quic_create_long_header(pkt, out)
    }
}

/// The length of the header create_header() makes (out == NULL).
pub fn ngx_quic_header_len(pkt: &QuicHeader<'_>) -> usize {
    if ngx_quic_short_pkt(pkt.flags) {
        return 1 + pkt.dcid.len() + pkt.num_len as usize;
    }

    let rem_len = pkt.num_len as usize + pkt.payload().len() + NGX_QUIC_TAG_LEN;

    5 + 2 + pkt.dcid.len() + pkt.scid.len() + ngx_quic_varint_len(rem_len as u64) + pkt.num_len as usize + if pkt.level == NGX_QUIC_ENCRYPTION_INITIAL { 1 } else { 0 }
}

fn ngx_quic_write_pn(pkt: &QuicHeader<'_>, out: &mut Vec<u8>) {
    match pkt.num_len {
        1 => out.push(pkt.trunc as u8),
        2 => out.extend_from_slice(&(pkt.trunc as u16).to_be_bytes()),
        3 => out.extend_from_slice(&pkt.trunc.to_be_bytes()[1..]),
        4 => out.extend_from_slice(&pkt.trunc.to_be_bytes()),
        _ => {}
    }
}

/// ngx_quic_create_long_header
fn ngx_quic_create_long_header(pkt: &QuicHeader<'_>, out: &mut Vec<u8>) -> (usize, usize) {
    let rem_len = pkt.num_len as usize + pkt.payload().len() + NGX_QUIC_TAG_LEN;

    let start = out.len();

    out.push(pkt.flags);

    out.extend_from_slice(&pkt.version.to_be_bytes());

    out.push(pkt.dcid.len() as u8);
    out.extend_from_slice(&pkt.dcid);

    out.push(pkt.scid.len() as u8);
    out.extend_from_slice(&pkt.scid);

    if pkt.level == NGX_QUIC_ENCRYPTION_INITIAL {
        ngx_quic_build_int(out, 0);
    }

    ngx_quic_build_int(out, rem_len as u64);

    let pnp = out.len() - start;

    ngx_quic_write_pn(pkt, out);

    (out.len() - start, pnp)
}

/// ngx_quic_create_short_header
fn ngx_quic_create_short_header(pkt: &QuicHeader<'_>, out: &mut Vec<u8>) -> (usize, usize) {
    let start = out.len();

    out.push(pkt.flags);

    out.extend_from_slice(&pkt.dcid);

    let pnp = out.len() - start;

    ngx_quic_write_pn(pkt, out);

    (out.len() - start, pnp)
}

/// ngx_quic_create_retry_itag: the Retry pseudo-packet; the length and
/// the offset where the Retry packet itself starts
pub fn ngx_quic_create_retry_itag(pkt: &QuicHeader<'_>, out: &mut Vec<u8>) -> (usize, usize) {
    let begin = out.len();

    out.push(pkt.odcid.len() as u8);
    out.extend_from_slice(&pkt.odcid);

    let start = out.len() - begin;

    out.push(0xff);

    out.extend_from_slice(&pkt.version.to_be_bytes());

    out.push(pkt.dcid.len() as u8);
    out.extend_from_slice(&pkt.dcid);

    out.push(pkt.scid.len() as u8);
    out.extend_from_slice(&pkt.scid);

    out.extend_from_slice(&pkt.token);

    (out.len() - begin, start)
}

/// ngx_quic_parse_frame: a frame from `buf[start..end]`; its length, or
/// NGX_ERROR. The data of a CRYPTO, STREAM or ACK frame is the range put
/// in `data`.
pub fn ngx_quic_parse_frame(pkt: &mut QuicHeader<'_>, buf: &[u8], start: usize, end: usize, f: &mut QuicFrame, data: &mut (usize, usize)) -> isize {
    let log = pkt.log().clone();
    let mut varint = 0u64;

    macro_rules! error {
        () => {{
            pkt.error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;

            ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to parse frame type:0x{:x}", f.ty);

            return NGX_ERROR as isize;
        }};
    }

    macro_rules! int {
        ($p:expr, $out:expr) => {
            match ngx_quic_parse_int(buf, $p, end, $out) {
                Some(p) => p,
                None => error!(),
            }
        };
    }

    let mut p = match ngx_quic_parse_int(buf, start, end, &mut varint) {
        Some(p) => p,
        None => {
            pkt.error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to obtain quic frame type");
            return NGX_ERROR as isize;
        }
    };

    if varint > NGX_QUIC_FT_LAST {
        pkt.error = NGX_QUIC_ERR_FRAME_ENCODING_ERROR;
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic unknown frame type 0x{:x}", varint);
        return NGX_ERROR as isize;
    }

    f.ty = varint;

    if ngx_quic_frame_allowed(pkt, f.ty) != NGX_OK {
        pkt.error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        return NGX_ERROR as isize;
    }

    match f.ty {
        NGX_QUIC_FT_CRYPTO => {
            p = int!(p, &mut f.u.ord.offset);
            p = int!(p, &mut f.u.ord.length);

            p = match ngx_quic_read_bytes(p, end, f.u.ord.length, data) {
                Some(p) => p,
                None => error!(),
            };
        }

        NGX_QUIC_FT_PADDING => {
            while p < end && buf[p] == NGX_QUIC_FT_PADDING as u8 {
                p += 1;
            }
        }

        NGX_QUIC_FT_ACK | NGX_QUIC_FT_ACK_ECN => {
            p = int!(p, &mut f.u.ack.largest);
            p = int!(p, &mut f.u.ack.delay);
            p = int!(p, &mut f.u.ack.range_count);
            p = int!(p, &mut f.u.ack.first_range);

            let pos = p;

            /* process all ranges to get bounds, values are ignored */
            for _ in 0..f.u.ack.range_count {
                p = int!(p, &mut varint);
                p = int!(p, &mut varint);
            }

            *data = (pos, p);

            f.u.ack.ranges_length = (p - pos) as u64;

            if f.ty == NGX_QUIC_FT_ACK_ECN {
                p = int!(p, &mut f.u.ack.ect0);
                p = int!(p, &mut f.u.ack.ect1);
                p = int!(p, &mut f.u.ack.ce);

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic ACK ECN counters ect0:{} ect1:{} ce:{}", f.u.ack.ect0, f.u.ack.ect1, f.u.ack.ce);
            }
        }

        NGX_QUIC_FT_PING => {}

        NGX_QUIC_FT_NEW_CONNECTION_ID => {
            p = int!(p, &mut f.u.ncid.seqnum);
            p = int!(p, &mut f.u.ncid.retire);

            if f.u.ncid.retire > f.u.ncid.seqnum {
                error!();
            }

            p = match ngx_quic_read_uint8(buf, p, end, &mut f.u.ncid.len) {
                Some(p) => p,
                None => error!(),
            };

            if f.u.ncid.len < 1 || f.u.ncid.len as usize > NGX_QUIC_CID_LEN_MAX {
                error!();
            }

            let len = f.u.ncid.len as usize;

            p = match ngx_quic_copy_bytes(buf, p, end, len, &mut f.u.ncid.cid) {
                Some(p) => p,
                None => error!(),
            };

            p = match ngx_quic_copy_bytes(buf, p, end, NGX_QUIC_SR_TOKEN_LEN, &mut f.u.ncid.srt) {
                Some(p) => p,
                None => error!(),
            };
        }

        NGX_QUIC_FT_RETIRE_CONNECTION_ID => {
            p = int!(p, &mut f.u.retire_cid.sequence_number);
        }

        NGX_QUIC_FT_CONNECTION_CLOSE | NGX_QUIC_FT_CONNECTION_CLOSE_APP => {
            p = int!(p, &mut f.u.close.error_code);

            if f.ty == NGX_QUIC_FT_CONNECTION_CLOSE {
                p = int!(p, &mut f.u.close.frame_type);
            }

            p = int!(p, &mut varint);

            let mut r = (0, 0);

            p = match ngx_quic_read_bytes(p, end, varint, &mut r) {
                Some(p) => p,
                None => error!(),
            };

            f.u.close.reason = buf[r.0..r.1].to_vec();
        }

        NGX_QUIC_FT_STREAM..=NGX_QUIC_FT_STREAM7 => {
            f.u.stream.fin = f.ty & NGX_QUIC_STREAM_FRAME_FIN != 0;

            p = int!(p, &mut f.u.stream.stream_id);

            if f.ty & NGX_QUIC_STREAM_FRAME_OFF != 0 {
                f.u.stream.off = true;

                p = int!(p, &mut f.u.ord.offset);
            } else {
                f.u.stream.off = false;
                f.u.ord.offset = 0;
            }

            if f.ty & NGX_QUIC_STREAM_FRAME_LEN != 0 {
                f.u.stream.len = true;

                p = int!(p, &mut f.u.ord.length);
            } else {
                f.u.stream.len = false;
                f.u.ord.length = (end - p) as u64; /* up to packet end */
            }

            p = match ngx_quic_read_bytes(p, end, f.u.ord.length, data) {
                Some(p) => p,
                None => error!(),
            };

            f.ty = NGX_QUIC_FT_STREAM;
        }

        NGX_QUIC_FT_MAX_DATA => {
            p = int!(p, &mut f.u.max_data.max_data);
        }

        NGX_QUIC_FT_RESET_STREAM => {
            p = int!(p, &mut f.u.reset_stream.id);
            p = int!(p, &mut f.u.reset_stream.error_code);
            p = int!(p, &mut f.u.reset_stream.final_size);
        }

        NGX_QUIC_FT_STOP_SENDING => {
            p = int!(p, &mut f.u.stop_sending.id);
            p = int!(p, &mut f.u.stop_sending.error_code);
        }

        NGX_QUIC_FT_STREAMS_BLOCKED | NGX_QUIC_FT_STREAMS_BLOCKED2 => {
            p = int!(p, &mut f.u.streams_blocked.limit);

            if f.u.streams_blocked.limit > 0x1000000000000000 {
                error!();
            }

            f.u.streams_blocked.bidi = f.ty == NGX_QUIC_FT_STREAMS_BLOCKED;
        }

        NGX_QUIC_FT_MAX_STREAMS | NGX_QUIC_FT_MAX_STREAMS2 => {
            p = int!(p, &mut f.u.max_streams.limit);

            if f.u.max_streams.limit > 0x1000000000000000 {
                error!();
            }

            f.u.max_streams.bidi = f.ty == NGX_QUIC_FT_MAX_STREAMS;
        }

        NGX_QUIC_FT_MAX_STREAM_DATA => {
            p = int!(p, &mut f.u.max_stream_data.id);
            p = int!(p, &mut f.u.max_stream_data.limit);
        }

        NGX_QUIC_FT_DATA_BLOCKED => {
            p = int!(p, &mut f.u.data_blocked.limit);
        }

        NGX_QUIC_FT_STREAM_DATA_BLOCKED => {
            p = int!(p, &mut f.u.stream_data_blocked.id);
            p = int!(p, &mut f.u.stream_data_blocked.limit);
        }

        NGX_QUIC_FT_PATH_CHALLENGE | NGX_QUIC_FT_PATH_RESPONSE => {
            p = match ngx_quic_copy_bytes(buf, p, end, 8, &mut f.u.path_challenge.data) {
                Some(p) => p,
                None => error!(),
            };
        }

        _ => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic unknown frame type 0x{:x}", f.ty);
            return NGX_ERROR as isize;
        }
    }

    f.level = pkt.level;
    f.pnum = pkt.pn;

    (p - start) as isize
}

/// ngx_quic_frame_allowed
fn ngx_quic_frame_allowed(pkt: &QuicHeader<'_>, frame_type: u64) -> i64 {
    // RFC 9000, 12.4. Frames and Frame Types: Table 3
    //
    // Frame permissions per packet: 4 bits: IH01
    const NGX_QUIC_FRAME_MASKS: [u8; 31] = [
        /* PADDING  */ 0xF, /* PING */ 0xF, /* ACK */ 0xD, /* ACK_ECN */ 0xD, /* RESET_STREAM */ 0x3, /* STOP_SENDING */ 0x3, /* CRYPTO */ 0xD,
        /* NEW_TOKEN */ 0x0, /* only sent by server */
        /* STREAM */ 0x3, /* STREAM1 */ 0x3, /* STREAM2 */ 0x3, /* STREAM3 */ 0x3, /* STREAM4 */ 0x3, /* STREAM5 */ 0x3, /* STREAM6 */ 0x3, /* STREAM7 */ 0x3,
        /* MAX_DATA */ 0x3, /* MAX_STREAM_DATA */ 0x3, /* MAX_STREAMS */ 0x3, /* MAX_STREAMS2 */ 0x3, /* DATA_BLOCKED */ 0x3, /* STREAM_DATA_BLOCKED */ 0x3,
        /* STREAMS_BLOCKED */ 0x3, /* STREAMS_BLOCKED2 */ 0x3, /* NEW_CONNECTION_ID */ 0x3, /* RETIRE_CONNECTION_ID */ 0x3, /* PATH_CHALLENGE */ 0x3,
        /* PATH_RESPONSE */ 0x1, /* CONNECTION_CLOSE */ 0xF, /* CONNECTION_CLOSE2 */ 0x3, /* HANDSHAKE_DONE */ 0x0, /* only sent by server */
    ];

    let ptype: u8 = if ngx_quic_long_pkt(pkt.flags) {
        if ngx_quic_pkt_in(pkt.flags) {
            8 /* initial */
        } else if ngx_quic_pkt_hs(pkt.flags) {
            4 /* handshake */
        } else {
            2 /* zero-rtt */
        }
    } else {
        1 /* application data */
    };

    if ptype & NGX_QUIC_FRAME_MASKS[frame_type as usize] != 0 {
        return NGX_OK;
    }

    ngx_log_error!(NGX_LOG_INFO, pkt.log(), None, "quic frame type 0x{:x} is not allowed in packet with flags 0x{:x}", frame_type, pkt.flags);

    NGX_DECLINED
}

/// ngx_quic_parse_ack_range: an ACK range from `buf[start..end]`; its
/// length, or NGX_ERROR
pub fn ngx_quic_parse_ack_range(log: &Log, buf: &[u8], start: usize, end: usize, gap: &mut u64, range: &mut u64) -> isize {
    let p = match ngx_quic_parse_int(buf, start, end, gap) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to parse ack frame gap");
            return NGX_ERROR as isize;
        }
    };

    let p = match ngx_quic_parse_int(buf, p, end, range) {
        Some(p) => p,
        None => {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to parse ack frame range");
            return NGX_ERROR as isize;
        }
    };

    (p - start) as isize
}

/// ngx_quic_create_ack_range (with p == NULL: create_ack_range_len())
pub fn ngx_quic_create_ack_range(out: &mut Vec<u8>, gap: u64, range: u64) -> usize {
    let start = out.len();

    ngx_quic_build_int(out, gap);
    ngx_quic_build_int(out, range);

    out.len() - start
}

pub fn ngx_quic_create_ack_range_len(gap: u64, range: u64) -> usize {
    ngx_quic_varint_len(gap) + ngx_quic_varint_len(range)
}

/// ngx_quic_create_frame with p == NULL: the length of the frame; sets
/// f->need_ack as C does.
pub fn ngx_quic_frame_len(f: &mut QuicFrame) -> isize {
    ngx_quic_create_frame_impl(None, f)
}

/// ngx_quic_create_frame: the frame appended to `out`; its length, or -1.
pub fn ngx_quic_create_frame(out: &mut Vec<u8>, f: &mut QuicFrame) -> isize {
    ngx_quic_create_frame_impl(Some(out), f)
}

fn ngx_quic_create_frame_impl(p: Option<&mut Vec<u8>>, f: &mut QuicFrame) -> isize {
    //  RFC 9002, 2.  Conventions and Definitions
    //
    //  Ack-eliciting frames:  All frames other than ACK, PADDING, and
    //  CONNECTION_CLOSE are considered ack-eliciting.
    f.need_ack = true;

    let n = match f.ty {
        NGX_QUIC_FT_PING => ngx_quic_create_ping(p),

        NGX_QUIC_FT_ACK => {
            f.need_ack = false;
            ngx_quic_create_ack(p, &f.u.ack, &f.data)
        }

        NGX_QUIC_FT_RESET_STREAM => ngx_quic_create_reset_stream(p, &f.u.reset_stream),

        NGX_QUIC_FT_STOP_SENDING => ngx_quic_create_stop_sending(p, &f.u.stop_sending),

        NGX_QUIC_FT_CRYPTO => ngx_quic_create_crypto(p, &f.u.ord, &f.data),

        NGX_QUIC_FT_HANDSHAKE_DONE => ngx_quic_create_hs_done(p),

        NGX_QUIC_FT_NEW_TOKEN => ngx_quic_create_new_token(p, &f.u.token, &f.data),

        NGX_QUIC_FT_STREAM => ngx_quic_create_stream(p, &f.u.stream, &f.u.ord, &f.data),

        NGX_QUIC_FT_CONNECTION_CLOSE | NGX_QUIC_FT_CONNECTION_CLOSE_APP => {
            f.need_ack = false;
            ngx_quic_create_close(p, f.ty, &f.u.close)
        }

        NGX_QUIC_FT_MAX_STREAMS => ngx_quic_create_max_streams(p, &f.u.max_streams),

        NGX_QUIC_FT_MAX_STREAM_DATA => ngx_quic_create_max_stream_data(p, &f.u.max_stream_data),

        NGX_QUIC_FT_MAX_DATA => ngx_quic_create_max_data(p, &f.u.max_data),

        NGX_QUIC_FT_PATH_CHALLENGE => ngx_quic_create_path_challenge(p, NGX_QUIC_FT_PATH_CHALLENGE, &f.u.path_challenge),

        NGX_QUIC_FT_PATH_RESPONSE => ngx_quic_create_path_challenge(p, NGX_QUIC_FT_PATH_RESPONSE, &f.u.path_challenge),

        NGX_QUIC_FT_NEW_CONNECTION_ID => ngx_quic_create_new_connection_id(p, &f.u.ncid),

        NGX_QUIC_FT_RETIRE_CONNECTION_ID => ngx_quic_create_retire_connection_id(p, &f.u.retire_cid),

        _ => {
            /* BUG: unsupported frame type generated */
            return NGX_ERROR as isize;
        }
    };

    n as isize
}

/// The data of a chain appended to `out`.
fn copy_chain(out: &mut Vec<u8>, data: &QChain) {
    for b in data.iter() {
        let block = b.block.borrow();
        out.extend_from_slice(&block[b.pos..b.last]);
    }
}

/// ngx_quic_create_ping
fn ngx_quic_create_ping(p: Option<&mut Vec<u8>>) -> usize {
    let out = match p {
        None => return ngx_quic_varint_len(NGX_QUIC_FT_PING),
        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_PING);

    out.len() - start
}

/// ngx_quic_create_ack
fn ngx_quic_create_ack(p: Option<&mut Vec<u8>>, ack: &QuicAckFrame, ranges: &QChain) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_ACK);
            len += ngx_quic_varint_len(ack.largest);
            len += ngx_quic_varint_len(ack.delay);
            len += ngx_quic_varint_len(ack.range_count);
            len += ngx_quic_varint_len(ack.first_range);
            len += ack.ranges_length as usize;

            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_ACK);
    ngx_quic_build_int(out, ack.largest);
    ngx_quic_build_int(out, ack.delay);
    ngx_quic_build_int(out, ack.range_count);
    ngx_quic_build_int(out, ack.first_range);

    copy_chain(out, ranges);

    out.len() - start
}

/// ngx_quic_create_reset_stream
fn ngx_quic_create_reset_stream(p: Option<&mut Vec<u8>>, rs: &QuicResetStreamFrame) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_RESET_STREAM);
            len += ngx_quic_varint_len(rs.id);
            len += ngx_quic_varint_len(rs.error_code);
            len += ngx_quic_varint_len(rs.final_size);
            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_RESET_STREAM);
    ngx_quic_build_int(out, rs.id);
    ngx_quic_build_int(out, rs.error_code);
    ngx_quic_build_int(out, rs.final_size);

    out.len() - start
}

/// ngx_quic_create_stop_sending
fn ngx_quic_create_stop_sending(p: Option<&mut Vec<u8>>, ss: &QuicStopSendingFrame) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_STOP_SENDING);
            len += ngx_quic_varint_len(ss.id);
            len += ngx_quic_varint_len(ss.error_code);
            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_STOP_SENDING);
    ngx_quic_build_int(out, ss.id);
    ngx_quic_build_int(out, ss.error_code);

    out.len() - start
}

/// ngx_quic_create_crypto
fn ngx_quic_create_crypto(p: Option<&mut Vec<u8>>, crypto: &QuicOrderedFrame, data: &QChain) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_CRYPTO);
            len += ngx_quic_varint_len(crypto.offset);
            len += ngx_quic_varint_len(crypto.length);
            len += crypto.length as usize;

            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_CRYPTO);
    ngx_quic_build_int(out, crypto.offset);
    ngx_quic_build_int(out, crypto.length);

    copy_chain(out, data);

    out.len() - start
}

/// ngx_quic_create_hs_done
fn ngx_quic_create_hs_done(p: Option<&mut Vec<u8>>) -> usize {
    let out = match p {
        None => return ngx_quic_varint_len(NGX_QUIC_FT_HANDSHAKE_DONE),
        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_HANDSHAKE_DONE);

    out.len() - start
}

/// ngx_quic_create_new_token
fn ngx_quic_create_new_token(p: Option<&mut Vec<u8>>, token: &QuicNewTokenFrame, data: &QChain) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_NEW_TOKEN);
            len += ngx_quic_varint_len(token.length);
            len += token.length as usize;

            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_NEW_TOKEN);
    ngx_quic_build_int(out, token.length);

    copy_chain(out, data);

    out.len() - start
}

/// ngx_quic_create_stream
fn ngx_quic_create_stream(p: Option<&mut Vec<u8>>, sf: &QuicStreamFrame, ord: &QuicOrderedFrame, data: &QChain) -> usize {
    let mut ty = NGX_QUIC_FT_STREAM;

    if sf.off {
        ty |= NGX_QUIC_STREAM_FRAME_OFF;
    }

    if sf.len {
        ty |= NGX_QUIC_STREAM_FRAME_LEN;
    }

    if sf.fin {
        ty |= NGX_QUIC_STREAM_FRAME_FIN;
    }

    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(ty);
            len += ngx_quic_varint_len(sf.stream_id);

            if sf.off {
                len += ngx_quic_varint_len(ord.offset);
            }

            if sf.len {
                len += ngx_quic_varint_len(ord.length);
            }

            len += ord.length as usize;

            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, ty);
    ngx_quic_build_int(out, sf.stream_id);

    if sf.off {
        ngx_quic_build_int(out, ord.offset);
    }

    if sf.len {
        ngx_quic_build_int(out, ord.length);
    }

    copy_chain(out, data);

    out.len() - start
}

/// ngx_quic_create_max_streams
fn ngx_quic_create_max_streams(p: Option<&mut Vec<u8>>, ms: &QuicMaxStreamsFrame) -> usize {
    let ty = if ms.bidi { NGX_QUIC_FT_MAX_STREAMS } else { NGX_QUIC_FT_MAX_STREAMS2 };

    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(ty);
            len += ngx_quic_varint_len(ms.limit);
            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, ty);
    ngx_quic_build_int(out, ms.limit);

    out.len() - start
}

/// ngx_quic_parse_transport_param
fn ngx_quic_parse_transport_param(buf: &[u8], p: usize, end: usize, id: u64, dst: &mut QuicTp) -> i64 {
    let mut varint = 0u64;
    let mut s: Vec<u8> = Vec::new();

    match id {
        NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION => {
            /* zero-length option */
            if end - p != 0 {
                return NGX_ERROR;
            }

            dst.disable_active_migration = true;
            return NGX_OK;
        }

        NGX_QUIC_TP_MAX_IDLE_TIMEOUT
        | NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE
        | NGX_QUIC_TP_INITIAL_MAX_DATA
        | NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
        | NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
        | NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI
        | NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI
        | NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI
        | NGX_QUIC_TP_ACK_DELAY_EXPONENT
        | NGX_QUIC_TP_MAX_ACK_DELAY
        | NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT => {
            if ngx_quic_parse_int(buf, p, end, &mut varint).is_none() {
                return NGX_ERROR;
            }
        }

        NGX_QUIC_TP_INITIAL_SCID => {
            s = buf[p..end].to_vec();
        }

        _ => return NGX_DECLINED,
    }

    match id {
        NGX_QUIC_TP_MAX_IDLE_TIMEOUT => dst.max_idle_timeout = varint,
        NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE => dst.max_udp_payload_size = varint,
        NGX_QUIC_TP_INITIAL_MAX_DATA => dst.initial_max_data = varint,
        NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => dst.initial_max_stream_data_bidi_local = varint,
        NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => dst.initial_max_stream_data_bidi_remote = varint,
        NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI => dst.initial_max_stream_data_uni = varint,
        NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI => dst.initial_max_streams_bidi = varint,
        NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI => dst.initial_max_streams_uni = varint,
        NGX_QUIC_TP_ACK_DELAY_EXPONENT => dst.ack_delay_exponent = varint,
        NGX_QUIC_TP_MAX_ACK_DELAY => dst.max_ack_delay = varint,
        NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT => dst.active_connection_id_limit = varint,
        NGX_QUIC_TP_INITIAL_SCID => dst.initial_scid = s,
        _ => return NGX_ERROR,
    }

    NGX_OK
}

/// ngx_quic_parse_transport_params
pub fn ngx_quic_parse_transport_params(buf: &[u8], tp: &mut QuicTp, log: &Log) -> i64 {
    let mut p = 0usize;
    let end = buf.len();

    let mut id = 0u64;
    let mut len = 0u64;

    while p < end {
        p = match ngx_quic_parse_int(buf, p, end, &mut id) {
            Some(p) => p,
            None => {
                ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to parse transport param id");
                return NGX_ERROR;
            }
        };

        match id {
            NGX_QUIC_TP_ORIGINAL_DCID | NGX_QUIC_TP_PREFERRED_ADDRESS | NGX_QUIC_TP_RETRY_SCID | NGX_QUIC_TP_SR_TOKEN => {
                ngx_log_error!(NGX_LOG_INFO, log, None, "quic client sent forbidden transport param id:0x{:x}", id);
                return NGX_ERROR;
            }
            _ => {}
        }

        p = match ngx_quic_parse_int(buf, p, end, &mut len) {
            Some(p) => p,
            None => {
                ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to parse transport param id:0x{:x} length", id);
                return NGX_ERROR;
            }
        };

        if ((end - p) as u64) < len {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to parse transport param id:0x{:x}, data length {} too long", id, len);
            return NGX_ERROR;
        }

        let rc = ngx_quic_parse_transport_param(buf, p, p + len as usize, id, tp);

        if rc == NGX_ERROR {
            ngx_log_error!(NGX_LOG_INFO, log, None, "quic failed to parse transport param id:0x{:x} data", id);
            return NGX_ERROR;
        }

        if rc == NGX_DECLINED {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic {} transport param id:0x{:x}, skipped", if id % 31 == 27 { "reserved" } else { "unknown" }, id);
        }

        p += len as usize;
    }

    if p != end {
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic trailing garbage in transport parameters: bytes:{}", end - p);
        return NGX_ERROR;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic transport parameters parsed ok");

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp disable active migration: {}", tp.disable_active_migration as u32);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp idle_timeout:{}", tp.max_idle_timeout);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp max_udp_payload_size:{}", tp.max_udp_payload_size);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp max_data:{}", tp.initial_max_data);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp max_stream_data_bidi_local:{}", tp.initial_max_stream_data_bidi_local);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp max_stream_data_bidi_remote:{}", tp.initial_max_stream_data_bidi_remote);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp max_stream_data_uni:{}", tp.initial_max_stream_data_uni);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp initial_max_streams_bidi:{}", tp.initial_max_streams_bidi);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp initial_max_streams_uni:{}", tp.initial_max_streams_uni);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp ack_delay_exponent:{}", tp.ack_delay_exponent);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp max_ack_delay:{}", tp.max_ack_delay);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp active_connection_id_limit:{}", tp.active_connection_id_limit);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic tp initial source_connection_id len:{} {}", tp.initial_scid.len(), hex(&tp.initial_scid));

    NGX_OK
}

/// ngx_quic_create_max_stream_data
fn ngx_quic_create_max_stream_data(p: Option<&mut Vec<u8>>, ms: &QuicMaxStreamDataFrame) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_MAX_STREAM_DATA);
            len += ngx_quic_varint_len(ms.id);
            len += ngx_quic_varint_len(ms.limit);
            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_MAX_STREAM_DATA);
    ngx_quic_build_int(out, ms.id);
    ngx_quic_build_int(out, ms.limit);

    out.len() - start
}

/// ngx_quic_create_max_data
fn ngx_quic_create_max_data(p: Option<&mut Vec<u8>>, md: &QuicMaxDataFrame) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_MAX_DATA);
            len += ngx_quic_varint_len(md.max_data);
            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_MAX_DATA);
    ngx_quic_build_int(out, md.max_data);

    out.len() - start
}

/// ngx_quic_create_path_challenge, ngx_quic_create_path_response
fn ngx_quic_create_path_challenge(p: Option<&mut Vec<u8>>, ty: u64, pc: &QuicPathChallengeFrame) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(ty);
            len += pc.data.len();
            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, ty);
    out.extend_from_slice(&pc.data);

    out.len() - start
}

/// ngx_quic_create_new_connection_id
fn ngx_quic_create_new_connection_id(p: Option<&mut Vec<u8>>, ncid: &QuicNewConnIdFrame) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_NEW_CONNECTION_ID);
            len += ngx_quic_varint_len(ncid.seqnum);
            len += ngx_quic_varint_len(ncid.retire);
            len += 1;
            len += ncid.len as usize;
            len += NGX_QUIC_SR_TOKEN_LEN;
            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_NEW_CONNECTION_ID);
    ngx_quic_build_int(out, ncid.seqnum);
    ngx_quic_build_int(out, ncid.retire);
    out.push(ncid.len);
    out.extend_from_slice(&ncid.cid[..ncid.len as usize]);
    out.extend_from_slice(&ncid.srt);

    out.len() - start
}

/// ngx_quic_create_retire_connection_id
fn ngx_quic_create_retire_connection_id(p: Option<&mut Vec<u8>>, rcid: &QuicRetireCidFrame) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(NGX_QUIC_FT_RETIRE_CONNECTION_ID);
            len += ngx_quic_varint_len(rcid.sequence_number);
            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, NGX_QUIC_FT_RETIRE_CONNECTION_ID);
    ngx_quic_build_int(out, rcid.sequence_number);

    out.len() - start
}

/// ngx_quic_init_transport_params
pub fn ngx_quic_init_transport_params(tp: &mut QuicTp, qcf: &QuicConf) -> i64 {
    *tp = QuicTp::default();

    tp.max_idle_timeout = qcf.idle_timeout.get();

    tp.max_udp_payload_size = NGX_QUIC_MAX_UDP_PAYLOAD_SIZE as u64;

    let nstreams = qcf.max_concurrent_streams_bidi + qcf.max_concurrent_streams_uni;

    tp.initial_max_data = nstreams * qcf.stream_buffer_size as u64;
    tp.initial_max_stream_data_bidi_local = qcf.stream_buffer_size as u64;
    tp.initial_max_stream_data_bidi_remote = qcf.stream_buffer_size as u64;
    tp.initial_max_stream_data_uni = qcf.stream_buffer_size as u64;

    tp.initial_max_streams_bidi = qcf.max_concurrent_streams_bidi;
    tp.initial_max_streams_uni = qcf.max_concurrent_streams_uni;

    tp.max_ack_delay = NGX_QUIC_DEFAULT_MAX_ACK_DELAY;
    tp.ack_delay_exponent = NGX_QUIC_DEFAULT_ACK_DELAY_EXPONENT;

    tp.active_connection_id_limit = qcf.active_connection_id_limit;
    tp.disable_active_migration = qcf.disable_active_migration;

    NGX_OK
}

/// ngx_quic_create_transport_params: the parameters appended to `out`
/// (when not None); the length, and in `clen` the length of the
/// parameters saved in 0-RTT context
pub fn ngx_quic_create_transport_params(out: Option<&mut Vec<u8>>, tp: &QuicTp, clen: Option<&mut usize>) -> isize {
    fn tp_len(id: u64, value: u64) -> usize {
        ngx_quic_varint_len(id) + ngx_quic_varint_len(value) + ngx_quic_varint_len(ngx_quic_varint_len(value) as u64)
    }

    fn tp_vint(p: &mut Vec<u8>, id: u64, value: u64) {
        ngx_quic_build_int(p, id);
        ngx_quic_build_int(p, ngx_quic_varint_len(value) as u64);
        ngx_quic_build_int(p, value);
    }

    fn tp_strlen(id: u64, value: &[u8]) -> usize {
        ngx_quic_varint_len(id) + ngx_quic_varint_len(value.len() as u64) + value.len()
    }

    fn tp_str(p: &mut Vec<u8>, id: u64, value: &[u8]) {
        ngx_quic_build_int(p, id);
        ngx_quic_build_int(p, value.len() as u64);
        p.extend_from_slice(value);
    }

    let mut len = tp_len(NGX_QUIC_TP_INITIAL_MAX_DATA, tp.initial_max_data);

    len += tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI, tp.initial_max_streams_uni);

    len += tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, tp.initial_max_streams_bidi);

    len += tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, tp.initial_max_stream_data_bidi_local);

    len += tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, tp.initial_max_stream_data_bidi_remote);

    len += tp_len(NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, tp.initial_max_stream_data_uni);

    len += tp_len(NGX_QUIC_TP_MAX_IDLE_TIMEOUT, tp.max_idle_timeout);

    len += tp_len(NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, tp.max_udp_payload_size);

    if tp.disable_active_migration {
        len += ngx_quic_varint_len(NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION);
        len += ngx_quic_varint_len(0);
    }

    len += tp_len(NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, tp.active_connection_id_limit);

    /* transport parameters listed above will be saved in 0-RTT context */
    if let Some(clen) = clen {
        *clen = len;
    }

    len += tp_len(NGX_QUIC_TP_MAX_ACK_DELAY, tp.max_ack_delay);

    len += tp_len(NGX_QUIC_TP_ACK_DELAY_EXPONENT, tp.ack_delay_exponent);

    len += tp_strlen(NGX_QUIC_TP_ORIGINAL_DCID, &tp.original_dcid);
    len += tp_strlen(NGX_QUIC_TP_INITIAL_SCID, &tp.initial_scid);

    if !tp.retry_scid.is_empty() {
        len += tp_strlen(NGX_QUIC_TP_RETRY_SCID, &tp.retry_scid);
    }

    len += ngx_quic_varint_len(NGX_QUIC_TP_SR_TOKEN);
    len += ngx_quic_varint_len(NGX_QUIC_SR_TOKEN_LEN as u64);
    len += NGX_QUIC_SR_TOKEN_LEN;

    let p = match out {
        None => return len as isize,
        Some(p) => p,
    };

    let pos = p.len();

    tp_vint(p, NGX_QUIC_TP_INITIAL_MAX_DATA, tp.initial_max_data);

    tp_vint(p, NGX_QUIC_TP_INITIAL_MAX_STREAMS_UNI, tp.initial_max_streams_uni);

    tp_vint(p, NGX_QUIC_TP_INITIAL_MAX_STREAMS_BIDI, tp.initial_max_streams_bidi);

    tp_vint(p, NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, tp.initial_max_stream_data_bidi_local);

    tp_vint(p, NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, tp.initial_max_stream_data_bidi_remote);

    tp_vint(p, NGX_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, tp.initial_max_stream_data_uni);

    tp_vint(p, NGX_QUIC_TP_MAX_IDLE_TIMEOUT, tp.max_idle_timeout);

    tp_vint(p, NGX_QUIC_TP_MAX_UDP_PAYLOAD_SIZE, tp.max_udp_payload_size);

    if tp.disable_active_migration {
        ngx_quic_build_int(p, NGX_QUIC_TP_DISABLE_ACTIVE_MIGRATION);
        ngx_quic_build_int(p, 0);
    }

    tp_vint(p, NGX_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT, tp.active_connection_id_limit);

    tp_vint(p, NGX_QUIC_TP_MAX_ACK_DELAY, tp.max_ack_delay);

    tp_vint(p, NGX_QUIC_TP_ACK_DELAY_EXPONENT, tp.ack_delay_exponent);

    tp_str(p, NGX_QUIC_TP_ORIGINAL_DCID, &tp.original_dcid);
    tp_str(p, NGX_QUIC_TP_INITIAL_SCID, &tp.initial_scid);

    if !tp.retry_scid.is_empty() {
        tp_str(p, NGX_QUIC_TP_RETRY_SCID, &tp.retry_scid);
    }

    ngx_quic_build_int(p, NGX_QUIC_TP_SR_TOKEN);
    ngx_quic_build_int(p, NGX_QUIC_SR_TOKEN_LEN as u64);
    p.extend_from_slice(&tp.sr_token);

    (p.len() - pos) as isize
}

/// ngx_quic_create_close
fn ngx_quic_create_close(p: Option<&mut Vec<u8>>, ty: u64, cl: &QuicCloseFrame) -> usize {
    let out = match p {
        None => {
            let mut len = ngx_quic_varint_len(ty);
            len += ngx_quic_varint_len(cl.error_code);

            if ty != NGX_QUIC_FT_CONNECTION_CLOSE_APP {
                len += ngx_quic_varint_len(cl.frame_type);
            }

            len += ngx_quic_varint_len(cl.reason.len() as u64);
            len += cl.reason.len();

            return len;
        }

        Some(out) => out,
    };

    let start = out.len();

    ngx_quic_build_int(out, ty);
    ngx_quic_build_int(out, cl.error_code);

    if ty != NGX_QUIC_FT_CONNECTION_CLOSE_APP {
        ngx_quic_build_int(out, cl.frame_type);
    }

    ngx_quic_build_int(out, cl.reason.len() as u64);
    out.extend_from_slice(&cl.reason);

    out.len() - start
}

/// ngx_quic_dcid_encode_key
pub fn ngx_quic_dcid_encode_key(dcid: &mut [u8], key: u64) {
    dcid[..8].copy_from_slice(&key.to_be_bytes());
}

/// "%xV" / "%*xs": the bytes in lowercase hex.
pub fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);

    for b in data {
        s.push_str(&format!("{:02x}", b));
    }

    s
}

#[allow(dead_code)]
fn _silence(log: &Log) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "{}", B(b""));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_ids_inline() {
        let a = QuicCid::new(b"0123456789");
        let b = a;

        assert_eq!(a.len(), 10);
        assert_eq!(&a[..], b"0123456789");
        assert!(a == b && a == b"0123456789".to_vec() && a == b"0123456789"[..]);
        assert!(a != QuicCid::new(b"012345678"));
        assert!(QuicCid::default().is_empty());

        let max = [7u8; NGX_QUIC_CID_LEN_MAX];
        assert_eq!(QuicCid::new(&max).as_slice(), &max);

        // as keys: hashed as their bytes
        let mut m = std::collections::HashMap::new();
        m.insert(a, 1);
        assert_eq!(m.get(&QuicCid::new(b"0123456789")), Some(&1));
    }

    #[test]
    fn headers_into_slices() {
        let long = |num_len: u8, level: usize, flags: u8| QuicHeader {
            flags,
            version: 1,
            level,
            dcid: QuicCid::new(b"destination-id"),
            scid: QuicCid::new(b"src-id"),
            num_len,
            trunc: 0x01020304,
            ..Default::default()
        };

        for num_len in 1..=4u8 {
            for payload_len in [1usize, 40, 100, 20000] {
                for pkt in [
                    long(num_len, crate::quic::NGX_QUIC_ENCRYPTION_INITIAL, NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_INITIAL),
                    long(num_len, crate::quic::NGX_QUIC_ENCRYPTION_HANDSHAKE, NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_HANDSHAKE),
                    long(num_len, crate::quic::NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_PKT_FIXED_BIT | 0x01),
                ] {
                    let pkt = QuicHeader { payload: vec![0; payload_len], ..pkt };

                    let mut want = Vec::new();
                    let (wlen, wpnp) = ngx_quic_create_header(&pkt, &mut want);

                    let mut buf = [0xaau8; 128];
                    let (len, pnp) = ngx_quic_create_header_into(&pkt, payload_len, &mut buf);

                    assert_eq!((len, pnp), (wlen, wpnp));
                    assert_eq!(&buf[..len], &want[..]);
                    assert_eq!(len, ngx_quic_header_len(&pkt));
                }
            }
        }
    }

    #[test]
    fn varints_as_rfc9000() {
        // RFC 9000, A.1.  Sample Variable-Length Integer Decoding
        let samples: [(&[u8], u64); 4] = [
            (&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c], 151288809941952652),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494878333),
            (&[0x7b, 0xbd], 15293),
            (&[0x25], 37),
        ];

        for (bytes, value) in samples {
            let mut v = 0;
            assert_eq!(ngx_quic_parse_int(bytes, 0, bytes.len(), &mut v), Some(bytes.len()));
            assert_eq!(v, value);

            let mut out = Vec::new();
            ngx_quic_build_int(&mut out, value);
            assert_eq!(out.len(), ngx_quic_varint_len(value));
        }

        // the two-byte encoding of 37 decodes too
        let mut v = 0;
        assert_eq!(ngx_quic_parse_int(&[0x40, 0x25], 0, 2, &mut v), Some(2));
        assert_eq!(v, 37);

        // truncated
        assert_eq!(ngx_quic_parse_int(&[0x9d, 0x7f], 0, 2, &mut v), None);
        assert_eq!(ngx_quic_parse_int(&[], 0, 0, &mut v), None);

        let mut out = Vec::new();
        ngx_quic_build_int(&mut out, 494878333);
        assert_eq!(out, [0x9d, 0x7f, 0x3e, 0x7d]);
    }

    #[test]
    fn transport_params_round_trip() {
        let mut tp = QuicTp {
            max_idle_timeout: 60000,
            max_udp_payload_size: 65527,
            initial_max_data: 131 * 65536,
            initial_max_stream_data_bidi_local: 65536,
            initial_max_stream_data_bidi_remote: 65536,
            initial_max_stream_data_uni: 65536,
            initial_max_streams_bidi: 128,
            initial_max_streams_uni: 3,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            active_connection_id_limit: 2,
            initial_scid: vec![1; 20],
            original_dcid: vec![2; 8],
            ..Default::default()
        };
        tp.sr_token = [7; 16];

        let len = ngx_quic_create_transport_params(None, &tp, None);
        let mut buf = Vec::new();
        assert_eq!(ngx_quic_create_transport_params(Some(&mut buf), &tp, None), len);
        assert_eq!(buf.len() as isize, len);

        // a client may not send the server's parameters
        let log = crate::log::Log::stderr(0);
        let mut ctp = QuicTp::default();
        assert_eq!(ngx_quic_parse_transport_params(&buf, &mut ctp, &log), NGX_ERROR);

        // the client's ones
        let mut buf = Vec::new();
        ngx_quic_build_int(&mut buf, NGX_QUIC_TP_INITIAL_MAX_DATA);
        ngx_quic_build_int(&mut buf, 4);
        ngx_quic_build_int(&mut buf, 1048576);
        ngx_quic_build_int(&mut buf, NGX_QUIC_TP_INITIAL_SCID);
        ngx_quic_build_int(&mut buf, 3);
        buf.extend_from_slice(b"abc");
        ngx_quic_build_int(&mut buf, 0x1b); // reserved, skipped
        ngx_quic_build_int(&mut buf, 0);
        assert_eq!(ngx_quic_parse_transport_params(&buf, &mut ctp, &log), NGX_OK);
        assert_eq!(ctp.initial_max_data, 1048576);
        assert_eq!(ctp.initial_scid, b"abc");
    }
}
