//! ngx_event_quic_frames.c: frames and the buffers of their data.
//!
//! The buffers (ngx_quic_alloc_buf) are parts of blocks of
//! NGX_QUIC_BUFFER_SIZE bytes: a clone (ngx_quic_clone_buf, a shadow
//! buffer in C) shares the block, which lives as long as a buffer uses it.
//! A chain is a queue of them. A buffer with `sync` set is a hole: its part
//! of the block has not been written yet.
//!
//! The frames are counted as C counts its allocations: the frames made
//! (qc->nframes) up to qc->max_frames, and those freed, which are reused
//! first.
//!
//! ngx_quic_buffer_t keeps no last_chain here: it is a shortcut for
//! ngx_quic_write_buffer() to the chain link where the previous write ended,
//! and walking the chain from its start reaches the same link.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::connection::Connection;
use crate::log::*;
use crate::rc::*;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};

use super::transport::*;
use super::{ngx_quic_get_connection, QuicConnection};

pub const NGX_QUIC_BUFFER_SIZE: usize = 4096;

/// ngx_buf_t of a QUIC connection (ngx_quic_alloc_buf)
#[derive(Clone)]
pub struct QBuf {
    pub block: Rc<RefCell<Box<[u8]>>>,
    pub pos: usize,
    pub last: usize,
    /// a hole
    pub sync: bool,
}

impl std::fmt::Debug for QBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QBuf({}..{}{})", self.pos, self.last, if self.sync { " hole" } else { "" })
    }
}

impl QBuf {
    pub fn len(&self) -> usize {
        self.last - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.last == self.pos
    }
}

/// ngx_chain_t of QBufs
#[derive(Clone, Default, Debug)]
pub struct QChain(pub VecDeque<QBuf>);

impl QChain {
    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, QBuf> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The data of the chain.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();

        for b in self.0.iter() {
            out.extend_from_slice(&b.block.borrow()[b.pos..b.last]);
        }

        out
    }
}

/// ngx_quic_buffer_t
#[derive(Default, Debug)]
pub struct QuicBuffer {
    pub size: u64,
    pub offset: u64,
    pub chain: QChain,
}

/// The most blocks no buffer uses that a worker keeps for reuse.
const NGX_QUIC_FREE_BLOCKS_KEPT: usize = 128;

/// The most frames a connection keeps on its free list.
pub const NGX_QUIC_FREE_FRAMES_KEPT: usize = 256;

type QBlock = Rc<RefCell<Box<[u8]>>>;

thread_local! {
    /// The blocks of the buffers no buffer uses any more, for the next
    /// ngx_quic_alloc_buf() of the worker (C keeps them per connection,
    /// qc->free_bufs). Their bytes are not cleared: a new buffer is empty,
    /// or a hole, until written.
    static FREE_BLOCKS: RefCell<Vec<QBlock>> = const { RefCell::new(Vec::new()) };
}

impl Drop for QBuf {
    /// ngx_quic_free_buf: the last buffer of a block gives it back.
    fn drop(&mut self) {
        if Rc::strong_count(&self.block) != 1 || Rc::weak_count(&self.block) != 0 {
            return;
        }

        let block = &self.block;

        let _ = FREE_BLOCKS.try_with(|free| {
            if let Ok(mut free) = free.try_borrow_mut() {
                if free.len() < NGX_QUIC_FREE_BLOCKS_KEPT {
                    free.push(block.clone());
                }
            }
        });
    }
}

/// ngx_quic_alloc_buf: an empty buffer of a block no buffer uses
fn ngx_quic_alloc_buf() -> QBuf {
    let block = FREE_BLOCKS.try_with(|free| free.try_borrow_mut().ok()?.pop()).ok().flatten();

    let block = block.unwrap_or_else(|| Rc::new(RefCell::new(vec![0u8; NGX_QUIC_BUFFER_SIZE].into_boxed_slice())));

    QBuf { block, pos: 0, last: 0, sync: false }
}

/// ngx_quic_split_chain: the buffer at `i` ends at `offset` into it, a
/// clone of it has the rest
fn ngx_quic_split_chain(chain: &mut QChain, i: usize, offset: usize) {
    let b = &mut chain.0[i];

    let mut tb = b.clone();

    tb.pos += offset;

    b.last = tb.pos;

    chain.0.insert(i + 1, tb);
}

/// ngx_quic_alloc_frame
pub fn ngx_quic_alloc_frame(c: &Connection) -> Option<Box<QuicFrame>> {
    let qc = ngx_quic_get_connection(c)?;

    if qc.free_frames.get() > 0 {
        qc.free_frames.set(qc.free_frames.get() - 1);
    } else if qc.nframes.get() < qc.max_frames.get() {
        qc.nframes.set(qc.nframes.get() + 1);
    } else {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic flood detected");
        return None;
    }

    let frame = qc.frames_free.borrow_mut().pop();

    Some(frame.unwrap_or_default())
}

/// ngx_quic_free_frame: the frame, reset (its data given up, the chain
/// keeping its room), to the free list of the connection
pub fn ngx_quic_free_frame(c: &Connection, mut frame: Box<QuicFrame>) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    qc.free_frames.set(qc.free_frames.get() + 1);

    let mut data = std::mem::take(&mut frame.data);

    data.0.clear();

    *frame = QuicFrame { data, ..Default::default() };

    let mut free = qc.frames_free.borrow_mut();

    if free.len() < NGX_QUIC_FREE_FRAMES_KEPT {
        free.push(frame);
    }
}

/// ngx_quic_free_chain
pub fn ngx_quic_free_chain(_c: &Connection, chain: QChain) {
    drop(chain);
}

/// ngx_quic_free_frames
pub fn ngx_quic_free_frames(c: &Connection, frames: VecDeque<Box<QuicFrame>>) {
    for f in frames {
        ngx_quic_free_frame(c, f);
    }
}

/// ngx_quic_queue_frame
pub fn ngx_quic_queue_frame(qc: &QuicConnection, mut frame: Box<QuicFrame>) {
    frame.len = ngx_quic_frame_len(&mut frame);
    /* always succeeds */

    qc.send_ctx(frame.level).borrow_mut().frames.push_back(frame);

    if qc.closing.get() {
        return;
    }

    qc.push.post();
}

/// ngx_quic_split_frame: the frame at `i` of `frames` fits `len` bytes, a
/// new frame after it has the rest of its data
pub fn ngx_quic_split_frame(c: &Connection, frames: &mut VecDeque<Box<QuicFrame>>, i: usize, len: usize) -> i64 {
    let f = &mut frames[i];

    match f.ty {
        NGX_QUIC_FT_CRYPTO | NGX_QUIC_FT_STREAM => {}
        _ => return NGX_DECLINED,
    }

    if f.len as usize <= len {
        return NGX_OK;
    }

    let shrink = f.len as usize - len;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic split frame now:{} need:{} shrink:{}", f.len, len, shrink);

    if f.u.ord.length <= shrink as u64 {
        return NGX_DECLINED;
    }

    f.u.ord.length -= shrink as u64;
    f.len = ngx_quic_frame_len(f);

    if f.len as usize > len {
        ngx_log_error!(NGX_LOG_ERR, c.log, None, "could not split QUIC frame");
        return NGX_ERROR;
    }

    let mut qb = QuicBuffer { chain: std::mem::take(&mut f.data), ..Default::default() };

    let mut nf = match ngx_quic_alloc_frame(c) {
        Some(nf) => nf,
        None => {
            frames[i].data = qb.chain;
            return NGX_ERROR;
        }
    };

    let f = &mut frames[i];

    // the first part into the chain of the new frame, which keeps its
    // room, then the chains swapped
    let mut head = std::mem::take(&mut nf.data);

    ngx_quic_read_buffer_into(c, &mut qb, f.u.ord.length, &mut head);

    f.data = head;

    // the new frame: a copy of the frame but for its data
    let data = std::mem::take(&mut f.data);

    *nf = (**f).clone();

    f.data = data;

    nf.u.ord.offset += f.u.ord.length;
    nf.u.ord.length = shrink as u64;
    nf.len = ngx_quic_frame_len(&mut nf);
    nf.data = qb.chain;

    if f.ty == NGX_QUIC_FT_STREAM {
        f.u.stream.fin = false;
    }

    frames.insert(i + 1, nf);

    NGX_OK
}

/// ngx_quic_copy_buffer
pub fn ngx_quic_copy_buffer(c: &Connection, data: &[u8]) -> QChain {
    let mut qb = QuicBuffer::default();

    let mut input = [data];

    ngx_quic_write_buffer(c, &mut qb, &mut input, data.len() as u64, 0);

    let out = ngx_quic_read_buffer(c, &mut qb, data.len() as u64);

    ngx_quic_free_buffer(c, &mut qb);

    out
}

/// ngx_quic_read_buffer: the data of the buffer from its offset, up to
/// `limit` bytes or a hole
pub fn ngx_quic_read_buffer(c: &Connection, qb: &mut QuicBuffer, limit: u64) -> QChain {
    let mut out = QChain::default();

    ngx_quic_read_buffer_into(c, qb, limit, &mut out);

    out
}

/// ngx_quic_read_buffer, the buffers moved to the end of `out` (a chain
/// with room for them, as C links them to the chain it returns)
pub fn ngx_quic_read_buffer_into(_c: &Connection, qb: &mut QuicBuffer, mut limit: u64, out: &mut QChain) {
    while let Some(b) = qb.chain.0.front() {
        if b.sync {
            /* hole */
            break;
        }

        if limit == 0 {
            break;
        }

        let mut n = b.len() as u64;

        if n > limit {
            ngx_quic_split_chain(&mut qb.chain, 0, limit as usize);

            n = limit;
        }

        limit -= n;
        qb.offset += n;

        if let Some(b) = qb.chain.0.pop_front() {
            out.0.push_back(b);
        }
    }
}

/// The bytes ngx_quic_read_buffer() takes: up to `limit`, the data from
/// the offset of the buffer to its first hole.
pub fn ngx_quic_buffer_readable(qb: &QuicBuffer, limit: u64) -> u64 {
    let mut n = 0u64;

    for b in qb.chain.iter() {
        if b.sync || n >= limit {
            break;
        }

        n += b.len() as u64;
    }

    n.min(limit)
}

/// ngx_quic_read_buffer() of up to `buf.len()` bytes copied to `buf` (the
/// buffers read freed, as ngx_quic_stream_recv() does): their number.
pub fn ngx_quic_read_buffer_copy(_c: &Connection, qb: &mut QuicBuffer, buf: &mut [u8]) -> usize {
    let mut len = 0usize;

    while let Some(b) = qb.chain.0.front_mut() {
        if b.sync {
            /* hole */
            break;
        }

        if len == buf.len() {
            break;
        }

        let n = b.len().min(buf.len() - len);

        buf[len..len + n].copy_from_slice(&b.block.borrow()[b.pos..b.pos + n]);

        len += n;
        qb.offset += n as u64;

        if n < b.len() {
            // the rest of it stays (a clone of it split off in C)
            b.pos += n;
            break;
        }

        qb.chain.0.pop_front();
    }

    len
}

/// ngx_quic_skip_buffer
pub fn ngx_quic_skip_buffer(_c: &Connection, qb: &mut QuicBuffer, offset: u64) {
    while let Some(b) = qb.chain.0.front_mut() {
        if qb.offset >= offset {
            break;
        }

        let n = b.len() as u64;

        if qb.offset + n > offset {
            let n = offset - qb.offset;
            b.pos += n as usize;
            qb.offset += n;
            break;
        }

        qb.offset += n;
        qb.chain.0.pop_front();
    }

    if qb.chain.is_empty() {
        qb.offset = offset;
    }
}

/// ngx_quic_alloc_chain
pub fn ngx_quic_alloc_chain(_c: &Connection) -> QBuf {
    ngx_quic_alloc_buf()
}

/// ngx_quic_write_buffer: the input (its slices advance as they are
/// consumed, as C moves in->buf->pos) written to the buffer at `offset`,
/// up to `limit` bytes; the data already there is kept
pub fn ngx_quic_write_buffer(_c: &Connection, qb: &mut QuicBuffer, input: &mut [&[u8]], mut limit: u64, mut offset: u64) {
    let mut base = qb.offset;
    let mut i = 0usize;
    let mut k = 0usize;

    while k < input.len() && limit > 0 {
        if offset < base {
            let n = (input[k].len() as u64).min((base - offset).min(limit));

            input[k] = &input[k][n as usize..];
            offset += n;
            limit -= n;

            if input[k].is_empty() {
                k += 1;
            }

            continue;
        }

        if i == qb.chain.0.len() {
            let mut b = ngx_quic_alloc_buf();

            b.last = NGX_QUIC_BUFFER_SIZE;
            b.sync = true; /* hole */

            qb.chain.0.push_back(b);
        }

        let n = qb.chain.0[i].len() as u64;

        if base + n <= offset {
            base += n;
            i += 1;
            continue;
        }

        if qb.chain.0[i].sync && offset > base {
            ngx_quic_split_chain(&mut qb.chain, i, (offset - base) as usize);
            continue;
        }

        let b = &mut qb.chain.0[i];

        let mut p = b.pos + (offset - base) as usize;

        while k < input.len() {
            if input[k].is_empty() {
                k += 1;
                continue;
            }

            if p == b.last || limit == 0 {
                break;
            }

            let n = ((b.last - p) as u64).min(input[k].len() as u64).min(limit) as usize;

            if b.sync {
                b.block.borrow_mut()[p..p + n].copy_from_slice(&input[k][..n]);
                qb.size += n as u64;
            }

            p += n;
            input[k] = &input[k][n..];
            offset += n as u64;
            limit -= n as u64;
        }

        if b.sync && p == b.last {
            b.sync = false;
            continue;
        }

        if b.sync && p != b.pos {
            let off = p - b.pos;

            ngx_quic_split_chain(&mut qb.chain, i, off);

            qb.chain.0[i].sync = false;
        }
    }
}

/// ngx_quic_free_buffer
pub fn ngx_quic_free_buffer(_c: &Connection, qb: &mut QuicBuffer) {
    qb.chain = QChain::default();
}

/// ngx_quic_log_frame: `data` is the data of a received frame (the ACK
/// ranges); a frame sent has it in f->data
pub fn ngx_quic_log_frame(log: &Log, f: &QuicFrame, data: &[u8], tx: bool) {
    if !log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
        return;
    }

    let mut p = String::new();

    match f.ty {
        NGX_QUIC_FT_CRYPTO => {
            p.push_str(&format!("CRYPTO len:{} off:{}", f.u.ord.length, f.u.ord.offset));
        }

        NGX_QUIC_FT_PADDING => p.push_str("PADDING"),

        NGX_QUIC_FT_ACK | NGX_QUIC_FT_ACK_ECN => {
            p.push_str(&format!("ACK n:{} delay:{} ", f.u.ack.range_count, f.u.ack.delay));

            let ranges;

            let data = if tx {
                ranges = f.data.to_vec();
                &ranges[..]
            } else {
                data
            };

            let mut pos = 0usize;
            let end = data.len();

            let mut largest = f.u.ack.largest;
            let mut smallest = f.u.ack.largest.wrapping_sub(f.u.ack.first_range);

            if largest == smallest {
                p.push_str(&format!("{}", largest));
            } else {
                p.push_str(&format!("{}-{}", largest, smallest));
            }

            for _ in 0..f.u.ack.range_count {
                let mut gap = 0;
                let mut range = 0;

                let n = ngx_quic_parse_ack_range(log, data, pos, end, &mut gap, &mut range);
                if n == NGX_ERROR as isize {
                    break;
                }

                pos += n as usize;

                largest = smallest.wrapping_sub(gap).wrapping_sub(2);
                smallest = largest.wrapping_sub(range);

                if largest == smallest {
                    p.push_str(&format!(" {}", largest));
                } else {
                    p.push_str(&format!(" {}-{}", largest, smallest));
                }
            }

            if f.ty == NGX_QUIC_FT_ACK_ECN {
                p.push_str(&format!(" ECN counters ect0:{} ect1:{} ce:{}", f.u.ack.ect0, f.u.ack.ect1, f.u.ack.ce));
            }
        }

        NGX_QUIC_FT_PING => p.push_str("PING"),

        NGX_QUIC_FT_NEW_CONNECTION_ID => {
            p.push_str(&format!("NEW_CONNECTION_ID seq:{} retire:{} len:{}", f.u.ncid.seqnum, f.u.ncid.retire, f.u.ncid.len));
        }

        NGX_QUIC_FT_RETIRE_CONNECTION_ID => {
            p.push_str(&format!("RETIRE_CONNECTION_ID seqnum:{}", f.u.retire_cid.sequence_number));
        }

        NGX_QUIC_FT_CONNECTION_CLOSE | NGX_QUIC_FT_CONNECTION_CLOSE_APP => {
            p.push_str(&format!("CONNECTION_CLOSE{} err:{}", if f.ty == NGX_QUIC_FT_CONNECTION_CLOSE { "" } else { "_APP" }, f.u.close.error_code));

            if !f.u.close.reason.is_empty() {
                p.push_str(&format!(" {}", B(&f.u.close.reason)));
            }

            if f.ty == NGX_QUIC_FT_CONNECTION_CLOSE {
                p.push_str(&format!(" ft:{}", f.u.close.frame_type));
            }
        }

        NGX_QUIC_FT_STREAM => {
            p.push_str(&format!("STREAM id:0x{:x}", f.u.stream.stream_id));

            if f.u.stream.off {
                p.push_str(&format!(" off:{}", f.u.ord.offset));
            }

            if f.u.stream.len {
                p.push_str(&format!(" len:{}", f.u.ord.length));
            }

            if f.u.stream.fin {
                p.push_str(" fin:1");
            }
        }

        NGX_QUIC_FT_MAX_DATA => {
            p.push_str(&format!("MAX_DATA max_data:{} on recv", f.u.max_data.max_data));
        }

        NGX_QUIC_FT_RESET_STREAM => {
            p.push_str(&format!("RESET_STREAM id:0x{:x} error_code:0x{:x} final_size:{}", f.u.reset_stream.id, f.u.reset_stream.error_code, f.u.reset_stream.final_size));
        }

        NGX_QUIC_FT_STOP_SENDING => {
            p.push_str(&format!("STOP_SENDING id:0x{:x} err:0x{:x}", f.u.stop_sending.id, f.u.stop_sending.error_code));
        }

        NGX_QUIC_FT_STREAMS_BLOCKED | NGX_QUIC_FT_STREAMS_BLOCKED2 => {
            p.push_str(&format!("STREAMS_BLOCKED limit:{} bidi:{}", f.u.streams_blocked.limit, f.u.streams_blocked.bidi as u32));
        }

        NGX_QUIC_FT_MAX_STREAMS | NGX_QUIC_FT_MAX_STREAMS2 => {
            p.push_str(&format!("MAX_STREAMS limit:{} bidi:{}", f.u.max_streams.limit, f.u.max_streams.bidi as u32));
        }

        NGX_QUIC_FT_MAX_STREAM_DATA => {
            p.push_str(&format!("MAX_STREAM_DATA id:0x{:x} limit:{}", f.u.max_stream_data.id, f.u.max_stream_data.limit));
        }

        NGX_QUIC_FT_DATA_BLOCKED => {
            p.push_str(&format!("DATA_BLOCKED limit:{}", f.u.data_blocked.limit));
        }

        NGX_QUIC_FT_STREAM_DATA_BLOCKED => {
            p.push_str(&format!("STREAM_DATA_BLOCKED id:0x{:x} limit:{}", f.u.stream_data_blocked.id, f.u.stream_data_blocked.limit));
        }

        NGX_QUIC_FT_PATH_CHALLENGE => {
            p.push_str(&format!("PATH_CHALLENGE data:0x{}", hex(&f.u.path_challenge.data)));
        }

        NGX_QUIC_FT_PATH_RESPONSE => {
            p.push_str(&format!("PATH_RESPONSE data:0x{}", hex(&f.u.path_challenge.data)));
        }

        NGX_QUIC_FT_NEW_TOKEN => p.push_str("NEW_TOKEN"),

        NGX_QUIC_FT_HANDSHAKE_DONE => p.push_str("HANDSHAKE DONE"),

        _ => p.push_str(&format!("unknown type 0x{:x}", f.ty)),
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic frame {} {}:{} {}", if tx { "tx" } else { "rx" }, ngx_quic_level_name(f.level), f.pnum, p);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(qc: &QChain) -> Vec<u8> {
        qc.to_vec()
    }

    #[test]
    fn blocks_reused_by_the_last_buffer() {
        FREE_BLOCKS.with(|f| f.borrow_mut().clear());

        let b = ngx_quic_alloc_buf();
        let p = b.block.borrow().as_ptr();

        // a clone shares the block: given back with the last of them
        let clone = b.clone();
        drop(b);
        assert_eq!(FREE_BLOCKS.with(|f| f.borrow().len()), 0);
        drop(clone);
        assert_eq!(FREE_BLOCKS.with(|f| f.borrow().len()), 1);

        // reused as it is (not cleared), empty
        clone_write(p);

        let b = ngx_quic_alloc_buf();
        assert_eq!(b.block.borrow().as_ptr(), p);
        assert_eq!((b.pos, b.last, b.sync), (0, 0, false));
        assert_eq!(FREE_BLOCKS.with(|f| f.borrow().len()), 0);
    }

    fn clone_write(p: *const u8) {
        FREE_BLOCKS.with(|f| {
            let f = f.borrow();
            let block = f.last().unwrap();
            assert_eq!(block.borrow().as_ptr(), p);
            block.borrow_mut()[0] = 9;
        });
    }

    #[test]
    fn readable_and_copied() {
        let log = crate::log::Log::stderr(0);
        crate::connection::set_connection_n(16);
        let c = crate::connection::Connection::get(-1, &log).expect("connection");

        let d: Vec<u8> = (0..200u8).collect();

        // [0, 50) and [60, 200): a hole between
        let mut qb = QuicBuffer::default();
        let mut input = [&d[0..50]];
        ngx_quic_write_buffer(&c, &mut qb, &mut input, 50, 0);
        let mut input = [&d[60..200]];
        ngx_quic_write_buffer(&c, &mut qb, &mut input, 140, 60);

        assert_eq!(ngx_quic_buffer_readable(&qb, 1000), 50);
        assert_eq!(ngx_quic_buffer_readable(&qb, 20), 20);

        let mut buf = [0u8; 20];
        assert_eq!(ngx_quic_read_buffer_copy(&c, &mut qb, &mut buf), 20);
        assert_eq!(&buf[..], &d[0..20]);
        assert_eq!(qb.offset, 20);

        let mut buf = [0u8; 100];
        assert_eq!(ngx_quic_read_buffer_copy(&c, &mut qb, &mut buf), 30);
        assert_eq!(&buf[..30], &d[20..50]);
        assert_eq!(qb.offset, 50);
        assert_eq!(ngx_quic_buffer_readable(&qb, 1000), 0);

        // the hole filled: the rest, read into a chain with room
        let mut input = [&d[50..60]];
        ngx_quic_write_buffer(&c, &mut qb, &mut input, 10, 50);
        assert_eq!(ngx_quic_buffer_readable(&qb, 1000), 150);

        let mut out = QChain(VecDeque::with_capacity(8));
        ngx_quic_read_buffer_into(&c, &mut qb, 1000, &mut out);
        assert_eq!(data(&out), &d[50..200]);
        assert_eq!(qb.offset, 200);
    }

    #[test]
    fn frames_from_the_free_list() {
        let log = crate::log::Log::stderr(0);
        crate::connection::set_connection_n(16);
        let c = crate::connection::Connection::get(-1, &log).expect("connection");

        let qc = Rc::new(crate::quic::QuicConnection::new_for_tests(&c));
        qc.max_frames.set(2);
        *c.quic_conn.borrow_mut() = Some(qc.clone());

        let mut f = ngx_quic_alloc_frame(&c).expect("frame");
        f.ty = NGX_QUIC_FT_STREAM;
        f.data.0.push_back(ngx_quic_alloc_buf());
        let p = &*f as *const QuicFrame;

        let g = ngx_quic_alloc_frame(&c).expect("frame");

        // the flood limit, as C counts
        assert!(ngx_quic_alloc_frame(&c).is_none());

        ngx_quic_free_frame(&c, f);
        assert_eq!(qc.free_frames.get(), 1);

        // the same frame, reset, its chain empty with its room
        let f = ngx_quic_alloc_frame(&c).expect("frame");
        assert_eq!(&*f as *const QuicFrame, p);
        assert_eq!(f.ty, 0);
        assert!(f.data.is_empty() && f.data.0.capacity() > 0);
        assert_eq!(qc.free_frames.get(), 0);

        ngx_quic_free_frame(&c, f);
        ngx_quic_free_frame(&c, g);
        assert_eq!((qc.free_frames.get(), qc.nframes.get()), (2, 2));
    }

    #[test]
    fn write_read_skip() {
        let log = crate::log::Log::stderr(0);
        crate::connection::set_connection_n(16);
        let c = crate::connection::Connection::get(-1, &log).expect("connection");

        let mut qb = QuicBuffer::default();

        // out of order: [10, 20) then [0, 10), then a retransmission
        let d: Vec<u8> = (0..30u8).collect();

        let mut input = [&d[10..20]];
        ngx_quic_write_buffer(&c, &mut qb, &mut input, 10, 10);
        assert_eq!(qb.size, 10);
        assert!(input[0].is_empty());

        // a hole first: nothing to read
        assert!(ngx_quic_read_buffer(&c, &mut qb, 100).is_empty());

        let mut input = [&d[0..10]];
        ngx_quic_write_buffer(&c, &mut qb, &mut input, 10, 0);
        assert_eq!(qb.size, 20);

        let mut input = [&d[5..25]];
        ngx_quic_write_buffer(&c, &mut qb, &mut input, 20, 5);
        assert_eq!(qb.size, 25);

        let out = ngx_quic_read_buffer(&c, &mut qb, 7);
        assert_eq!(data(&out), &d[0..7]);
        assert_eq!(qb.offset, 7);

        let out = ngx_quic_read_buffer(&c, &mut qb, 100);
        assert_eq!(data(&out), &d[7..25]);
        assert_eq!(qb.offset, 25);

        // data over a block
        let big: Vec<u8> = (0..10000u32).map(|i| i as u8).collect();
        let out = ngx_quic_copy_buffer(&c, &big);
        assert_eq!(out.0.len(), 3);
        assert_eq!(data(&out), big);

        let mut qb = QuicBuffer::default();
        let mut input = [&big[..]];
        ngx_quic_write_buffer(&c, &mut qb, &mut input, big.len() as u64, 0);
        ngx_quic_skip_buffer(&c, &mut qb, 5000);
        assert_eq!(qb.offset, 5000);
        assert_eq!(data(&ngx_quic_read_buffer(&c, &mut qb, u64::MAX)), &big[5000..]);
    }
}
