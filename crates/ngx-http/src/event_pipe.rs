//! ngx_event_pipe.c: the upstream response read into the buffers of the
//! pipe, passed through the module's input filter to p->in, written to a
//! temporary file when the client is slower than the upstream (or for the
//! cache and *_store: everything), and passed to the client.
//!
//! The raw buffers are p->bufs (p->allocated of p->bufs.num), and u->buffer
//! with the part of the body read with the header. A raw buffer is filled
//! before the input filter gets it, unless it holds the rest of the body
//! (p->length) or the upstream closed the connection. The buffers the input
//! filter makes of it are its shadows: the raw buffer is free again when
//! all of them are sent or written to the temporary file. The reading and
//! the writing are driven by crate::upstream_rt (ngx_event_pipe()); this
//! part is their buffer and file bookkeeping.

use std::collections::VecDeque;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, BufFile, Chain};
use ngx_core::conf::Bufs;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::{ngx_log_debug, ngx_log_error};

/// A raw buffer of the pipe: what was read into it, its size and number.
/// Its memory is initialized (zeroed) once, when it is first read into,
/// and read into in place.
pub struct RawBuf {
    /// buf->start .. buf->end once read into (empty before)
    pub data: Vec<u8>,
    /// buf->pos: u->buffer has the response header before the body
    pub pos: usize,
    /// buf->last
    pub last: usize,
    /// buf->end - buf->pos: the room for data
    pub size: usize,
    /// which raw buffer (0: u->buffer)
    pub slot: usize,
}

impl RawBuf {
    /// A raw buffer of `size` bytes, on the memory given (kept from its
    /// last use, or empty).
    pub fn new(data: Vec<u8>, size: usize, slot: usize) -> RawBuf {
        RawBuf { data, pos: 0, last: 0, size, slot }
    }

    /// buf->pos .. buf->last
    pub fn bytes(&self) -> &[u8] {
        &self.data[self.pos..self.last]
    }

    /// buf->last - buf->pos
    pub fn len(&self) -> usize {
        self.last - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// buf->last == buf->end
    pub fn full(&self) -> bool {
        self.len() >= self.size
    }

    /// The room left (buf->end - buf->last).
    pub fn room(&self) -> usize {
        self.size.saturating_sub(self.len())
    }

    /// buf->last .. buf->end, to read into: the memory initialized the
    /// first time.
    pub fn unfilled_mut(&mut self) -> &mut [u8] {
        let end = self.pos + self.size;

        if self.data.len() < end {
            self.data.resize(end, 0);
        }

        &mut self.data[self.last..end]
    }

    /// buf->last += n: what a read put in unfilled_mut()
    pub fn filled(&mut self, n: usize) {
        self.last = (self.last + n).min(self.pos + self.size);
    }

    /// The data appended (what was read into another buffer).
    pub fn extend(&mut self, data: &[u8]) {
        let n = data.len().min(self.room());

        self.unfilled_mut()[..n].copy_from_slice(&data[..n]);
        self.filled(n);
    }

    /// The shadow of all the data of the buffer, owning its memory.
    pub fn into_buf(mut self) -> Buf {
        self.data.truncate(self.last);

        let mut b = Buf::from_vec(self.data);
        b.pos = self.pos;
        b
    }
}

/// p->temp_file: a temporary file of the module's temp path, or the file
/// the cache will have.
pub enum PipeTempFile {
    Plain(ngx_core::file::TempFile),
    Cache(crate::upstream_cache::CacheWriter),
}

impl PipeTempFile {
    /// p->temp_file->offset
    pub fn offset(&self) -> i64 {
        match self {
            PipeTempFile::Plain(tf) => tf.offset,
            PipeTempFile::Cache(w) => w.tf.offset,
        }
    }

    /// p->temp_file->file.fd != NGX_INVALID_FILE
    pub fn created(&self) -> bool {
        match self {
            PipeTempFile::Plain(tf) => tf.fd != -1,
            PipeTempFile::Cache(w) => w.tf.fd != -1,
        }
    }

    fn fd_name(&self) -> (i32, Vec<u8>) {
        match self {
            PipeTempFile::Plain(tf) => (tf.fd, tf.name.clone()),
            PipeTempFile::Cache(w) => (w.tf.fd, w.tf.name.clone()),
        }
    }

    /// ngx_write_chain_to_temp_file, and the offset advanced
    fn write(&mut self, chain: &Chain, log: &Log) -> Result<i64, ()> {
        match self {
            PipeTempFile::Plain(tf) => {
                let n = tf.write_chain(chain)?;
                tf.offset += n;
                Ok(n)
            }

            PipeTempFile::Cache(w) => {
                let mut n = 0i64;

                for b in chain.iter() {
                    if let BufData::Memory(v) = &b.data {
                        let data = &v[b.pos.min(v.len())..b.last.min(v.len())];

                        if w.tf.write(data, log).is_err() {
                            w.failed = true;
                            return Err(());
                        }

                        n += data.len() as i64;
                    }
                }

                Ok(n)
            }
        }
    }
}

/// What the pipe keeps of a raw buffer.
struct RawSlot {
    /// its size
    size: usize,
    /// its shadows that are in p->in or being sent
    refs: usize,
    /// it is in free_raw
    in_free: bool,
    /// its memory, when the input filter did not give it to its shadows
    /// (they copied the data): kept for the next use of the buffer
    mem: Vec<u8>,
}

/// ngx_event_pipe_t
pub struct EventPipe {
    // the configuration of the upstream
    /// p->bufs
    pub bufs: Bufs,
    /// p->busy_size
    pub busy_size: usize,
    pub max_temp_file_size: i64,
    pub temp_file_write_size: i64,
    /// p->limit_rate and p->start_sec
    pub limit_rate: usize,
    pub start_sec: i64,
    pub read_timeout: u64,
    /// p->cacheable: u->cacheable || u->store
    pub cacheable: bool,

    // the state
    /// p->length: what is left of the body for the input filter (-1: up to
    /// the end of the connection)
    pub length: i64,
    pub upstream_done: bool,
    pub upstream_eof: bool,
    pub upstream_error: bool,
    pub downstream_done: bool,
    pub downstream_error: bool,
    /// p->read_length and p->preread_size
    pub read_length: i64,
    pub preread_size: i64,

    /// p->in: the buffers of the input filter
    pub in_bufs: Chain,
    /// p->out: the parts of the temporary file
    pub out_bufs: Chain,
    /// p->free_raw_bufs
    free_raw: VecDeque<RawBuf>,
    /// p->allocated
    allocated: usize,
    /// the raw buffers, by number
    slots: Vec<RawSlot>,
    /// the chain read into (taken by read_chain())
    pub chain: Vec<RawBuf>,
    /// the raw buffers of the memory buffers of the batch being sent
    pub sending: Vec<i32>,
    pub temp_file: PipeTempFile,
    file: Option<Rc<BufFile>>,
    /// p->preread_bufs: u->buffer with the body read with the header
    preread: Option<RawBuf>,
    log: Log,
}

impl EventPipe {
    /// The pipe of ngx_http_upstream_send_response, with u->buffer as its
    /// first raw buffer: `buffer`, the body read with the header from
    /// `pos`, with room for `preread_room` bytes of it.
    pub fn new(bufs: Bufs, busy_size: usize, temp_file: PipeTempFile, buffer: Vec<u8>, pos: usize, preread_room: usize, log: &Log) -> EventPipe {
        let pos = pos.min(buffer.len());
        let preread = buffer.len() - pos;

        let mut slots = Vec::with_capacity(bufs.num + 1);

        slots.push(RawSlot { size: preread_room.max(preread).max(1), refs: 0, in_free: false, mem: Vec::new() });

        let mut p = EventPipe {
            bufs,
            busy_size,
            max_temp_file_size: 0,
            temp_file_write_size: 0,
            limit_rate: 0,
            start_sec: 0,
            read_timeout: 60000,
            cacheable: false,
            length: -1,
            upstream_done: false,
            upstream_eof: false,
            upstream_error: false,
            downstream_done: false,
            downstream_error: false,
            read_length: 0,
            preread_size: preread as i64,
            in_bufs: Chain::new(),
            out_bufs: Chain::new(),
            free_raw: VecDeque::new(),
            allocated: 0,
            slots,
            chain: Vec::new(),
            sending: Vec::new(),
            temp_file,
            file: None,
            preread: None,
            log: log.clone(),
        };

        // p->preread_bufs: u->buffer as a raw buffer being read into
        let last = buffer.len();

        p.preread = Some(RawBuf { data: buffer, pos, last, size: p.slots[0].size, slot: 0 });

        p
    }

    /// p->upstream_eof || p->upstream_error || p->upstream_done
    pub fn upstream_finished(&self) -> bool {
        self.upstream_eof || self.upstream_error || self.upstream_done
    }

    /// Whether there is anything to pass to the client.
    pub fn has_output(&self) -> bool {
        !self.out_bufs.is_empty() || (!self.cacheable && !self.in_bufs.is_empty())
    }

    /// ngx_event_pipe_add_free_buf: a raw buffer free again goes to
    /// p->free_raw_bufs, first if the first one is empty, else after it.
    fn add_free_buf(&mut self, slot: usize) {
        let s = &mut self.slots[slot];

        // its memory, if kept (else made when it is read into)
        let b = RawBuf::new(std::mem::take(&mut s.mem), s.size, slot);

        s.in_free = true;

        match self.free_raw.front() {
            None => self.free_raw.push_back(b),
            Some(first) if first.is_empty() => self.free_raw.push_front(b),
            Some(_) => self.free_raw.insert(1, b),
        }
    }

    /// A shadow of a raw buffer is sent or written to the temporary file.
    pub fn release(&mut self, slot: usize) {
        let s = match self.slots.get_mut(slot) {
            Some(s) => s,
            None => return,
        };

        if s.refs > 0 {
            s.refs -= 1;
        }

        if s.refs == 0 && !s.in_free {
            self.add_free_buf(slot);
        }
    }

    /// A raw buffer the input filter made no shadow of.
    pub fn release_raw(&mut self, slot: usize) {
        if self.slots.get(slot).is_some_and(|s| s.refs == 0 && !s.in_free) {
            self.add_free_buf(slot);
        }
    }

    /// A shadow of a raw buffer goes to p->in (the input filters).
    pub fn push_in(&mut self, mut b: Buf, slot: usize) {
        b.num = slot as i32;
        b.recycled = true;

        if let Some(s) = self.slots.get_mut(slot) {
            s.refs += 1;
        }

        self.in_bufs.push_back(b);
    }

    /// The preread part of the body, if it was not taken yet.
    pub fn take_preread(&mut self) -> Option<RawBuf> {
        self.preread.take()
    }

    /// The raw buffers to read into, moved to `chain`, as
    /// ngx_event_pipe_read_upstream finds them: all the free ones (the
    /// first may be partly filled), a new one while p->allocated <
    /// p->bufs.num, or none (false: `downstream_ready`, the client can take
    /// p->in now, so the upstream waits; otherwise p->in goes to the
    /// temporary file first, if allowed, and the raw buffers it frees are
    /// read into).
    pub fn read_chain(&mut self, chain: &mut Vec<RawBuf>, downstream_ready: bool) -> Result<bool, ()> {
        if !self.free_raw.is_empty() {
            self.take_free(chain);
            return Ok(true);
        }

        if self.allocated < self.bufs.num {
            // allocate a new buf if it's still allowed (its memory when it
            // is read into)
            self.allocated += 1;

            let slot = self.slots.len();
            let size = self.bufs.size.max(1);

            self.slots.push(RawSlot { size, refs: 0, in_free: false, mem: Vec::new() });

            chain.push(RawBuf::new(Vec::new(), size, slot));

            return Ok(true);
        }

        if !self.cacheable && !self.downstream_error && downstream_ready {
            // the bufs are not needed to be saved in a cache and a
            // downstream is ready, then write the bufs to a downstream
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, self.log, "pipe downstream ready");
            return Ok(false);
        }

        if self.cacheable || self.temp_file.offset() < self.max_temp_file_size {
            // save some bufs from p->in to a temporary file, and add them
            // to a p->out chain
            let rc = self.write_chain_to_temp_file()?;

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, self.log, "pipe temp offset: {}", self.temp_file.offset());

            if rc == NGX_BUSY {
                return Ok(false);
            }

            self.take_free(chain);

            return Ok(!chain.is_empty());
        }

        // there are no bufs to read in
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, self.log, "no pipe bufs to read in");

        Ok(false)
    }

    /// p->free_raw_bufs taken (p->free_raw_bufs = NULL).
    fn take_free(&mut self, chain: &mut Vec<RawBuf>) {
        for b in self.free_raw.drain(..) {
            self.slots[b.slot].in_free = false;
            chain.push(b);
        }
    }

    /// The raw buffers of a chain not given to the input filter go back to
    /// p->free_raw_bufs, first, in their order (the partly filled one
    /// first).
    pub fn put_back_chain(&mut self, chain: &mut Vec<RawBuf>) {
        for b in chain.drain(..).rev() {
            self.put_back(b);
        }
    }

    /// The memory of a raw buffer whose data the input filter copied:
    /// kept for its next use.
    pub fn recycle(&mut self, b: RawBuf) {
        if let Some(s) = self.slots.get_mut(b.slot) {
            if s.mem.capacity() < b.data.capacity() {
                s.mem = b.data;
            }
        }
    }

    /// A raw buffer read into but not full goes back first to
    /// p->free_raw_bufs.
    pub fn put_back(&mut self, b: RawBuf) {
        self.slots[b.slot].in_free = true;
        self.free_raw.push_front(b);
    }

    /// The first free raw buffer, taken if it holds at least p->length (the
    /// rest of the body), or anything at the end of the connection.
    pub fn take_partial(&mut self) -> Option<RawBuf> {
        let first = self.free_raw.front()?;

        let take = if self.upstream_eof || self.upstream_error {
            true
        } else {
            self.length != -1 && first.len() as i64 >= self.length
        };

        if !take {
            return None;
        }

        let b = self.free_raw.pop_front()?;
        self.slots[b.slot].in_free = false;
        Some(b)
    }

    /// ngx_event_pipe_write_chain_to_temp_file: some of p->in (all of it
    /// when cacheable) written to the temporary file and added to p->out;
    /// NGX_BUSY if nothing could be written, Err (NGX_ABORT) on an error.
    pub fn write_chain_to_temp_file(&mut self) -> Result<i64, ()> {
        let mut n_out = 0;

        if !self.cacheable {
            let mut size: i64 = 0;
            let mut prev_slot: Option<i32> = None;

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, self.log, "pipe offset: {}", self.temp_file.offset());

            for b in self.in_bufs.iter() {
                let bsize = b.buf_size();

                // the shadows of a raw buffer are written together
                let first_of_raw = prev_slot != Some(b.num);

                if first_of_raw && (size + bsize > self.temp_file_write_size || self.temp_file.offset() + size + bsize > self.max_temp_file_size) {
                    break;
                }

                prev_slot = Some(b.num);
                size += bsize;
                n_out += 1;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, self.log, "size: {}", size);

            if n_out == 0 {
                return Ok(NGX_BUSY);
            }
        } else {
            n_out = self.in_bufs.len();
        }

        let out: Chain = self.in_bufs.drain(..n_out).collect();

        let offset = self.temp_file.offset();

        let n = self.temp_file.write(&out, &self.log)?;

        if self.file.is_none() && self.temp_file.created() {
            let (fd, name) = self.temp_file.fd_name();
            self.file = Some(Rc::new(BufFile { fd, name, directio: false }));
        }

        if n > 0 {
            // update previous buffer or add new buffer
            match self.out_bufs.back_mut() {
                Some(b) if b.file_last == offset => b.file_last = offset + n,
                _ => {
                    let mut b = Buf::file(self.file.clone().expect("temp file"), offset, offset + n);
                    b.in_file = true;
                    b.temp_file = true;
                    self.out_bufs.push_back(b);
                }
            }
        }

        for b in out.iter() {
            self.release(b.num as usize);
        }

        Ok(NGX_OK)
    }

    /// ngx_event_pipe_drain_chains: p->out and p->in dropped after a
    /// client error, their raw buffers free.
    pub fn drain_chains(&mut self) {
        let out: Vec<Buf> = self.out_bufs.drain(..).chain(self.in_bufs.drain(..)).collect();

        for b in out.iter() {
            if !b.in_file {
                self.release(b.num as usize);
            }
        }
    }

    /// What ngx_event_pipe_write_to_downstream passes to the output filter
    /// now: when the upstream is done, all of p->out and p->in; otherwise
    /// p->out, then (not cacheable) p->in up to p->busy_size of raw buffers.
    pub fn write_batch(&mut self) -> Option<Chain> {
        if self.downstream_error {
            self.drain_chains();
            return None;
        }

        let mut batch = Chain::new();

        if self.upstream_finished() {
            // pass the p->out and p->in chains to the output filter
            for mut b in self.out_bufs.drain(..).chain(self.in_bufs.drain(..)) {
                b.recycled = false;
                batch.push_back(b);
            }

            if batch.is_empty() {
                return None;
            }

            return Some(batch);
        }

        let mut bsize: usize = 0;
        let mut prev_slot: Option<i32> = None;

        loop {
            if let Some(b) = self.out_bufs.pop_front() {
                if b.recycled {
                    ngx_log_error!(NGX_LOG_ALERT, self.log, None, "recycled buffer in pipe out chain");
                }

                batch.push_back(b);
                continue;
            }

            if self.cacheable {
                break;
            }

            let (slot, recycled) = match self.in_bufs.front() {
                Some(b) => (b.num, b.recycled),
                None => break,
            };

            if recycled && prev_slot != Some(slot) {
                let size = self.slots.get(slot as usize).map(|s| s.size).unwrap_or(0);

                if bsize + size > self.busy_size && !batch.is_empty() {
                    break;
                }

                bsize += size;
            }

            prev_slot = Some(slot);

            let b = self.in_bufs.pop_front().expect("in buf");
            batch.push_back(b);
        }

        if batch.is_empty() {
            return None;
        }

        Some(batch)
    }

    /// The raw buffers of the shadows sent in a batch are free again.
    pub fn sent(&mut self, batch: &[i32]) {
        for &slot in batch {
            self.release(slot as usize);
        }
    }

    /// A batch goes to the output filter: the raw buffers of its memory
    /// buffers are noted (one batch is sent at a time).
    pub fn begin_send(&mut self, batch: &Chain) {
        self.sending.clear();
        self.sending.extend(batch.iter().filter(|b| !b.in_file).map(|b| b.num));
    }

    /// The batch of begin_send() is sent: its raw buffers are free again.
    pub fn end_send(&mut self) {
        let sending = std::mem::take(&mut self.sending);

        self.sent(&sending);

        self.sending = sending;
        self.sending.clear();
    }

    /// release_raw() of a raw buffer whose data the input filter copied,
    /// its memory kept (recycle()).
    pub fn release_raw_buf(&mut self, b: RawBuf) {
        let slot = b.slot;

        self.recycle(b);
        self.release_raw(slot);
    }
}

/// The numbers of the raw buffers of the memory buffers of a batch.
pub fn batch_slots(batch: &Chain) -> Vec<i32> {
    batch.iter().filter(|b| !b.in_file).map(|b| b.num).collect()
}

/// ngx_event_pipe_copy_input_filter: the raw buffer as it is (up to
/// p->length), its shadow in p->in.
pub fn copy_input_filter(p: &mut EventPipe, buf: RawBuf) -> i64 {
    if buf.is_empty() {
        p.release_raw_buf(buf);
        return NGX_OK;
    }

    if p.upstream_done {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, p.log, "input data after close");
        p.release_raw_buf(buf);
        return NGX_OK;
    }

    if p.length == 0 {
        p.upstream_done = true;

        ngx_log_error!(NGX_LOG_WARN, p.log, None, "upstream sent more data than specified in \"Content-Length\" header");

        p.release_raw_buf(buf);
        return NGX_OK;
    }

    let slot = buf.slot;
    let len = buf.len();
    let mut buf = buf;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, p.log, "input buf #{}", slot);

    if p.length != -1 {
        if len as i64 > p.length {
            ngx_log_error!(NGX_LOG_WARN, p.log, None, "upstream sent more data than specified in \"Content-Length\" header");

            buf.last = buf.pos + p.length as usize;
            p.length = 0;
            p.upstream_done = true;
        } else {
            p.length -= len as i64;
        }
    }

    p.push_in(buf.into_buf(), slot);

    NGX_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> Log {
        Log::stderr(NGX_LOG_ERR)
    }

    fn pipe(num: usize, size: usize, preread: &[u8], room: usize) -> EventPipe {
        let path = Rc::new(ngx_core::conf::PathConf::new(std::env::temp_dir().to_str().unwrap().as_bytes().to_vec(), [0, 0, 0]));
        let tf = ngx_core::file::TempFile::new(path, &log());
        let mut p = EventPipe::new(Bufs { num, size }, size * 2, PipeTempFile::Plain(tf), preread.to_vec(), 0, room, &log());
        p.max_temp_file_size = 1 << 20;
        p.temp_file_write_size = (size * 2) as i64;
        p
    }

    /// A raw buffer of `size` with the data read into it.
    fn raw(data: &[u8], size: usize, slot: usize) -> RawBuf {
        let mut b = RawBuf::new(Vec::new(), size, slot);
        b.extend(data);
        b
    }

    /// The one raw buffer read_chain() gives, if any.
    fn one(p: &mut EventPipe, downstream_ready: bool) -> Option<RawBuf> {
        let mut chain = Vec::new();

        if !p.read_chain(&mut chain, downstream_ready).unwrap() {
            return None;
        }

        assert_eq!(chain.len(), 1);
        chain.pop()
    }

    fn in_data(p: &EventPipe) -> Vec<u8> {
        p.in_bufs
            .iter()
            .flat_map(|b| match &b.data {
                BufData::Memory(v) => v[b.pos..b.last].to_vec(),
                _ => vec![],
            })
            .collect()
    }

    #[test]
    fn copy_filter_length() {
        let mut p = pipe(2, 4, b"", 8);
        p.length = 5;

        copy_input_filter(&mut p, raw(b"abcd", 4, 0));
        assert_eq!(p.length, 1);
        copy_input_filter(&mut p, raw(b"efgh", 4, 0));
        assert!(p.upstream_done);
        assert_eq!(in_data(&p), b"abcde");
    }

    #[test]
    fn raw_buf_read_in_place() {
        let mut b = RawBuf::new(Vec::new(), 4, 1);
        assert_eq!(b.unfilled_mut().len(), 4);

        b.unfilled_mut()[..3].copy_from_slice(b"abc");
        b.filled(3);
        assert_eq!(b.bytes(), b"abc");
        assert_eq!(b.room(), 1);

        // the shadow has the data only
        let s = b.into_buf();
        match &s.data {
            BufData::Memory(v) => assert_eq!(v, b"abc"),
            _ => panic!("memory"),
        }
    }

    #[test]
    fn raw_bufs_allocated_then_none() {
        let mut p = pipe(2, 4, b"", 8);
        let _ = p.take_preread();

        let a = one(&mut p, true).unwrap();
        let b = one(&mut p, true).unwrap();
        assert_ne!(a.slot, b.slot);

        // all allocated, the downstream ready: the upstream waits
        assert!(one(&mut p, true).is_none());

        copy_input_filter(&mut p, raw(b"1234", 4, a.slot));

        // the shadow sent: the raw buffer is free again
        let batch = p.write_batch().unwrap();
        assert_eq!(batch.len(), 1);
        p.begin_send(&batch);
        assert_eq!(p.sending, [a.slot as i32]);
        p.end_send();

        let c = one(&mut p, true).unwrap();
        assert_eq!(c.slot, a.slot);
    }

    #[test]
    fn all_free_buffers_read_into() {
        let mut p = pipe(3, 4, b"", 8);
        let _ = p.take_preread();

        let a = one(&mut p, false).unwrap();
        let b = one(&mut p, false).unwrap();

        // both free again, the first partly filled: read into together,
        // in their order
        let mut a = a;
        a.extend(b"x");
        p.put_back(b);
        p.put_back(a);

        let mut chain = Vec::new();
        assert!(p.read_chain(&mut chain, false).unwrap());
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].bytes(), b"x");
        assert_eq!(chain[0].room() + chain[1].room(), 7);

        // what was not filled goes back first, in order
        chain[1].extend(b"yz");
        p.put_back_chain(&mut chain);
        assert!(chain.is_empty());

        let t = p.take_partial();
        assert!(t.is_none());

        let mut chain = Vec::new();
        assert!(p.read_chain(&mut chain, false).unwrap());
        assert_eq!(chain[0].bytes(), b"x");
        assert_eq!(chain[1].bytes(), b"yz");
    }

    #[test]
    fn memory_kept_when_copied() {
        let mut p = pipe(1, 4, b"", 8);
        let _ = p.take_preread();

        let mut a = one(&mut p, true).unwrap();
        a.extend(b"ab");
        let ptr = a.data.as_ptr();

        // a filter that copied the data: the memory is used again
        p.release_raw_buf(a);

        let b = one(&mut p, true).unwrap();
        assert_eq!(b.data.as_ptr(), ptr);
        assert!(b.is_empty());
    }

    #[test]
    fn temp_file_when_downstream_busy() {
        let mut p = pipe(1, 4, b"", 8);
        let _ = p.take_preread();

        let a = one(&mut p, false).unwrap();
        copy_input_filter(&mut p, raw(b"1234", 4, a.slot));

        // no more buffers, the downstream busy: p->in goes to the file
        let b = one(&mut p, false).unwrap();
        assert_eq!(b.slot, a.slot);
        assert!(p.in_bufs.is_empty());
        assert_eq!(p.out_bufs.len(), 1);
        assert_eq!(p.temp_file.offset(), 4);

        // contiguous writes extend the file buffer
        copy_input_filter(&mut p, raw(b"5678", 4, b.slot));
        let _ = one(&mut p, false).unwrap();
        assert_eq!(p.out_bufs.len(), 1);
        assert_eq!(p.out_bufs[0].file_last, 8);
    }

    #[test]
    fn preread_after_header() {
        // u->buffer: the header, then the body read with it
        let path = Rc::new(ngx_core::conf::PathConf::new(std::env::temp_dir().to_str().unwrap().as_bytes().to_vec(), [0, 0, 0]));
        let tf = ngx_core::file::TempFile::new(path, &log());
        let mut p = EventPipe::new(Bufs { num: 2, size: 4 }, 8, PipeTempFile::Plain(tf), b"HDR\r\nbody".to_vec(), 5, 6, &log());

        assert_eq!(p.preread_size, 4);

        let mut raw = p.take_preread().unwrap();
        assert_eq!(raw.bytes(), b"body");
        assert_eq!(raw.room(), 2);
        assert!(!raw.full());

        // read on after the header
        raw.extend(b"!?");
        assert!(raw.full());
        assert_eq!(raw.bytes(), b"body!?");

        p.length = 3;
        copy_input_filter(&mut p, raw);

        assert_eq!(in_data(&p), b"bod");
        assert!(p.upstream_done);
    }

    #[test]
    fn partial_taken_for_length() {
        let mut p = pipe(1, 8, b"", 8);
        let _ = p.take_preread();
        p.length = 3;

        let mut a = one(&mut p, true).unwrap();
        a.extend(b"ab");
        p.put_back(a);
        assert!(p.take_partial().is_none());

        let mut a = one(&mut p, true).unwrap();
        a.extend(b"c");
        p.put_back(a);
        let t = p.take_partial().unwrap();
        assert_eq!(t.bytes(), b"abc");
    }
}
