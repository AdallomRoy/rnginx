//! ngx_http_gzip_filter_module
//!
//! zlib (through flate2's safe API, the system zlib as in the C build)
//! writes the gzip header and trailer itself (deflateInit2() with
//! windowBits + 16).  flate2 has no memLevel parameter: its
//! deflateInit2() uses memLevel 8, whatever ngx_http_gzip_filter_memory()
//! computes from gzip_hash and the response length, so the compressed
//! bytes can differ from C where C uses another memLevel (small responses
//! of known length, gzip_hash other than 64k).  zlib allocates its memory
//! itself (flate2's allocator): there is no preallocated memory, hence
//! no "gzip alloc" debug lines and no "gzip filter failed to use
//! preallocated memory" alert.
//!
//! The buffers own their data here: the output buffers a buffer of
//! ctx->free stands for are allocated again when it is taken, and those
//! passed on are free once the next filter returns, as the write filter
//! has sent them by then (C keeps the ones not sent yet in ctx->busy).

use std::any::Any;
use std::rc::Rc;

use flate2::{Compress, Compression, FlushCompress, Status};

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::{cmd, cmd_fn, ngx_log_error};

use crate::http_types::*;
use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_gzip_filter_module");

/// MAX_WBITS of zconf.h
const MAX_WBITS: usize = 15;
/// MAX_MEM_LEVEL of zconf.h
const MAX_MEM_LEVEL: usize = 9;

// the flush values and the return codes of zlib.h, as nginx logs them

const Z_NO_FLUSH: i32 = 0;
const Z_SYNC_FLUSH: i32 = 2;
const Z_FINISH: i32 = 4;

const Z_OK: i32 = 0;
const Z_STREAM_END: i32 = 1;
const Z_STREAM_ERROR: i32 = -2;
const Z_BUF_ERROR: i32 = -5;

/// ngx_http_gzip_conf_t
pub struct GzipConf {
    pub enable: Val<bool>,
    pub no_buffer: Val<bool>,

    types: HttpTypesHash,

    pub bufs: Bufs,

    pub postpone_gzipping: Val<usize>,
    pub level: Val<i64>,
    pub wbits: Val<usize>,
    pub memlevel: Val<usize>,
    pub min_length: Val<usize>,

    types_keys: Option<HttpTypesKeys>,
}

/// ngx_http_gzip_ctx_t
pub struct GzipCtx {
    in_: Chain,
    /// ctx->free: the output buffers sent, their data to be allocated
    /// again when one is taken
    free: Vec<Buf>,
    out: Chain,

    in_buf: Option<Buf>,
    out_buf: Option<Buf>,
    bufs: usize,

    /// the deflate stream: ctx->preallocated != NULL, the zlib stream
    /// ngx_http_gzip_filter_deflate_start() initialized, until
    /// deflateEnd()
    zstream: Option<Compress>,

    /// the level and window of the stream (kept for reuse once it ends)
    level: u32,
    wbits: i32,

    flush: i32,
    redo: bool,
    done: bool,
    nomem: bool,
    buffering: bool,

    zin: usize,
    zout: usize,

    /// zstream.next_in != NULL: the unprocessed input starts at
    /// in_buf.pos
    next_in: bool,
    /// zstream.avail_in
    avail_in: usize,
    /// zstream.avail_out: the free space of out_buf, from out_buf.last
    avail_out: usize,
}

impl GzipCtx {
    fn new() -> GzipCtx {
        GzipCtx {
            in_: Chain::new(),
            free: Vec::new(),
            out: Chain::new(),
            in_buf: None,
            out_buf: None,
            bufs: 0,
            zstream: None,
            level: 0,
            wbits: 0,
            flush: Z_NO_FLUSH,
            redo: false,
            done: false,
            nomem: false,
            buffering: false,
            zin: 0,
            zout: 0,
            next_in: false,
            avail_in: 0,
            avail_out: 0,
        }
    }

    /// The first buffer of ctx->in for "%p"
    fn in_ptr(&self) -> usize {
        self.in_.front().map_or(0, |b| b as *const Buf as usize)
    }

    fn in_buf_ptr(&self) -> usize {
        self.in_buf.as_ref().map_or(0, |b| b as *const Buf as usize)
    }

    fn in_buf_pos(&self) -> usize {
        self.in_buf.as_ref().map_or(0, |b| buf_data_addr(b) + b.pos)
    }

    /// zstream.next_in for "%p"
    fn next_in_ptr(&self) -> usize {
        if self.next_in {
            self.in_buf_pos()
        } else {
            0
        }
    }

    /// zstream.next_out for "%p": the end of the data of out_buf
    fn next_out_ptr(&self) -> usize {
        self.out_buf.as_ref().map_or(0, |b| buf_data_addr(b) + b.last)
    }
}

/// The tag of the buffers of the module, (ngx_buf_tag_t)
/// &ngx_http_gzip_filter_module
fn gzip_tag() -> usize {
    static TAG: u8 = 0;
    &TAG as *const u8 as usize
}

/// The address of the data of a buffer in memory (buf->start) for the
/// "%p" of the debug log, 0 (NULL) for the others (pos and last of these
/// are NULL in C)
fn buf_data_addr(b: &Buf) -> usize {
    match &b.data {
        BufData::Memory(v) => v.as_ptr() as usize,
        _ => 0,
    }
}

/// buf->last - buf->pos
fn buf_mem_size(b: &Buf) -> usize {
    match &b.data {
        BufData::Memory(_) => b.last - b.pos,
        _ => 0,
    }
}

/// A buffer sent, as ngx_chain_update_chains() moves it to ctx->free:
/// pos and last at its start, its data to be allocated again
fn buf_shell(b: &Buf) -> Buf {
    Buf {
        pos: 0,
        last: 0,
        file_pos: 0,
        file_last: 0,
        tag: b.tag,
        num: b.num,
        data: BufData::None,
        temporary: b.temporary,
        memory: b.memory,
        mmap: b.mmap,
        recycled: b.recycled,
        in_file: b.in_file,
        flush: b.flush,
        sync: b.sync,
        last_buf: b.last_buf,
        last_in_chain: b.last_in_chain,
        temp_file: b.temp_file,
    }
}

/// The free output buffers kept, and the ended deflate streams kept
const FREE_OUT_BUFS: usize = 16;
const FREE_STREAMS: usize = 2;

thread_local! {
    /// The memory of the output buffers sent, as C's ctx->free keeps the
    /// buffers of the request, for the next ones of the same size
    static FREE_OUT: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
    /// Deflate streams ended and reset (deflateReset() is deflateEnd()
    /// followed by deflateInit() without freeing the state), for the next
    /// response of the same level and window, as C allocates the zlib
    /// state from the request's pool
    static FREE_ZSTREAMS: std::cell::RefCell<Vec<(u32, i32, Compress)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// ngx_create_temp_buf(): an empty buffer of `size` bytes of memory, not
/// initialized (deflate writes it)
fn create_temp_buf(size: usize) -> Buf {
    Buf { data: BufData::Memory(take_out_buf(size)), pos: 0, last: 0, temporary: true, ..Default::default() }
}

/// The memory of an output buffer: a free one of that size, or a new one
/// with exactly that capacity
fn take_out_buf(size: usize) -> Vec<u8> {
    let free = FREE_OUT.with(|f| {
        let mut f = f.borrow_mut();
        let i = f.iter().rposition(|v| v.capacity() == size)?;
        Some(f.swap_remove(i))
    });

    match free {
        Some(mut v) => {
            v.clear();
            v
        }
        None => Vec::with_capacity(size),
    }
}

/// An output buffer of the module (its tag)
pub fn is_out_buf(b: &Buf) -> bool {
    b.tag == gzip_tag()
}

/// The memory of an output buffer sent is free for the next ones
pub fn free_out_buf(v: Vec<u8>) {
    FREE_OUT.with(|f| {
        let mut f = f.borrow_mut();
        if f.len() < FREE_OUT_BUFS {
            f.push(v);
        }
    });
}

/// ngx_http_gzip_header_filter
/// gzip_header_filter passes the response on as it is: gzip off
fn gzip_header_idle(r: &R) -> bool {
    !*r.loc_conf::<GzipConf>(ctx_index()).borrow().enable
}

async fn gzip_header_filter(r: R, next: HeaderFilter) -> i64 {
    let conf = r.loc_conf::<GzipConf>(ctx_index());

    let skip = {
        let c = conf.borrow();
        let (status, content_encoding, content_length_n) = {
            let ho = r.headers_out.borrow();
            (ho.status, ho.content_encoding.as_ref().is_some_and(|h| !h.value.borrow().is_empty()), ho.content_length_n)
        };

        !*c.enable
            || (status != NGX_HTTP_OK && status != NGX_HTTP_FORBIDDEN && status != NGX_HTTP_NOT_FOUND)
            || content_encoding
            || (content_length_n != -1 && content_length_n < *c.min_length as i64)
            || !http_test_content_type(&r, &c.types)
            || r.header_only.get()
    };

    if skip {
        return next(r).await;
    }

    r.gzip_vary.set(true);

    // NGX_HTTP_DEGRADATION
    if r.clcf().borrow().gzip_disable_degradation != 0 && crate::degradation::is_degraded(&r) {
        return next(r).await;
    }

    if !r.gzip_tested.get() {
        if crate::core_rt::gzip_ok(&r) != NGX_OK {
            return next(r).await;
        }
    } else if !r.gzip_ok.get() {
        return next(r).await;
    }

    let mut ctx = GzipCtx::new();

    ctx.buffering = *conf.borrow().postpone_gzipping != 0;

    gzip_filter_memory(&r, &mut ctx);

    r.set_ctx(ctx_index(), ctx);

    let h = TableElt::generated(b"Content-Encoding", b"gzip".to_vec());

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.headers.push(h.clone());
        ho.content_encoding = Some(h);
    }

    r.main_filter_need_in_memory.set(true);

    r.clear_content_length();
    r.clear_accept_ranges();
    crate::core_rt::weak_etag(&r);

    next(r).await
}

/// ngx_http_gzip_body_filter
/// gzip_body_filter passes the chain on as it is
fn gzip_body_idle(r: &R, _input: &Chain) -> bool {
    r.header_only.get() || r.get_ctx::<GzipCtx>(ctx_index()).is_none_or(|c| c.borrow().done)
}

async fn gzip_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx = match r.get_ctx::<GzipCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r, input).await,
    };

    if ctx.borrow().done || r.header_only.get() {
        return next(r, input).await;
    }

    http_debug!(r, "http gzip filter");

    let mut input = input;

    if ctx.borrow().buffering {
        // With default memory settings zlib starts to output gzipped data
        // only after it has got about 90K, so it makes sense to allocate
        // zlib memory (200-400K) only after we have enough data to compress.
        // Although we copy buffers, nevertheless for not big responses
        // this allows to allocate zlib memory, to compress and to output
        // the response in one step using hot CPU cache.

        if !input.is_empty() {
            let rc = gzip_filter_buffer(&r, &mut ctx.borrow_mut(), input);

            match rc {
                NGX_OK => return NGX_OK,
                NGX_DONE => input = Chain::new(),
                // NGX_ERROR
                _ => return gzip_filter_failed(&ctx),
            }
        } else {
            ctx.borrow_mut().buffering = false;
        }
    }

    if ctx.borrow().zstream.is_none() && gzip_filter_deflate_start(&r, &mut ctx.borrow_mut()) != NGX_OK {
        return gzip_filter_failed(&ctx);
    }

    if !input.is_empty() {
        ctx.borrow_mut().in_.extend(input);

        r.buffered.set(r.buffered.get() | NGX_HTTP_GZIP_BUFFERED);
    }

    let mut flush;

    if ctx.borrow().nomem {
        // flush busy buffers

        if next(r.clone(), Chain::new()).await == NGX_ERROR {
            return gzip_filter_failed(&ctx);
        }

        ctx.borrow_mut().nomem = false;
        flush = false;
    } else {
        // ctx->busy: none, the buffers passed on are sent
        flush = false;
    }

    loop {
        // cycle while we can write to a client

        loop {
            // cycle while there is data to feed zlib and ...

            let rc = gzip_filter_add_data(&r, &mut ctx.borrow_mut());

            if rc == NGX_DECLINED {
                break;
            }

            if rc == NGX_AGAIN {
                continue;
            }

            // ... there are buffers to write zlib output

            let rc = gzip_filter_get_buf(&r, &mut ctx.borrow_mut());

            if rc == NGX_DECLINED {
                break;
            }

            if rc == NGX_ERROR {
                return gzip_filter_failed(&ctx);
            }

            let rc = gzip_filter_deflate(&r, &mut ctx.borrow_mut());

            if rc == NGX_OK {
                break;
            }

            if rc == NGX_ERROR {
                return gzip_filter_failed(&ctx);
            }

            // rc == NGX_AGAIN
        }

        if ctx.borrow().out.is_empty() && !flush {
            return NGX_OK;
        }

        let out = std::mem::take(&mut ctx.borrow_mut().out);

        // ngx_chain_update_chains(): the buffers of the module passed on
        // are free once sent
        let sent: Vec<Buf> = out.iter().filter(|b| b.tag == gzip_tag()).map(buf_shell).collect();

        let rc = next(r.clone(), out).await;

        if rc == NGX_ERROR {
            return gzip_filter_failed(&ctx);
        }

        let mut c = ctx.borrow_mut();

        for b in sent {
            c.free.insert(0, b);
        }

        c.nomem = false;
        flush = false;

        if c.done {
            return rc;
        }
    }
}

/// The failed: part of ngx_http_gzip_body_filter()
fn gzip_filter_failed(ctx: &Rc<std::cell::RefCell<GzipCtx>>) -> i64 {
    let mut ctx = ctx.borrow_mut();

    ctx.done = true;

    // deflateEnd() and ngx_pfree(r->pool, ctx->preallocated)
    ctx.zstream = None;

    NGX_ERROR
}

/// ngx_http_gzip_filter_memory
fn gzip_filter_memory(r: &R, ctx: &mut GzipCtx) {
    let conf = r.loc_conf::<GzipConf>(ctx_index());
    let c = conf.borrow();

    let mut wbits = *c.wbits as i32;

    let content_length_n = r.headers_out.borrow().content_length_n;

    if content_length_n > 0 {
        // the actual zlib window size is smaller by 262 bytes

        while content_length_n < ((1i64 << (wbits - 1)) - 262) {
            wbits -= 1;
        }
    }

    // C lowers the memory level with the window bits (down to 1) and
    // preallocates zlib's memory (ctx->allocated) from both; flate2 takes
    // no memory level and zlib allocates its memory itself.

    ctx.wbits = wbits;
}

/// ngx_http_gzip_filter_buffer
fn gzip_filter_buffer(r: &R, ctx: &mut GzipCtx, input: Chain) -> i64 {
    r.buffered.set(r.buffered.get() | NGX_HTTP_GZIP_BUFFERED);

    let mut buffered: usize = ctx.in_.iter().map(|b| b.last - b.pos).sum();

    let postpone_gzipping = *r.loc_conf::<GzipConf>(ctx_index()).borrow().postpone_gzipping;

    for b in input {
        let size = b.last - b.pos;
        buffered += size;

        if b.flush || b.last_buf || buffered > postpone_gzipping {
            ctx.buffering = false;
        }

        if ctx.buffering && size != 0 {
            let data = match &b.data {
                BufData::Memory(v) => v[b.pos..b.last].to_vec(),
                _ => vec![0u8; size],
            };

            let mut buf = Buf::from_vec(data);

            buf.last_buf = b.last_buf;
            buf.tag = gzip_tag();

            ctx.in_.push_back(buf);
        } else {
            ctx.in_.push_back(b);
        }
    }

    if ctx.buffering {
        NGX_OK
    } else {
        NGX_DONE
    }
}

/// ngx_http_gzip_filter_deflate_start
fn gzip_filter_deflate_start(r: &R, ctx: &mut GzipCtx) -> i64 {
    let level = *r.loc_conf::<GzipConf>(ctx_index()).borrow().level;

    // deflateInit2(level, Z_DEFLATED, wbits + 16, memLevel 8,
    // Z_DEFAULT_STRATEGY); with valid parameters it fails only when out of
    // memory, which flate2 does not survive ("deflateInit2() failed")
    let (level, wbits) = (level as u32, ctx.wbits);

    let kept = FREE_ZSTREAMS.with(|f| {
        let mut f = f.borrow_mut();
        let i = f.iter().position(|(l, w, _)| *l == level && *w == wbits)?;
        Some(f.swap_remove(i).2)
    });

    ctx.zstream = Some(kept.unwrap_or_else(|| Compress::new_gzip(Compression::new(level), wbits as u8)));
    ctx.level = level;

    ctx.flush = Z_NO_FLUSH;

    NGX_OK
}

/// ngx_http_gzip_filter_add_data
fn gzip_filter_add_data(r: &R, ctx: &mut GzipCtx) -> i64 {
    if ctx.avail_in != 0 || ctx.flush != Z_NO_FLUSH || ctx.redo {
        return NGX_OK;
    }

    http_debug!(r, "gzip in: {:016X}", ctx.in_ptr());

    let buf = match ctx.in_.pop_front() {
        Some(buf) => buf,
        None => return NGX_DECLINED,
    };

    // the copies of postpone_gzipping own their data: nothing to free
    // later (ctx->copy_buf, ctx->copied)

    // the buffer before is consumed: a copy buffer's memory is free for
    // the next copies
    if let Some(consumed) = ctx.in_buf.replace(buf) {
        if !is_out_buf(&consumed) {
            crate::copy_filter::recycle(consumed);
        }
    }

    let in_buf = ctx.in_buf.as_ref().expect("in_buf");

    // zstream.next_in = in_buf->pos, NULL for the buffers without memory
    ctx.next_in = matches!(in_buf.data, BufData::Memory(_));
    ctx.avail_in = buf_mem_size(in_buf);

    http_debug!(r, "gzip in_buf:{:016X} ni:{:016X} ai:{}", ctx.in_buf_ptr(), ctx.next_in_ptr(), ctx.avail_in);

    let in_buf = ctx.in_buf.as_ref().expect("in_buf");

    if in_buf.last_buf {
        ctx.flush = Z_FINISH;
    } else if in_buf.flush {
        ctx.flush = Z_SYNC_FLUSH;
    } else if ctx.avail_in == 0 {
        // ctx->flush == Z_NO_FLUSH
        return NGX_AGAIN;
    }

    NGX_OK
}

/// ngx_http_gzip_filter_get_buf
fn gzip_filter_get_buf(r: &R, ctx: &mut GzipCtx) -> i64 {
    if ctx.avail_out != 0 {
        return NGX_OK;
    }

    let conf = r.loc_conf::<GzipConf>(ctx_index());
    let bufs = conf.borrow().bufs;

    if !ctx.free.is_empty() {
        let mut b = ctx.free.remove(0);

        b.data = BufData::Memory(take_out_buf(bufs.size));

        ctx.out_buf = Some(b);
    } else if ctx.bufs < bufs.num {
        let mut b = create_temp_buf(bufs.size);

        b.tag = gzip_tag();
        b.recycled = true;
        ctx.bufs += 1;

        ctx.out_buf = Some(b);
    } else {
        ctx.nomem = true;
        return NGX_DECLINED;
    }

    // zstream.next_out = ctx->out_buf->pos, the buffer is empty
    ctx.avail_out = bufs.size;

    NGX_OK
}

/// ngx_http_gzip_filter_deflate
/// deflate(&ctx->zstream, ctx->flush): the zlib return code; the input
/// consumed advances in_buf.pos (the C does it after the call from
/// zstream.next_in), the output is appended to out_buf.
fn deflate(ctx: &mut GzipCtx) -> i32 {
    let flush = match ctx.flush {
        Z_SYNC_FLUSH => FlushCompress::Sync,
        Z_FINISH => FlushCompress::Finish,
        _ => FlushCompress::None,
    };

    let GzipCtx { zstream, in_buf, out_buf, next_in, avail_in, avail_out, .. } = ctx;

    let z = zstream.as_mut().expect("deflate stream");

    let input: &[u8] = match (in_buf.as_ref(), *next_in) {
        (Some(b), true) => match &b.data {
            BufData::Memory(v) => &v[b.pos..b.pos + *avail_in],
            _ => &[],
        },
        _ => &[],
    };

    let out_buf = out_buf.as_mut().expect("out_buf");

    let (total_in, total_out) = (z.total_in(), z.total_out());

    // the output appended to the buffer's data, into its avail_out bytes of
    // spare capacity (not initialized before)
    let status = match &mut out_buf.data {
        BufData::Memory(v) => {
            debug_assert!(v.len() == out_buf.last && v.capacity() - v.len() == *avail_out);
            z.compress_vec(input, v, flush)
        }
        _ => z.compress(input, &mut [], flush),
    };

    let rc = match status {
        Ok(Status::Ok) => Z_OK,
        Ok(Status::StreamEnd) => Z_STREAM_END,
        Ok(Status::BufError) => Z_BUF_ERROR,
        Err(_) => Z_STREAM_ERROR,
    };

    let consumed = (z.total_in() - total_in) as usize;
    let produced = (z.total_out() - total_out) as usize;

    if consumed != 0 {
        if let Some(b) = in_buf.as_mut() {
            b.pos += consumed;
        }
    }

    *avail_in -= consumed;

    out_buf.last += produced;
    *avail_out -= produced;

    rc
}

/// ngx_http_gzip_filter_deflate
fn gzip_filter_deflate(r: &R, ctx: &mut GzipCtx) -> i64 {
    http_debug!(r, "deflate in: ni:{:016X} no:{:016X} ai:{} ao:{} fl:{} redo:{}", ctx.next_in_ptr(), ctx.next_out_ptr(), ctx.avail_in, ctx.avail_out, ctx.flush, ctx.redo as i32);

    let rc = deflate(ctx);

    if rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "deflate() failed: {}, {}", ctx.flush, rc);
        return NGX_ERROR;
    }

    http_debug!(r, "deflate out: ni:{:016X} no:{:016X} ai:{} ao:{} rc:{}", ctx.next_in_ptr(), ctx.next_out_ptr(), ctx.avail_in, ctx.avail_out, rc);

    http_debug!(r, "gzip in_buf:{:016X} pos:{:016X}", ctx.in_buf_ptr(), ctx.in_buf_pos());

    // in_buf->pos = zstream.next_in (done by deflate()), and
    if ctx.next_in && ctx.avail_in == 0 {
        ctx.next_in = false;
    }

    if ctx.avail_out == 0 && rc != Z_STREAM_END {
        // zlib wants to output some more gzipped data

        let b = ctx.out_buf.take().expect("out_buf");
        ctx.out.push_back(b);

        ctx.redo = true;

        return NGX_AGAIN;
    }

    ctx.redo = false;

    if ctx.flush == Z_SYNC_FLUSH {
        ctx.flush = Z_NO_FLUSH;

        let mut b = if ctx.out_buf.as_ref().expect("out_buf").buf_size() == 0 {
            // ngx_calloc_buf()
            Buf::default()
        } else {
            ctx.avail_out = 0;
            ctx.out_buf.take().expect("out_buf")
        };

        b.flush = true;

        ctx.out.push_back(b);

        r.buffered.set(r.buffered.get() & !NGX_HTTP_GZIP_BUFFERED);

        return NGX_OK;
    }

    if rc == Z_STREAM_END {
        if gzip_filter_deflate_end(r, ctx) != NGX_OK {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    let no_buffer = *r.loc_conf::<GzipConf>(ctx_index()).borrow().no_buffer;

    if no_buffer && ctx.in_.is_empty() {
        // C passes on ctx->out_buf, which zlib goes on filling; a copy of
        // the data goes here, the buffer staying with zlib
        let out_buf = ctx.out_buf.as_mut().expect("out_buf");

        let data = match &out_buf.data {
            BufData::Memory(v) => v[out_buf.pos..out_buf.last].to_vec(),
            _ => Vec::new(),
        };

        out_buf.pos = out_buf.last;

        let mut b = Buf::from_vec(data);
        b.recycled = out_buf.recycled;
        b.flush = out_buf.flush;

        ctx.out.push_back(b);

        return NGX_OK;
    }

    NGX_AGAIN
}

/// ngx_http_gzip_filter_deflate_end
fn gzip_filter_deflate_end(r: &R, ctx: &mut GzipCtx) -> i64 {
    let mut z = ctx.zstream.take().expect("deflate stream");

    ctx.zin = z.total_in() as usize;
    ctx.zout = z.total_out() as usize;

    // deflateEnd() (Z_OK after Z_STREAM_END: the "deflateEnd() failed"
    // alert cannot happen) and ngx_pfree(r->pool, ctx->preallocated): the
    // stream reset and kept for the next response
    z.reset();

    FREE_ZSTREAMS.with(|f| {
        let mut f = f.borrow_mut();
        if f.len() < FREE_STREAMS {
            f.push((ctx.level, ctx.wbits, z));
        }
    });

    // the last buffer is consumed
    if let Some(consumed) = ctx.in_buf.take() {
        if !is_out_buf(&consumed) {
            crate::copy_filter::recycle(consumed);
        }
    }

    let mut b = ctx.out_buf.take().expect("out_buf");

    if b.buf_size() == 0 {
        b.temporary = false;
    }

    b.last_buf = true;

    ctx.out.push_back(b);

    ctx.avail_in = 0;
    ctx.avail_out = 0;

    ctx.done = true;

    r.buffered.set(r.buffered.get() & !NGX_HTTP_GZIP_BUFFERED);

    NGX_OK
}

/// ngx_http_gzip_add_variables
fn gzip_add_variables(cf: &mut Conf) -> ConfResult {
    crate::variables::add_variables(
        cf,
        &[crate::variables::VarDef { name: "gzip_ratio", set: None, get: Some(gzip_ratio_variable), data: 0, flags: crate::variables::NGX_HTTP_VAR_NOHASH }],
    )
}

/// ngx_http_gzip_ratio_variable
fn gzip_ratio_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let (zin, zout) = match r.get_ctx::<GzipCtx>(ctx_index()) {
        Some(ctx) => {
            let c = ctx.borrow();
            (c.zin, c.zout)
        }
        None => (0, 0),
    };

    if zout == 0 {
        v.not_found = true;
        return NGX_OK;
    }

    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    let mut zint = zin / zout;
    let mut zfrac = (zin * 100 / zout) % 100;

    if (zin * 1000 / zout) % 10 > 4 {
        // the rounding, e.g., 2.125 to 2.13

        zfrac += 1;

        if zfrac > 99 {
            zint += 1;
            zfrac = 0;
        }
    }

    v.data = format!("{}.{:02}", zint, zfrac).into_bytes();

    NGX_OK
}

/// ngx_http_gzip_create_conf
fn gzip_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(GzipConf {
        enable: Val::unset(),
        no_buffer: Val::unset(),
        types: None,
        bufs: Bufs::default(),
        postpone_gzipping: Val::unset(),
        level: Val::unset(),
        wbits: Val::unset(),
        memlevel: Val::unset(),
        min_length: Val::unset(),
        types_keys: None,
    })
}

/// ngx_http_gzip_merge_conf
fn gzip_merge_conf(cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let mut prev = conf_cell::<GzipConf>(parent).borrow_mut();
    let mut conf = conf_cell::<GzipConf>(child).borrow_mut();

    conf.enable.merge(&prev.enable, false);
    conf.no_buffer.merge(&prev.no_buffer, false);

    let pagesize = ngx_core::os::pagesize();
    conf.bufs.merge(&prev.bufs, (128 * 1024) / pagesize, pagesize);

    conf.postpone_gzipping.merge(&prev.postpone_gzipping, 0);
    conf.level.merge(&prev.level, 1);
    conf.wbits.merge(&prev.wbits, MAX_WBITS);
    conf.memlevel.merge(&prev.memlevel, MAX_MEM_LEVEL - 1);
    conf.min_length.merge(&prev.min_length, 20);

    let conf = &mut *conf;
    let prev = &mut *prev;

    http_merge_types(cf, &mut conf.types_keys, &mut conf.types, &mut prev.types_keys, &mut prev.types, NGX_HTTP_HTML_DEFAULT_TYPES)
}

/// ngx_http_gzip_filter_init
fn gzip_filter_init(_cf: &mut Conf) -> ConfResult {
    crate::install_header_filter_idle(gzip_header_idle, gzip_header_filter);
    crate::install_body_filter_idle(gzip_body_idle, gzip_body_filter);
    Ok(())
}

/// ngx_http_types_slot for gzip_types, &ngx_http_html_default_types[0]
fn gzip_types_slot(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().expect("conf"));
    let mut c = cell.borrow_mut();

    http_types_slot(cf, &mut c.types_keys, Some(NGX_HTTP_HTML_DEFAULT_TYPES[0]))
}

/// ngx_conf_set_num_slot with ngx_http_gzip_comp_level_bounds
fn gzip_comp_level(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().expect("conf"));
    let mut c = cell.borrow_mut();

    set_num(cf, cmd, &mut c.level)?;

    check_num_bounds(cf, *c.level, 1, 9)
}

/// ngx_conf_set_size_slot with ngx_http_gzip_window_p
fn gzip_window_slot(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().expect("conf"));
    let mut c = cell.borrow_mut();

    set_size(cf, cmd, &mut c.wbits)?;

    match gzip_window(*c.wbits) {
        Some(wbits) => {
            c.wbits = Val::set(wbits);
            Ok(())
        }
        None => Err(msg("must be 512, 1k, 2k, 4k, 8k, 16k, or 32k")),
    }
}

/// ngx_http_gzip_window: the window bits of a window size
fn gzip_window(np: usize) -> Option<usize> {
    let mut wbits = 15;
    let mut wsize = 32 * 1024;

    while wsize > 256 {
        if wsize == np {
            return Some(wbits);
        }

        wbits -= 1;
        wsize >>= 1;
    }

    None
}

/// ngx_conf_set_size_slot with ngx_http_gzip_hash_p
fn gzip_hash_slot(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().expect("conf"));
    let mut c = cell.borrow_mut();

    set_size(cf, cmd, &mut c.memlevel)?;

    match gzip_hash(*c.memlevel) {
        Some(memlevel) => {
            c.memlevel = Val::set(memlevel);
            Ok(())
        }
        None => Err(msg("must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k")),
    }
}

/// ngx_http_gzip_hash: the memory level of a hash size
fn gzip_hash(np: usize) -> Option<usize> {
    let mut memlevel = 9;
    let mut hsize = 128 * 1024;

    while hsize > 256 {
        if hsize == np {
            return Some(memlevel);
        }

        memlevel -= 1;
        hsize >>= 1;
    }

    None
}

pub fn gzip_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(gzip_add_variables),
        postconfiguration: Some(gzip_filter_init),
        create_loc_conf: Some(gzip_create_conf),
        merge_loc_conf: Some(gzip_merge_conf),
        ..Default::default()
    };

    const MSL: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd!("gzip", MSL | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, ConfLevel::Loc, GzipConf, enable, set_flag),
        cmd!("gzip_buffers", MSL | NGX_CONF_TAKE2, ConfLevel::Loc, GzipConf, bufs, set_bufs),
        cmd_fn!("gzip_types", MSL | NGX_CONF_1MORE, ConfLevel::Loc, gzip_types_slot),
        cmd_fn!("gzip_comp_level", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, gzip_comp_level),
        cmd_fn!("gzip_window", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, gzip_window_slot),
        cmd_fn!("gzip_hash", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, gzip_hash_slot),
        cmd!("postpone_gzipping", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, GzipConf, postpone_gzipping, set_size),
        cmd!("gzip_no_buffer", MSL | NGX_CONF_FLAG, ConfLevel::Loc, GzipConf, no_buffer, set_flag),
        cmd!("gzip_min_length", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, GzipConf, min_length, set_size),
    ];

    http_module_def("ngx_http_gzip_filter_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_and_hash_sizes() {
        assert_eq!(gzip_window(32 * 1024), Some(15));
        assert_eq!(gzip_window(512), Some(9));
        assert_eq!(gzip_window(256), None);
        assert_eq!(gzip_window(3000), None);

        assert_eq!(gzip_hash(128 * 1024), Some(9));
        assert_eq!(gzip_hash(512), Some(1));
        assert_eq!(gzip_hash(256), None);
    }

    /// deflateInit2() with windowBits + 16 writes the gzip header with
    /// XFL 4 at level 1 in the first output
    #[test]
    fn gzip_header_by_zlib() {
        let mut z = Compress::new_gzip(Compression::new(1), 9);

        let input = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_vec();
        let mut out = vec![0u8; 4096];

        assert!(matches!(z.compress(&input, &mut out, FlushCompress::Finish), Ok(Status::StreamEnd)));

        let n = z.total_out() as usize;
        assert_eq!(&out[..10], &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0x04, 0x03]);
        assert_eq!(n, 24);
        assert_eq!(z.total_in() as usize, input.len());
    }

    /// A stream ended, reset and used again writes the bytes a new one
    /// writes (deflateReset: deflateEnd and deflateInit without freeing)
    #[test]
    fn reset_stream_as_new() {
        let gzip = |z: &mut Compress, data: &[u8]| {
            let mut out = Vec::with_capacity(64 * 1024);
            assert!(matches!(z.compress_vec(data, &mut out, FlushCompress::Finish), Ok(Status::StreamEnd)));
            out
        };

        let a = b"<html>first response, compressed once</html>".repeat(300);
        let b = b"<p>the second one, with other text</p>".repeat(500);

        let mut kept = Compress::new_gzip(Compression::new(1), 15);
        gzip(&mut kept, &a);
        kept.reset();
        assert_eq!(kept.total_in(), 0);

        let mut new = Compress::new_gzip(Compression::new(1), 15);
        assert_eq!(gzip(&mut kept, &b), gzip(&mut new, &b));

        // an output buffer sent is taken again for one of its size only
        let v = take_out_buf(100);
        assert_eq!(v.capacity(), 100);
        free_out_buf(Vec::with_capacity(200));
        assert_eq!(take_out_buf(100).capacity(), 100);
        assert_eq!(take_out_buf(200).capacity(), 200);
    }

    /// The bookkeeping of deflate(): the input consumed from in_buf, the
    /// output appended to out_buf.
    #[test]
    fn deflate_buffers() {
        let mut ctx = GzipCtx::new();
        ctx.zstream = Some(Compress::new_gzip(Compression::new(1), 15));

        let data = b"0123456789".repeat(100);
        ctx.in_buf = Some(Buf::from_vec(data.clone()));
        ctx.next_in = true;
        ctx.avail_in = data.len();

        ctx.out_buf = Some(create_temp_buf(16));
        ctx.avail_out = 16;

        // the first output fills the 16 bytes of out_buf
        ctx.flush = Z_FINISH;
        assert_eq!(deflate(&mut ctx), Z_OK);
        assert_eq!(ctx.avail_out, 0);
        assert_eq!(ctx.out_buf.as_ref().unwrap().last, 16);
        assert_eq!(ctx.avail_in + ctx.in_buf.as_ref().unwrap().pos, data.len());

        let out_data = |b: &Buf| match &b.data {
            BufData::Memory(v) => v[b.pos..b.last].to_vec(),
            _ => Vec::new(),
        };

        let mut gz = out_data(ctx.out_buf.as_ref().unwrap());

        loop {
            ctx.out_buf = Some(create_temp_buf(16));
            ctx.avail_out = 16;

            let rc = deflate(&mut ctx);
            gz.extend_from_slice(&out_data(ctx.out_buf.as_ref().unwrap()));

            if rc == Z_STREAM_END {
                break;
            }

            assert_eq!(rc, Z_OK);
        }

        assert_eq!(ctx.avail_in, 0);
        assert_eq!(ctx.zstream.as_ref().unwrap().total_out() as usize, gz.len());

        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut out).unwrap();
        assert_eq!(out, data);
    }
}
