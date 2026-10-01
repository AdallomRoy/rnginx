//! ngx_http_gzip_filter_module
//!
//! zlib (libz-sys, the system zlib as in the C build) writes the gzip
//! header and trailer itself (deflateInit2() with windowBits + 16).
//! The buffers own their data here: the output buffers a buffer of
//! ctx->free stands for are allocated again when it is taken, and those
//! passed on are free once the next filter returns, as the write filter
//! has sent them by then (C keeps the ones not sent yet in ctx->busy).

use std::any::Any;
use std::cell::Cell;
use std::rc::Rc;

use libz_sys as z;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

use crate::http_types::*;
use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_gzip_filter_module");

/// MAX_WBITS of zconf.h
const MAX_WBITS: usize = 15;
/// MAX_MEM_LEVEL of zconf.h
const MAX_MEM_LEVEL: usize = 9;

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

/// The memory ngx_http_gzip_filter_alloc() gives zlib: ctx->preallocated,
/// ctx->free_mem and ctx->allocated, and the allocations from the request
/// pool when the preallocated memory does not suffice. It is reached
/// through zstream.opaque during the zlib calls.
struct GzipAlloc {
    preallocated: Vec<u64>,
    /// ctx->free_mem: the offset of the free memory in preallocated
    free_mem: usize,
    allocated: usize,
    zlib_ng: bool,
    state_allocated: bool,
    pool: Vec<Vec<u64>>,
    log: Log,
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

    /// ctx->preallocated != NULL: ngx_http_gzip_filter_deflate_start()
    /// was called
    preallocated: bool,
    alloc: *mut GzipAlloc,

    wbits: i32,
    memlevel: i32,

    flush: i32,
    redo: bool,
    done: bool,
    nomem: bool,
    buffering: bool,

    zin: usize,
    zout: usize,

    zstream: Box<z::z_stream>,
}

impl Drop for GzipCtx {
    fn drop(&mut self) {
        // SAFETY: alloc comes from Box::into_raw() in GzipCtx::new() and is
        // freed only here; zlib does not use the memory any more (its zfree
        // is a no-op, as the pool frees the memory in C).
        unsafe { drop(Box::from_raw(self.alloc)) };
    }
}

impl GzipCtx {
    fn new(log: Log) -> GzipCtx {
        let alloc = Box::into_raw(Box::new(GzipAlloc {
            preallocated: Vec::new(),
            free_mem: 0,
            allocated: 0,
            zlib_ng: false,
            state_allocated: false,
            pool: Vec::new(),
            log,
        }));

        GzipCtx {
            in_: Chain::new(),
            free: Vec::new(),
            out: Chain::new(),
            in_buf: None,
            out_buf: None,
            bufs: 0,
            preallocated: false,
            alloc,
            wbits: 0,
            memlevel: 0,
            flush: z::Z_NO_FLUSH,
            redo: false,
            done: false,
            nomem: false,
            buffering: false,
            zin: 0,
            zout: 0,
            zstream: Box::new(z::z_stream {
                next_in: std::ptr::null_mut(),
                avail_in: 0,
                total_in: 0,
                next_out: std::ptr::null_mut(),
                avail_out: 0,
                total_out: 0,
                msg: std::ptr::null_mut(),
                state: std::ptr::null_mut(),
                zalloc: gzip_filter_alloc,
                zfree: gzip_filter_free,
                opaque: alloc as *mut libc::c_void,
                data_type: 0,
                adler: 0,
                reserved: 0,
            }),
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
        self.in_buf.as_ref().map_or(0, |b| buf_data_ptr(b) as usize + b.pos)
    }
}

thread_local! {
    /// ngx_http_gzip_assume_zlib_ng
    static GZIP_ASSUME_ZLIB_NG: Cell<bool> = const { Cell::new(false) };
}

/// The tag of the buffers of the module, (ngx_buf_tag_t)
/// &ngx_http_gzip_filter_module
fn gzip_tag() -> usize {
    static TAG: u8 = 0;
    &TAG as *const u8 as usize
}

/// The start of the data of a buffer in memory (buf->start), NULL for
/// the others (pos and last of these are NULL in C)
fn buf_data_ptr(b: &Buf) -> *const u8 {
    match &b.data {
        BufData::Memory(v) => v.as_ptr(),
        _ => std::ptr::null(),
    }
}

fn buf_data_mut_ptr(b: &mut Buf) -> *mut u8 {
    match &mut b.data {
        BufData::Memory(v) => v.as_mut_ptr(),
        _ => std::ptr::null_mut(),
    }
}

/// buf->last - buf->pos
fn buf_mem_size(b: &Buf) -> usize {
    if buf_data_ptr(b).is_null() {
        return 0;
    }

    b.last - b.pos
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

/// ngx_create_temp_buf()
fn create_temp_buf(size: usize) -> Buf {
    Buf { data: BufData::Memory(vec![0u8; size]), pos: 0, last: 0, temporary: true, ..Default::default() }
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

    let mut ctx = GzipCtx::new(r.connection.log.clone());

    ctx.buffering = *conf.borrow().postpone_gzipping != 0;

    gzip_filter_memory(&r, &mut ctx);

    r.set_ctx(ctx_index(), ctx);

    let h = TableElt::new(b"Content-Encoding", b"gzip");

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

    if !ctx.borrow().preallocated && gzip_filter_deflate_start(&r, &mut ctx.borrow_mut()) != NGX_OK {
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

    if ctx.preallocated {
        // SAFETY: the stream was initialized by deflateInit2_(); deflateEnd()
        // of an ended one returns Z_STREAM_ERROR without using its state.
        unsafe { z::deflateEnd(&mut *ctx.zstream) };

        free_preallocated(&mut ctx);
    }

    NGX_ERROR
}

/// ngx_pfree(r->pool, ctx->preallocated)
fn free_preallocated(ctx: &mut GzipCtx) {
    // SAFETY: alloc is valid for the life of the ctx, and zlib is not
    // running.
    let alloc = unsafe { &mut *ctx.alloc };

    alloc.preallocated = Vec::new();
}

/// ngx_http_gzip_filter_memory
fn gzip_filter_memory(r: &R, ctx: &mut GzipCtx) {
    let conf = r.loc_conf::<GzipConf>(ctx_index());
    let c = conf.borrow();

    let mut wbits = *c.wbits as i32;
    let mut memlevel = *c.memlevel as i32;

    let content_length_n = r.headers_out.borrow().content_length_n;

    if content_length_n > 0 {
        // the actual zlib window size is smaller by 262 bytes

        while content_length_n < ((1i64 << (wbits - 1)) - 262) {
            wbits -= 1;
            memlevel -= 1;
        }

        if memlevel < 1 {
            memlevel = 1;
        }
    }

    ctx.wbits = wbits;
    ctx.memlevel = memlevel;

    // We preallocate a memory for zlib in one buffer (200K-400K), this
    // decreases a number of malloc() and free() calls and also probably
    // decreases a number of syscalls (sbrk()/mmap() and so on).
    // Besides we free the memory as soon as a gzipping will complete
    // and do not wait while a whole response will be sent to a client.
    //
    // 8K is for zlib deflate_state, it takes
    //  *) 5816 bytes on i386 and sparc64 (32-bit mode)
    //  *) 5920 bytes on amd64 and sparc64
    //
    // A zlib variant from Intel (https://github.com/jtkukunas/zlib)
    // uses additional 16-byte padding in one of window-sized buffers.

    // SAFETY: alloc is valid for the life of the ctx, and zlib is not
    // running.
    let alloc = unsafe { &mut *ctx.alloc };

    if !GZIP_ASSUME_ZLIB_NG.with(|g| g.get()) {
        alloc.allocated = 8192 + 16 + (1 << (wbits + 2)) + (1 << (memlevel + 9));
    } else {
        // Another zlib variant, https://github.com/zlib-ng/zlib-ng.
        // It used to force window bits to 13 for fast compression level,
        // used (64 + sizeof(void*)) additional space on all allocations
        // for alignment and 16-byte padding in one of window-sized buffers,
        // uses a single allocation with up to 200 bytes for alignment and
        // internal pointers, 5/4 times more memory for the pending buffer,
        // and 128K hash.

        if *c.level == 1 {
            wbits = wbits.max(13);
        }

        alloc.allocated = 8192 + 16 + (1 << (wbits + 2)) + 131072 + (5 << (memlevel + 6)) + 4 * (64 + std::mem::size_of::<*const u8>());
        alloc.zlib_ng = true;
    }
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

    {
        // SAFETY: alloc is valid for the life of the ctx, and zlib is not
        // running.
        let alloc = unsafe { &mut *ctx.alloc };

        alloc.preallocated = vec![0u64; alloc.allocated.div_ceil(8)];
        alloc.free_mem = 0;
    }

    ctx.preallocated = true;

    ctx.zstream.zalloc = gzip_filter_alloc;
    ctx.zstream.zfree = gzip_filter_free;
    ctx.zstream.opaque = ctx.alloc as *mut libc::c_void;

    // SAFETY: the stream is boxed (zlib keeps a pointer to it in its state)
    // and its allocator is the one of the ctx, which outlives it.
    let rc = unsafe {
        z::deflateInit2_(
            &mut *ctx.zstream,
            level as i32,
            z::Z_DEFLATED,
            ctx.wbits + 16,
            ctx.memlevel,
            z::Z_DEFAULT_STRATEGY,
            z::zlibVersion(),
            std::mem::size_of::<z::z_stream>() as i32,
        )
    };

    if rc != z::Z_OK {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "deflateInit2() failed: {}", rc);
        return NGX_ERROR;
    }

    ctx.flush = z::Z_NO_FLUSH;

    NGX_OK
}

/// ngx_http_gzip_filter_add_data
fn gzip_filter_add_data(r: &R, ctx: &mut GzipCtx) -> i64 {
    if ctx.zstream.avail_in != 0 || ctx.flush != z::Z_NO_FLUSH || ctx.redo {
        return NGX_OK;
    }

    http_debug!(r, "gzip in: {:016X}", ctx.in_ptr());

    let buf = match ctx.in_.pop_front() {
        Some(buf) => buf,
        None => return NGX_DECLINED,
    };

    // the copies of postpone_gzipping own their data: nothing to free
    // later (ctx->copy_buf, ctx->copied)

    ctx.in_buf = Some(buf);

    let in_buf = ctx.in_buf.as_ref().expect("in_buf");

    let start = buf_data_ptr(in_buf);

    ctx.zstream.next_in = if start.is_null() { std::ptr::null_mut() } else { start.wrapping_add(in_buf.pos) as *mut u8 };
    ctx.zstream.avail_in = buf_mem_size(in_buf) as z::uInt;

    http_debug!(r, "gzip in_buf:{:016X} ni:{:016X} ai:{}", ctx.in_buf_ptr(), ctx.zstream.next_in as usize, ctx.zstream.avail_in);

    let in_buf = ctx.in_buf.as_ref().expect("in_buf");

    if in_buf.last_buf {
        ctx.flush = z::Z_FINISH;
    } else if in_buf.flush {
        ctx.flush = z::Z_SYNC_FLUSH;
    } else if ctx.zstream.avail_in == 0 {
        // ctx->flush == Z_NO_FLUSH
        return NGX_AGAIN;
    }

    NGX_OK
}

/// ngx_http_gzip_filter_get_buf
fn gzip_filter_get_buf(r: &R, ctx: &mut GzipCtx) -> i64 {
    if ctx.zstream.avail_out != 0 {
        return NGX_OK;
    }

    let conf = r.loc_conf::<GzipConf>(ctx_index());
    let bufs = conf.borrow().bufs;

    if !ctx.free.is_empty() {
        let mut b = ctx.free.remove(0);

        b.data = BufData::Memory(vec![0u8; bufs.size]);

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

    let out_buf = ctx.out_buf.as_mut().expect("out_buf");
    let pos = out_buf.pos;

    ctx.zstream.next_out = buf_data_mut_ptr(out_buf).wrapping_add(pos);
    ctx.zstream.avail_out = bufs.size as z::uInt;

    NGX_OK
}

/// ngx_http_gzip_filter_deflate
fn gzip_filter_deflate(r: &R, ctx: &mut GzipCtx) -> i64 {
    http_debug!(
        r,
        "deflate in: ni:{:016X} no:{:016X} ai:{} ao:{} fl:{} redo:{}",
        ctx.zstream.next_in as usize,
        ctx.zstream.next_out as usize,
        ctx.zstream.avail_in,
        ctx.zstream.avail_out,
        ctx.flush,
        ctx.redo as i32
    );

    // SAFETY: next_in points into ctx->in_buf and next_out into
    // ctx->out_buf, both owned by the ctx with the lengths avail_in and
    // avail_out; the stream was initialized by deflateInit2_().
    let rc = unsafe { z::deflate(&mut *ctx.zstream, ctx.flush) };

    if rc != z::Z_OK && rc != z::Z_STREAM_END && rc != z::Z_BUF_ERROR {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "deflate() failed: {}, {}", ctx.flush, rc);
        return NGX_ERROR;
    }

    http_debug!(
        r,
        "deflate out: ni:{:016X} no:{:016X} ai:{} ao:{} rc:{}",
        ctx.zstream.next_in as usize,
        ctx.zstream.next_out as usize,
        ctx.zstream.avail_in,
        ctx.zstream.avail_out,
        rc
    );

    http_debug!(r, "gzip in_buf:{:016X} pos:{:016X}", ctx.in_buf_ptr(), ctx.in_buf_pos());

    if !ctx.zstream.next_in.is_null() {
        if let Some(in_buf) = ctx.in_buf.as_mut() {
            in_buf.pos = ctx.zstream.next_in as usize - buf_data_ptr(in_buf) as usize;
        }

        if ctx.zstream.avail_in == 0 {
            ctx.zstream.next_in = std::ptr::null_mut();
        }
    }

    {
        let out_buf = ctx.out_buf.as_mut().expect("out_buf");
        out_buf.last = ctx.zstream.next_out as usize - buf_data_mut_ptr(out_buf) as usize;
    }

    if ctx.zstream.avail_out == 0 && rc != z::Z_STREAM_END {
        // zlib wants to output some more gzipped data

        let b = ctx.out_buf.take().expect("out_buf");
        ctx.out.push_back(b);

        ctx.redo = true;

        return NGX_AGAIN;
    }

    ctx.redo = false;

    if ctx.flush == z::Z_SYNC_FLUSH {
        ctx.flush = z::Z_NO_FLUSH;

        let mut b = if ctx.out_buf.as_ref().expect("out_buf").buf_size() == 0 {
            // ngx_calloc_buf()
            Buf::default()
        } else {
            ctx.zstream.avail_out = 0;
            ctx.out_buf.take().expect("out_buf")
        };

        b.flush = true;

        ctx.out.push_back(b);

        r.buffered.set(r.buffered.get() & !NGX_HTTP_GZIP_BUFFERED);

        return NGX_OK;
    }

    if rc == z::Z_STREAM_END {
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
    ctx.zin = ctx.zstream.total_in as usize;
    ctx.zout = ctx.zstream.total_out as usize;

    // SAFETY: the stream was initialized by deflateInit2_().
    let rc = unsafe { z::deflateEnd(&mut *ctx.zstream) };

    if rc != z::Z_OK {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "deflateEnd() failed: {}", rc);
        return NGX_ERROR;
    }

    free_preallocated(ctx);

    let mut b = ctx.out_buf.take().expect("out_buf");

    if b.buf_size() == 0 {
        b.temporary = false;
    }

    b.last_buf = true;

    ctx.out.push_back(b);

    ctx.zstream.avail_in = 0;
    ctx.zstream.avail_out = 0;

    ctx.done = true;

    r.buffered.set(r.buffered.get() & !NGX_HTTP_GZIP_BUFFERED);

    NGX_OK
}

/// ngx_http_gzip_filter_alloc
unsafe extern "C" fn gzip_filter_alloc(opaque: *mut libc::c_void, items: z::uInt, size: z::uInt) -> *mut libc::c_void {
    // SAFETY: opaque is the GzipAlloc of the ctx, alive during the zlib
    // calls, and nothing else refers to it meanwhile.
    let ctx = &mut *(opaque as *mut GzipAlloc);

    let mut alloc = items as usize * size as usize;

    if items == 1 && alloc % 512 != 0 && alloc < 8192 && !ctx.state_allocated {
        // The zlib deflate_state allocation, it takes about 6K,
        // we allocate 8K.  Other allocations are divisible by 512.

        ctx.state_allocated = true;

        alloc = 8192;
    }

    if alloc <= ctx.allocated {
        let p = (ctx.preallocated.as_mut_ptr() as *mut u8).add(ctx.free_mem);
        ctx.free_mem += alloc;
        ctx.allocated -= alloc;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "gzip alloc: n:{} s:{} a:{} p:{:016X}", items, size, alloc, p as usize);

        return p as *mut libc::c_void;
    }

    if ctx.zlib_ng {
        ngx_log_error!(NGX_LOG_ALERT, ctx.log, None, "gzip filter failed to use preallocated memory: {} of {}", items.wrapping_mul(size), ctx.allocated);
    } else {
        GZIP_ASSUME_ZLIB_NG.with(|g| g.set(true));
    }

    // ngx_palloc(ctx->request->pool, items * size)
    let mut v = vec![0u64; (items as usize * size as usize).div_ceil(8)];
    let p = v.as_mut_ptr() as *mut libc::c_void;

    ctx.pool.push(v);

    p
}

/// ngx_http_gzip_filter_free
unsafe extern "C" fn gzip_filter_free(_opaque: *mut libc::c_void, _address: *mut libc::c_void) {}

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
        let mut ctx = GzipCtx::new(Log::new(ngx_core::log::LogChain::new()));

        // SAFETY: the test owns the ctx
        unsafe {
            (*ctx.alloc).allocated = 8192 + 16 + (1 << (9 + 2)) + (1 << (2 + 9));
            (*ctx.alloc).preallocated = vec![0u64; (*ctx.alloc).allocated.div_ceil(8)];
        }

        let rc = unsafe {
            z::deflateInit2_(&mut *ctx.zstream, 1, z::Z_DEFLATED, 9 + 16, 2, z::Z_DEFAULT_STRATEGY, z::zlibVersion(), std::mem::size_of::<z::z_stream>() as i32)
        };
        assert_eq!(rc, z::Z_OK);

        let input = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_vec();
        let mut out = vec![0u8; 4096];

        ctx.zstream.next_in = input.as_ptr() as *mut u8;
        ctx.zstream.avail_in = input.len() as z::uInt;
        ctx.zstream.next_out = out.as_mut_ptr();
        ctx.zstream.avail_out = out.len() as z::uInt;

        let rc = unsafe { z::deflate(&mut *ctx.zstream, z::Z_FINISH) };
        assert_eq!(rc, z::Z_STREAM_END);

        let n = out.len() - ctx.zstream.avail_out as usize;
        assert_eq!(&out[..10], &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0x04, 0x03]);
        assert_eq!(n, 24);

        assert_eq!(unsafe { z::deflateEnd(&mut *ctx.zstream) }, z::Z_OK);
    }
}
