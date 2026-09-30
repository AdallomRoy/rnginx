//! ngx_http_gunzip_filter_module
//!
//! zlib (libz-sys, the system zlib as in the C build) decodes the gzip
//! framing itself (inflateInit2() with MAX_WBITS + 16). The buffers own
//! their data here: the output buffers a buffer of ctx->free stands for
//! are allocated again when it is taken, and those passed on are free once
//! the next filter returns, as the write filter has sent them by then (C
//! keeps the ones not sent yet in ctx->busy).

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use libz_sys as z;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::{cmd, ngx_log_debug, ngx_log_error};

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_gunzip_filter_module");

/// MAX_WBITS of zconf.h
const MAX_WBITS: i32 = 15;

/// ngx_http_gunzip_conf_t
pub struct GunzipConf {
    pub enable: Val<bool>,
    pub bufs: Bufs,
}

/// The memory ngx_http_gunzip_filter_alloc() gives zlib from the request
/// pool, reached through zstream.opaque during the zlib calls.
struct GunzipAlloc {
    pool: Vec<Vec<u64>>,
    log: Log,
}

/// ngx_http_gunzip_ctx_t
pub struct GunzipCtx {
    in_: Chain,
    /// ctx->free: the output buffers sent, their data to be allocated
    /// again when one is taken
    free: Vec<Buf>,
    out: Chain,

    in_buf: Option<Buf>,
    out_buf: Option<Buf>,
    bufs: usize,

    started: bool,
    flush: i32,
    redo: bool,
    done: bool,
    nomem: bool,

    alloc: *mut GunzipAlloc,
    zstream: Box<z::z_stream>,
}

impl Drop for GunzipCtx {
    fn drop(&mut self) {
        // SAFETY: alloc comes from Box::into_raw() in GunzipCtx::new() and
        // is freed only here; zlib does not use the memory any more (its
        // zfree is a no-op, as the pool frees the memory in C).
        unsafe { drop(Box::from_raw(self.alloc)) };
    }
}

impl GunzipCtx {
    fn new(log: Log) -> GunzipCtx {
        let alloc = Box::into_raw(Box::new(GunzipAlloc { pool: Vec::new(), log }));

        GunzipCtx {
            in_: Chain::new(),
            free: Vec::new(),
            out: Chain::new(),
            in_buf: None,
            out_buf: None,
            bufs: 0,
            started: false,
            flush: z::Z_NO_FLUSH,
            redo: false,
            done: false,
            nomem: false,
            alloc,
            zstream: Box::new(z::z_stream {
                next_in: std::ptr::null_mut(),
                avail_in: 0,
                total_in: 0,
                next_out: std::ptr::null_mut(),
                avail_out: 0,
                total_out: 0,
                msg: std::ptr::null_mut(),
                state: std::ptr::null_mut(),
                zalloc: gunzip_filter_alloc,
                zfree: gunzip_filter_free,
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

/// The tag of the buffers of the module, (ngx_buf_tag_t)
/// &ngx_http_gunzip_filter_module
fn gunzip_tag() -> usize {
    static TAG: u8 = 0;
    &TAG as *const u8 as usize
}

/// The start of the data of a buffer in memory (buf->start), NULL for
/// the others
fn buf_data_ptr(b: &Buf) -> *const u8 {
    match &b.data {
        BufData::Memory(v) if b.in_memory() => v.as_ptr(),
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

/// ngx_http_gunzip_header_filter
async fn gunzip_header_filter(r: R, next: HeaderFilter) -> i64 {
    let conf = r.loc_conf::<GunzipConf>(ctx_index());

    // TODO support multiple content-codings
    // TODO always gunzip - due to configuration or module request
    // TODO ignore content encoding?

    let gzip = {
        let ho = r.headers_out.borrow();
        ho.content_encoding.as_ref().is_some_and(|h| {
            let v = h.value.borrow();
            v.len() == 4 && v.eq_ignore_ascii_case(b"gzip")
        })
    };

    if !*conf.borrow().enable || !gzip {
        return next(r).await;
    }

    r.gzip_vary.set(true);

    if !r.gzip_tested.get() {
        if crate::core_rt::gzip_ok(&r) == NGX_OK {
            return next(r).await;
        }
    } else if r.gzip_ok.get() {
        return next(r).await;
    }

    r.set_ctx(ctx_index(), GunzipCtx::new(r.connection.log.clone()));

    r.filter_need_in_memory.set(true);

    r.clear_content_encoding();

    r.clear_content_length();
    r.clear_accept_ranges();
    crate::core_rt::weak_etag(&r);

    next(r).await
}

/// ngx_http_gunzip_body_filter
async fn gunzip_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx = match r.get_ctx::<GunzipCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r, input).await,
    };

    if ctx.borrow().done {
        return next(r, input).await;
    }

    http_debug!(r, "http gunzip filter");

    if !ctx.borrow().started && gunzip_filter_inflate_start(&r, &mut ctx.borrow_mut()) != NGX_OK {
        return gunzip_filter_failed(&ctx);
    }

    if !input.is_empty() {
        ctx.borrow_mut().in_.extend(input);
    }

    let mut flush;

    if ctx.borrow().nomem {
        // flush busy buffers

        if next(r.clone(), Chain::new()).await == NGX_ERROR {
            return gunzip_filter_failed(&ctx);
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

            let rc = gunzip_filter_add_data(&r, &mut ctx.borrow_mut());

            if rc == NGX_DECLINED {
                break;
            }

            if rc == NGX_AGAIN {
                continue;
            }

            // ... there are buffers to write zlib output

            let rc = gunzip_filter_get_buf(&r, &mut ctx.borrow_mut());

            if rc == NGX_DECLINED {
                break;
            }

            if rc == NGX_ERROR {
                return gunzip_filter_failed(&ctx);
            }

            let rc = gunzip_filter_inflate(&r, &mut ctx.borrow_mut());

            if rc == NGX_OK {
                break;
            }

            if rc == NGX_ERROR {
                return gunzip_filter_failed(&ctx);
            }

            // rc == NGX_AGAIN
        }

        if ctx.borrow().out.is_empty() && !flush {
            return NGX_OK;
        }

        let out = std::mem::take(&mut ctx.borrow_mut().out);

        // ngx_chain_update_chains(): the buffers of the module passed on
        // are free once sent
        let sent: Vec<Buf> = out.iter().filter(|b| b.tag == gunzip_tag()).map(buf_shell).collect();

        let rc = next(r.clone(), out).await;

        if rc == NGX_ERROR {
            return gunzip_filter_failed(&ctx);
        }

        let mut c = ctx.borrow_mut();

        for b in sent {
            c.free.insert(0, b);
        }

        http_debug!(r, "gunzip out: {:016X}", 0);

        c.nomem = false;
        flush = false;

        if c.done {
            return rc;
        }
    }
}

/// The failed: part of ngx_http_gunzip_body_filter()
fn gunzip_filter_failed(ctx: &Rc<RefCell<GunzipCtx>>) -> i64 {
    ctx.borrow_mut().done = true;

    NGX_ERROR
}

/// ngx_http_gunzip_filter_inflate_start
fn gunzip_filter_inflate_start(r: &R, ctx: &mut GunzipCtx) -> i64 {
    ctx.zstream.next_in = std::ptr::null_mut();
    ctx.zstream.avail_in = 0;

    ctx.zstream.zalloc = gunzip_filter_alloc;
    ctx.zstream.zfree = gunzip_filter_free;
    ctx.zstream.opaque = ctx.alloc as *mut libc::c_void;

    // windowBits +16 to decode gzip, zlib 1.2.0.4+
    // SAFETY: the stream is boxed (zlib keeps a pointer to it in its state)
    // and its allocator is the one of the ctx, which outlives it.
    let rc = unsafe { z::inflateInit2_(&mut *ctx.zstream, MAX_WBITS + 16, z::zlibVersion(), std::mem::size_of::<z::z_stream>() as i32) };

    if rc != z::Z_OK {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "inflateInit2() failed: {}", rc);
        return NGX_ERROR;
    }

    ctx.started = true;

    ctx.flush = z::Z_NO_FLUSH;

    NGX_OK
}

/// ngx_http_gunzip_filter_add_data
fn gunzip_filter_add_data(r: &R, ctx: &mut GunzipCtx) -> i64 {
    if ctx.zstream.avail_in != 0 || ctx.flush != z::Z_NO_FLUSH || ctx.redo {
        return NGX_OK;
    }

    http_debug!(r, "gunzip in: {:016X}", ctx.in_ptr());

    let buf = match ctx.in_.pop_front() {
        Some(buf) => buf,
        None => return NGX_DECLINED,
    };

    ctx.in_buf = Some(buf);

    let in_buf = ctx.in_buf.as_ref().expect("in_buf");

    let start = buf_data_ptr(in_buf);

    ctx.zstream.next_in = if start.is_null() { std::ptr::null_mut() } else { start.wrapping_add(in_buf.pos) as *mut u8 };
    ctx.zstream.avail_in = buf_mem_size(in_buf) as z::uInt;

    http_debug!(r, "gunzip in_buf:{:016X} ni:{:016X} ai:{}", ctx.in_buf_ptr(), ctx.zstream.next_in as usize, ctx.zstream.avail_in);

    let in_buf = ctx.in_buf.as_ref().expect("in_buf");

    if in_buf.last_buf || in_buf.last_in_chain {
        ctx.flush = z::Z_FINISH;
    } else if in_buf.flush {
        ctx.flush = z::Z_SYNC_FLUSH;
    } else if ctx.zstream.avail_in == 0 {
        // ctx->flush == Z_NO_FLUSH
        return NGX_AGAIN;
    }

    NGX_OK
}

/// ngx_http_gunzip_filter_get_buf
fn gunzip_filter_get_buf(r: &R, ctx: &mut GunzipCtx) -> i64 {
    if ctx.zstream.avail_out != 0 {
        return NGX_OK;
    }

    let conf = r.loc_conf::<GunzipConf>(ctx_index());
    let bufs = conf.borrow().bufs;

    if !ctx.free.is_empty() {
        let mut b = ctx.free.remove(0);

        b.data = BufData::Memory(vec![0u8; bufs.size]);
        b.flush = false;

        ctx.out_buf = Some(b);
    } else if ctx.bufs < bufs.num {
        // ngx_create_temp_buf()
        let mut b = Buf { data: BufData::Memory(vec![0u8; bufs.size]), pos: 0, last: 0, temporary: true, ..Default::default() };

        b.tag = gunzip_tag();
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

/// ngx_http_gunzip_filter_inflate
fn gunzip_filter_inflate(r: &R, ctx: &mut GunzipCtx) -> i64 {
    http_debug!(
        r,
        "inflate in: ni:{:016X} no:{:016X} ai:{} ao:{} fl:{} redo:{}",
        ctx.zstream.next_in as usize,
        ctx.zstream.next_out as usize,
        ctx.zstream.avail_in,
        ctx.zstream.avail_out,
        ctx.flush,
        ctx.redo as i32
    );

    // SAFETY: next_in points into ctx->in_buf and next_out into
    // ctx->out_buf, both owned by the ctx with the lengths avail_in and
    // avail_out; the stream was initialized by inflateInit2_().
    let rc = unsafe { z::inflate(&mut *ctx.zstream, ctx.flush) };

    if rc != z::Z_OK && rc != z::Z_STREAM_END && rc != z::Z_BUF_ERROR {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "inflate() failed: {}, {}", ctx.flush, rc);
        return NGX_ERROR;
    }

    http_debug!(
        r,
        "inflate out: ni:{:016X} no:{:016X} ai:{} ao:{} rc:{}",
        ctx.zstream.next_in as usize,
        ctx.zstream.next_out as usize,
        ctx.zstream.avail_in,
        ctx.zstream.avail_out,
        rc
    );

    http_debug!(r, "gunzip in_buf:{:016X} pos:{:016X}", ctx.in_buf_ptr(), ctx.in_buf_pos());

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

    if ctx.zstream.avail_out == 0 {
        // zlib wants to output some more data

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

        return NGX_OK;
    }

    if ctx.flush == z::Z_FINISH && ctx.zstream.avail_in == 0 {
        if rc != z::Z_STREAM_END {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "inflate() returned {} on response end", rc);
            return NGX_ERROR;
        }

        if gunzip_filter_inflate_end(r, ctx) != NGX_OK {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if rc == z::Z_STREAM_END && ctx.zstream.avail_in > 0 {
        // SAFETY: the stream was initialized by inflateInit2_().
        let rc = unsafe { z::inflateReset(&mut *ctx.zstream) };

        if rc != z::Z_OK {
            ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "inflateReset() failed: {}", rc);
            return NGX_ERROR;
        }

        ctx.redo = true;

        return NGX_AGAIN;
    }

    if ctx.in_.is_empty() {
        if ctx.out_buf.as_ref().expect("out_buf").buf_size() == 0 {
            return NGX_OK;
        }

        ctx.zstream.avail_out = 0;

        let b = ctx.out_buf.take().expect("out_buf");
        ctx.out.push_back(b);

        return NGX_OK;
    }

    NGX_AGAIN
}

/// ngx_http_gunzip_filter_inflate_end
fn gunzip_filter_inflate_end(r: &R, ctx: &mut GunzipCtx) -> i64 {
    http_debug!(r, "gunzip inflate end");

    // SAFETY: the stream was initialized by inflateInit2_().
    let rc = unsafe { z::inflateEnd(&mut *ctx.zstream) };

    if rc != z::Z_OK {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "inflateEnd() failed: {}", rc);
        return NGX_ERROR;
    }

    let mut b = if ctx.out_buf.as_ref().expect("out_buf").buf_size() == 0 {
        // ngx_calloc_buf()
        Buf::default()
    } else {
        ctx.out_buf.take().expect("out_buf")
    };

    b.last_buf = r.is_main();
    b.last_in_chain = true;
    b.sync = true;

    ctx.out.push_back(b);

    ctx.done = true;

    NGX_OK
}

/// ngx_http_gunzip_filter_alloc
unsafe extern "C" fn gunzip_filter_alloc(opaque: *mut libc::c_void, items: z::uInt, size: z::uInt) -> *mut libc::c_void {
    // SAFETY: opaque is the GunzipAlloc of the ctx, alive during the zlib
    // calls, and nothing else refers to it meanwhile.
    let ctx = &mut *(opaque as *mut GunzipAlloc);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "gunzip alloc: n:{} s:{}", items, size);

    // ngx_palloc(ctx->request->pool, items * size)
    let mut v = vec![0u64; (items as usize * size as usize).div_ceil(8)];
    let p = v.as_mut_ptr() as *mut libc::c_void;

    ctx.pool.push(v);

    p
}

/// ngx_http_gunzip_filter_free
unsafe extern "C" fn gunzip_filter_free(_opaque: *mut libc::c_void, _address: *mut libc::c_void) {}

/// ngx_http_gunzip_create_conf
fn gunzip_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(GunzipConf { enable: Val::unset(), bufs: Bufs::default() })
}

/// ngx_http_gunzip_merge_conf
fn gunzip_merge_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<GunzipConf>(parent).borrow();
    let mut conf = conf_cell::<GunzipConf>(child).borrow_mut();

    conf.enable.merge(&prev.enable, false);

    let pagesize = ngx_core::os::pagesize();
    conf.bufs.merge(&prev.bufs, (128 * 1024) / pagesize, pagesize);

    Ok(())
}

/// ngx_http_gunzip_filter_init
fn gunzip_filter_init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { gunzip_header_filter(r, next).await });
    install_body_filter(|r, input, next| async move { gunzip_body_filter(r, input, next).await });
    Ok(())
}

pub fn gunzip_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(gunzip_filter_init),
        create_loc_conf: Some(gunzip_create_conf),
        merge_loc_conf: Some(gunzip_merge_conf),
        ..Default::default()
    };

    const MSL: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd!("gunzip", MSL | NGX_CONF_FLAG, ConfLevel::Loc, GunzipConf, enable, set_flag),
        cmd!("gunzip_buffers", MSL | NGX_CONF_TAKE2, ConfLevel::Loc, GunzipConf, bufs, set_bufs),
    ];

    http_module_def("ngx_http_gunzip_filter_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// inflateInit2() with MAX_WBITS + 16 decodes a gzip member, and
    /// inflateReset() the next one
    #[test]
    fn gzip_members() {
        let mut ctx = GunzipCtx::new(Log::new(ngx_core::log::LogChain::new()));

        let rc = unsafe { z::inflateInit2_(&mut *ctx.zstream, MAX_WBITS + 16, z::zlibVersion(), std::mem::size_of::<z::z_stream>() as i32) };
        assert_eq!(rc, z::Z_OK);

        // "TEST" gzipped by the C gzip filter at level 1
        let member: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\x03\x0bq\x0d\x0e\x01\x00\xb8\x93\xea\xee\x04\x00\x00\x00";
        let mut input = member.to_vec();
        input.extend_from_slice(member);

        let mut out = vec![0u8; 64];

        ctx.zstream.next_in = input.as_mut_ptr();
        ctx.zstream.avail_in = input.len() as z::uInt;
        ctx.zstream.next_out = out.as_mut_ptr();
        ctx.zstream.avail_out = out.len() as z::uInt;

        let rc = unsafe { z::inflate(&mut *ctx.zstream, z::Z_FINISH) };
        assert_eq!(rc, z::Z_STREAM_END);
        assert_eq!(ctx.zstream.avail_in as usize, member.len());

        assert_eq!(unsafe { z::inflateReset(&mut *ctx.zstream) }, z::Z_OK);

        let rc = unsafe { z::inflate(&mut *ctx.zstream, z::Z_FINISH) };
        assert_eq!(rc, z::Z_STREAM_END);

        let n = out.len() - ctx.zstream.avail_out as usize;
        assert_eq!(&out[..n], b"TESTTEST");

        assert_eq!(unsafe { z::inflateEnd(&mut *ctx.zstream) }, z::Z_OK);
    }
}
