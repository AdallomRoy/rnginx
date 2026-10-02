//! ngx_http_gunzip_filter_module
//!
//! zlib (through flate2's safe API, the system zlib as in the C build)
//! decodes the gzip framing itself (inflateInit2() with MAX_WBITS + 16).
//! zlib allocates its memory itself (flate2's allocator), hence no
//! "gunzip alloc" debug lines.  The buffers own their data here: the
//! output buffers a buffer of ctx->free stands for are allocated again
//! when it is taken, and those passed on are free once the next filter
//! returns, as the write filter has sent them by then (C keeps the ones
//! not sent yet in ctx->busy).

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use flate2::{Decompress, FlushDecompress, Status};

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::{cmd, ngx_log_error};

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_gunzip_filter_module");

/// MAX_WBITS of zconf.h
const MAX_WBITS: u8 = 15;

// the flush values and the return codes of zlib.h, as nginx logs them

const Z_NO_FLUSH: i32 = 0;
const Z_SYNC_FLUSH: i32 = 2;
const Z_FINISH: i32 = 4;

const Z_OK: i32 = 0;
const Z_STREAM_END: i32 = 1;
const Z_NEED_DICT: i32 = 2;
const Z_DATA_ERROR: i32 = -3;
const Z_BUF_ERROR: i32 = -5;

/// ngx_http_gunzip_conf_t
pub struct GunzipConf {
    pub enable: Val<bool>,
    pub bufs: Bufs,
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

    /// the inflate stream inflateInit2() initialized, until inflateEnd()
    zstream: Option<Decompress>,

    /// zstream.next_in != NULL: the unprocessed input starts at
    /// in_buf.pos
    next_in: bool,
    /// zstream.avail_in
    avail_in: usize,
    /// zstream.avail_out: the free space of out_buf, from out_buf.last
    avail_out: usize,
}

impl GunzipCtx {
    fn new() -> GunzipCtx {
        GunzipCtx {
            in_: Chain::new(),
            free: Vec::new(),
            out: Chain::new(),
            in_buf: None,
            out_buf: None,
            bufs: 0,
            started: false,
            flush: Z_NO_FLUSH,
            redo: false,
            done: false,
            nomem: false,
            zstream: None,
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
/// &ngx_http_gunzip_filter_module
fn gunzip_tag() -> usize {
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

    r.set_ctx(ctx_index(), GunzipCtx::new());

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
fn gunzip_filter_inflate_start(_r: &R, ctx: &mut GunzipCtx) -> i64 {
    ctx.next_in = false;
    ctx.avail_in = 0;

    // windowBits +16 to decode gzip, zlib 1.2.0.4+; inflateInit2() fails
    // only when out of memory, which flate2 does not survive
    // ("inflateInit2() failed")
    ctx.zstream = Some(Decompress::new_gzip(MAX_WBITS));

    ctx.started = true;

    ctx.flush = Z_NO_FLUSH;

    NGX_OK
}

/// ngx_http_gunzip_filter_add_data
fn gunzip_filter_add_data(r: &R, ctx: &mut GunzipCtx) -> i64 {
    if ctx.avail_in != 0 || ctx.flush != Z_NO_FLUSH || ctx.redo {
        return NGX_OK;
    }

    http_debug!(r, "gunzip in: {:016X}", ctx.in_ptr());

    let buf = match ctx.in_.pop_front() {
        Some(buf) => buf,
        None => return NGX_DECLINED,
    };

    ctx.in_buf = Some(buf);

    let in_buf = ctx.in_buf.as_ref().expect("in_buf");

    // zstream.next_in = in_buf->pos, NULL for the buffers without memory
    ctx.next_in = matches!(in_buf.data, BufData::Memory(_));
    ctx.avail_in = buf_mem_size(in_buf);

    http_debug!(r, "gunzip in_buf:{:016X} ni:{:016X} ai:{}", ctx.in_buf_ptr(), ctx.next_in_ptr(), ctx.avail_in);

    let in_buf = ctx.in_buf.as_ref().expect("in_buf");

    if in_buf.last_buf || in_buf.last_in_chain {
        ctx.flush = Z_FINISH;
    } else if in_buf.flush {
        ctx.flush = Z_SYNC_FLUSH;
    } else if ctx.avail_in == 0 {
        // ctx->flush == Z_NO_FLUSH
        return NGX_AGAIN;
    }

    NGX_OK
}

/// ngx_http_gunzip_filter_get_buf
fn gunzip_filter_get_buf(r: &R, ctx: &mut GunzipCtx) -> i64 {
    if ctx.avail_out != 0 {
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

    // zstream.next_out = ctx->out_buf->pos, the buffer is empty
    ctx.avail_out = bufs.size;

    NGX_OK
}

/// ngx_http_gunzip_filter_inflate
/// inflate(&ctx->zstream, ctx->flush): the zlib return code; the input
/// consumed advances in_buf.pos (the C does it after the call from
/// zstream.next_in), the output is appended to out_buf.  The errors of
/// flate2 are Z_NEED_DICT and Z_DATA_ERROR: Z_STREAM_ERROR needs a NULL
/// buffer pointer, which flate2 never passes.
fn inflate(ctx: &mut GunzipCtx) -> i32 {
    let flush = match ctx.flush {
        Z_SYNC_FLUSH => FlushDecompress::Sync,
        Z_FINISH => FlushDecompress::Finish,
        _ => FlushDecompress::None,
    };

    let GunzipCtx { zstream, in_buf, out_buf, next_in, avail_in, avail_out, .. } = ctx;

    let z = zstream.as_mut().expect("inflate stream");

    let input: &[u8] = match (in_buf.as_ref(), *next_in) {
        (Some(b), true) => match &b.data {
            BufData::Memory(v) => &v[b.pos..b.pos + *avail_in],
            _ => &[],
        },
        _ => &[],
    };

    let out_buf = out_buf.as_mut().expect("out_buf");
    let last = out_buf.last;

    let output: &mut [u8] = match &mut out_buf.data {
        BufData::Memory(v) => &mut v[last..last + *avail_out],
        _ => &mut [],
    };

    let (total_in, total_out) = (z.total_in(), z.total_out());

    let rc = match z.decompress(input, output, flush) {
        Ok(Status::Ok) => Z_OK,
        Ok(Status::StreamEnd) => Z_STREAM_END,
        Ok(Status::BufError) => Z_BUF_ERROR,
        Err(e) if e.needs_dictionary().is_some() => Z_NEED_DICT,
        Err(_) => Z_DATA_ERROR,
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

/// ngx_http_gunzip_filter_inflate
fn gunzip_filter_inflate(r: &R, ctx: &mut GunzipCtx) -> i64 {
    http_debug!(r, "inflate in: ni:{:016X} no:{:016X} ai:{} ao:{} fl:{} redo:{}", ctx.next_in_ptr(), ctx.next_out_ptr(), ctx.avail_in, ctx.avail_out, ctx.flush, ctx.redo as i32);

    let rc = inflate(ctx);

    if rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "inflate() failed: {}, {}", ctx.flush, rc);
        return NGX_ERROR;
    }

    http_debug!(r, "inflate out: ni:{:016X} no:{:016X} ai:{} ao:{} rc:{}", ctx.next_in_ptr(), ctx.next_out_ptr(), ctx.avail_in, ctx.avail_out, rc);

    http_debug!(r, "gunzip in_buf:{:016X} pos:{:016X}", ctx.in_buf_ptr(), ctx.in_buf_pos());

    // in_buf->pos = zstream.next_in (done by inflate()), and
    if ctx.next_in && ctx.avail_in == 0 {
        ctx.next_in = false;
    }

    if ctx.avail_out == 0 {
        // zlib wants to output some more data

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

        return NGX_OK;
    }

    if ctx.flush == Z_FINISH && ctx.avail_in == 0 {
        if rc != Z_STREAM_END {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "inflate() returned {} on response end", rc);
            return NGX_ERROR;
        }

        if gunzip_filter_inflate_end(r, ctx) != NGX_OK {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if rc == Z_STREAM_END && ctx.avail_in > 0 {
        // inflateReset(), which keeps the gzip decoding: a new stream as
        // inflateInit2(MAX_WBITS + 16) makes it (flate2's reset() is
        // inflateReset2() with the zlib or raw format); it does not fail
        // on a valid stream ("inflateReset() failed")
        ctx.zstream = Some(Decompress::new_gzip(MAX_WBITS));

        ctx.redo = true;

        return NGX_AGAIN;
    }

    if ctx.in_.is_empty() {
        if ctx.out_buf.as_ref().expect("out_buf").buf_size() == 0 {
            return NGX_OK;
        }

        ctx.avail_out = 0;

        let b = ctx.out_buf.take().expect("out_buf");
        ctx.out.push_back(b);

        return NGX_OK;
    }

    NGX_AGAIN
}

/// ngx_http_gunzip_filter_inflate_end
fn gunzip_filter_inflate_end(r: &R, ctx: &mut GunzipCtx) -> i64 {
    http_debug!(r, "gunzip inflate end");

    // inflateEnd(): Z_OK for a valid stream ("inflateEnd() failed" cannot
    // happen)
    ctx.zstream = None;

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

    /// inflateInit2() with MAX_WBITS + 16 decodes a gzip member, and a
    /// new stream (inflateReset()) the next one
    #[test]
    fn gzip_members() {
        // "TEST" gzipped by the C gzip filter at level 1
        let member: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x04\x03\x0bq\x0d\x0e\x01\x00\xb8\x93\xea\xee\x04\x00\x00\x00";
        let mut input = member.to_vec();
        input.extend_from_slice(member);

        let mut ctx = GunzipCtx::new();
        ctx.zstream = Some(Decompress::new_gzip(MAX_WBITS));

        ctx.in_buf = Some(Buf::from_vec(input.clone()));
        ctx.next_in = true;
        ctx.avail_in = input.len();

        ctx.out_buf = Some(Buf { data: BufData::Memory(vec![0u8; 64]), temporary: true, ..Default::default() });
        ctx.avail_out = 64;

        ctx.flush = Z_FINISH;

        assert_eq!(inflate(&mut ctx), Z_STREAM_END);
        assert_eq!(ctx.avail_in, member.len());
        assert_eq!(ctx.in_buf.as_ref().unwrap().pos, member.len());

        ctx.zstream = Some(Decompress::new_gzip(MAX_WBITS));

        assert_eq!(inflate(&mut ctx), Z_STREAM_END);
        assert_eq!(ctx.avail_in, 0);

        let b = ctx.out_buf.as_ref().unwrap();
        assert_eq!(b.last, 8);
        match &b.data {
            BufData::Memory(v) => assert_eq!(&v[..8], b"TESTTEST"),
            _ => unreachable!(),
        }

        assert_eq!(ctx.avail_out, 56);

        // garbage: Z_DATA_ERROR
        ctx.zstream = Some(Decompress::new_gzip(MAX_WBITS));
        ctx.in_buf = Some(Buf::from_vec(b"not gzip".to_vec()));
        ctx.avail_in = 8;
        ctx.next_in = true;
        assert_eq!(inflate(&mut ctx), Z_DATA_ERROR);
    }
}
