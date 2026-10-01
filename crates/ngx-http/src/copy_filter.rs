//! ngx_http_copy_filter_module: reads file buffers into memory when needed,
//! as ngx_output_chain() does.

use std::collections::VecDeque;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_copy_filter_module");

/// NGX_NONE of ngx_output_chain()
const NGX_NONE: i64 = 1;

pub struct CopyConf {
    pub bufs: Bufs,
}

fn create_conf(_cf: &mut Conf) -> std::rc::Rc<dyn std::any::Any> {
    make_slot(CopyConf { bufs: Bufs::default() })
}

fn merge_conf(_cf: &mut Conf, prev: &std::rc::Rc<dyn std::any::Any>, conf: &std::rc::Rc<dyn std::any::Any>) -> ConfResult {
    let p = conf_cell::<CopyConf>(prev).borrow();
    let mut c = conf_cell::<CopyConf>(conf).borrow_mut();
    c.bufs.merge(&p.bufs, 2, 32768);
    Ok(())
}

pub fn copy_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), create_loc_conf: Some(create_conf), merge_loc_conf: Some(merge_conf), ..Default::default() };
    let commands = vec![ngx_core::cmd!("output_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, CopyConf, bufs, set_bufs)];
    http_module_def("ngx_http_copy_filter_module", def, commands)
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_body_filter(|r, chain, next| async move { copy_filter(r, chain, next).await });
    Ok(())
}

/// The output_buffers total: how much output may be in flight before the
/// copy filter has to wait (its busy buffers in C).
pub fn output_buffers_size(r: &R) -> usize {
    let conf = r.loc_conf::<CopyConf>(ctx_index());
    let b = conf.borrow();
    b.bufs.num.max(1) * b.bufs.size.max(1)
}

/// A copy buffer of ngx_output_chain_get_buf(): its size (b->end -
/// b->start) and whether it is recycled.
#[derive(Clone, Copy)]
struct CopyBuf {
    size: usize,
    recycled: bool,
}

/// The request's ngx_output_chain_ctx_t. The copy buffers themselves are
/// not kept: the data read goes out in new buffers, and ctx->free and
/// ctx->busy keep what the reuse of the buffers depends on.
struct CopyCtx {
    sendfile: bool,
    need_in_memory: bool,
    need_in_temp: bool,
    directio: bool,
    alignment: usize,
    bufs: Bufs,
    allocated: usize,
    free: Vec<CopyBuf>,
    busy: VecDeque<CopyBuf>,
}

/// ngx_http_copy_filter
async fn copy_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx = match r.get_ctx::<CopyCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => {
            let conf = r.loc_conf::<CopyConf>(ctx_index());
            let clcf = r.clcf();

            let ctx = r.set_ctx(ctx_index(), CopyCtx {
                sendfile: r.connection.sendfile.get(),
                need_in_memory: r.main_filter_need_in_memory.get() || r.filter_need_in_memory.get(),
                need_in_temp: r.filter_need_temporary.get(),
                directio: false,
                alignment: *clcf.borrow().directio_alignment as usize,
                bufs: conf.borrow().bufs,
                allocated: 0,
                free: Vec::new(),
                busy: VecDeque::new(),
            });

            if input.front().is_some_and(|b| b.buf_size() != 0) {
                r.request_output.set(true);
            }

            ctx
        }
    };

    let rc = output_chain(&r, &ctx, input, next).await;

    http_debug!(r, "http copy filter: {} \"{}?{}\"", rc, B(&r.uri.borrow()), B(&r.args.borrow()));

    rc
}

/// ngx_output_chain
async fn output_chain(r: &R, ctx: &std::rc::Rc<std::cell::RefCell<CopyCtx>>, input: Chain, next: BodyFilter) -> i64 {
    update_chains(r, &mut ctx.borrow_mut(), Vec::new());

    if ctx.borrow().busy.is_empty() && (input.is_empty() || (input.len() == 1 && as_is(&ctx.borrow(), &input[0]))) {
        // the short path for the case when the busy chain is empty (the
        // input is never kept), the incoming chain is empty too or has the
        // single buf that does not require the copy
        let rc = next(r.clone(), input).await;
        update_chains(r, &mut ctx.borrow_mut(), Vec::new());
        return rc;
    }

    let mut input = input;
    let mut out = Chain::new();
    let mut copies: Vec<CopyBuf> = Vec::new();
    let mut last = NGX_NONE;

    loop {
        while let Some(src) = input.front_mut() {
            let bsize = src.buf_size();

            if bsize == 0 && !src.special_buf() {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "zero size buf in output {}", buf_info(src));
                input.pop_front();
                continue;
            }

            if bsize < 0 {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "negative size buf in output {}", buf_info(src));
                return NGX_ERROR;
            }

            if as_is(&ctx.borrow(), src) {
                // move the buf to the output chain
                out.push_back(input.pop_front().unwrap());
                continue;
            }

            // ctx->buf == NULL: the buffer to copy in

            let mut c = ctx.borrow_mut();
            let tagged: Option<CopyBuf>;
            let unaligned: bool;
            let size: usize;

            if let Some(n) = align_file_buf(&mut c, src, bsize) {
                // not reused via the ctx->free list
                size = n;
                tagged = None;
                unaligned = true;
            } else {
                if let Some(b) = c.free.pop() {
                    // get the free buf
                    tagged = Some(b);
                } else if !out.is_empty() {
                    break;
                } else if c.allocated == c.bufs.num && !c.busy.is_empty() {
                    // All the buffers are passed on and not sent: C waits
                    // for the write events to free them, the write filter
                    // has bounded what is in flight.
                    let busy: Vec<CopyBuf> = c.busy.drain(..).collect();
                    c.free.extend(busy);
                    continue;
                } else {
                    let b = get_buf(&c, src, bsize);
                    c.allocated += 1;
                    tagged = Some(b);
                }

                size = tagged.map(|b| b.size).unwrap_or(0);
                unaligned = false;
            }

            let directio = c.directio;
            let alignment = c.alignment;
            drop(c);

            let dst = match copy_buf(r, src, size, directio, alignment, unaligned, tagged.is_some_and(|b| b.recycled)) {
                Ok(dst) => dst,
                Err(rc) => return rc,
            };

            // delete the completed buf from the input chain
            if src.buf_size() == 0 {
                input.pop_front();
            }

            out.push_back(dst);

            if let Some(b) = tagged {
                copies.push(b);
            }
        }

        if out.is_empty() && last != NGX_NONE {
            return last;
        }

        last = next(r.clone(), std::mem::take(&mut out)).await;

        if last == NGX_ERROR || last == NGX_DONE {
            return last;
        }

        update_chains(r, &mut ctx.borrow_mut(), std::mem::take(&mut copies));
    }
}

/// ngx_chain_update_chains for the copy buffers: those passed on join the
/// busy ones, which are free again once sent (what is not sent stays in
/// r->out).
fn update_chains(r: &R, c: &mut CopyCtx, copies: Vec<CopyBuf>) {
    c.busy.extend(copies);

    if r.out.borrow().is_empty() {
        while let Some(b) = c.busy.pop_front() {
            c.free.push(b);
        }
    }
}

/// "t:%d r:%d f:%d %p %p-%p %p %O-%O" of a buf: temporary, recycled,
/// in_file, start, pos, last, file, file_pos, file_last.
fn buf_info(b: &Buf) -> String {
    let (start, pos, last) = match &b.data {
        BufData::Memory(v) => {
            let p = v.as_ptr() as usize;
            (p, p + b.pos, p + b.last)
        }
        _ => (0, 0, 0),
    };

    let file = match &b.data {
        BufData::File(f) => std::rc::Rc::as_ptr(f) as usize,
        _ => 0,
    };

    format!("t:{} r:{} f:{} {:016X} {:016X}-{:016X} {:016X} {}-{}", b.temporary as i32, b.recycled as i32, b.in_file as i32, start, pos, last, file, b.file_pos, b.file_last)
}

/// Whether the buffer of the file is to be read with O_DIRECT.
fn file_directio(b: &Buf) -> bool {
    matches!(&b.data, BufData::File(f) if f.directio)
}

/// ngx_output_chain_as_is
fn as_is(c: &CopyCtx, b: &Buf) -> bool {
    if b.special_buf() {
        return true;
    }

    let mut sendfile = c.sendfile;

    // With DIRECTIO, disable sendfile() unless sendfile(SF_NOCACHE)
    // is available.

    if b.in_file && file_directio(b) {
        sendfile = false;
    }

    // a buffer is either in memory or in a file here, the memory one does
    // not need its in_file cleared for no sendfile
    if !sendfile && !b.in_memory() {
        return false;
    }

    if c.need_in_memory && !b.in_memory() {
        return false;
    }

    if c.need_in_temp && (b.memory || b.mmap) {
        return false;
    }

    true
}

/// ngx_output_chain_align_file_buf: the size of the buffer for the part of
/// a directio file up to the alignment, or for its small rest, which are
/// read without O_DIRECT
fn align_file_buf(c: &mut CopyCtx, src: &Buf, bsize: i64) -> Option<usize> {
    if !src.in_file || !file_directio(src) {
        return None;
    }

    c.directio = true;

    let alignment = c.alignment as i64;
    let mut size = (src.file_pos - (src.file_pos & !(alignment - 1))) as usize;

    if size == 0 {
        if bsize >= c.bufs.size as i64 {
            return None;
        }

        size = bsize as usize;
    } else {
        size = c.alignment - size;

        if size as i64 > bsize {
            size = bsize as usize;
        }
    }

    Some(size)
}

/// ngx_output_chain_get_buf
fn get_buf(c: &CopyCtx, src: &Buf, bsize: i64) -> CopyBuf {
    let mut size = c.bufs.size;
    let mut recycled = true;

    if src.last_in_chain {
        if bsize < size as i64 {
            // allocate a small temp buf for a small last buf
            // or its small last part

            size = bsize as usize;
            recycled = false;
        } else if !c.directio && c.bufs.num == 1 && bsize < (size + size / 4) as i64 {
            // allocate a temp buf that equals to a last buf,
            // if there is no directio, the last buf size is lesser
            // than 1.25 of bufs.size and the temp buf is single

            size = bsize as usize;
            recycled = false;
        }
    }

    CopyBuf { size, recycled }
}

/// ngx_output_chain_copy_buf: `size` bytes of src at most into a new
/// buffer, aligned for directio (ngx_pmemalign), and src moved past them
fn copy_buf(r: &R, src: &mut Buf, size: usize, directio: bool, alignment: usize, unaligned: bool, recycled: bool) -> Result<Buf, i64> {
    let log = &r.connection.log;
    let size = (src.buf_size() as usize).min(size);

    let mut dst;

    if src.in_memory() {
        let data = match &src.data {
            BufData::Memory(v) => v[src.pos..src.pos + size].to_vec(),
            _ => Vec::new(),
        };

        src.pos += size;

        dst = Buf::from_vec(data);

        if src.pos == src.last {
            dst.flush = src.flush;
            dst.last_buf = src.last_buf;
            dst.last_in_chain = src.last_in_chain;
        }
    } else {
        let (fd, name) = match &src.data {
            BufData::File(f) => (f.fd, f.name.clone()),
            _ => return Err(NGX_ERROR),
        };

        // with directio the buffer is aligned to a disk sector size
        let align = if directio && !unaligned { alignment.max(1) } else { 1 };
        let mut v = vec![0u8; size + align - 1];
        let start = v.as_ptr().align_offset(align).min(align - 1);

        if unaligned && ngx_core::os::directio_off(fd) == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(ngx_core::os::errno()), "{} \"{}\" failed", ngx_core::os::DIRECTIO_OFF_N, B(&name));
        }

        let buf = &mut v[start..start + size];

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "read: {}, {:p}, {}, {}", fd, buf.as_ptr(), size, src.file_pos);

        let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, size, src.file_pos as libc::off_t) };
        let err = ngx_core::os::errno();

        if unaligned && ngx_core::os::directio_on(fd) == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(ngx_core::os::errno()), "{} \"{}\" failed", ngx_core::os::DIRECTIO_ON_N, B(&name));
        }

        if n == -1 {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "pread() \"{}\" failed", B(&name));
            return Err(NGX_ERROR);
        }

        if n as usize != size {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "pread() read only {} of {} from \"{}\"", n, size, B(&name));
            return Err(NGX_ERROR);
        }

        dst = Buf::from_vec(v);
        dst.pos = start;
        dst.last = start + size;

        src.file_pos += n as i64;

        if src.file_pos == src.file_last {
            dst.flush = src.flush;
            dst.last_buf = src.last_buf;
            dst.last_in_chain = src.last_in_chain;
        }
    }

    dst.recycled = recycled;

    Ok(dst)
}
