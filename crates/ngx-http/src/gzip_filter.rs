//! ngx_http_gzip_filter_module — streaming deflate with the nginx gzip framing.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use flate2::{Compress, Compression, FlushCompress, Status};
use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::ngx_log_error;
use ngx_core::log::*;

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_gzip_filter_module");

pub struct GzipConf {
    pub enable: Val<bool>,
    pub level: Val<i32>,
    pub min_length: Val<usize>,
    pub types: Val<Vec<Vec<u8>>>,
    pub http_version: Val<u32>,
    pub gzip_vary: Val<bool>,
}

impl Default for GzipConf {
    fn default() -> Self {
        GzipConf {
            enable: Val::unset(),
            level: Val::unset(),
            min_length: Val::unset(),
            types: Val::unset(),
            http_version: Val::unset(),
            gzip_vary: Val::unset(),
        }
    }
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(GzipConf::default())
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<GzipConf>(prev).borrow();
    let mut c = conf_cell::<GzipConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    c.level.merge(&p.level, 1);
    c.min_length.merge(&p.min_length, 20);
    if c.types.as_option().is_none() { c.types = p.types.clone(); }
    c.http_version.merge(&p.http_version, NGX_HTTP_VERSION_11);
    c.gzip_vary.merge(&p.gzip_vary, false);
    Ok(())
}

fn set_gzip(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().unwrap());
    let v = match cf.args[1].as_slice() { b"on" => true, b"off" => false, _ => return Err(msg("invalid value")) };
    cell.borrow_mut().enable = Val::set(v);
    Ok(())
}
fn set_level(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().unwrap());
    let n = ngx_core::string::atoi(&cf.args[1]).ok_or(msg("invalid number"))?;
    if !(1..=9).contains(&n) { return Err(msg("invalid value")); }
    cell.borrow_mut().level = Val::set(n as i32);
    Ok(())
}
fn set_min_length(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().unwrap());
    let n = ngx_core::parse::parse_size(&cf.args[1]).ok_or(msg("invalid value"))?;
    cell.borrow_mut().min_length = Val::set(n as usize);
    Ok(())
}
fn set_http_version(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().unwrap());
    let v = match cf.args[1].as_slice() {
        b"1.0" => NGX_HTTP_VERSION_10,
        b"1.1" => NGX_HTTP_VERSION_11,
        _ => return Err(msg("invalid value")),
    };
    cell.borrow_mut().http_version = Val::set(v);
    Ok(())
}
fn set_types(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().unwrap());
    let mut t = cell.borrow().types.as_option().cloned().unwrap_or_default();
    for a in cf.args.iter().skip(1) {
        if a == b"text/html" { continue; }
        if !t.iter().any(|x| x == a) { t.push(a.clone()); }
    }
    // text/html is always gzipped
    if !t.iter().any(|x| x == b"text/html") { t.push(b"text/html".to_vec()); }
    cell.borrow_mut().types = Val::set(t);
    Ok(())
}
fn set_vary(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipConf>(conf.as_ref().unwrap());
    let v = match cf.args[1].as_slice() { b"on" => true, b"off" => false, _ => return Err(msg("invalid value")) };
    cell.borrow_mut().gzip_vary = Val::set(v);
    Ok(())
}
fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { Ok(()) }

pub fn gzip_filter_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("gzip", F | NGX_CONF_FLAG, ConfLevel::Loc, set_gzip),
        ngx_core::cmd_fn!("gzip_comp_level", F | NGX_CONF_TAKE1, ConfLevel::Loc, set_level),
        ngx_core::cmd_fn!("gzip_min_length", F | NGX_CONF_TAKE1, ConfLevel::Loc, set_min_length),
        ngx_core::cmd_fn!("gzip_types", F | NGX_CONF_1MORE, ConfLevel::Loc, set_types),
        ngx_core::cmd_fn!("gzip_http_version", F | NGX_CONF_TAKE1, ConfLevel::Loc, set_http_version),
        ngx_core::cmd_fn!("gzip_buffers", F | NGX_CONF_TAKE2, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("gzip_window", F | NGX_CONF_TAKE1, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("gzip_hash", F | NGX_CONF_TAKE1, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("gzip_proxied", F | NGX_CONF_1MORE, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("gzip_vary", F | NGX_CONF_FLAG, ConfLevel::Loc, set_vary),
        ngx_core::cmd_fn!("gzip_no_buffer", F | NGX_CONF_FLAG, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("gzip_disable", F | NGX_CONF_1MORE, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("postpone_gzipping", F | NGX_CONF_TAKE1, ConfLevel::Loc, accept),
    ];
    http_module_def("ngx_http_gzip_filter_module", def, commands)
}

/// ngx_http_gzip_add_variables
fn add_variables(cf: &mut Conf) -> ConfResult {
    crate::variables::add_variables(cf, &[crate::variables::VarDef {
        name: "gzip_ratio",
        set: None,
        get: Some(gzip_ratio_variable),
        data: 0,
        flags: crate::variables::NGX_HTTP_VAR_NOHASH,
    }])
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

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { gzip_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { gzip_body_filter(r, chain, next).await });
    Ok(())
}

struct GzipCtx {
    compress: Compress,
    output: Vec<u8>,
    crc32: crc32fast::Hasher,
    isize: u32,
    header_sent: bool,
    done: bool,
    /// ctx->zin and ctx->zout: zstream.total_in and total_out when the
    /// deflate stream ended (total_out of the gzip-wrapped stream counts
    /// the 10-byte header and 8-byte trailer written around the deflate data)
    zin: usize,
    zout: usize,
}

impl GzipCtx {
    fn new(level: i32) -> Self {
        // Raw deflate (no zlib header)
        GzipCtx {
            compress: Compress::new(Compression::new(level as u32), false),
            output: Vec::new(),
            crc32: crc32fast::Hasher::new(),
            isize: 0,
            header_sent: false,
            done: false,
            zin: 0,
            zout: 0,
        }
    }
}

/// True when this response is a candidate for gzipping — regardless of
/// whether the client accepted gzip. Matches the C gzip_filter checks
/// that happen BEFORE `r->gzip_vary = 1`.
fn is_gzippable(r: &R) -> bool {
    let conf = r.loc_conf::<GzipConf>(ctx_index());
    let c = conf.borrow();
    if !*c.enable { return false; }
    if !r.is_main() { return false; }
    let status = r.headers_out.borrow().status;
    if status != NGX_HTTP_OK && status != NGX_HTTP_FORBIDDEN && status != NGX_HTTP_NOT_FOUND { return false; }
    if r.header_only.get() { return false; }
    if r.headers_out.borrow().content_encoding.is_some() { return false; }
    let cl = r.headers_out.borrow().content_length_n;
    if cl != -1 && (cl as usize) < *c.min_length { return false; }
    let types = c.types.as_option().cloned().unwrap_or_default();
    let ct = r.headers_out.borrow().content_type.clone();
    let ct_type = if let Some(sc) = ct.iter().position(|&b| b == b';') { &ct[..sc] } else { &ct[..] };
    let ct_trim: Vec<u8> = ct_type.iter().copied().filter(|&b| b != b' ' && b != b'\t').collect();
    if types.is_empty() {
        if ct_trim != b"text/html" { return false; }
    } else if !types.iter().any(|t| t.as_slice() == ct_trim.as_slice()) {
        return false;
    }
    true
}

fn should_gzip(r: &R) -> bool {
    if !is_gzippable(r) { return false; }
    // gzip_ok checks Accept-Encoding, http_version, proxied
    crate::core_rt::gzip_ok(r) == NGX_OK
}

async fn gzip_header_filter(r: R, next: HeaderFilter) -> i64 {
    if !should_gzip(&r) {
        // Vary: Accept-Encoding — only when the response IS gzippable
        // but we chose not to compress (typically because the client
        // didn't accept gzip). Matches C's `r->gzip_vary = 1;` gating,
        // which happens only after the gzippable checks pass.
        if is_gzippable(&r) && *r.clcf().borrow().gzip_vary {
            add_vary(&r);
        }
        return next(r).await;
    }
    let level = *r.loc_conf::<GzipConf>(ctx_index()).borrow().level;
    let vary = *r.clcf().borrow().gzip_vary;
    r.set_ctx(ctx_index(), GzipCtx::new(level));
    // Content-Encoding: gzip
    let ce = TableElt::new(b"Content-Encoding", b"gzip");
    r.headers_out.borrow_mut().content_encoding = Some(ce);
    // Remove Content-Length — output size unknown
    r.clear_content_length();
    // Weaken ETag
    crate::core_rt::weak_etag(&r);
    // Clear Accept-Ranges: gzipped bodies aren't byte-range-friendly. C nulls
    // r->headers_out.accept_ranges; we also drop any upstream-supplied
    // Accept-Ranges from the generic headers list.
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.accept_ranges = None;
        for h in ho.headers.iter() {
            if h.lowcase_key.eq_ignore_ascii_case(b"accept-ranges") {
                h.hash.set(0);
            }
        }
    }
    r.allow_ranges.set(false);
    if vary {
        add_vary(&r);
    }
    r.buffered.set(r.buffered.get() | NGX_HTTP_GZIP_BUFFERED);
    r.filter_need_in_memory.set(true);
    next(r).await
}

fn add_vary(r: &R) {
    let ho = r.headers_out.borrow_mut();
    let mut have = false;
    for h in ho.headers.iter() {
        if h.key.eq_ignore_ascii_case(b"Vary") {
            have = true;
            let v = h.value.borrow().clone();
            if v.split(|&b| b == b',').any(|p| {
                let p: Vec<u8> = p.iter().copied().filter(|&b| b != b' ').collect();
                p.eq_ignore_ascii_case(b"Accept-Encoding")
            }) {
                return;
            }
            let mut nv = v;
            if !nv.is_empty() { nv.extend_from_slice(b", "); }
            nv.extend_from_slice(b"Accept-Encoding");
            h.set_value(&nv);
            return;
        }
    }
    drop(ho);
    if !have {
        let h = TableElt::new(b"Vary", b"Accept-Encoding");
        r.headers_out.borrow_mut().headers.push(h);
    }
}

async fn gzip_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx_opt = r.get_ctx::<GzipCtx>(ctx_index());
    let ctx = match ctx_opt {
        Some(c) => c,
        None => return next(r, input).await,
    };
    let mut out = Chain::new();
    let mut has_last = false;
    // Read file bufs into memory
    let materialized: Vec<Vec<u8>> = match materialize(input.clone()).await {
        Ok(v) => v,
        Err(rc) => return rc,
    };
    for b in input.iter() {
        if b.last_buf { has_last = true; }
    }
    // Emit gzip header once
    {
        let mut c = ctx.borrow_mut();
        if !c.header_sent {
            // 10-byte gzip header: id1=0x1f id2=0x8b, CM=8 (deflate), FLG=0, MTIME=0, XFL=0, OS=3 (Unix)
            static GZIP_HEADER: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
            out.push_back(Buf::from_vec(GZIP_HEADER.to_vec()));
            c.header_sent = true;
        }
    }
    // Compress each memory chunk
    for chunk in &materialized {
        if chunk.is_empty() { continue; }
        {
            let mut c = ctx.borrow_mut();
            c.crc32.update(chunk);
            c.isize = c.isize.wrapping_add(chunk.len() as u32);
        }
        let mut compressed = Vec::with_capacity(chunk.len() + 64);
        let mut input_pos = 0usize;
        loop {
            let mut buf = [0u8; 4096];
            let before_in;
            let before_out;
            {
                let c = ctx.borrow();
                before_in = c.compress.total_in();
                before_out = c.compress.total_out();
            }
            let flush = if input_pos >= chunk.len() { FlushCompress::None } else { FlushCompress::None };
            let status = {
                let mut c = ctx.borrow_mut();
                c.compress.compress(&chunk[input_pos..], &mut buf, flush).unwrap_or(Status::Ok)
            };
            let after_in;
            let after_out;
            {
                let c = ctx.borrow();
                after_in = c.compress.total_in();
                after_out = c.compress.total_out();
            }
            let consumed = (after_in - before_in) as usize;
            let produced = (after_out - before_out) as usize;
            input_pos += consumed;
            if produced > 0 {
                compressed.extend_from_slice(&buf[..produced]);
            }
            if input_pos >= chunk.len() && matches!(status, Status::Ok) && produced == 0 {
                break;
            }
            if input_pos >= chunk.len() && produced < buf.len() {
                break;
            }
            if matches!(status, Status::StreamEnd) { break; }
        }
        if !compressed.is_empty() {
            out.push_back(Buf::from_vec(compressed));
        }
    }
    if has_last {
        // Finish deflate stream
        let mut tail = Vec::new();
        loop {
            let mut buf = [0u8; 4096];
            let before_out;
            {
                let c = ctx.borrow();
                before_out = c.compress.total_out();
            }
            let status = {
                let mut c = ctx.borrow_mut();
                c.compress.compress(&[], &mut buf, FlushCompress::Finish).unwrap_or(Status::Ok)
            };
            let after_out;
            {
                let c = ctx.borrow();
                after_out = c.compress.total_out();
            }
            let produced = (after_out - before_out) as usize;
            if produced > 0 {
                tail.extend_from_slice(&buf[..produced]);
            }
            if matches!(status, Status::StreamEnd) { break; }
            if produced == 0 { break; }
        }
        // Append gzip trailer: CRC32 (LE) + ISIZE (LE)
        let (crc, isize) = {
            let mut c = ctx.borrow_mut();
            c.done = true;
            // ngx_http_gzip_filter_deflate_end
            c.zin = c.compress.total_in() as usize;
            c.zout = c.compress.total_out() as usize + 10 + 8;
            (c.crc32.clone().finalize(), c.isize)
        };
        tail.extend_from_slice(&crc.to_le_bytes());
        tail.extend_from_slice(&isize.to_le_bytes());
        let mut last = Buf::from_vec(tail);
        last.last_buf = true;
        last.flush = true;
        out.push_back(last);
        r.buffered.set(r.buffered.get() & !NGX_HTTP_GZIP_BUFFERED);
    }
    if out.is_empty() { return NGX_OK; }
    next(r, out).await
}

/// Read file bufs into memory (via pread) and collect all in-memory chunks.
async fn materialize(chain: Chain) -> Result<Vec<Vec<u8>>, i64> {
    let mut out = Vec::new();
    for b in chain.iter() {
        if b.buf_size() == 0 { continue; }
        match &b.data {
            BufData::Memory(v) => {
                let sz = (b.last - b.pos).min(v.len().saturating_sub(b.pos));
                if sz > 0 { out.push(v[b.pos..b.pos + sz].to_vec()); }
            }
            BufData::File(file) => {
                let mut buf = vec![0u8; (b.file_last - b.file_pos) as usize];
                let mut off = 0usize;
                while off < buf.len() {
                    let n = unsafe {
                        libc::pread(file.fd,
                            buf[off..].as_mut_ptr() as *mut libc::c_void,
                            buf.len() - off,
                            b.file_pos + off as i64) };
                    if n <= 0 { return Err(NGX_ERROR); }
                    off += n as usize;
                }
                out.push(buf);
            }
            BufData::None => {}
        }
    }
    Ok(out)
}
