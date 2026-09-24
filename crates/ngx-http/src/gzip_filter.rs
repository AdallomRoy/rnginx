//! ngx_http_gzip_filter_module: compresses HTTP response body with gzip

use flate2::Compression;
use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::request::{Request, R, TableElt};
use crate::variables::{add_variables, VarDef, VariableValue};
use crate::*;

crate::http_module_index!("ngx_http_gzip_filter_module");

pub struct GzipConf {
    pub enable: Val<bool>,
    pub no_buffer: Val<bool>,
    pub bufs: Bufs,
    pub postpone_gzipping: Val<usize>,
    pub level: Val<i32>,
    pub wbits: Val<usize>,
    pub memlevel: Val<usize>,
    pub min_length: Val<usize>,
}

pub struct GzipCtx {
    pub encoder: Option<flate2::write::GzEncoder<Vec<u8>>>,
    pub buffering: bool,
    pub done: bool,
    pub in_buf: Option<Buf>,
    pub buffered: Chain,
    pub zin: usize,
    pub zout: usize,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn std::any::Any> {
    make_slot(GzipConf {
        enable: Val::unset(),
        no_buffer: Val::unset(),
        bufs: Bufs::default(),
        postpone_gzipping: Val::unset(),
        level: Val::unset(),
        wbits: Val::unset(),
        memlevel: Val::unset(),
        min_length: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn std::any::Any>, conf: &Rc<dyn std::any::Any>) -> ConfResult {
    let p = conf_cell::<GzipConf>(prev).borrow();
    let mut c = conf_cell::<GzipConf>(conf).borrow_mut();

    c.enable.merge(&p.enable, false);
    c.no_buffer.merge(&p.no_buffer, false);
    c.bufs.merge(&p.bufs, (128 * 1024) / 4096, 4096);
    c.postpone_gzipping.merge(&p.postpone_gzipping, 0);
    c.level.merge(&p.level, 1);
    c.wbits.merge(&p.wbits, 15); // MAX_WBITS
    c.memlevel.merge(&p.memlevel, 8); // MAX_MEM_LEVEL - 1
    c.min_length.merge(&p.min_length, 20);

    Ok(())
}

fn add_vars(cf: &mut Conf) -> ConfResult {
    add_variables(cf, &[VarDef {
        name: b"gzip_ratio".to_vec(),
        get_handler: gzip_ratio_variable,
    }])
}

fn gzip_ratio_variable(r: &R, var: &mut VariableValue, _data: usize) -> i64 {
    let ctx = r.get_ctx::<GzipCtx>(ctx_index());
    if ctx.is_none() || ctx.as_ref().unwrap().zout == 0 {
        var.not_found = true;
        return NGX_OK;
    }

    let ctx = ctx.unwrap();
    let zint = ctx.zin / ctx.zout;
    let mut zfrac = (ctx.zin * 100 / ctx.zout) % 100;

    if (ctx.zin * 1000 / ctx.zout) % 10 > 4 {
        zfrac += 1;
        if zfrac > 99 {
            // rounding case, would increment zint but we just set frac to 0
            zfrac = 0;
        }
    }

    let s = format!("{}.{:02}", zint, zfrac);
    var.data = s.into_bytes();
    var.len = var.data.len();
    var.valid = true;
    var.no_cacheable = false;
    var.not_found = false;

    NGX_OK
}

pub fn gzip_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_vars),
        postconfiguration: Some(init),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!(
            "gzip",
            NGX_HTTP_MAIN_CONF
                | NGX_HTTP_SRV_CONF
                | NGX_HTTP_LOC_CONF
                | NGX_HTTP_LIF_CONF
                | NGX_CONF_FLAG,
            ConfLevel::Loc,
            GzipConf,
            enable,
            set_flag
        ),
        ngx_core::cmd!(
            "gzip_buffers",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
            ConfLevel::Loc,
            GzipConf,
            bufs,
            set_bufs
        ),
        ngx_core::cmd!(
            "gzip_comp_level",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            GzipConf,
            level,
            set_num
        ),
        ngx_core::cmd_fn!(
            "gzip_window",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            gzip_window_handler
        ),
        ngx_core::cmd_fn!(
            "gzip_hash",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            gzip_hash_handler
        ),
        ngx_core::cmd!(
            "gzip_min_length",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            GzipConf,
            min_length,
            set_size
        ),
        ngx_core::cmd!(
            "gzip_no_buffer",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
            ConfLevel::Loc,
            GzipConf,
            no_buffer,
            set_flag
        ),
        ngx_core::cmd!(
            "postpone_gzipping",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            GzipConf,
            postpone_gzipping,
            set_size
        ),
    ];
    http_module_def("ngx_http_gzip_filter_module", def, commands)
}

fn gzip_window_handler(cf: &mut Conf, _cmd: &Command, _slot: Option<Rc<dyn std::any::Any>>) -> ConfResult {
    let args = cf.args();
    if args.len() < 2 {
        return Err(msg("no value"));
    }

    let size_str = std::str::from_utf8(&args[1]).unwrap_or("0");
    let size: usize = size_str.parse().unwrap_or(0);

    let wbits = match size {
        512 => 9,
        1024 => 10,
        2048 => 11,
        4096 => 12,
        8192 => 13,
        16384 => 14,
        32768 => 15,
        _ => return Err(msg("must be 512, 1k, 2k, 4k, 8k, 16k, or 32k")),
    };

    let slot = conf_cell::<GzipConf>(&cf.ctx.loc.as_ref().unwrap().borrow()[ctx_index()].as_ref().unwrap());
    slot.borrow_mut().wbits = Val::set(wbits);
    Ok(())
}

fn gzip_hash_handler(cf: &mut Conf, _cmd: &Command, _slot: Option<Rc<dyn std::any::Any>>) -> ConfResult {
    let args = cf.args();
    if args.len() < 2 {
        return Err(msg("no value"));
    }

    let size_str = std::str::from_utf8(&args[1]).unwrap_or("0");
    let size: usize = size_str.parse().unwrap_or(0);

    let memlevel = match size {
        512 => 1,
        1024 => 2,
        2048 => 3,
        4096 => 4,
        8192 => 5,
        16384 => 6,
        32768 => 7,
        65536 => 8,
        131072 => 9,
        _ => return Err(msg("must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k")),
    };

    let slot = conf_cell::<GzipConf>(&cf.ctx.loc.as_ref().unwrap().borrow()[ctx_index()].as_ref().unwrap());
    slot.borrow_mut().memlevel = Val::set(memlevel);
    Ok(())
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { gzip_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { gzip_body_filter(r, chain, next).await });
    Ok(())
}

async fn gzip_header_filter(r: R, next: HeaderFilter) -> i64 {
    let conf = r.loc_conf::<GzipConf>(ctx_index());
    let conf_borrow = conf.borrow();

    if !*conf_borrow.enable {
        return next(r).await;
    }

    let status = r.headers_out.borrow().status;
    if status != NGX_HTTP_OK
        && status != NGX_HTTP_FORBIDDEN
        && status != NGX_HTTP_NOT_FOUND
    {
        return next(r).await;
    }

    let ho = r.headers_out.borrow();
    if ho.content_encoding.is_some() {
        drop(ho);
        return next(r).await;
    }

    let cl = ho.content_length_n;
    drop(ho);

    if cl >= 0 && (cl as usize) < *conf_borrow.min_length {
        return next(r).await;
    }

    if r.header_only.get() {
        return next(r).await;
    }

    r.gzip_vary.set(true);

    if !r.gzip_tested.get() {
        match crate::core_rt::gzip_ok(&r) {
            NGX_OK => {}
            _ => return next(r).await,
        }
    } else if !r.gzip_ok.get() {
        return next(r).await;
    }

    let ctx = GzipCtx {
        encoder: None,
        buffering: *conf_borrow.postpone_gzipping != 0,
        done: false,
        in_buf: None,
        buffered: Chain::new(),
        zin: 0,
        zout: 0,
    };

    r.set_ctx(ctx_index(), ctx);
    r.main_filter_need_in_memory.set(true);

    let mut ho = r.headers_out.borrow_mut();
    ho.content_encoding = Some(TableElt::new(b"Content-Encoding", b"gzip"));

    drop(ho);
    r.clear_content_length();
    r.clear_accept_ranges();
    crate::core_rt::weak_etag(&r);

    drop(ho);
    drop(conf_borrow);

    next(r).await
}

async fn gzip_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx_opt = r.get_ctx::<GzipCtx>(ctx_index());

    if ctx_opt.is_none() || r.header_only.get() {
        return next(r, input).await;
    }

    let mut ctx = ctx_opt.unwrap();

    if ctx.done {
        return next(r, input).await;
    }

    let conf = r.loc_conf::<GzipConf>(ctx_index());
    let conf_borrow = conf.borrow();

    // Handle buffering phase
    if ctx.buffering && !input.is_empty() {
        let mut buffered_size = 0;
        for buf in ctx.buffered.iter() {
            buffered_size += buf.buf_size() as usize;
        }

        for buf in input.iter() {
            let size = buf.buf_size() as usize;
            buffered_size += size;

            if buf.last_buf || buf.flush {
                ctx.buffering = false;
                break;
            }

            if buffered_size > *conf_borrow.postpone_gzipping {
                ctx.buffering = false;
                break;
            }
        }

        if ctx.buffering {
            // Copy input to buffered chain
            for b in input.iter() {
                let size = b.buf_size() as usize;
                let mut vec = vec![0u8; size];
                vec.copy_from_slice(&b.data_ref()[..size]);
                let mut new_buf = Buf::from_vec(vec);
                new_buf.last_buf = b.last_buf;
                ctx.buffered.push_back(new_buf);
            }
            r.set_ctx(ctx_index(), ctx);
            return NGX_OK;
        }
    }

    // Initialize encoder if needed
    if ctx.encoder.is_none() {
        let level = match *conf_borrow.level {
            9 => Compression::best(),
            1 => Compression::fast(),
            n => Compression::new(n as u32),
        };

        ctx.encoder = Some(flate2::write::GzEncoder::new(Vec::new(), level));
        ctx.zin = 0;
        ctx.zout = 0;
    }

    let mut encoder = ctx.encoder.take().unwrap();
    let mut output = Chain::new();

    // Process buffered data first
    if !ctx.buffered.is_empty() {
        for buf in ctx.buffered.iter() {
            if encoder.write_all(&buf.data_ref()[..buf.buf_size() as usize]).is_err() {
                return NGX_ERROR;
            }
            ctx.zin += buf.buf_size() as usize;
        }
        ctx.buffered = Chain::new();
    }

    // Process input data
    for buf in input.iter() {
        if encoder.write_all(&buf.data_ref()[..buf.buf_size() as usize]).is_err() {
            return NGX_ERROR;
        }
        ctx.zin += buf.buf_size() as usize;
    }

    // Check if we're at the end
    let is_last = input.iter().any(|b| b.last_buf);

    if is_last {
        if encoder.finish().is_err() {
            return NGX_ERROR;
        }

        let compressed = encoder.into_inner().unwrap_or_default();
        ctx.zout = compressed.len();

        if !compressed.is_empty() {
            output.push_back(Buf::from_vec(compressed));
        }

        if let Some(last_buf) = output.back_mut() {
            last_buf.last_buf = true;
        } else {
            let mut b = Buf::special();
            b.last_buf = true;
            output.push_back(b);
        }

        ctx.done = true;
    } else {
        // Intermediate flush - get compressed data
        let data = encoder.get_ref().clone();
        if !data.is_empty() {
            encoder.get_mut().clear();
            output.push_back(Buf::from_vec(data));
            ctx.zout = ctx.zout + output.back().unwrap().buf_size() as usize;
        }
    }

    ctx.encoder = Some(encoder);
    r.set_ctx(ctx_index(), ctx);

    if output.is_empty() {
        return NGX_OK;
    }

    next(r, output).await
}
