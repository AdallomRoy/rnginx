//! ngx_http_gunzip_filter_module: decompress gzipped upstream responses when
//! the client doesn't accept gzip encoding. Matches
//! ngx_http_gunzip_filter_module.c: header filter clears Content-Encoding /
//! Content-Length when engaging; body filter feeds each chunk through
//! flate2's gzip Decompress and emits plain bytes.

use std::any::Any;
use std::rc::Rc;

use flate2::{Decompress, FlushDecompress, Status};

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request::TableElt;
use crate::*;

crate::http_module_index!("ngx_http_gunzip_filter_module");

pub struct GunzipConf {
    pub enable: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(GunzipConf { enable: Val::unset() })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<GunzipConf>(prev).borrow();
    let mut c = conf_cell::<GunzipConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    Ok(())
}

pub fn gunzip_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!("gunzip", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, GunzipConf, enable, set_flag),
        ngx_core::cmd_fn!("gunzip_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
    ];
    http_module_def("ngx_http_gunzip_filter_module", def, commands)
}

struct GunzipCtx {
    decoder: Decompress,
    done: bool,
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::install_header_filter(|r, next| async move { gunzip_header_filter(r, next).await });
    crate::install_body_filter(|r, input, next| async move { gunzip_body_filter(r, input, next).await });
    Ok(())
}

async fn gunzip_header_filter(r: R, next: crate::HeaderFilter) -> i64 {
    if !r.is_main() {
        return next(r).await;
    }
    let conf = r.loc_conf::<GunzipConf>(ctx_index());
    if !*conf.borrow().enable {
        return next(r).await;
    }
    // Only engage if the response is gzipped.
    let is_gzip = {
        let ho = r.headers_out.borrow();
        ho.content_encoding.as_ref()
            .map(|h| h.value.borrow().eq_ignore_ascii_case(b"gzip"))
            .unwrap_or(false)
    };
    if !is_gzip {
        return next(r).await;
    }
    // Client accepts gzip → don't decompress (pass through).
    if crate::core_rt::gzip_ok(&r) == NGX_OK {
        return next(r).await;
    }
    // gzip-only decoder: window_bits=15 with new_gzip selects gzip framing.
    let decoder = Decompress::new_gzip(15);
    r.set_ctx(ctx_index(), GunzipCtx { decoder, done: false });
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.content_encoding = None;
        for h in ho.headers.iter() {
            if h.lowcase_key.eq_ignore_ascii_case(b"content-encoding") {
                h.hash.set(0);
            }
        }
        ho.content_length = None;
        ho.content_length_n = -1;
        // Vary: Accept-Encoding — the response body varies based on whether
        // the upstream sent gzip that we then decoded.
        let have_vary = ho.headers.iter().any(|h|
            h.hash.get() != 0 && h.lowcase_key.eq_ignore_ascii_case(b"vary")
                && h.value.borrow().eq_ignore_ascii_case(b"Accept-Encoding"));
        if !have_vary {
            let h = TableElt::new(b"Vary", b"Accept-Encoding");
            ho.headers.push(h);
        }
    }
    r.filter_need_in_memory.set(true);
    next(r).await
}

async fn gunzip_body_filter(r: R, input: Chain, next: crate::BodyFilter) -> i64 {
    let ctx_opt = r.get_ctx::<GunzipCtx>(ctx_index());
    let ctx = match ctx_opt { Some(c) => c, None => return next(r, input).await };

    let mut output = Chain::new();
    let mut last_buf = false;
    let mut last_in_chain = false;
    for buf in input.iter() {
        if buf.last_buf { last_buf = true; }
        if buf.last_in_chain { last_in_chain = true; }
        let data = match &buf.data {
            BufData::Memory(v) => v[buf.pos..buf.last].to_vec(),
            _ => { output.push_back(buf.clone()); continue; }
        };
        // Feed input to the decoder; may need multiple output buffers.
        let mut in_pos = 0usize;
        loop {
            let mut out = vec![0u8; 8192];
            let before_in = ctx.borrow().decoder.total_in();
            let before_out = ctx.borrow().decoder.total_out();
            let status = {
                let mut c = ctx.borrow_mut();
                c.decoder.decompress(&data[in_pos..], &mut out, FlushDecompress::None)
            };
            let consumed = (ctx.borrow().decoder.total_in() - before_in) as usize;
            let produced = (ctx.borrow().decoder.total_out() - before_out) as usize;
            in_pos += consumed;
            if produced > 0 {
                out.truncate(produced);
                let mut b = Buf::from_vec(out);
                b.last_buf = false;
                b.last_in_chain = false;
                output.push_back(b);
            }
            match status {
                Ok(Status::StreamEnd) => { ctx.borrow_mut().done = true; break; }
                Ok(Status::BufError) | Ok(Status::Ok) => {
                    if consumed == 0 && produced == 0 { break; }
                    if in_pos >= data.len() { break; }
                }
                Err(_) => { break; }
            }
        }
    }
    if last_buf || last_in_chain {
        if let Some(back) = output.back_mut() {
            back.last_buf = last_buf;
            back.last_in_chain = last_in_chain;
        } else {
            let mut b = Buf::from_vec(Vec::new());
            b.sync = true;
            b.last_buf = last_buf;
            b.last_in_chain = last_in_chain;
            output.push_back(b);
        }
    }
    next(r, output).await
}
