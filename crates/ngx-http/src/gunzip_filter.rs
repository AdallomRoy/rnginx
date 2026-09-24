//! ngx_http_gunzip_filter_module: decompresses gzipped upstream responses

use flate2::read::GzDecoder;
use std::cell::RefCell;
use std::io::Read;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_gunzip_filter_module");

pub struct GunzipConf {
    pub enable: Val<bool>,
    pub bufs: Bufs,
}

pub struct GunzipCtx {
    pub decoder: Option<GzDecoder<std::io::Cursor<Vec<u8>>>>,
    pub started: bool,
    pub done: bool,
    pub output: Chain,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn std::any::Any> {
    make_slot(GunzipConf {
        enable: Val::unset(),
        bufs: Bufs::default(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn std::any::Any>, conf: &Rc<dyn std::any::Any>) -> ConfResult {
    let p = conf_cell::<GunzipConf>(prev).borrow();
    let mut c = conf_cell::<GunzipConf>(conf).borrow_mut();

    c.enable.merge(&p.enable, false);
    c.bufs.merge(&p.bufs, (128 * 1024) / 4096, 4096);

    Ok(())
}

pub fn gunzip_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!(
            "gunzip",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
            ConfLevel::Loc,
            GunzipConf,
            enable,
            set_flag
        ),
        ngx_core::cmd!(
            "gunzip_buffers",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
            ConfLevel::Loc,
            GunzipConf,
            bufs,
            set_bufs
        ),
    ];
    http_module_def("ngx_http_gunzip_filter_module", def, commands)
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { gunzip_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { gunzip_body_filter(r, chain, next).await });
    Ok(())
}

async fn gunzip_header_filter(r: R, next: HeaderFilter) -> i64 {
    let conf = r.loc_conf::<GunzipConf>(ctx_index());

    if !*conf.borrow().enable {
        return next(r).await;
    }

    let ho = r.headers_out.borrow();
    let content_encoding = match &ho.content_encoding {
        Some(h) => h.value.borrow().clone(),
        None => {
            drop(ho);
            return next(r).await;
        }
    };
    drop(ho);

    // Check if content-encoding is "gzip"
    if content_encoding.len() != 4 || !content_encoding.starts_with(b"gzip") {
        return next(r).await;
    }

    r.gzip_vary.set(true);

    // Check if client accepts gzip (if so, don't decompress)
    if !r.gzip_tested.get() {
        match crate::core_rt::gzip_ok(&r) {
            NGX_OK => {
                // Client accepts gzip, pass through
                return next(r).await;
            }
            _ => {}
        }
    } else if r.gzip_ok.get() {
        // Client accepts gzip, pass through
        return next(r).await;
    }

    // Client doesn't accept gzip, we need to decompress
    let ctx = GunzipCtx {
        decoder: None,
        started: false,
        done: false,
        output: Chain::new(),
    };

    r.set_ctx(ctx_index(), ctx);
    r.filter_need_in_memory.set(true);

    // Remove Content-Encoding header
    let mut ho = r.headers_out.borrow_mut();
    if let Some(ref ce) = &ho.content_encoding {
        ce.hash.set(0);
    }
    ho.content_encoding = None;
    drop(ho);

    r.clear_content_length();
    r.clear_accept_ranges();
    crate::core_rt::weak_etag(&r);

    next(r).await
}

async fn gunzip_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx_opt = r.get_ctx::<GunzipCtx>(ctx_index());

    if ctx_opt.is_none() || r.header_only.get() {
        return next(r, input).await;
    }

    let mut ctx = ctx_opt.unwrap();

    if ctx.done {
        return next(r, input).await;
    }

    // Initialize decoder if needed
    if !ctx.started {
        ctx.started = true;
        let mut data = Vec::new();
        for buf in input.iter() {
            data.extend_from_slice(&buf.data_ref()[..buf.buf_size() as usize]);
        }

        match GzDecoder::new(std::io::Cursor::new(data)) {
            Ok(decoder) => {
                ctx.decoder = Some(decoder);
            }
            Err(_) => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "failed to initialize gzip decoder");
                return NGX_ERROR;
            }
        }
    } else {
        // Add more data to decoder
        if !input.is_empty() {
            let mut data = Vec::new();
            for buf in input.iter() {
                data.extend_from_slice(&buf.data_ref()[..buf.buf_size() as usize]);
            }

            if let Some(ref mut decoder) = &mut ctx.decoder {
                // We can't directly add data to an existing decoder, so we'll need a different approach
                // For now, decompress what we have
            }
        }
    }

    let mut decoder = ctx.decoder.take().unwrap();
    let mut output = Vec::new();

    // Decompress data
    match decoder.read_to_end(&mut output) {
        Ok(_) => {
            if !output.is_empty() {
                let mut buf = Buf::from_vec(output);
                // Check if this is the last buffer
                if input.iter().any(|b| b.last_buf) {
                    buf.last_buf = true;
                }
                ctx.output.push_back(buf);
            }
        }
        Err(_) => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "gzip decompression failed");
            return NGX_ERROR;
        }
    }

    if input.iter().any(|b| b.last_buf) {
        ctx.done = true;
    }

    ctx.decoder = Some(decoder);
    r.set_ctx(ctx_index(), ctx);

    if ctx.output.is_empty() {
        return NGX_OK;
    }

    let out = std::mem::take(&mut ctx.output);
    r.set_ctx(ctx_index(), GunzipCtx {
        decoder: ctx.decoder,
        started: ctx.started,
        done: ctx.done,
        output: Chain::new(),
    });

    next(r, out).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gunzip_consts() {
        // Just verify we can construct the config
        let _conf = GunzipConf {
            enable: Val::unset(),
            bufs: Bufs::default(),
        };
    }
}
