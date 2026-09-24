//! ngx_http_gzip_static_module: serves pre-compressed .gz files

use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::request::{Request, R, TableElt};
use crate::static_module::open_file_info;
use crate::*;

crate::http_module_index!("ngx_http_gzip_static_module");

const NGX_HTTP_GZIP_STATIC_OFF: usize = 0;
const NGX_HTTP_GZIP_STATIC_ON: usize = 1;
const NGX_HTTP_GZIP_STATIC_ALWAYS: usize = 2;

pub struct GzipStaticConf {
    pub enable: Val<usize>,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn std::any::Any> {
    make_slot(GzipStaticConf {
        enable: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn std::any::Any>, conf: &Rc<dyn std::any::Any>) -> ConfResult {
    let p = conf_cell::<GzipStaticConf>(prev).borrow();
    let mut c = conf_cell::<GzipStaticConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, NGX_HTTP_GZIP_STATIC_OFF);
    Ok(())
}

fn gzip_static_directive(
    cf: &mut Conf,
    _cmd: &Command,
    _slot: Option<Rc<dyn std::any::Any>>,
) -> ConfResult {
    let args = cf.args();
    if args.len() < 2 {
        return Err(msg("no value"));
    }

    let value = match std::str::from_utf8(&args[1]) {
        Ok("off") => NGX_HTTP_GZIP_STATIC_OFF,
        Ok("on") => NGX_HTTP_GZIP_STATIC_ON,
        Ok("always") => NGX_HTTP_GZIP_STATIC_ALWAYS,
        _ => return Err(msg("must be \"off\", \"on\", or \"always\"")),
    };

    let slot = conf_cell::<GzipStaticConf>(&cf.ctx.loc.as_ref().unwrap().borrow()[ctx_index()].as_ref().unwrap());
    slot.borrow_mut().enable = Val::set(value);
    Ok(())
}

pub fn gzip_static_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![ngx_core::cmd_fn!(
        "gzip_static",
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ConfLevel::Loc,
        gzip_static_directive
    )];
    http_module_def("ngx_http_gzip_static_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(gzip_static_handler(r))))?;
    Ok(())
}

async fn gzip_static_handler(r: R) -> i64 {
    if r.method.get() != NGX_HTTP_GET && r.method.get() != NGX_HTTP_HEAD {
        return NGX_DECLINED;
    }

    if r.uri.borrow().last() == Some(&b'/') {
        return NGX_DECLINED;
    }

    let conf = r.loc_conf::<GzipStaticConf>(ctx_index());
    let enable = *conf.borrow().enable;

    if enable == NGX_HTTP_GZIP_STATIC_OFF {
        return NGX_DECLINED;
    }

    let gzip_ok_result = if enable == NGX_HTTP_GZIP_STATIC_ON {
        crate::core_rt::gzip_ok(&r)
    } else {
        // always
        NGX_OK
    };

    let clcf = r.clcf();

    if !*clcf.borrow().gzip_vary && gzip_ok_result != NGX_OK {
        return NGX_DECLINED;
    }

    let log = r.connection.log.clone();

    // Map URI to path with room for ".gz" (3 bytes)
    let (mut path, _root) = match crate::core_rt::map_uri_to_path(&r, 3) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // Append .gz
    path.extend_from_slice(b".gz");

    http_debug!(r, "gzip_static filename: \"{}\"", B(&path));

    let mut of = {
        let c = clcf.borrow();
        open_file_info(&r, &c)
    };

    let cache = clcf.borrow().open_file_cache.get().clone();
    let _handle = match open_cached_file(cache.as_ref(), &path, &mut of, &log) {
        Ok(h) => h,
        Err(()) => {
            match of.err {
                libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG => {
                    return NGX_DECLINED;
                }
                _ => {
                    ngx_log_error!(NGX_LOG_ERR, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&path));
                    return NGX_DECLINED;
                }
            }
        }
    };

    http_debug!(r, "gzip_static fd: {}", of.fd);

    if of.is_dir {
        return NGX_DECLINED;
    }

    if !of.is_file {
        ngx_log_error!(NGX_LOG_CRIT, log, None, "\"{}\" is not a regular file", B(&path));
        return NGX_HTTP_NOT_FOUND;
    }

    r.root_tested.set(!r.error_page.get());

    // Discard request body
    match crate::request_body::discard_request_body(&r).await {
        NGX_OK => {}
        rc => return rc,
    }

    // Set response headers
    let mut ho = r.headers_out.borrow_mut();
    ho.status = NGX_HTTP_OK;
    ho.content_length_n = of.size;
    ho.last_modified_time = of.mtime;

    // Add Content-Encoding: gzip
    ho.content_encoding = Some(TableElt::new(b"Content-Encoding", b"gzip"));
    drop(ho);

    // Set etag
    match crate::core_rt::set_etag(&r) {
        NGX_OK => {}
        rc => return rc,
    }

    // Set content type
    match crate::core_rt::set_content_type(&r) {
        NGX_OK => {}
        rc => return rc,
    }

    r.allow_ranges.set(true);

    // Send header
    match crate::core_rt::send_header(&r).await {
        NGX_ERROR | rc if rc > NGX_OK => return rc,
        _ => {}
    }

    if r.header_only.get() {
        return NGX_OK;
    }

    // Create buffer with file
    let mut buf = Buf::new();
    buf.file_pos = 0;
    buf.file_last = of.size;
    buf.in_file = of.size > 0;
    buf.last_buf = r.is_main();
    buf.last_in_chain = true;
    buf.sync = !buf.last_buf && !buf.in_file;
    buf.data = BufData::File(BufFile {
        fd: of.fd,
        name: path.clone(),
    });

    let mut chain = Chain::new();
    chain.push_back(buf);

    // Send body
    crate::output::output_filter(&r, chain).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gzip_static_consts() {
        assert_eq!(NGX_HTTP_GZIP_STATIC_OFF, 0);
        assert_eq!(NGX_HTTP_GZIP_STATIC_ON, 1);
        assert_eq!(NGX_HTTP_GZIP_STATIC_ALWAYS, 2);
    }
}
