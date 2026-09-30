//! ngx_http_gzip_static_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::open_cached_file;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd, ngx_log_error};

use crate::core::*;
use crate::request::*;
use crate::static_module::open_file_info;
use crate::*;

crate::http_module_index!("ngx_http_gzip_static_module");

const NGX_HTTP_GZIP_STATIC_OFF: u32 = 0;
const NGX_HTTP_GZIP_STATIC_ON: u32 = 1;
const NGX_HTTP_GZIP_STATIC_ALWAYS: u32 = 2;

/// ngx_http_gzip_static
const NGX_HTTP_GZIP_STATIC: &[(&str, u32)] =
    &[("off", NGX_HTTP_GZIP_STATIC_OFF), ("on", NGX_HTTP_GZIP_STATIC_ON), ("always", NGX_HTTP_GZIP_STATIC_ALWAYS)];

/// ngx_http_gzip_static_conf_t
pub struct GzipStaticConf {
    pub enable: Val<u32>,
}

/// ngx_http_gzip_static_handler
async fn gzip_static_handler(r: R) -> i64 {
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_DECLINED;
    }

    if r.uri.borrow().last() == Some(&b'/') {
        return NGX_DECLINED;
    }

    let enable = *r.loc_conf::<GzipStaticConf>(ctx_index()).borrow().enable;

    if enable == NGX_HTTP_GZIP_STATIC_OFF {
        return NGX_DECLINED;
    }

    let mut rc = if enable == NGX_HTTP_GZIP_STATIC_ON {
        crate::core_rt::gzip_ok(&r)
    } else {
        // always
        NGX_OK
    };

    let clcf = r.clcf();

    if !*clcf.borrow().gzip_vary && rc != NGX_OK {
        return NGX_DECLINED;
    }

    let log = r.connection.log.clone();

    let mut path = match crate::core_rt::map_uri_to_path(&r, b".gz".len()) {
        Some((p, _root)) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    path.extend_from_slice(b".gz");

    http_debug!(r, "http filename: \"{}\"", B(&path));

    let mut of = {
        let c = clcf.borrow();
        open_file_info(&r, &c)
    };

    if crate::core_rt::set_disable_symlinks(&r, &clcf, &path, &mut of) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let cache = clcf.borrow().open_file_cache.get().clone();

    let handle = match open_cached_file(cache.as_ref(), &path, &mut of, &log) {
        Ok(h) => h,
        Err(()) => {
            let level = match of.err {
                0 => return NGX_HTTP_INTERNAL_SERVER_ERROR,

                libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG => return NGX_DECLINED,

                libc::EACCES | libc::EMLINK | libc::ELOOP => NGX_LOG_ERR,

                _ => NGX_LOG_CRIT,
            };

            ngx_log_error!(level, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&path));

            return NGX_DECLINED;
        }
    };

    if enable == NGX_HTTP_GZIP_STATIC_ON {
        r.gzip_vary.set(true);

        if rc != NGX_OK {
            return NGX_DECLINED;
        }
    }

    http_debug!(r, "http static fd: {}", of.fd);

    if of.is_dir {
        http_debug!(r, "http dir");
        return NGX_DECLINED;
    }

    // the not regular files are probably Unix specific

    if !of.is_file {
        ngx_log_error!(NGX_LOG_CRIT, log, None, "\"{}\" is not a regular file", B(&path));

        return NGX_HTTP_NOT_FOUND;
    }

    r.root_tested.set(!r.error_page.get());

    rc = crate::request_body::discard_request_body(&r).await;

    if rc != NGX_OK {
        return rc;
    }

    log.set_action(Some("sending response to client"));

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.content_length_n = of.size;
        ho.last_modified_time = of.mtime;
    }

    if crate::core_rt::set_etag(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if crate::core_rt::set_content_type(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let h = TableElt::new(b"Content-Encoding", b"gzip");

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.headers.push(h.clone());
        ho.content_encoding = Some(h);
    }

    r.allow_ranges.set(true);

    rc = crate::core_rt::send_header(&r).await;

    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return rc;
    }

    let file = Rc::new(BufFile { fd: of.fd, name: path, directio: of.is_directio });

    let mut b = Buf::file(file, 0, of.size);

    b.in_file = b.file_last != 0;
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    b.sync = !(b.last_buf || b.in_file);

    let mut out = Chain::new();
    out.push_back(b);

    let rc = crate::core_rt::output_filter(&r, out).await;

    // the file stays open until the response is sent
    drop(handle);

    rc
}

/// ngx_http_gzip_static_create_conf
fn gzip_static_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(GzipStaticConf { enable: Val::unset() })
}

/// ngx_http_gzip_static_merge_conf
fn gzip_static_merge_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<GzipStaticConf>(parent).borrow();
    let mut conf = conf_cell::<GzipStaticConf>(child).borrow_mut();

    conf.enable.merge(&prev.enable, NGX_HTTP_GZIP_STATIC_OFF);

    Ok(())
}

/// ngx_http_gzip_static_init
fn gzip_static_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(gzip_static_handler(r))));

    Ok(())
}

pub fn gzip_static_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(gzip_static_init),
        create_loc_conf: Some(gzip_static_create_conf),
        merge_loc_conf: Some(gzip_static_merge_conf),
        ..Default::default()
    };

    let commands = vec![cmd!(
        "gzip_static",
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ConfLevel::Loc,
        GzipStaticConf,
        enable,
        set_enum,
        NGX_HTTP_GZIP_STATIC
    )];

    http_module_def("ngx_http_gzip_static_module", def, commands)
}
