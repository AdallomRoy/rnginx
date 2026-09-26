//! ngx_http_gzip_static_module — content handler that serves a sibling `.gz` file when the
//! client accepts gzip. `off` (default), `on`, or `always`.

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::open_cached_file;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::static_module::open_file_info;
use crate::*;

crate::http_module_index!("ngx_http_gzip_static_module");

pub struct GzipStaticConf {
    pub enable: Val<u32>, // 0=off, 1=on, 2=always
}

impl Default for GzipStaticConf {
    fn default() -> Self { GzipStaticConf { enable: Val::unset() } }
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> { make_slot(GzipStaticConf::default()) }
fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<GzipStaticConf>(prev).borrow();
    let mut c = conf_cell::<GzipStaticConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, 0);
    Ok(())
}
fn set_gzip_static(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<GzipStaticConf>(conf.as_ref().unwrap());
    let v = match cf.args[1].as_slice() {
        b"off" => 0u32, b"on" => 1, b"always" => 2,
        _ => return Err(msg("invalid value")),
    };
    cell.borrow_mut().enable = Val::set(v);
    Ok(())
}

pub fn gzip_static_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(|cf| { add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(handler(r)))); Ok(()) }),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("gzip_static", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_gzip_static),
    ];
    http_module_def("ngx_http_gzip_static_module", def, commands)
}

async fn handler(r: R) -> i64 {
    let conf = r.loc_conf::<GzipStaticConf>(ctx_index());
    let mode = *conf.borrow().enable;
    if mode == 0 { return NGX_DECLINED; }
    if !(r.method.get() == NGX_HTTP_GET || r.method.get() == NGX_HTTP_HEAD) { return NGX_DECLINED; }
    if r.uri.borrow().last() == Some(&b'/') { return NGX_DECLINED; }
    let accept_gzip = crate::core_rt::gzip_ok(&r) == NGX_OK;
    if mode == 1 && !accept_gzip { return NGX_DECLINED; }

    let (mut path, _rl) = match crate::core_rt::map_uri_to_path(&r, 4) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    path.extend_from_slice(b".gz");
    let log = r.connection.log.clone();
    let clcf = r.clcf();
    let mut of = { let c = clcf.borrow(); open_file_info(&r, &c) };
    let cache = clcf.borrow().open_file_cache.get().clone();
    let handle = match open_cached_file(cache.as_ref(), &path, &mut of, &log) {
        Ok(h) => h,
        Err(_) => return NGX_DECLINED,
    };
    let _ = handle;
    if !of.is_file { return NGX_DECLINED; }

    let rc = crate::request_body::discard_request_body(&r).await;
    if rc != NGX_OK { return rc; }
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.content_length_n = of.size;
        ho.last_modified_time = of.mtime;
    }
    // Derive Content-Type from the ORIGINAL uri extension (not `.gz`); charset_filter
    // will layer on the configured charset if applicable.
    crate::core_rt::set_content_type(&r);
    // We're serving a .gz file. Always set Content-Encoding: gzip — even in
    // `always` mode where the client didn't advertise gzip, since gunzip
    // filter may still decompress downstream. Matches C's
    // ngx_http_gzip_static_handler which sets the header unconditionally.
    let h = TableElt::new(b"Content-Encoding", b"gzip");
    r.headers_out.borrow_mut().content_encoding = Some(h);
    let _ = accept_gzip;
    r.allow_ranges.set(true);
    let rc = crate::core_rt::send_header(&r).await;
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() { return rc; }
    let file = Rc::new(BufFile { fd: of.fd, name: path.clone(), directio: of.is_directio });
    let mut b = Buf::file(file, 0, of.size);
    b.in_file = true;
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    let mut chain = Chain::new();
    chain.push_back(b);
    ngx_log_error!(NGX_LOG_DEBUG, log, None, "gzip_static: serving \"{}\"", B(&path));
    crate::core_rt::output_filter(&r, chain).await
}
