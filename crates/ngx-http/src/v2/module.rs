//! ngx_http_v2_module (nginx-c/src/http/v2/ngx_http_v2_module.c)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use super::{NGX_HTTP_V2_MAX_FRAME_SIZE, NGX_HTTP_V2_MAX_WINDOW, NGX_HTTP_V2_STATE_BUFFER_SIZE};
use crate::request::VariableValue;
use crate::*;

crate::http_module_index!("ngx_http_v2_module");

// NGX_MIN_POOL_SIZE and NGX_POOL_ALIGNMENT (ngx_palloc.h): on LP64
// ngx_align(sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t), 16) is 112.
const NGX_MIN_POOL_SIZE: usize = 112;
const NGX_POOL_ALIGNMENT: usize = 16;

pub struct Http2MainConf {
    pub recv_buffer_size: Val<usize>,
}

pub struct Http2SrvConf {
    pub enable: Val<bool>,
    pub pool_size: Val<usize>,
    pub concurrent_streams: Val<i64>,
    pub preread_size: Val<usize>,
    /// Holds `http2_streams_index_size - 1` once parsed, as in C.
    pub streams_index_mask: Val<i64>,
}

pub struct Http2LocConf {
    pub chunk_size: Val<usize>,
}

/// ngx_http_v2_add_variables
fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = [crate::variables::VarDef { name: "http2", set: None, get: Some(variable), data: 0, flags: 0 }];
    crate::variables::add_variables(cf, &vars)
}

/// ngx_http_v2_variable: "h2" or "h2c" on HTTP/2 streams, empty otherwise.
fn variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    v.data = if r.stream.borrow().is_none() {
        Vec::new()
    } else if r.connection.ssl.borrow().is_some() {
        b"h2".to_vec()
    } else {
        b"h2c".to_vec()
    };
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    NGX_OK
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(Http2MainConf { recv_buffer_size: Val::unset() })
}

fn init_main_conf(_cf: &mut Conf, conf: &Rc<dyn Any>) -> ConfResult {
    let mut c = conf_cell::<Http2MainConf>(conf).borrow_mut();
    c.recv_buffer_size.init(256 * 1024);
    Ok(())
}

fn create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(Http2SrvConf {
        enable: Val::unset(),
        pool_size: Val::unset(),
        concurrent_streams: Val::unset(),
        preread_size: Val::unset(),
        streams_index_mask: Val::unset(),
    })
}

fn merge_srv_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<Http2SrvConf>(prev).borrow();
    let mut c = conf_cell::<Http2SrvConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    c.pool_size.merge(&p.pool_size, 4096);
    c.concurrent_streams.merge(&p.concurrent_streams, 128);
    c.preread_size.merge(&p.preread_size, 65536);
    c.streams_index_mask.merge(&p.streams_index_mask, 32 - 1);
    Ok(())
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(Http2LocConf { chunk_size: Val::unset() })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<Http2LocConf>(prev).borrow();
    let mut c = conf_cell::<Http2LocConf>(conf).borrow_mut();
    c.chunk_size.merge(&p.chunk_size, 8 * 1024);
    Ok(())
}

/// ngx_conf_set_size_slot + ngx_http_v2_recv_buffer_size post handler
fn set_recv_buffer_size(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.expect("main conf");
    let mut c = conf_cell::<Http2MainConf>(&conf).borrow_mut();
    set_size(cf, cmd, &mut c.recv_buffer_size)?;
    if *c.recv_buffer_size <= NGX_HTTP_V2_STATE_BUFFER_SIZE {
        return Err(msg("value is too small"));
    }
    Ok(())
}

/// ngx_conf_set_size_slot + ngx_http_v2_pool_size post handler
fn set_pool_size(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.expect("srv conf");
    let mut c = conf_cell::<Http2SrvConf>(&conf).borrow_mut();
    set_size(cf, cmd, &mut c.pool_size)?;
    let v = *c.pool_size;
    if v < NGX_MIN_POOL_SIZE {
        return Err(cf.emerg(format_args!("the pool size must be no less than {}", NGX_MIN_POOL_SIZE)));
    }
    if v % NGX_POOL_ALIGNMENT != 0 {
        return Err(cf.emerg(format_args!("the pool size must be a multiple of {}", NGX_POOL_ALIGNMENT)));
    }
    Ok(())
}

/// ngx_conf_set_size_slot + ngx_http_v2_preread_size post handler
fn set_preread_size(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.expect("srv conf");
    let mut c = conf_cell::<Http2SrvConf>(&conf).borrow_mut();
    set_size(cf, cmd, &mut c.preread_size)?;
    if *c.preread_size > NGX_HTTP_V2_MAX_WINDOW {
        return Err(cf.emerg(format_args!("the maximum body preread buffer size is {}", NGX_HTTP_V2_MAX_WINDOW)));
    }
    Ok(())
}

/// ngx_conf_set_num_slot + ngx_http_v2_streams_index_mask post handler
fn set_streams_index_size(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.expect("srv conf");
    let mut c = conf_cell::<Http2SrvConf>(&conf).borrow_mut();
    set_num(cf, cmd, &mut c.streams_index_mask)?;
    let n = *c.streams_index_mask;
    if n == 0 || n & (n - 1) != 0 {
        return Err(msg("must be a power of two"));
    }
    c.streams_index_mask = Val::set(n - 1);
    Ok(())
}

/// ngx_conf_set_size_slot + ngx_http_v2_chunk_size post handler
fn set_chunk_size(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let conf = conf.expect("loc conf");
    let mut c = conf_cell::<Http2LocConf>(&conf).borrow_mut();
    set_size(cf, cmd, &mut c.chunk_size)?;
    if *c.chunk_size == 0 {
        return Err(cf.emerg(format_args!("the http2 chunk size cannot be zero")));
    }
    if *c.chunk_size > NGX_HTTP_V2_MAX_FRAME_SIZE {
        c.chunk_size = Val::set(NGX_HTTP_V2_MAX_FRAME_SIZE);
    }
    Ok(())
}

/// ngx_http_v2_obsolete. The C command's `post` names the replacing
/// directive (ngx_conf_deprecated_t); here it is looked up by name.
fn obsolete(cf: &mut Conf, cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let new_name = match cmd.name {
        "http2_recv_timeout" => Some("client_header_timeout"),
        "http2_idle_timeout" => Some("keepalive_timeout"),
        "http2_max_requests" => Some("keepalive_requests"),
        "http2_max_field_size" | "http2_max_header_size" => Some("large_client_header_buffers"),
        _ => None,
    };
    match new_name {
        Some(n) => cf.warn(format_args!("the \"{}\" directive is obsolete, use the \"{}\" directive instead", cmd.name, n)),
        None => cf.warn(format_args!("the \"{}\" directive is obsolete, ignored", cmd.name)),
    }
    Ok(())
}

pub fn v2_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        create_main_conf: Some(create_main_conf),
        init_main_conf: Some(init_main_conf),
        create_srv_conf: Some(create_srv_conf),
        merge_srv_conf: Some(merge_srv_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let obsolete_cmd = |name, ty| Command::new(name, ty, ConfLevel::None, obsolete);
    let commands = vec![
        ngx_core::cmd!("http2", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, Http2SrvConf, enable, set_flag),
        Command::new("http2_recv_buffer_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, set_recv_buffer_size),
        Command::new("http2_pool_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_pool_size),
        ngx_core::cmd!("http2_max_concurrent_streams", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, Http2SrvConf, concurrent_streams, set_num),
        obsolete_cmd("http2_max_concurrent_pushes", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1),
        obsolete_cmd("http2_max_requests", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1),
        obsolete_cmd("http2_max_field_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1),
        obsolete_cmd("http2_max_header_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1),
        Command::new("http2_body_preread_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_preread_size),
        Command::new("http2_streams_index_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_streams_index_size),
        obsolete_cmd("http2_recv_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1),
        obsolete_cmd("http2_idle_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1),
        Command::new("http2_chunk_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_chunk_size),
        obsolete_cmd("http2_push_preload", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG),
        obsolete_cmd("http2_push", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1),
    ];
    http_module_def("ngx_http_v2_module", def, commands)
}
