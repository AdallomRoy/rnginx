//! Placeholders for modules not yet ported: they register their directives so that
//! configurations parse, and provide hooks used by the core.

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::module::ModuleDef;

use crate::core::*;
use crate::request::*;
use crate::*;

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn temp_path_module(name: &'static str, directive: &'static str) -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![
        Command::new(directive, NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::None, |cf, cmd, _conf| {
            let mut slot: Val<Rc<PathConf>> = Val::unset();
            set_path(cf, cmd, &mut slot)
        }),
    ];
    http_module_def(name, def, commands)
}

fn simple_directive_module(name: &'static str, directive: &'static str, flags: u32, args: u32) -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![
        Command::new(directive, flags | args, ConfLevel::None, accept),
    ];
    http_module_def(name, def, commands)
}

pub fn early_modules() -> Vec<ModuleDef> {
    vec![]
}

pub fn handler_modules_a() -> Vec<ModuleDef> {
    vec![]
}

pub fn handler_modules_b() -> Vec<ModuleDef> {
    vec![]
}

pub fn handler_modules_c() -> Vec<ModuleDef> {
    vec![]
}

pub fn handler_modules_d() -> Vec<ModuleDef> {
    vec![
        simple_directive_module("ngx_http_proxy_module", "proxy_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF, NGX_CONF_TAKE1),
        temp_path_module("ngx_http_proxy_module", "proxy_temp_path"),
        temp_path_module("ngx_http_fastcgi_module", "fastcgi_temp_path"),
        temp_path_module("ngx_http_uwsgi_module", "uwsgi_temp_path"),
        temp_path_module("ngx_http_scgi_module", "scgi_temp_path"),
        simple_directive_module("ngx_http_limit_req_module", "limit_req_zone", NGX_HTTP_MAIN_CONF, NGX_CONF_TAKE3),
        simple_directive_module("ngx_http_limit_req_module", "limit_req", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF, NGX_CONF_TAKE1),
        simple_directive_module("ngx_http_limit_req_module", "limit_req_log_level", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF, NGX_CONF_TAKE1),
    ]
}

pub fn filter_modules_a() -> Vec<ModuleDef> {
    vec![]
}

pub fn filter_modules_b() -> Vec<ModuleDef> {
    vec![]
}

pub fn filter_modules_c() -> Vec<ModuleDef> {
    vec![]
}

pub fn filter_modules_d() -> Vec<ModuleDef> {
    vec![]
}

pub fn upstream_log_info(_r: &Request) -> Option<Vec<u8>> {
    None
}

pub async fn ssl_handshake(_c: &Rc<Connection>, _hc: &Rc<HttpConnection>) -> bool {
    false
}

pub fn ssl_verify_enabled(_cscf: &Rc<std::cell::RefCell<CoreSrvConf>>) -> bool {
    false
}

pub fn ssl_process_request_checks(_r: &R) -> Option<i64> {
    None
}

pub async fn ssl_shutdown(_c: &Rc<Connection>) {}

pub fn _accept_unused() -> ConfSet {
    accept
}
