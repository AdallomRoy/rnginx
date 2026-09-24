//! stub: parse-only

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use crate::*;

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { Ok(()) }
pub fn map_module() -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![
        ngx_core::cmd_fn!("map", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, accept),
        ngx_core::cmd_fn!("map_hash_max_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, accept),
        ngx_core::cmd_fn!("map_hash_bucket_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, accept),
    ];
    http_module_def("ngx_http_map_module", def, commands)
}
