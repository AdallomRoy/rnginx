//! stub: parse-only

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use crate::*;

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { Ok(()) }
pub fn geo_module() -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![ngx_core::cmd_fn!("geo", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE12, ConfLevel::Main, accept)];
    http_module_def("ngx_http_geo_module", def, commands)
}
