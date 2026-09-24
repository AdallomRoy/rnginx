//! stub: parse-only

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use crate::*;

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { Ok(()) }
pub fn browser_module() -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![
        ngx_core::cmd_fn!("modern_browser", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("ancient_browser", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("ancient_browser_value", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("modern_browser_value", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, accept),
    ];
    http_module_def("ngx_http_browser_module", def, commands)
}
