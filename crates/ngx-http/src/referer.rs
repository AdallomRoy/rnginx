//! stub: parse-only

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use crate::*;

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult { Ok(()) }
pub fn referer_module() -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![
        ngx_core::cmd_fn!("valid_referers", NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("referer_hash_max_size", NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, accept),
        ngx_core::cmd_fn!("referer_hash_bucket_size", NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, accept),
    ];
    http_module_def("ngx_http_referer_module", def, commands)
}
