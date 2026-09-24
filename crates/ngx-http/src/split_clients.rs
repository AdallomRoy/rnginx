//! ngx_http_split_clients_module - A/B testing (placeholder)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;

use crate::*;

crate::http_module_index!("ngx_http_split_clients_module");

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

pub fn split_clients_module() -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![
        ngx_core::cmd_fn!("split_clients", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, accept),
    ];
    http_module_def("ngx_http_split_clients_module", def, commands)
}
