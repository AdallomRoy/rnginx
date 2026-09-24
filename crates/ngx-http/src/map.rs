//! ngx_http_map_module - variable mapping (placeholder)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::*;

crate::http_module_index!("ngx_http_map_module");

pub struct MapMainConf {
    pub hash_max_size: Val<u32>,
    pub hash_bucket_size: Val<u32>,
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(MapMainConf { hash_max_size: Val::unset(), hash_bucket_size: Val::unset() })
}

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

pub fn map_module() -> ModuleDef {
    let def = HttpModuleDef {
        create_main_conf: Some(create_main_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("map", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, accept),
    ];
    http_module_def("ngx_http_map_module", def, commands)
}
