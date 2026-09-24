//! ngx_http_referer_module - Referer validation (placeholder)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::*;

crate::http_module_index!("ngx_http_referer_module");

pub struct RefererLocConf {
    pub referer_hash_max_size: Val<u32>,
    pub referer_hash_bucket_size: Val<u32>,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(RefererLocConf { referer_hash_max_size: Val::unset(), referer_hash_bucket_size: Val::unset() })
}

fn merge_loc_conf(_cf: &mut Conf, _prev: &Rc<dyn Any>, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let var = add_variable(cf, b"invalid_referer", NGX_HTTP_VAR_CHANGEABLE)?;
    var.get_handler.set(Some(referer_variable_handler));
    Ok(())
}

fn referer_variable_handler(_r: &crate::request::R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // Always valid (not invalid)
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    v.data = Vec::new();
    v.escape = false;
    0 // NGX_OK
}

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

pub fn referer_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("valid_referers", NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, accept),
    ];
    http_module_def("ngx_http_referer_module", def, commands)
}
