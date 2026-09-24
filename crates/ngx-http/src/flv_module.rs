//! ngx_http_flv_module (placeholder: directives accepted, handler declines)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::*;
use crate::*;
use crate::Command;

crate::http_module_index!("ngx_http_flv_module");

pub struct FlvConf;

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(FlvConf)
}

fn merge_conf(_cf: &mut Conf, _prev: &Rc<dyn Any>, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

pub fn flv_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_LOC_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("flv", F | NGX_CONF_NOARGS, ConfLevel::Loc, accept_flv),
    ];
    http_module_def("ngx_http_flv_module", def, commands)
}

fn accept_flv(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|_r| Box::pin(async { NGX_DECLINED })));
    Ok(())
}
