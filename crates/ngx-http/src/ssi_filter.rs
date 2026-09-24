//! ngx_http_ssi_filter_module (placeholder: directives accepted, handler declines)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::*;
use crate::*;

crate::http_module_index!("ngx_http_ssi_filter_module");

pub struct SsiFilterConf {
    pub enable: Val<bool>,
    pub silent_errors: Val<bool>,
    pub ignore_recycled_buffers: Val<bool>,
    pub min_file_chunk: Val<usize>,
    pub value_length: Val<usize>,
    pub last_modified: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SsiFilterConf {
        enable: Val::unset(),
        silent_errors: Val::unset(),
        ignore_recycled_buffers: Val::unset(),
        min_file_chunk: Val::unset(),
        value_length: Val::unset(),
        last_modified: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<SsiFilterConf>(prev).borrow();
    let mut c = conf_cell::<SsiFilterConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    c.silent_errors.merge(&p.silent_errors, false);
    c.ignore_recycled_buffers.merge(&p.ignore_recycled_buffers, false);
    c.min_file_chunk.merge(&p.min_file_chunk, 0);
    c.value_length.merge(&p.value_length, 256);
    c.last_modified.merge(&p.last_modified, false);
    Ok(())
}

pub fn ssi_filter_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!("ssi", F | NGX_CONF_FLAG, ConfLevel::Loc, SsiFilterConf, enable, set_flag),
        ngx_core::cmd!("ssi_silent_errors", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, SsiFilterConf, silent_errors, set_flag),
        ngx_core::cmd!("ssi_ignore_recycled_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, SsiFilterConf, ignore_recycled_buffers, set_flag),
        ngx_core::cmd!("ssi_min_file_chunk", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, SsiFilterConf, min_file_chunk, set_size),
        ngx_core::cmd!("ssi_value_length", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, SsiFilterConf, value_length, set_size),
        ngx_core::cmd!("ssi_last_modified", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, SsiFilterConf, last_modified, set_flag),
    ];
    http_module_def("ngx_http_ssi_filter_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|_r| Box::pin(async { NGX_DECLINED })));
    Ok(())
}
