//! ngx_http_autoindex_module (placeholder: directives accepted, handler declines)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::*;
use crate::*;

crate::http_module_index!("ngx_http_autoindex_module");

pub struct AutoindexConf {
    pub enable: Val<bool>,
    pub format: Val<u32>,
    pub localtime: Val<bool>,
    pub exact_size: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AutoindexConf { enable: Val::unset(), format: Val::unset(), localtime: Val::unset(), exact_size: Val::unset() })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AutoindexConf>(prev).borrow();
    let mut c = conf_cell::<AutoindexConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    c.format.merge(&p.format, 0);
    c.localtime.merge(&p.localtime, false);
    c.exact_size.merge(&p.exact_size, true);
    Ok(())
}

pub fn autoindex_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;
    let def = HttpModuleDef { postconfiguration: Some(init), create_loc_conf: Some(create_conf), merge_loc_conf: Some(merge_conf), ..Default::default() };
    let commands = vec![
        ngx_core::cmd!("autoindex", F | NGX_CONF_FLAG, ConfLevel::Loc, AutoindexConf, enable, set_flag),
        ngx_core::cmd!("autoindex_format", F | NGX_CONF_TAKE1, ConfLevel::Loc, AutoindexConf, format, set_enum, &[("html", 0), ("json", 1), ("jsonp", 2), ("xml", 3)]),
        ngx_core::cmd!("autoindex_localtime", F | NGX_CONF_FLAG, ConfLevel::Loc, AutoindexConf, localtime, set_flag),
        ngx_core::cmd!("autoindex_exact_size", F | NGX_CONF_FLAG, ConfLevel::Loc, AutoindexConf, exact_size, set_flag),
    ];
    http_module_def("ngx_http_autoindex_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|_r| Box::pin(async { NGX_DECLINED })));
    Ok(())
}
