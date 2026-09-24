//! ngx_http_browser_module - Browser detection

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::*;

crate::http_module_index!("ngx_http_browser_module");

pub struct BrowserLocConf {
    pub modern_browser_value: Val<Vec<u8>>,
    pub ancient_browser_value: Val<Vec<u8>>,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(BrowserLocConf {
        modern_browser_value: Val::unset(),
        ancient_browser_value: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, _prev: &Rc<dyn Any>, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    add_variable(cf, b"msie", NGX_HTTP_VAR_CHANGEABLE)?;
    add_variable(cf, b"modern_browser", NGX_HTTP_VAR_CHANGEABLE)?;
    add_variable(cf, b"ancient_browser", NGX_HTTP_VAR_CHANGEABLE)?;
    Ok(())
}

fn browser_handler(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

pub fn browser_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!(
            "modern_browser",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
            ConfLevel::Loc,
            browser_handler
        ),
        ngx_core::cmd_fn!(
            "ancient_browser",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
            ConfLevel::Loc,
            browser_handler
        ),
        ngx_core::cmd_fn!(
            "modern_browser_value",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            browser_handler
        ),
        ngx_core::cmd_fn!(
            "ancient_browser_value",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            browser_handler
        ),
    ];
    http_module_def("ngx_http_browser_module", def, commands)
}
