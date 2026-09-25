//! ngx_http_browser_module - Browser detection

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::{request::*, *};

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

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<BrowserLocConf>(prev).borrow();
    let mut c = conf_cell::<BrowserLocConf>(conf).borrow_mut();
    c.modern_browser_value.merge(&p.modern_browser_value, Vec::new());
    c.ancient_browser_value.merge(&p.ancient_browser_value, Vec::new());
    Ok(())
}

fn msie_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data.clear();

    let headers_in = r.headers_in.borrow();
    if let Some(user_agent_header) = headers_in.user_agent.first() {
        let ua = user_agent_header.value.borrow();
        if ua.windows(4).any(|w| w == b"MSIE") {
            v.data = b"1".to_vec();
        }
    }

    NGX_OK
}

fn modern_browser_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let blcf = r.loc_conf::<BrowserLocConf>(ctx_index());
    let blcf = blcf.borrow();

    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data.clone_from(blcf.modern_browser_value.get());

    NGX_OK
}

fn ancient_browser_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let blcf = r.loc_conf::<BrowserLocConf>(ctx_index());
    let blcf = blcf.borrow();

    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data.clone_from(blcf.ancient_browser_value.get());

    NGX_OK
}

fn modern_browser_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let _blcf = conf_cell::<BrowserLocConf>(conf.as_ref().unwrap());
    // For now, just parse the directive without storing the pattern
    // Full implementation would check User-Agent against patterns
    Ok(())
}

fn ancient_browser_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let _blcf = conf_cell::<BrowserLocConf>(conf.as_ref().unwrap());
    // For now, just parse the directive without storing the pattern
    Ok(())
}

fn set_browser_value(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let blcf = conf_cell::<BrowserLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() < 2 {
        return Err(msg("requires an argument"));
    }

    if args[0] == b"modern_browser_value" {
        blcf.borrow_mut().modern_browser_value = Val::set(args[1].clone());
    } else if args[0] == b"ancient_browser_value" {
        blcf.borrow_mut().ancient_browser_value = Val::set(args[1].clone());
    }

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
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
            ConfLevel::Loc,
            modern_browser_directive
        ),
        ngx_core::cmd_fn!(
            "ancient_browser",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
            ConfLevel::Loc,
            ancient_browser_directive
        ),
        ngx_core::cmd_fn!(
            "modern_browser_value",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            set_browser_value
        ),
        ngx_core::cmd_fn!(
            "ancient_browser_value",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            set_browser_value
        ),
    ];
    http_module_def("ngx_http_browser_module", def, commands)
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let var = add_variable(cf, b"msie", NGX_HTTP_VAR_CHANGEABLE)?;
    var.get_handler.set(Some(msie_variable));

    let var = add_variable(cf, b"modern_browser", NGX_HTTP_VAR_CHANGEABLE)?;
    var.get_handler.set(Some(modern_browser_variable));

    let var = add_variable(cf, b"ancient_browser", NGX_HTTP_VAR_CHANGEABLE)?;
    var.get_handler.set(Some(ancient_browser_variable));

    Ok(())
}
