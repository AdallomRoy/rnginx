//! ngx_http_limit_conn_module: limits concurrent connections

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::{cmd_fn};

use crate::*;

crate::http_module_index!("ngx_http_limit_conn_module");

pub struct LimitConnConf {
    limits: Vec<()>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitConnConf { limits: Vec::new() })
}

fn merge_conf(_cf: &mut Conf, _prev: &Rc<dyn Any>, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

fn limit_conn_zone(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement limit_conn_zone directive
    Ok(())
}

fn limit_conn(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement limit_conn directive
    Ok(())
}

fn limit_conn_log_level(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement limit_conn_log_level directive
    Ok(())
}

fn limit_conn_status(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement limit_conn_status directive
    Ok(())
}

fn limit_conn_dry_run(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement limit_conn_dry_run directive
    Ok(())
}

pub fn limit_conn_module() -> ModuleDef {
    let def = HttpModuleDef {
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("limit_conn_zone", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2, ConfLevel::None, limit_conn_zone),
        cmd_fn!("limit_conn", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, limit_conn),
        cmd_fn!("limit_conn_log_level", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, limit_conn_log_level),
        cmd_fn!("limit_conn_status", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, limit_conn_status),
        cmd_fn!("limit_conn_dry_run", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, limit_conn_dry_run),
    ];
    http_module_def("ngx_http_limit_conn_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder() {
        // TODO: implement
    }
}
