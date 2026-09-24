//! ngx_http_limit_req_module: Limit request rate per zone.

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::*;

crate::http_module_index!("ngx_http_limit_req_module");

pub struct LimitReqConf {
    pub limits: Val<Vec<()>>,
    pub limit_log_level: Val<u32>,
    pub delay_log_level: Val<u32>,
    pub status_code: Val<i64>,
    pub dry_run: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitReqConf {
        limits: Val::unset(),
        limit_log_level: Val::unset(),
        delay_log_level: Val::unset(),
        status_code: Val::unset(),
        dry_run: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<LimitReqConf>(prev).borrow();
    let mut c = conf_cell::<LimitReqConf>(conf).borrow_mut();
    c.limit_log_level.merge(&p.limit_log_level, NGX_LOG_ERR);
    c.delay_log_level.merge(&p.delay_log_level, NGX_LOG_ERR + 1);
    c.status_code.merge(&p.status_code, NGX_HTTP_SERVICE_UNAVAILABLE);
    c.dry_run.merge(&p.dry_run, false);
    Ok(())
}

pub fn limit_req_module() -> ModuleDef {
    let def = HttpModuleDef {
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![];
    http_module_def("ngx_http_limit_req_module", def, commands)
}
