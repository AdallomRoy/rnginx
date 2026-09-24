//! ngx_http_try_files_module (placeholder: directive accepted)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;

use crate::*;

crate::http_module_index!("ngx_http_try_files_module");

pub struct TryFilesConf {
    pub try_files: Option<Vec<Vec<u8>>>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(TryFilesConf { try_files: None })
}

fn set_try_files(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<TryFilesConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();
    if c.try_files.is_some() {
        return Err(msg("is duplicate"));
    }
    c.try_files = Some(cf.args[1..].to_vec());
    Ok(())
}

pub fn try_files_module() -> ModuleDef {
    let def = HttpModuleDef { create_loc_conf: Some(create_conf), ..Default::default() };
    let commands = vec![ngx_core::cmd_fn!("try_files", NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_2MORE, ConfLevel::Loc, set_try_files)];
    http_module_def("ngx_http_try_files_module", def, commands)
}
