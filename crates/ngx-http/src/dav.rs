//! ngx_http_dav_module (placeholder: directives accepted, handler declines)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::*;
use crate::*;
use crate::Command;

crate::http_module_index!("ngx_http_dav_module");

const NGX_HTTP_DAV_OFF: u32 = 0;

pub struct DavConf {
    pub methods: u32,
    pub create_full_put_path: Val<bool>,
    pub min_delete_depth: Val<i64>,
    pub access: Val<u32>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(DavConf {
        methods: 0,
        create_full_put_path: Val::unset(),
        min_delete_depth: Val::unset(),
        access: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<DavConf>(prev).borrow();
    let mut c = conf_cell::<DavConf>(conf).borrow_mut();
    if c.methods == 0 {
        c.methods = p.methods;
    }
    c.create_full_put_path.merge(&p.create_full_put_path, false);
    c.min_delete_depth.merge(&p.min_delete_depth, 0);
    c.access.merge(&p.access, 0);
    Ok(())
}

pub fn dav_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("dav_methods", F | NGX_CONF_1MORE, ConfLevel::Loc, set_dav_methods),
        ngx_core::cmd!("create_full_put_path", F | NGX_CONF_FLAG, ConfLevel::Loc, DavConf, create_full_put_path, set_flag),
        ngx_core::cmd!("min_delete_depth", F | NGX_CONF_TAKE1, ConfLevel::Loc, DavConf, min_delete_depth, set_num),
        ngx_core::cmd!("dav_access", F | NGX_CONF_TAKE123, ConfLevel::Loc, DavConf, access, set_access),
    ];
    http_module_def("ngx_http_dav_module", def, commands)
}

fn set_dav_methods(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let slot = conf.ok_or(ConfError::Logged)?;
    let mut c = conf_cell::<DavConf>(&slot).borrow_mut();
    for v in &cf.args[1..] {
        let method_name = String::from_utf8_lossy(v).to_lowercase();
        let mask = match method_name.as_str() {
            "off" => NGX_HTTP_DAV_OFF,
            "put" => NGX_HTTP_PUT,
            "delete" => NGX_HTTP_DELETE,
            "mkcol" => NGX_HTTP_MKCOL,
            "copy" => NGX_HTTP_COPY,
            "move" => NGX_HTTP_MOVE,
            _ => return Err(ConfError::Msg(format!("invalid dav method: {}", method_name))),
        };
        if c.methods & mask != 0 {
            cf.warn(format_args!("duplicate dav method"));
        } else {
            c.methods |= mask;
        }
    }
    Ok(())
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|_r| Box::pin(async { NGX_DECLINED })));
    Ok(())
}
