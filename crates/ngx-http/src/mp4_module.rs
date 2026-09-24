//! ngx_http_mp4_module (placeholder: directives accepted, handler declines)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::*;
use crate::*;
use crate::Command;

crate::http_module_index!("ngx_http_mp4_module");

pub struct Mp4Conf {
    pub buffer_size: Val<usize>,
    pub max_buffer_size: Val<usize>,
    pub start_key_frame: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(Mp4Conf {
        buffer_size: Val::unset(),
        max_buffer_size: Val::unset(),
        start_key_frame: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<Mp4Conf>(prev).borrow();
    let mut c = conf_cell::<Mp4Conf>(conf).borrow_mut();
    c.buffer_size.merge(&p.buffer_size, 512 * 1024);
    c.max_buffer_size.merge(&p.max_buffer_size, 10 * 1024 * 1024);
    c.start_key_frame.merge(&p.start_key_frame, false);
    Ok(())
}

pub fn mp4_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("mp4", NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, ConfLevel::Loc, accept_mp4),
        ngx_core::cmd!("mp4_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, Mp4Conf, buffer_size, set_size),
        ngx_core::cmd!("mp4_max_buffer_size", F | NGX_CONF_TAKE1, ConfLevel::Loc, Mp4Conf, max_buffer_size, set_size),
        ngx_core::cmd!("mp4_start_key_frame", F | NGX_CONF_FLAG, ConfLevel::Loc, Mp4Conf, start_key_frame, set_flag),
    ];
    http_module_def("ngx_http_mp4_module", def, commands)
}

fn accept_mp4(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|_r| Box::pin(async { NGX_DECLINED })));
    Ok(())
}
