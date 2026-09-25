//! realip module - get client IP from headers
use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::{ModuleDef, NGX_MAIL_MODULE};

use crate::NGX_MAIL_SRV_CONF;

const NGX_CONF_TAKE1: u32 = 0x00000002;

fn set_real_ip(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // set_real_ip_from address
    Ok(())
}

fn real_ip_header(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // real_ip_header name
    Ok(())
}

pub fn realip_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_realip_module",
        ty: NGX_MAIL_MODULE,
        commands: vec![
            Command::new("set_real_ip_from", NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, set_real_ip),
            Command::new("real_ip_header", NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, real_ip_header),
        ],
        ctx: None,
        init_master: None,
        init_module: None,
        init_process: None,
        exit_process: None,
        exit_master: None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {}
}
