//! SMTP protocol module
use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::{ModuleDef, NGX_MAIL_MODULE};

use crate::{NGX_MAIL_MAIN_CONF, NGX_MAIL_SRV_CONF};

const NGX_CONF_1MORE: u32 = 0x00000800;
const NGX_CONF_TAKE1: u32 = 0x00000002;

#[derive(Debug, Clone, Default)]
pub struct SmtpConf {
    pub auth: Vec<Vec<u8>>,
    pub client_buffer_size: Option<usize>,
    pub greeting_delay: Option<u64>,
}

fn smtp_auth(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // smtp_auth plain login cram-md5
    Ok(())
}

fn smtp_client_buffer(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // smtp_client_buffer size
    Ok(())
}

fn smtp_greeting_delay(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // smtp_greeting_delay msec
    Ok(())
}

pub fn smtp_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_smtp_module",
        ty: NGX_MAIL_MODULE,
        commands: vec![
            Command::new("smtp_auth", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, smtp_auth),
            Command::new("smtp_client_buffer", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, smtp_client_buffer),
            Command::new("smtp_greeting_delay", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, smtp_greeting_delay),
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
    fn test_smtp_conf_default() {
        let conf = SmtpConf::default();
        assert!(conf.auth.is_empty());
    }
}
