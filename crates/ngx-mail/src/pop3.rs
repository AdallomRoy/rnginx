//! POP3 protocol module
use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::{ModuleDef, NGX_MAIL_MODULE};

use crate::{NGX_MAIL_MAIN_CONF, NGX_MAIL_SRV_CONF};

const NGX_CONF_1MORE: u32 = 0x00000800;

#[derive(Debug, Clone, Default)]
pub struct Pop3Conf {
    pub auth: Vec<Vec<u8>>,
}

fn pop3_auth(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // pop3_auth plain apop cram-md5 external
    Ok(())
}

pub fn pop3_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_pop3_module",
        ty: NGX_MAIL_MODULE,
        commands: vec![
            Command::new("pop3_auth", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, pop3_auth),
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
    use super::*;

    #[test]
    fn test_pop3_conf_default() {
        let conf = Pop3Conf::default();
        assert!(conf.auth.is_empty());
    }
}
