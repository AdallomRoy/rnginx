//! IMAP protocol module
use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::{ModuleDef, NGX_MAIL_MODULE};

use crate::{NGX_MAIL_MAIN_CONF, NGX_MAIL_SRV_CONF};

const NGX_CONF_1MORE: u32 = 0x00000800;
const NGX_CONF_TAKE1: u32 = 0x00000002;

#[derive(Debug, Clone, Default)]
pub struct ImapConf {
    pub auth: Vec<Vec<u8>>,
    pub client_buffer_size: Option<usize>,
}

fn imap_auth(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // imap_auth plain login cram-md5
    Ok(())
}

fn imap_client_buffer(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // imap_client_buffer size
    Ok(())
}

pub fn imap_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_imap_module",
        ty: NGX_MAIL_MODULE,
        commands: vec![
            Command::new("imap_auth", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, imap_auth),
            Command::new("imap_client_buffer", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, imap_client_buffer),
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
    fn test_imap_conf_default() {
        let conf = ImapConf::default();
        assert!(conf.auth.is_empty());
    }
}
