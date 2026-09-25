//! auth_http module - authentication via HTTP
use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::{ModuleDef, NGX_MAIL_MODULE};

use crate::{NGX_MAIL_MAIN_CONF, NGX_MAIL_SRV_CONF};

const NGX_CONF_TAKE1: u32 = 0x00000002;
const NGX_CONF_TAKE2: u32 = 0x00000004;
const NGX_CONF_FLAG: u32 = 0x00000200;

#[derive(Debug, Clone, Default)]
pub struct AuthHttpConf {
    pub uri: Vec<u8>,
    pub timeout: u64,
    pub pass_client_cert: bool,
}

fn auth_http_directive(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // auth_http http://server/path
    Ok(())
}

fn auth_http_timeout_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // auth_http_timeout msec
    Ok(())
}

fn auth_http_pass_client_cert_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // auth_http_pass_client_cert on/off
    Ok(())
}

fn auth_http_header_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // auth_http_header name value
    Ok(())
}

pub fn auth_http_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_auth_http_module",
        ty: NGX_MAIL_MODULE,
        commands: vec![
            Command::new("auth_http", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Main, auth_http_directive),
            Command::new("auth_http_timeout", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Main, auth_http_timeout_conf),
            Command::new("auth_http_pass_client_cert", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Main, auth_http_pass_client_cert_conf),
            Command::new("auth_http_header", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE2, ConfLevel::Main, auth_http_header_conf),
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
    fn test_auth_http_conf_default() {
        let conf = AuthHttpConf::default();
        assert!(conf.uri.is_empty());
        assert!(!conf.pass_client_cert);
    }
}
