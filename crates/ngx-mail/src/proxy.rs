//! proxy module - mail backend proxy
use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::{ModuleDef, NGX_MAIL_MODULE};

use crate::{NGX_MAIL_MAIN_CONF, NGX_MAIL_SRV_CONF};

const NGX_CONF_FLAG: u32 = 0x00000200;
const NGX_CONF_TAKE1: u32 = 0x00000002;
const NGX_CONF_1MORE: u32 = 0x00000800;

#[derive(Debug, Clone, Default)]
pub struct ProxyConf {
    pub enable: bool,
    pub pass_error_message: bool,
    pub xclient: bool,
    pub smtp_auth: bool,
    pub proxy_protocol: u32,
    pub buffer_size: usize,
    pub timeout: u64,
}

fn proxy_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // proxy on/off
    Ok(())
}

fn proxy_buffer_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // proxy_buffer size
    Ok(())
}

fn proxy_timeout_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // proxy_timeout msec
    Ok(())
}

fn proxy_pass_error_message_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // proxy_pass_error_message on/off
    Ok(())
}

fn xclient_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // xclient on/off
    Ok(())
}

fn proxy_smtp_auth_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // proxy_smtp_auth on/off
    Ok(())
}

fn proxy_protocol_conf(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // proxy_protocol off/on/v2
    Ok(())
}

pub fn proxy_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_proxy_module",
        ty: NGX_MAIL_MODULE,
        commands: vec![
            Command::new("proxy", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Main, proxy_conf),
            Command::new("proxy_buffer", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Main, proxy_buffer_conf),
            Command::new("proxy_timeout", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Main, proxy_timeout_conf),
            Command::new("proxy_pass_error_message", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Main, proxy_pass_error_message_conf),
            Command::new("xclient", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Main, xclient_conf),
            Command::new("proxy_smtp_auth", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Main, proxy_smtp_auth_conf),
            Command::new("proxy_protocol", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Main, proxy_protocol_conf),
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
    fn test_proxy_conf_default() {
        let conf = ProxyConf::default();
        assert!(!conf.enable);
        assert!(!conf.pass_error_message);
    }
}
