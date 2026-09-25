//! ssl module (parse-only stub) - SSL/TLS support for mail
use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::{ModuleDef, NGX_MAIL_MODULE};

use crate::{NGX_MAIL_MAIN_CONF, NGX_MAIL_SRV_CONF};

const NGX_CONF_FLAG: u32 = 0x00000200;
const NGX_CONF_TAKE1: u32 = 0x00000002;
const NGX_CONF_TAKE2: u32 = 0x00000004;
const NGX_CONF_1MORE: u32 = 0x00000800;

// All SSL directives are parse-only stubs for now
// TLS termination for mail comes in a later wave

fn ssl_protocols(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_ciphers(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_certificate(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_certificate_key(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_conf_command(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_dhparam(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_ecdh_curve(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_prefer_server_ciphers(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_session_cache(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn ssl_session_timeout(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

pub fn ssl_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_ssl_module",
        ty: NGX_MAIL_MODULE,
        commands: vec![
            Command::new("ssl_protocols", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, ssl_protocols),
            Command::new("ssl_ciphers", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ssl_ciphers),
            Command::new("ssl_certificate", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ssl_certificate),
            Command::new("ssl_certificate_key", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ssl_certificate_key),
            Command::new("ssl_conf_command", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE2, ConfLevel::Srv, ssl_conf_command),
            Command::new("ssl_dhparam", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ssl_dhparam),
            Command::new("ssl_ecdh_curve", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ssl_ecdh_curve),
            Command::new("ssl_prefer_server_ciphers", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, ssl_prefer_server_ciphers),
            Command::new("ssl_session_cache", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ssl_session_cache),
            Command::new("ssl_session_timeout", NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, ssl_session_timeout),
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
