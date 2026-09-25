//! ngx_mail_core_module - core mail configuration (listen, protocol, server, timeout, resolver, etc.)

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;

use crate::{NGX_MAIL_MAIN_CONF, NGX_MAIL_SRV_CONF};
use ngx_core::module::NGX_MAIL_MODULE;

const NGX_CONF_BLOCK: u32 = 0x00000100;
const NGX_CONF_NOARGS: u32 = 0x00000001;
const NGX_CONF_TAKE1: u32 = 0x00000002;
const NGX_CONF_1MORE: u32 = 0x00000800;

/// Main mail configuration
#[derive(Debug)]
pub struct MailMainConf {
    // Array of servers
    pub servers: Vec<Rc<RefCell<MailSrvConf>>>,
    // Array of listen configurations
    pub listen: Vec<MailListenConf>,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct MailSrvConf {
    pub protocol: Option<i32>,
    pub server_name: Vec<u8>,
    pub timeout: u64,           // milliseconds
    pub resolver_timeout: u64,   // milliseconds
    pub max_errors: u32,
    pub error_log: Option<String>,
    pub resolver: Option<String>,
    pub file_name: String,
    pub line: u32,
}

/// Listen configuration
#[derive(Debug, Clone)]
pub struct MailListenConf {
    pub addr: String,
    pub port: u16,
    pub protocol: Option<i32>,
    pub bind: bool,
    pub wildcard: bool,
    pub ssl: bool,
    pub proxy_protocol: bool,
    pub so_keepalive: u8,
    pub backlog: i32,
    pub rcvbuf: Option<usize>,
    pub sndbuf: Option<usize>,
}

impl Default for MailSrvConf {
    fn default() -> Self {
        MailSrvConf {
            protocol: None,
            server_name: Vec::new(),
            timeout: 60000,
            resolver_timeout: 30000,
            max_errors: 5,
            error_log: None,
            resolver: None,
            file_name: String::new(),
            line: 0,
        }
    }
}

// Protocol type constants (matching C ngx_mail_proto_t)
pub const NGX_MAIL_POP3_PROTOCOL: i32 = 0;
pub const NGX_MAIL_IMAP_PROTOCOL: i32 = 1;
pub const NGX_MAIL_SMTP_PROTOCOL: i32 = 2;

// Handler functions for directives
fn mail_core_listen(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // listen address[:port] [ssl] [proxy_protocol] [backlog=n] [rcvbuf=n] [sndbuf=n] [bind] [ipv6only=on|off] [so_keepalive=on|off|...];
    // For now, just accept it and don't fail - real parsing would store the listen config
    // in a way that mail_block can use to create listening sockets
    Ok(())
}

fn mail_core_server(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // server { ... }
    // Parse nested configuration for server block
    let saved_cmd_type = cf.cmd_type;
    cf.cmd_type = NGX_MAIL_SRV_CONF;

    let result = cf.parse_block();

    cf.cmd_type = saved_cmd_type;

    result
}

fn mail_core_protocol(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // protocol pop3|imap|smtp;
    // For now just accept - real parsing would happen here
    Ok(())
}

fn mail_core_error_log(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // error_log /path/to/log [level];
    Ok(())
}

fn mail_core_resolver(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // resolver 8.8.8.8 8.8.4.4 [valid=300s] [status_zone=name];
    Ok(())
}

pub fn core_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_core_module",
        ty: NGX_MAIL_MODULE,
        commands: vec![
            Command::new(
                "server",
                NGX_MAIL_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
                ConfLevel::Main,
                mail_core_server,
            ),
            Command::new(
                "listen",
                NGX_MAIL_SRV_CONF | NGX_CONF_1MORE,
                ConfLevel::Srv,
                mail_core_listen,
            ),
            Command::new(
                "protocol",
                NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1,
                ConfLevel::Srv,
                mail_core_protocol,
            ),
            Command::new(
                "timeout",
                NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1,
                ConfLevel::Main,
                |_cf, _cmd, _conf| Ok(()),
            ),
            Command::new(
                "server_name",
                NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1,
                ConfLevel::Main,
                |_cf, _cmd, _conf| Ok(()),
            ),
            Command::new(
                "error_log",
                NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_1MORE,
                ConfLevel::Main,
                mail_core_error_log,
            ),
            Command::new(
                "resolver",
                NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_1MORE,
                ConfLevel::Main,
                mail_core_resolver,
            ),
            Command::new(
                "resolver_timeout",
                NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1,
                ConfLevel::Main,
                |_cf, _cmd, _conf| Ok(()),
            ),
            Command::new(
                "max_errors",
                NGX_MAIL_MAIN_CONF | NGX_MAIL_SRV_CONF | NGX_CONF_TAKE1,
                ConfLevel::Main,
                |_cf, _cmd, _conf| Ok(()),
            ),
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
    fn test_default_srv_conf() {
        let conf = MailSrvConf::default();
        assert_eq!(conf.timeout, 60000);
        assert_eq!(conf.max_errors, 5);
    }
}
