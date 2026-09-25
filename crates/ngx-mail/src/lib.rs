//! ngx-mail: Mail proxy module - POP3, IMAP, SMTP

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::module::{NGX_MAIL_MODULE, NGX_CORE_MODULE};

pub mod core;
pub mod handler;
pub mod parse;
pub mod pop3;
pub mod imap;
pub mod smtp;
pub mod proxy;
pub mod auth_http;
pub mod realip;
pub mod ssl;

// Mail configuration levels
pub const NGX_MAIL_MAIN_CONF: u32 = 0x01000000;
pub const NGX_MAIL_SRV_CONF: u32 = 0x02000000;

// Return codes
pub use ngx_core::rc::*;

/// Register all mail modules in the order matching nginx-c/objs/ngx_modules.c:
/// 1. ngx_mail_module (main block)
/// 2. ngx_mail_core_module
/// 3. ngx_mail_ssl_module (parse-only stub)
/// 4. ngx_mail_pop3_module
/// 5. ngx_mail_imap_module
/// 6. ngx_mail_smtp_module
/// 7. ngx_mail_auth_http_module
/// 8. ngx_mail_proxy_module
/// 9. ngx_mail_realip_module
pub fn modules() -> Vec<ModuleDef> {
    vec![
        mail_module(),
        core::core_module(),
        ssl::ssl_module(),
        pop3::pop3_module(),
        imap::imap_module(),
        smtp::smtp_module(),
        auth_http::auth_http_module(),
        proxy::proxy_module(),
        realip::realip_module(),
    ]
}

/// Main mail {} block handler
fn mail_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // Parse the mail { } block
    // Set the command type so directives are allowed at the correct level
    let saved_module_type = cf.module_type;
    let saved_cmd_type = cf.cmd_type;

    cf.module_type = NGX_MAIL_MODULE;
    cf.cmd_type = NGX_MAIL_MAIN_CONF;

    let result = cf.parse_block();

    cf.module_type = saved_module_type;
    cf.cmd_type = saved_cmd_type;

    result
}

/// ngx_mail_module: the main mail block directive
fn mail_module() -> ModuleDef {
    ModuleDef {
        name: "ngx_mail_module",
        ty: NGX_CORE_MODULE,
        commands: vec![
            Command::new(
                "mail",
                NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
                ConfLevel::None,
                mail_block,
            ),
        ],
        ctx: Some(Rc::new(CoreModuleCtx {
            name: "mail",
            create_conf: None,
            init_conf: None,
        })),
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
    fn test_modules_registered() {
        let mods = super::modules();
        assert!(!mods.is_empty());
        assert_eq!(mods[0].name, "ngx_mail_module");
        assert_eq!(mods[1].name, "ngx_mail_core_module");
    }
}
