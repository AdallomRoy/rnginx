//! ngx_http_upstream_keepalive_module
//! Connection pooling for upstream keepalive connections

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::cmd_fn;

use crate::core::*;
use crate::request::*;
use crate::{NGX_HTTP_UPS_CONF, NGX_CONF_TAKE1, NGX_CONF_TAKE12, HttpModuleDef, http_module_def};

crate::http_module_index!("ngx_http_upstream_keepalive_module");

/// Keepalive configuration for an upstream block
#[derive(Clone)]
pub struct KeepaliveConf {
    pub max_cached: u32,
    pub max_requests: u32,
    pub timeout: u64,  // milliseconds
    pub time: u64,     // milliseconds
}

impl Default for KeepaliveConf {
    fn default() -> Self {
        KeepaliveConf {
            max_cached: 32,
            max_requests: 100,
            timeout: 60000,
            time: 0,
        }
    }
}

fn keepalive_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }

    // TODO: Parse keepalive count and store in upstream conf
    // cf.args[1] = count (number)
    // cf.args[2] = "type=..." optional

    Ok(())
}

fn keepalive_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }

    // TODO: Parse timeout value

    Ok(())
}

fn keepalive_time_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }

    // TODO: Parse time value

    Ok(())
}

fn keepalive_requests_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }

    // TODO: Parse requests value

    Ok(())
}

pub fn upstream_keepalive_module() -> ModuleDef {
    let commands = vec![
        cmd_fn!("keepalive", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::None, keepalive_handler),
        cmd_fn!("keepalive_timeout", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, keepalive_timeout_handler),
        cmd_fn!("keepalive_time", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, keepalive_time_handler),
        cmd_fn!("keepalive_requests", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, keepalive_requests_handler),
    ];

    let def = HttpModuleDef {
        ..Default::default()
    };

    http_module_def("ngx_http_upstream_keepalive_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_conf_default() {
        let conf = KeepaliveConf::default();
        assert_eq!(conf.max_cached, 32);
        assert_eq!(conf.timeout, 60000);
    }
}
