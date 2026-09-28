//! ngx_http_upstream_zone_module: "zone name [size]". The peers of an
//! upstream in a zone are shared by all requests of the worker, as with a
//! single worker in C; servers with "resolve" are resolved at run time.

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::string::B;
use ngx_core::cmd_fn;

use crate::upstream::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_TAKE12, NGX_HTTP_UPS_CONF};

/// ngx_http_upstream_zone
fn zone_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let uscf = current_upstream(cf).ok_or_else(|| msg("\"zone\" directive is not allowed here"))?;

    let value = cf.args.clone();

    if value[1].is_empty() {
        return Err(cf.emerg(format_args!("invalid zone name \"{}\"", B(&value[1]))));
    }

    let size = if value.len() == 3 {
        let size = match ngx_core::parse::parse_size(&value[2]) {
            Some(s) => s,
            None => return Err(cf.emerg(format_args!("invalid zone size \"{}\"", B(&value[2])))),
        };

        if size < 8 * ngx_core::os::pagesize() {
            return Err(cf.emerg(format_args!("zone \"{}\" is too small", B(&value[1]))));
        }

        size
    } else {
        0
    };

    if uscf.zone.borrow().is_some() {
        return Err(msg("is duplicate"));
    }

    *uscf.zone.borrow_mut() = Some((value[1].clone(), size));

    Ok(())
}

pub fn upstream_zone_module() -> ModuleDef {
    let commands = vec![cmd_fn!("zone", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::None, zone_handler)];
    http_module_def("ngx_http_upstream_zone_module", HttpModuleDef::default(), commands)
}
