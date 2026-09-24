//! ngx_http_referer_module - Referer validation

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::{request::*, *};

crate::http_module_index!("ngx_http_referer_module");

pub struct RefererLocConf {
    pub referer_hash_max_size: Val<u32>,
    pub referer_hash_bucket_size: Val<u32>,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(RefererLocConf {
        referer_hash_max_size: Val::unset(),
        referer_hash_bucket_size: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, _prev: &Rc<dyn Any>, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let var = add_variable(cf, b"invalid_referer", NGX_HTTP_VAR_CHANGEABLE)?;
    var.get_handler.set(Some(referer_variable_handler));
    Ok(())
}

fn referer_variable_handler(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    // Default: valid (not invalid)
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    v.data = Vec::new();
    v.escape = false;
    NGX_OK
}

fn valid_referers_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let args = args.iter().map(|a| a.clone()).collect::<Vec<_>>();

    if args.len() < 2 {
        return Err(msg("valid_referers requires at least 1 argument"));
    }

    for i in 1..args.len() {
        let arg = &args[i];

        if arg == b"none" || arg == b"blocked" || arg == b"server_names" {
            continue;
        }

        // Regex pattern starting with ~
        if !arg.is_empty() && arg[0] == b'~' {
            continue;
        }

        // Regular hostname/wildcard
        continue;
    }

    Ok(())
}

pub fn referer_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!(
            "valid_referers",
            NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
            ConfLevel::Loc,
            valid_referers_handler
        ),
        ngx_core::cmd_fn!(
            "referer_hash_max_size",
            NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            |cf, _cmd, conf| {
                let slot = conf.ok_or_else(|| msg("no conf"))?;
                let mut rlcf = conf_cell::<RefererLocConf>(&slot).borrow_mut();
                let args = cf.args.clone();
                let args = args.iter().map(|a| a.clone()).collect::<Vec<_>>();
                if args.len() < 2 {
                    return Err(msg("requires an argument"));
                }
                let val_str = std::str::from_utf8(&args[1]).map_err(|_| msg("invalid number"))?;
                let val: u32 = val_str.parse().map_err(|_| msg("invalid number"))?;
                rlcf.referer_hash_max_size = Val::set(val);
                Ok(())
            }
        ),
        ngx_core::cmd_fn!(
            "referer_hash_bucket_size",
            NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            |cf, _cmd, conf| {
                let slot = conf.ok_or_else(|| msg("no conf"))?;
                let mut rlcf = conf_cell::<RefererLocConf>(&slot).borrow_mut();
                let args = cf.args.clone();
                let args = args.iter().map(|a| a.clone()).collect::<Vec<_>>();
                if args.len() < 2 {
                    return Err(msg("requires an argument"));
                }
                let val_str = std::str::from_utf8(&args[1]).map_err(|_| msg("invalid number"))?;
                let val: u32 = val_str.parse().map_err(|_| msg("invalid number"))?;
                rlcf.referer_hash_bucket_size = Val::set(val);
                Ok(())
            }
        ),
    ];
    http_module_def("ngx_http_referer_module", def, commands)
}
