//! ngx_http_map_module - variable mapping

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::{request::*, *};

crate::http_module_index!("ngx_http_map_module");

pub struct MapMainConf {
    pub hash_max_size: Val<u32>,
    pub hash_bucket_size: Val<u32>,
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(MapMainConf {
        hash_max_size: Val::unset(),
        hash_bucket_size: Val::unset(),
    })
}

fn map_variable(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data = Vec::new();
    NGX_OK
}

fn map_block_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let args = args.iter().map(|a| a.clone()).collect::<Vec<_>>();

    if args.len() < 3 {
        return Err(msg("map requires at least 2 arguments"));
    }

    let _source = &args[1];
    let var_name = &args[2];

    if var_name.is_empty() || var_name[0] != b'$' {
        return Err(msg("invalid variable name"));
    }

    let var_name_str = &var_name[1..];
    let var = add_variable(cf, var_name_str, NGX_HTTP_VAR_CHANGEABLE)?;
    var.get_handler.set(Some(map_variable));

    // Set handler for block contents
    cf.handler = Some(map_item_handler);
    cf.handler_conf = Some(Rc::new(()));

    Ok(())
}

fn map_item_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();

    if args.is_empty() {
        return Err(msg("empty map item"));
    }

    let first = &args[0];

    // Handle single-argument flags
    if args.len() == 1 {
        if first == b"hostnames" || first == b"volatile" {
            return Ok(());
        }
    }

    // Handle include directive
    if args.len() == 2 && first == b"include" {
        return Ok(());
    }

    // Handle map entries (key value)
    if args.len() == 2 {
        return Ok(());
    }

    // Unknown item
    Err(msg("invalid map item"))
}

fn set_num(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let slot = conf.ok_or_else(|| msg("no conf"))?;
    let mut mcf = conf_cell::<MapMainConf>(&slot).borrow_mut();
    let args = cf.args.clone();
    let args = args.iter().map(|a| a.clone()).collect::<Vec<_>>();

    if args.len() < 2 {
        return Err(msg("requires an argument"));
    }

    let val_str = std::str::from_utf8(&args[1]).map_err(|_| msg("invalid number"))?;
    let val: u32 = val_str.parse().map_err(|_| msg("invalid number"))?;

    if args[0] == b"map_hash_max_size" {
        mcf.hash_max_size = Val::set(val);
    } else if args[0] == b"map_hash_bucket_size" {
        mcf.hash_bucket_size = Val::set(val);
    }

    Ok(())
}

pub fn map_module() -> ModuleDef {
    let def = HttpModuleDef {
        create_main_conf: Some(create_main_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!(
            "map",
            NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2,
            ConfLevel::Main,
            map_block_handler
        ),
        ngx_core::cmd_fn!(
            "map_hash_max_size",
            NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
            ConfLevel::Main,
            set_num
        ),
        ngx_core::cmd_fn!(
            "map_hash_bucket_size",
            NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
            ConfLevel::Main,
            set_num
        ),
    ];
    http_module_def("ngx_http_map_module", def, commands)
}
