//! ngx_http_split_clients_module - A/B testing

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;

use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::{request::*, *};

crate::http_module_index!("ngx_http_split_clients_module");

fn split_clients_variable(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data = Vec::new();
    NGX_OK
}

fn split_clients_block_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    let args = args.iter().map(|a| a.clone()).collect::<Vec<_>>();

    if args.len() < 3 {
        return Err(msg("split_clients requires 2 arguments"));
    }

    let _source = &args[1];
    let var_name = &args[2];

    if var_name.is_empty() || var_name[0] != b'$' {
        return Err(msg("invalid variable name"));
    }

    let var_name_str = &var_name[1..];
    let var = add_variable(cf, var_name_str, NGX_HTTP_VAR_CHANGEABLE)?;
    var.get_handler.set(Some(split_clients_variable));

    // Set handler for block contents
    cf.handler = Some(split_clients_item_handler);
    cf.handler_conf = Some(Rc::new(()));

    Ok(())
}

fn split_clients_item_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();

    if args.len() != 2 {
        return Err(msg("split_clients item requires 2 arguments"));
    }

    let percent_str = &args[0];

    if percent_str == b"*" {
        return Ok(());
    }

    if percent_str.is_empty() || percent_str[percent_str.len() - 1] != b'%' {
        return Err(msg("invalid percent value"));
    }

    let percent_bytes = &percent_str[..percent_str.len() - 1];
    let _percent_str_utf8 =
        std::str::from_utf8(percent_bytes).map_err(|_| msg("invalid percent value"))?;
    let _percent_f: f64 = _percent_str_utf8
        .parse()
        .map_err(|_| msg("invalid percent value"))?;

    Ok(())
}

pub fn split_clients_module() -> ModuleDef {
    let def = HttpModuleDef::default();
    let commands = vec![ngx_core::cmd_fn!(
        "split_clients",
        NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2,
        ConfLevel::Main,
        split_clients_block_handler
    )];
    http_module_def("ngx_http_split_clients_module", def, commands)
}
