//! ngx_http_map_module - variable mapping

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
use ngx_core::string::{B, eq_ignore_case};
use ngx_core::ngx_log_debug;

use crate::script::ComplexValue;
use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE, NGX_HTTP_VAR_NOCACHEABLE};
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

enum MapEntry {
    Static(Vec<u8>),
    Complex(ComplexValue),
}

struct MapRegex {
    regex: Rc<Regex>,
    case_sensitive: bool,
    value: MapEntry,
}

pub struct MapCtx {
    cv: ComplexValue,
    default: Option<MapEntry>,
    entries: RefCell<Vec<(Vec<u8>, MapEntry)>>,
    regexes: RefCell<Vec<MapRegex>>,
    volatile: bool,
    hostnames: bool,
}

fn map_variable(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    let ctx = unsafe { &*(data as *const MapCtx) };

    v.valid = true;
    v.not_found = false;
    v.no_cacheable = ctx.volatile;
    v.escape = false;
    v.data.clear();

    match crate::script::complex_value(r, &ctx.cv) {
        Ok(mut lookup_key) => {
            if ctx.hostnames && !lookup_key.is_empty() && lookup_key[lookup_key.len() - 1] == b'.' {
                lookup_key.pop();
            }

            let entries = ctx.entries.borrow();
            for (key, entry) in entries.iter() {
                if eq_ignore_case(key, &lookup_key) {
                    match entry {
                        MapEntry::Static(val) => {
                            v.data.clone_from(val);
                        }
                        MapEntry::Complex(cv) => {
                            if let Ok(val) = crate::script::complex_value(r, cv) {
                                v.data = val;
                            }
                        }
                    }
                    return NGX_OK;
                }
            }

            let regexes = ctx.regexes.borrow();
            for regex_entry in regexes.iter() {
                let flags = if regex_entry.case_sensitive { 0 } else { ngx_core::regex::NGX_REGEX_CASELESS };
                if regex_entry.regex.is_match(&lookup_key) {
                    match &regex_entry.value {
                        MapEntry::Static(val) => {
                            v.data.clone_from(val);
                        }
                        MapEntry::Complex(cv) => {
                            if let Ok(val) = crate::script::complex_value(r, cv) {
                                v.data = val;
                            }
                        }
                    }
                    return NGX_OK;
                }
            }

            if let Some(default) = &ctx.default {
                match default {
                    MapEntry::Static(val) => {
                        v.data.clone_from(val);
                    }
                    MapEntry::Complex(cv) => {
                        if let Ok(val) = crate::script::complex_value(r, cv) {
                            v.data = val;
                        }
                    }
                }
            }

            NGX_OK
        }
        Err(_) => NGX_OK,
    }
}

fn map_item_handler(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let args = cf.args.clone();

    let key = &args[0];

    // Single argument: flags
    if args.len() == 1 {
        if key == b"hostnames" || key == b"volatile" {
            return Ok(());
        }
        return Ok(());
    }

    // Two arguments: key value
    if args.len() != 2 {
        return Ok(());
    }

    let value_str = &args[1];

    if key == b"include" {
        return Ok(());
    }

    let ctx_ptr = *conf.downcast_ref::<usize>()
        .ok_or_else(|| msg("invalid conf"))?;
    let ctx = unsafe { &*(ctx_ptr as *const MapCtx) };

    let value = if value_str.first() == Some(&b'$') {
        MapEntry::Complex(crate::script::compile_complex_value(cf, value_str, 0)?)
    } else {
        MapEntry::Static(value_str.clone())
    };

    if key == b"default" {
        // Default is handled specially
        return Ok(());
    }

    if !key.is_empty() && key[0] == b'~' {
        let is_case_sensitive = key.len() < 2 || key[1] != b'*';
        let pattern_start = if is_case_sensitive { 1 } else { 2 };
        let pattern = &key[pattern_start..];

        let flags = if is_case_sensitive { 0 } else { ngx_core::regex::NGX_REGEX_CASELESS };
        match Regex::compile(pattern, flags) {
            Ok(regex) => {
                ctx.regexes.borrow_mut().push(MapRegex {
                    regex,
                    case_sensitive: is_case_sensitive,
                    value,
                });
                Ok(())
            }
            Err(e) => Err(cf.emerg(format_args!("regex error: {}", e))),
        }
    } else {
        ctx.entries.borrow_mut().push((key.clone(), value));
        Ok(())
    }
}

fn map_block_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 3 {
        return Err(msg("requires at least 2 arguments"));
    }

    let cv = crate::script::compile_complex_value(cf, &args[1], 0)?;

    let var_name = &args[2];
    if var_name.is_empty() || var_name[0] != b'$' {
        return Err(msg("invalid variable name"));
    }

    let var = add_variable(cf, &var_name[1..], NGX_HTTP_VAR_CHANGEABLE)?;

    let ctx = Box::leak(Box::new(MapCtx {
        cv,
        default: None,
        entries: RefCell::new(Vec::new()),
        regexes: RefCell::new(Vec::new()),
        volatile: false,
        hostnames: false,
    }));

    var.get_handler.set(Some(map_variable));
    var.data.set(ctx as *const _ as usize);

    let saved_h = cf.handler.take();
    let saved_hc = cf.handler_conf.take();
    cf.handler = Some(map_item_handler);
    cf.handler_conf = Some(Rc::new(ctx as *const _ as usize));

    cf.parse_block()?;

    cf.handler = saved_h;
    cf.handler_conf = saved_hc;

    // Post-process to set default and volatile flag
    let mut entries = cf.args.clone();
    for directive_args in &[args.clone()] {
        for arg in directive_args {
            if arg == b"volatile" {
                ctx.volatile = true;
                var.flags.set(var.flags.get() | NGX_HTTP_VAR_NOCACHEABLE);
            }
            if arg == b"hostnames" {
                ctx.hostnames = true;
            }
        }
    }

    Ok(())
}

fn set_num(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let slot = conf.ok_or_else(|| msg("no conf"))?;
    let mut mcf = conf_cell::<MapMainConf>(&slot).borrow_mut();
    let args = cf.args.clone();

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
