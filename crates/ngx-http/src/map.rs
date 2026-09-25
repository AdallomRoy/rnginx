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

#[derive(Clone)]
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
    default: RefCell<Option<MapEntry>>,
    entries: RefCell<Vec<(Vec<u8>, MapEntry)>>,
    regexes: RefCell<Vec<MapRegex>>,
    volatile: bool,
    hostnames: bool,
}

fn is_wildcard_pattern(key: &[u8]) -> bool {
    if key.is_empty() {
        return false;
    }
    // *.suffix
    if key[0] == b'*' && key.len() > 1 && key[1] == b'.' {
        return true;
    }
    // prefix.*
    if key.len() > 1 && key[key.len() - 1] == b'*' && key[key.len() - 2] == b'.' {
        return true;
    }
    // .suffix (leading dot)
    if key[0] == b'.' {
        return true;
    }
    false
}

fn wildcard_match(pattern: &[u8], key: &[u8]) -> bool {
    // All matching is case-insensitive for hostnames

    // Handle *.suffix pattern (left wildcard): *.example.com matches foo.example.com
    if pattern.len() > 1 && pattern[0] == b'*' && pattern[1] == b'.' {
        let suffix = &pattern[1..]; // ".example.com"
        if key.len() >= suffix.len() {
            let key_end = &key[key.len() - suffix.len()..];
            return eq_ignore_case(key_end, suffix);
        }
        return false;
    }

    // Handle prefix.* pattern (right wildcard): example.* matches example.com, example.org
    if pattern.len() > 1 && pattern[pattern.len() - 1] == b'*' && pattern[pattern.len() - 2] == b'.' {
        let prefix = &pattern[..pattern.len() - 1]; // "example."
        if key.len() >= prefix.len() {
            let key_start = &key[..prefix.len()];
            return eq_ignore_case(key_start, prefix);
        }
        return false;
    }

    // Handle .suffix pattern (leading dot): .example.com matches foo.example.com, dot.example.com, etc
    // Also matches subdomain.dot.example.com
    if pattern.len() > 0 && pattern[0] == b'.' {
        // Match if the key ends with the pattern
        if key.len() >= pattern.len() {
            let key_end = &key[key.len() - pattern.len()..];
            if eq_ignore_case(key_end, pattern) {
                return true;
            }
        }
        // Also match if key is exactly the pattern without the leading dot
        // i.e., .example.com matches example.com
        if key.len() == pattern.len() - 1 {
            return eq_ignore_case(key, &pattern[1..]);
        }
        return false;
    }

    false
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

            // Try exact matches first
            let entries = ctx.entries.borrow();
            for (key, entry) in entries.iter() {
                if is_wildcard_pattern(key) || (key.len() > 0 && key[0] == b'~') {
                    continue;  // Skip wildcard and regex patterns
                }
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

            // Try wildcard patterns (exact and then with wildcards)
            for (key, entry) in entries.iter() {
                if !is_wildcard_pattern(key) || (key.len() > 0 && key[0] == b'~') {
                    continue;  // Skip non-wildcard and regex patterns
                }
                if wildcard_match(key, &lookup_key) {
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

            // Try regexes
            let regexes = ctx.regexes.borrow();
            for regex_entry in regexes.iter() {
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

            // Try default
            if let Some(default) = ctx.default.borrow().as_ref() {
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

    let ctx_ptr = *conf.downcast_ref::<usize>()
        .ok_or_else(|| msg("invalid conf"))?;
    let ctx = unsafe { &*(ctx_ptr as *const MapCtx) };

    // Single argument: flags
    if args.len() == 1 {
        // Flags are set during ctx creation and block parsing, not handled here
        return Ok(());
    }

    // Two arguments: key value
    if args.len() != 2 {
        return Ok(());
    }

    let value_str = &args[1];

    // Handle "include" directive (without escaping)
    if key == b"include" && !args.is_empty() && args.len() >= 2 {
        // TODO: Actually read the include file
        return Ok(());
    }

    let value = if value_str.first() == Some(&b'$') {
        MapEntry::Complex(crate::script::compile_complex_value(cf, value_str, 0)?)
    } else {
        MapEntry::Static(value_str.clone())
    };

    if key == b"default" {
        *ctx.default.borrow_mut() = Some(value);
        return Ok(());
    }

    // Handle escaped keys like "\include" -> key is literally "include" (with backslash stripped by parser)
    // The key is already unescaped by nginx parser, so just add it as a regular entry

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

    // Parse flags from map directive arguments (volatile, hostnames, etc.)
    let mut volatile = false;
    let mut hostnames = false;
    for (i, arg) in args.iter().enumerate().skip(3) {
        if arg == b"volatile" {
            volatile = true;
        } else if arg == b"hostnames" {
            hostnames = true;
        }
    }

    let ctx = Box::leak(Box::new(MapCtx {
        cv,
        default: RefCell::new(None),
        entries: RefCell::new(Vec::new()),
        regexes: RefCell::new(Vec::new()),
        volatile,
        hostnames,
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

    // Set volatile flag if needed
    if volatile {
        var.flags.set(var.flags.get() | NGX_HTTP_VAR_NOCACHEABLE);
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
