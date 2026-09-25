//! ngx_http_geo_module - Geographic IP lookup with CIDR and range support

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::SockAddr;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::radix_tree::RadixTree;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::{request::*, *};

crate::http_module_index!("ngx_http_geo_module");

#[derive(Clone, Copy)]
pub struct GeoRange {
    pub start: u32,
    pub end: u32,
    pub value_idx: usize,
}

pub struct GeoCtx {
    pub default_value: Vec<u8>,
    pub tree: Option<RadixTree>,
    pub values: Vec<Vec<u8>>,
    pub ranges_mode: bool,
    pub ranges: Vec<GeoRange>,
}

pub struct GeoLocConf {
    pub ctx: RefCell<Option<Rc<GeoCtx>>>,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(GeoLocConf {
        ctx: RefCell::new(None),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<GeoLocConf>(prev).borrow();
    let mut c = conf_cell::<GeoLocConf>(conf).borrow_mut();
    if c.ctx.borrow().is_none() {
        c.ctx = RefCell::new(p.ctx.borrow().clone());
    }
    Ok(())
}

fn geo_variable(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    let ctx = unsafe { &*(data as *const GeoCtx) };

    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data.clear();

    // Get remote address
    let ip_u32 = get_remote_addr_u32(r);

    if ctx.ranges_mode {
        // Binary search in ranges array
        for r in &ctx.ranges {
            if ip_u32 >= r.start && ip_u32 <= r.end {
                if r.value_idx < ctx.values.len() {
                    v.data.clone_from(&ctx.values[r.value_idx]);
                    return NGX_OK;
                }
            }
        }
    } else {
        // IPv4 radix tree lookup
        if let Some(ref tree) = ctx.tree {
            let result = tree.find32(ip_u32);
            if result != 0 {
                let idx = (result - 1) as usize;
                if idx < ctx.values.len() {
                    v.data.clone_from(&ctx.values[idx]);
                    return NGX_OK;
                }
            }
        }
    }

    // Use default value
    if !ctx.default_value.is_empty() {
        v.data.clone_from(&ctx.default_value);
    }

    NGX_OK
}

fn parse_ipv4_to_u32(s: &[u8]) -> Option<u32> {
    let s_str = std::str::from_utf8(s).ok()?;
    let parts: Vec<&str> = s_str.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut ip = 0u32;
    for part in parts {
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        ip = (ip << 8) | octet;
    }
    Some(ip)
}

fn parse_ip_range(s: &[u8]) -> Option<(u32, u32)> {
    let s_str = std::str::from_utf8(s).ok()?;
    if let Some(dash_pos) = s_str.find('-') {
        let start_str = &s_str[..dash_pos];
        let end_str = &s_str[dash_pos + 1..];

        let start = parse_ipv4_to_u32(start_str.as_bytes())?;
        let end = parse_ipv4_to_u32(end_str.as_bytes())?;

        Some((start, end))
    } else {
        None
    }
}

fn get_remote_addr_u32(r: &R) -> u32 {
    let addr = r.connection.sockaddr.borrow();
    match &*addr {
        SockAddr::V4(v4) => {
            let octets = v4.ip().octets();
            u32::from_be_bytes(octets)
        }
        _ => 0,
    }
}

fn parse_cidr(s: &[u8]) -> Option<(u32, u32)> {
    let s_str = std::str::from_utf8(s).ok()?;
    if let Some(slash_pos) = s_str.find('/') {
        let ip_part = &s_str[..slash_pos];
        let prefix_part = &s_str[slash_pos + 1..];

        let ip = parse_ipv4_to_u32(ip_part.as_bytes())?;
        let prefix_len: u32 = prefix_part.parse().ok()?;

        if prefix_len > 32 {
            return None;
        }

        let mask = if prefix_len == 0 {
            0
        } else {
            (0xffffffffu32) << (32 - prefix_len)
        };

        Some((ip & mask, mask))
    } else {
        let ip = parse_ipv4_to_u32(s)?;
        Some((ip, 0xffffffff))
    }
}

fn geo_block_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();

    if args.len() < 2 {
        return Err(msg("requires at least 1 argument"));
    }

    let var_arg = &args[args.len() - 1];
    if var_arg.is_empty() || var_arg[0] != b'$' {
        return Err(msg("invalid variable name"));
    }

    let var = add_variable(cf, &var_arg[1..], NGX_HTTP_VAR_CHANGEABLE)?;

    let ctx = Box::leak(Box::new(GeoCtx {
        default_value: Vec::new(),
        tree: Some(RadixTree::create(-1)),
        values: Vec::new(),
        ranges_mode: false,
        ranges: Vec::new(),
    }));

    var.get_handler.set(Some(geo_variable));
    let ctx_ptr = ctx as *const _ as usize;
    var.data.set(ctx_ptr);

    let saved_h = cf.handler.take();
    let saved_hc = cf.handler_conf.take();
    cf.handler = Some(geo_item_handler);
    cf.handler_conf = Some(Rc::new(ctx_ptr));

    cf.parse_block()?;

    cf.handler = saved_h;
    cf.handler_conf = saved_hc;

    // Sort ranges if in ranges mode
    if ctx.ranges_mode {
        ctx.ranges.sort_by_key(|r| r.start);
    }

    Ok(())
}

fn geo_item_handler(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let args = cf.args.clone();
    if args.is_empty() {
        return Ok(());
    }

    let ctx_ptr = *conf.downcast_ref::<usize>()
        .ok_or_else(|| msg("invalid conf"))?;
    let ctx = unsafe { &mut *(ctx_ptr as *mut GeoCtx) };

    match &args[0][..] {
        b"default" => {
            if args.len() >= 2 {
                ctx.default_value = args[1].clone();
            }
            Ok(())
        }
        b"ranges" => {
            ctx.ranges_mode = true;
            Ok(())
        }
        b"include" => {
            if args.len() >= 2 {
                // TODO: implement include file reading
            }
            Ok(())
        }
        b"delete" => {
            if args.len() >= 2 {
                // TODO: implement delete
            }
            Ok(())
        }
        b"proxy" | b"proxy_recursive" => {
            // Proxy directives - for now just accept
            Ok(())
        }
        _ => {
            // Parse entry (CIDR or range depending on mode)
            if args.len() >= 2 {
                let value = &args[1];
                let value_idx = ctx.values.len();
                ctx.values.push(value.clone());

                if ctx.ranges_mode {
                    // Parse as IP range (127.0.0.0-127.0.0.1)
                    if let Some((start, end)) = parse_ip_range(&args[0]) {
                        ctx.ranges.push(GeoRange { start, end, value_idx });
                        Ok(())
                    } else {
                        Err(cf.emerg(format_args!("invalid range in \"{}\"", B(&args[0]))))
                    }
                } else {
                    // Parse as CIDR (192.0.2.0/24 or 192.0.2.0)
                    if let Some((ip, mask)) = parse_cidr(&args[0]) {
                        if let Some(ref tree) = ctx.tree {
                            tree.insert32(ip, mask, (value_idx + 1) as usize);
                        }
                        Ok(())
                    } else {
                        Err(cf.emerg(format_args!("invalid network in \"{}\"", B(&args[0]))))
                    }
                }
            } else {
                Ok(())
            }
        }
    }
}

pub fn geo_module() -> ModuleDef {
    let def = HttpModuleDef {
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!(
            "geo",
            NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE12,
            ConfLevel::Main,
            geo_block_handler
        ),
    ];
    http_module_def("ngx_http_geo_module", def, commands)
}
