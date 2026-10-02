//! ngx_http_split_clients_module - A/B testing with murmurhash

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::ngx_log_debug;

use crate::script::ComplexValue;
use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::{request::*, *};

crate::http_module_index!("ngx_http_split_clients_module");

fn murmur_hash2(data: &[u8]) -> u32 {
    let mut h = 0u32 ^ (data.len() as u32);
    let mut i = 0;
    let len = data.len();

    while i + 4 <= len {
        let mut k = u32::from(data[i]) |
                    (u32::from(data[i+1]) << 8) |
                    (u32::from(data[i+2]) << 16) |
                    (u32::from(data[i+3]) << 24);

        k = k.wrapping_mul(0x5bd1e995);
        k ^= k >> 24;
        k = k.wrapping_mul(0x5bd1e995);

        h = h.wrapping_mul(0x5bd1e995);
        h ^= k;
        i += 4;
    }

    match len - i {
        3 => {
            h ^= (data[i+2] as u32) << 16;
            h ^= (data[i+1] as u32) << 8;
            h ^= data[i] as u32;
            h = h.wrapping_mul(0x5bd1e995);
        }
        2 => {
            h ^= (data[i+1] as u32) << 8;
            h ^= data[i] as u32;
            h = h.wrapping_mul(0x5bd1e995);
        }
        1 => {
            h ^= data[i] as u32;
            h = h.wrapping_mul(0x5bd1e995);
        }
        _ => {}
    }

    h ^= h >> 13;
    h = h.wrapping_mul(0x5bd1e995);
    h ^= h >> 15;
    h
}

struct SplitClientsPart {
    percent: u32,
    value: Vec<u8>,
}

pub struct SplitClientsCtx {
    pub cv: ComplexValue,
    pub parts: RefCell<Vec<SplitClientsPart>>,
}

/// The contexts of the "split_clients" blocks (the configuration pool in
/// C; the C module has no main conf): the variables' data is the index of
/// their context.
#[derive(Default)]
pub struct SplitClientsMainConf {
    pub ctxs: Vec<Rc<SplitClientsCtx>>,
}

fn split_clients_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SplitClientsMainConf::default())
}

fn split_clients_variable(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    // data: the index of the context in the module's main conf
    let ctx = r.main_conf::<SplitClientsMainConf>(ctx_index()).borrow().ctxs[data].clone();

    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data.clear();

    match crate::script::complex_value(r, &ctx.cv) {
        Ok(val) => {
            let hash = murmur_hash2(&val);
            let parts = ctx.parts.borrow();
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http split: hash={}", hash);

            for part in parts.iter() {
                if hash < part.percent || part.percent == 0 {
                    v.data.clone_from(&part.value);
                    return NGX_OK;
                }
            }
            NGX_OK
        }
        Err(_) => NGX_OK,
    }
}

fn parse_atofp(data: &[u8], point: usize) -> Result<i64, ()> {
    if data.is_empty() {
        return Err(());
    }
    let mut value: i64 = 0;
    let mut dot = 0;
    for &c in data {
        if point == 0 {
            return Err(());
        }
        if c == b'.' {
            if dot != 0 {
                return Err(());
            }
            dot = 1;
        } else if c >= b'0' && c <= b'9' {
            value = value * 10 + (c - b'0') as i64;
            if dot == 1 {
                dot = 2;
            }
        } else {
            return Err(());
        }
    }
    for _ in 0..(point - dot.max(1) + 1) {
        value *= 10;
    }
    if value == 0 {
        Err(())
    } else {
        Ok(value)
    }
}

fn split_clients_item_handler(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() != 2 {
        return Err(msg("requires exactly 2 arguments"));
    }

    let percent_str = &args[0];
    let value = &args[1];

    let ctx = conf.downcast::<SplitClientsCtx>().map_err(|_| msg("invalid conf"))?;

    let percent = if percent_str == b"*" {
        0u32
    } else {
        if percent_str.is_empty() || percent_str[percent_str.len()-1] != b'%' {
            return Err(msg("invalid percent value"));
        }
        let num_part = &percent_str[..percent_str.len()-1];
        let n = parse_atofp(num_part, 2).map_err(|_| msg("invalid percent value"))?;
        if n == 0 || n > 10000 {
            return Err(msg("invalid percent value"));
        }
        n as u32
    };

    ctx.parts.borrow_mut().push(SplitClientsPart {
        percent,
        value: value.clone(),
    });

    Ok(())
}

fn split_clients_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
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

    let ctx = Rc::new(SplitClientsCtx {
        cv,
        parts: RefCell::new(Vec::new()),
    });

    let index = {
        let mcf = conf_rc::<SplitClientsMainConf>(conf.as_ref().ok_or_else(|| msg("no conf"))?);
        let mut m = mcf.borrow_mut();
        m.ctxs.push(ctx.clone());
        m.ctxs.len() - 1
    };

    var.get_handler.set(Some(split_clients_variable));
    var.data.set(index);

    let saved_h = cf.handler.take();
    let saved_hc = cf.handler_conf.take();
    cf.handler = Some(split_clients_item_handler);
    cf.handler_conf = Some(ctx.clone() as Rc<dyn Any>);

    cf.parse_block()?;

    cf.handler = saved_h;
    cf.handler_conf = saved_hc;

    let mut parts = ctx.parts.borrow_mut();
    let mut sum = 0u32;
    let mut last = 0u64;
    for part in parts.iter_mut() {
        sum = if part.percent != 0 { sum + part.percent } else { 10000 };

        if sum == 10000 {
            part.percent = 0;
        }

        if sum > 10000 {
            return Err(cf.emerg(format_args!("percent total is greater than 100%")));
        }

        if part.percent != 0 {
            last += (part.percent as u64) * 0xffffffff / 10000;
            part.percent = last as u32;
        }
    }

    Ok(())
}

pub fn split_clients_module() -> ModuleDef {
    let def = HttpModuleDef {
        create_main_conf: Some(split_clients_create_main_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!(
            "split_clients",
            NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2,
            ConfLevel::Main,
            split_clients_directive
        ),
    ];
    http_module_def("ngx_http_split_clients_module", def, commands)
}
