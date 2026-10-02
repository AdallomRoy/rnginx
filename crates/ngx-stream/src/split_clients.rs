//! ngx_stream_split_clients_module.c: a variable for A/B testing, the
//! value is chosen by the MurmurHash2 of a complex value.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::{atofp, B};
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::script::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_split_clients_module");

/// ngx_stream_split_clients_part_t
pub struct SplitClientsPart {
    pub percent: u32,
    pub value: VariableValue,
}

/// ngx_stream_split_clients_ctx_t
pub struct SplitClientsCtx {
    pub value: ComplexValue,
    pub parts: Vec<SplitClientsPart>,
}

/// The contexts of the split_clients blocks (the configuration pool in C;
/// the C module has no main conf): the variables' data is the index of
/// their context.
#[derive(Default)]
pub struct SplitClientsMainConf {
    pub ctxs: Vec<Rc<SplitClientsCtx>>,
}

/// ngx_murmur_hash2 (src/core/ngx_murmurhash.c)
pub fn murmur_hash2(data: &[u8]) -> u32 {
    let mut h: u32 = data.len() as u32;

    let mut chunks = data.chunks_exact(4);

    for c in &mut chunks {
        let mut k = c[0] as u32;
        k |= (c[1] as u32) << 8;
        k |= (c[2] as u32) << 16;
        k |= (c[3] as u32) << 24;

        k = k.wrapping_mul(0x5bd1e995);
        k ^= k >> 24;
        k = k.wrapping_mul(0x5bd1e995);

        h = h.wrapping_mul(0x5bd1e995);
        h ^= k;
    }

    let rest = chunks.remainder();

    if rest.len() == 3 {
        h ^= (rest[2] as u32) << 16;
    }

    if rest.len() >= 2 {
        h ^= (rest[1] as u32) << 8;
    }

    if !rest.is_empty() {
        h ^= rest[0] as u32;
        h = h.wrapping_mul(0x5bd1e995);
    }

    h ^= h >> 13;
    h = h.wrapping_mul(0x5bd1e995);
    h ^= h >> 15;

    h
}

/// ngx_stream_split_clients_variable
fn split_clients_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    // data: the index of the context in the module's main conf
    let ctx = s.main_conf::<SplitClientsMainConf>(ctx_index()).borrow().ctxs[data].clone();

    *v = null_value();

    let val = match complex_value(s, &ctx.value) {
        Ok(v) => v,
        Err(()) => return NGX_OK,
    };

    let hash = murmur_hash2(&val);

    for part in ctx.parts.iter() {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream split: {} {}", hash, part.percent);

        if hash < part.percent || part.percent == 0 {
            *v = part.value.clone();
            return NGX_OK;
        }
    }

    NGX_OK
}

fn split_clients_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SplitClientsMainConf::default())
}

/// ngx_conf_split_clients_block
fn split_clients_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let value = cf.args.clone();

    let mut ccv = CompileComplexValue::default();
    let cv = compile_complex_value(cf, &value[1], &mut ccv)?;

    let name = &value[2];

    if name.first() != Some(&b'$') {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(name))));
    }

    let var = add_variable(cf, &name[1..], NGX_STREAM_VAR_CHANGEABLE)?;

    var.get_handler.set(Some(split_clients_variable));

    let parts: Rc<RefCell<Vec<SplitClientsPart>>> = Rc::new(RefCell::new(Vec::new()));

    let saved_handler = cf.handler.take();
    let saved_handler_conf = cf.handler_conf.take();

    cf.handler = Some(split_clients);
    cf.handler_conf = Some(parts.clone() as Rc<dyn Any>);

    let rv = cf.parse_block();

    cf.handler = saved_handler;
    cf.handler_conf = saved_handler_conf;

    rv?;

    let mut parts = std::mem::take(&mut *parts.borrow_mut());

    let mut sum: u32 = 0;
    let mut last: u32 = 0;

    for part in parts.iter_mut() {
        sum = if part.percent != 0 { sum.wrapping_add(part.percent) } else { 10000 };

        if sum == 10000 {
            part.percent = 0;
        }

        if sum > 10000 {
            return Err(cf.emerg(format_args!("percent total is greater than 100%")));
        }

        if part.percent != 0 {
            last = last.wrapping_add((part.percent as u64 * 0xffffffff / 10000) as u32);
            part.percent = last;
        }
    }

    let ctx = Rc::new(SplitClientsCtx { value: cv, parts });

    let mcf = conf_rc::<SplitClientsMainConf>(conf.as_ref().expect("split_clients conf"));
    let mut m = mcf.borrow_mut();

    var.data.set(m.ctxs.len());

    m.ctxs.push(ctx);

    Ok(())
}

/// ngx_stream_split_clients: a "percent value" line of the block
fn split_clients(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let parts = conf.downcast::<RefCell<Vec<SplitClientsPart>>>().expect("split_clients parts");

    let value = cf.args.clone();

    let percent = if value[0] == b"*" {
        0
    } else {
        let n = if value[0].last() != Some(&b'%') { None } else { atofp(&value[0][..value[0].len() - 1], 2) };

        match n {
            Some(n) if n != 0 => n as u32,
            _ => return Err(cf.emerg(format_args!("invalid percent value \"{}\"", B(&value[0])))),
        }
    };

    // the value is value[1], the other words are not checked
    let data = value.get(1).cloned().unwrap_or_default();

    parts.borrow_mut().push(SplitClientsPart { percent, value: VariableValue { data, valid: true, no_cacheable: false, not_found: false } });

    Ok(())
}

pub fn split_clients_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_split_clients_module",
        StreamModuleDef { create_main_conf: Some(split_clients_create_main_conf), ..Default::default() },
        vec![cmd_fn!("split_clients", NGX_STREAM_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, split_clients_block)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur() {
        // values of ngx_murmur_hash2()
        assert_eq!(murmur_hash2(b""), 0);
        assert_eq!(murmur_hash2(b"1"), 0x49342faf);
        assert_eq!(murmur_hash2(b"hello"), 0xe56129cb);
        assert_eq!(murmur_hash2(b"hello, world"), 0x4b4c9d80);
        assert_eq!(murmur_hash2(b"\xff\xfe\xfd"), 0x3d614590);
    }
}
