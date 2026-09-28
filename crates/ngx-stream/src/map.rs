//! ngx_stream_map_module.c: the "map" block, a variable whose value
//! depends on the value of another (complex) value.

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::regex::NGX_REGEX_CASELESS;
use ngx_core::string::{dns_strcmp, to_lower_vec, B};
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

use crate::script::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_map_module");

/// ngx_stream_map_conf_t
pub struct MapConf {
    pub hash_max_size: Val<i64>,
    pub hash_bucket_size: Val<i64>,

    /// The maps of the "map" blocks: the variables' data point to them
    /// (the configuration pool in C).
    pub maps: Vec<Rc<MapCtx>>,
}

/// A value of a map: ngx_stream_variable_value_t, where "valid = 0" means
/// the data is a complex value.
#[derive(Debug)]
pub enum MapValue {
    Value(VariableValue),
    Complex(ComplexValue),
}

pub type MapVal = Rc<MapValue>;

/// ngx_stream_map_ctx_t
pub struct MapCtx {
    pub map: StreamMap<MapVal>,
    pub value: ComplexValue,
    pub default_value: MapVal,
    pub hostnames: bool,
}

/// ngx_stream_map_conf_ctx_t: the state while the map block is parsed
struct MapConfCtx {
    keys: HashKeysArrays<MapVal>,

    /// the values seen, so equal values share the same entry
    values_hash: HashMap<Vec<u8>, MapVal>,
    regexes: Vec<MapRegex<MapVal>>,

    default_value: Option<MapVal>,
    hostnames: bool,
    no_cacheable: bool,
}

/// ngx_stream_map_variable
fn map_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    // data is Rc::as_ptr() of a MapCtx kept alive by the MapConf of the
    // configuration the session uses (s->main_conf holds it)
    let map = unsafe { &*(data as *const MapCtx) };

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream map started");

    let mut val = match complex_value(s, &map.value) {
        Ok(v) => v,
        Err(()) => return NGX_ERROR,
    };

    if map.hostnames && val.last() == Some(&b'.') {
        val.pop();
    }

    let value = map_find(s, &map.map, &val).unwrap_or_else(|| map.default_value.clone());

    match &*value {
        MapValue::Complex(cv) => {
            let str = match complex_value(s, cv) {
                Ok(v) => v,
                Err(()) => return NGX_ERROR,
            };

            *v = VariableValue { data: str, valid: true, no_cacheable: false, not_found: false };
        }

        MapValue::Value(vv) => *v = vv.clone(),
    }

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream map: \"{}\" \"{}\"", B(&val), B(&v.data));

    NGX_OK
}

/// ngx_stream_map_create_conf
fn map_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(MapConf { hash_max_size: Val::unset(), hash_bucket_size: Val::unset(), maps: Vec::new() })
}

/// ngx_stream_map_block
fn map_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let mcf = conf_rc::<MapConf>(conf.as_ref().expect("map conf"));

    let (max_size, bucket_size) = {
        let mut m = mcf.borrow_mut();

        if !m.hash_max_size.is_set() {
            m.hash_max_size = Val::set(2048);
        }

        let cl = ngx_core::os::cacheline_size() as i64;

        if !m.hash_bucket_size.is_set() {
            m.hash_bucket_size = Val::set(cl);
        } else {
            let v = *m.hash_bucket_size;
            m.hash_bucket_size = Val::set((v + cl - 1) / cl * cl);
        }

        (*m.hash_max_size, *m.hash_bucket_size)
    };

    let value = cf.args.clone();

    let mut ccv = CompileComplexValue::default();
    let map_value = compile_complex_value(cf, &value[1], &mut ccv)?;

    let name = &value[2];

    if name.first() != Some(&b'$') {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(name))));
    }

    let var = add_variable(cf, &name[1..], NGX_STREAM_VAR_CHANGEABLE)?;

    var.get_handler.set(Some(map_variable));

    let ctx = Rc::new(RefCell::new(MapConfCtx {
        keys: HashKeysArrays::new(HashKind::Large),
        values_hash: HashMap::new(),
        regexes: Vec::new(),
        default_value: None,
        hostnames: false,
        no_cacheable: false,
    }));

    let saved_handler = cf.handler.take();
    let saved_handler_conf = cf.handler_conf.take();

    cf.handler = Some(map_handler);
    cf.handler_conf = Some(ctx.clone() as Rc<dyn Any>);

    let rv = cf.parse_block();

    cf.handler = saved_handler;
    cf.handler_conf = saved_handler_conf;

    rv?;

    let ctx = match Rc::try_unwrap(ctx) {
        Ok(c) => c.into_inner(),
        Err(_) => return Err(ConfError::Logged),
    };

    if ctx.no_cacheable {
        var.flags.set(var.flags.get() | NGX_STREAM_VAR_NOCACHEABLE);
    }

    let default_value = ctx.default_value.clone().unwrap_or_else(|| Rc::new(MapValue::Value(null_value())));

    let hinit = HashInit { name: "map_hash", max_size: max_size as usize, bucket_size: bucket_size as usize, log: &cf.log };

    let fail = |e: String| {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
        ConfError::Logged
    };

    let hash = if !ctx.keys.keys().is_empty() {
        Hash::init(&hinit, ctx.keys.keys().to_vec()).map_err(fail)?
    } else {
        // no exact keys: the hash is empty (hash.buckets == NULL in C)
        Hash::init(&HashInit { name: "map_hash", max_size: 1, bucket_size: bucket_size as usize, log: &cf.log }, Vec::new()).map_err(fail)?
    };

    let mut wc_head = None;
    let mut wc_tail = None;

    if !ctx.keys.dns_wc_head().is_empty() {
        let mut keys = ctx.keys.dns_wc_head().to_vec();
        keys.sort_by(map_cmp_dns_wildcards);
        wc_head = Some(HashWildcard::init(&hinit, keys).map_err(fail)?);
    }

    if !ctx.keys.dns_wc_tail().is_empty() {
        let mut keys = ctx.keys.dns_wc_tail().to_vec();
        keys.sort_by(map_cmp_dns_wildcards);
        wc_tail = Some(HashWildcard::init(&hinit, keys).map_err(fail)?);
    }

    let map = Rc::new(MapCtx {
        map: StreamMap { hash: HashCombined { hash, wc_head, wc_tail }, regex: ctx.regexes },
        value: map_value,
        default_value,
        hostnames: ctx.hostnames,
    });

    var.data.set(Rc::as_ptr(&map) as usize);

    mcf.borrow_mut().maps.push(map);

    Ok(())
}

/// ngx_stream_map_cmp_dns_wildcards (ngx_qsort)
fn map_cmp_dns_wildcards(one: &HashKey<MapVal>, two: &HashKey<MapVal>) -> std::cmp::Ordering {
    dns_strcmp(&one.key, &two.key).cmp(&0)
}

/// The "include" of a map block: ngx_conf_include() with the map handler.
fn map_include(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let dummy = Command::new("include", NGX_ANY_CONF | NGX_CONF_TAKE1, ConfLevel::None, conf_include);
    conf_include(cf, &dummy, Some(conf))
}

/// ngx_stream_map: a line of the map block
fn map_handler(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let ctx = conf.clone().downcast::<RefCell<MapConfCtx>>().expect("map conf ctx");

    let mut value = cf.args.clone();

    if value.len() == 1 && value[0] == b"hostnames" {
        ctx.borrow_mut().hostnames = true;
        return Ok(());
    }

    if value.len() == 1 && value[0] == b"volatile" {
        ctx.borrow_mut().no_cacheable = true;
        return Ok(());
    }

    if value.len() != 2 {
        return Err(cf.emerg(format_args!("invalid number of the map parameters")));
    }

    if value[0] == b"include" {
        return map_include(cf, conf);
    }

    let existing = ctx.borrow().values_hash.get(&value[1]).cloned();

    let var = match existing {
        Some(v) => v,
        None => {
            let v = value[1].clone();

            let mut ccv = CompileComplexValue::default();
            let cv = compile_complex_value(cf, &v, &mut ccv)?;

            let var = if !cv.is_constant() {
                Rc::new(MapValue::Complex(cv))
            } else {
                Rc::new(MapValue::Value(VariableValue { data: v.clone(), valid: true, no_cacheable: false, not_found: false }))
            };

            ctx.borrow_mut().values_hash.insert(v, var.clone());

            var
        }
    };

    // found:

    if value[0] == b"default" {
        if ctx.borrow().default_value.is_some() {
            return Err(cf.emerg(format_args!("duplicate default map parameter")));
        }

        ctx.borrow_mut().default_value = Some(var);

        return Ok(());
    }

    if value[0].first() == Some(&b'~') {
        let mut pattern = &value[0][1..];
        let mut options = 0;

        if pattern.first() == Some(&b'*') {
            pattern = &pattern[1..];
            options = NGX_REGEX_CASELESS;
        }

        let pattern = pattern.to_vec();

        let regex = regex_compile(cf, &pattern, options)?;

        ctx.borrow_mut().regexes.push(MapRegex { regex, value: var });

        return Ok(());
    }

    if value[0].first() == Some(&b'\\') {
        value[0].remove(0);
    }

    let key = value[0].clone();

    let rv = {
        let mut c = ctx.borrow_mut();
        let flags = if c.hostnames { NGX_HASH_WILDCARD_KEY } else { 0 };
        c.keys.add_key(key.clone(), var, flags)
    };

    if rv == NGX_OK {
        return Ok(());
    }

    if rv == NGX_DECLINED {
        return Err(cf.emerg(format_args!("invalid hostname or wildcard \"{}\"", B(&key))));
    }

    if rv == NGX_BUSY {
        // ngx_hash_add_key() lowercases the key in place
        return Err(cf.emerg(format_args!("conflicting parameter \"{}\"", B(&to_lower_vec(&key)))));
    }

    Err(ConfError::Logged)
}

pub fn map_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_map_module",
        StreamModuleDef { create_main_conf: Some(map_create_conf), ..Default::default() },
        vec![
            cmd_fn!("map", NGX_STREAM_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, map_block),
            cmd!("map_hash_max_size", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, MapConf, hash_max_size, set_num),
            cmd!("map_hash_bucket_size", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, MapConf, hash_bucket_size, set_num),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_wildcards_sort() {
        let v: MapVal = Rc::new(MapValue::Value(null_value()));
        let mut keys = vec![
            HashKey { key: b"org.example".to_vec(), key_hash: 0, value: v.clone() },
            HashKey { key: b"com.example.".to_vec(), key_hash: 0, value: v.clone() },
            HashKey { key: b"com.example".to_vec(), key_hash: 0, value: v.clone() },
        ];
        keys.sort_by(map_cmp_dns_wildcards);
        assert_eq!(keys[0].key, b"com.example");
        assert_eq!(keys[1].key, b"com.example.");
        assert_eq!(keys[2].key, b"org.example");
    }
}
