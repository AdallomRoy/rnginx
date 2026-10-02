//! ngx_http_map_module: the "map" block, a variable whose value depends on
//! the value of another (complex) value: exact and wildcard keys in a
//! combined hash (ngx_hash_find_combined), then the regexes.

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::regex::NGX_REGEX_CASELESS;
use ngx_core::string::{dns_strcmp, to_lower_vec, B};
use ngx_core::{cmd, cmd_fn, ngx_log_error};

use crate::script::*;
use crate::variables::*;
use crate::{request::*, *};

crate::http_module_index!("ngx_http_map_module");

/// ngx_http_map_conf_t
pub struct MapMainConf {
    pub hash_max_size: Val<i64>,
    pub hash_bucket_size: Val<i64>,
    /// The maps of the "map" blocks (the configuration pool in C): the
    /// variables' data is the index of their map.
    pub maps: Vec<Rc<MapCtx>>,
}

/// A value of a map: ngx_http_variable_value_t, where "valid = 0" means
/// the data is a complex value.
pub enum MapValue {
    Value(VariableValue),
    Complex(ComplexValue),
}

pub type MapVal = Rc<MapValue>;

/// ngx_http_map_regex_t
pub struct MapRegex {
    pub regex: Rc<HttpRegex>,
    pub value: MapVal,
}

/// ngx_http_map_t
pub struct HttpMap {
    pub hash: HashCombined<MapVal>,
    pub regex: Vec<MapRegex>,
}

/// ngx_http_map_ctx_t
pub struct MapCtx {
    pub map: HttpMap,
    pub value: ComplexValue,
    pub default_value: MapVal,
    pub hostnames: bool,
}

/// ngx_http_map_conf_ctx_t: the state while the map block is parsed
struct MapConfCtx {
    keys: HashKeysArrays<MapVal>,

    /// the values seen, so equal values share the same entry
    values_hash: HashMap<Vec<u8>, MapVal>,
    regexes: Vec<MapRegex>,

    default_value: Option<MapVal>,
    hostnames: bool,
    no_cacheable: bool,
}

/// What the hash part of ngx_http_map_find() found for a value
enum Found<'a> {
    Value(&'a MapVal),
    /// not in the hash: the value (a copy) for the regexes
    Regex(Vec<u8>),
    None,
}

/// ngx_http_map_variable
fn map_variable(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    // data: the index of the map in the module's main conf
    let map = r.main_conf::<MapMainConf>(ctx_index()).borrow().maps[data].clone();

    http_debug!(r, "http map started");

    let debug = r.connection.log.debug_enabled(NGX_LOG_DEBUG_HTTP);

    // the value is looked up in the hash where it is (a variable's cached
    // value); the regexes, which set the captures and the variables of the
    // request, match a copy of it
    let looked_up = with_complex_value(r, &map.value, |val| {
        let val = if map.hostnames && val.last() == Some(&b'.') { &val[..val.len() - 1] } else { val };

        let shown = if debug { val.to_vec() } else { Vec::new() };

        let found = match map_find_hash(&map.map, val) {
            Some(value) => Found::Value(value),
            None if !val.is_empty() && !map.map.regex.is_empty() => Found::Regex(val.to_vec()),
            None => Found::None,
        };

        (found, shown)
    });

    let (found, shown) = match looked_up {
        Ok(f) => f,
        Err(_) => return NGX_ERROR,
    };

    let value = match found {
        Found::Value(value) => Some(value),
        Found::Regex(val) => map_find_regex(r, &map.map, &val),
        Found::None => None,
    };

    match &**value.unwrap_or(&map.default_value) {
        MapValue::Complex(cv) => {
            let str = match complex_value(r, cv) {
                Ok(s) => s,
                Err(_) => return NGX_ERROR,
            };

            *v = VariableValue { data: str, valid: true, no_cacheable: false, not_found: false, escape: false };
        }

        MapValue::Value(vv) => *v = vv.clone(),
    }

    http_debug!(r, "http map: \"{}\" \"{}\"", B(&shown), B(&v.data));

    NGX_OK
}

/// The hash part of ngx_http_map_find(): the value lowercased
/// (ngx_hash_strlow, on the stack for the usual values) and looked up with
/// ngx_hash_find_combined()
fn map_find_hash<'a>(map: &'a HttpMap, val: &[u8]) -> Option<&'a MapVal> {
    let mut stack = [0u8; 256];
    let mut heap = Vec::new();

    let low: &mut [u8] = if val.len() <= stack.len() {
        &mut stack[..val.len()]
    } else {
        heap.resize(val.len(), 0);
        &mut heap
    };

    let key = hash_strlow(low, val);

    map.hash.find(key, low)
}

/// The regex part of ngx_http_map_find(): the value of the first regex that
/// matches the value; None when none does, or on an error (NULL)
fn map_find_regex<'a>(r: &R, map: &'a HttpMap, val: &[u8]) -> Option<&'a MapVal> {
    for reg in map.regex.iter() {
        let n = regex_exec(r, &reg.regex, val);

        if n == NGX_OK {
            return Some(&reg.value);
        }

        if n == NGX_DECLINED {
            continue;
        }

        // NGX_ERROR

        return None;
    }

    None
}

/// ngx_http_map_create_conf
fn map_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(MapMainConf { hash_max_size: Val::unset(), hash_bucket_size: Val::unset(), maps: Vec::new() })
}

/// ngx_http_map_block
fn map_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let mcf = conf_rc::<MapMainConf>(conf.as_ref().expect("map conf"));

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

    let map_value = compile_complex_value(cf, &value[1], 0)?;

    let name = &value[2];

    if name.first() != Some(&b'$') {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(name))));
    }

    let var = add_variable(cf, &name[1..], NGX_HTTP_VAR_CHANGEABLE)?;

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
        var.flags.set(var.flags.get() | NGX_HTTP_VAR_NOCACHEABLE);
    }

    // ngx_http_variable_null_value
    let default_value = ctx.default_value.clone().unwrap_or_else(|| Rc::new(MapValue::Value(VariableValue { valid: true, ..Default::default() })));

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
        map: HttpMap { hash: HashCombined { hash, wc_head, wc_tail }, regex: ctx.regexes },
        value: map_value,
        default_value,
        hostnames: ctx.hostnames,
    });

    let mut m = mcf.borrow_mut();

    var.data.set(m.maps.len());

    m.maps.push(map);

    Ok(())
}

/// ngx_http_map_cmp_dns_wildcards (ngx_qsort)
fn map_cmp_dns_wildcards(one: &HashKey<MapVal>, two: &HashKey<MapVal>) -> std::cmp::Ordering {
    dns_strcmp(&one.key, &two.key).cmp(&0)
}

/// The "include" of a map block: ngx_conf_include() with the map handler.
fn map_include(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let dummy = Command::new("include", NGX_ANY_CONF | NGX_CONF_TAKE1, ConfLevel::None, conf_include);
    conf_include(cf, &dummy, Some(conf))
}

/// ngx_http_map: a line of the map block
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

            let cv = compile_complex_value(cf, &v, 0)?;

            let var = if !cv.is_constant() {
                Rc::new(MapValue::Complex(cv))
            } else {
                Rc::new(MapValue::Value(VariableValue { data: v.clone(), valid: true, no_cacheable: false, not_found: false, escape: false }))
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
    let def = HttpModuleDef { create_main_conf: Some(map_create_conf), ..Default::default() };
    let commands = vec![
        cmd_fn!("map", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, map_block),
        cmd!("map_hash_max_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, MapMainConf, hash_max_size, set_num),
        cmd!("map_hash_bucket_size", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, MapMainConf, hash_bucket_size, set_num),
    ];
    http_module_def("ngx_http_map_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val(s: &str) -> MapVal {
        Rc::new(MapValue::Value(VariableValue { data: s.as_bytes().to_vec(), valid: true, ..Default::default() }))
    }

    /// The combined hash of the keys of a block with "hostnames".
    fn hostnames_map(keys: &[(&str, &str)]) -> HttpMap {
        let mut k = HashKeysArrays::new(HashKind::Large);
        for (key, value) in keys {
            assert_eq!(k.add_key(key.as_bytes().to_vec(), val(value), NGX_HASH_WILDCARD_KEY), NGX_OK, "{}", key);
        }

        let log = Log::stderr(NGX_LOG_ALERT);
        let hinit = HashInit { name: "map_hash", max_size: 2048, bucket_size: 64, log: &log };

        let hash = Hash::init(&hinit, k.keys().to_vec()).unwrap();

        let mut head = k.dns_wc_head().to_vec();
        head.sort_by(map_cmp_dns_wildcards);
        let mut tail = k.dns_wc_tail().to_vec();
        tail.sort_by(map_cmp_dns_wildcards);

        let wc_head = if head.is_empty() { None } else { Some(HashWildcard::init(&hinit, head).unwrap()) };
        let wc_tail = if tail.is_empty() { None } else { Some(HashWildcard::init(&hinit, tail).unwrap()) };

        HttpMap { hash: HashCombined { hash, wc_head, wc_tail }, regex: Vec::new() }
    }

    fn find(map: &HttpMap, s: &str) -> Option<String> {
        map_find_hash(map, s.as_bytes()).map(|v| match &**v {
            MapValue::Value(vv) => String::from_utf8(vv.data.clone()).unwrap(),
            MapValue::Complex(_) => "complex".to_string(),
        })
    }

    #[test]
    fn exact_and_wildcards() {
        // the keys of map.t
        let map = hostnames_map(&[
            ("example.com", "foo"),
            ("example.*", "right-wildcard"),
            ("*.example.com", "left-wildcard"),
            (".dot.example.com", "special-wildcard"),
        ]);

        assert_eq!(find(&map, "example.com").as_deref(), Some("foo"));
        assert_eq!(find(&map, "EXAMPLE.COM").as_deref(), Some("foo"));
        assert_eq!(find(&map, "example.org").as_deref(), Some("right-wildcard"));
        assert_eq!(find(&map, "foo.example.com").as_deref(), Some("left-wildcard"));
        assert_eq!(find(&map, "dot.example.com").as_deref(), Some("special-wildcard"));
        assert_eq!(find(&map, "www.dot.example.com").as_deref(), Some("special-wildcard"));
        assert_eq!(find(&map, "regex.example.org").as_deref(), None);
        assert_eq!(find(&map, "example").as_deref(), None);
        assert_eq!(find(&map, "").as_deref(), None);

        // a value longer than the stack buffer is lowercased on the heap
        let long = format!("{}.example.com", "A".repeat(300));
        assert_eq!(find(&map, &long).as_deref(), Some("left-wildcard"));
    }

    #[test]
    fn many_keys() {
        let keys: Vec<(String, String)> = (0..5000).map(|i| (format!("key{}", i), format!("value{}", i))).collect();
        let refs: Vec<(&str, &str)> = keys.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let map = hostnames_map(&refs);

        for (k, v) in keys.iter().step_by(7) {
            assert_eq!(find(&map, k).as_deref(), Some(v.as_str()));
            assert_eq!(find(&map, &k.to_uppercase()).as_deref(), Some(v.as_str()));
        }

        assert_eq!(find(&map, "key5000"), None);
    }

    #[test]
    fn dns_wildcards_sort() {
        let v = val("");
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
