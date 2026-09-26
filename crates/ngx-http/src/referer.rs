//! ngx_http_referer_module - HTTP referer validation

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
use ngx_core::string::eq_ignore_case;

use crate::variables::{add_variable, NGX_HTTP_VAR_CHANGEABLE};
use crate::{request::*, *};

crate::http_module_index!("ngx_http_referer_module");

pub struct RefererLocConf {
    pub no_referer: bool,
    pub blocked_referer: bool,
    pub server_names: bool,
    pub referers: RefCell<Vec<Vec<u8>>>,
    pub regexes: RefCell<Vec<Rc<Regex>>>,
    pub hash_max_size: Val<u32>,
    pub hash_bucket_size: Val<u32>,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(RefererLocConf {
        no_referer: false,
        blocked_referer: false,
        server_names: false,
        referers: RefCell::new(Vec::new()),
        regexes: RefCell::new(Vec::new()),
        hash_max_size: Val::unset(),
        hash_bucket_size: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<RefererLocConf>(prev).borrow();
    let mut c = conf_cell::<RefererLocConf>(conf).borrow_mut();
    if !c.no_referer && !c.blocked_referer && !c.server_names
        && c.referers.borrow().is_empty() && c.regexes.borrow().is_empty()
    {
        c.no_referer = p.no_referer;
        c.blocked_referer = p.blocked_referer;
        c.server_names = p.server_names;
        c.referers = RefCell::new(p.referers.borrow().clone());
        c.regexes = RefCell::new(p.regexes.borrow().clone());
    }
    c.hash_max_size.merge(&p.hash_max_size, 2048);
    c.hash_bucket_size.merge(&p.hash_bucket_size, 64);
    Ok(())
}

fn invalid_referer_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    // Match ngx_http_referer_variable:
    //   1. No config     -> valid.
    //   2. No Referer    -> no_referer ? valid : invalid.
    //   3. Strip scheme  -> !scheme ? (blocked_referer ? valid : invalid) : continue.
    //   4. Extract host (up to '/' or ':').
    //   5. Look up host in exact/wildcard list; if entry has URI, require prefix match.
    //   6. Regex match on host (server_names) or full referer (regex list).
    //   7. Otherwise invalid.
    let rlcf = r.loc_conf::<RefererLocConf>(ctx_index());

    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data.clear();

    let rlcf = rlcf.borrow();

    let has_config = rlcf.no_referer
        || rlcf.blocked_referer
        || rlcf.server_names
        || !rlcf.referers.borrow().is_empty()
        || !rlcf.regexes.borrow().is_empty();
    if !has_config {
        return NGX_OK;
    }

    // C distinguishes 'no Referer header at all' (headers_in.referer == NULL)
    // from 'Referer header with empty value'. no_referer only matches the
    // absent case; an empty referer falls through to blocked_referer.
    let (has_referer, referer_value): (bool, Vec<u8>) = {
        let hin = r.headers_in.borrow();
        match hin.referer.first() {
            Some(h) => (true, h.value.borrow().clone()),
            None => (false, Vec::new()),
        }
    };

    if !has_referer {
        if rlcf.no_referer {
            return NGX_OK;
        }
        v.data = b"1".to_vec();
        return NGX_OK;
    }

    // Strip scheme (only if the URL is long enough to plausibly contain one —
    // C guards with `len >= sizeof("http://i.ru") - 1` = 11).
    let ref_bytes = &referer_value[..];
    let stripped: Option<&[u8]> = if ref_bytes.len() < 11 {
        None
    } else if ref_bytes[..7].eq_ignore_ascii_case(b"http://") {
        Some(&ref_bytes[7..])
    } else if ref_bytes.len() >= 8 && ref_bytes[..8].eq_ignore_ascii_case(b"https://") {
        Some(&ref_bytes[8..])
    } else {
        None
    };

    let after_scheme = match stripped {
        Some(s) => s,
        None => {
            if rlcf.blocked_referer {
                return NGX_OK;
            }
            v.data = b"1".to_vec();
            return NGX_OK;
        }
    };

    // Extract host up to '/' or ':' (skip port).
    let mut host_end = 0;
    while host_end < after_scheme.len() {
        let ch = after_scheme[host_end];
        if ch == b'/' || ch == b':' { break; }
        host_end += 1;
        if host_end > 256 { // C's 256-byte buf limit
            v.data = b"1".to_vec();
            return NGX_OK;
        }
    }
    let host_bytes = &after_scheme[..host_end];
    let host_lower = ngx_core::string::to_lower_vec(host_bytes);

    // The rest after the host — starts with '/' or ':port/...' — used for URI-prefix
    // matching against configured referers that carry a URI.
    let ref_uri_start = {
        // Skip ':port' if present, then keep from '/'.
        let mut i = host_end;
        if i < after_scheme.len() && after_scheme[i] == b':' {
            while i < after_scheme.len() && after_scheme[i] != b'/' { i += 1; }
        }
        i
    };
    let ref_uri = &after_scheme[ref_uri_start..];

    // server_names option matches if the host equals any server_name (or wildcard/regex).
    if rlcf.server_names {
        let scf = r.cscf();
        let scf = scf.borrow();
        for sn in &scf.server_names {
            // Regex server names: try match. Exact/wildcard: compare lowercase.
            if let Some(re) = &sn.regex {
                if crate::variables::regex_exec(r, re, &host_lower) == NGX_OK {
                    return NGX_OK;
                }
            } else if wildcard_or_exact_match(&sn.name, &host_lower) {
                return NGX_OK;
            }
        }
    }

    // Check configured referer entries: each is "host" or "host/uri-prefix"
    // (host part is case-insensitive; scheme was already stripped).
    for entry in rlcf.referers.borrow().iter() {
        // Split entry into host + optional uri part.
        let (entry_host, entry_uri) = if let Some(slash) = entry.iter().position(|&b| b == b'/') {
            (&entry[..slash], &entry[slash..])
        } else {
            (&entry[..], &[][..])
        };
        if !wildcard_or_exact_match(entry_host, &host_lower) {
            continue;
        }
        if !entry_uri.is_empty() {
            if ref_uri.len() < entry_uri.len() || !ref_uri.starts_with(entry_uri) {
                continue;
            }
        }
        return NGX_OK;
    }

    // ~pattern regex match: C tests against `ref`, the after-scheme URL
    // (host+port+path), not the full referer including scheme.
    for regex in rlcf.regexes.borrow().iter() {
        if regex.is_match(after_scheme) {
            return NGX_OK;
        }
    }

    v.data = b"1".to_vec();
    NGX_OK
}

/// Case-insensitive match with wildcard support:
///   *.foo.com  matches sub.foo.com
///   foo.*      matches foo.com, foo.org
///   .foo.com   matches foo.com AND sub.foo.com
fn wildcard_or_exact_match(pattern: &[u8], host: &[u8]) -> bool {
    if pattern.starts_with(b"*.") {
        let suffix = &pattern[1..]; // ".foo.com"
        return host.len() > suffix.len() && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix);
    }
    if pattern.ends_with(b".*") {
        let prefix = &pattern[..pattern.len() - 1]; // "foo."
        return host.len() > prefix.len() && host[..prefix.len()].eq_ignore_ascii_case(prefix);
    }
    if pattern.starts_with(b".") {
        if host.len() == pattern.len() - 1 && host.eq_ignore_ascii_case(&pattern[1..]) {
            return true;
        }
        return host.len() >= pattern.len() && host[host.len() - pattern.len()..].eq_ignore_ascii_case(pattern);
    }
    pattern.len() == host.len() && pattern.eq_ignore_ascii_case(host)
}

fn valid_referers_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let rlcf = conf_cell::<RefererLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    for arg in args.iter().skip(1) {
        if arg == b"none" {
            rlcf.borrow_mut().no_referer = true;
        } else if arg == b"blocked" {
            rlcf.borrow_mut().blocked_referer = true;
        } else if arg == b"server_names" {
            rlcf.borrow_mut().server_names = true;
        } else if !arg.is_empty() && arg[0] == b'~' {
            // C's valid_referers regex is always compiled CASELESS; the (?-i)
            // inline modifier is used in-pattern to disable case-insensitivity.
            let pattern = &arg[1..];
            let flags = ngx_core::regex::NGX_REGEX_CASELESS;
            match Regex::compile(pattern, flags) {
                Ok(regex) => {
                    rlcf.borrow_mut().regexes.borrow_mut().push(regex);
                }
                Err(e) => return Err(cf.emerg(format_args!("regex error: {}", e))),
            }
        } else {
            rlcf.borrow_mut().referers.borrow_mut().push(arg.clone());
        }
    }

    Ok(())
}

fn set_num(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let rlcf = conf_cell::<RefererLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() < 2 {
        return Err(msg("requires an argument"));
    }

    let val_str = std::str::from_utf8(&args[1]).map_err(|_| msg("invalid number"))?;
    let val: u32 = val_str.parse().map_err(|_| msg("invalid number"))?;

    if args[0] == b"referer_hash_max_size" {
        rlcf.borrow_mut().hash_max_size = Val::set(val);
    } else if args[0] == b"referer_hash_bucket_size" {
        rlcf.borrow_mut().hash_bucket_size = Val::set(val);
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
            valid_referers_directive
        ),
        ngx_core::cmd_fn!(
            "referer_hash_max_size",
            NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            set_num
        ),
        ngx_core::cmd_fn!(
            "referer_hash_bucket_size",
            NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            set_num
        ),
    ];
    http_module_def("ngx_http_referer_module", def, commands)
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let var = add_variable(cf, b"invalid_referer", NGX_HTTP_VAR_CHANGEABLE)?;
    var.get_handler.set(Some(invalid_referer_variable));
    Ok(())
}
