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
    if !c.no_referer && !c.blocked_referer && !c.server_names && c.referers.borrow().is_empty() {
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
    let rlcf = r.loc_conf::<RefererLocConf>(ctx_index());

    v.valid = true;
    v.not_found = false;
    v.no_cacheable = false;
    v.escape = false;
    v.data.clear();

    let rlcf = rlcf.borrow();

    // If no referers are configured, it's valid
    if !rlcf.no_referer && !rlcf.blocked_referer && !rlcf.server_names && rlcf.referers.borrow().is_empty() && rlcf.regexes.borrow().is_empty() {
        return NGX_OK;
    }

    let headers_in = r.headers_in.borrow();
    let referer_value = if let Some(ref_header) = headers_in.referer.first() {
        ref_header.value.borrow().clone()
    } else {
        Vec::new()
    };

    if referer_value.is_empty() {
        // No referer header
        if rlcf.no_referer {
            return NGX_OK;
        } else {
            v.data = b"1".to_vec();
            return NGX_OK;
        }
    }

    // Check if it's an empty referer (shouldn't happen after above check, but be safe)
    if referer_value.is_empty() {
        if rlcf.blocked_referer {
            return NGX_OK;
        } else {
            v.data = b"1".to_vec();
            return NGX_OK;
        }
    }

    // Check if referer matches server_names
    if rlcf.server_names {
        let scf = r.cscf();
        let scf = scf.borrow();
        for sn in &scf.server_names {
            if &referer_value == &sn.name || (sn.regex.is_some() && referer_value.len() == sn.name.len() && eq_ignore_case(&referer_value, &sn.name)) {
                return NGX_OK;
            }
        }
    }

    // Check exact matches
    for referer_allowed in rlcf.referers.borrow().iter() {
        if &referer_value == referer_allowed || eq_ignore_case(&referer_value, referer_allowed) {
            return NGX_OK;
        }
    }

    // Check regexes
    for regex in rlcf.regexes.borrow().iter() {
        if regex.is_match(&referer_value) {
            return NGX_OK;
        }
    }

    // No match found - invalid referer
    v.data = b"1".to_vec();
    NGX_OK
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
            let pattern = if arg.len() > 1 && arg[1] == b'*' {
                &arg[2..]
            } else {
                &arg[1..]
            };
            let flags = if arg.len() > 1 && arg[1] == b'*' { 0 } else { ngx_core::regex::NGX_REGEX_CASELESS };
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
