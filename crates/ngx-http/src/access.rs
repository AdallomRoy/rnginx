//! ngx_http_access_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::{ptocidr, Cidr, CidrParse, SockAddr};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::*;
use crate::core::*;
use crate::request::*;

crate::http_module_index!("ngx_http_access_module");

#[derive(Clone)]
struct AccessRuleV4 {
    mask: u32,
    addr: u32,
    deny: bool,
}

#[derive(Clone)]
struct AccessRuleV6 {
    mask: [u8; 16],
    addr: [u8; 16],
    deny: bool,
}

#[derive(Clone)]
struct AccessRuleUnix {
    deny: bool,
}

pub struct AccessLocConf {
    pub rules_v4: Option<Vec<AccessRuleV4>>,
    pub rules_v6: Option<Vec<AccessRuleV6>>,
    pub rules_unix: Option<Vec<AccessRuleUnix>>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AccessLocConf {
        rules_v4: None,
        rules_v6: None,
        rules_unix: None,
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AccessLocConf>(prev).borrow();
    let mut c = conf_cell::<AccessLocConf>(conf).borrow_mut();

    if c.rules_v4.is_none() && c.rules_v6.is_none() && c.rules_unix.is_none() {
        c.rules_v4 = p.rules_v4.clone();
        c.rules_v6 = p.rules_v6.clone();
        c.rules_unix = p.rules_unix.clone();
    }

    Ok(())
}

/// ngx_http_access_rule
fn access_rule(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AccessLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    let deny = args[0][0] == b'd';

    let value = &args[1];

    let mut all = false;
    let mut cidr: Option<Cidr> = None;

    if value.as_slice() == b"all" {
        all = true;
    } else if value.as_slice() == b"unix:" {
        cidr = Some(Cidr::Unix);
    } else {
        match ptocidr(value) {
            CidrParse::Ok(c) => cidr = Some(c),
            CidrParse::Done(c) => {
                cf.warn(format_args!("low address bits of {} are meaningless", B(value)));
                cidr = Some(c);
            }
            CidrParse::Error => return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(value)))),
        }
    }

    let mut c = cell.borrow_mut();

    match cidr {
        Some(Cidr::V4 { addr, mask }) => c.rules_v4.get_or_insert_with(Vec::new).push(AccessRuleV4 { mask, addr, deny }),
        None if all => c.rules_v4.get_or_insert_with(Vec::new).push(AccessRuleV4 { mask: 0, addr: 0, deny }),
        _ => {}
    }

    match cidr {
        Some(Cidr::V6 { addr, mask }) => c.rules_v6.get_or_insert_with(Vec::new).push(AccessRuleV6 { mask, addr, deny }),
        None if all => c.rules_v6.get_or_insert_with(Vec::new).push(AccessRuleV6 { mask: [0; 16], addr: [0; 16], deny }),
        _ => {}
    }

    match cidr {
        Some(Cidr::Unix) => c.rules_unix.get_or_insert_with(Vec::new).push(AccessRuleUnix { deny }),
        None if all => c.rules_unix.get_or_insert_with(Vec::new).push(AccessRuleUnix { deny }),
        _ => {}
    }

    Ok(())
}

pub fn access_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("allow", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, access_rule),
        cmd_fn!("deny", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, access_rule),
    ];
    http_module_def("ngx_http_access_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_ACCESS_PHASE,
        Rc::new(|r| Box::pin(access_handler(r))),
    );
    Ok(())
}

/// ngx_http_access_handler
async fn access_handler(r: R) -> i64 {
    let conf = r.loc_conf::<AccessLocConf>(ctx_index());
    let alcf = conf.borrow();

    let sockaddr = r.connection.sockaddr.borrow().clone();

    match sockaddr {
        SockAddr::V4(sin) => {
            if let Some(rules) = &alcf.rules_v4 {
                return access_inet(&r, rules, u32::from(*sin.ip()));
            }
        }

        SockAddr::V6(sin6) => {
            let p = sin6.ip().octets();

            if let Some(rules) = &alcf.rules_v4 {
                if let Some(v4) = sin6.ip().to_ipv4_mapped() {
                    return access_inet(&r, rules, u32::from(v4));
                }
            }

            if let Some(rules) = &alcf.rules_v6 {
                return access_inet6(&r, rules, &p);
            }
        }

        SockAddr::Unix(_) => {
            if let Some(rules) = &alcf.rules_unix {
                return access_unix(&r, rules);
            }
        }
    }

    NGX_DECLINED
}

/// ngx_http_access_inet: `addr` in host byte order; the debug line shows
/// the in_addr_t values as C prints them
fn access_inet(r: &R, rules: &[AccessRuleV4], addr: u32) -> i64 {
    for rule in rules {
        http_debug!(r, "access: {:08X} {:08X} {:08X}", addr.to_be(), rule.mask.to_be(), rule.addr.to_be());

        if (addr & rule.mask) == rule.addr {
            return access_found(r, rule.deny);
        }
    }

    NGX_DECLINED
}

/// ngx_http_access_inet6
fn access_inet6(r: &R, rules: &[AccessRuleV6], p: &[u8; 16]) -> i64 {
    'rules: for rule in rules {
        http_debug!(
            r,
            "access: {} {} {}",
            B(&ngx_core::inet::inet6_ntop(p)),
            B(&ngx_core::inet::inet6_ntop(&rule.mask)),
            B(&ngx_core::inet::inet6_ntop(&rule.addr))
        );

        for n in 0..16 {
            if (p[n] & rule.mask[n]) != rule.addr[n] {
                continue 'rules;
            }
        }

        return access_found(r, rule.deny);
    }

    NGX_DECLINED
}

/// ngx_http_access_unix
fn access_unix(r: &R, rules: &[AccessRuleUnix]) -> i64 {
    // TODO in C too: check path
    match rules.first() {
        Some(rule) => access_found(r, rule.deny),
        None => NGX_DECLINED,
    }
}

/// ngx_http_access_found
fn access_found(r: &R, deny: bool) -> i64 {
    if deny {
        let clcf = r.clcf();
        if *clcf.borrow().satisfy.get() == NGX_HTTP_SATISFY_ALL {
            ngx_log_error!(
                NGX_LOG_ERR,
                r.connection.log,
                None,
                "access forbidden by rule"
            );
        }
        NGX_HTTP_FORBIDDEN
    } else {
        NGX_OK
    }
}
