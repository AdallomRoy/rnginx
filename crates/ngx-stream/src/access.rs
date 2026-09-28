//! ngx_stream_access_module.c

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::{ptocidr, Cidr, CidrParse, SockAddr};
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::*;

stream_module_index!("ngx_stream_access_module");

/// ngx_stream_access_rule_t (host byte order)
#[derive(Clone, Copy)]
pub struct AccessRule {
    pub mask: u32,
    pub addr: u32,
    pub deny: bool,
}

/// ngx_stream_access_rule6_t
#[derive(Clone, Copy)]
pub struct AccessRule6 {
    pub addr: [u8; 16],
    pub mask: [u8; 16],
    pub deny: bool,
}

/// ngx_stream_access_rule_un_t
#[derive(Clone, Copy)]
pub struct AccessRuleUn {
    pub deny: bool,
}

/// ngx_stream_access_srv_conf_t
#[derive(Default)]
pub struct AccessSrvConf {
    pub rules: Option<Rc<Vec<AccessRule>>>,
    pub rules6: Option<Rc<Vec<AccessRule6>>>,
    pub rules_un: Option<Rc<Vec<AccessRuleUn>>>,
}

/// ngx_stream_access_handler
async fn access_handler(s: S) -> i64 {
    let ascf = s.srv_conf::<AccessSrvConf>(ctx_index());

    let (rules, rules6, rules_un) = {
        let a = ascf.borrow();
        (a.rules.clone(), a.rules6.clone(), a.rules_un.clone())
    };

    let sa = s.connection.sockaddr.borrow().clone();

    match sa {
        SockAddr::V4(a) => {
            if let Some(rules) = rules {
                return access_inet(&s, &rules, u32::from(*a.ip()));
            }
        }

        SockAddr::V6(a) => {
            if let Some(rules) = &rules {
                if let Some(v4) = a.ip().to_ipv4_mapped() {
                    return access_inet(&s, rules, u32::from(v4));
                }
            }

            if let Some(rules6) = rules6 {
                return access_inet6(&s, &rules6, &a.ip().octets());
            }
        }

        SockAddr::Unix(_) => {
            if let Some(rules_un) = rules_un {
                return access_unix(&s, &rules_un);
            }
        }
    }

    NGX_DECLINED
}

/// ngx_stream_access_inet
fn access_inet(s: &Session, rules: &[AccessRule], addr: u32) -> i64 {
    for rule in rules {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "access: {:08X} {:08X} {:08X}", addr.to_be(), rule.mask.to_be(), rule.addr.to_be());

        if (addr & rule.mask) == rule.addr {
            return access_found(s, rule.deny);
        }
    }

    NGX_DECLINED
}

/// ngx_stream_access_inet6
fn access_inet6(s: &Session, rules6: &[AccessRule6], p: &[u8; 16]) -> i64 {
    'next: for rule6 in rules6 {
        for n in 0..16 {
            if (p[n] & rule6.mask[n]) != rule6.addr[n] {
                continue 'next;
            }
        }

        return access_found(s, rule6.deny);
    }

    NGX_DECLINED
}

/// ngx_stream_access_unix
fn access_unix(s: &Session, rules_un: &[AccessRuleUn]) -> i64 {
    // TODO: check path
    if let Some(rule_un) = rules_un.first() {
        return access_found(s, rule_un.deny);
    }

    NGX_DECLINED
}

/// ngx_stream_access_found
fn access_found(s: &Session, deny: bool) -> i64 {
    if deny {
        ngx_log_error!(NGX_LOG_ERR, s.connection.log, None, "access forbidden by rule");
        return NGX_STREAM_FORBIDDEN;
    }

    NGX_OK
}

/// ngx_stream_access_rule
fn access_rule(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let ascf = conf_rc::<AccessSrvConf>(conf.as_ref().expect("conf"));

    let value = cf.args.clone();

    let deny = value[0].first() == Some(&b'd');

    let mut all = false;
    let mut cidr: Option<Cidr> = None;

    if value[1] == b"all" {
        all = true;
    } else if value[1] == b"unix:" {
        cidr = Some(Cidr::Unix);
    } else {
        match ptocidr(&value[1]) {
            CidrParse::Error => return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[1])))),
            CidrParse::Done(c) => {
                cf.warn(format_args!("low address bits of {} are meaningless", B(&value[1])));
                cidr = Some(c);
            }
            CidrParse::Ok(c) => cidr = Some(c),
        }
    }

    let mut a = ascf.borrow_mut();

    if matches!(cidr, Some(Cidr::V4 { .. })) || all {
        let (addr, mask) = match cidr {
            Some(Cidr::V4 { addr, mask }) => (addr, mask),
            _ => (0, 0),
        };

        let mut rules = a.rules.as_deref().cloned().unwrap_or_default();
        rules.push(AccessRule { mask, addr, deny });
        a.rules = Some(Rc::new(rules));
    }

    if matches!(cidr, Some(Cidr::V6 { .. })) || all {
        let (addr, mask) = match cidr {
            Some(Cidr::V6 { addr, mask }) => (addr, mask),
            _ => ([0; 16], [0; 16]),
        };

        let mut rules6 = a.rules6.as_deref().cloned().unwrap_or_default();
        rules6.push(AccessRule6 { addr, mask, deny });
        a.rules6 = Some(Rc::new(rules6));
    }

    if matches!(cidr, Some(Cidr::Unix)) || all {
        let mut rules_un = a.rules_un.as_deref().cloned().unwrap_or_default();
        rules_un.push(AccessRuleUn { deny });
        a.rules_un = Some(Rc::new(rules_un));
    }

    Ok(())
}

fn access_create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AccessSrvConf::default())
}

/// ngx_stream_access_merge_srv_conf
fn access_merge_srv_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<AccessSrvConf>(parent).borrow();
    let mut conf = conf_cell::<AccessSrvConf>(child).borrow_mut();

    if conf.rules.is_none() && conf.rules6.is_none() && conf.rules_un.is_none() {
        conf.rules = prev.rules.clone();
        conf.rules6 = prev.rules6.clone();
        conf.rules_un = prev.rules_un.clone();
    }

    Ok(())
}

/// ngx_stream_access_init
fn access_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_STREAM_ACCESS_PHASE, phase_fn(access_handler));
    Ok(())
}

pub fn access_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_access_module",
        StreamModuleDef {
            postconfiguration: Some(access_init),
            create_srv_conf: Some(access_create_srv_conf),
            merge_srv_conf: Some(access_merge_srv_conf),
            ..Default::default()
        },
        vec![
            cmd_fn!("allow", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, access_rule),
            cmd_fn!("deny", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, access_rule),
        ],
    )
}
