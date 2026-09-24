//! ngx_http_access_module

use std::any::Any;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::SockAddr;
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

fn access_rule(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AccessLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let deny = args[0][0] == b'd'; // 'd' for deny, 'a' for allow

    let spec = &args[1];

    // Check for "all"
    if spec == b"all" {
        // Add rules for both IPv4 and IPv6
        {
            let mut c = cell.borrow_mut();
            if c.rules_v4.is_none() {
                c.rules_v4 = Some(Vec::new());
            }
            c.rules_v4.as_mut().unwrap().push(AccessRuleV4 {
                mask: 0,
                addr: 0,
                deny,
            });
        }
        {
            let mut c = cell.borrow_mut();
            if c.rules_v6.is_none() {
                c.rules_v6 = Some(Vec::new());
            }
            c.rules_v6.as_mut().unwrap().push(AccessRuleV6 {
                mask: [0; 16],
                addr: [0; 16],
                deny,
            });
        }
        {
            let mut c = cell.borrow_mut();
            if c.rules_unix.is_none() {
                c.rules_unix = Some(Vec::new());
            }
            c.rules_unix.as_mut().unwrap().push(AccessRuleUnix { deny });
        }
        return Ok(());
    }

    // Check for unix:
    if spec.starts_with(b"unix:") {
        let mut c = cell.borrow_mut();
        if c.rules_unix.is_none() {
            c.rules_unix = Some(Vec::new());
        }
        c.rules_unix.as_mut().unwrap().push(AccessRuleUnix { deny });
        return Ok(());
    }

    // Parse CIDR (IPv4 or IPv6)
    match parse_cidr(spec) {
        Ok((family, addr, mask)) => {
            let mut c = cell.borrow_mut();
            match family {
                "inet" => {
                    if c.rules_v4.is_none() {
                        c.rules_v4 = Some(Vec::new());
                    }
                    if let (Ok(addr_u32), Ok(mask_u32)) = (parse_ipv4_as_u32(&addr), parse_ipv4_as_u32(&mask)) {
                        c.rules_v4.as_mut().unwrap().push(AccessRuleV4 {
                            mask: mask_u32,
                            addr: addr_u32,
                            deny,
                        });
                    } else {
                        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(spec))));
                    }
                }
                "inet6" => {
                    if c.rules_v6.is_none() {
                        c.rules_v6 = Some(Vec::new());
                    }
                    if let (Ok(addr_bytes), Ok(mask_bytes)) = (parse_ipv6_as_bytes(&addr), parse_ipv6_as_bytes(&mask)) {
                        c.rules_v6.as_mut().unwrap().push(AccessRuleV6 {
                            mask: mask_bytes,
                            addr: addr_bytes,
                            deny,
                        });
                    } else {
                        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(spec))));
                    }
                }
                _ => {
                    return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(spec))));
                }
            }
            Ok(())
        }
        Err(_) => Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(spec)))),
    }
}

fn parse_ipv4_as_u32(addr: &str) -> Result<u32, ()> {
    addr.parse::<Ipv4Addr>()
        .map(|a| u32::from_be_bytes(a.octets()))
        .map_err(|_| ())
}

fn parse_ipv6_as_bytes(addr: &str) -> Result<[u8; 16], ()> {
    addr.parse::<Ipv6Addr>()
        .map(|a| a.octets())
        .map_err(|_| ())
}

fn parse_cidr(spec: &[u8]) -> Result<(&'static str, String, String), ()> {
    let spec_str = std::str::from_utf8(spec).map_err(|_| ())?;

    if spec_str.contains(':') && !spec_str.starts_with('[') {
        // IPv6 without prefix
        return Ok(("inet6", spec_str.to_string(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()));
    }

    if let Some(slash_pos) = spec_str.find('/') {
        let addr_part = &spec_str[..slash_pos];
        let prefix_part = &spec_str[slash_pos + 1..];

        let prefix_len: u32 = prefix_part.parse().map_err(|_| ())?;

        if addr_part.contains(':') {
            // IPv6
            let addr_str = addr_part.trim_start_matches('[').trim_end_matches(']');
            let addr_obj = addr_str.parse::<Ipv6Addr>().map_err(|_| ())?;
            let mask = ipv6_mask_from_prefix(prefix_len);
            Ok(("inet6", addr_obj.to_string(), ipv6_to_string(&mask)))
        } else {
            // IPv4
            let addr_obj = addr_part.parse::<Ipv4Addr>().map_err(|_| ())?;
            let mask = ipv4_mask_from_prefix(prefix_len);
            Ok(("inet", addr_obj.to_string(), ipv4_to_string(mask)))
        }
    } else if spec_str.contains(':') {
        // IPv6 without prefix
        let addr_str = spec_str.trim_start_matches('[').trim_end_matches(']');
        let _ = addr_str.parse::<Ipv6Addr>().map_err(|_| ())?;
        Ok(("inet6", spec_str.to_string(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()))
    } else {
        // IPv4 without prefix
        let _ = spec_str.parse::<Ipv4Addr>().map_err(|_| ())?;
        Ok(("inet", spec_str.to_string(), "255.255.255.255".to_string()))
    }
}

fn ipv4_mask_from_prefix(prefix: u32) -> u32 {
    if prefix >= 32 {
        0xffffffff
    } else {
        (0xffffffffu32 << (32 - prefix))
    }
}

fn ipv4_to_string(mask: u32) -> String {
    let bytes = mask.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn ipv6_mask_from_prefix(prefix: u32) -> [u8; 16] {
    let mut mask = [0u8; 16];
    let mut remaining = prefix;
    for i in 0..16 {
        if remaining >= 8 {
            mask[i] = 0xff;
            remaining -= 8;
        } else if remaining > 0 {
            mask[i] = (0xff << (8 - remaining)) as u8;
            remaining = 0;
        }
    }
    mask
}

fn ipv6_to_string(mask: &[u8; 16]) -> String {
    let addr = Ipv6Addr::from(*mask);
    addr.to_string()
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

async fn access_handler(r: R) -> i64 {
    let conf = r.loc_conf::<AccessLocConf>(ctx_index());
    let conf = conf.borrow();

    let remote_addr_ref = r.connection.sockaddr.borrow();
    let remote_addr = &*remote_addr_ref;

    match remote_addr {
        SockAddr::V4(sa) => {
            let addr = u32::from_be_bytes(sa.ip().octets());
            if let Some(rules) = &conf.rules_v4 {
                for rule in rules {
                    if (addr & rule.mask) == rule.addr {
                        return access_found(&r, rule.deny);
                    }
                }
            }
        }
        SockAddr::V6(sa) => {
            let addr_bytes = sa.ip().octets();
            // Check if it's a v4-mapped IPv6 address
            if is_ipv4_mapped(&addr_bytes) {
                let v4_addr = u32::from_be_bytes([addr_bytes[12], addr_bytes[13], addr_bytes[14], addr_bytes[15]]);
                if let Some(rules) = &conf.rules_v4 {
                    for rule in rules {
                        if (v4_addr & rule.mask) == rule.addr {
                            return access_found(&r, rule.deny);
                        }
                    }
                }
            }
            if let Some(rules) = &conf.rules_v6 {
                for rule in rules {
                    if ipv6_match(&addr_bytes, &rule.addr, &rule.mask) {
                        return access_found(&r, rule.deny);
                    }
                }
            }
        }
        SockAddr::Unix(_) => {
            if let Some(rules) = &conf.rules_unix {
                for rule in rules {
                    // Unix socket always matches
                    return access_found(&r, rule.deny);
                }
            }
        }
    }

    NGX_DECLINED
}

fn is_ipv4_mapped(addr: &[u8; 16]) -> bool {
    addr[0..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] && addr[10..12] == [0xff, 0xff]
}

fn ipv6_match(addr: &[u8; 16], rule_addr: &[u8; 16], mask: &[u8; 16]) -> bool {
    for i in 0..16 {
        if (addr[i] & mask[i]) != rule_addr[i] {
            return false;
        }
    }
    true
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_mask_from_prefix() {
        assert_eq!(ipv4_mask_from_prefix(32), 0xffffffff);
        assert_eq!(ipv4_mask_from_prefix(24), 0xffffff00);
        assert_eq!(ipv4_mask_from_prefix(16), 0xffff0000);
        assert_eq!(ipv4_mask_from_prefix(8), 0xff000000);
        assert_eq!(ipv4_mask_from_prefix(0), 0);
    }

    #[test]
    fn test_ipv6_mask_from_prefix() {
        let mask = ipv6_mask_from_prefix(128);
        assert_eq!(mask, [0xff; 16]);

        let mask = ipv6_mask_from_prefix(64);
        assert_eq!(&mask[0..8], &[0xff; 8]);
        assert_eq!(&mask[8..16], &[0; 8]);
    }

    #[test]
    fn test_ipv6_match() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let rule_addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mask = [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(ipv6_match(&addr, &rule_addr, &mask));
    }
}
