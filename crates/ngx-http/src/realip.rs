//! ngx_http_realip_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::{Cidr, SockAddr, ptocidr};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::core_rt::get_forwarded_addr;
use crate::*;

crate::http_module_index!("ngx_http_realip_module");

// Type constants for real_ip_header directive
const NGX_HTTP_REALIP_XREALIP: u32 = 0;
const NGX_HTTP_REALIP_XFWD: u32 = 1;
const NGX_HTTP_REALIP_HEADER: u32 = 2;
const NGX_HTTP_REALIP_PROXY: u32 = 3;

pub struct RealipLocConf {
    pub from: Vec<Cidr>,
    pub header_type: Val<u32>,
    pub header_name: Val<Vec<u8>>,
    pub header_hash: u32,
    pub recursive: Val<bool>,
}

pub struct RealipCtx {
    pub original_sockaddr: SockAddr,
    pub original_addr_text: Vec<u8>,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(RealipLocConf {
        from: Vec::new(),
        header_type: Val::unset(),
        header_name: Val::unset(),
        header_hash: 0,
        recursive: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<RealipLocConf>(prev).borrow();
    let mut c = conf_cell::<RealipLocConf>(conf).borrow_mut();

    if c.from.is_empty() {
        c.from = p.from.clone();
    }

    // Merge header_type (default to X-Real-IP)
    if !c.header_type.is_set() {
        if p.header_type.is_set() {
            c.header_type = Val::set(*p.header_type.get());
        } else {
            c.header_type = Val::set(NGX_HTTP_REALIP_XREALIP);
        }
    }

    // Merge recursive (default to false)
    if !c.recursive.is_set() {
        let recursive_val = p.recursive.get_or(false);
        c.recursive = Val::set(recursive_val);
    }

    // Merge header_name and hash if needed
    if !c.header_name.is_set() && p.header_name.is_set() {
        c.header_name = Val::set(p.header_name.get().clone());
        c.header_hash = p.header_hash;
    }

    Ok(())
}

fn set_real_ip_from(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RealipLocConf>(conf.as_ref().unwrap());

    if cf.args.is_empty() || cf.args.len() < 2 {
        return Err(msg("invalid arguments"));
    }

    let value = &cf.args[1];

    // Check for unix:
    if value == b"unix:" {
        cell.borrow_mut().from.push(Cidr::Unix);
        return Ok(());
    }

    // Try parsing as CIDR
    match ptocidr(value) {
        ngx_core::inet::CidrParse::Ok(cidr) => {
            cell.borrow_mut().from.push(cidr);
            return Ok(());
        }
        ngx_core::inet::CidrParse::Done(cidr) => {
            ngx_log_error!(NGX_LOG_WARN, cf.log, None, "low address bits of {} are meaningless", B(value));
            cell.borrow_mut().from.push(cidr);
            return Ok(());
        }
        ngx_core::inet::CidrParse::Error => {
            // Fall through to hostname resolution
        }
    }

    // Try hostname resolution
    match resolve_hostname(value) {
        Ok(addrs) => {
            for sa in addrs {
                let cidr = match sa {
                    SockAddr::V4(v4) => {
                        let addr = u32::from(*v4.ip());
                        let mask = 0xffffffff;
                        Cidr::V4 { addr, mask }
                    }
                    SockAddr::V6(v6) => {
                        let addr = v6.ip().octets();
                        let mask = [0xff; 16];
                        Cidr::V6 { addr, mask }
                    }
                    SockAddr::Unix(_) => Cidr::Unix,
                };
                cell.borrow_mut().from.push(cidr);
            }
            Ok(())
        }
        Err(msg_str) => {
            Err(cf.emerg(format_args!("{} in set_real_ip_from \"{}\"", msg_str, B(value))))
        }
    }
}

fn set_real_ip_header(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RealipLocConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    if c.header_type.is_set() {
        return Err(msg("is duplicate"));
    }

    if cf.args.is_empty() || cf.args.len() < 2 {
        return Err(msg("invalid arguments"));
    }

    let value = &cf.args[1];

    if value.eq_ignore_ascii_case(b"X-Real-IP") {
        c.header_type = Val::set(NGX_HTTP_REALIP_XREALIP);
    } else if value.eq_ignore_ascii_case(b"X-Forwarded-For") {
        c.header_type = Val::set(NGX_HTTP_REALIP_XFWD);
    } else if value.eq_ignore_ascii_case(b"proxy_protocol") {
        c.header_type = Val::set(NGX_HTTP_REALIP_PROXY);
    } else if value.eq_ignore_ascii_case(b"proxy_protocol_server") {
        c.header_type = Val::set(NGX_HTTP_REALIP_PROXY);
    } else {
        // Custom header name
        c.header_type = Val::set(NGX_HTTP_REALIP_HEADER);
        c.header_name = Val::set(value.clone());
        c.header_hash = hash_lowcase(value);
    }

    Ok(())
}

/// Hash function for header names (lowercase)
fn hash_lowcase(data: &[u8]) -> u32 {
    let mut hash = 5381u32;
    for &b in data {
        let lower = b.to_ascii_lowercase();
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(lower as u32);
    }
    hash
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(&x, &y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

pub fn realip_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        postconfiguration: Some(init),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    let commands = vec![
        ngx_core::cmd_fn!(
            "set_real_ip_from",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            set_real_ip_from
        ),
        ngx_core::cmd_fn!(
            "real_ip_header",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            set_real_ip_header
        ),
        ngx_core::cmd!(
            "real_ip_recursive",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
            ConfLevel::Loc,
            RealipLocConf,
            recursive,
            set_flag
        ),
    ];

    http_module_def("ngx_http_realip_module", def, commands)
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    crate::variables::add_variables(
        cf,
        &[
            VarDef {
                name: "realip_remote_addr",
                get: Some(realip_remote_addr_var),
                set: None,
                data: 0,
                flags: 0,
            },
            VarDef {
                name: "realip_remote_port",
                get: Some(realip_remote_port_var),
                set: None,
                data: 0,
                flags: 0,
            },
        ],
    )?;
    Ok(())
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_POST_READ_PHASE, Rc::new(|r| Box::pin(realip_handler(r))));
    add_phase_handler(cf, NGX_HTTP_PREACCESS_PHASE, Rc::new(|r| Box::pin(realip_handler(r))));
    Ok(())
}

async fn realip_handler(r: R) -> i64 {
    let idx = ctx_index();

    let rlcf = r.loc_conf::<RealipLocConf>(idx);
    let c = rlcf.borrow();

    // No trusted addresses configured
    if c.from.is_empty() {
        return NGX_DECLINED;
    }

    // Already processed this request
    if r.get_ctx::<RealipCtx>(idx).is_some() {
        return NGX_DECLINED;
    }

    drop(c);

    let c = rlcf.borrow();
    let header_type = c.header_type.get_or(NGX_HTTP_REALIP_XREALIP);
    let recursive = c.recursive.get_or(false);

    // Check if connection sockaddr is in trusted list
    let current_addr = r.connection.sockaddr.borrow().clone();

    let is_trusted = c.from.iter().any(|cidr| cidr.matches(&current_addr));
    if !is_trusted {
        return NGX_DECLINED;
    }

    drop(c);

    // Get the header value to parse
    let (headers_vec, value_opt) = match header_type {
        NGX_HTTP_REALIP_XREALIP => {
            let value = {
                let hin = r.headers_in.borrow();
                if hin.x_real_ip.is_empty() {
                    return NGX_DECLINED;
                }
                // Use the last X-Real-IP header - must borrow and clone in the same scope
                let val = hin.x_real_ip[hin.x_real_ip.len() - 1].value.borrow().clone();
                drop(hin);
                val
            };
            (Vec::new(), Some(value))
        }
        NGX_HTTP_REALIP_XFWD => {
            let headers = {
                let hin = r.headers_in.borrow();
                if hin.x_forwarded_for.is_empty() {
                    return NGX_DECLINED;
                }
                hin.x_forwarded_for.clone()
            };
            (headers, None)
        }
        NGX_HTTP_REALIP_PROXY => match proxy_protocol(&r) {
            Some(pp) => (Vec::new(), Some(pp.src_addr.clone())),
            None => return NGX_DECLINED,
        },
        NGX_HTTP_REALIP_HEADER => {
            // Custom header name lookup
            let (header_name, header_hash) = {
                let c = rlcf.borrow();
                (c.header_name.get().clone(), c.header_hash)
            };

            let found_value = {
                let hin = r.headers_in.borrow();
                let mut found: Option<Vec<u8>> = None;

                let _ = header_hash;
                for h in &hin.headers {
                    if h.hash.get() == 0 { continue; }
                    if h.key.len() != header_name.len() { continue; }
                    if h.key.iter().zip(&header_name).all(|(&a, &b)| a.to_ascii_lowercase() == b.to_ascii_lowercase()) {
                        found = Some(h.value.borrow().clone());
                        break;
                    }
                }
                found
            };

            if found_value.is_none() {
                return NGX_DECLINED;
            }

            (Vec::new(), found_value)
        }
        _ => return NGX_DECLINED,
    };

    // Parse the address
    let c = rlcf.borrow();
    let proxies = c.from.clone();
    drop(c);

    let (rc, mut new_addr) = get_forwarded_addr(&r, &current_addr, &headers_vec, value_opt.as_deref().unwrap_or(&[]), &proxies, recursive);

    if rc == NGX_DECLINED {
        return NGX_DECLINED;
    }

    if header_type == NGX_HTTP_REALIP_PROXY {
        if let Some(pp) = proxy_protocol(&r) {
            new_addr.set_port(pp.src_port);
        }
    }

    // Set the new address
    set_real_addr(&r, new_addr).await
}

/// The PROXY protocol header read for this connection (c->proxy_protocol).
fn proxy_protocol(r: &R) -> Option<Rc<ngx_core::proxy_protocol::ProxyProtocol>> {
    let pp = r.connection.proxy_protocol.borrow().clone()?;
    pp.downcast::<ngx_core::proxy_protocol::ProxyProtocol>().ok()
}

async fn set_real_addr(r: &R, new_addr: SockAddr) -> i64 {
    let idx = ctx_index();

    // Save original address on the connection (survives internal_redirect,
    // which clears per-request ctx).
    if r.connection.original_sockaddr.borrow().is_none() {
        *r.connection.original_sockaddr.borrow_mut() =
            Some(r.connection.sockaddr.borrow().clone());
        *r.connection.original_addr_text.borrow_mut() =
            Some(r.connection.addr_text.borrow().clone());
    }
    let original_sockaddr = r.connection.original_sockaddr.borrow().clone().unwrap();
    let original_addr_text = r.connection.original_addr_text.borrow().clone().unwrap();
    let ctx = RealipCtx { original_sockaddr, original_addr_text };
    r.set_ctx(idx, ctx);

    // Update connection address
    let new_text = new_addr.addr_text();
    *r.connection.sockaddr.borrow_mut() = new_addr;
    *r.connection.addr_text.borrow_mut() = new_text;

    NGX_DECLINED
}

fn realip_remote_addr_var(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let idx = ctx_index();
    // Priority: per-request ctx (if realip already ran this request), else
    // the persistent per-connection copy (survives internal_redirect that
    // clears ctx), else the (possibly overwritten) current addr_text.
    let addr_text = if let Some(ctx) = r.get_ctx::<RealipCtx>(idx) {
        ctx.borrow().original_addr_text.clone()
    } else if let Some(t) = r.connection.original_addr_text.borrow().clone() {
        t
    } else {
        r.connection.addr_text.borrow().clone()
    };

    v.data = addr_text;
    v.valid = true;
    v.no_cacheable = false;

    NGX_OK
}

fn realip_remote_port_var(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let idx = ctx_index();
    let addr = if let Some(ctx) = r.get_ctx::<RealipCtx>(idx) {
        ctx.borrow().original_sockaddr.clone()
    } else if let Some(a) = r.connection.original_sockaddr.borrow().clone() {
        a
    } else {
        r.connection.sockaddr.borrow().clone()
    };

    let port = addr.port();
    let port_str = format!("{}", port).into_bytes();
    v.data = port_str;
    v.valid = true;
    v.no_cacheable = false;

    NGX_OK
}

fn resolve_hostname(hostname: &[u8]) -> Result<Vec<SockAddr>, String> {
    let hostname_str = match std::str::from_utf8(hostname) {
        Ok(s) => s,
        Err(_) => return Err("invalid hostname encoding".to_string()),
    };

    // Try to resolve the hostname
    use std::net::ToSocketAddrs;
    match format!("{}:0", hostname_str).to_socket_addrs() {
        Ok(addrs) => {
            let result: Vec<SockAddr> = addrs
                .filter_map(|addr| match addr {
                    std::net::SocketAddr::V4(v4) => Some(SockAddr::V4(v4)),
                    std::net::SocketAddr::V6(v6) => Some(SockAddr::V6(v6)),
                })
                .collect();

            if result.is_empty() {
                Err("invalid hostname".to_string())
            } else {
                Ok(result)
            }
        }
        Err(_) => Err("invalid hostname".to_string()),
    }
}

use crate::variables::VarDef;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_lowcase() {
        let h1 = hash_lowcase(b"X-Real-IP");
        let h2 = hash_lowcase(b"x-real-ip");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_eq_ignore_ascii_case() {
        assert!(eq_ignore_ascii_case(b"X-Real-IP", b"x-real-ip"));
        assert!(!eq_ignore_ascii_case(b"X-Real-IP", b"x-forwarded-for"));
    }
}
