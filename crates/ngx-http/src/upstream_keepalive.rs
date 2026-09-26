//! ngx_http_upstream_keepalive_module
//! Registers the `keepalive`, `keepalive_time`, `keepalive_timeout`
//! and `keepalive_requests` directives on the enclosing upstream block,
//! and hands the parsed limits to the per-worker connection pool in
//! [`crate::upstream_keepalive_pool`].

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::cmd_fn;

use crate::core::*;
use crate::upstream::UpstreamMainConf;
use crate::upstream_keepalive_pool::{get_limits, set_limits, KeepaliveLimits};
use crate::{NGX_HTTP_UPS_CONF, NGX_CONF_TAKE1, NGX_CONF_TAKE12, HttpModuleDef, http_module_def};

crate::http_module_index!("ngx_http_upstream_keepalive_module");

fn current_upstream_name(cf: &mut Conf) -> Option<Vec<u8>> {
    let umcf = crate::get_main_conf::<UpstreamMainConf>(cf, crate::upstream::ctx_index());
    let cb = umcf.borrow().current_builder.borrow().as_ref().map(|b| b.name.clone());
    cb
}

fn parse_number(v: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(v).ok()?;
    s.parse().ok()
}

fn parse_time_ms(v: &[u8]) -> Option<u64> {
    // Accept "60s", "60000ms", plain "60" (seconds).
    let s = std::str::from_utf8(v).ok()?;
    let (num_end, unit_ms): (usize, u64) = if let Some(p) = s.find(|c: char| !c.is_ascii_digit()) {
        let unit = &s[p..];
        let m = match unit {
            "ms" => 1,
            "s"  => 1000,
            "m"  => 60_000,
            "h"  => 3_600_000,
            _ => return None,
        };
        (p, m)
    } else {
        (s.len(), 1000)
    };
    let n: u64 = s[..num_end].parse().ok()?;
    Some(n.saturating_mul(unit_ms))
}

fn keepalive_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    let n = parse_number(&cf.args[1])
        .ok_or_else(|| cf.emerg(format_args!("invalid keepalive count \"{}\"",
            ngx_core::string::B(&cf.args[1]))))?;
    let name = current_upstream_name(cf)
        .ok_or_else(|| msg("keepalive outside upstream block"))?;
    let mut lim = get_limits(&name).unwrap_or_default();
    lim.max_cached = n;
    set_limits(&name, lim);
    Ok(())
}

fn keepalive_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 { return Err(msg("invalid number of arguments")); }
    let ms = parse_time_ms(&cf.args[1])
        .ok_or_else(|| cf.emerg(format_args!("invalid keepalive_timeout \"{}\"",
            ngx_core::string::B(&cf.args[1]))))?;
    let name = current_upstream_name(cf)
        .ok_or_else(|| msg("keepalive_timeout outside upstream block"))?;
    let mut lim = get_limits(&name).unwrap_or_default();
    lim.timeout_ms = ms;
    set_limits(&name, lim);
    Ok(())
}

fn keepalive_time_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 { return Err(msg("invalid number of arguments")); }
    let ms = parse_time_ms(&cf.args[1])
        .ok_or_else(|| cf.emerg(format_args!("invalid keepalive_time \"{}\"",
            ngx_core::string::B(&cf.args[1]))))?;
    let name = current_upstream_name(cf)
        .ok_or_else(|| msg("keepalive_time outside upstream block"))?;
    let mut lim = get_limits(&name).unwrap_or_default();
    lim.time_ms = ms;
    set_limits(&name, lim);
    Ok(())
}

fn keepalive_requests_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 { return Err(msg("invalid number of arguments")); }
    let n = parse_number(&cf.args[1])
        .ok_or_else(|| cf.emerg(format_args!("invalid keepalive_requests \"{}\"",
            ngx_core::string::B(&cf.args[1]))))?;
    let name = current_upstream_name(cf)
        .ok_or_else(|| msg("keepalive_requests outside upstream block"))?;
    let mut lim = get_limits(&name).unwrap_or_default();
    lim.max_requests = n;
    set_limits(&name, lim);
    Ok(())
}

pub fn upstream_keepalive_module() -> ModuleDef {
    let commands = vec![
        cmd_fn!("keepalive", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::None, keepalive_handler),
        cmd_fn!("keepalive_timeout", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, keepalive_timeout_handler),
        cmd_fn!("keepalive_time", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, keepalive_time_handler),
        cmd_fn!("keepalive_requests", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, keepalive_requests_handler),
    ];
    let def = HttpModuleDef { ..Default::default() };
    http_module_def("ngx_http_upstream_keepalive_module", def, commands)
}

// Re-export the limits type so callers outside this module (proxy) can
// consult get_limits without importing the pool module directly.
pub use crate::upstream_keepalive_pool::KeepaliveLimits as Limits;
pub use crate::upstream_keepalive_pool::get_limits as limits_for;

// Re-export the actual pool primitives for the proxy request handler.
pub use crate::upstream_keepalive_pool::{take as pool_take, put as pool_put};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_time_ms() {
        assert_eq!(parse_time_ms(b"60"), Some(60_000));
        assert_eq!(parse_time_ms(b"60s"), Some(60_000));
        assert_eq!(parse_time_ms(b"500ms"), Some(500));
        assert_eq!(parse_time_ms(b"1m"), Some(60_000));
    }
}
