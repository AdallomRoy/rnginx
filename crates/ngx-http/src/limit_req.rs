//! ngx_http_limit_req_module: request rate limiting with leaky bucket algorithm

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::times::current_msec;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_limit_req_module");

const NGX_HTTP_LIMIT_REQ_PASSED: u32 = 1;
const NGX_HTTP_LIMIT_REQ_DELAYED: u32 = 2;
const NGX_HTTP_LIMIT_REQ_REJECTED: u32 = 3;
const NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN: u32 = 4;
const NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN: u32 = 5;

/// Node in the LimitReq zone
#[derive(Clone, Default)]
struct LimitReqNode {
    last_ms: u64,
    excess: u64,
}

/// A zone for limit_req
pub struct LimitReqZone {
    rate_num: u64,   // N requests
    rate_per: u64,   // per N seconds (1 or 60)
    key_expr: Vec<u8>,  // The key expression (e.g., $binary_remote_addr)
    /// Pre-compiled version of key_expr — evaluated per request. Runtime
    /// evaluator prefers this over key_expr when set.
    key_cv: Option<std::rc::Rc<crate::script::ComplexValue>>,
    map: RefCell<HashMap<Vec<u8>, LimitReqNode>>,
}

/// Limit in a location
#[derive(Clone)]
pub struct LimitReqLimit {
    pub zone_name: Vec<u8>,
    pub burst: u64,
    /// `delay=N` in nginx: how many "excess" requests can accumulate before
    /// the burst starts delaying. Stored in thousandths (matches C's
    /// limit->delay = delay * 1000). `nodelay` maps to burst*1000 so no
    /// requests within the burst are delayed. Absence of the parameter is
    /// treated as 0 (any excess delays — the historical default).
    pub delay: u64,
}

/// Location configuration
pub struct LimitReqLocConf {
    pub limits: Vec<LimitReqLimit>,
    pub limit_log_level: Val<u32>,
    pub delay_log_level: Val<u32>,
    pub status_code: Val<u32>,
    pub dry_run: Val<bool>,
}

// Global zone registry
thread_local! {
    static ZONES: RefCell<HashMap<Vec<u8>, Rc<LimitReqZone>>> = RefCell::new(HashMap::new());
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitReqLocConf {
        limits: Vec::new(),
        limit_log_level: Val::unset(),
        delay_log_level: Val::unset(),
        status_code: Val::unset(),
        dry_run: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<LimitReqLocConf>(prev).borrow();
    let mut c = conf_cell::<LimitReqLocConf>(conf).borrow_mut();

    if c.limits.is_empty() {
        c.limits = p.limits.clone();
    }

    c.limit_log_level.merge(&p.limit_log_level, NGX_LOG_ERR);

    let delay_level = if *c.limit_log_level.get() == NGX_LOG_INFO {
        NGX_LOG_INFO
    } else {
        *c.limit_log_level.get() + 1
    };
    c.delay_log_level = Val::set(delay_level);

    c.status_code.merge(&p.status_code, NGX_HTTP_SERVICE_UNAVAILABLE as u32);
    c.dry_run.merge(&p.dry_run, false);

    Ok(())
}

fn limit_req_status_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let status = r.limit_req_status.get();
    if status == 0 {
        v.not_found = true;
        return NGX_OK;
    }
    let status_str = match status {
        NGX_HTTP_LIMIT_REQ_PASSED => "PASSED",
        NGX_HTTP_LIMIT_REQ_DELAYED => "DELAYED",
        NGX_HTTP_LIMIT_REQ_REJECTED => "REJECTED",
        NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN => "DELAYED_DRY_RUN",
        NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN => "REJECTED_DRY_RUN",
        _ => "UNKNOWN",
    };
    v.data = status_str.as_bytes().to_vec();
    v.valid = true;
    NGX_OK
}

pub fn limit_req_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        postconfiguration: Some(init),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("limit_req_zone", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, limit_req_zone),
        cmd_fn!("limit_req", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, limit_req),
        cmd_fn!("limit_req_log_level", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, limit_req_log_level),
        cmd_fn!("limit_req_status", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, limit_req_status),
        cmd_fn!("limit_req_dry_run", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, limit_req_dry_run),
    ];
    http_module_def("ngx_http_limit_req_module", def, commands)
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = [
        VarDef {
            name: "limit_req_status",
            set: None,
            get: Some(limit_req_status_variable),
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
    ];
    variables::add_variables(cf, &vars)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_PREACCESS_PHASE,
        Rc::new(|r| Box::pin(limit_req_handler(r))),
    );
    Ok(())
}

async fn limit_req_handler(r: R) -> i64 {
    if r.limit_req_status.get() != 0 {
        return NGX_DECLINED;
    }

    let loc_conf = r.loc_conf::<LimitReqLocConf>(ctx_index());
    let conf = loc_conf.borrow();

    if conf.limits.is_empty() {
        return NGX_DECLINED;
    }

    let now = current_msec();

    for limit in &conf.limits {
        let zone_opt = ZONES.with(|zones| zones.borrow().get(&limit.zone_name).cloned());

        let Some(zone) = zone_opt else {
            continue;
        };

        // Evaluate the key expression
        let key = evaluate_zone_key(&r, &zone);
        if key.is_empty() {
            // Empty key means variable not set - skip this limit
            continue;
        }

        let mut map = zone.map.borrow_mut();
        let node = map.entry(key).or_default();

        // Compute rate in excess units per second
        let _rate_per_second = zone.rate_num * 1000 / zone.rate_per;

        // Leaky bucket algorithm
        // Decay is: elapsed_ms * rate_num / rate_per thousandths
        // (rate_num requests / rate_per seconds = rate_num / rate_per requests per second)
        // = (rate_num / rate_per / 1000) requests per millisecond
        // = (rate_num / rate_per) thousandths per millisecond
        // Match ngx_http_limit_req_lookup's signed math:
        //   excess = lr->excess - ctx->rate * ms / 1000 + 1000
        //   if (excess < 0) excess = 0;
        // The order matters — decay and the +1000 combine BEFORE the floor.
        // A saturating_sub would clamp the decay first and then add 1000
        // unconditionally, which permanently biases excess upward for a
        // freshly-created node whose last_ms is 0 (elapsed = now = huge).
        let elapsed_ms = now.saturating_sub(node.last_ms) as i64;
        let decay = elapsed_ms.saturating_mul(zone.rate_num as i64) / (zone.rate_per as i64);
        let signed = (node.excess as i64) - decay + 1000;
        let new_excess: u64 = if signed < 0 { 0 } else { signed as u64 };
        // burst is in requests; compare against thousandths.
        if new_excess > limit.burst * 1000 {
            // Reject - DON'T update state
            drop(map); // Release borrow before logging

            let dry_run_str = if *conf.dry_run.get() { ", dry run" } else { "" };
            ngx_log_error!(*conf.limit_log_level.get() as u32, r.connection.log, None,
                "limiting requests{}, excess: {:.3} by zone \"{}\"",
                dry_run_str,
                new_excess as f64 / 1000.0,
                B(&limit.zone_name)
            );

            if *conf.dry_run.get() {
                r.limit_req_status.set(NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN);
                return NGX_DECLINED;
            }

            r.limit_req_status.set(NGX_HTTP_LIMIT_REQ_REJECTED);
            return *conf.status_code.get() as i64;
        }

        // Not rejected, so count this request
        let excess = new_excess;
        node.last_ms = now;
        node.excess = excess;

        drop(map); // Release borrow before potential sleep/log

        // Delay decision: nginx's threshold is `limit->delay` (thousandths).
        // If excess exceeds it, wait long enough to drain back down.
        if excess > limit.delay {
            let delay_ms = ((excess - limit.delay) * zone.rate_per) / zone.rate_num;

            let dry_run_str = if *conf.dry_run.get() { ", dry run" } else { "" };
            ngx_log_error!(*conf.delay_log_level.get() as u32, r.connection.log, None,
                "delaying request{}, excess: {:.3}, by zone \"{}\"",
                dry_run_str,
                excess as f64 / 1000.0,
                B(&limit.zone_name)
            );

            if *conf.dry_run.get() {
                r.limit_req_status.set(NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN);
                return NGX_DECLINED;
            }

            r.limit_req_status.set(NGX_HTTP_LIMIT_REQ_DELAYED);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            return NGX_DECLINED;
        }
    }

    r.limit_req_status.set(NGX_HTTP_LIMIT_REQ_PASSED);
    NGX_DECLINED
}

fn limit_req_zone(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 3 {
        return Err(msg("invalid number of arguments"));
    }

    // Parse: limit_req_zone $variable zone=name:size rate=X[r/m]
    let key_expr = args[1].clone();  // The variable expression
    let mut zone_name: Option<Vec<u8>> = None;
    let mut rate_num: u64 = 0;
    let mut rate_per: u64 = 0;

    for arg in &args[2..] {
        let arg_str = String::from_utf8_lossy(arg);

        if arg_str.starts_with("zone=") {
            let parts: Vec<&str> = arg_str[5..].split(':').collect();
            if parts.len() >= 1 {
                zone_name = Some(parts[0].as_bytes().to_vec());
            }
        } else if arg_str.starts_with("rate=") {
            let (num, per) = parse_zone_rate(&arg_str[5..])?;
            rate_num = num;
            rate_per = per;
        }
    }

    if zone_name.is_none() || rate_num == 0 {
        return Err(msg("zone and rate required"));
    }

    let zone_name = zone_name.unwrap();
    // Pre-compile the key so per-request evaluation doesn't need to parse it.
    // Fast path: $binary_remote_addr short-circuits the ComplexValue plumbing.
    let key_cv = if key_expr == b"$binary_remote_addr" {
        None
    } else {
        crate::script::compile_complex_value(cf, &key_expr, 0).ok().map(Rc::new)
    };
    let zone = Rc::new(LimitReqZone {
        rate_num,
        rate_per,
        key_expr,
        key_cv,
        map: RefCell::new(HashMap::new()),
    });

    ZONES.with(|zones| {
        zones.borrow_mut().insert(zone_name, zone);
    });

    Ok(())
}

fn limit_req(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("at least zone= required"));
    }

    // Parse: limit_req zone=name [burst=N] [nodelay|delay=N]
    let mut zone_name: Option<Vec<u8>> = None;
    let mut burst: u64 = 0;
    let mut delay: Option<u64> = None;
    let mut nodelay = false;

    for arg in &args[1..] {
        let arg_str = String::from_utf8_lossy(arg);

        if arg_str.starts_with("zone=") {
            zone_name = Some(arg_str[5..].as_bytes().to_vec());
        } else if arg_str.starts_with("burst=") {
            burst = arg_str[6..].parse().unwrap_or(0);
        } else if arg_str == "nodelay" {
            nodelay = true;
        } else if let Some(n) = arg_str.strip_prefix("delay=") {
            delay = Some(n.parse().unwrap_or(0));
        }
    }

    if zone_name.is_none() {
        return Err(msg("zone required"));
    }

    // Resolve delay threshold (in thousandths, matching C's `delay * 1000`):
    //   - explicit delay=N ⇒ N * 1000
    //   - nodelay          ⇒ burst * 1000 (no requests within burst are delayed)
    //   - neither          ⇒ 0 (every excess request delays)
    let delay_thousandths = if let Some(n) = delay {
        n * 1000
    } else if nodelay {
        burst * 1000
    } else {
        0
    };

    let loc_conf = conf_rc::<LimitReqLocConf>(conf.as_ref().unwrap());
    loc_conf.borrow_mut().limits.push(LimitReqLimit {
        zone_name: zone_name.unwrap(),
        burst,
        delay: delay_thousandths,
    });

    Ok(())
}

fn limit_req_log_level(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let loc_conf = conf_rc::<LimitReqLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() != 2 {
        return Err(msg("one argument expected"));
    }

    let level_str = String::from_utf8_lossy(&args[1]);
    let level = match level_str.as_ref() {
        "info" => NGX_LOG_INFO,
        "notice" => NGX_LOG_NOTICE,
        "warn" => NGX_LOG_WARN,
        "error" => NGX_LOG_ERR,
        _ => return Err(msg("invalid log level")),
    };

    loc_conf.borrow_mut().limit_log_level = Val::set(level);
    Ok(())
}

fn limit_req_status(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let loc_conf = conf_rc::<LimitReqLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() != 2 {
        return Err(msg("one argument expected"));
    }

    let code_str = String::from_utf8_lossy(&args[1]);
    let code: u32 = code_str.parse()
        .map_err(|_| msg("invalid status code"))?;

    if code < 400 || code > 599 {
        return Err(msg("status code must be 400-599"));
    }

    loc_conf.borrow_mut().status_code = Val::set(code);
    Ok(())
}

fn limit_req_dry_run(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let loc_conf = conf_rc::<LimitReqLocConf>(conf.as_ref().unwrap());
    // NGX_CONF_FLAG: on/off.
    let v = match cf.args.get(1).map(|a| a.as_slice()) {
        Some(b"on") => true,
        Some(b"off") => false,
        _ => return Err(msg("invalid value")),
    };
    loc_conf.borrow_mut().dry_run = Val::set(v);
    Ok(())
}

fn evaluate_zone_key(r: &R, zone: &LimitReqZone) -> Vec<u8> {
    // Fast path: $binary_remote_addr is the overwhelmingly common case.
    if zone.key_expr == b"$binary_remote_addr" {
        return match &*r.connection.sockaddr.borrow() {
            ngx_core::inet::SockAddr::V4(sa) => sa.ip().octets().to_vec(),
            ngx_core::inet::SockAddr::V6(sa) => sa.ip().octets().to_vec(),
            // C uses zeroes for anything that isn't inet(6).
            ngx_core::inet::SockAddr::Unix(_) => vec![0, 0, 0, 0],
        };
    }
    // General case: evaluate the pre-compiled ComplexValue.
    match &zone.key_cv {
        Some(cv) => crate::script::complex_value(r, cv).unwrap_or_default(),
        None => Vec::new(),
    }
}

fn parse_zone_rate(s: &str) -> Result<(u64, u64), ConfError> {
    let s = s.trim();
    let (num_str, per) = if s.ends_with("r/s") || s.ends_with("r/S") {
        (&s[..s.len()-3], 1u64)
    } else if s.ends_with("r/m") || s.ends_with("r/M") {
        (&s[..s.len()-3], 60u64)
    } else {
        return Err(msg("invalid rate format"));
    };

    let num: u64 = num_str.parse()
        .map_err(|_| msg("invalid rate"))?;

    // Return (numerator, denominator in seconds)
    Ok((num, per))
}
