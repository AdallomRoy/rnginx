//! ngx_http_limit_conn_module: cap concurrent connections per key.
//!
//! Simplified — no shared memory (single tokio worker), no read-side
//! separation. The zone stores a per-key counter that goes up when the
//! access-phase handler passes a request through and comes back down when
//! the request's cleanup fires.

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::{cmd_fn};

use crate::script::ComplexValue;
use crate::*;

crate::http_module_index!("ngx_http_limit_conn_module");

// ------------------------------------------------------------------
// Config data
// ------------------------------------------------------------------

pub struct LimitConnMainConf {
    /// name -> key expression compiled at conf time.
    pub zones: HashMap<Vec<u8>, Rc<ComplexValue>>,
}

pub struct LimitConnLocConf {
    /// (zone_name, max_conns)
    pub limits: Val<Vec<(Vec<u8>, u32)>>,
    pub log_level: Val<u32>,
    pub status: Val<u32>,
    pub dry_run: Val<bool>,
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitConnMainConf { zones: HashMap::new() })
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitConnLocConf {
        limits: Val::unset(),
        log_level: Val::unset(),
        status: Val::unset(),
        dry_run: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<LimitConnLocConf>(prev).borrow();
    let mut c = conf_cell::<LimitConnLocConf>(conf).borrow_mut();
    c.limits.merge(&p.limits, Vec::new());
    c.log_level.merge(&p.log_level, ngx_core::log::NGX_LOG_ERR);
    c.status.merge(&p.status, 503);
    c.dry_run.merge(&p.dry_run, false);
    Ok(())
}

// ------------------------------------------------------------------
// Directive handlers
// ------------------------------------------------------------------

fn limit_conn_zone(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 3 {
        return Err(msg("invalid number of arguments in limit_conn_zone"));
    }
    let key = cf.args[1].clone();
    // args[2] is "zone=name:size" — pull the name out.
    let z = &cf.args[2];
    if !z.starts_with(b"zone=") {
        return Err(cf.emerg(format_args!("invalid zone \"{}\"", ngx_core::string::B(z))));
    }
    let after = &z[5..];
    let colon = after.iter().position(|&b| b == b':').unwrap_or(after.len());
    let name = after[..colon].to_vec();
    let cv = crate::script::compile_complex_value(cf, &key, 0)?;
    let mcf = crate::get_main_conf::<LimitConnMainConf>(cf, ctx_index());
    mcf.borrow_mut().zones.insert(name, Rc::new(cv));
    Ok(())
}

fn limit_conn_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 3 {
        return Err(msg("invalid number of arguments in limit_conn"));
    }
    let name = cf.args[1].clone();
    let s = std::str::from_utf8(&cf.args[2])
        .map_err(|_| cf.emerg(format_args!("invalid connection count")))?;
    let n: u32 = s.parse().map_err(|_| cf.emerg(format_args!("invalid connection count \"{}\"", s)))?;
    let cell = conf_rc::<LimitConnLocConf>(conf.as_ref().unwrap());
    let cur = cell.borrow().limits.as_option().cloned().unwrap_or_default();
    let mut new_list = cur;
    new_list.push((name, n));
    cell.borrow_mut().limits = Val::set(new_list);
    Ok(())
}

fn limit_conn_log_level(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 { return Err(msg("invalid number of arguments")); }
    let cell = conf_rc::<LimitConnLocConf>(conf.as_ref().unwrap());
    let level = match cf.args[1].as_slice() {
        b"info"   => ngx_core::log::NGX_LOG_INFO,
        b"notice" => ngx_core::log::NGX_LOG_NOTICE,
        b"warn"   => ngx_core::log::NGX_LOG_WARN,
        b"error"  => ngx_core::log::NGX_LOG_ERR,
        _ => return Err(cf.emerg(format_args!("invalid level \"{}\"", ngx_core::string::B(&cf.args[1])))),
    };
    cell.borrow_mut().log_level = Val::set(level);
    Ok(())
}

fn limit_conn_status(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 { return Err(msg("invalid number of arguments")); }
    let s = std::str::from_utf8(&cf.args[1])
        .map_err(|_| cf.emerg(format_args!("invalid status")))?;
    let n: u32 = s.parse().map_err(|_| cf.emerg(format_args!("invalid status \"{}\"", s)))?;
    let cell = conf_rc::<LimitConnLocConf>(conf.as_ref().unwrap());
    cell.borrow_mut().status = Val::set(n);
    Ok(())
}

fn limit_conn_dry_run(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 { return Err(msg("invalid number of arguments")); }
    let cell = conf_rc::<LimitConnLocConf>(conf.as_ref().unwrap());
    let on = match cf.args[1].as_slice() {
        b"on" => true,
        b"off" => false,
        _ => return Err(cf.emerg(format_args!("invalid value"))),
    };
    cell.borrow_mut().dry_run = Val::set(on);
    Ok(())
}

// ------------------------------------------------------------------
// Runtime counters
// ------------------------------------------------------------------

thread_local! {
    /// zone_name -> (key_bytes -> current_conn_count)
    static COUNTS: RefCell<HashMap<Vec<u8>, HashMap<Vec<u8>, u32>>> = RefCell::new(HashMap::new());
}

fn incr(zone: &[u8], key: &[u8]) -> u32 {
    COUNTS.with(|c| {
        let mut m = c.borrow_mut();
        let z = m.entry(zone.to_vec()).or_insert_with(HashMap::new);
        let e = z.entry(key.to_vec()).or_insert(0);
        *e += 1;
        *e
    })
}

fn decr(zone: &[u8], key: &[u8]) {
    COUNTS.with(|c| {
        let mut m = c.borrow_mut();
        if let Some(z) = m.get_mut(zone) {
            if let Some(e) = z.get_mut(key) {
                if *e > 1 { *e -= 1; }
                else { z.remove(key); }
            }
            if z.is_empty() { m.remove(zone); }
        }
    });
}

// Cleanup entry that fires when the request completes and drops the
// tracked keys.
struct ReleaseKeys(Vec<(Vec<u8>, Vec<u8>)>);
impl Drop for ReleaseKeys {
    fn drop(&mut self) {
        for (zone, key) in self.0.drain(..) {
            decr(&zone, &key);
        }
    }
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(
        cf,
        NGX_HTTP_PREACCESS_PHASE,
        Rc::new(|r| Box::pin(limit_conn_handler(r))),
    );
    Ok(())
}

/// Per-request marker for what limit_conn did.
#[derive(Clone, Copy)]
enum Status { Passed, Rejected, RejectedDryRun }

thread_local! { static STATUS: RefCell<HashMap<u64, Status>> = RefCell::new(HashMap::new()); }

fn set_status(r: &R, s: Status) {
    STATUS.with(|m| { m.borrow_mut().insert(Rc::as_ptr(r) as u64, s); });
}
fn get_status(r: &R) -> Option<Status> {
    STATUS.with(|m| m.borrow().get(&(Rc::as_ptr(r) as u64)).copied())
}
fn clear_status(r: &R) {
    STATUS.with(|m| { m.borrow_mut().remove(&(Rc::as_ptr(r) as u64)); });
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = [
        crate::variables::VarDef {
            name: "limit_conn_status",
            set: None,
            get: Some(var_limit_conn_status),
            data: 0,
            flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE,
        },
    ];
    crate::variables::add_variables(cf, &vars)
}

fn var_limit_conn_status(r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    match get_status(r) {
        Some(Status::Passed) => { v.data = b"PASSED".to_vec(); v.valid = true; }
        Some(Status::Rejected) => { v.data = b"REJECTED".to_vec(); v.valid = true; }
        Some(Status::RejectedDryRun) => { v.data = b"REJECTED_DRY_RUN".to_vec(); v.valid = true; }
        None => { v.not_found = true; }
    }
    NGX_OK
}

async fn limit_conn_handler(r: R) -> i64 {
    use ngx_core::log::*;

    if !r.is_main() {
        return NGX_DECLINED;
    }
    let (limits, log_level, status, dry_run) = {
        let cell = r.loc_conf::<LimitConnLocConf>(ctx_index());
        let c = cell.borrow();
        (
            c.limits.get().clone(),
            *c.log_level.get(),
            *c.status.get(),
            *c.dry_run.get(),
        )
    };
    if limits.is_empty() {
        return NGX_DECLINED;
    }
    let mcf = r.main_conf::<LimitConnMainConf>(ctx_index());
    let zones = mcf.borrow().zones.clone();

    let mut acquired: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(limits.len());
    let mut saw_dry_reject = false;
    for (zone_name, max_n) in &limits {
        let cv = match zones.get(zone_name) {
            Some(cv) => cv.clone(),
            None => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None,
                    "unknown limit_conn zone \"{}\"", ngx_core::string::B(zone_name));
                // Roll back partial acquires.
                drop(ReleaseKeys(acquired));
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        };
        let key = match crate::script::complex_value(&r, &cv) {
            Ok(v) => v,
            Err(_) => {
                drop(ReleaseKeys(acquired));
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        };
        if key.is_empty() { continue; }
        let n = incr(zone_name, &key);
        if n > *max_n {
            // Over the limit — drop this one and roll back the earlier
            // acquires so the request doesn't accidentally hold a slot.
            decr(zone_name, &key);
            if dry_run {
                ngx_core::ngx_log_error!(log_level, r.connection.log, None,
                    "limiting connections, dry run, by zone \"{}\"", ngx_core::string::B(zone_name));
                saw_dry_reject = true;
                acquired.push((zone_name.clone(), key));
                continue;
            }
            ngx_core::ngx_log_error!(log_level, r.connection.log, None,
                "limiting connections by zone \"{}\"", ngx_core::string::B(zone_name));
            set_status(&r, Status::Rejected);
            drop(ReleaseKeys(acquired));
            let rp = Rc::as_ptr(&r) as u64;
            r.add_cleanup(Box::new(move || {
                STATUS.with(|m| { m.borrow_mut().remove(&rp); });
            }));
            return status as i64;
        }
        acquired.push((zone_name.clone(), key));
    }

    set_status(&r, if saw_dry_reject { Status::RejectedDryRun } else { Status::Passed });
    // Register cleanup to release the counts when the request is done.
    let release = ReleaseKeys(acquired);
    let rp = Rc::as_ptr(&r) as u64;
    r.add_cleanup(Box::new(move || {
        drop(release);
        STATUS.with(|m| { m.borrow_mut().remove(&rp); });
    }));

    NGX_DECLINED
}

// ------------------------------------------------------------------
// Module definition
// ------------------------------------------------------------------

pub fn limit_conn_module() -> ModuleDef {
    let def = HttpModuleDef {
        create_main_conf: Some(create_main_conf),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        preconfiguration: Some(add_variables),
        postconfiguration: Some(init),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("limit_conn_zone", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2, ConfLevel::None, limit_conn_zone),
        cmd_fn!("limit_conn", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, limit_conn_directive),
        cmd_fn!("limit_conn_log_level", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, limit_conn_log_level),
        cmd_fn!("limit_conn_status", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, limit_conn_status),
        cmd_fn!("limit_conn_dry_run", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, limit_conn_dry_run),
    ];
    http_module_def("ngx_http_limit_conn_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_incr_decr() {
        assert_eq!(incr(b"z", b"k"), 1);
        assert_eq!(incr(b"z", b"k"), 2);
        decr(b"z", b"k");
        assert_eq!(incr(b"z", b"k"), 2);
        decr(b"z", b"k");
        decr(b"z", b"k");
    }
}
