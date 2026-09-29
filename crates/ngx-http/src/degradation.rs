//! ngx_http_degradation_module: monitor memory usage and degrade responses

use std::any::Any;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::*;

crate::http_module_index!("ngx_http_degradation_module");

pub struct DegradationMainConf {
    pub sbrk_size: Val<usize>,
}

pub struct DegradationLocConf {
    pub degrade: Val<u32>,
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(DegradationMainConf {
        sbrk_size: Val::unset(),
    })
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(DegradationLocConf {
        degrade: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<DegradationLocConf>(prev).borrow();
    let mut c = conf_cell::<DegradationLocConf>(conf).borrow_mut();
    c.degrade.merge(&p.degrade, 0);
    Ok(())
}

pub fn degradation_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_main_conf: Some(create_main_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("degradation", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, set_degradation),
        ngx_core::cmd!("degrade", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, DegradationLocConf, degrade, set_enum, &[("204", 204), ("444", 444)]),
    ];
    http_module_def("ngx_http_degradation_module", def, commands)
}

fn set_degradation(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<DegradationMainConf>(conf.as_ref().unwrap());
    let value = &cf.args[1];

    if value.len() > 5 && &value[..5] == b"sbrk=" {
        let size_bytes = &value[5..];
        let sbrk_size = ngx_core::parse::parse_size(size_bytes).ok_or(msg("invalid sbrk size"))?;
        cell.borrow_mut().sbrk_size = Val::set(sbrk_size);
        Ok(())
    } else {
        Err(cf.emerg(format_args!("invalid parameter \"{}\"", String::from_utf8_lossy(value))))
    }
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(cf, NGX_HTTP_PREACCESS_PHASE, Rc::new(|r| Box::pin(degradation_handler(r))));
    Ok(())
}

async fn degradation_handler(r: R) -> i64 {
    use ngx_core::rc::*;

    let conf = r.loc_conf::<DegradationLocConf>(ctx_index());
    let degrade_status = *conf.borrow().degrade.get();

    if degrade_status == 0 {
        return NGX_DECLINED;
    }

    if is_degraded(&r) {
        return degrade_status as i64;
    }

    NGX_DECLINED
}

// Thread-local state for memory tracking
thread_local! {
    static SBRK_STATE: Mutex<SbrkState> = Mutex::new(SbrkState {
        size: 0,
        time: 0,
    });
}

struct SbrkState {
    size: usize,
    time: u64,
}

fn is_degraded(r: &R) -> bool {
    use ngx_core::rc::*;

    let main_conf = r.main_conf::<DegradationMainConf>(ctx_index());
    let main_conf = main_conf.borrow();

    if !main_conf.sbrk_size.is_set() {
        return false;
    }

    let sbrk_limit = *main_conf.sbrk_size.get();
    if sbrk_limit == 0 {
        return false;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut should_log = false;
    let is_over_limit = SBRK_STATE.with(|state| {
        let mut state = state.lock().unwrap();
        if now != state.time {
            // Update sbrk size (using memory usage as proxy)
            state.size = estimate_heap_size();
            state.time = now;
            should_log = true;
        }
        state.size >= sbrk_limit
    });

    if is_over_limit && should_log {
        SBRK_STATE.with(|state| {
            let state = state.lock().unwrap();
            ngx_log_error!(NGX_LOG_NOTICE, r.log(), None, "degradation sbrk:{}M", state.size / (1024 * 1024));
        });
    }

    is_over_limit
}

fn estimate_heap_size() -> usize {
    // Simple estimation based on current memory usage
    // In a real implementation, we'd use sbrk(0) or similar
    // For now, use a simple heuristic
    std::mem::size_of::<usize>() * 1000 // Placeholder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_degradation_conf() {
        let conf = DegradationLocConf {
            degrade: Val::unset(),
        };
        assert!(!conf.degrade.is_set());
    }
}
