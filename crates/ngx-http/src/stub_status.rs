//! ngx_http_stub_status_module: returns server statistics

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::CoreLocConf;
use crate::request::VariableValue;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_stub_status_module");

pub struct StubStatusConf;

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(StubStatusConf)
}

fn merge_conf(_cf: &mut Conf, _prev: &Rc<dyn Any>, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

pub fn stub_status_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![ngx_core::cmd_fn!(
        "stub_status",
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ConfLevel::Loc,
        set_handler
    )];
    http_module_def("ngx_http_stub_status_module", def, commands)
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = [
        VarDef {
            name: "connections_active",
            set: None,
            get: Some(stub_status_variable),
            data: 0,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "connections_reading",
            set: None,
            get: Some(stub_status_variable),
            data: 1,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "connections_writing",
            set: None,
            get: Some(stub_status_variable),
            data: 2,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
        VarDef {
            name: "connections_waiting",
            set: None,
            get: Some(stub_status_variable),
            data: 3,
            flags: NGX_HTTP_VAR_NOCACHEABLE,
        },
    ];
    variables::add_variables(cf, &vars)
}

fn stub_status_variable(r: &R, v: &mut VariableValue, data: usize) -> i64 {
    use ngx_core::rc::*;
    use std::sync::atomic::Ordering;
    let stats = ngx_core::connection::stats();
    let value = match data {
        0 => stats.active.load(Ordering::Relaxed),
        1 => stats.reading.load(Ordering::Relaxed),
        2 => stats.writing.load(Ordering::Relaxed),
        3 => stats.waiting.load(Ordering::Relaxed),
        _ => 0,
    };
    v.data = format!("{}", value).into_bytes();
    v.valid = true;
    NGX_OK
}

fn set_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let loc_conf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());
    loc_conf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(stub_status_handler(r))));
    Ok(())
}

fn init(_cf: &mut Conf) -> ConfResult {
    Ok(())
}

async fn stub_status_handler(r: R) -> i64 {
    use ngx_core::rc::*;
    use std::sync::atomic::Ordering;

    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return 405; // NGX_HTTP_NOT_ALLOWED
    }

    let stats = ngx_core::connection::stats();
    let output = format!(
        "Active connections: {} \nserver accepts handled requests\n {} {} {} \nReading: {} Writing: {} Waiting: {} \n",
        stats.active.load(Ordering::Relaxed),
        stats.accepted.load(Ordering::Relaxed),
        stats.handled.load(Ordering::Relaxed),
        stats.requests.load(Ordering::Relaxed),
        stats.reading.load(Ordering::Relaxed),
        stats.writing.load(Ordering::Relaxed),
        stats.waiting.load(Ordering::Relaxed)
    );

    let cv = ComplexValue::constant(output.as_bytes());
    core_rt::send_response(&r, NGX_HTTP_OK, Some(b"text/plain"), &cv).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_status_conf() {
        let _conf = StubStatusConf;
    }
}
