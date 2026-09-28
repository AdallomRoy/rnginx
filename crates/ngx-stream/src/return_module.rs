//! ngx_stream_return_module.c

use std::any::Any;
use std::rc::Rc;
use std::time::Duration;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::core::*;
use crate::handler::finalize_session;
use crate::script::*;
use crate::write_filter::{top_filter, WriteError};
use crate::*;

stream_module_index!("ngx_stream_return_module");

/// ngx_stream_return_srv_conf_t
#[derive(Default)]
pub struct ReturnSrvConf {
    pub text: Option<ComplexValue>,
}

/// ngx_stream_return_handler
async fn return_handler(s: S) {
    let c = s.connection.clone();

    c.log.set_action(Some("returning text"));

    let rscf = s.srv_conf::<ReturnSrvConf>(ctx_index());
    let cv = rscf.borrow().text.clone().unwrap_or_default();

    let text = match complex_value(&s, &cv) {
        Ok(t) => t,
        Err(()) => {
            finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return;
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream return text: \"{}\"", B(&text));

    if text.is_empty() {
        finalize_session(&s, NGX_STREAM_OK).await;
        return;
    }

    // ngx_stream_return_write_handler

    match top_filter(&s, &c, &[&text], true, Some(Duration::from_millis(5000))).await {
        Ok(()) => {}
        Err(WriteError::TimedOut) => {
            c.connection_error(libc::ETIMEDOUT, "connection timed out");
            finalize_session(&s, NGX_STREAM_OK).await;
            return;
        }
        Err(WriteError::Error) => {
            finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return;
        }
    }

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream return done sending");

    finalize_session(&s, NGX_STREAM_OK).await;
}

fn return_create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(ReturnSrvConf::default())
}

/// ngx_stream_return
fn return_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let rscf = conf_rc::<ReturnSrvConf>(conf.as_ref().expect("conf"));

    if rscf.borrow().text.is_some() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args[1].clone();

    let mut ccv = CompileComplexValue::default();
    let cv = compile_complex_value(cf, &value, &mut ccv)?;

    rscf.borrow_mut().text = Some(cv);

    let cscf = core_srv_conf(cf);
    cscf.borrow_mut().handler = Some(content_fn(return_handler));

    Ok(())
}

pub fn return_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_return_module",
        StreamModuleDef { create_srv_conf: Some(return_create_srv_conf), ..Default::default() },
        vec![cmd_fn!("return", NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, return_directive)],
    )
}
