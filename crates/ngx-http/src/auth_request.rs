//! ngx_http_auth_request_module

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_error};

use crate::*;
use crate::core::*;
use crate::request::*;
use crate::request_rt::*;
use crate::script::*;

crate::http_module_index!("ngx_http_auth_request_module");

#[derive(Clone)]
pub struct AuthRequestVariable {
    pub var_index: usize,
    pub value: ComplexValue,
}

pub struct AuthRequestLocConf {
    pub uri: Val<Vec<u8>>,
    pub vars: Vec<AuthRequestVariable>,
}

pub struct AuthRequestCtx {
    pub done: bool,
    pub status: i64,
    pub subrequest_response: Option<Box<R>>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AuthRequestLocConf {
        uri: Val::unset(),
        vars: Vec::new(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AuthRequestLocConf>(prev).borrow();
    let mut c = conf_cell::<AuthRequestLocConf>(conf).borrow_mut();

    c.uri.merge(&p.uri, Vec::new());

    if c.vars.is_empty() {
        c.vars = p.vars.clone();
    }

    Ok(())
}

fn set_auth_request(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AuthRequestLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    let uri = args[1].clone();
    if uri == b"off" {
        return Ok(());
    }

    cell.borrow_mut().uri = Val::set(uri);
    Ok(())
}

fn set_auth_request_set(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AuthRequestLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    // Parse variable name
    let var_name = &args[1];
    if var_name.is_empty() || var_name[0] != b'$' {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(var_name))));
    }

    // Compile the complex value
    let cv = compile_complex_value(cf, &args[2], 0)?;

    // Get variable index
    let var_index = match add_variable(cf, var_name) {
        Some(idx) => idx,
        None => return Err(cf.emerg(format_args!("cannot add variable \"{}\"", B(var_name)))),
    };

    cell.borrow_mut().vars.push(AuthRequestVariable {
        var_index,
        value: cv,
    });

    Ok(())
}

fn add_variable(cf: &Conf, name: &[u8]) -> Option<usize> {
    // For now, just return a dummy index. The variable handling needs to be integrated
    // with the core variables system during preconfiguration
    Some(0)
}

pub fn auth_request_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("auth_request", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_auth_request),
        cmd_fn!("auth_request_set", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, set_auth_request_set),
    ];
    http_module_def("ngx_http_auth_request_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_ACCESS_PHASE,
        Rc::new(|r| Box::pin(auth_request_handler(r))),
    );
    Ok(())
}

async fn auth_request_handler(r: R) -> i64 {
    let conf = r.loc_conf::<AuthRequestLocConf>(ctx_index());
    let conf = conf.borrow();

    let uri = match &conf.uri.0 {
        Some(v) => v.clone(),
        None => return NGX_DECLINED,
    };

    if uri.is_empty() || uri == b"off" {
        return NGX_DECLINED;
    }

    // Check if context already exists
    if let Some(ctx) = r.get_ctx::<AuthRequestCtx>(ctx_index()) {
        let ctx_ref = ctx.borrow();
        if !ctx_ref.done {
            return NGX_AGAIN;
        }

        // Set variables from subrequest
        if set_variables(&r, &conf, &*ctx_ref).is_err() {
            return NGX_ERROR;
        }

        return ctx_ref.status;
    }

    // Create new context
    let uri_bytes = uri.clone();

    // Issue subrequest
    let flags = NGX_HTTP_SUBREQUEST_WAITED;
    match subrequest(&r, &uri_bytes, None, flags, None).await {
        Ok((sr, status)) => {
            let ctx_val = AuthRequestCtx {
                done: true,
                status,
                subrequest_response: Some(Box::new(sr)),
            };

            let ctx = r.set_ctx(ctx_index(), ctx_val);

            let ctx_ref = ctx.borrow();
            // Set variables from subrequest
            if set_variables(&r, &conf, &*ctx_ref).is_err() {
                return NGX_ERROR;
            }

            ctx_ref.status
        }
        Err(_) => {
            let ctx_val = AuthRequestCtx {
                done: true,
                status: NGX_HTTP_INTERNAL_SERVER_ERROR,
                subrequest_response: None,
            };
            let _ = r.set_ctx(ctx_index(), ctx_val);
            NGX_HTTP_INTERNAL_SERVER_ERROR
        }
    }
}

fn set_variables(r: &R, conf: &AuthRequestLocConf, ctx: &AuthRequestCtx) -> Result<(), i64> {
    if let Some(sr) = &ctx.subrequest_response {
        for var in &conf.vars {
            match complex_value(sr, &var.value) {
                Ok(v) => {
                    // Set the variable value - this is a placeholder
                    // Proper variable setting would need to be integrated with variables.rs
                }
                Err(_) => return Err(NGX_ERROR),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
}
