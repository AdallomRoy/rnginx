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
    /// Cached set_handler (from the variable's original registration). Called after
    /// storing the value so side-effecting variables like $args update r->args.
    pub set_handler: Option<crate::variables::SetHandler>,
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

    // Match C ngx_http_auth_request_set: register the variable, set its fallback
    // get_handler if not already installed, then get its index.
    let var_name_bare = &var_name[1..];
    let v = crate::variables::add_variable(cf, var_name_bare, crate::variables::NGX_HTTP_VAR_CHANGEABLE)?;

    let var_index = match crate::variables::get_variable_index(cf, var_name_bare) {
        Ok(idx) => idx,
        Err(_) => return Err(cf.emerg(format_args!("cannot add variable \"{}\"", B(var_name)))),
    };

    if v.get_handler.get().is_none() {
        // Fallback handler: returns "not_found" when the auth subrequest never ran
        // for this location (e.g. the variable is read outside an auth_request-guarded
        // location). auth_request_handler will overwrite via set_indexed_variable when
        // it does run.
        v.get_handler.set(Some(auth_request_variable));
        v.data.set(var_index);
    }

    // Capture the variable's set_handler so we can re-invoke it at set time (e.g.
    // $args updates r.args). C stores this in av->set_handler.
    let set_handler = v.set_handler.get();

    cell.borrow_mut().vars.push(AuthRequestVariable {
        var_index,
        value: cv,
        set_handler,
    });

    Ok(())
}

fn auth_request_variable(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    v.not_found = true;
    NGX_OK
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

/// ngx_http_auth_request_handler
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

    http_debug!(r, "auth request handler");

    if let Some(ctx) = r.get_ctx::<AuthRequestCtx>(ctx_index()) {
        return auth_request_status(&r, &conf, &ctx);
    }

    // ngx_http_subrequest(r, &arcf->uri, NULL, &sr, ps, NGX_HTTP_SUBREQUEST_WAITED),
    // then, before it runs, a fake request body (so that the subrequest does not
    // read the client's, nor its upstream close the body file) and
    // sr->header_only = 1
    let sr = match subrequest_posted(&r, &uri, None, NGX_HTTP_SUBREQUEST_WAITED, None) {
        Ok(sr) => sr,
        Err(()) => return NGX_ERROR,
    };

    *sr.request_body.borrow_mut() = Some(Rc::new(RefCell::new(RequestBody {
        temp_file: None,
        bufs: ngx_core::buf::Chain::new(),
        buf: None,
        rest: 0,
        received: 0,
        chunked: None,
        filter_need_buffering: false,
        last_sent: false,
        last_saved: false,
        buf_size: 0,
        buf_last: 0,
    })));

    sr.header_only.set(true);

    // the handler returns NGX_AGAIN in C, and the posted subrequest runs
    crate::postpone_filter::run_posted_requests(&r).await;

    // ngx_http_auth_request_done: the status of the subrequest
    let status = sr.headers_out.borrow().status;

    http_debug!(sr, "auth request done s:{}", status);

    let ctx = r.set_ctx(ctx_index(), AuthRequestCtx { done: true, status, subrequest_response: Some(Box::new(sr)) });

    // the phase handler again, with the subrequest done
    auth_request_status(&r, &conf, &ctx)
}

/// The part of ngx_http_auth_request_handler once the subrequest is done:
/// the variables of auth_request_set, then the status to return: 403 and
/// 401 as they are (with the WWW-Authenticate headers of the subrequest, or
/// those of its upstream), NGX_OK for 2xx, else 500.
fn auth_request_status(r: &R, conf: &AuthRequestLocConf, ctx: &Rc<RefCell<AuthRequestCtx>>) -> i64 {
    let ctx = ctx.borrow();

    if !ctx.done {
        return NGX_AGAIN;
    }

    // as soon as we are done - explicitly set variables to make sure they
    // will be available after internal redirects

    if set_variables(r, conf, &ctx).is_err() {
        return NGX_ERROR;
    }

    // return appropriate status

    if ctx.status == NGX_HTTP_FORBIDDEN {
        return ctx.status;
    }

    if ctx.status == NGX_HTTP_UNAUTHORIZED {
        if let Some(sr) = &ctx.subrequest_response {
            let mut h: Vec<Header> = sr.headers_out.borrow().www_authenticate.clone();

            if h.is_empty() {
                // sr->upstream->headers_in.www_authenticate
                h = sr.upstream_headers_in.borrow().iter().filter(|h| h.lowcase_key == b"www-authenticate").cloned().collect();
            }

            let mut ho = r.headers_out.borrow_mut();

            for h in h.iter() {
                let o = TableElt::with_hash(&h.key, &h.value.borrow(), h.hash.get(), h.lowcase_key.clone());

                ho.headers.push(o.clone());
                ho.www_authenticate.push(o);
            }
        }

        return ctx.status;
    }

    if ctx.status >= NGX_HTTP_OK && ctx.status < NGX_HTTP_SPECIAL_RESPONSE {
        return NGX_OK;
    }

    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "auth request unexpected status: {}", ctx.status);

    NGX_HTTP_INTERNAL_SERVER_ERROR
}

fn set_variables(r: &R, conf: &AuthRequestLocConf, ctx: &AuthRequestCtx) -> Result<(), i64> {
    if let Some(sr) = &ctx.subrequest_response {
        for var in &conf.vars {
            match complex_value(sr, &var.value) {
                Ok(v) => {
                    crate::variables::set_indexed_variable(r, var.var_index, v.clone());
                    // C also calls av->set_handler if the variable had one (e.g. $args
                    // side-effects r->args). Mirror that.
                    if let Some(handler) = var.set_handler {
                        let mut vv = VariableValue {
                            data: v,
                            valid: true,
                            not_found: false,
                            no_cacheable: false,
                            escape: false,
                        };
                        handler(r, &mut vv, var.var_index);
                    }
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
