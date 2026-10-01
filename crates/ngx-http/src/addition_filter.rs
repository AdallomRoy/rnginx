//! ngx_http_addition_filter_module: adds content before and after the response body

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::Chain;
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request_rt::subrequest_posted;
use crate::*;

crate::http_module_index!("ngx_http_addition_filter_module");

#[derive(Clone)]
pub struct AdditionLocConf {
    pub before_body: Val<Vec<u8>>,
    pub after_body: Val<Vec<u8>>,
    /// addition_types list (lowercased). None -> use default ("text/html").
    pub types: Option<Vec<Vec<u8>>>,
}

#[derive(Clone)]
struct AdditionCtx {
    before_body_sent: bool,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AdditionLocConf {
        before_body: Val::unset(),
        after_body: Val::unset(),
        types: None,
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AdditionLocConf>(prev).borrow();
    let mut c = conf_cell::<AdditionLocConf>(conf).borrow_mut();

    c.before_body.merge(&p.before_body, Vec::new());
    c.after_body.merge(&p.after_body, Vec::new());
    if c.types.is_none() {
        c.types = p.types.clone();
    }

    Ok(())
}

pub fn addition_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!("add_before_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, AdditionLocConf, before_body, set_str),
        ngx_core::cmd!("add_after_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, AdditionLocConf, after_body, set_str),
        ngx_core::cmd_fn!("addition_types", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, set_types),
    ];
    http_module_def("ngx_http_addition_filter_module", def, commands)
}

fn set_types(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AdditionLocConf>(conf.as_ref().unwrap());
    let mut types: Vec<Vec<u8>> = Vec::new();
    for arg in cf.args.iter().skip(1) {
        types.push(arg.to_ascii_lowercase());
    }
    cell.borrow_mut().types = Some(types);
    Ok(())
}

fn init(_cf: &mut Conf) -> ConfResult {
    crate::install_header_filter_idle(addition_header_idle, addition_header_filter);
    crate::install_body_filter_idle(addition_body_idle, addition_body_filter);
    Ok(())
}

/// addition_header_filter passes the response on as it is: not a 200 of
/// the main request, or no add_before_body/add_after_body
fn addition_header_idle(r: &R) -> bool {
    if r.headers_out.borrow().status != NGX_HTTP_OK || !r.is_main() {
        return true;
    }

    let conf = r.loc_conf::<AdditionLocConf>(ctx_index());
    let c = conf.borrow();
    c.before_body.get().is_empty() && c.after_body.get().is_empty()
}

async fn addition_header_filter(r: R, next: HeaderFilter) -> i64 {
    let status = r.headers_out.borrow().status;
    if status != NGX_HTTP_OK || !r.is_main() {
        return next(r).await;
    }

    let conf = r.loc_conf::<AdditionLocConf>(ctx_index());
    let conf = conf.borrow();

    if conf.before_body.get().is_empty() && conf.after_body.get().is_empty() {
        drop(conf);
        return next(r).await;
    }

    // Match C: only fire addition for content-types in addition_types
    // (default: text/html only). "*" matches any.
    {
        let ct = r.headers_out.borrow().content_type.clone();
        let ct_bare: Vec<u8> = ct.split(|&b| b == b';').next().unwrap_or(&ct).to_ascii_lowercase();
        let matched = if let Some(types) = &conf.types {
            if types.iter().any(|t| t.as_slice() == b"*") {
                true
            } else {
                types.iter().any(|t| t.as_slice() == ct_bare.as_slice())
            }
        } else {
            ct_bare.as_slice() == b"text/html"
        };
        if !matched {
            drop(conf);
            return next(r).await;
        }
    }

    drop(conf);

    // Create context
    let ctx = AdditionCtx {
        before_body_sent: false,
    };
    r.set_ctx(ctx_index(), ctx);

    r.clear_content_length();
    r.clear_accept_ranges();
    core_rt::weak_etag(&r);

    r.preserve_body.set(true);

    next(r).await
}

/// ngx_http_addition_body_filter: the subrequests are posted ones
/// (ngx_http_subrequest), which the request waits for once its handler is
/// done (request_rt::finalize_request).
/// addition_body_filter passes the chain on as it is
fn addition_body_idle(r: &R, chain: &Chain) -> bool {
    chain.is_empty() || r.header_only.get() || !r.has_ctx(ctx_index())
}

async fn addition_body_filter(r: R, mut chain: Chain, next: BodyFilter) -> i64 {
    if chain.is_empty() || r.header_only.get() {
        return next(r, chain).await;
    }

    let ctx = match r.get_ctx::<AdditionCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r, chain).await,
    };

    let (before_body, after_body) = {
        let conf = r.loc_conf::<AdditionLocConf>(ctx_index());
        let conf = conf.borrow();
        (conf.before_body.get().clone(), conf.after_body.get().clone())
    };

    let before_body_sent = std::mem::replace(&mut ctx.borrow_mut().before_body_sent, true);

    if !before_body_sent && !before_body.is_empty() && subrequest_posted(&r, &before_body, None, 0, None).is_err() {
        return NGX_ERROR;
    }

    if after_body.is_empty() {
        r.clear_ctx(ctx_index());
        return next(r, chain).await;
    }

    let mut last = false;

    for b in chain.iter_mut() {
        if b.last_buf {
            b.last_buf = false;
            b.last_in_chain = true;
            b.sync = true;
            last = true;
        }
    }

    let rc = next(r.clone(), chain).await;

    if rc == NGX_ERROR || !last {
        return rc;
    }

    if subrequest_posted(&r, &after_body, None, 0, None).is_err() {
        return NGX_ERROR;
    }

    r.clear_ctx(ctx_index());

    crate::special_response::send_special(&r, true).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition_conf() {
        let conf = AdditionLocConf {
            before_body: Val::unset(),
            after_body: Val::unset(),
            types: None,
        };
        assert!(!conf.before_body.is_set());
        assert!(!conf.after_body.is_set());
    }
}
