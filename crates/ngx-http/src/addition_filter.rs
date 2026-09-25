//! ngx_http_addition_filter_module: adds content before and after the response body

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::Chain;
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request_rt::subrequest;
use crate::*;

crate::http_module_index!("ngx_http_addition_filter_module");

#[derive(Clone)]
pub struct AdditionLocConf {
    pub before_body: Val<Vec<u8>>,
    pub after_body: Val<Vec<u8>>,
}

#[derive(Clone)]
struct AdditionCtx {
    before_body_sent: bool,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AdditionLocConf {
        before_body: Val::unset(),
        after_body: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AdditionLocConf>(prev).borrow();
    let mut c = conf_cell::<AdditionLocConf>(conf).borrow_mut();

    c.before_body.merge(&p.before_body, Vec::new());
    c.after_body.merge(&p.after_body, Vec::new());

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
    ];
    http_module_def("ngx_http_addition_filter_module", def, commands)
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { addition_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { addition_body_filter(r, chain, next).await });
    Ok(())
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

    drop(conf);

    // Create context
    let ctx = AdditionCtx {
        before_body_sent: false,
    };
    r.set_ctx(ctx_index(), Rc::new(RefCell::new(ctx)));

    r.clear_content_length();
    r.clear_accept_ranges();
    core_rt::weak_etag(&r);

    next(r).await
}

async fn addition_body_filter(r: R, chain: Chain, next: BodyFilter) -> i64 {
    if chain.is_empty() || r.header_only.get() {
        return next(r, chain).await;
    }

    let ctx_opt = r.get_ctx::<AdditionCtx>(ctx_index());
    if ctx_opt.is_none() {
        return next(r, chain).await;
    }

    let conf = r.loc_conf::<AdditionLocConf>(ctx_index());
    let conf_ref = conf.borrow();

    if let Some(ctx) = ctx_opt {
        let mut ctx_ref = ctx.borrow_mut();
        if !ctx_ref.before_body_sent {
            ctx_ref.before_body_sent = true;
            if !conf_ref.before_body.get().is_empty() {
                let _ = subrequest(&r, conf_ref.before_body.get(), None, 0, None).await;
            }
        }
    }

    if conf_ref.after_body.get().is_empty() {
        drop(conf_ref);
        return next(r, chain).await;
    }

    // Check if this is the last buffer
    let mut has_last = false;
    for buf in chain.iter() {
        if buf.last_buf {
            has_last = true;
            break;
        }
    }

    // Clear last_buf flags
    let mut modified = Chain::new();
    for mut buf in chain {
        if buf.last_buf {
            buf.last_buf = false;
            buf.last_in_chain = true;
            buf.sync = true;
        }
        modified.push_back(buf);
    }

    let rc = next(r.clone(), modified).await;

    if rc == NGX_ERROR || !has_last {
        drop(conf_ref);
        return rc;
    }

    // Send the after_body subrequest
    let after_body = conf_ref.after_body.get().clone();
    drop(conf_ref);

    let _ = subrequest(&r, &after_body, None, 0, None).await;

    NGX_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition_conf() {
        let conf = AdditionLocConf {
            before_body: Val::unset(),
            after_body: Val::unset(),
        };
        assert!(conf.before_body.is_unset());
        assert!(conf.after_body.is_unset());
    }
}
