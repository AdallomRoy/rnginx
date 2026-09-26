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

    let mut chain = chain;
    if let Some(ctx) = ctx_opt {
        let mut ctx_ref = ctx.borrow_mut();
        if !ctx_ref.before_body_sent {
            ctx_ref.before_body_sent = true;
            if !conf_ref.before_body.get().is_empty() {
                let before_uri = conf_ref.before_body.get().clone();
                drop(ctx_ref);
                let _ = subrequest(&r, &before_uri, None, 0, None).await;
                // Subrequest wrote through write_filter to the shared
                // connection before returning, so its bytes are already in
                // flight — nothing more to do here.
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

    // Send the after_body subrequest, again absorbing its output into our
    // chain so it appears after the main body.
    let after_body = conf_ref.after_body.get().clone();
    drop(conf_ref);

    // After the last body chunk, run the after_body subrequest. Same shared-
    // connection story as before_body — write_filter sends its bytes.
    let _ = subrequest(&r, &after_body, None, 0, None).await;

    // Terminate the response with an empty last_buf so write_filter flushes
    // the connection. Without postpone_filter we have to inject this
    // ourselves; C achieves it because the subrequest's postpone-flush
    // eventually propagates last_buf into the parent's chain.
    use ngx_core::buf::Buf;
    let mut end_chain: Chain = Chain::new();
    let mut b = Buf::from_vec(Vec::new());
    b.last_buf = true;
    b.last_in_chain = true;
    b.sync = true;
    end_chain.push_back(b);
    let _ = next(r.clone(), end_chain).await;
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
