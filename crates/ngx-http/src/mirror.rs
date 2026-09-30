//! ngx_http_mirror_module: mirrors requests to other URIs with background
//! subrequests.

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request_rt::subrequest_posted;
use crate::*;

crate::http_module_index!("ngx_http_mirror_module");

/// ngx_http_mirror_loc_conf_t: unset (NGX_CONF_UNSET_PTR), the list of
/// URIs, or "mirror off" (NULL in C), which is the empty list here.
pub struct MirrorLocConf {
    pub mirror: Val<Vec<Vec<u8>>>,
    pub request_body: Val<bool>,
}

/// ngx_http_mirror_ctx_t
struct MirrorCtx {
    status: i64,
}

/// ngx_http_mirror_create_loc_conf
fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(MirrorLocConf {
        mirror: Val::unset(),
        request_body: Val::unset(),
    })
}

/// ngx_http_mirror_merge_loc_conf
fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<MirrorLocConf>(prev).borrow();
    let mut c = conf_cell::<MirrorLocConf>(conf).borrow_mut();
    c.mirror.merge(&p.mirror, Vec::new());
    c.request_body.merge(&p.request_body, true);
    Ok(())
}

pub fn mirror_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("mirror", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, mirror_directive),
        ngx_core::cmd!("mirror_request_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, MirrorLocConf, request_body, set_flag),
    ];
    http_module_def("ngx_http_mirror_module", def, commands)
}

/// ngx_http_mirror
fn mirror_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<MirrorLocConf>(conf.as_ref().unwrap());
    let value = cf.args[1].clone();

    let rv = mirror_add(&mut cell.borrow_mut(), value);
    rv.map_err(msg)
}

/// What ngx_http_mirror() does with the value of the directive.
fn mirror_add(mlcf: &mut MirrorLocConf, value: Vec<u8>) -> Result<(), &'static str> {
    if value == b"off" {
        if mlcf.mirror.is_set() {
            return Err("is duplicate");
        }

        mlcf.mirror = Val::set(Vec::new());
        return Ok(());
    }

    let mut mirror = match mlcf.mirror.as_option() {
        Some(m) if m.is_empty() => return Err("is duplicate"),
        Some(m) => m.clone(),
        None => Vec::new(),
    };

    mirror.push(value);
    mlcf.mirror = Val::set(mirror);

    Ok(())
}

/// ngx_http_mirror_init
fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(cf, NGX_HTTP_PRECONTENT_PHASE, Rc::new(|r| Box::pin(mirror_handler(r))));
    Ok(())
}

/// ngx_http_mirror_handler
async fn mirror_handler(r: R) -> i64 {
    if !r.is_main() {
        return NGX_DECLINED;
    }

    let mlcf = r.loc_conf::<MirrorLocConf>(ctx_index());

    let request_body = {
        let mlcf = mlcf.borrow();

        if mlcf.mirror.as_option().is_none_or(|m| m.is_empty()) {
            return NGX_DECLINED;
        }

        *mlcf.request_body.get()
    };

    http_debug!(r, "mirror handler");

    if request_body {
        if let Some(ctx) = r.get_ctx::<MirrorCtx>(ctx_index()) {
            return ctx.borrow().status;
        }

        let ctx = r.set_ctx(ctx_index(), MirrorCtx { status: NGX_DONE });

        let rc = crate::request_body::read_client_request_body(&r).await;
        if rc >= NGX_HTTP_SPECIAL_RESPONSE {
            return rc;
        }

        // ngx_http_mirror_body_handler: the phases go on at this handler,
        // which returns ctx->status then
        let status = mirror_handler_internal(&r);
        ctx.borrow_mut().status = status;

        r.preserve_body.set(true);

        return status;
    }

    mirror_handler_internal(&r)
}

/// ngx_http_mirror_handler_internal: a background subrequest for each URI;
/// they run once this request waits, with the method of the request and
/// header_only, and the connection is not finalized before they are over.
fn mirror_handler_internal(r: &R) -> i64 {
    let mlcf = r.loc_conf::<MirrorLocConf>(ctx_index());
    let mirror = mlcf.borrow().mirror.get().clone();

    let args = r.args.borrow().clone();
    let method = r.method.get();
    let method_name = r.method_name.borrow().clone();

    for name in mirror.iter() {
        let sr = match subrequest_posted(r, name, Some(&args), NGX_HTTP_SUBREQUEST_BACKGROUND, None) {
            Ok(sr) => sr,
            Err(()) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
        };

        sr.header_only.set(true);
        sr.method.set(method);
        *sr.method_name.borrow_mut() = method_name.clone();
    }

    NGX_DECLINED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf() -> MirrorLocConf {
        MirrorLocConf { mirror: Val::unset(), request_body: Val::unset() }
    }

    #[test]
    fn test_mirror_add() {
        let mut c = conf();
        assert!(mirror_add(&mut c, b"/m1".to_vec()).is_ok());
        assert!(mirror_add(&mut c, b"/m2".to_vec()).is_ok());
        assert_eq!(c.mirror.get(), &vec![b"/m1".to_vec(), b"/m2".to_vec()]);

        // "off" after a URI, and anything after "off"
        assert_eq!(mirror_add(&mut c, b"off".to_vec()), Err("is duplicate"));

        let mut c = conf();
        assert!(mirror_add(&mut c, b"off".to_vec()).is_ok());
        assert!(c.mirror.get().is_empty());
        assert_eq!(mirror_add(&mut c, b"off".to_vec()), Err("is duplicate"));
        assert_eq!(mirror_add(&mut c, b"/m".to_vec()), Err("is duplicate"));

        // ngx_strcmp(): "OFF" is a URI
        let mut c = conf();
        assert!(mirror_add(&mut c, b"OFF".to_vec()).is_ok());
        assert_eq!(c.mirror.get(), &vec![b"OFF".to_vec()]);
    }

    #[test]
    fn test_mirror_merge() {
        // ngx_conf_merge_ptr_value(conf->mirror, prev->mirror, NULL)
        let mut c = conf();
        c.mirror.merge(&Val::unset(), Vec::new());
        assert!(c.mirror.get().is_empty());

        let mut p = conf();
        mirror_add(&mut p, b"/m".to_vec()).unwrap();
        let mut c = conf();
        c.mirror.merge(&p.mirror, Vec::new());
        assert_eq!(c.mirror.get(), &vec![b"/m".to_vec()]);

        let mut c = conf();
        mirror_add(&mut c, b"off".to_vec()).unwrap();
        c.mirror.merge(&p.mirror, Vec::new());
        assert!(c.mirror.get().is_empty());
    }
}
