//! ngx_http_mirror_module: mirrors requests to other URIs asynchronously

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request_rt::subrequest;
use crate::*;

crate::http_module_index!("ngx_http_mirror_module");

pub struct MirrorLocConf {
    pub mirror: Val<Vec<Vec<u8>>>,
    pub request_body: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(MirrorLocConf {
        mirror: Val::unset(),
        request_body: Val::unset(),
    })
}

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

fn mirror_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<MirrorLocConf>(conf.as_ref().unwrap());
    let uri = cf.args[1].clone();

    if uri == b"off" {
        cell.borrow_mut().mirror = Val::set(Vec::new());
        return Ok(());
    }

    let mut c = cell.borrow_mut();

    // Get existing mirrors or start with empty
    let current_mirrors = c.mirror.as_option().map(|m| m.clone()).unwrap_or_default();

    // Add the new URI to the list
    let mut new_mirrors = current_mirrors;
    new_mirrors.push(uri);

    // Set the updated list
    c.mirror = Val::set(new_mirrors);
    Ok(())
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(cf, NGX_HTTP_PRECONTENT_PHASE, Rc::new(|r| Box::pin(mirror_handler(r))));
    Ok(())
}

async fn mirror_handler(r: R) -> i64 {
    use ngx_core::rc::*;

    if !r.is_main() {
        return NGX_DECLINED;
    }

    let conf = r.loc_conf::<MirrorLocConf>(ctx_index());
    let conf = conf.borrow();

    if !conf.mirror.is_set() || conf.mirror.get().is_empty() {
        drop(conf);
        return NGX_DECLINED;
    }

    let mirrors = conf.mirror.get().clone();
    drop(conf);

    let args = r.args.borrow().clone();
    let args_ref = if args.is_empty() { None } else { Some(args.as_slice()) };
    let method = r.method.get();
    let method_name = r.method_name.borrow().clone();

    for uri in mirrors {
        // Create a subrequest for each mirror URI (background = no waiting)
        match subrequest(&r, &uri, args_ref, NGX_HTTP_SUBREQUEST_BACKGROUND, None).await {
            Ok((sr, _)) => {
                // Follow C implementation: set header_only and copy method info
                sr.header_only.set(true);
                sr.method.set(method);
                *sr.method_name.borrow_mut() = method_name.clone();
            }
            Err(_) => {
                // Log error but continue with other mirrors
            }
        }
    }

    NGX_DECLINED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mirror_conf() {
        let conf = MirrorLocConf {
            mirror: Val::unset(),
            request_body: Val::unset(),
        };
        assert!(conf.mirror.is_unset());
        assert!(conf.request_body.is_unset());
    }
}
