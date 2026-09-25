//! ngx_http_charset_filter_module: charset conversion filter

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::script::ComplexValue;
use crate::*;

crate::http_module_index!("ngx_http_charset_filter_module");

pub struct CharsetLocConf {
    pub charset: Val<ComplexValue>,
    pub source_charset: Val<Vec<u8>>,
    pub override_charset: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CharsetLocConf {
        charset: Val::unset(),
        source_charset: Val::unset(),
        override_charset: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<CharsetLocConf>(prev).borrow();
    let mut c = conf_cell::<CharsetLocConf>(conf).borrow_mut();

    // charset default is handled in header filter
    if !c.charset.is_set() && p.charset.is_set() {
        c.charset = Val::set(p.charset.get().clone());
    }

    c.source_charset.merge(&p.source_charset, Vec::new());
    c.override_charset.merge(&p.override_charset, false);
    Ok(())
}

pub fn charset_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_charset),
        ngx_core::cmd!("source_charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, CharsetLocConf, source_charset, set_str),
        ngx_core::cmd!("override_charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, ConfLevel::Loc, CharsetLocConf, override_charset, set_flag),
        ngx_core::cmd_fn!("charset_types", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, stub_types),
        ngx_core::cmd_fn!("charset_map", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, stub_charset_map),
    ];
    http_module_def("ngx_http_charset_filter_module", def, commands)
}

fn set_charset(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<CharsetLocConf>(conf.as_ref().unwrap());
    let arg = cf.args[1].clone();

    let charset_val = crate::script::compile_complex_value(cf, &arg, 0)?;
    cell.borrow_mut().charset = Val::set(charset_val);
    Ok(())
}

fn stub_types(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement types filtering
    Ok(())
}

fn stub_charset_map(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement charset_map block (parse-only for now)
    crate::stubs::skip_block(cf, cmd, conf)
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { charset_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { charset_body_filter(r, chain, next).await });
    Ok(())
}

async fn charset_header_filter(r: R, next: HeaderFilter) -> i64 {
    let status = r.headers_out.borrow().status;
    if status != NGX_HTTP_OK || !r.is_main() {
        return next(r).await;
    }

    let conf = r.loc_conf::<CharsetLocConf>(ctx_index());
    let conf_ref = conf.borrow();

    // Only set charset if explicitly configured
    if let Some(charset_val) = conf_ref.charset.as_option() {
        let charset_bytes = match crate::script::complex_value(&r, charset_val) {
            Ok(b) => {
                if b.is_empty() {
                    drop(conf_ref);
                    return next(r).await;
                }
                b
            }
            Err(_) => {
                drop(conf_ref);
                return next(r).await;
            }
        };

        drop(conf_ref);

        // Set the charset in headers_out
        // This will be used when headers are serialized
        {
            let mut headers_out = r.headers_out.borrow_mut();
            if headers_out.charset.is_empty() {
                // Set the charset
                headers_out.charset = charset_bytes;
            }
        }
    } else {
        drop(conf_ref);
        // No charset configured: don't touch content_length
        return next(r).await;
    }

    // Charset was applied: content will be recoded, so length becomes unknown
    r.clear_content_length();

    next(r).await
}

async fn charset_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    if input.is_empty() {
        return next(r, input).await;
    }

    let conf = r.loc_conf::<CharsetLocConf>(ctx_index());
    let conf_ref = conf.borrow();

    // If source_charset is specified, try to convert
    if !conf_ref.source_charset.get().is_empty() {
        // TODO: implement charset recoding
        // For now, just pass through
    }

    drop(conf_ref);
    next(r, input).await
}

