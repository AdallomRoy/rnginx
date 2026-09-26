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
    /// Effective charset_types list. `Some(types)` means we recognise types;
    /// `Some(vec![b"*".to_vec()])` means match ANY type. `None` uses default.
    pub types: Option<Vec<Vec<u8>>>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CharsetLocConf {
        charset: Val::unset(),
        source_charset: Val::unset(),
        override_charset: Val::unset(),
        types: None,
    })
}

pub const DEFAULT_TYPES: &[&[u8]] = &[
    b"text/html",
    b"text/xml",
    b"text/plain",
    b"text/vnd.wap.wml",
    b"application/javascript",
    b"application/rss+xml",
];

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<CharsetLocConf>(prev).borrow();
    let mut c = conf_cell::<CharsetLocConf>(conf).borrow_mut();

    // charset default is handled in header filter
    if !c.charset.is_set() && p.charset.is_set() {
        c.charset = Val::set(p.charset.get().clone());
    }

    c.source_charset.merge(&p.source_charset, Vec::new());
    c.override_charset.merge(&p.override_charset, false);
    if c.types.is_none() {
        c.types = p.types.clone();
    }
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
        ngx_core::cmd_fn!("charset_types", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, set_types),
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

fn set_types(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<CharsetLocConf>(conf.as_ref().unwrap());
    let mut types: Vec<Vec<u8>> = Vec::new();
    for arg in cf.args.iter().skip(1) {
        types.push(arg.to_ascii_lowercase());
    }
    cell.borrow_mut().types = Some(types);
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
        // If the response already has a charset, only override when
        // override_charset is on. Otherwise, only set when the content type
        // matches charset_types (default: text/html + text/xml + text/plain
        // + text/vnd.wap.wml + application/javascript + application/rss+xml).
        let already_has = !r.headers_out.borrow().charset.is_empty();
        let override_on = conf_ref.override_charset.get_or(false);
        if already_has {
            if !override_on {
                drop(conf_ref);
                return next(r).await;
            }
        } else {
            let ct = r.headers_out.borrow().content_type.clone();
            let ct_bare: Vec<u8> = ct.split(|&b| b == b';').next().unwrap_or(&ct).to_ascii_lowercase();
            let types_opt = conf_ref.types.clone();
            let matched = if let Some(types) = &types_opt {
                if types.iter().any(|t| t.as_slice() == b"*") {
                    true
                } else {
                    types.iter().any(|t| t.as_slice() == ct_bare.as_slice())
                }
            } else {
                DEFAULT_TYPES.iter().any(|t| *t == ct_bare.as_slice())
            };
            if !matched {
                drop(conf_ref);
                return next(r).await;
            }
        }

        drop(conf_ref);

        // Set the charset in headers_out
        {
            let mut headers_out = r.headers_out.borrow_mut();
            if headers_out.charset.is_empty() || override_on {
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

