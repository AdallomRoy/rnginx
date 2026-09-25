//! ngx_http_charset_filter_module: charset conversion filter

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::*;

crate::http_module_index!("ngx_http_charset_filter_module");

pub struct CharsetLocConf {
    pub charset: Val<Vec<u8>>,
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
    c.charset.merge(&p.charset, b"utf-8".to_vec());
    c.source_charset.merge(&p.source_charset, Vec::new());
    c.override_charset.merge(&p.override_charset, true);
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
        ngx_core::cmd!("charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, CharsetLocConf, charset, set_str),
        ngx_core::cmd!("source_charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, CharsetLocConf, source_charset, set_str),
        ngx_core::cmd!("override_charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, ConfLevel::Loc, CharsetLocConf, override_charset, set_flag),
        ngx_core::cmd_fn!("charset_types", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, stub_types),
        ngx_core::cmd_fn!("charset_map", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, stub_charset_map),
    ];
    http_module_def("ngx_http_charset_filter_module", def, commands)
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

    // If charset is specified, add it to Content-Type
    if !conf_ref.charset.get().is_empty() {
        let charset = conf_ref.charset.get().clone();
        drop(conf_ref);

        // Note: Full charset parameter addition requires deeper integration
        // with Content-Type header management, which is complex
        r.clear_content_length();
    }

    next(r).await
}

async fn charset_body_filter(r: R, mut input: Chain, next: BodyFilter) -> i64 {
    if input.is_empty() {
        return next(r, input).await;
    }

    let conf = r.loc_conf::<CharsetLocConf>(ctx_index());
    let conf_ref = conf.borrow();

    // If source_charset is specified, try to convert
    if !conf_ref.source_charset.get().is_empty() && !conf_ref.charset.get().is_empty() {
        let source = conf_ref.source_charset.get().clone();
        let target = conf_ref.charset.get().clone();
        drop(conf_ref);

        // For now, just pass through (full charset conversion is complex)
        // In a real implementation, we'd use encoding libraries
        return next(r, input).await;
    }

    next(r, input).await
}

// Helper trait for checking if slice contains a pattern (case-insensitive)
trait CaseInsensitiveContains {
    fn windows_1251_contains(&self, pattern: &[u8]) -> bool;
}

impl CaseInsensitiveContains for [u8] {
    fn windows_1251_contains(&self, pattern: &[u8]) -> bool {
        if pattern.is_empty() || self.len() < pattern.len() {
            return false;
        }

        for i in 0..=self.len() - pattern.len() {
            let mut match_found = true;
            for j in 0..pattern.len() {
                if self[i + j].to_ascii_lowercase() != pattern[j].to_ascii_lowercase() {
                    match_found = false;
                    break;
                }
            }
            if match_found {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_insensitive_contains() {
        let haystack = b"Content-Type: text/html; charset=utf-8";
        assert!(haystack.windows_1251_contains(b"charset"));
        assert!(haystack.windows_1251_contains(b"CHARSET"));
        assert!(!haystack.windows_1251_contains(b"foobar"));
    }
}
