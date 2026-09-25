//! ngx_http_sub_filter_module: substitute text in response body

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_sub_filter_module");

#[derive(Clone)]
pub struct SubPair {
    pub match_val: ComplexValue,
    pub replacement_val: ComplexValue,
}

pub struct SubLocConf {
    pub pairs: Val<Vec<SubPair>>,
    pub once: Val<bool>,
    pub last_modified: Val<bool>,
}

#[derive(Clone)]
struct SubCtx {
    applied: u32,
    once: bool,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SubLocConf {
        pairs: Val::unset(),
        once: Val::unset(),
        last_modified: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<SubLocConf>(prev).borrow();
    let mut c = conf_cell::<SubLocConf>(conf).borrow_mut();
    c.pairs.merge(&p.pairs, Vec::new());
    c.once.merge(&p.once, false);
    c.last_modified.merge(&p.last_modified, true);
    Ok(())
}

pub fn sub_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("sub_filter", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, add_sub_filter),
        ngx_core::cmd_fn!("sub_filter_types", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, stub_types),
        ngx_core::cmd!("sub_filter_once", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, SubLocConf, once, set_flag),
        ngx_core::cmd!("sub_filter_last_modified", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, SubLocConf, last_modified, set_flag),
    ];
    http_module_def("ngx_http_sub_filter_module", def, commands)
}

fn stub_types(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement types filtering
    Ok(())
}

fn add_sub_filter(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let match_arg = cf.args[1].clone();
    let replacement_arg = cf.args[2].clone();
    let cell = conf_rc::<SubLocConf>(conf.as_ref().unwrap());
    let match_val = compile_complex_value(cf, &match_arg, 0)?;
    let replacement_val = compile_complex_value(cf, &replacement_arg, 0)?;

    let pair = SubPair {
        match_val,
        replacement_val,
    };

    let mut c = cell.borrow_mut();
    let mut pairs = c.pairs.as_option().cloned().unwrap_or_default();
    pairs.push(pair);
    c.pairs = Val::set(pairs);

    Ok(())
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { sub_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { sub_body_filter(r, chain, next).await });
    Ok(())
}

async fn sub_header_filter(r: R, next: HeaderFilter) -> i64 {
    let status = r.headers_out.borrow().status;
    let conf = r.loc_conf::<SubLocConf>(ctx_index());
    let conf = conf.borrow();

    if status != NGX_HTTP_OK || !r.is_main() || conf.pairs.is_empty() {
        drop(conf);
        return next(r).await;
    }

    drop(conf);

    // Set up context
    let ctx = SubCtx { applied: 0, once: *r.loc_conf::<SubLocConf>(ctx_index()).borrow().once.get() };
    r.set_ctx(ctx_index(), ctx);

    r.clear_content_length();

    if !*r.loc_conf::<SubLocConf>(ctx_index()).borrow().last_modified.get() {
        r.clear_last_modified();
        r.clear_etag();
    } else {
        crate::core_rt::weak_etag(&r);
    }

    next(r).await
}

async fn sub_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    if input.is_empty() {
        return next(r, input).await;
    }

    let ctx_opt = r.get_ctx::<SubCtx>(ctx_index());
    if ctx_opt.is_none() {
        return next(r, input).await;
    }

    let conf = r.loc_conf::<SubLocConf>(ctx_index());
    let conf = conf.borrow();
    if conf.pairs.is_empty() {
        drop(conf);
        return next(r, input).await;
    }

    let mut output = Chain::new();

    // Simple substring replacement
    for buf in input {
        let content_data = match &buf.data {
            ngx_core::buf::BufData::Memory(v) => v.clone(),
            _ => {
                output.push_back(buf);
                continue;
            }
        };

        let mut content = content_data[buf.pos..buf.last].to_vec();

        for pair in conf.pairs.iter() {
            // Evaluate match pattern
            let match_bytes = match crate::script::complex_value(&r, &pair.match_val) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Evaluate replacement
            let replacement = match crate::script::complex_value(&r, &pair.replacement_val) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Simple case-insensitive search-replace
            content = simple_replace(&content, &match_bytes, &replacement);

            if ctx_opt.as_ref().map_or(false, |c| c.borrow().once) && !content.is_empty() {
                break;
            }
        }

        let mut new_buf = Buf::from_vec(content);
        new_buf.last_buf = buf.last_buf;
        output.push_back(new_buf);
    }

    drop(conf);

    if output.is_empty() {
        return NGX_OK;
    }

    next(r, output).await
}

fn simple_replace(content: &[u8], search: &[u8], replace: &[u8]) -> Vec<u8> {
    if search.is_empty() || content.len() < search.len() {
        return content.to_vec();
    }

    let mut result = Vec::new();
    let mut pos = 0;

    while pos < content.len() {
        if pos + search.len() <= content.len() && content[pos..pos + search.len()].eq_ignore_ascii_case(search) {
            result.extend_from_slice(replace);
            pos += search.len();
        } else {
            result.push(content[pos]);
            pos += 1;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_replace() {
        let content = b"Hello World";
        let search = b"world";
        let replace = b"Rust";
        let result = simple_replace(content, search, replace);
        assert_eq!(result, b"Hello Rust");
    }
}
