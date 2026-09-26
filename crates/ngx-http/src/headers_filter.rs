//! ngx_http_headers_filter_module (placeholder: directives accepted, add_header applied simply)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_headers_filter_module");

pub struct HeadersConf {
    pub headers: Option<Vec<(Vec<u8>, ComplexValue, bool)>>,
    pub trailers: Option<Vec<(Vec<u8>, ComplexValue, bool)>>,
    pub expires_set: bool,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(HeadersConf { headers: None, trailers: None, expires_set: false })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<HeadersConf>(prev).borrow();
    let mut c = conf_cell::<HeadersConf>(conf).borrow_mut();
    if c.headers.is_none() {
        c.headers = p.headers.clone();
    }
    if c.trailers.is_none() {
        c.trailers = p.trailers.clone();
    }
    Ok(())
}

fn add_header(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let cv = compile_complex_value(cf, &args[2], 0)?;
    let mut always = false;
    if args.len() == 4 {
        if args[3] == b"always" {
            always = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", ngx_core::string::B(&args[3]))));
        }
    }
    let mut c = cell.borrow_mut();
    c.headers.get_or_insert_with(Vec::new).push((args[1].clone(), cv, always));
    Ok(())
}

fn add_trailer(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let cv = compile_complex_value(cf, &args[2], 0)?;
    let always = args.len() == 4 && args[3] == b"always";
    let mut c = cell.borrow_mut();
    c.trailers.get_or_insert_with(Vec::new).push((args[1].clone(), cv, always));
    Ok(())
}

pub fn headers_filter_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF;
    let def = HttpModuleDef { postconfiguration: Some(init), create_loc_conf: Some(create_conf), merge_loc_conf: Some(merge_conf), ..Default::default() };
    let commands = vec![
        ngx_core::cmd_fn!("add_header", F | NGX_CONF_TAKE23, ConfLevel::Loc, add_header),
        ngx_core::cmd_fn!("expires", F | NGX_CONF_TAKE12, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("add_trailer", F | NGX_CONF_TAKE23, ConfLevel::Loc, add_trailer),
    ];
    http_module_def("ngx_http_headers_filter_module", def, commands)
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { headers_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { trailers_body_filter(r, chain, next).await });
    Ok(())
}

async fn trailers_body_filter(r: R, input: ngx_core::buf::Chain, next: BodyFilter) -> i64 {
    // Match ngx_http_trailers_filter: on last_buf, evaluate each add_trailer
    // complex value and push into r.headers_out.trailers so the chunked filter
    // can emit them in the terminator.
    if input.is_empty() || r.header_only.get() || !r.expect_trailers.get() {
        return next(r, input).await;
    }
    let has_last = input.iter().any(|b| b.last_buf);
    if !has_last {
        return next(r, input).await;
    }
    let conf = r.loc_conf::<HeadersConf>(ctx_index());
    let trailers = conf.borrow().trailers.clone();
    let ts = match trailers { Some(t) if !t.is_empty() => t, _ => return next(r, input).await };

    let status = r.headers_out.borrow().status;
    let safe_status = matches!(
        status,
        NGX_HTTP_OK | NGX_HTTP_CREATED | NGX_HTTP_NO_CONTENT | NGX_HTTP_PARTIAL_CONTENT
        | NGX_HTTP_MOVED_PERMANENTLY | NGX_HTTP_MOVED_TEMPORARILY | NGX_HTTP_SEE_OTHER
        | NGX_HTTP_NOT_MODIFIED | NGX_HTTP_TEMPORARY_REDIRECT | NGX_HTTP_PERMANENT_REDIRECT
    );

    for (name, cv, always) in ts.iter() {
        if !safe_status && !always {
            continue;
        }
        let value = match crate::script::complex_value(&r, cv) {
            Ok(v) => v,
            Err(_) => return NGX_ERROR,
        };
        if value.is_empty() {
            continue;
        }
        let h = crate::request::TableElt::new(name, &value);
        r.headers_out.borrow_mut().trailers.push(h);
    }
    next(r, input).await
}

async fn headers_filter(r: R, next: HeaderFilter) -> i64 {
    if !r.is_main() {
        return next(r).await;
    }
    let conf = r.loc_conf::<HeadersConf>(ctx_index());
    let headers = conf.borrow().headers.clone();
    let status = r.headers_out.borrow().status;
    let safe = matches!(status, 200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308);
    if let Some(hs) = headers {
        for (name, cv, always) in hs.iter() {
            if !safe && !always {
                continue;
            }
            let v = match complex_value(&r, cv) {
                Ok(v) => v,
                Err(_) => return NGX_ERROR,
            };
            if v.is_empty() {
                continue;
            }
            r.headers_out.borrow_mut().add(name, &v);
        }
    }
    let trailers = conf.borrow().trailers.clone();
    if let Some(ts) = &trailers {
        if !ts.is_empty() && !r.header_only.get() {
            r.expect_trailers.set(true);
        }
    }
    next(r).await
}
