//! ngx_http_not_modified_filter_module

use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::*;
use crate::request::*;
use crate::*;

pub fn not_modified_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_not_modified_filter_module", def, Vec::new())
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { not_modified_header_filter(r, next).await });
    Ok(())
}

async fn not_modified_header_filter(r: R, next: HeaderFilter) -> i64 {
    let status = r.headers_out.borrow().status;
    if status != NGX_HTTP_OK || !r.is_main() || r.disable_not_modified.get() {
        return next(r).await;
    }
    let (ius, im, ims, inm) = {
        let hin = r.headers_in.borrow();
        (hin.if_unmodified_since.clone(), hin.if_match.clone(), hin.if_modified_since.clone(), hin.if_none_match.clone())
    };
    if let Some(h) = &ius {
        if !test_if_unmodified(&r, &h.value.borrow()) {
            return crate::special_response::filter_finalize_request(&r, NGX_HTTP_PRECONDITION_FAILED).await;
        }
    }
    if let Some(h) = &im {
        if !test_if_match(&r, &h.value.borrow(), false) {
            return crate::special_response::filter_finalize_request(&r, NGX_HTTP_PRECONDITION_FAILED).await;
        }
    }
    if ims.is_some() || inm.is_some() {
        if let Some(h) = &ims {
            if !test_if_modified(&r, &h.value.borrow()) {
                return not_modified(&r, next).await;
            }
        }
        if let Some(h) = &inm {
            if !test_if_match(&r, &h.value.borrow(), true) {
                return not_modified(&r, next).await;
            }
        }
        // both present: if-none-match matched? then continue only if both say modified
        if let (Some(_ims), Some(inm)) = (&ims, &inm) {
            let _ = inm;
        }
    }
    next(r).await
}

async fn not_modified(r: &R, next: HeaderFilter) -> i64 {
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_NOT_MODIFIED;
        ho.status_line.clear();
        ho.content_type.clear();
        ho.content_type_len = 0;
    }
    r.clear_content_length();
    r.clear_accept_ranges();
    let ho = r.headers_out.borrow();
    if let Some(cc) = ho.cache_control.first() {
        let _ = cc;
    }
    drop(ho);
    next(r.clone()).await
}

fn test_if_unmodified(r: &R, v: &[u8]) -> bool {
    let lm = r.headers_out.borrow().last_modified_time;
    if lm == -1 {
        return true;
    }
    match ngx_core::parse::parse_http_time(v) {
        Some(t) => lm <= t,
        None => true,
    }
}

fn test_if_modified(r: &R, v: &[u8]) -> bool {
    let lm = r.headers_out.borrow().last_modified_time;
    if lm == -1 {
        return true;
    }
    let clcf = r.clcf();
    let ims_mode = *clcf.borrow().if_modified_since;
    if ims_mode == NGX_HTTP_IMS_OFF {
        return true;
    }
    let ims = match ngx_core::parse::parse_http_time(v) {
        Some(t) => t,
        None => return true,
    };
    if ims == lm {
        return false;
    }
    if ims_mode == NGX_HTTP_IMS_EXACT || ims < lm {
        return true;
    }
    false
}

fn test_if_match(r: &R, list: &[u8], weak: bool) -> bool {
    if list.len() == 1 && list[0] == b'*' {
        return true;
    }
    let etag = match &r.headers_out.borrow().etag {
        Some(e) => e.value.borrow().clone(),
        None => return false,
    };
    let mut etag: &[u8] = &etag;
    if weak && etag.len() > 2 && etag[0] == b'W' && etag[1] == b'/' {
        etag = &etag[2..];
    }
    let mut start = 0;
    let end = list.len();
    let mut i = 0;
    loop {
        // skip spaces
        while start < end && list[start] == b' ' {
            start += 1;
        }
        let mut s = start;
        if weak && s + 2 <= end && list[s] == b'W' && list[s + 1] == b'/' {
            s += 2;
        }
        let mut t = s;
        while t < end && list[t] != b',' {
            t += 1;
        }
        let mut tok_end = t;
        while tok_end > s && list[tok_end - 1] == b' ' {
            tok_end -= 1;
        }
        if &list[s..tok_end] == etag {
            return true;
        }
        if t >= end {
            break;
        }
        start = t + 1;
        i += 1;
        if i > 1000 {
            break;
        }
    }
    false
}
