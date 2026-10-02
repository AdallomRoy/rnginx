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
    crate::install_header_filter_fn(not_modified_header_filter);
    Ok(())
}

/// ngx_http_not_modified_header_filter
fn not_modified_header_filter(r: R, next: &HeaderFilter) -> Step {
    if r.headers_out.borrow().status != NGX_HTTP_OK || !r.is_main() || r.disable_not_modified.get() {
        return next(r);
    }
    let (ius, im, ims, inm) = {
        let hin = r.headers_in.borrow();
        if hin.if_unmodified_since.is_none() && hin.if_match.is_none() && hin.if_modified_since.is_none() && hin.if_none_match.is_none() {
            drop(hin);
            return next(r);
        }
        (hin.if_unmodified_since.clone(), hin.if_match.clone(), hin.if_modified_since.clone(), hin.if_none_match.clone())
    };
    if let Some(h) = &ius {
        if !test_if_unmodified(&r, &h.value.borrow()) {
            return precondition_failed(r);
        }
    }
    if let Some(h) = &im {
        if !test_if_match(&r, &h.value.borrow(), false) {
            return precondition_failed(r);
        }
    }
    if ims.is_some() || inm.is_some() {
        // Match C ngx_http_not_modified_header_filter: if If-Modified-Since says
        // "modified" OR If-None-Match doesn't match, serve the response;
        // otherwise fall through to 304.
        if let Some(h) = &ims {
            if test_if_modified(&r, &h.value.borrow()) {
                return next(r);
            }
        }
        if let Some(h) = &inm {
            if !test_if_match(&r, &h.value.borrow(), true) {
                return next(r);
            }
        }
        return not_modified(r, next);
    }
    next(r)
}

/// ngx_http_filter_finalize_request(r, NULL, NGX_HTTP_PRECONDITION_FAILED)
fn precondition_failed(r: R) -> Step {
    Step::boxed(async move { crate::special_response::filter_finalize_request(&r, NGX_HTTP_PRECONDITION_FAILED).await })
}

fn not_modified(r: R, next: &HeaderFilter) -> Step {
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_NOT_MODIFIED;
        ho.status_line.clear();
        ho.content_type.clear();
        ho.content_type_len = 0;
    }
    r.clear_content_length();
    r.clear_accept_ranges();
    next(r)
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
    let etag_owned = match &r.headers_out.borrow().etag {
        Some(e) => e.value.borrow().clone(),
        None => return false,
    };
    let mut etag: &[u8] = &etag_owned;
    if weak && etag.len() > 2 && etag[0] == b'W' && etag[1] == b'/' {
        etag = &etag[2..];
    }
    // Port of ngx_http_test_if_match: walk the list token by token, skipping
    // leading spaces/tabs, an optional weak marker (when weak=true), then
    // require the etag literal followed by end/comma (with optional trailing
    // whitespace).
    let end = list.len();
    let mut start = 0;
    while start < end {
        while start < end && (list[start] == b' ' || list[start] == b'\t') {
            start += 1;
        }
        if weak && end - start > 2 && list[start] == b'W' && list[start + 1] == b'/' {
            start += 2;
        }
        if etag.len() > end - start {
            return false;
        }
        if &list[start..start + etag.len()] != etag {
            // Skip to next comma
            while start < end && list[start] != b',' {
                start += 1;
            }
            if start < end {
                start += 1;
            }
            continue;
        }
        let mut p = start + etag.len();
        while p < end && (list[p] == b' ' || list[p] == b'\t') {
            p += 1;
        }
        if p == end || list[p] == b',' {
            return true;
        }
        // Otherwise, skip to next comma and keep looking
        while p < end && list[p] != b',' {
            p += 1;
        }
        if p < end {
            p += 1;
        }
        start = p;
    }
    false
}
