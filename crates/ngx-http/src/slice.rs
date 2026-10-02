//! ngx_http_slice_filter_module: the response is fetched in slices of
//! "slice" bytes, the first one by the request itself, the next ones by
//! subrequests (NGX_HTTP_SUBREQUEST_CLONE), each asking for its range with
//! the $slice_range variable.

use std::any::Any;
use std::rc::{Rc, Weak};

use ngx_core::buf::Chain;
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::ngx_log_error;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_slice_filter_module");

const NGX_MAX_OFF_T_VALUE: i64 = i64::MAX;

/// ngx_http_slice_loc_conf_t
pub struct SliceLocConf {
    size: Val<usize>,
}

/// ngx_http_slice_ctx_t: the one of the main request, which its slice
/// subrequests share
struct SliceCtx {
    start: i64,
    end: i64,
    range: Vec<u8>,
    etag: Vec<u8>,
    last: bool,
    active: bool,
    /// the subrequest of the last slice; the ctx it shares does not keep it
    /// alive, and a subrequest that is gone is done
    sr: Option<Weak<Request>>,
}

/// ngx_http_slice_content_range_t
struct SliceContentRange {
    start: i64,
    end: i64,
    complete_length: i64,
}

pub fn slice_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(slice_add_variables),
        postconfiguration: Some(slice_init),
        create_loc_conf: Some(slice_create_loc_conf),
        merge_loc_conf: Some(slice_merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!("slice", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, SliceLocConf, size, set_size),
    ];
    http_module_def("ngx_http_slice_filter_module", def, commands)
}

/// slcf->size
fn slice_size(r: &R) -> i64 {
    let slcf = r.loc_conf::<SliceLocConf>(ctx_index());
    let size = *slcf.borrow().size;
    size as i64
}

/// ngx_http_slice_header_filter
/// slice_header_filter passes the response on as it is: not a slice
fn slice_header_idle(r: &R) -> bool {
    !r.has_ctx(ctx_index())
}

async fn slice_header_filter(r: R, next: HeaderFilter) -> i64 {
    let ctx = match r.get_ctx::<SliceCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r).await,
    };

    let status = r.headers_out.borrow().status;

    if status != NGX_HTTP_PARTIAL_CONTENT {
        if r.is_main() {
            r.clear_ctx(ctx_index());
            return next(r).await;
        }

        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "unexpected status code {} in slice response", status);
        return NGX_ERROR;
    }

    let h = r.headers_out.borrow().etag.as_ref().map(|h| h.value());

    {
        let mut ctx = ctx.borrow_mut();

        if !ctx.etag.is_empty() && h.as_deref() != Some(&ctx.etag[..]) {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "etag mismatch in slice response");
            return NGX_ERROR;
        }

        if let Some(h) = h {
            ctx.etag = h;
        }
    }

    let cr = match slice_parse_content_range(&r) {
        Some(cr) => cr,
        None => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid range in slice response");
            return NGX_ERROR;
        }
    };

    if cr.complete_length == -1 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no complete length in slice response");
        return NGX_ERROR;
    }

    http_debug!(r, "http slice response range: {}-{}/{}", cr.start, cr.end, cr.complete_length);

    let size = slice_size(&r);

    let end = std::cmp::min(cr.start.wrapping_add(size), cr.complete_length);

    {
        let mut ctx = ctx.borrow_mut();

        if cr.start != ctx.start || cr.end != end {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "unexpected range in slice response: {}-{}, expected: {}-{}", cr.start, cr.end, ctx.start, end);
            return NGX_ERROR;
        }

        ctx.start = end;
        ctx.active = true;
    }

    {
        let mut ho = r.headers_out.borrow_mut();

        ho.status = NGX_HTTP_OK;
        ho.status_line.clear();
        ho.content_length_n = cr.complete_length;
        ho.content_offset = cr.start;

        if let Some(h) = ho.content_range.take() {
            h.hash.set(0);
        }

        if let Some(h) = ho.accept_ranges.take() {
            h.hash.set(0);
        }
    }

    r.allow_ranges.set(true);
    r.subrequest_ranges.set(true);
    r.single_range.set(true);

    let rc = next(r.clone()).await;

    if !r.is_main() {
        return rc;
    }

    r.preserve_body.set(true);

    let (status, content_offset, content_length_n) = {
        let ho = r.headers_out.borrow();
        (ho.status, ho.content_offset, ho.content_length_n)
    };

    let mut ctx = ctx.borrow_mut();

    if status == NGX_HTTP_PARTIAL_CONTENT {
        if ctx.start + size <= content_offset {
            ctx.start = size * (content_offset / size);
        }

        ctx.end = content_offset + content_length_n;

    } else {
        ctx.end = cr.complete_length;
    }

    rc
}

/// ngx_http_slice_body_filter
/// slice_body_filter passes the chain on as it is
fn slice_body_idle(r: &R, _input: &Chain) -> bool {
    !r.is_main() || !r.has_ctx(ctx_index())
}

async fn slice_body_filter(r: R, mut input: Chain, next: BodyFilter) -> i64 {
    let ctx = match r.get_ctx::<SliceCtx>(ctx_index()) {
        Some(ctx) if r.is_main() => ctx,
        _ => return next(r, input).await,
    };

    for b in input.iter_mut() {
        if b.last_buf {
            b.last_buf = false;
            b.last_in_chain = true;
            b.sync = true;
            ctx.borrow_mut().last = true;
        }
    }

    let rc = next(r.clone(), input).await;

    if rc == NGX_ERROR || !ctx.borrow().last {
        return rc;
    }

    let sr = ctx.borrow().sr.as_ref().and_then(|sr| sr.upgrade());

    if sr.is_some_and(|sr| !sr.done.get()) {
        return rc;
    }

    if !ctx.borrow().active {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "missing slice response");
        return NGX_ERROR;
    }

    let (start, end) = {
        let ctx = ctx.borrow();
        (ctx.start, ctx.end)
    };

    if start >= end {
        r.clear_ctx(ctx_index());
        crate::special_response::send_special(&r, true).await;
        return rc;
    }

    // r->buffered: the low-level flags kept in it here are c->buffered's
    if r.buffered.get() & !NGX_HTTP_LOWLEVEL_BUFFERED != 0 {
        return rc;
    }

    let uri = r.uri.borrow().clone();
    let args = r.args.borrow().clone();

    let sr = match crate::request_rt::subrequest_posted(&r, &uri, Some(&args), NGX_HTTP_SUBREQUEST_CLONE, None) {
        Ok(sr) => sr,
        Err(()) => return NGX_ERROR,
    };

    // ngx_http_set_ctx(ctx->sr, ctx, ngx_http_slice_filter_module)
    sr.ctx.borrow_mut()[ctx_index()] = Some(ctx.clone() as Rc<dyn Any>);

    let size = slice_size(&r);

    let mut ctx = ctx.borrow_mut();

    ctx.sr = Some(Rc::downgrade(&sr));

    ctx.range = format!("bytes={}-{}", ctx.start, ctx.start + size - 1).into_bytes();

    ctx.active = false;

    http_debug!(r, "http slice subrequest: \"{}\"", B(&ctx.range));

    rc
}

/// ngx_http_slice_parse_content_range: the header value is NUL-terminated
/// in C
fn slice_parse_content_range(r: &R) -> Option<SliceContentRange> {
    let h = r.headers_out.borrow().content_range.as_ref().map(|h| h.value())?;

    if h.len() < 7 || &h[..6] != b"bytes " {
        return None;
    }

    let at = |p: usize| h.get(p).copied().unwrap_or(0);

    let mut p = 6;

    let cutoff = NGX_MAX_OFF_T_VALUE / 10;
    let cutlim = NGX_MAX_OFF_T_VALUE % 10;

    let mut start: i64 = 0;
    let mut end: i64 = 0;
    let mut complete_length: i64 = 0;

    while at(p) == b' ' {
        p += 1;
    }

    if !at(p).is_ascii_digit() {
        return None;
    }

    while at(p).is_ascii_digit() {
        let d = (at(p) - b'0') as i64;

        if start >= cutoff && (start > cutoff || d > cutlim) {
            return None;
        }

        start = start * 10 + d;
        p += 1;
    }

    while at(p) == b' ' {
        p += 1;
    }

    if at(p) != b'-' {
        return None;
    }

    p += 1;

    while at(p) == b' ' {
        p += 1;
    }

    if !at(p).is_ascii_digit() {
        return None;
    }

    while at(p).is_ascii_digit() {
        let d = (at(p) - b'0') as i64;

        if end >= cutoff && (end > cutoff || d > cutlim) {
            return None;
        }

        end = end * 10 + d;
        p += 1;
    }

    end += 1;

    while at(p) == b' ' {
        p += 1;
    }

    if at(p) != b'/' {
        return None;
    }

    p += 1;

    while at(p) == b' ' {
        p += 1;
    }

    if at(p) != b'*' {
        if !at(p).is_ascii_digit() {
            return None;
        }

        while at(p).is_ascii_digit() {
            let d = (at(p) - b'0') as i64;

            if complete_length >= cutoff && (complete_length > cutoff || d > cutlim) {
                return None;
            }

            complete_length = complete_length * 10 + d;
            p += 1;
        }

    } else {
        complete_length = -1;
        p += 1;
    }

    while at(p) == b' ' {
        p += 1;
    }

    if at(p) != 0 {
        return None;
    }

    Some(SliceContentRange { start, end, complete_length })
}

/// ngx_http_slice_range_variable
fn slice_range_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let ctx = match r.get_ctx::<SliceCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => {
            if !r.is_main() || r.headers_out.borrow().status != 0 {
                v.not_found = true;
                return NGX_OK;
            }

            let size = slice_size(r);

            if size == 0 {
                v.not_found = true;
                return NGX_OK;
            }

            let ctx = r.set_ctx(ctx_index(), SliceCtx { start: 0, end: 0, range: Vec::new(), etag: Vec::new(), last: false, active: false, sr: None });

            {
                let mut ctx = ctx.borrow_mut();

                ctx.start = size * (slice_get_start(r) / size);

                if ctx.start > NGX_MAX_OFF_T_VALUE - size {
                    ctx.start = 0;
                }

                ctx.range = format!("bytes={}-{}", ctx.start, ctx.start + size - 1).into_bytes();
            }

            ctx
        }
    };

    v.data = ctx.borrow().range.clone();
    v.valid = true;
    v.not_found = false;
    v.no_cacheable = true;

    NGX_OK
}

/// ngx_http_slice_get_start: the header value is NUL-terminated in C
fn slice_get_start(r: &R) -> i64 {
    let hin = r.headers_in.borrow();

    if hin.if_range.is_some() {
        return 0;
    }

    let h = match hin.range.first() {
        Some(h) => h.value(),
        None => return 0,
    };

    if h.len() < 7 || !h[..6].eq_ignore_ascii_case(b"bytes=") {
        return 0;
    }

    let p = &h[6..];

    if p.contains(&b',') {
        return 0;
    }

    let at = |i: usize| p.get(i).copied().unwrap_or(0);

    let mut i = 0;

    while at(i) == b' ' {
        i += 1;
    }

    if at(i) == b'-' {
        return 0;
    }

    let cutoff = NGX_MAX_OFF_T_VALUE / 10;
    let cutlim = NGX_MAX_OFF_T_VALUE % 10;

    let mut start: i64 = 0;

    while at(i).is_ascii_digit() {
        let d = (at(i) - b'0') as i64;

        if start >= cutoff && (start > cutoff || d > cutlim) {
            return 0;
        }

        start = start * 10 + d;
        i += 1;
    }

    start
}

/// ngx_http_slice_create_loc_conf
fn slice_create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SliceLocConf { size: Val::unset() })
}

/// ngx_http_slice_merge_loc_conf
fn slice_merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<SliceLocConf>(prev).borrow();
    let mut conf = conf_cell::<SliceLocConf>(conf).borrow_mut();

    conf.size.merge(&prev.size, 0);

    Ok(())
}

/// ngx_http_slice_add_variables
fn slice_add_variables(cf: &mut Conf) -> ConfResult {
    use crate::variables::{add_variables, VarDef};

    add_variables(cf, &[VarDef { name: "slice_range", set: None, get: Some(slice_range_variable), data: 0, flags: 0 }])
}

/// ngx_http_slice_init
fn slice_init(_cf: &mut Conf) -> ConfResult {
    crate::install_header_filter_idle(slice_header_idle, slice_header_filter);
    crate::install_body_filter_idle(slice_body_idle, slice_body_filter);
    Ok(())
}
