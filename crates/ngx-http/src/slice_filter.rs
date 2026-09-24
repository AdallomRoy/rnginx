//! ngx_http_slice_filter_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::Chain;
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_slice_filter_module");

/// Location configuration for slice filter
pub struct SliceLocConf {
    pub size: Val<usize>,
}

/// Request context for slice filter
#[derive(Clone)]
pub struct SliceFilterCtx {
    pub start: i64,
    pub end: i64,
    pub range: Vec<u8>,
    pub etag: Vec<u8>,
    pub last: bool,
    pub active: bool,
}

pub fn slice_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        postconfiguration: Some(postconfiguration),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![ngx_core::cmd!("slice", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, SliceLocConf, size, set_off_t_slot)];
    http_module_def("ngx_http_slice_filter_module", def, commands)
}

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    let defs = vec![VarDef {
        name: "slice_range",
        get: Some(slice_range_variable),
        set: None,
        data: 0,
        flags: 0,
    }];
    add_variables(cf, &defs)
}

fn postconfiguration(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { slice_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { slice_body_filter(r, chain, next).await });
    Ok(())
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SliceLocConf { size: Val::unset() })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<SliceLocConf>(prev).borrow();
    let mut c = conf_cell::<SliceLocConf>(conf).borrow_mut();
    c.size.merge(&p.size, 0);
    Ok(())
}

async fn slice_header_filter(r: R, next: HeaderFilter) -> i64 {
    let ctx = match r.get_ctx::<SliceFilterCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r).await,
    };

    let status = r.headers_out.borrow().status;

    if status != NGX_HTTP_PARTIAL_CONTENT {
        if r == r.main {
            r.set_ctx(ctx_index(), SliceFilterCtx {
                start: 0,
                end: 0,
                range: Vec::new(),
                etag: Vec::new(),
                last: false,
                active: false,
            });
            return next(r).await;
        }

        return NGX_ERROR;
    }

    // Verify ETag consistency
    {
        let ho = r.headers_out.borrow();
        if !ctx.etag.is_empty() {
            if let Some(etag) = &ho.etag {
                let etag_val = etag.value.borrow();
                if ctx.etag.len() != etag_val.len() || ctx.etag != *etag_val {
                    return NGX_ERROR;
                }
            } else {
                return NGX_ERROR;
            }
        }
    }

    // Parse Content-Range
    let (cr_start, cr_end, cr_complete) = match parse_content_range(&r) {
        Ok(info) => info,
        Err(_) => return NGX_ERROR,
    };

    if cr_complete == -1 {
        return NGX_ERROR;
    }

    let slcf = r.loc_conf::<SliceLocConf>(ctx_index());
    let slice_size = slcf.borrow().size.get();

    let end = std::cmp::min(cr_start + slice_size as i64, cr_complete);

    if cr_start != ctx.start || cr_end != end {
        return NGX_ERROR;
    }

    let mut new_ctx = ctx;
    new_ctx.start = end;
    new_ctx.active = true;

    // Update etag
    if let Some(etag) = &r.headers_out.borrow().etag {
        let etag_val = etag.value.borrow();
        new_ctx.etag = etag_val.clone();
    }

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.status_line.clear();
        ho.content_length_n = cr_complete;
        ho.content_offset = cr_start;
        if let Some(cr) = &ho.content_range {
            cr.hash.set(0);
        }
        ho.content_range = None;
        if let Some(ar) = &ho.accept_ranges {
            ar.hash.set(0);
        }
        ho.accept_ranges = None;
    }

    r.allow_ranges.set(true);
    r.subrequest_ranges.set(true);
    r.single_range.set(true);

    let rc = next(r.clone()).await;

    if r == r.main {
        r.preserve_body.set(true);

        let main_status = r.headers_out.borrow().status;
        if main_status == NGX_HTTP_PARTIAL_CONTENT {
            let content_offset = r.headers_out.borrow().content_offset;
            if new_ctx.start + slice_size as i64 <= content_offset {
                new_ctx.start = slice_size as i64 * (content_offset / slice_size as i64);
            }
            new_ctx.end = content_offset + r.headers_out.borrow().content_length_n;
        } else {
            new_ctx.end = cr_complete;
        }
    }

    r.set_ctx(ctx_index(), new_ctx);
    rc
}

async fn slice_body_filter(r: R, mut chain: Chain, next: BodyFilter) -> i64 {
    let ctx = match r.get_ctx::<SliceFilterCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r, chain).await,
    };

    if r != r.main {
        return next(r, chain).await;
    }

    // Modify last_buf on all buffers
    let mut last_buf_found = false;
    for buf in chain.iter_mut() {
        if buf.last_buf {
            buf.last_buf = false;
            buf.last_in_chain = true;
            buf.sync = true;
            last_buf_found = true;
        }
    }

    let mut new_ctx = ctx;
    if last_buf_found {
        new_ctx.last = true;
    }

    let rc = next(r.clone(), chain).await;

    if rc == NGX_ERROR || !new_ctx.last {
        r.set_ctx(ctx_index(), new_ctx);
        return rc;
    }

    if !new_ctx.active {
        return NGX_ERROR;
    }

    if new_ctx.start >= new_ctx.end {
        r.set_ctx(ctx_index(), SliceFilterCtx {
            start: 0,
            end: 0,
            range: Vec::new(),
            etag: Vec::new(),
            last: false,
            active: false,
        });
        return rc;
    }

    if r.buffered.get() != 0 {
        r.set_ctx(ctx_index(), new_ctx);
        return rc;
    }

    // Stub: Don't actually make subrequest for now since we don't have full subrequest API
    // Just close the slice processing
    r.set_ctx(ctx_index(), SliceFilterCtx {
        start: 0,
        end: 0,
        range: Vec::new(),
        etag: Vec::new(),
        last: false,
        active: false,
    });

    rc
}

fn slice_range_variable(r: &R, _data: usize) -> VarResult {
    let ctx = match r.get_ctx::<SliceFilterCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => {
            if r != r.main || r.headers_out.borrow().status != 0 {
                return VarResult::NotFound;
            }

            let slcf = r.loc_conf::<SliceLocConf>(ctx_index());
            let slice_size = slcf.borrow().size.get();

            if slice_size == 0 {
                return VarResult::NotFound;
            }

            let mut new_ctx = SliceFilterCtx {
                start: 0,
                end: 0,
                range: Vec::new(),
                etag: Vec::new(),
                last: false,
                active: false,
            };

            let start = slice_get_start(&r);
            new_ctx.start = slice_size as i64 * (start / slice_size as i64);

            if new_ctx.start > i64::MAX - slice_size as i64 {
                new_ctx.start = 0;
            }

            let range_str = format!("bytes={}-{}", new_ctx.start, new_ctx.start + slice_size as i64 - 1);
            new_ctx.range = range_str.into_bytes();

            r.set_ctx(ctx_index(), new_ctx.clone());
            return VarResult::Data(new_ctx.range);
        }
    };

    VarResult::Data(ctx.range)
}

fn parse_content_range(r: &R) -> Result<(i64, i64, i64), ()> {
    let ho = r.headers_out.borrow();
    if let Some(cr) = &ho.content_range {
        let cr_val = cr.value.borrow();
        if cr_val.len() < 7 || !cr_val.starts_with(b"bytes ") {
            return Err(());
        }

        let mut p = &cr_val[6..];
        let mut start = 0i64;
        let mut end = 0i64;
        let mut complete = 0i64;

        const CUTOFF: i64 = i64::MAX / 10;
        const CUTLIM: i64 = i64::MAX % 10;

        // Skip spaces
        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if p.is_empty() || !(p[0] >= b'0' && p[0] <= b'9') {
            return Err(());
        }

        // Parse start
        while !p.is_empty() && p[0] >= b'0' && p[0] <= b'9' {
            if start >= CUTOFF && (start > CUTOFF || p[0] as i64 - b'0' as i64 > CUTLIM) {
                return Err(());
            }
            start = start * 10 + (p[0] as i64 - b'0' as i64);
            p = &p[1..];
        }

        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if p.is_empty() || p[0] != b'-' {
            return Err(());
        }
        p = &p[1..];

        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if p.is_empty() || !(p[0] >= b'0' && p[0] <= b'9') {
            return Err(());
        }

        // Parse end
        while !p.is_empty() && p[0] >= b'0' && p[0] <= b'9' {
            if end >= CUTOFF && (end > CUTOFF || p[0] as i64 - b'0' as i64 > CUTLIM) {
                return Err(());
            }
            end = end * 10 + (p[0] as i64 - b'0' as i64);
            p = &p[1..];
        }

        end += 1;

        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if p.is_empty() || p[0] != b'/' {
            return Err(());
        }
        p = &p[1..];

        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if p.is_empty() {
            return Err(());
        }

        if p[0] == b'*' {
            complete = -1;
        } else if p[0] >= b'0' && p[0] <= b'9' {
            // Parse complete_length
            while !p.is_empty() && p[0] >= b'0' && p[0] <= b'9' {
                if complete >= CUTOFF && (complete > CUTOFF || p[0] as i64 - b'0' as i64 > CUTLIM) {
                    return Err(());
                }
                complete = complete * 10 + (p[0] as i64 - b'0' as i64);
                p = &p[1..];
            }
        } else {
            return Err(());
        }

        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if !p.is_empty() {
            return Err(());
        }

        Ok((start, end, complete))
    } else {
        Err(())
    }
}

fn slice_get_start(r: &R) -> i64 {
    let hi = r.headers_in.borrow();

    if hi.if_range.is_some() {
        return 0;
    }

    if let Some(range) = &hi.range {
        if range.len() < 7 || !range.starts_with(b"bytes=") {
            return 0;
        }

        let range_val = &range[6..];

        // Check for comma (multipart)
        if range_val.iter().any(|&b| b == b',') {
            return 0;
        }

        let mut p = range_val;

        // Skip spaces
        while !p.is_empty() && p[0] == b' ' {
            p = &p[1..];
        }

        if p.is_empty() || p[0] == b'-' {
            return 0;
        }

        const CUTOFF: i64 = i64::MAX / 10;
        const CUTLIM: i64 = i64::MAX % 10;

        let mut start = 0i64;

        while !p.is_empty() && p[0] >= b'0' && p[0] <= b'9' {
            if start >= CUTOFF && (start > CUTOFF || p[0] as i64 - b'0' as i64 > CUTLIM) {
                return 0;
            }
            start = start * 10 + (p[0] as i64 - b'0' as i64);
            p = &p[1..];
        }

        return start;
    }

    0
}
