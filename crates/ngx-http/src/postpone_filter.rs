//! ngx_http_postpone_filter_module: the output of a request waits in
//! r->postponed while subrequests made before it are not done; the output
//! of an in-memory subrequest is collected in r->out.
//!
//! Subrequests run one at a time here. One made by request_rt::subrequest()
//! runs to its end at once; the ones made by request_rt::subrequest_posted()
//! are appended to r->postponed and run from run_posted_requests(), which
//! stands for ngx_http_run_posted_requests() and the wake up loop below.
//! So the running request is the active one (C: c->data), except a parent
//! whose r->postponed holds subrequests still to run: its output has to
//! wait after theirs.

use std::cell::RefCell;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::ngx_log_error;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_postpone_filter_module");

thread_local! {
    /// ngx_http_next_body_filter
    static NEXT_BODY_FILTER: RefCell<Option<BodyFilter>> = const { RefCell::new(None) };
}

pub fn postpone_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(postpone_filter_init), ..Default::default() };
    http_module_def("ngx_http_postpone_filter_module", def, Vec::new())
}

/// ngx_http_postpone_filter_init
fn postpone_filter_init(_cf: &mut Conf) -> ConfResult {
    let next = top_body_filter();
    NEXT_BODY_FILTER.with(|n| *n.borrow_mut() = Some(next));
    install_body_filter(|r, chain, next| async move { postpone_filter(r, chain, next).await });
    Ok(())
}

fn next_body_filter() -> BodyFilter {
    NEXT_BODY_FILTER.with(|n| n.borrow().clone().expect("postpone filter not initialized"))
}

/// r == c->data: see the module comment. A background subrequest is never
/// c->data.
fn is_active(r: &R) -> bool {
    !r.background.get() && r.postponed.borrow().is_empty()
}

/// ngx_http_postpone_filter
async fn postpone_filter(r: R, mut input: Chain, next: BodyFilter) -> i64 {
    http_debug!(r, "http postpone filter \"{}?{}\" {:p}", B(&r.uri.borrow()), B(&r.args.borrow()), chain_ptr(&input));

    if r.subrequest_in_memory.get() {
        return postpone_filter_in_memory(&r, input);
    }

    if !r.is_main() {
        subrequest_last_buf(&mut input);
    }

    if !is_active(&r) {
        if r.background.get() {
            // C keeps it in r->postponed for good: every C caller makes
            // its background subrequests header_only, the subrequest API
            // here cannot, so their body is dropped
            return NGX_OK;
        }

        if !input.is_empty() {
            postpone_filter_add(&r, input);
            return NGX_OK;
        }

        return NGX_OK;
    }

    // r->postponed == NULL; c->buffered is not kept here: the write filter
    // sends what it is given before it returns
    if !input.is_empty() {
        return next(r.main(), input).await;
    }

    NGX_OK
}

/// The end of a subrequest's output is a sync buffer with last_in_chain,
/// never last_buf (ngx_http_send_special()); a few modules here set
/// last_buf regardless (fastcgi, the cached response), which would end the
/// main request's output in the middle.
fn subrequest_last_buf(chain: &mut Chain) {
    for b in chain.iter_mut() {
        if b.last_buf {
            b.last_buf = false;
            b.last_in_chain = true;

            if !b.in_memory() && !b.in_file {
                b.sync = true;
            }
        }
    }
}

/// ngx_http_postpone_filter_add
fn postpone_filter_add(r: &R, input: Chain) {
    let mut postponed = r.postponed.borrow_mut();

    if let Some(pr) = postponed.back_mut() {
        if pr.request.is_none() {
            pr.out.extend(input);
            return;
        }
    }

    postponed.push_back(PostponedRequest { request: None, out: input });
}

/// ngx_http_postpone_filter_in_memory: the response of the subrequest goes
/// into the one buffer of r->out, of the "Content-Length" size if known,
/// otherwise of subrequest_output_buffer_size.
fn postpone_filter_in_memory(r: &R, input: Chain) -> i64 {
    let c = &r.connection;

    http_debug!(r, "http postpone filter in memory");

    if r.out.borrow().is_empty() {
        let clcf = r.clcf();
        let buffer_size = *clcf.borrow().subrequest_output_buffer_size;
        let content_length_n = r.headers_out.borrow().content_length_n;

        let len = if content_length_n != -1 {
            let len = content_length_n as usize;

            if len > buffer_size {
                ngx_log_error!(NGX_LOG_ERR, c.log, None, "too big subrequest response: {}", len);
                return NGX_ERROR;
            }

            len
        } else {
            buffer_size
        };

        // ngx_create_temp_buf(): data.len() is the buffer's size, the
        // response is data[pos..last]
        let mut b = Buf::temp(len);
        b.last = 0;
        b.last_buf = true;

        r.out.borrow_mut().push_back(b);
    }

    let mut out = r.out.borrow_mut();
    let b = out.front_mut().expect("r->out");

    for buf in input.iter() {
        if buf.special_buf() {
            continue;
        }

        let data: &[u8] = match &buf.data {
            BufData::Memory(v) if buf.last > buf.pos => &v[buf.pos..buf.last],
            _ => &[],
        };

        let len = data.len();

        let (dst, last) = match &mut b.data {
            BufData::Memory(v) => (v, b.last),
            _ => unreachable!("r->out of an in-memory subrequest"),
        };

        if len > dst.len() - last {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "too big subrequest response");
            return NGX_ERROR;
        }

        http_debug!(r, "http postpone filter in memory {} bytes", len);

        dst[last..last + len].copy_from_slice(data);
        b.last += len;
    }

    NGX_OK
}

/// What makes the postponed subrequests of r run in C, done at once:
/// ngx_http_run_posted_requests() runs the subrequests posted by
/// ngx_http_subrequest() once the handler of r returns, and each one done
/// wakes its parent, whose postpone filter (in the wake up loop of
/// ngx_http_postpone_filter) sends the output postponed after it and wakes
/// the next postponed subrequest. Here each subrequest runs to its end, in
/// the order of r->postponed, and r is the active request again when the
/// list is empty.
pub async fn run_posted_requests(r: &R) -> i64 {
    let c = r.connection.clone();

    loop {
        if c.destroyed.get() || c.error.get() {
            return NGX_ERROR;
        }

        let pr = r.postponed.borrow_mut().pop_front();

        let pr = match pr {
            Some(pr) => pr,
            None => return NGX_OK,
        };

        if let Some(sr) = pr.request {
            http_debug!(r, "http postpone filter wake \"{}?{}\"", B(&sr.uri.borrow()), B(&sr.args.borrow()));

            crate::request_rt::subrequest_run(r, &sr).await;

            continue;
        }

        if pr.out.is_empty() {
            ngx_log_error!(NGX_LOG_ALERT, c.log, None, "http postpone filter NULL output");
        } else {
            http_debug!(r, "http postpone filter output \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));

            let next = next_body_filter();

            if next(r.main(), pr.out).await == NGX_ERROR {
                return NGX_ERROR;
            }
        }
    }
}

/// The chain pointer the C debug message prints: NULL for no chain.
fn chain_ptr(chain: &Chain) -> *const Buf {
    chain.front().map_or(std::ptr::null(), |b| b as *const Buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_ptr() {
        let mut chain = Chain::new();
        assert!(chain_ptr(&chain).is_null());
        chain.push_back(Buf::special());
        assert!(!chain_ptr(&chain).is_null());
    }
}
