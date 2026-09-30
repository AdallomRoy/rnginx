//! ngx_http_postpone_filter_module: the output of a request that is not the
//! active one (c->data) waits in its r->postponed, as does the output of
//! the active one after a subrequest still to run; the output of an
//! in-memory subrequest is collected in r->out.
//!
//! This module also keeps what C keeps for posted subrequests, the ones
//! request_rt::subrequest_posted() makes: c->data, and the posting of
//! requests, a posted subrequest being a task of its own that is woken up
//! when posted, in the order C runs ngx_http_run_posted_requests(). A task
//! runs the subrequest's handler, then what ngx_http_finalize_request()
//! does with a subrequest once the handler is done (posted_request()). A
//! request waiting for its subrequests is posted in turn; where C's
//! handler returns and the request goes on in ngx_http_writer() once
//! posted, the request here waits in wait_posted() and goes on.
//!
//! A subrequest made by request_rt::subrequest() runs at once, the parent
//! waiting for it, and is never c->data: it is active when its parent is.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll};

use tokio::sync::Notify;

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

// ---------------------------------------------------------------------------
// c->data and the posted requests

/// What C keeps in the connection and the main request for posted
/// subrequests: the main request's context of this module.
#[derive(Default)]
struct PostponeMain {
    /// c->data: None for the main request
    data: Option<Weak<Request>>,
    /// the subrequests made by subrequest_posted() that are not over
    posted: HashSet<usize>,
    /// a request waits for being posted on its Notify (ngx_http_post_request)
    notify: HashMap<usize, Rc<Notify>>,
    /// the tasks of the posted subrequests
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// notified when a task is over, or the main request is terminated
    tasks_done: Rc<Notify>,
}

fn key(r: &R) -> usize {
    Rc::as_ptr(r) as usize
}

fn main_state(r: &R) -> Rc<RefCell<PostponeMain>> {
    if let Some(st) = main_state_if_any(r) {
        return st;
    }

    let st = Rc::new(RefCell::new(PostponeMain::default()));
    *r.main().posted_subrequests.borrow_mut() = Some(st.clone());
    st
}

/// The state if there is one: without posted subrequests so far, c->data
/// is the main request. It is kept in r->main->posted_subrequests, not in
/// the module context an internal redirect of the main request clears.
fn main_state_if_any(r: &R) -> Option<Rc<RefCell<PostponeMain>>> {
    let st = r.main().posted_subrequests.borrow().clone();
    st.and_then(|st| st.downcast::<RefCell<PostponeMain>>().ok())
}

/// The request that stands for r as c->data: r itself when it is the main
/// request or a posted subrequest, otherwise (a subrequest run at once)
/// that of its parent.
fn anchor(st: &RefCell<PostponeMain>, r: &R) -> R {
    let mut r = r.clone();

    loop {
        if r.is_main() || st.borrow().posted.contains(&key(&r)) {
            return r;
        }

        match r.parent() {
            Some(pr) => r = pr,
            None => return r,
        }
    }
}

/// r is a subrequest made by subrequest_posted() that is not over.
pub fn is_posted(r: &R) -> bool {
    main_state_if_any(r).is_some_and(|st| st.borrow().posted.contains(&key(r)))
}

/// r == c->data. A background subrequest is never c->data.
pub fn is_active(r: &R) -> bool {
    if r.background.get() {
        return false;
    }

    let st = match main_state_if_any(r) {
        Some(st) => st,
        None => return true,
    };

    let data = st.borrow().data.as_ref().and_then(|w| w.upgrade()).unwrap_or_else(|| r.main());

    Rc::ptr_eq(&data, &anchor(&st, r))
}

/// c->data: the request the events of the connection go to, the main
/// request unless a posted subrequest is.
pub fn connection_data(r: &R) -> R {
    match main_state_if_any(r) {
        Some(st) => st.borrow().data.as_ref().and_then(|w| w.upgrade()).unwrap_or_else(|| r.main()),
        None => r.main(),
    }
}

/// c->data = r
fn set_data(r: &R) {
    let st = main_state(r);
    let a = anchor(&st, r);
    st.borrow_mut().data = if a.is_main() { None } else { Some(Rc::downgrade(&a)) };
}

fn notify_of(r: &R) -> Rc<Notify> {
    let st = main_state(r);
    let mut st = st.borrow_mut();
    st.notify.entry(key(r)).or_insert_with(|| Rc::new(Notify::new())).clone()
}

/// ngx_http_post_request(r, NULL): r runs once the requests posted before
/// it have: its wait_posted() returns (a request posted again before it
/// runs is posted once).
fn post_request(r: &R) {
    notify_of(r).notify_one();
}

/// What a request waiting for its subrequests does until it is posted
/// (C: its handler has returned and it goes on in its write event
/// handler). NGX_ERROR if the request is being terminated meanwhile.
pub async fn wait_posted(r: &R) -> i64 {
    if !is_terminated(r) {
        let notify = notify_of(r);
        notify.notified().await;
        r.set_log_request();
    }

    if is_terminated(r) {
        terminate_posted(r);
        return NGX_ERROR;
    }

    NGX_OK
}

fn is_terminated(r: &R) -> bool {
    let c = &r.connection;
    c.error.get() || c.destroyed.get() || r.main().terminated.get()
}

/// The main request is being terminated (ngx_http_terminate_request drops
/// the posted requests and closes it): every request waiting for being
/// posted gives up, and the tasks of the posted subrequests are cancelled.
fn terminate_posted(r: &R) {
    let st = main_state(r);

    let (notify, tasks, tasks_done) = {
        let mut st = st.borrow_mut();
        (st.notify.values().cloned().collect::<Vec<_>>(), std::mem::take(&mut st.tasks), st.tasks_done.clone())
    };

    for n in notify {
        n.notify_one();
    }

    tasks_done.notify_one();

    for t in tasks {
        t.abort();
    }
}

/// The part of ngx_http_subrequest() about posted subrequests: sr goes to
/// the end of r->postponed (unless it is a background one), is c->data if
/// r is and has nothing postponed, and is posted.
pub fn postpone_subrequest(r: &R, sr: &R) {
    let st = main_state(r);

    st.borrow_mut().posted.insert(key(sr));

    if !sr.background.get() {
        let active = is_active(r) && r.postponed.borrow().is_empty();

        if active {
            set_data(sr);
        }

        r.postponed.borrow_mut().push_back(PostponedRequest { request: Some(sr.clone()), out: Chain::new() });
    }

    let task = ngx_core::event::spawn(LogRequest { r: sr.clone(), f: Box::pin(posted_request(r.clone(), sr.clone())) });

    let mut st = st.borrow_mut();
    st.tasks.retain(|t| !t.is_finished());
    st.tasks.push(task);
}

/// A posted subrequest's task: its write_event_handler once posted
/// (ngx_http_handler, see request_rt::subrequest_run), then what
/// ngx_http_finalize_request() does with a subrequest once the handler is
/// done, with the ngx_http_writer and ngx_http_request_finalizer handlers
/// that make it end when it is c->data.
async fn posted_request(pr: R, sr: R) {
    http_debug!(sr, "http posted request: \"{}?{}\"", B(&sr.uri.borrow()), B(&sr.args.borrow()));

    crate::request_rt::subrequest_run(&pr, &sr).await;

    subrequest_finalize(&pr, &sr).await;

    let st = main_state(&sr);
    let mut st = st.borrow_mut();
    st.posted.remove(&key(&sr));
    st.notify.remove(&key(&sr));
    st.tasks_done.notify_one();
}

/// The subrequest part of ngx_http_finalize_request() after the handler and
/// the special response, which request_rt::finalize_request() leaves to
/// this for a posted subrequest.
async fn subrequest_finalize(pr: &R, r: &R) {
    loop {
        if is_terminated(r) {
            terminate_posted(r);
            return;
        }

        if r.buffered.get() != 0 || !r.postponed.borrow().is_empty() {
            // ngx_http_set_write_handler(): ngx_http_writer once posted

            if wait_posted(r).await == NGX_ERROR {
                return;
            }

            http_debug!(r, "http writer handler: \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));

            // ngx_http_output_filter(r, NULL)
            if crate::core_rt::output_filter(r, Chain::new()).await == NGX_ERROR {
                r.connection.error.set(true);
            }

            continue;
        }

        let active = r.background.get() || is_active(r);

        if active {
            if !r.logged.get() {
                let clcf = r.clcf();

                if *clcf.borrow().log_subrequest {
                    crate::request_rt::log_request(r);
                }

                r.logged.set(true);
            } else {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "subrequest: \"{}?{}\" logged again", B(&r.uri.borrow()), B(&r.args.borrow()));
            }

            r.done.set(true);

            if r.background.get() {
                return;
            }

            {
                let mut postponed = pr.postponed.borrow_mut();

                if postponed.front().and_then(|p| p.request.as_ref()).is_some_and(|s| Rc::ptr_eq(s, r)) {
                    postponed.pop_front();
                }
            }

            set_data(pr);

        } else {
            http_debug!(r, "http finalize non-active request: \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));

            if r.waited.get() {
                r.done.set(true);
            }
        }

        post_request(pr);

        http_debug!(r, "http wake parent request: \"{}?{}\"", B(&pr.uri.borrow()), B(&pr.args.borrow()));

        if active {
            return;
        }

        // ngx_http_request_finalizer once posted: finalized again, it ends
        // if it is c->data then
        if wait_posted(r).await == NGX_ERROR {
            return;
        }

        http_debug!(r, "http finalizer done: \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));
    }
}

/// What a request does with its postponed subrequests until they are over,
/// once C's handler has returned: it is posted as they are done and wakes
/// the next one up (ngx_http_writer, then the postpone filter). NGX_ERROR
/// if the request is being terminated meanwhile.
pub async fn run_posted_requests(r: &R) -> i64 {
    while !r.postponed.borrow().is_empty() {
        if wait_posted(r).await == NGX_ERROR {
            return NGX_ERROR;
        }

        http_debug!(r, "http writer handler: \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));

        // ngx_http_writer: ngx_http_output_filter(r, NULL), the whole chain
        // (a filter above this one may go on with the response, as the
        // slice filter makes its next subrequest)
        if crate::core_rt::output_filter(r, Chain::new()).await == NGX_ERROR {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// r->main->count of the posted subrequests, NGX_HTTP_SUBREQUEST_BACKGROUND
/// ones among them: the connection of the main request is not finalized
/// (closed or kept alive, ngx_http_finalize_connection) before they are over.
/// If the main request is terminated, they are not waited for: C closes it
/// at once (ngx_http_terminate_handler), and the cleanups of their upstreams
/// have run.
pub async fn wait_posted_subrequests(r: &R) {
    let st = match main_state_if_any(r) {
        Some(st) => st,
        None => return,
    };

    loop {
        if is_terminated(r) {
            terminate_posted(r);
            return;
        }

        let tasks_done = st.borrow().tasks_done.clone();
        let done = tasks_done.notified();

        {
            let mut st = st.borrow_mut();
            st.tasks.retain(|t| !t.is_finished());

            if st.tasks.is_empty() {
                return;
            }
        }

        done.await;
    }
}

/// Sets the log request of a subrequest's task whenever it runs, as C does
/// before running a posted request (ngx_http_set_log_request), and gives
/// it back when the task waits: C sets it for the request of each event,
/// and the request that goes on meanwhile (the main request while a
/// background subrequest runs) logs with its own.
struct LogRequest {
    r: R,
    f: Pin<Box<dyn Future<Output = ()>>>,
}

impl Future for LogRequest {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let prev = self.r.log_ctx.current_request.borrow().clone();

        self.r.set_log_request();
        let rv = self.f.as_mut().poll(cx);

        *self.r.log_ctx.current_request.borrow_mut() = prev;

        rv
    }
}

// ---------------------------------------------------------------------------
// the filter

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

    if r.postponed.borrow().is_empty() {
        // c->buffered is not kept here: the write filter sends what it is
        // given before it returns
        if !input.is_empty() {
            return next(r.main(), input).await;
        }

        return NGX_OK;
    }

    if !input.is_empty() {
        postpone_filter_add(&r, input);
    }

    postpone_filter_wake(&r).await
}

/// The loop of ngx_http_postpone_filter() for the active request with
/// something postponed: the output postponed is sent up to the first
/// subrequest, which is woken up (made c->data and posted).
async fn postpone_filter_wake(r: &R) -> i64 {
    let c = &r.connection;

    loop {
        let pr = r.postponed.borrow_mut().pop_front();

        let pr = match pr {
            Some(pr) => pr,
            None => return NGX_OK,
        };

        if let Some(sr) = pr.request {
            http_debug!(r, "http postpone filter wake \"{}?{}\"", B(&sr.uri.borrow()), B(&sr.args.borrow()));

            set_data(&sr);

            post_request(&sr);

            return NGX_OK;
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

        if r.postponed.borrow().is_empty() {
            return NGX_OK;
        }
    }
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

    #[test]
    fn test_subrequest_last_buf() {
        let mut chain = Chain::new();
        let mut b = Buf::special();
        b.last_buf = true;
        chain.push_back(b);
        let mut d = Buf::from_vec(b"x".to_vec());
        d.last_buf = true;
        chain.push_back(d);
        subrequest_last_buf(&mut chain);
        assert!(!chain[0].last_buf && chain[0].sync && chain[0].last_in_chain);
        assert!(!chain[1].last_buf && !chain[1].sync && chain[1].last_in_chain);
    }
}
