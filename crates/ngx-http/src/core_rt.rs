//! ngx_http_core_module: runtime (phases, location lookup, helpers).

use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::string::{filename_cmp, B};
use ngx_core::{ngx_log_error};

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::*;

/// ngx_http_handler: entry point running the phases for a (main or internal) request.
pub fn handler(r: R) -> Phases {
    r.connection.log.set_action(None);
    if !r.internal.get() {
        if r.method.get() != NGX_HTTP_CONNECT {
            let ct = r.headers_in.borrow().connection_type;
            match ct {
                0 => r.keepalive.set(r.http_version.get() > NGX_HTTP_VERSION_10),
                NGX_HTTP_CONNECTION_CLOSE => r.keepalive.set(false),
                NGX_HTTP_CONNECTION_KEEP_ALIVE => r.keepalive.set(true),
                _ => {}
            }
        }
        let hin = r.headers_in.borrow();
        r.lingering_close.set(hin.content_length_n > 0 || hin.chunked);
        drop(hin);
        r.phase_handler.set(0);
    } else {
        let cmcf = r.cmcf();
        let idx = cmcf.borrow().phase_engine.server_rewrite_index;
        r.phase_handler.set(idx);
    }
    r.valid_location.set(true);
    r.gzip_tested.set(false);
    r.gzip_ok.set(false);
    r.gzip_vary.set(false);
    run_phases(r)
}

/// ngx_http_core_run_phases: the future of the rc to pass to
/// finalize_request.
pub fn run_phases(r: R) -> Phases {
    Phases { r, engine: None, wait: None }
}

/// The phases of a request, run as C runs them: the checkers and the
/// handlers that do not wait are plain calls in a loop; a handler that
/// returns a pending step (or a checker that waits) is awaited, and the
/// loop goes on with its result. Not boxed: awaited by the request.
pub struct Phases {
    r: R,
    /// the phase handlers, taken from the main conf once per run
    engine: Option<Rc<[PhaseHandler]>>,
    /// what the phases wait for, and what its result is
    wait: Option<(BoxFut<i64>, After)>,
}

/// What the result of what the phases wait for is
#[derive(Clone, Copy)]
enum After {
    /// that of the phase handler at this index of the engine, for its
    /// checker
    Handler(usize),
    /// the result of the phases
    Finalize,
}

/// What a checker comes to
enum Next {
    /// the phase handler of r->phase_handler next
    Continue,
    /// the end of the phases, with the rc to finalize the request with
    Finalize(i64),
    /// waiting
    Wait(BoxFut<i64>, After),
}

impl std::future::Future for Phases {
    type Output = i64;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<i64> {
        let this = self.get_mut();
        let r = &this.r;
        let engine = this.engine.get_or_insert_with(|| r.cmcf().borrow().phase_engine.handlers.clone()).clone();

        loop {
            let next = match &mut this.wait {
                Some((fut, after)) => {
                    let rc = match fut.as_mut().poll(cx) {
                        std::task::Poll::Ready(rc) => rc,
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                    };
                    let after = *after;
                    this.wait = None;
                    match after {
                        After::Finalize => Next::Finalize(rc),
                        After::Handler(idx) => handler_rc(&this.r, &engine, idx, rc),
                    }
                }
                None => run(&this.r, &engine),
            };

            match next {
                Next::Continue => {}
                Next::Finalize(rc) => return std::task::Poll::Ready(rc),
                Next::Wait(fut, after) => this.wait = Some((fut, after)),
            }
        }
    }
}

/// The loop of ngx_http_core_run_phases until a checker finalizes the
/// request or waits
fn run(r: &R, engine: &[PhaseHandler]) -> Next {
    loop {
        let idx = r.phase_handler.get();
        let ph = match engine.get(idx) {
            Some(p) => p,
            None => return Next::Finalize(NGX_DONE),
        };
        let next = match ph.checker {
            Checker::Generic => {
                http_debug!(r, "generic phase: {}", idx);
                call(r, engine, ph, idx)
            }
            Checker::Rewrite => {
                http_debug!(r, "rewrite phase: {}", idx);
                call(r, engine, ph, idx)
            }
            Checker::FindConfig => find_config_phase(r),
            Checker::PostRewrite => post_rewrite_phase(r, ph),
            Checker::Access => {
                if !r.is_main() {
                    r.phase_handler.set(ph.next);
                    continue;
                }
                http_debug!(r, "access phase: {}", idx);
                call(r, engine, ph, idx)
            }
            Checker::PostAccess => post_access_phase(r),
            Checker::Content => {
                let ch = r.content_handler.borrow().clone();
                if let Some(h) = ch {
                    return Next::Wait(h(r.clone()), After::Finalize);
                }
                http_debug!(r, "content phase: {}", idx);
                call(r, engine, ph, idx)
            }
        };
        match next {
            Next::Continue => continue,
            next => return next,
        }
    }
}

/// The phase handler at `idx` called, its result to its checker
fn call(r: &R, engine: &[PhaseHandler], ph: &PhaseHandler, idx: usize) -> Next {
    match (ph.handler.as_ref().unwrap())(r.clone()) {
        Step::Ready(rc) => handler_rc(r, engine, idx, rc),
        Step::Pending(fut) => Next::Wait(fut, After::Handler(idx)),
    }
}

/// What the checker of the phase handler at `idx` does with its result
fn handler_rc(r: &R, engine: &[PhaseHandler], idx: usize, rc: i64) -> Next {
    let ph = &engine[idx];
    match ph.checker {
        Checker::Generic => generic_phase_rc(r, ph, rc),
        Checker::Rewrite => rewrite_phase_rc(r, rc),
        Checker::Access => access_phase_rc(r, ph, rc),
        Checker::Content => content_phase_rc(r, engine, rc),
        Checker::FindConfig | Checker::PostRewrite | Checker::PostAccess => unreachable!("a checker without handler"),
    }
}

/// ngx_http_core_generic_phase, after the handler
fn generic_phase_rc(r: &R, ph: &PhaseHandler, rc: i64) -> Next {
    if rc == NGX_OK {
        r.phase_handler.set(ph.next);
        return Next::Continue;
    }
    if rc == NGX_DECLINED {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return Next::Continue;
    }
    if rc == NGX_AGAIN || rc == NGX_DONE {
        return Next::Finalize(NGX_DONE);
    }
    Next::Finalize(rc)
}

/// ngx_http_core_rewrite_phase, after the handler
fn rewrite_phase_rc(r: &R, rc: i64) -> Next {
    if rc == NGX_DECLINED {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return Next::Continue;
    }
    if rc == NGX_DONE {
        return Next::Finalize(NGX_DONE);
    }
    Next::Finalize(rc)
}

/// ngx_http_core_find_config_phase
fn find_config_phase(r: &R) -> Next {
    *r.content_handler.borrow_mut() = None;
    r.uri_changed.set(false);
    let rc = find_location(r);
    if rc == NGX_ERROR {
        return Next::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    let clcf = r.clcf();
    if !r.internal.get() && *clcf.borrow().internal {
        return Next::Finalize(NGX_HTTP_NOT_FOUND);
    }
    {
        let c = clcf.borrow();
        http_debug!(r, "using configuration \"{}{}\"", if c.noname { "*" } else if c.exact_match { "=" } else { "" }, B(&c.name));
    }
    update_location_config(r);
    let clcf = r.clcf();
    let max_body = *clcf.borrow().client_max_body_size;
    let cl = r.headers_in.borrow().content_length_n;
    http_debug!(r, "http cl:{} max:{}", cl, max_body);
    if cl != -1 && !r.discard_body.get() && max_body != 0 && max_body < cl {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client intended to send too large body: {} bytes", cl);
        r.expect_tested.set(true);
        let r = r.clone();
        return Next::Wait(
            Box::pin(async move {
                let _ = crate::request_body::discard_request_body(&r).await;
                NGX_HTTP_REQUEST_ENTITY_TOO_LARGE
            }),
            After::Finalize,
        );
    }
    if rc == NGX_DONE {
        let value = {
            let c = clcf.borrow();
            let args = r.args.borrow();
            let mut v = Vec::with_capacity(c.escaped_name.len() + if args.is_empty() { 0 } else { 1 + args.len() });
            v.extend_from_slice(&c.escaped_name);
            if !args.is_empty() {
                v.push(b'?');
                v.extend_from_slice(&args);
            }
            v
        };
        r.clear_location();
        let h = r.headers_out.borrow_mut().add(b"Location", &value);
        r.headers_out.borrow_mut().location = Some(h);
        return Next::Finalize(NGX_HTTP_MOVED_PERMANENTLY);
    }
    r.phase_handler.set(r.phase_handler.get() + 1);
    Next::Continue
}

/// ngx_http_core_post_rewrite_phase
fn post_rewrite_phase(r: &R, ph: &PhaseHandler) -> Next {
    http_debug!(r, "post rewrite phase: {}", r.phase_handler.get());
    if !r.uri_changed.get() {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return Next::Continue;
    }
    http_debug!(r, "uri changes: {}", r.uri_changes.get());
    r.uri_changes.set(r.uri_changes.get() - 1);
    if r.uri_changes.get() == 0 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "rewrite or internal redirection cycle while processing \"{}\"", B(&r.uri.borrow()));
        return Next::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    r.phase_handler.set(ph.next);
    let cscf = r.cscf();
    let loc = cscf.borrow().ctx.loc.clone().unwrap();
    *r.loc_conf.borrow_mut() = loc;
    Next::Continue
}

/// ngx_http_core_access_phase, after the handler
fn access_phase_rc(r: &R, ph: &PhaseHandler, rc: i64) -> Next {
    if rc == NGX_DECLINED {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return Next::Continue;
    }
    if rc == NGX_AGAIN || rc == NGX_DONE {
        return Next::Finalize(NGX_DONE);
    }
    let clcf = r.clcf();
    let satisfy = *clcf.borrow().satisfy;
    if satisfy == NGX_HTTP_SATISFY_ALL {
        if rc == NGX_OK {
            r.phase_handler.set(r.phase_handler.get() + 1);
            return Next::Continue;
        }
    } else {
        if rc == NGX_OK {
            r.access_code.set(0);
            let ho = r.headers_out.borrow();
            let list = if r.is_proxy_auth() { &ho.proxy_authenticate } else { &ho.www_authenticate };
            for h in list.iter() {
                h.hash.set(0);
            }
            drop(ho);
            r.phase_handler.set(ph.next);
            return Next::Continue;
        }
        if rc == NGX_HTTP_FORBIDDEN || rc == NGX_HTTP_UNAUTHORIZED || rc == NGX_HTTP_PROXY_AUTH_REQUIRED {
            if r.access_code.get() != NGX_HTTP_UNAUTHORIZED && r.access_code.get() != NGX_HTTP_PROXY_AUTH_REQUIRED {
                r.access_code.set(rc);
            }
            r.phase_handler.set(r.phase_handler.get() + 1);
            return Next::Continue;
        }
    }
    if rc == NGX_HTTP_UNAUTHORIZED || rc == NGX_HTTP_PROXY_AUTH_REQUIRED {
        r.access_code.set(rc);
        return auth_delay(r);
    }
    Next::Finalize(rc)
}

/// ngx_http_core_post_access_phase
fn post_access_phase(r: &R) -> Next {
    http_debug!(r, "post access phase: {}", r.phase_handler.get());
    let access_code = r.access_code.get();
    if access_code != 0 {
        if access_code == NGX_HTTP_FORBIDDEN {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "access forbidden by rule");
        }
        if access_code == NGX_HTTP_UNAUTHORIZED || access_code == NGX_HTTP_PROXY_AUTH_REQUIRED {
            return auth_delay(r);
        }
        r.access_code.set(0);
        return Next::Finalize(access_code);
    }
    r.phase_handler.set(r.phase_handler.get() + 1);
    Next::Continue
}

/// ngx_http_core_auth_delay: the access code to finalize with, after the
/// delay if there is one.
fn auth_delay(r: &R) -> Next {
    let clcf = r.clcf();
    let delay = *clcf.borrow().auth_delay;
    let access_code = r.access_code.get();
    r.access_code.set(0);
    if delay == 0 {
        return Next::Finalize(access_code);
    }
    ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "delaying unauthorized request");
    let r = r.clone();
    Next::Wait(
        Box::pin(async move {
            let closed = crate::request_rt::wait_delay_or_close(&r, delay).await;
            if closed {
                return NGX_HTTP_CLIENT_CLOSED_REQUEST;
            }
            access_code
        }),
        After::Finalize,
    )
}

/// ngx_http_core_content_phase, after the handler
fn content_phase_rc(r: &R, engine: &[PhaseHandler], rc: i64) -> Next {
    if rc != NGX_DECLINED {
        return Next::Finalize(rc);
    }
    // rc == NGX_DECLINED
    if engine.get(r.phase_handler.get() + 1).is_some() {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return Next::Continue;
    }
    if r.uri.borrow().last() == Some(&b'/') {
        if let Some((path, _root)) = map_uri_to_path(r, 0) {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "directory index of \"{}\" is forbidden", B(&path));
        }
        return Next::Finalize(NGX_HTTP_FORBIDDEN);
    }
    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no handler found");
    Next::Finalize(NGX_HTTP_NOT_FOUND)
}

/// ngx_http_update_location_config
pub fn update_location_config(r: &R) {
    let mut clcf = r.clcf();
    if r.method.get() & clcf.borrow().limit_except != 0 {
        let lc = clcf.borrow().limit_except_loc_conf.clone().unwrap();
        *r.loc_conf.borrow_mut() = lc;
        clcf = r.clcf();
    }
    let c = clcf.borrow();
    if r.is_main() {
        r.connection.log.set_chain(c.error_log.clone().unwrap());
    }
    r.connection.sendfile.set(*c.sendfile);
    if *c.client_body_in_file_only != 0 {
        r.request_body_in_file_only.set(true);
        r.request_body_in_persistent_file.set(true);
        r.request_body_in_clean_file.set(*c.client_body_in_file_only == NGX_HTTP_REQUEST_BODY_FILE_CLEAN);
        r.request_body_file_log_level.set(NGX_LOG_NOTICE);
    } else {
        r.request_body_file_log_level.set(NGX_LOG_WARN);
    }
    r.request_body_in_single_buf.set(*c.client_body_in_single_buffer);
    if r.keepalive.get() {
        let hin = r.headers_in.borrow();
        if *c.keepalive_timeout == 0 {
            r.keepalive.set(false);
        } else if r.connection.requests.get() as i64 >= *c.keepalive_requests {
            r.keepalive.set(false);
        } else if {
            // Both timestamps are wall-clock milliseconds since epoch.
            // ngx_core::times::current_msec() returns MONOTONIC time
            // (secs since boot × 1000), which is a different clock and would
            // give a nonsense diff. Use cached wall time to compare.
            let now = ngx_core::times::cached();
            let now_ms = now.sec as u64 * 1000 + now.msec;
            now_ms.saturating_sub(r.connection.start_msec.get()) > *c.keepalive_time
        } {
            r.keepalive.set(false);
        } else if hin.msie6 && r.method.get() == NGX_HTTP_POST && (c.keepalive_disable & NGX_HTTP_KEEPALIVE_DISABLE_MSIE6) != 0 {
            r.keepalive.set(false);
        } else if hin.safari && (c.keepalive_disable & NGX_HTTP_KEEPALIVE_DISABLE_SAFARI) != 0 {
            r.keepalive.set(false);
        }
    }
    if !*c.tcp_nopush {
        r.connection.tcp_nopush.set(ngx_core::connection::TcpNopush::Disabled);
    }
    if let Some(h) = &c.handler {
        *r.content_handler.borrow_mut() = Some(h.clone());
    }
}

/// ngx_http_core_find_location
pub fn find_location(r: &R) -> i64 {
    let mut noregex = false;
    let pclcf = r.clcf();
    let mut rc = {
        let p = pclcf.borrow();
        find_static_location(r, p.static_locations.as_deref())
    };
    if rc == NGX_AGAIN {
        let clcf = r.clcf();
        noregex = clcf.borrow().noregex;
        rc = find_location(r);
    }
    if rc == NGX_OK || rc == NGX_DONE || rc == NGX_ERROR {
        return rc;
    }
    // the parent's location conf is not changed while it is searched: its
    // regex and predicate locations are borrowed
    let p = pclcf.borrow();
    if !noregex && !p.regex_locations.is_empty() {
        for clcf in p.regex_locations.iter() {
            let re = {
                let c = clcf.borrow();
                http_debug!(r, "test location: ~ \"{}\"", B(&c.name));
                c.regex.clone().unwrap()
            };
            // regex_exec writes the captures, not r->uri
            let n = crate::variables::regex_exec(r, &re, &r.uri.borrow());
            if n == NGX_OK {
                *r.loc_conf.borrow_mut() = clcf.borrow().loc_conf.clone().unwrap();
                let rc = find_location(r);
                return if rc == NGX_ERROR { rc } else { NGX_OK };
            }
            if n == NGX_DECLINED {
                continue;
            }
            return NGX_ERROR;
        }
    }
    if !noregex && !p.predicate_locations.is_empty() {
        for clcf in p.predicate_locations.iter() {
            let pidx = {
                let c = clcf.borrow();
                http_debug!(r, "test location: \"{}\"", B(&c.name));
                c.predicate
            };
            let vv = match crate::variables::get_flushed_variable(r, pidx - 1) {
                Some(v) => v,
                None => return NGX_ERROR,
            };
            if !vv.not_found && !vv.data.is_empty() && !(vv.data.len() == 1 && vv.data[0] == b'0') {
                *r.loc_conf.borrow_mut() = clcf.borrow().loc_conf.clone().unwrap();
                let rc = find_location(r);
                return if rc == NGX_ERROR || rc == NGX_DONE { rc } else { NGX_OK };
            }
        }
    }
    rc
}

fn find_static_location(r: &R, mut node: Option<&LocationTreeNode>) -> i64 {
    // only r->loc_conf changes here
    let uri_full = r.uri.borrow();
    let mut uri: &[u8] = &uri_full;
    let mut rv = NGX_DECLINED;
    loop {
        let n = match node {
            Some(n) => n,
            None => return rv,
        };
        http_debug!(r, "test location: \"{}\"", B(&n.name));
        let len = uri.len();
        let cmp_len = if len <= n.name.len() { len } else { n.name.len() };
        let rc = filename_cmp(uri, &n.name, cmp_len);
        if rc != 0 {
            node = if rc < 0 { n.left.as_deref() } else { n.right.as_deref() };
            continue;
        }
        if len > n.name.len() {
            if let Some(inc) = &n.inclusive {
                *r.loc_conf.borrow_mut() = inc.borrow().loc_conf.clone().unwrap();
                rv = NGX_AGAIN;
                node = n.tree.as_deref();
                uri = &uri[cmp_len..];
                continue;
            }
            node = n.right.as_deref();
            continue;
        }
        if len == n.name.len() {
            if let Some(ex) = &n.exact {
                *r.loc_conf.borrow_mut() = ex.borrow().loc_conf.clone().unwrap();
                return NGX_OK;
            }
            *r.loc_conf.borrow_mut() = n.inclusive.as_ref().unwrap().borrow().loc_conf.clone().unwrap();
            return NGX_AGAIN;
        }
        if len + 1 == n.name.len() && n.auto_redirect {
            let lc = n.exact.as_ref().or(n.inclusive.as_ref()).unwrap();
            *r.loc_conf.borrow_mut() = lc.borrow().loc_conf.clone().unwrap();
            rv = NGX_DONE;
        }
        node = n.left.as_deref();
    }
}

/// ngx_http_test_content_type: returns Some(value) if content type is in the hash
/// (or Some(empty) when the hash is empty meaning "any"), None otherwise.
pub fn test_content_type(r: &R, types_hash: &ngx_core::hash::Hash<Rc<Vec<u8>>>) -> Option<Rc<Vec<u8>>> {
    if types_hash.is_empty() {
        return Some(Rc::new(Vec::new()));
    }
    let mut ho = r.headers_out.borrow_mut();
    if ho.content_type.is_empty() {
        return None;
    }
    let len = ho.content_type_len;
    if ho.content_type_lowcase.is_none() {
        let lower: Vec<u8> = ho.content_type[..len].iter().map(|c| ngx_core::string::tolower(*c)).collect();
        ho.content_type_hash = ngx_core::hash::hash_key(&lower);
        ho.content_type_lowcase = Some(lower);
    }
    let lc = ho.content_type_lowcase.clone().unwrap();
    types_hash.find(ho.content_type_hash, &lc[..len]).cloned()
}

/// ngx_http_set_content_type
pub fn set_content_type(r: &R) -> i64 {
    // Match ngx_http_set_content_type: don't clobber an already-set
    // Content-Type (e.g. one carried through from an upstream response).
    if r.headers_out.borrow().content_type_len != 0 {
        return NGX_OK;
    }
    let clcf = r.clcf();
    {
        let exten = r.exten.borrow();
        let c = clcf.borrow();
        if let (false, Some(th)) = (exten.is_empty(), &c.types_hash) {
            // the extension lowercased (ngx_hash_strlow), on the stack
            // unless it is long
            let mut stack = [0u8; 32];
            let heap;
            let lower: &[u8] = if exten.len() <= stack.len() {
                for (d, s) in stack.iter_mut().zip(exten.iter()) {
                    *d = ngx_core::string::tolower(*s);
                }
                &stack[..exten.len()]
            } else {
                heap = ngx_core::string::to_lower_vec(&exten);
                &heap
            };
            let hash = ngx_core::hash::hash_key(lower);
            if let Some(t) = th.find(hash, lower) {
                let mut ho = r.headers_out.borrow_mut();
                ho.content_type_len = t.len();
                ho.content_type = (**t).clone();
                return NGX_OK;
            }
        }
    }
    let c = clcf.borrow();
    let mut ho = r.headers_out.borrow_mut();
    ho.content_type_len = c.default_type.len();
    ho.content_type = (*c.default_type).clone();
    NGX_OK
}

/// ngx_http_set_exten
pub fn set_exten(r: &R) {
    let uri = r.uri.borrow();
    let mut exten = Vec::new();
    let mut i = uri.len() as isize - 1;
    while i > 1 {
        let iu = i as usize;
        if uri[iu] == b'.' && uri[iu - 1] != b'/' {
            exten = uri[iu + 1..].to_vec();
            break;
        } else if uri[iu] == b'/' {
            break;
        }
        i -= 1;
    }
    drop(uri);
    *r.exten.borrow_mut() = exten;
}

/// ngx_http_set_etag
pub fn set_etag(r: &R) -> i64 {
    let clcf = r.clcf();
    if !*clcf.borrow().etag {
        return NGX_OK;
    }
    let mut ho = r.headers_out.borrow_mut();
    // "\"%xT-%xO\"", on the stack: the header copies it
    let mut value = crate::header_filter::StackBuf::<40>::new();
    value.push(b"\"");
    value.push(crate::header_filter::hex_digits(ho.last_modified_time, &mut [0u8; 16]));
    value.push(b"-");
    value.push(crate::header_filter::hex_digits(ho.content_length_n, &mut [0u8; 16]));
    value.push(b"\"");
    let h = ho.add(b"ETag", value.as_slice());
    ho.etag = Some(h);
    NGX_OK
}

/// ngx_http_weak_etag
pub fn weak_etag(r: &R) {
    let mut ho = r.headers_out.borrow_mut();
    let etag = match &ho.etag {
        Some(e) => e.clone(),
        None => return,
    };
    let v = etag.value.borrow().clone();
    if v.len() > 2 && v[0] == b'W' && v[1] == b'/' {
        return;
    }
    if v.is_empty() || v[0] != b'"' {
        etag.hash.set(0);
        ho.etag = None;
        return;
    }
    let mut nv = b"W/".to_vec();
    nv.extend_from_slice(&v);
    etag.set_value(&nv);
}

/// ngx_http_send_early_hints: the early hints of r->headers_out, if the
/// "early_hints" predicates let them go
pub fn send_early_hints(r: &R) -> Step {
    if r.post_action.get() {
        return Step::Ready(NGX_OK);
    }

    if r.header_sent.get() {
        ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ALERT, r.connection.log, None, "header already sent");
        return Step::Ready(NGX_ERROR);
    }

    let early_hints = r.clcf().borrow().early_hints.get_or(None);

    let rc = crate::script::test_predicates(r, &early_hints);

    if rc != NGX_DECLINED {
        return Step::Ready(rc);
    }

    ngx_core::ngx_log_debug!(ngx_core::log::NGX_LOG_DEBUG_HTTP, r.connection.log, "http send early hints \"{}?{}\"", ngx_core::string::B(&r.uri.borrow()), ngx_core::string::B(&r.args.borrow()));

    crate::top_early_hints_filter()(r.clone())
}

/// ngx_http_send_header: the header filters run at once; the step is
/// pending only if one of them has to wait
pub fn send_header(r: &R) -> Step {
    if r.post_action.get() {
        return Step::Ready(NGX_OK);
    }
    if r.header_sent.get() {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "header already sent");
        return Step::Ready(NGX_ERROR);
    }
    if r.err_status.get() != 0 {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = r.err_status.get();
        ho.status_line.clear();
    }
    let f = top_header_filter();
    f(r.clone())
}

/// ngx_http_output_filter: the body filters run at once; the future is
/// pending only if one of them has to wait
pub fn output_filter(r: &R, chain: Chain) -> OutputFilter {
    http_debug!(r, "http output filter \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));
    let f = top_body_filter();
    match f(r.clone(), chain) {
        Step::Ready(rc) => {
            if rc == NGX_ERROR {
                // NGX_ERROR may be returned by any filter
                r.connection.error.set(true);
            }
            OutputFilter { step: Step::Ready(rc), r: None }
        }
        step => OutputFilter { step, r: Some(r.clone()) },
    }
}

/// The future of ngx_http_output_filter(): the result of the body filters,
/// with c->error set if it is NGX_ERROR once they are done
pub struct OutputFilter {
    step: Step,
    /// the request, while the filters are not done
    r: Option<R>,
}

impl OutputFilter {
    /// The result, if the filters are done
    pub fn done(&self) -> Option<i64> {
        match (&self.step, &self.r) {
            (Step::Ready(rc), None) => Some(*rc),
            _ => None,
        }
    }

    /// The step of the call; one that is not done goes on in a new boxed
    /// future
    pub fn into_step(self) -> Step {
        match self.r {
            None => self.step,
            Some(r) => self.step.map(move |rc| {
                if rc == NGX_ERROR {
                    r.connection.error.set(true);
                }
                rc
            }),
        }
    }
}

impl std::future::Future for OutputFilter {
    type Output = i64;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<i64> {
        let this = self.get_mut();

        let rc = match std::pin::Pin::new(&mut this.step).poll(cx) {
            std::task::Poll::Ready(rc) => rc,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        };

        if let Some(r) = this.r.take() {
            if rc == NGX_ERROR {
                // NGX_ERROR may be returned by any filter
                r.connection.error.set(true);
            }
        }

        std::task::Poll::Ready(rc)
    }
}

/// ngx_http_map_uri_to_path: returns (path, root_length).
/// ngx_http_set_disable_symlinks: of->disable_symlinks of the location,
/// and of->disable_symlinks_from when the path starts with the "from"
/// value (off when it is the whole path)
pub fn set_disable_symlinks(r: &R, clcf: &Rc<RefCell<CoreLocConf>>, path: &[u8], of: &mut ngx_core::open_file_cache::OpenFileInfo) -> i64 {
    let from = {
        let c = clcf.borrow();

        of.disable_symlinks = *c.disable_symlinks as u8;

        c.disable_symlinks_from.as_option().cloned().flatten()
    };

    let from = match from {
        Some(cv) => cv,
        None => return NGX_OK,
    };

    let from = match crate::script::complex_value(r, &from) {
        Ok(v) => v,
        Err(_) => return NGX_ERROR,
    };

    if from.is_empty() || from.len() > path.len() || path[..from.len()] != from[..] {
        return NGX_OK;
    }

    if from.len() == path.len() {
        of.disable_symlinks = crate::core::NGX_DISABLE_SYMLINKS_OFF as u8;
        return NGX_OK;
    }

    let p = from.len();

    if path[p] == b'/' {
        of.disable_symlinks_from = from.len();
        return NGX_OK;
    }

    if path[p - 1] == b'/' {
        of.disable_symlinks_from = from.len() - 1;
    }

    NGX_OK
}

pub fn map_uri_to_path(r: &R, reserved: usize) -> Option<(Vec<u8>, usize)> {
    let clcf = r.clcf();
    let c = clcf.borrow();
    let mut alias = c.alias;
    let uri_len = r.uri.borrow().len();
    if alias != 0 && !r.valid_location.get() {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "\"alias\" cannot be used in location \"{}\" where URI was rewritten", B(&c.name));
        return None;
    }
    if alias > uri_len && alias != usize::MAX {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "URI shorter than aliased URI part");
        return None;
    }
    let mut path: Vec<u8>;
    let root_length;
    match &c.root_script {
        None => {
            // the root, the URI and what the caller adds, as C reserves
            path = Vec::with_capacity(c.root.len() + uri_len.saturating_sub(alias) + reserved);
            path.extend_from_slice(&c.root);
            root_length = path.len();
        }
        Some(script) => {
            let v = match complex_value(r, script) {
                Ok(v) => v,
                Err(_) => return None,
            };
            path = v;
            if path.first() != Some(&b'/') {
                let mut full = ngx_core::cycle::cycle().prefix.clone();
                full.extend_from_slice(&path);
                path = full;
            }
            root_length = path.len();
            if alias == usize::MAX {
                if !r.add_uri_to_alias.get() {
                    return Some((path, root_length));
                }
                alias = 0;
            }
        }
    }
    path.extend_from_slice(&r.uri.borrow()[alias..]);
    Some((path, root_length))
}

/// ngx_http_send_response: a plain call while nothing waits (the request
/// body to discard, the client to take the output)
pub fn send_response(r: &R, status: i64, ct: Option<&[u8]>, cv: &ComplexValue) -> Step {
    match crate::request_body::discard_request_body_step(r) {
        Step::Ready(rc) => send_response_discarded(r, rc, status, ct, cv),
        Step::Pending(fut) => {
            let (r, ct, cv) = (r.clone(), ct.map(|ct| ct.to_vec()), cv.clone());
            Step::boxed(async move {
                let rc = fut.await;
                send_response_discarded(&r, rc, status, ct.as_deref(), &cv).await
            })
        }
    }
}

/// ngx_http_send_response after the request body is discarded
fn send_response_discarded(r: &R, rc: i64, status: i64, ct: Option<&[u8]>, cv: &ComplexValue) -> Step {
    if rc != NGX_OK {
        return Step::Ready(rc);
    }
    r.headers_out.borrow_mut().status = status;
    let val = match complex_value(r, cv) {
        Ok(v) => v,
        Err(_) => return Step::Ready(NGX_HTTP_INTERNAL_SERVER_ERROR),
    };
    if status == NGX_HTTP_MOVED_PERMANENTLY || status == NGX_HTTP_MOVED_TEMPORARILY || status == NGX_HTTP_SEE_OTHER || status == NGX_HTTP_TEMPORARY_REDIRECT || status == NGX_HTTP_PERMANENT_REDIRECT {
        r.clear_location();
        let h = r.headers_out.borrow_mut().add(b"Location", &val);
        r.headers_out.borrow_mut().location = Some(h);
        return Step::Ready(status);
    }
    r.headers_out.borrow_mut().content_length_n = val.len() as i64;
    match ct {
        Some(ct) => {
            let mut ho = r.headers_out.borrow_mut();
            ho.content_type_len = ct.len();
            ho.content_type = ct.to_vec();
        }
        None => {
            if set_content_type(r) != NGX_OK {
                return Step::Ready(NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
        }
    }
    // the value is the response body: the buffer takes it
    let memory = !val.is_empty();
    let mut b = Buf::from_vec(val);
    b.memory = memory;
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    b.sync = !(b.last_buf || b.memory);
    match send_header(r) {
        Step::Ready(rc) => send_response_body(r, rc, b),
        Step::Pending(fut) => {
            let r = r.clone();
            Step::boxed(async move {
                let rc = fut.await;
                send_response_body(&r, rc, b).await
            })
        }
    }
}

/// ngx_http_send_response after the header
fn send_response_body(r: &R, rc: i64, b: Buf) -> Step {
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return Step::Ready(rc);
    }
    let mut out = Chain::new();
    out.push_back(b);
    output_filter(r, out).into_step()
}

/// ngx_http_internal_redirect: runs the request again from the server rewrite phase.
/// Returns NGX_DONE once the redirected request has been processed.
pub async fn internal_redirect(r: &R, uri: &[u8], args: Option<&[u8]>) -> i64 {
    r.uri_changes.set(r.uri_changes.get() - 1);
    if r.uri_changes.get() == 0 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "rewrite or internal redirection cycle while internally redirecting to \"{}\"", B(uri));
        Box::pin(crate::request_rt::finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR)).await;
        return NGX_DONE;
    }
    *r.uri.borrow_mut() = uri.to_vec();
    *r.args.borrow_mut() = args.map(|a| a.to_vec()).unwrap_or_default();
    http_debug!(r, "internal redirect: \"{}?{}\"", B(uri), B(&r.args.borrow()));
    set_exten(r);
    {
        let mut ctx = r.ctx.borrow_mut();
        for c in ctx.iter_mut() {
            *c = None;
        }
    }
    let cscf = r.cscf();
    let loc = cscf.borrow().ctx.loc.clone().unwrap();
    *r.loc_conf.borrow_mut() = loc;
    update_location_config(r);
    *r.cache.borrow_mut() = None;
    r.internal.set(true);
    r.valid_unparsed_uri.set(false);
    r.add_uri_to_alias.set(false);
    let rc = Box::pin(handler(r.clone())).await;
    Box::pin(crate::request_rt::finalize_request(r, rc)).await;
    NGX_DONE
}

/// ngx_http_named_location
pub async fn named_location(r: &R, name: &[u8]) -> i64 {
    r.uri_changes.set(r.uri_changes.get() - 1);
    if r.uri_changes.get() == 0 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "rewrite or internal redirection cycle while redirect to named location \"{}\"", B(name));
        Box::pin(crate::request_rt::finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR)).await;
        return NGX_DONE;
    }
    if r.uri.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "empty URI in redirect to named location \"{}\"", B(name));
        Box::pin(crate::request_rt::finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR)).await;
        return NGX_DONE;
    }
    let cscf = r.cscf();
    let named = cscf.borrow().named_locations.clone();
    for clcf in named.iter() {
        let cname = clcf.borrow().name.clone();
        http_debug!(r, "test location: \"{}\"", B(&cname));
        if cname != name {
            continue;
        }
        http_debug!(r, "using location: {} \"{}?{}\"", B(name), B(&r.uri.borrow()), B(&r.args.borrow()));
        r.internal.set(true);
        *r.content_handler.borrow_mut() = None;
        r.uri_changed.set(false);
        *r.loc_conf.borrow_mut() = clcf.borrow().loc_conf.clone().unwrap();
        {
            let mut ctx = r.ctx.borrow_mut();
            for c in ctx.iter_mut() {
                *c = None;
            }
        }
        update_location_config(r);
        let cmcf = r.cmcf();
        let idx = cmcf.borrow().phase_engine.location_rewrite_index;
        r.phase_handler.set(idx);
        let rc = Box::pin(run_phases(r.clone())).await;
        Box::pin(crate::request_rt::finalize_request(r, rc)).await;
        return NGX_DONE;
    }
    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "could not find named location \"{}\"", B(name));
    Box::pin(crate::request_rt::finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR)).await;
    NGX_DONE
}

/// ngx_http_auth_basic_user
pub fn auth_basic_user(r: &R) -> i64 {
    {
        let hin = r.headers_in.borrow();
        if hin.user.is_empty() && hin.user_tested {
            return NGX_DECLINED;
        }
    }
    let h = {
        let hin = r.headers_in.borrow();
        if r.is_proxy_auth() { hin.proxy_authorization.clone() } else { hin.authorization.clone() }
    };
    let fail = |r: &R| {
        r.headers_in.borrow_mut().user_tested = true;
        NGX_DECLINED
    };
    let h = match h {
        Some(h) => h,
        None => return fail(r),
    };
    let encoded = h.value.borrow().clone();
    if encoded.len() < 6 || !ngx_core::string::starts_with_ignore_case(&encoded, b"Basic ") {
        return fail(r);
    }
    let mut enc = &encoded[6..];
    while !enc.is_empty() && enc[0] == b' ' {
        enc = &enc[1..];
    }
    if enc.is_empty() {
        return fail(r);
    }
    let auth = match ngx_core::string::decode_base64(enc) {
        Some(a) => a,
        None => return fail(r),
    };
    let len = auth.iter().position(|&c| c == b':').unwrap_or(auth.len());
    if len == 0 || len == auth.len() {
        return fail(r);
    }
    let mut hin = r.headers_in.borrow_mut();
    hin.user = auth[..len].to_vec();
    hin.passwd = auth[len + 1..].to_vec();
    hin.user_tested = true;
    NGX_OK
}

/// ngx_http_gzip_ok
pub fn gzip_ok(r: &R) -> i64 {
    r.gzip_tested.set(true);
    if !r.is_main() {
        return NGX_DECLINED;
    }
    let hin = r.headers_in.borrow();
    let ae = match hin.accept_encoding.first() {
        Some(a) => a.value.borrow().clone(),
        None => return NGX_DECLINED,
    };
    if ae.len() < 4 {
        return NGX_DECLINED;
    }
    if !ae.starts_with(b"gzip,") && gzip_accept_encoding(&ae) != NGX_OK {
        return NGX_DECLINED;
    }
    let clcf = r.clcf();
    let c = clcf.borrow();
    if hin.msie6 && c.gzip_disable_msie6 != 0 {
        return NGX_DECLINED;
    }
    if r.http_version.get() < *c.gzip_http_version {
        return NGX_DECLINED;
    }
    let ok = 'ok: {
        if hin.via.is_empty() {
            break 'ok true;
        }
        let p = c.gzip_proxied;
        if p & NGX_HTTP_GZIP_PROXIED_OFF != 0 {
            return NGX_DECLINED;
        }
        if p & NGX_HTTP_GZIP_PROXIED_ANY != 0 {
            break 'ok true;
        }
        if hin.authorization.is_some() && (p & NGX_HTTP_GZIP_PROXIED_AUTH) != 0 {
            break 'ok true;
        }
        let ho = r.headers_out.borrow();
        if let Some(e) = &ho.expires {
            if p & NGX_HTTP_GZIP_PROXIED_EXPIRED == 0 {
                return NGX_DECLINED;
            }
            let expires = match ngx_core::parse::parse_http_time(&e.value.borrow()) {
                Some(t) => t,
                None => return NGX_DECLINED,
            };
            let date = match &ho.date {
                Some(d) => match ngx_core::parse::parse_http_time(&d.value.borrow()) {
                    Some(t) => t,
                    None => return NGX_DECLINED,
                },
                None => ngx_core::times::time(),
            };
            if expires < date {
                break 'ok true;
            }
            return NGX_DECLINED;
        }
        if !ho.cache_control.is_empty() {
            let vals: Vec<Vec<u8>> = ho.cache_control.iter().map(|h| h.value.borrow().clone()).collect();
            let refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();
            if (p & NGX_HTTP_GZIP_PROXIED_NO_CACHE) != 0 && crate::parse::parse_multi_header_lines(&refs, b"no-cache", b',').is_some() {
                break 'ok true;
            }
            if (p & NGX_HTTP_GZIP_PROXIED_NO_STORE) != 0 && crate::parse::parse_multi_header_lines(&refs, b"no-store", b',').is_some() {
                break 'ok true;
            }
            if (p & NGX_HTTP_GZIP_PROXIED_PRIVATE) != 0 && crate::parse::parse_multi_header_lines(&refs, b"private", b',').is_some() {
                break 'ok true;
            }
            return NGX_DECLINED;
        }
        if (p & NGX_HTTP_GZIP_PROXIED_NO_LM) != 0 && ho.last_modified.is_some() {
            return NGX_DECLINED;
        }
        if (p & NGX_HTTP_GZIP_PROXIED_NO_ETAG) != 0 && ho.etag.is_some() {
            return NGX_DECLINED;
        }
        true
    };
    let _ = ok;
    if let Some(list) = c.gzip_disable.as_option().and_then(|o| o.as_ref()) {
        if let Some(ua) = hin.user_agent.first() {
            let ua = ua.value.borrow();
            if list.iter().any(|re| re.is_match(&ua)) {
                return NGX_DECLINED;
            }
        }
    }
    r.gzip_ok.set(true);
    NGX_OK
}

/// ngx_http_gzip_accept_encoding: parses "gzip;q=..." in Accept-Encoding.
fn gzip_accept_encoding(ae: &[u8]) -> i64 {
    let mut start = 0;
    loop {
        let rest = &ae[start..];
        let p = match ngx_core::string::strcasestr(rest, b"gzip") {
            Some(p) => start + p,
            None => return NGX_DECLINED,
        };
        if p == 0 || ae[p - 1] == b',' || ae[p - 1] == b' ' {
            let mut q = p + 4;
            while q < ae.len() && ae[q] == b' ' {
                q += 1;
            }
            if q == ae.len() || ae[q] == b',' {
                return NGX_OK;
            }
            if ae[q] == b';' {
                q += 1;
                while q < ae.len() && ae[q] == b' ' {
                    q += 1;
                }
                if q + 1 < ae.len() && ae[q] == b'q' && ae[q + 1] == b'=' {
                    return gzip_quantity(&ae[q + 2..]);
                }
                return NGX_DECLINED;
            }
        }
        start = p + 4;
        if start >= ae.len() {
            return NGX_DECLINED;
        }
    }
}

fn gzip_quantity(p: &[u8]) -> i64 {
    let mut i = 0;
    let c = p.get(0).copied().unwrap_or(0);
    if c != b'0' && c != b'1' {
        return NGX_DECLINED;
    }
    let mut q = (c - b'0') as u32 * 100;
    i += 1;
    if i < p.len() && p[i] == b'.' {
        i += 1;
        let mut n = 0;
        let mut m = 10;
        while i < p.len() && n < 3 {
            let d = p[i];
            if !d.is_ascii_digit() {
                break;
            }
            q += (d - b'0') as u32 * m;
            m /= 10;
            n += 1;
            i += 1;
        }
    }
    while i < p.len() && p[i] == b' ' {
        i += 1;
    }
    if i < p.len() && p[i] != b',' {
        return NGX_DECLINED;
    }
    if q > 100 || q == 0 {
        return NGX_DECLINED;
    }
    NGX_OK
}

/// ngx_http_get_forwarded_addr: returns the resolved address if trusted proxies allow it.
pub fn get_forwarded_addr(r: &R, addr: &ngx_core::inet::SockAddr, headers: &[Header], value: &[u8], proxies: &[ngx_core::inet::Cidr], recursive: bool) -> (i64, ngx_core::inet::SockAddr) {
    let mut cur = addr.clone();
    if headers.is_empty() {
        let rc = forwarded_addr_internal(&mut cur, value, proxies, recursive);
        return (rc, cur);
    }
    let mut rc = NGX_DECLINED;
    let mut found = false;
    for h in headers.iter().rev() {
        let v = h.value.borrow().clone();
        rc = forwarded_addr_internal(&mut cur, &v, proxies, recursive);
        if !recursive {
            break;
        }
        if rc == NGX_DECLINED && found {
            rc = NGX_DONE;
            break;
        }
        if rc != NGX_OK {
            break;
        }
        found = true;
    }
    let _ = r;
    (rc, cur)
}

/// ngx_http_get_forwarded_addr_internal
fn forwarded_addr_internal(addr: &mut ngx_core::inet::SockAddr, xff: &[u8], proxies: &[ngx_core::inet::Cidr], recursive: bool) -> i64 {
    let mut found = false;
    let mut xfflen = xff.len();

    loop {
        if !proxies.iter().any(|c| c.matches(addr)) {
            return if found { NGX_DONE } else { NGX_DECLINED };
        }

        if xfflen == 0 {
            // an empty value: C parses the byte before it, the ':' or the
            // space of the header line, which is not an address
            return if found { NGX_DONE } else { NGX_DECLINED };
        }

        // p is an index in xff; as in C, the first character is never
        // taken for a separator

        let mut p = xfflen - 1;

        while p > 0 {
            if xff[p] != b' ' && xff[p] != b',' {
                break;
            }

            p -= 1;
            xfflen -= 1;
        }

        while p > 0 {
            if xff[p] == b' ' || xff[p] == b',' {
                p += 1;
                break;
            }

            p -= 1;
        }

        match ngx_core::inet::parse_addr_port(&xff[p..xfflen]) {
            Some(a) => *addr = a,
            None => return if found { NGX_DONE } else { NGX_DECLINED },
        }

        found = true;

        if !(recursive && p > 0) {
            break;
        }

        xfflen = p - 1;
    }

    NGX_OK
}

/// Convenience for handlers: current core loc conf borrow.
pub fn clcf_ref(r: &R) -> Rc<RefCell<CoreLocConf>> {
    r.clcf()
}
