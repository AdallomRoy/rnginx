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
pub async fn handler(r: R) -> i64 {
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
    run_phases(r).await
}

/// ngx_http_core_run_phases: returns the rc to pass to finalize_request.
pub async fn run_phases(r: R) -> i64 {
    let cmcf = r.cmcf();
    loop {
        let ph = {
            let m = cmcf.borrow();
            let idx = r.phase_handler.get();
            match m.phase_engine.handlers.get(idx) {
                Some(p) => p.clone(),
                None => return NGX_DONE,
            }
        };
        let step = match ph.checker {
            Checker::Generic => generic_phase(&r, &ph).await,
            Checker::Rewrite => rewrite_phase(&r, &ph).await,
            Checker::FindConfig => find_config_phase(&r, &ph).await,
            Checker::PostRewrite => post_rewrite_phase(&r, &ph),
            Checker::Access => access_phase(&r, &ph).await,
            Checker::PostAccess => post_access_phase(&r, &ph).await,
            Checker::Content => content_phase(&r, &ph).await,
        };
        match step {
            PhaseStep::Continue => continue,
            PhaseStep::Finalize(rc) => return rc,
        }
    }
}

pub enum PhaseStep {
    Continue,
    Finalize(i64),
}

async fn generic_phase(r: &R, ph: &PhaseHandler) -> PhaseStep {
    http_debug!(r, "generic phase: {}", r.phase_handler.get());
    let rc = (ph.handler.as_ref().unwrap())(r.clone()).await;
    if rc == NGX_OK {
        r.phase_handler.set(ph.next);
        return PhaseStep::Continue;
    }
    if rc == NGX_DECLINED {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return PhaseStep::Continue;
    }
    if rc == NGX_AGAIN || rc == NGX_DONE {
        return PhaseStep::Finalize(NGX_DONE);
    }
    PhaseStep::Finalize(rc)
}

async fn rewrite_phase(r: &R, ph: &PhaseHandler) -> PhaseStep {
    http_debug!(r, "rewrite phase: {}", r.phase_handler.get());
    let rc = (ph.handler.as_ref().unwrap())(r.clone()).await;
    if rc == NGX_DECLINED {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return PhaseStep::Continue;
    }
    if rc == NGX_DONE {
        return PhaseStep::Finalize(NGX_DONE);
    }
    PhaseStep::Finalize(rc)
}

async fn find_config_phase(r: &R, _ph: &PhaseHandler) -> PhaseStep {
    *r.content_handler.borrow_mut() = None;
    r.uri_changed.set(false);
    let rc = find_location(r);
    if rc == NGX_ERROR {
        return PhaseStep::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    let clcf = r.clcf();
    if !r.internal.get() && *clcf.borrow().internal {
        return PhaseStep::Finalize(NGX_HTTP_NOT_FOUND);
    }
    {
        let c = clcf.borrow();
        http_debug!(r, "using configuration \"{}{}\"", if c.noname { "*" } else if c.exact_match { "=" } else { "" }, B(&c.name));
    }
    update_location_config(r);
    let clcf = r.clcf();
    let (max_body, name) = {
        let c = clcf.borrow();
        (*c.client_max_body_size, c.escaped_name.clone())
    };
    let cl = r.headers_in.borrow().content_length_n;
    http_debug!(r, "http cl:{} max:{}", cl, max_body);
    if cl != -1 && !r.discard_body.get() && max_body != 0 && max_body < cl {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client intended to send too large body: {} bytes", cl);
        r.expect_tested.set(true);
        let _ = crate::request_body::discard_request_body(r).await;
        return PhaseStep::Finalize(NGX_HTTP_REQUEST_ENTITY_TOO_LARGE);
    }
    if rc == NGX_DONE {
        r.clear_location();
        let args = r.args.borrow().clone();
        let value = if args.is_empty() {
            name
        } else {
            let mut v = name;
            v.push(b'?');
            v.extend_from_slice(&args);
            v
        };
        let h = r.headers_out.borrow_mut().add(b"Location", &value);
        r.headers_out.borrow_mut().location = Some(h);
        return PhaseStep::Finalize(NGX_HTTP_MOVED_PERMANENTLY);
    }
    r.phase_handler.set(r.phase_handler.get() + 1);
    PhaseStep::Continue
}

fn post_rewrite_phase(r: &R, ph: &PhaseHandler) -> PhaseStep {
    http_debug!(r, "post rewrite phase: {}", r.phase_handler.get());
    if !r.uri_changed.get() {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return PhaseStep::Continue;
    }
    http_debug!(r, "uri changes: {}", r.uri_changes.get());
    r.uri_changes.set(r.uri_changes.get() - 1);
    if r.uri_changes.get() == 0 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "rewrite or internal redirection cycle while processing \"{}\"", B(&r.uri.borrow()));
        return PhaseStep::Finalize(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    r.phase_handler.set(ph.next);
    let cscf = r.cscf();
    let loc = cscf.borrow().ctx.loc.clone().unwrap();
    *r.loc_conf.borrow_mut() = loc;
    PhaseStep::Continue
}

async fn access_phase(r: &R, ph: &PhaseHandler) -> PhaseStep {
    if !r.is_main() {
        r.phase_handler.set(ph.next);
        return PhaseStep::Continue;
    }
    http_debug!(r, "access phase: {}", r.phase_handler.get());
    let rc = (ph.handler.as_ref().unwrap())(r.clone()).await;
    if rc == NGX_DECLINED {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return PhaseStep::Continue;
    }
    if rc == NGX_AGAIN || rc == NGX_DONE {
        return PhaseStep::Finalize(NGX_DONE);
    }
    let clcf = r.clcf();
    let satisfy = *clcf.borrow().satisfy;
    if satisfy == NGX_HTTP_SATISFY_ALL {
        if rc == NGX_OK {
            r.phase_handler.set(r.phase_handler.get() + 1);
            return PhaseStep::Continue;
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
            return PhaseStep::Continue;
        }
        if rc == NGX_HTTP_FORBIDDEN || rc == NGX_HTTP_UNAUTHORIZED || rc == NGX_HTTP_PROXY_AUTH_REQUIRED {
            if r.access_code.get() != NGX_HTTP_UNAUTHORIZED && r.access_code.get() != NGX_HTTP_PROXY_AUTH_REQUIRED {
                r.access_code.set(rc);
            }
            r.phase_handler.set(r.phase_handler.get() + 1);
            return PhaseStep::Continue;
        }
    }
    if rc == NGX_HTTP_UNAUTHORIZED || rc == NGX_HTTP_PROXY_AUTH_REQUIRED {
        r.access_code.set(rc);
        return PhaseStep::Finalize(auth_delay(r).await);
    }
    PhaseStep::Finalize(rc)
}

async fn post_access_phase(r: &R, _ph: &PhaseHandler) -> PhaseStep {
    http_debug!(r, "post access phase: {}", r.phase_handler.get());
    let access_code = r.access_code.get();
    if access_code != 0 {
        if access_code == NGX_HTTP_FORBIDDEN {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "access forbidden by rule");
        }
        if access_code == NGX_HTTP_UNAUTHORIZED || access_code == NGX_HTTP_PROXY_AUTH_REQUIRED {
            return PhaseStep::Finalize(auth_delay(r).await);
        }
        r.access_code.set(0);
        return PhaseStep::Finalize(access_code);
    }
    r.phase_handler.set(r.phase_handler.get() + 1);
    PhaseStep::Continue
}

/// ngx_http_core_auth_delay: returns the access code to finalize with after the delay.
async fn auth_delay(r: &R) -> i64 {
    let clcf = r.clcf();
    let delay = *clcf.borrow().auth_delay;
    let access_code = r.access_code.get();
    r.access_code.set(0);
    if delay == 0 {
        return access_code;
    }
    ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "delaying unauthorized request");
    let closed = crate::request_rt::wait_delay_or_close(r, delay).await;
    if closed {
        return NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }
    access_code
}

async fn content_phase(r: &R, ph: &PhaseHandler) -> PhaseStep {
    let ch = r.content_handler.borrow().clone();
    if let Some(h) = ch {
        let rc = h(r.clone()).await;
        return PhaseStep::Finalize(rc);
    }
    http_debug!(r, "content phase: {}", r.phase_handler.get());
    let rc = (ph.handler.as_ref().unwrap())(r.clone()).await;
    if rc != NGX_DECLINED {
        return PhaseStep::Finalize(rc);
    }
    // rc == NGX_DECLINED
    let cmcf = r.cmcf();
    let has_next = {
        let m = cmcf.borrow();
        m.phase_engine.handlers.get(r.phase_handler.get() + 1).is_some()
    };
    if has_next {
        r.phase_handler.set(r.phase_handler.get() + 1);
        return PhaseStep::Continue;
    }
    let uri = r.uri.borrow().clone();
    if uri.last() == Some(&b'/') {
        if let Some((path, _root)) = map_uri_to_path(r, 0) {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "directory index of \"{}\" is forbidden", B(&path));
        }
        return PhaseStep::Finalize(NGX_HTTP_FORBIDDEN);
    }
    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no handler found");
    PhaseStep::Finalize(NGX_HTTP_NOT_FOUND)
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
    let regex_locations = pclcf.borrow().regex_locations.clone();
    if !noregex && !regex_locations.is_empty() {
        for clcf in regex_locations.iter() {
            let (name, re) = {
                let c = clcf.borrow();
                (c.name.clone(), c.regex.clone().unwrap())
            };
            http_debug!(r, "test location: ~ \"{}\"", B(&name));
            let uri = r.uri.borrow().clone();
            let n = crate::variables::regex_exec(r, &re, &uri);
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
    let preds = pclcf.borrow().predicate_locations.clone();
    if !noregex && !preds.is_empty() {
        for clcf in preds.iter() {
            let (name, pidx) = {
                let c = clcf.borrow();
                (c.name.clone(), c.predicate)
            };
            http_debug!(r, "test location: \"{}\"", B(&name));
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
    let uri_full = r.uri.borrow().clone();
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
    let exten = r.exten.borrow().clone();
    if !exten.is_empty() {
        let lower = ngx_core::string::to_lower_vec(&exten);
        let hash = ngx_core::hash::hash_key(&lower);
        let c = clcf.borrow();
        if let Some(th) = &c.types_hash {
            if let Some(t) = th.find(hash, &lower) {
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
    let value = format!("\"{:x}-{:x}\"", ho.last_modified_time, ho.content_length_n);
    let h = ho.add(b"ETag", value.as_bytes());
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

/// ngx_http_send_header
pub async fn send_header(r: &R) -> i64 {
    if r.post_action.get() {
        return NGX_OK;
    }
    if r.header_sent.get() {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "header already sent");
        return NGX_ERROR;
    }
    if r.err_status.get() != 0 {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = r.err_status.get();
        ho.status_line.clear();
    }
    let f = top_header_filter();
    f(r.clone()).await
}

/// ngx_http_output_filter
pub async fn output_filter(r: &R, chain: Chain) -> i64 {
    http_debug!(r, "http output filter \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));
    let f = top_body_filter();
    let rc = f(r.clone(), chain).await;
    if rc == NGX_ERROR {
        r.connection.error.set(true);
    }
    rc
}

/// ngx_http_map_uri_to_path: returns (path, root_length).
pub fn map_uri_to_path(r: &R, reserved: usize) -> Option<(Vec<u8>, usize)> {
    let clcf = r.clcf();
    let c = clcf.borrow();
    let mut alias = c.alias;
    let uri = r.uri.borrow().clone();
    if alias != 0 && !r.valid_location.get() {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "\"alias\" cannot be used in location \"{}\" where URI was rewritten", B(&c.name));
        return None;
    }
    if alias > uri.len() && alias != usize::MAX {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "URI shorter than aliased URI part");
        return None;
    }
    let _ = reserved;
    let mut path: Vec<u8>;
    let root_length;
    match &c.root_script {
        None => {
            path = c.root.clone();
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
    path.extend_from_slice(&uri[alias..]);
    Some((path, root_length))
}

/// ngx_http_send_response
pub async fn send_response(r: &R, status: i64, ct: Option<&[u8]>, cv: &ComplexValue) -> i64 {
    let rc = crate::request_body::discard_request_body(r).await;
    if rc != NGX_OK {
        return rc;
    }
    r.headers_out.borrow_mut().status = status;
    let val = match complex_value(r, cv) {
        Ok(v) => v,
        Err(_) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    if status == NGX_HTTP_MOVED_PERMANENTLY || status == NGX_HTTP_MOVED_TEMPORARILY || status == NGX_HTTP_SEE_OTHER || status == NGX_HTTP_TEMPORARY_REDIRECT || status == NGX_HTTP_PERMANENT_REDIRECT {
        r.clear_location();
        let h = r.headers_out.borrow_mut().add(b"Location", &val);
        r.headers_out.borrow_mut().location = Some(h);
        return status;
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
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    let mut b = Buf::from_vec(val.clone());
    b.memory = !val.is_empty();
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    b.sync = !(b.last_buf || b.memory);
    let rc = send_header(r).await;
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return rc;
    }
    let mut out = Chain::new();
    out.push_back(b);
    output_filter(r, out).await
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
