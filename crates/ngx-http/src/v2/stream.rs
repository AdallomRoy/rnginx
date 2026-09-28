//! Streams (nginx-c/src/http/v2/ngx_http_v2.c): creation, the priority tree,
//! building the request from the header block, running it, and closing or
//! terminating it.
//!
//! Each stream's request runs in its own task (C runs it inline from the
//! state machine and resumes it from the fake connection's events). Where C
//! calls a stream's event handler synchronously from a frame handler, the
//! state machine posts the effect and the driver runs it (run_posted) before
//! parsing the next frame; terminating a stream (RST_STREAM, flow control
//! errors, connection teardown) is done synchronously, as in C.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use ngx_core::connection::Connection;
use ngx_core::log::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use super::connection::send_rst_stream;
use super::module::Http2SrvConf;
use super::*;
use crate::core::CoreSrvConf;
use crate::request::{HttpLogCtx, HttpState, TableElt, R};
use crate::request_rt;
use crate::*;

/// The ngx_http_v2_srv_conf_t values the runtime reads.
pub struct SrvConf {
    pub enable: bool,
    pub concurrent_streams: usize,
    pub preread_size: usize,
}

fn srv_conf_of(slots: &Rc<ngx_core::conf::ConfSlots>) -> SrvConf {
    let c = ngx_core::conf::slot_of::<Http2SrvConf>(slots, super::module::ctx_index());
    let c = c.borrow();
    SrvConf {
        enable: *c.enable,
        concurrent_streams: *c.concurrent_streams as usize,
        preread_size: *c.preread_size,
    }
}

/// h2scf of hc->conf_ctx (the default or SNI-selected server).
pub fn h2c_srv_conf(h2c: &H2Connection) -> SrvConf {
    let ctx = h2c.http_connection.conf_ctx.borrow();
    srv_conf_of(ctx.srv.as_ref().expect("srv conf"))
}

/// h2scf of the request's server.
pub fn srv_conf(r: &R) -> SrvConf {
    let slots = r.srv_conf.borrow().clone();
    srv_conf_of(&slots)
}

/// The HTTP/2 stream of a request (r->stream).
pub fn request_stream(r: &R) -> Option<Rc<H2Stream>> {
    r.stream.borrow().clone().and_then(|s| s.downcast::<H2Stream>().ok())
}

// ---------------------------------------------------------------------------
// the priority tree

fn index_of(h2c: &H2Connection, sid: u32) -> usize {
    ((sid >> 1) as usize) & h2c.streams_index_mask
}

/// ngx_http_v2_get_node_by_id
pub fn get_node_by_id(h2c: &Rc<H2Connection>, sid: u32, alloc: bool) -> Option<Rc<H2Node>> {
    let index = index_of(h2c, sid);

    if let Some(node) = h2c.streams_index.borrow().get(index).and_then(|b| b.iter().find(|n| n.id.get() == sid)) {
        return Some(node.clone());
    }

    if !alloc {
        return None;
    }

    let node = if h2c.closed_nodes.get() < 32 {
        Rc::new(H2Node {
            id: Cell::new(0),
            parent: RefCell::new(Parent::None),
            children: RefCell::new(Vec::new()),
            rank: Cell::new(0),
            weight: Cell::new(0),
            rel_weight: Cell::new(0.0),
            stream: RefCell::new(None),
        })
    } else {
        get_closed_node(h2c)
    };

    node.id.set(sid);

    h2c.streams_index.borrow_mut()[index].insert(0, node.clone());

    Some(node)
}

/// ngx_http_v2_get_closed_node: take the oldest closed node out of the tree
/// for reuse, handing its children to its parent.
fn get_closed_node(h2c: &Rc<H2Connection>) -> Rc<H2Node> {
    h2c.closed_nodes.set(h2c.closed_nodes.get() - 1);

    let node = h2c.closed.borrow_mut().pop_front().expect("closed node");

    {
        let index = index_of(h2c, node.id.get());
        let mut idx = h2c.streams_index.borrow_mut();
        idx[index].retain(|n| !Rc::ptr_eq(n, &node));
    }

    let parent = node.parent.borrow().clone();

    remove_from_parent(h2c, &node, &parent);

    let weight: usize = node.children.borrow().iter().map(|c| c.weight.get()).sum();

    let children = std::mem::take(&mut *node.children.borrow_mut());

    for child in children.iter() {
        *child.parent.borrow_mut() = parent.clone();
        let w = node.weight.get() * child.weight.get() / weight.max(1);
        child.weight.set(if w == 0 { 1 } else { w });
    }

    match parent.node() {
        None => {
            node.rank.set(0);
            node.rel_weight.set(1.0);
        }
        Some(p) => {
            node.rank.set(p.rank.get());
            node.rel_weight.set(p.rel_weight.get());
        }
    }

    // ngx_http_v2_node_children_update(node) with node's rank/weight, then
    // ngx_queue_add(children, &node->children)
    *node.children.borrow_mut() = children;
    node_children_update(&node);
    let children = std::mem::take(&mut *node.children.borrow_mut());
    match parent.node() {
        None => h2c.dependencies.borrow_mut().extend(children),
        Some(p) => p.children.borrow_mut().extend(children),
    }

    // ngx_memzero(node)
    *node.parent.borrow_mut() = Parent::None;
    node.rank.set(0);
    node.weight.set(0);
    node.rel_weight.set(0.0);
    *node.stream.borrow_mut() = None;

    node
}

/// ngx_queue_remove(&node->queue): out of the parent's children (or the
/// roots).
fn remove_from_parent(h2c: &H2Connection, node: &Rc<H2Node>, parent: &Parent) {
    match parent {
        Parent::None => {}
        Parent::Root => h2c.dependencies.borrow_mut().retain(|n| !Rc::ptr_eq(n, node)),
        Parent::Node(w) => {
            if let Some(p) = w.upgrade() {
                p.children.borrow_mut().retain(|n| !Rc::ptr_eq(n, node));
            }
        }
    }
}

/// ngx_queue_remove(&node->reuse)
pub fn closed_remove(h2c: &H2Connection, node: &Rc<H2Node>) {
    h2c.closed.borrow_mut().retain(|n| !Rc::ptr_eq(n, node));
}

/// ngx_http_v2_set_dependency
pub fn set_dependency(h2c: &Rc<H2Connection>, node: &Rc<H2Node>, depend: u32, mut exclusive: bool) {
    let parent = if depend != 0 { get_node_by_id(h2c, depend, false) } else { None };

    // the list the node joins: None for the roots
    let new_parent: Parent;

    match parent {
        None => {
            new_parent = Parent::Root;

            if depend != 0 {
                exclusive = false;
            }

            node.rank.set(1);
            node.rel_weight.set((1.0 / 256.0) * node.weight.get() as f64);
        }

        Some(parent) => {
            if !node.parent.borrow().is_none() {
                // is the new parent a descendant of the node?
                let mut next = parent.parent.borrow().node();
                while let Some(n) = next {
                    if n.rank.get() < node.rank.get() {
                        break;
                    }

                    if !Rc::ptr_eq(&n, node) {
                        next = n.parent.borrow().node();
                        continue;
                    }

                    // move the parent up to the node's place, right after it
                    let pparent = parent.parent.borrow().clone();
                    remove_from_parent(h2c, &parent, &pparent);

                    let node_parent = node.parent.borrow().clone();
                    insert_after(h2c, &node_parent, node, &parent);

                    *parent.parent.borrow_mut() = node_parent.clone();

                    match node_parent.node() {
                        None => {
                            parent.rank.set(1);
                            parent.rel_weight.set((1.0 / 256.0) * parent.weight.get() as f64);
                        }
                        Some(np) => {
                            parent.rank.set(np.rank.get() + 1);
                            parent.rel_weight.set((np.rel_weight.get() / 256.0) * parent.weight.get() as f64);
                        }
                    }

                    if !exclusive {
                        node_children_update(&parent);
                    }

                    break;
                }
            }

            node.rank.set(parent.rank.get() + 1);
            node.rel_weight.set((parent.rel_weight.get() / 256.0) * node.weight.get() as f64);

            if parent.stream.borrow().is_none() {
                closed_remove(h2c, &parent);
                h2c.closed.borrow_mut().push_back(parent.clone());
            }

            new_parent = Parent::Node(Rc::downgrade(&parent));
        }
    }

    if exclusive {
        // the node adopts all of the new parent's children
        let children = match new_parent.node() {
            None => std::mem::take(&mut *h2c.dependencies.borrow_mut()),
            Some(ref p) => std::mem::take(&mut *p.children.borrow_mut()),
        };
        for child in children.iter() {
            *child.parent.borrow_mut() = Parent::Node(Rc::downgrade(node));
        }
        node.children.borrow_mut().extend(children);
    }

    let old_parent = node.parent.borrow().clone();
    if !old_parent.is_none() {
        remove_from_parent(h2c, node, &old_parent);
    }

    match new_parent.node() {
        None => h2c.dependencies.borrow_mut().push(node.clone()),
        Some(ref p) => p.children.borrow_mut().push(node.clone()),
    }

    *node.parent.borrow_mut() = new_parent;

    node_children_update(node);
}

/// ngx_queue_insert_after(&node->queue, &parent->queue) in node's list.
fn insert_after(h2c: &H2Connection, list_owner: &Parent, node: &Rc<H2Node>, item: &Rc<H2Node>) {
    let insert = |list: &mut Vec<Rc<H2Node>>| {
        let at = list.iter().position(|n| Rc::ptr_eq(n, node)).map(|i| i + 1).unwrap_or(list.len());
        list.insert(at, item.clone());
    };
    match list_owner {
        Parent::None => {}
        Parent::Root => insert(&mut h2c.dependencies.borrow_mut()),
        Parent::Node(w) => {
            if let Some(p) = w.upgrade() {
                insert(&mut p.children.borrow_mut());
            }
        }
    }
}

/// ngx_http_v2_node_children_update
fn node_children_update(node: &Rc<H2Node>) {
    let children = node.children.borrow().clone();
    for child in children.iter() {
        child.rank.set(node.rank.get() + 1);
        child.rel_weight.set((node.rel_weight.get() / 256.0) * child.weight.get() as f64);

        node_children_update(child);
    }
}

// ---------------------------------------------------------------------------
// creating streams

/// ngx_http_v2_create_stream
pub fn create_stream(h2c: &Rc<H2Connection>, node: &Rc<H2Node>) -> Rc<H2Stream> {
    let c = &h2c.connection;
    let hc = &h2c.http_connection;

    let fc = Connection::new_fake(c);

    let log_ctx = Rc::new(HttpLogCtx {
        connection: Rc::downgrade(&fc),
        request: RefCell::new(None),
        current_request: RefCell::new(None),
    });
    fc.log.set_context(Some(log_ctx.clone()));
    fc.log.set_action(Some("reading client request headers"));

    let r = crate::request::create_request(&fc, hc, &log_ctx);

    *r.http_protocol.borrow_mut() = b"HTTP/2.0".to_vec();
    r.http_version.set(NGX_HTTP_VERSION_20);
    r.valid_location.set(true);

    c.requests.set(c.requests.get() + 1);

    r.headers_in.borrow_mut().connection_type = NGX_HTTP_CONNECTION_CLOSE;

    let h2scf = srv_conf(&r);

    let stream = Rc::new(H2Stream {
        request: RefCell::new(Some(r.clone())),
        connection: h2c.clone(),
        node: RefCell::new(node.clone()),
        fc: fc.clone(),
        queued: Cell::new(0),
        send_window: Cell::new(h2c.init_window.get() as isize),
        recv_window: Cell::new(h2scf.preread_size),
        preread: RefCell::new(None),
        frames: Cell::new(0),
        free_frames: Cell::new(0),
        cookies: RefCell::new(Vec::new()),
        initialized: Cell::new(false),
        waiting: Cell::new(false),
        blocked: Cell::new(false),
        exhausted: Cell::new(false),
        in_closed: Cell::new(false),
        out_closed: Cell::new(false),
        rst_sent: Cell::new(false),
        no_flow_control: Cell::new(false),
        skip_data: Cell::new(false),
        notify: tokio::sync::Notify::new(),
        task: RefCell::new(None),
        request_done: Cell::new(false),
        closed: Cell::new(false),
        authority: RefCell::new(None),
    });

    let any: Rc<dyn std::any::Any> = stream.clone();
    *r.stream.borrow_mut() = Some(any);

    h2c.processing.set(h2c.processing.get() + 1);

    h2c.priority_limit.set(h2c.priority_limit.get() + h2scf.concurrent_streams);

    h2c.read_timer.set(None);

    stream
}

/// The fake connection's read timer, armed while a stream's header block
/// is incomplete (ngx_http_v2_state_headers_save); on expiry
/// ngx_http_v2_close_stream_handler closes the stream as timed out.
pub fn arm_header_timer(stream: &Rc<H2Stream>) {
    if stream.task.borrow().is_some() {
        return;
    }

    let timeout = match stream.request.borrow().as_ref() {
        Some(r) => *r.cscf().borrow().client_header_timeout,
        None => return,
    };

    let s = stream.clone();
    let handle = ngx_core::event::spawn(async move {
        tokio::time::sleep(Duration::from_millis(timeout)).await;
        if s.closed.get() {
            return;
        }
        s.task.borrow_mut().take();
        ngx_log_error!(NGX_LOG_INFO, s.fc.log, Some(libc::ETIMEDOUT), "client timed out");
        s.fc.timedout.set(true);
        close_stream(&s, NGX_HTTP_REQUEST_TIME_OUT);
    });
    *stream.task.borrow_mut() = Some(handle);
}

// ---------------------------------------------------------------------------
// the header block

/// The request side of ngx_http_v2_state_process_header. Err(Some(())): the
/// request has been finalized (or is being finalized), stop feeding it
/// headers ("goto error"); Err(None): internal error.
pub fn header_request(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, name: &[u8], value: &[u8]) -> Result<(), Option<()>> {
    let r = match stream.request.borrow().clone() {
        Some(r) => r,
        None => return Err(Some(())),
    };

    // TODO in C too: validate headers while parsing.
    if validate_header(&r, name, value).is_err() {
        finalize(h2c, stream, NGX_HTTP_BAD_REQUEST);
        return Err(Some(()));
    }

    if name[0] == b':' {
        return match pseudo_header(h2c, stream, &r, &name[1..], value) {
            Pseudo::Ok => {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http2 header: \":{}: {}\"", B(&name[1..]), B(value));
                Ok(())
            }
            Pseudo::Abort => Err(Some(())),
            Pseudo::Declined => {
                finalize(h2c, stream, NGX_HTTP_BAD_REQUEST);
                Err(Some(()))
            }
        };
    }

    if construct_request_line(h2c, stream, &r).is_err() {
        return Err(Some(()));
    }

    if r.invalid_header.get() {
        let ignore = *r.cscf().borrow().ignore_invalid_headers;
        if ignore {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid header: \"{}\"", B(name));
            return Ok(());
        }
    }

    if name == b"cookie" {
        // ngx_http_v2_cookie
        stream.cookies.borrow_mut().push(value.to_vec());
    } else {
        let max_headers = *r.cscf().borrow().max_headers;

        let count = {
            let mut hin = r.headers_in.borrow_mut();
            let n = hin.count;
            hin.count += 1;
            n
        };

        if count as i64 >= max_headers {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent too many header lines");
            finalize(h2c, stream, NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
            return Err(Some(()));
        }

        if process_header_line(h2c, stream, &r, name, value).is_err() {
            return Err(Some(()));
        }
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http2 header: \"{}: {}\"", B(name), B(value));

    Ok(())
}

/// Add a header to headers_in and run its headers_in_hash handler.
fn process_header_line(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, r: &R, name: &[u8], value: &[u8]) -> Result<(), ()> {
    let hash = ngx_core::hash::hash_key(name);
    let h = TableElt::with_hash(name, value, hash, name.to_vec());

    r.headers_in.borrow_mut().headers.push(h.clone());

    let handler = {
        let cmcf = r.cmcf();
        let m = cmcf.borrow();
        m.headers_in_hash.as_ref().and_then(|hh| hh.find(hash, name).copied())
    };

    if let Some(f) = handler {
        if f(r, h) != NGX_OK {
            // the C handler has finalized the request
            let pending = request_rt::take_pending_finalize();
            finalize(h2c, stream, if pending != 0 { pending } else { NGX_HTTP_INTERNAL_SERVER_ERROR });
            return Err(());
        }
    }

    Ok(())
}

/// ngx_http_v2_validate_header
fn validate_header(r: &R, name: &[u8], value: &[u8]) -> Result<(), ()> {
    r.invalid_header.set(false);

    let underscores = *r.cscf().borrow().underscores_in_headers;

    let start = (name[0] == b':') as usize;

    for &ch in &name[start..] {
        if ch.is_ascii_lowercase() || ch == b'-' || ch.is_ascii_digit() || (ch == b'_' && underscores) {
            continue;
        }

        if ch <= 0x20 || ch == 0x7f || ch == b':' || ch.is_ascii_uppercase() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid header name: \"{}\"", B(name));
            return Err(());
        }

        r.invalid_header.set(true);
    }

    for &ch in value {
        if ch == b'\0' || ch == b'\n' || ch == b'\r' {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent header \"{}\" with invalid value: \"{}\"", B(name), B(value));
            return Err(());
        }
    }

    Ok(())
}

enum Pseudo {
    Ok,
    /// NGX_DECLINED: the caller finalizes with 400.
    Declined,
    /// NGX_ABORT: already finalized.
    Abort,
}

/// ngx_http_v2_pseudo_header (the name without the colon)
fn pseudo_header(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, r: &R, name: &[u8], value: &[u8]) -> Pseudo {
    if !r.request_line.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent out of order pseudo-headers");
        return Pseudo::Declined;
    }

    match name {
        b"path" => return parse_path(h2c, stream, r, value),
        b"method" => return parse_method(r, value),
        b"scheme" => return parse_scheme(r, value),
        b"authority" => return parse_authority(h2c, stream, r, value),
        _ => {}
    }

    ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent unknown pseudo-header \":{}\"", B(name));

    Pseudo::Declined
}

/// ngx_http_v2_parse_path
fn parse_path(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, r: &R, value: &[u8]) -> Pseudo {
    if !r.unparsed_uri.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent duplicate :path header");
        return Pseudo::Declined;
    }

    if value.is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent empty :path header");
        return Pseudo::Declined;
    }

    let rc = {
        let mut p = r.parse.borrow_mut();
        *p = crate::parse::ParseRequest::default();
        p.uri_start = Some(0);
        p.uri_end = Some(value.len());
        crate::parse::parse_uri(&mut p, value)
    };

    if rc != NGX_OK {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid :path header: \"{}\"", B(value));
        return Pseudo::Declined;
    }

    if request_rt::process_request_uri_data(r, value).is_err() {
        // ngx_http_process_request_uri finalizes the request
        finalize(h2c, stream, NGX_HTTP_BAD_REQUEST);
        return Pseudo::Abort;
    }

    Pseudo::Ok
}

/// ngx_http_v2_parse_method
fn parse_method(r: &R, value: &[u8]) -> Pseudo {
    const TESTS: [(&[u8], u32); 16] = [
        (b"GET", NGX_HTTP_GET),
        (b"POST", NGX_HTTP_POST),
        (b"HEAD", NGX_HTTP_HEAD),
        (b"OPTIONS", NGX_HTTP_OPTIONS),
        (b"PROPFIND", NGX_HTTP_PROPFIND),
        (b"PUT", NGX_HTTP_PUT),
        (b"MKCOL", NGX_HTTP_MKCOL),
        (b"DELETE", NGX_HTTP_DELETE),
        (b"COPY", NGX_HTTP_COPY),
        (b"MOVE", NGX_HTTP_MOVE),
        (b"PROPPATCH", NGX_HTTP_PROPPATCH),
        (b"LOCK", NGX_HTTP_LOCK),
        (b"UNLOCK", NGX_HTTP_UNLOCK),
        (b"PATCH", NGX_HTTP_PATCH),
        (b"TRACE", NGX_HTTP_TRACE),
        (b"CONNECT", NGX_HTTP_CONNECT),
    ];

    if !r.method_name.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent duplicate :method header");
        return Pseudo::Declined;
    }

    if value.is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent empty :method header");
        return Pseudo::Declined;
    }

    *r.method_name.borrow_mut() = value.to_vec();

    if let Some((_, m)) = TESTS.iter().find(|(name, _)| *name == value) {
        r.method.set(*m);
        return Pseudo::Ok;
    }

    for &ch in value {
        if !ch.is_ascii_uppercase() && ch != b'_' && ch != b'-' {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid method: \"{}\"", B(value));
            return Pseudo::Declined;
        }
    }

    Pseudo::Ok
}

/// ngx_http_v2_parse_scheme
fn parse_scheme(r: &R, value: &[u8]) -> Pseudo {
    if !r.schema.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent duplicate :scheme header");
        return Pseudo::Declined;
    }

    if value.is_empty() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent empty :scheme header");
        return Pseudo::Declined;
    }

    for (i, &ch) in value.iter().enumerate() {
        let c = ch | 0x20;
        if c.is_ascii_lowercase() {
            continue;
        }

        if (ch.is_ascii_digit() || ch == b'+' || ch == b'-' || ch == b'.') && i > 0 {
            continue;
        }

        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid :scheme header: \"{}\"", B(value));
        return Pseudo::Declined;
    }

    *r.schema.borrow_mut() = value.to_vec();

    Pseudo::Ok
}

/// ngx_http_v2_parse_authority
fn parse_authority(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, r: &R, value: &[u8]) -> Pseudo {
    if stream.authority.borrow().is_some() {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent duplicate \":authority\" header");
        return Pseudo::Declined;
    }

    *stream.authority.borrow_mut() = Some(value.to_vec());

    let (host, port) = match request_rt::validate_host(value, false) {
        Ok(v) => v,
        Err(()) => {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent invalid \":authority\" header");
            return Pseudo::Declined;
        }
    };

    if request_rt::set_virtual_server(r, &host) == NGX_ERROR {
        // ngx_http_set_virtual_server finalized the request (421)
        let pending = request_rt::take_pending_finalize();
        finalize(h2c, stream, if pending != 0 { pending } else { NGX_HTTP_INTERNAL_SERVER_ERROR });
        return Pseudo::Abort;
    }

    r.headers_in.borrow_mut().server = host;
    r.port.set(port);

    Pseudo::Ok
}

/// ngx_http_v2_construct_request_line
fn construct_request_line(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, r: &R) -> Result<(), ()> {
    if !r.request_line.borrow().is_empty() {
        return Ok(());
    }

    let (method, schema, uri) = (r.method_name.borrow().clone(), r.schema.borrow().clone(), r.unparsed_uri.borrow().clone());

    if method.is_empty() || schema.is_empty() || uri.is_empty() {
        if method.is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no :method header");
        } else if schema.is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no :scheme header");
        } else {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no :path header");
        }

        finalize(h2c, stream, NGX_HTTP_BAD_REQUEST);
        return Err(());
    }

    let mut line = method;
    line.push(b' ');
    line.extend_from_slice(&uri);
    line.extend_from_slice(b" HTTP/2.0");

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http2 request line: \"{}\"", B(&line));

    *r.request_line.borrow_mut() = line;

    Ok(())
}

/// ngx_http_v2_construct_cookie_header: join the cookie fields with "; ".
fn construct_cookie_header(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, r: &R) -> Result<(), ()> {
    let cookies = std::mem::take(&mut *stream.cookies.borrow_mut());

    if cookies.is_empty() {
        return Ok(());
    }

    let value = cookies.join(&b"; "[..]);

    process_header_line(h2c, stream, r, b"cookie", &value)
}

/// ngx_http_v2_construct_host_header: Host from :authority, for $http_host.
fn construct_host_header(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, r: &R, host: &[u8]) -> Result<(), ()> {
    process_header_line(h2c, stream, r, b"host", host)
}

// ---------------------------------------------------------------------------
// running the request

/// ngx_http_v2_run_request, called when the header block is complete: the
/// request runs in its own task, which the driver lets run to its first
/// wait before parsing on (as C runs it inline).
pub fn run_request(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>) {
    let r = match stream.request.borrow().clone() {
        Some(r) => r,
        None => return,
    };

    // cancel the incomplete-header timer, if armed
    if let Some(t) = stream.task.borrow_mut().take() {
        t.abort();
    }

    let s = stream.clone();
    let h2c2 = h2c.clone();
    spawn_stream_task(h2c, stream, async move {
        let rc = run_request_checks(&h2c2, &s, &r);
        match rc {
            Checked::Ok => {
                let payload = h2c2.payload_bytes.get();
                h2c2.payload_bytes.set(payload + r.request_length.get());
                let _ = request_rt::process_request(&r).await;
            }
            Checked::Finalize(status) => {
                request_rt::finalize_request(&r, status).await;
            }
            Checked::Done => {}
        }
    });
}

enum Checked {
    Ok,
    Finalize(i64),
    /// the stream is closed already
    Done,
}

/// The checks of ngx_http_v2_run_request before ngx_http_process_request.
fn run_request_checks(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, r: &R) -> Checked {
    let fc = &stream.fc;

    let h2scf = srv_conf(r);

    if !h2scf.enable && !r.http_connection.addr_conf.http2 {
        ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client attempted to request the server name for which the negotiated protocol is disabled");
        return Checked::Finalize(NGX_HTTP_MISDIRECTED_REQUEST);
    }

    if construct_request_line_checked(r).is_err() {
        return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
    }

    if construct_cookie_header(h2c, stream, r).is_err() {
        return Checked::Done;
    }

    r.http_state.set(HttpState::ProcessRequest);

    {
        let hin = r.headers_in.borrow();

        if !hin.connection.is_empty() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent \"Connection\" header");
            return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
        }

        if !hin.keep_alive.is_empty() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent \"Keep-Alive\" header");
            return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
        }

        if hin.transfer_encoding.is_some() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent \"Transfer-Encoding\" header");
            return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
        }

        if !hin.upgrade.is_empty() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent \"Upgrade\" header");
            return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
        }

        if !hin.te.is_empty() && (hin.te.len() > 1 || !hin.te[0].value.borrow().eq_ignore_ascii_case(b"trailers")) {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent invalid \"TE\" header");
            return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
        }

        if hin.server.is_empty() {
            drop(hin);
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent neither \":authority\" nor \"Host\" header");
            return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
        }
    }

    let authority = stream.authority.borrow().clone();

    if let Some(host) = authority {
        let host_header = r.headers_in.borrow().host.as_ref().map(|h| h.value.borrow().clone());

        match host_header {
            Some(h) => {
                if h != host {
                    ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent \":authority\" and \"Host\" headers with different values");
                    return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
                }
            }
            None => {
                // compatibility for $http_host
                if construct_host_header(h2c, stream, r, &host).is_err() {
                    return Checked::Done;
                }
            }
        }
    }

    let content_length = r.headers_in.borrow().content_length.as_ref().map(|h| h.value.borrow().clone());

    if let Some(cl) = content_length {
        let n = ngx_core::string::atoof(&cl).unwrap_or(-1);

        r.headers_in.borrow_mut().content_length_n = n;

        if n == -1 {
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent invalid \"Content-Length\" header");
            return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
        }

        if n > 0 && stream.in_closed.get() {
            ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client prematurely closed stream");

            stream.skip_data.set(true);

            return Checked::Finalize(NGX_HTTP_BAD_REQUEST);
        }
    } else if !stream.in_closed.get() {
        r.headers_in.borrow_mut().chunked = true;
    }

    if r.method.get() == NGX_HTTP_CONNECT {
        ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent CONNECT method");
        return Checked::Finalize(NGX_HTTP_NOT_ALLOWED);
    }

    if r.method.get() == NGX_HTTP_TRACE {
        ngx_log_error!(NGX_LOG_INFO, fc.log, None, "client sent TRACE method");
        return Checked::Finalize(NGX_HTTP_NOT_ALLOWED);
    }

    Checked::Ok
}

/// construct_request_line without finalizing (run_request finalizes).
fn construct_request_line_checked(r: &R) -> Result<(), ()> {
    if !r.request_line.borrow().is_empty() {
        return Ok(());
    }

    let (method, schema, uri) = (r.method_name.borrow().clone(), r.schema.borrow().clone(), r.unparsed_uri.borrow().clone());

    if method.is_empty() || schema.is_empty() || uri.is_empty() {
        if method.is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no :method header");
        } else if schema.is_empty() {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no :scheme header");
        } else {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent no :path header");
        }
        return Err(());
    }

    let mut line = method;
    line.push(b' ');
    line.extend_from_slice(&uri);
    line.extend_from_slice(b" HTTP/2.0");

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http2 request line: \"{}\"", B(&line));

    *r.request_line.borrow_mut() = line;

    Ok(())
}

/// Finalize a request while its header block is being parsed (C calls
/// ngx_http_finalize_request inline): the stream task does it.
fn finalize(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, status: i64) {
    let r = match stream.request.borrow().clone() {
        Some(r) => r,
        None => return,
    };

    if stream.task.borrow().is_some() && !stream.request_done.get() {
        // a request task is already running (or the header timer): let
        // the task finalize
        if let Some(t) = stream.task.borrow_mut().take() {
            t.abort();
        }
    }

    spawn_stream_task(h2c, stream, async move {
        request_rt::finalize_request(&r, status).await;
    });
}

/// Spawn the stream's request task. When the request returns, the stream
/// closes once its queued frames are out (ngx_http_v2_close_stream).
fn spawn_stream_task<F>(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, fut: F)
where
    F: std::future::Future<Output = ()> + 'static,
{
    let s = stream.clone();
    let handle = ngx_core::event::spawn(async move {
        fut.await;
        s.request_done.set(true);
        close_stream_when_sent(&s, 0).await;
    });

    *stream.task.borrow_mut() = Some(handle);

    h2c.posted.borrow_mut().push_back(Posted::Run);
}

/// ngx_http_v2_close_stream + the retry handler: wait for the stream's
/// queued frames to go out, then close it.
async fn close_stream_when_sent(stream: &Rc<H2Stream>, rc: i64) {
    loop {
        if stream.closed.get() {
            return;
        }

        if stream.queued.get() == 0 || stream.connection.finalized.get() && stream.connection.last_out.borrow().is_empty() {
            break;
        }

        stream.fc.error.set(true);
        stream.notify.notified().await;
    }

    stream.task.borrow_mut().take();
    close_stream(stream, rc);
}

/// ngx_http_v2_close_stream, once no frames are queued: reset the stream
/// if needed, free the request, and keep the node in the tree as closed.
pub fn close_stream(stream: &Rc<H2Stream>, rc: i64) {
    if stream.closed.get() {
        return;
    }

    let h2c = stream.connection.clone();
    let node = stream.node.borrow().clone();

    ngx_log_debug!(
        NGX_LOG_DEBUG_HTTP,
        h2c.connection.log,
        "http2 close stream {}, queued {}, processing {}",
        node.id.get(),
        stream.queued.get(),
        h2c.processing.get()
    );

    stream.closed.set(true);

    let fc = &stream.fc;

    if !stream.rst_sent.get() && !h2c.connection.error.get() {
        if !stream.out_closed.get() {
            let status = if fc.timedout.get() { NGX_HTTP_V2_PROTOCOL_ERROR } else { NGX_HTTP_V2_INTERNAL_ERROR };
            if send_rst_stream(&h2c, node.id.get(), status).is_err() {
                h2c.connection.error.set(true);
            }
        } else if !stream.in_closed.get() {
            if send_rst_stream(&h2c, node.id.get(), NGX_HTTP_V2_NO_ERROR).is_err() {
                h2c.connection.error.set(true);
            }
        }
    }

    {
        let mut st = h2c.state.stream.borrow_mut();
        if st.as_ref().map(|s| Rc::ptr_eq(s, stream)).unwrap_or(false) {
            *st = None;
        }
    }

    *node.stream.borrow_mut() = None;

    h2c.closed.borrow_mut().push_back(node);
    h2c.closed_nodes.set(h2c.closed_nodes.get() + 1);

    h2c.frames.set(h2c.frames.get().saturating_sub(stream.frames.get()));

    if let Some(r) = stream.request.borrow_mut().take() {
        request_rt::free_request(&r, rc);
        super::filter::filter_cleanup(stream);
        *r.stream.borrow_mut() = None;
    }

    h2c.processing.set(h2c.processing.get() - 1);

    if h2c.processing.get() > 0 || h2c.blocked.get() {
        return;
    }

    // ngx_http_v2_handle_connection_handler
    h2c.out_notify.notify_one();
}

/// End a stream's request now: the fake connection's read handler after
/// fc->error was set (RST_STREAM, ngx_http_v2_terminate_stream, connection
/// teardown) finalizes it as 499 (ngx_http_test_reading and friends).
fn terminate_request_now(stream: &Rc<H2Stream>, rc: i64) {
    if stream.closed.get() {
        return;
    }

    if stream.request_done.get() {
        // already closing: wake it up to notice fc->error / queued
        stream.notify.notify_one();
        return;
    }

    let task = stream.task.borrow_mut().take();
    if let Some(t) = task {
        t.abort();
    }

    let r = match stream.request.borrow().clone() {
        Some(r) => r,
        None => return,
    };

    stream.request_done.set(true);

    request_rt::terminate_request(&r, rc);

    if stream.queued.get() == 0 {
        close_stream(stream, rc);
        return;
    }

    let s = stream.clone();
    let handle = ngx_core::event::spawn(async move {
        close_stream_when_sent(&s, rc).await;
    });
    *stream.task.borrow_mut() = Some(handle);
}

/// The fake connection's read handler after RST_STREAM.
pub fn stream_rst_received(_h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>) {
    if stream.task.borrow().is_none() && !stream.request_done.get() {
        // no request yet (header block incomplete):
        // ngx_http_v2_close_stream_handler
        close_stream(stream, 0);
        return;
    }

    terminate_request_now(stream, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}

/// ngx_http_v2_terminate_stream
pub fn terminate_stream(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>, status: u32) -> Result<(), ()> {
    if stream.rst_sent.get() {
        return Ok(());
    }

    send_rst_stream(h2c, stream.node.borrow().id.get(), status)?;

    stream.rst_sent.set(true);
    stream.skip_data.set(true);

    stream.fc.error.set(true);

    stream_rst_received(h2c, stream);

    Ok(())
}

/// The stream part of ngx_http_v2_finalize_connection: every stream's
/// request ends with fc->error set; queued output is dropped.
pub fn finalize_streams(h2c: &Rc<H2Connection>) {
    let nodes: Vec<Rc<H2Node>> = h2c.streams_index.borrow().iter().flat_map(|b| b.iter().cloned()).collect();

    for node in nodes {
        let stream = match node.stream.borrow().clone() {
            Some(s) => s,
            None => continue,
        };

        stream.waiting.set(false);

        stream.fc.error.set(true);

        // the write handler ends a request with queued output (NGX_ERROR),
        // the read handler one without (ngx_http_test_reading: 499)
        let rc = if stream.queued.get() > 0 {
            stream.queued.set(0);
            NGX_ERROR
        } else {
            NGX_HTTP_CLIENT_CLOSED_REQUEST
        };

        if !stream.request_done.get() && stream.task.borrow().is_some() && stream.request.borrow().is_some() {
            terminate_request_now(&stream, rc);
        } else {
            if let Some(t) = stream.task.borrow_mut().take() {
                t.abort();
            }
            close_stream(&stream, 0);
        }
    }
}

/// ngx_http_v2_adjust_windows (SETTINGS_INITIAL_WINDOW_SIZE changed)
pub fn adjust_windows(h2c: &Rc<H2Connection>, delta: isize) -> Result<(), ()> {
    let nodes: Vec<Rc<H2Node>> = h2c.streams_index.borrow().iter().flat_map(|b| b.iter().cloned()).collect();

    for node in nodes {
        let stream = match node.stream.borrow().clone() {
            Some(s) => s,
            None => continue,
        };

        if delta > 0 && stream.send_window.get() > NGX_HTTP_V2_MAX_WINDOW as isize - delta {
            terminate_stream(h2c, &stream, NGX_HTTP_V2_FLOW_CTRL_ERROR)?;
            continue;
        }

        stream.send_window.set(stream.send_window.get() + delta);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, h2c.connection.log, "http2:{} adjusted window: {}", node.id.get(), stream.send_window.get());

        if stream.send_window.get() > 0 && stream.exhausted.get() {
            stream.exhausted.set(false);
            post_write(h2c, &stream);
        }
    }

    Ok(())
}

/// Post the stream's write event (wev->handler(wev) in C).
pub fn post_write(h2c: &Rc<H2Connection>, stream: &Rc<H2Stream>) {
    h2c.posted.borrow_mut().push_back(Posted::Write(stream.clone()));
}

/// Post the drain of the waiting queue after a connection WINDOW_UPDATE.
pub fn post_drain_waiting(h2c: &Rc<H2Connection>) {
    h2c.posted.borrow_mut().push_back(Posted::DrainWaiting);
}

/// Run the effects the last frame posted, in order, letting each woken
/// stream task run (and queue its output) before the next.
pub async fn run_posted(h2c: &Rc<H2Connection>) {
    loop {
        let ev = h2c.posted.borrow_mut().pop_front();

        match ev {
            None => return,

            Some(Posted::Run) => tokio::task::yield_now().await,

            Some(Posted::Write(stream)) => {
                if !stream.closed.get() {
                    stream.notify.notify_one();
                    tokio::task::yield_now().await;
                }
            }

            Some(Posted::DrainWaiting) => loop {
                let stream = match h2c.waiting.borrow_mut().pop_front() {
                    Some(s) => s,
                    None => break,
                };

                stream.waiting.set(false);

                stream.notify.notify_one();
                tokio::task::yield_now().await;

                if h2c.send_window.get() == 0 {
                    break;
                }
            },
        }
    }
}

#[allow(dead_code)]
fn _core_srv(_: &CoreSrvConf) {}
