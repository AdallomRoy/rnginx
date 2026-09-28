//! ngx_stream_core_module.c: the server{} blocks, listen, the phase
//! checkers.

use std::any::Any;
use std::cell::RefCell;
use std::rc::{Rc, Weak};
use std::time::Duration;

use ngx_core::conf::*;
use ngx_core::hash::*;
use ngx_core::inet::{parse_url, Url};
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::resolver::Resolver;
use ngx_core::string::{eq_ignore_case, B};
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

use crate::handler::finalize_session;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_core_module");

/// ngx_stream_core_main_conf_t
pub struct CoreMainConf {
    pub servers: Vec<Rc<RefCell<CoreSrvConf>>>,

    pub phase_engine: Rc<Vec<PhaseHandler>>,

    pub variables_hash: Option<Hash<Rc<Variable>>>,

    pub variables: Vec<Rc<Variable>>,
    pub prefix_variables: Vec<Rc<Variable>>,
    pub ncaptures: usize,

    pub server_names_hash_max_size: Val<i64>,
    pub server_names_hash_bucket_size: Val<i64>,

    pub variables_hash_max_size: Val<i64>,
    pub variables_hash_bucket_size: Val<i64>,

    pub variables_keys: Option<HashKeysArrays<Rc<Variable>>>,

    pub ports: Vec<ConfPort>,

    pub phases: [Vec<PhaseFn>; NGX_STREAM_LOG_PHASE + 1],
}

/// ngx_stream_core_srv_conf_t
pub struct CoreSrvConf {
    pub server_names: Vec<ServerName>,

    pub handler: Option<ContentHandler>,

    pub ctx: ConfCtx,

    pub file_name: Vec<u8>,
    pub line: usize,

    pub server_name: Vec<u8>,

    pub tcp_nodelay: Val<bool>,
    pub preread_buffer_size: Val<usize>,
    pub preread_timeout: Val<u64>,

    pub error_log: Option<Rc<LogChain>>,

    pub resolver_timeout: Val<u64>,
    pub resolver: Option<Rc<Resolver>>,

    pub proxy_protocol_timeout: Val<u64>,

    pub listen: bool,
    pub captures: bool,

    pub me: Weak<RefCell<CoreSrvConf>>,
}

pub fn main_conf_from_ctx(ctx: &ConfCtx) -> Rc<RefCell<CoreMainConf>> {
    get_conf::<CoreMainConf>(ctx, ConfLevel::Main, ctx_index())
}

pub fn srv_conf_from_ctx(ctx: &ConfCtx) -> Rc<RefCell<CoreSrvConf>> {
    get_conf::<CoreSrvConf>(ctx, ConfLevel::Srv, ctx_index())
}

/// ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module)
pub fn core_main_conf(cf: &Conf) -> Rc<RefCell<CoreMainConf>> {
    get_main_conf::<CoreMainConf>(cf, ctx_index())
}

/// ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module)
pub fn core_srv_conf(cf: &Conf) -> Rc<RefCell<CoreSrvConf>> {
    get_srv_conf::<CoreSrvConf>(cf, ctx_index())
}

fn cscf_of(conf: &Option<Rc<dyn Any>>) -> Rc<RefCell<CoreSrvConf>> {
    conf_rc::<CoreSrvConf>(conf.as_ref().expect("srv conf"))
}

/// Add a handler to a phase (the array push of the modules'
/// postconfiguration).
pub fn add_phase_handler(cf: &Conf, phase: usize, h: PhaseFn) {
    let cmcf = core_main_conf(cf);
    cmcf.borrow_mut().phases[phase].push(h);
}

// --- the phase engine ---

/// ngx_stream_core_run_phases
pub async fn run_phases(s: &S) {
    let ph = s.cmcf().borrow().phase_engine.clone();

    loop {
        let i = s.phase_handler.get();

        let h = match ph.get(i) {
            Some(h) => h,
            None => return,
        };

        let rc = match h.checker {
            Checker::Generic => generic_phase(s, h).await,
            Checker::Preread => preread_phase(s, h).await,
            Checker::Content => content_phase(s, h).await,
        };

        if rc == NGX_OK {
            return;
        }
    }
}

/// ngx_stream_core_generic_phase: the generic phase checker, used by all
/// phases, except for preread and content
async fn generic_phase(s: &S, ph: &PhaseHandler) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "generic phase: {}", s.phase_handler.get());

    let handler = ph.handler.clone().expect("phase handler");

    let rc = handler(s.clone()).await;

    if rc == NGX_OK {
        s.phase_handler.set(ph.next);
        return NGX_AGAIN;
    }

    if rc == NGX_DECLINED {
        s.phase_handler.set(s.phase_handler.get() + 1);
        return NGX_AGAIN;
    }

    if rc == NGX_AGAIN || rc == NGX_DONE {
        return NGX_OK;
    }

    let rc = if rc == NGX_ERROR { NGX_STREAM_INTERNAL_SERVER_ERROR } else { rc };

    finalize_session(s, rc).await;

    NGX_OK
}

/// ngx_stream_core_preread_phase
async fn preread_phase(s: &S, ph: &PhaseHandler) -> i64 {
    let c = s.connection.clone();

    c.log.set_action(Some("prereading client data"));

    let cscf = s.cscf();
    let (preread_buffer_size, preread_timeout) = {
        let cscf = cscf.borrow();
        (*cscf.preread_buffer_size, *cscf.preread_timeout)
    };

    let handler = ph.handler.clone().expect("phase handler");

    let rc = 'done: {
        let rc = handler(s.clone()).await;

        if rc != NGX_AGAIN {
            break 'done rc;
        }

        // the preread buffer is c->buffer, preread_buffer_size bytes

        let deadline = tokio::time::Instant::now() + Duration::from_millis(preread_timeout);

        let work = async {
            if preread_can_peek(&c) {
                preread_peek(s, &handler, preread_buffer_size).await
            } else {
                preread(s, &handler, preread_buffer_size).await
            }
        };

        tokio::select! {
            rc = work => rc,
            _ = tokio::time::sleep_until(deadline) => {
                // c->read->timedout
                NGX_STREAM_OK
            }
            _ = c.close_notify.notified() => NGX_STREAM_OK,
        }
    };

    if rc == NGX_OK {
        s.phase_handler.set(ph.next);
        return NGX_AGAIN;
    }

    if rc == NGX_DECLINED {
        s.phase_handler.set(s.phase_handler.get() + 1);
        return NGX_AGAIN;
    }

    if rc == NGX_DONE {
        return NGX_OK;
    }

    let rc = if rc == NGX_ERROR { NGX_STREAM_INTERNAL_SERVER_ERROR } else { rc };

    finalize_session(s, rc).await;

    NGX_OK
}

/// ngx_stream_preread_can_peek: epoll with EPOLLRDHUP, unless SSL
fn preread_can_peek(c: &ngx_core::connection::Connection) -> bool {
    c.ssl.borrow().is_none()
}

/// ngx_stream_preread_peek
async fn preread_peek(s: &S, handler: &PhaseFn, size: usize) -> i64 {
    let c = s.connection.clone();

    let mut buf = vec![0u8; size];
    let mut have = 0;

    loop {
        let (n, pending_eof) = match c.peek_more(&mut buf, have).await {
            Ok(r) => r,
            Err(e) => {
                c.connection_error(e.raw_os_error().unwrap_or(0), "recv() failed");
                return NGX_STREAM_OK;
            }
        };

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream recv(): {}", n);

        if n == 0 {
            return NGX_STREAM_OK;
        }

        have = n;

        *c.buffer.borrow_mut() = buf[..n].to_vec();

        let rc = handler(s.clone()).await;

        if rc != NGX_AGAIN {
            c.buffer.borrow_mut().clear();
            return rc;
        }

        if n == size {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "preread buffer full");
            return NGX_STREAM_BAD_REQUEST;
        }

        if pending_eof {
            return NGX_STREAM_OK;
        }

        c.buffer.borrow_mut().clear();
    }
}

/// ngx_stream_preread
async fn preread(s: &S, handler: &PhaseFn, size: usize) -> i64 {
    let c = s.connection.clone();

    loop {
        let len = c.buffer.borrow().len();

        let mut buf = vec![0u8; size - len];

        let n = match c.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => return NGX_STREAM_OK,
        };

        if n == 0 {
            return NGX_STREAM_OK;
        }

        c.buffer.borrow_mut().extend_from_slice(&buf[..n]);

        let rc = handler(s.clone()).await;

        if rc != NGX_AGAIN {
            return rc;
        }

        if c.buffer.borrow().len() == size {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "preread buffer full");
            return NGX_STREAM_BAD_REQUEST;
        }
    }
}

/// ngx_stream_core_content_phase
async fn content_phase(s: &S, _ph: &PhaseHandler) -> i64 {
    let c = s.connection.clone();

    c.log.set_action(None);

    let cscf = s.cscf();
    let (tcp_nodelay, handler) = {
        let cscf = cscf.borrow();
        (*cscf.tcp_nodelay, cscf.handler.clone())
    };

    if c.ty == libc::SOCK_STREAM && tcp_nodelay && !c.set_tcp_nodelay() {
        finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return NGX_OK;
    }

    let handler = match handler {
        Some(h) => h,
        None => {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "no handler for server");
            finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
            return NGX_OK;
        }
    };

    handler(s.clone()).await;

    NGX_OK
}

/// ngx_stream_validate_host: the host is valid (and lowercased if needed)
/// or NGX_DECLINED
pub fn validate_host(host: &[u8]) -> Result<Vec<u8>, i64> {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum State {
        HostStart,
        Host,
        HostIpLiteral,
        HostEnd,
        Port,
    }

    let mut dot_pos = host.len();
    let mut host_len = host.len();
    let mut port: u32 = 0;
    let mut alloc = false;

    let mut state = State::HostStart;

    for (i, &ch) in host.iter().enumerate() {
        match state {
            State::HostStart | State::Host => {
                if state == State::HostStart {
                    if ch == b'[' {
                        state = State::HostIpLiteral;
                        continue;
                    }

                    state = State::Host;
                }

                if ch.is_ascii_uppercase() {
                    alloc = true;
                    continue;
                }

                if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                    continue;
                }

                match ch {
                    b':' => {
                        host_len = i;
                        state = State::Port;
                    }
                    b'-' => {}
                    b'.' => {
                        if dot_pos == i.wrapping_sub(1) {
                            return Err(NGX_DECLINED);
                        }
                        dot_pos = i;
                    }
                    // unreserved
                    b'_' | b'~' => {}
                    // sub-delims
                    b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' => {}
                    // pct-encoded
                    b'%' => {}
                    _ => return Err(NGX_DECLINED),
                }
            }

            State::HostIpLiteral => {
                if ch.is_ascii_uppercase() {
                    alloc = true;
                    continue;
                }

                if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                    continue;
                }

                match ch {
                    b':' => {}
                    b']' => {
                        host_len = i + 1;
                        state = State::HostEnd;
                    }
                    b'-' => {}
                    b'.' => {
                        if dot_pos == i.wrapping_sub(1) {
                            return Err(NGX_DECLINED);
                        }
                        dot_pos = i;
                    }
                    // unreserved
                    b'_' | b'~' => {}
                    // sub-delims
                    b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' => {}
                    _ => return Err(NGX_DECLINED),
                }
            }

            State::HostEnd => {
                if ch == b':' {
                    state = State::Port;
                    continue;
                }
                return Err(NGX_DECLINED);
            }

            State::Port => {
                if ch.is_ascii_digit() {
                    if port >= 6553 && (port > 6553 || (ch - b'0') > 5) {
                        return Err(NGX_DECLINED);
                    }

                    port = port * 10 + (ch - b'0') as u32;
                    continue;
                }
                return Err(NGX_DECLINED);
            }
        }
    }

    if state == State::HostIpLiteral {
        return Err(NGX_DECLINED);
    }

    if host_len > 0 && dot_pos == host_len - 1 {
        host_len -= 1;
    }

    if host_len == 0 {
        return Err(NGX_DECLINED);
    }

    if alloc {
        return Ok(ngx_core::string::to_lower_vec(&host[..host_len]));
    }

    Ok(host[..host_len].to_vec())
}

/// ngx_stream_find_virtual_server
pub fn find_virtual_server(s: &S, host: &[u8]) -> Result<Rc<RefCell<CoreSrvConf>>, i64> {
    let vn = match &s.virtual_names {
        None => return Err(NGX_DECLINED),
        Some(vn) => vn.clone(),
    };

    if let Some(cscf) = vn.names.find(hash_key(host), host) {
        return Ok(cscf.clone());
    }

    if !host.is_empty() && !vn.regex.is_empty() {
        for sn in vn.regex.iter() {
            let n = regex_exec(s, sn.regex.as_ref().unwrap(), host);

            if n == NGX_DECLINED {
                continue;
            }

            if n == NGX_OK {
                return Ok(sn.server.clone());
            }

            return Err(NGX_ERROR);
        }
    }

    Err(NGX_DECLINED)
}

// --- configuration ---

/// ngx_stream_core_preconfiguration
fn core_preconfiguration(cf: &mut Conf) -> ConfResult {
    add_core_vars(cf)
}

/// ngx_stream_core_create_main_conf
fn core_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CoreMainConf {
        servers: Vec::new(),
        phase_engine: Rc::new(Vec::new()),
        variables_hash: None,
        variables: Vec::new(),
        prefix_variables: Vec::new(),
        ncaptures: 0,
        server_names_hash_max_size: Val::unset(),
        server_names_hash_bucket_size: Val::unset(),
        variables_hash_max_size: Val::unset(),
        variables_hash_bucket_size: Val::unset(),
        variables_keys: None,
        ports: Vec::new(),
        phases: Default::default(),
    })
}

/// ngx_stream_core_init_main_conf
fn core_init_main_conf(_cf: &mut Conf, conf: &Rc<dyn Any>) -> ConfResult {
    let c = conf_cell::<CoreMainConf>(conf);
    let mut cmcf = c.borrow_mut();

    let cl = ngx_core::os::cacheline_size() as i64;
    let align = |v: i64| (v + cl - 1) / cl * cl;

    cmcf.server_names_hash_max_size.init(512);
    cmcf.server_names_hash_bucket_size.init(cl);

    let v = *cmcf.server_names_hash_bucket_size;
    cmcf.server_names_hash_bucket_size = Val::set(align(v));

    cmcf.variables_hash_max_size.init(1024);
    cmcf.variables_hash_bucket_size.init(64);

    let v = *cmcf.variables_hash_bucket_size;
    cmcf.variables_hash_bucket_size = Val::set(align(v));

    if cmcf.ncaptures != 0 {
        cmcf.ncaptures = (cmcf.ncaptures + 1) * 3;
    }

    Ok(())
}

/// ngx_stream_core_create_srv_conf
fn core_create_srv_conf(cf: &mut Conf) -> Rc<dyn Any> {
    let cscf = Rc::new(RefCell::new(CoreSrvConf {
        server_names: Vec::new(),
        handler: None,
        ctx: ConfCtx::default(),
        file_name: cf.conf_file_name(),
        line: cf.conf_line(),
        server_name: Vec::new(),
        tcp_nodelay: Val::unset(),
        preread_buffer_size: Val::unset(),
        preread_timeout: Val::unset(),
        error_log: None,
        resolver_timeout: Val::unset(),
        resolver: None,
        proxy_protocol_timeout: Val::unset(),
        listen: false,
        captures: false,
        me: Weak::new(),
    }));
    cscf.borrow_mut().me = Rc::downgrade(&cscf);
    cscf
}

/// ngx_stream_core_merge_srv_conf
fn core_merge_srv_conf(cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let pcell = conf_cell::<CoreSrvConf>(parent);
    let cell = conf_cell::<CoreSrvConf>(child);

    let same = std::ptr::eq(pcell, cell);

    {
        let prev_timeout = pcell.borrow().resolver_timeout;
        cell.borrow_mut().resolver_timeout.merge(&prev_timeout, 30000);
    }

    if cell.borrow().resolver.is_none() {
        if pcell.borrow().resolver.is_none() {
            // create dummy resolver in stream {} context
            // to inherit it in all servers

            let r = Resolver::create(cf, &[])?;
            pcell.borrow_mut().resolver = Some(r);
        }

        let r = pcell.borrow().resolver.clone();
        cell.borrow_mut().resolver = r;
    }

    if !same {
        let prev = pcell.borrow();
        let mut conf = cell.borrow_mut();

        if conf.error_log.is_none() {
            conf.error_log = Some(prev.error_log.clone().unwrap_or_else(|| cf.cycle.new_log.clone()));
        }

        conf.proxy_protocol_timeout.merge(&prev.proxy_protocol_timeout, 30000);

        conf.tcp_nodelay.merge(&prev.tcp_nodelay, true);

        conf.preread_buffer_size.merge(&prev.preread_buffer_size, 16384);

        conf.preread_timeout.merge(&prev.preread_timeout, 30000);
    }

    let mut conf = cell.borrow_mut();

    if conf.server_names.is_empty() {
        let me = conf.me.upgrade().unwrap();
        conf.server_names.push(ServerName { regex: None, server: me, name: Vec::new() });
    }

    let sn = &conf.server_names[0];
    let mut name = sn.name.clone();

    if sn.regex.is_some() {
        name.insert(0, b'~');
    } else if name.first() == Some(&b'.') {
        name.remove(0);
    }

    conf.server_name = name;

    Ok(())
}

/// ngx_stream_core_error_log
fn core_error_log(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cscf = cscf_of(&conf);

    let chain = {
        let mut c = cscf.borrow_mut();
        if c.error_log.is_none() {
            c.error_log = Some(LogChain::new());
        }
        c.error_log.clone().unwrap()
    };

    ngx_core::core_module::log_set_log(cf, &chain)
}

/// ngx_stream_core_server
fn core_server(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let n = stream_max_module();

    let stream_ctx = cf.ctx.clone();
    let ctx = ConfCtx { main: stream_ctx.main.clone(), srv: Some(new_slots(n)), loc: None };

    // the server{}'s srv_conf

    let modules = cf.cycle.modules.clone();

    for m in modules.iter().filter(|m| m.def.ty == NGX_STREAM_MODULE) {
        if let Some(d) = m.ctx::<StreamModuleDef>() {
            if let Some(f) = d.create_srv_conf {
                let c = f(cf);
                ctx.srv.as_ref().unwrap().borrow_mut()[m.ctx_index] = Some(c);
            }
        }
    }

    // the server configuration context

    let cscf = srv_conf_from_ctx(&ctx);
    cscf.borrow_mut().ctx = ctx.clone();

    let cmcf = main_conf_from_ctx(&ctx);
    cmcf.borrow_mut().servers.push(cscf.clone());

    // parse inside server{}

    let saved_ctx = std::mem::replace(&mut cf.ctx, ctx);
    let saved_ct = cf.cmd_type;
    cf.cmd_type = NGX_STREAM_SRV_CONF;

    let rv = cf.parse_block();

    cf.ctx = saved_ctx;
    cf.cmd_type = saved_ct;

    rv?;

    let c = cscf.borrow();

    if !c.listen {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "no \"listen\" is defined for server in {}:{}", B(&c.file_name), c.line);
        return Err(ConfError::Logged);
    }

    Ok(())
}

/// ngx_stream_core_listen
fn core_listen(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cscf = cscf_of(&conf);

    cscf.borrow_mut().listen = true;

    let value = cf.args.clone();

    let mut u = Url::new(&value[1]);
    u.listen = true;

    if parse_url(&mut u).is_err() {
        if let Some(e) = u.err {
            return Err(cf.emerg(format_args!("{} in \"{}\" of the \"listen\" directive", e, B(&u.url))));
        }

        return Err(ConfError::Logged);
    }

    let mut lsopt = ListenOpt {
        sockaddr: ngx_core::inet::SockAddr::v4(std::net::Ipv4Addr::UNSPECIFIED, 0),
        addr_text: Vec::new(),
        set: false,
        default_server: false,
        bind: false,
        wildcard: false,
        ssl: false,
        ipv6only: true,
        deferred_accept: false,
        reuseport: false,
        so_keepalive: 0,
        proxy_protocol: false,
        backlog: NGX_LISTEN_BACKLOG,
        rcvbuf: -1,
        sndbuf: -1,
        ty: libc::SOCK_STREAM,
        protocol: 0,
        fastopen: -1,
        tcp_keepidle: 0,
        tcp_keepintvl: 0,
        tcp_keepcnt: 0,
    };

    let mut backlog = false;

    for v in &value[2..] {
        let s: &[u8] = v;

        if s == b"default_server" {
            lsopt.default_server = true;
            continue;
        }

        if s == b"udp" {
            lsopt.ty = libc::SOCK_DGRAM;
            continue;
        }

        if s == b"bind" {
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }

        if let Some(rest) = s.strip_prefix(b"fastopen=") {
            match ngx_core::string::atoi(rest) {
                Some(n) => lsopt.fastopen = n as i32,
                None => return Err(cf.emerg(format_args!("invalid fastopen \"{}\"", B(s)))),
            }

            lsopt.set = true;
            lsopt.bind = true;

            continue;
        }

        if let Some(rest) = s.strip_prefix(b"backlog=") {
            match ngx_core::string::atoi(rest) {
                Some(n) if n != 0 => lsopt.backlog = n as i32,
                _ => return Err(cf.emerg(format_args!("invalid backlog \"{}\"", B(s)))),
            }

            lsopt.set = true;
            lsopt.bind = true;

            backlog = true;

            continue;
        }

        if let Some(rest) = s.strip_prefix(b"rcvbuf=") {
            match ngx_core::parse::parse_size(rest) {
                Some(n) => lsopt.rcvbuf = n as i32,
                None => return Err(cf.emerg(format_args!("invalid rcvbuf \"{}\"", B(s)))),
            }

            lsopt.set = true;
            lsopt.bind = true;

            continue;
        }

        if let Some(rest) = s.strip_prefix(b"sndbuf=") {
            match ngx_core::parse::parse_size(rest) {
                Some(n) => lsopt.sndbuf = n as i32,
                None => return Err(cf.emerg(format_args!("invalid sndbuf \"{}\"", B(s)))),
            }

            lsopt.set = true;
            lsopt.bind = true;

            continue;
        }

        if s.starts_with(b"accept_filter=") {
            cf.log_error(NGX_LOG_EMERG, None, format_args!("accept filters \"{}\" are not supported on this platform, ignored", B(s)));
            continue;
        }

        if s == b"deferred" {
            lsopt.deferred_accept = true;
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }

        if let Some(rest) = s.strip_prefix(b"ipv6only=o") {
            if rest == b"n" {
                lsopt.ipv6only = true;
            } else if rest == b"ff" {
                lsopt.ipv6only = false;
            } else {
                return Err(cf.emerg(format_args!("invalid ipv6only flags \"{}\"", B(&s[9..]))));
            }

            lsopt.set = true;
            lsopt.bind = true;

            continue;
        }

        if s == b"reuseport" {
            lsopt.reuseport = true;
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }

        if s == b"multipath" {
            lsopt.protocol = libc::IPPROTO_MPTCP;
            lsopt.set = true;
            lsopt.bind = true;
            continue;
        }

        if s == b"ssl" {
            lsopt.ssl = true;
            continue;
        }

        if let Some(rest) = s.strip_prefix(b"so_keepalive=") {
            if rest == b"on" {
                lsopt.so_keepalive = 1;
            } else if rest == b"off" {
                lsopt.so_keepalive = 2;
            } else {
                let invalid = |cf: &Conf| cf.emerg(format_args!("invalid so_keepalive value: \"{}\"", B(rest)));

                let end = rest.len();

                let p = memchr_pos(rest, 0, b':').unwrap_or(end);

                if p > 0 {
                    match ngx_core::parse::parse_time(&rest[..p], true) {
                        Some(t) => lsopt.tcp_keepidle = t as i32,
                        None => return Err(invalid(cf)),
                    }
                }

                let start = if p < end { p + 1 } else { end };

                let p = memchr_pos(rest, start, b':').unwrap_or(end);

                if p > start {
                    match ngx_core::parse::parse_time(&rest[start..p], true) {
                        Some(t) => lsopt.tcp_keepintvl = t as i32,
                        None => return Err(invalid(cf)),
                    }
                }

                let start = if p < end { p + 1 } else { end };

                if start < end {
                    match ngx_core::string::atoi(&rest[start..]) {
                        Some(n) => lsopt.tcp_keepcnt = n as i32,
                        None => return Err(invalid(cf)),
                    }
                }

                if lsopt.tcp_keepidle == 0 && lsopt.tcp_keepintvl == 0 && lsopt.tcp_keepcnt == 0 {
                    return Err(invalid(cf));
                }

                lsopt.so_keepalive = 1;
            }

            lsopt.set = true;
            lsopt.bind = true;

            continue;
        }

        if s == b"proxy_protocol" {
            lsopt.proxy_protocol = true;
            continue;
        }

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(s))));
    }

    if lsopt.ty == libc::SOCK_DGRAM {
        if lsopt.fastopen != -1 {
            return Err(msg("\"fastopen\" parameter is incompatible with \"udp\""));
        }

        if backlog {
            return Err(msg("\"backlog\" parameter is incompatible with \"udp\""));
        }

        if lsopt.deferred_accept {
            return Err(msg("\"deferred\" parameter is incompatible with \"udp\""));
        }

        if lsopt.protocol == libc::IPPROTO_MPTCP {
            return Err(msg("\"multipath\" parameter is incompatible with \"udp\""));
        }

        if lsopt.ssl {
            return Err(msg("\"ssl\" parameter is incompatible with \"udp\""));
        }

        if lsopt.so_keepalive != 0 {
            return Err(msg("\"so_keepalive\" parameter is incompatible with \"udp\""));
        }

        if lsopt.proxy_protocol {
            return Err(msg("\"proxy_protocol\" parameter is incompatible with \"udp\""));
        }
    }

    for n in 0..u.addrs.len() {
        if (0..n).any(|i| u.addrs[n].sockaddr.cmp(&u.addrs[i].sockaddr, true)) {
            continue;
        }

        lsopt.sockaddr = u.addrs[n].sockaddr.clone();
        lsopt.addr_text = u.addrs[n].name.clone();
        lsopt.wildcard = lsopt.sockaddr.is_wildcard();

        add_listen(cf, &cscf, &lsopt)?;
    }

    Ok(())
}

fn memchr_pos(s: &[u8], from: usize, c: u8) -> Option<usize> {
    s[from..].iter().position(|&x| x == c).map(|p| p + from)
}

/// ngx_stream_core_server_name
fn core_server_name(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cscf = cscf_of(&conf);

    let args = cf.args.clone();

    for v in &args[1..] {
        let ch = v.first().copied().unwrap_or(0);

        if (ch == b'*' && (v.len() < 3 || v[1] != b'.')) || (ch == b'.' && v.len() < 2) {
            return Err(cf.emerg(format_args!("server name \"{}\" is invalid", B(v))));
        }

        if v.contains(&b'/') {
            cf.warn(format_args!("server name \"{}\" has suspicious symbols", B(v)));
        }

        let me = cscf.borrow().me.upgrade().unwrap();

        let mut sn = ServerName { regex: None, server: me, name: if eq_ignore_case(v, b"$hostname") { cf.cycle.hostname.clone() } else { v.clone() } };

        if ch != b'~' {
            sn.name = ngx_core::string::to_lower_vec(&sn.name);
            cscf.borrow_mut().server_names.push(sn);
            continue;
        }

        if v.len() == 1 {
            return Err(cf.emerg(format_args!("empty regex in server name \"{}\"", B(v))));
        }

        let pattern = &v[1..];

        let options = if pattern.iter().any(|c| c.is_ascii_uppercase()) { ngx_core::regex::NGX_REGEX_CASELESS } else { 0 };

        let re = regex_compile(cf, pattern, options)?;

        let captures = re.ncaptures > 0;

        sn.regex = Some(re);
        sn.name = pattern.to_vec();

        let mut c = cscf.borrow_mut();
        c.server_names.push(sn);
        c.captures = captures;
    }

    Ok(())
}

/// ngx_stream_core_resolver
fn core_resolver(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cscf = cscf_of(&conf);

    if cscf.borrow().resolver.is_some() {
        return Err(msg("is duplicate"));
    }

    let args = cf.args[1..].to_vec();

    let r = Resolver::create(cf, &args)?;

    cscf.borrow_mut().resolver = Some(r);

    Ok(())
}

pub fn core_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_core_module",
        StreamModuleDef {
            preconfiguration: Some(core_preconfiguration),
            postconfiguration: None,
            create_main_conf: Some(core_create_main_conf),
            init_main_conf: Some(core_init_main_conf),
            create_srv_conf: Some(core_create_srv_conf),
            merge_srv_conf: Some(core_merge_srv_conf),
        },
        vec![
            cmd!("variables_hash_max_size", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, CoreMainConf, variables_hash_max_size, set_num),
            cmd!("variables_hash_bucket_size", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, CoreMainConf, variables_hash_bucket_size, set_num),
            cmd!("server_names_hash_max_size", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, CoreMainConf, server_names_hash_max_size, set_num),
            cmd!("server_names_hash_bucket_size", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE1, ConfLevel::Main, CoreMainConf, server_names_hash_bucket_size, set_num),
            cmd_fn!("server", NGX_STREAM_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS, ConfLevel::None, core_server),
            cmd_fn!("listen", NGX_STREAM_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, core_listen),
            cmd_fn!("server_name", NGX_STREAM_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, core_server_name),
            cmd_fn!("error_log", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, core_error_log),
            cmd_fn!("resolver", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_1MORE, ConfLevel::Srv, core_resolver),
            cmd!("resolver_timeout", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, CoreSrvConf, resolver_timeout, set_msec),
            cmd!("proxy_protocol_timeout", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, CoreSrvConf, proxy_protocol_timeout, set_msec),
            cmd!("tcp_nodelay", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, CoreSrvConf, tcp_nodelay, set_flag),
            cmd!("preread_buffer_size", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, CoreSrvConf, preread_buffer_size, set_size),
            cmd!("preread_timeout", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, CoreSrvConf, preread_timeout, set_msec),
        ],
    )
}
