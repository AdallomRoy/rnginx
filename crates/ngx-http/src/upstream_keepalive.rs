//! ngx_http_upstream_keepalive_module: a cache of idle upstream
//! connections, wrapped around the upstream's balancer. As in nginx 1.31,
//! an upstream{} without "keepalive" caches up to 32 connections, reused
//! only by the location that opened them ("local").

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::rc::{Rc, Weak};
use std::time::Duration;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::inet::SockAddr;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug};

use crate::request::*;
use crate::upstream::*;
use crate::{http_module_def, HttpModuleDef, NGX_CONF_TAKE1, NGX_CONF_TAKE12, NGX_HTTP_UPS_CONF};

/// ngx_http_upstream_keepalive_srv_conf_t
pub struct KeepaliveConf {
    max_cached: Cell<Option<usize>>,
    requests: Cell<Option<u64>>,
    time: Cell<Option<u64>>,
    timeout: Cell<Option<u64>>,
    local: Cell<bool>,

    /// cached connections, the most recently saved first
    cache: RefCell<VecDeque<CacheItem>>,
    next_id: Cell<u64>,

    original_init_peer: RefCell<Option<InitPeer>>,
}

/// ngx_http_upstream_keepalive_cache_t
struct CacheItem {
    id: u64,
    conn: UpstreamConn,
    sockaddr: SockAddr,
    tag: usize,
    /// closes the connection when the upstream closes it, sends data, or
    /// keepalive_timeout passes (ngx_http_upstream_keepalive_close_handler)
    watch: tokio::task::JoinHandle<()>,
}

impl KeepaliveConf {
    fn new() -> KeepaliveConf {
        KeepaliveConf {
            max_cached: Cell::new(None),
            requests: Cell::new(None),
            time: Cell::new(None),
            timeout: Cell::new(None),
            local: Cell::new(false),
            cache: RefCell::new(VecDeque::new()),
            next_id: Cell::new(0),
            original_init_peer: RefCell::new(None),
        }
    }
}

/// ngx_http_upstream_keepalive_peer_data_t
struct KeepalivePeerData {
    conf: Rc<KeepaliveConf>,
    original: Box<dyn PeerBalancer>,
}

impl PeerBalancer for KeepalivePeerData {
    fn tries(&self) -> u32 {
        self.original.tries()
    }

    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        get_keepalive_peer(pc, self)
    }

    fn free(&mut self, pc: &mut PeerConnection, state: u32, us: &UpstreamState) {
        free_keepalive_peer(pc, self, state, us);
    }

    fn notify(&mut self, pc: &mut PeerConnection, typ: u32, us: &UpstreamState) {
        self.original.notify(pc, typ, us);
    }

    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        self.original.set_session()
    }

    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        self.original.save_session(session)
    }

    fn rr(&mut self) -> Option<&mut crate::upstream_round_robin::RrPeerData> {
        self.original.rr()
    }
}

/// ngx_http_upstream_get_keepalive_peer: ask the balancer, then look for a
/// cached connection to the peer (NGX_DONE).
fn get_keepalive_peer(pc: &mut PeerConnection, kp: &mut KeepalivePeerData) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get keepalive peer");

    // ask balancer

    let rc = kp.original.get(pc);

    if rc != NGX_OK {
        return rc;
    }

    // search cache for suitable connection

    let sockaddr = match pc.sockaddr.as_ref() {
        Some(s) => s.clone(),
        None => return NGX_OK,
    };

    let item = {
        let mut cache = kp.conf.cache.borrow_mut();

        let pos = cache.iter().position(|item| (!kp.conf.local.get() || item.tag == pc.tag) && item.sockaddr.cmp(&sockaddr, true));

        match pos {
            Some(i) => cache.remove(i),
            None => return NGX_OK,
        }
    };

    let item = match item {
        Some(i) => i,
        None => return NGX_OK,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "get keepalive peer: using connection {}", item.id);

    item.watch.abort();

    // c->idle = 0; c->sent = 0; c->data = NULL
    if let UpstreamSock::Conn(c) = &item.conn.sock {
        c.set_idle(false);
    }

    pc.connection = Some(item.conn);
    pc.cached = true;

    NGX_DONE
}

/// ngx_http_upstream_free_keepalive_peer: cache the connection if it and
/// the response allow, then free the peer.
fn free_keepalive_peer(pc: &mut PeerConnection, kp: &mut KeepalivePeerData, state: u32, us: &UpstreamState) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "free keepalive peer");

    // cache valid connections

    'invalid: {
        let conn = match pc.connection.as_ref() {
            Some(c) => c,
            None => break 'invalid,
        };

        if state & NGX_PEER_FAILED != 0 {
            break 'invalid;
        }

        if conn.requests >= kp.conf.requests.get().unwrap_or(1000) {
            break 'invalid;
        }

        if ngx_core::times::current_msec().saturating_sub(conn.start_time) > kp.conf.time.get().unwrap_or(3600000) {
            break 'invalid;
        }

        if !pc.keepalive {
            break 'invalid;
        }

        if !pc.request_body_sent {
            break 'invalid;
        }

        if ngx_core::event::is_exiting() || ngx_core::process::SIG_TERMINATE.load(std::sync::atomic::Ordering::SeqCst) {
            break 'invalid;
        }

        if raw_fd(&conn.sock).is_none() {
            break 'invalid;
        }

        let sockaddr = match pc.sockaddr.clone() {
            Some(s) => s,
            None => break 'invalid,
        };

        let conn = pc.connection.take().unwrap();

        let id = kp.conf.next_id.get();
        kp.conf.next_id.set(id + 1);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "free keepalive peer: saving connection {}", id);

        // an https connection is closed when the worker shuts down (c->close)
        let c = match &conn.sock {
            UpstreamSock::Conn(c) => Some(c.c.clone()),
            _ => None,
        };

        let watch = spawn_close_handler(Rc::downgrade(&kp.conf), id, kp.conf.timeout.get().unwrap_or(60000), c);

        // c->idle = 1
        if let UpstreamSock::Conn(c) = &conn.sock {
            c.set_idle(true);
        }

        let old = {
            let mut cache = kp.conf.cache.borrow_mut();

            // the least recently used one is closed
            let old = if cache.len() >= kp.conf.max_cached.get().unwrap_or(32) { cache.pop_back() } else { None };

            cache.push_front(CacheItem { id, conn, sockaddr, tag: pc.tag, watch });

            old
        };

        if let Some(old) = old {
            old.watch.abort();
            keepalive_close(old);
        }
    }

    kp.original.free(pc, state, us);
}

fn raw_fd(sock: &UpstreamSock) -> Option<RawFd> {
    match sock {
        UpstreamSock::Tcp(s) => Some(s.as_raw_fd()),
        UpstreamSock::Unix(s) => Some(s.as_raw_fd()),
        UpstreamSock::Conn(c) => Some(c.fd()),
    }
}

/// ngx_http_upstream_keepalive_close: an https connection is closed
/// without "close notify".
fn keepalive_close(item: CacheItem) {
    item.conn.sock.set_no_shutdown();
    drop(item);
}

/// ngx_http_upstream_keepalive_close_handler, as a task on a duplicate of
/// the socket: the connection is closed when data or the end of it arrives
/// (a peek that does not return EAGAIN), or on keepalive_timeout.
///
/// The duplicate is made when the task first runs, from the item still in
/// the cache (taking the item out of the cache aborts the task), and is
/// owned at once: a connection reused before then aborts the task unpolled,
/// and a descriptor duplicated up front would leak with the dropped future.
fn spawn_close_handler(conf: Weak<KeepaliveConf>, id: u64, timeout: u64, c: Option<Rc<ngx_core::connection::Connection>>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let dup = match conf.upgrade() {
            Some(conf) => {
                let cache = conf.cache.borrow();

                match cache.iter().find(|it| it.id == id) {
                    Some(it) => raw_fd(&it.conn.sock).map(|fd| unsafe { libc::dup(fd) }).filter(|&d| d >= 0).map(|d| unsafe { OwnedFd::from_raw_fd(d) }),
                    None => return,
                }
            }
            None => return,
        };

        // c->close: ngx_close_idle_connections() at the worker's shutdown
        let close = async {
            match &c {
                Some(c) => loop {
                    let notified = c.close_notify.notified();

                    if c.close.get() {
                        return;
                    }

                    notified.await;
                },
                None => std::future::pending().await,
            }
        };

        tokio::pin!(close);

        if let Some(owned) = dup {
            if let Ok(afd) = tokio::io::unix::AsyncFd::with_interest(owned, tokio::io::Interest::READABLE) {
                let watch = async {
                    loop {
                        let mut guard = match afd.readable().await {
                            Ok(g) => g,
                            Err(_) => return,
                        };

                        let mut b = [0u8; 1];
                        let n = unsafe { libc::recv(afd.as_raw_fd(), b.as_mut_ptr() as *mut libc::c_void, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };

                        if n == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                            continue;
                        }

                        return;
                    }
                };

                tokio::select! {
                    _ = tokio::time::timeout(Duration::from_millis(timeout), watch) => {}
                    _ = &mut close => {}
                }
            }
        }

        // close: the item leaves the cache and its connection is closed
        if let Some(conf) = conf.upgrade() {
            let item = {
                let mut cache = conf.cache.borrow_mut();
                cache.iter().position(|it| it.id == id).and_then(|i| cache.remove(i))
            };

            // the watch handle is this task's own: dropping it detaches
            if let Some(item) = item {
                keepalive_close(item);
            }
        }
    })
}

/// ngx_http_upstream_keepalive
fn keepalive_handler(cf: &mut Conf, cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let kcf = keepalive_conf(cf)?;

    if kcf.max_cached.get().is_some() {
        return Err(msg("is duplicate"));
    }

    // read options

    let value = cf.args.clone();

    let n = match ngx_core::string::atoi(&value[1]) {
        Some(n) => n,
        None => {
            return Err(cf.emerg(format_args!("invalid value \"{}\" in \"{}\" directive", B(&value[1]), cmd.name)));
        }
    };

    kcf.max_cached.set(Some(n as usize));

    if value.len() == 3 {
        if value[2] == b"local" {
            kcf.local.set(true);
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    Ok(())
}

fn keepalive_conf(cf: &Conf) -> Result<Rc<KeepaliveConf>, ConfError> {
    let uscf = current_upstream(cf).ok_or_else(|| msg("directive is not allowed here"))?;

    if let Some(k) = uscf.module_conf::<KeepaliveConf>() {
        return Ok(k);
    }

    let k = Rc::new(KeepaliveConf::new());
    uscf.set_module_conf(k.clone());
    Ok(k)
}

/// keepalive_time / keepalive_timeout (ngx_conf_set_msec_slot)
fn msec_handler(cf: &mut Conf, cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let kcf = keepalive_conf(cf)?;

    let slot = if cmd.name == "keepalive_time" { &kcf.time } else { &kcf.timeout };

    if slot.get().is_some() {
        return Err(msg("is duplicate"));
    }

    match ngx_core::parse::parse_time(&cf.args[1], false) {
        Some(t) => slot.set(Some(t as u64)),
        None => return Err(msg("invalid value")),
    }

    Ok(())
}

/// keepalive_requests (ngx_conf_set_num_slot)
fn requests_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let kcf = keepalive_conf(cf)?;

    if kcf.requests.get().is_some() {
        return Err(msg("is duplicate"));
    }

    match ngx_core::string::atoi(&cf.args[1]) {
        Some(n) => kcf.requests.set(Some(n as u64)),
        None => return Err(msg("invalid number")),
    }

    Ok(())
}

/// The module has no main configuration of its own; init_main_conf needs
/// a slot.
fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    ngx_core::conf::make_slot(())
}

/// ngx_http_upstream_keepalive_init_main_conf: wrap the balancer of every
/// upstream{} that caches connections.
fn init_main_conf(cf: &mut Conf, _conf: &Rc<dyn Any>) -> ConfResult {
    let umcf = crate::get_main_conf::<UpstreamMainConf>(cf, crate::upstream::ctx_index());
    let upstreams = umcf.borrow().upstreams.borrow().clone();

    for uscf in upstreams.iter() {
        // skip implicit upstreams
        if !uscf.block.get() {
            continue;
        }

        let kcf = match uscf.module_conf::<KeepaliveConf>() {
            Some(k) => k,
            None => {
                let k = Rc::new(KeepaliveConf::new());
                uscf.set_module_conf(k.clone());
                k
            }
        };

        if kcf.max_cached.get() == Some(0) {
            continue;
        }

        if kcf.time.get().is_none() {
            kcf.time.set(Some(3600000));
        }
        if kcf.timeout.get().is_none() {
            kcf.timeout.set(Some(60000));
        }
        if kcf.requests.get().is_none() {
            kcf.requests.set(Some(1000));
        }

        if kcf.max_cached.get().is_none() {
            kcf.local.set(true);
            kcf.max_cached.set(Some(32));
        }

        let original = uscf.init.borrow().clone();
        *kcf.original_init_peer.borrow_mut() = original;

        *uscf.init.borrow_mut() = Some(Rc::new(|r: &R, us: &Rc<UpstreamSrvConf>| -> Result<Box<dyn PeerBalancer>, ()> {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "init keepalive peer");

            let kcf = us.module_conf::<KeepaliveConf>().ok_or(())?;
            let init = kcf.original_init_peer.borrow().clone().ok_or(())?;
            let original = init(r, us)?;

            Ok(Box::new(KeepalivePeerData { conf: kcf, original }))
        }));
    }

    Ok(())
}

pub fn upstream_keepalive_module() -> ModuleDef {
    let commands = vec![
        cmd_fn!("keepalive", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12, ConfLevel::None, keepalive_handler),
        cmd_fn!("keepalive_time", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, msec_handler),
        cmd_fn!("keepalive_timeout", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, msec_handler),
        cmd_fn!("keepalive_requests", NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1, ConfLevel::None, requests_handler),
    ];

    let def = HttpModuleDef { create_main_conf: Some(create_main_conf), init_main_conf: Some(init_main_conf), ..Default::default() };

    http_module_def("ngx_http_upstream_keepalive_module", def, commands)
}
