//! ngx_http_upstream_sticky_module: session persistence with
//! "sticky cookie", "sticky route" and "sticky learn".

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rbtree::*;
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::slab::SlabPool;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::request::*;
use crate::script::ComplexValue;
use crate::upstream::*;
use crate::upstream_round_robin::{RrPeerData, NGX_HTTP_UPSTREAM_SID_LEN};
use crate::variables::{get_flushed_variable, get_variable_index};
use crate::{http_module_def, HttpModuleDef, NGX_HTTP_UPS_CONF};

const NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES: i64 = 2145916555;

const NGX_CONF_UNSET_TIME: i64 = -1;

/// ngx_http_upstream_sticky_sess_key_t: the md5 of a session ID, the
/// first word of it is the rbtree key
struct SessKey {
    md5: [u8; 16],
}

impl SessKey {
    fn hash(&self) -> usize {
        let mut w = [0u8; std::mem::size_of::<usize>()];
        w.copy_from_slice(&self.md5[..std::mem::size_of::<usize>()]);
        usize::from_ne_bytes(w)
    }
}

/// ngx_http_upstream_sticky_sess_shared_t
#[repr(C)]
struct SessShared {
    rbtree: Rbtree,
    sentinel: RbtreeNode,

    exp_rbtree: Rbtree,
    exp_sentinel: RbtreeNode,
}

/// ngx_http_upstream_sticky_sess_node_t: session data, mapping of
/// session ID hash to server ID
#[repr(C)]
struct SessNode {
    rbnode: RbtreeNode,
    enode: RbtreeNode,

    md5: [u8; 16],

    last: u64,

    sid_len: u8,
    sid: [u8; NGX_HTTP_UPSTREAM_SID_LEN],
}

/// ngx_http_upstream_sticky_sess_t: the sessions zone of a process
struct StickySess {
    sh: Cell<*mut SessShared>,
    shpool: Cell<*mut SlabPool>,
    host: Vec<u8>,

    timeout: u64,
    /// sess->event.timer_set
    timer_set: Cell<bool>,
}

/// ngx_http_upstream_sticky_srv_conf_t: per-upstream sticky configuration
pub struct StickySrvConf {
    original_init_upstream: Cell<Option<InitUpstream>>,
    original_init_peer: RefCell<Option<InitPeer>>,

    lookup_vars: Vec<usize>,
    create_vars: Vec<usize>,
    /// sessions
    shm_zone: Option<Rc<ShmZone>>,

    cookie_name: Vec<u8>,
    cookie_domain: Option<ComplexValue>,
    cookie_path: Vec<u8>,
    cookie_expires: i64,
    cookie_samesite: Option<ComplexValue>,
    cookie_httponly: bool,
    cookie_secure: bool,
    learn_after_headers: bool,
}

impl StickySrvConf {
    fn new() -> StickySrvConf {
        StickySrvConf {
            original_init_upstream: Cell::new(None),
            original_init_peer: RefCell::new(None),
            lookup_vars: Vec::new(),
            create_vars: Vec::new(),
            shm_zone: None,
            cookie_name: Vec::new(),
            cookie_domain: None,
            cookie_path: Vec::new(),
            cookie_expires: NGX_CONF_UNSET_TIME,
            cookie_samesite: None,
            cookie_httponly: false,
            cookie_secure: false,
            learn_after_headers: false,
        }
    }

    fn sess(&self) -> Option<Rc<StickySess>> {
        self.shm_zone.as_ref().and_then(|z| z.data::<StickySess>())
    }
}

/// ngx_http_upstream_sticky_peer_data_t
struct StickyPeerData {
    original: Box<dyn PeerBalancer>,
    request: R,

    conf: Rc<StickySrvConf>,

    id: Vec<u8>,
    cookie: Option<Header>,
}

const EXPIRES: &[u8] = b"; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=315360000";
const HTTPONLY: &[u8] = b"; httponly";
const SECURE: &[u8] = b"; secure";

/// ngx_http_upstream_sticky_init_upstream
fn init_upstream(cf: &mut Conf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    let stcf = us.module_conf::<StickySrvConf>().expect("sticky conf");

    let original = stcf.original_init_upstream.get().unwrap_or(crate::upstream_round_robin::init_round_robin);
    original(cf, us)?;

    *stcf.original_init_peer.borrow_mut() = us.init.borrow().clone();

    *us.init.borrow_mut() = Some(Rc::new(init_peer));

    Ok(())
}

/// ngx_http_upstream_sticky_init_peer
fn init_peer(r: &R, us: &Rc<UpstreamSrvConf>) -> Result<Box<dyn PeerBalancer>, ()> {
    let stcf = us.module_conf::<StickySrvConf>().ok_or(())?;

    let original_init_peer = stcf.original_init_peer.borrow().clone().ok_or(())?;

    let original = original_init_peer(r, us)?;

    let mut stp = StickyPeerData { original, request: r.clone(), conf: stcf.clone(), id: Vec::new(), cookie: None };

    get_id(r, &stcf.lookup_vars, &mut stp.id);

    Ok(Box::new(stp))
}

/// ngx_http_upstream_sticky_get_id
fn get_id(r: &R, vars: &[usize], id: &mut Vec<u8>) -> i64 {
    for (i, index) in vars.iter().enumerate() {
        let v = match get_flushed_variable(r, *index) {
            Some(v) => v,
            None => continue,
        };

        if v.not_found || v.data.is_empty() {
            continue;
        }

        *id = v.data;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "sticky: using \"{}\" found in variable #{}", B(id), i + 1);

        return NGX_OK;
    }

    id.clear();

    NGX_DONE
}

/// ngx_http_upstream_sticky_sess_init_key
fn sess_init_key(sess_id: &[u8]) -> SessKey {
    use md5::{Digest, Md5};
    let mut md5 = Md5::new();
    md5.update(sess_id);
    SessKey { md5: md5.finalize().into() }
}

impl PeerBalancer for StickyPeerData {
    fn tries(&self) -> u32 {
        self.original.tries()
    }

    /// ngx_http_upstream_sticky_get_peer
    fn get(&mut self, pc: &mut PeerConnection) -> i64 {
        if pc.hint.is_none() && self.conf.shm_zone.is_some() && !self.id.is_empty() {
            // request holds session ID, extract server ID from session

            let sess = self.conf.sess().expect("sticky sessions");

            let key = sess_init_key(&self.id);

            let shpool = unsafe { &*sess.shpool.get() };

            shpool.lock();

            let sn = unsafe { sess_lookup(&sess, &key) };

            if sn.is_null() {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "sticky: session \"{}\" not found", B(&self.id));
            } else {
                let sid = unsafe { (&(*sn).sid)[..(*sn).sid_len as usize].to_vec() };

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "sticky: session \"{}\", SID \"{}\"", B(&self.id), B(&sid));

                pc.hint = Some(sid);
            }

            shpool.unlock();
        } else if pc.hint.is_none() && !self.id.is_empty() {
            // request holds server ID

            pc.hint = Some(self.id.clone());
        }

        let rc = self.original.get(pc);

        pc.hint = None;

        if rc != NGX_OK && rc != NGX_DONE {
            return rc;
        }

        if self.conf.cookie_name.is_empty() {
            return rc;
        }

        if self.cookie_insert(pc) != NGX_OK {
            return NGX_ERROR;
        }

        rc
    }

    /// ngx_http_upstream_sticky_free_peer
    fn free(&mut self, pc: &mut PeerConnection, state: u32, us: &UpstreamState) {
        if state & (NGX_PEER_FAILED | NGX_PEER_NEXT) == 0 && self.conf.shm_zone.is_some() && !self.conf.learn_after_headers {
            self.learn_peer(pc);
        }

        self.original.free(pc, state, us);
    }

    /// ngx_http_upstream_sticky_notify_peer
    fn notify(&mut self, pc: &mut PeerConnection, typ: u32, us: &UpstreamState) {
        if typ == NGX_HTTP_UPSTREAM_NOTIFY_HEADER && self.conf.learn_after_headers {
            self.learn_peer(pc);
        }

        self.original.notify(pc, typ, us);
    }

    /// ngx_http_upstream_sticky_set_session
    fn set_session(&mut self) -> Option<openssl::ssl::SslSession> {
        self.original.set_session()
    }

    /// ngx_http_upstream_sticky_save_session
    fn save_session(&mut self, session: openssl::ssl::SslSession) {
        self.original.save_session(session)
    }

    fn rr(&mut self) -> Option<&mut RrPeerData> {
        self.original.rr()
    }
}

impl StickyPeerData {
    /// ngx_http_upstream_sticky_learn_peer
    fn learn_peer(&mut self, pc: &PeerConnection) {
        let sid = match &pc.sid {
            Some(sid) => sid,
            None => {
                ngx_log_error!(NGX_LOG_WARN, pc.log, None, "balancer does not support sticky");
                return;
            }
        };

        let stcf = &self.conf;

        let r = &self.request;

        let sess = stcf.sess().expect("sticky sessions");

        let mut sess_id = Vec::new();

        let create = if get_id(r, &stcf.create_vars, &mut sess_id) == NGX_OK {
            true
        } else if !self.id.is_empty() {
            sess_id = self.id.clone();
            false
        } else {
            return;
        };

        let now = ngx_core::times::msec();

        let key = sess_init_key(&sess_id);

        let shpool = unsafe { &*sess.shpool.get() };

        shpool.lock();

        unsafe {
            let sh = sess.sh.get();

            let sn = sess_lookup(&sess, &key);

            if !sn.is_null() {
                if sid.len() != (*sn).sid_len as usize || sid.as_slice() != &(&(*sn).sid)[..(*sn).sid_len as usize] {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "sticky: session \"{}\" reused for SID \"{}\"", B(&sess_id), B(sid));

                    (*sn).sid_len = sid.len() as u8;
                    (&mut (*sn).sid)[..sid.len()].copy_from_slice(sid);
                }

                (*sh).exp_rbtree.delete(&mut (*sn).enode);
                (*sn).last = now;
                (*sn).enode.key = (*sn).last as usize;
                (*sh).exp_rbtree.insert(&mut (*sn).enode);

                shpool.unlock();
                return;
            }

            if create {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "sticky: creating session \"{}\", SID \"{}\"", B(&sess_id), B(sid));

                let sn = sess_create(&sess, &key, sid);

                if !sn.is_null() {
                    (*sn).last = now;
                    (*sn).enode.key = (*sn).last as usize;
                    (*sh).exp_rbtree.insert(&mut (*sn).enode);

                    if !sess.timer_set.get() {
                        sess_add_timer(&sess, sess.timeout);
                    }
                }
            }
        }

        shpool.unlock();
    }

    /// ngx_http_upstream_sticky_cookie_insert
    fn cookie_insert(&mut self, pc: &PeerConnection) -> i64 {
        let stcf = self.conf.clone();
        let r = self.request.clone();

        let sid = match &pc.sid {
            Some(sid) => sid,
            None => {
                ngx_log_error!(NGX_LOG_WARN, pc.log, None, "balancer does not support sticky");
                return NGX_OK;
            }
        };

        if !self.id.is_empty() {
            // check that the selected peer matches SID from request

            if sid != &self.id {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, pc.log, "sticky: server with requested SID is unavailable");
            }
        }

        let mut domain = Vec::new();

        if let Some(cv) = &stcf.cookie_domain {
            domain = match crate::script::complex_value(&r, cv) {
                Ok(v) => v,
                Err(_) => return NGX_ERROR,
            };
        }

        let mut samesite = Vec::new();

        if let Some(cv) = &stcf.cookie_samesite {
            samesite = match crate::script::complex_value(&r, cv) {
                Ok(v) => v,
                Err(_) => return NGX_ERROR,
            };

            if !cv.is_constant() && !samesite.is_empty() && samesite_check(&samesite) != NGX_OK {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "sticky: invalid cookie samesite value \"{}\"", B(&samesite));
                samesite = b"strict".to_vec();
            }
        }

        let mut data = Vec::with_capacity(stcf.cookie_name.len() + 1 + sid.len() + stcf.cookie_path.len() + 128);

        data.extend_from_slice(&stcf.cookie_name);
        data.push(b'=');
        data.extend_from_slice(sid);

        if stcf.cookie_expires != NGX_CONF_UNSET_TIME {
            if stcf.cookie_expires == NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES {
                data.extend_from_slice(EXPIRES);
            } else {
                data.extend_from_slice(b"; expires=");
                data.extend_from_slice(ngx_core::times::http_cookie_time(ngx_core::times::time() + stcf.cookie_expires).as_bytes());
                data.extend_from_slice(format!("; max-age={}", stcf.cookie_expires).as_bytes());
            }
        }

        if !domain.is_empty() {
            data.extend_from_slice(b"; domain=");
            data.extend_from_slice(&domain);
        }

        if stcf.cookie_httponly {
            data.extend_from_slice(HTTPONLY);
        }

        if stcf.cookie_secure {
            data.extend_from_slice(SECURE);
        }

        if !samesite.is_empty() {
            data.extend_from_slice(b"; samesite=");
            data.extend_from_slice(&samesite);
        }

        data.extend_from_slice(&stcf.cookie_path);

        match &self.cookie {
            Some(cookie) => *cookie.value.borrow_mut() = data,
            None => {
                let cookie = TableElt::new(b"Set-Cookie", &data);
                r.headers_out.borrow_mut().headers.push(cookie.clone());
                self.cookie = Some(cookie);
            }
        }

        if let Some(cookie) = &self.cookie {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "sticky: set cookie: \"{}\"", B(&cookie.value.borrow()));
        }

        NGX_OK
    }
}

/// ngx_http_upstream_sticky_samesite
fn samesite_check(value: &[u8]) -> i64 {
    const SAMESITE: [&[u8]; 3] = [b"strict", b"lax", b"none"];

    for s in SAMESITE {
        if s.len() == value.len() && s.eq_ignore_ascii_case(value) {
            return NGX_OK;
        }
    }

    NGX_ERROR
}

/// ngx_http_upstream_sticky_sess_lookup
unsafe fn sess_lookup(sess: &StickySess, key: &SessKey) -> *mut SessNode {
    let sh = sess.sh.get();

    let hash = key.hash();
    let mut node = (*sh).rbtree.root;
    let sentinel = (*sh).rbtree.sentinel;

    while node != sentinel {
        if hash < (*node).key {
            node = (*node).left;
            continue;
        }

        if hash > (*node).key {
            node = (*node).right;
            continue;
        }

        // hash == node->key

        loop {
            let sn = node as *mut SessNode;

            let rc = key.md5.cmp(&(*sn).md5);

            if rc == std::cmp::Ordering::Equal {
                return sn;
            }

            node = if rc == std::cmp::Ordering::Less { (*node).left } else { (*node).right };

            if !(node != sentinel && hash == (*node).key) {
                break;
            }
        }

        break;
    }

    std::ptr::null_mut()
}

/// ngx_http_upstream_sticky_sess_create
unsafe fn sess_create(sess: &StickySess, key: &SessKey, sid: &[u8]) -> *mut SessNode {
    let n = std::mem::size_of::<SessNode>();

    let shpool = &*sess.shpool.get();

    let mut sn = shpool.alloc_locked(n) as *mut SessNode;

    if sn.is_null() {
        let log = ngx_core::cycle::cycle().log.clone();

        ngx_log_error!(
            NGX_LOG_WARN,
            log,
            None,
            "could not allocate node{}, expiring least recently used session",
            B(shpool.log_ctx())
        );

        let _ = sess_expire(sess, true);

        sn = shpool.alloc_locked(n) as *mut SessNode;
        if sn.is_null() {
            ngx_log_error!(NGX_LOG_ALERT, log, None, "could not allocate node{}", B(shpool.log_ctx()));
            return std::ptr::null_mut();
        }
    }

    (*sn).md5 = key.md5;

    (*sn).sid_len = sid.len() as u8;
    (&mut (*sn).sid)[..sid.len()].copy_from_slice(sid);

    let node = &mut (*sn).rbnode as *mut RbtreeNode;
    (*node).key = key.hash();

    (*sess.sh.get()).rbtree.insert(node);

    sn
}

/// ngx_http_upstream_sticky_sess_rbtree_insert_value
unsafe fn sess_rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let mut p: *mut *mut RbtreeNode;

    loop {
        if (*node).key < (*temp).key {
            p = &mut (*temp).left;
        } else if (*node).key > (*temp).key {
            p = &mut (*temp).right;
        } else {
            // node->key == temp->key

            let sn = node as *mut SessNode;
            let snt = temp as *mut SessNode;

            p = if (*sn).md5 < (*snt).md5 { &mut (*temp).left } else { &mut (*temp).right };
        }

        if *p == sentinel {
            break;
        }

        temp = *p;
    }

    *p = node;
    (*node).parent = temp;
    (*node).left = sentinel;
    (*node).right = sentinel;
    rbt_red(node);
}

/// ngx_add_timer(&sess->event, timer)
fn sess_add_timer(sess: &Rc<StickySess>, timer: u64) {
    sess.timer_set.set(true);

    let sess = sess.clone();

    ngx_core::event::spawn_posted(async move {
        tokio::time::sleep(std::time::Duration::from_millis(timer)).await;
        sess.timer_set.set(false);
        sess_timer_handler(&sess);
    });
}

/// ngx_http_upstream_sticky_sess_timer_handler
fn sess_timer_handler(sess: &Rc<StickySess>) {
    if let Some(c) = ngx_core::cycle::try_cycle() {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "sticky: session timer");
    }

    let shpool = unsafe { &*sess.shpool.get() };

    shpool.lock();

    let wait = unsafe { sess_expire(sess, false) };

    shpool.unlock();

    sess_rearm(sess, wait);
}

/// "if (wait > 0) ngx_add_timer(&sess->event, wait)" with the unsigned
/// wait: a negative one is a timer already expired.
fn sess_rearm(sess: &Rc<StickySess>, wait: i64) {
    if wait != 0 {
        sess_add_timer(sess, wait.max(0) as u64);
    }
}

/// ngx_http_upstream_sticky_sess_expire: the time till the next session
/// expires, as ngx_msec_int_t.
unsafe fn sess_expire(sess: &StickySess, force: bool) -> i64 {
    let mut wait: i64 = 0;

    let now = ngx_core::times::msec() as i64;

    let sh = sess.sh.get();
    let shpool = &*sess.shpool.get();

    if (*sh).exp_rbtree.root == (*sh).exp_rbtree.sentinel {
        return 0;
    }

    let mut force = force;

    let mut node = rbtree_min((*sh).exp_rbtree.root, (*sh).exp_rbtree.sentinel);

    while !node.is_null() {
        let sn = (node as *mut u8).sub(std::mem::offset_of!(SessNode, enode)) as *mut SessNode;
        wait = (*sn).last as i64 + sess.timeout as i64 - now;

        if !force && wait > 0 {
            break;
        }

        force = false;

        let next = rbtree_next(&(*sh).exp_rbtree, node);

        // remove node
        (*sh).exp_rbtree.delete(&mut (*sn).enode);

        (*sh).rbtree.delete(&mut (*sn).rbnode);
        shpool.free_locked(sn as *mut u8);

        node = next;
    }

    wait
}

/// ngx_http_upstream_sticky_sess_init_zone
fn sess_init_zone(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn Any>>) -> Result<(), ()> {
    let sess = shm_zone.data::<StickySess>().ok_or(())?;

    if let Some(old_sess) = data.and_then(|d| d.downcast::<StickySess>().ok()) {
        if sess.host != old_sess.host {
            if let Some(log) = shm_zone.shm.log.borrow().as_ref() {
                ngx_log_error!(
                    NGX_LOG_EMERG,
                    log,
                    None,
                    "sticky zone \"{}\" is used in upstream \"{}\" while previously it was used in upstream \"{}\"",
                    B(shm_zone.name()),
                    B(&sess.host),
                    B(&old_sess.host)
                );
            }

            return Err(());
        }

        sess.sh.set(old_sess.sh.get());
        sess.shpool.set(old_sess.shpool.get());
        return Ok(());
    }

    let shpool = shm_zone.shm.addr.get() as *mut SlabPool;
    sess.shpool.set(shpool);

    unsafe {
        if shm_zone.shm.exists.get() {
            sess.sh.set((*shpool).data as *mut SessShared);
            return Ok(());
        }

        let sh = (*shpool).alloc(std::mem::size_of::<SessShared>()) as *mut SessShared;
        if sh.is_null() {
            return Err(());
        }

        sess.sh.set(sh);

        (*shpool).data = sh as *mut u8;

        (*sh).rbtree.init(&mut (*sh).sentinel, sess_rbtree_insert_value);

        (*sh).exp_rbtree.init(&mut (*sh).exp_sentinel, rbtree_insert_timer_value);

        let ctx = format!(" in sticky session zone \"{}\"", B(shm_zone.name()));

        (*shpool).set_log_ctx(ctx.as_bytes())?;

        (*shpool).log_nomem = false;
    }

    Ok(())
}

/// ngx_http_upstream_sticky
fn sticky_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let us = current_upstream(cf).ok_or_else(|| msg("is not allowed here"))?;

    if us.module_conf::<StickySrvConf>().is_some() {
        return Err(msg("is duplicate"));
    }

    let mut stcf = StickySrvConf::new();

    stcf.original_init_upstream.set(Some(us.init_upstream.get().unwrap_or(crate::upstream_round_robin::init_round_robin)));

    us.init_upstream.set(Some(init_upstream));

    let value = cf.args.clone();

    if value[1] == b"cookie" {
        sticky_cookie(cf, &mut stcf)?;
    } else if value[1] == b"route" {
        for v in &value[2..] {
            if v.first() != Some(&b'$') {
                return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(v))));
            }

            let index = get_variable_index(cf, &v[1..])?;

            stcf.lookup_vars.push(index);
        }
    } else if value[1] == b"learn" {
        sticky_learn(cf, &mut stcf, &us)?;
    } else {
        return Err(cf.emerg(format_args!("unknown parameter \"{}\"", B(&value[1]))));
    }

    us.set_module_conf(Rc::new(stcf));

    Ok(())
}

/// ngx_http_upstream_sticky_cookie
fn sticky_cookie(cf: &mut Conf, stcf: &mut StickySrvConf) -> ConfResult {
    let value = cf.args.clone();

    if value[2].is_empty() {
        return Err(msg("empty cookie name"));
    }

    stcf.cookie_name = value[2].clone();

    for v in &value[3..] {
        if let Some(domain) = v.strip_prefix(b"domain=") {
            if stcf.cookie_domain.is_some() {
                return Err(msg("parameter \"domain\" is duplicate"));
            }

            if domain.is_empty() {
                return Err(msg("no value for \"domain\""));
            }

            stcf.cookie_domain = Some(crate::script::compile_complex_value(cf, domain, 0)?);
        } else if let Some(path) = v.strip_prefix(b"path=") {
            if !stcf.cookie_path.is_empty() {
                return Err(msg("parameter \"path\" is duplicate"));
            }

            if path.is_empty() {
                return Err(msg("no value for \"path\""));
            }

            stcf.cookie_path = [b"; path=".as_slice(), path].concat();
        } else if let Some(expires) = v.strip_prefix(b"expires=") {
            if stcf.cookie_expires != NGX_CONF_UNSET_TIME {
                return Err(msg("parameter \"expires\" is duplicate"));
            }

            if expires == b"max" {
                stcf.cookie_expires = NGX_HTTP_STICKY_COOKIE_MAX_EXPIRES;
            } else {
                stcf.cookie_expires = match ngx_core::parse::parse_time(expires, true) {
                    Some(t) => t,
                    None => return Err(msg("invalid \"expires\" parameter value")),
                };
            }
        } else if v == b"httponly" {
            if stcf.cookie_httponly {
                return Err(msg("parameter \"httponly\" is duplicate"));
            }

            stcf.cookie_httponly = true;
        } else if v == b"secure" {
            if stcf.cookie_secure {
                return Err(msg("parameter \"secure\" is duplicate"));
            }

            stcf.cookie_secure = true;
        } else if let Some(samesite) = v.strip_prefix(b"samesite=") {
            if stcf.cookie_samesite.is_some() {
                return Err(msg("parameter \"samesite\" is duplicate"));
            }

            let cv = crate::script::compile_complex_value(cf, samesite, 0)?;

            if cv.is_constant() && samesite_check(samesite) != NGX_OK {
                return Err(msg("invalid \"samesite\" parameter value"));
            }

            stcf.cookie_samesite = Some(cv);
        } else {
            return Err(cf.emerg(format_args!("unknown parameter \"{}\"", B(v))));
        }
    }

    let name = [b"cookie_".as_slice(), &stcf.cookie_name].concat();

    let index = get_variable_index(cf, &name)?;

    stcf.lookup_vars.push(index);

    Ok(())
}

/// ngx_http_upstream_sticky_learn
fn sticky_learn(cf: &mut Conf, stcf: &mut StickySrvConf, us: &Rc<UpstreamSrvConf>) -> ConfResult {
    let mut zone_size: usize = 0;
    let mut timeout: Option<u64> = None;
    let mut name: Vec<u8> = Vec::new();

    let value = cf.args.clone();

    for v in &value[2..] {
        if let Some(z) = v.strip_prefix(b"zone=") {
            if zone_size != 0 {
                return Err(msg("duplicate zone"));
            }

            let colon = match z.iter().position(|&c| c == b':') {
                Some(p) => p,
                None => return Err(msg("zone size is not specified")),
            };

            name = z[..colon].to_vec();

            if name.is_empty() {
                return Err(msg("zone name is not specified"));
            }

            zone_size = match ngx_core::parse::parse_size(&z[colon + 1..]) {
                Some(s) => s,
                None => return Err(msg("invalid zone size")),
            };

            // 32k ~ 200 sessions, 1m ~ 8000 sessions
            if zone_size < 8 * ngx_core::os::pagesize() {
                return Err(msg("zone is too small"));
            }
        } else if let Some(t) = v.strip_prefix(b"timeout=") {
            if timeout.is_some() {
                return Err(msg("duplicate timeout"));
            }

            timeout = match ngx_core::parse::parse_time(t, false) {
                Some(t) if t != 0 => Some(t as u64),
                _ => return Err(msg("invalid timeout")),
            };
        } else if let Some(c) = v.strip_prefix(b"create=") {
            if c.first() != Some(&b'$') {
                return Err(msg("missing variable in the \"create\" parameter"));
            }

            let index = get_variable_index(cf, &c[1..])?;

            stcf.create_vars.push(index);
        } else if let Some(l) = v.strip_prefix(b"lookup=") {
            if l.first() != Some(&b'$') {
                return Err(msg("missing variable in the \"lookup\" parameter"));
            }

            let index = get_variable_index(cf, &l[1..])?;

            stcf.lookup_vars.push(index);
        } else if v == b"header" {
            stcf.learn_after_headers = true;
        } else {
            return Err(cf.emerg(format_args!("unknown parameter \"{}\"", B(v))));
        }
    }

    if stcf.lookup_vars.is_empty() {
        return Err(msg("\"lookup\" parameter is not specified"));
    }

    if stcf.create_vars.is_empty() {
        return Err(msg("\"create\" parameter is not specified"));
    }

    if zone_size == 0 {
        return Err(msg("\"zone\" parameter is not specified"));
    }

    // 10m
    let timeout = timeout.unwrap_or(600000);

    let shm_zone = ngx_core::cycle::shared_memory_add(cf, &name, zone_size, "ngx_http_upstream_sticky_module")?;

    if let Some(sess) = shm_zone.data::<StickySess>() {
        return Err(cf.emerg(format_args!("sticky zone \"{}\" is already used in upstream \"{}\"", B(&name), B(&sess.host))));
    }

    let sess = Rc::new(StickySess {
        sh: Cell::new(std::ptr::null_mut()),
        shpool: Cell::new(std::ptr::null_mut()),
        host: us.host.clone(),
        timeout,
        timer_set: Cell::new(false),
    });

    *shm_zone.init.borrow_mut() = Some(Rc::new(sess_init_zone));
    *shm_zone.data.borrow_mut() = Some(sess);

    stcf.shm_zone = Some(shm_zone);

    Ok(())
}

/// ngx_http_upstream_sticky_init_worker
fn init_worker(cycle: &Rc<ngx_core::cycle::Cycle>) -> Result<(), ()> {
    let process = ngx_core::cycle::globals(|g| g.process);

    if (process != ngx_core::cycle::ProcessType::Worker || ngx_core::event::worker_index() != 0)
        && process != ngx_core::cycle::ProcessType::Single
    {
        return Ok(());
    }

    let umcf = match crate::cycle_main_conf::<UpstreamMainConf>(cycle, crate::upstream::ctx_index) {
        Some(umcf) => umcf,
        None => return Ok(()),
    };

    let upstreams = umcf.borrow().upstreams.borrow().clone();

    for us in upstreams.iter() {
        if !us.block.get() {
            continue;
        }

        let stcf = match us.module_conf::<StickySrvConf>() {
            Some(stcf) => stcf,
            None => continue,
        };

        let sess = match stcf.sess() {
            Some(sess) => sess,
            None => continue,
        };

        let shpool = unsafe { &*sess.shpool.get() };

        shpool.lock();

        let wait = unsafe { sess_expire(&sess, false) };

        shpool.unlock();

        sess_rearm(&sess, wait);
    }

    Ok(())
}

pub fn upstream_sticky_module() -> ModuleDef {
    let commands = vec![cmd_fn!("sticky", NGX_HTTP_UPS_CONF | NGX_CONF_2MORE, ConfLevel::None, sticky_handler)];
    let mut m = http_module_def("ngx_http_upstream_sticky_module", HttpModuleDef::default(), commands);
    m.init_process = Some(init_worker);
    m
}
