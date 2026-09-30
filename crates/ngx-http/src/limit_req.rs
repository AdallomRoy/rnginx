//! ngx_http_limit_req_module: the rate of requests per key (a leaky
//! bucket), kept in a shared memory zone: an rbtree of the keys and an LRU
//! queue to expire them.

use std::any::Any;
use std::cell::Cell;
use std::ptr::{addr_of, addr_of_mut};
use std::rc::Rc;
use std::time::Duration;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::queue::*;
use ngx_core::rbtree::*;
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::slab::SlabPool;
use ngx_core::string::B;
use ngx_core::times::current_msec;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::write_filter::{test_reading_closed, TestReading};
use crate::*;

crate::http_module_index!("ngx_http_limit_req_module");

const NGX_HTTP_LIMIT_REQ_PASSED: u32 = 1;
const NGX_HTTP_LIMIT_REQ_DELAYED: u32 = 2;
const NGX_HTTP_LIMIT_REQ_REJECTED: u32 = 3;
const NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN: u32 = 4;
const NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN: u32 = 5;

const TAG: &str = "ngx_http_limit_req_module";

/// ngx_http_limit_req_node_t: it starts at the color of the rbtree node
#[repr(C)]
struct LimitReqNode {
    color: u8,
    dummy: u8,
    len: u16,
    queue: Queue,
    /// ngx_msec_t
    last: u64,
    /// integer value, 1 corresponds to 0.001 r/s
    excess: usize,
    count: usize,
    data: [u8; 1],
}

/// ngx_http_limit_req_shctx_t
#[repr(C)]
struct LimitReqShctx {
    rbtree: Rbtree,
    sentinel: RbtreeNode,
    queue: Queue,
}

/// ngx_http_limit_req_ctx_t
pub struct LimitReqCtx {
    sh: Cell<*mut LimitReqShctx>,
    shpool: Cell<*mut SlabPool>,
    /// integer value, 1 corresponds to 0.001 r/s
    rate: usize,
    key: ComplexValue,
    node: Cell<*mut LimitReqNode>,
}

/// ngx_http_limit_req_limit_t
#[derive(Clone)]
pub struct LimitReqLimit {
    shm_zone: Rc<ShmZone>,
    /// integer value, 1 corresponds to 0.001 r/s
    burst: usize,
    delay: usize,
}

/// ngx_http_limit_req_conf_t
pub struct LimitReqConf {
    /// None: limits.elts == NULL
    limits: Option<Vec<LimitReqLimit>>,
    limit_log_level: Val<u32>,
    delay_log_level: u32,
    status_code: Val<i64>,
    dry_run: Val<bool>,
}

static LIMIT_REQ_LOG_LEVELS: &[(&str, u32)] = &[("info", NGX_LOG_INFO), ("notice", NGX_LOG_NOTICE), ("warn", NGX_LOG_WARN), ("error", NGX_LOG_ERR)];

static LIMIT_REQ_VARS: &[VarDef] = &[VarDef { name: "limit_req_status", set: None, get: Some(limit_req_status_variable), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE }];

static LIMIT_REQ_STATUS: [&str; 5] = ["PASSED", "DELAYED", "REJECTED", "DELAYED_DRY_RUN", "REJECTED_DRY_RUN"];

const COLOR_OFF: usize = std::mem::offset_of!(RbtreeNode, color);

const DATA_OFF: usize = std::mem::offset_of!(LimitReqNode, data);

/// (ngx_http_limit_req_node_t *) &node->color
unsafe fn lr_of(node: *mut RbtreeNode) -> *mut LimitReqNode {
    (node as *mut u8).add(COLOR_OFF) as *mut LimitReqNode
}

/// (ngx_rbtree_node_t *) ((u_char *) lr - offsetof(ngx_rbtree_node_t, color))
unsafe fn node_of(lr: *mut LimitReqNode) -> *mut RbtreeNode {
    (lr as *mut u8).sub(COLOR_OFF) as *mut RbtreeNode
}

/// ngx_queue_data(q, ngx_http_limit_req_node_t, queue)
unsafe fn lr_of_queue(q: *mut Queue) -> *mut LimitReqNode {
    (q as *mut u8).sub(std::mem::offset_of!(LimitReqNode, queue)) as *mut LimitReqNode
}

/// lr->data, lr->len
unsafe fn lr_data<'a>(lr: *mut LimitReqNode) -> &'a [u8] {
    std::slice::from_raw_parts((lr as *const u8).add(DATA_OFF), (*lr).len as usize)
}

/// ngx_memn2cmp
fn memn2cmp(s1: &[u8], s2: &[u8]) -> i32 {
    let (n, z) = if s1.len() <= s2.len() { (s1.len(), -1) } else { (s2.len(), 1) };

    match s1[..n].cmp(&s2[..n]) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal if s1.len() == s2.len() => 0,
        std::cmp::Ordering::Equal => z,
    }
}

/// The zone's context: shm_zone->data, set by limit_req_zone (a zone that
/// no limit_req_zone declared has no size, and the configuration fails).
fn zone_ctx(limit: &LimitReqLimit) -> Rc<LimitReqCtx> {
    limit.shm_zone.data::<LimitReqCtx>().expect("limit_req zone without data")
}

/// ngx_http_limit_req_handler
async fn limit_req_handler(r: R) -> i64 {
    let main = r.main();

    if main.limit_req_status.get() != 0 {
        return NGX_DECLINED;
    }

    let lrcf_cell = r.loc_conf::<LimitReqConf>(ctx_index());
    let lrcf = lrcf_cell.borrow();

    let limits: &[LimitReqLimit] = lrcf.limits.as_deref().unwrap_or(&[]);

    let mut excess: usize = 0;

    let mut rc = NGX_DECLINED;

    let mut limit: usize = 0;

    let mut n = 0;

    while n < limits.len() {
        limit = n;

        let ctx = zone_ctx(&limits[n]);

        let key = match complex_value(&r, &ctx.key) {
            Ok(k) => k,
            Err(_) => {
                limit_req_unlock(limits, n);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        };

        if key.is_empty() {
            n += 1;
            continue;
        }

        if key.len() > 65535 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "the value of the \"{}\" key is more than 65535 bytes: \"{}\"", B(&ctx.key.value), B(&key));
            n += 1;
            continue;
        }

        let hash = crc32fast::hash(&key);

        // SAFETY: shpool was set by the zone init to the zone's slab pool
        let shpool = unsafe { &*ctx.shpool.get() };

        shpool.lock();

        // SAFETY: the zone's rbtree and queue are used under its mutex
        rc = unsafe { limit_req_lookup(&limits[n], hash, &key, &mut excess, n == limits.len() - 1) };

        shpool.unlock();

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "limit_req[{}]: {} {}.{:03}", n, rc, excess / 1000, excess % 1000);

        if rc != NGX_AGAIN {
            break;
        }

        n += 1;
    }

    if rc == NGX_DECLINED {
        return NGX_DECLINED;
    }

    if rc == NGX_BUSY || rc == NGX_ERROR {
        if rc == NGX_BUSY {
            ngx_log_error!(
                *lrcf.limit_log_level,
                r.connection.log,
                None,
                "limiting requests{}, excess: {}.{:03} by zone \"{}\"",
                if *lrcf.dry_run { ", dry run" } else { "" },
                excess / 1000,
                excess % 1000,
                B(limits[limit].shm_zone.name())
            );
        }

        limit_req_unlock(limits, n);

        if *lrcf.dry_run {
            main.limit_req_status.set(NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN);
            return NGX_DECLINED;
        }

        main.limit_req_status.set(NGX_HTTP_LIMIT_REQ_REJECTED);

        return *lrcf.status_code;
    }

    // rc == NGX_AGAIN || rc == NGX_OK

    if rc == NGX_AGAIN {
        excess = 0;
    }

    let delay = limit_req_account(limits, n, &mut excess, &mut limit);

    if delay == 0 {
        main.limit_req_status.set(NGX_HTTP_LIMIT_REQ_PASSED);
        return NGX_DECLINED;
    }

    ngx_log_error!(
        lrcf.delay_log_level,
        r.connection.log,
        None,
        "delaying request{}, excess: {}.{:03}, by zone \"{}\"",
        if *lrcf.dry_run { ", dry run" } else { "" },
        excess / 1000,
        excess % 1000,
        B(limits[limit].shm_zone.name())
    );

    if *lrcf.dry_run {
        main.limit_req_status.set(NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN);
        return NGX_DECLINED;
    }

    main.limit_req_status.set(NGX_HTTP_LIMIT_REQ_DELAYED);

    drop(lrcf);

    // r->read_event_handler = ngx_http_test_reading;
    // r->write_event_handler = ngx_http_limit_req_delay;
    // ngx_add_timer(r->connection->write, delay);

    limit_req_delay(&r, delay).await
}

/// ngx_http_limit_req_delay: the request waits for the write event timer,
/// ngx_http_test_reading being the read event handler meanwhile: if the
/// client closes the connection, the request is finalized with
/// NGX_HTTP_CLIENT_CLOSED_REQUEST. Then the phases run again, from this
/// handler, which declines as r->main->limit_req_status is set.
async fn limit_req_delay(r: &R, delay: u64) -> i64 {
    // the read event is posted at once; ngx_http_test_reading of an
    // HTTP/2 stream only tests c->error
    let closed = if r.stream.borrow().is_some() && r.connection.error.get() {
        Some(0)
    } else {
        let watch = TestReading::new(r);

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(delay)) => None,
            err = watch.closed() => Some(err),
        }
    };

    if let Some(err) = closed {
        test_reading_closed(r, err);
        return NGX_HTTP_CLIENT_CLOSED_REQUEST;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "limit_req delay");

    NGX_DECLINED
}

/// ngx_http_limit_req_rbtree_insert_value
unsafe fn limit_req_rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let p: *mut *mut RbtreeNode = loop {
        let p = if (*node).key < (*temp).key {
            addr_of_mut!((*temp).left)
        } else if (*node).key > (*temp).key {
            addr_of_mut!((*temp).right)
        } else {
            // node->key == temp->key

            let lrn = lr_of(node);
            let lrnt = lr_of(temp);

            if memn2cmp(lr_data(lrn), lr_data(lrnt)) < 0 {
                addr_of_mut!((*temp).left)
            } else {
                addr_of_mut!((*temp).right)
            }
        };

        if *p == sentinel {
            break p;
        }

        temp = *p;
    };

    *p = node;
    (*node).parent = temp;
    (*node).left = sentinel;
    (*node).right = sentinel;
    rbt_red(node);
}

/// ngx_http_limit_req_lookup (the zone's mutex is locked)
unsafe fn limit_req_lookup(limit: &LimitReqLimit, hash: u32, key: &[u8], ep: &mut usize, account: bool) -> i64 {
    let now = current_msec();

    let ctx = zone_ctx(limit);

    let sh = ctx.sh.get();

    let mut node = (*sh).rbtree.root;
    let sentinel = (*sh).rbtree.sentinel;

    let hash = hash as usize;

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

        let lr = lr_of(node);

        let rc = memn2cmp(key, lr_data(lr));

        if rc == 0 {
            queue_remove(addr_of_mut!((*lr).queue));
            queue_insert_head(addr_of_mut!((*sh).queue), addr_of_mut!((*lr).queue));

            let mut ms = now.wrapping_sub((*lr).last) as i64;

            if ms < -60000 {
                ms = 1;
            } else if ms < 0 {
                ms = 0;
            }

            let mut excess = (*lr).excess.wrapping_sub(ctx.rate.wrapping_mul(ms as usize) / 1000).wrapping_add(1000) as isize;

            if excess < 0 {
                excess = 0;
            }

            *ep = excess as usize;

            if excess as usize > limit.burst {
                return NGX_BUSY;
            }

            if account {
                (*lr).excess = excess as usize;

                if ms != 0 {
                    (*lr).last = now;
                }

                return NGX_OK;
            }

            (*lr).count += 1;

            ctx.node.set(lr);

            return NGX_AGAIN;
        }

        node = if rc < 0 { (*node).left } else { (*node).right };
    }

    *ep = 0;

    let size = COLOR_OFF + DATA_OFF + key.len();

    limit_req_expire(&ctx, 1);

    let shpool = &*ctx.shpool.get();

    let mut node = shpool.alloc_locked(size) as *mut RbtreeNode;

    if node.is_null() {
        limit_req_expire(&ctx, 0);

        node = shpool.alloc_locked(size) as *mut RbtreeNode;
        if node.is_null() {
            if let Some(cycle) = ngx_core::cycle::try_cycle() {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, None, "could not allocate node{}", B(shpool.log_ctx()));
            }
            return NGX_ERROR;
        }
    }

    (*node).key = hash;

    let lr = lr_of(node);

    (*lr).len = key.len() as u16;
    (*lr).excess = 0;

    std::ptr::copy_nonoverlapping(key.as_ptr(), (lr as *mut u8).add(DATA_OFF), key.len());

    (*sh).rbtree.insert(node);

    queue_insert_head(addr_of_mut!((*sh).queue), addr_of_mut!((*lr).queue));

    if account {
        (*lr).last = now;
        (*lr).count = 0;
        return NGX_OK;
    }

    (*lr).last = 0;
    (*lr).count = 1;

    ctx.node.set(lr);

    NGX_AGAIN
}

/// ngx_http_limit_req_account: `limit` is the index of the limit in
/// `limits`
fn limit_req_account(limits: &[LimitReqLimit], mut n: usize, ep: &mut usize, limit: &mut usize) -> u64 {
    let mut excess = *ep as isize;

    let mut max_delay: u64 = if excess as usize <= limits[*limit].delay {
        0
    } else {
        let ctx = zone_ctx(&limits[*limit]);
        ((excess as usize - limits[*limit].delay).wrapping_mul(1000) / ctx.rate) as u64
    };

    while n > 0 {
        n -= 1;

        let ctx = zone_ctx(&limits[n]);
        let lr = ctx.node.get();

        if lr.is_null() {
            continue;
        }

        // SAFETY: ctx->node is a node of the zone, not expired while its
        // count is not zero; it is changed under the zone's mutex
        unsafe {
            let shpool = &*ctx.shpool.get();

            shpool.lock();

            let now = current_msec();
            let mut ms = now.wrapping_sub((*lr).last) as i64;

            if ms < -60000 {
                ms = 1;
            } else if ms < 0 {
                ms = 0;
            }

            excess = (*lr).excess.wrapping_sub(ctx.rate.wrapping_mul(ms as usize) / 1000).wrapping_add(1000) as isize;

            if excess < 0 {
                excess = 0;
            }

            if ms != 0 {
                (*lr).last = now;
            }

            (*lr).excess = excess as usize;
            (*lr).count -= 1;

            shpool.unlock();
        }

        ctx.node.set(std::ptr::null_mut());

        if excess as usize <= limits[n].delay {
            continue;
        }

        let delay = ((excess as usize - limits[n].delay).wrapping_mul(1000) / ctx.rate) as u64;

        if delay > max_delay {
            max_delay = delay;
            *ep = excess as usize;
            *limit = n;
        }
    }

    max_delay
}

/// ngx_http_limit_req_unlock
fn limit_req_unlock(limits: &[LimitReqLimit], mut n: usize) {
    while n > 0 {
        n -= 1;

        let ctx = zone_ctx(&limits[n]);
        let lr = ctx.node.get();

        if lr.is_null() {
            continue;
        }

        // SAFETY: as in limit_req_account
        unsafe {
            let shpool = &*ctx.shpool.get();

            shpool.lock();

            (*lr).count -= 1;

            shpool.unlock();
        }

        ctx.node.set(std::ptr::null_mut());
    }
}

/// ngx_http_limit_req_expire (the zone's mutex is locked)
unsafe fn limit_req_expire(ctx: &LimitReqCtx, mut n: usize) {
    let now = current_msec();

    let sh = ctx.sh.get();

    // n == 1 deletes one or two zero rate entries
    // n == 0 deletes oldest entry by force
    //        and one or two zero rate entries

    while n < 3 {
        if queue_empty(addr_of!((*sh).queue)) {
            return;
        }

        let q = queue_last(addr_of!((*sh).queue));

        let lr = lr_of_queue(q);

        if (*lr).count != 0 {
            // There is not much sense in looking further,
            // because we bump nodes on the lookup stage.

            return;
        }

        let force = n == 0;

        n += 1;

        if !force {
            let ms = (now.wrapping_sub((*lr).last) as i64).wrapping_abs();

            if ms < 60000 {
                return;
            }

            let excess = (*lr).excess.wrapping_sub(ctx.rate.wrapping_mul(ms as usize) / 1000) as isize;

            if excess > 0 {
                return;
            }
        }

        queue_remove(q);

        let node = node_of(lr);

        (*sh).rbtree.delete(node);

        (*ctx.shpool.get()).free_locked(node as *mut u8);
    }
}

/// ngx_http_limit_req_init_zone
fn limit_req_init_zone(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn Any>>) -> Result<(), ()> {
    let ctx = shm_zone.data::<LimitReqCtx>().ok_or(())?;

    if let Some(octx) = data.and_then(|d| d.downcast::<LimitReqCtx>().ok()) {
        if ctx.key.value != octx.key.value {
            if let Some(log) = shm_zone.shm.log.borrow().as_ref() {
                ngx_log_error!(
                    NGX_LOG_EMERG,
                    log,
                    None,
                    "limit_req \"{}\" uses the \"{}\" key while previously it used the \"{}\" key",
                    B(shm_zone.name()),
                    B(&ctx.key.value),
                    B(&octx.key.value)
                );
            }
            return Err(());
        }

        ctx.sh.set(octx.sh.get());
        ctx.shpool.set(octx.shpool.get());

        return Ok(());
    }

    let shpool = shm_zone.shm.addr.get() as *mut SlabPool;

    ctx.shpool.set(shpool);

    // SAFETY: the zone is mapped, with its slab pool at the start
    unsafe {
        if shm_zone.shm.exists.get() {
            ctx.sh.set((*shpool).data as *mut LimitReqShctx);
            return Ok(());
        }

        let sh = (*shpool).alloc(std::mem::size_of::<LimitReqShctx>()) as *mut LimitReqShctx;
        if sh.is_null() {
            return Err(());
        }

        ctx.sh.set(sh);

        (*shpool).data = sh as *mut u8;

        (*sh).rbtree.init(addr_of_mut!((*sh).sentinel), limit_req_rbtree_insert_value);

        queue_init(addr_of_mut!((*sh).queue));

        let log_ctx = format!(" in limit_req zone \"{}\"", B(shm_zone.name()));

        (*shpool).set_log_ctx(log_ctx.as_bytes())?;

        (*shpool).log_nomem = false;
    }

    Ok(())
}

/// ngx_http_limit_req_status_variable
fn limit_req_status_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let status = r.main().limit_req_status.get();

    if status == 0 {
        v.not_found = true;
        return NGX_OK;
    }

    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    v.data = LIMIT_REQ_STATUS[status as usize - 1].as_bytes().to_vec();

    NGX_OK
}

/// ngx_http_limit_req_create_conf
fn limit_req_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitReqConf { limits: None, limit_log_level: Val::unset(), delay_log_level: 0, status_code: Val::unset(), dry_run: Val::unset() })
}

/// ngx_http_limit_req_merge_conf
fn limit_req_merge_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<LimitReqConf>(parent).borrow();
    let mut conf = conf_cell::<LimitReqConf>(child).borrow_mut();

    if conf.limits.is_none() {
        conf.limits = prev.limits.clone();
    }

    conf.limit_log_level.merge(&prev.limit_log_level, NGX_LOG_ERR);

    conf.delay_log_level = if *conf.limit_log_level == NGX_LOG_INFO { NGX_LOG_INFO } else { *conf.limit_log_level + 1 };

    conf.status_code.merge(&prev.status_code, NGX_HTTP_SERVICE_UNAVAILABLE);

    conf.dry_run.merge(&prev.dry_run, false);

    Ok(())
}

/// ngx_http_limit_req_zone
fn limit_req_zone(cf: &mut Conf, cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let value = cf.args.clone();

    let key = compile_complex_value(cf, &value[1], 0)?;

    let mut size = 0usize;
    let mut rate: i64 = 1;
    let mut scale: i64 = 1;
    let mut name: Vec<u8> = Vec::new();

    for v in &value[2..] {
        if let Some(z) = v.strip_prefix(b"zone=") {
            let p = match z.iter().position(|&c| c == b':') {
                Some(p) => p,
                None => return Err(cf.emerg(format_args!("invalid zone size \"{}\"", B(v)))),
            };

            name = z[..p].to_vec();

            size = match ngx_core::parse::parse_size(&z[p + 1..]) {
                Some(s) => s,
                None => return Err(cf.emerg(format_args!("invalid zone size \"{}\"", B(v)))),
            };

            if size < 8 * ngx_core::os::pagesize() {
                return Err(cf.emerg(format_args!("zone \"{}\" is too small", B(v))));
            }

            continue;
        }

        if v.starts_with(b"rate=") {
            let mut len = v.len();
            let p = &v[len - 3..];

            if p == b"r/s" {
                scale = 1;
                len -= 3;
            } else if p == b"r/m" {
                scale = 60;
                len -= 3;
            }

            rate = ngx_core::string::atoi(&v[5..len]).unwrap_or(NGX_ERROR);
            if rate <= 0 {
                return Err(cf.emerg(format_args!("invalid rate \"{}\"", B(v))));
            }

            continue;
        }

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(v))));
    }

    if name.is_empty() {
        return Err(cf.emerg(format_args!("\"{}\" must have \"zone\" parameter", cmd.name)));
    }

    let rate = (rate.wrapping_mul(1000) / scale) as usize;

    let shm_zone = ngx_core::cycle::shared_memory_add(cf, &name, size, TAG)?;

    if let Some(ctx) = shm_zone.data::<LimitReqCtx>() {
        return Err(cf.emerg(format_args!("{} \"{}\" is already bound to key \"{}\"", cmd.name, B(&name), B(&ctx.key.value))));
    }

    let ctx = Rc::new(LimitReqCtx { sh: Cell::new(std::ptr::null_mut()), shpool: Cell::new(std::ptr::null_mut()), rate, key, node: Cell::new(std::ptr::null_mut()) });

    *shm_zone.init.borrow_mut() = Some(Rc::new(limit_req_init_zone));
    *shm_zone.data.borrow_mut() = Some(ctx);

    Ok(())
}

/// ngx_http_limit_req
fn limit_req(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lrcf = conf_rc::<LimitReqConf>(conf.as_ref().expect("conf"));

    let value = cf.args.clone();

    let mut shm_zone: Option<Rc<ShmZone>> = None;
    let mut burst: i64 = 0;
    let mut delay: i64 = 0;

    for v in &value[1..] {
        if let Some(s) = v.strip_prefix(b"zone=") {
            shm_zone = Some(ngx_core::cycle::shared_memory_add(cf, s, 0, TAG)?);
            continue;
        }

        if let Some(s) = v.strip_prefix(b"burst=") {
            burst = ngx_core::string::atoi(s).unwrap_or(NGX_ERROR);
            if burst <= 0 {
                return Err(cf.emerg(format_args!("invalid burst value \"{}\"", B(v))));
            }

            continue;
        }

        if let Some(s) = v.strip_prefix(b"delay=") {
            delay = ngx_core::string::atoi(s).unwrap_or(NGX_ERROR);
            if delay <= 0 {
                return Err(cf.emerg(format_args!("invalid delay value \"{}\"", B(v))));
            }

            continue;
        }

        if v.as_slice() == b"nodelay" {
            delay = ngx_core::parse::NGX_MAX_INT_T_VALUE / 1000;
            continue;
        }

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(v))));
    }

    let shm_zone = match shm_zone {
        Some(z) => z,
        None => return Err(cf.emerg(format_args!("\"{}\" must have \"zone\" parameter", cmd.name))),
    };

    let mut l = lrcf.borrow_mut();

    let limits = l.limits.get_or_insert_with(Vec::new);

    if limits.iter().any(|lim| Rc::ptr_eq(&lim.shm_zone, &shm_zone)) {
        return Err(msg("is duplicate"));
    }

    limits.push(LimitReqLimit { shm_zone, burst: (burst * 1000) as usize, delay: (delay * 1000) as usize });

    Ok(())
}

/// limit_req_status: ngx_conf_set_num_slot with
/// ngx_http_limit_req_status_bounds (ngx_conf_check_num_bounds, 400..599)
fn limit_req_status(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lrcf = conf_rc::<LimitReqConf>(conf.as_ref().expect("conf"));
    let mut l = lrcf.borrow_mut();

    set_num(cf, cmd, &mut l.status_code)?;

    check_num_bounds(cf, *l.status_code, 400, 599)
}

/// ngx_http_limit_req_add_variables
fn limit_req_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, LIMIT_REQ_VARS)
}

/// ngx_http_limit_req_init
fn limit_req_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_PREACCESS_PHASE, Rc::new(|r| Box::pin(limit_req_handler(r))));
    Ok(())
}

pub fn limit_req_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(limit_req_add_variables),
        postconfiguration: Some(limit_req_init),
        create_loc_conf: Some(limit_req_create_conf),
        merge_loc_conf: Some(limit_req_merge_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("limit_req_zone", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE3, ConfLevel::None, limit_req_zone),
        cmd_fn!("limit_req", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::Loc, limit_req),
        cmd!("limit_req_log_level", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, LimitReqConf, limit_log_level, set_enum, LIMIT_REQ_LOG_LEVELS),
        cmd_fn!("limit_req_status", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, limit_req_status),
        cmd!("limit_req_dry_run", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, LimitReqConf, dry_run, set_flag),
    ];
    http_module_def("ngx_http_limit_req_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    use ngx_core::shmtx::ShmTx;

    /// A zone with its slab pool in `mem`, initialized by the zone init.
    fn zone(mem: &mut Vec<u64>, rate: usize) -> Rc<ShmZone> {
        let size = mem.len() * 8;
        let zone = ShmZone::new(b"test".to_vec(), size, TAG);

        // SAFETY: as ngx_init_zone_pool does, on memory of the given size
        unsafe {
            ngx_core::slab::sizes_init();
            let addr = mem.as_mut_ptr() as *mut u8;
            let sp = addr as *mut SlabPool;
            (*sp).end = addr.add(size);
            (*sp).min_shift = 3;
            (*sp).addr = addr;
            std::ptr::write(addr_of_mut!((*sp).mutex), ShmTx::create(addr_of_mut!((*sp).lock) as *mut AtomicUsize));
            ngx_core::slab::slab_init(sp);
            zone.shm.addr.set(addr);
        }

        let ctx = Rc::new(LimitReqCtx {
            sh: Cell::new(std::ptr::null_mut()),
            shpool: Cell::new(std::ptr::null_mut()),
            rate,
            key: ComplexValue::constant(b"$binary_remote_addr"),
            node: Cell::new(std::ptr::null_mut()),
        });

        *zone.data.borrow_mut() = Some(ctx);

        limit_req_init_zone(&zone, None).unwrap();

        zone
    }

    fn limit(zone: &Rc<ShmZone>, burst: usize, delay: usize) -> LimitReqLimit {
        LimitReqLimit { shm_zone: zone.clone(), burst: burst * 1000, delay: delay * 1000 }
    }

    fn lookup(limit: &LimitReqLimit, hash: u32, key: &[u8], account: bool) -> (i64, usize) {
        let mut excess = 0;
        let rc = unsafe { limit_req_lookup(limit, hash, key, &mut excess, account) };
        (rc, excess)
    }

    /// The node of a key, walking the tree as ngx_http_limit_req_lookup.
    fn find(limit: &LimitReqLimit, hash: u32, key: &[u8]) -> *mut LimitReqNode {
        let ctx = zone_ctx(limit);
        unsafe {
            let sh = ctx.sh.get();
            let mut node = (*sh).rbtree.root;
            let sentinel = (*sh).rbtree.sentinel;
            while node != sentinel {
                if (hash as usize) < (*node).key {
                    node = (*node).left;
                    continue;
                }
                if (hash as usize) > (*node).key {
                    node = (*node).right;
                    continue;
                }
                let lr = lr_of(node);
                match memn2cmp(key, lr_data(lr)) {
                    0 => return lr,
                    rc if rc < 0 => node = (*node).left,
                    _ => node = (*node).right,
                }
            }
        }
        std::ptr::null_mut()
    }

    fn queue_len(limit: &LimitReqLimit) -> usize {
        let ctx = zone_ctx(limit);
        let mut n = 0;
        unsafe {
            let h = addr_of_mut!((*ctx.sh.get()).queue);
            let mut q = queue_head(h);
            while q != h {
                n += 1;
                q = (*q).next;
            }
        }
        n
    }

    #[test]
    fn memn2cmp_as_c() {
        assert_eq!(memn2cmp(b"abc", b"abc"), 0);
        assert!(memn2cmp(b"ab", b"abc") < 0);
        assert!(memn2cmp(b"abc", b"ab") > 0);
        assert!(memn2cmp(b"abd", b"abc") > 0);
        assert!(memn2cmp(b"b", b"abc") > 0);
        assert!(memn2cmp(b"", b"a") < 0);
    }

    #[test]
    fn node_layout_as_c() {
        // offsetof(ngx_rbtree_node_t, color) + offsetof(ngx_http_limit_req_node_t, data)
        assert_eq!(COLOR_OFF, 32);
        assert_eq!(std::mem::offset_of!(LimitReqNode, queue), 8);
        assert_eq!(std::mem::offset_of!(LimitReqNode, last), 24);
        assert_eq!(DATA_OFF, 48);
    }

    #[test]
    fn lookup_colliding_hashes() {
        let mut mem = vec![0u64; 1 << 16];
        let zone = zone(&mut mem, 1000);
        let l = limit(&zone, 5, 0);

        // the same hash for all keys: the keys order the nodes
        let keys: Vec<Vec<u8>> = (0..50u32).map(|i| format!("key{}", (i * 7919) % 50).into_bytes()).collect();

        for k in &keys {
            assert_eq!(lookup(&l, 42, k, true), (NGX_OK, 0));
        }

        for k in &keys {
            let lr = find(&l, 42, k);
            assert!(!lr.is_null());
            assert_eq!(unsafe { lr_data(lr) }, k.as_slice());
        }

        assert!(find(&l, 42, b"key50").is_null());
        assert!(find(&l, 43, b"key1").is_null());
        assert_eq!(queue_len(&l), 50);

        // found again: one more request within the same millisecond or so
        let (rc, excess) = lookup(&l, 42, b"key7", true);
        assert_eq!(rc, NGX_OK);
        assert!(excess > 0 && excess <= 1000);

        // the node found goes to the head of the queue
        let ctx = zone_ctx(&l);
        unsafe {
            let head = queue_head(addr_of!((*ctx.sh.get()).queue));
            assert_eq!(lr_of_queue(head), find(&l, 42, b"key7"));
        }
    }

    #[test]
    fn excess_arithmetic() {
        let mut mem = vec![0u64; 1 << 16];
        // rate=2r/s
        let zone = zone(&mut mem, 2000);
        let l = limit(&zone, 1, 0);

        assert_eq!(lookup(&l, 1, b"k", true), (NGX_OK, 0));

        let lr = find(&l, 1, b"k");

        unsafe {
            // 250ms ago with excess 1.500: 1500 - 2000 * 250 / 1000 + 1000
            (*lr).excess = 1500;
            (*lr).last = current_msec() - 250;
        }

        let (rc, excess) = lookup(&l, 1, b"k", false);

        // more than the burst: rejected, the node is not changed
        assert_eq!(rc, NGX_BUSY);
        assert!((1996..=2000).contains(&excess), "{}", excess);
        assert_eq!(unsafe { (*lr).excess }, 1500);

        unsafe {
            // 2s ago: negative excess is 0, then the request counts
            (*lr).excess = 1500;
            (*lr).last = current_msec() - 2000;
        }

        assert_eq!(lookup(&l, 1, b"k", true), (NGX_OK, 0));
        assert_eq!(unsafe { (*lr).excess }, 0);

        let l = limit(&zone, 5, 0);

        unsafe {
            // time went backwards by more than a minute: ms = 1
            (*lr).excess = 900;
            (*lr).last = current_msec() + 120000;
        }

        assert_eq!(lookup(&l, 1, b"k", true), (NGX_OK, 1898));
        // ...and last is set again
        assert!(unsafe { (*lr).last } <= current_msec());

        unsafe {
            // backwards by less than a minute: ms = 0, last is kept
            (*lr).excess = 100;
            (*lr).last = current_msec() + 30000;
        }

        assert_eq!(lookup(&l, 1, b"k", true), (NGX_OK, 1100));
        assert!(unsafe { (*lr).last } > current_msec());
    }

    #[test]
    fn account_takes_the_maximum_delay() {
        let mut mem1 = vec![0u64; 1 << 16];
        let mut mem2 = vec![0u64; 1 << 16];
        let mut mem3 = vec![0u64; 1 << 16];

        // 1r/s, 2r/s, 30r/m
        let z1 = zone(&mut mem1, 1000);
        let z2 = zone(&mut mem2, 2000);
        let z3 = zone(&mut mem3, 500);

        let limits = vec![limit(&z1, 10, 0), limit(&z2, 10, 1), limit(&z3, 10, 0)];

        for l in &limits {
            assert_eq!(lookup(l, 7, b"k", true), (NGX_OK, 0));
        }

        let now = current_msec();

        unsafe {
            (*find(&limits[0], 7, b"k")).excess = 2000;
            (*find(&limits[0], 7, b"k")).last = now;
            (*find(&limits[1], 7, b"k")).excess = 3000;
            (*find(&limits[1], 7, b"k")).last = now;
        }

        // the first two limits are looked up without accounting
        let (rc, excess) = lookup(&limits[0], 7, b"k", false);
        assert_eq!(rc, NGX_AGAIN);
        assert!(excess > 2900 && excess <= 3000);
        let (rc, _) = lookup(&limits[1], 7, b"k", false);
        assert_eq!(rc, NGX_AGAIN);

        assert_eq!(unsafe { (*find(&limits[0], 7, b"k")).count }, 1);

        // the last limit: 1.000 excess (2000ms at 30r/m)
        unsafe {
            (*find(&limits[2], 7, b"k")).last = current_msec();
        }
        let (rc, mut excess) = lookup(&limits[2], 7, b"k", true);
        assert_eq!((rc, excess), (NGX_OK, 1000));

        let mut limit = 2;

        let delay = limit_req_account(&limits, 2, &mut excess, &mut limit);

        // limit 0: (3000 - 0) * 1000 / 1000 = 3000ms (a millisecond may
        // have passed); limit 1: (4000 - 1000) * 1000 / 2000 = 1500ms;
        // limit 2: 1000 * 1000 / 500 = 2000ms
        assert_eq!(limit, 0);
        assert!((2998..=3000).contains(&delay), "{}", delay);
        assert!((2998..=3000).contains(&excess), "{}", excess);

        for l in &limits[..2] {
            let lr = find(l, 7, b"k");
            assert_eq!(unsafe { (*lr).count }, 0);
            assert!(zone_ctx(l).node.get().is_null());
        }

        assert_eq!(unsafe { (*find(&limits[1], 7, b"k")).excess } / 10, 400);
    }

    #[test]
    fn unlock_decrements_counts() {
        let mut mem1 = vec![0u64; 1 << 16];
        let mut mem2 = vec![0u64; 1 << 16];
        let z1 = zone(&mut mem1, 1000);
        let z2 = zone(&mut mem2, 1000);
        let limits = vec![limit(&z1, 0, 0), limit(&z2, 0, 0)];

        assert_eq!(lookup(&limits[0], 3, b"a", false).0, NGX_AGAIN);
        assert_eq!(unsafe { (*find(&limits[0], 3, b"a")).count }, 1);
        // a new node looked up without accounting has last = 0
        assert_eq!(unsafe { (*find(&limits[0], 3, b"a")).last }, 0);

        limit_req_unlock(&limits, 1);

        assert_eq!(unsafe { (*find(&limits[0], 3, b"a")).count }, 0);
        assert!(zone_ctx(&limits[0]).node.get().is_null());
    }

    #[test]
    fn expire_old_and_forced() {
        let mut mem = vec![0u64; 1 << 16];
        let zone = zone(&mut mem, 1000);
        let l = limit(&zone, 5, 0);
        let ctx = zone_ctx(&l);

        for k in [b"a", b"b", b"c", b"d"] {
            assert_eq!(lookup(&l, 9, k, true).0, NGX_OK);
        }

        // "a" is the oldest: nothing expires while it is recent
        unsafe { limit_req_expire(&ctx, 1) };
        assert_eq!(queue_len(&l), 4);

        let now = current_msec();

        unsafe {
            (*find(&l, 9, b"a")).last = now - 61000;
            (*find(&l, 9, b"b")).last = now - 61000;
            (*find(&l, 9, b"b")).excess = 100000;
            (*find(&l, 9, b"c")).last = now - 61000;
        }

        // "a" expires; "b" still has excess after 61s at 1r/s
        unsafe { limit_req_expire(&ctx, 1) };
        assert!(find(&l, 9, b"a").is_null());
        assert!(!find(&l, 9, b"b").is_null());
        assert_eq!(queue_len(&l), 3);

        // by force: the oldest ("b") goes, then "c" (61s, no excess)
        unsafe { limit_req_expire(&ctx, 0) };
        assert!(find(&l, 9, b"b").is_null());
        assert!(find(&l, 9, b"c").is_null());
        assert!(!find(&l, 9, b"d").is_null());

        // a node in use (count) stops the expiration
        assert_eq!(lookup(&l, 9, b"d", false).0, NGX_AGAIN);
        unsafe { limit_req_expire(&ctx, 0) };
        assert!(!find(&l, 9, b"d").is_null());
        limit_req_unlock(std::slice::from_ref(&l), 1);
        unsafe { limit_req_expire(&ctx, 0) };
        assert!(find(&l, 9, b"d").is_null());
        assert_eq!(queue_len(&l), 0);
    }

    #[test]
    fn no_memory() {
        // the smallest zone: 8 pages
        let mut mem = vec![0u64; ngx_core::os::pagesize()];
        let zone = zone(&mut mem, 1000);
        let l = limit(&zone, 5, 0);

        let key = |n: u32| format!("{:0>1000}", n).into_bytes();

        // accounted nodes are not in use: the oldest one is expired by
        // force when there is no room for a new one
        for n in 0..100 {
            assert_eq!(lookup(&l, n, &key(n), true).0, NGX_OK);
        }

        let kept = queue_len(&l);
        assert!(kept > 1 && kept < 100, "{}", kept);
        assert!(find(&l, 0, &key(0)).is_null());
        assert!(!find(&l, 99, &key(99)).is_null());

        // nodes in use are not expired: "could not allocate node"
        let mut n = 100;
        loop {
            let (rc, _) = lookup(&l, n, &key(n), false);
            if rc == NGX_ERROR {
                break;
            }
            assert_eq!(rc, NGX_AGAIN);
            n += 1;
            assert!(n < 300);
        }

        assert!(n > 100);
    }
}
