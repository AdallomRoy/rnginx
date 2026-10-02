//! ngx_http_limit_req_module: the rate of requests per key (a leaky
//! bucket), kept in a shared memory zone: an rbtree of the keys and an LRU
//! queue to expire them.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::shmem::queue;
use ngx_core::shmem::rbtree::{self as rb, RbNode, RbTree, ShmRbtree};
use ngx_core::shmem::slab::SlabPool;
use ngx_core::shmem::ShmMem;
use ngx_core::string::B;
use ngx_core::times::current_msec;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error, shm_struct};

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

shm_struct! {
    /// ngx_http_limit_req_node_t: it starts at the color of the rbtree node
    struct LimitReqNode {
        color: u8,
        dummy: u8,
        len: u16,
        /// ngx_queue_t queue
        queue_prev: usize,
        queue_next: usize,
        /// ngx_msec_t
        last: u64,
        /// integer value, 1 corresponds to 0.001 r/s
        excess: usize,
        count: usize,
        /// the key, len bytes
        data: u8,
    }
}

shm_struct! {
    /// ngx_http_limit_req_shctx_t: the rbtree, its sentinel node, then the
    /// LRU queue of the nodes
    struct LimitReqShctx {
        rbtree_root: usize,
        rbtree_sentinel: usize,
        rbtree_insert: usize,
        sentinel_key: usize,
        sentinel_left: usize,
        sentinel_right: usize,
        sentinel_parent: usize,
        sentinel_color: u8,
        sentinel_data: u8,
        queue_prev: usize,
        queue_next: usize,
    }
}

/// ngx_http_limit_req_ctx_t
pub struct LimitReqCtx {
    /// ctx->sh: the offset of the shctx in the zone
    sh: Cell<usize>,
    /// the zone's memory, its slab pool at the start (ctx->shpool)
    mem: RefCell<Option<Rc<ShmMem>>>,
    /// integer value, 1 corresponds to 0.001 r/s
    rate: usize,
    key: ComplexValue,
    /// ctx->node: the offset of the ngx_http_limit_req_node_t looked up
    /// without accounting, 0 for NULL
    node: Cell<usize>,
}

impl LimitReqCtx {
    fn mem(&self) -> Rc<ShmMem> {
        self.mem.borrow().clone().expect("limit_req zone memory")
    }

    /// &ctx->sh->rbtree
    fn rbtree<'a>(&self, mem: &'a ShmMem) -> ShmRbtree<'a> {
        ShmRbtree::at(mem, self.sh.get() + LimitReqShctx::rbtree_root.off)
    }

    /// &ctx->sh->queue
    fn queue(&self) -> usize {
        self.sh.get() + LimitReqShctx::queue_prev.off
    }
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

const COLOR_OFF: usize = RbNode::color.off;

const DATA_OFF: usize = LimitReqNode::data.off;

/// offsetof(ngx_http_limit_req_node_t, queue)
const QUEUE_OFF: usize = LimitReqNode::queue_prev.off;

/// (ngx_http_limit_req_node_t *) &node->color
fn lr_of(mem: &ShmMem, node: usize) -> LimitReqNode<'_> {
    LimitReqNode::at(mem, node + COLOR_OFF)
}

/// (ngx_rbtree_node_t *) ((u_char *) lr - offsetof(ngx_rbtree_node_t, color))
fn node_of(lr: LimitReqNode<'_>) -> usize {
    lr.off - COLOR_OFF
}

/// ngx_queue_data(q, ngx_http_limit_req_node_t, queue)
fn lr_of_queue(mem: &ShmMem, q: usize) -> LimitReqNode<'_> {
    LimitReqNode::at(mem, q - QUEUE_OFF)
}

/// lr->data, lr->len
fn lr_data(lr: LimitReqNode<'_>) -> Vec<u8> {
    lr.mem.bytes(lr.field(LimitReqNode::data), lr.get(LimitReqNode::len) as usize)
}

/// ngx_memn2cmp(key, lr->data, key.len, lr->len), without copying lr->data
fn lr_cmp(key: &[u8], lr: LimitReqNode<'_>) -> i32 {
    let len = lr.get(LimitReqNode::len) as usize;
    let n = key.len().min(len);

    match lr.mem.cmp_bytes(lr.field(LimitReqNode::data), &key[..n]) {
        std::cmp::Ordering::Greater => -1,
        std::cmp::Ordering::Less => 1,
        std::cmp::Ordering::Equal => match key.len().cmp(&len) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        },
    }
}

/// The zone's context: shm_zone->data, set by limit_req_zone (a zone that
/// no limit_req_zone declared has no size, and the configuration fails).
fn zone_ctx(limit: &LimitReqLimit) -> Rc<LimitReqCtx> {
    limit.shm_zone.data::<LimitReqCtx>().expect("limit_req zone without data")
}

/// ngx_http_limit_req_handler
/// limit_req_handler declines at once: a status set before, or no
/// limit_req for the location
fn limit_req_idle(r: &R) -> bool {
    r.main().limit_req_status.get() != 0
        || r.loc_conf::<LimitReqConf>(ctx_index()).borrow().limits.as_deref().is_none_or(|l| l.is_empty())
}

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

        // the key is looked up where it is (a variable's cached value):
        // None for an empty or too long key
        let looked_up = with_complex_value(&r, &ctx.key, |key| {
            if key.is_empty() {
                return None;
            }

            if key.len() > 65535 {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "the value of the \"{}\" key is more than 65535 bytes: \"{}\"", B(&ctx.key.value), B(key));
                return None;
            }

            let hash = crc32fast::hash(key);

            let mem = ctx.mem();
            let shpool = SlabPool::of(&mem);

            shpool.lock();

            // the zone's rbtree and queue are used under its mutex
            let rc = limit_req_lookup(&limits[n], hash, key, &mut excess, n == limits.len() - 1);

            shpool.unlock();

            Some(rc)
        });

        rc = match looked_up {
            Ok(Some(rc)) => rc,
            Ok(None) => {
                n += 1;
                continue;
            }
            Err(_) => {
                limit_req_unlock(limits, n);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        };

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
    // HTTP/2 stream only tests c->error, which the stream's read events
    // set (see crate::v2::stream::terminate_request_now)
    let closed = if r.stream.borrow().is_some() && r.connection.error.get() {
        Some(0)
    } else {
        let watch = TestReading::new(r);
        let _stream = StreamTestReading::new(r);

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

/// r->read_event_handler = ngx_http_test_reading on an HTTP/2 stream, for
/// the time of the delay
struct StreamTestReading(Option<Rc<crate::v2::H2Stream>>);

impl StreamTestReading {
    fn new(r: &R) -> StreamTestReading {
        let stream = crate::v2::stream::request_stream(r);

        if let Some(s) = &stream {
            *s.test_reading.borrow_mut() = Some(Rc::downgrade(r));
        }

        StreamTestReading(stream)
    }
}

impl Drop for StreamTestReading {
    fn drop(&mut self) {
        if let Some(s) = &self.0 {
            s.test_reading.borrow_mut().take();
        }
    }
}

/// ngx_http_limit_req_rbtree_insert_value
fn limit_req_rbtree_insert_value(tree: &ShmRbtree<'_>, temp: usize, node: usize, sentinel: usize) {
    rb::insert_by(tree, temp, node, sentinel, |t, node, temp| {
        let (nk, tk) = (t.key(node), t.key(temp));

        if nk != tk {
            return nk < tk;
        }

        // node->key == temp->key

        lr_cmp(&lr_data(lr_of(t.mem, node)), lr_of(t.mem, temp)) < 0
    });
}

/// ngx_http_limit_req_lookup (the zone's mutex is locked)
fn limit_req_lookup(limit: &LimitReqLimit, hash: u32, key: &[u8], ep: &mut usize, account: bool) -> i64 {
    let now = current_msec();

    let ctx = zone_ctx(limit);

    let mem = ctx.mem();
    let tree = ctx.rbtree(&mem);

    let mut node = tree.root();
    let sentinel = tree.sentinel();

    let hash = hash as usize;

    while node != sentinel {
        let k = tree.key(node);

        if hash < k {
            node = tree.left(node);
            continue;
        }

        if hash > k {
            node = tree.right(node);
            continue;
        }

        // hash == node->key

        let lr = lr_of(&mem, node);

        let rc = lr_cmp(key, lr);

        if rc == 0 {
            let q = lr.field(LimitReqNode::queue_prev);

            queue::remove(&mem, q);
            queue::insert_head(&mem, ctx.queue(), q);

            let mut ms = now.wrapping_sub(lr.get(LimitReqNode::last)) as i64;

            if ms < -60000 {
                ms = 1;
            } else if ms < 0 {
                ms = 0;
            }

            let mut excess = lr.get(LimitReqNode::excess).wrapping_sub(ctx.rate.wrapping_mul(ms as usize) / 1000).wrapping_add(1000) as isize;

            if excess < 0 {
                excess = 0;
            }

            *ep = excess as usize;

            if excess as usize > limit.burst {
                return NGX_BUSY;
            }

            if account {
                lr.set(LimitReqNode::excess, excess as usize);

                if ms != 0 {
                    lr.set(LimitReqNode::last, now);
                }

                return NGX_OK;
            }

            lr.set(LimitReqNode::count, lr.get(LimitReqNode::count).wrapping_add(1));

            ctx.node.set(lr.off);

            return NGX_AGAIN;
        }

        node = if rc < 0 { tree.left(node) } else { tree.right(node) };
    }

    *ep = 0;

    let size = COLOR_OFF + DATA_OFF + key.len();

    limit_req_expire(&ctx, 1);

    let shpool = SlabPool::of(&mem);

    let mut node = shpool.alloc_locked(size);

    if node == 0 {
        limit_req_expire(&ctx, 0);

        node = shpool.alloc_locked(size);
        if node == 0 {
            if let Some(cycle) = ngx_core::cycle::try_cycle() {
                ngx_log_error!(NGX_LOG_ALERT, cycle.log, None, "could not allocate node{}", B(&shpool.log_ctx()));
            }
            return NGX_ERROR;
        }
    }

    tree.set_key(node, hash);

    let lr = lr_of(&mem, node);

    lr.set(LimitReqNode::len, key.len() as u16);
    lr.set(LimitReqNode::excess, 0);

    mem.write(lr.field(LimitReqNode::data), key);

    rb::insert(&tree, node, limit_req_rbtree_insert_value);

    queue::insert_head(&mem, ctx.queue(), lr.field(LimitReqNode::queue_prev));

    if account {
        lr.set(LimitReqNode::last, now);
        lr.set(LimitReqNode::count, 0);
        return NGX_OK;
    }

    lr.set(LimitReqNode::last, 0);
    lr.set(LimitReqNode::count, 1);

    ctx.node.set(lr.off);

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

        if ctx.node.get() == 0 {
            continue;
        }

        // ctx->node is a node of the zone, not expired while its count is
        // not zero; it is changed under the zone's mutex
        let mem = ctx.mem();
        let shpool = SlabPool::of(&mem);
        let lr = LimitReqNode::at(&mem, ctx.node.get());

        shpool.lock();

        let now = current_msec();
        let mut ms = now.wrapping_sub(lr.get(LimitReqNode::last)) as i64;

        if ms < -60000 {
            ms = 1;
        } else if ms < 0 {
            ms = 0;
        }

        excess = lr.get(LimitReqNode::excess).wrapping_sub(ctx.rate.wrapping_mul(ms as usize) / 1000).wrapping_add(1000) as isize;

        if excess < 0 {
            excess = 0;
        }

        if ms != 0 {
            lr.set(LimitReqNode::last, now);
        }

        lr.set(LimitReqNode::excess, excess as usize);
        lr.set(LimitReqNode::count, lr.get(LimitReqNode::count).wrapping_sub(1));

        shpool.unlock();

        ctx.node.set(0);

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

        if ctx.node.get() == 0 {
            continue;
        }

        // as in limit_req_account
        let mem = ctx.mem();
        let shpool = SlabPool::of(&mem);
        let lr = LimitReqNode::at(&mem, ctx.node.get());

        shpool.lock();

        lr.set(LimitReqNode::count, lr.get(LimitReqNode::count).wrapping_sub(1));

        shpool.unlock();

        ctx.node.set(0);
    }
}

/// ngx_http_limit_req_expire (the zone's mutex is locked)
fn limit_req_expire(ctx: &LimitReqCtx, mut n: usize) {
    let now = current_msec();

    let mem = ctx.mem();
    let tree = ctx.rbtree(&mem);
    let head = ctx.queue();

    // n == 1 deletes one or two zero rate entries
    // n == 0 deletes oldest entry by force
    //        and one or two zero rate entries

    while n < 3 {
        if queue::empty(&mem, head) {
            return;
        }

        let q = queue::last(&mem, head);

        let lr = lr_of_queue(&mem, q);

        if lr.get(LimitReqNode::count) != 0 {
            // There is not much sense in looking further,
            // because we bump nodes on the lookup stage.

            return;
        }

        let force = n == 0;

        n += 1;

        if !force {
            let ms = (now.wrapping_sub(lr.get(LimitReqNode::last)) as i64).wrapping_abs();

            if ms < 60000 {
                return;
            }

            let excess = lr.get(LimitReqNode::excess).wrapping_sub(ctx.rate.wrapping_mul(ms as usize) / 1000) as isize;

            if excess > 0 {
                return;
            }
        }

        queue::remove(&mem, q);

        let node = node_of(lr);

        rb::delete(&tree, node);

        SlabPool::of(&mem).free_locked(node);
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
        *ctx.mem.borrow_mut() = octx.mem.borrow().clone();

        return Ok(());
    }

    let mem = shm_zone.mem();
    let shpool = SlabPool::of(&mem);

    *ctx.mem.borrow_mut() = Some(mem.clone());

    if shm_zone.shm.exists.get() {
        ctx.sh.set(shpool.data());
        return Ok(());
    }

    let sh = shpool.alloc(LimitReqShctx::SIZE);
    if sh == 0 {
        return Err(());
    }

    ctx.sh.set(sh);

    shpool.set_data(sh);

    ctx.rbtree(&mem).init(LimitReqShctx::at(&mem, sh).field(LimitReqShctx::sentinel_key));

    queue::init(&mem, ctx.queue());

    let log_ctx = format!(" in limit_req zone \"{}\"", B(shm_zone.name()));

    shpool.set_log_ctx(log_ctx.as_bytes())?;

    shpool.set_log_nomem(false);

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

    let ctx = Rc::new(LimitReqCtx { sh: Cell::new(0), mem: RefCell::new(None), rate, key, node: Cell::new(0) });

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

    limits.push(LimitReqLimit { shm_zone, burst: burst.wrapping_mul(1000) as usize, delay: delay.wrapping_mul(1000) as usize });

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
    add_phase_handler(cf, NGX_HTTP_PREACCESS_PHASE, crate::core::phase_handler(limit_req_idle, limit_req_handler));
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

    use ngx_core::shmem::{Field, ShmValue};

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

    /// A zone of `size` bytes with its slab pool, initialized by the zone
    /// init.
    fn zone_of(size: usize, rate: usize) -> Rc<ShmZone> {
        let mem = Rc::new(ShmMem::private(size).unwrap());
        SlabPool::init_zone(&mem);

        let zone = ShmZone::new(b"test".to_vec(), mem.len(), TAG);
        zone.shm.attach(mem);

        let ctx = Rc::new(LimitReqCtx { sh: Cell::new(0), mem: RefCell::new(None), rate, key: ComplexValue::constant(b"$binary_remote_addr"), node: Cell::new(0) });

        *zone.data.borrow_mut() = Some(ctx);

        limit_req_init_zone(&zone, None).unwrap();

        zone
    }

    fn zone(rate: usize) -> Rc<ShmZone> {
        zone_of(1 << 19, rate)
    }

    fn limit(zone: &Rc<ShmZone>, burst: usize, delay: usize) -> LimitReqLimit {
        LimitReqLimit { shm_zone: zone.clone(), burst: burst * 1000, delay: delay * 1000 }
    }

    fn lookup(limit: &LimitReqLimit, hash: u32, key: &[u8], account: bool) -> (i64, usize) {
        let mut excess = 0;
        let rc = limit_req_lookup(limit, hash, key, &mut excess, account);
        (rc, excess)
    }

    /// The node of a key (its ngx_http_limit_req_node_t), walking the tree
    /// as ngx_http_limit_req_lookup; 0 if none.
    fn find(limit: &LimitReqLimit, hash: u32, key: &[u8]) -> usize {
        let ctx = zone_ctx(limit);
        let mem = ctx.mem();
        let tree = ctx.rbtree(&mem);
        let mut node = tree.root();
        let sentinel = tree.sentinel();
        while node != sentinel {
            if (hash as usize) < tree.key(node) {
                node = tree.left(node);
                continue;
            }
            if (hash as usize) > tree.key(node) {
                node = tree.right(node);
                continue;
            }
            let lr = lr_of(&mem, node);
            match memn2cmp(key, &lr_data(lr)) {
                0 => return lr.off,
                rc if rc < 0 => node = tree.left(node),
                _ => node = tree.right(node),
            }
        }
        0
    }

    /// A field of the node of a key.
    fn get<T: ShmValue>(limit: &LimitReqLimit, hash: u32, key: &[u8], f: Field<T>) -> T {
        let lr = find(limit, hash, key);
        assert!(lr != 0, "no node {:?}", key);
        LimitReqNode::at(&zone_ctx(limit).mem(), lr).get(f)
    }

    /// Sets a field of the node of a key.
    fn set<T: ShmValue>(limit: &LimitReqLimit, hash: u32, key: &[u8], f: Field<T>, v: T) {
        let lr = find(limit, hash, key);
        assert!(lr != 0, "no node {:?}", key);
        LimitReqNode::at(&zone_ctx(limit).mem(), lr).set(f, v)
    }

    fn queue_len(limit: &LimitReqLimit) -> usize {
        let ctx = zone_ctx(limit);
        queue::walk(&ctx.mem(), ctx.queue()).len()
    }

    #[test]
    fn memn2cmp_as_c() {
        assert_eq!(memn2cmp(b"abc", b"abc"), 0);
        assert!(memn2cmp(b"ab", b"abc") < 0);
        assert!(memn2cmp(b"abc", b"ab") > 0);
        assert!(memn2cmp(b"abd", b"abc") > 0);
        assert!(memn2cmp(b"b", b"abc") > 0);
        assert!(memn2cmp(b"", b"a") < 0);

        let mem = ShmMem::private(4096).unwrap();
        let lr = LimitReqNode::at(&mem, 64);
        for (a, b) in [(&b"abc"[..], &b"abc"[..]), (b"ab", b"abc"), (b"abc", b"ab"), (b"abd", b"abc"), (b"b", b"abc"), (b"", b"a")] {
            lr.set(LimitReqNode::len, b.len() as u16);
            mem.write(lr.field(LimitReqNode::data), b);
            assert_eq!(lr_cmp(a, lr), memn2cmp(a, b), "{:?} {:?}", a, b);
            assert_eq!(lr_data(lr), b);
        }
    }

    #[test]
    fn node_layout_as_c() {
        // offsetof(ngx_rbtree_node_t, color) + offsetof(ngx_http_limit_req_node_t, data)
        assert_eq!(COLOR_OFF, 32);
        assert_eq!(QUEUE_OFF, 8);
        assert_eq!(LimitReqNode::last.off, 24);
        assert_eq!(LimitReqNode::excess.off, 32);
        assert_eq!(LimitReqNode::count.off, 40);
        assert_eq!(DATA_OFF, 48);
        // sizeof(ngx_http_limit_req_shctx_t)
        assert_eq!(LimitReqShctx::SIZE, 80);
        assert_eq!(LimitReqShctx::sentinel_key.off, 24);
        assert_eq!(LimitReqShctx::queue_prev.off, 64);
    }

    #[test]
    fn lookup_colliding_hashes() {
        let zone = zone(1000);
        let l = limit(&zone, 5, 0);

        // the same hash for all keys: the keys order the nodes
        let keys: Vec<Vec<u8>> = (0..50u32).map(|i| format!("key{}", (i * 7919) % 50).into_bytes()).collect();

        for k in &keys {
            assert_eq!(lookup(&l, 42, k, true), (NGX_OK, 0));
        }

        let ctx = zone_ctx(&l);
        let mem = ctx.mem();

        for k in &keys {
            let lr = find(&l, 42, k);
            assert!(lr != 0);
            assert_eq!(lr_data(LimitReqNode::at(&mem, lr)), k.as_slice());
        }

        assert_eq!(find(&l, 42, b"key50"), 0);
        assert_eq!(find(&l, 43, b"key1"), 0);
        assert_eq!(queue_len(&l), 50);

        // in order: the walk of the tree gives the keys sorted
        let tree = ctx.rbtree(&mem);
        let walked: Vec<Vec<u8>> = rb::walk(&tree).into_iter().map(|n| lr_data(lr_of(&mem, n))).collect();
        let mut sorted = walked.clone();
        sorted.sort_by(|a, b| memn2cmp(a, b).cmp(&0));
        assert_eq!(walked, sorted);

        // found again: one more request within the same millisecond or so
        let (rc, excess) = lookup(&l, 42, b"key7", true);
        assert_eq!(rc, NGX_OK);
        assert!(excess > 0 && excess <= 1000);

        // the node found goes to the head of the queue
        assert_eq!(lr_of_queue(&mem, queue::head(&mem, ctx.queue())).off, find(&l, 42, b"key7"));
    }

    #[test]
    fn excess_arithmetic() {
        // rate=2r/s
        let zone = zone(2000);
        let l = limit(&zone, 1, 0);

        assert_eq!(lookup(&l, 1, b"k", true), (NGX_OK, 0));

        // 250ms ago with excess 1.500: 1500 - 2000 * 250 / 1000 + 1000
        set(&l, 1, b"k", LimitReqNode::excess, 1500);
        set(&l, 1, b"k", LimitReqNode::last, current_msec() - 250);

        let (rc, excess) = lookup(&l, 1, b"k", false);

        // more than the burst: rejected, the node is not changed
        assert_eq!(rc, NGX_BUSY);
        assert!((1996..=2000).contains(&excess), "{}", excess);
        assert_eq!(get(&l, 1, b"k", LimitReqNode::excess), 1500);

        // 2s ago: negative excess is 0, then the request counts
        set(&l, 1, b"k", LimitReqNode::excess, 1500);
        set(&l, 1, b"k", LimitReqNode::last, current_msec() - 2000);

        assert_eq!(lookup(&l, 1, b"k", true), (NGX_OK, 0));
        assert_eq!(get(&l, 1, b"k", LimitReqNode::excess), 0);

        let l = limit(&zone, 5, 0);

        // time went backwards by more than a minute: ms = 1
        set(&l, 1, b"k", LimitReqNode::excess, 900);
        set(&l, 1, b"k", LimitReqNode::last, current_msec() + 120000);

        assert_eq!(lookup(&l, 1, b"k", true), (NGX_OK, 1898));
        // ...and last is set again
        assert!(get(&l, 1, b"k", LimitReqNode::last) <= current_msec());

        // backwards by less than a minute: ms = 0, last is kept
        set(&l, 1, b"k", LimitReqNode::excess, 100);
        set(&l, 1, b"k", LimitReqNode::last, current_msec() + 30000);

        assert_eq!(lookup(&l, 1, b"k", true), (NGX_OK, 1100));
        assert!(get(&l, 1, b"k", LimitReqNode::last) > current_msec());
    }

    #[test]
    fn account_takes_the_maximum_delay() {
        // 1r/s, 2r/s, 30r/m
        let z1 = zone(1000);
        let z2 = zone(2000);
        let z3 = zone(500);

        let limits = vec![limit(&z1, 10, 0), limit(&z2, 10, 1), limit(&z3, 10, 0)];

        for l in &limits {
            assert_eq!(lookup(l, 7, b"k", true), (NGX_OK, 0));
        }

        let now = current_msec();

        set(&limits[0], 7, b"k", LimitReqNode::excess, 2000);
        set(&limits[0], 7, b"k", LimitReqNode::last, now);
        set(&limits[1], 7, b"k", LimitReqNode::excess, 3000);
        set(&limits[1], 7, b"k", LimitReqNode::last, now);

        // the first two limits are looked up without accounting
        let (rc, excess) = lookup(&limits[0], 7, b"k", false);
        assert_eq!(rc, NGX_AGAIN);
        assert!(excess > 2900 && excess <= 3000);
        let (rc, _) = lookup(&limits[1], 7, b"k", false);
        assert_eq!(rc, NGX_AGAIN);

        assert_eq!(get(&limits[0], 7, b"k", LimitReqNode::count), 1);
        assert_eq!(zone_ctx(&limits[0]).node.get(), find(&limits[0], 7, b"k"));

        // the last limit: 1.000 excess (2000ms at 30r/m)
        set(&limits[2], 7, b"k", LimitReqNode::last, current_msec());
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
            assert_eq!(get(l, 7, b"k", LimitReqNode::count), 0);
            assert_eq!(zone_ctx(l).node.get(), 0);
        }

        assert_eq!(get(&limits[1], 7, b"k", LimitReqNode::excess) / 10, 400);
    }

    #[test]
    fn unlock_decrements_counts() {
        let z1 = zone(1000);
        let z2 = zone(1000);
        let limits = vec![limit(&z1, 0, 0), limit(&z2, 0, 0)];

        assert_eq!(lookup(&limits[0], 3, b"a", false).0, NGX_AGAIN);
        assert_eq!(get(&limits[0], 3, b"a", LimitReqNode::count), 1);
        // a new node looked up without accounting has last = 0
        assert_eq!(get(&limits[0], 3, b"a", LimitReqNode::last), 0);

        limit_req_unlock(&limits, 1);

        assert_eq!(get(&limits[0], 3, b"a", LimitReqNode::count), 0);
        assert_eq!(zone_ctx(&limits[0]).node.get(), 0);
    }

    #[test]
    fn expire_old_and_forced() {
        let zone = zone(1000);
        let l = limit(&zone, 5, 0);
        let ctx = zone_ctx(&l);
        let pfree = SlabPool::of(&ctx.mem()).pfree();

        for k in [b"a", b"b", b"c", b"d"] {
            assert_eq!(lookup(&l, 9, k, true).0, NGX_OK);
        }

        // "a" is the oldest: nothing expires while it is recent
        limit_req_expire(&ctx, 1);
        assert_eq!(queue_len(&l), 4);

        let now = current_msec();

        set(&l, 9, b"a", LimitReqNode::last, now - 61000);
        set(&l, 9, b"b", LimitReqNode::last, now - 61000);
        set(&l, 9, b"b", LimitReqNode::excess, 100000);
        set(&l, 9, b"c", LimitReqNode::last, now - 61000);

        // "a" expires; "b" still has excess after 61s at 1r/s
        limit_req_expire(&ctx, 1);
        assert_eq!(find(&l, 9, b"a"), 0);
        assert!(find(&l, 9, b"b") != 0);
        assert_eq!(queue_len(&l), 3);

        // by force: the oldest ("b") goes, then "c" (61s, no excess)
        limit_req_expire(&ctx, 0);
        assert_eq!(find(&l, 9, b"b"), 0);
        assert_eq!(find(&l, 9, b"c"), 0);
        assert!(find(&l, 9, b"d") != 0);

        // a node in use (count) stops the expiration
        assert_eq!(lookup(&l, 9, b"d", false).0, NGX_AGAIN);
        limit_req_expire(&ctx, 0);
        assert!(find(&l, 9, b"d") != 0);
        limit_req_unlock(std::slice::from_ref(&l), 1);
        limit_req_expire(&ctx, 0);
        assert_eq!(find(&l, 9, b"d"), 0);
        assert_eq!(queue_len(&l), 0);

        // every node is freed, the tree is empty
        let mem = ctx.mem();
        let tree = ctx.rbtree(&mem);
        assert_eq!(tree.root(), tree.sentinel());
        assert_eq!(SlabPool::of(&mem).pfree(), pfree);
    }

    #[test]
    fn no_memory() {
        // the smallest zone: 8 pages
        let zone = zone_of(8 * ngx_core::os::pagesize(), 1000);
        let l = limit(&zone, 5, 0);

        let key = |n: u32| format!("{:0>1000}", n).into_bytes();

        // accounted nodes are not in use: the oldest one is expired by
        // force when there is no room for a new one
        for n in 0..100 {
            assert_eq!(lookup(&l, n, &key(n), true).0, NGX_OK);
        }

        let kept = queue_len(&l);
        assert!(kept > 1 && kept < 100, "{}", kept);
        assert_eq!(find(&l, 0, &key(0)), 0);
        assert!(find(&l, 99, &key(99)) != 0);

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

        // the pool does not log "ngx_slab_alloc() failed: no memory"
        assert!(!SlabPool::of(&zone_ctx(&l).mem()).log_nomem());
    }

    /// The tree and the queue hold the same nodes: their number.
    fn check_zone(limit: &LimitReqLimit) -> usize {
        let ctx = zone_ctx(limit);
        let mem = ctx.mem();
        let tree = ctx.rbtree(&mem);

        let mut in_tree: Vec<usize> = rb::walk(&tree).into_iter().map(|n| lr_of(&mem, n).off).collect();
        let mut in_queue: Vec<usize> = queue::walk(&mem, ctx.queue()).into_iter().map(|q| lr_of_queue(&mem, q).off).collect();

        in_tree.sort_unstable();
        in_queue.sort_unstable();
        assert_eq!(in_tree, in_queue);

        // and the tree is ordered by the hash, then by the key
        let keys: Vec<(usize, Vec<u8>)> = rb::walk(&tree).into_iter().map(|n| (tree.key(n), lr_data(lr_of(&mem, n)))).collect();
        for w in keys.windows(2) {
            assert!(w[0].0 < w[1].0 || (w[0].0 == w[1].0 && memn2cmp(&w[0].1, &w[1].1) < 0), "{:?}", w);
        }

        in_tree.len()
    }

    #[test]
    fn random_operations_keep_the_zone_consistent() {
        // a small zone: the nodes are expired to make room
        let zone = zone_of(16 * ngx_core::os::pagesize(), 1000);
        let l = limit(&zone, 3, 0);
        let ctx = zone_ctx(&l);

        let mut seed: u32 = 12345;
        let mut rnd = move || {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            (seed >> 16) & 0x7fff
        };

        let mut max = 0;

        for i in 0..20000 {
            let k = rnd() % 500;
            let key = format!("key-{}-{}", k, "x".repeat((k % 64) as usize)).into_bytes();
            // few hashes: many keys collide
            let hash = crc32fast::hash(&key) % 32;

            match lookup(&l, hash, &key, rnd() % 4 != 0).0 {
                NGX_AGAIN => limit_req_unlock(std::slice::from_ref(&l), 1),
                // NGX_ERROR: the node expired by force was of another
                // size, no room yet ("could not allocate node")
                NGX_OK | NGX_BUSY | NGX_ERROR => {}
                rc => panic!("rc {}", rc),
            }

            assert_eq!(ctx.node.get(), 0);

            if i % 500 == 0 {
                max = max.max(check_zone(&l));

                // some nodes get old
                let mem = ctx.mem();
                for (j, q) in queue::walk(&mem, ctx.queue()).into_iter().enumerate() {
                    if j % 3 == 0 {
                        let lr = lr_of_queue(&mem, q);
                        lr.set(LimitReqNode::last, current_msec().wrapping_sub(120000));
                    }
                }
            }
        }

        assert!(max > 50, "{}", max);
        check_zone(&l);
    }
}
