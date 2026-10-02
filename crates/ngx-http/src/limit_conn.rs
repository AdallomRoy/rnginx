//! ngx_http_limit_conn_module: the number of connections (requests being
//! processed) per key, counted in a shared memory zone.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::shmem::rbtree::{self as rb, RbNode, RbTree, ShmRbtree};
use ngx_core::shmem::slab::SlabPool;
use ngx_core::shmem::ShmMem;
use ngx_core::string::B;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error, shm_struct};

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_limit_conn_module");

const NGX_HTTP_LIMIT_CONN_PASSED: u32 = 1;
const NGX_HTTP_LIMIT_CONN_REJECTED: u32 = 2;
const NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN: u32 = 3;

const TAG: &str = "ngx_http_limit_conn_module";

shm_struct! {
    /// ngx_http_limit_conn_node_t: it starts at the color of the rbtree node
    struct LimitConnNode {
        color: u8,
        len: u8,
        conn: u16,
        /// the key, len bytes
        data: u8,
    }
}

/// ngx_http_limit_conn_cleanup_t
struct LimitConnCleanup {
    shm_zone: Rc<ShmZone>,
    node: usize,
}

shm_struct! {
    /// ngx_http_limit_conn_shctx_t: the rbtree, then its sentinel node
    struct LimitConnShctx {
        rbtree_root: usize,
        rbtree_sentinel: usize,
        rbtree_insert: usize,
        sentinel_key: usize,
        sentinel_left: usize,
        sentinel_right: usize,
        sentinel_parent: usize,
        sentinel_color: u8,
        sentinel_data: u8,
    }
}

/// ngx_http_limit_conn_ctx_t
pub struct LimitConnCtx {
    /// ctx->sh: the offset of the shctx in the zone
    sh: Cell<usize>,
    /// the zone's memory, its slab pool at the start (ctx->shpool)
    mem: RefCell<Option<Rc<ShmMem>>>,
    key: ComplexValue,
}

impl LimitConnCtx {
    fn mem(&self) -> Rc<ShmMem> {
        self.mem.borrow().clone().expect("limit_conn zone memory")
    }

    /// &ctx->sh->rbtree
    fn rbtree<'a>(&self, mem: &'a ShmMem) -> ShmRbtree<'a> {
        ShmRbtree::at(mem, self.sh.get() + LimitConnShctx::rbtree_root.off)
    }
}

/// ngx_http_limit_conn_limit_t
#[derive(Clone)]
pub struct LimitConnLimit {
    shm_zone: Rc<ShmZone>,
    conn: usize,
}

/// ngx_http_limit_conn_conf_t
pub struct LimitConnConf {
    /// None: limits.elts == NULL
    limits: Option<Vec<LimitConnLimit>>,
    log_level: Val<u32>,
    status_code: Val<i64>,
    dry_run: Val<bool>,
}

static LIMIT_CONN_LOG_LEVELS: &[(&str, u32)] = &[("info", NGX_LOG_INFO), ("notice", NGX_LOG_NOTICE), ("warn", NGX_LOG_WARN), ("error", NGX_LOG_ERR)];

static LIMIT_CONN_VARS: &[VarDef] = &[VarDef { name: "limit_conn_status", set: None, get: Some(limit_conn_status_variable), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE }];

static LIMIT_CONN_STATUS: [&str; 3] = ["PASSED", "REJECTED", "REJECTED_DRY_RUN"];

const COLOR_OFF: usize = RbNode::color.off;

const DATA_OFF: usize = LimitConnNode::data.off;

/// (ngx_http_limit_conn_node_t *) &node->color
fn lc_of(mem: &ShmMem, node: usize) -> LimitConnNode<'_> {
    LimitConnNode::at(mem, node + COLOR_OFF)
}

/// lc->data, lc->len
fn lc_data(lc: LimitConnNode<'_>) -> Vec<u8> {
    lc.mem.bytes(lc.field(LimitConnNode::data), lc.get(LimitConnNode::len) as usize)
}

/// ngx_memn2cmp(key, lc->data, key.len, lc->len), without copying lc->data
fn lc_cmp(key: &[u8], lc: LimitConnNode<'_>) -> i32 {
    let len = lc.get(LimitConnNode::len) as usize;
    let n = key.len().min(len);

    match lc.mem.cmp_bytes(lc.field(LimitConnNode::data), &key[..n]) {
        std::cmp::Ordering::Greater => -1,
        std::cmp::Ordering::Less => 1,
        std::cmp::Ordering::Equal => match key.len().cmp(&len) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        },
    }
}

/// ngx_memn2cmp (lc_cmp() is the one on the zone's bytes)
#[cfg(test)]
fn memn2cmp(s1: &[u8], s2: &[u8]) -> i32 {
    let (n, z) = if s1.len() <= s2.len() { (s1.len(), -1) } else { (s2.len(), 1) };

    match s1[..n].cmp(&s2[..n]) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Greater => 1,
        std::cmp::Ordering::Equal if s1.len() == s2.len() => 0,
        std::cmp::Ordering::Equal => z,
    }
}

/// The zone's context: shm_zone->data, set by limit_conn_zone (a zone that
/// no limit_conn_zone declared has no size, and the configuration fails).
fn zone_ctx(shm_zone: &ShmZone) -> Rc<LimitConnCtx> {
    shm_zone.data::<LimitConnCtx>().expect("limit_conn zone without data")
}

/// ngx_http_limit_conn_handler
async fn limit_conn_handler(r: R) -> i64 {
    let main = r.main();

    if main.limit_conn_status.get() != 0 {
        return NGX_DECLINED;
    }

    let lccf_cell = r.loc_conf::<LimitConnConf>(ctx_index());
    let lccf = lccf_cell.borrow();

    let limits: &[LimitConnLimit] = lccf.limits.as_deref().unwrap_or(&[]);

    // the cleanups added to r->pool (the main request's) by this handler
    let mut cleanups: Vec<LimitConnCleanup> = Vec::new();

    for limit in limits {
        let ctx = zone_ctx(&limit.shm_zone);

        let key = match complex_value(&r, &ctx.key) {
            Ok(k) => k,
            Err(_) => {
                pool_cleanup_add(&r, cleanups);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        };

        if key.is_empty() {
            continue;
        }

        if key.len() > 255 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "the value of the \"{}\" key is more than 255 bytes: \"{}\"", B(&ctx.key.value), B(&key));
            continue;
        }

        main.limit_conn_status.set(NGX_HTTP_LIMIT_CONN_PASSED);

        let hash = crc32fast::hash(&key);

        let mem = ctx.mem();
        let shpool = SlabPool::of(&mem);

        shpool.lock();

        // the zone's rbtree and its nodes are used under its mutex
        let tree = ctx.rbtree(&mem);

        let mut node = limit_conn_lookup(&tree, &key, hash);

        if node == 0 {
            let n = COLOR_OFF + DATA_OFF + key.len();

            node = shpool.alloc_locked(n);

            if node == 0 {
                shpool.unlock();
                limit_conn_cleanup_all(&mut cleanups);

                if *lccf.dry_run {
                    main.limit_conn_status.set(NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN);
                    return NGX_DECLINED;
                }

                main.limit_conn_status.set(NGX_HTTP_LIMIT_CONN_REJECTED);

                return *lccf.status_code;
            }

            let lc = lc_of(&mem, node);

            tree.set_key(node, hash as usize);
            lc.set(LimitConnNode::len, key.len() as u8);
            lc.set(LimitConnNode::conn, 1);
            mem.write(lc.field(LimitConnNode::data), &key);

            rb::insert(&tree, node, limit_conn_rbtree_insert_value);
        } else {
            let lc = lc_of(&mem, node);

            if lc.get(LimitConnNode::conn) as usize >= limit.conn {
                shpool.unlock();

                ngx_log_error!(
                    *lccf.log_level,
                    r.connection.log,
                    None,
                    "limiting connections{} by zone \"{}\"",
                    if *lccf.dry_run { ", dry run," } else { "" },
                    B(limit.shm_zone.name())
                );

                limit_conn_cleanup_all(&mut cleanups);

                if *lccf.dry_run {
                    main.limit_conn_status.set(NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN);
                    return NGX_DECLINED;
                }

                main.limit_conn_status.set(NGX_HTTP_LIMIT_CONN_REJECTED);

                return *lccf.status_code;
            }

            lc.set(LimitConnNode::conn, lc.get(LimitConnNode::conn).wrapping_add(1));
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "limit conn: {:08X} {}", tree.key(node), lc_of(&mem, node).get(LimitConnNode::conn));

        shpool.unlock();

        cleanups.push(LimitConnCleanup { shm_zone: limit.shm_zone.clone(), node });
    }

    pool_cleanup_add(&r, cleanups);

    NGX_DECLINED
}

/// ngx_pool_cleanup_add(r->pool) of the handler's cleanups, with
/// ngx_http_limit_conn_cleanup as the handler: the pool of a request is
/// that of its main request; the cleanups run in the order of the pool's
/// list, the last added first.
fn pool_cleanup_add(r: &R, mut cleanups: Vec<LimitConnCleanup>) {
    if cleanups.is_empty() {
        return;
    }

    r.add_pool_cleanup(Box::new(move || {
        while let Some(lccln) = cleanups.pop() {
            limit_conn_cleanup(&lccln);
        }
    }));
}

/// ngx_http_limit_conn_rbtree_insert_value
fn limit_conn_rbtree_insert_value(tree: &ShmRbtree<'_>, temp: usize, node: usize, sentinel: usize) {
    rb::insert_by(tree, temp, node, sentinel, |t, node, temp| {
        let (nk, tk) = (t.key(node), t.key(temp));

        if nk != tk {
            return nk < tk;
        }

        // node->key == temp->key

        lc_cmp(&lc_data(lc_of(t.mem, node)), lc_of(t.mem, temp)) < 0
    });
}

/// ngx_http_limit_conn_lookup: the node of the key, or 0
fn limit_conn_lookup(rbtree: &ShmRbtree<'_>, key: &[u8], hash: u32) -> usize {
    let mut node = rbtree.root();
    let sentinel = rbtree.sentinel();

    let hash = hash as usize;

    while node != sentinel {
        let k = rbtree.key(node);

        if hash < k {
            node = rbtree.left(node);
            continue;
        }

        if hash > k {
            node = rbtree.right(node);
            continue;
        }

        // hash == node->key

        let rc = lc_cmp(key, lc_of(rbtree.mem, node));

        if rc == 0 {
            return node;
        }

        node = if rc < 0 { rbtree.left(node) } else { rbtree.right(node) };
    }

    0
}

/// ngx_http_limit_conn_cleanup
fn limit_conn_cleanup(lccln: &LimitConnCleanup) {
    let ctx = zone_ctx(&lccln.shm_zone);
    let node = lccln.node;

    // the node stays in the zone while its conn is not zero; it is changed
    // under the zone's mutex
    let mem = ctx.mem();
    let shpool = SlabPool::of(&mem);
    let tree = ctx.rbtree(&mem);
    let lc = lc_of(&mem, node);

    shpool.lock();

    if let Some(log) = lccln.shm_zone.shm.log.borrow().as_ref() {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "limit conn cleanup: {:08X} {}", tree.key(node), lc.get(LimitConnNode::conn));
    }

    lc.set(LimitConnNode::conn, lc.get(LimitConnNode::conn).wrapping_sub(1));

    if lc.get(LimitConnNode::conn) == 0 {
        rb::delete(&tree, node);
        shpool.free_locked(node);
    }

    shpool.unlock();
}

/// ngx_http_limit_conn_cleanup_all: the cleanups the handler added, at
/// the head of the pool's list, run and removed
fn limit_conn_cleanup_all(cleanups: &mut Vec<LimitConnCleanup>) {
    while let Some(lccln) = cleanups.pop() {
        limit_conn_cleanup(&lccln);
    }
}

/// ngx_http_limit_conn_init_zone
fn limit_conn_init_zone(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn Any>>) -> Result<(), ()> {
    let ctx = shm_zone.data::<LimitConnCtx>().ok_or(())?;

    if let Some(octx) = data.and_then(|d| d.downcast::<LimitConnCtx>().ok()) {
        if ctx.key.value != octx.key.value {
            if let Some(log) = shm_zone.shm.log.borrow().as_ref() {
                ngx_log_error!(
                    NGX_LOG_EMERG,
                    log,
                    None,
                    "limit_conn_zone \"{}\" uses the \"{}\" key while previously it used the \"{}\" key",
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

    let sh = shpool.alloc(LimitConnShctx::SIZE);
    if sh == 0 {
        return Err(());
    }

    ctx.sh.set(sh);

    shpool.set_data(sh);

    ctx.rbtree(&mem).init(LimitConnShctx::at(&mem, sh).field(LimitConnShctx::sentinel_key));

    let log_ctx = format!(" in limit_conn_zone \"{}\"", B(shm_zone.name()));

    shpool.set_log_ctx(log_ctx.as_bytes())?;

    Ok(())
}

/// ngx_http_limit_conn_status_variable
fn limit_conn_status_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let status = r.main().limit_conn_status.get();

    if status == 0 {
        v.not_found = true;
        return NGX_OK;
    }

    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
    v.data = LIMIT_CONN_STATUS[status as usize - 1].as_bytes().to_vec();

    NGX_OK
}

/// ngx_http_limit_conn_create_conf
fn limit_conn_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitConnConf { limits: None, log_level: Val::unset(), status_code: Val::unset(), dry_run: Val::unset() })
}

/// ngx_http_limit_conn_merge_conf
fn limit_conn_merge_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<LimitConnConf>(parent).borrow();
    let mut conf = conf_cell::<LimitConnConf>(child).borrow_mut();

    if conf.limits.is_none() {
        conf.limits = prev.limits.clone();
    }

    conf.log_level.merge(&prev.log_level, NGX_LOG_ERR);
    conf.status_code.merge(&prev.status_code, NGX_HTTP_SERVICE_UNAVAILABLE);

    conf.dry_run.merge(&prev.dry_run, false);

    Ok(())
}

/// ngx_http_limit_conn_zone
fn limit_conn_zone(cf: &mut Conf, cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let value = cf.args.clone();

    let key = compile_complex_value(cf, &value[1], 0)?;

    let mut size = 0usize;
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

        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(v))));
    }

    if name.is_empty() {
        return Err(cf.emerg(format_args!("\"{}\" must have \"zone\" parameter", cmd.name)));
    }

    let shm_zone = ngx_core::cycle::shared_memory_add(cf, &name, size, TAG)?;

    if let Some(ctx) = shm_zone.data::<LimitConnCtx>() {
        return Err(cf.emerg(format_args!("{} \"{}\" is already bound to key \"{}\"", cmd.name, B(&name), B(&ctx.key.value))));
    }

    let ctx = Rc::new(LimitConnCtx { sh: Cell::new(0), mem: RefCell::new(None), key });

    *shm_zone.init.borrow_mut() = Some(Rc::new(limit_conn_init_zone));
    *shm_zone.data.borrow_mut() = Some(ctx);

    Ok(())
}

/// ngx_http_limit_conn
fn limit_conn(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lccf = conf_rc::<LimitConnConf>(conf.as_ref().expect("conf"));

    let value = cf.args.clone();

    let shm_zone = ngx_core::cycle::shared_memory_add(cf, &value[1], 0, TAG)?;

    let mut l = lccf.borrow_mut();

    let limits = l.limits.get_or_insert_with(Vec::new);

    if limits.iter().any(|lim| Rc::ptr_eq(&lim.shm_zone, &shm_zone)) {
        return Err(msg("is duplicate"));
    }

    let n = ngx_core::string::atoi(&value[2]).unwrap_or(NGX_ERROR);
    if n <= 0 {
        return Err(cf.emerg(format_args!("invalid number of connections \"{}\"", B(&value[2]))));
    }

    if n > 65535 {
        return Err(cf.emerg(format_args!("connection limit must be less 65536")));
    }

    limits.push(LimitConnLimit { shm_zone, conn: n as usize });

    Ok(())
}

/// limit_conn_status: ngx_conf_set_num_slot with
/// ngx_http_limit_conn_status_bounds (ngx_conf_check_num_bounds, 400..599)
fn limit_conn_status(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lccf = conf_rc::<LimitConnConf>(conf.as_ref().expect("conf"));
    let mut l = lccf.borrow_mut();

    set_num(cf, cmd, &mut l.status_code)?;

    check_num_bounds(cf, *l.status_code, 400, 599)
}

/// ngx_http_limit_conn_add_variables
fn limit_conn_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, LIMIT_CONN_VARS)
}

/// ngx_http_limit_conn_init
fn limit_conn_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_PREACCESS_PHASE, Rc::new(|r| Box::pin(limit_conn_handler(r))));
    Ok(())
}

pub fn limit_conn_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(limit_conn_add_variables),
        postconfiguration: Some(limit_conn_init),
        create_loc_conf: Some(limit_conn_create_conf),
        merge_loc_conf: Some(limit_conn_merge_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("limit_conn_zone", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2, ConfLevel::None, limit_conn_zone),
        cmd_fn!("limit_conn", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, limit_conn),
        cmd!("limit_conn_log_level", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, LimitConnConf, log_level, set_enum, LIMIT_CONN_LOG_LEVELS),
        cmd_fn!("limit_conn_status", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, limit_conn_status),
        cmd!("limit_conn_dry_run", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, LimitConnConf, dry_run, set_flag),
    ];
    http_module_def("ngx_http_limit_conn_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zone with its slab pool, initialized by the zone init.
    fn zone() -> Rc<ShmZone> {
        let mem = Rc::new(ShmMem::private(1 << 19).unwrap());
        SlabPool::init_zone(&mem);

        let zone = ShmZone::new(b"test".to_vec(), mem.len(), TAG);
        zone.shm.attach(mem);

        let ctx = Rc::new(LimitConnCtx { sh: Cell::new(0), mem: RefCell::new(None), key: ComplexValue::constant(b"$binary_remote_addr") });

        *zone.data.borrow_mut() = Some(ctx);

        limit_conn_init_zone(&zone, None).unwrap();

        zone
    }

    /// The part of ngx_http_limit_conn_handler for one limit and key.
    fn acquire(zone: &Rc<ShmZone>, key: &[u8], hash: u32, max: usize) -> Option<LimitConnCleanup> {
        let ctx = zone_ctx(zone);
        let mem = ctx.mem();
        let shpool = SlabPool::of(&mem);
        let tree = ctx.rbtree(&mem);

        let mut node = limit_conn_lookup(&tree, key, hash);
        if node == 0 {
            node = shpool.alloc_locked(COLOR_OFF + DATA_OFF + key.len());
            assert!(node != 0);
            let lc = lc_of(&mem, node);
            tree.set_key(node, hash as usize);
            lc.set(LimitConnNode::len, key.len() as u8);
            lc.set(LimitConnNode::conn, 1);
            mem.write(lc.field(LimitConnNode::data), key);
            rb::insert(&tree, node, limit_conn_rbtree_insert_value);
        } else {
            let lc = lc_of(&mem, node);
            if lc.get(LimitConnNode::conn) as usize >= max {
                return None;
            }
            lc.set(LimitConnNode::conn, lc.get(LimitConnNode::conn) + 1);
        }
        Some(LimitConnCleanup { shm_zone: zone.clone(), node })
    }

    fn conn(zone: &Rc<ShmZone>, key: &[u8], hash: u32) -> Option<u16> {
        let ctx = zone_ctx(zone);
        let mem = ctx.mem();
        let node = limit_conn_lookup(&ctx.rbtree(&mem), key, hash);
        if node == 0 {
            None
        } else {
            Some(lc_of(&mem, node).get(LimitConnNode::conn))
        }
    }

    #[test]
    fn node_layout_as_c() {
        assert_eq!(COLOR_OFF, 32);
        assert_eq!(DATA_OFF, 4);
        assert_eq!(LimitConnShctx::SIZE, 64);
        assert_eq!(LimitConnShctx::sentinel_key.off, 24);
    }

    #[test]
    fn memn2cmp_as_c() {
        assert_eq!(memn2cmp(b"k1", b"k1"), 0);
        assert!(memn2cmp(b"k", b"k1") < 0);
        assert!(memn2cmp(b"k10", b"k1") > 0);
        assert!(memn2cmp(b"a9", b"b") < 0);

        let mem = ShmMem::private(4096).unwrap();
        let lc = LimitConnNode::at(&mem, 64);
        for (a, b) in [(&b"k1"[..], &b"k1"[..]), (b"k", b"k1"), (b"k10", b"k1"), (b"a9", b"b"), (b"b", b"a9")] {
            lc.set(LimitConnNode::len, b.len() as u8);
            mem.write(lc.field(LimitConnNode::data), b);
            assert_eq!(lc_cmp(a, lc), memn2cmp(a, b), "{:?} {:?}", a, b);
        }
    }

    #[test]
    fn count_and_cleanup() {
        let zone = zone();
        let ctx = zone_ctx(&zone);
        let mem = ctx.mem();
        let pfree = SlabPool::of(&mem).pfree();

        let c1 = acquire(&zone, b"127.0.0.1", 5, 2).unwrap();
        let c2 = acquire(&zone, b"127.0.0.1", 5, 2).unwrap();
        assert!(acquire(&zone, b"127.0.0.1", 5, 2).is_none());
        assert_eq!(conn(&zone, b"127.0.0.1", 5), Some(2));

        // the same hash, another key
        let c3 = acquire(&zone, b"127.0.0.2", 5, 2).unwrap();
        assert_eq!(conn(&zone, b"127.0.0.2", 5), Some(1));

        limit_conn_cleanup(&c1);
        assert_eq!(conn(&zone, b"127.0.0.1", 5), Some(1));

        // the last connection of a key frees its node
        let mut all = vec![c2, c3];
        limit_conn_cleanup_all(&mut all);
        assert!(all.is_empty());
        assert_eq!(conn(&zone, b"127.0.0.1", 5), None);
        assert_eq!(conn(&zone, b"127.0.0.2", 5), None);

        let tree = ctx.rbtree(&mem);
        assert_eq!(tree.root(), tree.sentinel());
        assert_eq!(SlabPool::of(&mem).pfree(), pfree);
    }

    #[test]
    fn lookup_many_keys() {
        let zone = zone();

        let keys: Vec<Vec<u8>> = (0..200u32).map(|i| format!("{}", i * 37 % 200).into_bytes()).collect();

        let cleanups: Vec<LimitConnCleanup> = keys.iter().map(|k| acquire(&zone, k, crc32fast::hash(k) % 16, 1).unwrap()).collect();

        for k in &keys {
            assert_eq!(conn(&zone, k, crc32fast::hash(k) % 16), Some(1));
            assert!(acquire(&zone, k, crc32fast::hash(k) % 16, 1).is_none());
        }

        assert_eq!(conn(&zone, b"200", crc32fast::hash(b"200") % 16), None);

        for c in cleanups.iter().rev() {
            limit_conn_cleanup(c);
        }

        for k in &keys {
            assert_eq!(conn(&zone, k, crc32fast::hash(k) % 16), None);
        }
    }
}
