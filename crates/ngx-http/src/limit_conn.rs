//! ngx_http_limit_conn_module: the number of connections (requests being
//! processed) per key, counted in a shared memory zone.

use std::any::Any;
use std::cell::Cell;
use std::ptr::addr_of_mut;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rbtree::*;
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::slab::SlabPool;
use ngx_core::string::B;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

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

/// ngx_http_limit_conn_node_t: it starts at the color of the rbtree node
#[repr(C)]
struct LimitConnNode {
    color: u8,
    len: u8,
    conn: u16,
    data: [u8; 1],
}

/// ngx_http_limit_conn_cleanup_t
struct LimitConnCleanup {
    shm_zone: Rc<ShmZone>,
    node: *mut RbtreeNode,
}

/// ngx_http_limit_conn_shctx_t
#[repr(C)]
struct LimitConnShctx {
    rbtree: Rbtree,
    sentinel: RbtreeNode,
}

/// ngx_http_limit_conn_ctx_t
pub struct LimitConnCtx {
    sh: Cell<*mut LimitConnShctx>,
    shpool: Cell<*mut SlabPool>,
    key: ComplexValue,
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

const COLOR_OFF: usize = std::mem::offset_of!(RbtreeNode, color);

const DATA_OFF: usize = std::mem::offset_of!(LimitConnNode, data);

/// (ngx_http_limit_conn_node_t *) &node->color
unsafe fn lc_of(node: *mut RbtreeNode) -> *mut LimitConnNode {
    (node as *mut u8).add(COLOR_OFF) as *mut LimitConnNode
}

/// lc->data, lc->len
unsafe fn lc_data<'a>(lc: *mut LimitConnNode) -> &'a [u8] {
    std::slice::from_raw_parts((lc as *const u8).add(DATA_OFF), (*lc).len as usize)
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

/// The zone's context: shm_zone->data, set by limit_conn_zone (a zone that
/// no limit_conn_zone declared has no size, and the configuration fails).
fn zone_ctx(shm_zone: &ShmZone) -> Rc<LimitConnCtx> {
    shm_zone.data::<LimitConnCtx>().expect("limit_conn zone without data")
}

/// ngx_http_limit_conn_handler
/// limit_conn_handler declines at once: a status set before, or no
/// limit_conn for the location
fn limit_conn_idle(r: &R) -> bool {
    r.main().limit_conn_status.get() != 0
        || r.loc_conf::<LimitConnConf>(ctx_index()).borrow().limits.as_deref().is_none_or(|l| l.is_empty())
}

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

        // SAFETY: shpool was set by the zone init to the zone's slab pool
        let shpool = unsafe { &*ctx.shpool.get() };

        shpool.lock();

        // SAFETY: the zone's rbtree and its nodes are used under its mutex
        let node = unsafe {
            let sh = ctx.sh.get();

            let mut node = limit_conn_lookup(&(*sh).rbtree, &key, hash);

            if node.is_null() {
                let n = COLOR_OFF + DATA_OFF + key.len();

                node = shpool.alloc_locked(n) as *mut RbtreeNode;

                if node.is_null() {
                    shpool.unlock();
                    limit_conn_cleanup_all(&mut cleanups);

                    if *lccf.dry_run {
                        main.limit_conn_status.set(NGX_HTTP_LIMIT_CONN_REJECTED_DRY_RUN);
                        return NGX_DECLINED;
                    }

                    main.limit_conn_status.set(NGX_HTTP_LIMIT_CONN_REJECTED);

                    return *lccf.status_code;
                }

                let lc = lc_of(node);

                (*node).key = hash as usize;
                (*lc).len = key.len() as u8;
                (*lc).conn = 1;
                std::ptr::copy_nonoverlapping(key.as_ptr(), (lc as *mut u8).add(DATA_OFF), key.len());

                (*sh).rbtree.insert(node);
            } else {
                let lc = lc_of(node);

                if (*lc).conn as usize >= limit.conn {
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

                (*lc).conn = (*lc).conn.wrapping_add(1);
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "limit conn: {:08X} {}", (*node).key, (*lc_of(node)).conn);

            node
        };

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
unsafe fn limit_conn_rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let p: *mut *mut RbtreeNode = loop {
        let p = if (*node).key < (*temp).key {
            addr_of_mut!((*temp).left)
        } else if (*node).key > (*temp).key {
            addr_of_mut!((*temp).right)
        } else {
            // node->key == temp->key

            let lcn = lc_of(node);
            let lcnt = lc_of(temp);

            if memn2cmp(lc_data(lcn), lc_data(lcnt)) < 0 {
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

/// ngx_http_limit_conn_lookup
unsafe fn limit_conn_lookup(rbtree: &Rbtree, key: &[u8], hash: u32) -> *mut RbtreeNode {
    let mut node = rbtree.root;
    let sentinel = rbtree.sentinel;

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

        let lcn = lc_of(node);

        let rc = memn2cmp(key, lc_data(lcn));

        if rc == 0 {
            return node;
        }

        node = if rc < 0 { (*node).left } else { (*node).right };
    }

    std::ptr::null_mut()
}

/// ngx_http_limit_conn_cleanup
fn limit_conn_cleanup(lccln: &LimitConnCleanup) {
    let ctx = zone_ctx(&lccln.shm_zone);
    let node = lccln.node;

    // SAFETY: the node stays in the zone while its conn is not zero; it is
    // changed under the zone's mutex
    unsafe {
        let lc = lc_of(node);

        let shpool = &*ctx.shpool.get();

        shpool.lock();

        if let Some(log) = lccln.shm_zone.shm.log.borrow().as_ref() {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "limit conn cleanup: {:08X} {}", (*node).key, (*lc).conn);
        }

        (*lc).conn = (*lc).conn.wrapping_sub(1);

        if (*lc).conn == 0 {
            (*ctx.sh.get()).rbtree.delete(node);
            shpool.free_locked(node as *mut u8);
        }

        shpool.unlock();
    }
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
        ctx.shpool.set(octx.shpool.get());

        return Ok(());
    }

    let shpool = shm_zone.shm.addr.get() as *mut SlabPool;

    ctx.shpool.set(shpool);

    // SAFETY: the zone is mapped, with its slab pool at the start
    unsafe {
        if shm_zone.shm.exists.get() {
            ctx.sh.set((*shpool).data as *mut LimitConnShctx);
            return Ok(());
        }

        let sh = (*shpool).alloc(std::mem::size_of::<LimitConnShctx>()) as *mut LimitConnShctx;
        if sh.is_null() {
            return Err(());
        }

        ctx.sh.set(sh);

        (*shpool).data = sh as *mut u8;

        (*sh).rbtree.init(addr_of_mut!((*sh).sentinel), limit_conn_rbtree_insert_value);

        let log_ctx = format!(" in limit_conn_zone \"{}\"", B(shm_zone.name()));

        (*shpool).set_log_ctx(log_ctx.as_bytes())?;
    }

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

    let ctx = Rc::new(LimitConnCtx { sh: Cell::new(std::ptr::null_mut()), shpool: Cell::new(std::ptr::null_mut()), key });

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
    add_phase_handler(cf, NGX_HTTP_PREACCESS_PHASE, crate::core::phase_handler(limit_conn_idle, limit_conn_handler));
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
    use std::sync::atomic::AtomicUsize;

    use ngx_core::shmtx::ShmTx;

    /// A zone with its slab pool in `mem`, initialized by the zone init.
    fn zone(mem: &mut Vec<u64>) -> Rc<ShmZone> {
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

        let ctx = Rc::new(LimitConnCtx { sh: Cell::new(std::ptr::null_mut()), shpool: Cell::new(std::ptr::null_mut()), key: ComplexValue::constant(b"$binary_remote_addr") });

        *zone.data.borrow_mut() = Some(ctx);

        limit_conn_init_zone(&zone, None).unwrap();

        zone
    }

    /// The part of ngx_http_limit_conn_handler for one limit and key.
    fn acquire(zone: &Rc<ShmZone>, key: &[u8], hash: u32, max: usize) -> Option<LimitConnCleanup> {
        let ctx = zone_ctx(zone);
        unsafe {
            let sh = ctx.sh.get();
            let shpool = &*ctx.shpool.get();
            let mut node = limit_conn_lookup(&(*sh).rbtree, key, hash);
            if node.is_null() {
                node = shpool.alloc_locked(COLOR_OFF + DATA_OFF + key.len()) as *mut RbtreeNode;
                assert!(!node.is_null());
                let lc = lc_of(node);
                (*node).key = hash as usize;
                (*lc).len = key.len() as u8;
                (*lc).conn = 1;
                std::ptr::copy_nonoverlapping(key.as_ptr(), (lc as *mut u8).add(DATA_OFF), key.len());
                (*sh).rbtree.insert(node);
            } else {
                if (*lc_of(node)).conn as usize >= max {
                    return None;
                }
                (*lc_of(node)).conn += 1;
            }
            Some(LimitConnCleanup { shm_zone: zone.clone(), node })
        }
    }

    fn conn(zone: &Rc<ShmZone>, key: &[u8], hash: u32) -> Option<u16> {
        let ctx = zone_ctx(zone);
        unsafe {
            let node = limit_conn_lookup(&(*ctx.sh.get()).rbtree, key, hash);
            if node.is_null() {
                None
            } else {
                Some((*lc_of(node)).conn)
            }
        }
    }

    #[test]
    fn node_layout_as_c() {
        assert_eq!(COLOR_OFF, 32);
        assert_eq!(DATA_OFF, 4);
    }

    #[test]
    fn memn2cmp_as_c() {
        assert_eq!(memn2cmp(b"k1", b"k1"), 0);
        assert!(memn2cmp(b"k", b"k1") < 0);
        assert!(memn2cmp(b"k10", b"k1") > 0);
        assert!(memn2cmp(b"a9", b"b") < 0);
    }

    #[test]
    fn count_and_cleanup() {
        let mut mem = vec![0u64; 1 << 16];
        let zone = zone(&mut mem);
        let ctx = zone_ctx(&zone);
        let pfree = unsafe { (*ctx.shpool.get()).pfree };

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

        unsafe {
            let sh = ctx.sh.get();
            assert_eq!((*sh).rbtree.root, (*sh).rbtree.sentinel);
            assert_eq!((*ctx.shpool.get()).pfree, pfree);
        }
    }

    #[test]
    fn lookup_many_keys() {
        let mut mem = vec![0u64; 1 << 16];
        let zone = zone(&mut mem);

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
