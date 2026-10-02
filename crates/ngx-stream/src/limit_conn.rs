//! ngx_stream_limit_conn_module.c: the number of connections per key in a
//! shared memory zone.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::connection::PoolCleanup;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::shmem::rbtree::{self as rb, RbNode, RbTree, ShmRbtree};
use ngx_core::shmem::slab::SlabPool;
use ngx_core::shmem::ShmMem;
use ngx_core::string::B;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error, shm_struct};

use crate::core::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_limit_conn_module");

pub const NGX_STREAM_LIMIT_CONN_PASSED: u32 = 1;
pub const NGX_STREAM_LIMIT_CONN_REJECTED: u32 = 2;
pub const NGX_STREAM_LIMIT_CONN_REJECTED_DRY_RUN: u32 = 3;

const TAG: &str = "ngx_stream_limit_conn_module";

shm_struct! {
    /// ngx_stream_limit_conn_node_t: it starts at the color of the rbtree
    /// node
    struct LimitConnNode {
        color: u8,
        len: u8,
        conn: u16,
        /// the key, len bytes
        data: u8,
    }
}

shm_struct! {
    /// ngx_stream_limit_conn_shctx_t: the rbtree, then its sentinel node
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

/// ngx_stream_limit_conn_ctx_t
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

const COLOR_OFF: usize = RbNode::color.off;

const DATA_OFF: usize = LimitConnNode::data.off;

/// (ngx_stream_limit_conn_node_t *) &node->color
fn lc_of(mem: &ShmMem, node: usize) -> LimitConnNode<'_> {
    LimitConnNode::at(mem, node + COLOR_OFF)
}

/// lc->data, lc->len
fn lc_data(lc: LimitConnNode<'_>) -> Vec<u8> {
    lc.mem.bytes(lc.field(LimitConnNode::data), lc.get(LimitConnNode::len) as usize)
}

/// ngx_memn2cmp(key, lc->data, key.len, lc->len), without copying lc->data
fn lc_cmp(key: &[u8], lc: LimitConnNode<'_>) -> std::cmp::Ordering {
    let len = lc.get(LimitConnNode::len) as usize;
    let n = key.len().min(len);

    match lc.mem.cmp_bytes(lc.field(LimitConnNode::data), &key[..n]) {
        std::cmp::Ordering::Equal => key.len().cmp(&len),
        o => o.reverse(),
    }
}

/// ngx_stream_limit_conn_limit_t
#[derive(Clone)]
pub struct LimitConnLimit {
    pub shm_zone: Rc<ShmZone>,
    pub conn: usize,
}

/// ngx_stream_limit_conn_conf_t
pub struct LimitConnConf {
    /// None: limits.elts == NULL
    pub limits: Option<Vec<LimitConnLimit>>,
    pub log_level: Val<u32>,
    pub dry_run: Val<bool>,
}

static LIMIT_CONN_STATUS: [&str; 3] = ["PASSED", "REJECTED", "REJECTED_DRY_RUN"];

/// ngx_stream_limit_conn_handler
async fn limit_conn_handler(s: S) -> i64 {
    let lccf = s.srv_conf::<LimitConnConf>(ctx_index());

    let (limits, log_level, dry_run) = {
        let l = lccf.borrow();
        (l.limits.clone().unwrap_or_default(), *l.log_level, *l.dry_run)
    };

    for limit in limits.iter() {
        let ctx = match limit.shm_zone.data::<LimitConnCtx>() {
            Some(c) => c,
            None => return NGX_ERROR,
        };

        let key = match complex_value(&s, &ctx.key) {
            Ok(k) => k,
            Err(()) => return NGX_ERROR,
        };

        if key.is_empty() {
            continue;
        }

        if key.len() > 255 {
            ngx_log_error!(NGX_LOG_ERR, s.connection.log, None, "the value of the \"{}\" key is more than 255 bytes: \"{}\"", B(&ctx.key.value), B(&key));
            continue;
        }

        s.limit_conn_status.set(NGX_STREAM_LIMIT_CONN_PASSED);

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

                cleanup_all(&s);

                if dry_run {
                    s.limit_conn_status.set(NGX_STREAM_LIMIT_CONN_REJECTED_DRY_RUN);
                    return NGX_DECLINED;
                }

                s.limit_conn_status.set(NGX_STREAM_LIMIT_CONN_REJECTED);

                return NGX_STREAM_SERVICE_UNAVAILABLE;
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

                ngx_log_error!(log_level, s.connection.log, None, "limiting connections{} by zone \"{}\"", if dry_run { ", dry run," } else { "" }, B(limit.shm_zone.name()));

                cleanup_all(&s);

                if dry_run {
                    s.limit_conn_status.set(NGX_STREAM_LIMIT_CONN_REJECTED_DRY_RUN);
                    return NGX_DECLINED;
                }

                s.limit_conn_status.set(NGX_STREAM_LIMIT_CONN_REJECTED);

                return NGX_STREAM_SERVICE_UNAVAILABLE;
            }

            lc.set(LimitConnNode::conn, lc.get(LimitConnNode::conn).wrapping_add(1));
        }

        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "limit conn: {:08X} {}", tree.key(node), lc_of(&mem, node).get(LimitConnNode::conn));

        shpool.unlock();

        let shm_zone = limit.shm_zone.clone();

        s.connection.add_cleanup(PoolCleanup { tag: TAG, data: None, handler: Some(Box::new(move || limit_conn_cleanup(&shm_zone, node))) });
    }

    NGX_DECLINED
}

/// ngx_stream_limit_conn_rbtree_insert_value
fn limit_conn_rbtree_insert_value(tree: &ShmRbtree<'_>, temp: usize, node: usize, sentinel: usize) {
    rb::insert_by(tree, temp, node, sentinel, |t, node, temp| {
        let (nk, tk) = (t.key(node), t.key(temp));

        if nk != tk {
            return nk < tk;
        }

        // node->key == temp->key

        lc_cmp(&lc_data(lc_of(t.mem, node)), lc_of(t.mem, temp)) == std::cmp::Ordering::Less
    });
}

/// ngx_stream_limit_conn_lookup: the node of the key, or 0
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

        match lc_cmp(key, lc_of(rbtree.mem, node)) {
            std::cmp::Ordering::Equal => return node,
            std::cmp::Ordering::Less => node = rbtree.left(node),
            std::cmp::Ordering::Greater => node = rbtree.right(node),
        }
    }

    0
}

/// ngx_stream_limit_conn_cleanup
fn limit_conn_cleanup(shm_zone: &Rc<ShmZone>, node: usize) {
    let ctx = match shm_zone.data::<LimitConnCtx>() {
        Some(c) => c,
        None => return,
    };

    // the node stays in the zone while its conn is not zero; it is changed
    // under the zone's mutex
    let mem = ctx.mem();
    let shpool = SlabPool::of(&mem);
    let tree = ctx.rbtree(&mem);
    let lc = lc_of(&mem, node);

    shpool.lock();

    if let Some(log) = shm_zone.shm.log.borrow().as_ref() {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, log, "limit conn cleanup: {:08X} {}", tree.key(node), lc.get(LimitConnNode::conn));
    }

    lc.set(LimitConnNode::conn, lc.get(LimitConnNode::conn).wrapping_sub(1));

    if lc.get(LimitConnNode::conn) == 0 {
        rb::delete(&tree, node);
        shpool.free_locked(node);
    }

    shpool.unlock();
}

/// ngx_stream_limit_conn_cleanup_all: the cleanups the handler added
/// (at the head of the pool's list)
fn cleanup_all(s: &Session) {
    loop {
        let cln = {
            let mut cleanups = s.connection.cleanups.borrow_mut();
            match cleanups.last() {
                Some(c) if c.tag == TAG => cleanups.pop(),
                _ => None,
            }
        };

        match cln {
            Some(cln) => {
                if let Some(h) = cln.handler {
                    h();
                }
            }
            None => break,
        }
    }
}

/// ngx_stream_limit_conn_init_zone
fn limit_conn_init_zone(shm_zone: &Rc<ShmZone>, data: Option<Rc<dyn Any>>) -> Result<(), ()> {
    let ctx = shm_zone.data::<LimitConnCtx>().ok_or(())?;

    if let Some(octx) = data.and_then(|d| d.downcast::<LimitConnCtx>().ok()) {
        if ctx.key.value != octx.key.value {
            if let Some(log) = shm_zone.shm.log.borrow().as_ref() {
                ngx_log_error!(NGX_LOG_EMERG, log, None, "limit_conn_zone \"{}\" uses the \"{}\" key while previously it used the \"{}\" key", B(shm_zone.name()), B(&ctx.key.value), B(&octx.key.value));
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

    let lctx = format!(" in limit_conn_zone \"{}\"", B(shm_zone.name()));

    shpool.set_log_ctx(lctx.as_bytes())?;

    Ok(())
}

/// ngx_stream_limit_conn_status_variable
fn limit_conn_status_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let status = s.limit_conn_status.get();

    if status == 0 {
        v.not_found = true;
        return NGX_OK;
    }

    *v = VariableValue::new(LIMIT_CONN_STATUS[status as usize - 1].as_bytes());

    NGX_OK
}

fn limit_conn_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitConnConf { limits: None, log_level: Val::unset(), dry_run: Val::unset() })
}

/// ngx_stream_limit_conn_merge_conf
fn limit_conn_merge_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<LimitConnConf>(parent).borrow();
    let mut conf = conf_cell::<LimitConnConf>(child).borrow_mut();

    if conf.limits.is_none() {
        conf.limits = prev.limits.clone();
    }

    conf.log_level.merge(&prev.log_level, NGX_LOG_ERR);

    conf.dry_run.merge(&prev.dry_run, false);

    Ok(())
}

/// ngx_stream_limit_conn_zone
fn limit_conn_zone(cf: &mut Conf, cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let value = cf.args.clone();

    let mut ccv = CompileComplexValue::default();
    let key = compile_complex_value(cf, &value[1], &mut ccv)?;

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

    shm_zone.safe_pool.set(true);
    *shm_zone.init.borrow_mut() = Some(Rc::new(limit_conn_init_zone));
    *shm_zone.data.borrow_mut() = Some(ctx);

    Ok(())
}

/// ngx_stream_limit_conn
fn limit_conn(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lccf = conf_rc::<LimitConnConf>(conf.as_ref().expect("conf"));

    let value = cf.args.clone();

    let shm_zone = ngx_core::cycle::shared_memory_add(cf, &value[1], 0, TAG)?;

    {
        let l = lccf.borrow();
        if let Some(limits) = &l.limits {
            if limits.iter().any(|lim| Rc::ptr_eq(&lim.shm_zone, &shm_zone)) {
                return Err(msg("is duplicate"));
            }
        }
    }

    let n = match ngx_core::string::atoi(&value[2]) {
        Some(n) if n > 0 => n,
        _ => return Err(cf.emerg(format_args!("invalid number of connections \"{}\"", B(&value[2])))),
    };

    if n > 65535 {
        return Err(cf.emerg(format_args!("connection limit must be less 65536")));
    }

    lccf.borrow_mut().limits.get_or_insert_with(Vec::new).push(LimitConnLimit { shm_zone, conn: n as usize });

    Ok(())
}

static LIMIT_CONN_VARS: &[VarDef] = &[VarDef { name: "limit_conn_status", set: None, get: Some(limit_conn_status_variable), data: 0, flags: NGX_STREAM_VAR_NOCACHEABLE }];

/// ngx_stream_limit_conn_add_variables
fn limit_conn_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, LIMIT_CONN_VARS)
}

/// ngx_stream_limit_conn_init
fn limit_conn_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_STREAM_PREACCESS_PHASE, phase_fn(limit_conn_handler));
    Ok(())
}

static LOG_LEVELS: &[(&str, u32)] = &[("info", NGX_LOG_INFO), ("notice", NGX_LOG_NOTICE), ("warn", NGX_LOG_WARN), ("error", NGX_LOG_ERR)];

fn limit_conn_log_level(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lccf = conf_rc::<LimitConnConf>(conf.as_ref().expect("conf"));
    let mut l = lccf.borrow_mut();
    set_enum(cf, cmd, &mut l.log_level, LOG_LEVELS)
}

pub fn limit_conn_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_limit_conn_module",
        StreamModuleDef {
            preconfiguration: Some(limit_conn_add_variables),
            postconfiguration: Some(limit_conn_init),
            create_srv_conf: Some(limit_conn_create_conf),
            merge_srv_conf: Some(limit_conn_merge_conf),
            ..Default::default()
        },
        vec![
            cmd_fn!("limit_conn_zone", NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE2, ConfLevel::None, limit_conn_zone),
            cmd_fn!("limit_conn", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2, ConfLevel::Srv, limit_conn),
            cmd_fn!("limit_conn_log_level", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, limit_conn_log_level),
            cmd!("limit_conn_dry_run", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, LimitConnConf, dry_run, set_flag),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ngx_memn2cmp
    fn memn2cmp(s1: &[u8], s2: &[u8]) -> std::cmp::Ordering {
        let z = s1.len().min(s2.len());
        match s1[..z].cmp(&s2[..z]) {
            std::cmp::Ordering::Equal => s1.len().cmp(&s2.len()),
            o => o,
        }
    }

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

    fn zone_ctx(zone: &Rc<ShmZone>) -> Rc<LimitConnCtx> {
        zone.data::<LimitConnCtx>().unwrap()
    }

    /// The part of ngx_stream_limit_conn_handler for one limit and key:
    /// the node counted, None if the limit is reached.
    fn acquire(zone: &Rc<ShmZone>, key: &[u8], hash: u32, max: usize) -> Option<usize> {
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
        Some(node)
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
        assert_eq!(LimitConnNode::len.off, 1);
        assert_eq!(LimitConnNode::conn.off, 2);
        assert_eq!(DATA_OFF, 4);
        assert_eq!(LimitConnShctx::SIZE, 64);
        assert_eq!(LimitConnShctx::sentinel_key.off, 24);
    }

    #[test]
    fn memn2cmp_as_c() {
        let mem = ShmMem::private(4096).unwrap();
        let lc = LimitConnNode::at(&mem, 64);
        for (a, b) in [(&b"k1"[..], &b"k1"[..]), (b"k", b"k1"), (b"k10", b"k1"), (b"a9", b"b"), (b"b", b"a9"), (b"", b"a")] {
            lc.set(LimitConnNode::len, b.len() as u8);
            mem.write(lc.field(LimitConnNode::data), b);
            assert_eq!(lc_cmp(a, lc), memn2cmp(a, b), "{:?} {:?}", a, b);
            assert_eq!(lc_data(lc), b);
        }
    }

    #[test]
    fn count_and_cleanup() {
        let zone = zone();
        let ctx = zone_ctx(&zone);
        let mem = ctx.mem();
        let pfree = SlabPool::of(&mem).pfree();

        let n1 = acquire(&zone, b"127.0.0.1", 5, 2).unwrap();
        let n2 = acquire(&zone, b"127.0.0.1", 5, 2).unwrap();
        assert_eq!(n1, n2);
        assert!(acquire(&zone, b"127.0.0.1", 5, 2).is_none());
        assert_eq!(conn(&zone, b"127.0.0.1", 5), Some(2));

        // the same hash, another key
        let n3 = acquire(&zone, b"127.0.0.2", 5, 2).unwrap();
        assert_eq!(conn(&zone, b"127.0.0.2", 5), Some(1));

        limit_conn_cleanup(&zone, n1);
        assert_eq!(conn(&zone, b"127.0.0.1", 5), Some(1));

        // the last connection of a key frees its node
        limit_conn_cleanup(&zone, n2);
        limit_conn_cleanup(&zone, n3);
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

        let nodes: Vec<usize> = keys.iter().map(|k| acquire(&zone, k, crc32fast::hash(k) % 16, 1).unwrap()).collect();

        for k in &keys {
            assert_eq!(conn(&zone, k, crc32fast::hash(k) % 16), Some(1));
            assert!(acquire(&zone, k, crc32fast::hash(k) % 16, 1).is_none());
        }

        assert_eq!(conn(&zone, b"200", crc32fast::hash(b"200") % 16), None);

        for n in nodes.iter().rev() {
            limit_conn_cleanup(&zone, *n);
        }

        for k in &keys {
            assert_eq!(conn(&zone, k, crc32fast::hash(k) % 16), None);
        }
    }
}
