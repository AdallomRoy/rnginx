//! ngx_stream_limit_conn_module.c: the number of connections per key in a
//! shared memory zone.

use std::any::Any;
use std::cell::Cell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::connection::PoolCleanup;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rbtree::*;
use ngx_core::rc::*;
use ngx_core::shm::ShmZone;
use ngx_core::slab::SlabPool;
use ngx_core::string::B;
use ngx_core::{cmd, cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_limit_conn_module");

pub const NGX_STREAM_LIMIT_CONN_PASSED: u32 = 1;
pub const NGX_STREAM_LIMIT_CONN_REJECTED: u32 = 2;
pub const NGX_STREAM_LIMIT_CONN_REJECTED_DRY_RUN: u32 = 3;

const TAG: &str = "ngx_stream_limit_conn_module";

// ngx_stream_limit_conn_node_t starts at the color of the rbtree node:
// u_char color; u_char len; u_short conn; u_char data[1];

const COLOR_OFF: usize = std::mem::offset_of!(RbtreeNode, color);

unsafe fn lc_len(node: *mut RbtreeNode) -> usize {
    *(node as *mut u8).add(COLOR_OFF + 1) as usize
}

unsafe fn lc_conn(node: *mut RbtreeNode) -> *mut u16 {
    (node as *mut u8).add(COLOR_OFF + 2) as *mut u16
}

unsafe fn lc_data<'a>(node: *mut RbtreeNode) -> &'a [u8] {
    std::slice::from_raw_parts((node as *mut u8).add(COLOR_OFF + 4), lc_len(node))
}

/// ngx_stream_limit_conn_shctx_t
#[repr(C)]
struct LimitConnShctx {
    rbtree: Rbtree,
    sentinel: RbtreeNode,
}

/// ngx_stream_limit_conn_ctx_t
pub struct LimitConnCtx {
    sh: Cell<*mut LimitConnShctx>,
    shpool: Cell<*mut SlabPool>,
    key: ComplexValue,
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

/// ngx_memn2cmp
fn memn2cmp(s1: &[u8], s2: &[u8]) -> std::cmp::Ordering {
    let z = s1.len().min(s2.len());
    match s1[..z].cmp(&s2[..z]) {
        std::cmp::Ordering::Equal => s1.len().cmp(&s2.len()),
        o => o,
    }
}

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

        let shpool = unsafe { &*ctx.shpool.get() };
        let sh = ctx.sh.get();

        shpool.lock();

        let node = unsafe {
            let mut node = limit_conn_lookup(&(*sh).rbtree, &key, hash);

            if node.is_null() {
                let n = COLOR_OFF + 4 + key.len();

                node = shpool.alloc_locked(n) as *mut RbtreeNode;

                if node.is_null() {
                    shpool.unlock();

                    cleanup_all(&s);

                    if dry_run {
                        s.limit_conn_status.set(NGX_STREAM_LIMIT_CONN_REJECTED_DRY_RUN);
                        return NGX_DECLINED;
                    }

                    s.limit_conn_status.set(NGX_STREAM_LIMIT_CONN_REJECTED);

                    return NGX_STREAM_SERVICE_UNAVAILABLE;
                }

                (*node).key = hash as usize;
                *(node as *mut u8).add(COLOR_OFF + 1) = key.len() as u8;
                *lc_conn(node) = 1;
                std::ptr::copy_nonoverlapping(key.as_ptr(), (node as *mut u8).add(COLOR_OFF + 4), key.len());

                (*sh).rbtree.insert(node);
            } else {
                if (*lc_conn(node)) as usize >= limit.conn {
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

                *lc_conn(node) += 1;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "limit conn: {:08X} {}", (*node).key, *lc_conn(node));

            node
        };

        shpool.unlock();

        let shm_zone = limit.shm_zone.clone();
        let node = node as usize;

        s.connection.add_cleanup(PoolCleanup { tag: TAG, data: None, handler: Some(Box::new(move || limit_conn_cleanup(&shm_zone, node as *mut RbtreeNode))) });
    }

    NGX_DECLINED
}

/// ngx_stream_limit_conn_rbtree_insert_value
unsafe fn limit_conn_rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let p: *mut *mut RbtreeNode = loop {
        let p = if (*node).key < (*temp).key {
            &mut (*temp).left as *mut *mut RbtreeNode
        } else if (*node).key > (*temp).key {
            &mut (*temp).right as *mut *mut RbtreeNode
        } else if memn2cmp(lc_data(node), lc_data(temp)) == std::cmp::Ordering::Less {
            &mut (*temp).left as *mut *mut RbtreeNode
        } else {
            &mut (*temp).right as *mut *mut RbtreeNode
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

/// ngx_stream_limit_conn_lookup
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

        match memn2cmp(key, lc_data(node)) {
            std::cmp::Ordering::Equal => return node,
            std::cmp::Ordering::Less => node = (*node).left,
            std::cmp::Ordering::Greater => node = (*node).right,
        }
    }

    std::ptr::null_mut()
}

/// ngx_stream_limit_conn_cleanup
fn limit_conn_cleanup(shm_zone: &Rc<ShmZone>, node: *mut RbtreeNode) {
    let ctx = match shm_zone.data::<LimitConnCtx>() {
        Some(c) => c,
        None => return,
    };

    let shpool = unsafe { &*ctx.shpool.get() };

    shpool.lock();

    unsafe {
        if let Some(log) = shm_zone.shm.log.borrow().as_ref() {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, log, "limit conn cleanup: {:08X} {}", (*node).key, *lc_conn(node));
        }

        *lc_conn(node) -= 1;

        if *lc_conn(node) == 0 {
            (*ctx.sh.get()).rbtree.delete(node);
            shpool.free_locked(node as *mut u8);
        }
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
        ctx.shpool.set(octx.shpool.get());

        return Ok(());
    }

    let shpool = shm_zone.shm.addr.get() as *mut SlabPool;

    ctx.shpool.set(shpool);

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

        (*sh).rbtree.init(&mut (*sh).sentinel, limit_conn_rbtree_insert_value);

        let lctx = format!(" in limit_conn_zone \"{}\"", B(shm_zone.name()));

        (*shpool).set_log_ctx(lctx.as_bytes())?;
    }

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

    let ctx = Rc::new(LimitConnCtx { sh: Cell::new(std::ptr::null_mut()), shpool: Cell::new(std::ptr::null_mut()), key });

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
