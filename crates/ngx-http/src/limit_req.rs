//! ngx_http_limit_req_module: request rate limiting with leaky bucket algorithm

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;
use std::ptr;
use std::time::Duration;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::queue::Queue;
use ngx_core::rc::*;
use ngx_core::rbtree::{Rbtree, RbtreeNode};
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_limit_req_module");

// Limit request status constants
const NGX_HTTP_LIMIT_REQ_PASSED: u32 = 1;
const NGX_HTTP_LIMIT_REQ_DELAYED: u32 = 2;
const NGX_HTTP_LIMIT_REQ_REJECTED: u32 = 3;
const NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN: u32 = 4;
const NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN: u32 = 5;

// Status strings for $limit_req_status variable
static LIMIT_REQ_STATUS: &[&[u8]] = &[
    b"PASSED",
    b"DELAYED",
    b"REJECTED",
    b"DELAYED_DRY_RUN",
    b"REJECTED_DRY_RUN",
];

/// Node in the request limit tracking (stored in shared memory).
/// Layout: rbtree node internals (color, padding, key) + LimitReqNode body
#[repr(C)]
struct LimitReqNode {
    color: u8,
    _dummy: u8,
    len: u16,
    queue: Queue,
    last: u64,              // last update time (milliseconds)
    excess: u32,            // excess in thousandths (1 = 0.001 r/s)
    count: u32,             // reference count
    data: u8,               // start of variable-length key data
}

/// Shared context for a limit_req zone (stored in shared memory).
#[repr(C)]
struct LimitReqShCtx {
    rbtree: Rbtree,
    sentinel: RbtreeNode,
    queue: Queue,
}

/// Per-zone context (stored per-process in zone.data).
struct LimitReqCtx {
    sh: *mut LimitReqShCtx,
    shpool: *mut ngx_core::slab::SlabPool,
    rate: u32,              // rate in thousandths of r/s
    key: ComplexValue,
    node: *mut LimitReqNode, // current request's node
}

/// A single limit within a location directive.
#[derive(Clone)]
struct LimitReqLimit {
    zone: Rc<crate::shm::ShmZone>,
    burst: u32,             // burst in thousandths
    delay: u32,             // delay in thousandths
}

/// Module location configuration.
pub struct LimitReqLocConf {
    pub limits: Vec<LimitReqLimit>,
    pub limit_log_level: Val<u32>,
    pub delay_log_level: Val<u32>,
    pub status_code: Val<u32>,
    pub dry_run: Val<bool>,
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitReqLocConf {
        limits: Vec::new(),
        limit_log_level: Val::unset(),
        delay_log_level: Val::unset(),
        status_code: Val::unset(),
        dry_run: Val::unset(),
    })
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<LimitReqLocConf>(prev).borrow();
    let mut c = conf_cell::<LimitReqLocConf>(conf).borrow_mut();

    if c.limits.is_empty() {
        c.limits = p.limits.clone();
    }

    c.limit_log_level.merge(&p.limit_log_level, NGX_LOG_ERR);

    c.delay_log_level.set(if *c.limit_log_level == NGX_LOG_INFO {
        NGX_LOG_INFO
    } else {
        *c.limit_log_level + 1
    });

    c.status_code.merge(&p.status_code, NGX_HTTP_SERVICE_UNAVAILABLE);
    c.dry_run.merge(&p.dry_run, false);

    Ok(())
}

/// Compare two byte sequences
fn memcmp(a: &[u8], b: &[u8]) -> i32 {
    for i in 0..a.len().min(b.len()) {
        let diff = (a[i] as i32) - (b[i] as i32);
        if diff != 0 {
            return diff;
        }
    }
    (a.len() as i32) - (b.len() as i32)
}

/// Insert function for rbtree
unsafe fn limit_req_rbtree_insert_value(
    mut temp: *mut RbtreeNode,
    node: *mut RbtreeNode,
    sentinel: *mut RbtreeNode,
) {
    loop {
        if (*node).key < (*temp).key {
            if (*temp).left == sentinel {
                (*node).parent = temp;
                (*temp).left = node;
                break;
            }
            temp = (*temp).left;
        } else if (*node).key > (*temp).key {
            if (*temp).right == sentinel {
                (*node).parent = temp;
                (*temp).right = node;
                break;
            }
            temp = (*temp).right;
        } else {
            // Same hash: compare data
            let lrn = &(*node).color as *const u8 as *const LimitReqNode;
            let lrnt = &(*temp).color as *const u8 as *const LimitReqNode;
            let len_n = (*lrn).len as usize;
            let len_t = (*lrnt).len as usize;
            let key_n = std::slice::from_raw_parts(&(*lrn).data, len_n);
            let key_t = std::slice::from_raw_parts(&(*lrnt).data, len_t);

            let cmp = memcmp(key_n, key_t);

            if cmp < 0 {
                if (*temp).left == sentinel {
                    (*node).parent = temp;
                    (*temp).left = node;
                    break;
                }
                temp = (*temp).left;
            } else {
                if (*temp).right == sentinel {
                    (*node).parent = temp;
                    (*temp).right = node;
                    break;
                }
                temp = (*temp).right;
            }
        }
    }

    (*node).left = sentinel;
    (*node).right = sentinel;
    (*node).color = 1; // red
}

/// Lookup a node by hash and key. Returns (rc, excess).
unsafe fn limit_req_lookup(
    ctx: &mut LimitReqCtx,
    hash: u32,
    key: &[u8],
    account: bool,
) -> (i64, u32) {
    let now = ngx_core::times::now_msec();
    let sh = &mut *ctx.sh;

    let mut node = sh.rbtree.root;
    let sentinel = sh.rbtree.sentinel;

    while node != sentinel {
        if hash < (*node).key as u32 {
            node = (*node).left;
        } else if hash > (*node).key as u32 {
            node = (*node).right;
        } else {
            // Hash match: compare data
            let lr = &(*node).color as *const u8 as *const LimitReqNode;
            let key_len = (*lr).len as usize;
            let stored_key = std::slice::from_raw_parts(&(*lr).data, key_len);

            if memcmp(key, stored_key) == 0 {
                // Found!
                let q = &(*lr).queue as *const _ as *mut Queue;
                (*q).remove();
                sh.queue.insert_head(q);

                let ms = (now as i64) - ((*lr).last as i64);
                let ms = if ms < -60000 { 1 } else if ms < 0 { 0 } else { ms };

                let excess = ((*lr).excess as i64) - (ctx.rate as i64) * ms / 1000 + 1000;
                let excess = if excess < 0 { 0 } else { excess as u32 };

                if account {
                    let lr_mut = lr as *mut LimitReqNode;
                    (*lr_mut).excess = excess;
                    if ms != 0 {
                        (*lr_mut).last = now;
                    }
                    return (NGX_OK, excess);
                }

                let lr_mut = lr as *mut LimitReqNode;
                (*lr_mut).count += 1;
                ctx.node = lr_mut;
                return (NGX_AGAIN, excess);
            }

            node = if memcmp(key, stored_key) < 0 {
                (*node).left
            } else {
                (*node).right
            };
        }
    }

    // Not found: allocate new node
    let size = std::mem::offset_of!(LimitReqNode, data) + key.len();

    // Try LRU eviction
    limit_req_expire(ctx, 1);

    let shpool = &mut *ctx.shpool;
    let node_ptr = shpool.alloc(size) as *mut RbtreeNode;
    if node_ptr.is_null() {
        limit_req_expire(ctx, 0);
        let node_ptr2 = shpool.alloc(size) as *mut RbtreeNode;
        if node_ptr2.is_null() {
            ngx_log_error!(NGX_LOG_ALERT, ngx_core::cycle::CYCLE.log.as_ref().unwrap(), None,
                          "could not allocate node in limit_req zone");
            return (NGX_ERROR, 0);
        }
        return limit_req_lookup(ctx, hash, key, account);
    }

    // Initialize new node
    let node = node_ptr;
    (*node).key = hash as usize;

    let lr = &mut (*node).color as *mut u8 as *mut LimitReqNode;
    (*lr).len = key.len() as u16;
    (*lr).excess = 0;
    (*lr).count = if account { 0 } else { 1 };
    (*lr).last = if account { now } else { 0 };
    ptr::copy_nonoverlapping(key.as_ptr(), &mut (*lr).data, key.len());

    // Insert into tree
    if sh.rbtree.root == sentinel {
        (*node).parent = ptr::null_mut();
        (*node).left = sentinel;
        (*node).right = sentinel;
        (*node).color = 0;
        sh.rbtree.root = node;
    } else if let Some(insert_fn) = sh.rbtree.insert {
        insert_fn(sh.rbtree.root, node, sentinel);
    }

    let q = &mut (*lr).queue as *mut Queue;
    sh.queue.insert_head(q);

    if account {
        return (NGX_OK, 0);
    }

    ctx.node = lr;
    (NGX_AGAIN, 0)
}

/// Account for a request: compute delay. Returns max delay in ms.
unsafe fn limit_req_account(
    ctx: &LimitReqCtx,
    node: *mut LimitReqNode,
    delay: u32,
) -> u64 {
    let now = ngx_core::times::now_msec();

    let ms = (now as i64) - ((*node).last as i64);
    let ms = if ms < -60000 { 1 } else if ms < 0 { 0 } else { ms };

    let excess = ((*node).excess as i64) - (ctx.rate as i64) * ms / 1000 + 1000;
    let excess = if excess < 0 { 0 } else { excess as u32 };

    if ms != 0 {
        (*node).last = now;
    }

    (*node).excess = excess;
    (*node).count -= 1;

    if excess <= delay {
        0
    } else {
        ((excess - delay) as u64) * 1000 / (ctx.rate as u64)
    }
}

/// Expire (remove) old nodes from the queue (LRU eviction).
unsafe fn limit_req_expire(ctx: &mut LimitReqCtx, n: u32) {
    let now = ngx_core::times::now_msec();
    let sh = &mut (*ctx.sh);
    let shpool = &mut *ctx.shpool;
    let mut n = n;

    while n < 3 {
        if sh.queue.is_empty() {
            return;
        }

        let q = sh.queue.last();
        let lr = &(*q) as *const Queue as *const LimitReqNode;

        if (*lr).count != 0 {
            return;
        }

        if n != 0 {
            n += 1;

            let ms = ((now as i64) - ((*lr).last as i64)).abs();

            if ms < 60000 {
                return;
            }

            let excess = ((*lr).excess as i64) - (ctx.rate as i64) * ms / 1000;
            if excess > 0 {
                return;
            }
        } else {
            n += 1;
        }

        let lr_mut = lr as *mut LimitReqNode;
        let q_mut = &mut (*lr_mut).queue as *mut Queue;
        (*q_mut).remove();

        let node = &(*lr_mut).color as *const u8 as usize
            - std::mem::offset_of!(RbtreeNode, color);
        let node = node as *mut RbtreeNode;

        if sh.rbtree.root != sh.rbtree.sentinel {
            sh.rbtree.delete(node);
        }

        shpool.free(node as *mut u8, std::mem::offset_of!(LimitReqNode, data) + (*lr).len as usize);
    }
}

/// Initialize a limit_req zone.
fn init_zone(zone: &Rc<crate::shm::ShmZone>, data: Option<Rc<dyn Any>>) -> Result<(), ()> {
    let addr = zone.shm.addr.get();
    if addr.is_null() {
        return Err(());
    }

    let conf = zone.conf::<LimitReqCtx>()?;
    let mut ctx = conf.as_ref().borrow_mut();

    if let Some(_old_data) = data {
        // Zone already initialized
        let old_conf = zone.conf::<LimitReqCtx>()?;
        let old_ctx = old_conf.as_ref().borrow();

        // Verify key hasn't changed
        if ctx.key != old_ctx.key {
            return Err(());
        }

        ctx.sh = old_ctx.sh;
        ctx.shpool = old_ctx.shpool;
        return Ok(());
    }

    unsafe {
        let shpool = zone.pool() as *const _ as *mut ngx_core::slab::SlabPool;
        ctx.shpool = shpool;

        if zone.shm.exists.get() {
            ctx.sh = (*shpool).data as *mut LimitReqShCtx;
            return Ok(());
        }

        // Initialize new zone
        let sh_size = std::mem::size_of::<LimitReqShCtx>();
        let sh_ptr = (*shpool).alloc(sh_size) as *mut LimitReqShCtx;
        if sh_ptr.is_null() {
            return Err(());
        }

        ctx.sh = sh_ptr;
        (*shpool).data = sh_ptr as *mut u8;

        // Initialize rbtree
        (*sh_ptr).sentinel.color = 0;
        (*sh_ptr).sentinel.left = &mut (*sh_ptr).sentinel;
        (*sh_ptr).sentinel.right = &mut (*sh_ptr).sentinel;
        (*sh_ptr).sentinel.parent = ptr::null_mut();
        (*sh_ptr).rbtree.root = &mut (*sh_ptr).sentinel;
        (*sh_ptr).rbtree.sentinel = &mut (*sh_ptr).sentinel;
        (*sh_ptr).rbtree.insert = Some(limit_req_rbtree_insert_value);

        // Initialize queue
        (*sh_ptr).queue.init();
    }

    Ok(())
}

/// Handler for $limit_req_status variable
fn limit_req_status_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let status = r.main.borrow().limit_req_status.get();
    if status == 0 {
        v.not_found = true;
    } else if status >= 1 && (status as usize) <= 5 {
        v.len = LIMIT_REQ_STATUS[status as usize - 1].len();
        v.data = LIMIT_REQ_STATUS[status as usize - 1].as_ptr();
        v.valid = true;
        v.no_cacheable = false;
        v.not_found = false;
    }
    NGX_OK
}

/// Directive handler for limit_req_zone
fn limit_req_zone_cmd(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 4 {
        return Err(cf.emerg(format_args!("limit_req_zone requires at least 4 arguments")));
    }

    // Parse key
    let key_value = compile_complex_value(cf, &args[1], 0)?;

    // Parse zone, rate
    let mut zone_name = Vec::new();
    let mut zone_size: i64 = 0;
    let mut rate: i64 = 1;
    let mut scale: i64 = 1;

    for i in 2..args.len() {
        let arg = &args[i];
        if arg.starts_with(b"zone=") {
            let rest = &arg[5..];
            if let Some(colon_pos) = rest.iter().position(|&b| b == b':') {
                zone_name = rest[..colon_pos].to_vec();
                let size_str = &rest[colon_pos + 1..];
                zone_size = ngx_core::parse::parse_size(size_str)
                    .ok_or_else(|| cf.emerg(format_args!("invalid zone size")))?;
            } else {
                return Err(cf.emerg(format_args!("invalid zone format")));
            }
        } else if arg.starts_with(b"rate=") {
            let rest = &arg[5..];
            if rest.ends_with(b"r/s") {
                scale = 1;
                let num_str = &rest[..rest.len() - 3];
                rate = ngx_core::string::atoi(num_str)
                    .ok_or_else(|| cf.emerg(format_args!("invalid rate")))?;
            } else if rest.ends_with(b"r/m") {
                scale = 60;
                let num_str = &rest[..rest.len() - 3];
                rate = ngx_core::string::atoi(num_str)
                    .ok_or_else(|| cf.emerg(format_args!("invalid rate")))?;
            } else {
                return Err(cf.emerg(format_args!("invalid rate format")));
            }
        }
    }

    if zone_name.is_empty() {
        return Err(cf.emerg(format_args!("zone parameter missing")));
    }

    if zone_size < 8 * 4096 {
        return Err(cf.emerg(format_args!("zone too small")));
    }

    // Create zone
    let zone = crate::shm::ShmZone::new(zone_name, zone_size as usize, "ngx_http_limit_req_module");

    // Create context
    let ctx = LimitReqCtx {
        sh: ptr::null_mut(),
        shpool: ptr::null_mut(),
        rate: ((rate * 1000) / scale) as u32,
        key: key_value,
        node: ptr::null_mut(),
    };
    let ctx_rc = Rc::new(RefCell::new(ctx));
    zone.conf.replace(Some(ctx_rc as Rc<dyn Any>));

    // Set zone init callback
    zone.init.replace(Some(Rc::new(move |z, old| init_zone(z, old))));

    Ok(())
}

/// Directive handler for limit_req
fn limit_req_cmd(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<LimitReqLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    let mut zone_name = Vec::new();
    let mut burst: u32 = 0;
    let mut delay: u32 = 0;

    for i in 1..args.len() {
        let arg = &args[i];
        if arg.starts_with(b"zone=") {
            zone_name = arg[5..].to_vec();
        } else if arg.starts_with(b"burst=") {
            burst = ngx_core::string::atoi(&arg[6..])
                .ok_or_else(|| cf.emerg(format_args!("invalid burst")))? as u32;
            burst *= 1000;
        } else if arg.starts_with(b"delay=") {
            delay = ngx_core::string::atoi(&arg[6..])
                .ok_or_else(|| cf.emerg(format_args!("invalid delay")))? as u32;
            delay *= 1000;
        } else if arg == b"nodelay" {
            delay = u32::MAX;
        }
    }

    if zone_name.is_empty() {
        return Err(cf.emerg(format_args!("zone parameter missing")));
    }

    // Find zone by name (simplified: would need to search cf.shm_zones)
    // For now accept it and mark as found
    // In a complete implementation, would call cf.shared_memory_add or lookup
    let zone = crate::shm::ShmZone::new(zone_name.clone(), 1024 * 1024, "ngx_http_limit_req_module");

    cell.borrow_mut().limits.push(LimitReqLimit {
        zone,
        burst,
        delay,
    });

    Ok(())
}

fn add_variables(cf: &mut Conf) -> ConfResult {
    let v = add_variable(cf, b"limit_req_status", NGX_HTTP_VAR_NOCACHEABLE)?;
    v.get_handler.set(Some(limit_req_status_variable));
    Ok(())
}

/// Main handler (PREACCESS phase)
async fn limit_req_handler(r: R) -> i64 {
    let mut r = r;

    // Skip if already processed
    if r.main.borrow().limit_req_status.get() != 0 {
        return NGX_DECLINED;
    }

    let conf = r.loc_conf::<LimitReqLocConf>(ctx_index());
    let limits = conf.borrow().limits.clone();

    if limits.is_empty() {
        return NGX_DECLINED;
    }

    let mut excess = 0u32;
    let mut rc = NGX_DECLINED;
    let mut limit_idx = 0;
    let mut last_zone_name = Vec::new();

    // Check all limits
    for (i, limit) in limits.iter().enumerate() {
        let zone_data = match limit.zone.data::<LimitReqCtx>() {
            Some(d) => d,
            None => return NGX_ERROR,
        };
        last_zone_name = limit.zone.name().to_vec();

        let mut ctx = zone_data.borrow_mut();

        // Evaluate key
        let key = match complex_value(&r, &ctx.key) {
            Ok(k) => k,
            Err(_) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
        };

        if key.is_empty() {
            continue;
        }

        if key.len() > 65535 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None,
                          "the value of the key is more than 65535 bytes");
            continue;
        }

        let hash = { fn h(b:&[u8])->u32{let mut c=crc32fast::Hasher::new();c.update(b);c.finalize()} h }(&key) as u32;

        // Lock and lookup
        let (lookup_rc, ex) = unsafe {
            let shpool = &mut *ctx.shpool;
            shpool.lock();
            let result = limit_req_lookup(&mut ctx, hash, &key, i == limits.len() - 1);
            shpool.unlock();
            result
        };

        excess = ex;
        limit_idx = i;

        http_debug!(r, "limit_req[{}]: {} {}.{:03}", i, lookup_rc, excess / 1000, excess % 1000);

        if lookup_rc != NGX_AGAIN {
            rc = lookup_rc;
            break;
        }
    }

    if rc == NGX_DECLINED {
        return NGX_DECLINED;
    }

    if rc == NGX_BUSY || rc == NGX_ERROR {
        if rc == NGX_BUSY {
            let conf_ref = conf.borrow();
            let dry_run = *conf_ref.dry_run;
            ngx_log_error!(*conf_ref.limit_log_level, r.connection.log, None,
                          "limiting requests{}, excess: {}.{:03} by zone \"{}\"",
                          if dry_run { ", dry run" } else { "" },
                          excess / 1000, excess % 1000, B(&last_zone_name));
        }

        let conf_ref = conf.borrow();
        if *conf_ref.dry_run {
            r.main.borrow_mut().limit_req_status.set(NGX_HTTP_LIMIT_REQ_REJECTED_DRY_RUN);
            return NGX_DECLINED;
        }

        r.main.borrow_mut().limit_req_status.set(NGX_HTTP_LIMIT_REQ_REJECTED);
        return *conf_ref.status_code as i64;
    }

    // rc == NGX_OK or NGX_AGAIN
    if rc == NGX_AGAIN {
        excess = 0;
    }

    // Account for all limits
    let mut max_delay = 0u64;
    for i in 0..=limit_idx {
        let limit = &limits[i];
        let zone_data = match limit.zone.data::<LimitReqCtx>() {
            Some(d) => d,
            None => continue,
        };
        let mut ctx = zone_data.borrow_mut();

        if ctx.node.is_null() {
            continue;
        }

        let shpool = unsafe { &mut *ctx.shpool };
        shpool.lock();

        let delay = unsafe { limit_req_account(&ctx, ctx.node, limit.delay) };
        ctx.node = ptr::null_mut();

        shpool.unlock();

        if delay > max_delay {
            max_delay = delay;
        }
    }

    if max_delay == 0 {
        r.main.borrow_mut().limit_req_status.set(NGX_HTTP_LIMIT_REQ_PASSED);
        return NGX_DECLINED;
    }

    let conf_ref = conf.borrow();
    let dry_run = *conf_ref.dry_run;
    ngx_log_error!(*conf_ref.delay_log_level, r.connection.log, None,
                  "delaying request{}, excess: {}.{:03}, by zone \"{}\"",
                  if dry_run { ", dry run" } else { "" },
                  excess / 1000, excess % 1000, B(&last_zone_name));

    if dry_run {
        r.main.borrow_mut().limit_req_status.set(NGX_HTTP_LIMIT_REQ_DELAYED_DRY_RUN);
        return NGX_DECLINED;
    }

    r.main.borrow_mut().limit_req_status.set(NGX_HTTP_LIMIT_REQ_DELAYED);

    // Schedule async delay
    if max_delay > 0 {
        tokio::time::sleep(Duration::from_millis(max_delay)).await;
    }

    NGX_DECLINED
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_PREACCESS_PHASE, Rc::new(|r| Box::pin(limit_req_handler(r))))?;
    Ok(())
}

pub fn limit_req_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        postconfiguration: Some(init),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    let commands = vec![
        ngx_core::cmd_fn!("limit_req_zone", NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE3, ConfLevel::Main, limit_req_zone_cmd),
        ngx_core::cmd_fn!("limit_req", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::Loc, limit_req_cmd),
        ngx_core::cmd!("limit_req_log_level", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, LimitReqLocConf, limit_log_level, set_uint),
        ngx_core::cmd!("limit_req_status", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, LimitReqLocConf, status_code, set_uint),
        ngx_core::cmd!("limit_req_dry_run", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, LimitReqLocConf, dry_run, set_flag),
    ];

    http_module_def("ngx_http_limit_req_module", def, commands)
}
