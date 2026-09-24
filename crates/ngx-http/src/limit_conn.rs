//! ngx_http_limit_conn_module: Limit concurrent connections per zone.

use std::any::Any;
use std::cell::RefCell;
use std::mem;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::hash::crc32_short;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::rbtree::RbtreeNode;
use ngx_core::shm::ShmZone;
use ngx_core::string::{atoi, B};
use ngx_core::ngx_log_error;

use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::core::add_phase_handler;
use crate::*;

// Status values for $limit_conn_status variable
const LIMIT_CONN_PASSED: u32 = 1;
const LIMIT_CONN_REJECTED: u32 = 2;
const LIMIT_CONN_REJECTED_DRY_RUN: u32 = 3;

// Module index for configuration access
crate::http_module_index!("ngx_http_limit_conn_module");

/// Node in the shared rbtree, containing the key length and connection counter.
/// Layout: after the RbtreeNode, we store: len (u8), conn (u16), then variable key data.
#[repr(C)]
struct LimitConnNode {
    len: u8,
    conn: u16,
    data: [u8; 1],  // Flexible array marker
}

/// Per-request cleanup callback wrapper.
struct LimitConnCleanupData {
    zone: Rc<ShmZone>,
    node_ptr: *mut RbtreeNode,
}

/// Shared context stored in the zone's slab pool (via zone.data).
pub struct LimitConnCtx {
    pub key: ComplexValue,
    pub root: RefCell<*mut RbtreeNode>,
    pub sentinel: *mut RbtreeNode,
    pub shpool: *const SlabPool,
}

impl LimitConnCtx {
    /// Allocate shared context in slab, initialize rbtree, return Option.
    fn new(zone: &ShmZone, key: ComplexValue) -> Option<Self> {
        let pool = zone.pool();

        // Allocate sentinel node in slab
        let sentinel_size = mem::size_of::<RbtreeNode>();
        let sentinel_ptr = unsafe { pool.alloc_locked(sentinel_size) } as *mut RbtreeNode;
        if sentinel_ptr.is_null() {
            return None;
        }

        unsafe {
            (*sentinel_ptr).key = 0;
            (*sentinel_ptr).color = 0;  // black
            (*sentinel_ptr).left = sentinel_ptr;
            (*sentinel_ptr).right = sentinel_ptr;
            (*sentinel_ptr).parent = sentinel_ptr;
        }

        // Set up log context message
        let log_msg = format!(" in limit_conn_zone \"{}\"", B(&zone.shm.name));
        let log_bytes = log_msg.as_bytes();
        unsafe {
            let ctx_ptr = pool.alloc_locked(log_bytes.len() + 1);
            if ctx_ptr.is_null() {
                pool.free_locked(sentinel_ptr as *mut u8);
                return None;
            }
            std::ptr::copy_nonoverlapping(log_bytes.as_ptr(), ctx_ptr, log_bytes.len());
            (*ctx_ptr.add(log_bytes.len())) = 0;
            pool.log_ctx = ctx_ptr;
        }

        Some(LimitConnCtx {
            key,
            root: RefCell::new(sentinel_ptr),
            sentinel: sentinel_ptr,
            shpool: pool as *const SlabPool,
        })
    }
}

/// Limit for a single zone with its maximum concurrent connection count.
#[derive(Clone)]
struct LimitConnLimit {
    zone: Rc<ShmZone>,
    conn: u32,
}

/// Location configuration for limit_conn module.
pub struct LimitConnConf {
    pub limits: Vec<LimitConnLimit>,
    pub log_level: Val<u32>,
    pub status_code: Val<u32>,
    pub dry_run: Val<bool>,
}

/// Create location configuration.
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LimitConnConf {
        limits: Vec::new(),
        log_level: Val::unset(),
        status_code: Val::unset(),
        dry_run: Val::unset(),
    })
}

/// Merge location configuration from parent.
fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<LimitConnConf>(prev).borrow();
    let mut c = conf_cell::<LimitConnConf>(conf).borrow_mut();

    if c.limits.is_empty() {
        c.limits = p.limits.clone();
    }

    c.log_level.merge(&p.log_level, NGX_LOG_ERR);
    c.status_code.merge(&p.status_code, 503);  // SERVICE_UNAVAILABLE
    c.dry_run.merge(&p.dry_run, false);

    Ok(())
}

/// Variable handler for $limit_conn_status.
fn limit_conn_status_variable(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let status = r.limit_conn_status.get();
    if status == 0 {
        v.not_found = 1;
        return NGX_OK;
    }

    let status_str = match status {
        LIMIT_CONN_PASSED => b"PASSED",
        LIMIT_CONN_REJECTED => b"REJECTED",
        LIMIT_CONN_REJECTED_DRY_RUN => b"REJECTED_DRY_RUN",
        _ => b"UNKNOWN",
    };

    v.data = status_str.to_vec();
    v.len = status_str.len();
    v.valid = 1;
    v.no_cacheable = 0;
    v.not_found = 0;

    NGX_OK
}

/// Add variables: $limit_conn_status
fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = vec![VarDef {
        name: "limit_conn_status",
        set: None,
        get: Some(limit_conn_status_variable),
        data: 0,
        flags: NGX_HTTP_VAR_NOCACHEABLE,
    }];
    variables::add_variables(cf, &vars)?;
    Ok(())
}

/// Initialize a limit_conn zone.
fn init_zone(zone: &Rc<ShmZone>, _prev_ctx: Option<Rc<dyn Any>>) -> Result<(), ()> {
    // Retrieve the key stored during directive parsing
    let zone_conf = zone.conf::<LimitConnZoneConf>()?;

    // Check if this zone was already initialized (reload scenario)
    if zone.data::<LimitConnCtx>().is_some() {
        return Ok(());
    }

    // Create and initialize the context
    let ctx = LimitConnCtx::new(zone, zone_conf.key.clone()).ok_or(())?;
    zone.data.replace(Some(Rc::new(ctx)));
    Ok(())
}

/// Delete a node from the rbtree.
unsafe fn limit_conn_rbtree_delete(ctx: &LimitConnCtx, node: *mut RbtreeNode) {
    let mut root_ref = ctx.root.borrow_mut();
    let root = *root_ref;
    let sentinel = ctx.sentinel;

    // Simple deletion: just unlink from tree (rebalancing is optional for this use case)
    let parent = (*node).parent;

    if parent == std::ptr::null_mut() || parent == root {
        // Node is root or root
        if (*node).left == sentinel && (*node).right == sentinel {
            *root_ref = sentinel;
        } else if (*node).left == sentinel {
            *root_ref = (*node).right;
            (*(*node).right).parent = std::ptr::null_mut();
        } else if (*node).right == sentinel {
            *root_ref = (*node).left;
            (*(*node).left).parent = std::ptr::null_mut();
        } else {
            // Both children exist - find in-order successor
            let mut succ = (*node).right;
            while (*succ).left != sentinel {
                succ = (*succ).left;
            }
            // Replace node with successor
            if (*node).left != sentinel {
                (*(*node).left).parent = succ;
            }
            (*succ).left = (*node).left;
            if succ != (*node).right {
                let succ_parent = (*succ).parent;
                (*succ_parent).left = (*succ).right;
                if (*succ).right != sentinel {
                    (*(*succ).right).parent = succ_parent;
                }
                (*succ).right = (*node).right;
                (*(*node).right).parent = succ;
            }
            *root_ref = succ;
            (*succ).parent = std::ptr::null_mut();
        }
    } else if (*parent).left == node {
        // Node is left child
        (*parent).left = if (*node).left != sentinel { (*node).left } else { (*node).right };
        if (*parent).left != sentinel {
            (*(*parent).left).parent = parent;
        }
    } else {
        // Node is right child
        (*parent).right = if (*node).left != sentinel { (*node).left } else { (*node).right };
        if (*parent).right != sentinel {
            (*(*parent).right).parent = parent;
        }
    }
}

/// RBtree insert function: inserts by hash first, then by key data.
unsafe fn limit_conn_rbtree_insert_value(
    mut temp: *mut RbtreeNode,
    node: *mut RbtreeNode,
    sentinel: *mut RbtreeNode,
) {
    loop {
        if (*node).key < (*temp).key {
            if (*temp).left == sentinel {
                (*temp).left = node;
                break;
            }
            temp = (*temp).left;
        } else if (*node).key > (*temp).key {
            if (*temp).right == sentinel {
                (*temp).right = node;
                break;
            }
            temp = (*temp).right;
        } else {
            // Same hash; compare key data lexicographically
            let lcn = ((&(*node).color as *const u8).add(1)) as *const LimitConnNode;
            let lcnt = ((&(*temp).color as *const u8).add(1)) as *const LimitConnNode;

            let cmp_len = std::cmp::min((*lcn).len, (*lcnt).len) as usize;
            let cmp = libc::memcmp(
                (*lcn).data.as_ptr() as *const libc::c_void,
                (*lcnt).data.as_ptr() as *const libc::c_void,
                cmp_len,
            );

            let left_side = if cmp == 0 {
                (*lcn).len < (*lcnt).len
            } else {
                cmp < 0
            };

            if left_side {
                if (*temp).left == sentinel {
                    (*temp).left = node;
                    break;
                }
                temp = (*temp).left;
            } else {
                if (*temp).right == sentinel {
                    (*temp).right = node;
                    break;
                }
                temp = (*temp).right;
            }
        }
    }

    (*node).parent = temp;
    (*node).left = sentinel;
    (*node).right = sentinel;
    rbtree::rbt_red(node);
}

/// Lookup a node in the rbtree by hash and key.
unsafe fn limit_conn_lookup(
    root: *mut RbtreeNode,
    sentinel: *mut RbtreeNode,
    key: &[u8],
    hash: u32,
) -> Option<*mut RbtreeNode> {
    let mut node = root;

    while node != sentinel {
        if (hash as usize) < (*node).key {
            node = (*node).left;
        } else if (hash as usize) > (*node).key {
            node = (*node).right;
        } else {
            // Hash matches; compare key data
            let lcn = ((&(*node).color as *const u8).add(1)) as *const LimitConnNode;
            let cmp_len = std::cmp::min(key.len(), (*lcn).len as usize);
            let cmp = libc::memcmp(
                key.as_ptr() as *const libc::c_void,
                (*lcn).data.as_ptr() as *const libc::c_void,
                cmp_len,
            );

            if cmp == 0 && key.len() == (*lcn).len as usize {
                return Some(node);
            } else if cmp < 0 || (cmp == 0 && key.len() < (*lcn).len as usize) {
                node = (*node).left;
            } else {
                node = (*node).right;
            }
        }
    }

    None
}

/// PREACCESS phase handler: check connection limit.
async fn limit_conn_handler(r: R) -> i64 {
    // Skip if already processed (for multiple limit_conn zones)
    if r.limit_conn_status.get() != 0 {
        return NGX_DECLINED;
    }

    let lccf = r.loc_conf::<LimitConnConf>(ctx_index());
    let limits = lccf.borrow().limits.clone();

    for limit in limits.iter() {
        let ctx_rc = match limit.zone.data::<LimitConnCtx>() {
            Some(c) => c,
            None => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "limit_conn zone context not found");
                continue;
            }
        };
        let ctx = ctx_rc.as_ref();

        // Compute the key from the complex value
        let key = match complex_value(&r, &ctx.key) {
            Ok(k) => k,
            Err(_) => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "failed to compute limit_conn key");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        };

        if key.is_empty() {
            continue;
        }

        if key.len() > 255 {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None,
                "the value of the \"{}\" key is more than 255 bytes",
                B(&ctx.key.value));
            continue;
        }

        r.limit_conn_status.set(LIMIT_CONN_PASSED);

        let hash = crc32_short(&key);
        let pool = unsafe { &*ctx.shpool };

        pool.lock();

        let node_opt = unsafe {
            limit_conn_lookup(*ctx.root.borrow(), ctx.sentinel, &key, hash)
        };

        let node = match node_opt {
            Some(n) => {
                // Node exists; check and increment counter
                unsafe {
                    let lc = ((&(*n).color as *const u8).add(1)) as *mut LimitConnNode;
                    if ((*lc).conn as u32) >= limit.conn {
                        pool.unlock();

                        let lccf_b = lccf.borrow();
                        ngx_log_error!(
                            lccf_b.log_level.get(),
                            r.connection.log,
                            None,
                            "limiting connections{} by zone \"{}\"",
                            if lccf_b.dry_run.get() { ", dry run," } else { "" },
                            B(&limit.zone.shm.name)
                        );

                        if lccf_b.dry_run.get() {
                            r.limit_conn_status.set(LIMIT_CONN_REJECTED_DRY_RUN);
                            return NGX_DECLINED;
                        }

                        r.limit_conn_status.set(LIMIT_CONN_REJECTED);
                        return lccf_b.status_code.get() as i64;
                    }

                    (*lc).conn += 1;
                    n
                }
            }
            None => {
                // Allocate new node: RbtreeNode + (len u8, conn u16, key data)
                let node_size = mem::size_of::<RbtreeNode>()
                    + mem::size_of::<u8>()  // len
                    + mem::size_of::<u16>() // conn
                    + key.len();

                let node_ptr = unsafe { pool.alloc_locked(node_size) };
                if node_ptr.is_null() {
                    pool.unlock();
                    // Could not allocate; treat as rejection if not dry_run
                    let lccf_b = lccf.borrow();
                    if lccf_b.dry_run.get() {
                        r.limit_conn_status.set(LIMIT_CONN_REJECTED_DRY_RUN);
                        return NGX_DECLINED;
                    }
                    r.limit_conn_status.set(LIMIT_CONN_REJECTED);
                    return lccf_b.status_code.get() as i64;
                }

                unsafe {
                    let n = node_ptr as *mut RbtreeNode;
                    (*n).key = hash as usize;

                    let lc = ((&(*n).color as *const u8).add(1)) as *mut LimitConnNode;
                    (*lc).len = key.len() as u8;
                    (*lc).conn = 1;
                    std::ptr::copy_nonoverlapping(
                        key.as_ptr(),
                        (*lc).data.as_mut_ptr(),
                        key.len(),
                    );

                    // Insert into rbtree
                    let mut root_ref = ctx.root.borrow_mut();
                    if *root_ref == ctx.sentinel {
                        // First node in tree
                        (*n).parent = std::ptr::null_mut();
                        (*n).left = ctx.sentinel;
                        (*n).right = ctx.sentinel;
                        (*n).color = 0;  // black
                        *root_ref = n;
                    } else {
                        limit_conn_rbtree_insert_value(*root_ref, n, ctx.sentinel);
                        rbtree::rbt_black(*root_ref);
                    }
                    drop(root_ref);

                    n
                }
            }
        };

        ngx_log_error!(NGX_LOG_DEBUG, r.connection.log, None,
            "limit conn: {:08x} {}",
            unsafe { (*node).key },
            unsafe { ((&(*node).color as *const u8).add(1) as *const LimitConnNode).as_ref().unwrap().conn });

        pool.unlock();

        // Register cleanup callback - capture the necessary values
        let zone_clone = limit.zone.clone();
        r.add_cleanup(Box::new(move || {
            if let Some(ctx_rc) = zone_clone.data::<LimitConnCtx>() {
                let ctx = ctx_rc.as_ref();
                let pool = unsafe { &*ctx.shpool };
                pool.lock();

                unsafe {
                    let lc = ((&(*node).color as *const u8).add(1)) as *mut LimitConnNode;
                    ngx_log_error!(NGX_LOG_DEBUG, pool.log_ctx, None,
                        "limit conn cleanup: {:08x} {}",
                        (*node).key, (*lc).conn);

                    (*lc).conn -= 1;
                    if (*lc).conn == 0 {
                        // Delete node from tree manually (simplified rbtree operations)
                        limit_conn_rbtree_delete(ctx, node);
                        pool.free_locked(node as *mut u8);
                    }
                }

                pool.unlock();
            }
        }));
    }

    NGX_DECLINED
}

/// Zone configuration stored temporarily in zone.conf
struct LimitConnZoneConf {
    key: ComplexValue,
}

/// Directive: limit_conn_zone KEY zone=NAME:SIZE
fn directive_limit_conn_zone(
    cf: &mut Conf,
    _cmd: &Command,
    _conf: Option<Rc<dyn Any>>,
) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 3 {
        return Err(cf.emerg(format_args!("limit_conn_zone requires at least 2 arguments")));
    }

    // Parse key (complex value)
    let key = compile_complex_value(cf, &args[1], 0)?;

    // Parse zone=NAME:SIZE
    let mut zone_name = Vec::new();
    let mut zone_size: usize = 0;

    for arg in &args[2..] {
        if arg.starts_with(b"zone=") {
            let rest = &arg[5..];
            if let Some(colon_pos) = rest.iter().position(|&b| b == b':') {
                zone_name = rest[..colon_pos].to_vec();
                let size_str = &rest[colon_pos + 1..];
                zone_size = ngx_core::parse::parse_size(size_str).ok_or_else(|| {
                    cf.emerg(format_args!("invalid zone size \"{}\"", B(size_str)))
                })?;

                if zone_size < 8 * 4096 {
                    return Err(cf.emerg(format_args!("zone \"{}\" is too small", B(&zone_name))));
                }
            } else {
                return Err(cf.emerg(format_args!("invalid zone syntax \"{}\"", B(arg))));
            }
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(arg))));
        }
    }

    if zone_name.is_empty() {
        return Err(cf.emerg(format_args!("limit_conn_zone must have \"zone\" parameter")));
    }

    // Create or reuse shared memory zone
    let zone = ngx_core::conf::shared_memory_add(cf, &zone_name, zone_size, "ngx_http_limit_conn_module")?;

    // Store zone config for init callback
    let zone_conf = LimitConnZoneConf { key };
    zone.conf.replace(Some(Rc::new(zone_conf)));

    // Set init callback
    zone.init.replace(Some(Rc::new(move |z, prev| init_zone(z, prev))));

    Ok(())
}

/// Directive: limit_conn ZONE NUMBER
fn directive_limit_conn(
    cf: &mut Conf,
    _cmd: &Command,
    conf: Option<Rc<dyn Any>>,
) -> ConfResult {
    let args = cf.args.clone();
    if args.len() != 3 {
        return Err(cf.emerg(format_args!("limit_conn requires exactly 2 arguments")));
    }

    let zone_name = &args[1];
    let conn_limit = atoi(&args[2]).ok_or_else(|| {
        cf.emerg(format_args!("invalid connection limit \"{}\"", B(&args[2])))
    })?;

    if conn_limit <= 0 {
        return Err(cf.emerg(format_args!("connection limit must be positive")));
    }

    if conn_limit > 65535 {
        return Err(cf.emerg(format_args!("connection limit must be less than 65536")));
    }

    // Find or create the zone
    let zone = ngx_core::conf::shared_memory_add(cf, zone_name, 0, "ngx_http_limit_conn_module")?;

    let lccf = conf_cell::<LimitConnConf>(conf.as_ref().unwrap());
    let mut c = lccf.borrow_mut();

    // Check for duplicates
    for limit in &c.limits {
        if Rc::ptr_eq(&limit.zone, &zone) {
            return Err(msg("is duplicate"));
        }
    }

    c.limits.push(LimitConnLimit {
        zone,
        conn: conn_limit as u32,
    });

    Ok(())
}

/// Module definition
pub fn limit_conn_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(add_variables),
        postconfiguration: Some(init),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    let commands = vec![
        ngx_core::cmd_fn!(
            "limit_conn_zone",
            NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE2MORE,
            ConfLevel::Main,
            directive_limit_conn_zone
        ),
        ngx_core::cmd_fn!(
            "limit_conn",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
            ConfLevel::Loc,
            directive_limit_conn
        ),
        ngx_core::cmd!(
            "limit_conn_log_level",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            LimitConnConf,
            log_level,
            set_enum_slot
        ),
        ngx_core::cmd!(
            "limit_conn_status",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            LimitConnConf,
            status_code,
            set_num_slot
        ),
        ngx_core::cmd!(
            "limit_conn_dry_run",
            NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
            ConfLevel::Loc,
            LimitConnConf,
            dry_run,
            set_flag
        ),
    ];

    http_module_def("ngx_http_limit_conn_module", def, commands)
}

/// Initialize module: register PREACCESS phase handler
fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_PREACCESS_PHASE,
        Rc::new(|r| Box::pin(limit_conn_handler(r))),
    );
    Ok(())
}
