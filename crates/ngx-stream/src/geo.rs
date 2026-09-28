//! ngx_stream_geo_module.c: a variable whose value depends on the client
//! address (or on the address in a variable): networks in radix trees, or
//! address ranges ("ranges"), with the binary geo range base.

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::{inet_addr, parse_addr, ptocidr, Cidr, CidrParse, SockAddr};
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::os;
use ngx_core::radix_tree::{RadixTree, NGX_RADIX_NO_VALUE};
use ngx_core::rbtree::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_geo_module");

const INADDR_NONE: u32 = 0xffffffff;

/// sizeof(void *)
const PTR: usize = std::mem::size_of::<usize>();

/// sizeof(ngx_stream_geo_header_t)
const HEADER_SIZE: usize = 16;

/// sizeof(ngx_stream_variable_value_t): a 32-bit bit field and a pointer
const VV_SIZE: usize = 2 * PTR;

/// sizeof(ngx_stream_geo_range_t): a pointer and two u_short
const RANGE_SIZE: usize = 2 * PTR;

/// ngx_stream_geo_range_t
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeoRange {
    /// the value: an index in GeoCtx::values
    pub value: usize,
    pub start: u16,
    pub end: u16,
}

/// ngx_stream_geo_high_ranges_t
pub struct GeoHighRanges {
    /// the ranges of each /16 network, NULL if there are no ranges
    pub low: Option<Vec<Option<Box<[GeoRange]>>>>,
    pub default_value: usize,
}

/// ngx_stream_geo_ctx_t "u"
pub enum GeoU {
    /// ngx_stream_geo_trees_t, the values in the trees are indices in
    /// GeoCtx::values
    Trees { tree: RadixTree, tree6: RadixTree },
    High(GeoHighRanges),
}

/// ngx_stream_geo_ctx_t
pub struct GeoCtx {
    pub u: GeoU,
    /// the index of the variable with the address, -1 for the client
    pub index: i64,
    /// the values (the configuration pool in C), the first one is
    /// ngx_stream_variable_null_value
    pub values: Vec<VariableValue>,
}

/// The contexts of the geo blocks, the variables' data point to them (the
/// configuration pool in C; the C module has no main conf).
#[derive(Default)]
pub struct GeoMainConf {
    pub geos: Vec<Rc<GeoCtx>>,
}

/// ngx_str_node_t
#[repr(C)]
struct StrNode {
    node: RbtreeNode,
    str: Vec<u8>,
}

/// ngx_stream_geo_variable_value_node_t
#[repr(C)]
struct GeoValueNode {
    sn: StrNode,
    value: usize,
    offset: usize,
}

/// ngx_stream_geo_conf_ctx_t
struct GeoConfCtx {
    value: usize,
    net: Vec<u8>,

    /// high.low: the ranges of each /16 while parsing (ngx_array_t)
    high_low: Option<Vec<Option<Vec<GeoRange>>>>,
    high_default: Option<usize>,

    tree: Option<RadixTree>,
    tree6: Option<RadixTree>,

    /// the values by their text (ngx_str_rbtree), nodes owned by the ctx
    rbtree: Rbtree,
    sentinel: *mut RbtreeNode,
    nodes: Vec<*mut GeoValueNode>,

    values: Vec<VariableValue>,

    data_size: usize,

    include_name: Vec<u8>,
    includes: usize,
    entries: usize,

    ranges: bool,
    outside_entries: bool,
    allow_binary_include: bool,
    binary_include: bool,
    no_cacheable: bool,
}

impl GeoConfCtx {
    fn new() -> GeoConfCtx {
        let sentinel = Box::into_raw(Box::new(RbtreeNode::new(0)));

        let mut rbtree = Rbtree { root: std::ptr::null_mut(), sentinel: std::ptr::null_mut(), insert: None };

        // the sentinel is owned by the ctx and freed in drop()
        unsafe { rbtree.init(sentinel, str_rbtree_insert_value) };

        GeoConfCtx {
            value: 0,
            net: Vec::new(),
            high_low: None,
            high_default: None,
            tree: None,
            tree6: None,
            rbtree,
            sentinel,
            nodes: Vec::new(),
            values: vec![null_value()],
            data_size: HEADER_SIZE + VV_SIZE + 0x10000 * PTR,
            include_name: Vec::new(),
            includes: 0,
            entries: 0,
            ranges: false,
            outside_entries: false,
            allow_binary_include: true,
            binary_include: false,
            no_cacheable: false,
        }
    }
}

impl Drop for GeoConfCtx {
    fn drop(&mut self) {
        // the nodes and the sentinel were allocated with Box::into_raw()
        // and are referenced only by the tree, which dies with the ctx
        for p in self.nodes.drain(..) {
            drop(unsafe { Box::from_raw(p) });
        }
        drop(unsafe { Box::from_raw(self.sentinel) });
    }
}

/// ngx_str_rbtree_insert_value: all nodes of the tree are StrNodes
unsafe fn str_rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let mut p: *mut *mut RbtreeNode;

    loop {
        let n: &Vec<u8> = &(*(node as *mut StrNode)).str;
        let t: &Vec<u8> = &(*(temp as *mut StrNode)).str;

        if (*node).key != (*temp).key {
            p = if (*node).key < (*temp).key { &mut (*temp).left } else { &mut (*temp).right };
        } else if n.len() != t.len() {
            p = if n.len() < t.len() { &mut (*temp).left } else { &mut (*temp).right };
        } else {
            p = if n < t { &mut (*temp).left } else { &mut (*temp).right };
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

/// ngx_str_rbtree_lookup
unsafe fn str_rbtree_lookup(rbtree: &Rbtree, val: &[u8], hash: u32) -> *mut StrNode {
    let mut node = rbtree.root;
    let sentinel = rbtree.sentinel;

    let hash = hash as usize;

    while node != sentinel {
        let n = node as *mut StrNode;
        let nstr: &Vec<u8> = &(*n).str;

        if hash != (*node).key {
            node = if hash < (*node).key { (*node).left } else { (*node).right };
            continue;
        }

        if val.len() != nstr.len() {
            node = if val.len() < nstr.len() { (*node).left } else { (*node).right };
            continue;
        }

        match val.cmp(&nstr[..]) {
            std::cmp::Ordering::Less => node = (*node).left,
            std::cmp::Ordering::Greater => node = (*node).right,
            std::cmp::Ordering::Equal => return n,
        }
    }

    std::ptr::null_mut()
}

/// ngx_align
fn align(d: usize, a: usize) -> usize {
    (d + (a - 1)) & !(a - 1)
}

/// IN6_IS_ADDR_V4MAPPED, the IPv4 address in host order
fn v4mapped(p: &[u8; 16]) -> Option<u32> {
    if p[..10].iter().all(|&b| b == 0) && p[10] == 0xff && p[11] == 0xff {
        return Some(u32::from_be_bytes([p[12], p[13], p[14], p[15]]));
    }

    None
}

/// The geo module ctx of a variable's data.
fn geo_ctx(data: usize) -> &'static GeoCtx {
    // data is Rc::as_ptr() of a GeoCtx kept alive by the module's main conf
    // of the configuration the session uses (s->main_conf holds it)
    unsafe { &*(data as *const GeoCtx) }
}

/// ngx_stream_geo_cidr_variable
fn geo_cidr_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let ctx = geo_ctx(data);

    let (tree, tree6) = match &ctx.u {
        GeoU::Trees { tree, tree6 } => (tree, tree6),
        GeoU::High(_) => return NGX_ERROR,
    };

    let vv = match geo_addr(s, ctx) {
        None => tree.find32(INADDR_NONE),

        Some(SockAddr::V6(sin6)) => {
            let p = sin6.ip().octets();

            match v4mapped(&p) {
                Some(inaddr) => tree.find32(inaddr),
                None => tree6.find128(&p),
            }
        }

        Some(SockAddr::Unix(_)) => tree.find32(INADDR_NONE),

        Some(SockAddr::V4(sin)) => tree.find32(u32::from(*sin.ip())),
    };

    // the root of the trees always has a value
    let vv = if vv == NGX_RADIX_NO_VALUE { 0 } else { vv };

    *v = ctx.values[vv].clone();

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream geo: {}", B(&v.data));

    NGX_OK
}

/// ngx_stream_geo_range_variable
fn geo_range_variable(s: &Session, v: &mut VariableValue, data: usize) -> i64 {
    let ctx = geo_ctx(data);

    let high = match &ctx.u {
        GeoU::High(h) => h,
        GeoU::Trees { .. } => return NGX_ERROR,
    };

    *v = ctx.values[high.default_value].clone();

    let inaddr = match geo_addr(s, ctx) {
        Some(SockAddr::V6(sin6)) => v4mapped(&sin6.ip().octets()).unwrap_or(INADDR_NONE),
        Some(SockAddr::Unix(_)) => INADDR_NONE,
        Some(SockAddr::V4(sin)) => u32::from(*sin.ip()),
        None => INADDR_NONE,
    };

    if let Some(low) = &high.low {
        if let Some(range) = &low[(inaddr >> 16) as usize] {
            let n = (inaddr & 0xffff) as u16;

            for r in range.iter() {
                if n >= r.start && n <= r.end {
                    *v = ctx.values[r.value].clone();
                    break;
                }
            }
        }
    }

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, s.connection.log, "stream geo: {}", B(&v.data));

    NGX_OK
}

/// ngx_stream_geo_addr: the address to look up, None (NGX_ERROR) if the
/// variable is not found or is not an address
fn geo_addr(s: &Session, ctx: &GeoCtx) -> Option<SockAddr> {
    let c = &s.connection;

    if ctx.index == -1 {
        ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream geo started: {}", B(&c.addr_text.borrow()));

        return Some(c.sockaddr.borrow().clone());
    }

    let v = match get_flushed_variable(s, ctx.index as usize) {
        Some(v) if !v.not_found => v,
        _ => {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream geo not found");
            return None;
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream geo started: {}", B(&v.data));

    parse_addr(&v.data)
}

fn geo_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(GeoMainConf::default())
}

/// ngx_stream_geo_block
fn geo_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let value = cf.args.clone();

    let mut name = value[1].clone();

    if name.first() != Some(&b'$') {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(&name))));
    }

    name.remove(0);

    let index = if value.len() == 3 {
        let index = get_variable_index(cf, &name)? as i64;

        name = value[2].clone();

        if name.first() != Some(&b'$') {
            return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(&name))));
        }

        name.remove(0);

        index
    } else {
        -1
    };

    let var = add_variable(cf, &name, NGX_STREAM_VAR_CHANGEABLE)?;

    let ctx = Rc::new(RefCell::new(GeoConfCtx::new()));

    let saved_handler = cf.handler.take();
    let saved_handler_conf = cf.handler_conf.take();

    cf.handler = Some(geo_handler);
    cf.handler_conf = Some(ctx.clone() as Rc<dyn Any>);

    let rv = cf.parse_block();

    cf.handler = saved_handler;
    cf.handler_conf = saved_handler_conf;

    rv?;

    let mut ctx = match Rc::try_unwrap(ctx) {
        Ok(c) => c.into_inner(),
        Err(_) => return Err(ConfError::Logged),
    };

    if ctx.no_cacheable {
        var.flags.set(var.flags.get() | NGX_STREAM_VAR_NOCACHEABLE);
    }

    let geo = if ctx.ranges {
        if ctx.high_low.is_some() && !ctx.binary_include {
            let mut data_size = 0;

            for a in ctx.high_low.as_mut().unwrap().iter_mut() {
                let n = match a {
                    None => continue,
                    Some(a) => a.len(),
                };

                if n == 0 {
                    *a = None;
                    continue;
                }

                data_size += n * RANGE_SIZE + PTR;
            }

            ctx.data_size += data_size;

            if ctx.allow_binary_include && !ctx.outside_entries && ctx.entries > 100000 && ctx.includes == 1 {
                geo_create_binary_base(cf, &mut ctx);
            }
        }

        let default_value = ctx.high_default.unwrap_or(0);

        let low = ctx.high_low.take().map(|low| low.into_iter().map(|a| a.filter(|a| !a.is_empty()).map(|a| a.into_boxed_slice())).collect());

        var.get_handler.set(Some(geo_range_variable));

        GeoCtx { u: GeoU::High(GeoHighRanges { low, default_value }), index, values: std::mem::take(&mut ctx.values) }
    } else {
        let tree = ctx.tree.take().unwrap_or_else(|| RadixTree::create(-1));
        let tree6 = ctx.tree6.take().unwrap_or_else(|| RadixTree::create(-1));

        var.get_handler.set(Some(geo_cidr_variable));

        // NGX_BUSY is okay (default was set explicitly)

        if tree.insert32(0, 0, 0) == NGX_ERROR as i32 {
            return Err(ConfError::Logged);
        }

        let zero = [0u8; 16];

        if tree6.insert128(&zero, &zero, 0) == NGX_ERROR as i32 {
            return Err(ConfError::Logged);
        }

        GeoCtx { u: GeoU::Trees { tree, tree6 }, index, values: std::mem::take(&mut ctx.values) }
    };

    let geo = Rc::new(geo);

    var.data.set(Rc::as_ptr(&geo) as usize);

    let gmcf = conf_rc::<GeoMainConf>(conf.as_ref().expect("geo conf"));
    gmcf.borrow_mut().geos.push(geo);

    Ok(())
}

/// ngx_stream_geo: a line of the geo block
fn geo_handler(cf: &mut Conf, conf: Rc<dyn Any>) -> ConfResult {
    let ctx = conf.clone().downcast::<RefCell<GeoConfCtx>>().expect("geo conf ctx");

    let value = cf.args.clone();

    if value.len() == 1 {
        if value[0] == b"ranges" {
            let trees = {
                let c = ctx.borrow();
                c.tree.is_some() || c.tree6.is_some()
            };

            if trees {
                return Err(cf.emerg(format_args!("the \"ranges\" directive must be the first directive inside \"geo\" block")));
            }

            ctx.borrow_mut().ranges = true;

            return Ok(());
        } else if value[0] == b"volatile" {
            ctx.borrow_mut().no_cacheable = true;
            return Ok(());
        }
    }

    if value.len() != 2 {
        return Err(cf.emerg(format_args!("invalid number of the geo parameters")));
    }

    if value[0] == b"include" {
        if !value[1].iter().any(|c| b"*?[".contains(c)) {
            return geo_include(cf, &ctx, &value[1]);
        }

        let dummy = Command::new("include", NGX_ANY_CONF | NGX_CONF_TAKE1, ConfLevel::None, conf_include);

        return conf_include(cf, &dummy, Some(conf));
    }

    let ranges = ctx.borrow().ranges;

    let mut c = ctx.borrow_mut();

    if ranges {
        geo_range(cf, &mut c, &value)
    } else {
        geo_cidr(cf, &mut c, &value)
    }
}

/// ngx_stream_geo_range
fn geo_range(cf: &mut Conf, ctx: &mut GeoConfCtx, value: &[Vec<u8>]) -> ConfResult {
    if value[0] == b"default" {
        if let Some(old) = ctx.high_default {
            cf.warn(format_args!("duplicate default geo range value: \"{}\", old value: \"{}\"", B(&value[1]), B(&ctx.values[old].data)));
        }

        ctx.high_default = Some(geo_value(ctx, &value[1]));

        return Ok(());
    }

    if ctx.binary_include {
        return Err(cf.emerg(format_args!("binary geo range base \"{}\" cannot be mixed with usual entries", B(&ctx.include_name))));
    }

    if ctx.high_low.is_none() {
        ctx.high_low = Some(vec![None; 0x10000]);
    }

    ctx.entries += 1;
    ctx.outside_entries = true;

    let (net, del) = if value[0] == b"delete" { (&value[1], true) } else { (&value[0], false) };

    let invalid = |cf: &Conf| cf.emerg(format_args!("invalid range \"{}\"", B(net)));

    let p = match net.iter().position(|&c| c == b'-') {
        Some(p) => p,
        None => return Err(invalid(cf)),
    };

    let start = match inet_addr(&net[..p]).map(u32::from) {
        Some(a) => a,
        None => return Err(invalid(cf)),
    };

    let end = match inet_addr(&net[p + 1..]).map(u32::from) {
        Some(a) => a,
        None => return Err(invalid(cf)),
    };

    if start > end {
        return Err(invalid(cf));
    }

    if del {
        if geo_delete_range(ctx, start, end) {
            cf.warn(format_args!("no address range \"{}\" to delete", B(net)));
        }

        return Ok(());
    }

    ctx.value = geo_value(ctx, &value[1]);

    ctx.net = net.clone();

    geo_add_range(cf, ctx, start, end)
}

/// ngx_stream_geo_add_range: the add procedure is optimized to add a
/// growing up sequence
fn geo_add_range(cf: &mut Conf, ctx: &mut GeoConfCtx, start: u32, end: u32) -> ConfResult {
    let value = ctx.value;

    let mut n = start;

    while n <= end {
        let h = (n >> 16) as usize;

        let mut s = if n == start { n & 0xffff } else { 0 };

        let mut e = if (n | 0xffff) > end { end & 0xffff } else { 0xffff };

        let a = ctx.high_low.as_mut().unwrap()[h].get_or_insert_with(|| Vec::with_capacity(64));

        let mut i = a.len();
        let mut added = false;

        while i > 0 {
            i -= 1;

            let r = a[i];

            if e < r.start as u32 {
                continue;
            }

            if s > r.end as u32 {
                // add after the range

                a.insert(i + 1, GeoRange { value, start: s as u16, end: e as u16 });

                added = true;
                break;
            }

            if s == r.start as u32 && e == r.end as u32 {
                cf.warn(format_args!(
                    "duplicate range \"{}\", value: \"{}\", old value: \"{}\"",
                    B(&ctx.net),
                    B(&ctx.values[value].data),
                    B(&ctx.values[r.value].data)
                ));

                a[i].value = value;

                added = true;
                break;
            }

            if s > r.start as u32 && e < r.end as u32 {
                // split the range and insert the new one

                a.insert(i + 1, GeoRange { value, start: s as u16, end: e as u16 });
                a.insert(i + 2, GeoRange { value: r.value, start: (e + 1) as u16, end: r.end });

                a[i].end = (s - 1) as u16;

                added = true;
                break;
            }

            if s == r.start as u32 && e < r.end as u32 {
                // shift the range start and insert the new range

                a.insert(i, GeoRange { value, start: s as u16, end: e as u16 });

                a[i + 1].start = (e + 1) as u16;

                added = true;
                break;
            }

            if s > r.start as u32 && e == r.end as u32 {
                // shift the range end and insert the new range

                a.insert(i + 1, GeoRange { value, start: s as u16, end: e as u16 });

                a[i].end = (s - 1) as u16;

                added = true;
                break;
            }

            s = r.start as u32;
            e = r.end as u32;

            return Err(cf.emerg(format_args!(
                "range \"{}\" overlaps \"{}.{}.{}.{}-{}.{}.{}.{}\"",
                B(&ctx.net),
                h >> 8,
                h & 0xff,
                s >> 8,
                s & 0xff,
                h >> 8,
                h & 0xff,
                e >> 8,
                e & 0xff
            )));
        }

        if !added {
            // add the first range

            a.insert(0, GeoRange { value, start: s as u16, end: e as u16 });
        }

        // next:

        if h == 0xffff {
            break;
        }

        n = n.wrapping_add(0x10000) & 0xffff0000;
    }

    Ok(())
}

/// ngx_stream_geo_delete_range: true (warn) if a range was not found
fn geo_delete_range(ctx: &mut GeoConfCtx, start: u32, end: u32) -> bool {
    let mut warn = false;

    let mut n = start;

    while n <= end {
        let h = (n >> 16) as usize;

        let s = if n == start { n & 0xffff } else { 0 };

        let e = if (n | 0xffff) > end { end & 0xffff } else { 0xffff };

        match &mut ctx.high_low.as_mut().unwrap()[h] {
            Some(a) if !a.is_empty() => {
                let len = a.len();

                for i in 0..len {
                    if s == a[i].start as u32 && e == a[i].end as u32 {
                        a.remove(i);
                        break;
                    }

                    if i == len - 1 {
                        warn = true;
                    }
                }
            }

            _ => warn = true,
        }

        // next:

        if h == 0xffff {
            break;
        }

        n = n.wrapping_add(0x10000) & 0xffff0000;
    }

    warn
}

/// ngx_stream_geo_cidr
fn geo_cidr(cf: &mut Conf, ctx: &mut GeoConfCtx, value: &[Vec<u8>]) -> ConfResult {
    if ctx.tree.is_none() {
        ctx.tree = Some(RadixTree::create(-1));
    }

    if ctx.tree6.is_none() {
        ctx.tree6 = Some(RadixTree::create(-1));
    }

    if value[0] == b"default" {
        let cidr = Cidr::V4 { addr: 0, mask: 0 };

        geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0])?;

        let cidr = Cidr::V6 { addr: [0; 16], mask: [0; 16] };

        geo_cidr_add(cf, ctx, &cidr, &value[1], &value[0])?;

        return Ok(());
    }

    let (net, del) = if value[0] == b"delete" { (&value[1], true) } else { (&value[0], false) };

    let cidr = geo_cidr_value(cf, net)?;

    if del {
        let rc = match &cidr {
            Cidr::V6 { addr, mask } => ctx.tree6.as_ref().unwrap().delete128(addr, mask),
            Cidr::V4 { addr, mask } => ctx.tree.as_ref().unwrap().delete32(*addr, *mask),
            Cidr::Unix => NGX_ERROR as i32,
        };

        if rc != NGX_OK as i32 {
            cf.warn(format_args!("no network \"{}\" to delete", B(net)));
        }

        return Ok(());
    }

    geo_cidr_add(cf, ctx, &cidr, &value[1], net)
}

/// ngx_stream_geo_cidr_add
fn geo_cidr_add(cf: &mut Conf, ctx: &mut GeoConfCtx, cidr: &Cidr, value: &[u8], net: &[u8]) -> ConfResult {
    let val = geo_value(ctx, value);

    let rc = match cidr {
        Cidr::V6 { addr, mask } => {
            let tree6 = ctx.tree6.as_ref().unwrap();

            let rc = tree6.insert128(addr, mask, val);

            if rc == NGX_OK as i32 {
                return Ok(());
            }

            if rc == NGX_ERROR as i32 {
                return Err(ConfError::Logged);
            }

            // rc == NGX_BUSY

            let old = tree6.find128(addr);

            cf.warn(format_args!("duplicate network \"{}\", value: \"{}\", old value: \"{}\"", B(net), B(&ctx.values[val].data), B(value_data(&ctx.values, old))));

            let rc = tree6.delete128(addr, mask);

            if rc == NGX_ERROR as i32 {
                return Err(cf.emerg(format_args!("invalid radix tree")));
            }

            tree6.insert128(addr, mask, val)
        }

        Cidr::V4 { addr, mask } => {
            let tree = ctx.tree.as_ref().unwrap();

            let rc = tree.insert32(*addr, *mask, val);

            if rc == NGX_OK as i32 {
                return Ok(());
            }

            if rc == NGX_ERROR as i32 {
                return Err(ConfError::Logged);
            }

            // rc == NGX_BUSY

            let old = tree.find32(*addr);

            cf.warn(format_args!("duplicate network \"{}\", value: \"{}\", old value: \"{}\"", B(net), B(&ctx.values[val].data), B(value_data(&ctx.values, old))));

            let rc = tree.delete32(*addr, *mask);

            if rc == NGX_ERROR as i32 {
                return Err(cf.emerg(format_args!("invalid radix tree")));
            }

            tree.insert32(*addr, *mask, val)
        }

        Cidr::Unix => NGX_ERROR as i32,
    };

    if rc == NGX_OK as i32 {
        return Ok(());
    }

    Err(ConfError::Logged)
}

/// The text of a value found in a tree.
fn value_data(values: &[VariableValue], v: usize) -> &[u8] {
    values.get(v).map(|v| &v.data[..]).unwrap_or(b"")
}

/// ngx_stream_geo_value: the values with the same text are shared
fn geo_value(ctx: &mut GeoConfCtx, value: &[u8]) -> usize {
    let hash = crc32fast::hash(value);

    let gvvn = unsafe { str_rbtree_lookup(&ctx.rbtree, value, hash) };

    if !gvvn.is_null() {
        // the tree nodes are GeoValueNodes
        return unsafe { (*(gvvn as *mut GeoValueNode)).value };
    }

    let index = ctx.values.len();

    ctx.values.push(VariableValue { data: value.to_vec(), valid: true, no_cacheable: false, not_found: false });

    let node = Box::into_raw(Box::new(GeoValueNode { sn: StrNode { node: RbtreeNode::new(hash as usize), str: value.to_vec() }, value: index, offset: 0 }));

    ctx.nodes.push(node);

    // the node lives until the ctx is dropped, as the tree
    unsafe { ctx.rbtree.insert(node as *mut RbtreeNode) };

    ctx.data_size += align(VV_SIZE + value.len(), PTR);

    index
}

/// ngx_stream_geo_cidr_value
fn geo_cidr_value(cf: &mut Conf, net: &[u8]) -> Result<Cidr, ConfError> {
    if net == b"255.255.255.255" {
        return Ok(Cidr::V4 { addr: 0xffffffff, mask: 0xffffffff });
    }

    let rc = ptocidr(net);

    match rc {
        CidrParse::Error => Err(cf.emerg(format_args!("invalid network \"{}\"", B(net)))),

        CidrParse::Done(cidr) => {
            cf.warn(format_args!("low address bits of {} are meaningless", B(net)));
            Ok(cidr)
        }

        CidrParse::Ok(cidr) => Ok(cidr),
    }
}

/// ngx_stream_geo_include
fn geo_include(cf: &mut Conf, ctx: &Rc<RefCell<GeoConfCtx>>, name: &[u8]) -> ConfResult {
    let mut file = name.to_vec();
    file.extend_from_slice(b".bin");

    let file = cf.full_name(&file, true);

    if ctx.borrow().ranges {
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, cf.log, "include {}", B(&file));

        match geo_include_binary_base(cf, ctx, &file) {
            NGX_OK => return Ok(()),
            NGX_ERROR => return Err(ConfError::Logged),
            _ => {}
        }
    }

    let file = file[..file.len() - 4].to_vec();

    {
        let mut c = ctx.borrow_mut();

        c.include_name = file.clone();

        if c.outside_entries {
            c.allow_binary_include = false;
        }
    }

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, cf.log, "include {}", B(&file));

    let rv = cf.parse_file(&file);

    {
        let mut c = ctx.borrow_mut();
        c.includes += 1;
        c.outside_entries = false;
    }

    rv
}

/// ngx_stream_geo_header_t without crc32: "GEORNG", version 0, the pointer
/// size and the byte order
fn geo_header() -> [u8; 12] {
    let mut h = [0u8; 12];
    h[..6].copy_from_slice(b"GEORNG");
    h[6] = 0;
    h[7] = PTR as u8;
    h[8..12].copy_from_slice(&0x12345678u32.to_ne_bytes());
    h
}

fn get_ptr(base: &[u8], off: usize) -> Option<usize> {
    let b = base.get(off..off + PTR)?;
    let mut a = [0u8; PTR];
    a.copy_from_slice(b);
    Some(usize::from_ne_bytes(a))
}

fn put_ptr(base: &mut [u8], off: usize, v: usize) {
    base[off..off + PTR].copy_from_slice(&v.to_ne_bytes());
}

/// The values and the ranges of a binary base (relocated in place in C):
/// None if the base is malformed.
fn geo_parse_binary_base(base: &[u8], values: &mut Vec<VariableValue>) -> Option<Vec<Option<Vec<GeoRange>>>> {
    let size = base.len();

    let mut offsets: HashMap<usize, usize> = HashMap::new();

    let mut vv = HEADER_SIZE;

    loop {
        let bits = u32::from_ne_bytes(base.get(vv..vv + 4)?.try_into().ok()?);
        let data = get_ptr(base, vv + PTR)?;

        if data == 0 {
            break;
        }

        let len = (bits & 0x0fffffff) as usize;

        if data.checked_add(len)? > size {
            return None;
        }

        offsets.insert(vv, values.len());

        values.push(VariableValue {
            data: base[data..data + len].to_vec(),
            valid: bits & (1 << 28) != 0,
            no_cacheable: bits & (1 << 29) != 0,
            not_found: bits & (1 << 30) != 0,
        });

        vv += align(VV_SIZE + len, PTR);
    }

    vv += VV_SIZE;

    let ranges = vv;

    if ranges + 0x10000 * PTR > size {
        return None;
    }

    let mut low: Vec<Option<Vec<GeoRange>>> = vec![None; 0x10000];

    for (i, l) in low.iter_mut().enumerate() {
        let mut range = get_ptr(base, ranges + i * PTR)?;

        if range == 0 {
            continue;
        }

        let mut a = Vec::new();

        loop {
            let value = get_ptr(base, range)?;

            if value == 0 {
                break;
            }

            let start = u16::from_ne_bytes(base.get(range + PTR..range + PTR + 2)?.try_into().ok()?);
            let end = u16::from_ne_bytes(base.get(range + PTR + 2..range + PTR + 4)?.try_into().ok()?);

            a.push(GeoRange { value: *offsets.get(&value)?, start, end });

            range += RANGE_SIZE;
        }

        if !a.is_empty() {
            *l = Some(a);
        }
    }

    Some(low)
}

/// ngx_stream_geo_include_binary_base: NGX_OK, NGX_ERROR, or NGX_DECLINED
/// to include the text file
fn geo_include_binary_base(cf: &mut Conf, ctx: &Rc<RefCell<GeoConfCtx>>, name: &[u8]) -> i64 {
    let fd = match os::open(name, libc::O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(err) => {
            if err != libc::ENOENT {
                cf.log_error(NGX_LOG_CRIT, Some(err), format_args!("open() \"{}\" failed", B(name)));
            }
            return NGX_DECLINED;
        }
    };

    let rc = 'done: {
        {
            let c = ctx.borrow();

            if c.outside_entries {
                cf.log_error(NGX_LOG_EMERG, None, format_args!("binary geo range base \"{}\" cannot be mixed with usual entries", B(name)));
                break 'done NGX_ERROR;
            }

            if c.binary_include {
                cf.log_error(NGX_LOG_EMERG, None, format_args!("second binary geo range base \"{}\" cannot be mixed with \"{}\"", B(name), B(&c.include_name)));
                break 'done NGX_ERROR;
            }
        }

        'failed: {
            let fi = match os::fstat(fd) {
                Ok(fi) => fi,
                Err(err) => {
                    cf.log_error(NGX_LOG_CRIT, Some(err), format_args!("fstat() \"{}\" failed", B(name)));
                    break 'failed;
                }
            };

            let size = fi.st_size as usize;
            let mtime = fi.st_mtime;

            let text = &name[..name.len() - 4];

            let fi = match os::stat(text) {
                Ok(fi) => fi,
                Err(err) => {
                    cf.log_error(NGX_LOG_CRIT, Some(err), format_args!("stat() \"{}\" failed", B(text)));
                    break 'failed;
                }
            };

            if mtime < fi.st_mtime {
                cf.log_error(NGX_LOG_WARN, None, format_args!("stale binary geo range base \"{}\"", B(name)));
                break 'failed;
            }

            let mut base = vec![0u8; size];

            ngx_log_debug!(NGX_LOG_DEBUG_CORE, cf.log, "read: {}, {:p}, {}, 0", fd, base.as_ptr(), size);

            let n = unsafe { libc::pread(fd, base.as_mut_ptr() as *mut libc::c_void, size, 0) };

            if n == -1 {
                let err = os::errno();
                ngx_log_error!(NGX_LOG_CRIT, cf.log, Some(err), "pread() \"{}\" failed", B(name));
                cf.log_error(NGX_LOG_CRIT, Some(err), format_args!("pread() \"{}\" failed", B(name)));
                break 'failed;
            }

            if n as usize != size {
                cf.log_error(NGX_LOG_CRIT, None, format_args!("pread() \"{}\" returned only {} bytes instead of {}", B(name), n, size));
                break 'failed;
            }

            if size < 16 || base[..12] != geo_header() {
                cf.log_error(NGX_LOG_WARN, None, format_args!("incompatible binary geo range base \"{}\"", B(name)));
                break 'failed;
            }

            // the base is walked below, so make sure it is intact first:
            // the checksum in the header is computed over the entire body

            if size < HEADER_SIZE + VV_SIZE + 0x10000 * PTR {
                cf.log_error(NGX_LOG_WARN, None, format_args!("truncated binary geo range base \"{}\"", B(name)));
                break 'failed;
            }

            let crc = u32::from_ne_bytes(base[12..16].try_into().unwrap());

            if crc32fast::hash(&base[HEADER_SIZE..]) != crc {
                cf.log_error(NGX_LOG_WARN, None, format_args!("CRC32 mismatch in binary geo range base \"{}\"", B(name)));
                break 'failed;
            }

            let mut values = std::mem::take(&mut ctx.borrow_mut().values);
            let nvalues = values.len();

            let low = geo_parse_binary_base(&base, &mut values);

            if low.is_none() {
                values.truncate(nvalues);
            }

            ctx.borrow_mut().values = values;

            let low = match low {
                Some(low) => low,
                None => {
                    // C walks the base without bounds checking
                    cf.log_error(NGX_LOG_WARN, None, format_args!("truncated binary geo range base \"{}\"", B(name)));
                    break 'failed;
                }
            };

            cf.log_error(NGX_LOG_NOTICE, None, format_args!("using binary geo range base \"{}\"", B(name)));

            let mut c = ctx.borrow_mut();

            c.include_name = name.to_vec();
            c.binary_include = true;
            c.high_low = Some(low);

            break 'done NGX_OK;
        }

        // failed:

        NGX_DECLINED
    };

    if unsafe { libc::close(fd) } == -1 {
        ngx_log_error!(NGX_LOG_ALERT, cf.log, Some(os::errno()), "close() \"{}\" failed", B(name));
    }

    rc
}

/// ngx_stream_geo_create_binary_base
fn geo_create_binary_base(cf: &Conf, ctx: &mut GeoConfCtx) {
    let mut name = ctx.include_name.clone();
    name.extend_from_slice(b".bin");

    let size = ctx.data_size;

    let log = &cf.log;

    ngx_log_error!(NGX_LOG_NOTICE, log, None, "creating binary geo range base \"{}\"", B(&name));

    // ngx_create_file_mapping

    let fd = match os::open(&name, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) {
        Ok(fd) => fd,
        Err(err) => {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "open() \"{}\" failed", B(&name));
            return;
        }
    };

    let close = |fd: i32| {
        if unsafe { libc::close(fd) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(os::errno()), "close() \"{}\" failed", B(&name));
        }
    };

    if unsafe { libc::ftruncate(fd, size as libc::off_t) } == -1 {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(os::errno()), "ftruncate() \"{}\" failed", B(&name));
        close(fd);
        return;
    }

    let addr = unsafe { libc::mmap(std::ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0) };

    if addr == libc::MAP_FAILED {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(os::errno()), "mmap({}) \"{}\" failed", size, B(&name));
        close(fd);
        return;
    }

    // the mapping of the new file: size zero bytes, unmapped below
    let base = unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, size) };

    base[..12].copy_from_slice(&geo_header());

    let mut p = HEADER_SIZE;

    p = unsafe { geo_copy_values(base, p, ctx.rbtree.root, ctx.rbtree.sentinel, &ctx.values) };

    p += VV_SIZE;

    let ranges = p;

    p += 0x10000 * PTR;

    for (i, r) in ctx.high_low.as_ref().unwrap().iter().enumerate() {
        let r = match r {
            None => continue,
            Some(r) => r,
        };

        put_ptr(base, ranges + i * PTR, p);

        for range in r.iter() {
            let s = &ctx.values[range.value].data;
            let hash = crc32fast::hash(s);

            // the values of the ranges are in the tree
            let gvvn = unsafe { str_rbtree_lookup(&ctx.rbtree, s, hash) as *mut GeoValueNode };
            let offset = unsafe { (*gvvn).offset };

            put_ptr(base, p, offset);
            base[p + PTR..p + PTR + 2].copy_from_slice(&range.start.to_ne_bytes());
            base[p + PTR + 2..p + PTR + 4].copy_from_slice(&range.end.to_ne_bytes());

            p += RANGE_SIZE;
        }

        // range->value = NULL

        p += PTR;
    }

    let crc = crc32fast::hash(&base[HEADER_SIZE..size]);
    base[12..16].copy_from_slice(&crc.to_ne_bytes());

    // ngx_close_file_mapping

    if unsafe { libc::munmap(addr, size) } == -1 {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(os::errno()), "munmap({}) \"{}\" failed", size, B(&name));
    }

    close(fd);
}

/// ngx_stream_geo_copy_values: the values of the tree in preorder
unsafe fn geo_copy_values(base: &mut [u8], mut p: usize, node: *mut RbtreeNode, sentinel: *mut RbtreeNode, values: &[VariableValue]) -> usize {
    if node == sentinel {
        return p;
    }

    let gvvn = node as *mut GeoValueNode;

    (*gvvn).offset = p;

    let vv = &values[(*gvvn).value];

    let bits = (vv.data.len() as u32 & 0x0fffffff) | (vv.valid as u32) << 28 | (vv.no_cacheable as u32) << 29 | (vv.not_found as u32) << 30;

    base[p..p + 4].copy_from_slice(&bits.to_ne_bytes());

    let data = p + PTR;

    p += VV_SIZE;

    put_ptr(base, data, p);

    let str: &Vec<u8> = &(*gvvn).sn.str;

    base[p..p + str.len()].copy_from_slice(str);

    p += str.len();

    p = align(p, PTR);

    p = geo_copy_values(base, p, (*node).left, sentinel, values);

    geo_copy_values(base, p, (*node).right, sentinel, values)
}

pub fn geo_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_geo_module",
        StreamModuleDef { create_main_conf: Some(geo_create_main_conf), ..Default::default() },
        vec![cmd_fn!("geo", NGX_STREAM_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE12, ConfLevel::Main, geo_block)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_ranges() -> GeoConfCtx {
        let mut ctx = GeoConfCtx::new();
        ctx.high_low = Some(vec![None; 0x10000]);
        ctx
    }

    fn ranges(ctx: &GeoConfCtx, h: usize) -> Vec<(u16, u16, Vec<u8>)> {
        ctx.high_low.as_ref().unwrap()[h].as_ref().map(|a| a.iter().map(|r| (r.start, r.end, ctx.values[r.value].data.clone())).collect()).unwrap_or_default()
    }

    #[test]
    fn values_shared() {
        let mut ctx = GeoConfCtx::new();
        let a = geo_value(&mut ctx, b"a");
        let b = geo_value(&mut ctx, b"b");
        assert_ne!(a, b);
        assert_eq!(geo_value(&mut ctx, b"a"), a);
        assert_eq!(ctx.values.len(), 3);
        assert_eq!(ctx.data_size, HEADER_SIZE + VV_SIZE + 0x10000 * PTR + 2 * align(VV_SIZE + 1, PTR));
    }

    #[test]
    fn delete_range() {
        let mut ctx = ctx_with_ranges();
        let v = geo_value(&mut ctx, b"x");
        let a = ctx.high_low.as_mut().unwrap();
        a[0x7f00] = Some(vec![GeoRange { value: v, start: 0, end: 0xffff }]);
        a[0x7f01] = Some(vec![GeoRange { value: v, start: 0, end: 0 }]);

        // 127.0.0.0-127.1.0.0
        assert!(!geo_delete_range(&mut ctx, 0x7f000000, 0x7f010000));
        assert!(ranges(&ctx, 0x7f00).is_empty());
        assert!(ranges(&ctx, 0x7f01).is_empty());

        assert!(geo_delete_range(&mut ctx, 0x7f000000, 0x7f000000));
    }

    #[test]
    fn header() {
        let h = geo_header();
        assert_eq!(&h[..6], b"GEORNG");
        assert_eq!(h[7] as usize, PTR);
    }
}
