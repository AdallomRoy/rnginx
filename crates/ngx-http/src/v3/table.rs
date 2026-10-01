//! ngx_http_v3_table.c: the QPACK static table and the dynamic table the
//! client's encoder stream fills.

use std::rc::Rc;

use ngx_core::connection::{Connection, PoolCleanup};
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use super::module::srv_conf_of;
use super::uni::send_inc_insert_count;
use super::*;

/// ngx_http_v3_field_t
#[derive(Clone, Debug)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// ngx_http_v3_dynamic_table_t (send_insert_count is in the session)
#[derive(Default)]
pub struct DynamicTable {
    pub elts: Vec<Field>,
    pub base: u64,
    pub size: usize,
    pub capacity: usize,
    pub insert_count: u64,
    pub ack_insert_count: u64,
    /// the insert buffer: its capacity and how much of it is used (the
    /// literals of an encoder instruction are decoded into it)
    pub insert_buffer: Option<(usize, usize)>,
}

/// ngx_http_v3_table_entry_size
fn entry_size(name: &[u8], value: &[u8]) -> usize {
    name.len() + value.len() + 32
}

macro_rules! f {
    ($n:expr, $v:expr) => {
        ($n as &[u8], $v as &[u8])
    };
}

/// ngx_http_v3_static_table
static STATIC_TABLE: [(&[u8], &[u8]); 99] = [
    f!(b":authority", b""),
    f!(b":path", b"/"),
    f!(b"age", b"0"),
    f!(b"content-disposition", b""),
    f!(b"content-length", b"0"),
    f!(b"cookie", b""),
    f!(b"date", b""),
    f!(b"etag", b""),
    f!(b"if-modified-since", b""),
    f!(b"if-none-match", b""),
    f!(b"last-modified", b""),
    f!(b"link", b""),
    f!(b"location", b""),
    f!(b"referer", b""),
    f!(b"set-cookie", b""),
    f!(b":method", b"CONNECT"),
    f!(b":method", b"DELETE"),
    f!(b":method", b"GET"),
    f!(b":method", b"HEAD"),
    f!(b":method", b"OPTIONS"),
    f!(b":method", b"POST"),
    f!(b":method", b"PUT"),
    f!(b":scheme", b"http"),
    f!(b":scheme", b"https"),
    f!(b":status", b"103"),
    f!(b":status", b"200"),
    f!(b":status", b"304"),
    f!(b":status", b"404"),
    f!(b":status", b"503"),
    f!(b"accept", b"*/*"),
    f!(b"accept", b"application/dns-message"),
    f!(b"accept-encoding", b"gzip, deflate, br"),
    f!(b"accept-ranges", b"bytes"),
    f!(b"access-control-allow-headers", b"cache-control"),
    f!(b"access-control-allow-headers", b"content-type"),
    f!(b"access-control-allow-origin", b"*"),
    f!(b"cache-control", b"max-age=0"),
    f!(b"cache-control", b"max-age=2592000"),
    f!(b"cache-control", b"max-age=604800"),
    f!(b"cache-control", b"no-cache"),
    f!(b"cache-control", b"no-store"),
    f!(b"cache-control", b"public, max-age=31536000"),
    f!(b"content-encoding", b"br"),
    f!(b"content-encoding", b"gzip"),
    f!(b"content-type", b"application/dns-message"),
    f!(b"content-type", b"application/javascript"),
    f!(b"content-type", b"application/json"),
    f!(b"content-type", b"application/x-www-form-urlencoded"),
    f!(b"content-type", b"image/gif"),
    f!(b"content-type", b"image/jpeg"),
    f!(b"content-type", b"image/png"),
    f!(b"content-type", b"text/css"),
    f!(b"content-type", b"text/html;charset=utf-8"),
    f!(b"content-type", b"text/plain"),
    f!(b"content-type", b"text/plain;charset=utf-8"),
    f!(b"range", b"bytes=0-"),
    f!(b"strict-transport-security", b"max-age=31536000"),
    f!(b"strict-transport-security", b"max-age=31536000;includesubdomains"),
    f!(b"strict-transport-security", b"max-age=31536000;includesubdomains;preload"),
    f!(b"vary", b"accept-encoding"),
    f!(b"vary", b"origin"),
    f!(b"x-content-type-options", b"nosniff"),
    f!(b"x-xss-protection", b"1;mode=block"),
    f!(b":status", b"100"),
    f!(b":status", b"204"),
    f!(b":status", b"206"),
    f!(b":status", b"302"),
    f!(b":status", b"400"),
    f!(b":status", b"403"),
    f!(b":status", b"421"),
    f!(b":status", b"425"),
    f!(b":status", b"500"),
    f!(b"accept-language", b""),
    f!(b"access-control-allow-credentials", b"FALSE"),
    f!(b"access-control-allow-credentials", b"TRUE"),
    f!(b"access-control-allow-headers", b"*"),
    f!(b"access-control-allow-methods", b"get"),
    f!(b"access-control-allow-methods", b"get, post, options"),
    f!(b"access-control-allow-methods", b"options"),
    f!(b"access-control-expose-headers", b"content-length"),
    f!(b"access-control-request-headers", b"content-type"),
    f!(b"access-control-request-method", b"get"),
    f!(b"access-control-request-method", b"post"),
    f!(b"alt-svc", b"clear"),
    f!(b"authorization", b""),
    f!(b"content-security-policy", b"script-src 'none';object-src 'none';base-uri 'none'"),
    f!(b"early-data", b"1"),
    f!(b"expect-ct", b""),
    f!(b"forwarded", b""),
    f!(b"if-range", b""),
    f!(b"origin", b""),
    f!(b"purpose", b"prefetch"),
    f!(b"server", b""),
    f!(b"timing-allow-origin", b"*"),
    f!(b"upgrade-insecure-requests", b"1"),
    f!(b"user-agent", b""),
    f!(b"x-forwarded-for", b""),
    f!(b"x-frame-options", b"deny"),
    f!(b"x-frame-options", b"sameorigin"),
];

/// ngx_http_v3_get_insert_buffer: the insert buffer emptied; its capacity
pub fn get_insert_buffer(c: &Rc<Connection>) -> Option<usize> {
    let h3c = get_session(c)?;
    let mut dt = h3c.table.borrow_mut();

    if dt.insert_buffer.is_none() {
        let h3scf = srv_conf_of(&h3c.http_connection);

        dt.insert_buffer = Some((h3scf.max_table_capacity, 0));
    }

    if let Some(ib) = dt.insert_buffer.as_mut() {
        ib.1 = 0;
    }

    dt.insert_buffer.map(|ib| ib.0)
}

/// Take n bytes of the insert buffer (a literal decoded into it); false
/// if they do not fit.
pub fn insert_buffer_alloc(c: &Rc<Connection>, n: usize) -> bool {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return false,
    };

    let mut dt = h3c.table.borrow_mut();

    match dt.insert_buffer.as_mut() {
        Some((cap, used)) => {
            if *cap - *used < n {
                return false;
            }

            *used += n;
            true
        }
        None => false,
    }
}

/// ngx_http_v3_ref_insert
pub fn ref_insert(c: &Rc<Connection>, dynamic: bool, index: u64, value: &[u8]) -> i64 {
    let name;

    if dynamic {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 ref insert dynamic[{}] \"{}\"", index, B(value));

        let h3c = match get_session(c) {
            Some(h3c) => h3c,
            None => return NGX_ERROR,
        };

        let (base, nelts) = {
            let dt = h3c.table.borrow();
            (dt.base, dt.elts.len() as u64)
        };

        if base + nelts <= index {
            return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR as i64;
        }

        let index = base + nelts - 1 - index;

        match lookup(c, index) {
            Some(f) => name = f.name,
            None => return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR as i64,
        }
    } else {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 ref insert static[{}] \"{}\"", index, B(value));

        match lookup_static(c, index) {
            Some(f) => name = f.name,
            None => return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR as i64,
        }
    }

    insert(c, &name, value)
}

/// ngx_http_v3_insert
pub fn insert(c: &Rc<Connection>, name: &[u8], value: &[u8]) -> i64 {
    let size = entry_size(name, value);

    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    {
        let mut dt = h3c.table.borrow_mut();

        if size > dt.capacity {
            ngx_log_error!(NGX_LOG_ERR, c.log, None, "not enough dynamic table capacity");
            return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR as i64;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 insert [{}] \"{}\":\"{}\", size:{}", dt.base + dt.elts.len() as u64, B(name), B(value), size);

        dt.elts.push(Field { name: name.to_vec(), value: value.to_vec() });
        dt.size += size;

        dt.insert_count += 1;
    }

    let capacity = h3c.table.borrow().capacity;

    if evict(c, capacity) != NGX_OK {
        return NGX_ERROR;
    }

    h3c.send_insert_count.post();

    if new_entry(c) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_http_v3_inc_insert_count_handler
pub fn inc_insert_count_handler(c: &Rc<Connection>) {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 inc insert count handler");

    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return,
    };

    let (insert_count, ack_insert_count) = {
        let dt = h3c.table.borrow();
        (dt.insert_count, dt.ack_insert_count)
    };

    if insert_count > ack_insert_count {
        if send_inc_insert_count(c, insert_count - ack_insert_count) != NGX_OK {
            return;
        }

        h3c.table.borrow_mut().ack_insert_count = insert_count;
    }
}

/// ngx_http_v3_set_capacity
pub fn set_capacity(c: &Rc<Connection>, capacity: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 set capacity {}", capacity);

    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    let h3scf = srv_conf_of(&h3c.http_connection);

    if capacity > h3scf.max_table_capacity as u64 {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client exceeded http3_max_table_capacity limit");
        return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR as i64;
    }

    if evict(c, capacity as usize) != NGX_OK {
        return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR as i64;
    }

    h3c.table.borrow_mut().capacity = capacity as usize;

    NGX_OK
}

/// ngx_http_v3_cleanup_table
pub fn cleanup_table(h3c: &H3Session) {
    let mut dt = h3c.table.borrow_mut();

    dt.elts.clear();
}

/// ngx_http_v3_evict
fn evict(c: &Rc<Connection>, target: usize) -> i64 {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    let mut dt = h3c.table.borrow_mut();

    let mut n = 0;

    while dt.size > target {
        let field = dt.elts[n].clone();
        n += 1;

        let size = entry_size(&field.name, &field.value);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 evict [{}] \"{}\":\"{}\" size:{}", dt.base, B(&field.name), B(&field.value), size);

        dt.size -= size;
    }

    if n != 0 {
        dt.elts.drain(..n);
        dt.base += n as u64;
    }

    NGX_OK
}

/// ngx_http_v3_duplicate
pub fn duplicate(c: &Rc<Connection>, index: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 duplicate {}", index);

    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    let (base, nelts) = {
        let dt = h3c.table.borrow();
        (dt.base, dt.elts.len() as u64)
    };

    if base + nelts <= index {
        return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR as i64;
    }

    let index = base + nelts - 1 - index;

    let f = match lookup(c, index) {
        Some(f) => f,
        None => return NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR as i64,
    };

    insert(c, &f.name, &f.value)
}

/// ngx_http_v3_ack_section
pub fn ack_section(c: &Connection, stream_id: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 ack section {}", stream_id);

    /* we do not use dynamic tables */

    NGX_HTTP_V3_ERR_DECODER_STREAM_ERROR as i64
}

/// ngx_http_v3_inc_insert_count
pub fn inc_insert_count(c: &Connection, inc: u64) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 increment insert count {}", inc);

    /* we do not use dynamic tables */

    NGX_HTTP_V3_ERR_DECODER_STREAM_ERROR as i64
}

/// ngx_http_v3_lookup_static
pub fn lookup_static(c: &Connection, index: u64) -> Option<Field> {
    let nelts = STATIC_TABLE.len() as u64;

    if index >= nelts {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 static[{}] lookup out of bounds: {}", index, nelts);
        return None;
    }

    let (name, value) = STATIC_TABLE[index as usize];

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 static[{}] lookup \"{}\":\"{}\"", index, B(name), B(value));

    Some(Field { name: name.to_vec(), value: value.to_vec() })
}

/// ngx_http_v3_lookup
pub fn lookup(c: &Rc<Connection>, index: u64) -> Option<Field> {
    let h3c = get_session(c)?;
    let dt = h3c.table.borrow();

    if index < dt.base || index - dt.base >= dt.elts.len() as u64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 dynamic[{}] lookup out of bounds: [{},{}]", index, dt.base, dt.base + dt.elts.len() as u64);
        return None;
    }

    let field = dt.elts[(index - dt.base) as usize].clone();

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 dynamic[{}] lookup \"{}\":\"{}\"", index, B(&field.name), B(&field.value));

    Some(field)
}

/// ngx_http_v3_decode_insert_count
pub fn decode_insert_count(c: &Rc<Connection>, insert_count: &mut u64) -> i64 {
    /* QPACK 4.5.1.1. Required Insert Count */

    if *insert_count == 0 {
        return NGX_OK;
    }

    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    let h3scf = srv_conf_of(&h3c.http_connection);

    let max_entries = h3scf.max_table_capacity as u64 / 32;
    let full_range = 2 * max_entries;

    if *insert_count > full_range {
        return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED as i64;
    }

    let (base, nelts) = {
        let dt = h3c.table.borrow();
        (dt.base, dt.elts.len() as u64)
    };

    let max_value = base + nelts + max_entries;
    let max_wrapped = (max_value / full_range) * full_range;
    let mut req_insert_count = max_wrapped + *insert_count - 1;

    if req_insert_count > max_value {
        if req_insert_count <= full_range {
            return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED as i64;
        }

        req_insert_count -= full_range;
    }

    if req_insert_count == 0 {
        return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED as i64;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 decode insert_count {} -> {}", *insert_count, req_insert_count);

    *insert_count = req_insert_count;

    NGX_OK
}

/// ngx_http_v3_check_insert_count
pub fn check_insert_count(c: &Rc<Connection>, insert_count: u64) -> i64 {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    let n = {
        let dt = h3c.table.borrow();
        dt.base + dt.elts.len() as u64
    };

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 check insert count req:{}, have:{}", insert_count, n);

    if n >= insert_count {
        return NGX_OK;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 block stream");

    // the ngx_http_v3_block_t of the stream: its pool cleanup
    let registered = c.cleanups.borrow().iter().any(|cln| cln.tag == "ngx_http_v3_unblock");

    if !registered {
        let number = c.number;
        let wh3c = Rc::downgrade(&h3c);

        c.add_cleanup(PoolCleanup {
            tag: "ngx_http_v3_unblock",
            data: None,
            handler: Some(Box::new(move || {
                if let Some(h3c) = wh3c.upgrade() {
                    unblock(&h3c, number);
                }
            })),
        });
    }

    let queued = h3c.blocked.borrow().iter().any(|w| w.upgrade().is_some_and(|bc| bc.number == c.number));

    if !queued {
        let h3scf = srv_conf_of(&h3c.http_connection);

        if h3c.nblocked.get() == h3scf.max_blocked_streams as u64 {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client exceeded http3_max_blocked_streams limit");

            finalize_connection(c, NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED, Some("too many blocked streams"));
            return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED as i64;
        }

        h3c.nblocked.set(h3c.nblocked.get() + 1);
        h3c.blocked.borrow_mut().push(Rc::downgrade(c));
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 blocked:{}", h3c.nblocked.get());

    NGX_BUSY
}

/// ngx_http_v3_ack_insert_count
pub fn ack_insert_count(c: &Rc<Connection>, insert_count: u64) {
    if let Some(h3c) = get_session(c) {
        let mut dt = h3c.table.borrow_mut();

        if dt.ack_insert_count < insert_count {
            dt.ack_insert_count = insert_count;
        }
    }
}

/// ngx_http_v3_unblock
fn unblock(h3c: &H3Session, number: u64) {
    let mut blocked = h3c.blocked.borrow_mut();

    let before = blocked.len();

    blocked.retain(|w| !w.upgrade().is_some_and(|bc| bc.number == number) && w.strong_count() > 0);

    let removed = before - blocked.len();

    h3c.nblocked.set(h3c.nblocked.get() - removed as u64);
}

/// ngx_http_v3_new_entry
fn new_entry(c: &Rc<Connection>) -> i64 {
    let h3c = match get_session(c) {
        Some(h3c) => h3c,
        None => return NGX_ERROR,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 new dynamic entry, blocked:{}", h3c.nblocked.get());

    loop {
        let bc = {
            let blocked = h3c.blocked.borrow();

            match blocked.first() {
                Some(w) => w.upgrade(),
                None => break,
            }
        };

        let bc = match bc {
            Some(bc) => bc,
            None => {
                h3c.blocked.borrow_mut().remove(0);
                h3c.nblocked.set(h3c.nblocked.get() - 1);
                continue;
            }
        };

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, bc.log, "http3 unblock stream");

        unblock(&h3c, bc.number);

        if let Some(qs) = ngx_core::quic::streams::ngx_quic_stream(&bc) {
            qs.read.post();
        }
    }

    NGX_OK
}

/// ngx_http_v3_set_param
pub fn set_param(c: &Connection, id: u64, value: u64) -> i64 {
    match id {
        NGX_HTTP_V3_PARAM_MAX_TABLE_CAPACITY => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 param QPACK_MAX_TABLE_CAPACITY:{}", value);
        }

        NGX_HTTP_V3_PARAM_MAX_FIELD_SECTION_SIZE => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 param SETTINGS_MAX_FIELD_SECTION_SIZE:{}", value);
        }

        NGX_HTTP_V3_PARAM_BLOCKED_STREAMS => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 param QPACK_BLOCKED_STREAMS:{}", value);
        }

        _ => {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 param #{}:{}", id, value);
        }
    }

    NGX_OK
}
