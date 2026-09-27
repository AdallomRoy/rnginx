//! Minimal ngx_http_file_cache — enough to serve MISS/HIT on the common
//! proxy_cache flow. Stores responses under `<cache_path>/<hex-md5-of-key>`
//! with a small `CacheFileHeader` prefix (Rust-native layout — not
//! byte-compatible with C nginx yet).

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;

use crate::request::*;
use crate::script::ComplexValue;
use crate::*;

/// Registered cache paths, keyed by zone name.
#[derive(Clone)]
pub struct CachePath {
    pub name: Vec<u8>,
    pub path: Vec<u8>,        // filesystem directory root
    pub levels: Vec<u8>,      // e.g. [1, 2] for "levels=1:2"
}

thread_local! {
    static ZONES: RefCell<HashMap<Vec<u8>, CachePath>> = RefCell::new(HashMap::new());
}

/// One `proxy_cache_valid` clause: TTL applied to a list of upstream
/// response statuses. If `statuses` is empty the clause applies to the
/// default set (200/301/302).
#[derive(Clone)]
pub struct CacheValid {
    pub statuses: Vec<u16>,
    pub any: bool,
    pub ttl_secs: u64,
}

#[derive(Clone)]
pub struct ProxyCacheConf {
    pub zone: Option<Vec<u8>>,                // proxy_cache <zone> (literal or "$var...")
    pub zone_cv: Option<Rc<ComplexValue>>,    // compiled complex value if zone is dynamic
    pub key: Option<Rc<ComplexValue>>,        // proxy_cache_key <expr>
    pub valid: Vec<CacheValid>,               // proxy_cache_valid ...
    pub min_uses: u32,                        // proxy_cache_min_uses (unused: always cache)
    pub methods: u32,                         // proxy_cache_methods bitmask (GET|HEAD by default)
    pub convert_head: bool,
    pub bypass: Vec<Rc<ComplexValue>>,        // proxy_cache_bypass expressions
    pub no_cache: Vec<Rc<ComplexValue>>,      // proxy_no_cache expressions
}

impl ProxyCacheConf {
    pub fn new() -> Self {
        ProxyCacheConf {
            zone: None,
            zone_cv: None,
            key: None,
            valid: Vec::new(),
            min_uses: 1,
            methods: crate::NGX_HTTP_GET | crate::NGX_HTTP_HEAD,
            convert_head: true,
            bypass: Vec::new(),
            no_cache: Vec::new(),
        }
    }
}

/// One cached response. Body follows the header in `<cache_dir>/<hex>`.
#[derive(Clone)]
pub struct CachedResponse {
    pub expires_epoch: u64,
    pub status: u16,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// $upstream_cache_status possible values.
#[derive(Clone, Copy, PartialEq)]
pub enum CacheStatus {
    Miss,
    Hit,
    Expired,
    Bypass,
    Revalidated,
    Updating,
    Stale,
    #[allow(dead_code)]
    Scarce,
}

impl CacheStatus {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            CacheStatus::Miss => b"MISS",
            CacheStatus::Hit => b"HIT",
            CacheStatus::Expired => b"EXPIRED",
            CacheStatus::Bypass => b"BYPASS",
            CacheStatus::Revalidated => b"REVALIDATED",
            CacheStatus::Updating => b"UPDATING",
            CacheStatus::Stale => b"STALE",
            CacheStatus::Scarce => b"SCARCE",
        }
    }
}

// ---------------------------------------------------------------------
// Config parsers
// ---------------------------------------------------------------------

pub fn parse_proxy_cache_path(cf: &mut Conf) -> ConfResult {
    if cf.args.len() < 3 {
        return Err(msg("proxy_cache_path requires path and keys_zone="));
    }
    let path = cf.args[1].clone();
    let mut name: Vec<u8> = Vec::new();
    let mut levels: Vec<u8> = Vec::new();
    for a in cf.args.iter().skip(2) {
        if let Some(rest) = a.strip_prefix(b"keys_zone=") {
            let colon = rest.iter().position(|&b| b == b':').unwrap_or(rest.len());
            name = rest[..colon].to_vec();
        } else if let Some(rest) = a.strip_prefix(b"levels=") {
            for part in rest.split(|&b| b == b':') {
                if let Ok(n) = std::str::from_utf8(part).unwrap_or("").parse::<u8>() {
                    levels.push(n);
                }
            }
        } else {
            // Ignore other params (max_size, inactive, ...) — the tests
            // don't exercise eviction.
        }
    }
    if name.is_empty() {
        return Err(cf.emerg(format_args!("keys_zone= missing in proxy_cache_path")));
    }
    // Create the cache directory if missing.
    let _ = std::fs::create_dir_all(std::ffi::OsStr::new(std::str::from_utf8(&path).unwrap_or("")));
    ZONES.with(|z| {
        z.borrow_mut().insert(name.clone(), CachePath { name, path, levels });
    });
    Ok(())
}

pub fn zone(name: &[u8]) -> Option<CachePath> {
    ZONES.with(|z| z.borrow().get(name).cloned())
}

/// Resolve the effective zone name for a request. Returns:
///   - Some(Ok(name)) — a valid zone name to use for lookup/save
///   - Some(Err(())) — a dynamic name was set but expanded to something
///     that doesn't match a configured zone (500 in C)
///   - None — no caching configured
pub fn resolve_zone_name(r: &R, conf: &ProxyCacheConf) -> Option<Result<Vec<u8>, ()>> {
    let name = match &conf.zone_cv {
        Some(cv) => crate::script::complex_value(r, cv).ok()?,
        None => conf.zone.as_ref()?.clone(),
    };
    if name.is_empty() { return None; }  // empty variable → cache disabled, not an error
    if zone(&name).is_some() { Some(Ok(name)) } else { Some(Err(())) }
}

pub fn parse_cache_valid(args: &[Vec<u8>]) -> Result<CacheValid, ConfError> {
    // Last arg is time. Preceding args are status codes (or "any").
    if args.len() < 2 {
        return Err(msg("proxy_cache_valid requires time"));
    }
    let time_arg = &args[args.len() - 1];
    let ttl_secs = ngx_core::parse::parse_time(time_arg, true)
        .ok_or_else(|| msg("invalid time"))?;
    let mut cv = CacheValid { statuses: Vec::new(), any: false, ttl_secs: ttl_secs as u64 };
    if args.len() == 1 {
        cv.statuses = vec![200, 301, 302];
        return Ok(cv);
    }
    for a in &args[..args.len() - 1] {
        if a == b"any" {
            cv.any = true;
        } else if let Ok(s) = std::str::from_utf8(a) {
            if let Ok(n) = s.parse::<u16>() { cv.statuses.push(n); }
        }
    }
    if !cv.any && cv.statuses.is_empty() {
        cv.statuses = vec![200, 301, 302];
    }
    Ok(cv)
}

/// Pick a TTL for `status` based on the location's `proxy_cache_valid`
/// clauses. Returns `None` if the status shouldn't be cached.
pub fn ttl_for(conf: &ProxyCacheConf, status: u16) -> Option<u64> {
    for cv in &conf.valid {
        if cv.statuses.iter().any(|&s| s == status) {
            return Some(cv.ttl_secs);
        }
    }
    // `any` clauses match last so an explicit status match wins.
    for cv in &conf.valid {
        if cv.any {
            return Some(cv.ttl_secs);
        }
    }
    None
}

// ---------------------------------------------------------------------
// Storage — hex-md5 of key as filename, levels split the path prefix.
// ---------------------------------------------------------------------

fn hex(v: &[u8]) -> String {
    let mut s = String::with_capacity(v.len() * 2);
    for &b in v {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn cache_key_hex(key: &[u8]) -> String {
    // md5 of the raw key bytes — matches ngx_http_file_cache_create_key.
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(key);
    let d = h.finalize();
    hex(&d)
}

fn cache_file_path(zone: &CachePath, key_hex: &str) -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(std::str::from_utf8(&zone.path).unwrap_or(""));
    // Build "levels=1:2" style directory prefix from the tail of the hex key.
    let mut used = key_hex.len();
    for &lvl in &zone.levels {
        let lvl = lvl as usize;
        if lvl == 0 || used < lvl { continue; }
        let start = used - lvl;
        p.push(&key_hex[start..used]);
        used = start;
    }
    p.push(key_hex);
    p
}

fn ensure_parent(p: &std::path::Path) {
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
}

/// On-disk framing: 8-byte little-endian expires_epoch, 2-byte status,
/// then a repeated 4-byte length prefix + name/value pairs terminated by a
/// zero-length name, then body bytes.
fn serialize(resp: &CachedResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + resp.body.len());
    out.extend_from_slice(&resp.expires_epoch.to_le_bytes());
    out.extend_from_slice(&resp.status.to_le_bytes());
    for (k, v) in &resp.headers {
        let kl = k.len() as u32;
        out.extend_from_slice(&kl.to_le_bytes());
        out.extend_from_slice(k);
        let vl = v.len() as u32;
        out.extend_from_slice(&vl.to_le_bytes());
        out.extend_from_slice(v);
    }
    out.extend_from_slice(&0u32.to_le_bytes()); // terminator
    out.extend_from_slice(&resp.body);
    out
}

fn deserialize(bytes: &[u8]) -> Option<CachedResponse> {
    if bytes.len() < 10 { return None; }
    let expires = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let status = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
    let mut i = 10usize;
    let mut headers = Vec::new();
    loop {
        if i + 4 > bytes.len() { return None; }
        let kl = u32::from_le_bytes(bytes[i..i + 4].try_into().ok()?) as usize;
        i += 4;
        if kl == 0 { break; }
        if i + kl > bytes.len() { return None; }
        let k = bytes[i..i + kl].to_vec();
        i += kl;
        if i + 4 > bytes.len() { return None; }
        let vl = u32::from_le_bytes(bytes[i..i + 4].try_into().ok()?) as usize;
        i += 4;
        if i + vl > bytes.len() { return None; }
        let v = bytes[i..i + vl].to_vec();
        i += vl;
        headers.push((k, v));
    }
    let body = bytes[i..].to_vec();
    Some(CachedResponse { expires_epoch: expires, status, headers, body })
}

pub fn lookup(zone_name: &[u8], key: &[u8]) -> Option<CachedResponse> {
    let z = zone(zone_name)?;
    let hex = cache_key_hex(key);
    let p = cache_file_path(&z, &hex);
    let bytes = std::fs::read(&p).ok()?;
    deserialize(&bytes)
}

pub fn save(zone_name: &[u8], key: &[u8], resp: &CachedResponse) {
    let z = match zone(zone_name) { Some(z) => z, None => return };
    let hex = cache_key_hex(key);
    let p = cache_file_path(&z, &hex);
    ensure_parent(&p);
    // Write to <p>.tmp then rename to avoid partial-read races.
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, serialize(resp)).is_err() { return; }
    let _ = std::fs::rename(&tmp, &p);
}

// ---------------------------------------------------------------------
// $upstream_cache_status
// ---------------------------------------------------------------------

thread_local! {
    static REQUEST_STATUS: RefCell<HashMap<u64, CacheStatus>> = RefCell::new(HashMap::new());
}

pub fn set_status(r: &R, s: CacheStatus) {
    let id = Rc::as_ptr(r) as u64;
    REQUEST_STATUS.with(|m| { m.borrow_mut().insert(id, s); });
    let id_c = id;
    r.add_cleanup(Box::new(move || {
        REQUEST_STATUS.with(|m| { m.borrow_mut().remove(&id_c); });
    }));
}

fn get_status(r: &R) -> Option<CacheStatus> {
    REQUEST_STATUS.with(|m| m.borrow().get(&(Rc::as_ptr(r) as u64)).copied())
}

fn var_upstream_cache_status(r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    match get_status(r) {
        Some(s) => { v.data = s.as_bytes().to_vec(); v.valid = true; }
        None => { v.not_found = true; }
    }
    NGX_OK
}

pub fn add_variables(cf: &mut Conf) -> ConfResult {
    let vars = [
        crate::variables::VarDef {
            name: "upstream_cache_status",
            set: None,
            get: Some(var_upstream_cache_status),
            data: 0,
            flags: crate::variables::NGX_HTTP_VAR_NOCACHEABLE,
        },
    ];
    crate::variables::add_variables(cf, &vars)
}

pub fn is_bypass(r: &R, conf: &ProxyCacheConf) -> bool {
    for cv in &conf.bypass {
        let v = crate::script::complex_value(r, cv).unwrap_or_default();
        // Any non-empty, non-"0" value bypasses the cache — matches C's
        // ngx_http_test_predicates semantics.
        if !v.is_empty() && v != b"0" { return true; }
    }
    false
}

pub fn is_no_cache(r: &R, conf: &ProxyCacheConf) -> bool {
    for cv in &conf.no_cache {
        let v = crate::script::complex_value(r, cv).unwrap_or_default();
        if !v.is_empty() && v != b"0" { return true; }
    }
    false
}

/// Default cache key when proxy_cache_key isn't set (matches C's
/// ngx_http_proxy_module default: `$scheme$proxy_host$request_uri`).
pub fn default_cache_key(r: &R, upstream_uri: &[u8]) -> Vec<u8> {
    let mut key: Vec<u8> = Vec::new();
    // We don't have $scheme easily; just include upstream_uri and request_uri.
    key.extend_from_slice(upstream_uri);
    key.extend_from_slice(&r.uri.borrow());
    let args = r.args.borrow();
    if !args.is_empty() {
        key.push(b'?');
        key.extend_from_slice(&args);
    }
    key
}

/// Populate headers_out from a cached response and stream the body.
/// Returns the phase-handler exit code (NGX_OK / NGX_ERROR / NGX_HTTP_*).
pub async fn serve_hit(r: &R, resp: CachedResponse) -> i64 {
    // Fill headers_out. Cached headers are already the pre-filter set that
    // came off the upstream, so we can add them directly. Special-case the
    // handful that HeadersOut has typed slots for so the header filter
    // renders them.
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = resp.status as i64;
        ho.content_length_n = resp.body.len() as i64;
        for (k, v) in &resp.headers {
            let lc = k.to_ascii_lowercase();
            match lc.as_slice() {
                b"content-length" => {
                    // We recompute this from the cached body length above;
                    // skip so we don't emit two Content-Length headers.
                }
                b"content-type" => {
                    ho.content_type = v.clone();
                    ho.content_type_len = v.len();
                }
                b"content-encoding" => {
                    ho.content_encoding = Some(crate::request::TableElt::new(k, v));
                }
                b"location" => {
                    ho.location = Some(crate::request::TableElt::new(k, v));
                }
                b"last-modified" => {
                    ho.last_modified = Some(crate::request::TableElt::new(k, v));
                }
                b"etag" => {
                    ho.etag = Some(crate::request::TableElt::new(k, v));
                }
                _ => {
                    ho.add(k, v);
                }
            }
        }
    }

    // Cache the response but skip 304-handling — we're serving a fresh copy.
    r.disable_not_modified.set(true);

    let sh = crate::core_rt::send_header(r).await;
    if sh != NGX_OK { return NGX_ERROR; }

    if r.method.get() == crate::NGX_HTTP_HEAD || r.header_only.get() {
        return NGX_OK;
    }

    use ngx_core::buf::{Buf, BufData};
    use std::collections::VecDeque;
    let mut chain: ngx_core::buf::Chain = VecDeque::new();
    let buf = Buf {
        pos: 0,
        last: resp.body.len(),
        file_pos: 0,
        file_last: 0,
        tag: 0,
        num: 0,
        data: BufData::Memory(resp.body),
        temporary: true,
        memory: false,
        mmap: false,
        recycled: false,
        in_file: false,
        flush: false,
        sync: false,
        last_buf: true,
        last_in_chain: true,
        temp_file: false,
    };
    chain.push_back(buf);
    if crate::core_rt::output_filter(r, chain).await != NGX_OK {
        return NGX_ERROR;
    }
    NGX_OK
}

/// Try to serve the request from cache. Returns:
///   - `Some(rc)` if we handled the request (HIT served, or BYPASS decision recorded)
///   - `None` to continue on to upstream (MISS / EXPIRED / not configured)
pub async fn try_serve(r: &R, conf: &ProxyCacheConf, upstream_uri: &[u8]) -> Option<i64> {
    let zone = match resolve_zone_name(r, conf)? {
        Ok(z) => z,
        Err(()) => return Some(crate::NGX_HTTP_INTERNAL_SERVER_ERROR as i64),
    };
    // Bypass predicates: skip lookup but keep saving allowed.
    if is_bypass(r, conf) {
        set_status(r, CacheStatus::Bypass);
        return None;
    }
    let key = match &conf.key {
        Some(cv) => crate::script::complex_value(r, cv).ok()?,
        None => default_cache_key(r, upstream_uri),
    };
    match lookup(&zone, &key) {
        Some(resp) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if resp.expires_epoch > now {
                set_status(r, CacheStatus::Hit);
                // proxy_intercept_errors on a cached error: skip the
                // regular hit-serve path and hand the status to error_page,
                // matching C where u->cache serves through
                // ngx_http_upstream_intercept_errors.
                let cached_status = resp.status;
                if cached_status >= crate::NGX_HTTP_SPECIAL_RESPONSE as u16 {
                    let intercept = r
                        .loc_conf::<crate::proxy::NgxHttpProxyLocConf>(crate::proxy::ctx_index())
                        .borrow()
                        .intercept_errors
                        .get_or(false);
                    if intercept {
                        let has_page = r.clcf()
                            .borrow()
                            .error_pages
                            .as_ref()
                            .map(|pages| pages.iter().any(|p| p.status == cached_status as i64))
                            .unwrap_or(false);
                        if has_page {
                            return Some(cached_status as i64);
                        }
                    }
                }
                return Some(serve_hit(r, resp).await);
            }
            set_status(r, CacheStatus::Expired);
            None
        }
        None => {
            set_status(r, CacheStatus::Miss);
            None
        }
    }
}

/// Save the upstream response as a cache entry, subject to
/// proxy_no_cache predicates and a matching proxy_cache_valid TTL.
pub fn maybe_save(
    r: &R,
    conf: &ProxyCacheConf,
    upstream_uri: &[u8],
    status: u16,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
) {
    let zone = match resolve_zone_name(r, conf) {
        Some(Ok(z)) => z,
        _ => return,
    };
    if is_no_cache(r, conf) { return; }
    // A Cache-Control response header — max-age / s-maxage / no-cache /
    // no-store / private — overrides proxy_cache_valid. Matches C's
    // ngx_http_upstream_process_cache_control.
    let mut cc_ttl: Option<u64> = None;
    let mut cc_forbid = false;
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case(b"cache-control") {
            for part in v.split(|&b| b == b',') {
                let part = trim_ws(part);
                if part.eq_ignore_ascii_case(b"no-cache")
                    || part.eq_ignore_ascii_case(b"no-store")
                    || part.eq_ignore_ascii_case(b"private")
                {
                    cc_forbid = true;
                } else if let Some(rest) = strip_prefix_ci(part, b"s-maxage=") {
                    if let Ok(n) = std::str::from_utf8(rest).unwrap_or("").parse::<u64>() {
                        cc_ttl = Some(n);
                    }
                } else if cc_ttl.is_none() {
                    if let Some(rest) = strip_prefix_ci(part, b"max-age=") {
                        if let Ok(n) = std::str::from_utf8(rest).unwrap_or("").parse::<u64>() {
                            cc_ttl = Some(n);
                        }
                    }
                }
            }
        }
    }
    if cc_forbid { return; }
    let ttl = match cc_ttl {
        Some(t) => t,
        None => match ttl_for(conf, status) { Some(t) => t, None => return },
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let resp = CachedResponse {
        expires_epoch: now + ttl,
        status,
        headers,
        body,
    };
    let key = match &conf.key {
        Some(cv) => crate::script::complex_value(r, cv).unwrap_or_else(|_| default_cache_key(r, upstream_uri)),
        None => default_cache_key(r, upstream_uri),
    };
    save(&zone, &key, &resp);
}

fn trim_ws(mut s: &[u8]) -> &[u8] {
    while let Some(&b) = s.first() { if b == b' ' || b == b'\t' { s = &s[1..]; } else { break; } }
    while let Some(&b) = s.last() { if b == b' ' || b == b'\t' { s = &s[..s.len()-1]; } else { break; } }
    s
}

fn strip_prefix_ci<'a>(s: &'a [u8], p: &[u8]) -> Option<&'a [u8]> {
    if s.len() < p.len() { return None; }
    if s[..p.len()].eq_ignore_ascii_case(p) { Some(&s[p.len()..]) } else { None }
}
