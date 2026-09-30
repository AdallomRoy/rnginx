//! ngx_http_headers_filter_module (placeholder: directives accepted, add_header applied simply)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_headers_filter_module");

#[derive(Clone, Copy, PartialEq)]
pub enum ExpiresKind { Off, Epoch, Max, Access, Modified, DailyAt }

pub struct HeadersConf {
    pub headers: Option<Vec<(Vec<u8>, ComplexValue, bool)>>,
    pub trailers: Option<Vec<(Vec<u8>, ComplexValue, bool)>>,
    pub expires: Option<ExpiresKind>,
    /// Base offset in seconds (or seconds-since-midnight for DailyAt).
    pub expires_time: i64,
    /// If set, evaluate this complex value at request time and parse the
    /// resulting bytes as an expires spec ("epoch"/"max"/"modified 60s"/etc.).
    pub expires_value: Option<ComplexValue>,
    pub expires_set: bool,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(HeadersConf {
        headers: None,
        trailers: None,
        expires: None,
        expires_time: 0,
        expires_value: None,
        expires_set: false,
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<HeadersConf>(prev).borrow();
    let mut c = conf_cell::<HeadersConf>(conf).borrow_mut();
    if c.headers.is_none() {
        c.headers = p.headers.clone();
    }
    if c.trailers.is_none() {
        c.trailers = p.trailers.clone();
    }
    if !c.expires_set {
        c.expires_set = p.expires_set;
        c.expires = p.expires;
        c.expires_time = p.expires_time;
        c.expires_value = p.expires_value.clone();
    }
    Ok(())
}

fn set_expires(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    // If any argument contains a $var, compile as a complex value; parse
    // happens at request time (matches C's ngx_http_headers_expires when
    // ngx_http_script_variables_count(&value[i]) > 0).
    let any_var = args.iter().skip(1).any(|a| a.contains(&b'$'));
    if any_var {
        // Reconstruct the args as a single space-joined string.
        let mut src: Vec<u8> = Vec::new();
        for (i, a) in args.iter().enumerate().skip(1) {
            if i > 1 { src.push(b' '); }
            src.extend_from_slice(a);
        }
        let cv = crate::script::compile_complex_value(cf, &src, 0)?;
        let mut c = cell.borrow_mut();
        c.expires_value = Some(cv);
        c.expires = None;
        c.expires_time = 0;
        c.expires_set = true;
        return Ok(());
    }
    // Minimal parser for common forms:
    //   expires off
    //   expires epoch
    //   expires max
    //   expires <time>            (relative from access)
    //   expires modified <time>
    //   expires @HH:MM[:SS]       (daily-at)
    let (kind, time_str_opt) = if args.len() == 2 {
        let a = &args[1];
        if a == b"off" { return { cell.borrow_mut().expires = Some(ExpiresKind::Off); cell.borrow_mut().expires_set = true; Ok(()) } }
        if a == b"epoch" { return { cell.borrow_mut().expires = Some(ExpiresKind::Epoch); cell.borrow_mut().expires_set = true; Ok(()) } }
        if a == b"max" { return { cell.borrow_mut().expires = Some(ExpiresKind::Max); cell.borrow_mut().expires_set = true; Ok(()) } }
        if a.first() == Some(&b'@') {
            (ExpiresKind::DailyAt, Some(a[1..].to_vec()))
        } else {
            (ExpiresKind::Access, Some(a.clone()))
        }
    } else if args.len() == 3 && args[1] == b"modified" {
        (ExpiresKind::Modified, Some(args[2].clone()))
    } else {
        return Err(cf.emerg(format_args!("invalid expires arguments")));
    };
    let mut secs: i64 = 0;
    if let Some(s) = time_str_opt {
        if kind == ExpiresKind::DailyAt {
            // Two forms: "HH:MM[:SS]" or an ngx_parse_time-style value like
            // "15h30m33s" that expresses seconds-since-midnight.
            let s_str = std::str::from_utf8(&s).map_err(|_| cf.emerg(format_args!("invalid time")))?;
            if s_str.contains(':') {
                let parts: Vec<&str> = s_str.split(':').collect();
                if parts.len() < 2 || parts.len() > 3 {
                    return Err(cf.emerg(format_args!("invalid daily-at expires")));
                }
                let h: i64 = parts[0].parse().map_err(|_| cf.emerg(format_args!("invalid hours")))?;
                let m: i64 = parts[1].parse().map_err(|_| cf.emerg(format_args!("invalid minutes")))?;
                let sec: i64 = if parts.len() == 3 { parts[2].parse().map_err(|_| cf.emerg(format_args!("invalid seconds")))? } else { 0 };
                secs = h * 3600 + m * 60 + sec;
            } else {
                match ngx_core::parse::parse_time(&s, true) {
                    Some(v) => secs = v,
                    None => return Err(cf.emerg(format_args!("invalid daily-at expires"))),
                }
            }
            if secs < 0 || secs >= 86400 {
                return Err(cf.emerg(format_args!("invalid daily-at expires (out of range)")));
            }
        } else {
            // Signed time value like 1d, 30m, 60s, or bare seconds.
            let (sign, tail): (i64, &[u8]) = if s.first() == Some(&b'-') { (-1, &s[1..]) }
                else if s.first() == Some(&b'+') { (1, &s[1..]) } else { (1, &s[..]) };
            match ngx_core::parse::parse_time(tail, true) {
                Some(v) => secs = sign * v,
                None => return Err(cf.emerg(format_args!("invalid expires time"))),
            }
        }
    }
    let mut c = cell.borrow_mut();
    c.expires = Some(kind);
    c.expires_time = secs;
    c.expires_set = true;
    Ok(())
}

fn add_header(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let cv = compile_complex_value(cf, &args[2], 0)?;
    let mut always = false;
    if args.len() == 4 {
        if args[3] == b"always" {
            always = true;
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", ngx_core::string::B(&args[3]))));
        }
    }
    let mut c = cell.borrow_mut();
    c.headers.get_or_insert_with(Vec::new).push((args[1].clone(), cv, always));
    Ok(())
}

fn add_trailer(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let cv = compile_complex_value(cf, &args[2], 0)?;
    let always = args.len() == 4 && args[3] == b"always";
    let mut c = cell.borrow_mut();
    c.trailers.get_or_insert_with(Vec::new).push((args[1].clone(), cv, always));
    Ok(())
}

pub fn headers_filter_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF;
    let def = HttpModuleDef { postconfiguration: Some(init), create_loc_conf: Some(create_conf), merge_loc_conf: Some(merge_conf), ..Default::default() };
    let commands = vec![
        ngx_core::cmd_fn!("add_header", F | NGX_CONF_TAKE23, ConfLevel::Loc, add_header),
        ngx_core::cmd_fn!("expires", F | NGX_CONF_TAKE12, ConfLevel::Loc, set_expires),
        ngx_core::cmd_fn!("add_trailer", F | NGX_CONF_TAKE23, ConfLevel::Loc, add_trailer),
    ];
    http_module_def("ngx_http_headers_filter_module", def, commands)
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { headers_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { trailers_body_filter(r, chain, next).await });
    Ok(())
}

async fn trailers_body_filter(r: R, input: ngx_core::buf::Chain, next: BodyFilter) -> i64 {
    // Match ngx_http_trailers_filter: on last_buf, evaluate each add_trailer
    // complex value and push into r.headers_out.trailers so the chunked filter
    // can emit them in the terminator.
    if input.is_empty() || r.header_only.get() || !r.expect_trailers.get() {
        return next(r, input).await;
    }
    let has_last = input.iter().any(|b| b.last_buf);
    if !has_last {
        return next(r, input).await;
    }
    let conf = r.loc_conf::<HeadersConf>(ctx_index());
    let trailers = conf.borrow().trailers.clone();
    let ts = match trailers { Some(t) if !t.is_empty() => t, _ => return next(r, input).await };

    let status = r.headers_out.borrow().status;
    let safe_status = matches!(
        status,
        NGX_HTTP_OK | NGX_HTTP_CREATED | NGX_HTTP_NO_CONTENT | NGX_HTTP_PARTIAL_CONTENT
        | NGX_HTTP_MOVED_PERMANENTLY | NGX_HTTP_MOVED_TEMPORARILY | NGX_HTTP_SEE_OTHER
        | NGX_HTTP_NOT_MODIFIED | NGX_HTTP_TEMPORARY_REDIRECT | NGX_HTTP_PERMANENT_REDIRECT
    );

    for (name, cv, always) in ts.iter() {
        if !safe_status && !always {
            continue;
        }
        let value = match crate::script::complex_value(&r, cv) {
            Ok(v) => v,
            Err(_) => return NGX_ERROR,
        };
        if value.is_empty() {
            continue;
        }
        let h = crate::request::TableElt::new(name, &value);
        r.headers_out.borrow_mut().trailers.push(h);
    }
    next(r, input).await
}

/// Parse "epoch"/"max"/"off"/"modified <time>"/"<time>"/"@<time>" into
/// (kind, seconds). Same forms accepted at conf time; used at request time
/// when `expires` uses a complex value.
pub fn parse_expires_spec(bytes: &[u8]) -> Option<(ExpiresKind, i64)> {
    let s = bytes;
    if s.is_empty() { return None; }
    if s == b"off" { return Some((ExpiresKind::Off, 0)); }
    if s == b"epoch" { return Some((ExpiresKind::Epoch, 0)); }
    if s == b"max" { return Some((ExpiresKind::Max, 0)); }
    // "modified <time>"
    if s.starts_with(b"modified ") {
        let rest = &s[b"modified ".len()..];
        let (sign, tail): (i64, &[u8]) = if rest.first() == Some(&b'-') { (-1, &rest[1..]) }
            else if rest.first() == Some(&b'+') { (1, &rest[1..]) } else { (1, rest) };
        let v = ngx_core::parse::parse_time(tail, true)?;
        return Some((ExpiresKind::Modified, sign * v));
    }
    // "@time"
    if s.first() == Some(&b'@') {
        let rest = &s[1..];
        let secs = if rest.contains(&b':') {
            let s_str = std::str::from_utf8(rest).ok()?;
            let parts: Vec<&str> = s_str.split(':').collect();
            if parts.len() < 2 || parts.len() > 3 { return None; }
            let h: i64 = parts[0].parse().ok()?;
            let m: i64 = parts[1].parse().ok()?;
            let sec: i64 = if parts.len() == 3 { parts[2].parse().ok()? } else { 0 };
            h * 3600 + m * 60 + sec
        } else {
            ngx_core::parse::parse_time(rest, true)?
        };
        if !(0..86400).contains(&secs) { return None; }
        return Some((ExpiresKind::DailyAt, secs));
    }
    // "<time>"
    let (sign, tail): (i64, &[u8]) = if s.first() == Some(&b'-') { (-1, &s[1..]) }
        else if s.first() == Some(&b'+') { (1, &s[1..]) } else { (1, s) };
    let v = ngx_core::parse::parse_time(tail, true)?;
    Some((ExpiresKind::Access, sign * v))
}

fn apply_expires(r: &R, kind: ExpiresKind, base: i64) {
    // Determine the Expires date + Cache-Control value per C set_expires.
    let (expires_date, cc_val): (Vec<u8>, Vec<u8>) = match kind {
        ExpiresKind::Off => return,
        ExpiresKind::Epoch => (
            b"Thu, 01 Jan 1970 00:00:01 GMT".to_vec(),
            b"no-cache".to_vec(),
        ),
        ExpiresKind::Max => (
            b"Thu, 31 Dec 2037 23:55:55 GMT".to_vec(),
            b"max-age=315360000".to_vec(),
        ),
        ExpiresKind::Access | ExpiresKind::Modified | ExpiresKind::DailyAt => {
            let now = ngx_core::times::time();
            let expires_time = match kind {
                ExpiresKind::Modified => {
                    let lm = r.headers_out.borrow().last_modified_time;
                    if lm == -1 { now + base } else { lm + base }
                }
                ExpiresKind::DailyAt => {
                    // Next occurrence of "base" seconds past midnight (UTC).
                    let day = 86400;
                    let today_midnight = now - (now.rem_euclid(day));
                    let mut candidate = today_midnight + base;
                    if candidate < now { candidate += day; }
                    candidate
                }
                _ => now + base,
            };
            let date_s = ngx_core::times::http_time(expires_time);
            let cc = if base <= 0 { b"no-cache".to_vec() } else { format!("max-age={}", base).into_bytes() };
            (date_s.into_bytes(), cc)
        }
    };

    let mut ho = r.headers_out.borrow_mut();
    // Clear any existing Expires (both slot and stray headers entries) so we
    // don't emit duplicates.
    if let Some(old) = ho.expires.take() {
        old.hash.set(0);
    }
    for h in ho.headers.iter() {
        if h.lowcase_key.as_slice() == b"expires" {
            h.hash.set(0);
        }
    }
    let e = crate::request::TableElt::new(b"Expires", &expires_date);
    ho.expires = Some(e.clone());
    ho.headers.push(e);

    // Clear all pre-existing Cache-Control headers, then add ours.
    for h in ho.headers.iter() {
        if h.lowcase_key.as_slice() == b"cache-control" {
            h.hash.set(0);
        }
    }
    ho.cache_control.clear();
    let cc = crate::request::TableElt::new(b"Cache-Control", &cc_val);
    ho.cache_control.push(cc.clone());
    ho.headers.push(cc);
}

async fn headers_filter(r: R, next: HeaderFilter) -> i64 {
    if !r.is_main() {
        return next(r).await;
    }
    let conf = r.loc_conf::<HeadersConf>(ctx_index());
    let headers = conf.borrow().headers.clone();
    let (mut expires, mut expires_time) = (conf.borrow().expires, conf.borrow().expires_time);
    let expires_value = conf.borrow().expires_value.clone();
    let status = r.headers_out.borrow().status;
    let safe = matches!(status, 200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308);

    // Resolve dynamic expires (from `expires <$var>` or similar).
    if safe {
        if let Some(cv) = &expires_value {
            if let Ok(bytes) = crate::script::complex_value(&r, cv) {
                if let Some((k, t)) = parse_expires_spec(&bytes) {
                    expires = Some(k);
                    expires_time = t;
                }
            }
        }
    }

    // Apply expires before add_header — matches C which runs
    // ngx_http_set_expires early in the header filter for safe statuses.
    if safe {
        if let Some(kind) = expires {
            if kind != ExpiresKind::Off {
                apply_expires(&r, kind, expires_time);
            }
        }
    }
    if let Some(hs) = headers {
        for (name, cv, always) in hs.iter() {
            if !safe && !always {
                continue;
            }
            let v = match complex_value(&r, cv) {
                Ok(v) => v,
                Err(_) => return NGX_ERROR,
            };
            // Match ngx_http_set_response_header / set_last_modified /
            // set_content_length semantics: an empty value on a well-known
            // header slot CLEARS that slot rather than being appended.
            if v.is_empty() {
                let lc = name.to_ascii_lowercase();
                match lc.as_slice() {
                    b"last-modified" => {
                        let mut ho = r.headers_out.borrow_mut();
                        if let Some(h) = ho.last_modified.take() {
                            h.hash.set(0);
                        }
                        ho.last_modified_time = -1;
                    }
                    b"etag" => {
                        let mut ho = r.headers_out.borrow_mut();
                        if let Some(h) = ho.etag.take() {
                            h.hash.set(0);
                        }
                    }
                    b"expires" => {
                        let mut ho = r.headers_out.borrow_mut();
                        if let Some(h) = ho.expires.take() {
                            h.hash.set(0);
                        }
                    }
                    b"location" => {
                        let mut ho = r.headers_out.borrow_mut();
                        if let Some(h) = ho.location.take() {
                            h.hash.set(0);
                        }
                    }
                    _ => {}
                }
                continue;
            }
            // Set specific slots when the user overrides a well-known header,
            // so downstream filters (range, not_modified, header_filter emit)
            // see the new value rather than stale cache. Also zero the hash of
            // any pre-existing header slot entry so header_filter's generic
            // headers loop doesn't emit a stale duplicate.
            let lc = name.to_ascii_lowercase();
            match lc.as_slice() {
                b"last-modified" => {
                    let mut ho = r.headers_out.borrow_mut();
                    if let Some(old) = ho.last_modified.take() {
                        old.hash.set(0);
                    }
                    let h = ho.add(name, &v);
                    ho.last_modified = Some(h);
                    ho.last_modified_time = ngx_core::parse::parse_http_time(&v).unwrap_or(-1);
                }
                b"etag" => {
                    let mut ho = r.headers_out.borrow_mut();
                    if let Some(old) = ho.etag.take() {
                        old.hash.set(0);
                    }
                    let h = ho.add(name, &v);
                    ho.etag = Some(h);
                }
                // ngx_http_add_multi_header_lines
                b"cache-control" => {
                    let mut ho = r.headers_out.borrow_mut();
                    let h = ho.add(name, &v);
                    ho.cache_control.push(h);
                }
                b"link" => {
                    let mut ho = r.headers_out.borrow_mut();
                    let h = ho.add(name, &v);
                    ho.link.push(h);
                }
                _ => {
                    r.headers_out.borrow_mut().add(name, &v);
                }
            }
        }
    }
    let trailers = conf.borrow().trailers.clone();
    if let Some(ts) = &trailers {
        // a trailer for the status (or "always") expects trailers
        if ts.iter().any(|(_, _, always)| safe || *always) {
            r.expect_trailers.set(true);
        }
    }
    next(r).await
}
