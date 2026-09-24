//! ngx_http_headers_filter_module: full port with expires, add_header, add_trailer directives

use std::any::Any;
use std::cell::Cell;
use std::rc::Rc;

use ngx_core::buf::Chain;
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::parse::parse_time;
use ngx_core::rc::*;
use ngx_core::times;

use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_headers_filter_module");

// Expires directive types
#[derive(Debug, Clone, Copy, PartialEq)]
enum ExpiresType {
    Off,
    Epoch,
    Max,
    Access,
    Modified,
    Daily,
    Unset,
}

pub struct HeadersConf {
    pub headers: Option<Vec<HeaderVal>>,
    pub trailers: Option<Vec<HeaderVal>>,
    pub expires_type: ExpiresType,
    pub expires_time: i64,
    pub expires_value: Option<ComplexValue>,
}

#[derive(Clone)]
struct HeaderVal {
    name: Vec<u8>,
    value: ComplexValue,
    always: bool,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(HeadersConf {
        headers: None,
        trailers: None,
        expires_type: ExpiresType::Unset,
        expires_time: 0,
        expires_value: None,
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<HeadersConf>(prev).borrow();
    let mut c = conf_cell::<HeadersConf>(conf).borrow_mut();

    // Merge expires
    if c.expires_type == ExpiresType::Unset {
        c.expires_type = p.expires_type;
        c.expires_time = p.expires_time;
        c.expires_value.clone_from(&p.expires_value);
        if c.expires_type == ExpiresType::Unset {
            c.expires_type = ExpiresType::Off;
        }
    }

    // Merge headers: default behavior is "on" (inherit if not redefined)
    if c.headers.is_none() {
        c.headers = p.headers.clone();
    }

    // Merge trailers: default behavior is "on" (inherit if not redefined)
    if c.trailers.is_none() {
        c.trailers = p.trailers.clone();
    }

    Ok(())
}

fn add_header(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let cv = compile_complex_value(cf, &args[2], 0)?;
    let always = args.len() == 4 && args[3] == b"always";
    let mut c = cell.borrow_mut();
    c.headers.get_or_insert_with(Vec::new).push(HeaderVal {
        name: args[1].clone(),
        value: cv,
        always,
    });
    Ok(())
}

fn add_trailer(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let cv = compile_complex_value(cf, &args[2], 0)?;
    let always = args.len() == 4 && args[3] == b"always";
    let mut c = cell.borrow_mut();
    c.trailers.get_or_insert_with(Vec::new).push(HeaderVal {
        name: args[1].clone(),
        value: cv,
        always,
    });
    Ok(())
}

fn expires_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let mut c = cell.borrow_mut();

    if c.expires_type != ExpiresType::Unset {
        return Err(msg("is duplicate"));
    }

    let (mut expires_type, val_idx) = if args.len() == 2 {
        (ExpiresType::Access, 1)
    } else if args.len() == 3 {
        if args[1] != b"modified" {
            return Err(msg("invalid value"));
        }
        (ExpiresType::Modified, 2)
    } else {
        return Err(msg("invalid arguments"));
    };

    let cv = compile_complex_value(cf, &args[val_idx], 0)?;

    // If the value contains variables, store it for runtime evaluation
    if cv.parts.is_some() {
        c.expires_type = expires_type;
        c.expires_value = Some(cv);
        return Ok(());
    }

    // Parse static expires value
    let mut expires_time = 0i64;
    if let Err(e) = parse_expires(&args[val_idx], &mut expires_type, &mut expires_time, expires_type) {
        return Err(msg(&e));
    }

    c.expires_type = expires_type;
    c.expires_time = expires_time;

    Ok(())
}

fn parse_expires(value: &[u8], expires_type: &mut ExpiresType, expires_time: &mut i64, conf_type: ExpiresType) -> Result<(), String> {
    // Check for special keywords (unless we're in MODIFIED mode)
    if conf_type != ExpiresType::Modified {
        if value.eq_ignore_ascii_case(b"epoch") {
            *expires_type = ExpiresType::Epoch;
            return Ok(());
        }
        if value.eq_ignore_ascii_case(b"max") {
            *expires_type = ExpiresType::Max;
            return Ok(());
        }
        if value.eq_ignore_ascii_case(b"off") {
            *expires_type = ExpiresType::Off;
            return Ok(());
        }
    }

    // Parse @HH:MM:SS (daily time)
    let (parsed_val, is_daily) = if !value.is_empty() && value[0] == b'@' {
        if conf_type == ExpiresType::Modified {
            return Err("daily time cannot be used with \"modified\" parameter".to_string());
        }
        (&value[1..], true)
    } else if !value.is_empty() && (value[0] == b'+' || value[0] == b'-') {
        (&value[1..], false)
    } else {
        (value, false)
    };

    // Parse time value
    let t = parse_time(parsed_val, true).ok_or_else(|| "invalid value".to_string())?;

    if is_daily {
        if t > 24 * 3600 {
            return Err("daily time value must be less than 24 hours".to_string());
        }
        *expires_type = ExpiresType::Daily;
    } else {
        *expires_type = conf_type;
    }

    // Handle sign
    if !value.is_empty() && value[0] == b'-' {
        *expires_time = -t;
    } else {
        *expires_time = t;
    }

    Ok(())
}

pub fn headers_filter_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("expires", F | NGX_CONF_TAKE12, ConfLevel::Loc, expires_directive),
        ngx_core::cmd_fn!("add_header", F | NGX_CONF_TAKE23, ConfLevel::Loc, add_header),
        ngx_core::cmd_fn!("add_trailer", F | NGX_CONF_TAKE23, ConfLevel::Loc, add_trailer),
    ];
    http_module_def("ngx_http_headers_filter_module", def, commands)
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { headers_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { trailers_filter(r, chain, next).await });
    Ok(())
}

fn is_safe_status(status: i64) -> bool {
    matches!(
        status,
        200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308
    )
}

async fn headers_filter(r: R, next: HeaderFilter) -> i64 {
    if !r.is_main() {
        return next(r).await;
    }

    let conf = r.loc_conf::<HeadersConf>(ctx_index());
    let conf_borrow = conf.borrow();

    // Early exit if nothing to do
    if conf_borrow.expires_type == ExpiresType::Off
        && conf_borrow.headers.is_none()
        && conf_borrow.trailers.is_none()
    {
        drop(conf_borrow);
        return next(r).await;
    }

    let status = r.headers_out.borrow().status;
    let safe = is_safe_status(status);

    // Handle expires
    if conf_borrow.expires_type != ExpiresType::Off && safe {
        drop(conf_borrow);
        if set_expires(&r, &conf) != NGX_OK {
            return NGX_ERROR;
        }
    } else {
        drop(conf_borrow);
    }

    // Handle add_header directives
    {
        let conf_borrow = conf.borrow();
        if let Some(headers) = &conf_borrow.headers {
            for hv in headers {
                if !safe && !hv.always {
                    continue;
                }
                let value = match complex_value(&r, &hv.value) {
                    Ok(v) => v,
                    Err(_) => return NGX_ERROR,
                };

                if let Err(_) = add_or_set_header(&r, &hv.name, &value) {
                    return NGX_ERROR;
                }
            }
        }
    }

    // Mark trailers if present
    {
        let conf_borrow = conf.borrow();
        if let Some(trailers) = &conf_borrow.trailers {
            if !trailers.is_empty() && !r.header_only.get() {
                r.expect_trailers.set(true);
            }
        }
    }

    next(r).await
}

/// Helper to create a TableElt
fn make_header(key: &[u8], value: &[u8]) -> Header {
    Rc::new(TableElt {
        key: key.to_vec(),
        value: std::cell::RefCell::new(value.to_vec()),
        lowcase_key: key.to_ascii_lowercase(),
    })
}

/// Handle setting special headers or generic headers
fn add_or_set_header(r: &R, name: &[u8], value: &[u8]) -> Result<(), i64> {
    // Compare case-insensitively for special headers
    let name_lower = name.to_ascii_lowercase();

    if name_lower == b"cache-control" {
        // Cache-Control: accumulate multiple values
        if !value.is_empty() {
            r.headers_out.borrow_mut().cache_control.push(make_header(name, value));
        }
        Ok(())
    } else if name_lower == b"link" {
        // Link: accumulate multiple values
        if !value.is_empty() {
            r.headers_out.borrow_mut().link.push(make_header(name, value));
        }
        Ok(())
    } else if name_lower == b"last-modified" {
        // Last-Modified: set or clear
        let mut h = r.headers_out.borrow_mut();
        if value.is_empty() {
            if let Some(hdr) = &h.last_modified {
                hdr.hash.set(0);
            }
            h.last_modified = None;
            h.last_modified_time = -1;
        } else {
            let hdr = make_header(name, value);
            // Update last_modified_time
            if let Some(t) = ngx_core::parse::parse_http_time(value) {
                h.last_modified_time = t;
            }
            h.last_modified = Some(hdr);
        }
        Ok(())
    } else if name_lower == b"etag" {
        // ETag: set or clear
        let mut h = r.headers_out.borrow_mut();
        if value.is_empty() {
            if let Some(hdr) = &h.etag {
                hdr.hash.set(0);
            }
            h.etag = None;
        } else {
            let hdr = make_header(name, value);
            h.etag = Some(hdr);
        }
        Ok(())
    } else if name_lower == b"content-type" {
        // Content-Type: set or clear
        let mut h = r.headers_out.borrow_mut();
        if value.is_empty() {
            h.content_type.clear();
        } else {
            h.content_type.clear();
            h.content_type.extend_from_slice(value);
        }
        Ok(())
    } else if name_lower == b"content-length" {
        // Content-Length: set or clear
        let mut h = r.headers_out.borrow_mut();
        if value.is_empty() {
            h.content_length = None;
            h.content_length_n = -1;
        } else {
            // Try to parse as number
            if let Ok(s) = std::str::from_utf8(value) {
                if let Ok(n) = s.parse::<i64>() {
                    h.content_length_n = n;
                    h.content_length = Some(make_header(name, value));
                }
            }
        }
        Ok(())
    } else {
        // Generic header: just add
        if !value.is_empty() {
            r.headers_out.borrow_mut().add(name, value);
        }
        Ok(())
    }
}

fn set_expires(r: &R, conf: &Rc<RefCell<HeadersConf>>) -> i64 {
    let conf_borrow = conf.borrow();
    let mut expires_type = conf_borrow.expires_type;
    let mut expires_time = conf_borrow.expires_time;
    let expires_value = conf_borrow.expires_value.clone();
    drop(conf_borrow);

    // If expires_value is set, evaluate it at runtime
    if let Some(ev) = expires_value {
        let value = match complex_value(r, &ev) {
            Ok(v) => v,
            Err(_) => return NGX_ERROR,
        };

        if let Err(_) = parse_expires(&value, &mut expires_type, &mut expires_time, expires_type) {
            return NGX_OK; // Silently ignore parse errors
        }

        if expires_type == ExpiresType::Off {
            return NGX_OK;
        }
    }

    // Get current time
    let now = times::time();

    // Build Expires header value
    if expires_type == ExpiresType::Epoch {
        // Thu, 01 Jan 1970 00:00:01 GMT
        r.headers_out.borrow_mut().expires =
            Some(make_header(b"Expires", b"Thu, 01 Jan 1970 00:00:01 GMT"));
        // Set Cache-Control: no-cache
        r.headers_out.borrow_mut().cache_control.push(make_header(b"Cache-Control", b"no-cache"));
        return NGX_OK;
    } else if expires_type == ExpiresType::Max {
        // Thu, 31 Dec 2037 23:55:55 GMT
        r.headers_out.borrow_mut().expires =
            Some(make_header(b"Expires", b"Thu, 31 Dec 2037 23:55:55 GMT"));
        // Set Cache-Control: max-age=315360000 (10 years)
        r.headers_out.borrow_mut().cache_control.push(make_header(b"Cache-Control", b"max-age=315360000"));
        return NGX_OK;
    } else if expires_type == ExpiresType::Daily {
        // Next occurrence of the time
        let next = next_time(expires_time);
        if next == -1 {
            let http_time_str = times::http_time(now);
            r.headers_out.borrow_mut().expires =
                Some(make_header(b"Expires", http_time_str.as_bytes()));
            r.headers_out.borrow_mut().cache_control.push(make_header(b"Cache-Control", b"max-age=0"));
            return NGX_OK;
        }
        let max_age = next - now;
        let http_time_str = times::http_time(next);
        r.headers_out.borrow_mut().expires =
            Some(make_header(b"Expires", http_time_str.as_bytes()));
        let cache_control = format!("max-age={}", max_age);
        r.headers_out.borrow_mut().cache_control.push(make_header(b"Cache-Control", cache_control.as_bytes()));
        return NGX_OK;
    }

    // For ACCESS and MODIFIED types
    if expires_time == 0 {
        // Immediate expiry
        let http_time_str = times::http_time(now);
        r.headers_out.borrow_mut().expires =
            Some(make_header(b"Expires", http_time_str.as_bytes()));
        r.headers_out.borrow_mut().cache_control.push(make_header(b"Cache-Control", b"max-age=0"));
        return NGX_OK;
    }

    // Calculate final expiry time based on type
    let (final_expires_time, max_age) = if expires_type == ExpiresType::Modified {
        let lm = r.headers_out.borrow().last_modified_time;
        if lm == -1 {
            // No Last-Modified, treat like ACCESS
            let t = now + expires_time;
            let ma = expires_time;
            (t, ma)
        } else {
            let t = lm + expires_time;
            let ma = t - now;
            (t, ma)
        }
    } else {
        // ACCESS type
        let t = now + expires_time;
        (t, expires_time)
    };

    // Set Expires header
    let http_time_str = times::http_time(final_expires_time);
    r.headers_out.borrow_mut().expires = Some(make_header(b"Expires", http_time_str.as_bytes()));

    // Set Cache-Control header
    if max_age < 0 {
        r.headers_out.borrow_mut().cache_control.push(make_header(b"Cache-Control", b"no-cache"));
    } else {
        let cache_control = format!("max-age={}", max_age);
        r.headers_out.borrow_mut().cache_control.push(make_header(b"Cache-Control", cache_control.as_bytes()));
    }

    NGX_OK
}

/// Port of ngx_next_time: get the next occurrence of a time-of-day within 24 hours
fn next_time(when: i64) -> i64 {
    let now = times::time();
    let tm_now = times::localtime(now);

    let hour = when / 3600;
    let min = (when % 3600) / 60;
    let sec = when % 60;

    // Try today
    let mut next_tm = tm_now;
    next_tm.hour = hour as u32;
    next_tm.min = min as u32;
    next_tm.sec = sec as u32;

    if let Some(next) = mktime(next_tm) {
        if next > now {
            return next;
        }
    }

    // Try tomorrow
    next_tm.mday += 1;
    if let Some(next) = mktime(next_tm) {
        return next;
    }

    -1
}

/// Convert Tm to time_t via mktime
fn mktime(tm: times::Tm) -> Option<i64> {
    unsafe {
        let mut libc_tm: libc::tm = std::mem::zeroed();
        libc_tm.tm_sec = tm.sec as i32;
        libc_tm.tm_min = tm.min as i32;
        libc_tm.tm_hour = tm.hour as i32;
        libc_tm.tm_mday = tm.mday as i32;
        libc_tm.tm_mon = (tm.mon as i32) - 1;
        libc_tm.tm_year = (tm.year as i32) - 1900;
        libc_tm.tm_wday = tm.wday as i32;
        libc_tm.tm_yday = 0; // mktime recalculates this
        libc_tm.tm_isdst = -1; // Let mktime determine DST

        let t = libc::mktime(&mut libc_tm);
        if t == -1 {
            None
        } else {
            Some(t as i64)
        }
    }
}

async fn trailers_filter(r: R, chain: Chain, next: BodyFilter) -> i64 {
    // Only add trailers to the last buffer (last_buf)
    let mut has_last_buf = false;
    for buf in chain.iter() {
        if buf.last_buf.get() {
            has_last_buf = true;
            break;
        }
    }

    if !has_last_buf || r.header_only.get() {
        return next(r.clone(), chain).await;
    }

    let conf = r.loc_conf::<HeadersConf>(ctx_index());
    let conf_borrow = conf.borrow();

    if conf_borrow.trailers.is_none() || !r.expect_trailers.get() {
        drop(conf_borrow);
        return next(r.clone(), chain).await;
    }

    let status = r.headers_out.borrow().status;
    let safe = is_safe_status(status);

    let trailers = match &conf_borrow.trailers {
        Some(t) => t.clone(),
        None => {
            drop(conf_borrow);
            return next(r.clone(), chain).await;
        }
    };
    drop(conf_borrow);

    for hv in &trailers {
        if !safe && !hv.always {
            continue;
        }

        let value = match complex_value(&r, &hv.value) {
            Ok(v) => v,
            Err(_) => return NGX_ERROR,
        };

        if !value.is_empty() {
            r.headers_out.borrow_mut().trailers.push(make_header(&hv.name, &value));
        }
    }

    next(r.clone(), chain).await
}
