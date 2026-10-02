//! ngx_http_headers_filter_module: add_header, add_trailer and their
//! inheritance, and expires.

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::Chain;
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_headers_filter_module");

const NGX_HTTP_HEADERS_INHERIT_OFF: u32 = 0;
const NGX_HTTP_HEADERS_INHERIT_ON: u32 = 1;
const NGX_HTTP_HEADERS_INHERIT_MERGE: u32 = 2;

/// ngx_http_headers_inherit
const HEADERS_INHERIT: [(&str, u32); 3] = [
    ("off", NGX_HTTP_HEADERS_INHERIT_OFF),
    ("on", NGX_HTTP_HEADERS_INHERIT_ON),
    ("merge", NGX_HTTP_HEADERS_INHERIT_MERGE),
];

/// ngx_http_expires_t
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expires {
    Off,
    Epoch,
    Max,
    Access,
    Modified,
    Daily,
    Unset,
}

/// The handler (and the headers_out offset) of an add_header
/// (ngx_http_set_header_pt of ngx_http_set_headers[])
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SetHeader {
    /// ngx_http_add_header
    Add,
    /// ngx_http_add_multi_header_lines, r->headers_out.cache_control
    CacheControl,
    /// ngx_http_add_multi_header_lines, r->headers_out.link
    Link,
    /// ngx_http_set_last_modified, r->headers_out.last_modified
    LastModified,
    /// ngx_http_set_response_header, r->headers_out.etag
    ETag,
}

/// ngx_http_header_val_t
#[derive(Clone)]
pub struct HeaderVal {
    value: ComplexValue,
    key: Vec<u8>,
    handler: SetHeader,
    always: bool,
}

/// ngx_http_headers_conf_t
pub struct HeadersConf {
    pub expires: Expires,
    pub expires_time: i64,
    pub expires_value: Option<ComplexValue>,
    /// the add_header list, shared by the requests (and the locations that
    /// inherit it as it is)
    pub headers: Option<Rc<[HeaderVal]>>,
    /// the add_trailer list
    pub trailers: Option<Rc<[HeaderVal]>>,
    pub headers_inherit: Val<u32>,
    pub trailers_inherit: Val<u32>,
}

pub fn headers_filter_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF;

    let def = HttpModuleDef { postconfiguration: Some(filter_init), create_loc_conf: Some(create_conf), merge_loc_conf: Some(merge_conf), ..Default::default() };

    let commands = vec![
        ngx_core::cmd_fn!("expires", F | NGX_CONF_TAKE12, ConfLevel::Loc, headers_expires),
        ngx_core::cmd_fn!("add_header", F | NGX_CONF_TAKE23, ConfLevel::Loc, headers_add_header),
        ngx_core::cmd_fn!("add_trailer", F | NGX_CONF_TAKE23, ConfLevel::Loc, headers_add_trailer),
        ngx_core::cmd_fn!("add_header_inherit", F | NGX_CONF_TAKE1, ConfLevel::Loc, headers_inherit),
        ngx_core::cmd_fn!("add_trailer_inherit", F | NGX_CONF_TAKE1, ConfLevel::Loc, trailers_inherit),
    ];

    http_module_def("ngx_http_headers_filter_module", def, commands)
}

/// The statuses the headers are added to without "always"
fn safe_status(status: i64) -> bool {
    matches!(
        status,
        NGX_HTTP_OK
            | NGX_HTTP_CREATED
            | NGX_HTTP_NO_CONTENT
            | NGX_HTTP_PARTIAL_CONTENT
            | NGX_HTTP_MOVED_PERMANENTLY
            | NGX_HTTP_MOVED_TEMPORARILY
            | NGX_HTTP_SEE_OTHER
            | NGX_HTTP_NOT_MODIFIED
            | NGX_HTTP_TEMPORARY_REDIRECT
            | NGX_HTTP_PERMANENT_REDIRECT
    )
}

/// ngx_http_headers_filter
fn headers_filter(r: R, next: &HeaderFilter) -> Step {
    if !r.is_main() {
        return next(r);
    }

    let conf = r.loc_conf::<HeadersConf>(ctx_index());

    {
        let c = conf.borrow();

        if c.expires == Expires::Off && c.headers.is_none() && c.trailers.is_none() {
            drop(c);
            return next(r);
        }
    }

    let safe_status = safe_status(r.headers_out.borrow().status);

    if conf.borrow().expires != Expires::Off && safe_status && set_expires(&r, &conf.borrow()) != NGX_OK {
        return Step::Ready(NGX_ERROR);
    }

    let headers = conf.borrow().headers.clone();

    if let Some(h) = headers {
        for hv in h.iter() {
            if !safe_status && !hv.always {
                continue;
            }

            let value = match complex_value(&r, &hv.value) {
                Ok(v) => v,
                Err(_) => return Step::Ready(NGX_ERROR),
            };

            set_header(&r, hv, value);
        }
    }

    if let Some(t) = conf.borrow().trailers.as_ref() {
        if t.iter().any(|hv| safe_status || hv.always) {
            r.expect_trailers.set(true);
        }
    }

    next(r)
}

/// ngx_http_trailers_filter
fn trailers_filter(r: R, input: Chain, next: &BodyFilter) -> Step {
    if input.is_empty() || !r.expect_trailers.get() || r.header_only.get() {
        return next(r, input);
    }

    let conf = r.loc_conf::<HeadersConf>(ctx_index());

    let trailers = conf.borrow().trailers.clone();

    let trailers = match trailers {
        Some(t) => t,
        None => return next(r, input),
    };

    if !input.iter().any(|b| b.last_buf) {
        return next(r, input);
    }

    let safe_status = safe_status(r.headers_out.borrow().status);

    for hv in trailers.iter() {
        if !safe_status && !hv.always {
            continue;
        }

        let value = match complex_value(&r, &hv.value) {
            Ok(v) => v,
            Err(_) => return Step::Ready(NGX_ERROR),
        };

        if !value.is_empty() {
            r.headers_out.borrow_mut().trailers.push(TableElt::generated(&hv.key, value));
        }
    }

    next(r, input)
}

/// ngx_http_set_expires
fn set_expires(r: &R, conf: &HeadersConf) -> i64 {
    let mut expires = conf.expires;
    let mut expires_time = conf.expires_time;

    if let Some(cv) = &conf.expires_value {
        let value = match complex_value(r, cv) {
            Ok(v) => v,
            Err(_) => return NGX_ERROR,
        };

        if parse_expires(&value, &mut expires, &mut expires_time).is_err() {
            return NGX_OK;
        }

        if expires == Expires::Off {
            return NGX_OK;
        }
    }

    let mut ho = r.headers_out.borrow_mut();

    let e = match ho.expires.clone() {
        Some(e) => e,
        None => {
            let e = ho.add_generated(b"Expires", Vec::new());
            ho.expires = Some(e.clone());
            e
        }
    };

    // the first Cache-Control, the others removed
    let cc = match ho.cache_control.first().cloned() {
        Some(cc) => {
            for next in ho.cache_control.iter().skip(1) {
                next.hash.set(0);
            }

            ho.cache_control.truncate(1);

            cc
        }
        None => {
            let cc = ho.add_generated(b"Cache-Control", Vec::new());
            ho.cache_control.push(cc.clone());
            cc
        }
    };

    if expires == Expires::Epoch {
        *e.value.borrow_mut() = b"Thu, 01 Jan 1970 00:00:01 GMT".to_vec();
        *cc.value.borrow_mut() = b"no-cache".to_vec();
        return NGX_OK;
    }

    if expires == Expires::Max {
        *e.value.borrow_mut() = b"Thu, 31 Dec 2037 23:55:55 GMT".to_vec();
        // 10 years
        *cc.value.borrow_mut() = b"max-age=315360000".to_vec();
        return NGX_OK;
    }

    if expires_time == 0 && expires != Expires::Daily {
        *e.value.borrow_mut() = ngx_core::times::cached_http_time().as_bytes().to_vec();
        *cc.value.borrow_mut() = b"max-age=0".to_vec();
        return NGX_OK;
    }

    let now = ngx_core::times::time();

    let max_age;

    if expires == Expires::Daily {
        expires_time = ngx_core::times::next_time(expires_time);
        max_age = expires_time - now;
    } else if expires == Expires::Access || ho.last_modified_time == -1 {
        max_age = expires_time;
        expires_time += now;
    } else {
        expires_time += ho.last_modified_time;
        max_age = expires_time - now;
    }

    *e.value.borrow_mut() = ngx_core::times::http_time(expires_time).into_bytes();

    if conf.expires_time < 0 || max_age < 0 {
        *cc.value.borrow_mut() = b"no-cache".to_vec();
        return NGX_OK;
    }

    *cc.value.borrow_mut() = format!("max-age={}", max_age).into_bytes();

    NGX_OK
}

/// ngx_http_parse_expires: Err with the message of the directive
fn parse_expires(value: &[u8], expires: &mut Expires, expires_time: &mut i64) -> Result<(), &'static str> {
    if *expires != Expires::Modified {
        if value == b"epoch" {
            *expires = Expires::Epoch;
            return Ok(());
        }

        if value == b"max" {
            *expires = Expires::Max;
            return Ok(());
        }

        if value == b"off" {
            *expires = Expires::Off;
            return Ok(());
        }
    }

    let (value, minus) = match value.first() {
        Some(b'@') => {
            if *expires == Expires::Modified {
                return Err("daily time cannot be used with \"modified\" parameter");
            }

            *expires = Expires::Daily;

            (&value[1..], false)
        }
        Some(b'+') => (&value[1..], false),
        Some(b'-') => (&value[1..], true),
        _ => (value, false),
    };

    *expires_time = match ngx_core::parse::parse_time(value, true) {
        Some(t) => t,
        None => return Err("invalid value"),
    };

    if *expires == Expires::Daily && *expires_time > 24 * 60 * 60 {
        return Err("daily time value must be less than 24 hours");
    }

    if minus {
        *expires_time = -*expires_time;
    }

    Ok(())
}

/// The handler of an add_header with its value, which the header takes
fn set_header(r: &R, hv: &HeaderVal, value: Vec<u8>) {
    let mut ho = r.headers_out.borrow_mut();

    match hv.handler {
        SetHeader::Add => {
            // ngx_http_add_header
            if !value.is_empty() {
                ho.add_generated(&hv.key, value);
            }
        }

        SetHeader::CacheControl | SetHeader::Link => {
            // ngx_http_add_multi_header_lines
            if value.is_empty() {
                return;
            }

            let h = ho.add_generated(&hv.key, value);

            if hv.handler == SetHeader::CacheControl {
                ho.cache_control.push(h);
            } else {
                ho.link.push(h);
            }
        }

        SetHeader::LastModified => {
            // ngx_http_set_last_modified
            let time = if value.is_empty() { -1 } else { ngx_core::parse::parse_http_time(&value).unwrap_or(-1) };

            let slot = ho.last_modified.take();
            ho.last_modified = set_response_header(&mut ho, slot, hv, value);

            ho.last_modified_time = time;
        }

        SetHeader::ETag => {
            let slot = ho.etag.take();
            ho.etag = set_response_header(&mut ho, slot, hv, value);
        }
    }
}

/// ngx_http_set_response_header: the header of the slot gets the key and
/// value in its place in the list (or a new one), or is removed for an
/// empty value; the new slot
fn set_response_header(ho: &mut HeadersOut, old: Option<Header>, hv: &HeaderVal, value: Vec<u8>) -> Option<Header> {
    if value.is_empty() {
        if let Some(old) = old {
            old.hash.set(0);
        }

        return None;
    }

    let h = TableElt::generated(&hv.key, value);

    match old.and_then(|old| ho.headers.iter().position(|x| Rc::ptr_eq(x, &old))) {
        Some(i) => ho.headers[i] = h.clone(),
        None => ho.headers.push(h.clone()),
    }

    Some(h)
}

/// ngx_http_headers_create_conf
fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(HeadersConf {
        expires: Expires::Unset,
        expires_time: 0,
        expires_value: None,
        headers: None,
        trailers: None,
        headers_inherit: Val::unset(),
        trailers_inherit: Val::unset(),
    })
}

/// ngx_http_headers_merge_conf
fn merge_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<HeadersConf>(parent).borrow();
    let mut conf = conf_cell::<HeadersConf>(child).borrow_mut();

    if conf.expires == Expires::Unset {
        conf.expires = prev.expires;
        conf.expires_time = prev.expires_time;
        conf.expires_value = prev.expires_value.clone();

        if conf.expires == Expires::Unset {
            conf.expires = Expires::Off;
        }
    }

    conf.headers_inherit.merge(&prev.headers_inherit, NGX_HTTP_HEADERS_INHERIT_ON);
    conf.trailers_inherit.merge(&prev.trailers_inherit, NGX_HTTP_HEADERS_INHERIT_ON);

    let headers_inherit = *conf.headers_inherit;
    inherit(&mut conf.headers, prev.headers.as_ref(), headers_inherit);

    let trailers_inherit = *conf.trailers_inherit;
    inherit(&mut conf.trailers, prev.trailers.as_ref(), trailers_inherit);

    Ok(())
}

/// The parent's headers (trailers) as add_header_inherit says
fn inherit(headers: &mut Option<Rc<[HeaderVal]>>, prev: Option<&Rc<[HeaderVal]>>, mode: u32) {
    let prev = match prev {
        Some(p) if mode != NGX_HTTP_HEADERS_INHERIT_OFF => p,
        _ => return,
    };

    match headers {
        None => *headers = Some(prev.clone()),
        Some(h) if mode == NGX_HTTP_HEADERS_INHERIT_MERGE => *h = h.iter().chain(prev.iter()).cloned().collect(),
        Some(_) => {}
    }
}

/// ngx_http_headers_filter_init
fn filter_init(_cf: &mut Conf) -> ConfResult {
    crate::install_header_filter_fn(headers_filter);
    crate::install_body_filter_fn(trailers_filter);
    Ok(())
}

/// ngx_http_headers_expires
fn headers_expires(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let mut hcf = cell.borrow_mut();

    if hcf.expires != Expires::Unset {
        return Err(msg("is duplicate"));
    }

    let value = cf.args.clone();

    let n = if value.len() == 2 {
        hcf.expires = Expires::Access;
        1
    } else {
        if value[1] != b"modified" {
            return Err(msg("invalid value"));
        }

        hcf.expires = Expires::Modified;
        2
    };

    let cv = compile_complex_value(cf, &value[n], 0)?;

    if cv.parts.is_some() {
        hcf.expires_value = Some(cv);
        return Ok(());
    }

    let HeadersConf { expires, expires_time, .. } = &mut *hcf;

    parse_expires(&value[n], expires, expires_time).map_err(msg)
}

fn headers_add_header(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    headers_add(cf, conf, false)
}

fn headers_add_trailer(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    headers_add(cf, conf, true)
}

/// ngx_http_headers_add, for add_header or add_trailer
fn headers_add(cf: &mut Conf, conf: Option<Rc<dyn Any>>, trailer: bool) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());

    let value = cf.args.clone();

    let mut handler = SetHeader::Add;

    if !trailer {
        // ngx_http_set_headers[]
        let set = [
            (&b"Cache-Control"[..], SetHeader::CacheControl),
            (&b"Link"[..], SetHeader::Link),
            (&b"Last-Modified"[..], SetHeader::LastModified),
            (&b"ETag"[..], SetHeader::ETag),
        ];

        if let Some((_, h)) = set.iter().find(|(name, _)| name.eq_ignore_ascii_case(&value[1])) {
            handler = *h;
        }
    }

    let cv = compile_complex_value(cf, &value[2], 0)?;

    let mut hv = HeaderVal { value: cv, key: value[1].clone(), handler, always: false };

    if value.len() == 4 {
        if value[3] != b"always" {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[3]))));
        }

        hv.always = true;
    }

    let mut hcf = cell.borrow_mut();

    let headers = if trailer { &mut hcf.trailers } else { &mut hcf.headers };

    let mut list = headers.as_deref().map(|h| h.to_vec()).unwrap_or_default();
    list.push(hv);
    *headers = Some(list.into());

    Ok(())
}

/// ngx_conf_set_enum_slot of add_header_inherit
fn headers_inherit(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let mut hcf = cell.borrow_mut();

    set_enum(cf, cmd, &mut hcf.headers_inherit, &HEADERS_INHERIT)
}

/// ngx_conf_set_enum_slot of add_trailer_inherit
fn trailers_inherit(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<HeadersConf>(conf.as_ref().unwrap());
    let mut hcf = cell.borrow_mut();

    set_enum(cf, cmd, &mut hcf.trailers_inherit, &HEADERS_INHERIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: &[u8], modified: bool) -> Result<(Expires, i64), &'static str> {
        let mut expires = if modified { Expires::Modified } else { Expires::Access };
        let mut t = 0;

        parse_expires(v, &mut expires, &mut t).map(|()| (expires, t))
    }

    #[test]
    fn test_parse_expires() {
        assert_eq!(parse(b"epoch", false), Ok((Expires::Epoch, 0)));
        assert_eq!(parse(b"max", false), Ok((Expires::Max, 0)));
        assert_eq!(parse(b"off", false), Ok((Expires::Off, 0)));
        assert_eq!(parse(b"1h", false), Ok((Expires::Access, 3600)));
        assert_eq!(parse(b"+30m", false), Ok((Expires::Access, 1800)));
        assert_eq!(parse(b"-2048", false), Ok((Expires::Access, -2048)));
        assert_eq!(parse(b"@15h30m33s", false), Ok((Expires::Daily, 55833)));
        assert_eq!(parse(b"@24h", false), Ok((Expires::Daily, 86400)));
        assert_eq!(parse(b"@25h", false), Err("daily time value must be less than 24 hours"));
        assert_eq!(parse(b"@15:30", false), Err("invalid value"));
        assert_eq!(parse(b"bad", false), Err("invalid value"));

        // "modified": no epoch/max/off, no daily time
        assert_eq!(parse(b"2048", true), Ok((Expires::Modified, 2048)));
        assert_eq!(parse(b"epoch", true), Err("invalid value"));
        assert_eq!(parse(b"@1h", true), Err("daily time cannot be used with \"modified\" parameter"));
    }

    fn hv(key: &[u8], handler: SetHeader) -> HeaderVal {
        HeaderVal { value: ComplexValue { value: Vec::new(), parts: None, flags: 0 }, key: key.to_vec(), handler, always: false }
    }

    #[test]
    fn test_inherit() {
        let parent: Rc<[HeaderVal]> = vec![hv(b"X-A", SetHeader::Add)].into();

        let mut none = None;
        inherit(&mut none, Some(&parent), NGX_HTTP_HEADERS_INHERIT_ON);
        assert_eq!(none.as_ref().map(|h| h.len()), Some(1));
        // shared, not copied
        assert!(Rc::ptr_eq(none.as_ref().unwrap(), &parent));

        let mut own: Option<Rc<[HeaderVal]>> = Some(vec![hv(b"X-B", SetHeader::Add)].into());
        inherit(&mut own, Some(&parent), NGX_HTTP_HEADERS_INHERIT_ON);
        assert_eq!(own.as_ref().unwrap().iter().map(|h| h.key.clone()).collect::<Vec<_>>(), vec![b"X-B".to_vec()]);

        inherit(&mut own, Some(&parent), NGX_HTTP_HEADERS_INHERIT_MERGE);
        assert_eq!(own.as_ref().unwrap().iter().map(|h| h.key.clone()).collect::<Vec<_>>(), vec![b"X-B".to_vec(), b"X-A".to_vec()]);

        let mut off = None;
        inherit(&mut off, Some(&parent), NGX_HTTP_HEADERS_INHERIT_OFF);
        assert!(off.is_none());
    }
}
