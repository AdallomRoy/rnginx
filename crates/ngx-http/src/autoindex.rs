//! ngx_http_autoindex_module: directory listings in the html, json, jsonp
//! and xml formats (port of ngx_http_autoindex_module.c).

use std::any::Any;
use std::cmp::Ordering;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::{escape_html_into, escape_json_into, escape_uri_count, escape_uri_into, utf8_cpystrn, utf8_length, B, NGX_ESCAPE_URI_COMPONENT};
use ngx_core::times::{gmtime, http_time, MONTHS};
use ngx_core::ngx_log_error;
use ngx_core::os::Dir;

use crate::*;

crate::http_module_index!("ngx_http_autoindex_module");

const NGX_HTTP_AUTOINDEX_HTML: u32 = 0;
const NGX_HTTP_AUTOINDEX_JSON: u32 = 1;
const NGX_HTTP_AUTOINDEX_JSONP: u32 = 2;
const NGX_HTTP_AUTOINDEX_XML: u32 = 3;

const NGX_HTTP_AUTOINDEX_PREALLOCATE: usize = 50;

const NGX_HTTP_AUTOINDEX_NAME_LEN: usize = 50;

pub struct AutoIndexConf {
    pub enable: Val<bool>,
    pub format: Val<u32>,
    pub localtime: Val<bool>,
    pub exact_size: Val<bool>,
}

struct Entry {
    name: Vec<u8>,
    utf_len: usize,
    escape: usize,
    escape_html: usize,

    dir: bool,
    file: bool,

    mtime: i64,
    size: i64,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AutoIndexConf {
        enable: Val::unset(),
        format: Val::unset(),
        localtime: Val::unset(),
        exact_size: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AutoIndexConf>(prev).borrow();
    let mut c = conf_cell::<AutoIndexConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    c.format.merge(&p.format, NGX_HTTP_AUTOINDEX_HTML);
    c.localtime.merge(&p.localtime, false);
    c.exact_size.merge(&p.exact_size, true);
    Ok(())
}

pub fn autoindex_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!("autoindex", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, AutoIndexConf, enable, set_flag),
        ngx_core::cmd_fn!("autoindex_format", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, autoindex_format_handler),
        ngx_core::cmd!("autoindex_localtime", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, AutoIndexConf, localtime, set_flag),
        ngx_core::cmd!("autoindex_exact_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, AutoIndexConf, exact_size, set_flag),
    ];
    http_module_def("ngx_http_autoindex_module", def, commands)
}

/// ngx_conf_set_enum_slot with ngx_http_autoindex_format[]
fn autoindex_format_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    const FORMATS: [(&str, u32); 4] = [
        ("html", NGX_HTTP_AUTOINDEX_HTML),
        ("json", NGX_HTTP_AUTOINDEX_JSON),
        ("jsonp", NGX_HTTP_AUTOINDEX_JSONP),
        ("xml", NGX_HTTP_AUTOINDEX_XML),
    ];

    let cell = conf_rc::<AutoIndexConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    set_enum(cf, cmd, &mut c.format, &FORMATS)
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, crate::core::phase_handler(autoindex_idle, autoindex_handler));
    Ok(())
}

fn close_dir(r: &R, dir: Dir, path: &[u8]) {
    if let Err(err) = dir.close() {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, Some(err), "closedir() \"{}\" failed", B(path));
    }
}

/// autoindex_handler declines at once: not a directory URI, a method it
/// does not handle, or autoindex off
fn autoindex_idle(r: &R) -> bool {
    r.uri.borrow().last() != Some(&b'/')
        || r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0
        || !*r.loc_conf::<AutoIndexConf>(ctx_index()).borrow().enable
}

async fn autoindex_handler(r: R) -> i64 {
    {
        let uri = r.uri.borrow();
        if uri.last() != Some(&b'/') {
            return NGX_DECLINED;
        }
    }

    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_DECLINED;
    }

    let alcf = r.loc_conf::<AutoIndexConf>(ctx_index());

    let (enable, mut format, localtime, exact_size) = {
        let c = alcf.borrow();
        (*c.enable, *c.format, *c.localtime, *c.exact_size)
    };

    if !enable {
        return NGX_DECLINED;
    }

    let rc = crate::request_body::discard_request_body(&r).await;

    if rc != NGX_OK {
        return rc;
    }

    let mut path = match crate::core_rt::map_uri_to_path(&r, NGX_HTTP_AUTOINDEX_PREALLOCATE) {
        Some((path, _root)) => path,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // the file names are appended where the mapped path ends, in the
    // buffer that has NGX_HTTP_AUTOINDEX_PREALLOCATE bytes reserved
    let mut filename = path.clone();
    let mut allocated = path.len() + NGX_HTTP_AUTOINDEX_PREALLOCATE + 1;

    if path.len() > 1 {
        path.pop();
    }

    http_debug!(r, "http autoindex: \"{}\"", B(&path));

    let mut callback = Vec::new();

    if format == NGX_HTTP_AUTOINDEX_JSONP {
        callback = match autoindex_jsonp_callback(&r) {
            Some(callback) => callback,
            None => return NGX_HTTP_BAD_REQUEST,
        };

        if callback.is_empty() {
            format = NGX_HTTP_AUTOINDEX_JSON;
        }
    }

    let mut dir = match Dir::open(&path) {
        Ok(dir) => dir,
        Err(err) => {
            let (level, rc) = if err == libc::ENOENT || err == libc::ENOTDIR || err == libc::ENAMETOOLONG {
                (NGX_LOG_ERR, NGX_HTTP_NOT_FOUND)
            } else if err == libc::EACCES {
                (NGX_LOG_ERR, NGX_HTTP_FORBIDDEN)
            } else {
                (NGX_LOG_CRIT, NGX_HTTP_INTERNAL_SERVER_ERROR)
            };

            ngx_log_error!(level, r.connection.log, Some(err), "opendir() \"{}\" failed", B(&path));

            return rc;
        }
    };

    {
        let mut ho = r.headers_out.borrow_mut();

        ho.status = NGX_HTTP_OK;

        match format {
            NGX_HTTP_AUTOINDEX_JSON => ho.content_type = b"application/json".to_vec(),
            NGX_HTTP_AUTOINDEX_JSONP => ho.content_type = b"application/javascript".to_vec(),
            NGX_HTTP_AUTOINDEX_XML => {
                ho.content_type = b"text/xml".to_vec();
                ho.charset = b"utf-8".to_vec();
            }
            _ => ho.content_type = b"text/html".to_vec(),
        }

        ho.content_type_len = ho.content_type.len();
        ho.content_type_lowcase = None;
    }

    let rc = crate::core_rt::send_header(&r).await;

    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        close_dir(&r, dir, &path);
        return rc;
    }

    let mut entries: Vec<Entry> = Vec::with_capacity(40);

    loop {
        let name = match dir.read() {
            Ok(name) => name,
            Err(0) => break,
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "readdir() \"{}\" failed", B(&path));
                close_dir(&r, dir, &path);
                return NGX_ERROR;
            }
        };

        http_debug!(r, "http autoindex file: \"{}\"", B(&name));

        if name.first() == Some(&b'.') {
            continue;
        }

        // 1 byte for '/' and 1 byte for terminating '\0'

        if path.len() + 1 + name.len() + 1 > allocated {
            allocated = path.len() + 1 + name.len() + 1 + NGX_HTTP_AUTOINDEX_PREALLOCATE;

            filename.clear();
            filename.extend_from_slice(&path);
            filename.push(b'/');
        }

        let prefix = filename.len();
        filename.extend_from_slice(&name);

        let info = match ngx_core::os::stat(&filename) {
            Ok(st) => st,
            Err(err) => {
                if err != libc::ENOENT && err != libc::ELOOP {
                    ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "stat() \"{}\" failed", B(&filename));

                    if err == libc::EACCES {
                        filename.truncate(prefix);
                        continue;
                    }

                    close_dir(&r, dir, &path);
                    return NGX_ERROR;
                }

                match ngx_core::os::lstat(&filename) {
                    Ok(st) => st,
                    Err(err) => {
                        ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "lstat() \"{}\" failed", B(&filename));
                        close_dir(&r, dir, &path);
                        return NGX_ERROR;
                    }
                }
            }
        };

        filename.truncate(prefix);

        entries.push(Entry {
            name,
            utf_len: 0,
            escape: 0,
            escape_html: 0,
            dir: ngx_core::os::is_dir(&info),
            file: ngx_core::os::is_file(&info),
            mtime: info.st_mtime as i64,
            size: info.st_size as i64,
        });
    }

    close_dir(&r, dir, &path);

    if entries.len() > 1 {
        entries.sort_by(autoindex_cmp_entries);
    }

    let body = match format {
        NGX_HTTP_AUTOINDEX_JSON => autoindex_json(&mut entries, None),
        NGX_HTTP_AUTOINDEX_JSONP => autoindex_json(&mut entries, Some(&callback)),
        NGX_HTTP_AUTOINDEX_XML => autoindex_xml(&mut entries),
        _ => {
            let utf8 = {
                let ho = r.headers_out.borrow();
                ho.charset.eq_ignore_ascii_case(b"utf-8")
            };
            let uri = r.uri.borrow().clone();
            let gmtoff = ngx_core::times::with_cached(|tp| tp.gmtoff);

            autoindex_html(&uri, &mut entries, utf8, gmtoff * 60 * localtime as i64, exact_size)
        }
    };

    let mut b = Buf::from_vec(body);

    if r.is_main() {
        b.last_buf = true;
    }

    b.last_in_chain = true;

    let mut out = Chain::new();
    out.push_back(b);

    crate::core_rt::output_filter(&r, out).await
}

/// Number of bytes ngx_escape_html() adds
fn escape_html_len(src: &[u8]) -> usize {
    src.iter()
        .map(|&ch| match ch {
            b'<' | b'>' => "&lt;".len() - 1,
            b'&' => "&amp;".len() - 1,
            b'"' => "&quot;".len() - 1,
            _ => 0,
        })
        .sum()
}

/// Number of bytes ngx_escape_json() adds
fn escape_json_len(src: &[u8]) -> usize {
    src.iter()
        .map(|&ch| match ch {
            b'\\' | b'"' => 1,
            b'\n' | b'\r' | b'\t' | 0x08 | 0x0c => 1,
            0..=0x1f => "\\u001F".len() - 1,
            _ => 0,
        })
        .sum()
}

/// ngx_sprintf() "%[0][width]i" / "%O": '-' for a negative value, then the
/// magnitude padded to `width` with `zero`
fn sprintf_num(buf: &mut Vec<u8>, value: i64, zero: u8, width: usize) {
    if value < 0 {
        buf.push(b'-');
    }

    let digits = value.unsigned_abs().to_string();

    for _ in digits.len()..width {
        buf.push(zero);
    }

    buf.extend_from_slice(digits.as_bytes());
}

/// ngx_http_autoindex_html; `offset` is the gmtoff in seconds when
/// autoindex_localtime is on, and 0 otherwise
fn autoindex_html(uri: &[u8], entries: &mut [Entry], utf8: bool, offset: i64, exact_size: bool) -> Vec<u8> {
    const TITLE: &[u8] = b"<html>\r\n<head><title>Index of ";
    const HEADER: &[u8] = b"</title></head>\r\n<body>\r\n<h1>Index of ";
    const TAIL: &[u8] = b"</body>\r\n</html>\r\n";

    let escape_html = escape_html_len(uri);

    let mut len = TITLE.len() + 2 * (uri.len() + escape_html) + HEADER.len() + TAIL.len() + 64;

    for e in entries.iter_mut() {
        e.escape = 2 * escape_uri_count(&e.name, NGX_ESCAPE_URI_COMPONENT);

        e.escape_html = escape_html_len(&e.name);

        e.utf_len = if utf8 { utf8_length(&e.name) } else { e.name.len() };

        len += 2 * e.name.len() + e.escape + e.escape_html + NGX_HTTP_AUTOINDEX_NAME_LEN + 64;
    }

    let mut b = Vec::with_capacity(len);

    b.extend_from_slice(TITLE);

    if escape_html != 0 {
        escape_html_into(&mut b, uri);
        b.extend_from_slice(HEADER);
        escape_html_into(&mut b, uri);
    } else {
        b.extend_from_slice(uri);
        b.extend_from_slice(HEADER);
        b.extend_from_slice(uri);
    }

    b.extend_from_slice(b"</h1>");

    b.extend_from_slice(b"<hr><pre><a href=\"../\">../</a>\r\n");

    for e in entries.iter() {
        b.extend_from_slice(b"<a href=\"");

        if e.escape != 0 {
            escape_uri_into(&mut b, &e.name, NGX_ESCAPE_URI_COMPONENT);
        } else {
            b.extend_from_slice(&e.name);
        }

        if e.dir {
            b.push(b'/');
        }

        b.push(b'"');
        b.push(b'>');

        let mut len = e.utf_len;

        // where "..&gt;" goes for a name longer than NGX_HTTP_AUTOINDEX_NAME_LEN
        let last;

        if e.name.len() != len {
            let char_len = if len > NGX_HTTP_AUTOINDEX_NAME_LEN {
                NGX_HTTP_AUTOINDEX_NAME_LEN - 3 + 1
            } else {
                NGX_HTTP_AUTOINDEX_NAME_LEN + 1
            };

            let copied = utf8_cpystrn(&e.name, char_len).len();

            if e.escape_html != 0 {
                escape_html_into(&mut b, &e.name[..copied]);
            } else {
                b.extend_from_slice(&e.name[..copied]);
            }

            last = b.len();
        } else if e.escape_html != 0 {
            let char_len = if len > NGX_HTTP_AUTOINDEX_NAME_LEN { NGX_HTTP_AUTOINDEX_NAME_LEN - 3 } else { len };

            escape_html_into(&mut b, &e.name[..char_len]);
            last = b.len();
        } else {
            // ngx_cpystrn(b->last, name, NGX_HTTP_AUTOINDEX_NAME_LEN + 1)
            b.extend_from_slice(&e.name[..len.min(NGX_HTTP_AUTOINDEX_NAME_LEN)]);
            last = b.len() - 3;
        }

        if len > NGX_HTTP_AUTOINDEX_NAME_LEN {
            b.truncate(last);
            b.extend_from_slice(b"..&gt;</a>");
        } else {
            if e.dir && NGX_HTTP_AUTOINDEX_NAME_LEN - len > 0 {
                b.push(b'/');
                len += 1;
            }

            b.extend_from_slice(b"</a>");

            if NGX_HTTP_AUTOINDEX_NAME_LEN - len > 0 {
                b.resize(b.len() + NGX_HTTP_AUTOINDEX_NAME_LEN - len, b' ');
            }
        }

        b.push(b' ');

        let tm = gmtime(e.mtime + offset);

        sprintf_num(&mut b, tm.mday as i64, b'0', 2);
        b.push(b'-');
        b.extend_from_slice(MONTHS[(tm.mon - 1) as usize].as_bytes());
        b.push(b'-');
        sprintf_num(&mut b, tm.year as i64, b' ', 0);
        b.push(b' ');
        sprintf_num(&mut b, tm.hour as i64, b'0', 2);
        b.push(b':');
        sprintf_num(&mut b, tm.min as i64, b'0', 2);
        b.push(b' ');

        if exact_size {
            if e.dir {
                b.extend_from_slice(b"                  -");
            } else {
                sprintf_num(&mut b, e.size, b' ', 19);
            }
        } else if e.dir {
            b.extend_from_slice(b"      -");
        } else {
            let (size, scale) = human_size(e.size);

            if scale != 0 {
                sprintf_num(&mut b, size, b' ', 6);
                b.push(scale);
            } else {
                b.push(b' ');
                sprintf_num(&mut b, size, b' ', 6);
            }
        }

        b.extend_from_slice(b"\r\n");
    }

    b.extend_from_slice(b"</pre><hr>");

    b.extend_from_slice(TAIL);

    b
}

/// The size and scale letter ("autoindex_exact_size off"), 0 for no scale
fn human_size(length: i64) -> (i64, u8) {
    const G: i64 = 1024 * 1024 * 1024;
    const M: i64 = 1024 * 1024;

    if length > G - 1 {
        let mut size = length / G;
        if length % G > G / 2 - 1 {
            size += 1;
        }
        (size, b'G')
    } else if length > M - 1 {
        let mut size = length / M;
        if length % M > M / 2 - 1 {
            size += 1;
        }
        (size, b'M')
    } else if length > 9999 {
        let mut size = length / 1024;
        if length % 1024 > 511 {
            size += 1;
        }
        (size, b'K')
    } else {
        (length, 0)
    }
}

fn entry_type(e: &Entry) -> &'static [u8] {
    if e.dir {
        b"directory"
    } else if e.file {
        b"file"
    } else {
        b"other"
    }
}

/// ngx_http_autoindex_json
fn autoindex_json(entries: &mut [Entry], callback: Option<&[u8]>) -> Vec<u8> {
    let mut len = "[\r\n\r\n]".len();

    if let Some(callback) = callback {
        len += "/* callback */\r\n();".len() + callback.len();
    }

    for e in entries.iter_mut() {
        e.escape = escape_json_len(&e.name);

        len += e.name.len() + e.escape + 128;
    }

    let mut b = Vec::with_capacity(len);

    if let Some(callback) = callback {
        b.extend_from_slice(b"/* callback */\r\n");

        b.extend_from_slice(callback);

        b.push(b'(');
    }

    b.push(b'[');

    for e in entries.iter() {
        b.extend_from_slice(b"\r\n{ \"name\":\"");

        if e.escape != 0 {
            escape_json_into(&mut b, &e.name);
        } else {
            b.extend_from_slice(&e.name);
        }

        b.extend_from_slice(b"\", \"type\":\"");

        b.extend_from_slice(entry_type(e));

        b.extend_from_slice(b"\", \"mtime\":\"");

        b.extend_from_slice(http_time(e.mtime).as_bytes());

        if e.file {
            b.extend_from_slice(b"\", \"size\":");
            sprintf_num(&mut b, e.size, b' ', 0);
        } else {
            b.push(b'"');
        }

        b.extend_from_slice(b" },");
    }

    if !entries.is_empty() {
        b.pop(); /* strip last comma */
    }

    b.extend_from_slice(b"\r\n]");

    if callback.is_some() {
        b.push(b')');
        b.push(b';');
    }

    b
}

/// ngx_http_autoindex_jsonp_callback: Some(callback), empty when there is
/// no "callback" argument, or None for an invalid one (400)
fn autoindex_jsonp_callback(r: &R) -> Option<Vec<u8>> {
    let callback = {
        let args = r.args.borrow();
        match crate::parse::arg(&args, b"callback") {
            Some(callback) => callback.to_vec(),
            None => return Some(Vec::new()),
        }
    };

    match check_jsonp_callback(&callback) {
        Ok(()) => Some(callback),
        Err(e) => {
            ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "client sent {} callback name: \"{}\"", e, B(&callback));
            None
        }
    }
}

/// The callback name checks: Err("too long") or Err("invalid")
fn check_jsonp_callback(callback: &[u8]) -> Result<(), &'static str> {
    if callback.len() > 128 {
        return Err("too long");
    }

    for &ch in callback {
        let c = ch | 0x20;
        if c.is_ascii_lowercase() {
            continue;
        }

        if ch.is_ascii_digit() || ch == b'_' || ch == b'.' {
            continue;
        }

        return Err("invalid");
    }

    Ok(())
}

/// ngx_http_autoindex_xml
fn autoindex_xml(entries: &mut [Entry]) -> Vec<u8> {
    const HEAD: &[u8] = b"<?xml version=\"1.0\"?>\r\n<list>\r\n";
    const TAIL: &[u8] = b"</list>\r\n";

    let mut len = HEAD.len() + TAIL.len();

    for e in entries.iter_mut() {
        e.escape = escape_html_len(&e.name);

        len += e.name.len() + e.escape + 96;
    }

    let mut b = Vec::with_capacity(len);

    b.extend_from_slice(HEAD);

    for e in entries.iter() {
        b.push(b'<');

        let ty = entry_type(e);

        b.extend_from_slice(ty);

        b.extend_from_slice(b" mtime=\"");

        let tm = gmtime(e.mtime);

        sprintf_num(&mut b, tm.year as i64, b' ', 4);
        b.push(b'-');
        sprintf_num(&mut b, tm.mon as i64, b'0', 2);
        b.push(b'-');
        sprintf_num(&mut b, tm.mday as i64, b'0', 2);
        b.push(b'T');
        sprintf_num(&mut b, tm.hour as i64, b'0', 2);
        b.push(b':');
        sprintf_num(&mut b, tm.min as i64, b'0', 2);
        b.push(b':');
        sprintf_num(&mut b, tm.sec as i64, b'0', 2);
        b.push(b'Z');

        if e.file {
            b.extend_from_slice(b"\" size=\"");
            sprintf_num(&mut b, e.size, b' ', 0);
        }

        b.push(b'"');
        b.push(b'>');

        if e.escape != 0 {
            escape_html_into(&mut b, &e.name);
        } else {
            b.extend_from_slice(&e.name);
        }

        b.push(b'<');
        b.push(b'/');

        b.extend_from_slice(ty);

        b.push(b'>');

        b.extend_from_slice(b"\r\n");
    }

    b.extend_from_slice(TAIL);

    b
}

/// ngx_http_autoindex_cmp_entries: directories first, then ngx_strcmp()
fn autoindex_cmp_entries(first: &Entry, second: &Entry) -> Ordering {
    if first.dir && !second.dir {
        /* move the directories to the start */
        return Ordering::Less;
    }

    if !first.dir && second.dir {
        /* move the directories to the start */
        return Ordering::Greater;
    }

    first.name.cmp(&second.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &[u8], dir: bool, file: bool, mtime: i64, size: i64) -> Entry {
        Entry { name: name.to_vec(), utf_len: 0, escape: 0, escape_html: 0, dir, file, mtime, size }
    }

    /// The entry lines of an html listing of "/d/"
    fn html_lines(entries: &mut [Entry], utf8: bool, exact_size: bool) -> Vec<Vec<u8>> {
        let out = autoindex_html(b"/d/", entries, utf8, 0, exact_size);
        let mut lines: Vec<Vec<u8>> = out.split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec()).collect();
        lines.retain(|l| l.starts_with(b"<a href=\"") && !l.starts_with(b"<a href=\"../"));
        lines
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn html_layout() {
        let mut e = vec![entry(b"dir", true, false, 0, 4096), entry(b"a<b", false, true, 86400 * 365, 12345)];
        let out = autoindex_html(b"/x&y/", &mut e, false, 0, true);
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("<html>\r\n<head><title>Index of /x&amp;y/</title></head>\r\n<body>\r\n<h1>Index of /x&amp;y/</h1><hr><pre><a href=\"../\">../</a>\r\n"));
        assert!(s.ends_with("</pre><hr></body>\r\n</html>\r\n"));
        let lines: Vec<&str> = s.split("\r\n").collect();
        assert_eq!(lines[4], format!("<a href=\"dir/\">dir/</a>{} 01-Jan-1970 00:00 {}-", " ".repeat(46), " ".repeat(18)));
        assert_eq!(lines[5], format!("<a href=\"a%3Cb\">a&lt;b</a>{} 01-Jan-1971 00:00 {}12345", " ".repeat(47), " ".repeat(14)));

        // autoindex_localtime: the offset is added to the mtime
        let mut e = vec![entry(b"f", false, true, 0, 1)];
        let out = autoindex_html(b"/", &mut e, false, 3 * 3600 + 25 * 60, true);
        assert!(contains(&out, b" 01-Jan-1970 03:25 "));
    }

    #[test]
    fn html_long_names() {
        let long = [b"test-long-".to_vec(), vec![b'0'; 50]].concat();
        let long_esc = [b"test-long-".to_vec(), vec![b'>'; 50]].concat();
        let exact = [b"x".to_vec(), vec![b'y'; 49]].concat();
        let mut e = vec![entry(&long, false, true, 0, 0), entry(&long_esc, false, true, 0, 0), entry(&exact, true, false, 0, 0)];
        let lines = html_lines(&mut e, false, true);
        assert!(contains(&lines[0], format!(">test-long-{}..&gt;</a> 01-Jan", "0".repeat(37)).as_bytes()));
        assert!(contains(&lines[1], format!(">test-long-{}..&gt;</a> 01-Jan", "&gt;".repeat(37)).as_bytes()));
        // exactly 50 characters: no room for the directory slash, no padding
        assert!(contains(&lines[2], format!("<a href=\"x{0}/\">x{0}</a> 01-Jan", "y".repeat(49)).as_bytes()));
    }

    #[test]
    fn html_utf8_names() {
        let f = "\u{444}";
        let short = format!("test-utf8-{}", f.repeat(3));
        let long = format!("test-utf8-{}", f.repeat(45));
        let long_esc = format!("test-utf8-<>&-{}", f.repeat(45));
        let mut e = vec![entry(short.as_bytes(), false, true, 0, 0), entry(long.as_bytes(), false, true, 0, 0), entry(long_esc.as_bytes(), false, true, 0, 0)];
        let lines = html_lines(&mut e, true, true);
        assert!(contains(&lines[0], format!(">test-utf8-{}</a>{} 01-Jan", f.repeat(3), " ".repeat(37)).as_bytes()));
        assert!(contains(&lines[1], format!(">test-utf8-{}..&gt;</a> 01-Jan", f.repeat(37)).as_bytes()));
        assert!(contains(&lines[2], format!(">test-utf8-&lt;&gt;&amp;-{}..&gt;</a> 01-Jan", f.repeat(33)).as_bytes()));

        // without the utf-8 charset the name is cut at 47 bytes
        let mut e = vec![entry(long.as_bytes(), false, true, 0, 0)];
        let lines = html_lines(&mut e, false, true);
        let cut = [b">test-utf8-".to_vec(), f.repeat(18).into_bytes(), b"\xd1..&gt;</a> ".to_vec()].concat();
        assert!(contains(&lines[0], &cut));

        // invalid utf-8 is counted in bytes
        let mut e = vec![entry(b"\xff\xffabc", false, true, 0, 0), entry(b"\xd1\x84abc", false, true, 0, 0)];
        let lines = html_lines(&mut e, true, true);
        assert!(contains(&lines[0], [b">\xff\xffabc</a>".to_vec(), vec![b' '; 45], b" 01-Jan".to_vec()].concat().as_slice()));
        assert!(contains(&lines[1], [b">\xd1\x84abc</a>".to_vec(), vec![b' '; 46], b" 01-Jan".to_vec()].concat().as_slice()));
    }

    #[test]
    fn html_sizes() {
        let mut e = vec![
            entry(b"d", true, false, 0, 0),
            entry(b"a", false, true, 0, 9999),
            entry(b"b", false, true, 0, 10000),
            entry(b"c", false, true, 0, 1024 * 1024 - 1),
            entry(b"e", false, true, 0, 1024 * 1024 + 512 * 1024),
            entry(b"f", false, true, 0, 3 * 1024 * 1024 * 1024 - 1),
        ];
        let lines = html_lines(&mut e, false, false);
        let tails: Vec<&[u8]> = lines.iter().map(|l| &l[l.len() - 8..]).collect();
        let expected: Vec<&[u8]> = vec![b"       -", b"    9999", b"     10K", b"   1024K", b"      2M", b"      3G"];
        assert_eq!(tails, expected);
        assert_eq!(human_size(1024 * 1024 + 512 * 1024 - 1), (1, b'M'));
        assert_eq!(human_size(10240 + 511), (10, b'K'));
        assert_eq!(human_size(10240 + 512), (11, b'K'));
    }

    #[test]
    fn json_output() {
        let mut e = vec![entry(b"d\"x", true, false, 0, 0), entry(b"f", false, true, 784111777, 42), entry(b"l", false, false, 0, 7)];
        let out = autoindex_json(&mut e, None);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "[\r\n{ \"name\":\"d\\\"x\", \"type\":\"directory\", \"mtime\":\"Thu, 01 Jan 1970 00:00:00 GMT\" },\
             \r\n{ \"name\":\"f\", \"type\":\"file\", \"mtime\":\"Sun, 06 Nov 1994 08:49:37 GMT\", \"size\":42 },\
             \r\n{ \"name\":\"l\", \"type\":\"other\", \"mtime\":\"Thu, 01 Jan 1970 00:00:00 GMT\" }\r\n]"
        );
        assert_eq!(autoindex_json(&mut [], None), b"[\r\n]");
        assert_eq!(autoindex_json(&mut [], Some(b"foo")), b"/* callback */\r\nfoo([\r\n]);");
    }

    #[test]
    fn xml_output() {
        let mut e = vec![entry(b"d", true, false, 0, 0), entry(b"a<\"'", false, true, 784111777, 42), entry(b"s", false, false, 0, 3)];
        let out = autoindex_xml(&mut e);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "<?xml version=\"1.0\"?>\r\n<list>\r\n<directory mtime=\"1970-01-01T00:00:00Z\">d</directory>\r\n\
             <file mtime=\"1994-11-06T08:49:37Z\" size=\"42\">a&lt;&quot;'</file>\r\n\
             <other mtime=\"1970-01-01T00:00:00Z\">s</other>\r\n</list>\r\n"
        );
    }

    #[test]
    fn jsonp_callback_names() {
        assert_eq!(check_jsonp_callback(b"foo.bar_1"), Ok(()));
        assert_eq!(check_jsonp_callback(b""), Ok(()));
        assert_eq!(check_jsonp_callback(b"a-b"), Err("invalid"));
        assert_eq!(check_jsonp_callback(b"a%28"), Err("invalid"));
        assert_eq!(check_jsonp_callback(b"\xc1"), Err("invalid"));
        assert_eq!(check_jsonp_callback(&[b'a'; 128]), Ok(()));
        assert_eq!(check_jsonp_callback(&[b'a'; 129]), Err("too long"));
    }

    #[test]
    fn sort_order() {
        let mut e = vec![entry(b"b", false, true, 0, 0), entry(b"z", true, false, 0, 0), entry(b"\xd1\x84", false, true, 0, 0), entry(b"B", false, true, 0, 0), entry(b"a", true, false, 0, 0)];
        e.sort_by(autoindex_cmp_entries);
        let names: Vec<&[u8]> = e.iter().map(|e| e.name.as_slice()).collect();
        assert_eq!(names, vec![&b"a"[..], b"z", b"B", b"b", b"\xd1\x84"]);
    }

    #[test]
    fn numbers() {
        let mut b = Vec::new();
        sprintf_num(&mut b, 7, b'0', 2);
        sprintf_num(&mut b, 123, b'0', 2);
        sprintf_num(&mut b, -5, b' ', 3);
        assert_eq!(b, b"07123-  5");
        assert_eq!(escape_html_len(b"<a&\"'>"), 3 + 4 + 5 + 3);
        assert_eq!(escape_json_len(b"a\"\\\n\x01"), 1 + 1 + 1 + 5);
    }
}
