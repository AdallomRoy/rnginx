//! ngx_http_autoindex_module: HTML directory listing when the request URI
//! resolves to a directory. Renders the same format ngx_http_autoindex_html
//! does (roughly): `<h1>Index of /uri/</h1><hr><pre><a>../</a>...</pre>`.
//! Filenames are HTML-escaped for display and percent-escaped in the href.
//! Long names are truncated at 50 display columns with `..&gt;`.

use std::any::Any;
use std::os::unix::ffi::OsStrExt;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::*;

crate::http_module_index!("ngx_http_autoindex_module");

pub struct AutoIndexConf {
    pub enable: Val<bool>,
    pub localtime: Val<bool>,
    pub exact_size: Val<bool>,
    pub format: Val<u32>, // 0=html, 1=xml, 2=json, 3=jsonp (only html implemented)
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AutoIndexConf {
        enable: Val::unset(),
        localtime: Val::unset(),
        exact_size: Val::unset(),
        format: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AutoIndexConf>(prev).borrow();
    let mut c = conf_cell::<AutoIndexConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    c.localtime.merge(&p.localtime, false);
    c.exact_size.merge(&p.exact_size, true);
    c.format.merge(&p.format, 0);
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
        ngx_core::cmd!("autoindex_localtime", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, AutoIndexConf, localtime, set_flag),
        ngx_core::cmd!("autoindex_exact_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, AutoIndexConf, exact_size, set_flag),
        ngx_core::cmd_fn!("autoindex_format", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, autoindex_format_handler),
    ];
    http_module_def("ngx_http_autoindex_module", def, commands)
}

fn autoindex_format_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AutoIndexConf>(conf.as_ref().unwrap());
    let v = &cf.args[1];
    let format = match v.as_slice() {
        b"html" => 0,
        b"xml"  => 1,
        b"json" => 2,
        b"jsonp" => 3,
        _ => return Err(cf.emerg(format_args!("invalid parameter \"{}\"", ngx_core::string::B(v)))),
    };
    cell.borrow_mut().format = Val::set(format);
    Ok(())
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(autoindex_handler(r))));
    Ok(())
}

async fn autoindex_handler(r: R) -> i64 {
    // Only fire on directory requests: URI must end with `/`.
    {
        let uri = r.uri.borrow();
        if uri.is_empty() || uri[uri.len() - 1] != b'/' {
            return NGX_DECLINED;
        }
    }
    if !(r.method.get() == NGX_HTTP_GET || r.method.get() == NGX_HTTP_HEAD) {
        return NGX_DECLINED;
    }
    let conf = r.loc_conf::<AutoIndexConf>(ctx_index());
    if !*conf.borrow().enable { return NGX_DECLINED; }

    let (path, _root) = match crate::core_rt::map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // Read directory entries.
    let os_path = std::ffi::OsStr::from_bytes(&path);
    let read = match std::fs::read_dir(os_path) {
        Ok(rd) => rd,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => return NGX_HTTP_NOT_FOUND,
                std::io::ErrorKind::PermissionDenied => return NGX_HTTP_FORBIDDEN,
                _ => return NGX_HTTP_INTERNAL_SERVER_ERROR,
            }
        }
    };

    let mut entries: Vec<Entry> = Vec::new();
    for de in read.flatten() {
        let name = de.file_name();
        let name_bytes = name.as_bytes().to_vec();
        let is_dir = de.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let is_dir_effective = if is_dir { true } else {
            // Follow symlinks so `symlink to directory` displays correctly.
            std::fs::metadata(de.path()).map(|m| m.is_dir()).unwrap_or(false)
        };
        let (size, mtime) = match std::fs::metadata(de.path()) {
            Ok(m) => (m.len(), file_mtime(&m)),
            Err(_) => (0, 0),
        };
        entries.push(Entry { name: name_bytes, is_dir: is_dir_effective, size, mtime });
    }

    // Sort: directories first, then by name (C uses locale-independent lex sort).
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries.sort_by_key(|e| !e.is_dir);

    // Render HTML.
    let uri = r.uri.borrow().clone();
    let title = html_escape(&uri);
    let mut body = Vec::with_capacity(1024 + entries.len() * 128);
    body.extend_from_slice(b"<html>\n<head><title>Index of ");
    body.extend_from_slice(&title);
    body.extend_from_slice(b"</title></head>\n<body>\n<h1>Index of ");
    body.extend_from_slice(&title);
    body.extend_from_slice(b"</h1><hr><pre><a href=\"../\">../</a>\n");

    let localtime = *conf.borrow().localtime;
    let exact = *conf.borrow().exact_size;

    for e in &entries {
        let mut href = percent_escape_uri(&e.name);
        let mut display = html_escape(&e.name);
        if e.is_dir { href.push(b'/'); display.push(b'/'); }

        // Column layout: name link (padded to 50 chars), space, mtime (formatted),
        // space, size (or "-" for directory).
        let (short_display, dots_needed, cols_used) = truncate_display_to(&display, 50);
        body.extend_from_slice(b"<a href=\"");
        body.extend_from_slice(&href);
        body.extend_from_slice(b"\">");
        body.extend_from_slice(&short_display);
        if dots_needed { body.extend_from_slice(b"..&gt;"); }
        body.extend_from_slice(b"</a>");
        // Pad to column 51
        let pad = if dots_needed { 51usize.saturating_sub(cols_used + 3) }
                  else { 51usize.saturating_sub(cols_used) };
        for _ in 0..pad { body.push(b' '); }
        // Date
        body.extend_from_slice(&format_time(e.mtime, localtime));
        body.push(b' ');
        if e.is_dir {
            body.extend_from_slice(b"                  -");
        } else if exact {
            let s = format!("{:>19}", e.size);
            body.extend_from_slice(s.as_bytes());
        } else {
            body.extend_from_slice(&format_human_size(e.size));
        }
        body.push(b'\n');
    }
    body.extend_from_slice(b"</pre><hr></body>\n</html>\n");

    // Discard body then send response.
    let rc = crate::request_body::discard_request_body(&r).await;
    if rc != NGX_OK { return rc; }

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.content_length_n = body.len() as i64;
        ho.content_type_len = "text/html".len();
        ho.content_type = b"text/html".to_vec();
    }
    let rc = crate::core_rt::send_header(&r).await;
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() { return rc; }

    use ngx_core::buf::{Buf, Chain};
    let mut b = Buf::from_vec(body);
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    let mut chain = Chain::new();
    chain.push_back(b);
    crate::core_rt::output_filter(&r, chain).await
}

struct Entry {
    name: Vec<u8>,
    is_dir: bool,
    size: u64,
    mtime: i64,
}

fn file_mtime(m: &std::fs::Metadata) -> i64 {
    use std::time::UNIX_EPOCH;
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// HTML-escape < > & (no need to escape " because href uses percent-escapes).
fn html_escape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        match b {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            _ => out.push(b),
        }
    }
    out
}

/// Percent-escape all bytes that aren't in the "safe URI path char" set
/// (alnum, `-_.~/`). Matches ngx_escape_uri(NGX_ESCAPE_HTML) roughly.
fn percent_escape_uri(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        let safe = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/');
        if safe {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{:02x}", b).as_bytes());
        }
    }
    out
}

/// Truncate the (already HTML-escaped) display name so it fits in `cols`
/// display columns. Returns (truncated_bytes, needs_dots, display_cols_used).
/// Counts entity escapes as their display width (1 column) and UTF-8
/// multi-byte sequences as 1 column each.
fn truncate_display_to(s: &[u8], cols: usize) -> (Vec<u8>, bool, usize) {
    let mut out = Vec::with_capacity(s.len());
    let mut used = 0usize;
    let mut i = 0;
    while i < s.len() {
        // If we've already used `cols - 3` columns and there's more, need `..>`.
        if used > cols.saturating_sub(3) && i < s.len() {
            // Check if remaining fits.
            let rest_cols = count_display_cols(&s[i..]);
            if rest_cols > 0 {
                // Only trigger if there IS more content past cols-3.
            }
        }
        let b = s[i];
        let (adv_bytes, adv_cols) = if b == b'&' {
            // find ';' to consume the entity
            let end = s[i..].iter().position(|&c| c == b';').map(|p| i + p + 1).unwrap_or(i + 1);
            (end - i, 1usize)
        } else if b < 0x80 {
            (1, 1)
        } else {
            // UTF-8 leading byte
            let n = if b >= 0xF0 { 4 } else if b >= 0xE0 { 3 } else if b >= 0xC0 { 2 } else { 1 };
            (n.min(s.len() - i), 1usize)
        };
        if used + adv_cols > cols - 3 && count_display_cols(&s[i..]) > 3 {
            return (out, true, used);
        }
        out.extend_from_slice(&s[i..i + adv_bytes]);
        used += adv_cols;
        i += adv_bytes;
        if used >= cols { break; }
    }
    (out, false, used)
}

fn count_display_cols(s: &[u8]) -> usize {
    let mut cols = 0usize;
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b == b'&' {
            let end = s[i..].iter().position(|&c| c == b';').map(|p| i + p + 1).unwrap_or(i + 1);
            i = end;
        } else if b < 0x80 {
            i += 1;
        } else {
            let n = if b >= 0xF0 { 4 } else if b >= 0xE0 { 3 } else if b >= 0xC0 { 2 } else { 1 };
            i += n.min(s.len() - i);
        }
        cols += 1;
    }
    cols
}

fn format_time(t: i64, localtime: bool) -> Vec<u8> {
    if t == 0 { return b"                  -".to_vec(); } // 19 chars, no time
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let tt: libc::time_t = t as libc::time_t;
    unsafe {
        if localtime { libc::localtime_r(&tt, &mut tm); }
        else { libc::gmtime_r(&tt, &mut tm); }
    }
    let months = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
                  b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];
    let mon = months.get(tm.tm_mon as usize).copied().unwrap_or(b"???");
    format!("{:02}-{}-{} {:02}:{:02}",
        tm.tm_mday,
        std::str::from_utf8(mon).unwrap(),
        tm.tm_year + 1900,
        tm.tm_hour,
        tm.tm_min).into_bytes()
}

fn format_human_size(size: u64) -> Vec<u8> {
    // Matches ngx_http_autoindex.c's readable-size formatting.
    if size < 1024 {
        format!("{:>19}", size).into_bytes()
    } else if size < 1024 * 1024 {
        let n = (size + 512) / 1024;
        format!("{:>18}K", n).into_bytes()
    } else if size < 1024 * 1024 * 1024 {
        let mb = size as f64 / (1024.0 * 1024.0);
        format!("{:>17.1}M", mb).into_bytes()
    } else {
        let gb = size as f64 / (1024.0 * 1024.0 * 1024.0);
        format!("{:>17.1}G", gb).into_bytes()
    }
}
