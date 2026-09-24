//! ngx_http_autoindex_module: directory listing with HTML/JSON/JSONP/XML formats

use std::any::Any;
use std::cmp::Ordering;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::core_rt::*;
use crate::request_body::*;
use crate::*;

crate::http_module_index!("ngx_http_autoindex_module");

const NGX_HTTP_AUTOINDEX_HTML: u32 = 0;
const NGX_HTTP_AUTOINDEX_JSON: u32 = 1;
const NGX_HTTP_AUTOINDEX_JSONP: u32 = 2;
const NGX_HTTP_AUTOINDEX_XML: u32 = 3;

pub struct AutoindexConf {
    pub enable: Val<bool>,
    pub format: Val<u32>,
    pub localtime: Val<bool>,
    pub exact_size: Val<bool>,
}

struct DirEntry {
    name: Vec<u8>,
    is_dir: bool,
    mtime: i64,
    size: u64,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AutoindexConf {
        enable: Val::unset(),
        format: Val::unset(),
        localtime: Val::unset(),
        exact_size: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AutoindexConf>(prev).borrow();
    let mut c = conf_cell::<AutoindexConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    c.format.merge(&p.format, 0);
    c.localtime.merge(&p.localtime, false);
    c.exact_size.merge(&p.exact_size, true);
    Ok(())
}

pub fn autoindex_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd!("autoindex", F | NGX_CONF_FLAG, ConfLevel::Loc, AutoindexConf, enable, set_flag),
        ngx_core::cmd!(
            "autoindex_format",
            F | NGX_CONF_TAKE1,
            ConfLevel::Loc,
            AutoindexConf,
            format,
            set_enum,
            &[("html", 0), ("json", 1), ("jsonp", 2), ("xml", 3)]
        ),
        ngx_core::cmd!(
            "autoindex_localtime",
            F | NGX_CONF_FLAG,
            ConfLevel::Loc,
            AutoindexConf,
            localtime,
            set_flag
        ),
        ngx_core::cmd!(
            "autoindex_exact_size",
            F | NGX_CONF_FLAG,
            ConfLevel::Loc,
            AutoindexConf,
            exact_size,
            set_flag
        ),
    ];
    http_module_def("ngx_http_autoindex_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_CONTENT_PHASE,
        Rc::new(|r| Box::pin(autoindex_handler(r))),
    );
    Ok(())
}

async fn autoindex_handler(r: R) -> i64 {
    // Directive requires URI to end with /
    {
        let uri = r.uri.borrow();
        if uri.is_empty() || uri[uri.len() - 1] != b'/' {
            return NGX_DECLINED;
        }
    }

    // Only GET/HEAD
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_DECLINED;
    }

    let (enable, format, localtime, exact_size) = {
        let slot = r.loc_conf::<AutoindexConf>(ctx_index());
        let alcf = slot.borrow();
        (*alcf.enable, *alcf.format, *alcf.localtime, *alcf.exact_size)
    };
    if !enable {
        return NGX_DECLINED;
    }

    if discard_request_body(&r).await != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let (path, _root) = match map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // Open directory
    let dir_ptr = unsafe { libc::opendir(path.as_ptr() as *const i8) };
    if dir_ptr.is_null() {
        let errno = unsafe { *libc::__errno_location() };
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(errno), "opendir \"{}\" failed", B(&path));
        return if errno == libc::EACCES {
            NGX_HTTP_FORBIDDEN
        } else {
            NGX_HTTP_NOT_FOUND
        };
    }

    // Collect directory entries
    let mut entries = Vec::new();
    loop {
        let ent = unsafe { libc::readdir(dir_ptr) };
        if ent.is_null() {
            break;
        }
        let ent_ref = unsafe { &*ent };
        let name_ptr = ent_ref.d_name.as_ptr();
        let name_len = unsafe { libc::strlen(name_ptr) };
        let name_slice = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, name_len) };

        // Skip "."
        if name_slice == b"." {
            continue;
        }

        // Stat file to get mtime, size, is_dir
        let full_path = {
            let mut p = path.clone();
            if p[p.len() - 1] != b'/' {
                p.push(b'/');
            }
            p.extend_from_slice(name_slice);
            p.push(0);
            p
        };

        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let stat_rc = unsafe { libc::stat(full_path.as_ptr() as *const i8, &mut stat_buf) };

        let (is_dir, mtime, size) = if stat_rc == 0 {
            let is_dir = (stat_buf.st_mode & libc::S_IFDIR) != 0;
            (is_dir, stat_buf.st_mtime, stat_buf.st_size as u64)
        } else {
            (false, 0, 0)
        };

        entries.push(DirEntry {
            name: name_slice.to_vec(),
            is_dir,
            mtime,
            size,
        });
    }

    unsafe { libc::closedir(dir_ptr) };

    // Sort entries
    entries.sort_by(|a, b| {
        // Directories first, then by name
        match (b.is_dir, a.is_dir) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => a.name.cmp(&b.name),
        }
    });

    // Generate response body
    let body = match format {
        NGX_HTTP_AUTOINDEX_JSON => generate_json(&r, &entries, false, localtime, exact_size),
        NGX_HTTP_AUTOINDEX_JSONP => generate_json(&r, &entries, true, localtime, exact_size),
        NGX_HTTP_AUTOINDEX_XML => generate_xml(&r, &entries, localtime, exact_size),
        _ => generate_html(&r, &entries, localtime, exact_size),
    };

    // Set response headers
    {
        let mut headers_out = r.headers_out.borrow_mut();
        headers_out.status = 200;
        headers_out.content_length_n = body.len() as i64;
        let ct = match format {
            NGX_HTTP_AUTOINDEX_JSON => b"application/json".as_slice(),
            NGX_HTTP_AUTOINDEX_JSONP => b"application/javascript".as_slice(),
            NGX_HTTP_AUTOINDEX_XML => b"application/xml".as_slice(),
            _ => b"text/html".as_slice(),
        };
        headers_out.content_type = ct.to_vec();
    }

    if send_header(&r).await != NGX_OK {
        return NGX_ERROR;
    }

    // Send body
    let mut buf = Buf::from_vec(body);
    buf.last_buf = r.is_main();
    buf.last_in_chain = true;
    let mut chain = Chain::new();
    chain.push_back(buf);

    output_filter(&r, chain).await
}

fn generate_html(r: &R, entries: &[DirEntry], localtime: bool, exact_size: bool) -> Vec<u8> {
    let uri = r.uri.borrow();
    let mut buf = Vec::new();

    buf.extend_from_slice(b"<html>\r\n<head><title>Index of ");
    html_escape(&uri, &mut buf);
    buf.extend_from_slice(b"</title></head>\r\n<body>\r\n<h1>Index of ");
    html_escape(&uri, &mut buf);
    buf.extend_from_slice(b"</h1>\r\n<hr><pre><a href=\"../\">../</a>\r\n");

    for entry in entries {
        buf.extend_from_slice(b"<a href=\"");
        html_escape(&entry.name, &mut buf);
        if entry.is_dir {
            buf.extend_from_slice(b"/");
        }
        buf.extend_from_slice(b"\">");
        html_escape(&entry.name, &mut buf);
        if entry.is_dir {
            buf.extend_from_slice(b"/");
        }
        buf.extend_from_slice(b"</a>");

        // Padding to align
        let name_len = entry.name.len() + if entry.is_dir { 1 } else { 0 };
        let padding = if name_len < 50 { 50 - name_len } else { 1 };
        for _ in 0..padding {
            buf.push(b' ');
        }

        // Date
        let date_str = if localtime {
            format_time(entry.mtime, true)
        } else {
            format_time(entry.mtime, false)
        };
        buf.extend_from_slice(&date_str);
        buf.extend_from_slice(b"                  ");

        // Size
        if entry.is_dir {
            buf.extend_from_slice(b"-");
        } else if exact_size {
            buf.extend_from_slice(format!("{}", entry.size).as_bytes());
        } else {
            let size_str = format_size(entry.size);
            buf.extend_from_slice(&size_str);
        }
        buf.extend_from_slice(b"\r\n");
    }

    buf.extend_from_slice(b"</pre><hr>\r\n</body>\r\n</html>\r\n");
    buf
}

fn generate_json(
    r: &R,
    entries: &[DirEntry],
    jsonp: bool,
    localtime: bool,
    exact_size: bool,
) -> Vec<u8> {
    let _uri = r.uri.borrow();
    let mut buf = Vec::new();

    if jsonp {
        buf.extend_from_slice(b"ngx_index(");
    }

    buf.extend_from_slice(b"[\r\n");

    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            buf.extend_from_slice(b",\r\n");
        }

        buf.extend_from_slice(b"  {\"name\":\"");
        json_escape(&entry.name, &mut buf);
        buf.extend_from_slice(b"\",\"type\":\"");
        if entry.is_dir {
            buf.extend_from_slice(b"directory");
        } else {
            buf.extend_from_slice(b"file");
        }
        buf.extend_from_slice(b"\",\"mtime\":\"");
        let date_str = if localtime {
            format_time(entry.mtime, true)
        } else {
            format_time(entry.mtime, false)
        };
        buf.extend_from_slice(&date_str);
        buf.extend_from_slice(b"\"");

        if !entry.is_dir {
            buf.extend_from_slice(b",\"size\":");
            if exact_size {
                buf.extend_from_slice(format!("{}", entry.size).as_bytes());
            } else {
                buf.push(b'"');
                let size_str = format_size(entry.size);
                buf.extend_from_slice(&size_str);
                buf.push(b'"');
            }
        }

        buf.extend_from_slice(b"}");
    }

    buf.extend_from_slice(b"\r\n]");
    if jsonp {
        buf.extend_from_slice(b");");
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

fn generate_xml(r: &R, entries: &[DirEntry], localtime: bool, exact_size: bool) -> Vec<u8> {
    let _uri = r.uri.borrow();
    let mut buf = Vec::new();

    buf.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n");
    buf.extend_from_slice(b"<list>\r\n");

    for entry in entries {
        buf.extend_from_slice(b"  <entry>\r\n");

        buf.extend_from_slice(b"    <name>");
        xml_escape(&entry.name, &mut buf);
        buf.extend_from_slice(b"</name>\r\n");

        buf.extend_from_slice(b"    <type>");
        if entry.is_dir {
            buf.extend_from_slice(b"directory");
        } else {
            buf.extend_from_slice(b"file");
        }
        buf.extend_from_slice(b"</type>\r\n");

        buf.extend_from_slice(b"    <mtime>");
        let date_str = if localtime {
            format_time(entry.mtime, true)
        } else {
            format_time(entry.mtime, false)
        };
        buf.extend_from_slice(&date_str);
        buf.extend_from_slice(b"</mtime>\r\n");

        if !entry.is_dir {
            buf.extend_from_slice(b"    <size>");
            if exact_size {
                buf.extend_from_slice(format!("{}", entry.size).as_bytes());
            } else {
                let size_str = format_size(entry.size);
                buf.extend_from_slice(&size_str);
            }
            buf.extend_from_slice(b"</size>\r\n");
        }

        buf.extend_from_slice(b"  </entry>\r\n");
    }

    buf.extend_from_slice(b"</list>\r\n");
    buf
}

fn html_escape(s: &[u8], buf: &mut Vec<u8>) {
    for &b in s {
        match b {
            b'<' => buf.extend_from_slice(b"&lt;"),
            b'>' => buf.extend_from_slice(b"&gt;"),
            b'&' => buf.extend_from_slice(b"&amp;"),
            b'"' => buf.extend_from_slice(b"&quot;"),
            b'\'' => buf.extend_from_slice(b"&#39;"),
            _ => buf.push(b),
        }
    }
}

fn json_escape(s: &[u8], buf: &mut Vec<u8>) {
    for &b in s {
        match b {
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            _ => buf.push(b),
        }
    }
}

fn xml_escape(s: &[u8], buf: &mut Vec<u8>) {
    for &b in s {
        match b {
            b'<' => buf.extend_from_slice(b"&lt;"),
            b'>' => buf.extend_from_slice(b"&gt;"),
            b'&' => buf.extend_from_slice(b"&amp;"),
            b'"' => buf.extend_from_slice(b"&quot;"),
            b'\'' => buf.extend_from_slice(b"&apos;"),
            _ => buf.push(b),
        }
    }
}

fn format_time(mtime: i64, localtime: bool) -> Vec<u8> {
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let time_val = unsafe {
        let tv = libc::time_t::from(mtime);
        if localtime {
            libc::localtime(&tv as *const _)
        } else {
            libc::gmtime(&tv as *const _)
        }
    };

    if time_val.is_null() {
        return b"                 ".to_vec();
    }

    let tm = unsafe { *time_val };
    let month_idx = tm.tm_mon as usize % 12;
    let month = months[month_idx];

    format!(
        "{:2}-{}-{:04} {:02}:{:02}:{:02}",
        tm.tm_mday, month, 1900 + tm.tm_year, tm.tm_hour, tm.tm_min, tm.tm_sec
    )
    .into_bytes()
}

fn format_size(size: u64) -> Vec<u8> {
    let units = [("", 1), ("K", 1024), ("M", 1024 * 1024), ("G", 1024 * 1024 * 1024)];
    for (i, (unit, divisor)) in units.iter().enumerate() {
        if size < 1024 * divisor || i == units.len() - 1 {
            return format!("{:>4}{}", size / divisor, unit).into_bytes();
        }
    }
    format!("{:>4}G", size / (1024 * 1024 * 1024)).into_bytes()
}
