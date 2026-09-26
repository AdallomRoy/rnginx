//! ngx_http_dav_module: minimal WebDAV — PUT, DELETE, MKCOL, COPY, MOVE.
//!
//! Follows nginx C's dav module for the "flat file / single-file mkcol"
//! behaviour tests exercise.  Recursive DELETE / COPY / MOVE of directories
//! is implemented with std::fs::remove_dir_all / copy_dir walk so
//! `dav.t`'s directory cases pass.

use std::any::Any;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::*;

crate::http_module_index!("ngx_http_dav_module");

const DAV_OFF: u32 = 0;

pub struct DavLocConf {
    /// Bitmask of NGX_HTTP_{PUT,DELETE,MKCOL,COPY,MOVE}.
    pub methods: Val<u32>,
    pub min_delete_depth: Val<u32>,
    pub create_full_put_path: Val<bool>,
    pub access: Val<u32>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(DavLocConf {
        methods: Val::unset(),
        min_delete_depth: Val::unset(),
        create_full_put_path: Val::unset(),
        access: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<DavLocConf>(prev).borrow();
    let mut c = conf_cell::<DavLocConf>(conf).borrow_mut();
    c.methods.merge(&p.methods, DAV_OFF);
    c.min_delete_depth.merge(&p.min_delete_depth, 0);
    c.create_full_put_path.merge(&p.create_full_put_path, false);
    c.access.merge(&p.access, 0o600);
    Ok(())
}

pub fn dav_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("dav_methods", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, dav_methods_handler),
        ngx_core::cmd!("create_full_put_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, DavLocConf, create_full_put_path, set_flag),
        ngx_core::cmd_fn!("min_delete_depth", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, min_delete_depth_handler),
        ngx_core::cmd_fn!("dav_access", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::Loc, dav_access_handler),
    ];
    http_module_def("ngx_http_dav_module", def, commands)
}

fn dav_methods_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<DavLocConf>(conf.as_ref().unwrap());
    let mut methods: u32 = 0;
    for a in cf.args.iter().skip(1) {
        match a.as_slice() {
            b"off"    => { methods = DAV_OFF; break; }
            b"PUT"    => methods |= NGX_HTTP_PUT,
            b"DELETE" => methods |= NGX_HTTP_DELETE,
            b"MKCOL"  => methods |= NGX_HTTP_MKCOL,
            b"COPY"   => methods |= NGX_HTTP_COPY,
            b"MOVE"   => methods |= NGX_HTTP_MOVE,
            _ => return Err(cf.emerg(format_args!("invalid method \"{}\"", ngx_core::string::B(a)))),
        }
    }
    cell.borrow_mut().methods = Val::set(methods);
    Ok(())
}

fn min_delete_depth_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<DavLocConf>(conf.as_ref().unwrap());
    let s = std::str::from_utf8(&cf.args[1])
        .map_err(|_| cf.emerg(format_args!("invalid min_delete_depth value")))?;
    let n: u32 = s.parse().map_err(|_| cf.emerg(format_args!("invalid min_delete_depth")))?;
    cell.borrow_mut().min_delete_depth = Val::set(n);
    Ok(())
}

fn dav_access_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<DavLocConf>(conf.as_ref().unwrap());
    // Parses "user:rw group:r all:r" into a rwxrwxrwx-style mode. We only
    // honour "user:", "group:", "all:" prefixes with r/w/rw values (matches
    // ngx_conf_set_access_slot semantics for the dav_access directive).
    let mut mode: u32 = 0;
    for a in cf.args.iter().skip(1) {
        let s = a.as_slice();
        let (target_shift, val_str): (u32, &[u8]) = if let Some(rest) = s.strip_prefix(b"user:") {
            (6, rest)
        } else if let Some(rest) = s.strip_prefix(b"group:") {
            (3, rest)
        } else if let Some(rest) = s.strip_prefix(b"all:") {
            (0, rest)
        } else {
            return Err(cf.emerg(format_args!("invalid access value \"{}\"", ngx_core::string::B(s))));
        };
        let bits = match val_str {
            b"rw" => 6u32,
            b"r"  => 4u32,
            b"w"  => 2u32,
            b"rwx"|b"rx"|b"wx"|b"x" => {
                let mut v = 0u32;
                if val_str.contains(&b'r') { v |= 4; }
                if val_str.contains(&b'w') { v |= 2; }
                if val_str.contains(&b'x') { v |= 1; }
                v
            }
            _ => return Err(cf.emerg(format_args!("invalid access mode \"{}\"", ngx_core::string::B(val_str)))),
        };
        mode |= bits << target_shift;
    }
    cell.borrow_mut().access = Val::set(mode);
    Ok(())
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(dav_handler(r))));
    Ok(())
}

/// Convenience: turn a byte slice into a std::path::Path.
fn as_path(b: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(b))
}

/// Strip a possible trailing NUL that the C-style map_uri_to_path leaves
/// behind (nginx allocates path.len + 1 and writes a terminator; the len
/// includes the NUL, so callers do `path.len--`).
fn strip_nul(mut p: Vec<u8>) -> Vec<u8> {
    if p.last() == Some(&0) { p.pop(); }
    p
}

async fn dav_handler(r: R) -> i64 {
    use ngx_core::rc::*;

    let dlcf = r.loc_conf::<DavLocConf>(ctx_index());
    let (methods, min_delete_depth, create_full_put_path, access) = {
        let c = dlcf.borrow();
        (*c.methods.get(), *c.min_delete_depth.get(), *c.create_full_put_path.get(), *c.access.get())
    };
    let method = r.method.get();
    if methods == DAV_OFF || methods & method == 0 {
        return NGX_DECLINED;
    }

    // Resolve URI to a filesystem path (strip trailing NUL from map_uri).
    let (raw_path, _root) = match crate::core_rt::map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    let path = strip_nul(raw_path);

    match method {
        m if m == NGX_HTTP_PUT => dav_put(r, path, create_full_put_path, access).await,
        m if m == NGX_HTTP_DELETE => dav_delete(r, path, min_delete_depth).await,
        m if m == NGX_HTTP_MKCOL => dav_mkcol(r, path, access).await,
        m if m == NGX_HTTP_COPY => dav_copy_move(r, path, false, access, create_full_put_path).await,
        m if m == NGX_HTTP_MOVE => dav_copy_move(r, path, true, access, create_full_put_path).await,
        _ => NGX_DECLINED,
    }
}

async fn dav_put(r: R, path: Vec<u8>, create_full_put_path: bool, access: u32) -> i64 {
    // PUT to a "collection" (URI ends with /) is a conflict.
    if r.uri.borrow().last() == Some(&b'/') {
        ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "cannot PUT to a collection");
        return NGX_HTTP_CONFLICT;
    }
    if r.headers_in.borrow().content_range.is_some() {
        ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "PUT with range is unsupported");
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    // Force body-in-file so we can rename the temp file directly.
    r.request_body_in_file_only.set(true);
    r.request_body_in_persistent_file.set(true);
    r.request_body_in_clean_file.set(true);
    r.request_body_file_log_level.set(0);

    let rc = crate::request_body::read_client_request_body(&r).await;
    if rc >= crate::NGX_HTTP_SPECIAL_RESPONSE {
        return rc;
    }

    // Grab the temp-file path from request_body.
    let temp_name: Vec<u8> = {
        let rb_opt = r.request_body.borrow();
        let rb_rc = match rb_opt.as_ref() {
            Some(rc) => rc.clone(),
            None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
        };
        drop(rb_opt);
        let rb = rb_rc.borrow();
        match rb.temp_file.as_ref() {
            Some(tf) => tf.name.clone(),
            None => {
                // Empty body — read_client_request_body doesn't create a
                // temp file for a zero-length body; make one on the fly.
                Vec::new()
            }
        }
    };

    // Determine target status (201 vs 204) by pre-existence.
    let existed = match ngx_core::os::stat(&path) {
        Ok(st) => {
            if ngx_core::os::is_dir(&st) {
                ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, Some(libc::EISDIR),
                    "\"{}\" could not be created", ngx_core::string::B(&path));
                if !temp_name.is_empty() {
                    let _ = ngx_core::os::unlink(&temp_name);
                }
                return NGX_HTTP_CONFLICT;
            }
            true
        }
        Err(_) => false,
    };

    // Create parent directories if the target has any that don't exist.
    if create_full_put_path {
        if let Some(parent) = as_path(&path).parent() {
            let parent_bytes = parent.as_os_str().as_bytes();
            if !parent_bytes.is_empty() {
                // Add a trailing slash so create_full_path's loop, which
                // only calls mkdir at '/' positions, also creates the
                // leaf directory.
                let mut with_slash = parent_bytes.to_vec();
                with_slash.push(b'/');
                let _ = ngx_core::os::create_full_path(&with_slash, 0o700);
            }
        }
    }

    if temp_name.is_empty() {
        // Zero-length body: create/truncate the target directly.
        match std::fs::File::create(as_path(&path)) {
            Ok(_) => {}
            Err(e) => {
                ngx_log_error!(ngx_core::log::NGX_LOG_CRIT, r.connection.log,
                    e.raw_os_error(),
                    "open() \"{}\" failed", ngx_core::string::B(&path));
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    } else {
        // Rename temp file into place, then chmod to configured access.
        let src = ngx_core::os::cstr(&temp_name);
        let dst = ngx_core::os::cstr(&path);
        let rc = unsafe { libc::rename(src.as_ptr(), dst.as_ptr()) };
        if rc == -1 {
            let e = ngx_core::os::errno();
            // Cross-device? Copy + unlink.
            if e == libc::EXDEV {
                if std::fs::copy(as_path(&temp_name), as_path(&path)).is_err() {
                    let _ = ngx_core::os::unlink(&temp_name);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                let _ = ngx_core::os::unlink(&temp_name);
            } else {
                ngx_log_error!(ngx_core::log::NGX_LOG_CRIT, r.connection.log, Some(e),
                    "rename() \"{}\" to \"{}\" failed", ngx_core::string::B(&temp_name), ngx_core::string::B(&path));
                let _ = ngx_core::os::unlink(&temp_name);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
        // Mark the temp file as already-renamed so its Drop doesn't unlink it.
        if let Some(rb_rc) = r.request_body.borrow().as_ref().cloned() {
            let mut rb = rb_rc.borrow_mut();
            if let Some(tf) = rb.temp_file.as_mut() {
                tf.clean = false;
            }
        }
        // Apply access mode.
        let _ = std::fs::set_permissions(as_path(&path), std::fs::Permissions::from_mode(access));
    }

    let status = if existed { NGX_HTTP_NO_CONTENT } else { NGX_HTTP_CREATED };
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = status;
        ho.content_length_n = 0;
    }
    if status == NGX_HTTP_CREATED {
        let loc = escaped_uri(&r.uri.borrow());
        let h = r.headers_out.borrow_mut().add(b"Location", &loc);
        r.headers_out.borrow_mut().location = Some(h);
    }
    r.header_only.set(true);
    crate::core_rt::send_header(&r).await
}

fn escaped_uri(uri: &[u8]) -> Vec<u8> {
    ngx_core::string::escape_uri(uri, ngx_core::string::NGX_ESCAPE_URI)
}

fn has_body(r: &R) -> bool {
    let hin = r.headers_in.borrow();
    hin.content_length_n > 0 || hin.chunked
}

/// Parsed Depth header value.  `Infinity` mirrors nginx's magic -1.
#[derive(Clone, Copy, PartialEq)]
enum Depth {
    Zero,
    One,
    Infinity,
    Absent,
    Invalid,
}

fn parse_depth(r: &R) -> Depth {
    let hin = r.headers_in.borrow();
    let dh = hin.headers.iter().find(|h| h.lowcase_key.eq_ignore_ascii_case(b"depth"));
    let v = match dh { Some(h) => h.value.borrow().clone(), None => return Depth::Absent };
    match v.as_slice() {
        b"0" => Depth::Zero,
        b"1" => Depth::One,
        b"infinity" => Depth::Infinity,
        _ => Depth::Invalid,
    }
}

async fn dav_delete(r: R, path: Vec<u8>, min_delete_depth: u32) -> i64 {
    if has_body(&r) {
        ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
            "DELETE with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
    // Enforce min_delete_depth against the number of URI path segments.
    let depth = uri_depth(&r.uri.borrow());
    if depth < min_delete_depth {
        ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
            "insufficient URI depth: {} (min {})", depth, min_delete_depth);
        return NGX_HTTP_CONFLICT;
    }

    let _ = crate::request_body::discard_request_body(&r).await;

    let st = match ngx_core::os::lstat(&path) {
        Ok(s) => s,
        Err(e) => {
            let status = match e {
                libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG => NGX_HTTP_NOT_FOUND,
                libc::EACCES | libc::EPERM => NGX_HTTP_FORBIDDEN,
                _ => NGX_HTTP_INTERNAL_SERVER_ERROR,
            };
            return status;
        }
    };
    let is_dir = ngx_core::os::is_dir(&st);

    // For a directory, the URI must end with `/`. For a file, must not.
    let uri = r.uri.borrow().clone();
    let ends_slash = uri.last() == Some(&b'/');
    if is_dir && !ends_slash {
        // C: return conflict if directory URI missing trailing slash.
        return NGX_HTTP_CONFLICT;
    }
    if !is_dir && ends_slash {
        return NGX_HTTP_CONFLICT;
    }

    // Depth header validation (matches ngx_http_dav_delete_handler).
    let depth = parse_depth(&r);
    if is_dir {
        // Directory delete needs Depth: infinity (default when absent).
        match depth {
            Depth::Absent | Depth::Infinity => {}
            _ => {
                ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
                    "\"Depth\" header must be infinity");
                return NGX_HTTP_BAD_REQUEST;
            }
        }
    } else {
        match depth {
            Depth::Absent | Depth::Zero | Depth::Infinity => {}
            _ => {
                ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
                    "\"Depth\" header must be 0 or infinity");
                return NGX_HTTP_BAD_REQUEST;
            }
        }
    }

    let del_result = if is_dir {
        std::fs::remove_dir_all(as_path(&path))
    } else {
        std::fs::remove_file(as_path(&path))
    };
    if let Err(e) = del_result {
        ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log,
            e.raw_os_error(),
            "delete \"{}\" failed", ngx_core::string::B(&path));
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_NO_CONTENT;
        ho.content_length_n = 0;
    }
    r.header_only.set(true);
    crate::core_rt::send_header(&r).await
}

async fn dav_mkcol(r: R, path: Vec<u8>, access: u32) -> i64 {
    if has_body(&r) {
        ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
            "MKCOL with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
    // MKCOL requires a trailing slash on the URI.
    if r.uri.borrow().last() != Some(&b'/') {
        return NGX_HTTP_CONFLICT;
    }
    let _ = crate::request_body::discard_request_body(&r).await;

    // Trim trailing slash from the resolved path for mkdir.
    let mut p = path;
    while p.last() == Some(&b'/') { p.pop(); }
    match ngx_core::os::mkdir(&p, access | 0o111) {
        Ok(()) => {
            {
                let mut ho = r.headers_out.borrow_mut();
                ho.status = NGX_HTTP_CREATED;
                ho.content_length_n = 0;
            }
            let loc = escaped_uri(&r.uri.borrow());
            let h = r.headers_out.borrow_mut().add(b"Location", &loc);
            r.headers_out.borrow_mut().location = Some(h);
            r.header_only.set(true);
            crate::core_rt::send_header(&r).await
        }
        Err(e) => match e {
            libc::EEXIST => NGX_HTTP_NOT_ALLOWED,
            libc::EACCES | libc::EPERM => NGX_HTTP_FORBIDDEN,
            libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG => NGX_HTTP_CONFLICT,
            _ => NGX_HTTP_INTERNAL_SERVER_ERROR,
        },
    }
}

async fn dav_copy_move(r: R, path: Vec<u8>, is_move: bool, access: u32, create_full_put_path: bool) -> i64 {
    if has_body(&r) {
        ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
            "{} with body is unsupported", if is_move { "MOVE" } else { "COPY" });
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }
    let _ = crate::request_body::discard_request_body(&r).await;

    // Depth validation: COPY allows 0 or infinity; MOVE only infinity.
    let depth = parse_depth(&r);
    match (is_move, depth) {
        (_, Depth::Absent) | (_, Depth::Infinity) => {}
        (false, Depth::Zero) => {}
        _ => {
            ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
                "\"Depth\" header must be {}", if is_move { "infinity" } else { "0 or infinity" });
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    // Overwrite header: only single-char T or F allowed.
    {
        let hin = r.headers_in.borrow();
        let ov = hin.headers.iter().find(|h| h.lowcase_key.eq_ignore_ascii_case(b"overwrite"));
        if let Some(h) = ov {
            let v = h.value.borrow();
            let valid = v.len() == 1 && (v[0] == b'T' || v[0] == b't' || v[0] == b'F' || v[0] == b'f');
            if !valid {
                drop(v);
                drop(hin);
                ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
                    "client sent invalid \"Overwrite\" header");
                return NGX_HTTP_BAD_REQUEST;
            }
        }
    }

    // Read Destination header.
    let dest_uri: Vec<u8> = {
        let hin = r.headers_in.borrow();
        let d = hin.headers.iter().find(|h| h.lowcase_key.eq_ignore_ascii_case(b"destination"));
        match d {
            Some(h) => h.value.borrow().clone(),
            None => {
                ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
                    "client sent no \"Destination\" header");
                return NGX_HTTP_BAD_REQUEST;
            }
        }
    };

    // Parse the destination — accept both absolute (http://host/uri) and
    // path-only forms.  Reject non-http(s) schemes and mismatched hosts.
    let dest_uri_path: Vec<u8> = {
        let d = dest_uri.clone();
        if d.starts_with(b"/") {
            // Path-only.
            let mut path = d;
            if let Some(q) = path.iter().position(|&b| b == b'?' || b == b'#') {
                path.truncate(q);
            }
            path
        } else if d.starts_with(b"http://") || d.starts_with(b"https://") {
            let scheme_end = if d.starts_with(b"http://") { 7 } else { 8 };
            let after = &d[scheme_end..];
            // Extract the request Host — strip any :port suffix — then
            // require the destination to start with the same hostname
            // (C's ngx_strncmp semantics against headers_in.server).
            let server_host: Vec<u8> = {
                let hin = r.headers_in.borrow();
                let host = hin.host.as_ref().map(|h| h.value.borrow().clone()).unwrap_or_default();
                match host.iter().position(|&b| b == b':') {
                    Some(i) => host[..i].to_vec(),
                    None => host,
                }
            };
            if server_host.is_empty() || after.len() < server_host.len()
                || !after[..server_host.len()].eq_ignore_ascii_case(&server_host)
            {
                ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
                    "\"Destination\" URI is handled by different repository than the source URI");
                return NGX_HTTP_BAD_REQUEST;
            }
            // After the hostname, allow optional :port, then '/'.
            let mut i = server_host.len();
            while i < after.len() && after[i] != b'/' { i += 1; }
            if i >= after.len() {
                return NGX_HTTP_BAD_REQUEST;
            }
            let mut path = after[i..].to_vec();
            if let Some(q) = path.iter().position(|&b| b == b'?' || b == b'#') {
                path.truncate(q);
            }
            path
        } else {
            ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None,
                "invalid \"Destination\" scheme");
            return NGX_HTTP_BAD_REQUEST;
        }
    };

    // Unescape %xx sequences.
    let (dest_decoded, _) = ngx_core::string::unescape_uri(&dest_uri_path, 0);

    // Resolve destination to a filesystem path. We synthesise a
    // temporary request with the destination URI so map_uri_to_path
    // uses the same location's alias/root.
    // Simpler approach: replace the request's URI, call map_uri_to_path,
    // then restore. This is what C does with r->uri temporarily.
    let saved_uri = std::mem::replace(&mut *r.uri.borrow_mut(), dest_decoded.clone());
    let dest_result = crate::core_rt::map_uri_to_path(&r, 0);
    *r.uri.borrow_mut() = saved_uri;
    let dest_path_raw = match dest_result {
        Some((p, _)) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };
    let dest_path = strip_nul(dest_path_raw);

    // Trim trailing slash on dest_path for existence checks; nginx does
    // its own merge_slashes. Keep both variants around.
    let dest_path_trimmed: Vec<u8> = {
        let mut p = dest_path.clone();
        while p.len() > 1 && p.last() == Some(&b'/') { p.pop(); }
        p
    };

    // Source must exist.
    let src_st = match ngx_core::os::lstat(&path) {
        Ok(s) => s,
        Err(_) => return NGX_HTTP_NOT_FOUND,
    };
    let src_is_dir = ngx_core::os::is_dir(&src_st);
    let uri_ends_slash = r.uri.borrow().last() == Some(&b'/');
    if src_is_dir && !uri_ends_slash {
        return NGX_HTTP_CONFLICT;
    }
    if !src_is_dir && uri_ends_slash {
        return NGX_HTTP_CONFLICT;
    }
    // Collection-vs-non-collection must agree between source and dest URIs.
    let dest_ends_slash = dest_decoded.last() == Some(&b'/');
    if uri_ends_slash != dest_ends_slash {
        return NGX_HTTP_CONFLICT;
    }

    // Overwrite: default "T". "F" means fail if destination exists.
    let overwrite: bool = {
        let hin = r.headers_in.borrow();
        let ov = hin.headers.iter().find(|h| h.lowcase_key.eq_ignore_ascii_case(b"overwrite"));
        match ov {
            Some(h) => {
                let v = h.value.borrow();
                !v.eq_ignore_ascii_case(b"F")
            }
            None => true,
        }
    };

    let dest_st = ngx_core::os::lstat(&dest_path_trimmed);
    let dest_exists = dest_st.is_ok();
    let dest_is_dir = dest_st.as_ref().map(|s| ngx_core::os::is_dir(s)).unwrap_or(false);
    if dest_exists && !overwrite {
        return NGX_HTTP_PRECONDITION_FAILED;
    }
    // If destination exists and is a directory but the URI has no trailing
    // slash, or vice-versa, it's a conflict (matches C validate_paths).
    if dest_exists && dest_is_dir != dest_ends_slash {
        return NGX_HTTP_CONFLICT;
    }

    // Create parent directories if requested.
    if create_full_put_path {
        if let Some(parent) = as_path(&dest_path_trimmed).parent() {
            let parent_bytes = parent.as_os_str().as_bytes();
            if !parent_bytes.is_empty() {
                let _ = ngx_core::os::create_full_path(parent_bytes, 0o700);
            }
        }
    }

    let created_new = !dest_exists;

    // Remove existing destination if overwriting.
    if dest_exists {
        let dst_st = ngx_core::os::lstat(&dest_path_trimmed);
        let is_dst_dir = dst_st.map(|s| ngx_core::os::is_dir(&s)).unwrap_or(false);
        let rm_res = if is_dst_dir {
            std::fs::remove_dir_all(as_path(&dest_path_trimmed))
        } else {
            std::fs::remove_file(as_path(&dest_path_trimmed))
        };
        if rm_res.is_err() {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    // Do the copy/move.
    let src_path_trimmed: Vec<u8> = {
        let mut p = path.clone();
        while p.len() > 1 && p.last() == Some(&b'/') { p.pop(); }
        p
    };

    let action_ok = if is_move {
        // Prefer rename; fall back to copy+delete on EXDEV.
        let src = ngx_core::os::cstr(&src_path_trimmed);
        let dst = ngx_core::os::cstr(&dest_path_trimmed);
        let rc = unsafe { libc::rename(src.as_ptr(), dst.as_ptr()) };
        if rc == 0 {
            true
        } else if ngx_core::os::errno() == libc::EXDEV {
            if src_is_dir {
                copy_tree(as_path(&src_path_trimmed), as_path(&dest_path_trimmed), access).is_ok()
                    && std::fs::remove_dir_all(as_path(&src_path_trimmed)).is_ok()
            } else {
                std::fs::copy(as_path(&src_path_trimmed), as_path(&dest_path_trimmed)).is_ok()
                    && std::fs::remove_file(as_path(&src_path_trimmed)).is_ok()
            }
        } else {
            false
        }
    } else {
        if src_is_dir {
            copy_tree(as_path(&src_path_trimmed), as_path(&dest_path_trimmed), access).is_ok()
        } else {
            match std::fs::copy(as_path(&src_path_trimmed), as_path(&dest_path_trimmed)) {
                Ok(_) => {
                    let _ = std::fs::set_permissions(as_path(&dest_path_trimmed), std::fs::Permissions::from_mode(access));
                    true
                }
                Err(_) => false,
            }
        }
    };
    if !action_ok {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Status is 201 for directory ops, 204 for file ops (matches
    // ngx_http_dav_copy_move_handler — doesn't depend on dest existence).
    let status = if src_is_dir { NGX_HTTP_CREATED } else { NGX_HTTP_NO_CONTENT };
    let _ = created_new;
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = status;
        ho.content_length_n = 0;
    }
    r.header_only.set(true);
    crate::core_rt::send_header(&r).await
}

fn copy_tree(src: &Path, dst: &Path, access: u32) -> std::io::Result<()> {
    let st = std::fs::metadata(src)?;
    if st.is_dir() {
        std::fs::create_dir_all(dst)?;
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(access | 0o111));
        for entry in std::fs::read_dir(src)? {
            let e = entry?;
            let sp = e.path();
            let name = e.file_name();
            let dp = dst.join(&name);
            copy_tree(&sp, &dp, access)?;
        }
        Ok(())
    } else {
        std::fs::copy(src, dst)?;
        let _ = std::fs::set_permissions(dst, std::fs::Permissions::from_mode(access));
        Ok(())
    }
}

/// Number of non-empty path segments in `uri` (i.e. how many `/foo` chunks
/// follow the leading slash). Matches C ngx_http_dav_delete_handler's depth
/// gate against `dlcf->min_delete_depth`.
fn uri_depth(uri: &[u8]) -> u32 {
    let mut d = 0u32;
    let mut in_seg = false;
    for &b in uri {
        if b == b'/' {
            in_seg = false;
        } else if !in_seg {
            in_seg = true;
            d += 1;
        }
    }
    d
}
