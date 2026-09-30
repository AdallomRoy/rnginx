//! ngx_http_dav_module: PUT, DELETE, MKCOL, COPY and MOVE (port of
//! ngx_http_dav_module.c), with the ngx_file.c helpers it uses:
//! ngx_ext_rename_file, ngx_copy_file, ngx_walk_tree, ngx_create_full_path.

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::os::Dir;
use ngx_core::rc::*;
use ngx_core::string::{escape_uri, escape_uri_count, B, NGX_ESCAPE_URI};
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::*;

crate::http_module_index!("ngx_http_dav_module");

const NGX_HTTP_DAV_OFF: u32 = 2;

/// NGX_CONF_BITMASK_SET
const NGX_CONF_BITMASK_SET: u32 = 1;

const NGX_HTTP_DAV_INVALID_DEPTH: i64 = -2;
const NGX_HTTP_DAV_INFINITY_DEPTH: i64 = -1;

pub struct DavLocConf {
    pub methods: u32,
    pub access: Val<u32>,
    pub min_delete_depth: Val<i64>,
    pub create_full_put_path: Val<bool>,
}

/// ngx_http_dav_copy_ctx_t
struct DavCopyCtx {
    path: Vec<u8>,
    len: usize,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(DavLocConf {
        methods: 0,
        access: Val::unset(),
        min_delete_depth: Val::unset(),
        create_full_put_path: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<DavLocConf>(prev).borrow();
    let mut c = conf_cell::<DavLocConf>(conf).borrow_mut();

    // ngx_conf_merge_bitmask_value
    if c.methods == 0 {
        c.methods = if p.methods == 0 { NGX_CONF_BITMASK_SET | NGX_HTTP_DAV_OFF } else { p.methods };
    }

    c.min_delete_depth.merge(&p.min_delete_depth, 0);
    c.access.merge(&p.access, 0o600);
    c.create_full_put_path.merge(&p.create_full_put_path, false);
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
        ngx_core::cmd!("min_delete_depth", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, DavLocConf, min_delete_depth, set_num),
        ngx_core::cmd!("dav_access", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::Loc, DavLocConf, access, set_access),
    ];
    http_module_def("ngx_http_dav_module", def, commands)
}

/// ngx_conf_set_bitmask_slot with ngx_http_dav_methods_mask[]
fn dav_methods_handler(cf: &mut Conf, cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    const METHODS: [(&str, u32); 6] = [
        ("off", NGX_HTTP_DAV_OFF),
        ("put", NGX_HTTP_PUT),
        ("delete", NGX_HTTP_DELETE),
        ("mkcol", NGX_HTTP_MKCOL),
        ("copy", NGX_HTTP_COPY),
        ("move", NGX_HTTP_MOVE),
    ];

    let cell = conf_rc::<DavLocConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();

    set_bitmask(cf, cmd, &mut c.methods, &METHODS)
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(dav_handler(r))));
    Ok(())
}

fn has_body(r: &R) -> bool {
    let hin = r.headers_in.borrow();
    hin.content_length_n > 0 || hin.chunked
}

fn uri_is_collection(r: &R) -> bool {
    r.uri.borrow().last() == Some(&b'/')
}

async fn dav_handler(r: R) -> i64 {
    let dlcf = r.loc_conf::<DavLocConf>(ctx_index());

    let method = r.method.get();

    if method & dlcf.borrow().methods == 0 {
        return NGX_DECLINED;
    }

    match method {
        NGX_HTTP_PUT => {
            if uri_is_collection(&r) {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "cannot PUT to a collection");
                return NGX_HTTP_CONFLICT;
            }

            if r.headers_in.borrow().content_range.is_some() {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "PUT with range is unsupported");
                return NGX_HTTP_NOT_IMPLEMENTED;
            }

            r.request_body_in_file_only.set(true);
            r.request_body_in_persistent_file.set(true);
            r.request_body_in_clean_file.set(true);
            r.request_body_file_group_access.set(true);
            r.request_body_file_log_level.set(0);

            let rc = crate::request_body::read_client_request_body(&r).await;

            if rc != NGX_OK {
                return rc;
            }

            dav_put_handler(&r).await
        }

        NGX_HTTP_DELETE => dav_delete_handler(&r),

        NGX_HTTP_MKCOL => {
            let access = *dlcf.borrow().access;
            dav_mkcol_handler(&r, access)
        }

        NGX_HTTP_COPY | NGX_HTTP_MOVE => dav_copy_move_handler(&r),

        _ => NGX_DECLINED,
    }
}

/// ngx_http_dav_put_handler, the post handler of the request body
async fn dav_put_handler(r: &R) -> i64 {
    let rb = r.request_body.borrow().clone();

    let rb = match rb {
        Some(rb) => rb,
        None => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "PUT request body is unavailable");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    };

    let (temp, fd) = match rb.borrow().temp_file.as_ref() {
        Some(tf) => (tf.name.clone(), tf.fd),
        None => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "PUT request body must be in a file");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    };

    let path = match crate::core_rt::map_uri_to_path(r, 0) {
        Some((path, _root)) => path,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    http_debug!(r, "http put filename: \"{}\"", B(&path));

    let status = match ngx_core::os::stat(&path) {
        Err(_) => NGX_HTTP_CREATED,
        Ok(fi) => {
            if ngx_core::os::is_dir(&fi) {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::EISDIR), "\"{}\" could not be created", B(&path));

                if let Err(err) = ngx_core::os::unlink(&temp) {
                    ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(err), "unlink() \"{}\" failed", B(&temp));
                }

                return NGX_HTTP_CONFLICT;
            }

            NGX_HTTP_NO_CONTENT
        }
    };

    let (access, create_full_put_path) = {
        let dlcf = r.loc_conf::<DavLocConf>(ctx_index());
        let c = dlcf.borrow();
        (*c.access, *c.create_full_put_path)
    };

    let mut ext = ExtRenameFile {
        access,
        path_access: access,
        time: -1,
        fd: -1,
        create_path: create_full_put_path,
        delete_file: true,
        log: &r.connection.log,
    };

    let date = r.headers_in.borrow().date.first().map(|h| h.value());

    if let Some(date) = date {
        if let Some(date) = ngx_core::parse::parse_http_time(&date) {
            ext.time = date;
            ext.fd = fd;
        }
    }

    if ext_rename_file(&temp, &path, &ext) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if status == NGX_HTTP_CREATED {
        dav_location(r);

        r.headers_out.borrow_mut().content_length_n = 0;
    }

    r.headers_out.borrow_mut().status = status;
    r.header_only.set(true);

    crate::core_rt::send_header(r).await
}

fn dav_delete_handler(r: &R) -> i64 {
    if has_body(r) {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "DELETE with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    let min_delete_depth = {
        let dlcf = r.loc_conf::<DavLocConf>(ctx_index());
        let d = *dlcf.borrow().min_delete_depth;
        d
    };

    if min_delete_depth != 0 {
        if let Err(d) = check_delete_depth(&r.uri.borrow(), min_delete_depth) {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "insufficient URI depth:{} to DELETE", d);
            return NGX_HTTP_CONFLICT;
        }
    }

    let path = match crate::core_rt::map_uri_to_path(r, 0) {
        Some((path, _root)) => path,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    http_debug!(r, "http delete filename: \"{}\"", B(&path));

    let fi = match ngx_core::os::lstat(&path) {
        Ok(fi) => fi,
        Err(err) => {
            let rc = if err == libc::ENOTDIR { NGX_HTTP_CONFLICT } else { NGX_HTTP_NOT_FOUND };

            return dav_error(&r.connection.log, err, rc, "lstat()", &path);
        }
    };

    let len;
    let dir;

    if ngx_core::os::is_dir(&fi) {
        if !uri_is_collection(r) {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, Some(libc::EISDIR), "DELETE \"{}\" failed", B(&path));
            return NGX_HTTP_CONFLICT;
        }

        let depth = dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);

        if depth != NGX_HTTP_DAV_INFINITY_DEPTH {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "\"Depth\" header must be infinity");
            return NGX_HTTP_BAD_REQUEST;
        }

        len = path.len().saturating_sub(1); /* omit "/\0" */

        dir = true;
    } else {
        /*
         * we do not need to test (r->uri.data[r->uri.len - 1] == '/')
         * because ngx_link_info("/file/") returned NGX_ENOTDIR above
         */

        let depth = dav_depth(r, 0);

        if depth != 0 && depth != NGX_HTTP_DAV_INFINITY_DEPTH {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "\"Depth\" header must be 0 or infinity");
            return NGX_HTTP_BAD_REQUEST;
        }

        len = path.len();

        dir = false;
    }

    let rc = dav_delete_path(r, &path, len, dir);

    if rc == NGX_OK {
        return NGX_HTTP_NO_CONTENT;
    }

    rc
}

/// The min_delete_depth check: Err(d) with the number of slashes counted
/// when the URI is not deep enough
fn check_delete_depth(uri: &[u8], min_delete_depth: i64) -> Result<(), i64> {
    let mut d = 0i64;
    let mut i = 0;

    while i < uri.len() {
        let ch = uri[i];
        i += 1;

        if ch == b'/' {
            d += 1;

            if d >= min_delete_depth && i < uri.len() {
                return Ok(());
            }
        }
    }

    Err(d)
}

/// ngx_http_dav_delete_path; `path` is the C string and `len` the
/// path.len the tree walk appends the names at
fn dav_delete_path(r: &R, path: &[u8], len: usize, dir: bool) -> i64 {
    let failed;

    if dir {
        let mut tree = TreeCtx::new(TreeOp::Delete, &r.connection.log);

        /* TODO: 207 */

        if walk_tree(&mut tree, path, len) != NGX_OK {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if delete_dir(path).is_ok() {
            return NGX_OK;
        }

        failed = "rmdir()";
    } else {
        if ngx_core::os::unlink(path).is_ok() {
            return NGX_OK;
        }

        failed = "unlink()";
    }

    dav_error(&r.connection.log, ngx_core::os::errno(), NGX_HTTP_NOT_FOUND, failed, path)
}

fn dav_mkcol_handler(r: &R, access: u32) -> i64 {
    if has_body(r) {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "MKCOL with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if !uri_is_collection(r) {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "MKCOL can create a collection only");
        return NGX_HTTP_CONFLICT;
    }

    let mut path = match crate::core_rt::map_uri_to_path(r, 0) {
        Some((path, _root)) => path,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    // *(p - 1) = '\0'
    path.pop();

    http_debug!(r, "http mkcol path: \"{}\"", B(&path));

    if ngx_core::os::mkdir(&path, dir_access(access)).is_ok() {
        dav_location(r);

        return NGX_HTTP_CREATED;
    }

    dav_error(&r.connection.log, ngx_core::os::errno(), NGX_HTTP_CONFLICT, "mkdir()", &path)
}

fn dav_invalid_destination(r: &R, dest: &[u8]) -> i64 {
    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client sent invalid \"Destination\" header: \"{}\"", B(dest));
    NGX_HTTP_BAD_REQUEST
}

fn dav_copy_move_handler(r: &R) -> i64 {
    let log = &r.connection.log;

    if has_body(r) {
        ngx_log_error!(NGX_LOG_ERR, log, None, "COPY and MOVE with body are unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    let dest = r.headers_in.borrow().destination.first().map(|h| h.value());

    let dest = match dest {
        Some(dest) => dest,
        None => {
            ngx_log_error!(NGX_LOG_ERR, log, None, "client sent no \"Destination\" header");
            return NGX_HTTP_BAD_REQUEST;
        }
    };

    // where the destination URI starts in the header value
    let p = if dest.first() == Some(&b'/') {
        0
    } else {
        let server = r.headers_in.borrow().server.clone();
        let len = server.len();

        if len == 0 {
            ngx_log_error!(NGX_LOG_ERR, log, None, "client sent no \"Host\" header");
            return NGX_HTTP_BAD_REQUEST;
        }

        let scheme: &[u8] = if r.connection.ssl.borrow().is_some() { b"https://" } else { b"http://" };

        if !dest.starts_with(scheme) {
            return dav_invalid_destination(r, &dest);
        }

        let host = scheme.len();

        if dest.len() < host + len || dest[host..host + len] != server[..] {
            ngx_log_error!(NGX_LOG_ERR, log, None, "\"Destination\" URI \"{}\" is handled by different repository than the source URI", B(&dest));
            return NGX_HTTP_BAD_REQUEST;
        }

        match memchr::memchr(b'/', &dest[host + len..]) {
            Some(n) => host + len + n,
            None => return dav_invalid_destination(r, &dest),
        }
    };

    let mut duri = dest[p..].to_vec();
    let mut args = Vec::new();

    if crate::parse::parse_unsafe_uri_args(log, &mut duri, &mut args, crate::parse::NGX_HTTP_LOG_UNSAFE) != NGX_OK {
        return dav_invalid_destination(r, &dest);
    }

    let uri = r.uri.borrow().clone();

    if uri_is_collection(r) != (dest.last() == Some(&b'/')) {
        ngx_log_error!(NGX_LOG_ERR, log, None, "both URI \"{}\" and \"Destination\" URI \"{}\" should be either collections or non-collections", B(&uri), B(&dest));
        return NGX_HTTP_CONFLICT;
    }

    let alias = r.clcf().borrow().alias;

    if alias != 0 && alias != usize::MAX && r.valid_location.get() && (alias > duri.len() || alias > uri.len() || duri[..alias] != uri[..alias]) {
        ngx_log_error!(NGX_LOG_ERR, log, None, "\"Destination\" URI \"{}\" must be within location prefix when using \"alias\"", B(&dest));
        return NGX_HTTP_BAD_REQUEST;
    }

    let depth = dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);

    if depth != NGX_HTTP_DAV_INFINITY_DEPTH {
        if r.method.get() == NGX_HTTP_COPY {
            if depth != 0 {
                ngx_log_error!(NGX_LOG_ERR, log, None, "\"Depth\" header must be 0 or infinity");
                return NGX_HTTP_BAD_REQUEST;
            }
        } else {
            ngx_log_error!(NGX_LOG_ERR, log, None, "\"Depth\" header must be infinity");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    let over = r.headers_in.borrow().overwrite.first().map(|h| h.value());

    let mut overwrite = match over {
        Some(over) => match over.as_slice() {
            b"T" | b"t" => true,
            b"F" | b"f" => false,
            _ => {
                ngx_log_error!(NGX_LOG_ERR, log, None, "client sent invalid \"Overwrite\" header: \"{}\"", B(&over));
                return NGX_HTTP_BAD_REQUEST;
            }
        },
        None => true,
    };

    let path = match crate::core_rt::map_uri_to_path(r, 0) {
        Some((path, _root)) => path,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    http_debug!(r, "http copy from: \"{}\"", B(&path));

    // r->uri = duri, restored only when the mapping succeeds, as in C
    *r.uri.borrow_mut() = duri;

    let copy_path = match crate::core_rt::map_uri_to_path(r, 0) {
        Some((path, _root)) => path,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    *r.uri.borrow_mut() = uri.clone();

    let path = dav_merge_slashes(&path);
    let mut copy_path = dav_merge_slashes(&copy_path);

    let slash = copy_path.last() == Some(&b'/');

    if slash {
        copy_path.pop();
    }

    http_debug!(r, "http copy to: \"{}\"", B(&copy_path));

    if dav_validate_paths(r, &path, &copy_path, slash, &dest) != NGX_OK {
        return NGX_HTTP_FORBIDDEN;
    }

    let dir;

    match ngx_core::os::lstat(&copy_path) {
        Err(err) => {
            if err != libc::ENOENT {
                return dav_error(log, err, NGX_HTTP_NOT_FOUND, "lstat()", &copy_path);
            }

            /* destination does not exist */

            overwrite = false;
            dir = false;
        }

        Ok(fi) => {
            /* destination exists */

            if ngx_core::os::is_dir(&fi) && !slash {
                ngx_log_error!(NGX_LOG_ERR, log, None, "\"{}\" could not be {}ed to collection \"{}\"", B(&uri), B(&r.method_name.borrow()), B(&dest));
                return NGX_HTTP_CONFLICT;
            }

            if !overwrite {
                ngx_log_error!(NGX_LOG_ERR, log, Some(libc::EEXIST), "\"{}\" could not be created", B(&copy_path));
                return NGX_HTTP_PRECONDITION_FAILED;
            }

            dir = ngx_core::os::is_dir(&fi);
        }
    }

    let fi = match ngx_core::os::lstat(&path) {
        Ok(fi) => fi,
        Err(err) => return dav_error(log, err, NGX_HTTP_NOT_FOUND, "lstat()", &path),
    };

    if ngx_core::os::is_dir(&fi) {
        if !uri_is_collection(r) {
            ngx_log_error!(NGX_LOG_ERR, log, None, "\"{}\" is collection", B(&uri));
            return NGX_HTTP_BAD_REQUEST;
        }

        if overwrite {
            http_debug!(r, "http delete: \"{}\"", B(&copy_path));

            let rc = dav_delete_path(r, &copy_path, copy_path.len(), dir);

            if rc != NGX_OK {
                return rc;
            }
        }

        let len = path.len().saturating_sub(1); /* omit "/\0" */

        if r.method.get() == NGX_HTTP_MOVE && rename_file(&path, &copy_path).is_ok() {
            return NGX_HTTP_CREATED;
        }

        if ngx_core::os::mkdir(&copy_path, file_access(&fi)).is_err() {
            return dav_error(log, ngx_core::os::errno(), NGX_HTTP_NOT_FOUND, "mkdir()", &copy_path);
        }

        let copy = DavCopyCtx { path: copy_path.clone(), len };

        let mut tree = TreeCtx::new(TreeOp::Copy(&copy), log);

        if walk_tree(&mut tree, &path, len) == NGX_OK {
            if r.method.get() == NGX_HTTP_MOVE {
                let rc = dav_delete_path(r, &path, len, true);

                if rc != NGX_OK {
                    return rc;
                }
            }

            return NGX_HTTP_CREATED;
        }
    } else {
        if r.method.get() == NGX_HTTP_MOVE {
            let access = *r.loc_conf::<DavLocConf>(ctx_index()).borrow().access;

            let ext = ExtRenameFile {
                access: 0,
                path_access: access,
                time: -1,
                fd: -1,
                create_path: true,
                delete_file: false,
                log,
            };

            if ext_rename_file(&path, &copy_path, &ext) == NGX_OK {
                return NGX_HTTP_NO_CONTENT;
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        let cf = CopyFile {
            size: fi.st_size as i64,
            buf_size: 0,
            access: file_access(&fi),
            time: fi.st_mtime as i64,
            log,
        };

        if copy_file(&path, &copy_path, &cf) == NGX_OK {
            return NGX_HTTP_NO_CONTENT;
        }
    }

    NGX_HTTP_INTERNAL_SERVER_ERROR
}

/// ngx_http_dav_merge_slashes
fn dav_merge_slashes(path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(path.len());
    let mut p = 0;

    while p < path.len() && path[p] != 0 {
        let ch = path[p];
        p += 1;

        out.push(ch);

        if ch == b'/' {
            while p < path.len() && path[p] == b'/' {
                p += 1;
            }
        }
    }

    out
}

/// ngx_http_dav_validate_paths
fn dav_validate_paths(r: &R, src: &[u8], dst: &[u8], slash: bool, dest: &[u8]) -> i64 {
    match check_paths(src, dst, slash) {
        Ok(()) => NGX_OK,
        Err(same) => {
            let uri = r.uri.borrow().clone();

            if same {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "both URI \"{}\" and \"Destination\" URI \"{}\" point to the same location", B(&uri), B(dest));
            } else {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "\"{}\" could not be {}ed to collection \"{}\"", B(&uri), B(&r.method_name.borrow()), B(dest));
            }

            NGX_HTTP_FORBIDDEN
        }
    }
}

/// The checks of ngx_http_dav_validate_paths: Err(true) when both paths
/// are the same, Err(false) when a collection would go into itself
fn check_paths(src: &[u8], dst: &[u8], slash: bool) -> Result<(), bool> {
    let mut len = src.len();

    if len > 0 && src[len - 1] == b'/' {
        len -= 1;
    }

    if len == dst.len() && src[..len] == dst[..len] {
        return Err(true);
    }

    let min = len.min(dst.len());

    if slash
        && src[..min] == dst[..min]
        && (if len < dst.len() { dst[len] == b'/' } else { src.get(dst.len()) == Some(&b'/') })
    {
        return Err(false);
    }

    Ok(())
}

/// What the tree walk of ngx_http_dav_delete_path or of the directory
/// copy does with each entry
enum TreeOp<'a> {
    Delete,
    Copy(&'a DavCopyCtx),
}

/// ngx_tree_ctx_t
struct TreeCtx<'a> {
    size: i64,
    fs_size: i64,
    access: u32,
    mtime: i64,
    op: TreeOp<'a>,
    log: &'a Log,
}

impl<'a> TreeCtx<'a> {
    fn new(op: TreeOp<'a>, log: &'a Log) -> TreeCtx<'a> {
        TreeCtx { size: 0, fs_size: 0, access: 0, mtime: 0, op, log }
    }

    fn file_handler(&mut self, path: &[u8]) -> i64 {
        match self.op {
            TreeOp::Delete => dav_delete_file(self, path),
            TreeOp::Copy(copy) => dav_copy_tree_file(self, copy, path),
        }
    }

    fn pre_tree_handler(&mut self, path: &[u8]) -> i64 {
        match self.op {
            TreeOp::Delete => NGX_OK,
            TreeOp::Copy(copy) => dav_copy_dir(self, copy, path),
        }
    }

    fn post_tree_handler(&mut self, path: &[u8]) -> i64 {
        match self.op {
            TreeOp::Delete => dav_delete_dir(self, path),
            TreeOp::Copy(copy) => dav_copy_dir_time(self, copy, path),
        }
    }

    fn spec_handler(&mut self, path: &[u8]) -> i64 {
        match self.op {
            TreeOp::Delete => dav_delete_file(self, path),
            TreeOp::Copy(_) => NGX_OK,
        }
    }
}

/// ngx_http_dav_delete_dir
fn dav_delete_dir(ctx: &TreeCtx, path: &[u8]) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "http delete dir: \"{}\"", B(path));

    if delete_dir(path).is_err() {
        /* TODO: add to 207 */

        dav_error(ctx.log, ngx_core::os::errno(), 0, "rmdir()", path);
    }

    NGX_OK
}

/// ngx_http_dav_delete_file
fn dav_delete_file(ctx: &TreeCtx, path: &[u8]) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "http delete file: \"{}\"", B(path));

    if let Err(err) = ngx_core::os::unlink(path) {
        /* TODO: add to 207 */

        dav_error(ctx.log, err, 0, "unlink()", path);
    }

    NGX_OK
}

/// The copy.path + the part of `path` under the source directory
fn copy_target(copy: &DavCopyCtx, path: &[u8]) -> Vec<u8> {
    let mut target = copy.path.clone();
    target.extend_from_slice(&path[copy.len..]);
    target
}

/// ngx_http_dav_copy_dir
fn dav_copy_dir(ctx: &TreeCtx, copy: &DavCopyCtx, path: &[u8]) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "http copy dir: \"{}\"", B(path));

    let dir = copy_target(copy, path);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "http copy dir to: \"{}\"", B(&dir));

    if let Err(err) = ngx_core::os::mkdir(&dir, dir_access(ctx.access)) {
        dav_error(ctx.log, err, 0, "mkdir()", &dir);
    }

    NGX_OK
}

/// ngx_http_dav_copy_dir_time
fn dav_copy_dir_time(ctx: &TreeCtx, copy: &DavCopyCtx, path: &[u8]) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "http copy dir time: \"{}\"", B(path));

    let dir = copy_target(copy, path);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "http copy dir time to: \"{}\"", B(&dir));

    if let Err(err) = set_file_time(&dir, 0, ctx.mtime) {
        ngx_log_error!(NGX_LOG_ALERT, ctx.log, Some(err), "utimes() \"{}\" failed", B(&dir));
    }

    NGX_OK
}

/// ngx_http_dav_copy_tree_file
fn dav_copy_tree_file(ctx: &TreeCtx, copy: &DavCopyCtx, path: &[u8]) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "http copy file: \"{}\"", B(path));

    let file = copy_target(copy, path);

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, ctx.log, "http copy file to: \"{}\"", B(&file));

    let cf = CopyFile { size: ctx.size, buf_size: 0, access: ctx.access, time: ctx.mtime, log: ctx.log };

    copy_file(path, &file, &cf);

    NGX_OK
}

/// ngx_http_dav_depth
fn dav_depth(r: &R, dflt: i64) -> i64 {
    let depth = r.headers_in.borrow().depth.first().map(|h| h.value());

    let depth = match depth {
        Some(depth) => depth,
        None => return dflt,
    };

    if depth.len() == 1 {
        if depth[0] == b'0' {
            return 0;
        }

        if depth[0] == b'1' {
            return 1;
        }
    } else if depth == b"infinity" {
        return NGX_HTTP_DAV_INFINITY_DEPTH;
    }

    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "client sent invalid \"Depth\" header: \"{}\"", B(&depth));

    NGX_HTTP_DAV_INVALID_DEPTH
}

/// ngx_http_dav_error
fn dav_error(log: &Log, err: i32, not_found: i64, failed: &str, path: &[u8]) -> i64 {
    let (level, rc) = if err == libc::ENOENT || err == libc::ENOTDIR || err == libc::ENAMETOOLONG {
        (NGX_LOG_ERR, not_found)
    } else if err == libc::EACCES || err == libc::EPERM {
        (NGX_LOG_ERR, NGX_HTTP_FORBIDDEN)
    } else if err == libc::EEXIST {
        (NGX_LOG_ERR, NGX_HTTP_NOT_ALLOWED)
    } else if err == libc::ENOSPC {
        (NGX_LOG_CRIT, NGX_HTTP_INSUFFICIENT_STORAGE)
    } else {
        (NGX_LOG_CRIT, NGX_HTTP_INTERNAL_SERVER_ERROR)
    };

    ngx_log_error!(level, log, Some(err), "{} \"{}\" failed", failed, B(path));

    rc
}

/// ngx_http_dav_location
fn dav_location(r: &R) {
    let uri = r.uri.borrow().clone();

    let escape = 2 * escape_uri_count(&uri, NGX_ESCAPE_URI);

    let value = if escape != 0 { escape_uri(&uri, NGX_ESCAPE_URI) } else { uri };

    let mut ho = r.headers_out.borrow_mut();
    let h = ho.add(b"Location", &value);
    ho.location = Some(h);
}

// ---------------------------------------------------------------------------
// ngx_file.c / ngx_files.c

/// ngx_dir_access
fn dir_access(a: u32) -> u32 {
    a | (a & 0o444) >> 2
}

/// ngx_file_access
fn file_access(fi: &libc::stat) -> u32 {
    fi.st_mode & 0o777
}

/// ngx_delete_dir
fn delete_dir(name: &[u8]) -> Result<(), i32> {
    let c = ngx_core::os::cstr(name);

    // SAFETY: c is a NUL-terminated string that outlives the call
    if unsafe { libc::rmdir(c.as_ptr()) } == -1 {
        return Err(ngx_core::os::errno());
    }

    Ok(())
}

/// ngx_rename_file
fn rename_file(from: &[u8], to: &[u8]) -> Result<(), i32> {
    let f = ngx_core::os::cstr(from);
    let t = ngx_core::os::cstr(to);

    // SAFETY: both are NUL-terminated strings that outlive the call
    if unsafe { libc::rename(f.as_ptr(), t.as_ptr()) } == -1 {
        return Err(ngx_core::os::errno());
    }

    Ok(())
}

/// ngx_change_file_access
fn change_file_access(name: &[u8], access: u32) -> Result<(), i32> {
    let c = ngx_core::os::cstr(name);

    // SAFETY: c is a NUL-terminated string that outlives the call
    if unsafe { libc::chmod(c.as_ptr(), access as libc::mode_t) } == -1 {
        return Err(ngx_core::os::errno());
    }

    Ok(())
}

/// ngx_set_file_time: utimes() with the current time as the access time
/// (the descriptor is not used on Unix)
fn set_file_time(name: &[u8], _fd: i32, s: i64) -> Result<(), i32> {
    let c = ngx_core::os::cstr(name);

    let tv = [
        libc::timeval { tv_sec: ngx_core::times::time() as libc::time_t, tv_usec: 0 },
        libc::timeval { tv_sec: s as libc::time_t, tv_usec: 0 },
    ];

    // SAFETY: c is a NUL-terminated string, tv an array of two timevals
    if unsafe { libc::utimes(c.as_ptr(), tv.as_ptr()) } == -1 {
        return Err(ngx_core::os::errno());
    }

    Ok(())
}

/// ngx_create_full_path: creates the directories of the path up to its
/// last '/'; returns the error of the last failed mkdir() (EEXIST
/// counting as none), stopping at errors other than EACCES
fn create_full_path(dir: &[u8], access: u32) -> i32 {
    let mut err = 0;

    for i in 1..dir.len() {
        if dir[i] == 0 {
            break;
        }

        if dir[i] != b'/' {
            continue;
        }

        if let Err(e) = ngx_core::os::mkdir(&dir[..i], access) {
            err = e;

            match e {
                libc::EEXIST => err = 0,
                libc::EACCES => {}
                _ => return err,
            }
        }
    }

    err
}

/// ngx_ext_rename_file_t
struct ExtRenameFile<'a> {
    access: u32,
    path_access: u32,
    time: i64,
    fd: i32,
    create_path: bool,
    delete_file: bool,
    log: &'a Log,
}

/// ngx_ext_rename_file
fn ext_rename_file(src: &[u8], to: &[u8], ext: &ExtRenameFile) -> i64 {
    let log = ext.log;
    let mut err;

    'failed: {
        if ext.access != 0 {
            if let Err(e) = change_file_access(src, ext.access) {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "chmod() \"{}\" failed", B(src));
                err = 0;
                break 'failed;
            }
        }

        if ext.time != -1 {
            if let Err(e) = set_file_time(src, ext.fd, ext.time) {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "utimes() \"{}\" failed", B(src));
                err = 0;
                break 'failed;
            }
        }

        match rename_file(src, to) {
            Ok(()) => return NGX_OK,
            Err(e) => err = e,
        }

        if err == libc::ENOENT {
            if !ext.create_path {
                break 'failed;
            }

            err = create_full_path(to, dir_access(ext.path_access));

            if err != 0 {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "mkdir() \"{}\" failed", B(to));
                err = 0;
                break 'failed;
            }

            match rename_file(src, to) {
                Ok(()) => return NGX_OK,
                Err(e) => err = e,
            }
        }

        if err == libc::EXDEV {
            let cf = CopyFile { size: -1, buf_size: 0, access: ext.access, time: ext.time, log };

            // ngx_next_temp_number(0)
            let n = ngx_core::connection::stats().temp_number.fetch_add(1, std::sync::atomic::Ordering::Relaxed).wrapping_add(1) as u32;

            let mut name = to.to_vec();
            name.extend_from_slice(format!(".{:010}", n).as_bytes());

            if copy_file(src, &name, &cf) == NGX_OK {
                if rename_file(&name, to).is_ok() {
                    if let Err(e) = ngx_core::os::unlink(src) {
                        ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "unlink() \"{}\" failed", B(src));
                        return NGX_ERROR;
                    }

                    return NGX_OK;
                }

                ngx_log_error!(NGX_LOG_CRIT, log, Some(ngx_core::os::errno()), "rename() \"{}\" to \"{}\" failed", B(&name), B(to));

                if let Err(e) = ngx_core::os::unlink(&name) {
                    ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "unlink() \"{}\" failed", B(&name));
                }
            }

            err = 0;
        }
    }

    // failed:

    if ext.delete_file {
        if let Err(e) = ngx_core::os::unlink(src) {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(e), "unlink() \"{}\" failed", B(src));
        }
    }

    if err != 0 {
        ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "rename() \"{}\" to \"{}\" failed", B(src), B(to));
    }

    NGX_ERROR
}

/// ngx_copy_file_t
struct CopyFile<'a> {
    size: i64,
    buf_size: usize,
    access: u32,
    time: i64,
    log: &'a Log,
}

/// ngx_copy_file
fn copy_file(from: &[u8], to: &[u8], cf: &CopyFile) -> i64 {
    let log = cf.log;

    let fd = match ngx_core::os::open(from, libc::O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(err) => {
            ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "open() \"{}\" failed", B(from));
            return NGX_ERROR;
        }
    };

    let mut nfd = -1;

    let rc = 'failed: {
        let (mut size, access, time) = if cf.size != -1 && cf.access != 0 && cf.time != -1 {
            (cf.size, cf.access, cf.time)
        } else {
            let fi = match ngx_core::os::fstat(fd) {
                Ok(fi) => fi,
                Err(err) => {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(err), "fstat() \"{}\" failed", B(from));
                    break 'failed NGX_ERROR;
                }
            };

            (
                if cf.size != -1 { cf.size } else { fi.st_size as i64 },
                if cf.access != 0 { cf.access } else { file_access(&fi) },
                if cf.time != -1 { cf.time } else { fi.st_mtime as i64 },
            )
        };

        let mut len = if cf.buf_size != 0 { cf.buf_size } else { 65536 };

        if len as i64 > size {
            len = size as usize;
        }

        let mut buf = vec![0u8; len];

        nfd = match ngx_core::os::open(to, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, access) {
            Ok(nfd) => nfd,
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, log, Some(err), "open() \"{}\" failed", B(to));
                break 'failed NGX_ERROR;
            }
        };

        while size > 0 {
            if len as i64 > size {
                len = size as usize;
            }

            // SAFETY: buf has at least len bytes
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, len) };

            if n == -1 {
                ngx_log_error!(NGX_LOG_ALERT, log, Some(ngx_core::os::errno()), "read() \"{}\" failed", B(from));
                break 'failed NGX_ERROR;
            }

            if n as usize != len {
                ngx_log_error!(NGX_LOG_ALERT, log, None, "read() has read only {} of {} from {}", n, size, B(from));
                break 'failed NGX_ERROR;
            }

            let n = match ngx_core::os::write_fd(nfd, &buf[..len]) {
                Ok(n) => n,
                Err(err) => {
                    ngx_log_error!(NGX_LOG_ALERT, log, Some(err), "write() \"{}\" failed", B(to));
                    break 'failed NGX_ERROR;
                }
            };

            if n != len {
                ngx_log_error!(NGX_LOG_ALERT, log, None, "write() has written only {} of {} to {}", n, size, B(to));
                break 'failed NGX_ERROR;
            }

            size -= n as i64;
        }

        if let Err(err) = set_file_time(to, nfd, time) {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(err), "utimes() \"{}\" failed", B(to));
            break 'failed NGX_ERROR;
        }

        NGX_OK
    };

    // SAFETY: the descriptors were opened above and are closed once
    if nfd != -1 && unsafe { libc::close(nfd) } == -1 {
        ngx_log_error!(NGX_LOG_ALERT, log, Some(ngx_core::os::errno()), "close() \"{}\" failed", B(to));
    }

    // SAFETY: as above
    if unsafe { libc::close(fd) } == -1 {
        ngx_log_error!(NGX_LOG_ALERT, log, Some(ngx_core::os::errno()), "close() \"{}\" failed", B(from));
    }

    rc
}

/// ngx_walk_tree; `tree` is the C string of the directory, `len` the
/// tree->len the names are appended at (a trailing '/' of the C string
/// beyond it is used by opendir() and in the messages only)
fn walk_tree(ctx: &mut TreeCtx, tree: &[u8], len: usize) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, ctx.log, "walk tree \"{}\"", B(&tree[..len]));

    let mut dir = match Dir::open(tree) {
        Ok(dir) => dir,
        Err(err) => {
            ngx_log_error!(NGX_LOG_CRIT, ctx.log, Some(err), "opendir() \"{}\" failed", B(tree));
            return NGX_ERROR;
        }
    };

    let rc = loop {
        let name = match dir.read() {
            Ok(name) => name,
            Err(0) => break NGX_OK,
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, ctx.log, Some(err), "readdir() \"{}\" failed", B(tree));
                break NGX_ERROR;
            }
        };

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, ctx.log, "tree name {}:\"{}\"", name.len(), B(&name));

        if name == b"." || name == b".." {
            continue;
        }

        let mut file = Vec::with_capacity(len + 1 + name.len());
        file.extend_from_slice(&tree[..len]);
        file.push(b'/');
        file.extend_from_slice(&name);

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, ctx.log, "tree path \"{}\"", B(&file));

        let fi = match ngx_core::os::stat(&file) {
            Ok(fi) => fi,
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, ctx.log, Some(err), "stat() \"{}\" failed", B(&file));
                continue;
            }
        };

        if ngx_core::os::is_file(&fi) {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, ctx.log, "tree file \"{}\"", B(&file));

            ctx.size = fi.st_size as i64;
            ctx.fs_size = (fi.st_size as i64).max(fi.st_blocks as i64 * 512);
            ctx.access = file_access(&fi);
            ctx.mtime = fi.st_mtime as i64;

            if ctx.file_handler(&file) == NGX_ABORT {
                break NGX_ABORT;
            }
        } else if ngx_core::os::is_dir(&fi) {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, ctx.log, "tree enter dir \"{}\"", B(&file));

            ctx.access = file_access(&fi);
            ctx.mtime = fi.st_mtime as i64;

            let rc = ctx.pre_tree_handler(&file);

            if rc == NGX_ABORT {
                break NGX_ABORT;
            }

            if rc == NGX_DECLINED {
                ngx_log_debug!(NGX_LOG_DEBUG_CORE, ctx.log, "tree skip dir \"{}\"", B(&file));
                continue;
            }

            if walk_tree(ctx, &file, file.len()) == NGX_ABORT {
                break NGX_ABORT;
            }

            ctx.access = file_access(&fi);
            ctx.mtime = fi.st_mtime as i64;

            if ctx.post_tree_handler(&file) == NGX_ABORT {
                break NGX_ABORT;
            }
        } else {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, ctx.log, "tree special \"{}\"", B(&file));

            if ctx.spec_handler(&file) == NGX_ABORT {
                break NGX_ABORT;
            }
        }
    };

    if let Err(err) = dir.close() {
        ngx_log_error!(NGX_LOG_CRIT, ctx.log, Some(err), "closedir() \"{}\" failed", B(tree));
    }

    rc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_depth() {
        assert_eq!(check_delete_depth(b"/min3/shallow", 3), Err(2));
        assert_eq!(check_delete_depth(b"/min3/a/b/deep", 3), Ok(()));
        // the slash that reaches the depth must not be the last character
        assert_eq!(check_delete_depth(b"/a/b/", 3), Err(3));
        assert_eq!(check_delete_depth(b"/a/b/c", 3), Ok(()));
        assert_eq!(check_delete_depth(b"/top", 1), Ok(()));
        assert_eq!(check_delete_depth(b"/", 1), Err(1));
    }

    #[test]
    fn merge_slashes() {
        assert_eq!(dav_merge_slashes(b"/a//b///c/"), b"/a/b/c/");
        assert_eq!(dav_merge_slashes(b"//"), b"/");
        assert_eq!(dav_merge_slashes(b"abc"), b"abc");
        assert_eq!(dav_merge_slashes(b"/a\0/b"), b"/a");
    }

    #[test]
    fn validate_paths() {
        // the same file, or the same directory with and without a slash
        assert_eq!(check_paths(b"/r/file", b"/r/file", false), Err(true));
        assert_eq!(check_paths(b"/r/dir/", b"/r/dir", true), Err(true));
        // a collection into itself or into its parent
        assert_eq!(check_paths(b"/r/dir/", b"/r/dir/sub", true), Err(false));
        assert_eq!(check_paths(b"/r/dir/sub/", b"/r/dir", true), Err(false));
        // a common prefix is not a parent
        assert_eq!(check_paths(b"/r/dir/", b"/r/dir2", true), Ok(()));
        assert_eq!(check_paths(b"/r/file", b"/r/file2", false), Ok(()));
        assert_eq!(check_paths(b"/r/file2", b"/r/file", false), Ok(()));
        // files are not checked for nesting
        assert_eq!(check_paths(b"/r/a", b"/r/a/b", false), Ok(()));
    }

    #[test]
    fn access() {
        assert_eq!(dir_access(0o600), 0o700);
        assert_eq!(dir_access(0o644), 0o755);
        assert_eq!(dir_access(0o640), 0o750);
    }

    #[test]
    fn full_path() {
        let d = std::env::temp_dir().join(format!("dav-test-{}", std::process::id()));
        let d = d.as_os_str().as_encoded_bytes().to_vec();
        let mut p = d.clone();
        p.extend_from_slice(b"/a/b/file");
        assert_eq!(create_full_path(&p, 0o700), 0);
        assert!(std::path::Path::new(std::str::from_utf8(&[&d[..], b"/a/b"].concat()).unwrap()).is_dir());
        // existing directories are fine
        assert_eq!(create_full_path(&p, 0o700), 0);
        // a file in the way
        std::fs::write(std::str::from_utf8(&[&d[..], b"/a/f"].concat()).unwrap(), b"x").unwrap();
        let mut q = d.clone();
        q.extend_from_slice(b"/a/f/x/y");
        assert_eq!(create_full_path(&q, 0o700), libc::ENOTDIR);
        std::fs::remove_dir_all(std::str::from_utf8(&d).unwrap()).unwrap();
    }
}
