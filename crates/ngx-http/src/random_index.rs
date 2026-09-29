//! ngx_http_random_index_module: picks a random file from a directory

use std::any::Any;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::CoreLocConf;
use crate::*;

crate::http_module_index!("ngx_http_random_index_module");

pub struct RandomIndexConf {
    pub enable: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(RandomIndexConf {
        enable: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<RandomIndexConf>(prev).borrow();
    let mut c = conf_cell::<RandomIndexConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    Ok(())
}

pub fn random_index_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![ngx_core::cmd!("random_index", NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, RandomIndexConf, enable, set_flag)];
    http_module_def("ngx_http_random_index_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    crate::core::add_phase_handler(cf, NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(random_index_handler(r))));
    Ok(())
}

async fn random_index_handler(r: R) -> i64 {
    use ngx_core::rc::*;

    // Only handle directory requests (URI ends with /)
    {
        let uri = r.uri.borrow();
        if uri.is_empty() || uri[uri.len() - 1] != b'/' {
            return NGX_DECLINED;
        }
    }

    // Only handle GET, HEAD, POST
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD | NGX_HTTP_POST) == 0 {
        return NGX_DECLINED;
    }

    let conf = r.loc_conf::<RandomIndexConf>(ctx_index());
    if !*conf.borrow().enable.get() {
        return NGX_DECLINED;
    }

    // Map URI to filesystem path
    let (path_bytes, _root) = match crate::core_rt::map_uri_to_path(&r, 0) {
        Some((p, root)) => (p, root),
        None => return NGX_DECLINED,
    };

    let path_str = String::from_utf8_lossy(&path_bytes);
    let path = PathBuf::from(path_str.as_ref());

    // Try to open directory
    let Ok(dir_entries) = fs::read_dir(&path) else {
        return NGX_DECLINED;
    };

    // Collect regular files (skip . and .., follow symlinks per C's
    // ngx_de_info which stats the target).
    let mut files = Vec::new();
    for entry in dir_entries.flatten() {
        let name = match entry.file_name().into_string() { Ok(s) => s, Err(_) => continue };
        if name.starts_with('.') { continue; }
        // Follow symlinks: fs::metadata does stat(), symlink_metadata does lstat().
        let md = match fs::metadata(entry.path()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.is_file() {
            files.push(name.as_bytes().to_vec());
        }
    }

    if files.is_empty() {
        return NGX_DECLINED;
    }

    // Pick a random file
    let idx = (ngx_random() as usize) % files.len();
    let filename = &files[idx];

    // Redirect to filename
    let mut new_uri = r.uri.borrow().clone();
    new_uri.extend_from_slice(filename);

    let args = r.args.borrow().clone();
    let args_ref = if args.is_empty() { None } else { Some(args.as_slice()) };

    crate::core_rt::internal_redirect(&r, &new_uri, args_ref).await
}

fn ngx_random() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u32;
    now.wrapping_mul(1664525).wrapping_add(1013904223)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_index_conf() {
        let conf = RandomIndexConf {
            enable: Val::unset(),
        };
        assert!(!conf.enable.is_set());
    }
}
