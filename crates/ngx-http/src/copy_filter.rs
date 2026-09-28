//! ngx_http_copy_filter_module: reads file buffers into memory when needed.

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::request::*;
use crate::*;

crate::http_module_index!("ngx_http_copy_filter_module");

pub struct CopyConf {
    pub bufs: Bufs,
}

fn create_conf(_cf: &mut Conf) -> std::rc::Rc<dyn std::any::Any> {
    make_slot(CopyConf { bufs: Bufs::default() })
}

fn merge_conf(_cf: &mut Conf, prev: &std::rc::Rc<dyn std::any::Any>, conf: &std::rc::Rc<dyn std::any::Any>) -> ConfResult {
    let p = conf_cell::<CopyConf>(prev).borrow();
    let mut c = conf_cell::<CopyConf>(conf).borrow_mut();
    c.bufs.merge(&p.bufs, 2, 32768);
    Ok(())
}

pub fn copy_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), create_loc_conf: Some(create_conf), merge_loc_conf: Some(merge_conf), ..Default::default() };
    let commands = vec![ngx_core::cmd!("output_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, CopyConf, bufs, set_bufs)];
    http_module_def("ngx_http_copy_filter_module", def, commands)
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_body_filter(|r, chain, next| async move { copy_filter(r, chain, next).await });
    Ok(())
}

/// The output_buffers total: how much output may be in flight before the
/// copy filter has to wait (its busy buffers in C).
pub fn output_buffers_size(r: &R) -> usize {
    let conf = r.loc_conf::<CopyConf>(ctx_index());
    let b = conf.borrow();
    b.bufs.num.max(1) * b.bufs.size.max(1)
}

async fn copy_filter(r: R, mut input: Chain, next: BodyFilter) -> i64 {
    let need_in_memory = r.main_filter_need_in_memory.get() || r.filter_need_in_memory.get() || !r.connection.sendfile.get();
    let has_file = input.iter().any(|b| b.in_file && !b.in_memory());
    if !has_file || !need_in_memory {
        return next(r, input).await;
    }
    let conf = r.loc_conf::<CopyConf>(ctx_index());
    let size = conf.borrow().bufs.size.max(1);
    let mut out = Chain::new();
    while let Some(b) = input.pop_front() {
        if !(b.in_file && !b.in_memory()) {
            out.push_back(b);
            continue;
        }
        let (fd, name) = match &b.data {
            BufData::File(f) => (f.fd, f.name.clone()),
            _ => continue,
        };
        let mut pos = b.file_pos;
        let end = b.file_last;
        let mut first = true;
        while pos < end || first {
            first = false;
            let want = ((end - pos) as usize).min(size);
            let mut buf = vec![0u8; want];
            let n = if want > 0 { unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, want, pos as libc::off_t) } } else { 0 };
            if n < 0 {
                let e = ngx_core::os::errno();
                ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(e), "pread() \"{}\" failed", B(&name));
                return NGX_ERROR;
            }
            if n == 0 && want > 0 {
                ngx_log_error!(NGX_LOG_ALERT, r.connection.log, None, "pread() read only 0 of {} from \"{}\"", want, B(&name));
                return NGX_ERROR;
            }
            buf.truncate(n as usize);
            pos += n as i64;
            let last_piece = pos >= end;
            let mut nb = Buf::from_vec(buf);
            nb.memory = true;
            nb.temporary = true;
            if last_piece {
                nb.last_buf = b.last_buf;
                nb.last_in_chain = b.last_in_chain;
                nb.flush = b.flush;
                nb.sync = b.sync;
            }
            out.push_back(nb);
            if last_piece {
                break;
            }
            // send pieces progressively to bound memory
            let chunk = std::mem::take(&mut out);
            let rc = next(r.clone(), chunk).await;
            if rc != NGX_OK {
                return rc;
            }
        }
    }
    if out.is_empty() {
        return NGX_OK;
    }
    next(r, out).await
}
