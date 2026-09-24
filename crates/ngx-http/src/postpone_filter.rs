//! ngx_http_postpone_filter_module: routes subrequest output to the main request's filters.

use ngx_core::buf::Chain;
use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::request::*;
use crate::*;

pub fn postpone_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_postpone_filter_module", def, Vec::new())
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_body_filter(|r, chain, next| async move { postpone_filter(r, chain, next).await });
    Ok(())
}

async fn postpone_filter(r: R, mut chain: Chain, next: BodyFilter) -> i64 {
    if r.is_main() {
        return next(r, chain).await;
    }
    if r.background.get() {
        return NGX_OK;
    }
    if r.subrequest_in_memory.get() {
        return subrequest_in_memory_collect(&r, chain);
    }
    // subrequest output goes to the main request's remaining filters; drop last_buf
    let main = r.main();
    for b in chain.iter_mut() {
        b.last_buf = false;
    }
    if chain.iter().all(|b| b.buf_size() == 0 && !b.flush) {
        return NGX_OK;
    }
    next(main, chain).await
}

/// In-memory subrequests keep their body in a buffer (ngx_http_subrequest in_memory + upstream).
fn subrequest_in_memory_collect(r: &R, chain: Chain) -> i64 {
    let mut data = r.captures_data.borrow_mut(); // reuse? no: use dedicated ctx
    drop(data);
    let ctx = match r.get_ctx::<InMemoryBody>(crate::core::ctx_index()) {
        Some(c) => c,
        None => r.set_ctx(crate::core::ctx_index(), InMemoryBody { data: Vec::new() }),
    };
    let mut c = ctx.borrow_mut();
    for b in chain.iter() {
        if let ngx_core::buf::BufData::Memory(v) = &b.data {
            c.data.extend_from_slice(&v[b.pos..b.last]);
        }
    }
    NGX_OK
}

pub struct InMemoryBody {
    pub data: Vec<u8>,
}
