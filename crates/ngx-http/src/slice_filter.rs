//! ngx_http_slice_filter_module

use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;

use crate::*;

pub fn slice_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init), ..Default::default() };
    http_module_def("ngx_http_slice_filter_module", def, Vec::new())
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { next(r).await });
    install_body_filter(|r, chain, next| async move { next(r, chain).await });
    Ok(())
}
