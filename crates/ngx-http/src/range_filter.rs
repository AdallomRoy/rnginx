//! ngx_http_range_header_filter_module / ngx_http_range_body_filter_module

use ngx_core::conf::{Conf, ConfResult};
use ngx_core::module::ModuleDef;

use crate::*;

pub fn range_header_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init_header), ..Default::default() };
    http_module_def("ngx_http_range_header_filter_module", def, Vec::new())
}

pub fn range_body_filter_module() -> ModuleDef {
    let def = HttpModuleDef { postconfiguration: Some(init_body), ..Default::default() };
    http_module_def("ngx_http_range_body_filter_module", def, Vec::new())
}

fn init_header(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move {
        // Advertise Accept-Ranges when no Range header
        if r.allow_ranges.get() && r.headers_out.borrow().status == NGX_HTTP_OK && r.is_main() {
            let hi = r.headers_in.borrow();
            if hi.range.is_empty() {
                let h = r.headers_out.borrow_mut().add(b"Accept-Ranges", b"bytes");
                r.headers_out.borrow_mut().accept_ranges = Some(h);
            }
        }
        next(r).await
    });
    Ok(())
}

fn init_body(_cf: &mut Conf) -> ConfResult {
    install_body_filter(|r, chain, next| async move { next(r, chain).await });
    Ok(())
}
