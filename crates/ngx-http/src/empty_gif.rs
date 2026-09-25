//! ngx_http_empty_gif_module: returns a fixed transparent GIF (43 bytes)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::core::CoreLocConf;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_empty_gif_module");

pub struct EmptyGifConf;

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(EmptyGifConf)
}

fn merge_conf(_cf: &mut Conf, _prev: &Rc<dyn Any>, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

pub fn empty_gif_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![ngx_core::cmd_fn!(
        "empty_gif",
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ConfLevel::Loc,
        set_handler
    )];
    http_module_def("ngx_http_empty_gif_module", def, commands)
}

fn set_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let loc_conf = get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());
    loc_conf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(empty_gif_handler(r))));
    Ok(())
}

fn init(_cf: &mut Conf) -> ConfResult {
    Ok(())
}

async fn empty_gif_handler(r: R) -> i64 {
    use ngx_core::rc::*;

    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return 405; // NGX_HTTP_NOT_ALLOWED
    }

    // Minimal single pixel transparent GIF, 43 bytes
    let gif: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x01\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x01\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00\x3b";

    r.headers_out.borrow_mut().last_modified_time = 23349600;

    let cv = ComplexValue::constant(gif);
    core_rt::send_response(&r, NGX_HTTP_OK, Some(b"image/gif"), &cv).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gif_size() {
        let gif: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x01\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x01\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x4c\x01\x00\x3b";
        assert_eq!(gif.len(), 43);
    }
}
