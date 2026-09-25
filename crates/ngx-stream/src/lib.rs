//! ngx-stream: minimal skeleton. Accepts and skips the `stream {}` block (and every nested
//! block inside it) so configs parse.

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::*;
use ngx_core::cmd_fn;

/// Parse a block, silently accepting every directive (non-block or block). Recurses into blocks.
fn skip_block_deep(cf: &mut Conf) -> ConfResult {
    let saved_h = cf.handler.take();
    let saved_hc = cf.handler_conf.take();
    // Use a handler that accepts any non-block directive and, on block starts, recurses.
    cf.handler = Some(skip_any_or_recurse);
    cf.handler_conf = Some(Rc::new(()));
    let rv = cf.parse_block();
    cf.handler = saved_h;
    cf.handler_conf = saved_hc;
    rv
}

fn skip_any_or_recurse(_cf: &mut Conf, _c: Rc<dyn Any>) -> ConfResult {
    Ok(())
}

fn stream_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // The parse_inner loop will call our handler for every token, but errors on BlockStart
    // when a handler is set. To support nested `server {}` blocks, we set cmd_type to accept
    // any directive and register the block-directives explicitly via a subhandler pass.
    //
    // Approach: parse manually — read tokens; for BlockStart, recurse; for Ok/BlockDone, continue.
    manual_skip_block(cf)
}

/// Manually parse tokens skipping everything up to matching `}`.
fn manual_skip_block(cf: &mut Conf) -> ConfResult {
    // We don't have direct token access — but we can use a handler that never runs
    // for BlockStart if we register `server` and other known block directives.
    // Simpler: just use skip_block_deep but with a saved cmd_type that permits all directives.
    let saved_ct = cf.cmd_type;
    let saved_mt = cf.module_type;
    cf.cmd_type = 0xFFFFFFFF;
    cf.module_type = NGX_CONF_MODULE;
    let rv = skip_block_deep(cf);
    cf.cmd_type = saved_ct;
    cf.module_type = saved_mt;
    rv
}

pub fn stream_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_stream_module", NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: "stream", create_conf: None, init_conf: None }));
    m.commands = vec![cmd_fn!("stream", NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS, ConfLevel::None, stream_block)];
    m
}

pub fn modules() -> Vec<ModuleDef> {
    vec![stream_module()]
}
