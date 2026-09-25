//! Parse-only stubs for core/event modules not yet ported (directives accepted, no effect).

use std::any::Any;
use std::rc::Rc;

use crate::conf::*;
use crate::module::*;

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn core_stub(name: &'static str, ctx_name: &'static str, commands: Vec<Command>) -> ModuleDef {
    let mut m = ModuleDef::new(name, NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: ctx_name, create_conf: None, init_conf: None }));
    m.commands = commands;
    m
}

/// ngx_openssl_cache_module (ngx_event_openssl_cache.c)
pub fn openssl_cache_module() -> ModuleDef {
    core_stub("ngx_openssl_cache_module", "openssl_cache", vec![Command::new("ssl_object_cache_inheritable", NGX_MAIN_CONF | NGX_DIRECT_CONF | NGX_CONF_FLAG, ConfLevel::None, accept)])
}

/// ngx_quic_module (ngx_event_quic.c): no directives.
pub fn quic_module() -> ModuleDef {
    core_stub("ngx_quic_module", "quic", vec![])
}

/// ngx_quic_bpf_module (ngx_event_quic_bpf.c)
pub fn quic_bpf_module() -> ModuleDef {
    core_stub("ngx_quic_bpf_module", "quic_bpf", vec![Command::new("quic_bpf", NGX_MAIN_CONF | NGX_DIRECT_CONF | NGX_CONF_FLAG, ConfLevel::None, accept)])
}

/// ngx_thread_pool_module (ngx_thread_pool.c)
pub fn thread_pool_module() -> ModuleDef {
    core_stub("ngx_thread_pool_module", "thread_pool", vec![Command::new("thread_pool", NGX_MAIN_CONF | NGX_DIRECT_CONF | NGX_CONF_TAKE23, ConfLevel::None, accept)])
}

/// ngx_epoll_module (ngx_epoll_module.c): event module directives.
pub fn epoll_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_epoll_module", NGX_EVENT_MODULE);
    m.ctx = Some(Rc::new(crate::event::EventModuleCtx { name: "epoll", create_conf: None, init_conf: None }));
    m.commands = vec![
        Command::new("epoll_events", crate::event::NGX_EVENT_CONF | NGX_CONF_TAKE1, ConfLevel::None, accept),
        Command::new("worker_aio_requests", crate::event::NGX_EVENT_CONF | NGX_CONF_TAKE1, ConfLevel::None, accept),
    ];
    m
}
