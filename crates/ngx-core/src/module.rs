//! Module registry, mirroring ngx_module_t.

use std::any::Any;
use std::rc::Rc;

use crate::conf::Command;
use crate::cycle::Cycle;

pub const NGX_CORE_MODULE: u32 = 0x45524F43; // "CORE"
pub const NGX_CONF_MODULE: u32 = 0x464E4F43; // "CONF"
pub const NGX_EVENT_MODULE: u32 = 0x544E5645; // "EVNT"
pub const NGX_HTTP_MODULE: u32 = 0x50545448; // "HTTP"
pub const NGX_MAIL_MODULE: u32 = 0x4C49414D; // "MAIL"
pub const NGX_STREAM_MODULE: u32 = 0x4d525453; // "STRM"

pub type InitFn = fn(&mut Cycle) -> Result<(), ()>;
pub type InitProcessFn = fn(&std::rc::Rc<Cycle>) -> Result<(), ()>;
pub type ExitFn = fn(&std::rc::Rc<Cycle>);

/// Core module context (ngx_core_module_t).
pub struct CoreModuleCtx {
    pub name: &'static str,
    pub create_conf: Option<fn(&mut Cycle) -> Rc<dyn Any>>,
    pub init_conf: Option<fn(&mut Cycle, &Rc<dyn Any>) -> Result<(), ()>>,
}

pub struct ModuleDef {
    pub name: &'static str,
    pub ty: u32,
    pub commands: Vec<Command>,
    /// Type specific context: CoreModuleCtx, EventModuleCtx, HttpModuleDef, ...
    pub ctx: Option<Rc<dyn Any>>,
    pub init_master: Option<InitFn>,
    pub init_module: Option<InitFn>,
    pub init_process: Option<InitProcessFn>,
    pub exit_process: Option<ExitFn>,
    pub exit_master: Option<ExitFn>,
}

impl ModuleDef {
    pub fn new(name: &'static str, ty: u32) -> ModuleDef {
        ModuleDef {
            name,
            ty,
            commands: Vec::new(),
            ctx: None,
            init_master: None,
            init_module: None,
            init_process: None,
            exit_process: None,
            exit_master: None,
        }
    }
}

pub struct Module {
    pub def: ModuleDef,
    /// Index in the global module list.
    pub index: usize,
    /// Index among modules of the same type.
    pub ctx_index: usize,
}

impl Module {
    pub fn ctx<T: 'static>(&self) -> Option<&T> {
        self.def.ctx.as_ref().and_then(|c| c.downcast_ref::<T>())
    }
}

/// Build the ordered module table, assigning indexes like ngx_preinit_modules.
pub fn build_modules(defs: Vec<ModuleDef>) -> Vec<Module> {
    let mut out = Vec::with_capacity(defs.len());
    let mut counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for (i, def) in defs.into_iter().enumerate() {
        let c = counts.entry(def.ty).or_insert(0);
        let ctx_index = *c;
        *c += 1;
        out.push(Module { def, index: i, ctx_index });
    }
    out
}

pub fn count_modules(modules: &[Module], ty: u32) -> usize {
    modules.iter().filter(|m| m.def.ty == ty).count()
}

pub fn find_module<'a>(modules: &'a [Module], name: &str) -> Option<&'a Module> {
    modules.iter().find(|m| m.def.name == name)
}
