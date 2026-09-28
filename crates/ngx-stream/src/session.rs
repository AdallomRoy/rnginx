//! ngx_stream_session_t

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::connection::Connection;

use crate::variables::VariableValue;
use crate::*;

/// ngx_stream_session_t
pub struct Session {
    pub connection: Rc<Connection>,

    pub received: Cell<i64>,
    pub start_sec: Cell<i64>,
    pub start_msec: Cell<u64>,

    /// s->log_handler: the context the content module adds to the
    /// connection's log lines
    pub log_handler: RefCell<Option<Rc<dyn Fn(&Session, &mut Vec<u8>)>>>,

    pub ctx: RefCell<Vec<Option<Rc<dyn Any>>>>,
    pub main_conf: Rc<ConfSlots>,
    pub srv_conf: RefCell<Rc<ConfSlots>>,

    pub virtual_names: Option<Rc<VirtualNames>>,

    pub upstream: RefCell<Option<Rc<crate::upstream::StreamUpstream>>>,
    pub upstream_states: RefCell<Vec<crate::upstream::UpstreamState>>,

    pub variables: RefCell<Vec<VariableValue>>,

    pub ncaptures: Cell<usize>,
    pub captures: RefCell<Vec<i32>>,
    pub captures_data: RefCell<Vec<u8>>,

    pub phase_handler: Cell<usize>,
    pub status: Cell<i64>,

    pub ssl: Cell<bool>,

    pub stat_processing: Cell<bool>,
    pub health_check: Cell<bool>,

    pub limit_conn_status: Cell<u32>,

    /// ngx_stream_finalize_session() was called
    pub finalized: Cell<bool>,

}

pub type S = Rc<Session>;

impl Session {
    pub fn new(c: &Rc<Connection>, main_conf: Rc<ConfSlots>, srv_conf: Rc<ConfSlots>, virtual_names: Option<Rc<VirtualNames>>) -> S {
        Rc::new(Session {
            connection: c.clone(),
            received: Cell::new(0),
            start_sec: Cell::new(0),
            start_msec: Cell::new(0),
            log_handler: RefCell::new(None),
            ctx: RefCell::new(vec![None; stream_max_module()]),
            main_conf,
            srv_conf: RefCell::new(srv_conf),
            virtual_names,
            upstream: RefCell::new(None),
            upstream_states: RefCell::new(Vec::new()),
            variables: RefCell::new(Vec::new()),
            ncaptures: Cell::new(0),
            captures: RefCell::new(Vec::new()),
            captures_data: RefCell::new(Vec::new()),
            phase_handler: Cell::new(0),
            status: Cell::new(0),
            ssl: Cell::new(false),
            stat_processing: Cell::new(false),
            health_check: Cell::new(false),
            limit_conn_status: Cell::new(0),
            finalized: Cell::new(false),
        })
    }

    /// ngx_stream_get_module_main_conf
    pub fn main_conf<T: 'static>(&self, idx: usize) -> Rc<RefCell<T>> {
        slot::<T>(&self.main_conf, idx)
    }

    /// ngx_stream_get_module_srv_conf
    pub fn srv_conf<T: 'static>(&self, idx: usize) -> Rc<RefCell<T>> {
        let slots = self.srv_conf.borrow().clone();
        slot::<T>(&slots, idx)
    }

    pub fn cmcf(&self) -> Rc<RefCell<crate::core::CoreMainConf>> {
        self.main_conf::<crate::core::CoreMainConf>(crate::core::ctx_index())
    }

    pub fn cscf(&self) -> Rc<RefCell<crate::core::CoreSrvConf>> {
        self.srv_conf::<crate::core::CoreSrvConf>(crate::core::ctx_index())
    }

    /// ngx_stream_get_module_ctx
    pub fn get_ctx<T: 'static>(&self, idx: usize) -> Option<Rc<T>> {
        self.ctx.borrow().get(idx).cloned().flatten().and_then(|c| c.downcast::<T>().ok())
    }

    /// ngx_stream_set_ctx
    pub fn set_ctx<T: 'static>(&self, idx: usize, c: Rc<T>) {
        let mut ctx = self.ctx.borrow_mut();
        if ctx.len() <= idx {
            ctx.resize(idx + 1, None);
        }
        ctx[idx] = Some(c);
    }

    /// ngx_stream_delete_ctx
    pub fn delete_ctx(&self, idx: usize) {
        let mut ctx = self.ctx.borrow_mut();
        if idx < ctx.len() {
            ctx[idx] = None;
        }
    }
}
