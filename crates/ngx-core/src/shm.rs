//! Shared memory zones (ngx_shmem.c / ngx_cycle.c zone handling).

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::log::*;
use crate::ngx_log_error;
use crate::shmem::ShmMem;

pub struct Shm {
    pub addr: Cell<*mut u8>,
    pub size: Cell<usize>,
    pub name: Vec<u8>,
    pub exists: Cell<bool>,
    /// the cycle's log, set when the zone is created or reused
    pub log: RefCell<Option<Log>>,
}

thread_local! {
    /// The zones' mappings of the process, found by their addresses
    /// (shm.addr): a zone reused by a new cycle gets the address only.
    static MAPPINGS: RefCell<Vec<Rc<ShmMem>>> = const { RefCell::new(Vec::new()) };
}

impl Shm {
    /// ngx_shm_alloc: mmap(MAP_ANON|MAP_SHARED) of the zone's size.
    pub fn alloc(&self, log: &Log) -> Result<(), ()> {
        let mem = match ShmMem::shared(self.size.get()) {
            Ok(m) => Rc::new(m),
            Err(e) => {
                ngx_log_error!(NGX_LOG_ALERT, log, e.raw_os_error(), "mmap(MAP_ANON|MAP_SHARED, {}) failed", self.size.get());
                return Err(());
            }
        };
        self.addr.set(mem.addr());
        MAPPINGS.with(|m| m.borrow_mut().push(mem));
        Ok(())
    }

    /// ngx_shm_free: the mapping goes (munmap()) when the last user of it
    /// in the process drops it.
    pub fn free(&self, _log: &Log) {
        let p = self.addr.get();
        if p.is_null() {
            return;
        }
        MAPPINGS.with(|m| m.borrow_mut().retain(|mem| mem.addr() != p));
        self.addr.set(std::ptr::null_mut());
    }

    /// Makes `mem` the zone's memory (tests: a private mapping).
    pub fn attach(&self, mem: Rc<ShmMem>) {
        self.addr.set(mem.addr());
        MAPPINGS.with(|m| m.borrow_mut().push(mem));
    }

    /// The memory of the zone, once allocated.
    pub fn mem(&self) -> Option<Rc<ShmMem>> {
        let p = self.addr.get();
        if p.is_null() {
            return None;
        }
        MAPPINGS.with(|m| m.borrow().iter().find(|mem| mem.addr() == p).cloned())
    }
}

/// Zone init callback: receives the zone and the previous cycle's data (on reload).
pub type ShmZoneInit = Rc<dyn Fn(&Rc<ShmZone>, Option<Rc<dyn Any>>) -> Result<(), ()>>;

pub struct ShmZone {
    pub shm: Shm,
    pub init: RefCell<Option<ShmZoneInit>>,
    /// Per-process descriptor for the zone contents (set by init).
    pub data: RefCell<Option<Rc<dyn Any>>>,
    /// Module identity used to detect reuse (pointer of module def in C; a name here).
    pub tag: &'static str,
    /// Config-time data shared between the directive that created the zone and users.
    pub conf: RefCell<Option<Rc<dyn Any>>>,
    pub noreuse: Cell<bool>,
    pub sync: Cell<bool>,
}

impl ShmZone {
    pub fn new(name: Vec<u8>, size: usize, tag: &'static str) -> Rc<ShmZone> {
        Rc::new(ShmZone {
            shm: Shm { addr: Cell::new(std::ptr::null_mut()), size: Cell::new(size), name, exists: Cell::new(false), log: RefCell::new(None) },
            init: RefCell::new(None),
            data: RefCell::new(None),
            tag,
            conf: RefCell::new(None),
            noreuse: Cell::new(false),
            sync: Cell::new(false),
        })
    }

    pub fn name(&self) -> &[u8] {
        &self.shm.name
    }

    pub fn data<T: 'static>(&self) -> Option<Rc<T>> {
        self.data.borrow().clone().and_then(|d| d.downcast::<T>().ok())
    }

    pub fn conf<T: 'static>(&self) -> Option<Rc<T>> {
        self.conf.borrow().clone().and_then(|d| d.downcast::<T>().ok())
    }

    /// The memory of the zone (allocated when the cycle is initialized,
    /// before the zone's init callback).
    pub fn mem(&self) -> Rc<ShmMem> {
        self.shm.mem().unwrap_or_else(|| panic!("shared zone \"{}\" has no memory", crate::string::B(&self.shm.name)))
    }
}

/// ngx_init_zone_pool: the slab pool of a new zone (the "shared zone has
/// no equal addresses" check of a zone that already existed is for
/// Windows only: zones are always new here).
pub fn init_zone_pool(_cycle: &crate::cycle::Cycle, zone: &Rc<ShmZone>) -> Result<(), ()> {
    crate::shmem::slab::SlabPool::init_zone(&zone.mem());
    Ok(())
}
