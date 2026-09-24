//! Shared memory zones (ngx_shmem.c / ngx_cycle.c zone handling).

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::log::*;
use crate::ngx_log_error;

pub struct Shm {
    pub addr: Cell<*mut u8>,
    pub size: usize,
    pub name: Vec<u8>,
    pub exists: Cell<bool>,
}

impl Shm {
    pub fn alloc(&self, log: &Log) -> Result<(), ()> {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                self.size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(errno()), "mmap(MAP_ANON|MAP_SHARED, {}) failed", self.size);
            return Err(());
        }
        self.addr.set(p as *mut u8);
        Ok(())
    }

    pub fn free(&self, log: &Log) {
        let p = self.addr.get();
        if p.is_null() {
            return;
        }
        if unsafe { libc::munmap(p as *mut libc::c_void, self.size) } == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(errno()), "munmap({:p}, {}) failed", p, self.size);
        }
        self.addr.set(std::ptr::null_mut());
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
            shm: Shm { addr: Cell::new(std::ptr::null_mut()), size, name, exists: Cell::new(false) },
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

    /// Slab pool at the start of the zone.
    pub fn pool(&self) -> &crate::slab::SlabPool {
        unsafe { &*(self.shm.addr.get() as *const crate::slab::SlabPool) }
    }
}
