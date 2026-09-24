//! Slab allocator in shared memory (ngx_slab.c). Placeholder API; full port follows.

use std::cell::Cell;

#[repr(C)]
pub struct SlabPool {
    pub lock: Cell<u64>,
    pub min_size: usize,
    pub min_shift: usize,
    pub start: *mut u8,
    pub end: *mut u8,
    pub data: Cell<*mut u8>,
    pub addr: *mut u8,
    pub log_nomem: bool,
}

/// ngx_init_zone_pool: initialize the slab pool header in a fresh zone.
pub fn init_zone_pool(cycle: &crate::cycle::Cycle, zone: &std::rc::Rc<crate::shm::ShmZone>) -> Result<(), ()> {
    let _ = cycle;
    let addr = zone.shm.addr.get();
    if addr.is_null() {
        return Err(());
    }
    unsafe {
        let sp = addr as *mut SlabPool;
        std::ptr::write(sp, SlabPool {
            lock: Cell::new(0),
            min_size: 8,
            min_shift: 3,
            start: addr.add(std::mem::size_of::<SlabPool>()),
            end: addr.add(zone.shm.size),
            data: Cell::new(addr.add(std::mem::size_of::<SlabPool>())),
            addr,
            log_nomem: true,
        });
    }
    Ok(())
}
