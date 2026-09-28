//! Slab allocator in shared memory (ngx_slab.c).
//!
//! The pool header lives at the start of a zone; pages and chunks of the
//! rest are handed out from it. Everything is plain repr(C) data: the zone
//! is mapped at the same address in all processes.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::log::*;
use crate::ngx_log_debug;
use crate::ngx_log_error;
use crate::shmtx::ShmTx;
use crate::string::B;

const NGX_SLAB_PAGE_MASK: usize = 3;
const NGX_SLAB_PAGE: usize = 0;
const NGX_SLAB_BIG: usize = 1;
const NGX_SLAB_EXACT: usize = 2;
const NGX_SLAB_SMALL: usize = 3;

const NGX_SLAB_PAGE_FREE: usize = 0;
const NGX_SLAB_PAGE_BUSY: usize = usize::MAX;
const NGX_SLAB_PAGE_START: usize = 1 << (usize::BITS - 1);

const NGX_SLAB_SHIFT_MASK: usize = 0xf;
const NGX_SLAB_MAP_SHIFT: usize = usize::BITS as usize / 2;
const NGX_SLAB_MAP_MASK: usize = usize::MAX << NGX_SLAB_MAP_SHIFT;

const NGX_SLAB_BUSY: usize = usize::MAX;

const UINTPTR_BITS: usize = usize::BITS as usize;

#[repr(C)]
pub struct SlabPage {
    pub slab: usize,
    pub next: *mut SlabPage,
    pub prev: usize,
}

#[repr(C)]
pub struct SlabStat {
    pub total: usize,
    pub used: usize,
    pub reqs: usize,
    pub fails: usize,
}

/// ngx_slab_pool_t
#[repr(C)]
pub struct SlabPool {
    /// ngx_shmtx_sh_t: the lock word the mutex works on
    pub lock: AtomicUsize,
    pub min_size: usize,
    pub min_shift: usize,
    pub pages: *mut SlabPage,
    pub last: *mut SlabPage,
    pub free: SlabPage,
    pub stats: *mut SlabStat,
    pub pfree: usize,
    pub start: *mut u8,
    pub end: *mut u8,
    pub mutex: ShmTx,
    /// a NUL-terminated string appended to allocation errors
    pub log_ctx: *mut u8,
    pub zero: u8,
    pub log_nomem: bool,
    pub data: *mut u8,
    pub addr: *mut u8,
}

static NGX_PAGESIZE: AtomicUsize = AtomicUsize::new(0);
static NGX_PAGESIZE_SHIFT: AtomicUsize = AtomicUsize::new(0);
static NGX_SLAB_MAX_SIZE: AtomicUsize = AtomicUsize::new(0);
static NGX_SLAB_EXACT_SIZE: AtomicUsize = AtomicUsize::new(0);
static NGX_SLAB_EXACT_SHIFT: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn pagesize() -> usize {
    NGX_PAGESIZE.load(Ordering::Relaxed)
}

#[inline]
fn pagesize_shift() -> usize {
    NGX_PAGESIZE_SHIFT.load(Ordering::Relaxed)
}

#[inline]
fn slab_max_size() -> usize {
    NGX_SLAB_MAX_SIZE.load(Ordering::Relaxed)
}

#[inline]
fn slab_exact_size() -> usize {
    NGX_SLAB_EXACT_SIZE.load(Ordering::Relaxed)
}

#[inline]
fn slab_exact_shift() -> usize {
    NGX_SLAB_EXACT_SHIFT.load(Ordering::Relaxed)
}

/// ngx_slab_sizes_init (with ngx_pagesize and ngx_pagesize_shift of
/// ngx_os_init)
pub fn sizes_init() {
    let ps = crate::os::pagesize();
    let mut shift = 0;
    let mut n = ps;
    while {
        n >>= 1;
        n != 0
    } {
        shift += 1;
    }
    NGX_PAGESIZE.store(ps, Ordering::Relaxed);
    NGX_PAGESIZE_SHIFT.store(shift, Ordering::Relaxed);

    NGX_SLAB_MAX_SIZE.store(ps / 2, Ordering::Relaxed);
    let exact = ps / (8 * std::mem::size_of::<usize>());
    NGX_SLAB_EXACT_SIZE.store(exact, Ordering::Relaxed);

    let mut exact_shift = 0;
    let mut n = exact;
    while {
        n >>= 1;
        n != 0
    } {
        exact_shift += 1;
    }
    NGX_SLAB_EXACT_SHIFT.store(exact_shift, Ordering::Relaxed);
}

#[inline]
unsafe fn slab_slots(pool: *mut SlabPool) -> *mut SlabPage {
    (pool as *mut u8).add(std::mem::size_of::<SlabPool>()) as *mut SlabPage
}

#[inline]
unsafe fn slab_page_type(page: *mut SlabPage) -> usize {
    (*page).prev & NGX_SLAB_PAGE_MASK
}

#[inline]
unsafe fn slab_page_prev(page: *mut SlabPage) -> *mut SlabPage {
    ((*page).prev & !NGX_SLAB_PAGE_MASK) as *mut SlabPage
}

#[inline]
unsafe fn slab_page_addr(pool: *mut SlabPool, page: *mut SlabPage) -> usize {
    ((page.offset_from((*pool).pages) as usize) << pagesize_shift()) + (*pool).start as usize
}

/// ngx_init_zone_pool: the pool at the start of a new zone.
pub fn init_zone_pool(cycle: &crate::cycle::Cycle, zone: &std::rc::Rc<crate::shm::ShmZone>) -> Result<(), ()> {
    let addr = zone.shm.addr.get();
    let sp = addr as *mut SlabPool;

    unsafe {
        if zone.shm.exists.get() {
            if (*sp).addr == addr {
                return Ok(());
            }

            ngx_log_error!(
                NGX_LOG_EMERG,
                cycle.log,
                None,
                "shared zone \"{}\" has no equal addresses: {:p} vs {:p}",
                B(&zone.shm.name),
                (*sp).addr,
                sp
            );
            return Err(());
        }

        sizes_init();

        (*sp).end = addr.add(zone.shm.size.get());
        (*sp).min_shift = 3;
        (*sp).addr = addr;

        let mutex = ShmTx::create(&mut (*sp).lock as *mut AtomicUsize);
        std::ptr::write(&mut (*sp).mutex, mutex);

        slab_init(sp);
    }

    Ok(())
}

/// Cast a zone address to its pool.
pub unsafe fn from_zone(addr: *mut u8) -> &'static SlabPool {
    &*(addr as *const SlabPool)
}

/// ngx_slab_init
pub unsafe fn slab_init(pool: *mut SlabPool) {
    (*pool).min_size = 1 << (*pool).min_shift;

    let slots = slab_slots(pool);

    let mut p = slots as *mut u8;
    let mut size = (*pool).end.offset_from(p) as usize;

    let n = pagesize_shift() - (*pool).min_shift;

    for i in 0..n {
        // only "next" is used in list head
        let s = slots.add(i);
        (*s).slab = 0;
        (*s).next = s;
        (*s).prev = 0;
    }

    p = p.add(n * std::mem::size_of::<SlabPage>());

    (*pool).stats = p as *mut SlabStat;
    std::ptr::write_bytes((*pool).stats, 0, n);

    p = p.add(n * std::mem::size_of::<SlabStat>());

    size -= n * (std::mem::size_of::<SlabPage>() + std::mem::size_of::<SlabStat>());

    let mut pages = size / (pagesize() + std::mem::size_of::<SlabPage>());

    (*pool).pages = p as *mut SlabPage;
    std::ptr::write_bytes((*pool).pages, 0, pages);

    let page = (*pool).pages;

    // only "next" is used in list head
    (*pool).free.slab = 0;
    (*pool).free.next = page;
    (*pool).free.prev = 0;

    (*page).slab = pages;
    (*page).next = &mut (*pool).free;
    (*page).prev = &mut (*pool).free as *mut SlabPage as usize;

    let a = p.add(pages * std::mem::size_of::<SlabPage>()) as usize;
    (*pool).start = ((a + pagesize() - 1) & !(pagesize() - 1)) as *mut u8;

    let m = pages as isize - ((*pool).end.offset_from((*pool).start) / pagesize() as isize);
    if m > 0 {
        pages -= m as usize;
        (*page).slab = pages;
    }

    (*pool).last = (*pool).pages.add(pages);
    (*pool).pfree = pages;

    (*pool).log_nomem = true;
    (*pool).log_ctx = &mut (*pool).zero;
    (*pool).zero = 0;
}

impl SlabPool {
    /// ngx_slab_alloc
    pub fn alloc(&self, size: usize) -> *mut u8 {
        self.mutex.lock();
        let p = unsafe { self.alloc_locked(size) };
        self.mutex.unlock();
        p
    }

    /// ngx_slab_alloc_locked
    pub unsafe fn alloc_locked(&self, size: usize) -> *mut u8 {
        slab_alloc_locked(self as *const SlabPool as *mut SlabPool, size)
    }

    /// ngx_slab_calloc
    pub fn calloc(&self, size: usize) -> *mut u8 {
        self.mutex.lock();
        let p = unsafe { self.calloc_locked(size) };
        self.mutex.unlock();
        p
    }

    /// ngx_slab_calloc_locked
    pub unsafe fn calloc_locked(&self, size: usize) -> *mut u8 {
        let p = self.alloc_locked(size);
        if !p.is_null() {
            std::ptr::write_bytes(p, 0, size);
        }
        p
    }

    /// ngx_slab_free
    pub fn free(&self, p: *mut u8) {
        self.mutex.lock();
        unsafe { self.free_locked(p) };
        self.mutex.unlock();
    }

    /// ngx_slab_free_locked
    pub unsafe fn free_locked(&self, p: *mut u8) {
        slab_free_locked(self as *const SlabPool as *mut SlabPool, p);
    }

    /// ngx_shmtx_lock(&pool->mutex)
    pub fn lock(&self) {
        self.mutex.lock();
    }

    /// ngx_shmtx_unlock(&pool->mutex)
    pub fn unlock(&self) {
        self.mutex.unlock();
    }

    /// The pool's log_ctx: a copy of text allocated in the pool, as the
    /// zones do with ngx_slab_alloc() and ngx_sprintf().
    pub unsafe fn set_log_ctx(&self, text: &[u8]) -> Result<(), ()> {
        let pool = self as *const SlabPool as *mut SlabPool;
        let p = self.alloc(text.len() + 1);
        if p.is_null() {
            return Err(());
        }
        std::ptr::copy_nonoverlapping(text.as_ptr(), p, text.len());
        *p.add(text.len()) = 0;
        (*pool).log_ctx = p;
        Ok(())
    }

    /// The log_ctx string.
    pub fn log_ctx(&self) -> &[u8] {
        unsafe {
            if self.log_ctx.is_null() {
                return b"";
            }
            std::ffi::CStr::from_ptr(self.log_ctx as *const libc::c_char).to_bytes()
        }
    }
}

unsafe fn slab_alloc_locked(pool: *mut SlabPool, size: usize) -> *mut u8 {
    let p: usize;

    'done: {
        if size > slab_max_size() {
            if let Some(c) = crate::cycle::try_cycle() {
                ngx_log_debug!(NGX_LOG_DEBUG_ALLOC, c.log, "slab alloc: {}", size);
            }

            let page = slab_alloc_pages(pool, (size >> pagesize_shift()) + if size % pagesize() != 0 { 1 } else { 0 });
            p = if !page.is_null() { slab_page_addr(pool, page) } else { 0 };

            break 'done;
        }

        let (shift, slot) = if size > (*pool).min_size {
            let mut shift = 1;
            let mut s = size - 1;
            while {
                s >>= 1;
                s != 0
            } {
                shift += 1;
            }
            (shift, shift - (*pool).min_shift)
        } else {
            ((*pool).min_shift, 0)
        };

        let stats = (*pool).stats.add(slot);
        (*stats).reqs += 1;

        if let Some(c) = crate::cycle::try_cycle() {
            ngx_log_debug!(NGX_LOG_DEBUG_ALLOC, c.log, "slab alloc: {} slot: {}", size, slot);
        }

        let slots = slab_slots(pool);
        let page = (*slots.add(slot)).next;

        if (*page).next != page {
            if shift < slab_exact_shift() {
                let bitmap = slab_page_addr(pool, page) as *mut usize;

                let map = (pagesize() >> shift) / UINTPTR_BITS;

                let mut n = 0;
                while n < map {
                    if *bitmap.add(n) != NGX_SLAB_BUSY {
                        let mut m: usize = 1;
                        let mut i = 0;
                        while m != 0 {
                            if *bitmap.add(n) & m != 0 {
                                m <<= 1;
                                i += 1;
                                continue;
                            }

                            *bitmap.add(n) |= m;

                            let off = (n * UINTPTR_BITS + i) << shift;

                            p = bitmap as usize + off;

                            (*stats).used += 1;

                            if *bitmap.add(n) == NGX_SLAB_BUSY {
                                let mut k = n + 1;
                                while k < map {
                                    if *bitmap.add(k) != NGX_SLAB_BUSY {
                                        break 'done;
                                    }
                                    k += 1;
                                }

                                let prev = slab_page_prev(page);
                                (*prev).next = (*page).next;
                                (*(*page).next).prev = (*page).prev;

                                (*page).next = std::ptr::null_mut();
                                (*page).prev = NGX_SLAB_SMALL;
                            }

                            break 'done;
                        }
                    }
                    n += 1;
                }
            } else if shift == slab_exact_shift() {
                let mut m: usize = 1;
                let mut i = 0;
                while m != 0 {
                    if (*page).slab & m != 0 {
                        m <<= 1;
                        i += 1;
                        continue;
                    }

                    (*page).slab |= m;

                    if (*page).slab == NGX_SLAB_BUSY {
                        let prev = slab_page_prev(page);
                        (*prev).next = (*page).next;
                        (*(*page).next).prev = (*page).prev;

                        (*page).next = std::ptr::null_mut();
                        (*page).prev = NGX_SLAB_EXACT;
                    }

                    p = slab_page_addr(pool, page) + (i << shift);

                    (*stats).used += 1;

                    break 'done;
                }
            } else {
                // shift > ngx_slab_exact_shift
                let mask = ((1usize << (pagesize() >> shift)) - 1) << NGX_SLAB_MAP_SHIFT;

                let mut m: usize = 1 << NGX_SLAB_MAP_SHIFT;
                let mut i = 0;
                while m & mask != 0 {
                    if (*page).slab & m != 0 {
                        m <<= 1;
                        i += 1;
                        continue;
                    }

                    (*page).slab |= m;

                    if (*page).slab & NGX_SLAB_MAP_MASK == mask {
                        let prev = slab_page_prev(page);
                        (*prev).next = (*page).next;
                        (*(*page).next).prev = (*page).prev;

                        (*page).next = std::ptr::null_mut();
                        (*page).prev = NGX_SLAB_BIG;
                    }

                    p = slab_page_addr(pool, page) + (i << shift);

                    (*stats).used += 1;

                    break 'done;
                }
            }

            slab_error(pool, NGX_LOG_ALERT, "ngx_slab_alloc(): page is busy");
        }

        let page = slab_alloc_pages(pool, 1);

        if !page.is_null() {
            if shift < slab_exact_shift() {
                let bitmap = slab_page_addr(pool, page) as *mut usize;

                let mut n = (pagesize() >> shift) / ((1 << shift) * 8);

                if n == 0 {
                    n = 1;
                }

                // "n" elements for bitmap, plus one requested

                let mut i = 0;
                while i < (n + 1) / UINTPTR_BITS {
                    *bitmap.add(i) = NGX_SLAB_BUSY;
                    i += 1;
                }

                let m = (1usize << ((n + 1) % UINTPTR_BITS)) - 1;
                *bitmap.add(i) = m;

                let map = (pagesize() >> shift) / UINTPTR_BITS;

                i += 1;
                while i < map {
                    *bitmap.add(i) = 0;
                    i += 1;
                }

                (*page).slab = shift;
                (*page).next = slots.add(slot);
                (*page).prev = slots.add(slot) as usize | NGX_SLAB_SMALL;

                (*slots.add(slot)).next = page;

                (*stats).total += (pagesize() >> shift) - n;

                p = slab_page_addr(pool, page) + (n << shift);

                (*stats).used += 1;

                break 'done;
            } else if shift == slab_exact_shift() {
                (*page).slab = 1;
                (*page).next = slots.add(slot);
                (*page).prev = slots.add(slot) as usize | NGX_SLAB_EXACT;

                (*slots.add(slot)).next = page;

                (*stats).total += UINTPTR_BITS;

                p = slab_page_addr(pool, page);

                (*stats).used += 1;

                break 'done;
            } else {
                // shift > ngx_slab_exact_shift
                (*page).slab = (1usize << NGX_SLAB_MAP_SHIFT) | shift;
                (*page).next = slots.add(slot);
                (*page).prev = slots.add(slot) as usize | NGX_SLAB_BIG;

                (*slots.add(slot)).next = page;

                (*stats).total += pagesize() >> shift;

                p = slab_page_addr(pool, page);

                (*stats).used += 1;

                break 'done;
            }
        }

        p = 0;

        (*stats).fails += 1;
    }

    if let Some(c) = crate::cycle::try_cycle() {
        ngx_log_debug!(NGX_LOG_DEBUG_ALLOC, c.log, "slab alloc: {:p}", p as *const u8);
    }

    p as *mut u8
}

unsafe fn slab_free_locked(pool: *mut SlabPool, p: *mut u8) {
    if let Some(c) = crate::cycle::try_cycle() {
        ngx_log_debug!(NGX_LOG_DEBUG_ALLOC, c.log, "slab free: {:p}", p);
    }

    if p < (*pool).start || p > (*pool).end {
        slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
        return;
    }

    let pu = p as usize;

    let n = (pu - (*pool).start as usize) >> pagesize_shift();
    let page = (*pool).pages.add(n);
    let slab = (*page).slab;
    let typ = slab_page_type(page);

    // the chunk size and the slot of "done:"
    let (size, slot): (usize, usize);

    match typ {
        NGX_SLAB_SMALL => {
            let shift = slab & NGX_SLAB_SHIFT_MASK;
            size = 1 << shift;

            if pu & (size - 1) != 0 {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong chunk");
                return;
            }

            let mut n = (pu & (pagesize() - 1)) >> shift;
            let mut m = 1usize << (n % UINTPTR_BITS);
            n /= UINTPTR_BITS;
            let bitmap = (pu & !(pagesize() - 1)) as *mut usize;

            if *bitmap.add(n) & m == 0 {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): chunk is already free");
                return;
            }

            slot = shift - (*pool).min_shift;

            if (*page).next.is_null() {
                let slots = slab_slots(pool);

                (*page).next = (*slots.add(slot)).next;
                (*slots.add(slot)).next = page;

                (*page).prev = slots.add(slot) as usize | NGX_SLAB_SMALL;
                (*(*page).next).prev = page as usize | NGX_SLAB_SMALL;
            }

            *bitmap.add(n) &= !m;

            let mut n = (pagesize() >> shift) / ((1 << shift) * 8);

            if n == 0 {
                n = 1;
            }

            let mut i = n / UINTPTR_BITS;
            m = (1usize << (n % UINTPTR_BITS)) - 1;

            'check: {
                if *bitmap.add(i) & !m != 0 {
                    break 'check;
                }

                let map = (pagesize() >> shift) / UINTPTR_BITS;

                i += 1;
                while i < map {
                    if *bitmap.add(i) != 0 {
                        break 'check;
                    }
                    i += 1;
                }

                slab_free_pages(pool, page, 1);

                (*(*pool).stats.add(slot)).total -= (pagesize() >> shift) - n;
            }
        }

        NGX_SLAB_EXACT => {
            let m = 1usize << ((pu & (pagesize() - 1)) >> slab_exact_shift());
            size = slab_exact_size();

            if pu & (size - 1) != 0 {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong chunk");
                return;
            }

            if slab & m == 0 {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): chunk is already free");
                return;
            }

            slot = slab_exact_shift() - (*pool).min_shift;

            if slab == NGX_SLAB_BUSY {
                let slots = slab_slots(pool);

                (*page).next = (*slots.add(slot)).next;
                (*slots.add(slot)).next = page;

                (*page).prev = slots.add(slot) as usize | NGX_SLAB_EXACT;
                (*(*page).next).prev = page as usize | NGX_SLAB_EXACT;
            }

            (*page).slab &= !m;

            if (*page).slab == 0 {
                slab_free_pages(pool, page, 1);

                (*(*pool).stats.add(slot)).total -= UINTPTR_BITS;
            }
        }

        NGX_SLAB_BIG => {
            let shift = slab & NGX_SLAB_SHIFT_MASK;
            size = 1 << shift;

            if pu & (size - 1) != 0 {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong chunk");
                return;
            }

            let m = 1usize << (((pu & (pagesize() - 1)) >> shift) + NGX_SLAB_MAP_SHIFT);

            if slab & m == 0 {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): chunk is already free");
                return;
            }

            slot = shift - (*pool).min_shift;

            if (*page).next.is_null() {
                let slots = slab_slots(pool);

                (*page).next = (*slots.add(slot)).next;
                (*slots.add(slot)).next = page;

                (*page).prev = slots.add(slot) as usize | NGX_SLAB_BIG;
                (*(*page).next).prev = page as usize | NGX_SLAB_BIG;
            }

            (*page).slab &= !m;

            if (*page).slab & NGX_SLAB_MAP_MASK == 0 {
                slab_free_pages(pool, page, 1);

                (*(*pool).stats.add(slot)).total -= pagesize() >> shift;
            }
        }

        _ => {
            // NGX_SLAB_PAGE
            if pu & (pagesize() - 1) != 0 {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong chunk");
                return;
            }

            if slab & NGX_SLAB_PAGE_START == 0 {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): page is already free");
                return;
            }

            if slab == NGX_SLAB_PAGE_BUSY {
                slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong page");
                return;
            }

            let size = slab & !NGX_SLAB_PAGE_START;

            slab_free_pages(pool, page, size);

            return;
        }
    }

    // done:
    let _ = size;
    (*(*pool).stats.add(slot)).used -= 1;
}

/// ngx_slab_alloc_pages
unsafe fn slab_alloc_pages(pool: *mut SlabPool, pages: usize) -> *mut SlabPage {
    let free = &mut (*pool).free as *mut SlabPage;
    let mut page = (*pool).free.next;
    let mut pages = pages;

    while page != free {
        if (*page).slab >= pages {
            if (*page).slab > pages {
                (*page.add((*page).slab - 1)).prev = page.add(pages) as usize;

                (*page.add(pages)).slab = (*page).slab - pages;
                (*page.add(pages)).next = (*page).next;
                (*page.add(pages)).prev = (*page).prev;

                let p = (*page).prev as *mut SlabPage;
                (*p).next = page.add(pages);
                (*(*page).next).prev = page.add(pages) as usize;
            } else {
                let p = (*page).prev as *mut SlabPage;
                (*p).next = (*page).next;
                (*(*page).next).prev = (*page).prev;
            }

            (*page).slab = pages | NGX_SLAB_PAGE_START;
            (*page).next = std::ptr::null_mut();
            (*page).prev = NGX_SLAB_PAGE;

            (*pool).pfree -= pages;

            pages -= 1;
            if pages == 0 {
                return page;
            }

            let mut p = page.add(1);
            while pages > 0 {
                (*p).slab = NGX_SLAB_PAGE_BUSY;
                (*p).next = std::ptr::null_mut();
                (*p).prev = NGX_SLAB_PAGE;
                p = p.add(1);
                pages -= 1;
            }

            return page;
        }

        page = (*page).next;
    }

    if (*pool).log_nomem {
        slab_error(pool, NGX_LOG_CRIT, "ngx_slab_alloc() failed: no memory");
    }

    std::ptr::null_mut()
}

/// ngx_slab_free_pages
unsafe fn slab_free_pages(pool: *mut SlabPool, page: *mut SlabPage, pages: usize) {
    let mut page = page;
    let mut pages = pages;

    (*pool).pfree += pages;

    (*page).slab = pages;
    pages -= 1;

    if pages > 0 {
        std::ptr::write_bytes(page.add(1), 0, pages);
    }

    if !(*page).next.is_null() {
        let prev = slab_page_prev(page);
        (*prev).next = (*page).next;
        (*(*page).next).prev = (*page).prev;
    }

    let join = page.add((*page).slab);

    if join < (*pool).last && slab_page_type(join) == NGX_SLAB_PAGE && !(*join).next.is_null() {
        pages += (*join).slab;
        (*page).slab += (*join).slab;

        let prev = slab_page_prev(join);
        (*prev).next = (*join).next;
        (*(*join).next).prev = (*join).prev;

        (*join).slab = NGX_SLAB_PAGE_FREE;
        (*join).next = std::ptr::null_mut();
        (*join).prev = NGX_SLAB_PAGE;
    }

    if page > (*pool).pages {
        let mut join = page.sub(1);

        if slab_page_type(join) == NGX_SLAB_PAGE {
            if (*join).slab == NGX_SLAB_PAGE_FREE {
                join = slab_page_prev(join);
            }

            if !(*join).next.is_null() {
                pages += (*join).slab;
                (*join).slab += (*page).slab;

                let prev = slab_page_prev(join);
                (*prev).next = (*join).next;
                (*(*join).next).prev = (*join).prev;

                (*page).slab = NGX_SLAB_PAGE_FREE;
                (*page).next = std::ptr::null_mut();
                (*page).prev = NGX_SLAB_PAGE;

                page = join;
            }
        }
    }

    if pages > 0 {
        (*page.add(pages)).prev = page as usize;
    }

    (*page).prev = &mut (*pool).free as *mut SlabPage as usize;
    (*page).next = (*pool).free.next;

    (*(*page).next).prev = page as usize;

    (*pool).free.next = page;
}

/// ngx_slab_error
unsafe fn slab_error(pool: *mut SlabPool, level: u32, text: &str) {
    if let Some(c) = crate::cycle::try_cycle() {
        ngx_log_error!(level, c.log, None, "{}{}", text, B((*pool).log_ctx()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn pool_of(mem: &mut Vec<u64>) -> *mut SlabPool {
        sizes_init();
        let addr = mem.as_mut_ptr() as *mut u8;
        let sp = addr as *mut SlabPool;
        (*sp).end = addr.add(mem.len() * 8);
        (*sp).min_shift = 3;
        (*sp).addr = addr;
        std::ptr::write(&mut (*sp).mutex, ShmTx::create(&mut (*sp).lock as *mut AtomicUsize));
        slab_init(sp);
        sp
    }

    #[test]
    fn alloc_free_all_sizes() {
        let mut mem = vec![0u64; 1 << 19];
        unsafe {
            let sp = pool_of(&mut mem);
            let pfree = (*sp).pfree;
            let mut ptrs = Vec::new();
            for size in [1usize, 8, 9, 16, 17, 60, 64, 65, 100, 128, 200, 1000, 2048, 2049, 5000, 9000] {
                for _ in 0..50 {
                    let p = (*sp).alloc(size);
                    assert!(!p.is_null(), "size {}", size);
                    std::ptr::write_bytes(p, 0x5a, size);
                    ptrs.push((p, size));
                }
            }
            let mut sorted: Vec<(usize, usize)> = ptrs.iter().map(|(p, s)| (*p as usize, *s)).collect();
            sorted.sort();
            for w in sorted.windows(2) {
                assert!(w[0].0 + w[0].1 <= w[1].0, "overlap {:?}", w);
            }
            for (p, _) in ptrs.iter().rev() {
                (*sp).free(*p);
            }
            assert_eq!((*sp).pfree, pfree);
        }
    }
}
