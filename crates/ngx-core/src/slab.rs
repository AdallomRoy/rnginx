//! Slab allocator in shared memory (ngx_slab.c).
//!
//! Manages allocation of fixed-size slots and multi-page blocks within a zone.
//! The pool structure itself lives at the zone start; all data is plain C-compatible
//! repr(C) because it lives in shared memory mapped at the same address in all processes.

use std::sync::atomic::AtomicUsize;
use crate::shmtx::ShmTx;

const NGX_SLAB_PAGE_MASK: usize = 3;
const NGX_SLAB_PAGE: usize = 0;
const NGX_SLAB_BIG: usize = 1;
const NGX_SLAB_EXACT: usize = 2;
const NGX_SLAB_SMALL: usize = 3;

const NGX_SLAB_PAGE_FREE: usize = 0;
const NGX_SLAB_PAGE_BUSY: usize = if cfg!(target_pointer_width = "64") { 0xffffffffffffffff } else { 0xffffffff };
const NGX_SLAB_PAGE_START: usize = if cfg!(target_pointer_width = "64") { 0x8000000000000000 } else { 0x80000000 };

const NGX_SLAB_SHIFT_MASK: usize = 0x0000000f;
const NGX_SLAB_MAP_MASK: usize = if cfg!(target_pointer_width = "64") { 0xffffffff00000000 } else { 0xffff0000 };
const NGX_SLAB_MAP_SHIFT: usize = if cfg!(target_pointer_width = "64") { 32 } else { 16 };
const NGX_SLAB_BUSY: usize = NGX_SLAB_PAGE_BUSY;

static mut NGX_SLAB_MAX_SIZE: usize = 0;
static mut NGX_SLAB_EXACT_SIZE: usize = 0;
static mut NGX_SLAB_EXACT_SHIFT: usize = 0;

/// Slab page descriptor.
#[repr(C)]
pub struct SlabPage {
    pub slab: usize,
    pub next: *mut SlabPage,
    pub prev: usize,  // encoded: low 2 bits are type, upper bits are pointer
}

/// Statistics for a size class.
#[repr(C)]
pub struct SlabStat {
    pub total: usize,
    pub used: usize,
    pub reqs: usize,
    pub fails: usize,
}

/// Slab pool header (lives at the start of a shared zone).
#[repr(C)]
pub struct SlabPool {
    pub lock: AtomicUsize,  // the actual lock word in shared memory
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
    pub log_ctx: *mut u8,
    pub zero: u8,
    pub log_nomem: bool,
    pub data: *mut u8,
    pub addr: *mut u8,
}

/// Initialize the slab pool. Called once per zone on startup (or reload).
pub fn init_zone_pool(
    _cycle: &crate::cycle::Cycle,
    zone: &std::rc::Rc<crate::shm::ShmZone>,
) -> Result<(), ()> {
    let addr = zone.shm.addr.get();
    if addr.is_null() {
        return Err(());
    }

    // Check if this zone already exists from a previous cycle
    if zone.shm.exists.get() {
        return Ok(());
    }

    unsafe {
        let sp = addr as *mut SlabPool;

        // Initialize the slab sizes once (global state)
        slab_sizes_init();

        // Create the lock at the address of the lock field
        let lock_ptr = &mut (*sp).lock as *mut AtomicUsize;
        let mutex = ShmTx::create(lock_ptr);

        // Initialize the pool struct
        slab_init(sp, mutex);
    }

    zone.shm.exists.set(true);
    Ok(())
}

/// Cast zone address to SlabPool reference.
pub unsafe fn from_zone(addr: *mut u8) -> &'static SlabPool {
    &*(addr as *const SlabPool)
}

unsafe fn slab_sizes_init() {
    if NGX_SLAB_EXACT_SIZE != 0 {
        return;  // Already initialized
    }

    let pagesize = 4096;  // Linux page size
    NGX_SLAB_MAX_SIZE = pagesize / 2;
    NGX_SLAB_EXACT_SIZE = pagesize / (8 * std::mem::size_of::<usize>());

    let mut n = NGX_SLAB_EXACT_SIZE;
    let mut shift = 0;
    while n > 1 {
        n >>= 1;
        shift += 1;
    }
    NGX_SLAB_EXACT_SHIFT = shift;
}

unsafe fn slab_init(pool: *mut SlabPool, mutex: ShmTx) {
    let pagesize = 4096;
    let mut p = pool.offset(1) as *mut u8;
    let mut size = (*pool).end.offset_from(p) as usize;

    // Clear all memory
    std::ptr::write_bytes(p, 0, size);

    let n = 32 - (*pool).min_shift;  // 32 - 3 = 29 slots for 64-bit, or adjust for actual shift

    // Initialize slots
    let slots = p as *mut SlabPage;
    for i in 0..n {
        (*slots.offset(i as isize)).slab = 0;
        (*slots.offset(i as isize)).next = slots.offset(i as isize);
        (*slots.offset(i as isize)).prev = 0;
    }

    p = p.add(n * std::mem::size_of::<SlabPage>());
    size -= n * std::mem::size_of::<SlabPage>();

    // Initialize stats
    (*pool).stats = p as *mut SlabStat;
    std::ptr::write_bytes((*pool).stats, 0, n * std::mem::size_of::<SlabStat>());

    p = p.add(n * std::mem::size_of::<SlabStat>());
    size -= n * std::mem::size_of::<SlabStat>();

    // Calculate number of pages
    let pages_count = size / (pagesize + std::mem::size_of::<SlabPage>());

    // Initialize page array
    (*pool).pages = p as *mut SlabPage;
    std::ptr::write_bytes((*pool).pages, 0, pages_count * std::mem::size_of::<SlabPage>());

    let page = (*pool).pages;

    // Initialize free list
    (*pool).free.slab = 0;
    (*pool).free.next = page;
    (*pool).free.prev = 0;

    (*page).slab = pages_count;
    (*page).next = &mut (*pool).free;
    (*page).prev = &(*pool).free as *const _ as usize;

    // Align start to page boundary
    let meta_size = std::mem::size_of::<SlabPage>() * pages_count;
    let mut start = (p.add(meta_size) as usize + pagesize - 1) & !(pagesize - 1);
    (*pool).start = start as *mut u8;

    let m = pages_count as i32 - ((*pool).end.offset_from((*pool).start) as i32 / pagesize as i32);
    if m > 0 {
        (*page).slab = (pages_count as i32 - m) as usize;
    }

    (*pool).last = (*pool).pages.add(pages_count);
    (*pool).pfree = pages_count;

    (*pool).log_nomem = true;
    (*pool).log_ctx = &mut (*pool).zero;
    (*pool).zero = b'\0';
    (*pool).mutex = mutex;
    (*pool).data = std::ptr::null_mut();
    (*pool).addr = pool as *mut u8;
}

impl SlabPool {
    /// Allocate memory from the pool (thread-safe).
    pub fn alloc(&self, size: usize) -> *mut u8 {
        self.mutex.lock();
        let p = unsafe { self.alloc_locked(size) };
        self.mutex.unlock();
        p
    }

    /// Allocate memory from the pool (caller must hold lock).
    pub unsafe fn alloc_locked(&self, size: usize) -> *mut u8 {
        let pool = self as *const _ as *mut SlabPool;
        alloc_locked(pool, size)
    }

    /// Allocate and zero-fill memory (thread-safe).
    pub fn calloc(&self, size: usize) -> *mut u8 {
        self.mutex.lock();
        let p = unsafe { self.calloc_locked(size) };
        self.mutex.unlock();
        p
    }

    /// Allocate and zero-fill memory (caller must hold lock).
    pub unsafe fn calloc_locked(&self, size: usize) -> *mut u8 {
        let pool = self as *const _ as *mut SlabPool;
        let p = alloc_locked(pool, size);
        if !p.is_null() {
            std::ptr::write_bytes(p, 0, size);
        }
        p
    }

    /// Free memory back to the pool (thread-safe).
    pub fn free(&self, p: *mut u8) {
        self.mutex.lock();
        unsafe { self.free_locked(p) };
        self.mutex.unlock();
    }

    /// Free memory back to the pool (caller must hold lock).
    pub unsafe fn free_locked(&self, p: *mut u8) {
        let pool = self as *const _ as *mut SlabPool;
        free_locked(pool, p);
    }

    /// Acquire the pool lock.
    pub fn lock(&self) {
        self.mutex.lock();
    }

    /// Release the pool lock.
    pub fn unlock(&self) {
        self.mutex.unlock();
    }

    /// Set the log context string (stored inside the pool).
    pub unsafe fn set_log_ctx(&self, text: &[u8]) {
        let pool = self as *const _ as *mut SlabPool;
        // Store log_ctx as a copy in the pool's zeroed field area
        // For simplicity, we store the text directly after the first byte
        if text.len() < 64 {
            let ctx_ptr = &mut (*pool).zero as *mut u8;
            std::ptr::copy_nonoverlapping(text.as_ptr(), ctx_ptr, text.len());
        }
    }
}

unsafe fn alloc_locked(pool: *mut SlabPool, size: usize) -> *mut u8 {
    let pagesize = 4096;

    if size > NGX_SLAB_MAX_SIZE {
        // Allocate pages
        let pages = (size >> 12) + (if (size & 0xfff) != 0 { 1 } else { 0 });
        let page = alloc_pages(pool, pages);
        if !page.is_null() {
            return slab_page_addr(pool, page) as *mut u8;
        } else {
            return std::ptr::null_mut();
        }
    }

    // Calculate slot index
    let (shift, slot) = if size > (*pool).min_size {
        let mut shift = 1;
        let mut s = size - 1;
        while s > 0 {
            s >>= 1;
            shift += 1;
        }
        let slot = shift - (*pool).min_shift;
        (shift, slot)
    } else {
        ((*pool).min_shift, 0)
    };

    (*(*pool).stats.add(slot)).reqs += 1;

    let slots = pool.add(1) as *mut SlabPage;
    let mut page = (*slots.offset(slot as isize)).next;

    if page != &(*pool).free as *const _ as *mut SlabPage && (*page).next != page {
        if shift < NGX_SLAB_EXACT_SHIFT {
            // Small allocations with bitmap
            let bitmap = slab_page_addr(pool, page) as *mut usize;
            let map = (pagesize >> shift) / (8 * std::mem::size_of::<usize>());

            for n in 0..map {
                if (*bitmap.add(n)) != NGX_SLAB_BUSY {
                    for m_bit in 0..(8 * std::mem::size_of::<usize>()) {
                        let m = 1usize << m_bit;
                        if ((*bitmap.add(n)) & m) == 0 {
                            (*bitmap.add(n)) |= m;

                            let i = (n * 8 * std::mem::size_of::<usize>() + m_bit) << shift;
                            let p = bitmap as *mut u8 as usize + i;

                            (*(*pool).stats.add(slot)).used += 1;

                            if (*bitmap.add(n)) == NGX_SLAB_BUSY {
                                // Remove page from free list
                                let prev = slab_page_prev(page);
                                (*prev).next = (*page).next;
                                (*(*page).next).prev = (*page).prev;
                                (*page).next = std::ptr::null_mut();
                                (*page).prev = NGX_SLAB_SMALL;
                            }

                            return p as *mut u8;
                        }
                    }
                }
            }
        } else if shift == NGX_SLAB_EXACT_SHIFT {
            // Exact size allocations
            for m_bit in 0..(8 * std::mem::size_of::<usize>()) {
                let m = 1usize << m_bit;
                if ((*page).slab & m) == 0 {
                    (*page).slab |= m;

                    if (*page).slab == NGX_SLAB_BUSY {
                        let prev = slab_page_prev(page);
                        (*prev).next = (*page).next;
                        (*(*page).next).prev = (*page).prev;
                        (*page).next = std::ptr::null_mut();
                        (*page).prev = NGX_SLAB_EXACT;
                    }

                    let p = slab_page_addr(pool, page) + (m_bit << shift);

                    (*(*pool).stats.add(slot)).used += 1;

                    return p as *mut u8;
                }
            }
        } else {
            // Big allocations
            let mask = ((1usize << (pagesize >> shift)) - 1) << NGX_SLAB_MAP_SHIFT;

            for m_bit in 0..(pagesize >> shift) {
                let m = (1usize << NGX_SLAB_MAP_SHIFT) << m_bit;
                if ((*page).slab & m) == 0 {
                    (*page).slab |= m;

                    if ((*page).slab & NGX_SLAB_MAP_MASK) == mask {
                        let prev = slab_page_prev(page);
                        (*prev).next = (*page).next;
                        (*(*page).next).prev = (*page).prev;
                        (*page).next = std::ptr::null_mut();
                        (*page).prev = NGX_SLAB_BIG;
                    }

                    let p = slab_page_addr(pool, page) + (m_bit << shift);

                    (*(*pool).stats.add(slot)).used += 1;

                    return p as *mut u8;
                }
            }
        }
    }

    // Need to allocate a new page
    let page = alloc_pages(pool, 1);
    if page.is_null() {
        (*(*pool).stats.add(slot)).fails += 1;
        return std::ptr::null_mut();
    }

    if shift < NGX_SLAB_EXACT_SHIFT {
        let bitmap = slab_page_addr(pool, page) as *mut usize;
        let n = (pagesize >> shift) / ((1 << shift) * 8);
        let n = if n == 0 { 1 } else { n };

        for i in 0..((n + 1 + 8 * std::mem::size_of::<usize>() - 1) / (8 * std::mem::size_of::<usize>())) {
            *bitmap.add(i) = NGX_SLAB_BUSY;
        }

        let m = ((1usize << ((n + 1) % (8 * std::mem::size_of::<usize>()))) - 1);
        let i = (n + 8 * std::mem::size_of::<usize>() - 1) / (8 * std::mem::size_of::<usize>());
        *bitmap.add(i) = m;

        let map = (pagesize >> shift) / (8 * std::mem::size_of::<usize>());
        for i in i + 1..map {
            *bitmap.add(i) = 0;
        }

        (*page).slab = shift;
        (*page).next = slots.offset(slot as isize);
        (*page).prev = (slots.offset(slot as isize) as usize) | NGX_SLAB_SMALL;

        (*slots.offset(slot as isize)).next = page;

        (*(*pool).stats.add(slot)).total += (pagesize >> shift) - n;

        let p = slab_page_addr(pool, page) + (n << shift);
        (*(*pool).stats.add(slot)).used += 1;

        return p as *mut u8;
    } else if shift == NGX_SLAB_EXACT_SHIFT {
        (*page).slab = 1;
        (*page).next = slots.offset(slot as isize);
        (*page).prev = (slots.offset(slot as isize) as usize) | NGX_SLAB_EXACT;

        (*slots.offset(slot as isize)).next = page;

        (*(*pool).stats.add(slot)).total += 8 * std::mem::size_of::<usize>();
        (*(*pool).stats.add(slot)).used += 1;

        return slab_page_addr(pool, page) as *mut u8;
    } else {
        (*page).slab = (1usize << NGX_SLAB_MAP_SHIFT) | shift;
        (*page).next = slots.offset(slot as isize);
        (*page).prev = (slots.offset(slot as isize) as usize) | NGX_SLAB_BIG;

        (*slots.offset(slot as isize)).next = page;

        (*(*pool).stats.add(slot)).total += pagesize >> shift;
        (*(*pool).stats.add(slot)).used += 1;

        return slab_page_addr(pool, page) as *mut u8;
    }
}

unsafe fn free_locked(pool: *mut SlabPool, p: *mut u8) {
    let pagesize = 4096;

    if p < (*pool).start || p > (*pool).end {
        return;
    }

    let n = ((p as usize) - ((*pool).start as usize)) >> 12;
    let page = (*pool).pages.add(n);
    let slab = (*page).slab;
    let page_type = (*page).prev & NGX_SLAB_PAGE_MASK;

    match page_type {
        NGX_SLAB_SMALL => {
            let shift = slab & NGX_SLAB_SHIFT_MASK;
            let size = 1usize << shift;

            if ((p as usize) & (size - 1)) != 0 {
                return;
            }

            let n = ((p as usize) & (pagesize - 1)) >> shift;
            let m = 1usize << (n % (8 * std::mem::size_of::<usize>()));
            let n = n / (8 * std::mem::size_of::<usize>());
            let bitmap = ((p as usize) & !(pagesize - 1)) as *mut usize;

            if ((*bitmap.add(n)) & m) != 0 {
                let slot = shift - (*pool).min_shift;

                if (*page).next.is_null() {
                    let slots = pool.add(1) as *mut SlabPage;
                    (*page).next = (*slots.offset(slot as isize)).next;
                    (*slots.offset(slot as isize)).next = page;
                    (*page).prev = (slots.offset(slot as isize) as usize) | NGX_SLAB_SMALL;
                    (*(*page).next).prev = (page as usize) | NGX_SLAB_SMALL;
                }

                (*bitmap.add(n)) &= !m;

                let n_bits = (pagesize >> shift) / ((1 << shift) * 8);
                let n_bits = if n_bits == 0 { 1 } else { n_bits };

                let i = n_bits / (8 * std::mem::size_of::<usize>());
                let m = ((1usize << (n_bits % (8 * std::mem::size_of::<usize>()))) - 1);

                if ((*bitmap.add(i)) & !m) == 0 {
                    let map = (pagesize >> shift) / (8 * std::mem::size_of::<usize>());
                    let mut all_free = true;
                    for i in i + 1..map {
                        if *bitmap.add(i) != 0 {
                            all_free = false;
                            break;
                        }
                    }

                    if all_free {
                        free_pages(pool, page, 1);
                        (*(*pool).stats.add(slot)).total -= (pagesize >> shift) - n_bits;
                    }
                } else {
                    (*(*pool).stats.add(slot)).used -= 1;
                }
            }
        }
        NGX_SLAB_EXACT => {
            let m = 1usize << (((p as usize) & (pagesize - 1)) >> NGX_SLAB_EXACT_SHIFT);
            let size = NGX_SLAB_EXACT_SIZE;

            if ((p as usize) & (size - 1)) != 0 {
                return;
            }

            if (slab & m) != 0 {
                let slot = NGX_SLAB_EXACT_SHIFT - (*pool).min_shift;

                if slab == NGX_SLAB_BUSY {
                    let slots = pool.add(1) as *mut SlabPage;
                    (*page).next = (*slots.offset(slot as isize)).next;
                    (*slots.offset(slot as isize)).next = page;
                    (*page).prev = (slots.offset(slot as isize) as usize) | NGX_SLAB_EXACT;
                    (*(*page).next).prev = (page as usize) | NGX_SLAB_EXACT;
                }

                (*page).slab &= !m;

                if (*page).slab == 0 {
                    free_pages(pool, page, 1);
                    (*(*pool).stats.add(slot)).total -= 8 * std::mem::size_of::<usize>();
                } else {
                    (*(*pool).stats.add(slot)).used -= 1;
                }
            }
        }
        NGX_SLAB_BIG => {
            let shift = slab & NGX_SLAB_SHIFT_MASK;
            let size = 1usize << shift;

            if ((p as usize) & (size - 1)) != 0 {
                return;
            }

            let m = 1usize << ((((p as usize) & (pagesize - 1)) >> shift) + NGX_SLAB_MAP_SHIFT);

            if (slab & m) != 0 {
                let slot = shift - (*pool).min_shift;

                if (*page).next.is_null() {
                    let slots = pool.add(1) as *mut SlabPage;
                    (*page).next = (*slots.offset(slot as isize)).next;
                    (*slots.offset(slot as isize)).next = page;
                    (*page).prev = (slots.offset(slot as isize) as usize) | NGX_SLAB_BIG;
                    (*(*page).next).prev = (page as usize) | NGX_SLAB_BIG;
                }

                (*page).slab &= !m;

                if ((*page).slab & NGX_SLAB_MAP_MASK) == 0 {
                    free_pages(pool, page, 1);
                    (*(*pool).stats.add(slot)).total -= pagesize >> shift;
                } else {
                    (*(*pool).stats.add(slot)).used -= 1;
                }
            }
        }
        NGX_SLAB_PAGE => {
            if ((p as usize) & (pagesize - 1)) != 0 {
                return;
            }

            if (slab & NGX_SLAB_PAGE_START) != 0 {
                let size = slab & !NGX_SLAB_PAGE_START;
                free_pages(pool, page, size);
            }
        }
        _ => {}
    }
}

unsafe fn alloc_pages(pool: *mut SlabPool, pages: usize) -> *mut SlabPage {
    let mut page = (*pool).free.next;

    while page != &mut (*pool).free {
        if (*page).slab >= pages {
            if (*page).slab > pages {
                (*page.offset(((*page).slab - 1) as isize)).prev =
                    page.offset(pages as isize) as usize;

                (*page.offset(pages as isize)).slab = (*page).slab - pages;
                (*page.offset(pages as isize)).next = (*page).next;
                (*page.offset(pages as isize)).prev = (*page).prev;

                let p = ((*page).prev & !NGX_SLAB_PAGE_MASK) as *mut SlabPage;
                (*p).next = page.offset(pages as isize);
                (*(*page).next).prev = (page.offset(pages as isize)) as usize;
            } else {
                let p = ((*page).prev & !NGX_SLAB_PAGE_MASK) as *mut SlabPage;
                (*p).next = (*page).next;
                (*(*page).next).prev = (*page).prev;
            }

            (*page).slab = pages | NGX_SLAB_PAGE_START;
            (*page).next = std::ptr::null_mut();
            (*page).prev = NGX_SLAB_PAGE;

            (*pool).pfree -= pages;

            return page;
        }

        page = (*page).next;
    }

    std::ptr::null_mut()
}

unsafe fn free_pages(pool: *mut SlabPool, page: *mut SlabPage, pages: usize) {
    (*pool).pfree += pages;

    (*page).slab = pages - 1;

    if pages > 1 {
        std::ptr::write_bytes(page.offset(1), 0, (pages - 1) * std::mem::size_of::<SlabPage>());
    }

    if !(*page).next.is_null() {
        let prev = slab_page_prev(page);
        (*prev).next = (*page).next;
        (*(*page).next).prev = (*page).prev;
    }

    let join = page.offset((*page).slab as isize).offset(1);

    if (join as usize) < ((*pool).last as usize) {
        if ((*join).prev & NGX_SLAB_PAGE_MASK) == NGX_SLAB_PAGE {
            if !(*join).next.is_null() {
                (*page).slab += (*join).slab;

                let prev = slab_page_prev(join);
                (*prev).next = (*join).next;
                (*(*join).next).prev = (*join).prev;

                (*join).slab = NGX_SLAB_PAGE_FREE;
                (*join).next = std::ptr::null_mut();
                (*join).prev = NGX_SLAB_PAGE;
            }
        }
    }

    if page > (*pool).pages {
        let join = page.offset(-1);

        if ((*join).prev & NGX_SLAB_PAGE_MASK) == NGX_SLAB_PAGE {
            if (*join).slab == NGX_SLAB_PAGE_FREE {
                // Find the actual free page
            }

            if !(*join).next.is_null() {
                (*join).slab += (*page).slab;

                let prev = slab_page_prev(join);
                (*prev).next = (*join).next;
                (*(*join).next).prev = (*join).prev;

                (*page).slab = NGX_SLAB_PAGE_FREE;
                (*page).next = std::ptr::null_mut();
                (*page).prev = NGX_SLAB_PAGE;

                return;
            }
        }
    }

    (*page).prev = &(*pool).free as *const _ as usize;
    (*page).next = (*pool).free.next;
    (*(*page).next).prev = page as usize;
    (*pool).free.next = page;
}

#[inline]
unsafe fn slab_page_addr(pool: *const SlabPool, page: *const SlabPage) -> usize {
    let pagesize = 4096;
    ((page as usize - (*pool).pages as usize) / std::mem::size_of::<SlabPage>()) << 12
        + (*pool).start as usize
}

#[inline]
unsafe fn slab_page_prev(page: *const SlabPage) -> *mut SlabPage {
    ((*page).prev & !NGX_SLAB_PAGE_MASK) as *mut SlabPage
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    #[ignore]
    fn test_slab_pool_basic() {
        unsafe {
            // Allocate a shared zone
            let size = 1024 * 1024;  // 1MB for testing
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            );

            assert!(ptr != libc::MAP_FAILED);
            let pool = ptr as *mut SlabPool;

            // Initialize lock
            (*pool).lock = AtomicUsize::new(0);
            let lock_ptr = &mut (*pool).lock as *mut AtomicUsize;

            // Set up the pool
            (*pool).end = (ptr as usize + size) as *mut u8;
            (*pool).addr = pool as *mut u8;
            (*pool).data = std::ptr::null_mut();
            (*pool).min_shift = 3;
            (*pool).log_nomem = true;
            (*pool).zero = b'\0';
            (*pool).log_ctx = &mut (*pool).zero;

            slab_sizes_init();
            let mutex = ShmTx::create(lock_ptr);
            (*pool).mutex = mutex;
            slab_init(pool, mutex);

            // Test allocation
            let p1 = alloc_locked(pool, 64);
            assert!(!p1.is_null());

            let p2 = alloc_locked(pool, 128);
            assert!(!p2.is_null());

            // Pointers should be different
            assert_ne!(p1, p2);

            // Free and reuse
            free_locked(pool, p1);
            let p3 = alloc_locked(pool, 64);
            assert!(!p3.is_null());

            libc::munmap(ptr, size);
        }
    }
}
