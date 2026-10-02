//! Slab allocator in a zone (ngx_slab.c), on offsets.
//!
//! The pool header (ngx_slab_pool_t, laid out as in C) is at the start of
//! the zone; the slots, the stats and the page descriptors follow, then the
//! pages, from the first page boundary. Pointers are offsets in the zone
//! (0 for NULL); "prev" fields keep the page type in their two low bits as
//! C does, offsets of descriptors being multiples of 8.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::ShmMem;
use crate::log::*;
use crate::ngx_log_debug;
use crate::ngx_log_error;
use crate::shm_struct;
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
const WORD: usize = std::mem::size_of::<usize>();

shm_struct! {
    /// ngx_slab_pool_t (ngx_shmtx_sh_t and ngx_shmtx_t with their POSIX
    /// semaphore fields, unused here, keep the size of C)
    pub struct PoolHeader {
        /// ngx_shmtx_sh_t: the word the mutex works on
        lock: usize,
        wait: usize,
        min_size: usize,
        min_shift: usize,
        pages: usize,
        last: usize,
        /// free: the list head of the free pages (an ngx_slab_page_t)
        free_slab: usize,
        free_next: usize,
        free_prev: usize,
        stats: usize,
        pfree: usize,
        start: usize,
        end: usize,
        mutex_lock: usize,
        mutex_wait: usize,
        mutex_semaphore: usize,
        mutex_sem0: usize,
        mutex_sem1: usize,
        mutex_sem2: usize,
        mutex_sem3: usize,
        mutex_spin: usize,
        log_ctx: usize,
        zero: u8,
        log_nomem: u32,
        data: usize,
        addr: usize,
    }
}

shm_struct! {
    /// ngx_slab_page_t
    pub struct SlabPage {
        slab: usize,
        next: usize,
        prev: usize,
    }
}

shm_struct! {
    /// ngx_slab_stat_t
    pub struct SlabStat {
        total: usize,
        used: usize,
        reqs: usize,
        fails: usize,
    }
}

/// The values of a slot's ngx_slab_stat_t.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlabStats {
    pub total: usize,
    pub used: usize,
    pub reqs: usize,
    pub fails: usize,
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
    let exact = ps / (8 * WORD);
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

/// The slab pool of a zone (ngx_slab_pool_t *, the header at offset 0).
#[derive(Clone, Copy, Debug)]
pub struct SlabPool<'a> {
    pub mem: &'a ShmMem,
}

const FREE: usize = 6 * WORD;

impl<'a> SlabPool<'a> {
    /// The pool of the zone `mem`.
    pub fn of(mem: &'a ShmMem) -> SlabPool<'a> {
        SlabPool { mem }
    }

    #[inline]
    fn h(&self) -> PoolHeader<'a> {
        PoolHeader::at(self.mem, 0)
    }

    #[inline]
    fn page(&self, off: usize) -> SlabPage<'a> {
        SlabPage::at(self.mem, off)
    }

    #[inline]
    fn stat(&self, slot: usize) -> SlabStat<'a> {
        SlabStat::at(self.mem, self.h().get(PoolHeader::stats) + slot * SlabStat::SIZE)
    }

    /// The offset of the free list head (&pool->free).
    #[inline]
    fn free_head(&self) -> usize {
        FREE
    }

    /// ngx_slab_slots(pool)
    #[inline]
    fn slots(&self) -> usize {
        PoolHeader::SIZE
    }

    #[inline]
    fn page_type(&self, page: usize) -> usize {
        self.page(page).get(SlabPage::prev) & NGX_SLAB_PAGE_MASK
    }

    #[inline]
    fn page_prev(&self, page: usize) -> usize {
        self.page(page).get(SlabPage::prev) & !NGX_SLAB_PAGE_MASK
    }

    /// ngx_slab_page_addr(pool, page)
    #[inline]
    fn page_addr(&self, page: usize) -> usize {
        let h = self.h();
        (((page - h.get(PoolHeader::pages)) / SlabPage::SIZE) << pagesize_shift()) + h.get(PoolHeader::start)
    }

    /// The part of ngx_init_zone_pool that makes the pool of a new zone,
    /// and ngx_slab_init.
    pub fn init_zone(mem: &'a ShmMem) -> SlabPool<'a> {
        sizes_init();

        let pool = SlabPool::of(mem);
        let h = pool.h();

        h.set(PoolHeader::end, mem.len());
        h.set(PoolHeader::min_shift, 3);
        h.set(PoolHeader::addr, mem.addr());

        pool.init();

        pool
    }

    /// ngx_slab_init
    pub fn init(&self) {
        let h = self.h();
        let mem = self.mem;

        let min_shift = h.get(PoolHeader::min_shift);
        h.set(PoolHeader::min_size, 1 << min_shift);

        let slots = self.slots();

        let mut p = slots;
        let mut size = h.get(PoolHeader::end) - p;

        let n = pagesize_shift() - min_shift;

        for i in 0..n {
            // only "next" is used in list head
            let s = self.page(slots + i * SlabPage::SIZE);
            s.set(SlabPage::slab, 0);
            s.set(SlabPage::next, s.off);
            s.set(SlabPage::prev, 0);
        }

        p += n * SlabPage::SIZE;

        h.set(PoolHeader::stats, p);
        mem.fill(p, n * SlabStat::SIZE, 0);

        p += n * SlabStat::SIZE;

        size -= n * (SlabPage::SIZE + SlabStat::SIZE);

        let mut pages = size / (pagesize() + SlabPage::SIZE);

        h.set(PoolHeader::pages, p);
        mem.fill(p, pages * SlabPage::SIZE, 0);

        let page = self.page(p);

        // only "next" is used in list head
        h.set(PoolHeader::free_slab, 0);
        h.set(PoolHeader::free_next, page.off);
        h.set(PoolHeader::free_prev, 0);

        page.set(SlabPage::slab, pages);
        page.set(SlabPage::next, self.free_head());
        page.set(SlabPage::prev, self.free_head());

        let a = p + pages * SlabPage::SIZE;
        let start = (a + pagesize() - 1) & !(pagesize() - 1);
        h.set(PoolHeader::start, start);

        let m = pages as isize - ((h.get(PoolHeader::end) - start) / pagesize()) as isize;
        if m > 0 {
            pages -= m as usize;
            page.set(SlabPage::slab, pages);
        }

        h.set(PoolHeader::last, h.get(PoolHeader::pages) + pages * SlabPage::SIZE);
        h.set(PoolHeader::pfree, pages);

        h.set(PoolHeader::log_nomem, 1);
        h.set(PoolHeader::log_ctx, h.field(PoolHeader::zero));
        h.set(PoolHeader::zero, 0);
    }

    /// ngx_shmtx_lock(&pool->mutex)
    pub fn lock(&self) {
        super::lock::shmtx_lock(self.mem.word(0));
    }

    /// ngx_shmtx_trylock(&pool->mutex)
    pub fn trylock(&self) -> bool {
        super::lock::shmtx_trylock(self.mem.word(0))
    }

    /// ngx_shmtx_unlock(&pool->mutex)
    pub fn unlock(&self) {
        super::lock::shmtx_unlock(self.mem.word(0));
    }

    /// ngx_shmtx_force_unlock(&pool->mutex, pid)
    pub fn force_unlock(&self, pid: i32) -> bool {
        super::lock::shmtx_force_unlock(self.mem.word(0), pid)
    }

    /// pool->data
    pub fn data(&self) -> usize {
        self.h().get(PoolHeader::data)
    }

    pub fn set_data(&self, data: usize) {
        self.h().set(PoolHeader::data, data);
    }

    /// pool->log_nomem
    pub fn log_nomem(&self) -> bool {
        self.h().get(PoolHeader::log_nomem) != 0
    }

    pub fn set_log_nomem(&self, on: bool) {
        self.h().set(PoolHeader::log_nomem, on as u32);
    }

    /// pool->pfree: the free pages
    pub fn pfree(&self) -> usize {
        self.h().get(PoolHeader::pfree)
    }

    /// The pages of the pool ((pool->last - pool->pages) / sizeof(page)).
    pub fn pages(&self) -> usize {
        let h = self.h();
        (h.get(PoolHeader::last) - h.get(PoolHeader::pages)) / SlabPage::SIZE
    }

    /// pool->stats[slot]
    pub fn stats(&self, slot: usize) -> SlabStats {
        let s = self.stat(slot);
        SlabStats { total: s.get(SlabStat::total), used: s.get(SlabStat::used), reqs: s.get(SlabStat::reqs), fails: s.get(SlabStat::fails) }
    }

    /// The number of slots (pool->stats entries).
    pub fn slots_n(&self) -> usize {
        pagesize_shift() - self.h().get(PoolHeader::min_shift)
    }

    /// The pool's log_ctx: a copy of text allocated in the pool, as the
    /// zones do with ngx_slab_alloc() and ngx_sprintf().
    pub fn set_log_ctx(&self, text: &[u8]) -> Result<(), ()> {
        let p = self.alloc(text.len() + 1);
        if p == 0 {
            return Err(());
        }
        self.mem.write(p, text);
        self.mem.store::<u8>(p + text.len(), 0);
        self.h().set(PoolHeader::log_ctx, p);
        Ok(())
    }

    /// The log_ctx string.
    pub fn log_ctx(&self) -> Vec<u8> {
        let mut p = self.h().get(PoolHeader::log_ctx);
        let mut v = Vec::new();
        if p == 0 {
            return v;
        }
        while p < self.mem.len() {
            let c = self.mem.byte(p);
            if c == 0 {
                break;
            }
            v.push(c);
            p += 1;
        }
        v
    }

    /// ngx_slab_alloc
    pub fn alloc(&self, size: usize) -> usize {
        self.lock();
        let p = self.alloc_locked(size);
        self.unlock();
        p
    }

    /// ngx_slab_calloc
    pub fn calloc(&self, size: usize) -> usize {
        self.lock();
        let p = self.calloc_locked(size);
        self.unlock();
        p
    }

    /// ngx_slab_calloc_locked
    pub fn calloc_locked(&self, size: usize) -> usize {
        let p = self.alloc_locked(size);
        if p != 0 {
            self.mem.fill(p, size, 0);
        }
        p
    }

    /// ngx_slab_free
    pub fn free(&self, p: usize) {
        self.lock();
        self.free_locked(p);
        self.unlock();
    }

    fn addr_of(&self, p: usize) -> usize {
        self.mem.addr() + p
    }

    /// ngx_slab_alloc_locked: the offset of the chunk, 0 if none
    pub fn alloc_locked(&self, size: usize) -> usize {
        let h = self.h();
        let mem = self.mem;
        let p: usize;

        'done: {
            if size > slab_max_size() {
                if let Some(c) = crate::cycle::try_cycle() {
                    ngx_log_debug!(NGX_LOG_DEBUG_ALLOC, c.log, "slab alloc: {}", size);
                }

                let page = self.alloc_pages((size >> pagesize_shift()) + if size % pagesize() != 0 { 1 } else { 0 });
                p = if page != 0 { self.page_addr(page) } else { 0 };

                break 'done;
            }

            let min_size = h.get(PoolHeader::min_size);
            let min_shift = h.get(PoolHeader::min_shift);

            let (shift, slot) = if size > min_size {
                let mut shift = 1;
                let mut s = size - 1;
                while {
                    s >>= 1;
                    s != 0
                } {
                    shift += 1;
                }
                (shift, shift - min_shift)
            } else {
                (min_shift, 0)
            };

            let stats = self.stat(slot);
            stats.set(SlabStat::reqs, stats.get(SlabStat::reqs) + 1);

            if let Some(c) = crate::cycle::try_cycle() {
                ngx_log_debug!(NGX_LOG_DEBUG_ALLOC, c.log, "slab alloc: {} slot: {}", size, slot);
            }

            let slots = self.slots();
            let slot_head = slots + slot * SlabPage::SIZE;
            let page = self.page(self.page(slot_head).get(SlabPage::next));

            if page.get(SlabPage::next) != page.off {
                if shift < slab_exact_shift() {
                    let bitmap = self.page_addr(page.off);

                    let map = (pagesize() >> shift) / UINTPTR_BITS;

                    let mut n = 0;
                    while n < map {
                        let bn = bitmap + n * WORD;
                        if mem.get(bn) != NGX_SLAB_BUSY {
                            let mut m: usize = 1;
                            let mut i = 0;
                            while m != 0 {
                                if mem.get(bn) & m != 0 {
                                    m <<= 1;
                                    i += 1;
                                    continue;
                                }

                                mem.set(bn, mem.get(bn) | m);

                                let off = (n * UINTPTR_BITS + i) << shift;

                                p = bitmap + off;

                                stats.set(SlabStat::used, stats.get(SlabStat::used) + 1);

                                if mem.get(bn) == NGX_SLAB_BUSY {
                                    let mut k = n + 1;
                                    while k < map {
                                        if mem.get(bitmap + k * WORD) != NGX_SLAB_BUSY {
                                            break 'done;
                                        }
                                        k += 1;
                                    }

                                    let prev = self.page(self.page_prev(page.off));
                                    let next = page.get(SlabPage::next);
                                    prev.set(SlabPage::next, next);
                                    self.page(next).set(SlabPage::prev, page.get(SlabPage::prev));

                                    page.set(SlabPage::next, 0);
                                    page.set(SlabPage::prev, NGX_SLAB_SMALL);
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
                        if page.get(SlabPage::slab) & m != 0 {
                            m <<= 1;
                            i += 1;
                            continue;
                        }

                        page.set(SlabPage::slab, page.get(SlabPage::slab) | m);

                        if page.get(SlabPage::slab) == NGX_SLAB_BUSY {
                            let prev = self.page(self.page_prev(page.off));
                            let next = page.get(SlabPage::next);
                            prev.set(SlabPage::next, next);
                            self.page(next).set(SlabPage::prev, page.get(SlabPage::prev));

                            page.set(SlabPage::next, 0);
                            page.set(SlabPage::prev, NGX_SLAB_EXACT);
                        }

                        p = self.page_addr(page.off) + (i << shift);

                        stats.set(SlabStat::used, stats.get(SlabStat::used) + 1);

                        break 'done;
                    }
                } else {
                    // shift > ngx_slab_exact_shift
                    let mask = ((1usize << (pagesize() >> shift)) - 1) << NGX_SLAB_MAP_SHIFT;

                    let mut m: usize = 1 << NGX_SLAB_MAP_SHIFT;
                    let mut i = 0;
                    while m & mask != 0 {
                        if page.get(SlabPage::slab) & m != 0 {
                            m <<= 1;
                            i += 1;
                            continue;
                        }

                        page.set(SlabPage::slab, page.get(SlabPage::slab) | m);

                        if page.get(SlabPage::slab) & NGX_SLAB_MAP_MASK == mask {
                            let prev = self.page(self.page_prev(page.off));
                            let next = page.get(SlabPage::next);
                            prev.set(SlabPage::next, next);
                            self.page(next).set(SlabPage::prev, page.get(SlabPage::prev));

                            page.set(SlabPage::next, 0);
                            page.set(SlabPage::prev, NGX_SLAB_BIG);
                        }

                        p = self.page_addr(page.off) + (i << shift);

                        stats.set(SlabStat::used, stats.get(SlabStat::used) + 1);

                        break 'done;
                    }
                }

                self.error(NGX_LOG_ALERT, "ngx_slab_alloc(): page is busy");
            }

            let page = self.alloc_pages(1);

            if page != 0 {
                let page = self.page(page);

                if shift < slab_exact_shift() {
                    let bitmap = self.page_addr(page.off);

                    let mut n = (pagesize() >> shift) / ((1 << shift) * 8);

                    if n == 0 {
                        n = 1;
                    }

                    // "n" elements for bitmap, plus one requested

                    let mut i = 0;
                    while i < (n + 1) / UINTPTR_BITS {
                        mem.set(bitmap + i * WORD, NGX_SLAB_BUSY);
                        i += 1;
                    }

                    let m = (1usize << ((n + 1) % UINTPTR_BITS)) - 1;
                    mem.set(bitmap + i * WORD, m);

                    let map = (pagesize() >> shift) / UINTPTR_BITS;

                    i += 1;
                    while i < map {
                        mem.set(bitmap + i * WORD, 0);
                        i += 1;
                    }

                    page.set(SlabPage::slab, shift);
                    page.set(SlabPage::next, slot_head);
                    page.set(SlabPage::prev, slot_head | NGX_SLAB_SMALL);

                    self.page(slot_head).set(SlabPage::next, page.off);

                    stats.set(SlabStat::total, stats.get(SlabStat::total) + (pagesize() >> shift) - n);

                    p = self.page_addr(page.off) + (n << shift);

                    stats.set(SlabStat::used, stats.get(SlabStat::used) + 1);

                    break 'done;
                } else if shift == slab_exact_shift() {
                    page.set(SlabPage::slab, 1);
                    page.set(SlabPage::next, slot_head);
                    page.set(SlabPage::prev, slot_head | NGX_SLAB_EXACT);

                    self.page(slot_head).set(SlabPage::next, page.off);

                    stats.set(SlabStat::total, stats.get(SlabStat::total) + UINTPTR_BITS);

                    p = self.page_addr(page.off);

                    stats.set(SlabStat::used, stats.get(SlabStat::used) + 1);

                    break 'done;
                } else {
                    // shift > ngx_slab_exact_shift
                    page.set(SlabPage::slab, (1usize << NGX_SLAB_MAP_SHIFT) | shift);
                    page.set(SlabPage::next, slot_head);
                    page.set(SlabPage::prev, slot_head | NGX_SLAB_BIG);

                    self.page(slot_head).set(SlabPage::next, page.off);

                    stats.set(SlabStat::total, stats.get(SlabStat::total) + (pagesize() >> shift));

                    p = self.page_addr(page.off);

                    stats.set(SlabStat::used, stats.get(SlabStat::used) + 1);

                    break 'done;
                }
            }

            p = 0;

            stats.set(SlabStat::fails, stats.get(SlabStat::fails) + 1);
        }

        if let Some(c) = crate::cycle::try_cycle() {
            ngx_log_debug!(NGX_LOG_DEBUG_ALLOC, c.log, "slab alloc: {:#x}", if p == 0 { 0 } else { self.addr_of(p) });
        }

        p
    }

    /// ngx_slab_free_locked
    pub fn free_locked(&self, p: usize) {
        let h = self.h();
        let mem = self.mem;

        if let Some(c) = crate::cycle::try_cycle() {
            ngx_log_debug!(NGX_LOG_DEBUG_ALLOC, c.log, "slab free: {:#x}", self.addr_of(p));
        }

        if p < h.get(PoolHeader::start) || p > h.get(PoolHeader::end) {
            self.error(NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
            return;
        }

        let n = (p - h.get(PoolHeader::start)) >> pagesize_shift();
        let page = self.page(h.get(PoolHeader::pages) + n * SlabPage::SIZE);
        let slab = page.get(SlabPage::slab);
        let typ = self.page_type(page.off);
        let min_shift = h.get(PoolHeader::min_shift);

        // the chunk size and the slot of "done:"
        let slot: usize;

        match typ {
            NGX_SLAB_SMALL => {
                let shift = slab & NGX_SLAB_SHIFT_MASK;
                let size = 1 << shift;

                if p & (size - 1) != 0 {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong chunk");
                    return;
                }

                let mut n = (p & (pagesize() - 1)) >> shift;
                let mut m = 1usize << (n % UINTPTR_BITS);
                n /= UINTPTR_BITS;
                let bitmap = p & !(pagesize() - 1);

                if mem.get(bitmap + n * WORD) & m == 0 {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): chunk is already free");
                    return;
                }

                slot = shift - min_shift;

                if page.get(SlabPage::next) == 0 {
                    let slot_head = self.slots() + slot * SlabPage::SIZE;

                    page.set(SlabPage::next, self.page(slot_head).get(SlabPage::next));
                    self.page(slot_head).set(SlabPage::next, page.off);

                    page.set(SlabPage::prev, slot_head | NGX_SLAB_SMALL);
                    self.page(page.get(SlabPage::next)).set(SlabPage::prev, page.off | NGX_SLAB_SMALL);
                }

                mem.set(bitmap + n * WORD, mem.get(bitmap + n * WORD) & !m);

                let mut n = (pagesize() >> shift) / ((1 << shift) * 8);

                if n == 0 {
                    n = 1;
                }

                let mut i = n / UINTPTR_BITS;
                m = (1usize << (n % UINTPTR_BITS)) - 1;

                'check: {
                    if mem.get(bitmap + i * WORD) & !m != 0 {
                        break 'check;
                    }

                    let map = (pagesize() >> shift) / UINTPTR_BITS;

                    i += 1;
                    while i < map {
                        if mem.get(bitmap + i * WORD) != 0 {
                            break 'check;
                        }
                        i += 1;
                    }

                    self.free_pages(page.off, 1);

                    let s = self.stat(slot);
                    s.set(SlabStat::total, s.get(SlabStat::total) - ((pagesize() >> shift) - n));
                }
            }

            NGX_SLAB_EXACT => {
                let m = 1usize << ((p & (pagesize() - 1)) >> slab_exact_shift());
                let size = slab_exact_size();

                if p & (size - 1) != 0 {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong chunk");
                    return;
                }

                if slab & m == 0 {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): chunk is already free");
                    return;
                }

                slot = slab_exact_shift() - min_shift;

                if slab == NGX_SLAB_BUSY {
                    let slot_head = self.slots() + slot * SlabPage::SIZE;

                    page.set(SlabPage::next, self.page(slot_head).get(SlabPage::next));
                    self.page(slot_head).set(SlabPage::next, page.off);

                    page.set(SlabPage::prev, slot_head | NGX_SLAB_EXACT);
                    self.page(page.get(SlabPage::next)).set(SlabPage::prev, page.off | NGX_SLAB_EXACT);
                }

                page.set(SlabPage::slab, page.get(SlabPage::slab) & !m);

                if page.get(SlabPage::slab) == 0 {
                    self.free_pages(page.off, 1);

                    let s = self.stat(slot);
                    s.set(SlabStat::total, s.get(SlabStat::total) - UINTPTR_BITS);
                }
            }

            NGX_SLAB_BIG => {
                let shift = slab & NGX_SLAB_SHIFT_MASK;
                let size = 1 << shift;

                if p & (size - 1) != 0 {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong chunk");
                    return;
                }

                let m = 1usize << (((p & (pagesize() - 1)) >> shift) + NGX_SLAB_MAP_SHIFT);

                if slab & m == 0 {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): chunk is already free");
                    return;
                }

                slot = shift - min_shift;

                if page.get(SlabPage::next) == 0 {
                    let slot_head = self.slots() + slot * SlabPage::SIZE;

                    page.set(SlabPage::next, self.page(slot_head).get(SlabPage::next));
                    self.page(slot_head).set(SlabPage::next, page.off);

                    page.set(SlabPage::prev, slot_head | NGX_SLAB_BIG);
                    self.page(page.get(SlabPage::next)).set(SlabPage::prev, page.off | NGX_SLAB_BIG);
                }

                page.set(SlabPage::slab, page.get(SlabPage::slab) & !m);

                if page.get(SlabPage::slab) & NGX_SLAB_MAP_MASK == 0 {
                    self.free_pages(page.off, 1);

                    let s = self.stat(slot);
                    s.set(SlabStat::total, s.get(SlabStat::total) - (pagesize() >> shift));
                }
            }

            _ => {
                // NGX_SLAB_PAGE
                if p & (pagesize() - 1) != 0 {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong chunk");
                    return;
                }

                if slab & NGX_SLAB_PAGE_START == 0 {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): page is already free");
                    return;
                }

                if slab == NGX_SLAB_PAGE_BUSY {
                    self.error(NGX_LOG_ALERT, "ngx_slab_free(): pointer to wrong page");
                    return;
                }

                let size = slab & !NGX_SLAB_PAGE_START;

                self.free_pages(page.off, size);

                return;
            }
        }

        // done:
        let s = self.stat(slot);
        s.set(SlabStat::used, s.get(SlabStat::used) - 1);
    }

    /// ngx_slab_alloc_pages: the descriptor of the first page, 0 if none
    fn alloc_pages(&self, pages: usize) -> usize {
        let h = self.h();
        let free = self.free_head();
        let mut page = h.get(PoolHeader::free_next);
        let mut pages = pages;

        while page != free {
            let pg = self.page(page);
            let slab = pg.get(SlabPage::slab);

            if slab >= pages {
                let after = self.page(page + pages * SlabPage::SIZE);

                if slab > pages {
                    self.page(page + (slab - 1) * SlabPage::SIZE).set(SlabPage::prev, after.off);

                    after.set(SlabPage::slab, slab - pages);
                    after.set(SlabPage::next, pg.get(SlabPage::next));
                    after.set(SlabPage::prev, pg.get(SlabPage::prev));

                    let p = self.page(pg.get(SlabPage::prev));
                    p.set(SlabPage::next, after.off);
                    self.page(pg.get(SlabPage::next)).set(SlabPage::prev, after.off);
                } else {
                    let p = self.page(pg.get(SlabPage::prev));
                    p.set(SlabPage::next, pg.get(SlabPage::next));
                    self.page(pg.get(SlabPage::next)).set(SlabPage::prev, pg.get(SlabPage::prev));
                }

                pg.set(SlabPage::slab, pages | NGX_SLAB_PAGE_START);
                pg.set(SlabPage::next, 0);
                pg.set(SlabPage::prev, NGX_SLAB_PAGE);

                h.set(PoolHeader::pfree, h.get(PoolHeader::pfree) - pages);

                pages -= 1;
                if pages == 0 {
                    return page;
                }

                let mut p = page + SlabPage::SIZE;
                while pages > 0 {
                    let q = self.page(p);
                    q.set(SlabPage::slab, NGX_SLAB_PAGE_BUSY);
                    q.set(SlabPage::next, 0);
                    q.set(SlabPage::prev, NGX_SLAB_PAGE);
                    p += SlabPage::SIZE;
                    pages -= 1;
                }

                return page;
            }

            page = pg.get(SlabPage::next);
        }

        if self.log_nomem() {
            self.error(NGX_LOG_CRIT, "ngx_slab_alloc() failed: no memory");
        }

        0
    }

    /// ngx_slab_free_pages
    fn free_pages(&self, page: usize, pages: usize) {
        let h = self.h();
        let mut page = self.page(page);
        let mut pages = pages;

        h.set(PoolHeader::pfree, h.get(PoolHeader::pfree) + pages);

        page.set(SlabPage::slab, pages);
        pages -= 1;

        if pages > 0 {
            self.mem.fill(page.off + SlabPage::SIZE, pages * SlabPage::SIZE, 0);
        }

        if page.get(SlabPage::next) != 0 {
            let prev = self.page(self.page_prev(page.off));
            prev.set(SlabPage::next, page.get(SlabPage::next));
            self.page(page.get(SlabPage::next)).set(SlabPage::prev, page.get(SlabPage::prev));
        }

        let join = self.page(page.off + page.get(SlabPage::slab) * SlabPage::SIZE);

        if join.off < h.get(PoolHeader::last) && self.page_type(join.off) == NGX_SLAB_PAGE && join.get(SlabPage::next) != 0 {
            pages += join.get(SlabPage::slab);
            page.set(SlabPage::slab, page.get(SlabPage::slab) + join.get(SlabPage::slab));

            let prev = self.page(self.page_prev(join.off));
            prev.set(SlabPage::next, join.get(SlabPage::next));
            self.page(join.get(SlabPage::next)).set(SlabPage::prev, join.get(SlabPage::prev));

            join.set(SlabPage::slab, NGX_SLAB_PAGE_FREE);
            join.set(SlabPage::next, 0);
            join.set(SlabPage::prev, NGX_SLAB_PAGE);
        }

        if page.off > h.get(PoolHeader::pages) {
            let mut join = self.page(page.off - SlabPage::SIZE);

            if self.page_type(join.off) == NGX_SLAB_PAGE {
                if join.get(SlabPage::slab) == NGX_SLAB_PAGE_FREE {
                    join = self.page(self.page_prev(join.off));
                }

                if join.get(SlabPage::next) != 0 {
                    pages += join.get(SlabPage::slab);
                    join.set(SlabPage::slab, join.get(SlabPage::slab) + page.get(SlabPage::slab));

                    let prev = self.page(self.page_prev(join.off));
                    prev.set(SlabPage::next, join.get(SlabPage::next));
                    self.page(join.get(SlabPage::next)).set(SlabPage::prev, join.get(SlabPage::prev));

                    page.set(SlabPage::slab, NGX_SLAB_PAGE_FREE);
                    page.set(SlabPage::next, 0);
                    page.set(SlabPage::prev, NGX_SLAB_PAGE);

                    page = join;
                }
            }
        }

        if pages > 0 {
            self.page(page.off + pages * SlabPage::SIZE).set(SlabPage::prev, page.off);
        }

        page.set(SlabPage::prev, self.free_head());
        page.set(SlabPage::next, h.get(PoolHeader::free_next));

        self.page(page.get(SlabPage::next)).set(SlabPage::prev, page.off);

        h.set(PoolHeader::free_next, page.off);
    }

    /// ngx_slab_error
    fn error(&self, level: u32, text: &str) {
        if let Some(c) = crate::cycle::try_cycle() {
            ngx_log_error!(level, c.log, None, "{}{}", text, B(&self.log_ctx()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_ngx_slab_pool_t() {
        // sizeof(ngx_slab_pool_t) of x86-64 Linux, with POSIX semaphores
        assert_eq!(PoolHeader::SIZE, 200);
        assert_eq!(PoolHeader::free_slab.off, FREE);
        assert_eq!(PoolHeader::zero.off, 176);
        assert_eq!(PoolHeader::log_nomem.off, 180);
        assert_eq!(SlabPage::SIZE, 24);
        assert_eq!(SlabStat::SIZE, 32);
    }

    #[test]
    fn alloc_free_all_sizes() {
        let mem = ShmMem::private(8 << 20).unwrap();
        let sp = SlabPool::init_zone(&mem);
        let pfree = sp.pfree();
        let mut offs = Vec::new();

        for size in [1usize, 8, 9, 16, 17, 60, 64, 65, 100, 128, 200, 1000, 2048, 2049, 5000, 9000] {
            for _ in 0..50 {
                let p = sp.alloc(size);
                assert!(p != 0, "size {}", size);
                assert!(p + size <= mem.len());
                mem.fill(p, size, 0x5a);
                offs.push((p, size));
            }
        }

        let mut sorted = offs.clone();
        sorted.sort();
        for w in sorted.windows(2) {
            assert!(w[0].0 + w[0].1 <= w[1].0, "overlap {:?}", w);
        }

        for (p, _) in offs.iter().rev() {
            sp.free(*p);
        }

        assert_eq!(sp.pfree(), pfree);

        for slot in 0..sp.slots_n() {
            assert_eq!(sp.stats(slot).used, 0, "slot {}", slot);
        }
    }

    #[test]
    fn no_memory() {
        let mem = ShmMem::private(64 << 10).unwrap();
        let sp = SlabPool::init_zone(&mem);
        let pages = sp.pfree();
        assert!(pages > 0 && pages <= 16);

        let mut got = Vec::new();
        loop {
            let p = sp.alloc(4096);
            if p == 0 {
                break;
            }
            got.push(p);
        }
        assert_eq!(got.len(), pages);
        assert_eq!(sp.pfree(), 0);

        for p in got {
            sp.free(p);
        }
        assert_eq!(sp.pfree(), pages);

        // freed pages are joined again: one allocation of all of them
        let p = sp.alloc(pages * 4096);
        assert!(p != 0);
        sp.free(p);
    }

    #[test]
    fn calloc_and_log_ctx() {
        let mem = ShmMem::private(1 << 20).unwrap();
        let sp = SlabPool::init_zone(&mem);
        assert_eq!(sp.log_ctx(), b"");

        let p = sp.alloc(100);
        mem.fill(p, 100, 0xff);
        sp.free(p);
        let q = sp.calloc(100);
        assert_eq!(q, p, "the chunk is reused");
        assert_eq!(mem.bytes(q, 100), vec![0u8; 100]);

        sp.set_log_ctx(b" in zone \"one\"").unwrap();
        assert_eq!(sp.log_ctx(), b" in zone \"one\"");

        sp.set_data(q);
        assert_eq!(sp.data(), q);
        assert!(sp.log_nomem());
        sp.set_log_nomem(false);
        assert!(!sp.log_nomem());
    }
}
