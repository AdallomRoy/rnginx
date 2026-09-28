//! Read-write spinlock on an atomic word in shared memory (ngx_rwlock.c).

use std::sync::atomic::{AtomicUsize, Ordering};

const NGX_RWLOCK_SPIN: usize = 2048;
const NGX_RWLOCK_WLOCK: usize = usize::MAX;

#[inline]
fn ncpu() -> usize {
    use std::sync::OnceLock;
    static NCPU: OnceLock<usize> = OnceLock::new();
    *NCPU.get_or_init(crate::os::ncpu)
}

#[inline]
fn cmp_set(lock: &AtomicUsize, old: usize, set: usize) -> bool {
    lock.compare_exchange(old, set, Ordering::AcqRel, Ordering::Relaxed).is_ok()
}

/// ngx_rwlock_wlock
pub fn wlock(lock: &AtomicUsize) {
    loop {
        if lock.load(Ordering::Relaxed) == 0 && cmp_set(lock, 0, NGX_RWLOCK_WLOCK) {
            return;
        }

        if ncpu() > 1 {
            let mut n = 1;
            while n < NGX_RWLOCK_SPIN {
                for _ in 0..n {
                    std::hint::spin_loop();
                }

                if lock.load(Ordering::Relaxed) == 0 && cmp_set(lock, 0, NGX_RWLOCK_WLOCK) {
                    return;
                }

                n <<= 1;
            }
        }

        unsafe {
            libc::sched_yield();
        }
    }
}

/// ngx_rwlock_rlock
pub fn rlock(lock: &AtomicUsize) {
    loop {
        let readers = lock.load(Ordering::Relaxed);

        if readers != NGX_RWLOCK_WLOCK && cmp_set(lock, readers, readers + 1) {
            return;
        }

        if ncpu() > 1 {
            let mut n = 1;
            while n < NGX_RWLOCK_SPIN {
                for _ in 0..n {
                    std::hint::spin_loop();
                }

                let readers = lock.load(Ordering::Relaxed);

                if readers != NGX_RWLOCK_WLOCK && cmp_set(lock, readers, readers + 1) {
                    return;
                }

                n <<= 1;
            }
        }

        unsafe {
            libc::sched_yield();
        }
    }
}

/// ngx_rwlock_unlock
pub fn unlock(lock: &AtomicUsize) {
    if lock.load(Ordering::Relaxed) == NGX_RWLOCK_WLOCK {
        let _ = cmp_set(lock, NGX_RWLOCK_WLOCK, 0);
    } else {
        lock.fetch_sub(1, Ordering::AcqRel);
    }
}

/// ngx_rwlock_downgrade
pub fn downgrade(lock: &AtomicUsize) {
    if lock.load(Ordering::Relaxed) == NGX_RWLOCK_WLOCK {
        lock.store(1, Ordering::Release);
    }
}
