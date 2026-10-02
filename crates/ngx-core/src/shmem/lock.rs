//! The mutex of a zone (ngx_shmtx.c, the atomic variant: spinning, then
//! sched_yield(), as the port has no POSIX semaphore): the lock word holds
//! the pid of the owner, 0 when free.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

/// mtx->spin
const NGX_SHMTX_SPIN: usize = 2048;

fn ncpu() -> usize {
    static NCPU: OnceLock<usize> = OnceLock::new();
    *NCPU.get_or_init(crate::os::ncpu)
}

fn pid() -> usize {
    crate::os::getpid() as usize
}

#[inline]
fn cmp_set(lock: &AtomicUsize, old: usize, set: usize) -> bool {
    lock.compare_exchange(old, set, Ordering::AcqRel, Ordering::Relaxed).is_ok()
}

/// ngx_shmtx_lock
pub fn shmtx_lock(lock: &AtomicUsize) {
    let pid = pid();

    loop {
        if lock.load(Ordering::Relaxed) == 0 && cmp_set(lock, 0, pid) {
            return;
        }

        if ncpu() > 1 {
            let mut n = 1;
            while n < NGX_SHMTX_SPIN {
                for _ in 0..n {
                    std::hint::spin_loop();
                }

                if lock.load(Ordering::Relaxed) == 0 && cmp_set(lock, 0, pid) {
                    return;
                }

                n <<= 1;
            }
        }

        // ngx_sched_yield()
        std::thread::yield_now();
    }
}

/// ngx_shmtx_trylock
pub fn shmtx_trylock(lock: &AtomicUsize) -> bool {
    lock.load(Ordering::Relaxed) == 0 && cmp_set(lock, 0, pid())
}

/// ngx_shmtx_unlock
pub fn shmtx_unlock(lock: &AtomicUsize) {
    cmp_set(lock, pid(), 0);
}

/// ngx_shmtx_force_unlock: the lock of the dead process `pid` released
pub fn shmtx_force_unlock(lock: &AtomicUsize, pid: i32) -> bool {
    cmp_set(lock, pid as usize, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_unlock() {
        let w = AtomicUsize::new(0);
        assert!(shmtx_trylock(&w));
        assert_eq!(w.load(Ordering::Relaxed), pid());
        assert!(!shmtx_trylock(&w));
        shmtx_unlock(&w);
        assert_eq!(w.load(Ordering::Relaxed), 0);

        shmtx_lock(&w);
        assert!(!shmtx_force_unlock(&w, 1));
        assert!(shmtx_force_unlock(&w, pid() as i32));
        assert_eq!(w.load(Ordering::Relaxed), 0);
    }
}
