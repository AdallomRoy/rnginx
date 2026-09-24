//! Shared memory lock (ngx_shmtx.c) — an atomic lock word for synchronization across processes.
//!
//! Implementation uses spin/`sched_yield` waiting (not semaphores) to match the atomic
//! branch of nginx's shmtx.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Shared memory lock: an atomic lock word at a fixed address.
/// The word stores the pid of the owner, or 0 if unlocked.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ShmTx {
    lock: *mut AtomicUsize,
    spin: u32,
}

impl ShmTx {
    /// Create a lock from a pointer to an AtomicUsize in shared memory.
    /// Panics if lock_ptr is null.
    pub fn create(lock_ptr: *mut AtomicUsize) -> Self {
        assert!(!lock_ptr.is_null(), "ShmTx::create: lock_ptr is null");
        ShmTx {
            lock: lock_ptr,
            spin: 2048,
        }
    }

    /// Acquire the lock, spinning and yielding until available.
    pub fn lock(&self) {
        let pid = std::process::id() as usize;
        let lock = unsafe { &*self.lock };

        loop {
            // Try fast CAS
            if let Ok(_) = lock.compare_exchange(0, pid, Ordering::Acquire, Ordering::Relaxed) {
                return;
            }

            // Spin on multi-CPU systems (assume multi-CPU for simplicity)
            if true {
                for n in 1..self.spin {
                    let bits = 1usize.wrapping_shl(31 - (n.leading_zeros() % 32));
                    for _ in 0..bits {
                        // cpu_pause equivalent: x86 pause or spin
                        std::hint::spin_loop();
                    }

                    if let Ok(_) = lock.compare_exchange(0, pid, Ordering::Acquire, Ordering::Relaxed) {
                        return;
                    }
                }
            }

            // Yield to scheduler
            unsafe {
                libc::sched_yield();
            }
        }
    }

    /// Try to acquire the lock without blocking.
    /// Returns true if locked, false if already owned.
    pub fn trylock(&self) -> bool {
        let pid = std::process::id() as usize;
        let lock = unsafe { &*self.lock };

        if let Ok(_) = lock.compare_exchange(0, pid, Ordering::Acquire, Ordering::Relaxed) {
            true
        } else {
            false
        }
    }

    /// Release the lock.
    pub fn unlock(&self) {
        let pid = std::process::id() as usize;
        let lock = unsafe { &*self.lock };

        let _ = lock.compare_exchange(pid, 0, Ordering::Release, Ordering::Relaxed);
    }

    /// Force unlock if the lock is held by a specific pid.
    /// Returns true if the lock was held by that pid and was released.
    pub fn force_unlock(&self, pid: usize) -> bool {
        let lock = unsafe { &*self.lock };

        if let Ok(_) = lock.compare_exchange(pid, 0, Ordering::Release, Ordering::Relaxed) {
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_shmtx_basic() {
        // Allocate a lock in a shared region
        let lock = Arc::new(AtomicUsize::new(0));
        let mtx = ShmTx::create(Arc::as_ptr(&lock) as *mut AtomicUsize);

        // Should be unlocked
        assert_eq!(lock.load(Ordering::Relaxed), 0);

        // Try lock succeeds
        assert!(mtx.trylock());

        // Lock is held by this process
        let pid = std::process::id() as usize;
        assert_eq!(lock.load(Ordering::Relaxed), pid);

        // Second trylock fails
        assert!(!mtx.trylock());

        // Unlock
        mtx.unlock();
        assert_eq!(lock.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_shmtx_lock() {
        let lock = Arc::new(AtomicUsize::new(0));
        let mtx = ShmTx::create(Arc::as_ptr(&lock) as *mut AtomicUsize);

        // Lock should succeed immediately
        mtx.lock();
        let pid = std::process::id() as usize;
        assert_eq!(lock.load(Ordering::Relaxed), pid);

        mtx.unlock();
        assert_eq!(lock.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_shmtx_force_unlock() {
        let lock = Arc::new(AtomicUsize::new(0));
        let mtx = ShmTx::create(Arc::as_ptr(&lock) as *mut AtomicUsize);

        // Force unlock on unlocked lock should fail
        assert!(!mtx.force_unlock(12345));

        // Lock it
        mtx.lock();
        let pid = std::process::id() as usize;

        // Force unlock with wrong pid should fail
        assert!(!mtx.force_unlock(99999));
        assert_eq!(lock.load(Ordering::Relaxed), pid);

        // Force unlock with correct pid should succeed
        assert!(mtx.force_unlock(pid));
        assert_eq!(lock.load(Ordering::Relaxed), 0);
    }
}
