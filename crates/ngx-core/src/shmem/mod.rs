//! The memory of a shared zone, addressed by offsets.
//!
//! nginx keeps raw pointers in its zones, which works because a zone is
//! mapped at the same address in the master and in the workers it forks.
//! Here a zone is a ShmMem: a MAP_SHARED anonymous mapping (owned by
//! vm-memory's MmapRegion, unmapped when dropped) seen as words, every
//! access an atomic one, because the other processes write the same memory
//! concurrently. The "pointers" stored in a zone are byte offsets from its
//! start, 0 standing for NULL (offset 0 is the slab pool's header, never
//! handed out).
//!
//! Values smaller than a word (u8, u16, u32) and byte strings are read
//! from the words they are in, and written by a read-modify-write of those
//! words: write them under the zone's mutex (or another lock), as C does.
//!
//! Structures in a zone are declared with `shm_struct!`, which lays the
//! fields out as repr(C) would (natural alignment), so that allocation
//! sizes stay the C ones; fields are read and written through
//! `Field<T>` constants: `node.get(Node::excess)`, `node.set(Node::excess, v)`.

pub mod lock;
pub mod queue;
pub mod rbtree;
pub mod slab;

use std::cmp::Ordering;
use std::io;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use vm_memory::mmap::MmapRegion;
use vm_memory::VolatileMemory;

const WORD: usize = std::mem::size_of::<usize>();

/// The memory of a zone.
#[derive(Debug)]
pub struct ShmMem {
    region: MmapRegion<()>,
}

impl ShmMem {
    fn map(size: usize, flags: i32) -> io::Result<ShmMem> {
        if size == 0 || size % WORD != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }

        match MmapRegion::<()>::build(None, size, libc::PROT_READ | libc::PROT_WRITE, flags | libc::MAP_ANONYMOUS) {
            Ok(region) => Ok(ShmMem { region }),
            Err(vm_memory::mmap::MmapRegionError::Mmap(e)) => Err(e),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    /// mmap(MAP_ANON|MAP_SHARED) of `size` bytes, zeroed: shared with the
    /// processes forked after.
    pub fn shared(size: usize) -> io::Result<ShmMem> {
        ShmMem::map(size, libc::MAP_SHARED)
    }

    /// The same, private to the process (tests, process-local structures).
    pub fn private(size: usize) -> io::Result<ShmMem> {
        ShmMem::map(size, libc::MAP_PRIVATE)
    }

    /// The size in bytes.
    pub fn len(&self) -> usize {
        self.region.size()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The address of the mapping, for messages (and, during the
    /// conversion, for the code still using pointers).
    pub fn addr(&self) -> *mut u8 {
        self.region.as_ptr()
    }

    /// The word at `off` (a multiple of the word size).
    #[inline]
    pub fn word(&self, off: usize) -> &AtomicUsize {
        match self.region.get_atomic_ref::<AtomicUsize>(off) {
            Ok(w) => w,
            Err(e) => panic!("shared memory offset {:#x} of {:#x} bytes: {}", off, self.len(), e),
        }
    }

    /// The word at `off`.
    #[inline]
    pub fn get(&self, off: usize) -> usize {
        self.word(off).load(Relaxed)
    }

    /// Sets the word at `off`.
    #[inline]
    pub fn set(&self, off: usize, v: usize) {
        self.word(off).store(v, Relaxed)
    }

    /// A value of type T at `off` (aligned to its size).
    #[inline]
    pub fn load<T: ShmValue>(&self, off: usize) -> T {
        debug_assert!(off % T::SIZE == 0, "unaligned shared memory value at {:#x}", off);

        if T::SIZE == WORD {
            return T::from_bits(self.get(off) as u64);
        }

        let w = self.get(off & !(WORD - 1));
        let shift = (off & (WORD - 1)) * 8;

        T::from_bits(((w >> shift) as u64) & mask(T::SIZE))
    }

    /// Stores a value of type T at `off` (aligned to its size).
    #[inline]
    pub fn store<T: ShmValue>(&self, off: usize, v: T) {
        debug_assert!(off % T::SIZE == 0, "unaligned shared memory value at {:#x}", off);

        if T::SIZE == WORD {
            self.set(off, v.to_bits() as usize);
            return;
        }

        let base = off & !(WORD - 1);
        let shift = (off & (WORD - 1)) * 8;
        let m = (mask(T::SIZE) as usize) << shift;
        let w = self.get(base);

        self.set(base, (w & !m) | (((v.to_bits() as usize) << shift) & m));
    }

    /// The byte at `off`.
    #[inline]
    pub fn byte(&self, off: usize) -> u8 {
        self.load::<u8>(off)
    }

    /// Copies `buf.len()` bytes at `off` into `buf`.
    pub fn read(&self, off: usize, buf: &mut [u8]) {
        let mut i = 0;

        while i < buf.len() {
            let p = off + i;
            let base = p & !(WORD - 1);
            let w = self.get(base).to_ne_bytes();
            let from = p - base;
            let n = (WORD - from).min(buf.len() - i);

            buf[i..i + n].copy_from_slice(&w[from..from + n]);
            i += n;
        }
    }

    /// The `len` bytes at `off`.
    pub fn bytes(&self, off: usize, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        self.read(off, &mut v);
        v
    }

    /// Copies `data` to `off`.
    pub fn write(&self, off: usize, data: &[u8]) {
        let mut i = 0;

        while i < data.len() {
            let p = off + i;
            let base = p & !(WORD - 1);
            let from = p - base;
            let n = (WORD - from).min(data.len() - i);

            if n == WORD {
                let mut w = [0u8; WORD];
                w.copy_from_slice(&data[i..i + WORD]);
                self.set(base, usize::from_ne_bytes(w));
            } else {
                let mut w = self.get(base).to_ne_bytes();
                w[from..from + n].copy_from_slice(&data[i..i + n]);
                self.set(base, usize::from_ne_bytes(w));
            }

            i += n;
        }
    }

    /// memset()
    pub fn fill(&self, off: usize, len: usize, byte: u8) {
        let mut i = 0;
        let full = usize::from_ne_bytes([byte; WORD]);

        while i < len {
            let p = off + i;
            let base = p & !(WORD - 1);
            let from = p - base;
            let n = (WORD - from).min(len - i);

            if n == WORD {
                self.set(base, full);
            } else {
                let mut w = self.get(base).to_ne_bytes();
                w[from..from + n].fill(byte);
                self.set(base, usize::from_ne_bytes(w));
            }

            i += n;
        }
    }

    /// memmove() inside the zone.
    pub fn copy(&self, dst: usize, src: usize, len: usize) {
        let data = self.bytes(src, len);
        self.write(dst, &data);
    }

    /// ngx_memcmp() of the `data.len()` bytes at `off` with `data`.
    pub fn cmp_bytes(&self, off: usize, data: &[u8]) -> Ordering {
        let mut buf = [0u8; 64];
        let mut i = 0;

        while i < data.len() {
            let n = buf.len().min(data.len() - i);
            self.read(off + i, &mut buf[..n]);

            match buf[..n].cmp(&data[i..i + n]) {
                Ordering::Equal => {}
                o => return o,
            }

            i += n;
        }

        Ordering::Equal
    }

    /// The `data.len()` bytes at `off` are `data`.
    pub fn eq_bytes(&self, off: usize, data: &[u8]) -> bool {
        self.cmp_bytes(off, data) == Ordering::Equal
    }
}

#[inline]
fn mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// A plain value a zone stores: its size (and alignment) and its bits.
pub trait ShmValue: Copy {
    const SIZE: usize;
    fn from_bits(bits: u64) -> Self;
    fn to_bits(self) -> u64;
}

macro_rules! shm_value {
    ($($t:ty),*) => {
        $(
            impl ShmValue for $t {
                const SIZE: usize = std::mem::size_of::<$t>();
                #[inline]
                fn from_bits(bits: u64) -> Self {
                    bits as $t
                }
                #[inline]
                fn to_bits(self) -> u64 {
                    // sign-extended values are masked by the stores
                    self as u64
                }
            }
        )*
    };
}

shm_value!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl ShmValue for bool {
    const SIZE: usize = 1;
    #[inline]
    fn from_bits(bits: u64) -> Self {
        bits & 0xff != 0
    }
    #[inline]
    fn to_bits(self) -> u64 {
        self as u64
    }
}

/// A field of a structure in a zone: its offset in the structure.
#[derive(Debug)]
pub struct Field<T> {
    pub off: usize,
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for Field<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Field<T> {}

impl<T> Field<T> {
    pub const fn new(off: usize) -> Field<T> {
        Field { off, _t: PhantomData }
    }
}

/// The repr(C) layout of fields of the given sizes (each aligned to its
/// size): their offsets, and the size of the structure.
pub const fn layout<const N: usize>(sizes: [usize; N]) -> ([usize; N], usize) {
    let mut offs = [0usize; N];
    let mut end = 0;
    let mut align = 1;
    let mut i = 0;

    while i < N {
        let a = sizes[i];
        end = (end + a - 1) / a * a;
        offs[i] = end;
        end += a;
        if a > align {
            align = a;
        }
        i += 1;
    }

    (offs, (end + align - 1) / align * align)
}

/// Declares a structure kept in a zone: a view (the memory and the offset
/// of the structure), `SIZE` (its sizeof), and a `Field` constant per
/// field, laid out as repr(C) would.
///
/// ```ignore
/// shm_struct! {
///     /// ngx_http_limit_req_shctx_t
///     pub struct Shctx {
///         rbtree_root: usize,
///         rbtree_sentinel: usize,
///         len: u16,
///     }
/// }
/// let sh = Shctx::at(&mem, off);
/// sh.set(Shctx::len, 3);
/// ```
#[macro_export]
macro_rules! shm_struct {
    ($(#[$m:meta])* $vis:vis struct $name:ident { $($(#[$fm:meta])* $f:ident : $t:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug)]
        $vis struct $name<'a> {
            pub mem: &'a $crate::shmem::ShmMem,
            pub off: usize,
        }

        #[allow(dead_code)]
        impl<'a> $name<'a> {
            const LAYOUT: ([usize; [$(stringify!($f)),*].len()], usize) =
                $crate::shmem::layout([$(<$t as $crate::shmem::ShmValue>::SIZE),*]);

            /// sizeof
            pub const SIZE: usize = Self::LAYOUT.1;

            /// The structure at `off`.
            pub fn at(mem: &'a $crate::shmem::ShmMem, off: usize) -> Self {
                $name { mem, off }
            }

            /// A field's value.
            #[inline]
            pub fn get<T: $crate::shmem::ShmValue>(&self, f: $crate::shmem::Field<T>) -> T {
                self.mem.load(self.off + f.off)
            }

            /// Sets a field.
            #[inline]
            pub fn set<T: $crate::shmem::ShmValue>(&self, f: $crate::shmem::Field<T>, v: T) {
                self.mem.store(self.off + f.off, v)
            }

            /// The offset of a field in the zone (&s->field).
            #[inline]
            pub fn field<T>(&self, f: $crate::shmem::Field<T>) -> usize {
                self.off + f.off
            }
        }

        $crate::shm_struct!(@fields $name, 0usize, $($(#[$fm])* $f : $t,)*);
    };

    (@fields $name:ident, $idx:expr, $(#[$fm:meta])* $f:ident : $t:ty, $($rest:tt)*) => {
        #[allow(non_upper_case_globals, dead_code)]
        impl<'a> $name<'a> {
            $(#[$fm])*
            pub const $f: $crate::shmem::Field<$t> = $crate::shmem::Field::new(Self::LAYOUT.0[$idx]);
        }

        $crate::shm_struct!(@fields $name, $idx + 1, $($rest)*);
    };

    (@fields $name:ident, $idx:expr,) => {};
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::shm_struct! {
        /// a structure as C lays it out
        struct Node {
            key: usize,
            color: u8,
            data: u8,
            len: u16,
            /// after padding
            last: u64,
            small: u32,
        }
    }

    #[test]
    fn layout_is_repr_c() {
        assert_eq!(Node::key.off, 0);
        assert_eq!(Node::color.off, 8);
        assert_eq!(Node::data.off, 9);
        assert_eq!(Node::len.off, 10);
        assert_eq!(Node::last.off, 16);
        assert_eq!(Node::small.off, 24);
        assert_eq!(Node::SIZE, 32);
        assert_eq!(layout([1, 1]), ([0, 1], 2));
        assert_eq!(layout([8, 1]), ([0, 8], 16));
    }

    #[test]
    fn fields_and_bytes() {
        let mem = ShmMem::private(4096).unwrap();
        let n = Node::at(&mem, 64);

        n.set(Node::key, 7);
        n.set(Node::color, 1);
        n.set(Node::data, 0xff);
        n.set(Node::len, 0xbeef);
        n.set(Node::small, u32::MAX);
        n.set(Node::last, 1 << 40);

        assert_eq!(n.get(Node::key), 7);
        assert_eq!(n.get(Node::color), 1);
        assert_eq!(n.get(Node::data), 0xff);
        assert_eq!(n.get(Node::len), 0xbeef);
        assert_eq!(n.get(Node::small), u32::MAX);
        assert_eq!(n.get(Node::last), 1 << 40);

        n.set(Node::data, 0);
        assert_eq!(n.get(Node::color), 1, "the neighbour byte is kept");
        assert_eq!(n.get(Node::len), 0xbeef);

        mem.store::<i32>(128, -2);
        assert_eq!(mem.load::<i32>(128), -2);
        assert_eq!(mem.load::<u32>(132), 0, "the other half is kept");
        mem.store::<isize>(136, -5);
        assert_eq!(mem.load::<isize>(136), -5);
        mem.store::<bool>(145, true);
        assert!(mem.load::<bool>(145));

        mem.write(203, b"hello, shared world");
        assert_eq!(mem.bytes(203, 19), b"hello, shared world");
        assert!(mem.eq_bytes(203, b"hello"));
        assert_eq!(mem.cmp_bytes(203, b"hellp"), Ordering::Less);
        assert_eq!(mem.cmp_bytes(203, b"hella"), Ordering::Greater);
        assert_eq!(mem.byte(202), 0);
        assert_eq!(mem.byte(222), 0);

        mem.copy(301, 203, 19);
        assert_eq!(mem.bytes(301, 19), b"hello, shared world");

        mem.fill(203, 19, b'x');
        assert_eq!(mem.bytes(202, 21), b"\0xxxxxxxxxxxxxxxxxxx\0");
    }

    #[test]
    fn shared_after_fork_is_shared_memory() {
        let mem = ShmMem::shared(4096).unwrap();
        mem.set(8, 5);
        assert_eq!(mem.word(8).fetch_add(1, Relaxed), 5);
        assert_eq!(mem.get(8), 6);
        assert_eq!(mem.len(), 4096);
        assert!(ShmMem::shared(5).is_err());
    }

    #[test]
    #[should_panic]
    fn out_of_the_zone() {
        let mem = ShmMem::private(4096).unwrap();
        mem.get(4096);
    }
}
