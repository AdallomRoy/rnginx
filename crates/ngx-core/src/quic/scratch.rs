//! The packet buffers of the worker, as C's static arrays: `src` (the
//! payload of a packet being built) and `dst` (a datagram) of
//! ngx_event_quic_output.c, the GSO buffer of ngx_quic_create_segments(),
//! the plaintext of ngx_quic_handle_payload(). A buffer is taken for a
//! packet or a datagram and given back when its guard goes, so nothing is
//! allocated per packet, and the buffers of fixed size stay initialised,
//! so nothing is zero-filled per packet either. Taking a buffer which is
//! out already (a nested use) gives a new one: always safe, only slower.

use std::cell::Cell;
use std::ops::{Deref, DerefMut};

use super::NGX_QUIC_MAX_UDP_PAYLOAD_SIZE;

/// NGX_QUIC_MAX_UDP_SEGMENT_BUF: 65K - IPv6 header
pub const NGX_QUIC_MAX_UDP_SEGMENT_BUF: usize = 65487;

/// The buffers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// src: empty, with room for NGX_QUIC_MAX_UDP_PAYLOAD_SIZE bytes (a
    /// packet's frames are appended to it)
    Src,
    /// dst: NGX_QUIC_MAX_UDP_PAYLOAD_SIZE initialised bytes
    Dst,
    /// the GSO buffer: NGX_QUIC_MAX_UDP_SEGMENT_BUF initialised bytes
    Gso,
    /// the plaintext: NGX_QUIC_MAX_UDP_PAYLOAD_SIZE initialised bytes
    Plain,
}

thread_local! {
    static SRC: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
    static DST: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
    static GSO: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
    static PLAIN: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

fn slot(kind: Kind) -> &'static std::thread::LocalKey<Cell<Vec<u8>>> {
    match kind {
        Kind::Src => &SRC,
        Kind::Dst => &DST,
        Kind::Gso => &GSO,
        Kind::Plain => &PLAIN,
    }
}

fn size(kind: Kind) -> usize {
    match kind {
        Kind::Gso => NGX_QUIC_MAX_UDP_SEGMENT_BUF,
        _ => NGX_QUIC_MAX_UDP_PAYLOAD_SIZE,
    }
}

/// A buffer of the worker, given back when dropped.
pub struct Scratch {
    kind: Kind,
    buf: Vec<u8>,
}

impl Scratch {
    /// The buffer of `kind`: an empty one for Src, the initialised bytes of
    /// its size for the others.
    pub fn take(kind: Kind) -> Scratch {
        let mut buf = slot(kind).try_with(|s| s.take()).unwrap_or_default();

        let size = size(kind);

        match kind {
            Kind::Src => {
                buf.clear();
                buf.reserve(size);
            }

            _ => {
                if buf.len() != size {
                    buf = vec![0; size];
                }
            }
        }

        Scratch { kind, buf }
    }

    /// The Vec itself, for a while: given back with put_vec().
    pub fn take_vec(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn put_vec(&mut self, buf: Vec<u8>) {
        self.buf = buf;
    }
}

impl Deref for Scratch {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.buf
    }
}

impl DerefMut for Scratch {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        give_back(self.kind, std::mem::take(&mut self.buf));
    }
}

/// A buffer of `kind` taken away (Scratch::take_vec()) given back to the
/// worker.
pub fn give_back(kind: Kind, buf: Vec<u8>) {
    // a Src buffer that was taken away has no capacity left; one of the
    // others not of its size is not kept
    let keep = match kind {
        Kind::Src => buf.capacity() >= size(kind),
        _ => buf.len() == size(kind),
    };

    if keep {
        let _ = slot(kind).try_with(|s| s.set(buf));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_kept_and_reused() {
        // src: empty, with its room, and given back
        let mut s = Scratch::take(Kind::Src);
        assert!(s.is_empty() && s.capacity() >= NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);
        s.extend_from_slice(b"frames");
        let p = s.as_ptr();
        drop(s);

        let s = Scratch::take(Kind::Src);
        assert!(s.is_empty());
        assert_eq!(s.as_ptr(), p);

        // taken while out: another one, both work
        let t = Scratch::take(Kind::Src);
        assert_ne!(t.as_ptr(), p);
        drop(t);
        drop(s);

        // the fixed ones keep their bytes initialised, of their size
        let mut d = Scratch::take(Kind::Dst);
        assert_eq!(d.len(), NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);
        d[0] = 7;
        let p = d.as_ptr();
        drop(d);

        let d = Scratch::take(Kind::Dst);
        assert_eq!((d.as_ptr(), d[0], d.len()), (p, 7, NGX_QUIC_MAX_UDP_PAYLOAD_SIZE));
        drop(d);

        let g = Scratch::take(Kind::Gso);
        assert_eq!(g.len(), NGX_QUIC_MAX_UDP_SEGMENT_BUF);

        // a Vec taken away and given back
        let mut s = Scratch::take(Kind::Plain);
        let v = s.take_vec();
        assert_eq!(v.len(), NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);
        s.put_vec(v);
        let p = s.as_ptr();
        drop(s);
        assert_eq!(Scratch::take(Kind::Plain).as_ptr(), p);
    }
}
