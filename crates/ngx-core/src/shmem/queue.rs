//! Doubly linked lists in a zone (ngx_queue.h): an ngx_queue_t is two
//! offsets, prev and next, embedded in the structures it links; the list
//! head is an ngx_queue_t of its own (the sentinel).

use super::ShmMem;
use crate::shm_struct;

shm_struct! {
    /// ngx_queue_t
    pub struct Queue {
        prev: usize,
        next: usize,
    }
}

/// ngx_queue_init
pub fn init(m: &ShmMem, q: usize) {
    let q = Queue::at(m, q);
    q.set(Queue::prev, q.off);
    q.set(Queue::next, q.off);
}

/// ngx_queue_empty
pub fn empty(m: &ShmMem, h: usize) -> bool {
    Queue::at(m, h).get(Queue::prev) == h
}

/// ngx_queue_insert_head (ngx_queue_insert_after)
pub fn insert_head(m: &ShmMem, h: usize, x: usize) {
    let (hq, xq) = (Queue::at(m, h), Queue::at(m, x));
    let next = hq.get(Queue::next);
    xq.set(Queue::next, next);
    Queue::at(m, next).set(Queue::prev, x);
    xq.set(Queue::prev, h);
    hq.set(Queue::next, x);
}

/// ngx_queue_insert_after
pub fn insert_after(m: &ShmMem, h: usize, x: usize) {
    insert_head(m, h, x);
}

/// ngx_queue_insert_tail (ngx_queue_insert_before)
pub fn insert_tail(m: &ShmMem, h: usize, x: usize) {
    let (hq, xq) = (Queue::at(m, h), Queue::at(m, x));
    let prev = hq.get(Queue::prev);
    xq.set(Queue::prev, prev);
    Queue::at(m, prev).set(Queue::next, x);
    xq.set(Queue::next, h);
    hq.set(Queue::prev, x);
}

/// ngx_queue_insert_before
pub fn insert_before(m: &ShmMem, h: usize, x: usize) {
    insert_tail(m, h, x);
}

/// ngx_queue_head
pub fn head(m: &ShmMem, h: usize) -> usize {
    Queue::at(m, h).get(Queue::next)
}

/// ngx_queue_last
pub fn last(m: &ShmMem, h: usize) -> usize {
    Queue::at(m, h).get(Queue::prev)
}

/// ngx_queue_next
pub fn next(m: &ShmMem, q: usize) -> usize {
    Queue::at(m, q).get(Queue::next)
}

/// ngx_queue_prev
pub fn prev(m: &ShmMem, q: usize) -> usize {
    Queue::at(m, q).get(Queue::prev)
}

/// ngx_queue_remove (of a debug build: the links of x are cleared)
pub fn remove(m: &ShmMem, x: usize) {
    let xq = Queue::at(m, x);
    let (prev, next) = (xq.get(Queue::prev), xq.get(Queue::next));
    Queue::at(m, next).set(Queue::prev, prev);
    Queue::at(m, prev).set(Queue::next, next);
    xq.set(Queue::prev, 0);
    xq.set(Queue::next, 0);
}

/// ngx_queue_split: the list h is cut before q, q and the rest go to n
pub fn split(m: &ShmMem, h: usize, q: usize, n: usize) {
    let (hq, qq, nq) = (Queue::at(m, h), Queue::at(m, q), Queue::at(m, n));
    let hprev = hq.get(Queue::prev);
    nq.set(Queue::prev, hprev);
    Queue::at(m, hprev).set(Queue::next, n);
    nq.set(Queue::next, q);
    let qprev = qq.get(Queue::prev);
    hq.set(Queue::prev, qprev);
    Queue::at(m, qprev).set(Queue::next, h);
    qq.set(Queue::prev, n);
}

/// ngx_queue_add: the list n appended to h
pub fn add(m: &ShmMem, h: usize, n: usize) {
    let (hq, nq) = (Queue::at(m, h), Queue::at(m, n));
    let hprev = hq.get(Queue::prev);
    let nnext = nq.get(Queue::next);
    Queue::at(m, hprev).set(Queue::next, nnext);
    Queue::at(m, nnext).set(Queue::prev, hprev);
    let nprev = nq.get(Queue::prev);
    hq.set(Queue::prev, nprev);
    Queue::at(m, nprev).set(Queue::next, h);
}

/// The elements of the list h, first to last.
pub fn walk(m: &ShmMem, h: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut q = head(m, h);
    while q != h {
        out.push(q);
        q = next(m, q);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists() {
        let m = ShmMem::private(4096).unwrap();
        let h = 64;
        init(&m, h);
        assert!(empty(&m, h));

        let (a, b, c, d) = (128, 160, 192, 224);
        insert_tail(&m, h, a);
        insert_tail(&m, h, b);
        insert_head(&m, h, c);
        assert_eq!(walk(&m, h), vec![c, a, b]);
        assert_eq!(head(&m, h), c);
        assert_eq!(last(&m, h), b);
        assert_eq!(prev(&m, b), a);

        remove(&m, a);
        assert_eq!(walk(&m, h), vec![c, b]);
        assert_eq!(next(&m, a), 0, "cleared links");

        insert_after(&m, c, d);
        assert_eq!(walk(&m, h), vec![c, d, b]);

        let n = 256;
        split(&m, h, d, n);
        assert_eq!(walk(&m, h), vec![c]);
        assert_eq!(walk(&m, n), vec![d, b]);

        add(&m, h, n);
        assert_eq!(walk(&m, h), vec![c, d, b]);
        assert!(!empty(&m, h));
    }
}
