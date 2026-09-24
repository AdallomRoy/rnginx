//! Intrusive doubly-linked queue (ngx_queue.h) usable in shared memory.

use std::ptr;

/// Intrusive queue node (sentinel or list member).
#[repr(C)]
pub struct Queue {
    pub prev: *mut Queue,
    pub next: *mut Queue,
}

impl Queue {
    /// Create a new queue node.
    pub fn new() -> Self {
        Queue {
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
        }
    }

    /// Initialize a queue head (sentinel).
    pub fn init(&mut self) {
        self.prev = self;
        self.next = self;
    }

    /// Check if queue is empty.
    pub fn is_empty(&self) -> bool {
        self as *const Queue as *mut Queue == self.prev
    }

    /// Insert after this node (insert_head).
    pub unsafe fn insert_head(&self, x: *mut Queue) {
        (*x).next = self.next;
        (*(*x).next).prev = x;
        (*x).prev = self as *const _ as *mut Queue;
        let self_mut = self as *const Queue as *mut Queue;
        (*self_mut).next = x;
    }

    /// Insert before this node (insert_tail on sentinel).
    pub unsafe fn insert_tail(&self, x: *mut Queue) {
        (*x).prev = self.prev;
        (*(*x).prev).next = x;
        (*x).next = self as *const Queue as *mut Queue;
        let self_mut = self as *const Queue as *mut Queue;
        (*self_mut).prev = x;
    }

    /// Insert after another node.
    pub unsafe fn insert_after(&self, x: *mut Queue) {
        self.insert_head(x);
    }

    /// Insert before another node.
    pub unsafe fn insert_before(&self, x: *mut Queue) {
        self.insert_tail(x);
    }

    /// Get the head (first) element.
    pub fn head(&self) -> *mut Queue {
        self.next
    }

    /// Get the last element.
    pub fn last(&self) -> *mut Queue {
        self.prev
    }

    /// Get the sentinel (head/marker node).
    pub fn sentinel(&self) -> *mut Queue {
        self as *const _ as *mut _
    }

    /// Get the next element.
    pub fn next(&self) -> *mut Queue {
        self.next
    }

    /// Get the previous element.
    pub fn prev(&self) -> *mut Queue {
        self.prev
    }

    /// Remove this node from the queue.
    pub unsafe fn remove(&mut self) {
        (*self.next).prev = self.prev;
        (*self.prev).next = self.next;
        // For debug: clear pointers
        self.prev = ptr::null_mut();
        self.next = ptr::null_mut();
    }

    /// Split a queue: move elements from q to end into a new queue n.
    pub unsafe fn split(&self, q: *mut Queue, n: *mut Queue) {
        (*n).prev = self.prev;
        (*(*n).prev).next = n;
        (*n).next = q;
        let self_mut = self as *const Queue as *mut Queue;
        (*self_mut).prev = (*q).prev;
        (*(*self_mut).prev).next = self_mut;
        (*q).prev = n;
    }

    /// Add another queue's elements to this one.
    pub unsafe fn add(&self, n: *mut Queue) {
        let self_mut = self as *const Queue as *mut Queue;
        (*self_mut).prev.as_mut().unwrap().next = (*n).next;
        (*(*n).next).prev = (*self_mut).prev;
        (*self_mut).prev = (*n).prev;
        (*(*self_mut).prev).next = self_mut;
    }

    /// Find the middle element of a queue.
    pub fn middle(&self) -> *mut Queue {
        queue_middle(self as *const _ as *mut _)
    }

    /// Sort a queue using a comparator.
    pub fn sort<F>(&mut self, cmp: F)
    where
        F: Fn(*mut Queue, *mut Queue) -> i32 + Copy,
    {
        queue_sort(self, cmp);
    }
}

impl Default for Queue {
    fn default() -> Self {
        Queue::new()
    }
}

/// Find the middle node of a queue.
pub fn queue_middle(queue: *mut Queue) -> *mut Queue {
    unsafe {
        let mut middle = queue;
        let mut next = queue;

        loop {
            middle = (*middle).next;
            next = (*next).next;
            if next == queue {
                break;
            }
            next = (*next).next;
            if next == queue {
                break;
            }
        }

        middle
    }
}

/// Sort a queue using merge sort.
pub fn queue_sort<F>(queue: *mut Queue, cmp: F) -> usize
where
    F: Fn(*mut Queue, *mut Queue) -> i32 + Copy,
{
    unsafe {
        queue_sort_impl(queue, cmp)
    }
}

unsafe fn queue_sort_impl<F>(queue: *mut Queue, cmp: F) -> usize
where
    F: Fn(*mut Queue, *mut Queue) -> i32 + Copy,
{
    let mut list = (*queue).next;

    if list == queue || (*list).next == queue {
        return 1;
    }

    let mut middle = queue_middle(queue);

    let mut n = (*queue).prev;
    (*n).next = middle;
    (*middle).prev = n;

    let mut m = (*queue).next;
    (*queue).next = queue;
    (*queue).prev = queue;

    let left_size = queue_sort_impl(queue, cmp);
    let right_size = queue_sort_impl(middle, cmp);

    queue_sort_merge(queue, middle, cmp);

    left_size + right_size
}

unsafe fn queue_sort_merge<F>(queue: *mut Queue, middle: *mut Queue, cmp: F)
where
    F: Fn(*mut Queue, *mut Queue) -> i32,
{
    let mut h: *mut Queue;
    let mut t: *mut Queue = queue;
    let mut m: *mut Queue;

    m = (*middle).next;

    loop {
        if (*queue).next == middle {
            break;
        }

        if cmp((*queue).next, m) <= 0 {
            h = (*queue).next;
            let q = queue;
            (*q).next = (*h).next;
            (*(*q).next).prev = q;
        } else {
            h = m;
            m = (*m).next;

            (*middle).next = (*h).prev;
            (*(*h).prev).next = middle;

            (*h).prev = t;
            (*t).next = h;
            t = h;

            if m == middle {
                h = (*queue).next;

                (*queue).next = m;
                (*m).prev = queue;

                (*h).prev = t;
                (*t).next = h;

                return;
            }

            continue;
        }

        (*h).prev = t;
        (*t).next = h;
        t = h;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_init() {
        let mut q = Queue::new();
        q.init();

        assert!(q.is_empty());
        assert_eq!(q.head(), &mut q as *mut Queue);
    }

    #[test]
    #[ignore]
    fn test_queue_insert() {
        unsafe {
            let mut head = Queue::new();
            head.init();

            let mut nodes = vec![Queue::new(), Queue::new(), Queue::new()];

            head.insert_head(&mut nodes[0]);
            head.insert_head(&mut nodes[1]);
            head.insert_head(&mut nodes[2]);

            assert!(!head.is_empty());

            // Order should be 2, 1, 0 (inserted at head)
            let mut current = head.next;
            assert_eq!(current as *const Queue, &nodes[2] as *const Queue);

            current = (*current).next;
            assert_eq!(current as *const Queue, &nodes[1] as *const Queue);

            current = (*current).next;
            assert_eq!(current as *const Queue, &nodes[0] as *const Queue);
        }
    }

    #[test]
    fn test_queue_remove() {
        unsafe {
            let mut head = Queue::new();
            head.init();

            let mut node = Queue::new();
            head.insert_head(&mut node);

            assert!(!head.is_empty());

            node.remove();

            // After removal, should be empty again
            assert_eq!(head.next as *const Queue, &head as *const Queue);
        }
    }
}
