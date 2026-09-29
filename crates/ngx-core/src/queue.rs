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

// The operations that link and unlink nodes take raw pointers, as the
// ngx_queue.h macros do: a node is reached through the pointers of its
// neighbours, and changing it through a pointer derived from a shared
// reference to it (or while a mutable one is live) is undefined behaviour,
// which the compiler did exploit (a write to the head was dropped).

/// ngx_queue_init
pub unsafe fn queue_init(q: *mut Queue) {
    (*q).prev = q;
    (*q).next = q;
}

/// ngx_queue_empty
pub unsafe fn queue_empty(h: *const Queue) -> bool {
    h as *mut Queue == (*h).prev
}

/// ngx_queue_insert_head
pub unsafe fn queue_insert_head(h: *mut Queue, x: *mut Queue) {
    (*x).next = (*h).next;
    (*(*x).next).prev = x;
    (*x).prev = h;
    (*h).next = x;
}

/// ngx_queue_insert_after
pub unsafe fn queue_insert_after(h: *mut Queue, x: *mut Queue) {
    queue_insert_head(h, x);
}

/// ngx_queue_insert_tail
pub unsafe fn queue_insert_tail(h: *mut Queue, x: *mut Queue) {
    (*x).prev = (*h).prev;
    (*(*x).prev).next = x;
    (*x).next = h;
    (*h).prev = x;
}

/// ngx_queue_insert_before
pub unsafe fn queue_insert_before(h: *mut Queue, x: *mut Queue) {
    queue_insert_tail(h, x);
}

/// ngx_queue_head
pub unsafe fn queue_head(h: *const Queue) -> *mut Queue {
    (*h).next
}

/// ngx_queue_last
pub unsafe fn queue_last(h: *const Queue) -> *mut Queue {
    (*h).prev
}

/// ngx_queue_remove (NGX_DEBUG clears the pointers)
pub unsafe fn queue_remove(x: *mut Queue) {
    (*(*x).next).prev = (*x).prev;
    (*(*x).prev).next = (*x).next;
    (*x).prev = ptr::null_mut();
    (*x).next = ptr::null_mut();
}

/// ngx_queue_split
pub unsafe fn queue_split(h: *mut Queue, q: *mut Queue, n: *mut Queue) {
    (*n).prev = (*h).prev;
    (*(*n).prev).next = n;
    (*n).next = q;
    (*h).prev = (*q).prev;
    (*(*h).prev).next = h;
    (*q).prev = n;
}

/// ngx_queue_add
pub unsafe fn queue_add(h: *mut Queue, n: *mut Queue) {
    (*(*h).prev).next = (*n).next;
    (*(*n).next).prev = (*h).prev;
    (*h).prev = (*n).prev;
    (*(*h).prev).next = h;
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
    fn test_queue_insert() {
        unsafe {
            let head: *mut Queue = Box::into_raw(Box::new(Queue::new()));
            queue_init(head);

            let nodes: Vec<*mut Queue> = (0..3).map(|_| Box::into_raw(Box::new(Queue::new()))).collect();

            queue_insert_head(head, nodes[0]);
            queue_insert_head(head, nodes[1]);
            queue_insert_tail(head, nodes[2]);

            assert!(!queue_empty(head));

            // 1, 0, 2
            let mut current = queue_head(head);
            assert_eq!(current, nodes[1]);

            current = (*current).next;
            assert_eq!(current, nodes[0]);

            current = (*current).next;
            assert_eq!(current, nodes[2]);

            assert_eq!(queue_last(head), nodes[2]);
            assert_eq!((*current).next, head);

            for n in nodes.iter() {
                queue_remove(*n);
            }

            assert!(queue_empty(head));

            for n in nodes {
                drop(Box::from_raw(n));
            }
            drop(Box::from_raw(head));
        }
    }

    #[test]
    fn test_queue_remove() {
        unsafe {
            let head: *mut Queue = Box::into_raw(Box::new(Queue::new()));
            queue_init(head);

            let node: *mut Queue = Box::into_raw(Box::new(Queue::new()));
            queue_insert_head(head, node);

            assert!(!queue_empty(head));

            queue_remove(node);

            // After removal, should be empty again
            assert_eq!((*head).next, head);
            assert!(queue_empty(head));

            drop(Box::from_raw(node));
            drop(Box::from_raw(head));
        }
    }
}
