//! Binary radix tree for CIDR lookups (port of ngx_radix_tree.c)

use std::cell::RefCell;
use std::rc::Rc;

pub const NGX_RADIX_NO_VALUE: usize = usize::MAX;

#[derive(Debug)]
pub struct RadixNode {
    pub right: Option<Rc<RefCell<RadixNode>>>,
    pub left: Option<Rc<RefCell<RadixNode>>>,
    pub parent: Option<Rc<RefCell<RadixNode>>>,
    pub value: usize,
}

pub struct RadixTree {
    pub root: Rc<RefCell<RadixNode>>,
    pub free: RefCell<Vec<Rc<RefCell<RadixNode>>>>,
}

impl RadixTree {
    /// Create a new radix tree with optional preallocation
    pub fn create(preallocate: i32) -> Self {
        let root = Rc::new(RefCell::new(RadixNode {
            right: None,
            left: None,
            parent: None,
            value: NGX_RADIX_NO_VALUE,
        }));

        let tree = RadixTree {
            root: root.clone(),
            free: RefCell::new(Vec::new()),
        };

        // ngx_radix_tree_create(): -1 is the default preallocation, the
        // first levels of the tree that fit in a page
        let preallocate = if preallocate == -1 {
            match crate::os::pagesize() / (4 * std::mem::size_of::<usize>()) {
                // amd64
                128 => 6,
                // i386, sparc64
                256 => 7,
                // sparc64 in 32-bit mode
                _ => 8,
            }
        } else {
            preallocate
        };

        if preallocate > 0 {
            let mut p = preallocate as u32;
            let mut mask: u32 = 0;
            let mut inc: u32 = 0x80000000;

            while p > 0 {
                p -= 1;
                let mut key: u32 = 0;
                mask >>= 1;
                mask |= 0x80000000;

                loop {
                    let _ = tree.insert32(key, mask, NGX_RADIX_NO_VALUE);
                    key = key.wrapping_add(inc);
                    if key == 0 {
                        break;
                    }
                }

                inc >>= 1;
            }
        }

        tree
    }

    fn alloc(&self) -> Rc<RefCell<RadixNode>> {
        if let Some(node) = self.free.borrow_mut().pop() {
            return node;
        }

        Rc::new(RefCell::new(RadixNode {
            right: None,
            left: None,
            parent: None,
            value: NGX_RADIX_NO_VALUE,
        }))
    }

    /// Insert a 32-bit key with mask
    pub fn insert32(&self, key: u32, mask: u32, value: usize) -> i32 {
        let mut bit: u32 = 0x80000000;
        let mut node = self.root.clone();
        let mut next = self.root.clone();
        // next != NULL: the root, for a zero mask
        let mut found = true;

        // Find insertion point
        while bit & mask != 0 {
            let borrowed = node.borrow();
            let next_opt = if key & bit != 0 {
                borrowed.right.clone()
            } else {
                borrowed.left.clone()
            };
            drop(borrowed);

            if let Some(n) = next_opt {
                next = n.clone();
                node = next.clone();
                found = true;
                bit >>= 1;
            } else {
                found = false;
                break;
            }
        }

        // Check if we found an existing node at this position
        if found && Rc::ptr_eq(&next, &node) {
            let mut n = node.borrow_mut();
            if n.value != NGX_RADIX_NO_VALUE {
                return -3; // NGX_BUSY
            }
            n.value = value;
            return 0; // NGX_OK
        }

        // Create new nodes
        while bit & mask != 0 {
            let new_node = self.alloc();
            {
                let mut new = new_node.borrow_mut();
                new.parent = Some(node.clone());
                new.value = NGX_RADIX_NO_VALUE;
            }

            {
                let mut n = node.borrow_mut();
                if key & bit != 0 {
                    n.right = Some(new_node.clone());
                } else {
                    n.left = Some(new_node.clone());
                }
            }

            node = new_node;
            bit >>= 1;
        }

        {
            let mut n = node.borrow_mut();
            n.value = value;
        }

        0 // NGX_OK
    }

    /// Delete a 32-bit key with mask
    pub fn delete32(&self, key: u32, mask: u32) -> i32 {
        let mut bit: u32 = 0x80000000;
        let mut node = self.root.clone();

        // Find the node
        while (bit & mask) != 0 {
            let borrowed = node.borrow();
            let next = if key & bit != 0 {
                borrowed.right.clone()
            } else {
                borrowed.left.clone()
            };
            drop(borrowed);

            if let Some(n) = next {
                node = n;
                bit >>= 1;
            } else {
                return -1; // NGX_ERROR
            }
        }

        // Check if node has children
        let has_children = {
            let n = node.borrow();
            n.right.is_some() || n.left.is_some()
        };

        if has_children {
            let mut n = node.borrow_mut();
            if n.value != NGX_RADIX_NO_VALUE {
                n.value = NGX_RADIX_NO_VALUE;
                return 0; // NGX_OK
            }
            return -1; // NGX_ERROR
        }

        // Remove node and parents if they become empty
        let mut current = node.clone();
        loop {
            let parent_opt = {
                let n = current.borrow();
                n.parent.clone()
            };

            if let Some(parent) = parent_opt {
                {
                    let mut p = parent.borrow_mut();
                    if p.right.as_ref().map_or(false, |r| Rc::ptr_eq(r, &current)) {
                        p.right = None;
                    } else {
                        p.left = None;
                    }
                }

                {
                    let mut current_mut = current.borrow_mut();
                    current_mut.right = None;
                    current_mut.left = None;
                }

                // Free the current node
                self.free.borrow_mut().push(current.clone());

                current = parent;

                // Check if we should continue
                let should_continue = {
                    let p = current.borrow();
                    !( (p.right.is_some() || p.left.is_some()) || p.value != NGX_RADIX_NO_VALUE || p.parent.is_none())
                };

                if !should_continue {
                    break;
                }
            } else {
                break;
            }
        }

        0 // NGX_OK
    }

    /// Find a 32-bit key
    pub fn find32(&self, key: u32) -> usize {
        let mut bit: u32 = 0x80000000;
        let mut value = NGX_RADIX_NO_VALUE;
        let mut node = Some(self.root.clone());

        while let Some(n) = node {
            {
                let borrowed = n.borrow();
                if borrowed.value != NGX_RADIX_NO_VALUE {
                    value = borrowed.value;
                }

                node = if key & bit != 0 {
                    borrowed.right.clone()
                } else {
                    borrowed.left.clone()
                };
            }

            bit >>= 1;
        }

        value
    }

    /// Insert a 128-bit (IPv6) key with mask
    pub fn insert128(&self, key: &[u8; 16], mask: &[u8; 16], value: usize) -> i32 {
        let mut i = 0usize;
        let mut bit: u8 = 0x80;
        let mut node = self.root.clone();
        let mut next = self.root.clone();
        // next != NULL: the root, for a zero mask
        let mut found = true;

        // Find insertion point
        while bit & mask[i] != 0 {
            let borrowed = node.borrow();
            let next_opt = if key[i] & bit != 0 {
                borrowed.right.clone()
            } else {
                borrowed.left.clone()
            };
            drop(borrowed);

            if let Some(n) = next_opt {
                next = n.clone();
                node = next.clone();
                found = true;
                bit >>= 1;
                if bit == 0 {
                    i += 1;
                    if i == 16 {
                        break;
                    }
                    bit = 0x80;
                }
            } else {
                found = false;
                break;
            }
        }

        // Check if we found an existing node
        if found && Rc::ptr_eq(&next, &node) {
            let mut n = node.borrow_mut();
            if n.value != NGX_RADIX_NO_VALUE {
                return -3; // NGX_BUSY
            }
            n.value = value;
            return 0; // NGX_OK
        }

        // Create new nodes
        while bit & mask[i] != 0 {
            let new_node = self.alloc();
            {
                let mut new = new_node.borrow_mut();
                new.parent = Some(node.clone());
                new.value = NGX_RADIX_NO_VALUE;
            }

            {
                let mut n = node.borrow_mut();
                if key[i] & bit != 0 {
                    n.right = Some(new_node.clone());
                } else {
                    n.left = Some(new_node.clone());
                }
            }

            node = new_node;
            bit >>= 1;

            if bit == 0 {
                i += 1;
                if i == 16 {
                    break;
                }
                bit = 0x80;
            }
        }

        {
            let mut n = node.borrow_mut();
            n.value = value;
        }

        0 // NGX_OK
    }

    /// Delete a 128-bit (IPv6) key with mask
    pub fn delete128(&self, key: &[u8; 16], mask: &[u8; 16]) -> i32 {
        let mut i = 0usize;
        let mut bit: u8 = 0x80;
        let mut node = self.root.clone();

        // Find the node
        while (bit & mask[i]) != 0 {
            let borrowed = node.borrow();
            let next = if key[i] & bit != 0 {
                borrowed.right.clone()
            } else {
                borrowed.left.clone()
            };
            drop(borrowed);

            if let Some(n) = next {
                node = n;
                bit >>= 1;

                if bit == 0 {
                    i += 1;
                    if i == 16 {
                        break;
                    }
                    bit = 0x80;
                }
            } else {
                return -1; // NGX_ERROR
            }
        }

        // Check if node has children
        let has_children = {
            let n = node.borrow();
            n.right.is_some() || n.left.is_some()
        };

        if has_children {
            let mut n = node.borrow_mut();
            if n.value != NGX_RADIX_NO_VALUE {
                n.value = NGX_RADIX_NO_VALUE;
                return 0; // NGX_OK
            }
            return -1; // NGX_ERROR
        }

        // Remove node and parents if they become empty
        let mut current = node.clone();
        loop {
            let parent_opt = {
                let n = current.borrow();
                n.parent.clone()
            };

            if let Some(parent) = parent_opt {
                {
                    let mut p = parent.borrow_mut();
                    if p.right.as_ref().map_or(false, |r| Rc::ptr_eq(r, &current)) {
                        p.right = None;
                    } else {
                        p.left = None;
                    }
                }

                {
                    let mut current_mut = current.borrow_mut();
                    current_mut.right = None;
                    current_mut.left = None;
                }

                // Free the current node
                self.free.borrow_mut().push(current.clone());

                current = parent;

                // Check if we should continue
                let should_continue = {
                    let p = current.borrow();
                    !( (p.right.is_some() || p.left.is_some()) || p.value != NGX_RADIX_NO_VALUE || p.parent.is_none())
                };

                if !should_continue {
                    break;
                }
            } else {
                break;
            }
        }

        0 // NGX_OK
    }

    /// Find a 128-bit (IPv6) key
    pub fn find128(&self, key: &[u8; 16]) -> usize {
        let mut i = 0usize;
        let mut bit: u8 = 0x80;
        let mut value = NGX_RADIX_NO_VALUE;
        let mut node = Some(self.root.clone());

        while let Some(n) = node {
            {
                let borrowed = n.borrow();
                if borrowed.value != NGX_RADIX_NO_VALUE {
                    value = borrowed.value;
                }

                // a node of a /128 network has no children
                if i == 16 {
                    break;
                }

                node = if key[i] & bit != 0 {
                    borrowed.right.clone()
                } else {
                    borrowed.left.clone()
                };
            }

            bit >>= 1;
            if bit == 0 {
                i += 1;
                bit = 0x80;
            }
        }

        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_zero_mask_busy() {
        // the default network 0.0.0.0/0 is the root, as in C
        let t = RadixTree::create(-1);
        assert_eq!(t.insert32(0, 0, 1), 0);
        assert_eq!(t.insert32(0, 0, 2), -3);
        assert_eq!(t.find32(0x7f000001), 1);

        assert_eq!(t.insert32(0x7f000000, 0xff000000, 3), 0);
        assert_eq!(t.insert32(0x7f000000, 0xff000000, 4), -3);
        assert_eq!(t.find32(0x7f000001), 3);
        assert_eq!(t.find32(0x0a000001), 1);

        assert_eq!(t.delete32(0x7f000000, 0xff000000), 0);
        assert_eq!(t.find32(0x7f000001), 1);

        // the preallocated root has children
        assert_eq!(t.delete32(0, 0), 0);
        assert_eq!(t.find32(0x7f000001), NGX_RADIX_NO_VALUE);
        assert_eq!(t.delete32(0, 0), -1);
    }

    #[test]
    fn find128_full_mask() {
        let t = RadixTree::create(-1);
        let zero = [0u8; 16];
        let mut one = [0u8; 16];
        one[15] = 1;
        let full = [0xffu8; 16];

        assert_eq!(t.insert128(&zero, &zero, 1), 0);
        assert_eq!(t.insert128(&zero, &zero, 2), -3);
        assert_eq!(t.insert128(&one, &full, 3), 0);
        assert_eq!(t.insert128(&one, &full, 4), -3);

        assert_eq!(t.find128(&one), 3);
        assert_eq!(t.find128(&full), 1);

        assert_eq!(t.delete128(&one, &full), 0);
        assert_eq!(t.find128(&one), 1);
    }
}
