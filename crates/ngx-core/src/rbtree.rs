//! Red-black tree (ngx_rbtree.c) — intrusive tree usable in shared memory.

use std::ptr;

/// Red-black tree node. Uses color in lower bits and contains user data.
#[repr(C)]
#[derive(PartialEq)]
pub struct RbtreeNode {
    pub key: usize,
    pub left: *mut RbtreeNode,
    pub right: *mut RbtreeNode,
    pub parent: *mut RbtreeNode,
    pub color: u8,  // 0=black, 1=red
    pub data: u8,   // padding/user data
}

/// Red-black tree with custom insert function.
#[repr(C)]
pub struct Rbtree {
    pub root: *mut RbtreeNode,
    pub sentinel: *mut RbtreeNode,
    pub insert: Option<unsafe fn(temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode)>,
}

impl RbtreeNode {
    /// Create a new node (uninitialized parent/children).
    pub fn new(key: usize) -> Self {
        RbtreeNode {
            key,
            left: ptr::null_mut(),
            right: ptr::null_mut(),
            parent: ptr::null_mut(),
            color: 1,  // red by default
            data: 0,
        }
    }
}

impl Rbtree {
    /// Initialize a tree with a sentinel node.
    pub unsafe fn init(&mut self, sentinel: *mut RbtreeNode, insert_fn: unsafe fn(*mut RbtreeNode, *mut RbtreeNode, *mut RbtreeNode)) {
        (*sentinel).color = 0;  // black
        self.root = sentinel;
        self.sentinel = sentinel;
        self.insert = Some(insert_fn);
    }

    /// Insert a node with the tree's insert function.
    pub unsafe fn insert(&mut self, node: *mut RbtreeNode) {
        let sentinel = self.sentinel;

        if self.root == sentinel {
            (*node).parent = ptr::null_mut();
            (*node).left = sentinel;
            (*node).right = sentinel;
            (*node).color = 0;  // black
            self.root = node;
            return;
        }

        if let Some(insert_fn) = self.insert {
            insert_fn(self.root, node, sentinel);
        }

        // Re-balance
        self._rebalance_after_insert(node);

        rbt_black(self.root);
    }

    unsafe fn _rebalance_after_insert(&mut self, mut node: *mut RbtreeNode) {
        while node != self.root && rbt_is_red(node) && !(*node).parent.is_null() {
            let parent = (*node).parent;
            if parent.is_null() {
                break;
            }
            let grandparent = (*parent).parent;

            if parent == (*grandparent).left {
                let uncle = (*grandparent).right;

                if rbt_is_red(uncle) {
                    rbt_black(parent);
                    rbt_black(uncle);
                    rbt_red(grandparent);
                    node = grandparent;
                } else {
                    if node == (*parent).right {
                        node = parent;
                        self._left_rotate(node);
                    }

                    rbt_black((*node).parent);
                    rbt_red((*(*node).parent).parent);
                    self._right_rotate((*(*node).parent).parent);
                }
            } else {
                let uncle = (*grandparent).left;

                if rbt_is_red(uncle) {
                    rbt_black(parent);
                    rbt_black(uncle);
                    rbt_red(grandparent);
                    node = grandparent;
                } else {
                    if node == (*parent).left {
                        node = parent;
                        self._right_rotate(node);
                    }

                    rbt_black((*node).parent);
                    rbt_red((*(*node).parent).parent);
                    self._left_rotate((*(*node).parent).parent);
                }
            }
        }
    }

    unsafe fn _left_rotate(&mut self, node: *mut RbtreeNode) {
        let temp = (*node).right;
        (*node).right = (*temp).left;

        if (*temp).left != self.sentinel {
            (*(*temp).left).parent = node;
        }

        (*temp).parent = (*node).parent;

        if node == self.root {
            self.root = temp;
        } else if node == (*(*node).parent).left {
            (*(*node).parent).left = temp;
        } else {
            (*(*node).parent).right = temp;
        }

        (*temp).left = node;
        (*node).parent = temp;
    }

    unsafe fn _right_rotate(&mut self, node: *mut RbtreeNode) {
        let temp = (*node).left;
        (*node).left = (*temp).right;

        if (*temp).right != self.sentinel {
            (*(*temp).right).parent = node;
        }

        (*temp).parent = (*node).parent;

        if node == self.root {
            self.root = temp;
        } else if node == (*(*node).parent).left {
            (*(*node).parent).left = temp;
        } else {
            (*(*node).parent).right = temp;
        }

        (*temp).right = node;
        (*node).parent = temp;
    }

    /// Delete a node from the tree.
    pub unsafe fn delete(&mut self, node: *mut RbtreeNode) {
        let mut subst: *mut RbtreeNode;
        let mut temp: *mut RbtreeNode;

        if (*node).left == self.sentinel {
            temp = (*node).right;
            subst = node;
        } else if (*node).right == self.sentinel {
            temp = (*node).left;
            subst = node;
        } else {
            subst = rbtree_min((*node).right, self.sentinel);
            temp = (*subst).right;
        }

        if subst == self.root {
            self.root = temp;
            rbt_black(temp);
            return;
        }

        let red = rbt_is_red(subst);

        if subst == (*(*subst).parent).left {
            (*(*subst).parent).left = temp;
        } else {
            (*(*subst).parent).right = temp;
        }

        if !red {
            self._rebalance_after_delete(temp);
        }
    }

    unsafe fn _rebalance_after_delete(&mut self, mut node: *mut RbtreeNode) {
        while node != self.root && !rbt_is_red(node) {
            if node == (*(*node).parent).left {
                let mut sibling = (*(*node).parent).right;

                if rbt_is_red(sibling) {
                    rbt_black(sibling);
                    rbt_red((*node).parent);
                    self._left_rotate((*node).parent);
                    sibling = (*(*node).parent).right;
                }

                if !rbt_is_red((*sibling).left) && !rbt_is_red((*sibling).right) {
                    rbt_red(sibling);
                    node = (*node).parent;
                } else {
                    if !rbt_is_red((*sibling).right) {
                        rbt_black((*sibling).left);
                        rbt_red(sibling);
                        self._right_rotate(sibling);
                        sibling = (*(*node).parent).right;
                    }

                    rbt_copy_color(sibling, (*node).parent);
                    rbt_black((*node).parent);
                    rbt_black((*sibling).right);
                    self._left_rotate((*node).parent);
                    node = self.root;
                }
            } else {
                let mut sibling = (*(*node).parent).left;

                if rbt_is_red(sibling) {
                    rbt_black(sibling);
                    rbt_red((*node).parent);
                    self._right_rotate((*node).parent);
                    sibling = (*(*node).parent).left;
                }

                if !rbt_is_red((*sibling).right) && !rbt_is_red((*sibling).left) {
                    rbt_red(sibling);
                    node = (*node).parent;
                } else {
                    if !rbt_is_red((*sibling).left) {
                        rbt_black((*sibling).right);
                        rbt_red(sibling);
                        self._left_rotate(sibling);
                        sibling = (*(*node).parent).left;
                    }

                    rbt_copy_color(sibling, (*node).parent);
                    rbt_black((*node).parent);
                    rbt_black((*sibling).left);
                    self._right_rotate((*node).parent);
                    node = self.root;
                }
            }
        }

        rbt_black(node);
    }
}

/// Find the minimum node in a subtree.
pub unsafe fn rbtree_min(mut node: *mut RbtreeNode, sentinel: *mut RbtreeNode) -> *mut RbtreeNode {
    while (*node).left != sentinel {
        node = (*node).left;
    }
    node
}

/// Find the next node in order.
pub unsafe fn rbtree_next(tree: &Rbtree, node: *mut RbtreeNode) -> *mut RbtreeNode {
    let sentinel = tree.sentinel;

    if (*node).right != sentinel {
        return rbtree_min((*node).right, sentinel);
    }

    let mut parent = (*node).parent;
    let mut n = node;

    while n == (*parent).right {
        n = parent;
        parent = (*parent).parent;
    }

    if n != (*parent).right {
        return parent;
    }

    sentinel
}

/// Default insert function: by key value.
pub unsafe fn rbtree_insert_value(
    mut temp: *mut RbtreeNode,
    node: *mut RbtreeNode,
    sentinel: *mut RbtreeNode,
) {
    let mut p: *mut *mut RbtreeNode;
    loop {
        p = if (*node).key < (*temp).key { &mut (*temp).left } else { &mut (*temp).right };

        if *p == sentinel {
            break;
        }

        temp = *p;
    }

    *p = node;
    (*node).parent = temp;
    (*node).left = sentinel;
    (*node).right = sentinel;
    rbt_red(node);
}

/// Insert function for timer values (handles overflow).
pub unsafe fn rbtree_insert_timer_value(
    mut temp: *mut RbtreeNode,
    node: *mut RbtreeNode,
    sentinel: *mut RbtreeNode,
) {
    let mut p: *mut *mut RbtreeNode;
    loop {
        // Handle timer overflow (49 days for ms in 32 bits)
        let cmp = ((*node).key as i64) - ((*temp).key as i64);
        p = if cmp < 0 { &mut (*temp).left } else { &mut (*temp).right };

        if *p == sentinel {
            break;
        }

        temp = *p;
    }

    *p = node;
    (*node).parent = temp;
    (*node).left = sentinel;
    (*node).right = sentinel;
    rbt_red(node);
}

// Color helpers
#[inline]
unsafe fn rbt_red(node: *mut RbtreeNode) {
    (*node).color = 1;
}

#[inline]
unsafe fn rbt_black(node: *mut RbtreeNode) {
    (*node).color = 0;
}

#[inline]
unsafe fn rbt_is_red(node: *mut RbtreeNode) -> bool {
    (*node).color != 0
}

#[inline]
unsafe fn rbt_is_black(node: *mut RbtreeNode) -> bool {
    (*node).color == 0
}

#[inline]
unsafe fn rbt_copy_color(n1: *mut RbtreeNode, n2: *mut RbtreeNode) {
    (*n1).color = (*n2).color;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_rbtree_basic() {
        unsafe {
            // Create sentinel
            let mut sentinel = Box::new(RbtreeNode::new(0));
            sentinel.color = 0; // black
            let sentinel_ptr = &mut *sentinel as *mut RbtreeNode;

            // Create tree
            let mut tree = Rbtree {
                root: sentinel_ptr,
                sentinel: sentinel_ptr,
                insert: Some(rbtree_insert_value),
            };

            // Insert nodes
            let mut nodes = vec![];
            for i in (0..10).rev() {
                nodes.push(Box::new(RbtreeNode::new(i)));
            }

            let node_ptrs: Vec<_> = nodes.iter_mut().map(|n| &mut **n as *mut RbtreeNode).collect();

            for &ptr in &node_ptrs {
                tree.insert(ptr);
            }

            // Verify order by traversing
            let mut keys = vec![];
            let mut current = rbtree_min(tree.root, tree.sentinel);
            while current != tree.sentinel {
                keys.push((*current).key);
                current = rbtree_next(&tree, current);
            }

            assert_eq!(keys, (0..10).collect::<Vec<_>>());

            // Test delete
            tree.delete(node_ptrs[3]);
            keys.clear();
            current = rbtree_min(tree.root, tree.sentinel);
            while current != tree.sentinel {
                keys.push((*current).key);
                current = rbtree_next(&tree, current);
            }

            let expected: Vec<_> = (0..10).filter(|&i| i != 3).collect();
            assert_eq!(keys, expected);
        }
    }
}
