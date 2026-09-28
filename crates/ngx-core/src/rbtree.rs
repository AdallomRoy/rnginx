//! Red-black tree (ngx_rbtree.c): an intrusive tree, usable in shared
//! memory.
//!
//! The red-black tree code is based on the algorithm described in
//! the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.

use std::ptr;

/// ngx_rbtree_node_t
#[repr(C)]
pub struct RbtreeNode {
    pub key: usize,
    pub left: *mut RbtreeNode,
    pub right: *mut RbtreeNode,
    pub parent: *mut RbtreeNode,
    pub color: u8,
    pub data: u8,
}

pub type RbtreeInsertPt = unsafe fn(root: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode);

/// ngx_rbtree_t
#[repr(C)]
pub struct Rbtree {
    pub root: *mut RbtreeNode,
    pub sentinel: *mut RbtreeNode,
    pub insert: Option<RbtreeInsertPt>,
}

impl RbtreeNode {
    pub fn new(key: usize) -> Self {
        RbtreeNode { key, left: ptr::null_mut(), right: ptr::null_mut(), parent: ptr::null_mut(), color: 0, data: 0 }
    }
}

impl Rbtree {
    /// ngx_rbtree_init: a sentinel must be black
    pub unsafe fn init(&mut self, sentinel: *mut RbtreeNode, insert: RbtreeInsertPt) {
        rbt_black(sentinel);
        self.root = sentinel;
        self.sentinel = sentinel;
        self.insert = Some(insert);
    }

    /// ngx_rbtree_insert
    pub unsafe fn insert(&mut self, node: *mut RbtreeNode) {
        let mut node = node;

        // a binary tree insert

        let root: *mut *mut RbtreeNode = &mut self.root;
        let sentinel = self.sentinel;

        if *root == sentinel {
            (*node).parent = ptr::null_mut();
            (*node).left = sentinel;
            (*node).right = sentinel;
            rbt_black(node);
            *root = node;

            return;
        }

        (self.insert.expect("rbtree insert"))(*root, node, sentinel);

        // re-balance tree

        while node != *root && rbt_is_red((*node).parent) {
            if (*node).parent == (*(*(*node).parent).parent).left {
                let temp = (*(*(*node).parent).parent).right;

                if rbt_is_red(temp) {
                    rbt_black((*node).parent);
                    rbt_black(temp);
                    rbt_red((*(*node).parent).parent);
                    node = (*(*node).parent).parent;
                } else {
                    if node == (*(*node).parent).right {
                        node = (*node).parent;
                        left_rotate(root, sentinel, node);
                    }

                    rbt_black((*node).parent);
                    rbt_red((*(*node).parent).parent);
                    right_rotate(root, sentinel, (*(*node).parent).parent);
                }
            } else {
                let temp = (*(*(*node).parent).parent).left;

                if rbt_is_red(temp) {
                    rbt_black((*node).parent);
                    rbt_black(temp);
                    rbt_red((*(*node).parent).parent);
                    node = (*(*node).parent).parent;
                } else {
                    if node == (*(*node).parent).left {
                        node = (*node).parent;
                        right_rotate(root, sentinel, node);
                    }

                    rbt_black((*node).parent);
                    rbt_red((*(*node).parent).parent);
                    left_rotate(root, sentinel, (*(*node).parent).parent);
                }
            }
        }

        rbt_black(*root);
    }

    /// ngx_rbtree_delete
    pub unsafe fn delete(&mut self, node: *mut RbtreeNode) {
        // a binary tree delete

        let root: *mut *mut RbtreeNode = &mut self.root;
        let sentinel = self.sentinel;

        let subst;
        let mut temp;

        if (*node).left == sentinel {
            temp = (*node).right;
            subst = node;
        } else if (*node).right == sentinel {
            temp = (*node).left;
            subst = node;
        } else {
            subst = rbtree_min((*node).right, sentinel);
            temp = (*subst).right;
        }

        if subst == *root {
            *root = temp;
            rbt_black(temp);

            // DEBUG stuff
            (*node).left = ptr::null_mut();
            (*node).right = ptr::null_mut();
            (*node).parent = ptr::null_mut();
            (*node).key = 0;

            return;
        }

        let red = rbt_is_red(subst);

        if subst == (*(*subst).parent).left {
            (*(*subst).parent).left = temp;
        } else {
            (*(*subst).parent).right = temp;
        }

        if subst == node {
            (*temp).parent = (*subst).parent;
        } else {
            if (*subst).parent == node {
                (*temp).parent = subst;
            } else {
                (*temp).parent = (*subst).parent;
            }

            (*subst).left = (*node).left;
            (*subst).right = (*node).right;
            (*subst).parent = (*node).parent;
            rbt_copy_color(subst, node);

            if node == *root {
                *root = subst;
            } else if node == (*(*node).parent).left {
                (*(*node).parent).left = subst;
            } else {
                (*(*node).parent).right = subst;
            }

            if (*subst).left != sentinel {
                (*(*subst).left).parent = subst;
            }

            if (*subst).right != sentinel {
                (*(*subst).right).parent = subst;
            }
        }

        // DEBUG stuff
        (*node).left = ptr::null_mut();
        (*node).right = ptr::null_mut();
        (*node).parent = ptr::null_mut();
        (*node).key = 0;

        if red {
            return;
        }

        // a delete fixup

        while temp != *root && rbt_is_black(temp) {
            if temp == (*(*temp).parent).left {
                let mut w = (*(*temp).parent).right;

                if rbt_is_red(w) {
                    rbt_black(w);
                    rbt_red((*temp).parent);
                    left_rotate(root, sentinel, (*temp).parent);
                    w = (*(*temp).parent).right;
                }

                if rbt_is_black((*w).left) && rbt_is_black((*w).right) {
                    rbt_red(w);
                    temp = (*temp).parent;
                } else {
                    if rbt_is_black((*w).right) {
                        rbt_black((*w).left);
                        rbt_red(w);
                        right_rotate(root, sentinel, w);
                        w = (*(*temp).parent).right;
                    }

                    rbt_copy_color(w, (*temp).parent);
                    rbt_black((*temp).parent);
                    rbt_black((*w).right);
                    left_rotate(root, sentinel, (*temp).parent);
                    temp = *root;
                }
            } else {
                let mut w = (*(*temp).parent).left;

                if rbt_is_red(w) {
                    rbt_black(w);
                    rbt_red((*temp).parent);
                    right_rotate(root, sentinel, (*temp).parent);
                    w = (*(*temp).parent).left;
                }

                if rbt_is_black((*w).left) && rbt_is_black((*w).right) {
                    rbt_red(w);
                    temp = (*temp).parent;
                } else {
                    if rbt_is_black((*w).left) {
                        rbt_black((*w).right);
                        rbt_red(w);
                        left_rotate(root, sentinel, w);
                        w = (*(*temp).parent).left;
                    }

                    rbt_copy_color(w, (*temp).parent);
                    rbt_black((*temp).parent);
                    rbt_black((*w).left);
                    right_rotate(root, sentinel, (*temp).parent);
                    temp = *root;
                }
            }
        }

        rbt_black(temp);
    }
}

/// ngx_rbtree_left_rotate
#[inline]
unsafe fn left_rotate(root: *mut *mut RbtreeNode, sentinel: *mut RbtreeNode, node: *mut RbtreeNode) {
    let temp = (*node).right;
    (*node).right = (*temp).left;

    if (*temp).left != sentinel {
        (*(*temp).left).parent = node;
    }

    (*temp).parent = (*node).parent;

    if node == *root {
        *root = temp;
    } else if node == (*(*node).parent).left {
        (*(*node).parent).left = temp;
    } else {
        (*(*node).parent).right = temp;
    }

    (*temp).left = node;
    (*node).parent = temp;
}

/// ngx_rbtree_right_rotate
#[inline]
unsafe fn right_rotate(root: *mut *mut RbtreeNode, sentinel: *mut RbtreeNode, node: *mut RbtreeNode) {
    let temp = (*node).left;
    (*node).left = (*temp).right;

    if (*temp).right != sentinel {
        (*(*temp).right).parent = node;
    }

    (*temp).parent = (*node).parent;

    if node == *root {
        *root = temp;
    } else if node == (*(*node).parent).right {
        (*(*node).parent).right = temp;
    } else {
        (*(*node).parent).left = temp;
    }

    (*temp).right = node;
    (*node).parent = temp;
}

/// ngx_rbtree_min
pub unsafe fn rbtree_min(mut node: *mut RbtreeNode, sentinel: *mut RbtreeNode) -> *mut RbtreeNode {
    while (*node).left != sentinel {
        node = (*node).left;
    }
    node
}

/// ngx_rbtree_next: the next node in order, or null after the last one.
pub unsafe fn rbtree_next(tree: &Rbtree, node: *mut RbtreeNode) -> *mut RbtreeNode {
    let sentinel = tree.sentinel;

    if (*node).right != sentinel {
        return rbtree_min((*node).right, sentinel);
    }

    let root = tree.root;
    let mut node = node;

    loop {
        let parent = (*node).parent;

        if node == root {
            return ptr::null_mut();
        }

        if node == (*parent).left {
            return parent;
        }

        node = parent;
    }
}

/// ngx_rbtree_insert_value
pub unsafe fn rbtree_insert_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
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

/// ngx_rbtree_insert_timer_value
pub unsafe fn rbtree_insert_timer_value(mut temp: *mut RbtreeNode, node: *mut RbtreeNode, sentinel: *mut RbtreeNode) {
    let mut p: *mut *mut RbtreeNode;

    loop {
        // Timer values
        // 1) are spread in small range, usually several minutes,
        // 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
        // The comparison takes into account that overflow.

        // node->key < temp->key

        p = if ((*node).key.wrapping_sub((*temp).key) as isize) < 0 { &mut (*temp).left } else { &mut (*temp).right };

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

#[inline]
pub unsafe fn rbt_red(node: *mut RbtreeNode) {
    (*node).color = 1;
}

#[inline]
pub unsafe fn rbt_black(node: *mut RbtreeNode) {
    (*node).color = 0;
}

#[inline]
pub unsafe fn rbt_is_red(node: *mut RbtreeNode) -> bool {
    (*node).color != 0
}

#[inline]
pub unsafe fn rbt_is_black(node: *mut RbtreeNode) -> bool {
    !rbt_is_red(node)
}

#[inline]
pub unsafe fn rbt_copy_color(n1: *mut RbtreeNode, n2: *mut RbtreeNode) {
    (*n1).color = (*n2).color;
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn keys(tree: &Rbtree) -> Vec<usize> {
        let mut out = vec![];
        if tree.root == tree.sentinel {
            return out;
        }
        let mut n = rbtree_min(tree.root, tree.sentinel);
        while !n.is_null() {
            out.push((*n).key);
            n = rbtree_next(tree, n);
        }
        out
    }

    // every path from a node down has the same number of black nodes, and
    // a red node has no red child
    unsafe fn black_height(n: *mut RbtreeNode, sentinel: *mut RbtreeNode) -> usize {
        if n == sentinel {
            return 1;
        }
        if rbt_is_red(n) {
            assert!(rbt_is_black((*n).left) && rbt_is_black((*n).right));
        }
        let l = black_height((*n).left, sentinel);
        let r = black_height((*n).right, sentinel);
        assert_eq!(l, r);
        l + if rbt_is_black(n) { 1 } else { 0 }
    }

    #[test]
    fn insert_delete() {
        unsafe {
            let mut sentinel = Box::new(RbtreeNode::new(0));
            let mut tree = Rbtree { root: ptr::null_mut(), sentinel: ptr::null_mut(), insert: None };
            tree.init(&mut *sentinel, rbtree_insert_value);

            let mut nodes: Vec<Box<RbtreeNode>> = (0..200).map(|i| Box::new(RbtreeNode::new((i * 7919) % 200))).collect();
            for n in nodes.iter_mut() {
                tree.insert(&mut **n);
                black_height(tree.root, tree.sentinel);
            }
            assert_eq!(keys(&tree), (0..200).collect::<Vec<_>>());

            for (i, n) in nodes.iter_mut().enumerate() {
                if i % 3 == 0 {
                    tree.delete(&mut **n);
                    black_height(tree.root, tree.sentinel);
                }
            }
            let expected: Vec<usize> = {
                let mut v: Vec<usize> = (0..200).filter(|i| i % 3 != 0).map(|i| (i * 7919) % 200).collect();
                v.sort();
                v
            };
            assert_eq!(keys(&tree), expected);

            for (i, n) in nodes.iter_mut().enumerate() {
                if i % 3 != 0 {
                    tree.delete(&mut **n);
                }
            }
            assert!(tree.root == tree.sentinel);
        }
    }
}
