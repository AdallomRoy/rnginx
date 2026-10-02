//! Red-black tree (ngx_rbtree.c), on node handles instead of pointers.
//!
//! The red-black tree code is based on the algorithm described in
//! the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
//!
//! The algorithm works on any storage of nodes implementing `RbTree`
//! (node handles are offsets in a zone or indexes in a vector, 0 meaning
//! NULL): `ShmRbtree` is a tree in a zone, laid out as C lays out
//! ngx_rbtree_t and ngx_rbtree_node_t (modules overlay their nodes on
//! them as in C); `LocalRbtree` is a tree of the process, nodes in a
//! vector with a value each.

use std::cell::{Cell, Ref, RefCell, RefMut};

use super::ShmMem;
use crate::shm_struct;

/// The storage of a tree: its root, its sentinel, and the fields of its
/// nodes (the handle 0 is NULL).
pub trait RbTree {
    fn root(&self) -> usize;
    fn set_root(&self, n: usize);
    fn sentinel(&self) -> usize;
    fn key(&self, n: usize) -> usize;
    fn set_key(&self, n: usize, key: usize);
    fn left(&self, n: usize) -> usize;
    fn set_left(&self, n: usize, v: usize);
    fn right(&self, n: usize) -> usize;
    fn set_right(&self, n: usize, v: usize);
    fn parent(&self, n: usize) -> usize;
    fn set_parent(&self, n: usize, v: usize);
    fn is_red(&self, n: usize) -> bool;
    fn set_red(&self, n: usize, red: bool);
}

/// ngx_rbt_red()
#[inline]
fn red<T: RbTree + ?Sized>(t: &T, n: usize) {
    t.set_red(n, true);
}

/// ngx_rbt_black()
#[inline]
fn black<T: RbTree + ?Sized>(t: &T, n: usize) {
    t.set_red(n, false);
}

/// ngx_rbtree_init: an empty tree, its sentinel black
pub fn init<T: RbTree + ?Sized>(t: &T) {
    let sentinel = t.sentinel();
    black(t, sentinel);
    t.set_root(sentinel);
}

/// ngx_rbtree_insert: `insert_value(tree, temp, node, sentinel)` places
/// the node under the root (ngx_rbtree_insert_value() and the like)
pub fn insert<T: RbTree + ?Sized>(t: &T, node: usize, insert_value: impl FnOnce(&T, usize, usize, usize)) {
    let mut node = node;

    // a binary tree insert

    let sentinel = t.sentinel();

    if t.root() == sentinel {
        t.set_parent(node, 0);
        t.set_left(node, sentinel);
        t.set_right(node, sentinel);
        black(t, node);
        t.set_root(node);

        return;
    }

    insert_value(t, t.root(), node, sentinel);

    // re-balance tree

    while node != t.root() && t.is_red(t.parent(node)) {
        let parent = t.parent(node);
        let grand = t.parent(parent);

        if parent == t.left(grand) {
            let temp = t.right(grand);

            if t.is_red(temp) {
                black(t, parent);
                black(t, temp);
                red(t, grand);
                node = grand;
            } else {
                if node == t.right(parent) {
                    node = parent;
                    left_rotate(t, sentinel, node);
                }

                let parent = t.parent(node);
                let grand = t.parent(parent);
                black(t, parent);
                red(t, grand);
                right_rotate(t, sentinel, grand);
            }
        } else {
            let temp = t.left(grand);

            if t.is_red(temp) {
                black(t, parent);
                black(t, temp);
                red(t, grand);
                node = grand;
            } else {
                if node == t.left(parent) {
                    node = parent;
                    right_rotate(t, sentinel, node);
                }

                let parent = t.parent(node);
                let grand = t.parent(parent);
                black(t, parent);
                red(t, grand);
                left_rotate(t, sentinel, grand);
            }
        }
    }

    black(t, t.root());
}

/// ngx_rbtree_insert_value: by key, equal keys to the right
pub fn insert_value<T: RbTree + ?Sized>(t: &T, temp: usize, node: usize, sentinel: usize) {
    insert_by(t, temp, node, sentinel, |t, node, temp| t.key(node) < t.key(temp));
}

/// ngx_rbtree_insert_timer_value: by key, as timers wrapping around
pub fn insert_timer_value<T: RbTree + ?Sized>(t: &T, temp: usize, node: usize, sentinel: usize) {
    // Timer values
    // 1) are spread in small range, usually several minutes,
    // 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
    // The comparison takes into account that overflow.

    // node->key < temp->key

    insert_by(t, temp, node, sentinel, |t, node, temp| (t.key(node).wrapping_sub(t.key(temp)) as isize) < 0);
}

/// The binary insert of the insert_value functions: `left(tree, node,
/// temp)` tells whether the node goes to the left of temp.
pub fn insert_by<T: RbTree + ?Sized>(t: &T, mut temp: usize, node: usize, sentinel: usize, mut left: impl FnMut(&T, usize, usize) -> bool) {
    loop {
        let go_left = left(t, node, temp);
        let next = if go_left { t.left(temp) } else { t.right(temp) };

        if next == sentinel {
            if go_left {
                t.set_left(temp, node);
            } else {
                t.set_right(temp, node);
            }
            break;
        }

        temp = next;
    }

    t.set_parent(node, temp);
    t.set_left(node, sentinel);
    t.set_right(node, sentinel);
    red(t, node);
}

/// ngx_rbtree_delete
pub fn delete<T: RbTree + ?Sized>(t: &T, node: usize) {
    // a binary tree delete

    let sentinel = t.sentinel();

    let subst;
    let mut temp;

    if t.left(node) == sentinel {
        temp = t.right(node);
        subst = node;
    } else if t.right(node) == sentinel {
        temp = t.left(node);
        subst = node;
    } else {
        subst = min(t, t.right(node));
        temp = t.right(subst);
    }

    if subst == t.root() {
        t.set_root(temp);
        black(t, temp);

        // DEBUG stuff
        t.set_left(node, 0);
        t.set_right(node, 0);
        t.set_parent(node, 0);
        t.set_key(node, 0);

        return;
    }

    let is_red = t.is_red(subst);

    if subst == t.left(t.parent(subst)) {
        t.set_left(t.parent(subst), temp);
    } else {
        t.set_right(t.parent(subst), temp);
    }

    if subst == node {
        t.set_parent(temp, t.parent(subst));
    } else {
        if t.parent(subst) == node {
            t.set_parent(temp, subst);
        } else {
            t.set_parent(temp, t.parent(subst));
        }

        t.set_left(subst, t.left(node));
        t.set_right(subst, t.right(node));
        t.set_parent(subst, t.parent(node));
        t.set_red(subst, t.is_red(node));

        if node == t.root() {
            t.set_root(subst);
        } else if node == t.left(t.parent(node)) {
            t.set_left(t.parent(node), subst);
        } else {
            t.set_right(t.parent(node), subst);
        }

        if t.left(subst) != sentinel {
            t.set_parent(t.left(subst), subst);
        }

        if t.right(subst) != sentinel {
            t.set_parent(t.right(subst), subst);
        }
    }

    // DEBUG stuff
    t.set_left(node, 0);
    t.set_right(node, 0);
    t.set_parent(node, 0);
    t.set_key(node, 0);

    if is_red {
        return;
    }

    // a delete fixup

    while temp != t.root() && !t.is_red(temp) {
        let parent = t.parent(temp);

        if temp == t.left(parent) {
            let mut w = t.right(parent);

            if t.is_red(w) {
                black(t, w);
                red(t, parent);
                left_rotate(t, sentinel, parent);
                w = t.right(t.parent(temp));
            }

            if !t.is_red(t.left(w)) && !t.is_red(t.right(w)) {
                red(t, w);
                temp = t.parent(temp);
            } else {
                if !t.is_red(t.right(w)) {
                    black(t, t.left(w));
                    red(t, w);
                    right_rotate(t, sentinel, w);
                    w = t.right(t.parent(temp));
                }

                t.set_red(w, t.is_red(t.parent(temp)));
                black(t, t.parent(temp));
                black(t, t.right(w));
                left_rotate(t, sentinel, t.parent(temp));
                temp = t.root();
            }
        } else {
            let mut w = t.left(parent);

            if t.is_red(w) {
                black(t, w);
                red(t, parent);
                right_rotate(t, sentinel, parent);
                w = t.left(t.parent(temp));
            }

            if !t.is_red(t.left(w)) && !t.is_red(t.right(w)) {
                red(t, w);
                temp = t.parent(temp);
            } else {
                if !t.is_red(t.left(w)) {
                    black(t, t.right(w));
                    red(t, w);
                    left_rotate(t, sentinel, w);
                    w = t.left(t.parent(temp));
                }

                t.set_red(w, t.is_red(t.parent(temp)));
                black(t, t.parent(temp));
                black(t, t.left(w));
                right_rotate(t, sentinel, t.parent(temp));
                temp = t.root();
            }
        }
    }

    black(t, temp);
}

fn left_rotate<T: RbTree + ?Sized>(t: &T, sentinel: usize, node: usize) {
    let temp = t.right(node);
    t.set_right(node, t.left(temp));

    if t.left(temp) != sentinel {
        t.set_parent(t.left(temp), node);
    }

    t.set_parent(temp, t.parent(node));

    if node == t.root() {
        t.set_root(temp);
    } else if node == t.left(t.parent(node)) {
        t.set_left(t.parent(node), temp);
    } else {
        t.set_right(t.parent(node), temp);
    }

    t.set_left(temp, node);
    t.set_parent(node, temp);
}

fn right_rotate<T: RbTree + ?Sized>(t: &T, sentinel: usize, node: usize) {
    let temp = t.left(node);
    t.set_left(node, t.right(temp));

    if t.right(temp) != sentinel {
        t.set_parent(t.right(temp), node);
    }

    t.set_parent(temp, t.parent(node));

    if node == t.root() {
        t.set_root(temp);
    } else if node == t.right(t.parent(node)) {
        t.set_right(t.parent(node), temp);
    } else {
        t.set_left(t.parent(node), temp);
    }

    t.set_right(temp, node);
    t.set_parent(node, temp);
}

/// ngx_rbtree_min
pub fn min<T: RbTree + ?Sized>(t: &T, mut node: usize) -> usize {
    let sentinel = t.sentinel();

    while t.left(node) != sentinel {
        node = t.left(node);
    }

    node
}

/// ngx_rbtree_next: the next node in order, or 0 after the last one.
pub fn next<T: RbTree + ?Sized>(t: &T, node: usize) -> usize {
    let sentinel = t.sentinel();

    if t.right(node) != sentinel {
        return min(t, t.right(node));
    }

    let root = t.root();
    let mut node = node;

    loop {
        let parent = t.parent(node);

        if node == root {
            return 0;
        }

        if node == t.left(parent) {
            return parent;
        }

        node = parent;
    }
}

/// The nodes in order (an empty tree has none).
pub fn walk<T: RbTree + ?Sized>(t: &T) -> Vec<usize> {
    let mut out = Vec::new();

    if t.root() == t.sentinel() {
        return out;
    }

    let mut n = min(t, t.root());

    while n != 0 {
        out.push(n);
        n = next(t, n);
    }

    out
}

shm_struct! {
    /// ngx_rbtree_node_t
    pub struct RbNode {
        key: usize,
        left: usize,
        right: usize,
        parent: usize,
        color: u8,
        data: u8,
    }
}

shm_struct! {
    /// ngx_rbtree_t (the insert function is passed to insert() instead)
    pub struct RbtreeHeader {
        root: usize,
        sentinel: usize,
        insert: usize,
    }
}

shm_struct! {
    /// ngx_str_node_t: a node keyed by a hash, then by a string
    pub struct StrNode {
        key: usize,
        left: usize,
        right: usize,
        parent: usize,
        color: u8,
        data: u8,
        str_len: usize,
        str_data: usize,
    }
}

/// A tree in a zone: the ngx_rbtree_t at `tree`, its nodes ngx_rbtree_node_t
/// (or structures starting with one) at the offsets the tree links.
#[derive(Clone, Copy, Debug)]
pub struct ShmRbtree<'a> {
    pub mem: &'a ShmMem,
    pub tree: usize,
}

impl<'a> ShmRbtree<'a> {
    pub fn at(mem: &'a ShmMem, tree: usize) -> ShmRbtree<'a> {
        ShmRbtree { mem, tree }
    }

    /// ngx_rbtree_init(tree, sentinel, insert)
    pub fn init(&self, sentinel: usize) {
        let h = RbtreeHeader::at(self.mem, self.tree);
        h.set(RbtreeHeader::sentinel, sentinel);
        h.set(RbtreeHeader::insert, 0);
        init(self);
    }

    fn node(&self, n: usize) -> RbNode<'a> {
        RbNode::at(self.mem, n)
    }

    /// node->data
    pub fn data(&self, n: usize) -> u8 {
        self.node(n).get(RbNode::data)
    }

    pub fn set_data(&self, n: usize, data: u8) {
        self.node(n).set(RbNode::data, data)
    }

    /// ngx_str_rbtree_insert_value
    pub fn str_insert_value(&self, temp: usize, node: usize, sentinel: usize) {
        insert_by(self, temp, node, sentinel, |t, node, temp| {
            let (nk, tk) = (t.key(node), t.key(temp));
            if nk != tk {
                return nk < tk;
            }
            let n = StrNode::at(t.mem, node);
            let m = StrNode::at(t.mem, temp);
            t.str_cmp(n.get(StrNode::str_data), n.get(StrNode::str_len), m.get(StrNode::str_data), m.get(StrNode::str_len))
                == std::cmp::Ordering::Less
        });
    }

    /// ngx_memn2cmp() of two strings of the zone
    fn str_cmp(&self, a: usize, alen: usize, b: usize, blen: usize) -> std::cmp::Ordering {
        let x = self.mem.bytes(a, alen.min(blen));
        match self.mem.cmp_bytes(b, &x).reverse() {
            std::cmp::Ordering::Equal => alen.cmp(&blen),
            o => o,
        }
    }

    /// ngx_str_rbtree_lookup: the node of ngx_str_node_t with `name` and
    /// `hash`, or 0
    pub fn str_lookup(&self, name: &[u8], hash: usize) -> usize {
        let mut node = self.root();
        let sentinel = self.sentinel();

        while node != sentinel {
            let n = StrNode::at(self.mem, node);
            let key = n.get(StrNode::key);

            if hash != key {
                node = if hash < key { self.left(node) } else { self.right(node) };
                continue;
            }

            let len = n.get(StrNode::str_len);
            let data = n.get(StrNode::str_data);

            // ngx_memn2cmp(name->data, n->str.data, name->len, n->str.len)
            let rc = match self.mem.cmp_bytes(data, &name[..name.len().min(len)]).reverse() {
                std::cmp::Ordering::Equal => name.len().cmp(&len),
                o => o,
            };

            match rc {
                std::cmp::Ordering::Less => node = self.left(node),
                std::cmp::Ordering::Greater => node = self.right(node),
                std::cmp::Ordering::Equal => return node,
            }
        }

        // not found

        0
    }
}

impl RbTree for ShmRbtree<'_> {
    fn root(&self) -> usize {
        RbtreeHeader::at(self.mem, self.tree).get(RbtreeHeader::root)
    }
    fn set_root(&self, n: usize) {
        RbtreeHeader::at(self.mem, self.tree).set(RbtreeHeader::root, n)
    }
    fn sentinel(&self) -> usize {
        RbtreeHeader::at(self.mem, self.tree).get(RbtreeHeader::sentinel)
    }
    fn key(&self, n: usize) -> usize {
        self.node(n).get(RbNode::key)
    }
    fn set_key(&self, n: usize, key: usize) {
        self.node(n).set(RbNode::key, key)
    }
    fn left(&self, n: usize) -> usize {
        self.node(n).get(RbNode::left)
    }
    fn set_left(&self, n: usize, v: usize) {
        self.node(n).set(RbNode::left, v)
    }
    fn right(&self, n: usize) -> usize {
        self.node(n).get(RbNode::right)
    }
    fn set_right(&self, n: usize, v: usize) {
        self.node(n).set(RbNode::right, v)
    }
    fn parent(&self, n: usize) -> usize {
        self.node(n).get(RbNode::parent)
    }
    fn set_parent(&self, n: usize, v: usize) {
        self.node(n).set(RbNode::parent, v)
    }
    fn is_red(&self, n: usize) -> bool {
        self.node(n).get(RbNode::color) != 0
    }
    fn set_red(&self, n: usize, red: bool) {
        self.node(n).set(RbNode::color, red as u8)
    }
}

/// A node of a LocalRbtree.
#[derive(Debug)]
struct LocalNode<V> {
    key: usize,
    left: usize,
    right: usize,
    parent: usize,
    red: bool,
    value: Option<V>,
}

impl<V> LocalNode<V> {
    fn new(key: usize, value: Option<V>) -> LocalNode<V> {
        LocalNode { key, left: 0, right: 0, parent: 0, red: false, value }
    }
}

/// A tree of the process: nodes (a key and a value each) in a vector, the
/// handle 0 unused (NULL), 1 the sentinel.
#[derive(Debug)]
pub struct LocalRbtree<V> {
    nodes: RefCell<Vec<LocalNode<V>>>,
    root: Cell<usize>,
    free: RefCell<Vec<usize>>,
}

const LOCAL_SENTINEL: usize = 1;

impl<V> Default for LocalRbtree<V> {
    fn default() -> Self {
        LocalRbtree::new()
    }
}

impl<V> LocalRbtree<V> {
    /// An empty tree (ngx_rbtree_init).
    pub fn new() -> LocalRbtree<V> {
        let t = LocalRbtree {
            nodes: RefCell::new(vec![LocalNode::new(0, None), LocalNode::new(0, None)]),
            root: Cell::new(LOCAL_SENTINEL),
            free: RefCell::new(Vec::new()),
        };
        init(&t);
        t
    }

    /// A new node, not in the tree yet: its handle.
    pub fn alloc(&self, key: usize, value: V) -> usize {
        if let Some(n) = self.free.borrow_mut().pop() {
            self.nodes.borrow_mut()[n] = LocalNode::new(key, Some(value));
            return n;
        }

        let mut nodes = self.nodes.borrow_mut();
        nodes.push(LocalNode::new(key, Some(value)));
        nodes.len() - 1
    }

    /// Frees a node deleted from the tree (or never inserted): its value.
    pub fn free(&self, n: usize) -> Option<V> {
        let v = self.nodes.borrow_mut()[n].value.take();
        self.free.borrow_mut().push(n);
        v
    }

    /// The value of a node.
    pub fn value(&self, n: usize) -> Ref<'_, V> {
        Ref::map(self.nodes.borrow(), |nodes| nodes[n].value.as_ref().expect("rbtree node value"))
    }

    pub fn value_mut(&self, n: usize) -> RefMut<'_, V> {
        RefMut::map(self.nodes.borrow_mut(), |nodes| nodes[n].value.as_mut().expect("rbtree node value"))
    }

    /// The tree is empty.
    pub fn is_empty(&self) -> bool {
        self.root.get() == LOCAL_SENTINEL
    }
}

impl<V> RbTree for LocalRbtree<V> {
    fn root(&self) -> usize {
        self.root.get()
    }
    fn set_root(&self, n: usize) {
        self.root.set(n)
    }
    fn sentinel(&self) -> usize {
        LOCAL_SENTINEL
    }
    fn key(&self, n: usize) -> usize {
        self.nodes.borrow()[n].key
    }
    fn set_key(&self, n: usize, key: usize) {
        self.nodes.borrow_mut()[n].key = key
    }
    fn left(&self, n: usize) -> usize {
        self.nodes.borrow()[n].left
    }
    fn set_left(&self, n: usize, v: usize) {
        self.nodes.borrow_mut()[n].left = v
    }
    fn right(&self, n: usize) -> usize {
        self.nodes.borrow()[n].right
    }
    fn set_right(&self, n: usize, v: usize) {
        self.nodes.borrow_mut()[n].right = v
    }
    fn parent(&self, n: usize) -> usize {
        self.nodes.borrow()[n].parent
    }
    fn set_parent(&self, n: usize, v: usize) {
        self.nodes.borrow_mut()[n].parent = v
    }
    fn is_red(&self, n: usize) -> bool {
        self.nodes.borrow()[n].red
    }
    fn set_red(&self, n: usize, red: bool) {
        self.nodes.borrow_mut()[n].red = red
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys<T: RbTree>(t: &T) -> Vec<usize> {
        walk(t).into_iter().map(|n| t.key(n)).collect()
    }

    /// the red-black properties: a black root, no red node with a red
    /// child, the same number of black nodes on every path
    fn check<T: RbTree>(t: &T) {
        fn black_height<T: RbTree>(t: &T, n: usize) -> usize {
            if n == t.sentinel() {
                return 1;
            }
            if t.is_red(n) {
                assert!(!t.is_red(t.left(n)) && !t.is_red(t.right(n)), "red node with a red child");
            }
            let l = black_height(t, t.left(n));
            let r = black_height(t, t.right(n));
            assert_eq!(l, r, "black heights");
            l + if t.is_red(n) { 0 } else { 1 }
        }

        assert!(!t.is_red(t.root()));
        black_height(t, t.root());
    }

    fn exercise<T: RbTree>(t: &T, nodes: &[usize]) {
        let mut want = Vec::new();

        for (i, &n) in nodes.iter().enumerate() {
            let k = (i * 7919) % 1000;
            t.set_key(n, k);
            insert(t, n, insert_value);
            want.push(k);
            check(t);
        }

        want.sort();
        assert_eq!(keys(t), want);

        for (i, &n) in nodes.iter().enumerate().filter(|(i, _)| i % 3 == 0) {
            let k = (i * 7919) % 1000;
            delete(t, n);
            let pos = want.iter().position(|&x| x == k).unwrap();
            want.remove(pos);
            check(t);
        }

        assert_eq!(keys(t), want);
    }

    #[test]
    fn shm_tree() {
        let mem = ShmMem::private(1 << 20).unwrap();
        let tree = ShmRbtree::at(&mem, 64);
        let sentinel = 128;
        tree.init(sentinel);
        assert!(walk(&tree).is_empty());

        let nodes: Vec<usize> = (0..300).map(|i| 4096 + i * RbNode::SIZE).collect();
        exercise(&tree, &nodes);
    }

    #[test]
    fn local_tree() {
        let tree: LocalRbtree<String> = LocalRbtree::new();
        let nodes: Vec<usize> = (0..300).map(|i| tree.alloc(0, format!("v{}", i))).collect();
        exercise(&tree, &nodes);
        assert_eq!(*tree.value(nodes[1]), "v1");

        delete(&tree, nodes[1]);
        assert_eq!(tree.free(nodes[1]).as_deref(), Some("v1"));
        let again = tree.alloc(5, "w".to_string());
        assert_eq!(again, nodes[1], "the freed node is reused");
    }

    #[test]
    fn timer_order_wraps() {
        let tree: LocalRbtree<()> = LocalRbtree::new();
        let a = tree.alloc(usize::MAX - 1, ());
        let b = tree.alloc(1, ());
        insert(&tree, a, insert_timer_value);
        insert(&tree, b, insert_timer_value);
        assert_eq!(keys(&tree), vec![usize::MAX - 1, 1], "1 comes after MAX - 1");
    }

    #[test]
    fn shm_str_tree() {
        let mem = ShmMem::private(1 << 20).unwrap();
        let tree = ShmRbtree::at(&mem, 64);
        tree.init(128);

        let names: [&[u8]; 4] = [b"alpha", b"beta", b"al", b"gamma"];
        let mut data = 8192;
        for (i, name) in names.iter().enumerate() {
            let n = StrNode::at(&mem, 4096 + i * StrNode::SIZE);
            n.set(StrNode::key, 7);
            mem.write(data, name);
            n.set(StrNode::str_data, data);
            n.set(StrNode::str_len, name.len());
            data += 64;
            insert(&tree, n.off, |t: &ShmRbtree<'_>, temp, node, sentinel| t.str_insert_value(temp, node, sentinel));
        }

        for (i, name) in names.iter().enumerate() {
            assert_eq!(tree.str_lookup(name, 7), 4096 + i * StrNode::SIZE);
        }
        assert_eq!(tree.str_lookup(b"alph", 7), 0);
        assert_eq!(tree.str_lookup(b"alpha", 8), 0);
    }
}
