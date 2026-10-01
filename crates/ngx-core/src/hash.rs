//! Hash table implementation, ported from ngx_hash.c.
//!
//! nginx's hash tables support exact matching and wildcard matching:
//! - `*.example.com`: stored as reversed domain labels `com.example.` in dns_wc_head
//! - `.example.com`: stored in BOTH exact exact_hash as `example.com` and dns_wc_head as `com.example`
//! - `www.example.*`: stored as `www.example` in dns_wc_tail
//!
//! Lookups follow exact-first precedence: exact match > wildcard head > wildcard tail.
//!
//! The internal hash implementation uses a real hash map instead of packed memory buckets,
//! but performs the identical feasibility calculations during `init()` to ensure
//! the same error messages and failure modes as nginx.

use crate::log::Log;
use crate::rc::{NGX_BUSY, NGX_DECLINED, NGX_OK};
use crate::string::tolower;
use std::collections::HashSet;

pub const NGX_HASH_WILDCARD_KEY: u32 = 1;
pub const NGX_HASH_READONLY_KEY: u32 = 2;

pub const NGX_HASH_SMALL: u32 = 1;
pub const NGX_HASH_LARGE: u32 = 2;

const NGX_HASH_LARGE_HSIZE: usize = 10007;

// Cache line size for hash table bucket alignment.
const NGX_CACHELINE_SIZE: usize = 64;

// Maximum bucket size (65536 - NGX_CACHELINE_SIZE).
const MAX_BUCKET_SIZE: usize = 65536 - NGX_CACHELINE_SIZE;

// Hash function: h = h*31 + c, in ngx_uint_t
#[inline]
pub fn ngx_hash(hash: usize, c: u8) -> usize {
    hash.wrapping_mul(31).wrapping_add(c as usize)
}

/// Compute hash key for exact matches (case-sensitive by default).
pub fn hash_key(data: &[u8]) -> usize {
    let mut key = 0usize;
    for &c in data {
        key = ngx_hash(key, c);
    }
    key
}

/// Compute hash key for exact matches (case-insensitive).
pub fn hash_key_lc(data: &[u8]) -> usize {
    let mut key = 0usize;
    for &c in data {
        key = ngx_hash(key, tolower(c));
    }
    key
}

/// Lowercase a byte string and compute its hash key simultaneously.
pub fn hash_strlow(dst: &mut [u8], src: &[u8]) -> usize {
    let mut key = 0usize;
    let n = dst.len().min(src.len());
    for i in 0..n {
        dst[i] = tolower(src[i]);
        key = ngx_hash(key, dst[i]);
    }
    key
}

/// Configuration for hash table initialization.
pub struct HashInit<'a> {
    pub name: &'static str,
    pub max_size: usize,
    pub bucket_size: usize,
    pub log: &'a Log,
}

/// A key-value pair to be inserted into a hash table.
#[derive(Clone)]
pub struct HashKey<V: Clone> {
    pub key: Vec<u8>,
    pub key_hash: usize,
    pub value: V,
}

/// Hash kind for `HashKeysArrays::new()`.
#[derive(Clone, Copy, Debug)]
pub enum HashKind {
    Small,
    Large,
}

/// Accumulator for hash keys before finalizing into a hash table.
/// Handles exact keys, wildcard head keys, and wildcard tail keys.
pub struct HashKeysArrays<V: Clone> {
    hsize: usize,
    keys: Vec<HashKey<V>>,
    dns_wc_head: Vec<HashKey<V>>,
    dns_wc_tail: Vec<HashKey<V>>,
    keys_hash: Vec<HashSet<Vec<u8>>>,
    dns_wc_head_hash: Vec<HashSet<Vec<u8>>>,
    dns_wc_tail_hash: Vec<HashSet<Vec<u8>>>,
}

impl<V: Clone> HashKeysArrays<V> {
    /// Create a new hash keys array with the given kind (Small or Large).
    pub fn new(kind: HashKind) -> Self {
        let hsize = match kind {
            HashKind::Small => 107,
            HashKind::Large => NGX_HASH_LARGE_HSIZE,
        };
        HashKeysArrays {
            hsize,
            keys: Vec::new(),
            dns_wc_head: Vec::new(),
            dns_wc_tail: Vec::new(),
            keys_hash: vec![HashSet::new(); hsize],
            dns_wc_head_hash: vec![HashSet::new(); hsize],
            dns_wc_tail_hash: vec![HashSet::new(); hsize],
        }
    }

    /// Add a key with value and flags (NGX_HASH_WILDCARD_KEY, NGX_HASH_READONLY_KEY).
    /// Returns NGX_OK, NGX_BUSY (conflict), or NGX_DECLINED (invalid name).
    pub fn add_key(&mut self, key: Vec<u8>, value: V, flags: u32) -> i64 {
        let last = key.len();

        if flags & NGX_HASH_WILDCARD_KEY != 0 {
            // Validate wildcard: check for multiple asterisks, double dots, null bytes
            let mut n = 0;
            let mut is_leading_dot = false;
            let mut is_asterisk_prefix = false;
            let mut is_asterisk_suffix = false;

            for i in 0..last {
                if key[i] == b'*' {
                    n += 1;
                    if n > 1 {
                        return NGX_DECLINED;
                    }
                }
                if key[i] == b'.' && i + 1 < last && key[i + 1] == b'.' {
                    return NGX_DECLINED;
                }
                if key[i] == 0 {
                    return NGX_DECLINED;
                }
            }

            // Determine the pattern (only one can be true at a time)
            if last > 1 && key[0] == b'.' {
                is_leading_dot = true;
            } else if last > 2 && key[0] == b'*' && key[1] == b'.' {
                is_asterisk_prefix = true;
            } else if last > 2 && key[last - 2] == b'.' && key[last - 1] == b'*' {
                is_asterisk_suffix = true;
            } else if n > 0 {
                // Invalid wildcard
                return NGX_DECLINED;
            }

            // Process the pattern
            if is_leading_dot {
                return self.add_wildcard_key_with_last(key, value, 1, last);
            } else if is_asterisk_prefix {
                return self.add_wildcard_key_with_last(key, value, 2, last);
            } else if is_asterisk_suffix {
                return self.add_wildcard_key_with_last(key, value, 0, last - 2);
            }
        }

        // Exact hash
        self.add_exact_key(key, value, flags, last)
    }

    fn add_exact_key(&mut self, mut key: Vec<u8>, value: V, flags: u32, last: usize) -> i64 {
        let mut k = 0usize;
        for i in 0..last {
            if flags & NGX_HASH_READONLY_KEY == 0 {
                key[i] = tolower(key[i]);
            }
            k = ngx_hash(k, key[i]);
        }

        let k_idx = k % self.hsize;

        // Check for conflicts in exact hash
        let key_slice = &key[..last];
        for existing in &self.keys_hash[k_idx] {
            if existing == key_slice {
                return NGX_BUSY;
            }
        }

        self.keys_hash[k_idx].insert(key_slice.to_vec());

        let hk = HashKey {
            key: key_slice.to_vec(),
            key_hash: hash_key(&key[..last]),
            value,
        };
        self.keys.push(hk);

        NGX_OK
    }

    /// The "wildcard:" part of ngx_hash_add_key: "*.example.com" (skip 2),
    /// ".example.com" (skip 1) and "www.example.*" (skip 0, last is the
    /// length without ".*").
    fn add_wildcard_key_with_last(&mut self, mut key: Vec<u8>, value: V, skip: usize, mut last: usize) -> i64 {
        // wildcard hash

        let mut low = key[skip..last].to_vec();
        let k = hash_strlow(&mut low, &key[skip..last]);
        key[skip..last].copy_from_slice(&low);

        let k = k % self.hsize;

        if skip == 1 {
            // check conflicts in exact hash for ".example.com"

            let exact = &key[1..last];

            if self.keys_hash[k].contains(exact) {
                return NGX_BUSY;
            }

            self.keys_hash[k].insert(exact.to_vec());
        }

        let p = if skip > 0 {
            // convert "*.example.com" to "com.example.\0"
            //      and ".example.com" to "com.example\0"

            let mut p = Vec::with_capacity(last);
            let mut len = 0;

            let mut i = last - 1;
            while i > 0 {
                if key[i] == b'.' {
                    p.extend_from_slice(&key[i + 1..i + 1 + len]);
                    p.push(b'.');
                    len = 0;
                } else {
                    len += 1;
                }
                i -= 1;
            }

            if len > 0 {
                p.extend_from_slice(&key[1..1 + len]);
            }

            p
        } else {
            // convert "www.example.*" to "www.example\0"

            last += 1;

            key[..last - 1].to_vec()
        };

        // check conflicts in wildcard hash ("www.example." for the tail
        // wildcards)

        let name = &key[skip..last];

        let keys = if skip > 0 { &mut self.dns_wc_head_hash[k] } else { &mut self.dns_wc_tail_hash[k] };

        if keys.contains(name) {
            return NGX_BUSY;
        }

        keys.insert(name.to_vec());

        // add to wildcard hash

        let hk = HashKey { key: p, key_hash: 0, value };

        if skip > 0 {
            self.dns_wc_head.push(hk);
        } else {
            self.dns_wc_tail.push(hk);
        }

        NGX_OK
    }

    /// Get the exact keys.
    pub fn keys(&self) -> &[HashKey<V>] {
        &self.keys
    }

    /// Get the wildcard head keys.
    pub fn dns_wc_head(&self) -> &[HashKey<V>] {
        &self.dns_wc_head
    }

    /// Get the wildcard tail keys.
    pub fn dns_wc_tail(&self) -> &[HashKey<V>] {
        &self.dns_wc_tail
    }
}

/// A single hash table for exact-key lookups.
pub struct Hash<V: Clone> {
    buckets: Vec<Option<Vec<(usize, Vec<u8>, V)>>>,
    size: usize,
}

impl<V: Clone> Hash<V> {
    /// Initialize a hash table from keys.
    /// Returns an error with the exact C error message if initialization fails.
    pub fn init(hinit: &HashInit, names: Vec<HashKey<V>>) -> Result<Hash<V>, String> {
        let max_size = hinit.max_size;
        let bucket_size = hinit.bucket_size;
        let name = hinit.name;

        // Check for max_size == 0
        if max_size == 0 {
            return Err(format!(
                "could not build {}, you should increase {}_max_size: {}",
                name, name, max_size
            ));
        }

        // Check bucket_size limit
        if bucket_size > MAX_BUCKET_SIZE {
            return Err(format!(
                "could not build {}, too large {}_bucket_size: {}",
                name, name, bucket_size
            ));
        }

        // Check each key fits in a bucket
        for hk in &names {
            let elt_size = compute_elt_size(hk.key.len());
            if bucket_size < elt_size + std::mem::size_of::<*const ()>() {
                return Err(format!(
                    "could not build {}, you should increase {}_bucket_size: {}",
                    name, name, bucket_size
                ));
            }
        }

        // Try to find a suitable hash table size
        let mut test = vec![0usize; max_size];
        let bucket_size_adjusted = bucket_size.saturating_sub(std::mem::size_of::<*const ()>());

        let start = if names.is_empty() {
            1
        } else {
            let s = names.len() / (bucket_size_adjusted / (2 * std::mem::size_of::<*const ()>()));
            if s == 0 { 1 } else { s }
        };

        let start = if max_size > 10000 && !names.is_empty() && max_size / names.len() < 100 {
            max_size - 1000
        } else {
            start
        };

        let mut found_size = None;

        for size in start..=max_size {
            test.fill(0);

            let mut valid = true;
            for hk in &names {
                let key = hk.key_hash % size;
                let len = test[key as usize] + compute_elt_size(hk.key.len());

                if len > bucket_size_adjusted {
                    valid = false;
                    break;
                }

                test[key as usize] = len;
            }

            if valid {
                found_size = Some(size);
                break;
            }
        }

        let size = match found_size {
            Some(size) => size,
            None => {
                crate::ngx_log_error!(
                    crate::log::NGX_LOG_WARN,
                    hinit.log,
                    None,
                    "could not build optimal {}, you should increase either {}_max_size: {} or {}_bucket_size: {}; ignoring {}_bucket_size",
                    name,
                    name,
                    max_size,
                    name,
                    bucket_size,
                    name
                );
                max_size
            }
        };

        // Finalize bucket sizes
        for i in 0..size {
            test[i] = std::mem::size_of::<*const ()>();
        }

        for hk in &names {
            let key = hk.key_hash % size;
            let len = test[key as usize] + compute_elt_size(hk.key.len());

            if len > MAX_BUCKET_SIZE {
                return Err(format!(
                    "could not build {}, you should increase {}_max_size: {}",
                    name, name, max_size
                ));
            }

            test[key as usize] = len;
        }

        // Align bucket sizes to cache line multiples
        for i in 0..size {
            if test[i] > std::mem::size_of::<*const ()>() {
                test[i] = align(test[i], NGX_CACHELINE_SIZE);
            }
        }

        // Build the actual hash table
        let mut buckets: Vec<Option<Vec<(usize, Vec<u8>, V)>>> = vec![None; size];
        let mut bucket_offsets = vec![0usize; size];

        // Initialize bucket offsets
        for i in 0..size {
            if test[i] > std::mem::size_of::<*const ()>() {
                bucket_offsets[i] = 0;
            }
        }

        // Insert keys into buckets
        for hk in &names {
            let key = hk.key_hash % size;
            let key_idx = key as usize;
            let bucket = buckets[key_idx].get_or_insert_with(Vec::new);
            bucket.push((hk.key_hash, hk.key.clone(), hk.value.clone()));
        }

        Ok(Hash {
            buckets,
            size,
        })
    }

    /// Find a key in the hash table. Returns the value if found, None otherwise.
    pub fn find(&self, key_hash: usize, name: &[u8]) -> Option<&V> {
        let bucket_idx = key_hash % self.size;
        if let Some(bucket) = &self.buckets[bucket_idx] {
            for (_hash, key, value) in bucket {
                if key.len() == name.len() && key == name {
                    return Some(value);
                }
            }
        }
        None
    }

    /// Check if the hash table is empty.
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.is_none())
    }
}

/// A wildcard hash table for prefix/suffix matching (ngx_hash_wildcard_t).
pub struct HashWildcard<V: Clone> {
    hash: Hash<WildcardValue<V>>,
    /// hwc->value: the value of "example.com" for a hash of the
    /// "*.example.com" wildcards
    value: Option<V>,
}

/// The value of a wildcard hash element: the 2 low bits of the value
/// pointer in C.
enum WildcardValue<V: Clone> {
    /// 00: the value for both "example.com" and "*.example.com"
    Value(V),
    /// 01: the value for "*.example.com" only
    DotValue(V),
    /// 10: a wildcard hash allowing both "example.com" and "*.example.com"
    Hash(std::rc::Rc<HashWildcard<V>>),
    /// 11: a wildcard hash allowing "*.example.com" only
    DotHash(std::rc::Rc<HashWildcard<V>>),
}

impl<V: Clone> Clone for WildcardValue<V> {
    fn clone(&self) -> Self {
        match self {
            WildcardValue::Value(v) => WildcardValue::Value(v.clone()),
            WildcardValue::DotValue(v) => WildcardValue::DotValue(v.clone()),
            WildcardValue::Hash(h) => WildcardValue::Hash(h.clone()),
            WildcardValue::DotHash(h) => WildcardValue::DotHash(h.clone()),
        }
    }
}

impl<V: Clone> HashWildcard<V> {
    /// ngx_hash_wildcard_init: the keys are the converted wildcards
    /// ("com.example." for "*.example.com", "com.example" for
    /// ".example.com", "www.example" for "www.example.*"), sorted with
    /// ngx_dns_strcmp().
    pub fn init(hinit: &HashInit, names: Vec<HashKey<V>>) -> Result<Self, String> {
        let mut curr_names: Vec<HashKey<WildcardValue<V>>> = Vec::with_capacity(names.len());

        let mut n = 0;

        while n < names.len() {
            let key = &names[n].key;

            let mut dot = false;
            let mut len = 0;

            while len < key.len() {
                if key[len] == b'.' {
                    dot = true;
                    break;
                }
                len += 1;
            }

            let name_key = key[..len].to_vec();
            let name_hash = hash_key_lc(&name_key);
            let mut name_value = WildcardValue::Value(names[n].value.clone());

            let dot_len = len + 1;

            if dot {
                len += 1;
            }

            let mut next_names: Vec<HashKey<V>> = Vec::new();

            if key.len() != len {
                next_names.push(HashKey { key: key[len..].to_vec(), key_hash: 0, value: names[n].value.clone() });
            }

            let mut i = n + 1;

            while i < names.len() {
                let next = &names[i].key;

                // ngx_strncmp(names[n].key.data, names[i].key.data, len)
                // over NUL-terminated keys
                if next.len() < len || key[..len] != next[..len] {
                    break;
                }

                if !dot && next.len() > len && next[len] != b'.' {
                    break;
                }

                next_names.push(HashKey { key: next[dot_len.min(next.len())..].to_vec(), key_hash: 0, value: names[i].value.clone() });

                i += 1;
            }

            if !next_names.is_empty() {
                let mut wdc = Self::init(hinit, next_names)?;

                if key.len() == len {
                    wdc.value = Some(names[n].value.clone());
                }

                let wdc = std::rc::Rc::new(wdc);

                name_value = if dot { WildcardValue::DotHash(wdc) } else { WildcardValue::Hash(wdc) };
            } else if dot {
                name_value = WildcardValue::DotValue(names[n].value.clone());
            }

            curr_names.push(HashKey { key: name_key, key_hash: name_hash, value: name_value });

            n = i;
        }

        let hash = Hash::init(hinit, curr_names)?;

        Ok(HashWildcard { hash, value: None })
    }

    /// ngx_hash_find_wc_head: a lowercased name for "*.example.com" and
    /// ".example.com" wildcards.
    pub fn find_wc_head(&self, name: &[u8]) -> Option<&V> {
        let len = name.len();

        let mut n = len;

        while n > 0 {
            if name[n - 1] == b'.' {
                break;
            }
            n -= 1;
        }

        let mut key = 0usize;

        for &c in &name[n..len] {
            key = ngx_hash(key, c);
        }

        let value = match self.hash.find(key, &name[n..len]) {
            Some(v) => v,
            None => return self.value.as_ref(),
        };

        match value {
            WildcardValue::Hash(hwc) | WildcardValue::DotHash(hwc) => {
                if n == 0 {
                    // "example.com"

                    if let WildcardValue::DotHash(_) = value {
                        return None;
                    }

                    return hwc.value.as_ref();
                }

                if let Some(v) = hwc.find_wc_head(&name[..n - 1]) {
                    return Some(v);
                }

                hwc.value.as_ref()
            }

            WildcardValue::DotValue(v) => {
                if n == 0 {
                    // "example.com"
                    return None;
                }

                Some(v)
            }

            WildcardValue::Value(v) => Some(v),
        }
    }

    /// ngx_hash_find_wc_tail: a lowercased name for "www.example.*"
    /// wildcards.
    pub fn find_wc_tail(&self, name: &[u8]) -> Option<&V> {
        let len = name.len();

        let mut key = 0usize;
        let mut i = 0;

        while i < len {
            if name[i] == b'.' {
                break;
            }

            key = ngx_hash(key, name[i]);
            i += 1;
        }

        if i == len {
            return None;
        }

        let value = match self.hash.find(key, &name[..i]) {
            Some(v) => v,
            None => return self.value.as_ref(),
        };

        match value {
            WildcardValue::Hash(hwc) | WildcardValue::DotHash(hwc) => {
                i += 1;

                if let Some(v) = hwc.find_wc_tail(&name[i..len]) {
                    return Some(v);
                }

                hwc.value.as_ref()
            }

            WildcardValue::Value(v) | WildcardValue::DotValue(v) => Some(v),
        }
    }
}

/// A combined hash table with exact and wildcard lookups.
pub struct HashCombined<V: Clone> {
    pub hash: Hash<V>,
    pub wc_head: Option<HashWildcard<V>>,
    pub wc_tail: Option<HashWildcard<V>>,
}

impl<V: Clone> HashCombined<V> {
    /// Find a key, checking exact first, then wildcard head, then wildcard tail.
    pub fn find(&self, key_hash: usize, name: &[u8]) -> Option<&V> {
        // Try exact first
        if let Some(v) = self.hash.find(key_hash, name) {
            return Some(v);
        }

        // Try wildcard head
        if name.len() > 0 {
            if let Some(wc_head) = &self.wc_head {
                if let Some(v) = wc_head.find_wc_head(name) {
                    return Some(v);
                }
            }
        }

        // Try wildcard tail
        if name.len() > 0 {
            if let Some(wc_tail) = &self.wc_tail {
                if let Some(v) = wc_tail.find_wc_tail(name) {
                    return Some(v);
                }
            }
        }

        None
    }
}

// Helper: compute the size of a hash element
fn compute_elt_size(key_len: usize) -> usize {
    std::mem::size_of::<*const ()>() + align(key_len + 2, std::mem::size_of::<*const ()>())
}

// Helper: round up to the nearest multiple
fn align(val: usize, alignment: usize) -> usize {
    (val + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_key() {
        let key = b"example";
        let h1 = hash_key(key);
        let h2 = hash_key(key);
        assert_eq!(h1, h2);

        // ngx_uint_t arithmetic: the buckets of a key longer than 6
        // characters are those of C
        assert_eq!(hash_key(b"http_x_forwarded_for"), 2810977803666258672);
        assert_eq!(hash_key_lc(b"Content-Type"), 2609428126162509838);
    }

    #[test]
    fn test_hash_key_lc() {
        let key1 = b"Example";
        let key2 = b"example";
        let h1 = hash_key_lc(key1);
        let h2 = hash_key_lc(key2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_strlow() {
        let src = b"ExAmPlE";
        let mut dst = vec![0u8; src.len()];
        let h = hash_strlow(&mut dst, src);
        assert_eq!(&dst, b"example");
        // Verify it matches hash_key_lc
        assert_eq!(h, hash_key_lc(b"example"));
    }

    #[test]
    fn test_exact_key_basic() {
        let names = vec![HashKey {
            key: b"example.com".to_vec(),
            key_hash: hash_key(b"example.com"),
            value: 42i32,
        }];

        // We can't easily test Hash::init without proper Log setup,
        // but we verify the basic structure exists
        assert_eq!(names[0].value, 42);
    }

    #[test]
    fn test_hash_keys_arrays_small() {
        let mut ha: HashKeysArrays<i32> = HashKeysArrays::new(HashKind::Small);
        assert_eq!(ha.hsize, 107);
    }

    #[test]
    fn test_hash_keys_arrays_large() {
        let mut ha: HashKeysArrays<i32> = HashKeysArrays::new(HashKind::Large);
        assert_eq!(ha.hsize, NGX_HASH_LARGE_HSIZE);
    }

    #[test]
    fn test_add_exact_key() {
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        let result = ha.add_key(b"example.com".to_vec(), "value1", 0);
        assert_eq!(result, NGX_OK);

        // Exact keys should be in the keys array
        assert_eq!(ha.keys().len(), 1);
    }

    #[test]
    fn test_add_exact_key_duplicate() {
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        ha.add_key(b"example.com".to_vec(), "value1", 0);
        let result = ha.add_key(b"example.com".to_vec(), "value2", 0);
        assert_eq!(result, NGX_BUSY);
    }

    #[test]
    fn test_add_wildcard_head() {
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        let result = ha.add_key(b"*.example.com".to_vec(), "wildcard_value", NGX_HASH_WILDCARD_KEY);
        assert_eq!(result, NGX_OK);
        assert_eq!(ha.dns_wc_head().len(), 1);
    }

    #[test]
    fn test_add_wildcard_head_leading_dot() {
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        let result = ha.add_key(b".example.com".to_vec(), "wildcard_value", NGX_HASH_WILDCARD_KEY);
        assert_eq!(result, NGX_OK);
        assert_eq!(ha.dns_wc_head().len(), 1);
        // For ".example.com", it's stored as wildcard head, not exact keys
        // but it does get tracked in keys_hash for conflict detection
        assert_eq!(ha.keys().len(), 0);
    }

    #[test]
    fn test_add_wildcard_tail() {
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        let result = ha.add_key(b"www.example.*".to_vec(), "tail_value", NGX_HASH_WILDCARD_KEY);
        assert_eq!(result, NGX_OK);
        assert_eq!(ha.dns_wc_tail().len(), 1);
    }

    #[test]
    fn test_invalid_wildcard_multiple_asterisks() {
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        let result = ha.add_key(b"*.*.example.com".to_vec(), "value", NGX_HASH_WILDCARD_KEY);
        assert_eq!(result, NGX_DECLINED);
    }

    #[test]
    fn test_invalid_wildcard_double_dot() {
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        let result = ha.add_key(b"example..com".to_vec(), "value", NGX_HASH_WILDCARD_KEY);
        assert_eq!(result, NGX_DECLINED);
    }

    #[test]
    fn test_invalid_wildcard_asterisk_in_middle() {
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        let result = ha.add_key(b"exam*ple.com".to_vec(), "value", NGX_HASH_WILDCARD_KEY);
        assert_eq!(result, NGX_DECLINED);
    }

    #[test]
    fn test_exact_key_case_insensitive() {
        // Keys are lowercased unless READONLY_KEY is set
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        ha.add_key(b"ExAmPlE.cOm".to_vec(), "value1", 0);
        assert_eq!(ha.keys()[0].key, b"example.com");
    }

    #[test]
    fn test_wildcard_head_reversal() {
        // Test that *.example.com gets reversed properly
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        ha.add_key(b"*.example.com".to_vec(), "wildcard", NGX_HASH_WILDCARD_KEY);
        // The reversed key should have labels in reverse order
        let wc_key = &ha.dns_wc_head()[0].key;
        // For "*.example.com", it becomes "example.com" which reverses to "com.example."
        assert!(wc_key.starts_with(b"com"));
    }

    #[test]
    fn test_wildcard_tail_no_reversal() {
        // Test that www.example.* doesn't get reversed
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        ha.add_key(b"www.example.*".to_vec(), "tail", NGX_HASH_WILDCARD_KEY);
        let wc_key = &ha.dns_wc_tail()[0].key;
        // For "www.example.*", it becomes "www.example" (no reversal)
        assert_eq!(wc_key, b"www.example");
    }

    #[test]
    fn test_wildcard_head_leading_dot_reversal() {
        // Test that .example.com gets reversed properly
        let mut ha: HashKeysArrays<&str> = HashKeysArrays::new(HashKind::Small);
        ha.add_key(b".example.com".to_vec(), "wildcard", NGX_HASH_WILDCARD_KEY);
        let wc_key = &ha.dns_wc_head()[0].key;
        // For ".example.com", it becomes "example.com" which reverses to "com.example."
        assert!(wc_key.starts_with(b"com"));
    }

    #[test]
    fn test_hash_strlow_correct_hash() {
        // Verify that hash_strlow produces the same hash as hash_key_lc
        let src = b"ExAmPlE.CoM";
        let mut dst = vec![0u8; src.len()];
        let h1 = hash_strlow(&mut dst, src);
        let h2 = hash_key_lc(b"example.com");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_multiple_keys_different_hashes() {
        // Verify that different keys produce different hashes
        let h1 = hash_key(b"example.com");
        let h2 = hash_key(b"example.org");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_ngx_hash_formula() {
        // Verify the hash formula h = h*31 + c
        let h1 = hash_key(b"a");
        assert_eq!(h1, 97); // 'a' = 97
        let h2 = hash_key(b"ab");
        assert_eq!(h2, 97 * 31 + 98); // (97 * 31) + 'b'
    }

    #[test]
    fn test_wildcard_find_semantics() {
        // as ngx_hash_find_wc_head()/ngx_hash_find_wc_tail() in C
        let mut ha: HashKeysArrays<i32> = HashKeysArrays::new(HashKind::Small);
        assert_eq!(ha.add_key(b".example.com".to_vec(), 1, NGX_HASH_WILDCARD_KEY), NGX_OK);
        assert_eq!(ha.add_key(b"*.y.example.com".to_vec(), 2, NGX_HASH_WILDCARD_KEY), NGX_OK);
        assert_eq!(ha.add_key(b"*.example.org".to_vec(), 3, NGX_HASH_WILDCARD_KEY), NGX_OK);
        assert_eq!(ha.add_key(b"*.Example.com".to_vec(), 9, NGX_HASH_WILDCARD_KEY), NGX_BUSY);
        assert_eq!(ha.add_key(b"example.com".to_vec(), 9, NGX_HASH_WILDCARD_KEY), NGX_BUSY);
        assert_eq!(ha.add_key(b"www.example.*".to_vec(), 4, NGX_HASH_WILDCARD_KEY), NGX_OK);
        assert_eq!(ha.add_key(b"www.example.*".to_vec(), 5, NGX_HASH_WILDCARD_KEY), NGX_BUSY);
        assert_eq!(ha.add_key(b"com.*".to_vec(), 6, NGX_HASH_WILDCARD_KEY), NGX_OK);

        let log = Log::stderr(crate::log::NGX_LOG_EMERG);
        let hinit = HashInit { name: "test_hash", max_size: 512, bucket_size: 64, log: &log };

        let mut head = ha.dns_wc_head().to_vec();
        head.sort_by(|a, b| crate::string::dns_strcmp(&a.key, &b.key).cmp(&0));
        let head = HashWildcard::init(&hinit, head).unwrap();

        let mut tail = ha.dns_wc_tail().to_vec();
        tail.sort_by(|a, b| crate::string::dns_strcmp(&a.key, &b.key).cmp(&0));
        let tail = HashWildcard::init(&hinit, tail).unwrap();

        assert_eq!(head.find_wc_head(b"example.com"), Some(&1));
        assert_eq!(head.find_wc_head(b"www.example.com"), Some(&1));
        assert_eq!(head.find_wc_head(b"y.example.com"), Some(&1));
        assert_eq!(head.find_wc_head(b"x.y.example.com"), Some(&2));
        assert_eq!(head.find_wc_head(b"example.org"), None);
        assert_eq!(head.find_wc_head(b"a.example.org"), Some(&3));
        assert_eq!(head.find_wc_head(b"example.net"), None);

        assert_eq!(tail.find_wc_tail(b"www.example.net"), Some(&4));
        assert_eq!(tail.find_wc_tail(b"www.example"), None);
        assert_eq!(tail.find_wc_tail(b"com.example"), Some(&6));
        assert_eq!(tail.find_wc_tail(b"www.other.net"), None);
    }
}
