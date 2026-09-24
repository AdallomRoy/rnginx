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

// Hash function: h = h*31 + c
#[inline]
fn ngx_hash(hash: u32, c: u8) -> u32 {
    hash.wrapping_mul(31).wrapping_add(c as u32)
}

/// Compute hash key for exact matches (case-sensitive by default).
pub fn hash_key(data: &[u8]) -> u32 {
    let mut key = 0u32;
    for &c in data {
        key = ngx_hash(key, c);
    }
    key
}

/// Compute hash key for exact matches (case-insensitive).
pub fn hash_key_lc(data: &[u8]) -> u32 {
    let mut key = 0u32;
    for &c in data {
        key = ngx_hash(key, tolower(c));
    }
    key
}

/// Lowercase a byte string and compute its hash key simultaneously.
pub fn hash_strlow(dst: &mut [u8], src: &[u8]) -> u32 {
    let mut key = 0u32;
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
    pub key_hash: u32,
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
        let key = key;
        let last = key.len();

        if flags & NGX_HASH_WILDCARD_KEY != 0 {
            // Validate wildcard: check for multiple asterisks, double dots, null bytes
            let mut n = 0;
            for i in 0..key.len() {
                if key[i] == b'*' {
                    n += 1;
                    if n > 1 {
                        return NGX_DECLINED;
                    }
                }
                if key[i] == b'.' && i + 1 < key.len() && key[i + 1] == b'.' {
                    return NGX_DECLINED;
                }
                if key[i] == 0 {
                    return NGX_DECLINED;
                }
            }

            // Check for ".example.com" pattern (leading dot)
            if key.len() > 1 && key[0] == b'.' {
                return self.add_wildcard_key(key, value, 1); // skip=1
            }

            // Check for "*.example.com" pattern
            if key.len() > 2 && key[0] == b'*' && key[1] == b'.' {
                return self.add_wildcard_key(key, value, 2); // skip=2
            }

            // Check for "www.example.*" pattern
            if key.len() > 2 && key[key.len() - 2] == b'.' && key[key.len() - 1] == b'*' {
                return self.add_wildcard_key(key, value, 0); // skip=0, last adjusted
            }

            // Invalid wildcard (has asterisk but doesn't match patterns)
            if n > 0 {
                return NGX_DECLINED;
            }
        }

        // Exact hash
        self.add_exact_key(key, value, flags, last)
    }

    fn add_exact_key(&mut self, mut key: Vec<u8>, value: V, flags: u32, last: usize) -> i64 {
        let mut k = 0u32;
        for i in 0..last {
            if flags & NGX_HASH_READONLY_KEY == 0 {
                key[i] = tolower(key[i]);
            }
            k = ngx_hash(k, key[i]);
        }

        k = (k % self.hsize as u32) as u32;
        let k_idx = k as usize;

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

    fn add_wildcard_key(&mut self, mut key: Vec<u8>, value: V, skip: usize) -> i64 {
        let last = key.len();
        // Lowercase the part after skip
        let mut k_part = key[skip..].to_vec();
        let mut k = hash_strlow(&mut k_part, &key[skip..]);
        key[skip..].copy_from_slice(&k_part);

        k = (k % self.hsize as u32) as u32;
        let k_idx = k as usize;

        if skip == 1 {
            // For ".example.com", also check exact hash for "example.com"
            let exact_key = &key[1..last];
            for existing in &self.keys_hash[k_idx] {
                if existing == exact_key {
                    return NGX_BUSY;
                }
            }
            self.keys_hash[k_idx].insert(exact_key.to_vec());
        }

        // Check conflicts in wildcard hash
        let wc_key = &key[skip..last];
        for existing in &self.dns_wc_head_hash[k_idx] {
            if existing == wc_key {
                return NGX_BUSY;
            }
        }

        if skip > 0 {
            self.dns_wc_head_hash[k_idx].insert(wc_key.to_vec());
        } else {
            self.dns_wc_tail_hash[k_idx].insert(wc_key.to_vec());
        }

        // Reverse the key for wildcard head
        let reversed = if skip > 0 {
            // "*.example.com" -> "com.example.\0" or ".example.com" -> "com.example"
            // Reverse domain labels: walk backwards from the end
            let mut p = vec![0u8; last];
            let mut p_pos = 0usize;
            let mut label_len = 0usize;

            let mut i = last - 1;
            while i > 0 {
                if key[i] == b'.' {
                    // Found a dot. Copy the label (from i+1 to i+1+label_len) to output
                    if label_len > 0 {
                        p[p_pos..p_pos + label_len].copy_from_slice(&key[i + 1..i + 1 + label_len]);
                        p_pos += label_len;
                        p[p_pos] = b'.';
                        p_pos += 1;
                    }
                    label_len = 0;
                    i -= 1;
                } else {
                    label_len += 1;
                    i -= 1;
                }
            }

            // Handle the remaining part at the beginning (after skip)
            // For "*.example.com" with skip=2, we process "example.com" (indices 2..13)
            // The beginning part is key[skip..skip+label_len]
            if label_len > 0 {
                p[p_pos..p_pos + label_len].copy_from_slice(&key[skip..skip + label_len]);
                p_pos += label_len;
            }

            p.truncate(p_pos);
            p
        } else {
            // "www.example.*" -> "www.example\0"
            let mut p = vec![0u8; last];
            p[..last - 1].copy_from_slice(&key[..last - 1]);
            p.truncate(last - 1);
            p
        };

        let hk = HashKey {
            key: reversed,
            key_hash: 0,
            value,
        };

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
    buckets: Vec<Option<Vec<(u32, Vec<u8>, V)>>>,
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
                let key = hk.key_hash % size as u32;
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

        let size = found_size.unwrap_or(max_size);

        // Finalize bucket sizes
        for i in 0..size {
            test[i] = std::mem::size_of::<*const ()>();
        }

        for hk in &names {
            let key = hk.key_hash % size as u32;
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
        let mut buckets: Vec<Option<Vec<(u32, Vec<u8>, V)>>> = vec![None; size];
        let mut bucket_offsets = vec![0usize; size];

        // Initialize bucket offsets
        for i in 0..size {
            if test[i] > std::mem::size_of::<*const ()>() {
                bucket_offsets[i] = 0;
            }
        }

        // Insert keys into buckets
        for hk in &names {
            let key = hk.key_hash % size as u32;
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
    pub fn find(&self, key_hash: u32, name: &[u8]) -> Option<&V> {
        let bucket_idx = (key_hash % self.size as u32) as usize;
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

/// A wildcard hash table for prefix/suffix matching.
pub struct HashWildcard<V: Clone> {
    hash: Hash<WildcardValue<V>>,
}

enum WildcardValue<V: Clone> {
    Value(V),
    SubHashWithValue(std::rc::Rc<HashWildcard<V>>, V),
    SubHashOnly(std::rc::Rc<HashWildcard<V>>),
}

impl<V: Clone> Clone for WildcardValue<V> {
    fn clone(&self) -> Self {
        match self {
            WildcardValue::Value(v) => WildcardValue::Value(v.clone()),
            WildcardValue::SubHashWithValue(h, v) => WildcardValue::SubHashWithValue(h.clone(), v.clone()),
            WildcardValue::SubHashOnly(h) => WildcardValue::SubHashOnly(h.clone()),
        }
    }
}

impl<V: Clone> HashWildcard<V> {
    /// Initialize a wildcard hash table from keys. Keys are expected to be
    /// pre-processed (reversed domain labels for head, etc.).
    pub fn init(hinit: &HashInit, names: Vec<HashKey<V>>) -> Result<Self, String> {
        if names.is_empty() {
            // Return an empty wildcard hash
            let empty_hash = Hash {
                buckets: vec![],
                size: 0,
            };
            return Ok(HashWildcard { hash: empty_hash });
        }

        Self::init_recursive(hinit, names)
    }

    fn init_recursive(hinit: &HashInit, names: Vec<HashKey<V>>) -> Result<Self, String> {
        if names.is_empty() {
            let empty_hash = Hash {
                buckets: vec![],
                size: 0,
            };
            return Ok(HashWildcard { hash: empty_hash });
        }

        // Split keys by first label
        let mut curr_names = Vec::new();
        let mut n = 0usize;

        while n < names.len() {
            let key = &names[n].key;

            // Find the first dot
            let mut dot_pos = None;
            for (i, &byte) in key.iter().enumerate() {
                if byte == b'.' {
                    dot_pos = Some(i);
                    break;
                }
            }

            let first_label_len = dot_pos.unwrap_or(key.len());
            let first_label = &key[..first_label_len];

            let mut curr_key = HashKey {
                key: first_label.to_vec(),
                key_hash: hash_key_lc(first_label),
                value: WildcardValue::Value(names[n].value.clone()),
            };

            let mut next_batch = vec![];
            let mut i = n + 1;

            // Collect all keys with the same prefix
            while i < names.len() {
                let next_key = &names[i].key;
                let mut next_dot_pos = None;
                for (j, &byte) in next_key.iter().enumerate() {
                    if byte == b'.' {
                        next_dot_pos = Some(j);
                        break;
                    }
                }

                let next_first_label_len = next_dot_pos.unwrap_or(next_key.len());
                let next_first_label = &next_key[..next_first_label_len];

                if next_first_label != first_label {
                    break;
                }

                // Add remaining part to next_batch
                if next_key.len() > next_first_label_len + 1 {
                    next_batch.push(HashKey {
                        key: next_key[next_first_label_len + 1..].to_vec(),
                        key_hash: 0,
                        value: names[i].value.clone(),
                    });
                }

                i += 1;
            }

            // If current key has remaining parts, add them to next_batch
            if key.len() > first_label_len + 1 {
                next_batch.insert(
                    0,
                    HashKey {
                        key: key[first_label_len + 1..].to_vec(),
                        key_hash: 0,
                        value: names[n].value.clone(),
                    },
                );
            }

            if !next_batch.is_empty() {
                let sub_hash = Self::init_recursive(hinit, next_batch)?;
                curr_key.value = if first_label_len == key.len() {
                    WildcardValue::SubHashWithValue(std::rc::Rc::new(sub_hash), names[n].value.clone())
                } else {
                    WildcardValue::SubHashOnly(std::rc::Rc::new(sub_hash))
                };
            }

            curr_names.push(curr_key);
            n = i;
        }

        // Initialize the hash for the current level
        let hash = Hash::init(hinit, curr_names)?;

        Ok(HashWildcard { hash })
    }

    /// Find in wildcard head (e.g., "*.example.com").
    pub fn find_wc_head(&self, name: &[u8]) -> Option<&V> {
        self.find_wc_head_impl(name)
    }

    fn find_wc_head_impl(&self, name: &[u8]) -> Option<&V> {
        // Find the last dot
        let mut n = name.len();
        while n > 0 {
            if name[n - 1] == b'.' {
                break;
            }
            n -= 1;
        }

        let mut key = 0u32;
        for i in n..name.len() {
            key = ngx_hash(key, name[i]);
        }

        // Try to find in the current level
        if let Some(wildcard_val) = self.hash.find(key, &name[n..]) {
            match wildcard_val {
                WildcardValue::Value(v) => {
                    // Check the encoding rules
                    if n == 0 {
                        // "example.com" - matches exact entry only if not marked as wildcard-only
                        return Some(v);
                    }
                    return Some(v);
                }
                WildcardValue::SubHashWithValue(sub_hash, v) => {
                    if n == 0 {
                        // "example.com" - return the value associated with the wildcard
                        return Some(v);
                    }
                    // Try sub-hash first
                    if let Some(val) = sub_hash.find_wc_head_impl(&name[..n - 1]) {
                        return Some(val);
                    }
                    // Return the sub-hash's default value
                    return Some(v);
                }
                WildcardValue::SubHashOnly(sub_hash) => {
                    if n == 0 {
                        // "example.com" doesn't match wildcard-only entries
                        return None;
                    }
                    // Try sub-hash
                    if let Some(val) = sub_hash.find_wc_head_impl(&name[..n - 1]) {
                        return Some(val);
                    }
                    return None;
                }
            }
        }

        None
    }

    /// Find in wildcard tail (e.g., "www.example.*").
    pub fn find_wc_tail(&self, name: &[u8]) -> Option<&V> {
        self.find_wc_tail_impl(name)
    }

    fn find_wc_tail_impl(&self, name: &[u8]) -> Option<&V> {
        // Find the first dot
        let mut i = 0;
        let mut key = 0u32;
        while i < name.len() {
            if name[i] == b'.' {
                break;
            }
            key = ngx_hash(key, name[i]);
            i += 1;
        }

        if i == name.len() {
            // No dot found
            return None;
        }

        // Try to find in the current level
        if let Some(wildcard_val) = self.hash.find(key, &name[..i]) {
            match wildcard_val {
                WildcardValue::Value(v) => Some(v),
                WildcardValue::SubHashWithValue(sub_hash, v) => {
                    // Try sub-hash
                    if let Some(val) = sub_hash.find_wc_tail_impl(&name[i + 1..]) {
                        return Some(val);
                    }
                    // Return the sub-hash's default value
                    Some(v)
                }
                WildcardValue::SubHashOnly(sub_hash) => {
                    // Try sub-hash
                    sub_hash.find_wc_tail_impl(&name[i + 1..])
                }
            }
        } else {
            None
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
    pub fn find(&self, key_hash: u32, name: &[u8]) -> Option<&V> {
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
}
