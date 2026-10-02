//! HPACK header tables (nginx-c/src/http/v2/ngx_http_v2_table.c).

use ngx_core::log::{Log, NGX_LOG_DEBUG_HTTP, NGX_LOG_INFO};
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

pub const NGX_HTTP_V2_TABLE_SIZE: usize = 4096;

static STATIC_TABLE: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// ngx_http_v2_get_static_name (1-based index)
pub fn get_static_name(index: usize) -> &'static [u8] {
    STATIC_TABLE[index - 1].0
}

/// ngx_http_v2_get_static_value (1-based index)
pub fn get_static_value(index: usize) -> &'static [u8] {
    STATIC_TABLE[index - 1].1
}

/// A dynamic table entry: (position, length) of name and value in the
/// storage ring.
#[derive(Clone, Copy, Default)]
struct Entry {
    name: (usize, usize),
    value: (usize, usize),
}

/// ngx_http_v2_hpack_t: the decoder's dynamic table. Names and values live
/// in a NGX_HTTP_V2_TABLE_SIZE byte ring and may wrap around its end; the
/// entry ring is indexed by the running `added` / `deleted` counters.
#[derive(Default)]
pub struct Hpack {
    entries: Vec<Entry>,
    added: usize,
    deleted: usize,
    allocated: usize,
    size: usize,
    free: usize,
    storage: Vec<u8>,
    pos: usize,
}

impl Hpack {
    pub fn new() -> Hpack {
        Hpack::default()
    }

    /// ngx_http_v2_get_indexed_header: resolve an HPACK index to (name,
    /// value). With `name_only`, the value of a dynamic entry is not copied.
    pub fn get_indexed_header(&self, index: usize, name_only: bool, log: &Log) -> Result<(Vec<u8>, Vec<u8>), ()> {
        let (mut name, mut value) = (Vec::new(), Vec::new());
        self.get_indexed_header_into(index, name_only, log, &mut name, &mut value)?;
        Ok((name, value))
    }

    /// ngx_http_v2_get_indexed_header into the caller's buffers, which
    /// keep their capacity: the name, and unless `name_only` the value,
    /// replace what they hold. Nothing changes on an error.
    pub fn get_indexed_header_into(&self, index: usize, name_only: bool, log: &Log, name: &mut Vec<u8>, value: &mut Vec<u8>) -> Result<(), ()> {
        if index == 0 {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent invalid hpack table index 0");
            return Err(());
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 get indexed {}: {}", if name_only { "name" } else { "header" }, index);

        let mut index = index - 1;

        if index < STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[index];

            name.clear();
            name.extend_from_slice(n);

            if !name_only {
                value.clear();
                value.extend_from_slice(v);
            }

            return Ok(());
        }

        index -= STATIC_TABLE.len();

        if index < self.added - self.deleted {
            let entry = self.entries[(self.added - index - 1) % self.allocated];

            self.read_into(entry.name, name);

            if !name_only {
                self.read_into(entry.value, value);
            }

            return Ok(());
        }

        ngx_log_error!(NGX_LOG_INFO, log, None, "client sent out of bound hpack table index: {}", index);

        Err(())
    }

    /// A (possibly wrapped) string of the storage ring into `dst`.
    fn read_into(&self, (pos, len): (usize, usize), dst: &mut Vec<u8>) {
        dst.clear();

        let rest = NGX_HTTP_V2_TABLE_SIZE - pos;

        if len > rest {
            dst.extend_from_slice(&self.storage[pos..]);
            dst.extend_from_slice(&self.storage[..len - rest]);
        } else {
            dst.extend_from_slice(&self.storage[pos..pos + len]);
        }
    }

    /// Copy `data` into the storage ring at `pos`, wrapping at its end.
    fn write(&mut self, data: &[u8]) -> (usize, usize) {
        let at = self.pos;
        let avail = NGX_HTTP_V2_TABLE_SIZE - self.pos;
        if avail >= data.len() {
            self.storage[at..at + data.len()].copy_from_slice(data);
            self.pos += data.len();
        } else {
            self.storage[at..].copy_from_slice(&data[..avail]);
            let rest = data.len() - avail;
            self.storage[..rest].copy_from_slice(&data[avail..]);
            self.pos = rest;
        }
        (at, data.len())
    }

    /// ngx_http_v2_add_header: insert a header, evicting the oldest entries
    /// as needed. An entry larger than the whole table empties it and is not
    /// stored.
    pub fn add_header(&mut self, name: &[u8], value: &[u8], log: &Log) {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 table add: \"{}: {}\"", B(name), B(value));

        if self.entries.is_empty() {
            self.allocated = 64;
            self.size = NGX_HTTP_V2_TABLE_SIZE;
            self.free = NGX_HTTP_V2_TABLE_SIZE;
            self.entries = vec![Entry::default(); self.allocated];
            self.storage = vec![0; NGX_HTTP_V2_TABLE_SIZE];
            self.pos = 0;
        }

        if !self.account(name.len() + value.len(), log) {
            return;
        }

        let entry = Entry { name: self.write(name), value: self.write(value) };

        if self.allocated == self.added - self.deleted {
            let index = self.deleted % self.allocated;
            let mut entries = Vec::with_capacity(self.allocated + 64);
            entries.extend_from_slice(&self.entries[index..]);
            entries.extend_from_slice(&self.entries[..index]);
            entries.resize(self.allocated + 64, Entry::default());
            self.entries = entries;
            self.added = self.allocated;
            self.deleted = 0;
            self.allocated += 64;
        }

        let slot = self.added % self.allocated;
        self.entries[slot] = entry;
        self.added += 1;
    }

    /// ngx_http_v2_table_account: make room for an entry of `size` octets
    /// (plus the 32-octet overhead). False when it can never fit.
    fn account(&mut self, size: usize, log: &Log) -> bool {
        let size = size + 32;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 table account: {} free:{}", size, self.free);

        if size <= self.free {
            self.free -= size;
            return true;
        }

        if size > self.size {
            self.deleted = self.added;
            self.free = self.size;
            return false;
        }

        while size > self.free {
            self.evict();
        }

        self.free -= size;

        true
    }

    fn evict(&mut self) {
        let entry = self.entries[self.deleted % self.allocated];
        self.deleted += 1;
        self.free += 32 + entry.name.1 + entry.value.1;
    }

    /// ngx_http_v2_table_size: apply a dynamic table size update.
    ///
    /// As in C, an update received before the first insertion is lost when
    /// add_header() initialises the table to NGX_HTTP_V2_TABLE_SIZE.
    pub fn table_size(&mut self, size: usize, log: &Log) -> Result<(), ()> {
        if size > NGX_HTTP_V2_TABLE_SIZE {
            ngx_log_error!(NGX_LOG_INFO, log, None, "client sent invalid table size update: {}", size);
            return Err(());
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, log, "http2 new hpack table size: {} was:{}", size, self.size);

        let needed = self.size as isize - size as isize;

        while needed > self.free as isize {
            self.evict();
        }

        self.size = size;
        self.free = (self.free as isize - needed) as usize;

        Ok(())
    }
}
