//! HPACK codec tests: RFC 7541 Appendix C vectors plus nginx-specific
//! behaviour the HTTP/2 tests depend on.

use ngx_core::log::{Log, NGX_LOG_ERR};
use ngx_http::huff_decode::huff_decode;
use ngx_http::huff_encode::huff_encode;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn decode(src: &[u8]) -> Result<Vec<u8>, ()> {
    let log = Log::stderr(NGX_LOG_ERR);
    let mut state = 0u8;
    let mut out = Vec::new();
    huff_decode(&mut state, src, &mut out, true, &log)?;
    assert_eq!(state, 0);
    Ok(out)
}

fn encode(src: &[u8], lower: bool) -> Option<Vec<u8>> {
    let mut dst = vec![0u8; src.len()];
    match huff_encode(src, &mut dst, lower) {
        0 => None,
        n => Some(dst[..n].to_vec()),
    }
}

// RFC 7541 C.4 and C.6: (plain, Huffman-coded)
const VECTORS: &[(&str, &str)] = &[
    ("www.example.com", "f1e3 c2e5 f23a 6ba0 ab90 f4ff"),
    ("no-cache", "a8eb 1064 9cbf"),
    ("custom-key", "25a8 49e9 5ba9 7d7f"),
    ("custom-value", "25a8 49e9 5bb8 e8b4 bf"),
    ("302", "6402"),
    ("private", "aec3 771a 4b"),
    ("Mon, 21 Oct 2013 20:13:21 GMT", "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff"),
    ("https://www.example.com", "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3"),
    ("307", "640e ff"),
    ("Mon, 21 Oct 2013 20:13:22 GMT", "d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff"),
    ("gzip", "9bd9 ab"),
    (
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        "94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
    ),
];

#[test]
fn rfc7541_decode() {
    for (plain, coded) in VECTORS {
        assert_eq!(decode(&hex(coded)).unwrap(), plain.as_bytes(), "{}", plain);
    }
}

#[test]
fn rfc7541_encode() {
    for (plain, coded) in VECTORS {
        let coded = hex(coded);
        // nginx only uses Huffman when strictly shorter: "307" (3 octets
        // either way) stays raw.
        if coded.len() < plain.len() {
            assert_eq!(encode(plain.as_bytes(), false).unwrap(), coded, "{}", plain);
        } else {
            assert_eq!(encode(plain.as_bytes(), false), None, "{}", plain);
        }
    }
}

#[test]
fn decode_resumes_across_buffers() {
    let log = Log::stderr(NGX_LOG_ERR);
    let coded = hex("9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3");
    for split in 1..coded.len() {
        let mut state = 0u8;
        let mut out = Vec::new();
        huff_decode(&mut state, &coded[..split], &mut out, false, &log).unwrap();
        huff_decode(&mut state, &coded[split..], &mut out, true, &log).unwrap();
        assert_eq!(out, b"https://www.example.com");
    }
}

#[test]
fn decode_accepts_full_padding_byte() {
    // Test::Nginx::HTTP2 appends a whole 0xFF byte when a string ends on a
    // byte boundary ("localhost" is 48 bits); nginx's table accepts it.
    let mut coded = encode(b"localhost", false).unwrap();
    assert_eq!(coded.len(), 6);
    coded.push(0xff);
    assert_eq!(decode(&coded).unwrap(), b"localhost");
}

#[test]
fn encode_only_when_shorter() {
    // h2_headers.t: "{{{{{" stays raw (Huffman would take 10 bytes),
    // "aaaaa" is Huffman-coded (4 bytes).
    assert_eq!(encode(b"{{{{{", false), None);
    assert_eq!(encode(b"aaaaa", false).map(|v| v.len()), Some(4));
    assert_eq!(encode(b"", false), None);
}

#[test]
fn encode_lowercase_table() {
    assert_eq!(encode(b"WWW.Example.COM", true), encode(b"www.example.com", false));
}

use ngx_http::v2::table::Hpack;

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| b'a' + ((i + seed as usize) % 26) as u8).collect()
}

#[test]
fn hpack_static_and_dynamic_indexing() {
    let log = Log::stderr(NGX_LOG_ERR);
    let mut t = Hpack::new();
    assert_eq!(t.get_indexed_header(2, false, &log).unwrap(), (b":method".to_vec(), b"GET".to_vec()));
    assert_eq!(t.get_indexed_header(61, false, &log).unwrap().0, b"www-authenticate");
    assert!(t.get_indexed_header(0, false, &log).is_err());
    assert!(t.get_indexed_header(62, false, &log).is_err());

    t.add_header(b"custom-key", b"custom-header", &log);
    assert_eq!(t.get_indexed_header(62, false, &log).unwrap(), (b"custom-key".to_vec(), b"custom-header".to_vec()));
    t.add_header(b"a", b"b", &log);
    // newest entry first
    assert_eq!(t.get_indexed_header(62, false, &log).unwrap().0, b"a");
    assert_eq!(t.get_indexed_header(63, true, &log).unwrap(), (b"custom-key".to_vec(), Vec::new()));
    assert!(t.get_indexed_header(64, false, &log).is_err());
}

#[test]
fn hpack_size_update_evicts() {
    // h2_headers.t "size update": entries of 51, 42 and 42 octets, then a
    // table size update to 61 leaves only the newest.
    let log = Log::stderr(NGX_LOG_ERR);
    let mut t = Hpack::new();
    t.add_header(b":authority", b"localhost", &log);
    t.add_header(b"referer", b"foo", &log);
    t.add_header(b"x-foo", b"X-Bar", &log);
    t.table_size(61, &log).unwrap();
    assert_eq!(t.get_indexed_header(62, false, &log).unwrap().0, b"x-foo");
    assert!(t.get_indexed_header(63, false, &log).is_err());
    // a 51-octet entry no longer fits beside it
    t.add_header(b":authority", b"localhost", &log);
    assert_eq!(t.get_indexed_header(62, false, &log).unwrap().0, b":authority");
    assert!(t.get_indexed_header(63, false, &log).is_err());
    assert!(t.table_size(4097, &log).is_err());
}

#[test]
fn hpack_entry_larger_than_table_empties_it() {
    let log = Log::stderr(NGX_LOG_ERR);
    let mut t = Hpack::new();
    t.add_header(b"a", b"b", &log);
    t.add_header(&pattern(2100, 0), &pattern(2000, 1), &log);
    assert!(t.get_indexed_header(62, false, &log).is_err());
}

#[test]
fn hpack_storage_ring_wraps() {
    // h2_headers.t "hpack table boundary": an entry filling the table
    // exactly, then entries whose name and then value wrap the ring.
    let log = Log::stderr(NGX_LOG_ERR);
    let mut t = Hpack::new();
    for (i, (nlen, vlen)) in [(2016, 2048), (33, 4031), (1, 64), (100, 3900), (3000, 1000)].into_iter().enumerate() {
        let name = pattern(nlen, i as u8);
        let value = pattern(vlen, i as u8 + 7);
        t.add_header(&name, &value, &log);
        assert_eq!(t.get_indexed_header(62, false, &log).unwrap(), (name, value), "entry {}", i);
    }
}

#[test]
fn hpack_entry_ring_grows() {
    // more than 64 live entries: the entry ring is reallocated in order
    let log = Log::stderr(NGX_LOG_ERR);
    let mut t = Hpack::new();
    for i in 0..100u32 {
        t.add_header(format!("n{}", i).as_bytes(), b"v", &log);
    }
    for back in 0..100usize {
        let want = format!("n{}", 99 - back);
        assert_eq!(t.get_indexed_header(62 + back, true, &log).unwrap().0, want.as_bytes());
    }
}

use ngx_http::v2::encode::{prefix, string_encode, write_int, NGX_HTTP_V2_ENCODE_HUFF};

#[test]
fn integer_encoding() {
    // RFC 7541 C.1
    let mut v = Vec::new();
    write_int(&mut v, 0, prefix(5), 10);
    assert_eq!(v, [0x0a]);
    let mut v = Vec::new();
    write_int(&mut v, 0, prefix(5), 1337);
    assert_eq!(v, [0x1f, 0x9a, 0x0a]);
    let mut v = Vec::new();
    write_int(&mut v, 0, prefix(8), 42);
    assert_eq!(v, [0x2a]);
    // flag bits of the first octet are kept
    let mut v = Vec::new();
    write_int(&mut v, NGX_HTTP_V2_ENCODE_HUFF, prefix(7), 127);
    assert_eq!(v, [0xff, 0x00]);
}

#[test]
fn string_encoding() {
    let mut v = Vec::new();
    string_encode(&mut v, b"www.example.com", false);
    assert_eq!(v[0], 0x80 | 12);
    assert_eq!(&v[1..], &hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff")[..]);
    // not shorter: raw, lowercased when asked
    let mut v = Vec::new();
    string_encode(&mut v, b"{{{{{", true);
    assert_eq!(v, b"\x05{{{{{");
    let mut v = Vec::new();
    string_encode(&mut v, b"X-{Z}", true);
    assert_eq!(v, b"\x05x-{z}");
}
