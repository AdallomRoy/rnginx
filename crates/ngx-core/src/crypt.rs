//! Password hashing (ngx_crypt.c): nginx's own $apr1$, {PLAIN}, {SHA} and
//! {SSHA} formats, and ngx_libc_crypt(), the fallback to crypt_r() of the
//! system's libcrypt for the others.  The libcrypt of the supported
//! systems is libxcrypt 4.4 (with its default "failure tokens"): its
//! crypt_r() is done here in Rust, format by format:
//!
//! * DES ("ab..."), bigcrypt (longer DES hashes) and BSDi extended DES
//!   ("_...") with pwhash's DES;
//! * MD5 ($1$, the algorithm of $apr1$), SHA-256 ($5$), SHA-512 ($6$),
//!   SHA-1 ($sha1$), Sun MD5 ($md5) and NT ($3$) ported from libxcrypt,
//!   which validates settings differently from pwhash's versions (any
//!   printable salt character, no clamping of "rounds=");
//! * bcrypt ($2a$, $2b$, $2x$, $2y$) on the blowfish crate (what pwhash's
//!   bcrypt uses), with crypt_blowfish's sign extension bug ($2x$) and
//!   its countermeasure ($2a$);
//! * yescrypt ($y$), scrypt ($7$) and gost-yescrypt ($gy$, with GOST R
//!   34.11-2012) ported from libxcrypt (yescrypt.rs, gost.rs).
//!
//! A failure gives libxcrypt's failure token ("*0", "*1" for a setting
//! starting with "*0"), which never matches the setting: crypt_r() never
//! returns NULL, so the "crypt_r() failed" message of ngx_libc_crypt()
//! cannot happen.

use md5::Md5;
use sha1::{Digest, Sha1};

mod gost;
mod gost_tables;
mod yescrypt;

/// Hash a password with the algorithm of the salt (ngx_crypt()).
pub fn crypt(key: &[u8], salt: &[u8]) -> Result<Vec<u8>, i32> {
    if salt.len() >= 6 && &salt[..6] == b"$apr1$" {
        crypt_apr1(key, salt)
    } else if salt.len() >= 7 && &salt[..7] == b"{PLAIN}" {
        crypt_plain(key)
    } else if salt.len() >= 6 && &salt[..6] == b"{SSHA}" {
        crypt_ssha(key, salt)
    } else if salt.len() >= 5 && &salt[..5] == b"{SHA}" {
        crypt_sha(key)
    } else {
        crypt_libc(key, salt)
    }
}

/// ngx_crypt_apr1(): Poul-Henning Kamp's MD5 crypt with the $apr1$ magic
fn crypt_apr1(key: &[u8], salt: &[u8]) -> Result<Vec<u8>, i32> {
    Ok(md5_crypt(key, b"$apr1$", &salt[6..]))
}

/// The MD5 crypt of ngx_crypt_apr1() and of libxcrypt's
/// crypt_md5crypt_rn() with their magic: the true salt is at most 8
/// characters and stops at the first '$'.
fn md5_crypt(key: &[u8], magic: &[u8], salt: &[u8]) -> Vec<u8> {
    let salt_len = salt.iter().take(8).position(|&c| c == b'$').unwrap_or(salt.len().min(8));

    let true_salt = &salt[..salt_len];
    let key_len = key.len();

    // Initial hash: key + magic + salt
    let mut md5 = Md5::new();
    md5.update(key);
    md5.update(magic);
    md5.update(true_salt);

    // Intermediate hash: key + salt + key
    let mut ctx1 = Md5::new();
    ctx1.update(key);
    ctx1.update(true_salt);
    ctx1.update(key);
    let mut final_digest = [0u8; 16];
    final_digest.copy_from_slice(&ctx1.finalize());

    // Add intermediate hash to main hash, repeating 16-byte chunks
    let mut n = key_len;
    while n > 0 {
        let chunk = if n > 16 { 16 } else { n };
        md5.update(&final_digest[..chunk]);
        n -= chunk;
    }

    // Clear final_digest temporarily
    final_digest.fill(0);

    // Extra hashing based on key length bits
    let mut i = key_len;
    while i > 0 {
        if i & 1 == 1 {
            md5.update(&final_digest[..1]);
        } else {
            md5.update(&key[..1]);
        }
        i >>= 1;
    }

    final_digest.copy_from_slice(&md5.finalize());

    // 1000-round loop
    for i in 0..1000 {
        let mut ctx = Md5::new();

        if i & 1 == 1 {
            ctx.update(key);
        } else {
            ctx.update(final_digest);
        }

        if i % 3 != 0 {
            ctx.update(true_salt);
        }

        if i % 7 != 0 {
            ctx.update(key);
        }

        if i & 1 == 1 {
            ctx.update(final_digest);
        } else {
            ctx.update(key);
        }

        final_digest.copy_from_slice(&ctx.finalize());
    }

    // Output: magic + salt + $ + base64-encoded digest
    let mut result = magic.to_vec();
    result.extend_from_slice(true_salt);
    result.push(b'$');

    // Encode digest using custom base64 alphabet: ./0-9A-Za-z
    result.extend_from_slice(&crypt_to64((final_digest[0] as u32) << 16 | (final_digest[6] as u32) << 8 | final_digest[12] as u32, 4));
    result.extend_from_slice(&crypt_to64((final_digest[1] as u32) << 16 | (final_digest[7] as u32) << 8 | final_digest[13] as u32, 4));
    result.extend_from_slice(&crypt_to64((final_digest[2] as u32) << 16 | (final_digest[8] as u32) << 8 | final_digest[14] as u32, 4));
    result.extend_from_slice(&crypt_to64((final_digest[3] as u32) << 16 | (final_digest[9] as u32) << 8 | final_digest[15] as u32, 4));
    result.extend_from_slice(&crypt_to64((final_digest[4] as u32) << 16 | (final_digest[10] as u32) << 8 | final_digest[5] as u32, 4));
    result.extend_from_slice(&crypt_to64(final_digest[11] as u32, 2));

    result
}

/// Convert 6-bit chunks to base64-like characters using ./0-9A-Za-z alphabet
fn crypt_to64(mut v: u32, n: usize) -> Vec<u8> {
    let mut result = Vec::new();
    for _ in 0..n {
        result.push(ASCII64[(v & 0x3f) as usize]);
        v >>= 6;
    }
    result
}

/// {PLAIN} - plaintext password
fn crypt_plain(key: &[u8]) -> Result<Vec<u8>, i32> {
    let mut result = b"{PLAIN}".to_vec();
    result.extend_from_slice(key);
    Ok(result)
}

/// {SHA} - base64(SHA1(key))
fn crypt_sha(key: &[u8]) -> Result<Vec<u8>, i32> {
    let digest = Sha1::digest(key);
    let encoded = base64_encode(&digest);

    let mut result = b"{SHA}".to_vec();
    result.extend_from_slice(&encoded);
    Ok(result)
}

/// {SSHA} - base64(SHA1(key+salt)+salt)
fn crypt_ssha(key: &[u8], salt_arg: &[u8]) -> Result<Vec<u8>, i32> {
    // Extract the base64-encoded part
    let encoded_part = &salt_arg[6..]; // Skip "{SSHA}"

    // Decode the base64 to get the stored digest + salt; as in C, a value
    // that is empty or does not decode has no salt
    let decoded = crate::string::decode_base64(encoded_part).unwrap_or_default();

    // The stored format is: SHA1(key+salt) || salt
    // Minimum is 20 bytes (SHA1 digest), rest is salt
    let true_salt = if decoded.len() > 20 { &decoded[20..] } else { &[] };

    // Compute new hash: SHA1(key + true_salt)
    let mut hasher = Sha1::new();
    hasher.update(key);
    hasher.update(true_salt);
    let new_digest = hasher.finalize();

    // Combine: new_digest || true_salt
    let mut payload = new_digest.to_vec();
    payload.extend_from_slice(true_salt);

    let encoded = base64_encode(&payload);

    let mut result = b"{SSHA}".to_vec();
    result.extend_from_slice(&encoded);
    Ok(result)
}

/// Simple base64 encoder
fn base64_encode(data: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = Vec::new();
    let mut i = 0;

    while i + 3 <= data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];
        let b3 = data[i + 2];

        result.push(ALPHABET[(b1 >> 2) as usize]);
        result.push(ALPHABET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize]);
        result.push(ALPHABET[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize]);
        result.push(ALPHABET[(b3 & 0x3f) as usize]);

        i += 3;
    }

    // Handle remaining bytes
    if i < data.len() {
        let b1 = data[i];
        result.push(ALPHABET[(b1 >> 2) as usize]);

        if i + 1 < data.len() {
            let b2 = data[i + 1];
            result.push(ALPHABET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize]);
            result.push(ALPHABET[((b2 & 0x0f) << 2) as usize]);
            result.push(b'=');
        } else {
            result.push(ALPHABET[((b1 & 0x03) << 4) as usize]);
            result.push(b'=');
            result.push(b'=');
        }
    }

    result
}

/// Simple base64 decoder
#[cfg(test)]
fn base64_decode(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut result = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;

    for &byte in data {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return Err(()),
        };

        buf = (buf << 6) | (val as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push(((buf >> bits) & 0xff) as u8);
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------
// crypt_r() of libxcrypt 4.4

/// CRYPT_OUTPUT_SIZE of crypt.h
const CRYPT_OUTPUT_SIZE: usize = 384;
/// CRYPT_MAX_PASSPHRASE_SIZE of crypt.h
const CRYPT_MAX_PASSPHRASE_SIZE: usize = 512;

/// ascii64 (itoa64, b64t) of libxcrypt
const ASCII64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The C string of the bytes: they end at the first NUL.
fn c_str(s: &[u8]) -> &[u8] {
    &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
}

/// ngx_libc_crypt(): crypt_r() returns the hash or a failure token, never
/// NULL.
fn crypt_libc(key: &[u8], salt: &[u8]) -> Result<Vec<u8>, i32> {
    Ok(crypt_r(c_str(key), c_str(salt)))
}

/// crypt_r(): make_failure_token(), then do_crypt()
fn crypt_r(phrase: &[u8], setting: &[u8]) -> Vec<u8> {
    match do_crypt(phrase, setting) {
        Some(output) => output,
        None => {
            if setting.starts_with(b"*0") {
                b"*1".to_vec()
            } else {
                b"*0".to_vec()
            }
        }
    }
}

/// check_badsalt_chars(): settings are printable ASCII without
/// whitespace and without '!', '*', ':', ';' and '\'.
fn bad_salt_chars(setting: &[u8]) -> bool {
    setting.iter().any(|&c| c <= 0x20 || c >= 0x7f || b"!*:;\\".contains(&c))
}

/// is_des_salt_char()
fn is_des_salt_char(c: Option<&u8>) -> bool {
    c.is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'.' || c == b'/')
}

/// ascii_to_bin() of crypt-des.c: the value of an ascii64 character
fn ascii_to_bin(c: u8) -> Option<u32> {
    ASCII64.iter().position(|&a| a == c).map(|v| v as u32)
}

/// do_crypt(): the hash, None for what sets errno (the failure token)
fn do_crypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    if phrase.len() >= CRYPT_MAX_PASSPHRASE_SIZE {
        // ERANGE
        return None;
    }

    if bad_salt_chars(setting) {
        return None;
    }

    // get_hashfn(): the prefixes of the hashes, longest first
    if setting.starts_with(b"$sha1") {
        sha1crypt(phrase, setting)
    } else if setting.starts_with(b"$2a$") || setting.starts_with(b"$2b$") || setting.starts_with(b"$2x$") || setting.starts_with(b"$2y$") {
        bcrypt(phrase, setting)
    } else if setting.starts_with(b"$gy$") {
        yescrypt::gost_yescrypt(phrase, setting)
    } else if setting.starts_with(b"$md5") {
        sunmd5(phrase, setting)
    } else if setting.starts_with(b"$1$") {
        md5crypt(phrase, setting)
    } else if setting.starts_with(b"$3$") {
        nt(phrase, setting)
    } else if setting.starts_with(b"$5$") {
        sha_crypt(phrase, setting, false)
    } else if setting.starts_with(b"$6$") {
        sha_crypt(phrase, setting, true)
    } else if setting.starts_with(b"$7$") {
        yescrypt::scrypt(phrase, setting)
    } else if setting.starts_with(b"$y$") {
        yescrypt::yescrypt(phrase, setting)
    } else if setting.starts_with(b"_") {
        bsdicrypt(phrase, setting)
    } else if setting.is_empty() || (is_des_salt_char(setting.first()) && is_des_salt_char(setting.get(1))) {
        bigcrypt(phrase, setting)
    } else {
        // unrecognized hash algorithm
        None
    }
}

/// crypt_descrypt_rn(): the traditional DES hash of the first 8
/// characters, with the canonical salt
#[allow(deprecated)]
fn descrypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    let salt = setting.get(..2)?;

    ascii_to_bin(salt[0])?;
    ascii_to_bin(salt[1])?;

    let salt = std::str::from_utf8(salt).ok()?;

    pwhash::unix_crypt::hash_with(salt, phrase).ok().map(String::into_bytes)
}

/// crypt_bigcrypt_rn(): the DES hashes of the blocks of 8 characters of
/// the phrase (up to 16), the salt of a block being the first two
/// characters of the hash of the previous one; a setting of 13
/// characters or less hashes a longer phrase with descrypt.
#[allow(deprecated)]
fn bigcrypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    if phrase.len() > 8 && setting.len() <= 13 {
        return descrypt(phrase, setting);
    }

    let first = descrypt(phrase.get(..8).unwrap_or(phrase), setting)?;

    let mut output = first.clone();
    let mut salt = first[2..4].to_vec();

    for seg in 1..16 {
        if seg * 8 >= phrase.len() {
            break;
        }

        let block = &phrase[seg * 8..phrase.len().min(seg * 8 + 8)];

        let h = pwhash::unix_crypt::hash_with(std::str::from_utf8(&salt).ok()?, block).ok()?.into_bytes();

        output.extend_from_slice(&h[2..]);
        salt = h[2..4].to_vec();
    }

    Some(output)
}

/// crypt_bsdicrypt_rn(): "_", 4 characters of count, 4 of salt, the
/// phrase folded into a DES key; the count 0 runs 1 iteration
/// (des_crypt_block()) and the setting is copied as it is.
#[allow(deprecated)]
fn bsdicrypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    if setting.len() < 9 {
        return None;
    }

    let mut count = 0u32;

    for i in 1..5 {
        count |= ascii_to_bin(setting[i])? << ((i - 1) * 6);
    }

    for &c in &setting[5..9] {
        ascii_to_bin(c)?;
    }

    let salt = std::str::from_utf8(&setting[5..9]).ok()?;

    let h = pwhash::bsdi_crypt::hash_with(pwhash::HashSetup { salt: Some(salt), rounds: Some(count.max(1)) }, phrase).ok()?.into_bytes();

    let mut output = setting[..9].to_vec();
    output.extend_from_slice(&h[9..]);

    Some(output)
}

/// crypt_md5crypt_rn(): the salt ends at '$' (':' and '\n' are bad salt
/// characters already)
fn md5crypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    Some(md5_crypt(phrase, b"$1$", &setting[3..]))
}

/// A SHA-2 digest of the SHA-crypts.
enum Sha2 {
    S256(openssl::sha::Sha256),
    S512(openssl::sha::Sha512),
}

impl Sha2 {
    fn new(sha512: bool) -> Sha2 {
        if sha512 {
            Sha2::S512(openssl::sha::Sha512::new())
        } else {
            Sha2::S256(openssl::sha::Sha256::new())
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Sha2::S256(h) => h.update(data),
            Sha2::S512(h) => h.update(data),
        }
    }

    /// SHAxxx_Update_recycled(): len bytes of block repeated
    fn update_recycled(&mut self, block: &[u8], len: usize) {
        let mut cnt = len;

        while cnt >= block.len() {
            self.update(block);
            cnt -= block.len();
        }

        self.update(&block[..cnt]);
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Sha2::S256(h) => h.finish().to_vec(),
            Sha2::S512(h) => h.finish().to_vec(),
        }
    }
}

/// The digits of a number as strtoul() reads them after the first digit
/// was checked: the value (None if it overflows unsigned long) and the
/// number of digits.
fn decimal(s: &[u8]) -> (Option<u64>, usize) {
    let n = s.iter().take_while(|c| c.is_ascii_digit()).count();
    let v = s[..n].iter().try_fold(0u64, |v, &c| v.checked_mul(10)?.checked_add((c - b'0') as u64));

    (v, n)
}

/// crypt_sha256crypt_rn(), crypt_sha512crypt_rn()
fn sha_crypt(phrase: &[u8], setting: &[u8], sha512: bool) -> Option<Vec<u8>> {
    const ROUNDS_DEFAULT: u64 = 5000;
    const ROUNDS_MIN: u64 = 1000;
    const ROUNDS_MAX: u64 = 999999999;
    const SALT_LEN_MAX: usize = 16;

    let prefix = &setting[..3];
    let mut salt = &setting[3..];

    let mut rounds = ROUNDS_DEFAULT;
    let mut rounds_custom = false;

    if let Some(num) = salt.strip_prefix(b"rounds=") {
        // Do not allow an explicit setting of zero rounds, nor of the
        // default number of rounds, nor leading zeroes on the rounds.
        if !matches!(num.first(), Some(b'1'..=b'9')) {
            return None;
        }

        let (value, n) = decimal(num);

        if num.get(n) != Some(&b'$') {
            return None;
        }

        rounds = value.filter(|r| (ROUNDS_MIN..=ROUNDS_MAX).contains(r))?;
        salt = &num[n + 1..];
        rounds_custom = true;
    }

    // The salt ends at the next '$' or the end of the string (':' and
    // '\n' are bad salt characters already).
    let salt_size = salt.iter().position(|&c| c == b'$').unwrap_or(salt.len()).min(SALT_LEN_MAX);
    let salt = &salt[..salt_size];

    let phr_size = phrase.len();

    // Compute alternate sum with input PHRASE, SALT, and PHRASE.
    let mut ctx = Sha2::new(sha512);
    ctx.update(phrase);
    ctx.update(salt);
    ctx.update(phrase);
    let mut result = ctx.finish();
    let dlen = result.len();

    // Prepare for the real work.
    let mut ctx = Sha2::new(sha512);
    ctx.update(phrase);
    ctx.update(salt);

    // Add for any character in the phrase one byte of the alternate sum.
    let mut cnt = phr_size;
    while cnt > dlen {
        ctx.update(&result);
        cnt -= dlen;
    }
    ctx.update(&result[..cnt]);

    // Take the binary representation of the length of the phrase and for
    // every 1 add the alternate sum, for every 0 the phrase.
    let mut cnt = phr_size;
    while cnt > 0 {
        if cnt & 1 != 0 {
            ctx.update(&result);
        } else {
            ctx.update(phrase);
        }
        cnt >>= 1;
    }

    result = ctx.finish();

    // Start computation of P byte sequence.
    let mut ctx = Sha2::new(sha512);
    for _ in 0..phr_size {
        ctx.update(phrase);
    }
    let p_bytes = ctx.finish();

    // Start computation of S byte sequence.
    let mut ctx = Sha2::new(sha512);
    for _ in 0..16 + result[0] as usize {
        ctx.update(salt);
    }
    let s_bytes = ctx.finish();

    // Repeatedly run the collected hash value through SHA to burn CPU
    // cycles.
    for cnt in 0..rounds {
        let mut ctx = Sha2::new(sha512);

        if cnt & 1 != 0 {
            ctx.update_recycled(&p_bytes, phr_size);
        } else {
            ctx.update(&result);
        }

        if cnt % 3 != 0 {
            ctx.update_recycled(&s_bytes, salt_size);
        }

        if cnt % 7 != 0 {
            ctx.update_recycled(&p_bytes, phr_size);
        }

        if cnt & 1 != 0 {
            ctx.update(&result);
        } else {
            ctx.update_recycled(&p_bytes, phr_size);
        }

        result = ctx.finish();
    }

    let mut output = prefix.to_vec();

    if rounds_custom {
        output.extend_from_slice(format!("rounds={}$", rounds).as_bytes());
    }

    output.extend_from_slice(salt);
    output.push(b'$');

    let mut b64_from_24bit = |b2: u8, b1: u8, b0: u8, n: usize| {
        let mut w = (b2 as u32) << 16 | (b1 as u32) << 8 | b0 as u32;
        for _ in 0..n {
            output.push(ASCII64[(w & 0x3f) as usize]);
            w >>= 6;
        }
    };

    let r = &result;

    if sha512 {
        for (a, b, c) in [
            (0, 21, 42),
            (22, 43, 1),
            (44, 2, 23),
            (3, 24, 45),
            (25, 46, 4),
            (47, 5, 26),
            (6, 27, 48),
            (28, 49, 7),
            (50, 8, 29),
            (9, 30, 51),
            (31, 52, 10),
            (53, 11, 32),
            (12, 33, 54),
            (34, 55, 13),
            (56, 14, 35),
            (15, 36, 57),
            (37, 58, 16),
            (59, 17, 38),
            (18, 39, 60),
            (40, 61, 19),
            (62, 20, 41),
        ] {
            b64_from_24bit(r[a], r[b], r[c], 4);
        }
        b64_from_24bit(0, 0, r[63], 2);
    } else {
        for (a, b, c) in [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14), (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29)] {
            b64_from_24bit(r[a], r[b], r[c], 4);
        }
        b64_from_24bit(0, r[31], r[30], 3);
    }

    Some(output)
}

/// hmac_sha1_process_data()
fn hmac_sha1(text: &[u8], key: &[u8]) -> [u8; 20] {
    const HMAC_BLOCKSZ: usize = 64;

    let tk;
    let key = if key.len() > HMAC_BLOCKSZ {
        tk = Sha1::digest(key);
        &tk[..]
    } else {
        key
    };

    let mut k_ipad = [0x36u8; HMAC_BLOCKSZ];
    let mut k_opad = [0x5cu8; HMAC_BLOCKSZ];

    for (i, &k) in key.iter().enumerate() {
        k_ipad[i] ^= k;
        k_opad[i] ^= k;
    }

    let mut ctx = Sha1::new();
    ctx.update(k_ipad);
    ctx.update(text);
    let inner = ctx.finalize();

    let mut ctx = Sha1::new();
    ctx.update(k_opad);
    ctx.update(inner);

    ctx.finalize().into()
}

/// strtoul(s, &ep, 10) as glibc reads a number that may start with a
/// sign (whitespace is a bad salt character already): the value and the
/// length read, 0 if there are no digits (ep == s).  An overflow gives
/// ULONG_MAX.
fn strtoul(s: &[u8]) -> (u64, usize) {
    let (neg, start) = match s.first() {
        Some(b'-') => (true, 1),
        Some(b'+') => (false, 1),
        _ => (false, 0),
    };

    let (v, n) = decimal(&s[start..]);

    if n == 0 {
        return (0, 0);
    }

    let v = match v {
        None => u64::MAX,
        Some(v) if neg => v.wrapping_neg(),
        Some(v) => v,
    };

    (v, start + n)
}

/// crypt_sha1crypt_rn(): "$sha1$", the iterations, '$', 1 or more ascii64
/// characters of salt, an optional '$'.  (The C hashes a salt longer
/// than its output buffer past the buffer; the port hashes the salt.)
fn sha1crypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    const MAGIC: &[u8] = b"$sha1$";

    let rest = setting.strip_prefix(MAGIC)?;

    // get the iteration count
    let (iterations, n) = strtoul(rest);

    if rest.get(n) != Some(&b'$') {
        return None;
    }

    let rest = &rest[n + 1..];

    let sl = rest.iter().take_while(|c| ASCII64.contains(c)).count();

    if sl == 0 || (sl < rest.len() && rest[sl] != b'$') {
        return None;
    }

    let salt = &rest[..sl];

    // Prime the pump with <salt><magic><iterations>
    let mut data = salt.to_vec();
    data.extend_from_slice(MAGIC);
    data.extend_from_slice(iterations.to_string().as_bytes());

    // Then hmac using <phrase> as key, and repeat...
    let mut hmac_buf = hmac_sha1(&data, phrase);

    let mut i = 1u64;
    while i < iterations {
        hmac_buf = hmac_sha1(&hmac_buf, phrase);
        i += 1;
    }

    // Now output...
    let mut output = MAGIC.to_vec();
    output.extend_from_slice(format!("{}$", iterations).as_bytes());
    output.extend_from_slice(salt);
    output.push(b'$');

    let to64 = |out: &mut Vec<u8>, mut v: u32| {
        for _ in 0..4 {
            out.push(ASCII64[(v & 0x3f) as usize]);
            v >>= 6;
        }
    };

    // Every 3 bytes of hash gives 24 bits which is 4 base64 chars
    for i in (0..17).step_by(3) {
        to64(&mut output, (hmac_buf[i] as u32) << 16 | (hmac_buf[i + 1] as u32) << 8 | hmac_buf[i + 2] as u32);
    }

    // Only 2 bytes left, so we pad with byte0
    to64(&mut output, (hmac_buf[18] as u32) << 16 | (hmac_buf[19] as u32) << 8 | hmac_buf[0] as u32);

    Some(output)
}

/// The quotation of crypt_sunmd5_rn() (its trailing NUL is hashed too).
const HAMLET_QUOTATION: &[u8] = b"To be, or not to be,--that is the question:--\n\
Whether 'tis nobler in the mind to suffer\n\
The slings and arrows of outrageous fortune\n\
Or to take arms against a sea of troubles,\n\
And by opposing end them?--To die,--to sleep,--\n\
No more; and by a sleep to say we end\n\
The heartache, and the thousand natural shocks\n\
That flesh is heir to,--'tis a consummation\n\
Devoutly to be wish'd. To die,--to sleep;--\n\
To sleep! perchance to dream:--ay, there's the rub;\n\
For in that sleep of death what dreams may come,\n\
When we have shuffled off this mortal coil,\n\
Must give us pause: there's the respect\n\
That makes calamity of so long life;\n\
For who would bear the whips and scorns of time,\n\
The oppressor's wrong, the proud man's contumely,\n\
The pangs of despis'd love, the law's delay,\n\
The insolence of office, and the spurns\n\
That patient merit of the unworthy takes,\n\
When he himself might his quietus make\n\
With a bare bodkin? who would these fardels bear,\n\
To grunt and sweat under a weary life,\n\
But that the dread of something after death,--\n\
The undiscover'd country, from whose bourn\n\
No traveller returns,--puzzles the will,\n\
And makes us rather bear those ills we have\n\
Than fly to others that we know not of?\n\
Thus conscience does make cowards of us all;\n\
And thus the native hue of resolution\n\
Is sicklied o'er with the pale cast of thought;\n\
And enterprises of great pith and moment,\n\
With this regard, their currents turn awry,\n\
And lose the name of action.--Soft you now!\n\
The fair Ophelia!--Nymph, in thy orisons\n\
Be all my sins remember'd.\n\0";

/// get_nth_bit()
fn get_nth_bit(digest: &[u8; 16], n: u32) -> bool {
    let byte = (n % 128) / 8;
    let bit = (n % 128) % 8;
    digest[byte as usize] & (1 << bit) != 0
}

/// muffet_coin_toss(): whether the round includes the quotation
fn muffet_coin_toss(prev_digest: &[u8; 16], round_count: u32) -> bool {
    let mut x = 0u32;
    let mut y = 0u32;

    for i in 0..8u32 {
        let a = prev_digest[((i + 0) % 16) as usize] as u32;
        let b = prev_digest[((i + 3) % 16) as usize] as u32;
        let r = a >> (b % 5);
        let mut v = prev_digest[(r % 16) as usize] as u32;
        if b & (1 << (a % 8)) != 0 {
            v /= 2;
        }
        x |= (get_nth_bit(prev_digest, v) as u32) << i;

        let a = prev_digest[((i + 8) % 16) as usize] as u32;
        let b = prev_digest[((i + 11) % 16) as usize] as u32;
        let r = a >> (b % 5);
        let mut v = prev_digest[(r % 16) as usize] as u32;
        if b & (1 << (a % 8)) != 0 {
            v /= 2;
        }
        y |= (get_nth_bit(prev_digest, v) as u32) << i;
    }

    if get_nth_bit(prev_digest, round_count) {
        x /= 2;
    }
    if get_nth_bit(prev_digest, round_count.wrapping_add(64)) {
        y /= 2;
    }

    get_nth_bit(prev_digest, x) ^ get_nth_bit(prev_digest, y)
}

/// crypt_sunmd5_rn(): "$md5" or "$md5,", an optional "rounds=N$", the salt
fn sunmd5(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    const SUNMD5_BARE_OUTPUT_LEN: usize = 22;
    const SUNMD5_MAX_ROUNDS: u64 = 0xffffffff;

    if !matches!(setting.get(4), Some(b'$' | b',')) {
        return None;
    }

    // For bug-compatibility with the original implementation, we allow
    // 'rounds=' to follow either '$md5,' or '$md5$'.
    let mut p = 5;
    let mut nrounds: u32 = 4096;

    if setting[p..].starts_with(b"rounds=") {
        p += 7;

        // Do not allow an explicit setting of zero additional rounds, nor
        // leading zeroes on the number of rounds.
        if !matches!(setting.get(p), Some(b'1'..=b'9')) {
            return None;
        }

        let (arounds, n) = decimal(&setting[p..]);
        let arounds = arounds.filter(|&r| r <= SUNMD5_MAX_ROUNDS)?;

        nrounds = nrounds.wrapping_add(arounds as u32);
        p += n;

        if setting.get(p) != Some(&b'$') {
            return None;
        }

        p += 1;
    }

    // p now points to the beginning of the actual salt.
    p += setting[p..].iter().take_while(|c| ASCII64.contains(c)).count();

    if p < setting.len() && setting[p] != b'$' {
        return None;
    }

    // For bug-compatibility with the original implementation, if p points
    // to a '$' and the following character is either another '$' or NUL,
    // the first '$' should be included in the salt.
    if setting.get(p) == Some(&b'$') && (setting.get(p + 1) == Some(&b'$') || p + 1 == setting.len()) {
        p += 1;
    }

    let saltlen = p;

    // Do we have enough space?
    if CRYPT_OUTPUT_SIZE < saltlen + SUNMD5_BARE_OUTPUT_LEN + 2 {
        return None;
    }

    // Initial round.
    let mut ctx = Md5::new();
    ctx.update(phrase);
    ctx.update(&setting[..saltlen]);
    let mut dg: [u8; 16] = ctx.finalize().into();

    // Stretching rounds.
    for i in 0..nrounds {
        let mut ctx = Md5::new();

        ctx.update(dg);

        if muffet_coin_toss(&dg, i) {
            ctx.update(HAMLET_QUOTATION);
        }

        ctx.update(i.to_string().as_bytes());

        dg = ctx.finalize().into();
    }

    let mut output = setting[..saltlen].to_vec();
    output.push(b'$');

    let mut write_itoa64 = |b0: u8, b1: u8, b2: u8, n: usize| {
        let mut value = b0 as u32 | (b1 as u32) << 8 | (b2 as u32) << 16;
        for _ in 0..n {
            output.push(ASCII64[(value & 0x3f) as usize]);
            value >>= 6;
        }
    };

    // This is the same permuted order used by BSD md5-crypt ($1$).
    write_itoa64(dg[12], dg[6], dg[0], 4);
    write_itoa64(dg[13], dg[7], dg[1], 4);
    write_itoa64(dg[14], dg[8], dg[2], 4);
    write_itoa64(dg[15], dg[9], dg[3], 4);
    write_itoa64(dg[5], dg[10], dg[4], 4);
    write_itoa64(dg[11], 0, 0, 2);

    Some(output)
}

/// MD4 (RFC 1320), for the NT hash.
fn md4(data: &[u8]) -> [u8; 16] {
    let mut h: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
    let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
    let hh = |x: u32, y: u32, z: u32| x ^ y ^ z;

    for block in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }

        let [mut a, mut b, mut c, mut d] = h;

        // round 1
        for &i in &[0, 4, 8, 12] {
            a = a.wrapping_add(f(b, c, d)).wrapping_add(x[i]).rotate_left(3);
            d = d.wrapping_add(f(a, b, c)).wrapping_add(x[i + 1]).rotate_left(7);
            c = c.wrapping_add(f(d, a, b)).wrapping_add(x[i + 2]).rotate_left(11);
            b = b.wrapping_add(f(c, d, a)).wrapping_add(x[i + 3]).rotate_left(19);
        }

        // round 2
        for &i in &[0, 1, 2, 3] {
            a = a.wrapping_add(g(b, c, d)).wrapping_add(x[i]).wrapping_add(0x5a827999).rotate_left(3);
            d = d.wrapping_add(g(a, b, c)).wrapping_add(x[i + 4]).wrapping_add(0x5a827999).rotate_left(5);
            c = c.wrapping_add(g(d, a, b)).wrapping_add(x[i + 8]).wrapping_add(0x5a827999).rotate_left(9);
            b = b.wrapping_add(g(c, d, a)).wrapping_add(x[i + 12]).wrapping_add(0x5a827999).rotate_left(13);
        }

        // round 3
        for &i in &[0, 2, 1, 3] {
            a = a.wrapping_add(hh(b, c, d)).wrapping_add(x[i]).wrapping_add(0x6ed9eba1).rotate_left(3);
            d = d.wrapping_add(hh(a, b, c)).wrapping_add(x[i + 8]).wrapping_add(0x6ed9eba1).rotate_left(9);
            c = c.wrapping_add(hh(d, a, b)).wrapping_add(x[i + 4]).wrapping_add(0x6ed9eba1).rotate_left(11);
            b = b.wrapping_add(hh(c, d, a)).wrapping_add(x[i + 12]).wrapping_add(0x6ed9eba1).rotate_left(15);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }

    let mut out = [0u8; 16];
    for (i, w) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// crypt_nt_rn(): "$3$$" and the MD4 of the phrase as UCS-2LE (each byte
/// a code point) in hex
fn nt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    if !setting.starts_with(b"$3$") {
        return None;
    }

    let unipw: Vec<u8> = phrase.iter().flat_map(|&c| [c, 0]).collect();

    let mut output = b"$3$$".to_vec();

    for b in md4(&unipw) {
        output.extend_from_slice(format!("{:02x}", b).as_bytes());
    }

    Some(output)
}

/// BF_itoa64 of crypt-bcrypt.c
const BF_ITOA64: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// BF_atoi64: the values of the characters from 0x20, 64 for invalid ones
const BF_ATOI64: [u8; 0x60] = [
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 0, 1, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 64, 64, 64, 64, 64, 64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 64, 64, 64, 64, 64, 64, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 64, 64, 64, 64, 64,
];

/// BF_safe_atoi64()
fn bf_atoi64(c: Option<&u8>) -> Option<u32> {
    let t = (*c? as u32).wrapping_sub(0x20);

    if t >= 0x60 {
        return None;
    }

    let v = BF_ATOI64[t as usize] as u32;

    if v > 63 {
        None
    } else {
        Some(v)
    }
}

/// BF_decode(): the 16 bytes of the 22 characters of the salt
fn bf_decode(src: &[u8]) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut d = 0;
    let mut s = 0;

    loop {
        let c1 = bf_atoi64(src.get(s))?;
        let c2 = bf_atoi64(src.get(s + 1))?;
        s += 2;
        out[d] = ((c1 << 2) | ((c2 & 0x30) >> 4)) as u8;
        d += 1;
        if d >= 16 {
            break;
        }

        let c3 = bf_atoi64(src.get(s))?;
        s += 1;
        out[d] = (((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)) as u8;
        d += 1;
        if d >= 16 {
            break;
        }

        let c4 = bf_atoi64(src.get(s))?;
        s += 1;
        out[d] = (((c3 & 0x03) << 6) | c4) as u8;
        d += 1;
        if d >= 16 {
            break;
        }
    }

    Some(out)
}

/// BF_encode()
fn bf_encode(out: &mut Vec<u8>, src: &[u8]) {
    let mut i = 0;

    while i < src.len() {
        let mut c1 = src[i] as usize;
        i += 1;
        out.push(BF_ITOA64[c1 >> 2]);
        c1 = (c1 & 0x03) << 4;
        if i >= src.len() {
            out.push(BF_ITOA64[c1]);
            break;
        }

        let c2 = src[i] as usize;
        i += 1;
        c1 |= c2 >> 4;
        out.push(BF_ITOA64[c1]);
        c1 = (c2 & 0x0f) << 2;
        if i >= src.len() {
            out.push(BF_ITOA64[c1]);
            break;
        }

        let c2 = src[i] as usize;
        i += 1;
        c1 |= c2 >> 6;
        out.push(BF_ITOA64[c1]);
        out.push(BF_ITOA64[c2 & 0x3f]);
    }
}

/// BF_set_key(): the expanded key (18 words) and the key words of the
/// initial state, as the bytes the blowfish crate takes.  flags: 1 for
/// the sign extension bug of $2x$, 2 for the countermeasure of $2a$
/// (bit 16 of the first word of the initial key flipped for the
/// passwords on which the correct and buggy algorithms collide).
fn bf_set_key(key: &[u8], flags: u8) -> ([u8; 72], [u8; 72]) {
    let bug = (flags & 1) as usize;
    let safety = ((flags & 2) as u32) << 15;

    let mut sign = 0u32;
    let mut diff = 0u32;

    let mut expanded = [0u32; 18];
    let mut ptr = 0;

    for word in expanded.iter_mut() {
        let mut tmp = [0u32; 2];

        for j in 0..4 {
            // the key is a C string: its NUL is used, then it restarts
            let c = key.get(ptr).copied().unwrap_or(0);

            tmp[0] = (tmp[0] << 8) | c as u32;
            tmp[1] = (tmp[1] << 8) | (c as i8 as i32 as u32);

            if j != 0 {
                sign |= tmp[1] & 0x80;
            }

            if c == 0 {
                ptr = 0;
            } else {
                ptr += 1;
            }
        }

        diff |= tmp[0] ^ tmp[1];

        *word = tmp[bug];
    }

    diff |= diff >> 16;
    diff &= 0xffff;
    diff += 0xffff;
    sign <<= 9;
    sign &= !diff & safety;

    let mut expanded_bytes = [0u8; 72];
    for (i, w) in expanded.iter().enumerate() {
        expanded_bytes[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }

    let mut initial_bytes = expanded_bytes;
    initial_bytes[..4].copy_from_slice(&(expanded[0] ^ sign).to_be_bytes());

    (expanded_bytes, initial_bytes)
}

/// BF_crypt(): min is the lowest iteration count accepted (16; 1 for the
/// self-test of BF_full_crypt())
fn bf_crypt(key: &[u8], setting: &[u8], min: u32) -> Option<Vec<u8>> {
    let s = |i: usize| setting.get(i).copied().unwrap_or(0);

    // flags_by_subtype
    let flags = match s(2) {
        b'a' => 2,
        b'b' => 4,
        b'x' => 1,
        b'y' => 4,
        _ => 0,
    };

    if s(0) != b'$'
        || s(1) != b'2'
        || flags == 0
        || s(3) != b'$'
        || !(b'0'..=b'3').contains(&s(4))
        || !s(5).is_ascii_digit()
        || (s(4) == b'3' && s(5) > b'1')
        || s(6) != b'$'
    {
        return None;
    }

    let count = 1u32 << ((s(4) - b'0') as u32 * 10 + (s(5) - b'0') as u32);

    if count < min {
        return None;
    }

    let salt = bf_decode(&setting[7..])?;

    let (expanded, initial) = bf_set_key(key, flags);

    let mut state = blowfish::Blowfish::bc_init_state();

    state.salted_expand_key(&salt, &initial);

    for _ in 0..count {
        state.bc_expand_key(&expanded);
        state.bc_expand_key(&salt);
    }

    // "OrpheanBeholderScryDoubt"
    const BF_MAGIC_W: [u32; 6] = [0x4F727068, 0x65616E42, 0x65686F6C, 0x64657253, 0x63727944, 0x6F756274];

    let mut out = [0u8; 24];

    for i in (0..6).step_by(2) {
        let (mut l, mut r) = (BF_MAGIC_W[i], BF_MAGIC_W[i + 1]);

        for _ in 0..64 {
            (l, r) = state.bc_encrypt(l, r);
        }

        out[4 * i..4 * i + 4].copy_from_slice(&l.to_be_bytes());
        out[4 * i + 4..4 * i + 8].copy_from_slice(&r.to_be_bytes());
    }

    // the setting with the last salt character made canonical
    let mut output = setting[..28].to_vec();
    output.push(BF_ITOA64[(BF_ATOI64[(setting[28] - 0x20) as usize] & 0x30) as usize]);

    // This has to be bug-compatible with the original implementation, so
    // only encode 23 of the 24 bytes. :-)
    bf_encode(&mut output, &out[..23]);

    Some(output)
}

/// crypt_bcrypt_rn() and its $2a$, $2x$, $2y$ variants (BF_full_crypt():
/// its self-test always passes here)
fn bcrypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    bf_crypt(phrase, setting, 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apr1_basic() {
        let key = b"test";
        let salt = b"$apr1$abcdefgh$";
        let result = crypt(key, salt).unwrap();
        assert!(result.starts_with(b"$apr1$abcdefgh$"));
        // Result should be reproducible
        let result2 = crypt(key, salt).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_apr1_known_vector() {
        // Test with a known APR1 vector
        let key = b"test";
        let salt = b"$apr1$salt1234$";
        let result = crypt(key, salt).unwrap();
        // The result should be deterministic
        assert!(result.starts_with(b"$apr1$salt1234$"));
        assert!(result.len() > 14); // $apr1$salt1234$ + encoded hash
    }

    #[test]
    fn test_apr1_openssl_vector() {
        // openssl passwd -apr1 -salt salt password
        let key = b"password";
        let salt = b"$apr1$salt$Xxd1irWT9ycqoYxGFn4cb.";
        let result = crypt(key, salt).unwrap();
        assert_eq!(&result[..], b"$apr1$salt$Xxd1irWT9ycqoYxGFn4cb." as &[u8]);
    }

    #[test]
    fn test_plain() {
        let key = b"mypassword";
        let result = crypt(key, b"{PLAIN}").unwrap();
        assert_eq!(result, b"{PLAIN}mypassword");
    }

    #[test]
    fn test_sha() {
        let key = b"test";
        let result = crypt(key, b"{SHA}").unwrap();
        assert!(result.starts_with(b"{SHA}"));
        // SHA1("test") in base64 = "qUqP5cyxm6YcTAhz05Hph5gvu9M="
        assert_eq!(result, b"{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=");
    }

    #[test]
    fn test_ssha() {
        // {SSHA} test with a known salt
        let key = b"test";
        let salt = b"{SSHA}qUqP5cyxm6YcTAhz05Hph5gvu9Mtest";
        let result = crypt(key, salt).unwrap();
        assert!(result.starts_with(b"{SSHA}"));
    }

    #[test]
    fn test_ssha_no_salt() {
        // as ngx_crypt_ssha: no salt when the value is empty, does not
        // decode or is shorter than the digest
        let sha = crypt(b"test", b"{SHA}").unwrap();
        let expected = [&b"{SSHA}"[..], &sha[5..]].concat();
        assert_eq!(crypt(b"test", b"{SSHA}").unwrap(), expected);
        assert_eq!(crypt(b"test", b"{SSHA}_____wQadOA1e+/f+T+H3eCQQhRzYWx0").unwrap(), expected);
        assert_eq!(crypt(b"test", b"{SSHA}Zm9vCg==").unwrap(), expected);
        assert_eq!(crypt(b"password", b"{SSHA}yI6cZwQadOA1e+/f+T+H3eCQQhRzYWx0").unwrap(), b"{SSHA}yI6cZwQadOA1e+/f+T+H3eCQQhRzYWx0");
    }

    #[test]
    fn test_base64_encode_decode() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_crypt_to64() {
        let result = crypt_to64(0x00, 2);
        assert_eq!(result, b"..");
    }

    #[test]
    fn test_crypt_to64_nonzero() {
        let result = crypt_to64(0x3f, 1);
        assert_eq!(result, b"z");
    }

    fn c(key: &[u8], salt: &[u8]) -> String {
        String::from_utf8(crypt(key, salt).unwrap()).unwrap()
    }

    /// crypt_r() of libxcrypt 4.4.27 (Ubuntu 22.04) gave these
    #[test]
    fn crypt_r_of_libxcrypt() {
        assert_eq!(c(b"password", b"$1$"), "$1$$I2o9Z7NcvQAKp7wyCTlia0");
        assert_eq!(c(b"password", b"$1$salt$"), "$1$salt$qJH7.N4xYta3aEG/dfqo/0");
        assert_eq!(c(b"password", b"$1$salt"), "$1$salt$qJH7.N4xYta3aEG/dfqo/0");
        assert_eq!(c(b"password", b"$1$saltsaltsalt$x"), "$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/");
        assert_eq!(c(b"pw", b"$1$a#b-c$"), "$1$a#b-c$g.3cBg2p2sgvlOGXN6FvZ0");

        assert_eq!(c(b"password", b"$5$"), "$5$$V0edGK/GfSrNwzYCrbML4V/gvkNuNTfvn.Pt/LMSAf8");
        assert_eq!(c(b"password", b"$5$rounds=1000$salt$"), "$5$rounds=1000$salt$p.wiWs2zrZ7irikO2AL64QDIJo00A3KDq2xWHpLJGgB");
        assert_eq!(c(b"password", b"$5$rounds=999$salt$"), "*0");
        assert_eq!(c(b"password", b"$5$rounds=01000$salt$"), "*0");
        assert_eq!(c(b"password", b"$5$rounds=5000$salt$"), "$5$rounds=5000$salt$Gcm6FsVtF/Qa77ZKD.iwsJlCVPY0XSMgLJL0Hnww/c1");
        assert_eq!(
            c(b"password", b"$6$saltsaltsaltsaltsalt$"),
            "$6$saltsaltsaltsalt$bcXJ8qxwY5sQ4v8MTl.0B1jeZ0z0JlA9jjmbUoCJZ.1wYXiLTU.q2ILyrDJLm890lyfuF7sWAeli0yjOyFPkf0"
        );

        assert_eq!(c(b"password", b"ab"), "abJnggxhB/yWI");
        assert_eq!(c(b"password", b"a"), "*0");
        assert_eq!(c(b"password", b""), "*0");
        assert_eq!(c(b"password", b"!!"), "*0");
        assert_eq!(c(b"password", b"*0"), "*1");
        assert_eq!(c(b"password", b"*0xx"), "*1");
        assert_eq!(c(b"test", b"aZGJuE6EXrjEE"), "aZGJuE6EXrjEE");
        assert_eq!(c(b"longpasswordlongpassword", b"ab01234567890"), "abD6HAB6eqg.k");
        assert_eq!(c(b"longpasswordlongpassword", b"ab012345678901"), "abD6HAB6eqg.kwFCSNNOJrysP/XpYbqUI.2");
        assert_eq!(c(&[b'x'; 511], b"ab"), "abzDJoqKYZJww");
        assert_eq!(c(&[b'x'; 512], b"ab"), "*0");

        assert_eq!(c(b"password", b"$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe"), "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe");
        assert_eq!(c(b"password", b"$2y$03$bvIG6Nmid91Mu9RcmmWZfO"), "*0");
        assert_eq!(c(b"password", b"$2x$05$bvIG6Nmid91Mu9RcmmWZfO"), "$2x$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe");
        assert_eq!(c(b"password", b"$2a$05$bvIG6Nmid91Mu9RcmmWZf"), "*0");

        assert_eq!(c(b"password", b"$3$"), "$3$$8846f7eaee8fb117ad06bdd830b7586c");
        assert_eq!(c(b"password", b"$md5$salt$"), "$md5$salt$$wzeAbcD.IeWmdgZ1DkhxH/");
        assert_eq!(c(b"password", b"$sha1$1000$salt$"), "$sha1$1000$salt$91xEa0TCSk6jnl996QgXUA8913Xy");
        assert_eq!(c(b"password", b"_J9..salt"), "_J9..saltJW8FtKdEkNM");
        assert_eq!(c(b"password", b"_J9..sal"), "*0");

        assert_eq!(c(b"pw", b"$1$sa lt"), "*0");
        assert_eq!(c(b"pw", b"$9$x"), "*0");
        assert_eq!(c(b"pw", b"a\xe9"), "*0");

        assert_eq!(c(b"password", b"$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7"), "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$tnSYvahCwPBHKZUspmcxMfb0.WiB9W.zEaKlOBL35rC");
        assert_eq!(c(b"password", b"$7$CU..../....abc$"), "$7$CU..../....abc$aq9nTbuadDKl/OmAH9ktvpXiAjiuBYpB578rVYQ/6K/");
    }

    /// The self-tests of BF_full_crypt()
    #[test]
    fn bcrypt_self_test() {
        let key = b"8b \xd0\xc1\xd2\xcf\xcc\xd8";

        for (subtype, hash) in [(b'a', "i1D709vfamulimlGcq0qq3UvuUasvEa"), (b'b', "i1D709vfamulimlGcq0qq3UvuUasvEa"), (b'y', "i1D709vfamulimlGcq0qq3UvuUasvEa"), (b'x', "VUrPmXD6q/nVSSp7pNDhCR9071IfIRe")] {
            let mut setting = b"$2a$00$abcdefghijklmnopqrstuu".to_vec();
            setting[2] = subtype;

            let out = bf_crypt(key, &setting, 1).unwrap();
            assert_eq!(&out[..29], &setting[..]);
            assert_eq!(&out[29..], hash.as_bytes());
        }

        // the key-expansion "safety" logic
        let k = b"\xff\xa3\x33\x34\xff\xff\xff\xa3\x33\x34\x35";
        let (ae, mut ai) = bf_set_key(k, 2);
        let (ye, yi) = bf_set_key(k, 4);

        // undo the safety (for comparison)
        ai[1] ^= 0x01;

        let word = |b: &[u8; 72], i: usize| u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);

        assert_eq!(word(&ai, 0) ^ blowfish_p0(), 0xdb9c59bc);
        assert_eq!(word(&ye, 17), 0x33343500);
        assert_eq!(ae, ye);
        assert_eq!(ai, yi);
    }

    /// P[0] of the initial state of Blowfish (the digits of pi):
    /// initial[0] of BF_set_key() is P[0] ^ key word 0
    fn blowfish_p0() -> u32 {
        0x243f6a88
    }

    #[test]
    fn md4_vectors() {
        // RFC 1320
        let hex = |d: [u8; 16]| d.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(hex(md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex(md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(hex(md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")), "e33b4ddc9c38f2199c3e7b164fcc0536");
    }

    /// The cases of a file (hex phrase, hex setting per line), hashed into
    /// another, to compare with crypt_r() (a differential test, run by
    /// hand: CRYPT_DIFF_IN, CRYPT_DIFF_OUT).
    #[test]
    #[ignore]
    fn differential() {
        let input = std::fs::read_to_string(std::env::var("CRYPT_DIFF_IN").unwrap()).unwrap();
        let unhex = |s: &str| (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>();

        let mut out = Vec::new();

        for line in input.lines() {
            let (p, s) = line.split_once(' ').unwrap();
            out.extend_from_slice(&crypt_r(c_str(&unhex(p)), c_str(&unhex(s))));
            out.push(b'\n');
        }

        std::fs::write(std::env::var("CRYPT_DIFF_OUT").unwrap(), out).unwrap();
    }
}
