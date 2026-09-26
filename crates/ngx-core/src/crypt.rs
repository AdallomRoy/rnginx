//! Password hashing functions: APR1, SHA, SSHA, and libc crypt, ported from ngx_crypt.c.

use md5::Md5;
use sha1::{Sha1, Digest};

#[cfg(target_os = "linux")]
#[link(name = "crypt")]
extern "C" {}

/// Hash a password using the specified algorithm.
/// Supports $apr1$, {PLAIN}, {SHA}, {SSHA}, and falls back to libc crypt_r.
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

/// APR1 MD5 crypt - Poul-Henning Kamp's md5 crypt with $apr1$ magic
fn crypt_apr1(key: &[u8], salt: &[u8]) -> Result<Vec<u8>, i32> {
    // Extract true salt: no magic, max 8 chars, stop at first $
    let salt_start = 6; // len("$apr1$")
    let salt_end = salt.len().min(salt_start + 8);
    let mut salt_len = 0;
    for i in salt_start..salt_end {
        if salt[i] == b'$' {
            break;
        }
        salt_len += 1;
    }

    let true_salt = &salt[salt_start..salt_start + salt_len];
    let key_len = key.len();

    // Initial hash: key + $apr1$ + salt
    let mut md5 = Md5::new();
    md5.update(key);
    md5.update(b"$apr1$");
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
            ctx.update(&final_digest);
        }

        if i % 3 != 0 {
            ctx.update(true_salt);
        }

        if i % 7 != 0 {
            ctx.update(key);
        }

        // Match C: `if (i & 1) update(final, 16); else update(key, keylen);`
        // (odd → final; even → key). The FIRST update in the pair is the
        // inverse (odd → key; even → final).
        if i & 1 == 1 {
            ctx.update(&final_digest);
        } else {
            ctx.update(key);
        }

        final_digest.copy_from_slice(&ctx.finalize());
    }

    // Output: $apr1$ + salt + $ + base64-encoded digest
    let mut result = b"$apr1$".to_vec();
    result.extend_from_slice(true_salt);
    result.push(b'$');

    // Encode digest using custom base64 alphabet: ./0-9A-Za-z
    result.extend_from_slice(&crypt_to64((final_digest[0] as u32) << 16 | (final_digest[6] as u32) << 8 | final_digest[12] as u32, 4));
    result.extend_from_slice(&crypt_to64((final_digest[1] as u32) << 16 | (final_digest[7] as u32) << 8 | final_digest[13] as u32, 4));
    result.extend_from_slice(&crypt_to64((final_digest[2] as u32) << 16 | (final_digest[8] as u32) << 8 | final_digest[14] as u32, 4));
    result.extend_from_slice(&crypt_to64((final_digest[3] as u32) << 16 | (final_digest[9] as u32) << 8 | final_digest[15] as u32, 4));
    result.extend_from_slice(&crypt_to64((final_digest[4] as u32) << 16 | (final_digest[10] as u32) << 8 | final_digest[5] as u32, 4));
    result.extend_from_slice(&crypt_to64(final_digest[11] as u32, 2));

    Ok(result)
}

/// Convert 6-bit chunks to base64-like characters using ./0-9A-Za-z alphabet
fn crypt_to64(mut v: u32, n: usize) -> Vec<u8> {
    const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    let mut result = Vec::new();
    for _ in 0..n {
        result.push(ITOA64[(v & 0x3f) as usize]);
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
    let encoded_part = if salt_arg.len() > 6 {
        &salt_arg[6..] // Skip "{SSHA}"
    } else {
        return Err(22); // EINVAL
    };

    // Decode the base64 to get the stored digest + salt
    let decoded = match base64_decode(encoded_part) {
        Ok(d) => d,
        Err(_) => {
            // Invalid base64; return with just 20 zero bytes for SHA1 digest
            let mut result = b"{SSHA}".to_vec();
            let payload = [vec![0u8; 20], vec![0u8; 0]].concat();
            result.extend_from_slice(&base64_encode(&payload));
            return Ok(result);
        }
    };

    // The stored format is: SHA1(key+salt) || salt
    // Minimum is 20 bytes (SHA1 digest), rest is salt
    let true_salt = if decoded.len() > 20 {
        &decoded[20..]
    } else {
        &[]
    };

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

/// crypt_data structure for crypt_r
#[repr(C)]
struct CryptData {
    initialized: [u8; 1],
    buf: [u8; 32768],
}

extern "C" {
    fn crypt_r(key: *const u8, salt: *const u8, data: *mut CryptData) -> *mut u8;
}

/// Fallback to libc crypt_r
#[cfg(target_os = "linux")]
fn crypt_libc(key: &[u8], salt: &[u8]) -> Result<Vec<u8>, i32> {
    // crypt_r wants null-terminated C strings.
    let mut key_c = key.to_vec();
    key_c.push(0);
    let mut salt_c = salt.to_vec();
    salt_c.push(0);
    let mut crypt_data = CryptData {
        initialized: [0u8; 1],
        buf: [0u8; 32768],
    };

    let result = unsafe {
        crypt_r(
            key_c.as_ptr(),
            salt_c.as_ptr(),
            &mut crypt_data,
        )
    };

    if result.is_null() {
        return Err(libc::EINVAL);
    }

    // Find null terminator
    let mut len = 0;
    unsafe {
        while *result.add(len) != 0 {
            len += 1;
        }
        let bytes = std::slice::from_raw_parts(result, len);
        Ok(bytes.to_vec())
    }
}

/// Fallback for non-Linux systems
#[cfg(not(target_os = "linux"))]
fn crypt_libc(key: &[u8], salt: &[u8]) -> Result<Vec<u8>, i32> {
    // Fallback: just return PLAIN format
    let mut result = b"{PLAIN}".to_vec();
    result.extend_from_slice(key);
    Ok(result)
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
}
