//! ngx_event_quic_protection.c: packet protection (RFC 9001): the keys of
//! the encryption levels, AEAD, header protection, the Retry integrity tag
//! and the key update.

use std::os::raw::c_int;
use std::rc::Rc;

use crate::connection::Connection;
use crate::event_openssl::{explicit_memzero, ngx_ssl_error};
use crate::log::*;
use crate::openssl_ffi::*;
use crate::rc::*;
use crate::{ngx_log_debug, ngx_log_error};

use super::transport::*;
use super::{NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_ENCRYPTION_LAST};

/* RFC 5116, 5.1/5.3 and RFC 8439, 2.3/2.5 for all supported ciphers */
pub const NGX_QUIC_IV_LEN: usize = 12;
pub const NGX_QUIC_TAG_LEN: usize = 16;

/* largest hash used in TLS is SHA-384 */
pub const NGX_QUIC_MAX_MD_SIZE: usize = 48;

/* RFC 9001, 5.4.1.  Header Protection Application: 5-byte mask */
const NGX_QUIC_HP_LEN: usize = 5;

const NGX_QUIC_AES_128_KEY_LEN: usize = 16;

const NGX_QUIC_INITIAL_CIPHER: u32 = TLS1_3_CK_AES_128_GCM_SHA256;

const SHA256_DIGEST_LENGTH: usize = 32;

/// An EVP_CIPHER_CTX (ngx_quic_crypto_ctx_t), freed when dropped.
pub struct CipherCtx(*mut EVP_CIPHER_CTX);

impl CipherCtx {
    /// EVP_CIPHER_CTX_new()
    pub fn new() -> Option<CipherCtx> {
        // SAFETY: a new context, owned by the value returned
        let ctx = unsafe { EVP_CIPHER_CTX_new() };

        if ctx.is_null() {
            return None;
        }

        Some(CipherCtx(ctx))
    }

    pub fn as_ptr(&self) -> *mut EVP_CIPHER_CTX {
        self.0
    }
}

impl Drop for CipherCtx {
    fn drop(&mut self) {
        // SAFETY: the context was made by EVP_CIPHER_CTX_new() and is owned
        unsafe { EVP_CIPHER_CTX_free(self.0) }
    }
}

impl std::fmt::Debug for CipherCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CipherCtx({:p})", self.0)
    }
}

/// ngx_quic_md_t
#[derive(Clone, Copy, Debug)]
pub struct QuicMd {
    pub len: usize,
    pub data: [u8; NGX_QUIC_MAX_MD_SIZE],
}

impl Default for QuicMd {
    fn default() -> Self {
        QuicMd { len: 0, data: [0; NGX_QUIC_MAX_MD_SIZE] }
    }
}

impl QuicMd {
    pub fn from(data: &[u8]) -> QuicMd {
        let mut md = QuicMd { len: data.len(), ..Default::default() };
        md.data[..data.len()].copy_from_slice(data);
        md
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// ngx_quic_iv_t
#[derive(Clone, Copy, Default, Debug)]
pub struct QuicIv {
    pub len: usize,
    pub data: [u8; NGX_QUIC_IV_LEN],
}

/// ngx_quic_secret_t. The header protection context is shared by the
/// current and the next keys of the application level (the key update
/// keeps the header protection keys).
#[derive(Default, Debug)]
pub struct QuicSecret {
    pub secret: QuicMd,
    pub iv: QuicIv,
    pub hp: QuicMd,
    pub ctx: Option<CipherCtx>,
    pub hp_ctx: Option<Rc<CipherCtx>>,
}

/// ngx_quic_secrets_t
#[derive(Default, Debug)]
pub struct QuicSecrets {
    pub client: QuicSecret,
    pub server: QuicSecret,
}

/// ngx_quic_keys_t
#[derive(Default, Debug)]
pub struct QuicKeys {
    pub secrets: [QuicSecrets; NGX_QUIC_ENCRYPTION_LAST],
    pub next_key: QuicSecrets,
    pub cipher: u32,
}

/// ngx_quic_ciphers_t
pub struct QuicCiphers {
    pub c: *const EVP_CIPHER,
    pub hp: *const EVP_CIPHER,
    pub d: *const EVP_MD,
}

/// ngx_quic_ciphers: the ciphers of a TLS 1.3 cipher suite; the key
/// length, or NGX_ERROR
pub fn ngx_quic_ciphers(id: u32, ciphers: &mut QuicCiphers) -> i64 {
    // SAFETY: the EVP_*() functions return static objects
    unsafe {
        match id {
            TLS1_3_CK_AES_128_GCM_SHA256 => {
                ciphers.c = EVP_aes_128_gcm();
                ciphers.hp = EVP_aes_128_ctr();
                ciphers.d = EVP_sha256();
                16
            }

            TLS1_3_CK_AES_256_GCM_SHA384 => {
                ciphers.c = EVP_aes_256_gcm();
                ciphers.hp = EVP_aes_256_ctr();
                ciphers.d = EVP_sha384();
                32
            }

            TLS1_3_CK_CHACHA20_POLY1305_SHA256 => {
                ciphers.c = EVP_chacha20_poly1305();
                ciphers.hp = EVP_chacha20();
                ciphers.d = EVP_sha256();
                32
            }

            TLS1_3_CK_AES_128_CCM_SHA256 => {
                ciphers.c = EVP_aes_128_ccm();
                ciphers.hp = EVP_aes_128_ctr();
                ciphers.d = EVP_sha256();
                16
            }

            _ => NGX_ERROR,
        }
    }
}

fn new_ciphers() -> QuicCiphers {
    QuicCiphers { c: std::ptr::null(), hp: std::ptr::null(), d: std::ptr::null() }
}

/// ngx_quic_keys_set_initial_secret
pub fn ngx_quic_keys_set_initial_secret(keys: &mut QuicKeys, secret: &[u8], log: &Log) -> i64 {
    static SALT: [u8; 20] = [0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];

    // RFC 9001, section 5.  Packet Protection
    //
    // Initial packets use AEAD_AES_128_GCM.  The hash function
    // for HKDF when deriving initial secrets and keys is SHA-256.

    // SAFETY: a static object
    let digest = unsafe { EVP_sha256() };
    let mut is = [0u8; SHA256_DIGEST_LENGTH];
    let mut is_len = SHA256_DIGEST_LENGTH;

    if ngx_hkdf_extract(&mut is, &mut is_len, digest, secret, &SALT) != NGX_OK {
        return NGX_ERROR;
    }

    let iss = &is[..is_len];

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic ngx_quic_set_initial_secret");

    let initial = &mut keys.secrets[super::NGX_QUIC_ENCRYPTION_INITIAL];

    let client = &mut initial.client;

    client.secret.len = SHA256_DIGEST_LENGTH;
    client.hp.len = NGX_QUIC_AES_128_KEY_LEN;
    client.iv.len = NGX_QUIC_IV_LEN;

    let mut client_key = QuicMd { len: NGX_QUIC_AES_128_KEY_LEN, ..Default::default() };
    let mut server_key = QuicMd { len: NGX_QUIC_AES_128_KEY_LEN, ..Default::default() };

    /* labels per RFC 9001, 5.1. Packet Protection Keys */
    let len = client.secret.len;
    if ngx_quic_hkdf_expand(&mut client.secret.data[..len], b"tls13 client in", iss, digest, log) != NGX_OK {
        return NGX_ERROR;
    }

    let csecret = client.secret;

    if ngx_quic_hkdf_expand(&mut client_key.data[..NGX_QUIC_AES_128_KEY_LEN], b"tls13 quic key", csecret.as_slice(), digest, log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_hkdf_expand(&mut client.iv.data, b"tls13 quic iv", csecret.as_slice(), digest, log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_hkdf_expand(&mut client.hp.data[..NGX_QUIC_AES_128_KEY_LEN], b"tls13 quic hp", csecret.as_slice(), digest, log) != NGX_OK {
        return NGX_ERROR;
    }

    let server = &mut initial.server;

    server.secret.len = SHA256_DIGEST_LENGTH;
    server.hp.len = NGX_QUIC_AES_128_KEY_LEN;
    server.iv.len = NGX_QUIC_IV_LEN;

    let len = server.secret.len;
    if ngx_quic_hkdf_expand(&mut server.secret.data[..len], b"tls13 server in", iss, digest, log) != NGX_OK {
        return NGX_ERROR;
    }

    let ssecret = server.secret;

    if ngx_quic_hkdf_expand(&mut server_key.data[..NGX_QUIC_AES_128_KEY_LEN], b"tls13 quic key", ssecret.as_slice(), digest, log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_hkdf_expand(&mut server.iv.data, b"tls13 quic iv", ssecret.as_slice(), digest, log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_hkdf_expand(&mut server.hp.data[..NGX_QUIC_AES_128_KEY_LEN], b"tls13 quic hp", ssecret.as_slice(), digest, log) != NGX_OK {
        return NGX_ERROR;
    }

    let mut ciphers = new_ciphers();

    if ngx_quic_ciphers(NGX_QUIC_INITIAL_CIPHER, &mut ciphers) == NGX_ERROR {
        return NGX_ERROR;
    }

    let initial = &mut keys.secrets[super::NGX_QUIC_ENCRYPTION_INITIAL];

    if ngx_quic_crypto_init(ciphers.c, &mut initial.client, &client_key, 0, log) == NGX_ERROR {
        return NGX_ERROR;
    }

    if ngx_quic_crypto_init(ciphers.c, &mut initial.server, &server_key, 1, log) == NGX_ERROR
        || ngx_quic_crypto_hp_init(ciphers.hp, &mut initial.client, log) == NGX_ERROR
        || ngx_quic_crypto_hp_init(ciphers.hp, &mut initial.server, log) == NGX_ERROR
    {
        ngx_quic_keys_cleanup(keys);
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_hkdf_expand: HKDF-Expand-Label of `label` from `prk` into `out`
pub fn ngx_quic_hkdf_expand(out: &mut [u8], label: &[u8], prk: &[u8], digest: *const EVP_MD, log: &Log) -> i64 {
    let mut info = Vec::with_capacity(20);

    info.push(0);
    info.push(out.len() as u8);
    info.push(label.len() as u8);
    info.extend_from_slice(label);
    info.push(0);

    if ngx_hkdf_expand(out, digest, prk, &info) != NGX_OK {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("ngx_hkdf_expand({}) failed", String::from_utf8_lossy(label)));
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_hkdf_expand
fn ngx_hkdf_expand(out: &mut [u8], digest: *const EVP_MD, prk: &[u8], info: &[u8]) -> i64 {
    // SAFETY: the context is created, used and freed here; the buffers are
    // valid for the lengths passed
    unsafe {
        let pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, std::ptr::null_mut());
        if pctx.is_null() {
            return NGX_ERROR;
        }

        let mut out_len = out.len();

        let ok = EVP_PKEY_derive_init(pctx) > 0
            && EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0
            && EVP_PKEY_CTX_set_hkdf_md(pctx, digest) > 0
            && EVP_PKEY_CTX_set1_hkdf_key(pctx, prk.as_ptr(), prk.len() as c_int) > 0
            && EVP_PKEY_CTX_add1_hkdf_info(pctx, info.as_ptr(), info.len() as c_int) > 0
            && EVP_PKEY_derive(pctx, out.as_mut_ptr(), &mut out_len) > 0;

        EVP_PKEY_CTX_free(pctx);

        if ok {
            NGX_OK
        } else {
            NGX_ERROR
        }
    }
}

/// ngx_hkdf_extract
fn ngx_hkdf_extract(out: &mut [u8], out_len: &mut usize, digest: *const EVP_MD, secret: &[u8], salt: &[u8]) -> i64 {
    // SAFETY: as in ngx_hkdf_expand()
    unsafe {
        let pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, std::ptr::null_mut());
        if pctx.is_null() {
            return NGX_ERROR;
        }

        let ok = EVP_PKEY_derive_init(pctx) > 0
            && EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) > 0
            && EVP_PKEY_CTX_set_hkdf_md(pctx, digest) > 0
            && EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.as_ptr(), secret.len() as c_int) > 0
            && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.as_ptr(), salt.len() as c_int) > 0
            && EVP_PKEY_derive(pctx, out.as_mut_ptr(), out_len) > 0;

        EVP_PKEY_CTX_free(pctx);

        if ok {
            NGX_OK
        } else {
            NGX_ERROR
        }
    }
}

/// ngx_quic_crypto_init
pub fn ngx_quic_crypto_init(cipher: *const EVP_CIPHER, s: &mut QuicSecret, key: &QuicMd, enc: c_int, log: &Log) -> i64 {
    // SAFETY: the context is made here and freed on failure; the key is
    // valid for the cipher's key length
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CIPHER_CTX_new() failed"));
            return NGX_ERROR;
        }

        let ctx = CipherCtx(ctx);

        if EVP_CipherInit_ex(ctx.0, cipher, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), enc) != 1 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CipherInit_ex() failed"));
            return NGX_ERROR;
        }

        if EVP_CIPHER_get_mode(cipher) == EVP_CIPH_CCM_MODE && EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_TAG, NGX_QUIC_TAG_LEN as c_int, std::ptr::null_mut()) == 0 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG) failed"));
            return NGX_ERROR;
        }

        if EVP_CIPHER_CTX_ctrl(ctx.0, EVP_CTRL_AEAD_SET_IVLEN, s.iv.len as c_int, std::ptr::null_mut()) == 0 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_IVLEN) failed"));
            return NGX_ERROR;
        }

        if EVP_CipherInit_ex(ctx.0, std::ptr::null(), std::ptr::null_mut(), key.data.as_ptr(), std::ptr::null(), enc) != 1 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CipherInit_ex() failed"));
            return NGX_ERROR;
        }

        s.ctx = Some(ctx);
    }

    NGX_OK
}

/// ngx_quic_crypto_open: the decrypted `input` (with the tag) appended to
/// `out`
fn ngx_quic_crypto_open(s: &QuicSecret, out: &mut Vec<u8>, nonce: &[u8], input: &[u8], ad: &[u8], log: &Log) -> i64 {
    ngx_quic_crypto_common(s, out, nonce, input, ad, log)
}

/// ngx_quic_crypto_seal: the encrypted `input` and the tag appended to
/// `out`
pub fn ngx_quic_crypto_seal(s: &QuicSecret, out: &mut Vec<u8>, nonce: &[u8], input: &[u8], ad: &[u8], log: &Log) -> i64 {
    ngx_quic_crypto_common(s, out, nonce, input, ad, log)
}

/// ngx_quic_crypto_common
fn ngx_quic_crypto_common(s: &QuicSecret, out: &mut Vec<u8>, nonce: &[u8], input: &[u8], ad: &[u8], log: &Log) -> i64 {
    let ctx = match &s.ctx {
        Some(ctx) => ctx.0,
        None => return NGX_ERROR,
    };

    // SAFETY: the context is initialized; the buffers are valid for the
    // lengths passed, `out` has room for the input and the tag
    unsafe {
        let enc = EVP_CIPHER_CTX_is_encrypting(ctx);

        if EVP_CipherInit_ex(ctx, std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), nonce.as_ptr(), enc) != 1 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CipherInit_ex() failed"));
            return NGX_ERROR;
        }

        let mut input = input;

        if enc == 0 {
            if input.len() < NGX_QUIC_TAG_LEN {
                return NGX_ERROR;
            }

            let (data, tag) = input.split_at(input.len() - NGX_QUIC_TAG_LEN);
            input = data;

            if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, NGX_QUIC_TAG_LEN as c_int, tag.as_ptr() as *mut _) == 0 {
                ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG) failed"));
                return NGX_ERROR;
            }
        }

        let mut len: c_int = 0;

        if EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(ctx)) == EVP_CIPH_CCM_MODE && EVP_CipherUpdate(ctx, std::ptr::null_mut(), &mut len, std::ptr::null(), input.len() as c_int) != 1 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CipherUpdate() failed"));
            return NGX_ERROR;
        }

        if EVP_CipherUpdate(ctx, std::ptr::null_mut(), &mut len, ad.as_ptr(), ad.len() as c_int) != 1 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CipherUpdate() failed"));
            return NGX_ERROR;
        }

        let base = out.len();
        out.resize(base + input.len() + NGX_QUIC_TAG_LEN + 16, 0);

        if EVP_CipherUpdate(ctx, out.as_mut_ptr().add(base), &mut len, input.as_ptr(), input.len() as c_int) != 1 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CipherUpdate() failed"));
            out.truncate(base);
            return NGX_ERROR;
        }

        let mut olen = len as usize;

        if EVP_CipherFinal_ex(ctx, out.as_mut_ptr().add(base + olen), &mut len) <= 0 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CipherFinal_ex failed"));
            out.truncate(base);
            return NGX_ERROR;
        }

        olen += len as usize;

        if enc == 1 {
            if EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, NGX_QUIC_TAG_LEN as c_int, out.as_mut_ptr().add(base + olen) as *mut _) == 0 {
                ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_GET_TAG) failed"));
                out.truncate(base);
                return NGX_ERROR;
            }

            olen += NGX_QUIC_TAG_LEN;
        }

        out.truncate(base + olen);
    }

    NGX_OK
}

/// ngx_quic_crypto_cleanup
pub fn ngx_quic_crypto_cleanup(s: &mut QuicSecret) {
    s.ctx = None;
}

/// ngx_quic_crypto_hp_init
fn ngx_quic_crypto_hp_init(cipher: *const EVP_CIPHER, s: &mut QuicSecret, log: &Log) -> i64 {
    // SAFETY: the context is made here and freed on failure
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_CIPHER_CTX_new() failed"));
            return NGX_ERROR;
        }

        let ctx = CipherCtx(ctx);

        if EVP_EncryptInit_ex(ctx.0, cipher, std::ptr::null_mut(), s.hp.data.as_ptr(), std::ptr::null()) != 1 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_EncryptInit_ex() failed"));
            return NGX_ERROR;
        }

        s.hp_ctx = Some(Rc::new(ctx));
    }

    NGX_OK
}

/// ngx_quic_crypto_hp: the header protection mask of a sample
fn ngx_quic_crypto_hp(s: &QuicSecret, out: &mut [u8; 32], input: &[u8], log: &Log) -> i64 {
    static ZERO: [u8; NGX_QUIC_HP_LEN] = [0; NGX_QUIC_HP_LEN];

    let ctx = match &s.hp_ctx {
        Some(ctx) => ctx.0,
        None => return NGX_ERROR,
    };

    // SAFETY: the context is initialized; the sample is 16 bytes, the
    // output has room for the mask and a block
    unsafe {
        let mut outlen: c_int = 0;

        if EVP_EncryptInit_ex(ctx, std::ptr::null(), std::ptr::null_mut(), std::ptr::null(), input.as_ptr()) != 1 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_EncryptInit_ex() failed"));
            return NGX_ERROR;
        }

        if EVP_EncryptUpdate(ctx, out.as_mut_ptr(), &mut outlen, ZERO.as_ptr(), NGX_QUIC_HP_LEN as c_int) == 0 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_EncryptUpdate() failed"));
            return NGX_ERROR;
        }

        if EVP_EncryptFinal_ex(ctx, out.as_mut_ptr().add(NGX_QUIC_HP_LEN), &mut outlen) == 0 {
            ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("EVP_EncryptFinal_Ex() failed"));
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_quic_crypto_hp_cleanup
fn ngx_quic_crypto_hp_cleanup(s: &mut QuicSecret) {
    s.hp_ctx = None;
}

/// ngx_quic_keys_set_encryption_secret
pub fn ngx_quic_keys_set_encryption_secret(log: &Log, is_write: bool, keys: &mut QuicKeys, level: usize, cipher: *const SSL_CIPHER, secret: &[u8]) -> i64 {
    // SAFETY: the cipher is the current one of the SSL connection
    keys.cipher = unsafe { SSL_CIPHER_get_id(cipher) };

    let mut ciphers = new_ciphers();

    let key_len = ngx_quic_ciphers(keys.cipher, &mut ciphers);

    if key_len == NGX_ERROR {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("unexpected cipher"));
        return NGX_ERROR;
    }

    let peer_secret = if is_write { &mut keys.secrets[level].server } else { &mut keys.secrets[level].client };

    if peer_secret.secret.data.len() < secret.len() {
        ngx_log_error!(NGX_LOG_ALERT, log, None, "unexpected secret len: {}", secret.len());
        return NGX_ERROR;
    }

    peer_secret.secret.len = secret.len();
    peer_secret.secret.data[..secret.len()].copy_from_slice(secret);

    let mut key = QuicMd { len: key_len as usize, ..Default::default() };
    peer_secret.iv.len = NGX_QUIC_IV_LEN;
    peer_secret.hp.len = key_len as usize;

    if ngx_quic_hkdf_expand(&mut key.data[..key_len as usize], b"tls13 quic key", secret, ciphers.d, log) != NGX_OK
        || ngx_quic_hkdf_expand(&mut peer_secret.iv.data, b"tls13 quic iv", secret, ciphers.d, log) != NGX_OK
        || ngx_quic_hkdf_expand(&mut peer_secret.hp.data[..key_len as usize], b"tls13 quic hp", secret, ciphers.d, log) != NGX_OK
    {
        return NGX_ERROR;
    }

    if ngx_quic_crypto_init(ciphers.c, peer_secret, &key, is_write as c_int, log) == NGX_ERROR {
        return NGX_ERROR;
    }

    if ngx_quic_crypto_hp_init(ciphers.hp, peer_secret, log) == NGX_ERROR {
        return NGX_ERROR;
    }

    explicit_memzero(&mut key.data[..key.len]);

    NGX_OK
}

/// ngx_quic_keys_available
pub fn ngx_quic_keys_available(keys: &QuicKeys, level: usize, is_write: bool) -> bool {
    if !is_write {
        return keys.secrets[level].client.ctx.is_some();
    }

    keys.secrets[level].server.ctx.is_some()
}

/// ngx_quic_keys_discard
pub fn ngx_quic_keys_discard(keys: &mut QuicKeys, level: usize) {
    let secrets = &mut keys.secrets[level];

    ngx_quic_crypto_cleanup(&mut secrets.client);
    ngx_quic_crypto_cleanup(&mut secrets.server);

    ngx_quic_crypto_hp_cleanup(&mut secrets.client);
    ngx_quic_crypto_hp_cleanup(&mut secrets.server);

    for s in [&mut secrets.client, &mut secrets.server] {
        if s.secret.len != 0 {
            let len = s.secret.len;
            explicit_memzero(&mut s.secret.data[..len]);
            s.secret.len = 0;
        }
    }
}

/// ngx_quic_keys_switch
pub fn ngx_quic_keys_switch(_c: &Connection, keys: &mut QuicKeys) {
    let QuicKeys { secrets, next_key, .. } = keys;
    let current = &mut secrets[NGX_QUIC_ENCRYPTION_APPLICATION];

    ngx_quic_crypto_cleanup(&mut current.client);
    ngx_quic_crypto_cleanup(&mut current.server);

    std::mem::swap(current, next_key);
}

/// ngx_quic_keys_update: the key_update event handler, generating the next
/// keys
pub fn ngx_quic_keys_update(c: &Rc<Connection>) {
    let qc = match super::ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic key update");

    c.log.set_action(Some("updating keys"));

    let rc = keys_update_impl(&mut qc.keys.borrow_mut(), &c.log);

    if rc != NGX_OK {
        super::ngx_quic_close_connection(c, NGX_ERROR);
    }
}

/// The body of ngx_quic_keys_update: the next keys derived from the
/// current ones.
pub fn keys_update_impl(keys: &mut QuicKeys, log: &Log) -> i64 {
    let mut ciphers = new_ciphers();

    let key_len = ngx_quic_ciphers(keys.cipher, &mut ciphers);

    if key_len == NGX_ERROR {
        return NGX_ERROR;
    }

    let key_len = key_len as usize;

    let mut client_key = QuicMd { len: key_len, ..Default::default() };
    let mut server_key = QuicMd { len: key_len, ..Default::default() };

    let QuicKeys { secrets, next_key: next, .. } = keys;
    let current = &mut secrets[NGX_QUIC_ENCRYPTION_APPLICATION];

    next.client.secret.len = current.client.secret.len;
    next.client.iv.len = NGX_QUIC_IV_LEN;
    next.client.hp = current.client.hp;
    next.client.hp_ctx = current.client.hp_ctx.clone();

    next.server.secret.len = current.server.secret.len;
    next.server.iv.len = NGX_QUIC_IV_LEN;
    next.server.hp = current.server.hp;
    next.server.hp_ctx = current.server.hp_ctx.clone();

    let clen = next.client.secret.len;
    let slen = next.server.secret.len;

    if ngx_quic_hkdf_expand(&mut next.client.secret.data[..clen], b"tls13 quic ku", current.client.secret.as_slice(), ciphers.d, log) != NGX_OK {
        return NGX_ERROR;
    }

    let ncs = next.client.secret;

    if ngx_quic_hkdf_expand(&mut client_key.data[..key_len], b"tls13 quic key", ncs.as_slice(), ciphers.d, log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_hkdf_expand(&mut next.client.iv.data, b"tls13 quic iv", ncs.as_slice(), ciphers.d, log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_hkdf_expand(&mut next.server.secret.data[..slen], b"tls13 quic ku", current.server.secret.as_slice(), ciphers.d, log) != NGX_OK {
        return NGX_ERROR;
    }

    let nss = next.server.secret;

    if ngx_quic_hkdf_expand(&mut server_key.data[..key_len], b"tls13 quic key", nss.as_slice(), ciphers.d, log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_hkdf_expand(&mut next.server.iv.data, b"tls13 quic iv", nss.as_slice(), ciphers.d, log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_crypto_init(ciphers.c, &mut next.client, &client_key, 0, log) == NGX_ERROR {
        return NGX_ERROR;
    }

    if ngx_quic_crypto_init(ciphers.c, &mut next.server, &server_key, 1, log) == NGX_ERROR {
        return NGX_ERROR;
    }

    let len = current.client.secret.len;
    explicit_memzero(&mut current.client.secret.data[..len]);
    let len = current.server.secret.len;
    explicit_memzero(&mut current.server.secret.data[..len]);

    current.client.secret.len = 0;
    current.server.secret.len = 0;

    explicit_memzero(&mut client_key.data[..key_len]);
    explicit_memzero(&mut server_key.data[..key_len]);

    NGX_OK
}

/// ngx_quic_keys_cleanup
pub fn ngx_quic_keys_cleanup(keys: &mut QuicKeys) {
    for i in 0..NGX_QUIC_ENCRYPTION_LAST {
        ngx_quic_keys_discard(keys, i);
    }

    let next = &mut keys.next_key;

    ngx_quic_crypto_cleanup(&mut next.client);
    ngx_quic_crypto_cleanup(&mut next.server);

    for s in [&mut next.client, &mut next.server] {
        if s.secret.len != 0 {
            let len = s.secret.len;
            explicit_memzero(&mut s.secret.data[..len]);
            s.secret.len = 0;
        }
    }
}

/// ngx_quic_create_packet: the protected packet appended to `res`
fn ngx_quic_create_packet(pkt: &QuicHeader<'_>, keys: &QuicKeys, res: &mut Vec<u8>) -> i64 {
    let log = pkt.log();
    let base = res.len();

    let (ad_len, pnp) = ngx_quic_create_header(pkt, res);

    let secret = &keys.secrets[pkt.level].server;

    let mut nonce = [0u8; NGX_QUIC_IV_LEN];
    nonce[..secret.iv.len].copy_from_slice(&secret.iv.data[..secret.iv.len]);
    ngx_quic_compute_nonce(&mut nonce, pkt.number);

    let ad = res[base..base + ad_len].to_vec();

    if ngx_quic_crypto_seal(secret, res, &nonce, &pkt.payload, &ad, log) != NGX_OK {
        res.truncate(base);
        return NGX_ERROR;
    }

    let sample = base + ad_len + 4 - pkt.num_len as usize;
    let mut mask = [0u8; 32];

    if ngx_quic_crypto_hp(secret, &mut mask, &res[sample..sample + 16], log) != NGX_OK {
        res.truncate(base);
        return NGX_ERROR;
    }

    /* RFC 9001, 5.4.1.  Header Protection Application */
    res[base] ^= mask[0] & ngx_quic_pkt_hp_mask(pkt.flags);

    for i in 0..pkt.num_len as usize {
        res[base + pnp + i] ^= mask[i + 1];
    }

    NGX_OK
}

/// ngx_quic_create_retry_packet: the Retry packet appended to `res`
fn ngx_quic_create_retry_packet(pkt: &QuicHeader<'_>, res: &mut Vec<u8>) -> i64 {
    let log = pkt.log();

    /* 5.8.  Retry Packet Integrity */
    static KEY: [u8; 16] = [0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e];
    static NONCE: [u8; NGX_QUIC_IV_LEN] = [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];

    let mut ad = Vec::new();
    let (_, start) = ngx_quic_create_retry_itag(pkt, &mut ad);

    let mut ciphers = new_ciphers();

    if ngx_quic_ciphers(NGX_QUIC_INITIAL_CIPHER, &mut ciphers) == NGX_ERROR {
        return NGX_ERROR;
    }

    let mut secret = QuicSecret::default();
    secret.iv.len = NGX_QUIC_IV_LEN;

    let key = QuicMd::from(&KEY);

    if ngx_quic_crypto_init(ciphers.c, &mut secret, &key, 1, log) == NGX_ERROR {
        return NGX_ERROR;
    }

    let mut itag = Vec::new();

    if ngx_quic_crypto_seal(&secret, &mut itag, &NONCE, b"", &ad, log) != NGX_OK {
        ngx_quic_crypto_cleanup(&mut secret);
        return NGX_ERROR;
    }

    ngx_quic_crypto_cleanup(&mut secret);

    res.extend_from_slice(&ad[start..]);
    res.extend_from_slice(&itag);

    NGX_OK
}

/// ngx_quic_derive_key
pub fn ngx_quic_derive_key(log: &Log, label: &str, secret: &[u8], salt: &[u8], out: &mut [u8]) -> i64 {
    // SAFETY: a static object
    let digest = unsafe { EVP_sha256() };

    let mut is = [0u8; SHA256_DIGEST_LENGTH];
    let mut is_len = SHA256_DIGEST_LENGTH;

    if ngx_hkdf_extract(&mut is, &mut is_len, digest, secret, salt) != NGX_OK {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("ngx_hkdf_extract({}) failed", label));
        return NGX_ERROR;
    }

    let info_len = 2 + 1 + label.len() + 1;

    if info_len >= 20 {
        ngx_log_error!(NGX_LOG_INFO, log, None, "ngx_quic_create_key label \"{}\" too long", label);
        return NGX_ERROR;
    }

    let mut info = Vec::with_capacity(info_len);
    info.push(0);
    info.push(out.len() as u8);
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    info.push(0);

    if ngx_hkdf_expand(out, digest, &is[..is_len], &info) != NGX_OK {
        ngx_ssl_error(NGX_LOG_INFO, log, 0, format_args!("ngx_hkdf_expand({}) failed", label));
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_parse_pn
fn ngx_quic_parse_pn(buf: &[u8], pos: &mut usize, mut len: usize, mask: &[u8], largest_pn: &mut u64) -> u64 {
    let pn_nbits = (len as u64 * 8).min(62);

    let mut p = *pos;
    let mut m = 0usize;

    let mut truncated_pn = (buf[p] ^ mask[m]) as u64;
    p += 1;
    m += 1;

    while {
        len -= 1;
        len > 0
    } {
        truncated_pn = (truncated_pn << 8) + (buf[p] ^ mask[m]) as u64;
        p += 1;
        m += 1;
    }

    *pos = p;

    let expected_pn = largest_pn.wrapping_add(1);
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    let mut candidate_pn = (expected_pn & !pn_mask) | truncated_pn;

    if (candidate_pn as i64) <= (expected_pn.wrapping_sub(pn_hwin) as i64) && candidate_pn < (1u64 << 62) - pn_win {
        candidate_pn += pn_win;
    } else if candidate_pn > expected_pn.wrapping_add(pn_hwin) && candidate_pn >= pn_win {
        candidate_pn -= pn_win;
    }

    *largest_pn = (*largest_pn as i64).max(candidate_pn as i64) as u64;

    candidate_pn
}

/// ngx_quic_compute_nonce
pub fn ngx_quic_compute_nonce(nonce: &mut [u8], pn: u64) {
    let len = nonce.len();

    nonce[len - 8] ^= ((pn >> 56) & 0x3f) as u8;
    nonce[len - 7] ^= ((pn >> 48) & 0xff) as u8;
    nonce[len - 6] ^= ((pn >> 40) & 0xff) as u8;
    nonce[len - 5] ^= ((pn >> 32) & 0xff) as u8;
    nonce[len - 4] ^= ((pn >> 24) & 0xff) as u8;
    nonce[len - 3] ^= ((pn >> 16) & 0xff) as u8;
    nonce[len - 2] ^= ((pn >> 8) & 0xff) as u8;
    nonce[len - 1] ^= (pn & 0xff) as u8;
}

/// ngx_quic_encrypt: the packet (a Retry one, or protected with its keys)
/// appended to `res`
pub fn ngx_quic_encrypt(pkt: &QuicHeader<'_>, res: &mut Vec<u8>) -> i64 {
    if ngx_quic_pkt_retry(pkt.flags) {
        return ngx_quic_create_retry_packet(pkt, res);
    }

    let keys = match &pkt.keys {
        Some(k) => k.clone(),
        None => return NGX_ERROR,
    };

    let keys = keys.borrow();

    ngx_quic_create_packet(pkt, &keys, res)
}

/// ngx_quic_decrypt: the payload of the packet into pkt.payload
pub fn ngx_quic_decrypt(pkt: &mut QuicHeader<'_>, largest_pn: &mut u64) -> i64 {
    let log = pkt.log().clone();

    let keys = match &pkt.keys {
        Some(k) => k.clone(),
        None => return NGX_ERROR,
    };

    let keys = keys.borrow();

    let mut secret = &keys.secrets[pkt.level].client;

    let raw = pkt.raw;
    let mut p = pkt.raw_pos;
    let len = pkt.data + pkt.len - p;

    // RFC 9001, 5.4.2. Header Protection Sample
    //           5.4.3. AES-Based Header Protection
    //           5.4.4. ChaCha20-Based Header Protection
    //
    // the Packet Number field is assumed to be 4 bytes long
    // AES and ChaCha20 algorithms sample 16 bytes

    if len < NGX_QUIC_TAG_LEN + 4 {
        return NGX_DECLINED;
    }

    let sample = &raw[p + 4..p + 4 + 16];

    /* header protection */

    let mut mask = [0u8; 32];

    if ngx_quic_crypto_hp(secret, &mut mask, sample, &log) != NGX_OK {
        return NGX_DECLINED;
    }

    pkt.flags ^= mask[0] & ngx_quic_pkt_hp_mask(pkt.flags);

    if ngx_quic_short_pkt(pkt.flags) {
        let key_phase = pkt.flags & NGX_QUIC_PKT_KPHASE != 0;

        if key_phase != pkt.key_phase {
            if keys.next_key.client.ctx.is_some() {
                secret = &keys.next_key.client;
                pkt.key_update = true;
            } else {
                // RFC 9001,  6.3. Timing of Receive Key Generation.
                //
                // Trial decryption to avoid timing side-channel.
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic next key missing");
            }
        }
    }

    let mut lpn = *largest_pn;

    let mut pnl = ((pkt.flags & 0x03) + 1) as usize;
    let pn = ngx_quic_parse_pn(raw, &mut p, pnl, &mask[1..], &mut lpn);

    pkt.pn = pn;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic packet rx clearflags:{:x}", pkt.flags);
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, log, "quic packet rx number:{} len:{:x}", pn, pnl);

    /* packet protection */

    let input = &raw[p..p + len - pnl];

    let mut ad = raw[pkt.data..p].to_vec();
    ad[0] = pkt.flags;

    let ad_len = ad.len();

    loop {
        ad[ad_len - pnl] = (pn >> (8 * (pnl - 1))) as u8;

        pnl -= 1;
        if pnl == 0 {
            break;
        }
    }

    let mut nonce = [0u8; NGX_QUIC_IV_LEN];
    nonce[..secret.iv.len].copy_from_slice(&secret.iv.data[..secret.iv.len]);
    ngx_quic_compute_nonce(&mut nonce, pn);

    let mut payload = Vec::with_capacity(input.len());

    if ngx_quic_crypto_open(secret, &mut payload, &nonce, input, &ad, &log) != NGX_OK {
        return NGX_DECLINED;
    }

    pkt.payload = payload;

    if pkt.payload.is_empty() {
        // RFC 9000, 12.4.  Frames and Frame Types
        //
        // An endpoint MUST treat receipt of a packet containing no
        // frames as a connection error of type PROTOCOL_VIOLATION.
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic zero-length packet");
        pkt.error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        return NGX_ERROR;
    }

    if pkt.flags & ngx_quic_pkt_rb_mask(pkt.flags) != 0 {
        // RFC 9000, Reserved Bits
        //
        // An endpoint MUST treat receipt of a packet that has
        // a non-zero value for these bits, after removing both
        // packet and header protection, as a connection error
        // of type PROTOCOL_VIOLATION.
        ngx_log_error!(NGX_LOG_INFO, log, None, "quic reserved bit set in packet");
        pkt.error = NGX_QUIC_ERR_PROTOCOL_VIOLATION;
        return NGX_ERROR;
    }

    *largest_pn = lpn;

    NGX_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn log() -> Log {
        Log::stderr(0)
    }

    /// RFC 9001, A.1.  Keys
    #[test]
    fn initial_keys_as_rfc9001() {
        let mut keys = QuicKeys::default();
        let dcid = unhex("8394c8f03e515708");

        assert_eq!(ngx_quic_keys_set_initial_secret(&mut keys, &dcid, &log()), NGX_OK);

        let client = &keys.secrets[super::super::NGX_QUIC_ENCRYPTION_INITIAL].client;
        assert_eq!(client.secret.as_slice(), unhex("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea").as_slice());
        assert_eq!(&client.iv.data[..], unhex("fa044b2f42a3fd3b46fb255c").as_slice());
        assert_eq!(client.hp.as_slice(), unhex("9f50449e04a0e810283a1e9933adedd2").as_slice());

        let server = &keys.secrets[super::super::NGX_QUIC_ENCRYPTION_INITIAL].server;
        assert_eq!(server.secret.as_slice(), unhex("3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b").as_slice());
        assert_eq!(&server.iv.data[..], unhex("0ac1493ca1905853b0bba03e").as_slice());
        assert_eq!(server.hp.as_slice(), unhex("c206b8d9b9f0f37644430b490eeaa314").as_slice());

        assert!(ngx_quic_keys_available(&keys, 0, false));
        assert!(ngx_quic_keys_available(&keys, 0, true));

        ngx_quic_keys_cleanup(&mut keys);
        assert!(!ngx_quic_keys_available(&keys, 0, true));
    }

    /// RFC 9001, A.3.  Server Initial: the packet protected as in the RFC,
    /// and decrypted back
    #[test]
    fn server_initial_as_rfc9001() {
        let keys = Rc::new(std::cell::RefCell::new(QuicKeys::default()));
        let dcid = unhex("8394c8f03e515708");

        assert_eq!(ngx_quic_keys_set_initial_secret(&mut keys.borrow_mut(), &dcid, &log()), NGX_OK);

        let payload = unhex(
            "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739 88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94 0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304",
        );

        let pkt = QuicHeader {
            log: Some(log()),
            keys: Some(keys.clone()),
            flags: NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_INITIAL | 0x01,
            version: 1,
            level: super::super::NGX_QUIC_ENCRYPTION_INITIAL,
            dcid: vec![],
            scid: unhex("f067a5502a4262b5"),
            number: 1,
            num_len: 2,
            trunc: 1,
            payload,
            ..Default::default()
        };

        let mut res = Vec::new();
        assert_eq!(ngx_quic_encrypt(&pkt, &mut res), NGX_OK);

        let expected = unhex(
            "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a 5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3 dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84 022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4 2158407dd074ee",
        );

        assert_eq!(res, expected);

        // the server's packet read back with the server keys as the peer's
        let mut rkeys = QuicKeys::default();
        assert_eq!(ngx_quic_keys_set_initial_secret(&mut rkeys, &dcid, &log()), NGX_OK);
        {
            // the server's keys to decrypt with: RFC 9001, A.1 server key
            let init = &mut rkeys.secrets[super::super::NGX_QUIC_ENCRYPTION_INITIAL];
            std::mem::swap(&mut init.client, &mut init.server);

            let key = QuicMd::from(&unhex("cf3a5331653c364c88f0f379b6067e37"));
            // SAFETY: a static cipher
            let cipher = unsafe { EVP_aes_128_gcm() };
            assert_eq!(ngx_quic_crypto_init(cipher, &mut init.client, &key, 0, &log()), NGX_OK);
        }

        let mut rpkt = QuicHeader {
            log: Some(log()),
            keys: Some(Rc::new(std::cell::RefCell::new(rkeys))),
            raw: &res,
            raw_pos: 1,
            data: 0,
            len: res.len(),
            flags: res[0],
            ..Default::default()
        };

        rpkt.first = true;
        assert_eq!(ngx_quic_parse_packet(&mut rpkt), NGX_ERROR); // too small for an initial packet in a datagram

        rpkt.raw_pos = 1;
        rpkt.len = res.len();
        let mut pos = rpkt.raw_pos;
        let mut v = 0u32;
        pos = ngx_quic_read_uint32_pub(&res, pos, &mut v);
        let dlen = res[pos] as usize;
        pos += 1 + dlen;
        let slen = res[pos] as usize;
        pos += 1 + slen;
        let mut tl = 0u64;
        pos = ngx_quic_parse_int(&res, pos, res.len(), &mut tl).unwrap();
        pos += tl as usize;
        let mut plen = 0u64;
        pos = ngx_quic_parse_int(&res, pos, res.len(), &mut plen).unwrap();
        rpkt.raw_pos = pos;
        rpkt.len = pos + plen as usize;
        rpkt.level = super::super::NGX_QUIC_ENCRYPTION_INITIAL;

        let mut largest = u64::MAX;
        assert_eq!(ngx_quic_decrypt(&mut rpkt, &mut largest), NGX_OK);
        assert_eq!(rpkt.pn, 1);
        assert_eq!(largest, 1);
        assert_eq!(rpkt.payload, pkt.payload);
    }

    fn ngx_quic_read_uint32_pub(buf: &[u8], pos: usize, v: &mut u32) -> usize {
        *v = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        pos + 4
    }

    /// RFC 9001, A.4.  Retry
    #[test]
    fn retry_as_rfc9001() {
        let pkt = QuicHeader {
            log: Some(log()),
            flags: NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_RETRY | 0x0f,
            version: 1,
            odcid: unhex("8394c8f03e515708"),
            dcid: vec![],
            scid: unhex("f067a5502a4262b5"),
            token: b"token".to_vec(),
            ..Default::default()
        };

        let mut res = Vec::new();
        assert_eq!(ngx_quic_encrypt(&pkt, &mut res), NGX_OK);

        assert_eq!(res, unhex("ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f 0f2496ba"));
    }

    /// RFC 9001, A.5.  ChaCha20-Poly1305 Short Header Packet
    #[test]
    fn chacha20_short_header_as_rfc9001() {
        let secret = unhex("9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b");

        let mut keys = QuicKeys::default();

        // SAFETY: a cipher of the SSL library, looked up by its protocol id
        let cipher = unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            let ssl = SSL_new(ctx);
            let c = SSL_CIPHER_find(ssl, [0x13, 0x03].as_ptr());
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            c
        };

        assert!(!cipher.is_null());

        assert_eq!(ngx_quic_keys_set_encryption_secret(&log(), true, &mut keys, NGX_QUIC_ENCRYPTION_APPLICATION, cipher, &secret), NGX_OK);

        let s = &keys.secrets[NGX_QUIC_ENCRYPTION_APPLICATION].server;
        assert_eq!(&s.iv.data[..], unhex("e0459b3474bdd0e44a41c144").as_slice());
        assert_eq!(s.hp.as_slice(), unhex("25a282b9e82f06f21f488917a4fc8f1b 73573685608597d0efcb076b0ab7a7a4").as_slice());

        let pkt = QuicHeader {
            log: Some(log()),
            keys: Some(Rc::new(std::cell::RefCell::new(keys))),
            flags: 0x42,
            level: NGX_QUIC_ENCRYPTION_APPLICATION,
            dcid: vec![],
            number: 654360564,
            num_len: 3,
            trunc: 654360564 & 0xffffff,
            payload: vec![0x01],
            ..Default::default()
        };

        let mut res = Vec::new();
        assert_eq!(ngx_quic_encrypt(&pkt, &mut res), NGX_OK);
        assert_eq!(res, unhex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

        // the key update derives the next keys from these
        let mut keys = QuicKeys::default();
        assert_eq!(ngx_quic_keys_set_encryption_secret(&log(), true, &mut keys, NGX_QUIC_ENCRYPTION_APPLICATION, cipher, &secret), NGX_OK);
        assert_eq!(ngx_quic_keys_set_encryption_secret(&log(), false, &mut keys, NGX_QUIC_ENCRYPTION_APPLICATION, cipher, &secret), NGX_OK);
        assert_eq!(keys_update_impl(&mut keys, &log()), NGX_OK);
        assert!(keys.next_key.server.ctx.is_some());
        assert_eq!(keys.next_key.server.secret.as_slice(), unhex("1223504755036d556342ee9361d25342 1a826c9ecdf3c7148684b36b714881f9").as_slice());
    }

    #[test]
    fn packet_numbers_as_rfc9000() {
        // RFC 9000, A.3.  Sample Packet Number Decoding
        let mut largest = 0xa82f30ea;
        let mut pos = 0;
        let pn = ngx_quic_parse_pn(&[0x9b, 0x32], &mut pos, 2, &[0, 0], &mut largest);
        assert_eq!(pn, 0xa82f9b32);
        assert_eq!(largest, 0xa82f9b32);

        // the first packet
        let mut largest = u64::MAX;
        let mut pos = 0;
        assert_eq!(ngx_quic_parse_pn(&[0x00], &mut pos, 1, &[0], &mut largest), 0);
        assert_eq!(largest, 0);
    }
}
