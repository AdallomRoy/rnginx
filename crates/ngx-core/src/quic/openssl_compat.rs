//! ngx_event_quic_openssl_compat.c: QUIC over the TLS of OpenSSL, which
//! has no QUIC API (NGX_QUIC_OPENSSL_COMPAT).
//!
//! The traffic secrets come from the keylog callback, the transport
//! parameters in a custom extension; the handshake messages OpenSSL sends
//! are taken by the message callback, and those of the client are given to
//! OpenSSL as TLS records (encrypted with the client's handshake keys past
//! the Initial level) in a memory BIO.

use std::os::raw::c_int;

use ngx_sys::ssl as sys;
use openssl::ssl::{ExtensionContext, SslAlert, SslCipherRef, SslRef};
use openssl::x509::X509Ref;

use crate::connection::Connection;
use crate::event_openssl::{explicit_memzero, ngx_ssl_error, ngx_ssl_get_connection, NgxSsl};
use crate::log::*;
use crate::rc::*;
use crate::{ngx_log_debug, ngx_log_error};

use super::ngx_quic_get_connection;
use super::protection::*;
use super::transport::*;

const NGX_QUIC_COMPAT_RECORD_SIZE: usize = 1024;

const NGX_QUIC_COMPAT_SSL_TP_EXT: u16 = 0x39;

const NGX_QUIC_COMPAT_CLIENT_HANDSHAKE: &[u8] = b"CLIENT_HANDSHAKE_TRAFFIC_SECRET";
const NGX_QUIC_COMPAT_SERVER_HANDSHAKE: &[u8] = b"SERVER_HANDSHAKE_TRAFFIC_SECRET";
const NGX_QUIC_COMPAT_CLIENT_APPLICATION: &[u8] = b"CLIENT_TRAFFIC_SECRET_0";
const NGX_QUIC_COMPAT_SERVER_APPLICATION: &[u8] = b"SERVER_TRAFFIC_SECRET_0";

/// enum ssl_encryption_level_t
pub const SSL_ENCRYPTION_INITIAL: usize = 0;
pub const SSL_ENCRYPTION_EARLY_DATA: usize = 1;
pub const SSL_ENCRYPTION_HANDSHAKE: usize = 2;
pub const SSL_ENCRYPTION_APPLICATION: usize = 3;

/// SSL_QUIC_METHOD; add_handshake_data is called from the message callback
/// with the SSL object being processed
pub struct SslQuicMethod {
    pub set_read_secret: fn(c: &Connection, level: usize, cipher: &SslCipherRef, secret: &[u8]) -> c_int,
    pub set_write_secret: fn(c: &Connection, level: usize, cipher: &SslCipherRef, secret: &[u8]) -> c_int,
    pub add_handshake_data: fn(c: &Connection, ssl: &SslRef, level: usize, data: &[u8]) -> c_int,
    pub flush_flight: fn(c: &Connection) -> c_int,
    pub send_alert: fn(c: &Connection, level: usize, alert: u8) -> c_int,
}

/// ngx_quic_compat_keys_t
#[derive(Default)]
struct QuicCompatKeys {
    secret: QuicSecret,
    cipher: u32,
}

/// ngx_quic_compat_record_t
struct QuicCompatRecord<'a> {
    log: &'a Log,

    ty: u8,
    payload: &'a [u8],
    number: u64,
    keys: &'a QuicCompatKeys,
}

/// ngx_quic_compat_t
pub struct QuicCompat {
    method: &'static SslQuicMethod,

    write_level: usize,

    read_record: u64,
    keys: QuicCompatKeys,

    tp: Vec<u8>,
    ctp: Vec<u8>,
}

/// ngx_quic_compat_keylog_init
pub fn ngx_quic_compat_keylog_init(ssl: &mut NgxSsl) {
    if let Some(ctx) = ssl.ctx.builder_mut() {
        ctx.set_keylog_callback(ngx_quic_compat_keylog_callback);
    }
}

/// ngx_quic_compat_ext_init
pub fn ngx_quic_compat_ext_init(log: &Log, ssl: &mut NgxSsl) -> i64 {
    // SSL_CTX_has_client_custom_ext()
    if ssl.quic_compat_ext {
        return NGX_OK;
    }

    let ctx = match ssl.ctx.builder_mut() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    if let Err(e) = ctx.add_custom_ext(NGX_QUIC_COMPAT_SSL_TP_EXT, ExtensionContext::CLIENT_HELLO | ExtensionContext::TLS1_3_ENCRYPTED_EXTENSIONS, ngx_quic_compat_add_transport_params_callback, ngx_quic_compat_parse_transport_params_callback) {
        e.put();
        ngx_log_error!(NGX_LOG_EMERG, log, None, "SSL_CTX_add_custom_ext() failed");
        return NGX_ERROR;
    }

    ssl.quic_compat_ext = true;

    NGX_OK
}

/// ngx_quic_compat_keylog_callback
fn ngx_quic_compat_keylog_callback(ssl: &SslRef, line: &str) {
    let c = match ngx_ssl_get_connection(ssl) {
        Some(c) => c,
        None => return,
    };

    if c.ty != libc::SOCK_DGRAM {
        return;
    }

    let line = line.as_bytes();

    let mut p = 0;

    while p < line.len() && line[p] != b' ' {
        p += 1;
    }

    let name = &line[..p];

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic compat secret {}", crate::string::B(name));

    let (level, write) = if name == NGX_QUIC_COMPAT_CLIENT_HANDSHAKE {
        (SSL_ENCRYPTION_HANDSHAKE, false)
    } else if name == NGX_QUIC_COMPAT_SERVER_HANDSHAKE {
        (SSL_ENCRYPTION_HANDSHAKE, true)
    } else if name == NGX_QUIC_COMPAT_CLIENT_APPLICATION {
        (SSL_ENCRYPTION_APPLICATION, false)
    } else if name == NGX_QUIC_COMPAT_SERVER_APPLICATION {
        (SSL_ENCRYPTION_APPLICATION, true)
    } else {
        return;
    };

    if p >= line.len() {
        return;
    }

    p += 1;

    while p < line.len() && line[p] != b' ' {
        p += 1;
    }

    if p >= line.len() {
        return;
    }

    p += 1;

    let start = p;

    let mut secret = [0u8; sys::EVP_MAX_MD_SIZE];
    let mut n = 0usize;

    while p < line.len() {
        let mut ch = line[p];

        let value = if ch.is_ascii_digit() {
            ch - b'0'
        } else {
            ch |= 0x20;

            if (b'a'..=b'f').contains(&ch) {
                ch - b'a' + 10
            } else {
                ngx_log_error!(NGX_LOG_EMERG, c.log, None, "invalid OpenSSL QUIC secret format");

                return;
            }
        };

        if (p - start) % 2 != 0 {
            secret[n] += value;
            n += 1;
        } else {
            if n >= sys::EVP_MAX_MD_SIZE {
                ngx_log_error!(NGX_LOG_EMERG, c.log, None, "too big OpenSSL QUIC secret");
                return;
            }

            secret[n] = value << 4;
        }

        p += 1;
    }

    let qc = match ngx_quic_get_connection(&c) {
        Some(qc) => qc,
        None => return,
    };

    let cipher = match ssl.current_cipher() {
        Some(cipher) => cipher,
        None => return,
    };

    let method = match qc.compat.borrow().as_ref() {
        Some(com) => com.method,
        None => return,
    };

    if write {
        (method.set_write_secret)(&c, level, cipher, &secret[..n]);

        if let Some(com) = qc.compat.borrow_mut().as_mut() {
            com.write_level = level;
        }
    } else {
        (method.set_read_secret)(&c, level, cipher, &secret[..n]);

        let rc = match qc.compat.borrow_mut().as_mut() {
            Some(com) => {
                com.read_record = 0;

                ngx_quic_compat_set_encryption_secret(&c, &mut com.keys, level, cipher, &secret[..n])
            }

            None => NGX_ERROR,
        };

        if rc != NGX_OK {
            qc.error.set(NGX_QUIC_ERR_INTERNAL_ERROR);
        }
    }

    explicit_memzero(&mut secret[..n]);
}

/// ngx_quic_compat_set_encryption_secret
fn ngx_quic_compat_set_encryption_secret(c: &Connection, keys: &mut QuicCompatKeys, _level: usize, cipher: &SslCipherRef, secret: &[u8]) -> i64 {
    keys.cipher = ngx_quic_cipher_id(cipher);

    let mut ciphers = QuicCiphers::default();

    let key_len = ngx_quic_ciphers(keys.cipher, &mut ciphers);

    if key_len == NGX_ERROR {
        ngx_ssl_error(NGX_LOG_INFO, &c.log, 0, format_args!("unexpected cipher"));
        return NGX_ERROR;
    }

    let peer_secret = &mut keys.secret;

    let mut key = QuicMd { len: key_len as usize, ..Default::default() };

    peer_secret.iv.len = NGX_QUIC_IV_LEN;

    if ngx_quic_hkdf_expand(&mut key.data[..key_len as usize], b"tls13 key", secret, ciphers.d, &c.log) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_hkdf_expand(&mut peer_secret.iv.data, b"tls13 iv", secret, ciphers.d, &c.log) != NGX_OK {
        return NGX_ERROR;
    }

    /* the cleanup handler: the context is freed with the secret */

    if peer_secret.ctx.is_some() {
        ngx_quic_crypto_cleanup(peer_secret);
    }

    if ngx_quic_crypto_init(ciphers.c, peer_secret, &key, 1, &c.log) == NGX_ERROR {
        return NGX_ERROR;
    }

    explicit_memzero(&mut key.data[..key_len as usize]);

    NGX_OK
}

/// ngx_quic_compat_add_transport_params_callback: the parameters of the
/// connection (None: the extension is not added)
fn ngx_quic_compat_add_transport_params_callback(ssl: &mut SslRef, _ctx: ExtensionContext, _x: Option<(usize, &X509Ref)>) -> Result<Option<Vec<u8>>, SslAlert> {
    let c = match ngx_ssl_get_connection(ssl) {
        Some(c) => c,
        None => return Ok(None),
    };

    if c.ty != libc::SOCK_DGRAM {
        return Ok(None);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic compat add transport params");

    let qc = match ngx_quic_get_connection(&c) {
        Some(qc) => qc,
        None => return Ok(None),
    };

    let com = qc.compat.borrow();

    // OpenSSL copies the parameters
    Ok(com.as_ref().map(|com| com.tp.clone()))
}

/// ngx_quic_compat_parse_transport_params_callback
fn ngx_quic_compat_parse_transport_params_callback(ssl: &mut SslRef, _ctx: ExtensionContext, inp: &[u8], _x: Option<(usize, &X509Ref)>) -> Result<(), SslAlert> {
    let c = match ngx_ssl_get_connection(ssl) {
        Some(c) => c,
        None => return Ok(()),
    };

    if c.ty != libc::SOCK_DGRAM {
        return Ok(());
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic compat parse transport params");

    let qc = match ngx_quic_get_connection(&c) {
        Some(qc) => qc,
        None => return Err(SslAlert::DECODE_ERROR),
    };

    let mut com = qc.compat.borrow_mut();

    let com = match com.as_mut() {
        Some(com) => com,
        None => return Err(SslAlert::DECODE_ERROR),
    };

    com.ctp = inp.to_vec();

    Ok(())
}

/// The message callback of the SSL objects of the QUIC connections.
struct MsgCb;

impl sys::MsgCallback for MsgCb {
    fn msg(write_p: bool, version: i32, content_type: i32, buf: &[u8], ssl: &SslRef) {
        ngx_quic_compat_message_callback(write_p, version, content_type, buf, ssl);
    }
}

/// SSL_set_quic_method
pub fn ssl_set_quic_method(c: &Connection, ssl: &mut SslRef, quic_method: &'static SslQuicMethod) -> c_int {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic compat set method");

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return 0,
    };

    *qc.compat.borrow_mut() = Some(QuicCompat { method: quic_method, write_level: SSL_ENCRYPTION_INITIAL, read_record: 0, keys: QuicCompatKeys::default(), tp: Vec::new(), ctp: Vec::new() });

    if !sys::set_quic_compat_bio(ssl) {
        return 0;
    }

    sys::set_msg_callback::<MsgCb>(ssl);

    /* early data is not supported */
    let _ = ssl.set_max_early_data(0);

    1
}

/// ngx_quic_compat_message_callback
fn ngx_quic_compat_message_callback(write_p: bool, _version: i32, content_type: i32, data: &[u8], ssl: &SslRef) {
    if !write_p {
        return;
    }

    let c = match ngx_ssl_get_connection(ssl) {
        Some(c) => c,
        None => return,
    };

    let qc = match ngx_quic_get_connection(&c) {
        Some(qc) => qc,
        /* closing */
        None => return,
    };

    let (method, level) = match qc.compat.borrow().as_ref() {
        Some(com) => (com.method, com.write_level),
        None => return,
    };

    let len = data.len();

    match content_type {
        sys::SSL3_RT_HANDSHAKE => {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic compat tx level:{} len:{}", level, len);

            (method.add_handshake_data)(&c, ssl, level, data);
        }

        sys::SSL3_RT_ALERT => {
            if len >= 2 {
                let alert = data[1];

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic compat level:{} alert:{} len:{}", level, alert, len);

                (method.send_alert)(&c, level, alert);
            }
        }

        _ => {}
    }
}

/// SSL_provide_quic_data
pub fn ssl_provide_quic_data(c: &Connection, level: usize, mut data: &[u8]) -> c_int {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic compat rx level:{} len:{}", level, data.len());

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return 0,
    };

    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return 0,
    };

    let mut com = qc.compat.borrow_mut();

    let com = match com.as_mut() {
        Some(com) => com,
        None => return 0,
    };

    // the memory BIO takes all the data written
    let rbio_write = |b: &[u8]| {
        sc.with_mut(|ssl| sys::rbio_write(ssl, b));
    };

    while !data.is_empty() {
        let number = com.read_record;
        com.read_record += 1;

        if level == SSL_ENCRYPTION_INITIAL {
            let n = data.len().min(65535);

            let rec = QuicCompatRecord { log: &c.log, ty: sys::SSL3_RT_HANDSHAKE as u8, payload: &data[..n], number, keys: &com.keys };

            let mut out = Vec::with_capacity(sys::SSL3_RT_HEADER_LENGTH);

            ngx_quic_compat_create_header(&rec, &mut out, true);

            rbio_write(&out[..sys::SSL3_RT_HEADER_LENGTH]);
            rbio_write(&data[..n]);

            data = &data[n..];
        } else {
            let n = data.len().min(NGX_QUIC_COMPAT_RECORD_SIZE);

            let mut input = Vec::with_capacity(n + 1);
            input.extend_from_slice(&data[..n]);
            input.push(sys::SSL3_RT_HANDSHAKE as u8);

            let rec = QuicCompatRecord { log: &c.log, ty: sys::SSL3_RT_HANDSHAKE as u8, payload: &input, number, keys: &com.keys };

            let mut res = Vec::with_capacity(NGX_QUIC_COMPAT_RECORD_SIZE + 1 + sys::SSL3_RT_HEADER_LENGTH + NGX_QUIC_TAG_LEN);

            if ngx_quic_compat_create_record(&rec, &mut res) != NGX_OK {
                return 0;
            }

            rbio_write(&res);

            data = &data[n..];
        }
    }

    1
}

/// ngx_quic_compat_create_header
fn ngx_quic_compat_create_header(rec: &QuicCompatRecord<'_>, out: &mut Vec<u8>, plain: bool) -> usize {
    let mut len = rec.payload.len();

    let ty = if plain {
        rec.ty
    } else {
        len += NGX_QUIC_TAG_LEN;
        sys::SSL3_RT_APPLICATION_DATA as u8
    };

    out.push(ty);
    out.push(0x03);
    out.push(0x03);
    out.push((len >> 8) as u8);
    out.push(len as u8);

    5
}

/// ngx_quic_compat_create_record
fn ngx_quic_compat_create_record(rec: &QuicCompatRecord<'_>, res: &mut Vec<u8>) -> i64 {
    let base = res.len();

    ngx_quic_compat_create_header(rec, res, false);

    let ad = res[base..].to_vec();

    let secret = &rec.keys.secret;

    if secret.ctx.is_none() {
        return NGX_ERROR;
    }

    let mut nonce = [0u8; NGX_QUIC_IV_LEN];
    nonce[..secret.iv.len].copy_from_slice(&secret.iv.data[..secret.iv.len]);
    ngx_quic_compute_nonce(&mut nonce, rec.number);

    if ngx_quic_crypto_seal(secret, res, &nonce, rec.payload, &ad, rec.log) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// SSL_set_quic_transport_params
pub fn ssl_set_quic_transport_params(c: &Connection, params: Vec<u8>) -> c_int {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return 0,
    };

    match qc.compat.borrow_mut().as_mut() {
        Some(com) => com.tp = params,
        None => return 0,
    }

    1
}

/// SSL_get_peer_quic_transport_params
pub fn ssl_get_peer_quic_transport_params(c: &Connection) -> Vec<u8> {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return Vec::new(),
    };

    let com = qc.compat.borrow();

    com.as_ref().map(|com| com.ctp.clone()).unwrap_or_default()
}
