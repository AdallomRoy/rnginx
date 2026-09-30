//! ngx_event_quic_tokens.c: stateless reset tokens, address validation
//! tokens (Retry and NEW_TOKEN).

use std::os::raw::c_int;

use crate::connection::Connection;
use crate::inet::SockAddr;
use crate::log::*;
use crate::openssl_ffi::*;
use crate::rc::*;
use crate::{ngx_log_debug, ngx_log_error};

use super::protection::{ngx_quic_derive_key, CipherCtx};
use super::transport::*;
use super::{ngx_quic_address_hash, NGX_QUIC_SR_KEY_LEN, NGX_QUIC_SR_TOKEN_LEN};

pub const NGX_QUIC_MAX_TOKEN_SIZE: usize = 64;
/* SHA-1(addr)=20 + sizeof(time_t) + retry(1) + odcid.len(1) + odcid */

pub const NGX_QUIC_AES_256_GCM_IV_LEN: usize = 12;
pub const NGX_QUIC_AES_256_GCM_TAG_LEN: usize = 16;

pub const NGX_QUIC_TOKEN_BUF_SIZE: usize = NGX_QUIC_AES_256_GCM_IV_LEN + NGX_QUIC_MAX_TOKEN_SIZE + NGX_QUIC_AES_256_GCM_TAG_LEN;

/// sizeof(time_t)
const TIME_T_LEN: usize = 8;

/// ngx_quic_new_sr_token
pub fn ngx_quic_new_sr_token(c: &Connection, cid: &[u8], secret: &[u8; NGX_QUIC_SR_KEY_LEN], token: &mut [u8; NGX_QUIC_SR_TOKEN_LEN]) -> i64 {
    let mut buf = [0u8; NGX_QUIC_SR_KEY_LEN + 8];

    buf[..NGX_QUIC_SR_KEY_LEN].copy_from_slice(secret);
    buf[NGX_QUIC_SR_KEY_LEN..].copy_from_slice(&(crate::event::worker_index() as u64).to_ne_bytes());

    if ngx_quic_derive_key(&c.log, "sr_token_key", &buf, cid, token) != NGX_OK {
        return NGX_ERROR;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stateless reset token {}", hex(token));

    NGX_OK
}

/// ngx_quic_new_token: the token, or None
pub fn ngx_quic_new_token(log: &Log, sockaddr: &SockAddr, key: &[u8; 32], odcid: Option<&[u8]>, exp: i64, is_retry: bool) -> Option<Vec<u8>> {
    let mut input = Vec::with_capacity(NGX_QUIC_MAX_TOKEN_SIZE);

    input.extend_from_slice(&ngx_quic_address_hash(sockaddr, !is_retry, None));

    input.extend_from_slice(&exp.to_ne_bytes());

    input.push(if is_retry { 1 } else { 0 });

    match odcid {
        Some(odcid) => {
            input.push(odcid.len() as u8);
            input.extend_from_slice(odcid);
        }

        None => input.push(0),
    }

    let len = input.len();

    let iv_len = NGX_QUIC_AES_256_GCM_IV_LEN;

    if iv_len + len + NGX_QUIC_AES_256_GCM_TAG_LEN > NGX_QUIC_TOKEN_BUF_SIZE {
        ngx_log_error!(NGX_LOG_ALERT, log, None, "quic token buffer is too small");
        return None;
    }

    let ctx = CipherCtx::new()?;

    let mut token = vec![0u8; NGX_QUIC_TOKEN_BUF_SIZE];

    // SAFETY: the buffers are large enough for the IV, the data (a block
    // cipher in GCM mode outputs as much as its input) and the tag
    unsafe {
        let cipher = EVP_aes_256_gcm();

        if RAND_bytes(token.as_mut_ptr(), iv_len as c_int) <= 0 || EVP_EncryptInit_ex(ctx.as_ptr(), cipher, std::ptr::null_mut(), key.as_ptr(), token.as_ptr()) == 0 {
            return None;
        }

        let mut tlen = iv_len;
        let mut n: c_int = 0;

        if EVP_EncryptUpdate(ctx.as_ptr(), token.as_mut_ptr().add(tlen), &mut n, input.as_ptr(), len as c_int) != 1 {
            return None;
        }

        tlen += n as usize;

        if EVP_EncryptFinal_ex(ctx.as_ptr(), token.as_mut_ptr().add(tlen), &mut n) <= 0 {
            return None;
        }

        tlen += n as usize;

        if EVP_CIPHER_CTX_ctrl(ctx.as_ptr(), EVP_CTRL_AEAD_GET_TAG, NGX_QUIC_AES_256_GCM_TAG_LEN as c_int, token.as_mut_ptr().add(tlen) as *mut std::os::raw::c_void) == 0 {
            return None;
        }

        tlen += NGX_QUIC_AES_256_GCM_TAG_LEN;

        token.truncate(tlen);
    }

    Some(token)
}

/// ngx_quic_validate_token
pub fn ngx_quic_validate_token(c: &Connection, key: &[u8; 32], pkt: &mut QuicHeader<'_>) -> i64 {
    /* Retry token or NEW_TOKEN in a previous connection */

    let iv_len = NGX_QUIC_AES_256_GCM_IV_LEN;

    let garbage = || {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic garbage token");
        NGX_ABORT
    };

    let bad_token = || {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic invalid token");
        NGX_DECLINED
    };

    /* sanity checks */

    if pkt.token.len() < iv_len + NGX_QUIC_AES_256_GCM_TAG_LEN {
        return garbage();
    }

    if pkt.token.len() > iv_len + NGX_QUIC_MAX_TOKEN_SIZE + NGX_QUIC_AES_256_GCM_TAG_LEN {
        return garbage();
    }

    let ctx = match CipherCtx::new() {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    let mut tdec = [0u8; NGX_QUIC_MAX_TOKEN_SIZE];
    let mut total: usize;

    // SAFETY: the token has the IV, the data and the tag (checked above),
    // and the data decrypted fits tdec
    unsafe {
        let cipher = EVP_aes_256_gcm();

        if EVP_DecryptInit_ex(ctx.as_ptr(), cipher, std::ptr::null_mut(), key.as_ptr(), pkt.token.as_ptr()) == 0 {
            return NGX_ERROR;
        }

        let p = pkt.token.as_ptr().add(iv_len);
        let len = pkt.token.len() - iv_len - NGX_QUIC_AES_256_GCM_TAG_LEN;

        let mut tlen: c_int = 0;

        if EVP_DecryptUpdate(ctx.as_ptr(), tdec.as_mut_ptr(), &mut tlen, p, len as c_int) != 1 {
            return garbage();
        }

        total = tlen as usize;

        if EVP_CIPHER_CTX_ctrl(ctx.as_ptr(), EVP_CTRL_AEAD_SET_TAG, NGX_QUIC_AES_256_GCM_TAG_LEN as c_int, p.add(len) as *mut std::os::raw::c_void) == 0 {
            return garbage();
        }

        if EVP_DecryptFinal_ex(ctx.as_ptr(), tdec.as_mut_ptr().add(total), &mut tlen) <= 0 {
            return garbage();
        }

        total += tlen as usize;
    }

    drop(ctx);

    if total < 20 + TIME_T_LEN + 2 {
        return garbage();
    }

    let mut p = 20;

    let exp = i64::from_ne_bytes(tdec[p..p + TIME_T_LEN].try_into().unwrap_or([0; TIME_T_LEN]));
    p += TIME_T_LEN;

    pkt.retried = tdec[p] == 1;
    p += 1;

    let addr_hash = ngx_quic_address_hash(&c.sockaddr.borrow(), !pkt.retried, None);

    if tdec[..20] != addr_hash {
        return bad_token();
    }

    let odcid_len = tdec[p] as usize;
    p += 1;

    if odcid_len != 0 {
        if odcid_len > NGX_QUIC_MAX_CID_LEN {
            return bad_token();
        }

        if total - p < odcid_len {
            return bad_token();
        }
    }

    let now = crate::times::cached().sec;

    if now > exp {
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic expired token");
        return NGX_DECLINED;
    }

    if odcid_len != 0 {
        pkt.odcid = tdec[p..p + odcid_len].to_vec();
    } else {
        pkt.odcid = pkt.dcid.clone();
    }

    pkt.validated = true;

    NGX_OK
}
