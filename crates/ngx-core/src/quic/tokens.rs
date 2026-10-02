//! ngx_event_quic_tokens.c: stateless reset tokens, address validation
//! tokens (Retry and NEW_TOKEN).

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::rand::rand_bytes;

use crate::connection::Connection;
use crate::inet::SockAddr;
use crate::log::*;
use crate::rc::*;
use crate::{ngx_log_debug, ngx_log_error};

use super::protection::ngx_quic_derive_key;
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

    // the errors of OpenSSL are left on its queue, as in the C
    let failed = |e: openssl::error::ErrorStack| {
        e.put();
        None
    };

    let mut ctx = match CipherCtx::new() {
        Ok(ctx) => ctx,
        Err(e) => return failed(e),
    };

    let cipher = Cipher::aes_256_gcm();

    let mut token = vec![0u8; NGX_QUIC_TOKEN_BUF_SIZE];

    /* the IV, then the data (GCM outputs as much as its input) and the tag */

    if let Err(e) = rand_bytes(&mut token[..iv_len]) {
        return failed(e);
    }

    if let Err(e) = ctx.encrypt_init(Some(cipher), Some(&key[..]), Some(&token[..iv_len])) {
        return failed(e);
    }

    let mut tlen = iv_len;

    match ctx.cipher_update(&input[..len], Some(&mut token[tlen..])) {
        Ok(n) => tlen += n,
        Err(e) => return failed(e),
    }

    match ctx.cipher_final(&mut token[tlen..]) {
        Ok(n) => tlen += n,
        Err(e) => return failed(e),
    }

    if let Err(e) = ctx.tag(&mut token[tlen..tlen + NGX_QUIC_AES_256_GCM_TAG_LEN]) {
        return failed(e);
    }

    tlen += NGX_QUIC_AES_256_GCM_TAG_LEN;

    token.truncate(tlen);

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

    // the errors of OpenSSL are left on its queue, as in the C
    let requeue = |e: openssl::error::ErrorStack| e.put();

    let mut ctx = match CipherCtx::new() {
        Ok(ctx) => ctx,
        Err(e) => {
            requeue(e);
            return NGX_ERROR;
        }
    };

    let cipher = Cipher::aes_256_gcm();

    /* the token is the IV, the data and the tag (checked above) */

    if let Err(e) = ctx.decrypt_init(Some(cipher), Some(&key[..]), Some(&pkt.token[..iv_len])) {
        requeue(e);
        return NGX_ERROR;
    }

    let len = pkt.token.len() - iv_len - NGX_QUIC_AES_256_GCM_TAG_LEN;
    let (data, tag) = pkt.token[iv_len..].split_at(len);

    /* the data decrypted fits tdec (checked above) */
    let mut tdec = [0u8; NGX_QUIC_MAX_TOKEN_SIZE];

    let mut total = match ctx.cipher_update(data, Some(&mut tdec)) {
        Ok(n) => n,
        Err(e) => {
            requeue(e);
            return garbage();
        }
    };

    if let Err(e) = ctx.set_tag(tag) {
        requeue(e);
        return garbage();
    }

    match ctx.cipher_final(&mut tdec[total..]) {
        Ok(n) => total += n,
        Err(e) => {
            requeue(e);
            return garbage();
        }
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

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use openssl::symm;

    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn addr(port: u16) -> SockAddr {
        SockAddr::v4(std::net::Ipv4Addr::new(127, 0, 0, 1), port)
    }

    fn conn(sockaddr: SockAddr) -> Rc<Connection> {
        crate::connection::set_connection_n(16);
        Connection::peer(-1, libc::SOCK_DGRAM, sockaddr, &Log::stderr(0)).expect("connection")
    }

    fn validate(c: &Connection, key: &[u8; 32], token: &[u8], dcid: &[u8]) -> (i64, QuicHeader<'static>) {
        let mut pkt = QuicHeader { token: token.to_vec(), dcid: dcid.to_vec(), ..Default::default() };
        let rc = ngx_quic_validate_token(c, key, &mut pkt);

        (rc, pkt)
    }

    #[test]
    fn retry_token() {
        let c = conn(addr(4433));
        let exp = crate::times::cached().sec + 3;
        let odcid = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let token = ngx_quic_new_token(&c.log, &addr(4433), &KEY, Some(&odcid), exp, true).expect("token");

        assert_eq!(token.len(), NGX_QUIC_AES_256_GCM_IV_LEN + 20 + TIME_T_LEN + 2 + odcid.len() + NGX_QUIC_AES_256_GCM_TAG_LEN);

        // AES-256-GCM of the address hash, the time, retry and the odcid
        let (iv, rest) = token.split_at(NGX_QUIC_AES_256_GCM_IV_LEN);
        let (data, tag) = rest.split_at(rest.len() - NGX_QUIC_AES_256_GCM_TAG_LEN);
        let plain = symm::decrypt_aead(symm::Cipher::aes_256_gcm(), &KEY, Some(iv), b"", data, tag).unwrap();

        assert_eq!(&plain[..20], &ngx_quic_address_hash(&addr(4433), false, None));
        assert_eq!(&plain[20..28], &exp.to_ne_bytes());
        assert_eq!(&plain[28..], &[1, 8, 1, 2, 3, 4, 5, 6, 7, 8]);

        let (rc, pkt) = validate(&c, &KEY, &token, b"dcid");
        assert_eq!(rc, NGX_OK);
        assert!(pkt.retried && pkt.validated);
        assert_eq!(pkt.odcid, odcid);

        // a Retry token is for the address and the port
        let (rc, pkt) = validate(&conn(addr(4434)), &KEY, &token, b"dcid");
        assert_eq!(rc, NGX_DECLINED);
        assert!(!pkt.validated);

        // another key: the tag does not match
        let (rc, pkt) = validate(&c, &[8; 32], &token, b"dcid");
        assert_eq!(rc, NGX_ABORT);
        assert!(!pkt.validated);

        // the IVs are random
        let again = ngx_quic_new_token(&c.log, &addr(4433), &KEY, Some(&odcid), exp, true).expect("token");
        assert_ne!(token[..NGX_QUIC_AES_256_GCM_IV_LEN], again[..NGX_QUIC_AES_256_GCM_IV_LEN]);
    }

    #[test]
    fn new_token() {
        let c = conn(addr(4433));
        let exp = crate::times::cached().sec + 600;

        let token = ngx_quic_new_token(&c.log, &addr(4433), &KEY, None, exp, false).expect("token");

        // a NEW_TOKEN token is for the address, whatever the port
        let (rc, pkt) = validate(&conn(addr(5000)), &KEY, &token, b"the dcid");
        assert_eq!(rc, NGX_OK);
        assert!(!pkt.retried && pkt.validated);
        assert_eq!(pkt.odcid, b"the dcid");

        let (rc, _) = validate(&conn(SockAddr::v4(std::net::Ipv4Addr::new(127, 0, 0, 2), 4433)), &KEY, &token, b"dcid");
        assert_eq!(rc, NGX_DECLINED);

        let token = ngx_quic_new_token(&c.log, &addr(4433), &KEY, None, crate::times::cached().sec - 1, false).expect("token");
        let (rc, pkt) = validate(&c, &KEY, &token, b"dcid");
        assert_eq!(rc, NGX_DECLINED, "expired");
        assert!(!pkt.validated);
    }

    #[test]
    fn garbage_tokens() {
        let c = conn(addr(4433));

        for len in [0, NGX_QUIC_AES_256_GCM_IV_LEN + NGX_QUIC_AES_256_GCM_TAG_LEN - 1, NGX_QUIC_TOKEN_BUF_SIZE + 1] {
            let (rc, _) = validate(&c, &KEY, &vec![0u8; len], b"dcid");
            assert_eq!(rc, NGX_ABORT, "length {}", len);
        }

        // authentic, but too short to be a token
        let iv = [3u8; NGX_QUIC_AES_256_GCM_IV_LEN];
        let mut tag = [0u8; NGX_QUIC_AES_256_GCM_TAG_LEN];
        let data = symm::encrypt_aead(symm::Cipher::aes_256_gcm(), &KEY, Some(&iv), b"", &[0; 29], &mut tag).unwrap();

        let mut token = iv.to_vec();
        token.extend_from_slice(&data);
        token.extend_from_slice(&tag);

        let (rc, _) = validate(&c, &KEY, &token, b"dcid");
        assert_eq!(rc, NGX_ABORT);
    }

    #[test]
    fn sr_tokens() {
        let c = conn(addr(4433));
        let key = [1u8; NGX_QUIC_SR_KEY_LEN];

        let mut t1 = [0u8; NGX_QUIC_SR_TOKEN_LEN];
        let mut t2 = [0u8; NGX_QUIC_SR_TOKEN_LEN];

        assert_eq!(ngx_quic_new_sr_token(&c, b"cid1", &key, &mut t1), NGX_OK);
        assert_eq!(ngx_quic_new_sr_token(&c, b"cid1", &key, &mut t2), NGX_OK);
        assert_eq!(t1, t2);

        assert_eq!(ngx_quic_new_sr_token(&c, b"cid2", &key, &mut t2), NGX_OK);
        assert_ne!(t1, t2);
    }
}
