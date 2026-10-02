//! ngx_event_quic_ssl.c: the TLS handshake over CRYPTO frames (the
//! BoringSSL API, which the OpenSSL compat layer provides).

use std::os::raw::c_int;
use std::rc::Rc;

use ngx_sys::ssl as sys;
use openssl::ssl::{SslCipherRef, SslRef};

use crate::connection::Connection;
use crate::event_openssl::{ngx_ssl_connection_error, ngx_ssl_error, ngx_ssl_handshake_log, ngx_ssl_with};
use crate::log::*;
use crate::rc::*;
use crate::ngx_log_debug;
use crate::ngx_log_error;

use super::ack::ngx_quic_resend_frames;
use super::connid::ngx_quic_create_sockets;
use super::frames::*;
use super::migration::ngx_quic_discover_path_mtu;
use super::openssl_compat::*;
use super::output::ngx_quic_send_new_token;
use super::protection::*;
use super::streams::ngx_quic_init_streams;
use super::tokens::ngx_quic_new_sr_token;
use super::transport::*;
use super::{ngx_quic_apply_transport_params, ngx_quic_discard_ctx, ngx_quic_get_connection, ngx_quic_get_socket, ngx_quic_send_ctx_index, NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_ENCRYPTION_EARLY_DATA, NGX_QUIC_ENCRYPTION_HANDSHAKE, NGX_QUIC_ENCRYPTION_INITIAL, NGX_QUIC_SR_TOKEN_LEN};

// RFC 9000, 7.5.  Cryptographic Message Buffering
//
// Implementations MUST support buffering at least 4096 bytes of data
const NGX_QUIC_MAX_BUFFERED: u64 = 65535;

/// the quic_method of ngx_quic_init_connection()
static QUIC_METHOD: SslQuicMethod = SslQuicMethod {
    set_read_secret: ngx_quic_set_read_secret,
    set_write_secret: ngx_quic_set_write_secret,
    add_handshake_data: ngx_quic_add_handshake_data,
    flush_flight: ngx_quic_flush_flight,
    send_alert: ngx_quic_send_alert,
};

/// ngx_quic_map_encryption_level
fn ngx_quic_map_encryption_level(ssl_level: usize) -> usize {
    match ssl_level {
        SSL_ENCRYPTION_INITIAL => NGX_QUIC_ENCRYPTION_INITIAL,
        SSL_ENCRYPTION_EARLY_DATA => NGX_QUIC_ENCRYPTION_EARLY_DATA,
        SSL_ENCRYPTION_HANDSHAKE => NGX_QUIC_ENCRYPTION_HANDSHAKE,
        /* ssl_encryption_application */
        _ => NGX_QUIC_ENCRYPTION_APPLICATION,
    }
}

/// ngx_quic_set_read_secret
fn ngx_quic_set_read_secret(c: &Connection, ssl_level: usize, cipher: &SslCipherRef, rsecret: &[u8]) -> c_int {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return 1,
    };

    let level = ngx_quic_map_encryption_level(ssl_level);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ngx_quic_set_read_secret() level:{}", ssl_level);

    if ngx_quic_keys_set_encryption_secret(&c.log, false, &mut qc.keys.borrow_mut(), level, cipher, rsecret) != NGX_OK {
        qc.error.set(NGX_QUIC_ERR_INTERNAL_ERROR);
    }

    1
}

/// ngx_quic_set_write_secret
fn ngx_quic_set_write_secret(c: &Connection, ssl_level: usize, cipher: &SslCipherRef, wsecret: &[u8]) -> c_int {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return 1,
    };

    let level = ngx_quic_map_encryption_level(ssl_level);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ngx_quic_set_write_secret() level:{}", ssl_level);

    if ngx_quic_keys_set_encryption_secret(&c.log, true, &mut qc.keys.borrow_mut(), level, cipher, wsecret) != NGX_OK {
        qc.error.set(NGX_QUIC_ERR_INTERNAL_ERROR);
    }

    1
}

/// ngx_quic_add_handshake_data: `ssl_conn` is the SSL object being
/// processed (the message callback)
fn ngx_quic_add_handshake_data(c: &Connection, ssl_conn: &SslRef, ssl_level: usize, data: &[u8]) -> c_int {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return 1,
    };

    let level = ngx_quic_map_encryption_level(ssl_level);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ngx_quic_add_handshake_data");

    if !qc.client_tp_done.get() {
        // things to do once during handshake: check ALPN and transport
        // parameters; we want to break handshake if something is wrong
        // here;

        let alpn_len = ssl_conn.selected_alpn_protocol().map(|p| p.len()).unwrap_or(0);

        if alpn_len == 0 {
            if qc.error.get() == 0 {
                qc.error.set(ngx_quic_err_crypto(sys::SSL_AD_NO_APPLICATION_PROTOCOL as u64));
                qc.error_reason.set(Some("missing ALPN extension"));

                ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic missing ALPN extension");
            }

            return 1;
        }

        let client_params = ssl_get_peer_quic_transport_params(c);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic SSL_get_peer_quic_transport_params(): params_len:{}", client_params.len());

        if client_params.is_empty() {
            /* RFC 9001, 8.2.  QUIC Transport Parameters Extension */

            if qc.error.get() == 0 {
                qc.error.set(ngx_quic_err_crypto(sys::SSL_AD_MISSING_EXTENSION as u64));
                qc.error_reason.set(Some("missing transport parameters"));

                ngx_log_error!(NGX_LOG_INFO, c.log, None, "missing transport parameters");
            }

            return 1;
        }

        /* defaults for parameters not sent by client */
        let mut ctp = qc.ctp.borrow().clone();

        if ngx_quic_parse_transport_params(&client_params, &mut ctp, &c.log) != NGX_OK {
            qc.error.set(NGX_QUIC_ERR_TRANSPORT_PARAMETER_ERROR);
            qc.error_reason.set(Some("failed to process transport parameters"));

            return 1;
        }

        if ngx_quic_apply_transport_params(c, &ctp) != NGX_OK {
            return 1;
        }

        qc.client_tp_done.set(true);
    }

    let out = ngx_quic_copy_buffer(c, data);

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => {
            qc.error.set(NGX_QUIC_ERR_INTERNAL_ERROR);
            return 1;
        }
    };

    let offset = {
        let mut ctx = qc.send_ctx(level).borrow_mut();
        let offset = ctx.crypto_sent;
        ctx.crypto_sent += data.len() as u64;
        offset
    };

    frame.data = out;
    frame.level = level;
    frame.ty = NGX_QUIC_FT_CRYPTO;
    frame.u.ord.offset = offset;
    frame.u.ord.length = data.len() as u64;

    ngx_quic_queue_frame(&qc, frame);

    1
}

/// ngx_quic_flush_flight
fn ngx_quic_flush_flight(c: &Connection) -> c_int {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ngx_quic_flush_flight()");

    1
}

/// ngx_quic_send_alert
fn ngx_quic_send_alert(c: &Connection, ssl_level: usize, alert: u8) -> c_int {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ngx_quic_send_alert() level:{} alert:{}", ssl_level, alert as i32);

    /* already closed on regular shutdown */

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return 1,
    };

    qc.error.set(ngx_quic_err_crypto(alert as u64));
    qc.error_reason.set(Some("handshake failed"));

    1
}

/// ngx_quic_handle_crypto_frame
pub fn ngx_quic_handle_crypto_frame(c: &Rc<Connection>, pkt: &QuicHeader<'_>, frame: &QuicFrame, data: &[u8]) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if !ngx_quic_keys_available(&qc.keys.borrow(), pkt.level, false) {
        return NGX_OK;
    }

    if c.ssl.borrow().as_ref().is_some_and(|s| s.handshaked.get()) {
        /* QUIC doesn't define post-handshake messages for a client */

        qc.error.set(ngx_quic_err_crypto(sys::SSL_AD_UNEXPECTED_MESSAGE as u64));
        qc.error_reason.set(Some("unexpected CRYPTO frame"));

        return NGX_ERROR;
    }

    let f = &frame.u.ord;

    /* no overflow since both values are 62-bit */
    let last = f.offset + f.length;

    let crypto_offset = qc.send_ctx(pkt.level).borrow().crypto.offset;

    if last > crypto_offset + NGX_QUIC_MAX_BUFFERED {
        qc.error.set(NGX_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED);
        return NGX_ERROR;
    }

    if last <= crypto_offset {
        if pkt.level == NGX_QUIC_ENCRYPTION_INITIAL {
            /* speeding up handshake completion */

            let i = ngx_quic_send_ctx_index(pkt.level);

            if !qc.send_ctx[i].borrow().sent.is_empty() {
                ngx_quic_resend_frames(c, i);

                let h = ngx_quic_send_ctx_index(NGX_QUIC_ENCRYPTION_HANDSHAKE);

                while !qc.send_ctx[h].borrow().sent.is_empty() {
                    ngx_quic_resend_frames(c, h);
                }
            }
        }

        return NGX_OK;
    }

    {
        let mut ctx = qc.send_ctx(pkt.level).borrow_mut();
        let mut input = [data];

        ngx_quic_write_buffer(c, &mut ctx.crypto, &mut input, f.length, f.offset);
    }

    if ngx_quic_crypto_provide(c, pkt.level) != NGX_OK {
        return NGX_ERROR;
    }

    ngx_quic_handshake(c)
}

/// ngx_quic_handshake
fn ngx_quic_handshake(c: &Rc<Connection>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let sc = match c.ssl.borrow().clone() {
        Some(sc) => sc,
        None => return NGX_ERROR,
    };

    let io = match sc.with_mut(sys::do_handshake) {
        Some(io) => io,
        None => return NGX_ERROR,
    };

    let n = io.rc;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_do_handshake: {}", n);

    if n <= 0 {
        let sslerr = io.error;

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "SSL_get_error: {}", sslerr);

        let rejected = c.ssl.borrow().as_ref().is_some_and(|s| s.state.handshake_rejected.get());

        if rejected {
            c.connection_error(0, "handshake rejected");
            sys::err_clear_error();
            return NGX_ERROR;
        }

        if qc.error.get() != 0 {
            c.connection_error(0, "SSL_do_handshake() failed");
            sys::err_clear_error();
            return NGX_ERROR;
        }

        if sslerr != sys::SSL_ERROR_WANT_READ {
            ngx_ssl_connection_error(c, sslerr, 0, "SSL_do_handshake() failed");
            return NGX_ERROR;
        }
    }

    if qc.error.get() != 0 {
        c.connection_error(0, "SSL_do_handshake() failed");
        return NGX_ERROR;
    }

    if !ngx_ssl_with(c, |ssl| ssl.is_init_finished()).unwrap_or(false) {
        let early = ngx_quic_keys_available(&qc.keys.borrow(), NGX_QUIC_ENCRYPTION_EARLY_DATA, false);

        if early && qc.client_tp_done.get() && ngx_quic_init_streams(c) != NGX_OK {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    ngx_ssl_handshake_log(c);

    if let Some(sc) = c.ssl.borrow().as_ref() {
        sc.handshaked.set(true);
    }

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_HANDSHAKE_DONE;
    ngx_quic_queue_frame(&qc, frame);

    if qc.conf.retry && ngx_quic_send_new_token(c, &qc.path()) != NGX_OK {
        return NGX_ERROR;
    }

    // RFC 9001, 9.5.  Header Protection Timing Side Channels
    //
    // Generating next keys before a key update is received.

    qc.key_update.post();

    // RFC 9001, 4.9.2.  Discarding Handshake Keys
    //
    // An endpoint MUST discard its Handshake keys
    // when the TLS handshake is confirmed.
    ngx_quic_discard_ctx(c, NGX_QUIC_ENCRYPTION_HANDSHAKE);

    ngx_quic_discover_path_mtu(c, &qc.path());

    /* start accepting clients on negotiated number of server ids */
    if ngx_quic_create_sockets(c) != NGX_OK {
        return NGX_ERROR;
    }

    if ngx_quic_init_streams(c) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_crypto_provide
fn ngx_quic_crypto_provide(c: &Connection, level: usize) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let out = {
        let mut ctx = qc.send_ctx(level).borrow_mut();

        ngx_quic_read_buffer(c, &mut ctx.crypto, u64::MAX)
    };

    let ssl_level = match level {
        NGX_QUIC_ENCRYPTION_INITIAL => SSL_ENCRYPTION_INITIAL,
        NGX_QUIC_ENCRYPTION_EARLY_DATA => SSL_ENCRYPTION_EARLY_DATA,
        NGX_QUIC_ENCRYPTION_HANDSHAKE => SSL_ENCRYPTION_HANDSHAKE,
        /* NGX_QUIC_ENCRYPTION_APPLICATION */
        _ => SSL_ENCRYPTION_APPLICATION,
    };

    for b in out.iter() {
        let data = b.block.borrow()[b.pos..b.last].to_vec();

        if ssl_provide_quic_data(c, ssl_level, &data) == 0 {
            ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("SSL_provide_quic_data() failed"));
            return NGX_ERROR;
        }
    }

    ngx_quic_free_chain(c, out);

    NGX_OK
}

/// ngx_quic_init_connection
pub fn ngx_quic_init_connection(c: &Rc<Connection>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let create_ssl = match qc.conf.create_ssl.clone() {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    if create_ssl(c) != NGX_OK {
        return NGX_ERROR;
    }

    if let Some(sc) = c.ssl.borrow().as_ref() {
        sc.no_wait_shutdown.set(true);
    }

    let rc = c.ssl.borrow().clone().and_then(|sc| sc.with_mut(|ssl| ssl_set_quic_method(c, ssl, &QUIC_METHOD))).unwrap_or(0);

    if rc == 0 {
        ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("quic SSL_set_quic_method() failed"));
        return NGX_ERROR;
    }

    let dcid = match ngx_quic_get_socket(c) {
        Some(qsock) => qsock.sid.borrow().id.clone(),
        None => return NGX_ERROR,
    };

    let mut sr_token = [0u8; NGX_QUIC_SR_TOKEN_LEN];

    if ngx_quic_new_sr_token(c, &dcid, &qc.conf.sr_token_key, &mut sr_token) != NGX_OK {
        return NGX_ERROR;
    }

    qc.tp.borrow_mut().sr_token = sr_token;

    let mut clen = 0usize;

    let len = ngx_quic_create_transport_params(None, &qc.tp.borrow(), Some(&mut clen));
    /* always succeeds */

    let mut p = Vec::with_capacity(len as usize);

    let len = ngx_quic_create_transport_params(Some(&mut p), &qc.tp.borrow(), None);
    if len < 0 {
        return NGX_ERROR;
    }

    if ssl_set_quic_transport_params(c, p) == 0 {
        ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("quic SSL_set_quic_transport_params() failed"));
        return NGX_ERROR;
    }

    NGX_OK
}

