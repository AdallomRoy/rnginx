//! ngx_event_quic_connid.c: connection ids, those of the client and those
//! of the server (the sockets).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::connection::Connection;
use crate::log::*;
use crate::openssl_ffi::RAND_bytes;
use crate::rc::*;
use crate::{ngx_log_debug, ngx_log_error};

use super::frames::{ngx_quic_alloc_frame, ngx_quic_queue_frame};
use super::socket::{ngx_quic_close_socket, ngx_quic_create_socket, ngx_quic_find_socket, ngx_quic_listen};
use super::tokens::ngx_quic_new_sr_token;
use super::transport::*;
use super::{ngx_quic_get_connection, ngx_quic_get_socket, QuicClientId, QuicServerId, NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_SR_TOKEN_LEN};

const NGX_QUIC_MAX_SERVER_IDS: u64 = 8;

/// ngx_quic_create_server_id
pub fn ngx_quic_create_server_id(c: &Connection, id: &mut [u8; NGX_QUIC_SERVER_CID_LEN]) -> i64 {
    // SAFETY: the buffer has NGX_QUIC_SERVER_CID_LEN bytes
    if unsafe { RAND_bytes(id.as_mut_ptr(), NGX_QUIC_SERVER_CID_LEN as i32) } != 1 {
        return NGX_ERROR;
    }

    if ngx_quic_bpf_attach_id(c, id) != NGX_OK {
        ngx_log_error!(NGX_LOG_ERR, c.log, None, "quic bpf failed to generate socket key");
        /* ignore error, things still may work */
    }

    NGX_OK
}

/// ngx_quic_bpf_attach_id
fn ngx_quic_bpf_attach_id(c: &Connection, id: &mut [u8; NGX_QUIC_SERVER_CID_LEN]) -> i64 {
    let fd = match c.listening() {
        Some(ls) => ls.fd.get(),
        None => c.fd.get(),
    };

    let mut cookie: u64 = 0;
    let mut optlen = std::mem::size_of::<u64>() as libc::socklen_t;

    // SAFETY: cookie is a u64 of optlen bytes
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_COOKIE, &mut cookie as *mut u64 as *mut libc::c_void, &mut optlen) } == -1 {
        ngx_log_error!(NGX_LOG_ERR, c.log, Some(crate::os::errno()), "quic getsockopt(SO_COOKIE) failed");

        return NGX_ERROR;
    }

    ngx_quic_dcid_encode_key(id, cookie);

    NGX_OK
}

/// ngx_quic_handle_new_connection_id_frame
pub fn ngx_quic_handle_new_connection_id_frame(c: &Rc<Connection>, f: &QuicNewConnIdFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let mut retire_only = false;

    if f.seqnum < qc.max_retired_seqnum.get() {
        // RFC 9000, 19.15.  NEW_CONNECTION_ID Frame
        //
        //  An endpoint that receives a NEW_CONNECTION_ID frame with
        //  a sequence number smaller than the Retire Prior To field
        //  of a previously received NEW_CONNECTION_ID frame MUST send
        //  a corresponding RETIRE_CONNECTION_ID frame that retires
        //  the newly received connection ID, unless it has already
        //  done so for that sequence number.

        let mut frame = match ngx_quic_alloc_frame(c) {
            Some(f) => f,
            None => return NGX_ERROR,
        };

        frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
        frame.ty = NGX_QUIC_FT_RETIRE_CONNECTION_ID;
        frame.u.retire_cid.sequence_number = f.seqnum;

        ngx_quic_queue_frame(&qc, frame);

        retire_only = true;
    }

    if !retire_only {
        let cid = qc.client_ids.borrow().iter().find(|item| item.seqnum.get() == f.seqnum).cloned();

        let id = &f.cid[..f.len as usize];

        if let Some(cid) = cid {
            // Transmission errors, timeouts, and retransmissions might cause the
            // same NEW_CONNECTION_ID frame to be received multiple times.

            if *cid.id.borrow() != id || *cid.sr_token.borrow() != f.srt {
                // ..if a sequence number is used for different connection IDs,
                // the endpoint MAY treat that receipt as a connection error
                // of type PROTOCOL_VIOLATION.
                qc.error.set(NGX_QUIC_ERR_PROTOCOL_VIOLATION);
                qc.error_reason.set(Some("seqnum refers to different connection id/token"));
                return NGX_ERROR;
            }
        } else {
            ngx_quic_create_client_id(c, id, f.seqnum, Some(&f.srt));
        }
    }

    // retire:

    if qc.max_retired_seqnum.get() != 0 && f.retire <= qc.max_retired_seqnum.get() {
        // Once a sender indicates a Retire Prior To value, smaller values sent
        // in subsequent NEW_CONNECTION_ID frames have no effect.  A receiver
        // MUST ignore any Retire Prior To fields that do not increase the
        // largest received Retire Prior To value.
    } else {
        qc.max_retired_seqnum.set(f.retire);

        let cids: Vec<Rc<QuicClientId>> = qc.client_ids.borrow().clone();

        for cid in cids {
            if cid.seqnum.get() >= f.retire {
                continue;
            }

            if ngx_quic_retire_client_id(c, &cid) != NGX_OK {
                return NGX_ERROR;
            }
        }
    }

    // done:

    if qc.nclient_ids.get() > qc.tp.borrow().active_connection_id_limit {
        // RFC 9000, 5.1.1.  Issuing Connection IDs
        //
        // After processing a NEW_CONNECTION_ID frame and
        // adding and retiring active connection IDs, if the number of active
        // connection IDs exceeds the value advertised in its
        // active_connection_id_limit transport parameter, an endpoint MUST
        // close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.
        qc.error.set(NGX_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR);
        qc.error_reason.set(Some("too many connection ids received"));
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_retire_client_id
fn ngx_quic_retire_client_id(c: &Rc<Connection>, cid: &Rc<QuicClientId>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if !cid.used.get() {
        return ngx_quic_free_client_id(c, cid);
    }

    /* we are going to retire client id which is in use */

    let paths = qc.paths.borrow().clone();

    for path in paths {
        let same = path.cid.borrow().as_ref().is_some_and(|p| Rc::ptr_eq(p, cid));

        if !same {
            continue;
        }

        if Rc::ptr_eq(&path, &qc.path()) {
            /* this is the active path: update it with new CID */
            let new_cid = match ngx_quic_next_client_id(c) {
                Some(cid) => cid,
                None => return NGX_ERROR,
            };

            *qc.path().cid.borrow_mut() = Some(new_cid.clone());
            new_cid.used.set(true);

            return ngx_quic_free_client_id(c, cid);
        }

        return super::migration::ngx_quic_free_path(c, &path);
    }

    NGX_OK
}

/// ngx_quic_create_client_id
pub fn ngx_quic_create_client_id(c: &Connection, id: &[u8], seqnum: u64, token: Option<&[u8; NGX_QUIC_SR_TOKEN_LEN]>) -> Rc<QuicClientId> {
    let qc = ngx_quic_get_connection(c).expect("quic connection");

    let cid = Rc::new(QuicClientId { seqnum: Cell::new(seqnum), id: RefCell::new(id.to_vec()), sr_token: RefCell::new([0; NGX_QUIC_SR_TOKEN_LEN]), used: Cell::new(false) });

    if let Some(token) = token {
        *cid.sr_token.borrow_mut() = *token;
    }

    qc.client_ids.borrow_mut().push(cid.clone());
    qc.nclient_ids.set(qc.nclient_ids.get() + 1);

    if seqnum > qc.client_seqnum.get() {
        qc.client_seqnum.set(seqnum);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic cid seq:{} received id:{}:{}:{}", seqnum, id.len(), hex(id), hex(&*cid.sr_token.borrow()));

    cid
}

/// ngx_quic_next_client_id
pub fn ngx_quic_next_client_id(c: &Connection) -> Option<Rc<QuicClientId>> {
    let qc = ngx_quic_get_connection(c)?;

    let cid = qc.client_ids.borrow().iter().find(|cid| !cid.used.get()).cloned();

    cid
}

/// ngx_quic_handle_retire_connection_id_frame
pub fn ngx_quic_handle_retire_connection_id_frame(c: &Rc<Connection>, f: &QuicRetireCidFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if f.sequence_number >= qc.server_seqnum.get() {
        // RFC 9000, 19.16.
        //
        //  Receipt of a RETIRE_CONNECTION_ID frame containing a sequence
        //  number greater than any previously sent to the peer MUST be
        //  treated as a connection error of type PROTOCOL_VIOLATION.
        qc.error.set(NGX_QUIC_ERR_PROTOCOL_VIOLATION);
        qc.error_reason.set(Some("sequence number of id to retire was never issued"));

        return NGX_ERROR;
    }

    if let Some(qsock) = ngx_quic_get_socket(c) {
        if qsock.sid.borrow().seqnum == f.sequence_number {
            // RFC 9000, 19.16.
            //
            // The sequence number specified in a RETIRE_CONNECTION_ID frame MUST
            // NOT refer to the Destination Connection ID field of the packet in
            // which the frame is contained.  The peer MAY treat this as a
            // connection error of type PROTOCOL_VIOLATION.

            qc.error.set(NGX_QUIC_ERR_PROTOCOL_VIOLATION);
            qc.error_reason.set(Some("sequence number of id to retire refers DCID"));

            return NGX_ERROR;
        }
    }

    let qsock = match ngx_quic_find_socket(c, f.sequence_number) {
        Some(qsock) => qsock,
        None => return NGX_OK,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic socket seq:{} is retired", qsock.sid.borrow().seqnum);

    ngx_quic_close_socket(c, &qsock);

    /* restore socket count up to a limit after deletion */
    if ngx_quic_create_sockets(c) != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_create_sockets
pub fn ngx_quic_create_sockets(c: &Rc<Connection>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let n = NGX_QUIC_MAX_SERVER_IDS.min(qc.ctp.borrow().active_connection_id_limit) as usize;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic create sockets has:{} max:{}", qc.nsockets.get(), n);

    while qc.nsockets.get() < n {
        let qsock = match ngx_quic_create_socket(c, &qc) {
            Some(qsock) => qsock,
            None => return NGX_ERROR,
        };

        if ngx_quic_listen(c, &qc, &qsock) != NGX_OK {
            return NGX_ERROR;
        }

        let sid = qsock.sid.borrow().clone();

        if ngx_quic_send_server_id(c, &sid) != NGX_OK {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_quic_send_server_id
fn ngx_quic_send_server_id(c: &Connection, sid: &QuicServerId) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_NEW_CONNECTION_ID;
    frame.u.ncid.seqnum = sid.seqnum;
    frame.u.ncid.retire = 0;
    frame.u.ncid.len = NGX_QUIC_SERVER_CID_LEN as u8;
    frame.u.ncid.cid[..NGX_QUIC_SERVER_CID_LEN].copy_from_slice(&sid.id[..NGX_QUIC_SERVER_CID_LEN]);

    let mut srt = [0u8; NGX_QUIC_SR_TOKEN_LEN];

    if ngx_quic_new_sr_token(c, &sid.id, &qc.conf.sr_token_key, &mut srt) != NGX_OK {
        return NGX_ERROR;
    }

    frame.u.ncid.srt = srt;

    ngx_quic_queue_frame(&qc, frame);

    NGX_OK
}

/// ngx_quic_free_client_id
pub fn ngx_quic_free_client_id(c: &Connection, cid: &Rc<QuicClientId>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_RETIRE_CONNECTION_ID;
    frame.u.retire_cid.sequence_number = cid.seqnum.get();

    ngx_quic_queue_frame(&qc, frame);

    /* we are no longer going to use this client id */

    qc.client_ids.borrow_mut().retain(|item| !Rc::ptr_eq(item, cid));

    qc.nclient_ids.set(qc.nclient_ids.get() - 1);

    NGX_OK
}
