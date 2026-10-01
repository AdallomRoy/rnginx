//! ngx_event_quic_migration.c: paths, their validation, connection
//! migration, path MTU discovery.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::connection::{Connection, NGX_ERROR_IGNORE_EMSGSIZE};
use crate::inet::{cmp_sockaddr, SockAddr};
use crate::log::*;
use crate::openssl_ffi::RAND_bytes;
use crate::rc::*;
use crate::times;
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};

use super::ack::ngx_quic_pto;
use super::connid::{ngx_quic_free_client_id, ngx_quic_next_client_id};
use super::frames::{ngx_quic_alloc_frame, ngx_quic_queue_frame};
use super::output::{ngx_quic_frame_sendto, ngx_quic_path_limit, ngx_quic_send_new_token};
use super::transport::*;
use super::{ngx_quic_close_connection, ngx_quic_get_connection, ngx_quic_get_socket, QuicClientId, QuicPath, QuicPathState, NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_MIN_INITIAL_SIZE, NGX_QUIC_UNSET_PN};

pub const NGX_QUIC_PATH_RETRIES: u64 = 3;

pub const NGX_QUIC_PATH_PROBE: u64 = 0;
pub const NGX_QUIC_PATH_ACTIVE: u64 = 1;
pub const NGX_QUIC_PATH_BACKUP: u64 = 2;

const NGX_QUIC_PATH_MTU_DELAY: u64 = 100;
const NGX_QUIC_PATH_MTU_PRECISION: usize = 16;

/// ngx_quic_path_dbg
pub fn ngx_quic_path_dbg(c: &Connection, msg: &str, path: &QuicPath) {
    ngx_log_debug!(
        NGX_LOG_DEBUG_EVENT,
        c.log,
        "quic path seq:{} {} tx:{} rx:{} valid:{} st:{} mtu:{}",
        path.seqnum.get(),
        msg,
        path.sent.get(),
        path.received.get(),
        path.validated.get() as u32,
        path.state.get() as u32,
        path.mtu.get()
    );
}

/// ngx_quic_handle_path_challenge_frame
pub fn ngx_quic_handle_path_challenge_frame(c: &Rc<Connection>, pkt: &mut QuicHeader<'_>, f: &QuicPathChallengeFrame) -> i64 {
    if pkt.level != NGX_QUIC_ENCRYPTION_APPLICATION || pkt.path_challenged {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ignoring PATH_CHALLENGE");
        return NGX_OK;
    }

    pkt.path_challenged = true;

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let mut fp = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    fp.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    fp.ty = NGX_QUIC_FT_PATH_RESPONSE;
    fp.u.path_challenge = *f;

    // RFC 9000, 8.2.2.  Path Validation Responses
    //
    // A PATH_RESPONSE frame MUST be sent on the network path where the
    // PATH_CHALLENGE frame was received.

    // An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame
    // to at least the smallest allowed maximum datagram size of 1200 bytes.
    // ...
    // However, an endpoint MUST NOT expand the datagram containing the
    // PATH_RESPONSE if the resulting data exceeds the anti-amplification limit.

    let path = match pkt.path.clone() {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    let min = if ngx_quic_path_limit(c, &path, 1200) < 1200 { 0 } else { 1200 };

    if ngx_quic_frame_sendto(c, fp, min, &path) == NGX_ERROR {
        return NGX_ERROR;
    }

    if Rc::ptr_eq(&path, &qc.path()) {
        // RFC 9000, 9.3.3.  Off-Path Packet Forwarding
        //
        // An endpoint that receives a PATH_CHALLENGE on an active path SHOULD
        // send a non-probing packet in response.

        let mut fp = match ngx_quic_alloc_frame(c) {
            Some(f) => f,
            None => return NGX_ERROR,
        };

        fp.level = NGX_QUIC_ENCRYPTION_APPLICATION;
        fp.ty = NGX_QUIC_FT_PING;

        ngx_quic_queue_frame(&qc, fp);
    }

    NGX_OK
}

/// ngx_quic_handle_path_response_frame
pub fn ngx_quic_handle_path_response_frame(c: &Rc<Connection>, f: &QuicPathChallengeFrame) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    // RFC 9000, 8.2.3.  Successful Path Validation
    //
    // A PATH_RESPONSE frame received on any network path validates the path
    // on which the PATH_CHALLENGE was sent.

    let path = qc
        .paths
        .borrow()
        .iter()
        .find(|path| {
            if path.state.get() != QuicPathState::Validating {
                return false;
            }

            let challenge = path.challenge.borrow();

            challenge[0] == f.data || challenge[1] == f.data
        })
        .cloned();

    let path = match path {
        Some(path) => path,
        None => {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic stale PATH_RESPONSE ignored");
            return NGX_OK;
        }
    };

    // valid:

    // RFC 9000, 9.4.  Loss Detection and Congestion Control
    //
    // On confirming a peer's ownership of its new address,
    // an endpoint MUST immediately reset the congestion controller
    // and round-trip time estimator for the new path to initial values
    // unless the only change in the peer's address is its port number.

    let mut rst = true;

    if let Some(prev) = ngx_quic_get_path(c, NGX_QUIC_PATH_BACKUP) {
        if cmp_sockaddr(&prev.sockaddr.borrow(), &path.sockaddr.borrow(), false) == NGX_OK {
            /* address did not change */
            rst = false;

            path.mtu.set(prev.mtu.get());
            path.max_mtu.set(prev.max_mtu.get());
            path.mtu_unvalidated.set(false);
        }
    }

    if rst {
        /* prevent old path packets contribution to congestion control */

        qc.rst_pnum.set(qc.send_ctx(NGX_QUIC_ENCRYPTION_APPLICATION).borrow().pnum);

        let cg = &qc.congestion;

        cg.reset();

        cg.window.set((10 * NGX_QUIC_MIN_INITIAL_SIZE).min((2 * NGX_QUIC_MIN_INITIAL_SIZE).max(14720)));
        cg.ssthresh.set(usize::MAX);
        cg.mtu.set(NGX_QUIC_MIN_INITIAL_SIZE);
        cg.recovery_start.set(times::event_msec().wrapping_sub(1));

        qc.init_rtt();
    }

    path.validated.set(true);

    ngx_quic_set_connection_path(c, &path);

    if path.mtu_unvalidated.get() {
        path.mtu_unvalidated.set(false);
        return ngx_quic_validate_path(c, &path);
    }

    // RFC 9000, 9.3.  Responding to Connection Migration
    //
    //  After verifying a new client address, the server SHOULD
    //  send new address validation tokens (Section 8) to the client.

    if ngx_quic_send_new_token(c, &path) != NGX_OK {
        return NGX_ERROR;
    }

    ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic path seq:{} addr:{} successfully validated", path.seqnum.get(), B(&path.addr_text.borrow()));

    ngx_quic_path_dbg(c, "is validated", &path);

    ngx_quic_discover_path_mtu(c, &path);

    NGX_OK
}

/// ngx_quic_new_path
pub fn ngx_quic_new_path(c: &Connection, sockaddr: &SockAddr, cid: Rc<QuicClientId>) -> Rc<QuicPath> {
    let qc = ngx_quic_get_connection(c).expect("quic connection");

    cid.used.set(true);

    let seqnum = qc.path_seqnum.get();
    qc.path_seqnum.set(seqnum + 1);

    let path = Rc::new(QuicPath {
        sockaddr: RefCell::new(sockaddr.clone()),
        cid: RefCell::new(Some(cid)),
        state: Cell::new(QuicPathState::Idle),
        expires: Cell::new(0),
        tries: Cell::new(0),
        tag: Cell::new(0),
        mtu: Cell::new(NGX_QUIC_MIN_INITIAL_SIZE),
        mtud: Cell::new(0),
        max_mtu: Cell::new(0),
        sent: Cell::new(0),
        received: Cell::new(0),
        challenge: RefCell::new([[0; 8]; 2]),
        seqnum: Cell::new(seqnum),
        mtu_pnum: RefCell::new([0; NGX_QUIC_PATH_RETRIES as usize]),
        addr_text: RefCell::new(sockaddr.to_text(true)),
        validated: Cell::new(false),
        mtu_unvalidated: Cell::new(false),
    });

    qc.paths.borrow_mut().push(path.clone());

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} created addr:{}", seqnum, B(&path.addr_text.borrow()));

    path
}

/// ngx_quic_get_path
fn ngx_quic_get_path(c: &Connection, tag: u64) -> Option<Rc<QuicPath>> {
    let qc = ngx_quic_get_connection(c)?;

    let path = qc.paths.borrow().iter().find(|path| path.tag.get() == tag).cloned();

    path
}

/// ngx_quic_set_path
pub fn ngx_quic_set_path(c: &Rc<Connection>, pkt: &mut QuicHeader<'_>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let qsock = match ngx_quic_get_socket(c) {
        Some(qsock) => qsock,
        None => return NGX_ERROR,
    };

    let len = pkt.raw.len() as i64;

    let path = 'found: {
        if !qc.udp_buffer.get() {
            /* first ever packet in connection, path already exists  */
            break 'found qc.path();
        }

        let mut probe = None;

        let paths = qc.paths.borrow().clone();

        for path in paths {
            if cmp_sockaddr(&qsock.sockaddr.borrow(), &path.sockaddr.borrow(), true) == NGX_OK {
                break 'found path;
            }

            if path.tag.get() == NGX_QUIC_PATH_PROBE {
                probe = Some(path);
            }
        }

        /* packet from new path, drop current probe, if any */

        // only accept highest-numbered packets to prevent connection id
        // exhaustion by excessive probing packets from unknown paths
        if pkt.pn != qc.send_ctx(pkt.level).borrow().largest_pn {
            return NGX_DONE;
        }

        if let Some(probe) = probe {
            if ngx_quic_free_path(c, &probe) != NGX_OK {
                return NGX_ERROR;
            }
        }

        /* new path requires new client id */
        let cid = match ngx_quic_next_client_id(c) {
            Some(cid) => cid,
            None => {
                ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic no available client ids for new path");
                /* stop processing of this datagram */
                return NGX_DONE;
            }
        };

        let sockaddr = qsock.sockaddr.borrow().clone();

        let path = ngx_quic_new_path(c, &sockaddr, cid);

        path.tag.set(NGX_QUIC_PATH_PROBE);

        // client arrived using new path and previously seen DCID,
        // this indicates NAT rebinding (or bad client)
        if qsock.used.get() {
            pkt.rebound = true;
        }

        path
    };

    // update:

    qsock.used.set(true);
    pkt.path = Some(path.clone());

    // TODO: this may be too late in some cases;
    //       for example, if error happens during decrypt(), we cannot
    //       send CC, if error happens in 1st packet, due to amplification
    //       limit, because path->received = 0
    //
    //       should we account garbage as received or only decrypting packets?
    path.received.set(path.received.get() + len);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic packet len:{} via sock seq:{} path seq:{}", len, qsock.sid.borrow().seqnum as i64, path.seqnum.get());
    ngx_quic_path_dbg(c, "status", &path);

    NGX_OK
}

/// ngx_quic_free_path
pub fn ngx_quic_free_path(c: &Connection, path: &Rc<QuicPath>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    qc.paths.borrow_mut().retain(|p| !Rc::ptr_eq(p, path));

    // invalidate CID that is no longer usable for any other path;
    // this also requests new CIDs from client
    let cid = path.cid.borrow().clone();

    if let Some(cid) = cid {
        if ngx_quic_free_client_id(c, &cid) != NGX_OK {
            return NGX_ERROR;
        }
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} addr:{} retired", path.seqnum.get(), B(&path.addr_text.borrow()));

    NGX_OK
}

/// ngx_quic_set_connection_path
fn ngx_quic_set_connection_path(c: &Connection, path: &QuicPath) {
    let sockaddr = path.sockaddr.borrow().clone();

    *c.addr_text.borrow_mut() = sockaddr.to_text(false);
    *c.sockaddr.borrow_mut() = sockaddr;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic send path set to seq:{} addr:{}", path.seqnum.get(), B(&path.addr_text.borrow()));
}

/// ngx_quic_handle_migration
pub fn ngx_quic_handle_migration(c: &Rc<Connection>, pkt: &QuicHeader<'_>) -> i64 {
    /* got non-probing packet via non-active path */

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    // RFC 9000, 9.3.  Responding to Connection Migration
    //
    // An endpoint only changes the address to which it sends packets in
    // response to the highest-numbered non-probing packet.
    if pkt.pn != qc.send_ctx(pkt.level).borrow().largest_pn {
        return NGX_OK;
    }

    let next = match pkt.path.clone() {
        Some(p) => p,
        None => return NGX_ERROR,
    };

    // RFC 9000, 9.3.3:
    //
    // In response to an apparent migration, endpoints MUST validate the
    // previously active path using a PATH_CHALLENGE frame.
    if pkt.rebound {
        /* NAT rebinding: client uses new path with old SID */
        if ngx_quic_validate_path(c, &qc.path()) != NGX_OK {
            return NGX_ERROR;
        }
    }

    let active = qc.path();

    if active.validated.get() {
        if next.tag.get() != NGX_QUIC_PATH_BACKUP {
            /* can delete backup path, if any */
            if let Some(bkp) = ngx_quic_get_path(c, NGX_QUIC_PATH_BACKUP) {
                if ngx_quic_free_path(c, &bkp) != NGX_OK {
                    return NGX_ERROR;
                }
            }
        }

        active.tag.set(NGX_QUIC_PATH_BACKUP);
        ngx_quic_path_dbg(c, "is now backup", &active);
    } else if ngx_quic_free_path(c, &active) != NGX_OK {
        return NGX_ERROR;
    }

    /* switch active path to migrated */
    *qc.path.borrow_mut() = Some(next.clone());
    next.tag.set(NGX_QUIC_PATH_ACTIVE);

    if next.validated.get() {
        ngx_quic_set_connection_path(c, &next);
    } else if next.state.get() != QuicPathState::Validating && ngx_quic_validate_path(c, &next) != NGX_OK {
        return NGX_ERROR;
    }

    ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic migrated to path seq:{} addr:{}", next.seqnum.get(), B(&next.addr_text.borrow()));

    ngx_quic_path_dbg(c, "is now active", &next);

    NGX_OK
}

/// ngx_quic_validate_path
fn ngx_quic_validate_path(c: &Rc<Connection>, path: &Rc<QuicPath>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic initiated validation of path seq:{}", path.seqnum.get());

    path.tries.set(0);

    {
        let mut challenge = path.challenge.borrow_mut();

        // SAFETY: the challenge is 16 bytes
        if unsafe { RAND_bytes(challenge.as_mut_ptr() as *mut u8, 16) } != 1 {
            return NGX_ERROR;
        }
    }

    let _ = ngx_quic_send_path_challenge(c, path);

    let pto = ngx_quic_pto(c, NGX_QUIC_ENCRYPTION_APPLICATION).max(1000);

    let _ = qc;

    path.expires.set(times::event_msec().wrapping_add(pto));
    path.state.set(QuicPathState::Validating);

    ngx_quic_set_path_timer(c);

    NGX_OK
}

/// ngx_quic_send_path_challenge
fn ngx_quic_send_path_challenge(c: &Rc<Connection>, path: &Rc<QuicPath>) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} send path_challenge tries:{}", path.seqnum.get(), path.tries.get());

    for n in 0..2 {
        let mut frame = match ngx_quic_alloc_frame(c) {
            Some(f) => f,
            None => return NGX_ERROR,
        };

        frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
        frame.ty = NGX_QUIC_FT_PATH_CHALLENGE;

        frame.u.path_challenge.data = path.challenge.borrow()[n];

        // RFC 9000, 8.2.1.  Initiating Path Validation
        //
        // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
        // to at least the smallest allowed maximum datagram size of 1200 bytes,
        // unless the anti-amplification limit for the path does not permit
        // sending a datagram of this size.

        let min = if path.mtu_unvalidated.get() || ngx_quic_path_limit(c, path, 1200) < 1200 {
            path.mtu_unvalidated.set(true);
            0
        } else {
            1200
        };

        if ngx_quic_frame_sendto(c, frame, min, path) == NGX_ERROR {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

/// ngx_quic_discover_path_mtu
pub fn ngx_quic_discover_path_mtu(c: &Rc<Connection>, path: &Rc<QuicPath>) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    if path.max_mtu.get() != 0 {
        if path.max_mtu.get().wrapping_sub(path.mtu.get()) <= NGX_QUIC_PATH_MTU_PRECISION {
            path.state.set(QuicPathState::Idle);
            ngx_quic_set_path_timer(c);
            return;
        }

        path.mtud.set((path.mtu.get() + path.max_mtu.get()) / 2);
    } else {
        path.mtud.set(path.mtu.get() * 2);

        let max = qc.ctp.borrow().max_udp_payload_size as usize;

        if path.mtud.get() >= max {
            path.mtud.set(max);
            path.max_mtu.set(max);
        }
    }

    path.state.set(QuicPathState::Waiting);
    path.expires.set(times::event_msec().wrapping_add(NGX_QUIC_PATH_MTU_DELAY));

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} schedule mtu:{}", path.seqnum.get(), path.mtud.get());

    ngx_quic_set_path_timer(c);
}

/// ngx_quic_set_path_timer
fn ngx_quic_set_path_timer(c: &Connection) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let now = times::event_msec();
    let mut next: i64 = -1;

    for path in qc.paths.borrow().iter() {
        if path.state.get() == QuicPathState::Idle {
            continue;
        }

        let left = (path.expires.get().wrapping_sub(now) as i64).max(1);

        if next == -1 || left < next {
            next = left;
        }
    }

    if next != -1 {
        qc.path_validation.add_timer(next as u64);
    } else if qc.path_validation.timer_set() {
        qc.path_validation.del_timer();
    }
}

/// ngx_quic_path_handler
pub fn ngx_quic_path_handler(c: &Rc<Connection>) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let now = times::event_msec();

    let paths = qc.paths.borrow().clone();

    for path in paths {
        if path.state.get() == QuicPathState::Idle {
            continue;
        }

        let left = path.expires.get().wrapping_sub(now) as i64;

        if left > 0 {
            continue;
        }

        let rc = match path.state.get() {
            QuicPathState::Validating => ngx_quic_expire_path_validation(c, &path),
            QuicPathState::Waiting => ngx_quic_expire_path_mtu_delay(c, &path),
            QuicPathState::Mtud => ngx_quic_expire_path_mtu_discovery(c, &path),
            _ => NGX_OK,
        };

        if rc != NGX_OK {
            ngx_quic_close_connection(c, NGX_ERROR);
            return;
        }
    }

    ngx_quic_set_path_timer(c);
}

/// ngx_quic_expire_path_validation
fn ngx_quic_expire_path_validation(c: &Rc<Connection>, path: &Rc<QuicPath>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    path.tries.set(path.tries.get() + 1);

    if path.tries.get() < NGX_QUIC_PATH_RETRIES {
        let pto = ngx_quic_pto(c, NGX_QUIC_ENCRYPTION_APPLICATION).max(1000) << path.tries.get();
        path.expires.set(times::event_msec().wrapping_add(pto));

        let _ = ngx_quic_send_path_challenge(c, path);

        return NGX_OK;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} validation failed", path.seqnum.get());

    /* found expired path */

    path.validated.set(false);

    // RFC 9000, 9.3.2.  On-Path Address Spoofing
    //
    // To protect the connection from failing due to such a spurious
    // migration, an endpoint MUST revert to using the last validated
    // peer address when validation of a new peer address fails.

    if Rc::ptr_eq(&qc.path(), path) {
        /* active path validation failed */

        let bkp = match ngx_quic_get_path(c, NGX_QUIC_PATH_BACKUP) {
            Some(bkp) => bkp,
            None => {
                qc.error.set(NGX_QUIC_ERR_NO_VIABLE_PATH);
                qc.error_reason.set(Some("no viable path"));
                return NGX_ERROR;
            }
        };

        *qc.path.borrow_mut() = Some(bkp.clone());
        bkp.tag.set(NGX_QUIC_PATH_ACTIVE);

        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic path seq:{} addr:{} is restored from backup", bkp.seqnum.get(), B(&bkp.addr_text.borrow()));

        ngx_quic_path_dbg(c, "is active", &bkp);
    }

    ngx_quic_free_path(c, path)
}

/// ngx_quic_expire_path_mtu_delay
fn ngx_quic_expire_path_mtu_delay(c: &Rc<Connection>, path: &Rc<QuicPath>) -> i64 {
    path.tries.set(0);

    loop {
        *path.mtu_pnum.borrow_mut() = [NGX_QUIC_UNSET_PN; NGX_QUIC_PATH_RETRIES as usize];

        let rc = ngx_quic_send_path_mtu_probe(c, path);

        if rc == NGX_ERROR {
            return NGX_ERROR;
        }

        if rc == NGX_OK {
            let pto = ngx_quic_pto(c, NGX_QUIC_ENCRYPTION_APPLICATION);
            path.expires.set(times::event_msec().wrapping_add(pto));
            path.state.set(QuicPathState::Mtud);
            return NGX_OK;
        }

        /* rc == NGX_DECLINED */

        path.max_mtu.set(path.mtud.get());

        if path.max_mtu.get().wrapping_sub(path.mtu.get()) <= NGX_QUIC_PATH_MTU_PRECISION {
            path.state.set(QuicPathState::Idle);
            return NGX_OK;
        }

        path.mtud.set((path.mtu.get() + path.max_mtu.get()) / 2);
    }
}

/// ngx_quic_expire_path_mtu_discovery
fn ngx_quic_expire_path_mtu_discovery(c: &Rc<Connection>, path: &Rc<QuicPath>) -> i64 {
    path.tries.set(path.tries.get() + 1);

    if path.tries.get() < NGX_QUIC_PATH_RETRIES {
        let rc = ngx_quic_send_path_mtu_probe(c, path);

        if rc == NGX_ERROR {
            return NGX_ERROR;
        }

        if rc == NGX_OK {
            let pto = ngx_quic_pto(c, NGX_QUIC_ENCRYPTION_APPLICATION) << path.tries.get();
            path.expires.set(times::event_msec().wrapping_add(pto));
            return NGX_OK;
        }

        /* rc == NGX_DECLINED */
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} expired mtu:{}", path.seqnum.get(), path.mtud.get());

    path.max_mtu.set(path.mtud.get());

    ngx_quic_discover_path_mtu(c, path);

    NGX_OK
}

/// ngx_quic_send_path_mtu_probe
fn ngx_quic_send_path_mtu_probe(c: &Rc<Connection>, path: &Rc<QuicPath>) -> i64 {
    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_PING;
    frame.ignore_loss = true;
    frame.ignore_congestion = true;

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let pnum = qc.send_ctx(NGX_QUIC_ENCRYPTION_APPLICATION).borrow().pnum;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} send probe mtu:{} pnum:{} tries:{}", path.seqnum.get(), path.mtud.get(), pnum, path.tries.get());

    let log_error = c.log_error.get();
    c.log_error.set(NGX_ERROR_IGNORE_EMSGSIZE);

    let mtu = path.mtu.get();
    path.mtu.set(path.mtud.get());

    let rc = ngx_quic_frame_sendto(c, frame, path.mtud.get(), path);

    path.mtu.set(mtu);
    c.log_error.set(log_error);

    if rc == NGX_OK {
        path.mtu_pnum.borrow_mut()[path.tries.get() as usize] = pnum;
        return NGX_OK;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} rejected mtu:{}", path.seqnum.get(), path.mtud.get());

    if rc == NGX_ERROR {
        if qc.write_error.get() {
            qc.write_error.set(false);
            return NGX_DECLINED;
        }

        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_handle_path_mtu
pub fn ngx_quic_handle_path_mtu(c: &Rc<Connection>, path: &Rc<QuicPath>, min: u64, max: u64) -> i64 {
    if path.state.get() != QuicPathState::Mtud {
        return NGX_OK;
    }

    let pnums = *path.mtu_pnum.borrow();

    for pnum in pnums {
        if pnum == NGX_QUIC_UNSET_PN {
            continue;
        }

        if pnum < min || pnum > max {
            continue;
        }

        path.mtu.set(path.mtud.get());

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic path seq:{} ack mtu:{}", path.seqnum.get(), path.mtu.get());

        ngx_quic_discover_path_mtu(c, path);

        break;
    }

    NGX_OK
}
