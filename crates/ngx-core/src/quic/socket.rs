//! ngx_event_quic_socket.c: the server connection ids the connection
//! listens at (the sockets, in the lookup of the listening, udp.rs).

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use crate::connection::Connection;
use crate::log::*;
use crate::rc::*;
use crate::ngx_log_debug;

use super::connid::{ngx_quic_create_client_id, ngx_quic_create_server_id};
use super::migration::{ngx_quic_new_path, ngx_quic_path_dbg, NGX_QUIC_PATH_ACTIVE};
use super::transport::*;
use super::{ngx_quic_get_connection, QuicConnection, QuicServerId, QuicSocket, NGX_QUIC_UNSET_PN};

/// ngx_quic_open_sockets
pub fn ngx_quic_open_sockets(c: &Rc<Connection>, qc: &Rc<QuicConnection>, pkt: &QuicHeader<'_>) -> i64 {
    qc.tp.borrow_mut().original_dcid = pkt.odcid.to_vec();

    /* socket to use for further processing (id auto-generated) */
    let qsock = match ngx_quic_create_socket(c, qc) {
        Some(qsock) => qsock,
        None => return NGX_ERROR,
    };

    /* socket is listening at new server id */
    if ngx_quic_listen(c, qc, &qsock) != NGX_OK {
        return NGX_ERROR;
    }

    qsock.used.set(true);

    qc.tp.borrow_mut().initial_scid = qsock.sid.borrow().id.clone();

    /* for all packets except first, this is set at udp layer */
    *c.quic_sock.borrow_mut() = Some(qsock.clone());
    *c.quic_conn.borrow_mut() = Some(qc.clone());

    /* ngx_quic_get_connection(c) macro is now usable */

    /* we have a client identified by scid */
    let cid = ngx_quic_create_client_id(c, &pkt.scid, 0, None);

    /* path of the first packet is our initial active path */
    let sockaddr = c.sockaddr.borrow().clone();
    let path = ngx_quic_new_path(c, &sockaddr, cid);

    *qc.path.borrow_mut() = Some(path.clone());

    path.tag.set(NGX_QUIC_PATH_ACTIVE);

    if pkt.validated {
        path.validated.set(true);
    }

    ngx_quic_path_dbg(c, "set active", &path);

    let tmp = Rc::new(QuicSocket {
        quic: RefCell::new(Weak::new()),
        connection: RefCell::new(Weak::new()),
        sid: RefCell::new(QuicServerId { seqnum: NGX_QUIC_UNSET_PN, /* temporary socket */ id: pkt.dcid.to_vec() }),
        sockaddr: RefCell::new(c.sockaddr.borrow().clone()),
        used: Cell::new(false),
        key: RefCell::new(None),
    });

    if ngx_quic_listen(c, qc, &tmp) != NGX_OK {
        super::udp::ngx_quic_unlisten(c, &qsock);
        *c.quic_sock.borrow_mut() = None;
        *c.quic_conn.borrow_mut() = None;
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_quic_create_socket
pub fn ngx_quic_create_socket(c: &Connection, qc: &QuicConnection) -> Option<Rc<QuicSocket>> {
    let mut id = [0u8; NGX_QUIC_SERVER_CID_LEN];

    if ngx_quic_create_server_id(c, &mut id) != NGX_OK {
        return None;
    }

    let seqnum = qc.server_seqnum.get();
    qc.server_seqnum.set(seqnum + 1);

    Some(Rc::new(QuicSocket {
        quic: RefCell::new(Weak::new()),
        connection: RefCell::new(Weak::new()),
        sid: RefCell::new(QuicServerId { seqnum, id: id.to_vec() }),
        sockaddr: RefCell::new(c.sockaddr.borrow().clone()),
        used: Cell::new(false),
        key: RefCell::new(None),
    }))
}

/// ngx_quic_close_socket
pub fn ngx_quic_close_socket(c: &Connection, qsock: &Rc<QuicSocket>) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    qc.sockets.borrow_mut().retain(|s| !Rc::ptr_eq(s, qsock));

    super::udp::ngx_quic_unlisten(c, qsock);
    qc.nsockets.set(qc.nsockets.get() - 1);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic socket seq:{} closed nsock:{}", qsock.sid.borrow().seqnum as i64, qc.nsockets.get());
}

/// ngx_quic_listen
pub fn ngx_quic_listen(c: &Rc<Connection>, qc: &Rc<QuicConnection>, qsock: &Rc<QuicSocket>) -> i64 {
    *qsock.connection.borrow_mut() = Rc::downgrade(c);

    super::udp::ngx_quic_insert_socket(c, qsock);

    qc.sockets.borrow_mut().push(qsock.clone());

    qc.nsockets.set(qc.nsockets.get() + 1);
    *qsock.quic.borrow_mut() = Rc::downgrade(qc);

    let sid = qsock.sid.borrow();

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic socket seq:{} listening at sid:{} nsock:{}", sid.seqnum as i64, hex(&sid.id), qc.nsockets.get());

    NGX_OK
}

/// ngx_quic_close_sockets
pub fn ngx_quic_close_sockets(c: &Connection) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    loop {
        let qsock = qc.sockets.borrow().first().cloned();

        match qsock {
            Some(qsock) => ngx_quic_close_socket(c, &qsock),
            None => break,
        }
    }
}

/// ngx_quic_find_socket
pub fn ngx_quic_find_socket(c: &Connection, seqnum: u64) -> Option<Rc<QuicSocket>> {
    let qc = ngx_quic_get_connection(c)?;

    let qsock = qc.sockets.borrow().iter().find(|s| s.sid.borrow().seqnum == seqnum).cloned();

    qsock
}
