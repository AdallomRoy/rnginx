//! ngx_event_quic_output.c: packets out: the frames queued are sent in
//! datagrams (segments with GSO); the packets sent without a connection
//! (Version Negotiation, Stateless Reset, early CONNECTION_CLOSE, Retry);
//! acknowledgments.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::connection::Connection;
use crate::event_udp::{cmsg_space_addrinfo, set_srcaddr_cmsg, CmsgBuf};
use crate::inet::SockAddr;
use crate::log::*;
use crate::openssl_ffi::RAND_bytes;
use crate::rc::*;
use crate::times;
use crate::{ngx_log_debug, ngx_log_error, os};

use super::ack::{ngx_quic_congestion_idle, ngx_quic_generate_ack, ngx_quic_set_lost_timer};
use super::frames::*;
use super::protection::*;
use super::tokens::{ngx_quic_new_sr_token, ngx_quic_new_token};
use super::transport::*;
use super::{ngx_quic_address_hash, ngx_quic_get_connection, QuicConf, QuicConnection, QuicPath, QuicSendCtx, NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_ENCRYPTION_HANDSHAKE, NGX_QUIC_ENCRYPTION_INITIAL, NGX_QUIC_MAX_UDP_PAYLOAD_SIZE, NGX_QUIC_MIN_INITIAL_SIZE, NGX_QUIC_SEND_CTX_LAST, NGX_QUIC_SR_TOKEN_LEN};

const NGX_QUIC_MAX_UDP_SEGMENT_BUF: usize = 65487; /* 65K - IPv6 header */
const NGX_QUIC_MAX_SEGMENTS: usize = 64; /* UDP_MAX_SEGMENTS */

const NGX_QUIC_RETRY_TOKEN_LIFETIME: i64 = 3; /* seconds */
const NGX_QUIC_NEW_TOKEN_LIFETIME: i64 = 600; /* seconds */

// RFC 9000, 10.3.  Stateless Reset
//
// Endpoints MUST discard packets that are too small to be valid QUIC
// packets.  With the set of AEAD functions defined in [QUIC-TLS],
// short header packets that are smaller than 21 bytes are never valid.
const NGX_QUIC_MIN_PKT_LEN: usize = 41; /* 21 + 20 (server cid length) */

const NGX_QUIC_MIN_SR_PACKET: usize = 43; /* 5 rand + 16 srt + 22 padding */
const NGX_QUIC_MAX_SR_PACKET: usize = 1200;

const NGX_QUIC_CC_MIN_INTERVAL: u64 = 1000; /* 1s */

const NGX_QUIC_SOCKET_RETRY_DELAY: u64 = 10; /* ms, for NGX_AGAIN on write */

/// ngx_quic_log_packet
fn ngx_quic_log_packet(log: &Log, pkt: &QuicHeader<'_>) {
    ngx_log_debug!(
        NGX_LOG_DEBUG_EVENT,
        log,
        "quic packet tx {} bytes:{} need_ack:{} number:{} encoded nl:{} trunc:0x{:x}",
        ngx_quic_level_name(pkt.level),
        pkt.payload.len(),
        pkt.need_ack as i32,
        pkt.number as i64,
        pkt.num_len,
        pkt.trunc
    );
}

/// ngx_quic_output
pub fn ngx_quic_output(c: &Rc<Connection>) -> i64 {
    c.log.set_action(Some("sending frames"));

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let cg = &qc.congestion;

    let in_flight = cg.in_flight.get();

    let rc = if ngx_quic_allow_segmentation(&qc) { ngx_quic_create_segments(c, &qc) } else { ngx_quic_create_datagrams(c, &qc) };

    if rc != NGX_OK {
        return NGX_ERROR;
    }

    if in_flight == cg.in_flight.get() || qc.closing.get() {
        /* no ack-eliciting data was sent or we are done */
        return NGX_OK;
    }

    if !qc.send_timer_set.get() {
        qc.send_timer_set.set(true);
        let idle = qc.tp.borrow().max_idle_timeout;
        qc.read.add_timer(idle);
    }

    ngx_quic_set_lost_timer(c);

    NGX_OK
}

/// ngx_quic_create_datagrams
fn ngx_quic_create_datagrams(c: &Rc<Connection>, qc: &QuicConnection) -> i64 {
    let cg = &qc.congestion;
    let path = qc.path();

    let mut preserved_pnum = [0u64; NGX_QUIC_SEND_CTX_LAST];

    let mut dst: Vec<u8> = Vec::with_capacity(NGX_QUIC_MAX_UDP_PAYLOAD_SIZE);

    loop {
        dst.clear();

        let mut len = ngx_quic_path_limit(c, &path, path.mtu.get());

        let pad = ngx_quic_get_padding_level(qc);

        for i in 0..NGX_QUIC_SEND_CTX_LAST {
            {
                let mut ctx = qc.send_ctx[i].borrow_mut();

                preserved_pnum[i] = ctx.pnum;

                if ngx_quic_generate_ack(c, qc, &mut ctx) != NGX_OK {
                    return NGX_ERROR;
                }
            }

            let min = if i == pad && dst.len() < NGX_QUIC_MIN_INITIAL_SIZE { NGX_QUIC_MIN_INITIAL_SIZE - dst.len() } else { 0 };

            if min > len {
                /* padding can't be applied - avoid sending the packet */
                ngx_quic_revert_send(c, qc, &preserved_pnum);
                return NGX_OK;
            }

            let n = ngx_quic_output_packet(c, qc, i, &mut dst, len, min, cg.in_flight.get() >= cg.window.get());
            if n == NGX_ERROR as isize {
                return NGX_ERROR;
            }

            len -= n as usize;
        }

        let len = dst.len();
        if len == 0 {
            break;
        }

        let sockaddr = path.sockaddr.borrow().clone();

        let n = ngx_quic_send(c, &dst, &sockaddr);

        if n == NGX_ERROR as isize {
            return NGX_ERROR;
        }

        if n == NGX_AGAIN as isize {
            ngx_quic_revert_send(c, qc, &preserved_pnum);
            qc.push.add_timer(NGX_QUIC_SOCKET_RETRY_DELAY);
            break;
        }

        ngx_quic_commit_send(c, qc);

        path.sent.set(path.sent.get() + len as i64);

        if cg.in_flight.get() >= cg.window.get() {
            break;
        }
    }

    NGX_OK
}

/// ngx_quic_commit_send
fn ngx_quic_commit_send(c: &Connection, qc: &QuicConnection) {
    let cg = &qc.congestion;

    let mut idle = true;

    for i in 0..NGX_QUIC_SEND_CTX_LAST {
        let sending = {
            let mut ctx = qc.send_ctx[i].borrow_mut();

            if !ctx.frames.is_empty() {
                idle = false;
            }

            std::mem::take(&mut ctx.sending)
        };

        for f in sending {
            if f.pkt_need_ack && !qc.closing.get() {
                cg.in_flight.set(cg.in_flight.get() + f.plen);

                qc.send_ctx[i].borrow_mut().sent.push_back(f);
            } else {
                ngx_quic_free_frame(c, f);
            }
        }
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion send if:{}", cg.in_flight.get());

    ngx_quic_congestion_idle(c, idle);
}

/// ngx_quic_revert_send
fn ngx_quic_revert_send(c: &Connection, qc: &QuicConnection, pnum: &[u64; NGX_QUIC_SEND_CTX_LAST]) {
    for i in 0..NGX_QUIC_SEND_CTX_LAST {
        let mut ctx = qc.send_ctx[i].borrow_mut();

        if ctx.sending.is_empty() {
            continue;
        }

        while let Some(f) = ctx.sending.pop_back() {
            ctx.frames.push_front(f);
        }

        ctx.pnum = pnum[i];
    }

    ngx_quic_congestion_idle(c, true);
}

/// ngx_quic_allow_segmentation
fn ngx_quic_allow_segmentation(qc: &QuicConnection) -> bool {
    if !qc.conf.gso_enabled {
        return false;
    }

    let path = qc.path();

    if !path.validated.get() {
        /* don't even try to be faster on non-validated paths */
        return false;
    }

    if !qc.send_ctx(NGX_QUIC_ENCRYPTION_INITIAL).borrow().frames.is_empty() {
        return false;
    }

    if !qc.send_ctx(NGX_QUIC_ENCRYPTION_HANDSHAKE).borrow().frames.is_empty() {
        return false;
    }

    let ctx = qc.send_ctx(NGX_QUIC_ENCRYPTION_APPLICATION).borrow();

    let mut bytes = 0usize;
    let len = path.mtu.get().min(NGX_QUIC_MAX_UDP_SEGMENT_BUF);

    for f in ctx.frames.iter() {
        bytes += f.len as usize;

        if qc.congestion.in_flight.get() + bytes >= qc.congestion.window.get() {
            return false;
        }

        if bytes > len * 3 {
            /* require at least ~3 full packets to batch */
            return true;
        }
    }

    false
}

/// ngx_quic_create_segments
fn ngx_quic_create_segments(c: &Rc<Connection>, qc: &QuicConnection) -> i64 {
    let cg = &qc.congestion;
    let path = qc.path();

    let level = 2; /* ctx - qc->send_ctx: the application context */

    {
        let mut ctx = qc.send_ctx[level].borrow_mut();

        if ngx_quic_generate_ack(c, qc, &mut ctx) != NGX_OK {
            return NGX_ERROR;
        }
    }

    let segsize = path.mtu.get().min(NGX_QUIC_MAX_UDP_SEGMENT_BUF);

    let mut dst: Vec<u8> = Vec::with_capacity(NGX_QUIC_MAX_UDP_SEGMENT_BUF);

    let mut nseg = 0;

    let mut preserved_pnum = [0u64; NGX_QUIC_SEND_CTX_LAST];

    preserved_pnum[level] = qc.send_ctx[level].borrow().pnum;

    loop {
        let len = segsize.min(NGX_QUIC_MAX_UDP_SEGMENT_BUF - dst.len());

        let mut n: isize;

        if len != 0 && cg.in_flight.get() + dst.len() < cg.window.get() {
            n = ngx_quic_output_packet(c, qc, level, &mut dst, len, len, false);
            if n == NGX_ERROR as isize {
                return NGX_ERROR;
            }

            if n != 0 {
                nseg += 1;
            }
        } else {
            n = 0;
        }

        if dst.is_empty() {
            break;
        }

        if n == 0 || nseg == NGX_QUIC_MAX_SEGMENTS {
            let sockaddr = path.sockaddr.borrow().clone();

            n = ngx_quic_send_segments(c, &dst, &sockaddr, segsize);
            if n == NGX_ERROR as isize {
                return NGX_ERROR;
            }

            if n == NGX_AGAIN as isize {
                ngx_quic_revert_send(c, qc, &preserved_pnum);
                qc.push.add_timer(NGX_QUIC_SOCKET_RETRY_DELAY);
                break;
            }

            ngx_quic_commit_send(c, qc);

            path.sent.set(path.sent.get() + n as i64);

            dst.clear();
            nseg = 0;
            preserved_pnum[level] = qc.send_ctx[level].borrow().pnum;
        }
    }

    NGX_OK
}

/// ngx_quic_send_segments
fn ngx_quic_send_segments(c: &Connection, buf: &[u8], sockaddr: &SockAddr, segment: usize) -> isize {
    #[repr(C, align(8))]
    struct Control([u8; 128]);

    let mut control = Control([0; 128]);

    let mut iov = libc::iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() };

    let (mut ss, slen) = sockaddr.to_libc();

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    msg.msg_name = &mut ss as *mut _ as *mut libc::c_void;
    msg.msg_namelen = slen;

    msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;

    // SAFETY: the control buffer has room for both control messages
    unsafe {
        msg.msg_controllen = (libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize + cmsg_space_addrinfo()) as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);

        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;

        let mut clen = libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize;

        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, segment as u16);

        if c.listening().is_some_and(|ls| ls.wildcard.get()) {
            if let Some(local) = c.local_sockaddr.borrow().as_ref() {
                let cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                clen += set_srcaddr_cmsg(cmsg, local);
            }
        }

        msg.msg_controllen = clen as _;
    }

    let n = ngx_sendmsg(c, &msg);
    if n < 0 {
        return n;
    }

    c.sent.set(c.sent.get() + n as u64);

    n
}

/// ngx_quic_get_padding_level
fn ngx_quic_get_padding_level(qc: &QuicConnection) -> usize {
    // RFC 9000, 14.1.  Initial Datagram Size
    //
    // Similarly, a server MUST expand the payload of all UDP datagrams
    // carrying ack-eliciting Initial packets to at least the smallest
    // allowed maximum datagram size of 1200 bytes.

    let ctx = qc.send_ctx(NGX_QUIC_ENCRYPTION_INITIAL).borrow();

    for f in ctx.frames.iter() {
        if f.need_ack {
            let mut i = 0;

            while i + 1 < NGX_QUIC_SEND_CTX_LAST {
                if qc.send_ctx[i + 1].borrow().frames.is_empty() {
                    break;
                }

                i += 1;
            }

            return i;
        }
    }

    NGX_QUIC_SEND_CTX_LAST
}

/// ngx_quic_output_packet: a packet of the frames of qc->send_ctx[i]
/// appended to `out`; its length
fn ngx_quic_output_packet(c: &Connection, qc: &QuicConnection, i: usize, out: &mut Vec<u8>, max: usize, min: usize, ack_only: bool) -> isize {
    let mut ctx = qc.send_ctx[i].borrow_mut();

    if ctx.frames.is_empty() {
        return 0;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic output {} packet max:{} min:{}", ngx_quic_level_name(ctx.level), max, min);

    if !ngx_quic_keys_available(&qc.keys.borrow(), ctx.level, true) {
        ngx_log_error!(NGX_LOG_ALERT, c.log, None, "quic {} write keys discarded", ngx_quic_level_name(ctx.level));

        let frames = std::mem::take(&mut ctx.frames);

        drop(ctx);

        ngx_quic_free_frames(c, frames);

        return 0;
    }

    let path = qc.path();

    let mut pkt = QuicHeader::default();

    ngx_quic_init_packet(c, qc, &ctx, &mut pkt, &path);

    let mut min_payload = ngx_quic_payload_size(&pkt, min);
    let max_payload = ngx_quic_payload_size(&pkt, max);

    /* RFC 9001, 5.4.2.  Header Protection Sample */
    let pad = 4 - pkt.num_len as usize;
    min_payload = min_payload.max(pad);

    if min_payload > max_payload {
        return 0;
    }

    let now = times::event_msec();
    let mut nframes = 0;
    let mut src: Vec<u8> = Vec::new();

    let mut k = 0;

    while k < ctx.frames.len() {
        if ack_only && ctx.frames[k].ty != NGX_QUIC_FT_ACK {
            break;
        }

        let len = src.len();

        if len >= max_payload {
            break;
        }

        if len + ctx.frames[k].len as usize > max_payload {
            let rc = ngx_quic_split_frame(c, &mut ctx.frames, k, max_payload - len);

            if rc == NGX_ERROR {
                return NGX_ERROR as isize;
            }

            if rc == NGX_DECLINED {
                break;
            }
        }

        let pnum = ctx.pnum;
        let f = &mut ctx.frames[k];

        if f.need_ack {
            pkt.need_ack = true;
        }

        f.pnum = pnum;
        f.send_time = now;
        f.plen = 0;

        ngx_quic_log_frame(&c.log, f, &[], true);

        let flen = ngx_quic_create_frame(&mut src, f);
        if flen == -1 {
            return NGX_ERROR as isize;
        }

        nframes += 1;
        k += 1;
    }

    if nframes == 0 {
        return 0;
    }

    if src.len() < min_payload {
        src.resize(min_payload, NGX_QUIC_FT_PADDING as u8);
    }

    pkt.payload = src;

    ngx_quic_log_packet(&c.log, &pkt);

    let start = out.len();

    if ngx_quic_encrypt(&pkt, out) != NGX_OK {
        return NGX_ERROR as isize;
    }

    let res_len = out.len() - start;

    ctx.pnum += 1;

    if pkt.need_ack {
        if let Some(f) = ctx.frames.front_mut() {
            f.plen = res_len;
        }
    }

    for _ in 0..nframes {
        if let Some(mut f) = ctx.frames.pop_front() {
            f.pkt_need_ack = pkt.need_ack;

            ctx.sending.push_back(f);
        }
    }

    res_len as isize
}

/// ngx_quic_init_packet
fn ngx_quic_init_packet<'a>(c: &Connection, qc: &QuicConnection, ctx: &QuicSendCtx, pkt: &mut QuicHeader<'a>, path: &QuicPath) {
    *pkt = QuicHeader::default();

    pkt.flags = NGX_QUIC_PKT_FIXED_BIT;

    if ctx.level == NGX_QUIC_ENCRYPTION_INITIAL {
        pkt.flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_INITIAL;
    } else if ctx.level == NGX_QUIC_ENCRYPTION_HANDSHAKE {
        pkt.flags |= NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_HANDSHAKE;
    } else if qc.key_phase.get() {
        pkt.flags |= NGX_QUIC_PKT_KPHASE;
    }

    pkt.dcid = path.cid.borrow().as_ref().map(|cid| cid.id.borrow().clone()).unwrap_or_default();

    pkt.scid = qc.tp.borrow().initial_scid.clone();

    pkt.version = qc.version.get();
    pkt.log = Some(c.log.clone());
    pkt.level = ctx.level;

    pkt.keys = Some(qc.keys.clone());

    ngx_quic_set_packet_number(pkt, ctx);
}

/// ngx_sendmsg: the bytes sent, NGX_AGAIN or NGX_ERROR (logged)
fn ngx_sendmsg(c: &Connection, msg: &libc::msghdr) -> isize {
    let fd = match c.listening() {
        Some(ls) => ls.fd.get(),
        None => c.fd.get(),
    };

    loop {
        // SAFETY: the message and its buffers are valid for the call
        let n = unsafe { libc::sendmsg(fd, msg, 0) };

        if n == -1 {
            let err = os::errno();

            match err {
                libc::EAGAIN => {
                    if c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
                        c.log.error(NGX_LOG_DEBUG, Some(err), format_args!("sendmsg() not ready"));
                    }

                    return NGX_AGAIN as isize;
                }

                libc::EINTR => {
                    if c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
                        c.log.error(NGX_LOG_DEBUG, Some(err), format_args!("sendmsg() was interrupted"));
                    }

                    continue;
                }

                _ => {
                    if let Some(qc) = ngx_quic_get_connection(c) {
                        qc.write_error.set(true);
                    }

                    c.connection_error(err, "sendmsg() failed");
                    return NGX_ERROR as isize;
                }
            }
        }

        if c.log.debug_enabled(NGX_LOG_DEBUG_EVENT) {
            let size: usize = (0..msg.msg_iovlen as usize).map(|i| unsafe { (*msg.msg_iov.add(i)).iov_len }).sum();
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "sendmsg: {} of {}", n, size);
        }

        return n;
    }
}

/// ngx_quic_send: a datagram to the address
fn ngx_quic_send(c: &Connection, buf: &[u8], sockaddr: &SockAddr) -> isize {
    let mut iov = libc::iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() };

    let (mut ss, slen) = sockaddr.to_libc();

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    msg.msg_name = &mut ss as *mut _ as *mut libc::c_void;
    msg.msg_namelen = slen;

    let mut control = CmsgBuf::default();

    if c.listening().is_some_and(|ls| ls.wildcard.get()) {
        if let Some(local) = c.local_sockaddr.borrow().as_ref() {
            msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_space_addrinfo() as _;

            // SAFETY: the control buffer has room for ngx_addrinfo_t
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                msg.msg_controllen = set_srcaddr_cmsg(cmsg, local) as _;
            }
        }
    }

    let n = ngx_sendmsg(c, &msg);
    if n < 0 {
        return n;
    }

    c.sent.set(c.sent.get() + n as u64);

    n
}

/// ngx_quic_set_packet_number
fn ngx_quic_set_packet_number(pkt: &mut QuicHeader<'_>, ctx: &QuicSendCtx) {
    let delta = ctx.pnum.wrapping_sub(ctx.largest_ack);
    pkt.number = ctx.pnum;

    if delta <= 0x7F {
        pkt.num_len = 1;
        pkt.trunc = (ctx.pnum & 0xff) as u32;
    } else if delta <= 0x7FFF {
        pkt.num_len = 2;
        pkt.flags |= 0x1;
        pkt.trunc = (ctx.pnum & 0xffff) as u32;
    } else if delta <= 0x7FFFFF {
        pkt.num_len = 3;
        pkt.flags |= 0x2;
        pkt.trunc = (ctx.pnum & 0xffffff) as u32;
    } else {
        pkt.num_len = 4;
        pkt.flags |= 0x3;
        pkt.trunc = (ctx.pnum & 0xffffffff) as u32;
    }
}

/// ngx_quic_negotiate_version
pub fn ngx_quic_negotiate_version(c: &Connection, inpkt: &QuicHeader<'_>) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "sending version negotiation packet");

    let pkt = QuicHeader { log: Some(c.log.clone()), flags: NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_FIXED_BIT, dcid: inpkt.scid.clone(), scid: inpkt.dcid.clone(), ..Default::default() };

    let mut buf = Vec::new();

    ngx_quic_create_version_negotiation(&pkt, &mut buf);

    let sockaddr = c.sockaddr.borrow().clone();

    let _ = ngx_quic_send(c, &buf, &sockaddr);

    NGX_DONE
}

/// ngx_quic_send_stateless_reset
pub fn ngx_quic_send_stateless_reset(c: &Connection, conf: &QuicConf, pkt: &QuicHeader<'_>) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic handle stateless reset output");

    if pkt.len <= NGX_QUIC_MIN_PKT_LEN {
        return NGX_DECLINED;
    }

    let rc = ngx_quic_stateless_reset_filter(c);
    if rc != NGX_OK {
        return rc;
    }

    let len = if pkt.len <= NGX_QUIC_MIN_SR_PACKET {
        pkt.len - 1
    } else {
        let max = NGX_QUIC_MAX_SR_PACKET.min(pkt.len);

        let mut rndbytes = [0u8; 2];

        // SAFETY: two bytes
        if unsafe { RAND_bytes(rndbytes.as_mut_ptr(), 2) } != 1 {
            return NGX_ERROR;
        }

        (u16::from_ne_bytes(rndbytes) as usize % (max - NGX_QUIC_MIN_SR_PACKET)) + NGX_QUIC_MIN_SR_PACKET
    };

    let mut buf = vec![0u8; len];

    // SAFETY: the buffer has len bytes
    if unsafe { RAND_bytes(buf.as_mut_ptr(), (len - NGX_QUIC_SR_TOKEN_LEN) as i32) } != 1 {
        return NGX_ERROR;
    }

    buf[0] &= !NGX_QUIC_PKT_LONG;
    buf[0] |= NGX_QUIC_PKT_FIXED_BIT;

    let mut token = [0u8; NGX_QUIC_SR_TOKEN_LEN];

    if ngx_quic_new_sr_token(c, &pkt.dcid, &conf.sr_token_key, &mut token) != NGX_OK {
        return NGX_ERROR;
    }

    buf[len - NGX_QUIC_SR_TOKEN_LEN..].copy_from_slice(&token);

    let sockaddr = c.sockaddr.borrow().clone();

    let _ = ngx_quic_send(c, &buf, &sockaddr);

    NGX_DECLINED
}

thread_local! {
    /// the static variables of ngx_quic_stateless_reset_filter
    static SR_FILTER: RefCell<(i64, u8, Vec<u8>)> = RefCell::new((0, 0, vec![0u8; 65536]));
}

/// ngx_quic_stateless_reset_filter
fn ngx_quic_stateless_reset_filter(c: &Connection) -> i64 {
    let now = times::cached().sec;

    SR_FILTER.with(|s| {
        let mut s = s.borrow_mut();
        let (t, rndbyte, bitmap) = &mut *s;

        if *t != now {
            *t = now;

            // SAFETY: one byte
            if unsafe { RAND_bytes(rndbyte, 1) } != 1 {
                return NGX_ERROR;
            }

            bitmap.iter_mut().for_each(|b| *b = 0);
        }

        let mut hit = 0;

        for i in 0..3u8 {
            let salt = rndbyte.wrapping_add(i);

            let hash = ngx_quic_address_hash(&c.sockaddr.borrow(), false, Some(&[salt]));

            let n = hash[0] as usize | (hash[1] as usize) << 8;
            let m = 1u8 << (hash[2] % 8);

            if bitmap[n] & m == 0 {
                bitmap[n] |= m;
            } else {
                hit += 1;
            }
        }

        if hit == 3 {
            return NGX_DECLINED;
        }

        NGX_OK
    })
}

/// ngx_quic_send_cc
pub fn ngx_quic_send_cc(c: &Rc<Connection>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    if qc.draining.get() {
        return NGX_OK;
    }

    if qc.closing.get() && times::event_msec().wrapping_sub(qc.last_cc.get()) < NGX_QUIC_CC_MIN_INTERVAL {
        /* dot not send CC too often */
        return NGX_OK;
    }

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = qc.error_level.get();
    frame.ty = if qc.error_app.get() { NGX_QUIC_FT_CONNECTION_CLOSE_APP } else { NGX_QUIC_FT_CONNECTION_CLOSE };
    frame.u.close.error_code = qc.error.get();
    frame.u.close.frame_type = qc.error_ftype.get();

    if let Some(reason) = qc.error_reason.get() {
        frame.u.close.reason = reason.as_bytes().to_vec();
    }

    frame.ignore_congestion = true;

    qc.last_cc.set(times::event_msec());

    ngx_quic_frame_sendto(c, frame, 0, &qc.path())
}

/// ngx_quic_send_early_cc
pub fn ngx_quic_send_early_cc(c: &Connection, inpkt: &QuicHeader<'_>, err: u64, reason: &str) -> i64 {
    let mut frame = QuicFrame { level: inpkt.level, ty: NGX_QUIC_FT_CONNECTION_CLOSE, ..Default::default() };

    frame.u.close.error_code = err;
    frame.u.close.reason = reason.as_bytes().to_vec();

    ngx_quic_log_frame(&c.log, &frame, &[], true);

    let len = ngx_quic_frame_len(&mut frame);
    if len as usize > NGX_QUIC_MAX_UDP_PAYLOAD_SIZE {
        return NGX_ERROR;
    }

    let mut src = Vec::new();

    let len = ngx_quic_create_frame(&mut src, &mut frame);
    if len == -1 {
        return NGX_ERROR;
    }

    let keys = Rc::new(RefCell::new(QuicKeys::default()));

    if ngx_quic_keys_set_initial_secret(&mut keys.borrow_mut(), &inpkt.dcid, &c.log) != NGX_OK {
        return NGX_ERROR;
    }

    let pkt = QuicHeader {
        keys: Some(keys.clone()),
        flags: NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_INITIAL,
        num_len: 1,
        // pkt.num = 0;
        // pkt.trunc = 0;
        version: inpkt.version,
        log: Some(c.log.clone()),
        level: inpkt.level,
        dcid: inpkt.scid.clone(),
        scid: inpkt.dcid.clone(),
        payload: src,
        ..Default::default()
    };

    let mut res = Vec::new();

    ngx_quic_log_packet(&c.log, &pkt);

    if ngx_quic_encrypt(&pkt, &mut res) != NGX_OK {
        ngx_quic_keys_cleanup(&mut keys.borrow_mut());
        return NGX_ERROR;
    }

    let sockaddr = c.sockaddr.borrow().clone();

    if ngx_quic_send(c, &res, &sockaddr) < 0 {
        ngx_quic_keys_cleanup(&mut keys.borrow_mut());
        return NGX_ERROR;
    }

    ngx_quic_keys_cleanup(&mut keys.borrow_mut());

    NGX_DONE
}

/// ngx_quic_send_retry
pub fn ngx_quic_send_retry(c: &Connection, conf: &QuicConf, inpkt: &QuicHeader<'_>) -> i64 {
    let expires = times::cached().sec + NGX_QUIC_RETRY_TOKEN_LIFETIME;

    let sockaddr = c.sockaddr.borrow().clone();

    let token = match ngx_quic_new_token(&c.log, &sockaddr, &conf.av_token_key, Some(&inpkt.dcid), expires, true) {
        Some(t) => t,
        None => return NGX_ERROR,
    };

    /* TODO: generate routable dcid */
    let mut dcid = [0u8; NGX_QUIC_SERVER_CID_LEN];

    // SAFETY: the buffer has NGX_QUIC_SERVER_CID_LEN bytes
    if unsafe { RAND_bytes(dcid.as_mut_ptr(), NGX_QUIC_SERVER_CID_LEN as i32) } != 1 {
        return NGX_ERROR;
    }

    let pkt = QuicHeader {
        flags: NGX_QUIC_PKT_FIXED_BIT | NGX_QUIC_PKT_LONG | NGX_QUIC_PKT_RETRY,
        version: inpkt.version,
        log: Some(c.log.clone()),
        odcid: inpkt.dcid.clone(),
        dcid: inpkt.scid.clone(),
        scid: dcid.to_vec(),
        token,
        ..Default::default()
    };

    let mut res = Vec::new();

    if ngx_quic_encrypt(&pkt, &mut res) != NGX_OK {
        return NGX_ERROR;
    }

    let len = ngx_quic_send(c, &res, &sockaddr);
    if len < 0 {
        return NGX_ERROR;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic retry packet sent to {}", hex(&pkt.dcid));

    // RFC 9000, 17.2.5.1.  Sending a Retry Packet
    //
    // A server MUST NOT send more than one Retry
    // packet in response to a single UDP datagram.
    // NGX_DONE will stop quic_input() from processing further
    NGX_DONE
}

/// ngx_quic_send_new_token
pub fn ngx_quic_send_new_token(c: &Connection, path: &QuicPath) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let expires = times::cached().sec + NGX_QUIC_NEW_TOKEN_LIFETIME;

    let sockaddr = path.sockaddr.borrow().clone();

    let token = match ngx_quic_new_token(&c.log, &sockaddr, &qc.conf.av_token_key, None, expires, false) {
        Some(t) => t,
        None => return NGX_ERROR,
    };

    let out = ngx_quic_copy_buffer(c, &token);

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = NGX_QUIC_ENCRYPTION_APPLICATION;
    frame.ty = NGX_QUIC_FT_NEW_TOKEN;
    frame.data = out;
    frame.u.token.length = token.len() as u64;

    ngx_quic_queue_frame(&qc, frame);

    NGX_OK
}

/// ngx_quic_send_ack
pub fn ngx_quic_send_ack(c: &Connection, qc: &QuicConnection, ctx: &mut QuicSendCtx) -> i64 {
    let mut ack_delay = times::event_msec().wrapping_sub(ctx.largest_received);
    ack_delay = ack_delay.wrapping_mul(1000);
    ack_delay >>= qc.tp.borrow().ack_delay_exponent;

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    let mut data = QChain::default();
    let mut range = Vec::new();

    for i in 0..ctx.nranges {
        let len = ngx_quic_create_ack_range_len(ctx.ranges[i].gap, ctx.ranges[i].range);

        let left = data.0.back().map_or(0, |b| NGX_QUIC_BUFFER_SIZE - b.last);

        if left < len {
            data.0.push_back(ngx_quic_alloc_chain(c));
        }

        range.clear();
        ngx_quic_create_ack_range(&mut range, ctx.ranges[i].gap, ctx.ranges[i].range);

        if let Some(b) = data.0.back_mut() {
            b.block.borrow_mut()[b.last..b.last + range.len()].copy_from_slice(&range);
            b.last += range.len();
        }

        frame.u.ack.ranges_length += len as u64;
    }

    frame.data = data;

    frame.level = ctx.level;
    frame.ty = NGX_QUIC_FT_ACK;
    frame.u.ack.largest = ctx.largest_range;
    frame.u.ack.delay = ack_delay;
    frame.u.ack.range_count = ctx.nranges as u64;
    frame.u.ack.first_range = ctx.first_range;
    frame.len = ngx_quic_frame_len(&mut frame);

    ctx.frames.push_front(frame);

    NGX_OK
}

/// ngx_quic_send_ack_range
pub fn ngx_quic_send_ack_range(c: &Connection, level: usize, smallest: u64, largest: u64) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let mut frame = match ngx_quic_alloc_frame(c) {
        Some(f) => f,
        None => return NGX_ERROR,
    };

    frame.level = qc.send_ctx(level).borrow().level;
    frame.ty = NGX_QUIC_FT_ACK;
    frame.u.ack.largest = largest;
    frame.u.ack.delay = 0;
    frame.u.ack.range_count = 0;
    frame.u.ack.first_range = largest - smallest;

    ngx_quic_queue_frame(&qc, frame);

    NGX_OK
}

/// ngx_quic_frame_sendto
pub fn ngx_quic_frame_sendto(c: &Connection, mut frame: Box<QuicFrame>, min: usize, path: &QuicPath) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let cg = &qc.congestion;

    let now = times::event_msec();

    let max = ngx_quic_path_limit(c, path, path.mtu.get());

    let level = frame.level;

    let mut pkt = QuicHeader::default();

    {
        let ctx = qc.send_ctx(level).borrow();

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic sendto {} packet max:{} min:{}", ngx_quic_level_name(ctx.level), max, min);

        if cg.in_flight.get() >= cg.window.get() && !frame.ignore_congestion {
            drop(ctx);
            ngx_quic_free_frame(c, frame);
            return NGX_AGAIN;
        }

        ngx_quic_init_packet(c, &qc, &ctx, &mut pkt, path);
    }

    let mut min_payload = ngx_quic_payload_size(&pkt, min);
    let max_payload = ngx_quic_payload_size(&pkt, max);

    /* RFC 9001, 5.4.2.  Header Protection Sample */
    let pad = 4 - pkt.num_len as usize;
    min_payload = min_payload.max(pad);

    if min_payload > max_payload {
        ngx_quic_free_frame(c, frame);
        return NGX_AGAIN;
    }

    frame.pnum = pkt.number;

    ngx_quic_log_frame(&c.log, &frame, &[], true);

    let len = ngx_quic_frame_len(&mut frame);
    if len as usize > max_payload {
        ngx_quic_free_frame(c, frame);
        return NGX_AGAIN;
    }

    let mut src = Vec::new();

    let len = ngx_quic_create_frame(&mut src, &mut frame);
    if len == -1 {
        ngx_quic_free_frame(c, frame);
        return NGX_ERROR;
    }

    if src.len() < min_payload {
        src.resize(min_payload, NGX_QUIC_FT_PADDING as u8);
    }

    pkt.payload = src;

    let mut res = Vec::new();

    ngx_quic_log_packet(&c.log, &pkt);

    if ngx_quic_encrypt(&pkt, &mut res) != NGX_OK {
        ngx_quic_free_frame(c, frame);
        return NGX_ERROR;
    }

    {
        let mut ctx = qc.send_ctx(level).borrow_mut();

        frame.pnum = ctx.pnum;
        frame.send_time = now;
        frame.plen = res.len();

        ctx.pnum += 1;
    }

    let sockaddr = path.sockaddr.borrow().clone();

    let sent = ngx_quic_send(c, &res, &sockaddr);
    if sent < 0 {
        ngx_quic_free_frame(c, frame);
        return sent as i64;
    }

    path.sent.set(path.sent.get() + sent as i64);

    if frame.need_ack && !qc.closing.get() {
        cg.in_flight.set(cg.in_flight.get() + frame.plen);

        qc.send_ctx(level).borrow_mut().sent.push_back(frame);
    } else {
        ngx_quic_free_frame(c, frame);
        return NGX_OK;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion send if:{}", cg.in_flight.get());

    if !qc.send_timer_set.get() {
        qc.send_timer_set.set(true);
        let idle = qc.tp.borrow().max_idle_timeout;
        qc.read.add_timer(idle);
    }

    ngx_quic_set_lost_timer(c);

    NGX_OK
}

/// ngx_quic_path_limit
pub fn ngx_quic_path_limit(_c: &Connection, path: &QuicPath, size: usize) -> usize {
    if !path.validated.get() {
        let mut max = path.received.get() * 3;
        max = if path.sent.get() >= max { 0 } else { max - path.sent.get() };

        if size as i64 > max {
            return max as usize;
        }
    }

    size
}

#[allow(dead_code)]
fn _io(_: io::Error) {}
