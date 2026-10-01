//! ngx_event_quic_ack.c: acknowledgments, loss detection, congestion
//! control (RFC 9002, CUBIC).

use std::rc::Rc;

use crate::connection::Connection;
use crate::log::*;
use crate::rc::*;
use crate::times;
use crate::{ngx_log_debug, ngx_log_error};

use super::frames::{ngx_quic_alloc_frame, ngx_quic_free_frame, ngx_quic_queue_frame};
use super::migration::ngx_quic_handle_path_mtu;
use super::output::{ngx_quic_frame_sendto, ngx_quic_send_ack, ngx_quic_send_ack_range};
use super::protection::ngx_quic_keys_available;
use super::streams::{ngx_quic_find_stream, ngx_quic_handle_stream_ack};
use super::transport::*;
use super::{ngx_quic_close_connection, ngx_quic_connstate_dbg, ngx_quic_get_connection, QuicConnection, QuicSendCtx, QuicStreamSendState, NGX_QUIC_ENCRYPTION_APPLICATION, NGX_QUIC_SEND_CTX_LAST, NGX_QUIC_UNSET_PN, NGX_TIMER_INFINITE};

const NGX_QUIC_MAX_ACK_GAP: u64 = 2;

/* RFC 9002, 6.1.1. Packet Threshold: kPacketThreshold */
const NGX_QUIC_PKT_THR: u64 = 3; /* packets */
/* RFC 9002, 6.1.2. Time Threshold: kGranularity */
const NGX_QUIC_TIME_GRANULARITY: u64 = 1; /* ms */

/* RFC 9002, 7.6.1. Duration: kPersistentCongestionThreshold */
const NGX_QUIC_PERSISTENT_CONGESTION_THR: u64 = 3;

/* CUBIC parameters x10 */
const NGX_QUIC_CUBIC_BETA: u64 = 7;
const NGX_QUIC_CUBIC_C: i64 = 4;

/// NGX_MAX_SIZE_T_VALUE
const NGX_MAX_SIZE_T_VALUE: i64 = i64::MAX;

/// ngx_quic_ack_stat_t: send time of ACK'ed packets
struct QuicAckStat {
    max_pn: u64,
    oldest: u64,
    newest: u64,
}

/// ngx_quic_time_threshold: RFC 9002, 6.1.2. Time Threshold: kTimeThreshold,
/// kGranularity
fn ngx_quic_time_threshold(qc: &QuicConnection) -> u64 {
    let mut thr = qc.latest_rtt.get().max(qc.avg_rtt.get());
    thr += thr >> 3;

    thr.max(NGX_QUIC_TIME_GRANULARITY)
}

/// ngx_quic_packet_threshold
fn ngx_quic_packet_threshold(ctx: &QuicSendCtx) -> u64 {
    let f = match ctx.sent.front() {
        Some(f) => f,
        None => return NGX_QUIC_PKT_THR,
    };

    let pkt_thr = ctx.pnum.wrapping_sub(f.pnum) / 2;

    if pkt_thr <= NGX_QUIC_PKT_THR {
        return NGX_QUIC_PKT_THR;
    }

    pkt_thr
}

/// c->ssl->handshaked
fn handshaked(c: &Connection) -> bool {
    c.ssl.borrow().as_ref().is_some_and(|s| s.handshaked.get())
}

/// ngx_quic_handle_ack_frame: `data` has the ACK ranges
pub fn ngx_quic_handle_ack_frame(c: &Rc<Connection>, pkt: &QuicHeader<'_>, f: &QuicFrame, data: &[u8]) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let level = pkt.level;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ngx_quic_handle_ack_frame level:{}", pkt.level);

    let ack = &f.u.ack;

    // RFC 9000, 19.3.1.  ACK Ranges
    //
    //  If any computed packet number is negative, an endpoint MUST
    //  generate a connection error of type FRAME_ENCODING_ERROR.

    if ack.first_range > ack.largest {
        qc.error.set(NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic invalid first range in ack frame");
        return NGX_ERROR;
    }

    let mut min = ack.largest - ack.first_range;
    let mut max = ack.largest;

    let mut send_time = QuicAckStat { max_pn: 0, oldest: NGX_TIMER_INFINITE, newest: NGX_TIMER_INFINITE };

    if ngx_quic_handle_ack_frame_range(c, level, min, max, &mut send_time) != NGX_OK {
        return NGX_ERROR;
    }

    /* RFC 9000, 13.2.4.  Limiting Ranges by Tracking ACK Frames */
    let update = {
        let mut ctx = qc.send_ctx(level).borrow_mut();

        if ctx.largest_ack < max || ctx.largest_ack == NGX_QUIC_UNSET_PN {
            ctx.largest_ack = max;
            true
        } else {
            false
        }
    };

    if update {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic updated largest received ack:{}", max);

        // RFC 9002, 5.1.  Generating RTT Samples
        //
        //  An endpoint generates an RTT sample on receiving an
        //  ACK frame that meets the following two conditions:
        //
        //  - the largest acknowledged packet number is newly acknowledged
        //  - at least one of the newly acknowledged packets was ack-eliciting.

        if send_time.max_pn != NGX_TIMER_INFINITE {
            ngx_quic_rtt_sample(c, ack, level, send_time.max_pn);
        }
    }

    let mut pos = 0usize;
    let end = data.len();

    for i in 0..ack.range_count {
        let mut gap = 0;
        let mut range = 0;

        let n = ngx_quic_parse_ack_range(pkt.log(), data, pos, end, &mut gap, &mut range);
        if n == NGX_ERROR as isize {
            return NGX_ERROR;
        }
        pos += n as usize;

        if gap.wrapping_add(2) > min {
            qc.error.set(NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic invalid range:{} in ack frame", i);
            return NGX_ERROR;
        }

        max = min - gap - 2;

        if range > max {
            qc.error.set(NGX_QUIC_ERR_FRAME_ENCODING_ERROR);
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic invalid range:{} in ack frame", i);
            return NGX_ERROR;
        }

        min = max - range;

        if ngx_quic_handle_ack_frame_range(c, level, min, max, &mut send_time) != NGX_OK {
            return NGX_ERROR;
        }
    }

    ngx_quic_detect_lost(c, Some(&send_time))
}

/// ngx_quic_rtt_sample
fn ngx_quic_rtt_sample(c: &Connection, ack: &QuicAckFrame, _level: usize, send_time: u64) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let now = times::event_msec();

    let latest_rtt = now.wrapping_sub(send_time);
    qc.latest_rtt.set(latest_rtt);

    if qc.min_rtt.get() == NGX_TIMER_INFINITE {
        qc.min_rtt.set(latest_rtt);
        qc.avg_rtt.set(latest_rtt);
        qc.rttvar.set(latest_rtt / 2);
        qc.first_rtt.set(now);
    } else {
        qc.min_rtt.set(qc.min_rtt.get().min(latest_rtt));

        let ctp = qc.ctp.borrow();

        let mut ack_delay = (ack.delay << ctp.ack_delay_exponent) / 1000;

        if handshaked(c) {
            ack_delay = ack_delay.min(ctp.max_ack_delay);
        }

        let mut adjusted_rtt = latest_rtt;

        if qc.min_rtt.get().wrapping_add(ack_delay) < latest_rtt {
            adjusted_rtt -= ack_delay;
        }

        let rttvar_sample = (qc.avg_rtt.get().wrapping_sub(adjusted_rtt) as i64).unsigned_abs();
        qc.rttvar.set(qc.rttvar.get().wrapping_add((rttvar_sample >> 2).wrapping_sub(qc.rttvar.get() >> 2)));
        qc.avg_rtt.set(qc.avg_rtt.get().wrapping_add((adjusted_rtt >> 3).wrapping_sub(qc.avg_rtt.get() >> 3)));
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic rtt sample latest:{} min:{} avg:{} var:{}", latest_rtt, qc.min_rtt.get(), qc.avg_rtt.get(), qc.rttvar.get());
}

/// ngx_quic_handle_ack_frame_range
fn ngx_quic_handle_ack_frame_range(c: &Rc<Connection>, level: usize, min: u64, max: u64, st: &mut QuicAckStat) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let ctx_level = qc.send_ctx(level).borrow().level;

    if ctx_level == NGX_QUIC_ENCRYPTION_APPLICATION && ngx_quic_handle_path_mtu(c, &qc.path(), min, max) != NGX_OK {
        return NGX_ERROR;
    }

    st.max_pn = NGX_TIMER_INFINITE;
    let mut found = false;

    let mut i = 0usize;

    loop {
        let f = {
            let mut ctx = qc.send_ctx(level).borrow_mut();

            while i < ctx.sent.len() && ctx.sent[i].pnum < min {
                i += 1;
            }

            if i >= ctx.sent.len() || ctx.sent[i].pnum > max {
                break;
            }

            match ctx.sent.remove(i) {
                Some(f) => f,
                None => break,
            }
        };

        ngx_quic_congestion_ack(c, &f);

        match f.ty {
            NGX_QUIC_FT_ACK | NGX_QUIC_FT_ACK_ECN => {
                ngx_quic_drop_ack_ranges(c, &mut qc.send_ctx(level).borrow_mut(), f.u.ack.largest);
            }

            NGX_QUIC_FT_STREAM | NGX_QUIC_FT_RESET_STREAM => {
                ngx_quic_handle_stream_ack(c, &f);
            }

            _ => {}
        }

        if f.pnum == max {
            st.max_pn = f.send_time;
        }

        /* save earliest and latest send times of frames ack'ed */
        if st.oldest == NGX_TIMER_INFINITE || f.send_time < st.oldest {
            st.oldest = f.send_time;
        }

        if st.newest == NGX_TIMER_INFINITE || f.send_time > st.newest {
            st.newest = f.send_time;
        }

        ngx_quic_free_frame(c, f);
        found = true;
    }

    if !found {
        if max < qc.send_ctx(level).borrow().pnum {
            /* duplicate ACK or ACK for non-ack-eliciting frame */
            return NGX_OK;
        }

        ngx_log_error!(NGX_LOG_INFO, c.log, None, "quic ACK for the packet not sent");

        qc.error.set(NGX_QUIC_ERR_PROTOCOL_VIOLATION);
        qc.error_ftype.set(NGX_QUIC_FT_ACK);
        qc.error_reason.set(Some("unknown packet number"));

        return NGX_ERROR;
    }

    if !qc.push.timer_set() {
        qc.push.post();
    }

    qc.pto_count.set(0);

    NGX_OK
}

/// ngx_quic_congestion_ack
pub fn ngx_quic_congestion_ack(c: &Connection, f: &QuicFrame) {
    if f.plen == 0 {
        return;
    }

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let cg = &qc.congestion;

    if f.pnum < qc.rst_pnum.get() {
        return;
    }

    let now = times::event_msec();

    let blocked = cg.in_flight.get() >= cg.window.get();

    cg.in_flight.set(cg.in_flight.get().wrapping_sub(f.plen));

    'done: {
        /* prevent recovery_start from wrapping */

        let timer = now.wrapping_sub(cg.recovery_start.get());

        if (timer as i64) < 0 {
            cg.recovery_start.set(ngx_quic_oldest_sent_packet(&qc).wrapping_sub(1));
        }

        let timer = f.send_time.wrapping_sub(cg.recovery_start.get());

        if (timer as i64) <= 0 {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion ack rec t:{} win:{} if:{}", now, cg.window.get(), cg.in_flight.get());

            break 'done;
        }

        if cg.idle.get() {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion ack idle t:{} win:{} if:{}", now, cg.window.get(), cg.in_flight.get());

            break 'done;
        }

        if cg.window.get() < cg.ssthresh.get() {
            cg.window.set(cg.window.get() + f.plen);

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion ack ss t:{} win:{} ss:{} if:{}", now, cg.window.get(), cg.ssthresh.get() as isize, cg.in_flight.get());
        } else {
            /* RFC 9438, 4.2. Window Increase Function */

            let w_cubic = ngx_quic_congestion_cubic(c, &qc);

            let mtu = cg.mtu.get() as u64;
            let plen = f.plen as u64;
            let window = cg.window.get() as u64;

            if cg.window.get() < cg.w_prior.get() {
                cg.w_est.set(cg.w_est.get().wrapping_add((mtu * plen * 3 * (10 - NGX_QUIC_CUBIC_BETA) / (10 + NGX_QUIC_CUBIC_BETA) / window) as usize));
            } else {
                cg.w_est.set(cg.w_est.get().wrapping_add((mtu * plen / window) as usize));
            }

            if w_cubic < cg.w_est.get() {
                cg.window.set(cg.w_est.get());

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion ack reno t:{} win:{} c:{} if:{}", now, cg.window.get(), w_cubic, cg.in_flight.get());
            } else if w_cubic > cg.window.get() {
                if w_cubic >= cg.window.get() * 3 / 2 {
                    cg.window.set(cg.window.get() + cg.mtu.get() / 2);
                } else {
                    cg.window.set(cg.window.get() + (mtu * (w_cubic - cg.window.get()) as u64 / window) as usize);
                }

                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion ack cubic t:{} win:{} c:{} if:{}", now, cg.window.get(), w_cubic, cg.in_flight.get());
            } else {
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion ack skip t:{} win:{} c:{} if:{}", now, cg.window.get(), w_cubic, cg.in_flight.get());
            }
        }
    }

    // done:

    if blocked && cg.in_flight.get() < cg.window.get() {
        qc.push.post();
    }
}

/// ngx_quic_congestion_cubic
fn ngx_quic_congestion_cubic(c: &Connection, qc: &QuicConnection) -> usize {
    let cg = &qc.congestion;

    ngx_quic_congestion_idle(c, cg.idle.get());

    let now = times::event_msec();
    let t = now.wrapping_sub(cg.k.get()) as i64;

    let w: i64 = 'done: {
        if t > 1000000 {
            break 'done NGX_MAX_SIZE_T_VALUE;
        }

        if t < -1000000 {
            break 'done 0;
        }

        // RFC 9438, Figure 1
        //
        //   w_cubic = C * (t_msec / 1000) ^ 3 * mtu + w_max

        let cc = 10000000000i64 / cg.mtu.get() as i64 / NGX_QUIC_CUBIC_C;
        let mut w = t * t * t / cc + cg.w_max.get() as i64;

        if w < 0 {
            w = 0;
        }

        w
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic cubic t:{} w:{} wm:{}", t, w, cg.w_max.get());

    w as usize
}

/// ngx_quic_congestion_idle
pub fn ngx_quic_congestion_idle(c: &Connection, idle: bool) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let cg = &qc.congestion;

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion idle:{}", idle as u32);

    if cg.window.get() >= cg.ssthresh.get() {
        /* RFC 9438, 5.8. Behavior for Application-Limited Flows */

        let now = times::event_msec();

        if cg.idle.get() {
            cg.k.set(cg.k.get().wrapping_add(now.wrapping_sub(cg.idle_start.get())));
        }

        cg.idle_start.set(now);
    }

    cg.idle.set(idle);
}

/// ngx_quic_drop_ack_ranges
fn ngx_quic_drop_ack_ranges(c: &Connection, ctx: &mut QuicSendCtx, pn: u64) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ngx_quic_drop_ack_ranges pn:{} largest:{} fr:{} nranges:{}", pn, ctx.largest_range, ctx.first_range, ctx.nranges);

    let base = ctx.largest_range;

    if base == NGX_QUIC_UNSET_PN {
        return;
    }

    if ctx.pending_ack != NGX_QUIC_UNSET_PN && pn >= ctx.pending_ack {
        ctx.pending_ack = NGX_QUIC_UNSET_PN;
    }

    let mut largest = base;
    let mut smallest = largest.wrapping_sub(ctx.first_range);

    if pn >= largest {
        ctx.largest_range = NGX_QUIC_UNSET_PN;
        ctx.first_range = 0;
        ctx.nranges = 0;
        return;
    }

    if pn >= smallest {
        ctx.first_range = largest - pn - 1;
        ctx.nranges = 0;
        return;
    }

    for i in 0..ctx.nranges {
        let r = &mut ctx.ranges[i];

        largest = smallest.wrapping_sub(r.gap).wrapping_sub(2);
        smallest = largest.wrapping_sub(r.range);

        if pn >= largest {
            ctx.nranges = i;
            return;
        }
        if pn >= smallest {
            r.range = largest - pn - 1;
            ctx.nranges = i + 1;
            return;
        }
    }
}

/// ngx_quic_detect_lost
fn ngx_quic_detect_lost(c: &Rc<Connection>, st: Option<&QuicAckStat>) -> i64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let now = times::event_msec();
    let thr = ngx_quic_time_threshold(&qc);

    let mut oldest = now;
    let mut newest = now;

    let mut nlost = 0u64;

    for i in 0..NGX_QUIC_SEND_CTX_LAST {
        let (largest_ack, pkt_thr) = {
            let ctx = qc.send_ctx[i].borrow();

            if ctx.largest_ack == NGX_QUIC_UNSET_PN {
                continue;
            }

            (ctx.largest_ack, ngx_quic_packet_threshold(&ctx))
        };

        loop {
            let (pnum, send_time, level) = {
                let ctx = qc.send_ctx[i].borrow();

                match ctx.sent.front() {
                    Some(start) => (start.pnum, start.send_time, start.level),
                    None => break,
                }
            };

            if pnum > largest_ack {
                break;
            }

            let wait = send_time.wrapping_add(thr).wrapping_sub(now);

            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic detect_lost pnum:{} thr:{} pthr:{} wait:{} level:{}", pnum, thr, pkt_thr, wait as i64, level);

            if (wait as i64) > 0 && largest_ack - pnum < pkt_thr {
                break;
            }

            if (send_time.wrapping_sub(qc.first_rtt.get()) as i64) > 0 {
                if nlost == 0 || (send_time.wrapping_sub(oldest) as i64) < 0 {
                    oldest = send_time;
                }

                if nlost == 0 || (send_time.wrapping_sub(newest) as i64) > 0 {
                    newest = send_time;
                }

                nlost += 1;
            }

            ngx_quic_resend_frames(c, i);
        }
    }

    /* RFC 9002, 7.6.2.  Establishing Persistent Congestion */

    // Once acknowledged, packets are no longer tracked. Thus no send time
    // information is available for such packets. This limits persistent
    // congestion algorithm to packets mentioned within ACK ranges of the
    // latest ACK frame.

    if let Some(st) = st {
        if nlost >= 2 && ((st.newest.wrapping_sub(oldest) as i64) < 0 || (st.oldest.wrapping_sub(newest) as i64) > 0) && newest.wrapping_sub(oldest) > ngx_quic_pcg_duration(&qc) {
            ngx_quic_persistent_congestion(c, &qc);
        }
    }

    ngx_quic_set_lost_timer(c);

    NGX_OK
}

/// ngx_quic_pcg_duration
fn ngx_quic_pcg_duration(qc: &QuicConnection) -> u64 {
    let mut duration = qc.avg_rtt.get();
    duration += (4 * qc.rttvar.get()).max(NGX_QUIC_TIME_GRANULARITY);
    duration += qc.ctp.borrow().max_ack_delay;
    duration *= NGX_QUIC_PERSISTENT_CONGESTION_THR;

    duration
}

/// ngx_quic_persistent_congestion
fn ngx_quic_persistent_congestion(c: &Connection, qc: &QuicConnection) {
    let cg = &qc.congestion;

    cg.mtu.set(qc.path().mtu.get());
    cg.recovery_start.set(ngx_quic_oldest_sent_packet(qc).wrapping_sub(1));
    cg.window.set(cg.mtu.get() * 2);

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion persistent t:{} win:{}", times::event_msec(), cg.window.get());
}

/// ngx_quic_oldest_sent_packet
fn ngx_quic_oldest_sent_packet(qc: &QuicConnection) -> u64 {
    let mut oldest = times::event_msec();

    for i in 0..NGX_QUIC_SEND_CTX_LAST {
        let ctx = qc.send_ctx[i].borrow();

        if let Some(start) = ctx.sent.front() {
            if (start.send_time.wrapping_sub(oldest) as i64) < 0 {
                oldest = start.send_time;
            }
        }
    }

    oldest
}

/// ngx_quic_resend_frames: the frames of the first packet sent in the
/// packet number space `i` (qc->send_ctx[i]) are lost
pub fn ngx_quic_resend_frames(c: &Rc<Connection>, i: usize) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let (level, mut frames) = {
        let mut ctx = qc.send_ctx[i].borrow_mut();

        let pnum = match ctx.sent.front() {
            Some(start) => start.pnum,
            None => return,
        };

        let mut frames = Vec::new();

        while ctx.sent.front().is_some_and(|f| f.pnum == pnum) {
            if let Some(f) = ctx.sent.pop_front() {
                frames.push(f);
            }
        }

        (ctx.level, frames)
    };

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic resend packet pnum:{}", frames[0].pnum);

    ngx_quic_congestion_lost(c, &mut frames[0]);

    for mut f in frames {
        match f.ty {
            NGX_QUIC_FT_ACK | NGX_QUIC_FT_ACK_ECN => {
                if level == NGX_QUIC_ENCRYPTION_APPLICATION {
                    /* force generation of most recent acknowledgment */
                    qc.send_ctx[i].borrow_mut().send_ack = NGX_QUIC_MAX_ACK_GAP;
                }

                ngx_quic_free_frame(c, f);
            }

            NGX_QUIC_FT_PING | NGX_QUIC_FT_PATH_CHALLENGE | NGX_QUIC_FT_PATH_RESPONSE | NGX_QUIC_FT_CONNECTION_CLOSE => {
                ngx_quic_free_frame(c, f);
            }

            NGX_QUIC_FT_MAX_DATA => {
                f.u.max_data.max_data = qc.streams.recv_max_data.get();
                ngx_quic_queue_frame(&qc, f);
            }

            NGX_QUIC_FT_MAX_STREAMS | NGX_QUIC_FT_MAX_STREAMS2 => {
                f.u.max_streams.limit = if f.u.max_streams.bidi { qc.streams.client_max_streams_bidi.get() } else { qc.streams.client_max_streams_uni.get() };
                ngx_quic_queue_frame(&qc, f);
            }

            NGX_QUIC_FT_MAX_STREAM_DATA => {
                let qs = match ngx_quic_find_stream(&qc, f.u.max_stream_data.id) {
                    Some(qs) => qs,
                    None => {
                        ngx_quic_free_frame(c, f);
                        continue;
                    }
                };

                f.u.max_stream_data.limit = qs.recv_max_data.get();
                ngx_quic_queue_frame(&qc, f);
            }

            NGX_QUIC_FT_STREAM => {
                let drop = match ngx_quic_find_stream(&qc, f.u.stream.stream_id) {
                    None => true,
                    Some(qs) => matches!(qs.send_state.get(), QuicStreamSendState::ResetSent | QuicStreamSendState::ResetRecvd),
                };

                if drop {
                    ngx_quic_free_frame(c, f);
                    continue;
                }

                qc.send_ctx[i].borrow_mut().frames.push_back(f);
            }

            _ => {
                qc.send_ctx[i].borrow_mut().frames.push_back(f);
            }
        }
    }

    if qc.closing.get() {
        return;
    }

    qc.push.post();
}

/// ngx_quic_congestion_lost
fn ngx_quic_congestion_lost(c: &Connection, f: &mut QuicFrame) {
    if f.plen == 0 {
        return;
    }

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let cg = &qc.congestion;

    if f.pnum < qc.rst_pnum.get() {
        return;
    }

    let blocked = cg.in_flight.get() >= cg.window.get();

    cg.in_flight.set(cg.in_flight.get().wrapping_sub(f.plen));
    f.plen = 0;

    let timer = f.send_time.wrapping_sub(cg.recovery_start.get());

    let now = times::event_msec();

    'done: {
        if (timer as i64) <= 0 {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion lost rec t:{} win:{} if:{}", now, cg.window.get(), cg.in_flight.get());

            break 'done;
        }

        if f.ignore_loss {
            ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion lost ignore t:{} win:{} if:{}", now, cg.window.get(), cg.in_flight.get());

            break 'done;
        }

        /* RFC 9438, 4.6. Multiplicative Decrease */

        cg.mtu.set(qc.path().mtu.get());
        cg.recovery_start.set(now);
        cg.w_prior.set(cg.window.get());
        /* RFC 9438, 4.7. Fast Convergence */
        cg.w_max.set(if cg.window.get() < cg.w_max.get() { cg.window.get() * (10 + NGX_QUIC_CUBIC_BETA as usize) / 20 } else { cg.window.get() });
        cg.ssthresh.set(cg.in_flight.get() * NGX_QUIC_CUBIC_BETA as usize / 10);
        cg.window.set(cg.ssthresh.get().max(cg.mtu.get() * 2));
        cg.w_est.set(cg.window.get());
        cg.k.set(now.wrapping_add(ngx_quic_congestion_cubic_time(c, &qc)));
        cg.idle_start.set(now);

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic congestion lost t:{} win:{} if:{}", now, cg.window.get(), cg.in_flight.get());
    }

    // done:

    if blocked && cg.in_flight.get() < cg.window.get() {
        qc.push.post();
    }
}

/// ngx_quic_congestion_cubic_time
fn ngx_quic_congestion_cubic_time(c: &Connection, qc: &QuicConnection) -> u64 {
    let cg = &qc.congestion;

    // RFC 9438, Figure 2
    //
    //   k_msec = ((w_max - cwnd_epoch) / C / mtu) ^ 1/3 * 1000

    if cg.w_max.get() <= cg.window.get() {
        return 0;
    }

    let cc = 10000000000i64 / cg.mtu.get() as i64 / NGX_QUIC_CUBIC_C;
    let v = (cg.w_max.get() - cg.window.get()) as i64 * cc;

    // Newton-Raphson method for x ^ 3 = v:
    //
    //   x_next = (2 * x_prev + v / x_prev ^ 2) / 3

    let mut x: i64 = 5000;
    let mut n = 1;

    while n <= 10 {
        let d = (v / x / x - x) / 3;
        x += d;

        if d.abs() <= 100 {
            break;
        }

        n += 1;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic cubic time:{} n:{}", x, n);

    x as u64
}

/// ngx_quic_set_lost_timer
pub fn ngx_quic_set_lost_timer(c: &Connection) {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let now = times::event_msec();

    let mut lost: i64 = -1;
    let mut pto: i64 = -1;

    for i in 0..NGX_QUIC_SEND_CTX_LAST {
        let ctx = qc.send_ctx[i].borrow();

        let (first, last) = match (ctx.sent.front(), ctx.sent.back()) {
            (Some(first), Some(last)) => (first, last),
            _ => continue,
        };

        if ctx.largest_ack != NGX_QUIC_UNSET_PN {
            let mut w = first.send_time.wrapping_add(ngx_quic_time_threshold(&qc)).wrapping_sub(now) as i64;

            if first.pnum <= ctx.largest_ack {
                let pkt_thr = ngx_quic_packet_threshold(&ctx);

                if w < 0 || ctx.largest_ack - first.pnum >= pkt_thr {
                    w = 0;
                }

                if lost == -1 || w < lost {
                    lost = w;
                }
            }
        }

        let mut w = last.send_time.wrapping_add(ngx_quic_pto_level(c, &qc, ctx.level) << qc.pto_count.get()).wrapping_sub(now) as i64;

        if w < 0 {
            w = 0;
        }

        if pto == -1 || w < pto {
            pto = w;
        }
    }

    if qc.pto.timer_set() {
        qc.pto.del_timer();
    }

    if lost != -1 {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic lost timer lost:{}", lost);

        qc.pto_lost.set(true);
        qc.pto.add_timer(lost as u64);
        return;
    }

    if pto != -1 {
        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic lost timer pto:{}", pto);

        qc.pto_lost.set(false);
        qc.pto.add_timer(pto as u64);
        return;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic lost timer unset");
}

/// ngx_quic_pto of the send context of the level
pub fn ngx_quic_pto(c: &Connection, level: usize) -> u64 {
    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return 0,
    };

    let level = qc.send_ctx(level).borrow().level;

    ngx_quic_pto_level(c, &qc, level)
}

/// ngx_quic_pto
fn ngx_quic_pto_level(c: &Connection, qc: &QuicConnection, level: usize) -> u64 {
    /* RFC 9002, Appendix A.8.  Setting the Loss Detection Timer */

    let mut duration = qc.avg_rtt.get();
    duration = duration.wrapping_add((4 * qc.rttvar.get()).max(NGX_QUIC_TIME_GRANULARITY));

    if level == NGX_QUIC_ENCRYPTION_APPLICATION && handshaked(c) {
        duration = duration.wrapping_add(qc.ctp.borrow().max_ack_delay);
    }

    duration
}

/// ngx_quic_lost_handler
pub fn ngx_quic_lost_handler(c: &Rc<Connection>) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic lost timer");

    if ngx_quic_detect_lost(c, None) != NGX_OK {
        ngx_quic_close_connection(c, NGX_ERROR);
        return;
    }

    ngx_quic_connstate_dbg(c);
}

/// ngx_quic_pto_handler
pub fn ngx_quic_pto_handler(c: &Rc<Connection>) {
    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic pto timer");

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return,
    };

    let now = times::event_msec();

    for i in 0..NGX_QUIC_SEND_CTX_LAST {
        let level = {
            let ctx = qc.send_ctx[i].borrow();

            let f = match ctx.sent.back() {
                Some(f) => f,
                None => continue,
            };

            let w = f.send_time.wrapping_add(ngx_quic_pto_level(c, &qc, ctx.level) << qc.pto_count.get()).wrapping_sub(now) as i64;

            if f.pnum <= ctx.largest_ack && ctx.largest_ack != NGX_QUIC_UNSET_PN {
                continue;
            }

            if w > 0 {
                continue;
            }

            ctx.level
        };

        ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic pto {} pto_count:{}", ngx_quic_level_name(level), qc.pto_count.get());

        for _ in 0..2 {
            let mut f = match ngx_quic_alloc_frame(c) {
                Some(f) => f,
                None => {
                    ngx_quic_close_connection(c, NGX_ERROR);
                    return;
                }
            };

            f.level = level;
            f.ty = NGX_QUIC_FT_PING;
            f.ignore_congestion = true;

            if ngx_quic_frame_sendto(c, f, 0, &qc.path()) == NGX_ERROR {
                ngx_quic_close_connection(c, NGX_ERROR);
                return;
            }
        }
    }

    qc.pto_count.set(qc.pto_count.get() + 1);

    ngx_quic_set_lost_timer(c);

    ngx_quic_connstate_dbg(c);
}

/// ngx_quic_ack_packet
pub fn ngx_quic_ack_packet(c: &Rc<Connection>, pkt: &QuicHeader<'_>) -> i64 {
    c.log.set_action(Some("preparing ack"));

    let qc = match ngx_quic_get_connection(c) {
        Some(qc) => qc,
        None => return NGX_ERROR,
    };

    let mut ctx = qc.send_ctx(pkt.level).borrow_mut();

    ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "quic ngx_quic_ack_packet pn:{} largest {} fr:{} nranges:{}", pkt.pn, ctx.largest_range as i64, ctx.first_range, ctx.nranges);

    if !ngx_quic_keys_available(&qc.keys.borrow(), ctx.level, true) {
        return NGX_OK;
    }

    let prev_pending = ctx.pending_ack;

    if pkt.need_ack {
        qc.push.post();

        if ctx.send_ack == 0 {
            ctx.ack_delay_start = times::event_msec();
        }

        ctx.send_ack += 1;

        if ctx.pending_ack == NGX_QUIC_UNSET_PN || ctx.pending_ack < pkt.pn {
            ctx.pending_ack = pkt.pn;
        }
    }

    let base = ctx.largest_range;
    let pn = pkt.pn;

    if base == NGX_QUIC_UNSET_PN {
        ctx.largest_range = pn;
        ctx.largest_received = pkt.received;
        return NGX_OK;
    }

    if base == pn {
        return NGX_OK;
    }

    let mut largest = base;
    let mut smallest = largest.wrapping_sub(ctx.first_range);

    let gap: u64;
    let range: u64;
    let mut i: usize;

    'insert: {
        if pn > base {
            if pn - base == 1 {
                ctx.first_range += 1;
                ctx.largest_range = pn;
                ctx.largest_received = pkt.received;

                return NGX_OK;
            }

            /* new gap in front of current largest */

            /* no place for new range, send current range as is */
            if ctx.nranges == NGX_QUIC_MAX_RANGES {
                if prev_pending != NGX_QUIC_UNSET_PN && ngx_quic_send_ack(c, &qc, &mut ctx) != NGX_OK {
                    return NGX_ERROR;
                }

                if prev_pending == ctx.pending_ack || !pkt.need_ack {
                    ctx.pending_ack = NGX_QUIC_UNSET_PN;
                }
            }

            gap = pn - base - 2;
            range = ctx.first_range;

            ctx.first_range = 0;
            ctx.largest_range = pn;
            ctx.largest_received = pkt.received;

            /* packet is out of order, force send */
            if pkt.need_ack {
                ctx.send_ack = NGX_QUIC_MAX_ACK_GAP;
            }

            i = 0;

            break 'insert;
        }

        /*  pn < base, perform lookup in existing ranges */

        /* packet is out of order */
        if pkt.need_ack {
            ctx.send_ack = NGX_QUIC_MAX_ACK_GAP;
        }

        if pn >= smallest && pn <= largest {
            return NGX_OK;
        }

        i = 0;

        while i < ctx.nranges {
            let r = ctx.ranges[i];

            let ge = smallest.wrapping_sub(1);
            let gs = ge.wrapping_sub(r.gap);

            if pn >= gs && pn <= ge {
                if gs == ge {
                    /* gap size is exactly one packet, now filled */

                    /* data moves to previous range, current is removed */

                    if i == 0 {
                        ctx.first_range += r.range + 2;
                    } else {
                        ctx.ranges[i - 1].range += r.range + 2;
                    }

                    let nr = ctx.nranges - i - 1;
                    if nr != 0 {
                        ctx.ranges.copy_within(i + 1..i + 1 + nr, i);
                    }

                    ctx.nranges -= 1;
                } else if pn == gs {
                    /* current gap shrinks from tail (current range grows) */
                    ctx.ranges[i].gap -= 1;
                    ctx.ranges[i].range += 1;
                } else if pn == ge {
                    /* current gap shrinks from head (previous range grows) */
                    ctx.ranges[i].gap -= 1;

                    if i == 0 {
                        ctx.first_range += 1;
                    } else {
                        ctx.ranges[i - 1].range += 1;
                    }
                } else {
                    /* current gap is split into two parts */

                    gap = ge - pn - 1;
                    range = 0;

                    if ctx.nranges == NGX_QUIC_MAX_RANGES {
                        if prev_pending != NGX_QUIC_UNSET_PN && ngx_quic_send_ack(c, &qc, &mut ctx) != NGX_OK {
                            return NGX_ERROR;
                        }

                        if prev_pending == ctx.pending_ack || !pkt.need_ack {
                            ctx.pending_ack = NGX_QUIC_UNSET_PN;
                        }
                    }

                    ctx.ranges[i].gap = pn - gs - 1;
                    break 'insert;
                }

                return NGX_OK;
            }

            largest = smallest.wrapping_sub(r.gap).wrapping_sub(2);
            smallest = largest.wrapping_sub(r.range);

            if pn >= smallest && pn <= largest {
                /* this packet number is already known */
                return NGX_OK;
            }

            i += 1;
        }

        if pn == smallest.wrapping_sub(1) {
            /* extend first or last range */

            if i == 0 {
                ctx.first_range += 1;
            } else {
                ctx.ranges[i - 1].range += 1;
            }

            return NGX_OK;
        }

        /* nothing found, add new range at the tail  */

        if ctx.nranges == NGX_QUIC_MAX_RANGES {
            /* packet is too old to keep it */

            if pkt.need_ack {
                drop(ctx);
                return ngx_quic_send_ack_range(c, pkt.level, pn, pn);
            }

            return NGX_OK;
        }

        gap = smallest.wrapping_sub(2).wrapping_sub(pn);
        range = 0;
    }

    // insert:

    if ctx.nranges < NGX_QUIC_MAX_RANGES {
        ctx.nranges += 1;
    }

    let n = ctx.nranges - i - 1;
    ctx.ranges.copy_within(i..i + n, i + 1);

    ctx.ranges[i].gap = gap;
    ctx.ranges[i].range = range;

    NGX_OK
}

/// ngx_quic_generate_ack
pub fn ngx_quic_generate_ack(c: &Connection, qc: &QuicConnection, ctx: &mut QuicSendCtx) -> i64 {
    if ctx.send_ack == 0 {
        return NGX_OK;
    }

    if ctx.level == NGX_QUIC_ENCRYPTION_APPLICATION {
        let delay = times::event_msec().wrapping_sub(ctx.ack_delay_start);

        let max_ack_delay = qc.tp.borrow().max_ack_delay;

        if ctx.frames.is_empty() && ctx.send_ack < NGX_QUIC_MAX_ACK_GAP && delay < max_ack_delay {
            if !qc.push.timer_set() && !qc.closing.get() {
                qc.push.add_timer(max_ack_delay - delay);
            }

            return NGX_OK;
        }
    }

    if ngx_quic_send_ack(c, qc, ctx) != NGX_OK {
        return NGX_ERROR;
    }

    ctx.send_ack = 0;

    NGX_OK
}
