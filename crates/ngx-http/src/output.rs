//! Sending buffer chains to a connection (ngx_linux_sendfile_chain / ngx_writev_chain).

use std::io;
use std::io::IoSlice;

use ngx_core::buf::{BufData, Chain};

use crate::copy_filter::recycle;
use ngx_core::connection::{Connection, IoStep, TcpNodelay, TcpNopush};
use ngx_core::event_openssl::{ngx_ssl_chain_taken, ngx_ssl_send_chain_wait_chain, ngx_ssl_send_chain_wait_step, ssl_error_logged, SslChainPos};
use ngx_core::log::*;
use ngx_core::ngx_log_debug;

/// NGX_IOVS_PREALLOCATE: the iovecs of a writev(), on the stack
pub const NGX_IOVS_PREALLOCATE: usize = 64;

/// What a pass of c->send_chain() without waiting came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pass {
    /// the chain is sent, or `limit` bytes of it
    Done,
    /// the connection takes no more now: the rest waits for the write
    /// event (NGX_AGAIN, wev->ready = 0)
    Again,
    /// a TLS connection takes no more now: ngx_ssl_send_chain() goes on
    /// from `pos` once the socket is writable (readable for WantRead), the
    /// chain not updated yet (ssl_send_chain_from())
    SslAgain { want_read: bool, pos: SslChainPos },
    /// not tried: an SSL object ngx_ssl does not run (none is made so)
    Async,
}

/// One pass of c->send_chain() without waiting: as much of `chain` as the
/// connection takes now, up to `limit` bytes of it (0: no limit). The
/// buffers sent are advanced in place, those fully sent removed
/// (ngx_chain_update_sent); the bytes sent are added to `total`. A pass
/// after Again goes on where it stopped, as send_chain() does once the
/// connection is writable.
pub fn send_chain_pass(c: &Connection, chain: &mut Chain, limit: i64, total: &mut i64) -> io::Result<Pass> {
    if c.is_quic_stream() {
        return quic_send_chain_pass(c, chain, limit, total);
    }

    let ssl = c.ssl.borrow().as_ref().map(|sc| sc.state.ngx.get());

    match ssl {
        Some(true) => return ssl_send_chain_pass(c, chain, limit, total),
        Some(false) => return Ok(Pass::Async),
        None => {}
    }

    plain_send_chain_pass(c, chain, limit, total)
}

/// Send as much of `chain` as possible up to `limit` bytes; returns bytes sent.
/// Buffers are advanced in place (like ngx_chain_update_sent); fully sent buffers are removed.
pub async fn send_chain(c: &Connection, chain: &mut Chain, limit: i64) -> io::Result<i64> {
    if c.is_quic_stream() {
        return quic_send_chain(c, chain, limit).await;
    }

    let ssl = c.ssl.borrow().as_ref().map(|sc| sc.state.ngx.get());

    match ssl {
        Some(true) => return ssl_send_chain(c, chain, limit).await,
        Some(false) => return send_chain_io(c, chain, limit).await,
        None => {}
    }

    let mut total: i64 = 0;

    loop {
        if plain_send_chain_pass(c, chain, limit, &mut total)? == Pass::Done {
            return Ok(total);
        }

        // NGX_AGAIN: the write event
        c.writable().await?;
    }
}

/// A pass of ngx_linux_sendfile_chain on a plain socket: writev() of the
/// memory buffers (from an iovec array on the stack, as
/// ngx_output_chain_to_iovec), sendfile() of the file ones, each tried
/// only while the socket is write-ready.
fn plain_send_chain_pass(c: &Connection, chain: &mut Chain, limit: i64, total: &mut i64) -> io::Result<Pass> {
    let limit = if limit <= 0 { i64::MAX } else { limit };

    loop {
        // drop empty non-special buffers at the front
        while let Some(b) = chain.front() {
            if b.buf_size() == 0 {
                recycle(chain.pop_front().unwrap());
            } else {
                break;
            }
        }

        let first = match chain.front() {
            Some(b) => b,
            None => return Ok(Pass::Done),
        };

        if *total >= limit {
            return Ok(Pass::Done);
        }

        let budget = limit - *total;

        if first.in_file && !first.in_memory() {
            let (fd, off, size) = match &first.data {
                BufData::File(f) => (f.fd, first.file_pos, (first.file_last - first.file_pos).min(budget)),
                _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
            };

            let n = match sendfile(c, fd, off, size as usize) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Pass::Again),
                Err(e) => return Err(e),
            };

            if n == 0 {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }

            *total += n as i64;
            update_sent(chain, n as i64);
            continue;
        }

        // gather memory buffers
        let mut iovs = [IoSlice::new(&[]); NGX_IOVS_PREALLOCATE];
        let mut niovs = 0;
        // the buffers gathered, empty ones included
        let mut nbufs = 0;
        let mut gathered: i64 = 0;
        // the buffer after the header is in a file
        let mut file_next = false;

        for b in chain.iter() {
            // ngx_output_chain_to_iovec: special buffers are skipped
            if b.special_buf() {
                continue;
            }
            if !b.in_memory() {
                file_next = b.in_file;
                break;
            }
            if gathered >= budget {
                break;
            }
            let slice = match &b.data {
                BufData::Memory(v) => &v[b.pos..b.last],
                _ => break,
            };
            let take = ((budget - gathered) as usize).min(slice.len());
            if take > 0 {
                iovs[niovs] = IoSlice::new(&slice[..take]);
                niovs += 1;
            }
            nbufs += 1;
            gathered += take as i64;
            if nbufs >= NGX_IOVS_PREALLOCATE {
                break;
            }
        }

        if nbufs == 0 {
            return Ok(Pass::Done);
        }

        // TCP_CORK if there is a header before a file
        if file_next && c.tcp_nopush.get() == TcpNopush::Unset {
            tcp_nopush(c)?;
        }

        let n = if niovs == 0 {
            0
        } else {
            match writev(c, &iovs[..niovs]) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Pass::Again),
                Err(e) => return Err(e),
            }
        };

        *total += n as i64;
        update_sent(chain, n as i64);

        // a partial write: the next attempt finds out whether the socket
        // takes more
    }
}

/// writev() on the socket while it is write-ready; WouldBlock otherwise
fn writev(c: &Connection, iovs: &[IoSlice<'_>]) -> io::Result<usize> {
    let n = c.try_write_io(|s| nix::sys::uio::writev(s, iovs).map_err(io::Error::from))?;

    c.sent.set(c.sent.get() + n as u64);

    Ok(n)
}

/// sendfile(2) of `count` bytes from `file_fd` at `offset` to the socket
/// while it is write-ready; WouldBlock otherwise
fn sendfile(c: &Connection, file_fd: i32, offset: i64, count: usize) -> io::Result<usize> {
    let n = c.try_write_io(|s| {
        let file = ngx_core::fd::get(file_fd)?;
        // the off_t of the kernel, as unsigned
        let mut off = offset as u64;
        rustix::fs::sendfile(s, &file, Some(&mut off), count).map_err(io::Error::from)
    })?;

    c.sent.set(c.sent.get() + n as u64);

    Ok(n)
}

/// send_chain() of a connection with an SSL object that ngx_ssl does not
/// run (none is made so): its writev() and sendfile() as they are
async fn send_chain_io(c: &Connection, chain: &mut Chain, limit: i64) -> io::Result<i64> {
    let mut total: i64 = 0;
    let limit = if limit <= 0 { i64::MAX } else { limit };
    loop {
        while let Some(b) = chain.front() {
            if b.buf_size() == 0 {
                chain.pop_front();
            } else {
                break;
            }
        }
        let first = match chain.front() {
            Some(b) => b,
            None => return Ok(total),
        };
        if total >= limit {
            return Ok(total);
        }
        let budget = limit - total;
        if first.in_file && !first.in_memory() {
            let (fd, off, size) = match &first.data {
                BufData::File(f) => (f.fd, first.file_pos, (first.file_last - first.file_pos).min(budget)),
                _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
            };
            let n = c.sendfile(fd, off, size as usize).await?;
            if n == 0 {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            total += n as i64;
            ngx_core::buf::chain_update_sent(chain, n as i64);
            continue;
        }
        let mut iov: Vec<&[u8]> = Vec::new();
        let mut gathered: i64 = 0;
        let mut file_next = false;
        for b in chain.iter() {
            if b.special_buf() {
                continue;
            }
            if !b.in_memory() {
                file_next = b.in_file;
                break;
            }
            if gathered >= budget {
                break;
            }
            let slice = match &b.data {
                BufData::Memory(v) => &v[b.pos..b.last],
                _ => break,
            };
            let take = ((budget - gathered) as usize).min(slice.len());
            iov.push(&slice[..take]);
            gathered += take as i64;
            if iov.len() >= NGX_IOVS_PREALLOCATE {
                break;
            }
        }
        if iov.is_empty() {
            return Ok(total);
        }
        if file_next && c.tcp_nopush.get() == TcpNopush::Unset {
            tcp_nopush(c)?;
        }
        let n = c.writev(&iov).await?;
        total += n as i64;
        drop(iov);
        ngx_core::buf::chain_update_sent(chain, n as i64);
    }
}

/// The TCP_CORK of ngx_linux_sendfile_chain for a header before a file:
/// TCP_NODELAY off first, the two are mutually exclusive. EINTR leaves the
/// connection as it is.
fn tcp_nopush(c: &Connection) -> io::Result<()> {
    if c.tcp_nodelay.get() == TcpNodelay::Set {
        match c.setsockopt_int(libc::IPPROTO_TCP, libc::TCP_NODELAY, 0) {
            Ok(()) => {
                c.tcp_nodelay.set(TcpNodelay::Unset);
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "no tcp_nodelay");
            }
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => {}
            Err(e) => {
                c.connection_error(e.raw_os_error().unwrap_or(0), "setsockopt(TCP_NODELAY) failed");
                return Err(e);
            }
        }
    }

    if c.tcp_nodelay.get() == TcpNodelay::Unset {
        match c.tcp_push_on() {
            Ok(()) => {
                c.tcp_nopush.set(TcpNopush::Set);
                ngx_log_debug!(NGX_LOG_DEBUG_EVENT, c.log, "tcp_nopush");
            }
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => {}
            Err(e) => {
                c.connection_error(e.raw_os_error().unwrap_or(0), "setsockopt(TCP_CORK) failed");
                return Err(e);
            }
        }
    }

    Ok(())
}

/// c->send_chain of an SSL connection: ngx_ssl_send_chain(), which keeps
/// the data in c->ssl->buf until a flush (NGX_SSL_BUFFER), and sends the
/// file buffers with kernel TLS.
async fn ssl_send_chain(c: &Connection, chain: &mut Chain, limit: i64) -> io::Result<i64> {
    let n = ngx_ssl_send_chain_wait_chain(c, chain, limit).await?;

    update_sent(chain, n);

    Ok(n)
}

/// A pass of ssl_send_chain() without waiting: the first step of
/// ngx_ssl_send_chain_wait()
fn ssl_send_chain_pass(c: &Connection, chain: &mut Chain, limit: i64, total: &mut i64) -> io::Result<Pass> {
    let mut pos = SslChainPos::default();

    match ngx_ssl_send_chain_wait_step(c, &*chain, &mut pos, limit) {
        IoStep::Done(Ok(())) => {
            let n = ngx_ssl_chain_taken(&*chain, pos);

            update_sent(chain, n);
            *total += n;

            Ok(Pass::Done)
        }
        IoStep::Done(Err(())) => Err(ssl_error_logged()),
        IoStep::WantRead => Ok(Pass::SslAgain { want_read: true, pos }),
        IoStep::WantWrite => Ok(Pass::SslAgain { want_read: false, pos }),
    }
}

/// ssl_send_chain() after a pass that came to SslAgain: the steps of
/// ngx_ssl_send_chain_wait() go on from that pass's result and position,
/// as if its drive_io had made the pass (the same SSL calls). Returns the
/// bytes of the chain taken, the pass's included.
pub async fn ssl_send_chain_from(c: &Connection, chain: &mut Chain, limit: i64, want_read: bool, pos: SslChainPos) -> io::Result<i64> {
    let mut pos = pos;
    let mut first = Some(if want_read { IoStep::WantRead } else { IoStep::WantWrite });

    let r = c
        .drive_io(|| match first.take() {
            Some(step) => step,
            None => ngx_ssl_send_chain_wait_step(c, &*chain, &mut pos, limit),
        })
        .await?;

    match r {
        Ok(()) => {
            let n = ngx_ssl_chain_taken(&*chain, pos);
            update_sent(chain, n);
            Ok(n)
        }
        Err(()) => Err(ssl_error_logged()),
    }
}

/// c->send_chain of a QUIC stream: ngx_quic_stream_send_chain(), the data
/// copied to the stream within its flow control window (the buffers not
/// in memory are skipped, as ngx_quic_write_buffer does), waiting for the
/// write event while the window is closed. `limit` 0 is none.
async fn quic_send_chain(c: &Connection, chain: &mut Chain, limit: i64) -> io::Result<i64> {
    let mut total: i64 = 0;

    loop {
        if quic_send_chain_pass(c, chain, limit, &mut total)? == Pass::Done {
            return Ok(total);
        }

        // wev->ready = 0: the write event, once the peer acknowledges data
        c.writable().await?;
    }
}

/// A pass of quic_send_chain(): what the stream's window takes now
fn quic_send_chain_pass(c: &Connection, chain: &mut Chain, limit: i64, total: &mut i64) -> io::Result<Pass> {
    while let Some(b) = chain.front() {
        if b.buf_size() == 0 {
            recycle(chain.pop_front().unwrap());
        } else {
            break;
        }
    }

    /// the data of a buffer in memory
    fn data(b: &ngx_core::buf::Buf) -> Option<&[u8]> {
        if !(b.in_memory() && b.last > b.pos) {
            return None;
        }

        match &b.data {
            BufData::Memory(v) => Some(&v[b.pos..b.last]),
            _ => None,
        }
    }

    let budget = if limit > 0 { (limit - *total) as u64 } else { 0 };

    let nbufs = chain.iter().filter(|b| data(b).is_some()).count();

    if nbufs == 0 {
        return Ok(Pass::Done);
    }

    // the input slices on the stack, unless there are many
    let mut stack: [&[u8]; NGX_IOVS_PREALLOCATE] = [&[]; NGX_IOVS_PREALLOCATE];
    let mut heap: Vec<&[u8]>;

    let iov: &mut [&[u8]] = if nbufs <= NGX_IOVS_PREALLOCATE {
        for (slot, s) in stack.iter_mut().zip(chain.iter().filter_map(data)) {
            *slot = s;
        }
        &mut stack[..nbufs]
    } else {
        heap = chain.iter().filter_map(data).collect();
        &mut heap[..]
    };

    let before: usize = iov.iter().map(|s| s.len()).sum();

    if ngx_core::quic::streams::ngx_quic_stream_send_chain(c, iov, budget).is_err() {
        return Err(io::Error::other("quic stream send failed"));
    }

    let left: usize = iov.iter().map(|s| s.len()).sum();
    let n = before - left;

    *total += n as i64;

    update_sent(chain, n as i64);

    if left == 0 || (limit > 0 && *total >= limit) {
        return Ok(Pass::Done);
    }

    Ok(Pass::Again)
}

/// ngx_chain_update_sent: `sent` bytes of the chain are taken off it, and
/// the special buffers after them; the memory of a copy buffer is free for
/// the next copies (ngx_chain_update_chains() in C)
fn update_sent(chain: &mut Chain, mut sent: i64) {
    while let Some(buf) = chain.front_mut() {
        if buf.special_buf() {
            recycle(chain.pop_front().unwrap());
            continue;
        }

        if sent == 0 {
            break;
        }

        let size = buf.buf_size();

        if sent >= size {
            sent -= size;

            if buf.in_memory() {
                buf.pos = buf.last;
            }

            if buf.in_file {
                buf.file_pos = buf.file_last;
            }

            recycle(chain.pop_front().unwrap());
            continue;
        }

        if buf.in_memory() {
            buf.pos += sent as usize;
        }

        if buf.in_file {
            buf.file_pos += sent;
        }

        break;
    }
}

/// Convenience: send a whole chain (awaiting writability) — used by simple paths.
pub async fn send_all(c: &Connection, chain: &mut Chain) -> io::Result<()> {
    loop {
        send_chain(c, chain, 0).await?;
        if chain.iter().all(|b| b.buf_size() == 0) {
            chain.clear();
            return Ok(());
        }
    }
}
