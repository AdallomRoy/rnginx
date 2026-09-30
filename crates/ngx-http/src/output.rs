//! Sending buffer chains to a connection (ngx_linux_sendfile_chain / ngx_writev_chain).

use std::io;

use ngx_core::buf::{BufData, Chain};
use ngx_core::connection::{Connection, TcpNodelay, TcpNopush};
use ngx_core::event_openssl::{ngx_ssl_send_chain_wait, SslChainBuf, SslChainFile};
use ngx_core::log::*;
use ngx_core::ngx_log_debug;

/// Send as much of `chain` as possible up to `limit` bytes; returns bytes sent.
/// Buffers are advanced in place (like ngx_chain_update_sent); fully sent buffers are removed.
pub async fn send_chain(c: &Connection, chain: &mut Chain, limit: i64) -> io::Result<i64> {
    if c.ssl.borrow().as_ref().is_some_and(|sc| sc.state.ngx.get()) {
        return ssl_send_chain(c, chain, limit).await;
    }

    let mut total: i64 = 0;
    let limit = if limit <= 0 { i64::MAX } else { limit };
    loop {
        // drop empty non-special buffers at the front
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
        // gather memory buffers
        let mut iov: Vec<&[u8]> = Vec::new();
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
            iov.push(&slice[..take]);
            gathered += take as i64;
            if iov.len() >= 64 {
                break;
            }
        }
        if iov.is_empty() {
            return Ok(total);
        }
        // TCP_CORK if there is a header before a file
        if file_next && c.tcp_nopush.get() == TcpNopush::Unset {
            tcp_nopush(c)?;
        }
        let n = c.writev(&iov).await?;
        total += n as i64;
        drop(iov);
        ngx_core::buf::chain_update_sent(chain, n as i64);
        if (n as i64) < gathered {
            // partial write; let caller decide (we loop again which awaits writability)
            continue;
        }
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
    let n = {
        let links: Vec<SslChainBuf> = chain
            .iter()
            .map(|b| {
                let (mem, file): (&[u8], Option<SslChainFile>) = match &b.data {
                    BufData::Memory(v) if b.in_memory() => (&v[b.pos..b.last], None),
                    BufData::File(f) if b.in_file => (&[], Some(SslChainFile { fd: f.fd, name: &f.name, pos: b.file_pos, last: b.file_last })),
                    _ => (&[], None),
                };
                SslChainBuf { mem, file, flush: b.flush, last_buf: b.last_buf }
            })
            .collect();

        ngx_ssl_send_chain_wait(c, &links, limit).await?
    };

    ngx_core::buf::chain_update_sent(chain, n);

    Ok(n)
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
