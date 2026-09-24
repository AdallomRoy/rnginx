//! Sending buffer chains to a connection (ngx_linux_sendfile_chain / ngx_writev_chain).

use std::io;

use ngx_core::buf::{BufData, Chain};
use ngx_core::connection::{Connection, TcpNopush};
use ngx_core::log::*;
use ngx_core::ngx_log_error;

/// Send as much of `chain` as possible up to `limit` bytes; returns bytes sent.
/// Buffers are advanced in place (like ngx_chain_update_sent); fully sent buffers are removed.
pub async fn send_chain(c: &Connection, chain: &mut Chain, limit: i64) -> io::Result<i64> {
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
            if c.tcp_nopush.get() == TcpNopush::Unset && c.ty == libc::SOCK_STREAM && !c.sockaddr.borrow().is_unix() {
                if let Err(e) = c.tcp_push_on() {
                    ngx_log_error!(NGX_LOG_CRIT, c.log, e.raw_os_error(), "setsockopt(TCP_CORK) failed");
                } else {
                    c.tcp_nopush.set(TcpNopush::Set);
                }
            }
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
        for b in chain.iter() {
            if !b.in_memory() {
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
