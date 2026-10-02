//! ngx_stream_write_filter_module.c: the top of the output filter chain,
//! sending the data to the client (from_upstream) or to the upstream.

use std::time::Duration;

use ngx_core::connection::Connection;
use ngx_core::event_openssl::{ngx_ssl_send_chain_wait_links, SslFlushedBufs};
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::ngx_log_debug;

use crate::*;

/// The write filter could not send the data.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WriteError {
    /// c->error: a send error, logged
    Error,
    /// no progress for the timeout
    TimedOut,
}

/// ngx_stream_top_filter (ngx_stream_write_filter): send the buffers to
/// `c`, the client connection for the data from the upstream and the
/// upstream connection otherwise. On UDP each buffer is a datagram, an
/// empty one too, and a client connection (sharing the listening socket)
/// fails with "shared connection is busy" instead of waiting. With a
/// timeout, waiting for the socket longer than it gives TimedOut (the
/// write event timer of the callers, re-armed after each write).
pub async fn top_filter(s: &Session, c: &Connection, bufs: &[&[u8]], from_upstream: bool, timeout: Option<Duration>) -> Result<(), WriteError> {
    if c.error.get() {
        return Err(WriteError::Error);
    }

    let size: usize = bufs.iter().map(|b| b.len()).sum();

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream write filter: l:0 f:1 s:{}", size);

    let _ = (s, from_upstream);

    if c.ty == libc::SOCK_DGRAM {
        // ngx_udp_unix_sendmsg_chain: each buffer is flushed as a datagram,
        // an empty one too (c->need_flush_buf)

        for b in bufs.iter() {
            let r = if c.shared.get() {
                // a connection sharing a UDP listening socket does not wait
                // for it

                match c.try_send(b) {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        ngx_core::ngx_log_error!(NGX_LOG_ALERT, c.log, None, "shared connection is busy");
                        return Err(WriteError::Error);
                    }
                    r => r,
                }
            } else {
                match timeout {
                    Some(t) => match tokio::time::timeout(t, c.send(b)).await {
                        Ok(r) => r,
                        Err(_) => return Err(WriteError::TimedOut),
                    },
                    None => c.send(b).await,
                }
            };

            if let Err(e) = r {
                c.connection_error(e.raw_os_error().unwrap_or(0), "sendmsg() failed");
                c.error.set(true);
                return Err(WriteError::Error);
            }
        }

        return Ok(());
    }

    if size == 0 {
        return Ok(());
    }

    if c.ssl.borrow().as_ref().is_some_and(|sc| sc.state.ngx.get()) {
        // c->send_chain: ngx_ssl_send_chain, the buffers of a read are
        // flushed (or last)

        let links = SslFlushedBufs(bufs);

        let r = match timeout {
            Some(t) => match tokio::time::timeout(t, ngx_ssl_send_chain_wait_links(c, &links, 0)).await {
                Ok(r) => r,
                Err(_) => return Err(WriteError::TimedOut),
            },
            None => ngx_ssl_send_chain_wait_links(c, &links, 0).await,
        };

        if let Err(e) = r {
            if !ngx_core::event_openssl::is_ssl_error_logged(&e) {
                c.connection_error(e.raw_os_error().unwrap_or(0), "SSL_write() failed");
            }
            c.error.set(true);
            return Err(WriteError::Error);
        }

        return Ok(());
    }

    // the unsent part of the chain

    let mut bi = 0;
    let mut off = 0;

    while bi < bufs.len() {
        if off == bufs[bi].len() {
            bi += 1;
            off = 0;
            continue;
        }

        let mut iov: Vec<&[u8]> = Vec::with_capacity(bufs.len() - bi);
        iov.push(&bufs[bi][off..]);
        for b in &bufs[bi + 1..] {
            if !b.is_empty() {
                iov.push(b);
            }
        }

        let r = match timeout {
            Some(t) => match tokio::time::timeout(t, c.writev(&iov)).await {
                Ok(r) => r,
                Err(_) => return Err(WriteError::TimedOut),
            },
            None => c.writev(&iov).await,
        };

        let mut n = match r {
            Ok(n) => n,
            Err(e) => {
                let err = e.raw_os_error().unwrap_or(0);
                if ngx_core::event_openssl::is_ssl_error_logged(&e) {
                    /* logged by ngx_ssl_write() */
                } else if c.ssl.borrow().is_some() {
                    ngx_core::ngx_log_error!(NGX_LOG_ERR, c.log, if err != 0 { Some(err) } else { None }, "SSL_write() failed");
                } else {
                    c.connection_error(err, "writev() failed");
                }
                c.error.set(true);
                return Err(WriteError::Error);
            }
        };

        while n > 0 && bi < bufs.len() {
            let left = bufs[bi].len() - off;

            if n < left {
                off += n;
                n = 0;
            } else {
                n -= left;
                bi += 1;
                off = 0;
            }
        }
    }

    Ok(())
}

/// ngx_stream_write_filter_init
fn write_filter_init(_cf: &mut ngx_core::conf::Conf) -> ngx_core::conf::ConfResult {
    Ok(())
}

pub fn write_filter_module() -> ModuleDef {
    stream_module_def("ngx_stream_write_filter_module", StreamModuleDef { postconfiguration: Some(write_filter_init), ..Default::default() }, Vec::new())
}
