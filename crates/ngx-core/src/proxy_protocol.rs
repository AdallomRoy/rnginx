//! PROXY protocol v1 and v2 implementation, ported from ngx_proxy_protocol.c.

use crate::inet::SockAddr;
use crate::log::{Log, NGX_LOG_ALERT, NGX_LOG_DEBUG_CORE, NGX_LOG_ERR};
use crate::string::B;
use crate::{ngx_log_debug, ngx_log_error};
use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};

pub const NGX_PROXY_PROTOCOL_V1_MAX_HEADER: usize = 107;
pub const NGX_PROXY_PROTOCOL_MAX_HEADER: usize = 4096;
pub const NGX_PROXY_PROTOCOL_V2_MAX_HEADER: usize = 52;

// V2 constants
const NGX_PROXY_PROTOCOL_CMD_LOCAL: u8 = 0;
const NGX_PROXY_PROTOCOL_CMD_PROXY: u8 = 1;

const NGX_PROXY_PROTOCOL_AF_UNSPEC: u8 = 0;
const NGX_PROXY_PROTOCOL_AF_INET: u8 = 1;
const NGX_PROXY_PROTOCOL_AF_INET6: u8 = 2;

const NGX_PROXY_PROTOCOL_TYPE_UNSPEC: u8 = 0;
const NGX_PROXY_PROTOCOL_TYPE_STREAM: u8 = 1;
const NGX_PROXY_PROTOCOL_TYPE_DGRAM: u8 = 2;

pub const NGX_PROXY_PROTOCOL_TLV_ALPN: u8 = 0x01;
pub const NGX_PROXY_PROTOCOL_TLV_AUTHORITY: u8 = 0x02;
pub const NGX_PROXY_PROTOCOL_TLV_CRC32C: u8 = 0x03;
pub const NGX_PROXY_PROTOCOL_TLV_UNIQUE_ID: u8 = 0x05;
pub const NGX_PROXY_PROTOCOL_TLV_SSL: u8 = 0x20;
pub const NGX_PROXY_PROTOCOL_TLV_SSL_VERSION: u8 = 0x21;
pub const NGX_PROXY_PROTOCOL_TLV_SSL_CN: u8 = 0x22;
pub const NGX_PROXY_PROTOCOL_TLV_SSL_CIPHER: u8 = 0x23;
pub const NGX_PROXY_PROTOCOL_TLV_SSL_SIG_ALG: u8 = 0x24;
pub const NGX_PROXY_PROTOCOL_TLV_SSL_KEY_ALG: u8 = 0x25;
pub const NGX_PROXY_PROTOCOL_TLV_NETNS: u8 = 0x30;

const NGX_PROXY_PROTOCOL_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

#[derive(Clone, Debug)]
pub struct ProxyProtocol {
    pub src_addr: Vec<u8>,
    pub dst_addr: Vec<u8>,
    pub src_port: u16,
    pub dst_port: u16,
    pub tlvs: Vec<u8>,
}

/// Read and parse a PROXY protocol header from a buffer.
/// Returns (header, bytes_consumed) on success, Err(()) on error. The header
/// is None when it carries no addresses (v1 UNKNOWN; v2 commands other than
/// PROXY, transports other than STREAM, families other than INET/INET6),
/// where C leaves c->proxy_protocol NULL.
pub fn read(log: &Log, buf: &[u8]) -> Result<(Option<ProxyProtocol>, usize), ()> {
    let len = buf.len();

    // Check for v2 signature (12 bytes minimum): \r\n\r\n\0\r\nQUIT\n
    if len >= 12 {
        let sig = &buf[..12];
        if sig == NGX_PROXY_PROTOCOL_SIGNATURE {
            return read_v2(log, buf);
        }
    }

    // Check for v1 "PROXY " prefix
    if len < 8 || &buf[..6] != b"PROXY " {
        ngx_log_error!(NGX_LOG_ERR, log, None, "broken header: \"{}\"", B(&buf[..find_line_len(buf)]));
        return Err(());
    }

    read_v1(log, buf)
}

/// Read v1 PROXY protocol (text format).
fn read_v1(log: &Log, buf: &[u8]) -> Result<(Option<ProxyProtocol>, usize), ()> {
    let mut p = 6; // Skip "PROXY "
    let end = buf.len();

    // Check for UNKNOWN
    if end - p >= 7 && &buf[p..p + 7] == b"UNKNOWN" {
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "PROXY protocol unknown protocol");
        p += 7;
        // Skip to CRLF
        while p + 1 < end {
            if buf[p] == b'\r' && buf[p + 1] == b'\n' {
                return Ok((None, p + 2));
            }
            p += 1;
        }
        ngx_log_error!(NGX_LOG_ERR, log, None, "broken header: \"{}\"", B(&buf[..find_line_len(buf)]));
        return Err(());
    }

    // TCP4 or TCP6
    if end - p < 5 || &buf[p..p + 3] != b"TCP" || (buf[p + 3] != b'4' && buf[p + 3] != b'6') || buf[p + 4] != b' ' {
        ngx_log_error!(NGX_LOG_ERR, log, None, "broken header: \"{}\"", B(&buf[..find_line_len(buf)]));
        return Err(());
    }

    p += 5;

    // Read src_addr
    let (src_addr, new_p) = read_addr(buf, p)?;
    p = new_p;

    // Read dst_addr
    let (dst_addr, new_p) = read_addr(buf, p)?;
    p = new_p;

    // Read src_port
    let (src_port, new_p) = read_port(buf, p, b' ')?;
    p = new_p;

    // Read dst_port
    let (dst_port, new_p) = read_port(buf, p, b'\r')?;
    p = new_p;

    // Expect LF
    if p >= end || buf[p] != b'\n' {
        ngx_log_error!(NGX_LOG_ERR, log, None, "broken header: \"{}\"", B(&buf[..find_line_len(buf)]));
        return Err(());
    }
    p += 1;

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log,
                   "PROXY protocol src: {} {}, dst: {} {}",
                   B(&src_addr), src_port, B(&dst_addr), dst_port);

    Ok((Some(ProxyProtocol { src_addr, dst_addr, src_port, dst_port, tlvs: vec![] }), p))
}

/// Read a v1 address field (ends with space)
fn read_addr(buf: &[u8], start: usize) -> Result<(Vec<u8>, usize), ()> {
    let mut p = start;
    let end = buf.len();

    while p < end {
        match buf[p] {
            b' ' => break,
            b':' | b'.' | b'a'..=b'f' | b'A'..=b'F' | b'0'..=b'9' => {
                p += 1;
            }
            _ => return Err(()),
        }
    }

    if p >= end {
        return Err(());
    }

    let addr = buf[start..p].to_vec();
    Ok((addr, p + 1))
}

/// Read a v1 port field (ends with sep character)
fn read_port(buf: &[u8], start: usize, sep: u8) -> Result<(u16, usize), ()> {
    let mut p = start;
    let end = buf.len();

    while p < end && buf[p] != sep {
        p += 1;
    }

    if p >= end {
        return Err(());
    }

    let port_str = &buf[start..p];
    let port = match crate::string::atoi(port_str) {
        Some(n) if n >= 0 && n <= 65535 => n as u16,
        _ => return Err(()),
    };

    Ok((port, p + 1))
}

/// Read v2 PROXY protocol (binary format).
fn read_v2(log: &Log, buf: &[u8]) -> Result<(Option<ProxyProtocol>, usize), ()> {
    let len = buf.len();

    // V2 header minimum: 16 bytes (sig 12 + version/command 1 + family/transport 1 + length 2)
    if len < 16 {
        ngx_log_error!(NGX_LOG_ERR, log, None, "broken header: \"{}\"", B(&buf[..find_line_len(buf)]));
        return Err(());
    }

    let version = buf[12] >> 4;
    if version != 2 {
        ngx_log_error!(NGX_LOG_ERR, log, None, "unknown PROXY protocol version: {}", version);
        return Err(());
    }

    let data_len = parse_uint16(&buf[14..16]) as usize;
    // Check that the entire header+data fits in the buffer
    let header_end = 16 + data_len;
    if len < header_end {
        ngx_log_error!(NGX_LOG_ERR, log, None, "header is too large");
        return Err(());
    }

    let end = header_end;
    let data_start = 16;
    let command = buf[12] & 0x0f;

    // only PROXY is supported
    if command != NGX_PROXY_PROTOCOL_CMD_PROXY {
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log,
                       "PROXY protocol v2 unsupported command {}", command);
        return Ok((None, end));
    }

    let transport = buf[13] & 0x0f;
    // only STREAM is supported
    if transport != NGX_PROXY_PROTOCOL_TYPE_STREAM {
        ngx_log_debug!(NGX_LOG_DEBUG_CORE, log,
                       "PROXY protocol v2 unsupported transport {}", transport);
        return Ok((None, end));
    }

    let family = buf[13] >> 4;
    let mut addr_start = data_start;

    let (src_addr, dst_addr, src_port, dst_port) = match family {
        NGX_PROXY_PROTOCOL_AF_INET => {
            if end - addr_start < 12 {
                return Err(());
            }
            let data = &buf[addr_start..addr_start + 12];
            addr_start += 12;
            (format_ipv4(&data[0..4]), format_ipv4(&data[4..8]), parse_uint16(&data[8..10]), parse_uint16(&data[10..12]))
        }
        NGX_PROXY_PROTOCOL_AF_INET6 => {
            if end - addr_start < 36 {
                return Err(());
            }
            let data = &buf[addr_start..addr_start + 36];
            addr_start += 36;
            (format_ipv6(&data[0..16]), format_ipv6(&data[16..32]), parse_uint16(&data[32..34]), parse_uint16(&data[34..36]))
        }
        _ => {
            ngx_log_debug!(NGX_LOG_DEBUG_CORE, log,
                           "PROXY protocol v2 unsupported address family {}", family);
            return Ok((None, end));
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log,
                   "PROXY protocol v2 src: {} {}, dst: {} {}",
                   B(&src_addr), src_port, B(&dst_addr), dst_port);

    // Capture remaining bytes as TLVs
    let tlvs = if addr_start < end {
        buf[addr_start..end].to_vec()
    } else {
        vec![]
    };

    Ok((Some(ProxyProtocol { src_addr, dst_addr, src_port, dst_port, tlvs }), end))
}

/// Format IPv4 address from 4 bytes
fn format_ipv4(bytes: &[u8]) -> Vec<u8> {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]).into_bytes()
}

/// Format IPv6 address from 16 bytes
fn format_ipv6(bytes: &[u8]) -> Vec<u8> {
    let addr = Ipv6Addr::new(
        parse_uint16(&bytes[0..2]),
        parse_uint16(&bytes[2..4]),
        parse_uint16(&bytes[4..6]),
        parse_uint16(&bytes[6..8]),
        parse_uint16(&bytes[8..10]),
        parse_uint16(&bytes[10..12]),
        parse_uint16(&bytes[12..14]),
        parse_uint16(&bytes[14..16]),
    );
    format!("{}", addr).into_bytes()
}

/// Parse big-endian u16
fn parse_uint16(bytes: &[u8]) -> u16 {
    ((bytes[0] as u16) << 8) | (bytes[1] as u16)
}

/// Find length of first line (until CR or LF)
fn find_line_len(buf: &[u8]) -> usize {
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\r' || b == b'\n' {
            return i;
        }
    }
    buf.len()
}

/// Write v1 PROXY protocol header
pub fn write(_log: &Log, src: &SockAddr, dst: &SockAddr) -> Option<Vec<u8>> {
    match (src, dst) {
        (SockAddr::V4(src_addr), SockAddr::V4(dst_addr)) => {
            let mut result = b"PROXY TCP4 ".to_vec();
            result.extend_from_slice(&format!("{}", src_addr.ip()).into_bytes());
            result.push(b' ');
            result.extend_from_slice(&format!("{}", dst_addr.ip()).into_bytes());
            result.push(b' ');
            result.extend_from_slice(&format!("{}", src_addr.port()).into_bytes());
            result.push(b' ');
            result.extend_from_slice(&format!("{}", dst_addr.port()).into_bytes());
            result.extend_from_slice(b"\r\n");
            Some(result)
        }
        (SockAddr::V6(src_addr), SockAddr::V6(dst_addr)) => {
            let mut result = b"PROXY TCP6 ".to_vec();
            result.extend_from_slice(&format!("{}", src_addr.ip()).into_bytes());
            result.push(b' ');
            result.extend_from_slice(&format!("{}", dst_addr.ip()).into_bytes());
            result.push(b' ');
            result.extend_from_slice(&format!("{}", src_addr.port()).into_bytes());
            result.push(b' ');
            result.extend_from_slice(&format!("{}", dst_addr.port()).into_bytes());
            result.extend_from_slice(b"\r\n");
            Some(result)
        }
        _ => {
            // Unsupported family mix or Unix socket
            Some(b"PROXY UNKNOWN\r\n".to_vec())
        }
    }
}

/// ngx_proxy_protocol_get_tlv: the value of a TLV by name ("alpn",
/// "ssl_cn", "ssl_verify", "0x2c", ...); Ok(None) is NGX_DECLINED
pub fn get_tlv(pp: &ProxyProtocol, log: &Log, name: &[u8]) -> Result<Option<Vec<u8>>, ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "PROXY protocol v2 get tlv \"{}\"", B(name));

    let mut te: &[(&str, u8)] = TLV_ENTRIES;
    let mut tlvs: &[u8] = &pp.tlvs;

    let mut p = name;

    if p.len() >= 4 && &p[..4] == b"ssl_" {
        let (off, len) = match lookup_tlv_range(log, tlvs, NGX_PROXY_PROTOCOL_TLV_SSL as u64)? {
            Some(r) => r,
            None => return Ok(None),
        };

        let ssl = &tlvs[off..off + len];

        // ngx_proxy_protocol_tlv_ssl_t: client, verify[4]
        if ssl.len() < 5 {
            return Err(());
        }

        p = &p[4..];

        if p == b"verify" {
            let verify = u32::from_be_bytes([ssl[1], ssl[2], ssl[3], ssl[4]]);
            return Ok(Some(verify.to_string().into_bytes()));
        }

        te = TLV_SSL_ENTRIES;
        tlvs = &ssl[5..];
    }

    if p.len() >= 2 && p[0] == b'0' && p[1] == b'x' {
        let ty = match crate::string::hextoi(&p[2..]) {
            Some(t) => t,
            None => {
                ngx_log_error!(NGX_LOG_ERR, log, None, "invalid PROXY protocol TLV \"{}\"", B(name));
                return Err(());
            }
        };

        return lookup_tlv(log, tlvs, ty as u64);
    }

    for (n, ty) in te.iter() {
        if n.as_bytes() == p {
            return lookup_tlv(log, tlvs, *ty as u64);
        }
    }

    ngx_log_error!(NGX_LOG_ERR, log, None, "unknown PROXY protocol TLV \"{}\"", B(name));

    Ok(None)
}

/// ngx_proxy_protocol_tlv_entries
static TLV_ENTRIES: &[(&str, u8)] = &[
    ("alpn", NGX_PROXY_PROTOCOL_TLV_ALPN),
    ("authority", NGX_PROXY_PROTOCOL_TLV_AUTHORITY),
    ("unique_id", NGX_PROXY_PROTOCOL_TLV_UNIQUE_ID),
    ("ssl", NGX_PROXY_PROTOCOL_TLV_SSL),
    ("netns", NGX_PROXY_PROTOCOL_TLV_NETNS),
];

/// ngx_proxy_protocol_tlv_ssl_entries
static TLV_SSL_ENTRIES: &[(&str, u8)] = &[
    ("version", NGX_PROXY_PROTOCOL_TLV_SSL_VERSION),
    ("cn", NGX_PROXY_PROTOCOL_TLV_SSL_CN),
    ("cipher", NGX_PROXY_PROTOCOL_TLV_SSL_CIPHER),
    ("sig_alg", NGX_PROXY_PROTOCOL_TLV_SSL_SIG_ALG),
    ("key_alg", NGX_PROXY_PROTOCOL_TLV_SSL_KEY_ALG),
];

/// ngx_proxy_protocol_lookup_tlv
fn lookup_tlv(log: &Log, tlvs: &[u8], tlv_type: u64) -> Result<Option<Vec<u8>>, ()> {
    Ok(lookup_tlv_range(log, tlvs, tlv_type)?.map(|(off, len)| tlvs[off..off + len].to_vec()))
}

/// ngx_proxy_protocol_lookup_tlv: the offset and the length of the value
fn lookup_tlv_range(log: &Log, tlvs: &[u8], tlv_type: u64) -> Result<Option<(usize, usize)>, ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, log, "PROXY protocol v2 lookup tlv:{:02x}", tlv_type);

    let mut p = 0;

    while p < tlvs.len() {
        if tlvs.len() - p < 3 {
            ngx_log_error!(NGX_LOG_ERR, log, None, "broken PROXY protocol TLV");
            return Err(());
        }

        let ty = tlvs[p];
        let len = parse_uint16(&tlvs[p + 1..p + 3]) as usize;
        p += 3;

        if tlvs.len() - p < len {
            ngx_log_error!(NGX_LOG_ERR, log, None, "broken PROXY protocol TLV");
            return Err(());
        }

        if ty as u64 == tlv_type {
            return Ok(Some((p, len)));
        }

        p += len;
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Log;

    #[test]
    fn test_read_v1_tcp4() {
        let log = Log::stderr(NGX_LOG_ERR);
        let header = b"PROXY TCP4 192.0.2.1 198.51.100.2 54321 443\r\n";
        let (pp, consumed) = read(&log, header).unwrap();
        let pp = pp.unwrap();
        assert_eq!(pp.src_addr, b"192.0.2.1");
        assert_eq!(pp.dst_addr, b"198.51.100.2");
        assert_eq!(pp.src_port, 54321);
        assert_eq!(pp.dst_port, 443);
        assert_eq!(consumed, header.len());
    }

    #[test]
    fn test_read_v1_tcp6() {
        let log = Log::stderr(NGX_LOG_ERR);
        let header = b"PROXY TCP6 2001:db8::1 2001:db8::2 54321 443\r\n";
        let (pp, consumed) = read(&log, header).unwrap();
        let pp = pp.unwrap();
        assert_eq!(pp.src_addr, b"2001:db8::1");
        assert_eq!(pp.dst_addr, b"2001:db8::2");
        assert_eq!(pp.src_port, 54321);
        assert_eq!(pp.dst_port, 443);
        assert_eq!(consumed, header.len());
    }

    #[test]
    fn test_read_v1_unknown() {
        let log = Log::stderr(NGX_LOG_ERR);
        let header = b"PROXY UNKNOWN\r\n";
        let (pp, consumed) = read(&log, header).unwrap();
        assert!(pp.is_none());
        assert_eq!(consumed, header.len());
    }

    #[test]
    fn test_read_v1_broken_no_crlf() {
        let log = Log::stderr(NGX_LOG_ERR);
        let header = b"PROXY TCP4 192.0.2.1 198.51.100.2 54321 443";
        assert!(read(&log, header).is_err());
    }

    #[test]
    fn test_read_v2_ipv4() {
        let log = Log::stderr(NGX_LOG_ERR);
        // PROXY v2 header structure:
        // 0-11: Signature (12 bytes)
        // 12: Version (4 bits) + Command (4 bits)
        // 13: Family (4 bits) + Transport (4 bits)
        // 14-15: Length (2 bytes, big-endian)
        // 16-27: IPv4 addresses (4+4+2+2 bytes)
        let mut header = vec![0u8; 28];
        header[0..12].copy_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
        header[12] = 0x21; // version=2 (0x2), command=1 (0x1)
        header[13] = 0x11; // family=1 (0x1), transport=1 (0x1)
        header[14..16].copy_from_slice(&12u16.to_be_bytes()); // data length = 12 bytes

        // IPv4 addresses: 192.0.2.1:54321 -> 198.51.100.2:443
        header[16..20].copy_from_slice(&[192, 0, 2, 1]);
        header[20..24].copy_from_slice(&[198, 51, 100, 2]);
        header[24..26].copy_from_slice(&54321u16.to_be_bytes());
        header[26..28].copy_from_slice(&443u16.to_be_bytes());

        let (pp, consumed) = read(&log, &header).unwrap();
        let pp = pp.unwrap();
        assert_eq!(pp.src_addr, b"192.0.2.1");
        assert_eq!(pp.dst_addr, b"198.51.100.2");
        assert_eq!(pp.src_port, 54321);
        assert_eq!(pp.dst_port, 443);
        assert_eq!(consumed, 28);
    }

    #[test]
    fn test_write_ipv4() {
        let log = Log::stderr(NGX_LOG_ERR);
        let src = SockAddr::V4(SocketAddrV4::new([192, 0, 2, 1].into(), 54321));
        let dst = SockAddr::V4(SocketAddrV4::new([198, 51, 100, 2].into(), 443));
        let result = write(&log, &src, &dst).unwrap();
        assert!(result.starts_with(b"PROXY TCP4 "));
        assert!(result.ends_with(b"\r\n"));
    }

    #[test]
    fn test_write_ipv6() {
        let log = Log::stderr(NGX_LOG_ERR);
        let src = SockAddr::V6(SocketAddrV6::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(), 54321, 0, 0));
        let dst = SockAddr::V6(SocketAddrV6::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2].into(), 443, 0, 0));
        let result = write(&log, &src, &dst).unwrap();
        assert!(result.starts_with(b"PROXY TCP6 "));
        assert!(result.ends_with(b"\r\n"));
    }

    #[test]
    fn test_get_tlv_hex() {
        let pp = ProxyProtocol {
            src_addr: vec![],
            dst_addr: vec![],
            src_port: 0,
            dst_port: 0,
            tlvs: vec![
                0x01, // type = 0x01 (ALPN)
                0x00, 0x04, // length = 4
                b'h', b't', b't', b'p', // value
            ],
        };
        let log = Log::stderr(NGX_LOG_ERR);
        let result = get_tlv(&pp, &log, b"0x01").unwrap();
        assert_eq!(result, Some(b"http".to_vec()));
    }
}

/// The address of a sockaddr without the port, as ngx_sock_ntop(.., 0).
fn sock_ntop_noport(sa: &SockAddr) -> Vec<u8> {
    sa.to_text(false)
}

/// ngx_proxy_protocol_write: the v1 header of a connection with the client
/// address `sockaddr` accepted on `local`.
pub fn proxy_protocol_write(sockaddr: &SockAddr, local: &SockAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(NGX_PROXY_PROTOCOL_V1_MAX_HEADER);

    match sockaddr {
        SockAddr::V4(_) => buf.extend_from_slice(b"PROXY TCP4 "),
        SockAddr::V6(_) => buf.extend_from_slice(b"PROXY TCP6 "),
        _ => return b"PROXY UNKNOWN\r\n".to_vec(),
    }

    buf.extend_from_slice(&sock_ntop_noport(sockaddr));
    buf.push(b' ');
    buf.extend_from_slice(&sock_ntop_noport(local));

    let port = sockaddr.port();
    let lport = local.port();

    buf.extend_from_slice(format!(" {} {}\r\n", port, lport).as_bytes());

    buf
}

/// ngx_crc32c_table256
const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut k = 0;
        while k < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
            k += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC32C_TABLE256: [u32; 256] = crc32c_table();

/// ngx_crc32c_long
pub fn crc32c_long(p: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in p {
        crc = CRC32C_TABLE256[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

/// ngx_proxy_protocol_v2_family
fn v2_family(sa: &SockAddr) -> u8 {
    match sa {
        SockAddr::V4(_) => NGX_PROXY_PROTOCOL_AF_INET,
        SockAddr::V6(_) => NGX_PROXY_PROTOCOL_AF_INET6,
        _ => NGX_PROXY_PROTOCOL_AF_UNSPEC,
    }
}

/// ngx_proxy_protocol_v2_write_ipv6: an IPv4 address is promoted to
/// ::ffff:a.b.c.d
fn v2_write_ipv6(buf: &mut Vec<u8>, sa: &SockAddr) -> [u8; 2] {
    match sa {
        SockAddr::V6(a) => {
            buf.extend_from_slice(&a.ip().octets());
            a.port().to_be_bytes()
        }
        SockAddr::V4(a) => {
            buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
            buf.extend_from_slice(&a.ip().octets());
            a.port().to_be_bytes()
        }
        _ => [0, 0],
    }
}

/// The SSL TLV of a v2 header (ngx_proxy_protocol_v2_write_ssl).
pub struct ProxyProtocolSslTlv {
    pub client: u8,
    pub verify: u32,
    pub tlvs: Vec<(u8, Vec<u8>)>,
}

fn v2_write_tlv(buf: &mut Vec<u8>, ty: u8, value: &[u8]) {
    buf.push(ty);
    buf.push((value.len() >> 8) as u8);
    buf.push(value.len() as u8);
    buf.extend_from_slice(value);
}

/// ngx_proxy_protocol_v2_write: the v2 header of a connection (`ty`:
/// SOCK_STREAM or SOCK_DGRAM) with the client address `sockaddr` accepted
/// on `local`, the TLVs (the SSL ones evaluated by the caller:
/// ngx_proxy_protocol_v2_eval_ssl) and the CRC32c TLV.
pub fn proxy_protocol_v2_write(sockaddr: &SockAddr, local: &SockAddr, ty: i32, tlvs: &[(u8, Vec<u8>)], ssl: Option<&ProxyProtocolSslTlv>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(NGX_PROXY_PROTOCOL_V2_MAX_HEADER);

    // ngx_proxy_protocol_v2_write_header

    buf.extend_from_slice(NGX_PROXY_PROTOCOL_SIGNATURE);

    let src_af = v2_family(sockaddr);
    let dst_af = v2_family(local);

    // promote to the highest address family present on either side

    let (command, family, transport) = if src_af == NGX_PROXY_PROTOCOL_AF_UNSPEC || dst_af == NGX_PROXY_PROTOCOL_AF_UNSPEC {
        (NGX_PROXY_PROTOCOL_CMD_LOCAL, NGX_PROXY_PROTOCOL_AF_UNSPEC, NGX_PROXY_PROTOCOL_TYPE_UNSPEC)
    } else {
        let transport = match ty {
            libc::SOCK_STREAM => NGX_PROXY_PROTOCOL_TYPE_STREAM,
            libc::SOCK_DGRAM => NGX_PROXY_PROTOCOL_TYPE_DGRAM,
            _ => NGX_PROXY_PROTOCOL_TYPE_UNSPEC,
        };
        (NGX_PROXY_PROTOCOL_CMD_PROXY, src_af.max(dst_af), transport)
    };

    buf.push(0x20 | command);
    buf.push((family << 4) | transport);

    // the length, set once all TLVs are written
    buf.extend_from_slice(&[0, 0]);

    let header_len = buf.len();

    match family {
        NGX_PROXY_PROTOCOL_AF_INET => {
            let (SockAddr::V4(src), SockAddr::V4(dst)) = (sockaddr, local) else { unreachable!() };
            buf.extend_from_slice(&src.ip().octets());
            buf.extend_from_slice(&dst.ip().octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }

        NGX_PROXY_PROTOCOL_AF_INET6 => {
            let mapped = |sa: &SockAddr| match sa {
                SockAddr::V6(a) => a.ip().to_ipv4_mapped(),
                _ => None,
            };

            match (mapped(sockaddr), mapped(local)) {
                (Some(src4), Some(dst4)) => {
                    // both v4-mapped: demote to AF_INET

                    buf[13] = (NGX_PROXY_PROTOCOL_AF_INET << 4) | transport;

                    buf.extend_from_slice(&src4.octets());
                    buf.extend_from_slice(&dst4.octets());
                    buf.extend_from_slice(&sockaddr.port().to_be_bytes());
                    buf.extend_from_slice(&local.port().to_be_bytes());
                }
                _ => {
                    let src_port = v2_write_ipv6(&mut buf, sockaddr);
                    let dst_port = v2_write_ipv6(&mut buf, local);
                    buf.extend_from_slice(&src_port);
                    buf.extend_from_slice(&dst_port);
                }
            }
        }

        _ => {}
    }

    for (ty, value) in tlvs {
        v2_write_tlv(&mut buf, *ty, value);
    }

    if let Some(ssl) = ssl {
        // ngx_proxy_protocol_v2_write_ssl

        let mut value = Vec::new();
        value.push(ssl.client);
        value.extend_from_slice(&ssl.verify.to_be_bytes());

        for (ty, v) in ssl.tlvs.iter() {
            v2_write_tlv(&mut value, *ty, v);
        }

        v2_write_tlv(&mut buf, NGX_PROXY_PROTOCOL_TLV_SSL, &value);
    }

    // ngx_proxy_protocol_v2_set_len: with the CRC32c TLV

    let len = buf.len() + 3 + 4 - header_len;
    buf[14] = (len >> 8) as u8;
    buf[15] = len as u8;

    // ngx_proxy_protocol_v2_write_crc32c: the checksum covers the entire
    // header with the zeroed value

    buf.push(NGX_PROXY_PROTOCOL_TLV_CRC32C);
    buf.push(0);
    buf.push(4);

    let at = buf.len();
    buf.extend_from_slice(&[0, 0, 0, 0]);

    let crc = crc32c_long(&buf);

    buf[at..at + 4].copy_from_slice(&crc.to_be_bytes());

    buf
}

#[cfg(test)]
mod write_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn crc32c_check_value() {
        // the check value of CRC-32C (Castagnoli)
        assert_eq!(crc32c_long(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c_long(b""), 0);
    }

    #[test]
    fn v1_header() {
        let src = SockAddr::v4(Ipv4Addr::new(127, 0, 0, 1), 5000);
        let dst = SockAddr::v4(Ipv4Addr::new(127, 0, 0, 2), 8080);
        assert_eq!(proxy_protocol_write(&src, &dst), b"PROXY TCP4 127.0.0.1 127.0.0.2 5000 8080\r\n");

        let src6 = SockAddr::v6(Ipv6Addr::LOCALHOST, 1);
        assert_eq!(proxy_protocol_write(&src6, &dst), b"PROXY TCP6 ::1 127.0.0.2 1 8080\r\n");

        let unix = SockAddr::Unix(b"/tmp/s".to_vec());
        assert_eq!(proxy_protocol_write(&unix, &dst), b"PROXY UNKNOWN\r\n");
    }

    #[test]
    fn v2_header_inet() {
        let src = SockAddr::v4(Ipv4Addr::new(10, 0, 0, 1), 0x1234);
        let dst = SockAddr::v4(Ipv4Addr::new(10, 0, 0, 2), 0x5678);

        let h = proxy_protocol_v2_write(&src, &dst, libc::SOCK_STREAM, &[], None);

        // signature, PROXY command, INET/STREAM, 12 bytes of addresses and
        // the 7 bytes of the CRC32c TLV
        assert_eq!(&h[..12], NGX_PROXY_PROTOCOL_SIGNATURE);
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x11);
        assert_eq!(u16::from_be_bytes([h[14], h[15]]) as usize, 12 + 7);
        assert_eq!(&h[16..20], &[10, 0, 0, 1]);
        assert_eq!(&h[20..24], &[10, 0, 0, 2]);
        assert_eq!(&h[24..26], &[0x12, 0x34]);
        assert_eq!(&h[26..28], &[0x56, 0x78]);
        assert_eq!(&h[28..31], &[NGX_PROXY_PROTOCOL_TLV_CRC32C, 0, 4]);

        // the checksum is of the header with the zeroed value
        let mut zeroed = h.clone();
        zeroed[31..35].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(u32::from_be_bytes([h[31], h[32], h[33], h[34]]), crc32c_long(&zeroed));

        // the header reads back
        let (pp, size) = read(&Log::stderr(0), &h).expect("valid header");
        let pp = pp.expect("addresses");
        assert_eq!(size, h.len());
        assert_eq!(pp.src_addr, b"10.0.0.1");
        assert_eq!(pp.dst_port, 0x5678);
    }

    #[test]
    fn v2_header_mapped_and_unix() {
        let src = SockAddr::v6("::ffff:1.2.3.4".parse().unwrap(), 1);
        let dst = SockAddr::v6("::ffff:5.6.7.8".parse().unwrap(), 2);

        // both v4-mapped: demoted to AF_INET
        let h = proxy_protocol_v2_write(&src, &dst, libc::SOCK_DGRAM, &[], None);
        assert_eq!(h[13], 0x12);
        assert_eq!(&h[16..20], &[1, 2, 3, 4]);

        // a unix client: LOCAL with no addresses
        let unix = SockAddr::Unix(b"/tmp/s".to_vec());
        let h = proxy_protocol_v2_write(&unix, &dst, libc::SOCK_STREAM, &[], None);
        assert_eq!(h[12], 0x20);
        assert_eq!(h[13], 0x00);
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 7);
    }
}

// --- the SSL TLVs of a v2 header ---

pub const NGX_PROXY_PROTOCOL_V2_CLIENT_SSL: u8 = 0x01;
pub const NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_CONN: u8 = 0x02;
pub const NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_SESS: u8 = 0x04;

/// ngx_proxy_protocol_v2_ssl_sub: Ok(None) is NGX_DECLINED
fn v2_ssl_sub(c: &crate::connection::Connection, ssl: &openssl::ssl::SslRef, ty: u8) -> Result<Option<Vec<u8>>, ()> {
    use openssl::nid::Nid;
    use openssl::pkey::Id;

    match ty {
        NGX_PROXY_PROTOCOL_TLV_SSL_VERSION => Ok(Some(ssl.version_str().as_bytes().to_vec())),

        // SSL_get_cipher_name(): "(NONE)" without a cipher
        NGX_PROXY_PROTOCOL_TLV_SSL_CIPHER => Ok(Some(ssl.current_cipher().map(|cipher| cipher.name()).unwrap_or("(NONE)").as_bytes().to_vec())),

        NGX_PROXY_PROTOCOL_TLV_SSL_CN => {
            let cert = match ssl.peer_certificate() {
                Some(cert) => cert,
                None => return Ok(None),
            };

            let entry = match cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
                Some(e) => e,
                None => return Ok(None),
            };

            match entry.data().to_string() {
                Ok(s) => Ok(Some(s.into_bytes())),
                Err(e) => {
                    e.put();
                    crate::event_openssl::ngx_ssl_error(NGX_LOG_ALERT, &c.log, 0, format_args!("ASN1_STRING_to_UTF8() failed"));
                    Err(())
                }
            }
        }

        NGX_PROXY_PROTOCOL_TLV_SSL_SIG_ALG => {
            let cert = match ssl.certificate() {
                Some(cert) => cert,
                None => return Ok(None),
            };

            // OBJ_nid2sn(X509_get_signature_nid(cert))
            Ok(Some(cert.signature_algorithm().object().nid().short_name().unwrap_or("").as_bytes().to_vec()))
        }

        NGX_PROXY_PROTOCOL_TLV_SSL_KEY_ALG => {
            let cert = match ssl.certificate() {
                Some(cert) => cert,
                None => return Ok(None),
            };

            let pkey = match cert.public_key() {
                Ok(p) => p,
                Err(_) => return Err(()),
            };

            let alg = match pkey.id() {
                Id::RSA | Id::RSA_PSS => "RSA",
                Id::EC => "EC",
                Id::DSA => "DSA",
                _ => return Ok(None),
            };

            Ok(Some(format!("{}{}", alg, pkey.bits()).into_bytes()))
        }

        _ => Ok(None),
    }
}

/// ngx_proxy_protocol_v2_eval_ssl: the TLVs of the TLS client connection
/// (authority, ALPN) and its SSL TLV
pub fn proxy_protocol_v2_eval_ssl(c: &crate::connection::Connection) -> Result<(Vec<(u8, Vec<u8>)>, ProxyProtocolSslTlv), ()> {
    // X509_V_ERR_CERT_REVOKED
    const X509_V_ERR_CERT_REVOKED: i64 = 23;

    crate::event_openssl::ngx_ssl_with(c, |ssl| {
        let mut tlvs = Vec::new();

        // ngx_proxy_protocol_v2_authority
        if let Some(sni) = ssl.servername_raw(openssl::ssl::NameType::HOST_NAME) {
            tlvs.push((NGX_PROXY_PROTOCOL_TLV_AUTHORITY, sni.to_vec()));
        }

        // ngx_proxy_protocol_v2_alpn
        if let Some(alpn) = ssl.selected_alpn_protocol().filter(|a| !a.is_empty()) {
            tlvs.push((NGX_PROXY_PROTOCOL_TLV_ALPN, alpn.to_vec()));
        }

        let mut ssl_tlvs = Vec::new();

        for ty in NGX_PROXY_PROTOCOL_TLV_SSL_VERSION..=NGX_PROXY_PROTOCOL_TLV_SSL_KEY_ALG {
            if let Some(v) = v2_ssl_sub(c, ssl, ty)? {
                ssl_tlvs.push((ty, v));
            }
        }

        let mut client = NGX_PROXY_PROTOCOL_V2_CLIENT_SSL;
        // X509_V_ERR_UNSPECIFIED
        let mut verify: u32 = 1;

        if ssl.peer_certificate().is_some() {
            client |= NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_SESS;

            if !ssl.session_reused() {
                client |= NGX_PROXY_PROTOCOL_V2_CLIENT_CERT_CONN;
            }

            let mut n = ssl.verify_result().as_raw() as i64;

            if n == 0 && crate::event_openssl_stapling::ngx_ssl_ocsp_get_status(c).is_err() {
                n = X509_V_ERR_CERT_REVOKED;
            }

            verify = n as u32;
        }

        Ok((tlvs, ProxyProtocolSslTlv { client, verify, tlvs: ssl_tlvs }))
    })
    .unwrap_or(Err(()))
}
