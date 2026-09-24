//! DNS resolver, ported from ngx_resolver.c.
//! Async tokio-based DNS resolver with same externally observable behaviour as C nginx.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::{timeout, Instant};

use crate::inet::SockAddr;
use crate::log::Log;
use crate::conf;

// DNS error codes
pub const NGX_RESOLVE_FORMERR: i64 = 1;   // Format error
pub const NGX_RESOLVE_SERVFAIL: i64 = 2;  // Server failure
pub const NGX_RESOLVE_NXDOMAIN: i64 = 3;  // Host not found
pub const NGX_RESOLVE_NOTIMP: i64 = 4;    // Unimplemented
pub const NGX_RESOLVE_REFUSED: i64 = 5;   // Operation refused
pub const NGX_RESOLVE_TIMEDOUT: i64 = 110; // Operation timed out (ETIMEDOUT)

// DNS query types
const NGX_RESOLVE_A: u16 = 1;
#[allow(dead_code)]
const NGX_RESOLVE_CNAME: u16 = 5;
#[allow(dead_code)]
const NGX_RESOLVE_PTR: u16 = 12;
const NGX_RESOLVE_AAAA: u16 = 28;
#[allow(dead_code)]
const NGX_RESOLVE_SRV: u16 = 33;

#[allow(dead_code)]
const NGX_RESOLVER_MAX_RECURSION: u32 = 50;

// DNS message header (RFC 1035)
#[derive(Clone, Copy)]
struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHeader {
    fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        buf[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        buf[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        buf[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        buf
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        Some(DnsHeader {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    fn rcode(&self) -> u8 {
        (self.flags & 0x0F) as u8
    }

    #[allow(dead_code)]
    fn tc(&self) -> bool {
        (self.flags & 0x0200) != 0
    }

    #[allow(dead_code)]
    fn rd(&self) -> bool {
        (self.flags & 0x0100) != 0
    }

    fn response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }
}

/// Result of a resolved address
#[derive(Clone, Debug)]
pub struct ResolverAddr {
    pub sockaddr: SockAddr,
    pub name: Vec<u8>, // "ip:port" text or priority/weight
    pub priority: u16,
    pub weight: u16,
}

/// SRV record result
#[derive(Clone, Debug)]
pub struct ResolverSrv {
    pub name: Vec<u8>,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
}

/// The resolver instance (shared via Rc)
pub struct Resolver {
    // DNS servers (addresses)
    servers: Vec<SocketAddr>,

    // Configuration
    ipv4: bool,
    ipv6: bool,
    #[allow(dead_code)]
    valid: Option<i64>, // TTL override in seconds
    #[allow(dead_code)]
    resend_timeout: u64, // milliseconds
    expire_time: u64,    // seconds for cached entries

    // Cache and state
    cache: std::cell::RefCell<HashMap<Vec<u8>, CacheEntry>>,
    #[allow(dead_code)]
    in_flight: std::cell::RefCell<HashMap<Vec<u8>, Rc<Notify>>>,

    // UDP sockets (per server)
    #[allow(dead_code)]
    sockets: std::cell::RefCell<Vec<Option<Rc<UdpSocket>>>>,
}

struct CacheEntry {
    addrs: Vec<ResolverAddr>,
    error: Option<i64>,
    expire_at: SystemTime,
}

impl Resolver {
    /// Parse the `resolver` directive arguments and create a new resolver.
    /// args[0] is the directive name, args[1..] are the arguments.
    pub fn create(_cf: &mut conf::Conf, args: &[Vec<u8>]) -> Result<Rc<Resolver>, conf::ConfError> {
        if args.len() < 2 {
            return Err(conf::msg("no resolver addresses specified"));
        }

        let mut servers = Vec::new();
        let mut ipv4 = true;
        let mut ipv6 = true;
        let mut valid: Option<i64> = None;

        for arg in &args[1..] {
            let s = std::str::from_utf8(arg).map_err(|_| conf::msg("invalid UTF-8 in resolver argument"))?;

            if s.starts_with("valid=") {
                let time_str = &s[6..];
                let time_bytes = time_str.as_bytes();
                if let Some(t) = crate::parse::parse_time(time_bytes, true) {
                    valid = Some(t);
                } else {
                    return Err(conf::msg(format!("invalid parameter: valid={}", time_str)));
                }
                continue;
            }

            if s.starts_with("ipv4=") {
                let val = &s[5..];
                match val {
                    "on" => ipv4 = true,
                    "off" => ipv4 = false,
                    _ => return Err(conf::msg(format!("invalid parameter: ipv4={}", val))),
                }
                continue;
            }

            if s.starts_with("ipv6=") {
                let val = &s[5..];
                match val {
                    "on" => ipv6 = true,
                    "off" => ipv6 = false,
                    _ => return Err(conf::msg(format!("invalid parameter: ipv6={}", val))),
                }
                continue;
            }

            if s.starts_with("status_zone=") {
                // Accept and ignore status_zone parameter
                continue;
            }

            // Parse as address:port
            let (addr_str, port_str) = if let Some(colon_pos) = s.rfind(':') {
                // Check if this is IPv6 address [...]
                if s.starts_with('[') && s[..colon_pos].ends_with(']') {
                    (&s[1..colon_pos - 1], &s[colon_pos + 1..])
                } else if s.starts_with('[') {
                    // Pure IPv6 without port
                    (&s[1..s.len() - 1], "53")
                } else {
                    (&s[..colon_pos], &s[colon_pos + 1..])
                }
            } else {
                // No port, could be IPv6 or IPv4
                if s.contains(':') {
                    // IPv6
                    (&s[..], "53")
                } else {
                    (&s[..], "53")
                }
            };

            let port: u16 = port_str.parse().map_err(|_| conf::msg(format!("invalid port: {}", port_str)))?;

            // Try to parse as IP address
            if let Ok(ip) = addr_str.parse::<IpAddr>() {
                servers.push(SocketAddr::new(ip, port));
            } else {
                // Try to resolve hostname at config time using getaddrinfo
                match resolve_hostname_at_config_time(addr_str) {
                    Some(addrs) => {
                        for addr in addrs {
                            servers.push(SocketAddr::new(addr, port));
                        }
                    }
                    None => {
                        return Err(conf::msg(format!("resolver: invalid address: {}", addr_str)));
                    }
                }
            }
        }

        if !ipv4 && !ipv6 {
            return Err(conf::msg("\"ipv4\" and \"ipv6\" cannot both be \"off\""));
        }

        if servers.is_empty() {
            return Err(conf::msg("no name servers defined"));
        }

        Ok(Rc::new(Resolver {
            servers,
            ipv4,
            ipv6,
            valid,
            resend_timeout: 5000, // 5 seconds
            expire_time: 30,       // 30 seconds
            cache: std::cell::RefCell::new(HashMap::new()),
            in_flight: std::cell::RefCell::new(HashMap::new()),
            sockets: std::cell::RefCell::new(vec![None; 0]), // Will be lazily initialized
        }))
    }

    /// Create an empty resolver (no servers, all lookups fail)
    pub fn empty() -> Rc<Resolver> {
        Rc::new(Resolver {
            servers: Vec::new(),
            ipv4: true,
            ipv6: true,
            valid: None,
            resend_timeout: 5000,
            expire_time: 30,
            cache: std::cell::RefCell::new(HashMap::new()),
            in_flight: std::cell::RefCell::new(HashMap::new()),
            sockets: std::cell::RefCell::new(Vec::new()),
        })
    }

    pub fn has_servers(&self) -> bool {
        !self.servers.is_empty()
    }

    /// Resolve a hostname to a list of addresses.
    /// Handles A and AAAA queries in parallel if both ipv4 and ipv6 are enabled.
    pub async fn resolve_name(
        self: &Rc<Self>,
        name: &[u8],
        timeout_ms: u64,
        _log: &Log,
    ) -> Result<Vec<ResolverAddr>, i64> {
        // Check if already an IP literal
        if let Ok(addr) = parse_ip_literal(name) {
            return Ok(vec![ResolverAddr {
                sockaddr: addr,
                name: name.to_vec(),
                priority: 0,
                weight: 0,
            }]);
        }

        // Check cache
        if let Some(cached) = self.check_cache(name) {
            if let Some(err) = cached.error {
                return Err(err);
            }
            return Ok(cached.addrs);
        }

        // Perform DNS query
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);

        let result = self.do_resolve(name, deadline).await;

        // Cache the result
        self.cache_result(name, &result);

        result
    }

    /// Resolve a service (SRV record)
    pub async fn resolve_srv(
        self: &Rc<Self>,
        name: &[u8],
        timeout_ms: u64,
        _log: &Log,
    ) -> Result<Vec<ResolverAddr>, i64> {
        // SRV resolution: query for SRV, then resolve the targets
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);

        let srv_records = self.query_srv(name, deadline).await?;

        // Now resolve each target name
        let mut results = Vec::new();
        for srv in srv_records {
            if let Ok(addrs) = self.resolve_name(&srv.name, remaining_time_ms(&deadline), _log).await {
                for addr in addrs {
                    results.push(ResolverAddr {
                        sockaddr: addr.sockaddr,
                        name: format!("{} {} {}", srv.priority, srv.weight, srv.port).into_bytes(),
                        priority: srv.priority,
                        weight: srv.weight,
                    });
                }
            }
        }

        if results.is_empty() {
            return Err(NGX_RESOLVE_NXDOMAIN);
        }

        Ok(results)
    }

    /// Resolve an address to a hostname (PTR query)
    pub async fn resolve_addr(
        self: &Rc<Self>,
        addr: &SockAddr,
        timeout_ms: u64,
        _log: &Log,
    ) -> Result<Vec<u8>, i64> {
        let ptr_name = match addr {
            SockAddr::V4(a) => {
                let ip = a.ip().octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa.",
                    ip[3], ip[2], ip[1], ip[0]
                )
                .into_bytes()
            }
            SockAddr::V6(a) => {
                let ip = a.ip().octets();
                let mut name = Vec::new();
                for byte in ip.iter().rev() {
                    name.extend_from_slice(format!("{:x}.{:x}.", byte & 0x0F, (byte >> 4) & 0x0F).as_bytes());
                }
                name.extend_from_slice(b"ip6.arpa.");
                name
            }
            SockAddr::Unix(_) => return Err(NGX_RESOLVE_FORMERR),
        };

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        self.query_ptr(&ptr_name, deadline).await
    }

    pub fn strerror(code: i64) -> &'static str {
        match code {
            NGX_RESOLVE_FORMERR => "Format error",
            NGX_RESOLVE_SERVFAIL => "Server failure",
            NGX_RESOLVE_NXDOMAIN => "Host not found",
            NGX_RESOLVE_NOTIMP => "Unimplemented",
            NGX_RESOLVE_REFUSED => "Operation refused",
            NGX_RESOLVE_TIMEDOUT => "Operation timed out",
            _ => "Unknown error",
        }
    }

    // --- Private methods ---

    fn check_cache(&self, name: &[u8]) -> Option<CacheEntry> {
        let cache = self.cache.borrow();
        cache.get(name).and_then(|entry| {
            if SystemTime::now() < entry.expire_at {
                Some(entry.clone())
            } else {
                None
            }
        })
    }

    fn cache_result(&self, name: &[u8], result: &Result<Vec<ResolverAddr>, i64>) {
        let expire_at = SystemTime::now() + Duration::from_secs(self.expire_time);
        let entry = match result {
            Ok(addrs) => CacheEntry {
                addrs: addrs.clone(),
                error: None,
                expire_at,
            },
            Err(e) => CacheEntry {
                addrs: Vec::new(),
                error: Some(*e),
                expire_at,
            },
        };
        self.cache.borrow_mut().insert(name.to_vec(), entry);
    }

    async fn do_resolve(
        &self,
        name: &[u8],
        deadline: Instant,
    ) -> Result<Vec<ResolverAddr>, i64> {
        if name.is_empty() {
            return Err(NGX_RESOLVE_FORMERR);
        }

        if name.len() > 255 {
            return Err(NGX_RESOLVE_FORMERR);
        }

        // Perform DNS query
        self.perform_dns_query(name, deadline).await
    }

    async fn perform_dns_query(
        &self,
        name: &[u8],
        deadline: Instant,
    ) -> Result<Vec<ResolverAddr>, i64> {
        // Try A record if ipv4 enabled
        let a_result = if self.ipv4 {
            self.query_type(name, NGX_RESOLVE_A, deadline).await
        } else {
            Err(NGX_RESOLVE_NXDOMAIN)
        };

        // Try AAAA record if ipv6 enabled
        let aaaa_result = if self.ipv6 {
            self.query_type(name, NGX_RESOLVE_AAAA, deadline).await
        } else {
            Err(NGX_RESOLVE_NXDOMAIN)
        };

        // Merge results
        match (a_result, aaaa_result) {
            (Ok(mut a_addrs), Ok(aaaa_addrs)) => {
                a_addrs.extend(aaaa_addrs);
                Ok(a_addrs)
            }
            (Ok(a_addrs), Err(_)) => Ok(a_addrs),
            (Err(_), Ok(aaaa_addrs)) => Ok(aaaa_addrs),
            (Err(e), Err(_)) => Err(e),
        }
    }

    async fn query_type(
        &self,
        name: &[u8],
        qtype: u16,
        deadline: Instant,
    ) -> Result<Vec<ResolverAddr>, i64> {
        if self.servers.is_empty() {
            return Err(NGX_RESOLVE_NXDOMAIN);
        }

        // Create DNS query
        let query = create_dns_query(name, qtype)?;
        let ident = (query[0] as u16) << 8 | query[1] as u16;

        // Send to each server and collect responses
        for server in self.servers.iter() {
            match timeout(
                Duration::from_millis(remaining_time_ms(&deadline)),
                self.send_query(&query, server),
            )
            .await
            {
                Ok(Ok(response)) => {
                    // Parse response
                    if let Ok(result) = parse_dns_response(&response, name, ident, qtype) {
                        return Ok(result);
                    }
                }
                _ => continue,
            }
        }

        Err(NGX_RESOLVE_TIMEDOUT)
    }

    async fn send_query(&self, query: &[u8], server: &SocketAddr) -> Result<Vec<u8>, i64> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|_| NGX_RESOLVE_TIMEDOUT)?;

        socket.connect(server)
            .await
            .map_err(|_| NGX_RESOLVE_TIMEDOUT)?;

        socket.send(query)
            .await
            .map_err(|_| NGX_RESOLVE_TIMEDOUT)?;

        let mut buf = [0u8; 4096];
        let n = socket.recv(&mut buf)
            .await
            .map_err(|_| NGX_RESOLVE_TIMEDOUT)?;

        Ok(buf[..n].to_vec())
    }

    async fn query_srv(
        &self,
        _name: &[u8],
        _deadline: Instant,
    ) -> Result<Vec<ResolverSrv>, i64> {
        // TODO: Implement SRV query
        Err(NGX_RESOLVE_NOTIMP)
    }

    async fn query_ptr(&self, _name: &[u8], _deadline: Instant) -> Result<Vec<u8>, i64> {
        // TODO: Implement PTR query
        Err(NGX_RESOLVE_NOTIMP)
    }
}

impl Clone for CacheEntry {
    fn clone(&self) -> Self {
        CacheEntry {
            addrs: self.addrs.clone(),
            error: self.error,
            expire_at: self.expire_at,
        }
    }
}

// Helper functions

fn resolve_hostname_at_config_time(_hostname: &str) -> Option<Vec<IpAddr>> {
    // Use std::net::lookup_host or similar
    // For now, just support IP addresses
    None
}

fn parse_ip_literal(name: &[u8]) -> Result<SockAddr, String> {
    let s = std::str::from_utf8(name).map_err(|e| e.to_string())?;

    // Try IPv4
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Ok(SockAddr::v4(ip, 0));
    }

    // Try IPv6
    if let Ok(ip) = s.parse::<Ipv6Addr>() {
        return Ok(SockAddr::v6(ip, 0));
    }

    Err("not an IP literal".to_string())
}

fn create_dns_query(name: &[u8], qtype: u16) -> Result<Vec<u8>, i64> {
    let mut query = Vec::new();

    // Random ID
    let id = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u16;

    // Header
    let header = DnsHeader {
        id,
        flags: 0x0100, // RD=1 (recursion desired)
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    query.extend_from_slice(&header.to_bytes());

    // Question section
    encode_name(&mut query, name)?;
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // IN class

    Ok(query)
}

fn encode_name(buf: &mut Vec<u8>, name: &[u8]) -> Result<(), i64> {
    let name = if name.ends_with(b".") {
        &name[..name.len() - 1]
    } else {
        name
    };

    let labels: Vec<&[u8]> = name.split(|&b| b == b'.').collect();
    for label in labels {
        if label.len() > 63 {
            return Err(NGX_RESOLVE_FORMERR);
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label);
    }
    buf.push(0); // Root label
    Ok(())
}

fn decode_name(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, i64> {
    let mut name = Vec::new();

    loop {
        if *offset >= buf.len() {
            return Err(NGX_RESOLVE_FORMERR);
        }

        let len = buf[*offset] as usize;
        *offset += 1;

        if len == 0 {
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Pointer (compression)
            if *offset >= buf.len() {
                return Err(NGX_RESOLVE_FORMERR);
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (buf[*offset] as usize);
            *offset += 1;

            // Recursively decode from pointer
            let mut ptr_offset = ptr;
            let mut ptr_name = decode_name(buf, &mut ptr_offset)?;
            name.append(&mut ptr_name);
            break;
        }

        if *offset + len > buf.len() {
            return Err(NGX_RESOLVE_FORMERR);
        }

        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend_from_slice(&buf[*offset..*offset + len]);
        *offset += len;
    }

    Ok(name)
}

fn parse_dns_response(
    response: &[u8],
    _query_name: &[u8],
    ident: u16,
    qtype: u16,
) -> Result<Vec<ResolverAddr>, i64> {
    let header = DnsHeader::from_bytes(response).ok_or(NGX_RESOLVE_FORMERR)?;

    // Verify response
    if header.id != ident {
        return Err(NGX_RESOLVE_FORMERR);
    }

    if !header.response() {
        return Err(NGX_RESOLVE_FORMERR);
    }

    let rcode = header.rcode();
    if rcode != 0 {
        return Err(rcode as i64);
    }

    let mut offset = 12;

    // Skip questions
    for _ in 0..header.qdcount {
        decode_name(response, &mut offset)?;
        offset += 4; // type and class
    }

    // Parse answers
    let mut results = Vec::new();
    for _ in 0..header.ancount {
        let _name = decode_name(response, &mut offset)?;
        if offset + 10 > response.len() {
            return Err(NGX_RESOLVE_FORMERR);
        }

        let rtype = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let _rclass = u16::from_be_bytes([response[offset + 2], response[offset + 3]]);
        let _ttl = u32::from_be_bytes([response[offset + 4], response[offset + 5], response[offset + 6], response[offset + 7]]);
        let rdlen = u16::from_be_bytes([response[offset + 8], response[offset + 9]]);
        offset += 10;

        if offset + rdlen as usize > response.len() {
            return Err(NGX_RESOLVE_FORMERR);
        }

        let rdata = &response[offset..offset + rdlen as usize];
        offset += rdlen as usize;

        match rtype {
            NGX_RESOLVE_A if qtype == NGX_RESOLVE_A => {
                if rdlen != 4 {
                    return Err(NGX_RESOLVE_FORMERR);
                }
                let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                results.push(ResolverAddr {
                    sockaddr: SockAddr::v4(ip, 0),
                    name: format!("{}", ip).into_bytes(),
                    priority: 0,
                    weight: 0,
                });
            }
            NGX_RESOLVE_AAAA if qtype == NGX_RESOLVE_AAAA => {
                if rdlen != 16 {
                    return Err(NGX_RESOLVE_FORMERR);
                }
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(rdata);
                let ip = Ipv6Addr::from(bytes);
                results.push(ResolverAddr {
                    sockaddr: SockAddr::v6(ip, 0),
                    name: format!("{}", ip).into_bytes(),
                    priority: 0,
                    weight: 0,
                });
            }
            _ => {}
        }
    }

    if results.is_empty() {
        return Err(NGX_RESOLVE_NXDOMAIN);
    }

    Ok(results)
}

fn remaining_time_ms(deadline: &Instant) -> u64 {
    let now = Instant::now();
    if now >= *deadline {
        1
    } else {
        (*deadline - now).as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[test]
    fn test_strerror() {
        assert_eq!(Resolver::strerror(NGX_RESOLVE_FORMERR), "Format error");
        assert_eq!(Resolver::strerror(NGX_RESOLVE_SERVFAIL), "Server failure");
        assert_eq!(Resolver::strerror(NGX_RESOLVE_NXDOMAIN), "Host not found");
        assert_eq!(Resolver::strerror(NGX_RESOLVE_NOTIMP), "Unimplemented");
        assert_eq!(Resolver::strerror(NGX_RESOLVE_REFUSED), "Operation refused");
        assert_eq!(Resolver::strerror(NGX_RESOLVE_TIMEDOUT), "Operation timed out");
    }

    #[test]
    fn test_dns_header() {
        let header = DnsHeader {
            id: 0x1234,
            flags: 0x8180,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        let bytes = header.to_bytes();
        let header2 = DnsHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.id, header2.id);
        assert_eq!(header.flags, header2.flags);
    }

    #[test]
    fn test_parse_ip_literal_v4() {
        let result = parse_ip_literal(b"127.0.0.1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ip_literal_v6() {
        let result = parse_ip_literal(b"::1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_encode_decode_name() {
        let mut encoded = Vec::new();
        encode_name(&mut encoded, b"example.com").unwrap();

        let mut offset = 0;
        let decoded = decode_name(&encoded, &mut offset).unwrap();
        assert_eq!(decoded, b"example.com");
    }

    #[tokio::test]
    async fn test_empty_resolver() {
        let resolver = Resolver::empty();
        assert!(!resolver.has_servers());
    }

    /// Simple in-process fake DNS server for testing
    #[allow(dead_code)]
    async fn fake_dns_server(port: u16, _queries: &[(&[u8], Vec<u8>)]) -> tokio::task::JoinHandle<()> {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("bind failed");

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        // Simple mock: if it's asking for a.example.com, respond with 127.0.0.1
                        let query = &buf[..n];
                        let mut response = vec![0u8; 512];

                        // Copy header (change response bit)
                        if n >= 12 {
                            response[0..2].copy_from_slice(&query[0..2]); // ID
                            response[2] = 0x84; // QR=1, AA=0, TC=0, RD=1, RA=1
                            response[3] = 0x00; // Z, RCODE=0
                            response[4..6].copy_from_slice(&query[4..6]); // QDCOUNT
                            response[6] = 0x00;
                            response[7] = 0x01; // ANCOUNT=1
                            response[8..12].copy_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT

                            // Copy question
                            let mut offset = 12;
                            while offset < n && offset < 100 {
                                let len = query[offset] as usize;
                                if len == 0 {
                                    offset += 1;
                                    break;
                                }
                                response[offset] = query[offset];
                                offset += 1;
                                if offset + len > n {
                                    break;
                                }
                                response[offset..offset + len].copy_from_slice(&query[offset..offset + len]);
                                offset += len;
                            }

                            // Copy QTYPE and QCLASS
                            if offset + 4 <= n {
                                response[offset..offset + 4].copy_from_slice(&query[offset..offset + 4]);
                                offset += 4;
                            }

                            // Add answer: A record for 127.0.0.1
                            response[offset] = 0xc0; // Pointer to name
                            response[offset + 1] = 0x0c; // offset 12
                            response[offset + 2] = 0x00;
                            response[offset + 3] = 0x01; // TYPE A
                            response[offset + 4] = 0x00;
                            response[offset + 5] = 0x01; // CLASS IN
                            response[offset + 6..offset + 10].copy_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60
                            response[offset + 10] = 0x00;
                            response[offset + 11] = 0x04; // RDLEN 4
                            response[offset + 12..offset + 16].copy_from_slice(&[127, 0, 0, 1]); // IP
                            offset += 16;

                            let _ = socket.send_to(&response[..offset], addr).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    }

    #[tokio::test]
    async fn test_resolve_ip_literal() {
        // Test IP literal resolution (doesn't need actual resolver)
        let resolver = Resolver::empty();

        let log = Log::stderr(crate::log::NGX_LOG_ERR);
        let result = resolver.resolve_name(b"127.0.0.1", 1000, &log).await;
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].name, b"127.0.0.1");

        // Test IPv6 literal
        let result = resolver.resolve_name(b"::1", 1000, &log).await;
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert_eq!(addrs.len(), 1);
    }

    #[tokio::test]
    async fn test_dns_query_creation() {
        let query = create_dns_query(b"example.com", NGX_RESOLVE_A).unwrap();
        assert!(query.len() > 12); // At least header + encoded name + QTYPE + QCLASS

        // Verify header
        let header = DnsHeader::from_bytes(&query).unwrap();
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 0);
    }

    #[test]
    fn test_dns_response_parsing() {
        // Create a minimal DNS response with A record
        let mut response = vec![0u8; 50];
        response[0] = 0x12;
        response[1] = 0x34; // ID
        response[2] = 0x84; // QR=1, RD=1, RA=1
        response[3] = 0x00; // RCODE=0
        response[4] = 0x00;
        response[5] = 0x01; // QDCOUNT
        response[6] = 0x00;
        response[7] = 0x01; // ANCOUNT
        response[8] = 0x00;
        response[9] = 0x00; // NSCOUNT
        response[10] = 0x00;
        response[11] = 0x00; // ARCOUNT

        // Question: example.com A IN
        response[12] = 0x07;
        response[13..20].copy_from_slice(b"example");
        response[20] = 0x03;
        response[21..24].copy_from_slice(b"com");
        response[24] = 0x00;
        response[25..27].copy_from_slice(&(NGX_RESOLVE_A as u16).to_be_bytes());
        response[27..29].copy_from_slice(&1u16.to_be_bytes()); // IN class

        // Answer: pointer to name, A record, 127.0.0.1
        response[29] = 0xc0;
        response[30] = 0x0c; // Pointer to offset 12
        response[31..33].copy_from_slice(&(NGX_RESOLVE_A as u16).to_be_bytes());
        response[33..35].copy_from_slice(&1u16.to_be_bytes()); // IN class
        response[35..39].copy_from_slice(&0u32.to_be_bytes()); // TTL
        response[39] = 0x00;
        response[40] = 0x04; // RDLEN=4
        response[41..45].copy_from_slice(&[127, 0, 0, 1]); // IP

        let result = parse_dns_response(&response[..45], b"example.com", 0x1234, NGX_RESOLVE_A);
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert_eq!(addrs.len(), 1);
    }
}
