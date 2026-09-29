//! Address parsing and formatting, ported from ngx_inet.c.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use crate::string::{atoi, starts_with_ignore_case, B};

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum SockAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Unix(Vec<u8>),
}

impl SockAddr {
    pub fn family(&self) -> i32 {
        match self {
            SockAddr::V4(_) => libc::AF_INET,
            SockAddr::V6(_) => libc::AF_INET6,
            SockAddr::Unix(_) => libc::AF_UNIX,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            SockAddr::V4(a) => a.port(),
            SockAddr::V6(a) => a.port(),
            SockAddr::Unix(_) => 0,
        }
    }

    pub fn set_port(&mut self, port: u16) {
        match self {
            SockAddr::V4(a) => a.set_port(port),
            SockAddr::V6(a) => a.set_port(port),
            SockAddr::Unix(_) => {}
        }
    }

    pub fn is_wildcard(&self) -> bool {
        match self {
            SockAddr::V4(a) => a.ip().is_unspecified(),
            SockAddr::V6(a) => a.ip().is_unspecified(),
            SockAddr::Unix(_) => false,
        }
    }

    pub fn is_unix(&self) -> bool {
        matches!(self, SockAddr::Unix(_))
    }

    /// ngx_sock_ntop
    pub fn to_text(&self, with_port: bool) -> Vec<u8> {
        match self {
            SockAddr::V4(a) => {
                if with_port {
                    format!("{}:{}", a.ip(), a.port()).into_bytes()
                } else {
                    format!("{}", a.ip()).into_bytes()
                }
            }
            SockAddr::V6(a) => {
                let text = inet6_ntop(&a.ip().octets());
                if with_port {
                    let mut v = Vec::with_capacity(text.len() + 8);
                    v.push(b'[');
                    v.extend_from_slice(&text);
                    v.extend_from_slice(format!("]:{}", a.port()).as_bytes());
                    v
                } else {
                    text
                }
            }
            SockAddr::Unix(p) => {
                let mut v = b"unix:".to_vec();
                v.extend_from_slice(p);
                v
            }
        }
    }

    /// Address text without port (ngx_sock_ntop with port=0).
    pub fn addr_text(&self) -> Vec<u8> {
        self.to_text(false)
    }

    /// Convert to libc sockaddr_storage + length.
    pub fn to_libc(&self) -> (libc::sockaddr_storage, libc::socklen_t) {
        let mut ss: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        match self {
            SockAddr::V4(a) => {
                let sin = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = a.port().to_be();
                sin.sin_addr.s_addr = u32::from(*a.ip()).to_be();
                (ss, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SockAddr::V6(a) => {
                let sin6 = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6) };
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = a.port().to_be();
                sin6.sin6_addr.s6_addr = a.ip().octets();
                sin6.sin6_flowinfo = a.flowinfo();
                sin6.sin6_scope_id = a.scope_id();
                (ss, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
            SockAddr::Unix(p) => {
                let sun = unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_un) };
                sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
                let n = p.len().min(sun.sun_path.len() - 1);
                for i in 0..n {
                    sun.sun_path[i] = p[i] as libc::c_char;
                }
                (ss, std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t)
            }
        }
    }

    /// Convert from libc sockaddr.
    pub fn from_libc(sa: *const libc::sockaddr, len: libc::socklen_t) -> Option<SockAddr> {
        if sa.is_null() {
            return None;
        }
        let family = unsafe { (*sa).sa_family } as i32;
        match family {
            libc::AF_INET => {
                let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
                Some(SockAddr::V4(SocketAddrV4::new(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)), u16::from_be(sin.sin_port))))
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
                Some(SockAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    sin6.sin6_flowinfo,
                    sin6.sin6_scope_id,
                )))
            }
            libc::AF_UNIX => {
                let sun = unsafe { &*(sa as *const libc::sockaddr_un) };
                let off = std::mem::size_of::<libc::sa_family_t>();
                if (len as usize) <= off {
                    return Some(SockAddr::Unix(Vec::new()));
                }
                let max = (len as usize - off).min(sun.sun_path.len());
                let mut p = Vec::new();
                for i in 0..max {
                    let c = sun.sun_path[i] as u8;
                    if c == 0 {
                        break;
                    }
                    p.push(c);
                }
                Some(SockAddr::Unix(p))
            }
            _ => None,
        }
    }

    /// ngx_cmp_sockaddr
    pub fn cmp(&self, other: &SockAddr, cmp_port: bool) -> bool {
        match (self, other) {
            (SockAddr::V4(a), SockAddr::V4(b)) => a.ip() == b.ip() && (!cmp_port || a.port() == b.port()),
            (SockAddr::V6(a), SockAddr::V6(b)) => a.ip() == b.ip() && (!cmp_port || a.port() == b.port()),
            (SockAddr::Unix(a), SockAddr::Unix(b)) => a == b,
            _ => false,
        }
    }

    pub fn ip_bytes(&self) -> Vec<u8> {
        match self {
            SockAddr::V4(a) => a.ip().octets().to_vec(),
            SockAddr::V6(a) => a.ip().octets().to_vec(),
            SockAddr::Unix(_) => Vec::new(),
        }
    }

    pub fn v4(ip: Ipv4Addr, port: u16) -> SockAddr {
        SockAddr::V4(SocketAddrV4::new(ip, port))
    }

    pub fn v6(ip: Ipv6Addr, port: u16) -> SockAddr {
        SockAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
    }
}

/// ngx_inet_addr: strict dotted quad; returns host-order address.
pub fn inet_addr(text: &[u8]) -> Option<Ipv4Addr> {
    let mut addr: u32 = 0;
    let mut octet: u32 = 0;
    let mut n = 0;
    for &c in text {
        if c.is_ascii_digit() {
            octet = octet * 10 + (c - b'0') as u32;
            if octet > 255 {
                return None;
            }
            continue;
        }
        if c == b'.' {
            addr = (addr << 8) + octet;
            octet = 0;
            n += 1;
            continue;
        }
        return None;
    }
    if n == 3 {
        addr = (addr << 8) + octet;

        // INADDR_NONE: "255.255.255.255" is an error for the callers
        if addr == 0xffffffff {
            return None;
        }

        return Some(Ipv4Addr::from(addr));
    }
    None
}

/// ngx_inet6_addr
pub fn inet6_addr(text: &[u8]) -> Option<Ipv6Addr> {
    let mut addr = [0u8; 16];
    let mut a = 0usize;

    let mut p = text;

    if p.is_empty() {
        return None;
    }

    let mut zero: Option<usize> = None;
    let mut digit: Option<&[u8]> = None;
    let mut nibbles = 0u32;
    let mut word = 0u32;
    let mut n = 8u32;

    if p[0] == b':' {
        p = &p[1..];
    }

    let mut rest = p;

    while let Some((&c, tail)) = rest.split_first() {
        rest = tail;

        if c == b':' {
            if nibbles != 0 {
                digit = Some(rest);
                addr[a] = (word >> 8) as u8;
                addr[a + 1] = (word & 0xff) as u8;
                a += 2;

                n -= 1;

                if n != 0 {
                    nibbles = 0;
                    word = 0;
                    continue;
                }
            } else if zero.is_none() {
                digit = Some(rest);
                zero = Some(a);
                continue;
            }

            return None;
        }

        if c == b'.' && nibbles != 0 {
            let digit = match digit {
                Some(d) if n >= 2 => d,
                _ => return None,
            };

            // the IPv4 part: from the last ':' to the end
            let v4 = u32::from(inet_addr(digit)?);

            addr[a] = ((v4 >> 24) & 0xff) as u8;
            addr[a + 1] = ((v4 >> 16) & 0xff) as u8;
            a += 2;
            n -= 1;

            word = v4 & 0xffff;
            nibbles = 1;
            rest = &[];
            break;
        }

        nibbles += 1;

        if nibbles > 4 {
            return None;
        }

        if c.is_ascii_digit() {
            word = word * 16 + (c - b'0') as u32;
            continue;
        }

        let c = c | 0x20;

        if (b'a'..=b'f').contains(&c) {
            word = word * 16 + (c - b'a') as u32 + 10;
            continue;
        }

        return None;
    }

    let _ = rest;

    if nibbles == 0 && zero.is_none() {
        return None;
    }

    addr[a] = (word >> 8) as u8;
    addr[a + 1] = (word & 0xff) as u8;
    a += 2;

    n -= 1;

    if n != 0 {
        if let Some(z) = zero {
            // move the words after "::" to the end
            let shift = n as usize * 2;
            addr.copy_within(z..a, z + shift);
            for b in addr[z..z + shift].iter_mut() {
                *b = 0;
            }
            return Some(Ipv6Addr::from(addr));
        }
    } else if zero.is_none() {
        return Some(Ipv6Addr::from(addr));
    }

    None
}

/// ngx_inet6_ntop
pub fn inet6_ntop(p: &[u8; 16]) -> Vec<u8> {
    let mut zero = usize::MAX;
    let mut last = usize::MAX;
    let mut max = 1usize;
    let mut n = 0usize;

    for i in (0..16).step_by(2) {
        if p[i] != 0 || p[i + 1] != 0 {
            if max < n {
                zero = last;
                max = n;
            }

            n = 0;
            continue;
        }

        if n == 0 {
            last = i;
        }

        n += 1;
    }

    if max < n {
        zero = last;
        max = n;
    }

    let mut dst = Vec::with_capacity(46);
    let mut n = 16;

    if zero == 0 {
        if (max == 5 && p[10] == 0xff && p[11] == 0xff) || max == 6 || (max == 7 && p[14] != 0 && p[15] != 1) {
            n = 12;
        }

        dst.push(b':');
    }

    let mut i = 0;

    while i < n {
        if i == zero {
            dst.push(b':');
            i += (max - 1) * 2 + 2;
            continue;
        }

        dst.extend_from_slice(format!("{:x}", p[i] as u32 * 256 + p[i + 1] as u32).as_bytes());

        if i < 14 {
            dst.push(b':');
        }

        i += 2;
    }

    if n == 12 {
        dst.extend_from_slice(format!("{}.{}.{}.{}", p[12], p[13], p[14], p[15]).as_bytes());
    }

    dst
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cidr {
    V4 { addr: u32, mask: u32 },
    V6 { addr: [u8; 16], mask: [u8; 16] },
    Unix,
}

impl Cidr {
    pub fn family(&self) -> i32 {
        match self {
            Cidr::V4 { .. } => libc::AF_INET,
            Cidr::V6 { .. } => libc::AF_INET6,
            Cidr::Unix => libc::AF_UNIX,
        }
    }

    /// ngx_cidr_match for a single cidr: an IPv4-mapped IPv6 address is
    /// AF_INET, it matches IPv4 cidrs only.
    pub fn matches(&self, sa: &SockAddr) -> bool {
        if let SockAddr::V6(a) = sa {
            // IN6_IS_ADDR_V4MAPPED
            if let Some(v4) = a.ip().to_ipv4_mapped() {
                return match self {
                    Cidr::V4 { addr, mask } => (u32::from(v4) & mask) == *addr,
                    _ => false,
                };
            }
        }

        match (self, sa) {
            (Cidr::V4 { addr, mask }, SockAddr::V4(a)) => (u32::from(*a.ip()) & mask) == *addr,
            (Cidr::V6 { addr, mask }, SockAddr::V6(a)) => {
                let o = a.ip().octets();
                (0..16).all(|i| (o[i] & mask[i]) == addr[i])
            }
            (Cidr::Unix, SockAddr::Unix(_)) => true,
            _ => false,
        }
    }
}

pub enum CidrParse {
    Ok(Cidr),
    /// Low bits were non-zero and have been cleared (NGX_DONE).
    Done(Cidr),
    Error,
}

/// ngx_ptocidr
pub fn ptocidr(text: &[u8]) -> CidrParse {
    let (addr_text, mask_text) = match memchr::memchr(b'/', text) {
        Some(i) => (&text[..i], Some(&text[i + 1..])),
        None => (text, None),
    };
    if let Some(a4) = inet_addr(addr_text) {
        let addr = u32::from(a4);
        let mask_text = match mask_text {
            None => return CidrParse::Ok(Cidr::V4 { addr, mask: 0xffffffff }),
            Some(m) => m,
        };
        let shift = match atoi(mask_text) {
            Some(s) => s,
            None => return CidrParse::Error,
        };
        if shift > 32 {
            return CidrParse::Error;
        }
        let mask: u32 = if shift > 0 { 0xffffffffu32 << (32 - shift) } else { 0 };
        if addr == addr & mask {
            return CidrParse::Ok(Cidr::V4 { addr, mask });
        }
        return CidrParse::Done(Cidr::V4 { addr: addr & mask, mask });
    }
    if let Some(a6) = inet6_addr(addr_text) {
        let mut addr = a6.octets();
        let mask_text = match mask_text {
            None => return CidrParse::Ok(Cidr::V6 { addr, mask: [0xff; 16] }),
            Some(m) => m,
        };
        let mut shift = match atoi(mask_text) {
            Some(s) => s,
            None => return CidrParse::Error,
        };
        if shift > 128 {
            return CidrParse::Error;
        }
        let mut mask = [0u8; 16];
        let mut done = false;
        for i in 0..16 {
            let s = if shift > 8 { 8 } else { shift };
            shift -= s;
            mask[i] = (0xffu32 << (8 - s)) as u8;
            if addr[i] != addr[i] & mask[i] {
                done = true;
                addr[i] &= mask[i];
            }
        }
        if done {
            return CidrParse::Done(Cidr::V6 { addr, mask });
        }
        return CidrParse::Ok(Cidr::V6 { addr, mask });
    }
    CidrParse::Error
}

/// ngx_parse_addr: IPv4 or IPv6 text (no port). None if not an address (NGX_DECLINED).
pub fn parse_addr(text: &[u8]) -> Option<SockAddr> {
    if let Some(a) = inet_addr(text) {
        return Some(SockAddr::v4(a, 0));
    }
    if let Some(a) = inet6_addr(text) {
        return Some(SockAddr::v6(a, 0));
    }
    None
}

/// ngx_parse_addr_port: an address, "addr:port", "[addr]:port" or "[addr]";
/// None if not an address (NGX_DECLINED).
pub fn parse_addr_port(text: &[u8]) -> Option<SockAddr> {
    if let Some(a) = parse_addr(text) {
        return Some(a);
    }

    let last = text.len();

    let (host, port): (&[u8], &[u8]);

    if !text.is_empty() && text[0] == b'[' {
        let p = memchr::memchr(b']', text);

        if p == Some(last - 1) {
            return parse_addr(&text[1..last - 1]);
        }

        // p < last - 1: the character after "]" must be ":"
        let p = match p {
            Some(p) if text[p + 1] == b':' => p + 1,
            _ => return None,
        };

        host = &text[1..p - 1];
        port = &text[p + 1..];
    } else {
        let p = memchr::memchr(b':', text)?;

        host = &text[..p];
        port = &text[p + 1..];
    }

    let port = match atoi(port) {
        Some(n) if (1..=65535).contains(&n) => n as u16,
        _ => return None,
    };

    let mut a = parse_addr(host)?;

    a.set_port(port);

    Some(a)
}

#[derive(Clone, Debug)]
pub struct Addr {
    pub sockaddr: SockAddr,
    pub name: Vec<u8>,
}

/// ngx_url_t
#[derive(Clone, Debug, Default)]
pub struct Url {
    pub url: Vec<u8>,
    pub host: Vec<u8>,
    pub port_text: Vec<u8>,
    pub uri: Vec<u8>,
    pub port: u16,
    pub last_port: u16,
    pub default_port: u16,
    pub family: i32,
    pub listen: bool,
    pub uri_part: bool,
    pub no_resolve: bool,
    pub no_port: bool,
    pub wildcard: bool,
    pub err: Option<&'static str>,
    pub sockaddr: Option<SockAddr>,
    pub addrs: Vec<Addr>,
}

impl Url {
    pub fn new(url: &[u8]) -> Url {
        Url { url: url.to_vec(), ..Default::default() }
    }
}

/// ngx_inet_add_addr: an address for each port of a listen port range
fn add_addr(u: &mut Url, sa: SockAddr) {
    u.sockaddr = Some(sa.clone());
    let nports = if u.last_port != 0 { u.last_port - u.port + 1 } else { 1 };
    for i in 0..nports {
        let mut sa = sa.clone();
        sa.set_port(u.port + i);
        let name = sa.to_text(true);
        u.addrs.push(Addr { sockaddr: sa, name });
    }
}

/// ngx_parse_url. On error, returns Err and sets u.err (may be None for resolve errors already set).
pub fn parse_url(u: &mut Url) -> Result<(), ()> {
    let url = u.url.clone();
    if url.len() >= 5 && starts_with_ignore_case(&url, b"unix:") {
        return parse_unix_domain_url(u, &url);
    }
    if !url.is_empty() && url[0] == b'[' {
        return parse_inet6_url(u, &url);
    }
    parse_inet_url(u, &url)
}

fn parse_unix_domain_url(u: &mut Url, url: &[u8]) -> Result<(), ()> {
    let mut path = &url[5..];
    if u.uri_part {
        if let Some(i) = memchr::memchr(b':', path) {
            u.uri = path[i + 1..].to_vec();
            path = &path[..i];
        }
    }
    if path.is_empty() {
        u.err = Some("no path in the unix domain socket");
        return Err(());
    }
    u.host = path.to_vec();
    if path.len() + 1 > 108 {
        u.err = Some("too long path in the unix domain socket");
        return Err(());
    }
    u.family = libc::AF_INET;
    u.family = libc::AF_UNIX;
    let sa = SockAddr::Unix(path.to_vec());
    u.sockaddr = Some(sa.clone());
    let mut name = b"unix:".to_vec();
    name.extend_from_slice(path);
    u.addrs.push(Addr { sockaddr: sa, name });
    Ok(())
}

fn parse_inet_url(u: &mut Url, url: &[u8]) -> Result<(), ()> {
    u.family = libc::AF_INET;
    let mut last = url.len();
    let host_start = 0usize;
    let mut port = memchr::memchr(b':', url);
    let mut uri = memchr::memchr(b'/', url);
    let args = memchr::memchr(b'?', url);
    if let Some(a) = args {
        if uri.is_none() || a < uri.unwrap() {
            uri = Some(a);
        }
    }
    if let Some(ui) = uri {
        if u.listen || !u.uri_part {
            u.err = Some("invalid host");
            return Err(());
        }
        u.uri = url[ui..].to_vec();
        last = ui;
        if let Some(p) = port {
            if ui < p {
                port = None;
            }
        }
    }
    let mut host_end = last;
    if let Some(p) = port {
        let port_start = p + 1;
        let mut len = last - port_start;
        if u.listen {
            if let Some(d) = memchr::memchr(b'-', &url[port_start..last]) {
                let dash = port_start + d + 1;
                let n = atoi(&url[dash..last]);
                match n {
                    Some(n) if (1..=65535).contains(&n) => u.last_port = n as u16,
                    _ => {
                        u.err = Some("invalid port");
                        return Err(());
                    }
                }
                len = dash - port_start - 1;
            }
        }
        let n = atoi(&url[port_start..port_start + len]);
        let n = match n {
            Some(n) if (1..=65535).contains(&n) => n,
            _ => {
                u.err = Some("invalid port");
                return Err(());
            }
        };
        if u.last_port != 0 && n > u.last_port as i64 {
            u.err = Some("invalid port range");
            return Err(());
        }
        u.port = n as u16;
        u.port_text = url[port_start..last].to_vec();
        host_end = p;
    } else {
        let mut handled = false;
        if uri.is_none() && u.listen {
            // test value as port only
            let mut len = last - host_start;
            let mut skip = false;
            if let Some(d) = memchr::memchr(b'-', &url[..last]) {
                let dash = d + 1;
                match atoi(&url[dash..last]) {
                    None => skip = true,
                    Some(n) => {
                        if !(1..=65535).contains(&n) {
                            u.err = Some("invalid port");
                        } else {
                            u.last_port = n as u16;
                        }
                        len = dash - 1;
                    }
                }
            }
            if !skip {
                if let Some(n) = atoi(&url[..len]) {
                    if u.err.is_some() {
                        return Err(());
                    }
                    if !(1..=65535).contains(&n) {
                        u.err = Some("invalid port");
                        return Err(());
                    }
                    if u.last_port != 0 && n > u.last_port as i64 {
                        u.err = Some("invalid port range");
                        return Err(());
                    }
                    u.port = n as u16;
                    u.port_text = url[..last].to_vec();
                    u.wildcard = true;
                    add_addr(u, SockAddr::v4(Ipv4Addr::UNSPECIFIED, u.port));
                    handled = true;
                }
            }
        }
        if handled {
            return Ok(());
        }
        u.err = None;
        u.no_port = true;
        u.port = u.default_port;
        u.last_port = 0;
    }

    let host = &url[host_start..host_end];
    if host.is_empty() {
        u.err = Some("no host");
        return Err(());
    }
    u.host = host.to_vec();

    if u.listen && host == b"*" {
        u.wildcard = true;
        add_addr(u, SockAddr::v4(Ipv4Addr::UNSPECIFIED, u.port));
        return Ok(());
    }

    if let Some(a) = inet_addr(host) {
        if a.is_unspecified() {
            u.wildcard = true;
        }
        add_addr(u, SockAddr::v4(a, u.port));
        return Ok(());
    }

    if u.no_resolve {
        return Ok(());
    }

    inet_resolve_host(u)?;
    let first = u.addrs[0].sockaddr.clone();
    u.family = first.family();
    u.wildcard = first.is_wildcard();
    u.sockaddr = Some(first);
    Ok(())
}

fn parse_inet6_url(u: &mut Url, url: &[u8]) -> Result<(), ()> {
    let host_start = 1;
    let mut last = url.len();
    let p = match memchr::memchr(b']', url) {
        Some(p) => p,
        None => {
            u.err = Some("invalid host");
            return Err(());
        }
    };
    let mut port = p + 1;
    if let Some(ui) = memchr::memchr(b'/', &url[port..]) {
        let ui = port + ui;
        if u.listen || !u.uri_part {
            u.err = Some("invalid host");
            return Err(());
        }
        u.uri = url[ui..].to_vec();
        last = ui;
    }
    if port < last {
        if url[port] != b':' {
            u.err = Some("invalid host");
            return Err(());
        }
        port += 1;
        let mut len = last - port;
        if u.listen {
            if let Some(d) = memchr::memchr(b'-', &url[port..last]) {
                let dash = port + d + 1;
                match atoi(&url[dash..last]) {
                    Some(n) if (1..=65535).contains(&n) => u.last_port = n as u16,
                    _ => {
                        u.err = Some("invalid port");
                        return Err(());
                    }
                }
                len = dash - port - 1;
            }
        }
        let n = match atoi(&url[port..port + len]) {
            Some(n) if (1..=65535).contains(&n) => n,
            _ => {
                u.err = Some("invalid port");
                return Err(());
            }
        };
        if u.last_port != 0 && n > u.last_port as i64 {
            u.err = Some("invalid port range");
            return Err(());
        }
        u.port = n as u16;
        u.port_text = url[port..last].to_vec();
    } else {
        u.no_port = true;
        u.port = u.default_port;
    }
    let host = &url[host_start..p];
    if host.is_empty() {
        u.err = Some("no host");
        return Err(());
    }
    u.host = url[host_start - 1..p + 1].to_vec();
    let a = match inet6_addr(host) {
        Some(a) => a,
        None => {
            u.err = Some("invalid IPv6 address");
            return Err(());
        }
    };
    if a.is_unspecified() {
        u.wildcard = true;
    }
    u.family = libc::AF_INET6;
    add_addr(u, SockAddr::v6(a, u.port));
    Ok(())
}

/// ngx_inet_resolve_host via getaddrinfo.
pub fn inet_resolve_host(u: &mut Url) -> Result<(), ()> {
    let host = crate::os::cstr(&u.host);
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = unsafe { libc::getaddrinfo(host.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        u.err = Some("host not found");
        return Err(());
    }
    let mut addrs = Vec::new();
    let mut rp = res;
    while !rp.is_null() {
        let ai = unsafe { &*rp };
        if let Some(mut sa) = SockAddr::from_libc(ai.ai_addr, ai.ai_addrlen) {
            if matches!(sa, SockAddr::V4(_) | SockAddr::V6(_)) {
                sa.set_port(u.port);
                let name = sa.to_text(true);
                addrs.push(Addr { sockaddr: sa, name });
            }
        }
        rp = ai.ai_next;
    }
    unsafe { libc::freeaddrinfo(res) };
    if addrs.is_empty() {
        u.err = Some("host not found");
        return Err(());
    }
    u.addrs = addrs;
    Ok(())
}

/// Format for error messages like nginx: e.g. "127.0.0.1:8080"
pub fn fmt_addr(sa: &SockAddr) -> String {
    B(&sa.to_text(true)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet() {
        assert_eq!(inet_addr(b"127.0.0.1"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(inet_addr(b"256.0.0.1"), None);
        assert_eq!(inet_addr(b"1.2.3"), None);
        assert_eq!(inet_addr(b"255.255.255.255"), None);
        assert_eq!(inet_addr(b"255.255.255.254"), Some(Ipv4Addr::new(255, 255, 255, 254)));
        assert!(matches!(ptocidr(b"10.0.0.0/8"), CidrParse::Ok(Cidr::V4 { addr: 0x0a000000, mask: 0xff000000 })));
        assert!(matches!(ptocidr(b"10.0.0.1/8"), CidrParse::Done(_)));
        assert!(matches!(ptocidr(b"10.0.0.1/33"), CidrParse::Error));
    }

    #[test]
    fn addr_port() {
        let v4 = |a, b, c, d, port| Some(SockAddr::v4(Ipv4Addr::new(a, b, c, d), port));
        let v6 = |s: &str, port| Some(SockAddr::v6(s.parse().unwrap(), port));

        assert_eq!(parse_addr_port(b"192.0.2.1"), v4(192, 0, 2, 1, 0));
        assert_eq!(parse_addr_port(b"192.0.2.1:8080"), v4(192, 0, 2, 1, 8080));
        assert_eq!(parse_addr_port(b"::1"), v6("::1", 0));
        assert_eq!(parse_addr_port(b"[::1]:80"), v6("::1", 80));
        assert_eq!(parse_addr_port(b"[::1]"), v6("::1", 0));
        assert_eq!(parse_addr_port(b"[192.0.2.1]:80"), v4(192, 0, 2, 1, 80));
        assert_eq!(parse_addr_port(b"[192.0.2.1]"), v4(192, 0, 2, 1, 0));

        // not addresses in ngx_parse_addr_port
        assert_eq!(parse_addr_port(b""), None);
        assert_eq!(parse_addr_port(b"unix:/tmp/x"), None);
        assert_eq!(parse_addr_port(b"192.0.2.1:0"), None);
        assert_eq!(parse_addr_port(b"192.0.2.1:65536"), None);
        assert_eq!(parse_addr_port(b"192.0.2.1:"), None);
        assert_eq!(parse_addr_port(b"[::1]x"), None);
        assert_eq!(parse_addr_port(b"[::1"), None);
        assert_eq!(parse_addr_port(b"["), None);
        assert_eq!(parse_addr_port(b"[]"), None);
        assert_eq!(parse_addr_port(b",192.0.2.1"), None);
        assert_eq!(parse_addr_port(b"localhost:80"), None);
    }

    #[test]
    fn inet6_addr_as_c() {
        let a = |s: &str| inet6_addr(s.as_bytes()).map(|a| a.to_string());

        assert_eq!(a("::1"), Some("::1".into()));
        assert_eq!(a("::"), Some("::".into()));
        assert_eq!(a("2001:db8::1"), Some("2001:db8::1".into()));
        assert_eq!(a("1:2:3:4:5:6:7:8"), Some("1:2:3:4:5:6:7:8".into()));
        assert_eq!(a("::ffff:1.2.3.4"), Some("::ffff:1.2.3.4".into()));
        assert_eq!(a("1:2:3:4:5:6:1.2.3.4"), Some("1:2:3:4:5:6:102:304".into()));
        assert_eq!(a("1::"), Some("1::".into()));
        assert_eq!(a("ABCD::EF"), Some("abcd::ef".into()));

        // a leading ":" is skipped by ngx_inet6_addr
        assert_eq!(a(":1:2:3:4:5:6:7:8"), Some("1:2:3:4:5:6:7:8".into()));

        // INADDR_NONE in the IPv4 part
        assert_eq!(a("::ffff:255.255.255.255"), None);

        assert_eq!(a(""), None);
        assert_eq!(a(":::"), None);
        assert_eq!(a("1::2::3"), None);
        assert_eq!(a("12345::"), None);
        assert_eq!(a("1:2:3:4:5:6:7:8:9"), None);
        assert_eq!(a("1:2:3:4:5:6:7:8:"), None);
        assert_eq!(a("1::2:3:4:5:6:7:8"), None);
        assert_eq!(a("::1%eth0"), None);
        assert_eq!(a("g::1"), None);
        assert_eq!(a("1:2:3:4:5:6:7:1.2.3.4"), None);
    }

    #[test]
    fn inet6_ntop_as_c() {
        let t = |s: &str| String::from_utf8(inet6_ntop(&s.parse::<Ipv6Addr>().unwrap().octets())).unwrap();

        assert_eq!(t("::1"), "::1");
        assert_eq!(t("::"), "::");
        assert_eq!(t("::ffff:127.0.0.1"), "::ffff:127.0.0.1");
        assert_eq!(t("2001:db8::1"), "2001:db8::1");
        assert_eq!(t("1::"), "1::");
        assert_eq!(t("1:0:0:2::"), "1:0:0:2::");
        assert_eq!(t("1:0:1:0:1:0:1:0"), "1:0:1:0:1:0:1:0");
        assert_eq!(t("1:2:3:4:5:6:7:8"), "1:2:3:4:5:6:7:8");

        // the IPv4-compatible forms of ngx_inet6_ntop
        assert_eq!(t("::102:304"), "::1.2.3.4");
        assert_eq!(t("::100"), "::0.0.1.0");
        assert_eq!(t("::2"), "::2");
        assert_eq!(t("::201"), "::201");
        assert_eq!(t("::ffff:0:0"), "::ffff:0.0.0.0");
    }

    #[test]
    fn cidr_match() {
        let v4 = |s: &str| SockAddr::v4(s.parse().unwrap(), 0);
        let v6 = |s: &str| SockAddr::v6(s.parse().unwrap(), 0);
        let cidr = |s: &[u8]| match ptocidr(s) {
            CidrParse::Ok(c) => c,
            _ => panic!("cidr"),
        };

        assert!(cidr(b"10.0.0.0/8").matches(&v4("10.1.2.3")));
        assert!(!cidr(b"10.0.0.0/8").matches(&v4("11.1.2.3")));
        assert!(cidr(b"2001:db8::/32").matches(&v6("2001:db8::1")));
        assert!(cidr(b"::/0").matches(&v6("::1")));

        // an IPv4-mapped address is AF_INET in ngx_cidr_match
        assert!(cidr(b"10.0.0.0/8").matches(&v6("::ffff:10.0.0.1")));
        assert!(!cidr(b"::/0").matches(&v6("::ffff:10.0.0.1")));
        assert!(!cidr(b"::ffff:0.0.0.0/96").matches(&v6("::ffff:10.0.0.1")));

        assert!(!cidr(b"10.0.0.0/8").matches(&SockAddr::Unix(b"/tmp/x".to_vec())));
        assert!(Cidr::Unix.matches(&SockAddr::Unix(b"/tmp/x".to_vec())));
        assert!(!Cidr::Unix.matches(&v4("10.0.0.1")));
    }

    #[test]
    fn urls() {
        let mut u = Url::new(b"127.0.0.1:8080");
        u.listen = true;
        parse_url(&mut u).unwrap();
        assert_eq!(u.port, 8080);
        assert_eq!(u.addrs[0].name, b"127.0.0.1:8080".to_vec());
        let mut u = Url::new(b"8080");
        u.listen = true;
        parse_url(&mut u).unwrap();
        assert!(u.wildcard);
        let mut u = Url::new(b"[::1]:8080");
        u.listen = true;
        parse_url(&mut u).unwrap();
        assert_eq!(u.addrs[0].name, b"[::1]:8080".to_vec());
        let mut u = Url::new(b"unix:/tmp/sock");
        parse_url(&mut u).unwrap();
        assert_eq!(u.addrs[0].name, b"unix:/tmp/sock".to_vec());
        let mut u = Url::new(b"localhost:80/path");
        u.uri_part = true;
        u.no_resolve = true;
        parse_url(&mut u).unwrap();
        assert_eq!(u.uri, b"/path".to_vec());
        assert_eq!(u.host, b"localhost".to_vec());
    }
}
