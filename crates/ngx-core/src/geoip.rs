//! What ngx_http_geoip_module and ngx_stream_geoip_module use of the legacy
//! MaxMind GeoIP C library, libGeoIP 1.6.12 (GeoIP.c, GeoIPCity.c and
//! regionName.c), ported: GeoIP_open() with GEOIP_MEMORY_CACHE (the
//! database file is read into memory, its structure info read from its
//! end), the country, organization (name) and city lookups by IPv4 and
//! IPv6 address, GeoIP_set_charset() and GeoIP_region_name_by_code().
//!
//! The messages the library prints on stderr when GEOIP_SILENCE is not
//! set ("Error Opening file ...", "Error Traversing Database ...") are
//! printed the same way.  The C library behaves as if built with
//! NGX_HAVE_GEOIP_V6 (every 1.6 library has the _v6 functions).
//!
//! Where the C reads outside the database without checking (corrupt
//! files: a pointer to a name past its end, a city record cut by the end
//! of the file), the port reads the bytes outside the file as zeroes,
//! which is what follows the cache in memory most of the time.

use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;

use crate::conf::{Conf, ConfError};
use crate::string::B;

mod region_name;
mod tables;

// GeoIPOptions

pub const GEOIP_STANDARD: i32 = 0;
pub const GEOIP_MEMORY_CACHE: i32 = 1;
pub const GEOIP_CHECK_CACHE: i32 = 2;
pub const GEOIP_INDEX_CACHE: i32 = 4;
pub const GEOIP_MMAP_CACHE: i32 = 8;
pub const GEOIP_SILENCE: i32 = 16;

// GeoIPCharset

pub const GEOIP_CHARSET_ISO_8859_1: i32 = 0;
pub const GEOIP_CHARSET_UTF8: i32 = 1;

// GeoIPDBTypes

pub const GEOIP_COUNTRY_EDITION: i32 = 1;
pub const GEOIP_REGION_EDITION_REV0: i32 = 7;
pub const GEOIP_CITY_EDITION_REV0: i32 = 6;
pub const GEOIP_ORG_EDITION: i32 = 5;
pub const GEOIP_ISP_EDITION: i32 = 4;
pub const GEOIP_CITY_EDITION_REV1: i32 = 2;
pub const GEOIP_REGION_EDITION_REV1: i32 = 3;
pub const GEOIP_PROXY_EDITION: i32 = 8;
pub const GEOIP_ASNUM_EDITION: i32 = 9;
pub const GEOIP_NETSPEED_EDITION: i32 = 10;
pub const GEOIP_DOMAIN_EDITION: i32 = 11;
pub const GEOIP_COUNTRY_EDITION_V6: i32 = 12;
pub const GEOIP_LOCATIONA_EDITION: i32 = 13;
pub const GEOIP_ACCURACYRADIUS_EDITION: i32 = 14;
pub const GEOIP_CITYCONFIDENCE_EDITION: i32 = 15;
pub const GEOIP_CITYCONFIDENCEDIST_EDITION: i32 = 16;
pub const GEOIP_LARGE_COUNTRY_EDITION: i32 = 17;
pub const GEOIP_LARGE_COUNTRY_EDITION_V6: i32 = 18;
pub const GEOIP_CITYCONFIDENCEDIST_ISP_ORG_EDITION: i32 = 19;
pub const GEOIP_CCM_COUNTRY_EDITION: i32 = 20;
pub const GEOIP_ASNUM_EDITION_V6: i32 = 21;
pub const GEOIP_ISP_EDITION_V6: i32 = 22;
pub const GEOIP_ORG_EDITION_V6: i32 = 23;
pub const GEOIP_DOMAIN_EDITION_V6: i32 = 24;
pub const GEOIP_LOCATIONA_EDITION_V6: i32 = 25;
pub const GEOIP_REGISTRAR_EDITION: i32 = 26;
pub const GEOIP_REGISTRAR_EDITION_V6: i32 = 27;
pub const GEOIP_USERTYPE_EDITION: i32 = 28;
pub const GEOIP_USERTYPE_EDITION_V6: i32 = 29;
pub const GEOIP_CITY_EDITION_REV1_V6: i32 = 30;
pub const GEOIP_CITY_EDITION_REV0_V6: i32 = 31;
pub const GEOIP_NETSPEED_EDITION_REV1: i32 = 32;
pub const GEOIP_NETSPEED_EDITION_REV1_V6: i32 = 33;
pub const GEOIP_COUNTRYCONF_EDITION: i32 = 34;
pub const GEOIP_CITYCONF_EDITION: i32 = 35;
pub const GEOIP_REGIONCONF_EDITION: i32 = 36;
pub const GEOIP_POSTALCONF_EDITION: i32 = 37;
pub const GEOIP_ACCURACYRADIUS_EDITION_V6: i32 = 38;

/// NUM_DB_TYPES
const NUM_DB_TYPES: usize = 38 + 1;

const SEGMENT_RECORD_LENGTH: usize = 3;
const STANDARD_RECORD_LENGTH: u8 = 3;
const ORG_RECORD_LENGTH: u8 = 4;

const COUNTRY_BEGIN: u32 = 16776960;
const LARGE_COUNTRY_BEGIN: u32 = 16515072;
const STATE_BEGIN_REV0: u32 = 16700000;
const STATE_BEGIN_REV1: u32 = 16000000;
const STRUCTURE_INFO_MAX_SIZE: usize = 20;

/// The country lookups of ngx_*_geoip_country_functions[] and
/// ngx_*_geoip_country_v6_functions[]: GeoIP_country_code_by_ipnum*()
pub const GEOIP_COUNTRY_CODE: usize = 0;
/// GeoIP_country_code3_by_ipnum*()
pub const GEOIP_COUNTRY_CODE3: usize = 1;
/// GeoIP_country_name_by_ipnum*()
pub const GEOIP_COUNTRY_NAME: usize = 2;

/// geoipv6_t: a struct in6_addr, the address in network order
pub type GeoIPv6 = [u8; 16];

/// GeoIPDBDescription
static DB_DESCRIPTION: [Option<&str>; NUM_DB_TYPES] = [
    None,
    Some("GeoIP Country Edition"),
    Some("GeoIP City Edition, Rev 1"),
    Some("GeoIP Region Edition, Rev 1"),
    Some("GeoIP ISP Edition"),
    Some("GeoIP Organization Edition"),
    Some("GeoIP City Edition, Rev 0"),
    Some("GeoIP Region Edition, Rev 0"),
    Some("GeoIP Proxy Edition"),
    Some("GeoIP ASNum Edition"),
    Some("GeoIP Netspeed Edition"),
    Some("GeoIP Domain Name Edition"),
    Some("GeoIP Country V6 Edition"),
    Some("GeoIP LocationID ASCII Edition"),
    Some("GeoIP Accuracy Radius Edition"),
    None,
    None,
    Some("GeoIP Large Country Edition"),
    Some("GeoIP Large Country V6 Edition"),
    None,
    Some("GeoIP CCM Edition"),
    Some("GeoIP ASNum V6 Edition"),
    Some("GeoIP ISP V6 Edition"),
    Some("GeoIP Organization V6 Edition"),
    Some("GeoIP Domain Name V6 Edition"),
    Some("GeoIP LocationID ASCII V6 Edition"),
    Some("GeoIP Registrar Edition"),
    Some("GeoIP Registrar V6 Edition"),
    Some("GeoIP UserType Edition"),
    Some("GeoIP UserType V6 Edition"),
    Some("GeoIP City Edition V6, Rev 1"),
    Some("GeoIP City Edition V6, Rev 0"),
    Some("GeoIP Netspeed Edition, Rev 1"),
    Some("GeoIP Netspeed Edition V6, Rev1"),
    Some("GeoIP Country Confidence Edition"),
    Some("GeoIP City Confidence Edition"),
    Some("GeoIP Region Confidence Edition"),
    Some("GeoIP Postal Confidence Edition"),
    Some("GeoIP Accuracy Radius Edition V6"),
];

/// get_db_description() of GeoIP.c
fn db_description(dbtype: i32) -> &'static str {
    usize::try_from(dbtype).ok().and_then(|t| DB_DESCRIPTION.get(t).copied().flatten()).unwrap_or("Unknown")
}

/// GeoIPDBDescription[type] as GeoIPCity.c prints it with "%s": glibc
/// prints "(null)" for a NULL string (the C indexes the table with any
/// type; the port gives "(null)" for the ones outside it as well)
fn city_db_description(dbtype: i32) -> &'static str {
    usize::try_from(dbtype).ok().and_then(|t| DB_DESCRIPTION.get(t).copied().flatten()).unwrap_or("(null)")
}

/// The printf() of the lookup functions given a database of another type:
/// "Invalid database type %s, expected %s\n" on stdout.
fn invalid_database_type(have: &str, expected: &str) {
    let mut out = std::io::stdout();
    let _ = write!(out, "Invalid database type {}, expected {}\n", have, expected);
    let _ = out.flush();
}

/// DEBUG_MSGF(): fprintf(stderr, ...) unless GEOIP_SILENCE is set.  stderr
/// is unbuffered in C, the message is written at once.
fn debug_msg(flags: i32, msg: &[u8]) {
    if flags & GEOIP_SILENCE == 0 {
        let _ = std::io::stderr().write_all(msg);
    }
}

/// _GeoIP_iso_8859_1__utf8()
fn iso_8859_1_utf8(iso: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(iso.len() + iso.iter().filter(|&&c| c >= 0x80).count());

    for &c in iso {
        if c >= 0x80 {
            out.push(if c >= 0xc0 { 0xc3 } else { 0xc2 });
            out.push(c & !0x40);
        } else {
            out.push(c);
        }
    }

    out
}

/// GeoIP_code_by_id()
fn code_by_id(id: i32) -> Option<&'static [u8]> {
    usize::try_from(id).ok().and_then(|id| tables::COUNTRY_CODE.get(id).copied())
}

/// GeoIP_code3_by_id()
fn code3_by_id(id: i32) -> Option<&'static [u8]> {
    usize::try_from(id).ok().and_then(|id| tables::COUNTRY_CODE3.get(id).copied())
}

/// The inet_ntop(AF_INET6) of glibc: the longest run of two or more zero
/// words (the first of equal ones) is "::", an IPv4-compatible or
/// IPv4-mapped address ends with the dotted IPv4 address.
fn inet_ntop6(src: &GeoIPv6) -> String {
    let mut words = [0u32; 8];

    for (i, w) in words.iter_mut().enumerate() {
        *w = (src[2 * i] as u32) << 8 | src[2 * i + 1] as u32;
    }

    let mut best: Option<(usize, usize)> = None;
    let mut cur: Option<(usize, usize)> = None;

    for (i, &w) in words.iter().enumerate() {
        if w == 0 {
            cur = match cur {
                None => Some((i, 1)),
                Some((base, len)) => Some((base, len + 1)),
            };
        } else if let Some(c) = cur.take() {
            if best.is_none_or(|b| c.1 > b.1) {
                best = Some(c);
            }
        }
    }

    if let Some(c) = cur {
        if best.is_none_or(|b| c.1 > b.1) {
            best = Some(c);
        }
    }

    if best.is_some_and(|b| b.1 < 2) {
        best = None;
    }

    let mut out = String::new();

    for i in 0..8 {
        if let Some((base, len)) = best {
            if i >= base && i < base + len {
                if i == base {
                    out.push(':');
                }
                continue;
            }
        }

        if i != 0 {
            out.push(':');
        }

        if i == 6 && best.is_some_and(|(base, len)| base == 0 && (len == 6 || (len == 5 && words[5] == 0xffff))) {
            out.push_str(&format!("{}.{}.{}.{}", src[12], src[13], src[14], src[15]));
            break;
        }

        out.push_str(&format!("{:x}", words[i]));
    }

    if best.is_some_and(|(base, len)| base + len == 8) {
        out.push(':');
    }

    out
}

/// _database_has_content()
fn database_has_content(database_type: i32) -> bool {
    !matches!(
        database_type,
        GEOIP_COUNTRY_EDITION
            | GEOIP_PROXY_EDITION
            | GEOIP_NETSPEED_EDITION
            | GEOIP_COUNTRY_EDITION_V6
            | GEOIP_LARGE_COUNTRY_EDITION
            | GEOIP_LARGE_COUNTRY_EDITION_V6
            | GEOIP_REGION_EDITION_REV0
            | GEOIP_REGION_EDITION_REV1
    )
}

/// The structure info of a database: what _setup_segments() sets in the
/// GeoIP struct.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Segments {
    /// gi->databaseType, a C char
    database_type: i8,
    /// gi->record_length
    record_length: u8,
    /// gi->databaseSegments[0]
    segment: u32,
}

/// _setup_segments(): the structure info at the end of the file, None if
/// the file is corrupt (gi->databaseSegments == NULL).  The C reads the
/// file with pread(), the port reads the copy in memory, which is the
/// whole file.
fn setup_segments(data: &[u8]) -> Option<Segments> {
    // pread(fd, buf, n, offset) == n
    let pread = |offset: i64, n: usize| -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        data.get(start..start.checked_add(n)?)
    };

    // default to GeoIP Country Edition
    let mut database_type = GEOIP_COUNTRY_EDITION as i8;
    let mut record_length = STANDARD_RECORD_LENGTH;
    let mut segment = None;

    let mut offset = data.len() as i64 - 3;

    for _ in 0..STRUCTURE_INFO_MAX_SIZE {
        let delim = pread(offset, 3)?;
        offset += 3;

        if delim == [255, 255, 255] {
            database_type = pread(offset, 1)?[0] as i8;
            offset += 1;

            if database_type >= 106 {
                // backwards compatibility with databases from April 2003
                // and earlier
                database_type -= 105;
            }

            let t = database_type as i32;

            if t == GEOIP_REGION_EDITION_REV0 {
                // Region Edition, pre June 2003
                segment = Some(STATE_BEGIN_REV0);
            } else if t == GEOIP_REGION_EDITION_REV1 {
                // Region Edition, post June 2003
                segment = Some(STATE_BEGIN_REV1);
            } else if matches!(
                t,
                GEOIP_CITY_EDITION_REV0
                    | GEOIP_CITY_EDITION_REV1
                    | GEOIP_ORG_EDITION
                    | GEOIP_ORG_EDITION_V6
                    | GEOIP_DOMAIN_EDITION
                    | GEOIP_DOMAIN_EDITION_V6
                    | GEOIP_ISP_EDITION
                    | GEOIP_ISP_EDITION_V6
                    | GEOIP_REGISTRAR_EDITION
                    | GEOIP_REGISTRAR_EDITION_V6
                    | GEOIP_USERTYPE_EDITION
                    | GEOIP_USERTYPE_EDITION_V6
                    | GEOIP_ASNUM_EDITION
                    | GEOIP_ASNUM_EDITION_V6
                    | GEOIP_NETSPEED_EDITION_REV1
                    | GEOIP_NETSPEED_EDITION_REV1_V6
                    | GEOIP_LOCATIONA_EDITION
                    | GEOIP_ACCURACYRADIUS_EDITION
                    | GEOIP_ACCURACYRADIUS_EDITION_V6
                    | GEOIP_CITY_EDITION_REV0_V6
                    | GEOIP_CITY_EDITION_REV1_V6
                    | GEOIP_CITYCONF_EDITION
                    | GEOIP_COUNTRYCONF_EDITION
                    | GEOIP_REGIONCONF_EDITION
                    | GEOIP_POSTALCONF_EDITION
            ) {
                // City/Org Editions have two segments, read offset of
                // second segment
                let buf = pread(offset, SEGMENT_RECORD_LENGTH)?;

                segment = Some(buf.iter().enumerate().fold(0u32, |s, (j, &b)| s + ((b as u32) << (j * 8))));

                // the record_length must be correct from here on
                if matches!(
                    t,
                    GEOIP_ORG_EDITION | GEOIP_ORG_EDITION_V6 | GEOIP_DOMAIN_EDITION | GEOIP_DOMAIN_EDITION_V6 | GEOIP_ISP_EDITION | GEOIP_ISP_EDITION_V6
                ) {
                    record_length = ORG_RECORD_LENGTH;
                }
            }

            break;
        }

        offset -= 4;

        if offset < 0 {
            return None;
        }
    }

    match database_type as i32 {
        GEOIP_COUNTRY_EDITION | GEOIP_PROXY_EDITION | GEOIP_NETSPEED_EDITION | GEOIP_COUNTRY_EDITION_V6 => {
            segment = Some(COUNTRY_BEGIN);
        }

        GEOIP_LARGE_COUNTRY_EDITION | GEOIP_LARGE_COUNTRY_EDITION_V6 => {
            segment = Some(LARGE_COUNTRY_BEGIN);
        }

        _ => {}
    }

    Some(Segments { database_type, record_length, segment: segment? })
}

/// get_index_size(): -1 if the index would not fit in the file.  (The
/// multiplication cannot overflow a 64-bit ssize_t.)
fn index_size(seg: &Segments, st_size: i64) -> i64 {
    if !database_has_content(seg.database_type as i32) {
        return st_size;
    }

    let index_size = seg.segment as i64 * (seg.record_length as i64 * 2);

    // Index size should never exceed the size of the file
    if index_size > st_size {
        return -1;
    }

    index_size
}

/// An open database (GeoIP *), opened with GEOIP_MEMORY_CACHE.  The C
/// keeps the database file open (gi->GeoIPDatabase) until GeoIP_delete(),
/// which is what the pool cleanup handlers ngx_http_geoip_cleanup() and
/// ngx_stream_geoip_cleanup() call when the configuration is freed: here
/// the file is closed when the GeoIPDb is dropped.
pub struct GeoIPDb {
    _file: File,
    /// gi->cache: the database
    cache: Vec<u8>,
    /// gi->size
    size: i64,
    seg: Segments,
    flags: i32,
    charset: i32,
    /// gi->ext_flags, bit GEOIP_TEREDO_BIT
    teredo: bool,
}

/// Selectors of the members of a GeoIPRecord, the values of
/// offsetof(GeoIPRecord, member) of GeoIPCity.h on LP64, which the C
/// modules pass to their variable handlers as data.
pub mod record_member {
    pub const COUNTRY_CODE: usize = 0;
    pub const COUNTRY_CODE3: usize = 8;
    pub const COUNTRY_NAME: usize = 16;
    pub const REGION: usize = 24;
    pub const CITY: usize = 32;
    pub const POSTAL_CODE: usize = 40;
    pub const LATITUDE: usize = 48;
    pub const LONGITUDE: usize = 52;
    /// union { int metro_code; int dma_code; }
    pub const DMA_CODE: usize = 56;
    pub const AREA_CODE: usize = 60;
    pub const CHARSET: usize = 64;
    pub const CONTINENT_CODE: usize = 72;
    pub const NETMASK: usize = 80;
}

/// GeoIPRecord (struct GeoIPRecordTag of GeoIPCity.h), as
/// GeoIP_record_by_ipnum*() return it; GeoIPRecord_delete() is the drop.
#[derive(Debug, Clone, PartialEq)]
pub struct GeoIPRecord {
    pub country_code: &'static [u8],
    pub country_code3: &'static [u8],
    /// NULL for the country id 0
    pub country_name: Option<&'static [u8]>,
    pub region: Option<Vec<u8>>,
    pub city: Option<Vec<u8>>,
    pub postal_code: Option<Vec<u8>>,
    pub latitude: f32,
    pub longitude: f32,
    /// union { int metro_code; int dma_code; }
    pub dma_code: i32,
    pub area_code: i32,
    pub charset: i32,
    pub continent_code: &'static [u8],
    pub netmask: i32,
}

impl GeoIPRecord {
    /// *(char **) ((char *) gr + data): the string member a selector of
    /// record_member names, None if NULL.
    pub fn str_member(&self, member: usize) -> Option<Vec<u8>> {
        match member {
            record_member::COUNTRY_CODE => Some(self.country_code.to_vec()),
            record_member::COUNTRY_CODE3 => Some(self.country_code3.to_vec()),
            record_member::COUNTRY_NAME => self.country_name.map(|s| s.to_vec()),
            record_member::REGION => self.region.clone(),
            record_member::CITY => self.city.clone(),
            record_member::POSTAL_CODE => self.postal_code.clone(),
            record_member::CONTINENT_CODE => Some(self.continent_code.to_vec()),
            _ => panic!("no char * member of GeoIPRecord at offset {}", member),
        }
    }

    /// *(float *) ((char *) gr + data)
    pub fn float_member(&self, member: usize) -> f32 {
        match member {
            record_member::LATITUDE => self.latitude,
            record_member::LONGITUDE => self.longitude,
            _ => panic!("no float member of GeoIPRecord at offset {}", member),
        }
    }

    /// *(int *) ((char *) gr + data)
    pub fn int_member(&self, member: usize) -> i32 {
        match member {
            record_member::DMA_CODE => self.dma_code,
            record_member::AREA_CODE => self.area_code,
            record_member::CHARSET => self.charset,
            record_member::NETMASK => self.netmask,
            _ => panic!("no int member of GeoIPRecord at offset {}", member),
        }
    }

    /// GeoIP_region_name_by_code(gr->country_code, gr->region)
    pub fn region_name(&self) -> Option<&'static [u8]> {
        region_name_by_code(self.country_code, self.region.as_deref())
    }
}

/// GeoIP_region_name_by_code(): the name of a region, the names are
/// ASCII (they are not converted to UTF-8 for the "utf8" databases).
pub fn region_name_by_code(country_code: &[u8], region_code: Option<&[u8]>) -> Option<&'static [u8]> {
    let region_code = region_code?;

    // the C string: its terminating NUL ends the comparisons
    let c0 = region_code.first().copied().unwrap_or(0) as i32;
    let c1 = region_code.get(1).copied().unwrap_or(0) as i32;

    let digit = |c: i32| (48..48 + 10).contains(&c);
    let upper = |c: i32| (65..65 + 26).contains(&c);

    let region_code2 = if digit(c0) && digit(c1) {
        // only numbers, that shortens the large switch statements
        (c0 - 48) * 10 + c1 - 48
    } else if (upper(c0) || digit(c0)) && (upper(c1) || digit(c1)) {
        (c0 - 48) * (65 + 26 - 48) + c1 - 48 + 100
    } else {
        return None;
    };

    // strcmp(country_code, "XX") == 0
    let country: [u8; 2] = country_code.try_into().ok()?;
    let key = (country, region_code2 as u16);

    region_name::REGION_NAMES.binary_search_by(|&(cc, code, _)| (cc, code).cmp(&key)).ok().map(|i| region_name::REGION_NAMES[i].2.as_bytes())
}

/// The little-endian number of n bytes, as the record lookups read it.
fn le(buf: &[u8]) -> u32 {
    buf.iter().rev().fold(0u32, |x, &b| (x << 8).wrapping_add(b as u32))
}

impl GeoIPDb {
    /// GeoIP_open(filename, flags): None if it failed, after the message
    /// of the library on stderr unless GEOIP_SILENCE is set.  As in C, the
    /// name ends at the first NUL byte.  Only GEOIP_MEMORY_CACHE, the
    /// mode nginx uses, is supported.
    pub fn open(filename: &[u8], flags: i32) -> Option<GeoIPDb> {
        debug_assert!(flags & GEOIP_MEMORY_CACHE != 0, "only GEOIP_MEMORY_CACHE is supported");

        let len = filename.iter().position(|&c| c == 0).unwrap_or(filename.len());
        let filename = &filename[..len];

        let msg = |fmt: &str| {
            let mut m = Vec::new();
            m.extend_from_slice(fmt.as_bytes());
            m.extend_from_slice(filename);
            m.push(b'\n');
            m
        };

        // fopen(filename, "rb")
        let file = match File::open(std::ffi::OsStr::from_bytes(filename)) {
            Ok(f) => f,
            Err(_) => {
                debug_msg(flags, &msg("Error Opening file "));
                return None;
            }
        };

        let size = match file.metadata() {
            Ok(m) => m.len() as i64,
            Err(_) => {
                debug_msg(flags, &msg("Error stating file "));
                return None;
            }
        };

        // the cache: malloc(st_size) and one pread() of st_size bytes
        let mut cache = Vec::new();

        if usize::try_from(size).ok().is_none_or(|n| cache.try_reserve_exact(n).is_err()) {
            debug_msg(flags, &msg("Error reading file "));
            return None;
        }

        cache.resize(size as usize, 0);

        match file.read_at(&mut cache, 0) {
            Ok(n) if n as i64 == size => {}
            _ => {
                debug_msg(flags, &msg("Error reading file "));
                return None;
            }
        }

        let seg = match setup_segments(&cache) {
            Some(seg) => seg,
            None => {
                let mut m = msg("Error reading file ");
                m.truncate(m.len() - 1);
                m.extend_from_slice(b" -- corrupt\n");
                debug_msg(flags, &m);
                return None;
            }
        };

        if index_size(&seg, size) < 0 {
            let mut m = msg("Error file ");
            m.truncate(m.len() - 1);
            m.extend_from_slice(b" -- corrupt\n");
            debug_msg(flags, &m);
            return None;
        }

        Some(GeoIPDb { _file: file, cache, size, seg, flags, charset: GEOIP_CHARSET_ISO_8859_1, teredo: true })
    }

    /// GeoIP_set_charset(): returns the previous charset
    pub fn set_charset(&mut self, charset: i32) -> i32 {
        std::mem::replace(&mut self.charset, charset)
    }

    /// gi->databaseType: a C char, promoted to int as in the "type:%d"
    /// messages of nginx.
    pub fn database_type(&self) -> i32 {
        self.seg.database_type as i32
    }

    /// One step of the lookups: the left (0) or right (1) record of the
    /// node at offset, None if the node is outside the file.
    fn node(&self, offset: u32, right: bool) -> Option<u32> {
        let rl = self.seg.record_length as u32;
        let record_pair_length = rl * 2;
        let byte_offset = record_pair_length.wrapping_mul(offset);

        if byte_offset as i64 > self.size - record_pair_length as i64 {
            // The pointer is invalid
            return None;
        }

        let start = byte_offset as usize + if right { rl as usize } else { 0 };

        Some(le(&self.cache[start..start + rl as usize]))
    }

    /// _GeoIP_seek_record_gl(): the record of an IPv4 address and the
    /// netmask (gl->netmask), 0 if the tree is broken.
    fn seek_record(&self, ipnum: u32) -> (u32, i32) {
        let mut offset = 0;

        for depth in (0..32).rev() {
            let x = match self.node(offset, ipnum & (1 << depth) != 0) {
                Some(x) => x,
                None => break,
            };

            if x >= self.seg.segment {
                return (x, 32 - depth);
            }

            offset = x;
        }

        // shouldn't reach here
        debug_msg(self.flags, format!("Error Traversing Database for ipnum = {} - Perhaps database is corrupt?\n", ipnum).as_bytes());

        (0, 0)
    }

    /// _GeoIP_seek_record_v6_gl()
    fn seek_record_v6(&self, mut ipnum: GeoIPv6) -> (u32, i32) {
        if self.teredo {
            // __GEOIP_PREPARE_TEREDO()
            if ipnum[..4] == [0x20, 0x01, 0x00, 0x00] {
                for b in &mut ipnum[..12] {
                    *b = 0;
                }
                for b in &mut ipnum[12..] {
                    *b ^= 0xff;
                }
            }
        }

        let mut offset = 0;

        for depth in (0..128).rev() {
            // GEOIP_CHKBIT_V6(depth, ipnum.s6_addr)
            let bit = 127 - depth;
            let right = ipnum[bit >> 3] & (1 << (!bit & 7)) != 0;

            let x = match self.node(offset, right) {
                Some(x) => x,
                None => break,
            };

            if x >= self.seg.segment {
                return (x, 128 - depth as i32);
            }

            offset = x;
        }

        // shouldn't reach here
        debug_msg(self.flags, format!("Error Traversing Database for ipnum = {} - Perhaps database is corrupt?\n", inet_ntop6(&ipnum)).as_bytes());

        (0, 0)
    }

    /// GeoIP_id_by_ipnum_gl()
    fn id_by_ipnum(&self, ipnum: u32) -> i32 {
        if ipnum == 0 {
            return 0;
        }

        let t = self.database_type();

        if !matches!(t, GEOIP_COUNTRY_EDITION | GEOIP_LARGE_COUNTRY_EDITION | GEOIP_PROXY_EDITION | GEOIP_NETSPEED_EDITION) {
            invalid_database_type(db_description(t), db_description(GEOIP_COUNTRY_EDITION));
            return 0;
        }

        self.seek_record(ipnum).0.wrapping_sub(self.seg.segment) as i32
    }

    /// GeoIP_id_by_ipnum_v6_gl()
    fn id_by_ipnum_v6(&self, ipnum: GeoIPv6) -> i32 {
        let t = self.database_type();

        if !matches!(t, GEOIP_COUNTRY_EDITION_V6 | GEOIP_LARGE_COUNTRY_EDITION_V6) {
            invalid_database_type(db_description(t), db_description(GEOIP_COUNTRY_EDITION_V6));
            return 0;
        }

        self.seek_record_v6(ipnum).0.wrapping_sub(self.seg.segment) as i32
    }

    /// GeoIP_country_name_by_id()
    fn country_name_by_id(&self, id: i32) -> Option<&'static [u8]> {
        // return NULL also even for index 0 for backward compatibility
        if id <= 0 || id as usize >= tables::COUNTRY_NAME.len() {
            return None;
        }

        Some(if self.charset == GEOIP_CHARSET_UTF8 { tables::UTF8_COUNTRY_NAME[id as usize] } else { tables::COUNTRY_NAME[id as usize] })
    }

    /// The country of an id as the GeoIP_country_*_by_ipnum*() functions
    /// give it: n is GEOIP_COUNTRY_CODE, GEOIP_COUNTRY_CODE3 or
    /// GEOIP_COUNTRY_NAME.
    fn country_by_id(&self, n: usize, id: i32) -> Option<&'static [u8]> {
        match n {
            GEOIP_COUNTRY_CODE => {
                if id > 0 {
                    code_by_id(id)
                } else {
                    None
                }
            }
            GEOIP_COUNTRY_CODE3 => {
                if id > 0 {
                    code3_by_id(id)
                } else {
                    None
                }
            }
            GEOIP_COUNTRY_NAME => self.country_name_by_id(id),
            _ => panic!("no GeoIP country function {}", n),
        }
    }

    /// ngx_*_geoip_country_functions[n](gi, addr):
    /// GeoIP_country_code_by_ipnum(), GeoIP_country_code3_by_ipnum() or
    /// GeoIP_country_name_by_ipnum(); the C result is a static string.
    pub fn country_by_ipnum(&self, n: usize, ipnum: u32) -> Option<&'static [u8]> {
        self.country_by_id(n, self.id_by_ipnum(ipnum))
    }

    /// ngx_*_geoip_country_v6_functions[n](gi, addr)
    pub fn country_by_ipnum_v6(&self, n: usize, ipnum: GeoIPv6) -> Option<&'static [u8]> {
        self.country_by_id(n, self.id_by_ipnum_v6(ipnum))
    }

    /// The pointer to the data of a record: seek_record + (2 *
    /// gi->record_length - 1) * gi->databaseSegments[0], computed in
    /// unsigned int and stored in an int.
    fn record_pointer(&self, seek_record: u32) -> i32 {
        let rl = self.seg.record_length as u32;

        seek_record.wrapping_add((2 * rl - 1).wrapping_mul(self.seg.segment)) as i32
    }

    /// The NUL-terminated string at record_pointer in the cache, converted
    /// to UTF-8 for the GEOIP_CHARSET_UTF8 databases (the copies of
    /// _get_name_gl()).  The C does not check the pointer: the bytes
    /// outside the file read as zeroes here, as what follows the cache in
    /// memory mostly does.
    fn name_at(&self, record_pointer: i32) -> Vec<u8> {
        let rest = usize::try_from(record_pointer).ok().and_then(|start| self.cache.get(start..)).unwrap_or(&[]);
        let s = &rest[..rest.iter().position(|&c| c == 0).unwrap_or(rest.len())];

        if self.charset == GEOIP_CHARSET_UTF8 {
            iso_8859_1_utf8(s)
        } else {
            s.to_vec()
        }
    }

    /// GeoIP_name_by_ipnum() (_get_name_gl()): the name of the
    /// organization, ISP, ...; the C result is malloc()ed and freed by
    /// the caller.
    pub fn name_by_ipnum(&self, ipnum: u32) -> Option<Vec<u8>> {
        let t = self.database_type();

        if !matches!(
            t,
            GEOIP_ORG_EDITION
                | GEOIP_ISP_EDITION
                | GEOIP_DOMAIN_EDITION
                | GEOIP_ASNUM_EDITION
                | GEOIP_ACCURACYRADIUS_EDITION
                | GEOIP_NETSPEED_EDITION_REV1
                | GEOIP_USERTYPE_EDITION
                | GEOIP_REGISTRAR_EDITION
                | GEOIP_LOCATIONA_EDITION
                | GEOIP_CITYCONF_EDITION
                | GEOIP_COUNTRYCONF_EDITION
                | GEOIP_REGIONCONF_EDITION
                | GEOIP_POSTALCONF_EDITION
        ) {
            invalid_database_type(db_description(t), db_description(GEOIP_ORG_EDITION));
            return None;
        }

        let (seek_org, _) = self.seek_record(ipnum);

        if seek_org == self.seg.segment {
            return None;
        }

        Some(self.name_at(self.record_pointer(seek_org)))
    }

    /// GeoIP_name_by_ipnum_v6() (_get_name_v6_gl())
    pub fn name_by_ipnum_v6(&self, ipnum: GeoIPv6) -> Option<Vec<u8>> {
        let t = self.database_type();

        if !matches!(
            t,
            GEOIP_ORG_EDITION_V6
                | GEOIP_ISP_EDITION_V6
                | GEOIP_DOMAIN_EDITION_V6
                | GEOIP_ASNUM_EDITION_V6
                | GEOIP_ACCURACYRADIUS_EDITION_V6
                | GEOIP_NETSPEED_EDITION_REV1_V6
                | GEOIP_USERTYPE_EDITION_V6
                | GEOIP_REGISTRAR_EDITION_V6
                | GEOIP_LOCATIONA_EDITION_V6
        ) {
            invalid_database_type(db_description(t), db_description(GEOIP_ORG_EDITION));
            return None;
        }

        let (seek_org, _) = self.seek_record_v6(ipnum);

        if seek_org == self.seg.segment {
            return None;
        }

        Some(self.name_at(self.record_pointer(seek_org)))
    }

    /// _extract_record() of GeoIPCity.c from the cache: the bytes past the
    /// end of the file read as zeroes.
    fn extract_record(&self, seek_record: u32) -> Option<GeoIPRecord> {
        if seek_record == self.seg.segment {
            return None;
        }

        let record_pointer = self.record_pointer(seek_record);

        if self.size <= record_pointer as i64 {
            // record does not exist in the cache
            return None;
        }

        let base = record_pointer as i64;
        let byte = |i: usize| usize::try_from(base + i as i64).ok().and_then(|j| self.cache.get(j)).copied().unwrap_or(0);

        // a NUL-terminated string at position i: its bytes, the position
        // after it
        let string = |i: usize| -> (Vec<u8>, usize) {
            let mut s = Vec::new();
            let mut j = i;

            while byte(j) != 0 {
                s.push(byte(j));
                j += 1;
            }

            (s, j + 1)
        };

        // get country
        let id = byte(0) as usize;

        let country_code = tables::COUNTRY_CODE[id];
        let mut pos = 1;

        // get region
        let (region, next) = string(pos);
        pos = next;

        // get city
        let (city, next) = string(pos);
        pos = next;

        // get postal code
        let (postal_code, next) = string(pos);
        pos = next;

        // get latitude
        let latitude = (0..3).fold(0.0f64, |l, j| l + (((byte(pos + j) as u32) << (j * 8)) as f64));
        pos += 3;

        // get longitude
        let longitude = (0..3).fold(0.0f64, |l, j| l + (((byte(pos + j) as u32) << (j * 8)) as f64));

        let mut dma_code = 0;
        let mut area_code = 0;

        // get area code and metro code for post April 2002 databases and
        // for US locations
        let t = self.database_type();

        if (t == GEOIP_CITY_EDITION_REV1 || t == GEOIP_CITY_EDITION_REV1_V6) && country_code == b"US" {
            pos += 3;

            let metroarea_combo = (0..3).fold(0i32, |c, j| c + ((byte(pos + j) as i32) << (j * 8)));

            dma_code = metroarea_combo / 1000;
            area_code = metroarea_combo % 1000;
        }

        Some(GeoIPRecord {
            country_code,
            country_code3: tables::COUNTRY_CODE3[id],
            country_name: self.country_name_by_id(id as i32),
            region: if region.is_empty() { None } else { Some(region) },
            city: if city.is_empty() {
                None
            } else if self.charset == GEOIP_CHARSET_UTF8 {
                Some(iso_8859_1_utf8(&city))
            } else {
                Some(city)
            },
            postal_code: if postal_code.is_empty() { None } else { Some(postal_code) },
            latitude: (latitude / 10000.0 - 180.0) as f32,
            longitude: (longitude / 10000.0 - 180.0) as f32,
            dma_code,
            area_code,
            charset: self.charset,
            continent_code: tables::COUNTRY_CONTINENT[id],
            netmask: 0,
        })
    }

    /// GeoIP_record_by_ipnum(): the city record; the C result is freed by
    /// the caller with GeoIPRecord_delete().
    pub fn record_by_ipnum(&self, ipnum: u32) -> Option<GeoIPRecord> {
        let t = self.database_type();

        if t != GEOIP_CITY_EDITION_REV0 && t != GEOIP_CITY_EDITION_REV1 {
            invalid_database_type(city_db_description(t), city_db_description(GEOIP_CITY_EDITION_REV1));
            return None;
        }

        let (seek_record, netmask) = self.seek_record(ipnum);

        let mut r = self.extract_record(seek_record)?;
        r.netmask = netmask;

        Some(r)
    }

    /// GeoIP_record_by_ipnum_v6()
    pub fn record_by_ipnum_v6(&self, ipnum: GeoIPv6) -> Option<GeoIPRecord> {
        let t = self.database_type();

        if t != GEOIP_CITY_EDITION_REV0_V6 && t != GEOIP_CITY_EDITION_REV1_V6 {
            invalid_database_type(city_db_description(t), city_db_description(GEOIP_CITY_EDITION_REV1_V6));
            return None;
        }

        let (seek_record, netmask) = self.seek_record_v6(ipnum);

        let mut r = self.extract_record(seek_record)?;
        r.netmask = netmask;

        Some(r)
    }
}

/// The common part of the geoip_country, geoip_org and geoip_city handlers
/// of the http and stream modules: GeoIP_open() of the database and its
/// optional "utf8" parameter.  As in C, the database is stored in *db
/// before the parameter is checked; the caller checks the database type.
pub fn conf_open(cf: &mut Conf, db: &mut Option<GeoIPDb>) -> Result<(), ConfError> {
    let value = cf.args.clone();

    *db = GeoIPDb::open(&value[1], GEOIP_MEMORY_CACHE);

    let gi = match db {
        None => {
            return Err(cf.emerg(format_args!("GeoIP_open(\"{}\") failed", B(&value[1]))));
        }
        Some(gi) => gi,
    };

    if value.len() == 3 {
        // ngx_strcmp(value[2].data, "utf8")
        if value[2].split(|&c| c == 0).next() == Some(b"utf8") {
            gi.set_charset(GEOIP_CHARSET_UTF8);
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    Ok(())
}

/// (int64_t) d as x86-64 converts it (cvttsd2si): the "integer indefinite"
/// INT64_MIN for NaN and what is out of range.
fn c_f64_to_i64(d: f64) -> i64 {
    if d.is_nan() || d >= 9223372036854775808.0 || d < -9223372036854775808.0 {
        i64::MIN
    } else {
        d as i64
    }
}

/// (uint64_t) d as gcc converts it on x86-64: cvttsd2si of d below 2^63
/// (and of NaN), of d - 2^63 with the top bit flipped otherwise.
fn c_f64_to_u64(d: f64) -> u64 {
    const TWO63: f64 = 9223372036854775808.0;

    if d >= TWO63 {
        c_f64_to_i64(d - TWO63) as u64 ^ (1 << 63)
    } else {
        c_f64_to_i64(d) as u64
    }
}

/// The "%.<frac_width>f" conversion of ngx_vslprintf(), as used for the
/// float variables ("%.4f" of a float promoted to double); the C casts of
/// NaN, infinities and large values give what they give on x86-64.
pub fn sprintf_float(buf: &mut Vec<u8>, mut f: f64, frac_width: u32) {
    if f < 0.0 {
        buf.push(b'-');
        f = -f;
    }

    let mut ui64 = c_f64_to_i64(f) as u64;
    let mut frac: u64 = 0;

    if frac_width != 0 {
        let mut scale: u64 = 1;
        for _ in 0..frac_width {
            scale *= 10;
        }

        frac = c_f64_to_u64((f - ui64 as f64) * scale as f64 + 0.5);

        if frac == scale {
            ui64 += 1;
            frac = 0;
        }
    }

    buf.extend_from_slice(ui64.to_string().as_bytes());

    if frac_width != 0 {
        buf.push(b'.');

        let digits = frac.to_string();
        for _ in digits.len()..frac_width as usize {
            buf.push(b'0');
        }
        buf.extend_from_slice(digits.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(f: f64, w: u32) -> String {
        let mut b = Vec::new();
        sprintf_float(&mut b, f, w);
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn sprintf_float_as_ngx_vslprintf() {
        assert_eq!(fmt(55.7543f32 as f64, 4), "55.7543");
        assert_eq!(fmt(37.6202f32 as f64, 4), "37.6202");
        assert_eq!(fmt(0.0, 4), "0.0000");
        assert_eq!(fmt(-12.5, 4), "-12.5000");
        assert_eq!(fmt(0.00004, 4), "0.0000");
        assert_eq!(fmt(0.00005, 4), "0.0001");
        assert_eq!(fmt(1.99999, 4), "2.0000");
        assert_eq!(fmt(-0.00996, 4), "-0.0100");
        assert_eq!(fmt(3.7, 0), "3");
        assert_eq!(fmt(123.0456, 3), "123.046");
    }

    #[test]
    fn sprintf_float_casts_as_x86_64() {
        // the output of the C code, built with the flags of nginx
        assert_eq!(fmt(f64::INFINITY, 3), "9223372036854775808.000");
        assert_eq!(fmt(f64::NAN, 3), "9223372036854775808.9223372036854775808");
        assert_eq!(fmt(f64::NEG_INFINITY, 3), "-9223372036854775808.000");
        assert_eq!(fmt(1e19, 3), "9223372036854775808.000");
        assert_eq!(fmt(2e19, 3), "9223372036854775808.000");
        assert_eq!(fmt(9.3e18, 3), "9223372036854775808.000");
        assert_eq!(fmt(1.8446744073709552e19, 3), "9223372036854775808.000");
        assert_eq!(fmt(1e30, 3), "9223372036854775808.000");
        assert_eq!(fmt(12.3456, 3), "12.346");
        assert_eq!(fmt(0.0005, 3), "0.001");
        assert_eq!(fmt(0.9995, 3), "1.000");
        assert_eq!(fmt(1.0e-10, 3), "0.000");
        assert_eq!(fmt(4294967295.9999, 3), "4294967296.000");
        assert_eq!(fmt(9.2e18, 3), "9200000000000000000.000");
        assert_eq!(fmt(9.223372036854775e18, 3), "9223372036854774784.000");
    }

    #[test]
    fn record_members_are_geoipcity_h_offsets() {
        // offsetof(GeoIPRecord, member) of GeoIPCity.h of libGeoIP 1.6 on
        // LP64 (checked against the DWARF of the C nginx build)
        assert_eq!(record_member::COUNTRY_CODE, 0);
        assert_eq!(record_member::COUNTRY_CODE3, 8);
        assert_eq!(record_member::COUNTRY_NAME, 16);
        assert_eq!(record_member::REGION, 24);
        assert_eq!(record_member::CITY, 32);
        assert_eq!(record_member::POSTAL_CODE, 40);
        assert_eq!(record_member::LATITUDE, 48);
        assert_eq!(record_member::LONGITUDE, 52);
        assert_eq!(record_member::DMA_CODE, 56);
        assert_eq!(record_member::AREA_CODE, 60);
        assert_eq!(record_member::CHARSET, 64);
        assert_eq!(record_member::CONTINENT_CODE, 72);
        assert_eq!(record_member::NETMASK, 80);
    }

    #[test]
    fn country_tables() {
        assert_eq!(tables::COUNTRY_CODE[0], b"--");
        assert_eq!(tables::COUNTRY_CODE[185], b"RU");
        assert_eq!(tables::COUNTRY_CODE[225], b"US");
        assert_eq!(tables::COUNTRY_CODE[255], b"O1");
        assert_eq!(tables::COUNTRY_CODE3[185], b"RUS");
        assert_eq!(tables::COUNTRY_CODE3[1], b"AP");
        assert_eq!(tables::COUNTRY_NAME[185], b"Russian Federation");
        assert_eq!(tables::COUNTRY_NAME[10], b"Curacao");
        assert_eq!(tables::UTF8_COUNTRY_NAME[10], b"Cura\xc3\xa7ao");
        assert_eq!(tables::COUNTRY_CONTINENT[185], b"EU");
        assert_eq!(tables::COUNTRY_CONTINENT[12], b"AN");

        // the ISO-8859-1 and UTF-8 names differ in Curacao only
        for i in 0..256 {
            assert_eq!(tables::COUNTRY_NAME[i] == tables::UTF8_COUNTRY_NAME[i], i != 10, "{}", i);
        }
    }

    #[test]
    fn region_names() {
        let rn = |cc: &[u8], r: &[u8]| region_name_by_code(cc, Some(r)).map(|s| String::from_utf8(s.to_vec()).unwrap());

        assert_eq!(rn(b"RU", b"48").as_deref(), Some("Moscow City"));
        assert_eq!(rn(b"US", b"CA").as_deref(), Some("California"));
        assert_eq!(rn(b"CA", b"ON").as_deref(), Some("Ontario"));
        assert_eq!(rn(b"AD", b"03").as_deref(), Some("Encamp"));
        assert_eq!(rn(b"ZW", b"10").as_deref(), Some("Harare"));
        assert_eq!(rn(b"GB", b"A1").as_deref(), Some("Barking and Dagenham"));
        assert_eq!(rn(b"AD", b"3").as_deref(), None);
        assert_eq!(rn(b"AD", b"").as_deref(), None);
        assert_eq!(rn(b"US", b"ca").as_deref(), None);
        assert_eq!(rn(b"XX", b"01").as_deref(), None);
        assert_eq!(rn(b"US", b"CAX").as_deref(), Some("California"));
        assert_eq!(region_name_by_code(b"US", None), None);

        let t = &region_name::REGION_NAMES;
        assert!(t.windows(2).all(|w| (w[0].0, w[0].1) < (w[1].0, w[1].1)));
    }

    #[test]
    fn utf8_of_iso_8859_1() {
        assert_eq!(iso_8859_1_utf8(b"abc"), b"abc");
        assert_eq!(iso_8859_1_utf8(b"\xe7\x80\xbf\xc0\xff"), b"\xc3\xa7\xc2\x80\xc2\xbf\xc3\x80\xc3\xbf");
    }

    #[test]
    fn inet_ntop6_as_glibc() {
        let a = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap().octets();

        assert_eq!(inet_ntop6(&a("::")), "::");
        assert_eq!(inet_ntop6(&a("::1")), "::1");
        assert_eq!(inet_ntop6(&a("::2")), "::2");
        assert_eq!(inet_ntop6(&a("::1.2.3.4")), "::1.2.3.4");
        assert_eq!(inet_ntop6(&a("::ffff:10.0.0.1")), "::ffff:10.0.0.1");
        assert_eq!(inet_ntop6(&a("2001:db8::")), "2001:db8::");
        assert_eq!(inet_ntop6(&a("2001:db8:0:1:0:0:0:1")), "2001:db8:0:1::1");
        assert_eq!(inet_ntop6(&a("2001:0:0:1:0:0:1:1")), "2001::1:0:0:1:1");
        assert_eq!(inet_ntop6(&a("1:0:2:3:4:5:6:7")), "1:0:2:3:4:5:6:7");
        assert_eq!(inet_ntop6(&a("::ffff:0:1.2.3.4")), "::ffff:0:102:304");
        assert_eq!(inet_ntop6(&a("fe80::1:0:0")), "fe80::1:0:0");
    }

    fn pack_node(v: u32) -> [u8; 3] {
        let b = v.to_le_bytes();
        [b[0], b[1], b[2]]
    }

    /// The databases of nginx-tests geoip.t / stream_geoip.t.
    fn country_db() -> Vec<u8> {
        let mut d = Vec::new();
        for i in 0..=156u32 {
            let (l, r) = match i {
                2 => (i + 1, 32),
                31 => (0xffffb9, 0xffff00),
                44 | 49 | 50 | 52 | 53 | 55 | 56 | 57 => (0xffff00, i + 1),
                156 => (0xffffe1, 0xffff00),
                _ => (i + 1, 0xffff00),
            };
            d.extend_from_slice(&pack_node(l));
            d.extend_from_slice(&pack_node(r));
        }
        d.extend_from_slice(&[0, 0, 0, 0xff, 0xff, 0xff, 12]);
        d
    }

    fn city_db() -> Vec<u8> {
        let mut d = Vec::new();
        for i in 0..=31u32 {
            let (l, r) = match i {
                4 | 6 => (32, i + 1),
                31 => (32, i + 2),
                _ => (i + 1, 32),
            };
            d.extend_from_slice(&pack_node(l));
            d.extend_from_slice(&pack_node(r));
        }
        d.push(42);
        d.push(185);
        d.extend_from_slice(b"48\0Moscow\0119034\0");
        d.extend_from_slice(&pack_node(((55.7543f64 + 180.0) * 10000.0) as u32));
        d.extend_from_slice(&pack_node(((37.6202f64 + 180.0) * 10000.0) as u32));
        d.extend_from_slice(&[0, 0, 0, 0xff, 0xff, 0xff, 2]);
        d.extend_from_slice(&pack_node(32));
        d
    }

    fn org_db() -> Vec<u8> {
        let mut d = Vec::new();
        for i in 0..=31u32 {
            let (l, r) = match i {
                4 | 6 => (32, i + 1),
                31 => (32, i + 2),
                _ => (i + 1, 32),
            };
            d.extend_from_slice(&l.to_le_bytes());
            d.extend_from_slice(&r.to_le_bytes());
        }
        d.push(42);
        d.extend_from_slice(b"Nginx\0");
        d.extend_from_slice(&[0xff, 0xff, 0xff, 5]);
        d.extend_from_slice(&pack_node(32));
        d
    }

    fn write_db(name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ngx-geoip-test-{}-{}", std::process::id(), name));
        std::fs::write(&p, data).unwrap();
        p
    }

    fn v6(a: &str) -> GeoIPv6 {
        a.parse::<std::net::Ipv6Addr>().unwrap().octets()
    }

    fn open(p: &std::path::Path) -> Option<GeoIPDb> {
        GeoIPDb::open(p.as_os_str().as_encoded_bytes(), GEOIP_MEMORY_CACHE | GEOIP_SILENCE)
    }

    #[test]
    fn lookups_in_test_databases() {
        let country = write_db("country.dat", &country_db());
        let city = write_db("city.dat", &city_db());
        let org = write_db("org.dat", &org_db());

        let ten = u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1));

        {
            let mut db = open(&country).unwrap();
            assert_eq!(db.database_type(), GEOIP_COUNTRY_EDITION_V6);

            let mapped = v6("::ffff:10.0.0.1");
            assert_eq!(db.country_by_ipnum_v6(GEOIP_COUNTRY_CODE, mapped), Some(&b"RU"[..]));
            assert_eq!(db.country_by_ipnum_v6(GEOIP_COUNTRY_CODE3, mapped), Some(&b"RUS"[..]));
            assert_eq!(db.country_by_ipnum_v6(GEOIP_COUNTRY_NAME, mapped), Some(&b"Russian Federation"[..]));

            let doc = v6("2001:db8::");
            assert_eq!(db.country_by_ipnum_v6(GEOIP_COUNTRY_CODE, doc), Some(&b"US"[..]));
            assert_eq!(db.country_by_ipnum_v6(GEOIP_COUNTRY_CODE3, doc), Some(&b"USA"[..]));
            assert_eq!(db.country_by_ipnum_v6(GEOIP_COUNTRY_NAME, doc), Some(&b"United States"[..]));

            // the unknown country ("--") is not found
            assert_eq!(db.country_by_ipnum_v6(GEOIP_COUNTRY_CODE, v6("8000::")), None);

            assert_eq!(db.set_charset(GEOIP_CHARSET_UTF8), GEOIP_CHARSET_ISO_8859_1);
            assert_eq!(db.set_charset(GEOIP_CHARSET_UTF8), GEOIP_CHARSET_UTF8);
        }

        {
            let db = open(&city).unwrap();
            assert_eq!(db.database_type(), GEOIP_CITY_EDITION_REV1);

            let gr = db.record_by_ipnum(ten).unwrap();
            assert_eq!(gr.str_member(record_member::CONTINENT_CODE).as_deref(), Some(&b"EU"[..]));
            assert_eq!(gr.str_member(record_member::COUNTRY_CODE).as_deref(), Some(&b"RU"[..]));
            assert_eq!(gr.str_member(record_member::COUNTRY_CODE3).as_deref(), Some(&b"RUS"[..]));
            assert_eq!(gr.str_member(record_member::COUNTRY_NAME).as_deref(), Some(&b"Russian Federation"[..]));
            assert_eq!(gr.str_member(record_member::REGION).as_deref(), Some(&b"48"[..]));
            assert_eq!(gr.str_member(record_member::CITY).as_deref(), Some(&b"Moscow"[..]));
            assert_eq!(gr.str_member(record_member::POSTAL_CODE).as_deref(), Some(&b"119034"[..]));
            assert_eq!(gr.int_member(record_member::DMA_CODE), 0);
            assert_eq!(gr.int_member(record_member::AREA_CODE), 0);
            assert_eq!(gr.int_member(record_member::NETMASK), 32);
            assert_eq!(gr.region_name(), Some(&b"Moscow City"[..]));

            let mut b = Vec::new();
            sprintf_float(&mut b, gr.float_member(record_member::LATITUDE) as f64, 4);
            assert_eq!(b, b"55.7543");
            b.clear();
            sprintf_float(&mut b, gr.float_member(record_member::LONGITUDE) as f64, 4);
            assert_eq!(b, b"37.6202");

            assert!(db.record_by_ipnum(0x0a000002).is_none());
        }

        {
            let mut db = open(&org).unwrap();
            assert_eq!(db.database_type(), GEOIP_ORG_EDITION);
            assert_eq!(db.name_by_ipnum(ten).as_deref(), Some(&b"Nginx"[..]));
            assert_eq!(db.name_by_ipnum(0x0a000002), None);
            db.set_charset(GEOIP_CHARSET_UTF8);
            assert_eq!(db.name_by_ipnum(ten).as_deref(), Some(&b"Nginx"[..]));
        }

        assert!(GeoIPDb::open(b"/nonexistent/geoip.dat", GEOIP_MEMORY_CACHE | GEOIP_SILENCE).is_none());

        for p in [country, city, org] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// The lookups of a list of databases, printed as the C program that
    /// does them with libGeoIP prints them (a differential test, run by
    /// hand: GEOIP_DIFF_DBS, GEOIP_DIFF_ADDRS and GEOIP_DIFF_OUT name the
    /// list of databases, the list of addresses and the output file).
    #[test]
    #[ignore]
    fn differential() {
        use std::fmt::Write as _;

        let env = |n: &str| std::env::var(n).unwrap();
        let dbs = std::fs::read_to_string(env("GEOIP_DIFF_DBS")).unwrap();
        let addrs = std::fs::read_to_string(env("GEOIP_DIFF_ADDRS")).unwrap();

        let pstr = |out: &mut String, s: Option<&[u8]>| match s {
            None => out.push_str("(null)"),
            Some(s) => {
                for &c in s {
                    if c > 0x20 && c < 0x7f && c != b'\\' {
                        out.push(c as char);
                    } else {
                        let _ = write!(out, "\\x{:02x}", c);
                    }
                }
            }
        };

        let precord = |out: &mut String, gr: Option<GeoIPRecord>| {
            let gr = match gr {
                None => {
                    out.push_str(" -\n");
                    return;
                }
                Some(gr) => gr,
            };

            out.push_str(" cc=");
            pstr(out, Some(gr.country_code));
            out.push_str(" cc3=");
            pstr(out, Some(gr.country_code3));
            out.push_str(" cn=");
            pstr(out, gr.country_name);
            out.push_str(" region=");
            pstr(out, gr.region.as_deref());
            out.push_str(" city=");
            pstr(out, gr.city.as_deref());
            out.push_str(" postal=");
            pstr(out, gr.postal_code.as_deref());
            let _ = write!(out, " lat={:08x} lon={:08x} dma={} area={} charset={}", gr.latitude.to_bits(), gr.longitude.to_bits(), gr.dma_code, gr.area_code, gr.charset);
            out.push_str(" cont=");
            pstr(out, Some(gr.continent_code));
            let _ = write!(out, " netmask={}", gr.netmask);
            out.push_str(" rname=");
            pstr(out, gr.region_name());
            out.push('\n');
        };

        let mut out = String::new();

        for line in dbs.lines() {
            let _ = writeln!(out, "DB {}", line);
            let _ = std::io::stderr().write_all(format!("DB {}\n", line).as_bytes());

            let mut gi = match GeoIPDb::open(line.as_bytes(), GEOIP_MEMORY_CACHE) {
                None => {
                    out.push_str("FAIL\n");
                    continue;
                }
                Some(gi) => gi,
            };

            let t = gi.database_type();
            let _ = writeln!(out, "TYPE {}", t);

            for cs in 0..2 {
                let _ = writeln!(out, "CS {}", gi.set_charset(cs));

                for a in addrs.lines() {
                    if let Some(a) = a.strip_prefix("4 ") {
                        let a: u32 = a.parse().unwrap();

                        if [1, 17, 8, 10].contains(&t) {
                            let _ = write!(out, "C4 {} ", a);
                            pstr(&mut out, gi.country_by_ipnum(GEOIP_COUNTRY_CODE, a));
                            out.push(' ');
                            pstr(&mut out, gi.country_by_ipnum(GEOIP_COUNTRY_CODE3, a));
                            out.push(' ');
                            pstr(&mut out, gi.country_by_ipnum(GEOIP_COUNTRY_NAME, a));
                            out.push('\n');
                        } else if [4, 5, 9, 11].contains(&t) {
                            let _ = write!(out, "N4 {} ", a);
                            pstr(&mut out, gi.name_by_ipnum(a).as_deref());
                            out.push('\n');
                        } else if [2, 6].contains(&t) {
                            let _ = write!(out, "R4 {}", a);
                            precord(&mut out, gi.record_by_ipnum(a));
                        }
                    } else if let Some(s) = a.strip_prefix("6 ") {
                        let a = s.parse::<std::net::Ipv6Addr>().unwrap().octets();

                        if [12, 18].contains(&t) {
                            let _ = write!(out, "C6 {} ", s);
                            pstr(&mut out, gi.country_by_ipnum_v6(GEOIP_COUNTRY_CODE, a));
                            out.push(' ');
                            pstr(&mut out, gi.country_by_ipnum_v6(GEOIP_COUNTRY_CODE3, a));
                            out.push(' ');
                            pstr(&mut out, gi.country_by_ipnum_v6(GEOIP_COUNTRY_NAME, a));
                            out.push('\n');
                        } else if [21, 22, 23, 24].contains(&t) {
                            let _ = write!(out, "N6 {} ", s);
                            pstr(&mut out, gi.name_by_ipnum_v6(a).as_deref());
                            out.push('\n');
                        } else if [30, 31].contains(&t) {
                            let _ = write!(out, "R6 {}", s);
                            precord(&mut out, gi.record_by_ipnum_v6(a));
                        }
                    }
                }
            }
        }

        std::fs::write(env("GEOIP_DIFF_OUT"), out).unwrap();
    }

    #[test]
    fn structure_info() {
        let seg = |d: &[u8]| setup_segments(d);

        // too short, no structure info within 20 positions
        assert_eq!(seg(b""), None);
        assert_eq!(seg(b"ab"), None);
        assert_eq!(seg(&[1u8; 22]), None);
        assert_eq!(seg(&[1u8; 23]), Some(Segments { database_type: 1, record_length: 3, segment: COUNTRY_BEGIN }));

        // the structure info found, the type byte missing
        assert_eq!(seg(&[0xff, 0xff, 0xff]), None);
        assert_eq!(seg(&[0xff, 0xff, 0xff, 1]), Some(Segments { database_type: 1, record_length: 3, segment: COUNTRY_BEGIN }));

        // types of April 2003 and earlier
        assert_eq!(seg(&[0xff, 0xff, 0xff, 106]).map(|s| s.database_type), Some(1));
        assert_eq!(seg(&[0xff, 0xff, 0xff, 0x80]), None);

        // the second segment of city and org databases
        assert_eq!(seg(&[0xff, 0xff, 0xff, 2, 1, 2, 3]), Some(Segments { database_type: 2, record_length: 3, segment: 0x030201 }));
        assert_eq!(seg(&[0xff, 0xff, 0xff, 5, 1, 2, 3]), Some(Segments { database_type: 5, record_length: 4, segment: 0x030201 }));
        assert_eq!(seg(&[0xff, 0xff, 0xff, 9, 1, 2, 3]), Some(Segments { database_type: 9, record_length: 3, segment: 0x030201 }));
        assert_eq!(seg(&[0, 0xff, 0xff, 0xff, 5, 1, 2]), None);

        // region editions, unknown types
        assert_eq!(seg(&[0xff, 0xff, 0xff, 7]).map(|s| s.segment), Some(STATE_BEGIN_REV0));
        assert_eq!(seg(&[0xff, 0xff, 0xff, 3]).map(|s| s.segment), Some(STATE_BEGIN_REV1));
        assert_eq!(seg(&[0xff, 0xff, 0xff, 17]).map(|s| s.segment), Some(LARGE_COUNTRY_BEGIN));
        assert_eq!(seg(&[0xff, 0xff, 0xff, 0]), None);
        assert_eq!(seg(&[0xff, 0xff, 0xff, 15]), None);

        // the index must fit in the file
        let s = Segments { database_type: 2, record_length: 3, segment: 10 };
        assert_eq!(index_size(&s, 60), 60);
        assert_eq!(index_size(&s, 59), -1);
        assert_eq!(index_size(&Segments { database_type: 1, record_length: 3, segment: COUNTRY_BEGIN }, 7), 7);
    }

    #[test]
    fn broken_trees_and_records() {
        // a country database of 4 bytes: the first node is outside the file
        let tiny = write_db("tiny.dat", &[0xff, 0xff, 0xff, 1]);
        let db = open(&tiny).unwrap();
        assert_eq!(db.seek_record(1), (0, 0));
        assert_eq!(db.country_by_ipnum(GEOIP_COUNTRY_CODE, 1), None);
        assert_eq!(db.country_by_ipnum(GEOIP_COUNTRY_NAME, 1), None);
        let _ = std::fs::remove_file(tiny);

        // records and names cut by the end of the file: zeroes past the
        // end; segment 1, record length 3: the data of the record x is at
        // x + 5
        let mk = |cache: Vec<u8>, database_type: i32, record_length: u8| GeoIPDb {
            _file: File::open("/dev/null").unwrap(),
            size: cache.len() as i64,
            cache,
            seg: Segments { database_type: database_type as i8, record_length, segment: 1 },
            flags: GEOIP_SILENCE,
            charset: GEOIP_CHARSET_ISO_8859_1,
            teredo: true,
        };

        let mut cache = vec![0u8; 7];
        cache.extend_from_slice(&[225, b'C', b'A', 0, b'S', b'F']);
        let db = mk(cache, GEOIP_CITY_EDITION_REV1, 3);

        assert!(db.extract_record(1).is_none());

        let gr = db.extract_record(2).unwrap();
        assert_eq!(gr.country_code, b"US");
        assert_eq!(gr.region.as_deref(), Some(&b"CA"[..]));
        assert_eq!(gr.city.as_deref(), Some(&b"SF"[..]));
        assert_eq!(gr.postal_code, None);
        assert_eq!(gr.latitude, -180.0);
        assert_eq!((gr.dma_code, gr.area_code), (0, 0));

        // the record pointer at the end of the file and past it
        assert!(db.extract_record(7).is_some());
        assert!(db.extract_record(8).is_none());

        // a name at the end of the file and past it: zeroes
        let db = mk(b"0123456Nginx".to_vec(), GEOIP_ORG_EDITION, 3);
        assert_eq!(db.name_at(db.record_pointer(2)), b"Nginx");
        assert_eq!(db.name_at(db.record_pointer(6)), b"x");
        assert_eq!(db.name_at(db.record_pointer(7)), b"");
        assert_eq!(db.name_at(db.record_pointer(100)), b"");
        assert_eq!(db.name_at(-1), b"");
    }
}
