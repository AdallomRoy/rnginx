//! The legacy MaxMind GeoIP C library (GeoIP.h and GeoIPCity.h of libGeoIP
//! 1.6), used by ngx_http_geoip_module and ngx_stream_geoip_module.
//!
//! C nginx links libGeoIP (auto/lib/geoip).  The port has no build-time
//! dependency on it: the library is dlopen()ed when the first geoip_*
//! directive is parsed (conf_load()), so the binary starts without it and
//! only a configuration that uses the GeoIP modules needs it; if it cannot
//! be loaded, the configuration fails with an emerg message like the ones
//! of ngx_load_module().  The library is never unloaded, the resolved
//! function table is process-wide.
//!
//! The configure test of C nginx defines NGX_HAVE_GEOIP_V6 when the library
//! has GeoIP_country_code_by_ipnum_v6(), which is the case for every 1.6
//! library; the port requires the _v6 functions and always behaves as built
//! with NGX_HAVE_GEOIP_V6.

use std::ffi::{c_char, c_int, c_uchar, c_ulong, c_void, CStr, CString};
use std::mem::offset_of;
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::OnceLock;

use crate::conf::{Conf, ConfError};
use crate::string::B;

/// The soname of libGeoIP 1.x.
pub const LIBGEOIP: &str = "libGeoIP.so.1";

// GeoIPOptions

pub const GEOIP_STANDARD: c_int = 0;
pub const GEOIP_MEMORY_CACHE: c_int = 1;
pub const GEOIP_CHECK_CACHE: c_int = 2;
pub const GEOIP_INDEX_CACHE: c_int = 4;
pub const GEOIP_MMAP_CACHE: c_int = 8;
pub const GEOIP_SILENCE: c_int = 16;

// GeoIPCharset

pub const GEOIP_CHARSET_ISO_8859_1: c_int = 0;
pub const GEOIP_CHARSET_UTF8: c_int = 1;

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

/// GeoIP (struct GeoIPTag).  Opaque: nginx reads only its databaseType
/// member, which GeoIP_database_edition() returns.
#[repr(C)]
pub struct GeoIP {
    _opaque: [u8; 0],
}

/// geoipv6_t: a struct in6_addr, passed by value.
pub type GeoIPv6 = libc::in6_addr;

/// GeoIPRecord (struct GeoIPRecordTag of GeoIPCity.h).
#[repr(C)]
pub struct GeoIPRecord {
    pub country_code: *mut c_char,
    pub country_code3: *mut c_char,
    pub country_name: *mut c_char,
    pub region: *mut c_char,
    pub city: *mut c_char,
    pub postal_code: *mut c_char,
    pub latitude: f32,
    pub longitude: f32,
    /// union { int metro_code; int dma_code; }
    pub dma_code: c_int,
    pub area_code: c_int,
    pub charset: c_int,
    pub continent_code: *mut c_char,
    pub netmask: c_int,
}

/// The functions of libGeoIP used by nginx, resolved with dlsym().  The
/// members are named after the C functions.
#[allow(non_snake_case)]
pub struct GeoIPLib {
    pub GeoIP_open: unsafe extern "C" fn(filename: *const c_char, flags: c_int) -> *mut GeoIP,
    pub GeoIP_delete: unsafe extern "C" fn(gi: *mut GeoIP),
    pub GeoIP_set_charset: unsafe extern "C" fn(gi: *mut GeoIP, charset: c_int) -> c_int,
    pub GeoIP_database_edition: unsafe extern "C" fn(gi: *mut GeoIP) -> c_uchar,

    pub GeoIP_country_code_by_ipnum: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: c_ulong) -> *const c_char,
    pub GeoIP_country_code3_by_ipnum: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: c_ulong) -> *const c_char,
    pub GeoIP_country_name_by_ipnum: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: c_ulong) -> *const c_char,
    pub GeoIP_country_code_by_ipnum_v6: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: GeoIPv6) -> *const c_char,
    pub GeoIP_country_code3_by_ipnum_v6: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: GeoIPv6) -> *const c_char,
    pub GeoIP_country_name_by_ipnum_v6: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: GeoIPv6) -> *const c_char,

    /// the result is malloc()ed, it is freed with free()
    pub GeoIP_name_by_ipnum: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: c_ulong) -> *mut c_char,
    pub GeoIP_name_by_ipnum_v6: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: GeoIPv6) -> *mut c_char,

    pub GeoIP_record_by_ipnum: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: c_ulong) -> *mut GeoIPRecord,
    pub GeoIP_record_by_ipnum_v6: unsafe extern "C" fn(gi: *mut GeoIP, ipnum: GeoIPv6) -> *mut GeoIPRecord,
    pub GeoIPRecord_delete: unsafe extern "C" fn(gir: *mut GeoIPRecord),

    pub GeoIP_region_name_by_code: unsafe extern "C" fn(country_code: *const c_char, region_code: *const c_char) -> *const c_char,
}

static LIB: OnceLock<GeoIPLib> = OnceLock::new();

/// ngx_dlerror()
fn dlerror() -> String {
    // SAFETY: dlerror() returns NULL or a NUL-terminated string that stays
    // valid until the next dl* call; it is copied at once.
    let err = unsafe { libc::dlerror() };

    if err.is_null() {
        return String::new();
    }

    // SAFETY: see above
    unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned()
}

impl GeoIPLib {
    /// dlopen() the library (LIBGEOIP) and resolve the functions.
    fn load(name: &str) -> Result<GeoIPLib, String> {
        let file = CString::new(name).expect("soname");

        // SAFETY: a valid NUL-terminated file name; the handle is never
        // dlclose()d, so the resolved functions stay valid for the lifetime
        // of the process.
        let handle = unsafe { libc::dlopen(file.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };

        if handle.is_null() {
            return Err(format!("dlopen() \"{}\" failed ({})", name, dlerror()));
        }

        macro_rules! sym {
            ($name:ident) => {{
                let symbol = concat!(stringify!($name), "\0");

                // SAFETY: a valid handle and a NUL-terminated symbol name
                let p: *mut c_void = unsafe { libc::dlsym(handle, symbol.as_ptr() as *const c_char) };

                if p.is_null() {
                    let err = format!("dlsym() \"{}\", \"{}\" failed ({})", name, stringify!($name), dlerror());

                    // SAFETY: the handle is not used afterwards
                    unsafe { libc::dlclose(handle) };

                    return Err(err);
                }

                // SAFETY: p is the address of the libGeoIP function of this
                // name, the member's type is its prototype in GeoIP.h /
                // GeoIPCity.h of libGeoIP 1.6.
                unsafe { std::mem::transmute::<*mut c_void, _>(p) }
            }};
        }

        Ok(GeoIPLib {
            GeoIP_open: sym!(GeoIP_open),
            GeoIP_delete: sym!(GeoIP_delete),
            GeoIP_set_charset: sym!(GeoIP_set_charset),
            GeoIP_database_edition: sym!(GeoIP_database_edition),
            GeoIP_country_code_by_ipnum: sym!(GeoIP_country_code_by_ipnum),
            GeoIP_country_code3_by_ipnum: sym!(GeoIP_country_code3_by_ipnum),
            GeoIP_country_name_by_ipnum: sym!(GeoIP_country_name_by_ipnum),
            GeoIP_country_code_by_ipnum_v6: sym!(GeoIP_country_code_by_ipnum_v6),
            GeoIP_country_code3_by_ipnum_v6: sym!(GeoIP_country_code3_by_ipnum_v6),
            GeoIP_country_name_by_ipnum_v6: sym!(GeoIP_country_name_by_ipnum_v6),
            GeoIP_name_by_ipnum: sym!(GeoIP_name_by_ipnum),
            GeoIP_name_by_ipnum_v6: sym!(GeoIP_name_by_ipnum_v6),
            GeoIP_record_by_ipnum: sym!(GeoIP_record_by_ipnum),
            GeoIP_record_by_ipnum_v6: sym!(GeoIP_record_by_ipnum_v6),
            GeoIPRecord_delete: sym!(GeoIPRecord_delete),
            GeoIP_region_name_by_code: sym!(GeoIP_region_name_by_code),
        })
    }
}

/// The library, loaded once per process; a failure is not remembered, the
/// next configuration (reload) tries again.
pub fn lib() -> Result<&'static GeoIPLib, String> {
    if let Some(lib) = LIB.get() {
        return Ok(lib);
    }

    let lib = GeoIPLib::load(LIBGEOIP)?;

    Ok(LIB.get_or_init(|| lib))
}

/// The library for a geoip_* directive: logs the emerg message
/// (ngx_load_module() style, "in file:line" appended) if it cannot be
/// loaded.
pub fn conf_load(cf: &Conf) -> Result<&'static GeoIPLib, ConfError> {
    lib().map_err(|err| cf.emerg(format_args!("{}", err)))
}

/// The common part of the geoip_country, geoip_org and geoip_city handlers
/// of the http and stream modules: GeoIP_open() of the database and its
/// optional "utf8" parameter.  As in C, the database is stored in *db
/// before the parameter is checked; the caller checks the database type.
pub fn conf_open(cf: &mut Conf, db: &mut Option<GeoIPDb>) -> Result<(), ConfError> {
    let value = cf.args.clone();

    let lib = conf_load(cf)?;

    *db = GeoIPDb::open(lib, &value[1], GEOIP_MEMORY_CACHE);

    let gi = match db {
        None => {
            return Err(cf.emerg(format_args!("GeoIP_open(\"{}\") failed", B(&value[1]))));
        }
        Some(gi) => gi,
    };

    if value.len() == 3 {
        if value[2] == b"utf8" {
            gi.set_charset(GEOIP_CHARSET_UTF8);
        } else {
            return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&value[2]))));
        }
    }

    Ok(())
}

/// The bytes of a C string, None for NULL.
///
/// SAFETY: p must be NULL or point to a NUL-terminated string.
unsafe fn c_bytes(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }

    // SAFETY: by the contract of the function
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

/// An open database (GeoIP *).  It is GeoIP_delete()d when dropped, which
/// is what the pool cleanup handlers ngx_http_geoip_cleanup() and
/// ngx_stream_geoip_cleanup() do when the configuration is freed.
pub struct GeoIPDb {
    gi: NonNull<GeoIP>,
    lib: &'static GeoIPLib,
}

impl GeoIPDb {
    /// GeoIP_open(filename, flags): None if it failed.  As in C, the name
    /// ends at the first NUL byte.
    pub fn open(lib: &'static GeoIPLib, filename: &[u8], flags: c_int) -> Option<GeoIPDb> {
        let len = filename.iter().position(|&c| c == 0).unwrap_or(filename.len());
        let file = CString::new(&filename[..len]).expect("no NUL bytes");

        // SAFETY: a NUL-terminated file name
        let gi = unsafe { (lib.GeoIP_open)(file.as_ptr(), flags) };

        NonNull::new(gi).map(|gi| GeoIPDb { gi, lib })
    }

    /// GeoIP_set_charset(): returns the previous charset
    pub fn set_charset(&self, charset: c_int) -> c_int {
        // SAFETY: gi is an open database
        unsafe { (self.lib.GeoIP_set_charset)(self.gi.as_ptr(), charset) }
    }

    /// gi->databaseType: a C char (signed on the supported platforms),
    /// promoted to int as in the "type:%d" messages of nginx.
    pub fn database_type(&self) -> i32 {
        // SAFETY: gi is an open database
        let t = unsafe { (self.lib.GeoIP_database_edition)(self.gi.as_ptr()) };
        t as i8 as i32
    }

    /// ngx_*_geoip_country_functions[n](gi, addr): n is
    /// NGX_GEOIP_COUNTRY_CODE, NGX_GEOIP_COUNTRY_CODE3 or
    /// NGX_GEOIP_COUNTRY_NAME.  The C result is a static string.
    pub fn country_by_ipnum(&self, n: usize, addr: c_ulong) -> Option<Vec<u8>> {
        let handler = [self.lib.GeoIP_country_code_by_ipnum, self.lib.GeoIP_country_code3_by_ipnum, self.lib.GeoIP_country_name_by_ipnum][n];

        // SAFETY: gi is an open database; the result is NULL or a static
        // NUL-terminated string of the library
        unsafe { c_bytes(handler(self.gi.as_ptr(), addr)) }
    }

    /// ngx_*_geoip_country_v6_functions[n](gi, addr)
    pub fn country_by_ipnum_v6(&self, n: usize, addr: GeoIPv6) -> Option<Vec<u8>> {
        let handler = [self.lib.GeoIP_country_code_by_ipnum_v6, self.lib.GeoIP_country_code3_by_ipnum_v6, self.lib.GeoIP_country_name_by_ipnum_v6][n];

        // SAFETY: as in country_by_ipnum()
        unsafe { c_bytes(handler(self.gi.as_ptr(), addr)) }
    }

    /// GeoIP_name_by_ipnum(): the malloc()ed result is copied and freed
    /// (ngx_free()).
    pub fn name_by_ipnum(&self, addr: c_ulong) -> Option<Vec<u8>> {
        // SAFETY: gi is an open database
        let val = unsafe { (self.lib.GeoIP_name_by_ipnum)(self.gi.as_ptr(), addr) };
        // SAFETY: val is NULL or a malloc()ed NUL-terminated string owned by
        // the caller
        unsafe { take_malloced(val) }
    }

    /// GeoIP_name_by_ipnum_v6()
    pub fn name_by_ipnum_v6(&self, addr: GeoIPv6) -> Option<Vec<u8>> {
        // SAFETY: gi is an open database
        let val = unsafe { (self.lib.GeoIP_name_by_ipnum_v6)(self.gi.as_ptr(), addr) };
        // SAFETY: as in name_by_ipnum()
        unsafe { take_malloced(val) }
    }

    /// GeoIP_record_by_ipnum()
    pub fn record_by_ipnum(&self, addr: c_ulong) -> Option<GeoIPRecordPtr> {
        // SAFETY: gi is an open database
        let gr = unsafe { (self.lib.GeoIP_record_by_ipnum)(self.gi.as_ptr(), addr) };
        NonNull::new(gr).map(|gr| GeoIPRecordPtr { gr, lib: self.lib })
    }

    /// GeoIP_record_by_ipnum_v6()
    pub fn record_by_ipnum_v6(&self, addr: GeoIPv6) -> Option<GeoIPRecordPtr> {
        // SAFETY: gi is an open database
        let gr = unsafe { (self.lib.GeoIP_record_by_ipnum_v6)(self.gi.as_ptr(), addr) };
        NonNull::new(gr).map(|gr| GeoIPRecordPtr { gr, lib: self.lib })
    }
}

impl Drop for GeoIPDb {
    fn drop(&mut self) {
        // SAFETY: gi was returned by GeoIP_open() and is deleted once
        unsafe { (self.lib.GeoIP_delete)(self.gi.as_ptr()) };
    }
}

/// Copy and free() a malloc()ed C string.
///
/// SAFETY: p must be NULL or a malloc()ed NUL-terminated string that the
/// caller owns.
unsafe fn take_malloced(p: *mut c_char) -> Option<Vec<u8>> {
    // SAFETY: by the contract of the function
    let v = unsafe { c_bytes(p) }?;

    // SAFETY: p was malloc()ed by the library and is not used afterwards
    unsafe { libc::free(p as *mut c_void) };

    Some(v)
}

/// A record of GeoIP_record_by_ipnum*(): GeoIPRecord_delete()d when dropped.
pub struct GeoIPRecordPtr {
    gr: NonNull<GeoIPRecord>,
    lib: &'static GeoIPLib,
}

impl Deref for GeoIPRecordPtr {
    type Target = GeoIPRecord;

    fn deref(&self) -> &GeoIPRecord {
        // SAFETY: the record is alive until self is dropped
        unsafe { self.gr.as_ref() }
    }
}

impl Drop for GeoIPRecordPtr {
    fn drop(&mut self) {
        // SAFETY: the record was returned by GeoIP_record_by_ipnum*() and is
        // deleted once
        unsafe { (self.lib.GeoIPRecord_delete)(self.gr.as_ptr()) };
    }
}

impl GeoIPRecordPtr {
    /// *(char **) ((char *) gr + offset): the string member at offset
    /// (offset_of!(GeoIPRecord, member), the variables' data), None if
    /// NULL.
    pub fn str_member(&self, offset: usize) -> Option<Vec<u8>> {
        let gr: &GeoIPRecord = self;

        let p = match offset {
            o if o == offset_of!(GeoIPRecord, country_code) => gr.country_code,
            o if o == offset_of!(GeoIPRecord, country_code3) => gr.country_code3,
            o if o == offset_of!(GeoIPRecord, country_name) => gr.country_name,
            o if o == offset_of!(GeoIPRecord, region) => gr.region,
            o if o == offset_of!(GeoIPRecord, city) => gr.city,
            o if o == offset_of!(GeoIPRecord, postal_code) => gr.postal_code,
            o if o == offset_of!(GeoIPRecord, continent_code) => gr.continent_code,
            _ => panic!("no char * member of GeoIPRecord at offset {}", offset),
        };

        // SAFETY: the members are NULL or NUL-terminated strings (static
        // tables or malloc()ed with the record)
        unsafe { c_bytes(p) }
    }

    /// *(float *) ((char *) gr + offset)
    pub fn float_member(&self, offset: usize) -> f32 {
        match offset {
            o if o == offset_of!(GeoIPRecord, latitude) => self.latitude,
            o if o == offset_of!(GeoIPRecord, longitude) => self.longitude,
            _ => panic!("no float member of GeoIPRecord at offset {}", offset),
        }
    }

    /// *(int *) ((char *) gr + offset)
    pub fn int_member(&self, offset: usize) -> c_int {
        match offset {
            o if o == offset_of!(GeoIPRecord, dma_code) => self.dma_code,
            o if o == offset_of!(GeoIPRecord, area_code) => self.area_code,
            o if o == offset_of!(GeoIPRecord, charset) => self.charset,
            o if o == offset_of!(GeoIPRecord, netmask) => self.netmask,
            _ => panic!("no int member of GeoIPRecord at offset {}", offset),
        }
    }

    /// GeoIP_region_name_by_code(gr->country_code, gr->region): a static
    /// string of the library.
    pub fn region_name(&self) -> Option<Vec<u8>> {
        // SAFETY: the members are NULL or NUL-terminated strings, as
        // GeoIP_region_name_by_code() expects them; the result is NULL or a
        // static string
        unsafe { c_bytes((self.lib.GeoIP_region_name_by_code)(self.country_code, self.region)) }
    }
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
    fn load_errors() {
        let err = GeoIPLib::load("libGeoIP-nonexistent.so.1").err().unwrap();
        assert!(err.starts_with("dlopen() \"libGeoIP-nonexistent.so.1\" failed (libGeoIP-nonexistent.so.1: "), "{}", err);

        let err = GeoIPLib::load("libc.so.6").err().unwrap();
        assert!(err.starts_with("dlsym() \"libc.so.6\", \"GeoIP_open\" failed ("), "{}", err);
        assert!(err.contains("undefined symbol: GeoIP_open"), "{}", err);
    }

    #[test]
    fn record_layout_is_geoipcity_h() {
        // GeoIPCity.h of libGeoIP 1.6 on LP64 (checked against the DWARF of
        // the C nginx build)
        assert_eq!(offset_of!(GeoIPRecord, country_code), 0);
        assert_eq!(offset_of!(GeoIPRecord, country_code3), 8);
        assert_eq!(offset_of!(GeoIPRecord, country_name), 16);
        assert_eq!(offset_of!(GeoIPRecord, region), 24);
        assert_eq!(offset_of!(GeoIPRecord, city), 32);
        assert_eq!(offset_of!(GeoIPRecord, postal_code), 40);
        assert_eq!(offset_of!(GeoIPRecord, latitude), 48);
        assert_eq!(offset_of!(GeoIPRecord, longitude), 52);
        assert_eq!(offset_of!(GeoIPRecord, dma_code), 56);
        assert_eq!(offset_of!(GeoIPRecord, area_code), 60);
        assert_eq!(offset_of!(GeoIPRecord, charset), 64);
        assert_eq!(offset_of!(GeoIPRecord, continent_code), 72);
        assert_eq!(offset_of!(GeoIPRecord, netmask), 80);
        assert_eq!(std::mem::size_of::<GeoIPRecord>(), 88);
        assert_eq!(std::mem::size_of::<GeoIPv6>(), 16);
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

    fn v6(a: std::net::Ipv6Addr) -> GeoIPv6 {
        GeoIPv6 { s6_addr: a.octets() }
    }

    #[test]
    fn lookups_in_test_databases() {
        let lib = match lib() {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipped: {}", e);
                return;
            }
        };

        let country = write_db("country.dat", &country_db());
        let city = write_db("city.dat", &city_db());
        let org = write_db("org.dat", &org_db());

        let ten = u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1)) as c_ulong;

        {
            let db = GeoIPDb::open(lib, country.as_os_str().as_encoded_bytes(), GEOIP_MEMORY_CACHE).unwrap();
            assert_eq!(db.database_type(), GEOIP_COUNTRY_EDITION_V6);

            let mapped = v6("::ffff:10.0.0.1".parse().unwrap());
            assert_eq!(db.country_by_ipnum_v6(0, mapped).as_deref(), Some(&b"RU"[..]));
            assert_eq!(db.country_by_ipnum_v6(1, mapped).as_deref(), Some(&b"RUS"[..]));
            assert_eq!(db.country_by_ipnum_v6(2, mapped).as_deref(), Some(&b"Russian Federation"[..]));

            let doc = v6("2001:db8::".parse().unwrap());
            assert_eq!(db.country_by_ipnum_v6(0, doc).as_deref(), Some(&b"US"[..]));
            assert_eq!(db.country_by_ipnum_v6(1, doc).as_deref(), Some(&b"USA"[..]));
            assert_eq!(db.country_by_ipnum_v6(2, doc).as_deref(), Some(&b"United States"[..]));

            assert_eq!(db.set_charset(GEOIP_CHARSET_UTF8), GEOIP_CHARSET_ISO_8859_1);
        }

        {
            let db = GeoIPDb::open(lib, city.as_os_str().as_encoded_bytes(), GEOIP_MEMORY_CACHE).unwrap();
            assert_eq!(db.database_type(), GEOIP_CITY_EDITION_REV1);

            let gr = db.record_by_ipnum(ten).unwrap();
            assert_eq!(gr.str_member(offset_of!(GeoIPRecord, continent_code)).as_deref(), Some(&b"EU"[..]));
            assert_eq!(gr.str_member(offset_of!(GeoIPRecord, country_code)).as_deref(), Some(&b"RU"[..]));
            assert_eq!(gr.str_member(offset_of!(GeoIPRecord, country_code3)).as_deref(), Some(&b"RUS"[..]));
            assert_eq!(gr.str_member(offset_of!(GeoIPRecord, country_name)).as_deref(), Some(&b"Russian Federation"[..]));
            assert_eq!(gr.str_member(offset_of!(GeoIPRecord, region)).as_deref(), Some(&b"48"[..]));
            assert_eq!(gr.str_member(offset_of!(GeoIPRecord, city)).as_deref(), Some(&b"Moscow"[..]));
            assert_eq!(gr.str_member(offset_of!(GeoIPRecord, postal_code)).as_deref(), Some(&b"119034"[..]));
            assert_eq!(gr.int_member(offset_of!(GeoIPRecord, dma_code)), 0);
            assert_eq!(gr.int_member(offset_of!(GeoIPRecord, area_code)), 0);
            assert_eq!(gr.region_name().as_deref(), Some(&b"Moscow City"[..]));

            let mut b = Vec::new();
            sprintf_float(&mut b, gr.float_member(offset_of!(GeoIPRecord, latitude)) as f64, 4);
            assert_eq!(b, b"55.7543");
            b.clear();
            sprintf_float(&mut b, gr.float_member(offset_of!(GeoIPRecord, longitude)) as f64, 4);
            assert_eq!(b, b"37.6202");

            assert!(db.record_by_ipnum(0x0a000002).is_none());
        }

        {
            let db = GeoIPDb::open(lib, org.as_os_str().as_encoded_bytes(), GEOIP_MEMORY_CACHE).unwrap();
            assert_eq!(db.database_type(), GEOIP_ORG_EDITION);
            assert_eq!(db.name_by_ipnum(ten).as_deref(), Some(&b"Nginx"[..]));
            assert_eq!(db.name_by_ipnum(0x0a000002), None);
        }

        assert!(GeoIPDb::open(lib, b"/nonexistent/geoip.dat", GEOIP_MEMORY_CACHE | GEOIP_SILENCE).is_none());

        for p in [country, city, org] {
            let _ = std::fs::remove_file(p);
        }
    }
}
