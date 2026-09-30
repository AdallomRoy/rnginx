//! Cached time and time formatting, ported from ngx_times.c.

use std::cell::RefCell;
use std::time::{SystemTime, UNIX_EPOCH};

pub const WEEK: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
pub const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

#[derive(Clone, Copy, Debug, Default)]
pub struct Tm {
    pub sec: u32,
    pub min: u32,
    pub hour: u32,
    pub mday: u32,
    pub mon: u32,  // 1..=12
    pub year: u32,
    pub wday: u32,
}

/// Port of ngx_gmtime (valid for positive time only).
pub fn gmtime(t: i64) -> Tm {
    let t = if t < 0 { 0 } else { t } as u64;
    let mut days = t / 86400;
    let mut sec = t % 86400;
    if days > 2932896 {
        days = 2932896;
        sec = 86399;
    }
    let wday = ((4 + days) % 7) as u32;
    let hour = (sec / 3600) as u32;
    sec %= 3600;
    let min = (sec / 60) as u32;
    sec %= 60;

    let days = days as i64 - (31 + 28) + 719527;
    let mut year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);
    let mut yday = days - (365 * year + year / 4 - year / 100 + year / 400);
    if yday < 0 {
        let leap = (year % 4 == 0) && (year % 100 != 0 || (year % 400 == 0));
        yday = 365 + leap as i64 + yday;
        year -= 1;
    }
    let mut mon = (yday + 31) * 10 / 306;
    let mday = yday - (367 * mon / 12 - 30) + 1;
    if yday >= 306 {
        year += 1;
        mon -= 10;
    } else {
        mon += 2;
    }
    Tm { sec: sec as u32, min, hour, mday: mday as u32, mon: mon as u32, year: year as u32, wday }
}

/// "Sun, 06 Nov 1994 08:49:37 GMT"
pub fn http_time(t: i64) -> String {
    let tm = gmtime(t);
    format!(
        "{}, {:02} {} {:4} {:02}:{:02}:{:02} GMT",
        WEEK[tm.wday as usize], tm.mday, MONTHS[(tm.mon - 1) as usize], tm.year, tm.hour, tm.min, tm.sec
    )
}

/// "Sun, 06-Nov-94 08:49:37 GMT" (two digit year unless > 2037)
pub fn http_cookie_time(t: i64) -> String {
    let tm = gmtime(t);
    if tm.year > 2037 {
        format!(
            "{}, {:02}-{}-{} {:02}:{:02}:{:02} GMT",
            WEEK[tm.wday as usize], tm.mday, MONTHS[(tm.mon - 1) as usize], tm.year, tm.hour, tm.min, tm.sec
        )
    } else {
        format!(
            "{}, {:02}-{}-{:02} {:02}:{:02}:{:02} GMT",
            WEEK[tm.wday as usize], tm.mday, MONTHS[(tm.mon - 1) as usize], tm.year % 100, tm.hour, tm.min, tm.sec
        )
    }
}

/// Local timezone offset in minutes for time `t`.
pub fn gmtoff(t: i64) -> i64 {
    unsafe {
        let tt: libc::time_t = t as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&tt, &mut tm).is_null() {
            return 0;
        }
        (tm.tm_gmtoff / 60) as i64
    }
}

#[derive(Clone, Debug)]
pub struct CachedTime {
    pub sec: i64,
    pub msec: u64,
    pub gmtoff: i64,
    pub err_log_time: String,     // "1970/09/28 12:00:00"
    pub http_time: String,        // "Mon, 28 Sep 1970 06:00:00 GMT"
    pub http_log_time: String,    // "28/Sep/1970:12:00:00 +0600"
    pub http_log_iso8601: String, // "1970-09-28T12:00:00+06:00"
    pub syslog_time: String,      // "Sep 28 12:00:00"
}

thread_local! {
    static CACHED: RefCell<CachedTime> = RefCell::new(build(0, 0));
    static TZ_INIT: RefCell<bool> = const { RefCell::new(false) };
}

fn build(sec: i64, msec: u64) -> CachedTime {
    let gmt = gmtime(sec);
    let off = gmtoff(sec);
    let tm = gmtime(sec + off * 60);
    let sign = if off < 0 { '-' } else { '+' };
    let aoff = off.abs();
    CachedTime {
        sec,
        msec,
        gmtoff: off,
        http_time: format!(
            "{}, {:02} {} {:4} {:02}:{:02}:{:02} GMT",
            WEEK[gmt.wday as usize], gmt.mday, MONTHS[(gmt.mon - 1) as usize], gmt.year, gmt.hour, gmt.min, gmt.sec
        ),
        err_log_time: format!("{:4}/{:02}/{:02} {:02}:{:02}:{:02}", tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec),
        http_log_time: format!(
            "{:02}/{}/{}:{:02}:{:02}:{:02} {}{:02}{:02}",
            tm.mday, MONTHS[(tm.mon - 1) as usize], tm.year, tm.hour, tm.min, tm.sec, sign, aoff / 60, aoff % 60
        ),
        http_log_iso8601: format!(
            "{:4}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}:{:02}",
            tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec, sign, aoff / 60, aoff % 60
        ),
        syslog_time: format!("{} {:2} {:02}:{:02}:{:02}", MONTHS[(tm.mon - 1) as usize], tm.mday, tm.hour, tm.min, tm.sec),
    }
}

fn now_raw() -> (i64, u64) {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() as i64, (d.subsec_millis()) as u64)
}

/// Refresh the cached time (call at least once per event-loop iteration; cheap).
pub fn update() {
    TZ_INIT.with(|i| {
        if !*i.borrow() {
            extern "C" { fn tzset(); }
            unsafe { tzset() };
            *i.borrow_mut() = true;
        }
    });
    let (sec, msec) = now_raw();
    CACHED.with(|c| {
        let mut c = c.borrow_mut();
        if c.sec == sec {
            c.msec = msec;
            return;
        }
        *c = build(sec, msec);
    });
}

/// Current cached time in seconds (updates the cache first).
pub fn time() -> i64 {
    update();
    CACHED.with(|c| c.borrow().sec)
}

/// ngx_next_time: the next moment `when` seconds after a local midnight
/// (today's if still to come, else tomorrow's), -1 if mktime() fails.
pub fn next_time(when: i64) -> i64 {
    let now = time();

    // SAFETY: tm is a plain struct filled by localtime_r() and normalized
    // by mktime().
    unsafe {
        let t = now as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();

        libc::localtime_r(&t, &mut tm);

        tm.tm_hour = (when / 3600) as libc::c_int;
        let when = when % 3600;
        tm.tm_min = (when / 60) as libc::c_int;
        tm.tm_sec = (when % 60) as libc::c_int;

        let next = libc::mktime(&mut tm);

        if next == -1 {
            return -1;
        }

        if next as i64 - now > 0 {
            return next as i64;
        }

        tm.tm_mday += 1;

        // mktime() should normalize a date (Jan 32, etc)

        let next = libc::mktime(&mut tm);

        if next != -1 {
            return next as i64;
        }

        -1
    }
}

/// Current time in milliseconds since epoch (wall clock).
pub fn msec() -> u64 {
    update();
    CACHED.with(|c| {
        let c = c.borrow();
        c.sec as u64 * 1000 + c.msec
    })
}

/// Monotonic milliseconds, like ngx_current_msec.
pub fn current_msec() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1000 + (ts.tv_nsec / 1_000_000) as u64
}

pub fn cached() -> CachedTime {
    update();
    CACHED.with(|c| c.borrow().clone())
}

pub fn with_cached<R>(f: impl FnOnce(&CachedTime) -> R) -> R {
    update();
    CACHED.with(|c| f(&c.borrow()))
}

pub fn cached_http_time() -> String {
    with_cached(|c| c.http_time.clone())
}

pub fn cached_err_log_time() -> String {
    with_cached(|c| c.err_log_time.clone())
}

pub fn cached_http_log_time() -> String {
    with_cached(|c| c.http_log_time.clone())
}

pub fn cached_http_log_iso8601() -> String {
    with_cached(|c| c.http_log_iso8601.clone())
}

pub fn cached_syslog_time() -> String {
    with_cached(|c| c.syslog_time.clone())
}

/// Local time broken down (like ngx_localtime) for `t`.
pub fn localtime(t: i64) -> Tm {
    gmtime(t + gmtoff(t) * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_time() {
        let now = time();

        for when in [0, 1, 3600, 55833, 86399, 86400] {
            let next = next_time(when);

            // later than now, within a day (and the DST hour)
            assert!(next > now, "{when}: {next} <= {now}");
            assert!(next - now <= 86400 + 3600, "{when}: {next} - {now}");

            // at `when` after a local midnight
            let local = next + gmtoff(next) * 60;
            assert_eq!(local.rem_euclid(86400), when % 86400, "{when}");
        }
    }

    #[test]
    fn gm() {
        let tm = gmtime(784111777);
        assert_eq!((tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec, tm.wday), (1994, 11, 6, 8, 49, 37, 0));
        assert_eq!(http_time(784111777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_cookie_time(784111777), "Sun, 06-Nov-94 08:49:37 GMT");
        assert_eq!(gmtime(0).year, 1970);
        let tm = gmtime(951782400); // 2000-02-29
        assert_eq!((tm.year, tm.mon, tm.mday), (2000, 2, 29));
    }
}
