//! The gmtime_r(), localtime_r(), localtime(), mktime() and strftime() of
//! glibc 2.35 in the C locale: the local time of the error log, $time_local
//! and the like (ngx_times.c), ngx_next_time(), and the "timefmt" of SSI's
//! $date_local and $date_gmt.  The time zone is glibc's: the TZ variable (a
//! TZif file, or a POSIX TZ string, with the "posixrules" file for the
//! strings without rules), /etc/localtime by default, UTC without it
//! (tzset.c, tzfile.c); %Z needs the abbreviation of the zone.  Leap
//! seconds of the "right/" zones are applied as glibc applies them.
//!
//! As in glibc, localtime_r() and gmtime_r() read the zone once (the first
//! call), localtime(), mktime() and tzset() check the TZ variable and the
//! file again (tzset_internal(always)), reread when they changed: nginx's
//! ngx_timezone_update() calls localtime() at each configuration.

use std::cell::RefCell;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;

/// struct tm, with tm_gmtoff and tm_zone
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Tm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    pub year: i32,
    pub wday: i32,
    pub yday: i32,
    pub isdst: i32,
    pub gmtoff: i64,
    pub zone: Vec<u8>,
}

const SECS_PER_HOUR: i64 = 60 * 60;
const SECS_PER_DAY: i64 = SECS_PER_HOUR * 24;

/// TZDEFAULT, TZDIR, TZDEFRULES
const TZDEFAULT: &[u8] = b"/etc/localtime";
const TZDIR: &[u8] = b"/usr/share/zoneinfo";
const TZDEFRULES: &[u8] = b"posixrules";

/// __mon_yday
const MON_YDAY: [[i64; 13]; 2] = [[0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365], [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366]];

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// __offtime(): the broken-down time of t at offset seconds east of UTC
/// (the fields other than isdst, gmtoff and zone); None if the year does
/// not fit an int.
fn offtime(t: i64, offset: i64, tm: &mut Tm) -> bool {
    let mut days = t / SECS_PER_DAY;
    let mut rem = t % SECS_PER_DAY + offset;

    while rem < 0 {
        rem += SECS_PER_DAY;
        days -= 1;
    }

    while rem >= SECS_PER_DAY {
        rem -= SECS_PER_DAY;
        days += 1;
    }

    tm.hour = (rem / SECS_PER_HOUR) as i32;
    rem %= SECS_PER_HOUR;
    tm.min = (rem / 60) as i32;
    tm.sec = (rem % 60) as i32;

    // January 1, 1970 was a Thursday.
    tm.wday = ((4 + days) % 7) as i32;
    if tm.wday < 0 {
        tm.wday += 7;
    }

    let div = |a: i64, b: i64| a / b - ((a % b < 0) as i64);
    let leaps_thru_end_of = |y: i64| div(y, 4) - div(y, 100) + div(y, 400);

    let mut y: i64 = 1970;

    while days < 0 || days >= if is_leap(y) { 366 } else { 365 } {
        // Guess a corrected year, assuming 365 days per year.
        let yg = y + days / 365 - ((days % 365 < 0) as i64);

        // Adjust DAYS and Y to match the guessed year.
        days -= (yg - y) * 365 + leaps_thru_end_of(yg - 1) - leaps_thru_end_of(y - 1);
        y = yg;
    }

    match i32::try_from(y - 1900) {
        Ok(year) => tm.year = year,
        // The year cannot be represented due to overflow.
        Err(_) => return false,
    }

    tm.yday = days as i32;

    let ip = &MON_YDAY[is_leap(y) as usize];
    let mut m = 11;
    while days < ip[m] {
        m -= 1;
    }

    tm.mon = m as i32;
    tm.mday = (days - ip[m] + 1) as i32;

    true
}

/// struct ttinfo of tzfile.c
#[derive(Clone, Debug)]
struct TtInfo {
    offset: i64,
    isdst: bool,
    idx: usize,
    isstd: bool,
    isgmt: bool,
}

/// A TZif file, as __tzfile_read() keeps it.
#[derive(Clone, Debug)]
struct TzFile {
    transitions: Vec<i64>,
    type_idxs: Vec<usize>,
    types: Vec<TtInfo>,
    zone_names: Vec<u8>,
    /// (transition, change)
    leaps: Vec<(i64, i64)>,
    tzspec: Option<Vec<u8>>,
    rule_stdoff: i64,
    rule_dstoff: i64,
}

impl TzFile {
    /// &zone_names[idx]: the NUL-terminated name
    fn name(&self, idx: usize) -> Vec<u8> {
        let s = self.zone_names.get(idx..).unwrap_or(&[]);
        s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())].to_vec()
    }
}

/// enum { J0, J1, M } of tz_rule
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum RuleType {
    #[default]
    J0,
    J1,
    M,
}

/// tz_rule of tzset.c: tz_rules[0] is standard, tz_rules[1] is daylight
#[derive(Clone, Debug, Default)]
struct TzRule {
    name: Vec<u8>,
    rtype: RuleType,
    m: u16,
    n: u16,
    d: u16,
    secs: i64,
    offset: i64,
}

/// The time zone glibc uses: a file (__use_tzfile) or the rules of a
/// POSIX TZ string (tz_rules).
#[derive(Clone, Debug)]
enum Zone {
    File(TzFile),
    Rules([TzRule; 2]),
}

/// The cached zone: the TZ value it is for and the identity of its file
struct Cache {
    tz: Option<Vec<u8>>,
    file: Option<(u64, u64, i64)>,
    zone: Rc<Zone>,
}

thread_local! {
    static CACHE: RefCell<Option<Cache>> = const { RefCell::new(None) };
    /// localtime_offset of mktime.c
    static LOCALTIME_OFFSET: RefCell<i64> = const { RefCell::new(0) };
}

/// The value of a 4-byte big-endian signed integer (decode())
fn decode(b: &[u8]) -> i64 {
    i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64
}

/// The path of a zone file: relative names are in TZDIR.
fn tzfile_path(file: &[u8]) -> Vec<u8> {
    if file.first() == Some(&b'/') {
        return file.to_vec();
    }

    let tzdir = std::env::var_os("TZDIR").map(|d| d.as_bytes().to_vec()).filter(|d| !d.is_empty()).unwrap_or_else(|| TZDIR.to_vec());

    let mut path = tzdir;
    path.push(b'/');
    path.extend_from_slice(file);
    path
}

/// The identity of the file (dev, ino, mtime) as __tzfile_read() checks
/// it for changes.
fn file_identity(path: &[u8]) -> Option<(u64, u64, i64)> {
    std::fs::metadata(std::ffi::OsStr::from_bytes(path)).ok().map(|m| (m.dev(), m.ino(), m.mtime()))
}

/// __tzfile_read(): the zone of a TZif file, None if it cannot be read
/// (glibc then uses a POSIX TZ string or UTC).
fn tzfile_read(file: &[u8]) -> Option<TzFile> {
    let path = tzfile_path(file);
    let data = std::fs::read(std::ffi::OsStr::from_bytes(&path)).ok()?;

    tzfile_parse(&data)
}

/// The parsing of __tzfile_read()
fn tzfile_parse(data: &[u8]) -> Option<TzFile> {
    struct Reader<'a> {
        d: &'a [u8],
        pos: usize,
    }

    impl Reader<'_> {
        fn take(&mut self, n: usize) -> Option<&[u8]> {
            let end = self.pos.checked_add(n)?;
            let s = self.d.get(self.pos..end)?;
            self.pos = end;
            Some(s)
        }
    }

    let mut r = Reader { d: data, pos: 0 };

    let mut trans_width = 4;

    // the counts of the header: (size_t) decode() of each
    let counts = loop {
        let h = r.take(44)?;

        if &h[..4] != b"TZif" {
            return None;
        }

        let c = |i: usize| decode(&h[20 + 4 * i..]) as usize;

        let (num_isgmt, num_isstd, num_leaps, num_transitions, num_types, chars) = (c(0), c(1), c(2), c(3), c(4), c(5));

        if num_isstd > num_types || num_isgmt > num_types {
            return None;
        }

        if trans_width == 4 && h[4] != 0 {
            // We use the 8-byte format.
            trans_width = 8;

            // Position the stream before the second header.
            let to_skip = num_transitions
                .checked_mul(4 + 1)?
                .checked_add(num_types.checked_mul(6)?)?
                .checked_add(chars)?
                .checked_add(num_leaps.checked_mul(8)?)?
                .checked_add(num_isstd)?
                .checked_add(num_isgmt)?;

            r.take(to_skip)?;

            continue;
        }

        break (num_isgmt, num_isstd, num_leaps, num_transitions, num_types, chars);
    };

    let (num_isgmt, num_isstd, num_leaps, num_transitions, num_types, chars) = counts;

    // Compute the size of the POSIX time zone specification in the file.
    let mut tzspec_len = 0;

    if trans_width == 8 {
        let rem = data.len() - r.pos;
        let fixed = num_transitions.checked_mul(8 + 1)?.checked_add(num_types.checked_mul(6)?)?.checked_add(chars)?;

        tzspec_len = rem.checked_sub(fixed)?;
        tzspec_len = tzspec_len.checked_sub(num_leaps.checked_mul(12)?)?;
        tzspec_len = tzspec_len.checked_sub(num_isstd)?;

        if tzspec_len == 0 || tzspec_len - 1 < num_isgmt {
            return None;
        }

        tzspec_len -= num_isgmt + 1;

        if tzspec_len == 0 {
            return None;
        }
    }

    let mut transitions = Vec::with_capacity(num_transitions.min(data.len()));

    for _ in 0..num_transitions {
        let b = r.take(trans_width)?;
        transitions.push(if trans_width == 4 { decode(b) } else { i64::from_be_bytes(b.try_into().ok()?) });
    }

    let type_idxs: Vec<usize> = r.take(num_transitions)?.iter().map(|&i| i as usize).collect();

    // Check for bogus indices in the data file.
    if type_idxs.iter().any(|&i| i >= num_types) {
        return None;
    }

    let mut types = Vec::with_capacity(num_types.min(data.len()));

    for _ in 0..num_types {
        let b = r.take(6)?;

        if b[4] > 1 {
            return None;
        }

        if b[5] as usize > chars {
            // Bogus index in data file.
            return None;
        }

        types.push(TtInfo { offset: decode(b), isdst: b[4] != 0, idx: b[5] as usize, isstd: false, isgmt: false });
    }

    let zone_names = r.take(chars)?.to_vec();

    let mut leaps = Vec::with_capacity(num_leaps.min(data.len()));

    for _ in 0..num_leaps {
        let b = r.take(trans_width)?;
        let transition = if trans_width == 4 { decode(b) } else { i64::from_be_bytes(b.try_into().ok()?) };
        let change = decode(r.take(4)?);
        leaps.push((transition, change));
    }

    for t in types.iter_mut().take(num_isstd) {
        t.isstd = r.take(1)?[0] != 0;
    }

    for t in types.iter_mut().take(num_isgmt) {
        t.isgmt = r.take(1)?[0] != 0;
    }

    // Read the POSIX TZ-style information if possible.
    let mut tzspec = None;

    if tzspec_len > 0 {
        // Skip over the newline first.
        if r.take(1).is_some_and(|c| c[0] == b'\n') {
            if let Some(s) = r.take(tzspec_len - 1) {
                tzspec = Some(s.to_vec());
            }
        }
    }

    // Don't use an empty TZ string.
    if tzspec.as_ref().is_some_and(|s| s.is_empty() || s[0] == 0) {
        tzspec = None;
    }

    // the TZ string ends at a NUL
    if let Some(s) = tzspec.as_mut() {
        if let Some(n) = s.iter().position(|&c| c == 0) {
            s.truncate(n);
        }
    }

    let mut f = TzFile { transitions, type_idxs, types, zone_names, leaps, tzspec, rule_stdoff: 0, rule_dstoff: 0 };

    if f.types.is_empty() {
        // glibc reads types[0] then: the file is broken
        return None;
    }

    if f.transitions.is_empty() {
        // Use the first rule (which should also be the only one).
        f.rule_stdoff = f.types[0].offset;
        f.rule_dstoff = f.types[0].offset;
    } else {
        let mut stdoff_set = false;
        let mut dstoff_set = false;

        for &ti in f.type_idxs.iter().rev() {
            let t = &f.types[ti];

            if !stdoff_set && !t.isdst {
                stdoff_set = true;
                f.rule_stdoff = t.offset;
            } else if !dstoff_set && t.isdst {
                dstoff_set = true;
                f.rule_dstoff = t.offset;
            }

            if stdoff_set && dstoff_set {
                break;
            }
        }

        if !dstoff_set {
            f.rule_dstoff = f.rule_stdoff;
        }
    }

    Some(f)
}

/// isspace() in the C locale
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// One "%hu" of sscanf(): whitespace, an optional sign, digits (strtoul
/// to unsigned short); the value and the position after it.
fn scan_hu(s: &[u8], mut pos: usize) -> Option<(u16, usize)> {
    while s.get(pos).copied().is_some_and(is_space) {
        pos += 1;
    }

    let neg = match s.get(pos) {
        Some(b'-') => {
            pos += 1;
            true
        }
        Some(b'+') => {
            pos += 1;
            false
        }
        _ => false,
    };

    let start = pos;
    let mut v: u64 = 0;
    let mut overflow = false;

    while let Some(&c) = s.get(pos).filter(|c| c.is_ascii_digit()) {
        match v.checked_mul(10).and_then(|v| v.checked_add((c - b'0') as u64)) {
            Some(n) => v = n,
            None => overflow = true,
        }
        pos += 1;
    }

    if pos == start {
        return None;
    }

    let v = if overflow {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    };

    Some((v as u16, pos))
}

/// sscanf (tz, "%hu%n:%hu%n:%hu%n", &hh, &consumed, &mm, &consumed, &ss,
/// &consumed): the number of conversions, the values (hh, mm and ss keep
/// what they were given for those not converted) and consumed.
fn scan_hms(s: &[u8], hh: &mut u16, mm: &mut u16, ss: &mut u16, consumed: &mut usize) -> usize {
    let (v, p) = match scan_hu(s, 0) {
        Some(x) => x,
        None => return 0,
    };

    *hh = v;
    *consumed = p;

    if s.get(p) != Some(&b':') {
        return 1;
    }

    let (v, p) = match scan_hu(s, p + 1) {
        Some(x) => x,
        None => return 1,
    };

    *mm = v;
    *consumed = p;

    if s.get(p) != Some(&b':') {
        return 2;
    }

    let (v, p) = match scan_hu(s, p + 1) {
        Some(x) => x,
        None => return 2,
    };

    *ss = v;
    *consumed = p;

    3
}

/// compute_offset()
fn compute_offset(ss: u16, mm: u16, hh: u16) -> i64 {
    ss.min(59) as i64 + mm.min(59) as i64 * 60 + hh.min(24) as i64 * 60 * 60
}

/// The parsing of a POSIX TZ string (__tzset_parse_tz()): the rules, or
/// the zone of the TZDEFRULES file for a string with a DST name and no
/// rules (__tzfile_default()).
fn tzset_parse_tz(tz: &[u8]) -> Zone {
    let mut rules: [TzRule; 2] = Default::default();
    let mut p = 0;

    let at = |p: usize| tz.get(p).copied().unwrap_or(0);

    // parse_tzname()
    let parse_tzname = |p: &mut usize, rule: &mut TzRule| -> bool {
        let start = *p;
        let mut q = start;

        while at(q).is_ascii_alphabetic() {
            q += 1;
        }

        let (s, e, end) = if q - start < 3 {
            let mut q = *p;

            if at(q) != b'<' {
                return false;
            }

            q += 1;
            let start = q;

            while at(q).is_ascii_alphanumeric() || at(q) == b'+' || at(q) == b'-' {
                q += 1;
            }

            if at(q) != b'>' || q - start < 3 {
                return false;
            }

            (start, q, q + 1)
        } else {
            (start, q, q)
        };

        rule.name = tz[s..e].to_vec();
        *p = end;

        true
    };

    // parse_offset()
    let parse_offset = |p: &mut usize, rules: &mut [TzRule; 2], which: usize| -> bool {
        let c = at(*p);

        if which == 0 && (c == 0 || (c != b'+' && c != b'-' && !c.is_ascii_digit())) {
            return false;
        }

        let sign: i64 = if c == b'-' || c == b'+' {
            *p += 1;
            if c == b'-' {
                1
            } else {
                -1
            }
        } else {
            -1
        };

        let (mut hh, mut mm, mut ss, mut consumed) = (0u16, 0u16, 0u16, 0usize);

        if scan_hms(&tz[(*p).min(tz.len())..], &mut hh, &mut mm, &mut ss, &mut consumed) > 0 {
            rules[which].offset = sign * compute_offset(ss, mm, hh);
        } else if which == 0 {
            // Standard time defaults to offset zero.
            rules[0].offset = 0;
            return false;
        } else {
            // DST defaults to one hour later than standard time.
            rules[1].offset = rules[0].offset + 60 * 60;
        }

        *p += consumed;

        true
    };

    // parse_rule()
    let parse_rule = |p: &mut usize, rule: &mut TzRule, which: usize| -> bool {
        let mut q = *p;

        // Ignore comma to support string following the incorrect
        // specification in early POSIX.1 printings.
        if at(q) == b',' {
            q += 1;
        }

        // Get the date of the change.
        if at(q) == b'J' || at(q).is_ascii_digit() {
            rule.rtype = if at(q) == b'J' { RuleType::J1 } else { RuleType::J0 };

            if rule.rtype == RuleType::J1 {
                q += 1;
                if !at(q).is_ascii_digit() {
                    return false;
                }
            }

            let n = tz[q..].iter().take_while(|c| c.is_ascii_digit()).count();
            let d = tz[q..q + n].iter().try_fold(0u64, |v, &c| v.checked_mul(10)?.checked_add((c - b'0') as u64)).unwrap_or(u64::MAX);

            if n == 0 || d > 365 {
                return false;
            }

            if rule.rtype == RuleType::J1 && d == 0 {
                return false;
            }

            rule.d = d as u16;
            q += n;
        } else if at(q) == b'M' {
            rule.rtype = RuleType::M;

            // sscanf (tz, "M%hu.%hu.%hu%n", ...) == 3: it stores the
            // values it converts, before the range checks
            let mut converted = 0;
            let mut end = q;

            if let Some((m, r1)) = scan_hu(tz, q + 1) {
                rule.m = m;
                converted = 1;

                if at(r1) == b'.' {
                    if let Some((n, r2)) = scan_hu(tz, r1 + 1) {
                        rule.n = n;
                        converted = 2;

                        if at(r2) == b'.' {
                            if let Some((d, r3)) = scan_hu(tz, r2 + 1) {
                                rule.d = d;
                                converted = 3;
                                end = r3;
                            }
                        }
                    }
                }
            }

            if converted != 3 || rule.m < 1 || rule.m > 12 || rule.n < 1 || rule.n > 5 || rule.d > 6 {
                return false;
            }

            q = end;
        } else if at(q) == 0 {
            // the U.S. rules: "M3.2.0,M11.1.0"
            rule.rtype = RuleType::M;

            if which == 0 {
                rule.m = 3;
                rule.n = 2;
                rule.d = 0;
            } else {
                rule.m = 11;
                rule.n = 1;
                rule.d = 0;
            }
        } else {
            return false;
        }

        if at(q) != 0 && at(q) != b'/' && at(q) != b',' {
            return false;
        } else if at(q) == b'/' {
            // Get the time of day of the change.
            q += 1;

            if at(q) == 0 {
                return false;
            }

            let negative = at(q) == b'-';
            if negative {
                q += 1;
            }

            // Default to 2:00 AM.
            let (mut hh, mut mm, mut ss, mut consumed) = (2u16, 0u16, 0u16, 0usize);
            scan_hms(&tz[q.min(tz.len())..], &mut hh, &mut mm, &mut ss, &mut consumed);
            q += consumed;

            rule.secs = (if negative { -1 } else { 1 }) * (hh as i64 * 60 * 60 + mm as i64 * 60 + ss as i64);
        } else {
            // Default to 2:00 AM.
            rule.secs = 2 * 60 * 60;
        }

        *p = q;

        true
    };

    // Get the standard timezone name.
    if parse_tzname(&mut p, &mut rules[0]) && parse_offset(&mut p, &mut rules, 0) {
        // Get the DST timezone name (if any).
        if at(p) != 0 {
            if parse_tzname(&mut p, &mut rules[1]) {
                parse_offset(&mut p, &mut rules, 1);

                if at(p) == 0 || (at(p) == b',' && at(p + 1) == 0) {
                    // There is no rule.  See if there is a default rule
                    // file.
                    if let Some(f) = tzfile_default(&rules) {
                        return Zone::File(f);
                    }
                }
            }

            // Figure out the standard <-> DST rules.
            let (r0, r1) = rules.split_at_mut(1);
            if parse_rule(&mut p, &mut r0[0], 0) {
                parse_rule(&mut p, &mut r1[0], 1);
            }
        } else {
            // There is no DST.
            rules[1].name = rules[0].name.clone();
            rules[1].offset = rules[0].offset;
        }
    }

    Zone::Rules(rules)
}

/// __tzfile_default(): the transitions of the TZDEFRULES file with the
/// names and offsets of the TZ string.
fn tzfile_default(rules: &[TzRule; 2]) -> Option<TzFile> {
    let mut f = tzfile_read(TZDEFRULES)?;

    if f.types.len() < 2 {
        return None;
    }

    let (stdoff, dstoff) = (rules[0].offset, rules[1].offset);

    // Ignore the zone names read from the file and use the given ones
    // instead.
    let mut zone_names = rules[0].name.clone();
    zone_names.push(0);
    let dst_idx = zone_names.len();
    zone_names.extend_from_slice(&rules[1].name);
    zone_names.push(0);

    // Now correct the transition times for the user-specified standard and
    // daylight offsets from GMT.
    let mut isdst = false;

    for i in 0..f.transitions.len() {
        let trans_type = f.types[f.type_idxs[i]].clone();

        // We will use only types 0 (standard) and 1 (daylight).
        f.type_idxs[i] = trans_type.isdst as usize;

        if trans_type.isgmt {
            // The transition time is in GMT.  No correction to apply.
        } else if isdst && !trans_type.isstd {
            f.transitions[i] += dstoff - f.rule_dstoff;
        } else {
            f.transitions[i] += stdoff - f.rule_stdoff;
        }

        isdst = trans_type.isdst;
    }

    f.rule_stdoff = stdoff;
    f.rule_dstoff = dstoff;

    // Now there are only two zones, regardless of what the file contained.
    f.types.truncate(2);
    f.types[0] = TtInfo { offset: stdoff, isdst: false, idx: 0, isstd: f.types[0].isstd, isgmt: f.types[0].isgmt };
    f.types[1] = TtInfo { offset: dstoff, isdst: true, idx: dst_idx, isstd: f.types[1].isstd, isgmt: f.types[1].isgmt };

    f.zone_names = zone_names;

    Some(f)
}

/// tzset(): the zone of the TZ variable read again if it changed
pub fn tzset() {
    tzset_internal(true);
}

/// tzset_internal(): the zone of the TZ variable, cached; unless `always`,
/// the cached zone as it is
fn tzset_internal(always: bool) -> Rc<Zone> {
    if !always {
        if let Some(zone) = CACHE.with(|c| c.borrow().as_ref().map(|c| c.zone.clone())) {
            return zone;
        }
    }

    let tz: Option<Vec<u8>> = std::env::var_os("TZ").map(|v| {
        let v = v.as_bytes();

        if v.is_empty() {
            // User specified the empty string; use UTC explicitly.
            b"Universal".to_vec()
        } else if v[0] == b':' {
            // A leading colon means "implementation defined syntax".
            v[1..].to_vec()
        } else {
            v.to_vec()
        }
    });

    let file = tz.clone().unwrap_or_else(|| TZDEFAULT.to_vec());
    let identity = if file.is_empty() { None } else { file_identity(&tzfile_path(&file)) };

    let cached = CACHE.with(|c| c.borrow().as_ref().filter(|c| c.tz == tz && c.file == identity).map(|c| c.zone.clone()));

    if let Some(zone) = cached {
        return zone;
    }

    let zone = match if file.is_empty() { None } else { tzfile_read(&file) } {
        Some(f) => Zone::File(f),

        None => {
            if file.is_empty() || file == TZDEFAULT {
                // No data file found.  Default to UTC if nothing
                // specified.
                let utc = TzRule { name: b"UTC".to_vec(), ..Default::default() };
                Zone::Rules([utc.clone(), utc])
            } else {
                tzset_parse_tz(&file)
            }
        }
    };

    let zone = Rc::new(zone);

    CACHE.with(|c| *c.borrow_mut() = Some(Cache { tz, file: identity, zone: zone.clone() }));

    zone
}

/// compute_change(): when the change of a rule happens in a year
fn compute_change(rule: &TzRule, year: i64) -> i64 {
    // First set T to January 1st, 0:00:00 GMT in YEAR.
    let mut t = if year > 1970 {
        ((year - 1970) * 365 + ((year - 1) / 4 - 1970 / 4) - ((year - 1) / 100 - 1970 / 100) + ((year - 1) / 400 - 1970 / 400)) * SECS_PER_DAY
    } else {
        0
    };

    match rule.rtype {
        RuleType::J1 => {
            // Jn - Julian day, 1 == January 1, 60 == March 1 even in leap
            // years.
            t += (rule.d as i64 - 1) * SECS_PER_DAY;
            if rule.d >= 60 && is_leap(year) {
                t += SECS_PER_DAY;
            }
        }

        RuleType::J0 => {
            // n - Day of year.
            t += rule.d as i64 * SECS_PER_DAY;
        }

        RuleType::M => {
            // Mm.n.d - Nth "Dth day" of month M.  (A rule whose month
            // failed the checks is used too: C reads __mon_yday out of
            // its row, or out of the array, read as 0 here.)
            let base = is_leap(year) as i64 * 13 + rule.m as i64;
            let mon_yday = |i: i64| usize::try_from(i).ok().and_then(|i| MON_YDAY.as_flattened().get(i)).copied().unwrap_or(0);

            // myday[-1], myday[0]
            let (before, after) = (mon_yday(base - 1), mon_yday(base));

            // First add SECSPERDAY for each day in months before M.
            t += before * SECS_PER_DAY;

            // Use Zeller's Congruence to get day-of-week of first day of
            // month.
            let m1 = (rule.m as i64 + 9) % 12 + 1;
            let yy0 = if rule.m <= 2 { year - 1 } else { year };
            let yy1 = yy0 / 100;
            let yy2 = yy0 % 100;
            let mut dow = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
            if dow < 0 {
                dow += 7;
            }

            // DOW is the day-of-week of the first day of the month.  Get
            // the day-of-month (zero-origin) of the first DOW day of the
            // month.
            let mut d = rule.d as i64 - dow;
            if d < 0 {
                d += 7;
            }

            for _ in 1..rule.n {
                if d + 7 >= after - before {
                    break;
                }
                d += 7;
            }

            // D is the day-of-month (zero-origin) of the day we want.
            t += d * SECS_PER_DAY;
        }
    }

    // T is now the Epoch-relative time of 0:00:00 GMT on the day we want.
    // Just add the time of day and local offset from GMT, and we're done.
    t - rule.offset + rule.secs
}

/// __tz_compute() with use_localtime: isdst, zone and gmtoff of the rules
fn tz_compute(rules: &[TzRule; 2], timer: i64, tm: &mut Tm) {
    let year = 1900 + tm.year as i64;
    let change0 = compute_change(&rules[0], year);
    let change1 = compute_change(&rules[1], year);

    // We have to distinguish between northern and southern hemisphere.
    // For the latter the daylight saving time ends in the next year.
    let isdst = if change0 > change1 { timer < change1 || timer >= change0 } else { timer >= change0 && timer < change1 };

    tm.isdst = isdst as i32;
    tm.zone = rules[isdst as usize].name.clone();
    tm.gmtoff = rules[isdst as usize].offset;
}

/// __tzfile_compute(): isdst, zone and gmtoff (with use_localtime), the
/// leap second correction and hits
fn tzfile_compute(f: &TzFile, timer: i64, use_localtime: bool, tm: &mut Tm) -> (i64, i32) {
    if use_localtime {
        let n = f.transitions.len();

        let i = if n == 0 || timer < f.transitions[0] {
            // TIMER is before any transition (or there are no
            // transitions).  Choose the first non-DST type (or the first if
            // they're all DST types).
            f.types.iter().position(|t| !t.isdst).unwrap_or(0)
        } else if timer >= f.transitions[n - 1] {
            match &f.tzspec {
                None => f.type_idxs[n - 1],

                Some(spec) => {
                    // Parse the POSIX TZ-style string.  (glibc's override
                    // of the names with the ones of a TZ string without
                    // rules compares the names with the end of the leap
                    // seconds, which never holds since glibc 2.28: no
                    // override.)
                    let rules = match tzset_parse_tz(spec) {
                        Zone::Rules(r) => Some(r),
                        // a footer without rules and the posixrules file:
                        // glibc replaces the zone by it; use the rules
                        // the parsing would use without the file
                        Zone::File(_) => None,
                    };

                    let mut utc = Tm::default();

                    match rules {
                        Some(rules) if offtime(timer, 0, &mut utc) => {
                            tz_compute(&rules, timer, &mut utc);
                            tm.isdst = utc.isdst;
                            tm.zone = utc.zone;
                            tm.gmtoff = utc.gmtoff;

                            return leap_correction(f, timer);
                        }

                        _ => f.type_idxs[n - 1],
                    }
                }
            }
        } else {
            // Find the first transition after TIMER, and then pick the
            // type of the transition before it.
            let after = f.transitions.partition_point(|&t| t <= timer);
            f.type_idxs[after - 1]
        };

        let info = &f.types[i];

        tm.isdst = info.isdst as i32;
        tm.zone = f.name(info.idx);
        tm.gmtoff = info.offset;
    }

    leap_correction(f, timer)
}

/// The leap part of __tzfile_compute()
fn leap_correction(f: &TzFile, timer: i64) -> (i64, i32) {
    // Find the last leap second correction transition time before TIMER.
    let mut i = f.leaps.len();

    loop {
        if i == 0 {
            return (0, 0);
        }

        i -= 1;

        if timer >= f.leaps[i].0 {
            break;
        }
    }

    // Apply its correction.
    let correct = f.leaps[i].1;
    let mut hit = 0;

    if timer == f.leaps[i].0 && f.leaps[i].1 > if i == 0 { 0 } else { f.leaps[i - 1].1 } {
        hit = 1;

        while i > 0 && f.leaps[i].0 == f.leaps[i - 1].0 + 1 && f.leaps[i].1 == f.leaps[i - 1].1 + 1 {
            hit += 1;
            i -= 1;
        }
    }

    (correct, hit)
}

/// __tz_convert(): `always` as the call of tzset_internal() it makes
fn tz_convert(timer: i64, use_localtime: bool, always: bool) -> Option<Tm> {
    let zone = tzset_internal(always);
    let mut tm = Tm::default();

    let (leap_correction, leap_extra_secs) = match &*zone {
        Zone::File(f) => tzfile_compute(f, timer, use_localtime, &mut tm),

        Zone::Rules(rules) => {
            if !offtime(timer, 0, &mut tm) {
                return None;
            }

            if use_localtime {
                tz_compute(rules, timer, &mut tm);
            }

            (0, 0)
        }
    };

    if !use_localtime {
        tm.isdst = 0;
        tm.zone = b"GMT".to_vec();
        tm.gmtoff = 0;
    }

    if !offtime(timer, tm.gmtoff - leap_correction, &mut tm) {
        return None;
    }

    tm.sec += leap_extra_secs;

    Some(tm)
}

/// localtime_r(): the zone as it was read first
pub fn localtime_r(t: i64) -> Option<Tm> {
    tz_convert(t, true, false)
}

/// localtime(): the zone read again if it changed
pub fn localtime(t: i64) -> Option<Tm> {
    tz_convert(t, true, true)
}

/// gmtime_r()
pub fn gmtime(t: i64) -> Option<Tm> {
    tz_convert(t, false, false)
}

/// shr() of mktime.c
fn shr(a: i64, b: u32) -> i64 {
    a >> b
}

/// ydhms_diff()
fn ydhms_diff(year1: i64, yday1: i64, hour1: i64, min1: i64, sec1: i64, year0: i64, yday0: i64, hour0: i64, min0: i64, sec0: i64) -> i64 {
    const TM_YEAR_BASE: i64 = 1900;

    // Compute intervening leap days correctly even if year is negative.
    let a4 = shr(year1, 2) + shr(TM_YEAR_BASE, 2) - ((year1 & 3 == 0) as i64);
    let b4 = shr(year0, 2) + shr(TM_YEAR_BASE, 2) - ((year0 & 3 == 0) as i64);
    let a100 = (a4 + (a4 < 0) as i64) / 25 - (a4 < 0) as i64;
    let b100 = (b4 + (b4 < 0) as i64) / 25 - (b4 < 0) as i64;
    let a400 = shr(a100, 2);
    let b400 = shr(b100, 2);
    let intervening_leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);

    // Compute the desired time without overflowing.
    let years = year1 - year0;
    let days = 365 * years + yday1 - yday0 + intervening_leap_days;
    let hours = 24 * days + hour1 - hour0;
    let minutes = 60 * hours + min1 - min0;
    60 * minutes + sec1 - sec0
}

/// isdst_differ()
fn isdst_differ(a: i32, b: i32) -> bool {
    ((a == 0) != (b == 0)) && 0 <= a && 0 <= b
}

/// mktime(): the time of the broken-down local time, -1 if there is none;
/// *tp normalized as C does (the zone checked by tzset() first, then
/// __mktime_internal() with localtime_r)
pub fn mktime(tp: &mut Tm) -> i64 {
    tzset();

    match mktime_internal(tp) {
        Some((t, tm)) => {
            *tp = tm;
            t
        }
        None => -1,
    }
}

/// __mktime_internal(): the time and its broken-down local time
fn mktime_internal(tp: &Tm) -> Option<(i64, Tm)> {
    const EPOCH_YEAR: i64 = 1970;
    const TM_YEAR_BASE: i64 = 1900;

    // the conversion with the range checks of ranged_convert(): localtime
    // fails only when the year overflows an int, far outside the times
    // this is used for
    let convert = |t: i64| localtime_r(t);

    let mut remaining_probes = 6;

    let mut sec = tp.sec as i64;
    let min = tp.min as i64;
    let hour = tp.hour as i64;
    let mday = tp.mday as i64;
    let mon = tp.mon as i64;
    let year_requested = tp.year as i64;
    let isdst = tp.isdst;

    // 1 if the previous probe was DST.
    let mut dst2 = false;

    // Ensure that mon is in range, and set year accordingly.
    let mon_remainder = mon % 12;
    let negative_mon_remainder = mon_remainder < 0;
    let mon_years = mon / 12 - negative_mon_remainder as i64;
    let year = year_requested + mon_years;

    // Calculate day of year from year, month, and day of month.
    let mon_yday = MON_YDAY[is_leap(year + TM_YEAR_BASE) as usize][(mon_remainder + 12 * negative_mon_remainder as i64) as usize] - 1;
    let yday = mon_yday + mday;

    let off = LOCALTIME_OFFSET.with(|o| *o.borrow());
    let negative_offset_guess = 0i64.wrapping_sub(off);

    let sec_requested = sec;

    // Handle out-of-range seconds specially, since ydhms_diff assumes
    // every minute has 60 seconds.
    sec = sec.clamp(0, 59);

    // Invert CONVERT by probing.  First assume the same offset as last
    // time.
    let t0 = ydhms_diff(year, yday, hour, min, sec, EPOCH_YEAR - TM_YEAR_BASE, 0, 0, 0, negative_offset_guess);
    let mut t = t0;
    let mut t1 = t0;
    let mut t2 = t0;

    let tm_diff = |tm: &Tm| ydhms_diff(year, yday, hour, min, sec, tm.year as i64, tm.yday as i64, tm.hour as i64, tm.min as i64, tm.sec as i64);

    let mut tm;

    // Repeatedly use the error to improve the guess.
    loop {
        tm = match convert(t) {
            Some(tm) => tm,
            None => return None,
        };

        let dt = tm_diff(&tm);

        if dt == 0 {
            break;
        }

        if t == t1 && t != t2 && (tm.isdst < 0 || if isdst < 0 { dst2 <= (tm.isdst != 0) } else { (isdst != 0) != (tm.isdst != 0) }) {
            // We can't possibly find a match, as we are oscillating
            // between two values.
            return offset_found(t, t0, negative_offset_guess, sec, sec_requested, tm);
        }

        remaining_probes -= 1;

        if remaining_probes == 0 {
            return None;
        }

        t1 = t2;
        t2 = t;
        t = t.wrapping_add(dt);
        dst2 = tm.isdst != 0;
    }

    // We have a match.  Check whether tm.tm_isdst has the requested value,
    // if any.
    if isdst_differ(isdst, tm.isdst) {
        // tm.tm_isdst has the wrong value.  Look for a neighboring time
        // with the right value, and use its UTC offset.
        let stride: i64 = 601200;
        let duration_max: i64 = 536454000;
        let delta_bound = duration_max / 2 + stride;

        let mut delta = stride;

        while delta < delta_bound {
            for direction in [-1i64, 1] {
                if let Some(ot) = t.checked_add(delta * direction) {
                    let otm = match convert(ot) {
                        Some(otm) => otm,
                        None => return None,
                    };

                    if !isdst_differ(isdst, otm.isdst) {
                        // We found the desired tm_isdst.  Extrapolate back
                        // to the desired time.
                        let gt = ot + tm_diff(&otm);

                        if let Some(gtm) = convert(gt) {
                            return offset_found(gt, t0, negative_offset_guess, sec, sec_requested, gtm);
                        }
                    }
                }
            }

            delta += stride;
        }

        return None;
    }

    offset_found(t, t0, negative_offset_guess, sec, sec_requested, tm)
}

/// The offset_found part of __mktime_internal()
fn offset_found(mut t: i64, t0: i64, negative_offset_guess: i64, sec: i64, sec_requested: i64, mut tm: Tm) -> Option<(i64, Tm)> {
    // Set *OFFSET to the low-order bits of T - T0 - NEGATIVE_OFFSET_GUESS.
    LOCALTIME_OFFSET.with(|o| *o.borrow_mut() = t.wrapping_sub(t0).wrapping_sub(negative_offset_guess));

    if sec_requested != tm.sec as i64 {
        // Adjust time to reflect the tm_sec requested, not the normalized
        // value.  Also, repair any damage from a false match due to a leap
        // second.
        let mut sec_adjustment = (sec == 0 && tm.sec == 60) as i64;
        sec_adjustment -= sec;
        sec_adjustment += sec_requested;

        t = t.checked_add(sec_adjustment)?;

        tm = localtime_r(t)?;
    }

    Some((t, tm))
}

/// The names of the C locale (LC_TIME of glibc's C locale)
const ABDAY: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const DAY: [&[u8]; 7] = [b"Sunday", b"Monday", b"Tuesday", b"Wednesday", b"Thursday", b"Friday", b"Saturday"];
const ABMON: [&[u8]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];
const MON: [&[u8]; 12] = [b"January", b"February", b"March", b"April", b"May", b"June", b"July", b"August", b"September", b"October", b"November", b"December"];
const D_T_FMT: &[u8] = b"%a %b %e %H:%M:%S %Y";
const D_FMT: &[u8] = b"%m/%d/%y";
const T_FMT: &[u8] = b"%H:%M:%S";
const T_FMT_AMPM: &[u8] = b"%I:%M:%S %p";

/// iso_week_days()
fn iso_week_days(yday: i32, wday: i32) -> i32 {
    // Add enough to the first operand of % to make it nonnegative.
    const ISO_WEEK_START_WDAY: i32 = 1; // Monday
    const ISO_WEEK1_WDAY: i32 = 4; // Thursday
    const YDAY_MINIMUM: i32 = -366;
    let big_enough_multiple_of_7 = (-YDAY_MINIMUM / 7 + 2) * 7;
    yday - (yday - wday + ISO_WEEK1_WDAY + big_enough_multiple_of_7) % 7 + ISO_WEEK1_WDAY - ISO_WEEK_START_WDAY
}

/// strftime(): the formatted time, empty when strftime() returns 0 (the
/// result and its NUL do not fit in maxsize bytes, or the result is
/// empty).
pub fn strftime(maxsize: usize, format: &[u8], tm: &Tm) -> Vec<u8> {
    let mut out = Vec::new();

    match strftime_internal(&mut out, maxsize, format, tm) {
        Some(_) => out,
        None => Vec::new(),
    }
}

/// __strftime_internal(): appends the result to p, its length or None (0)
fn strftime_internal(p: &mut Vec<u8>, maxsize: usize, format: &[u8], tp: &Tm) -> Option<usize> {
    let start = p.len();
    let mut i: usize = 0;

    let mut hour12 = tp.hour;
    if hour12 > 12 {
        hour12 -= 12;
    } else if hour12 == 0 {
        hour12 = 12;
    }

    let a_wkday: &[u8] = if (0..=6).contains(&tp.wday) { ABDAY[tp.wday as usize] } else { b"?" };
    let f_wkday: &[u8] = if (0..=6).contains(&tp.wday) { DAY[tp.wday as usize] } else { b"?" };
    let a_month: &[u8] = if (0..=11).contains(&tp.mon) { ABMON[tp.mon as usize] } else { b"?" };
    let f_month: &[u8] = if (0..=11).contains(&tp.mon) { MON[tp.mon as usize] } else { b"?" };
    let ampm: &[u8] = if tp.hour > 11 { b"PM" } else { b"AM" };

    let fmt = |k: usize| format.get(k).copied().unwrap_or(0);

    let mut f = 0;

    while fmt(f) != 0 {
        let mut pad: u8 = 0;
        let modifier: u8;
        let mut width: i64 = -1;
        let mut to_lowcase = false;
        let mut to_uppcase = false;
        let mut change_case = false;

        // add(n, f): the n bytes of s, padded to width
        macro_rules! add {
            ($s:expr) => {{
                let s: &[u8] = $s;
                let n = s.len() as i64;
                let delta = width - n;
                let incr = (n + delta.max(0)) as usize;

                if incr >= maxsize - i {
                    return None;
                }

                if delta > 0 {
                    let c = if pad == b'0' { b'0' } else { b' ' };
                    p.extend(std::iter::repeat(c).take(delta as usize));
                }

                if to_lowcase {
                    p.extend(s.iter().map(|c| c.to_ascii_lowercase()));
                } else if to_uppcase {
                    p.extend(s.iter().map(|c| c.to_ascii_uppercase()));
                } else {
                    p.extend_from_slice(s);
                }

                i += incr;
            }};
        }

        if fmt(f) != b'%' {
            to_lowcase = false;
            to_uppcase = false;
            add!(&[fmt(f)]);
            f += 1;
            continue;
        }

        let percent = f;

        // Check for flags that can modify a format.
        loop {
            f += 1;
            match fmt(f) {
                // This influences the number formats.
                b'_' | b'-' | b'0' => pad = fmt(f),
                // This changes textual output.
                b'^' => to_uppcase = true,
                b'#' => change_case = true,
                _ => break,
            }
        }

        // As a GNU extension we allow to specify the field width.
        if fmt(f).is_ascii_digit() {
            width = 0;
            loop {
                let d = (fmt(f) - b'0') as i64;
                if width > i32::MAX as i64 / 10 || (width == i32::MAX as i64 / 10 && d > i32::MAX as i64 % 10) {
                    // Avoid overflow.
                    width = i32::MAX as i64;
                } else {
                    width = width * 10 + d;
                }
                f += 1;
                if !fmt(f).is_ascii_digit() {
                    break;
                }
            }
        }

        // Check for modifiers.
        match fmt(f) {
            b'E' | b'O' => {
                modifier = fmt(f);
                f += 1;
            }
            _ => modifier = 0,
        }

        // the number to format: (digits, value, space padding)
        let mut number: Option<(i64, i64, bool)> = None;
        // a subformat
        let mut subfmt: Option<&[u8]> = None;
        let mut bad_format = false;

        let format_char = fmt(f);

        match format_char {
            b'%' => {
                if modifier != 0 {
                    bad_format = true;
                } else {
                    add!(b"%");
                }
            }

            b'a' => {
                if modifier != 0 {
                    bad_format = true;
                } else {
                    if change_case {
                        to_uppcase = true;
                        to_lowcase = false;
                    }
                    add!(a_wkday);
                }
            }

            b'A' => {
                if modifier != 0 {
                    bad_format = true;
                } else {
                    if change_case {
                        to_uppcase = true;
                        to_lowcase = false;
                    }
                    add!(f_wkday);
                }
            }

            b'b' | b'h' => {
                if change_case {
                    to_uppcase = true;
                    to_lowcase = false;
                }
                if modifier == b'E' {
                    bad_format = true;
                } else {
                    // the alternative month names of the C locale are the
                    // month names
                    add!(a_month);
                }
            }

            b'B' => {
                if modifier == b'E' {
                    bad_format = true;
                } else {
                    if change_case {
                        to_uppcase = true;
                        to_lowcase = false;
                    }
                    add!(f_month);
                }
            }

            b'c' => {
                if modifier == b'O' {
                    bad_format = true;
                } else {
                    // ERA_D_T_FMT is empty in the C locale
                    subfmt = Some(D_T_FMT);
                }
            }

            b'C' => {
                // %EC: no era in the C locale
                let year = tp.year as i64 + 1900;
                number = Some((1, year / 100 - (year % 100 < 0) as i64, false));
            }

            b'x' => {
                if modifier == b'O' {
                    bad_format = true;
                } else {
                    subfmt = Some(D_FMT);
                }
            }

            b'D' => {
                if modifier != 0 {
                    bad_format = true;
                } else {
                    subfmt = Some(b"%m/%d/%y");
                }
            }

            b'd' => {
                if modifier == b'E' {
                    bad_format = true;
                } else {
                    number = Some((2, tp.mday as i64, false));
                }
            }

            b'e' => {
                if modifier == b'E' {
                    bad_format = true;
                } else {
                    number = Some((2, tp.mday as i64, true));
                }
            }

            b'F' => {
                if modifier != 0 {
                    bad_format = true;
                } else {
                    subfmt = Some(b"%Y-%m-%d");
                }
            }

            b'H' | b'I' | b'k' | b'l' | b'j' | b'M' | b'm' | b'S' | b'U' | b'W' | b'w' => {
                if modifier == b'E' {
                    bad_format = true;
                } else {
                    number = Some(match format_char {
                        b'H' => (2, tp.hour as i64, false),
                        b'I' => (2, hour12 as i64, false),
                        b'k' => (2, tp.hour as i64, true),
                        b'l' => (2, hour12 as i64, true),
                        b'j' => (3, 1 + tp.yday as i64, false),
                        b'M' => (2, tp.min as i64, false),
                        b'm' => (2, tp.mon as i64 + 1, false),
                        b'S' => (2, tp.sec as i64, false),
                        b'U' => (2, ((tp.yday - tp.wday + 7) / 7) as i64, false),
                        b'W' => (2, ((tp.yday - (tp.wday - 1 + 7) % 7 + 7) / 7) as i64, false),
                        _ => (1, tp.wday as i64, false),
                    });
                }
            }

            b'n' => add!(b"\n"),

            b'P' | b'p' => {
                if format_char == b'P' {
                    to_lowcase = true;
                }
                if change_case {
                    to_uppcase = false;
                    to_lowcase = true;
                }
                add!(ampm);
            }

            b'R' => subfmt = Some(b"%H:%M"),

            b'r' => subfmt = Some(T_FMT_AMPM),

            b's' => {
                // mktime() of a copy of *tp
                let t = mktime(&mut tp.clone());

                // the digits of t, then the sign and padding
                let digits = t.unsigned_abs().to_string().into_bytes();

                if let Some(s) = number_sign_and_padding(digits, t < 0, 1, pad, &mut width, maxsize, &mut i, p)? {
                    add!(&s);
                }
            }

            b'X' => {
                if modifier == b'O' {
                    bad_format = true;
                } else {
                    subfmt = Some(T_FMT);
                }
            }

            b'T' => subfmt = Some(b"%H:%M:%S"),

            b't' => add!(b"\t"),

            b'u' => number = Some((1, ((tp.wday - 1 + 7) % 7 + 1) as i64, false)),

            b'V' | b'g' | b'G' => {
                if modifier == b'E' {
                    bad_format = true;
                } else {
                    let mut year = tp.year as i64 + 1900;
                    let mut days = iso_week_days(tp.yday, tp.wday);

                    if days < 0 {
                        // This ISO week belongs to the previous year.
                        year -= 1;
                        days = iso_week_days(tp.yday + (365 + is_leap(year) as i32), tp.wday);
                    } else {
                        let d = iso_week_days(tp.yday - (365 + is_leap(year) as i32), tp.wday);
                        if 0 <= d {
                            // This ISO week belongs to the next year.
                            year += 1;
                            days = d;
                        }
                    }

                    number = Some(match format_char {
                        b'g' => (2, (year % 100 + 100) % 100, false),
                        b'G' => (1, year, false),
                        _ => (2, (days / 7 + 1) as i64, false),
                    });
                }
            }

            b'Y' => {
                // %EY: no era in the C locale
                if modifier == b'O' {
                    bad_format = true;
                } else {
                    number = Some((1, tp.year as i64 + 1900, false));
                }
            }

            b'y' => {
                // %Ey: no era in the C locale
                number = Some((2, (tp.year as i64 % 100 + 100) % 100, false));
            }

            b'Z' => {
                if change_case {
                    to_uppcase = false;
                    to_lowcase = true;
                }

                // an empty tm_zone: tzname[tm_isdst] after tzset()
                let zone: Vec<u8> = if tp.zone.is_empty() && tp.isdst >= 0 {
                    match &*tzset_internal(true) {
                        Zone::Rules(rules) if tp.isdst <= 1 => rules[tp.isdst as usize].name.clone(),
                        Zone::File(file) if tp.isdst <= 1 => file_tzname(file, tp.isdst),
                        _ => b"?".to_vec(),
                    }
                } else {
                    tp.zone.clone()
                };

                add!(&zone);
            }

            b'z' => {
                if tp.isdst >= 0 {
                    let mut diff = tp.gmtoff;

                    if diff < 0 {
                        add!(b"-");
                        diff = -diff;
                    } else {
                        add!(b"+");
                    }

                    diff /= 60;
                    number = Some((4, (diff / 60) * 100 + diff % 60, false));
                }
            }

            _ => bad_format = true,
        }

        if let Some((d, value, spacepad)) = number {
            let digits = d.max(width);

            if spacepad && pad != b'0' && pad != b'-' {
                // Force `_' flag unless overwritten by `0' or '-' flag.
                pad = b'_';
            }

            // %O: no alternative digits in the C locale
            let negative = value < 0;
            let u = (value as i32 as u32).wrapping_neg();
            let u = if negative { u } else { value as i32 as u32 };
            let buf = u.to_string().into_bytes();

            if let Some(s) = number_sign_and_padding(buf, negative, digits, pad, &mut width, maxsize, &mut i, p)? {
                add!(&s);
            }
        }

        if let Some(sub) = subfmt {
            let mut tmp = Vec::new();
            let len = strftime_internal(&mut tmp, usize::MAX, sub, tp)?;

            let old_start = p.len();

            // add(len, __strftime_internal(p, maxsize - i, subfmt, ...))
            let n = len as i64;
            let delta = width - n;
            let incr = (n + delta.max(0)) as usize;

            if incr >= maxsize - i {
                return None;
            }

            if delta > 0 {
                let c = if pad == b'0' { b'0' } else { b' ' };
                p.extend(std::iter::repeat(c).take(delta as usize));
            }

            strftime_internal(p, maxsize - i, sub, tp)?;

            i += incr;

            if to_uppcase {
                for c in &mut p[old_start..] {
                    *c = c.to_ascii_uppercase();
                }
            }
        }

        if bad_format {
            // Unknown format; output the format, including the '%', since
            // this is most likely the right thing to do if a multibyte
            // string has been misparsed.  (C looks back for the '%' from
            // the conversion character: a '%' there, as in "%E%", is the
            // whole output; a '%' at the end of the format is output with
            // its flags.)
            let end = if fmt(f) == 0 { f } else { f + 1 };
            let start = if fmt(f) == b'%' { f } else { percent };
            add!(&format[start..end]);

            if fmt(f) == 0 {
                break;
            }
        }

        f += 1;
    }

    debug_assert_eq!(p.len() - start, i);

    Some(i)
}

/// tzname[isdst] of a zone file as glibc sets it in __tzfile_compute()
/// for the strftime() of a struct tm without a zone: approximated by the
/// name of the latest type of that flavor.
fn file_tzname(f: &TzFile, isdst: i32) -> Vec<u8> {
    f.type_idxs.iter().rev().map(|&i| &f.types[i]).find(|t| t.isdst as i32 == isdst).map(|t| f.name(t.idx)).unwrap_or_default()
}

/// do_number_sign_and_padding: the digits with the sign, padded to digits
/// with zeros or spaces (the padding is output here, the rest returned to
/// be output with add()); None when the result does not fit.
#[allow(clippy::too_many_arguments)]
fn number_sign_and_padding(buf: Vec<u8>, negative: bool, digits: i64, pad: u8, width: &mut i64, maxsize: usize, i: &mut usize, p: &mut Vec<u8>) -> Option<Option<Vec<u8>>> {
    let mut bufp = Vec::with_capacity(buf.len() + 1);

    if negative {
        bufp.push(b'-');
    }

    bufp.extend_from_slice(&buf);

    if pad != b'-' {
        let padding = digits - bufp.len() as i64;

        if padding > 0 {
            if pad == b'_' {
                if padding as usize >= maxsize - *i {
                    return None;
                }

                p.extend(std::iter::repeat(b' ').take(padding as usize));
                *i += padding as usize;
                *width = if *width > padding { *width - padding } else { 0 };
            } else {
                if digits as usize >= maxsize - *i {
                    return None;
                }

                if negative {
                    bufp.remove(0);
                    p.push(b'-');
                    *i += 1;
                }

                p.extend(std::iter::repeat(b'0').take(padding as usize));
                *i += padding as usize;
                *width = 0;
            }
        }
    }

    Some(Some(bufp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tm_utc(t: i64) -> Tm {
        let mut tm = Tm::default();
        assert!(offtime(t, 0, &mut tm));
        tm.zone = b"GMT".to_vec();
        tm
    }

    fn sf(fmt: &str, tm: &Tm) -> String {
        String::from_utf8(strftime(2048, fmt.as_bytes(), tm)).unwrap()
    }

    #[test]
    fn offtime_dates() {
        let tm = tm_utc(0);
        assert_eq!((tm.year, tm.mon, tm.mday, tm.hour, tm.wday, tm.yday), (70, 0, 1, 0, 4, 0));

        // 2026-10-02 08:39:12 UTC, a Friday
        let tm = tm_utc(1790930352);
        assert_eq!((tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec, tm.wday, tm.yday), (126, 9, 2, 8, 39, 12, 5, 274));

        // 2000-02-29, before 1970
        let tm = tm_utc(951782400);
        assert_eq!((tm.year, tm.mon, tm.mday), (100, 1, 29));
        let tm = tm_utc(-86400);
        assert_eq!((tm.year, tm.mon, tm.mday, tm.wday), (69, 11, 31, 3));
    }

    #[test]
    fn formats_of_the_c_locale() {
        let tm = tm_utc(1790930352);

        assert_eq!(sf("%A, %d-%b-%Y %H:%M:%S %Z", &tm), "Friday, 02-Oct-2026 08:39:12 GMT");
        assert_eq!(sf("%a %b %e %H:%M:%S %Y", &tm), "Fri Oct  2 08:39:12 2026");
        assert_eq!(sf("%c|%x|%X|%D|%F|%R|%r|%T", &tm), "Fri Oct  2 08:39:12 2026|10/02/26|08:39:12|10/02/26|2026-10-02|08:39|08:39:12 AM|08:39:12");
        assert_eq!(sf("%C %g %G %V %U %W %w %u %j %y", &tm), "20 26 2026 40 39 39 5 5 275 26");
        assert_eq!(sf("%I %l %k %p %P %#p %^a %#A %#Z %^B", &tm), "08  8  8 AM am am FRI FRIDAY gmt OCTOBER");
        assert_eq!(sf("%-d %_d %0e %5d %-5d %_5d %05A", &tm), "2  2 02 00002     2     2 Friday");
        assert_eq!(sf("%z %n%t%%", &tm), "+0000 \n\t%");
        assert_eq!(sf("%Ey %EY %EC %Od %Ec %Ex %EX", &tm), "26 2026 20 02 Fri Oct  2 08:39:12 2026 10/02/26 08:39:12");
        assert_eq!(sf("%Ed %OY %Oc %q %:z %", &tm), "%Ed %OY %Oc %q %:z %");
        assert_eq!(sf("%10c|%-10c", &tm), "Fri Oct  2 08:39:12 2026|Fri Oct  2 08:39:12 2026");
        assert_eq!(sf("%30c", &tm), "      Fri Oct  2 08:39:12 2026");
        assert_eq!(sf("%^30c", &tm), "      FRI OCT  2 08:39:12 2026");
        assert_eq!(sf("%10z", &tm), "         +0000000000");
        assert_eq!(sf("IF", &tm), "IF");
        assert_eq!(sf("", &tm), "");

        // the result and its NUL must fit
        assert_eq!(strftime(5, b"%Y", &tm), b"2026");
        assert_eq!(strftime(4, b"%Y", &tm), b"");
        assert_eq!(strftime(2048, "%2047Y".as_bytes(), &tm).len(), 2047);
        assert_eq!(strftime(2048, "%2048Y".as_bytes(), &tm), b"");
        assert_eq!(strftime(2048, "%2047A".as_bytes(), &tm).len(), 2047);
        assert_eq!(strftime(2048, "%2048A".as_bytes(), &tm), b"");
    }

    #[test]
    fn iso_weeks() {
        // 2021-01-03 is in week 53 of 2020; 2024-12-30 in week 1 of 2025
        let tm = tm_utc(1609632000);
        assert_eq!(sf("%G-%V %g", &tm), "2020-53 20");
        let tm = tm_utc(1735516800);
        assert_eq!(sf("%G-%V %g", &tm), "2025-01 25");
    }

    #[test]
    fn posix_tz_strings() {
        let zone = |s: &str| match tzset_parse_tz(s.as_bytes()) {
            Zone::Rules(r) => r,
            Zone::File(_) => panic!("file"),
        };

        let r = zone("MSK-3");
        assert_eq!((&r[0].name[..], r[0].offset, &r[1].name[..], r[1].offset), (&b"MSK"[..], 10800, &b"MSK"[..], 10800));

        let r = zone("<+0330>-3:30");
        assert_eq!((&r[0].name[..], r[0].offset), (&b"+0330"[..], 12600));

        let r = zone("EST5EDT,M3.2.0,M11.1.0");
        assert_eq!((r[0].offset, r[1].offset, r[0].rtype, r[0].m, r[0].n, r[0].d, r[0].secs), (-18000, -14400, RuleType::M, 3, 2, 0, 7200));

        // 2026: DST from March 8 7:00 UTC to November 1 6:00 UTC
        assert_eq!(compute_change(&r[0], 2026), 1772953200);
        assert_eq!(compute_change(&r[1], 2026), 1793512800);

        let mut tm = tm_utc(1790930352);
        tz_compute(&r, 1790930352, &mut tm);
        assert_eq!((tm.isdst, &tm.zone[..], tm.gmtoff), (1, &b"EDT"[..], -14400));
    }

    /// Lines of "TZ<TAB>time<TAB>hex format<TAB>gmt" formatted into hex
    /// (or "(0)"), to compare with glibc (a differential test, run by hand
    /// and alone, it sets TZ: TIME_DIFF_IN, TIME_DIFF_OUT).
    #[test]
    #[ignore]
    fn differential() {
        let input = std::fs::read_to_string(std::env::var("TIME_DIFF_IN").unwrap()).unwrap();
        let unhex = |s: &str| (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>();

        let mut out = String::new();

        for line in input.lines() {
            let f: Vec<&str> = line.split('\t').collect();

            if f[0] == "-" {
                std::env::remove_var("TZ");
            } else {
                std::env::set_var("TZ", f[0]);
            }

            let t: i64 = f[1].parse().unwrap();
            let tm = if f[3] == "1" { gmtime(t) } else { localtime(t) }.unwrap_or_default();
            let s = strftime(2048, &unhex(f[2]), &tm);

            if s.is_empty() {
                out.push_str("(0)\n");
            } else {
                for b in s {
                    out.push_str(&format!("{:02x}", b));
                }
                out.push('\n');
            }
        }

        std::fs::write(std::env::var("TIME_DIFF_OUT").unwrap(), out).unwrap();
    }

    /// The zones of the test machine as glibc gives them (localtime_r() and
    /// strftime("%Y-%m-%d %H:%M:%S %Z %z")); skipped without tzdata
    #[test]
    fn zone_files() {
        if tzfile_read(b"America/New_York").is_none() {
            eprintln!("skipped: no tzdata");
            return;
        }

        let check = |zone: &str, t: i64, expected: &str| {
            let f = tzfile_read(zone.as_bytes()).unwrap();
            let mut tm = Tm::default();
            let (corr, hit) = tzfile_compute(&f, t, true, &mut tm);
            assert!(offtime(t, tm.gmtoff - corr, &mut tm));
            tm.sec += hit;
            assert_eq!(sf("%Y-%m-%d %H:%M:%S %Z %z", &tm), expected, "{} {}", zone, t);
        };

        check("America/New_York", 1790930352, "2026-10-02 04:39:12 EDT -0400");
        check("America/New_York", 1790930352 + 90 * 86400, "2026-12-31 03:39:12 EST -0500");
        check("Europe/Moscow", 1790930352, "2026-10-02 11:39:12 MSK +0300");
        check("Asia/Kolkata", 1790930352, "2026-10-02 14:09:12 IST +0530");
        check("Etc/UTC", 1790930352, "2026-10-02 08:39:12 UTC +0000");
        check("America/New_York", 2208988800, "2039-12-31 19:00:00 EST -0500");
    }
}
