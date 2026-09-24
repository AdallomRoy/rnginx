//! Size, offset and time parsing ported from ngx_parse.c / ngx_parse_time.c.

use crate::string::{atoi, atoof, atosz};

pub const NGX_MAX_SIZE_T_VALUE: isize = isize::MAX;
pub const NGX_MAX_OFF_T_VALUE: i64 = i64::MAX;
pub const NGX_MAX_INT_T_VALUE: i64 = i64::MAX;

/// Returns None on error (NGX_ERROR).
pub fn parse_size(line: &[u8]) -> Option<usize> {
    if line.is_empty() {
        return None;
    }
    let mut len = line.len();
    let (max, scale): (isize, isize) = match line[len - 1] {
        b'K' | b'k' => {
            len -= 1;
            (NGX_MAX_SIZE_T_VALUE / 1024, 1024)
        }
        b'M' | b'm' => {
            len -= 1;
            (NGX_MAX_SIZE_T_VALUE / (1024 * 1024), 1024 * 1024)
        }
        _ => (NGX_MAX_SIZE_T_VALUE, 1),
    };
    let size = atosz(&line[..len])?;
    if size > max {
        return None;
    }
    Some((size * scale) as usize)
}

pub fn parse_offset(line: &[u8]) -> Option<i64> {
    if line.is_empty() {
        return None;
    }
    let mut len = line.len();
    let (max, scale): (i64, i64) = match line[len - 1] {
        b'K' | b'k' => {
            len -= 1;
            (NGX_MAX_OFF_T_VALUE / 1024, 1024)
        }
        b'M' | b'm' => {
            len -= 1;
            (NGX_MAX_OFF_T_VALUE / (1024 * 1024), 1024 * 1024)
        }
        b'G' | b'g' => {
            len -= 1;
            (NGX_MAX_OFF_T_VALUE / (1024 * 1024 * 1024), 1024 * 1024 * 1024)
        }
        _ => (NGX_MAX_OFF_T_VALUE, 1),
    };
    let off = atoof(&line[..len])?;
    if off > max {
        return None;
    }
    Some(off * scale)
}

#[derive(PartialEq, PartialOrd, Clone, Copy)]
enum Step {
    Start = 0,
    Year,
    Month,
    Week,
    Day,
    Hour,
    Min,
    Sec,
    Msec,
    Last,
}

/// Port of ngx_parse_time. `is_sec` selects seconds (true) or milliseconds.
/// Returns None on error.
pub fn parse_time(line: &[u8], is_sec: bool) -> Option<i64> {
    let mut valid = false;
    let mut value: i64 = 0;
    let mut total: i64 = 0;
    let cutoff = NGX_MAX_INT_T_VALUE / 10;
    let cutlim = NGX_MAX_INT_T_VALUE % 10;
    let mut step = if is_sec { Step::Start } else { Step::Month };

    let mut p = 0;
    let last = line.len();

    while p < last {
        let c = line[p];
        if c.is_ascii_digit() {
            let d = (c - b'0') as i64;
            if value >= cutoff && (value > cutoff || d > cutlim) {
                return None;
            }
            value = value * 10 + d;
            valid = true;
            p += 1;
            continue;
        }

        p += 1;
        let (mut max, mut scale): (i64, i64);
        match c {
            b'y' => {
                if step > Step::Start {
                    return None;
                }
                step = Step::Year;
                max = NGX_MAX_INT_T_VALUE / (60 * 60 * 24 * 365);
                scale = 60 * 60 * 24 * 365;
            }
            b'M' => {
                if step >= Step::Month {
                    return None;
                }
                step = Step::Month;
                max = NGX_MAX_INT_T_VALUE / (60 * 60 * 24 * 30);
                scale = 60 * 60 * 24 * 30;
            }
            b'w' => {
                if step >= Step::Week {
                    return None;
                }
                step = Step::Week;
                max = NGX_MAX_INT_T_VALUE / (60 * 60 * 24 * 7);
                scale = 60 * 60 * 24 * 7;
            }
            b'd' => {
                if step >= Step::Day {
                    return None;
                }
                step = Step::Day;
                max = NGX_MAX_INT_T_VALUE / (60 * 60 * 24);
                scale = 60 * 60 * 24;
            }
            b'h' => {
                if step >= Step::Hour {
                    return None;
                }
                step = Step::Hour;
                max = NGX_MAX_INT_T_VALUE / (60 * 60);
                scale = 60 * 60;
            }
            b'm' => {
                if p < last && line[p] == b's' {
                    if is_sec || step >= Step::Msec {
                        return None;
                    }
                    p += 1;
                    step = Step::Msec;
                    max = NGX_MAX_INT_T_VALUE;
                    scale = 1;
                } else {
                    if step >= Step::Min {
                        return None;
                    }
                    step = Step::Min;
                    max = NGX_MAX_INT_T_VALUE / 60;
                    scale = 60;
                }
            }
            b's' => {
                if step >= Step::Sec {
                    return None;
                }
                step = Step::Sec;
                max = NGX_MAX_INT_T_VALUE;
                scale = 1;
            }
            b' ' => {
                if step >= Step::Sec {
                    return None;
                }
                step = Step::Last;
                max = NGX_MAX_INT_T_VALUE;
                scale = 1;
            }
            _ => return None,
        }

        if step != Step::Msec && !is_sec {
            scale *= 1000;
            max /= 1000;
        }

        if value > max {
            return None;
        }

        value *= scale;

        if total > NGX_MAX_INT_T_VALUE - value {
            return None;
        }

        total += value;
        value = 0;

        while p < last && line[p] == b' ' {
            p += 1;
        }
    }

    if !valid {
        return None;
    }

    if !is_sec {
        if value > NGX_MAX_INT_T_VALUE / 1000 {
            return None;
        }
        value *= 1000;
    }

    if total > NGX_MAX_INT_T_VALUE - value {
        return None;
    }

    Some(total + value)
}

pub fn parse_sec(line: &[u8]) -> Option<i64> {
    parse_time(line, true)
}

pub fn parse_msec(line: &[u8]) -> Option<u64> {
    parse_time(line, false).map(|v| v as u64)
}

static MDAY: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Port of ngx_parse_http_time; returns seconds since epoch or None.
pub fn parse_http_time(value: &[u8]) -> Option<i64> {
    #[derive(PartialEq, Clone, Copy)]
    enum Fmt {
        No,
        Rfc822,
        Rfc850,
        Isoc,
    }
    let end = value.len();
    let at = |i: usize| -> u8 { if i < end { value[i] } else { 0 } };
    let mut fmt = Fmt::No;
    let mut p = 0;
    while p < end {
        if value[p] == b',' {
            break;
        }
        if value[p] == b' ' {
            fmt = Fmt::Isoc;
            break;
        }
        p += 1;
    }
    p += 1;
    while p < end {
        if value[p] != b' ' {
            break;
        }
        p += 1;
    }
    if end < p + 18 {
        return None;
    }
    let mut day: u32 = 32;
    let mut year: u32 = 2038;
    if fmt != Fmt::Isoc {
        if !at(p).is_ascii_digit() || !at(p + 1).is_ascii_digit() {
            return None;
        }
        day = (at(p) - b'0') as u32 * 10 + (at(p + 1) - b'0') as u32;
        p += 2;
        if at(p) == b' ' {
            if end < p + 18 {
                return None;
            }
            fmt = Fmt::Rfc822;
        } else if at(p) == b'-' {
            fmt = Fmt::Rfc850;
        } else {
            return None;
        }
        p += 1;
    }
    let month: i32 = match at(p) {
        b'J' => {
            if at(p + 1) == b'a' {
                0
            } else if at(p + 2) == b'n' {
                5
            } else {
                6
            }
        }
        b'F' => 1,
        b'M' => if at(p + 2) == b'r' { 2 } else { 4 },
        b'A' => if at(p + 1) == b'p' { 3 } else { 7 },
        b'S' => 8,
        b'O' => 9,
        b'N' => 10,
        b'D' => 11,
        _ => return None,
    };
    p += 3;
    if (fmt == Fmt::Rfc822 && at(p) != b' ') || (fmt == Fmt::Rfc850 && at(p) != b'-') {
        return None;
    }
    p += 1;
    if fmt == Fmt::Rfc822 {
        if !at(p).is_ascii_digit() || !at(p + 1).is_ascii_digit() || !at(p + 2).is_ascii_digit() || !at(p + 3).is_ascii_digit() {
            return None;
        }
        year = (at(p) - b'0') as u32 * 1000 + (at(p + 1) - b'0') as u32 * 100 + (at(p + 2) - b'0') as u32 * 10 + (at(p + 3) - b'0') as u32;
        p += 4;
    } else if fmt == Fmt::Rfc850 {
        if !at(p).is_ascii_digit() || !at(p + 1).is_ascii_digit() {
            return None;
        }
        year = (at(p) - b'0') as u32 * 10 + (at(p + 1) - b'0') as u32;
        year += if year < 70 { 2000 } else { 1900 };
        p += 2;
    }
    if fmt == Fmt::Isoc {
        if at(p) == b' ' {
            p += 1;
        }
        if !at(p).is_ascii_digit() {
            return None;
        }
        day = (at(p) - b'0') as u32;
        p += 1;
        if at(p) != b' ' {
            if !at(p).is_ascii_digit() {
                return None;
            }
            day = day * 10 + (at(p) - b'0') as u32;
            p += 1;
        }
        if end < p + 14 {
            return None;
        }
    }
    if at(p) != b' ' {
        return None;
    }
    p += 1;
    if !at(p).is_ascii_digit() || !at(p + 1).is_ascii_digit() {
        return None;
    }
    let hour = (at(p) - b'0') as u32 * 10 + (at(p + 1) - b'0') as u32;
    p += 2;
    if at(p) != b':' {
        return None;
    }
    p += 1;
    if !at(p).is_ascii_digit() || !at(p + 1).is_ascii_digit() {
        return None;
    }
    let min = (at(p) - b'0') as u32 * 10 + (at(p + 1) - b'0') as u32;
    p += 2;
    if at(p) != b':' {
        return None;
    }
    p += 1;
    if !at(p).is_ascii_digit() || !at(p + 1).is_ascii_digit() {
        return None;
    }
    let sec = (at(p) - b'0') as u32 * 10 + (at(p + 1) - b'0') as u32;
    if fmt == Fmt::Isoc {
        p += 2;
        if at(p) != b' ' {
            return None;
        }
        p += 1;
        if !at(p).is_ascii_digit() || !at(p + 1).is_ascii_digit() || !at(p + 2).is_ascii_digit() || !at(p + 3).is_ascii_digit() {
            return None;
        }
        year = (at(p) - b'0') as u32 * 1000 + (at(p + 1) - b'0') as u32 * 100 + (at(p + 2) - b'0') as u32 * 10 + (at(p + 3) - b'0') as u32;
    }
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    if day == 29 && month == 1 {
        if (year & 3) != 0 || ((year % 100 == 0) && (year % 400) != 0) {
            return None;
        }
    } else if day > MDAY[month as usize] {
        return None;
    }
    let mut month = month as i64;
    let mut year = year as i64;
    month -= 1;
    if month <= 0 {
        month += 12;
        year -= 1;
    }
    let time: i64 = (365 * year + year / 4 - year / 100 + year / 400 + 367 * month / 12 - 30 + day as i64 - 1 - 719527 + 31 + 28) * 86400
        + hour as i64 * 3600
        + min as i64 * 60
        + sec as i64;
    Some(time)
}

/// Helper to convert time in seconds to i64 or error; kept for API parity.
pub fn atoi_i64(s: &[u8]) -> Option<i64> {
    atoi(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size(b"8k"), Some(8192));
        assert_eq!(parse_size(b"1m"), Some(1048576));
        assert_eq!(parse_size(b"10"), Some(10));
        assert_eq!(parse_size(b"1g"), None);
        assert_eq!(parse_offset(b"1g"), Some(1 << 30));
    }

    #[test]
    fn times() {
        assert_eq!(parse_time(b"1s", true), Some(1));
        assert_eq!(parse_time(b"1s", false), Some(1000));
        assert_eq!(parse_time(b"1m30s", true), Some(90));
        assert_eq!(parse_time(b"75", false), Some(75000));
        assert_eq!(parse_time(b"100ms", false), Some(100));
        assert_eq!(parse_time(b"100ms", true), None);
        assert_eq!(parse_time(b"1s1m", true), None);
        assert_eq!(parse_time(b"1d 12h", true), Some(86400 + 43200));
        assert_eq!(parse_time(b"", true), None);
        assert_eq!(parse_time(b"1x", true), None);
    }

    #[test]
    fn http_time() {
        assert_eq!(parse_http_time(b"Sun, 06 Nov 1994 08:49:37 GMT"), Some(784111777));
        assert_eq!(parse_http_time(b"Sunday, 06-Nov-94 08:49:37 GMT"), Some(784111777));
        assert_eq!(parse_http_time(b"Sun Nov  6 08:49:37 1994"), Some(784111777));
        assert_eq!(parse_http_time(b"garbage"), None);
    }
}
