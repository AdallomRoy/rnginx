//! ngx_json_unescape.c: the escape sequences of a JSON string (RFC 8259,
//! Section 7), \uXXXX and UTF-16 surrogate pairs included.

/// ngx_json_unescape_string: the escape sequences of an unquoted JSON string
/// body (the bytes between the double quotes) decoded in place. Err on a
/// malformed escape or invalid input, the string being left as it is then
/// partly decoded.
pub fn unescape_string(s: &mut Vec<u8>) -> Result<(), ()> {
    const SW_USUAL: u8 = 0;
    const SW_QUOTED: u8 = 1;
    const SW_HEX: u8 = 2;
    // expect '\' of \uDCxx after a high surrogate
    const SW_SURROGATE_START: u8 = 3;
    // expect 'u'
    const SW_SURROGATE_U: u8 = 4;

    // RFC 8259, Section 7:
    //
    // string = quotation-mark *char quotation-mark
    //
    // char = unescaped /
    //        escape (
    //            %x22 /          ; "    quotation mark  U+0022
    //            %x5C /          ; \    reverse solidus U+005C
    //            %x2F /          ; /    solidus         U+002F
    //            %x62 /          ; b    backspace       U+0008
    //            %x66 /          ; f    form feed       U+000C
    //            %x6E /          ; n    line feed       U+000A
    //            %x72 /          ; r    carriage return U+000D
    //            %x74 /          ; t    tab             U+0009
    //            %x75 4HEXDIG )  ; uXXXX                U+XXXX
    //
    // Non-BMP code points are encoded as a UTF-16 surrogate pair:
    //   \uD800..\uDBFF  high surrogate
    //   \uDC00..\uDFFF  low  surrogate
    // The pair decodes to U+10000 + (high - 0xD800) * 0x400
    //                              + (low  - 0xDC00).

    if s.is_empty() {
        return Ok(());
    }

    let mut d = 0;

    let mut state = SW_USUAL;
    let mut codepoint: u32 = 0;
    let mut high_surrogate: u32 = 0;
    let mut hex_left = 0;

    for i in 0..s.len() {
        let ch = s[i];

        match state {
            SW_USUAL => {
                if ch == b'"' {
                    return Err(());
                }

                if ch == b'\\' {
                    state = SW_QUOTED;
                    continue;
                }

                if ch < 0x20 {
                    // RFC 8259: control characters must be escaped
                    return Err(());
                }

                s[d] = ch;
                d += 1;
            }

            SW_QUOTED => {
                let c = match ch {
                    b'u' => {
                        codepoint = 0;
                        hex_left = 4;
                        state = SW_HEX;
                        continue;
                    }

                    b'"' | b'/' | b'\\' => ch,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',

                    _ => return Err(()),
                };

                s[d] = c;
                d += 1;
                state = SW_USUAL;
            }

            SW_HEX => {
                let n = hex_digit(ch).ok_or(())?;

                codepoint = (codepoint << 4) | n;

                hex_left -= 1;

                if hex_left > 0 {
                    continue;
                }

                if high_surrogate != 0 {
                    if !(0xDC00..=0xDFFF).contains(&codepoint) {
                        return Err(());
                    }

                    codepoint = 0x10000 + ((high_surrogate - 0xD800) << 10) + (codepoint - 0xDC00);
                    d = utf8_encode(s, d, codepoint);
                    high_surrogate = 0;
                    state = SW_USUAL;
                    continue;
                }

                if (0xD800..=0xDBFF).contains(&codepoint) {
                    // high surrogate - wait for the low surrogate
                    high_surrogate = codepoint;
                    state = SW_SURROGATE_START;
                    continue;
                }

                if (0xDC00..=0xDFFF).contains(&codepoint) {
                    // lone low surrogate
                    return Err(());
                }

                d = utf8_encode(s, d, codepoint);
                state = SW_USUAL;
            }

            SW_SURROGATE_START => {
                // Expect '\' to begin the low-surrogate escape. Lone
                // surrogates are not valid Unicode scalar values (RFC 8259,
                // Section 8.2).
                if ch == b'\\' {
                    state = SW_SURROGATE_U;
                    continue;
                }

                // lone high surrogate
                return Err(());
            }

            _ => {
                // SW_SURROGATE_U
                if ch == b'u' {
                    codepoint = 0;
                    hex_left = 4;
                    state = SW_HEX;
                    continue;
                }

                // lone high surrogate
                return Err(());
            }
        }
    }

    if state != SW_USUAL {
        // truncated escape sequence or unpaired high surrogate
        return Err(());
    }

    s.truncate(d);

    Ok(())
}

/// ngx_json_utf8_encode: the code point written at `d`, which is behind
/// what the escape sequence took
fn utf8_encode(s: &mut [u8], mut d: usize, codepoint: u32) -> usize {
    let mut put = |b: u32| {
        s[d] = b as u8;
        d += 1;
    };

    if codepoint <= 0x7F {
        put(codepoint);
    } else if codepoint <= 0x7FF {
        put(0xC0 | (codepoint >> 6));
        put(0x80 | (codepoint & 0x3F));
    } else if codepoint <= 0xFFFF {
        put(0xE0 | (codepoint >> 12));
        put(0x80 | ((codepoint >> 6) & 0x3F));
        put(0x80 | (codepoint & 0x3F));
    } else {
        put(0xF0 | (codepoint >> 18));
        put(0x80 | ((codepoint >> 12) & 0x3F));
        put(0x80 | ((codepoint >> 6) & 0x3F));
        put(0x80 | (codepoint & 0x3F));
    }

    d
}

/// ngx_json_hex_digit
pub fn hex_digit(ch: u8) -> Option<u32> {
    if ch.is_ascii_digit() {
        return Some((ch - b'0') as u32);
    }

    let ch = ch | 0x20;

    if (b'a'..=b'f').contains(&ch) {
        return Some((ch - b'a' + 10) as u32);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unescaped(s: &[u8]) -> Result<Vec<u8>, ()> {
        let mut v = s.to_vec();
        unescape_string(&mut v).map(|()| v)
    }

    #[test]
    fn test_unescape() {
        assert_eq!(unescaped(b""), Ok(Vec::new()));
        assert_eq!(unescaped(b"plain"), Ok(b"plain".to_vec()));
        assert_eq!(unescaped(br#"a\nb\tc\"d\\e\/f\bg\fh\ri"#), Ok(b"a\nb\tc\"d\\e/f\x08g\x0ch\ri".to_vec()));
        assert_eq!(unescaped(br"A\u00e9\u07ff\u8898"), Ok("A\u{e9}\u{7ff}\u{8898}".as_bytes().to_vec()));
        assert_eq!(unescaped(br"x\uD83D\uDE00y"), Ok("x\u{1F600}y".as_bytes().to_vec()));
        assert_eq!(unescaped(br"a\u0000b"), Ok(b"a\0b".to_vec()));
    }

    #[test]
    fn test_unescape_invalid() {
        for s in [&br#"a"b"#[..], b"a\x01b", br"\q", br"\u12", br"\uZZZZ", br"\uDC00", br"\uD83D", br"\uD83Dz", br"\uD83D\n", br"\uD83DA", br"abc\"] {
            assert_eq!(unescaped(s), Err(()), "{:?}", String::from_utf8_lossy(s));
        }
    }

    #[test]
    fn test_hex_digit() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b' '), None);
    }
}
