//! ngx_json_parse.c: a JSON parser (RFC 8259 for the JSON grammar) calling a
//! handler with the events of the document: the objects and arrays opened
//! and closed, the keys and the values, each with its token as the offset
//! and the length of it in the input.

use crate::json_unescape::hex_digit;
use crate::rc::*;

/// NGX_JSON_SKIP: the handler prunes the rest of the current container
pub const NGX_JSON_SKIP: i64 = -7;
pub const NGX_JSON_DEFAULT_MAX_DEPTH: usize = 64;

/// ngx_json_event_e
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JsonEvent {
    ObjectOpen,
    ObjectClose,
    ArrayOpen,
    ArrayClose,
    Key,
    ValueString,
    ValueNumber,
    ValueBool,
    ValueNull,
}

/// ngx_json_state_e
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Start,
    Done,
    Object,
    ObjectNext,
    ObjectNameSeparator,
    Value,
    ObjectValueSeparator,
    ArrayValueSeparator,
    Array,
    String,
    NumberMinus,
    NumberInt,
    NumberIntZero,
    NumberFrac,
    NumberFracDigit,
    NumberExp,
    NumberExpPlusminus,
    NumberExpDigit,
    Escaped,
    /// first \uXXXX: reading the four hex digits
    EscapedHex,
    /// expect '\' beginning the low surrogate
    SurrogateStart,
    /// expect 'u' of the low surrogate
    SurrogateU,
    /// low \uXXXX: reading the four hex digits
    SurrogateHex,
    TrueT,
    TrueTr,
    TrueTru,
    FalseF,
    FalseFa,
    FalseFal,
    FalseFals,
    NullN,
    NullNu,
    NullNul,
}

/// ngx_json_container_e
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Container {
    None,
    Object,
    Array,
}

/// NGX_JSON_NOT_SKIPPING
const NOT_SKIPPING: usize = usize::MAX;

/// ngx_json_ws
fn ws(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'\r' || c == b'\n'
}

/// ngx_json_ctx_t
pub struct JsonCtx {
    state: State,

    stack: Vec<Container>,
    depth: usize,
    pub max_depth: usize,

    codepoint: u32,
    /// hex digits still expected
    hex_left: usize,

    skip_until_depth: usize,

    in_key: bool,
}

impl Default for JsonCtx {
    fn default() -> Self {
        JsonCtx::new()
    }
}

impl JsonCtx {
    /// ngx_json_ctx_init
    pub fn new() -> JsonCtx {
        JsonCtx {
            state: State::Start,
            // the stack is allocated on the first push, sized to max_depth
            stack: Vec::new(),
            depth: 0,
            max_depth: NGX_JSON_DEFAULT_MAX_DEPTH,
            codepoint: 0,
            hex_left: 0,
            skip_until_depth: NOT_SKIPPING,
            in_key: false,
        }
    }

    /// ngx_json_parse_ctx: `handler` gets each event with the offset and the
    /// length of its token in `data`. NGX_OK when the document is complete,
    /// NGX_DECLINED when it is invalid or incomplete, or the error of the
    /// handler.
    pub fn parse(&mut self, data: &[u8], handler: &mut dyn FnMut(JsonEvent, usize, usize) -> i64) -> i64 {
        if data.is_empty() {
            return NGX_DECLINED;
        }

        if self.state == State::Done {
            return NGX_DECLINED;
        }

        let last = data.len();
        let mut state = self.state;
        let mut skip_depth = self.skip_until_depth;
        let mut start = 0;

        let mut p = 0;

        while p < last {
            // skipping suppresses emission only; the machine still validates

            if skip_depth != NOT_SKIPPING && self.depth <= skip_depth && matches!(state, State::ObjectValueSeparator | State::ArrayValueSeparator | State::Done) {
                skip_depth = NOT_SKIPPING;
                self.skip_until_depth = NOT_SKIPPING;

                // the character again
                continue;
            }

            let ch = data[p];

            // the character is looked at again in the next state (p-- in C)
            let mut again = false;

            match state {
                State::Start => {
                    if !ws(ch) {
                        again = true;
                        state = State::Value;
                    }
                }

                State::Object | State::ObjectNext => {
                    if ws(ch) {
                        // skip
                    } else if ch == b'}' && state == State::Object {
                        let rc = self.close(handler, JsonEvent::ObjectClose, &mut state, p);
                        if rc != NGX_OK {
                            return rc;
                        }
                    } else if ch == b'"' {
                        self.in_key = true;
                        start = p + 1;
                        state = State::String;
                    } else {
                        return NGX_DECLINED;
                    }
                }

                State::ObjectNameSeparator => {
                    if ws(ch) {
                        // skip
                    } else if ch == b':' {
                        state = State::Value;
                    } else {
                        return NGX_DECLINED;
                    }
                }

                State::ObjectValueSeparator => {
                    if ws(ch) {
                        // skip
                    } else if ch == b',' {
                        state = State::ObjectNext;
                    } else if ch == b'}' {
                        let rc = self.close(handler, JsonEvent::ObjectClose, &mut state, p);
                        if rc != NGX_OK {
                            return rc;
                        }
                    } else {
                        return NGX_DECLINED;
                    }
                }

                State::ArrayValueSeparator => {
                    if ws(ch) {
                        // skip
                    } else if ch == b',' {
                        state = State::Value;
                    } else if ch == b']' {
                        let rc = self.close(handler, JsonEvent::ArrayClose, &mut state, p);
                        if rc != NGX_OK {
                            return rc;
                        }
                    } else {
                        return NGX_DECLINED;
                    }
                }

                State::Array | State::Value => {
                    if ws(ch) {
                        // skip
                    } else if ch == b']' && state == State::Array {
                        let rc = self.close(handler, JsonEvent::ArrayClose, &mut state, p);
                        if rc != NGX_OK {
                            return rc;
                        }
                    } else {
                        start = p;

                        match ch {
                            b'"' => {
                                self.in_key = false;
                                start = p + 1;
                                state = State::String;
                            }

                            b'{' => {
                                let rc = self.emit(handler, JsonEvent::ObjectOpen, p, 1);
                                if rc != NGX_OK {
                                    return rc;
                                }

                                let rc = self.push_state(Container::Object);
                                if rc != NGX_OK {
                                    return rc;
                                }

                                state = State::Object;
                            }

                            b'[' => {
                                let rc = self.emit(handler, JsonEvent::ArrayOpen, p, 1);
                                if rc != NGX_OK {
                                    return rc;
                                }

                                let rc = self.push_state(Container::Array);
                                if rc != NGX_OK {
                                    return rc;
                                }

                                state = State::Array;
                            }

                            b'-' => state = State::NumberMinus,
                            b'0' => state = State::NumberIntZero,
                            b'1'..=b'9' => state = State::NumberInt,
                            b't' => state = State::TrueT,
                            b'f' => state = State::FalseF,
                            b'n' => state = State::NullN,

                            _ => return NGX_DECLINED,
                        }
                    }
                }

                State::String => {
                    if ch == b'"' {
                        if self.in_key {
                            let rc = self.emit(handler, JsonEvent::Key, start, p - start);
                            if rc != NGX_OK {
                                return rc;
                            }

                            self.in_key = false;
                            state = State::ObjectNameSeparator;
                        } else {
                            let rc = self.emit(handler, JsonEvent::ValueString, start, p - start);
                            if rc != NGX_OK {
                                return rc;
                            }

                            state = self.after_value();
                        }
                    } else if ch == b'\\' {
                        state = State::Escaped;
                    } else if ch < b' ' {
                        return NGX_DECLINED;
                    }
                }

                State::Escaped => match ch {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => state = State::String,

                    b'u' => {
                        self.codepoint = 0;
                        self.hex_left = 4;
                        state = State::EscapedHex;
                    }

                    _ => return NGX_DECLINED,
                },

                State::EscapedHex => {
                    // accumulate the four hex digits of the first \uXXXX escape

                    let hd = match hex_digit(ch) {
                        Some(d) => d,
                        None => return NGX_DECLINED,
                    };

                    self.codepoint = (self.codepoint << 4) | hd;

                    self.hex_left -= 1;

                    if self.hex_left == 0 {
                        if (0xD800..=0xDBFF).contains(&self.codepoint) {
                            // high surrogate - must be followed by \uDC00..\uDFFF
                            state = State::SurrogateStart;
                        } else if (0xDC00..=0xDFFF).contains(&self.codepoint) {
                            // lone low surrogate
                            return NGX_DECLINED;
                        } else {
                            state = State::String;
                        }
                    }
                }

                State::SurrogateStart => {
                    if ch != b'\\' {
                        // high surrogate not followed by \uXXXX
                        return NGX_DECLINED;
                    }

                    state = State::SurrogateU;
                }

                State::SurrogateU => {
                    if ch != b'u' {
                        // high surrogate followed by non-\u escape
                        return NGX_DECLINED;
                    }

                    self.codepoint = 0;
                    self.hex_left = 4;
                    state = State::SurrogateHex;
                }

                State::SurrogateHex => {
                    // accumulate the four hex digits of the low \uXXXX escape

                    let hd = match hex_digit(ch) {
                        Some(d) => d,
                        None => return NGX_DECLINED,
                    };

                    self.codepoint = (self.codepoint << 4) | hd;

                    self.hex_left -= 1;

                    if self.hex_left == 0 {
                        if !(0xDC00..=0xDFFF).contains(&self.codepoint) {
                            // high surrogate not followed by low surrogate
                            return NGX_DECLINED;
                        }

                        // valid surrogate pair
                        state = State::String;
                    }
                }

                State::NumberMinus => match ch {
                    b'1'..=b'9' => state = State::NumberInt,
                    b'0' => state = State::NumberIntZero,
                    _ => return NGX_DECLINED,
                },

                State::NumberIntZero | State::NumberInt => {
                    if ch.is_ascii_digit() && state == State::NumberInt {
                        // more digits
                    } else if ch == b'.' {
                        state = State::NumberFrac;
                    } else if ch == b'e' || ch == b'E' {
                        // No sense, but permitted by RFC
                        state = State::NumberExp;
                    } else {
                        again = true;

                        let rc = self.end_number(handler, start, p, &mut state);
                        if rc != NGX_OK {
                            return rc;
                        }
                    }
                }

                State::NumberFrac => {
                    if !ch.is_ascii_digit() {
                        return NGX_DECLINED;
                    }

                    state = State::NumberFracDigit;
                }

                State::NumberFracDigit => {
                    if ch.is_ascii_digit() {
                        // more digits
                    } else if ch == b'e' || ch == b'E' {
                        state = State::NumberExp;
                    } else {
                        again = true;

                        let rc = self.end_number(handler, start, p, &mut state);
                        if rc != NGX_OK {
                            return rc;
                        }
                    }
                }

                State::NumberExp => {
                    if ch == b'-' || ch == b'+' {
                        state = State::NumberExpPlusminus;
                    } else if ch.is_ascii_digit() {
                        state = State::NumberExpDigit;
                    } else {
                        return NGX_DECLINED;
                    }
                }

                State::NumberExpPlusminus => {
                    if !ch.is_ascii_digit() {
                        return NGX_DECLINED;
                    }

                    state = State::NumberExpDigit;
                }

                State::NumberExpDigit => {
                    if !ch.is_ascii_digit() {
                        again = true;

                        let rc = self.end_number(handler, start, p, &mut state);
                        if rc != NGX_OK {
                            return rc;
                        }
                    }
                }

                State::TrueT | State::TrueTr | State::FalseF | State::FalseFa | State::FalseFal | State::NullN | State::NullNu => {
                    let (want, next) = match state {
                        State::TrueT => (b'r', State::TrueTr),
                        State::TrueTr => (b'u', State::TrueTru),
                        State::FalseF => (b'a', State::FalseFa),
                        State::FalseFa => (b'l', State::FalseFal),
                        State::FalseFal => (b's', State::FalseFals),
                        State::NullN => (b'u', State::NullNu),
                        _ => (b'l', State::NullNul),
                    };

                    if ch != want {
                        return NGX_DECLINED;
                    }

                    state = next;
                }

                State::TrueTru | State::FalseFals | State::NullNul => {
                    let (want, event) = match state {
                        State::NullNul => (b'l', JsonEvent::ValueNull),
                        _ => (b'e', JsonEvent::ValueBool),
                    };

                    if ch != want {
                        return NGX_DECLINED;
                    }

                    let rc = self.emit(handler, event, start, p + 1 - start);
                    if rc != NGX_OK {
                        return rc;
                    }

                    state = self.after_value();
                }

                State::Done => {
                    if !ws(ch) {
                        return NGX_DECLINED;
                    }
                }
            }

            skip_depth = self.skip_until_depth;

            if !again {
                p += 1;
            }
        }

        // a bare top-level number is not self-delimited; emit it at end of
        // input

        if self.depth == 0 && matches!(state, State::NumberIntZero | State::NumberInt | State::NumberFracDigit | State::NumberExpDigit) {
            let rc = self.emit(handler, JsonEvent::ValueNumber, start, last - start);
            if rc != NGX_OK {
                return rc;
            }

            state = State::Done;
        }

        self.state = state;

        if state == State::Done {
            return NGX_OK;
        }

        NGX_DECLINED
    }

    /// ngx_json_end_number
    fn end_number(&mut self, handler: &mut dyn FnMut(JsonEvent, usize, usize) -> i64, start: usize, end: usize, state: &mut State) -> i64 {
        let rc = self.emit(handler, JsonEvent::ValueNumber, start, end - start);
        if rc != NGX_OK {
            return rc;
        }

        *state = self.after_value();

        NGX_OK
    }

    /// ngx_json_emit
    fn emit(&mut self, handler: &mut dyn FnMut(JsonEvent, usize, usize) -> i64, event: JsonEvent, start: usize, len: usize) -> i64 {
        if self.skip_until_depth != NOT_SKIPPING {
            return NGX_OK;
        }

        let rc = handler(event, start, len);

        if rc == NGX_JSON_SKIP {
            // NGX_JSON_SKIP prunes the rest of the current container. It is
            // honoured only where it is meaningful:
            //
            //   - OBJECT_OPEN / ARRAY_OPEN: skip the whole container;
            //   - a scalar VALUE_* that is an array element: skip the rest of
            //     that array.
            //
            // A skip requested on a CLOSE, or on an object member value, is
            // ignored: object members are navigated by KEY (use a KEY skip),
            // and a CLOSE fires after the container is already complete.

            match event {
                JsonEvent::Key | JsonEvent::ObjectOpen | JsonEvent::ArrayOpen => {
                    self.skip_until_depth = self.depth;
                }

                JsonEvent::ValueString | JsonEvent::ValueNumber | JsonEvent::ValueBool | JsonEvent::ValueNull => {
                    if self.depth > 0 && self.stack[self.depth - 1] == Container::Array {
                        self.skip_until_depth = self.depth - 1;
                    }
                }

                _ => {}
            }

            return NGX_OK;
        }

        rc
    }

    /// ngx_json_after_value
    fn after_value(&self) -> State {
        if self.depth == 0 {
            return State::Done;
        }

        if self.stack[self.depth - 1] == Container::Object {
            return State::ObjectValueSeparator;
        }

        State::ArrayValueSeparator
    }

    /// ngx_json_close
    fn close(&mut self, handler: &mut dyn FnMut(JsonEvent, usize, usize) -> i64, event: JsonEvent, state: &mut State, p: usize) -> i64 {
        self.depth -= 1;

        let rc = self.emit(handler, event, p, 1);
        if rc != NGX_OK {
            return rc;
        }

        *state = self.after_value();

        NGX_OK
    }

    /// ngx_json_push_state
    fn push_state(&mut self, container: Container) -> i64 {
        if self.depth >= self.max_depth {
            return NGX_DECLINED;
        }

        if self.stack.is_empty() {
            self.stack = vec![Container::None; self.max_depth];
        }

        self.stack[self.depth] = container;
        self.depth += 1;

        NGX_OK
    }
}

/// ngx_json_parse
pub fn parse(json: &[u8], handler: &mut dyn FnMut(JsonEvent, usize, usize) -> i64) -> i64 {
    JsonCtx::new().parse(json, handler)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the events of a document with their tokens
    fn events(json: &[u8], max_depth: usize) -> (i64, Vec<(JsonEvent, String)>) {
        let mut ev = Vec::new();
        let mut ctx = JsonCtx::new();
        ctx.max_depth = max_depth;

        let rc = ctx.parse(json, &mut |e, start, len| {
            ev.push((e, String::from_utf8_lossy(&json[start..start + len]).into_owned()));
            NGX_OK
        });

        (rc, ev)
    }

    #[test]
    fn test_parse_events() {
        use JsonEvent::*;

        let (rc, ev) = events(br#" {"a" : [1, -2.5e+3, true, false, null, "s\"x"], "b":{}} "#, 64);

        assert_eq!(rc, NGX_OK);
        assert_eq!(
            ev,
            vec![
                (ObjectOpen, "{".into()),
                (Key, "a".into()),
                (ArrayOpen, "[".into()),
                (ValueNumber, "1".into()),
                (ValueNumber, "-2.5e+3".into()),
                (ValueBool, "true".into()),
                (ValueBool, "false".into()),
                (ValueNull, "null".into()),
                (ValueString, "s\\\"x".into()),
                (ArrayClose, "]".into()),
                (Key, "b".into()),
                (ObjectOpen, "{".into()),
                (ObjectClose, "}".into()),
                (ObjectClose, "}".into()),
            ]
        );
    }

    #[test]
    fn test_parse_top_level() {
        assert_eq!(events(b"42", 64), (NGX_OK, vec![(JsonEvent::ValueNumber, "42".into())]));
        assert_eq!(events(b"0", 64), (NGX_OK, vec![(JsonEvent::ValueNumber, "0".into())]));
        assert_eq!(events(b"1.5 ", 64), (NGX_OK, vec![(JsonEvent::ValueNumber, "1.5".into())]));
        assert_eq!(events(br#""s""#, 64), (NGX_OK, vec![(JsonEvent::ValueString, "s".into())]));
        assert_eq!(events(b"null", 64).0, NGX_OK);
        assert_eq!(events(b"", 64).0, NGX_DECLINED);
    }

    #[test]
    fn test_parse_invalid() {
        for s in [
            &b"{bad"[..],
            br#"{"a":1"#,
            br#"{"a":01}"#,
            br#"{"a":1.}"#,
            br#"{"a":-z}"#,
            br#"{"a":1e}"#,
            br#"{"a":1e+}"#,
            br#"{"a":.5}"#,
            br#"{"a":tru}"#,
            br#"{"a":fals}"#,
            br#"{"a":nul}"#,
            br#"{"a":?}"#,
            br#"{"a":1}x"#,
            br#"{"a":"\q"}"#,
            br#"{"a":"\uZZZZ"}"#,
            br#"{"a":"\uDEAD"}"#,
            br#"{"a":"\uD83Dz"}"#,
            br#"{"a":"\uD83D\n"}"#,
            br#"{"a":"\uD83DA"}"#,
            br#"{"a" 1}"#,
            br#"{"a":1 "b":2}"#,
            br#"[1 2]"#,
            b"[\"a\x01b\"]",
            b"[1,]",
            b"{,}",
        ] {
            assert_eq!(events(s, 64).0, NGX_DECLINED, "{}", String::from_utf8_lossy(s));
        }
    }

    #[test]
    fn test_parse_max_depth() {
        assert_eq!(events(b"[[[1]]]", 3).0, NGX_OK);
        assert_eq!(events(b"[[[[1]]]]", 3).0, NGX_DECLINED);
    }

    #[test]
    fn test_parse_skip() {
        use JsonEvent::*;

        // a key skipped with its value, a container skipped as a whole, and
        // the rest of an array after one of its values

        let json = br#"{"skip":{"x":[1,2]},"keep":[{"in":1},3,4],"k2":5}"#;
        let mut ev = Vec::new();

        let rc = parse(json, &mut |e, start, len| {
            let token = &json[start..start + len];
            ev.push((e, String::from_utf8_lossy(token).into_owned()));

            match (e, token) {
                (Key, b"skip") => NGX_JSON_SKIP,
                (ObjectOpen, b"{") if start == 28 => NGX_JSON_SKIP,
                (ValueNumber, b"3") => NGX_JSON_SKIP,
                _ => NGX_OK,
            }
        });

        assert_eq!(rc, NGX_OK);
        assert_eq!(
            ev,
            vec![
                (ObjectOpen, "{".into()),
                (Key, "skip".into()),
                (Key, "keep".into()),
                (ArrayOpen, "[".into()),
                (ObjectOpen, "{".into()),
                (ValueNumber, "3".into()),
                (Key, "k2".into()),
                (ValueNumber, "5".into()),
                (ObjectClose, "}".into()),
            ]
        );
    }

    #[test]
    fn test_parse_handler_error() {
        let rc = parse(b"[1,2]", &mut |e, _, _| if e == JsonEvent::ValueNumber { NGX_ERROR } else { NGX_OK });

        assert_eq!(rc, NGX_ERROR);
    }
}
