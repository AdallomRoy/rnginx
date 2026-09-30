//! ngx_http_v3_parse.c: the parsers of the request stream (headers and
//! data frames) and of the unidirectional streams (control, encoder and
//! decoder instructions).
//!
//! Parse functions return codes:
//!   NGX_DONE - parsing done
//!   NGX_OK - sub-element done
//!   NGX_AGAIN - more data expected
//!   NGX_BUSY - waiting for external event
//!   NGX_ERROR - internal error
//!   NGX_HTTP_V3_ERROR_XXX - HTTP/3 or QPACK error

use std::rc::Rc;

use ngx_core::connection::Connection;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use super::table;
use super::uni::{cancel_stream, register_uni_stream, send_ack_section};
use super::*;

/// ngx_buf_t of the parsers: data[pos..last] is to parse
pub struct PBuf<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    pub last: usize,
}

impl<'a> PBuf<'a> {
    pub fn new(data: &'a [u8]) -> PBuf<'a> {
        PBuf { data, pos: 0, last: data.len() }
    }
}

/// ngx_http_v3_is_v2_frame
fn is_v2_frame(ty: u64) -> bool {
    ty == 0x02 || ty == 0x06 || ty == 0x08 || ty == 0x09
}

/// ngx_http_v3_parse_varlen_int_t
#[derive(Default, Clone)]
pub struct ParseVarlenInt {
    pub state: u32,
    pub value: u64,
}

/// ngx_http_v3_parse_prefix_int_t
#[derive(Default, Clone)]
pub struct ParsePrefixInt {
    pub state: u32,
    pub shift: u32,
    pub value: u64,
}

/// ngx_http_v3_parse_settings_t
#[derive(Default, Clone)]
pub struct ParseSettings {
    pub state: u32,
    pub id: u64,
    pub vlint: ParseVarlenInt,
}

/// ngx_http_v3_parse_field_section_prefix_t
#[derive(Default, Clone)]
pub struct ParseFieldSectionPrefix {
    pub state: u32,
    pub insert_count: u64,
    pub delta_base: u64,
    pub sign: bool,
    pub base: u64,
    pub pint: ParsePrefixInt,
}

/// ngx_http_v3_parse_literal_t: `buf` is set when the literal is decoded
/// into the insert buffer of the dynamic table
#[derive(Default, Clone)]
pub struct ParseLiteral {
    pub state: u32,
    pub length: u64,
    pub huffman: bool,
    pub value: Vec<u8>,
    pub huffstate: u8,
    pub buf: bool,
}

/// ngx_http_v3_parse_field_t
#[derive(Default, Clone)]
pub struct ParseField {
    pub state: u32,
    pub index: u64,
    pub base: u64,
    pub dynamic: bool,

    pub name: Vec<u8>,
    pub value: Vec<u8>,

    pub pint: ParsePrefixInt,
    pub literal: ParseLiteral,
}

/// ngx_http_v3_parse_field_rep_t
#[derive(Default, Clone)]
pub struct ParseFieldRep {
    pub state: u32,
    pub field: ParseField,
}

/// ngx_http_v3_parse_headers_t
#[derive(Default, Clone)]
pub struct ParseHeaders {
    pub state: u32,
    pub ty: u64,
    pub length: u64,
    pub vlint: ParseVarlenInt,
    pub prefix: ParseFieldSectionPrefix,
    pub field_rep: ParseFieldRep,
}

/// ngx_http_v3_parse_encoder_t
#[derive(Default, Clone)]
pub struct ParseEncoder {
    pub state: u32,
    pub field: ParseField,
    pub pint: ParsePrefixInt,
}

/// ngx_http_v3_parse_decoder_t
#[derive(Default, Clone)]
pub struct ParseDecoder {
    pub state: u32,
    pub pint: ParsePrefixInt,
}

/// ngx_http_v3_parse_control_t
#[derive(Default, Clone)]
pub struct ParseControl {
    pub state: u32,
    pub ty: u64,
    pub length: u64,
    pub vlint: ParseVarlenInt,
    pub settings: ParseSettings,
}

/// ngx_http_v3_parse_uni_t (the union as separate members)
#[derive(Default, Clone)]
pub struct ParseUni {
    pub state: u32,
    pub vlint: ParseVarlenInt,
    pub encoder: ParseEncoder,
    pub decoder: ParseDecoder,
    pub control: ParseControl,
}

/// ngx_http_v3_parse_data_t
#[derive(Default, Clone)]
pub struct ParseData {
    pub state: u32,
    pub ty: u64,
    pub length: u64,
    pub vlint: ParseVarlenInt,
}

/// ngx_http_v3_parse_start_local
fn start_local<'a>(b: &PBuf<'a>, n: u64) -> PBuf<'a> {
    let mut loc = PBuf { data: b.data, pos: b.pos, last: b.last };

    if (loc.last - loc.pos) as u64 > n {
        loc.last = loc.pos + n as usize;
    }

    loc
}

/// ngx_http_v3_parse_end_local
fn end_local(b: &mut PBuf<'_>, loc: &PBuf<'_>, pn: &mut u64) {
    *pn -= (loc.pos - b.pos) as u64;
    b.pos = loc.pos;
}

/// ngx_http_v3_parse_skip
fn parse_skip(b: &mut PBuf<'_>, length: &mut u64) -> i64 {
    if ((b.last - b.pos) as u64) < *length {
        *length -= (b.last - b.pos) as u64;
        b.pos = b.last;
        return NGX_AGAIN;
    }

    b.pos += *length as usize;
    NGX_DONE
}

/// ngx_http_v3_parse_varlen_int
fn parse_varlen_int(c: &Connection, st: &mut ParseVarlenInt, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_LENGTH_2: u32 = 1;
    const SW_LENGTH_3: u32 = 2;
    const SW_LENGTH_4: u32 = 3;
    const SW_LENGTH_5: u32 = 4;
    const SW_LENGTH_6: u32 = 5;
    const SW_LENGTH_7: u32 = 6;
    const SW_LENGTH_8: u32 = 7;

    loop {
        if b.pos == b.last {
            return NGX_AGAIN;
        }

        let ch = b.data[b.pos] as u64;
        b.pos += 1;

        match st.state {
            SW_START => {
                st.value = ch;
                if st.value & 0xc0 != 0 {
                    st.state = SW_LENGTH_2;
                    continue;
                }

                break;
            }

            SW_LENGTH_2 => {
                st.value = (st.value << 8) + ch;
                if st.value & 0xc000 == 0x4000 {
                    st.value &= 0x3fff;
                    break;
                }

                st.state = SW_LENGTH_3;
            }

            SW_LENGTH_4 => {
                st.value = (st.value << 8) + ch;
                if st.value & 0xc0000000 == 0x80000000 {
                    st.value &= 0x3fffffff;
                    break;
                }

                st.state = SW_LENGTH_5;
            }

            SW_LENGTH_3 | SW_LENGTH_5 | SW_LENGTH_6 | SW_LENGTH_7 => {
                st.value = (st.value << 8) + ch;
                st.state += 1;
            }

            SW_LENGTH_8 => {
                st.value = (st.value << 8) + ch;
                st.value &= 0x3fffffffffffffff;
                break;
            }

            _ => {}
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse varlen int {}", st.value);

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_prefix_int
fn parse_prefix_int(c: &Connection, st: &mut ParsePrefixInt, prefix: u32, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_VALUE: u32 = 1;

    loop {
        if b.pos == b.last {
            return NGX_AGAIN;
        }

        let ch = b.data[b.pos];
        b.pos += 1;

        match st.state {
            SW_START => {
                let mask = (1u64 << prefix) - 1;
                st.value = ch as u64 & mask;

                if st.value != mask {
                    break;
                }

                st.shift = 0;
                st.state = SW_VALUE;
            }

            _ => {
                st.value = st.value.wrapping_add(((ch & 0x7f) as u64) << st.shift);

                if st.shift == 56 && (ch & 0x80 != 0 || st.value & 0xc000000000000000 != 0) {
                    ngx_log_error!(NGX_LOG_INFO, c.log, None, "client exceeded integer size limit");
                    return NGX_HTTP_V3_ERR_EXCESSIVE_LOAD as i64;
                }

                if ch & 0x80 != 0 {
                    st.shift += 7;
                    continue;
                }

                break;
            }
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse prefix int {}", st.value);

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_headers
pub fn parse_headers(c: &Rc<Connection>, st: &mut ParseHeaders, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_TYPE: u32 = 1;
    const SW_LENGTH: u32 = 2;
    const SW_SKIP: u32 = 3;
    const SW_PREFIX: u32 = 4;
    const SW_VERIFY: u32 = 5;
    const SW_FIELD_REP: u32 = 6;

    loop {
        match st.state {
            SW_START | SW_TYPE => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse headers");

                    st.state = SW_TYPE;
                }

                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.ty = st.vlint.value;

                if is_v2_frame(st.ty)
                    || st.ty == NGX_HTTP_V3_FRAME_DATA
                    || st.ty == NGX_HTTP_V3_FRAME_GOAWAY
                    || st.ty == NGX_HTTP_V3_FRAME_SETTINGS
                    || st.ty == NGX_HTTP_V3_FRAME_MAX_PUSH_ID
                    || st.ty == NGX_HTTP_V3_FRAME_CANCEL_PUSH
                    || st.ty == NGX_HTTP_V3_FRAME_PUSH_PROMISE
                {
                    return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED as i64;
                }

                st.state = SW_LENGTH;
            }

            SW_LENGTH => {
                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.length = st.vlint.value;

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse headers type:{}, len:{}", st.ty, st.length);

                if st.ty != NGX_HTTP_V3_FRAME_HEADERS {
                    st.state = if st.length > 0 { SW_SKIP } else { SW_TYPE };
                    continue;
                }

                if st.length == 0 {
                    return NGX_HTTP_V3_ERR_FRAME_ERROR as i64;
                }

                st.state = SW_PREFIX;
            }

            SW_SKIP => {
                let rc = parse_skip(b, &mut st.length);
                if rc != NGX_DONE {
                    return rc;
                }

                st.state = SW_TYPE;
            }

            SW_PREFIX => {
                let mut loc = start_local(b, st.length);

                let rc = parse_field_section_prefix(c, &mut st.prefix, &mut loc);

                end_local(b, &loc, &mut st.length);

                if st.length == 0 && rc == NGX_AGAIN {
                    return NGX_HTTP_V3_ERR_FRAME_ERROR as i64;
                }

                if rc != NGX_DONE {
                    return rc;
                }

                st.state = SW_VERIFY;
            }

            SW_VERIFY | SW_FIELD_REP => {
                if st.state == SW_VERIFY {
                    let rc = table::check_insert_count(c, st.prefix.insert_count);
                    if rc != NGX_OK {
                        return rc;
                    }

                    st.state = SW_FIELD_REP;
                }

                let mut loc = start_local(b, st.length);

                let base = st.prefix.base;

                let rc = parse_field_rep(c, &mut st.field_rep, base, &mut loc);

                end_local(b, &loc, &mut st.length);

                if st.length == 0 && rc == NGX_AGAIN {
                    return NGX_HTTP_V3_ERR_FRAME_ERROR as i64;
                }

                if rc != NGX_DONE {
                    return rc;
                }

                if st.length == 0 {
                    break;
                }

                return NGX_OK;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse headers done");

    if st.prefix.insert_count > 0 {
        let id = ngx_core::quic::streams::ngx_quic_stream(c).map(|qs| qs.id).unwrap_or(0);

        if send_ack_section(c, id) != NGX_OK {
            return NGX_ERROR;
        }

        table::ack_insert_count(c, st.prefix.insert_count);
    }

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_field_section_prefix
fn parse_field_section_prefix(c: &Rc<Connection>, st: &mut ParseFieldSectionPrefix, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_REQ_INSERT_COUNT: u32 = 1;
    const SW_DELTA_BASE: u32 = 2;
    const SW_READ_DELTA_BASE: u32 = 3;

    loop {
        match st.state {
            SW_START | SW_REQ_INSERT_COUNT => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field section prefix");

                    st.state = SW_REQ_INSERT_COUNT;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 8, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.insert_count = st.pint.value;
                st.state = SW_DELTA_BASE;
            }

            SW_DELTA_BASE | SW_READ_DELTA_BASE => {
                if st.state == SW_DELTA_BASE {
                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.sign = ch & 0x80 != 0;
                    st.state = SW_READ_DELTA_BASE;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 7, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.delta_base = st.pint.value;
                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    let rc = table::decode_insert_count(c, &mut st.insert_count);
    if rc != NGX_OK {
        return rc;
    }

    if st.sign {
        if st.insert_count <= st.delta_base {
            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent negative base");
            return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED as i64;
        }

        st.base = st.insert_count - st.delta_base - 1;
    } else {
        st.base = st.insert_count.wrapping_add(st.delta_base);
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field section prefix done insert_count:{}, sign:{}, delta_base:{}, base:{}", st.insert_count, st.sign as u32, st.delta_base, st.base);

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_field_rep
fn parse_field_rep(c: &Rc<Connection>, st: &mut ParseFieldRep, base: u64, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_FIELD_RI: u32 = 1;
    const SW_FIELD_LRI: u32 = 2;
    const SW_FIELD_L: u32 = 3;
    const SW_FIELD_PBI: u32 = 4;
    const SW_FIELD_LPBI: u32 = 5;

    if st.state == SW_START {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field representation");

        if b.pos == b.last {
            return NGX_AGAIN;
        }

        let ch = b.data[b.pos];

        st.field = ParseField::default();

        st.field.base = base;

        st.state = if ch & 0x80 != 0 {
            /* Indexed Field Line */
            SW_FIELD_RI
        } else if ch & 0x40 != 0 {
            /* Literal Field Line With Name Reference */
            SW_FIELD_LRI
        } else if ch & 0x20 != 0 {
            /* Literal Field Line With Literal Name */
            SW_FIELD_L
        } else if ch & 0x10 != 0 {
            /* Indexed Field Line With Post-Base Index */
            SW_FIELD_PBI
        } else {
            /* Literal Field Line With Post-Base Name Reference */
            SW_FIELD_LPBI
        };
    }

    let rc = match st.state {
        SW_FIELD_RI => parse_field_ri(c, &mut st.field, b),
        SW_FIELD_LRI => parse_field_lri(c, &mut st.field, b),
        SW_FIELD_L => parse_field_l(c, &mut st.field, b),
        SW_FIELD_PBI => parse_field_pbi(c, &mut st.field, b),
        SW_FIELD_LPBI => parse_field_lpbi(c, &mut st.field, b),
        _ => NGX_OK,
    };

    if rc != NGX_DONE {
        return rc;
    }

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field representation done");

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_literal
fn parse_literal(c: &Rc<Connection>, st: &mut ParseLiteral, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_VALUE: u32 = 1;

    loop {
        match st.state {
            SW_START | SW_VALUE => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse literal huff:{}, len:{}", st.huffman as u32, st.length);

                    let mut n = st.length;

                    let size = match quic_get_connection(c) {
                        Some(hc) => crate::core::srv_conf_from_ctx(&hc.conf_ctx.borrow()).borrow().large_client_header_buffers.size,
                        None => return NGX_ERROR,
                    };

                    if n > size as u64 {
                        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent too large field line");
                        return NGX_HTTP_V3_ERR_EXCESSIVE_LOAD as i64;
                    }

                    if st.huffman {
                        if n > i64::MAX as u64 / 8 {
                            ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent too large field line");
                            return NGX_HTTP_V3_ERR_EXCESSIVE_LOAD as i64;
                        }

                        n = n * 8 / 5;
                        st.huffstate = 0;
                    }

                    if st.buf {
                        if !table::insert_buffer_alloc(c, n as usize + 1) {
                            ngx_log_error!(NGX_LOG_INFO, c.log, None, "not enough dynamic table capacity");

                            return NGX_ERROR;
                        }
                    }

                    st.value = Vec::with_capacity(n as usize + 1);
                    st.state = SW_VALUE;
                }

                if b.pos == b.last {
                    return NGX_AGAIN;
                }

                let ch = b.data[b.pos];
                b.pos += 1;

                if st.huffman {
                    if crate::huff_decode::huff_decode(&mut st.huffstate, &[ch], &mut st.value, st.length == 1, &c.log).is_err() {
                        ngx_log_error!(NGX_LOG_INFO, c.log, None, "client sent invalid encoded field line");
                        return NGX_ERROR;
                    }
                } else {
                    st.value.push(ch);
                }

                st.length -= 1;

                if st.length != 0 {
                    continue;
                }

                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse literal done \"{}\"", B(&st.value));

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_field_ri
fn parse_field_ri(c: &Rc<Connection>, st: &mut ParseField, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_INDEX: u32 = 1;

    loop {
        match st.state {
            SW_START | SW_INDEX => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field ri");

                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.dynamic = ch & 0x40 == 0;
                    st.state = SW_INDEX;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 6, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.index = st.pint.value;
                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field ri done {}{}]", if st.dynamic { "dynamic[-" } else { "static[" }, st.index);

    if st.dynamic {
        st.index = st.base.wrapping_sub(st.index).wrapping_sub(1);
    }

    let rc = parse_lookup(c, st.dynamic, st.index, true, true, &mut st.name, &mut st.value);
    if rc != NGX_OK {
        return rc;
    }

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_field_lri
fn parse_field_lri(c: &Rc<Connection>, st: &mut ParseField, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_INDEX: u32 = 1;
    const SW_VALUE_LEN: u32 = 2;
    const SW_READ_VALUE_LEN: u32 = 3;
    const SW_VALUE: u32 = 4;

    loop {
        match st.state {
            SW_START | SW_INDEX => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field lri");

                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.dynamic = ch & 0x10 == 0;
                    st.state = SW_INDEX;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 4, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.index = st.pint.value;
                st.state = SW_VALUE_LEN;
            }

            SW_VALUE_LEN | SW_READ_VALUE_LEN => {
                if st.state == SW_VALUE_LEN {
                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.literal.huffman = ch & 0x80 != 0;
                    st.state = SW_READ_VALUE_LEN;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 7, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.literal.length = st.pint.value;
                if st.literal.length == 0 {
                    st.value = Vec::new();
                    break;
                }

                st.state = SW_VALUE;
            }

            SW_VALUE => {
                let rc = parse_literal(c, &mut st.literal, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.value = std::mem::take(&mut st.literal.value);
                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field lri done {}{}] \"{}\"", if st.dynamic { "dynamic[-" } else { "static[" }, st.index, B(&st.value));

    if st.dynamic {
        st.index = st.base.wrapping_sub(st.index).wrapping_sub(1);
    }

    let mut unused = Vec::new();

    let rc = parse_lookup(c, st.dynamic, st.index, true, false, &mut st.name, &mut unused);
    if rc != NGX_OK {
        return rc;
    }

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_field_l
fn parse_field_l(c: &Rc<Connection>, st: &mut ParseField, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_NAME_LEN: u32 = 1;
    const SW_NAME: u32 = 2;
    const SW_VALUE_LEN: u32 = 3;
    const SW_READ_VALUE_LEN: u32 = 4;
    const SW_VALUE: u32 = 5;

    loop {
        match st.state {
            SW_START | SW_NAME_LEN => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field l");

                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.literal.huffman = ch & 0x08 != 0;
                    st.state = SW_NAME_LEN;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 3, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.literal.length = st.pint.value;
                if st.literal.length == 0 {
                    return NGX_ERROR;
                }

                st.state = SW_NAME;
            }

            SW_NAME => {
                let rc = parse_literal(c, &mut st.literal, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.name = std::mem::take(&mut st.literal.value);
                st.state = SW_VALUE_LEN;
            }

            SW_VALUE_LEN | SW_READ_VALUE_LEN => {
                if st.state == SW_VALUE_LEN {
                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.literal.huffman = ch & 0x80 != 0;
                    st.state = SW_READ_VALUE_LEN;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 7, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.literal.length = st.pint.value;
                if st.literal.length == 0 {
                    st.value = Vec::new();
                    break;
                }

                st.state = SW_VALUE;
            }

            SW_VALUE => {
                let rc = parse_literal(c, &mut st.literal, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.value = std::mem::take(&mut st.literal.value);
                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field l done \"{}\" \"{}\"", B(&st.name), B(&st.value));

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_field_pbi
fn parse_field_pbi(c: &Rc<Connection>, st: &mut ParseField, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_INDEX: u32 = 1;

    loop {
        match st.state {
            SW_START | SW_INDEX => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field pbi");

                    st.state = SW_INDEX;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 4, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.index = st.pint.value;
                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field pbi done dynamic[+{}]", st.index);

    let index = st.base.wrapping_add(st.index);

    let rc = parse_lookup(c, true, index, true, true, &mut st.name, &mut st.value);
    if rc != NGX_OK {
        return rc;
    }

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_field_lpbi
fn parse_field_lpbi(c: &Rc<Connection>, st: &mut ParseField, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_INDEX: u32 = 1;
    const SW_VALUE_LEN: u32 = 2;
    const SW_READ_VALUE_LEN: u32 = 3;
    const SW_VALUE: u32 = 4;

    loop {
        match st.state {
            SW_START | SW_INDEX => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field lpbi");

                    st.state = SW_INDEX;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 3, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.index = st.pint.value;
                st.state = SW_VALUE_LEN;
            }

            SW_VALUE_LEN | SW_READ_VALUE_LEN => {
                if st.state == SW_VALUE_LEN {
                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.literal.huffman = ch & 0x80 != 0;
                    st.state = SW_READ_VALUE_LEN;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 7, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.literal.length = st.pint.value;
                if st.literal.length == 0 {
                    st.value = Vec::new();
                    break;
                }

                st.state = SW_VALUE;
            }

            SW_VALUE => {
                let rc = parse_literal(c, &mut st.literal, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.value = std::mem::take(&mut st.literal.value);
                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field lpbi done dynamic[+{}] \"{}\"", st.index, B(&st.value));

    let index = st.base.wrapping_add(st.index);

    let mut unused = Vec::new();

    let rc = parse_lookup(c, true, index, true, false, &mut st.name, &mut unused);
    if rc != NGX_OK {
        return rc;
    }

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_lookup: the name (and the value, if asked) of a
/// table entry
fn parse_lookup(c: &Rc<Connection>, dynamic: bool, index: u64, want_name: bool, want_value: bool, name: &mut Vec<u8>, value: &mut Vec<u8>) -> i64 {
    let field = if !dynamic { table::lookup_static(c, index) } else { table::lookup(c, index) };

    let field = match field {
        Some(f) => f,
        None => return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED as i64,
    };

    if want_name {
        *name = field.name;
    }

    if want_value {
        *value = field.value;
    }

    NGX_OK
}

/// ngx_http_v3_parse_control
fn parse_control(c: &Rc<Connection>, st: &mut ParseControl, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_FIRST_TYPE: u32 = 1;
    const SW_TYPE: u32 = 2;
    const SW_LENGTH: u32 = 3;
    const SW_SETTINGS: u32 = 4;
    const SW_SKIP: u32 = 5;

    loop {
        match st.state {
            SW_START | SW_FIRST_TYPE | SW_TYPE => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse control");

                    st.state = SW_FIRST_TYPE;
                }

                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.ty = st.vlint.value;

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse frame type:{}", st.ty);

                if st.state == SW_FIRST_TYPE && st.ty != NGX_HTTP_V3_FRAME_SETTINGS {
                    return NGX_HTTP_V3_ERR_MISSING_SETTINGS as i64;
                }

                if st.state != SW_FIRST_TYPE && st.ty == NGX_HTTP_V3_FRAME_SETTINGS {
                    return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED as i64;
                }

                if is_v2_frame(st.ty) || st.ty == NGX_HTTP_V3_FRAME_DATA || st.ty == NGX_HTTP_V3_FRAME_HEADERS || st.ty == NGX_HTTP_V3_FRAME_PUSH_PROMISE {
                    return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED as i64;
                }

                if st.ty == NGX_HTTP_V3_FRAME_CANCEL_PUSH {
                    return NGX_HTTP_V3_ERR_ID_ERROR as i64;
                }

                st.state = SW_LENGTH;
            }

            SW_LENGTH => {
                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse frame len:{}", st.vlint.value);

                st.length = st.vlint.value;
                if st.length == 0 {
                    st.state = SW_TYPE;
                    continue;
                }

                match st.ty {
                    NGX_HTTP_V3_FRAME_SETTINGS => st.state = SW_SETTINGS,

                    _ => {
                        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse skip unknown frame");
                        st.state = SW_SKIP;
                    }
                }
            }

            SW_SETTINGS => {
                let mut loc = start_local(b, st.length);

                let rc = parse_settings(c, &mut st.settings, &mut loc);

                end_local(b, &loc, &mut st.length);

                if st.length == 0 && rc == NGX_AGAIN {
                    return NGX_HTTP_V3_ERR_SETTINGS_ERROR as i64;
                }

                if rc != NGX_DONE {
                    return rc;
                }

                if st.length == 0 {
                    st.state = SW_TYPE;
                }
            }

            SW_SKIP => {
                let rc = parse_skip(b, &mut st.length);
                if rc != NGX_DONE {
                    return rc;
                }

                st.state = SW_TYPE;
            }

            _ => return NGX_ERROR,
        }
    }
}

/// ngx_http_v3_parse_settings
fn parse_settings(c: &Rc<Connection>, st: &mut ParseSettings, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_ID: u32 = 1;
    const SW_VALUE: u32 = 2;

    loop {
        match st.state {
            SW_START | SW_ID => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse settings");

                    st.state = SW_ID;
                }

                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.id = st.vlint.value;
                st.state = SW_VALUE;
            }

            SW_VALUE => {
                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                if table::set_param(c, st.id, st.vlint.value) != NGX_OK {
                    return NGX_HTTP_V3_ERR_SETTINGS_ERROR as i64;
                }

                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse settings done");

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_encoder
fn parse_encoder(c: &Rc<Connection>, st: &mut ParseEncoder, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_INR: u32 = 1;
    const SW_ILN: u32 = 2;
    const SW_CAPACITY: u32 = 3;
    const SW_DUPLICATE: u32 = 4;

    loop {
        if st.state == SW_START {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse encoder instruction");

            if b.pos == b.last {
                return NGX_AGAIN;
            }

            let ch = b.data[b.pos];

            st.state = if ch & 0x80 != 0 {
                /* Insert With Name Reference */
                SW_INR
            } else if ch & 0x40 != 0 {
                /* Insert With Literal Name */
                SW_ILN
            } else if ch & 0x20 != 0 {
                /* Set Dynamic Table Capacity */
                SW_CAPACITY
            } else {
                /* Duplicate */
                SW_DUPLICATE
            };
        }

        match st.state {
            SW_INR => {
                let rc = parse_field_inr(c, &mut st.field, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.state = SW_START;
            }

            SW_ILN => {
                let rc = parse_field_iln(c, &mut st.field, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.state = SW_START;
            }

            SW_CAPACITY => {
                let rc = parse_prefix_int(c, &mut st.pint, 5, b);
                if rc != NGX_DONE {
                    return rc;
                }

                let rc = table::set_capacity(c, st.pint.value);
                if rc != NGX_OK {
                    return rc;
                }

                st.state = SW_START;
            }

            _ => {
                /* sw_duplicate */

                let rc = parse_prefix_int(c, &mut st.pint, 5, b);
                if rc != NGX_DONE {
                    return rc;
                }

                let rc = table::duplicate(c, st.pint.value);
                if rc != NGX_OK {
                    return rc;
                }

                st.state = SW_START;
            }
        }
    }
}

/// ngx_http_v3_parse_field_inr
fn parse_field_inr(c: &Rc<Connection>, st: &mut ParseField, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_NAME_INDEX: u32 = 1;
    const SW_VALUE_LEN: u32 = 2;
    const SW_READ_VALUE_LEN: u32 = 3;
    const SW_VALUE: u32 = 4;

    loop {
        match st.state {
            SW_START | SW_NAME_INDEX => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field inr");

                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    if table::get_insert_buffer(c).is_none() {
                        return NGX_ERROR;
                    }

                    st.literal.buf = true;

                    st.dynamic = ch & 0x40 == 0;
                    st.state = SW_NAME_INDEX;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 6, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.index = st.pint.value;
                st.state = SW_VALUE_LEN;
            }

            SW_VALUE_LEN | SW_READ_VALUE_LEN => {
                if st.state == SW_VALUE_LEN {
                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.literal.huffman = ch & 0x80 != 0;
                    st.state = SW_READ_VALUE_LEN;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 7, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.literal.length = st.pint.value;
                if st.literal.length == 0 {
                    st.value = Vec::new();
                    break;
                }

                st.state = SW_VALUE;
            }

            SW_VALUE => {
                let rc = parse_literal(c, &mut st.literal, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.value = std::mem::take(&mut st.literal.value);
                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field inr done {}[{}] \"{}\"", if st.dynamic { "dynamic" } else { "static" }, st.index, B(&st.value));

    let rc = table::ref_insert(c, st.dynamic, st.index, &st.value);
    if rc != NGX_OK {
        return rc;
    }

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_field_iln
fn parse_field_iln(c: &Rc<Connection>, st: &mut ParseField, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_NAME_LEN: u32 = 1;
    const SW_NAME: u32 = 2;
    const SW_VALUE_LEN: u32 = 3;
    const SW_READ_VALUE_LEN: u32 = 4;
    const SW_VALUE: u32 = 5;

    loop {
        match st.state {
            SW_START | SW_NAME_LEN => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field iln");

                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    if table::get_insert_buffer(c).is_none() {
                        return NGX_ERROR;
                    }

                    st.literal.buf = true;

                    st.literal.huffman = ch & 0x20 != 0;
                    st.state = SW_NAME_LEN;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 5, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.literal.length = st.pint.value;
                if st.literal.length == 0 {
                    return NGX_ERROR;
                }

                st.state = SW_NAME;
            }

            SW_NAME => {
                let rc = parse_literal(c, &mut st.literal, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.name = std::mem::take(&mut st.literal.value);
                st.state = SW_VALUE_LEN;
            }

            SW_VALUE_LEN | SW_READ_VALUE_LEN => {
                if st.state == SW_VALUE_LEN {
                    if b.pos == b.last {
                        return NGX_AGAIN;
                    }

                    let ch = b.data[b.pos];

                    st.literal.huffman = ch & 0x80 != 0;
                    st.state = SW_READ_VALUE_LEN;
                }

                let rc = parse_prefix_int(c, &mut st.pint, 7, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.literal.length = st.pint.value;
                if st.literal.length == 0 {
                    st.value = Vec::new();
                    break;
                }

                st.state = SW_VALUE;
            }

            SW_VALUE => {
                let rc = parse_literal(c, &mut st.literal, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.value = std::mem::take(&mut st.literal.value);
                break;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse field iln done \"{}\":\"{}\"", B(&st.name), B(&st.value));

    let rc = table::insert(c, &st.name, &st.value);
    if rc != NGX_OK {
        return rc;
    }

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_decoder
fn parse_decoder(c: &Rc<Connection>, st: &mut ParseDecoder, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_ACK_SECTION: u32 = 1;
    const SW_CANCEL_STREAM: u32 = 2;
    const SW_INC_INSERT_COUNT: u32 = 3;

    loop {
        if st.state == SW_START {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse decoder instruction");

            if b.pos == b.last {
                return NGX_AGAIN;
            }

            let ch = b.data[b.pos];

            st.state = if ch & 0x80 != 0 {
                /* Section Acknowledgment */
                SW_ACK_SECTION
            } else if ch & 0x40 != 0 {
                /*  Stream Cancellation */
                SW_CANCEL_STREAM
            } else {
                /*  Insert Count Increment */
                SW_INC_INSERT_COUNT
            };
        }

        match st.state {
            SW_ACK_SECTION => {
                let rc = parse_prefix_int(c, &mut st.pint, 7, b);
                if rc != NGX_DONE {
                    return rc;
                }

                let rc = table::ack_section(c, st.pint.value);
                if rc != NGX_OK {
                    return rc;
                }

                st.state = SW_START;
            }

            SW_CANCEL_STREAM => {
                let rc = parse_prefix_int(c, &mut st.pint, 6, b);
                if rc != NGX_DONE {
                    return rc;
                }

                let rc = cancel_stream(c, st.pint.value);
                if rc != NGX_OK {
                    return rc;
                }

                st.state = SW_START;
            }

            SW_INC_INSERT_COUNT => {
                let rc = parse_prefix_int(c, &mut st.pint, 6, b);
                if rc != NGX_DONE {
                    return rc;
                }

                let rc = table::inc_insert_count(c, st.pint.value);
                if rc != NGX_OK {
                    return rc;
                }

                st.state = SW_START;
            }

            _ => return NGX_ERROR,
        }
    }
}

/// ngx_http_v3_parse_data
pub fn parse_data(c: &Connection, st: &mut ParseData, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_TYPE: u32 = 1;
    const SW_LENGTH: u32 = 2;
    const SW_SKIP: u32 = 3;

    loop {
        match st.state {
            SW_START | SW_TYPE => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse data");

                    st.state = SW_TYPE;
                }

                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.ty = st.vlint.value;

                if st.ty == NGX_HTTP_V3_FRAME_HEADERS {
                    /* trailers */
                    break;
                }

                if is_v2_frame(st.ty)
                    || st.ty == NGX_HTTP_V3_FRAME_GOAWAY
                    || st.ty == NGX_HTTP_V3_FRAME_SETTINGS
                    || st.ty == NGX_HTTP_V3_FRAME_MAX_PUSH_ID
                    || st.ty == NGX_HTTP_V3_FRAME_CANCEL_PUSH
                    || st.ty == NGX_HTTP_V3_FRAME_PUSH_PROMISE
                {
                    return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED as i64;
                }

                st.state = SW_LENGTH;
            }

            SW_LENGTH => {
                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                st.length = st.vlint.value;

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse data type:{}, len:{}", st.ty, st.length);

                if st.ty != NGX_HTTP_V3_FRAME_DATA && st.length > 0 {
                    st.state = SW_SKIP;
                    continue;
                }

                st.state = SW_TYPE;
                return NGX_OK;
            }

            SW_SKIP => {
                let rc = parse_skip(b, &mut st.length);
                if rc != NGX_DONE {
                    return rc;
                }

                st.state = SW_TYPE;
            }

            _ => return NGX_ERROR,
        }
    }

    // done:

    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse data done");

    st.state = SW_START;
    NGX_DONE
}

/// ngx_http_v3_parse_uni: `index` is the us->index of the stream
pub fn parse_uni(c: &Rc<Connection>, st: &mut ParseUni, index: &mut i64, b: &mut PBuf<'_>) -> i64 {
    const SW_START: u32 = 0;
    const SW_TYPE: u32 = 1;
    const SW_CONTROL: u32 = 2;
    const SW_ENCODER: u32 = 3;
    const SW_DECODER: u32 = 4;
    const SW_UNKNOWN: u32 = 5;

    loop {
        match st.state {
            SW_START | SW_TYPE => {
                if st.state == SW_START {
                    ngx_log_debug!(NGX_LOG_DEBUG_HTTP, c.log, "http3 parse uni");

                    st.state = SW_TYPE;
                }

                let rc = parse_varlen_int(c, &mut st.vlint, b);
                if rc != NGX_DONE {
                    return rc;
                }

                let rc = register_uni_stream(c, index, st.vlint.value);
                if rc != NGX_OK {
                    return rc;
                }

                st.state = match st.vlint.value {
                    NGX_HTTP_V3_STREAM_CONTROL => SW_CONTROL,
                    NGX_HTTP_V3_STREAM_ENCODER => SW_ENCODER,
                    NGX_HTTP_V3_STREAM_DECODER => SW_DECODER,
                    _ => SW_UNKNOWN,
                };
            }

            SW_CONTROL => return parse_control(c, &mut st.control, b),

            SW_ENCODER => return parse_encoder(c, &mut st.encoder, b),

            SW_DECODER => return parse_decoder(c, &mut st.decoder, b),

            SW_UNKNOWN => {
                b.pos = b.last;
                return NGX_AGAIN;
            }

            _ => return NGX_ERROR,
        }
    }
}
