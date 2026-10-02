//! ngx_http_charset_filter_module.c: the charset of the response, and the
//! recoding of its body between the charsets of a charset_map (one byte
//! charsets, and to or from utf-8).

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::*;

crate::http_module_index!("ngx_http_charset_filter_module");

const NGX_HTTP_CHARSET_OFF: i64 = -2;
const NGX_HTTP_NO_CHARSET: i64 = -3;
const NGX_HTTP_CHARSET_VAR: i64 = 0x10000;

/// NGX_CONF_UNSET of the charset slots
const CHARSET_UNSET: i64 = -1;

/// 1 byte length and up to 3 bytes for the UTF-8 encoding of the UCS-2
const NGX_UTF_LEN: usize = 4;

/// The tables of a charset_map: from a one byte charset to another, or to
/// and from utf-8.
enum Table {
    /// one byte to one byte
    Byte(Box<[u8; 256]>),
    /// one byte to utf-8: 256 entries of NGX_UTF_LEN bytes, the length
    /// and up to 3 bytes of the encoding
    ToUtf8(Box<[u8; 256 * NGX_UTF_LEN]>),
    /// utf-8 (a UCS-2 value) to one byte: 256 pages of 256 values
    FromUtf8(Box<[Option<Box<[u8; 256]>>; 256]>),
}

/// ngx_http_charset_t
struct Charset {
    /// tables[dst]: the table from this charset to charset dst
    tables: Option<Vec<Option<Rc<RefCell<Table>>>>>,
    name: Vec<u8>,
    length: u32,
    utf8: bool,
}

/// ngx_http_charset_tables_t
struct CharsetTables {
    src: usize,
    dst: usize,
    src2dst: Rc<RefCell<Table>>,
    dst2src: Rc<RefCell<Table>>,
}

/// ngx_http_charset_main_conf_t
#[derive(Default)]
pub struct CharsetMainConf {
    charsets: Vec<Charset>,
    tables: Vec<CharsetTables>,
    /// ngx_http_charset_recode_t: src, dst
    recodes: Vec<(i64, i64)>,
}

/// ngx_http_charset_loc_conf_t
pub struct CharsetLocConf {
    charset: i64,
    source_charset: i64,
    override_charset: Val<bool>,
    /// types_keys: None unset, Some(vec![]) with "*" (any type)
    types: Option<Vec<Vec<u8>>>,
    any_type: bool,
}

/// ngx_http_charset_ctx_t
struct CharsetCtx {
    table: Option<Rc<RefCell<Table>>>,
    charset: i64,
    charset_name: Vec<u8>,
    saved: [u8; NGX_UTF_LEN],
    saved_len: usize,
    length: u32,
    from_utf8: bool,
    to_utf8: bool,
}

/// ngx_http_charset_default_types
const DEFAULT_TYPES: &[&[u8]] = &[b"text/html", b"text/xml", b"text/plain", b"text/vnd.wap.wml", b"application/javascript", b"application/rss+xml"];

pub fn charset_filter_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(charset_postconfiguration),
        create_main_conf: Some(charset_create_main_conf),
        create_loc_conf: Some(charset_create_loc_conf),
        merge_loc_conf: Some(charset_merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("charset", F | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_charset_slot),
        ngx_core::cmd_fn!("source_charset", F | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_source_charset_slot),
        ngx_core::cmd!("override_charset", F | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, ConfLevel::Loc, CharsetLocConf, override_charset, set_flag),
        ngx_core::cmd_fn!("charset_types", F | NGX_CONF_1MORE, ConfLevel::Loc, charset_types_slot),
        ngx_core::cmd_fn!("charset_map", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, charset_map_block),
    ];
    http_module_def("ngx_http_charset_filter_module", def, commands)
}

/// ngx_http_charset_header_filter
/// charset_header_filter passes the response of the main request on as it
/// is: ngx_http_destination_charset() declines at once, without a content
/// type, or with charset off and no charset to override
fn charset_header_idle(r: &R) -> bool {
    if !r.is_main() {
        return false;
    }

    {
        let ho = r.headers_out.borrow();

        if ho.content_type.is_empty() {
            return true;
        }

        if ho.override_charset.as_ref().is_some_and(|o| !o.is_empty()) {
            return false;
        }
    }

    r.loc_conf::<CharsetLocConf>(ctx_index()).borrow().charset == NGX_HTTP_CHARSET_OFF
}

async fn charset_header_filter(r: R, next: HeaderFilter) -> i64 {
    let mut dst = Vec::new();

    let charset = if r.is_main() { destination_charset(&r, &mut dst) } else { main_request_charset(&r, &mut dst) };

    if charset == NGX_ERROR {
        return NGX_ERROR;
    }

    if charset == NGX_DECLINED {
        return next(r).await;
    }

    /* charset: charset index or NGX_HTTP_NO_CHARSET */

    let mut src = Vec::new();

    let source_charset = source_charset(&r, &mut src);

    if source_charset == NGX_ERROR {
        return NGX_ERROR;
    }

    /*
     * source_charset: charset index, NGX_HTTP_NO_CHARSET,
     *                 or NGX_HTTP_CHARSET_OFF
     */

    http_debug!(r, "charset: \"{}\" > \"{}\"", B(&src), B(&dst));

    if source_charset == NGX_HTTP_CHARSET_OFF {
        set_charset(&r, &dst);
        return next(r).await;
    }

    if charset == NGX_HTTP_NO_CHARSET || source_charset == NGX_HTTP_NO_CHARSET {
        if source_charset != charset || dst.len() > src.len() || !dst.eq_ignore_ascii_case(&src[..dst.len()]) {
            return no_charset_map(r, next, &src, &dst).await;
        }

        set_charset(&r, &dst);
        return next(r).await;
    }

    if source_charset == charset {
        {
            let mut ho = r.headers_out.borrow_mut();
            let len = ho.content_type_len;
            ho.content_type.truncate(len);
        }

        set_charset(&r, &dst);
        return next(r).await;
    }

    /* source_charset != charset */

    let encoded = r.headers_out.borrow().content_encoding.as_ref().is_some_and(|ce| !ce.value.borrow().is_empty());

    if encoded {
        return next(r).await;
    }

    let mcf = r.main_conf::<CharsetMainConf>(ctx_index());

    let table = {
        let m = mcf.borrow();
        m.charsets[source_charset as usize].tables.as_ref().and_then(|t| t[charset as usize].clone())
    };

    let table = match table {
        Some(t) => t,
        None => return no_charset_map(r, next, &src, &dst).await,
    };

    {
        let mut ho = r.headers_out.borrow_mut();
        let len = ho.content_type_len;
        ho.content_type.truncate(len);
    }

    set_charset(&r, &dst);

    charset_ctx(r, next, &mcf, table, charset, source_charset).await
}

async fn no_charset_map(r: R, next: HeaderFilter, src: &[u8], dst: &[u8]) -> i64 {
    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no \"charset_map\" between the charsets \"{}\" and \"{}\"", B(src), B(dst));
    next(r).await
}

/// ngx_http_destination_charset
fn destination_charset(r: &R, name: &mut Vec<u8>) -> i64 {
    if r.headers_out.borrow().content_type.is_empty() {
        return NGX_DECLINED;
    }

    let override_charset = r.headers_out.borrow().override_charset.clone();

    if let Some(ov) = override_charset.filter(|o| !o.is_empty()) {
        *name = ov;

        let charset = get_charset(r, name);

        if charset != NGX_HTTP_NO_CHARSET {
            return charset;
        }

        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "unknown charset \"{}\" to override", B(name));

        return NGX_DECLINED;
    }

    let mlcf = r.loc_conf::<CharsetLocConf>(ctx_index());

    let (charset, override_on, types, any_type) = {
        let c = mlcf.borrow();
        (c.charset, *c.override_charset, c.types.clone(), c.any_type)
    };

    if charset == NGX_HTTP_CHARSET_OFF {
        return NGX_DECLINED;
    }

    if !r.headers_out.borrow().charset.is_empty() {
        if !override_on {
            return NGX_DECLINED;
        }
    } else if !test_content_type(r, types.as_deref(), any_type) {
        return NGX_DECLINED;
    }

    if charset < NGX_HTTP_CHARSET_VAR {
        let mcf = r.main_conf::<CharsetMainConf>(ctx_index());
        *name = mcf.borrow().charsets[charset as usize].name.clone();
        return charset;
    }

    let vv = crate::variables::get_indexed_variable(r, (charset - NGX_HTTP_CHARSET_VAR) as usize);

    match vv {
        Some(v) if !v.not_found => *name = v.data.clone(),
        _ => return NGX_ERROR,
    }

    get_charset(r, name)
}

/// ngx_http_test_content_type with the charset_types (the default types
/// when not set, any type with "*")
fn test_content_type(r: &R, types: Option<&[Vec<u8>]>, any_type: bool) -> bool {
    if any_type {
        return true;
    }

    let ho = r.headers_out.borrow();

    if ho.content_type.is_empty() {
        return false;
    }

    let ct = ho.content_type[..ho.content_type_len.min(ho.content_type.len())].to_ascii_lowercase();

    match types {
        Some(t) => t.iter().any(|x| x.as_slice() == ct.as_slice()),
        None => DEFAULT_TYPES.iter().any(|x| *x == ct.as_slice()),
    }
}

/// ngx_http_main_request_charset
fn main_request_charset(r: &R, src: &mut Vec<u8>) -> i64 {
    let main = r.main();

    if let Some(ctx) = main.get_ctx::<CharsetCtx>(ctx_index()) {
        let c = ctx.borrow();
        *src = c.charset_name.clone();
        return c.charset;
    }

    let main_charset = main.headers_out.borrow().charset.clone();

    if main_charset.is_empty() {
        return NGX_DECLINED;
    }

    let charset = get_charset(r, &main_charset);

    main.set_ctx(ctx_index(), CharsetCtx { table: None, charset, charset_name: main_charset.clone(), saved: [0; NGX_UTF_LEN], saved_len: 0, length: 0, from_utf8: false, to_utf8: false });

    *src = main_charset;

    charset
}

/// ngx_http_source_charset
fn source_charset(r: &R, name: &mut Vec<u8>) -> i64 {
    let cs = r.headers_out.borrow().charset.clone();

    if !cs.is_empty() {
        *name = cs;
        return get_charset(r, name);
    }

    let lcf = r.loc_conf::<CharsetLocConf>(ctx_index());
    let charset = lcf.borrow().source_charset;

    if charset == NGX_HTTP_CHARSET_OFF {
        name.clear();
        return charset;
    }

    if charset < NGX_HTTP_CHARSET_VAR {
        let mcf = r.main_conf::<CharsetMainConf>(ctx_index());
        *name = mcf.borrow().charsets[charset as usize].name.clone();
        return charset;
    }

    let vv = crate::variables::get_indexed_variable(r, (charset - NGX_HTTP_CHARSET_VAR) as usize);

    match vv {
        Some(v) if !v.not_found => *name = v.data.clone(),
        _ => return NGX_ERROR,
    }

    get_charset(r, name)
}

/// ngx_http_get_charset
fn get_charset(r: &R, name: &[u8]) -> i64 {
    let mcf = r.main_conf::<CharsetMainConf>(ctx_index());
    let m = mcf.borrow();

    for (i, c) in m.charsets.iter().enumerate() {
        if c.name.len() == name.len() && c.name.eq_ignore_ascii_case(name) {
            return i as i64;
        }
    }

    NGX_HTTP_NO_CHARSET
}

/// ngx_http_set_charset
fn set_charset(r: &R, charset: &[u8]) {
    if !r.is_main() {
        return;
    }

    let mut ho = r.headers_out.borrow_mut();

    if ho.status == NGX_HTTP_MOVED_PERMANENTLY || ho.status == NGX_HTTP_MOVED_TEMPORARILY {
        /*
         * do not set charset for the redirect because NN 4.x
         * use this charset instead of the next page charset
         */

        ho.charset.clear();
        return;
    }

    ho.charset = charset.to_vec();
}

/// ngx_http_charset_ctx
async fn charset_ctx(r: R, next: HeaderFilter, mcf: &Rc<RefCell<CharsetMainConf>>, table: Rc<RefCell<Table>>, charset: i64, source_charset: i64) -> i64 {
    let (name, length, from_utf8, to_utf8) = {
        let m = mcf.borrow();
        let dst = &m.charsets[charset as usize];
        (dst.name.clone(), dst.length, m.charsets[source_charset as usize].utf8, dst.utf8)
    };

    r.set_ctx(ctx_index(), CharsetCtx { table: Some(table), charset, charset_name: name, saved: [0; NGX_UTF_LEN], saved_len: 0, length, from_utf8, to_utf8 });

    r.filter_need_in_memory.set(true);

    if (to_utf8 || from_utf8) && r.is_main() {
        r.clear_content_length();
    } else {
        r.filter_need_temporary.set(true);
    }

    next(r).await
}

/// ngx_http_charset_body_filter
/// charset_body_filter passes the chain on as it is: no recoding
fn charset_body_idle(r: &R, _input: &Chain) -> bool {
    r.get_ctx::<CharsetCtx>(ctx_index()).is_none_or(|c| c.borrow().table.is_none())
}

async fn charset_body_filter(r: R, mut input: Chain, next: BodyFilter) -> i64 {
    let ctx = match r.get_ctx::<CharsetCtx>(ctx_index()) {
        Some(c) => c,
        None => return next(r, input).await,
    };

    let table = match ctx.borrow().table.clone() {
        Some(t) => t,
        None => return next(r, input).await,
    };

    let (to_utf8, from_utf8) = {
        let c = ctx.borrow();
        (c.to_utf8, c.from_utf8)
    };

    if to_utf8 || from_utf8 {
        let mut out = Chain::new();

        for b in input.drain(..) {
            if b.buf_size() == 0 {
                out.push_back(b);
                continue;
            }

            let t = table.borrow();
            let mut c = ctx.borrow_mut();

            let recoded = if c.to_utf8 { recode_to_utf8(&b, &t, &c) } else { recode_from_utf8(&r, &b, &t, &mut c) };

            out.extend(recoded);
        }

        return next(r, out).await;
    }

    if let Table::Byte(t) = &*table.borrow() {
        for b in input.iter_mut() {
            charset_recode(b, t);
        }
    }

    next(r, input).await
}

/// The bytes of a buffer in memory.
fn buf_bytes(b: &Buf) -> &[u8] {
    match &b.data {
        BufData::Memory(v) => &v[b.pos.min(v.len())..b.last.min(v.len())],
        _ => &[],
    }
}

/// ngx_http_charset_recode: one byte charsets, in place
fn charset_recode(b: &mut Buf, table: &[u8; 256]) -> bool {
    let (pos, last) = (b.pos, b.last);

    let data = match &mut b.data {
        BufData::Memory(v) => v,
        _ => return false,
    };

    let last = last.min(data.len());

    let start = match data[pos.min(last)..last].iter().position(|&c| c != table[c as usize]) {
        Some(i) => pos + i,
        None => return false,
    };

    for c in data[start..last].iter_mut() {
        *c = table[*c as usize];
    }

    b.in_file = false;

    true
}

/// ngx_utf8_decode: 0xffffffff for an invalid sequence, 0xfffffffe for an
/// incomplete one; `p` moves past what is decoded
fn utf8_decode(p: &mut usize, data: &[u8], n: usize) -> u32 {
    let mut u = data[*p] as u32;

    let (valid, mut len) = if u >= 0xf0 {
        u &= 0x07;
        (0xffff, 3usize)
    } else if u >= 0xe0 {
        u &= 0x0f;
        (0x7ff, 2)
    } else if u >= 0xc2 {
        u &= 0x1f;
        (0x7f, 1)
    } else {
        *p += 1;
        return 0xffffffff;
    };

    if n - 1 < len {
        return 0xfffffffe;
    }

    *p += 1;

    while len > 0 {
        let i = data[*p] as u32;
        *p += 1;

        if i < 0x80 {
            return 0xffffffff;
        }

        u = (u << 6) | (i & 0x3f);

        len -= 1;
    }

    if u > valid {
        return u;
    }

    0xffffffff
}

/// A buffer of recoded data, with the flags of the buffer it replaces.
fn recoded_buf(data: Vec<u8>, from: &Buf, flags: bool) -> Buf {
    let mut b = Buf::from_vec(data);

    b.temporary = true;

    if flags {
        b.last_buf = from.last_buf;
        b.last_in_chain = from.last_in_chain;
        b.flush = from.flush;
    }

    b
}

/// ngx_http_charset_recode_from_utf8
fn recode_from_utf8(r: &R, buf: &Buf, table: &Table, ctx: &mut CharsetCtx) -> Vec<Buf> {
    let pages = match table {
        Table::FromUtf8(p) => p,
        _ => return vec![buf.clone()],
    };

    let lookup = |n: u32| -> u8 {
        match &pages[(n >> 8) as usize] {
            Some(p) => p[(n & 0xff) as usize],
            None => 0,
        }
    };

    let data = buf_bytes(buf);
    let mut src = 0usize;
    let mut out: Vec<Buf> = Vec::new();
    let mut dst: Vec<u8> = Vec::new();

    if ctx.saved_len == 0 {
        while src < data.len() && data[src] < 0x80 {
            src += 1;
        }

        if src == data.len() {
            return vec![buf.clone()];
        }

        let len = src;

        if len > 512 {
            let mut first = recoded_buf(data[..src].to_vec(), buf, false);
            first.flush = buf.flush;
            out.push(first);

            let mut saved = src;
            let n = utf8_decode(&mut saved, data, data.len() - src);

            if n == 0xfffffffe {
                /* incomplete UTF-8 symbol */

                let size = data.len() - src;
                ctx.saved[..size].copy_from_slice(&data[src..]);
                ctx.saved_len = size;

                return out;
            }
        } else {
            src = 0;
        }
    } else {
        /* process incomplete UTF sequence from previous buffer */

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http charset utf saved: {}", ctx.saved_len);

        let len = (NGX_UTF_LEN - ctx.saved_len).min(data.len());
        let saved_len = ctx.saved_len;
        ctx.saved[saved_len..saved_len + len].copy_from_slice(&data[..len]);
        let len = len + saved_len;

        let saved_copy = ctx.saved;
        let mut saved = 0usize;
        let n = utf8_decode(&mut saved, &saved_copy, len);

        let mut c = 0u8;

        if n < 0x10000 {
            c = lookup(n);
        } else if n == 0xfffffffe {
            /* incomplete UTF-8 symbol */

            if len < NGX_UTF_LEN {
                let mut b = Buf::special();
                b.sync = true;
                ctx.saved_len = len;
                return vec![b];
            }
        }

        if c != 0 {
            dst.push(c);
        } else if n == 0xfffffffe {
            dst.push(b'?');

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http charset invalid utf 0");

            saved = NGX_UTF_LEN;
        } else if n > 0x10ffff {
            dst.push(b'?');

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http charset invalid utf 1");

            if saved < ctx.saved_len {
                saved = ctx.saved_len;
            }
        } else {
            dst.extend_from_slice(format!("&#{};", n).as_bytes());
        }

        src += saved - ctx.saved_len;
        ctx.saved_len = 0;
    }

    /* recode: */

    while src < data.len() {
        if data[src] < 0x80 {
            dst.push(data[src]);
            src += 1;
            continue;
        }

        let len = data.len() - src;

        let n = utf8_decode(&mut src, data, len);

        if n < 0x10000 {
            let c = lookup(n);

            if c != 0 {
                dst.push(c);
                continue;
            }

            dst.extend_from_slice(format!("&#{};", n).as_bytes());
            continue;
        }

        if n == 0xfffffffe {
            /* incomplete UTF-8 symbol */

            ctx.saved[..len].copy_from_slice(&data[src..src + len]);
            ctx.saved_len = len;

            break;
        }

        if n > 0x10ffff {
            dst.push(b'?');

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, r.connection.log, "http charset invalid utf 2");

            continue;
        }

        /* n > 0xffff */

        dst.extend_from_slice(format!("&#{};", n).as_bytes());
    }

    let empty = dst.is_empty();

    let mut b = recoded_buf(dst, buf, true);

    if empty && !b.last_buf && !b.flush {
        b.sync = true;
        b.temporary = false;
    }

    out.push(b);

    out
}

/// ngx_http_charset_recode_to_utf8
fn recode_to_utf8(buf: &Buf, table: &Table, _ctx: &CharsetCtx) -> Vec<Buf> {
    let t = match table {
        Table::ToUtf8(t) => t,
        _ => return vec![buf.clone()],
    };

    let data = buf_bytes(buf);

    let first = match data.iter().position(|&c| t[c as usize * NGX_UTF_LEN] != 1) {
        Some(i) => i,
        None => return vec![buf.clone()],
    };

    let mut out = Vec::new();

    let mut src = 0usize;

    if first > 512 {
        let mut b = recoded_buf(data[..first].to_vec(), buf, false);
        b.flush = buf.flush;
        out.push(b);
        src = first;
    }

    // about half of the characters are assumed to be recoded
    let size = data.len() - src;
    let mut dst = Vec::with_capacity(src + size / 2 + size / 2 * _ctx.length as usize);

    while src < data.len() {
        let p = data[src] as usize * NGX_UTF_LEN;
        src += 1;

        let len = t[p] as usize;

        dst.extend_from_slice(&t[p + 1..p + 1 + len]);
    }

    out.push(recoded_buf(dst, buf, true));

    out
}

/// ngx_http_charset_map_block
fn charset_map_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let mcf = conf_rc::<CharsetMainConf>(conf.as_ref().expect("conf"));

    let value1 = cf.args[1].clone();
    let value2 = cf.args[2].clone();

    let src = add_charset(&mut mcf.borrow_mut().charsets, &value1);
    let dst = add_charset(&mut mcf.borrow_mut().charsets, &value2);

    if src == dst {
        return Err(cf.emerg(format_args!("\"charset_map\" between the same charsets \"{}\" and \"{}\"", B(&value1), B(&value2))));
    }

    if value1.eq_ignore_ascii_case(b"utf-8") {
        return Err(cf.emerg(format_args!("\"charset_map\" with \"utf-8\" charset should be given in the second column")));
    }

    let duplicate = mcf.borrow().tables.iter().any(|t| (src == t.src && dst == t.dst) || (src == t.dst && dst == t.src));

    if duplicate {
        return Err(cf.emerg(format_args!("duplicate \"charset_map\" between \"{}\" and \"{}\"", B(&value1), B(&value2))));
    }

    let utf8 = value2.eq_ignore_ascii_case(b"utf-8");

    let (src2dst, dst2src) = if utf8 {
        let mut s2d = Box::new([0u8; 256 * NGX_UTF_LEN]);
        let mut first = Box::new([0u8; 256]);

        for i in 0..128usize {
            s2d[i * NGX_UTF_LEN] = 1;
            s2d[i * NGX_UTF_LEN + 1] = i as u8;
            first[i] = i as u8;
        }

        for i in 128..256usize {
            s2d[i * NGX_UTF_LEN] = 1;
            s2d[i * NGX_UTF_LEN + 1] = b'?';
        }

        let mut pages: Box<[Option<Box<[u8; 256]>>; 256]> = Box::new(std::array::from_fn(|_| None));
        pages[0] = Some(first);

        (Table::ToUtf8(s2d), Table::FromUtf8(pages))
    } else {
        let mut s2d = Box::new([0u8; 256]);
        let mut d2s = Box::new([0u8; 256]);

        for i in 0..128usize {
            s2d[i] = i as u8;
            d2s[i] = i as u8;
        }

        for i in 128..256usize {
            s2d[i] = b'?';
            d2s[i] = b'?';
        }

        (Table::Byte(s2d), Table::Byte(d2s))
    };

    let src2dst = Rc::new(RefCell::new(src2dst));
    let dst2src = Rc::new(RefCell::new(dst2src));

    mcf.borrow_mut().tables.push(CharsetTables { src, dst, src2dst: src2dst.clone(), dst2src: dst2src.clone() });

    let ctx: Rc<dyn Any> = Rc::new(CharsetConfCtx { mcf: mcf.clone(), src2dst, dst2src, charset: dst, characters: RefCell::new(0) });

    let saved_h = cf.handler.take();
    let saved_hc = cf.handler_conf.take();
    cf.handler = Some(charset_map);
    cf.handler_conf = Some(ctx.clone());

    let rv = cf.parse_block();

    cf.handler = saved_h;
    cf.handler_conf = saved_hc;

    let ctx = ctx.downcast::<CharsetConfCtx>().expect("ctx");
    let characters = *ctx.characters.borrow();

    if characters > 0 {
        let mut m = mcf.borrow_mut();
        let cs = &mut m.charsets[dst];
        let n = cs.length;
        cs.length /= characters;

        if ((n * 10) / characters) % 10 > 4 {
            cs.length += 1;
        }
    }

    rv
}

/// ngx_http_charset_conf_ctx_t
struct CharsetConfCtx {
    mcf: Rc<RefCell<CharsetMainConf>>,
    src2dst: Rc<RefCell<Table>>,
    dst2src: Rc<RefCell<Table>>,
    charset: usize,
    characters: RefCell<u32>,
}

/// ngx_hextoi
fn hextoi(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }

    let mut v: u32 = 0;

    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };

        v = v.checked_mul(16)?.checked_add(d as u32)?;
    }

    Some(v)
}

/// ngx_http_charset_map
fn charset_map(cf: &mut Conf, hc: Rc<dyn Any>) -> ConfResult {
    let ctx = hc.downcast::<CharsetConfCtx>().map_err(|_| msg("charset_map"))?;

    if cf.args.len() != 2 {
        return Err(cf.emerg(format_args!("invalid parameters number")));
    }

    let value0 = cf.args[0].clone();
    let value1 = cf.args[1].clone();

    let src = match hextoi(&value0) {
        Some(v) if v <= 255 => v as usize,
        _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", B(&value0)))),
    };

    let utf8 = ctx.mcf.borrow().charsets[ctx.charset].utf8;

    if utf8 {
        if value1.len() / 2 > NGX_UTF_LEN - 1 {
            return Err(cf.emerg(format_args!("invalid value \"{}\"", B(&value1))));
        }

        let mut bytes = Vec::new();

        let mut i = 0;
        while i < value1.len() {
            let end = (i + 2).min(value1.len());
            match hextoi(&value1[i..end]) {
                Some(d) if d <= 255 && end - i == 2 => bytes.push(d as u8),
                _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", B(&value1)))),
            }
            i += 2;
        }

        let n_bytes = bytes.len();

        if let Table::ToUtf8(t) = &mut *ctx.src2dst.borrow_mut() {
            let p = src * NGX_UTF_LEN;
            t[p] = n_bytes as u8;
            t[p + 1..p + 1 + n_bytes].copy_from_slice(&bytes);
        }

        ctx.mcf.borrow_mut().charsets[ctx.charset].length += n_bytes as u32;
        *ctx.characters.borrow_mut() += 1;

        let mut pos = 0usize;
        let n = if n_bytes == 0 { 0xffffffff } else { utf8_decode(&mut pos, &bytes, n_bytes) };

        if n > 0xffff {
            return Err(cf.emerg(format_args!("invalid value \"{}\"", B(&value1))));
        }

        if let Table::FromUtf8(pages) = &mut *ctx.dst2src.borrow_mut() {
            let page = pages[(n >> 8) as usize].get_or_insert_with(|| Box::new([0u8; 256]));
            page[(n & 0xff) as usize] = src as u8;
        }
    } else {
        let dst = match hextoi(&value1) {
            Some(v) if v <= 255 => v as u8,
            _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", B(&value1)))),
        };

        if let Table::Byte(t) = &mut *ctx.src2dst.borrow_mut() {
            t[src] = dst;
        }

        if let Table::Byte(t) = &mut *ctx.dst2src.borrow_mut() {
            t[dst as usize] = src as u8;
        }
    }

    Ok(())
}

/// ngx_http_set_charset_slot for "charset"
fn set_charset_slot(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    set_charset_value(cf, conf, true)
}

/// ngx_http_set_charset_slot for "source_charset"
fn set_source_charset_slot(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    set_charset_value(cf, conf, false)
}

fn set_charset_value(cf: &mut Conf, conf: Option<Rc<dyn Any>>, is_charset: bool) -> ConfResult {
    let lcf = conf_rc::<CharsetLocConf>(conf.as_ref().expect("conf"));

    let current = if is_charset { lcf.borrow().charset } else { lcf.borrow().source_charset };

    if current != CHARSET_UNSET {
        return Err(msg("is duplicate"));
    }

    let value = cf.args[1].clone();

    let v = if is_charset && value.as_slice() == b"off" {
        NGX_HTTP_CHARSET_OFF
    } else if value.first() == Some(&b'$') {
        let index = crate::variables::get_variable_index(cf, &value[1..])?;
        index as i64 + NGX_HTTP_CHARSET_VAR
    } else {
        let mcf = crate::get_main_conf::<CharsetMainConf>(cf, ctx_index());
        let i = add_charset(&mut mcf.borrow_mut().charsets, &value);
        i as i64
    };

    if is_charset {
        lcf.borrow_mut().charset = v;
    } else {
        lcf.borrow_mut().source_charset = v;
    }

    Ok(())
}

/// ngx_http_types_slot for charset_types
fn charset_types_slot(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lcf = conf_rc::<CharsetLocConf>(conf.as_ref().expect("conf"));

    if lcf.borrow().types.is_some() || lcf.borrow().any_type {
        return Err(msg("is duplicate"));
    }

    let mut types = Vec::new();
    let mut any = false;

    for a in cf.args.iter().skip(1) {
        if a.as_slice() == b"*" {
            any = true;
            continue;
        }

        let lc = a.to_ascii_lowercase();

        if types.contains(&lc) {
            cf.warn(format_args!("duplicate MIME type \"{}\"", B(a)));
            continue;
        }

        types.push(lc);
    }

    let mut c = lcf.borrow_mut();
    c.any_type = any;
    c.types = Some(types);

    Ok(())
}

/// ngx_http_add_charset
fn add_charset(charsets: &mut Vec<Charset>, name: &[u8]) -> usize {
    if let Some(i) = charsets.iter().position(|c| c.name.len() == name.len() && c.name.eq_ignore_ascii_case(name)) {
        return i;
    }

    charsets.push(Charset { tables: None, name: name.to_vec(), length: 0, utf8: name.eq_ignore_ascii_case(b"utf-8") });

    charsets.len() - 1
}

fn charset_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CharsetMainConf::default())
}

fn charset_create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CharsetLocConf { charset: CHARSET_UNSET, source_charset: CHARSET_UNSET, override_charset: Val::unset(), types: None, any_type: false })
}

/// ngx_http_charset_merge_loc_conf
fn charset_merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<CharsetLocConf>(prev).borrow();
    let mut c = conf_cell::<CharsetLocConf>(conf).borrow_mut();

    // ngx_http_merge_types
    if c.types.is_none() && !c.any_type {
        c.types = p.types.clone();
        c.any_type = p.any_type;
    }

    c.override_charset.merge(&p.override_charset, false);

    if c.charset == CHARSET_UNSET {
        c.charset = if p.charset == CHARSET_UNSET { NGX_HTTP_CHARSET_OFF } else { p.charset };
    }

    if c.source_charset == CHARSET_UNSET {
        c.source_charset = if p.source_charset == CHARSET_UNSET { NGX_HTTP_CHARSET_OFF } else { p.source_charset };
    }

    if c.charset == NGX_HTTP_CHARSET_OFF || c.source_charset == NGX_HTTP_CHARSET_OFF || c.charset == c.source_charset {
        return Ok(());
    }

    if c.source_charset >= NGX_HTTP_CHARSET_VAR || c.charset >= NGX_HTTP_CHARSET_VAR {
        return Ok(());
    }

    let (src, dst) = (c.source_charset, c.charset);
    drop(c);
    drop(p);

    let mcf = crate::get_main_conf::<CharsetMainConf>(cf, ctx_index());
    let mut m = mcf.borrow_mut();

    if !m.recodes.iter().any(|&(s, d)| s == src && d == dst) {
        m.recodes.push((src, dst));
    }

    Ok(())
}

/// ngx_http_charset_postconfiguration
fn charset_postconfiguration(cf: &mut Conf) -> ConfResult {
    let mcf = crate::get_main_conf::<CharsetMainConf>(cf, ctx_index());

    {
        let m = mcf.borrow();

        for &(src, dst) in m.recodes.iter() {
            let found = m.tables.iter().any(|t| (src as usize == t.src && dst as usize == t.dst) || (src as usize == t.dst && dst as usize == t.src));

            if !found {
                ngx_log_error!(
                    NGX_LOG_EMERG,
                    cf.log,
                    None,
                    "no \"charset_map\" between the charsets \"{}\" and \"{}\"",
                    B(&m.charsets[src as usize].name),
                    B(&m.charsets[dst as usize].name)
                );
                return Err(ConfError::Logged);
            }
        }
    }

    {
        let mut m = mcf.borrow_mut();
        let n = m.charsets.len();

        let links: Vec<(usize, usize, Rc<RefCell<Table>>, Rc<RefCell<Table>>)> = m.tables.iter().map(|t| (t.src, t.dst, t.src2dst.clone(), t.dst2src.clone())).collect();

        for (src, dst, s2d, d2s) in links {
            m.charsets[src].tables.get_or_insert_with(|| vec![None; n])[dst] = Some(s2d);
            m.charsets[dst].tables.get_or_insert_with(|| vec![None; n])[src] = Some(d2s);
        }
    }

    crate::install_header_filter_idle(charset_header_idle, charset_header_filter);
    crate::install_body_filter_idle(charset_body_idle, charset_body_filter);

    Ok(())
}
