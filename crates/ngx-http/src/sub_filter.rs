//! ngx_http_sub_filter_module
//!
//! The buffers own their data here: the parts of ctx->buf passed on are
//! copies of its data (C makes buffers pointing into it, with ctx->buf as
//! their shadow), and the buffers passed on are sent once the next filter
//! returns (C keeps the ones not sent yet in ctx->busy).

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd, cmd_fn};

use crate::http_types::*;
use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_sub_filter_module");

/// ngx_http_sub_pair_t
#[derive(Clone)]
pub struct SubPair {
    pub match_: ComplexValue,
    pub value: ComplexValue,
}

/// ngx_http_sub_match_t: the value is the one of the pair with this index
#[derive(Clone, Debug, PartialEq, Eq)]
struct SubMatch {
    match_: Vec<u8>,
    value: usize,
}

/// ngx_http_sub_tables_t
struct SubTables {
    min_match_len: usize,
    max_match_len: usize,

    index: [u8; 257],
    shift: [u8; 256],
}

/// ngx_http_sub_loc_conf_t
pub struct SubLocConf {
    dynamic: bool,

    pairs: Option<Rc<Vec<SubPair>>>,

    tables: Option<Rc<SubTables>>,

    types: HttpTypesHash,

    pub once: Val<bool>,
    pub last_modified: Val<bool>,

    types_keys: Option<HttpTypesKeys>,
    matches: Option<Rc<Vec<SubMatch>>>,
}

/// ngx_http_sub_ctx_t
struct SubCtx {
    saved: Vec<u8>,
    looked: Vec<u8>,

    once: bool,

    buf: Option<Buf>,

    pos: usize,
    copy_start: usize,
    copy_end: usize,

    in_: Chain,
    out: Chain,

    /// ctx->sub: the replacements computed, by match
    sub: Option<Vec<Option<Vec<u8>>>>,
    applied: usize,

    offset: isize,
    index: usize,

    tables: Rc<SubTables>,
    matches: Rc<Vec<SubMatch>>,
    pairs: Rc<Vec<SubPair>>,
}

/// The data of a buffer in memory
fn buf_data(b: &Buf) -> &[u8] {
    match &b.data {
        BufData::Memory(v) => v,
        _ => &[],
    }
}

/// A buffer with b->memory set, of the data given
fn memory_buf(data: Vec<u8>) -> Buf {
    let len = data.len();

    Buf { data: BufData::Memory(data), pos: 0, last: len, memory: true, ..Default::default() }
}

/// ngx_http_sub_header_filter
/// sub_header_filter passes the response on as it is: no sub_filter
fn sub_header_idle(r: &R) -> bool {
    r.loc_conf::<SubLocConf>(ctx_index()).borrow().pairs.is_none()
}

async fn sub_header_filter(r: R, next: HeaderFilter) -> i64 {
    let slcf = r.loc_conf::<SubLocConf>(ctx_index());

    let (dynamic, pairs, tables, matches, last_modified) = {
        let c = slcf.borrow();

        let pairs = match &c.pairs {
            Some(pairs) if r.headers_out.borrow().content_length_n != 0 && http_test_content_type(&r, &c.types) => pairs.clone(),
            _ => {
                drop(c);
                return next(r).await;
            }
        };

        (c.dynamic, pairs, c.tables.clone(), c.matches.clone(), *c.last_modified)
    };

    let (tables, matches) = if !dynamic {
        (tables.expect("tables"), matches.expect("matches"))
    } else {
        let mut matches = Vec::with_capacity(pairs.len());

        for (i, pair) in pairs.iter().enumerate() {
            if pair.match_.is_constant() {
                matches.push(SubMatch { match_: pair.match_.value.clone(), value: i });
                continue;
            }

            let mut m = match complex_value(&r, &pair.match_) {
                Ok(m) => m,
                Err(_) => return NGX_ERROR,
            };

            if m.is_empty() {
                continue;
            }

            m.make_ascii_lowercase();

            matches.push(SubMatch { match_: m, value: i });
        }

        if matches.is_empty() {
            return next(r).await;
        }

        let tables = sub_init_tables(&mut matches);

        (Rc::new(tables), Rc::new(matches))
    };

    let max = tables.max_match_len - 1;

    let ctx = SubCtx {
        saved: Vec::with_capacity(max),
        looked: Vec::with_capacity(max),
        once: false,
        buf: None,
        pos: 0,
        copy_start: 0,
        copy_end: 0,
        in_: Chain::new(),
        out: Chain::new(),
        sub: None,
        applied: 0,
        offset: tables.min_match_len as isize - 1,
        index: 0,
        tables,
        matches,
        pairs,
    };

    r.set_ctx(ctx_index(), ctx);

    r.filter_need_in_memory.set(true);

    if r.is_main() {
        r.clear_content_length();

        if !last_modified {
            r.clear_last_modified();
            r.clear_etag();
        } else {
            crate::core_rt::weak_etag(&r);
        }
    }

    next(r).await
}

/// ngx_http_sub_body_filter
/// sub_body_filter passes the chain on as it is
fn sub_body_idle(r: &R, _input: &Chain) -> bool {
    !r.has_ctx(ctx_index())
}

async fn sub_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx = match r.get_ctx::<SubCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => return next(r, input).await,
    };

    // ctx->busy: none, the buffers passed on are sent

    let pass = {
        let c = ctx.borrow();

        (input.is_empty() && c.buf.is_none() && c.in_.is_empty()) || (c.once && (c.buf.is_none() || c.in_.is_empty()))
    };

    if pass {
        return next(r, input).await;
    }

    // add the incoming chain to the chain ctx->in

    if !input.is_empty() {
        ctx.borrow_mut().in_.extend(input);
    }

    http_debug!(r, "http sub filter \"{}\"", B(&r.uri.borrow()));

    let mut flush = false;
    let mut last = false;

    loop {
        let mut c = ctx.borrow_mut();
        let c = &mut *c;

        if c.in_.is_empty() && c.buf.is_none() {
            break;
        }

        if c.buf.is_none() {
            let buf = c.in_.pop_front().expect("ctx->in");
            c.pos = buf.pos;
            c.buf = Some(buf);
        }

        {
            let buf = c.buf.as_ref().expect("ctx->buf");

            if buf.flush || buf.recycled {
                flush = true;
            }
        }

        if c.in_.is_empty() {
            last = flush;
        }

        // the last buffer of ctx->out is "b"
        let mut b = false;

        while c.pos < c.buf.as_ref().expect("ctx->buf").last {
            let rc = sub_parse(&r, c, last);

            http_debug!(r, "parse: {}, looked: \"{}\" {}-{}", rc, B(&c.looked), c.copy_start, c.copy_end);

            if rc == NGX_ERROR {
                return rc;
            }

            if !c.saved.is_empty() {
                http_debug!(r, "saved: \"{}\"", B(&c.saved));

                c.out.push_back(memory_buf(c.saved.clone()));
                b = true;

                c.saved.clear();
            }

            if c.copy_start != c.copy_end {
                let buf = c.buf.as_ref().expect("ctx->buf");

                c.out.push_back(sub_copy_buf(buf, c.copy_start, c.copy_end));
                b = true;
            }

            if rc == NGX_AGAIN {
                continue;
            }

            // rc == NGX_OK

            let once = *r.loc_conf::<SubLocConf>(ctx_index()).borrow().once;

            let n = c.matches.len();
            let sub = c.sub.get_or_insert_with(|| vec![None; n]);

            if sub[c.index].is_none() {
                let value = &c.pairs[c.matches[c.index].value].value;

                match complex_value(&r, value) {
                    Ok(v) => sub[c.index] = Some(v),
                    Err(_) => return NGX_ERROR,
                }
            }

            let value = sub[c.index].as_ref().expect("sub");

            let nb = if !value.is_empty() { memory_buf(value.clone()) } else { Buf::special() };

            c.out.push_back(nb);
            b = true;

            c.index = 0;
            c.applied += 1;
            c.once = once && c.applied == n;
        }

        let buf = c.buf.take().expect("ctx->buf");

        if !c.looked.is_empty() && (buf.last_buf || buf.last_in_chain) {
            c.out.push_back(memory_buf(std::mem::take(&mut c.looked)));
            b = true;
        }

        if buf.last_buf || buf.flush || buf.sync || buf.in_memory() {
            if !b {
                c.out.push_back(Buf::special());
            }

            let ob = c.out.back_mut().expect("b");

            ob.last_buf = buf.last_buf;
            ob.last_in_chain = buf.last_in_chain;
            ob.flush = buf.flush;

            ob.recycled = buf.recycled;
        }
    }

    if ctx.borrow().out.is_empty() {
        return NGX_OK;
    }

    sub_output(&r, &ctx, &next).await
}

/// The buffer ngx_http_sub_body_filter() makes of a copy of ctx->buf with
/// pos and last at ctx->copy_start and ctx->copy_end
fn sub_copy_buf(buf: &Buf, start: usize, end: usize) -> Buf {
    let data = buf_data(buf)[start..end].to_vec();
    let len = data.len();

    let mut b = Buf {
        pos: 0,
        last: len,
        file_pos: 0,
        file_last: 0,
        tag: buf.tag,
        num: buf.num,
        data: BufData::Memory(data),
        temporary: buf.temporary,
        memory: buf.memory,
        mmap: buf.mmap,
        recycled: false,
        in_file: false,
        flush: buf.flush,
        sync: buf.sync,
        last_buf: false,
        last_in_chain: false,
        temp_file: buf.temp_file,
    };

    if !b.in_memory() {
        b.memory = true;
    }

    b
}

/// ngx_http_sub_output
async fn sub_output(r: &R, ctx: &Rc<RefCell<SubCtx>>, next: &BodyFilter) -> i64 {
    let out = std::mem::take(&mut ctx.borrow_mut().out);

    for b in out.iter() {
        http_debug!(r, "sub out: {:p} {}", b as *const Buf, b.pos);
    }

    let rc = next(r.clone(), out).await;

    let c = ctx.borrow();

    if !c.in_.is_empty() || c.buf.is_some() {
        r.buffered.set(r.buffered.get() | NGX_HTTP_SUB_BUFFERED);
    } else {
        r.buffered.set(r.buffered.get() & !NGX_HTTP_SUB_BUFFERED);
    }

    rc
}

/// ngx_http_sub_parse
fn sub_parse(r: &R, ctx: &mut SubCtx, flush: bool) -> i64 {
    let once = *r.loc_conf::<SubLocConf>(ctx_index()).borrow().once;

    let tables = ctx.tables.clone();
    let matches = ctx.matches.clone();

    let min_match_len = tables.min_match_len as isize;

    let buf = ctx.buf.as_ref().expect("ctx->buf");
    let data = buf_data(buf);
    let last = buf.last;

    let mut offset = ctx.offset;
    let mut end = (last - ctx.pos) as isize;

    let (start, next, rc) = 'done: {
        'again: {
            if ctx.once {
                // sets start and next to end
                offset = end + min_match_len - 1;
                break 'again;
            }

            while offset < end {
                let c = if offset < 0 { ctx.looked[(ctx.looked.len() as isize + offset) as usize] } else { data[ctx.pos + offset as usize] };

                let c = c.to_ascii_lowercase() as usize;

                let shift = tables.shift[c];
                if shift > 0 {
                    offset += shift as isize;
                    continue;
                }

                // a potential match

                let start = offset - min_match_len + 1;

                let mut i = (tables.index[c] as usize).max(ctx.index);
                let j = tables.index[c + 1] as usize;

                while i != j {
                    if once && ctx.sub.as_ref().is_some_and(|sub| sub[i].is_some()) {
                        i += 1;
                        continue;
                    }

                    let m = &matches[i].match_;

                    let rc = sub_match(data, ctx.pos, last, &ctx.looked, start, m);

                    if rc == NGX_DECLINED {
                        i += 1;
                        continue;
                    }

                    ctx.index = i;

                    if rc == NGX_AGAIN {
                        break 'again;
                    }

                    ctx.offset = offset + m.len() as isize;
                    let next = start + m.len() as isize;
                    end = next.max(0);

                    break 'done (start, next, NGX_OK);
                }

                offset += 1;
                ctx.index = 0;
            }

            if flush {
                loop {
                    let start = offset - min_match_len + 1;

                    if start >= end {
                        break;
                    }

                    for m in matches.iter() {
                        if sub_match(data, ctx.pos, last, &ctx.looked, start, &m.match_) == NGX_AGAIN {
                            break 'again;
                        }
                    }

                    offset += 1;
                }
            }
        }

        // again:

        ctx.offset = offset;
        let start = offset - min_match_len + 1;

        (start, start, NGX_AGAIN)
    };

    // done:

    // send [ - looked.len, start ] to client

    let saved_len = (ctx.looked.len() as isize + start.min(0)) as usize;
    ctx.saved.clear();
    ctx.saved.extend_from_slice(&ctx.looked[..saved_len]);

    ctx.copy_start = ctx.pos;
    ctx.copy_end = ctx.pos + start.max(0) as usize;

    // save [ next, end ] in looked

    let len = next.min(0);
    let keep = (ctx.looked.len() as isize + len) as usize;
    ctx.looked.drain(..keep);

    let len = next.max(0) as usize;
    ctx.looked.extend_from_slice(&data[ctx.pos + len..ctx.pos + end as usize]);

    // update position

    ctx.pos += end as usize;
    ctx.offset -= end;

    rc
}

/// ngx_http_sub_match: the data of ctx->buf, ctx->pos, ctx->buf->last and
/// ctx->looked
fn sub_match(data: &[u8], pos: usize, last: usize, looked: &[u8], start: isize, m: &[u8]) -> i64 {
    let mut pat = 0;
    let mut p;

    if start >= 0 {
        p = pos + start as usize;
    } else {
        let mut lp = (looked.len() as isize + start) as usize;

        while lp < looked.len() && pat < m.len() {
            if looked[lp].to_ascii_lowercase() != m[pat] {
                return NGX_DECLINED;
            }

            lp += 1;
            pat += 1;
        }

        p = pos;
    }

    while p < last && pat < m.len() {
        if data[p].to_ascii_lowercase() != m[pat] {
            return NGX_DECLINED;
        }

        p += 1;
        pat += 1;
    }

    if pat != m.len() {
        // partial match
        return NGX_AGAIN;
    }

    NGX_OK
}

/// ngx_http_sub_filter
fn sub_filter(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<SubLocConf>(conf.as_ref().expect("conf"));

    let value1 = cf.args[1].to_ascii_lowercase();
    let value2 = cf.args[2].clone();

    if value1.is_empty() {
        return Err(cf.emerg(format_args!("empty search pattern")));
    }

    if cell.borrow().pairs.as_ref().is_some_and(|p| p.len() == 255) {
        return Err(cf.emerg(format_args!("number of search patterns exceeds 255")));
    }

    let match_ = compile_complex_value(cf, &value1, 0)?;

    if !match_.is_constant() {
        cell.borrow_mut().dynamic = true;
    }

    let value = compile_complex_value(cf, &value2, 0)?;

    let mut slcf = cell.borrow_mut();
    let pairs = slcf.pairs.get_or_insert_with(|| Rc::new(Vec::new()));

    Rc::make_mut(pairs).push(SubPair { match_, value });

    Ok(())
}

/// ngx_http_types_slot for sub_filter_types, &ngx_http_html_default_types[0]
fn sub_types_slot(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<SubLocConf>(conf.as_ref().expect("conf"));
    let mut c = cell.borrow_mut();

    http_types_slot(cf, &mut c.types_keys, Some(NGX_HTTP_HTML_DEFAULT_TYPES[0]))
}

/// ngx_http_sub_create_conf
fn sub_create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SubLocConf {
        dynamic: false,
        pairs: None,
        tables: None,
        types: None,
        once: Val::unset(),
        last_modified: Val::unset(),
        types_keys: None,
        matches: None,
    })
}

/// ngx_http_sub_merge_conf
fn sub_merge_conf(cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let mut prev = conf_cell::<SubLocConf>(parent).borrow_mut();
    let mut conf = conf_cell::<SubLocConf>(child).borrow_mut();

    let prev = &mut *prev;
    let conf = &mut *conf;

    conf.once.merge(&prev.once, true);
    conf.last_modified.merge(&prev.last_modified, false);

    http_merge_types(cf, &mut conf.types_keys, &mut conf.types, &mut prev.types_keys, &mut prev.types, NGX_HTTP_HTML_DEFAULT_TYPES)?;

    if conf.pairs.is_none() {
        conf.dynamic = prev.dynamic;
        conf.pairs = prev.pairs.clone();
        conf.matches = prev.matches.clone();
        conf.tables = prev.tables.clone();
    }

    if let Some(pairs) = &conf.pairs {
        if !conf.dynamic && conf.tables.is_none() {
            let mut matches: Vec<SubMatch> = pairs.iter().enumerate().map(|(i, pair)| SubMatch { match_: pair.match_.value.clone(), value: i }).collect();

            let tables = sub_init_tables(&mut matches);

            conf.matches = Some(Rc::new(matches));
            conf.tables = Some(Rc::new(tables));
        }
    }

    Ok(())
}

/// ngx_http_sub_init_tables
fn sub_init_tables(matches: &mut [SubMatch]) -> SubTables {
    let n = matches.len();

    let mut min = matches[0].match_.len();
    let mut max = matches[0].match_.len();

    for m in matches[1..].iter() {
        min = min.min(m.match_.len());
        max = max.max(m.match_.len());
    }

    let mut tables = SubTables { min_match_len: min, max_match_len: max, index: [0; 257], shift: [0; 256] };

    // ngx_sort() with ngx_http_sub_cmp_matches: stable, by the character at
    // ngx_http_sub_cmp_index
    let cmp_index = tables.min_match_len - 1;
    matches.sort_by_key(|m| m.match_[cmp_index]);

    let min = min.min(255);
    tables.shift = [min as u8; 256];

    let mut ch = 0usize;

    for (i, m) in matches.iter().enumerate() {
        for j in 0..min {
            let c = m.match_[tables.min_match_len - 1 - j] as usize;
            tables.shift[c] = tables.shift[c].min(j as u8);
        }

        let c = m.match_[tables.min_match_len - 1] as usize;
        while ch <= c {
            tables.index[ch] = i as u8;
            ch += 1;
        }
    }

    while ch < 257 {
        tables.index[ch] = n as u8;
        ch += 1;
    }

    tables
}

/// ngx_http_sub_filter_init
fn sub_filter_init(_cf: &mut Conf) -> ConfResult {
    crate::install_header_filter_idle(sub_header_idle, sub_header_filter);
    crate::install_body_filter_idle(sub_body_idle, sub_body_filter);
    Ok(())
}

pub fn sub_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(sub_filter_init),
        create_loc_conf: Some(sub_create_conf),
        merge_loc_conf: Some(sub_merge_conf),
        ..Default::default()
    };

    const MSL: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd_fn!("sub_filter", MSL | NGX_CONF_TAKE2, ConfLevel::Loc, sub_filter),
        cmd_fn!("sub_filter_types", MSL | NGX_CONF_1MORE, ConfLevel::Loc, sub_types_slot),
        cmd!("sub_filter_once", MSL | NGX_CONF_FLAG, ConfLevel::Loc, SubLocConf, once, set_flag),
        cmd!("sub_filter_last_modified", MSL | NGX_CONF_FLAG, ConfLevel::Loc, SubLocConf, last_modified, set_flag),
    ];

    http_module_def("ngx_http_sub_filter_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(p: &[&[u8]]) -> Vec<SubMatch> {
        p.iter().enumerate().map(|(i, m)| SubMatch { match_: m.to_vec(), value: i }).collect()
    }

    #[test]
    fn init_tables() {
        let mut m = matches(&[b"foo"]);
        let t = sub_init_tables(&mut m);

        assert_eq!((t.min_match_len, t.max_match_len), (3, 3));
        assert_eq!(t.shift[b'o' as usize], 0);
        assert_eq!(t.shift[b'f' as usize], 2);
        assert_eq!(t.shift[b'x' as usize], 3);
        assert_eq!(t.index[b'o' as usize], 0);
        assert_eq!(t.index[b'o' as usize + 1], 1);

        // sorted by the character at min_match_len - 1, stable
        let mut m = matches(&[b"xab", b"yb", b"za", b"wb"]);
        let t = sub_init_tables(&mut m);

        assert_eq!((t.min_match_len, t.max_match_len), (2, 3));
        assert_eq!(m.iter().map(|m| m.value).collect::<Vec<_>>(), vec![0, 2, 1, 3]);
        assert_eq!(t.index[b'a' as usize], 0);
        assert_eq!(t.index[b'b' as usize], 2);
        assert_eq!(t.index[b'c' as usize], 4);
    }

    #[test]
    fn match_across_looked() {
        assert_eq!(sub_match(b"obar", 0, 4, b"fo", -2, b"foo"), NGX_OK);
        assert_eq!(sub_match(b"xbar", 0, 4, b"fo", -2, b"foo"), NGX_DECLINED);
        assert_eq!(sub_match(b"ABC", 0, 3, b"", 1, b"bcd"), NGX_AGAIN);
        assert_eq!(sub_match(b"ABCD", 0, 4, b"", 1, b"bcd"), NGX_OK);
    }
}
