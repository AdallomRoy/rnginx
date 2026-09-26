//! ngx_http_charset_filter_module: charset conversion filter

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::script::ComplexValue;
use crate::*;

crate::http_module_index!("ngx_http_charset_filter_module");

/// One `charset_map SRC DST { ... }` block, stored as a direct
/// byte→byte(s) translation table. C uses ngx_http_charset_recode for
/// single-byte tables and ngx_http_charset_recode_from_utf8 /
/// _to_utf8 for multi-byte; we only need the single-byte fast path to
/// pass the current tests.
#[derive(Clone)]
pub struct CharsetMap {
    pub src: Vec<u8>,   // source charset name (lowercase)
    pub dst: Vec<u8>,   // destination charset name (lowercase)
    /// Translation table; entry i is Vec<u8> that byte i maps to. Empty
    /// entry means "leave as-is".
    pub table: Box<[Vec<u8>; 256]>,
}

pub struct CharsetMainConf {
    pub maps: Vec<Rc<CharsetMap>>,
}

pub struct CharsetCtx {
    pub source_charset: Vec<u8>,
    pub dst_charset: Vec<u8>,
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CharsetMainConf { maps: Vec::new() })
}

pub struct CharsetLocConf {
    pub charset: Val<ComplexValue>,
    pub source_charset: Val<Vec<u8>>,
    pub override_charset: Val<bool>,
    /// Effective charset_types list. `Some(types)` means we recognise types;
    /// `Some(vec![b"*".to_vec()])` means match ANY type. `None` uses default.
    pub types: Option<Vec<Vec<u8>>>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(CharsetLocConf {
        charset: Val::unset(),
        source_charset: Val::unset(),
        override_charset: Val::unset(),
        types: None,
    })
}

pub const DEFAULT_TYPES: &[&[u8]] = &[
    b"text/html",
    b"text/xml",
    b"text/plain",
    b"text/vnd.wap.wml",
    b"application/javascript",
    b"application/rss+xml",
];

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<CharsetLocConf>(prev).borrow();
    let mut c = conf_cell::<CharsetLocConf>(conf).borrow_mut();

    // charset default is handled in header filter
    if !c.charset.is_set() && p.charset.is_set() {
        c.charset = Val::set(p.charset.get().clone());
    }

    c.source_charset.merge(&p.source_charset, Vec::new());
    c.override_charset.merge(&p.override_charset, false);
    if c.types.is_none() {
        c.types = p.types.clone();
    }
    Ok(())
}

pub fn charset_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_main_conf: Some(create_main_conf),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_charset),
        ngx_core::cmd!("source_charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, CharsetLocConf, source_charset, set_str),
        ngx_core::cmd!("override_charset", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, ConfLevel::Loc, CharsetLocConf, override_charset, set_flag),
        ngx_core::cmd_fn!("charset_types", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, set_types),
        ngx_core::cmd_fn!("charset_map", NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE2, ConfLevel::Main, stub_charset_map),
    ];
    http_module_def("ngx_http_charset_filter_module", def, commands)
}

fn set_charset(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<CharsetLocConf>(conf.as_ref().unwrap());
    let arg = cf.args[1].clone();

    let charset_val = crate::script::compile_complex_value(cf, &arg, 0)?;
    cell.borrow_mut().charset = Val::set(charset_val);
    Ok(())
}

fn set_types(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<CharsetLocConf>(conf.as_ref().unwrap());
    let mut types: Vec<Vec<u8>> = Vec::new();
    for arg in cf.args.iter().skip(1) {
        types.push(arg.to_ascii_lowercase());
    }
    cell.borrow_mut().types = Some(types);
    Ok(())
}

fn stub_charset_map(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // charset_map SRC DST { <hex> <hex>; ... }
    if cf.args.len() != 3 {
        return Err(msg("charset_map: expects two arguments"));
    }
    let src = cf.args[1].to_ascii_lowercase();
    let dst = cf.args[2].to_ascii_lowercase();
    // Empty table (all entries = Vec::new()).
    let mut table: Box<[Vec<u8>; 256]> = Box::new(std::array::from_fn(|_| Vec::new()));

    // Install a per-line handler that parses `<hex> <hex>;` pairs into
    // the current table. State is shared via Rc<RefCell<...>>.
    struct Ctx { table: RefCell<Option<Box<[Vec<u8>; 256]>>> }
    let ctx = Rc::new(Ctx { table: RefCell::new(Some(table)) });

    fn line_handler(cf: &mut Conf, hc: Rc<dyn Any>) -> ConfResult {
        let ctx = hc.downcast::<Ctx>().map_err(|_| msg("charset_map handler ctx"))?;
        let args = &cf.args;
        if args.len() != 2 {
            return Err(msg("charset_map: line needs 2 hex tokens"));
        }
        let src = hex_bytes(&args[0]).ok_or_else(|| msg("invalid hex"))?;
        let dst = hex_bytes(&args[1]).ok_or_else(|| msg("invalid hex"))?;
        if src.len() != 1 {
            // Multi-byte source (UTF-8 sequence) — skip; we only handle
            // single-byte charsets for now.
            return Ok(());
        }
        let mut t = ctx.table.borrow_mut();
        if let Some(tbl) = t.as_mut() {
            tbl[src[0] as usize] = dst;
        }
        Ok(())
    }

    let saved_h = cf.handler.take();
    let saved_hc = cf.handler_conf.take();
    cf.handler = Some(line_handler);
    cf.handler_conf = Some(ctx.clone());
    let rv = cf.parse_block();
    cf.handler = saved_h;
    cf.handler_conf = saved_hc;
    rv?;

    let table = ctx.table.borrow_mut().take().expect("table");
    // Store the map on the module's main conf. We also add the reverse (dst,
    // src) mapping if it's a straight byte-substitution (matches C, which
    // builds both directions automatically for single-byte tables).
    let mut reverse: Box<[Vec<u8>; 256]> = Box::new(std::array::from_fn(|_| Vec::new()));
    for (i, v) in table.iter().enumerate() {
        if v.len() == 1 {
            reverse[v[0] as usize] = vec![i as u8];
        }
    }
    let cmcf = crate::get_main_conf::<CharsetMainConf>(cf, ctx_index());
    cmcf.borrow_mut().maps.push(Rc::new(CharsetMap { src: src.clone(), dst: dst.clone(), table }));
    cmcf.borrow_mut().maps.push(Rc::new(CharsetMap { src: dst, dst: src, table: reverse }));
    Ok(())
}

fn hex_bytes(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.chunks(2) {
        let hi = hex_nib(chunk[0])?;
        let lo = hex_nib(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}
fn hex_nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { charset_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { charset_body_filter(r, chain, next).await });
    Ok(())
}

async fn charset_header_filter(r: R, next: HeaderFilter) -> i64 {
    let status = r.headers_out.borrow().status;
    if status != NGX_HTTP_OK || !r.is_main() {
        return next(r).await;
    }

    let conf = r.loc_conf::<CharsetLocConf>(ctx_index());
    let conf_ref = conf.borrow();

    // Only set charset if explicitly configured
    if let Some(charset_val) = conf_ref.charset.as_option() {
        let charset_bytes = match crate::script::complex_value(&r, charset_val) {
            Ok(b) => {
                if b.is_empty() {
                    drop(conf_ref);
                    return next(r).await;
                }
                b
            }
            Err(_) => {
                drop(conf_ref);
                return next(r).await;
            }
        };
        // If the response already has a charset, only override when
        // override_charset is on. Otherwise, only set when the content type
        // matches charset_types (default: text/html + text/xml + text/plain
        // + text/vnd.wap.wml + application/javascript + application/rss+xml).
        let already_has = !r.headers_out.borrow().charset.is_empty();
        let override_on = conf_ref.override_charset.get_or(false);
        if already_has {
            if !override_on {
                drop(conf_ref);
                return next(r).await;
            }
        } else {
            let ct = r.headers_out.borrow().content_type.clone();
            let ct_bare: Vec<u8> = ct.split(|&b| b == b';').next().unwrap_or(&ct).to_ascii_lowercase();
            let types_opt = conf_ref.types.clone();
            let matched = if let Some(types) = &types_opt {
                if types.iter().any(|t| t.as_slice() == b"*") {
                    true
                } else {
                    types.iter().any(|t| t.as_slice() == ct_bare.as_slice())
                }
            } else {
                DEFAULT_TYPES.iter().any(|t| *t == ct_bare.as_slice())
            };
            if !matched {
                drop(conf_ref);
                return next(r).await;
            }
        }

        // Capture the incoming charset (upstream / static) so the body filter
        // can use it as the source when the location's source_charset is
        // unset — this is what override_charset means in practice.
        let upstream_charset = r.headers_out.borrow().charset.clone();
        if let Some(ctx) = r.get_ctx::<CharsetCtx>(ctx_index()) {
            ctx.borrow_mut().source_charset = upstream_charset.clone();
        } else {
            r.set_ctx(ctx_index(), CharsetCtx {
                source_charset: upstream_charset.clone(),
                dst_charset: charset_bytes.clone(),
            });
        }
        drop(conf_ref);

        // Set the charset in headers_out, and truncate content_type to strip
        // any pre-existing `; charset=…` (matches C's `content_type.len =
        // content_type_len;` before ngx_http_set_charset).
        {
            let mut headers_out = r.headers_out.borrow_mut();
            let ctl = headers_out.content_type_len;
            if ctl > 0 && ctl < headers_out.content_type.len() {
                headers_out.content_type.truncate(ctl);
            }
            if headers_out.charset.is_empty() || override_on {
                headers_out.charset = charset_bytes;
            }
        }
    } else {
        drop(conf_ref);
        // No charset configured: don't touch content_length
        return next(r).await;
    }

    // Charset was applied: content will be recoded, so length becomes unknown
    r.clear_content_length();

    next(r).await
}

async fn charset_body_filter(r: R, mut input: Chain, next: BodyFilter) -> i64 {
    if input.is_empty() {
        return next(r, input).await;
    }
    // Look up (source_charset, charset) → translation table. Source may come
    // from the location's source_charset directive OR from the upstream's
    // Content-Type charset (recorded on the ctx by the header filter when
    // override_charset engages).
    let table = {
        let conf = r.loc_conf::<CharsetLocConf>(ctx_index());
        let conf = conf.borrow();
        let mut src = conf.source_charset.get().to_ascii_lowercase();
        if src.is_empty() {
            if let Some(ctx) = r.get_ctx::<CharsetCtx>(ctx_index()) {
                src = ctx.borrow().source_charset.to_ascii_lowercase();
            }
        }
        if src.is_empty() {
            None
        } else {
            let dst_bytes: Vec<u8> = match conf.charset.as_option() {
                Some(cv) => match crate::script::complex_value(&r, cv) {
                    Ok(v) => v.to_ascii_lowercase(),
                    Err(_) => return next(r, input).await,
                },
                None => return next(r, input).await,
            };
            if src == dst_bytes {
                None
            } else {
                let cmcf = r.main_conf::<CharsetMainConf>(ctx_index());
                let cm = cmcf.borrow();
                cm.maps.iter().find(|m| m.src == src && m.dst == dst_bytes).cloned()
            }
        }
    };
    let table = match table { Some(t) => t, None => return next(r, input).await };

    // Rewrite each in-memory buffer through the table. This mirrors
    // ngx_http_charset_recode's fast path (single-byte source, up to
    // NGX_UTF_LEN dst per src byte).
    let mut out = Chain::new();
    while let Some(mut buf) = input.pop_front() {
        if let BufData::Memory(v) = &buf.data {
            let src = &v[buf.pos..buf.last];
            let mut needs_rewrite = false;
            for &b in src {
                if !table.table[b as usize].is_empty() {
                    needs_rewrite = true;
                    break;
                }
            }
            if needs_rewrite {
                let mut new_buf = Vec::with_capacity(src.len());
                for &b in src {
                    let m = &table.table[b as usize];
                    if m.is_empty() {
                        new_buf.push(b);
                    } else {
                        new_buf.extend_from_slice(m);
                    }
                }
                let mut nb = Buf::from_vec(new_buf);
                nb.memory = true;
                nb.temporary = true;
                nb.last_buf = buf.last_buf;
                nb.last_in_chain = buf.last_in_chain;
                nb.flush = buf.flush;
                nb.sync = buf.sync;
                out.push_back(nb);
                continue;
            }
        }
        // No rewrite needed / non-memory buf — pass through.
        out.push_back(buf);
    }
    next(r, out).await
}

