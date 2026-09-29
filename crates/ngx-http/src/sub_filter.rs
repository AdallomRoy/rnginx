//! ngx_http_sub_filter_module: substitute text in response body

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;

use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_sub_filter_module");

#[derive(Clone)]
pub struct SubPair {
    pub match_val: ComplexValue,
    pub replacement_val: ComplexValue,
}

pub struct SubLocConf {
    pub pairs: Val<Vec<SubPair>>,
    pub once: Val<bool>,
    pub last_modified: Val<bool>,
}

#[derive(Clone)]
struct SubCtx {
    applied: u32,
    once: bool,
    /// Trailing bytes of the last chunk that could be the prefix of a still-
    /// pending pattern match (e.g. seeing 'z' when the pattern is 'za'). These
    /// stay buffered across body_filter calls, waiting for the next chunk to
    /// either complete a match or reveal that no match starts here.
    pending: Vec<u8>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SubLocConf {
        pairs: Val::unset(),
        once: Val::unset(),
        last_modified: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<SubLocConf>(prev).borrow();
    let mut c = conf_cell::<SubLocConf>(conf).borrow_mut();
    c.pairs.merge(&p.pairs, Vec::new());
    c.once.merge(&p.once, true);  // default is true (replace only once)
    c.last_modified.merge(&p.last_modified, false);  // default is false (remove Last-Modified)
    Ok(())
}

pub fn sub_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("sub_filter", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::Loc, add_sub_filter),
        ngx_core::cmd_fn!("sub_filter_types", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, stub_types),
        ngx_core::cmd!("sub_filter_once", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, SubLocConf, once, set_flag),
        ngx_core::cmd!("sub_filter_last_modified", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, SubLocConf, last_modified, set_flag),
    ];
    http_module_def("ngx_http_sub_filter_module", def, commands)
}

fn stub_types(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // TODO: implement types filtering
    Ok(())
}

fn add_sub_filter(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let match_arg = cf.args[1].clone();
    let replacement_arg = cf.args[2].clone();
    let cell = conf_rc::<SubLocConf>(conf.as_ref().unwrap());
    let match_val = compile_complex_value(cf, &match_arg, 0)?;
    let replacement_val = compile_complex_value(cf, &replacement_arg, 0)?;

    let pair = SubPair {
        match_val,
        replacement_val,
    };

    let mut c = cell.borrow_mut();
    let mut pairs = if let Some(p) = c.pairs.as_option() {
        p.clone()
    } else {
        Vec::new()
    };
    pairs.push(pair);
    c.pairs = Val::set(pairs);

    Ok(())
}

fn init(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { sub_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { sub_body_filter(r, chain, next).await });
    Ok(())
}

async fn sub_header_filter(r: R, next: HeaderFilter) -> i64 {
    let status = r.headers_out.borrow().status;
    let conf = r.loc_conf::<SubLocConf>(ctx_index());
    let conf_cell = conf.borrow();

    // Check if pairs exist
    let has_pairs = conf_cell.pairs.as_option().map_or(false, |p| !p.is_empty());

    if status != NGX_HTTP_OK || !r.is_main() || !has_pairs {
        drop(conf_cell);
        return next(r).await;
    }

    drop(conf_cell);

    // Set up context
    let once = r.loc_conf::<SubLocConf>(ctx_index()).borrow().once.get_or(false);

    let ctx = SubCtx { applied: 0, once, pending: Vec::new() };
    r.set_ctx(ctx_index(), ctx);

    r.clear_content_length();

    let last_modified = r.loc_conf::<SubLocConf>(ctx_index()).borrow().last_modified.get_or(false);

    if !last_modified {
        // Default: clear Last-Modified and ETag
        r.clear_last_modified();
        r.clear_etag();
    } else {
        // If last_modified is on: set weak ETag
        crate::core_rt::weak_etag(&r);
    }

    next(r).await
}

/// One left-to-right pass over `content` with all the (lowercased)
/// patterns: at each position the longest match is replaced, each pattern
/// at most once with `once`. Returns the text and whether it replaced.
fn replace_matches(content: &[u8], compiled: &[(Vec<u8>, Vec<u8>)], once: bool, used: &mut [bool]) -> (Vec<u8>, bool) {
    let mut processed = Vec::with_capacity(content.len());
    let mut did_replace = false;
    let mut pos = 0;
    while pos < content.len() {
        // Try each pattern; pick the longest matching one (skip used ones
        // in once mode).
        let mut best: Option<(usize, usize)> = None; // (mlen, pair_idx)
        for (i, (m, _repl)) in compiled.iter().enumerate() {
            if once && used[i] { continue; }
            if pos + m.len() > content.len() { continue; }
            let slice = &content[pos..pos + m.len()];
            if slice.to_ascii_lowercase() == *m {
                if best.map_or(true, |(len, _)| m.len() > len) {
                    best = Some((m.len(), i));
                }
            }
        }
        if let Some((mlen, i)) = best {
            processed.extend_from_slice(&compiled[i].1);
            pos += mlen;
            did_replace = true;
            if once { used[i] = true; }
        } else {
            processed.push(content[pos]);
            pos += 1;
        }
    }
    (processed, did_replace)
}

async fn sub_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    if input.is_empty() {
        return next(r, input).await;
    }

    let ctx_opt = r.get_ctx::<SubCtx>(ctx_index());
    let ctx_rc = match ctx_opt {
        Some(c) => c,
        None => return next(r, input).await,
    };

    let conf = r.loc_conf::<SubLocConf>(ctx_index());
    let conf_ref = conf.borrow();

    // Check if pairs exist
    let pairs_opt = conf_ref.pairs.as_option();
    if pairs_opt.is_none() || pairs_opt.unwrap().is_empty() {
        drop(conf_ref);
        return next(r, input).await;
    }
    let pairs = pairs_opt.unwrap().clone();
    let once = conf_ref.once.get_or(false);
    drop(conf_ref);

    let mut output = Chain::new();
    let mut last_buf_flag = false;
    let mut flush_flag = false;
    let mut had_memory_buf = false;

    // Collect all memory buffers and pass through non-memory buffers.
    // Prepend any leftover partial-match buffer from the previous chunk so
    // we can detect matches straddling chunk boundaries (e.g. "z" tail + "a"
    // head of next chunk == "za").
    let mut full_content = ctx_rc.borrow_mut().pending.split_off(0);
    for buf in input.iter() {
        match &buf.data {
            ngx_core::buf::BufData::Memory(v) => {
                had_memory_buf = true;
                full_content.extend_from_slice(&v[buf.pos..buf.last]);
                if buf.last_buf {
                    last_buf_flag = true;
                }
                if buf.flush {
                    flush_flag = true;
                }
            }
            _ => {
                // Pass through non-memory buffers
                output.push_back(buf.clone());
            }
        }
    }

    // If no memory buffers, just pass through
    if !had_memory_buf {
        return next(r, output).await;
    }

    if full_content.is_empty() {
        if !output.is_empty() {
            return next(r, output).await;
        }
        return NGX_OK;
    }

    // Compile all patterns / replacements up-front so we can walk the
    // buffer left-to-right and pick the LONGEST match at each position
    // (matches ngx_http_sub_filter_module: single pass, all patterns tried
    // together, longest wins).
    let compiled: Vec<(Vec<u8>, Vec<u8>)> = pairs
        .iter()
        .filter_map(|p| {
            let m = crate::script::complex_value(&r, &p.match_val).ok()?;
            let repl = crate::script::complex_value(&r, &p.replacement_val).ok()?;
            if m.is_empty() { return None; }
            Some((m.to_ascii_lowercase(), repl))
        })
        .collect();

    // Per-pattern "already replaced" tracking for once=on (C's behavior: each
    // pattern replaces at most once, independently, not the whole filter).
    let mut used: Vec<bool> = vec![false; compiled.len()];
    let (processed, did_replace) = replace_matches(&full_content, &compiled, once, &mut used);

    // Compute the largest trailing suffix of `processed` that could still
    // be a prefix of one of our patterns. That tail is buffered until the
    // next chunk arrives; on last_buf we flush it as-is (no more data can
    // complete the match).
    let tail_len = if last_buf_flag {
        0
    } else {
        let mut max = 0usize;
        for pair in pairs.iter() {
            let m = match crate::script::complex_value(&r, &pair.match_val) {
                Ok(b) => b.to_ascii_lowercase(),
                Err(_) => continue,
            };
            if m.is_empty() { continue; }
            // Check if any suffix of `processed` (length 1..m.len()-1) matches
            // a prefix of `m`. Pick the longest one.
            let start = processed.len().saturating_sub(m.len() - 1);
            for k in start..processed.len() {
                let suf = &processed[k..];
                if suf.len() >= m.len() { continue; }
                let lc: Vec<u8> = suf.iter().map(|b| b.to_ascii_lowercase()).collect();
                if m.starts_with(&lc[..]) {
                    let cand = processed.len() - k;
                    if cand > max { max = cand; }
                    break;
                }
            }
        }
        max
    };
    let (emit, tail) = processed.split_at(processed.len() - tail_len);
    let emit_vec = emit.to_vec();
    let tail_vec = tail.to_vec();
    if !emit_vec.is_empty() {
        let mut new_buf = Buf::from_vec(emit_vec);
        new_buf.last_buf = last_buf_flag;
        new_buf.flush = flush_flag;
        output.push_back(new_buf);
    } else if last_buf_flag || flush_flag {
        // Preserve the last_buf and flush signals downstream even if
        // nothing to emit (b->last_buf = ctx->buf->last_buf, b->flush =
        // ctx->buf->flush on a sync buffer).
        let mut new_buf = Buf::from_vec(Vec::new());
        new_buf.last_buf = last_buf_flag;
        new_buf.flush = flush_flag;
        new_buf.sync = true;
        output.push_back(new_buf);
    }
    ctx_rc.borrow_mut().pending = tail_vec;
    let _ = did_replace;

    if output.is_empty() {
        return NGX_OK;
    }

    next(r, output).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(p: &[(&[u8], &[u8])]) -> Vec<(Vec<u8>, Vec<u8>)> {
        p.iter().map(|(m, r)| (m.to_ascii_lowercase(), r.to_vec())).collect()
    }

    #[test]
    fn replace_matches_case_insensitively() {
        let compiled = pairs(&[(b"world", b"Rust")]);
        let mut used = vec![false; 1];
        let (out, replaced) = replace_matches(b"Hello World, world", &compiled, false, &mut used);
        assert_eq!(out, b"Hello Rust, Rust");
        assert!(replaced);
    }

    #[test]
    fn replace_matches_once_per_pattern() {
        let compiled = pairs(&[(b"a", b"1"), (b"b", b"2")]);
        let mut used = vec![false; 2];
        let (out, _) = replace_matches(b"abab", &compiled, true, &mut used);
        assert_eq!(out, b"12ab");
    }

    #[test]
    fn replace_matches_longest_first() {
        let compiled = pairs(&[(b"ab", b"x"), (b"abc", b"y")]);
        let mut used = vec![false; 2];
        let (out, _) = replace_matches(b"abcab", &compiled, false, &mut used);
        assert_eq!(out, b"yx");

        let mut used = vec![false; 2];
        let (out, replaced) = replace_matches(b"none", &compiled, false, &mut used);
        assert_eq!(out, b"none");
        assert!(!replaced);
    }
}
