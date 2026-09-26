//! Complex values and predicates (subset of ngx_http_script.c).

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::rc::*;
use ngx_core::string::B;

use crate::request::*;
use crate::variables::*;
use crate::*;

pub const NGX_HTTP_COMPLEX_VALUE_ZERO: u32 = 1;
pub const NGX_HTTP_COMPLEX_VALUE_ROOT_PREFIX: u32 = 2;
pub const NGX_HTTP_COMPLEX_VALUE_CONF_PREFIX: u32 = 4;

#[derive(Clone, Debug)]
pub enum Part {
    Literal(Vec<u8>),
    Var(usize),
    Capture(usize),
}

#[derive(Clone, Debug)]
pub struct ComplexValue {
    pub value: Vec<u8>,
    pub parts: Option<Vec<Part>>,
    pub flags: u32,
}

impl ComplexValue {
    pub fn constant(v: &[u8]) -> ComplexValue {
        ComplexValue { value: v.to_vec(), parts: None, flags: 0 }
    }
    pub fn is_constant(&self) -> bool {
        self.parts.is_none()
    }
    pub fn set_constant(&mut self, v: &[u8]) {
        self.value = v.to_vec();
    }
}

/// ngx_http_script_variables_count
pub fn script_variables_count(s: &[u8]) -> usize {
    s.iter().filter(|&&c| c == b'$').count()
}

/// Parse "$name", "${name}", "$1" at position i (after the '$'). Returns (part, consumed).
fn parse_var_ref(cf: &mut Conf, s: &[u8], i: usize) -> Result<(Part, usize), ConfError> {
    let src = &s[i..];
    if src.is_empty() {
        return Err(cf.emerg(format_args!("invalid variable name")));
    }
    if src[0].is_ascii_digit() {
        let n = (src[0] - b'0') as usize;
        return Ok((Part::Capture(n * 2), 1));
    }
    let (name, consumed) = if src[0] == b'{' {
        let end = match memchr::memchr(b'}', src) {
            Some(e) => e,
            None => return Err(cf.emerg(format_args!("the closing bracket in \"{}\" variable is missing", B(&src[1..])))),
        };
        if end == 1 {
            return Err(cf.emerg(format_args!("invalid variable name")));
        }
        (src[1..end].to_vec(), end + 1)
    } else {
        let mut end = 0;
        while end < src.len() && (src[end].is_ascii_alphanumeric() || src[end] == b'_') {
            end += 1;
        }
        if end == 0 {
            return Err(cf.emerg(format_args!("invalid variable name")));
        }
        (src[..end].to_vec(), end)
    };
    if name.iter().all(|c| c.is_ascii_digit()) && !name.is_empty() && src[0] == b'{' {
        let n: usize = std::str::from_utf8(&name).unwrap().parse().unwrap_or(0);
        return Ok((Part::Capture(n * 2), consumed));
    }
    let index = get_variable_index(cf, &name)?;
    Ok((Part::Var(index), consumed))
}

/// ngx_http_compile_complex_value
pub fn compile_complex_value(cf: &mut Conf, v: &[u8], flags: u32) -> Result<ComplexValue, ConfError> {
    let nv = v.iter().filter(|&&c| c == b'$').count();
    let mut value = v.to_vec();
    let mut prefix = false;
    if (flags & NGX_HTTP_COMPLEX_VALUE_ROOT_PREFIX) != 0 || (flags & NGX_HTTP_COMPLEX_VALUE_CONF_PREFIX) != 0 {
        if !value.is_empty() && value[0] != b'$' && value[0] != b'/' {
            prefix = true;
        }
    }
    if nv == 0 && !prefix {
        return Ok(ComplexValue { value, parts: None, flags });
    }
    if prefix {
        value = cf.full_name(&value, (flags & NGX_HTTP_COMPLEX_VALUE_CONF_PREFIX) != 0);
        if nv == 0 {
            return Ok(ComplexValue { value, parts: None, flags });
        }
    }
    let mut parts = Vec::new();
    let mut lit = Vec::new();
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'$' {
            if !lit.is_empty() {
                parts.push(Part::Literal(std::mem::take(&mut lit)));
            }
            let (p, consumed) = parse_var_ref(cf, &value, i + 1)?;
            parts.push(p);
            i += 1 + consumed;
            continue;
        }
        lit.push(value[i]);
        i += 1;
    }
    if !lit.is_empty() {
        parts.push(Part::Literal(lit));
    }
    Ok(ComplexValue { value, parts: Some(parts), flags })
}

/// ngx_http_complex_value
pub fn complex_value(r: &R, cv: &ComplexValue) -> Result<Vec<u8>, i64> {
    let parts = match &cv.parts {
        None => return Ok(cv.value.clone()),
        Some(p) => p,
    };
    let mut out = Vec::new();
    for p in parts {
        match p {
            Part::Literal(l) => out.extend_from_slice(l),
            Part::Var(idx) => {
                let vv = match crate::variables::get_flushed_variable(r, *idx) {
                    Some(v) => v,
                    None => return Err(NGX_ERROR),
                };
                if !vv.not_found {
                    out.extend_from_slice(&vv.data);
                }
            }
            Part::Capture(n) => {
                let caps = r.captures.borrow();
                let data = r.captures_data.borrow();
                if *n + 1 < caps.len() {
                    let s = caps[*n];
                    let e = caps[*n + 1];
                    if s >= 0 && e >= s {
                        out.extend_from_slice(&data[s as usize..e as usize]);
                    }
                }
            }
        }
    }
    if cv.flags & NGX_HTTP_COMPLEX_VALUE_ZERO != 0 {
        // C appends a terminating zero; irrelevant here
    }
    Ok(out)
}

/// ngx_http_complex_value_size: parse the value as a size; `default` on empty.
pub fn complex_value_size(r: &R, cv: &Option<Rc<ComplexValue>>, default: usize) -> usize {
    let cv = match cv {
        Some(c) => c,
        None => return default,
    };
    if cv.is_constant() {
        return ngx_core::parse::parse_size(&cv.value).unwrap_or(default);
    }
    match complex_value(r, cv) {
        Ok(v) => match ngx_core::parse::parse_size(&v) {
            Some(s) => s,
            None => {
                ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "invalid size \"{}\"", B(&v));
                default
            }
        },
        Err(_) => default,
    }
}

/// ngx_http_set_complex_value_slot
pub fn set_complex_value_slot(cf: &mut Conf, _cmd: &Command, slot: &mut Val<Option<Rc<ComplexValue>>>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    let v = cf.args[1].clone();
    let cv = compile_complex_value(cf, &v, 0)?;
    *slot = Val::set(Some(Rc::new(cv)));
    Ok(())
}

/// ngx_http_set_complex_value_zero_slot
pub fn set_complex_value_zero_slot(cf: &mut Conf, _cmd: &Command, slot: &mut Val<Option<Rc<ComplexValue>>>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    let v = cf.args[1].clone();
    let cv = compile_complex_value(cf, &v, NGX_HTTP_COMPLEX_VALUE_ZERO)?;
    *slot = Val::set(Some(Rc::new(cv)));
    Ok(())
}

/// ngx_http_set_complex_value_size_slot
pub fn set_complex_value_size_slot(cf: &mut Conf, cmd: &Command, slot: &mut Val<Option<Rc<ComplexValue>>>) -> ConfResult {
    set_complex_value_slot(cf, cmd, slot)?;
    let cv = slot.get().clone().unwrap();
    if cv.is_constant() {
        if ngx_core::parse::parse_size(&cv.value).is_none() {
            return Err(msg("invalid value"));
        }
    }
    Ok(())
}

/// ngx_http_set_predicate_slot
pub fn set_predicate_slot(cf: &mut Conf, _cmd: &Command, slot: &mut Val<Option<Rc<Vec<ComplexValue>>>>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    let args = cf.args.clone();
    let mut v = Vec::new();
    for a in &args[1..] {
        v.push(compile_complex_value(cf, a, 0)?);
    }
    *slot = Val::set(Some(Rc::new(v)));
    Ok(())
}

/// ngx_http_test_predicates: NGX_OK if all non-empty and not "0", else NGX_DECLINED.
pub fn test_predicates(r: &R, preds: &Option<Rc<Vec<ComplexValue>>>) -> i64 {
    let preds = match preds {
        None => return NGX_OK,
        Some(p) => p,
    };
    // Matches ngx_http_test_predicates in C: any truthy predicate ⇒
    // NGX_DECLINED; all empty/"0" (and predicates non-empty) ⇒ NGX_OK.
    for cv in preds.iter() {
        let val = match complex_value(r, cv) {
            Ok(v) => v,
            Err(_) => return NGX_ERROR,
        };
        if !val.is_empty() && !(val.len() == 1 && val[0] == b'0') {
            return NGX_DECLINED;
        }
    }
    NGX_OK
}

/// ngx_http_test_required_predicates: NGX_OK if all are "1"? — C: declined when any value is empty or "0" (same as test_predicates but requires each to be non-empty)
pub fn test_required_predicates(r: &R, preds: &Option<Rc<Vec<ComplexValue>>>) -> i64 {
    let preds = match preds {
        None => return NGX_OK,
        Some(p) => p,
    };
    for cv in preds.iter() {
        let val = match complex_value(r, cv) {
            Ok(v) => v,
            Err(_) => return NGX_ERROR,
        };
        if val.is_empty() || (val.len() == 1 && val[0] == b'0') {
            return NGX_DECLINED;
        }
    }
    NGX_OK
}

pub fn _unused(_: &dyn Any) {}
