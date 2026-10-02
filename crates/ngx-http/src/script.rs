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
        // an empty value gets the prefix too, as in C
        if value.first() != Some(&b'$') && value.first() != Some(&b'/') {
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

/// ngx_http_complex_value, into a buffer of its own: a copy of a constant
/// or of a single variable's value, else the parts evaluated into one
/// buffer sized up front.
///
/// (A terminating zero of NGX_HTTP_COMPLEX_VALUE_ZERO is irrelevant
/// here.)
pub fn complex_value(r: &R, cv: &ComplexValue) -> Result<Vec<u8>, i64> {
    let parts = match &cv.parts {
        None => return Ok(cv.value.clone()),
        Some(p) => p,
    };
    if let [Part::Var(index)] = parts[..] {
        return with_flushed_variable(r, index, |v| match v {
            None => Err(NGX_ERROR),
            Some(v) if v.not_found => Ok(Vec::new()),
            Some(v) => Ok(v.data.clone()),
        });
    }
    let mut out = Vec::new();
    complex_value_parts(r, parts, &mut out)?;
    Ok(out)
}

/// ngx_http_complex_value, copied only when it has variables: a constant
/// is its stored bytes.
pub fn complex_value_cow<'a>(r: &R, cv: &'a ComplexValue) -> Result<std::borrow::Cow<'a, [u8]>, i64> {
    match &cv.parts {
        None => Ok(std::borrow::Cow::Borrowed(&cv.value)),
        Some(_) => complex_value(r, cv).map(std::borrow::Cow::Owned),
    }
}

/// ngx_http_complex_value lent to `f`, without a copy: a constant's stored
/// bytes, a single variable's value where r->variables caches it, else the
/// parts evaluated into one buffer sized up front. Err when a variable
/// cannot be evaluated.
///
/// `f` must not evaluate variables (r->variables may be borrowed while it
/// runs).
pub fn with_complex_value<T>(r: &R, cv: &ComplexValue, f: impl FnOnce(&[u8]) -> T) -> Result<T, i64> {
    let parts = match &cv.parts {
        None => return Ok(f(&cv.value)),
        Some(p) => p,
    };
    if let [Part::Var(index)] = parts[..] {
        return with_flushed_variable(r, index, |v| match v {
            None => Err(NGX_ERROR),
            Some(v) if v.not_found => Ok(f(b"")),
            Some(v) => Ok(f(&v.data)),
        });
    }
    let mut out = Vec::new();
    complex_value_parts(r, parts, &mut out)?;
    Ok(f(&out))
}

/// The codes of a complex value with variables, as ngx_http_complex_value()
/// runs them: the non-cacheable variables of the value flushed
/// (ngx_http_script_flush_complex_value), the lengths codes, then the
/// values codes into `out`, reserved for the value; the variables are taken
/// with ngx_http_get_indexed_variable() (e.flushed = 1), so a variable is
/// evaluated once even if the value has it twice.
fn complex_value_parts(r: &R, parts: &[Part], out: &mut Vec<u8>) -> Result<(), i64> {
    for p in parts {
        if let Part::Var(index) = p {
            flush_variable(r, *index);
        }
    }

    let mut len = 0;

    for p in parts {
        len += match p {
            Part::Literal(l) => l.len(),
            Part::Var(index) => match with_indexed_variable(r, *index, |v| v.map(|v| if v.not_found { 0 } else { v.data.len() })) {
                Some(n) => n,
                None => return Err(NGX_ERROR),
            },
            Part::Capture(n) => capture(r, *n, |c| c.len()),
        };
    }

    out.reserve(len);

    for p in parts {
        match p {
            Part::Literal(l) => out.extend_from_slice(l),
            Part::Var(index) => {
                let found = with_indexed_variable(r, *index, |v| match v {
                    None => false,
                    Some(v) => {
                        if !v.not_found {
                            out.extend_from_slice(&v.data);
                        }
                        true
                    }
                });
                if !found {
                    return Err(NGX_ERROR);
                }
            }
            Part::Capture(n) => capture(r, *n, |c| out.extend_from_slice(c)),
        }
    }

    Ok(())
}

/// The capture n (2 * $n) of the request, empty if there is none
/// (ngx_http_script_copy_capture_code: n < r->ncaptures)
fn capture<T>(r: &R, n: usize, f: impl FnOnce(&[u8]) -> T) -> T {
    if n < r.ncaptures.get() {
        let caps = r.captures.borrow();
        if n + 1 < caps.len() {
            let (s, e) = (caps[n], caps[n + 1]);
            if s >= 0 && e >= s {
                let data = r.captures_data.borrow();
                if (e as usize) <= data.len() {
                    return f(&data[s as usize..e as usize]);
                }
            }
        }
    }
    f(b"")
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
    let size = with_complex_value(r, cv, |v| match ngx_core::parse::parse_size(v) {
        Some(s) => s,
        None => {
            ngx_core::ngx_log_error!(ngx_core::log::NGX_LOG_ERR, r.connection.log, None, "invalid size \"{}\"", B(v));
            default
        }
    });
    size.unwrap_or(default)
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
        match with_complex_value(r, cv, |val| !val.is_empty() && !(val.len() == 1 && val[0] == b'0')) {
            Ok(true) => return NGX_DECLINED,
            Ok(false) => {}
            Err(_) => return NGX_ERROR,
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
        match with_complex_value(r, cv, |val| val.is_empty() || (val.len() == 1 && val[0] == b'0')) {
            Ok(true) => return NGX_DECLINED,
            Ok(false) => {}
            Err(_) => return NGX_ERROR,
        }
    }
    NGX_OK
}

/// ngx_http_script_compile() of the lengths and values programs run by
/// script_run() (sc->complete_lengths and sc->complete_values, without
/// sc->flushes; the args, zero and prefix codes are not used by the
/// callers): Part::Literal is ngx_http_script_copy_code, Part::Var
/// ngx_http_script_copy_var_code and Part::Capture(2 * n) the
/// ngx_http_script_copy_capture_code of $1..$9.
pub fn script_compile(cf: &mut Conf, source: &[u8]) -> Result<Vec<Part>, ConfError> {
    let mut codes = Vec::new();

    let invalid_variable = |cf: &Conf| cf.emerg(format_args!("invalid variable name"));

    let mut i = 0;

    while i < source.len() {
        if source[i] == b'$' {
            i += 1;

            if i == source.len() {
                return Err(invalid_variable(cf));
            }

            if (b'1'..=b'9').contains(&source[i]) {
                let n = (source[i] - b'0') as usize;

                codes.push(Part::Capture(2 * n));

                i += 1;

                continue;
            }

            let mut bracket = false;

            if source[i] == b'{' {
                bracket = true;

                i += 1;

                if i == source.len() {
                    return Err(invalid_variable(cf));
                }
            }

            let start = i;
            let mut len = 0;

            while i < source.len() {
                let ch = source[i];

                if ch == b'}' && bracket {
                    i += 1;
                    bracket = false;
                    break;
                }

                if ch.is_ascii_alphanumeric() || ch == b'_' {
                    i += 1;
                    len += 1;
                    continue;
                }

                break;
            }

            if bracket {
                return Err(cf.emerg(format_args!("the closing bracket in \"{}\" variable is missing", B(&source[start..start + len]))));
            }

            if len == 0 {
                return Err(invalid_variable(cf));
            }

            let index = get_variable_index(cf, &source[start..start + len])?;

            codes.push(Part::Var(index));

            continue;
        }

        let start = i;

        while i < source.len() && source[i] != b'$' {
            i += 1;
        }

        codes.push(Part::Literal(source[start..i].to_vec()));
    }

    Ok(codes)
}

/// ngx_http_script_run: the value of the codes of script_compile(), the
/// no cacheable variables are flushed first and the variables are taken
/// with ngx_http_get_indexed_variable() (e.flushed = 1): the lengths codes,
/// then the values codes into a buffer of that length
pub fn script_run(r: &R, codes: &[Part]) -> Option<Vec<u8>> {
    {
        let mut vars = r.variables.borrow_mut();

        for v in vars.iter_mut() {
            if v.no_cacheable {
                v.valid = false;
                v.not_found = false;
            }
        }
    }

    let mut len = 0;

    for code in codes {
        len += match code {
            Part::Literal(data) => data.len(),
            Part::Var(index) => with_indexed_variable(r, *index, |v| match v {
                Some(v) if !v.not_found => v.data.len(),
                _ => 0,
            }),
            Part::Capture(n) => capture(r, *n, |c| c.len()),
        };
    }

    let mut value = Vec::with_capacity(len);

    for code in codes {
        match code {
            Part::Literal(data) => {
                value.extend_from_slice(data);

                http_debug!(r, "http script copy: \"{}\"", B(data));
            }

            Part::Var(index) => {
                with_indexed_variable(r, *index, |v| {
                    if let Some(v) = v {
                        if !v.not_found {
                            value.extend_from_slice(&v.data);

                            http_debug!(r, "http script var: \"{}\"", B(&v.data));
                        }
                    }
                });
            }

            Part::Capture(n) => {
                let pos = value.len();

                capture(r, *n, |c| value.extend_from_slice(c));

                http_debug!(r, "http script capture: \"{}\"", B(&value[pos..]));
            }
        }
    }

    Some(value)
}

/// ngx_http_script_flush_no_cacheable_variables
pub fn script_flush_no_cacheable_variables(r: &R, indices: Option<&[usize]>) {
    if let Some(indices) = indices {
        let mut vars = r.variables.borrow_mut();

        for index in indices {
            if let Some(v) = vars.get_mut(*index) {
                if v.no_cacheable {
                    v.valid = false;
                    v.not_found = false;
                }
            }
        }
    }
}

pub fn _unused(_: &dyn Any) {}
