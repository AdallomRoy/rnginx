//! Complex values (ngx_stream_script.c).

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::variables::*;
use crate::*;

/// A code of the lengths/values programs of a complex value.
#[derive(Clone, Debug)]
pub enum Code {
    /// ngx_stream_script_copy_code
    Copy(Vec<u8>),
    /// ngx_stream_script_copy_var_code
    Var(usize),
    /// ngx_stream_script_copy_capture_code: n = 2 * $n
    Capture(usize),
    /// ngx_stream_script_full_name_code
    FullName(bool),
}

/// ngx_stream_complex_value_t
#[derive(Clone, Debug, Default)]
pub struct ComplexValue {
    pub value: Vec<u8>,
    pub flushes: Option<Vec<usize>>,
    /// the lengths and values programs (NULL for a constant value)
    pub codes: Option<Vec<Code>>,
    /// u.size
    pub size: usize,
}

impl ComplexValue {
    /// A value without variables.
    pub fn constant(v: &[u8]) -> ComplexValue {
        ComplexValue { value: v.to_vec(), flushes: None, codes: None, size: 0 }
    }

    /// cv->lengths == NULL
    pub fn is_constant(&self) -> bool {
        self.codes.is_none()
    }
}

/// ngx_stream_compile_complex_value_t
#[derive(Default)]
pub struct CompileComplexValue {
    pub zero: bool,
    pub conf_prefix: bool,
    pub root_prefix: bool,
}

/// ngx_stream_script_flush_complex_value
pub fn flush_complex_value(s: &Session, val: &ComplexValue) {
    if let Some(flushes) = &val.flushes {
        let mut vars = s.variables.borrow_mut();

        for index in flushes {
            if let Some(v) = vars.get_mut(*index) {
                if v.no_cacheable {
                    v.valid = false;
                    v.not_found = false;
                }
            }
        }
    }
}

/// ngx_stream_complex_value
pub fn complex_value(s: &Session, val: &ComplexValue) -> Result<Vec<u8>, ()> {
    let codes = match &val.codes {
        None => return Ok(val.value.clone()),
        Some(c) => c,
    };

    flush_complex_value(s, val);

    run_codes(s, codes)
}

/// The values program (e.flushed = 1: the variables are taken with
/// ngx_stream_get_indexed_variable()).
fn run_codes(s: &Session, codes: &[Code]) -> Result<Vec<u8>, ()> {
    let mut buf: Vec<u8> = Vec::new();

    for code in codes {
        match code {
            Code::Copy(data) => buf.extend_from_slice(data),

            Code::Var(index) => {
                if let Some(value) = get_indexed_variable(s, *index) {
                    if !value.not_found {
                        buf.extend_from_slice(&value.data);
                    }
                }
            }

            Code::Capture(n) => {
                let n = *n;

                if n < s.ncaptures.get() {
                    let cap = s.captures.borrow();

                    if n + 1 < cap.len() {
                        let (a, b) = (cap[n], cap[n + 1]);

                        if a >= 0 && b >= a {
                            let data = s.captures_data.borrow();
                            buf.extend_from_slice(&data[a as usize..b as usize]);
                        }
                    }
                }
            }

            Code::FullName(conf_prefix) => {
                let cycle = ngx_core::cycle::cycle();
                let prefix = if *conf_prefix { &cycle.conf_prefix } else { &cycle.prefix };

                if buf.first() != Some(&b'/') {
                    let mut v = prefix.clone();
                    v.extend_from_slice(&buf);
                    buf = v;
                }
            }
        }
    }

    Ok(buf)
}

/// ngx_stream_complex_value_size
pub fn complex_value_size(s: &Session, val: Option<&ComplexValue>, default_value: usize) -> usize {
    let val = match val {
        None => return default_value,
        Some(v) => v,
    };

    if val.is_constant() {
        return val.size;
    }

    let value = match complex_value(s, val) {
        Ok(v) => v,
        Err(()) => return default_value,
    };

    match ngx_core::parse::parse_size(&value) {
        Some(size) => size,
        None => {
            ngx_log_error!(NGX_LOG_ERR, s.connection.log, None, "invalid size \"{}\"", B(&value));
            default_value
        }
    }
}

/// ngx_stream_compile_complex_value
pub fn compile_complex_value(cf: &mut Conf, v: &[u8], ccv: &mut CompileComplexValue) -> Result<ComplexValue, ConfError> {
    let mut v = v.to_vec();

    let mut nv = 0;
    let mut nc = 0;

    for i in 0..v.len() {
        if v[i] == b'$' {
            if i + 1 < v.len() && (b'1'..=b'9').contains(&v[i + 1]) {
                nc += 1;
            } else {
                nv += 1;
            }
        }
    }

    if (v.is_empty() || v[0] != b'$') && (ccv.conf_prefix || ccv.root_prefix) {
        v = cf.full_name(&v, ccv.conf_prefix);

        ccv.conf_prefix = false;
        ccv.root_prefix = false;
    }

    let mut cv = ComplexValue { value: v.clone(), flushes: None, codes: None, size: 0 };

    if nv == 0 && nc == 0 {
        return Ok(cv);
    }

    let mut sc = ScriptCompile { source: v, flushes: Some(Vec::new()), codes: Vec::new(), variables: 0, ncaptures: 0, size: 0, zero: ccv.zero, conf_prefix: ccv.conf_prefix, root_prefix: ccv.root_prefix };

    script_compile(cf, &mut sc)?;

    if let Some(f) = sc.flushes.take() {
        if !f.is_empty() {
            cv.flushes = Some(f);
        }
    }

    cv.codes = Some(sc.codes);

    Ok(cv)
}

/// ngx_stream_script_compile_t
pub struct ScriptCompile {
    pub source: Vec<u8>,
    pub flushes: Option<Vec<usize>>,
    pub codes: Vec<Code>,
    pub variables: usize,
    pub ncaptures: usize,
    pub size: usize,
    pub zero: bool,
    pub conf_prefix: bool,
    pub root_prefix: bool,
}

/// ngx_stream_set_complex_value_slot
pub fn set_complex_value_slot(cf: &mut Conf, slot: &mut Option<ComplexValue>) -> ConfResult {
    if slot.is_some() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args[1].clone();

    let mut ccv = CompileComplexValue::default();

    *slot = Some(compile_complex_value(cf, &value, &mut ccv)?);

    Ok(())
}

/// ngx_stream_set_complex_value_zero_slot
pub fn set_complex_value_zero_slot(cf: &mut Conf, slot: &mut Val<Option<ComplexValue>>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args[1].clone();

    let mut ccv = CompileComplexValue { zero: true, ..Default::default() };

    *slot = Val::set(Some(compile_complex_value(cf, &value, &mut ccv)?));

    Ok(())
}

/// ngx_stream_set_complex_value_size_slot
pub fn set_complex_value_size_slot(cf: &mut Conf, slot: &mut Option<ComplexValue>) -> ConfResult {
    set_complex_value_slot(cf, slot)?;

    let cv = slot.as_mut().unwrap();

    if !cv.is_constant() {
        return Ok(());
    }

    match ngx_core::parse::parse_size(&cv.value) {
        Some(size) => cv.size = size,
        None => return Err(msg("invalid value")),
    }

    Ok(())
}

/// ngx_stream_script_variables_count
pub fn script_variables_count(value: &[u8]) -> usize {
    value.iter().filter(|&&c| c == b'$').count()
}

/// ngx_stream_script_compile
pub fn script_compile(cf: &mut Conf, sc: &mut ScriptCompile) -> ConfResult {
    let src = sc.source.clone();

    sc.variables = 0;

    let invalid_variable = |cf: &Conf| cf.emerg(format_args!("invalid variable name"));

    let mut i = 0;

    while i < src.len() {
        if src[i] == b'$' {
            i += 1;

            if i == src.len() {
                return Err(invalid_variable(cf));
            }

            if (b'1'..=b'9').contains(&src[i]) {
                let n = (src[i] - b'0') as usize;

                add_capture_code(sc, n);

                i += 1;

                continue;
            }

            let mut bracket = false;

            if src[i] == b'{' {
                bracket = true;

                i += 1;

                if i == src.len() {
                    return Err(invalid_variable(cf));
                }
            }

            let start = i;
            let mut len = 0;

            while i < src.len() {
                let ch = src[i];

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
                return Err(cf.emerg(format_args!("the closing bracket in \"{}\" variable is missing", B(&src[start..start + len]))));
            }

            if len == 0 {
                return Err(invalid_variable(cf));
            }

            sc.variables += 1;

            add_var_code(cf, sc, &src[start..start + len])?;

            continue;
        }

        let start = i;

        while i < src.len() {
            if src[i] == b'$' {
                break;
            }

            i += 1;
        }

        sc.size += i - start;

        add_copy_code(sc, &src[start..i], i == src.len());
    }

    script_done(sc);

    Ok(())
}

/// ngx_stream_script_done
fn script_done(sc: &mut ScriptCompile) {
    if sc.zero {
        add_copy_code(sc, b"\0", false);
    }

    if sc.conf_prefix || sc.root_prefix {
        sc.codes.push(Code::FullName(sc.conf_prefix));
    }
}

/// ngx_stream_script_add_copy_code
fn add_copy_code(sc: &mut ScriptCompile, value: &[u8], last: bool) {
    let zero = sc.zero && last;

    let mut data = value.to_vec();

    if zero {
        data.push(b'\0');
        sc.zero = false;
    }

    sc.codes.push(Code::Copy(data));
}

/// ngx_stream_script_add_var_code
fn add_var_code(cf: &mut Conf, sc: &mut ScriptCompile, name: &[u8]) -> ConfResult {
    let index = get_variable_index(cf, name)?;

    if let Some(f) = sc.flushes.as_mut() {
        f.push(index);
    }

    sc.codes.push(Code::Var(index));

    Ok(())
}

/// ngx_stream_script_add_capture_code
fn add_capture_code(sc: &mut ScriptCompile, n: usize) {
    sc.codes.push(Code::Capture(2 * n));

    if sc.ncaptures < n {
        sc.ncaptures = n;
    }
}

/// ngx_stream_script_run: the value of a compiled script
pub fn script_run(s: &Session, codes: &[Code]) -> Option<Vec<u8>> {
    let nvars = s.cmcf().borrow().variables.len();

    {
        let mut vars = s.variables.borrow_mut();
        if vars.len() < nvars {
            vars.resize(nvars, VariableValue::default());
        }

        for v in vars.iter_mut() {
            if v.no_cacheable {
                v.valid = false;
                v.not_found = false;
            }
        }
    }

    run_codes(s, codes).ok()
}

/// ngx_stream_script_flush_no_cacheable_variables
pub fn flush_no_cacheable_variables(s: &Session, indices: Option<&[usize]>) {
    if let Some(indices) = indices {
        let mut vars = s.variables.borrow_mut();

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

#[allow(dead_code)]
fn _unused() -> i64 {
    NGX_OK
}
