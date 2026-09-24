//! ngx_http_rewrite_module — port of ngx_http_rewrite_module.c and ngx_http_script.c
//!
//! Implements: rewrite, return, break, if, set directives.
//! Uses a bytecode approach with ScriptOp enum and a runtime executor.

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
use ngx_core::string::{atoi, B};

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_rewrite_module");

/// Bytecode operations for rewrite/set execution.
#[derive(Clone)]
pub enum ScriptOp {
    /// Copy literal bytes.
    Copy(Vec<u8>),
    /// Append a variable's value.
    Var(usize),
    /// Append a capture group (index * 2).
    Capture(usize),
    /// Rewrite: matches regex, applies replacement_code on match.
    Rewrite {
        re: Rc<Regex>,
        replacement_code: Vec<ScriptOp>,
        flags: RewriteFlags,
    },
    /// Set: sets variable to the result of evaluating value_code.
    Set {
        var_index: usize,
        value_code: Vec<ScriptOp>,
    },
    /// Break: stop rewrite processing.
    Break,
    /// Return: stop with status (and optional text).
    Return {
        status: i64,
        text: Option<ComplexValue>,
    },
    /// If: condition-based block execution.
    If {
        cond: Condition,
        block_codes: Vec<ScriptOp>,
    },
}

/// Condition for if() directive.
#[derive(Clone)]
pub enum Condition {
    /// Variable truthiness: $var
    Var(usize),
    /// Equality: $var = value
    Eq(usize, Vec<u8>),
    /// Inequality: $var != value
    Neq(usize, Vec<u8>),
    /// Regex match (case-sensitive): $var ~ regex
    Match(usize, Rc<Regex>),
    /// Regex match (case-insensitive): $var ~* regex
    MatchCI(usize, Rc<Regex>),
    /// Regex non-match (case-sensitive): $var !~ regex
    NotMatch(usize, Rc<Regex>),
    /// Regex non-match (case-insensitive): $var !~* regex
    NotMatchCI(usize, Rc<Regex>),
    /// File exists: -e path
    FileExists(Vec<u8>),
    /// Not file exists: !-e path
    NotFileExists(Vec<u8>),
    /// Is regular file: -f path
    IsFile(Vec<u8>),
    /// Is not regular file: !-f path
    NotIsFile(Vec<u8>),
    /// Is directory: -d path
    IsDir(Vec<u8>),
    /// Is not directory: !-d path
    NotIsDir(Vec<u8>),
    /// Is executable: -x path
    IsExec(Vec<u8>),
    /// Is not executable: !-x path
    NotIsExec(Vec<u8>),
}

/// Rewrite flags.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RewriteFlags {
    Default,  // restart from location rewrite phase
    Last,     // same as default (internal redirect)
    Break,    // break to next phase
    Redirect, // 302 if no scheme in replacement
    Permanent, // 301 if no scheme in replacement
}

pub struct RewriteConf {
    pub codes: Vec<ScriptOp>,
    pub stack_size: Val<i64>,
    pub log: Val<bool>,
    pub uninitialized_variable_warn: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(RewriteConf {
        codes: Vec::new(),
        stack_size: Val::unset(),
        log: Val::unset(),
        uninitialized_variable_warn: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<RewriteConf>(prev).borrow();
    let mut c = conf_cell::<RewriteConf>(conf).borrow_mut();
    c.stack_size.merge(&p.stack_size, 10);
    c.log.merge(&p.log, false);
    c.uninitialized_variable_warn.merge(&p.uninitialized_variable_warn, true);
    Ok(())
}

/// Parse a rewrite directive: rewrite regex replacement [flag]
fn rewrite_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() < 3 {
        return Err(cf.emerg(format_args!("invalid number of arguments")));
    }

    let regex_pattern = &args[1];
    let replacement = &args[2];
    let flag = if args.len() > 3 { Some(&args[3]) } else { None };

    // Compile regex (PCRE2)
    let regex = match Regex::compile(regex_pattern, 0) {
        Ok(r) => r,
        Err(e) => return Err(cf.emerg(format_args!("invalid regex \"{}\": {}", B(regex_pattern), e))),
    };

    // Parse replacement into bytecode
    let replacement_code = compile_replacement_code(cf, replacement)?;

    // Parse flags
    let flags = parse_rewrite_flags(flag);

    cell.borrow_mut().codes.push(ScriptOp::Rewrite {
        re: regex,
        replacement_code,
        flags,
    });

    Ok(())
}

/// Parse rewrite flags: last, break, redirect, permanent.
fn parse_rewrite_flags(flag: Option<&Vec<u8>>) -> RewriteFlags {
    match flag {
        None => RewriteFlags::Default,
        Some(f) => match f.as_slice() {
            b"last" => RewriteFlags::Last,
            b"break" => RewriteFlags::Break,
            b"redirect" => RewriteFlags::Redirect,
            b"permanent" => RewriteFlags::Permanent,
            _ => RewriteFlags::Default,
        },
    }
}

/// Compile replacement string into ScriptOp bytecode (variables and captures).
fn compile_replacement_code(cf: &mut Conf, replacement: &[u8]) -> Result<Vec<ScriptOp>, ConfError> {
    let mut code = Vec::new();
    let mut lit = Vec::new();
    let mut i = 0;

    while i < replacement.len() {
        if replacement[i] == b'$' && i + 1 < replacement.len() {
            if !lit.is_empty() {
                code.push(ScriptOp::Copy(std::mem::take(&mut lit)));
            }

            if replacement[i + 1].is_ascii_digit() {
                // Capture group: $1, $2, etc.
                let n = (replacement[i + 1] - b'0') as usize;
                code.push(ScriptOp::Capture(n * 2));
                i += 2;
            } else if replacement[i + 1] == b'{' {
                // Braced variable or capture: ${var} or ${1}
                if let Some(end) = memchr::memchr(b'}', &replacement[i + 2..]) {
                    let end = i + 2 + end;
                    let name = &replacement[i + 2..end];
                    if name.iter().all(|&c| c.is_ascii_digit()) {
                        // Capture: ${1}
                        if let Ok(n) = std::str::from_utf8(name).unwrap_or("").parse::<usize>() {
                            code.push(ScriptOp::Capture(n * 2));
                        }
                    } else {
                        // Variable: ${var}
                        let var_idx = get_variable_index(cf, name)?;
                        code.push(ScriptOp::Var(var_idx));
                    }
                    i = end + 1;
                } else {
                    lit.push(b'$');
                    i += 1;
                }
            } else if replacement[i + 1].is_ascii_alphabetic() || replacement[i + 1] == b'_' {
                // Variable name: $var
                let mut end = i + 1;
                while end < replacement.len() && (replacement[end].is_ascii_alphanumeric() || replacement[end] == b'_') {
                    end += 1;
                }
                let name = &replacement[i + 1..end];
                let var_idx = get_variable_index(cf, name)?;
                code.push(ScriptOp::Var(var_idx));
                i = end;
            } else {
                lit.push(b'$');
                i += 1;
            }
        } else {
            lit.push(replacement[i]);
            i += 1;
        }
    }

    if !lit.is_empty() {
        code.push(ScriptOp::Copy(lit));
    }

    Ok(code)
}

/// Parse and compile a condition for if() directive.
fn compile_condition(cf: &mut Conf, cond_str: &[u8]) -> Result<Condition, ConfError> {
    let s = cond_str.trim_ascii();

    // Try to parse special file test operators: -f, -d, -e, -x (and negations)
    if s.starts_with(b"!-f ") {
        return Ok(Condition::NotIsFile(s[4..].to_vec()));
    }
    if s.starts_with(b"-f ") {
        return Ok(Condition::IsFile(s[3..].to_vec()));
    }
    if s.starts_with(b"!-d ") {
        return Ok(Condition::NotIsDir(s[4..].to_vec()));
    }
    if s.starts_with(b"-d ") {
        return Ok(Condition::IsDir(s[3..].to_vec()));
    }
    if s.starts_with(b"!-e ") {
        return Ok(Condition::NotFileExists(s[4..].to_vec()));
    }
    if s.starts_with(b"-e ") {
        return Ok(Condition::FileExists(s[3..].to_vec()));
    }
    if s.starts_with(b"!-x ") {
        return Ok(Condition::NotIsExec(s[4..].to_vec()));
    }
    if s.starts_with(b"-x ") {
        return Ok(Condition::IsExec(s[3..].to_vec()));
    }

    // Parse variable comparisons: $var op value
    // Look for $var as first token
    if !s.starts_with(b"$") {
        return Err(cf.emerg(format_args!("invalid condition")));
    }

    let mut i = 1;
    while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'_') {
        i += 1;
    }

    let var_name = &s[1..i];
    let var_idx = get_variable_index(cf, var_name)?;
    let rest = s[i..].trim_ascii();

    if rest.is_empty() {
        // Just $var (truthiness test)
        return Ok(Condition::Var(var_idx));
    }

    // Try to parse operator and operand
    if rest.starts_with(b"=") && !rest.starts_with(b"==") {
        let operand = rest[1..].trim_ascii();
        return Ok(Condition::Eq(var_idx, operand.to_vec()));
    }
    if rest.starts_with(b"!=") {
        let operand = rest[2..].trim_ascii();
        return Ok(Condition::Neq(var_idx, operand.to_vec()));
    }
    if rest.starts_with(b"~*") {
        let operand = rest[2..].trim_ascii();
        let regex = match Regex::compile(operand, 0) {
            Ok(r) => r,
            Err(e) => return Err(cf.emerg(format_args!("invalid regex in condition: {}", e))),
        };
        return Ok(Condition::MatchCI(var_idx, regex));
    }
    if rest.starts_with(b"~") {
        let operand = rest[1..].trim_ascii();
        let regex = match Regex::compile(operand, 0) {
            Ok(r) => r,
            Err(e) => return Err(cf.emerg(format_args!("invalid regex in condition: {}", e))),
        };
        return Ok(Condition::Match(var_idx, regex));
    }
    if rest.starts_with(b"!~*") {
        let operand = rest[3..].trim_ascii();
        let regex = match Regex::compile(operand, 0) {
            Ok(r) => r,
            Err(e) => return Err(cf.emerg(format_args!("invalid regex in condition: {}", e))),
        };
        return Ok(Condition::NotMatchCI(var_idx, regex));
    }
    if rest.starts_with(b"!~") {
        let operand = rest[2..].trim_ascii();
        let regex = match Regex::compile(operand, 0) {
            Ok(r) => r,
            Err(e) => return Err(cf.emerg(format_args!("invalid regex in condition: {}", e))),
        };
        return Ok(Condition::NotMatch(var_idx, regex));
    }

    Err(cf.emerg(format_args!("invalid condition")))
}

/// Parse if block: if (condition) { ... }
/// The condition is in cf.args[1].
fn if_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let parent_cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let cond_bytes = cf.args[1].clone();
    let cond = compile_condition(cf, &cond_bytes)?;

    // Remember the current number of codes in the parent
    let code_count_before = parent_cell.borrow().codes.len();

    // Parse the block; directives inside will be added directly to the parent's codes
    // because handler_conf is the same parent conf, and cmd_type is just for matching.
    let saved_ct = cf.cmd_type;
    cf.cmd_type = if saved_ct == NGX_HTTP_SRV_CONF {
        NGX_HTTP_SIF_CONF
    } else {
        NGX_HTTP_LIF_CONF
    };

    let rv = cf.parse_block();

    cf.cmd_type = saved_ct;

    if rv.is_ok() {
        // Extract codes added during the if block
        let mut parent_codes = parent_cell.borrow_mut();
        let block_codes = parent_codes.drain(code_count_before..).collect();

        // Add the If opcode containing the condition and block codes
        parent_codes.push(ScriptOp::If {
            cond,
            block_codes,
        });
    }

    rv
}

/// Parse set directive: set $var value
fn set_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() != 3 {
        return Err(cf.emerg(format_args!("invalid number of arguments")));
    }

    let var_name = &args[1];
    if !var_name.starts_with(b"$") {
        return Err(cf.emerg(format_args!("invalid variable name")));
    }

    let var_idx = get_variable_index(cf, &var_name[1..])?;
    let value = &args[2];

    // Compile value as bytecode
    let value_code = compile_replacement_code(cf, value)?;

    cell.borrow_mut().codes.push(ScriptOp::Set { var_index: var_idx, value_code });

    Ok(())
}

/// Parse break directive.
fn break_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    cell.borrow_mut().codes.push(ScriptOp::Break);
    Ok(())
}

/// Parse return directive: return code [text]
fn return_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    let v = &args[1];
    let status: i64;
    let mut text: Option<Vec<u8>> = None;

    match atoi(v) {
        Some(s) => {
            status = s;
            if status > 999 {
                return Err(cf.emerg(format_args!("invalid return code \"{}\"", B(v))));
            }
            if args.len() == 3 {
                text = Some(args[2].clone());
            }
        }
        None => {
            if args.len() == 3 {
                return Err(cf.emerg(format_args!("invalid return code \"{}\"", B(v))));
            }
            status = NGX_HTTP_MOVED_TEMPORARILY;
            text = Some(v.clone());
        }
    }

    let cv = match text {
        Some(t) => Some(compile_complex_value(cf, &t, 0)?),
        None => None,
    };

    cell.borrow_mut().codes.push(ScriptOp::Return { status, text: cv });

    Ok(())
}

pub fn rewrite_module() -> ModuleDef {
    const F: u32 =
        NGX_HTTP_SRV_CONF | NGX_HTTP_SIF_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("rewrite", F | NGX_CONF_TAKE23, ConfLevel::Loc, rewrite_directive),
        ngx_core::cmd_fn!("return", F | NGX_CONF_TAKE12, ConfLevel::Loc, return_directive),
        ngx_core::cmd_fn!("break", F | NGX_CONF_NOARGS, ConfLevel::Loc, break_directive),
        ngx_core::cmd_fn!(
            "if",
            NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_BLOCK | NGX_CONF_1MORE,
            ConfLevel::Loc,
            if_block
        ),
        ngx_core::cmd_fn!("set", F | NGX_CONF_TAKE2, ConfLevel::Loc, set_directive),
        ngx_core::cmd!(
            "rewrite_log",
            NGX_HTTP_MAIN_CONF | F | NGX_CONF_FLAG,
            ConfLevel::Loc,
            RewriteConf,
            log,
            set_flag
        ),
        ngx_core::cmd!(
            "uninitialized_variable_warn",
            NGX_HTTP_MAIN_CONF | F | NGX_CONF_FLAG,
            ConfLevel::Loc,
            RewriteConf,
            uninitialized_variable_warn,
            set_flag
        ),
    ];
    http_module_def("ngx_http_rewrite_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_SERVER_REWRITE_PHASE,
        Rc::new(|r| Box::pin(rewrite_handler(r))),
    );
    add_phase_handler(
        cf,
        NGX_HTTP_REWRITE_PHASE,
        Rc::new(|r| Box::pin(rewrite_handler(r))),
    );
    Ok(())
}

/// Execute rewrite rules from a location's config.
async fn rewrite_handler(r: R) -> i64 {
    let conf = r.loc_conf::<RewriteConf>(ctx_index());
    let codes = conf.borrow().codes.clone();

    let (status, uri_changed) = execute_codes(&r, &codes).await;

    if uri_changed && status == NGX_DECLINED {
        // Restart from location rewrite phase via setting phase index
        let cmcf = r.cmcf();
        let idx = cmcf.borrow().phase_engine.location_rewrite_index;
        r.phase_handler.set(idx);
    }

    status
}

/// Execute codes async, returning (status, uri_changed).
async fn execute_codes(r: &R, codes: &[ScriptOp]) -> (i64, bool) {
    let mut uri_changed = false;
    let mut should_break = false;

    for code in codes.iter() {
        match code {
            ScriptOp::Rewrite {
                re,
                replacement_code,
                flags,
            } => {
                let uri = r.uri.borrow();
                if let Some(caps) = re.exec(uri.as_slice()) {
                    // Match! Store captures and apply replacement.
                    let cap_vec: Vec<i32> = caps.iter().flat_map(|(a, b)| vec![*a, *b]).collect();
                    r.ncaptures.set(caps.len());
                    *r.captures.borrow_mut() = cap_vec;
                    *r.captures_data.borrow_mut() = uri.clone();

                    // Execute replacement bytecode to get new URI
                    let new_uri = execute_replacement_code(&r, replacement_code);

                    // Check if replacement starts with scheme for redirect
                    let is_redirect =
                        new_uri.starts_with(b"http://") || new_uri.starts_with(b"https://");

                    if is_redirect || matches!(flags, RewriteFlags::Redirect | RewriteFlags::Permanent) {
                        // Prepare Location header and status
                        let status = if *flags == RewriteFlags::Permanent {
                            NGX_HTTP_MOVED_PERMANENTLY
                        } else if *flags == RewriteFlags::Redirect || is_redirect {
                            NGX_HTTP_MOVED_TEMPORARILY
                        } else {
                            NGX_HTTP_OK
                        };

                        let cv = ComplexValue::constant(&new_uri);
                        let rc = send_response(&r, status, None, &cv).await;
                        return if rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE {
                            (NGX_DONE, uri_changed)
                        } else {
                            (rc, uri_changed)
                        };
                    } else if *flags == RewriteFlags::Break {
                        should_break = true;
                        set_uri_and_args(&r, &new_uri);
                        uri_changed = true;
                        break;
                    } else {
                        // Default or Last: set URI and mark as changed for restart
                        set_uri_and_args(&r, &new_uri);
                        uri_changed = true;
                    }
                }
            }

            ScriptOp::Set {
                var_index,
                value_code,
            } => {
                let val = execute_replacement_code(&r, value_code);
                set_indexed_variable(&r, *var_index, val);
            }

            ScriptOp::Break => {
                should_break = true;
                break;
            }

            ScriptOp::Return { status, text } => {
                let status = *status;
                if status == NGX_HTTP_MOVED_PERMANENTLY
                    || status == NGX_HTTP_MOVED_TEMPORARILY
                    || status == NGX_HTTP_SEE_OTHER
                    || status == NGX_HTTP_TEMPORARY_REDIRECT
                    || status == NGX_HTTP_PERMANENT_REDIRECT
                    || text.is_some()
                {
                    let cv = text
                        .clone()
                        .unwrap_or_else(|| ComplexValue::constant(b""));
                    let ct: Option<&[u8]> = if text.is_some() && status < 300 {
                        Some(b"text/plain")
                    } else {
                        None
                    };
                    let rc = send_response(&r, status, ct, &cv).await;
                    return if rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE {
                        (NGX_DONE, uri_changed)
                    } else {
                        (rc, uri_changed)
                    };
                }
                return (status, uri_changed);
            }

            ScriptOp::If { cond, block_codes } => {
                if test_condition(&r, cond) {
                    // Execute block codes recursively
                    let (status, inner_changed) = execute_codes(&r, block_codes).await;
                    uri_changed = uri_changed || inner_changed;
                    if status != NGX_DECLINED {
                        return (status, uri_changed);
                    }
                }
            }
        }
    }

    (if should_break { NGX_DECLINED } else { NGX_DECLINED }, uri_changed)
}

/// Execute bytecode and return the result as a string.
fn execute_replacement_code(r: &R, code: &[ScriptOp]) -> Vec<u8> {
    let mut result = Vec::new();

    for op in code {
        match op {
            ScriptOp::Copy(bytes) => {
                result.extend_from_slice(bytes);
            }
            ScriptOp::Var(idx) => {
                if let Some(vv) = get_indexed_variable(r, *idx) {
                    if !vv.not_found {
                        result.extend_from_slice(&vv.data);
                    }
                }
            }
            ScriptOp::Capture(n) => {
                let caps = r.captures.borrow();
                let data = r.captures_data.borrow();
                if *n + 1 < caps.len() {
                    let s = caps[*n];
                    let e = caps[*n + 1];
                    if s >= 0 && e >= s {
                        result.extend_from_slice(&data[s as usize..e as usize]);
                    }
                }
            }
            _ => {}
        }
    }

    result
}

/// Set URI and args from a new URI string (handles '?' boundary).
fn set_uri_and_args(r: &R, new_uri: &[u8]) {
    if let Some(q_pos) = memchr::memchr(b'?', new_uri) {
        *r.uri.borrow_mut() = new_uri[..q_pos].to_vec();
        let new_args = &new_uri[q_pos + 1..];
        if !new_args.is_empty() {
            // Merge with existing args if present
            let mut args = r.args.borrow_mut();
            if !args.is_empty() {
                args.push(b'&');
                args.extend_from_slice(new_args);
            } else {
                *args = new_args.to_vec();
            }
        }
    } else {
        *r.uri.borrow_mut() = new_uri.to_vec();
    }
    r.uri_changed.set(true);
}

/// Test a condition in the context of a request.
fn test_condition(r: &R, cond: &Condition) -> bool {
    match cond {
        Condition::Var(idx) => {
            if let Some(vv) = get_indexed_variable(r, *idx) {
                if vv.not_found {
                    return false;
                }
                return !vv.data.is_empty() && vv.data != b"0";
            }
            false
        }

        Condition::Eq(idx, operand) => {
            if let Some(vv) = get_indexed_variable(r, *idx) {
                if !vv.not_found {
                    return vv.data == operand.as_slice();
                }
            }
            false
        }

        Condition::Neq(idx, operand) => {
            if let Some(vv) = get_indexed_variable(r, *idx) {
                if !vv.not_found {
                    return vv.data != operand.as_slice();
                }
            }
            true
        }

        Condition::Match(idx, regex) => {
            if let Some(vv) = get_indexed_variable(r, *idx) {
                if !vv.not_found {
                    return regex.is_match(vv.data.as_slice());
                }
            }
            false
        }

        Condition::MatchCI(idx, regex) => {
            if let Some(vv) = get_indexed_variable(r, *idx) {
                if !vv.not_found {
                    let lower = vv.data.to_ascii_lowercase();
                    return regex.is_match(lower.as_slice());
                }
            }
            false
        }

        Condition::NotMatch(idx, regex) => {
            if let Some(vv) = get_indexed_variable(r, *idx) {
                if !vv.not_found {
                    return !regex.is_match(vv.data.as_slice());
                }
            }
            true
        }

        Condition::NotMatchCI(idx, regex) => {
            if let Some(vv) = get_indexed_variable(r, *idx) {
                if !vv.not_found {
                    let lower = vv.data.to_ascii_lowercase();
                    return !regex.is_match(lower.as_slice());
                }
            }
            true
        }

        Condition::FileExists(path) => {
            let path_str = expand_path(r, path);
            std::path::Path::new(&path_str).exists()
        }

        Condition::NotFileExists(path) => {
            let path_str = expand_path(r, path);
            !std::path::Path::new(&path_str).exists()
        }

        Condition::IsFile(path) => {
            let path_str = expand_path(r, path);
            std::path::Path::new(&path_str).is_file()
        }

        Condition::NotIsFile(path) => {
            let path_str = expand_path(r, path);
            !std::path::Path::new(&path_str).is_file()
        }

        Condition::IsDir(path) => {
            let path_str = expand_path(r, path);
            std::path::Path::new(&path_str).is_dir()
        }

        Condition::NotIsDir(path) => {
            let path_str = expand_path(r, path);
            !std::path::Path::new(&path_str).is_dir()
        }

        Condition::IsExec(path) => {
            let path_str = expand_path(r, path);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&path_str) {
                    let mode = metadata.permissions().mode();
                    return (mode & 0o111) != 0;
                }
                false
            }
            #[cfg(not(unix))]
            {
                false
            }
        }

        Condition::NotIsExec(path) => {
            let path_str = expand_path(r, path);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(&path_str) {
                    let mode = metadata.permissions().mode();
                    return (mode & 0o111) == 0;
                }
                true
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
    }
}

/// Expand variables in path (replace $var with actual values).
fn expand_path(_r: &R, path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rewrite_flags() {
        assert_eq!(parse_rewrite_flags(None), RewriteFlags::Default);
        assert_eq!(parse_rewrite_flags(Some(&b"last".to_vec())), RewriteFlags::Last);
        assert_eq!(parse_rewrite_flags(Some(&b"break".to_vec())), RewriteFlags::Break);
        assert_eq!(parse_rewrite_flags(Some(&b"redirect".to_vec())), RewriteFlags::Redirect);
        assert_eq!(
            parse_rewrite_flags(Some(&b"permanent".to_vec())),
            RewriteFlags::Permanent
        );
    }
}
