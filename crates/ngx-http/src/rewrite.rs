//! ngx_http_rewrite_module - URL rewriting and conditional request handling

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::{atoi, B};

use ngx_core::open_file_cache::*;

use crate::core::*;
use crate::core_rt::*;
use crate::request::*;
use crate::script::ComplexValue;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_rewrite_module");

/// Compiled rewrite rule (regex rewrite directive)
#[derive(Clone)]
pub struct RewriteRule {
    pub regex: Rc<HttpRegex>,
    pub replacement: Vec<u8>,
    pub flags: RewriteFlags,
    pub log: bool,
    /// regex->add_args: the replacement does not end with "?", the
    /// original arguments are appended
    pub add_args: bool,
    /// the values codes of the replacement (ngx_http_script_compile)
    pub values: Vec<ReplacementCode>,
    /// regex->args: the replacement has a "?"
    pub args: bool,
}

/// The codes ngx_http_script_compile() makes of a rewrite replacement.
#[derive(Clone)]
pub enum ReplacementCode {
    /// ngx_http_script_copy_code
    Copy(Vec<u8>),
    /// ngx_http_script_copy_var_code
    Var(usize),
    /// ngx_http_script_copy_capture_code, n = 2 * $n
    Capture(usize),
    /// ngx_http_script_start_args_code: the first "?" of a replacement
    /// that is not a redirect
    StartArgs,
}

#[derive(Clone, Copy, Debug)]
pub struct RewriteFlags {
    pub last: bool,
    pub break_cycle: bool,
    pub redirect: bool,
    pub redirect_status: i64,
}

/// Compiled code instruction for rewrite handler execution
#[derive(Clone)]
pub enum Code {
    Rewrite(RewriteRule),
    Set { var_idx: usize, value: ComplexValue },
    /// Evaluate `value`, then feed the result into the variable's set_handler.
    /// Matches C's ngx_http_script_var_set_handler_code emitted by rewrite_set
    /// when v->set_handler is non-NULL (e.g. $args, $limit_rate); the handler
    /// updates the underlying request field (r.args, r.limit_rate) and the
    /// value is NOT cached in r.variables[index].
    SetHandler { var_idx: usize, value: ComplexValue, handler: crate::variables::SetHandler },
    Return { status: i64, text: Option<ComplexValue> },
    Break { is_break_cycle: bool }, // true = break, false = last
    /// ngx_http_script_if_code_t: `loc_conf` is the configuration of the
    /// if block inside a location (NULL for an if at the server level).
    If { condition: IfCondition, codes: Vec<Code>, loc_conf: Option<Rc<ConfSlots>> },
}

/// Condition types for if blocks
#[derive(Clone)]
pub enum IfCondition {
    /// Variable is non-empty and not "0"
    Variable(usize),
    /// String equality: $var = "value" (the value may have variables,
    /// ngx_http_rewrite_value)
    Equal(usize, ComplexValue),
    /// String inequality: $var != "value"
    NotEqual(usize, ComplexValue),
    /// Regex match: $var ~ pattern
    RegexMatch(usize, Rc<HttpRegex>),
    /// Case-insensitive regex: $var ~* pattern
    RegexMatchCaseInsensitive(usize, Rc<HttpRegex>),
    /// Negated regex: $var !~ pattern
    RegexNotMatch(usize, Rc<HttpRegex>),
    /// Negated case-insensitive: $var !~* pattern
    RegexNotMatchCaseInsensitive(usize, Rc<HttpRegex>),
    /// File exists: -f "path"
    FileExists(crate::script::ComplexValue),
    /// File does not exist: !-f "path"
    FileNotExists(crate::script::ComplexValue),
    /// Directory exists: -d "path"
    DirectoryExists(crate::script::ComplexValue),
    /// Directory does not exist: !-d "path"
    DirectoryNotExists(crate::script::ComplexValue),
    /// Entity exists: -e "path"
    EntityExists(crate::script::ComplexValue),
    /// Entity does not exist: !-e "path"
    EntityNotExists(crate::script::ComplexValue),
    /// Executable: -x "path"
    Executable(crate::script::ComplexValue),
    /// Not executable: !-x "path"
    NotExecutable(crate::script::ComplexValue),
}

pub struct RewriteConf {
    pub codes: Vec<Code>,
    pub stack_size: Val<i64>,
    pub log: Val<bool>,
    pub uninitialized_variable_warn: Val<bool>,
}

/// ngx_http_rewrite_if_condition: `value` are the arguments of the "if"
/// directive (value[0] is "if"), the first one starting with "(" and the
/// last one ending with ")".
fn parse_if_condition(cf: &mut Conf, args: &[Vec<u8>]) -> Result<IfCondition, ConfError> {
    let mut value = args.to_vec();
    let mut last = value.len() - 1;

    if value[1].is_empty() || value[1][0] != b'(' {
        return Err(cf.emerg(format_args!("invalid condition \"{}\"", B(&value[1]))));
    }

    let mut cur;

    if value[1].len() == 1 {
        cur = 2;

    } else {
        cur = 1;
        value[1].remove(0);
    }

    if value[last].last() != Some(&b')') {
        return Err(cf.emerg(format_args!("invalid condition \"{}\"", B(&value[last]))));
    }

    if value[last].len() == 1 {
        last -= 1;

    } else {
        value[last].pop();
    }

    let p = value.get(cur).cloned().unwrap_or_default();
    let len = p.len();

    if len > 1 && p[0] == b'$' {

        if cur != last && cur + 2 != last {
            return Err(cf.emerg(format_args!("invalid condition \"{}\"", B(&p))));
        }

        // ngx_http_rewrite_variable
        let index = get_variable_index(cf, &p[1..])?;

        if cur == last {
            return Ok(IfCondition::Variable(index));
        }

        cur += 1;

        let p = value[cur].clone();

        if p == b"=" {
            // ngx_http_rewrite_value
            let value = crate::script::compile_complex_value(cf, &value[last], 0)?;
            return Ok(IfCondition::Equal(index, value));
        }

        if p == b"!=" {
            let value = crate::script::compile_complex_value(cf, &value[last], 0)?;
            return Ok(IfCondition::NotEqual(index, value));
        }

        if p == b"~" || p == b"~*" || p == b"!~" || p == b"!~*" {
            let caseless = p.last() == Some(&b'*');
            let options = if caseless { ngx_core::regex::NGX_REGEX_CASELESS } else { 0 };

            let regex = crate::variables::regex_compile(cf, &value[last], options)?;

            return Ok(match (p[0] == b'!', caseless) {
                (false, false) => IfCondition::RegexMatch(index, regex),
                (false, true) => IfCondition::RegexMatchCaseInsensitive(index, regex),
                (true, false) => IfCondition::RegexNotMatch(index, regex),
                (true, true) => IfCondition::RegexNotMatchCaseInsensitive(index, regex),
            });
        }

        return Err(cf.emerg(format_args!("unexpected \"{}\" in condition", B(&p))));

    } else if (len == 2 && p[0] == b'-') || (len == 3 && p[0] == b'!' && p[1] == b'-') {

        if cur + 1 != last {
            return Err(cf.emerg(format_args!("invalid condition \"{}\"", B(&p))));
        }

        // ngx_http_rewrite_value
        let file = crate::script::compile_complex_value(cf, &value[last], 0)?;

        match p[1] {
            b'f' => return Ok(IfCondition::FileExists(file)),
            b'd' => return Ok(IfCondition::DirectoryExists(file)),
            b'e' => return Ok(IfCondition::EntityExists(file)),
            b'x' => return Ok(IfCondition::Executable(file)),
            _ => {}
        }

        if p[0] == b'!' {
            match p[2] {
                b'f' => return Ok(IfCondition::FileNotExists(file)),
                b'd' => return Ok(IfCondition::DirectoryNotExists(file)),
                b'e' => return Ok(IfCondition::EntityNotExists(file)),
                b'x' => return Ok(IfCondition::NotExecutable(file)),
                _ => {}
            }
        }

        return Err(cf.emerg(format_args!("invalid condition \"{}\"", B(&p))));
    }

    Err(cf.emerg(format_args!("invalid condition \"{}\"", B(&p))))
}

/// The operations of ngx_http_script_file_code.
#[derive(Clone, Copy, Debug)]
enum FileOp {
    Plain,
    NotPlain,
    Dir,
    NotDir,
    Exists,
    NotExists,
    Exec,
    NotExec,
}

/// ngx_http_script_file_code: the file is looked up as ngx_open_cached_file
/// with of.test_only and the symlink restrictions of the location;
/// Err(status) ends the codes.
fn file_code(r: &R, file: &ComplexValue, op: FileOp) -> Result<bool, i64> {
    let path = crate::script::complex_value(r, file).unwrap_or_default();

    http_debug!(r, "http script file op {:?} \"{}\"", op, B(&path));

    let clcf = r.clcf();

    let (mut of, cache) = {
        let c = clcf.borrow();

        let mut of = crate::static_module::open_file_info(r, &c);
        of.test_only = true;

        (of, c.open_file_cache.get().clone())
    };

    if set_disable_symlinks(r, &clcf, &path, &mut of) != NGX_OK {
        return Err(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if ngx_core::open_file_cache::open_cached_file(cache.as_ref(), &path, &mut of, &r.connection.log).is_err() {
        if of.err == 0 {
            return Err(NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        if of.err != libc::ENOENT && of.err != libc::ENOTDIR && of.err != libc::ENAMETOOLONG {
            ngx_core::ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(of.err), "{} \"{}\" failed", of.failed, B(&path));
        }

        let value = match op {
            FileOp::Plain | FileOp::Dir | FileOp::Exists | FileOp::Exec => false,
            FileOp::NotPlain | FileOp::NotDir | FileOp::NotExists | FileOp::NotExec => true,
        };

        if !value {
            http_debug!(r, "http script file op false");
        }

        return Ok(value);
    }

    let value = match op {
        FileOp::Plain => of.is_file,
        FileOp::NotPlain => !of.is_file,
        FileOp::Dir => of.is_dir,
        FileOp::NotDir => !of.is_dir,
        FileOp::Exists => of.is_file || of.is_dir || of.is_link,
        FileOp::NotExists => !(of.is_file || of.is_dir || of.is_link),
        FileOp::Exec => of.is_exec,
        FileOp::NotExec => !of.is_exec,
    };

    if !value {
        http_debug!(r, "http script file op false");
    }

    Ok(value)
}

/// ngx_http_set_disable_symlinks
fn set_disable_symlinks(r: &R, clcf: &Rc<std::cell::RefCell<CoreLocConf>>, path: &[u8], of: &mut OpenFileInfo) -> i64 {
    let from = {
        let c = clcf.borrow();

        of.disable_symlinks = *c.disable_symlinks as u8;

        c.disable_symlinks_from.as_option().cloned().flatten()
    };

    let from = match from {
        Some(cv) => cv,
        None => return NGX_OK,
    };

    let from = match crate::script::complex_value(r, &from) {
        Ok(v) => v,
        Err(_) => return NGX_ERROR,
    };

    if from.is_empty() || from.len() > path.len() || path[..from.len()] != from[..] {
        return NGX_OK;
    }

    if from.len() == path.len() {
        of.disable_symlinks = NGX_DISABLE_SYMLINKS_OFF as u8;
        return NGX_OK;
    }

    let p = from.len();

    if path[p] == b'/' {
        of.disable_symlinks_from = from.len();
        return NGX_OK;
    }

    if path[p - 1] == b'/' {
        of.disable_symlinks_from = from.len() - 1;
    }

    NGX_OK
}

/// The regex test of an if condition (ngx_http_script_regex_start_code with
/// code->test): the variable's value (empty if not found, as
/// ngx_http_script_var_code) is matched with ngx_http_regex_exec, which
/// makes the captures of a match the request's, and a mismatch resets them.
fn regex_test(r: &R, idx: usize, regex: &Rc<HttpRegex>, negative_test: bool, log: bool) -> Result<bool, i64> {
    let line = match crate::variables::get_flushed_variable(r, idx) {
        Some(vv) if !vv.not_found => vv.data,
        _ => Vec::new(),
    };

    http_debug!(r, "http script regex: \"{}\"", B(&regex.name));

    let log = log || r.connection.log.debug_enabled(NGX_LOG_DEBUG_HTTP);

    let rc = crate::variables::regex_exec(r, regex, &line);

    if rc == NGX_DECLINED {
        if log {
            ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "\"{}\" does not match \"{}\"", B(&regex.name), B(&line));
        }

        r.ncaptures.set(0);

        return Ok(negative_test);
    }

    if rc == NGX_ERROR {
        return Err(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if log {
        ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "\"{}\" matches \"{}\"", B(&regex.name), B(&line));
    }

    Ok(!negative_test)
}

/// The value of the variable of a condition, empty when not found
/// (ngx_http_script_var_code).
fn condition_variable(r: &R, idx: usize) -> Vec<u8> {
    match crate::variables::get_flushed_variable(r, idx) {
        Some(vv) if !vv.not_found => vv.data,
        _ => Vec::new(),
    }
}

/// The value of the condition of an if code; Err(status) ends the codes.
fn eval_if_condition(r: &R, condition: &IfCondition, log: bool) -> Result<bool, i64> {
    match condition {
        IfCondition::Variable(idx) => {
            let v = condition_variable(r, *idx);
            Ok(!v.is_empty() && !(v.len() == 1 && v[0] == b'0'))
        }
        IfCondition::Equal(idx, value) => {
            // ngx_http_script_equal_code
            let v = condition_variable(r, *idx);
            let value = crate::script::complex_value(r, value).unwrap_or_default();
            http_debug!(r, "http script equal");
            if v != value {
                http_debug!(r, "http script equal: no \"{}\"", B(&value));
            }
            Ok(v == value)
        }
        IfCondition::NotEqual(idx, value) => {
            // ngx_http_script_not_equal_code
            let v = condition_variable(r, *idx);
            let value = crate::script::complex_value(r, value).unwrap_or_default();
            http_debug!(r, "http script not equal");
            if v == value {
                http_debug!(r, "http script not equal: no");
            }
            Ok(v != value)
        }
        IfCondition::RegexMatch(idx, regex) | IfCondition::RegexMatchCaseInsensitive(idx, regex) => {
            regex_test(r, *idx, regex, false, log)
        }
        IfCondition::RegexNotMatch(idx, regex) | IfCondition::RegexNotMatchCaseInsensitive(idx, regex) => {
            regex_test(r, *idx, regex, true, log)
        }
        IfCondition::FileExists(cv) => file_code(r, cv, FileOp::Plain),
        IfCondition::FileNotExists(cv) => file_code(r, cv, FileOp::NotPlain),
        IfCondition::DirectoryExists(cv) => file_code(r, cv, FileOp::Dir),
        IfCondition::DirectoryNotExists(cv) => file_code(r, cv, FileOp::NotDir),
        IfCondition::EntityExists(cv) => file_code(r, cv, FileOp::Exists),
        IfCondition::EntityNotExists(cv) => file_code(r, cv, FileOp::NotExists),
        IfCondition::Executable(cv) => file_code(r, cv, FileOp::Exec),
        IfCondition::NotExecutable(cv) => file_code(r, cv, FileOp::NotExec),
    }
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

/// ngx_http_script_compile() of a rewrite replacement (sc->complete_lengths,
/// sc->compile_args unless the rewrite is a redirect): the values codes and
/// sc->args, whether the replacement has a "?".
fn compile_replacement(cf: &mut Conf, source: &[u8], mut compile_args: bool) -> Result<(Vec<ReplacementCode>, bool), ConfError> {
    let mut codes = Vec::new();
    let mut args = false;

    let mut i = 0;

    while i < source.len() {
        if source[i] == b'$' {
            i += 1;

            if i == source.len() {
                return Err(cf.emerg(format_args!("invalid variable name")));
            }

            if (b'1'..=b'9').contains(&source[i]) {
                codes.push(ReplacementCode::Capture(2 * (source[i] - b'0') as usize));

                i += 1;

                continue;
            }

            let mut bracket = false;

            if source[i] == b'{' {
                bracket = true;

                i += 1;

                if i == source.len() {
                    return Err(cf.emerg(format_args!("invalid variable name")));
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
                return Err(cf.emerg(format_args!("invalid variable name")));
            }

            let index = get_variable_index(cf, &source[start..start + len])?;

            codes.push(ReplacementCode::Var(index));

            continue;
        }

        if source[i] == b'?' && compile_args {
            args = true;
            compile_args = false;

            codes.push(ReplacementCode::StartArgs);

            i += 1;

            continue;
        }

        let start = i;

        while i < source.len() {
            if source[i] == b'$' {
                break;
            }

            if source[i] == b'?' {
                args = true;

                if compile_args {
                    break;
                }
            }

            i += 1;
        }

        codes.push(ReplacementCode::Copy(source[start..i].to_vec()));
    }

    Ok((codes, args))
}

/// ngx_http_rewrite directive handler
fn rewrite_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() < 3 {
        return Err(cf.emerg(format_args!("invalid number of arguments")));
    }

    let pattern = &args[1];
    let mut replacement = args[2].clone();

    if replacement.is_empty() {
        return Err(cf.emerg(format_args!("empty replacement")));
    }

    // ngx_http_regex_compile
    let regex = crate::variables::regex_compile(cf, pattern, 0)?;

    let add_args = if replacement.last() == Some(&b'?') {
        // the last "?" drops the original arguments
        replacement.pop();
        false
    } else {
        true
    };

    // Parse flags and determine rewrite behavior
    let mut flags = RewriteFlags {
        last: false,
        break_cycle: false,
        redirect: false,
        redirect_status: NGX_HTTP_MOVED_TEMPORARILY,
    };

    // Check if replacement looks like a redirect (http://, https://, $scheme)
    if replacement.starts_with(b"http://") || replacement.starts_with(b"https://")
        || replacement.starts_with(b"$scheme")
    {
        flags.redirect = true;
        flags.last = true;
    }

    // Parse optional 4th argument (flag)
    if args.len() == 4 {
        let flag_str = &args[3];
        let flag = std::str::from_utf8(flag_str)
            .unwrap_or("")
            .trim();

        match flag {
            "last" => flags.last = true,
            "break" => {
                flags.break_cycle = true;
                flags.last = true;
            }
            "redirect" => {
                flags.redirect = true;
                flags.redirect_status = NGX_HTTP_MOVED_TEMPORARILY;
                flags.last = true;
            }
            "permanent" => {
                flags.redirect = true;
                flags.redirect_status = NGX_HTTP_MOVED_PERMANENTLY;
                flags.last = true;
            }
            _ => {
                return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(flag_str))))
            }
        }
    }

    // sc.compile_args = !regex->redirect
    let (values, args) = compile_replacement(cf, &replacement, !flags.redirect)?;

    let rule = RewriteRule {
        regex,
        replacement,
        flags,
        log: cell.borrow().log.get_or(false),
        add_args,
        values,
        args,
    };

    // the regex code with its end code; with "last" (flags.last) a match
    // also ends the codes (the NULL code that C adds after the end code,
    // which a regex that does not match skips with regex->next)
    cell.borrow_mut().codes.push(Code::Rewrite(rule));

    Ok(())
}

/// ngx_http_rewrite_return directive handler
fn return_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() < 2 {
        return Err(cf.emerg(format_args!("invalid number of arguments")));
    }

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
            // only a URL can be given without a code
            if args.len() != 2
                || !(v.starts_with(b"http://") || v.starts_with(b"https://") || v.starts_with(b"$scheme"))
            {
                return Err(cf.emerg(format_args!("invalid return code \"{}\"", B(v))));
            }
            status = NGX_HTTP_MOVED_TEMPORARILY;
            text = Some(v.clone());
        }
    }

    let cv = match text {
        Some(t) => Some(crate::script::compile_complex_value(cf, &t, 0)?),
        None => None,
    };

    cell.borrow_mut()
        .codes
        .push(Code::Return { status, text: cv });

    Ok(())
}

/// ngx_http_rewrite_set directive handler
fn set_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() != 3 {
        return Err(cf.emerg(format_args!("invalid number of arguments")));
    }

    let raw = &args[1];
    if raw.is_empty() || raw[0] != b'$' {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(raw))));
    }
    let var_name = &raw[1..];

    // Register the variable and get its index. Matches C ngx_http_rewrite_set.
    let v = crate::variables::add_variable(
        cf,
        var_name,
        crate::variables::NGX_HTTP_VAR_CHANGEABLE | crate::variables::NGX_HTTP_VAR_WEAK,
    )?;
    let var_idx = get_variable_index(cf, var_name)?;

    if v.get_handler.get().is_none() {
        v.get_handler.set(Some(rewrite_var));
        v.data.set(var_idx);
    }

    // Compile the value as a ComplexValue
    let value_bytes = &args[2];
    let value = crate::script::compile_complex_value(cf, value_bytes, 0)?;

    // If the variable has a set_handler (e.g. $args, $limit_rate), emit the
    // handler code instead of caching the value in r.variables — the handler
    // owns the underlying storage.
    if let Some(handler) = v.set_handler.get() {
        cell.borrow_mut()
            .codes
            .push(Code::SetHandler { var_idx, value, handler });
    } else {
        cell.borrow_mut()
            .codes
            .push(Code::Set { var_idx, value });
    }

    Ok(())
}

/// ngx_http_rewrite_var: the module sets the variables directly in
/// r->variables, so the handler only runs for a variable not set yet.
fn rewrite_var(r: &R, v: &mut crate::request::VariableValue, data: usize) -> i64 {
    // ngx_http_variable_null_value
    *v = crate::request::VariableValue { valid: true, ..Default::default() };

    if !*r.loc_conf::<RewriteConf>(ctx_index()).borrow().uninitialized_variable_warn {
        return NGX_OK;
    }

    let name = r.cmcf().borrow().variables.get(data).map(|var| var.name.clone()).unwrap_or_default();
    ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "using uninitialized \"{}\" variable", B(&name));

    NGX_OK
}

/// ngx_http_rewrite_break directive handler
fn break_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    cell.borrow_mut().codes.push(Code::Break { is_break_cycle: true });
    Ok(())
}

/// ngx_http_rewrite_if: the block has its own location configuration, a
/// "noname" location added to the enclosing one (merged with it like any
/// nested location, never matched), and its rewrite directives are compiled
/// into the code sequence of the enclosing level.
fn if_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lcf = conf_rc::<RewriteConf>(conf.as_ref().unwrap());

    let pctx = cf.ctx.clone();
    let ctx = ConfCtx {
        main: pctx.main.clone(),
        srv: pctx.srv.clone(),
        loc: Some(new_slots(http_max_module())),
    };

    let modules = cf.cycle.modules.clone();
    for m in modules.iter().filter(|m| m.def.ty == ngx_core::module::NGX_HTTP_MODULE) {
        if let Some(module) = m.ctx::<HttpModuleDef>() {
            if let Some(create_loc_conf) = module.create_loc_conf {
                let mconf = create_loc_conf(cf);
                ctx.loc.as_ref().unwrap().borrow_mut()[m.ctx_index] = Some(mconf);
            }
        }
    }

    let pclcf = loc_conf_from_ctx(&pctx);

    let clcf = loc_conf_from_ctx(&ctx);
    {
        let name = pclcf.borrow().name.clone();
        let mut c = clcf.borrow_mut();
        c.loc_conf = ctx.loc.clone();
        c.name = name;
        c.noname = true;
    }

    add_location(cf, &pclcf, &clcf)?;

    // ngx_http_rewrite_if_condition
    let args = cf.args.clone();
    let condition = parse_if_condition(cf, &args)?;

    // the inner directives must be compiled to the same code array: they
    // are collected in the codes of the if's rewrite conf, which are moved
    // into the if code after the block

    let nlcf = slot_of::<RewriteConf>(ctx.loc.as_ref().unwrap(), ctx_index());

    let saved_ctx = std::mem::replace(&mut cf.ctx, ctx.clone());
    let saved_cmd_type = cf.cmd_type;

    let loc_conf = if cf.cmd_type == NGX_HTTP_SRV_CONF {
        cf.cmd_type = NGX_HTTP_SIF_CONF;
        None
    } else {
        cf.cmd_type = NGX_HTTP_LIF_CONF;
        ctx.loc.clone()
    };

    let rv = cf.parse_block();

    cf.ctx = saved_ctx;
    cf.cmd_type = saved_cmd_type;

    rv?;

    // the code array belong to parent block

    let codes = std::mem::take(&mut nlcf.borrow_mut().codes);

    lcf.borrow_mut().codes.push(Code::If { condition, codes, loc_conf });

    Ok(())
}

fn accept_directive(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // Stub for directives that are parsed but we don't handle yet
    Ok(())
}

pub fn rewrite_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_SRV_CONF | NGX_HTTP_SIF_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF;
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };

    let commands = vec![
        ngx_core::cmd_fn!(
            "rewrite",
            F | NGX_CONF_TAKE23,
            ConfLevel::Loc,
            rewrite_directive
        ),
        ngx_core::cmd_fn!(
            "return",
            F | NGX_CONF_TAKE12,
            ConfLevel::Loc,
            return_directive
        ),
        ngx_core::cmd_fn!(
            "break",
            F | NGX_CONF_NOARGS,
            ConfLevel::Loc,
            break_directive
        ),
        ngx_core::cmd_fn!(
            "if",
            NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_BLOCK | NGX_CONF_1MORE,
            ConfLevel::Loc,
            if_block
        ),
        ngx_core::cmd_fn!(
            "set",
            F | NGX_CONF_TAKE2,
            ConfLevel::Loc,
            set_directive
        ),
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

/// e->ip after a code: the next code, or out of the handler with e->status
enum Flow {
    Next,
    Exit(i64),
}

/// ngx_http_rewrite_handler
async fn rewrite_handler(r: R) -> i64 {
    let index = r.cmcf().borrow().phase_engine.location_rewrite_index;

    let null_location = {
        let cscf = r.cscf();
        let srv_loc_conf = cscf.borrow().ctx.loc.clone();
        srv_loc_conf.map_or(false, |lc| Rc::ptr_eq(&lc, &r.loc_conf.borrow()))
    };

    if r.phase_handler.get() == index && null_location {
        /* skipping location rewrite phase for server null location */
        return NGX_DECLINED;
    }

    let rlcf = r.loc_conf::<RewriteConf>(ctx_index());

    let (codes, log) = {
        let c = rlcf.borrow();

        if c.codes.is_empty() {
            return NGX_DECLINED;
        }

        (c.codes.clone(), c.log.get_or(false))
    };

    match run_codes(&r, &codes, log).await {
        Flow::Next => NGX_DECLINED,
        Flow::Exit(status) => status,
    }
}

/// The script engine loop of ngx_http_rewrite_handler.  The codes of an "if"
/// block are part of the enclosing sequence (C compiles them into the same
/// code array): they run when the condition is true, and the codes after the
/// block follow unless one of them ended the script.
async fn run_codes(r: &R, codes: &[Code], log: bool) -> Flow {
    for code in codes {
        let flow = match code {
            Code::Rewrite(rule) => regex_code(r, rule, log).await,

            Code::Set { var_idx, value } => {
                if let Ok(val) = crate::script::complex_value(r, value) {
                    set_indexed_variable(r, *var_idx, val);
                }
                Flow::Next
            }

            Code::SetHandler { var_idx, value, handler } => {
                if let Ok(val) = crate::script::complex_value(r, value) {
                    let mut vv = crate::request::VariableValue {
                        data: val,
                        valid: true,
                        not_found: false,
                        no_cacheable: false,
                        escape: false,
                    };
                    handler(r, &mut vv, *var_idx);
                }
                Flow::Next
            }

            Code::Return { status, text } => return_code(r, *status, text).await,

            Code::Break { .. } => break_code(r),

            Code::If { condition, codes, loc_conf } => {
                match if_code(r, condition, loc_conf, log) {
                    Ok(true) => Box::pin(run_codes(r, codes, log)).await,
                    Ok(false) => Flow::Next,
                    Err(status) => Flow::Exit(status),
                }
            }
        };

        if let Flow::Exit(_) = flow {
            return flow;
        }
    }

    Flow::Next
}

/// ngx_http_script_if_code: the condition value is popped; if it is true,
/// the location configuration of the block (if any) becomes the request's;
/// Err(status) when the condition ended the codes
fn if_code(r: &R, condition: &IfCondition, loc_conf: &Option<Rc<ConfSlots>>, log: bool) -> Result<bool, i64> {
    let value = eval_if_condition(r, condition, log)?;

    http_debug!(r, "http script if");

    if value {
        if let Some(loc_conf) = loc_conf {
            *r.loc_conf.borrow_mut() = loc_conf.clone();
            update_location_config(r);
        }

        return Ok(true);
    }

    http_debug!(r, "http script if: false");

    Ok(false)
}

/// ngx_http_script_break_code
fn break_code(r: &R) -> Flow {
    if r.uri_changed.get() {
        r.valid_location.set(false);
        r.uri_changed.set(false);
    }

    Flow::Exit(NGX_DECLINED)
}

/// ngx_http_script_return_code
async fn return_code(r: &R, status: i64, text: &Option<ComplexValue>) -> Flow {
    // an error status without text (or with an empty one) is the special
    // response of the status: code->text.value.len || code->text.lengths
    let has_text = text.as_ref().map_or(false, |t| !t.value.is_empty() || !t.is_constant());

    if status >= 400 && !has_text {
        // Set the error status and return it to be handled by error_page/default error page
        r.headers_out.borrow_mut().status = status;
        return Flow::Exit(status);
    }

    // Always send a response with explicit text or empty body
    let text_val = text.clone().unwrap_or_else(|| ComplexValue::constant(b""));

    // Match C: `return NNN "text"` passes ct=NULL, so
    // set_content_type applies from the extension/types_hash.
    let rc = send_response(r, status, None, &text_val).await;
    if rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE {
        return Flow::Exit(NGX_DONE);
    }

    Flow::Exit(rc)
}

/// ngx_http_script_copy_capture_code: the capture n (2 * $n) of the
/// request's captures, escaped as arguments in the arguments of the
/// replacement or in a redirect (e->is_args || e->quote) when the request
/// URI was quoted or had a "+".
fn copy_capture(r: &R, n: usize, escape: bool, buf: &mut Vec<u8>) {
    if n >= r.ncaptures.get() {
        return;
    }

    let cap = r.captures.borrow();

    if n + 1 >= cap.len() || cap[n] < 0 || cap[n + 1] < cap[n] {
        return;
    }

    let data = r.captures_data.borrow();

    let (start, end) = (cap[n] as usize, cap[n + 1] as usize);

    if end > data.len() {
        return;
    }

    let p = &data[start..end];

    if escape && (r.quoted_uri.get() || r.plus_in_uri.get()) {
        ngx_core::string::escape_uri_into(buf, p, ngx_core::string::NGX_ESCAPE_ARGS);
    } else {
        buf.extend_from_slice(p);
    }
}

/// The Location of a redirect in ngx_http_script_regex_end_code: the buffer
/// unescaped up to the first "?", the rest as is, then the original
/// arguments unless the replacement ended with "?" (add_args), after "&" if
/// the replacement had a "?" (code->args), else after "?".
fn redirect_location(buf: &[u8], add_args: bool, args: bool, orig_args: &[u8]) -> Vec<u8> {
    let (mut location, consumed) = ngx_core::string::unescape_uri(buf, ngx_core::string::NGX_UNESCAPE_REDIRECT);

    if consumed < buf.len() {
        location.extend_from_slice(&buf[consumed..]);
    }

    if add_args && !orig_args.is_empty() {
        location.push(if args { b'&' } else { b'?' });
        location.extend_from_slice(orig_args);
    }

    location
}

/// The URI and the arguments of an internal rewrite in
/// ngx_http_script_regex_end_code: with the start args code (e->args at
/// `args_pos`) the arguments of the replacement, then "&" and the original
/// ones if add_args; else the original arguments if add_args, or none.
fn rewritten_uri_args(mut buf: Vec<u8>, args_pos: Option<usize>, add_args: bool, orig_args: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match args_pos {
        Some(pos) => {
            let mut args = buf.split_off(pos);

            if add_args && !orig_args.is_empty() {
                args.push(b'&');
                args.extend_from_slice(orig_args);
            }

            (buf, args)
        }

        None => {
            let args = if add_args { orig_args.to_vec() } else { Vec::new() };

            (buf, args)
        }
    }
}

/// ngx_http_script_regex_start_code and ngx_http_script_regex_end_code of
/// the rewrite directive (code->uri set), with the NULL code that follows
/// them after a rewrite with "last", "break", "redirect" or "permanent".
async fn regex_code(r: &R, rule: &RewriteRule, log: bool) -> Flow {
    let uri = r.uri.borrow().clone();

    http_debug!(r, "http script regex: \"{}\"", B(&rule.regex.name));

    let log = log || r.connection.log.debug_enabled(NGX_LOG_DEBUG_HTTP);

    // ngx_http_regex_exec: the captures of a match are the request's
    let rc = crate::variables::regex_exec(r, &rule.regex, &uri);

    if rc == NGX_DECLINED {
        if log {
            ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "\"{}\" does not match \"{}\"", B(&rule.regex.name), B(&uri));
        }

        r.ncaptures.set(0);

        // e->ip += code->next: past the end code and the NULL code
        return Flow::Next;
    }

    if rc == NGX_ERROR {
        return Flow::Exit(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    if log {
        ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "\"{}\" matches \"{}\"", B(&rule.regex.name), B(&uri));
    }

    // code->uri
    r.internal.set(true);
    r.valid_unparsed_uri.set(false);

    if rule.flags.break_cycle {
        r.valid_location.set(false);
        r.uri_changed.set(false);
    } else {
        r.uri_changed.set(true);
    }

    // the values codes: e->quote = code->redirect, e->is_args after the
    // start args code, e->args the position of the arguments

    let mut buf = Vec::new();
    let mut is_args = false;
    let mut args_pos = None;

    for code in &rule.values {
        match code {
            ReplacementCode::Copy(data) => {
                buf.extend_from_slice(data);

                http_debug!(r, "http script copy: \"{}\"", B(data));
            }

            ReplacementCode::Var(index) => {
                let pos = buf.len();

                if let Some(value) = crate::variables::get_flushed_variable(r, *index) {
                    if !value.not_found {
                        buf.extend_from_slice(&value.data);
                    }
                }

                http_debug!(r, "http script var: \"{}\"", B(&buf[pos..]));
            }

            ReplacementCode::Capture(n) => {
                let pos = buf.len();

                copy_capture(r, *n, is_args || rule.flags.redirect, &mut buf);

                http_debug!(r, "http script capture: \"{}\"", B(&buf[pos..]));
            }

            ReplacementCode::StartArgs => {
                http_debug!(r, "http script args");

                is_args = true;
                args_pos = Some(buf.len());
            }
        }
    }

    // ngx_http_script_regex_end_code

    http_debug!(r, "http script regex end");

    if rule.flags.redirect {
        let orig_args = r.args.borrow().clone();

        let location = redirect_location(&buf, rule.add_args, rule.args, &orig_args);

        if log {
            ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "rewritten redirect: \"{}\"", B(&location));
        }

        // the Location header and e->status = code->status, which the
        // NULL code after the end code returns
        let cv = ComplexValue::constant(&location);
        let rc = send_response(r, rule.flags.redirect_status, None, &cv).await;
        if rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE {
            return Flow::Exit(NGX_DONE);
        }
        return Flow::Exit(rc);
    }

    let orig_args = r.args.borrow().clone();

    let (rewritten_uri, rewritten_args) = rewritten_uri_args(buf, args_pos, rule.add_args, &orig_args);

    if log {
        ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "rewritten data: \"{}\", args: \"{}\"", B(&rewritten_uri), B(&rewritten_args));
    }

    *r.args.borrow_mut() = rewritten_args;

    let zero_length = rewritten_uri.is_empty();

    *r.uri.borrow_mut() = rewritten_uri;

    if zero_length {
        ngx_core::ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "the rewritten URI has a zero length");
        return Flow::Exit(NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    set_exten(r);

    if rule.flags.last {
        // the NULL code after the end code
        return Flow::Exit(NGX_DECLINED);
    }

    Flow::Next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_flags_parsing() {
        let flags = RewriteFlags {
            last: true,
            break_cycle: false,
            redirect: false,
            redirect_status: NGX_HTTP_MOVED_TEMPORARILY,
        };
        assert!(flags.last);
        assert!(!flags.break_cycle);
    }

    #[test]
    fn test_redirect_location() {
        // the original arguments after "?", or after "&" when the
        // replacement had a "?"
        assert_eq!(redirect_location(b"http://x/a", true, false, b"q=1"), b"http://x/a?q=1".to_vec());
        assert_eq!(redirect_location(b"http://x/a?b=2", true, true, b"q=1"), b"http://x/a?b=2&q=1".to_vec());

        // a replacement that ended with "?" drops them
        assert_eq!(redirect_location(b"http://x/a", false, false, b"q=1"), b"http://x/a".to_vec());
        assert_eq!(redirect_location(b"http://x/a", true, false, b""), b"http://x/a".to_vec());

        // NGX_UNESCAPE_REDIRECT up to the first "?": characters above "%"
        // are decoded, others stay escaped; the arguments are left as is
        assert_eq!(redirect_location(b"http://x/a%41%20%3F?c=%41", true, true, b""), b"http://x/aA%20??c=%41".to_vec());
    }

    #[test]
    fn test_rewritten_uri_args() {
        // e->args: the arguments of the replacement, then the original ones
        assert_eq!(rewritten_uri_args(b"/xa=1".to_vec(), Some(2), true, b"q=2"), (b"/x".to_vec(), b"a=1&q=2".to_vec()));
        assert_eq!(rewritten_uri_args(b"/xa=1".to_vec(), Some(2), false, b"q=2"), (b"/x".to_vec(), b"a=1".to_vec()));
        assert_eq!(rewritten_uri_args(b"/xa=1".to_vec(), Some(2), true, b""), (b"/x".to_vec(), b"a=1".to_vec()));

        // "?" at the end of the replacement: empty arguments of the
        // replacement
        assert_eq!(rewritten_uri_args(b"/x".to_vec(), Some(2), true, b"q=2"), (b"/x".to_vec(), b"&q=2".to_vec()));

        // no arguments in the replacement
        assert_eq!(rewritten_uri_args(b"/x".to_vec(), None, true, b"q=2"), (b"/x".to_vec(), b"q=2".to_vec()));
        assert_eq!(rewritten_uri_args(b"/x".to_vec(), None, false, b"q=2"), (b"/x".to_vec(), Vec::new()));
    }
}
