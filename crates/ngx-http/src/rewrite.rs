//! ngx_http_rewrite_module - URL rewriting and conditional request handling

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
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
    pub regex: Rc<Regex>,
    pub replacement: Vec<u8>,
    pub flags: RewriteFlags,
    pub log: bool,
    /// regex->add_args: the replacement does not end with "?", the
    /// original arguments are appended
    pub add_args: bool,
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
    /// String equality: $var = "value"
    Equal(usize, Vec<u8>),
    /// String inequality: $var != "value"
    NotEqual(usize, Vec<u8>),
    /// Regex match: $var ~ pattern
    RegexMatch(usize, Rc<Regex>),
    /// Case-insensitive regex: $var ~* pattern
    RegexMatchCaseInsensitive(usize, Rc<Regex>),
    /// Negated regex: $var !~ pattern
    RegexNotMatch(usize, Rc<Regex>),
    /// Negated case-insensitive: $var !~* pattern
    RegexNotMatchCaseInsensitive(usize, Rc<Regex>),
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

/// Parse if condition from directive arguments
fn parse_if_condition(cf: &mut Conf, args_orig: &[Vec<u8>]) -> Result<IfCondition, ConfError> {
    if args_orig.is_empty() {
        return Err(cf.emerg(format_args!("no condition specified")));
    }

    // Handle parentheses around condition: if ($var) or if ( $var )
    let mut args = args_orig.to_vec();

    // Remove leading '(' from first arg if present
    if args[0].starts_with(b"(") {
        if args[0].len() == 1 {
            // Just "(" - remove it and shift subsequent args
            args.remove(0);
        } else {
            // "($var" etc - remove the leading paren
            args[0] = args[0][1..].to_vec();
        }
    }

    // Remove trailing ')' from last arg if present
    if !args.is_empty() && args[args.len() - 1].ends_with(b")") {
        let last_idx = args.len() - 1;
        if args[last_idx].len() == 1 {
            // Just ")" - remove it
            args.pop();
        } else {
            // "var)" etc - remove the trailing paren
            args[last_idx] = args[last_idx][..args[last_idx].len() - 1].to_vec();
        }
    }

    if args.is_empty() {
        return Err(cf.emerg(format_args!("no condition specified")));
    }

    // Check for file test operators: -f, -d, -e, -x (and negated !-f, !-d, etc)
    let first = std::str::from_utf8(&args[0]).unwrap_or("");
    let is_negated = first.starts_with('!');
    let test_str = if is_negated { &first[1..] } else { first };

    if test_str.starts_with('-') && test_str.len() == 2 {
        // File test operator
        if args.len() < 2 {
            return Err(cf.emerg(format_args!("file test needs an argument")));
        }

        let test_char = test_str.chars().nth(1).unwrap();
        let path_cv = crate::script::compile_complex_value(cf, &args[1], 0)?;

        let cond = match (test_char, is_negated) {
            ('f', false) => IfCondition::FileExists(path_cv),
            ('f', true) => IfCondition::FileNotExists(path_cv),
            ('d', false) => IfCondition::DirectoryExists(path_cv),
            ('d', true) => IfCondition::DirectoryNotExists(path_cv),
            ('e', false) => IfCondition::EntityExists(path_cv),
            ('e', true) => IfCondition::EntityNotExists(path_cv),
            ('x', false) => IfCondition::Executable(path_cv),
            ('x', true) => IfCondition::NotExecutable(path_cv),
            _ => return Err(cf.emerg(format_args!("unknown file test operator: {}", test_str))),
        };

        return Ok(cond);
    }

    // Variable-based condition
    if !first.starts_with('$') {
        return Err(cf.emerg(format_args!("invalid condition: {}", B(&args[0]))));
    }

    let var_name = &args[0][1..]; // Remove leading '$'
    // ngx_http_rewrite_variable: the variable is referenced by its index only
    let var_idx = get_variable_index(cf, var_name)?;

    // If only variable, check if non-empty and not "0"
    if args.len() == 1 {
        return Ok(IfCondition::Variable(var_idx));
    }

    // Check for comparison/regex operators
    let op = std::str::from_utf8(&args[1]).unwrap_or("");

    if args.len() < 3 {
        return Err(cf.emerg(format_args!("operator {} needs a value", op)));
    }

    let value = &args[2];

    match op {
        "=" => Ok(IfCondition::Equal(var_idx, value.clone())),
        "!=" => Ok(IfCondition::NotEqual(var_idx, value.clone())),
        "~" => {
            let regex = match ngx_core::regex::Regex::compile(value, 0) {
                Ok(r) => r,
                Err(e) => return Err(cf.emerg(format_args!("{}", e))),
            };
            Ok(IfCondition::RegexMatch(var_idx, regex))
        }
        "~*" => {
            let regex = match ngx_core::regex::Regex::compile(value, ngx_core::regex::NGX_REGEX_CASELESS) {
                Ok(r) => r,
                Err(e) => return Err(cf.emerg(format_args!("{}", e))),
            };
            Ok(IfCondition::RegexMatchCaseInsensitive(var_idx, regex))
        }
        "!~" => {
            let regex = match ngx_core::regex::Regex::compile(value, 0) {
                Ok(r) => r,
                Err(e) => return Err(cf.emerg(format_args!("{}", e))),
            };
            Ok(IfCondition::RegexNotMatch(var_idx, regex))
        }
        "!~*" => {
            let regex = match ngx_core::regex::Regex::compile(value, ngx_core::regex::NGX_REGEX_CASELESS) {
                Ok(r) => r,
                Err(e) => return Err(cf.emerg(format_args!("{}", e))),
            };
            Ok(IfCondition::RegexNotMatchCaseInsensitive(var_idx, regex))
        }
        _ => Err(cf.emerg(format_args!("unknown operator: {}", op))),
    }
}

/// Check file existence and type
fn check_file_type(r: &R, cv: &crate::script::ComplexValue, is_dir: bool, is_exec: bool, entity: bool) -> bool {
    let path = match crate::script::complex_value(r, cv) {
        Ok(v) => v,
        Err(_) => return false,
    };
    use std::os::unix::ffi::OsStrExt;
    let os = std::ffi::OsStr::from_bytes(&path);
    match std::fs::metadata(os) {
        Ok(m) => {
            if entity { true }
            else if is_dir { m.is_dir() }
            else if is_exec {
                // -x matches file or directory with any execute bit set
                // (C: ngx_file_info + (fi.st_mode & S_IXUSR)).
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            } else { m.is_file() }
        }
        Err(_) => false,
    }
}

/// The regex test of an if condition (ngx_http_script_regex_start_code with
/// code->test): the variable's value (empty if not found, as
/// ngx_http_script_var_code) is matched, the captures of a match are the
/// request's captures, and a mismatch resets them.
fn regex_test(r: &R, idx: usize, regex: &Rc<Regex>, negative_test: bool, log: bool) -> bool {
    let line = match crate::variables::get_flushed_variable(r, idx) {
        Some(vv) if !vv.not_found => vv.data,
        _ => Vec::new(),
    };

    http_debug!(r, "http script regex: \"{}\"", B(&regex.pattern));

    let log = log || r.connection.log.debug_enabled(NGX_LOG_DEBUG_HTTP);

    let captures = match regex.exec(&line) {
        Some(c) => c,
        None => {
            if log {
                ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "\"{}\" does not match \"{}\"", B(&regex.pattern), B(&line));
            }

            r.ncaptures.set(0);

            return negative_test;
        }
    };

    // ngx_http_regex_exec
    let mut cap_vec = Vec::with_capacity(captures.len() * 2);
    for (start, end) in &captures {
        cap_vec.push(*start);
        cap_vec.push(*end);
    }

    r.ncaptures.set(cap_vec.len());
    *r.captures.borrow_mut() = cap_vec;
    *r.captures_data.borrow_mut() = line.clone();

    if log {
        ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "\"{}\" matches \"{}\"", B(&regex.pattern), B(&line));
    }

    !negative_test
}

/// Evaluate if condition at runtime
fn eval_if_condition(r: &R, condition: &IfCondition, log: bool) -> bool {
    match condition {
        IfCondition::Variable(idx) => {
            if let Some(vv) = crate::variables::get_flushed_variable(r, *idx) {
                !vv.not_found && !vv.data.is_empty() && !(vv.data.len() == 1 && vv.data[0] == b'0')
            } else {
                false
            }
        }
        IfCondition::Equal(idx, expected) => {
            // Match C ngx_http_script_equal_code: compare value bytes regardless
            // of not_found (unset variables have empty data, so `$x = ""` is true).
            match crate::variables::get_flushed_variable(r, *idx) {
                Some(vv) => vv.data == *expected,
                None => expected.is_empty(),
            }
        }
        IfCondition::NotEqual(idx, expected) => {
            match crate::variables::get_flushed_variable(r, *idx) {
                Some(vv) => vv.data != *expected,
                None => !expected.is_empty(),
            }
        }
        IfCondition::RegexMatch(idx, regex) | IfCondition::RegexMatchCaseInsensitive(idx, regex) => {
            regex_test(r, *idx, regex, false, log)
        }
        IfCondition::RegexNotMatch(idx, regex) | IfCondition::RegexNotMatchCaseInsensitive(idx, regex) => {
            regex_test(r, *idx, regex, true, log)
        }
        IfCondition::FileExists(cv) => {
            check_file_type(&r, cv, false, false, false)
        }
        IfCondition::FileNotExists(cv) => {
            !check_file_type(&r, cv, false, false, false)
        }
        IfCondition::DirectoryExists(cv) => {
            check_file_type(&r, cv, true, false, false)
        }
        IfCondition::DirectoryNotExists(cv) => {
            !check_file_type(&r, cv, true, false, false)
        }
        IfCondition::EntityExists(cv) => {
            check_file_type(&r, cv, false, false, true)
        }
        IfCondition::EntityNotExists(cv) => {
            !check_file_type(&r, cv, false, false, true)
        }
        IfCondition::Executable(cv) => {
            check_file_type(&r, cv, false, true, false)
        }
        IfCondition::NotExecutable(cv) => {
            !check_file_type(&r, cv, false, true, false)
        }
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

    // Compile regex
    let regex = match ngx_core::regex::Regex::compile(pattern, 0) {
        Ok(r) => r,
        Err(e) => return Err(cf.emerg(format_args!("{}", e))),
    };

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

    let rule = RewriteRule {
        regex,
        replacement,
        flags,
        log: cell.borrow().log.get_or(false),
        add_args,
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
            if args.len() == 3 {
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
    let condition = parse_if_condition(cf, &args[1..])?;

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
                if if_code(r, condition, loc_conf, log) {
                    Box::pin(run_codes(r, codes, log)).await
                } else {
                    Flow::Next
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
/// the location configuration of the block (if any) becomes the request's
fn if_code(r: &R, condition: &IfCondition, loc_conf: &Option<Rc<ConfSlots>>, log: bool) -> bool {
    let value = eval_if_condition(r, condition, log);

    http_debug!(r, "http script if");

    if value {
        if let Some(loc_conf) = loc_conf {
            *r.loc_conf.borrow_mut() = loc_conf.clone();
            update_location_config(r);
        }

        return true;
    }

    http_debug!(r, "http script if: false");

    false
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
    // If no explicit text, send error page HTML for error statuses
    if text.is_none() && status >= 400 {
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

/// The replacement of a rewrite for the URI matched with `captures`.
fn rewrite_replacement(r: &R, rule: &RewriteRule, uri: &[u8], cap_vec: &[i32]) -> Vec<u8> {
    // Build replacement string from template
    // Track which captures have been used for encoding on second+ use
    let mut replacement = Vec::new();
    let repl = &rule.replacement;
    let mut i = 0;
    let mut capture_use_count: [usize; 10] = [0; 10];

    while i < repl.len() {
        if repl[i] == b'$' && i + 1 < repl.len() {
            if repl[i + 1].is_ascii_digit() {
                // Capture group reference: $1, $2, etc.
                let cap_num = (repl[i + 1] - b'0') as usize;
                let cap_idx = cap_num * 2;

                // Check if this capture group exists
                if cap_idx + 1 < cap_vec.len() {
                    let start = cap_vec[cap_idx];
                    let end = cap_vec[cap_idx + 1];
                    if start >= 0 && end >= start {
                        let s = start as usize;
                        let e = end as usize;
                        if e <= uri.len() {
                            let captured = &uri[s..e];
                            // URL-encode on second and subsequent uses
                            if capture_use_count[cap_num] > 0 {
                                // Percent-encode special characters
                                for &byte in captured {
                                    match byte {
                                        b'%' | b'?' | b'#' | b'&' | b'=' | b'+' => {
                                            replacement.extend_from_slice(
                                                format!("%{:02X}", byte).as_bytes()
                                            );
                                        }
                                        _ => replacement.push(byte),
                                    }
                                }
                            } else {
                                replacement.extend_from_slice(captured);
                            }
                            capture_use_count[cap_num] += 1;
                        }
                    }
                }
                i += 2;
                continue;
            } else if repl[i + 1] == b'{' {
                // ${N} style capture reference
                let end = match memchr::memchr(b'}', &repl[i + 2..]) {
                    Some(e) => e,
                    None => {
                        replacement.push(b'$');
                        i += 1;
                        continue;
                    }
                };

                if let Ok(num_str) = std::str::from_utf8(&repl[i + 2..i + 2 + end]) {
                    if let Ok(cap_num) = num_str.parse::<usize>() {
                        let cap_idx = cap_num * 2;
                        if cap_idx + 1 < cap_vec.len() {
                            let start = cap_vec[cap_idx];
                            let end_val = cap_vec[cap_idx + 1];
                            if start >= 0 && end_val >= start {
                                let s = start as usize;
                                let e = end_val as usize;
                                if e <= uri.len() {
                                    replacement.extend_from_slice(&uri[s..e]);
                                }
                            }
                        }
                        i += 3 + end;
                        continue;
                    }
                }
                replacement.push(b'$');
                i += 1;
                continue;
            } else if repl[i + 1] == b'$' {
                // Escaped $: $$
                replacement.push(b'$');
                i += 2;
                continue;
            } else if repl[i + 1].is_ascii_alphabetic() || repl[i + 1] == b'_' {
                // Variable reference: $name or ${name}
                let start = i + 1;
                let mut end = start;
                while end < repl.len()
                    && (repl[end].is_ascii_alphanumeric() || repl[end] == b'_')
                {
                    end += 1;
                }
                let name = &repl[start..end];
                if let Some(vv) = crate::variables::get_variable(r, name) {
                    if !vv.not_found {
                        replacement.extend_from_slice(&vv.data);
                    }
                }
                i = end;
                continue;
            }
        }
        replacement.push(repl[i]);
        i += 1;
    }

    replacement
}

/// ngx_http_script_regex_start_code and ngx_http_script_regex_end_code of
/// the rewrite directive (code->uri set), with the NULL code that follows
/// them after a rewrite with "last", "break", "redirect" or "permanent".
async fn regex_code(r: &R, rule: &RewriteRule, log: bool) -> Flow {
    let uri = r.uri.borrow().clone();

    http_debug!(r, "http script regex: \"{}\"", B(&rule.regex.pattern));

    let log = log || r.connection.log.debug_enabled(NGX_LOG_DEBUG_HTTP);

    let captures = match rule.regex.exec(&uri) {
        Some(c) => c,
        None => {
            if log {
                ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "\"{}\" does not match \"{}\"", B(&rule.regex.pattern), B(&uri));
            }

            r.ncaptures.set(0);

            // e->ip += code->next: past the end code and the NULL code
            return Flow::Next;
        }
    };

    if log {
        ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "\"{}\" matches \"{}\"", B(&rule.regex.pattern), B(&uri));
    }

    // Store captures in request for later use ($1, $2, etc)
    // captures is Vec<(i32, i32)> pairs
    let mut cap_vec = Vec::new();
    for (start, end) in &captures {
        cap_vec.push(*start);
        cap_vec.push(*end);
    }

    // Store captures and the URI being rewritten (ngx_http_regex_exec)
    r.ncaptures.set(cap_vec.len());
    *r.captures.borrow_mut() = cap_vec.clone();
    *r.captures_data.borrow_mut() = uri.clone();

    // code->uri
    r.internal.set(true);
    r.valid_unparsed_uri.set(false);

    if rule.flags.break_cycle {
        r.valid_location.set(false);
        r.uri_changed.set(false);
    } else {
        r.uri_changed.set(true);
    }

    let replacement = rewrite_replacement(r, rule, &uri, &cap_vec);

    // Handle redirect response
    if rule.flags.redirect {
        // A trailing '?' of the replacement (removed at
        // configuration time) suppresses the original args
        let mut response_url = replacement;
        let suppress_args = !rule.add_args;

        // Unescape the URL per C ngx_http_script_regex_end_code:
        // percent-encoded bytes in variable/capture expansions get
        // decoded up to the first '?', then the query string is
        // copied verbatim.
        let (mut decoded, consumed) = ngx_core::string::unescape_uri(
            &response_url,
            ngx_core::string::NGX_UNESCAPE_REDIRECT,
        );
        if consumed < response_url.len() {
            decoded.extend_from_slice(&response_url[consumed..]);
        }
        response_url = decoded;

        let orig_args = r.args.borrow().clone();
        if !suppress_args && !orig_args.is_empty() {
            // Append original args to the replacement URL
            if !response_url.contains(&b'?') {
                response_url.push(b'?');
            } else {
                response_url.push(b'&');
            }
            response_url.extend_from_slice(&orig_args);
        }

        if log {
            ngx_core::ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "rewritten redirect: \"{}\"", B(&response_url));
        }

        // Send redirect response
        let cv = ComplexValue::constant(&response_url);
        let rc = send_response(r, rule.flags.redirect_status, None, &cv).await;
        if rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE {
            return Flow::Exit(NGX_DONE);
        }
        return Flow::Exit(rc);
    }

    // the args of the replacement (e->args), then the original args unless
    // the replacement ended with '?'
    let orig_args = r.args.borrow().clone();

    let (rewritten_uri, rewritten_args) = if let Some(qpos) = replacement.iter().position(|&b| b == b'?') {
        let uri_part = replacement[..qpos].to_vec();
        let mut args_part = replacement[qpos + 1..].to_vec();
        if rule.add_args && !orig_args.is_empty() {
            args_part.push(b'&');
            args_part.extend_from_slice(&orig_args);
        }
        (uri_part, args_part)
    } else if rule.add_args {
        (replacement, orig_args)
    } else {
        (replacement, Vec::new())
    };

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
}
