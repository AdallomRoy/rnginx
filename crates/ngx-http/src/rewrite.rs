//! ngx_http_rewrite_module - port of C rewrite module with full if/condition support

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::{atoi, B};

use crate::core::*;
use crate::core_rt::*;
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_rewrite_module");

// File operation codes
const FILE_PLAIN: u32 = 0;
const FILE_NOT_PLAIN: u32 = 1;
const FILE_DIR: u32 = 2;
const FILE_NOT_DIR: u32 = 3;
const FILE_EXISTS: u32 = 4;
const FILE_NOT_EXISTS: u32 = 5;
const FILE_EXEC: u32 = 6;
const FILE_NOT_EXEC: u32 = 7;

#[derive(Clone, Debug)]
pub enum ScriptCode {
    /// Regex match on URI - pushes 1 on match, 0 on no match (for "last" flag)
    RegexStart {
        regex: Rc<HttpRegex>,
        add_args: bool,
        redirect: bool,
        redirect_status: i64,
        break_cycle: bool,
    },
    RegexEnd {
        add_args: bool,
        redirect: bool,
    },
    /// Return directive - sends response and exits
    Return {
        status: i64,
        text: Option<ComplexValue>,
    },
    /// Break - reset uri_changed flag and exit rewrite processing
    Break,
    /// If condition - pops stack, tests truthiness, may jump or apply loc_conf
    If,
    /// Equal comparison - pops val and cmp, pushes result
    Equal,
    NotEqual,
    /// File tests - pops path, tests file properties
    File {
        op: u32,
    },
    /// Push literal value
    Value {
        data: Vec<u8>,
    },
    /// Push variable value
    Var {
        index: usize,
    },
    /// Push regex capture group
    Capture {
        n: usize,
    },
    /// Pop and store in variable
    SetVar {
        index: usize,
    },
    /// Evaluate complex value and push
    ComplexValue {
        value: ComplexValue,
    },
    /// Noop marker
    Nop,
}

pub struct RewriteConf {
    pub codes: Vec<ScriptCode>,
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

fn rewrite_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let pattern = &args[1];
    let mut replacement = args[2].clone();

    // Parse flags
    let mut last = false;
    let mut break_cycle = false;
    let mut redirect = false;
    let mut redirect_status = NGX_HTTP_MOVED_TEMPORARILY;

    if args.len() == 4 {
        let flag = &args[3];
        match flag.as_slice() {
            b"last" => last = true,
            b"break" => {
                break_cycle = true;
                last = true;
            }
            b"redirect" => {
                redirect = true;
                redirect_status = NGX_HTTP_MOVED_TEMPORARILY;
                last = true;
            }
            b"permanent" => {
                redirect = true;
                redirect_status = NGX_HTTP_MOVED_PERMANENTLY;
                last = true;
            }
            _ => {
                return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(flag))));
            }
        }
    }

    // Check for redirect prefixes in replacement
    if replacement.starts_with(b"http://") || replacement.starts_with(b"https://") || replacement.starts_with(b"$scheme") {
        redirect = true;
        redirect_status = NGX_HTTP_MOVED_TEMPORARILY;
        last = true;
    }

    // Check for "?" at the end of replacement to disable adding old args
    let mut add_args = true;
    if replacement.ends_with(b"?") {
        replacement.pop();
        add_args = false;
    }

    // Compile regex pattern
    let regex = regex_compile(cf, pattern, 0)?;

    // Compile replacement as complex value
    let cv = compile_complex_value(cf, &replacement, 0)?;

    let mut codes = cell.borrow_mut();

    // Add RegexStart code
    codes.push(ScriptCode::RegexStart {
        regex,
        add_args,
        redirect,
        redirect_status,
        break_cycle,
    });

    // Add replacement codes (from the complex value parts)
    if let Some(ref parts) = cv.parts {
        for part in parts {
            match part {
                Part::Literal(l) => codes.push(ScriptCode::Value { data: l.clone() }),
                Part::Var(idx) => codes.push(ScriptCode::Var { index: *idx }),
                Part::Capture(n) => codes.push(ScriptCode::Capture { n: *n }),
            }
        }
    } else {
        codes.push(ScriptCode::Value { data: cv.value.clone() });
    }

    // Add RegexEnd code
    codes.push(ScriptCode::RegexEnd { add_args, redirect });

    // Add Nop to mark end if "last"
    if last {
        codes.push(ScriptCode::Nop);
    }

    drop(codes);
    Ok(())
}

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
    cell.borrow_mut().codes.push(ScriptCode::Return { status, text: cv });
    Ok(())
}

fn break_directive(_cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    cell.borrow_mut().codes.push(ScriptCode::Break);
    Ok(())
}

fn set_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let var_name = &args[1];
    let var_value = &args[2];

    // Variable name must start with $
    if var_name.is_empty() || var_name[0] != b'$' {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(var_name))));
    }

    // Get or create variable
    let var_name = &var_name[1..];
    let index = add_variable(cf, var_name, NGX_HTTP_VAR_CHANGEABLE)?.index.get();

    // Compile the value as a complex value
    let cv = compile_complex_value(cf, var_value, 0)?;

    let mut codes = cell.borrow_mut();
    codes.push(ScriptCode::ComplexValue { value: cv });
    codes.push(ScriptCode::SetVar { index });

    drop(codes);
    Ok(())
}

fn if_block(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());

    // Parse the condition
    parse_if_condition(cf, &cell)?;

    // Parse the block as part of same code array
    let saved_ct = cf.cmd_type;
    cf.cmd_type = if saved_ct == NGX_HTTP_SRV_CONF {
        NGX_HTTP_SIF_CONF
    } else {
        NGX_HTTP_LIF_CONF
    };
    let rv = cf.parse_block();
    cf.cmd_type = saved_ct;
    rv
}

fn parse_if_condition(cf: &mut Conf, cell: &Rc<RefCell<RewriteConf>>) -> ConfResult {
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(cf.emerg(format_args!("if requires a condition")));
    }

    // Arguments are already tokenized by conf parser
    // Format: if ( <expr> ) { ... }
    // args[0] = "if", args[1] = first_expr_token, args[2] = second_expr_token, ...

    let mut cur = 1;
    let mut last = args.len() - 1;

    // Handle opening paren
    let mut first_token = args[1].clone();
    if first_token == b"(" {
        cur = 2;
    } else if first_token.starts_with(b"(") {
        first_token = first_token[1..].to_vec();
    } else {
        return Err(cf.emerg(format_args!("invalid condition \"{}\"", B(&args[1]))));
    }

    // Handle closing paren
    let mut last_token = args[last].clone();
    if last_token == b")" {
        last -= 1;
    } else if last_token.ends_with(b")") {
        last_token.truncate(last_token.len() - 1);
    } else {
        return Err(cf.emerg(format_args!("invalid condition \"{}\"", B(&args[last]))));
    }

    let mut codes = cell.borrow_mut();

    // Now parse the condition based on number and types of tokens
    if cur > last {
        return Err(cf.emerg(format_args!("empty condition")));
    }

    let first = if cur == 1 { &first_token } else { &args[cur] };

    // Check if first token is a variable
    if first.len() > 1 && first[0] == b'$' {
        // Variable condition: $var [ operator value ]
        let var_name = &first[1..];
        let index = get_variable_index(cf, var_name)?;
        codes.push(ScriptCode::Var { index });

        if cur == last {
            // Just test variable truthiness
        } else if cur + 2 == last {
            // Variable with operator and value
            let op = &args[cur + 1];
            let val = if cur + 1 == last { &last_token } else { &args[last] };

            if op == b"=" {
                codes.push(ScriptCode::Value { data: val.clone() });
                codes.push(ScriptCode::Equal);
            } else if op == b"!=" {
                codes.push(ScriptCode::Value { data: val.clone() });
                codes.push(ScriptCode::NotEqual);
            } else if op == b"~" {
                let regex = regex_compile(cf, val, 0)?;
                codes.push(ScriptCode::RegexStart {
                    regex,
                    add_args: false,
                    redirect: false,
                    redirect_status: 0,
                    break_cycle: false,
                });
            } else if op == b"~*" {
                let regex = regex_compile(cf, val, NGX_REGEX_CASELESS)?;
                codes.push(ScriptCode::RegexStart {
                    regex,
                    add_args: false,
                    redirect: false,
                    redirect_status: 0,
                    break_cycle: false,
                });
            } else if op == b"!~" {
                let regex = regex_compile(cf, val, 0)?;
                codes.push(ScriptCode::RegexStart {
                    regex,
                    add_args: false,
                    redirect: false,
                    redirect_status: 0,
                    break_cycle: false,
                });
            } else if op == b"!~*" {
                let regex = regex_compile(cf, val, NGX_REGEX_CASELESS)?;
                codes.push(ScriptCode::RegexStart {
                    regex,
                    add_args: false,
                    redirect: false,
                    redirect_status: 0,
                    break_cycle: false,
                });
            } else {
                return Err(cf.emerg(format_args!("unexpected \"{}\" in condition", B(op))));
            }
        } else {
            return Err(cf.emerg(format_args!("invalid condition \"{}\"", B(first))));
        }
    } else if first == b"-f" && cur + 1 == last {
        let path = if cur == last { &last_token } else { &args[last] };
        let cv = compile_complex_value(cf, path, 0)?;
        codes.push(ScriptCode::ComplexValue { value: cv });
        codes.push(ScriptCode::File { op: FILE_PLAIN });
    } else if first == b"!-f" && cur + 1 == last {
        let path = if cur == last { &last_token } else { &args[last] };
        let cv = compile_complex_value(cf, path, 0)?;
        codes.push(ScriptCode::ComplexValue { value: cv });
        codes.push(ScriptCode::File { op: FILE_NOT_PLAIN });
    } else if first == b"-d" && cur + 1 == last {
        let path = if cur == last { &last_token } else { &args[last] };
        let cv = compile_complex_value(cf, path, 0)?;
        codes.push(ScriptCode::ComplexValue { value: cv });
        codes.push(ScriptCode::File { op: FILE_DIR });
    } else if first == b"!-d" && cur + 1 == last {
        let path = if cur == last { &last_token } else { &args[last] };
        let cv = compile_complex_value(cf, path, 0)?;
        codes.push(ScriptCode::ComplexValue { value: cv });
        codes.push(ScriptCode::File { op: FILE_NOT_DIR });
    } else if first == b"-e" && cur + 1 == last {
        let path = if cur == last { &last_token } else { &args[last] };
        let cv = compile_complex_value(cf, path, 0)?;
        codes.push(ScriptCode::ComplexValue { value: cv });
        codes.push(ScriptCode::File { op: FILE_EXISTS });
    } else if first == b"!-e" && cur + 1 == last {
        let path = if cur == last { &last_token } else { &args[last] };
        let cv = compile_complex_value(cf, path, 0)?;
        codes.push(ScriptCode::ComplexValue { value: cv });
        codes.push(ScriptCode::File { op: FILE_NOT_EXISTS });
    } else if first == b"-x" && cur + 1 == last {
        let path = if cur == last { &last_token } else { &args[last] };
        let cv = compile_complex_value(cf, path, 0)?;
        codes.push(ScriptCode::ComplexValue { value: cv });
        codes.push(ScriptCode::File { op: FILE_EXEC });
    } else if first == b"!-x" && cur + 1 == last {
        let path = if cur == last { &last_token } else { &args[last] };
        let cv = compile_complex_value(cf, path, 0)?;
        codes.push(ScriptCode::ComplexValue { value: cv });
        codes.push(ScriptCode::File { op: FILE_NOT_EXEC });
    } else {
        return Err(cf.emerg(format_args!("invalid condition")));
    }

    // Add the If code which will test the condition result
    codes.push(ScriptCode::If);

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
        ngx_core::cmd_fn!("rewrite", F | NGX_CONF_TAKE23, ConfLevel::Loc, rewrite_directive),
        ngx_core::cmd_fn!("return", F | NGX_CONF_TAKE12, ConfLevel::Loc, return_directive),
        ngx_core::cmd_fn!("break", F | NGX_CONF_NOARGS, ConfLevel::Loc, break_directive),
        ngx_core::cmd_fn!("if", NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_BLOCK | NGX_CONF_1MORE, ConfLevel::Loc, if_block),
        ngx_core::cmd_fn!("set", F | NGX_CONF_TAKE2, ConfLevel::Loc, set_directive),
        ngx_core::cmd!("rewrite_log", NGX_HTTP_MAIN_CONF | F | NGX_CONF_FLAG, ConfLevel::Loc, RewriteConf, log, set_flag),
        ngx_core::cmd!("uninitialized_variable_warn", NGX_HTTP_MAIN_CONF | F | NGX_CONF_FLAG, ConfLevel::Loc, RewriteConf, uninitialized_variable_warn, set_flag),
    ];
    http_module_def("ngx_http_rewrite_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_SERVER_REWRITE_PHASE, Rc::new(|r| Box::pin(rewrite_handler(r))));
    add_phase_handler(cf, NGX_HTTP_REWRITE_PHASE, Rc::new(|r| Box::pin(rewrite_handler(r))));
    Ok(())
}

async fn rewrite_handler(r: R) -> i64 {
    let conf = r.loc_conf::<RewriteConf>(ctx_index());
    let codes = conf.borrow().codes.clone();

    execute_script(&r, &codes).await
}

/// Script interpreter engine
async fn execute_script(r: &R, codes: &[ScriptCode]) -> i64 {
    let mut ip = 0;
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let conf = r.loc_conf::<RewriteConf>(ctx_index());
    let log_rewrite = conf.borrow().log.get();
    let uninitialized_warn = conf.borrow().uninitialized_variable_warn.get();

    while ip < codes.len() {
        match &codes[ip] {
            ScriptCode::RegexStart {
                regex,
                add_args,
                redirect,
                redirect_status,
                break_cycle,
            } => {
                let uri = r.uri.borrow().clone();
                let rc = regex_exec(r, regex, &uri);

                if rc == NGX_OK {
                    if log_rewrite {
                        ngx_log_error!(
                            NGX_LOG_NOTICE,
                            r.connection.log,
                            None,
                            "\"{}\" matches \"{}\"",
                            B(&regex.regex_text),
                            B(&uri)
                        );
                    }

                    if !*break_cycle {
                        r.uri_changed.set(true);
                    } else {
                        r.valid_location.set(false);
                        r.uri_changed.set(false);
                    }
                } else if rc == NGX_DECLINED {
                    if log_rewrite {
                        ngx_log_error!(
                            NGX_LOG_NOTICE,
                            r.connection.log,
                            None,
                            "\"{}\" does not match \"{}\"",
                            B(&regex.regex_text),
                            B(&uri)
                        );
                    }
                    while ip < codes.len() {
                        if matches!(codes[ip], ScriptCode::RegexEnd { .. }) {
                            break;
                        }
                        ip += 1;
                    }
                    if ip < codes.len() {
                        ip += 1;
                    }
                    continue;
                } else {
                    return NGX_ERROR;
                }

                ip += 1;
            }

            ScriptCode::RegexEnd { add_args, redirect } => {
                let mut new_uri = stack.join(&b""[..]);
                let mut new_args = Vec::new();

                if *add_args && !r.args.is_empty() {
                    new_args.push(b'&');
                    new_args.extend_from_slice(&r.args);
                }

                if *redirect {
                    if log_rewrite {
                        ngx_log_error!(NGX_LOG_NOTICE, r.connection.log, None, "rewritten redirect: \"{}\"", B(&new_uri));
                    }

                    let status = codes[..ip]
                        .iter()
                        .rev()
                        .find_map(|c| {
                            if let ScriptCode::RegexStart {
                                redirect_status, ..
                            } = c
                            {
                                Some(*redirect_status)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(NGX_HTTP_MOVED_TEMPORARILY);

                    let cv = ComplexValue::constant(&new_uri);
                    let rc = send_response(r, status, None, &cv).await;
                    return if rc == NGX_OK || rc == NGX_DONE { NGX_DONE } else { rc };
                } else {
                    if new_uri.is_empty() {
                        ngx_log_error!(
                            NGX_LOG_ERR,
                            r.connection.log,
                            None,
                            "the rewritten URI has a zero length"
                        );
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    *r.uri.borrow_mut() = new_uri;
                    r.args.clone_from_slice(&new_args);

                    if log_rewrite {
                        ngx_log_error!(
                            NGX_LOG_NOTICE,
                            r.connection.log,
                            None,
                            "rewritten data: \"{}\", args: \"{}\"",
                            B(&r.uri.borrow()),
                            B(&r.args)
                        );
                    }
                }

                stack.clear();
                ip += 1;
            }

            ScriptCode::Return { status, text } => {
                let status = *status;
                if status == NGX_HTTP_MOVED_PERMANENTLY
                    || status == NGX_HTTP_MOVED_TEMPORARILY
                    || status == NGX_HTTP_SEE_OTHER
                    || status == NGX_HTTP_TEMPORARY_REDIRECT
                    || status == NGX_HTTP_PERMANENT_REDIRECT
                    || text.is_some()
                {
                    let cv = text.clone().unwrap_or_else(|| ComplexValue::constant(b""));
                    let ct: Option<&[u8]> = if text.is_some() && status < 300 {
                        Some(b"text/plain")
                    } else {
                        None
                    };
                    let rc = send_response(r, status, ct, &cv).await;
                    return if rc == NGX_OK || rc == NGX_DONE { NGX_DONE } else { rc };
                }
                return status;
            }

            ScriptCode::Break => {
                if r.uri_changed.get() {
                    r.valid_location.set(false);
                    r.uri_changed.set(false);
                }
                return NGX_DECLINED;
            }

            ScriptCode::If => {
                if let Some(val) = stack.pop() {
                    let is_true = !val.is_empty() && !(val.len() == 1 && val[0] == b'0');
                    if is_true {
                        ip += 1;
                    } else {
                        // Skip to end of if block
                        let mut depth = 1;
                        while ip < codes.len() && depth > 0 {
                            ip += 1;
                            match &codes[ip] {
                                ScriptCode::If => depth += 1,
                                ScriptCode::Nop => depth -= 1,
                                _ => {}
                            }
                        }
                        ip += 1;
                    }
                } else {
                    ip += 1;
                }
                continue;
            }

            ScriptCode::Value { data } => {
                stack.push(data.clone());
                ip += 1;
            }

            ScriptCode::Var { index } => {
                if let Some(v) = get_indexed_variable(r, *index) {
                    stack.push(v.data);
                } else if uninitialized_warn {
                    ngx_log_error!(NGX_LOG_WARN, r.connection.log, None, "using uninitialized variable");
                }
                ip += 1;
            }

            ScriptCode::Capture { n } => {
                let caps = r.captures.borrow();
                let data = r.captures_data.borrow();
                if *n + 1 < caps.len() {
                    let s = caps[*n] as usize;
                    let e = caps[*n + 1] as usize;
                    if s <= e && e <= data.len() {
                        stack.push(data[s..e].to_vec());
                    }
                }
                ip += 1;
            }

            ScriptCode::SetVar { index } => {
                if let Some(val) = stack.pop() {
                    set_indexed_variable(r, *index, val);
                }
                ip += 1;
            }

            ScriptCode::ComplexValue { value } => {
                match complex_value(r, value) {
                    Ok(v) => stack.push(v),
                    Err(_) => return NGX_ERROR,
                }
                ip += 1;
            }

            ScriptCode::Equal => {
                if let (Some(cmp), Some(val)) = (stack.pop(), stack.pop()) {
                    if val == cmp {
                        stack.push(b"1".to_vec());
                    } else {
                        stack.push(Vec::new());
                    }
                }
                ip += 1;
            }

            ScriptCode::NotEqual => {
                if let (Some(cmp), Some(val)) = (stack.pop(), stack.pop()) {
                    if val != cmp {
                        stack.push(b"1".to_vec());
                    } else {
                        stack.push(Vec::new());
                    }
                }
                ip += 1;
            }

            ScriptCode::File { op } => {
                if let Some(path) = stack.pop() {
                    let result = test_file(r, &path, *op).await;
                    if result {
                        stack.push(b"1".to_vec());
                    } else {
                        stack.push(Vec::new());
                    }
                }
                ip += 1;
            }

            ScriptCode::Nop => {
                ip += 1;
            }
        }
    }

    NGX_DECLINED
}

async fn test_file(r: &R, path: &[u8], op: u32) -> bool {
    // Map path using URI -> path conversion
    let path_buf = if path.is_empty() {
        return false;
    } else {
        String::from_utf8_lossy(path).into_owned()
    };

    // Get file stat using open_cached_file semantics
    use ngx_core::os::FileInfo;
    match std::fs::metadata(&path_buf) {
        Ok(metadata) => {
            let is_file = metadata.is_file();
            let is_dir = metadata.is_dir();
            let is_symlink = metadata.is_symlink();
            #[cfg(unix)]
            let is_exec = {
                use std::os::unix::fs::PermissionsExt;
                let perms = metadata.permissions();
                (perms.mode() & 0o111) != 0
            };
            #[cfg(not(unix))]
            let is_exec = false;

            match op {
                FILE_PLAIN => is_file,
                FILE_NOT_PLAIN => !is_file,
                FILE_DIR => is_dir,
                FILE_NOT_DIR => !is_dir,
                FILE_EXISTS => is_file || is_dir || is_symlink,
                FILE_NOT_EXISTS => !(is_file || is_dir || is_symlink),
                FILE_EXEC => is_exec || is_dir,
                FILE_NOT_EXEC => !(is_exec || is_dir),
                _ => false,
            }
        }
        Err(_) => {
            // File doesn't exist
            match op {
                FILE_PLAIN | FILE_DIR | FILE_EXISTS | FILE_EXEC => false,
                FILE_NOT_PLAIN | FILE_NOT_DIR | FILE_NOT_EXISTS | FILE_NOT_EXEC => true,
                _ => false,
            }
        }
    }
}
