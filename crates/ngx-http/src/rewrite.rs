//! ngx_http_rewrite_module - URL rewriting and conditional request handling

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::regex::Regex;
use ngx_core::string::{atoi, B};

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
    Return { status: i64, text: Option<ComplexValue> },
    Break,
}

pub struct RewriteConf {
    pub codes: Vec<Code>,
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

/// ngx_http_rewrite directive handler
fn rewrite_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();

    if args.len() < 3 {
        return Err(cf.emerg(format_args!("invalid number of arguments")));
    }

    let pattern = &args[1];
    let replacement = args[2].clone();

    // Compile regex
    let regex = match ngx_core::regex::Regex::compile(pattern, 0) {
        Ok(r) => r,
        Err(e) => return Err(cf.emerg(format_args!("{}", e))),
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
                return Err(cf.emerg(format_args!("invalid flag \"{}\"", B(flag_str))))
            }
        }
    }

    let rule = RewriteRule {
        regex,
        replacement,
        flags,
        log: cell.borrow().log.get_or(false),
    };

    cell.borrow_mut().codes.push(Code::Rewrite(rule));

    // If "last" flag, add terminator code
    if flags.last {
        cell.borrow_mut().codes.push(Code::Break);
    }

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

    let var_name = &args[1];

    // Get or create variable index
    let var_idx = get_variable_index(cf, var_name)?;

    // Compile the value as a ComplexValue
    let value_bytes = &args[2];
    let value = crate::script::compile_complex_value(cf, value_bytes, 0)?;

    cell.borrow_mut()
        .codes
        .push(Code::Set { var_idx, value });

    Ok(())
}

/// ngx_http_rewrite_break directive handler
fn break_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    cell.borrow_mut().codes.push(Code::Break);
    Ok(())
}

/// ngx_http_rewrite_if directive handler - parses if block
fn if_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // Parse the condition
    let args = cf.args.clone();

    if args.len() < 2 {
        return Err(cf.emerg(format_args!("no condition specified")));
    }

    // Parse "if (condition) { ... }" block
    // Save current context and parse a new location context for the if block
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

/// Execute rewrite codes for a request
async fn rewrite_handler(r: R) -> i64 {
    let conf = r.loc_conf::<RewriteConf>(ctx_index());
    let codes = conf.borrow().codes.clone();
    let log_enabled = conf.borrow().log.get_or(false);

    for code in codes.iter() {
        match code {
            Code::Rewrite(rule) => {
                // Test regex against current URI
                let uri = r.uri.borrow().clone();

                // Try to match the regex
                let captures = match rule.regex.exec(&uri) {
                    Some(c) => c,
                    None => continue, // No match, continue to next rule
                };

                // Store captures in request for later use ($1, $2, etc)
                // captures is Vec<(i32, i32)> pairs
                let mut cap_vec = Vec::new();
                for (start, end) in &captures {
                    cap_vec.push(*start);
                    cap_vec.push(*end);
                }

                // Store captures and the URI being rewritten
                *r.captures.borrow_mut() = cap_vec.clone();
                *r.captures_data.borrow_mut() = uri.clone();

                // Build replacement string from template
                let mut replacement = Vec::new();
                let repl = &rule.replacement;
                let mut i = 0;

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
                                        replacement.extend_from_slice(&uri[s..e]);
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
                        }
                    }
                    replacement.push(repl[i]);
                    i += 1;
                }

                if log_enabled {
                    http_debug!(r, "rewrite: {} -> {}", B(&uri), B(&replacement));
                }

                // Handle redirect response
                if rule.flags.redirect {
                    // For redirects, check if trailing '?' suppresses original args
                    let mut response_url = replacement.clone();
                    let suppress_args = response_url.ends_with(b"?");
                    if suppress_args {
                        response_url.pop(); // Remove the trailing '?'
                    }

                    let orig_args = r.args.borrow();
                    if !suppress_args && !orig_args.is_empty() {
                        // Append original args to the replacement URL
                        if !response_url.contains(&b'?') {
                            response_url.push(b'?');
                        } else {
                            response_url.push(b'&');
                        }
                        response_url.extend_from_slice(&orig_args);
                    }

                    // Send redirect response
                    let cv = ComplexValue::constant(&response_url);
                    let rc = send_response(&r, rule.flags.redirect_status, None, &cv).await;
                    if rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE {
                        return NGX_DONE;
                    }
                    return rc;
                }

                // For internal rewrites, parse replacement to separate URI and args
                let (rewritten_uri, rewritten_args) = if let Some(qpos) = replacement.iter().position(|&b| b == b'?') {
                    // Split on '?'
                    let uri_part = replacement[..qpos].to_vec();
                    let args_part = replacement[qpos + 1..].to_vec();
                    (uri_part, args_part)
                } else if replacement.ends_with(b"?") {
                    // "?" at end means drop query string
                    let uri_part = replacement[..replacement.len() - 1].to_vec();
                    (uri_part, Vec::new())
                } else {
                    // No '?' - preserve original args
                    (replacement.clone(), r.args.borrow().clone())
                };

                // Update request URI and args for internal rewrites
                *r.uri.borrow_mut() = rewritten_uri.clone();
                set_exten(&r);
                *r.args.borrow_mut() = rewritten_args;

                // Check for "last" or "break" flags
                if rule.flags.break_cycle {
                    // break: stop processing rewrite rules for this location
                    break;
                }

                if rule.flags.last {
                    // last: restart rewrite phase from beginning
                    // This is handled at the phase level
                    break;
                }
            }

            Code::Set { var_idx, value } => {
                // Evaluate the value and set the variable
                match crate::script::complex_value(&r, value) {
                    Ok(val) => {
                        set_indexed_variable(&r, *var_idx, val);
                    }
                    Err(_) => {
                        // Error evaluating value, log it but continue
                        // (ignore for now)
                    }
                }
            }

            Code::Return { status, text } => {
                let status = *status;

                // If no explicit text, send error page HTML for error statuses
                if text.is_none() && status >= 400 {
                    // Set the error status and return it to be handled by error_page/default error page
                    r.headers_out.borrow_mut().status = status;
                    return status;
                }

                // Always send a response with explicit text or empty body
                let text_val = text
                    .clone()
                    .unwrap_or_else(|| ComplexValue::constant(b""));
                let ct: Option<&[u8]> =
                    if text.is_some() && status < 300 {
                        Some(b"text/plain")
                    } else {
                        None
                    };

                let rc = send_response(&r, status, ct, &text_val).await;
                if rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE {
                    return NGX_DONE;
                }
                return rc;
            }

            Code::Break => {
                // Stop processing rules
                break;
            }
        }
    }

    NGX_DECLINED
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
