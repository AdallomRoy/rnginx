//! ngx_http_log_module (access log): basic version with log_format and access_log.

use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_log_module");

#[derive(Clone)]
pub enum LogOp {
    Literal(Vec<u8>),
    Var(usize, u32),
}

#[derive(Clone)]
pub struct LogFormat {
    pub name: Vec<u8>,
    pub escape: u32,
    pub ops: Vec<LogOp>,
}

pub struct LogMainConf {
    pub formats: Vec<Rc<LogFormat>>,
    pub combined_used: bool,
}

#[derive(Clone)]
pub struct AccessLog {
    pub file: Option<Rc<OpenFile>>,
    pub path: Option<ComplexValue>,
    pub format: Rc<LogFormat>,
    pub filter: Option<ComplexValue>,
}

pub struct LogLocConf {
    pub logs: Option<Vec<AccessLog>>,
    pub off: bool,
}

pub const ESCAPE_DEFAULT: u32 = 0;
pub const ESCAPE_JSON: u32 = 1;
pub const ESCAPE_NONE: u32 = 2;

pub const COMBINED_FMT: &[u8] = b"$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LogMainConf { formats: Vec::new(), combined_used: false })
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(LogLocConf { logs: None, off: false })
}

fn merge_loc_conf(cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<LogLocConf>(prev).borrow();
    let mut c = conf_cell::<LogLocConf>(conf).borrow_mut();
    if c.logs.is_some() || c.off {
        return Ok(());
    }
    c.logs = p.logs.clone();
    c.off = p.off;
    if c.logs.is_some() || c.off {
        return Ok(());
    }
    drop(p);
    let lmcf = get_main_conf::<LogMainConf>(cf, ctx_index());
    let fmt = lmcf.borrow().formats.iter().find(|f| f.name == b"combined").cloned();
    let fmt = match fmt {
        Some(f) => f,
        None => {
            drop(c);
            let f = compile_format(cf, b"combined", ESCAPE_DEFAULT, COMBINED_FMT)?;
            let f = Rc::new(f);
            lmcf.borrow_mut().formats.push(f.clone());
            f
        }
    };
    let file = cf.cycle.open_file(ngx_core::NGX_HTTP_LOG_PATH.as_bytes());
    let mut c = conf_cell::<LogLocConf>(conf).borrow_mut();
    lmcf.borrow_mut().combined_used = true;
    c.logs = Some(vec![AccessLog { file: Some(file), path: None, format: fmt, filter: None }]);
    Ok(())
}

fn compile_format(cf: &mut Conf, name: &[u8], escape: u32, fmt: &[u8]) -> Result<LogFormat, ConfError> {
    let mut ops = Vec::new();
    let mut lit = Vec::new();
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] == b'$' {
            if !lit.is_empty() {
                ops.push(LogOp::Literal(std::mem::take(&mut lit)));
            }
            let mut j = i + 1;
            let vname: Vec<u8>;
            if j < fmt.len() && fmt[j] == b'{' {
                let end = match memchr::memchr(b'}', &fmt[j..]) {
                    Some(e) => j + e,
                    None => return Err(cf.emerg(format_args!("the closing bracket in \"{}\" variable is missing", B(&fmt[j + 1..])))),
                };
                vname = fmt[j + 1..end].to_vec();
                j = end + 1;
            } else {
                let start = j;
                while j < fmt.len() && (fmt[j].is_ascii_alphanumeric() || fmt[j] == b'_') {
                    j += 1;
                }
                vname = fmt[start..j].to_vec();
            }
            if vname.is_empty() {
                return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&fmt[i..]))));
            }
            let idx = get_variable_index(cf, &vname)?;
            ops.push(LogOp::Var(idx, escape));
            i = j;
            continue;
        }
        lit.push(fmt[i]);
        i += 1;
    }
    if !lit.is_empty() {
        ops.push(LogOp::Literal(lit));
    }
    Ok(LogFormat { name: name.to_vec(), escape, ops })
}

fn log_format_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let lmcf = conf_rc::<LogMainConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let name = args[1].clone();
    if name == b"combined" {
        lmcf.borrow_mut().combined_used = true;
    }
    if lmcf.borrow().formats.iter().any(|f| f.name == name) {
        return Err(cf.emerg(format_args!("duplicate \"log_format\" name \"{}\"", B(&name))));
    }
    let mut escape = ESCAPE_DEFAULT;
    let mut start = 2;
    if args.len() > 2 {
        if let Some(e) = args[2].strip_prefix(b"escape=") {
            escape = match e {
                b"json" => ESCAPE_JSON,
                b"none" => ESCAPE_NONE,
                b"default" => ESCAPE_DEFAULT,
                _ => return Err(cf.emerg(format_args!("unknown log format escaping \"{}\"", B(e)))),
            };
            start = 3;
        }
    }
    let mut fmt: Vec<u8> = Vec::new();
    for a in &args[start..] {
        fmt.extend_from_slice(a);
    }
    let f = compile_format(cf, &name, escape, &fmt)?;
    lmcf.borrow_mut().formats.push(Rc::new(f));
    Ok(())
}

fn access_log_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<LogLocConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    if args[1] == b"off" {
        let mut c = cell.borrow_mut();
        c.off = true;
        if args.len() == 2 {
            return Ok(());
        }
        drop(c);
        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(&args[2]))));
    }
    let lmcf = get_main_conf::<LogMainConf>(cf, ctx_index());
    let n = script_variables_count(&args[1]);
    let (file, path) = if n == 0 {
        (Some(cf.cycle.open_file(&args[1].clone())), None)
    } else {
        let cv = compile_complex_value(cf, &args[1].clone(), NGX_HTTP_COMPLEX_VALUE_CONF_PREFIX)?;
        (None, Some(cv))
    };
    let fmt_name: Vec<u8> = if args.len() >= 3 { args[2].clone() } else { b"combined".to_vec() };
    if fmt_name == b"combined" {
        lmcf.borrow_mut().combined_used = true;
    }
    let fmt = lmcf.borrow().formats.iter().find(|f| f.name == fmt_name).cloned();
    let fmt = match fmt {
        Some(f) => f,
        None => {
            if fmt_name == b"combined" {
                let f = Rc::new(compile_format(cf, b"combined", ESCAPE_DEFAULT, COMBINED_FMT)?);
                lmcf.borrow_mut().formats.push(f.clone());
                f
            } else {
                return Err(cf.emerg(format_args!("unknown log format \"{}\"", B(&fmt_name))));
            }
        }
    };
    let mut filter = None;
    for a in args.iter().skip(3) {
        if let Some(v) = a.strip_prefix(b"if=") {
            filter = Some(compile_complex_value(cf, v, 0)?);
            continue;
        }
        if a.starts_with(b"buffer=") || a.starts_with(b"flush=") || a.starts_with(b"gzip") {
            continue;
        }
        return Err(cf.emerg(format_args!("invalid parameter \"{}\"", B(a))));
    }
    let mut c = cell.borrow_mut();
    c.logs.get_or_insert_with(Vec::new).push(AccessLog { file, path, format: fmt, filter });
    Ok(())
}

pub fn log_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_main_conf: Some(create_main_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("log_format", NGX_HTTP_MAIN_CONF | NGX_CONF_2MORE, ConfLevel::Main, log_format_directive),
        ngx_core::cmd_fn!("access_log", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_1MORE, ConfLevel::Loc, access_log_directive),
        ngx_core::cmd_fn!("open_log_file_cache", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
    ];
    http_module_def("ngx_http_log_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_log_handler(cf, Rc::new(|r| log_handler(r)));
    Ok(())
}

fn escape_default(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len());
    for &c in v {
        if c == b'"' || c == b'\\' || c < 0x20 || c >= 0x7f {
            out.extend_from_slice(format!("\\x{:02X}", c).as_bytes());
        } else {
            out.push(c);
        }
    }
    out
}

fn log_handler(r: &R) -> i64 {
    http_debug!(r, "http log handler");
    let conf = r.loc_conf::<LogLocConf>(ctx_index());
    let logs = match &conf.borrow().logs {
        Some(l) if !conf.borrow().off => l.clone(),
        _ => return NGX_OK,
    };
    for log in logs.iter() {
        if let Some(f) = &log.filter {
            match complex_value(r, f) {
                Ok(v) => {
                    if v.is_empty() || (v.len() == 1 && v[0] == b'0') {
                        continue;
                    }
                }
                Err(_) => return NGX_ERROR,
            }
        }
        let mut line = Vec::with_capacity(256);
        for op in log.format.ops.iter() {
            match op {
                LogOp::Literal(l) => line.extend_from_slice(l),
                LogOp::Var(idx, escape) => {
                    let v = get_indexed_variable(r, *idx);
                    match v {
                        Some(v) if !v.not_found => match *escape {
                            ESCAPE_JSON => line.extend_from_slice(&ngx_core::string::escape_json(&v.data)),
                            ESCAPE_NONE => line.extend_from_slice(&v.data),
                            _ => line.extend_from_slice(&escape_default(&v.data)),
                        },
                        _ => {
                            // Only default-escape emits the '-' placeholder for
                            // missing / empty variables; json and none leave
                            // the slot empty (matches ngx_http_log_escape).
                            if *escape != ESCAPE_JSON && *escape != ESCAPE_NONE {
                                line.push(b'-');
                            }
                        }
                    }
                }
            }
        }
        line.push(b'\n');
        match (&log.file, &log.path) {
            (Some(f), _) => {
                if let Err(e) = f.write_all(&line) {
                    ngx_log_error!(NGX_LOG_ALERT, r.connection.log, Some(e), "write() to \"{}\" failed", B(&f.name));
                }
            }
            (None, Some(cv)) => {
                let path = match complex_value(r, cv) {
                    Ok(p) => p,
                    Err(_) => return NGX_ERROR,
                };
                if path.is_empty() {
                    continue;
                }
                let fd = ngx_core::log::open_log_file(&path);
                if fd < 0 {
                    ngx_log_error!(NGX_LOG_CRIT, r.connection.log, Some(ngx_core::os::errno()), "open() \"{}\" failed", B(&path));
                    continue;
                }
                let _ = ngx_core::os::write_fd(fd, &line);
                ngx_core::os::close(fd);
            }
            _ => {}
        }
    }
    NGX_OK
}

#[allow(dead_code)]
fn _unused(_: &RefCell<()>) {}
