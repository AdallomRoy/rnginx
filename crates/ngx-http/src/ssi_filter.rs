//! ngx_http_ssi_filter_module: Server-Side Includes

use std::any::Any;
use std::collections::HashMap;
use std::rc::Rc;
use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::times;
use ngx_core::{cmd_fn, ngx_log_error};
use crate::request::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_ssi_filter_module");

const SSI_ERROR_MSG: &[u8] = b"[an error occurred while processing the directive]";
const SSI_NONE: &[u8] = b"(none)";

pub struct SsiMainConf;
pub struct SsiLocConf {
    pub enable: Val<bool>,
    pub silent_errors: Val<bool>,
    pub ignore_recycled_buffers: Val<bool>,
    pub last_modified: Val<bool>,
    pub types_keys: Val<Vec<u8>>,
    pub min_file_chunk: Val<usize>,
    pub value_len: Val<usize>,
}

impl Default for SsiLocConf {
    fn default() -> Self {
        SsiLocConf {
            enable: Val::unset(),
            silent_errors: Val::unset(),
            ignore_recycled_buffers: Val::unset(),
            last_modified: Val::unset(),
            types_keys: Val::unset(),
            min_file_chunk: Val::unset(),
            value_len: Val::unset(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SsiState {
    Start,Tag,Comment0,Comment1,Sharp,PreCommand,Command,PreParam,Param,PreEqual,
    PreValue,DblQuotedVal,QuotedVal,QuotedSymbol,PostParam,CommentEnd0,CommentEnd1,
    Error,ErrorEnd0,ErrorEnd1,
}

pub struct SsiCtx {
    pub buf: Option<Buf>,
    pub pos: usize,
    pub copy_start: usize,
    pub copy_end: usize,
    pub key: u32,
    pub command: Vec<u8>,
    pub params: HashMap<Vec<u8>, Vec<u8>>,
    pub param_name: Vec<u8>,
    pub param_value: Vec<u8>,
    pub state: SsiState,
    pub saved: usize,
    pub looked: usize,
    pub variables: HashMap<Vec<u8>, Vec<u8>>,
    pub timefmt: Vec<u8>,
    pub errmsg: Vec<u8>,
}

impl Default for SsiCtx {
    fn default() -> Self {
        SsiCtx {
            buf: None,pos:0,copy_start:0,copy_end:0,key:0,
            command: Vec::new(),
            params: HashMap::new(),
            param_name: Vec::new(),
            param_value: Vec::new(),
            state: SsiState::Start,
            saved:0,looked:0,
            variables: HashMap::new(),
            timefmt: b"%A, %d-%b-%Y %H:%M:%S %Z".to_vec(),
            errmsg: SSI_ERROR_MSG.to_vec(),
        }
    }
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> { make_slot(SsiMainConf) }
fn init_main_conf(_cf: &mut Conf, _conf: &Rc<dyn Any>) -> ConfResult { Ok(()) }
fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> { make_slot(SsiLocConf::default()) }
fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<SsiLocConf>(prev).borrow();
    let mut c = conf_cell::<SsiLocConf>(conf).borrow_mut();
    c.enable.merge(&p.enable, false);
    c.silent_errors.merge(&p.silent_errors, false);
    c.ignore_recycled_buffers.merge(&p.ignore_recycled_buffers, false);
    c.last_modified.merge(&p.last_modified, false);
    c.types_keys.merge(&p.types_keys, Vec::new());
    c.min_file_chunk.merge(&p.min_file_chunk, 1024);
    c.value_len.merge(&p.value_len, 256);
    Ok(())
}

pub fn ssi_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        postconfiguration: Some(postconfiguration),
        create_main_conf: Some(create_main_conf),
        init_main_conf: Some(init_main_conf),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("ssi", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, ConfLevel::Loc, ssi_enable),
        cmd_fn!("ssi_silent_errors", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, ssi_silent_errors),
        cmd_fn!("ssi_ignore_recycled_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, ssi_ignore_recycled_buffers),
        cmd_fn!("ssi_min_file_chunk", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, ssi_min_file_chunk),
        cmd_fn!("ssi_value_length", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, ssi_value_length),
        cmd_fn!("ssi_types", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, ssi_types),
        cmd_fn!("ssi_last_modified", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, ssi_last_modified),
    ];
    http_module_def("ngx_http_ssi_filter_module", def, commands)
}

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    add_variables(cf, &SSI_VARIABLES)?;
    Ok(())
}

fn postconfiguration(_cf: &mut Conf) -> ConfResult {
    install_header_filter(|r, next| async move { ssi_header_filter(r, next).await });
    install_body_filter(|r, chain, next| async move { ssi_body_filter(r, chain, next).await });
    Ok(())
}

fn ssi_enable(cf: &mut Conf, _: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    conf_rc::<SsiLocConf>(conf.as_ref().unwrap()).borrow_mut().enable = Val::set(cf.args.get(1).map(|a| *a == b"on").unwrap_or(false));
    Ok(())
}
fn ssi_silent_errors(cf: &mut Conf, _: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    conf_rc::<SsiLocConf>(conf.as_ref().unwrap()).borrow_mut().silent_errors = Val::set(cf.args.get(1).map(|a| *a == b"on").unwrap_or(false));
    Ok(())
}
fn ssi_ignore_recycled_buffers(cf: &mut Conf, _: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    conf_rc::<SsiLocConf>(conf.as_ref().unwrap()).borrow_mut().ignore_recycled_buffers = Val::set(cf.args.get(1).map(|a| *a == b"on").unwrap_or(false));
    Ok(())
}
fn ssi_min_file_chunk(cf: &mut Conf, _: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if let Some(arg) = cf.args.get(1) {
        if let Ok(val) = std::str::from_utf8(arg) { if let Ok(n) = val.parse() { conf_rc::<SsiLocConf>(conf.as_ref().unwrap()).borrow_mut().min_file_chunk = Val::set(n); return Ok(()); } }
    }
    Err(msg("invalid size"))
}
fn ssi_value_length(cf: &mut Conf, _: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if let Some(arg) = cf.args.get(1) {
        if let Ok(val) = std::str::from_utf8(arg) { if let Ok(n) = val.parse() { conf_rc::<SsiLocConf>(conf.as_ref().unwrap()).borrow_mut().value_len = Val::set(n); return Ok(()); } }
    }
    Err(msg("invalid size"))
}
fn ssi_types(cf: &mut Conf, _: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    conf_rc::<SsiLocConf>(conf.as_ref().unwrap()).borrow_mut().types_keys = Val::set(cf.args[1..].join(&b' '));
    Ok(())
}
fn ssi_last_modified(cf: &mut Conf, _: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    conf_rc::<SsiLocConf>(conf.as_ref().unwrap()).borrow_mut().last_modified = Val::set(cf.args.get(1).map(|a| *a == b"on").unwrap_or(false));
    Ok(())
}

fn var_date_gmt(_r: &R, v: &mut VariableValue, _: usize) -> i64 {
    v.data = times::http_time(times::time()).into_bytes();
    v.not_found = false;
    NGX_OK
}
fn var_date_local(_r: &R, v: &mut VariableValue, _: usize) -> i64 {
    v.data = times::http_time(times::time()).into_bytes();
    v.not_found = false;
    NGX_OK
}

pub static SSI_VARIABLES: &[VarDef] = &[
    VarDef { name: "date_gmt", set: None, get: Some(var_date_gmt), data: 1, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "date_local", set: None, get: Some(var_date_local), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
];

async fn ssi_header_filter(r: R, next: HeaderFilter) -> i64 {
    let clcf = r.loc_conf::<SsiLocConf>(ctx_index());
    if !*clcf.borrow().enable {
        return next(r).await;
    }
    let _ctx = r.set_ctx(ctx_index(), SsiCtx::default());
    r.headers_out.borrow_mut().content_length_n = -1;
    r.filter_need_in_memory.set(true);
    next(r).await
}

async fn ssi_body_filter(r: R, mut input: Chain, next: BodyFilter) -> i64 {
    let clcf = r.loc_conf::<SsiLocConf>(ctx_index());
    if !*clcf.borrow().enable {
        return next(r, input).await;
    }

    let ctx_rc = match r.get_ctx::<SsiCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => r.set_ctx(ctx_index(), SsiCtx::default()),
    };

    let mut output = Chain::new();
    while let Some(buf) = input.pop_front() {
        let data = match &buf.data {
            BufData::Memory(v) => v.clone(),
            _ => {
                output.push_back(buf);
                continue;
            }
        };

        let processed = process_ssi(&data, &mut ctx_rc.borrow_mut(), &r);
        if !processed.is_empty() {
            output.push_back(Buf::from_vec(processed));
        }
    }

    next(r, output).await
}

fn process_ssi(data: &[u8], ctx: &mut SsiCtx, r: &R) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut tag_start = 0;

    while i < data.len() {
        match ctx.state {
            SsiState::Start => {
                if data[i] == b'<' {
                    tag_start = i;
                    ctx.looked = 1;
                    ctx.state = SsiState::Tag;
                } else {
                    out.push(data[i]);
                }
                i += 1;
            }
            SsiState::Tag => {
                if data[i] == b'!' {
                    ctx.looked = 2;
                    ctx.state = SsiState::Comment0;
                } else if data[i] == b'<' {
                    out.extend_from_slice(&data[tag_start..i]);
                    tag_start = i;
                } else {
                    out.extend_from_slice(&data[tag_start..=i]);
                    ctx.state = SsiState::Start;
                }
                i += 1;
            }
            SsiState::Comment0 => {
                if data[i] == b'-' {
                    ctx.looked = 3;
                    ctx.state = SsiState::Comment1;
                } else if data[i] == b'<' {
                    out.extend_from_slice(&data[tag_start..i]);
                    tag_start = i;
                    ctx.state = SsiState::Tag;
                } else {
                    out.extend_from_slice(&data[tag_start..=i]);
                    ctx.state = SsiState::Start;
                }
                i += 1;
            }
            SsiState::Comment1 => {
                if data[i] == b'-' {
                    ctx.looked = 4;
                    ctx.state = SsiState::Sharp;
                } else if data[i] == b'<' {
                    out.extend_from_slice(&data[tag_start..i]);
                    tag_start = i;
                    ctx.state = SsiState::Tag;
                } else {
                    out.extend_from_slice(&data[tag_start..=i]);
                    ctx.state = SsiState::Start;
                }
                i += 1;
            }
            SsiState::Sharp => {
                if data[i] == b'#' {
                    ctx.command.clear();
                    ctx.params.clear();
                    ctx.param_name.clear();
                    ctx.param_value.clear();
                    ctx.state = SsiState::PreCommand;
                } else if data[i] == b'<' {
                    out.extend_from_slice(&data[tag_start..i]);
                    tag_start = i;
                    ctx.state = SsiState::Tag;
                } else {
                    out.extend_from_slice(&data[tag_start..=i]);
                    ctx.state = SsiState::Start;
                }
                i += 1;
            }
            SsiState::PreCommand => {
                if data[i] != b' ' && data[i] != b'\t' {
                    ctx.state = SsiState::Command;
                } else {
                    i += 1;
                }
            }
            SsiState::Command => {
                if data[i] >= 32 && data[i] < 127 && data[i] != b' ' && data[i] != b'\t' && data[i] != b'-' && data[i] != b'"' && data[i] != b'\'' {
                    ctx.command.push(data[i]);
                    i += 1;
                } else {
                    ctx.state = SsiState::PreParam;
                }
            }
            SsiState::PreParam => {
                if data[i] == b' ' || data[i] == b'\t' {
                    i += 1;
                } else if data[i] == b'-' {
                    if i + 2 < data.len() && &data[i..i+3] == b"-->" {
                        let cmd = ctx.command.clone();
                        let params = ctx.params.clone();
                        let result = execute_directive(&cmd, &params, ctx, r);
                        out.extend_from_slice(&result);
                        ctx.state = SsiState::Start;
                        i += 3;
                    } else { ctx.state = SsiState::Error; i += 1; }
                } else if data[i] >= 32 && data[i] < 127 {
                    ctx.param_name.clear();
                    ctx.param_name.push(data[i]);
                    ctx.state = SsiState::Param;
                    i += 1;
                } else { ctx.state = SsiState::Error; i += 1; }
            }
            SsiState::Param => {
                if data[i] == b'=' {
                    ctx.state = SsiState::PreValue; i += 1;
                } else if data[i] == b' ' || data[i] == b'\t' {
                    ctx.state = SsiState::PreEqual; i += 1;
                } else if data[i] >= 32 && data[i] < 127 {
                    ctx.param_name.push(data[i]); i += 1;
                } else { ctx.state = SsiState::Error; i += 1; }
            }
            SsiState::PreEqual => {
                if data[i] == b'=' {
                    ctx.state = SsiState::PreValue; i += 1;
                } else if data[i] == b' ' || data[i] == b'\t' {
                    i += 1;
                } else { ctx.state = SsiState::Error; i += 1; }
            }
            SsiState::PreValue => {
                if data[i] == b'"' {
                    ctx.state = SsiState::DblQuotedVal; i += 1;
                } else if data[i] == b'\'' {
                    ctx.state = SsiState::QuotedVal; i += 1;
                } else if data[i] == b' ' || data[i] == b'\t' {
                    i += 1;
                } else { ctx.state = SsiState::Error; i += 1; }
            }
            SsiState::DblQuotedVal => {
                if data[i] == b'"' {
                    ctx.params.insert(ctx.param_name.clone(), ctx.param_value.clone());
                    ctx.param_name.clear();
                    ctx.param_value.clear();
                    ctx.state = SsiState::PostParam;
                    i += 1;
                } else {
                    ctx.param_value.push(data[i]); i += 1;
                }
            }
            SsiState::QuotedVal => {
                if data[i] == b'\'' {
                    ctx.params.insert(ctx.param_name.clone(), ctx.param_value.clone());
                    ctx.param_name.clear();
                    ctx.param_value.clear();
                    ctx.state = SsiState::PostParam;
                    i += 1;
                } else {
                    ctx.param_value.push(data[i]); i += 1;
                }
            }
            SsiState::QuotedSymbol => { i += 1; ctx.state = SsiState::QuotedVal; }
            SsiState::PostParam => {
                if data[i] == b' ' || data[i] == b'\t' {
                    i += 1;
                } else if data[i] == b'-' {
                    if i + 2 < data.len() && &data[i..i+3] == b"-->" {
                        let cmd = ctx.command.clone();
                        let params = ctx.params.clone();
                        let result = execute_directive(&cmd, &params, ctx, r);
                        out.extend_from_slice(&result);
                        ctx.state = SsiState::Start;
                        i += 3;
                    } else { ctx.state = SsiState::Error; i += 1; }
                } else {
                    ctx.state = SsiState::PreParam;
                }
            }
            _ => { i += 1; }
        }
    }

    out
}

fn ssi_get_variable(var_name: &[u8], ctx: &SsiCtx, r: &R) -> Option<Vec<u8>> {
    // Check stored variables first
    if let Some(val) = ctx.variables.get(var_name) {
        return Some(val.clone());
    }

    // Try to get from nginx variable system (handles arg_*, etc.)
    if let Some(vv) = get_variable(r, var_name) {
        if !vv.not_found {
            return Some(vv.data);
        }
    }

    None
}

fn ssi_encode(value: &[u8], encoding: Option<&[u8]>) -> Vec<u8> {
    match encoding {
        Some(b"url") => {
            let mut result = Vec::new();
            for &byte in value {
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        result.push(byte);
                    }
                    _ => {
                        result.extend_from_slice(format!("%{:02X}", byte).as_bytes());
                    }
                }
            }
            result
        }
        Some(b"entity") => {
            let mut result = Vec::new();
            for &byte in value {
                match byte {
                    b'&' => result.extend_from_slice(b"&amp;"),
                    b'<' => result.extend_from_slice(b"&lt;"),
                    b'>' => result.extend_from_slice(b"&gt;"),
                    b'"' => result.extend_from_slice(b"&quot;"),
                    b'\'' => result.extend_from_slice(b"&#39;"),
                    _ => result.push(byte),
                }
            }
            result
        }
        _ => value.to_vec(), // "none" or default
    }
}

fn execute_directive(cmd: &[u8], params: &HashMap<Vec<u8>, Vec<u8>>, ctx: &mut SsiCtx, r: &R) -> Vec<u8> {
    match cmd {
        b"echo" => {
            if let Some(var_name) = params.get(&b"var".to_vec()) {
                if let Some(val) = ssi_get_variable(var_name, ctx, r) {
                    let encoding = params.get(&b"encoding".to_vec()).map(|v| v.as_slice());
                    return ssi_encode(&val, encoding);
                }
                if let Some(def) = params.get(&b"default".to_vec()) {
                    return def.clone();
                }
            }
            SSI_NONE.to_vec()
        }
        b"set" => {
            if let Some(var) = params.get(&b"var".to_vec()) {
                if let Some(val) = params.get(&b"value".to_vec()) {
                    ctx.variables.insert(var.clone(), val.clone());
                }
            }
            Vec::new()
        }
        b"config" => {
            if let Some(fmt) = params.get(&b"timefmt".to_vec()) {
                ctx.timefmt = fmt.clone();
            }
            if let Some(err) = params.get(&b"errmsg".to_vec()) {
                ctx.errmsg = err.clone();
            }
            Vec::new()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {}
