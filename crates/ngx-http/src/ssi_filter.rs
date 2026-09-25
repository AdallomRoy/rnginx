//! ngx_http_ssi_filter_module: Server-Side Includes (SSI) processing

use std::any::Any;
use std::collections::HashMap;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::times;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::request::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_ssi_filter_module");

const SSI_ERROR_MSG: &[u8] = b"[an error occurred while processing the directive]";

// Configuration
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

// Parser state machine states
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SsiParseState {
    Start = 0,
    Tag = 1,
    Comment0 = 2,
    Comment1 = 3,
    Sharp = 4,
    PreCommand = 5,
    Command = 6,
    PreParam = 7,
    Param = 8,
    PreEqual = 9,
    PreValue = 10,
    DoubleQuotedValue = 11,
    QuotedValue = 12,
    QuotedSymbol = 13,
    PostParam = 14,
    CommentEnd0 = 15,
    CommentEnd1 = 16,
    Error = 17,
    ErrorEnd0 = 18,
    ErrorEnd1 = 19,
}

// Per-request SSI context
pub struct SsiCtx {
    pub buf: Option<Buf>,
    pub pos: usize,
    pub copy_start: Option<usize>,
    pub copy_end: usize,
    pub key: u32,
    pub command: Vec<u8>,
    pub params: Vec<(Vec<u8>, Vec<u8>)>,
    pub param_name: Vec<u8>,
    pub param_value: Vec<u8>,
    pub state: SsiParseState,
    pub saved_state: SsiParseState,
    pub saved: usize,
    pub looked: usize,
    pub value_len: usize,
    pub variables: HashMap<Vec<u8>, Vec<u8>>,
    pub timefmt: Vec<u8>,
    pub errmsg: Vec<u8>,
}

impl Default for SsiCtx {
    fn default() -> Self {
        SsiCtx {
            buf: None,
            pos: 0,
            copy_start: None,
            copy_end: 0,
            key: 0,
            command: Vec::new(),
            params: Vec::new(),
            param_name: Vec::new(),
            param_value: Vec::new(),
            state: SsiParseState::Start,
            saved_state: SsiParseState::Start,
            saved: 0,
            looked: 0,
            value_len: 256,
            variables: HashMap::new(),
            timefmt: b"%A, %d-%b-%Y %H:%M:%S %Z".to_vec(),
            errmsg: SSI_ERROR_MSG.to_vec(),
        }
    }
}

fn create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SsiMainConf)
}

fn init_main_conf(_cf: &mut Conf, _conf: &Rc<dyn Any>) -> ConfResult {
    Ok(())
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SsiLocConf::default())
}

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

// Directive handlers
fn ssi_enable(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = &cf.args;
    let cell = conf_rc::<SsiLocConf>(conf.as_ref().unwrap());
    if args.len() < 2 {
        return Err(msg("requires a value"));
    }
    cell.borrow_mut().enable = Val::set(args[1] == b"on");
    Ok(())
}

fn ssi_silent_errors(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = &cf.args;
    let cell = conf_rc::<SsiLocConf>(conf.as_ref().unwrap());
    if args.len() < 2 {
        return Err(msg("requires a value"));
    }
    cell.borrow_mut().silent_errors = Val::set(args[1] == b"on");
    Ok(())
}

fn ssi_ignore_recycled_buffers(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = &cf.args;
    let cell = conf_rc::<SsiLocConf>(conf.as_ref().unwrap());
    if args.len() < 2 {
        return Err(msg("requires a value"));
    }
    cell.borrow_mut().ignore_recycled_buffers = Val::set(args[1] == b"on");
    Ok(())
}

fn ssi_min_file_chunk(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = &cf.args;
    let cell = conf_rc::<SsiLocConf>(conf.as_ref().unwrap());
    if args.len() < 2 {
        return Err(msg("requires a value"));
    }
    let val = parse_size(&args[1])?;
    cell.borrow_mut().min_file_chunk = Val::set(val);
    Ok(())
}

fn ssi_value_length(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = &cf.args;
    let cell = conf_rc::<SsiLocConf>(conf.as_ref().unwrap());
    if args.len() < 2 {
        return Err(msg("requires a value"));
    }
    let val = parse_size(&args[1])?;
    cell.borrow_mut().value_len = Val::set(val);
    Ok(())
}

fn ssi_types(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<SsiLocConf>(conf.as_ref().unwrap());
    cell.borrow_mut().types_keys = Val::set(cf.args[1..].join(&b' '));
    Ok(())
}

fn ssi_last_modified(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let args = &cf.args;
    let cell = conf_rc::<SsiLocConf>(conf.as_ref().unwrap());
    if args.len() < 2 {
        return Err(msg("requires a value"));
    }
    cell.borrow_mut().last_modified = Val::set(args[1] == b"on");
    Ok(())
}

fn parse_size(s: &[u8]) -> Result<usize, ConfError> {
    use std::str;
    let s_str = str::from_utf8(s).map_err(|_| msg("invalid size"))?;
    s_str.parse::<usize>().map_err(|_| msg("invalid size"))
}

// Variables
fn var_date_gmt(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let ts = times::time();
    v.data = times::http_time(ts).into_bytes();
    v.not_found = false;
    NGX_OK
}

fn var_date_local(_r: &R, v: &mut VariableValue, _data: usize) -> i64 {
    let ts = times::time();
    v.data = times::http_time(ts).into_bytes();
    v.not_found = false;
    NGX_OK
}

pub static SSI_VARIABLES: &[VarDef] = &[
    VarDef {
        name: "date_gmt",
        set: None,
        get: Some(var_date_gmt),
        data: 1,
        flags: NGX_HTTP_VAR_NOCACHEABLE,
    },
    VarDef {
        name: "date_local",
        set: None,
        get: Some(var_date_local),
        data: 0,
        flags: NGX_HTTP_VAR_NOCACHEABLE,
    },
];

// Filters
async fn ssi_header_filter(r: R, next: HeaderFilter) -> i64 {
    let clcf = r.loc_conf::<SsiLocConf>(ctx_index());
    let clcf_borrow = clcf.borrow();

    if !*clcf_borrow.enable {
        drop(clcf_borrow);
        return next(r).await;
    }
    drop(clcf_borrow);

    let _ctx = r.set_ctx(ctx_index(), SsiCtx::default());

    {
        let mut headers = r.headers_out.borrow_mut();
        headers.content_length_n = -1;
    }

    r.filter_need_in_memory.set(true);

    next(r).await
}

async fn ssi_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let clcf = r.loc_conf::<SsiLocConf>(ctx_index());
    let clcf_borrow = clcf.borrow();

    if !*clcf_borrow.enable {
        drop(clcf_borrow);
        return next(r, input).await;
    }
    drop(clcf_borrow);

    // Get context
    let _ctx = match r.get_ctx::<SsiCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => {
            return next(r, input).await;
        }
    };

    // For now, pass through
    // Full implementation would parse and process SSI here
    next(r, input).await
}

#[cfg(test)]
mod tests {
    use super::*;
}
