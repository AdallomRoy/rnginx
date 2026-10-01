//! ngx_http_ssi_filter_module: Server Side Includes.
//!
//! The subrequests of "include" are posted ones
//! (request_rt::subrequest_posted(), see crate::postpone_filter). Where C
//! returns NGX_AGAIN to wait for a subrequest (wait="yes", set=, file=) and
//! the body filter is called again once the request is posted, the filter
//! here waits for being posted and goes on (ssi_wait()).

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::buf::{Buf, BufData, Chain};
use ngx_core::conf::*;
use ngx_core::hash::{hash_key, Hash, HashInit, HashKey, HashKeysArrays, HashKind, NGX_HASH_READONLY_KEY};
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::{eq_ignore_case, B};
use ngx_core::times;
use ngx_core::{cmd, cmd_fn, ngx_log_error};

use crate::request::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_ssi_filter_module");

const NGX_HTTP_SSI_ERROR: i64 = 1;

const NGX_HTTP_SSI_DATE_LEN: usize = 2048;

const NGX_HTTP_SSI_ADD_PREFIX: u32 = 1;
/// the evaluated string is a regex; C needs it NUL terminated
const NGX_HTTP_SSI_ADD_ZERO: u32 = 2;

const NGX_HTTP_SSI_MAX_PARAMS: usize = 16;

const NGX_HTTP_SSI_COMMAND_LEN: usize = 32;
const NGX_HTTP_SSI_PARAM_LEN: usize = 32;

const NGX_HTTP_SSI_COND_IF: u32 = 1;
const NGX_HTTP_SSI_COND_ELSE: u32 = 2;

const NGX_HTTP_SSI_NO_ENCODING: u32 = 0;
const NGX_HTTP_SSI_URL_ENCODING: u32 = 1;
const NGX_HTTP_SSI_ENTITY_ENCODING: u32 = 2;

/// ngx_http_ssi_string
const NGX_HTTP_SSI_STRING: &[u8] = b"<!--";
/// ngx_http_ssi_none
const NGX_HTTP_SSI_NONE: &[u8] = b"(none)";
/// ngx_http_ssi_timefmt
const NGX_HTTP_SSI_TIMEFMT: &[u8] = b"%A, %d-%b-%Y %H:%M:%S %Z";
const NGX_HTTP_SSI_ERRMSG: &[u8] = b"[an error occurred while processing the directive]";

/// ngx_http_html_default_types
const NGX_HTTP_HTML_DEFAULT_TYPES: &[&[u8]] = &[b"text/html"];

// ---------------------------------------------------------------------------
// configuration

/// ngx_http_ssi_main_conf_t
pub struct SsiMainConf {
    /// the commands by name: an index into SSI_COMMANDS
    hash: Option<Hash<usize>>,
    commands: HashKeysArrays<usize>,
}

/// ssi_types as ngx_http_types_slot() collects it: `*` is (void *) -1
#[derive(Clone)]
enum TypesKeys {
    Any,
    List(Vec<Vec<u8>>),
}

/// ngx_http_ssi_loc_conf_t
pub struct SsiLocConf {
    pub enable: Val<bool>,
    pub silent_errors: Val<bool>,
    pub ignore_recycled_buffers: Val<bool>,
    pub last_modified: Val<bool>,
    /// the types hash, None standing for an empty one (any type)
    types: Option<Rc<Hash<Rc<Vec<u8>>>>>,
    pub min_file_chunk: Val<usize>,
    pub value_len: Val<usize>,
    types_keys: Option<TypesKeys>,
}

/// ngx_http_ssi_create_main_conf
fn ssi_create_main_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SsiMainConf { hash: None, commands: HashKeysArrays::new(HashKind::Small) })
}

/// ngx_http_ssi_init_main_conf
fn ssi_init_main_conf(cf: &mut Conf, conf: &Rc<dyn Any>) -> ConfResult {
    let mut smcf = conf_cell::<SsiMainConf>(conf).borrow_mut();

    let names: Vec<HashKey<usize>> = smcf.commands.keys().to_vec();

    let hash = HashInit { name: "ssi_command_hash", max_size: 1024, bucket_size: 64, log: &cf.log };

    match Hash::init(&hash, names) {
        Ok(h) => smcf.hash = Some(h),
        Err(e) => {
            ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
            return Err(ConfError::Logged);
        }
    }

    Ok(())
}

/// ngx_http_ssi_create_loc_conf
fn ssi_create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SsiLocConf {
        enable: Val::unset(),
        silent_errors: Val::unset(),
        ignore_recycled_buffers: Val::unset(),
        last_modified: Val::unset(),
        types: None,
        min_file_chunk: Val::unset(),
        value_len: Val::unset(),
        types_keys: None,
    })
}

/// ngx_http_ssi_merge_loc_conf
fn ssi_merge_loc_conf(cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let mut prev = conf_cell::<SsiLocConf>(parent).borrow_mut();
    let mut conf = conf_cell::<SsiLocConf>(child).borrow_mut();

    conf.enable.merge(&prev.enable, false);
    conf.silent_errors.merge(&prev.silent_errors, false);
    conf.ignore_recycled_buffers.merge(&prev.ignore_recycled_buffers, false);
    conf.last_modified.merge(&prev.last_modified, false);

    conf.min_file_chunk.merge(&prev.min_file_chunk, 1024);
    conf.value_len.merge(&prev.value_len, 255);

    http_merge_types(cf, &mut conf, &mut prev)
}

/// ngx_http_merge_types with ngx_http_html_default_types
fn http_merge_types(cf: &Conf, conf: &mut SsiLocConf, prev: &mut SsiLocConf) -> ConfResult {
    if let Some(keys) = &conf.types_keys {
        if let TypesKeys::List(list) = keys {
            conf.types = Some(Rc::new(types_hash_init(cf, list)?));
        }

        return Ok(());
    }

    if prev.types.is_none() {
        match &prev.types_keys {
            None => {
                // ngx_http_set_default_types
                prev.types_keys = Some(TypesKeys::List(NGX_HTTP_HTML_DEFAULT_TYPES.iter().map(|t| t.to_vec()).collect()));
            }
            Some(TypesKeys::Any) => {
                conf.types_keys = Some(TypesKeys::Any);
                return Ok(());
            }
            Some(TypesKeys::List(_)) => {}
        }

        if let Some(TypesKeys::List(list)) = &prev.types_keys {
            prev.types = Some(Rc::new(types_hash_init(cf, list)?));
        }
    }

    conf.types = prev.types.clone();

    Ok(())
}

fn types_hash_init(cf: &Conf, list: &[Vec<u8>]) -> Result<Hash<Rc<Vec<u8>>>, ConfError> {
    let names = list.iter().map(|t| HashKey { key: t.clone(), key_hash: hash_key(t), value: Rc::new(t.clone()) }).collect();

    let hash = HashInit { name: "test_types_hash", max_size: 2048, bucket_size: 64, log: &cf.log };

    Hash::init(&hash, names).map_err(|e| {
        ngx_log_error!(NGX_LOG_EMERG, cf.log, None, "{}", e);
        ConfError::Logged
    })
}

/// ngx_http_types_slot with ngx_http_html_default_types[0] as the default
fn ssi_types_slot(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<SsiLocConf>(conf.as_ref().expect("conf"));
    let mut slcf = cell.borrow_mut();

    if matches!(slcf.types_keys, Some(TypesKeys::Any)) {
        return Ok(());
    }

    if slcf.types_keys.is_none() {
        slcf.types_keys = Some(TypesKeys::List(vec![NGX_HTTP_HTML_DEFAULT_TYPES[0].to_vec()]));
    }

    for value in cf.args[1..].iter() {
        if value.as_slice() == b"*" {
            slcf.types_keys = Some(TypesKeys::Any);
            return Ok(());
        }

        let value = value.to_ascii_lowercase();

        if let Some(TypesKeys::List(list)) = &mut slcf.types_keys {
            if list.iter().any(|t| *t == value) {
                cf.warn(format_args!("duplicate MIME type \"{}\"", B(&value)));
                continue;
            }

            list.push(value);
        }
    }

    Ok(())
}

pub fn ssi_filter_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(ssi_preconfiguration),
        postconfiguration: Some(ssi_filter_init),
        create_main_conf: Some(ssi_create_main_conf),
        init_main_conf: Some(ssi_init_main_conf),
        create_loc_conf: Some(ssi_create_loc_conf),
        merge_loc_conf: Some(ssi_merge_loc_conf),
        ..Default::default()
    };

    const MSL: u32 = NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF;

    let commands = vec![
        cmd!("ssi", MSL | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG, ConfLevel::Loc, SsiLocConf, enable, set_flag),
        cmd!("ssi_silent_errors", MSL | NGX_CONF_FLAG, ConfLevel::Loc, SsiLocConf, silent_errors, set_flag),
        cmd!("ssi_ignore_recycled_buffers", MSL | NGX_CONF_FLAG, ConfLevel::Loc, SsiLocConf, ignore_recycled_buffers, set_flag),
        cmd!("ssi_min_file_chunk", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, SsiLocConf, min_file_chunk, set_size),
        cmd!("ssi_value_length", MSL | NGX_CONF_TAKE1, ConfLevel::Loc, SsiLocConf, value_len, set_size),
        cmd_fn!("ssi_types", MSL | NGX_CONF_1MORE, ConfLevel::Loc, ssi_types_slot),
        cmd!("ssi_last_modified", MSL | NGX_CONF_FLAG, ConfLevel::Loc, SsiLocConf, last_modified, set_flag),
    ];

    http_module_def("ngx_http_ssi_filter_module", def, commands)
}

// ---------------------------------------------------------------------------
// the commands

const NGX_HTTP_SSI_INCLUDE_VIRTUAL: usize = 0;
const NGX_HTTP_SSI_INCLUDE_FILE: usize = 1;
const NGX_HTTP_SSI_INCLUDE_WAIT: usize = 2;
const NGX_HTTP_SSI_INCLUDE_SET: usize = 3;
const NGX_HTTP_SSI_INCLUDE_STUB: usize = 4;

const NGX_HTTP_SSI_ECHO_VAR: usize = 0;
const NGX_HTTP_SSI_ECHO_DEFAULT: usize = 1;
const NGX_HTTP_SSI_ECHO_ENCODING: usize = 2;

const NGX_HTTP_SSI_CONFIG_ERRMSG: usize = 0;
const NGX_HTTP_SSI_CONFIG_TIMEFMT: usize = 1;

const NGX_HTTP_SSI_SET_VAR: usize = 0;
const NGX_HTTP_SSI_SET_VALUE: usize = 1;

const NGX_HTTP_SSI_IF_EXPR: usize = 0;

const NGX_HTTP_SSI_BLOCK_NAME: usize = 0;

/// The parameters of a command, by the index of their ngx_http_ssi_param_t.
type SsiParams = [Option<Vec<u8>>; NGX_HTTP_SSI_MAX_PARAMS + 1];

/// ngx_http_ssi_command_pt; `command` is ctx->command
type SsiCommandHandler = fn(&R, &Rc<SsiCtx>, &[u8], &mut SsiParams) -> i64;

/// ngx_http_ssi_param_t
struct SsiParam {
    name: &'static [u8],
    index: usize,
    mandatory: bool,
    multiple: bool,
}

/// ngx_http_ssi_command_t
struct SsiCommand {
    name: &'static [u8],
    handler: SsiCommandHandler,
    params: &'static [SsiParam],
    conditional: u32,
    block: bool,
    flush: bool,
}

const fn param(name: &'static [u8], index: usize, mandatory: bool) -> SsiParam {
    SsiParam { name, index, mandatory, multiple: false }
}

static NGX_HTTP_SSI_INCLUDE_PARAMS: [SsiParam; 5] = [
    param(b"virtual", NGX_HTTP_SSI_INCLUDE_VIRTUAL, false),
    param(b"file", NGX_HTTP_SSI_INCLUDE_FILE, false),
    param(b"wait", NGX_HTTP_SSI_INCLUDE_WAIT, false),
    param(b"set", NGX_HTTP_SSI_INCLUDE_SET, false),
    param(b"stub", NGX_HTTP_SSI_INCLUDE_STUB, false),
];

static NGX_HTTP_SSI_ECHO_PARAMS: [SsiParam; 3] = [
    param(b"var", NGX_HTTP_SSI_ECHO_VAR, true),
    param(b"default", NGX_HTTP_SSI_ECHO_DEFAULT, false),
    param(b"encoding", NGX_HTTP_SSI_ECHO_ENCODING, false),
];

static NGX_HTTP_SSI_CONFIG_PARAMS: [SsiParam; 2] = [
    param(b"errmsg", NGX_HTTP_SSI_CONFIG_ERRMSG, false),
    param(b"timefmt", NGX_HTTP_SSI_CONFIG_TIMEFMT, false),
];

static NGX_HTTP_SSI_SET_PARAMS: [SsiParam; 2] = [
    param(b"var", NGX_HTTP_SSI_SET_VAR, true),
    param(b"value", NGX_HTTP_SSI_SET_VALUE, true),
];

static NGX_HTTP_SSI_IF_PARAMS: [SsiParam; 1] = [param(b"expr", NGX_HTTP_SSI_IF_EXPR, true)];

static NGX_HTTP_SSI_BLOCK_PARAMS: [SsiParam; 1] = [param(b"name", NGX_HTTP_SSI_BLOCK_NAME, true)];

static NGX_HTTP_SSI_NO_PARAMS: [SsiParam; 0] = [];

static NGX_HTTP_SSI_COMMANDS: [SsiCommand; 10] = [
    SsiCommand { name: b"include", handler: ssi_include, params: &NGX_HTTP_SSI_INCLUDE_PARAMS, conditional: 0, block: false, flush: true },
    SsiCommand { name: b"echo", handler: ssi_echo, params: &NGX_HTTP_SSI_ECHO_PARAMS, conditional: 0, block: false, flush: false },
    SsiCommand { name: b"config", handler: ssi_config, params: &NGX_HTTP_SSI_CONFIG_PARAMS, conditional: 0, block: false, flush: false },
    SsiCommand { name: b"set", handler: ssi_set, params: &NGX_HTTP_SSI_SET_PARAMS, conditional: 0, block: false, flush: false },
    SsiCommand { name: b"if", handler: ssi_if, params: &NGX_HTTP_SSI_IF_PARAMS, conditional: 0, block: false, flush: false },
    SsiCommand { name: b"elif", handler: ssi_if, params: &NGX_HTTP_SSI_IF_PARAMS, conditional: NGX_HTTP_SSI_COND_IF, block: false, flush: false },
    SsiCommand { name: b"else", handler: ssi_else, params: &NGX_HTTP_SSI_NO_PARAMS, conditional: NGX_HTTP_SSI_COND_IF, block: false, flush: false },
    SsiCommand { name: b"endif", handler: ssi_endif, params: &NGX_HTTP_SSI_NO_PARAMS, conditional: NGX_HTTP_SSI_COND_ELSE, block: false, flush: false },
    SsiCommand { name: b"block", handler: ssi_block, params: &NGX_HTTP_SSI_BLOCK_PARAMS, conditional: 0, block: false, flush: false },
    SsiCommand { name: b"endblock", handler: ssi_endblock, params: &NGX_HTTP_SSI_NO_PARAMS, conditional: 0, block: true, flush: false },
];

/// ngx_http_ssi_vars
static NGX_HTTP_SSI_VARS: [VarDef; 2] = [
    VarDef { name: "date_local", set: None, get: Some(ssi_date_gmt_local_variable), data: 0, flags: NGX_HTTP_VAR_NOCACHEABLE },
    VarDef { name: "date_gmt", set: None, get: Some(ssi_date_gmt_local_variable), data: 1, flags: NGX_HTTP_VAR_NOCACHEABLE },
];

// ---------------------------------------------------------------------------
// the request context

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SsiState {
    Start = 0,
    Tag,
    Comment0,
    Comment1,
    Sharp,
    PreCommand,
    Command,
    PreParam,
    Param,
    PreEqual,
    PreValue,
    DoubleQuotedValue,
    QuotedValue,
    QuotedSymbol,
    PostParam,
    CommentEnd0,
    CommentEnd1,
    Error,
    ErrorEnd0,
    ErrorEnd1,
}

/// ngx_http_ssi_var_t
pub struct SsiVar {
    name: Vec<u8>,
    key: usize,
    value: Vec<u8>,
}

/// ngx_http_ssi_block_t
pub struct SsiBlock {
    name: Vec<u8>,
    bufs: Chain,
    count: usize,
}

/// ctx->ncaptures, ctx->captures and ctx->captures_data
#[derive(Clone, Default)]
struct SsiCaptures {
    ncaptures: usize,
    captures: Vec<i32>,
    captures_data: Vec<u8>,
}

/// The parser part of ngx_http_ssi_ctx_t (ngx_http_ssi_parse()): offsets
/// are into the data of ctx->buf, as its pos and last are.
struct SsiParse {
    buf: Option<Buf>,
    pos: usize,
    copy_start: Option<usize>,
    copy_end: Option<usize>,
    key: usize,
    command: Vec<u8>,
    /// ctx->params: (key, value), ctx->param being the last one
    params: Vec<(Vec<u8>, Vec<u8>)>,
    state: SsiState,
    saved_state: SsiState,
    saved: usize,
    looked: usize,
    value_len: usize,
}

type SsiVariables = Rc<RefCell<Vec<SsiVar>>>;
type SsiBlocks = Rc<RefCell<Vec<SsiBlock>>>;

/// ngx_http_ssi_ctx_t. The variables, the blocks and the captures are the
/// ones of the main request's context (mctx); ctx->busy and ctx->free are
/// not needed with buffers owning their data.
pub struct SsiCtx {
    p: RefCell<SsiParse>,
    in_: RefCell<Chain>,
    out: RefCell<Chain>,
    variables: RefCell<Option<SsiVariables>>,
    blocks: RefCell<Option<SsiBlocks>>,
    captures: RefCell<SsiCaptures>,
    shared: Cell<bool>,
    conditional: Cell<u32>,
    encoding: Cell<u32>,
    block: Cell<bool>,
    output: Cell<bool>,
    output_chosen: Cell<bool>,
    wait: RefCell<Option<R>>,
    timefmt: RefCell<Vec<u8>>,
    errmsg: RefCell<Vec<u8>>,
}

impl SsiCtx {
    fn new(value_len: usize) -> SsiCtx {
        SsiCtx {
            p: RefCell::new(SsiParse {
                buf: None,
                pos: 0,
                copy_start: None,
                copy_end: None,
                key: 0,
                command: Vec::new(),
                params: Vec::new(),
                state: SsiState::Start,
                saved_state: SsiState::Start,
                saved: 0,
                looked: 0,
                value_len,
            }),
            in_: RefCell::new(Chain::new()),
            out: RefCell::new(Chain::new()),
            variables: RefCell::new(None),
            blocks: RefCell::new(None),
            captures: RefCell::new(SsiCaptures::default()),
            shared: Cell::new(false),
            conditional: Cell::new(0),
            encoding: Cell::new(NGX_HTTP_SSI_ENTITY_ENCODING),
            block: Cell::new(false),
            output: Cell::new(true),
            output_chosen: Cell::new(false),
            wait: RefCell::new(None),
            timefmt: RefCell::new(NGX_HTTP_SSI_TIMEFMT.to_vec()),
            errmsg: RefCell::new(NGX_HTTP_SSI_ERRMSG.to_vec()),
        }
    }

    /// mctx->variables, created if there is none
    fn variables_list(&self) -> SsiVariables {
        self.variables.borrow_mut().get_or_insert_with(|| Rc::new(RefCell::new(Vec::new()))).clone()
    }
}

/// ngx_http_get_module_ctx(r, ngx_http_ssi_filter_module)
fn ssi_get_ctx(r: &R) -> Option<Rc<SsiCtx>> {
    r.get_ctx::<Rc<SsiCtx>>(ctx_index()).map(|c| c.borrow().clone())
}

/// ngx_http_set_ctx(r, ctx, ngx_http_ssi_filter_module)
fn ssi_set_ctx(r: &R, ctx: Rc<SsiCtx>) {
    r.set_ctx(ctx_index(), ctx);
}

/// ngx_hash_strlow(s, s, len)
fn hash_strlow(s: &mut [u8]) -> usize {
    let mut key = 0usize;

    for c in s.iter_mut() {
        *c = c.to_ascii_lowercase();
        key = key.wrapping_mul(31).wrapping_add(*c as usize);
    }

    key
}

// ---------------------------------------------------------------------------
// the filters

/// ngx_http_ssi_header_filter
/// ssi_header_filter passes the response on as it is: ssi off
fn ssi_header_idle(r: &R) -> bool {
    !*r.loc_conf::<SsiLocConf>(ctx_index()).borrow().enable
}

async fn ssi_header_filter(r: R, next: HeaderFilter) -> i64 {
    let slcf = r.loc_conf::<SsiLocConf>(ctx_index());

    let (enable, value_len, last_modified, types) = {
        let c = slcf.borrow();
        (*c.enable, *c.value_len, *c.last_modified, c.types.clone())
    };

    if !enable || r.headers_out.borrow().content_length_n == 0 || !test_content_type(&r, types.as_deref()) {
        return next(r).await;
    }

    let mctx = ssi_get_ctx(&r.main());

    let ctx = Rc::new(SsiCtx::new(value_len));

    ssi_set_ctx(&r, ctx.clone());

    r.filter_need_in_memory.set(true);

    if r.is_main() {
        if let Some(mctx) = mctx {
            // if there was a shared context previously used as main,
            // copy variables and blocks

            *ctx.variables.borrow_mut() = mctx.variables.borrow().clone();
            *ctx.blocks.borrow_mut() = mctx.blocks.borrow().clone();
            *ctx.captures.borrow_mut() = mctx.captures.borrow().clone();

            mctx.shared.set(false);
        }

        r.clear_content_length();
        r.clear_accept_ranges();

        r.preserve_body.set(true);

        if !last_modified {
            r.clear_last_modified();
            r.clear_etag();
        } else {
            crate::core_rt::weak_etag(&r);
        }
    } else if mctx.is_none() {
        ssi_set_ctx(&r.main(), ctx.clone());
        ctx.shared.set(true);
    }

    next(r).await
}

/// ngx_http_test_content_type: an empty types hash matches anything
fn test_content_type(r: &R, types: Option<&Hash<Rc<Vec<u8>>>>) -> bool {
    match types {
        None => true,
        Some(hash) => crate::core_rt::test_content_type(r, hash).is_some(),
    }
}

/// How the processing of a command ends in ngx_http_ssi_body_filter().
enum SsiCommandRc {
    /// continue with the parsing
    Continue,
    /// goto ssi_error
    Error,
    /// the body filter returns this
    Return(i64),
}

/// ngx_http_ssi_body_filter
/// ssi_body_filter passes the chain on as it is
fn ssi_body_idle(r: &R, _input: &Chain) -> bool {
    !r.has_ctx(ctx_index())
}

async fn ssi_body_filter(r: R, input: Chain, next: BodyFilter) -> i64 {
    let ctx = match ssi_get_ctx(&r) {
        Some(ctx) => ctx,
        None => return next(r, input).await,
    };

    if (ctx.shared.get() && r.is_main()) || (input.is_empty() && ctx.p.borrow().buf.is_none() && ctx.in_.borrow().is_empty()) {
        return next(r, input).await;
    }

    // add the incoming chain to the chain ctx->in

    if !input.is_empty() {
        ctx.in_.borrow_mut().extend(input);
    }

    http_debug!(r, "http ssi filter \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));

    // ctx->wait is never set here: the filter waits for the subrequest
    // where the command returns NGX_AGAIN (ssi_wait())

    let slcf = r.loc_conf::<SsiLocConf>(ctx_index());

    let (silent_errors, ignore_recycled_buffers) = {
        let c = slcf.borrow();
        (*c.silent_errors, *c.ignore_recycled_buffers)
    };

    while !ctx.in_.borrow().is_empty() || ctx.p.borrow().buf.is_some() {
        {
            let mut p = ctx.p.borrow_mut();

            if p.buf.is_none() {
                let buf = ctx.in_.borrow_mut().pop_front().expect("ctx->in");
                p.pos = buf.pos;
                p.buf = Some(buf);
            }

            if p.state == SsiState::Start {
                p.copy_start = Some(p.pos);
                p.copy_end = Some(p.pos);
            }
        }

        // the last buffer of ctx->out is "b"
        let mut b = false;

        loop {
            {
                let p = ctx.p.borrow();

                if p.pos >= p.buf.as_ref().expect("ctx->buf").last {
                    break;
                }

                http_debug!(r, "saved: {} state: {}", p.saved, p.state as u32);
            }

            let rc = ssi_parse(&r.connection.log, &mut ctx.p.borrow_mut());

            {
                let p = ctx.p.borrow();
                http_debug!(r, "parse: {}, looked: {} {:?}-{:?}", rc, p.looked, p.copy_start, p.copy_end);
            }

            if rc == NGX_ERROR {
                return rc;
            }

            {
                let mut p = ctx.p.borrow_mut();

                if p.copy_start != p.copy_end {
                    let (start, end) = (p.copy_start.expect("copy_start"), p.copy_end.expect("copy_end"));

                    if ctx.output.get() {
                        http_debug!(r, "saved: {}", p.saved);

                        if p.saved > 0 {
                            ctx.out.borrow_mut().push_back(Buf::from_static(&NGX_HTTP_SSI_STRING[..p.saved]));
                            p.saved = 0;
                        }

                        ctx.out.borrow_mut().push_back(ssi_copy_buf(p.buf.as_ref().expect("ctx->buf"), start, end));
                        b = true;
                    } else {
                        if ctx.block.get() && p.saved + (end - start) > 0 {
                            let mut data = NGX_HTTP_SSI_STRING[..p.saved].to_vec();
                            data.extend_from_slice(buf_bytes(p.buf.as_ref().expect("ctx->buf"), start, end));

                            ssi_block_append(&r, Buf::from_vec(data));

                            b = false;
                        }

                        p.saved = 0;
                    }
                }

                if p.state == SsiState::Start {
                    p.copy_start = Some(p.pos);
                    p.copy_end = Some(p.pos);
                } else {
                    p.copy_start = None;
                    p.copy_end = None;
                }
            }

            if rc == NGX_AGAIN {
                continue;
            }

            b = false;

            if rc == NGX_OK {
                match ssi_command(&r, &ctx, &next).await {
                    SsiCommandRc::Continue => continue,
                    SsiCommandRc::Return(rc) => return rc,
                    SsiCommandRc::Error => {}
                }
            }

            // rc == NGX_HTTP_SSI_ERROR

            // ssi_error:

            if silent_errors {
                continue;
            }

            let errmsg = ctx.errmsg.borrow().clone();
            let mut eb = Buf::from_vec(errmsg);
            eb.temporary = false;
            eb.memory = true;
            ctx.out.borrow_mut().push_back(eb);
            b = true;
        }

        {
            let mut p = ctx.p.borrow_mut();
            let buf = p.buf.take().expect("ctx->buf");

            if buf.last_buf || buf.in_memory() {
                let mut out = ctx.out.borrow_mut();

                if !b {
                    out.push_back(Buf::special());
                }

                let ob = out.back_mut().expect("b");

                ob.last_buf = buf.last_buf;

                if !ignore_recycled_buffers {
                    ob.recycled = buf.recycled;
                }
            }

            p.saved = p.looked;
        }
    }

    let rc = if ctx.out.borrow().is_empty() { NGX_OK } else { ssi_output(&r, &ctx, &next).await };

    if rc == NGX_ERROR {
        return rc;
    }

    // what ngx_http_ssi_output() does: the input is all parsed by now (the
    // flag set while waiting for a subrequest would keep a subrequest
    // from ending, see crate::postpone_filter)
    ssi_buffered(&r, &ctx);

    // the subrequests posted run once the request waits (for more input,
    // or in request_rt::finalize_request() for its postponed subrequests)

    rc
}

/// The command of ngx_http_ssi_body_filter() once ngx_http_ssi_parse() has
/// returned NGX_OK.
async fn ssi_command(r: &R, ctx: &Rc<SsiCtx>, next: &BodyFilter) -> SsiCommandRc {
    let (key, command, params) = {
        let p = ctx.p.borrow();
        (p.key, p.command.clone(), p.params.clone())
    };

    let cmd = {
        let smcf = r.main_conf::<SsiMainConf>(ctx_index());
        let smcf = smcf.borrow();
        smcf.hash.as_ref().and_then(|h| h.find(key, &command).copied())
    };

    let cmd = match cmd {
        Some(i) => &NGX_HTTP_SSI_COMMANDS[i],
        None => {
            if ctx.output.get() {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid SSI command: \"{}\"", B(&command));
                return SsiCommandRc::Error;
            }

            return SsiCommandRc::Continue;
        }
    };

    if !ctx.output.get() && !cmd.block {
        if ctx.block.get() {
            // reconstruct the SSI command text

            let mut text = Vec::with_capacity(5 + command.len() + 4);

            text.extend_from_slice(b"<!--#");
            text.extend_from_slice(&command);

            for (k, v) in params.iter() {
                text.push(b' ');
                text.extend_from_slice(k);
                text.push(b'=');
                text.push(b'"');
                text.extend_from_slice(v);
                text.push(b'"');
            }

            text.extend_from_slice(b" -->");

            ssi_block_append(r, Buf::from_vec(text));

            return SsiCommandRc::Continue;
        }

        if cmd.conditional == 0 {
            return SsiCommandRc::Continue;
        }
    }

    if cmd.conditional != 0 && (ctx.conditional.get() == 0 || ctx.conditional.get() > cmd.conditional) {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid context of SSI command: \"{}\"", B(&command));
        return SsiCommandRc::Error;
    }

    if params.len() > NGX_HTTP_SSI_MAX_PARAMS {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "too many SSI command parameters: \"{}\"", B(&command));
        return SsiCommandRc::Error;
    }

    let mut args: SsiParams = Default::default();

    for (k, v) in params.into_iter() {
        let prm = match cmd.params.iter().find(|prm| prm.name == k.as_slice()) {
            Some(prm) => prm,
            None => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid parameter name: \"{}\" in \"{}\" SSI command", B(&k), B(&command));
                return SsiCommandRc::Error;
            }
        };

        if !prm.multiple {
            if args[prm.index].is_some() {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "duplicate \"{}\" parameter in \"{}\" SSI command", B(&k), B(&command));
                return SsiCommandRc::Error;
            }

            args[prm.index] = Some(v);
            continue;
        }

        let mut index = prm.index;

        while index < NGX_HTTP_SSI_MAX_PARAMS && args[index].is_some() {
            index += 1;
        }

        args[index] = Some(v);
    }

    for prm in cmd.params.iter() {
        if prm.mandatory && args[prm.index].is_none() {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "mandatory \"{}\" parameter is absent in \"{}\" SSI command", B(prm.name), B(&command));
            return SsiCommandRc::Error;
        }
    }

    if cmd.flush && !ctx.out.borrow().is_empty() {
        http_debug!(r, "ssi flush");

        if ssi_output(r, ctx, next).await == NGX_ERROR {
            return SsiCommandRc::Return(NGX_ERROR);
        }
    }

    let rc = (cmd.handler)(r, ctx, &command, &mut args);

    if rc == NGX_OK {
        return SsiCommandRc::Continue;
    }

    if rc == NGX_DONE || rc == NGX_AGAIN || rc == NGX_ERROR {
        ssi_buffered(r, ctx);

        if rc == NGX_AGAIN {
            if ssi_wait(r, ctx, next).await == NGX_ERROR {
                return SsiCommandRc::Return(NGX_ERROR);
            }

            return SsiCommandRc::Continue;
        }

        return SsiCommandRc::Return(rc);
    }

    SsiCommandRc::Error
}

/// C returns NGX_AGAIN from the body filter here, and the request goes on
/// in ngx_http_writer() once posted, calling the body filter again, which
/// then deals with ctx->wait (below) before going on with the parsing.
/// Here the request waits for being posted and goes on.
async fn ssi_wait(r: &R, ctx: &Rc<SsiCtx>, next: &BodyFilter) -> i64 {
    loop {
        if crate::postpone_filter::wait_posted(r).await == NGX_ERROR {
            return NGX_ERROR;
        }

        http_debug!(r, "http ssi filter \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));

        let wait = match ctx.wait.borrow().clone() {
            Some(wait) => wait,
            None => return NGX_OK,
        };

        if !crate::postpone_filter::is_active(r) {
            http_debug!(r, "http ssi filter wait \"{}?{}\" non-active", B(&wait.uri.borrow()), B(&wait.args.borrow()));
            continue;
        }

        if wait.done.get() {
            http_debug!(r, "http ssi filter wait \"{}?{}\" done", B(&wait.uri.borrow()), B(&wait.args.borrow()));

            *ctx.wait.borrow_mut() = None;

            return NGX_OK;
        }

        http_debug!(r, "http ssi filter wait \"{}?{}\"", B(&wait.uri.borrow()), B(&wait.args.borrow()));

        // ngx_http_next_body_filter(r, NULL)
        if next(r.clone(), Chain::new()).await == NGX_ERROR {
            return NGX_ERROR;
        }
    }
}

/// The bytes [start, end) of the data of a buffer.
fn buf_bytes(buf: &Buf, start: usize, end: usize) -> &[u8] {
    match &buf.data {
        BufData::Memory(v) => &v[start..end],
        _ => &[],
    }
}

/// The buffer ngx_http_ssi_body_filter() makes of a copy of ctx->buf with
/// pos and last at ctx->copy_start and ctx->copy_end. A buffer here is in
/// memory or in a file, never both, and ctx->buf is in memory: in C such a
/// copy of an in_file buffer longer than ssi_min_file_chunk is left in the
/// file too, and the others are made memory only, as this one is.
fn ssi_copy_buf(buf: &Buf, start: usize, end: usize) -> Buf {
    let data = buf_bytes(buf, start, end).to_vec();
    let len = data.len();

    let mut b = Buf {
        pos: 0,
        last: len,
        file_pos: 0,
        file_last: 0,
        tag: buf.tag,
        num: buf.num,
        data: BufData::Memory(data),
        temporary: buf.temporary,
        memory: buf.memory,
        mmap: buf.mmap,
        recycled: false,
        in_file: false,
        flush: buf.flush,
        sync: buf.sync,
        last_buf: false,
        last_in_chain: buf.last_in_chain,
        temp_file: buf.temp_file,
    };

    if !b.in_memory() {
        b.memory = true;
    }

    b
}

/// Appends a buffer to the bufs of the last block of mctx->blocks.
fn ssi_block_append(r: &R, b: Buf) {
    let mctx = match ssi_get_ctx(&r.main()) {
        Some(mctx) => mctx,
        None => return,
    };

    let blocks = mctx.blocks.borrow().clone();

    if let Some(blocks) = blocks {
        if let Some(bl) = blocks.borrow_mut().last_mut() {
            bl.bufs.push_back(b);
        }
    }
}

/// ngx_http_ssi_output
async fn ssi_output(r: &R, ctx: &Rc<SsiCtx>, next: &BodyFilter) -> i64 {
    let out = std::mem::take(&mut *ctx.out.borrow_mut());

    for b in out.iter() {
        http_debug!(r, "ssi out: {:p} {}", b as *const Buf, b.pos);
    }

    let rc = next(r.clone(), out).await;

    ssi_buffered(r, ctx);

    rc
}

/// ngx_http_ssi_buffered
fn ssi_buffered(r: &R, ctx: &SsiCtx) {
    if !ctx.in_.borrow().is_empty() || ctx.p.borrow().buf.is_some() {
        r.buffered.set(r.buffered.get() | NGX_HTTP_SSI_BUFFERED);
    } else {
        r.buffered.set(r.buffered.get() & !NGX_HTTP_SSI_BUFFERED);
    }
}

fn is_ws(ch: u8) -> bool {
    matches!(ch, b' ' | b'\r' | b'\n' | b'\t')
}

/// The bytes of a string and a character, as "%V%c" prints them.
fn with_ch(s: &[u8], ch: u8) -> Vec<u8> {
    let mut v = s.to_vec();
    v.push(ch);
    v
}

/// ngx_http_ssi_parse
fn ssi_parse(log: &Log, ctx: &mut SsiParse) -> i64 {
    let buf = ctx.buf.take().expect("ctx->buf");
    let rc = ssi_parse_buf(log, ctx, &buf);
    ctx.buf = Some(buf);
    rc
}

fn ssi_parse_buf(log: &Log, ctx: &mut SsiParse, buf: &Buf) -> i64 {
    let data: &[u8] = match &buf.data {
        BufData::Memory(v) => v,
        _ => &[],
    };

    let mut state = ctx.state;
    let mut looked = ctx.looked;
    let last = buf.last;
    let mut copy_end = ctx.copy_end;

    let mut p = ctx.pos;

    while p < last {
        let mut ch = data[p];

        if state == SsiState::Start {
            // the tight loop

            loop {
                if ch == b'<' {
                    copy_end = Some(p);
                    looked = 1;
                    state = SsiState::Tag;
                    break;
                }

                p += 1;

                if p == last {
                    ctx.state = state;
                    ctx.pos = p;
                    ctx.looked = looked;
                    ctx.copy_end = Some(p);

                    if ctx.copy_start.is_none() {
                        ctx.copy_start = Some(buf.pos);
                    }

                    return NGX_AGAIN;
                }

                ch = data[p];
            }

            // tag_started:
            p += 1;
            continue;
        }

        match state {
            SsiState::Start => {
                // not reached
            }

            SsiState::Tag => match ch {
                b'!' => {
                    looked = 2;
                    state = SsiState::Comment0;
                }
                b'<' => {
                    copy_end = Some(p);
                }
                _ => {
                    copy_end = Some(p);
                    looked = 0;
                    state = SsiState::Start;
                }
            },

            SsiState::Comment0 => match ch {
                b'-' => {
                    looked = 3;
                    state = SsiState::Comment1;
                }
                b'<' => {
                    copy_end = Some(p);
                    looked = 1;
                    state = SsiState::Tag;
                }
                _ => {
                    copy_end = Some(p);
                    looked = 0;
                    state = SsiState::Start;
                }
            },

            SsiState::Comment1 => match ch {
                b'-' => {
                    looked = 4;
                    state = SsiState::Sharp;
                }
                b'<' => {
                    copy_end = Some(p);
                    looked = 1;
                    state = SsiState::Tag;
                }
                _ => {
                    copy_end = Some(p);
                    looked = 0;
                    state = SsiState::Start;
                }
            },

            SsiState::Sharp => match ch {
                b'#' => {
                    if p - ctx.pos < 4 {
                        ctx.saved = 0;
                    }
                    looked = 0;
                    state = SsiState::PreCommand;
                }
                b'<' => {
                    copy_end = Some(p);
                    looked = 1;
                    state = SsiState::Tag;
                }
                _ => {
                    copy_end = Some(p);
                    looked = 0;
                    state = SsiState::Start;
                }
            },

            SsiState::PreCommand => {
                if !is_ws(ch) {
                    ctx.command.clear();
                    ctx.command.push(ch);

                    ctx.key = 0;
                    ctx.key = ctx.key.wrapping_mul(31).wrapping_add(ch as usize);

                    ctx.params.clear();

                    state = SsiState::Command;
                }
            }

            SsiState::Command => match ch {
                b' ' | b'\r' | b'\n' | b'\t' => {
                    state = SsiState::PreParam;
                }
                b'-' => {
                    state = SsiState::CommentEnd0;
                }
                _ => {
                    if ctx.command.len() == NGX_HTTP_SSI_COMMAND_LEN {
                        ngx_log_error!(NGX_LOG_ERR, log, None, "the \"{}...\" SSI command is too long", B(&with_ch(&ctx.command, ch)));

                        state = SsiState::Error;
                    } else {
                        ctx.command.push(ch);
                        ctx.key = ctx.key.wrapping_mul(31).wrapping_add(ch as usize);
                    }
                }
            },

            SsiState::PreParam => match ch {
                b' ' | b'\r' | b'\n' | b'\t' => {}
                b'-' => {
                    state = SsiState::CommentEnd0;
                }
                _ => {
                    ctx.params.push((vec![ch], Vec::new()));
                    state = SsiState::Param;
                }
            },

            SsiState::Param => match ch {
                b' ' | b'\r' | b'\n' | b'\t' => {
                    state = SsiState::PreEqual;
                }
                b'=' => {
                    state = SsiState::PreValue;
                }
                b'-' => {
                    state = SsiState::ErrorEnd0;

                    let (key, _) = ctx.params.last().expect("ctx->param");
                    ngx_log_error!(NGX_LOG_ERR, log, None, "unexpected \"-\" symbol after \"{}\" parameter in \"{}\" SSI command", B(key), B(&ctx.command));
                }
                _ => {
                    let (key, _) = ctx.params.last_mut().expect("ctx->param");

                    if key.len() == NGX_HTTP_SSI_PARAM_LEN {
                        state = SsiState::Error;
                        ngx_log_error!(NGX_LOG_ERR, log, None, "too long \"{}...\" parameter in \"{}\" SSI command", B(&with_ch(key, ch)), B(&ctx.command));
                    } else {
                        key.push(ch);
                    }
                }
            },

            SsiState::PreEqual => match ch {
                b' ' | b'\r' | b'\n' | b'\t' => {}
                b'=' => {
                    state = SsiState::PreValue;
                }
                _ => {
                    state = if ch == b'-' { SsiState::ErrorEnd0 } else { SsiState::Error };

                    let (key, _) = ctx.params.last().expect("ctx->param");
                    ngx_log_error!(NGX_LOG_ERR, log, None, "unexpected \"{}\" symbol after \"{}\" parameter in \"{}\" SSI command", B(&[ch]), B(key), B(&ctx.command));
                }
            },

            SsiState::PreValue => match ch {
                b' ' | b'\r' | b'\n' | b'\t' => {}
                b'"' => {
                    state = SsiState::DoubleQuotedValue;
                }
                b'\'' => {
                    state = SsiState::QuotedValue;
                }
                _ => {
                    state = if ch == b'-' { SsiState::ErrorEnd0 } else { SsiState::Error };

                    let (key, _) = ctx.params.last().expect("ctx->param");
                    ngx_log_error!(NGX_LOG_ERR, log, None, "unexpected \"{}\" symbol before value of \"{}\" parameter in \"{}\" SSI command", B(&[ch]), B(key), B(&ctx.command));
                }
            },

            SsiState::DoubleQuotedValue | SsiState::QuotedValue => {
                let quote = if state == SsiState::DoubleQuotedValue { b'"' } else { b'\'' };

                if ch == quote {
                    state = SsiState::PostParam;
                } else {
                    if ch == b'\\' {
                        ctx.saved_state = state;
                        state = SsiState::QuotedSymbol;
                    }

                    // fall through

                    if !ssi_param_value_push(log, ctx, ch) {
                        state = SsiState::Error;
                    }
                }
            }

            SsiState::QuotedSymbol => {
                state = ctx.saved_state;

                if !ssi_param_value_push(log, ctx, ch) {
                    state = SsiState::Error;
                }
            }

            SsiState::PostParam => match ch {
                b' ' | b'\r' | b'\n' | b'\t' => {
                    state = SsiState::PreParam;
                }
                b'-' => {
                    state = SsiState::CommentEnd0;
                }
                _ => {
                    let (key, value) = ctx.params.last().expect("ctx->param");
                    ngx_log_error!(NGX_LOG_ERR, log, None, "unexpected \"{}\" symbol after \"{}\" value of \"{}\" parameter in \"{}\" SSI command", B(&[ch]), B(value), B(key), B(&ctx.command));
                    state = SsiState::Error;
                }
            },

            SsiState::CommentEnd0 => match ch {
                b'-' => {
                    state = SsiState::CommentEnd1;
                }
                _ => {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "unexpected \"{}\" symbol in \"{}\" SSI command", B(&[ch]), B(&ctx.command));
                    state = SsiState::Error;
                }
            },

            SsiState::CommentEnd1 => match ch {
                b'>' => {
                    ctx.state = SsiState::Start;
                    ctx.pos = p + 1;
                    ctx.looked = looked;
                    ctx.copy_end = copy_end;

                    if ctx.copy_start.is_none() && copy_end.is_some() {
                        ctx.copy_start = Some(buf.pos);
                    }

                    return NGX_OK;
                }
                _ => {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "unexpected \"{}\" symbol in \"{}\" SSI command", B(&[ch]), B(&ctx.command));
                    state = SsiState::Error;
                }
            },

            SsiState::Error => {
                if ch == b'-' {
                    state = SsiState::ErrorEnd0;
                }
            }

            SsiState::ErrorEnd0 => {
                state = if ch == b'-' { SsiState::ErrorEnd1 } else { SsiState::Error };
            }

            SsiState::ErrorEnd1 => match ch {
                b'>' => {
                    ctx.state = SsiState::Start;
                    ctx.pos = p + 1;
                    ctx.looked = looked;
                    ctx.copy_end = copy_end;

                    if ctx.copy_start.is_none() && copy_end.is_some() {
                        ctx.copy_start = Some(buf.pos);
                    }

                    return NGX_HTTP_SSI_ERROR;
                }
                _ => {
                    state = SsiState::Error;
                }
            },
        }

        p += 1;
    }

    ctx.state = state;
    ctx.pos = p;
    ctx.looked = looked;

    ctx.copy_end = if state == SsiState::Start { Some(p) } else { copy_end };

    if ctx.copy_start.is_none() && ctx.copy_end.is_some() {
        ctx.copy_start = Some(buf.pos);
    }

    NGX_AGAIN
}

/// The value part of the states of ngx_http_ssi_parse(): false (and the
/// error logged) for a value too long.
fn ssi_param_value_push(log: &Log, ctx: &mut SsiParse, ch: u8) -> bool {
    let value_len = ctx.value_len;
    let command = &ctx.command;
    let (key, value) = ctx.params.last_mut().expect("ctx->param");

    if value.len() == value_len {
        ngx_log_error!(NGX_LOG_ERR, log, None, "too long \"{}...\" value of \"{}\" parameter in \"{}\" SSI command", B(&with_ch(value, ch)), B(key), B(command));
        return false;
    }

    value.push(ch);

    true
}

// ---------------------------------------------------------------------------
// variables

/// What ngx_http_ssi_get_variable() finds: a capture of the last regex
/// match (a copy: it cannot be changed) or an SSI variable.
enum SsiVarRef {
    Capture(Vec<u8>),
    Var(SsiVariables, usize),
}

impl SsiVarRef {
    fn value(&self) -> Vec<u8> {
        match self {
            SsiVarRef::Capture(v) => v.clone(),
            SsiVarRef::Var(vars, i) => vars.borrow()[*i].value.clone(),
        }
    }

    /// *vv = value
    fn set(&self, value: Vec<u8>) {
        if let SsiVarRef::Var(vars, i) = self {
            vars.borrow_mut()[*i].value = value;
        }
    }
}

/// ngx_http_ssi_get_variable
fn ssi_get_variable(r: &R, name: &[u8], key: usize) -> Option<SsiVarRef> {
    let ctx = ssi_get_ctx(&r.main())?;

    if key >= b'0' as usize && key <= b'9' as usize {
        let i = key - b'0' as usize;

        let caps = ctx.captures.borrow();

        if i < caps.ncaptures {
            let (start, end) = (caps.captures[2 * i], caps.captures[2 * i + 1]);

            let value = if start >= 0 && end >= start { caps.captures_data[start as usize..end as usize].to_vec() } else { Vec::new() };

            return Some(SsiVarRef::Capture(value));
        }
    }

    let vars = ctx.variables.borrow().clone()?;

    let i = vars.borrow().iter().position(|v| v.name.len() == name.len() && v.key == key && v.name == name)?;

    Some(SsiVarRef::Var(vars, i))
}

/// A part of the string ngx_http_ssi_evaluate_string() puts together.
enum EvalPart {
    /// a literal part: a range of the text, unescaped in place
    Text(usize, usize),
    Value(Vec<u8>),
}

/// What looking a variable up gives ngx_http_ssi_evaluate_string(): None
/// for an error, Some(None) for a variable not found.
type EvalLookup<'a> = dyn FnMut(&[u8], usize) -> Option<Option<Vec<u8>>> + 'a;

/// ngx_http_ssi_evaluate_string: the variables in `text` replaced with
/// their values (an SSI variable, else a variable of the request); a
/// backslash escapes "\", "'", '"' and "$". With NGX_HTTP_SSI_ADD_PREFIX,
/// a relative result gets the directory of the request's URI prepended.
fn ssi_evaluate_string(r: &R, text: &mut Vec<u8>, flags: u32) -> i64 {
    let uri = r.uri.borrow().clone();

    let mut lookup = |var: &[u8], key: usize| -> Option<Option<Vec<u8>>> {
        match ssi_get_variable(r, var, key) {
            Some(val) => Some(Some(val.value())),
            None => {
                let vv = get_variable(r, var)?;
                Some((!vv.not_found).then_some(vv.data))
            }
        }
    };

    evaluate_string(&r.connection.log, &uri, text, flags, &mut lookup)
}

/// The string part of ngx_http_ssi_evaluate_string(), for a request with
/// the URI `uri`, `lookup` looking the variables up.
fn evaluate_string(log: &Log, uri: &[u8], text: &mut Vec<u8>, flags: u32, lookup: &mut EvalLookup) -> i64 {
    // ngx_http_script_variables_count()
    let n = text.iter().filter(|&&c| c == b'$').count();

    if n == 0 {
        let mut data = Vec::with_capacity(text.len());

        if flags & NGX_HTTP_SSI_ADD_PREFIX != 0 && text.first() != Some(&b'/') {
            let mut prefix = uri.len();

            while prefix > 0 {
                if uri[prefix - 1] == b'/' {
                    break;
                }
                prefix -= 1;
            }

            if prefix > 0 {
                data.extend_from_slice(&uri[..prefix]);
            }
        }

        let mut quoted = false;

        for &ch in text.iter() {
            if !quoted {
                if ch == b'\\' {
                    quoted = true;
                    continue;
                }
            } else {
                quoted = false;

                if ch != b'\\' && ch != b'\'' && ch != b'"' && ch != b'$' {
                    data.push(b'\\');
                }
            }

            data.push(ch);
        }

        *text = data;

        return NGX_OK;
    }

    let mut parts: Vec<EvalPart> = Vec::new();

    let mut i = 0;

    'invalid_variable: {
        while i < text.len() {
            if text[i] == b'$' {
                i += 1;

                if i == text.len() {
                    break 'invalid_variable;
                }

                let mut bracket = false;

                if text[i] == b'{' {
                    bracket = true;

                    i += 1;

                    if i == text.len() {
                        break 'invalid_variable;
                    }
                }

                let var_start = i;
                let mut var_len = 0;

                while i < text.len() {
                    let ch = text[i];

                    if ch == b'}' && bracket {
                        i += 1;
                        bracket = false;
                        break;
                    }

                    if ch.is_ascii_alphanumeric() || ch == b'_' {
                        i += 1;
                        var_len += 1;
                        continue;
                    }

                    break;
                }

                if bracket {
                    ngx_log_error!(NGX_LOG_ERR, log, None, "the closing bracket in \"{}\" variable is missing", B(&text[var_start..var_start + var_len]));
                    return NGX_HTTP_SSI_ERROR;
                }

                if var_len == 0 {
                    break 'invalid_variable;
                }

                let key = hash_strlow(&mut text[var_start..var_start + var_len]);

                let var = text[var_start..var_start + var_len].to_vec();

                match lookup(&var, key) {
                    None => return NGX_ERROR,
                    // not found
                    Some(None) => continue,
                    Some(Some(value)) => parts.push(EvalPart::Value(value)),
                }
            } else {
                let part_start = i;
                let mut p = part_start;
                let mut quoted = false;

                while i < text.len() {
                    let ch = text[i];

                    if !quoted {
                        if ch == b'\\' {
                            quoted = true;
                            i += 1;
                            continue;
                        }

                        if ch == b'$' {
                            break;
                        }
                    } else {
                        quoted = false;

                        if ch != b'\\' && ch != b'\'' && ch != b'"' && ch != b'$' {
                            text[p] = b'\\';
                            p += 1;
                        }
                    }

                    text[p] = ch;
                    p += 1;
                    i += 1;
                }

                parts.push(EvalPart::Text(part_start, p - part_start));
            }
        }

        let part_first = |part: &EvalPart| -> Option<u8> {
            match part {
                EvalPart::Text(start, len) => (*len > 0).then(|| text[*start]),
                EvalPart::Value(v) => v.first().copied(),
            }
        };

        let mut prefix = 0;

        if flags & NGX_HTTP_SSI_ADD_PREFIX != 0 {
            for part in parts.iter() {
                if let Some(first) = part_first(part) {
                    if first != b'/' {
                        prefix = uri.len();

                        while prefix > 0 {
                            if uri[prefix - 1] == b'/' {
                                break;
                            }
                            prefix -= 1;
                        }
                    }

                    break;
                }
            }
        }

        let mut data = uri[..prefix].to_vec();

        for part in parts.iter() {
            match part {
                EvalPart::Text(start, len) => data.extend_from_slice(&text[*start..*start + *len]),
                EvalPart::Value(v) => data.extend_from_slice(v),
            }
        }

        *text = data;

        return NGX_OK;
    }

    // invalid_variable:

    ngx_log_error!(NGX_LOG_ERR, log, None, "invalid variable name in \"{}\"", B(text));

    NGX_HTTP_SSI_ERROR
}

/// ngx_http_ssi_regex_match: NGX_OK when `s` matches, with the captures
/// kept in the main request's context and the named ones set as SSI
/// variables; NGX_DECLINED when it does not.
fn ssi_regex_match(r: &R, pattern: &[u8], s: &[u8]) -> i64 {
    let re = match ngx_core::regex::Regex::compile(pattern, 0) {
        Ok(re) => re,
        Err(e) => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "{}", e);
            return NGX_HTTP_SSI_ERROR;
        }
    };

    let caps = match re.exec(s) {
        Some(caps) => caps,
        None => return NGX_DECLINED,
    };

    let ctx = match ssi_get_ctx(&r.main()) {
        Some(ctx) => ctx,
        None => return NGX_ERROR,
    };

    // rc of ngx_regex_exec(): the pairs up to the last one set
    let rc = caps.iter().rposition(|&(a, _)| a >= 0).map_or(0, |i| i + 1);

    {
        let mut c = ctx.captures.borrow_mut();

        c.ncaptures = rc;
        c.captures = caps.iter().flat_map(|&(a, b)| [a, b]).collect();
        c.captures_data = s.to_vec();
    }

    if !re.names.is_empty() {
        let variables = ctx.variables_list();

        for (name, n) in re.names.iter() {
            let mut name = name.clone();

            let value = match caps.get(*n) {
                Some(&(a, b)) if a >= 0 && b >= a => s[a as usize..b as usize].to_vec(),
                _ => Vec::new(),
            };

            let key = hash_strlow(&mut name);

            if let Some(vv) = ssi_get_variable(r, &name, key) {
                vv.set(value);
                continue;
            }

            variables.borrow_mut().push(SsiVar { name, key, value });
        }
    }

    NGX_OK
}

// ---------------------------------------------------------------------------
// the command handlers

/// ngx_http_ssi_include
fn ssi_include(r: &R, ctx: &Rc<SsiCtx>, _command: &[u8], params: &mut SsiParams) -> i64 {
    let uri = params[NGX_HTTP_SSI_INCLUDE_VIRTUAL].take();
    let file = params[NGX_HTTP_SSI_INCLUDE_FILE].take();
    let wait = params[NGX_HTTP_SSI_INCLUDE_WAIT].take();
    let set = params[NGX_HTTP_SSI_INCLUDE_SET].take();
    let stub = params[NGX_HTTP_SSI_INCLUDE_STUB].take();

    if let (Some(uri), Some(file)) = (&uri, &file) {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "inclusion may be either virtual=\"{}\" or file=\"{}\"", B(uri), B(file));
        return NGX_HTTP_SSI_ERROR;
    }

    if uri.is_none() && file.is_none() {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "no parameter in \"include\" SSI command");
        return NGX_HTTP_SSI_ERROR;
    }

    if set.is_some() && stub.is_some() {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "\"set\" and \"stub\" cannot be used together in \"include\" SSI command");
        return NGX_HTTP_SSI_ERROR;
    }

    // wait != NULL
    let mut wait_set = false;

    if let Some(w) = &wait {
        if uri.is_none() {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "\"wait\" cannot be used with file=\"{}\"", B(file.as_deref().unwrap_or_default()));
            return NGX_HTTP_SSI_ERROR;
        }

        if w.len() == 2 && eq_ignore_case(w, b"no") {
            wait_set = false;
        } else if w.len() != 3 || !eq_ignore_case(w, b"yes") {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid value \"{}\" in the \"wait\" parameter", B(w));
            return NGX_HTTP_SSI_ERROR;
        } else {
            wait_set = true;
        }
    }

    let mut uri = match uri {
        Some(uri) => uri,
        None => {
            // wait = (ngx_str_t *) -1
            wait_set = true;
            file.expect("file")
        }
    };

    let rc = ssi_evaluate_string(r, &mut uri, NGX_HTTP_SSI_ADD_PREFIX);

    if rc != NGX_OK {
        return rc;
    }

    http_debug!(r, "ssi include: \"{}\"", B(&uri));

    let mut args = Vec::new();
    let mut flags: u32 = crate::parse::NGX_HTTP_LOG_UNSAFE;

    if crate::parse::parse_unsafe_uri_args(&r.connection.log, &mut uri, &mut args, flags) != NGX_OK {
        return NGX_HTTP_SSI_ERROR;
    }

    let mctx = match ssi_get_ctx(&r.main()) {
        Some(mctx) => mctx,
        None => return NGX_ERROR,
    };

    let mut ps: Option<PostSubrequest> = None;
    let mut psa: Option<PostSubrequestAsync> = None;

    if let Some(stub) = &stub {
        let blocks = mctx.blocks.borrow().clone();

        let found = blocks.as_ref().and_then(|blocks| {
            let mut bl = blocks.borrow_mut();
            let i = bl.iter().position(|b| b.name == *stub)?;

            // the block's buffers, or a copy of them when used again:
            // a clone does for both here
            bl[i].count += 1;

            Some(bl[i].bufs.clone())
        });

        let out = match found {
            Some(out) => out,
            None => {
                ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "\"stub\"=\"{}\" for \"include\" not found", B(stub));
                return NGX_HTTP_SSI_ERROR;
            }
        };

        psa = Some(Rc::new(move |sr: R, rc: i64| {
            let out = out.clone();
            Box::pin(async move { ssi_stub_output(sr, out, rc).await }) as BoxFut<i64>
        }));
    }

    if wait_set {
        flags |= NGX_HTTP_SUBREQUEST_WAITED;
    }

    if let Some(mut set) = set.clone() {
        let key = hash_strlow(&mut set);

        let value = match ssi_get_variable(r, &set, key) {
            Some(SsiVarRef::Var(vars, i)) => Some((vars, i)),
            // not a variable of the list in C either
            Some(SsiVarRef::Capture(_)) => None,
            None => {
                let variables = mctx.variables_list();

                let i = {
                    let mut vars = variables.borrow_mut();
                    vars.push(SsiVar { name: set, key, value: Vec::new() });
                    vars.len() - 1
                };

                Some((variables, i))
            }
        };

        ps = Some(Rc::new(move |sr: &R, rc: i64| ssi_set_variable(sr, value.as_ref(), rc)));

        flags |= NGX_HTTP_SUBREQUEST_IN_MEMORY | NGX_HTTP_SUBREQUEST_WAITED;
    }

    let sr = match crate::request_rt::subrequest_posted(r, &uri, Some(&args), flags, ps) {
        Ok(sr) => sr,
        Err(()) => return NGX_HTTP_SSI_ERROR,
    };

    if psa.is_some() {
        *sr.post_subrequest_async.borrow_mut() = psa;
    }

    if !wait_set && set.is_none() {
        return NGX_OK;
    }

    if ctx.wait.borrow().is_none() {
        *ctx.wait.borrow_mut() = Some(sr);

        return NGX_AGAIN;
    }

    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "can only wait for one subrequest at a time");

    NGX_OK
}

/// ngx_http_ssi_stub_output
async fn ssi_stub_output(r: R, out: Chain, rc: i64) -> i64 {
    if rc == NGX_ERROR || r.connection.error.get() || r.request_output.get() {
        return rc;
    }

    http_debug!(r, "ssi stub output: \"{}?{}\"", B(&r.uri.borrow()), B(&r.args.borrow()));

    if !r.header_sent.get() {
        if let Some(parent) = r.parent() {
            let (content_type_len, content_type) = {
                let pho = parent.headers_out.borrow();
                (pho.content_type_len, pho.content_type.clone())
            };

            let mut ho = r.headers_out.borrow_mut();
            ho.content_type_len = content_type_len;
            ho.content_type = content_type;
        }

        if crate::core_rt::send_header(&r).await == NGX_ERROR {
            return NGX_ERROR;
        }
    }

    crate::core_rt::output_filter(&r, out).await
}

/// ngx_http_ssi_set_variable: the value is the response in r->out.
fn ssi_set_variable(r: &R, value: Option<&(SsiVariables, usize)>, rc: i64) -> i64 {
    if r.headers_out.borrow().status < NGX_HTTP_SPECIAL_RESPONSE {
        let out = r.out.borrow();

        if let Some(b) = out.front() {
            if let Some((vars, i)) = value {
                vars.borrow_mut()[*i].value = buf_bytes(b, b.pos, b.last).to_vec();
            }
        }
    }

    rc
}

/// ngx_http_ssi_echo
fn ssi_echo(r: &R, ctx: &Rc<SsiCtx>, _command: &[u8], params: &mut SsiParams) -> i64 {
    let var = params[NGX_HTTP_SSI_ECHO_VAR].as_mut().expect("var");

    http_debug!(r, "ssi echo \"{}\"", B(var));

    let key = hash_strlow(var);

    let mut value = ssi_get_variable(r, var, key).map(|v| v.value());

    if value.is_none() {
        match get_variable(r, var) {
            None => return NGX_HTTP_SSI_ERROR,
            Some(vv) => {
                if !vv.not_found {
                    value = Some(vv.data);
                }
            }
        }
    }

    let value = match value {
        None => match &params[NGX_HTTP_SSI_ECHO_DEFAULT] {
            None => NGX_HTTP_SSI_NONE.to_vec(),
            Some(default) => {
                if default.is_empty() {
                    return NGX_OK;
                }
                default.clone()
            }
        },
        Some(value) => {
            if value.is_empty() {
                return NGX_OK;
            }
            value
        }
    };

    if let Some(enc) = &params[NGX_HTTP_SSI_ECHO_ENCODING] {
        if enc.as_slice() == b"none" {
            ctx.encoding.set(NGX_HTTP_SSI_NO_ENCODING);
        } else if enc.as_slice() == b"url" {
            ctx.encoding.set(NGX_HTTP_SSI_URL_ENCODING);
        } else if enc.as_slice() == b"entity" {
            ctx.encoding.set(NGX_HTTP_SSI_ENTITY_ENCODING);
        } else {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "unknown encoding \"{}\" in the \"echo\" command", B(enc));
        }
    }

    let data = match ctx.encoding.get() {
        NGX_HTTP_SSI_URL_ENCODING => ngx_core::string::escape_uri(&value, ngx_core::string::NGX_ESCAPE_HTML),
        NGX_HTTP_SSI_ENTITY_ENCODING => ngx_core::string::escape_html(&value),
        // NGX_HTTP_SSI_NO_ENCODING
        _ => value,
    };

    let mut b = Buf::from_vec(data);
    b.temporary = false;
    b.memory = true;

    ctx.out.borrow_mut().push_back(b);

    NGX_OK
}

/// ngx_http_ssi_config
fn ssi_config(_r: &R, ctx: &Rc<SsiCtx>, _command: &[u8], params: &mut SsiParams) -> i64 {
    if let Some(value) = &params[NGX_HTTP_SSI_CONFIG_TIMEFMT] {
        *ctx.timefmt.borrow_mut() = value.clone();
    }

    if let Some(value) = &params[NGX_HTTP_SSI_CONFIG_ERRMSG] {
        *ctx.errmsg.borrow_mut() = value.clone();
    }

    NGX_OK
}

/// ngx_http_ssi_set
fn ssi_set(r: &R, _ctx: &Rc<SsiCtx>, _command: &[u8], params: &mut SsiParams) -> i64 {
    let mctx = match ssi_get_ctx(&r.main()) {
        Some(mctx) => mctx,
        None => return NGX_ERROR,
    };

    let variables = mctx.variables_list();

    let mut name = params[NGX_HTTP_SSI_SET_VAR].take().expect("var");
    let mut value = params[NGX_HTTP_SSI_SET_VALUE].take().expect("value");

    http_debug!(r, "ssi set \"{}\" \"{}\"", B(&name), B(&value));

    let rc = ssi_evaluate_string(r, &mut value, 0);

    if rc != NGX_OK {
        return rc;
    }

    let key = hash_strlow(&mut name);

    if let Some(vv) = ssi_get_variable(r, &name, key) {
        vv.set(value);
        return NGX_OK;
    }

    http_debug!(r, "set: \"{}\"=\"{}\"", B(&name), B(&value));

    variables.borrow_mut().push(SsiVar { name, key, value });

    NGX_OK
}

/// ngx_http_ssi_if, also for "elif"
fn ssi_if(r: &R, ctx: &Rc<SsiCtx>, command: &[u8], params: &mut SsiParams) -> i64 {
    if command.len() == 2 && ctx.conditional.get() != 0 {
        ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "the \"if\" command inside the \"if\" command");
        return NGX_HTTP_SSI_ERROR;
    }

    if ctx.output_chosen.get() {
        ctx.output.set(false);
        return NGX_OK;
    }

    let expr = params[NGX_HTTP_SSI_IF_EXPR].as_mut().expect("expr");

    http_debug!(r, "ssi if expr=\"{}\"", B(expr));

    let last = expr.len();
    let mut p = 0;

    while p < last {
        let c = expr[p];

        if c.is_ascii_uppercase() {
            expr[p] |= 0x20;
            p += 1;
            continue;
        }

        if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'$' | b'{' | b'}' | b'_' | b'"' | b'\'') {
            p += 1;
            continue;
        }

        break;
    }

    let mut left = expr[..p].to_vec();

    while p < last && expr[p] == b' ' {
        p += 1;
    }

    http_debug!(r, "left: \"{}\"", B(&left));

    let rc = ssi_evaluate_string(r, &mut left, 0);

    if rc != NGX_OK {
        return rc;
    }

    http_debug!(r, "evaluated left: \"{}\"", B(&left));

    if p == last {
        if !left.is_empty() {
            ctx.output.set(true);
            ctx.output_chosen.set(true);
        } else {
            ctx.output.set(false);
        }

        ctx.conditional.set(NGX_HTTP_SSI_COND_IF);

        return NGX_OK;
    }

    'invalid_expression: {
        let negative;

        if expr[p] == b'=' {
            negative = false;
            p += 1;
        } else if p + 1 < last && expr[p] == b'!' && expr[p + 1] == b'=' {
            negative = true;
            p += 2;
        } else {
            break 'invalid_expression;
        }

        while p < last && expr[p] == b' ' {
            p += 1;
        }

        let noregex;
        let flags;
        let mut end = last;

        if p + 1 < last && expr[p] == b'/' {
            if expr[last - 1] != b'/' {
                break 'invalid_expression;
            }

            noregex = false;
            flags = NGX_HTTP_SSI_ADD_ZERO;
            end -= 1;
            p += 1;
        } else {
            noregex = true;
            flags = 0;

            if p + 1 < last && expr[p] == b'\\' && expr[p + 1] == b'/' {
                p += 1;
            }
        }

        let mut right = expr[p..end].to_vec();

        http_debug!(r, "right: \"{}\"", B(&right));

        let rc = ssi_evaluate_string(r, &mut right, flags);

        if rc != NGX_OK {
            return rc;
        }

        http_debug!(r, "evaluated right: \"{}\"", B(&right));

        let rc = if noregex {
            if left.len() != right.len() || left != right {
                -1
            } else {
                0
            }
        } else {
            match ssi_regex_match(r, &right, &left) {
                NGX_OK => 0,
                NGX_DECLINED => -1,
                rc => return rc,
            }
        };

        if (rc == 0 && !negative) || (rc != 0 && negative) {
            ctx.output.set(true);
            ctx.output_chosen.set(true);
        } else {
            ctx.output.set(false);
        }

        ctx.conditional.set(NGX_HTTP_SSI_COND_IF);

        return NGX_OK;
    }

    // invalid_expression:

    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "invalid expression in \"{}\"", B(expr));

    NGX_HTTP_SSI_ERROR
}

/// ngx_http_ssi_else
fn ssi_else(r: &R, ctx: &Rc<SsiCtx>, _command: &[u8], _params: &mut SsiParams) -> i64 {
    http_debug!(r, "ssi else");

    ctx.output.set(!ctx.output_chosen.get());

    ctx.conditional.set(NGX_HTTP_SSI_COND_ELSE);

    NGX_OK
}

/// ngx_http_ssi_endif
fn ssi_endif(r: &R, ctx: &Rc<SsiCtx>, _command: &[u8], _params: &mut SsiParams) -> i64 {
    http_debug!(r, "ssi endif");

    ctx.output.set(true);
    ctx.output_chosen.set(false);
    ctx.conditional.set(0);

    NGX_OK
}

/// ngx_http_ssi_block
fn ssi_block(r: &R, ctx: &Rc<SsiCtx>, _command: &[u8], params: &mut SsiParams) -> i64 {
    http_debug!(r, "ssi block");

    let mctx = match ssi_get_ctx(&r.main()) {
        Some(mctx) => mctx,
        None => return NGX_HTTP_SSI_ERROR,
    };

    let blocks = mctx.blocks.borrow_mut().get_or_insert_with(|| Rc::new(RefCell::new(Vec::new()))).clone();

    blocks.borrow_mut().push(SsiBlock { name: params[NGX_HTTP_SSI_BLOCK_NAME].take().expect("name"), bufs: Chain::new(), count: 0 });

    ctx.output.set(false);
    ctx.block.set(true);

    NGX_OK
}

/// ngx_http_ssi_endblock
fn ssi_endblock(r: &R, ctx: &Rc<SsiCtx>, _command: &[u8], _params: &mut SsiParams) -> i64 {
    http_debug!(r, "ssi endblock");

    ctx.output.set(true);
    ctx.block.set(false);

    NGX_OK
}

/// ngx_http_ssi_date_gmt_local_variable
fn ssi_date_gmt_local_variable(r: &R, v: &mut VariableValue, gmt: usize) -> i64 {
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;

    let now = times::time();

    let timefmt = match ssi_get_ctx(r) {
        Some(ctx) => ctx.timefmt.borrow().clone(),
        None => NGX_HTTP_SSI_TIMEFMT.to_vec(),
    };

    if timefmt.len() == 2 && timefmt[0] == b'%' && timefmt[1] == b's' {
        v.data = now.to_string().into_bytes();
        return NGX_OK;
    }

    // the format is a C string, as ngx_cpystrn() makes it
    let mut fmt: Vec<u8> = timefmt.iter().copied().take_while(|&c| c != 0).collect();
    fmt.push(0);

    // SAFETY: tm is plain data filled in by gmtime_r()/localtime_r() from
    // a valid time_t; strftime() writes at most buf.len() bytes into buf
    // and reads the NUL terminated format.
    let len = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let t: libc::time_t = now as libc::time_t;

        if gmt != 0 {
            libc::gmtime_r(&t, &mut tm);
        } else {
            libc::localtime_r(&t, &mut tm);
        }

        let mut buf = [0u8; NGX_HTTP_SSI_DATE_LEN];
        let n = libc::strftime(buf.as_mut_ptr() as *mut libc::c_char, NGX_HTTP_SSI_DATE_LEN, fmt.as_ptr() as *const libc::c_char, &tm);

        v.data = buf[..n].to_vec();

        n
    };

    if len == 0 {
        return NGX_ERROR;
    }

    NGX_OK
}

/// ngx_http_ssi_preconfiguration
fn ssi_preconfiguration(cf: &mut Conf) -> ConfResult {
    add_variables(cf, &NGX_HTTP_SSI_VARS)?;

    let smcf = get_main_conf::<SsiMainConf>(cf, ctx_index());

    for (i, cmd) in NGX_HTTP_SSI_COMMANDS.iter().enumerate() {
        let rc = smcf.borrow_mut().commands.add_key(cmd.name.to_vec(), i, NGX_HASH_READONLY_KEY);

        if rc == NGX_OK {
            continue;
        }

        if rc == NGX_BUSY {
            return Err(cf.emerg(format_args!("conflicting SSI command \"{}\"", B(cmd.name))));
        }

        return Err(ConfError::Logged);
    }

    Ok(())
}

/// ngx_http_ssi_filter_init
fn ssi_filter_init(_cf: &mut Conf) -> ConfResult {
    crate::install_header_filter_idle(ssi_header_idle, ssi_header_filter);
    crate::install_body_filter_idle(ssi_body_idle, ssi_body_filter);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser(value_len: usize) -> SsiParse {
        SsiParse {
            buf: None,
            pos: 0,
            copy_start: None,
            copy_end: None,
            key: 0,
            command: Vec::new(),
            params: Vec::new(),
            state: SsiState::Start,
            saved_state: SsiState::Start,
            saved: 0,
            looked: 0,
            value_len,
        }
    }

    /// Feeds a buffer to the parser as the body filter does, returning the
    /// results of ngx_http_ssi_parse() with the copied text before each.
    fn feed(p: &mut SsiParse, data: &[u8]) -> Vec<(i64, Vec<u8>)> {
        let log = Log::stderr(NGX_LOG_EMERG);
        let buf = Buf::from_vec(data.to_vec());

        p.pos = buf.pos;
        p.buf = Some(buf);

        if p.state == SsiState::Start {
            p.copy_start = Some(p.pos);
            p.copy_end = Some(p.pos);
        }

        let mut res = Vec::new();

        while p.pos < p.buf.as_ref().unwrap().last {
            let rc = ssi_parse(&log, p);

            let copied = match (p.copy_start, p.copy_end) {
                (Some(s), Some(e)) if s != e => buf_bytes(p.buf.as_ref().unwrap(), s, e).to_vec(),
                _ => Vec::new(),
            };

            res.push((rc, copied));

            if p.state == SsiState::Start {
                p.copy_start = Some(p.pos);
                p.copy_end = Some(p.pos);
            } else {
                p.copy_start = None;
                p.copy_end = None;
            }
        }

        p.buf = None;
        p.saved = p.looked;

        res
    }

    #[test]
    fn test_parse_command() {
        let mut p = parser(255);
        let res = feed(&mut p, b"ab<!--# echo var=\"x\" default='a\\'b' -->cd");

        assert_eq!(res[0], (NGX_OK, b"ab".to_vec()));
        assert_eq!(p.command, b"echo");
        assert_eq!(p.key, hash_key(b"echo"));
        assert_eq!(p.params, vec![(b"var".to_vec(), b"x".to_vec()), (b"default".to_vec(), b"a\\'b".to_vec())]);
        assert_eq!(res[1], (NGX_AGAIN, b"cd".to_vec()));
    }

    #[test]
    fn test_parse_split_tag() {
        // "<!-" at the end of a buffer is kept (ctx->saved) until it is
        // known not to start a command
        let mut p = parser(255);
        let res = feed(&mut p, b"x<!-");
        assert_eq!(res, vec![(NGX_AGAIN, b"x".to_vec())]);
        assert_eq!(p.saved, 3);

        let res = feed(&mut p, b"-y");
        assert_eq!(res, vec![(NGX_AGAIN, b"-y".to_vec())]);
        assert_eq!(p.state, SsiState::Start);

        let mut p = parser(255);
        feed(&mut p, b"<!-");
        let res = feed(&mut p, b"-#endif-->z");
        assert_eq!(p.saved, 0);
        assert_eq!(res[0], (NGX_OK, Vec::new()));
        assert_eq!(p.command, b"endif");
        assert_eq!(res[1], (NGX_AGAIN, b"z".to_vec()));
    }

    #[test]
    fn test_parse_errors() {
        let mut p = parser(255);
        let res = feed(&mut p, b"<!--#echo var=x -->a");
        assert_eq!(res[0].0, NGX_HTTP_SSI_ERROR);
        assert_eq!(res[1], (NGX_AGAIN, b"a".to_vec()));

        // too long a value
        let mut p = parser(3);
        let res = feed(&mut p, b"<!--#set var=\"abcd\" value=\"\" -->");
        assert_eq!(res[0].0, NGX_HTTP_SSI_ERROR);

        let mut p = parser(4);
        let res = feed(&mut p, b"<!--#set var=\"abcd\" value=\"\" -->");
        assert_eq!(res[0].0, NGX_OK);

        // too long a command
        let mut p = parser(255);
        let long = [b'x'; NGX_HTTP_SSI_COMMAND_LEN + 1];
        let mut data = b"<!--#".to_vec();
        data.extend_from_slice(&long);
        data.extend_from_slice(b" -->");
        let res = feed(&mut p, &data);
        assert_eq!(res[0].0, NGX_HTTP_SSI_ERROR);
    }

    #[test]
    fn test_parse_not_a_command() {
        let mut p = parser(255);
        let res = feed(&mut p, b"a<b<!x<!--y");
        assert_eq!(res, vec![(NGX_AGAIN, b"a<b<!x<!--y".to_vec())]);
    }

    fn eval(uri: &[u8], text: &[u8], flags: u32) -> (i64, Vec<u8>) {
        let log = Log::stderr(NGX_LOG_EMERG);
        let mut lookup = |var: &[u8], key: usize| -> Option<Option<Vec<u8>>> {
            assert_eq!(key, hash_key(var));
            match var {
                b"a" => Some(Some(b"A".to_vec())),
                b"path" => Some(Some(b"/p/q".to_vec())),
                b"rel" => Some(Some(b"r.html".to_vec())),
                b"empty" => Some(Some(Vec::new())),
                b"error" => None,
                _ => Some(None),
            }
        };
        let mut text = text.to_vec();
        let rc = evaluate_string(&log, uri, &mut text, flags, &mut lookup);
        (rc, text)
    }

    #[test]
    fn test_evaluate_string() {
        // no variables: the escapes, and a lone backslash at the end dropped
        assert_eq!(eval(b"/", br#"a\b\\c\$d\"e\'f\"#, 0), (NGX_OK, br#"a\b\c$d"e'f"#.to_vec()));
        // variables, lowercased, with and without brackets
        assert_eq!(eval(b"/", b"x$A-${a}y", 0), (NGX_OK, b"xA-Ay".to_vec()));
        // "$ay" is a variable named "ay", not found: nothing
        assert_eq!(eval(b"/", b"[$ay]", 0), (NGX_OK, b"[]".to_vec()));
        assert_eq!(eval(b"/", b"[$empty]\\$a", 0), (NGX_OK, b"[]$a".to_vec()));
        // errors
        assert_eq!(eval(b"/", b"x$", 0).0, NGX_HTTP_SSI_ERROR);
        assert_eq!(eval(b"/", b"x${", 0).0, NGX_HTTP_SSI_ERROR);
        assert_eq!(eval(b"/", b"x${a", 0).0, NGX_HTTP_SSI_ERROR);
        assert_eq!(eval(b"/", b"x$-", 0).0, NGX_HTTP_SSI_ERROR);
        assert_eq!(eval(b"/", b"$error", 0).0, NGX_ERROR);
        // the prefix of relative includes
        assert_eq!(eval(b"/dir/page.html", b"inc.html", NGX_HTTP_SSI_ADD_PREFIX), (NGX_OK, b"/dir/inc.html".to_vec()));
        assert_eq!(eval(b"/dir/page.html", b"/inc.html", NGX_HTTP_SSI_ADD_PREFIX), (NGX_OK, b"/inc.html".to_vec()));
        assert_eq!(eval(b"/dir/page.html", b"$rel", NGX_HTTP_SSI_ADD_PREFIX), (NGX_OK, b"/dir/r.html".to_vec()));
        assert_eq!(eval(b"/dir/page.html", b"$path/x", NGX_HTTP_SSI_ADD_PREFIX), (NGX_OK, b"/p/q/x".to_vec()));
        // the first non-empty part decides
        assert_eq!(eval(b"/dir/page.html", b"$empty$path", NGX_HTTP_SSI_ADD_PREFIX), (NGX_OK, b"/p/q".to_vec()));
        assert_eq!(eval(b"page.html", b"x.html", NGX_HTTP_SSI_ADD_PREFIX), (NGX_OK, b"x.html".to_vec()));
    }

    #[test]
    fn test_hash_strlow() {
        let mut s = b"ArG_V".to_vec();
        assert_eq!(hash_strlow(&mut s), hash_key(b"arg_v"));
        assert_eq!(s, b"arg_v");
        // a one character name hashes to itself: the captures
        let mut s = b"1".to_vec();
        assert_eq!(hash_strlow(&mut s), b'1' as usize);
    }

    #[test]
    fn test_copy_buf() {
        let mut src = Buf::from_vec(b"0123456789".to_vec());
        src.flush = true;
        src.last_buf = true;
        src.recycled = true;
        let b = ssi_copy_buf(&src, 2, 5);
        assert_eq!(buf_bytes(&b, b.pos, b.last), b"234");
        assert!(b.flush && !b.last_buf && !b.recycled && b.in_memory());
    }
}
