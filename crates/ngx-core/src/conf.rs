//! Configuration file parsing, ported from ngx_conf_file.c.

use std::any::Any;
use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;

use crate::cycle::Cycle;
use crate::log::*;
use crate::module::*;
use crate::string::{atoi, eq_ignore_case, B};
use crate::{ngx_log_error, parse};

pub const NGX_CONF_NOARGS: u32 = 0x00000001;
pub const NGX_CONF_TAKE1: u32 = 0x00000002;
pub const NGX_CONF_TAKE2: u32 = 0x00000004;
pub const NGX_CONF_TAKE3: u32 = 0x00000008;
pub const NGX_CONF_TAKE4: u32 = 0x00000010;
pub const NGX_CONF_TAKE5: u32 = 0x00000020;
pub const NGX_CONF_TAKE6: u32 = 0x00000040;
pub const NGX_CONF_TAKE7: u32 = 0x00000080;
pub const NGX_CONF_MAX_ARGS: usize = 8;
pub const NGX_CONF_TAKE12: u32 = NGX_CONF_TAKE1 | NGX_CONF_TAKE2;
pub const NGX_CONF_TAKE13: u32 = NGX_CONF_TAKE1 | NGX_CONF_TAKE3;
pub const NGX_CONF_TAKE23: u32 = NGX_CONF_TAKE2 | NGX_CONF_TAKE3;
pub const NGX_CONF_TAKE123: u32 = NGX_CONF_TAKE1 | NGX_CONF_TAKE2 | NGX_CONF_TAKE3;
pub const NGX_CONF_TAKE1234: u32 = NGX_CONF_TAKE1 | NGX_CONF_TAKE2 | NGX_CONF_TAKE3 | NGX_CONF_TAKE4;
pub const NGX_CONF_ARGS_NUMBER: u32 = 0x000000ff;
pub const NGX_CONF_BLOCK: u32 = 0x00000100;
pub const NGX_CONF_FLAG: u32 = 0x00000200;
pub const NGX_CONF_ANY: u32 = 0x00000400;
pub const NGX_CONF_1MORE: u32 = 0x00000800;
pub const NGX_CONF_2MORE: u32 = 0x00001000;

pub const NGX_DIRECT_CONF: u32 = 0x00010000;
pub const NGX_MAIN_CONF: u32 = 0x01000000;
pub const NGX_ANY_CONF: u32 = 0x1F000000;

pub const NGX_CONF_BUFFER: usize = 4096;

static ARGUMENT_NUMBER: [u32; 8] = [
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2,
    NGX_CONF_TAKE3,
    NGX_CONF_TAKE4,
    NGX_CONF_TAKE5,
    NGX_CONF_TAKE6,
    NGX_CONF_TAKE7,
];

/// Error from a directive handler. `Logged` means the message was already
/// emitted via conf_log_error; `Msg` is appended as `"name" directive <msg>`.
#[derive(Debug)]
pub enum ConfError {
    Logged,
    Msg(String),
}

pub type ConfResult = Result<(), ConfError>;

pub fn msg<T: Into<String>>(s: T) -> ConfError {
    ConfError::Msg(s.into())
}

/// Which per-context slot array a command's conf comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfLevel {
    None,
    Main,
    Srv,
    Loc,
}

pub type ConfSet = fn(&mut Conf, &Command, Option<Rc<dyn Any>>) -> ConfResult;

pub struct Command {
    pub name: &'static str,
    pub ty: u32,
    pub set: ConfSet,
    pub conf: ConfLevel,
}

impl Command {
    pub const fn new(name: &'static str, ty: u32, conf: ConfLevel, set: ConfSet) -> Command {
        Command { name, ty, set, conf }
    }
}

/// Per-context slots: one optional conf object per module of a type, indexed by ctx_index.
pub type ConfSlots = RefCell<Vec<Option<Rc<dyn Any>>>>;

#[derive(Clone, Default)]
pub struct ConfCtx {
    pub main: Option<Rc<ConfSlots>>,
    pub srv: Option<Rc<ConfSlots>>,
    pub loc: Option<Rc<ConfSlots>>,
}

pub fn new_slots(n: usize) -> Rc<ConfSlots> {
    Rc::new(RefCell::new(vec![None; n]))
}

impl ConfCtx {
    pub fn get(&self, level: ConfLevel, ctx_index: usize) -> Option<Rc<dyn Any>> {
        let slots = match level {
            ConfLevel::Main => self.main.as_ref(),
            ConfLevel::Srv => self.srv.as_ref(),
            ConfLevel::Loc => self.loc.as_ref(),
            ConfLevel::None => None,
        }?;
        let v = slots.borrow();
        v.get(ctx_index).cloned().flatten()
    }
}

/// Downcast a conf slot to the module's RefCell<T>.
pub fn conf_cell<T: 'static>(c: &Rc<dyn Any>) -> &RefCell<T> {
    c.downcast_ref::<RefCell<T>>().expect("conf slot type mismatch")
}

pub fn conf_rc<T: 'static>(c: &Rc<dyn Any>) -> Rc<RefCell<T>> {
    c.clone().downcast::<RefCell<T>>().ok().expect("conf slot type mismatch")
}

pub fn slot_of<T: 'static>(slots: &Rc<ConfSlots>, idx: usize) -> Rc<RefCell<T>> {
    let v = slots.borrow();
    conf_rc::<T>(v[idx].as_ref().expect("conf slot empty"))
}

pub fn make_slot<T: 'static>(v: T) -> Rc<dyn Any> {
    Rc::new(RefCell::new(v))
}

// ---------------------------------------------------------------------------
// Val<T>: optionally-set config value with nginx merge semantics.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Val<T>(pub Option<T>);

impl<T> Default for Val<T> {
    fn default() -> Self {
        Val(None)
    }
}

impl<T: Clone> Val<T> {
    pub const fn unset() -> Val<T> {
        Val(None)
    }
    pub fn set(v: T) -> Val<T> {
        Val(Some(v))
    }
    pub fn is_set(&self) -> bool {
        self.0.is_some()
    }
    pub fn get(&self) -> &T {
        self.0.as_ref().expect("configuration value not set")
    }
    pub fn get_or(&self, d: T) -> T {
        self.0.clone().unwrap_or(d)
    }
    pub fn as_option(&self) -> Option<&T> {
        self.0.as_ref()
    }
    /// ngx_conf_merge_value: if unset, take prev if set else default.
    pub fn merge(&mut self, prev: &Val<T>, default: T) {
        if self.0.is_none() {
            self.0 = Some(prev.0.clone().unwrap_or(default));
        }
    }
    /// ngx_conf_init_value: if unset, take default.
    pub fn init(&mut self, default: T) {
        if self.0.is_none() {
            self.0 = Some(default);
        }
    }
    /// Merge where the default is itself an Option (ptr may stay NULL).
    pub fn merge_opt(&mut self, prev: &Val<T>) {
        if self.0.is_none() {
            self.0 = prev.0.clone();
        }
    }
}

impl<T> Deref for Val<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0.as_ref().expect("configuration value not set")
    }
}

/// ngx_bufs_t
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bufs {
    pub num: usize,
    pub size: usize,
}

impl Bufs {
    pub fn is_set(&self) -> bool {
        self.num != 0
    }
    pub fn merge(&mut self, prev: &Bufs, num: usize, size: usize) {
        if self.num == 0 {
            if prev.num != 0 {
                *self = *prev;
            } else {
                self.num = num;
                self.size = size;
            }
        }
    }
}

/// ngx_path_t
pub struct PathConf {
    pub name: Vec<u8>,
    pub len: usize,
    pub level: [usize; 3],
    pub conf_file: Vec<u8>,
    pub line: usize,
    /// Cache manager/loader/purger hooks and data (set by file cache).
    pub data: RefCell<Option<Rc<dyn Any>>>,
    pub manager: RefCell<Option<Rc<dyn Fn(&Rc<dyn Any>) -> u64>>>,
    pub loader: RefCell<Option<Rc<dyn Fn(&Rc<dyn Any>)>>>,
    pub purger: RefCell<Option<Rc<dyn Fn(&Rc<dyn Any>) -> u64>>>,
}

impl PathConf {
    pub fn new(name: Vec<u8>, level: [usize; 3]) -> PathConf {
        let len = level.iter().filter(|&&l| l > 0).map(|l| l + 1).sum();
        PathConf { name, len, level, conf_file: Vec::new(), line: 0, data: RefCell::new(None), manager: RefCell::new(None), loader: RefCell::new(None), purger: RefCell::new(None) }
    }

    /// Build hashed file name: name + "/" + levels of md5 hex key + "/" + key (ngx_create_hashed_filename)
    pub fn hashed_filename(&self, key: &[u8]) -> Vec<u8> {
        // key is hex string of the md5 (32 chars)
        let mut out = self.name.clone();
        let mut pos = key.len();
        for &lvl in self.level.iter() {
            if lvl == 0 {
                break;
            }
            out.push(b'/');
            pos -= lvl;
            out.extend_from_slice(&key[pos..pos + lvl]);
        }
        out.push(b'/');
        out.extend_from_slice(key);
        out
    }
}

// ---------------------------------------------------------------------------

pub struct ConfFile {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub pos: usize,
    pub line: usize,
    /// index into cycle.config_dump if dumping
    pub dump: Option<usize>,
    /// true when parsing "-g" params (no file)
    pub is_param: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Token {
    Ok,
    BlockStart,
    BlockDone,
    FileDone,
}

pub type ConfHandler = fn(&mut Conf, Rc<dyn Any>) -> ConfResult;

pub struct Conf<'c> {
    pub args: Vec<Vec<u8>>,
    pub cycle: &'c mut Cycle,
    pub conf_file: Option<ConfFile>,
    pub module_type: u32,
    pub cmd_type: u32,
    pub ctx: ConfCtx,
    pub handler: Option<ConfHandler>,
    pub handler_conf: Option<Rc<dyn Any>>,
    pub log: Log,
    /// index in cycle.modules of the module whose directive is being handled
    pub module_index: usize,
}

impl<'c> Conf<'c> {
    pub fn new(cycle: &'c mut Cycle, log: Log) -> Conf<'c> {
        Conf {
            args: Vec::new(),
            cycle,
            conf_file: None,
            module_type: NGX_CORE_MODULE,
            cmd_type: NGX_MAIN_CONF,
            ctx: ConfCtx::default(),
            handler: None,
            handler_conf: None,
            log,
            module_index: 0,
        }
    }

    pub fn modules(&self) -> Rc<Vec<Module>> {
        self.cycle.modules.clone()
    }

    pub fn module(&self) -> &Module {
        &self.cycle.modules[self.module_index]
    }

    /// Log a config error with " in file:line" suffix (ngx_conf_log_error).
    pub fn log_error(&self, level: u32, err: Option<i32>, args: std::fmt::Arguments<'_>) {
        let mut m = String::new();
        use std::fmt::Write;
        let _ = m.write_fmt(args);
        if let Some(e) = err {
            if e != 0 {
                let _ = write!(m, " ({}: {})", e, strerror(e));
            }
        }
        match &self.conf_file {
            None => ngx_log_error!(level, self.log, None, "{}", m),
            Some(cf) if cf.is_param => ngx_log_error!(level, self.log, None, "{} in command line", m),
            Some(cf) => ngx_log_error!(level, self.log, None, "{} in {}:{}", m, B(&cf.name), cf.line),
        }
    }

    pub fn emerg(&self, args: std::fmt::Arguments<'_>) -> ConfError {
        self.log_error(NGX_LOG_EMERG, None, args);
        ConfError::Logged
    }

    pub fn warn(&self, args: std::fmt::Arguments<'_>) {
        self.log_error(NGX_LOG_WARN, None, args);
    }

    pub fn conf_file_name(&self) -> Vec<u8> {
        self.conf_file.as_ref().map(|c| c.name.clone()).unwrap_or_default()
    }

    pub fn conf_line(&self) -> usize {
        self.conf_file.as_ref().map(|c| c.line).unwrap_or(0)
    }

    /// ngx_conf_param: parse "-g" directives.
    pub fn parse_param(&mut self) -> ConfResult {
        let param = self.cycle.conf_param.clone();
        if param.is_empty() {
            return Ok(());
        }
        let prev = self.conf_file.take();
        self.conf_file = Some(ConfFile { name: Vec::new(), data: param, pos: 0, line: 0, dump: None, is_param: true });
        let r = self.parse_inner(ParseType::Param);
        self.conf_file = prev;
        r
    }

    /// ngx_conf_parse(cf, filename)
    pub fn parse_file(&mut self, filename: &[u8]) -> ConfResult {
        let data = match std::fs::read(std::ffi::OsStr::from_bytes(filename)) {
            Ok(d) => d,
            Err(e) => {
                let en = e.raw_os_error().unwrap_or(0);
                self.log_error(NGX_LOG_EMERG, Some(en), format_args!("open() \"{}\" failed", B(filename)));
                return Err(ConfError::Logged);
            }
        };
        let dump = self.cycle.add_config_dump(filename, &data);
        let prev = self.conf_file.take();
        self.conf_file = Some(ConfFile { name: filename.to_vec(), data, pos: 0, line: 1, dump, is_param: false });
        let r = self.parse_inner(ParseType::File);
        self.conf_file = prev;
        r
    }

    /// Parse the body of a block (after "{") until the matching "}".
    pub fn parse_block(&mut self) -> ConfResult {
        self.parse_inner(ParseType::Block)
    }

    fn parse_inner(&mut self, ty: ParseType) -> ConfResult {
        loop {
            let rc = self.read_token()?;
            match rc {
                Token::BlockDone => {
                    if ty != ParseType::Block {
                        return Err(self.emerg(format_args!("unexpected \"}}\"")));
                    }
                    return Ok(());
                }
                Token::FileDone => {
                    if ty == ParseType::Block {
                        return Err(self.emerg(format_args!("unexpected end of file, expecting \"}}\"")));
                    }
                    return Ok(());
                }
                Token::BlockStart => {
                    if ty == ParseType::Param {
                        return Err(self.emerg(format_args!("block directives are not supported in -g option")));
                    }
                }
                Token::Ok => {}
            }

            if let Some(h) = self.handler {
                if rc == Token::BlockStart {
                    return Err(self.emerg(format_args!("unexpected \"{{\"")));
                }
                let hc = self.handler_conf.clone().expect("handler conf");
                match h(self, hc) {
                    Ok(()) => continue,
                    Err(ConfError::Logged) => return Err(ConfError::Logged),
                    Err(ConfError::Msg(m)) => {
                        return Err(self.emerg(format_args!("{}", m)));
                    }
                }
            }

            self.handle_directive(rc)?;
        }
    }

    fn handle_directive(&mut self, last: Token) -> ConfResult {
        let name = self.args[0].clone();
        let modules = self.cycle.modules.clone();
        let mut found = false;

        for m in modules.iter() {
            for cmd in m.def.commands.iter() {
                if cmd.name.as_bytes() != name.as_slice() {
                    continue;
                }
                found = true;
                if m.def.ty != NGX_CONF_MODULE && m.def.ty != self.module_type {
                    continue;
                }
                if cmd.ty & self.cmd_type == 0 {
                    continue;
                }
                if cmd.ty & NGX_CONF_BLOCK == 0 && last != Token::Ok {
                    return Err(self.emerg(format_args!("directive \"{}\" is not terminated by \";\"", B(&name))));
                }
                if cmd.ty & NGX_CONF_BLOCK != 0 && last != Token::BlockStart {
                    return Err(self.emerg(format_args!("directive \"{}\" has no opening \"{{\"", B(&name))));
                }
                let nargs = self.args.len();
                if cmd.ty & NGX_CONF_ANY == 0 {
                    let invalid = if cmd.ty & NGX_CONF_FLAG != 0 {
                        nargs != 2
                    } else if cmd.ty & NGX_CONF_1MORE != 0 {
                        nargs < 2
                    } else if cmd.ty & NGX_CONF_2MORE != 0 {
                        nargs < 3
                    } else if nargs > NGX_CONF_MAX_ARGS {
                        true
                    } else {
                        cmd.ty & ARGUMENT_NUMBER[nargs - 1] == 0
                    };
                    if invalid {
                        return Err(self.emerg(format_args!("invalid number of arguments in \"{}\" directive", B(&name))));
                    }
                }

                let conf: Option<Rc<dyn Any>> = if cmd.ty & NGX_DIRECT_CONF != 0 {
                    self.cycle.conf_ctx[m.index].clone()
                } else if cmd.ty & NGX_MAIN_CONF != 0 {
                    None
                } else {
                    self.ctx.get(cmd.conf, m.ctx_index)
                };

                let saved_index = self.module_index;
                self.module_index = m.index;
                let rv = (cmd.set)(self, cmd, conf);
                self.module_index = saved_index;

                return match rv {
                    Ok(()) => Ok(()),
                    Err(ConfError::Logged) => Err(ConfError::Logged),
                    Err(ConfError::Msg(msg)) => Err(self.emerg(format_args!("\"{}\" directive {}", B(&name), msg))),
                };
            }
        }

        if found {
            return Err(self.emerg(format_args!("\"{}\" directive is not allowed here", B(&name))));
        }
        Err(self.emerg(format_args!("unknown directive \"{}\"", B(&name))))
    }

    /// Port of ngx_conf_read_token over the in-memory buffer.
    fn read_token(&mut self) -> Result<Token, ConfError> {
        self.args.clear();
        let cf = self.conf_file.as_mut().expect("conf file");
        let data = std::mem::take(&mut cf.data);
        let r = read_token_impl(cf, &data, &mut self.args);
        let cf = self.conf_file.as_mut().unwrap();
        cf.data = data;
        match r {
            Ok(t) => Ok(t),
            Err(m) => Err(self.emerg(format_args!("{}", m))),
        }
    }

    /// Resolve a name against the prefix (ngx_conf_full_name).
    pub fn full_name(&self, name: &[u8], conf_prefix: bool) -> Vec<u8> {
        self.cycle.full_name(name, conf_prefix)
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum ParseType {
    File,
    Block,
    Param,
}

fn read_token_impl(cf: &mut ConfFile, b: &[u8], args: &mut Vec<Vec<u8>>) -> Result<Token, String> {
    let mut found = false;
    let mut need_space = false;
    let mut last_space = true;
    let mut sharp_comment = false;
    let mut variable = false;
    let mut quoted = false;
    let mut s_quoted = false;
    let mut d_quoted = false;

    let mut start = cf.pos;
    let mut start_line = cf.line;

    loop {
        if cf.pos >= b.len() {
            if !args.is_empty() || !last_space {
                if cf.is_param {
                    return Err("unexpected end of parameter, expecting \";\"".into());
                }
                return Err("unexpected end of file, expecting \";\" or \"}\"".into());
            }
            return Ok(Token::FileDone);
        }

        if cf.pos - start >= NGX_CONF_BUFFER {
            cf.line = start_line;
            let ch = if d_quoted {
                '"'
            } else if s_quoted {
                '\''
            } else {
                let end = (start + 10).min(b.len());
                return Err(format!("too long parameter \"{}...\" started", B(&b[start..end])));
            };
            return Err(format!("too long parameter, probably missing terminating \"{}\" character", ch));
        }

        let ch = b[cf.pos];
        cf.pos += 1;

        if ch == b'\n' {
            cf.line += 1;
            if sharp_comment {
                sharp_comment = false;
            }
        }

        if sharp_comment {
            continue;
        }

        if quoted {
            quoted = false;
            continue;
        }

        if need_space {
            if ch == b' ' || ch == b'\t' || ch == b'\r' || ch == b'\n' {
                last_space = true;
                need_space = false;
                continue;
            }
            if ch == b';' {
                return Ok(Token::Ok);
            }
            if ch == b'{' {
                return Ok(Token::BlockStart);
            }
            if ch == b')' {
                last_space = true;
                need_space = false;
            } else {
                return Err(format!("unexpected \"{}\"", ch as char));
            }
        }

        if last_space {
            start = cf.pos - 1;
            start_line = cf.line;

            if ch == b' ' || ch == b'\t' || ch == b'\r' || ch == b'\n' {
                continue;
            }

            match ch {
                b';' | b'{' => {
                    if args.is_empty() {
                        return Err(format!("unexpected \"{}\"", ch as char));
                    }
                    if ch == b'{' {
                        return Ok(Token::BlockStart);
                    }
                    return Ok(Token::Ok);
                }
                b'}' => {
                    if !args.is_empty() {
                        return Err("unexpected \"}\"".into());
                    }
                    return Ok(Token::BlockDone);
                }
                b'#' => {
                    sharp_comment = true;
                    continue;
                }
                b'\\' => {
                    quoted = true;
                    last_space = false;
                    continue;
                }
                b'"' => {
                    start += 1;
                    d_quoted = true;
                    last_space = false;
                    continue;
                }
                b'\'' => {
                    start += 1;
                    s_quoted = true;
                    last_space = false;
                    continue;
                }
                b'$' => {
                    variable = true;
                    last_space = false;
                    continue;
                }
                _ => {
                    last_space = false;
                }
            }
        } else {
            if ch == b'{' && variable {
                continue;
            }
            variable = false;

            if ch == b'\\' {
                quoted = true;
                continue;
            }

            if ch == b'$' {
                variable = true;
                continue;
            }

            if d_quoted {
                if ch == b'"' {
                    d_quoted = false;
                    need_space = true;
                    found = true;
                }
            } else if s_quoted {
                if ch == b'\'' {
                    s_quoted = false;
                    need_space = true;
                    found = true;
                }
            } else if ch == b' ' || ch == b'\t' || ch == b'\r' || ch == b'\n' || ch == b';' || ch == b'{' {
                last_space = true;
                found = true;
            }

            if found {
                let end = cf.pos - 1;
                let mut word = Vec::with_capacity(end - start);
                let mut src = start;
                while src < end {
                    if b[src] == b'\\' && src + 1 < end + 1 {
                        match b.get(src + 1).copied() {
                            Some(b'"') | Some(b'\'') | Some(b'\\') => {
                                src += 1;
                            }
                            Some(b't') => {
                                word.push(b'\t');
                                src += 2;
                                continue;
                            }
                            Some(b'r') => {
                                word.push(b'\r');
                                src += 2;
                                continue;
                            }
                            Some(b'n') => {
                                word.push(b'\n');
                                src += 2;
                                continue;
                            }
                            _ => {}
                        }
                    }
                    word.push(b[src]);
                    src += 1;
                }
                args.push(word);

                if ch == b';' {
                    return Ok(Token::Ok);
                }
                if ch == b'{' {
                    return Ok(Token::BlockStart);
                }
                found = false;
            }
        }
    }
}

use std::os::unix::ffi::OsStrExt;

// ---------------------------------------------------------------------------
// Generic slot setters (ngx_conf_set_*_slot).

pub fn set_flag(cf: &Conf, cmd: &Command, slot: &mut Val<bool>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    let v = &cf.args[1];
    if eq_ignore_case(v, b"on") {
        *slot = Val::set(true);
    } else if eq_ignore_case(v, b"off") {
        *slot = Val::set(false);
    } else {
        return Err(cf.emerg(format_args!(
            "invalid value \"{}\" in \"{}\" directive, it must be \"on\" or \"off\"",
            B(v),
            cmd.name
        )));
    }
    Ok(())
}

pub fn set_str(cf: &Conf, _cmd: &Command, slot: &mut Val<Vec<u8>>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    *slot = Val::set(cf.args[1].clone());
    Ok(())
}

pub fn set_str_array(cf: &Conf, _cmd: &Command, slot: &mut Val<Vec<Vec<u8>>>) -> ConfResult {
    if !slot.is_set() {
        *slot = Val::set(Vec::new());
    }
    slot.0.as_mut().unwrap().push(cf.args[1].clone());
    Ok(())
}

pub fn set_keyval(cf: &Conf, _cmd: &Command, slot: &mut Val<Vec<(Vec<u8>, Vec<u8>)>>) -> ConfResult {
    if !slot.is_set() {
        *slot = Val::set(Vec::new());
    }
    slot.0.as_mut().unwrap().push((cf.args[1].clone(), cf.args[2].clone()));
    Ok(())
}

pub fn set_num(cf: &Conf, _cmd: &Command, slot: &mut Val<i64>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    match atoi(&cf.args[1]) {
        Some(v) => {
            *slot = Val::set(v);
            Ok(())
        }
        None => Err(msg("invalid number")),
    }
}

pub fn set_size(cf: &Conf, _cmd: &Command, slot: &mut Val<usize>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    match parse::parse_size(&cf.args[1]) {
        Some(v) => {
            *slot = Val::set(v);
            Ok(())
        }
        None => Err(msg("invalid value")),
    }
}

pub fn set_off(cf: &Conf, _cmd: &Command, slot: &mut Val<i64>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    match parse::parse_offset(&cf.args[1]) {
        Some(v) => {
            *slot = Val::set(v);
            Ok(())
        }
        None => Err(msg("invalid value")),
    }
}

pub fn set_msec(cf: &Conf, _cmd: &Command, slot: &mut Val<u64>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    match parse::parse_time(&cf.args[1], false) {
        Some(v) => {
            *slot = Val::set(v as u64);
            Ok(())
        }
        None => Err(msg("invalid value")),
    }
}

pub fn set_sec(cf: &Conf, _cmd: &Command, slot: &mut Val<i64>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    match parse::parse_time(&cf.args[1], true) {
        Some(v) => {
            *slot = Val::set(v);
            Ok(())
        }
        None => Err(msg("invalid value")),
    }
}

pub fn set_bufs(cf: &Conf, _cmd: &Command, slot: &mut Bufs) -> ConfResult {
    if slot.num != 0 {
        return Err(msg("is duplicate"));
    }
    let num = atoi(&cf.args[1]);
    match num {
        Some(n) if n > 0 => slot.num = n as usize,
        _ => return Err(msg("invalid value")),
    }
    match parse::parse_size(&cf.args[2]) {
        Some(s) if s > 0 => slot.size = s,
        _ => {
            slot.num = 0;
            return Err(msg("invalid value"));
        }
    }
    Ok(())
}

pub fn set_enum(cf: &Conf, _cmd: &Command, slot: &mut Val<u32>, values: &[(&str, u32)]) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    let v = &cf.args[1];
    for (name, val) in values {
        if eq_ignore_case(name.as_bytes(), v) {
            *slot = Val::set(*val);
            return Ok(());
        }
    }
    Err(cf.emerg(format_args!("invalid value \"{}\"", B(v))))
}

pub fn set_bitmask(cf: &Conf, _cmd: &Command, slot: &mut u32, masks: &[(&str, u32)]) -> ConfResult {
    for v in &cf.args[1..] {
        let mut matched = false;
        for (name, mask) in masks {
            if eq_ignore_case(name.as_bytes(), v) {
                if *slot & *mask != 0 {
                    cf.warn(format_args!("duplicate value \"{}\"", B(v)));
                } else {
                    *slot |= *mask;
                }
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(cf.emerg(format_args!("invalid value \"{}\"", B(v))));
        }
    }
    Ok(())
}

/// ngx_conf_check_num_bounds
pub fn check_num_bounds(cf: &Conf, v: i64, low: i64, high: i64) -> ConfResult {
    if high == -1 {
        if v >= low {
            return Ok(());
        }
        return Err(cf.emerg(format_args!("value must be equal to or greater than {}", low)));
    }
    if v >= low && v <= high {
        return Ok(());
    }
    Err(cf.emerg(format_args!("value must be between {} and {}", low, high)))
}

/// ngx_conf_set_access_slot: "user:rw group:r all:r"
pub fn set_access(cf: &Conf, _cmd: &Command, slot: &mut Val<u32>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    let mut right: u32 = 0;
    let mut shift: u32;
    for v in &cf.args[1..] {
        let mut p: &[u8] = v;
        if p.starts_with(b"user:") {
            shift = 6;
            p = &p[5..];
        } else if p.starts_with(b"group:") {
            shift = 3;
            p = &p[6..];
        } else if p.starts_with(b"all:") {
            shift = 0;
            p = &p[4..];
        } else {
            return Err(msg("invalid value"));
        }
        let mode = if p == b"rw" {
            6
        } else if p == b"r" {
            4
        } else {
            return Err(msg("invalid value"));
        };
        right |= mode << shift;
    }
    *slot = Val::set(right);
    Ok(())
}

/// ngx_conf_set_path_slot: "path [level1 [level2 [level3]]]"
pub fn set_path(cf: &mut Conf, _cmd: &Command, slot: &mut Val<Rc<PathConf>>) -> ConfResult {
    if slot.is_set() {
        return Err(msg("is duplicate"));
    }
    let mut name = cf.args[1].clone();
    if name.len() > 1 && name.ends_with(b"/") {
        name.pop();
    }
    let name = cf.full_name(&name, false);
    let mut level = [0usize; 3];
    let mut n = 0;
    for (i, v) in cf.args.iter().skip(2).enumerate() {
        if i >= 3 {
            break;
        }
        let l = atoi(v);
        match l {
            Some(l) if l == 1 || l == 2 => level[i] = l as usize,
            _ => return Err(msg("invalid value")),
        }
        n += level[i] + 1;
    }
    let _ = n;
    let mut path = PathConf::new(name, level);
    path.conf_file = cf.conf_file_name();
    path.line = cf.conf_line();
    let (log, cfn, line) = (cf.log.clone(), cf.conf_file_name(), cf.conf_line());
    let path = cf.cycle.add_path(path, &log, &cfn, line)?;
    *slot = Val::set(path);
    Ok(())
}

/// ngx_conf_merge_path_value: inherit or create default path.
pub fn merge_path_value(cf: &mut Conf, slot: &mut Val<Rc<PathConf>>, prev: &Val<Rc<PathConf>>, name: &str, level: [usize; 3]) -> ConfResult {
    if slot.is_set() {
        return Ok(());
    }
    if prev.is_set() {
        *slot = prev.clone();
        return Ok(());
    }
    let full = cf.full_name(name.as_bytes(), false);
    let path = PathConf::new(full, level);
    let (log, cfn, line) = (cf.log.clone(), cf.conf_file_name(), cf.conf_line());
    let path = cf.cycle.add_path(path, &log, &cfn, line)?;
    *slot = Val::set(path);
    Ok(())
}

/// ngx_conf_deprecated
pub fn deprecated(cf: &Conf, old: &str, new: Option<&str>) {
    match new {
        Some(n) => cf.warn(format_args!("the \"{}\" directive is deprecated, use the \"{}\" directive instead", old, n)),
        None => cf.warn(format_args!("the \"{}\" directive is deprecated", old)),
    }
}

/// The "include" directive (ngx_conf_include).
pub fn conf_include(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let file = cf.full_name(&cf.args[1].clone(), true);
    if !file.iter().any(|&c| c == b'*' || c == b'?' || c == b'[') {
        return cf.parse_file(&file);
    }
    let names = match crate::os::glob(&file) {
        Ok(v) => v,
        Err(e) => {
            return Err({
                cf.log_error(NGX_LOG_EMERG, Some(e), format_args!("glob() \"{}\" failed", B(&file)));
                ConfError::Logged
            })
        }
    };
    for n in names {
        cf.parse_file(&n)?;
    }
    Ok(())
}

/// Convenience: fetch a module's slot at a level from cf.ctx as Rc<RefCell<T>>.
pub fn ctx_conf<T: 'static>(cf: &Conf, level: ConfLevel, ctx_index: usize) -> Rc<RefCell<T>> {
    conf_rc::<T>(&cf.ctx.get(level, ctx_index).expect("missing conf"))
}

/// Macro to build a Command that sets a field through a generic setter.
/// Usage: cmd!("name", TYPE, ConfLevel::Loc, ConfStruct, field, set_flag)
#[macro_export]
macro_rules! cmd {
    ($name:expr, $ty:expr, $level:expr, $conf:ty, $field:ident, $setter:ident) => {
        $crate::conf::Command::new($name, $ty, $level, |cf, cmd, conf| {
            let conf = conf.expect("conf");
            let cell = $crate::conf::conf_cell::<$conf>(&conf);
            let mut c = cell.borrow_mut();
            $crate::conf::$setter(cf, cmd, &mut c.$field)
        })
    };
    ($name:expr, $ty:expr, $level:expr, $conf:ty, $field:ident, $setter:ident, $extra:expr) => {
        $crate::conf::Command::new($name, $ty, $level, |cf, cmd, conf| {
            let conf = conf.expect("conf");
            let cell = $crate::conf::conf_cell::<$conf>(&conf);
            let mut c = cell.borrow_mut();
            $crate::conf::$setter(cf, cmd, &mut c.$field, $extra)
        })
    };
}

/// Macro for a custom handler command.
#[macro_export]
macro_rules! cmd_fn {
    ($name:expr, $ty:expr, $level:expr, $f:expr) => {
        $crate::conf::Command::new($name, $ty, $level, $f)
    };
}
