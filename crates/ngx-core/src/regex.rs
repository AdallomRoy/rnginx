//! PCRE2 regex wrapper (ngx_regex.c).

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::conf::*;
use crate::module::*;
use crate::string::B;
use crate::{cmd, ngx_log_error};

pub const NGX_REGEX_CASELESS: u32 = 0x1;
pub const NGX_REGEX_MULTILINE: u32 = 0x2;

thread_local! {
    static PCRE_JIT: Cell<bool> = const { Cell::new(false) };
}

pub struct Regex {
    pub re: pcre2::bytes::Regex,
    pub pattern: Vec<u8>,
    pub captures: usize,
    /// (name, index)
    pub names: Vec<(Vec<u8>, usize)>,
    pub ncaptures: usize,
}

pub struct RegexCompile {
    pub pattern: Vec<u8>,
    pub options: u32,
    pub err: String,
}

impl Regex {
    /// ngx_regex_compile
    pub fn compile(pattern: &[u8], options: u32) -> Result<Rc<Regex>, String> {
        let mut b = pcre2::bytes::RegexBuilder::new();
        b.caseless(options & NGX_REGEX_CASELESS != 0);
        b.multi_line(options & NGX_REGEX_MULTILINE != 0);
        b.jit_if_available(PCRE_JIT.with(|j| j.get()));
        let pat = match std::str::from_utf8(pattern) {
            Ok(s) => s.to_string(),
            Err(_) => {
                // pcre2 crate needs &str; escape as latin1-ish is not possible, use lossy
                String::from_utf8_lossy(pattern).into_owned()
            }
        };
        let re = b.build(&pat).map_err(|e| {
            let msg = e.to_string();
            let off = e.offset().unwrap_or(0).min(pattern.len());
            format!("pcre2_compile() failed: {} in \"{}\" at \"{}\"", msg, B(pattern), B(&pattern[off..]))
        })?;
        let ncaptures = re.captures_len().saturating_sub(1);
        let mut names = Vec::new();
        for (i, n) in re.capture_names().iter().enumerate() {
            if let Some(n) = n {
                names.push((n.as_bytes().to_vec(), i));
            }
        }
        Ok(Rc::new(Regex { re, pattern: pattern.to_vec(), captures: ncaptures, names, ncaptures }))
    }

    /// ngx_regex_exec: returns capture offsets (start,end) pairs; None if no match.
    /// The returned vector has (ncaptures+1) entries, unmatched groups are (-1,-1).
    pub fn exec(&self, s: &[u8]) -> Option<Vec<(i32, i32)>> {
        let mut locs = self.re.capture_locations();
        match self.re.captures_read(&mut locs, s) {
            Ok(Some(_)) => {
                let mut v = Vec::with_capacity(locs.len());
                for i in 0..locs.len() {
                    match locs.get(i) {
                        Some((a, b)) => v.push((a as i32, b as i32)),
                        None => v.push((-1, -1)),
                    }
                }
                Some(v)
            }
            _ => None,
        }
    }

    pub fn is_match(&self, s: &[u8]) -> bool {
        self.re.is_match(s).unwrap_or(false)
    }
}

pub struct RegexConf {
    pub pcre_jit: Val<bool>,
}

fn create_conf(_cycle: &mut crate::cycle::Cycle) -> Rc<dyn Any> {
    make_slot(RegexConf { pcre_jit: Val::unset() })
}

fn init_conf(_cycle: &mut crate::cycle::Cycle, conf: &Rc<dyn Any>) -> Result<(), ()> {
    let c = conf_cell::<RegexConf>(conf);
    let mut c = c.borrow_mut();
    c.pcre_jit.init(false);
    PCRE_JIT.with(|j| j.set(*c.pcre_jit));
    Ok(())
}

pub fn regex_module() -> ModuleDef {
    let mut m = ModuleDef::new("ngx_regex_module", NGX_CORE_MODULE);
    m.ctx = Some(Rc::new(CoreModuleCtx { name: "regex", create_conf: Some(create_conf), init_conf: Some(init_conf) }));
    m.commands = vec![cmd!("pcre_jit", NGX_MAIN_CONF | NGX_DIRECT_CONF | NGX_CONF_FLAG, ConfLevel::None, RegexConf, pcre_jit, set_flag)];
    m
}

/// Log a compile error the nginx way.
pub fn log_compile_error(log: &crate::log::Log, e: &str) {
    ngx_log_error!(crate::log::NGX_LOG_EMERG, log, None, "{}", e);
}

#[allow(dead_code)]
fn _unused(_: RefCell<()>) {}
