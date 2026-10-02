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
    /// The match data of the matches with captures, made once and reused
    /// (ngx_regex_match_data): taken out for a match and put back, so a
    /// nested match on the same regex would make its own.
    locs: Cell<Option<pcre2::bytes::CaptureLocations>>,
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
            // the PCRE2 message, without the "PCRE2: error compiling
            // pattern at offset N: " prefix the pcre2 crate adds
            let full = e.to_string();
            let msg = full.splitn(3, ": ").nth(2).unwrap_or(&full).to_string();
            let off = e.offset().unwrap_or(0).min(pattern.len());
            if off == pattern.len() {
                format!("pcre2_compile() failed: {} in \"{}\"", msg, B(pattern))
            } else {
                format!("pcre2_compile() failed: {} in \"{}\" at \"{}\"", msg, B(pattern), B(&pattern[off..]))
            }
        })?;
        let ncaptures = re.captures_len().saturating_sub(1);
        let mut names = Vec::new();
        for (i, n) in re.capture_names().iter().enumerate() {
            if let Some(n) = n {
                names.push((n.as_bytes().to_vec(), i));
            }
        }
        Ok(Rc::new(Regex { re, pattern: pattern.to_vec(), captures: ncaptures, names, ncaptures, locs: Cell::new(None) }))
    }

    /// A match of `s` with captures, in the reused match data: `f` gets
    /// the capture locations of a match, None without one (or when PCRE2
    /// fails).
    fn with_match<T>(&self, s: &[u8], f: impl FnOnce(Option<&pcre2::bytes::CaptureLocations>) -> T) -> T {
        let mut locs = match self.locs.take() {
            Some(locs) => locs,
            None => self.re.capture_locations(),
        };

        let matched = matches!(self.re.captures_read(&mut locs, s), Ok(Some(_)));

        let t = f(if matched { Some(&locs) } else { None });

        self.locs.set(Some(locs));

        t
    }

    /// ngx_regex_exec: returns capture offsets (start,end) pairs; None if no match.
    /// The returned vector has (ncaptures+1) entries, unmatched groups are (-1,-1).
    pub fn exec(&self, s: &[u8]) -> Option<Vec<(i32, i32)>> {
        self.with_match(s, |locs| {
            let locs = locs?;
            let mut v = Vec::with_capacity(locs.len());
            for i in 0..locs.len() {
                match locs.get(i) {
                    Some((a, b)) => v.push((a as i32, b as i32)),
                    None => v.push((-1, -1)),
                }
            }
            Some(v)
        })
    }

    /// ngx_regex_exec into the captures array of the caller, as C's int
    /// array of start and end offsets: on a match `captures` is cleared
    /// and filled with the (ncaptures+1) pairs, -1 for the unmatched
    /// groups, and the number of pairs returned; without a match (None)
    /// it is left as it was. Its capacity is reused.
    pub fn exec_into(&self, s: &[u8], captures: &mut Vec<i32>) -> Option<usize> {
        self.with_match(s, |locs| {
            let locs = locs?;
            let n = locs.len();
            captures.clear();
            captures.reserve(2 * n);
            for i in 0..n {
                match locs.get(i) {
                    Some((a, b)) => {
                        captures.push(a as i32);
                        captures.push(b as i32);
                    }
                    None => {
                        captures.push(-1);
                        captures.push(-1);
                    }
                }
            }
            Some(n)
        })
    }

    pub fn is_match(&self, s: &[u8]) -> bool {
        self.re.is_match(s).unwrap_or(false)
    }

    /// Match `s`, and if matched, produce the replacement string with
    /// $1..$9 substituted by capture groups. Returns `None` when no match
    /// (the caller keeps the original value).
    pub fn replace(&self, s: &[u8], template: &[u8]) -> Option<Vec<u8>> {
        let locs = self.exec(s)?;
        let mut out = Vec::with_capacity(s.len() + template.len());
        let mut i = 0;
        while i < template.len() {
            if template[i] == b'$' && i + 1 < template.len() && template[i + 1].is_ascii_digit() {
                let idx = (template[i + 1] - b'0') as usize;
                if idx < locs.len() {
                    let (a, b) = locs[idx];
                    if a >= 0 && b >= a {
                        out.extend_from_slice(&s[a as usize..b as usize]);
                    }
                }
                i += 2;
            } else {
                out.push(template[i]);
                i += 1;
            }
        }
        Some(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_into() {
        let re = Regex::compile(b"^/(a)?(b+)(c)?", 0).unwrap();

        let mut caps = vec![7, 7];

        // no match: the captures are left as they were
        assert_eq!(re.exec_into(b"/x", &mut caps), None);
        assert_eq!(caps, vec![7, 7]);

        // the pairs of all the groups, -1 for the unmatched ones
        assert_eq!(re.exec_into(b"/bbc", &mut caps), Some(4));
        assert_eq!(caps, vec![0, 4, -1, -1, 1, 3, 3, 4]);

        // the match data is reused, and gives the same as exec()
        assert_eq!(re.exec_into(b"/ab", &mut caps), Some(4));
        assert_eq!(caps, vec![0, 3, 1, 2, 2, 3, -1, -1]);
        assert_eq!(re.exec(b"/ab"), Some(vec![(0, 3), (1, 2), (2, 3), (-1, -1)]));
        assert_eq!(re.exec(b"/"), None);

        // a pattern without captures: the whole match
        let re = Regex::compile(b"b", 0).unwrap();
        assert_eq!(re.exec_into(b"abc", &mut caps), Some(1));
        assert_eq!(caps, vec![1, 2]);
    }

    #[test]
    fn replace() {
        let re = Regex::compile(b"^/(\\w+)/(\\w+)$", 0).unwrap();
        assert_eq!(re.replace(b"/a/b", b"/$2/$1/$3"), Some(b"/b/a/".to_vec()));
        assert_eq!(re.replace(b"/a", b"$1"), None);
    }
}
