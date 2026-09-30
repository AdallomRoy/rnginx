//! ngx_http_auth_basic_module

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::crypt;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_auth_basic_module");

const NGX_HTTP_AUTH_BUF_SIZE: usize = 2048;

pub struct AuthBasicLocConf {
    pub realm: Option<Rc<ComplexValue>>,
    pub user_file: Option<Rc<ComplexValue>>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(AuthBasicLocConf {
        realm: None,
        user_file: None,
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<AuthBasicLocConf>(prev).borrow();
    let mut c = conf_cell::<AuthBasicLocConf>(conf).borrow_mut();

    if c.realm.is_none() {
        c.realm = p.realm.clone();
    }
    if c.user_file.is_none() {
        c.user_file = p.user_file.clone();
    }

    Ok(())
}

/// ngx_http_set_complex_value_slot
fn set_realm(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AuthBasicLocConf>(conf.as_ref().unwrap());

    if cell.borrow().realm.is_some() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args[1].clone();

    let cv = compile_complex_value(cf, &value, 0)?;
    cell.borrow_mut().realm = Some(Rc::new(cv));
    Ok(())
}

/// ngx_http_auth_basic_user_file
fn set_user_file(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<AuthBasicLocConf>(conf.as_ref().unwrap());

    if cell.borrow().user_file.is_some() {
        return Err(msg("is duplicate"));
    }

    let value = cf.args[1].clone();

    let cv = compile_complex_value(cf, &value, NGX_HTTP_COMPLEX_VALUE_ZERO | NGX_HTTP_COMPLEX_VALUE_CONF_PREFIX)?;
    cell.borrow_mut().user_file = Some(Rc::new(cv));
    Ok(())
}

pub fn auth_basic_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        cmd_fn!("auth_basic", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_realm),
        cmd_fn!("auth_basic_user_file", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_user_file),
    ];
    http_module_def("ngx_http_auth_basic_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(
        cf,
        NGX_HTTP_ACCESS_PHASE,
        Rc::new(|r| Box::pin(auth_basic_handler(r))),
    );
    Ok(())
}

/// ngx_http_complex_value of the user file: a value starting with a
/// variable gets the conf prefix at run time (ngx_http_script_full_name_code),
/// other values got it when compiled
fn user_file_value(r: &R, cv: &ComplexValue) -> Result<Vec<u8>, i64> {
    let value = complex_value(r, cv)?;

    if cv.is_constant() || cv.value.first() != Some(&b'$') || value.first() == Some(&b'/') {
        return Ok(value);
    }

    let mut name = ngx_core::cycle::cycle().conf_prefix.clone();
    name.extend_from_slice(&value);

    http_debug!(r, "http script fullname: \"{}\"", B(&name));

    Ok(name)
}

/// The bytes of a NUL-terminated C string stored in `s`
fn c_str(s: &[u8]) -> &[u8] {
    match memchr::memchr(0, s) {
        Some(n) => &s[..n],
        None => s,
    }
}

/// ngx_file_t for ngx_read_file
struct File<'a> {
    fd: i32,
    name: &'a [u8],
    log: &'a Log,
}

/// ngx_read_file (with pread)
fn read_file(file: &File, buf: &mut [u8], offset: i64) -> Result<usize, ()> {
    ngx_log_debug!(NGX_LOG_DEBUG_CORE, file.log, "read: {}, {:016x}, {}, {}", file.fd, buf.as_ptr() as usize, buf.len(), offset);

    // SAFETY: buf is a valid writable slice of buf.len() bytes
    let n = unsafe { libc::pread(file.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), offset as libc::off_t) };

    if n == -1 {
        ngx_log_error!(NGX_LOG_CRIT, file.log, Some(ngx_core::os::errno()), "pread() \"{}\" failed", B(file.name));
        return Err(());
    }

    Ok(n as usize)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Login,
    Passwd,
    Skip,
}

/// What the htpasswd scan found
#[derive(PartialEq, Debug)]
enum Lookup {
    /// the password field of the user (up to LF, CR, ':' or the end of file)
    Found(Vec<u8>),
    NotFound,
    ReadError,
}

/// The htpasswd parser of ngx_http_auth_basic_handler: reads the file in
/// NGX_HTTP_AUTH_BUF_SIZE chunks through `read(buf, offset)` and looks for
/// "user:password"; the user name is followed by ':' as in the decoded
/// Authorization header, where r->headers_in.user.data[user.len] is ':'
fn lookup_user(user: &[u8], mut read: impl FnMut(&mut [u8], i64) -> Result<usize, ()>) -> Lookup {
    let mut buf = [0u8; NGX_HTTP_AUTH_BUF_SIZE];

    let mut state = State::Login;
    let mut passwd = 0usize;
    let mut login = 0usize;
    let mut left = 0usize;
    let mut offset = 0i64;
    let mut i;

    let user_at = |login: usize| if login < user.len() { user[login] } else { b':' };

    let result = loop {
        i = left;

        let n = match read(&mut buf[left..], offset) {
            Ok(n) => n,
            Err(()) => break Lookup::ReadError,
        };

        if n == 0 {
            break Lookup::NotFound;
        }

        let mut found = None;

        while i < left + n {
            match state {
                State::Login => {
                    if login == 0 {
                        if buf[i] == b'#' || buf[i] == b'\r' {
                            state = State::Skip;
                            i += 1;
                            continue;
                        }

                        if buf[i] == b'\n' {
                            i += 1;
                            continue;
                        }
                    }

                    if buf[i] != user_at(login) {
                        state = State::Skip;
                        i += 1;
                        continue;
                    }

                    if login == user.len() {
                        state = State::Passwd;
                        passwd = i + 1;
                    }

                    login += 1;
                }

                State::Passwd => {
                    if buf[i] == b'\n' || buf[i] == b'\r' || buf[i] == b':' {
                        buf[i] = b'\0';

                        found = Some(buf[passwd..i].to_vec());
                        break;
                    }
                }

                State::Skip => {
                    if buf[i] == b'\n' {
                        state = State::Login;
                        login = 0;
                    }
                }
            }

            i += 1;
        }

        if let Some(pwd) = found {
            break Lookup::Found(pwd);
        }

        if state == State::Passwd {
            left = left + n - passwd;
            buf.copy_within(passwd..passwd + left, 0);
            passwd = 0;
        } else {
            left = 0;
        }

        offset += n as i64;
    };

    let result = match result {
        Lookup::NotFound if state == State::Passwd => {
            // ngx_cpystrn(pwd.data, &buf[passwd], pwd.len + 1)
            Lookup::Found(c_str(&buf[passwd..i]).to_vec())
        }
        result => result,
    };

    // ngx_explicit_memzero
    buf.fill(0);
    std::hint::black_box(&buf);

    result
}

async fn auth_basic_handler(r: R) -> i64 {
    let alcf = r.loc_conf::<AuthBasicLocConf>(ctx_index());

    let (realm_cv, user_file_cv) = {
        let c = alcf.borrow();
        match (&c.realm, &c.user_file) {
            (Some(realm), Some(user_file)) => (realm.clone(), user_file.clone()),
            _ => return NGX_DECLINED,
        }
    };

    let realm = match complex_value(&r, &realm_cv) {
        Ok(v) => v,
        Err(_) => return NGX_ERROR,
    };

    if realm == b"off" {
        return NGX_DECLINED;
    }

    let rc = auth_basic_user(&r);

    if rc == NGX_DECLINED {
        ngx_log_error!(NGX_LOG_INFO, r.connection.log, None, "no user/password was provided for basic authentication");

        return auth_basic_set_realm(&r, &realm);
    }

    if rc == NGX_ERROR {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let user_file = match user_file_value(&r, &user_file_cv) {
        Ok(v) => v,
        Err(_) => return NGX_ERROR,
    };

    let fd = match ngx_core::os::open(c_str(&user_file), libc::O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(err) => {
            let (level, rc) = if err == libc::ENOENT {
                (NGX_LOG_ERR, NGX_HTTP_FORBIDDEN)
            } else {
                (NGX_LOG_CRIT, NGX_HTTP_INTERNAL_SERVER_ERROR)
            };

            ngx_log_error!(level, r.connection.log, Some(err), "open() \"{}\" failed", B(c_str(&user_file)));

            return rc;
        }
    };

    let user = r.headers_in.borrow().user.clone();

    let lookup = {
        let file = File { fd, name: c_str(&user_file), log: &r.connection.log };
        lookup_user(&user, |buf, offset| read_file(&file, buf, offset))
    };

    let rc = match lookup {
        Lookup::ReadError => NGX_HTTP_INTERNAL_SERVER_ERROR,
        Lookup::Found(pwd) => auth_basic_crypt_handler(&r, &pwd, &realm),
        Lookup::NotFound => {
            ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "user \"{}\" was not found in \"{}\"", B(&user), B(c_str(&user_file)));

            auth_basic_set_realm(&r, &realm)
        }
    };

    // SAFETY: fd was opened above and is closed once
    if unsafe { libc::close(fd) } == -1 {
        ngx_log_error!(NGX_LOG_ALERT, r.connection.log, Some(ngx_core::os::errno()), "close() \"{}\" failed", B(c_str(&user_file)));
    }

    rc
}

/// ngx_http_auth_basic_crypt_handler; `passwd` is the salt, the password
/// field of the user file
fn auth_basic_crypt_handler(r: &R, passwd: &[u8], realm: &[u8]) -> i64 {
    let (user, key) = {
        let hin = r.headers_in.borrow();
        (hin.user.clone(), hin.passwd.clone())
    };

    // ngx_crypt() gets C strings
    let salt = c_str(passwd);
    let rc = crypt::crypt(c_str(&key), salt);

    http_debug!(r, "rc: {} user: \"{}\" salt: \"{}\"", if rc.is_ok() { NGX_OK } else { NGX_ERROR }, B(&user), B(salt));

    let encrypted = match rc {
        Ok(encrypted) => encrypted,
        Err(_) => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    if c_str(&encrypted) == salt {
        return NGX_OK;
    }

    http_debug!(r, "encrypted: \"{}\"", B(c_str(&encrypted)));

    ngx_log_error!(NGX_LOG_ERR, r.connection.log, None, "user \"{}\": password mismatch", B(&user));

    auth_basic_set_realm(r, realm)
}

/// ngx_http_auth_basic_set_realm
fn auth_basic_set_realm(r: &R, realm: &[u8]) -> i64 {
    let mut basic = Vec::with_capacity("Basic realm=\"\"".len() + realm.len());
    basic.extend_from_slice(b"Basic realm=\"");
    basic.extend_from_slice(realm);
    basic.push(b'"');

    let mut ho = r.headers_out.borrow_mut();

    if r.is_proxy_auth() {
        let h = ho.add(b"Proxy-Authenticate", &basic);
        ho.proxy_authenticate = vec![h];
        NGX_HTTP_PROXY_AUTH_REQUIRED
    } else {
        let h = ho.add(b"WWW-Authenticate", &basic);
        ho.www_authenticate = vec![h];
        NGX_HTTP_UNAUTHORIZED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// lookup_user over `data` read in chunks of at most `chunk` bytes
    fn lookup(user: &[u8], data: &[u8], chunk: usize) -> Lookup {
        lookup_user(user, |buf, offset| {
            let start = (offset as usize).min(data.len());
            let n = buf.len().min(chunk).min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            Ok(n)
        })
    }

    fn found(s: &[u8]) -> Lookup {
        Lookup::Found(s.to_vec())
    }

    #[test]
    fn htpasswd_lines() {
        let data = b"# comment\n\nplain:{PLAIN}password\nuser:x:comment\r\nlast:nonl";
        for chunk in [1, 2, 3, 7, 2048] {
            assert_eq!(lookup(b"plain", data, chunk), found(b"{PLAIN}password"), "chunk {chunk}");
            assert_eq!(lookup(b"user", data, chunk), found(b"x"));
            assert_eq!(lookup(b"last", data, chunk), found(b"nonl"));
            assert_eq!(lookup(b"pla", data, chunk), Lookup::NotFound);
            assert_eq!(lookup(b"plainx", data, chunk), Lookup::NotFound);
            assert_eq!(lookup(b"comment", data, chunk), Lookup::NotFound);
        }
    }

    #[test]
    fn htpasswd_edge_cases() {
        // a line starting with CR is skipped, leading spaces are part of the name
        assert_eq!(lookup(b"a", b"\ra:1\n a:2\na:3\n", 2048), found(b"3"));
        assert_eq!(lookup(b" a", b"\ra:1\n a:2\na:3\n", 2048), found(b"2"));
        // empty password
        assert_eq!(lookup(b"a", b"a:\n", 2048), found(b""));
        assert_eq!(lookup(b"a", b"a:", 2048), found(b""));
        // a NUL in the password at the end of file ends the C string
        assert_eq!(lookup(b"a", b"a:x\0y", 2048), found(b"x"));
        assert_eq!(lookup(b"a", b"", 2048), Lookup::NotFound);
    }

    #[test]
    fn htpasswd_long_password() {
        // the password field is kept across reads, up to the buffer size
        let mut data = b"u:".to_vec();
        data.extend(std::iter::repeat(b'p').take(3000));
        data.push(b'\n');
        assert_eq!(lookup(b"u", &data, 2048), found(&[b'p'; 2048]));
        assert_eq!(lookup(b"u", &data, 1000), found(&[b'p'; 2048]));

        // a long line of another user is skipped over reads
        let mut data = vec![b'x'; 5000];
        data.extend_from_slice(b"\nu:ok\n");
        assert_eq!(lookup(b"u", &data, 2048), found(b"ok"));
    }

    #[test]
    fn htpasswd_read_error() {
        assert_eq!(lookup_user(b"u", |_, _| Err(())), Lookup::ReadError);
    }

    #[test]
    fn c_strings() {
        assert_eq!(c_str(b"ab\0cd"), b"ab");
        assert_eq!(c_str(b"abc"), b"abc");
    }
}
