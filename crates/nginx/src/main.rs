//! nginx entry point (nginx.c).

use std::rc::Rc;

use ngx_core::core_module::*;
use ngx_core::cycle::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_error, ngx_log_stderr, os, process};

const NGX_COMPILER: &str = "rustc 1.96.1";
const NGX_CONFIGURE: &str = " --with-debug --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_geoip_module --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_auth_request_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-mail --with-mail_ssl_module --with-stream --with-stream_ssl_module --with-stream_realip_module --with-stream_geoip_module --with-stream_ssl_preread_module --with-threads --with-file-aio";

struct Options {
    show_help: bool,
    show_version: bool,
    show_configure: bool,
    test_config: bool,
    dump_config: bool,
    quiet: bool,
    prefix: Option<Vec<u8>>,
    error_log: Option<Vec<u8>>,
    conf_file: Option<Vec<u8>>,
    conf_params: Option<Vec<u8>>,
    signal: Option<String>,
}

fn get_options(args: &[String]) -> Result<Options, ()> {
    let mut o = Options {
        show_help: false,
        show_version: false,
        show_configure: false,
        test_config: false,
        dump_config: false,
        quiet: false,
        prefix: None,
        error_log: None,
        conf_file: None,
        conf_params: None,
        signal: None,
    };
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_bytes();
        if a.first() != Some(&b'-') {
            ngx_log_stderr!(None, "invalid option: \"{}\"", args[i]);
            return Err(());
        }
        let mut p = 1;
        while p < a.len() {
            let c = a[p];
            p += 1;
            match c {
                b'?' | b'h' => {
                    o.show_version = true;
                    o.show_help = true;
                }
                b'v' => o.show_version = true,
                b'V' => {
                    o.show_version = true;
                    o.show_configure = true;
                }
                b't' => o.test_config = true,
                b'T' => {
                    o.test_config = true;
                    o.dump_config = true;
                }
                b'q' => o.quiet = true,
                b'p' | b'e' | b'c' | b'g' | b's' => {
                    let value: Vec<u8> = if p < a.len() {
                        a[p..].to_vec()
                    } else if i + 1 < args.len() {
                        i += 1;
                        args[i].as_bytes().to_vec()
                    } else {
                        let what = match c {
                            b'p' => "option \"-p\" requires directory name",
                            b'e' => "option \"-e\" requires file name",
                            b'c' => "option \"-c\" requires file name",
                            b'g' => "option \"-g\" requires parameter",
                            _ => "option \"-s\" requires parameter",
                        };
                        ngx_log_stderr!(None, "{}", what);
                        return Err(());
                    };
                    match c {
                        b'p' => o.prefix = Some(value),
                        b'e' => o.error_log = Some(if value == b"stderr" { Vec::new() } else { value }),
                        b'c' => o.conf_file = Some(value),
                        b'g' => o.conf_params = Some(value),
                        _ => {
                            let s = String::from_utf8_lossy(&value).into_owned();
                            if s == "stop" || s == "quit" || s == "reopen" || s == "reload" {
                                o.signal = Some(s);
                            } else {
                                ngx_log_stderr!(None, "invalid option: \"-s {}\"", s);
                                return Err(());
                            }
                        }
                    }
                    p = a.len();
                }
                _ => {
                    ngx_log_stderr!(None, "invalid option: \"{}\"", c as char);
                    return Err(());
                }
            }
        }
        i += 1;
    }
    Ok(o)
}

fn show_version_info(o: &Options) {
    let mut s = format!("nginx version: {}\n", ngx_core::NGINX_VER_BUILD);
    if o.show_help {
        s.push_str(
            "Usage: nginx [-?hvVtTq] [-s signal] [-p prefix]\n             [-e filename] [-c filename] [-g directives]\n\nOptions:\n  -?,-h         : this help\n  -v            : show version and exit\n  -V            : show version and configure options then exit\n  -t            : test configuration and exit\n  -T            : test configuration, dump it and exit\n  -q            : suppress non-error messages during configuration testing\n  -s signal     : send signal to a master process: stop, quit, reopen, reload\n  -p prefix     : set prefix path (default: /usr/local/nginx/)\n  -e filename   : set error log file (default: logs/error.log)\n  -c filename   : set configuration file (default: conf/nginx.conf)\n  -g directives : set global directives out of configuration file\n\n",
        );
    }
    if o.show_configure {
        s.push_str(&format!("built by {}\n", NGX_COMPILER));
        s.push_str(&format!("built with {}\n", ngx_core::ssl::openssl_version_text()));
        s.push_str("TLS SNI support enabled\n");
        s.push_str(&format!("configure arguments:{}\n", NGX_CONFIGURE));
    }
    write_stderr(s.as_bytes());
}

/// ngx_process_options
fn process_options(cycle: &mut Cycle, o: &Options) -> Result<(), ()> {
    if let Some(p) = &o.prefix {
        let mut prefix = p.clone();
        if prefix.last() != Some(&b'/') {
            prefix.push(b'/');
        }
        // make absolute
        if prefix[0] != b'/' {
            let cwd = std::env::current_dir().map_err(|e| {
                ngx_log_stderr!(e.raw_os_error(), "[emerg]: getcwd() failed");
            })?;
            use std::os::unix::ffi::OsStrExt;
            let mut full = cwd.as_os_str().as_bytes().to_vec();
            full.push(b'/');
            full.extend_from_slice(&prefix);
            prefix = full;
        }
        cycle.conf_prefix = prefix.clone();
        cycle.prefix = prefix;
    } else {
        cycle.conf_prefix = b"/usr/local/nginx/conf/".to_vec();
        cycle.prefix = ngx_core::NGX_PREFIX.as_bytes().to_vec();
    }
    if let Some(c) = &o.conf_file {
        cycle.conf_file = c.clone();
    } else {
        cycle.conf_file = ngx_core::NGX_CONF_PATH.as_bytes().to_vec();
    }
    cycle.conf_file = cycle.full_name(&cycle.conf_file.clone(), false);
    // conf_prefix = dirname of conf_file
    if let Some(i) = memchr::memrchr(b'/', &cycle.conf_file) {
        cycle.conf_prefix = cycle.conf_file[..i + 1].to_vec();
    }
    if let Some(p) = &o.conf_params {
        cycle.conf_param = p.clone();
    }
    cycle.error_log = match &o.error_log {
        Some(e) => e.clone(),
        None => ngx_core::NGX_ERROR_LOG_PATH.as_bytes().to_vec(),
    };
    if o.test_config {
        set_use_stderr(true);
    }
    Ok(())
}

fn modules() -> Vec<ModuleDef> {
    let mut v = vec![
        core_module(),
        errlog_module(),
        conf_module(),
        ngx_core::ssl::openssl_module(),
        ngx_core::event_openssl_cache::openssl_cache_module(),
        ngx_core::stubs::quic_module(),
        ngx_core::stubs::quic_bpf_module(),
        ngx_core::regex::regex_module(),
        ngx_core::event::events_module(),
        ngx_core::event::event_core_module(),
        ngx_core::stubs::epoll_module(),
        ngx_core::stubs::thread_pool_module(),
    ];
    v.extend(ngx_http::modules());
    v.extend(ngx_mail::modules());
    v.extend(ngx_stream::modules());
    v
}

fn main() {
    ngx_core::times::update();
    let args: Vec<String> = std::env::args().collect();
    process::save_argv(&args);
    let o = match get_options(&args) {
        Ok(o) => o,
        Err(()) => std::process::exit(1),
    };
    if o.show_version {
        show_version_info(&o);
        if !o.test_config {
            std::process::exit(0);
        }
    }
    globals_mut(|g| {
        g.test_config = o.test_config;
        g.dump_config = o.dump_config;
        g.quiet_mode = o.quiet;
    });
    ngx_core::times::update();
    let log = log_init(o.prefix.as_deref(), o.error_log.as_deref());
    ngx_core::ssl::ssl_init(&log);

    let mods = Rc::new(build_modules(modules()));
    let mut init = Cycle::init_cycle(log.clone(), mods);
    if process_options(&mut init, &o).is_err() {
        std::process::exit(1);
    }
    if process::add_inherited_sockets(&mut init).is_err() {
        std::process::exit(1);
    }
    let conf_file_name = init.conf_file.clone();
    let init = Rc::new(init);
    if let Some(sig) = &o.signal {
        globals_mut(|g| g.process = ProcessType::Signaller);
        process::set_process_kind(ProcessType::Signaller);
        let _ = sig;
    }

    let cycle = match init_cycle(init, &ngx_core::connection::init_hooks()) {
        Ok(c) => c,
        Err(()) => {
            if o.test_config {
                ngx_log_stderr!(None, "configuration file {} test failed", B(&conf_file_name));
            }
            std::process::exit(1);
        }
    };
    set_cycle(cycle.clone());

    if o.test_config {
        if !o.quiet {
            ngx_log_stderr!(None, "configuration file {} test is successful", B(&cycle.conf_file));
        }
        if o.dump_config {
            cycle.dump_config();
        }
        std::process::exit(0);
    }

    if let Some(sig) = &o.signal {
        std::process::exit(signal_process(&cycle, sig));
    }

    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "{}", ngx_core::NGINX_VER_BUILD);
    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "built by {}", NGX_COMPILER);
    ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "OS: {}", os_info());
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        ngx_log_error!(NGX_LOG_NOTICE, cycle.log, None, "getrlimit(RLIMIT_NOFILE): {}:{}", rl.rlim_cur, rl.rlim_max);
    }

    let ccf = core_conf(&cycle);
    let (daemon_on, master_on) = {
        let c = ccf.borrow();
        (*c.daemon, *c.master)
    };
    let inherited = globals(|g| g.inherited);
    let pt = if master_on { ProcessType::Master } else { ProcessType::Single };
    process::set_process_kind(pt);
    if process::init_signals(&cycle.log).is_err() {
        std::process::exit(1);
    }
    if !inherited && daemon_on {
        if process::daemon(&cycle.log).is_err() {
            std::process::exit(1);
        }
        process::DAEMONIZED.store(true, std::sync::atomic::Ordering::Relaxed);
        globals_mut(|g| g.daemonized = true);
    }
    if inherited {
        globals_mut(|g| g.daemonized = true);
        process::DAEMONIZED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let pid_path = ccf.borrow().pid.clone();
    if create_pidfile(&pid_path, &cycle.log).is_err() {
        std::process::exit(1);
    }
    let _ = log_redirect_stderr(&cycle);
    // close initial stderr log file if it isn't stderr
    set_use_stderr(false);
    process::init_setproctitle();

    if pt == ProcessType::Single {
        process::single_process_cycle(cycle);
    } else {
        process::master_process_cycle(cycle);
    }
}

fn os_info() -> String {
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) == 0 {
            let s = std::ffi::CStr::from_ptr(u.sysname.as_ptr()).to_string_lossy().into_owned();
            let r = std::ffi::CStr::from_ptr(u.release.as_ptr()).to_string_lossy().into_owned();
            return format!("{} {}", s, r);
        }
    }
    "unknown".into()
}
