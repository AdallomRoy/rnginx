//! ngx_stream_pass_module.c: passing the connection to a listening socket
//! (and its module) of the same address.

use std::any::Any;
use std::cell::Cell;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::connection::PoolCleanup;
use ngx_core::inet::{Addr, SockAddr, Url};
use ngx_core::listening::Listening;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::string::B;
use ngx_core::{cmd_fn, ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::handler::finalize_session;
use crate::script::*;
use crate::*;

stream_module_index!("ngx_stream_pass_module");

const NGX_STREAM_PASS_MAX_PASSES: usize = 10;

const TAG: &str = "ngx_stream_pass_module";

/// ngx_stream_pass_srv_conf_t
#[derive(Default)]
pub struct PassSrvConf {
    pub addr: Option<Addr>,
    pub addr_value: Option<ComplexValue>,
}

/// ngx_stream_pass_handler
async fn pass_handler(s: S) {
    let c = s.connection.clone();

    c.log.set_action(Some("passing connection to port"));

    if c.ty == libc::SOCK_DGRAM {
        ngx_log_error!(NGX_LOG_ERR, c.log, None, "cannot pass udp connection");
        finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return;
    }

    if !c.buffer.borrow().is_empty() {
        ngx_log_error!(NGX_LOG_ERR, c.log, None, "cannot pass connection with preread data");
        finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return;
    }

    let pscf = s.srv_conf::<PassSrvConf>(ctx_index());

    let (addr, addr_value) = {
        let p = pscf.borrow();
        (p.addr.clone(), p.addr_value.clone())
    };

    let addr = match addr {
        Some(a) => a,
        None => {
            let url = match complex_value(&s, addr_value.as_ref().expect("pass value")) {
                Ok(u) => u,
                Err(()) => {
                    finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
                    return;
                }
            };

            let mut u = Url::new(&url);
            u.no_resolve = true;

            if ngx_core::inet::parse_url(&mut u).is_err() {
                if let Some(err) = u.err {
                    ngx_log_error!(NGX_LOG_ERR, c.log, None, "{} in pass \"{}\"", err, B(&u.url));
                }

                finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
                return;
            }

            if u.addrs.is_empty() {
                ngx_log_error!(NGX_LOG_ERR, c.log, None, "no addresses in pass \"{}\"", B(&u.url));
                finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
                return;
            }

            if u.no_port {
                ngx_log_error!(NGX_LOG_ERR, c.log, None, "no port in pass \"{}\"", B(&u.url));
                finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
                return;
            }

            u.addrs[0].clone()
        }
    };

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "stream pass addr: \"{}\"", B(&addr.name));

    if !pass_check_cycle(&c) {
        finalize_session(&s, NGX_STREAM_INTERNAL_SERVER_ERROR).await;
        return;
    }

    let cycle = ngx_core::cycle::cycle();

    for ls in cycle.listening.iter() {
        if !pass_match(ls, &addr.sockaddr) {
            continue;
        }

        let handler = match ls.handler.borrow().clone() {
            Some(h) => h,
            None => continue,
        };

        *c.passed_listening.borrow_mut() = Some(ls.clone());
        c.data.borrow_mut().take();
        c.buffer.borrow_mut().clear();

        // *c->log = c->listening->log
        c.log.set_chain(ls.log.borrow().chain());
        c.log.set_context(None);
        c.log.set_action(None);

        *c.local_sockaddr.borrow_mut() = Some(addr.sockaddr.clone());

        handler(c.clone());

        return;
    }

    ngx_log_error!(NGX_LOG_ERR, c.log, None, "port not found for \"{}\"", B(&addr.name));

    finalize_session(&s, NGX_STREAM_OK).await;
}

/// ngx_stream_pass_check_cycle
fn pass_check_cycle(c: &ngx_core::connection::Connection) -> bool {
    {
        let cleanups = c.cleanups.borrow();

        for cln in cleanups.iter() {
            if cln.tag != TAG {
                continue;
            }

            let num = cln.data.clone().and_then(|d| d.downcast::<Cell<usize>>().ok()).expect("pass cleanup");

            num.set(num.get() + 1);

            if num.get() > NGX_STREAM_PASS_MAX_PASSES {
                ngx_log_error!(NGX_LOG_ERR, c.log, None, "stream pass cycle");
                return false;
            }

            return true;
        }
    }

    // ngx_stream_pass_cleanup does nothing: it holds the number
    let num: Rc<dyn Any> = Rc::new(Cell::new(1usize));

    c.add_cleanup(PoolCleanup { tag: TAG, data: Some(num), handler: None });

    true
}

/// ngx_stream_pass_match
fn pass_match(ls: &Listening, addr: &SockAddr) -> bool {
    if ls.ty == libc::SOCK_DGRAM {
        return false;
    }

    if !ls.wildcard.get() {
        return ls.sockaddr.cmp(addr, true);
    }

    ls.sockaddr.family() == addr.family() && ls.sockaddr.port() == addr.port()
}

fn pass_create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(PassSrvConf::default())
}

/// ngx_stream_pass
fn pass_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let pscf = conf_rc::<PassSrvConf>(conf.as_ref().expect("conf"));

    {
        let p = pscf.borrow();
        if p.addr.is_some() || p.addr_value.is_some() {
            return Err(msg("is duplicate"));
        }
    }

    let cscf = core_srv_conf(cf);
    cscf.borrow_mut().handler = Some(content_fn(pass_handler));

    let url = cf.args[1].clone();

    let mut ccv = CompileComplexValue::default();
    let cv = compile_complex_value(cf, &url, &mut ccv)?;

    if !cv.is_constant() {
        pscf.borrow_mut().addr_value = Some(cv);
        return Ok(());
    }

    let mut u = Url::new(&url);
    u.no_resolve = true;

    if ngx_core::inet::parse_url(&mut u).is_err() {
        if let Some(err) = u.err {
            return Err(cf.emerg(format_args!("{} in \"{}\" of the \"pass\" directive", err, B(&u.url))));
        }

        return Err(ConfError::Logged);
    }

    if u.addrs.is_empty() {
        return Err(msg("has no addresses"));
    }

    if u.no_port {
        return Err(msg("has no port"));
    }

    pscf.borrow_mut().addr = Some(u.addrs[0].clone());

    Ok(())
}

pub fn pass_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_pass_module",
        StreamModuleDef { create_srv_conf: Some(pass_create_srv_conf), ..Default::default() },
        vec![cmd_fn!("pass", NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, pass_directive)],
    )
}
