//! ngx_stream_realip_module.c

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::inet::{ptocidr, Cidr, CidrParse, SockAddr, Url};
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::cmd_fn;

use crate::core::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_realip_module");

/// ngx_stream_realip_srv_conf_t
#[derive(Default)]
pub struct RealipSrvConf {
    pub from: Option<Rc<Vec<Cidr>>>,
}

/// ngx_stream_realip_ctx_t: the address before the change
pub struct RealipCtx {
    pub sockaddr: SockAddr,
    pub addr_text: Vec<u8>,
}

/// ngx_stream_realip_handler
async fn realip_handler(s: S) -> i64 {
    let rscf = s.srv_conf::<RealipSrvConf>(ctx_index());

    let from = match rscf.borrow().from.clone() {
        None => return NGX_DECLINED,
        Some(f) => f,
    };

    let c = &s.connection;

    let pp = match c.proxy_protocol.borrow().clone().and_then(|p| p.downcast::<ngx_core::proxy_protocol::ProxyProtocol>().ok()) {
        None => return NGX_DECLINED,
        Some(pp) => pp,
    };

    let sa = c.sockaddr.borrow().clone();

    if !from.iter().any(|cidr| cidr.matches(&sa)) {
        return NGX_DECLINED;
    }

    let mut addr = match ngx_core::inet::parse_addr(&pp.src_addr) {
        None => return NGX_DECLINED,
        Some(a) => a,
    };

    addr.set_port(pp.src_port);

    realip_set_addr(&s, addr)
}

/// ngx_stream_realip_set_addr
fn realip_set_addr(s: &Session, addr: SockAddr) -> i64 {
    let c = &s.connection;

    let text = addr.to_text(false);

    if text.is_empty() {
        return NGX_ERROR;
    }

    let ctx = RealipCtx { sockaddr: c.sockaddr.borrow().clone(), addr_text: c.addr_text.borrow().clone() };

    s.set_ctx(ctx_index(), Rc::new(ctx));

    *c.sockaddr.borrow_mut() = addr;
    *c.addr_text.borrow_mut() = text;

    NGX_DECLINED
}

/// ngx_stream_realip_from
fn realip_from(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let rscf = conf_rc::<RealipSrvConf>(conf.as_ref().expect("conf"));

    let value = cf.args[1].clone();

    let mut from = rscf.borrow().from.as_deref().cloned().unwrap_or_default();

    if value == b"unix:" {
        from.push(Cidr::Unix);
        rscf.borrow_mut().from = Some(Rc::new(from));
        return Ok(());
    }

    match ptocidr(&value) {
        CidrParse::Error => {}

        CidrParse::Done(c) => {
            cf.warn(format_args!("low address bits of {} are meaningless", B(&value)));
            from.push(c);
            rscf.borrow_mut().from = Some(Rc::new(from));
            return Ok(());
        }

        CidrParse::Ok(c) => {
            from.push(c);
            rscf.borrow_mut().from = Some(Rc::new(from));
            return Ok(());
        }
    }

    let mut u = Url::default();
    u.host = value.clone();

    if ngx_core::inet::inet_resolve_host(&mut u).is_err() {
        if let Some(err) = u.err {
            return Err(cf.emerg(format_args!("{} in set_real_ip_from \"{}\"", err, B(&u.host))));
        }

        return Err(ConfError::Logged);
    }

    for a in u.addrs.iter() {
        match &a.sockaddr {
            SockAddr::V6(sa) => from.push(Cidr::V6 { addr: sa.ip().octets(), mask: [0xff; 16] }),
            SockAddr::V4(sa) => from.push(Cidr::V4 { addr: u32::from(*sa.ip()), mask: 0xffffffff }),
            SockAddr::Unix(_) => {}
        }
    }

    rscf.borrow_mut().from = Some(Rc::new(from));

    Ok(())
}

fn realip_create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(RealipSrvConf::default())
}

/// ngx_stream_realip_merge_srv_conf
fn realip_merge_srv_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<RealipSrvConf>(parent).borrow();
    let mut conf = conf_cell::<RealipSrvConf>(child).borrow_mut();

    if conf.from.is_none() {
        conf.from = prev.from.clone();
    }

    Ok(())
}

/// ngx_stream_realip_remote_addr_variable
fn realip_remote_addr_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let text = match s.get_ctx::<RealipCtx>(ctx_index()) {
        Some(ctx) => ctx.addr_text.clone(),
        None => s.connection.addr_text.borrow().clone(),
    };

    *v = VariableValue::new(&text);

    NGX_OK
}

/// ngx_stream_realip_remote_port_variable
fn realip_remote_port_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let port = match s.get_ctx::<RealipCtx>(ctx_index()) {
        Some(ctx) => ctx.sockaddr.port(),
        None => s.connection.sockaddr.borrow().port(),
    };

    *v = VariableValue::new(b"");

    if port > 0 {
        v.data = port.to_string().into_bytes();
    }

    NGX_OK
}

static REALIP_VARS: &[VarDef] = &[
    VarDef { name: "realip_remote_addr", set: None, get: Some(realip_remote_addr_variable), data: 0, flags: 0 },
    VarDef { name: "realip_remote_port", set: None, get: Some(realip_remote_port_variable), data: 0, flags: 0 },
];

/// ngx_stream_realip_add_variables
fn realip_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, REALIP_VARS)
}

/// ngx_stream_realip_init
fn realip_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_STREAM_POST_ACCEPT_PHASE, phase_fn(realip_handler));
    Ok(())
}

pub fn realip_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_realip_module",
        StreamModuleDef {
            preconfiguration: Some(realip_add_variables),
            postconfiguration: Some(realip_init),
            create_srv_conf: Some(realip_create_srv_conf),
            merge_srv_conf: Some(realip_merge_srv_conf),
            ..Default::default()
        },
        vec![cmd_fn!("set_real_ip_from", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1, ConfLevel::Srv, realip_from)],
    )
}
