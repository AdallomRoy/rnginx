//! ngx_http_rewrite_module (placeholder: "return" implemented, others accepted but not applied)

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::string::{atoi, B};

use crate::core::*;
use crate::request::*;
use crate::script::*;
use crate::*;

crate::http_module_index!("ngx_http_rewrite_module");

#[derive(Clone)]
pub enum Code {
    Return { status: i64, text: Option<ComplexValue> },
}

pub struct RewriteConf {
    pub codes: Vec<Code>,
    pub stack_size: Val<i64>,
    pub log: Val<bool>,
    pub uninitialized_variable_warn: Val<bool>,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(RewriteConf { codes: Vec::new(), stack_size: Val::unset(), log: Val::unset(), uninitialized_variable_warn: Val::unset() })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<RewriteConf>(prev).borrow();
    let mut c = conf_cell::<RewriteConf>(conf).borrow_mut();
    c.stack_size.merge(&p.stack_size, 10);
    c.log.merge(&p.log, false);
    c.uninitialized_variable_warn.merge(&p.uninitialized_variable_warn, true);
    Ok(())
}

fn return_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<RewriteConf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    let v = &args[1];
    let status: i64;
    let mut text: Option<Vec<u8>> = None;
    match atoi(v) {
        Some(s) => {
            status = s;
            if status > 999 {
                return Err(cf.emerg(format_args!("invalid return code \"{}\"", B(v))));
            }
            if args.len() == 3 {
                text = Some(args[2].clone());
            }
        }
        None => {
            if args.len() == 3 {
                return Err(cf.emerg(format_args!("invalid return code \"{}\"", B(v))));
            }
            status = NGX_HTTP_MOVED_TEMPORARILY;
            text = Some(v.clone());
        }
    }
    let cv = match text {
        Some(t) => Some(compile_complex_value(cf, &t, 0)?),
        None => None,
    };
    cell.borrow_mut().codes.push(Code::Return { status, text: cv });
    Ok(())
}

fn accept_directive(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn if_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // parse the block into a new location context (placeholder semantics)
    let saved_ct = cf.cmd_type;
    cf.cmd_type = if saved_ct == NGX_HTTP_SRV_CONF { NGX_HTTP_SIF_CONF } else { NGX_HTTP_LIF_CONF };
    let rv = cf.parse_block();
    cf.cmd_type = saved_ct;
    rv
}

pub fn rewrite_module() -> ModuleDef {
    const F: u32 = NGX_HTTP_SRV_CONF | NGX_HTTP_SIF_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF;
    let def = HttpModuleDef { postconfiguration: Some(init), create_loc_conf: Some(create_conf), merge_loc_conf: Some(merge_conf), ..Default::default() };
    let commands = vec![
        ngx_core::cmd_fn!("rewrite", F | NGX_CONF_TAKE23, ConfLevel::Loc, accept_directive),
        ngx_core::cmd_fn!("return", F | NGX_CONF_TAKE12, ConfLevel::Loc, return_directive),
        ngx_core::cmd_fn!("break", F | NGX_CONF_NOARGS, ConfLevel::Loc, accept_directive),
        ngx_core::cmd_fn!("if", NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_BLOCK | NGX_CONF_1MORE, ConfLevel::Loc, if_block),
        ngx_core::cmd_fn!("set", F | NGX_CONF_TAKE2, ConfLevel::Loc, accept_directive),
        ngx_core::cmd!("rewrite_log", NGX_HTTP_MAIN_CONF | F | NGX_CONF_FLAG, ConfLevel::Loc, RewriteConf, log, set_flag),
        ngx_core::cmd!("uninitialized_variable_warn", NGX_HTTP_MAIN_CONF | F | NGX_CONF_FLAG, ConfLevel::Loc, RewriteConf, uninitialized_variable_warn, set_flag),
    ];
    http_module_def("ngx_http_rewrite_module", def, commands)
}

fn init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_HTTP_SERVER_REWRITE_PHASE, Rc::new(|r| Box::pin(rewrite_handler(r))));
    add_phase_handler(cf, NGX_HTTP_REWRITE_PHASE, Rc::new(|r| Box::pin(rewrite_handler(r))));
    Ok(())
}

async fn rewrite_handler(r: R) -> i64 {
    let conf = r.loc_conf::<RewriteConf>(ctx_index());
    let codes = conf.borrow().codes.clone();
    for code in codes.iter() {
        match code {
            Code::Return { status, text } => {
                let status = *status;
                if status == NGX_HTTP_MOVED_PERMANENTLY || status == NGX_HTTP_MOVED_TEMPORARILY || status == NGX_HTTP_SEE_OTHER || status == NGX_HTTP_TEMPORARY_REDIRECT || status == NGX_HTTP_PERMANENT_REDIRECT || text.is_some() {
                    let cv = text.clone().unwrap_or_else(|| ComplexValue::constant(b""));
                    let ct: Option<&[u8]> = if text.is_some() && status < 300 { Some(b"text/plain") } else { None };
                    let rc = send_response(&r, status, ct, &cv).await;
                    if rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE {
                        return NGX_DONE;
                    }
                    return rc;
                }
                return status;
            }
        }
    }
    NGX_DECLINED
}
