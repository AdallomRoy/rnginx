//! ngx_stream_set_module.c

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::cmd_fn;

use crate::core::*;
use crate::script::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_set_module");

/// ngx_stream_set_cmd_t
pub struct SetCmd {
    pub index: usize,
    pub set_handler: Option<SetHandler>,
    pub data: usize,
    pub value: ComplexValue,
}

/// ngx_stream_set_srv_conf_t
#[derive(Default)]
pub struct SetSrvConf {
    pub commands: Vec<Rc<SetCmd>>,
}

/// ngx_stream_set_handler
async fn set_handler(s: S) -> i64 {
    let scf = s.srv_conf::<SetSrvConf>(ctx_index());
    let cmds = scf.borrow().commands.clone();

    for cmd in cmds.iter() {
        let str = match complex_value(&s, &cmd.value) {
            Ok(v) => v,
            Err(()) => return NGX_ERROR,
        };

        if let Some(set) = cmd.set_handler {
            let mut vv = null_value();
            vv.data = str;
            set(&s, &mut vv, cmd.data);
        } else {
            let mut vars = s.variables.borrow_mut();
            vars[cmd.index] = VariableValue { data: str, valid: true, no_cacheable: false, not_found: false };
        }
    }

    NGX_DECLINED
}

/// ngx_stream_set_var
fn set_var(_s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    *v = null_value();
    NGX_OK
}

/// ngx_stream_set_init
fn set_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_STREAM_PREACCESS_PHASE, phase_fn(set_handler));
    Ok(())
}

fn set_create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SetSrvConf::default())
}

/// ngx_stream_set
fn set_directive(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let scf = conf_rc::<SetSrvConf>(conf.as_ref().expect("conf"));

    let args = cf.args.clone();

    if args[1].first() != Some(&b'$') {
        return Err(cf.emerg(format_args!("invalid variable name \"{}\"", B(&args[1]))));
    }

    let name = &args[1][1..];

    let v = add_variable(cf, name, NGX_STREAM_VAR_CHANGEABLE | NGX_STREAM_VAR_WEAK)?;

    let index = get_variable_index(cf, name)?;

    if v.get_handler.get().is_none() {
        v.get_handler.set(Some(set_var));
    }

    let mut ccv = CompileComplexValue::default();
    let value = compile_complex_value(cf, &args[2], &mut ccv)?;

    scf.borrow_mut().commands.push(Rc::new(SetCmd { index, set_handler: v.set_handler.get(), data: v.data.get(), value }));

    Ok(())
}

pub fn set_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_set_module",
        StreamModuleDef { postconfiguration: Some(set_init), create_srv_conf: Some(set_create_srv_conf), ..Default::default() },
        vec![cmd_fn!("set", NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2, ConfLevel::Srv, set_directive)],
    )
}
