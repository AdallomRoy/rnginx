import re
# real modules that exist in Rust master (module name -> rust path expression)
real = {
 'ngx_http_core_module': 'core::core_module()',
 'ngx_http_log_module': 'log::log_module()',
 'ngx_http_static_module': 'static_module::static_module()',
 'ngx_http_index_module': 'index::index_module()',
 'ngx_http_rewrite_module': 'rewrite::rewrite_module()',
 'ngx_http_access_module': 'access::access_module()',
 'ngx_http_auth_basic_module': 'auth_basic::auth_basic_module()',
 'ngx_http_auth_request_module': 'auth_request::auth_request_module()',
 'ngx_http_realip_module': 'realip::realip_module()',
 'ngx_http_stub_status_module': 'stub_status::stub_status_module()',
 'ngx_http_write_filter_module': 'write_filter::write_filter_module()',
 'ngx_http_header_filter_module': 'header_filter::header_filter_module()',
 'ngx_http_chunked_filter_module': 'chunked_filter::chunked_filter_module()',
 'ngx_http_postpone_filter_module': 'postpone_filter::postpone_filter_module()',
 'ngx_http_headers_filter_module': 'headers_filter::headers_filter_module()',
 'ngx_http_copy_filter_module': 'copy_filter::copy_filter_module()',
 'ngx_http_not_modified_filter_module': 'not_modified_filter::not_modified_filter_module()',
}
order = [l.strip() for l in open('/tmp/module_order.txt')]
start = order.index('ngx_http_module') + 1
end = order.index('ngx_mail_module')
http_mods = order[start:end]
cmds = {}
cur = None
for line in open('/tmp/http_cmds.txt'):
    if line.startswith('MODULE'):
        cur = line.split()[1]; cmds.setdefault(cur, [])
    elif line.startswith('   ') and cur:
        name, flags = line.split()
        cmds[cur].append((name, flags))
out = []
out.append('''//! GENERATED parse-only stubs for modules not yet ported (scripts/gen_stubs.py).
//! Each stub registers the module's directives with the C flags so that
//! configurations parse; block directives are skipped. Replace a stub by adding a
//! real module file and switching the entry in `crate::modules()`.

#![allow(dead_code)]

use std::any::Any;
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::connection::Connection;
use ngx_core::module::ModuleDef;

use crate::core::*;
use crate::request::*;
use crate::*;

fn accept(_cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    Ok(())
}

fn skip_any(_cf: &mut Conf, _c: Rc<dyn Any>) -> ConfResult {
    Ok(())
}

/// Consume a `{ ... }` block, ignoring its contents.
pub fn skip_block(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let saved_h = cf.handler.take();
    let saved_hc = cf.handler_conf.take();
    cf.handler = Some(skip_any);
    cf.handler_conf = Some(Rc::new(()));
    let rv = cf.parse_block();
    cf.handler = saved_h;
    cf.handler_conf = saved_hc;
    rv
}

fn stub(name: &'static str, commands: Vec<Command>) -> ModuleDef {
    http_module_def(name, HttpModuleDef::default(), commands)
}
''')
fn_names = {}
for m in http_mods:
    if m in real: continue
    short = m
    if short.startswith('ngx_http_'): short = short[len('ngx_http_'):]
    if short.endswith('_module'): short = short[:-len('_module')]
    fn = short + '_module'
    fn_names[m] = fn
    out.append(f'pub fn {fn}() -> ModuleDef {{')
    out.append(f'    stub("{m}", vec![')
    for name, flags in cmds.get(m, []):
        fl = ' | '.join(flags.split('|'))
        handler = 'skip_block' if 'NGX_CONF_BLOCK' in flags else 'accept'
        out.append(f'        Command::new("{name}", {fl}, ConfLevel::None, {handler}),')
    out.append('    ])')
    out.append('}')
    out.append('')
out.append('''
// --- hooks the core calls into not-yet-ported modules ---

pub fn upstream_log_info(_r: &Request) -> Option<Vec<u8>> {
    None
}

pub async fn ssl_handshake(_c: &Rc<Connection>, _hc: &Rc<HttpConnection>) -> bool {
    false
}

pub fn ssl_verify_enabled(_cscf: &Rc<std::cell::RefCell<CoreSrvConf>>) -> bool {
    false
}

pub fn ssl_process_request_checks(_r: &R) -> Option<i64> {
    None
}

pub async fn ssl_shutdown(_c: &Rc<Connection>) {}
''')
open('/home/ubuntu/rnginx/crates/ngx-http/src/stubs.rs','w').write('\n'.join(out))
# modules() body
lines = ['/// All http modules in nginx order (nginx-c/objs/ngx_modules.c).', 'pub fn modules() -> Vec<ModuleDef> {', '    vec![', '        http_module(),']
for m in http_mods:
    if m in real: lines.append(f'        {real[m]},')
    else: lines.append(f'        stubs::{fn_names[m]}(),')
lines.append('    ]'); lines.append('}')
open('/tmp/modules_fn.rs','w').write('\n'.join(lines)+'\n')
print(len(http_mods), 'http modules;', sum(1 for m in http_mods if m not in real), 'stubs')
