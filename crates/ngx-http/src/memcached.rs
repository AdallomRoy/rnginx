//! ngx_http_memcached_module: minimal memcached upstream content handler.
//!
//! Sends `get <key>\r\n`, parses `VALUE <key> <flags> <bytes>\r\n<data>\r\nEND\r\n`
//! or `END\r\n` (not found). Enough for the test suite's use of a mock daemon.

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, Chain};
use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::request::*;
use crate::variables::*;
use crate::*;

crate::http_module_index!("ngx_http_memcached_module");

pub struct MemcachedLocConf {
    pub upstream: Option<Vec<u8>>,  // host:port
    /// the upstream of memcached_pass (ngx_http_upstream_add)
    pub upstream_conf: Option<Rc<crate::upstream::UpstreamSrvConf>>,
    pub gzip_flag: Val<u32>,
    pub next_upstream_not_found: Val<bool>,
}

impl Default for MemcachedLocConf {
    fn default() -> Self {
        MemcachedLocConf {
            upstream: None,
            upstream_conf: None,
            gzip_flag: Val::unset(),
            next_upstream_not_found: Val::unset(),
        }
    }
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> { make_slot(MemcachedLocConf::default()) }

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<MemcachedLocConf>(prev).borrow();
    let mut c = conf_cell::<MemcachedLocConf>(conf).borrow_mut();
    if c.upstream.is_none() {
        c.upstream = p.upstream.clone();
        c.upstream_conf = p.upstream_conf.clone();
    }
    c.gzip_flag.merge(&p.gzip_flag, 0);
    c.next_upstream_not_found.merge(&p.next_upstream_not_found, false);
    Ok(())
}

pub fn memcached_module() -> ModuleDef {
    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("memcached_pass", NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_memcached_pass),
        ngx_core::cmd_fn!("memcached_bind", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("memcached_socket_keepalive", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("memcached_connect_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("memcached_send_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("memcached_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("memcached_read_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("memcached_next_upstream", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::Loc, set_next_upstream),
        ngx_core::cmd_fn!("memcached_next_upstream_tries", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("memcached_next_upstream_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, |_cf, _cmd, _conf| Ok(())),
        ngx_core::cmd_fn!("memcached_gzip_flag", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, set_gzip_flag),
    ];
    http_module_def("ngx_http_memcached_module", def, commands)
}

fn set_memcached_pass(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<MemcachedLocConf>(conf.as_ref().unwrap());
    if cell.borrow().upstream.is_some() {
        return Err(msg("is duplicate"));
    }
    let mut u = ngx_core::inet::Url::new(&cf.args[1]);
    u.no_resolve = true;
    let uscf = crate::upstream::upstream_add(cf, &mut u, 0)?;
    cell.borrow_mut().upstream_conf = Some(uscf);
    cell.borrow_mut().upstream = Some(cf.args[1].clone());
    let loc = crate::get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());
    loc.borrow_mut().handler = Some(Rc::new(|r| Box::pin(handler(r))));
    Ok(())
}

fn set_next_upstream(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<MemcachedLocConf>(conf.as_ref().unwrap());
    let mut c = cell.borrow_mut();
    for a in cf.args.iter().skip(1) {
        if a.as_slice() == b"not_found" {
            c.next_upstream_not_found = Val::set(true);
        }
    }
    Ok(())
}

fn set_gzip_flag(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<MemcachedLocConf>(conf.as_ref().unwrap());
    let v: u32 = std::str::from_utf8(&cf.args[1]).ok().and_then(|s| s.parse().ok())
        .ok_or_else(|| msg("invalid gzip flag"))?;
    cell.borrow_mut().gzip_flag = Val::set(v);
    Ok(())
}

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    let vars = vec![
        VarDef { name: "memcached_key", set: None, get: Some(var_memcached_key), data: 0, flags: NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE },
    ];
    add_variables(cf, &vars)?;
    Ok(())
}

fn var_memcached_key(_r: &R, v: &mut VariableValue, _d: usize) -> i64 {
    v.data = Vec::new();
    v.valid = true;
    NGX_OK
}

async fn handler(r: R) -> i64 {
    // Read memcached_key: nginx exposes it as $memcached_key which is
    // usually set via `set $memcached_key $uri;`. We look up the value
    // through the variable engine (which handles the `set` writeback).
    let key = {
        let name = b"memcached_key".to_vec();
        match crate::variables::get_variable(&r, &name) {
            Some(v) if !v.not_found && !v.data.is_empty() => v.data,
            _ => {
                ngx_core::ngx_log_error!(NGX_LOG_ERR, r.connection.log, None,
                    "the \"$memcached_key\" variable is not set");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    };
    let (uscf, next_not_found, gzip_flag, tag) = {
        let conf = r.loc_conf::<MemcachedLocConf>(ctx_index());
        let c = conf.borrow();
        let uscf = match &c.upstream_conf {
            Some(u) => u.clone(),
            None => return NGX_DECLINED,
        };
        (uscf, c.next_upstream_not_found.get_or(false), *c.gzip_flag, Rc::as_ptr(&conf) as *const () as usize)
    };
    // Discard body — we don't proxy any body to memcached.
    let rc = crate::request_body::discard_request_body(&r).await;
    if rc != NGX_OK { return rc; }

    use crate::upstream::{UpstreamConn, UpstreamPeer, NGX_HTTP_UPSTREAM_FT_ERROR, NGX_HTTP_UPSTREAM_FT_NOLIVE, NGX_HTTP_UPSTREAM_FT_TIMEOUT};

    let mut u = match UpstreamPeer::init(&r, &uscf, NGX_HTTP_UPSTREAM_FT_ERROR | NGX_HTTP_UPSTREAM_FT_TIMEOUT, 0, 0, tag) {
        Ok(u) => u,
        Err(rc) => return rc,
    };

    let cmd = format!("get {}\r\n", std::str::from_utf8(&key).unwrap_or(""));

    let (conn, buf) = loop {
        // ngx_http_upstream_connect
        let rc = u.connect(&r);

        if rc == NGX_BUSY {
            match u.next(&r, NGX_HTTP_UPSTREAM_FT_NOLIVE) {
                Ok(()) => continue,
                Err(st) => return st,
            }
        }

        let start = u.start_time;

        let (mut stream, requests, start_time) = if rc == NGX_DONE {
            let c = u.pc.connection.take().unwrap();
            (c.sock, c.requests, c.start_time)
        } else {
            let sockaddr = match u.pc.sockaddr.clone() {
                Some(sa) => sa,
                None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
            };
            match crate::proxy::connect_upstream(&r, &sockaddr, None, None, 60000).await {
                Ok(s) => (s, 0, ngx_core::times::current_msec()),
                Err(_) => match u.next(&r, NGX_HTTP_UPSTREAM_FT_ERROR) {
                    Ok(()) => continue,
                    Err(st) => return st,
                },
            }
        };

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.connect_time = ngx_core::times::current_msec().saturating_sub(start);
        }

        u.request_sent = true;

        if stream.write_all(cmd.as_bytes()).await.is_err() {
            match u.next(&r, NGX_HTTP_UPSTREAM_FT_ERROR) {
                Ok(()) => continue,
                Err(st) => return st,
            }
        }

        let mut buf = Vec::new();
        // Read enough to see the framing. memcached responses start with either
        // `VALUE …\r\n<data>\r\nEND\r\n` or `END\r\n` (or an error string). We
        // read until we see the closing END or the connection closes.
        let mut tmp = [0u8; 4096];
        let mut failed = false;
        loop {
            match stream.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    // Look for terminating END\r\n or an error line.
                    if let Some(end) = find_seq(&buf, b"\r\nEND\r\n") {
                        buf.truncate(end + 7);
                        break;
                    }
                    if buf.starts_with(b"END\r\n") {
                        buf.truncate(5);
                        break;
                    }
                    if buf.starts_with(b"ERROR") || buf.starts_with(b"CLIENT_ERROR") || buf.starts_with(b"SERVER_ERROR") {
                        // Read until \r\n
                        if let Some(_p) = find_seq(&buf, b"\r\n") { break; }
                    }
                    if buf.len() > 1 << 20 { break; }
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }

        if failed || buf.is_empty() {
            match u.next(&r, NGX_HTTP_UPSTREAM_FT_ERROR) {
                Ok(()) => continue,
                Err(st) => return st,
            }
        }

        if let Some(st) = r.upstream_states.borrow_mut().last_mut() {
            st.header_time = ngx_core::times::current_msec().saturating_sub(start);
            st.bytes_received = buf.len() as i64;
        }

        break (UpstreamConn { sock: stream, requests: requests + 1, start_time }, buf);
    };

    // the response was read in full: u->keepalive
    let complete = buf.ends_with(b"END\r\n");
    u.finalize(&r, Some(conn), complete, true);

    if buf.starts_with(b"END\r\n") {
        // not found
        if next_not_found {
            return NGX_HTTP_NOT_FOUND;
        }
        return NGX_HTTP_NOT_FOUND;
    }
    if !buf.starts_with(b"VALUE ") {
        return NGX_HTTP_BAD_GATEWAY;
    }
    // Parse status line: VALUE <key> <flags> <bytes>\r\n
    let nl = match buf.iter().position(|&b| b == b'\n') {
        Some(i) => i,
        None => return NGX_HTTP_BAD_GATEWAY,
    };
    let status_line = &buf[..nl];
    let status_line = if status_line.last() == Some(&b'\r') { &status_line[..status_line.len()-1] } else { status_line };
    // parts: VALUE key flags bytes
    let parts: Vec<&[u8]> = status_line.split(|&b| b == b' ').collect();
    if parts.len() < 4 { return NGX_HTTP_BAD_GATEWAY; }
    let flags: u32 = std::str::from_utf8(parts[2]).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let bytes: usize = match std::str::from_utf8(parts[3]).ok().and_then(|s| s.parse().ok()) {
        Some(n) => n,
        None => return NGX_HTTP_BAD_GATEWAY,
    };
    // Data starts right after \r\n
    let data_start = nl + 1;
    if buf.len() < data_start + bytes {
        return NGX_HTTP_BAD_GATEWAY;
    }
    let data = buf[data_start..data_start + bytes].to_vec();

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.content_length_n = bytes as i64;
        if ho.content_type.is_empty() {
            ho.content_type = b"text/plain".to_vec();
            ho.content_type_len = 10;
        }
        // gzip_flag: set Content-Encoding: gzip when the memcached flags
        // include the configured bit (matches ngx_http_memcached_process
        // _header). Enables gunzip_static-style downstream decoding.
        if gzip_flag != 0 && (flags & gzip_flag) != 0 {
            let h = crate::request::TableElt::new(b"Content-Encoding", b"gzip");
            ho.content_encoding = Some(h);
        }
    }
    let rc = crate::core_rt::send_header(&r).await;
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return rc;
    }
    let mut b = Buf::from_vec(data);
    b.memory = true;
    b.last_buf = r.is_main();
    b.last_in_chain = true;
    let mut chain = Chain::new();
    chain.push_back(b);
    crate::core_rt::output_filter(&r, chain).await
}

fn find_seq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
