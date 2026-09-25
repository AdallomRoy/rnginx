//! ngx_http_proxy_module - HTTP proxy with upstream framework

use std::any::Any;
use std::rc::Rc;
use std::io::Write;

use ngx_core::conf::*;
use ngx_core::module::ModuleDef;
use ngx_core::rc::*;
use ngx_core::cmd_fn;
use ngx_core::conf::{NGX_CONF_TAKE1, NGX_CONF_TAKE2, NGX_CONF_TAKE3, NGX_CONF_TAKE4, NGX_CONF_TAKE12, NGX_CONF_TAKE123, NGX_CONF_TAKE1234, NGX_CONF_1MORE, NGX_CONF_2MORE};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::cell::RefCell;

use crate::core::*;
use crate::request::*;
use crate::upstream::*;
use crate::variables::VarDef;
use crate::get_loc_conf;
use crate::{NGX_HTTP_MAIN_CONF, NGX_HTTP_SRV_CONF, NGX_HTTP_LOC_CONF, NGX_HTTP_BAD_GATEWAY, NGX_HTTP_OK, HttpModuleDef, http_module_def};

crate::http_module_index!("ngx_http_proxy_module");

/// Proxy location configuration
pub struct NgxHttpProxyLocConf {
    pub upstream_uri: Option<Vec<u8>>,  // proxy_pass URL
}

impl Default for NgxHttpProxyLocConf {
    fn default() -> Self {
        NgxHttpProxyLocConf {
            upstream_uri: None,
        }
    }
}

fn create_loc_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(NgxHttpProxyLocConf::default())
}

fn merge_loc_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<NgxHttpProxyLocConf>(prev).borrow();
    let mut c = conf_cell::<NgxHttpProxyLocConf>(conf).borrow_mut();
    if c.upstream_uri.is_none() {
        c.upstream_uri = p.upstream_uri.clone();
    }
    Ok(())
}

fn proxy_pass_handler(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("no proxy_pass URI specified"));
    }

    if let Some(c) = conf {
        let conf = conf_rc::<NgxHttpProxyLocConf>(&c);
        conf.borrow_mut().upstream_uri = Some(cf.args[1].clone());
    }

    // Set the location handler to our proxy_handler
    let loc_conf = get_loc_conf::<crate::core::CoreLocConf>(cf, crate::core::ctx_index());
    loc_conf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(proxy_handler(r))));

    Ok(())
}

fn proxy_redirect_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_buffering_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_request_buffering_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_bind_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_connect_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_send_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_read_timeout_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 2 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_set_header_handler(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    if cf.args.len() < 3 {
        return Err(msg("invalid number of arguments"));
    }
    Ok(())
}

fn proxy_host_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return proxy_host (hostname being proxied to)
    v.not_found = true; NGX_OK
}

fn proxy_port_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return proxy_port (port being proxied to)
    v.not_found = true; NGX_OK
}

fn proxy_add_x_forwarded_for_variable(_r: &R, v: &mut crate::request::VariableValue, _data: usize) -> i64 {
    // TODO: Return whether to add X-Forwarded-For header
    v.not_found = true; NGX_OK
}

fn preconfiguration(cf: &mut Conf) -> ConfResult {
    let vars = vec![
        VarDef {
            name: "proxy_host",
            get: Some(proxy_host_variable),
            set: None,
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "proxy_port",
            get: Some(proxy_port_variable),
            set: None,
            data: 0,
            flags: 0,
        },
        VarDef {
            name: "proxy_add_x_forwarded_for",
            get: Some(proxy_add_x_forwarded_for_variable),
            set: None,
            data: 0,
            flags: 0,
        },
    ];

    crate::variables::add_variables(cf, &vars)?;

    // Register proxy handler in content phase
    crate::core::add_phase_handler(cf, crate::NGX_HTTP_CONTENT_PHASE, Rc::new(|r| Box::pin(proxy_handler(r))));

    Ok(())
}

async fn proxy_handler(r: R) -> i64 {
    eprintln!("DEBUG proxy_handler: CALLED");
    let lcf = r.loc_conf::<NgxHttpProxyLocConf>(ctx_index());
    let conf_borrowed = lcf.borrow();
    eprintln!("DEBUG proxy_handler: upstream_uri = {:?}", conf_borrowed.upstream_uri);

    // Check if this location has proxy_pass configured
    let upstream_uri = match &conf_borrowed.upstream_uri {
        Some(uri) => uri.clone(),
        None => {
            eprintln!("DEBUG proxy_handler: no upstream_uri, declining");
            return NGX_DECLINED;
        }
    };

    // Parse upstream URI
    let upstream_uri_str = match std::str::from_utf8(&upstream_uri) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("DEBUG proxy_handler: invalid UTF-8 in URI");
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    let (host, port, _path) = match parse_upstream_uri(upstream_uri_str) {
        Some(p) => {
            eprintln!("DEBUG: parsed URI successfully");
            p
        }
        None => {
            eprintln!("DEBUG: failed to parse URI: {}", upstream_uri_str);
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    // Try to connect to upstream
    let addr = format!("{}:{}", host, port);
    eprintln!("DEBUG: connecting to {}", addr);
    let mut upstream = match TcpStream::connect(&addr).await {
        Ok(s) => {
            eprintln!("DEBUG: connected");
            s
        }
        Err(e) => {
            eprintln!("DEBUG: connection failed: {}", e);
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    // Build request line
    let method_name = r.method_name.borrow();
    let method = std::str::from_utf8(&method_name).unwrap_or("GET");

    let uri = r.uri.borrow();
    let uri_path = std::str::from_utf8(&uri).unwrap_or("/");

    let request = format!(
        "{} {} HTTP/1.0\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         \r\n",
        method, uri_path, host
    );

    // Send request to upstream
    if let Err(_) = upstream.write_all(request.as_bytes()).await {
        return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
    }

    // Read entire response
    let mut response = Vec::new();
    if let Err(_) = upstream.read_to_end(&mut response).await {
        return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
    }

    if response.is_empty() {
        eprintln!("DEBUG: empty response from upstream");
        return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
    }

    eprintln!("DEBUG: upstream response ({} bytes): {:?}", response.len(), String::from_utf8_lossy(&response[..response.len().min(200)]));

    // Parse status line
    let status_line_end = match response.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => pos,
        None => match response.windows(2).position(|w| w == b"\n\n") {
            Some(pos) => pos,
            None => {
                eprintln!("DEBUG: could not find response header terminator");
                return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
            }
        }
    };

    let headers_section = &response[..status_line_end];
    let body_start = if response[status_line_end..].starts_with(b"\r\n\r\n") {
        status_line_end + 4
    } else {
        status_line_end + 2
    };

    // Parse status line
    let status_line_end_nl = match headers_section.iter().position(|&b| b == b'\n') {
        Some(pos) => pos,
        None => {
            eprintln!("DEBUG: could not find newline in status line");
            return return_error(&r, NGX_HTTP_BAD_GATEWAY as i64).await;
        }
    };

    let status_line = &headers_section[..status_line_end_nl];
    let status_line_str = std::str::from_utf8(status_line).unwrap_or("HTTP/1.0 500 Internal Server Error");
    eprintln!("DEBUG: status_line_str = {}", status_line_str);

    // Parse "HTTP/1.x NNN Reason"
    let parts: Vec<&str> = status_line_str.split_whitespace().collect();
    let status: i64 = if parts.len() >= 2 {
        parts[1].parse().unwrap_or(502)
    } else {
        502
    };
    eprintln!("DEBUG: parsed status = {}", status);

    // Set status in response headers
    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = status;
        eprintln!("DEBUG: set ho.status = {}", ho.status);
    }

    // Send status and headers to client
    eprintln!("DEBUG: before send_header: err_status={}, post_action={}, header_sent={}", r.err_status.get(), r.post_action.get(), r.header_sent.get());
    let send_hdr_rc = crate::core_rt::send_header(&r).await;
    eprintln!("DEBUG: send_header returned {}", send_hdr_rc);
    if send_hdr_rc != NGX_OK {
        eprintln!("DEBUG: send_header failed");
        return NGX_ERROR;
    }

    // Forward response body
    if body_start < response.len() {
        let body = &response[body_start..];

        // Create a buffer chain for the body
        use ngx_core::buf::{Buf, BufData, Chain};
        use std::collections::VecDeque;

        let mut chain: Chain = VecDeque::new();

        let buf = Buf {
            pos: 0,
            last: body.len(),
            file_pos: 0,
            file_last: 0,
            tag: 0,
            num: 0,
            data: BufData::Memory(body.to_vec()),
            temporary: true,
            memory: false,
            mmap: false,
            recycled: false,
            in_file: false,
            flush: false,
            sync: false,
            last_buf: true,
            last_in_chain: true,
            temp_file: false,
        };

        chain.push_back(buf);

        if crate::core_rt::output_filter(&r, chain).await != NGX_OK {
            return NGX_ERROR;
        }
    }

    NGX_OK
}

async fn return_error(r: &R, status: i64) -> i64 {
    let mut ho = r.headers_out.borrow_mut();
    ho.status = status;
    drop(ho);

    if crate::core_rt::send_header(r).await != NGX_OK {
        return NGX_ERROR;
    }

    NGX_OK
}

/// Parse upstream URL of form "http://host:port/path" or "http://host/path" (assumes port 80)
fn parse_upstream_uri(uri: &str) -> Option<(String, u16, String)> {
    if !uri.starts_with("http://") {
        return None;
    }

    let rest = &uri[7..];

    // Find host:port or just host
    let (host_port, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], rest[pos..].to_string())
    } else {
        (rest, "/".to_string())
    };

    // Parse host and port
    let (host, port) = if let Some(pos) = host_port.find(':') {
        let h = &host_port[..pos];
        let p: u16 = host_port[pos+1..].parse().ok()?;
        (h.to_string(), p)
    } else {
        (host_port.to_string(), 80)
    };

    Some((host, port, path))
}

pub fn proxy_module() -> ModuleDef {
    let commands = vec![
        cmd_fn!("proxy_pass", NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_pass_handler),
        cmd_fn!("proxy_redirect", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::None, proxy_redirect_handler),
        cmd_fn!("proxy_buffering", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_buffering_handler),
        cmd_fn!("proxy_request_buffering", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_request_buffering_handler),
        cmd_fn!("proxy_bind", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::Loc, proxy_bind_handler),
        cmd_fn!("proxy_connect_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_connect_timeout_handler),
        cmd_fn!("proxy_send_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_send_timeout_handler),
        cmd_fn!("proxy_read_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, proxy_read_timeout_handler),
        cmd_fn!("proxy_set_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::None, proxy_set_header_handler),
        // Additional proxy directives that tests need
        cmd_fn!("proxy_temp_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_buffers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_busy_buffers_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_max_temp_file_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_next_upstream", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_next_upstream_tries", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_next_upstream_timeout", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_pass_request_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_pass_request_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_method", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_http_version", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_socket_keepalive", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cookie_domain", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cookie_path", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_cookie_flags", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1234, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_set_body", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_pass_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_hide_header", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ignore_headers", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_intercept_errors", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_ignore_client_abort", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_store", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_store_access", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_limit_rate", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_force_ranges", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_headers_hash_max_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
        cmd_fn!("proxy_headers_hash_bucket_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::None, |_cf, _cmd, _conf| Ok(())),
    ];

    let def = HttpModuleDef {
        preconfiguration: Some(preconfiguration),
        create_loc_conf: Some(create_loc_conf),
        merge_loc_conf: Some(merge_loc_conf),
        ..Default::default()
    };

    http_module_def("ngx_http_proxy_module", def, commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_proxy_conf() {
        let mut cf = Conf::default();
        let _slot = create_loc_conf(&mut cf);
    }
}
