//! ngx_stream_ssl_preread_module.c: the server name, the ALPN protocols
//! and the version of the TLS ClientHello of the client, without
//! terminating TLS.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{cmd, ngx_log_debug};

use crate::core::*;
use crate::variables::*;
use crate::*;

stream_module_index!("ngx_stream_ssl_preread_module");

/// ngx_stream_ssl_preread_srv_conf_t
#[derive(Default)]
pub struct SslPrereadSrvConf {
    pub enabled: Val<bool>,
}

/// Where the parser copies the bytes (ctx->dst).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Dst {
    None,
    Buf(usize),
    Version(usize),
    Host(usize),
    Alpn(usize),
}

const SW_START: u32 = 0;
const SW_HEADER: u32 = 1; /* handshake msg_type, length */
const SW_VERSION: u32 = 2; /* client_version */
const SW_RANDOM: u32 = 3; /* random */
const SW_SID_LEN: u32 = 4; /* session_id length */
const SW_SID: u32 = 5; /* session_id */
const SW_CS_LEN: u32 = 6; /* cipher_suites length */
const SW_CS: u32 = 7; /* cipher_suites */
const SW_CM_LEN: u32 = 8; /* compression_methods length */
const SW_CM: u32 = 9; /* compression_methods */
const SW_EXT: u32 = 10; /* extension */
const SW_EXT_HEADER: u32 = 11; /* extension_type, extension_data length */
const SW_SNI_LEN: u32 = 12; /* SNI length */
const SW_SNI_HOST_HEAD: u32 = 13; /* SNI name_type, host_name length */
const SW_SNI_HOST: u32 = 14; /* SNI host_name */
const SW_ALPN_LEN: u32 = 15; /* ALPN length */
const SW_ALPN_PROTO_LEN: u32 = 16; /* ALPN protocol_name length */
const SW_ALPN_PROTO_DATA: u32 = 17; /* ALPN protocol_name */
const SW_SUPVER_LEN: u32 = 18; /* supported_versions length */

/// ngx_stream_ssl_preread_ctx_t
pub struct SslPrereadCtx {
    left: Cell<usize>,
    size: Cell<usize>,
    ext: Cell<usize>,
    /// the offset of the unparsed data in c->buffer
    pos: Cell<usize>,
    dst: Cell<Dst>,
    buf: Cell<[u8; 4]>,
    version: Cell<[u8; 2]>,
    /// host.data (NULL: no SNI yet) and host.len
    host: RefCell<Option<Vec<u8>>>,
    host_len: Cell<usize>,
    /// alpn.data and alpn.len
    alpn: RefCell<Option<Vec<u8>>>,
    alpn_len: Cell<usize>,
    log: Log,
    state: Cell<u32>,
}

impl SslPrereadCtx {
    fn new(log: Log, pos: usize) -> SslPrereadCtx {
        SslPrereadCtx {
            left: Cell::new(0),
            size: Cell::new(0),
            ext: Cell::new(0),
            pos: Cell::new(pos),
            dst: Cell::new(Dst::None),
            buf: Cell::new([0; 4]),
            version: Cell::new([0; 2]),
            host: RefCell::new(None),
            host_len: Cell::new(0),
            alpn: RefCell::new(None),
            alpn_len: Cell::new(0),
            log,
            state: Cell::new(SW_START),
        }
    }

    /// ngx_cpymem(dst, pos, n): the destination advances
    fn copy(&self, dst: Dst, data: &[u8]) -> Dst {
        let n = data.len();

        match dst {
            Dst::None => Dst::None,

            Dst::Buf(off) => {
                let mut b = self.buf.get();
                b[off..off + n].copy_from_slice(data);
                self.buf.set(b);
                Dst::Buf(off + n)
            }

            Dst::Version(off) => {
                let mut v = self.version.get();
                v[off..off + n].copy_from_slice(data);
                self.version.set(v);
                Dst::Version(off + n)
            }

            Dst::Host(off) => {
                let mut h = self.host.borrow_mut();
                h.as_mut().unwrap()[off..off + n].copy_from_slice(data);
                Dst::Host(off + n)
            }

            Dst::Alpn(off) => {
                let mut a = self.alpn.borrow_mut();
                a.as_mut().unwrap()[off..off + n].copy_from_slice(data);
                Dst::Alpn(off + n)
            }
        }
    }

    fn host(&self) -> Vec<u8> {
        match self.host.borrow().as_ref() {
            Some(h) => h[..self.host_len.get()].to_vec(),
            None => Vec::new(),
        }
    }

    fn alpn(&self) -> Vec<u8> {
        match self.alpn.borrow().as_ref() {
            Some(a) => a[..self.alpn_len.get()].to_vec(),
            None => Vec::new(),
        }
    }
}

/// ngx_stream_ssl_preread_handler
async fn ngx_stream_ssl_preread_handler(s: S) -> i64 {
    let c = s.connection.clone();

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "ssl preread handler");

    let enabled = *s.srv_conf::<SslPrereadSrvConf>(ctx_index()).borrow().enabled;

    if !enabled {
        return NGX_DECLINED;
    }

    if c.ty != libc::SOCK_STREAM {
        return NGX_DECLINED;
    }

    // c->buffer == NULL: nothing was read yet
    if c.buffer.borrow().is_empty() {
        return NGX_AGAIN;
    }

    let ctx = match s.get_ctx::<SslPrereadCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => {
            let ctx = Rc::new(SslPrereadCtx::new(c.log.clone(), 0));
            s.set_ctx(ctx_index(), ctx.clone());
            ctx
        }
    };

    let buffer = c.buffer.borrow().clone();

    let mut p = ctx.pos.get();
    let last = buffer.len();

    while last >= p + 5 {
        let h = &buffer[p..];

        if (h[0] & 0x80) != 0 && h[2] == 1 && (h[3] == 0 || h[3] == 3) {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: version 2 ClientHello");
            ctx.version.set([h[3], h[4]]);
            return NGX_OK;
        }

        if h[0] != 0x16 {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: not a handshake");
            s.delete_ctx(ctx_index());
            return NGX_DECLINED;
        }

        if h[1] != 3 {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: unsupported SSL version");
            s.delete_ctx(ctx_index());
            return NGX_DECLINED;
        }

        let len = ((h[3] as usize) << 8) + h[4] as usize;

        /* read the whole record before parsing */
        if last - p < len + 5 {
            break;
        }

        p += 5;

        let rc = ngx_stream_ssl_preread_parse_record(&ctx, &buffer[p..p + len]);

        if rc == NGX_DECLINED {
            s.delete_ctx(ctx_index());
            return NGX_DECLINED;
        }

        if rc == NGX_OK {
            let host = ctx.host();
            return ngx_stream_ssl_preread_servername(&s, &host);
        }

        if rc != NGX_AGAIN {
            return rc;
        }

        p += len;
    }

    ctx.pos.set(p);

    NGX_AGAIN
}

/// ngx_stream_ssl_preread_parse_record: a handshake record
fn ngx_stream_ssl_preread_parse_record(ctx: &SslPrereadCtx, data: &[u8]) -> i64 {
    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: state {} left {}", ctx.state.get(), ctx.left.get());

    let mut state = ctx.state.get();
    let mut size = ctx.size.get();
    let mut left = ctx.left.get();
    let mut ext = ctx.ext.get();
    let mut dst = ctx.dst.get();

    let mut pos = 0usize;
    let last = data.len();

    loop {
        let n = (last - pos).min(size);

        if dst != Dst::None {
            dst = ctx.copy(dst, &data[pos..pos + n]);
        }

        pos += n;
        size -= n;
        left = left.wrapping_sub(n);

        if size != 0 {
            break;
        }

        let p = ctx.buf.get();

        match state {
            SW_START => {
                state = SW_HEADER;
                dst = Dst::Buf(0);
                size = 4;
                left = size;
            }

            SW_HEADER => {
                if p[0] != 1 {
                    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: not a client hello");
                    return NGX_DECLINED;
                }

                state = SW_VERSION;
                dst = Dst::Version(0);
                size = 2;
                left = ((p[1] as usize) << 16) + ((p[2] as usize) << 8) + p[3] as usize;
            }

            SW_VERSION => {
                state = SW_RANDOM;
                dst = Dst::None;
                size = 32;
            }

            SW_RANDOM => {
                state = SW_SID_LEN;
                dst = Dst::Buf(0);
                size = 1;
            }

            SW_SID_LEN => {
                state = SW_SID;
                dst = Dst::None;
                size = p[0] as usize;
            }

            SW_SID => {
                state = SW_CS_LEN;
                dst = Dst::Buf(0);
                size = 2;
            }

            SW_CS_LEN => {
                state = SW_CS;
                dst = Dst::None;
                size = ((p[0] as usize) << 8) + p[1] as usize;
            }

            SW_CS => {
                state = SW_CM_LEN;
                dst = Dst::Buf(0);
                size = 1;
            }

            SW_CM_LEN => {
                state = SW_CM;
                dst = Dst::None;
                size = p[0] as usize;
            }

            SW_CM => {
                if left == 0 {
                    /* no extensions */
                    return NGX_OK;
                }

                state = SW_EXT;
                dst = Dst::Buf(0);
                size = 2;
            }

            SW_EXT => {
                if left == 0 {
                    return NGX_OK;
                }

                state = SW_EXT_HEADER;
                dst = Dst::Buf(0);
                size = 4;
            }

            SW_EXT_HEADER => {
                if p[0] == 0 && p[1] == 0 && ctx.host.borrow().is_none() {
                    /* SNI extension */
                    state = SW_SNI_LEN;
                    dst = Dst::Buf(0);
                    size = 2;
                } else if p[0] == 0 && p[1] == 16 && ctx.alpn.borrow().is_none() {
                    /* ALPN extension */
                    state = SW_ALPN_LEN;
                    dst = Dst::Buf(0);
                    size = 2;
                } else if p[0] == 0 && p[1] == 43 {
                    /* supported_versions extension */
                    state = SW_SUPVER_LEN;
                    dst = Dst::Buf(0);
                    size = 1;
                } else {
                    state = SW_EXT;
                    dst = Dst::None;
                    size = ((p[2] as usize) << 8) + p[3] as usize;
                }
            }

            SW_SNI_LEN => {
                ext = ((p[0] as usize) << 8) + p[1] as usize;
                state = SW_SNI_HOST_HEAD;
                dst = Dst::Buf(0);
                size = 3;
            }

            SW_SNI_HOST_HEAD => {
                if p[0] != 0 {
                    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: SNI hostname type is not DNS");
                    return NGX_DECLINED;
                }

                size = ((p[1] as usize) << 8) + p[2] as usize;

                if ext < 3 + size {
                    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: SNI format error");
                    return NGX_DECLINED;
                }
                ext -= 3 + size;

                *ctx.host.borrow_mut() = Some(vec![0u8; size]);

                state = SW_SNI_HOST;
                dst = Dst::Host(0);
            }

            SW_SNI_HOST => {
                ctx.host_len.set(((p[1] as usize) << 8) + p[2] as usize);

                state = SW_EXT;
                dst = Dst::None;
                size = ext;
            }

            SW_ALPN_LEN => {
                ext = ((p[0] as usize) << 8) + p[1] as usize;

                *ctx.alpn.borrow_mut() = Some(vec![0u8; ext]);

                state = SW_ALPN_PROTO_LEN;
                dst = Dst::Buf(0);
                size = 1;
            }

            SW_ALPN_PROTO_LEN => {
                size = p[0] as usize;

                if size == 0 {
                    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: ALPN empty protocol");
                    return NGX_DECLINED;
                }

                if ext < 1 + size {
                    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: ALPN format error");
                    return NGX_DECLINED;
                }
                ext -= 1 + size;

                state = SW_ALPN_PROTO_DATA;
                dst = Dst::Alpn(ctx.alpn_len.get());
            }

            SW_ALPN_PROTO_DATA => {
                ctx.alpn_len.set(ctx.alpn_len.get() + p[0] as usize);

                ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: ALPN protocols \"{}\"", B(&ctx.alpn()));

                if ext != 0 {
                    let l = ctx.alpn_len.get();
                    ctx.alpn.borrow_mut().as_mut().unwrap()[l] = b',';
                    ctx.alpn_len.set(l + 1);

                    state = SW_ALPN_PROTO_LEN;
                    dst = Dst::Buf(0);
                    size = 1;
                } else {
                    state = SW_EXT;
                    dst = Dst::None;
                    size = 0;
                }
            }

            _ => {
                /* SW_SUPVER_LEN */

                ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: supported_versions");

                /* set TLSv1.3 */
                ctx.version.set([3, 4]);

                state = SW_EXT;
                dst = Dst::None;
                size = p[0] as usize;
            }
        }

        if left < size {
            ngx_log_debug!(NGX_LOG_DEBUG_STREAM, ctx.log, "ssl preread: failed to parse handshake");
            return NGX_DECLINED;
        }
    }

    ctx.state.set(state);
    ctx.size.set(size);
    ctx.left.set(left);
    ctx.ext.set(ext);
    ctx.dst.set(dst);

    NGX_AGAIN
}

/// ngx_stream_ssl_preread_servername: the server of the session by the
/// server name
fn ngx_stream_ssl_preread_servername(s: &S, servername: &[u8]) -> i64 {
    let c = &s.connection;

    ngx_log_debug!(NGX_LOG_DEBUG_STREAM, c.log, "SSL preread server name: \"{}\"", B(servername));

    if servername.is_empty() {
        return NGX_OK;
    }

    let host = match validate_host(servername) {
        Ok(h) => h,
        Err(rc) if rc == NGX_DECLINED => return NGX_OK,
        Err(_) => return NGX_ERROR,
    };

    let cscf = match find_virtual_server(s, &host) {
        Ok(cscf) => cscf,
        Err(rc) if rc == NGX_DECLINED => return NGX_OK,
        Err(_) => return NGX_ERROR,
    };

    let (srv, error_log) = {
        let cscf = cscf.borrow();
        (cscf.ctx.srv.clone().expect("srv conf"), cscf.error_log.clone())
    };

    *s.srv_conf.borrow_mut() = srv;

    if let Some(chain) = error_log {
        c.log.set_chain(chain);
    }

    NGX_OK
}

fn set_value(v: &mut VariableValue, data: Vec<u8>) {
    v.data = data;
    v.valid = true;
    v.no_cacheable = false;
    v.not_found = false;
}

/// ngx_stream_ssl_preread_protocol_variable: SSL_get_version() format
fn ngx_stream_ssl_preread_protocol_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let ctx = match s.get_ctx::<SslPrereadCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    let version: &[u8] = match ctx.version.get() {
        [0, 2] => b"SSLv2",
        [3, 0] => b"SSLv3",
        [3, 1] => b"TLSv1",
        [3, 2] => b"TLSv1.1",
        [3, 3] => b"TLSv1.2",
        [3, 4] => b"TLSv1.3",
        _ => b"",
    };

    set_value(v, version.to_vec());

    NGX_OK
}

/// ngx_stream_ssl_preread_server_name_variable
fn ngx_stream_ssl_preread_server_name_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let ctx = match s.get_ctx::<SslPrereadCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    set_value(v, ctx.host());

    NGX_OK
}

/// ngx_stream_ssl_preread_alpn_protocols_variable
fn ngx_stream_ssl_preread_alpn_protocols_variable(s: &Session, v: &mut VariableValue, _data: usize) -> i64 {
    let ctx = match s.get_ctx::<SslPrereadCtx>(ctx_index()) {
        Some(ctx) => ctx,
        None => {
            v.not_found = true;
            return NGX_OK;
        }
    };

    set_value(v, ctx.alpn());

    NGX_OK
}

static NGX_STREAM_SSL_PREREAD_VARS: &[VarDef] = &[
    VarDef { name: "ssl_preread_protocol", set: None, get: Some(ngx_stream_ssl_preread_protocol_variable), data: 0, flags: 0 },
    VarDef { name: "ssl_preread_server_name", set: None, get: Some(ngx_stream_ssl_preread_server_name_variable), data: 0, flags: 0 },
    VarDef { name: "ssl_preread_alpn_protocols", set: None, get: Some(ngx_stream_ssl_preread_alpn_protocols_variable), data: 0, flags: 0 },
];

/// ngx_stream_ssl_preread_add_variables
fn ngx_stream_ssl_preread_add_variables(cf: &mut Conf) -> ConfResult {
    add_variables(cf, NGX_STREAM_SSL_PREREAD_VARS)
}

/// ngx_stream_ssl_preread_create_srv_conf
fn ngx_stream_ssl_preread_create_srv_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(SslPrereadSrvConf::default())
}

/// ngx_stream_ssl_preread_merge_srv_conf
fn ngx_stream_ssl_preread_merge_srv_conf(_cf: &mut Conf, parent: &Rc<dyn Any>, child: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<SslPrereadSrvConf>(parent).borrow().enabled;
    let conf = conf_cell::<SslPrereadSrvConf>(child);

    conf.borrow_mut().enabled.merge(&prev, false);

    Ok(())
}

/// ngx_stream_ssl_preread_init
fn ngx_stream_ssl_preread_init(cf: &mut Conf) -> ConfResult {
    add_phase_handler(cf, NGX_STREAM_PREREAD_PHASE, phase_fn(ngx_stream_ssl_preread_handler));

    Ok(())
}

pub fn ssl_preread_module() -> ModuleDef {
    stream_module_def(
        "ngx_stream_ssl_preread_module",
        StreamModuleDef {
            preconfiguration: Some(ngx_stream_ssl_preread_add_variables),
            postconfiguration: Some(ngx_stream_ssl_preread_init),
            create_main_conf: None,
            init_main_conf: None,
            create_srv_conf: Some(ngx_stream_ssl_preread_create_srv_conf),
            merge_srv_conf: Some(ngx_stream_ssl_preread_merge_srv_conf),
        },
        vec![cmd!("ssl_preread", NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_FLAG, ConfLevel::Srv, SslPrereadSrvConf, enabled, set_flag)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SslPrereadCtx {
        SslPrereadCtx::new(Log::stderr(NGX_LOG_EMERG), 0)
    }

    /// A ClientHello handshake message with the given extensions.
    fn client_hello(exts: &[u8]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[1, 0]); // compression
        body.extend_from_slice(&[(exts.len() >> 8) as u8, exts.len() as u8]);
        body.extend_from_slice(exts);

        let mut m = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        m.extend_from_slice(&body);
        m
    }

    #[test]
    fn sni_and_alpn() {
        let mut exts = vec![0, 0, 0, 14, 0, 12, 0, 0, 9];
        exts.extend_from_slice(b"localhost");
        exts.extend_from_slice(&[0, 16, 0, 9, 0, 7, 2]);
        exts.extend_from_slice(b"h2");
        exts.push(3);
        exts.extend_from_slice(b"foo");

        let c = ctx();
        assert_eq!(ngx_stream_ssl_preread_parse_record(&c, &client_hello(&exts)), NGX_OK);
        assert_eq!(c.host(), b"localhost");
        assert_eq!(c.alpn(), b"h2,foo");
        assert_eq!(c.version.get(), [3, 3]);
    }

    #[test]
    fn split_record() {
        let mut exts = vec![0, 0, 0, 8, 0, 6, 0, 0, 3];
        exts.extend_from_slice(b"foo");
        exts.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);

        let msg = client_hello(&exts);
        let c = ctx();
        assert_eq!(ngx_stream_ssl_preread_parse_record(&c, &msg[..20]), NGX_AGAIN);
        assert_eq!(ngx_stream_ssl_preread_parse_record(&c, &msg[20..]), NGX_OK);
        assert_eq!(c.host(), b"foo");
        assert_eq!(c.version.get(), [3, 4]);
    }

    #[test]
    fn not_client_hello() {
        let c = ctx();
        assert_eq!(ngx_stream_ssl_preread_parse_record(&c, &[2, 0, 0, 0]), NGX_DECLINED);
    }
}
