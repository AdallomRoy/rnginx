//! Raw OpenSSL (3.x) declarations used by the port of ngx_event_openssl.c.
//!
//! Everything nginx uses is declared here with the C signatures, so the
//! port does not depend on which items openssl-sys enables for the build;
//! the header macros nginx relies on (SSL_CTX_set_mode(), sk_X509_num(),
//! BIO_pending(), ...) are provided as functions with the macro names.

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use std::os::raw::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

pub use openssl_sys::{
    ASN1_INTEGER, ASN1_TIME, BIO, BIO_METHOD, DH, ENGINE, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MD, EVP_MD_CTX, EVP_PKEY, HMAC_CTX, OPENSSL_STACK, SSL, SSL_CIPHER, SSL_CTX, SSL_METHOD, SSL_SESSION, X509, X509_CRL, X509_NAME, X509_STORE,
    X509_STORE_CTX,
};

pub type SSL_CONF_CTX = c_void;
pub type OPENSSL_INIT_SETTINGS = c_void;

pub type pem_password_cb = unsafe extern "C" fn(buf: *mut c_char, size: c_int, rwflag: c_int, userdata: *mut c_void) -> c_int;
pub type SSL_verify_cb = unsafe extern "C" fn(ok: c_int, ctx: *mut X509_STORE_CTX) -> c_int;
pub type SSL_info_cb = unsafe extern "C" fn(ssl: *const SSL, where_: c_int, ret: c_int);
pub type SSL_servername_cb = unsafe extern "C" fn(ssl: *mut SSL, ad: *mut c_int, arg: *mut c_void) -> c_int;
pub type SSL_client_hello_cb = unsafe extern "C" fn(ssl: *mut SSL, al: *mut c_int, arg: *mut c_void) -> c_int;
pub type SSL_alpn_select_cb = unsafe extern "C" fn(ssl: *mut SSL, out: *mut *const u8, outlen: *mut u8, inp: *const u8, inlen: c_uint, arg: *mut c_void) -> c_int;
pub type SSL_cert_cb = unsafe extern "C" fn(ssl: *mut SSL, arg: *mut c_void) -> c_int;
pub type SSL_new_session_cb = unsafe extern "C" fn(ssl: *mut SSL, sess: *mut SSL_SESSION) -> c_int;
pub type SSL_remove_session_cb = unsafe extern "C" fn(ctx: *mut SSL_CTX, sess: *mut SSL_SESSION);
pub type SSL_get_session_cb = unsafe extern "C" fn(ssl: *mut SSL, data: *const u8, len: c_int, copy: *mut c_int) -> *mut SSL_SESSION;
pub type SSL_ticket_key_cb = unsafe extern "C" fn(ssl: *mut SSL, name: *mut u8, iv: *mut u8, ectx: *mut EVP_CIPHER_CTX, hctx: *mut HMAC_CTX, enc: c_int) -> c_int;
pub type SSL_status_cb = unsafe extern "C" fn(ssl: *mut SSL, arg: *mut c_void) -> c_int;
pub type sk_compfunc = unsafe extern "C" fn(a: *const c_void, b: *const c_void) -> c_int;
pub type sk_freefunc = unsafe extern "C" fn(a: *mut c_void);
pub type CRYPTO_EX_free = unsafe extern "C" fn(parent: *mut c_void, ptr: *mut c_void, ad: *mut c_void, idx: c_int, argl: c_long, argp: *mut c_void);

extern "C" {
    // library init
    pub fn OPENSSL_init_ssl(opts: u64, settings: *const OPENSSL_INIT_SETTINGS) -> c_int;
    pub fn CRYPTO_get_ex_new_index(class_index: c_int, argl: c_long, argp: *mut c_void, new_func: *mut c_void, dup_func: *mut c_void, free_func: Option<CRYPTO_EX_free>) -> c_int;
    pub fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int);
    pub fn OpenSSL_version(t: c_int) -> *const c_char;

    // SSL_CTX
    pub fn TLS_method() -> *const SSL_METHOD;
    pub fn SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX;
    pub fn SSL_CTX_free(ctx: *mut SSL_CTX);
    pub fn SSL_CTX_set_ex_data(ctx: *mut SSL_CTX, idx: c_int, data: *mut c_void) -> c_int;
    pub fn SSL_CTX_get_ex_data(ctx: *const SSL_CTX, idx: c_int) -> *mut c_void;
    pub fn SSL_CTX_set_options(ctx: *mut SSL_CTX, op: u64) -> u64;
    pub fn SSL_CTX_clear_options(ctx: *mut SSL_CTX, op: u64) -> u64;
    pub fn SSL_CTX_get_options(ctx: *const SSL_CTX) -> u64;
    pub fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_CTX_callback_ctrl(ctx: *mut SSL_CTX, cmd: c_int, fp: Option<unsafe extern "C" fn()>) -> c_long;
    pub fn SSL_CTX_set_info_callback(ctx: *mut SSL_CTX, cb: Option<SSL_info_cb>);
    pub fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, x: *mut X509) -> c_int;
    pub fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, pkey: *mut EVP_PKEY) -> c_int;
    pub fn SSL_CTX_set_cipher_list(ctx: *mut SSL_CTX, s: *const c_char) -> c_int;
    pub fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int, cb: Option<SSL_verify_cb>);
    pub fn SSL_CTX_set_verify_depth(ctx: *mut SSL_CTX, depth: c_int);
    pub fn SSL_CTX_get_verify_mode(ctx: *const SSL_CTX) -> c_int;
    pub fn SSL_CTX_get_verify_depth(ctx: *const SSL_CTX) -> c_int;
    pub fn SSL_CTX_get_verify_callback(ctx: *const SSL_CTX) -> Option<SSL_verify_cb>;
    pub fn SSL_CTX_get_cert_store(ctx: *const SSL_CTX) -> *mut X509_STORE;
    pub fn SSL_CTX_set_client_CA_list(ctx: *mut SSL_CTX, list: *mut OPENSSL_STACK);
    pub fn SSL_CTX_get_client_CA_list(ctx: *const SSL_CTX) -> *mut OPENSSL_STACK;
    pub fn SSL_CTX_set_timeout(ctx: *mut SSL_CTX, t: c_long) -> c_long;
    pub fn SSL_CTX_get_timeout(ctx: *const SSL_CTX) -> c_long;
    pub fn SSL_CTX_set_session_id_context(ctx: *mut SSL_CTX, sid_ctx: *const u8, len: c_uint) -> c_int;
    pub fn SSL_CTX_sess_set_new_cb(ctx: *mut SSL_CTX, cb: Option<SSL_new_session_cb>);
    pub fn SSL_CTX_sess_set_remove_cb(ctx: *mut SSL_CTX, cb: Option<SSL_remove_session_cb>);
    pub fn SSL_CTX_sess_set_get_cb(ctx: *mut SSL_CTX, cb: Option<SSL_get_session_cb>);
    pub fn SSL_CTX_remove_session(ctx: *mut SSL_CTX, sess: *mut SSL_SESSION) -> c_int;
    pub fn SSL_CTX_set_alpn_select_cb(ctx: *mut SSL_CTX, cb: Option<SSL_alpn_select_cb>, arg: *mut c_void);
    pub fn SSL_CTX_set_cert_cb(ctx: *mut SSL_CTX, cb: Option<SSL_cert_cb>, arg: *mut c_void);
    pub fn SSL_CTX_set_client_hello_cb(ctx: *mut SSL_CTX, cb: Option<SSL_client_hello_cb>, arg: *mut c_void);
    pub fn SSL_CTX_get_max_early_data(ctx: *const SSL_CTX) -> u32;
    pub fn SSL_CTX_set_max_early_data(ctx: *mut SSL_CTX, max: u32) -> c_int;

    // SSL
    pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    pub fn SSL_free(ssl: *mut SSL);
    pub fn SSL_set_fd(ssl: *mut SSL, fd: c_int) -> c_int;
    pub fn SSL_set_connect_state(ssl: *mut SSL);
    pub fn SSL_set_accept_state(ssl: *mut SSL);
    pub fn SSL_set_options(ssl: *mut SSL, op: u64) -> u64;
    pub fn SSL_clear_options(ssl: *mut SSL, op: u64) -> u64;
    pub fn SSL_get_options(ssl: *const SSL) -> u64;
    pub fn SSL_ctrl(ssl: *mut SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_set_ex_data(ssl: *mut SSL, idx: c_int, data: *mut c_void) -> c_int;
    pub fn SSL_get_ex_data(ssl: *const SSL, idx: c_int) -> *mut c_void;
    pub fn SSL_do_handshake(ssl: *mut SSL) -> c_int;
    pub fn SSL_get_error(ssl: *const SSL, ret: c_int) -> c_int;
    pub fn SSL_want(ssl: *const SSL) -> c_int;
    pub fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    pub fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
    pub fn SSL_read_early_data(ssl: *mut SSL, buf: *mut c_void, num: usize, readbytes: *mut usize) -> c_int;
    pub fn SSL_shutdown(ssl: *mut SSL) -> c_int;
    pub fn SSL_get_shutdown(ssl: *const SSL) -> c_int;
    pub fn SSL_set_shutdown(ssl: *mut SSL, mode: c_int);
    pub fn SSL_set_quiet_shutdown(ssl: *mut SSL, mode: c_int);
    pub fn SSL_in_init(ssl: *const SSL) -> c_int;
    pub fn SSL_is_init_finished(ssl: *const SSL) -> c_int;
    pub fn SSL_is_server(ssl: *const SSL) -> c_int;
    pub fn SSL_version(ssl: *const SSL) -> c_int;
    pub fn SSL_get_version(ssl: *const SSL) -> *const c_char;
    pub fn SSL_get_current_cipher(ssl: *const SSL) -> *const SSL_CIPHER;
    pub fn SSL_CIPHER_get_name(c: *const SSL_CIPHER) -> *const c_char;
    pub fn SSL_CIPHER_description(c: *const SSL_CIPHER, buf: *mut c_char, size: c_int) -> *mut c_char;
    pub fn SSL_CIPHER_find(ssl: *mut SSL, ptr: *const u8) -> *const SSL_CIPHER;
    pub fn SSL_session_reused(ssl: *const SSL) -> c_int;
    pub fn SSL_get_session(ssl: *const SSL) -> *mut SSL_SESSION;
    pub fn SSL_get1_session(ssl: *mut SSL) -> *mut SSL_SESSION;
    pub fn SSL_set_session(ssl: *mut SSL, sess: *mut SSL_SESSION) -> c_int;
    pub fn SSL_get_servername(ssl: *const SSL, ty: c_int) -> *const c_char;
    pub fn SSL_set_SSL_CTX(ssl: *mut SSL, ctx: *mut SSL_CTX) -> *mut SSL_CTX;
    pub fn SSL_get_SSL_CTX(ssl: *const SSL) -> *mut SSL_CTX;
    pub fn SSL_set_verify(ssl: *mut SSL, mode: c_int, cb: Option<SSL_verify_cb>);
    pub fn SSL_set_verify_depth(ssl: *mut SSL, depth: c_int);
    pub fn SSL_get_verify_result(ssl: *const SSL) -> c_long;
    pub fn SSL_get1_peer_certificate(ssl: *const SSL) -> *mut X509;
    pub fn SSL_get_certificate(ssl: *const SSL) -> *mut X509;
    pub fn SSL_select_next_proto(out: *mut *mut u8, outlen: *mut u8, server: *const u8, server_len: c_uint, client: *const u8, client_len: c_uint) -> c_int;
    pub fn SSL_get0_alpn_selected(ssl: *const SSL, data: *mut *const u8, len: *mut c_uint);
    pub fn SSL_set_alpn_protos(ssl: *mut SSL, protos: *const u8, len: c_uint) -> c_int;
    pub fn SSL_get_rbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_get_wbio(ssl: *const SSL) -> *mut BIO;
    pub fn SSL_get_ex_data_X509_STORE_CTX_idx() -> c_int;
    pub fn SSL_group_to_name(ssl: *mut SSL, id: c_int) -> *const c_char;
    pub fn SSL_get_sigalgs(ssl: *mut SSL, idx: c_int, psign: *mut c_int, phash: *mut c_int, psignhash: *mut c_int, rsig: *mut u8, rhash: *mut u8) -> c_int;
    pub fn SSL_client_hello_get0_ext(ssl: *mut SSL, ty: c_uint, out: *mut *const u8, outlen: *mut usize) -> c_int;
    pub fn SSL_use_certificate(ssl: *mut SSL, x: *mut X509) -> c_int;
    pub fn SSL_use_PrivateKey(ssl: *mut SSL, pkey: *mut EVP_PKEY) -> c_int;
    pub fn SSL_get0_param(ssl: *mut SSL) -> *mut c_void;

    // SSL_SESSION
    pub fn i2d_SSL_SESSION(sess: *const SSL_SESSION, pp: *mut *mut u8) -> c_int;
    pub fn d2i_SSL_SESSION(a: *mut *mut SSL_SESSION, pp: *mut *const u8, len: c_long) -> *mut SSL_SESSION;
    pub fn SSL_SESSION_get_id(sess: *const SSL_SESSION, len: *mut c_uint) -> *const u8;
    pub fn SSL_SESSION_free(sess: *mut SSL_SESSION);
    pub fn SSL_SESSION_up_ref(sess: *mut SSL_SESSION) -> c_int;
    pub fn SSL_SESSION_get_time(sess: *const SSL_SESSION) -> c_long;
    pub fn SSL_SESSION_set_time(sess: *mut SSL_SESSION, t: c_long) -> c_long;
    pub fn SSL_SESSION_get_timeout(sess: *const SSL_SESSION) -> c_long;
    pub fn SSL_SESSION_set_timeout(sess: *mut SSL_SESSION, t: c_long) -> c_long;
    pub fn SSL_SESSION_set1_id_context(sess: *mut SSL_SESSION, sid_ctx: *const u8, len: c_uint) -> c_int;

    // X509
    pub fn X509_free(x: *mut X509);
    pub fn X509_up_ref(x: *mut X509) -> c_int;
    pub fn X509_set_ex_data(x: *mut X509, idx: c_int, arg: *mut c_void) -> c_int;
    pub fn X509_get_ex_data(x: *const X509, idx: c_int) -> *mut c_void;
    pub fn X509_STORE_add_cert(store: *mut X509_STORE, x: *mut X509) -> c_int;
    pub fn X509_STORE_add_crl(store: *mut X509_STORE, x: *mut X509_CRL) -> c_int;
    pub fn X509_STORE_set_flags(store: *mut X509_STORE, flags: c_ulong) -> c_int;
    pub fn X509_get_subject_name(x: *const X509) -> *mut X509_NAME;
    pub fn X509_get_issuer_name(x: *const X509) -> *mut X509_NAME;
    pub fn X509_NAME_dup(n: *const X509_NAME) -> *mut X509_NAME;
    pub fn X509_NAME_free(n: *mut X509_NAME);
    pub fn X509_NAME_cmp(a: *const X509_NAME, b: *const X509_NAME) -> c_int;
    pub fn X509_NAME_oneline(n: *const X509_NAME, buf: *mut c_char, size: c_int) -> *mut c_char;
    pub fn X509_NAME_print_ex(out: *mut BIO, n: *const X509_NAME, indent: c_int, flags: c_ulong) -> c_int;
    pub fn X509_digest(x: *const X509, md: *const EVP_MD, out: *mut u8, len: *mut c_uint) -> c_int;
    pub fn X509_NAME_digest(n: *const X509_NAME, md: *const EVP_MD, out: *mut u8, len: *mut c_uint) -> c_int;
    pub fn X509_get_serialNumber(x: *mut X509) -> *mut ASN1_INTEGER;
    pub fn i2a_ASN1_INTEGER(bp: *mut BIO, a: *const ASN1_INTEGER) -> c_int;
    pub fn X509_get0_notBefore(x: *const X509) -> *const ASN1_TIME;
    pub fn X509_get0_notAfter(x: *const X509) -> *const ASN1_TIME;
    pub fn ASN1_TIME_print(bp: *mut BIO, t: *const ASN1_TIME) -> c_int;
    pub fn X509_check_host(x: *mut X509, chk: *const c_char, chklen: usize, flags: c_uint, peername: *mut *mut c_char) -> c_int;
    pub fn X509_verify_cert_error_string(n: c_long) -> *const c_char;
    pub fn X509_STORE_CTX_get_ex_data(ctx: *const X509_STORE_CTX, idx: c_int) -> *mut c_void;
    pub fn X509_STORE_CTX_get_current_cert(ctx: *const X509_STORE_CTX) -> *mut X509;
    pub fn X509_STORE_CTX_get_error(ctx: *const X509_STORE_CTX) -> c_int;
    pub fn X509_STORE_CTX_get_error_depth(ctx: *const X509_STORE_CTX) -> c_int;
    pub fn X509_CRL_free(x: *mut X509_CRL);
    pub fn X509_CRL_up_ref(x: *mut X509_CRL) -> c_int;

    // PEM
    pub fn PEM_read_bio_X509_AUX(bp: *mut BIO, x: *mut *mut X509, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut X509;
    pub fn PEM_read_bio_X509(bp: *mut BIO, x: *mut *mut X509, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut X509;
    pub fn PEM_read_bio_PrivateKey(bp: *mut BIO, x: *mut *mut EVP_PKEY, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut EVP_PKEY;
    pub fn PEM_read_bio_X509_CRL(bp: *mut BIO, x: *mut *mut X509_CRL, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut X509_CRL;
    pub fn PEM_read_bio_DHparams(bp: *mut BIO, x: *mut *mut DH, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut DH;
    pub fn PEM_write_bio_X509(bp: *mut BIO, x: *mut X509) -> c_int;
    pub fn DH_free(dh: *mut DH);
    pub fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    pub fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> c_int;

    // BIO
    pub fn BIO_new_file(filename: *const c_char, mode: *const c_char) -> *mut BIO;
    pub fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;
    pub fn BIO_new(ty: *const BIO_METHOD) -> *mut BIO;
    pub fn BIO_s_mem() -> *const BIO_METHOD;
    pub fn BIO_free(b: *mut BIO) -> c_int;
    pub fn BIO_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn BIO_int_ctrl(b: *mut BIO, cmd: c_int, larg: c_long, iarg: c_int) -> c_long;
    pub fn BIO_read(b: *mut BIO, data: *mut c_void, len: c_int) -> c_int;
    pub fn BIO_write(b: *mut BIO, data: *const c_void, len: c_int) -> c_int;
    pub fn BIO_ctrl_pending(b: *mut BIO) -> usize;

    // stacks
    pub fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
    pub fn OPENSSL_sk_new(cmp: Option<sk_compfunc>) -> *mut OPENSSL_STACK;
    pub fn OPENSSL_sk_num(st: *const OPENSSL_STACK) -> c_int;
    pub fn OPENSSL_sk_value(st: *const OPENSSL_STACK, i: c_int) -> *mut c_void;
    pub fn OPENSSL_sk_push(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int;
    pub fn OPENSSL_sk_shift(st: *mut OPENSSL_STACK) -> *mut c_void;
    pub fn OPENSSL_sk_dup(st: *const OPENSSL_STACK) -> *mut OPENSSL_STACK;
    pub fn OPENSSL_sk_free(st: *mut OPENSSL_STACK);
    pub fn OPENSSL_sk_pop_free(st: *mut OPENSSL_STACK, func: Option<sk_freefunc>);
    pub fn OPENSSL_sk_find(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int;

    // errors
    pub fn ERR_peek_error() -> c_ulong;
    pub fn ERR_peek_last_error() -> c_ulong;
    pub fn ERR_get_error() -> c_ulong;
    pub fn ERR_clear_error();
    pub fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
    pub fn ERR_peek_error_data(data: *mut *const c_char, flags: *mut c_int) -> c_ulong;

    // digests, ciphers, random
    pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    pub fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, ty: *const EVP_MD, e: *mut ENGINE) -> c_int;
    pub fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, d: *const c_void, cnt: usize) -> c_int;
    pub fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, md: *mut u8, s: *mut c_uint) -> c_int;
    pub fn EVP_sha1() -> *const EVP_MD;
    pub fn EVP_sha256() -> *const EVP_MD;
    pub fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
    pub fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    pub fn EVP_CIPHER_get_iv_length(cipher: *const EVP_CIPHER) -> c_int;
    pub fn EVP_EncryptInit_ex(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, e: *mut ENGINE, key: *const u8, iv: *const u8) -> c_int;
    pub fn EVP_DecryptInit_ex(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, e: *mut ENGINE, key: *const u8, iv: *const u8) -> c_int;
    pub fn HMAC_Init_ex(ctx: *mut HMAC_CTX, key: *const c_void, len: c_int, md: *const EVP_MD, e: *mut ENGINE) -> c_int;

    // SSL_CONF
    pub fn SSL_CONF_CTX_new() -> *mut SSL_CONF_CTX;
    pub fn SSL_CONF_CTX_free(cctx: *mut SSL_CONF_CTX);
    pub fn SSL_CONF_CTX_set_flags(cctx: *mut SSL_CONF_CTX, flags: c_uint) -> c_uint;
    pub fn SSL_CONF_CTX_set_ssl_ctx(cctx: *mut SSL_CONF_CTX, ctx: *mut SSL_CTX);
    pub fn SSL_CONF_cmd(cctx: *mut SSL_CONF_CTX, cmd: *const c_char, value: *const c_char) -> c_int;
    pub fn SSL_CONF_cmd_value_type(cctx: *mut SSL_CONF_CTX, cmd: *const c_char) -> c_int;
    pub fn SSL_CONF_CTX_finish(cctx: *mut SSL_CONF_CTX) -> c_int;

    // objects
    pub fn OBJ_nid2sn(n: c_int) -> *const c_char;
}

pub type OCSP_REQUEST = c_void;
pub type OCSP_RESPONSE = c_void;
pub type OCSP_BASICRESP = c_void;
pub type OCSP_CERTID = c_void;
pub type ASN1_GENERALIZEDTIME = c_void;

extern "C" {
    // OCSP (ngx_event_openssl_stapling.c)
    pub fn OCSP_REQUEST_new() -> *mut OCSP_REQUEST;
    pub fn OCSP_REQUEST_free(r: *mut OCSP_REQUEST);
    pub fn OCSP_cert_to_id(dgst: *const EVP_MD, subject: *const X509, issuer: *const X509) -> *mut OCSP_CERTID;
    pub fn OCSP_CERTID_free(id: *mut OCSP_CERTID);
    pub fn OCSP_request_add0_id(req: *mut OCSP_REQUEST, cid: *mut OCSP_CERTID) -> *mut c_void;
    pub fn i2d_OCSP_REQUEST(r: *const OCSP_REQUEST, out: *mut *mut u8) -> c_int;
    pub fn OCSP_RESPONSE_new() -> *mut OCSP_RESPONSE;
    pub fn d2i_OCSP_RESPONSE(a: *mut *mut OCSP_RESPONSE, pp: *mut *const u8, len: c_long) -> *mut OCSP_RESPONSE;
    pub fn i2d_OCSP_RESPONSE(r: *const OCSP_RESPONSE, out: *mut *mut u8) -> c_int;
    pub fn OCSP_RESPONSE_free(r: *mut OCSP_RESPONSE);
    pub fn OCSP_response_status(r: *mut OCSP_RESPONSE) -> c_int;
    pub fn OCSP_response_status_str(s: c_long) -> *const c_char;
    pub fn OCSP_response_get1_basic(r: *mut OCSP_RESPONSE) -> *mut OCSP_BASICRESP;
    pub fn OCSP_BASICRESP_free(b: *mut OCSP_BASICRESP);
    pub fn OCSP_basic_verify(bs: *mut OCSP_BASICRESP, certs: *mut OPENSSL_STACK, st: *mut X509_STORE, flags: c_ulong) -> c_int;
    pub fn OCSP_resp_find_status(bs: *mut OCSP_BASICRESP, id: *mut OCSP_CERTID, status: *mut c_int, reason: *mut c_int, revtime: *mut *mut ASN1_GENERALIZEDTIME, thisupd: *mut *mut ASN1_GENERALIZEDTIME, nextupd: *mut *mut ASN1_GENERALIZEDTIME) -> c_int;
    pub fn OCSP_check_validity(thisupd: *mut ASN1_GENERALIZEDTIME, nextupd: *mut ASN1_GENERALIZEDTIME, sec: c_long, maxsec: c_long) -> c_int;
    pub fn OCSP_cert_status_str(s: c_long) -> *const c_char;
    pub fn ASN1_GENERALIZEDTIME_print(bp: *mut BIO, a: *const ASN1_GENERALIZEDTIME) -> c_int;
    pub fn X509_get1_ocsp(x: *mut X509) -> *mut OPENSSL_STACK;
    pub fn X509_email_free(sk: *mut OPENSSL_STACK);
    pub fn X509_check_issued(issuer: *mut X509, subject: *mut X509) -> c_int;
    pub fn X509_STORE_CTX_new() -> *mut X509_STORE_CTX;
    pub fn X509_STORE_CTX_init(ctx: *mut X509_STORE_CTX, store: *mut X509_STORE, x509: *mut X509, chain: *mut OPENSSL_STACK) -> c_int;
    pub fn X509_STORE_CTX_free(ctx: *mut X509_STORE_CTX);
    pub fn X509_STORE_CTX_get1_issuer(issuer: *mut *mut X509, ctx: *mut X509_STORE_CTX, x: *mut X509) -> c_int;
    pub fn X509_STORE_CTX_get1_chain(ctx: *mut X509_STORE_CTX) -> *mut OPENSSL_STACK;
    pub fn X509_verify_cert(ctx: *mut X509_STORE_CTX) -> c_int;
    pub fn SSL_get0_verified_chain(s: *const SSL) -> *mut OPENSSL_STACK;
    pub fn X509_chain_up_ref(chain: *mut OPENSSL_STACK) -> *mut OPENSSL_STACK;
    pub fn SSL_get_peer_cert_chain(s: *const SSL) -> *mut OPENSSL_STACK;
    pub fn X509_pubkey_digest(data: *const X509, t: *const EVP_MD, md: *mut u8, len: *mut u32) -> c_int;
    pub fn ASN1_STRING_length(x: *const c_void) -> c_int;
    pub fn ASN1_STRING_get0_data(x: *const c_void) -> *const u8;
    pub fn ASN1_d2i_bio(xnew: unsafe extern "C" fn() -> *mut c_void, d2i: *const c_void, inp: *mut BIO, x: *mut *mut c_void) -> *mut c_void;
    pub fn CRYPTO_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void;
}


// --- constants (openssl/ssl.h, tls1.h, x509_vfy.h, ... of OpenSSL 3.0) ---

pub const SSL_OP_IGNORE_UNEXPECTED_EOF: u64 = 1 << 7;
pub const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS: u64 = 1 << 11;
pub const SSL_OP_NO_TICKET: u64 = 1 << 14;
pub const SSL_OP_NO_COMPRESSION: u64 = 1 << 17;
pub const SSL_OP_CIPHER_SERVER_PREFERENCE: u64 = 1 << 22;
pub const SSL_OP_NO_ANTI_REPLAY: u64 = 1 << 24;
pub const SSL_OP_NO_SSLv3: u64 = 1 << 25;
pub const SSL_OP_NO_TLSv1: u64 = 1 << 26;
pub const SSL_OP_NO_TLSv1_2: u64 = 1 << 27;
pub const SSL_OP_NO_TLSv1_1: u64 = 1 << 28;
pub const SSL_OP_NO_TLSv1_3: u64 = 1 << 29;
pub const SSL_OP_NO_RENEGOTIATION: u64 = 1 << 30;
/* the options defined as 0 in OpenSSL 3.0 */
pub const SSL_OP_MICROSOFT_SESS_ID_BUG: u64 = 0;
pub const SSL_OP_NETSCAPE_CHALLENGE_BUG: u64 = 0;
pub const SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG: u64 = 0;
pub const SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER: u64 = 0;
pub const SSL_OP_SSLEAY_080_CLIENT_DH_BUG: u64 = 0;
pub const SSL_OP_TLS_D5_BUG: u64 = 0;
pub const SSL_OP_TLS_BLOCK_PADDING_BUG: u64 = 0;
pub const SSL_OP_SINGLE_ECDH_USE: u64 = 0;
pub const SSL_OP_SINGLE_DH_USE: u64 = 0;
pub const SSL_OP_NO_SSLv2: u64 = 0;

pub const SSL_MODE_NO_AUTO_CHAIN: c_long = 0x00000008;
pub const SSL_MODE_RELEASE_BUFFERS: c_long = 0x00000010;

pub const SSL_CTRL_SET_TMP_DH: c_int = 3;
pub const SSL_CTRL_MODE: c_int = 33;
pub const SSL_CTRL_SET_READ_AHEAD: c_int = 41;
pub const SSL_CTRL_SET_SESS_CACHE_SIZE: c_int = 42;
pub const SSL_CTRL_SET_SESS_CACHE_MODE: c_int = 44;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
pub const SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB: c_int = 63;
pub const SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG: c_int = 64;
pub const SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE: c_int = 65;
pub const SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP: c_int = 70;
pub const SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP: c_int = 71;
pub const SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB: c_int = 72;
pub const SSL_CTRL_GET_EXTRA_CHAIN_CERTS: c_int = 82;
pub const SSL_CTRL_CHAIN: c_int = 88;
pub const SSL_CTRL_GET_GROUPS: c_int = 90;
pub const SSL_CTRL_SET_GROUPS_LIST: c_int = 92;
pub const SSL_CTRL_GET_RAW_CIPHERLIST: c_int = 110;
pub const SSL_CTRL_GET_CHAIN_CERTS: c_int = 115;
pub const SSL_CTRL_SELECT_CURRENT_CERT: c_int = 116;
pub const SSL_CTRL_SET_CURRENT_CERT: c_int = 117;
pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
pub const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
pub const SSL_CTRL_GET_NEGOTIATED_GROUP: c_int = 134;

pub const SSL_SESS_CACHE_OFF: c_long = 0x0000;
pub const SSL_SESS_CACHE_CLIENT: c_long = 0x0001;
pub const SSL_SESS_CACHE_SERVER: c_long = 0x0002;
pub const SSL_SESS_CACHE_NO_AUTO_CLEAR: c_long = 0x0080;
pub const SSL_SESS_CACHE_NO_INTERNAL_LOOKUP: c_long = 0x0100;
pub const SSL_SESS_CACHE_NO_INTERNAL_STORE: c_long = 0x0200;
pub const SSL_SESS_CACHE_NO_INTERNAL: c_long = SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE;

pub const SSL_SENT_SHUTDOWN: c_int = 1;
pub const SSL_RECEIVED_SHUTDOWN: c_int = 2;

pub const SSL_VERIFY_NONE: c_int = 0x00;
pub const SSL_VERIFY_PEER: c_int = 0x01;

pub const SSL_ST_ACCEPT: c_int = 0x2000;
pub const SSL_CB_LOOP: c_int = 0x01;
pub const SSL_CB_ACCEPT_LOOP: c_int = SSL_ST_ACCEPT | SSL_CB_LOOP;
pub const SSL_CB_HANDSHAKE_START: c_int = 0x10;

pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;

// SSL_want()
pub const SSL_WRITING: c_int = 2;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;

pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_WARNING: c_int = 1;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

pub const SSL_AD_DECODE_ERROR: c_int = 50;
pub const SSL_AD_INTERNAL_ERROR: c_int = 80;
pub const SSL_AD_NO_RENEGOTIATION: c_int = 100;
pub const SSL_AD_UNRECOGNIZED_NAME: c_int = 112;
pub const SSL_AD_REASON_OFFSET: c_int = 1000;

pub const SSL_CLIENT_HELLO_ERROR: c_int = 0;
pub const SSL_CLIENT_HELLO_SUCCESS: c_int = 1;

pub const SSL_READ_EARLY_DATA_ERROR: c_int = 0;
pub const SSL_READ_EARLY_DATA_SUCCESS: c_int = 1;
pub const SSL_READ_EARLY_DATA_FINISH: c_int = 2;

pub const TLSEXT_TYPE_server_name: c_uint = 0;
pub const TLSEXT_NAMETYPE_host_name: c_int = 0;
pub const TLSEXT_MAXLEN_host_name: usize = 255;
pub const TLSEXT_nid_unknown: c_int = 0x1000000;
pub const TLSEXT_STATUSTYPE_ocsp: c_long = 1;

pub const OPENSSL_NPN_NEGOTIATED: c_int = 1;

pub const TLS1_2_VERSION: c_int = 0x0303;
pub const TLS1_3_VERSION: c_int = 0x0304;

pub const SSL_CONF_FLAG_FILE: c_uint = 0x2;
pub const SSL_CONF_FLAG_CLIENT: c_uint = 0x4;
pub const SSL_CONF_FLAG_SERVER: c_uint = 0x8;
pub const SSL_CONF_FLAG_SHOW_ERRORS: c_uint = 0x10;
pub const SSL_CONF_FLAG_CERTIFICATE: c_uint = 0x20;
pub const SSL_CONF_TYPE_FILE: c_int = 0x2;
pub const SSL_CONF_TYPE_DIR: c_int = 0x3;

pub const X509_V_OK: c_long = 0;
pub const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_long = 18;
pub const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_long = 19;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_long = 20;
pub const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_long = 21;
pub const X509_V_ERR_CERT_UNTRUSTED: c_long = 27;
pub const X509_V_FLAG_CRL_CHECK: c_ulong = 0x4;
pub const X509_V_FLAG_CRL_CHECK_ALL: c_ulong = 0x8;

pub const XN_FLAG_RFC2253: c_ulong = 0x317 | (1 << 16) | (1 << 20) | (1 << 24);

pub const CRYPTO_EX_INDEX_SSL: c_int = 0;
pub const CRYPTO_EX_INDEX_SSL_CTX: c_int = 1;
pub const CRYPTO_EX_INDEX_X509: c_int = 3;

pub const BIO_CTRL_RESET: c_int = 1;
pub const BIO_CTRL_INFO: c_int = 3;
pub const BIO_CTRL_PENDING: c_int = 10;
pub const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
pub const BIO_C_SET_BUFF_SIZE: c_int = 117;

pub const ERR_TXT_STRING: c_int = 0x02;

pub const ERR_LIB_SYS: c_int = 2;
pub const ERR_LIB_PEM: c_int = 9;
pub const ERR_LIB_X509: c_int = 11;
pub const ERR_LIB_SSL: c_int = 20;

pub const PEM_R_NO_START_LINE: c_int = 108;
pub const X509_R_CERT_ALREADY_IN_HASH_TABLE: c_int = 101;
pub const X509_R_KEY_VALUES_MISMATCH: c_int = 116;
pub const SSL_R_UNINITIALIZED: c_int = 276;

pub const NID_undef: c_int = 0;
pub const EVP_MAX_MD_SIZE: usize = 64;

// --- the header macros ---

const ERR_SYSTEM_FLAG: c_ulong = (c_int::MAX as c_ulong) + 1;

/// ERR_GET_LIB()
pub fn ERR_GET_LIB(e: c_ulong) -> c_int {
    if e & ERR_SYSTEM_FLAG != 0 {
        return ERR_LIB_SYS;
    }
    ((e >> 23) & 0xff) as c_int
}

/// ERR_GET_REASON()
pub fn ERR_GET_REASON(e: c_ulong) -> c_int {
    if e & ERR_SYSTEM_FLAG != 0 {
        return (e & (c_int::MAX as c_ulong)) as c_int;
    }
    (e & 0x7fffff) as c_int
}

pub unsafe fn SSL_CTX_set_mode(ctx: *mut SSL_CTX, op: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, op, std::ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_read_ahead(ctx: *mut SSL_CTX, m: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_READ_AHEAD, m, std::ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_min_proto_version(ctx: *mut SSL_CTX, version: c_int) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version as c_long, std::ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_max_proto_version(ctx: *mut SSL_CTX, version: c_int) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version as c_long, std::ptr::null_mut())
}

pub unsafe fn SSL_CTX_set0_chain(ctx: *mut SSL_CTX, sk: *mut OPENSSL_STACK) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN, 0, sk as *mut c_void)
}

pub unsafe fn SSL_set0_chain(ssl: *mut SSL, sk: *mut OPENSSL_STACK) -> c_long {
    SSL_ctrl(ssl, SSL_CTRL_CHAIN, 0, sk as *mut c_void)
}

pub unsafe fn SSL_CTX_set_tlsext_servername_callback(ctx: *mut SSL_CTX, cb: SSL_servername_cb) -> c_long {
    // the callback type of SSL_CTX_callback_ctrl() is a generic function pointer
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, Some(std::mem::transmute::<SSL_servername_cb, unsafe extern "C" fn()>(cb)))
}

pub unsafe fn SSL_CTX_set_tlsext_ticket_key_cb(ctx: *mut SSL_CTX, cb: SSL_ticket_key_cb) -> c_long {
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB, Some(std::mem::transmute::<SSL_ticket_key_cb, unsafe extern "C" fn()>(cb)))
}

pub unsafe fn SSL_CTX_set_tlsext_status_cb(ctx: *mut SSL_CTX, cb: SSL_status_cb) -> c_long {
    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB, Some(std::mem::transmute::<SSL_status_cb, unsafe extern "C" fn()>(cb)))
}

pub unsafe fn SSL_CTX_set_tlsext_status_arg(ctx: *mut SSL_CTX, arg: *mut c_void) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG, 0, arg)
}

pub unsafe fn SSL_CTX_sess_set_cache_size(ctx: *mut SSL_CTX, t: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, t, std::ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_session_cache_mode(ctx: *mut SSL_CTX, m: c_long) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, m, std::ptr::null_mut())
}

pub unsafe fn SSL_CTX_set_tmp_dh(ctx: *mut SSL_CTX, dh: *mut DH) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_DH, 0, dh as *mut c_void)
}

pub unsafe fn SSL_CTX_set1_curves_list(ctx: *mut SSL_CTX, s: *const c_char) -> c_long {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_GROUPS_LIST, 0, s as *mut c_void)
}

pub unsafe fn SSL_set_tlsext_host_name(ssl: *mut SSL, name: *const c_char) -> c_long {
    SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name as c_long, name as *mut c_void)
}

pub unsafe fn SSL_get_negotiated_group(ssl: *mut SSL) -> c_int {
    SSL_ctrl(ssl, SSL_CTRL_GET_NEGOTIATED_GROUP, 0, std::ptr::null_mut()) as c_int
}

pub unsafe fn SSL_get1_curves(ssl: *mut SSL, curves: *mut c_int) -> c_int {
    SSL_ctrl(ssl, SSL_CTRL_GET_GROUPS, 0, curves as *mut c_void) as c_int
}

pub unsafe fn SSL_get0_raw_cipherlist(ssl: *mut SSL, plst: *mut *const u8) -> c_int {
    SSL_ctrl(ssl, SSL_CTRL_GET_RAW_CIPHERLIST, 0, plst as *mut c_void) as c_int
}

/// SSL_get0_session() is SSL_get_session()
pub unsafe fn SSL_get0_session(ssl: *const SSL) -> *mut SSL_SESSION {
    SSL_get_session(ssl)
}

pub unsafe fn SSL_get_cipher_name(ssl: *const SSL) -> *const c_char {
    SSL_CIPHER_get_name(SSL_get_current_cipher(ssl))
}

pub unsafe fn BIO_reset(b: *mut BIO) -> c_int {
    BIO_ctrl(b, BIO_CTRL_RESET, 0, std::ptr::null_mut()) as c_int
}

pub unsafe fn BIO_pending(b: *mut BIO) -> c_int {
    BIO_ctrl(b, BIO_CTRL_PENDING, 0, std::ptr::null_mut()) as c_int
}

pub unsafe fn BIO_get_mem_data(b: *mut BIO, pp: *mut *mut c_char) -> c_long {
    BIO_ctrl(b, BIO_CTRL_INFO, 0, pp as *mut c_void)
}

pub unsafe fn BIO_set_write_buffer_size(b: *mut BIO, size: c_long) -> c_long {
    BIO_int_ctrl(b, BIO_C_SET_BUFF_SIZE, size, 1)
}

pub unsafe fn BIO_get_ktls_send(b: *mut BIO) -> c_int {
    BIO_ctrl(b, BIO_CTRL_GET_KTLS_SEND, 0, std::ptr::null_mut()) as c_int
}

pub unsafe fn OPENSSL_free(p: *mut c_void) {
    CRYPTO_free(p, std::ptr::null(), 0)
}

unsafe extern "C" fn x509_free_void(p: *mut c_void) {
    X509_free(p as *mut X509)
}

unsafe extern "C" fn x509_crl_free_void(p: *mut c_void) {
    X509_CRL_free(p as *mut X509_CRL)
}

unsafe extern "C" fn x509_name_free_void(p: *mut c_void) {
    X509_NAME_free(p as *mut X509_NAME)
}

/// sk_X509_pop_free(sk, X509_free)
pub unsafe fn sk_X509_pop_free(sk: *mut OPENSSL_STACK) {
    OPENSSL_sk_pop_free(sk, Some(x509_free_void))
}

/// sk_X509_CRL_pop_free(sk, X509_CRL_free)
pub unsafe fn sk_X509_CRL_pop_free(sk: *mut OPENSSL_STACK) {
    OPENSSL_sk_pop_free(sk, Some(x509_crl_free_void))
}

/// sk_X509_NAME_pop_free(sk, X509_NAME_free)
pub unsafe fn sk_X509_NAME_pop_free(sk: *mut OPENSSL_STACK) {
    OPENSSL_sk_pop_free(sk, Some(x509_name_free_void))
}

pub type EVP_PKEY_CTX = c_void;

pub type SSL_CTX_keylog_cb = unsafe extern "C" fn(ssl: *const SSL, line: *const c_char);
pub type SSL_msg_cb = unsafe extern "C" fn(write_p: c_int, version: c_int, content_type: c_int, buf: *const c_void, len: usize, ssl: *mut SSL, arg: *mut c_void);
pub type SSL_custom_ext_add_cb_ex = unsafe extern "C" fn(s: *mut SSL, ext_type: c_uint, context: c_uint, out: *mut *const u8, outlen: *mut usize, x: *mut X509, chainidx: usize, al: *mut c_int, add_arg: *mut c_void) -> c_int;
pub type SSL_custom_ext_free_cb_ex = unsafe extern "C" fn(s: *mut SSL, ext_type: c_uint, context: c_uint, out: *const u8, add_arg: *mut c_void);
pub type SSL_custom_ext_parse_cb_ex = unsafe extern "C" fn(s: *mut SSL, ext_type: c_uint, context: c_uint, inp: *const u8, inlen: usize, x: *mut X509, chainidx: usize, al: *mut c_int, parse_arg: *mut c_void) -> c_int;

extern "C" {
    // QUIC (ngx_event_quic_protection.c, ngx_event_quic_tokens.c,
    // ngx_event_quic_openssl_compat.c)
    pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
    pub fn EVP_CIPHER_CTX_ctrl(ctx: *mut EVP_CIPHER_CTX, ty: c_int, arg: c_int, ptr: *mut c_void) -> c_int;
    pub fn EVP_CIPHER_CTX_is_encrypting(ctx: *const EVP_CIPHER_CTX) -> c_int;
    pub fn EVP_CIPHER_CTX_get0_cipher(ctx: *const EVP_CIPHER_CTX) -> *const EVP_CIPHER;
    pub fn EVP_CIPHER_get_mode(cipher: *const EVP_CIPHER) -> c_int;
    pub fn EVP_CipherInit_ex(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, e: *mut ENGINE, key: *const u8, iv: *const u8, enc: c_int) -> c_int;
    pub fn EVP_CipherUpdate(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, inp: *const u8, inl: c_int) -> c_int;
    pub fn EVP_CipherFinal_ex(ctx: *mut EVP_CIPHER_CTX, outm: *mut u8, outl: *mut c_int) -> c_int;
    pub fn EVP_EncryptUpdate(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, inp: *const u8, inl: c_int) -> c_int;
    pub fn EVP_EncryptFinal_ex(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int;
    pub fn EVP_DecryptUpdate(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, inp: *const u8, inl: c_int) -> c_int;
    pub fn EVP_DecryptFinal_ex(ctx: *mut EVP_CIPHER_CTX, outm: *mut u8, outl: *mut c_int) -> c_int;
    pub fn EVP_aes_128_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ccm() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
    pub fn EVP_chacha20() -> *const EVP_CIPHER;
    pub fn EVP_chacha20_poly1305() -> *const EVP_CIPHER;
    pub fn EVP_sha384() -> *const EVP_MD;
    pub fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    pub fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
    pub fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_derive(ctx: *mut EVP_PKEY_CTX, key: *mut u8, keylen: *mut usize) -> c_int;
    pub fn EVP_PKEY_CTX_set_hkdf_mode(ctx: *mut EVP_PKEY_CTX, mode: c_int) -> c_int;
    pub fn EVP_PKEY_CTX_set_hkdf_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;
    pub fn EVP_PKEY_CTX_set1_hkdf_key(ctx: *mut EVP_PKEY_CTX, key: *const u8, keylen: c_int) -> c_int;
    pub fn EVP_PKEY_CTX_set1_hkdf_salt(ctx: *mut EVP_PKEY_CTX, salt: *const u8, saltlen: c_int) -> c_int;
    pub fn EVP_PKEY_CTX_add1_hkdf_info(ctx: *mut EVP_PKEY_CTX, info: *const u8, infolen: c_int) -> c_int;
    pub fn SSL_CIPHER_get_id(c: *const SSL_CIPHER) -> u32;
    pub fn SSL_CTX_set_keylog_callback(ctx: *mut SSL_CTX, cb: Option<SSL_CTX_keylog_cb>);
    pub fn SSL_CTX_has_client_custom_ext(ctx: *const SSL_CTX, ext_type: c_uint) -> c_int;
    pub fn SSL_CTX_add_custom_ext(ctx: *mut SSL_CTX, ext_type: c_uint, context: c_uint, add_cb: Option<SSL_custom_ext_add_cb_ex>, free_cb: Option<SSL_custom_ext_free_cb_ex>, add_arg: *mut c_void, parse_cb: Option<SSL_custom_ext_parse_cb_ex>, parse_arg: *mut c_void) -> c_int;
    pub fn SSL_set_msg_callback(ssl: *mut SSL, cb: Option<SSL_msg_cb>);
    pub fn SSL_set_bio(ssl: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
    pub fn SSL_set_max_early_data(ssl: *mut SSL, max: u32) -> c_int;
    pub fn BIO_s_null() -> *const BIO_METHOD;
}

pub const EVP_PKEY_HKDF: c_int = 1036;
pub const EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY: c_int = 1;
pub const EVP_PKEY_HKDEF_MODE_EXPAND_ONLY: c_int = 2;

pub const EVP_CIPH_CCM_MODE: c_int = 0x7;

pub const EVP_CTRL_AEAD_SET_IVLEN: c_int = 0x9;
pub const EVP_CTRL_AEAD_GET_TAG: c_int = 0x10;
pub const EVP_CTRL_AEAD_SET_TAG: c_int = 0x11;

pub const TLS1_3_CK_AES_128_GCM_SHA256: u32 = 0x03001301;
pub const TLS1_3_CK_AES_256_GCM_SHA384: u32 = 0x03001302;
pub const TLS1_3_CK_CHACHA20_POLY1305_SHA256: u32 = 0x03001303;
pub const TLS1_3_CK_AES_128_CCM_SHA256: u32 = 0x03001304;

pub const SSL_EXT_CLIENT_HELLO: c_uint = 0x0080;
pub const SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS: c_uint = 0x0400;

pub const SSL3_RT_HEADER_LENGTH: usize = 5;
pub const SSL3_RT_ALERT: c_int = 21;
pub const SSL3_RT_HANDSHAKE: c_int = 22;
pub const SSL3_RT_APPLICATION_DATA: c_int = 23;

pub const SSL_AD_UNEXPECTED_MESSAGE: c_int = 10;
pub const SSL_AD_MISSING_EXTENSION: c_int = 109;
pub const SSL_AD_NO_APPLICATION_PROTOCOL: c_int = 120;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_macros() {
        // error:0A0000B9:SSL routines::no cipher match
        assert_eq!(ERR_GET_LIB(0x0A0000B9), ERR_LIB_SSL);
        assert_eq!(ERR_GET_REASON(0x0A0000B9), 0xB9);

        // system errors
        let e = ERR_SYSTEM_FLAG | 2;
        assert_eq!(ERR_GET_LIB(e), ERR_LIB_SYS);
        assert_eq!(ERR_GET_REASON(e), 2);
    }
}
