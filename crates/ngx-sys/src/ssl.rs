//! OpenSSL functions the openssl crate has no safe API for.
//!
//! nginx drives OpenSSL with the socket bound to the SSL object
//! (SSL_set_fd) and calls SSL_read()/SSL_write()/SSL_do_handshake()/...
//! itself, looking at SSL_get_error() and errno, and prints the error queue
//! in its messages. The crate's SslStream does its I/O through a BIO of its
//! own and drains the error queue into an ErrorStack, so these calls, and
//! the error queue functions nginx uses, are wrapped here; so are the
//! callbacks and getters the crate has no safe binding for. Each function
//! takes the crate's types (`&mut SslRef`, `&SslContextBuilder`, ...),
//! slices and numbers, returns owned crate types or copies, and makes the
//! foreign call(s) of one OpenSSL operation; the SAFETY comments explain
//! why the arguments make the call sound.
//!
//! Callbacks are generic over a handler type implementing a trait (e.g.
//! `ServernameCallback`): the trampoline registered with OpenSSL is
//! monomorphized for the handler, so it needs no data to find the Rust
//! function, and it may be installed on an SSL from another context
//! (SSL_set_verify() with SSL_CTX_get_verify_callback(), as nginx does on
//! SNI) without a lookup that could fail.

#![allow(non_camel_case_types, non_upper_case_globals)]

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void, CStr};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1GeneralizedTimeRef, Asn1IntegerRef, Asn1TimeRef};
use openssl::cipher::CipherRef;
use openssl::dh::Dh;
use openssl::hash::MessageDigest;
use openssl::md::MdRef;
use openssl::ocsp::OcspResponse;
use openssl::pkey::{PKey, Params, Private};
use openssl::ssl::{SslCipherRef, SslContextBuilder, SslContextRef, SslRef, SslSessionRef};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilderRef;
use openssl::x509::{X509CrlRef, X509NameRef, X509Ref, X509StoreContextRef, X509Crl, X509};
use openssl_sys as ffi;

// --- the C declarations (OpenSSL 3.0) ---

type SSL_CONF_CTX = c_void;
type ENGINE = c_void;
type UI_METHOD = c_void;
type OSSL_STORE_CTX = c_void;
type OSSL_STORE_INFO = c_void;
type HMAC_CTX = c_void;

type pem_password_cb = unsafe extern "C" fn(buf: *mut c_char, size: c_int, rwflag: c_int, userdata: *mut c_void) -> c_int;
type info_cb = unsafe extern "C" fn(ssl: *const ffi::SSL, where_: c_int, ret: c_int);
type verify_cb = unsafe extern "C" fn(ok: c_int, ctx: *mut ffi::X509_STORE_CTX) -> c_int;
type servername_cb = unsafe extern "C" fn(ssl: *mut ffi::SSL, ad: *mut c_int, arg: *mut c_void) -> c_int;
type client_hello_cb = unsafe extern "C" fn(ssl: *mut ffi::SSL, al: *mut c_int, arg: *mut c_void) -> c_int;
type cert_cb = unsafe extern "C" fn(ssl: *mut ffi::SSL, arg: *mut c_void) -> c_int;
type get_session_cb = unsafe extern "C" fn(ssl: *mut ffi::SSL, data: *const u8, len: c_int, copy: *mut c_int) -> *mut ffi::SSL_SESSION;
type ticket_key_cb = unsafe extern "C" fn(ssl: *mut ffi::SSL, name: *mut u8, iv: *mut u8, ectx: *mut ffi::EVP_CIPHER_CTX, hctx: *mut HMAC_CTX, enc: c_int) -> c_int;
type msg_cb = unsafe extern "C" fn(write_p: c_int, version: c_int, content_type: c_int, buf: *const c_void, len: usize, ssl: *mut ffi::SSL, arg: *mut c_void);
type d2i_of_void = unsafe extern "C" fn(a: *mut *mut c_void, pp: *mut *const u8, len: c_long) -> *mut c_void;
type xnew_fn = unsafe extern "C" fn() -> *mut c_void;

extern "C" {
    fn OPENSSL_init_ssl(opts: u64, settings: *const c_void) -> c_int;

    fn ERR_peek_error() -> c_ulong;
    fn ERR_peek_last_error() -> c_ulong;
    fn ERR_get_error() -> c_ulong;
    fn ERR_clear_error();
    fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
    fn ERR_peek_error_data(data: *mut *const c_char, flags: *mut c_int) -> c_ulong;

    fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int);

    fn BIO_new(ty: *const ffi::BIO_METHOD) -> *mut ffi::BIO;
    fn BIO_s_mem() -> *const ffi::BIO_METHOD;
    fn BIO_s_null() -> *const ffi::BIO_METHOD;
    fn BIO_new_file(filename: *const c_char, mode: *const c_char) -> *mut ffi::BIO;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut ffi::BIO;
    fn BIO_free(b: *mut ffi::BIO) -> c_int;
    fn BIO_ctrl(b: *mut ffi::BIO, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn BIO_int_ctrl(b: *mut ffi::BIO, cmd: c_int, larg: c_long, iarg: c_int) -> c_long;
    fn BIO_read(b: *mut ffi::BIO, data: *mut c_void, len: c_int) -> c_int;
    fn BIO_write(b: *mut ffi::BIO, data: *const c_void, len: c_int) -> c_int;

    fn PEM_read_bio_X509_AUX(bp: *mut ffi::BIO, x: *mut *mut ffi::X509, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut ffi::X509;
    fn PEM_read_bio_X509(bp: *mut ffi::BIO, x: *mut *mut ffi::X509, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut ffi::X509;
    fn PEM_read_bio_PrivateKey(bp: *mut ffi::BIO, x: *mut *mut ffi::EVP_PKEY, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut ffi::EVP_PKEY;
    fn PEM_read_bio_X509_CRL(bp: *mut ffi::BIO, x: *mut *mut ffi::X509_CRL, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut ffi::X509_CRL;
    fn PEM_read_bio_DHparams(bp: *mut ffi::BIO, x: *mut *mut ffi::DH, cb: Option<pem_password_cb>, u: *mut c_void) -> *mut ffi::DH;
    fn ASN1_d2i_bio(xnew: Option<xnew_fn>, d2i: Option<d2i_of_void>, inp: *mut ffi::BIO, x: *mut *mut c_void) -> *mut c_void;
    fn OCSP_RESPONSE_new() -> *mut ffi::OCSP_RESPONSE;
    fn d2i_OCSP_RESPONSE(a: *mut *mut ffi::OCSP_RESPONSE, pp: *mut *const u8, len: c_long) -> *mut ffi::OCSP_RESPONSE;

    fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;
    fn ENGINE_free(e: *mut ENGINE) -> c_int;
    fn ENGINE_load_private_key(e: *mut ENGINE, key_id: *const c_char, ui_method: *mut UI_METHOD, callback_data: *mut c_void) -> *mut ffi::EVP_PKEY;
    fn OSSL_STORE_open(uri: *const c_char, ui_method: *const UI_METHOD, ui_data: *mut c_void, post_process: *mut c_void, post_process_data: *mut c_void) -> *mut OSSL_STORE_CTX;
    fn OSSL_STORE_eof(ctx: *mut OSSL_STORE_CTX) -> c_int;
    fn OSSL_STORE_load(ctx: *mut OSSL_STORE_CTX) -> *mut OSSL_STORE_INFO;
    fn OSSL_STORE_close(ctx: *mut OSSL_STORE_CTX) -> c_int;
    fn OSSL_STORE_INFO_get_type(info: *const OSSL_STORE_INFO) -> c_int;
    fn OSSL_STORE_INFO_get1_PKEY(info: *const OSSL_STORE_INFO) -> *mut ffi::EVP_PKEY;
    fn OSSL_STORE_INFO_free(info: *mut OSSL_STORE_INFO);
    fn UI_UTIL_wrap_read_pem_callback(cb: Option<pem_password_cb>, rwflag: c_int) -> *mut UI_METHOD;
    fn UI_destroy_method(method: *mut UI_METHOD);
    fn UI_set_default_method(method: *const UI_METHOD);
    fn UI_null() -> *const UI_METHOD;

    fn SSL_set_fd(ssl: *mut ffi::SSL, fd: c_int) -> c_int;
    fn SSL_do_handshake(ssl: *mut ffi::SSL) -> c_int;
    fn SSL_read(ssl: *mut ffi::SSL, buf: *mut c_void, num: c_int) -> c_int;
    fn SSL_peek(ssl: *mut ffi::SSL, buf: *mut c_void, num: c_int) -> c_int;
    fn SSL_write(ssl: *mut ffi::SSL, buf: *const c_void, num: c_int) -> c_int;
    fn SSL_read_early_data(ssl: *mut ffi::SSL, buf: *mut c_void, num: usize, readbytes: *mut usize) -> c_int;
    fn SSL_write_early_data(ssl: *mut ffi::SSL, buf: *const c_void, num: usize, written: *mut usize) -> c_int;
    fn SSL_sendfile(s: *mut ffi::SSL, fd: c_int, offset: libc::off_t, size: usize, flags: c_int) -> isize;
    fn SSL_shutdown(ssl: *mut ffi::SSL) -> c_int;
    fn SSL_get_error(ssl: *const ffi::SSL, ret: c_int) -> c_int;
    fn SSL_want(ssl: *const ffi::SSL) -> c_int;
    fn SSL_in_init(ssl: *const ffi::SSL) -> c_int;
    fn SSL_is_server(ssl: *const ffi::SSL) -> c_int;
    fn SSL_get_shutdown(ssl: *const ffi::SSL) -> c_int;
    fn SSL_set_shutdown(ssl: *mut ffi::SSL, mode: c_int);
    fn SSL_set_quiet_shutdown(ssl: *mut ffi::SSL, mode: c_int);
    fn SSL_get_options(ssl: *const ffi::SSL) -> u64;
    fn SSL_set_options(ssl: *mut ffi::SSL, op: u64) -> u64;
    fn SSL_clear_options(ssl: *mut ffi::SSL, op: u64) -> u64;
    fn SSL_CTX_get_options(ctx: *const ffi::SSL_CTX) -> u64;
    fn SSL_set_verify(ssl: *mut ffi::SSL, mode: c_int, cb: Option<verify_cb>);
    fn SSL_set_verify_depth(ssl: *mut ffi::SSL, depth: c_int);
    fn SSL_CTX_get_verify_mode(ctx: *const ffi::SSL_CTX) -> c_int;
    fn SSL_CTX_get_verify_callback(ctx: *const ffi::SSL_CTX) -> Option<verify_cb>;
    fn SSL_CTX_get_verify_depth(ctx: *const ffi::SSL_CTX) -> c_int;
    fn SSL_CTX_set_verify(ctx: *mut ffi::SSL_CTX, mode: c_int, cb: Option<verify_cb>);
    fn SSL_set_session(ssl: *mut ffi::SSL, session: *mut ffi::SSL_SESSION) -> c_int;
    fn SSL_get_session(ssl: *const ffi::SSL) -> *mut ffi::SSL_SESSION;
    fn SSL_get_SSL_CTX(ssl: *const ffi::SSL) -> *mut ffi::SSL_CTX;
    fn SSL_get_rbio(ssl: *const ffi::SSL) -> *mut ffi::BIO;
    fn SSL_get_wbio(ssl: *const ffi::SSL) -> *mut ffi::BIO;
    fn SSL_set_bio(ssl: *mut ffi::SSL, rbio: *mut ffi::BIO, wbio: *mut ffi::BIO);
    fn SSL_ctrl(ssl: *mut ffi::SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_CTX_ctrl(ctx: *mut ffi::SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_CTX_callback_ctrl(ctx: *mut ffi::SSL_CTX, cmd: c_int, fp: Option<unsafe extern "C" fn()>) -> c_long;
    fn SSL_CTX_set_cipher_list(ctx: *mut ffi::SSL_CTX, s: *const c_char) -> c_int;
    fn SSL_CTX_set_timeout(ctx: *mut ffi::SSL_CTX, t: c_long) -> c_long;
    fn SSL_CTX_get_timeout(ctx: *const ffi::SSL_CTX) -> c_long;
    fn SSL_CTX_set_info_callback(ctx: *mut ffi::SSL_CTX, cb: Option<info_cb>);
    fn SSL_CTX_set_client_hello_cb(ctx: *mut ffi::SSL_CTX, cb: Option<client_hello_cb>, arg: *mut c_void);
    fn SSL_client_hello_get0_ext(ssl: *mut ffi::SSL, ty: c_uint, out: *mut *const u8, outlen: *mut usize) -> c_int;
    fn SSL_CTX_set_cert_cb(ctx: *mut ffi::SSL_CTX, cb: Option<cert_cb>, arg: *mut c_void);
    fn SSL_CTX_sess_set_get_cb(ctx: *mut ffi::SSL_CTX, cb: Option<get_session_cb>);
    fn SSL_set_msg_callback(ssl: *mut ffi::SSL, cb: Option<msg_cb>);
    fn SSL_SESSION_set_time(sess: *mut ffi::SSL_SESSION, t: c_long) -> c_long;
    fn SSL_SESSION_set_timeout(sess: *mut ffi::SSL_SESSION, t: c_long) -> c_long;
    fn SSL_SESSION_set1_id_context(sess: *mut ffi::SSL_SESSION, sid_ctx: *const u8, len: c_uint) -> c_int;
    fn d2i_SSL_SESSION(a: *mut *mut ffi::SSL_SESSION, pp: *mut *const u8, len: c_long) -> *mut ffi::SSL_SESSION;
    fn SSL_CIPHER_find(ssl: *mut ffi::SSL, ptr: *const u8) -> *const ffi::SSL_CIPHER;
    fn SSL_group_to_name(ssl: *mut ffi::SSL, id: c_int) -> *const c_char;
    fn SSL_get_sigalgs(ssl: *mut ffi::SSL, idx: c_int, psign: *mut c_int, phash: *mut c_int, psignhash: *mut c_int, rsig: *mut u8, rhash: *mut u8) -> c_int;

    fn EVP_EncryptInit_ex(ctx: *mut ffi::EVP_CIPHER_CTX, cipher: *const ffi::EVP_CIPHER, e: *mut ENGINE, key: *const u8, iv: *const u8) -> c_int;
    fn EVP_DecryptInit_ex(ctx: *mut ffi::EVP_CIPHER_CTX, cipher: *const ffi::EVP_CIPHER, e: *mut ENGINE, key: *const u8, iv: *const u8) -> c_int;
    fn HMAC_Init_ex(ctx: *mut HMAC_CTX, key: *const c_void, len: c_int, md: *const ffi::EVP_MD, e: *mut ENGINE) -> c_int;

    fn SSL_CONF_CTX_new() -> *mut SSL_CONF_CTX;
    fn SSL_CONF_CTX_free(cctx: *mut SSL_CONF_CTX);
    fn SSL_CONF_CTX_set_flags(cctx: *mut SSL_CONF_CTX, flags: c_uint) -> c_uint;
    fn SSL_CONF_CTX_set_ssl_ctx(cctx: *mut SSL_CONF_CTX, ctx: *mut ffi::SSL_CTX);
    fn SSL_CONF_cmd(cctx: *mut SSL_CONF_CTX, cmd: *const c_char, value: *const c_char) -> c_int;
    fn SSL_CONF_cmd_value_type(cctx: *mut SSL_CONF_CTX, cmd: *const c_char) -> c_int;
    fn SSL_CONF_CTX_finish(cctx: *mut SSL_CONF_CTX) -> c_int;

    fn X509_NAME_print_ex(out: *mut ffi::BIO, n: *const ffi::X509_NAME, indent: c_int, flags: c_ulong) -> c_int;
    fn X509_NAME_oneline(n: *const ffi::X509_NAME, buf: *mut c_char, size: c_int) -> *mut c_char;
    fn X509_NAME_digest(n: *const ffi::X509_NAME, md: *const ffi::EVP_MD, out: *mut u8, len: *mut c_uint) -> c_int;
    fn X509_pubkey_digest(x: *const ffi::X509, md: *const ffi::EVP_MD, out: *mut u8, len: *mut c_uint) -> c_int;
    fn i2a_ASN1_INTEGER(bp: *mut ffi::BIO, a: *const ffi::ASN1_INTEGER) -> c_int;
    fn ASN1_TIME_print(bp: *mut ffi::BIO, t: *const ffi::ASN1_TIME) -> c_int;
    fn ASN1_GENERALIZEDTIME_print(bp: *mut ffi::BIO, t: *const ffi::ASN1_GENERALIZEDTIME) -> c_int;
    fn X509_verify_cert_error_string(n: c_long) -> *const c_char;
    fn X509_STORE_add_crl(store: *mut ffi::X509_STORE, x: *mut ffi::X509_CRL) -> c_int;
    fn X509_check_host(x: *mut ffi::X509, chk: *const c_char, chklen: usize, flags: c_uint, peername: *mut *mut c_char) -> c_int;
    fn SSL_CTX_remove_session(ctx: *mut ffi::SSL_CTX, sess: *mut ffi::SSL_SESSION) -> c_int;
    fn X509_STORE_CTX_new() -> *mut ffi::X509_STORE_CTX;
    fn X509_STORE_CTX_init(ctx: *mut ffi::X509_STORE_CTX, store: *mut ffi::X509_STORE, x509: *mut ffi::X509, chain: *mut ffi::stack_st_X509) -> c_int;
    fn X509_STORE_CTX_free(ctx: *mut ffi::X509_STORE_CTX);
    fn X509_STORE_CTX_get1_issuer(issuer: *mut *mut ffi::X509, ctx: *mut ffi::X509_STORE_CTX, x: *mut ffi::X509) -> c_int;
    fn X509_get1_ocsp(x: *mut ffi::X509) -> *mut ffi::OPENSSL_STACK;
    fn X509_email_free(sk: *mut ffi::OPENSSL_STACK);
    fn OPENSSL_sk_num(st: *const ffi::OPENSSL_STACK) -> c_int;
    fn OPENSSL_sk_value(st: *const ffi::OPENSSL_STACK, i: c_int) -> *mut c_void;
}

// --- constants (ssl.h, tls1.h, x509_vfy.h, err.h, ... of OpenSSL 3.0) ---

pub const SSL_ERROR_NONE: i32 = 0;
pub const SSL_ERROR_SSL: i32 = 1;
pub const SSL_ERROR_WANT_READ: i32 = 2;
pub const SSL_ERROR_WANT_WRITE: i32 = 3;
pub const SSL_ERROR_SYSCALL: i32 = 5;
pub const SSL_ERROR_ZERO_RETURN: i32 = 6;

/// SSL_want()
pub const SSL_WRITING: i32 = 2;

pub const SSL_SENT_SHUTDOWN: i32 = 1;
pub const SSL_RECEIVED_SHUTDOWN: i32 = 2;

pub const SSL_OP_IGNORE_UNEXPECTED_EOF: u64 = 1 << 7;
pub const SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS: u64 = 1 << 11;
pub const SSL_OP_NO_TICKET: u64 = 1 << 14;
pub const SSL_OP_NO_COMPRESSION: u64 = 1 << 17;
pub const SSL_OP_ENABLE_MIDDLEBOX_COMPAT: u64 = 1 << 20;
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

pub const SSL_MODE_NO_AUTO_CHAIN: u64 = 0x00000008;
pub const SSL_MODE_RELEASE_BUFFERS: u64 = 0x00000010;

pub const SSL_SESS_CACHE_OFF: i64 = 0x0000;
pub const SSL_SESS_CACHE_CLIENT: i64 = 0x0001;
pub const SSL_SESS_CACHE_SERVER: i64 = 0x0002;
pub const SSL_SESS_CACHE_NO_AUTO_CLEAR: i64 = 0x0080;
pub const SSL_SESS_CACHE_NO_INTERNAL_LOOKUP: i64 = 0x0100;
pub const SSL_SESS_CACHE_NO_INTERNAL_STORE: i64 = 0x0200;
pub const SSL_SESS_CACHE_NO_INTERNAL: i64 = SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE;

pub const SSL_VERIFY_NONE: i32 = 0x00;
pub const SSL_VERIFY_PEER: i32 = 0x01;

pub const SSL_ST_ACCEPT: i32 = 0x2000;
pub const SSL_CB_LOOP: i32 = 0x01;
pub const SSL_CB_ACCEPT_LOOP: i32 = SSL_ST_ACCEPT | SSL_CB_LOOP;
pub const SSL_CB_HANDSHAKE_START: i32 = 0x10;

pub const SSL_TLSEXT_ERR_OK: i32 = 0;
pub const SSL_TLSEXT_ERR_ALERT_WARNING: i32 = 1;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: i32 = 2;
pub const SSL_TLSEXT_ERR_NOACK: i32 = 3;

pub const SSL_AD_UNEXPECTED_MESSAGE: i32 = 10;
pub const SSL_AD_DECODE_ERROR: i32 = 50;
pub const SSL_AD_INTERNAL_ERROR: i32 = 80;
pub const SSL_AD_NO_RENEGOTIATION: i32 = 100;
pub const SSL_AD_MISSING_EXTENSION: i32 = 109;
pub const SSL_AD_UNRECOGNIZED_NAME: i32 = 112;
pub const SSL_AD_NO_APPLICATION_PROTOCOL: i32 = 120;
pub const SSL_AD_REASON_OFFSET: i32 = 1000;

pub const SSL_CLIENT_HELLO_ERROR: i32 = 0;
pub const SSL_CLIENT_HELLO_SUCCESS: i32 = 1;

pub const SSL_READ_EARLY_DATA_ERROR: i32 = 0;
pub const SSL_READ_EARLY_DATA_SUCCESS: i32 = 1;
pub const SSL_READ_EARLY_DATA_FINISH: i32 = 2;

pub const TLSEXT_TYPE_server_name: u32 = 0;
pub const TLSEXT_NAMETYPE_host_name: i32 = 0;
pub const TLSEXT_MAXLEN_host_name: usize = 255;
pub const TLSEXT_nid_unknown: i32 = 0x1000000;

pub const TLS1_2_VERSION: i32 = 0x0303;
pub const TLS1_3_VERSION: i32 = 0x0304;

pub const SSL_CONF_FLAG_FILE: u32 = 0x2;
pub const SSL_CONF_FLAG_CLIENT: u32 = 0x4;
pub const SSL_CONF_FLAG_SERVER: u32 = 0x8;
pub const SSL_CONF_FLAG_SHOW_ERRORS: u32 = 0x10;
pub const SSL_CONF_FLAG_CERTIFICATE: u32 = 0x20;
pub const SSL_CONF_TYPE_FILE: i32 = 0x2;
pub const SSL_CONF_TYPE_DIR: i32 = 0x3;

pub const X509_V_OK: i64 = 0;
pub const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: i64 = 18;
pub const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: i64 = 19;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: i64 = 20;
pub const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: i64 = 21;
pub const X509_V_ERR_CERT_REVOKED: i64 = 23;
pub const X509_V_ERR_CERT_UNTRUSTED: i64 = 27;

/// XN_FLAG_RFC2253
pub const XN_FLAG_RFC2253: u64 = 0x317 | (1 << 16) | (1 << 20) | (1 << 24);

pub const ERR_TXT_STRING: i32 = 0x02;

pub const ERR_LIB_SYS: i32 = 2;
pub const ERR_LIB_PEM: i32 = 9;
pub const ERR_LIB_X509: i32 = 11;
pub const ERR_LIB_SSL: i32 = 20;

pub const PEM_R_NO_START_LINE: i32 = 108;
pub const X509_R_CERT_ALREADY_IN_HASH_TABLE: i32 = 101;
pub const X509_R_KEY_VALUES_MISMATCH: i32 = 116;
pub const SSL_R_UNINITIALIZED: i32 = 276;

pub const SSL3_RT_HEADER_LENGTH: usize = 5;
pub const SSL3_RT_ALERT: i32 = 21;
pub const SSL3_RT_HANDSHAKE: i32 = 22;
pub const SSL3_RT_APPLICATION_DATA: i32 = 23;

pub const NID_undef: i32 = 0;
pub const EVP_MAX_MD_SIZE: usize = 64;

const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
const SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB: c_int = 72;
const SSL_CTRL_GET_EXTRA_CHAIN_CERTS: c_int = 82;
const SSL_CTRL_CHAIN: c_int = 88;
const SSL_CTRL_GET_GROUPS: c_int = 90;
const SSL_CTRL_SET_GROUPS_LIST: c_int = 92;
const SSL_CTRL_GET_RAW_CIPHERLIST: c_int = 110;
const SSL_CTRL_SELECT_CURRENT_CERT: c_int = 116;
const SSL_CTRL_GET_NEGOTIATED_GROUP: c_int = 134;
const SSL_CTRL_GET_SESS_CACHE_MODE: c_int = 45;

const BIO_CTRL_RESET: c_int = 1;
const BIO_CTRL_PENDING: c_int = 10;
const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
const BIO_C_SET_BUFF_SIZE: c_int = 117;

const OSSL_STORE_INFO_PKEY: c_int = 4;

const ERR_SYSTEM_FLAG: u64 = (c_int::MAX as u64) + 1;

/// ERR_GET_LIB()
pub fn err_get_lib(e: u64) -> i32 {
    if e & ERR_SYSTEM_FLAG != 0 {
        return ERR_LIB_SYS;
    }
    ((e >> 23) & 0xff) as i32
}

/// ERR_GET_REASON()
pub fn err_get_reason(e: u64) -> i32 {
    if e & ERR_SYSTEM_FLAG != 0 {
        return (e & (c_int::MAX as u64)) as i32;
    }
    (e & 0x7fffff) as i32
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// A NUL-terminated C string owned by OpenSSL, copied out.
///
/// # Safety
/// `p` is NULL or points to a NUL-terminated string valid for the call.
unsafe fn copy_cstr(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    // SAFETY: as the caller guarantees
    Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
}

// --- the library and the error queue ---

/// OPENSSL_init_ssl(0, NULL): the library with its configuration file
/// loaded (OPENSSL_INIT_LOAD_CONFIG is the default).
pub fn init_ssl() -> bool {
    // SAFETY: no settings (NULL); the function initializes the library once
    // and is safe to call any number of times.
    unsafe { OPENSSL_init_ssl(0, std::ptr::null()) == 1 }
}

/// ERR_peek_error()
pub fn err_peek_error() -> u64 {
    // SAFETY: reads the thread's error queue
    unsafe { ERR_peek_error() as u64 }
}

/// ERR_peek_last_error()
pub fn err_peek_last_error() -> u64 {
    // SAFETY: reads the thread's error queue
    unsafe { ERR_peek_last_error() as u64 }
}

/// ERR_get_error(): the first error, removed from the queue
pub fn err_get_error() -> u64 {
    // SAFETY: takes an entry of the thread's error queue
    unsafe { ERR_get_error() as u64 }
}

/// ERR_clear_error()
pub fn err_clear_error() {
    // SAFETY: empties the thread's error queue
    unsafe { ERR_clear_error() }
}

/// ERR_peek_error_data(): the first error of the queue (0: none) and its
/// text data, if it has one (ERR_TXT_STRING)
pub fn err_peek_error_data() -> (u64, Option<Vec<u8>>) {
    let mut data: *const c_char = std::ptr::null();
    let mut flags: c_int = 0;

    // SAFETY: the function stores a pointer to the entry's data, valid
    // until the entry is removed, which is copied at once, and the flags.
    unsafe {
        let n = ERR_peek_error_data(&mut data, &mut flags);

        if n == 0 || flags & ERR_TXT_STRING == 0 {
            return (n as u64, None);
        }

        (n as u64, copy_cstr(data))
    }
}

/// ERR_error_string_n() with a buffer of `len` bytes (the terminating NUL
/// included, as in C): the text of an error code.
pub fn err_error_string_n(e: u64, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }

    let mut buf = vec![0u8; len];

    // SAFETY: the function writes at most len bytes, NUL-terminated, to the
    // buffer, which has len bytes.
    unsafe { ERR_error_string_n(e as c_ulong, buf.as_mut_ptr() as *mut c_char, len) };

    let n = buf.iter().position(|&c| c == 0).unwrap_or(len);
    buf.truncate(n);
    buf
}

// --- BIOs ---

/// A memory BIO written by the print functions.
struct MemBio(*mut ffi::BIO);

impl MemBio {
    fn new() -> Option<MemBio> {
        // SAFETY: BIO_s_mem() is a static method table; BIO_new() returns a
        // new BIO or NULL.
        let b = unsafe { BIO_new(BIO_s_mem()) };
        if b.is_null() {
            None
        } else {
            Some(MemBio(b))
        }
    }

    /// The bytes written to it.
    fn contents(&self) -> Vec<u8> {
        // SAFETY: the BIO is a valid memory BIO; BIO_read() copies at most
        // len bytes to the buffer, which has len bytes.
        unsafe {
            let len = BIO_ctrl(self.0, BIO_CTRL_PENDING, 0, std::ptr::null_mut()).max(0) as usize;
            let mut v = vec![0u8; len];

            if len > 0 {
                let n = BIO_read(self.0, v.as_mut_ptr() as *mut c_void, len.min(c_int::MAX as usize) as c_int);
                v.truncate(n.max(0) as usize);
            }

            v
        }
    }
}

impl Drop for MemBio {
    fn drop(&mut self) {
        // SAFETY: the BIO is owned and not used after this
        unsafe { BIO_free(self.0) };
    }
}

/// A BIO to read PEM or DER objects from: a file (BIO_new_file()), or a
/// memory buffer (BIO_new_mem_buf(), which reads the borrowed bytes).
pub struct Bio<'a> {
    ptr: *mut ffi::BIO,
    _data: PhantomData<&'a [u8]>,
}

impl Bio<'static> {
    /// BIO_new_file(name, mode); None (with the error queue set) on failure
    pub fn new_file(name: &CStr, mode: &CStr) -> Option<Bio<'static>> {
        // SAFETY: both arguments are NUL-terminated strings
        let b = unsafe { BIO_new_file(name.as_ptr(), mode.as_ptr()) };
        if b.is_null() {
            return None;
        }
        Some(Bio { ptr: b, _data: PhantomData })
    }
}

impl<'a> Bio<'a> {
    /// BIO_new_mem_buf(data, len): a read-only BIO of the bytes, which it
    /// borrows (not copied)
    pub fn new_mem_buf(data: &'a [u8]) -> Option<Bio<'a>> {
        if data.len() > c_int::MAX as usize {
            return None;
        }

        // SAFETY: the BIO reads the len bytes of data, which outlive it (the
        // lifetime of the Bio).
        let b = unsafe { BIO_new_mem_buf(data.as_ptr() as *const c_void, data.len() as c_int) };
        if b.is_null() {
            return None;
        }
        Some(Bio { ptr: b, _data: PhantomData })
    }

    /// BIO_reset(): back to the start
    pub fn reset(&mut self) -> i32 {
        // SAFETY: a valid BIO
        unsafe { BIO_ctrl(self.ptr, BIO_CTRL_RESET, 0, std::ptr::null_mut()) as i32 }
    }
}

impl Drop for Bio<'_> {
    fn drop(&mut self) {
        // SAFETY: the BIO is owned and not used after this
        unsafe { BIO_free(self.ptr) };
    }
}

/// PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)
pub fn pem_read_x509_aux(bio: &mut Bio<'_>) -> Option<X509> {
    // SAFETY: a valid BIO; no password callback; the certificate returned
    // is a new reference, owned by the X509.
    unsafe {
        let x = PEM_read_bio_X509_AUX(bio.ptr, std::ptr::null_mut(), None, std::ptr::null_mut());
        if x.is_null() {
            None
        } else {
            Some(X509::from_ptr(x))
        }
    }
}

/// PEM_read_bio_X509(bio, NULL, NULL, NULL)
pub fn pem_read_x509(bio: &mut Bio<'_>) -> Option<X509> {
    // SAFETY: as pem_read_x509_aux()
    unsafe {
        let x = PEM_read_bio_X509(bio.ptr, std::ptr::null_mut(), None, std::ptr::null_mut());
        if x.is_null() {
            None
        } else {
            Some(X509::from_ptr(x))
        }
    }
}

/// PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL)
pub fn pem_read_x509_crl(bio: &mut Bio<'_>) -> Option<X509Crl> {
    // SAFETY: as pem_read_x509_aux()
    unsafe {
        let x = PEM_read_bio_X509_CRL(bio.ptr, std::ptr::null_mut(), None, std::ptr::null_mut());
        if x.is_null() {
            None
        } else {
            Some(X509Crl::from_ptr(x))
        }
    }
}

/// PEM_read_bio_DHparams(bio, NULL, NULL, NULL)
pub fn pem_read_dhparams(bio: &mut Bio<'_>) -> Option<Dh<Params>> {
    // SAFETY: as pem_read_x509_aux()
    unsafe {
        let dh = PEM_read_bio_DHparams(bio.ptr, std::ptr::null_mut(), None, std::ptr::null_mut());
        if dh.is_null() {
            None
        } else {
            Some(Dh::from_ptr(dh))
        }
    }
}

/// The password callback of PEM_read_bio_PrivateKey(): the function given
/// fills the buffer (the second argument is rwflag, set when the password
/// is asked for encryption) and returns the length of the password.
pub type PasswordCallback<'a> = &'a mut dyn FnMut(&mut [u8], bool) -> usize;

unsafe extern "C" fn raw_pem_password(buf: *mut c_char, size: c_int, rwflag: c_int, userdata: *mut c_void) -> c_int {
    if buf.is_null() || size <= 0 || userdata.is_null() {
        return 0;
    }

    // SAFETY: userdata is the &mut PasswordCallback passed to OpenSSL by
    // pem_read_private_key() or store_load_private_key(), alive for the
    // call that invokes this callback; buf has size bytes.
    let (cb, buf) = unsafe { (&mut *(userdata as *mut PasswordCallback<'_>), std::slice::from_raw_parts_mut(buf as *mut u8, size as usize)) };

    let n = cb(buf, rwflag != 0);

    n.min(buf.len()) as c_int
}

/// PEM_read_bio_PrivateKey(bio, NULL, cb, u): with the callback given, or
/// OpenSSL's default one (prompting on the terminal) without
pub fn pem_read_private_key(bio: &mut Bio<'_>, cb: Option<PasswordCallback<'_>>) -> Option<PKey<Private>> {
    let mut cb = cb;

    let (f, u): (Option<pem_password_cb>, *mut c_void) = match cb.as_mut() {
        Some(c) => (Some(raw_pem_password), c as *mut PasswordCallback<'_> as *mut c_void),
        None => (None, std::ptr::null_mut()),
    };

    // SAFETY: a valid BIO; the callback data is the PasswordCallback, alive
    // for the call (the only one using it); the key returned is a new
    // reference, owned by the PKey.
    unsafe {
        let pkey = PEM_read_bio_PrivateKey(bio.ptr, std::ptr::null_mut(), f, u);
        if pkey.is_null() {
            None
        } else {
            Some(PKey::from_ptr(pkey))
        }
    }
}

/// d2i_OCSP_RESPONSE_bio(bio, NULL)
pub fn d2i_ocsp_response_bio(bio: &mut Bio<'_>) -> Option<OcspResponse> {
    // the d2i function as ASN1_d2i_bio() calls it (d2i_of_void)
    unsafe extern "C" fn d2i(a: *mut *mut c_void, pp: *mut *const u8, len: c_long) -> *mut c_void {
        // SAFETY: called by ASN1_d2i_bio() with the arguments of a d2i
        // function, of the OCSP_RESPONSE type it was given
        unsafe { d2i_OCSP_RESPONSE(a as *mut *mut ffi::OCSP_RESPONSE, pp, len) as *mut c_void }
    }

    unsafe extern "C" fn new() -> *mut c_void {
        // SAFETY: allocates an object
        unsafe { OCSP_RESPONSE_new() as *mut c_void }
    }

    // SAFETY: a valid BIO; the functions are the constructor and the
    // decoder of OCSP_RESPONSE, as the d2i_OCSP_RESPONSE_bio() macro passes
    // them; the response returned is new, owned by the OcspResponse.
    unsafe {
        let r = ASN1_d2i_bio(Some(new), Some(d2i), bio.ptr, std::ptr::null_mut());
        if r.is_null() {
            None
        } else {
            Some(OcspResponse::from_ptr(r as *mut ffi::OCSP_RESPONSE))
        }
    }
}

/// Why engine_load_private_key() failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    /// ENGINE_by_id() failed
    ById,
    /// ENGINE_load_private_key() failed
    Load,
}

/// ENGINE_by_id(engine), ENGINE_load_private_key(e, key, NULL, NULL),
/// ENGINE_free(e): an "engine:name:id" key
pub fn engine_load_private_key(engine: &CStr, key: &CStr) -> Result<PKey<Private>, EngineError> {
    // SAFETY: NUL-terminated strings; the engine reference taken is
    // released; the key returned is a new reference, owned by the PKey.
    unsafe {
        let e = ENGINE_by_id(engine.as_ptr());
        if e.is_null() {
            return Err(EngineError::ById);
        }

        let pkey = ENGINE_load_private_key(e, key.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut());

        ENGINE_free(e);

        if pkey.is_null() {
            return Err(EngineError::Load);
        }

        Ok(PKey::from_ptr(pkey))
    }
}

/// Why store_load_private_key() failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// OSSL_STORE_open() failed
    Open,
    /// no key loaded
    Load,
}

/// OSSL_STORE_open(uri) and OSSL_STORE_load() until a private key: a
/// "store:uri" key; the password callback, if any, is wrapped with
/// UI_UTIL_wrap_read_pem_callback()
pub fn store_load_private_key(uri: &CStr, cb: Option<PasswordCallback<'_>>) -> Result<PKey<Private>, StoreError> {
    let mut cb = cb;

    // SAFETY: the UI method made (and destroyed) here calls the password
    // callback with the ui_data given to OSSL_STORE_open(), the
    // PasswordCallback, which lives until the store is closed; the infos
    // loaded are freed, the key taken is a new reference owned by the PKey.
    unsafe {
        let (method, data) = match cb.as_mut() {
            Some(c) => (UI_UTIL_wrap_read_pem_callback(Some(raw_pem_password), 0), c as *mut PasswordCallback<'_> as *mut c_void),
            None => (std::ptr::null_mut(), std::ptr::null_mut()),
        };

        let store = OSSL_STORE_open(uri.as_ptr(), method, data, std::ptr::null_mut(), std::ptr::null_mut());

        if store.is_null() {
            if !method.is_null() {
                UI_destroy_method(method);
            }

            return Err(StoreError::Open);
        }

        let mut pkey: *mut ffi::EVP_PKEY = std::ptr::null_mut();

        while pkey.is_null() && OSSL_STORE_eof(store) == 0 {
            let info = OSSL_STORE_load(store);

            if info.is_null() {
                continue;
            }

            if OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY {
                pkey = OSSL_STORE_INFO_get1_PKEY(info);
            }

            OSSL_STORE_INFO_free(info);
        }

        OSSL_STORE_close(store);

        if !method.is_null() {
            UI_destroy_method(method);
        }

        if pkey.is_null() {
            return Err(StoreError::Load);
        }

        Ok(PKey::from_ptr(pkey))
    }
}

/// UI_set_default_method(UI_null()): no prompts on the terminal
pub fn ui_set_default_null() {
    // SAFETY: UI_null() is a static method table
    unsafe { UI_set_default_method(UI_null()) }
}

// --- printing ---

/// Why a print to a memory BIO failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintError {
    /// BIO_new() failed
    Bio,
    /// the print function failed
    Print,
}

/// X509_NAME_print_ex(bio, name, 0, flags) to a memory BIO: the text
pub fn x509_name_print_ex(name: &X509NameRef, flags: u64) -> Result<Vec<u8>, PrintError> {
    let bio = MemBio::new().ok_or(PrintError::Bio)?;

    // SAFETY: a valid memory BIO and name
    if unsafe { X509_NAME_print_ex(bio.0, name.as_ptr(), 0, flags as c_ulong) } < 0 {
        return Err(PrintError::Print);
    }

    Ok(bio.contents())
}

/// X509_NAME_oneline(name, NULL, 0): the text (None if it failed)
pub fn x509_name_oneline(name: &X509NameRef) -> Option<Vec<u8>> {
    // SAFETY: a valid name; the string returned is allocated by OpenSSL,
    // copied, and freed with OPENSSL_free().
    unsafe {
        let p = X509_NAME_oneline(name.as_ptr(), std::ptr::null_mut(), 0);
        let s = copy_cstr(p)?;
        CRYPTO_free(p as *mut c_void, std::ptr::null(), 0);
        Some(s)
    }
}

/// i2a_ASN1_INTEGER() to a memory BIO (None: BIO_new() failed)
pub fn asn1_integer_print(i: &Asn1IntegerRef) -> Option<Vec<u8>> {
    let bio = MemBio::new()?;

    // SAFETY: a valid memory BIO and integer
    unsafe { i2a_ASN1_INTEGER(bio.0, i.as_ptr()) };

    Some(bio.contents())
}

/// ASN1_TIME_print() to a memory BIO: what it wrote, whatever its result
/// ("Bad time value" for an invalid time); None if BIO_new() failed
pub fn asn1_time_print(t: &Asn1TimeRef) -> Option<Vec<u8>> {
    let bio = MemBio::new()?;

    // SAFETY: a valid memory BIO and time
    unsafe { ASN1_TIME_print(bio.0, t.as_ptr()) };

    Some(bio.contents())
}

/// ASN1_GENERALIZEDTIME_print() to a memory BIO, as asn1_time_print()
pub fn asn1_generalizedtime_print(t: &Asn1GeneralizedTimeRef) -> Option<Vec<u8>> {
    let bio = MemBio::new()?;

    // SAFETY: a valid memory BIO and time
    unsafe { ASN1_GENERALIZEDTIME_print(bio.0, t.as_ptr()) };

    Some(bio.contents())
}

/// X509_verify_cert_error_string(n)
pub fn x509_verify_cert_error_string(n: i64) -> Vec<u8> {
    // SAFETY: the function returns a static string (OpenSSL 3.0 has no
    // static buffer for unknown codes), copied at once
    unsafe { copy_cstr(X509_verify_cert_error_string(n as c_long)).unwrap_or_default() }
}

// --- certificates ---

/// X509_NAME_digest(name, md)
pub fn x509_name_digest(name: &X509NameRef, md: MessageDigest) -> Option<Vec<u8>> {
    let mut buf = [0u8; EVP_MAX_MD_SIZE];
    let mut len: c_uint = 0;

    // SAFETY: the digest written is at most EVP_MAX_MD_SIZE bytes, the size
    // of the buffer
    if unsafe { X509_NAME_digest(name.as_ptr(), md.as_ptr(), buf.as_mut_ptr(), &mut len) } == 0 {
        return None;
    }

    Some(buf[..(len as usize).min(EVP_MAX_MD_SIZE)].to_vec())
}

/// X509_pubkey_digest(x, md): the digest of the public key bit string
pub fn x509_pubkey_digest(x: &X509Ref, md: MessageDigest) -> Option<Vec<u8>> {
    let mut buf = [0u8; EVP_MAX_MD_SIZE];
    let mut len: c_uint = 0;

    // SAFETY: as x509_name_digest()
    if unsafe { X509_pubkey_digest(x.as_ptr(), md.as_ptr(), buf.as_mut_ptr(), &mut len) } == 0 {
        return None;
    }

    Some(buf[..(len as usize).min(EVP_MAX_MD_SIZE)].to_vec())
}

/// The first OCSP responder URL of the certificate (X509_get1_ocsp()), as
/// bytes
pub fn x509_ocsp_url(x: &X509Ref) -> Option<Vec<u8>> {
    // SAFETY: a valid certificate; the stack of strings returned is owned
    // here, read and freed with X509_email_free().
    unsafe {
        let aia = X509_get1_ocsp(x.as_ptr());
        if aia.is_null() {
            return None;
        }

        let url = if OPENSSL_sk_num(aia) > 0 { copy_cstr(OPENSSL_sk_value(aia, 0) as *const c_char) } else { None };

        X509_email_free(aia);

        url
    }
}

/// X509_check_host(x, name, len, 0, NULL)
pub fn x509_check_host(x: &X509Ref, name: &[u8]) -> i32 {
    // SAFETY: a valid certificate; the name is read for its length (not
    // NUL-terminated), no peername is returned
    unsafe { X509_check_host(x.as_ptr(), name.as_ptr() as *const c_char, name.len(), 0, std::ptr::null_mut()) }
}

/// X509_STORE_add_crl(store, crl): the store takes a reference
pub fn store_add_crl(store: &mut X509StoreBuilderRef, crl: &X509CrlRef) -> bool {
    // SAFETY: a valid store (borrowed mutably) and CRL, up-referenced by the
    // store if added
    unsafe { X509_STORE_add_crl(store.as_ptr(), crl.as_ptr()) == 1 }
}

/// Which call of store_get1_issuer() failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerError {
    /// X509_STORE_CTX_new()
    New,
    /// X509_STORE_CTX_init()
    Init,
    /// X509_STORE_CTX_get1_issuer() returned -1
    Get,
}

/// X509_STORE_CTX_init(ctx, store, NULL, NULL) and
/// X509_STORE_CTX_get1_issuer(): the issuer of the certificate in the
/// store, if found
pub fn store_get1_issuer(store: &X509StoreBuilderRef, cert: &X509Ref) -> Result<Option<X509>, IssuerError> {
    // SAFETY: valid store and certificate; the store context made here is
    // freed; the issuer returned is a new reference, owned by the X509.
    unsafe {
        let ctx = X509_STORE_CTX_new();
        if ctx.is_null() {
            return Err(IssuerError::New);
        }

        if X509_STORE_CTX_init(ctx, store.as_ptr(), std::ptr::null_mut(), std::ptr::null_mut()) == 0 {
            X509_STORE_CTX_free(ctx);
            return Err(IssuerError::Init);
        }

        let mut issuer: *mut ffi::X509 = std::ptr::null_mut();

        let rc = X509_STORE_CTX_get1_issuer(&mut issuer, ctx, cert.as_ptr());

        X509_STORE_CTX_free(ctx);

        match rc {
            -1 => Err(IssuerError::Get),
            0 => Ok(None),
            _ if issuer.is_null() => Ok(None),
            _ => Ok(Some(X509::from_ptr(issuer))),
        }
    }
}

// --- SSL_CTX ---

/// SSL_CTX_set_cipher_list(ctx, s)
pub fn ctx_set_cipher_list(ctx: &mut SslContextBuilder, s: &CStr) -> bool {
    // SAFETY: a valid context, borrowed mutably; a NUL-terminated string
    unsafe { SSL_CTX_set_cipher_list(ctx.as_ptr(), s.as_ptr()) == 1 }
}

/// SSL_CTX_set1_curves_list(ctx, s) (SSL_CTX_set1_groups_list())
pub fn ctx_set1_curves_list(ctx: &mut SslContextBuilder, s: &CStr) -> bool {
    // SAFETY: as ctx_set_cipher_list(); the string is copied
    unsafe { SSL_CTX_ctrl(ctx.as_ptr(), SSL_CTRL_SET_GROUPS_LIST, 0, s.as_ptr() as *mut c_void) != 0 }
}

/// SSL_CTX_set_timeout(ctx, t): the previous timeout
pub fn ctx_set_timeout(ctx: &mut SslContextBuilder, t: i64) -> i64 {
    // SAFETY: a valid context, borrowed mutably
    unsafe { SSL_CTX_set_timeout(ctx.as_ptr(), t as c_long) as i64 }
}

/// SSL_CTX_get_timeout(ctx)
pub fn ctx_timeout(ctx: &SslContextRef) -> i64 {
    // SAFETY: a valid context
    unsafe { SSL_CTX_get_timeout(ctx.as_ptr()) as i64 }
}

/// SSL_CTX_get_options(ctx)
pub fn ctx_options(ctx: &SslContextRef) -> u64 {
    // SAFETY: a valid context
    unsafe { SSL_CTX_get_options(ctx.as_ptr()) }
}

/// SSL_CTX_set0_chain(ctx, chain): the chain of the current certificate;
/// the context takes the stack (and the references it holds) on success,
/// it is given back on failure.
pub fn ctx_set0_chain(ctx: &mut SslContextBuilder, chain: Stack<X509>) -> Result<(), Stack<X509>> {
    // SAFETY: a valid context, borrowed mutably; on success the context
    // owns the stack, which is forgotten here.
    unsafe {
        if SSL_CTX_ctrl(ctx.as_ptr(), SSL_CTRL_CHAIN, 0, chain.as_ptr() as *mut c_void) == 0 {
            return Err(chain);
        }
    }

    std::mem::forget(chain);

    Ok(())
}

/// SSL_CTX_select_current_cert(ctx, cert) and
/// SSL_CTX_get_extra_chain_certs(ctx): the extra certificates of the
/// context or, without, the chain of that certificate (copies of the
/// references); None without either.
pub fn ctx_select_cert_chain(ctx: &mut SslContextBuilder, cert: &X509Ref) -> Option<Stack<X509>> {
    // SAFETY: a valid context, borrowed mutably (the current certificate
    // changes); the stack returned belongs to the context, its elements
    // are up-referenced into a stack owned here.
    unsafe {
        SSL_CTX_ctrl(ctx.as_ptr(), SSL_CTRL_SELECT_CURRENT_CERT, 0, cert.as_ptr() as *mut c_void);

        let mut chain: *mut ffi::stack_st_X509 = std::ptr::null_mut();

        SSL_CTX_ctrl(ctx.as_ptr(), SSL_CTRL_GET_EXTRA_CHAIN_CERTS, 0, &mut chain as *mut *mut ffi::stack_st_X509 as *mut c_void);

        if chain.is_null() {
            return None;
        }

        let chain = openssl::stack::StackRef::<X509>::from_ptr(chain);

        let mut copy = Stack::new().ok()?;

        for x in chain {
            copy.push(x.to_owned()).ok()?;
        }

        Some(copy)
    }
}

/// SSL_CTX_set_verify(ctx, mode, the handler's trampoline)
pub fn ctx_set_verify<H: VerifyCallback>(ctx: &mut SslContextBuilder, mode: i32) {
    // SAFETY: a valid context, borrowed mutably; the trampoline has the
    // signature of SSL_verify_cb.
    unsafe { SSL_CTX_set_verify(ctx.as_ptr(), mode, Some(raw_verify::<H>)) }
}

/// SSL_CTX_get_verify_mode(ctx) of a context being configured
pub fn ctx_verify_mode(ctx: &SslContextBuilder) -> i32 {
    // SAFETY: a valid context; reads its mode
    unsafe { SSL_CTX_get_verify_mode(ctx.as_ptr()) }
}

/// SSL_CTX_remove_session(ctx, session): the session is removed from the
/// context's internal cache (the remove callback is called) and marked not
/// resumable.
pub fn ctx_remove_session(ctx: &SslContextRef, session: &SslSessionRef) -> bool {
    // SAFETY: valid context and session. OpenSSL looks the session id up in
    // the context's own cache, under the context's lock, and unlinks the
    // entry it finds there (an object of that cache, whatever session was
    // passed), then sets the not_resumable flag of the session passed: no
    // list of another context is touched.
    unsafe { SSL_CTX_remove_session(ctx.as_ptr(), session.as_ptr()) == 1 }
}

/// The SSL_CTX_set_tlsext_status_arg() of nginx is not needed: the status
/// callback of the crate is used.
///
/// SSL_CTX_set_info_callback(ctx, the handler's trampoline)
pub fn ctx_set_info_callback<H: InfoCallback>(ctx: &mut SslContextBuilder) {
    // SAFETY: a valid context, borrowed mutably; the trampoline has the
    // signature of the info callback.
    unsafe { SSL_CTX_set_info_callback(ctx.as_ptr(), Some(raw_info::<H>)) }
}

/// SSL_CTX_set_tlsext_servername_callback(ctx, the handler's trampoline)
pub fn ctx_set_servername_callback<H: ServernameCallback>(ctx: &mut SslContextBuilder) -> bool {
    let cb: servername_cb = raw_servername::<H>;

    // SAFETY: a valid context, borrowed mutably; SSL_CTX_callback_ctrl()
    // takes a generic function pointer, which OpenSSL calls with the
    // servername callback signature, the one of the trampoline.
    unsafe {
        let f = std::mem::transmute::<servername_cb, unsafe extern "C" fn()>(cb);
        SSL_CTX_callback_ctrl(ctx.as_ptr(), SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, Some(f)) != 0
    }
}

/// SSL_CTX_set_client_hello_cb(ctx, the handler's trampoline, NULL)
pub fn ctx_set_client_hello_callback<H: ClientHelloCallback>(ctx: &mut SslContextBuilder) {
    // SAFETY: a valid context, borrowed mutably; no argument
    unsafe { SSL_CTX_set_client_hello_cb(ctx.as_ptr(), Some(raw_client_hello::<H>), std::ptr::null_mut()) }
}

/// SSL_CTX_set_cert_cb(ctx, the handler's trampoline, NULL)
pub fn ctx_set_cert_callback<H: CertCallback>(ctx: &mut SslContextBuilder) {
    // SAFETY: a valid context, borrowed mutably; no argument
    unsafe { SSL_CTX_set_cert_cb(ctx.as_ptr(), Some(raw_cert::<H>), std::ptr::null_mut()) }
}

/// SSL_CTX_sess_set_get_cb(ctx, the handler's trampoline): the sessions are
/// returned in their DER form and made here, so that they are new sessions
/// of no context (OpenSSL may add them to the context's cache).
pub fn ctx_set_get_session_callback<H: GetSessionCallback>(ctx: &mut SslContextBuilder) {
    // SAFETY: a valid context, borrowed mutably
    unsafe { SSL_CTX_sess_set_get_cb(ctx.as_ptr(), Some(raw_get_session::<H>)) }
}

/// SSL_CTX_set_tlsext_ticket_key_cb(ctx, the handler's trampoline)
pub fn ctx_set_ticket_key_callback<H: TicketKeyCallback>(ctx: &mut SslContextBuilder) -> bool {
    let cb: ticket_key_cb = raw_ticket_key::<H>;

    // SAFETY: a valid context, borrowed mutably; SSL_CTX_callback_ctrl()
    // takes a generic function pointer, which OpenSSL calls with the ticket
    // key callback signature, the one of the trampoline.
    unsafe {
        let f = std::mem::transmute::<ticket_key_cb, unsafe extern "C" fn()>(cb);
        SSL_CTX_callback_ctrl(ctx.as_ptr(), SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB, Some(f)) != 0
    }
}

/// SSL_CONF_CTX of a context (ssl_conf_command): freed when dropped.
pub struct SslConf<'a> {
    ptr: *mut SSL_CONF_CTX,
    _ctx: PhantomData<&'a mut SslContextBuilder>,
}

impl<'a> SslConf<'a> {
    /// SSL_CONF_CTX_new(), SSL_CONF_CTX_set_flags(flags),
    /// SSL_CONF_CTX_set_ssl_ctx(ctx): None if SSL_CONF_CTX_new() failed
    pub fn new(ctx: &'a mut SslContextBuilder, flags: u32) -> Option<SslConf<'a>> {
        // SAFETY: the context is borrowed mutably as long as the SslConf,
        // which keeps its pointer and changes it.
        unsafe {
            let cctx = SSL_CONF_CTX_new();
            if cctx.is_null() {
                return None;
            }

            SSL_CONF_CTX_set_flags(cctx, flags as c_uint);
            SSL_CONF_CTX_set_ssl_ctx(cctx, ctx.as_ptr());

            Some(SslConf { ptr: cctx, _ctx: PhantomData })
        }
    }

    /// SSL_CONF_cmd_value_type(cctx, cmd)
    pub fn value_type(&mut self, cmd: &CStr) -> i32 {
        // SAFETY: a valid SSL_CONF_CTX; a NUL-terminated string
        unsafe { SSL_CONF_cmd_value_type(self.ptr, cmd.as_ptr()) }
    }

    /// SSL_CONF_cmd(cctx, cmd, value)
    pub fn cmd(&mut self, cmd: &CStr, value: &CStr) -> i32 {
        // SAFETY: a valid SSL_CONF_CTX bound to a context borrowed mutably;
        // NUL-terminated strings
        unsafe { SSL_CONF_cmd(self.ptr, cmd.as_ptr(), value.as_ptr()) }
    }

    /// SSL_CONF_CTX_finish(cctx)
    pub fn finish(&mut self) -> i32 {
        // SAFETY: as cmd()
        unsafe { SSL_CONF_CTX_finish(self.ptr) }
    }
}

impl Drop for SslConf<'_> {
    fn drop(&mut self) {
        // SAFETY: owned, not used after this
        unsafe { SSL_CONF_CTX_free(self.ptr) }
    }
}

// --- SSL: I/O ---

/// The result of an SSL I/O function: its return value, the bytes it read
/// or wrote (for the functions reporting them apart), SSL_get_error() when
/// it failed (SSL_ERROR_NONE otherwise) and errno right after the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SslIo {
    pub rc: i64,
    pub n: usize,
    pub error: i32,
    pub errno: i32,
}

/// SSL_get_error() of the call that returned rc, and errno
fn io_result(ssl: &SslRef, rc: c_int, n: usize, failed: bool) -> SslIo {
    let errno = errno();

    // SAFETY: a valid SSL; SSL_get_error() only looks at its state and at
    // the error queue
    let error = if failed { unsafe { SSL_get_error(ssl.as_ptr(), rc) } } else { SSL_ERROR_NONE };

    SslIo { rc: rc as i64, n, error, errno }
}

/// SSL_set_fd(ssl, fd): the SSL object does its I/O on the socket of that
/// number (a socket BIO without BIO_CLOSE), which is a number, not a
/// borrow: the SSL keeps it for its later I/O.
pub fn set_fd(ssl: &mut SslRef, fd: RawFd) -> bool {
    // SAFETY: a valid SSL, borrowed mutably. Any int is fine: the socket BIO
    // reads and writes the descriptor of that number with buffers OpenSSL
    // owns (a bad descriptor fails with EBADF), and never closes it.
    unsafe { SSL_set_fd(ssl.as_ptr(), fd) == 1 }
}

/// SSL_do_handshake(ssl)
pub fn do_handshake(ssl: &mut SslRef) -> SslIo {
    // SAFETY: a valid SSL, borrowed mutably for the call (the callbacks it
    // runs get the same object from OpenSSL, as in all the crate's
    // callbacks)
    let rc = unsafe { SSL_do_handshake(ssl.as_ptr()) };
    io_result(ssl, rc, 0, rc != 1)
}

/// SSL_read(ssl, buf, len)
pub fn read(ssl: &mut SslRef, buf: &mut [u8]) -> SslIo {
    let len = buf.len().min(c_int::MAX as usize) as c_int;

    // SAFETY: a valid SSL, borrowed mutably; OpenSSL writes at most len
    // bytes to buf, which has at least len bytes
    let rc = unsafe { SSL_read(ssl.as_ptr(), buf.as_mut_ptr() as *mut c_void, len) };
    io_result(ssl, rc, rc.max(0) as usize, rc <= 0)
}

/// SSL_peek(ssl, buf, len)
pub fn peek(ssl: &mut SslRef, buf: &mut [u8]) -> SslIo {
    let len = buf.len().min(c_int::MAX as usize) as c_int;

    // SAFETY: as read()
    let rc = unsafe { SSL_peek(ssl.as_ptr(), buf.as_mut_ptr() as *mut c_void, len) };
    io_result(ssl, rc, rc.max(0) as usize, rc <= 0)
}

/// SSL_write(ssl, data, len)
pub fn write(ssl: &mut SslRef, data: &[u8]) -> SslIo {
    let len = data.len().min(c_int::MAX as usize) as c_int;

    // SAFETY: a valid SSL, borrowed mutably; OpenSSL reads at most len
    // bytes of data
    let rc = unsafe { SSL_write(ssl.as_ptr(), data.as_ptr() as *const c_void, len) };
    io_result(ssl, rc, rc.max(0) as usize, rc <= 0)
}

/// SSL_read_early_data(ssl, buf, len, &readbytes): rc is
/// SSL_READ_EARLY_DATA_ERROR, _SUCCESS or _FINISH, n the bytes read
pub fn read_early_data(ssl: &mut SslRef, buf: &mut [u8]) -> SslIo {
    let mut readbytes: usize = 0;

    // SAFETY: as read(); OpenSSL writes at most buf.len() bytes
    let rc = unsafe { SSL_read_early_data(ssl.as_ptr(), buf.as_mut_ptr() as *mut c_void, buf.len(), &mut readbytes) };
    io_result(ssl, rc, readbytes.min(buf.len()), rc == SSL_READ_EARLY_DATA_ERROR)
}

/// SSL_write_early_data(ssl, data, len, &written)
pub fn write_early_data(ssl: &mut SslRef, data: &[u8]) -> SslIo {
    let mut written: usize = 0;

    // SAFETY: as write(); OpenSSL reads at most data.len() bytes
    let rc = unsafe { SSL_write_early_data(ssl.as_ptr(), data.as_ptr() as *const c_void, data.len(), &mut written) };
    io_result(ssl, rc, written, rc <= 0)
}

/// SSL_sendfile(ssl, fd, offset, size, 0) (kernel TLS), errno cleared
/// before the call (nginx checks it after a failure)
pub fn sendfile(ssl: &mut SslRef, fd: BorrowedFd<'_>, offset: i64, size: usize) -> SslIo {
    // SAFETY: the thread's errno
    unsafe { *libc::__errno_location() = 0 };

    // SAFETY: a valid SSL, borrowed mutably; the file descriptor is open for
    // the call (borrowed)
    let n = unsafe { SSL_sendfile(ssl.as_ptr(), fd.as_raw_fd(), offset as libc::off_t, size, 0) };

    let errno = errno();

    // SAFETY: as io_result()
    let error = if n < 0 { unsafe { SSL_get_error(ssl.as_ptr(), n as c_int) } } else { SSL_ERROR_NONE };

    SslIo { rc: n as i64, n: n.max(0) as usize, error, errno }
}

/// SSL_shutdown(ssl)
pub fn shutdown(ssl: &mut SslRef) -> SslIo {
    // SAFETY: a valid SSL, borrowed mutably
    let rc = unsafe { SSL_shutdown(ssl.as_ptr()) };
    io_result(ssl, rc, 0, rc != 1)
}

// --- SSL: state ---

/// SSL_want(ssl)
pub fn want(ssl: &SslRef) -> i32 {
    // SAFETY: a valid SSL; reads its state
    unsafe { SSL_want(ssl.as_ptr()) }
}

/// SSL_in_init(ssl)
pub fn in_init(ssl: &SslRef) -> bool {
    // SAFETY: a valid SSL; reads its state
    unsafe { SSL_in_init(ssl.as_ptr()) != 0 }
}

/// SSL_get_shutdown(ssl)
pub fn get_shutdown(ssl: &SslRef) -> i32 {
    // SAFETY: a valid SSL; reads its state
    unsafe { SSL_get_shutdown(ssl.as_ptr()) }
}

/// SSL_set_shutdown(ssl, mode)
pub fn set_shutdown(ssl: &mut SslRef, mode: i32) {
    // SAFETY: a valid SSL, borrowed mutably
    unsafe { SSL_set_shutdown(ssl.as_ptr(), mode) }
}

/// SSL_set_quiet_shutdown(ssl, on)
pub fn set_quiet_shutdown(ssl: &mut SslRef, on: bool) {
    // SAFETY: a valid SSL, borrowed mutably
    unsafe { SSL_set_quiet_shutdown(ssl.as_ptr(), on as c_int) }
}

/// SSL_get_options(ssl)
pub fn options(ssl: &SslRef) -> u64 {
    // SAFETY: a valid SSL; reads its options
    unsafe { SSL_get_options(ssl.as_ptr()) }
}

/// SSL_set_options(ssl, op)
pub fn set_options(ssl: &mut SslRef, op: u64) -> u64 {
    // SAFETY: a valid SSL, borrowed mutably
    unsafe { SSL_set_options(ssl.as_ptr(), op) }
}

/// SSL_clear_options(ssl, op)
pub fn clear_options(ssl: &mut SslRef, op: u64) -> u64 {
    // SAFETY: a valid SSL, borrowed mutably
    unsafe { SSL_clear_options(ssl.as_ptr(), op) }
}

/// SSL_set_verify(ssl, SSL_CTX_get_verify_mode(ctx),
/// SSL_CTX_get_verify_callback(ctx)) and SSL_set_verify_depth(ssl,
/// SSL_CTX_get_verify_depth(ctx)): the verification of another context
pub fn copy_verify(ssl: &mut SslRef, ctx: &SslContextRef) {
    // SAFETY: a valid SSL, borrowed mutably, and context. The callback of a
    // context is a function OpenSSL calls with the SSL_verify_cb arguments,
    // whatever SSL it is installed on (the trampolines of this module use
    // no data of the context).
    unsafe {
        let mode = SSL_CTX_get_verify_mode(ctx.as_ptr());
        let cb = SSL_CTX_get_verify_callback(ctx.as_ptr());

        SSL_set_verify(ssl.as_ptr(), mode, cb);
        SSL_set_verify_depth(ssl.as_ptr(), SSL_CTX_get_verify_depth(ctx.as_ptr()));
    }
}

/// SSL_set_tlsext_host_name(ssl, name): the server name of a client
pub fn set_tlsext_host_name(ssl: &mut SslRef, name: &CStr) -> bool {
    // SAFETY: a valid SSL, borrowed mutably; the name is copied
    unsafe { SSL_ctrl(ssl.as_ptr(), SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name as c_long, name.as_ptr() as *mut c_void) != 0 }
}

/// SSL_set_session(ssl, session) of a client: a session saved from an
/// earlier connection. Refused (false) for a server SSL or a context
/// keeping sessions in its internal cache, the only cases where OpenSSL
/// could link the session into a cache other than the one it may already
/// be in.
pub fn set_session(ssl: &mut SslRef, session: &SslSessionRef) -> bool {
    // SAFETY: a valid SSL, borrowed mutably, and session, which the SSL
    // up-references. As checked first, the SSL is a client one of a context
    // with SSL_SESS_CACHE_NO_INTERNAL_STORE: OpenSSL never adds the session
    // to a cache list from this SSL.
    unsafe {
        if SSL_is_server(ssl.as_ptr()) != 0 {
            return false;
        }

        let mode = SSL_CTX_ctrl(SSL_get_SSL_CTX(ssl.as_ptr()), SSL_CTRL_GET_SESS_CACHE_MODE, 0, std::ptr::null_mut()) as i64;

        if mode & SSL_SESS_CACHE_NO_INTERNAL_STORE == 0 {
            return false;
        }

        SSL_set_session(ssl.as_ptr(), session.as_ptr()) == 1
    }
}

/// SSL_set0_chain(ssl, chain): the chain of the current certificate of the
/// connection; the SSL takes the stack on success, it is given back on
/// failure.
pub fn set0_chain(ssl: &mut SslRef, chain: Stack<X509>) -> Result<(), Stack<X509>> {
    // SAFETY: a valid SSL, borrowed mutably; on success it owns the stack,
    // which is forgotten here.
    unsafe {
        if SSL_ctrl(ssl.as_ptr(), SSL_CTRL_CHAIN, 0, chain.as_ptr() as *mut c_void) == 0 {
            return Err(chain);
        }
    }

    std::mem::forget(chain);

    Ok(())
}

/// BIO_get_ktls_send(SSL_get_wbio(ssl)) == 1: kernel TLS for sending
pub fn ktls_send(ssl: &SslRef) -> bool {
    // SAFETY: a valid SSL; its write BIO, if any, is valid
    unsafe {
        let wbio = SSL_get_wbio(ssl.as_ptr());
        !wbio.is_null() && BIO_ctrl(wbio, BIO_CTRL_GET_KTLS_SEND, 0, std::ptr::null_mut()) == 1
    }
}

/// The write buffer size of the handshake: when buffering was added to the
/// write side (the read and write BIOs differ),
/// BIO_set_write_buffer_size(wbio, size), and true.
pub fn set_handshake_buffer_size(ssl: &mut SslRef, size: i64) -> bool {
    // SAFETY: a valid SSL, borrowed mutably; its BIOs are valid
    unsafe {
        let rbio = SSL_get_rbio(ssl.as_ptr());
        let wbio = SSL_get_wbio(ssl.as_ptr());

        if rbio == wbio || wbio.is_null() {
            return false;
        }

        BIO_int_ctrl(wbio, BIO_C_SET_BUFF_SIZE, size as c_long, 1);
    }

    true
}

/// SSL_SESSION_set_time(SSL_get0_session(ssl), t)
pub fn session_set_time(ssl: &mut SslRef, t: i64) -> bool {
    // SAFETY: a valid SSL, borrowed mutably; its session, if any, is valid
    // while it holds it
    unsafe {
        let sess = SSL_get_session(ssl.as_ptr());
        !sess.is_null() && SSL_SESSION_set_time(sess, t as c_long) != 0
    }
}

/// SSL_SESSION_set_timeout(SSL_get0_session(ssl), t)
pub fn session_set_timeout(ssl: &mut SslRef, t: i64) -> bool {
    // SAFETY: as session_set_time()
    unsafe {
        let sess = SSL_get_session(ssl.as_ptr());
        !sess.is_null() && SSL_SESSION_set_timeout(sess, t as c_long) != 0
    }
}

/// SSL_SESSION_set1_id_context(SSL_get0_session(ssl), "", 0): the session
/// can't be resumed anymore
pub fn session_clear_id_context(ssl: &mut SslRef) -> bool {
    // SAFETY: as session_set_time(); a zero length context
    unsafe {
        let sess = SSL_get_session(ssl.as_ptr());
        !sess.is_null() && SSL_SESSION_set1_id_context(sess, b"".as_ptr(), 0) == 1
    }
}

/// SSL_client_hello_get0_ext(ssl, type): the data of the extension, during
/// the client hello callback (None otherwise, or without the extension)
pub fn client_hello_ext(ssl: &SslRef, ty: u32) -> Option<&[u8]> {
    let mut out: *const u8 = std::ptr::null();
    let mut len: usize = 0;

    // SAFETY: a valid SSL; the data returned is the ClientHello's, kept by
    // the SSL until the processing of the ClientHello goes on, which needs
    // the SSL borrowed mutably, so not while this borrow lasts (outside the
    // callback the function returns 0).
    unsafe {
        if SSL_client_hello_get0_ext(ssl.as_ptr(), ty as c_uint, &mut out, &mut len) == 0 || out.is_null() {
            return None;
        }

        Some(std::slice::from_raw_parts(out, len))
    }
}

// --- SSL: the getters of the variables ---

/// SSL_get0_raw_cipherlist(): the size of a cipher in the list and the
/// list the client sent (None if empty)
pub fn raw_cipherlist(ssl: &SslRef) -> Option<(usize, &[u8])> {
    let mut p: *const u8 = std::ptr::null();

    // SAFETY: a valid SSL; the control only reads (the list is the SSL's
    // own buffer, valid while the SSL is not changed, which needs it
    // borrowed mutably)
    unsafe {
        let bytes = SSL_ctrl(ssl.as_ptr(), SSL_CTRL_GET_RAW_CIPHERLIST, 0, std::ptr::null_mut());
        let n = SSL_ctrl(ssl.as_ptr(), SSL_CTRL_GET_RAW_CIPHERLIST, 0, &mut p as *mut *const u8 as *mut c_void);

        if n <= 0 || bytes <= 0 || p.is_null() {
            return None;
        }

        Some((bytes as usize, std::slice::from_raw_parts(p, n as usize)))
    }
}

/// SSL_CIPHER_find(ssl, id): the cipher of the two bytes of id
pub fn cipher_find<'a>(ssl: &'a SslRef, id: &[u8]) -> Option<&'a SslCipherRef> {
    if id.len() < 2 {
        return None;
    }

    // SAFETY: a valid SSL; OpenSSL reads the 2 bytes of a TLS cipher id and
    // returns a static cipher of its tables, or NULL
    unsafe {
        let c = SSL_CIPHER_find(ssl.as_ptr(), id.as_ptr());
        if c.is_null() {
            None
        } else {
            Some(SslCipherRef::from_ptr(c as *mut ffi::SSL_CIPHER))
        }
    }
}

/// SSL_get_negotiated_group(ssl)
pub fn negotiated_group(ssl: &SslRef) -> i32 {
    // SAFETY: a valid SSL; the control only reads
    unsafe { SSL_ctrl(ssl.as_ptr(), SSL_CTRL_GET_NEGOTIATED_GROUP, 0, std::ptr::null_mut()) as i32 }
}

/// SSL_group_to_name(ssl, id)
pub fn group_to_name(ssl: &SslRef, id: i32) -> Option<Vec<u8>> {
    // SAFETY: a valid SSL; the function only reads, the name returned is
    // copied at once
    unsafe { copy_cstr(SSL_group_to_name(ssl.as_ptr(), id)) }
}

/// SSL_get1_curves(ssl): the groups the client supports
pub fn peer_curves(ssl: &SslRef) -> Vec<i32> {
    // SAFETY: a valid SSL; the control writes as many ints as it returned
    // for the count to the array, which has that many
    unsafe {
        let n = SSL_ctrl(ssl.as_ptr(), SSL_CTRL_GET_GROUPS, 0, std::ptr::null_mut());

        if n <= 0 {
            return Vec::new();
        }

        let mut curves = vec![0 as c_int; n as usize];

        let m = SSL_ctrl(ssl.as_ptr(), SSL_CTRL_GET_GROUPS, 0, curves.as_mut_ptr() as *mut c_void);

        curves.truncate(m.clamp(0, n) as usize);
        curves
    }
}

/// SSL_get_sigalgs(ssl, i, ...) of all i: the raw signature and hash bytes
/// of the client's signature algorithms
pub fn peer_sigalgs(ssl: &SslRef) -> Vec<(u8, u8)> {
    // SAFETY: a valid SSL; the function only reads, and writes the bytes
    // asked for to the variables given
    unsafe {
        let n = SSL_get_sigalgs(ssl.as_ptr(), -1, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());

        let mut v = Vec::new();

        for i in 0..n.max(0) {
            let mut rsig: u8 = 0;
            let mut rhash: u8 = 0;

            SSL_get_sigalgs(ssl.as_ptr(), i, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut rsig, &mut rhash);

            v.push((rsig, rhash));
        }

        v
    }
}

// --- the QUIC compat BIOs (ngx_event_quic_openssl_compat.c) ---

/// SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_null())): the
/// records of the peer are given to OpenSSL in a memory BIO, what it
/// writes is dropped (the message callback takes it)
pub fn set_quic_compat_bio(ssl: &mut SslRef) -> bool {
    // SAFETY: a valid SSL, borrowed mutably, which takes the BIOs made here
    unsafe {
        let rbio = BIO_new(BIO_s_mem());
        if rbio.is_null() {
            return false;
        }

        let wbio = BIO_new(BIO_s_null());
        if wbio.is_null() {
            BIO_free(rbio);
            return false;
        }

        SSL_set_bio(ssl.as_ptr(), rbio, wbio);
    }

    true
}

/// BIO_write(SSL_get_rbio(ssl), data, len)
pub fn rbio_write(ssl: &mut SslRef, data: &[u8]) -> i32 {
    if data.len() > c_int::MAX as usize {
        return -1;
    }

    // SAFETY: a valid SSL, borrowed mutably; its read BIO, if any, reads at
    // most len bytes of data
    unsafe {
        let rbio = SSL_get_rbio(ssl.as_ptr());
        if rbio.is_null() {
            return -1;
        }

        BIO_write(rbio, data.as_ptr() as *const c_void, data.len() as c_int)
    }
}

/// SSL_set_msg_callback(ssl, the handler's trampoline)
pub fn set_msg_callback<H: MsgCallback>(ssl: &mut SslRef) {
    // SAFETY: a valid SSL, borrowed mutably; the trampoline has the
    // signature of the message callback
    unsafe { SSL_set_msg_callback(ssl.as_ptr(), Some(raw_msg::<H>)) }
}

// --- callbacks ---

/// The info callback (SSL_CTX_set_info_callback()).
pub trait InfoCallback {
    fn info(ssl: &mut SslRef, where_: i32, ret: i32);
}

/// The verify callback (SSL_CTX_set_verify()): the result of the
/// verification of a certificate is given, the result returned.
pub trait VerifyCallback {
    fn verify(ok: bool, ctx: &mut X509StoreContextRef) -> bool;
}

/// The servername callback: returns an SSL_TLSEXT_ERR_* code, the alert
/// is set with SSL_TLSEXT_ERR_ALERT_FATAL.
pub trait ServernameCallback {
    fn servername(ssl: &mut SslRef, alert: &mut i32) -> i32;
}

/// The client hello callback: returns SSL_CLIENT_HELLO_SUCCESS or
/// SSL_CLIENT_HELLO_ERROR (with the alert).
pub trait ClientHelloCallback {
    fn client_hello(ssl: &mut SslRef, alert: &mut i32) -> i32;
}

/// The certificate callback (SSL_CTX_set_cert_cb()): 1, or 0 on errors.
pub trait CertCallback {
    fn cert(ssl: &mut SslRef) -> i32;
}

/// The get session callback: the DER form of the session with the id.
pub trait GetSessionCallback {
    fn get_session(ssl: &mut SslRef, id: &[u8]) -> Option<Vec<u8>>;
}

/// The session ticket key callback: returns what OpenSSL expects (-1
/// error, 0 key not found, 1 success, 2 success and renew the ticket).
pub trait TicketKeyCallback {
    fn ticket_key(ssl: &mut SslRef, keys: &mut TicketKeyCtx<'_>, enc: bool) -> i32;
}

/// The message callback (SSL_set_msg_callback()).
pub trait MsgCallback {
    fn msg(write_p: bool, version: i32, content_type: i32, buf: &[u8], ssl: &SslRef);
}

unsafe extern "C" fn raw_info<H: InfoCallback>(ssl: *const ffi::SSL, where_: c_int, ret: c_int) {
    // SAFETY: OpenSSL calls the info callback from the function processing
    // this SSL (with the SSL it was given), which is not otherwise used
    // during the call; the pointer is const by declaration only.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl as *mut ffi::SSL) };
    H::info(ssl, where_, ret);
}

unsafe extern "C" fn raw_verify<H: VerifyCallback>(ok: c_int, ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    // SAFETY: OpenSSL calls the verify callback with the store context of
    // the verification in progress
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(ctx) };
    H::verify(ok != 0, ctx) as c_int
}

unsafe extern "C" fn raw_servername<H: ServernameCallback>(ssl: *mut ffi::SSL, ad: *mut c_int, _arg: *mut c_void) -> c_int {
    // SAFETY: OpenSSL calls the callback with the SSL being processed and a
    // pointer to the alert
    let (ssl, ad) = unsafe { (SslRef::from_ptr_mut(ssl), &mut *ad) };
    H::servername(ssl, ad)
}

unsafe extern "C" fn raw_client_hello<H: ClientHelloCallback>(ssl: *mut ffi::SSL, al: *mut c_int, _arg: *mut c_void) -> c_int {
    // SAFETY: as raw_servername()
    let (ssl, al) = unsafe { (SslRef::from_ptr_mut(ssl), &mut *al) };
    H::client_hello(ssl, al)
}

unsafe extern "C" fn raw_cert<H: CertCallback>(ssl: *mut ffi::SSL, _arg: *mut c_void) -> c_int {
    // SAFETY: OpenSSL calls the callback with the SSL being processed
    let ssl = unsafe { SslRef::from_ptr_mut(ssl) };
    H::cert(ssl)
}

unsafe extern "C" fn raw_get_session<H: GetSessionCallback>(ssl: *mut ffi::SSL, data: *const u8, len: c_int, copy: *mut c_int) -> *mut ffi::SSL_SESSION {
    // SAFETY: OpenSSL calls the callback with the SSL being processed, the
    // session id (len bytes) and the copy flag to set; the session made
    // from the DER form is new, OpenSSL takes its reference (copy = 0).
    unsafe {
        *copy = 0;

        let ssl = SslRef::from_ptr_mut(ssl);
        let id = if data.is_null() || len <= 0 { &[][..] } else { std::slice::from_raw_parts(data, len as usize) };

        let der = match H::get_session(ssl, id) {
            Some(d) => d,
            None => return std::ptr::null_mut(),
        };

        if der.len() > c_long::MAX as usize {
            return std::ptr::null_mut();
        }

        let mut p = der.as_ptr();

        d2i_SSL_SESSION(std::ptr::null_mut(), &mut p, der.len() as c_long)
    }
}

/// The ciphers of a session ticket, as the ticket key callback is given
/// them: the key name, the IV, the cipher and HMAC contexts to initialize.
pub struct TicketKeyCtx<'a> {
    name: &'a mut [u8; 16],
    iv: &'a mut [u8; 16],
    ectx: *mut ffi::EVP_CIPHER_CTX,
    hctx: *mut HMAC_CTX,
}

impl TicketKeyCtx<'_> {
    /// key_name: the name of the key of the ticket (decryption), or the
    /// one to set (encryption)
    pub fn name(&self) -> &[u8; 16] {
        self.name
    }

    pub fn name_mut(&mut self) -> &mut [u8; 16] {
        self.name
    }

    /// iv: to fill for an encryption
    pub fn iv_mut(&mut self) -> &mut [u8; 16] {
        self.iv
    }

    /// EVP_EncryptInit_ex(ectx, cipher, NULL, key, iv) or
    /// EVP_DecryptInit_ex()
    pub fn cipher_init(&mut self, cipher: &CipherRef, key: &[u8], encrypt: bool) -> bool {
        if key.len() < cipher.key_length() || cipher.iv_length() > self.iv.len() {
            return false;
        }

        // SAFETY: the cipher context OpenSSL gave the callback; the cipher
        // reads key_length() bytes of key and iv_length() bytes of the IV,
        // both checked above
        unsafe {
            if encrypt {
                EVP_EncryptInit_ex(self.ectx, cipher.as_ptr(), std::ptr::null_mut(), key.as_ptr(), self.iv.as_ptr()) == 1
            } else {
                EVP_DecryptInit_ex(self.ectx, cipher.as_ptr(), std::ptr::null_mut(), key.as_ptr(), self.iv.as_ptr()) == 1
            }
        }
    }

    /// HMAC_Init_ex(hctx, key, len, md, NULL)
    pub fn hmac_init(&mut self, key: &[u8], md: &MdRef) -> bool {
        if key.len() > c_int::MAX as usize {
            return false;
        }

        // SAFETY: the HMAC context OpenSSL gave the callback; the key is
        // read for its length
        unsafe { HMAC_Init_ex(self.hctx, key.as_ptr() as *const c_void, key.len() as c_int, md.as_ptr(), std::ptr::null_mut()) == 1 }
    }
}

unsafe extern "C" fn raw_ticket_key<H: TicketKeyCallback>(ssl: *mut ffi::SSL, name: *mut u8, iv: *mut u8, ectx: *mut ffi::EVP_CIPHER_CTX, hctx: *mut HMAC_CTX, enc: c_int) -> c_int {
    // SAFETY: OpenSSL calls the callback with the SSL being processed, the
    // key name (TLSEXT_KEYNAME_LENGTH, 16 bytes), the IV buffer
    // (EVP_MAX_IV_LENGTH, 16 bytes) and the contexts to initialize, all
    // valid for the call
    unsafe {
        let ssl = SslRef::from_ptr_mut(ssl);

        let mut keys = TicketKeyCtx { name: &mut *(name as *mut [u8; 16]), iv: &mut *(iv as *mut [u8; 16]), ectx, hctx };

        H::ticket_key(ssl, &mut keys, enc == 1)
    }
}

unsafe extern "C" fn raw_msg<H: MsgCallback>(write_p: c_int, version: c_int, content_type: c_int, buf: *const c_void, len: usize, ssl: *mut ffi::SSL, _arg: *mut c_void) {
    // SAFETY: OpenSSL calls the callback with the message (len bytes) and
    // the SSL being processed
    unsafe {
        let ssl = SslRef::from_ptr(ssl);
        let data = if buf.is_null() || len == 0 { &[][..] } else { std::slice::from_raw_parts(buf as *const u8, len) };

        H::msg(write_p != 0, version, content_type, data, ssl);
    }
}

// --- the SSL object of the callback being run ---

thread_local! {
    /// The SSL objects lent by with_current() to the code they run, the
    /// innermost last.
    static CURRENT: RefCell<Vec<*mut ffi::SSL>> = const { RefCell::new(Vec::new()) };
}

/// Runs `f` with `ssl` lent to it: `current()` gives it, shared, to the
/// code `f` calls. This is for a callback evaluating nginx variables of the
/// connection (ssl_certificate with $ssl_server_name), which C reads from
/// c->ssl->connection while the SSL call making the callback is in
/// progress: the owner of the SSL object is borrowed by that call.
pub fn with_current<R>(ssl: &mut SslRef, f: impl FnOnce() -> R) -> R {
    struct Pop;

    impl Drop for Pop {
        fn drop(&mut self) {
            CURRENT.with(|c| {
                c.borrow_mut().pop();
            });
        }
    }

    CURRENT.with(|c| c.borrow_mut().push(ssl.as_ptr()));

    let _pop = Pop;

    f()
}

/// The SSL object lent by the innermost with_current() of the thread.
pub fn current<R>(f: impl FnOnce(Option<&SslRef>) -> R) -> R {
    let p = CURRENT.with(|c| c.borrow().last().copied());

    match p {
        // SAFETY: the pointer was pushed by with_current() from an
        // &mut SslRef, which stays borrowed (unused) until with_current()
        // returns, after popping it: the SSL object is valid and not
        // changed while this shared reference lives (it can't outlive f).
        Some(p) => f(Some(unsafe { SslRef::from_ptr(p) })),
        None => f(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ssl::{SslContext, SslMethod};

    #[test]
    fn error_codes() {
        // error:0A0000B9:SSL routines::no cipher match
        assert_eq!(err_get_lib(0x0A0000B9), ERR_LIB_SSL);
        assert_eq!(err_get_reason(0x0A0000B9), 0xB9);

        let e = ERR_SYSTEM_FLAG | 2;
        assert_eq!(err_get_lib(e), ERR_LIB_SYS);
        assert_eq!(err_get_reason(e), 2);
    }

    #[test]
    fn error_queue() {
        init_ssl();
        err_clear_error();

        assert!(Bio::new_file(c"/nonexistent/file.pem", c"r").is_none());

        let (e, data) = err_peek_error_data();
        assert_ne!(e, 0);
        assert_eq!(err_get_lib(e), ERR_LIB_SYS);
        assert!(data.unwrap().starts_with(b"calling fopen("));

        let s = err_error_string_n(e, 1024);
        assert!(s.starts_with(b"error:80000002:system library::"), "{}", String::from_utf8_lossy(&s));

        // the minimal format when the text does not fit
        assert!(err_error_string_n(e, 16).starts_with(b"err:"));

        assert_eq!(err_get_error(), e);
        err_clear_error();
        assert_eq!(err_peek_error(), 0);
    }

    #[test]
    fn pem_reads() {
        let key = openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap()).unwrap()).unwrap();
        let pem = key.private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_128_cbc(), b"secret").unwrap();

        let mut bio = Bio::new_mem_buf(&pem).unwrap();

        let mut tries = 0;
        let mut cb = |buf: &mut [u8], rwflag: bool| -> usize {
            assert!(!rwflag);
            tries += 1;
            let p: &[u8] = if tries == 1 { b"wrong" } else { b"secret" };
            buf[..p.len()].copy_from_slice(p);
            p.len()
        };

        assert!(pem_read_private_key(&mut bio, Some(&mut cb)).is_none());
        err_clear_error();
        bio.reset();
        assert!(pem_read_private_key(&mut bio, Some(&mut cb)).is_some());

        let mut bio = Bio::new_mem_buf(b"junk").unwrap();
        assert!(pem_read_x509(&mut bio).is_none());
        assert_eq!(err_get_reason(err_peek_last_error()), PEM_R_NO_START_LINE);
        err_clear_error();
    }

    #[test]
    fn context_settings() {
        let mut b = SslContext::builder(SslMethod::tls()).unwrap();

        assert!(ctx_set_cipher_list(&mut b, c"HIGH"));
        assert!(!ctx_set_cipher_list(&mut b, c"NO-SUCH-CIPHER"));
        assert_ne!(err_peek_error(), 0);
        err_clear_error();

        ctx_set_timeout(&mut b, 123);
        assert_eq!(ctx_timeout(&b.build()), 123);
        let mut b = SslContext::builder(SslMethod::tls()).unwrap();

        assert!(ctx_set1_curves_list(&mut b, c"X25519:prime256v1"));

        let mut conf = SslConf::new(&mut b, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER).unwrap();
        assert_eq!(conf.cmd(c"Options", c"-SessionTicket"), 2);
        assert_eq!(conf.finish(), 1);
        drop(conf);

        assert_ne!(ctx_options(&b.build()) & SSL_OP_NO_TICKET, 0);
    }

    #[test]
    fn current_ssl() {
        let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
        let mut ssl = openssl::ssl::Ssl::new(&ctx).unwrap();
        ssl.set_connect_state();

        assert!(current(|s| s.is_none()));

        let server = with_current(&mut ssl, || current(|s| s.map(|s| s.is_server())));
        assert_eq!(server, Some(false));

        // nested, and after a panic
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| with_current(&mut ssl, || panic!("x"))));
        assert!(r.is_err());

        assert!(current(|s| s.is_none()));
    }
}
