use ngx_http::parse::*;

#[test]
fn test_parse_request_line_get_http11() {
    let buf = b"GET /index.html HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_GET);
    assert_eq!(r.http_major, 1);
    assert_eq!(r.http_minor, 1);
    assert_eq!(r.http_version, 1001);
    assert_eq!(r.uri_start, Some(4));
    assert_eq!(r.uri_end, Some(15));
    assert_eq!(pos, 26);
}

#[test]
fn test_parse_request_line_post_http10() {
    let buf = b"POST /api/data HTTP/1.0\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_POST);
    assert_eq!(r.http_version, 1000);
}

#[test]
fn test_parse_request_line_head() {
    let buf = b"HEAD /file.txt HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_HEAD);
}

#[test]
fn test_parse_request_line_delete() {
    let buf = b"DELETE /resource HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_DELETE);
}

#[test]
fn test_parse_request_line_put() {
    let buf = b"PUT /data HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_PUT);
}

#[test]
fn test_parse_request_line_options() {
    let buf = b"OPTIONS /path HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_OPTIONS);
}

#[test]
fn test_parse_request_line_connect() {
    let buf = b"CONNECT host:443 HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_CONNECT);
}

#[test]
fn test_parse_request_line_patch() {
    let buf = b"PATCH /api HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_PATCH);
}

#[test]
fn test_parse_request_line_trace() {
    let buf = b"TRACE / HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_TRACE);
}

#[test]
fn test_parse_request_line_with_query() {
    let buf = b"GET /path?query=value HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.args_start, Some(11));
}

#[test]
fn test_parse_request_line_with_extension() {
    let buf = b"GET /path/file.html HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.uri_ext, Some(23));
}

#[test]
fn test_parse_request_line_http09_get() {
    let buf = b"GET /path\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.http_version, 9);
}

#[test]
fn test_parse_request_line_invalid_method() {
    let buf = b"get /path HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, NGX_HTTP_PARSE_INVALID_METHOD);
}

#[test]
fn test_parse_request_line_invalid_version() {
    let buf = b"GET /path HTTP/9.9\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, NGX_HTTP_PARSE_INVALID_VERSION);
}

#[test]
fn test_parse_request_line_incomplete() {
    let buf = b"GET /path HTTP/1.1\r";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_AGAIN);
}

#[test]
fn test_parse_request_line_lf_only() {
    let buf = b"GET /path HTTP/1.1\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
}

#[test]
fn test_parse_header_line_simple() {
    let buf = b"Host: example.com\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_header_line(&mut r, buf, &mut pos, false);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.header_name_start, 0);
    assert_eq!(r.header_name_end, 4);
    assert_eq!(r.header_start, 6);
    assert_eq!(r.header_end, 17);
}

#[test]
fn test_parse_header_line_with_underscores_allowed() {
    let buf = b"X_Custom_Header: value\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_header_line(&mut r, buf, &mut pos, true);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
}

#[test]
fn test_parse_header_line_with_underscores_disallowed() {
    let buf = b"X_Custom_Header: value\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_header_line(&mut r, buf, &mut pos, false);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.invalid_header, true);
}

#[test]
fn test_parse_header_line_empty_line() {
    let buf = b"\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_header_line(&mut r, buf, &mut pos, false);

    assert_eq!(rc, NGX_HTTP_PARSE_HEADER_DONE);
}

#[test]
fn test_parse_header_line_lf_only() {
    let buf = b"\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_header_line(&mut r, buf, &mut pos, false);

    assert_eq!(rc, NGX_HTTP_PARSE_HEADER_DONE);
}

#[test]
fn test_arg_found() {
    let args = b"foo=bar&baz=qux";
    let result = arg(args, b"foo");
    assert_eq!(result, Some(&b"bar"[..]));
}

#[test]
fn test_arg_not_found() {
    let args = b"foo=bar&baz=qux";
    let result = arg(args, b"notfound");
    assert_eq!(result, None);
}

#[test]
fn test_arg_last_param() {
    let args = b"foo=bar&baz=qux";
    let result = arg(args, b"baz");
    assert_eq!(result, Some(&b"qux"[..]));
}

#[test]
fn test_split_args_with_query() {
    let uri = b"/path?arg1=val1&arg2=val2";
    let (path, args) = split_args(uri);
    assert_eq!(path, &b"/path"[..]);
    assert_eq!(args, &b"arg1=val1&arg2=val2"[..]);
}

#[test]
fn test_split_args_no_query() {
    let uri = b"/path/to/file";
    let (path, args) = split_args(uri);
    assert_eq!(path, &b"/path/to/file"[..]);
    assert_eq!(args, &b""[..]);
}

#[test]
fn test_status_line_http11_200() {
    let buf = b"HTTP/1.1 200 OK\r\n";
    let mut status = Status::default();
    let mut pos = 0;

    let rc = parse_status_line(buf, &mut pos, &mut status);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(status.code, 200);
    assert_eq!(status.http_version, 1001);
}

#[test]
fn test_status_line_http10_404() {
    let buf = b"HTTP/1.0 404 Not Found\r\n";
    let mut status = Status::default();
    let mut pos = 0;

    let rc = parse_status_line(buf, &mut pos, &mut status);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(status.code, 404);
    assert_eq!(status.http_version, 1000);
}

#[test]
fn test_mkcol() {
    let buf = b"MKCOL /col HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_MKCOL);
}

#[test]
fn test_propfind() {
    let buf = b"PROPFIND /col HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.method, NGX_HTTP_PROPFIND);
}

#[test]
fn test_uri_with_double_slash() {
    let buf = b"GET /path//to//file HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.complex_uri, true);
}

#[test]
fn test_uri_with_dotdot() {
    let buf = b"GET /path/../file HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.complex_uri, true);
}

#[test]
fn test_uri_with_percent() {
    let buf = b"GET /path%20with%20spaces HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.quoted_uri, true);
}

#[test]
fn test_uri_with_plus() {
    let buf = b"GET /path+with+plus HTTP/1.1\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;

    let rc = parse_request_line(&mut r, buf, &mut pos);

    assert_eq!(rc, ngx_core::rc::NGX_OK);
    assert_eq!(r.plus_in_uri, true);
}
