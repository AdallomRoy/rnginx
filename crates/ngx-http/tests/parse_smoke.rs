use ngx_http::parse::*;

fn line(s: &[u8]) -> (i64, ParseRequest, usize) {
    let mut r = ParseRequest::default();
    let mut pos = 0;
    let rc = parse_request_line(&mut r, s, &mut pos);
    (rc, r, pos)
}

#[test]
fn request_line_then_headers() {
    let buf = b"GET /two.txt HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let (rc, r, pos) = line(buf);
    assert_eq!(rc, 0, "rc");
    assert_eq!(&buf[r.request_start..r.request_end], b"GET /two.txt HTTP/1.1");
    assert_eq!(pos, 23);
    assert_eq!(r.method, NGX_HTTP_GET);
    assert_eq!(r.http_version, 1001);
    assert_eq!(&buf[r.uri_start.unwrap()..r.uri_end.unwrap()], b"/two.txt");
    assert_eq!(r.uri_ext.map(|x| &buf[x..r.uri_end.unwrap()]), Some(&b"txt"[..]));
    // now headers
    let mut p = pos;
    let rc = parse_header_line(&mut { let mut x = r; x.state = 0; x }, buf, &mut p, false);
    assert_eq!(rc, 0);
}

#[test]
fn request_line_09() {
    let buf = b"GET /two.txt\r\n";
    let (rc, r, pos) = line(buf);
    assert_eq!(rc, 0);
    assert_eq!(r.http_version, 9);
    assert_eq!(pos, buf.len());
    assert_eq!(&buf[r.uri_start.unwrap()..r.uri_end.unwrap()], b"/two.txt");
}

#[test]
fn request_line_incremental() {
    let buf = b"GET / HTTP/1.0\r\n";
    let mut r = ParseRequest::default();
    let mut pos = 0;
    let mut rc = -2;
    for end in 1..=buf.len() {
        rc = parse_request_line(&mut r, &buf[..end], &mut pos);
        if rc != -2 { break; }
    }
    assert_eq!(rc, 0);
    assert_eq!(&buf[r.request_start..r.request_end], b"GET / HTTP/1.0");
}
