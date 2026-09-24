use ngx_core::open_file_cache::*;
use ngx_core::log::Log;

#[test]
fn test_only_existing_file() {
    std::fs::write("/tmp/ofc_test_file", b"hello").unwrap();
    let log = Log::stderr(8);
    let mut of = OpenFileInfo::default();
    of.test_only = true;
    of.valid = 60;
    of.min_uses = 1;
    let r = open_cached_file(None, b"/tmp/ofc_test_file", &mut of, &log);
    assert!(r.is_ok(), "err {} {}", of.err, of.failed);
    assert!(of.is_file);
    assert_eq!(of.size, 5);
    let mut of2 = OpenFileInfo::default();
    of2.valid = 60;
    of2.min_uses = 1;
    let r = open_cached_file(None, b"/tmp/ofc_test_file", &mut of2, &log);
    assert!(r.is_ok());
    assert!(of2.fd >= 0);
    let mut of3 = OpenFileInfo::default();
    of3.test_dir = true;
    of3.test_only = true;
    let r = open_cached_file(None, b"/tmp", &mut of3, &log);
    assert!(r.is_ok());
    assert!(of3.is_dir);
}
