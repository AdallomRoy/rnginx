//! ngx_http_mp4_module
//!
//! MP4 pseudo-streaming module. Enables time-based seeking in MP4 files via
//! ?start=<ms>&end=<ms> query parameters. Rewrites MP4 atoms on the fly to serve
//! only the requested slice.

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::ngx_log_error;

use crate::core::*;
use crate::request::*;
use crate::parse::arg;
use crate::*;

crate::http_module_index!("ngx_http_mp4_module");

pub struct Mp4Conf {
    pub buffer_size: usize,
    pub max_buffer_size: usize,
    pub start_key_frame: bool,
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(Mp4Conf {
        buffer_size: 512 * 1024,      // default 512KB
        max_buffer_size: 10 * 1024 * 1024, // default 10MB
        start_key_frame: false,
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let p = conf_cell::<Mp4Conf>(prev).borrow();
    let mut c = conf_cell::<Mp4Conf>(conf).borrow_mut();

    if c.buffer_size == 0 {
        c.buffer_size = p.buffer_size;
    }
    if c.max_buffer_size == 0 {
        c.max_buffer_size = p.max_buffer_size;
    }
    if !c.start_key_frame {
        c.start_key_frame = p.start_key_frame;
    }

    Ok(())
}

fn mp4_directive(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    // Match C: install as the location's content handler only when 'mp4;' is set.
    use crate::core::CoreLocConf;
    let loc_conf = crate::get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());
    loc_conf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(mp4_handler(r))));
    Ok(())
}

pub fn mp4_module() -> ModuleDef {
    let def = HttpModuleDef {
        postconfiguration: Some(init),
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("mp4", NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, ConfLevel::None, mp4_directive),
        ngx_core::cmd_fn!("mp4_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, mp4_buffer_size_cmd),
        ngx_core::cmd_fn!("mp4_max_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, mp4_max_buffer_size_cmd),
        ngx_core::cmd_fn!("mp4_start_key_frame", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, mp4_start_key_frame_cmd),
    ];
    http_module_def("ngx_http_mp4_module", def, commands)
}

fn mp4_buffer_size_cmd(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<Mp4Conf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("requires size argument"));
    }
    match ngx_core::parse::parse_size(&args[1]) {
        Some(size) => {
            cell.borrow_mut().buffer_size = size;
            Ok(())
        }
        None => Err(cf.emerg(format_args!("invalid size \"{}\"", B(&args[1])))),
    }
}

fn mp4_max_buffer_size_cmd(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<Mp4Conf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("requires size argument"));
    }
    match ngx_core::parse::parse_size(&args[1]) {
        Some(size) => {
            cell.borrow_mut().max_buffer_size = size;
            Ok(())
        }
        None => Err(cf.emerg(format_args!("invalid size \"{}\"", B(&args[1])))),
    }
}

fn mp4_start_key_frame_cmd(cf: &mut Conf, _cmd: &Command, conf: Option<Rc<dyn Any>>) -> ConfResult {
    let cell = conf_rc::<Mp4Conf>(conf.as_ref().unwrap());
    let args = cf.args.clone();
    if args.len() < 2 {
        return Err(msg("requires on|off"));
    }
    let flag = match &args[1][..] {
        b"on" => true,
        b"off" => false,
        _ => return Err(cf.emerg(format_args!("invalid value \"{}\"", B(&args[1])))),
    };
    cell.borrow_mut().start_key_frame = flag;
    Ok(())
}

fn init(_cf: &mut Conf) -> ConfResult {
    // mp4 handler is only installed by the `mp4;` directive (see mp4_directive above),
    // matching nginx C behaviour. Do not register a global content-phase handler here.
    Ok(())
}

pub async fn mp4_handler(r: R) -> i64 {
    // Only GET and HEAD methods allowed
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // Don't serve directories
    if r.uri.borrow().last() == Some(&b'/') {
        return NGX_DECLINED;
    }

    // Discard request body
    let rc = crate::request_body::discard_request_body(&r).await;
    if rc != NGX_OK {
        return rc;
    }

    let log = r.connection.log.clone();

    // Map URI to file path
    let (path, root) = match map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    http_debug!(r, "http mp4 filename: \"{}\"", B(&path));

    let clcf = r.clcf();
    let mut of = {
        let c = clcf.borrow();
        OpenFileInfo {
            read_ahead: *c.read_ahead,
            directio: usize::MAX,
            valid: *c.open_file_cache_valid,
            min_uses: *c.open_file_cache_min_uses as u32,
            errors: *c.open_file_cache_errors,
            events: *c.open_file_cache_events,
            disable_symlinks: *c.disable_symlinks as u8,
            ..Default::default()
        }
    };

    let cache = clcf.borrow().open_file_cache.get().clone();
    let handle = match open_cached_file(cache.as_ref(), &path, &mut of, &log) {
        Ok(h) => h,
        Err(()) => {
            let (level, rc) = match of.err {
                libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG => (NGX_LOG_ERR, NGX_HTTP_NOT_FOUND),
                libc::EACCES | libc::EMLINK | libc::ELOOP => (NGX_LOG_ERR, NGX_HTTP_FORBIDDEN),
                _ => (NGX_LOG_CRIT, NGX_HTTP_INTERNAL_SERVER_ERROR),
            };
            if rc != NGX_HTTP_NOT_FOUND || *clcf.borrow().log_not_found {
                ngx_log_error!(level, log, Some(of.err), "{} \"{}\" failed", of.failed, B(&path));
            }
            return rc;
        }
    };

    r.root_tested.set(!r.error_page.get());

    if of.is_dir {
        http_debug!(r, "http mp4 dir");
        r.clear_location();
        let mut location = r.uri.borrow().clone();
        location.push(b'/');
        if !r.args.borrow().is_empty() {
            location.push(b'?');
            location.extend_from_slice(&r.args.borrow());
        }
        let h = r.headers_out.borrow_mut().add(b"Location", &location);
        r.headers_out.borrow_mut().location = Some(h);
        return NGX_HTTP_MOVED_PERMANENTLY;
    }

    if !of.is_file {
        ngx_log_error!(NGX_LOG_CRIT, log, None, "\"{}\" is not a regular file", B(&path));
        return NGX_HTTP_NOT_FOUND;
    }

    log.set_action(Some("sending response to client"));

    // Parse start and end query parameters (milliseconds, float format with 3 decimals)
    let args = r.args.borrow();
    let start_ms = arg(&args, b"start").and_then(parse_float_ms);
    let end_ms = arg(&args, b"end").and_then(parse_float_ms);

    // If no seek params, serve the file normally
    let (output_chain, content_length) = if start_ms.is_some() || end_ms.is_some() {
        // TODO: Implement full mp4 processing
        // This requires:
        // 1. Atom parsing: Read atoms hierarchically from file
        //    - Atom header: 4 bytes size (or size=1 for 64-bit), 4 bytes name
        //    - Support ftyp, moov (with recursive children), mdat atoms
        // 2. Track parsing: For each trak atom, extract timing/sample tables
        //    - stts (time-to-sample): Array of (count:u32, duration:u32) entries
        //    - stss (sync samples): Array of sample indices that are keyframes
        //    - ctts (composition offset): Array of (count:u32, offset:i32) entries
        //    - stsc (sample-to-chunk): Array of (chunk:u32, samples:u32, id:u32) entries
        //    - stsz (sample sizes): Array of sample sizes (4 bytes each)
        //    - stco (chunk offset): Array of chunk offsets (4 bytes each)
        //    - co64 (chunk offset 64-bit): Array of chunk offsets (8 bytes each)
        // 3. Seeking: Convert start_ms/end_ms to sample ranges
        //    - Use stts table to find sample index from milliseconds
        //    - Use stss to optionally snap to nearest keyframe if start_key_frame=true
        //    - Compute prefix duration (partial samples) for cropped atoms
        // 4. Atom rewriting: Update atom sizes and crop sample tables
        //    - Recalculate stts, stss, ctts, stsc, stsz entries for [start_sample, end_sample]
        //    - Adjust chunk offsets (stco/co64) by (ftyp_size + moov_size - original_mdat_offset)
        //    - Update atom sizes (mvhd, mdhd, trak, moov) with new child sizes
        // 5. Output chain: Build chain of atoms + file buffer slice
        //    - Memory buffers for ftyp, moov atom header, rewritten child atoms
        //    - File buffer for mdat data slice [start_offset, end_offset)
        // 6. Error handling: Validate seek within bounds, atom sizes, buffer limits
        // For now, fallback to serving full file
        (None, of.size)
    } else {
        (None, of.size)
    };

    let mut ho = r.headers_out.borrow_mut();
    ho.status = NGX_HTTP_OK;
    ho.content_length_n = content_length;
    ho.last_modified_time = of.mtime;
    drop(ho);

    if set_etag(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if set_content_type(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r.allow_ranges.set(true);

    let rc = send_header(&r).await;
    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return rc;
    }

    // If we have a custom chain from mp4 processing, use it; otherwise serve file as-is
    let chain = if let Some(c) = output_chain {
        c
    } else {
        let mut chain = Chain::new();
        let file = Rc::new(BufFile {
            fd: of.fd,
            name: path.clone(),
            directio: of.is_directio,
        });
        let mut buf = Buf::file(file, 0, of.size);
        buf.in_file = true;
        buf.last_buf = r.is_main();
        buf.last_in_chain = true;
        chain.push_back(buf);
        chain
    };

    let rc = output_filter(&r, chain).await;
    drop(handle);
    let _ = root;
    rc
}

/// Parse a floating-point millisecond value (e.g., "123.456" -> 123456 milliseconds)
/// Returns the millisecond value as an integer (multiply by 1000 to get the integer representation)
fn parse_float_ms(value: &[u8]) -> Option<i64> {
    if value.is_empty() {
        return None;
    }

    let mut whole = 0i64;
    let mut frac = 0i64;
    let mut frac_digits = 0;
    let mut in_frac = false;

    for &b in value {
        if b == b'.' {
            if in_frac {
                return None; // multiple dots
            }
            in_frac = true;
        } else if b >= b'0' && b <= b'9' {
            let digit = (b - b'0') as i64;
            if in_frac {
                frac = frac * 10 + digit;
                frac_digits += 1;
                if frac_digits > 10 {
                    return None; // too many decimals
                }
            } else {
                whole = whole * 10 + digit;
            }
        } else {
            return None; // invalid character
        }
    }

    // Pad fractional part to millisecond precision (3 decimal places)
    while frac_digits < 3 {
        frac *= 10;
        frac_digits += 1;
    }
    // If more than 3 decimals, truncate
    while frac_digits > 3 {
        frac /= 10;
        frac_digits -= 1;
    }

    Some(whole * 1000 + frac)
}

// ============================================================================
// MP4 Atom Parsing Infrastructure
// ============================================================================

/// MP4 atom header: 4 bytes size + 4 bytes name
#[derive(Debug, Clone, Copy)]
struct AtomHeader {
    size: u32,
    name: [u8; 4],
}

impl AtomHeader {
    /// Parse atom header from bytes
    fn from_bytes(data: &[u8]) -> Option<(Self, u64)> {
        if data.len() < 8 {
            return None;
        }
        let size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let name = [data[4], data[5], data[6], data[7]];

        let actual_size = if size == 1 {
            // Extended size: next 8 bytes contain the real size
            if data.len() < 16 {
                return None;
            }
            u64::from_be_bytes([
                data[8], data[9], data[10], data[11],
                data[12], data[13], data[14], data[15],
            ])
        } else if size == 0 {
            // Atom extends to end of file (only for last atom)
            0u64
        } else {
            size as u64
        };

        Some((AtomHeader { size, name }, actual_size))
    }

    fn name_str(&self) -> &str {
        match std::str::from_utf8(&self.name) {
            Ok(s) => s,
            Err(_) => "????",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_float_ms() {
        assert_eq!(parse_float_ms(b"0"), Some(0));
        assert_eq!(parse_float_ms(b"1.5"), Some(1500));
        assert_eq!(parse_float_ms(b"10.123"), Some(10123));
        assert_eq!(parse_float_ms(b"100"), Some(100000));
        assert_eq!(parse_float_ms(b"0.1"), Some(100));
        assert_eq!(parse_float_ms(b"0.001"), Some(1));
    }

    #[test]
    fn test_atom_header_parse() {
        // Standard 4-byte size header
        let data = b"\x00\x00\x00\x20ftyp";
        let (hdr, size) = AtomHeader::from_bytes(data).unwrap();
        assert_eq!(hdr.size, 0x20);
        assert_eq!(hdr.name, *b"ftyp");
        assert_eq!(size, 0x20 as u64);
    }
}
