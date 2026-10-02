//! ngx_http_mp4_module
//!
//! Pseudo-streaming of MP4 files: the "start" and "end" arguments (seconds,
//! milliseconds after the dot) crop the file to that time range, with the
//! moov atom rebuilt for the samples sent and put before the mdat data.
//!
//! The module works in the memory it reads the atoms into, as C does in the
//! request pool: the atoms kept for the response are buffers pointing into
//! it, and the atoms are updated in place. The C pointers are offsets into
//! that memory (Mem), 0 being NULL.

use std::any::Any;
use std::rc::Rc;

use ngx_core::buf::{Buf, BufFile, Chain};
use ngx_core::conf::*;
use ngx_core::log::*;
use ngx_core::module::ModuleDef;
use ngx_core::open_file_cache::*;
use ngx_core::rc::*;
use ngx_core::string::B;
use ngx_core::{ngx_log_debug, ngx_log_error};

use crate::core::*;
use crate::request::*;
use crate::parse::arg;
use crate::*;

crate::http_module_index!("ngx_http_mp4_module");

const NGX_HTTP_MP4_TRAK_ATOM: usize = 0;
const NGX_HTTP_MP4_TKHD_ATOM: usize = 1;
const NGX_HTTP_MP4_EDTS_ATOM: usize = 2;
const NGX_HTTP_MP4_ELST_ATOM: usize = 3;
const NGX_HTTP_MP4_MDIA_ATOM: usize = 4;
const NGX_HTTP_MP4_MDHD_ATOM: usize = 5;
const NGX_HTTP_MP4_HDLR_ATOM: usize = 6;
const NGX_HTTP_MP4_MINF_ATOM: usize = 7;
const NGX_HTTP_MP4_VMHD_ATOM: usize = 8;
const NGX_HTTP_MP4_SMHD_ATOM: usize = 9;
const NGX_HTTP_MP4_DINF_ATOM: usize = 10;
const NGX_HTTP_MP4_STBL_ATOM: usize = 11;
const NGX_HTTP_MP4_STSD_ATOM: usize = 12;
const NGX_HTTP_MP4_STTS_ATOM: usize = 13;
const NGX_HTTP_MP4_STTS_DATA: usize = 14;
const NGX_HTTP_MP4_STSS_ATOM: usize = 15;
const NGX_HTTP_MP4_STSS_DATA: usize = 16;
const NGX_HTTP_MP4_CTTS_ATOM: usize = 17;
const NGX_HTTP_MP4_CTTS_DATA: usize = 18;
const NGX_HTTP_MP4_STSC_ATOM: usize = 19;
const NGX_HTTP_MP4_STSC_START: usize = 20;
const NGX_HTTP_MP4_STSC_DATA: usize = 21;
const NGX_HTTP_MP4_STSC_END: usize = 22;
const NGX_HTTP_MP4_STSZ_ATOM: usize = 23;
const NGX_HTTP_MP4_STSZ_DATA: usize = 24;
const NGX_HTTP_MP4_STCO_ATOM: usize = 25;
const NGX_HTTP_MP4_STCO_DATA: usize = 26;
const NGX_HTTP_MP4_CO64_ATOM: usize = 27;
const NGX_HTTP_MP4_CO64_DATA: usize = 28;

const NGX_HTTP_MP4_LAST_ATOM: usize = NGX_HTTP_MP4_CO64_DATA;

const NGX_MAX_OFF_T_VALUE: i64 = i64::MAX;
const NGX_MAX_UINT32_VALUE: u64 = 0xffff_ffff;

/// ngx_http_mp4_conf_t
pub struct Mp4Conf {
    buffer_size: Val<usize>,
    max_buffer_size: Val<usize>,
    start_key_frame: Val<bool>,
}

/// sizeof(ngx_mp4_atom_header_t) and sizeof(ngx_mp4_atom_header64_t)
const ATOM_HEADER: usize = 8;
const ATOM_HEADER64: usize = 16;

/// The offsets of the fields every atom struct starts with: size[4],
/// name[4], and for the full atoms version[1], flags[3]; the tables have
/// entries[4] after them.
const ATOM_VERSION: usize = 8;
const ATOM_ENTRIES: usize = 12;

/// ngx_mp4_mvhd_atom_t, ngx_mp4_mvhd64_atom_t: sizeof() and the offsets of
/// the fields used; likewise for the other atoms.
mod mvhd {
    pub const SIZEOF: usize = 108;
    pub const TIMESCALE: usize = 20;
    pub const DURATION: usize = 24;
}

mod mvhd64 {
    pub const SIZEOF: usize = 120;
    pub const TIMESCALE: usize = 28;
    pub const DURATION: usize = 32;
}

mod tkhd {
    pub const SIZEOF: usize = 92;
    pub const DURATION: usize = 28;
}

mod tkhd64 {
    pub const SIZEOF: usize = 104;
    pub const DURATION: usize = 36;
}

mod mdhd {
    pub const SIZEOF: usize = 32;
    pub const TIMESCALE: usize = 20;
    pub const DURATION: usize = 24;
}

mod mdhd64 {
    pub const SIZEOF: usize = 44;
    pub const TIMESCALE: usize = 28;
    pub const DURATION: usize = 32;
}

mod stsd {
    pub const SIZEOF: usize = 24;
    pub const MEDIA_NAME: usize = 20;
}

/// ngx_mp4_stts_atom_t, and the ngx_mp4_stss/ctts/stsc/stco/co64 ones
const TABLE_ATOM_SIZEOF: usize = 16;

mod stsz {
    pub const SIZEOF: usize = 20;
    pub const UNIFORM_SIZE: usize = 12;
    pub const ENTRIES: usize = 16;
}

/// ngx_mp4_edts_atom_t
const EDTS_ATOM_SIZEOF: usize = 8;

/// ngx_mp4_elst_atom_t
mod elst {
    pub const SIZEOF: usize = 36;
    pub const FLAGS: usize = 9;
    pub const DURATION: usize = 16;
    pub const MEDIA_TIME: usize = 24;
    pub const MEDIA_RATE: usize = 32;
    pub const RESERVED: usize = 34;
}

/// ngx_mp4_stts_entry_t: count[4], duration[4]; ngx_mp4_ctts_entry_t:
/// count[4], offset[4]
const STTS_ENTRY_SIZEOF: usize = 8;
const CTTS_ENTRY_SIZEOF: usize = 8;

/// ngx_mp4_stsc_entry_t: chunk[4], samples[4], id[4]
const STSC_ENTRY_SIZEOF: usize = 12;
const STSC_SAMPLES: usize = 4;
const STSC_ID: usize = 8;

/// ngx_mp4_atom_data_size()
const fn atom_data_size_of(sizeof: usize) -> u64 {
    (sizeof - ATOM_HEADER) as u64
}

fn create_conf(_cf: &mut Conf) -> Rc<dyn Any> {
    make_slot(Mp4Conf {
        buffer_size: Val::unset(),
        max_buffer_size: Val::unset(),
        start_key_frame: Val::unset(),
    })
}

fn merge_conf(_cf: &mut Conf, prev: &Rc<dyn Any>, conf: &Rc<dyn Any>) -> ConfResult {
    let prev = conf_cell::<Mp4Conf>(prev).borrow();
    let mut conf = conf_cell::<Mp4Conf>(conf).borrow_mut();

    conf.buffer_size.merge(&prev.buffer_size, 512 * 1024);
    conf.max_buffer_size.merge(&prev.max_buffer_size, 10 * 1024 * 1024);
    conf.start_key_frame.merge(&prev.start_key_frame, false);

    Ok(())
}

/// ngx_http_mp4
fn mp4(cf: &mut Conf, _cmd: &Command, _conf: Option<Rc<dyn Any>>) -> ConfResult {
    let clcf = crate::get_loc_conf::<CoreLocConf>(cf, crate::core::ctx_index());
    clcf.borrow_mut().handler = Some(Rc::new(|r| Box::pin(mp4_handler(r))));
    Ok(())
}

pub fn mp4_module() -> ModuleDef {
    let def = HttpModuleDef {
        create_loc_conf: Some(create_conf),
        merge_loc_conf: Some(merge_conf),
        ..Default::default()
    };
    let commands = vec![
        ngx_core::cmd_fn!("mp4", NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, ConfLevel::None, mp4),
        ngx_core::cmd!("mp4_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, Mp4Conf, buffer_size, set_size),
        ngx_core::cmd!("mp4_max_buffer_size", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, ConfLevel::Loc, Mp4Conf, max_buffer_size, set_size),
        ngx_core::cmd!("mp4_start_key_frame", NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ConfLevel::Loc, Mp4Conf, start_key_frame, set_flag),
    ];
    http_module_def("ngx_http_mp4_module", def, commands)
}

/// ngx_http_mp4_handler
pub async fn mp4_handler(r: R) -> i64 {
    if r.method.get() & (NGX_HTTP_GET | NGX_HTTP_HEAD) == 0 {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if r.uri.borrow().last() == Some(&b'/') {
        return NGX_DECLINED;
    }

    let rc = crate::request_body::discard_request_body(&r).await;

    if rc != NGX_OK {
        return rc;
    }

    let (path, root) = match map_uri_to_path(&r, 0) {
        Some(p) => p,
        None => return NGX_HTTP_INTERNAL_SERVER_ERROR,
    };

    let log = r.connection.log.clone();

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
            ..Default::default()
        }
    };

    if crate::core_rt::set_disable_symlinks(&r, &clcf, &path, &mut of) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let cache = clcf.borrow().open_file_cache.get().clone();
    let handle = match open_cached_file(cache.as_ref(), &path, &mut of, &log) {
        Ok(h) => h,
        Err(()) => {
            let (level, rc) = match of.err {
                0 => return NGX_HTTP_INTERNAL_SERVER_ERROR,
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

    if !of.is_file {
        return NGX_DECLINED;
    }

    r.root_tested.set(!r.error_page.get());
    r.allow_ranges.set(true);

    let mut start: i64 = -1;
    let mut length: usize = 0;
    r.headers_out.borrow_mut().content_length_n = of.size;
    let mut mp4 = None;

    if !r.args.borrow().is_empty() {
        let args = r.args.borrow();

        if let Some(value) = arg(&args, b"start") {
            // A Flash player may send start value with a lot of digits
            // after dot so a custom function is used instead of ngx_atofp().

            start = atofp(value, 3);
        }

        if let Some(value) = arg(&args, b"end") {
            let end = atofp(value, 3);

            if end > 0 {
                if start < 0 {
                    start = 0;
                }

                if end > start {
                    length = (end - start) as usize;
                }
            }
        }
    }

    if start >= 0 {
        r.single_range.set(true);

        let conf = r.loc_conf::<Mp4Conf>(ctx_index());
        let mut f = {
            let conf = conf.borrow();
            Mp4File::new(of.fd, path.clone(), log.clone(), of.size, start as usize, length, &conf, r.is_main())
        };

        match f.process() {
            NGX_DECLINED => {}

            NGX_OK => {
                r.headers_out.borrow_mut().content_length_n = f.content_length;
                mp4 = Some(f);
            }

            _ => return NGX_HTTP_INTERNAL_SERVER_ERROR,
        }
    }

    log.set_action(Some("sending mp4 to client"));

    if *clcf.borrow().directio <= of.size {
        // DIRECTIO is set on transfer only
        // to allow kernel to cache "moov" atom

        if ngx_core::os::directio_on(of.fd) == -1 {
            ngx_log_error!(NGX_LOG_ALERT, log, Some(ngx_core::os::errno()), "{} \"{}\" failed", ngx_core::os::DIRECTIO_ON_N, B(&path));
        }

        of.is_directio = true;

        if let Some(mp4) = mp4.as_mut() {
            mp4.directio = true;
        }
    }

    {
        let mut ho = r.headers_out.borrow_mut();
        ho.status = NGX_HTTP_OK;
        ho.last_modified_time = of.mtime;
    }

    if set_etag(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if set_content_type(&r) != NGX_OK {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    let rc = send_header(&r).await;

    if rc == NGX_ERROR || rc > NGX_OK || r.header_only.get() {
        return rc;
    }

    let out = match mp4 {
        Some(mp4) => mp4.out(),
        None => {
            let file = Rc::new(BufFile { fd: of.fd, name: path.clone(), directio: of.is_directio });
            let mut b = Buf::file(file, 0, of.size);

            b.in_file = b.file_last != 0;
            b.last_buf = r.is_main();
            b.last_in_chain = true;
            b.sync = !(b.last_buf || b.in_file);

            let mut out = Chain::new();
            out.push_back(b);
            out
        }
    };

    // the file stays open until the output is sent
    let rc = output_filter(&r, out).await;
    drop(handle);
    let _ = root;
    rc
}

/// ngx_http_mp4_atofp: same as ngx_atofp(), but allows additional digits
fn atofp(line: &[u8], mut point: usize) -> i64 {
    if line.is_empty() {
        return NGX_ERROR;
    }

    let cutoff = i64::MAX / 10;
    let cutlim = i64::MAX % 10;

    let mut dot = 0usize;
    let mut value: i64 = 0;

    for &ch in line {
        if ch == b'.' {
            if dot != 0 {
                return NGX_ERROR;
            }

            dot = 1;
            continue;
        }

        if !ch.is_ascii_digit() {
            return NGX_ERROR;
        }

        if point == 0 {
            continue;
        }

        let d = (ch - b'0') as i64;

        if value >= cutoff && (value > cutoff || d > cutlim) {
            return NGX_ERROR;
        }

        value = value * 10 + d;
        point -= dot;
    }

    while point > 0 {
        point -= 1;

        if value > cutoff {
            return NGX_ERROR;
        }

        value *= 10;
    }

    value
}

/// The "%.3f" of a double, as ngx_vslprintf() formats it.
struct Fp3(f64);

impl std::fmt::Display for Fp3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = Vec::new();
        ngx_core::geoip::sprintf_float(&mut buf, self.0, 3);
        f.write_str(&String::from_utf8_lossy(&buf))
    }
}

/// The memory the module reads the atoms into and builds the new ones in,
/// the request pool of C as far as the module uses it: the C pointers are
/// offsets into it. It starts with a guard, so that no allocation is at 0,
/// which is NULL. The accessors read what is outside as zeros and do not
/// write there.
struct Mem(Vec<u8>);

/// Room for the small allocations after a large one, so that the
/// allocation of a few bytes does not copy a large buffer.
const MEM_SLACK: usize = 16 * 1024;

impl Mem {
    fn new() -> Mem {
        Mem(vec![0; 8])
    }

    /// ngx_palloc()
    fn alloc(&mut self, size: usize) -> usize {
        let p = self.0.len();

        if self.0.capacity() - p < size {
            self.0.reserve_exact(size.saturating_add(MEM_SLACK));
        }

        self.0.resize(p + size, 0);
        p
    }

    fn bytes(&self, pos: usize, last: usize) -> &[u8] {
        self.0.get(pos..last).unwrap_or(&[])
    }

    fn get8(&self, p: usize) -> u8 {
        self.0.get(p).copied().unwrap_or(0)
    }

    fn get<const N: usize>(&self, p: usize) -> [u8; N] {
        match self.0.get(p..p.wrapping_add(N)) {
            Some(b) => b.try_into().unwrap(),
            None => [0; N],
        }
    }

    fn set(&mut self, p: usize, v: &[u8]) {
        if let Some(b) = self.0.get_mut(p..p.wrapping_add(v.len())) {
            b.copy_from_slice(v);
        }
    }

    /// ngx_mp4_get_32value()
    fn get32(&self, p: usize) -> u32 {
        u32::from_be_bytes(self.get(p))
    }

    /// ngx_mp4_get_64value()
    fn get64(&self, p: usize) -> u64 {
        u64::from_be_bytes(self.get(p))
    }

    /// ngx_mp4_set_16value()
    fn set16(&mut self, p: usize, n: u16) {
        self.set(p, &n.to_be_bytes());
    }

    /// ngx_mp4_set_32value()
    fn set32(&mut self, p: usize, n: u32) {
        self.set(p, &n.to_be_bytes());
    }

    /// ngx_mp4_set_64value()
    fn set64(&mut self, p: usize, n: u64) {
        self.set(p, &n.to_be_bytes());
    }

    /// ngx_mp4_set_atom_name()
    fn set_atom_name(&mut self, p: usize, name: &[u8; 4]) {
        self.set(p.wrapping_add(4), name);
    }

    fn copy(&mut self, src: usize, dst: usize, n: usize) {
        if src.checked_add(n).is_some_and(|e| e <= self.0.len()) && dst.checked_add(n).is_some_and(|e| e <= self.0.len()) {
            self.0.copy_within(src..src + n, dst);
        }
    }
}

/// A memory ngx_buf_t: pos and last point into Mem.
#[derive(Clone, Copy, Default)]
struct MBuf {
    pos: usize,
    last: usize,
}

impl MBuf {
    fn size(&self) -> usize {
        self.last.wrapping_sub(self.pos)
    }
}

/// ngx_http_mp4_trak_t
#[derive(Default)]
struct Trak {
    timescale: u32,
    time_to_sample_entries: u32,
    sample_to_chunk_entries: u32,
    sync_samples_entries: u32,
    composition_offset_entries: u32,
    sample_sizes_entries: u32,
    chunks: u32,

    start_sample: usize,
    end_sample: usize,
    start_chunk: usize,
    end_chunk: usize,
    start_chunk_samples: usize,
    end_chunk_samples: usize,
    start_chunk_samples_size: u64,
    end_chunk_samples_size: u64,
    duration: u64,
    prefix: u64,
    movie_duration: u64,
    start_offset: i64,
    end_offset: i64,

    tkhd_size: usize,
    mdhd_size: usize,
    hdlr_size: usize,
    vmhd_size: usize,
    smhd_size: usize,
    dinf_size: usize,
    size: usize,

    /// out[]: whether the link of the buffer is in the chain (out[n].buf)
    out: [bool; NGX_HTTP_MP4_LAST_ATOM + 1],

    /// the buffers of the links: trak_atom_buf, tkhd_atom_buf etc.
    buf: [MBuf; NGX_HTTP_MP4_LAST_ATOM + 1],

    /// edts_atom, elst_atom, stsc_start_chunk_entry, stsc_end_chunk_entry
    edts_atom: usize,
    elst_atom: usize,
    stsc_start_chunk_entry: usize,
    stsc_end_chunk_entry: usize,
}

/// A file ngx_buf_t: mdat_data_buf
#[derive(Clone, Copy, Default)]
struct FileBuf {
    file_pos: i64,
    file_last: i64,
}

/// ngx_http_mp4_file_t
struct Mp4File {
    // file
    fd: i32,
    name: Vec<u8>,
    log: Log,
    directio: bool,

    mem: Mem,
    buffer: usize,
    buffer_start: usize,
    buffer_pos: usize,
    buffer_end: usize,
    buffer_size: usize,

    offset: i64,
    end: i64,
    content_length: i64,
    start: usize,
    length: usize,
    timescale: u32,
    trak: Vec<Trak>,

    ftyp_size: usize,
    moov_size: usize,

    // the buffers of the links ftyp_atom etc., None for a link without one
    ftyp_atom: Option<MBuf>,
    moov_atom: Option<MBuf>,
    mvhd_atom: Option<MBuf>,
    mdat_atom: Option<MBuf>,
    mdat_data: FileBuf,

    moov_atom_header: usize,
    mdat_atom_header: usize,

    // the location's configuration and whether mp4->request is the main one
    conf_buffer_size: usize,
    max_buffer_size: usize,
    start_key_frame: bool,
    main: bool,
}

type AtomHandler = fn(&mut Mp4File, u64) -> i64;

const NGX_HTTP_MP4_ATOMS: &[(&[u8; 4], AtomHandler)] = &[
    (b"ftyp", Mp4File::read_ftyp_atom),
    (b"moov", Mp4File::read_moov_atom),
    (b"mdat", Mp4File::read_mdat_atom),
];

const NGX_HTTP_MP4_MOOV_ATOMS: &[(&[u8; 4], AtomHandler)] = &[
    (b"mvhd", Mp4File::read_mvhd_atom),
    (b"trak", Mp4File::read_trak_atom),
    (b"cmov", Mp4File::read_cmov_atom),
];

const NGX_HTTP_MP4_TRAK_ATOMS: &[(&[u8; 4], AtomHandler)] = &[
    (b"tkhd", Mp4File::read_tkhd_atom),
    (b"mdia", Mp4File::read_mdia_atom),
];

const NGX_HTTP_MP4_MDIA_ATOMS: &[(&[u8; 4], AtomHandler)] = &[
    (b"mdhd", Mp4File::read_mdhd_atom),
    (b"hdlr", Mp4File::read_hdlr_atom),
    (b"minf", Mp4File::read_minf_atom),
];

const NGX_HTTP_MP4_MINF_ATOMS: &[(&[u8; 4], AtomHandler)] = &[
    (b"vmhd", Mp4File::read_vmhd_atom),
    (b"smhd", Mp4File::read_smhd_atom),
    (b"dinf", Mp4File::read_dinf_atom),
    (b"stbl", Mp4File::read_stbl_atom),
];

const NGX_HTTP_MP4_STBL_ATOMS: &[(&[u8; 4], AtomHandler)] = &[
    (b"stsd", Mp4File::read_stsd_atom),
    (b"stts", Mp4File::read_stts_atom),
    (b"stss", Mp4File::read_stss_atom),
    (b"ctts", Mp4File::read_ctts_atom),
    (b"stsc", Mp4File::read_stsc_atom),
    (b"stsz", Mp4File::read_stsz_atom),
    (b"stco", Mp4File::read_stco_atom),
    (b"co64", Mp4File::read_co64_atom),
];

/// Small excess buffer to process atoms after moov atom, mp4->buffer_start
/// will be set to this buffer part after moov atom processing.
const NGX_HTTP_MP4_MOOV_BUFFER_EXCESS: usize = 4 * 1024;

impl Mp4File {
    #[allow(clippy::too_many_arguments)]
    fn new(fd: i32, name: Vec<u8>, log: Log, end: i64, start: usize, length: usize, conf: &Mp4Conf, main: bool) -> Mp4File {
        let mut mem = Mem::new();
        let moov_atom_header = mem.alloc(8);
        let mdat_atom_header = mem.alloc(16);

        Mp4File {
            fd,
            name,
            log,
            directio: false,
            mem,
            buffer: 0,
            buffer_start: 0,
            buffer_pos: 0,
            buffer_end: 0,
            buffer_size: 0,
            offset: 0,
            end,
            content_length: 0,
            start,
            length,
            timescale: 0,
            trak: Vec::new(),
            ftyp_size: 0,
            moov_size: 0,
            ftyp_atom: None,
            moov_atom: None,
            mvhd_atom: None,
            mdat_atom: None,
            mdat_data: FileBuf::default(),
            moov_atom_header,
            mdat_atom_header,
            conf_buffer_size: *conf.buffer_size,
            max_buffer_size: *conf.max_buffer_size,
            start_key_frame: *conf.start_key_frame,
            main,
        }
    }

    /// ngx_mp4_atom_header()
    fn atom_header(&self) -> usize {
        self.buffer_pos.wrapping_sub(ATOM_HEADER)
    }

    /// ngx_mp4_atom_next()
    fn atom_next(&mut self, n: u64) {
        if n > self.buffer_end.wrapping_sub(self.buffer_pos) as u64 {
            self.buffer_pos = self.buffer_end;
        } else {
            self.buffer_pos += n as usize;
        }

        self.offset = self.offset.wrapping_add(n as i64);
    }

    /// ngx_mp4_last_trak()
    fn last_trak(&self) -> usize {
        self.trak.len() - 1
    }

    /// The chain of the response: mp4->out.
    fn out(&self) -> Chain {
        let mut out = Chain::new();

        let mut push = |b: &MBuf| {
            out.push_back(Buf::from_vec(self.mem.bytes(b.pos, b.last).to_vec()));
        };

        if let Some(b) = &self.ftyp_atom {
            push(b);
        }

        if let Some(b) = &self.moov_atom {
            push(b);
        }

        if let Some(b) = &self.mvhd_atom {
            push(b);
        }

        for trak in &self.trak {
            push(&trak.buf[NGX_HTTP_MP4_TRAK_ATOM]);

            for j in 1..NGX_HTTP_MP4_LAST_ATOM + 1 {
                if trak.out[j] {
                    push(&trak.buf[j]);
                }
            }
        }

        if let Some(b) = &self.mdat_atom {
            push(b);
        }

        let file = Rc::new(BufFile { fd: self.fd, name: self.name.clone(), directio: self.directio });
        let mut data = Buf::file(file, self.mdat_data.file_pos, self.mdat_data.file_last);
        data.last_buf = self.main;
        data.last_in_chain = true;
        out.push_back(data);

        out
    }

    /// ngx_http_mp4_process
    fn process(&mut self) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 start:{}, length:{}", self.start, self.length);

        self.buffer_size = self.conf_buffer_size;

        let rc = self.read_atom(NGX_HTTP_MP4_ATOMS, self.end as u64);
        if rc != NGX_OK {
            return rc;
        }

        if self.trak.is_empty() {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "no mp4 trak atoms were found in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if self.mdat_atom.is_none() {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "no mp4 mdat atom was found in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if let Some(b) = self.mvhd_atom {
            self.moov_size += b.size();
        }

        let mut start_offset = self.end;
        let mut end_offset = 0;

        for i in 0..self.trak.len() {
            if self.update_stts_atom(i) != NGX_OK {
                return NGX_ERROR;
            }

            if self.update_stss_atom(i) != NGX_OK {
                return NGX_ERROR;
            }

            self.update_ctts_atom(i);

            if self.update_stsc_atom(i) != NGX_OK {
                return NGX_ERROR;
            }

            if self.update_stsz_atom(i) != NGX_OK {
                return NGX_ERROR;
            }

            if self.trak[i].out[NGX_HTTP_MP4_CO64_DATA] {
                if self.update_co64_atom(i) != NGX_OK {
                    return NGX_ERROR;
                }
            } else if self.update_stco_atom(i) != NGX_OK {
                return NGX_ERROR;
            }

            self.update_stbl_atom(i);
            self.update_minf_atom(i);
            self.update_mdhd_atom(i);
            self.trak[i].size += self.trak[i].hdlr_size;
            self.update_mdia_atom(i);
            self.trak[i].size += self.trak[i].tkhd_size;
            self.update_edts_atom(i);
            self.update_trak_atom(i);

            self.moov_size += self.trak[i].size;

            if start_offset > self.trak[i].start_offset {
                start_offset = self.trak[i].start_offset;
            }

            if end_offset < self.trak[i].end_offset {
                end_offset = self.trak[i].end_offset;
            }
        }

        if end_offset <= start_offset {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "no data between start time and end time in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        self.moov_size += 8;

        self.mem.set32(self.moov_atom_header, self.moov_size as u32);
        self.mem.set_atom_name(self.moov_atom_header, b"moov");
        self.content_length += self.moov_size as i64;

        if start_offset >= self.mdat_data.file_last {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "start time is out mp4 mdat atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let mdat_header_size = self.update_mdat_atom(start_offset, end_offset);
        let adjustment = (self.ftyp_size + self.moov_size + mdat_header_size).wrapping_sub(start_offset as usize) as i64;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 adjustment:{}", adjustment);

        for i in 0..self.trak.len() {
            if self.trak[i].out[NGX_HTTP_MP4_CO64_DATA] {
                self.adjust_co64_atom(i, adjustment);
            } else {
                self.adjust_stco_atom(i, adjustment as i32);
            }
        }

        NGX_OK
    }

    /// ngx_http_mp4_read_atom
    fn read_atom(&mut self, atom: &[(&[u8; 4], AtomHandler)], atom_data_size: u64) -> i64 {
        let end = self.offset.wrapping_add(atom_data_size as i64);

        'next: while self.offset < end {
            if self.read(4) != NGX_OK {
                return NGX_ERROR;
            }

            let mut atom_header = self.buffer_pos;
            let mut atom_size = self.mem.get32(atom_header) as u64;
            let mut atom_header_size = ATOM_HEADER;

            if atom_size == 0 {
                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 atom end");
                return NGX_OK;
            }

            if atom_size < ATOM_HEADER as u64 {
                if atom_size == 1 {
                    if self.read(ATOM_HEADER64) != NGX_OK {
                        return NGX_ERROR;
                    }

                    // 64-bit atom size
                    atom_header = self.buffer_pos;
                    atom_size = self.mem.get64(atom_header + 8);
                    atom_header_size = ATOM_HEADER64;

                    if atom_size < ATOM_HEADER64 as u64 {
                        ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 atom is too small:{}", B(&self.name), atom_size);
                        return NGX_ERROR;
                    }
                } else {
                    ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 atom is too small:{}", B(&self.name), atom_size);
                    return NGX_ERROR;
                }
            }

            if self.read(ATOM_HEADER) != NGX_OK {
                return NGX_ERROR;
            }

            atom_header = self.buffer_pos;
            let atom_name = atom_header + 4;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 atom: {} @{}:{}", B(self.mem.bytes(atom_name, atom_name + 4)), self.offset, atom_size);

            if atom_size > (NGX_MAX_OFF_T_VALUE - self.offset) as u64 || self.offset + atom_size as i64 > end {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 atom too large:{}", B(&self.name), atom_size);
                return NGX_ERROR;
            }

            for (name, handler) in atom {
                if self.mem.bytes(atom_name, atom_name + 4) == &name[..] {
                    self.atom_next(atom_header_size as u64);

                    let rc = handler(self, atom_size - atom_header_size as u64);
                    if rc != NGX_OK {
                        return rc;
                    }

                    continue 'next;
                }
            }

            self.atom_next(atom_size);
        }

        NGX_OK
    }

    /// ngx_http_mp4_read
    fn read(&mut self, size: usize) -> i64 {
        if self.buffer_pos != 0 && self.buffer_end != 0 && self.buffer_pos.wrapping_add(size) <= self.buffer_end {
            return NGX_OK;
        }

        if self.offset.saturating_add(self.buffer_size as i64) > self.end {
            self.buffer_size = (self.end - self.offset) as usize;
        }

        if self.buffer_size < size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 file truncated", B(&self.name));
            return NGX_ERROR;
        }

        if self.buffer == 0 {
            self.buffer = self.mem.alloc(self.buffer_size);
            self.buffer_start = self.buffer;
        }

        let n = self.read_file(self.buffer_start, self.buffer_size, self.offset);

        if n == NGX_ERROR as isize {
            return NGX_ERROR;
        }

        if n as usize != self.buffer_size {
            ngx_log_error!(NGX_LOG_CRIT, self.log, None, "pread() read only {} of {} from \"{}\"", n, self.buffer_size, B(&self.name));
            return NGX_ERROR;
        }

        self.buffer_pos = self.buffer_start;
        self.buffer_end = self.buffer_start + self.buffer_size;

        NGX_OK
    }

    /// ngx_read_file
    fn read_file(&mut self, buf: usize, size: usize, offset: i64) -> isize {
        let Some(dst) = self.mem.0.get_mut(buf..buf.wrapping_add(size)) else {
            return NGX_ERROR as isize;
        };

        ngx_log_debug!(NGX_LOG_DEBUG_CORE, self.log, "read: {}, {:p}, {}, {}", self.fd, dst.as_ptr(), size, offset);

        match ngx_core::os::pread(self.fd, dst, offset) {
            Ok(n) => n as isize,
            Err(err) => {
                ngx_log_error!(NGX_LOG_CRIT, self.log, Some(err), "pread() \"{}\" failed", B(&self.name));
                NGX_ERROR as isize
            }
        }
    }

    /// ngx_http_mp4_read_ftyp_atom
    fn read_ftyp_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 ftyp atom");

        if atom_data_size > 1024 || self.buffer_pos.wrapping_add(atom_data_size as usize) > self.buffer_end {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 ftyp atom is too large:{}", B(&self.name), atom_data_size);
            return NGX_ERROR;
        }

        if self.ftyp_atom.is_some() {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 ftyp atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let atom_size = ATOM_HEADER + atom_data_size as usize;

        let ftyp_atom = self.mem.alloc(atom_size);

        self.mem.set32(ftyp_atom, atom_size as u32);
        self.mem.set_atom_name(ftyp_atom, b"ftyp");

        // only moov atom content is guaranteed to be in mp4->buffer
        // during sending response, so ftyp atom content should be copied
        self.mem.copy(self.buffer_pos, ftyp_atom + ATOM_HEADER, atom_data_size as usize);

        self.ftyp_atom = Some(MBuf { pos: ftyp_atom, last: ftyp_atom + atom_size });
        self.ftyp_size = atom_size;
        self.content_length = atom_size as i64;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_read_moov_atom
    fn read_moov_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 moov atom");

        let no_mdat = self.mdat_atom.is_none();

        if no_mdat && self.start == 0 && self.length == 0 {
            // send original file if moov atom resides before
            // mdat atom and client requests integral file
            return NGX_DECLINED;
        }

        if self.moov_atom.is_some() {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 moov atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if atom_data_size > self.buffer_size as u64 {
            if atom_data_size > self.max_buffer_size as u64 {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 moov atom is too large:{}, you may want to increase mp4_max_buffer_size", B(&self.name), atom_data_size);
                return NGX_ERROR;
            }

            // the old buffer is not freed, the pool is
            self.buffer = 0;
            self.buffer_pos = 0;
            self.buffer_end = 0;

            self.buffer_size = atom_data_size as usize + NGX_HTTP_MP4_MOOV_BUFFER_EXCESS * no_mdat as usize;
        }

        if self.read(atom_data_size as usize) != NGX_OK {
            return NGX_ERROR;
        }

        self.moov_atom = Some(MBuf { pos: self.moov_atom_header, last: self.moov_atom_header + 8 });

        let rc = self.read_atom(NGX_HTTP_MP4_MOOV_ATOMS, atom_data_size);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 moov atom done");

        if no_mdat {
            self.buffer_start = self.buffer_pos;
            self.buffer_size = NGX_HTTP_MP4_MOOV_BUFFER_EXCESS;

            if self.buffer_start.wrapping_add(self.buffer_size) > self.buffer_end {
                self.buffer = 0;
                self.buffer_pos = 0;
                self.buffer_end = 0;
            }
        } else {
            // skip atoms after moov atom
            self.offset = self.end;
        }

        rc
    }

    /// ngx_http_mp4_read_mdat_atom
    fn read_mdat_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 mdat atom");

        if self.mdat_atom.is_some() {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 mdat atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        self.mdat_data.file_last = self.offset.wrapping_add(atom_data_size as i64);

        self.mdat_atom = Some(MBuf::default());

        if !self.trak.is_empty() {
            // skip atoms after mdat atom
            self.offset = self.end;
        } else {
            self.atom_next(atom_data_size);
        }

        NGX_OK
    }

    /// ngx_http_mp4_update_mdat_atom
    fn update_mdat_atom(&mut self, start_offset: i64, end_offset: i64) -> usize {
        let atom_data_size = end_offset - start_offset;
        self.mdat_data.file_pos = start_offset;
        self.mdat_data.file_last = end_offset;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mdat new offset @{}:{}", start_offset, atom_data_size);

        let atom_header = self.mdat_atom_header;
        let atom_size: u64;
        let atom_header_size: usize;

        if atom_data_size as u64 > 0xffff_ffff - ATOM_HEADER as u64 {
            atom_size = 1;
            atom_header_size = ATOM_HEADER64;
            self.mem.set64(atom_header + ATOM_HEADER, (ATOM_HEADER64 as i64 + atom_data_size) as u64);
        } else {
            atom_size = ATOM_HEADER as u64 + atom_data_size as u64;
            atom_header_size = ATOM_HEADER;
        }

        self.content_length += atom_header_size as i64 + atom_data_size;

        self.mem.set32(atom_header, atom_size as u32);
        self.mem.set_atom_name(atom_header, b"mdat");

        self.mdat_atom = Some(MBuf { pos: atom_header, last: atom_header + atom_header_size });

        atom_header_size
    }

    /// ngx_http_mp4_read_mvhd_atom
    fn read_mvhd_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 mvhd atom");

        if self.mvhd_atom.is_some() {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 mvhd atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"mvhd");

        if atom_data_size_of(mvhd::SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 mvhd atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let version = self.mem.get8(atom_header + ATOM_VERSION);
        let timescale: u32;
        let mut duration: u64;

        if version == 0 {
            // version 0: 32-bit duration
            timescale = self.mem.get32(atom_header + mvhd::TIMESCALE);
            duration = self.mem.get32(atom_header + mvhd::DURATION) as u64;
        } else {
            // version 1: 64-bit duration

            if atom_data_size_of(mvhd64::SIZEOF) > atom_data_size {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 mvhd atom too small", B(&self.name));
                return NGX_ERROR;
            }

            timescale = self.mem.get32(atom_header + mvhd64::TIMESCALE);
            duration = self.mem.get64(atom_header + mvhd64::DURATION);
        }

        self.timescale = timescale;

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mvhd timescale:{}, duration:{}, time:{}s", timescale, duration, Fp3(duration as f64 / timescale as f64));

        let start_time = (self.start as u64).wrapping_mul(timescale as u64) / 1000;

        if duration < start_time {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 start time exceeds file duration", B(&self.name));
            return NGX_ERROR;
        }

        duration -= start_time;

        if self.length != 0 {
            let length_time = (self.length as u64).wrapping_mul(timescale as u64) / 1000;

            if duration > length_time {
                duration = length_time;
            }
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mvhd new duration:{}, time:{}s", duration, Fp3(duration as f64 / timescale as f64));

        let atom_size = ATOM_HEADER + atom_data_size as usize;
        self.mem.set32(atom_header, atom_size as u32);

        if version == 0 {
            self.mem.set32(atom_header + mvhd::DURATION, duration as u32);
        } else {
            self.mem.set64(atom_header + mvhd64::DURATION, duration);
        }

        self.mvhd_atom = Some(MBuf { pos: atom_header, last: atom_header + atom_size });

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_read_trak_atom
    fn read_trak_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 trak atom");

        let side = self.mem.alloc(EDTS_ATOM_SIZEOF + elst::SIZEOF + 2 * STSC_ENTRY_SIZEOF);

        let mut trak = Trak {
            edts_atom: side,
            elst_atom: side + EDTS_ATOM_SIZEOF,
            stsc_start_chunk_entry: side + EDTS_ATOM_SIZEOF + elst::SIZEOF,
            stsc_end_chunk_entry: side + EDTS_ATOM_SIZEOF + elst::SIZEOF + STSC_ENTRY_SIZEOF,
            ..Default::default()
        };

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"trak");

        trak.buf[NGX_HTTP_MP4_TRAK_ATOM] = MBuf { pos: atom_header, last: atom_header + ATOM_HEADER };
        trak.out[NGX_HTTP_MP4_TRAK_ATOM] = true;

        self.trak.push(trak);

        let atom_end = self.buffer_pos.wrapping_add(atom_data_size as usize);
        let atom_file_end = self.offset.wrapping_add(atom_data_size as i64);

        let rc = self.read_atom(NGX_HTTP_MP4_TRAK_ATOMS, atom_data_size);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 trak atom: {}", rc);

        if rc == NGX_DECLINED {
            // skip this trak
            self.trak.pop();
            self.buffer_pos = atom_end;
            self.offset = atom_file_end;
            return NGX_OK;
        }

        rc
    }

    /// ngx_http_mp4_update_trak_atom
    fn update_trak_atom(&mut self, i: usize) {
        let trak = &mut self.trak[i];

        trak.size += ATOM_HEADER;
        self.mem.set32(trak.buf[NGX_HTTP_MP4_TRAK_ATOM].pos, trak.size as u32);
    }

    /// ngx_http_mp4_read_cmov_atom
    fn read_cmov_atom(&mut self, _atom_data_size: u64) -> i64 {
        ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 compressed moov atom (cmov) is not supported", B(&self.name));

        NGX_ERROR
    }

    /// ngx_http_mp4_read_tkhd_atom
    fn read_tkhd_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 tkhd atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"tkhd");

        if atom_data_size_of(tkhd::SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 tkhd atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let version = self.mem.get8(atom_header + ATOM_VERSION);
        let mut duration: u64;

        if version == 0 {
            // version 0: 32-bit duration
            duration = self.mem.get32(atom_header + tkhd::DURATION) as u64;
        } else {
            // version 1: 64-bit duration

            if atom_data_size_of(tkhd64::SIZEOF) > atom_data_size {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 tkhd atom too small", B(&self.name));
                return NGX_ERROR;
            }

            duration = self.mem.get64(atom_header + tkhd64::DURATION);
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "tkhd duration:{}, time:{}s", duration, Fp3(duration as f64 / self.timescale as f64));

        let start_time = (self.start as u64).wrapping_mul(self.timescale as u64) / 1000;

        if duration <= start_time {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "tkhd duration is less than start time");
            return NGX_DECLINED;
        }

        duration -= start_time;

        if self.length != 0 {
            let length_time = (self.length as u64).wrapping_mul(self.timescale as u64) / 1000;

            if duration > length_time {
                duration = length_time;
            }
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "tkhd new duration:{}, time:{}s", duration, Fp3(duration as f64 / self.timescale as f64));

        let atom_size = ATOM_HEADER + atom_data_size as usize;

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_TKHD_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 tkhd atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.tkhd_size = atom_size;
        trak.movie_duration = duration;

        self.mem.set32(atom_header, atom_size as u32);

        if version == 0 {
            self.mem.set32(atom_header + tkhd::DURATION, duration as u32);
        } else {
            self.mem.set64(atom_header + tkhd64::DURATION, duration);
        }

        trak.buf[NGX_HTTP_MP4_TKHD_ATOM] = MBuf { pos: atom_header, last: atom_header + atom_size };
        trak.out[NGX_HTTP_MP4_TKHD_ATOM] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_read_mdia_atom
    fn read_mdia_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "process mdia atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"mdia");

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_MDIA_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 mdia atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_MDIA_ATOM] = MBuf { pos: atom_header, last: atom_header + ATOM_HEADER };
        trak.out[NGX_HTTP_MP4_MDIA_ATOM] = true;

        self.read_atom(NGX_HTTP_MP4_MDIA_ATOMS, atom_data_size)
    }

    /// ngx_http_mp4_update_mdia_atom
    fn update_mdia_atom(&mut self, i: usize) {
        let trak = &mut self.trak[i];

        trak.size += ATOM_HEADER;
        self.mem.set32(trak.buf[NGX_HTTP_MP4_MDIA_ATOM].pos, trak.size as u32);
    }

    /// ngx_http_mp4_read_mdhd_atom
    fn read_mdhd_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 mdhd atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"mdhd");

        if atom_data_size_of(mdhd::SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 mdhd atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let version = self.mem.get8(atom_header + ATOM_VERSION);
        let timescale: u32;
        let mut duration: u64;

        if version == 0 {
            // version 0: everything is 32-bit
            timescale = self.mem.get32(atom_header + mdhd::TIMESCALE);
            duration = self.mem.get32(atom_header + mdhd::DURATION) as u64;
        } else {
            // version 1: 64-bit duration and 32-bit timescale

            if atom_data_size_of(mdhd64::SIZEOF) > atom_data_size {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 mdhd atom too small", B(&self.name));
                return NGX_ERROR;
            }

            timescale = self.mem.get32(atom_header + mdhd64::TIMESCALE);
            duration = self.mem.get64(atom_header + mdhd64::DURATION);
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mdhd timescale:{}, duration:{}, time:{}s", timescale, duration, Fp3(duration as f64 / timescale as f64));

        let start_time = (self.start as u64).wrapping_mul(timescale as u64) / 1000;

        if duration <= start_time {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mdhd duration is less than start time");
            return NGX_DECLINED;
        }

        duration -= start_time;

        if self.length != 0 {
            let length_time = (self.length as u64).wrapping_mul(timescale as u64) / 1000;

            if duration > length_time {
                duration = length_time;
            }
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mdhd new duration:{}, time:{}s", duration, Fp3(duration as f64 / timescale as f64));

        let atom_size = ATOM_HEADER + atom_data_size as usize;

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_MDHD_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 mdhd atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.mdhd_size = atom_size;
        trak.timescale = timescale;
        trak.duration = duration;

        self.mem.set32(atom_header, atom_size as u32);

        trak.buf[NGX_HTTP_MP4_MDHD_ATOM] = MBuf { pos: atom_header, last: atom_header + atom_size };
        trak.out[NGX_HTTP_MP4_MDHD_ATOM] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_update_mdhd_atom
    fn update_mdhd_atom(&mut self, i: usize) {
        let trak = &mut self.trak[i];

        if !trak.out[NGX_HTTP_MP4_MDHD_ATOM] {
            return;
        }

        let atom = trak.buf[NGX_HTTP_MP4_MDHD_ATOM];

        if self.mem.get8(atom.pos + ATOM_VERSION) == 0 {
            self.mem.set32(atom.pos + mdhd::DURATION, trak.duration as u32);
        } else {
            self.mem.set64(atom.pos + mdhd64::DURATION, trak.duration);
        }

        trak.size += trak.mdhd_size;
    }

    /// ngx_http_mp4_read_hdlr_atom
    fn read_hdlr_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 hdlr atom");

        let atom_header = self.atom_header();
        let atom_size = ATOM_HEADER + atom_data_size as usize;
        self.mem.set32(atom_header, atom_size as u32);
        self.mem.set_atom_name(atom_header, b"hdlr");

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_HDLR_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 hdlr atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_HDLR_ATOM] = MBuf { pos: atom_header, last: atom_header + atom_size };

        trak.hdlr_size = atom_size;
        trak.out[NGX_HTTP_MP4_HDLR_ATOM] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_read_minf_atom
    fn read_minf_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "process minf atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"minf");

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_MINF_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 minf atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_MINF_ATOM] = MBuf { pos: atom_header, last: atom_header + ATOM_HEADER };
        trak.out[NGX_HTTP_MP4_MINF_ATOM] = true;

        self.read_atom(NGX_HTTP_MP4_MINF_ATOMS, atom_data_size)
    }

    /// ngx_http_mp4_update_minf_atom
    fn update_minf_atom(&mut self, i: usize) {
        let trak = &mut self.trak[i];

        trak.size += ATOM_HEADER + trak.vmhd_size + trak.smhd_size + trak.dinf_size;
        self.mem.set32(trak.buf[NGX_HTTP_MP4_MINF_ATOM].pos, trak.size as u32);
    }

    /// ngx_http_mp4_read_vmhd_atom
    fn read_vmhd_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 vmhd atom");

        let atom_header = self.atom_header();
        let atom_size = ATOM_HEADER + atom_data_size as usize;
        self.mem.set32(atom_header, atom_size as u32);
        self.mem.set_atom_name(atom_header, b"vmhd");

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_VMHD_ATOM] || self.trak[n].out[NGX_HTTP_MP4_SMHD_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 vmhd/smhd atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_VMHD_ATOM] = MBuf { pos: atom_header, last: atom_header + atom_size };

        trak.vmhd_size += atom_size;
        trak.out[NGX_HTTP_MP4_VMHD_ATOM] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_read_smhd_atom
    fn read_smhd_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 smhd atom");

        let atom_header = self.atom_header();
        let atom_size = ATOM_HEADER + atom_data_size as usize;
        self.mem.set32(atom_header, atom_size as u32);
        self.mem.set_atom_name(atom_header, b"smhd");

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_VMHD_ATOM] || self.trak[n].out[NGX_HTTP_MP4_SMHD_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 vmhd/smhd atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_SMHD_ATOM] = MBuf { pos: atom_header, last: atom_header + atom_size };

        trak.smhd_size += atom_size;
        trak.out[NGX_HTTP_MP4_SMHD_ATOM] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_read_dinf_atom
    fn read_dinf_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 dinf atom");

        let atom_header = self.atom_header();
        let atom_size = ATOM_HEADER + atom_data_size as usize;
        self.mem.set32(atom_header, atom_size as u32);
        self.mem.set_atom_name(atom_header, b"dinf");

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_DINF_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 dinf atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_DINF_ATOM] = MBuf { pos: atom_header, last: atom_header + atom_size };

        trak.dinf_size += atom_size;
        trak.out[NGX_HTTP_MP4_DINF_ATOM] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_read_stbl_atom
    fn read_stbl_atom(&mut self, atom_data_size: u64) -> i64 {
        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "process stbl atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"stbl");

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_STBL_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 stbl atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_STBL_ATOM] = MBuf { pos: atom_header, last: atom_header + ATOM_HEADER };
        trak.out[NGX_HTTP_MP4_STBL_ATOM] = true;

        self.read_atom(NGX_HTTP_MP4_STBL_ATOMS, atom_data_size)
    }

    /// ngx_http_mp4_update_edts_atom
    fn update_edts_atom(&mut self, i: usize) {
        let trak = &mut self.trak[i];

        if trak.prefix == 0 {
            return;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 edts atom update prefix:{}", trak.prefix);

        let edts_atom = trak.edts_atom;
        self.mem.set32(edts_atom, (EDTS_ATOM_SIZEOF + elst::SIZEOF) as u32);
        self.mem.set_atom_name(edts_atom, b"edts");

        trak.buf[NGX_HTTP_MP4_EDTS_ATOM] = MBuf { pos: edts_atom, last: edts_atom + EDTS_ATOM_SIZEOF };
        trak.out[NGX_HTTP_MP4_EDTS_ATOM] = true;

        let elst_atom = trak.elst_atom;
        self.mem.set32(elst_atom, elst::SIZEOF as u32);
        self.mem.set_atom_name(elst_atom, b"elst");

        self.mem.set(elst_atom + ATOM_VERSION, &[1]);
        self.mem.set(elst_atom + elst::FLAGS, &[0, 0, 0]);

        self.mem.set32(elst_atom + ATOM_ENTRIES, 1);
        self.mem.set64(elst_atom + elst::DURATION, trak.movie_duration);
        self.mem.set64(elst_atom + elst::MEDIA_TIME, trak.prefix);
        self.mem.set16(elst_atom + elst::MEDIA_RATE, 1);
        self.mem.set16(elst_atom + elst::RESERVED, 0);

        trak.buf[NGX_HTTP_MP4_ELST_ATOM] = MBuf { pos: elst_atom, last: elst_atom + elst::SIZEOF };
        trak.out[NGX_HTTP_MP4_ELST_ATOM] = true;

        trak.size += EDTS_ATOM_SIZEOF + elst::SIZEOF;
    }

    /// ngx_http_mp4_update_stbl_atom
    fn update_stbl_atom(&mut self, i: usize) {
        let trak = &mut self.trak[i];

        trak.size += ATOM_HEADER;
        self.mem.set32(trak.buf[NGX_HTTP_MP4_STBL_ATOM].pos, trak.size as u32);
    }

    /// ngx_http_mp4_read_stsd_atom
    fn read_stsd_atom(&mut self, atom_data_size: u64) -> i64 {
        // sample description atom

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stsd atom");

        let atom_header = self.atom_header();
        let atom_size = ATOM_HEADER + atom_data_size as usize;
        let atom_table = atom_header + atom_size;
        self.mem.set32(atom_header, atom_size as u32);
        self.mem.set_atom_name(atom_header, b"stsd");

        if atom_data_size_of(stsd::SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stsd atom too small", B(&self.name));
            return NGX_ERROR;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "stsd entries:{}, media:{}", self.mem.get32(atom_header + ATOM_ENTRIES), B(self.mem.bytes(atom_header + stsd::MEDIA_NAME, atom_header + stsd::MEDIA_NAME + 4)));

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_STSD_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 stsd atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_STSD_ATOM] = MBuf { pos: atom_header, last: atom_table };

        trak.out[NGX_HTTP_MP4_STSD_ATOM] = true;
        trak.size += atom_size;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_read_stts_atom
    fn read_stts_atom(&mut self, atom_data_size: u64) -> i64 {
        // time-to-sample atom

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stts atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"stts");

        if atom_data_size_of(TABLE_ATOM_SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stts atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let entries = self.mem.get32(atom_header + ATOM_ENTRIES);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 time-to-sample entries:{}", entries);

        if atom_data_size_of(TABLE_ATOM_SIZEOF) + entries as u64 * STTS_ENTRY_SIZEOF as u64 > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stts atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let atom_table = atom_header + TABLE_ATOM_SIZEOF;
        let atom_end = atom_table + entries as usize * STTS_ENTRY_SIZEOF;

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_STTS_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 stts atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.time_to_sample_entries = entries;

        trak.buf[NGX_HTTP_MP4_STTS_ATOM] = MBuf { pos: atom_header, last: atom_table };
        trak.buf[NGX_HTTP_MP4_STTS_DATA] = MBuf { pos: atom_table, last: atom_end };

        trak.out[NGX_HTTP_MP4_STTS_ATOM] = true;
        trak.out[NGX_HTTP_MP4_STTS_DATA] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_update_stts_atom
    fn update_stts_atom(&mut self, i: usize) -> i64 {
        // mdia.minf.stbl.stts updating requires trak->timescale
        // from mdia.mdhd atom which may reside after mdia.minf

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stts atom update");

        if !self.trak[i].out[NGX_HTTP_MP4_STTS_DATA] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "no mp4 stts atoms were found in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if self.crop_stts_data(i, true) != NGX_OK {
            return NGX_ERROR;
        }

        if self.crop_stts_data(i, false) != NGX_OK {
            return NGX_ERROR;
        }

        let trak = &mut self.trak[i];

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "time-to-sample entries:{}", trak.time_to_sample_entries);

        let atom_size = TABLE_ATOM_SIZEOF.wrapping_add(trak.buf[NGX_HTTP_MP4_STTS_DATA].size());
        trak.size = trak.size.wrapping_add(atom_size);

        let atom = trak.buf[NGX_HTTP_MP4_STTS_ATOM];
        self.mem.set32(atom.pos, atom_size as u32);
        self.mem.set32(atom.pos + ATOM_ENTRIES, trak.time_to_sample_entries);

        NGX_OK
    }

    /// ngx_http_mp4_crop_stts_data
    fn crop_stts_data(&mut self, i: usize, start: bool) -> i64 {
        let start_sec: usize;

        if start {
            start_sec = self.start;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stts crop start_time:{}", start_sec);
        } else if self.length != 0 {
            start_sec = self.length;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stts crop end_time:{}", start_sec);
        } else {
            return NGX_OK;
        }

        let data = self.trak[i].buf[NGX_HTTP_MP4_STTS_DATA];

        let mut start_time = ((start_sec as u64).wrapping_mul(self.trak[i].timescale as u64) / 1000).wrapping_add(self.trak[i].prefix);

        let mut entries = self.trak[i].time_to_sample_entries as usize;
        let mut start_sample: usize = 0;
        let mut entry = data.pos;
        let end = data.last;

        let mut count: u32;
        let mut duration: u32;
        let mut rest: u32;

        loop {
            if entry >= end {
                if start {
                    ngx_log_error!(NGX_LOG_ERR, self.log, None, "start time is out mp4 stts samples in \"{}\"", B(&self.name));

                    return NGX_ERROR;
                }

                let trak = &mut self.trak[i];

                trak.end_sample = trak.start_sample.wrapping_add(start_sample);

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "end_sample:{}", trak.end_sample);

                return NGX_OK;
            }

            count = self.mem.get32(entry);
            duration = self.mem.get32(entry + 4);

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "time:{}, count:{}, duration:{}", start_time, count, duration);

            if start_time < count as u64 * duration as u64 {
                start_sample = start_sample.wrapping_add((start_time / duration as u64) as usize);
                rest = (start_time / duration as u64) as u32;
                break;
            }

            start_sample = start_sample.wrapping_add(count as usize);
            start_time -= count as u64 * duration as u64;
            entries = entries.wrapping_sub(1);
            entry += STTS_ENTRY_SIZEOF;
        }

        // found:

        if start {
            let mut key_prefix: u32 = 0;

            if self.seek_key_frame(i, start_sample as u32, &mut key_prefix) != NGX_OK {
                return NGX_ERROR;
            }

            start_sample = start_sample.wrapping_sub(key_prefix as usize);

            let trak = &mut self.trak[i];

            while rest < key_prefix {
                trak.prefix = trak.prefix.wrapping_add(rest.wrapping_mul(duration) as u64);
                key_prefix -= rest;

                entry = entry.wrapping_sub(STTS_ENTRY_SIZEOF);
                entries = entries.wrapping_add(1);

                count = self.mem.get32(entry);
                duration = self.mem.get32(entry.wrapping_add(4));
                rest = count;
            }

            trak.prefix = trak.prefix.wrapping_add(key_prefix.wrapping_mul(duration) as u64);
            trak.duration = trak.duration.wrapping_add(trak.prefix);
            rest -= key_prefix;

            self.mem.set32(entry, count.wrapping_sub(rest));
            trak.buf[NGX_HTTP_MP4_STTS_DATA].pos = entry;
            trak.time_to_sample_entries = entries as u32;
            trak.start_sample = start_sample;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "start_sample:{}, new count:{}", trak.start_sample, count.wrapping_sub(rest));
        } else {
            let trak = &mut self.trak[i];

            self.mem.set32(entry, rest);
            trak.buf[NGX_HTTP_MP4_STTS_DATA].last = entry + STTS_ENTRY_SIZEOF;
            trak.time_to_sample_entries = (trak.time_to_sample_entries as usize).wrapping_sub(entries.wrapping_sub(1)) as u32;
            trak.end_sample = trak.start_sample.wrapping_add(start_sample);

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "end_sample:{}, new count:{}", trak.end_sample, rest);
        }

        NGX_OK
    }

    /// ngx_http_mp4_seek_key_frame
    fn seek_key_frame(&mut self, i: usize, start_sample: u32, key_prefix: &mut u32) -> i64 {
        *key_prefix = 0;

        if !self.start_key_frame {
            return NGX_OK;
        }

        if !self.trak[i].out[NGX_HTTP_MP4_STSS_DATA] {
            return NGX_OK;
        }

        let data = self.trak[i].buf[NGX_HTTP_MP4_STSS_DATA];

        let mut entry = data.pos;
        let end = data.last;

        // sync samples starts from 1
        let start_sample = start_sample.wrapping_add(1);

        while entry < end {
            let sample = self.mem.get32(entry);

            if sample == 0 {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "zero sync sample in \"{}\"", B(&self.name));
                return NGX_ERROR;
            }

            if sample > start_sample {
                break;
            }

            *key_prefix = start_sample - sample;
            entry += 4;
        }

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 key frame prefix:{}", *key_prefix);

        NGX_OK
    }

    /// ngx_http_mp4_read_stss_atom
    fn read_stss_atom(&mut self, atom_data_size: u64) -> i64 {
        // sync samples atom

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stss atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"stss");

        if atom_data_size_of(TABLE_ATOM_SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stss atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let entries = self.mem.get32(atom_header + ATOM_ENTRIES);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sync sample entries:{}", entries);

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_STSS_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 stss atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        self.trak[n].sync_samples_entries = entries;

        let atom_table = atom_header + TABLE_ATOM_SIZEOF;

        self.trak[n].buf[NGX_HTTP_MP4_STSS_ATOM] = MBuf { pos: atom_header, last: atom_table };

        if atom_data_size_of(TABLE_ATOM_SIZEOF) + entries as u64 * 4 > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stss atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let atom_end = atom_table + entries as usize * 4;

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_STSS_DATA] = MBuf { pos: atom_table, last: atom_end };

        trak.out[NGX_HTTP_MP4_STSS_ATOM] = true;
        trak.out[NGX_HTTP_MP4_STSS_DATA] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_update_stss_atom
    fn update_stss_atom(&mut self, i: usize) -> i64 {
        // mdia.minf.stbl.stss updating requires trak->start_sample
        // from mdia.minf.stbl.stts which depends on value from mdia.mdhd
        // atom which may reside after mdia.minf

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stss atom update");

        if !self.trak[i].out[NGX_HTTP_MP4_STSS_DATA] {
            return NGX_OK;
        }

        self.crop_stss_data(i, true);
        self.crop_stss_data(i, false);

        let trak = &mut self.trak[i];

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sync sample entries:{}", trak.sync_samples_entries);

        let data = trak.buf[NGX_HTTP_MP4_STSS_DATA];

        if trak.sync_samples_entries != 0 {
            let mut entry = data.pos;
            let end = data.last.min(self.mem.0.len());

            let start_sample = trak.start_sample as u32;

            while entry < end {
                let sample = self.mem.get32(entry).wrapping_sub(start_sample);
                self.mem.set32(entry, sample);
                entry += 4;
            }
        } else {
            trak.out[NGX_HTTP_MP4_STSS_DATA] = false;
        }

        let atom_size = TABLE_ATOM_SIZEOF.wrapping_add(data.size());
        trak.size = trak.size.wrapping_add(atom_size);

        let atom = trak.buf[NGX_HTTP_MP4_STSS_ATOM];

        self.mem.set32(atom.pos, atom_size as u32);
        self.mem.set32(atom.pos + ATOM_ENTRIES, trak.sync_samples_entries);

        NGX_OK
    }

    /// ngx_http_mp4_crop_stss_data
    fn crop_stss_data(&mut self, i: usize, start: bool) {
        let trak = &mut self.trak[i];

        // sync samples starts from 1

        let start_sample: u32;

        if start {
            start_sample = trak.start_sample.wrapping_add(1) as u32;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stss crop start_sample:{}", start_sample);
        } else if self.length != 0 {
            start_sample = trak.end_sample.wrapping_add(1) as u32;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stss crop end_sample:{}", start_sample);
        } else {
            return;
        }

        let data = trak.buf[NGX_HTTP_MP4_STSS_DATA];

        let mut entries = trak.sync_samples_entries as usize;
        let mut entry = data.pos;
        let end = data.last;

        let mut found = false;

        while entry < end {
            let sample = self.mem.get32(entry);

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sync:{}", sample);

            if sample >= start_sample {
                found = true;
                break;
            }

            entries = entries.wrapping_sub(1);
            entry += 4;
        }

        if !found {
            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sample is out of mp4 stss atom");
        }

        // found:

        if start {
            trak.buf[NGX_HTTP_MP4_STSS_DATA].pos = entry;
            trak.sync_samples_entries = entries as u32;
        } else {
            trak.buf[NGX_HTTP_MP4_STSS_DATA].last = entry;
            trak.sync_samples_entries = (trak.sync_samples_entries as usize).wrapping_sub(entries) as u32;
        }
    }

    /// ngx_http_mp4_read_ctts_atom
    fn read_ctts_atom(&mut self, atom_data_size: u64) -> i64 {
        // composition offsets atom

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 ctts atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"ctts");

        if atom_data_size_of(TABLE_ATOM_SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 ctts atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let entries = self.mem.get32(atom_header + ATOM_ENTRIES);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "composition offset entries:{}", entries);

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_CTTS_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 ctts atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        self.trak[n].composition_offset_entries = entries;

        let atom_table = atom_header + TABLE_ATOM_SIZEOF;

        self.trak[n].buf[NGX_HTTP_MP4_CTTS_ATOM] = MBuf { pos: atom_header, last: atom_table };

        if atom_data_size_of(TABLE_ATOM_SIZEOF) + entries as u64 * CTTS_ENTRY_SIZEOF as u64 > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 ctts atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let atom_end = atom_table + entries as usize * CTTS_ENTRY_SIZEOF;

        let trak = &mut self.trak[n];

        trak.buf[NGX_HTTP_MP4_CTTS_DATA] = MBuf { pos: atom_table, last: atom_end };

        trak.out[NGX_HTTP_MP4_CTTS_ATOM] = true;
        trak.out[NGX_HTTP_MP4_CTTS_DATA] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_update_ctts_atom
    fn update_ctts_atom(&mut self, i: usize) {
        // mdia.minf.stbl.ctts updating requires trak->start_sample
        // from mdia.minf.stbl.stts which depends on value from mdia.mdhd
        // atom which may reside after mdia.minf

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 ctts atom update");

        if !self.trak[i].out[NGX_HTTP_MP4_CTTS_DATA] {
            return;
        }

        self.crop_ctts_data(i, true);
        self.crop_ctts_data(i, false);

        let trak = &mut self.trak[i];

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "composition offset entries:{}", trak.composition_offset_entries);

        if trak.composition_offset_entries == 0 {
            trak.out[NGX_HTTP_MP4_CTTS_ATOM] = false;
            trak.out[NGX_HTTP_MP4_CTTS_DATA] = false;
            return;
        }

        let atom_size = TABLE_ATOM_SIZEOF.wrapping_add(trak.buf[NGX_HTTP_MP4_CTTS_DATA].size());
        trak.size = trak.size.wrapping_add(atom_size);

        let atom = trak.buf[NGX_HTTP_MP4_CTTS_ATOM];

        self.mem.set32(atom.pos, atom_size as u32);
        self.mem.set32(atom.pos + ATOM_ENTRIES, trak.composition_offset_entries);
    }

    /// ngx_http_mp4_crop_ctts_data
    fn crop_ctts_data(&mut self, i: usize, start: bool) {
        let trak = &mut self.trak[i];

        // sync samples starts from 1

        let mut start_sample: u32;

        if start {
            start_sample = trak.start_sample.wrapping_add(1) as u32;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 ctts crop start_sample:{}", start_sample);
        } else if self.length != 0 {
            start_sample = trak.end_sample.wrapping_sub(trak.start_sample).wrapping_add(1) as u32;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 ctts crop end_sample:{}", start_sample);
        } else {
            return;
        }

        let data = trak.buf[NGX_HTTP_MP4_CTTS_DATA];

        let mut entries = trak.composition_offset_entries as usize;
        let mut entry = data.pos;
        let end = data.last;

        while entry < end {
            let count = self.mem.get32(entry);

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sample:{}, count:{}, offset:{}", start_sample, count, self.mem.get32(entry + 4));

            if start_sample <= count {
                let rest = start_sample.wrapping_sub(1);

                // found:

                if start {
                    self.mem.set32(entry, count.wrapping_sub(rest));
                    trak.buf[NGX_HTTP_MP4_CTTS_DATA].pos = entry;
                    trak.composition_offset_entries = entries as u32;
                } else {
                    self.mem.set32(entry, rest);
                    trak.buf[NGX_HTTP_MP4_CTTS_DATA].last = entry + CTTS_ENTRY_SIZEOF;
                    trak.composition_offset_entries = (trak.composition_offset_entries as usize).wrapping_sub(entries.wrapping_sub(1)) as u32;
                }

                return;
            }

            start_sample -= count;
            entries = entries.wrapping_sub(1);
            entry += CTTS_ENTRY_SIZEOF;
        }

        if start {
            trak.buf[NGX_HTTP_MP4_CTTS_DATA].pos = end;
            trak.composition_offset_entries = 0;
        }
    }

    /// ngx_http_mp4_read_stsc_atom
    fn read_stsc_atom(&mut self, atom_data_size: u64) -> i64 {
        // sample-to-chunk atom

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stsc atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"stsc");

        if atom_data_size_of(TABLE_ATOM_SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stsc atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let entries = self.mem.get32(atom_header + ATOM_ENTRIES);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sample-to-chunk entries:{}", entries);

        if atom_data_size_of(TABLE_ATOM_SIZEOF) + entries as u64 * STSC_ENTRY_SIZEOF as u64 > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stsc atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let atom_table = atom_header + TABLE_ATOM_SIZEOF;
        let atom_end = atom_table + entries as usize * STSC_ENTRY_SIZEOF;

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_STSC_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 stsc atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.sample_to_chunk_entries = entries;

        trak.buf[NGX_HTTP_MP4_STSC_ATOM] = MBuf { pos: atom_header, last: atom_table };
        trak.buf[NGX_HTTP_MP4_STSC_DATA] = MBuf { pos: atom_table, last: atom_end };

        trak.out[NGX_HTTP_MP4_STSC_ATOM] = true;
        trak.out[NGX_HTTP_MP4_STSC_DATA] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_update_stsc_atom
    fn update_stsc_atom(&mut self, i: usize) -> i64 {
        // mdia.minf.stbl.stsc updating requires trak->start_sample
        // from mdia.minf.stbl.stts which depends on value from mdia.mdhd
        // atom which may reside after mdia.minf

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stsc atom update");

        if !self.trak[i].out[NGX_HTTP_MP4_STSC_DATA] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "no mp4 stsc atoms were found in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if self.trak[i].sample_to_chunk_entries == 0 {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "zero number of entries in stsc atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if self.crop_stsc_data(i, true) != NGX_OK {
            return NGX_ERROR;
        }

        if self.crop_stsc_data(i, false) != NGX_OK {
            return NGX_ERROR;
        }

        let trak = &mut self.trak[i];

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sample-to-chunk entries:{}", trak.sample_to_chunk_entries);

        let data = trak.buf[NGX_HTTP_MP4_STSC_DATA];

        let mut entry = data.pos;
        let end = data.last.min(self.mem.0.len());

        while entry < end {
            let chunk = (self.mem.get32(entry) as usize).wrapping_sub(trak.start_chunk) as u32;
            self.mem.set32(entry, chunk);
            entry += STSC_ENTRY_SIZEOF;
        }

        let atom_size = TABLE_ATOM_SIZEOF + trak.sample_to_chunk_entries as usize * STSC_ENTRY_SIZEOF;

        trak.size += atom_size;

        let atom = trak.buf[NGX_HTTP_MP4_STSC_ATOM];

        self.mem.set32(atom.pos, atom_size as u32);
        self.mem.set32(atom.pos + ATOM_ENTRIES, trak.sample_to_chunk_entries);

        NGX_OK
    }

    /// ngx_http_mp4_crop_stsc_data
    fn crop_stsc_data(&mut self, i: usize, start: bool) -> i64 {
        let trak = &mut self.trak[i];

        let mut entries = trak.sample_to_chunk_entries.wrapping_sub(1) as usize;
        let mut start_sample: u32;
        let mut samples: u32;

        if start {
            start_sample = trak.start_sample as u32;

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stsc crop start_sample:{}", start_sample);
        } else if self.length != 0 {
            start_sample = trak.end_sample.wrapping_sub(trak.start_sample) as u32;
            samples = 0;

            if trak.out[NGX_HTTP_MP4_STSC_START] {
                let entry = trak.buf[NGX_HTTP_MP4_STSC_START].pos;
                samples = self.mem.get32(entry + STSC_SAMPLES);
                entries = entries.wrapping_sub(1);

                if samples > start_sample {
                    samples = start_sample;
                    self.mem.set32(entry + STSC_SAMPLES, samples);
                }

                start_sample -= samples;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stsc crop end_sample:{}, ext_samples:{}", start_sample, samples);
        } else {
            return NGX_OK;
        }

        let data = trak.buf[NGX_HTTP_MP4_STSC_DATA];

        let mut entry = data.pos;
        let end = data.last;

        let mut chunk = self.mem.get32(entry);
        samples = self.mem.get32(entry + STSC_SAMPLES);
        let mut id = self.mem.get32(entry + STSC_ID);
        let mut prev_samples: u32 = 0;
        entry += STSC_ENTRY_SIZEOF;

        let mut next_chunk: u32;
        let mut found = false;

        while entry < end {
            next_chunk = self.mem.get32(entry);

            if next_chunk < chunk {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "unordered mp4 stsc chunks in \"{}\"", B(&self.name));
                return NGX_ERROR;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sample:{}, chunk:{}, chunks:{}, samples:{}, id:{}", start_sample, chunk, next_chunk - chunk, samples, id);

            let n = (next_chunk - chunk) as u64 * samples as u64;

            if (start_sample as u64) < n {
                found = true;
                break;
            }

            start_sample = (start_sample as u64 - n) as u32;

            if next_chunk > chunk {
                prev_samples = samples;
            }

            chunk = next_chunk;
            samples = self.mem.get32(entry + STSC_SAMPLES);
            id = self.mem.get32(entry + STSC_ID);
            entries = entries.wrapping_sub(1);
            entry += STSC_ENTRY_SIZEOF;
        }

        if found {
            next_chunk = self.mem.get32(entry);
        } else {
            next_chunk = trak.chunks.wrapping_add(1);

            if next_chunk < chunk {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "unordered mp4 stsc chunks in \"{}\"", B(&self.name));
                return NGX_ERROR;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sample:{}, chunk:{}, chunks:{}, samples:{}", start_sample, chunk, next_chunk - chunk, samples);

            let n = (next_chunk - chunk) as u64 * samples as u64;

            if start_sample as u64 > n {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "{} time is out mp4 stsc chunks in \"{}\"", if start { "start" } else { "end" }, B(&self.name));
                return NGX_ERROR;
            }
        }

        // found:

        entries = entries.wrapping_add(1);
        entry = entry.wrapping_sub(STSC_ENTRY_SIZEOF);

        if samples == 0 {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "zero number of samples in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if chunk == 0 {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "zero chunk in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let mut target_chunk = (chunk - 1) as usize;
        target_chunk += (start_sample / samples) as usize;
        let chunk_samples = (start_sample % samples) as usize;

        if start {
            trak.buf[NGX_HTTP_MP4_STSC_DATA].pos = entry;

            trak.sample_to_chunk_entries = entries as u32;
            trak.start_chunk = target_chunk;
            trak.start_chunk_samples = chunk_samples;

            self.mem.set32(entry, trak.start_chunk.wrapping_add(1) as u32);

            samples = samples.wrapping_sub(chunk_samples as u32);

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "start_chunk:{}, start_chunk_samples:{}", trak.start_chunk, trak.start_chunk_samples);
        } else {
            if start_sample != 0 {
                trak.buf[NGX_HTTP_MP4_STSC_DATA].last = entry.wrapping_add(STSC_ENTRY_SIZEOF);
                trak.sample_to_chunk_entries = (trak.sample_to_chunk_entries as usize).wrapping_sub(entries.wrapping_sub(1)) as u32;
                trak.end_chunk_samples = samples as usize;
            } else {
                trak.buf[NGX_HTTP_MP4_STSC_DATA].last = entry;
                trak.sample_to_chunk_entries = (trak.sample_to_chunk_entries as usize).wrapping_sub(entries) as u32;
                trak.end_chunk_samples = prev_samples as usize;
            }

            if chunk_samples != 0 {
                trak.end_chunk = target_chunk + 1;
                trak.end_chunk_samples = chunk_samples;
            } else {
                trak.end_chunk = target_chunk;
            }

            samples = chunk_samples as u32;
            next_chunk = chunk.wrapping_add(1);

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "end_chunk:{}, end_chunk_samples:{}", trak.end_chunk, trak.end_chunk_samples);
        }

        if chunk_samples != 0 && (next_chunk as usize).wrapping_sub(target_chunk) == 2 {
            self.mem.set32(entry + STSC_SAMPLES, samples);
        } else if chunk_samples != 0 && start {
            let first = trak.stsc_start_chunk_entry;
            self.mem.set32(first, 1);
            self.mem.set32(first + STSC_SAMPLES, samples);
            self.mem.set32(first + STSC_ID, id);

            trak.buf[NGX_HTTP_MP4_STSC_START] = MBuf { pos: first, last: first + STSC_ENTRY_SIZEOF };

            trak.out[NGX_HTTP_MP4_STSC_START] = true;

            self.mem.set32(entry, trak.start_chunk.wrapping_add(2) as u32);

            trak.sample_to_chunk_entries = trak.sample_to_chunk_entries.wrapping_add(1);
        } else if chunk_samples != 0 {
            let first = trak.stsc_end_chunk_entry;
            self.mem.set32(first, trak.end_chunk.wrapping_sub(trak.start_chunk) as u32);
            self.mem.set32(first + STSC_SAMPLES, samples);
            self.mem.set32(first + STSC_ID, id);

            trak.buf[NGX_HTTP_MP4_STSC_END] = MBuf { pos: first, last: first + STSC_ENTRY_SIZEOF };

            trak.out[NGX_HTTP_MP4_STSC_END] = true;

            trak.sample_to_chunk_entries = trak.sample_to_chunk_entries.wrapping_add(1);
        }

        NGX_OK
    }

    /// ngx_http_mp4_read_stsz_atom
    fn read_stsz_atom(&mut self, atom_data_size: u64) -> i64 {
        // sample sizes atom

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stsz atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"stsz");

        if atom_data_size_of(stsz::SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stsz atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let size = self.mem.get32(atom_header + stsz::UNIFORM_SIZE);
        let entries = self.mem.get32(atom_header + stsz::ENTRIES);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "sample uniform size:{}, entries:{}", size, entries);

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_STSZ_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 stsz atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        self.trak[n].sample_sizes_entries = entries;

        let atom_table = atom_header + stsz::SIZEOF;

        self.trak[n].buf[NGX_HTTP_MP4_STSZ_ATOM] = MBuf { pos: atom_header, last: atom_table };

        self.trak[n].out[NGX_HTTP_MP4_STSZ_ATOM] = true;

        if size == 0 {
            if atom_data_size_of(stsz::SIZEOF) + entries as u64 * 4 > atom_data_size {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stsz atom too small", B(&self.name));
                return NGX_ERROR;
            }

            let atom_end = atom_table + entries as usize * 4;

            let trak = &mut self.trak[n];

            trak.buf[NGX_HTTP_MP4_STSZ_DATA] = MBuf { pos: atom_table, last: atom_end };

            trak.out[NGX_HTTP_MP4_STSZ_DATA] = true;
        } else {
            // if size != 0 then all samples are the same size
            // TODO : chunk samples
            let atom_size = ATOM_HEADER + atom_data_size as usize;
            self.mem.set32(atom_header, atom_size as u32);
            self.trak[n].size += atom_size;
        }

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_update_stsz_atom
    fn update_stsz_atom(&mut self, i: usize) -> i64 {
        // mdia.minf.stbl.stsz updating requires trak->start_sample
        // from mdia.minf.stbl.stts which depends on value from mdia.mdhd
        // atom which may reside after mdia.minf

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stsz atom update");

        let trak = &mut self.trak[i];

        if trak.out[NGX_HTTP_MP4_STSZ_DATA] {
            let mut entries = trak.sample_sizes_entries;

            if trak.start_sample >= entries as usize {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "start time is out mp4 stsz samples in \"{}\"", B(&self.name));
                return NGX_ERROR;
            }

            entries = (entries as usize).wrapping_sub(trak.start_sample) as u32;

            let data = &mut trak.buf[NGX_HTTP_MP4_STSZ_DATA];

            data.pos = data.pos.wrapping_add(trak.start_sample.wrapping_mul(4));
            let end = data.pos;

            let mut pos = end.wrapping_sub(trak.start_chunk_samples.wrapping_mul(4));
            while pos < end {
                trak.start_chunk_samples_size = trak.start_chunk_samples_size.wrapping_add(self.mem.get32(pos) as u64);
                pos += 4;
            }

            ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "chunk samples sizes:{}", trak.start_chunk_samples_size);

            if trak.start_chunk_samples_size > self.end as u64 {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "too large mp4 start samples size in \"{}\"", B(&self.name));
                return NGX_ERROR;
            }

            if self.length != 0 {
                if trak.end_sample.wrapping_sub(trak.start_sample) > entries as usize {
                    ngx_log_error!(NGX_LOG_ERR, self.log, None, "end time is out mp4 stsz samples in \"{}\"", B(&self.name));
                    return NGX_ERROR;
                }

                entries = trak.end_sample.wrapping_sub(trak.start_sample) as u32;

                let data = &mut trak.buf[NGX_HTTP_MP4_STSZ_DATA];

                data.last = data.pos + entries as usize * 4;
                let end = data.last;

                let mut pos = end.wrapping_sub(trak.end_chunk_samples.wrapping_mul(4));
                while pos < end {
                    trak.end_chunk_samples_size = trak.end_chunk_samples_size.wrapping_add(self.mem.get32(pos) as u64);
                    pos += 4;
                }

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stsz end_chunk_samples_size:{}", trak.end_chunk_samples_size);

                if trak.end_chunk_samples_size > self.end as u64 {
                    ngx_log_error!(NGX_LOG_ERR, self.log, None, "too large mp4 end samples size in \"{}\"", B(&self.name));
                    return NGX_ERROR;
                }
            }

            let atom_size = stsz::SIZEOF.wrapping_add(trak.buf[NGX_HTTP_MP4_STSZ_DATA].size());
            trak.size = trak.size.wrapping_add(atom_size);

            let atom = trak.buf[NGX_HTTP_MP4_STSZ_ATOM];

            self.mem.set32(atom.pos, atom_size as u32);
            self.mem.set32(atom.pos + stsz::ENTRIES, entries);
        }

        NGX_OK
    }

    /// ngx_http_mp4_read_stco_atom
    fn read_stco_atom(&mut self, atom_data_size: u64) -> i64 {
        // chunk offsets atom

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stco atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"stco");

        if atom_data_size_of(TABLE_ATOM_SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stco atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let entries = self.mem.get32(atom_header + ATOM_ENTRIES);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "chunks:{}", entries);

        if atom_data_size_of(TABLE_ATOM_SIZEOF) + entries as u64 * 4 > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 stco atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let atom_table = atom_header + TABLE_ATOM_SIZEOF;
        let atom_end = atom_table + entries as usize * 4;

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_STCO_ATOM] || self.trak[n].out[NGX_HTTP_MP4_CO64_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 stco/co64 atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.chunks = entries;

        trak.buf[NGX_HTTP_MP4_STCO_ATOM] = MBuf { pos: atom_header, last: atom_table };
        trak.buf[NGX_HTTP_MP4_STCO_DATA] = MBuf { pos: atom_table, last: atom_end };

        trak.out[NGX_HTTP_MP4_STCO_ATOM] = true;
        trak.out[NGX_HTTP_MP4_STCO_DATA] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_update_stco_atom
    fn update_stco_atom(&mut self, i: usize) -> i64 {
        // mdia.minf.stbl.stco updating requires trak->start_chunk
        // from mdia.minf.stbl.stsc which depends on value from mdia.mdhd
        // atom which may reside after mdia.minf

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stco atom update");

        let trak = &mut self.trak[i];

        if !trak.out[NGX_HTTP_MP4_STCO_DATA] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "no mp4 stco atoms were found in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if trak.start_chunk >= trak.chunks as usize {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "start time is out mp4 stco chunks in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let data = &mut trak.buf[NGX_HTTP_MP4_STCO_DATA];

        data.pos += trak.start_chunk * 4;
        let data_pos = data.pos;

        let mut chunk_offset = self.mem.get32(data_pos) as u64;
        let mut samples_size = trak.start_chunk_samples_size;

        if chunk_offset > (self.end as u64).wrapping_sub(samples_size) || chunk_offset + samples_size > NGX_MAX_UINT32_VALUE {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "too large chunk offset in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        trak.start_offset = (chunk_offset + samples_size) as i64;
        self.mem.set32(data_pos, trak.start_offset as u32);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "start chunk offset:{}", trak.start_offset);

        let entries: u32;

        if self.length != 0 {
            if trak.end_chunk > trak.chunks as usize {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "end time is out mp4 stco chunks in \"{}\"", B(&self.name));
                return NGX_ERROR;
            }

            entries = trak.end_chunk.wrapping_sub(trak.start_chunk) as u32;

            let data = &mut trak.buf[NGX_HTTP_MP4_STCO_DATA];

            data.last = data.pos + entries as usize * 4;

            if entries != 0 {
                chunk_offset = self.mem.get32(data.last - 4) as u64;
                samples_size = trak.end_chunk_samples_size;

                if chunk_offset > (self.end as u64).wrapping_sub(samples_size) || chunk_offset + samples_size > NGX_MAX_UINT32_VALUE {
                    ngx_log_error!(NGX_LOG_ERR, self.log, None, "too large chunk offset in \"{}\"", B(&self.name));
                    return NGX_ERROR;
                }

                trak.end_offset = (chunk_offset + samples_size) as i64;

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "end chunk offset:{}", trak.end_offset);
            }
        } else {
            entries = trak.chunks.wrapping_sub(trak.start_chunk as u32);
            trak.end_offset = self.mdat_data.file_last;
        }

        if entries == 0 {
            trak.start_offset = self.end;
            trak.end_offset = 0;
        }

        let atom_size = TABLE_ATOM_SIZEOF.wrapping_add(trak.buf[NGX_HTTP_MP4_STCO_DATA].size());
        trak.size = trak.size.wrapping_add(atom_size);

        let atom = trak.buf[NGX_HTTP_MP4_STCO_ATOM];

        self.mem.set32(atom.pos, atom_size as u32);
        self.mem.set32(atom.pos + ATOM_ENTRIES, entries);

        NGX_OK
    }

    /// ngx_http_mp4_adjust_stco_atom
    fn adjust_stco_atom(&mut self, i: usize, adjustment: i32) {
        // moov.trak.mdia.minf.stbl.stco adjustment requires
        // minimal start offset of all traks and new moov atom size

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 stco atom adjustment");

        let data = self.trak[i].buf[NGX_HTTP_MP4_STCO_DATA];
        let mut entry = data.pos;
        let end = data.last.min(self.mem.0.len());

        while entry < end {
            let offset = self.mem.get32(entry).wrapping_add(adjustment as u32);
            self.mem.set32(entry, offset);
            entry += 4;
        }
    }

    /// ngx_http_mp4_read_co64_atom
    fn read_co64_atom(&mut self, atom_data_size: u64) -> i64 {
        // chunk offsets atom

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 co64 atom");

        let atom_header = self.atom_header();
        self.mem.set_atom_name(atom_header, b"co64");

        if atom_data_size_of(TABLE_ATOM_SIZEOF) > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 co64 atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let entries = self.mem.get32(atom_header + ATOM_ENTRIES);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "chunks:{}", entries);

        if atom_data_size_of(TABLE_ATOM_SIZEOF) + entries as u64 * 8 > atom_data_size {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "\"{}\" mp4 co64 atom too small", B(&self.name));
            return NGX_ERROR;
        }

        let atom_table = atom_header + TABLE_ATOM_SIZEOF;
        let atom_end = atom_table + entries as usize * 8;

        let n = self.last_trak();

        if self.trak[n].out[NGX_HTTP_MP4_STCO_ATOM] || self.trak[n].out[NGX_HTTP_MP4_CO64_ATOM] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "duplicate mp4 stco/co64 atom in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let trak = &mut self.trak[n];

        trak.chunks = entries;

        trak.buf[NGX_HTTP_MP4_CO64_ATOM] = MBuf { pos: atom_header, last: atom_table };
        trak.buf[NGX_HTTP_MP4_CO64_DATA] = MBuf { pos: atom_table, last: atom_end };

        trak.out[NGX_HTTP_MP4_CO64_ATOM] = true;
        trak.out[NGX_HTTP_MP4_CO64_DATA] = true;

        self.atom_next(atom_data_size);

        NGX_OK
    }

    /// ngx_http_mp4_update_co64_atom
    fn update_co64_atom(&mut self, i: usize) -> i64 {
        // mdia.minf.stbl.co64 updating requires trak->start_chunk
        // from mdia.minf.stbl.stsc which depends on value from mdia.mdhd
        // atom which may reside after mdia.minf

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 co64 atom update");

        let trak = &mut self.trak[i];

        if !trak.out[NGX_HTTP_MP4_CO64_DATA] {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "no mp4 co64 atoms were found in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        if trak.start_chunk >= trak.chunks as usize {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "start time is out mp4 co64 chunks in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        let data = &mut trak.buf[NGX_HTTP_MP4_CO64_DATA];

        data.pos += trak.start_chunk * 8;
        let data_pos = data.pos;

        let mut chunk_offset = self.mem.get64(data_pos);
        let mut samples_size = trak.start_chunk_samples_size;

        if chunk_offset > (self.end as u64).wrapping_sub(samples_size) {
            ngx_log_error!(NGX_LOG_ERR, self.log, None, "too large chunk offset in \"{}\"", B(&self.name));
            return NGX_ERROR;
        }

        trak.start_offset = chunk_offset.wrapping_add(samples_size) as i64;
        self.mem.set64(data_pos, trak.start_offset as u64);

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "start chunk offset:{}", trak.start_offset);

        let entries: u64;

        if self.length != 0 {
            if trak.end_chunk > trak.chunks as usize {
                ngx_log_error!(NGX_LOG_ERR, self.log, None, "end time is out mp4 co64 chunks in \"{}\"", B(&self.name));
                return NGX_ERROR;
            }

            entries = trak.end_chunk.wrapping_sub(trak.start_chunk) as u64;

            let data = &mut trak.buf[NGX_HTTP_MP4_CO64_DATA];

            data.last = data.pos.wrapping_add((entries as usize).wrapping_mul(8));

            if entries != 0 {
                chunk_offset = self.mem.get64(data.last.wrapping_sub(8));
                samples_size = trak.end_chunk_samples_size;

                if chunk_offset > (self.end as u64).wrapping_sub(samples_size) {
                    ngx_log_error!(NGX_LOG_ERR, self.log, None, "too large chunk offset in \"{}\"", B(&self.name));
                    return NGX_ERROR;
                }

                trak.end_offset = chunk_offset.wrapping_add(samples_size) as i64;

                ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "end chunk offset:{}", trak.end_offset);
            }
        } else {
            entries = (trak.chunks as usize).wrapping_sub(trak.start_chunk) as u64;
            trak.end_offset = self.mdat_data.file_last;
        }

        if entries == 0 {
            trak.start_offset = self.end;
            trak.end_offset = 0;
        }

        let atom_size = TABLE_ATOM_SIZEOF.wrapping_add(trak.buf[NGX_HTTP_MP4_CO64_DATA].size());
        trak.size = trak.size.wrapping_add(atom_size);

        let atom = trak.buf[NGX_HTTP_MP4_CO64_ATOM];

        self.mem.set32(atom.pos, atom_size as u32);
        self.mem.set32(atom.pos + ATOM_ENTRIES, entries as u32);

        NGX_OK
    }

    /// ngx_http_mp4_adjust_co64_atom
    fn adjust_co64_atom(&mut self, i: usize, adjustment: i64) {
        // moov.trak.mdia.minf.stbl.co64 adjustment requires
        // minimal start offset of all traks and new moov atom size

        ngx_log_debug!(NGX_LOG_DEBUG_HTTP, self.log, "mp4 co64 atom adjustment");

        let data = self.trak[i].buf[NGX_HTTP_MP4_CO64_DATA];
        let mut entry = data.pos;
        let end = data.last.min(self.mem.0.len());

        while entry < end {
            let offset = self.mem.get64(entry).wrapping_add(adjustment as u64);
            self.mem.set64(entry, offset);
            entry += 8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ngx_core::buf::BufData;
    use std::cell::RefCell;
    use std::os::unix::io::AsRawFd;

    fn capture() -> (Log, Rc<RefCell<Vec<u8>>>) {
        let logged: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let lg = logged.clone();
        let chain = LogChain::new();
        chain.insert(LogEntry::new(NGX_LOG_INFO, LogWriter::Custom(Rc::new(move |_, line: &[u8]| lg.borrow_mut().extend_from_slice(line)))));
        (Log::new(chain), logged)
    }

    fn atom(name: &[u8; 4], payload: &[u8], hdr64: bool) -> Vec<u8> {
        let mut v = Vec::new();
        if hdr64 {
            v.extend_from_slice(&1u32.to_be_bytes());
            v.extend_from_slice(name);
            v.extend_from_slice(&((16 + payload.len()) as u64).to_be_bytes());
        } else {
            v.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
            v.extend_from_slice(name);
        }
        v.extend_from_slice(payload);
        v
    }

    fn be32(v: &[u32]) -> Vec<u8> {
        v.iter().flat_map(|n| n.to_be_bytes()).collect()
    }

    #[derive(Clone, Copy, Default)]
    struct Layout {
        moov_first: bool,
        hdr64: bool,
        co64: bool,
    }

    const SAMPLES: u32 = 10;
    const SAMPLE_SIZE: usize = 100;

    /// One video trak of 10 samples of a second, a chunk each, the sample
    /// k of 100 bytes k, sync samples 1 and 6.
    fn moov(l: Layout, data_offset: u64) -> Vec<u8> {
        let h = l.hdr64;
        let mvhd = atom(b"mvhd", &[be32(&[0, 0, 0, 1000, SAMPLES * 1000]), vec![0; 80]].concat(), h);
        let tkhd = atom(b"tkhd", &[be32(&[0, 0, 0, 1, 0, SAMPLES * 1000]), vec![0; 60]].concat(), h);
        let mdhd = atom(b"mdhd", &[be32(&[0, 0, 0, 1000, SAMPLES * 1000]), vec![0; 4]].concat(), h);
        let hdlr = atom(b"hdlr", b"\0\0\0\0\0\0\0\0vide\0\0\0\0\0\0\0\0\0\0\0\0\0", h);
        let vmhd = atom(b"vmhd", &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], h);
        let dinf = atom(b"dinf", &atom(b"dref", &be32(&[0, 0]), false), h);
        let stsd = atom(b"stsd", &[be32(&[0, 1, 8]), b"avc1".to_vec()].concat(), h);
        let stts = atom(b"stts", &be32(&[0, 1, SAMPLES, 1000]), h);
        let stss = atom(b"stss", &be32(&[0, 2, 1, 6]), h);
        let stsc = atom(b"stsc", &be32(&[0, 1, 1, 1, 1]), h);
        let stsz = atom(b"stsz", &[be32(&[0, 0, SAMPLES]), be32(&[SAMPLE_SIZE as u32; SAMPLES as usize])].concat(), h);
        let offsets: Vec<u64> = (0..SAMPLES as u64).map(|k| data_offset + k * SAMPLE_SIZE as u64).collect();
        let stco = if l.co64 {
            atom(b"co64", &[be32(&[0, SAMPLES]), offsets.iter().flat_map(|o| o.to_be_bytes()).collect()].concat(), h)
        } else {
            atom(b"stco", &[be32(&[0, SAMPLES]), be32(&offsets.iter().map(|&o| o as u32).collect::<Vec<_>>())].concat(), h)
        };
        let stbl = atom(b"stbl", &[stsd, stts, stss, stsc, stsz, stco].concat(), h);
        let minf = atom(b"minf", &[vmhd, dinf, stbl].concat(), h);
        let mdia = atom(b"mdia", &[mdhd, hdlr, minf].concat(), h);
        let trak = atom(b"trak", &[tkhd, mdia].concat(), h);
        atom(b"moov", &[mvhd, trak].concat(), false)
    }

    fn build(l: Layout) -> Vec<u8> {
        let ftyp = atom(b"ftyp", b"isom\0\0\x02\0isomiso2", false);
        let data: Vec<u8> = (0..SAMPLES as u8).flat_map(|k| vec![k; SAMPLE_SIZE]).collect();
        let mdat = atom(b"mdat", &data, false);

        if l.moov_first {
            let size = moov(l, 0).len();
            [ftyp.clone(), moov(l, (ftyp.len() + size + 8) as u64), mdat].concat()
        } else {
            [ftyp.clone(), mdat, moov(l, (ftyp.len() + 8) as u64)].concat()
        }
    }

    struct Run {
        rc: i64,
        body: Vec<u8>,
        content_length: i64,
        logged: String,
    }

    fn run(name: &str, file: &[u8], start: usize, length: usize, start_key_frame: bool, buffer_size: usize) -> Run {
        let path = std::env::temp_dir().join(format!("rnginx-mp4-{}-{}", std::process::id(), name));
        std::fs::write(&path, file).unwrap();
        let f = std::fs::File::open(&path).unwrap();

        let (log, logged) = capture();
        let conf = Mp4Conf { buffer_size: Val::set(buffer_size), max_buffer_size: Val::set(300), start_key_frame: Val::set(start_key_frame) };
        let mut mp4 = Mp4File::new(f.as_raw_fd(), name.as_bytes().to_vec(), log, file.len() as i64, start, length, &conf, true);

        let rc = mp4.process();
        let mut body = Vec::new();

        if rc == NGX_OK {
            for b in mp4.out() {
                match &b.data {
                    BufData::Memory(v) => body.extend_from_slice(&v[b.pos..b.last]),
                    BufData::File(_) => body.extend_from_slice(&file[b.file_pos as usize..b.file_last as usize]),
                    BufData::None => {}
                }
            }
        }

        drop(f);
        std::fs::remove_file(&path).unwrap();

        let logged = String::from_utf8_lossy(&logged.borrow()).into_owned();

        Run { rc, body, content_length: mp4.content_length, logged }
    }

    /// The atom path (e.g. "moov/trak/mdia/minf/stbl/stco") of an mp4: its
    /// data, the header of 64 bits taken into account.
    fn find<'a>(buf: &'a [u8], path: &str) -> Option<&'a [u8]> {
        let (name, rest) = path.split_once('/').unwrap_or((path, ""));
        let mut pos = 0;

        while pos + 8 <= buf.len() {
            let mut size = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            let mut hdr = 8;

            if size == 1 {
                size = u64::from_be_bytes(buf[pos + 8..pos + 16].try_into().unwrap()) as usize;
                hdr = 16;
            }

            assert!(size >= hdr && pos + size <= buf.len(), "atom sizes");

            if &buf[pos + 4..pos + 8] == name.as_bytes() {
                let data = &buf[pos + hdr..pos + size];
                return if rest.is_empty() { Some(data) } else { find(data, rest) };
            }

            pos += size;
        }

        None
    }

    fn table32(data: &[u8], skip: usize) -> Vec<u32> {
        let n = u32::from_be_bytes(data[skip - 4..skip].try_into().unwrap()) as usize;
        (0..n).map(|i| u32::from_be_bytes(data[skip + 4 * i..skip + 4 * i + 4].try_into().unwrap())).collect()
    }

    /// The samples of the response, by the rebuilt tables: the value of
    /// the bytes of each (all equal) from the chunk offsets.
    fn samples(body: &[u8]) -> Vec<u8> {
        let stbl = find(body, "moov/trak/mdia/minf/stbl").expect("stbl");
        let sizes = table32(find(stbl, "stsz").unwrap(), 12);
        let offsets: Vec<u64> = match find(stbl, "co64") {
            Some(d) => {
                let n = u32::from_be_bytes(d[4..8].try_into().unwrap()) as usize;
                (0..n).map(|i| u64::from_be_bytes(d[8 + 8 * i..16 + 8 * i].try_into().unwrap())).collect()
            }
            None => table32(find(stbl, "stco").unwrap(), 8).iter().map(|&o| o as u64).collect(),
        };

        // a sample per chunk: the samples of the first entry of stsc
        let stsc = find(stbl, "stsc").unwrap();
        assert_eq!(&stsc[12..16], &1u32.to_be_bytes());
        assert_eq!(offsets.len(), sizes.len());

        offsets.iter().zip(&sizes).map(|(&o, &n)| {
            let s = &body[o as usize..o as usize + n as usize];
            assert!(s.iter().all(|&b| b == s[0]), "a sample at its offset");
            s[0]
        }).collect()
    }

    fn layouts() -> Vec<Layout> {
        let mut v = Vec::new();
        for moov_first in [false, true] {
            for hdr64 in [false, true] {
                for co64 in [false, true] {
                    v.push(Layout { moov_first, hdr64, co64 });
                }
            }
        }
        v
    }

    #[test]
    fn crop_start_and_end() {
        for (i, l) in layouts().into_iter().enumerate() {
            let file = build(l);

            let r = run(&format!("start{}", i), &file, 2000, 0, false, 512 * 1024);
            assert_eq!(r.rc, NGX_OK, "{}", r.logged);
            assert_eq!(r.content_length as usize, r.body.len());
            assert_eq!(samples(&r.body), vec![2, 3, 4, 5, 6, 7, 8, 9]);

            let stbl = find(&r.body, "moov/trak/mdia/minf/stbl").unwrap();
            assert_eq!(table32(find(stbl, "stss").unwrap(), 8), vec![4]);
            assert_eq!(&find(stbl, "stts").unwrap()[4..16], &be32(&[1, 8, 1000])[..]);
            assert!(find(&r.body, "moov/trak/edts").is_none());

            let mdhd = find(&r.body, "moov/trak/mdia/mdhd").unwrap();
            assert_eq!(&mdhd[16..20], &8000u32.to_be_bytes());

            let r = run(&format!("range{}", i), &file, 2500, 3500, false, 512 * 1024);
            assert_eq!(r.rc, NGX_OK, "{}", r.logged);
            assert_eq!(r.content_length as usize, r.body.len());
            assert_eq!(samples(&r.body), vec![2, 3, 4]);

            let r = run(&format!("end{}", i), &file, 0, 5600, false, 512 * 1024);
            assert_eq!(r.rc, NGX_OK, "{}", r.logged);
            assert_eq!(samples(&r.body), vec![0, 1, 2, 3, 4]);
            assert_eq!(&find(&r.body, "moov/mvhd").unwrap()[16..20], &5600u32.to_be_bytes());
        }
    }

    #[test]
    fn start_key_frame() {
        for (i, l) in layouts().into_iter().enumerate() {
            let r = run(&format!("key{}", i), &build(l), 2000, 0, true, 512 * 1024);
            assert_eq!(r.rc, NGX_OK, "{}", r.logged);

            // from the sync sample before, the samples up to the start
            // time skipped by the edit list
            assert_eq!(samples(&r.body), (0..10).collect::<Vec<u8>>());

            let elst = find(&r.body, "moov/trak/edts/elst").expect("elst");
            assert_eq!(elst[0], 1);
            assert_eq!(&elst[4..8], &1u32.to_be_bytes());
            assert_eq!(&elst[8..16], &8000u64.to_be_bytes());
            assert_eq!(&elst[16..24], &2000u64.to_be_bytes());
            assert_eq!(&find(&r.body, "moov/trak/mdia/mdhd").unwrap()[16..20], &10000u32.to_be_bytes());
        }
    }

    #[test]
    fn whole_file_and_errors() {
        // moov before mdat and the whole file asked for: the file as is
        let r = run("whole", &build(Layout { moov_first: true, ..Default::default() }), 0, 0, false, 512 * 1024);
        assert_eq!(r.rc, NGX_DECLINED);

        // the moov moved before mdat
        let file = build(Layout::default());
        let r = run("faststart", &file, 0, 0, false, 512 * 1024);
        assert_eq!(r.rc, NGX_OK, "{}", r.logged);
        assert_eq!(r.body.len(), file.len());
        assert_eq!(samples(&r.body), (0..10).collect::<Vec<u8>>());

        // the moov is larger than mp4_buffer_size and mp4_max_buffer_size
        let r = run("toolarge", &file, 1000, 0, false, 256);
        assert_eq!(r.rc, NGX_ERROR);
        assert!(r.logged.contains("\"toolarge\" mp4 moov atom is too large:"), "{}", r.logged);
        assert!(r.logged.contains("you may want to increase mp4_max_buffer_size"), "{}", r.logged);

        let r = run("beyond", &file, 11000, 0, false, 512 * 1024);
        assert_eq!(r.rc, NGX_ERROR);
        assert!(r.logged.contains("\"beyond\" mp4 start time exceeds file duration"), "{}", r.logged);

        let r = run("trunc", &file[..file.len() - 10], 1000, 0, false, 512 * 1024);
        assert_eq!(r.rc, NGX_ERROR);
        assert!(r.logged.contains("\"trunc\" mp4 atom too large:"), "{}", r.logged);

        let r = run("nomoov", &file[..file.len() - moov(Layout::default(), 0).len()], 1000, 0, false, 512 * 1024);
        assert_eq!(r.rc, NGX_ERROR);
        assert!(r.logged.contains("no mp4 trak atoms were found in \"nomoov\""), "{}", r.logged);
    }

    #[test]
    fn atofp_as_c() {
        assert_eq!(atofp(b"0", 3), 0);
        assert_eq!(atofp(b"1.5", 3), 1500);
        assert_eq!(atofp(b"10.123", 3), 10123);
        assert_eq!(atofp(b"100", 3), 100000);
        assert_eq!(atofp(b"0.1", 3), 100);
        assert_eq!(atofp(b"0.001", 3), 1);
        assert_eq!(atofp(b"7.1", 3), 7100);

        // more digits after the dot than asked for are skipped
        assert_eq!(atofp(b"2.123456789", 3), 2123);
        assert_eq!(atofp(b".5", 3), 500);
        assert_eq!(atofp(b"5.", 3), 5000);

        assert_eq!(atofp(b"", 3), NGX_ERROR);
        assert_eq!(atofp(b"1.2.3", 3), NGX_ERROR);
        assert_eq!(atofp(b"-1", 3), NGX_ERROR);
        assert_eq!(atofp(b"1x", 3), NGX_ERROR);

        // the overflow checks
        assert_eq!(atofp(b"9223372036854775", 3), 9223372036854775000);
        assert_eq!(atofp(b"9223372036854775.807", 3), i64::MAX);
        assert_eq!(atofp(b"9223372036854775.808", 3), NGX_ERROR);
        assert_eq!(atofp(b"9223372036854776", 3), NGX_ERROR);
    }
}
