# MP4 Module Implementation Guide

This document provides a detailed roadmap for completing the MP4 module implementation.

## Current Status

- Skeleton module created with configuration directives and basic handler structure
- Float parser for query parameters (ms format) implemented and tested
- Atom header parsing infrastructure started (AtomHeader struct)
- Module compiles successfully but doesn't process seek requests

## What Needs to Be Done

### 1. Complete Atom Reading Infrastructure

Create structures and functions to:
- Read file using pread/lseek (async via Connection trait)
- Parse atom hierarchy: ftyp → moov → (mvhd, trak) → (tkhd, mdia, edts) → ...
- Track atom positions and sizes for later rewriting
- Buffer management: allocate buffer_size initially, expand up to max_buffer_size if needed

Key atoms to handle:
- **ftyp**: File type signature, copy as-is
- **moov**: Movie metadata container (must rewrite children)
  - **mvhd**: Movie header (need to extract timescale)
  - **trak**: Track (0 or more; typically 1-2 for video+audio)
- **mdat**: Media data (don't read into memory, just note offset/size)

### 2. Track Structure & Sample Tables

For each **trak** atom, parse and store:
- **tkhd**: Track header (enabled flag, duration)
- **mdia** → **mdhd**: Media header (timescale, duration)
- **mdia** → **hdlr**: Handler type (vide/soun)
- **mdia** → **minf** → **vmhd/smhd**: Video/audio specific header
- **stbl**: Sample table container with:
  - **stsd**: Sample description (codec info)
  - **stts**: Time-to-sample table (array of {count:u32, duration:u32})
  - **stss**: Sync sample table (array of keyframe sample indices)
  - **ctts**: Composition offset table (array of {count:u32, offset:i32})
  - **stsc**: Sample-to-chunk table (array of {chunk:u32, samples:u32, id:u32})
  - **stsz**: Sample size table (array of sample sizes)
  - **stco**: Chunk offset table (32-bit offsets)
  - **co64**: Chunk offset table (64-bit offsets)

### 3. Seeking Implementation

```
fn seek_to_sample(stts_table, start_ms, timescale) -> (sample_idx, prefix_duration)
  - Iterate through stts entries accumulating time
  - Find first sample >= start_ms
  - Return sample index and how much of first sample to skip
```

For **mp4_start_key_frame**:
- Use stss table to find nearest keyframe >= start_sample
- Adjust prefix_duration accordingly

### 4. Atom Rewriting

After determining start/end samples:

**For each sample table:**
- **stts**: Trim entries to [start_sample, end_sample], adjust first/last counts
- **stss**: Filter sample indices, renumber to new sample indices
- **ctts**: Similar to stts, trim and renumber
- **stsc**: Rewrite to new chunk indices (chunks within [start, end] data range)
- **stsz**: Trim sample size entries
- **stco/co64**: Adjust offsets by (mdat_offset_delta = new_mdat_offset - original_mdat_offset)

**Recalculate atom sizes:**
- stbl_size = size of all children (stsd + rewritten stts/stss/ctts/stsc/stsz + stco/co64)
- minf_size = stbl_size + vmhd/smhd + dinf sizes
- mdia_size = minf_size + hdlr + mdhd sizes
- trak_size = tkhd + edts (if present) + mdia sizes
- moov_size = mvhd + sum(all trak_sizes)

### 5. Output Chain Construction

Build output as Vec<Buf>:
```
out = [
  memory buf: ftyp atom (if exists),
  memory buf: moov atom header (updated size),
  memory buf: mvhd atom,
  for each trak:
    memory buf: trak atom header (updated size),
    memory buf: tkhd atom,
    memory buf: mdia atom header (updated size),
      memory buf: mdhd atom (updated duration),
      memory buf: hdlr atom,
      memory buf: minf atom header,
        memory buf: vmhd/smhd atom,
        memory buf: dinf atom,
        memory buf: stbl atom header,
          memory buf: stsd atom,
          memory buf: stts atom header + data,
          memory buf: stss atom header + data,
          memory buf: ctts atom header + data,
          memory buf: stsc atom header + data,
          memory buf: stsz atom header + data,
          memory buf: stco/co64 atom header + data,
  memory buf: mdat atom header (updated size),
  file buf: mdat data [start_offset, end_offset) via in_file=1
]
```

### 6. Error Handling

Check for and handle:
- `"atom too large"` - if atom size exceeds available file/buffer
- `"no trak atoms"` - if no tracks found
- `"no mdat atom"` - if no media data
- `"start time is out mp4 stts samples"` - if seek beyond track duration
- Duplicate atoms (ftyp, moov, mdat)
- Malformed stts/stss/ctts tables (incomplete entries)

### 7. Test Files

The tests use ffmpeg-generated MP4 files with specific properties:
- **mp4.t**: Creates test.mp4 with 2 video tracks (10s and 20s duration)
- **mp4.t**: Creates no_mdat.mp4 with moov before mdat (faststart format)
- **mp4_start_key_frame.t**: Single track, tests keyframe alignment

The test verifies that:
- Sliced MP4 has correct duration metadata readable by ffprobe
- Range requests work with ?start= and ?end=
- Keyframe snapping works when mp4_start_key_frame=on

## Reference Materials

- C source: `/home/ubuntu/rnginx/nginx-c/src/http/modules/ngx_http_mp4_module.c`
- Key functions in C:
  - `ngx_http_mp4_process()` (line ~783): Main processing loop
  - `ngx_http_mp4_read_atom()`: Recursive atom dispatcher
  - `ngx_http_mp4_update_stts_atom()`: Example of table rewriting
  - `ngx_http_mp4_seek_key_frame()`: Keyframe seeking logic

## Implementation Strategy for Next Agent

1. **Phase 1**: Core atom reading
   - Implement async file reading for atoms
   - Parse ftyp, moov, mdat atom hierarchy
   - Build trak/stbl structures
   
2. **Phase 2**: Sample table parsing
   - Read and store all sample table entries
   - Implement seek_to_sample logic
   
3. **Phase 3**: Atom rewriting
   - Implement sample table trimming functions
   - Recalculate atom sizes
   - Adjust chunk offsets
   
4. **Phase 4**: Output chain building
   - Construct proper buf chain with memory + file buffers
   - Set content length
   
5. **Phase 5**: Error handling
   - Add validation for all edge cases
   - Match C error messages exactly

Estimated scope: 1500-2000 lines of Rust code, ~3-4 days for experienced developer.
