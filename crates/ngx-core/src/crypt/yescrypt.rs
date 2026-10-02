//! yescrypt ($y$), scrypt ($7$) and gost-yescrypt ($gy$) of libxcrypt
//! 4.4.27: crypt_yescrypt_rn() and crypt_gost_yescrypt_rn(), yescrypt_r()
//! and its encodings (alg-yescrypt-common.c), and yescrypt_kdf() of
//! alg-yescrypt-opt.c in its portable form (without OpenMP): the blocks
//! keep the "SIMD-shuffled" order of their 32-bit words of that code, on
//! which pwxform works.  ROM ("NROM") needs a shared ROM, which crypt_r()
//! never has: such settings fail, as there.

use openssl::hash::MessageDigest;
use openssl::sha::Sha256;

use super::{ascii_to_bin, gost, ASCII64, CRYPT_OUTPUT_SIZE};

const YESCRYPT_WORM: u32 = 1;
const YESCRYPT_RW: u32 = 0x002;
const YESCRYPT_ROUNDS_6: u32 = 0x004;
const YESCRYPT_GATHER_4: u32 = 0x010;
const YESCRYPT_SIMPLE_2: u32 = 0x020;
const YESCRYPT_SBOX_12K: u32 = 0x080;
const YESCRYPT_SHARED_PREALLOCATED: u32 = 0x10000;
const YESCRYPT_MODE_MASK: u32 = 0x003;
const YESCRYPT_RW_FLAVOR_MASK: u32 = 0x3fc;
const YESCRYPT_INIT_SHARED: u32 = 0x01000000;
const YESCRYPT_ALLOC_ONLY: u32 = 0x08000000;
const YESCRYPT_PREHASH: u32 = 0x10000000;
const YESCRYPT_KNOWN_FLAGS: u32 = YESCRYPT_MODE_MASK | YESCRYPT_RW_FLAVOR_MASK | YESCRYPT_SHARED_PREALLOCATED | YESCRYPT_INIT_SHARED | YESCRYPT_ALLOC_ONLY | YESCRYPT_PREHASH;

/// HASH_LEN: the characters of the 32 bytes of the hash
const HASH_LEN: usize = (32 * 8 + 5) / 6;

// pwxform: Swidth 8, PWXsimple 2, PWXgather 4

const SBYTES: usize = 3 * (1 << 8) * 2 * 8;
const SMASK: u64 = ((1 << 8) - 1) * 2 * 8;
const SMASK2: u64 = (SMASK << 32) | SMASK;

/// salsa20_blk_t: the 16 words, shuffled into 8 64-bit words
type Block = [u64; 8];

/// yescrypt_params_t
#[derive(Clone, Copy, Debug, Default)]
struct Params {
    flags: u32,
    n: u64,
    r: u32,
    p: u32,
    t: u32,
    g: u32,
    nrom: u64,
}

/// atoi64(): the value of an ascii64 character, 64 for the others (and
/// the end of the string)
fn atoi64(c: Option<&u8>) -> u32 {
    c.and_then(|&c| ascii_to_bin(c)).unwrap_or(64)
}

/// decode64_uint32(): the number and the position after it
fn decode64_uint32(s: &[u8], mut pos: usize, min: u32) -> Option<(u32, usize)> {
    let (mut start, mut end, mut chars, mut bits) = (0u32, 47u32, 1u32, 0u32);

    let mut c = atoi64(s.get(pos));
    pos += 1;

    if c > 63 {
        return None;
    }

    let mut dst = min;

    while c > end {
        dst = dst.wrapping_add((end + 1 - start) << bits);
        start = end + 1;
        end = start + (62 - end) / 2;
        chars += 1;
        bits += 6;
    }

    dst = dst.wrapping_add((c - start) << bits);

    while {
        chars -= 1;
        chars != 0
    } {
        c = atoi64(s.get(pos));
        pos += 1;

        if c > 63 {
            return None;
        }

        bits -= 6;
        dst = dst.wrapping_add(c << bits);
    }

    Some((dst, pos))
}

/// decode64_uint32_fixed()
fn decode64_uint32_fixed(s: &[u8], mut pos: usize, dstbits: u32) -> Option<(u32, usize)> {
    let mut dst = 0u32;
    let mut bits = 0;

    while bits < dstbits {
        let c = atoi64(s.get(pos));
        pos += 1;

        if c > 63 {
            return None;
        }

        dst |= c << bits;
        bits += 6;
    }

    Some((dst, pos))
}

/// decode64(): the bytes of src (at most dstlen) and the number of
/// characters decoded: the decoding stops at the first character outside
/// ascii64 (the callers' strings end with one: '$' or the NUL)
fn decode64(dstlen: usize, src: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut dst = Vec::new();
    let mut dstpos = 0usize;
    let mut s = 0usize;
    let mut srclen = src.len();

    while dstpos <= dstlen && srclen != 0 {
        let mut value = 0u32;
        let mut bits = 0u32;

        while srclen != 0 {
            srclen -= 1;

            let c = atoi64(src.get(s));

            if c > 63 {
                srclen = 0;
                break;
            }

            s += 1;
            value |= c << bits;
            bits += 6;

            if bits >= 24 {
                break;
            }
        }

        if bits == 0 {
            break;
        }

        if bits < 12 {
            // must have at least one full byte
            return None;
        }

        loop {
            let more = dstpos < dstlen;
            dstpos += 1;

            if !more {
                break;
            }

            dst.push(value as u8);
            value >>= 8;
            bits -= 8;

            if bits < 8 {
                // 2 or 4
                if value != 0 {
                    // must be 0
                    return None;
                }

                bits = 0;
                break;
            }
        }

        if bits != 0 {
            return None;
        }
    }

    if srclen == 0 && dstpos <= dstlen {
        return Some((dst, s));
    }

    None
}

/// encode64(): the characters of the bytes, 3 bytes (little-endian) at a
/// time
fn encode64(out: &mut Vec<u8>, src: &[u8]) {
    let mut i = 0;

    while i < src.len() {
        let mut value = 0u32;
        let mut bits = 0u32;

        loop {
            value |= (src[i] as u32) << bits;
            i += 1;
            bits += 8;

            if bits >= 24 || i >= src.len() {
                break;
            }
        }

        // encode64_uint32_fixed()
        let mut b = 0;
        while b < bits {
            out.push(ASCII64[(value & 0x3f) as usize]);
            value >>= 6;
            b += 6;
        }
    }
}

/// HMAC_SHA256_Buf(K, Klen, in, len, digest)
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k: Vec<u8> = if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        h.finish().to_vec()
    } else {
        key.to_vec()
    };

    let mut pad = [0u8; 64];
    pad[..k.len()].copy_from_slice(&k);

    let mut inner = Sha256::new();
    inner.update(&pad.map(|b| b ^ 0x36));
    inner.update(data);
    let ih = inner.finish();

    let mut outer = Sha256::new();
    outer.update(&pad.map(|b| b ^ 0x5c));
    outer.update(&ih);
    outer.finish()
}

/// PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, 1, buf, dkLen)
fn pbkdf2_sha256(passwd: &[u8], salt: &[u8], out: &mut [u8]) -> Option<()> {
    openssl::pkcs5::pbkdf2_hmac(passwd, salt, 1, MessageDigest::sha256(), out).ok()
}

/// salsa20_simd_shuffle(): the 16 words into the shuffled block
fn shuffle(w: &[u32; 16]) -> Block {
    let c = |in1: usize, in2: usize| w[in1 * 2] as u64 | ((w[in2 * 2 + 1] as u64) << 32);
    [c(0, 2), c(5, 7), c(2, 4), c(7, 1), c(4, 6), c(1, 3), c(6, 0), c(3, 5)]
}

/// salsa20_simd_unshuffle()
fn unshuffle(d: &Block) -> [u32; 16] {
    let mut w = [0u32; 16];

    for (out, in1, in2) in [(0, 0, 6), (1, 5, 3), (2, 2, 0), (3, 7, 5), (4, 4, 2), (5, 1, 7), (6, 6, 4), (7, 3, 1)] {
        w[out * 2] = d[in1] as u32;
        w[out * 2 + 1] = (d[in2] >> 32) as u32;
    }

    w
}

/// The 32-bit words of the storage of a block, as C's B->w[] reads them
fn words(d: &Block) -> [u32; 16] {
    std::array::from_fn(|i| if i % 2 == 0 { d[i / 2] as u32 } else { (d[i / 2] >> 32) as u32 })
}

fn from_words(w: &[u32; 16]) -> Block {
    std::array::from_fn(|k| w[2 * k] as u64 | ((w[2 * k + 1] as u64) << 32))
}

/// salsa20(B, Bout, doublerounds): B becomes the result too
fn salsa20(b: &mut Block, doublerounds: u32) {
    let mut x = unshuffle(b);

    let r = |a: u32, n: u32| a.rotate_left(n);

    for _ in 0..doublerounds {
        // Operate on columns
        x[4] ^= r(x[0].wrapping_add(x[12]), 7);
        x[8] ^= r(x[4].wrapping_add(x[0]), 9);
        x[12] ^= r(x[8].wrapping_add(x[4]), 13);
        x[0] ^= r(x[12].wrapping_add(x[8]), 18);

        x[9] ^= r(x[5].wrapping_add(x[1]), 7);
        x[13] ^= r(x[9].wrapping_add(x[5]), 9);
        x[1] ^= r(x[13].wrapping_add(x[9]), 13);
        x[5] ^= r(x[1].wrapping_add(x[13]), 18);

        x[14] ^= r(x[10].wrapping_add(x[6]), 7);
        x[2] ^= r(x[14].wrapping_add(x[10]), 9);
        x[6] ^= r(x[2].wrapping_add(x[14]), 13);
        x[10] ^= r(x[6].wrapping_add(x[2]), 18);

        x[3] ^= r(x[15].wrapping_add(x[11]), 7);
        x[7] ^= r(x[3].wrapping_add(x[15]), 9);
        x[11] ^= r(x[7].wrapping_add(x[3]), 13);
        x[15] ^= r(x[11].wrapping_add(x[7]), 18);

        // Operate on rows
        x[1] ^= r(x[0].wrapping_add(x[3]), 7);
        x[2] ^= r(x[1].wrapping_add(x[0]), 9);
        x[3] ^= r(x[2].wrapping_add(x[1]), 13);
        x[0] ^= r(x[3].wrapping_add(x[2]), 18);

        x[6] ^= r(x[5].wrapping_add(x[4]), 7);
        x[7] ^= r(x[6].wrapping_add(x[5]), 9);
        x[4] ^= r(x[7].wrapping_add(x[6]), 13);
        x[5] ^= r(x[4].wrapping_add(x[7]), 18);

        x[11] ^= r(x[10].wrapping_add(x[9]), 7);
        x[8] ^= r(x[11].wrapping_add(x[10]), 9);
        x[9] ^= r(x[8].wrapping_add(x[11]), 13);
        x[10] ^= r(x[9].wrapping_add(x[8]), 18);

        x[12] ^= r(x[15].wrapping_add(x[14]), 7);
        x[13] ^= r(x[12].wrapping_add(x[15]), 9);
        x[14] ^= r(x[13].wrapping_add(x[12]), 13);
        x[15] ^= r(x[14].wrapping_add(x[13]), 18);
    }

    let out = words(&shuffle(&x));
    let inp = words(b);
    let sum: [u32; 16] = std::array::from_fn(|i| out[i].wrapping_add(inp[i]));

    *b = from_words(&sum);
}

fn xor_block(x: &mut Block, y: &Block) {
    for k in 0..8 {
        x[k] ^= y[k];
    }
}

/// blockmix_salsa8(Bin, Bout, r)
fn blockmix_salsa8(bin: &[Block], bout: &mut [Block], r: usize) {
    let mut x = bin[r * 2 - 1];

    for i in 0..r {
        xor_block(&mut x, &bin[i * 2]);
        salsa20(&mut x, 4);
        bout[i] = x;

        xor_block(&mut x, &bin[i * 2 + 1]);
        salsa20(&mut x, 4);
        bout[r + i] = x;
    }
}

/// blockmix_salsa8_xor(Bin1, Bin2, Bout, r)
fn blockmix_salsa8_xor(bin1: &[Block], bin2: &[Block], bout: &mut [Block], r: usize) -> u32 {
    let mut x = bin1[r * 2 - 1];
    xor_block(&mut x, &bin2[r * 2 - 1]);

    for i in 0..r {
        xor_block(&mut x, &bin1[i * 2]);
        xor_block(&mut x, &bin2[i * 2]);
        salsa20(&mut x, 4);
        bout[i] = x;

        xor_block(&mut x, &bin1[i * 2 + 1]);
        xor_block(&mut x, &bin2[i * 2 + 1]);
        salsa20(&mut x, 4);
        bout[r + i] = x;
    }

    x[0] as u32
}

/// pwxform_ctx_t: the S-boxes S0, S1, S2 (u64 indices into s) and w
struct Pwxform {
    s: Vec<u64>,
    s0: usize,
    s1: usize,
    s2: usize,
    w: usize,
}

impl Pwxform {
    /// PWXFORM: 6 rounds on X, 4 writes into S2, the S-boxes rotated
    fn pwxform(&mut self, x: &mut Block) {
        let round = |ctx: &Pwxform, x: &mut Block| {
            for k in (0..8).step_by(2) {
                let (x0, x1) = (x[k], x[k + 1]);
                let m = x0 & SMASK2;
                let p0 = ctx.s0 + (m as u32 as usize) / 8;
                let p1 = ctx.s1 + ((m >> 32) as usize) / 8;

                x[k] = (x0 >> 32).wrapping_mul(x0 as u32 as u64).wrapping_add(ctx.s[p0]) ^ ctx.s[p1];
                x[k + 1] = (x1 >> 32).wrapping_mul(x1 as u32 as u64).wrapping_add(ctx.s[p0 + 1]) ^ ctx.s[p1 + 1];
            }
        };

        let mut sw = self.s2 + self.w / 8;

        round(self, x);

        for _ in 0..4 {
            round(self, x);
            self.s[sw..sw + 8].copy_from_slice(x);
            sw += 8;
        }

        round(self, x);

        self.w = ((self.w + 64 * 4) as u64 & SMASK2) as usize;

        let tmp = self.s2;
        self.s2 = self.s1;
        self.s1 = self.s0;
        self.s0 = tmp;
    }
}

/// blockmix(Bin, Bout, r, ctx): BlockMix_pwxform
fn blockmix(bin: &[Block], bout: &mut [Block], r: usize, ctx: &mut Pwxform) {
    // Convert count of 128-byte blocks to max index of 64-byte block
    let r = r * 2 - 1;

    let mut x = bin[r];

    let mut i = 0;
    loop {
        xor_block(&mut x, &bin[i]);
        ctx.pwxform(&mut x);

        if i >= r {
            break;
        }

        bout[i] = x;
        i += 1;
    }

    salsa20(&mut x, 1);
    bout[i] = x;
}

/// blockmix_xor(Bin1, Bin2, Bout, r, ...): Bin1 is Bout when bin1 is None
fn blockmix_xor(bin1: Option<&[Block]>, bin2: &[Block], bout: &mut [Block], r: usize, ctx: &mut Pwxform) -> u32 {
    // Convert count of 128-byte blocks to max index of 64-byte block
    let r = r * 2 - 1;

    let in1 = |bout: &[Block], k: usize| match bin1 {
        Some(b) => b[k],
        None => bout[k],
    };

    let mut x = in1(bout, r);
    xor_block(&mut x, &bin2[r]);

    let mut i = 0;
    let last = r - 1;

    loop {
        let b1 = in1(bout, i);
        xor_block(&mut x, &b1);
        xor_block(&mut x, &bin2[i]);
        ctx.pwxform(&mut x);
        bout[i] = x;

        let b1 = in1(bout, i + 1);
        xor_block(&mut x, &b1);
        xor_block(&mut x, &bin2[i + 1]);
        ctx.pwxform(&mut x);

        if i >= last {
            break;
        }

        bout[i + 1] = x;
        i += 2;
    }

    i += 1;

    salsa20(&mut x, 1);
    bout[i] = x;

    x[0] as u32
}

/// blockmix_xor_save(Bin1out, Bin2, r, ctx)
fn blockmix_xor_save(bin1out: &mut [Block], bin2: &mut [Block], r: usize, ctx: &mut Pwxform) -> u32 {
    // Convert count of 128-byte blocks to max index of 64-byte block
    let r = r * 2 - 1;

    let mut x = bin1out[r];
    xor_block(&mut x, &bin2[r]);

    let mut i = 0;
    let last = r - 1;

    loop {
        // XOR_X_WRITE_XOR_Y_2(Bin2[i], Bin1out[i])
        let mut y = bin2[i];
        xor_block(&mut y, &bin1out[i]);
        bin2[i] = y;
        xor_block(&mut x, &y);

        ctx.pwxform(&mut x);
        bin1out[i] = x;

        let mut y = bin2[i + 1];
        xor_block(&mut y, &bin1out[i + 1]);
        bin2[i + 1] = y;
        xor_block(&mut x, &y);

        ctx.pwxform(&mut x);

        if i >= last {
            break;
        }

        bin1out[i + 1] = x;
        i += 2;
    }

    i += 1;

    salsa20(&mut x, 1);
    bin1out[i] = x;

    x[0] as u32
}

/// integerify(B, r)
fn integerify(b: &[Block], r: usize) -> u32 {
    b[2 * r - 1][0] as u32
}

/// The 128r bytes of B as 2r shuffled blocks (le32dec, shuffle)
fn bytes_to_blocks(b: &[u8], out: &mut [Block]) {
    for (i, blk) in out.iter_mut().enumerate() {
        let w: [u32; 16] = std::array::from_fn(|k| u32::from_le_bytes(b[i * 64 + 4 * k..i * 64 + 4 * k + 4].try_into().expect("4 bytes")));
        *blk = shuffle(&w);
    }
}

/// The blocks back into B (unshuffle, le32enc)
fn blocks_to_bytes(blks: &[Block], b: &mut [u8]) {
    for (i, blk) in blks.iter().enumerate() {
        let w = unshuffle(blk);
        for k in 0..16 {
            b[i * 64 + 4 * k..i * 64 + 4 * k + 4].copy_from_slice(&w[k].to_le_bytes());
        }
    }
}

/// smix1(B, r, N, flags, V, NROM, VROM, XY, ctx) without ROM: B is 128r
/// bytes, V holds N chunks of 2r blocks
fn smix1(b: &mut [u8], r: usize, n: u32, flags: u32, v: &mut [Block], xy: &mut [Block], ctx: Option<&mut Pwxform>) {
    let s = 2 * r;

    bytes_to_blocks(&b[..128 * r], &mut v[..s]);

    let chunk = |k: usize| k * s..(k + 1) * s;

    // blockmix* from the chunk x into the chunk x + 1 of V
    let mut out = vec![[0u64; 8]; s];

    match ctx {
        Some(ctx) if flags & YESCRYPT_RW != 0 => {
            // X = chunk cx, Y = the next one
            {
                let (left, right) = v.split_at_mut(s);
                blockmix(&left[..s], &mut right[..s], r, ctx);
            }
            {
                let (left, right) = v.split_at_mut(2 * s);
                blockmix(&left[s..2 * s], &mut right[..s], r, ctx);
            }

            let mut cx = 2;
            let mut j = integerify(&v[chunk(cx)], r);

            let mut nn: u32 = 2;

            while nn < n {
                let m = if nn < n / 2 { nn } else { n - 1 - nn };
                let mut i: u32 = 1;

                while i < m {
                    let cy = cx + 1;

                    j &= nn - 1;
                    j = j.wrapping_add(i - 1);
                    let vj = j as usize;

                    {
                        let (left, right) = v.split_at_mut(cy * s);
                        j = blockmix_xor(Some(&left[chunk(cx)]), &left[chunk(vj)], &mut right[..s], r, ctx);
                    }

                    j &= nn - 1;
                    j = j.wrapping_add(i);
                    let vj = j as usize;

                    cx = cy + 1;

                    {
                        let (left, right) = v.split_at_mut(cx * s);
                        j = blockmix_xor(Some(&left[chunk(cy)]), &left[chunk(vj)], &mut right[..s], r, ctx);
                    }

                    i += 2;
                }

                nn <<= 1;
            }

            nn >>= 1;

            j &= nn - 1;
            j = j.wrapping_add(n - 2 - nn);
            let vj = j as usize;
            let cy = cx + 1;

            {
                let (left, right) = v.split_at_mut(cy * s);
                j = blockmix_xor(Some(&left[chunk(cx)]), &left[chunk(vj)], &mut right[..s], r, ctx);
            }

            j &= nn - 1;
            j = j.wrapping_add(n - 1 - nn);
            let vj = j as usize;

            blockmix_xor(Some(&v[chunk(cy)]), &v[chunk(vj)], &mut out, r, ctx);
        }

        _ => {
            for k in 0..(n as usize - 1) {
                let (left, right) = v.split_at_mut((k + 1) * s);
                blockmix_salsa8(&left[chunk(k)], &mut right[..s], r);
            }

            blockmix_salsa8(&v[chunk(n as usize - 1)], &mut out, r);
        }
    }

    xy[..s].copy_from_slice(&out);

    blocks_to_bytes(&xy[..s], &mut b[..128 * r]);
}

/// smix2(B, r, N, Nloop, flags, V, NROM, VROM, XY, ctx) without ROM
fn smix2(b: &mut [u8], r: usize, n: u32, mut nloop: u64, flags: u32, v: &mut [Block], xy: &mut [Block], mut ctx: Option<&mut Pwxform>) {
    let s = 2 * r;

    if nloop == 0 {
        return;
    }

    let (x, y) = xy.split_at_mut(s);
    let y = &mut y[..s];

    bytes_to_blocks(&b[..128 * r], x);

    let mut j = integerify(x, r) & (n - 1);

    let chunk = |j: u32| j as usize * s..(j as usize + 1) * s;

    if flags & YESCRYPT_RW != 0 {
        let ctx = ctx.as_deref_mut().expect("pwxform context");

        loop {
            j = blockmix_xor_save(x, &mut v[chunk(j)], r, ctx) & (n - 1);
            j = blockmix_xor_save(x, &mut v[chunk(j)], r, ctx) & (n - 1);

            nloop -= 2;
            if nloop == 0 {
                break;
            }
        }
    } else if let Some(ctx) = ctx.as_deref_mut() {
        loop {
            j = blockmix_xor(None, &v[chunk(j)], x, r, ctx) & (n - 1);
            j = blockmix_xor(None, &v[chunk(j)], x, r, ctx) & (n - 1);

            nloop -= 2;
            if nloop == 0 {
                break;
            }
        }
    } else {
        loop {
            j = blockmix_salsa8_xor(x, &v[chunk(j)], y, r) & (n - 1);
            j = blockmix_salsa8_xor(y, &v[chunk(j)], x, r) & (n - 1);

            nloop -= 2;
            if nloop == 0 {
                break;
            }
        }
    }

    blocks_to_bytes(x, &mut b[..128 * r]);
}

/// p2floor(x): the largest power of 2 not greater than x
fn p2floor(mut x: u64) -> u64 {
    loop {
        let y = x & x.wrapping_sub(1);
        if y == 0 {
            return x;
        }
        x = y;
    }
}

/// smix(B, r, N, p, t, flags, V, NROM, VROM, XY, S, passwd)
#[allow(clippy::too_many_arguments)]
fn smix(b: &mut [u8], r: usize, n: u32, p: u32, t: u32, flags: u32, v: &mut [Block], xy: &mut [Block], passwd: &mut [u8; 32]) {
    let s = 2 * r;

    let mut nchunk = n / p;
    let mut nloop_all = nchunk as u64;

    if flags & YESCRYPT_RW != 0 {
        if t <= 1 {
            if t != 0 {
                nloop_all *= 2; // 2/3
            }
            nloop_all = (nloop_all + 2) / 3; // 1/3, round up
        } else {
            nloop_all *= (t - 1) as u64;
        }
    } else if t != 0 {
        if t == 1 {
            nloop_all += (nloop_all + 1) / 2; // 1.5, round up
        }
        nloop_all *= t as u64;
    }

    let mut nloop_rw = 0u64;

    if flags & YESCRYPT_INIT_SHARED != 0 {
        nloop_rw = nloop_all;
    } else if flags & YESCRYPT_RW != 0 {
        nloop_rw = nloop_all / p as u64;
    }

    nchunk &= !1; // round down to even
    nloop_all = (nloop_all + 1) & !1; // round up to even
    nloop_rw = (nloop_rw + 1) & !1; // round up to even

    let mut ctxs: Vec<Option<Pwxform>> = Vec::with_capacity(p as usize);

    for i in 0..p {
        let vchunk = i * nchunk;
        let np = if i < p - 1 { nchunk } else { n - vchunk };
        let bp = &mut b[128 * r * i as usize..128 * r * (i as usize + 1)];
        let vp = &mut v[vchunk as usize * s..];

        let mut ctx_i = None;

        if flags & YESCRYPT_RW != 0 {
            // the S-boxes: smix1() of the first 128 bytes of Bp with V in
            // S (r = 1, N = Sbytes / 128, no flags)
            let mut sv = vec![[0u64; 8]; SBYTES / 64];
            smix1(bp, 1, (SBYTES / 128) as u32, 0, &mut sv, xy, None);

            let sflat: Vec<u64> = sv.iter().flat_map(|blk| blk.iter().copied()).collect();

            ctx_i = Some(Pwxform { s: sflat, s2: 0, s1: SBYTES / 3 / 8, s0: SBYTES / 3 * 2 / 8, w: 0 });

            if i == 0 {
                *passwd = hmac_sha256(&bp[128 * r - 64..128 * r], &passwd[..]);
            }
        }

        smix1(bp, r, np, flags, vp, xy, ctx_i.as_mut());
        smix2(bp, r, p2floor(np as u64) as u32, nloop_rw, flags, vp, xy, ctx_i.as_mut());

        ctxs.push(ctx_i);
    }

    if nloop_all > nloop_rw {
        for i in 0..p {
            let bp = &mut b[128 * r * i as usize..128 * r * (i as usize + 1)];
            let ctx_i = ctxs[i as usize].as_mut();

            smix2(bp, r, n, nloop_all - nloop_rw, flags & !YESCRYPT_RW, v, xy, ctx_i);
        }
    }
}

/// yescrypt_kdf_body() without ROM: None for EINVAL and ENOMEM
#[allow(clippy::too_many_arguments)]
fn kdf_body(passwd: &[u8], salt: &[u8], flags: u32, n: u64, r: u32, p: u32, t: u32, nrom: u64, buf: &mut [u8]) -> Option<()> {
    // Sanity-check parameters
    match flags & YESCRYPT_MODE_MASK {
        0 => {
            // classic scrypt - can't have anything non-standard
            if flags != 0 || t != 0 || nrom != 0 {
                return None;
            }
        }

        YESCRYPT_WORM => {
            if flags != YESCRYPT_WORM || nrom != 0 {
                return None;
            }
        }

        YESCRYPT_RW => {
            if flags != (flags & YESCRYPT_KNOWN_FLAGS) {
                return None;
            }

            if (flags & YESCRYPT_RW_FLAVOR_MASK) != (YESCRYPT_ROUNDS_6 | YESCRYPT_GATHER_4 | YESCRYPT_SIMPLE_2 | YESCRYPT_SBOX_12K) {
                return None;
            }
        }

        _ => return None,
    }

    if buf.len() as u64 > ((1u64 << 32) - 1) * 32 {
        return None;
    }

    if r as u64 * p as u64 >= 1 << 30 {
        return None;
    }

    if n > u32::MAX as u64 {
        return None;
    }

    if (n & n.wrapping_sub(1)) != 0 || n <= 3 || r < 1 || p < 1 {
        return None;
    }

    if r as u64 > usize::MAX as u64 / 256 / p as u64 || n > usize::MAX as u64 / 128 / r as u64 {
        return None;
    }

    if flags & YESCRYPT_RW != 0 && n / p as u64 <= 3 {
        return None;
    }

    // no shared ROM
    if nrom != 0 {
        return None;
    }

    if flags & YESCRYPT_ALLOC_ONLY != 0 {
        // the parameters are fine (the C allocates the memory here)
        return Some(());
    }

    let r = r as usize;
    let n32 = n as u32;

    // Allocate memory: V (2r blocks per N), B (128 r p bytes), XY (4r
    // blocks)
    let v_blocks = (2 * r).checked_mul(n as usize)?;

    let mut v: Vec<Block> = Vec::new();
    v.try_reserve_exact(v_blocks).ok()?;
    v.resize(v_blocks, [0; 8]);

    let b_size = 128usize.checked_mul(r)?.checked_mul(p as usize)?;

    let mut b: Vec<u8> = Vec::new();
    b.try_reserve_exact(b_size).ok()?;
    b.resize(b_size, 0);

    let mut xy = vec![[0u64; 8]; 4 * r];

    let mut sha256 = [0u8; 32];
    let mut passwd: &[u8] = passwd;

    if flags != 0 {
        sha256 = hmac_sha256(if flags & YESCRYPT_PREHASH != 0 { b"yescrypt-prehash" } else { b"yescrypt" }, passwd);
        passwd = &[];
    }

    let prehashed = flags != 0;

    pbkdf2_sha256(if prehashed { &sha256 } else { passwd }, salt, &mut b)?;

    if prehashed {
        sha256.copy_from_slice(&b[..32]);
    }

    if p == 1 || flags & YESCRYPT_RW != 0 {
        smix(&mut b, r, n32, p, t, flags, &mut v, &mut xy, &mut sha256);
    } else {
        for i in 0..p as usize {
            let mut unused = [0u8; 32];
            smix(&mut b[128 * r * i..128 * r * (i + 1)], r, n32, 1, t, flags, &mut v, &mut xy, &mut unused);
        }
    }

    let mut dk = [0u8; 32];
    let use_dk = prehashed && buf.len() < dk.len();

    if use_dk {
        pbkdf2_sha256(&sha256, &b, &mut dk)?;
    }

    pbkdf2_sha256(if prehashed { &sha256 } else { passwd }, &b, buf)?;

    // Except when computing classic scrypt, allow all computation so far
    // to be performed on the client.
    if prehashed && flags & YESCRYPT_PREHASH == 0 {
        let dkp: [u8; 32] = if use_dk { dk } else { buf[..32].try_into().ok()? };

        // Compute ClientKey
        let client_key = hmac_sha256(&dkp, b"Client Key");

        // Compute StoredKey
        let mut h = Sha256::new();
        h.update(&client_key);
        let stored = h.finish();

        let clen = buf.len().min(32);
        buf[..clen].copy_from_slice(&stored[..clen]);
    }

    Some(())
}

/// yescrypt_kdf()
fn kdf(passwd: &[u8], salt: &[u8], params: &Params, buf: &mut [u8]) -> Option<()> {
    let Params { flags, n, r, p, t, g, nrom } = *params;

    // Support for hash upgrades has been temporarily removed
    if g != 0 {
        return None;
    }

    let mut dk = [0u8; 32];
    let mut passwd = passwd;

    if (flags & (YESCRYPT_RW | YESCRYPT_INIT_SHARED)) == YESCRYPT_RW && p >= 1 && n / p as u64 >= 0x100 && n / p as u64 * r as u64 >= 0x20000 {
        // the parameters are checked (ALLOC_ONLY), then the password is
        // prehashed with N / 64
        kdf_body(passwd, salt, flags | YESCRYPT_ALLOC_ONLY, n, r, p, t, nrom, buf)?;
        kdf_body(passwd, salt, flags | YESCRYPT_PREHASH, n >> 6, r, p, 0, nrom, &mut dk)?;
        passwd = &dk;
    }

    kdf_body(passwd, salt, flags, n, r, p, t, nrom, buf)
}

/// yescrypt_r(): the hash of a "$y$" or "$7$" setting (buflen bytes of
/// output at most, with its NUL)
fn yescrypt_r(passwd: &[u8], setting: &[u8], buflen: usize) -> Option<Vec<u8>> {
    if setting.first() != Some(&b'$') || !matches!(setting.get(1), Some(b'7' | b'y')) || setting.get(2) != Some(&b'$') {
        return None;
    }

    let mut params = Params { p: 1, ..Default::default() };
    let mut src = 3;

    let scrypt = setting[1] == b'7';

    if scrypt {
        let n_log2 = atoi64(setting.get(src));
        src += 1;

        if !(1..=63).contains(&n_log2) {
            return None;
        }

        params.n = 1u64 << n_log2;

        let (r, s) = decode64_uint32_fixed(setting, src, 30)?;
        params.r = r;
        src = s;

        let (p, s) = decode64_uint32_fixed(setting, src, 30)?;
        params.p = p;
        src = s;
    } else {
        let (flavor, s) = decode64_uint32(setting, src, 0)?;
        src = s;

        if flavor < YESCRYPT_RW {
            params.flags = flavor;
        } else if flavor <= YESCRYPT_RW + (YESCRYPT_RW_FLAVOR_MASK >> 2) {
            params.flags = YESCRYPT_RW + ((flavor - YESCRYPT_RW) << 2);
        } else {
            return None;
        }

        let (n_log2, s) = decode64_uint32(setting, src, 1)?;
        src = s;

        if n_log2 > 63 {
            return None;
        }

        params.n = 1u64 << n_log2;

        let (r, s) = decode64_uint32(setting, src, 1)?;
        params.r = r;
        src = s;

        if setting.get(src) != Some(&b'$') {
            let (have, s) = decode64_uint32(setting, src, 1)?;
            src = s;

            if have & 1 != 0 {
                let (p, s) = decode64_uint32(setting, src, 2)?;
                params.p = p;
                src = s;
            }

            if have & 2 != 0 {
                let (t, s) = decode64_uint32(setting, src, 1)?;
                params.t = t;
                src = s;
            }

            if have & 4 != 0 {
                let (g, s) = decode64_uint32(setting, src, 1)?;
                params.g = g;
                src = s;
            }

            if have & 8 != 0 {
                let (nrom_log2, s) = decode64_uint32(setting, src, 1)?;
                src = s;

                if nrom_log2 > 63 {
                    return None;
                }

                params.nrom = 1u64 << nrom_log2;
            }
        }

        if setting.get(src) != Some(&b'$') {
            return None;
        }

        src += 1;
    }

    let prefixlen = src;

    let saltstr = setting.get(src..).unwrap_or(&[]);
    let saltstrlen = saltstr.iter().rposition(|&c| c == b'$').unwrap_or(saltstr.len());

    let salt: Vec<u8> = if scrypt {
        saltstr[..saltstrlen].to_vec()
    } else {
        match decode64(64, &saltstr[..saltstrlen]) {
            Some((salt, end)) if end == saltstrlen => salt,
            _ => return None,
        }
    };

    let need = prefixlen + saltstrlen + 1 + HASH_LEN + 1;

    if need > buflen {
        return None;
    }

    let mut hashbin = [0u8; 32];

    kdf(passwd, &salt, &params, &mut hashbin)?;

    let mut out = setting[..prefixlen + saltstrlen].to_vec();
    out.push(b'$');
    encode64(&mut out, &hashbin);

    Some(out)
}

/// crypt_yescrypt_rn(): $y$ and $7$
pub(super) fn yescrypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    if CRYPT_OUTPUT_SIZE < setting.len() + 1 + 43 + 1 {
        // ERANGE
        return None;
    }

    yescrypt_r(phrase, setting, CRYPT_OUTPUT_SIZE)
}

/// crypt_scrypt_rn(): $7$ with verify_salt(): from the salt on (after
/// "$7$", N and the 5 characters of r and of p), the characters are
/// ascii64 or '$' up to the first other one, which must follow a '$'
pub(super) fn scrypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    if CRYPT_OUTPUT_SIZE < setting.len() + 1 + 43 + 1 {
        // ERANGE
        return None;
    }

    if !setting.starts_with(b"$7$") {
        return None;
    }

    // check_salt_char()
    let salt_char = |c: u8| c.is_ascii_alphanumeric() || c == b'.' || c == b'/' || c == b'$';

    for i in (3 + 1 + 5 * 2)..setting.len() {
        if !salt_char(setting[i]) {
            // Salt is terminated properly.  Following characters don't
            // matter.
            if setting[i - 1] == b'$' {
                break;
            }

            // Salt has an invalid character.
            return None;
        }
    }

    yescrypt(phrase, setting)
}

/// crypt_gost_yescrypt_rn(): $gy$
pub(super) fn gost_yescrypt(phrase: &[u8], setting: &[u8]) -> Option<Vec<u8>> {
    if CRYPT_OUTPUT_SIZE < setting.len() + 1 + 43 + 1 {
        // ERANGE
        return None;
    }

    if !setting.starts_with(b"$gy$") {
        return None;
    }

    // convert gost setting to yescrypt setting
    let mut gsetting = b"$y$".to_vec();
    gsetting.extend_from_slice(&setting[4..]);

    let retval = yescrypt_r(phrase, &gsetting, CRYPT_OUTPUT_SIZE - 1)?;

    // extract yescrypt output from "$y$param$salt$output"
    let h1 = retval[3..].iter().position(|&c| c == b'$')? + 3;
    let h2 = retval[h1 + 1..].iter().position(|&c| c == b'$')? + h1 + 1;
    let hptr = h2 + 1; // start of output

    // decode yescrypt output into its raw 256-bit form
    let (y, _) = decode64(32, &retval[hptr..])?;

    if y.len() != 32 {
        return None;
    }

    // HMAC_GOSTR3411_2012_256(HMAC_GOSTR3411_2012_256(GOST2012_256(K), S),
    // yescrypt(K, S)), S being as many characters of the setting as the
    // yescrypt output has before its hash
    let hk = gost::hash256(phrase);
    let interm = gost::hmac256(&hk, setting.get(..hptr).unwrap_or(setting));
    let y = gost::hmac256(&interm, &y);

    let mut out = b"$g".to_vec();
    out.extend_from_slice(&retval[1..hptr]);
    encode64(&mut out, &y);

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn y(phrase: &str, setting: &str) -> Option<String> {
        yescrypt(phrase.as_bytes(), setting.as_bytes()).map(|v| String::from_utf8(v).unwrap())
    }

    #[test]
    fn encodings() {
        assert_eq!(decode64_uint32(b"j", 0, 0), Some((47, 1)));
        assert_eq!(decode64_uint32(b"9", 0, 1), Some((12, 1)));
        assert_eq!(decode64_uint32(b"T", 0, 1), Some((32, 1)));
        assert_eq!(decode64(64, b"F5Jx5fExrKuPp53xLKQ..1").map(|(v, n)| (v.len(), n)), Some((16, 22)));
        assert_eq!(decode64(64, b"F5Jx#").map(|(v, n)| (v.len(), n)), Some((3, 4)));
        assert_eq!(decode64(64, b"F"), None);

        let mut out = Vec::new();
        encode64(&mut out, &[0xff, 0x00, 0x12]);
        assert_eq!(out, b"z1U2");
    }

    /// crypt_r() of libxcrypt 4.4.27 gave these
    #[test]
    fn crypt_r_vectors() {
        assert_eq!(
            y("password", "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7").as_deref(),
            Some("$y$j9T$F5Jx5fExrKuPp53xLKQ..1$tnSYvahCwPBHKZUspmcxMfb0.WiB9W.zEaKlOBL35rC")
        );
        assert_eq!(y("password", "$7$CU..../....abc$").as_deref(), Some("$7$CU..../....abc$aq9nTbuadDKl/OmAH9ktvpXiAjiuBYpB578rVYQ/6K/"));
    }
}
