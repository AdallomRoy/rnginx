//! GOST R 34.11-2012 ("Streebog") with 256-bit digests and its HMAC, as
//! libxcrypt 4.4.27 has them for gost-yescrypt (alg-gost3411-2012-core.c
//! with the table-driven LPS of alg-gost3411-2012-ref.h,
//! alg-gost3411-2012-hmac.c), on little-endian hosts.

use super::gost_tables::{AX, C};

type U512 = [u64; 8];

/// buffer512: 512 as a 512-bit number
const BUFFER512: U512 = [0x200, 0, 0, 0, 0, 0, 0, 0];

/// XLPS(x, y): the LPS transformation of x ^ y
fn xlps(x: &U512, y: &U512) -> U512 {
    let r: U512 = std::array::from_fn(|k| x[k] ^ y[k]);
    let mut data = [0u64; 8];

    for (i, d) in data.iter_mut().enumerate() {
        let shift = i << 3;
        *d = (0..8).fold(0, |acc, k| acc ^ AX[k][((r[k] >> shift) & 0xff) as usize]);
    }

    data
}

fn xor(x: &U512, y: &U512) -> U512 {
    std::array::from_fn(|k| x[k] ^ y[k])
}

/// add512(): x + y modulo 2^512
fn add512(x: &U512, y: &U512) -> U512 {
    let mut r = [0u64; 8];
    let mut cf = 0u64;

    for i in 0..8 {
        let left = x[i];
        let sum = left.wrapping_add(y[i]).wrapping_add(cf);

        if sum != left {
            cf = (sum < left) as u64;
        }

        r[i] = sum;
    }

    r
}

/// The 64 bytes of a block as the 8 little-endian words of a uint512_u
fn words(m: &[u8]) -> U512 {
    std::array::from_fn(|k| u64::from_le_bytes(m[8 * k..8 * k + 8].try_into().expect("8 bytes")))
}

/// g(h, N, m): the compression function
fn g(h: &mut U512, n: &U512, m: &U512) {
    let mut data = xlps(h, n);

    // Starting E()
    let mut ki = data;
    data = xlps(&ki, m);

    for c in C.iter().take(11) {
        ki = xlps(&ki, c);
        data = xlps(&ki, &data);
    }

    ki = xlps(&ki, &C[11]);
    data = xor(&ki, &data);
    // E() done

    data = xor(&data, h);
    *h = xor(&data, m);
}

/// GOST34112012Context with a 256-bit digest
pub(super) struct Gost256 {
    h: U512,
    n: U512,
    sigma: U512,
    buffer: [u8; 64],
    bufsize: usize,
}

impl Gost256 {
    /// GOST34112012Init(CTX, 256)
    pub(super) fn new() -> Gost256 {
        Gost256 { h: [0x0101010101010101; 8], n: [0; 8], sigma: [0; 8], buffer: [0; 64], bufsize: 0 }
    }

    /// stage2()
    fn stage2(&mut self, data: &[u8]) {
        let m = words(data);

        g(&mut self.h, &self.n, &m);

        self.n = add512(&self.n, &BUFFER512);
        self.sigma = add512(&self.sigma, &m);
    }

    /// GOST34112012Update()
    pub(super) fn update(&mut self, mut data: &[u8]) {
        if self.bufsize != 0 {
            let chunksize = (64 - self.bufsize).min(data.len());

            self.buffer[self.bufsize..self.bufsize + chunksize].copy_from_slice(&data[..chunksize]);

            self.bufsize += chunksize;
            data = &data[chunksize..];

            if self.bufsize == 64 {
                let block = self.buffer;
                self.stage2(&block);
                self.bufsize = 0;
            }
        }

        while data.len() > 63 {
            self.stage2(&data[..64]);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.bufsize = data.len();
        }
    }

    /// GOST34112012Final(): stage3() and the 256-bit digest
    pub(super) fn finish(mut self) -> [u8; 32] {
        let buf: U512 = [(self.bufsize as u64) << 3, 0, 0, 0, 0, 0, 0, 0];

        // pad()
        if self.bufsize < 64 {
            for b in &mut self.buffer[self.bufsize..] {
                *b = 0;
            }
            self.buffer[self.bufsize] = 0x01;
        }

        let m = words(&self.buffer);

        g(&mut self.h, &self.n, &m);

        self.n = add512(&self.n, &buf);
        self.sigma = add512(&self.sigma, &m);

        let zero = [0u64; 8];
        let n = self.n;
        let sigma = self.sigma;

        g(&mut self.h, &zero, &n);
        g(&mut self.h, &zero, &sigma);

        let mut digest = [0u8; 32];
        for k in 0..4 {
            digest[8 * k..8 * k + 8].copy_from_slice(&self.h[4 + k].to_le_bytes());
        }

        digest
    }
}

/// gost_hash256()
pub(super) fn hash256(t: &[u8]) -> [u8; 32] {
    let mut ctx = Gost256::new();
    ctx.update(t);
    ctx.finish()
}

/// gost_hmac256(): the key is 32 to 64 bytes
pub(super) fn hmac256(k: &[u8], t: &[u8]) -> [u8; 32] {
    debug_assert!((32..=64).contains(&k.len()));

    let mut kstar = [0u8; 64];
    kstar[..k.len().min(64)].copy_from_slice(&k[..k.len().min(64)]);

    let mut ctx = Gost256::new();
    ctx.update(&kstar.map(|b| b ^ 0x36));
    ctx.update(t);
    let digest = ctx.finish();

    let mut ctx = Gost256::new();
    ctx.update(&kstar.map(|b| b ^ 0x5c));
    ctx.update(&digest);
    ctx.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// The examples of GOST R 34.11-2012 (M1, M2) and the HMAC example of
    /// R 50.1.113-2016, as libxcrypt's test-alg-gost3411-2012 has them.
    #[test]
    fn vectors() {
        let m1 = b"012345678901234567890123456789012345678901234567890123456789012";
        assert_eq!(hex(&hash256(m1)), "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");

        let m2: &[u8] = b"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee\xe6\xe8\x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20\xf1\x20\xec\xee\xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20\xed\xe0\x20\xf5\xf0\xe0\xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb";
        assert_eq!(hex(&hash256(m2)), "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50");

        // the carry test of gost-engine
        let mut carry = vec![0xeeu8; 64];
        carry.push(0x16);
        carry.extend_from_slice(&[0x11; 62]);
        carry.push(0x16);
        assert_eq!(hex(&hash256(&carry)), "81bb632fa31fcc38b4c379a662dbc58b9bed83f50d3a1b2ce7271ab02d25babb");

        let key: Vec<u8> = (0u8..32).collect();
        let data = b"\x01\x26\xbd\xb8\x78\x00\xaf\x21\x43\x41\x45\x65\x63\x78\x01\x00";
        assert_eq!(hex(&hmac256(&key, data)), "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9");
    }
}
