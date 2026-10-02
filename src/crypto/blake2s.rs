//! BLAKE2s-256 (RFC 7693) and HMAC over it: the hash of the Noise handshake
//! (`noise`).
//!
//! It is written out here rather than taken from the `blake2` crate because
//! the handshake hashes keys. HMAC's inner and outer states, once they have
//! taken in the key block, are as good as the key, and so is every chaining
//! key HKDF passes through them; the crate's hasher can neither be wiped nor
//! wipes itself, so every handshake would leave them behind. This one wipes
//! its state when it is dropped and wipes what its compression function
//! worked on before returning.
//!
//! Checked against RFC 7693's own example, against the `blake2` crate on
//! every input length up to several blocks, and — through the handshake —
//! against the Noise test vectors.

use zeroize::{Zeroize, Zeroizing};

/// Bytes of a block, and of HMAC's padded key.
pub(crate) const BLOCK_LEN: usize = 64;
/// Bytes of a hash.
pub(crate) const HASH_LEN: usize = 32;

/// The initial chaining value (the one SHA-256 starts from).
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// The message word schedule of each of the ten rounds.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// An unkeyed BLAKE2s hasher with 32 bytes of output. What it has taken in
/// — the chaining value and the block being filled — is wiped when it is
/// dropped, by the types it is held in.
pub(crate) struct Blake2s {
    h: Zeroizing<[u32; 8]>,
    /// Bytes compressed so far.
    t: u64,
    buf: Zeroizing<[u8; BLOCK_LEN]>,
    /// Bytes in `buf`. A full block stays there until more input arrives,
    /// since the last block, full or not, is compressed differently.
    len: usize,
}

impl Blake2s {
    pub(crate) fn new() -> Self {
        let mut h = IV;
        // Parameter block: digest length 32, no key, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ HASH_LEN as u32;
        Self {
            h: Zeroizing::new(h),
            t: 0,
            buf: Zeroizing::new([0; BLOCK_LEN]),
            len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.len == BLOCK_LEN {
                // More input follows, so this block is not the last one.
                self.t += BLOCK_LEN as u64;
                compress(&mut self.h, &self.buf, self.t, false);
                self.len = 0;
            }
            let n = (BLOCK_LEN - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
        }
    }

    pub(crate) fn finalize(mut self) -> Zeroizing<[u8; HASH_LEN]> {
        self.t += self.len as u64;
        self.buf[self.len..].fill(0);
        compress(&mut self.h, &self.buf, self.t, true);
        let mut out = Zeroizing::new([0u8; HASH_LEN]);
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.h.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// The hash of `parts`, one after the other.
pub(crate) fn hash(parts: &[&[u8]]) -> Zeroizing<[u8; HASH_LEN]> {
    let mut h = Blake2s::new();
    for part in parts {
        h.update(part);
    }
    h.finalize()
}

/// HMAC (RFC 2104) over BLAKE2s with a key of one hash length, which is the
/// only kind the Noise handshake uses (its `HMAC-HASH`).
pub(crate) fn hmac(key: &[u8; HASH_LEN], parts: &[&[u8]]) -> Zeroizing<[u8; HASH_LEN]> {
    let mut block = Zeroizing::new([0u8; BLOCK_LEN]);
    block[..HASH_LEN].copy_from_slice(key);
    block.iter_mut().for_each(|b| *b ^= 0x36);
    let mut inner = Blake2s::new();
    inner.update(&*block);
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();
    // From the inner pad to the outer one.
    block.iter_mut().for_each(|b| *b ^= 0x36 ^ 0x5c);
    let mut outer = Blake2s::new();
    outer.update(&*block);
    outer.update(&*inner);
    outer.finalize()
}

fn compress(h: &mut [u32; 8], block: &[u8; BLOCK_LEN], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for (word, bytes) in m.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().expect("four bytes"));
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, [0, 4, 8, 12], m[s[0]], m[s[1]]);
        g(&mut v, [1, 5, 9, 13], m[s[2]], m[s[3]]);
        g(&mut v, [2, 6, 10, 14], m[s[4]], m[s[5]]);
        g(&mut v, [3, 7, 11, 15], m[s[6]], m[s[7]]);
        g(&mut v, [0, 5, 10, 15], m[s[8]], m[s[9]]);
        g(&mut v, [1, 6, 11, 12], m[s[10]], m[s[11]]);
        g(&mut v, [2, 7, 8, 13], m[s[12]], m[s[13]]);
        g(&mut v, [3, 4, 9, 14], m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
    m.zeroize();
    v.zeroize();
}

/// The mixing function G, on the four words of `v` at `i`.
fn g(v: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Digest;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 7693, appendix B, and the hash of nothing.
    #[test]
    fn the_rfcs_example() {
        assert_eq!(
            hash(&[b"abc"]).to_vec(),
            hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
        assert_eq!(
            hash(&[]).to_vec(),
            hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
    }

    /// The same as the `blake2` crate for every length across several
    /// block boundaries, whether the input comes whole or in pieces.
    #[test]
    fn agrees_with_the_blake2_crate() {
        let data: Vec<u8> = (0..700u32).map(|i| (i * 131 + 7) as u8).collect();
        for len in 0..data.len() {
            let input = &data[..len];
            let reference = blake2::Blake2s256::digest(input);
            assert_eq!(
                hash(&[input]).as_slice(),
                reference.as_slice(),
                "length {}",
                len
            );
            let (a, b) = input.split_at(len / 3);
            assert_eq!(
                hash(&[a, b]).as_slice(),
                reference.as_slice(),
                "split {}",
                len
            );
        }
    }

    /// HMAC as RFC 2104 defines it, computed the long way with the crate.
    #[test]
    fn hmac_is_rfc_2104() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8 * 3);
        for len in [0usize, 1, 31, 32, 64, 65, 200] {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut padded = [0u8; 64];
            padded[..32].copy_from_slice(&key);
            let ipad: Vec<u8> = padded.iter().map(|b| b ^ 0x36).collect();
            let opad: Vec<u8> = padded.iter().map(|b| b ^ 0x5c).collect();
            let inner = blake2::Blake2s256::digest([&ipad[..], &msg].concat());
            let outer = blake2::Blake2s256::digest([&opad[..], &inner[..]].concat());
            assert_eq!(
                hmac(&key, &[&msg]).as_slice(),
                outer.as_slice(),
                "length {}",
                len
            );
        }
    }
}
