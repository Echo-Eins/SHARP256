//! Structured values from a fuzzer's bytes, for the targets that build
//! what they give the code rather than handing it the bytes: messages to
//! encode, and sequences of what peers do to a receiver or a relay.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

/// Reads values from the front of an input. Past its end every value reads
/// as zero, so every input makes some structure and a longer one a richer
/// one; a byte the fuzzer changes changes the value read from it.
pub struct Gen<'a> {
    data: &'a [u8],
}

impl<'a> Gen<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Whether the input is used up (from here on everything is zero).
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn u8(&mut self) -> u8 {
        match self.data.split_first() {
            Some((&b, rest)) => {
                self.data = rest;
                b
            }
            None => 0,
        }
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let n = N.min(self.data.len());
        out[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        out
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }

    pub fn i64(&mut self) -> i64 {
        i64::from_be_bytes(self.array())
    }

    pub fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }

    /// A number below `n` (1 or more), from as few bytes as it needs.
    pub fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        if n <= 1 << 8 {
            self.u8() as usize % n
        } else if n <= 1 << 16 {
            self.u16() as usize % n
        } else {
            self.u32() as usize % n
        }
    }

    /// A number in `lo..=hi`.
    pub fn within(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(lo <= hi);
        match hi - lo {
            u64::MAX => self.u64(),
            span => lo + self.u64() % (span + 1),
        }
    }

    /// One of `items`.
    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    /// Up to `max` bytes, as many as the next number says.
    pub fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| self.u8()).collect()
    }

    /// Text of up to `max` bytes, as many as the next number says: mostly
    /// ASCII, with characters of two, three and four bytes, and the ones
    /// that separate paths or end strings elsewhere.
    pub fn text(&mut self, max: usize) -> String {
        let n = self.below(max + 1);
        let mut s = String::new();
        while s.len() < n {
            let c = match self.u8() % 10 {
                0..=4 => char::from(b' ' + self.u8() % 95),
                5 => self.pick(&['é', 'ß', 'Ж', 'ж', 'ü']),
                6 => self.pick(&['€', '中', '文', '\u{200b}', '\u{fffd}']),
                7 => self.pick(&['😀', '𝄞', '🦀']),
                8 => self.pick(&['/', '\\', '.', ':', '\0', '\n', '%', '@']),
                _ => char::from(b'a' + self.u8() % 26),
            };
            if s.len() + c.len_utf8() > n {
                break;
            }
            s.push(c);
        }
        s
    }

    pub fn ipv4(&mut self) -> Ipv4Addr {
        Ipv4Addr::from(self.array::<4>())
    }

    pub fn ipv6(&mut self) -> Ipv6Addr {
        Ipv6Addr::from(self.array::<16>())
    }

    /// An address of either family: an IPv6 one sometimes with a flow label
    /// and a zone, sometimes an IPv4 one written in IPv6.
    pub fn socket_addr(&mut self) -> SocketAddr {
        let port = self.u16();
        match self.u8() % 4 {
            0 | 1 => SocketAddr::new(IpAddr::V4(self.ipv4()), port),
            2 => SocketAddr::V6(SocketAddrV6::new(self.ipv6(), port, self.u32(), self.u32())),
            _ => SocketAddr::V6(SocketAddrV6::new(self.ipv4().to_ipv6_mapped(), port, 0, 0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Past the end everything is zero; lengths and texts stay within what
    /// they were asked for.
    #[test]
    fn values_are_bounded_and_the_end_is_zero() {
        let mut g = Gen::new(&[7, 1, 2]);
        assert_eq!(g.u8(), 7);
        assert_eq!(g.u16(), 0x0102);
        assert_eq!((g.u8(), g.u32(), g.bool()), (0, 0, false));
        assert!(g.is_empty());
        for seed in 0..500u32 {
            let data: Vec<u8> = (0..64)
                .map(|i| (seed.wrapping_mul(2654435761) >> (i % 24)) as u8)
                .collect();
            let mut g = Gen::new(&data);
            assert!(g.text(30).len() <= 30);
            assert!(g.bytes(10).len() <= 10);
            assert!(g.below(3) < 3);
            let v = g.within(5, 9);
            assert!((5..=9).contains(&v));
        }
    }
}
