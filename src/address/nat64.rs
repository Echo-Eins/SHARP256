//! Reaching IPv4 addresses from a network that only has IPv6.
//!
//! Mobile networks, and more and more others, give their hosts IPv6 alone
//! and reach the IPv4 internet through a NAT64 translator (RFC 6146): an
//! IPv4 address is spoken to as an IPv6 address inside a prefix the
//! translator owns, with the IPv4 address embedded in it (RFC 6052). Their
//! name servers do the embedding for names (DNS64, RFC 6147). Nothing does
//! it for an IPv4 *literal* — and a receiver's published addresses, a
//! relay given as `host:port`, are exactly that. RFC 8305 section 7.1 asks
//! the client to do it itself, with the prefix learned the way RFC 7050
//! describes: the special name `ipv4only.arpa` has two well-known IPv4
//! addresses and no IPv6 ones, so any IPv6 answer for it was made by the
//! network's DNS64, and shows where the prefix is.
//!
//! As with everything else learned from the network, the result is a hint.
//! A forged prefix sends handshake initiations somewhere useless, and the
//! handshake decides who answers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// A NAT64 prefix: where a translator embeds IPv4 addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    bytes: [u8; 16],
    len: u8,
}

/// The two addresses `ipv4only.arpa` has (RFC 7050 section 2.2).
pub const WELL_KNOWN_V4: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

/// The name RFC 7050 asks about.
pub const DISCOVERY_NAME: &str = "ipv4only.arpa";

/// Which bytes of the IPv6 address carry the IPv4 one, for each prefix
/// length RFC 6052 (section 2.2) allows. Byte 8 — bits 64 to 71 — is
/// never used: it has to stay zero for compatibility with the interface
/// identifier format.
fn positions(len: u8) -> Option<[usize; 4]> {
    Some(match len {
        32 => [4, 5, 6, 7],
        40 => [5, 6, 7, 9],
        48 => [6, 7, 9, 10],
        56 => [7, 9, 10, 11],
        64 => [9, 10, 11, 12],
        96 => [12, 13, 14, 15],
        _ => return None,
    })
}

impl Prefix {
    /// `64:ff9b::/96`, the well-known prefix (RFC 6052 section 2.1).
    pub const WELL_KNOWN: Prefix = Prefix {
        bytes: [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        len: 96,
    };

    /// A prefix of one of the lengths RFC 6052 allows, with everything
    /// past the length cleared. `None` for any other length, or when bits
    /// 64 to 71 are not zero, which no valid prefix has.
    pub fn new(addr: Ipv6Addr, len: u8) -> Option<Self> {
        positions(len)?;
        let mut bytes = addr.octets();
        let whole = len as usize / 8;
        bytes[whole..].fill(0);
        if bytes[8] != 0 {
            return None;
        }
        Some(Self { bytes, len })
    }

    /// The prefix length, in bits.
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    pub fn addr(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.bytes)
    }

    /// The IPv6 address the translator knows `v4` by (RFC 6052 section
    /// 2.2); the suffix is zero.
    pub fn synthesize(&self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut out = self.bytes;
        let pos = positions(self.len).expect("valid prefix length");
        for (p, b) in pos.iter().zip(v4.octets()) {
            out[*p] = b;
        }
        Ipv6Addr::from(out)
    }

    /// The IPv4 address embedded in `v6`, if `v6` lies in this prefix.
    pub fn extract(&self, v6: Ipv6Addr) -> Option<Ipv4Addr> {
        let o = v6.octets();
        let whole = self.len as usize / 8;
        if o[..whole] != self.bytes[..whole] || o[8] != 0 {
            return None;
        }
        let pos = positions(self.len)?;
        Some(Ipv4Addr::new(o[pos[0]], o[pos[1]], o[pos[2]], o[pos[3]]))
    }

    /// `v4` as this prefix spells it, with the port kept. Only for
    /// addresses a translator can serve: the well-known prefix must not
    /// stand for anything but global IPv4 (RFC 6052 section 3.1), and a
    /// private address embedded in another network's prefix names nothing
    /// anyone could reach.
    pub fn synthesize_addr(&self, v4: SocketAddr) -> Option<SocketAddr> {
        let IpAddr::V4(ip) = super::canonical(v4).ip() else {
            return None;
        };
        if !super::class::is_global(ip.into()) {
            return None;
        }
        Some(SocketAddr::new(self.synthesize(ip).into(), v4.port()))
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr(), self.len)
    }
}

/// Learns the prefix from the IPv6 answers for [`DISCOVERY_NAME`] (RFC
/// 7050 section 3): each should be one of the two well-known addresses
/// embedded in the prefix, and where it sits says how long the prefix is.
///
/// The lengths are tried longest first, and a length only counts when
/// every answer agrees with it — a prefix that happened to contain the
/// bytes of a well-known address at another position then cannot fool it.
pub fn from_answers(answers: &[Ipv6Addr]) -> Option<Prefix> {
    if answers.is_empty() {
        return None;
    }
    let mut found: Option<Prefix> = None;
    for len in [96u8, 64, 56, 48, 40, 32] {
        let mut agreed: Option<Prefix> = None;
        let mut all = true;
        for a in answers {
            let Some(p) = Prefix::new(*a, len) else {
                all = false;
                break;
            };
            let embedded = p.extract(*a);
            if !embedded.is_some_and(|v4| WELL_KNOWN_V4.contains(&v4)) {
                all = false;
                break;
            }
            match agreed {
                None => agreed = Some(p),
                Some(q) if q == p => {}
                Some(_) => {
                    all = false;
                    break;
                }
            }
        }
        if all {
            found = agreed;
            break;
        }
    }
    found
}

/// How long a discovered prefix (or the absence of one) is believed. The
/// network may change under a long-running receiver — a laptop moving
/// from Wi-Fi to a mobile network — but asking on every address would
/// cost a name lookup each time.
const REMEMBERED: Duration = Duration::from_secs(300);
/// How long the discovery lookup may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

static CACHE: parking_lot::Mutex<Option<(Instant, Option<Prefix>)>> = parking_lot::Mutex::new(None);

/// The network's NAT64 prefix, if it has one. Remembered for a few
/// minutes; the lookup itself is bounded.
pub async fn discover() -> Option<Prefix> {
    if let Some((at, p)) = *CACHE.lock() {
        if at.elapsed() < REMEMBERED {
            return p;
        }
    }
    let answers = tokio::time::timeout(
        LOOKUP_TIMEOUT,
        super::dns::lookup(DISCOVERY_NAME, 0, super::dns::Family::V6),
    )
    .await;
    let prefix = match answers {
        Ok(Ok(addrs)) => {
            let v6: Vec<Ipv6Addr> = addrs
                .iter()
                .filter_map(|a| match a.ip() {
                    IpAddr::V6(v6) => Some(v6),
                    IpAddr::V4(_) => None,
                })
                .collect();
            from_answers(&v6)
        }
        _ => None,
    };
    if let Some(p) = prefix {
        tracing::info!(
            "this network translates IPv4 through the NAT64 prefix {}",
            p
        );
    }
    *CACHE.lock() = Some((Instant::now(), prefix));
    prefix
}

/// Whether this host can reach `v4` over IPv4 at all. On an IPv6-only
/// network it has no IPv4 route, and a literal IPv4 address is only
/// reachable through the translator.
pub fn has_ipv4_route(v4: SocketAddr) -> bool {
    super::class::source_for(v4).is_some_and(|s| s.is_ipv4())
}

/// The addresses to try for an IPv4 address that this host may not be
/// able to reach directly: itself, and — on a network that has no IPv4
/// route and translates through NAT64 — the translated form, first.
pub async fn alternatives(v4: SocketAddr) -> Vec<SocketAddr> {
    let v4 = super::canonical(v4);
    if !v4.is_ipv4() || has_ipv4_route(v4) {
        return vec![v4];
    }
    match discover().await.and_then(|p| p.synthesize_addr(v4)) {
        Some(v6) => vec![v6, v4],
        None => vec![v4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// The examples of RFC 6052 section 2.4, every prefix length.
    #[test]
    fn embeds_as_rfc6052_shows() {
        let v4 = Ipv4Addr::new(192, 0, 2, 33);
        let cases = [
            ("2001:db8::", 32, "2001:db8:c000:221::"),
            ("2001:db8:100::", 40, "2001:db8:1c0:2:21::"),
            ("2001:db8:122::", 48, "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::", 56, "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::", 64, "2001:db8:122:344:c0:2:2100:0"),
            ("2001:db8:122:344::", 96, "2001:db8:122:344::192.0.2.33"),
        ];
        for (prefix, len, want) in cases {
            let p = Prefix::new(v6(prefix), len).unwrap();
            assert_eq!(p.synthesize(v4), v6(want), "/{}", len);
            assert_eq!(p.extract(v6(want)), Some(v4), "/{}", len);
        }
        assert_eq!(Prefix::WELL_KNOWN.synthesize(v4), v6("64:ff9b::192.0.2.33"));
    }

    #[test]
    fn only_valid_prefixes_are_accepted() {
        assert!(Prefix::new(v6("64:ff9b::"), 80).is_none());
        assert!(Prefix::new(v6("64:ff9b::"), 0).is_none());
        // Bits 64 to 71 must be zero.
        assert!(Prefix::new(v6("2001:db8:0:0:ff00::"), 96).is_none());
        // Bits past the length are cleared.
        let p = Prefix::new(v6("2001:db8:1:2:3:4:5:6"), 32).unwrap();
        assert_eq!(p.addr(), v6("2001:db8::"));
        // An address outside the prefix has nothing embedded in it.
        assert_eq!(p.extract(v6("2001:db9::1")), None);
    }

    /// RFC 7050: the answers for ipv4only.arpa show the prefix, and a
    /// length only counts when every answer agrees.
    #[test]
    fn learns_the_prefix_from_the_well_known_name() {
        let wkp = [v6("64:ff9b::c000:aa"), v6("64:ff9b::c000:ab")];
        assert_eq!(from_answers(&wkp), Some(Prefix::WELL_KNOWN));

        let p56 = Prefix::new(v6("2001:db8:122:300::"), 56).unwrap();
        let answers: Vec<Ipv6Addr> = WELL_KNOWN_V4.iter().map(|a| p56.synthesize(*a)).collect();
        assert_eq!(from_answers(&answers), Some(p56));

        for len in [32u8, 40, 48, 64] {
            let p = Prefix::new(v6("2001:db8:aaaa:bbbb::"), len).unwrap();
            let answers: Vec<Ipv6Addr> = WELL_KNOWN_V4.iter().map(|a| p.synthesize(*a)).collect();
            assert_eq!(from_answers(&answers), Some(p), "/{}", len);
        }

        // A real IPv6 address for the name means no translation at all.
        assert_eq!(from_answers(&[v6("2001:db8::1")]), None);
        assert_eq!(from_answers(&[]), None);
        // Answers that disagree about the prefix prove nothing.
        assert_eq!(
            from_answers(&[v6("64:ff9b::c000:aa"), v6("2001:db8::c000:ab")]),
            None
        );
    }

    #[test]
    fn only_global_ipv4_is_translated() {
        let p = Prefix::WELL_KNOWN;
        assert_eq!(
            p.synthesize_addr("8.8.8.8:53".parse().unwrap()),
            Some("[64:ff9b::808:808]:53".parse().unwrap())
        );
        assert_eq!(
            p.synthesize_addr("[::ffff:8.8.8.8]:53".parse().unwrap()),
            Some("[64:ff9b::808:808]:53".parse().unwrap())
        );
        for private in [
            "192.168.1.7:5555",
            "10.0.0.1:1",
            "127.0.0.1:1",
            "100.64.0.1:1",
        ] {
            assert_eq!(
                p.synthesize_addr(private.parse().unwrap()),
                None,
                "{}",
                private
            );
        }
        assert_eq!(p.synthesize_addr("[2001:db8::1]:1".parse().unwrap()), None);
    }

    /// A host with an IPv4 route has nothing to translate.
    #[tokio::test]
    async fn a_reachable_ipv4_address_stays_as_it_is() {
        let lo: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(has_ipv4_route(lo));
        assert_eq!(alternatives(lo).await, vec![lo]);
        let v6: SocketAddr = "[2001:db8::1]:9".parse().unwrap();
        assert_eq!(alternatives(v6).await, vec![v6]);
    }
}
