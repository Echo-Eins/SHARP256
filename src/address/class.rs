//! What an IP address is, by its value alone, and which of several to try
//! first.
//!
//! Every decision this crate makes about an address without talking to it
//! — whether it is worth publishing, whether it is worth sending to on a
//! stranger's word, whether it says we are behind a NAT, which of several
//! a sender should try first — comes down to two documents: the
//! special-purpose address registries (RFC 6890 and the RFCs that updated
//! them) and the default policy table of RFC 6724. They live here, in one
//! place. A scatter of half-overlapping checks was what this replaced, and
//! an address one of those checks forgot is the classic way through such a
//! screen: `::ffff:127.0.0.1` is loopback, `::ffff:224.0.0.1` is multicast,
//! and a check that only knew IPv4 spellings let both through.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// What an address is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// `0.0.0.0`, `::`: no address at all.
    Unspecified,
    /// `127.0.0.0/8`, `::1`: this host.
    Loopback,
    /// `169.254.0.0/16`, `fe80::/10`: meaningful on one link only — and,
    /// for IPv6, only together with the interface it belongs to, which a
    /// written-down address does not carry.
    LinkLocal,
    /// RFC 1918 space, and unique local IPv6 (`fc00::/7`, RFC 4193):
    /// reachable inside one network, never from the internet.
    Private,
    /// `100.64.0.0/10` (RFC 6598): the inside of a carrier-grade NAT.
    Shared,
    /// Documentation ranges (RFC 5737, RFC 3849, RFC 9637). Nothing real
    /// lives there; tests and examples do.
    Documentation,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// Set aside for something other than a unicast host: "this network"
    /// (`0.0.0.0/8`), the old class E (`240.0.0.0/4`), benchmarking, IETF
    /// protocol assignments, deprecated site-local (`fec0::/10`) and
    /// IPv4-compatible IPv6, the rest of `::/8`, the discard prefix
    /// (`100::/64`), the local-use translation prefix (`64:ff9b:1::/48`)
    /// and SRv6 segment identifiers (`5f00::/16`).
    Reserved,
    /// Anything else: a unicast address the internet at large routes. The
    /// NAT64 well-known prefix (`64:ff9b::/96`), Teredo (`2001::/32`) and
    /// 6to4 (`2002::/16`) are here too — they reach real hosts, if less
    /// directly, which the precedence below accounts for.
    Global,
}

/// Classifies `ip`, looking through the IPv4-mapped spelling a dual-stack
/// socket uses for IPv4 peers.
pub fn classify(ip: IpAddr) -> Class {
    match ip.to_canonical() {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Class {
    let o = ip.octets();
    match o {
        [0, 0, 0, 0] => Class::Unspecified,
        [255, 255, 255, 255] => Class::Broadcast,
        [127, ..] => Class::Loopback,
        [169, 254, ..] => Class::LinkLocal,
        [10, ..] | [192, 168, ..] => Class::Private,
        [172, b, ..] if (16..32).contains(&b) => Class::Private,
        [100, b, ..] if (64..128).contains(&b) => Class::Shared,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _] => Class::Documentation,
        [a, ..] if (224..240).contains(&a) => Class::Multicast,
        // "This network", and 240.0.0.0/4 (the broadcast address is above).
        [0, ..] => Class::Reserved,
        [a, ..] if a >= 240 => Class::Reserved,
        // Benchmarking (RFC 2544).
        [198, 18 | 19, ..] => Class::Reserved,
        // IETF protocol assignments, except the PCP and TURN anycast
        // addresses, which are ordinary destinations (RFC 7723, RFC 8155).
        [192, 0, 0, d] if !matches!(d, 9 | 10) => Class::Reserved,
        // The 6to4 relay anycast prefix, deprecated (RFC 7526).
        [192, 88, 99, _] => Class::Reserved,
        _ => Class::Global,
    }
}

fn classify_v6(ip: Ipv6Addr) -> Class {
    let s = ip.segments();
    if ip.is_unspecified() {
        return Class::Unspecified;
    }
    if ip.is_loopback() {
        return Class::Loopback;
    }
    match s[0] {
        a if a & 0xff00 == 0xff00 => Class::Multicast,
        a if a & 0xffc0 == 0xfe80 => Class::LinkLocal,
        a if a & 0xfe00 == 0xfc00 => Class::Private,
        // Site-local, deprecated (RFC 3879).
        a if a & 0xffc0 == 0xfec0 => Class::Reserved,
        // 3fff::/20 (RFC 9637).
        a if a & 0xfff0 == 0x3ff0 => Class::Documentation,
        0x2001 => match s[1] {
            0x0db8 => Class::Documentation,
            // Benchmarking (RFC 5180).
            0x0002 if s[2] == 0 => Class::Reserved,
            // ORCHID, deprecated (RFC 7343 replaced it).
            b if b & 0xfff0 == 0x0010 => Class::Reserved,
            _ => Class::Global,
        },
        // The NAT64 well-known prefix is a real destination (a translator
        // answers it); the local-use prefix next to it is not global.
        0x0064 if s[1] == 0xff9b => {
            if s[2..6] == [0, 0, 0, 0] {
                Class::Global
            } else {
                Class::Reserved
            }
        }
        // Discard-only (RFC 6666).
        0x0100 if s[1..4] == [0, 0, 0] => Class::Reserved,
        // SRv6 segment identifiers (RFC 9602).
        0x5f00 => Class::Reserved,
        // The rest of ::/8, IPv4-compatible addresses included (the mapped
        // ones never get here: `classify` sees through them first).
        a if a < 0x0100 => Class::Reserved,
        _ => Class::Global,
    }
}

/// Whether the internet at large can route to `ip`, as far as its value
/// can say.
pub fn is_global(ip: IpAddr) -> bool {
    classify(ip) == Class::Global
}

/// Whether `ip` is unmistakably the inside of some network: private,
/// carrier-grade NAT space, link-local, loopback or nothing at all. A
/// router that calls such an address its "external" one is itself behind
/// another NAT.
pub fn is_inside(ip: IpAddr) -> bool {
    matches!(
        classify(ip),
        Class::Private | Class::Shared | Class::LinkLocal | Class::Loopback | Class::Unspecified
    )
}

/// Whether an IPv6 address is a unicast link-local one (`fe80::/10`).
/// `Ipv6Addr::is_unicast_link_local` says the same, but is newer than the
/// Rust version this crate supports.
pub fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

/// Whether an address somebody else told us about — a relay, a STUN
/// server, a name server — is one worth sending a datagram to from a
/// socket bound at `local`.
///
/// None of those is trusted, and every value here is entirely their
/// choice. Without the screen, a hostile one could name a port on this very
/// host, a multicast or broadcast group, or an address the socket cannot
/// reach at all, and we would fire datagrams there. What it cannot do is
/// tell an ordinary address from a victim's: any host on our network or
/// beyond may be named, and what bounds that is how little is ever sent on
/// such a say-so.
pub fn is_sendable_hint(addr: SocketAddr, local: SocketAddr) -> bool {
    if addr.port() == 0 || !super::Reach::assume(local).reaches(addr) {
        return false;
    }
    // Loopback only when we are on loopback ourselves: a stranger must never
    // be able to point a socket with a public address back into this host.
    // A server that really is on this host, and the simulated networks the
    // tests run on, still work.
    let on_loopback = classify(local.ip()) == Class::Loopback;
    match classify(addr.ip()) {
        Class::Loopback => on_loopback,
        Class::Global | Class::Private | Class::Shared | Class::Documentation => true,
        // A link-local address means nothing without the interface it
        // belongs to, and a stranger cannot know ours.
        Class::LinkLocal
        | Class::Unspecified
        | Class::Multicast
        | Class::Broadcast
        | Class::Reserved => false,
    }
}

/// Whether an address the user wrote, or a name the user gave resolved
/// to, is worth sending to from a socket bound at `local`.
///
/// Looser than [`is_sendable_hint`] where the user's word counts: a
/// receiver on this very host is an ordinary thing to reach, so loopback
/// is fine, and a link-local IPv6 address is fine when it names its
/// interface (`fe80::1%eth0`). What is never worth a datagram — no
/// address, a group, a reserved range — is still left out.
pub fn is_sendable_named(addr: SocketAddr, local: SocketAddr) -> bool {
    if addr.port() == 0 || !super::Reach::assume(local).reaches(addr) {
        return false;
    }
    match classify(addr.ip()) {
        Class::Unspecified | Class::Multicast | Class::Broadcast | Class::Reserved => false,
        Class::LinkLocal => match addr {
            SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_none() => v6.scope_id() != 0,
            _ => true,
        },
        Class::Loopback | Class::Global | Class::Private | Class::Shared | Class::Documentation => {
            true
        }
    }
}

/// Whether one of this host's own addresses is worth publishing to peers,
/// following ICE's rules for host candidates (RFC 8445 section 5.1.1.1):
/// never loopback, deprecated site-local or IPv4-compatible IPv6, nor
/// anything that is not a unicast address of this host; and no IPv6
/// link-local address, which a peer could use only together with an
/// interface of its own it cannot guess.
pub fn is_publishable_host(ip: IpAddr) -> bool {
    match classify(ip) {
        Class::Global | Class::Private | Class::Shared | Class::Documentation => true,
        // IPv4 link-local (a host that got no address from DHCP) still
        // reaches its neighbours; the IPv6 kind needs a zone.
        Class::LinkLocal => ip.to_canonical().is_ipv4(),
        _ => false,
    }
}

// ----- RFC 6724: default address selection ------------------------------

/// Precedence of a destination in the default policy table of RFC 6724
/// (section 2.1). Higher is tried first. IPv4 destinations count as their
/// mapped form (`::ffff:0:0/96`), as that section prescribes.
pub fn precedence(ip: IpAddr) -> u8 {
    policy(ip).0
}

/// Label of an address in the same table: a source and a destination with
/// the same label belong together (rule 5).
pub fn label(ip: IpAddr) -> u8 {
    policy(ip).1
}

fn policy(ip: IpAddr) -> (u8, u8) {
    let v6 = match ip.to_canonical() {
        IpAddr::V4(_) => return (35, 4),
        IpAddr::V6(v6) => v6,
    };
    let s = v6.segments();
    if v6.is_loopback() {
        (50, 0)
    } else if s[0] == 0x2002 {
        (30, 2)
    } else if s[0] == 0x2001 && s[1] == 0 {
        (5, 5)
    } else if s[0] & 0xfe00 == 0xfc00 {
        (3, 13)
    } else if s[..6] == [0, 0, 0, 0, 0, 0] {
        (1, 3)
    } else if s[0] & 0xffc0 == 0xfec0 {
        (1, 11)
    } else if s[0] == 0x3ffe {
        (1, 12)
    } else {
        (40, 1)
    }
}

/// Scope of an address in the sense of RFC 6724 section 3.1: 2 for
/// link-local (IPv4 loopback and 169.254/16 count as that, section 3.2), 5
/// for site-local, 14 for global; a multicast address carries its own.
pub fn scope(ip: IpAddr) -> u8 {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_link_local() {
                0x2
            } else {
                0xe
            }
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            if s0 & 0xff00 == 0xff00 {
                (s0 & 0x000f) as u8
            } else if v6.is_loopback() || s0 & 0xffc0 == 0xfe80 {
                0x2
            } else if s0 & 0xffc0 == 0xfec0 {
                0x5
            } else {
                0xe
            }
        }
    }
}

/// The source address this host would use to send to `dest`, or `None`
/// when it has no route there at all.
///
/// Asked of the system, which applies source address selection (RFC 6724
/// section 5, temporary addresses preferred where privacy extensions are
/// on) by connecting a throwaway UDP socket: connecting one sends nothing.
pub fn source_for(dest: SocketAddr) -> Option<IpAddr> {
    let dest = super::canonical(dest);
    // Linux takes a connect to "any" as one to this host, which is not a
    // route to anywhere.
    if dest.ip().is_unspecified() {
        return None;
    }
    let local: SocketAddr = if dest.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = std::net::UdpSocket::bind(local).ok()?;
    socket.connect(dest).ok()?;
    let src = socket.local_addr().ok()?.ip();
    (!src.is_unspecified()).then_some(src)
}

/// Orders destinations the way RFC 6724 section 6 does, as far as it
/// matters here, keeping the given order among equals (rule 10):
///
/// 1. one this host has no route to at all goes last;
/// 2. one whose scope matches that of the source it would be sent from
///    comes first;
/// 5. so does one whose label matches its source's;
/// 6. then higher precedence — native IPv6 before IPv4, IPv4 before
///    Teredo and unique-local addresses;
/// 8. then smaller scope.
///
/// The rules about deprecated, home, native and longest-matching source
/// addresses need what only the kernel knows, and cannot reorder anything
/// a peer publishes by much; they are left out.
pub fn sort_destinations(dests: &mut [SocketAddr]) {
    sort_by_source(dests, source_for)
}

/// [`sort_destinations`] with the source lookup supplied (the tests supply
/// one, having no control over this host's routes).
pub fn sort_by_source(dests: &mut [SocketAddr], source: impl Fn(SocketAddr) -> Option<IpAddr>) {
    let key = |d: &SocketAddr| {
        let ip = d.ip();
        let src = source(*d);
        let usable = src.is_some();
        let same_scope = src.is_some_and(|s| scope(s) == scope(ip));
        let same_label = src.is_some_and(|s| label(s) == label(ip));
        // Sorted ascending, so every "prefer" is a `false` that sorts
        // first, and precedence goes in reversed.
        (
            !usable,
            !same_scope,
            !same_label,
            u8::MAX - precedence(ip),
            scope(ip),
        )
    };
    let mut keyed: Vec<_> = dests.iter().map(|d| (key(d), *d)).collect();
    // Stable, so equals keep the order given (rule 10).
    keyed.sort_by_key(|&(k, _)| k);
    for (slot, (_, d)) in dests.iter_mut().zip(keyed) {
        *slot = d;
    }
}

/// Interleaves the address families of an ordered list, as RFC 8305
/// section 4 asks: the first address stays first, and after it the
/// families take turns, each keeping its own order. If one family is broken
/// end to end — a black-holed IPv6 path is the usual case — it can then
/// never fill the whole list of attempts.
pub fn interleave_families(dests: &[SocketAddr]) -> Vec<SocketAddr> {
    let Some(first) = dests.first() else {
        return Vec::new();
    };
    let first_v6 = super::canonical(*first).is_ipv6();
    let (mut a, mut b): (Vec<SocketAddr>, Vec<SocketAddr>) = dests
        .iter()
        .partition(|d| super::canonical(**d).is_ipv6() == first_v6);
    a.reverse();
    b.reverse();
    let mut out = Vec::with_capacity(dests.len());
    loop {
        match (a.pop(), b.pop()) {
            (None, None) => break,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_special_ranges() {
        let cases = [
            ("0.0.0.0", Class::Unspecified),
            ("0.1.2.3", Class::Reserved),
            ("10.1.2.3", Class::Private),
            ("100.63.255.255", Class::Global),
            ("100.64.0.1", Class::Shared),
            ("100.127.255.255", Class::Shared),
            ("100.128.0.0", Class::Global),
            ("127.0.0.1", Class::Loopback),
            ("127.255.0.9", Class::Loopback),
            ("169.254.10.1", Class::LinkLocal),
            ("172.15.255.255", Class::Global),
            ("172.16.0.1", Class::Private),
            ("172.31.255.255", Class::Private),
            ("172.32.0.0", Class::Global),
            ("192.0.0.1", Class::Reserved),
            ("192.0.0.9", Class::Global),
            ("192.0.0.10", Class::Global),
            ("192.0.0.170", Class::Reserved),
            ("192.0.2.33", Class::Documentation),
            ("192.88.99.1", Class::Reserved),
            ("192.168.1.7", Class::Private),
            ("198.18.0.1", Class::Reserved),
            ("198.19.255.1", Class::Reserved),
            ("198.20.0.1", Class::Global),
            ("198.51.100.7", Class::Documentation),
            ("203.0.113.5", Class::Documentation),
            ("224.0.0.1", Class::Multicast),
            ("239.255.255.250", Class::Multicast),
            ("240.0.0.1", Class::Reserved),
            ("255.255.255.255", Class::Broadcast),
            ("8.8.8.8", Class::Global),
            ("1.1.1.1", Class::Global),
        ];
        for (a, want) in cases {
            assert_eq!(classify(ip(a)), want, "{}", a);
        }
    }

    #[test]
    fn ipv6_special_ranges() {
        let cases = [
            ("::", Class::Unspecified),
            ("::1", Class::Loopback),
            ("::2", Class::Reserved),
            ("::192.0.2.1", Class::Reserved),
            ("64:ff9b::192.0.2.1", Class::Global),
            ("64:ff9b::1:2:3:4", Class::Reserved),
            ("64:ff9b:1::1", Class::Reserved),
            ("100::1", Class::Reserved),
            ("100:0:0:1::1", Class::Global),
            ("2001::1", Class::Global),
            ("2001:2::1", Class::Reserved),
            ("2001:10::1", Class::Reserved),
            ("2001:db8::7", Class::Documentation),
            ("2002:c000:221::1", Class::Global),
            ("2606:4700::1111", Class::Global),
            ("3fff::1", Class::Documentation),
            ("3fff:fff::1", Class::Documentation),
            ("5f00::1", Class::Reserved),
            ("fc00::1", Class::Private),
            ("fd12:3456::1", Class::Private),
            ("fe80::1", Class::LinkLocal),
            ("febf::1", Class::LinkLocal),
            ("fec0::1", Class::Reserved),
            ("ff02::1", Class::Multicast),
            ("ff0e::1", Class::Multicast),
        ];
        for (a, want) in cases {
            assert_eq!(classify(ip(a)), want, "{}", a);
        }
    }

    /// A dual-stack socket writes IPv4 peers as mapped IPv6 addresses; the
    /// classification must see through that spelling, or a screen written
    /// against IPv4 ranges lets `::ffff:127.0.0.1` straight past.
    #[test]
    fn mapped_addresses_are_what_they_map() {
        assert_eq!(classify(ip("::ffff:127.0.0.1")), Class::Loopback);
        assert_eq!(classify(ip("::ffff:224.0.0.1")), Class::Multicast);
        assert_eq!(classify(ip("::ffff:10.0.0.1")), Class::Private);
        assert_eq!(classify(ip("::ffff:8.8.8.8")), Class::Global);
        assert!(is_inside(ip("::ffff:100.64.1.1")));
        assert!(!is_inside(ip("::ffff:203.0.113.1")));
    }

    #[test]
    fn hints_from_strangers_are_screened() {
        let public: SocketAddr = sa("0.0.0.0:5555");
        let dual: SocketAddr = sa("[::]:5555");
        for bad in [
            "127.0.0.1:22",
            "[::ffff:127.0.0.1]:22",
            "[::1]:22",
            "224.0.0.1:5555",
            "[ff02::1]:5555",
            "255.255.255.255:5555",
            "0.0.0.0:5555",
            "[::]:5555",
            "0.1.2.3:5555",
            "240.0.0.1:5555",
            "169.254.1.1:5555",
            "[fe80::1]:5555",
            "[fec0::1]:5555",
            "[100::1]:5555",
            "198.51.100.7:0",
        ] {
            assert!(
                !is_sendable_hint(sa(bad), dual),
                "{} on a dual-stack socket",
                bad
            );
        }
        for good in [
            "198.51.100.7:5555",
            "192.168.1.7:5555",
            "100.64.1.1:5555",
            "[2001:db8::7]:5555",
            "[fd00::7]:5555",
            "[64:ff9b::c633:6407]:5555",
        ] {
            assert!(
                is_sendable_hint(sa(good), dual),
                "{} on a dual-stack socket",
                good
            );
        }
        // An IPv4 socket cannot send to IPv6 at all.
        assert!(!is_sendable_hint(sa("[2001:db8::7]:5555"), public));
        assert!(is_sendable_hint(sa("198.51.100.7:5555"), public));
        // Loopback is fine for a socket that is itself on loopback.
        assert!(is_sendable_hint(sa("127.0.0.1:9"), sa("127.0.0.1:5555")));
        assert!(is_sendable_hint(sa("[::1]:9"), sa("[::1]:5555")));
    }

    #[test]
    fn names_the_user_gave_may_point_home() {
        let dual = sa("[::]:0");
        for ok in [
            "127.0.0.1:5555",
            "[::1]:5555",
            "[fe80::1%2]:5555",
            "192.168.1.7:5555",
            "[2001:db8::7]:5555",
        ] {
            assert!(is_sendable_named(sa(ok), dual), "{}", ok);
        }
        for bad in [
            "[fe80::1]:5555",
            "0.0.0.0:5555",
            "[ff02::1]:5555",
            "255.255.255.255:1",
            "240.0.0.1:1",
            "127.0.0.1:0",
        ] {
            assert!(!is_sendable_named(sa(bad), dual), "{}", bad);
        }
        assert!(!is_sendable_named(sa("[::1]:5555"), sa("0.0.0.0:0")));
    }

    #[test]
    fn host_candidates_follow_ice() {
        for ok in [
            "192.168.1.7",
            "10.0.0.1",
            "203.0.113.5",
            "2606:4700::1",
            "fd00::1",
            "169.254.3.4",
        ] {
            assert!(is_publishable_host(ip(ok)), "{}", ok);
        }
        for bad in [
            "127.0.0.1",
            "::1",
            "fe80::1",
            "fec0::1",
            "::192.0.2.1",
            "::",
            "224.0.0.1",
            "ff02::1",
        ] {
            assert!(!is_publishable_host(ip(bad)), "{}", bad);
        }
    }

    #[test]
    fn precedence_follows_the_default_policy_table() {
        assert_eq!(precedence(ip("::1")), 50);
        assert_eq!(precedence(ip("2606:4700::1")), 40);
        assert_eq!(precedence(ip("203.0.113.5")), 35);
        assert_eq!(precedence(ip("::ffff:203.0.113.5")), 35);
        assert_eq!(precedence(ip("2002:c000:221::1")), 30);
        assert_eq!(precedence(ip("2001::1")), 5);
        assert_eq!(precedence(ip("fd00::1")), 3);
        assert_eq!(precedence(ip("fec0::1")), 1);
        assert_eq!(scope(ip("fe80::1")), 2);
        assert_eq!(scope(ip("169.254.1.1")), 2);
        assert_eq!(scope(ip("127.0.0.1")), 2);
        assert_eq!(scope(ip("10.0.0.1")), 14);
        assert_eq!(scope(ip("ff05::2")), 5);
    }

    /// With a global IPv6 source, native IPv6 goes before IPv4 and IPv4
    /// before unique-local; with no IPv6 route at all, every IPv6
    /// destination goes last. The published order survives among equals.
    #[test]
    fn destinations_sort_as_rfc6724_says() {
        let mut d = vec![
            sa("203.0.113.5:5555"),
            sa("[fd00::7]:5555"),
            sa("192.168.1.7:5555"),
            sa("[2001:db8::7]:5555"),
        ];
        let dual = |dst: SocketAddr| -> Option<IpAddr> {
            Some(if dst.is_ipv4() {
                ip("192.168.1.2")
            } else {
                ip("2001:db8::2")
            })
        };
        sort_by_source(&mut d, dual);
        assert_eq!(
            d,
            [
                sa("[2001:db8::7]:5555"),
                sa("203.0.113.5:5555"),
                sa("192.168.1.7:5555"),
                sa("[fd00::7]:5555"),
            ]
        );
        let v4_only = |dst: SocketAddr| dst.is_ipv4().then(|| ip("192.168.1.2"));
        sort_by_source(&mut d, v4_only);
        assert_eq!(
            d,
            [
                sa("203.0.113.5:5555"),
                sa("192.168.1.7:5555"),
                sa("[2001:db8::7]:5555"),
                sa("[fd00::7]:5555"),
            ]
        );
        // A host whose only IPv6 address is link-local has no business
        // trying global IPv6 first (rule 2, matching scope).
        let link_local_only = |dst: SocketAddr| -> Option<IpAddr> {
            Some(if dst.is_ipv4() {
                ip("192.168.1.2")
            } else {
                ip("fe80::2")
            })
        };
        let mut d = vec![sa("[2001:db8::7]:5555"), sa("203.0.113.5:5555")];
        sort_by_source(&mut d, link_local_only);
        assert_eq!(d, [sa("203.0.113.5:5555"), sa("[2001:db8::7]:5555")]);
    }

    #[test]
    fn families_take_turns_after_the_first() {
        let d = [
            sa("[2001:db8::1]:1"),
            sa("[2001:db8::2]:1"),
            sa("[2001:db8::3]:1"),
            sa("192.0.2.1:1"),
            sa("192.0.2.2:1"),
        ];
        assert_eq!(
            interleave_families(&d),
            [
                sa("[2001:db8::1]:1"),
                sa("192.0.2.1:1"),
                sa("[2001:db8::2]:1"),
                sa("192.0.2.2:1"),
                sa("[2001:db8::3]:1"),
            ]
        );
        // The first family is whichever the sorted list starts with, and
        // a mapped address counts as IPv4.
        let d = [
            sa("[::ffff:192.0.2.1]:1"),
            sa("192.0.2.2:1"),
            sa("[2001:db8::1]:1"),
        ];
        assert_eq!(
            interleave_families(&d),
            [
                sa("[::ffff:192.0.2.1]:1"),
                sa("[2001:db8::1]:1"),
                sa("192.0.2.2:1")
            ]
        );
        assert!(interleave_families(&[]).is_empty());
    }

    #[test]
    fn the_system_names_a_source_only_where_it_has_a_route() {
        assert_eq!(source_for(sa("127.0.0.1:9")), Some(ip("127.0.0.1")));
        // Unspecified is not a destination.
        assert_eq!(source_for(sa("0.0.0.0:9")), None);
        // Where the host has IPv6 at all, it has a route to its loopback.
        if std::net::UdpSocket::bind("[::1]:0").is_ok() {
            assert_eq!(source_for(sa("[::1]:9")), Some(ip("::1")));
        } else {
            assert!(
                std::env::var_os("SHARP_REQUIRE_IPV6").is_none(),
                "this host has no IPv6, and SHARP_REQUIRE_IPV6 is set"
            );
        }
    }
}
