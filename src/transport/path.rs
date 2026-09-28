//! Address validation before a session follows its peer to a new address.
//!
//! A peer's address legitimately changes mid-transfer: a NAT rebinds its
//! mapping, a laptop moves from Wi-Fi to a wired link, a mobile connection
//! switches base stations. A session that simply started sending to whatever
//! address its last packet came from would, however, be a redirection tool:
//! an attacker on the path can copy an authentic packet and re-send it with
//! a forged source address, and the two ends would then aim a multi-gigabit
//! stream at a victim of its choosing. Authentication alone does not prevent
//! this, because the attacker does not need to *make* a valid packet — only
//! to repeat one from somewhere else.
//!
//! So a new address is treated as a claim to be proven, exactly as QUIC does
//! it (RFC 9000 section 8). The session keeps sending to the address it has
//! already proven and sends a PATH_CHALLENGE, carrying an unpredictable
//! token, to the new one. Only the genuine peer can answer: the response is
//! an authenticated frame, so it takes the session keys to produce, and it
//! has to come back *from the challenged address*, so it takes delivery
//! there to return. Until that happens nothing else is sent to the new
//! address, which also means a challenge can never be used for amplification:
//! the one small frame it sends is a reply to a packet that was at least as
//! large.
//!
//! Replays of an old PATH_RESPONSE are caught before they reach this module,
//! by the transport's replay window; a token is used once and forgotten.

use crate::protocol::constants::PATH_TOKEN_LEN;
use rand::RngCore;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Challenges sent for one address claim before it is abandoned.
const MAX_TRIES: u32 = 4;
/// Shortest wait between challenges, however small the measured RTT is.
const MIN_RETRY: Duration = Duration::from_millis(100);

/// A challenge the caller should send: `nonce` to `to`, as an authenticated
/// PATH_CHALLENGE frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge {
    pub to: SocketAddr,
    pub nonce: [u8; PATH_TOKEN_LEN],
}

struct Probe {
    addr: SocketAddr,
    nonce: [u8; PATH_TOKEN_LEN],
    sent_at: Instant,
    tries: u32,
}

/// Tracks the one unproven address claim a session may have outstanding.
///
/// The caller owns the proven address (the one it sends to) and passes it in;
/// this type only decides when to challenge and when a claim is proven.
#[derive(Default)]
pub struct PathProbe {
    probe: Option<Probe>,
}

impl PathProbe {
    pub fn new() -> Self {
        Self { probe: None }
    }

    /// An authentic packet arrived from `from`, while `peer` is the address
    /// the session has proven and sends to. Returns the challenge to send
    /// when `from` is a new address whose claim is not already being tested.
    pub fn on_authentic(
        &mut self,
        from: SocketAddr,
        peer: SocketAddr,
        now: Instant,
    ) -> Option<Challenge> {
        if from == peer {
            // The proven path is alive; an outstanding claim for some other
            // address is no longer interesting.
            self.probe = None;
            return None;
        }
        if self.probe.as_ref().is_some_and(|p| p.addr == from) {
            return None; // already being tested
        }
        let mut nonce = [0u8; PATH_TOKEN_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.probe = Some(Probe {
            addr: from,
            nonce,
            sent_at: now,
            tries: 1,
        });
        Some(Challenge { to: from, nonce })
    }

    /// A PATH_RESPONSE carrying `data` arrived from `from`. Returns the
    /// address to migrate to when it proves the outstanding claim.
    ///
    /// The token must match *and* come back from the very address it was
    /// sent to: a peer that echoes it from somewhere else proves nothing
    /// about the address in question.
    pub fn on_response(
        &mut self,
        from: SocketAddr,
        data: [u8; PATH_TOKEN_LEN],
    ) -> Option<SocketAddr> {
        let p = self.probe.as_ref()?;
        if p.addr != from || p.nonce != data {
            return None;
        }
        self.probe = None;
        Some(from)
    }

    /// Re-sends an unanswered challenge once `rto` has passed, and gives the
    /// claim up after [`MAX_TRIES`]. Losing a challenge must not cost the
    /// session its chance to follow a peer that really did move.
    pub fn poll(&mut self, now: Instant, rto: Duration) -> Option<Challenge> {
        let p = self.probe.as_mut()?;
        if now.saturating_duration_since(p.sent_at) < rto.max(MIN_RETRY) {
            return None;
        }
        if p.tries >= MAX_TRIES {
            // Nothing answers there; keep sending to the proven address.
            let addr = p.addr;
            self.probe = None;
            tracing::debug!("address {} did not answer the path challenge", addr);
            return None;
        }
        p.tries += 1;
        p.sent_at = now;
        Some(Challenge {
            to: p.addr,
            nonce: p.nonce,
        })
    }

    /// Forgets any outstanding claim (the proven address was set by other
    /// means, such as a fresh handshake, which authenticates its source).
    pub fn reset(&mut self) {
        self.probe = None;
    }

    /// The address currently being tested, if any.
    #[cfg(test)]
    pub fn probing(&self) -> Option<SocketAddr> {
        self.probe.as_ref().map(|p| p.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_new_address_is_challenged_and_only_migrates_when_it_answers() {
        let peer = addr("192.0.2.1:5555");
        let moved = addr("198.51.100.9:6000");
        let now = Instant::now();
        let mut p = PathProbe::new();

        // Packets from the proven address change nothing.
        assert!(p.on_authentic(peer, peer, now).is_none());

        // A packet from elsewhere is a claim: challenge it, do not migrate.
        let c = p.on_authentic(moved, peer, now).expect("challenged");
        assert_eq!(c.to, moved);
        assert_eq!(p.probing(), Some(moved));

        // More packets from the same address do not restart the challenge.
        assert!(p.on_authentic(moved, peer, now).is_none());

        // A wrong token, or the right token from a third address, proves
        // nothing.
        assert!(p.on_response(moved, [0; PATH_TOKEN_LEN]).is_none());
        assert!(p.on_response(addr("203.0.113.5:1"), c.nonce).is_none());

        // The genuine echo migrates the session.
        assert_eq!(p.on_response(moved, c.nonce), Some(moved));
        assert_eq!(p.probing(), None);
        // The token is spent: repeating it does nothing.
        assert!(p.on_response(moved, c.nonce).is_none());
    }

    #[test]
    fn challenges_are_repeated_then_the_claim_is_dropped() {
        let peer = addr("192.0.2.1:5555");
        let other = addr("198.51.100.9:6000");
        let rto = Duration::from_millis(200);
        let mut now = Instant::now();
        let mut p = PathProbe::new();

        let first = p.on_authentic(other, peer, now).expect("challenged");
        // Too early to repeat.
        assert!(p.poll(now, rto).is_none());
        // Every repeat carries the same token, so a late answer to any of
        // them still counts.
        for _ in 1..MAX_TRIES {
            now += rto;
            let again = p.poll(now, rto).expect("repeated");
            assert_eq!(again, first);
        }
        // After the last try the claim is abandoned and the proven address
        // keeps the traffic.
        now += rto;
        assert!(p.poll(now, rto).is_none());
        assert_eq!(p.probing(), None);
        assert!(p.on_response(other, first.nonce).is_none());
    }

    #[test]
    fn traffic_from_the_proven_address_cancels_a_claim() {
        let peer = addr("192.0.2.1:5555");
        let other = addr("198.51.100.9:6000");
        let now = Instant::now();
        let mut p = PathProbe::new();
        let c = p.on_authentic(other, peer, now).expect("challenged");
        assert!(p.on_authentic(peer, peer, now).is_none());
        assert_eq!(p.probing(), None);
        // A late echo of the abandoned claim no longer migrates anything.
        assert!(p.on_response(other, c.nonce).is_none());
    }
}
