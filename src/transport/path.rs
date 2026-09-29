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
//! address, and the challenges themselves are held to three times what the
//! address has sent us (RFC 9000 section 8): a copied packet from a forged
//! source buys at most that, aimed at whoever owns the forged address.
//!
//! Replays of an old PATH_RESPONSE are caught before they reach this module,
//! by the transport's replay window; a token is used once and forgotten.

use crate::protocol::constants::PATH_TOKEN_LEN;
use rand::RngCore;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Challenges sent for one address claim before it is given up.
const MAX_TRIES: u32 = 6;
/// Shortest wait between challenges, however small the measured RTT is,
/// and the longest the doubling may reach.
const MIN_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(8);
/// Claims tested at once. More than one, because an attacker who copies the
/// peer's packets from a forged address makes a claim of its own every
/// time: with a single slot, each copy replaced the genuine claim and the
/// session could never follow a peer that really had moved.
const MAX_CLAIMS: usize = 4;
/// How long a given-up claim's token is still honoured. On a path slower
/// than the challenges, the answer may come back after the last of them —
/// and a new token for every new attempt meant it never matched anything.
const REMEMBER: Duration = Duration::from_secs(30);
/// Bytes of challenges sent to an address per byte received from it before
/// it is proven: the three RFC 9000 (section 8) allows. A challenge answers
/// traffic, so a copied packet from a forged source buys at most three
/// times its own size aimed at the forged address.
const AMPLIFICATION: usize = 3;
/// Size of one PATH_CHALLENGE datagram on the wire.
pub const CHALLENGE_BYTES: usize = crate::crypto::transport::OVERHEAD + PATH_TOKEN_LEN;

/// How long a direct path may be quiet before the session follows its peer
/// to a relay's or a TURN server's address again.
///
/// While the direct path is heard from, what comes through a server is the
/// other end catching up: packets it sent before it moved, answers to
/// challenges made then. Followed back, those made the two ends swap paths
/// in turn, each moving because the other just had, and a session could end
/// on a TURN server with a direct path open all along (the laboratory saw it
/// where the server's path is the slower one). A direct path that has gone
/// quiet this long is another matter: the session goes back to the server
/// (see the sender's re-handshakes after a stall).
pub const DIRECT_GRACE: Duration = Duration::from_secs(3);

/// Whether a claim for an address is to be passed over: it is a server's
/// (`to_relayed`) while the session runs on a direct address
/// (`!peer_relayed`) heard from `quiet` ago, within [`DIRECT_GRACE`]. A
/// direct address is always worth asking, and a server's is when the
/// session is on one already.
pub fn keeps_direct(to_relayed: bool, peer_relayed: bool, quiet: Duration) -> bool {
    to_relayed && !peer_relayed && quiet < DIRECT_GRACE
}

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
    /// Bytes of authentic packets from this address, and of challenges
    /// sent to it.
    received: usize,
    sent: usize,
    /// When the claim was given up; its token still counts for a while.
    given_up: Option<Instant>,
}

impl Probe {
    fn may_send(&self) -> bool {
        self.sent + CHALLENGE_BYTES <= AMPLIFICATION * self.received
    }

    fn challenge(&mut self, now: Instant) -> Challenge {
        self.sent_at = now;
        self.sent += CHALLENGE_BYTES;
        Challenge {
            to: self.addr,
            nonce: self.nonce,
        }
    }
}

/// Tracks the unproven address claims a session has outstanding.
///
/// The caller owns the proven address (the one it sends to) and passes it in;
/// this type only decides when to challenge and when a claim is proven.
#[derive(Default)]
pub struct PathProbe {
    probes: Vec<Probe>,
}

impl PathProbe {
    pub fn new() -> Self {
        Self { probes: Vec::new() }
    }

    /// An authentic packet of `len` bytes arrived from `from`, while `peer`
    /// is the address the session has proven and sends to. Returns the
    /// challenge to send when `from` is a new claim, or a given-up one
    /// speaking again.
    pub fn on_authentic(
        &mut self,
        from: SocketAddr,
        peer: SocketAddr,
        now: Instant,
        len: usize,
    ) -> Option<Challenge> {
        if from == peer {
            // The proven path is alive; claims for other addresses are no
            // longer interesting.
            self.probes.clear();
            return None;
        }
        self.forget_old(now);
        if let Some(p) = self.probes.iter_mut().find(|p| p.addr == from) {
            p.received = p.received.saturating_add(len);
            // Still being tested: nothing new to send.
            p.given_up?;
            // Speaking again after we gave up: test it again, with the same
            // token, so an answer to an earlier challenge still counts.
            p.given_up = None;
            p.tries = 1;
            return p.may_send().then(|| p.challenge(now));
        }
        if self.probes.len() >= MAX_CLAIMS {
            // Room for this one: a given-up claim goes first, then the
            // oldest.
            let victim = self
                .probes
                .iter()
                .enumerate()
                .min_by_key(|(_, p)| (p.given_up.is_none(), p.sent_at))
                .map(|(i, _)| i)
                .expect("full");
            self.probes.remove(victim);
        }
        let mut nonce = [0u8; PATH_TOKEN_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut p = Probe {
            addr: from,
            nonce,
            sent_at: now,
            tries: 1,
            received: len,
            sent: 0,
            given_up: None,
        };
        let c = p.may_send().then(|| p.challenge(now));
        self.probes.push(p);
        c
    }

    /// A PATH_RESPONSE carrying `data` arrived from `from`. Returns the
    /// address to migrate to when it proves a claim.
    ///
    /// The token must match *and* come back from the very address it was
    /// sent to: a peer that echoes it from somewhere else proves nothing
    /// about the address in question.
    pub fn on_response(
        &mut self,
        from: SocketAddr,
        data: [u8; PATH_TOKEN_LEN],
    ) -> Option<SocketAddr> {
        self.probes
            .iter()
            .find(|p| p.addr == from && p.nonce == data)?;
        // Proven. Every other claim is moot now.
        self.probes.clear();
        Some(from)
    }

    /// Re-sends unanswered challenges, each claim waiting twice as long as
    /// the time before — starting from `rto`, which should be an estimate
    /// of the round trip and not one already backed off — and gives a claim
    /// up after `MAX_TRIES`. Losing a challenge must not cost the session
    /// its chance to follow a peer that really did move.
    pub fn poll(&mut self, now: Instant, rto: Duration) -> Vec<Challenge> {
        self.forget_old(now);
        let mut out = Vec::new();
        for p in self.probes.iter_mut().filter(|p| p.given_up.is_none()) {
            let wait = (rto.max(MIN_RETRY) * (1u32 << (p.tries - 1).min(16))).min(MAX_RETRY);
            if now.saturating_duration_since(p.sent_at) < wait {
                continue;
            }
            if p.tries >= MAX_TRIES {
                // Nothing answers there; keep sending to the proven address.
                tracing::debug!("address {} did not answer the path challenge", p.addr);
                p.given_up = Some(now);
                continue;
            }
            // Only as much as the address has sent us; more of its traffic
            // raises the allowance.
            if !p.may_send() {
                continue;
            }
            p.tries += 1;
            out.push(p.challenge(now));
        }
        out
    }

    fn forget_old(&mut self, now: Instant) {
        self.probes.retain(|p| {
            p.given_up
                .is_none_or(|t| now.saturating_duration_since(t) < REMEMBER)
        });
    }

    /// Forgets every outstanding claim (the proven address was set by other
    /// means, such as a fresh handshake, which authenticates its source).
    pub fn reset(&mut self) {
        self.probes.clear();
    }

    /// The addresses currently being tested.
    #[cfg(test)]
    pub fn probing(&self) -> Vec<SocketAddr> {
        self.probes
            .iter()
            .filter(|p| p.given_up.is_none())
            .map(|p| p.addr)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// An ordinary packet's size: enough for a challenge and more.
    const LEN: usize = 100;

    #[test]
    fn a_new_address_is_challenged_and_only_migrates_when_it_answers() {
        let peer = addr("192.0.2.1:5555");
        let moved = addr("198.51.100.9:6000");
        let now = Instant::now();
        let mut p = PathProbe::new();

        // Packets from the proven address change nothing.
        assert!(p.on_authentic(peer, peer, now, LEN).is_none());

        // A packet from elsewhere is a claim: challenge it, do not migrate.
        let c = p.on_authentic(moved, peer, now, LEN).expect("challenged");
        assert_eq!(c.to, moved);
        assert_eq!(p.probing(), vec![moved]);

        // More packets from the same address do not restart the challenge.
        assert!(p.on_authentic(moved, peer, now, LEN).is_none());

        // A wrong token, or the right token from a third address, proves
        // nothing.
        assert!(p.on_response(moved, [0; PATH_TOKEN_LEN]).is_none());
        assert!(p.on_response(addr("203.0.113.5:1"), c.nonce).is_none());

        // The genuine echo migrates the session.
        assert_eq!(p.on_response(moved, c.nonce), Some(moved));
        assert!(p.probing().is_empty());
        // The token is spent: repeating it does nothing.
        assert!(p.on_response(moved, c.nonce).is_none());
    }

    #[test]
    fn challenges_back_off_and_a_late_answer_still_counts() {
        let peer = addr("192.0.2.1:5555");
        let other = addr("198.51.100.9:6000");
        let rto = Duration::from_millis(200);
        let start = Instant::now();
        let mut p = PathProbe::new();

        let first = p
            .on_authentic(other, peer, start, 10_000)
            .expect("challenged");
        // Too early to repeat.
        assert!(p.poll(start, rto).is_empty());
        // Every repeat carries the same token, and each waits twice as long
        // as the one before.
        let mut now = start;
        let mut wait = rto;
        for _ in 1..MAX_TRIES {
            assert!(p
                .poll(now + wait - Duration::from_millis(1), rto)
                .is_empty());
            now += wait;
            assert_eq!(p.poll(now, rto), vec![first]);
            wait = (wait * 2).min(MAX_RETRY);
        }
        // After the last try the claim is given up and the proven address
        // keeps the traffic...
        now += wait;
        assert!(p.poll(now, rto).is_empty());
        assert!(p.probing().is_empty());
        // ...but an answer that was merely slow still proves it.
        assert_eq!(p.on_response(other, first.nonce), Some(other));
    }

    #[test]
    fn a_claim_given_up_is_tested_again_with_the_same_token() {
        let peer = addr("192.0.2.1:5555");
        let other = addr("198.51.100.9:6000");
        let rto = Duration::from_millis(100);
        let mut now = Instant::now();
        let mut p = PathProbe::new();
        let first = p
            .on_authentic(other, peer, now, 10_000)
            .expect("challenged");
        for _ in 0..=MAX_TRIES {
            now += MAX_RETRY;
            p.poll(now, rto);
        }
        assert!(p.probing().is_empty());
        // It speaks again: challenged again, and a token from any round
        // proves it.
        let again = p.on_authentic(other, peer, now, LEN).expect("re-tested");
        assert_eq!(again.nonce, first.nonce);
        // Long after it was given up, it is forgotten.
        let mut q = PathProbe::new();
        let c = q.on_authentic(other, peer, now, 10_000).unwrap();
        for _ in 0..=MAX_TRIES {
            now += MAX_RETRY;
            q.poll(now, rto);
        }
        q.poll(now + REMEMBER, rto);
        assert!(q.on_response(other, c.nonce).is_none());
    }

    /// Somebody copying the peer's packets from forged addresses makes a
    /// claim of their own with every copy. The peer's real move must still
    /// be followed: claims are tested side by side, and none displaces
    /// another that is still being tested.
    #[test]
    fn a_copier_cannot_crowd_out_the_real_move() {
        let peer = addr("192.0.2.1:5555");
        let moved = addr("198.51.100.9:6000");
        let now = Instant::now();
        let mut p = PathProbe::new();
        let real = p.on_authentic(moved, peer, now, LEN).expect("challenged");
        for i in 0..MAX_CLAIMS - 1 {
            let forged = addr(&format!("203.0.113.{}:9", i + 1));
            assert!(p.on_authentic(forged, peer, now, LEN).is_some());
            // The real claim's packets keep arriving in between.
            assert!(p.on_authentic(moved, peer, now, LEN).is_none());
        }
        assert!(p.probing().contains(&moved));
        assert_eq!(p.on_response(moved, real.nonce), Some(moved));
    }

    /// A challenge answers traffic, and never more than three times what
    /// the address sent: one small copied packet from a forged source buys
    /// one challenge, not a stream of them.
    #[test]
    fn challenges_to_an_unproven_address_are_bounded_by_what_it_sent() {
        let peer = addr("192.0.2.1:5555");
        let forged = addr("198.51.100.9:6000");
        let rto = Duration::from_millis(100);
        let mut now = Instant::now();
        let mut p = PathProbe::new();
        let small = CHALLENGE_BYTES / 2;
        let mut sent = p.on_authentic(forged, peer, now, small).into_iter().count();
        for _ in 0..3 * MAX_TRIES {
            now += MAX_RETRY;
            sent += p.poll(now, rto).len();
        }
        assert!(
            sent * CHALLENGE_BYTES <= AMPLIFICATION * small,
            "{} challenges for {} bytes",
            sent,
            small
        );
        // A packet big enough is answered, though.
        let mut q = PathProbe::new();
        assert!(q.on_authentic(forged, peer, now, CHALLENGE_BYTES).is_some());
    }

    #[test]
    fn traffic_from_the_proven_address_cancels_a_claim() {
        let peer = addr("192.0.2.1:5555");
        let other = addr("198.51.100.9:6000");
        let now = Instant::now();
        let mut p = PathProbe::new();
        let c = p.on_authentic(other, peer, now, LEN).expect("challenged");
        assert!(p.on_authentic(peer, peer, now, LEN).is_none());
        assert!(p.probing().is_empty());
        // A late echo of the cancelled claim no longer migrates anything.
        assert!(p.on_response(other, c.nonce).is_none());
    }

    /// A session on a direct path does not follow its peer to a server's
    /// address while the direct one is heard from; it does once that has
    /// gone quiet, and a direct address is always worth asking.
    #[test]
    fn a_direct_path_is_not_given_up_for_a_server_while_it_is_heard() {
        let recent = Duration::from_millis(200);
        let quiet = DIRECT_GRACE + Duration::from_millis(1);
        assert!(keeps_direct(true, false, recent));
        assert!(
            !keeps_direct(true, false, quiet),
            "gone quiet: back to the server"
        );
        assert!(
            !keeps_direct(false, false, recent),
            "another direct address"
        );
        assert!(
            !keeps_direct(false, true, recent),
            "from a server to a direct one"
        );
        assert!(
            !keeps_direct(true, true, recent),
            "from one server to another"
        );
    }
}
