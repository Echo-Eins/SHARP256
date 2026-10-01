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
//! address, and the challenges themselves — with the answers to its own
//! challenges — are held to what the address has sent us (RFC 9000 section
//! 8 allows three times that): a copied packet from a forged source buys at
//! most its own size, aimed at whoever owns the forged address.
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
/// it is proven: one. RFC 9000 (section 8) allows three; here no more goes
/// to an address nobody has proven than came from it, so a packet copied
/// from a forged source buys at most its own size aimed at the forged
/// address. A challenge (41 bytes) is smaller than any packet that carries
/// data or an acknowledgement, so a peer that really moved is challenged at
/// once and again as its traffic keeps coming.
const AMPLIFICATION: usize = 1;
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
    /// Asked by us ([`PathProbe::ask`]) rather than claimed by the peer.
    asked: bool,
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

fn nonce() -> [u8; PATH_TOKEN_LEN] {
    let mut nonce = [0u8; PATH_TOKEN_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
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
    ///
    /// `answer` is what the packet draws back to `from` by itself — the
    /// PATH_RESPONSE to a PATH_CHALLENGE it carries — and is counted before
    /// any challenge of ours: one packet is answered with no more than its
    /// own size in all, and the answer it asked for comes first. (A copy of
    /// the peer's challenge sent from a forged address drew both an answer
    /// and a challenge of the same size, twice what it cost.)
    pub fn on_authentic(
        &mut self,
        from: SocketAddr,
        peer: SocketAddr,
        now: Instant,
        len: usize,
        answer: usize,
    ) -> Option<Challenge> {
        if from == peer {
            // The proven path is alive; claims for other addresses are no
            // longer interesting. A path we asked about is: the proven one
            // being alive is why it was asked.
            self.probes.retain(|p| p.asked);
            return None;
        }
        self.forget_old(now);
        if let Some(p) = self.probes.iter_mut().find(|p| p.addr == from) {
            p.received = p.received.saturating_add(len);
            p.sent = p.sent.saturating_add(answer);
            // Still being tested: nothing new to send.
            p.given_up?;
            // Speaking again after we gave up: test it again, with the same
            // token, so an answer to an earlier challenge still counts.
            p.given_up = None;
            p.tries = 1;
            return p.may_send().then(|| p.challenge(now));
        }
        self.make_room();
        let mut p = Probe {
            addr: from,
            nonce: nonce(),
            sent_at: now,
            tries: 1,
            received: len,
            sent: answer,
            given_up: None,
            asked: false,
        };
        let c = p.may_send().then(|| p.challenge(now));
        self.probes.push(p);
        c
    }

    /// A path of our own making to prove — a stream we dialled to the peer
    /// ourselves — while the peer is heard on the proven one. Nothing came
    /// from it to hold the challenges to, and nobody but us aimed it, so
    /// it is allowed its challenges outright; and a packet on the proven
    /// path does not end the asking. Returns the challenge to send, or
    /// None while one is out already.
    pub fn ask(&mut self, to: SocketAddr, now: Instant) -> Option<Challenge> {
        if self
            .probes
            .iter()
            .any(|p| p.addr == to && p.given_up.is_none())
        {
            return None;
        }
        self.probes.retain(|p| p.addr != to);
        self.make_room();
        let mut p = Probe {
            addr: to,
            nonce: nonce(),
            sent_at: now,
            tries: 1,
            received: MAX_TRIES as usize * CHALLENGE_BYTES,
            sent: 0,
            given_up: None,
            asked: true,
        };
        let c = p.challenge(now);
        self.probes.push(p);
        Some(c)
    }

    /// Room for one more claim: a given-up one goes first, then the oldest.
    fn make_room(&mut self) {
        if self.probes.len() < MAX_CLAIMS {
            return;
        }
        let victim = self
            .probes
            .iter()
            .enumerate()
            .min_by_key(|(_, p)| (p.given_up.is_none(), p.sent_at))
            .map(|(i, _)| i)
            .expect("full");
        self.probes.remove(victim);
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
        assert!(p.on_authentic(peer, peer, now, LEN, 0).is_none());

        // A packet from elsewhere is a claim: challenge it, do not migrate.
        let c = p
            .on_authentic(moved, peer, now, LEN, 0)
            .expect("challenged");
        assert_eq!(c.to, moved);
        assert_eq!(p.probing(), vec![moved]);

        // More packets from the same address do not restart the challenge.
        assert!(p.on_authentic(moved, peer, now, LEN, 0).is_none());

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
    fn a_path_we_ask_about_outlives_the_proven_one_being_heard() {
        let peer = addr("192.0.2.1:5555");
        let stream = addr("127.0.0.1:40000");
        let start = Instant::now();
        let mut p = PathProbe::new();
        let c = p.ask(stream, start).expect("challenged");
        assert_eq!(c.to, stream);
        // One out at a time.
        assert!(p.ask(stream, start).is_none());
        // The peer goes on being heard where it was: a claim it made would
        // be dropped, the asked path is not.
        let claimed = addr("198.51.100.9:6000");
        assert!(p.on_authentic(claimed, peer, start, 10_000, 0).is_some());
        assert!(p.on_authentic(peer, peer, start, 100, 0).is_none());
        assert_eq!(p.probing(), vec![stream]);
        // Nothing came from it, yet its repeats go out.
        let rto = Duration::from_millis(200);
        assert_eq!(p.poll(start + rto, rto), vec![c]);
        assert_eq!(p.on_response(stream, c.nonce), Some(stream));
    }

    #[test]
    fn challenges_back_off_and_a_late_answer_still_counts() {
        let peer = addr("192.0.2.1:5555");
        let other = addr("198.51.100.9:6000");
        let rto = Duration::from_millis(200);
        let start = Instant::now();
        let mut p = PathProbe::new();

        let first = p
            .on_authentic(other, peer, start, 10_000, 0)
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
            .on_authentic(other, peer, now, 10_000, 0)
            .expect("challenged");
        for _ in 0..=MAX_TRIES {
            now += MAX_RETRY;
            p.poll(now, rto);
        }
        assert!(p.probing().is_empty());
        // It speaks again: challenged again, and a token from any round
        // proves it.
        let again = p.on_authentic(other, peer, now, LEN, 0).expect("re-tested");
        assert_eq!(again.nonce, first.nonce);
        // Long after it was given up, it is forgotten.
        let mut q = PathProbe::new();
        let c = q.on_authentic(other, peer, now, 10_000, 0).unwrap();
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
        let real = p
            .on_authentic(moved, peer, now, LEN, 0)
            .expect("challenged");
        for i in 0..MAX_CLAIMS - 1 {
            let forged = addr(&format!("203.0.113.{}:9", i + 1));
            assert!(p.on_authentic(forged, peer, now, LEN, 0).is_some());
            // The real claim's packets keep arriving in between.
            assert!(p.on_authentic(moved, peer, now, LEN, 0).is_none());
        }
        assert!(p.probing().contains(&moved));
        assert_eq!(p.on_response(moved, real.nonce), Some(moved));
    }

    /// A challenge answers traffic, and never more than the address sent:
    /// one small copied packet from a forged source buys no challenge at
    /// all, and one of a challenge's size buys one, not a stream of them.
    #[test]
    fn challenges_to_an_unproven_address_are_bounded_by_what_it_sent() {
        let peer = addr("192.0.2.1:5555");
        let forged = addr("198.51.100.9:6000");
        let rto = Duration::from_millis(100);
        let mut now = Instant::now();
        let mut p = PathProbe::new();
        let small = CHALLENGE_BYTES / 2;
        let mut sent = p
            .on_authentic(forged, peer, now, small, 0)
            .into_iter()
            .count();
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
        // A packet big enough is answered, though — once.
        let mut q = PathProbe::new();
        assert!(q
            .on_authentic(forged, peer, now, CHALLENGE_BYTES, 0)
            .is_some());
        let mut repeats = 0;
        for _ in 0..3 * MAX_TRIES {
            now += MAX_RETRY;
            repeats += q.poll(now, rto).len();
        }
        assert_eq!(repeats, 0);
    }

    /// A copy of the peer's challenge from a forged address is answered —
    /// that answer is its own size — and draws no challenge on top; a
    /// packet with room for both gets both.
    #[test]
    fn a_challenge_from_an_unproven_address_is_answered_and_nothing_more() {
        let peer = addr("192.0.2.1:5555");
        let forged = addr("198.51.100.9:6000");
        let rto = Duration::from_millis(100);
        let mut now = Instant::now();
        let mut p = PathProbe::new();
        assert!(p
            .on_authentic(forged, peer, now, CHALLENGE_BYTES, CHALLENGE_BYTES)
            .is_none());
        for _ in 0..3 * MAX_TRIES {
            now += MAX_RETRY;
            assert!(p.poll(now, rto).is_empty());
        }
        let mut q = PathProbe::new();
        assert!(q
            .on_authentic(forged, peer, now, 2 * CHALLENGE_BYTES, CHALLENGE_BYTES)
            .is_some());
    }

    #[test]
    fn traffic_from_the_proven_address_cancels_a_claim() {
        let peer = addr("192.0.2.1:5555");
        let other = addr("198.51.100.9:6000");
        let now = Instant::now();
        let mut p = PathProbe::new();
        let c = p
            .on_authentic(other, peer, now, LEN, 0)
            .expect("challenged");
        assert!(p.on_authentic(peer, peer, now, LEN, 0).is_none());
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
