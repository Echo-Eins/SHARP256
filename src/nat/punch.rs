//! Hole punching: what to send, and where, given what each end knows of the
//! NAT it is behind.
//!
//! Two ends that both send to each other's public address at about the same
//! time get through most NATs (RFC 4787 section 4.2, and ICE's connectivity
//! checks are the same idea). What this module adds is the rest: the
//! address a peer was told about is right only if its NAT keeps one mapping
//! for every destination. Where it does not, the port the peer will send
//! *from* is a different one, and the first thing to know is whether that
//! port can be worked out.
//!
//! * **Stable mapping** (endpoint-independent, or a public address): the
//!   address is the address. One target.
//! * **Sequential allocation** (the next mapping is the last one plus a
//!   step): the port is the address's plus a small multiple of the step,
//!   the multiple being how many mappings the peer's NAT made in between —
//!   at least one, for the punch itself. A window of targets covers it.
//! * **Random allocation** (the port is drawn from the whole range): the
//!   port cannot be guessed, but it can be *hit*. The end behind the
//!   stable NAT sends to many ports at once, the end behind the random one
//!   opens many sockets and sends from each to the one address it knows,
//!   and by the birthday paradox the two meet: with 256 sockets and 2048
//!   probes the chance is over 99.9 %. Both ends being random needs the
//!   product of the two, which is beyond what is worth sending: that is
//!   what a relay is for.
//!
//! What a peer's NAT does comes from its own tests (RFC 5780), through a
//! contact card or a relay. Either way it is a hint from somebody who may be
//! wrong or hostile, and is used only to decide how many datagrams of a few
//! bytes to send, bounded here.

use super::behaviour::Allocation;
use super::birthday::{self, Hit};
use super::card::{FamilyHints, NatHints};
use crate::relay::Message;
use rand::seq::SliceRandom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Targets tried after a sequential NAT's last known port: enough for the
/// other traffic behind the same NAT to have taken a few in between.
pub const PREDICT_WINDOW: usize = 48;
/// And before it: a port that was seen when the peer talked to somebody
/// else (a relay, a STUN server) is not the first the peer's NAT handed out
/// — anything the peer had already sent, to us among others, is below it.
pub const PREDICT_BEHIND: usize = 12;
/// Ports probed to meet a random NAT, and sockets that NAT's owner opens.
pub const BIRTHDAY_PROBES: usize = 2048;
pub const BIRTHDAY_SOCKETS: usize = 256;
/// Where a random allocator draws from.
const DYNAMIC_PORTS: std::ops::RangeInclusive<u16> = 1024..=65535;
/// How long a punch goes on: enough for the peer's first datagram to be
/// sent, for ours to arrive after it, and for both to be repeated once.
pub const PUNCH_DURATION: Duration = Duration::from_secs(6);
/// Least time between two sprays. Spraying is the one thing here that sends
/// more than a handful of datagrams, and what triggers it is a hint from
/// somebody else.
const SPRAY_SPACING: Duration = Duration::from_secs(10);

/// How a punch is to go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The address is right as it stands.
    Direct,
    /// The peer's NAT counts up by `step`: aim at what it will hand out next.
    Predict { step: i16 },
    /// The peer's NAT draws ports at random and ours is stable: send to
    /// many of them; the peer opens many sockets.
    BirthdayEasy,
    /// Ours draws ports at random and the peer's is stable: open many
    /// sockets and send from each to the peer's one address.
    BirthdayHard,
    /// Both ends draw at random. No amount of sending gets through in
    /// reasonable time; only a relay does.
    RelayOnly,
}

impl Verdict {
    pub fn describe(self) -> &'static str {
        match self {
            Verdict::Direct => "the peer's address as told",
            Verdict::Predict { .. } => "the ports the peer's NAT will hand out next (it counts up)",
            Verdict::BirthdayEasy => {
                "very many ports at the peer, which opens very many sockets at us"
            }
            Verdict::BirthdayHard => {
                "very many sockets of ours at the peer's one address (our NAT draws ports at \
                 random)"
            }
            Verdict::RelayOnly => {
                "nothing that gets through both NATs (both draw ports at random): a relay is \
                 needed"
            }
        }
    }
}

/// What to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub verdict: Verdict,
    /// Ports of the peer's address to send to, most likely first.
    pub ports: Vec<u16>,
    /// Further random ports to probe, once each.
    pub spray: usize,
    /// Sockets of our own to open, each sending to the peer's address.
    pub sockets: usize,
}

/// Whether an end's NAT gives its next external port away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ports {
    /// The same for every destination, or no NAT, or nothing measured (which
    /// is treated as the best case: it costs nothing to try).
    Stable,
    Preserved,
    Sequential(i16),
    Random,
}

fn ports_of(h: &NatHints) -> Ports {
    if !h.is_symmetric() {
        return Ports::Stable;
    }
    match h.allocation {
        Allocation::Preserved => Ports::Preserved,
        Allocation::Sequential => Ports::Sequential(if h.delta == 0 { 1 } else { h.delta }),
        // Unmeasured is treated as random: the guess costs a window of
        // datagrams, and the birthday method needs nothing to be known.
        Allocation::Random | Allocation::Unknown => Ports::Random,
    }
}

/// The ports a sequential NAT may have handed out, or may hand out next:
/// `base` itself first (a NAT that keeps a mapping per address, not per
/// port, may reuse it), then `PREDICT_WINDOW` steps on, then
/// `PREDICT_BEHIND` steps back.
fn predicted(base: u16, step: i16) -> Vec<u16> {
    let mut out = vec![base];
    let step = i32::from(step);
    let mut add = |m: i32| {
        let p = i32::from(base) + step * m;
        if (1..=65535).contains(&p) {
            out.push(p as u16);
        }
    };
    (1..=PREDICT_WINDOW as i32).for_each(&mut add);
    (1..=PREDICT_BEHIND as i32).for_each(|m| add(-m));
    out
}

/// Works out how to punch towards `base`, the peer's address as it was told
/// to us, given what each end's NAT does.
pub fn plan(mine: &NatHints, theirs: &NatHints, base: SocketAddr) -> Plan {
    let port = base.port();
    let direct = |verdict| Plan {
        verdict,
        ports: vec![port],
        spray: 0,
        sockets: 0,
    };
    // Nothing translated in front of the peer, and what it lets in decided
    // by address alone (or not at all): which port we send from cannot
    // matter to it, so one socket is all it takes, whatever our own NAT
    // does with ports. A TURN server's relayed address is exactly this.
    if theirs.mapping == 4 && matches!(theirs.filtering, 1 | 2) {
        return direct(Verdict::Direct);
    }
    match (ports_of(mine), ports_of(theirs)) {
        (Ports::Random, Ports::Stable | Ports::Preserved) => Plan {
            verdict: Verdict::BirthdayHard,
            ports: vec![port],
            spray: 0,
            sockets: BIRTHDAY_SOCKETS,
        },
        (_, Ports::Stable | Ports::Preserved) => direct(Verdict::Direct),
        (_, Ports::Sequential(step)) => Plan {
            verdict: Verdict::Predict { step },
            ports: predicted(port, step),
            spray: 0,
            sockets: 0,
        },
        (Ports::Random, Ports::Random) => Plan {
            verdict: Verdict::RelayOnly,
            ports: vec![port],
            spray: 0,
            sockets: 0,
        },
        // Ours is stable enough that one socket sending to many ports is
        // seen from one address: the peer's sockets, each sending to it,
        // meet those probes. A sequential NAT of ours does not qualify — every
        // probe would leave from a port of its own, and none of the
        // peer's sockets would have sent to that one.
        (Ports::Sequential(_), Ports::Random) => Plan {
            verdict: Verdict::RelayOnly,
            ports: vec![port],
            spray: 0,
            sockets: 0,
        },
        (_, Ports::Random) => Plan {
            verdict: Verdict::BirthdayEasy,
            ports: vec![port],
            spray: BIRTHDAY_PROBES,
            sockets: 0,
        },
    }
}

/// What a peer whose NAT nothing has been said of may be, beyond the easy
/// case every first pass assumes: tried in turn on the passes that follow.
/// One that draws ports at random is here too, though against another that
/// draws at random nothing can be done ([`Verdict::RelayOnly`] is left out
/// of a schedule: it is no way of punching).
fn assumptions() -> [NatHints; 3] {
    let symmetric = |allocation, delta| NatHints {
        mapping: 3,
        filtering: 3,
        allocation,
        delta,
        ..NatHints::unknown()
    };
    [
        // Keeps one port for every destination, and lets in only the exact
        // address and port it was sent to.
        NatHints {
            mapping: 1,
            filtering: 3,
            ..NatHints::unknown()
        },
        symmetric(Allocation::Sequential, 1),
        symmetric(Allocation::Random, 0),
    ]
}

/// The plans a punch goes through, one to a pass: the one `theirs` calls
/// for; and, where nothing is known of the peer's NAT (an address from a
/// DHT, a name, a hand-written list) and the address is one the internet
/// routes, the ways a peer of each other kind would have to be approached —
/// so that a peer that needs a predicted or a guessed port is not left
/// waiting for a hint that no such source can give. Bounded as any pass
/// is: the datagrams are nine bytes, and a spray is at most one in
/// [`SPRAY_SPACING`] to an address.
fn schedule(mine: &NatHints, theirs: &NatHints, base: SocketAddr) -> Vec<Plan> {
    let direct = || Plan {
        verdict: Verdict::Direct,
        ports: vec![base.port()],
        spray: 0,
        sockets: 0,
    };
    // Working out where a peer's NAT will put a port only means something
    // for an address the internet routes: a private one is the peer's own
    // network, which is no place for a spray.
    if !crate::address::class::is_global(base.ip()) {
        return vec![direct()];
    }
    let mut out = vec![plan(mine, theirs, base)];
    if theirs.mapping == 0 && theirs.filtering == 0 {
        for assumed in assumptions() {
            let p = plan(mine, &assumed, base);
            if p.verdict != Verdict::RelayOnly && !out.iter().any(|q| q.verdict == p.verdict) {
                out.push(p);
            }
        }
    }
    out
}

/// Sends the punches a [`Plan`] calls for, on the socket the transfer uses:
/// the NAT mapping a punch opens is the one the peer's packets must find.
pub struct Puncher {
    socket: Arc<UdpSocket>,
    mine: watch::Receiver<FamilyHints>,
    /// Cancelled when what this end's NAT does will not become known any
    /// better than it is: the tests are over, or were never going to run.
    settled: CancellationToken,
    /// When each address was last sprayed at.
    last_spray: parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, Instant>>,
    /// What to do with the socket a birthday meeting was made at. Without
    /// one, an end whose NAT draws ports at random can only punch from the
    /// one socket, which is a hope and not a method.
    on_hit: Option<HitHandler>,
    /// TURN allocations, which pass only what comes from an address they
    /// were told to: every address punched at is one that may need it.
    turns: Vec<super::turn::Turn>,
}

/// Takes over a socket that a peer got through to (see [`super::birthday`]).
pub type HitHandler = Arc<dyn Fn(Hit) + Send + Sync>;

/// How long a punch waits for this end's own NAT tests, at most. They take
/// a round trip or two for what matters here (how ports are numbered); the
/// filtering tests after them are slower and are not waited for.
pub const HINTS_WAIT: Duration = Duration::from_millis(1500);
/// How long a punch goes on when it is waiting for a person to hand the
/// other side a card: the other side may take minutes to do it, and the
/// holes have to be open when it does.
pub const MEET_DURATION: Duration = Duration::from_secs(300);

impl Puncher {
    /// `mine` follows what this end's own NAT tests found; until they have,
    /// nothing is known and the peer is treated as easy to reach.
    pub fn new(socket: Arc<UdpSocket>, mine: watch::Receiver<FamilyHints>) -> Self {
        Self {
            socket,
            mine,
            settled: CancellationToken::new(),
            last_spray: parking_lot::Mutex::new(std::collections::HashMap::new()),
            on_hit: None,
            turns: Vec::new(),
        }
    }

    /// Lets each address punched at send through these TURN allocations.
    pub fn with_turns(mut self, turns: Vec<super::turn::Turn>) -> Self {
        self.turns = turns;
        self
    }

    /// Says what becomes of the socket a birthday meeting is made at.
    pub fn with_hit_handler(mut self, handler: HitHandler) -> Self {
        self.on_hit = Some(handler);
        self
    }

    /// A puncher that knows nothing of its own NAT and is told nothing new.
    pub fn without_hints(socket: Arc<UdpSocket>) -> Self {
        let (tx, rx) = watch::channel(FamilyHints::unknown());
        // Kept alive by the receiver; a closed channel is read as its last
        // value, which is what this wants.
        drop(tx);
        let p = Self::new(socket, rx);
        p.settled.cancel();
        p
    }

    /// Says that what is known of this end's NAT is all there will be.
    pub fn settle(&self) {
        self.settled.cancel();
    }

    /// The token [`Puncher::settle`] cancels.
    pub fn settled(&self) -> CancellationToken {
        self.settled.clone()
    }

    /// What this end's NAT is known to do, in each address family.
    pub fn mine(&self) -> FamilyHints {
        *self.mine.borrow()
    }

    /// Follows what this end's NAT is known to do, as it becomes known.
    pub fn subscribe(&self) -> watch::Receiver<FamilyHints> {
        self.mine.clone()
    }

    /// What this end's NAT is known to do once it is — or, at the longest,
    /// after [`HINTS_WAIT`], or when it is clear it never will be.
    pub async fn hints_when_known(&self) -> FamilyHints {
        let mut rx = self.mine.clone();
        tokio::select! {
            _ = rx.wait_for(|h| h.is_known()) => {}
            _ = self.settled.cancelled() => {}
            _ = tokio::time::sleep(HINTS_WAIT) => {}
        }
        let known = *rx.borrow();
        known
    }

    /// Punches towards `base` for [`PUNCH_DURATION`], or until `cancel`, so
    /// that our NAT has a way back open when the other side's first packet
    /// arrives.
    ///
    /// The address comes from a relay or a card, neither trusted, so it is
    /// screened the way a STUN server's suggestions are: never this host, a
    /// multicast or broadcast group, or an address the socket cannot reach.
    /// What the screen cannot do is tell a peer from anyone else that might
    /// be named, here or on the internet; what bounds that is how little is
    /// sent — datagrams of nine bytes that draw no reply from anyone, a
    /// few dozen at most unless the hints ask for a spray, and one spray
    /// per `SPRAY_SPACING`.
    pub async fn run(&self, base: SocketAddr, theirs: NatHints, cancel: &CancellationToken) {
        self.run_for(base, theirs, PUNCH_DURATION, cancel).await
    }

    /// [`Puncher::run`] for as long as `duration`: the same schedule again
    /// every `SPRAY_SPACING`, with fresh ports where the plan sprays.
    pub async fn run_for(
        &self,
        base: SocketAddr,
        theirs: NatHints,
        duration: Duration,
        cancel: &CancellationToken,
    ) {
        let Ok(local) = self.socket.local_addr() else {
            return;
        };
        // Written the way this socket sends to it.
        let Some(base) = crate::address::Reach::of(&self.socket).native(base) else {
            return;
        };
        if !crate::address::class::is_sendable_hint(base, local) {
            tracing::debug!("punch: {} is not worth sending to", base);
            return;
        }
        // Whoever is punched at may be sending through a TURN server, which
        // drops it unless the address has been permitted.
        for turn in &self.turns {
            turn.permit(base.ip());
        }
        let mine = self.hints_when_known().await.for_addr(&base);
        let schedule = schedule(&mine, &theirs, base);
        let started = Instant::now();
        // Sockets for a birthday meeting are opened once, by the first plan
        // that asks for them, and kept for the rest of the punch.
        let (open_tx, open_rx) = tokio::sync::oneshot::channel::<usize>();
        let aux = async {
            let Ok(count) = open_rx.await else {
                return;
            };
            let Some(handler) = &self.on_hit else {
                return;
            };
            let sockets = birthday::open_sockets(&self.socket, count);
            let left = duration.saturating_sub(started.elapsed());
            if let Some(hit) = birthday::meet(sockets, base, left, cancel).await {
                handler(hit);
            }
        };
        let passes = async {
            let mut open_tx = Some(open_tx);
            let mut pass = 0usize;
            loop {
                let plan = &schedule[pass % schedule.len()];
                // Said when it changes: the first pass, and each that tries
                // something else.
                if pass < schedule.len() {
                    tracing::info!("punching towards {}: {}", base, plan.verdict.describe());
                }
                if plan.sockets > 0 {
                    if let Some(tx) = open_tx.take() {
                        let _ = tx.send(plan.sockets);
                    }
                }
                let mut spray = plan.spray;
                if spray > 0 {
                    let now = Instant::now();
                    let mut last = self.last_spray.lock();
                    last.retain(|_, t| now.saturating_duration_since(*t) < SPRAY_SPACING);
                    if last.contains_key(&base.ip()) || last.len() >= 8 {
                        tracing::debug!("punch: not spraying at {} again so soon", base.ip());
                        spray = 0;
                    } else {
                        last.insert(base.ip(), now);
                    }
                }
                // Ports to probe once each, spread over the pass's first
                // rounds, so that the peer's side of it is open for some of
                // them whenever it opens.
                let mut random: Vec<u16> = Vec::new();
                if spray > 0 {
                    let mut all: Vec<u16> = DYNAMIC_PORTS.collect();
                    all.shuffle(&mut rand::thread_rng());
                    all.retain(|p| !plan.ports.contains(p));
                    all.truncate(spray);
                    random = all;
                }
                self.send_rounds(base, &plan.ports, &random, cancel).await;
                pass += 1;
                if cancel.is_cancelled() || started.elapsed() + SPRAY_SPACING >= duration {
                    return;
                }
                tokio::select! {
                    _ = tokio::time::sleep(SPRAY_SPACING - PUNCH_DURATION.min(SPRAY_SPACING)) => {}
                    _ = cancel.cancelled() => return,
                }
            }
        };
        tokio::join!(passes, aux);
    }

    /// The punches from the socket the transfer uses: to each of `ports`
    /// every round, and `random` ports spread over the first rounds.
    async fn send_rounds(
        &self,
        base: SocketAddr,
        ports: &[u16],
        random: &[u16],
        cancel: &CancellationToken,
    ) {
        let waves = 3usize;
        let msg = Message::Punch.encode();
        let start = Instant::now();
        let mut round = 0usize;
        loop {
            // First four quickly (the first may be the one that opens our
            // NAT rather than the one that gets through), then steadily.
            for &p in ports {
                let _ = self
                    .socket
                    .send_to(&msg, SocketAddr::new(base.ip(), p))
                    .await;
            }
            if !random.is_empty() && round % 2 == 0 && round / 2 < waves {
                let wave = round / 2;
                let per = random.len().div_ceil(waves);
                let chunk =
                    &random[(wave * per).min(random.len())..((wave + 1) * per).min(random.len())];
                for burst in chunk.chunks(32) {
                    for &p in burst {
                        let _ = self
                            .socket
                            .send_to(&msg, SocketAddr::new(base.ip(), p))
                            .await;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
            round += 1;
            let gap = if round < 4 {
                Duration::from_millis(150)
            } else {
                Duration::from_millis(500)
            };
            if start.elapsed() + gap >= PUNCH_DURATION {
                return;
            }
            tokio::select! {
                _ = tokio::time::sleep(gap) => {}
                _ = cancel.cancelled() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hints(mapping: u8, allocation: Allocation, delta: i16) -> NatHints {
        NatHints {
            mapping,
            allocation,
            delta,
            ..NatHints::unknown()
        }
    }

    fn base() -> SocketAddr {
        "203.0.113.9:40000".parse().unwrap()
    }

    #[test]
    fn a_stable_peer_is_sent_to_where_it_was_told() {
        for theirs in [NatHints::unknown(), hints(1, Allocation::Preserved, 0)] {
            let p = plan(&NatHints::unknown(), &theirs, base());
            assert_eq!(p.verdict, Verdict::Direct);
            assert_eq!(p.ports, vec![40000]);
            assert_eq!((p.spray, p.sockets), (0, 0));
        }
    }

    /// An address with nothing translated in front of it that lets in by
    /// address alone — a TURN server's relayed address — is sent to from
    /// one socket, however our own NAT numbers its ports. Without this a
    /// sender behind a symmetric NAT opened hundreds of sockets to guess a
    /// port that nothing was guarding.
    #[test]
    fn an_address_that_lets_in_by_address_alone_needs_no_port_games() {
        let relayed = |filtering: u8| NatHints {
            mapping: 4,
            filtering,
            ..NatHints::unknown()
        };
        let ours = [
            NatHints::unknown(),
            hints(3, Allocation::Random, 0),
            hints(3, Allocation::Sequential, 2),
        ];
        for mine in ours {
            for filtering in [1, 2] {
                let p = plan(&mine, &relayed(filtering), base());
                assert_eq!(
                    p.verdict,
                    Verdict::Direct,
                    "{:?} against filtering {}",
                    mine,
                    filtering
                );
                assert_eq!((p.spray, p.sockets), (0, 0));
            }
        }
        // But one that also filters by port, or has not said, is still
        // approached with what the port requires.
        let p = plan(&hints(3, Allocation::Random, 0), &relayed(3), base());
        assert_eq!(p.verdict, Verdict::BirthdayHard);
        let p = plan(&hints(3, Allocation::Random, 0), &relayed(0), base());
        assert_eq!(p.verdict, Verdict::BirthdayHard);
    }

    /// Where the peer's NAT is not known the first pass is the easy case,
    /// and the passes after it are what a peer of each harder kind would
    /// need — except where nothing could be done anyway.
    #[test]
    fn an_unknown_peer_is_approached_in_every_way_that_could_work() {
        // An address the internet routes (the documentation ranges are not).
        let base = || -> SocketAddr { "11.9.0.9:40000".parse().unwrap() };
        let stable = NatHints::unknown();
        let random = hints(3, Allocation::Random, 0);
        let verdicts = |mine: &NatHints, theirs: &NatHints, addr: SocketAddr| -> Vec<Verdict> {
            schedule(mine, theirs, addr)
                .iter()
                .map(|p| p.verdict)
                .collect()
        };
        assert_eq!(
            verdicts(&stable, &NatHints::unknown(), base()),
            [
                Verdict::Direct,
                Verdict::Predict { step: 1 },
                Verdict::BirthdayEasy
            ],
        );
        // Ours draws at random: the sockets are needed from the start, and
        // against another that draws at random there is nothing to try.
        assert_eq!(
            verdicts(&random, &NatHints::unknown(), base()),
            [Verdict::BirthdayHard, Verdict::Predict { step: 1 }],
        );
        // Said, it is believed: one plan, the one it calls for.
        assert_eq!(
            verdicts(&stable, &hints(1, Allocation::Preserved, 0), base()),
            [Verdict::Direct]
        );
        assert_eq!(
            verdicts(&stable, &hints(3, Allocation::Sequential, 2), base()),
            [Verdict::Predict { step: 2 }],
        );
        // A private address is the peer's own network: no spray, and no
        // guessing which NAT it is behind.
        let lan: SocketAddr = "192.168.1.7:5555".parse().unwrap();
        assert_eq!(
            verdicts(&random, &NatHints::unknown(), lan),
            [Verdict::Direct]
        );
    }

    #[test]
    fn a_counting_peer_is_aimed_at_its_next_ports() {
        let p = plan(
            &NatHints::unknown(),
            &hints(3, Allocation::Sequential, 2),
            base(),
        );
        assert_eq!(p.verdict, Verdict::Predict { step: 2 });
        assert_eq!(p.ports[0], 40000, "the address as told comes first");
        assert_eq!(p.ports[1], 40002);
        assert_eq!(p.ports.len(), 1 + PREDICT_WINDOW + PREDICT_BEHIND);
        assert!(p.ports.contains(&(40000 - 2)), "and the ones before it");
        // The same for a counting peer whichever kind of NAT we are behind.
        let q = plan(
            &hints(3, Allocation::Random, 0),
            &hints(3, Allocation::Sequential, 2),
            base(),
        );
        assert_eq!(q.verdict, p.verdict);
    }

    #[test]
    fn a_step_of_zero_means_one_and_the_ports_stay_in_range() {
        let p = plan(
            &NatHints::unknown(),
            &hints(3, Allocation::Sequential, 0),
            "203.0.113.9:65530".parse().unwrap(),
        );
        assert_eq!(p.ports[1], 65531);
        assert!(p.ports.iter().all(|&x| x >= 1));
        assert_eq!(p.ports.len(), 1 + 5 + PREDICT_BEHIND, "only what fits");
        let down = plan(
            &NatHints::unknown(),
            &hints(3, Allocation::Sequential, -3),
            "203.0.113.9:10".parse().unwrap(),
        );
        assert!(down.ports.contains(&7) && down.ports.contains(&13));
        assert!(!down.ports.contains(&0), "never port zero");
    }

    #[test]
    fn a_random_peer_is_met_by_the_birthday_method_from_the_stable_side() {
        let easy = plan(
            &hints(1, Allocation::Preserved, 0),
            &hints(3, Allocation::Random, 0),
            base(),
        );
        assert_eq!(easy.verdict, Verdict::BirthdayEasy);
        assert_eq!(easy.spray, BIRTHDAY_PROBES);
        assert_eq!(easy.sockets, 0);
        // Its own side of the same meeting.
        let hard = plan(
            &hints(3, Allocation::Random, 0),
            &hints(1, Allocation::Preserved, 0),
            base(),
        );
        assert_eq!(hard.verdict, Verdict::BirthdayHard);
        assert_eq!(hard.sockets, BIRTHDAY_SOCKETS);
        assert_eq!(hard.ports, vec![40000]);
        // An unmeasured allocation behind a symmetric mapping is no better.
        let unknown = plan(
            &NatHints::unknown(),
            &hints(2, Allocation::Unknown, 0),
            base(),
        );
        assert_eq!(unknown.verdict, Verdict::BirthdayEasy);
    }

    #[test]
    fn two_random_ends_need_a_relay() {
        let random = hints(3, Allocation::Random, 0);
        assert_eq!(plan(&random, &random, base()).verdict, Verdict::RelayOnly);
        // A counting NAT of ours cannot be the stable side of a birthday
        // meeting: each probe would leave from a port of its own.
        let counting = hints(3, Allocation::Sequential, 1);
        assert_eq!(plan(&counting, &random, base()).verdict, Verdict::RelayOnly);
    }

    #[test]
    fn the_birthday_arithmetic_holds() {
        // The chance that some probe meets some socket: 1 - (1 - S/N)^K.
        let n = f64::from(65535u32 - 1024 + 1);
        let s = BIRTHDAY_SOCKETS as f64;
        let k = BIRTHDAY_PROBES as f64;
        let p = 1.0 - (1.0 - s / n).powf(k);
        assert!(p > 0.999, "{}", p);
    }

    #[tokio::test]
    async fn every_planned_port_is_sent_to() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ours = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let puncher = Puncher::without_hints(ours);
        let cancel = CancellationToken::new();
        let addr = peer.local_addr().unwrap();
        let task = {
            let c = cancel.clone();
            tokio::spawn(async move {
                puncher.run(addr, NatHints::unknown(), &c).await;
            })
        };
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("no punch arrived")
            .unwrap();
        assert!(matches!(Message::decode(&buf[..n]), Some(Message::Punch)));
        cancel.cancel();
        task.await.unwrap();
    }
}
