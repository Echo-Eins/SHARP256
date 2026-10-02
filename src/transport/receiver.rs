//! Receiving side: one `Receiver` serves many concurrent transfers.
//!
//! The socket is read by a single dispatcher task that drains all queued
//! datagrams. Transport packets are routed by their connection id to
//! per-transfer session tasks. Anything else must be a handshake initiation
//! made by someone who knows this receiver's ID (its mac1 proves it);
//! everything that is not is dropped without an answer, so the receiver is
//! invisible to scanners. Initiations are rate limited per source, answered
//! with cookies when the receiver is under load, checked for replays, and
//! then authorised by the sender's identity.
//!
//! A session:
//!
//! * decides on the transfer (policy, or the application's decision, during
//!   which the sender is told "pending") and answers the handshake with
//!   accurate resume information computed from what is already durable;
//! * decrypts every transport packet and hands DATA payloads, without
//!   copying them again, to a coalescing writer thread at their absolute
//!   offsets; received bytes are tracked in a `RangeSet`;
//! * sends selective ACKs whose hole list always describes the acknowledged
//!   interval completely (the interval is shortened when the list is full);
//! * persists durable progress periodically (after fsync) for resume;
//! * when every byte is present, closes, hashes and renames the file in a
//!   background task while it keeps answering the sender, then exchanges
//!   FIN / FIN_ACK / FIN_DONE.
//!
//! A directory arrives as one stream as well (see [`crate::file::tree`]): the
//! session collects the manifest at its start in memory, verifies it against
//! the hash announced in HELLO, and only then lets the writer create files
//! in a private staging directory; data that overtakes the manifest waits in
//! a bounded buffer. The finished tree is hashed, gets its times and
//! permissions, and is renamed into place.

use crate::config::{AcceptPolicy, IncomingRequest, ReceiverConfig, TransportConfig};
use crate::crypto::handshake::{self as hs, CookieJar, HandshakeLimiter, ReplayGuard, Responder};
use crate::crypto::replay::ReplayWindow;
use crate::crypto::transport::{
    begin_packet, peek_cid, DirectionKeys, SessionKeys, Suite, HEADER_LEN, OVERHEAD, TAG_LEN,
};
use crate::crypto::{Identity, SharpId};
use crate::file::tree::{self, Manifest};
use crate::file::{
    available_space, hash_file, hash_to_hex, part_path_for, rename_with_retry, sanitize_file_name,
    unique_path, unique_path_besides, FileWriter,
};
use crate::progress::{emit, DirectoryInfo, EventCallback, TransferEvent, TransferStats};
use crate::protocol::constants::*;
use crate::protocol::wire::{
    self, parse_type_byte, type_byte, Ack, Fin, Hello, HelloAck, Message, MsgType, Pong, ProbeAck,
    TreeInfo, MAX_CONTROL_BODY,
};
use crate::protocol::RangeSet;
use crate::state::{hex16, ReceiverState, StateStore};
use crate::sync;
use crate::transport::io::{recv_buffers, BatchSocket, Received, RECV_BATCH, RECV_BUF_LEN};
use crate::transport::parallel;
use crate::transport::path::PathProbe;
use rand::RngCore;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("identity: {0}")]
    Identity(String),
}

/// Resume state older than this is deleted when a receiver starts.
const STATE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

/// Deliveries a session may have queued before the dispatcher drops more,
/// and the memory they may occupy.
const SESSION_QUEUE: usize = 16_384;
const SESSION_QUEUE_BYTES: u64 = 32 << 20;
/// Received runs up to this size are copied for their session; larger ones
/// hand over their whole buffer.
const RUN_COPY_MAX: usize = 16 << 10;
/// Receive calls the dispatcher makes before it lets other work run.
const RECV_CALLS_PER_WAKEUP: usize = 64;
/// Messages a session handles per wakeup before it checks its timers.
const SESSION_BATCH: usize = 256;
/// Senders whose last initiation timestamp is remembered (replay guard).
const REPLAY_GUARD_CAPACITY: usize = 100_000;
/// Directory data that overtook the manifest is held back, up to this many
/// bytes and datagrams, until the manifest is complete.
const EARLY_MAX_BYTES: u64 = 16 << 20;
const EARLY_MAX_ITEMS: usize = 16_384;
/// How long an unanswered address challenge first waits before it is
/// repeated; each repeat waits twice as long as the last.
const PATH_RETRY: Duration = Duration::from_millis(250);
/// Everything in a handshake answer but its hole list: the packet overhead
/// and the fixed fields of the response and its HELLO_ACK, with room over.
const RESPONSE_FIXED: usize = hs::RESPONSE_OVERHEAD + 64;
/// Separate pieces of a file one session may hold. Each costs an entry to
/// keep, to persist for resume and to walk when describing holes, and a
/// sender that scattered one-byte pieces across a large file could
/// otherwise make as many as it liked. An honest transfer stays far below
/// this — its pieces are the holes loss left inside one window — and at
/// the cap only data that joins what is already here is taken, which the
/// lowest hole always does, so it slows and never stops.
const MAX_RECEIVED_RANGES: usize = 1 << 16;

/// A transfer is identified by who sends it and its transfer id.
type TransferKey = (SharpId, [u8; 16]);

/// An authenticated initiation routed to the session it belongs to.
struct Handshake {
    incoming: hs::Incoming,
    init: wire::Initiation,
    suite: Suite,
    /// Connection id the dispatcher assigned to the session for it.
    cid: u64,
    from: SocketAddr,
    at: Instant,
    /// Size of the initiation: what the address it came from has sent us,
    /// and so what it may be sent back before it is proven.
    len: usize,
}

/// Datagrams from one receive buffer for a session: `buf` holds datagrams of
/// `stride` bytes each (the last one may be shorter).
struct Datagrams {
    buf: Vec<u8>,
    stride: usize,
    from: SocketAddr,
}

/// Messages delivered to a session task.
enum Incoming {
    /// Datagrams in arrival order; `bytes` is the memory they occupy.
    Datagrams {
        runs: Vec<Datagrams>,
        bytes: u64,
        at: Instant,
    },
    Handshake(Box<Handshake>),
    /// A version 4 handshake, answered, and the HELLO that came under its
    /// keys.
    Established(Box<Established>),
    /// The writer finished an fsync requested for persistence.
    FlushDone(io::Result<()>),
    /// Background close + hash + rename finished.
    Verified(Result<([u8; 32], PathBuf), String>),
}

/// A version 4 handshake answered whose HELLO has not come yet: keys, and
/// nothing else. Nothing the initiation said is acted on until the HELLO,
/// which is the first thing that proves the sender's key — message 1 can be
/// written by anyone who holds the receiver's own key — and whose contents
/// have the forward secrecy message 1 does not.
struct PendingV4 {
    keys: Arc<SessionKeys>,
    sender: SharpId,
    peer_cid: u64,
    from: SocketAddr,
    at: Instant,
    /// Bytes the initiation's fragments came to, and the answer's.
    len: usize,
    answered: usize,
}

/// Version 4 handshakes waiting for their HELLO at once, and how long each
/// waits.
const PENDING_V4_CAPACITY: usize = 4096;
const PENDING_V4_PATIENCE: Duration = Duration::from_secs(10);

/// What a session is handed for a version 4 handshake: its keys, made and
/// answered, and the HELLO that came under them (the datagram itself
/// follows, as any other).
struct Established {
    keys: Arc<SessionKeys>,
    cid: u64,
    peer_cid: u64,
    from: SocketAddr,
    at: Instant,
    len: usize,
    answered: usize,
    hello: Hello,
}

struct SessionHandle {
    tx: mpsc::Sender<Incoming>,
    /// Bytes of datagrams queued for the session.
    queued: Arc<AtomicU64>,
    /// The session's current connection id.
    cid: u64,
    task: tokio::task::JoinHandle<()>,
    /// When something from its sender last came for it.
    heard: Instant,
    /// Asks it to let go of its transfer; once asked, it is on its way out
    /// and no longer counts against the limits on sessions.
    release: Release,
}

struct Shared {
    cfg: ReceiverConfig,
    socket: Arc<BatchSocket>,
    store: Option<StateStore>,
    cancel: CancellationToken,
    identity: Identity,
    /// Transfers this receiver's user declined, and when. A sender whose
    /// handshake was already on its way when the user said no must get the
    /// same answer, not a fresh question.
    declined: parking_lot::Mutex<HashMap<TransferKey, Instant>>,
    /// Bytes of datagrams queued to sessions, all of them together; held to
    /// a quarter of the memory budget.
    queued_total: Budget,
    /// Sessions receiving file data now, which share the rest of it.
    receiving: std::sync::atomic::AtomicUsize,
    /// File data not yet on disk, all sessions together, as each last
    /// claimed or published it (see [`Unwritten`]); held to three quarters
    /// of the budget.
    unwritten_total: Budget,
    /// Which session holds which partial data (see [`Holder`]), and how
    /// many sessions there have been: each one's number among them.
    holders: parking_lot::Mutex<Vec<Holder>>,
    sessions_made: AtomicU64,
    /// Senders reached over a stream rather than the socket (see
    /// `transport::carrier`): what goes to them goes on their stream.
    streams: Arc<crate::transport::carrier::Streams>,
    /// Sockets particular peers are answered from.
    #[cfg(feature = "nat-traversal")]
    routes: Arc<crate::nat::birthday::Routes>,
    /// Punching at peers' addresses for a meeting, until each has done its
    /// work (see [`Shared::meet`]).
    #[cfg(feature = "nat-traversal")]
    meetings: Meetings,
    /// Addresses that carry a sender without being it (see [`Relayed`]).
    #[cfg(feature = "nat-traversal")]
    relayed: Relayed,
}

/// Addresses a sender reaches this receiver through without being there:
/// this receiver's own TURN shims, the hosts of the relays it is registered
/// with (a relay carries a pair on ports of its own), and the addresses on
/// senders' cards that are on a TURN server. A session on a direct path does
/// not follow its sender to one of them while the direct path is heard from
/// (see `path::DIRECT_GRACE`).
#[cfg(feature = "nat-traversal")]
#[derive(Default)]
struct Relayed {
    turns: parking_lot::RwLock<Vec<crate::nat::turn::Turn>>,
    hosts: parking_lot::RwLock<std::collections::HashSet<std::net::IpAddr>>,
    addrs: parking_lot::RwLock<std::collections::HashSet<SocketAddr>>,
}

/// Servers' addresses remembered from cards: a card names a few, and people
/// paste only so many.
#[cfg(feature = "nat-traversal")]
const MAX_RELAYED: usize = 256;

#[cfg(feature = "nat-traversal")]
impl Relayed {
    fn contains(&self, addr: SocketAddr) -> bool {
        let addr = crate::address::canonical(addr);
        self.turns.read().iter().any(|t| t.is_shim(addr))
            || self.hosts.read().contains(&addr.ip())
            || self.addrs.read().contains(&addr)
    }

    fn add_hosts(&self, addrs: &[SocketAddr]) {
        let mut hosts = self.hosts.write();
        for a in addrs {
            hosts.insert(crate::address::canonical(*a).ip());
        }
    }

    fn add(&self, addr: SocketAddr) {
        let mut addrs = self.addrs.write();
        if addrs.len() < MAX_RELAYED {
            addrs.insert(crate::address::canonical(addr));
        }
    }
}

/// Punching at peers' addresses for meetings — an address on a card, one
/// given by hand, one the DHT turned up — and what ends each early: a session
/// with that peer running directly to that address's host.
#[cfg(feature = "nat-traversal")]
#[derive(Default)]
struct Meetings(parking_lot::Mutex<Vec<Meeting>>);

#[cfg(feature = "nat-traversal")]
struct Meeting {
    /// Whose card the address was on, if it was on a card: only a session
    /// with that sender ends it then. An address without a card is anyone's.
    id: Option<SharpId>,
    ip: std::net::IpAddr,
    stop: CancellationToken,
}

#[cfg(feature = "nat-traversal")]
impl Meetings {
    /// A meeting at `addr`, stopped by the token returned — by this, or by
    /// whoever cancels `parent`.
    fn add(
        &self,
        addr: SocketAddr,
        id: Option<SharpId>,
        parent: &CancellationToken,
    ) -> CancellationToken {
        let stop = parent.child_token();
        let mut all = self.0.lock();
        all.retain(|m| !m.stop.is_cancelled());
        all.push(Meeting {
            id,
            ip: crate::address::canonical(addr).ip(),
            stop: stop.clone(),
        });
        stop
    }

    /// A session with `sender` runs at `peer` now: the meetings at that host
    /// stop — those without a card, and those on `sender`'s. Returns how many.
    fn met(&self, sender: &SharpId, peer: SocketAddr) -> usize {
        let ip = crate::address::canonical(peer).ip();
        let mut stopped = 0;
        self.0.lock().retain(|m| {
            let done = m.ip == ip && m.id.is_none_or(|id| id == *sender);
            if done {
                m.stop.cancel();
                stopped += 1;
            }
            !done && !m.stop.is_cancelled()
        });
        stopped
    }
}

/// Bytes that all sessions together may hold, taken and given back from
/// any of their threads. What is taken never passes the limit, at any
/// moment: every change that makes it grow is checked and made in one step
/// (a check first and a change after would let two sessions pass at once,
/// each on what the other had not added yet).
struct Budget {
    used: sync::AtomicU64,
    limit: u64,
}

impl Budget {
    fn new(limit: u64) -> Self {
        Self {
            used: sync::AtomicU64::new(0),
            limit,
        }
    }

    /// Takes `bytes`; false, with nothing taken, when that would pass the
    /// limit.
    fn take(&self, bytes: u64) -> bool {
        let limit = self.limit;
        sync::update_atomic(&self.used, |used| {
            (used + bytes <= limit).then_some(used + bytes)
        })
    }

    fn give(&self, bytes: u64) {
        sync::update_atomic(&self.used, |used| Some(used.saturating_sub(bytes)));
    }

    /// One holder's part, `held` until now, made `now`: always when it
    /// shrinks; when it grows, only if all parts together stay within the
    /// limit. Whether it was made.
    fn resize(&self, held: u64, now: u64) -> bool {
        let limit = self.limit;
        sync::update_atomic(&self.used, |used| {
            let others = used.saturating_sub(held);
            (now <= held || others + now <= limit).then_some(others + now)
        })
    }

    fn used(&self) -> u64 {
        self.used.load(sync::Ordering::Acquire)
    }

    fn room(&self) -> u64 {
        self.limit.saturating_sub(self.used())
    }
}

impl Shared {
    /// Punches at `addr` for a meeting: for as long as a person may take to
    /// hand the peer this receiver's own addresses, and no longer than it is
    /// needed — until a session with the peer runs directly to its host (see
    /// [`Shared::met`]), or the receiver stops.
    #[cfg(feature = "nat-traversal")]
    fn meet(
        &self,
        puncher: &Arc<crate::nat::punch::Puncher>,
        addr: SocketAddr,
        hints: crate::nat::card::NatHints,
        id: Option<SharpId>,
    ) {
        self.meet_as(puncher, addr, hints, id, false)
    }

    /// [`Shared::meet`] at an address the DHT turned up: punched at in
    /// earnest only once it is vouched for (see `Puncher::run_for_found`).
    #[cfg(feature = "nat-traversal")]
    fn meet_found(&self, puncher: &Arc<crate::nat::punch::Puncher>, addr: SocketAddr) {
        self.meet_as(
            puncher,
            addr,
            crate::nat::card::NatHints::unknown(),
            None,
            true,
        )
    }

    #[cfg(feature = "nat-traversal")]
    fn meet_as(
        &self,
        puncher: &Arc<crate::nat::punch::Puncher>,
        addr: SocketAddr,
        hints: crate::nat::card::NatHints,
        id: Option<SharpId>,
        found: bool,
    ) {
        let stop = self.meetings.add(addr, id, &self.cancel);
        let puncher = puncher.clone();
        tokio::spawn(async move {
            let duration = crate::nat::punch::MEET_DURATION;
            if found {
                puncher.run_for_found(addr, duration, &stop).await;
            } else {
                puncher.run_for(addr, hints, duration, &stop).await;
            }
            // Over: its entry goes with the next change.
            stop.cancel();
        });
    }

    /// A session with `sender` runs at `peer` now. Punching at that host has
    /// done its work: the meetings it was for stop. (A session carried by a
    /// relay or a TURN server runs at the server's address, which is no
    /// peer's: the punching that may yet open a direct path goes on.)
    #[cfg(feature = "nat-traversal")]
    fn met(&self, sender: &SharpId, peer: SocketAddr) {
        if self.meetings.met(sender, peer) > 0 {
            tracing::debug!("{} reached directly: punching at it no more", peer);
        }
    }

    /// Sends one datagram to `to` from the socket that peer is reached
    /// through: the receiver's own, unless the peer had to be met at another
    /// (see `nat::birthday`).
    fn send(&self, to: SocketAddr, datagram: &[u8]) -> io::Result<()> {
        if let Some(sent) = self.streams.send(to, datagram) {
            return sent;
        }
        #[cfg(feature = "nat-traversal")]
        if let Some(sent) = self.routes.send(to, datagram) {
            return sent;
        }
        self.socket.try_send(to, datagram)
    }

    /// How good a path `addr` is (see `path::Standing`): a relay's host or a
    /// TURN address (see [`Relayed`]), a stream of a sender's own, or the
    /// sender itself. A sender moves to a stream when its UDP has gone quiet,
    /// and from one when UDP answers again: in both, what still arrives over
    /// the path it left is what was on its way, and following that back
    /// would have the session swap paths for as long as it lasts.
    fn standing(&self, addr: SocketAddr) -> crate::transport::path::Standing {
        use crate::transport::path::Standing;
        #[cfg(feature = "nat-traversal")]
        if self.relayed.contains(addr) {
            return Standing::Server;
        }
        if self.streams.contains(addr) {
            return Standing::Stream;
        }
        Standing::Direct
    }

    /// Takes `bytes` of the queue budget; false when it is spent.
    fn take_queued(&self, bytes: u64) -> bool {
        self.queued_total.take(bytes)
    }

    fn give_queued(&self, bytes: u64) {
        self.queued_total.give(bytes);
    }

    /// What one receiving session may hold of file data not yet written:
    /// its part of three quarters of the budget, and never more than its
    /// writer takes.
    fn write_share(&self) -> u64 {
        let receiving = self.receiving.load(Ordering::Acquire).max(1) as u64;
        (self.cfg.memory_budget / 4 * 3 / receiving).min(self.cfg.transport.writer_capacity_bytes)
    }
}

/// One session's part of [`Shared::unwritten_total`]: what it last claimed
/// or said it holds, taken back out when it ends.
///
/// Shares alone bound each session to its part of the budget at the moment
/// it takes data; sessions that start while others are still full would
/// otherwise add their shares on top. The total is what makes the bound
/// hold for all of them at every moment — which it does only because data
/// is taken by claiming room for it in the total, in one step with the
/// check (it used to be checked, and added when published: two sessions
/// could each pass on what the other had not published yet).
struct Unwritten {
    shared: Arc<Shared>,
    published: u64,
}

impl Unwritten {
    fn new(shared: &Arc<Shared>) -> Self {
        Self {
            shared: shared.clone(),
            published: 0,
        }
    }

    /// Records that this session now holds `now` bytes not yet on disk:
    /// what it claimed, less what its writer has written since.
    fn publish(&mut self, now: u64) {
        if now >= self.published {
            self.shared
                .unwritten_total
                .used
                .fetch_add(now - self.published, sync::Ordering::AcqRel);
        } else {
            self.shared
                .unwritten_total
                .used
                .fetch_sub(self.published - now, sync::Ordering::AcqRel);
        }
        self.published = now;
    }

    /// How much more this session could take before all sessions together
    /// reach the budget.
    fn room(&self) -> u64 {
        self.shared.unwritten_total.room()
    }

    /// Makes this session's part `now` bytes, if that fits with what every
    /// other holds; whether it did.
    fn claim(&mut self, now: u64) -> bool {
        let made = self.shared.unwritten_total.resize(self.published, now);
        if made {
            self.published = now;
        }
        made
    }
}

impl Drop for Unwritten {
    fn drop(&mut self) {
        self.publish(0);
    }
}

/// Counts a session among those receiving for as long as it lives.
struct Receiving(Arc<Shared>);

impl Receiving {
    fn new(shared: &Arc<Shared>) -> Self {
        shared.receiving.fetch_add(1, Ordering::AcqRel);
        Self(shared.clone())
    }
}

impl Drop for Receiving {
    fn drop(&mut self) {
        self.0.receiving.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Asks a session to let go of its transfer (see [`Session::let_go`]), and
/// says why.
#[derive(Clone, Default)]
struct Release {
    asked: CancellationToken,
    why: Arc<std::sync::OnceLock<&'static str>>,
}

impl Release {
    fn ask(&self, why: &'static str) {
        let _ = self.why.set(why);
        self.asked.cancel();
    }

    fn is_asked(&self) -> bool {
        self.asked.is_cancelled()
    }

    fn why(&self) -> &'static str {
        self.why.get().copied().unwrap_or(LET_GO_QUIET)
    }
}

/// Why a session lets go of its transfer.
const LET_GO_CONTINUED: &str =
    "the sender started the transfer again, and the new one continues it";
const LET_GO_QUIET: &str = "the sender went silent, and its next transfer takes the place";

/// How long a session waits for another to let go of the partial data it
/// continues (see [`Session::let_go_first`]).
const RELEASE_WAIT: Duration = Duration::from_secs(10);

/// A session's hold on partial data, among [`Shared::holders`]: the
/// transfers whose resume state is its to keep — its own, and that of an
/// earlier transfer of the same sender whose partial file it continues —
/// and the partial file (or staging directory) it writes.
///
/// One partial file has one session. A sender restarted without its resume
/// state starts the transfer of the same file anew, and the new transfer
/// continues the partial file that the old one's session — waiting for its
/// sender still, up to `session_ttl` — holds: the new session asks the old
/// one to let go first (see [`Session::let_go_first`]). They used to share
/// the file until the old session, having heard nothing, removed it (no
/// data had come) or, at `session_ttl`, left a second resume state for it.
/// Nor is a fresh partial file given a name that another session has
/// chosen and not created yet.
struct Holder {
    session: u64,
    sender: SharpId,
    transfers: Vec<[u8; 16]>,
    part: Option<PathBuf>,
    release: Release,
    /// Cancelled once the session has let go: when it ends.
    released: CancellationToken,
}

/// Who, besides a session, holds a transfer's resume state.
enum Held {
    /// No other session.
    Free,
    /// Another session of the same sender.
    Elsewhere(Other),
    /// Its partial file is another sender's session's: the state is stale.
    Stale,
}

/// Another session of the same sender that holds resume state.
struct Other {
    transfer: [u8; 16],
    release: Release,
    released: CancellationToken,
}

/// A session's entry among [`Shared::holders`], taken out when it ends.
struct Holding {
    shared: Arc<Shared>,
    session: u64,
    release: Release,
    released: CancellationToken,
}

impl Holding {
    fn new(shared: &Arc<Shared>, (sender, transfer): TransferKey, release: Release) -> Self {
        let session = shared.sessions_made.fetch_add(1, Ordering::Relaxed);
        let released = CancellationToken::new();
        shared.holders.lock().push(Holder {
            session,
            sender,
            transfers: vec![transfer],
            part: None,
            release: release.clone(),
            released: released.clone(),
        });
        Self {
            shared: shared.clone(),
            session,
            release,
            released,
        }
    }

    fn find(&self, holders: &[Holder], state: &ReceiverState) -> Held {
        let transfer = crate::state::parse_hex16(&state.transfer_id);
        let holder = holders.iter().find(|h| {
            h.session != self.session
                && (transfer.is_some_and(|t| h.transfers.contains(&t))
                    && h.sender.to_string() == state.sender
                    || h.part.as_deref() == Some(state.data_path()))
        });
        match holder {
            None => Held::Free,
            Some(h) if h.sender.to_string() == state.sender => Held::Elsewhere(Other {
                transfer: h.transfers[0],
                release: h.release.clone(),
                released: h.released.clone(),
            }),
            Some(_) => Held::Stale,
        }
    }

    /// Who else holds `state`.
    fn held(&self, state: &ReceiverState) -> Held {
        self.find(&self.shared.holders.lock(), state)
    }

    /// Takes `state` for this session if no other holds it (then
    /// [`Held::Free`]); who holds it otherwise.
    fn take(&self, state: &ReceiverState) -> Held {
        let mut holders = self.shared.holders.lock();
        let held = self.find(&holders, state);
        if let (Held::Free, Some(me)) = (
            &held,
            holders.iter_mut().find(|h| h.session == self.session),
        ) {
            if let Some(t) = crate::state::parse_hex16(&state.transfer_id) {
                if !me.transfers.contains(&t) {
                    me.transfers.push(t);
                }
            }
            me.part = Some(state.part_path.clone());
        }
        held
    }

    /// Chooses the partial file of a transfer that continues nothing with
    /// `choose`, which is told the names other sessions have chosen, and
    /// takes it.
    fn choose_part(&self, choose: impl FnOnce(&dyn Fn(&Path) -> bool) -> PathBuf) -> PathBuf {
        let mut holders = self.shared.holders.lock();
        let part = {
            let theirs = |p: &Path| {
                holders
                    .iter()
                    .any(|h| h.session != self.session && h.part.as_deref() == Some(p))
            };
            choose(&theirs)
        };
        if let Some(me) = holders.iter_mut().find(|h| h.session == self.session) {
            me.part = Some(part.clone());
        }
        part
    }
}

impl Drop for Holding {
    fn drop(&mut self) {
        self.shared
            .holders
            .lock()
            .retain(|h| h.session != self.session);
        self.released.cancel();
    }
}

/// How long a declined transfer is remembered, and how many are.
const DECLINE_MEMORY: Duration = Duration::from_secs(120);
const DECLINES_REMEMBERED: usize = 1024;

pub struct Receiver {
    shared: Arc<Shared>,
    /// Datagrams that reach the receiver through a socket other than its
    /// own, from a peer that could only be met that way (see
    /// `nat::birthday`); the sender half keeps the channel open when there
    /// is nothing to send through it.
    aux_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    #[cfg(not(feature = "nat-traversal"))]
    _aux_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    /// Contact cards of peers, handed over while the receiver runs (see
    /// [`Receiver::peer_cards`]).
    #[cfg_attr(not(feature = "nat-traversal"), allow(dead_code))]
    cards_tx: mpsc::UnboundedSender<PeerCard>,
    cards_rx: mpsc::UnboundedReceiver<PeerCard>,
    /// Addresses of peers handed over the same way, without a card (see
    /// [`Receiver::peer_addrs`]).
    #[cfg_attr(not(feature = "nat-traversal"), allow(dead_code))]
    addrs_tx: mpsc::UnboundedSender<SocketAddr>,
    addrs_rx: mpsc::UnboundedReceiver<SocketAddr>,
    /// Where senders reach this receiver over TCP, and what comes in on
    /// their streams (see `transport::carrier`).
    listener: Option<tokio::net::TcpListener>,
    streams_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}

/// A peer's contact card; there is no such thing without NAT traversal.
#[cfg(feature = "nat-traversal")]
type PeerCard = crate::nat::card::Card;
#[cfg(not(feature = "nat-traversal"))]
type PeerCard = std::convert::Infallible;

impl Receiver {
    pub async fn new(cfg: ReceiverConfig) -> Result<Self, RecvError> {
        let cfg = ReceiverConfig {
            transport: cfg.transport.normalized(),
            ..cfg
        };
        let identity = match &cfg.identity {
            Some(id) => id.clone(),
            None => {
                let path = Identity::default_path()
                    .ok_or_else(|| RecvError::Identity("no per-user data directory".into()))?;
                Identity::load_or_create(&path)
                    .map_err(|e| RecvError::Identity(format!("{}: {}", path.display(), e)))?
            }
        };
        std::fs::create_dir_all(&cfg.output_dir)?;
        let socket = BatchSocket::bind(cfg.bind, cfg.transport.socket_buffer_bytes).await?;
        tracing::info!(
            "receiver {} listening on {} (up to {} datagrams per send), output {}",
            identity.id(),
            socket.local_addr()?,
            socket.max_segments(),
            cfg.output_dir.display()
        );
        let store = match StateStore::open(cfg.state_dir.clone()) {
            Ok(s) => {
                // Resume state of transfers abandoned long ago is useless.
                if let Ok(n) = s.cleanup_older_than(STATE_MAX_AGE) {
                    if n > 0 {
                        tracing::info!("removed {} stale resume state file(s)", n);
                    }
                }
                Some(s)
            }
            Err(e) => {
                tracing::warn!("resume state disabled: {}", e);
                None
            }
        };
        #[cfg(feature = "nat-traversal")]
        let (routes, aux_rx) = crate::nat::birthday::Routes::new();
        #[cfg(not(feature = "nat-traversal"))]
        let (_aux_tx, aux_rx) = mpsc::channel(1);
        let (cards_tx, cards_rx) = mpsc::unbounded_channel();
        let (addrs_tx, addrs_rx) = mpsc::unbounded_channel();
        let (streams, streams_rx) = crate::transport::carrier::Streams::new();
        // Senders whose network lets no UDP out reach the receiver over TCP,
        // at the port number its UDP socket has. A port taken by something
        // else costs them that, and nobody else anything.
        let listener = if cfg.tcp {
            let udp = socket.local_addr()?;
            let dual_stack = udp.is_ipv6()
                && udp.ip().is_unspecified()
                && crate::address::Reach::of(&socket.udp()).v4();
            match crate::transport::carrier::listen::bind(udp, dual_stack) {
                Ok(l) => {
                    tracing::info!("receiver also takes senders over TCP at {}", udp);
                    Some(l)
                }
                Err(e) => {
                    tracing::warn!("cannot take senders over TCP at {} ({}); UDP only", udp, e);
                    None
                }
            }
        } else {
            None
        };
        let memory_budget = cfg.memory_budget;
        Ok(Self {
            aux_rx,
            cards_tx,
            cards_rx,
            addrs_tx,
            addrs_rx,
            listener,
            streams_rx,
            #[cfg(not(feature = "nat-traversal"))]
            _aux_tx,
            shared: Arc::new(Shared {
                cfg,
                socket: Arc::new(socket),
                store,
                cancel: CancellationToken::new(),
                identity,
                declined: parking_lot::Mutex::new(HashMap::new()),
                streams,
                queued_total: Budget::new(memory_budget / 4),
                receiving: std::sync::atomic::AtomicUsize::new(0),
                unwritten_total: Budget::new(memory_budget / 4 * 3),
                holders: parking_lot::Mutex::new(Vec::new()),
                sessions_made: AtomicU64::new(0),
                #[cfg(feature = "nat-traversal")]
                routes,
                #[cfg(feature = "nat-traversal")]
                meetings: Meetings::default(),
                #[cfg(feature = "nat-traversal")]
                relayed: Relayed::default(),
            }),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.socket.local_addr()
    }

    /// Where a peer's contact card is handed to this receiver while it
    /// runs: it starts punching towards every address on the card at once,
    /// which is what lets a sender behind a NAT that filters unasked
    /// packets get in (see `nat::card`).
    #[cfg(feature = "nat-traversal")]
    pub fn peer_cards(&self) -> mpsc::UnboundedSender<crate::nat::card::Card> {
        self.cards_tx.clone()
    }

    /// Where a peer's bare address — the `IP:PORT` a NAT test on its side
    /// prints — is handed to this receiver while it runs: it starts sending
    /// there at once, as for a card, but knows nothing of the NAT in front of
    /// it, so it tries the ways that suit each kind in turn.
    #[cfg(feature = "nat-traversal")]
    pub fn peer_addrs(&self) -> mpsc::UnboundedSender<SocketAddr> {
        self.addrs_tx.clone()
    }

    /// Our identity: senders need it to reach us.
    pub fn id(&self) -> SharpId {
        self.shared.identity.id()
    }

    /// The ID in the form senders are to use (see
    /// [`ReceiverConfig::id_text`]).
    pub fn id_text(&self) -> String {
        self.shared.cfg.id_text(&self.id())
    }

    /// Token that stops the receiver (sessions persist their state first).
    pub fn cancel_token(&self) -> CancellationToken {
        self.shared.cancel.clone()
    }

    /// Serves transfers until cancelled.
    pub async fn run(self) -> Result<(), RecvError> {
        let shared = self.shared;
        let mut aux_rx = self.aux_rx;
        let mut cards_rx = self.cards_rx;
        let mut addrs_rx = self.addrs_rx;
        let mut streams_rx = self.streams_rx;
        if let Some(listener) = self.listener {
            tokio::spawn(crate::transport::carrier::listen::serve(
                listener,
                shared.streams.clone(),
                shared.cancel.child_token(),
            ));
        }

        // NAT discovery runs in the background; its STUN responses arrive on
        // this socket and are handed over below.
        // Not for a receiver that is to be reached only through its relays:
        // discovery would ask the router to open a port and publish the
        // very addresses the relays were asked to keep to themselves.
        #[cfg(feature = "nat-traversal")]
        if shared.cfg.relay_only() {
            tracing::info!(
                "reachable only through the relays: not discovering or publishing direct addresses"
            );
        }
        // One keepalive policy for everything that goes out through this
        // socket's NAT mapping — STUN and every relay registration — so
        // that what one learns about the NAT, all act on.
        #[cfg(feature = "nat-traversal")]
        let keepalive: crate::nat::keepalive::SharedKeepalive = Arc::new(parking_lot::Mutex::new(
            crate::nat::keepalive::Keepalive::new(shared.cfg.nat_keepalive),
        ));
        // What this receiver's NAT does, as its own tests find out: told to
        // every relay it registers with, and what a punch is aimed by.
        #[cfg(feature = "nat-traversal")]
        let (hints_tx, hints_rx) =
            tokio::sync::watch::channel(crate::nat::card::FamilyHints::unknown());
        // TURN servers this receiver was given: each makes an allocation in
        // the background, and lets in whoever is punched at.
        #[cfg(feature = "nat-traversal")]
        let turns = crate::nat::turn::start_all(
            &shared.cfg.turn_servers,
            &shared.socket.udp(),
            &shared.cancel,
        );
        #[cfg(feature = "nat-traversal")]
        {
            *shared.relayed.turns.write() = turns.clone();
        }
        #[cfg(feature = "nat-traversal")]
        let puncher = Arc::new(
            crate::nat::punch::Puncher::new(shared.socket.udp(), hints_rx)
                .with_hit_handler({
                    let routes = shared.routes.clone();
                    Arc::new(move |hit| routes.adopt(hit))
                })
                .with_turns(turns.clone()),
        );
        // What discovery finds and what the TURN servers give are reported
        // together, and again when either changes.
        #[cfg(feature = "nat-traversal")]
        let reports = {
            let events = shared.cfg.events.clone();
            let id = shared.identity.id();
            let id_text = shared.cfg.id_text(&id);
            let relay_refs = relay_refs(&shared.cfg.relays);
            crate::nat::RelayedReports::new(
                shared.socket.local_addr().unwrap_or(shared.cfg.bind),
                turns.clone(),
                shared.cancel.clone(),
                shared.cfg.nat_traversal && !shared.cfg.relay_only(),
                move |r| {
                    emit(
                        &events,
                        TransferEvent::Reachability {
                            advertised: r.advertised().map(|a| a.to_string()),
                            address: r.address_string(&id_text),
                            card: Some(
                                r.card(&id, crate::nat::card::Role::Receiver, &relay_refs)
                                    .to_text(),
                            ),
                            summary: r.describe(),
                        },
                    )
                },
            )
        };
        #[cfg(feature = "nat-traversal")]
        let nat = if shared.cfg.nat_traversal && !shared.cfg.relay_only() {
            let puncher = puncher.clone();
            let reports = reports.clone();
            crate::nat::spawn_discovery(
                shared.socket.udp(),
                {
                    let mut c = crate::nat::NatConfig {
                        publish_lan_addresses: shared.cfg.publish_lan_addresses,
                        ..crate::nat::NatConfig::default()
                    };
                    if !shared.cfg.stun_servers.is_empty() {
                        c.stun_servers = shared.cfg.stun_servers.clone();
                    }
                    c
                },
                keepalive.clone(),
                hints_tx,
                shared.cancel.clone(),
                move |r| {
                    // The tests are over: what is known of this NAT is what
                    // it will be, for the punches that wait for it.
                    puncher.settle();
                    reports.update(r);
                },
            )
        } else {
            None
        };
        #[cfg(feature = "nat-traversal")]
        if nat.is_none() {
            puncher.settle();
        }

        // Announced in the DHT, when asked to be, and the sender looked for
        // there: what turns up is punched at, as an address on a card is.
        #[cfg(feature = "nat-traversal")]
        if shared.cfg.dht {
            match crate::nat::dht::Dht::start(
                shared.cfg.dht_bootstrap.clone(),
                shared.cancel.clone(),
            ) {
                Ok(dht) => {
                    tracing::info!(
                        "announcing in the DHT: every node asked learns this host's address{}",
                        if shared.cfg.psk.is_none() {
                            ", and anybody who knows this receiver's ID can look it up (a shared secret prevents that)"
                        } else {
                            ""
                        }
                    );
                    let key = crate::nat::dht::rendezvous_key(
                        &shared.identity.id(),
                        shared.cfg.psk.as_ref(),
                    );
                    let (punch, meeting) = (puncher.clone(), shared.clone());
                    crate::nat::dht::spawn_rendezvous(
                        dht,
                        key,
                        crate::nat::dht::Role::Receiver,
                        puncher.subscribe(),
                        shared.cancel.clone(),
                        move |peer, news| {
                            use crate::nat::dht::PeerNews;
                            match news {
                                PeerNews::Found { vouched } => {
                                    if vouched {
                                        punch.vouch(peer.ip());
                                    }
                                    meeting.meet_found(&punch, peer);
                                }
                                PeerNews::Vouched => punch.vouch(peer.ip()),
                            }
                        },
                    );
                }
                Err(e) => tracing::warn!("cannot use the DHT: {}", e),
            }
        }

        // Announced on the local network, when asked to be: a sender there
        // that knows this receiver's ID finds it without an address.
        #[cfg(feature = "nat-traversal")]
        if shared.cfg.announce_lan {
            let (id, socket) = (shared.identity.id(), shared.socket.clone());
            match crate::nat::mdns::announce(
                move || crate::nat::mdns::Announcement {
                    id,
                    port: socket.local_addr().map(|a| a.port()).unwrap_or(0),
                    addresses: socket
                        .local_addr()
                        .map(|l| crate::nat::host_addresses(l, true))
                        .unwrap_or_default(),
                },
                shared.cancel.clone(),
            ) {
                Ok(_) => tracing::info!(
                    "announced on the local network as {}",
                    crate::nat::mdns::instance_name(&shared.identity.id())
                ),
                Err(e) => tracing::warn!("cannot announce on the local network: {}", e),
            }
        }

        // Relays run alongside: each registers this receiver so that a
        // sender who cannot reach any of its addresses can still be
        // introduced to it, and carried if the introduction is not enough.
        // Their control messages arrive on this same socket.
        #[cfg(feature = "nat-traversal")]
        let relays = spawn_relay_clients(&shared, &keepalive, &puncher);

        let socket = shared.socket.clone();
        let cancel = shared.cancel.clone();
        let (done_tx, mut done_rx) = mpsc::channel::<TransferKey>(256);
        let mut d = Dispatcher::new(shared.clone(), done_tx);
        let mut bufs = recv_buffers(RECV_BATCH);
        let mut got = vec![
            Received {
                from: shared.cfg.bind,
                len: 0,
                stride: 0,
                dst: None,
            };
            RECV_BATCH
        ];

        loop {
            tokio::select! {
                r = socket.readable() => {
                    if let Err(e) = r {
                        tracing::debug!("socket readiness error: {}", e);
                        continue;
                    }
                    for _ in 0..RECV_CALLS_PER_WAKEUP {
                        let n = match socket.try_recv(&mut bufs, &mut got) {
                            Ok(n) => n,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                tracing::debug!("recv error: {}", e);
                                break;
                            }
                        };
                        let now = Instant::now();
                        for (buf, r) in bufs.iter_mut().zip(&got[..n]) {
                            #[cfg(feature = "nat-traversal")]
                            if side_channel(nat.as_ref(), &relays, &puncher, &buf[..r.len], r.from, r.stride) {
                                continue;
                            }
                            d.on_received(buf, *r, now);
                        }
                        d.flush();
                    }
                }
                Some(key) = done_rx.recv() => d.forget(&key),
                Some(card) = cards_rx.recv() => {
                    #[cfg(feature = "nat-traversal")]
                    meet_card(&shared, &puncher, card);
                    #[cfg(not(feature = "nat-traversal"))]
                    match card {}
                }
                Some(addr) = addrs_rx.recv() => {
                    #[cfg(feature = "nat-traversal")]
                    meet_addr(&shared, &puncher, addr);
                    #[cfg(not(feature = "nat-traversal"))]
                    let _ = addr;
                }
                Some(first) = streams_rx.recv() => {
                    // From senders on streams: as if it had come in on the
                    // socket, from the address each stream comes from — what
                    // is waiting, at once, as a batch off the socket is.
                    let now = Instant::now();
                    let mut next = Some(first);
                    let mut taken = 0;
                    while let Some((mut buf, from)) = next.take() {
                        let r = Received { from, len: buf.len(), stride: buf.len(), dst: None };
                        d.on_received(&mut buf, r, now);
                        taken += 1;
                        if taken < RECV_BATCH * RECV_CALLS_PER_WAKEUP {
                            next = streams_rx.try_recv().ok();
                        }
                    }
                    d.flush();
                }
                Some((data, from)) = aux_rx.recv() => {
                    // From a peer met at a socket of its own: routed like
                    // anything the main socket reads.
                    let mut buf = data;
                    let r = Received { from, len: buf.len(), stride: buf.len(), dst: None };
                    #[cfg(feature = "nat-traversal")]
                    if side_channel(nat.as_ref(), &relays, &puncher, &buf, from, buf.len()) {
                        continue;
                    }
                    d.on_received(&mut buf, r, Instant::now());
                    d.flush();
                }
                _ = cancel.cancelled() => {
                    tracing::info!("receiver shutting down; {} active session(s)", d.sessions.len());
                    // Sessions observe the same token; wait until each one has
                    // flushed its file and persisted its resume state.
                    let handles: Vec<_> = d.sessions.drain().map(|(_, s)| s.task).collect();
                    for h in handles {
                        let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
                    }
                    // The NAT task observes the same token and gives its
                    // port forward back, and each relay task says goodbye
                    // so the relay stops sending people to an address
                    // nothing answers at. Both at once, and not for long.
                    #[cfg(feature = "nat-traversal")]
                    {
                        let mut tasks = relays.tasks;
                        if let Some(nat) = nat {
                            tasks.push(nat.task);
                        }
                        // They run on their own; one deadline covers all.
                        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                        for t in tasks {
                            let _ = tokio::time::timeout_at(deadline, t).await;
                        }
                        // And the TURN allocations are given back.
                        for t in &turns {
                            t.finished(Duration::from_secs(2)).await;
                        }
                    }
                    return Ok(());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

struct Dispatcher {
    shared: Arc<Shared>,
    responder: Responder,
    cookies: CookieJar,
    limiter: HandshakeLimiter,
    replays: ReplayGuard,
    sessions: HashMap<TransferKey, SessionHandle>,
    by_cid: HashMap<u64, TransferKey>,
    /// Version 4: initiations being put together, and handshakes answered
    /// that wait for their HELLO.
    fragments: hs::Fragments,
    pending: HashMap<u64, PendingV4>,
    /// Datagrams collected for sessions during the current receive call.
    outbox: Vec<(TransferKey, Vec<Datagrams>)>,
    at: Instant,
    done_tx: mpsc::Sender<TransferKey>,
    dropped: u64,
}

impl Dispatcher {
    fn new(shared: Arc<Shared>, done_tx: mpsc::Sender<TransferKey>) -> Self {
        let cfg = &shared.cfg;
        let responder = Responder::new(
            shared.identity.clone(),
            cfg.psk.clone().unwrap_or_else(crate::crypto::no_psk),
        );
        let cookies = CookieJar::new(&shared.identity.id());
        let limiter = HandshakeLimiter::new(
            cfg.handshake_rate,
            cfg.handshake_burst,
            cfg.handshake_load_threshold,
        );
        Self {
            shared,
            responder,
            cookies,
            limiter,
            replays: ReplayGuard::new(REPLAY_GUARD_CAPACITY),
            sessions: HashMap::new(),
            by_cid: HashMap::new(),
            fragments: hs::Fragments::default(),
            pending: HashMap::new(),
            outbox: Vec::new(),
            at: Instant::now(),
            done_tx,
            dropped: 0,
        }
    }

    /// Routes the datagrams of one receive buffer. A run that belongs to one
    /// session as a whole (always the case for datagrams the kernel
    /// coalesced) is passed on in one piece, large ones without a copy.
    fn on_received(&mut self, buf: &mut Vec<u8>, r: Received, now: Instant) {
        self.at = now;
        let run = &buf[..r.len];
        let stride = r.stride.max(1);
        let whole = peek_cid(run)
            .and_then(|cid| self.by_cid.get(&cid).map(|key| (cid, *key)))
            .filter(|(cid, _)| {
                run.chunks(stride)
                    .all(|d| d.len() >= OVERHEAD && peek_cid(d) == Some(*cid))
            });
        if let Some((_, key)) = whole {
            let data = if r.len <= RUN_COPY_MAX {
                run.to_vec()
            } else {
                let mut taken = std::mem::replace(buf, vec![0u8; RECV_BUF_LEN]);
                taken.truncate(r.len);
                taken
            };
            self.queue(
                key,
                Datagrams {
                    buf: data,
                    stride,
                    from: r.from,
                },
            );
            return;
        }
        for d in r.segments() {
            self.on_datagram(&buf[d], r.from, now);
        }
    }

    fn on_datagram(&mut self, pkt: &[u8], from: SocketAddr, now: Instant) {
        if let Some(cid) = peek_cid(pkt) {
            if let Some(&key) = self.by_cid.get(&cid) {
                if pkt.len() >= OVERHEAD {
                    self.queue(
                        key,
                        Datagrams {
                            buf: pkt.to_vec(),
                            stride: pkt.len(),
                            from,
                        },
                    );
                }
                return;
            }
        }
        // Not for a known connection: an initiation by someone who knows our
        // ID, or nothing we ever answer.
        if self.responder.is_initiation(pkt) {
            // A version 3 initiation, answered only when asked to (see
            // `ReceiverConfig::speak_v3`); otherwise as silent as to a
            // stranger.
            if !self.shared.cfg.speak_v3 {
                return;
            }
            // Deliver what arrived before it first, keeping the order.
            self.flush();
            self.on_initiation(pkt, from, now);
        } else if !self.shared.cfg.speak_v4 {
        } else if let Some(cid) = peek_cid(pkt).filter(|c| self.pending.contains_key(c)) {
            self.flush();
            self.on_pending(cid, pkt, from, now);
        } else if let Some(f) = self.responder.fragment(pkt) {
            self.flush();
            self.on_fragment(pkt, f, from, now);
        }
    }

    fn queue(&mut self, key: TransferKey, d: Datagrams) {
        match self.outbox.iter_mut().find(|(k, _)| *k == key) {
            Some((_, runs)) => runs.push(d),
            None => self.outbox.push((key, vec![d])),
        }
    }

    /// Hands the collected datagrams to their sessions; a session that
    /// cannot keep up loses them (the sender sees them as lost).
    fn flush(&mut self) {
        let at = self.at;
        for (key, runs) in self.outbox.drain(..) {
            let Some(s) = self.sessions.get_mut(&key) else {
                continue;
            };
            s.heard = at;
            let bytes: u64 = runs.iter().map(|d| d.buf.capacity() as u64).sum();
            // Within the session's own limit, and within what all sessions
            // together may have queued: sixteen sessions each at their own
            // limit would otherwise hold half a gigabyte between them.
            if !self.shared.take_queued(bytes) {
                self.dropped += 1;
                continue;
            }
            let queued = s.queued.fetch_add(bytes, Ordering::AcqRel);
            let refused = queued + bytes > SESSION_QUEUE_BYTES
                || s.tx
                    .try_send(Incoming::Datagrams { runs, bytes, at })
                    .is_err();
            if refused {
                s.queued.fetch_sub(bytes, Ordering::AcqRel);
                self.shared.give_queued(bytes);
                self.dropped += 1;
                if self.dropped.is_power_of_two() {
                    tracing::debug!(
                        "session queue full: {} deliveries dropped so far",
                        self.dropped
                    );
                }
            }
        }
    }

    fn on_initiation(&mut self, pkt: &[u8], from: SocketAddr, now: Instant) {
        let under_load = self.limiter.note_initiation(now);
        if under_load && !self.cookies.mac2_ok(pkt, from, now) {
            // Make the sender prove it receives at its address before we
            // spend public-key operations on it.
            if let Some(reply) = self.cookies.reply(pkt, from, now) {
                let _ = self.shared.send(from, &reply);
            }
            return;
        }
        if !self.limiter.allow(from, now) {
            return;
        }
        let incoming = match self.responder.read_initiation(pkt) {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("initiation from {} rejected: {}", from, e);
                return;
            }
        };
        let init = match wire::decode_initiation(&incoming.payload) {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("malformed initiation payload from {}: {}", from, e);
                return;
            }
        };
        let sender = incoming.sender;
        // Whom we refuse anyway is settled before the replay guard hears of
        // them: identities cost nothing to make, and a stranger's entries
        // there would otherwise push out those of the senders we serve.
        if let Some(allowed) = &self.shared.cfg.allowed_senders {
            if !allowed.contains(&sender) {
                tracing::info!(
                    "transfer from {} ({}) refused: sender not allowed",
                    from,
                    sender
                );
                self.reject(
                    incoming,
                    &init,
                    (from, pkt.len()),
                    REASON_UNAUTHORIZED,
                    "sender not authorized",
                );
                return;
            }
        }
        // And whoever has a transfer in progress is never pushed out.
        let sessions = &self.sessions;
        if !self.replays.accept_keeping(&sender, init.timestamp, |id| {
            sessions.keys().any(|(s, _)| s == id)
        }) {
            tracing::debug!("replayed initiation from {} ignored", from);
            return;
        }
        // The user already said no to this one.
        let key = (sender, init.hello.transfer_id);
        {
            let mut declined = self.shared.declined.lock();
            declined.retain(|_, at| now.saturating_duration_since(*at) < DECLINE_MEMORY);
            if declined.contains_key(&key) {
                drop(declined);
                self.reject(
                    incoming,
                    &init,
                    (from, pkt.len()),
                    REASON_DECLINED,
                    "declined by user",
                );
                return;
            }
        }
        let Some(suite) = Suite::choose(init.suites, init.hardware_aes) else {
            self.reject(
                incoming,
                &init,
                (from, pkt.len()),
                REASON_NO_SUITE,
                "no cipher in common",
            );
            return;
        };
        let cid = self.new_cid();
        let handshake = Box::new(Handshake {
            incoming,
            init,
            suite,
            cid,
            from,
            at: now,
            len: pkt.len(),
        });

        // A new handshake of a transfer we already serve (the sender lost the
        // session after an outage, or restarted): move the session over.
        if let Some(s) = self.sessions.get_mut(&key) {
            if !s.task.is_finished() {
                s.heard = now;
                // Routed to the new connection id only once the session
                // has the handshake: if its queue is full, moving the
                // routing anyway left it deaf to both ids until the next
                // handshake. Dropped instead, the handshake is repeated.
                if s.tx.try_send(Incoming::Handshake(handshake)).is_ok() {
                    self.by_cid.remove(&s.cid);
                    s.cid = cid;
                    self.by_cid.insert(cid, key);
                }
                return;
            }
            self.drop_session(&key);
        }

        self.prune();
        if let Err(message) = self.room_for(&sender, from, now) {
            let Handshake { incoming, init, .. } = *handshake;
            self.reject(incoming, &init, (from, pkt.len()), REASON_BUSY, message);
            return;
        }
        self.spawn_session(key, from, cid, Incoming::Handshake(handshake), now);
    }

    /// Whether a new session for `sender` fits: the limit on sessions, and
    /// its share of them — without one the limit is first-come-first-served,
    /// and one authenticated sender could take every slot and lock
    /// everybody else out. Being on the allow-list does not make that
    /// acceptable.
    ///
    /// A sender that finds its share full, or every session taken, makes
    /// room with its own transfer that has been silent longest, if that one
    /// has been for `stall_timeout`: it lets go (see [`Session::let_go`]),
    /// its partial file and state kept for when the sender comes back to it.
    /// A sender cut off in the middle of as many transfers as its share, and
    /// sending other files now, was refused until they ran out at
    /// `session_ttl`. Other senders' sessions are not let go of.
    fn room_for(
        &self,
        sender: &SharpId,
        from: SocketAddr,
        now: Instant,
    ) -> Result<(), &'static str> {
        let cfg = &self.shared.cfg;
        let counted = || self.sessions.iter().filter(|(_, s)| !s.release.is_asked());
        let its = || counted().filter(|((s, _), _)| s == sender);
        let share = cfg
            .max_sessions_per_sender
            .clamp(1, cfg.max_sessions.max(1));
        let full = counted().count() >= cfg.max_sessions;
        let spent = its().count() >= share;
        if !full && !spent {
            return Ok(());
        }
        let quiet = its()
            .filter(|(_, s)| now.saturating_duration_since(s.heard) >= cfg.transport.stall_timeout)
            .min_by_key(|(_, s)| s.heard);
        if let Some(((_, transfer), s)) = quiet {
            tracing::info!(
                "transfer {} from {} silent for {:.1?}: asked to let go, for the sender's next one",
                hex16(transfer),
                sender,
                now.saturating_duration_since(s.heard)
            );
            s.release.ask(LET_GO_QUIET);
            return Ok(());
        }
        if full {
            return Err("too many concurrent transfers");
        }
        tracing::info!(
            "transfer from {} ({}) refused: it already holds {} of {} sessions",
            from,
            sender,
            share,
            cfg.max_sessions
        );
        Err("too many concurrent transfers from this sender")
    }

    /// Starts the session for `key` at connection id `cid`, handing it
    /// `first` (its handshake).
    fn spawn_session(
        &mut self,
        key: TransferKey,
        from: SocketAddr,
        cid: u64,
        first: Incoming,
        now: Instant,
    ) {
        let (tx, rx) = mpsc::channel::<Incoming>(SESSION_QUEUE);
        let _ = tx.try_send(first);
        let shared = self.shared.clone();
        let done_tx = self.done_tx.clone();
        let session_tx = tx.clone();
        let queued = Arc::new(AtomicU64::new(0));
        let session_queued = queued.clone();
        let release = Release::default();
        let session_release = release.clone();
        let task = tokio::spawn(async move {
            let session = Session::new(
                shared,
                key,
                from,
                session_tx,
                session_queued,
                session_release,
            );
            let key = session.run(rx).await;
            let _ = done_tx.send(key).await;
        });
        self.by_cid.insert(cid, key);
        self.sessions.insert(
            key,
            SessionHandle {
                tx,
                queued,
                cid,
                task,
                heard: now,
                release,
            },
        );
    }

    // ----- version 4 -------------------------------------------------------

    /// A fragment of a version 4 initiation. Under load each needs the mac2
    /// of a cookie (a reply to any of them gives it); the whole initiation,
    /// once in, counts against its client's rate like any other.
    fn on_fragment(&mut self, pkt: &[u8], f: hs::Fragment, from: SocketAddr, now: Instant) {
        let under_load = self.limiter.note_initiation(now);
        if under_load && !self.cookies.mac2_ok(pkt, from, now) {
            if let Some(reply) = self.cookies.reply(pkt, from, now) {
                let _ = self.shared.send(from, &reply);
            }
            return;
        }
        let Some(whole) = self.fragments.add(pkt, f, from, now) else {
            return;
        };
        if !self.limiter.allow(from, now) {
            return;
        }
        self.on_initiation_v4(whole, from, now);
    }

    /// A version 4 initiation, put together: answered with keys and nothing
    /// more (see [`PendingV4`]), or refused.
    fn on_initiation_v4(&mut self, whole: hs::Assembled, from: SocketAddr, now: Instant) {
        let incoming = match self
            .responder
            .read_initiation_v4(whole.sender_cid, &whole.msg)
        {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("version 4 initiation from {} rejected: {}", from, e);
                return;
            }
        };
        let init = match wire::decode_initiation_v4(&incoming.payload) {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("malformed initiation payload from {}: {}", from, e);
                return;
            }
        };
        let sender = incoming.sender;
        if let Some(allowed) = &self.shared.cfg.allowed_senders {
            if !allowed.contains(&sender) {
                tracing::info!(
                    "transfer from {} ({}) refused: sender not allowed",
                    from,
                    sender
                );
                self.refuse_v4(incoming, from, whole.len, REASON_UNAUTHORIZED);
                return;
            }
        }
        let sessions = &self.sessions;
        if !self.replays.accept_keeping(&sender, init.timestamp, |id| {
            sessions.keys().any(|(s, _)| s == id)
        }) {
            tracing::debug!("replayed initiation from {} ignored", from);
            return;
        }
        let Some(suite) = Suite::choose(init.suites, init.hardware_aes) else {
            self.refuse_v4(incoming, from, whole.len, REASON_NO_SUITE);
            return;
        };
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.at) < PENDING_V4_PATIENCE);
        if self.pending.len() >= PENDING_V4_CAPACITY {
            if let Some(oldest) = self
                .pending
                .iter()
                .min_by_key(|(_, p)| p.at)
                .map(|(c, _)| *c)
            {
                self.pending.remove(&oldest);
            }
        }
        let cid = self.new_cid();
        let peer_cid = incoming.sender_cid;
        let payload = wire::encode_response_v4(&wire::ResponseV4 {
            suite: suite as u8,
            reason: REASON_NONE,
        });
        let Ok((pkt, split)) = incoming.respond(cid, &payload) else {
            return;
        };
        // No more back than came in (it is shorter by construction).
        if pkt.len() > whole.len {
            return;
        }
        let _ = self.shared.send(from, &pkt);
        self.pending.insert(
            cid,
            PendingV4 {
                keys: Arc::new(SessionKeys::derive(&split, false, suite)),
                sender,
                peer_cid,
                from,
                at: now,
                len: whole.len,
                answered: pkt.len(),
            },
        );
    }

    /// Refuses a version 4 handshake in its answer: a reason, no keys.
    fn refuse_v4(&self, incoming: hs::Incoming, to: SocketAddr, len: usize, reason: u8) {
        let payload = wire::encode_response_v4(&wire::ResponseV4 { suite: 0, reason });
        if let Ok((pkt, _)) = incoming.respond(self.new_cid(), &payload) {
            if pkt.len() <= len {
                let _ = self.shared.send(to, &pkt);
            }
        }
    }

    /// A datagram for a version 4 handshake that waits for its HELLO. The
    /// HELLO, and only it, makes the session: it names the transfer, and it
    /// is the first thing the sender's key stands behind. Anything else
    /// before it is dropped. The datagram then goes to the session like any
    /// other, which answers the HELLO.
    fn on_pending(&mut self, cid: u64, pkt: &[u8], from: SocketAddr, now: Instant) {
        let Some(p) = self.pending.get(&cid) else {
            return;
        };
        let mut copy = pkt.to_vec();
        let Ok((tb, _, body)) = p.keys.recv.open(&mut copy) else {
            return;
        };
        let Ok((MsgType::Hello, _)) = parse_type_byte(tb) else {
            return;
        };
        let Ok(Message::Hello(hello)) = wire::decode_body(MsgType::Hello, body) else {
            return;
        };
        let p = self.pending.remove(&cid).expect("present");
        let key = (p.sender, hello.transfer_id);
        let established = Box::new(Established {
            keys: p.keys.clone(),
            cid,
            peer_cid: p.peer_cid,
            from: p.from,
            at: p.at,
            len: p.len,
            answered: p.answered,
            hello: hello.clone(),
        });
        let delivery = Datagrams {
            buf: pkt.to_vec(),
            stride: pkt.len(),
            from,
        };
        // A new handshake of a transfer we already serve: the session moves
        // to it.
        if let Some(s) = self.sessions.get_mut(&key) {
            if !s.task.is_finished() {
                s.heard = now;
                if s.tx.try_send(Incoming::Established(established)).is_ok() {
                    self.by_cid.remove(&s.cid);
                    s.cid = cid;
                    self.by_cid.insert(cid, key);
                    self.queue(key, delivery);
                }
                return;
            }
            self.drop_session(&key);
        }
        let refusal = {
            let mut declined = self.shared.declined.lock();
            declined.retain(|_, at| now.saturating_duration_since(*at) < DECLINE_MEMORY);
            declined.contains_key(&key)
        }
        .then_some((REASON_DECLINED, "declined by user"));
        self.prune();
        let refusal = refusal.or_else(|| {
            self.room_for(&p.sender, from, now)
                .err()
                .map(|message| (REASON_BUSY, message))
        });
        if let Some((reason, message)) = refusal {
            // Sealed under the handshake's keys, and only to the address
            // the HELLO has just proven: a transport packet from where the
            // answer went.
            if from == p.from {
                let mut out = Vec::with_capacity(MAX_CONTROL_DATAGRAM);
                begin_packet(&mut out, p.peer_cid, type_byte(MsgType::HelloAck, 0), 0);
                let ack = rejection(hello.timestamp, reason, message);
                wire::encode_body(&Message::HelloAck(ack), &mut out, MAX_CONTROL_BODY);
                if p.keys.send.seal(&mut out).is_ok() {
                    let _ = self.shared.send(from, &out);
                }
            }
            tracing::info!("transfer from {} ({}) refused: {}", from, p.sender, message);
            return;
        }
        self.spawn_session(key, p.from, cid, Incoming::Established(established), now);
        self.queue(key, delivery);
    }

    /// Answers an authenticated initiation of `len` bytes with a rejection;
    /// no session is created.
    fn reject(
        &self,
        incoming: hs::Incoming,
        init: &wire::Initiation,
        (to, len): (SocketAddr, usize),
        reason: u8,
        message: &str,
    ) {
        let Some(payload) = rejection_within(init.hello.timestamp, reason, message, len) else {
            return;
        };
        if let Ok((pkt, _)) = incoming.respond(self.new_cid(), &payload) {
            let _ = self.shared.send(to, &pkt);
        }
    }

    fn new_cid(&self) -> u64 {
        loop {
            let c = rand::rngs::OsRng.next_u64();
            // Some values mean something else on the wire; see there.
            if is_usable_cid(c) && !self.by_cid.contains_key(&c) && !self.pending.contains_key(&c) {
                return c;
            }
        }
    }

    /// Drops the routing of a session whose task ended.
    fn forget(&mut self, key: &TransferKey) {
        if self.sessions.get(key).is_some_and(|s| s.task.is_finished()) {
            self.drop_session(key);
        }
    }

    fn prune(&mut self) {
        let finished: Vec<TransferKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.task.is_finished())
            .map(|(k, _)| *k)
            .collect();
        for k in finished {
            self.drop_session(&k);
        }
    }

    /// Forgets a finished session, and gives back the queue budget of
    /// whatever was still queued to it when it ended.
    fn drop_session(&mut self, key: &TransferKey) {
        if let Some(s) = self.sessions.remove(key) {
            self.by_cid.remove(&s.cid);
            self.shared.give_queued(s.queued.swap(0, Ordering::AcqRel));
        }
    }
}

/// A receiver's dispatcher driven by hand, for the fuzzing targets: every
/// datagram goes in as the socket loop hands it over, at the time the
/// target says, and the sessions it starts run on the caller's runtime.
#[cfg(any(test, fuzzing))]
pub struct DispatcherHarness {
    d: Dispatcher,
    _done: mpsc::Receiver<TransferKey>,
}

#[cfg(any(test, fuzzing))]
impl DispatcherHarness {
    /// A dispatcher as `receiver` runs one, fresh (and the transfers its
    /// user declined forgotten). Made within a tokio runtime, whose tasks
    /// the sessions become.
    pub fn new(receiver: &Receiver) -> Self {
        receiver.shared.declined.lock().clear();
        let (tx, rx) = mpsc::channel(64);
        Self {
            d: Dispatcher::new(receiver.shared.clone(), tx),
            _done: rx,
        }
    }

    /// One datagram from `from`, and what it leaves for the sessions handed
    /// to them.
    pub fn datagram(&mut self, pkt: &[u8], from: SocketAddr, now: Instant) {
        self.d.at = now;
        self.d.on_datagram(pkt, from, now);
        self.d.flush();
    }

    /// Sends `mark` to `to` from the receiver's socket, after everything
    /// the receiver sent there before it: once it arrives, so has the rest
    /// (a datagram on loopback is readable at once on Linux, a moment later
    /// on macOS).
    pub fn fence(&self, to: SocketAddr, mark: &[u8]) -> io::Result<()> {
        self.d.shared.socket.try_send(to, mark)
    }

    /// Sessions (but those asked to let go of their transfers, which are
    /// ending and count against no limit), version 4 handshakes waiting for
    /// their HELLO, fragments held.
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.d
                .sessions
                .values()
                .filter(|s| !s.release.is_asked())
                .count(),
            self.d.pending.len(),
            self.d.fragments.len(),
        )
    }

    /// Ends every session, and passes on the panic of any that panicked,
    /// which a runtime would only print.
    pub async fn finish(mut self) {
        let mut panicked = None;
        for (_, s) in self.d.sessions.drain() {
            s.task.abort();
            if let Err(e) = s.task.await {
                if e.is_panic() && panicked.is_none() {
                    panicked = Some(e.into_panic());
                }
            }
        }
        if let Some(p) = panicked {
            std::panic::resume_unwind(p);
        }
    }
}

/// A relay this receiver is registered with, and the channel the dispatcher
/// hands its control messages over on.
#[cfg(feature = "nat-traversal")]
struct RelayClient {
    /// Every address the relay's name gave, the one in use among them: its
    /// messages may come from any.
    addrs: Vec<SocketAddr>,
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

/// The relays this receiver registers with.
#[cfg(feature = "nat-traversal")]
struct RelayClients {
    /// Filled in as each relay's name resolves, so a slow or dead name
    /// server holds up nothing: transfers are served from the start.
    list: Arc<parking_lot::RwLock<Vec<RelayClient>>>,
    /// One task per relay; each says goodbye to its relay when cancelled,
    /// which is worth waiting a moment for on the way out.
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// How long one attempt at resolving a relay's name may take, and the most
/// the retries back off to. A name that does not resolve at start-up — the
/// network not up yet, say — is tried again, since the relay may be the
/// only way anyone can reach us.
#[cfg(feature = "nat-traversal")]
const RELAY_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "nat-traversal")]
const RELAY_RESOLVE_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Starts punching towards every address of a peer's card, for as long as a
/// person may take to hand the peer this receiver's own.
#[cfg(feature = "nat-traversal")]
fn meet_card(
    shared: &Arc<Shared>,
    puncher: &Arc<crate::nat::punch::Puncher>,
    card: crate::nat::card::Card,
) {
    if let Some(why) = card.staleness() {
        tracing::warn!("contact card of {}: {}", card.id.short(), why);
    }
    for c in &card.candidates {
        if c.kind == crate::nat::card::Kind::Relayed {
            shared.relayed.add(c.addr);
        }
    }
    let targets = card.punch_targets();
    tracing::info!(
        "contact card of {}: punching towards {} address(es)",
        card.id.short(),
        targets.len()
    );
    for (addr, hints) in targets {
        shared.meet(puncher, addr, hints, Some(card.id));
    }
}

/// Starts punching towards a peer's bare address, for as long as a person
/// may take to hand the peer this receiver's own. Nothing is known of the
/// NAT in front of it, so the ways that suit each kind are tried in turn.
#[cfg(feature = "nat-traversal")]
fn meet_addr(shared: &Arc<Shared>, puncher: &Arc<crate::nat::punch::Puncher>, addr: SocketAddr) {
    tracing::info!("peer address {}: punching towards it", addr);
    shared.meet(puncher, addr, crate::nat::card::NatHints::unknown(), None);
}

/// The relays this receiver is registered with that are written with an
/// identity and an address, as a card names them.
#[cfg(feature = "nat-traversal")]
fn relay_refs(relays: &[String]) -> Vec<crate::nat::card::RelayRef> {
    relays
        .iter()
        .filter_map(|r| {
            let (Some(id), host) = crate::relay::parse_relay(r).ok()? else {
                return None;
            };
            let addr = crate::address::dns::parse_literal(&host)?;
            Some(crate::nat::card::RelayRef { id, addr })
        })
        .collect()
}

/// Registers this receiver with every configured relay, in the background.
#[cfg(feature = "nat-traversal")]
fn spawn_relay_clients(
    shared: &Arc<Shared>,
    keepalive: &crate::nat::keepalive::SharedKeepalive,
    puncher: &Arc<crate::nat::punch::Puncher>,
) -> RelayClients {
    let list: Arc<parking_lot::RwLock<Vec<RelayClient>>> =
        Arc::new(parking_lot::RwLock::new(Vec::new()));
    let reach = crate::address::Reach::of(&shared.socket.udp());
    let mut tasks = Vec::new();
    for name in &shared.cfg.relays {
        // Registering means proving we own our identity against the relay's
        // public key, so a receiver has to be told which relay it is talking
        // to — `ID@host:port`. Without that there is nothing to prove
        // against, and anyone who knew our published ID could register it
        // here instead of us.
        let (relay_id, host) = match crate::relay::parse_relay(name) {
            Ok((Some(id), host)) => (id, host),
            Ok((None, _)) => {
                tracing::warn!(
                    "relay \"{}\" has no identity; write it as <relay ID>@<host>:<port>",
                    name
                );
                continue;
            }
            Err(e) => {
                tracing::warn!("relay \"{}\": {}", name, e);
                continue;
            }
        };
        let cancel = shared.cancel.clone();
        let shared = shared.clone();
        let list = list.clone();
        let keepalive = keepalive.clone();
        let puncher = puncher.clone();
        tasks.push(tokio::spawn(async move {
            let Some(addrs) = resolve_relay(&host, reach, &cancel).await else {
                return;
            };
            shared.relayed.add_hosts(&addrs);
            let (events, private, h) = (
                shared.cfg.events.clone(),
                shared.cfg.relay_private,
                host.clone(),
            );
            let on_registered: OnRegistered =
                Arc::new(move |addr: SocketAddr, observed: SocketAddr| {
                    // Deliberately *not* published as an address to hand a
                    // sender. It is this receiver's NAT mapping towards that
                    // relay's control port, and under the NAT a relay exists
                    // to get around — the kind that uses a different port for
                    // every destination — it is by definition not the mapping
                    // anybody else would arrive at. A sender reaches us here
                    // by naming the relay, not by naming this.
                    // Over a stream the relay is known by its address alone.
                    let at = if addr.port() == 0 {
                        format!("{} over TCP", addr.ip())
                    } else {
                        addr.to_string()
                    };
                    tracing::info!(
                        "registered with the relay at {} (it sees us at {}); senders reach us \
                     through it with --relay {}",
                        at,
                        observed,
                        h
                    );
                    emit(
                        &events,
                        TransferEvent::RelayRegistered {
                            relay: h.clone(),
                            observed: observed.to_string(),
                            private,
                        },
                    );
                });
            keep_registered(
                &shared,
                &list,
                addrs,
                relay_id,
                &host,
                &keepalive,
                &puncher,
                on_registered,
            )
            .await;
        }));
    }
    RelayClients { list, tasks }
}

/// What a relay client says when it is registered: where, and where the
/// relay sees it.
#[cfg(feature = "nat-traversal")]
type OnRegistered = Arc<dyn Fn(SocketAddr, SocketAddr) + Send + Sync>;

/// How long UDP is given to get a registration through — or back, once it
/// fell — before the relay is reached over a stream instead (see
/// `relay::tunnel`); and how long a stream then holds the registration
/// before UDP is given another chance, alongside it.
#[cfg(feature = "nat-traversal")]
const UDP_PATIENCE: Duration = Duration::from_secs(8);
#[cfg(feature = "nat-traversal")]
const STREAM_SPELL: Duration = Duration::from_secs(600);

/// One way of being registered with a relay, while it runs.
#[cfg(feature = "nat-traversal")]
struct Leg {
    task: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
    /// Whether the relay holds the registration now (see
    /// `relay::client::serve`), and since when it has not.
    standing: tokio::sync::watch::Receiver<bool>,
    down_since: Instant,
    /// The stream, when the leg runs over one.
    link: Option<crate::transport::carrier::Link>,
}

#[cfg(feature = "nat-traversal")]
impl Leg {
    fn up(&self) -> bool {
        *self.standing.borrow()
    }

    /// Stops it (saying goodbye, if it was registered), and forgets the
    /// routes its stream carried.
    async fn stop(self, shared: &Shared) {
        self.cancel.cancel();
        let _ = self.task.await;
        if let Some(link) = &self.link {
            link.close();
            shared.streams.unroute_link(link);
        }
    }
}

/// Keeps this receiver registered with one relay: over UDP from the
/// transfer socket while that works — it is what lets a sender punch through
/// to us — and over a stream when no registration gets through over UDP
/// within [`UDP_PATIENCE`]. While a stream holds it, UDP is tried again now
/// and then alongside, and takes the registration back as soon as it holds
/// it: the two never both go on refreshing it, which would move it from one
/// address to the other and back at every refresh.
#[cfg(feature = "nat-traversal")]
#[allow(clippy::too_many_arguments)]
async fn keep_registered(
    shared: &Arc<Shared>,
    list: &Arc<parking_lot::RwLock<Vec<RelayClient>>>,
    addrs: Vec<SocketAddr>,
    relay_id: SharpId,
    host: &str,
    keepalive: &crate::nat::keepalive::SharedKeepalive,
    puncher: &Arc<crate::nat::punch::Puncher>,
    on_registered: OnRegistered,
) {
    let cancel = shared.cancel.clone();
    let socket = shared.socket.udp();
    let local = socket.local_addr().unwrap_or(shared.cfg.bind);
    let tls = crate::relay::tunnel::TlsTo::new(host, Some(relay_id), shared.cfg.relay_tls_port);
    let start_udp = || {
        let (tx, rx) = mpsc::channel(32);
        {
            // The dispatcher hands this relay's datagrams over here now.
            let mut l = list.write();
            l.retain(|c| c.addrs != addrs);
            l.push(RelayClient {
                addrs: addrs.clone(),
                tx,
            });
        }
        let (standing_tx, standing) = tokio::sync::watch::channel(false);
        let leg_cancel = cancel.child_token();
        let cb = on_registered.clone();
        let task = tokio::spawn(crate::relay::client::serve(
            socket.clone(),
            addrs.clone(),
            relay_id,
            shared.identity.clone(),
            shared.cfg.relay_private,
            rx,
            leg_cancel.clone(),
            keepalive.clone(),
            puncher.clone(),
            standing_tx,
            move |a, o| cb(a, o),
        ));
        Leg {
            task,
            cancel: leg_cancel,
            standing,
            down_since: Instant::now(),
            link: None,
        }
    };
    let mut udp = Some(start_udp());
    let mut stream: Option<Leg> = None;
    // When UDP is next tried while a stream holds the registration.
    let mut udp_again = Instant::now();
    let mut pause = Duration::from_secs(2);
    loop {
        let now = Instant::now();
        if let Some(u) = &mut udp {
            if u.up() {
                // UDP holds it: a stream, if any, gives it up.
                if let Some(s) = stream.take() {
                    tracing::info!("relay {}: registered over UDP again; leaving TCP", host);
                    s.stop(shared).await;
                }
                pause = Duration::from_secs(2);
            } else if now.saturating_duration_since(u.down_since) >= UDP_PATIENCE {
                // Nothing over UDP for its whole patience.
                if let Some(u) = udp.take() {
                    u.stop(shared).await;
                }
                if stream
                    .as_ref()
                    .is_none_or(|s| s.link.as_ref().is_some_and(|l| l.is_closed()))
                {
                    if let Some(s) = stream.take() {
                        s.stop(shared).await;
                    }
                    tracing::info!("relay {}: no registration over UDP; trying TCP", host);
                    stream = over_stream(
                        shared,
                        &addrs,
                        tls.as_ref(),
                        relay_id,
                        local,
                        puncher,
                        &on_registered,
                    )
                    .await;
                }
                udp_again = Instant::now()
                    + if stream.is_some() {
                        STREAM_SPELL
                    } else {
                        pause
                    };
                if stream.is_none() {
                    pause = (pause * 2).min(Duration::from_secs(60));
                }
            }
        } else {
            let stream_dead = stream
                .as_ref()
                .is_none_or(|s| s.link.as_ref().is_some_and(|l| l.is_closed()));
            if stream_dead {
                if let Some(s) = stream.take() {
                    tracing::info!("relay {}: the TCP stream ended", host);
                    s.stop(shared).await;
                }
            }
            if stream_dead || now >= udp_again {
                udp = Some(start_udp());
            }
        }
        if cancel.is_cancelled() {
            break;
        }
        // Until either leg's registration changes, the stream ends, a
        // patience or a spell runs out, or the receiver stops.
        let deadline = match &udp {
            Some(u) if !u.up() => u.down_since + UDP_PATIENCE,
            Some(_) => now + Duration::from_secs(3600),
            None => udp_again,
        };
        let stream_link = stream.as_ref().and_then(|s| s.link.clone());
        tokio::select! {
            r = async { udp.as_mut().unwrap().standing.changed().await }, if udp.is_some() => {
                if r.is_ok() {
                    if let Some(u) = &mut udp {
                        if !u.up() {
                            u.down_since = Instant::now();
                        }
                    }
                }
            }
            _ = async { stream_link.as_ref().unwrap().closed().await }, if stream_link.is_some() => {}
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
            _ = cancel.cancelled() => {}
        }
    }
    // The receiver is stopping: each leg says goodbye, if it was registered.
    if let Some(u) = udp {
        u.stop(shared).await;
    }
    if let Some(s) = stream {
        s.stop(shared).await;
    }
}

/// Registers with the relay over a stream to the first of its addresses
/// that takes one.
#[cfg(feature = "nat-traversal")]
async fn over_stream(
    shared: &Arc<Shared>,
    addrs: &[SocketAddr],
    tls: Option<&crate::relay::tunnel::TlsTo>,
    relay_id: SharpId,
    local: SocketAddr,
    puncher: &Arc<crate::nat::punch::Puncher>,
    on_registered: &OnRegistered,
) -> Option<Leg> {
    let cancel = shared.cancel.clone();
    let reached = tokio::select! {
        r = crate::relay::tunnel::reach(addrs, tls, local) => r,
        _ = cancel.cancelled() => return None,
    };
    let (addr, stream) = match reached {
        Ok(v) => v,
        Err(crate::relay::tunnel::Unreached::Intercepted(why)) => {
            tracing::warn!(
                "relay: {} ({}); not using it",
                crate::relay::tunnel::Intercepted,
                why
            );
            return None;
        }
        Err(crate::relay::tunnel::Unreached::Failed(why)) => {
            tracing::info!("relay over TCP or TLS: {}", why);
            return None;
        }
    };
    let over = match tls {
        Some(t) if t.port() == addr.port() => "TLS",
        _ => "TCP",
    };
    tracing::info!("relay reached over {} at {}", over, addr);
    {
        let leg_cancel = cancel.child_token();
        let (tunnel, rx) = crate::relay::tunnel::ClientTunnel::open(
            stream,
            addr,
            shared.socket.udp(),
            crate::relay::tunnel::Pairs::Dispatcher(shared.streams.clone()),
            leg_cancel.clone(),
        );
        // A keepalive policy of its own: the stream's refreshes say nothing
        // of the NAT mapping the UDP ones keep.
        let keepalive = Arc::new(parking_lot::Mutex::new(
            crate::nat::keepalive::Keepalive::new(shared.cfg.nat_keepalive),
        ));
        let (standing_tx, standing) = tokio::sync::watch::channel(false);
        let cb = on_registered.clone();
        let link = tunnel.link().clone();
        let task = tokio::spawn(crate::relay::client::serve(
            tunnel.via(),
            vec![tunnel.relay()],
            relay_id,
            shared.identity.clone(),
            shared.cfg.relay_private,
            rx,
            leg_cancel.clone(),
            keepalive,
            puncher.clone(),
            standing_tx,
            move |a, o| cb(a, o),
        ));
        Some(Leg {
            task,
            cancel: leg_cancel,
            standing,
            down_since: Instant::now(),
            link: Some(link),
        })
    }
}

/// Resolves a relay's name to the addresses this socket can reach, in the
/// order to try them (IPv6 first where this host has it, the families
/// taking turns), trying again with growing pauses until there is one or
/// the receiver stops.
#[cfg(feature = "nat-traversal")]
async fn resolve_relay(
    host: &str,
    reach: crate::address::Reach,
    cancel: &CancellationToken,
) -> Option<Vec<SocketAddr>> {
    let mut wait = Duration::from_secs(2);
    let mut told = false;
    loop {
        let attempt = tokio::select! {
            r = tokio::time::timeout(RELAY_RESOLVE_TIMEOUT, crate::address::resolve_all(host)) => r,
            _ = cancel.cancelled() => return None,
        };
        let why = match attempt {
            Ok(Ok(all)) => {
                let usable: Vec<SocketAddr> = all.iter().filter_map(|a| reach.native(*a)).collect();
                if !usable.is_empty() {
                    return Some(usable);
                }
                format!(
                    "none of its addresses ({:?}) can be reached from this socket",
                    all
                )
            }
            Ok(Err(e)) => e.to_string(),
            Err(_) => "the name did not resolve in time".to_string(),
        };
        if told {
            tracing::debug!("relay {}: {}; trying again in {:?}", host, why, wait);
        } else {
            tracing::warn!("relay {}: {}; trying again in {:?}", host, why, wait);
            told = true;
        }
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = cancel.cancelled() => return None,
        }
        wait = (wait * 2).min(RELAY_RESOLVE_BACKOFF_MAX);
    }
}

/// Hands a run of datagrams that belongs to NAT discovery or to a relay
/// over to it, and says whether it did.
///
/// The kernel may have coalesced several datagrams from one sender into the
/// run (they are `stride` bytes apart), so each is looked at on its own:
/// passing only whole single datagrams, as this once did, lost every
/// message that happened to arrive in a batch.
#[cfg(feature = "nat-traversal")]
fn side_channel(
    nat: Option<&crate::nat::NatTask>,
    relays: &RelayClients,
    puncher: &crate::nat::punch::Puncher,
    run: &[u8],
    from: SocketAddr,
    stride: usize,
) -> bool {
    let stride = stride.max(1);
    let first = &run[..stride.min(run.len())];
    // STUN travels on the transfer socket, so discovery never competes for
    // datagrams. The hairpinning test looks for our own request coming
    // back, hence requests too.
    if let Some(nat) = nat {
        if crate::nat::stun::is_stun_message(first) {
            // Discovery is over once its task has let go of the channel;
            // copying the datagram only to have the send fail is waste.
            if nat.stun_responses.is_closed() {
                return true;
            }
            for d in run.chunks(stride) {
                if crate::nat::stun::is_stun_message(d) {
                    let _ = nat.stun_responses.try_send((d.to_vec(), from));
                }
            }
            return true;
        }
    }
    // A relay's control messages, from its control port or from a port it
    // set aside for us. They can never be traffic: the connection id they
    // would parse as is one no endpoint ever picks.
    if crate::relay::is_control(first) {
        let list = relays.list.read();
        if let Some(c) = list
            .iter()
            .find(|c| c.addrs.iter().any(|a| a.ip() == from.ip()))
        {
            for d in run.chunks(stride) {
                if crate::relay::is_control(d) {
                    let _ = c.tx.try_send((d.to_vec(), from));
                }
            }
        } else if matches!(
            crate::relay::Message::decode(first),
            Some(crate::relay::Message::Punch)
        ) {
            // A host punching at us is a peer's (see
            // `Puncher::run_for_found`).
            puncher.vouch(from.ip());
        }
        return true;
    }
    false
}

/// The payload of a handshake response that rejects a transfer, held to an
/// answer of at most `limit` bytes — the initiation's, since the address it
/// came from is not proven. The message is shortened to fit, and dropped if
/// need be; `None` if even the bare rejection would be longer.
fn rejection_within(echo_ts: u32, reason: u8, message: &str, limit: usize) -> Option<Vec<u8>> {
    let room = limit.checked_sub(hs::RESPONSE_OVERHEAD)?;
    let encode = |message: &str| {
        wire::encode_response(&wire::Response {
            suite: 0,
            ack_flags: 0,
            ack: rejection(echo_ts, reason, message),
        })
    };
    let bare = encode("");
    if bare.len() > room {
        return None;
    }
    let mut cut = message.len().min(room - bare.len());
    while !message.is_char_boundary(cut) {
        cut -= 1;
    }
    let payload = encode(&message[..cut]);
    (payload.len() <= room).then_some(payload).or(Some(bare))
}

fn rejection(echo_ts: u32, reason: u8, message: &str) -> HelloAck {
    HelloAck {
        status: HELLO_REJECTED,
        reason,
        max_chunk: 0,
        capabilities: 0,
        echo_ts,
        max_ack_delay_us: 0,
        rwnd: 0,
        resume_upto: 0,
        known_end: 0,
        holes: Vec::new(),
        message: message.to_string(),
    }
}

/// Closes the writer (fsync), hashes the partial file and moves it to its
/// final name. Runs outside the session task so the session stays responsive.
async fn finish_file(
    writer: FileWriter,
    part: PathBuf,
    final_path: PathBuf,
    overwrite: bool,
    all_on_disk: impl FnOnce() + Send + 'static,
    placed: impl FnOnce(&Path, &[u8; 32]) + Send + 'static,
) -> Result<([u8; 32], PathBuf), String> {
    writer
        .close()
        .await
        .map_err(|e| format!("cannot finish writing file: {}", e))?;
    all_on_disk();
    let p = part.clone();
    // The file hashed is the one moved into place: a regular file, still the
    // same one at the moment of the move (see `durable::no_follow`).
    let (hash, id) = tokio::task::spawn_blocking(move || -> io::Result<_> {
        let id = crate::file::durable::file_id(&p)?;
        let hash = hash_file(&p)?;
        crate::file::durable::still_the_same(&p, id)?;
        Ok((hash, id))
    })
    .await
    .map_err(|e| format!("hash task failed: {}", e))?
    .map_err(|e| format!("cannot hash file: {}", e))?;
    let target = tokio::task::spawn_blocking(move || -> io::Result<PathBuf> {
        crate::file::durable::still_the_same(&part, id)?;
        let dir = crate::file::durable::parent_of(&final_path);
        if overwrite {
            // A rename replaces what is there in one step (on Windows as
            // well: MoveFileEx with MOVEFILE_REPLACE_EXISTING); removing it
            // first left a moment with neither file under the name.
            rename_with_retry(&part, &final_path)?;
            // The rename is on disk before the sender is told the file is
            // stored (FIN follows this).
            crate::file::durable::sync_dir(&dir)?;
            placed(&final_path, &hash);
            return Ok(final_path);
        }
        let name = final_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        // Never over anything, even a file that appears after the free
        // name was chosen.
        let target = crate::file::move_into_free_name(&part, &dir, &name, unique_path)?;
        crate::file::durable::sync_dir(&dir)?;
        placed(&target, &hash);
        Ok(target)
    })
    .await
    .map_err(|e| format!("rename task failed: {}", e))?
    .map_err(|e| format!("cannot rename partial file: {}", e))?;
    Ok((hash, target))
}

/// Closes the writer of a complete directory (which creates the entries no
/// write created), hashes the stream, applies times and permissions and
/// moves the tree to its final name, which never replaces anything.
async fn finish_tree(
    writer: FileWriter,
    staging: PathBuf,
    final_path: PathBuf,
    plan: Arc<Manifest>,
    manifest: Arc<Vec<u8>>,
    all_on_disk: impl FnOnce() + Send + 'static,
    placed: impl FnOnce(&Path, &[u8; 32]) + Send + 'static,
) -> Result<([u8; 32], PathBuf), String> {
    writer
        .finish()
        .await
        .map_err(|e| format!("cannot finish writing the directory: {}", e))?;
    all_on_disk();
    tokio::task::spawn_blocking(move || {
        let hash = tree::hash_tree(&staging, &plan, &manifest)
            .map_err(|e| format!("cannot hash the directory: {}", e))?;
        let umask = tree::local_umask(&staging);
        // Applies times and permissions and flushes every entry, before the
        // tree is moved into place: what appears under the final name is
        // then what the manifest says, on disk.
        let failures = tree::apply_metadata(&staging, &plan, umask)
            .map_err(|e| format!("cannot flush {}: {}", staging.display(), e))?;
        if failures > 0 {
            tracing::warn!(
                "{} entries of {} keep default times or permissions",
                failures,
                staging.display()
            );
        }
        crate::file::durable::sync_dir(&staging)
            .map_err(|e| format!("cannot flush {}: {}", staging.display(), e))?;
        let dir = crate::file::durable::parent_of(&final_path);
        let name = final_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let target = crate::file::move_into_free_name(&staging, &dir, &name, tree::unique_dir_path)
            .map_err(|e| format!("cannot move {} into place: {}", staging.display(), e))?;
        if let Err(e) = tree::apply_root_metadata(&target, &plan, umask) {
            tracing::warn!("cannot set metadata of {}: {}", target.display(), e);
        }
        // The move on disk before the sender is told the directory is
        // stored (the root's own times and permissions went with
        // `apply_root_metadata`).
        crate::file::durable::sync_dir(&dir)
            .map_err(|e| format!("cannot flush {}: {}", dir.display(), e))?;
        placed(&target, &hash);
        Ok((hash, target))
    })
    .await
    .map_err(|e| format!("finishing task failed: {}", e))?
}

/// Checks a complete manifest against what HELLO announced and decodes it.
fn verify_manifest(bytes: &[u8], info: &TreeInfo, stream_len: u64) -> Result<Manifest, String> {
    if bytes.len() as u64 != info.manifest_len
        || *blake3::hash(bytes).as_bytes() != info.manifest_hash
    {
        return Err("the directory listing does not match its announced hash".into());
    }
    let m = Manifest::decode(bytes).map_err(|e| e.to_string())?;
    if m.stream_len() != stream_len || m.files() != info.files || m.dirs() != info.dirs {
        return Err("the directory listing does not match the announced transfer".into());
    }
    Ok(m)
}

/// Resolves when the application decided, or never without a pending
/// decision.
async fn decided(rx: &mut Option<oneshot::Receiver<bool>>) -> bool {
    match rx {
        Some(r) => r.await.unwrap_or(false),
        None => std::future::pending().await,
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

enum Phase {
    /// Waiting for the application to accept or decline.
    Pending {
        deadline: Instant,
    },
    Receiving,
    /// All bytes present; closing, hashing and renaming in the background.
    Verifying,
    /// FIN sent; waiting for the sender's verdict.
    Finishing {
        hash: [u8; 32],
        next_fin_at: Instant,
        fin_delay: Duration,
        started_at: Instant,
    },
    /// Refused, but the refusal could not go yet: the sender had not shown
    /// that it receives where the session is, and the refusal was longer
    /// than what may be sent there before it has (see `peer_allowance`). It
    /// goes with the answer to the sender's next question — its decision
    /// poll, a second at most — or, by `until`, not at all.
    Refusing {
        reason: u8,
        message: String,
        until: Instant,
    },
}

/// How long a refusal waits for the sender's address to prove itself (the
/// sender asks for the decision every second).
const REFUSAL_WAIT: Duration = Duration::from_secs(5);

/// A directory transfer's manifest, while it arrives and once verified.
struct TreeRecv {
    info: TreeInfo,
    /// Manifest bytes received so far.
    buf: Vec<u8>,
    /// The verified manifest and its encoding (hashed again at the end).
    plan: Option<(Arc<Manifest>, Arc<Vec<u8>>)>,
    /// DATA beyond the manifest that arrived before the manifest was
    /// complete: (stream offset, bytes).
    early: Vec<(u64, Vec<u8>)>,
    early_bytes: u64,
    /// The staging directory holds entries of an earlier attempt.
    resume: bool,
}

/// Keys and packet state of the session's current handshake.
struct Secure {
    keys: Arc<SessionKeys>,
    /// Increases with every key change; decryption results of older keys
    /// are discarded.
    generation: u64,
    /// Our connection id: the sender addresses its packets to it.
    local_cid: u64,
    /// The sender's connection id: our packets are addressed to it.
    peer_cid: u64,
    next_pn: u64,
    replay: ReplayWindow,
    auth_failures: u64,
}

/// File data found in one receive buffer: `(stream offset, start, len)` of
/// every payload piece, handed to the writer together with the buffer.
#[derive(Default)]
struct Pieces {
    list: Vec<(u64, usize, usize)>,
    bytes: u64,
}

/// Deliveries with this many datagrams or more are decrypted on the crypto
/// pool.
const MIN_POOLED: usize = 8;

/// A delivery, decrypted.
struct OpenedDelivery {
    seq: u64,
    /// Key generation the datagrams were decrypted with.
    generation: u64,
    runs: Vec<Datagrams>,
    opened: Vec<Vec<Opened>>,
    bytes: u64,
    at: Instant,
}

/// Deliveries between arriving and being processed: decrypted on the
/// crypto pool (or right away, when small), then processed strictly in the
/// order they arrived.
struct OpenPipe {
    next_seq: u64,
    next_done: u64,
    in_pool: usize,
    ready: std::collections::BTreeMap<u64, OpenedDelivery>,
    tx: mpsc::UnboundedSender<OpenedDelivery>,
    rx: mpsc::UnboundedReceiver<OpenedDelivery>,
}

impl OpenPipe {
    fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            next_seq: 0,
            next_done: 0,
            in_pool: 0,
            ready: std::collections::BTreeMap::new(),
            tx,
            rx,
        }
    }
}

/// Decrypts the datagrams of a run in place. Only authenticity is
/// established here; replays and contents are dealt with in order
/// afterwards.
fn open_datagrams(keys: &DirectionKeys, cid: u64, buf: &mut [u8], stride: usize) -> Vec<Opened> {
    let len = buf.len();
    let lengths = (0..len).step_by(stride).map(|s| (s + stride).min(len) - s);
    parallel::split_lengths(buf, lengths)
        .into_iter()
        .map(|d| {
            // Packets for a connection id we replaced are stale.
            if peek_cid(d) != Some(cid) {
                return Opened::Stale;
            }
            match keys.open(d) {
                Ok((tb, pn, _)) => Opened::Ok(tb, pn),
                Err(_) => Opened::Forged,
            }
        })
        .collect()
}

/// What decrypting one datagram of a run found.
#[derive(Debug, Clone, Copy)]
enum Opened {
    /// Addressed to a connection id we no longer use (or no session yet).
    Stale,
    /// Failed authentication.
    Forged,
    /// Authentic: its type byte and packet number.
    Ok(u8, u64),
}

/// A control frame taken out of a receive buffer.
struct Control {
    msg_type: MsgType,
    body: Vec<u8>,
    /// Length of the datagram that carried it.
    datagram_len: usize,
    /// Source address of that datagram. Address validation needs it: a
    /// PATH_RESPONSE only proves the address it comes back from.
    from: SocketAddr,
}

struct Session {
    shared: Arc<Shared>,
    cfg: TransportConfig,
    events: Option<EventCallback>,
    self_tx: mpsc::Sender<Incoming>,
    /// Bytes of datagrams the dispatcher queued for us.
    queued: Arc<AtomicU64>,
    /// Deliveries being decrypted, or decrypted and waiting for their turn.
    opening: OpenPipe,
    /// Counts us among the sessions sharing the memory budget while we
    /// receive file data.
    receiving: Option<Receiving>,
    /// Our part of the file data not yet on disk, all sessions together.
    unwritten: Unwritten,

    transfer_id: [u8; 16],
    sender: SharpId,
    /// The sender's address: everything we send goes there (before it is
    /// proven, within `peer_allowance`).
    peer: SocketAddr,
    /// Whether `peer` has shown that it receives there: a transport packet
    /// from it, under keys our answer to the handshake made (see
    /// `note_alive`), or an answer to a challenge. A session starts at the
    /// address its first initiation came from, which proves nothing — a
    /// copy of it may have had its source forged — and until then nothing
    /// may be sent there but what the initiation left over of its own
    /// length after the answer (`peer_allowance`): no more back than came in.
    peer_proven: bool,
    peer_allowance: usize,
    /// An address the sender claims but has not proven yet.
    path: PathProbe,
    /// The proven address the meetings at its host were last ended for (see
    /// [`Shared::met`]).
    #[cfg(feature = "nat-traversal")]
    met_at: Option<SocketAddr>,
    secure: Option<Secure>,
    tx_buf: Vec<u8>,

    file_name: String,
    file_size: u64,
    file_mtime: i64,
    max_chunk: u16,
    final_path: PathBuf,
    part_path: PathBuf,
    writer: Option<FileWriter>,
    /// Set for a directory transfer.
    tree: Option<TreeRecv>,
    received: RangeSet,
    highest: u64,
    resumed_from: u64,
    /// The result is under `final_path` already, with this hash, and only
    /// the sender's confirmation is missing (Р22).
    placed: Option<[u8; 32]>,

    pkts_since_ack: u32,
    last_ack_at: Instant,
    immediate_ack_at: Option<Instant>,
    last_data_ts: u32,
    last_data_at: Instant,

    persist_dirty: bool,
    last_persist_at: Instant,
    flush_in_progress: bool,
    flush_snapshot: Option<RangeSet>,

    start: Instant,
    last_rx: Instant,
    /// When the sender was last heard from at `peer` itself (see
    /// [`Session::keeps_direct`]).
    heard_peer_at: Instant,
    stalled: bool,
    last_progress_at: Instant,
    last_progress_bytes: u64,
    retransmitted_bytes: u64,
    writer_full_drops: u64,
    /// DATA refused because it would have split the file into more pieces
    /// than [`MAX_RECEIVED_RANGES`].
    fragment_drops: u64,
    /// Whether this session stored any new data (idle sessions expire early).
    got_data: bool,
    phase: Phase,
    /// The earlier transfer whose resume state this one continues: removed
    /// once this one's own is kept (see [`Session::persist_state_now`]).
    took_over: Option<String>,
    /// What partial data this session holds (see [`Holder`]); let go of
    /// last, when everything else is.
    holding: Holding,
}

impl Session {
    fn new(
        shared: Arc<Shared>,
        key: TransferKey,
        peer: SocketAddr,
        self_tx: mpsc::Sender<Incoming>,
        queued: Arc<AtomicU64>,
        release: Release,
    ) -> Self {
        let now = Instant::now();
        let cfg = shared.cfg.transport.clone();
        let events = shared.cfg.events.clone();
        Self {
            receiving: None,
            unwritten: Unwritten::new(&shared),
            holding: Holding::new(&shared, key, release),
            took_over: None,
            shared,
            cfg,
            events,
            self_tx,
            queued,
            opening: OpenPipe::new(),
            transfer_id: key.1,
            sender: key.0,
            peer,
            peer_proven: false,
            peer_allowance: 0,
            path: PathProbe::new(),
            #[cfg(feature = "nat-traversal")]
            met_at: None,
            secure: None,
            tx_buf: Vec::with_capacity(MAX_CONTROL_DATAGRAM),
            file_name: String::new(),
            file_size: 0,
            file_mtime: 0,
            max_chunk: DEFAULT_CHUNK,
            final_path: PathBuf::new(),
            part_path: PathBuf::new(),
            writer: None,
            tree: None,
            received: RangeSet::new(),
            highest: 0,
            resumed_from: 0,
            placed: None,
            pkts_since_ack: 0,
            last_ack_at: now,
            immediate_ack_at: None,
            last_data_ts: 0,
            last_data_at: now,
            persist_dirty: false,
            last_persist_at: now,
            flush_in_progress: false,
            flush_snapshot: None,
            start: now,
            last_rx: now,
            heard_peer_at: now,
            stalled: false,
            last_progress_at: now,
            last_progress_bytes: 0,
            retransmitted_bytes: 0,
            writer_full_drops: 0,
            fragment_drops: 0,
            got_data: false,
            phase: Phase::Receiving,
        }
    }

    fn tid_hex(&self) -> String {
        hex16(&self.transfer_id)
    }

    fn key(&self) -> TransferKey {
        (self.sender, self.transfer_id)
    }

    /// Encrypts `msg` as a transport packet to the sender's proven address.
    fn send(&mut self, flags: u8, msg: &Message<'_>) -> bool {
        self.send_to(self.peer, flags, msg)
    }

    /// Encrypts `msg` as a transport packet and sends it to `to`. Only
    /// address validation sends anywhere but the proven address, and only
    /// the small PATH_CHALLENGE / PATH_RESPONSE frames.
    /// Whether it went (not whether it arrives).
    fn send_to(&mut self, to: SocketAddr, flags: u8, msg: &Message<'_>) -> bool {
        let Some(sec) = self.secure.as_mut() else {
            return false;
        };
        let pn = sec.next_pn;
        sec.next_pn += 1;
        begin_packet(
            &mut self.tx_buf,
            sec.peer_cid,
            type_byte(msg.msg_type(), flags),
            pn,
        );
        wire::encode_body(msg, &mut self.tx_buf, MAX_CONTROL_BODY);
        if sec.keys.send.seal(&mut self.tx_buf).is_err() {
            return false;
        }
        // To an address that has not shown it receives, only what is left
        // of what came from it: an ACK for data that came from elsewhere
        // would otherwise go to wherever a copied initiation said it came
        // from. (A skipped packet number is only a gap.)
        if to == self.peer && !self.peer_proven {
            let Some(left) = self.peer_allowance.checked_sub(self.tx_buf.len()) else {
                return false;
            };
            self.peer_allowance = left;
        }
        if let Err(e) = self.shared.send(to, &self.tx_buf) {
            if e.kind() != io::ErrorKind::WouldBlock {
                tracing::debug!("send {:?} failed: {}", msg.msg_type(), e);
            }
        }
        true
    }

    // ----- lifecycle -------------------------------------------------------

    /// Runs the session; returns its key when it ends.
    async fn run(mut self, mut rx: mpsc::Receiver<Incoming>) -> TransferKey {
        // The session was created for its first handshake.
        let decision = loop {
            match rx.recv().await {
                Some(Incoming::Handshake(h)) => {
                    if !self.let_go_first(&h.init.hello).await {
                        return self.key();
                    }
                    break self.start(*h);
                }
                Some(Incoming::Established(e)) => {
                    if !self.let_go_first(&e.hello).await {
                        return self.key();
                    }
                    break self.start_v4(*e);
                }
                Some(_) => {}
                None => return self.key(),
            }
        };
        let Some(mut decision) = decision else {
            return self.key();
        };

        let cancel = self.shared.cancel.clone();
        let release = self.holding.release.asked.clone();
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut progress = tokio::time::interval(self.cfg.progress_interval);
        progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            let ack_wait = self.next_ack_delay(Instant::now());
            tokio::select! {
                msg = rx.recv() => {
                    let Some(msg) = msg else {
                        self.stop(&mut rx, "dispatcher dropped the session").await;
                        return self.key();
                    };
                    if self.handle(msg).await.is_break() {
                        return self.key();
                    }
                    // Drain what is already queued before looking at timers.
                    for _ in 0..SESSION_BATCH {
                        let Ok(msg) = rx.try_recv() else { break };
                        if self.handle(msg).await.is_break() {
                            return self.key();
                        }
                    }
                }
                r = self.opening.rx.recv(), if self.opening.in_pool > 0 => {
                    if let Some(msg) = r {
                        self.opening.in_pool -= 1;
                        self.opening.ready.insert(msg.seq, msg);
                        if self.process_ready().await.is_break() {
                            return self.key();
                        }
                    }
                }
                accepted = decided(&mut decision) => {
                    decision = None;
                    if self.on_decision(accepted).is_break() {
                        return self.key();
                    }
                }
                _ = tokio::time::sleep(ack_wait.unwrap_or(Duration::from_secs(3600))), if ack_wait.is_some() => {
                    self.send_ack(Instant::now());
                }
                _ = tick.tick() => {
                    if self.housekeeping(Instant::now()).await.is_break() {
                        return self.key();
                    }
                }
                _ = progress.tick() => {
                    self.emit_progress(Instant::now());
                }
                _ = cancel.cancelled() => {
                    self.stop(&mut rx, "receiver shutting down").await;
                    return self.key();
                }
                _ = release.cancelled() => {
                    self.let_go(&mut rx).await;
                    return self.key();
                }
            }
        }
    }

    /// Before the transfer is decided on: if the partial data it would
    /// continue is held by another session of the same sender — the one
    /// the sender left when it was restarted without its resume state —
    /// asks that session to let go of it (see [`Session::let_go`]), and
    /// waits until it has, `RELEASE_WAIT` at most; [`Session::prepare`]
    /// refuses the transfer as busy if it has not by then. False when this
    /// session is to end instead: the receiver stops, or this session is
    /// asked to let go itself.
    async fn let_go_first(&mut self, hello: &Hello) -> bool {
        let deadline = tokio::time::Instant::now() + RELEASE_WAIT;
        loop {
            let Some(state) = self.saved_state(hello) else {
                return true;
            };
            let Held::Elsewhere(other) = self.holding.held(&state) else {
                return true;
            };
            tracing::info!(
                "transfer {} continues the partial data of transfer {} of the same sender; \
                 asking that one to let go",
                self.tid_hex(),
                hex16(&other.transfer)
            );
            other.release.ask(LET_GO_CONTINUED);
            tokio::select! {
                _ = other.released.cancelled() => {}
                _ = tokio::time::sleep_until(deadline) => return true,
                _ = self.holding.release.asked.cancelled() => return false,
                _ = self.shared.cancel.cancelled() => return false,
            }
        }
    }

    /// Lets go of the transfer when asked to (see [`Holder`]): by a session
    /// of the same sender that continues its partial data, or by the
    /// dispatcher, to make room for the sender's next transfer while this
    /// one is silent (see [`Dispatcher::room_for`]). Unlike
    /// [`Session::stop`] it leaves what the transfer that continues needs:
    /// one in progress is suspended, its partial file and state kept (or,
    /// if nothing came, dropped as it would be at `handshake_timeout`); one
    /// being verified is let finish; and the state of a result in place is
    /// left as it is — completing would forget it — for the transfer that
    /// continues to confirm the result from (Р22).
    async fn let_go(&mut self, rx: &mut mpsc::Receiver<Incoming>) {
        let why = self.holding.release.why();
        if matches!(self.phase, Phase::Verifying) {
            while let Some(msg) = rx.recv().await {
                if let Incoming::Verified(r) = msg {
                    let _ = self.on_verified(r);
                    break;
                }
            }
        }
        match &self.phase {
            Phase::Receiving if self.got_data => self.suspend(why).await,
            Phase::Receiving => self.abandon_idle(why).await,
            Phase::Finishing { .. } => {
                tracing::info!(
                    "transfer {}: {}; {} is in place, confirmed to whoever continues it",
                    self.tid_hex(),
                    why,
                    self.final_path.display()
                );
                self.emit_failed(format!("{}; the result is in place", why), true);
            }
            Phase::Pending { .. } => self.emit_failed(why.to_string(), false),
            // A verification that failed was reported as such, a refusal
            // when it was made.
            Phase::Verifying | Phase::Refusing { .. } => {}
        }
    }

    /// Ends the session from outside (shutdown): a transfer in progress is
    /// suspended for resume, a complete file is kept and reported as such.
    async fn stop(&mut self, rx: &mut mpsc::Receiver<Incoming>, why: &str) {
        match &self.phase {
            Phase::Verifying => {
                // Let the verification finish so the file ends up in place.
                while let Some(msg) = rx.recv().await {
                    if let Incoming::Verified(r) = msg {
                        match r {
                            Ok((hash, path)) => {
                                self.final_path = path;
                                self.complete(hash, false);
                            }
                            Err(e) => self.report_failure(e, true),
                        }
                        break;
                    }
                }
            }
            // The file is complete, verified and in place; only the sender's
            // confirmation is missing.
            Phase::Finishing { hash, .. } => {
                let hash = *hash;
                self.complete(hash, false);
            }
            Phase::Pending { .. } => self.emit_failed(why.to_string(), false),
            // Already reported when it was refused.
            Phase::Refusing { .. } => {}
            Phase::Receiving => self.suspend(why).await,
        }
    }

    async fn handle(&mut self, msg: Incoming) -> ControlFlow<()> {
        match msg {
            Incoming::Datagrams { runs, bytes, at } => self.on_delivery(runs, bytes, at).await,
            Incoming::Handshake(h) => {
                // The sender performed a new handshake (after an outage or a
                // restart): answer with our current state under new keys.
                self.last_rx = h.at;
                self.respond(*h);
                ControlFlow::Continue(())
            }
            Incoming::Established(e) => {
                // The same in version 4: the handshake was answered; its
                // HELLO follows, and is answered with our state.
                self.last_rx = e.at;
                self.take_keys(&e);
                ControlFlow::Continue(())
            }
            Incoming::FlushDone(result) => {
                self.on_flush_done(result);
                ControlFlow::Continue(())
            }
            Incoming::Verified(result) => self.on_verified(result),
        }
    }

    /// Decides on the transfer and answers its first handshake. Returns the
    /// pending decision (if the application has to decide), or `None` when
    /// the transfer was rejected.
    fn start(&mut self, h: Handshake) -> Option<Option<oneshot::Receiver<bool>>> {
        self.peer = h.from;
        self.peer_proven = false;
        self.peer_allowance = 0;
        self.last_rx = h.at;
        self.heard_peer_at = h.at;
        let hello = h.init.hello.clone();
        if let Err((reason, message)) = self.prepare(&hello) {
            self.reject_handshake(h, reason, &message);
            return None;
        }
        emit(
            &self.events,
            TransferEvent::IncomingRequest {
                transfer_id: self.tid_hex(),
                peer: self.peer.to_string(),
                sender_id: self.sender.to_string(),
                file_name: self.file_name.clone(),
                file_size: self.file_size,
                directory: self.directory(),
                resumed_bytes: self.received.total(),
            },
        );
        match self.shared.cfg.accept.clone() {
            AcceptPolicy::AcceptAll => {
                if let Err(message) = self.create_file() {
                    self.reject_handshake(h, REASON_INTERNAL, &message);
                    return None;
                }
                self.phase = Phase::Receiving;
                self.respond(h);
                self.on_accepted();
                Some(None)
            }
            AcceptPolicy::Ask(cb) => {
                let (tx, rx) = oneshot::channel();
                cb(
                    IncomingRequest {
                        transfer_id: self.tid_hex(),
                        peer: self.peer,
                        sender_id: self.sender,
                        file_name: self.file_name.clone(),
                        file_size: self.file_size,
                        directory: self.directory(),
                        resumed_bytes: self.received.total(),
                    },
                    tx,
                );
                self.phase = Phase::Pending {
                    deadline: Instant::now() + self.cfg.handshake_timeout,
                };
                self.respond(h);
                Some(Some(rx))
            }
        }
    }

    /// Starts the session of a version 4 handshake. The keys are in place
    /// and the handshake answered; its HELLO — `e.hello`, whose datagram
    /// comes next — is what the transfer is decided on. What is said back
    /// (accepted, waiting for the user, refused) goes in answer to that
    /// datagram, which is also what proves the sender's address.
    fn start_v4(&mut self, e: Established) -> Option<Option<oneshot::Receiver<bool>>> {
        self.peer = e.from;
        self.peer_proven = false;
        self.peer_allowance = e.len.saturating_sub(e.answered);
        self.last_rx = e.at;
        self.heard_peer_at = e.at;
        self.take_keys(&e);
        let hello = e.hello;
        let refuse = |this: &mut Self, reason: u8, message: String| {
            this.phase = Phase::Refusing {
                reason,
                message,
                until: Instant::now() + REFUSAL_WAIT,
            };
            Some(None)
        };
        if let Err((reason, message)) = self.prepare(&hello) {
            tracing::info!("rejected transfer from {}: {}", self.peer, message);
            return refuse(self, reason, message);
        }
        emit(
            &self.events,
            TransferEvent::IncomingRequest {
                transfer_id: self.tid_hex(),
                peer: self.peer.to_string(),
                sender_id: self.sender.to_string(),
                file_name: self.file_name.clone(),
                file_size: self.file_size,
                directory: self.directory(),
                resumed_bytes: self.received.total(),
            },
        );
        match self.shared.cfg.accept.clone() {
            AcceptPolicy::AcceptAll => {
                if let Err(message) = self.create_file() {
                    self.report_failure(message.clone(), false);
                    return refuse(self, REASON_INTERNAL, message);
                }
                self.phase = Phase::Receiving;
                self.on_accepted();
                Some(None)
            }
            AcceptPolicy::Ask(cb) => {
                let (tx, rx) = oneshot::channel();
                cb(
                    IncomingRequest {
                        transfer_id: self.tid_hex(),
                        peer: self.peer,
                        sender_id: self.sender,
                        file_name: self.file_name.clone(),
                        file_size: self.file_size,
                        directory: self.directory(),
                        resumed_bytes: self.received.total(),
                    },
                    tx,
                );
                self.phase = Phase::Pending {
                    deadline: Instant::now() + self.cfg.handshake_timeout,
                };
                Some(Some(rx))
            }
        }
    }

    /// Takes the keys of a version 4 handshake (the first, or one after an
    /// outage). A handshake from an address other than the session's is a
    /// claim like any other (see [`Session::respond`]).
    fn take_keys(&mut self, e: &Established) {
        let generation = self.secure.as_ref().map_or(1, |s| s.generation + 1);
        let fresh = self.secure.is_none();
        self.secure = Some(Secure {
            keys: e.keys.clone(),
            generation,
            local_cid: e.cid,
            peer_cid: e.peer_cid,
            next_pn: self.cfg.first_packet_number,
            replay: ReplayWindow::new(),
            auth_failures: 0,
        });
        if fresh {
            return;
        }
        self.path.reset();
        let credit = e.len.saturating_sub(e.answered);
        if e.from == self.peer {
            if !self.peer_proven {
                self.peer_allowance = self.peer_allowance.saturating_add(credit);
            }
        } else if let Some(c) = self.path.on_authentic(e.from, self.peer, e.at, credit, 0) {
            tracing::info!(
                "handshake from {} while the session is at {}; validating it",
                c.to,
                self.peer
            );
            self.send_to(
                c.to,
                0,
                &Message::PathChallenge(wire::PathChallenge { data: c.nonce }),
            );
        }
    }

    /// The application accepted or declined a pending transfer.
    fn on_decision(&mut self, accepted: bool) -> ControlFlow<()> {
        if !matches!(self.phase, Phase::Pending { .. }) {
            return ControlFlow::Continue(());
        }
        if !accepted {
            {
                let mut declined = self.shared.declined.lock();
                if declined.len() >= DECLINES_REMEMBERED {
                    if let Some(oldest) =
                        declined.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k)
                    {
                        declined.remove(&oldest);
                    }
                }
                declined.insert(self.key(), Instant::now());
            }
            self.emit_failed("declined by user".into(), false);
            return self.refuse(REASON_DECLINED, "declined by user");
        }
        if let Err(message) = self.create_file() {
            self.report_failure(message.clone(), false);
            return self.refuse(REASON_INTERNAL, &message);
        }
        self.phase = Phase::Receiving;
        // Tell the sender right away instead of at its next poll.
        let (ack, flags) = self.current_ack(0, SUPPORTED_CAPS, HOLES_BYTE_BUDGET);
        self.send(flags, &Message::HelloAck(ack));
        self.on_accepted();
        ControlFlow::Continue(())
    }

    fn directory(&self) -> Option<DirectoryInfo> {
        self.tree.as_ref().map(|t| DirectoryInfo {
            files: t.info.files,
            dirs: t.info.dirs,
        })
    }

    fn on_accepted(&mut self) {
        if self.receiving.is_none() {
            self.receiving = Some(Receiving::new(&self.shared));
        }
        let cipher = self
            .secure
            .as_ref()
            .map(|s| s.keys.suite.name())
            .unwrap_or("none");
        tracing::info!(
            "transfer {} from {} ({}): {}{} ({} bytes) -> {}, {}",
            self.tid_hex(),
            self.peer,
            self.sender,
            self.file_name,
            match &self.tree {
                Some(t) => format!(" ({} files, {} folders)", t.info.files, t.info.dirs),
                None => String::new(),
            },
            self.file_size,
            self.final_path.display(),
            cipher
        );
        emit(
            &self.events,
            TransferEvent::Started {
                transfer_id: self.tid_hex(),
                peer: self.peer.to_string(),
                peer_id: self.sender.to_string(),
                cipher: cipher.to_string(),
                file_name: self.file_name.clone(),
                file_size: self.file_size,
                directory: self.directory(),
                resumed_from: self.resumed_from,
                chunk_size: self.max_chunk,
            },
        );
        if self.received.total() >= self.file_size {
            self.begin_finishing();
        }
    }

    /// The resume state the transfer continues, if any: its own, by its
    /// transfer id, or else the newest of the same sender's for the same
    /// file — name, size and source modification time or, for a directory,
    /// the hash of its listing, so that a changed source starts afresh
    /// instead of failing the whole-transfer check at the very end. Only the
    /// sender that started a partial transfer may continue it.
    fn saved_state(&self, hello: &Hello) -> Option<ReceiverState> {
        let name = sanitize_file_name(&hello.file_name)?;
        let manifest_hex = hello
            .tree
            .map(|t| hash_to_hex(&t.manifest_hash))
            .unwrap_or_default();
        let sender = self.sender.to_string();
        let st = self.shared.store.as_ref()?;
        st.load_receiver(&self.tid_hex())
            .filter(|s| {
                s.sender == sender
                    && s.file_size == hello.file_size
                    && s.file_mtime == hello.file_mtime
                    && s.manifest_hash == manifest_hex
                    && s.data_path().exists()
            })
            .or_else(|| {
                st.find_receiver_by_file(
                    &sender,
                    &name,
                    hello.file_size,
                    hello.file_mtime,
                    &manifest_hex,
                )
            })
    }

    /// Validates the request and resolves resume state and paths. The file
    /// itself is created by [`Session::create_file`] once accepted.
    fn prepare(&mut self, hello: &Hello) -> Result<(), (u8, String)> {
        let Some(name) = sanitize_file_name(&hello.file_name) else {
            return Err((REASON_BAD_FILE_NAME, "file name is not acceptable".into()));
        };
        self.file_name = name.clone();
        self.file_size = hello.file_size;
        self.file_mtime = hello.file_mtime;
        self.max_chunk = hello.max_chunk.min(self.cfg.max_chunk).max(MIN_CHUNK);
        let out_dir = self.shared.cfg.output_dir.clone();
        if let Some(info) = hello.tree {
            if info.manifest_len > MAX_MANIFEST_LEN {
                return Err((
                    REASON_UNSUPPORTED,
                    format!(
                        "directory listing of {} bytes exceeds the limit of {}",
                        info.manifest_len, MAX_MANIFEST_LEN
                    ),
                ));
            }
            self.tree = Some(TreeRecv {
                info,
                buf: Vec::new(),
                plan: None,
                early: Vec::new(),
                early_bytes: 0,
                resume: false,
            });
        }
        let tid_hex = self.tid_hex();
        let saved = self.saved_state(hello);
        let mut durable = RangeSet::new();
        if let Some(saved) = &saved {
            // Never continue through a symbolic link someone put in place
            // of the partial data.
            let usable = match std::fs::symlink_metadata(saved.data_path()) {
                Ok(m) if self.tree.is_some() => m.is_dir(),
                Ok(m) => m.is_file() && m.len() == hello.file_size,
                Err(_) => false,
            };
            // A result already in place is finished from there; it needs
            // all of its bytes on record (and a directory its listing, kept
            // below), or it is left alone and the transfer starts afresh.
            let placed = saved.placed_hash();
            let usable = usable
                && (saved.placed.is_empty()
                    || placed.is_some() && saved.durable_set().total() >= hello.file_size);
            // Nor is what another session holds (see `Holder`): one of the
            // same sender that did not let go in time (see `let_go_first`),
            // or one of another sender's whose partial file has the name
            // this stale state remembers.
            let usable = usable
                && match self.holding.take(saved) {
                    Held::Free => true,
                    Held::Elsewhere(other) => {
                        tracing::info!(
                            "transfer {}: transfer {} of the same sender still holds the partial data",
                            tid_hex,
                            hex16(&other.transfer)
                        );
                        return Err((
                            REASON_BUSY,
                            "an earlier transfer of this file still holds it".into(),
                        ));
                    }
                    Held::Stale => {
                        tracing::warn!(
                            "{} belongs to another transfer now; not resuming from it",
                            saved.data_path().display()
                        );
                        false
                    }
                };
            if usable {
                durable = saved.durable_set();
                if let Some(tree) = &mut self.tree {
                    // A directory resumes with its listing, if that was
                    // kept; otherwise the sender sends it again.
                    let m = tree.info.manifest_len;
                    let kept = self
                        .shared
                        .store
                        .as_ref()
                        .and_then(|st| st.load_manifest(&saved.transfer_id))
                        .and_then(|bytes| {
                            let plan = verify_manifest(&bytes, &tree.info, hello.file_size).ok()?;
                            Some((Arc::new(plan), Arc::new(bytes)))
                        });
                    match kept {
                        Some(plan) => {
                            tree.plan = Some(plan);
                            durable.insert(0, m);
                        }
                        None => {
                            durable.remove(0, m);
                        }
                    }
                    tree.resume = true;
                }
                if placed.is_some() && durable.total() < hello.file_size {
                    // A directory in place whose listing was not kept: not
                    // to be written into again.
                    tracing::info!(
                        "{} is in place already, but its listing was not kept; receiving it anew",
                        saved.final_path.display()
                    );
                    durable = RangeSet::new();
                    if let Some(tree) = &mut self.tree {
                        tree.plan = None;
                        tree.resume = false;
                    }
                } else {
                    self.placed = placed;
                    self.part_path = saved.part_path.clone();
                    self.final_path = saved.final_path.clone();
                    tracing::info!(
                        "resuming {}: {} of {} bytes already on disk{}",
                        name,
                        durable.total(),
                        hello.file_size,
                        if placed.is_some() {
                            ", stored and awaiting the sender's confirmation"
                        } else {
                            ""
                        }
                    );
                }
                // The earlier transfer's state goes once this one's own is
                // kept (see `persist_state_now`), not before: a transfer
                // declined, or let go of before it is decided on, leaves the
                // partial data as resumable as it found it.
                if saved.transfer_id != tid_hex {
                    self.took_over = Some(saved.transfer_id.clone());
                }
            }
        }
        if self.part_path.as_os_str().is_empty() {
            let (tree, overwrite) = (self.tree.is_some(), self.shared.cfg.overwrite);
            let part_name = format!("{}{}", name, crate::file::PART_SUFFIX);
            let mut final_path = out_dir.join(&name);
            // A name another session has chosen for its partial file, and
            // not created yet, is as taken as one that is there.
            self.part_path = self.holding.choose_part(|theirs| {
                if tree {
                    // The final name is chosen when the tree is complete.
                    return tree::unique_dir_path_besides(&out_dir, &part_name, theirs);
                }
                if !overwrite {
                    final_path = unique_path(&out_dir, &name);
                }
                let part = part_path_for(&final_path);
                if part.exists() || theirs(&part) {
                    // An unrelated leftover, or another transfer's; do not
                    // clobber it.
                    return unique_path_besides(&out_dir, &part_name, theirs);
                }
                part
            });
            self.final_path = final_path;
        }

        let needed = hello.file_size.saturating_sub(durable.total());
        match available_space(&out_dir) {
            Ok(Some(avail)) if avail < needed.saturating_add(1 << 20) => {
                return Err((
                    REASON_DISK_SPACE,
                    format!("need {} bytes, {} available", needed, avail),
                ));
            }
            Ok(Some(_)) => {}
            Ok(None) => tracing::debug!(
                "{} does not say how much space it has; not checked",
                out_dir.display()
            ),
            Err(e) => tracing::warn!("cannot query free space: {}", e),
        }
        self.received = durable;
        self.highest = self.received.last_end().unwrap_or(0);
        self.resumed_from = self.received.total();
        Ok(())
    }

    /// Opens (creates or reopens) the partial file, or the staging
    /// directory of a directory transfer.
    fn create_file(&mut self) -> Result<(), String> {
        if self.placed.is_some() {
            // Nothing to write: the result is in place. Its state is kept
            // under this transfer's id (it may have been another's).
            self.persist_state_now();
            return Ok(());
        }
        if let Some(tree) = &self.tree {
            if !tree.resume {
                // Its name flushed with the output directory's, before any
                // state that describes what is inside it is kept.
                tree::create_private_dir(&self.part_path)
                    .and_then(|()| {
                        crate::file::durable::sync_dir(&crate::file::durable::parent_of(
                            &self.part_path,
                        ))
                    })
                    .map_err(|e| format!("cannot create {}: {}", self.part_path.display(), e))?;
            }
            if tree.plan.is_some() {
                self.open_tree_writer()?;
            }
            self.persist_state_now();
            return Ok(());
        }
        let writer = FileWriter::open(
            &self.part_path,
            self.file_size,
            self.cfg.writer_capacity_bytes,
        )
        .map_err(|e| format!("cannot open output file: {}", e))?;
        self.writer = Some(writer);
        self.persist_state_now();
        Ok(())
    }

    /// Starts the writer of a directory whose manifest is verified. It
    /// keeps a copy of the manifest with the resume state.
    fn open_tree_writer(&mut self) -> Result<(), String> {
        let tree = self.tree.as_ref().expect("directory transfer");
        let (plan, bytes) = tree.plan.clone().expect("verified manifest");
        if tree.resume {
            // A tree whose finishing was cut short — a crash between giving
            // its entries the sender's permissions and moving it into place —
            // may hold read-only files and closed directories, and every
            // resume of it failed writing into them. The permissions are
            // applied again when it is complete.
            tree::make_writable(&self.part_path, &plan)
                .map_err(|e| format!("cannot reopen {}: {}", self.part_path.display(), e))?;
        }
        let keep = self
            .shared
            .store
            .as_ref()
            .map(|st| (st.manifest_path(&self.tid_hex()), bytes));
        let writer = FileWriter::open_tree(
            self.part_path.clone(),
            plan,
            tree.resume,
            keep,
            self.cfg.writer_capacity_bytes,
        )
        .map_err(|e| format!("cannot start writing: {}", e))?;
        self.writer = Some(writer);
        Ok(())
    }

    /// The manifest of a directory is complete: verify it, start the writer
    /// and hand it what arrived early.
    fn manifest_complete(&mut self) -> Result<(), String> {
        let tree = self.tree.as_mut().expect("directory transfer");
        let bytes = std::mem::take(&mut tree.buf);
        let plan = verify_manifest(&bytes, &tree.info, self.file_size)?;
        tracing::info!(
            "transfer {}: directory listing verified ({} files, {} folders)",
            hex16(&self.transfer_id),
            plan.files(),
            plan.dirs()
        );
        tree.plan = Some((Arc::new(plan), Arc::new(bytes)));
        let early = std::mem::take(&mut tree.early);
        if !early.is_empty() {
            tracing::debug!(
                "{} B that arrived before the listing go to the writer now",
                tree.early_bytes
            );
        }
        tree.early_bytes = 0;
        self.open_tree_writer()?;
        let writer = self.writer.as_ref().expect("writer just opened");
        for (offset, data) in early {
            writer
                .enqueue(offset, data)
                .map_err(|_| "the writer cannot take the buffered data".to_string())?;
        }
        Ok(())
    }

    /// The HELLO_ACK describing our current state, its hole list held to
    /// `budget` bytes. Fewer holes is always safe: the ACK then describes a
    /// shorter stretch of the file, and the sender resends past its end.
    fn current_ack(&self, echo_ts: u32, offered_caps: u32, budget: usize) -> (HelloAck, u8) {
        let max_ack_delay_us = self.cfg.ack_interval.as_micros().min(u32::MAX as u128) as u32;
        if matches!(self.phase, Phase::Pending { .. }) {
            let ack = HelloAck {
                status: HELLO_PENDING,
                reason: REASON_NONE,
                max_chunk: self.max_chunk,
                capabilities: offered_caps & SUPPORTED_CAPS,
                echo_ts,
                max_ack_delay_us,
                rwnd: 0,
                resume_upto: 0,
                known_end: 0,
                holes: Vec::new(),
                message: String::new(),
            };
            return (ack, 0);
        }
        let contiguous = self.received.contiguous_from(0);
        let last = self.received.last_end().unwrap_or(0).max(contiguous);
        let (holes, known_end) =
            wire::describe_holes_within(&self.received, contiguous, last, budget);
        let ack = HelloAck {
            status: HELLO_ACCEPTED,
            reason: REASON_NONE,
            max_chunk: self.max_chunk,
            capabilities: offered_caps & SUPPORTED_CAPS,
            echo_ts,
            max_ack_delay_us,
            rwnd: self.rwnd(),
            resume_upto: contiguous,
            known_end,
            holes,
            message: String::new(),
        };
        let flags = if self.resumed_from > 0 {
            HELLO_ACK_FLAG_RESUMED
        } else {
            0
        };
        (ack, flags)
    }

    /// Answers a handshake with our current state and switches to its keys.
    fn respond(&mut self, h: Handshake) {
        let hello = &h.init.hello;
        // The answer goes to wherever the initiation came from, which
        // nobody has proven: a copy of an initiation sent from a forged
        // address would otherwise draw an answer five times its size at
        // whoever owns that address. So no more goes back than came in — a
        // resuming sender pads its initiation to 1200 bytes, which leaves
        // the answer room for the holes of what we hold.
        let budget = h.len.saturating_sub(RESPONSE_FIXED);
        let (ack, ack_flags) = self.current_ack(hello.timestamp, hello.capabilities, budget);
        let payload = wire::encode_response(&wire::Response {
            suite: h.suite as u8,
            ack_flags,
            ack,
        });
        if hs::RESPONSE_OVERHEAD + payload.len() > h.len {
            tracing::debug!(
                "initiation of {} bytes from {} not answered: the answer would be longer",
                h.len,
                h.from
            );
            return;
        }
        let sender_cid = h.incoming.sender_cid;
        match h.incoming.respond(h.cid, &payload) {
            Ok((pkt, split)) => {
                let generation = self.secure.as_ref().map_or(1, |s| s.generation + 1);
                self.secure = Some(Secure {
                    keys: Arc::new(SessionKeys::derive(&split, false, h.suite)),
                    generation,
                    local_cid: h.cid,
                    peer_cid: sender_cid,
                    next_pn: self.cfg.first_packet_number,
                    replay: ReplayWindow::new(),
                    auth_failures: 0,
                });
                // The answer goes where the question came from, always.
                if let Err(e) = self.shared.send(h.from, &pkt) {
                    tracing::debug!("sending handshake response failed: {}", e);
                }
                // What the initiation left over is what may follow the
                // answer there before the address is proven.
                if h.from == self.peer && !self.peer_proven {
                    self.peer_allowance = self
                        .peer_allowance
                        .saturating_add(h.len.saturating_sub(pkt.len()));
                }
                // A handshake from an address we have not proven does not
                // move the session there on its own: an on-path attacker
                // able to race our sender could otherwise re-send a captured
                // initiation with a forged source and point the session's
                // traffic at it. The new keys are in place now, so the
                // challenge is sent under them.
                self.path.reset();
                if h.from != self.peer {
                    // What the answer used of the address's allowance is
                    // not there to spend again on challenges.
                    let credit = h.len.saturating_sub(pkt.len());
                    if let Some(c) = self.path.on_authentic(h.from, self.peer, h.at, credit, 0) {
                        tracing::info!(
                            "handshake from {} while the session is at {}; validating it",
                            c.to,
                            self.peer
                        );
                        self.send_to(
                            c.to,
                            0,
                            &Message::PathChallenge(wire::PathChallenge { data: c.nonce }),
                        );
                    }
                }
            }
            Err(e) => tracing::warn!("cannot answer handshake: {}", e),
        }
    }

    /// Rejects the transfer in the handshake response (no session keys).
    fn reject_handshake(&mut self, h: Handshake, reason: u8, message: &str) {
        tracing::info!("rejected transfer from {}: {}", h.from, message);
        let Some(payload) = rejection_within(h.init.hello.timestamp, reason, message, h.len) else {
            return;
        };
        if let Ok((pkt, _)) = h.incoming.respond(h.cid, &payload) {
            let _ = self.shared.send(h.from, &pkt);
        }
    }

    /// Rejects the transfer over the established session.
    fn send_rejection(&mut self, reason: u8, message: &str) -> bool {
        tracing::info!("rejected transfer {}: {}", self.tid_hex(), message);
        let ack = rejection(0, reason, message);
        let mut went = false;
        for _ in 0..2 {
            went |= self.send(0, &Message::HelloAck(ack.clone()));
        }
        went
    }

    /// Refuses the transfer over the session, and ends the session once the
    /// refusal has gone — at once, or when the sender's address has proven
    /// itself (see [`Phase::Refusing`]).
    fn refuse(&mut self, reason: u8, message: &str) -> ControlFlow<()> {
        if self.send_rejection(reason, message) {
            return ControlFlow::Break(());
        }
        self.phase = Phase::Refusing {
            reason,
            message: message.to_string(),
            until: Instant::now() + REFUSAL_WAIT,
        };
        ControlFlow::Continue(())
    }

    /// Holes in `[from, to)`, complete for the (possibly shortened)
    /// interval they describe; see [`wire::describe_holes`].
    fn describe(&self, from: u64, to: u64) -> (Vec<(u64, u64)>, u64) {
        wire::describe_holes(&self.received, from, to)
    }

    fn rwnd(&self) -> u64 {
        if let Some(w) = &self.writer {
            // What the writer can take once the datagrams already queued
            // for this session are processed — and no more than this
            // session's share of the memory all transfers together may use.
            let share = self.shared.write_share().saturating_sub(w.queued_bytes());
            return w
                .available()
                .min(share)
                .min(self.unwritten.room())
                .saturating_sub(self.queued.load(Ordering::Relaxed));
        }
        if !matches!(self.phase, Phase::Receiving | Phase::Pending { .. }) {
            return 0;
        }
        match &self.tree {
            // Until the manifest is complete, data beyond it is buffered.
            Some(t) if t.plan.is_none() => self
                .cfg
                .writer_capacity_bytes
                .min(EARLY_MAX_BYTES)
                .min(self.shared.write_share())
                .saturating_sub(t.early_bytes),
            _ => self.shared.write_share(),
        }
    }

    /// Answers a HELLO frame (a state query or a decision poll).
    fn answer_hello(&mut self, hello: &Hello) {
        let (ack, flags) = self.current_ack(hello.timestamp, hello.capabilities, HOLES_BYTE_BUDGET);
        self.send(flags, &Message::HelloAck(ack));
    }

    // ----- packets ---------------------------------------------------------

    /// Datagrams from the dispatcher: decrypted on the crypto pool when
    /// there are many (the results are processed in order), otherwise right
    /// away.
    async fn on_delivery(
        &mut self,
        mut runs: Vec<Datagrams>,
        bytes: u64,
        at: Instant,
    ) -> ControlFlow<()> {
        let seq = self.opening.next_seq;
        self.opening.next_seq += 1;
        let count: usize = runs
            .iter()
            .map(|r| r.buf.len().div_ceil(r.stride.max(1)))
            .sum();
        match (&self.secure, parallel::pool()) {
            (Some(sec), Some(pool)) if count >= MIN_POOLED => {
                let (keys, cid, generation) = (sec.keys.clone(), sec.local_cid, sec.generation);
                let tx = self.opening.tx.clone();
                self.opening.in_pool += 1;
                pool.spawn(move || {
                    let opened = runs
                        .iter_mut()
                        .map(|r| open_datagrams(&keys.recv, cid, &mut r.buf, r.stride.max(1)))
                        .collect();
                    let _ = tx.send(OpenedDelivery {
                        seq,
                        generation,
                        runs,
                        opened,
                        bytes,
                        at,
                    });
                });
                ControlFlow::Continue(())
            }
            (secure, _) => {
                let generation = secure.as_ref().map_or(0, |s| s.generation);
                let opened = match secure {
                    Some(sec) => runs
                        .iter_mut()
                        .map(|r| {
                            open_datagrams(
                                &sec.keys.recv,
                                sec.local_cid,
                                &mut r.buf,
                                r.stride.max(1),
                            )
                        })
                        .collect(),
                    None => Vec::new(),
                };
                self.opening.ready.insert(
                    seq,
                    OpenedDelivery {
                        seq,
                        generation,
                        runs,
                        opened,
                        bytes,
                        at,
                    },
                );
                self.process_ready().await
            }
        }
    }

    /// Processes decrypted deliveries in the order they arrived.
    async fn process_ready(&mut self) -> ControlFlow<()> {
        while let Some(d) = self.opening.ready.remove(&self.opening.next_done) {
            self.opening.next_done += 1;
            self.queued.fetch_sub(d.bytes, Ordering::AcqRel);
            self.shared.give_queued(d.bytes);
            // Decrypted under keys that were replaced since: stale.
            if self.secure.as_ref().map(|s| s.generation) != Some(d.generation) {
                continue;
            }
            for (run, opened) in d.runs.into_iter().zip(d.opened) {
                if self.on_run(run, opened, d.at).await.is_break() {
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Handles the decrypted datagrams of one receive buffer. Their file
    /// data goes to the writer as one command; control frames are acted
    /// upon afterwards, so that nothing (a suspension, for one) can see data
    /// counted as received that is not queued for writing.
    async fn on_run(
        &mut self,
        run: Datagrams,
        opened: Vec<Opened>,
        at: Instant,
    ) -> ControlFlow<()> {
        let Datagrams { buf, stride, from } = run;
        let stride = stride.max(1);
        let len = buf.len();
        let mut pieces = Pieces::default();
        let mut controls = Vec::new();
        let mut fatal = None;
        for (k, opened) in opened.into_iter().enumerate() {
            let start = k * stride;
            let range = start..(start + stride).min(len);
            let (tb, pn) = match opened {
                Opened::Stale => continue,
                Opened::Forged => {
                    if let Some(sec) = &mut self.secure {
                        sec.auth_failures += 1;
                    }
                    continue;
                }
                Opened::Ok(tb, pn) => (tb, pn),
            };
            if let Err(msg) =
                self.on_opened(&buf, range, tb, pn, from, at, &mut pieces, &mut controls)
            {
                fatal = Some(msg);
                break;
            }
        }
        self.commit(buf, pieces);
        if let Some(msg) = fatal {
            self.abandon(msg).await;
            return ControlFlow::Break(());
        }
        for c in controls {
            if self.on_control(c).await.is_break() {
                return ControlFlow::Break(());
            }
        }
        if matches!(self.phase, Phase::Receiving) {
            if self.received.total() >= self.file_size {
                self.send_ack(at);
                self.begin_finishing();
            } else if self.pkts_since_ack >= self.cfg.ack_every_packets {
                self.send_ack(at);
            }
        }
        ControlFlow::Continue(())
    }

    /// Handles an authentic datagram at `range` of `buf`. DATA is recorded
    /// right away (its payload position joins `pieces`); control frames are
    /// collected. An error ends the transfer for good (a directory listing
    /// that fails verification).
    #[allow(clippy::too_many_arguments)]
    fn on_opened(
        &mut self,
        buf: &[u8],
        range: std::ops::Range<usize>,
        tb: u8,
        pn: u64,
        from: SocketAddr,
        at: Instant,
        pieces: &mut Pieces,
        controls: &mut Vec<Control>,
    ) -> Result<(), String> {
        let Some(sec) = self.secure.as_mut() else {
            return Ok(());
        };
        if !sec.replay.accept(pn) {
            return Ok(());
        }
        let Ok((msg_type, flags)) = parse_type_byte(tb) else {
            return Ok(());
        };
        // A challenge is answered where it came from, and that answer is
        // part of what the address may be sent (see `PathProbe::on_authentic`).
        let answer = if msg_type == MsgType::PathChallenge {
            crate::transport::path::CHALLENGE_BYTES
        } else {
            0
        };
        self.note_alive(from, at, range.len(), answer);
        let body = range.start + HEADER_LEN..range.end - TAG_LEN;
        if msg_type != MsgType::Data {
            controls.push(Control {
                msg_type,
                body: buf[body].to_vec(),
                datagram_len: range.len(),
                from,
            });
            return Ok(());
        }
        if body.len() < DATA_FIXED_LEN {
            return Ok(());
        }
        let b = body.start;
        let offset = u64::from_be_bytes(buf[b..b + 8].try_into().unwrap());
        let ts = u32::from_be_bytes(buf[b + 8..b + 12].try_into().unwrap());
        let payload = b + DATA_FIXED_LEN..body.end;
        if flags & DATA_FLAG_RETRANSMIT != 0 {
            self.retransmitted_bytes += payload.len() as u64;
        }
        self.on_data(offset, ts, buf, payload, at, pieces)
    }

    /// Something authentic arrived from the sender.
    ///
    /// Whether `to` is passed over for now: a worse path than the one the
    /// session runs on, while the sender was heard there lately (see
    /// [`crate::transport::path::DIRECT_GRACE`]).
    fn keeps_direct(&self, to: SocketAddr, now: Instant) -> bool {
        crate::transport::path::keeps_direct(
            self.shared.standing(to),
            self.shared.standing(self.peer),
            now.saturating_duration_since(self.heard_peer_at),
        )
    }

    /// An authentic packet from an address we have not proven does *not*
    /// move the transfer there: it only makes us ask. See
    /// [`crate::transport::path`] — an attacker that repeats a captured
    /// packet with a forged source address must not be able to point our
    /// ACKs (and, on the sending side, the data stream) at a third party.
    fn note_alive(&mut self, from: SocketAddr, at: Instant, len: usize, answer: usize) {
        self.last_rx = at;
        if from == self.peer {
            self.heard_peer_at = at;
        }
        // A transport packet from the address the handshake came from proves
        // that address: it takes the keys our answer to the handshake made,
        // and the answer went there. (The handshake alone proves nothing
        // of where it came from: a copy may have had its source forged.)
        if from == self.peer {
            self.peer_proven = true;
            #[cfg(feature = "nat-traversal")]
            self.met_directly();
        }
        if self.stalled {
            self.stalled = false;
            emit(
                &self.events,
                TransferEvent::Recovered {
                    transfer_id: self.tid_hex(),
                },
            );
        }
        // Through a server while the direct path is heard from: the sender
        // catching up, not moving (see `path::DIRECT_GRACE`).
        let held = from != self.peer && self.keeps_direct(from, at);
        if let Some(c) = (!held)
            .then(|| self.path.on_authentic(from, self.peer, at, len, answer))
            .flatten()
        {
            tracing::info!(
                "sender claims address {} (was {}); validating it",
                c.to,
                self.peer
            );
            self.send_to(
                c.to,
                0,
                &Message::PathChallenge(wire::PathChallenge { data: c.nonce }),
            );
        }
    }

    /// The session runs at a proven address of the sender now: the punching
    /// at that host for a meeting has done its work (see [`Shared::met`]).
    #[cfg(feature = "nat-traversal")]
    fn met_directly(&mut self) {
        if self.met_at != Some(self.peer) {
            self.met_at = Some(self.peer);
            self.shared.met(&self.sender, self.peer);
        }
    }

    /// Repeats unanswered address challenges, or gives claims up.
    fn poll_path(&mut self, now: Instant) {
        for c in self.path.poll(now, PATH_RETRY) {
            self.send_to(
                c.to,
                0,
                &Message::PathChallenge(wire::PathChallenge { data: c.nonce }),
            );
        }
    }

    /// Queues the file data of one receive buffer for writing. Should the
    /// writer refuse it after all, it is not received.
    fn commit(&mut self, buf: Vec<u8>, pieces: Pieces) {
        if pieces.list.is_empty() {
            self.publish_unwritten();
            return;
        }
        let refused = match &self.writer {
            Some(w) => w.enqueue_pieces(buf, pieces.list).err(),
            None => Some(pieces.list),
        };
        if let Some(list) = refused {
            for &(s, _, len) in &list {
                self.received.remove(s, s + len as u64);
            }
            self.writer_full_drops += list.len() as u64;
        }
        self.publish_unwritten();
    }

    /// Tells the receiver-wide count what we hold that is not on disk yet:
    /// what the writer has queued, or the directory data held back for the
    /// manifest.
    fn publish_unwritten(&mut self) {
        let writer = self.writer.as_ref().map_or(0, |w| w.queued_bytes());
        let early = self.tree.as_ref().map_or(0, |t| t.early_bytes);
        self.unwritten.publish(writer + early);
    }

    async fn on_control(&mut self, c: Control) -> ControlFlow<()> {
        let decoded = match wire::decode_body(c.msg_type, &c.body) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("malformed {:?}: {}", c.msg_type, e);
                return ControlFlow::Continue(());
            }
        };
        match decoded {
            Message::Hello(h) => {
                if h.transfer_id == self.transfer_id {
                    // The sender asking again is the sender proving its
                    // address: a refusal that had to wait goes now.
                    if let Phase::Refusing {
                        reason, message, ..
                    } = &self.phase
                    {
                        let (reason, message) = (*reason, message.clone());
                        if self.send_rejection(reason, &message) {
                            return ControlFlow::Break(());
                        }
                        return ControlFlow::Continue(());
                    }
                    self.answer_hello(&h);
                }
            }
            Message::Ping(p) => {
                self.send(0, &Message::Pong(Pong { echo: p.timestamp }));
            }
            Message::Probe(_) => {
                let size = c.datagram_len.min(u16::MAX as usize) as u16;
                self.send(0, &Message::ProbeAck(ProbeAck { size }));
            }
            // The sender is validating an address of ours: echo the token
            // back from the address it challenged, and nowhere else.
            Message::PathChallenge(p) => {
                self.send_to(
                    c.from,
                    0,
                    &Message::PathResponse(wire::PathResponse { data: p.data }),
                );
            }
            Message::PathResponse(p) => {
                let now = Instant::now();
                if let Some(addr) = self
                    .path
                    .on_response(c.from, p.data)
                    .filter(|a| !self.keeps_direct(*a, now))
                {
                    tracing::info!("sender address {} proven; moving the session there", addr);
                    self.peer = addr;
                    self.peer_proven = true;
                    self.heard_peer_at = now;
                    #[cfg(feature = "nat-traversal")]
                    self.met_directly();
                }
            }
            Message::FinAck(f) => {
                if let Phase::Finishing { hash, .. } = &self.phase {
                    let hash = *hash;
                    // Lets the sender exit now instead of lingering for a
                    // repeated FIN; if this is lost, it lingers as before.
                    self.send(0, &Message::FinDone(wire::FinDone { verdict: f.verdict }));
                    if f.verdict == VERDICT_OK {
                        self.complete(hash, true);
                    } else {
                        self.fail_mismatch(hash, f.file_hash);
                    }
                    return ControlFlow::Break(());
                }
            }
            Message::Abort(a) => {
                tracing::warn!(
                    "sender aborted transfer {}: {} ({})",
                    self.tid_hex(),
                    a.reason,
                    a.code
                );
                let why = format!("aborted by sender: {}", a.reason);
                match self.phase {
                    Phase::Receiving => {
                        if self.got_data {
                            self.suspend(&why).await;
                        } else {
                            self.abandon_idle(&why).await;
                        }
                        return ControlFlow::Break(());
                    }
                    Phase::Pending { .. } => {
                        self.emit_failed(why, false);
                        return ControlFlow::Break(());
                    }
                    Phase::Refusing { .. } => return ControlFlow::Break(()),
                    Phase::Verifying | Phase::Finishing { .. } => {}
                }
            }
            Message::Data(_)
            | Message::HelloAck(_)
            | Message::Ack(_)
            | Message::Fin(_)
            | Message::Pong(_)
            | Message::ProbeAck(_)
            | Message::FinDone(_) => {}
        }
        ControlFlow::Continue(())
    }

    /// Handles a DATA payload `buf[payload]` for stream offset `offset`.
    fn on_data(
        &mut self,
        offset: u64,
        ts: u32,
        buf: &[u8],
        payload: std::ops::Range<usize>,
        at: Instant,
        pieces: &mut Pieces,
    ) -> Result<(), String> {
        if !matches!(self.phase, Phase::Receiving) {
            return Ok(());
        }
        let len = payload.len();
        let len64 = len as u64;
        let end = match offset.checked_add(len64) {
            Some(end) if len > 0 && len64 <= MAX_CHUNK as u64 && end <= self.file_size => end,
            _ => {
                tracing::debug!("ignoring DATA outside file: offset {} len {}", offset, len);
                return Ok(());
            }
        };
        // Past the cap, only data that extends or joins what is here. The
        // start of the file counts as something to join, or a transfer
        // whose first bytes were lost could never get them back.
        if self.received.len() >= MAX_RECEIVED_RANGES
            && offset > 0
            && self.received.would_add_range(offset, end)
        {
            self.fragment_drops += 1;
            return Ok(());
        }
        let prev_highest = self.highest;
        // The manifest of a directory is collected in memory; the rest of
        // the payload (if any) is file data.
        let (mut data_off, mut data) = (offset, payload.clone());
        let mut manifest_done = false;
        if let Some(tree) = &mut self.tree {
            let m = tree.info.manifest_len;
            if offset < m {
                let m_end = end.min(m);
                if tree.plan.is_none() {
                    for (s, e) in self.received.holes(offset, m_end, usize::MAX) {
                        if tree.buf.len() < e as usize {
                            tree.buf.resize(e as usize, 0);
                        }
                        let a = payload.start + (s - offset) as usize;
                        tree.buf[s as usize..e as usize]
                            .copy_from_slice(&buf[a..a + (e - s) as usize]);
                        self.received.insert(s, e);
                        self.got_data = true;
                    }
                    manifest_done = self.received.contains(0, m);
                }
                data.start += (m_end - offset) as usize;
                data_off = m_end;
            }
        }
        if !data.is_empty() && !self.store_data(data_off, buf, data, pieces) {
            // Saturated: treated as not received; the shrinking receive
            // window slows the sender down.
            return Ok(());
        }
        if manifest_done {
            self.manifest_complete()?;
        }
        self.highest = self.highest.max(end);
        self.last_data_ts = ts;
        self.last_data_at = at;
        self.pkts_since_ack += 1;
        if offset > prev_highest && self.immediate_ack_at.is_none() {
            // A gap appeared: ACK soon so the sender can retransmit quickly,
            // but leave a moment for reordered packets to arrive.
            self.immediate_ack_at = Some(at + Duration::from_millis(2));
        }
        Ok(())
    }

    /// Records file data `buf[data]` for stream offset `offset`: what is
    /// new joins `pieces` for the writer (or, while a directory's manifest
    /// is incomplete, the early buffer). Returns false when it had to be
    /// dropped because the writer is saturated.
    fn store_data(
        &mut self,
        offset: u64,
        buf: &[u8],
        data: std::ops::Range<usize>,
        pieces: &mut Pieces,
    ) -> bool {
        let end = offset + data.len() as u64;
        let missing = self.received.holes(offset, end, usize::MAX);
        if missing.is_empty() {
            return true;
        }
        let need: u64 = missing.iter().map(|&(s, e)| e - s).sum();
        if let Some(writer) = &self.writer {
            // Within the writer's capacity, and within this session's share
            // of the memory budget: a sender that ignores the window it is
            // given gets no more room for doing so.
            let holding = writer.queued_bytes() + pieces.bytes + need;
            if writer.available() < pieces.bytes + need
                || holding > self.shared.write_share()
                || !self.unwritten.claim(holding)
            {
                self.writer_full_drops += 1;
                return false;
            }
            // Usually the whole payload; after a chunk-size change only the
            // sub-ranges not received before.
            for (s, e) in missing {
                pieces
                    .list
                    .push((s, data.start + (s - offset) as usize, (e - s) as usize));
                self.received.insert(s, e);
            }
            pieces.bytes += need;
        } else if let Some(tree) = self.tree.as_mut().filter(|t| t.plan.is_none()) {
            // The manifest is not complete yet: hold the data until the
            // writer knows which files it belongs to.
            let cap = self
                .cfg
                .writer_capacity_bytes
                .min(EARLY_MAX_BYTES)
                .min(self.shared.write_share());
            if tree.early_bytes + need > cap
                || tree.early.len() + missing.len() > EARLY_MAX_ITEMS
                || !self.unwritten.claim(tree.early_bytes + need)
            {
                self.writer_full_drops += 1;
                return false;
            }
            for &(s, e) in &missing {
                let a = data.start + (s - offset) as usize;
                tree.early.push((s, buf[a..a + (e - s) as usize].to_vec()));
            }
            tree.early_bytes += need;
            for (s, e) in missing {
                self.received.insert(s, e);
            }
        } else {
            return false;
        }
        self.persist_dirty = true;
        self.got_data = true;
        true
    }

    fn next_ack_delay(&self, now: Instant) -> Option<Duration> {
        if !matches!(self.phase, Phase::Receiving) {
            return None;
        }
        let mut deadline: Option<Instant> = self.immediate_ack_at;
        if self.pkts_since_ack > 0 {
            let t = self.last_ack_at + self.cfg.ack_interval;
            deadline = Some(deadline.map_or(t, |d| d.min(t)));
        }
        // Holes below the highest offset: keep reporting them so that lost
        // retransmissions are requested again even when no new data arrives.
        if self.received.contiguous_from(0) < self.highest {
            let t = self.last_ack_at + Duration::from_millis(200);
            deadline = Some(deadline.map_or(t, |d| d.min(t)));
        }
        deadline.map(|d| d.saturating_duration_since(now))
    }

    fn send_ack(&mut self, now: Instant) {
        let contiguous = self.received.contiguous_from(0);
        let (holes, described) = self.describe(contiguous, self.highest.max(contiguous));
        let ack_delay_us = if self.last_data_ts != 0 {
            now.saturating_duration_since(self.last_data_at)
                .as_micros()
                .min(u32::MAX as u128) as u32
        } else {
            0
        };
        let ack = Ack {
            contiguous_upto: contiguous,
            highest: described,
            received_bytes: self.received.total(),
            echo_ts: self.last_data_ts,
            ack_delay_us,
            rwnd: self.rwnd(),
            holes,
        };
        self.send(0, &Message::Ack(ack));
        self.pkts_since_ack = 0;
        self.last_ack_at = now;
        self.immediate_ack_at = None;
        // Echo each timestamp once: a later ACK must not reuse it, otherwise
        // the sender would compute an inflated RTT.
        self.last_data_ts = 0;
    }

    // ----- persistence -----------------------------------------------------

    fn state(&self, durable: &RangeSet) -> ReceiverState {
        ReceiverState {
            format: 0,
            transfer_id: self.tid_hex(),
            file_name: self.file_name.clone(),
            file_size: self.file_size,
            file_mtime: self.file_mtime,
            part_path: self.part_path.clone(),
            final_path: self.final_path.clone(),
            peer: self.peer.to_string(),
            sender: self.sender.to_string(),
            manifest_hash: self
                .tree
                .as_ref()
                .map(|t| hash_to_hex(&t.info.manifest_hash))
                .unwrap_or_default(),
            manifest_len: self.tree.as_ref().map_or(0, |t| t.info.manifest_len),
            durable: durable.to_vec(),
            updated_unix: 0,
            placed: self.placed.map(|h| hash_to_hex(&h)).unwrap_or_default(),
        }
    }

    /// Persists `received` as durable. Only valid when everything in it is
    /// known to be on disk (right after open, or after the writer closed).
    fn persist_state_now(&mut self) {
        if let Some(store) = &self.shared.store {
            match store.save_receiver(&self.state(&self.received)) {
                // The state of the transfer this one continues is this
                // one's now (see `prepare`).
                Ok(()) => {
                    if let Some(earlier) = self.took_over.take() {
                        store.remove_receiver(&earlier);
                    }
                }
                Err(e) => tracing::warn!("cannot save resume state: {}", e),
            }
        }
        self.last_persist_at = Instant::now();
        self.persist_dirty = false;
    }

    fn request_flush(&mut self) {
        let Some(writer) = &self.writer else { return };
        let rx = writer.flush();
        self.flush_in_progress = true;
        self.flush_snapshot = Some(self.received.clone());
        self.persist_dirty = false;
        let tx = self.self_tx.clone();
        tokio::spawn(async move {
            let result = match rx.await {
                Ok(r) => r,
                Err(_) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "writer gone")),
            };
            let _ = tx.send(Incoming::FlushDone(result)).await;
        });
    }

    fn on_flush_done(&mut self, result: io::Result<()>) {
        self.flush_in_progress = false;
        let snapshot = self.flush_snapshot.take();
        match (result, snapshot) {
            (Ok(()), Some(snapshot)) => {
                if matches!(self.phase, Phase::Receiving) {
                    if let Some(store) = &self.shared.store {
                        if let Err(e) = store.save_receiver(&self.state(&snapshot)) {
                            tracing::warn!("cannot save resume state: {}", e);
                        }
                    }
                }
                self.last_persist_at = Instant::now();
            }
            (Err(e), _) => tracing::warn!("fsync failed: {}", e),
            _ => {}
        }
    }

    // ----- housekeeping ----------------------------------------------------

    async fn housekeeping(&mut self, now: Instant) -> ControlFlow<()> {
        // The writer drains in the background; say so, or the count would
        // only ever go down when more data arrives.
        self.publish_unwritten();
        let since_rx = now.saturating_duration_since(self.last_rx);
        self.poll_path(now);
        if let Some((kind, error)) = self.writer.as_ref().and_then(|w| w.error()) {
            let msg = format!("cannot write: {}", error);
            if kind == io::ErrorKind::AlreadyExists {
                // Entries of the directory collide here; no retry can help.
                self.abandon(msg).await;
            } else {
                self.send(
                    0,
                    &Message::Abort(wire::Abort {
                        code: ABORT_IO_ERROR,
                        reason: msg.clone(),
                    }),
                );
                self.suspend(&msg).await;
            }
            return ControlFlow::Break(());
        }
        match &mut self.phase {
            Phase::Receiving => {
                if self.persist_dirty
                    && !self.flush_in_progress
                    && now.saturating_duration_since(self.last_persist_at)
                        >= self.cfg.persist_interval
                {
                    self.request_flush();
                }
            }
            Phase::Finishing {
                hash,
                next_fin_at,
                fin_delay,
                started_at,
            } => {
                let hash = *hash;
                let waited = now.saturating_duration_since(*started_at);
                // The file is complete and verified locally; stop waiting for
                // the sender's verdict once it has gone quiet (or after the
                // overall limit). Its silence is counted from the first FIN:
                // it had nothing to say while the file was being verified.
                let quiet = waited.min(since_rx);
                if quiet >= self.cfg.stall_timeout || waited >= self.cfg.give_up_timeout {
                    tracing::warn!("no FIN_ACK from sender; file is complete and verified locally");
                    self.complete(hash, false);
                    return ControlFlow::Break(());
                }
                if now >= *next_fin_at {
                    *fin_delay = (*fin_delay * 2).min(Duration::from_secs(3));
                    *next_fin_at = now + *fin_delay;
                    self.send(0, &Message::Fin(Fin { file_hash: hash }));
                }
                return ControlFlow::Continue(());
            }
            Phase::Pending { deadline } => {
                if now >= *deadline {
                    self.emit_failed("no decision in time".into(), false);
                    return self.refuse(REASON_TIMEOUT, "no decision in time");
                }
                return ControlFlow::Continue(());
            }
            Phase::Refusing { until, .. } => {
                if now >= *until {
                    return ControlFlow::Break(());
                }
                return ControlFlow::Continue(());
            }
            Phase::Verifying => return ControlFlow::Continue(()),
        }

        if since_rx >= self.cfg.stall_timeout && !self.stalled {
            self.stalled = true;
            tracing::warn!("no packets from {} for {:?}", self.peer, since_rx);
            emit(
                &self.events,
                TransferEvent::Stalled {
                    transfer_id: self.tid_hex(),
                    since: since_rx,
                },
            );
            if !self.flush_in_progress {
                self.request_flush();
            }
        }
        // A session that never received data (sender vanished right after
        // the handshake, or a spoofed HELLO) must not hold a slot for long.
        if !self.got_data && since_rx >= self.cfg.handshake_timeout {
            self.abandon_idle("sender sent no data after the handshake")
                .await;
            return ControlFlow::Break(());
        }
        if since_rx >= self.cfg.session_ttl {
            self.suspend("sender silent for too long").await;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    /// Ends a session that received no data. A partial file created for it
    /// is removed; one resumed from an earlier attempt is kept for resume.
    async fn abandon_idle(&mut self, why: &str) {
        if self.resumed_from > 0 {
            self.suspend(why).await;
            return;
        }
        tracing::info!(
            "transfer {} from {}: {}; dropping the empty session",
            self.tid_hex(),
            self.peer,
            why
        );
        if let Some(writer) = self.writer.take() {
            let _ = writer.close().await;
        }
        let _ = tree::remove_partial(&self.part_path);
        if let Some(store) = &self.shared.store {
            store.remove_receiver(&self.tid_hex());
        }
        self.emit_failed(why.to_string(), false);
    }

    /// Ends a transfer that cannot succeed (a directory listing that fails
    /// verification, colliding names): tells the sender and removes the
    /// partial data together with its resume state.
    async fn abandon(&mut self, msg: String) {
        self.send(
            0,
            &Message::Abort(wire::Abort {
                code: ABORT_IO_ERROR,
                reason: msg.clone(),
            }),
        );
        if let Some(writer) = self.writer.take() {
            let _ = writer.close().await;
        }
        if let Some(store) = &self.shared.store {
            store.remove_receiver(&self.tid_hex());
        }
        let _ = tree::remove_partial(&self.part_path);
        self.report_failure(msg, false);
    }

    // ----- completion ------------------------------------------------------

    fn begin_finishing(&mut self) {
        if !matches!(self.phase, Phase::Receiving) {
            return;
        }
        if let Some(hash) = self.placed {
            self.check_placed(hash);
            return;
        }
        let Some(writer) = self.writer.take() else {
            return;
        };
        self.phase = Phase::Verifying;
        tracing::info!(
            "transfer {}: all {} bytes received; verifying",
            self.tid_hex(),
            self.file_size
        );
        let part = self.part_path.clone();
        let final_path = self.final_path.clone();
        let overwrite = self.shared.cfg.overwrite;
        let plan = self.tree.as_ref().and_then(|t| t.plan.clone());
        let tx = self.self_tx.clone();
        // Once the writer has flushed everything, the resume state says so:
        // a crash while the result is verified and moved into place then
        // resumes with every byte already there, instead of from the last
        // state kept during the transfer.
        let (shared, state) = (self.shared.clone(), self.state(&self.received));
        let (keep, mut stored) = (shared.clone(), state.clone());
        let all_on_disk = move || {
            if let Some(store) = &shared.store {
                if let Err(e) = store.save_receiver(&state) {
                    tracing::warn!("cannot save resume state: {}", e);
                }
            }
        };
        // And once the result is in place, that it is, with its hash: a
        // crash or a lost connection before the sender confirms it then
        // finishes from there (Р22).
        let placed = move |target: &Path, hash: &[u8; 32]| {
            if let Some(store) = &keep.store {
                stored.final_path = target.to_path_buf();
                stored.placed = hash_to_hex(hash);
                if let Err(e) = store.save_receiver(&stored) {
                    tracing::warn!("cannot save resume state: {}", e);
                }
            }
        };
        tokio::spawn(async move {
            let result = match plan {
                Some((plan, bytes)) => {
                    finish_tree(writer, part, final_path, plan, bytes, all_on_disk, placed).await
                }
                None => finish_file(writer, part, final_path, overwrite, all_on_disk, placed).await,
            };
            let _ = tx.send(Incoming::Verified(result)).await;
        });
    }

    /// Finishes a transfer whose result was in place before: if it is still
    /// what was stored, the sender is told so as if it had just been;
    /// otherwise — changed since, by its owner most likely — it is left
    /// alone and the transfer is forgotten, to start afresh when the sender
    /// tries again.
    fn check_placed(&mut self, hash: [u8; 32]) {
        self.phase = Phase::Verifying;
        tracing::info!(
            "transfer {}: {} is in place already; checking it is still what was stored",
            self.tid_hex(),
            self.final_path.display()
        );
        let path = self.final_path.clone();
        let plan = self.tree.as_ref().and_then(|t| t.plan.clone());
        let (shared, tid, tx) = (self.shared.clone(), self.tid_hex(), self.self_tx.clone());
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let now = match &plan {
                    Some((plan, bytes)) => tree::hash_tree(&path, plan, bytes),
                    None => hash_file(&path),
                };
                if now.as_ref().is_ok_and(|h| *h == hash) {
                    return Ok((hash, path));
                }
                if let Some(store) = &shared.store {
                    store.remove_receiver(&tid);
                }
                Err(format!(
                    "{} changed after it was stored; it is left as it is, and sending again \
                     receives the transfer anew",
                    path.display()
                ))
            })
            .await
            .unwrap_or_else(|e| Err(format!("hash task failed: {}", e)));
            let _ = tx.send(Incoming::Verified(result)).await;
        });
    }

    fn on_verified(&mut self, result: Result<([u8; 32], PathBuf), String>) -> ControlFlow<()> {
        if !matches!(self.phase, Phase::Verifying) {
            return ControlFlow::Continue(());
        }
        match result {
            Ok((hash, path)) => {
                self.final_path = path;
                self.placed = Some(hash);
                let now = Instant::now();
                tracing::info!(
                    "transfer {} stored as {} (BLAKE3 {}); confirming with sender",
                    self.tid_hex(),
                    self.final_path.display(),
                    hash_to_hex(&hash)
                );
                self.send(0, &Message::Fin(Fin { file_hash: hash }));
                self.phase = Phase::Finishing {
                    hash,
                    next_fin_at: now + Duration::from_millis(200),
                    fin_delay: Duration::from_millis(200),
                    started_at: now,
                };
                ControlFlow::Continue(())
            }
            Err(msg) => {
                self.send(
                    0,
                    &Message::Abort(wire::Abort {
                        code: ABORT_IO_ERROR,
                        reason: msg.clone(),
                    }),
                );
                self.report_failure(msg, true);
                ControlFlow::Break(())
            }
        }
    }

    fn complete(&mut self, hash: [u8; 32], peer_confirmed: bool) {
        // Everything is on disk: nothing of the budget is ours any more.
        self.receiving = None;
        if let Some(store) = &self.shared.store {
            store.remove_receiver(&self.tid_hex());
        }
        let stats = self.stats(Instant::now());
        tracing::info!(
            "transfer {} finished{}: {} in {:.2?}, avg {:.1} Mbit/s",
            self.tid_hex(),
            if peer_confirmed {
                ""
            } else {
                " (unconfirmed by sender)"
            },
            self.final_path.display(),
            stats.elapsed,
            stats.avg_rate_bps / 1e6
        );
        emit(
            &self.events,
            TransferEvent::Completed {
                transfer_id: self.tid_hex(),
                file_name: self.file_name.clone(),
                path: Some(self.final_path.display().to_string()),
                file_hash_hex: hash_to_hex(&hash),
                peer_confirmed,
                stats,
            },
        );
    }

    fn fail_mismatch(&mut self, ours: [u8; 32], theirs: [u8; 32]) {
        if let Some(store) = &self.shared.store {
            store.remove_receiver(&self.tid_hex());
        }
        let msg = format!(
            "whole-file hash mismatch: receiver {}, sender {}",
            hash_to_hex(&ours),
            hash_to_hex(&theirs)
        );
        tracing::error!("transfer {}: {}", self.tid_hex(), msg);
        let bad = {
            let mut s = self.final_path.as_os_str().to_owned();
            s.push(".mismatch");
            PathBuf::from(s)
        };
        let _ = std::fs::rename(&self.final_path, &bad);
        self.report_failure(msg, false);
    }

    fn report_failure(&self, error: String, resumable: bool) {
        tracing::error!("transfer {}: {}", self.tid_hex(), error);
        self.emit_failed(error, resumable);
    }

    fn emit_failed(&self, error: String, resumable: bool) {
        emit(
            &self.events,
            TransferEvent::Failed {
                transfer_id: self.tid_hex(),
                error,
                resumable,
            },
        );
    }

    /// Stops the session but keeps the partial file and its state for resume,
    /// and reports that to the application.
    async fn suspend(&mut self, why: &str) {
        tracing::info!("transfer {} suspended: {}", self.tid_hex(), why);
        if self.writer_full_drops > 0 {
            tracing::debug!(
                "transfer {}: {} packets dropped because the writer was saturated",
                self.tid_hex(),
                self.writer_full_drops
            );
        }
        if self.fragment_drops > 0 {
            tracing::info!(
                "transfer {}: {} packets refused for splitting the file into too many pieces",
                self.tid_hex(),
                self.fragment_drops
            );
        }
        if let Some(writer) = self.writer.take() {
            match writer.close().await {
                Ok(()) => {
                    if matches!(self.phase, Phase::Receiving) {
                        // Everything in `received` is now written and synced.
                        self.persist_state_now();
                    }
                }
                Err(e) => tracing::warn!("closing partial file failed: {}", e),
            }
        }
        self.emit_failed(format!("{}; partial file kept for resume", why), true);
    }

    // ----- stats -----------------------------------------------------------

    fn stats(&mut self, now: Instant) -> TransferStats {
        let done = self.received.total();
        let elapsed = now.saturating_duration_since(self.start);
        let dt = now
            .saturating_duration_since(self.last_progress_at)
            .as_secs_f64();
        let delta = done.saturating_sub(self.last_progress_bytes);
        let rate = if dt > 0.0 {
            delta as f64 * 8.0 / dt
        } else {
            0.0
        };
        let moved = done.saturating_sub(self.resumed_from);
        let avg = if elapsed.as_secs_f64() > 0.0 {
            moved as f64 * 8.0 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let remaining = self.file_size.saturating_sub(done);
        TransferStats {
            transfer_id: self.tid_hex(),
            bytes_done: done,
            total_bytes: self.file_size,
            rate_bps: rate,
            avg_rate_bps: avg,
            rtt_ms: 0.0,
            cwnd_bytes: 0,
            inflight_bytes: 0,
            chunk_size: self.max_chunk,
            retransmitted_bytes: self.retransmitted_bytes,
            loss_events: 0,
            elapsed,
            eta: if rate > 0.0 {
                Some(Duration::from_secs_f64(remaining as f64 * 8.0 / rate))
            } else {
                None
            },
            stalled: self.stalled,
        }
    }

    fn emit_progress(&mut self, now: Instant) {
        if !matches!(self.phase, Phase::Receiving) {
            return;
        }
        let stats = self.stats(now);
        self.last_progress_at = now;
        self.last_progress_bytes = stats.bytes_done;
        emit(&self.events, TransferEvent::Progress(stats));
    }
}

#[cfg(all(test, feature = "nat-traversal"))]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A rejection is no longer than the initiation it answers: its message
    /// is shortened to fit (on a character boundary), dropped if need be,
    /// and with no room even for the bare rejection there is no answer.
    #[test]
    fn a_rejection_fits_the_initiation_it_answers() {
        let message = "отказано: слишком много передач";
        let decoded = |p: &[u8]| wire::decode_response(p).unwrap().ack;
        let whole = rejection_within(7, REASON_BUSY, message, 1200).unwrap();
        assert_eq!(decoded(&whole).message, message);
        let bare = rejection_within(7, REASON_BUSY, "", 1200).unwrap();
        let smallest = hs::RESPONSE_OVERHEAD + bare.len();
        for limit in smallest..smallest + whole.len() - bare.len() + 2 {
            let p = rejection_within(7, REASON_BUSY, message, limit).unwrap();
            assert!(hs::RESPONSE_OVERHEAD + p.len() <= limit, "{}", limit);
            let ack = decoded(&p);
            assert_eq!((ack.status, ack.reason), (HELLO_REJECTED, REASON_BUSY));
            assert!(message.starts_with(&ack.message), "{}", limit);
        }
        assert!(rejection_within(7, REASON_BUSY, message, smallest - 1).is_none());
    }

    /// A session running directly to a peer's host ends the punching at it:
    /// every meeting there without a card, and the one on that sender's card
    /// — not another sender's card at the same host, nor another host's; and
    /// a session carried by a server, which runs at the server's address,
    /// ends none.
    #[test]
    fn a_direct_session_ends_the_meetings_at_its_host() {
        let m = Meetings::default();
        let root = CancellationToken::new();
        let (a, b) = (Identity::generate().id(), Identity::generate().id());
        let a_card = m.add(sa("203.0.113.7:4000"), Some(a), &root);
        let b_card = m.add(sa("203.0.113.7:4001"), Some(b), &root);
        let typed = m.add(sa("203.0.113.7:5000"), None, &root);
        let elsewhere = m.add(sa("198.51.100.1:4000"), None, &root);
        assert_eq!(m.met(&a, sa("192.0.2.50:3478")), 0);
        // The sender's NAT may give the session another port than the card's.
        assert_eq!(m.met(&a, sa("203.0.113.7:4999")), 2);
        assert!(a_card.is_cancelled() && typed.is_cancelled());
        assert!(!b_card.is_cancelled() && !elsewhere.is_cancelled());
        // IPv4 written as IPv6 is the same host.
        assert_eq!(m.met(&b, sa("[::ffff:203.0.113.7]:4001")), 1);
        assert!(b_card.is_cancelled());
        // The receiver stopping stops the rest; what is over is forgotten.
        root.cancel();
        assert!(elsewhere.is_cancelled());
        let _ = m.add(sa("192.0.2.1:1"), None, &CancellationToken::new());
        assert_eq!(m.0.lock().len(), 1);
    }
}

/// The receiver's memory budget, taken and given back by sessions on
/// several threads at once (`scripts/loom.sh`).
#[cfg(all(test, sharp_loom))]
mod loom_models {
    use super::Budget;
    use loom::sync::Arc;

    /// Two sessions each wanting 60 of 100 at once: in no interleaving do
    /// both get it (checking first and adding after, as the unwritten data
    /// once was, lets both).
    #[test]
    fn loom_two_sessions_never_claim_past_the_budget() {
        loom::model(|| {
            let budget = Arc::new(Budget::new(100));
            let other = {
                let budget = budget.clone();
                loom::thread::spawn(move || budget.resize(0, 60))
            };
            let mine = budget.resize(0, 60);
            let theirs = other.join().unwrap();
            assert!(!(mine && theirs), "both took 60 of 100");
            assert_eq!(budget.used(), 60 * (u64::from(mine) + u64::from(theirs)));
        });
    }

    /// One session shrinks its part while another grows into the room:
    /// the growth is made only if it fits with what is held at that
    /// moment, and the total is always what the parts are.
    #[test]
    fn loom_a_part_that_shrinks_makes_room() {
        loom::model(|| {
            let budget = Arc::new(Budget::new(100));
            assert!(budget.resize(0, 80));
            let shrink = {
                let budget = budget.clone();
                loom::thread::spawn(move || budget.resize(80, 10))
            };
            let grown = budget.resize(0, 50);
            assert!(shrink.join().unwrap());
            assert_eq!(budget.used(), 10 + if grown { 50 } else { 0 });
        });
    }

    /// The queue budget taken and given back on two threads: never more
    /// than the limit taken, and all of it back at the end.
    #[test]
    fn loom_the_queue_budget_is_taken_and_given_back() {
        loom::model(|| {
            let budget = Arc::new(Budget::new(100));
            let other = {
                let budget = budget.clone();
                loom::thread::spawn(move || {
                    let took = budget.take(70);
                    if took {
                        budget.give(70);
                    }
                    took
                })
            };
            let took = budget.take(70);
            assert!(budget.used() <= 100);
            if took {
                budget.give(70);
            }
            other.join().unwrap();
            assert_eq!(budget.used(), 0);
        });
    }
}
