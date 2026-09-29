//! Sending side of a SHARP-256 transfer.
//!
//! One `Sender` moves one file, or one directory tree, to one receiver (a
//! directory travels as a single stream: its manifest followed by the
//! contents of its files, see [`crate::file::tree`]). The engine is a single-owner
//! state machine. Each turn of its loop drains every datagram already queued
//! on the socket, runs timers, and then sends as much as the congestion
//! window, the receiver window and the pacer allow:
//!
//! * `pending` — byte ranges that still have to be (re)sent;
//! * `inflight` — ranges sent but not yet acknowledged, with send times;
//! * selective ACKs retire in-flight ranges, report holes (fast retransmit)
//!   and carry RTT samples; holes that are neither in flight nor queued are
//!   re-queued, so the sender's bookkeeping heals itself;
//! * RTO expiry returns stale in-flight ranges to `pending`;
//! * after a few seconds of silence the sender performs a new handshake,
//!   whose answer tells exactly what a live receiver holds and lets a
//!   restarted receiver resume from its saved state;
//! * the transfer completes when the receiver's whole-file BLAKE3 hash
//!   matches the sender's own.
//!
//! Every datagram after the handshake is an encrypted transport packet
//! (`crypto::transport`); the handshake authenticates the receiver by the
//! SHARP ID the sender was given.

use crate::config::{SenderConfig, TransportConfig};
use crate::crypto::handshake::{self as hs, Initiator, COOKIE_REPLY_LEN};
use crate::crypto::replay::ReplayWindow;
use crate::crypto::transport::{
    begin_packet, peek_cid, push_header, DirectionKeys, SessionKeys, Suite, TAG_LEN,
};
use crate::crypto::{CryptoError, Identity, SharpId, NO_PSK};
use crate::file::{hash_to_hex, sanitize_file_name, Source};
use crate::progress::{emit, DirectoryInfo, EventCallback, TransferEvent, TransferStats};
use crate::protocol::constants::*;
use crate::protocol::wire::{
    self, type_byte, Abort, Hello, HelloAck, Message, MsgType, Ping, Probe, MAX_CONTROL_BODY,
};
use crate::protocol::RangeSet;
use crate::state::{hex16, parse_hex16, SenderState, StateStore};
use crate::transport::congestion::{burst_for_rate, Cubic, Pacer, RttEstimator};
use crate::transport::io::{
    is_no_buffer_error, recv_buffers, BatchSocket, Received, MAX_SEND_BYTES,
};
use crate::transport::parallel;
use crate::transport::path::PathProbe;
use crate::transport::socket::{is_msgsize_error, Clock};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid file name: {0}")]
    BadFileName(String),
    #[error("receiver rejected the transfer ({reason}): {message}")]
    Rejected { reason: String, message: String },
    #[error(
        "no answer from receiver within the handshake timeout (wrong address or receiver ID?)"
    )]
    HandshakeTimeout,
    #[error("handshake with the receiver failed: {0}")]
    Handshake(String),
    #[error("cannot reach the receiver: {0}")]
    Unreachable(String),
    #[error("identity: {0}")]
    Identity(String),
    #[error("receiver unreachable for {0:?}; transfer state kept for resume")]
    PeerUnreachable(Duration),
    #[error("whole-file hash mismatch: sender {sender}, receiver {receiver}")]
    HashMismatch { sender: String, receiver: String },
    #[error("cancelled")]
    Cancelled,
    #[error("aborted by receiver (code {code}): {reason}")]
    Aborted { code: u16, reason: String },
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Result of a successful transfer.
#[derive(Debug, Clone)]
pub struct TransferSummary {
    pub transfer_id: String,
    pub file_size: u64,
    pub resumed_from: u64,
    pub bytes_sent: u64,
    pub retransmitted_bytes: u64,
    pub loss_events: u64,
    pub rto_events: u64,
    pub chunk_size: u16,
    pub elapsed: Duration,
    pub avg_rate_bps: f64,
    pub file_hash_hex: String,
}

pub struct Sender {
    cfg: SenderConfig,
    identity: Identity,
    socket: Arc<BatchSocket>,
    source: Arc<Source>,
    cancel: CancellationToken,
    store: Option<StateStore>,
}

impl Sender {
    /// Binds the socket and opens the file, or scans the directory. Nothing
    /// is sent yet.
    pub async fn new(cfg: SenderConfig) -> Result<Self, SendError> {
        let cfg = SenderConfig {
            transport: cfg.transport.normalized(),
            ..cfg
        };
        let identity = match &cfg.identity {
            Some(id) => id.clone(),
            None => {
                let path = Identity::default_path()
                    .ok_or_else(|| SendError::Identity("no per-user data directory".into()))?;
                Identity::load_or_create(&path)
                    .map_err(|e| SendError::Identity(format!("{}: {}", path.display(), e)))?
            }
        };
        let path = cfg.file_path.clone();
        let source = tokio::task::spawn_blocking(move || Source::open(&path))
            .await
            .map_err(io::Error::other)??;
        if let Some(tree) = source.tree() {
            for p in tree.skipped().iter().take(20) {
                tracing::warn!("not sent (symbolic link or special file): {}", p.display());
            }
            if tree.skipped().len() > 20 {
                tracing::warn!("... and {} more not sent", tree.skipped().len() - 20);
            }
        }
        let socket = BatchSocket::bind(cfg.bind, cfg.transport.socket_buffer_bytes).await?;
        tracing::info!(
            "sender bound to {} (up to {} datagrams per send), {} {} ({} bytes)",
            socket.local_addr()?,
            socket.max_segments(),
            if source.tree().is_some() {
                "directory"
            } else {
                "file"
            },
            cfg.file_path.display(),
            source.size()
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
        // Carry on above the newest handshake timestamp an earlier run
        // used, in case the clock has been set back since (see there).
        if let Some(store) = &store {
            hs::raise_initiation_timestamp_floor(store.load_stamp());
        }
        Ok(Self {
            cfg,
            identity,
            socket: Arc::new(socket),
            source: Arc::new(source),
            cancel: CancellationToken::new(),
            store,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Our identity, as the receiver will see it.
    pub fn id(&self) -> SharpId {
        self.identity.id()
    }

    /// Token that cancels the transfer when triggered.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// What is being sent (for a directory: its listing, and what was
    /// skipped).
    pub fn source(&self) -> &Source {
        &self.source
    }

    /// Starts asking each configured relay to put us through, in the
    /// background.
    ///
    /// The introductions run *alongside* the connectivity checks rather than
    /// before them, as ICE gathers candidates while it is already checking
    /// others (RFC 8445 section 6.1.4.2). Doing it the other way round made
    /// every transfer wait on the relay — including the ones on a local
    /// network that never needed it.
    ///
    /// A relay's name may resolve to several addresses — both families,
    /// usually — and only some of them may work from here: they are asked
    /// in turn, IPv6 first where this host has it, until one answers.
    ///
    /// Returns the inboxes the engine routes each relay's datagrams into —
    /// filled in as the relays' names resolve, so a slow name server holds
    /// up nothing. The addresses the introductions turn up go to `found`.
    #[cfg(feature = "nat-traversal")]
    fn spawn_relay_introductions(
        &self,
        found_tx: mpsc::UnboundedSender<Found>,
        puncher: Arc<crate::nat::punch::Puncher>,
    ) -> RelayInboxes {
        let inboxes: RelayInboxes = Arc::new(parking_lot::RwLock::new(Vec::new()));
        let reach = crate::address::Reach::of(&self.socket.udp());
        for name in &self.cfg.relays {
            // A sender claims no identity of its own unless the relay
            // insists, so the address alone is enough; the relay's identity,
            // when written with it, is what our proof would be made against.
            let (relay_id, host) = match crate::relay::parse_relay(name) {
                Ok(parsed) => parsed,
                Err(e) => {
                    tracing::warn!("relay \"{}\": {}", name, e);
                    continue;
                }
            };
            let socket = self.socket.udp();
            let target = self.cfg.receiver_id;
            let cancel = self.cancel.clone();
            let found = found_tx.clone();
            let inboxes = inboxes.clone();
            let identity = self.identity.clone();
            let puncher = puncher.clone();
            tokio::spawn(async move {
                // Only for a relay that asks, and only if we know its
                // identity to prove ours against.
                let auth = relay_id.map(|r| (&identity, r));
                // What our own NAT does is worth telling the relay — and
                // through it the receiver, who aims its punches by it — but
                // not worth holding the introduction up for long: the tests
                // take a round trip or two, and without them the receiver
                // simply treats our NAT as an easy one.
                let ours = puncher.hints_when_known().await;
                // A name is resolved like the receiver's own: as a hint.
                let resolved = tokio::select! {
                    r = tokio::time::timeout(
                        RELAY_RESOLVE_TIMEOUT,
                        crate::address::resolve_all(&host),
                    ) => r,
                    _ = cancel.cancelled() => return,
                };
                let addrs: Vec<SocketAddr> = match resolved {
                    Ok(Ok(all)) => all.into_iter().filter_map(|a| reach.native(a)).collect(),
                    Ok(Err(e)) => {
                        tracing::info!("relay {}: {}", host, e);
                        return;
                    }
                    Err(_) => {
                        tracing::info!("relay {}: the name did not resolve in time", host);
                        return;
                    }
                };
                if addrs.is_empty() {
                    tracing::info!("relay {}: no address this socket can reach", host);
                    return;
                }
                let (tx, mut rx) = mpsc::channel(32);
                for addr in addrs {
                    // The engine hands over what arrives from the address
                    // being asked, and only from it.
                    {
                        let mut list = inboxes.write();
                        list.retain(|(_, t)| !t.same_channel(&tx));
                        list.push((addr, tx.clone()));
                    }
                    match crate::relay::client::connect(
                        socket.clone(),
                        addr,
                        target,
                        &mut rx,
                        &cancel,
                        auth,
                        // Told in the family this relay is reached over,
                        // with where we can be aimed at in the other.
                        crate::relay::Hints::told_to(&ours, addr),
                    )
                    .await
                    {
                        Ok(i) => {
                            match i.peer {
                                Some(peer) => tracing::info!(
                                    "relay {} says the receiver is at {}, and will carry the \
                                     transfer on {}",
                                    addr,
                                    peer,
                                    i.relayed
                                ),
                                None => tracing::info!(
                                    "relay {} will not say where the receiver is, and will \
                                     carry the transfer on {}",
                                    addr,
                                    i.relayed
                                ),
                            }
                            // Where the receiver appears to be first: if that
                            // works the relay carries nothing.
                            if let Some(peer) = i.peer {
                                let _ = found.send(Found::Relay(peer));
                            }
                            // Then where it says it is in the other family:
                            // the path with no NAT in it, when both ends
                            // have IPv6 — and the only direct one when the
                            // IPv4 NATs cannot be got through.
                            if let Some(alt) = i.peer_alt.filter(|_| i.peer.is_some()) {
                                tracing::info!(
                                    "relay {} also says the receiver is at {}",
                                    addr,
                                    alt.addr
                                );
                                let _ = found.send(Found::Relay(alt.addr));
                            }
                            let _ = found.send(Found::Carrier(i.relayed));
                            // Push outwards at where the receiver appears
                            // to be, aimed by what it says its NAT does,
                            // while its own punches come the other way.
                            let aimed = i.peer.map(|peer| (peer, i.peer_hints)).into_iter().chain(
                                i.peer_alt
                                    .map(|a| (a.addr, a.nat))
                                    .filter(|_| i.peer.is_some()),
                            );
                            for (peer, nat) in aimed {
                                let Some(peer) = reach.native(peer) else {
                                    continue;
                                };
                                let (puncher, cancel) = (puncher.clone(), cancel.clone());
                                tokio::spawn(async move {
                                    puncher.run(peer, nat, &cancel).await;
                                });
                            }
                            // And bind our side of the relay's port, which
                            // takes a round trip to it: until then it carries
                            // nothing of ours.
                            crate::relay::client::hold(
                                socket, i.relayed, i.ticket, &mut rx, &cancel,
                            )
                            .await;
                            return;
                        }
                        // A relay that cannot help is not a failure: the
                        // addresses we already have may well work. One that
                        // refused (as opposed to not answering) would refuse
                        // at its other addresses too.
                        Err(crate::relay::client::ConnectError::Refused(e)) => {
                            tracing::info!("relay {}: {}", addr, e);
                            return;
                        }
                        Err(e) => tracing::info!("relay {}: {}", addr, e),
                    }
                    if cancel.is_cancelled() {
                        return;
                    }
                }
            });
        }
        inboxes
    }

    /// Resolves the names the receiver is published under while the
    /// handshake is already trying its addresses, both families at once,
    /// each address joining the attempts as RFC 8305 says it may (see
    /// `address::dns`). Returns where the names that did not resolve are
    /// told, for the error when nothing else turned up either.
    fn spawn_name_resolution(
        &self,
        reach: crate::address::Reach,
        found: mpsc::UnboundedSender<Found>,
    ) -> Arc<parking_lot::Mutex<Vec<String>>> {
        let unresolved = Arc::new(parking_lot::Mutex::new(Vec::new()));
        for name in &self.cfg.peer_names {
            let (host, port) = match crate::address::dns::split_host_port(name) {
                Ok((h, p)) => (h.to_string(), p),
                Err(e) => {
                    unresolved.lock().push(e.to_string());
                    continue;
                }
            };
            let name = name.clone();
            let found = found.clone();
            let unresolved = unresolved.clone();
            let cancel = self.cancel.clone();
            tokio::spawn(async move {
                let resolution = crate::address::dns::resolve_happily(
                    &host,
                    port,
                    reach.v6(),
                    reach.v4(),
                    CANDIDATE_PROBE,
                    crate::address::MAX_ADDRESSES,
                    |a| {
                        let _ = found.send(Found::Named(a));
                    },
                );
                tokio::select! {
                    r = resolution => {
                        if let Err(e) = r {
                            unresolved.lock().push(format!("cannot resolve {}: {}", name, e));
                        }
                    }
                    _ = cancel.cancelled() => {}
                }
            });
        }
        unresolved
    }

    /// On a network that has IPv6 alone, an IPv4 address is reachable only
    /// through the network's NAT64 translator, under an address inside its
    /// prefix (RFC 6052); RFC 8305 section 7.1 asks the client to work
    /// that address out itself for a literal, which is what a receiver
    /// publishes. The translated addresses join the attempts once the
    /// prefix is known (RFC 7050). Nothing happens on a host that has an
    /// IPv4 route.
    fn spawn_nat64(
        &self,
        given: &[SocketAddr],
        reach: crate::address::Reach,
        found: mpsc::UnboundedSender<Found>,
    ) {
        if !reach.v6() {
            return;
        }
        let v4: Vec<SocketAddr> = given
            .iter()
            .copied()
            .filter(|a| a.is_ipv4() && !crate::address::nat64::has_ipv4_route(*a))
            .collect();
        if v4.is_empty() {
            return;
        }
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            let prefix = tokio::select! {
                p = crate::address::nat64::discover() => p,
                _ = cancel.cancelled() => return,
            };
            let Some(prefix) = prefix else {
                tracing::info!(
                    "no IPv4 route to {:?}, and no NAT64 on this network to reach it through",
                    v4
                );
                return;
            };
            for a in v4 {
                if let Some(t) = prefix.synthesize_addr(a) {
                    tracing::info!("{} is reached through NAT64 as {}", a, t);
                    let _ = found.send(Found::Named(t));
                }
            }
        });
    }

    /// Runs the transfer to completion.
    pub async fn run(self) -> Result<TransferSummary, SendError> {
        // A directory is named after itself even when given as "." or "..".
        let named = match self.source.tree() {
            Some(_) => {
                std::fs::canonicalize(&self.cfg.file_path).unwrap_or(self.cfg.file_path.clone())
            }
            None => self.cfg.file_path.clone(),
        };
        let file_name = named
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .and_then(|n| sanitize_file_name(&n))
            .ok_or_else(|| SendError::BadFileName(self.cfg.file_path.display().to_string()))?;

        let size = self.source.size();
        let mtime = self.source.mtime_unix();
        let manifest_hex = self
            .source
            .tree_info()
            .map(|t| hash_to_hex(&t.manifest_hash))
            .unwrap_or_default();
        // Resume state is kept per receiver identity, not per address.
        let peer_str = self.cfg.receiver_id.to_string();
        // Present the id of an interrupted attempt so the receiver resumes
        // it, unless the source changed since (its data would not match).
        let transfer_id = self
            .store
            .as_ref()
            .and_then(|s| s.load_sender(&self.cfg.file_path, size, &peer_str))
            .filter(|st| st.file_mtime == mtime && st.manifest_hash == manifest_hex)
            .and_then(|st| parse_hex16(&st.transfer_id))
            .unwrap_or_else(rand::random::<[u8; 16]>);

        // Hash of the whole stream in the background; it is only needed at
        // the end.
        let hash_source = self.source.clone();
        let hash_task: JoinHandle<io::Result<[u8; 32]>> =
            tokio::task::spawn_blocking(move || hash_source.hash());

        // The receiver may be published under several addresses; the
        // handshake decides which one is really the receiver. They are
        // tried in the order RFC 6724 would use them — native IPv6 first
        // where this host has it, anything it has no route to last — with
        // the families taking turns after the first (RFC 8305 section 4).
        // Only those this socket can reach are worth a turn — an IPv4
        // socket handed an IPv6 address would spend it on an error — and
        // each is written the way this socket will see replies from it, or
        // a dual-stack socket would take its own peer's answers for a
        // stranger's.
        let reach = crate::address::Reach::of(&self.socket.udp());
        let local = self.socket.local_addr()?;
        let mut given: Vec<SocketAddr> = std::iter::once(self.cfg.peer)
            .chain(self.cfg.alternate_peers.iter().copied())
            // An unspecified address stands for "none": a receiver that is
            // reached only through a relay publishes no address of its own.
            .filter(|a| !a.ip().is_unspecified())
            .map(crate::address::canonical)
            .collect();
        crate::address::class::sort_destinations(&mut given);
        let given = crate::address::class::interleave_families(&given);
        let mut candidates: Vec<SocketAddr> = Vec::new();
        for a in &given {
            if !crate::address::class::is_sendable_named(*a, local) {
                tracing::info!("not trying {}: this socket ({}) cannot use it", a, local);
                continue;
            }
            match reach.native(*a) {
                Some(n) if !candidates.contains(&n) => candidates.push(n),
                _ => {}
            }
        }
        let names_pending = !self.cfg.peer_names.is_empty();
        let first = match candidates.first() {
            Some(&first) => first,
            // Nothing to try until a relay or a name turns something up.
            None if !self.cfg.relays.is_empty()
                || names_pending
                || self.cfg.find_lan
                || self.cfg.dht =>
            {
                if !names_pending {
                    tracing::info!(
                        "no direct address for the receiver; asking {}",
                        if self.cfg.find_lan {
                            "the local network and the relays"
                        } else if self.cfg.dht {
                            "the DHT and the relays"
                        } else {
                            "the relays"
                        }
                    );
                }
                self.cfg.peer
            }
            None => {
                return Err(SendError::Io(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!(
                        "none of the receiver's addresses can be reached from {} \
                         (to use IPv6, bind the sender to [::]:0)",
                        local
                    ),
                )));
            }
        };
        // Relays, names and the NAT64 translation of IPv4 addresses on an
        // IPv6-only network all add more as they turn up, while the
        // addresses above are already being tried.
        let (found_tx, found_rx) = mpsc::unbounded_channel();
        // What our NAT does, for the relays to pass on and our punches to be
        // aimed by; found out only where there is a relay to tell.
        #[cfg(feature = "nat-traversal")]
        let (hints_tx, hints_rx) =
            tokio::sync::watch::channel(crate::nat::card::FamilyHints::unknown());
        #[cfg(feature = "nat-traversal")]
        let (hits_tx, hits_rx) = mpsc::unbounded_channel();
        // Stops what the NAT machinery started — the router's forward, the
        // TURN allocations — once the transfer is over.
        #[cfg(feature = "nat-traversal")]
        let nat_cancel = self.cancel.child_token();
        // TURN servers this sender was given: each makes an allocation in
        // the background, whose address goes on the sender's card, and lets
        // in whoever is punched at.
        #[cfg(feature = "nat-traversal")]
        let turns =
            crate::nat::turn::start_all(&self.cfg.turn_servers, &self.socket.udp(), &nat_cancel);
        #[cfg(feature = "nat-traversal")]
        let puncher = Arc::new(
            crate::nat::punch::Puncher::new(self.socket.udp(), hints_rx)
                .with_hit_handler(Arc::new(move |hit| {
                    let _ = hits_tx.send(hit);
                }))
                .with_turns(turns.clone()),
        );
        // With a relay, or the receiver's card: what our own NAT does is
        // told to the receiver (through the relay, or on the card we give
        // it), and the punches are aimed by both.
        #[cfg(feature = "nat-traversal")]
        let meeting = self.cfg.peer_card.is_some();
        // A card is given to the peer when we were given theirs, and when
        // there is a TURN server, whose address only a card can tell.
        #[cfg(feature = "nat-traversal")]
        let wants_card = meeting || !self.cfg.turn_servers.is_empty();
        // What discovery finds and what the TURN servers give go on the card
        // together, and the card is given again when either changes.
        #[cfg(feature = "nat-traversal")]
        let reports = {
            let events = self.cfg.events.clone();
            let id = self.identity.id();
            let relay_refs = literal_relays(&self.cfg.relays);
            crate::nat::RelayedReports::new(
                self.socket.local_addr().unwrap_or(self.cfg.bind),
                turns.clone(),
                nat_cancel.clone(),
                self.cfg.nat_traversal
                    && (!self.cfg.relays.is_empty() || wants_card || self.cfg.dht),
                move |r| {
                    emit(
                        &events,
                        TransferEvent::ContactCard {
                            card: r
                                .card(&id, crate::nat::card::Role::Sender, &relay_refs)
                                .to_text(),
                            summary: r.describe(),
                        },
                    )
                },
            )
        };
        #[cfg(feature = "nat-traversal")]
        let nat_task = if self.cfg.nat_traversal
            && (!self.cfg.relays.is_empty() || wants_card || self.cfg.dht)
        {
            let mut c = crate::nat::NatConfig {
                // A card is only useful to the peer if we can be reached:
                // ask the router for a port, and look after it until we are
                // done — and give it back.
                enable_port_mapping: wants_card || self.cfg.dht,
                maintain: wants_card || self.cfg.dht,
                ..crate::nat::NatConfig::default()
            };
            if !self.cfg.stun_servers.is_empty() {
                c.stun_servers = self.cfg.stun_servers.clone();
            }
            let reports = reports.clone();
            crate::nat::spawn_discovery(
                self.socket.udp(),
                c,
                Default::default(),
                hints_tx,
                nat_cancel.clone(),
                // Only when there is a card to give: relays alone want the
                // hints, not a card nobody asked for.
                move |r| {
                    if wants_card {
                        reports.update(r)
                    }
                },
            )
        } else {
            None
        };
        #[cfg(feature = "nat-traversal")]
        let (stun_inbox, nat_done) = match nat_task {
            Some(t) => {
                // Told when the tests are over, so that a punch does not
                // wait for hints that are not coming.
                let (puncher, stun) = (puncher.clone(), t.stun_responses);
                let done = tokio::spawn(async move {
                    let _ = t.task.await;
                    puncher.settle();
                });
                (Some(stun), Some(done))
            }
            None => {
                puncher.settle();
                (None, None)
            }
        };
        // Punching towards every address on the receiver's card, at once
        // and for as long as its user may take to hand over ours.
        #[cfg(feature = "nat-traversal")]
        if let Some(card) = &self.cfg.peer_card {
            for (addr, hints) in card.punch_targets() {
                let (puncher, cancel) = (puncher.clone(), self.cancel.clone());
                tokio::spawn(async move {
                    puncher
                        .run_for(addr, hints, crate::nat::punch::MEET_DURATION, &cancel)
                        .await;
                });
            }
        }
        #[cfg(feature = "nat-traversal")]
        let relay_inboxes = self.spawn_relay_introductions(found_tx.clone(), puncher.clone());
        #[cfg(not(feature = "nat-traversal"))]
        let relay_inboxes = RelayInboxes::default();
        let unresolved = self.spawn_name_resolution(reach, found_tx.clone());
        // The local network, if asked: one multicast question, and whatever
        // the receiver there says of itself joins the candidates.
        #[cfg(feature = "nat-traversal")]
        if self.cfg.find_lan {
            let (found, id, cancel) = (found_tx.clone(), self.cfg.receiver_id, self.cancel.clone());
            tokio::spawn(async move {
                let addrs = tokio::select! {
                    a = crate::nat::mdns::find(&id, Duration::from_secs(3)) => a,
                    _ = cancel.cancelled() => return,
                };
                if addrs.is_empty() {
                    tracing::info!("nobody on the local network answered for the receiver");
                }
                for a in addrs {
                    tracing::info!("the receiver says it is at {} on the local network", a);
                    let _ = found.send(Found::Named(a));
                }
            });
        }
        // Each of the receiver's addresses is also reached through each
        // TURN server, in case the sender cannot send to it directly.
        #[cfg(feature = "nat-traversal")]
        spawn_turn_dials(&turns, &candidates, found_tx.clone(), nat_cancel.clone());
        // The DHT, if asked: this sender announced there and the receiver
        // looked for; what turns up is tried in the handshake and punched at.
        #[cfg(feature = "nat-traversal")]
        if self.cfg.dht {
            match crate::nat::dht::Dht::start(self.cfg.dht_bootstrap.clone(), nat_cancel.clone()) {
                Ok(dht) => {
                    tracing::info!(
                        "looking for the receiver in the DHT: every node asked learns this host's address{}",
                        if self.cfg.psk.is_none() {
                            ", and anybody who knows the receiver's ID can see it (a shared secret prevents that)"
                        } else {
                            ""
                        }
                    );
                    let key = crate::nat::dht::rendezvous_key(
                        &self.cfg.receiver_id,
                        self.cfg.psk.as_ref(),
                    );
                    let (punch, cancel, found) =
                        (puncher.clone(), nat_cancel.clone(), found_tx.clone());
                    crate::nat::dht::spawn_rendezvous(
                        dht,
                        key,
                        crate::nat::dht::Role::Sender,
                        puncher.subscribe(),
                        nat_cancel.clone(),
                        move |peer| {
                            let _ = found.send(Found::Relay(peer));
                            let (punch, cancel) = (punch.clone(), cancel.clone());
                            tokio::spawn(async move {
                                punch
                                    .run_for(
                                        peer,
                                        crate::nat::card::NatHints::unknown(),
                                        crate::nat::punch::MEET_DURATION,
                                        &cancel,
                                    )
                                    .await;
                            });
                        },
                    );
                }
                Err(e) => tracing::warn!("cannot use the DHT: {}", e),
            }
        }
        self.spawn_nat64(&given, reach, found_tx);

        let mut engine = Engine::new(
            self.cfg.transport.clone(),
            self.socket.clone(),
            first,
            candidates,
            relay_inboxes,
            found_rx,
            unresolved,
            Peer {
                identity: self.identity.clone(),
                receiver: self.cfg.receiver_id,
                psk: self.cfg.psk.unwrap_or(NO_PSK),
            },
            self.source.clone(),
            file_name,
            transfer_id,
            self.cfg.events.clone(),
            self.cancel.clone(),
        );

        #[cfg(feature = "nat-traversal")]
        {
            engine.stun_inbox = stun_inbox;
            engine.hits = Some(hits_rx);
            engine.turns = turns;
            // The addresses on the receiver's card that are on a TURN
            // server: where the transfer is carried, not where it is.
            if let Some(card) = &self.cfg.peer_card {
                for c in &card.candidates {
                    if c.kind == crate::nat::card::Kind::Relayed {
                        if let Some(a) = reach.native(c.addr) {
                            engine.relayed.insert(crate::address::canonical(a));
                        }
                    }
                }
            }
        }
        let result = engine.run(hash_task).await;
        // The NAT task gives back the port it asked the router for.
        #[cfg(feature = "nat-traversal")]
        {
            nat_cancel.cancel();
            if let Some(done) = nat_done {
                let _ = tokio::time::timeout(Duration::from_secs(4), done).await;
            }
            for t in &engine.turns {
                t.finished(Duration::from_secs(2)).await;
            }
        }

        // Tell the receiver why the transfer ends, so that it releases the
        // session (keeping its resume state) at once instead of timing out.
        if let Err(err) = &result {
            let code = match err {
                SendError::Cancelled => Some(ABORT_CANCELLED),
                SendError::Io(_) => Some(ABORT_IO_ERROR),
                SendError::Protocol(_) => Some(ABORT_PROTOCOL),
                SendError::PeerUnreachable(_) | SendError::HandshakeTimeout => Some(ABORT_TIMEOUT),
                // The receiver decided these itself, already knows, or no
                // session exists to tell it through.
                SendError::BadFileName(_)
                | SendError::Rejected { .. }
                | SendError::HashMismatch { .. }
                | SendError::Aborted { .. }
                | SendError::Handshake(_)
                | SendError::Unreachable(_)
                | SendError::Identity(_) => None,
            };
            if let Some(code) = code {
                engine.send_abort(code, &err.to_string());
            }
        }

        if let Some(store) = &self.store {
            if let Err(e) = store.save_stamp(hs::last_initiation_timestamp()) {
                tracing::debug!("could not save the handshake timestamp: {}", e);
            }
            // Kept whenever the transfer could still be finished: the
            // receiver went away, the user stopped it, or the receiver was
            // too busy to take it now.
            let resumable = match &result {
                Err(SendError::PeerUnreachable(_)) | Err(SendError::Cancelled) => true,
                Err(SendError::Rejected { reason, .. }) => reason == reason_name(REASON_BUSY),
                _ => false,
            };
            match resumable {
                true => {
                    let st = SenderState {
                        format: 0,
                        transfer_id: hex16(&transfer_id),
                        file_path: self.cfg.file_path.clone(),
                        file_size: size,
                        file_mtime: mtime,
                        manifest_hash: manifest_hex.clone(),
                        peer: peer_str.clone(),
                        updated_unix: 0,
                    };
                    if let Err(e) = store.save_sender(&st) {
                        tracing::warn!("could not save sender state: {}", e);
                    }
                }
                false => store.remove_sender(&self.cfg.file_path, size, &peer_str),
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Builds and seals a DATA packet in `out`.
fn seal_data(
    sec: &mut Secure,
    out: &mut Vec<u8>,
    flags: u8,
    offset: u64,
    timestamp: u32,
    payload: &[u8],
) -> Result<(), CryptoError> {
    let pn = sec.next_pn;
    sec.next_pn += 1;
    begin_packet(out, sec.peer_cid, type_byte(MsgType::Data, flags), pn);
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(payload);
    sec.keys.send.seal(out)
}

#[derive(Debug)]
struct Inflight {
    end: u64,
    sent_at: Instant,
    seq: u64,
}

enum SendBlock {
    /// Nothing left to send right now.
    Idle,
    /// Window (cwnd/rwnd) is full; wait for ACKs.
    Window,
    /// Pacer says wait this long.
    Pacer(Duration),
    /// Socket buffer full; wait for writability.
    Socket,
    /// Sent a large batch; let other work run, then continue.
    Yield,
    /// Enough batches are being encrypted; wait for them.
    Pipeline,
}

/// Where the payload of the next DATA packet lives.
enum PayloadSrc {
    Cache(usize, usize),
    Buf,
}

/// Resume state older than this is deleted when a sender starts.
const STATE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

/// Datagrams sent in one uninterrupted batch before input is processed again.
const MAX_BATCH: usize = 256;
/// Housekeeping (RTO, liveness) period.
const TICK: Duration = Duration::from_millis(5);
/// Without FIN_DONE the sender waits this long after its last FIN_ACK
/// (plus four RTTs, at most `FIN_LINGER_MAX`) before it ends: the receiver
/// repeats FIN after 200 ms and again 400 ms later if the verdict was lost,
/// and the sender must still be there to answer both.
const FIN_LINGER_BASE: Duration = Duration::from_millis(1000);
const FIN_LINGER_MAX: Duration = Duration::from_secs(3);
/// ACK summaries kept for diagnostics.
const ACK_LOG_LEN: usize = 24;
/// Losses in one round beyond this rate always count as congestion.
const LOSS_CEILING: f64 = 0.20;
/// Weight the background-loss counters keep per completed round (a memory
/// of about ten rounds).
const BG_DECAY: f64 = 0.9;
/// Highest loss rate ever accepted as background (non-congestive) loss.
const BASE_LOSS_MAX: f64 = 0.15;
/// Tail loss probes sent before falling back to the retransmission timeout.
const MAX_TAIL_PROBES: u32 = 2;
/// Upper bound for the ACK delay a receiver may announce.
const MAX_PEER_ACK_DELAY: Duration = Duration::from_secs(1);

/// Most batches between being built and being sent (being encrypted, or
/// waiting for their turn).
const MAX_PIPELINE: usize = 8;
/// Wait before retrying a send the network stack had no buffers for.
const NO_BUFFER_BACKOFF: Duration = Duration::from_millis(1);
/// Longest burst of one segmented send, at the pacing rate.
const BATCH_BURST: Duration = Duration::from_millis(1);
/// Batches with fewer datagrams are encrypted on the engine's own thread.
const MIN_POOLED: usize = 8;
/// Spare batch buffers kept for reuse.
const MAX_SPARE: usize = 16;

/// DATA datagrams encrypted together and sent with one call where the
/// platform allows.
struct Batch {
    seq: u64,
    buf: Vec<u8>,
    /// The chunk size it was built with. A batch built before a step-down
    /// that then fails for its size says nothing new about the path.
    chunk: u16,
    /// Length of every datagram but the last.
    segment: usize,
    /// The byte range each datagram carries.
    ranges: Vec<(u64, u64)>,
    /// Encryption failed (never expected).
    failed: bool,
}

/// Batches on their way from being built to being sent: encrypted on the
/// crypto pool (or right away, when small), then sent strictly in the order
/// they were built.
struct Pipe {
    next_seq: u64,
    next_send: u64,
    in_pool: usize,
    ready: BTreeMap<u64, Batch>,
    results_tx: tokio::sync::mpsc::UnboundedSender<Batch>,
    results: tokio::sync::mpsc::UnboundedReceiver<Batch>,
    spare: Vec<Vec<u8>>,
}

impl Pipe {
    fn new() -> Self {
        let (results_tx, results) = tokio::sync::mpsc::unbounded_channel();
        Self {
            next_seq: 0,
            next_send: 0,
            in_pool: 0,
            ready: BTreeMap::new(),
            results_tx,
            results,
            spare: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.in_pool + self.ready.len()
    }

    fn take_buf(&mut self) -> Vec<u8> {
        self.spare
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(MAX_SEND_BYTES))
    }

    fn recycle(&mut self, mut buf: Vec<u8>) {
        if self.spare.len() < MAX_SPARE {
            buf.clear();
            self.spare.push(buf);
        }
    }
}

/// Encrypts the datagrams of a batch, which start at `starts`.
fn seal_all(keys: &DirectionKeys, buf: &mut [u8], starts: &[usize]) -> bool {
    let total = buf.len();
    let lengths =
        (0..starts.len()).map(|i| starts.get(i + 1).copied().unwrap_or(total) - starts[i]);
    parallel::split_lengths(buf, lengths)
        .into_iter()
        .all(|p| keys.seal_in_place(p).is_ok())
}

/// Receive buffers of the sender (it only receives acknowledgements).
const RX_BUFFERS: usize = 8;
/// Receive calls per turn of the loop before it sends again.
const MAX_RECV_CALLS: usize = 64;

/// Handshake attempts kept alive at once (a response may answer any of them).
const MAX_ATTEMPTS: usize = 4;
/// While the receiver's user decides, ask for the decision this often.
const DECISION_POLL: Duration = Duration::from_secs(1);
/// Gap between initiations while candidate addresses are still untried.
const CANDIDATE_PROBE: Duration = Duration::from_millis(250);
/// Most addresses one transfer will ever try. Each costs a quarter of a
/// second of setup, so a peer (or a relay) cannot make us spend the whole
/// handshake budget walking a list.
const MAX_CANDIDATES: usize = 12;
/// Separate pieces the sender will queue on the receiver's word alone. A
/// receiver reports holes, and one that reported a different one-byte hole
/// in every ACK could otherwise grow the queue by an entry per byte
/// already sent. Holes past this wait for the queue to drain and are
/// reported again; data actually lost in flight is always queued.
const MAX_HEALED_RANGES: usize = 1 << 16;
/// How long to wait before sending again after the network refused a send
/// for a reason other than a full buffer.
const SEND_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// How long after stepping the chunk down its old size is tried again, with
/// a PROBE the receiver has to acknowledge; and how much longer each later
/// try waits.
const MTU_RAISE_AFTER: Duration = Duration::from_secs(30);
/// Retransmission timeouts in a row, with no data acknowledged while the
/// receiver is still heard from, before full-size packets are taken to be
/// too big for the path (RFC 8899, section 4.3).
const MTU_BLACKHOLE_RTOS: u32 = 2;

/// An address that turned up while the handshake was already under way,
/// and who named it: that decides how far it is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Found {
    /// From a relay, which is not trusted with anything.
    #[cfg_attr(not(feature = "nat-traversal"), allow(dead_code))]
    Relay(SocketAddr),
    /// From a name the user gave, or the NAT64 translation of an address
    /// the user gave.
    Named(SocketAddr),
    /// A loopback address that reaches a peer through one of our TURN
    /// allocations (see `nat::turn`): ours, and so worth sending to, though
    /// no address on loopback is otherwise.
    #[cfg_attr(not(feature = "nat-traversal"), allow(dead_code))]
    Turn(SocketAddr),
    /// A port a relay set aside for the pair: from a relay, like
    /// [`Found::Relay`], but one that carries and is not the receiver. A
    /// transfer over it is worth moving to a direct path once one opens.
    #[cfg_attr(not(feature = "nat-traversal"), allow(dead_code))]
    Carrier(SocketAddr),
}

/// Each of `candidates` — as many as three, the ones the internet routes —
/// reached through each TURN allocation too, once it has an address: the
/// loopback address that stands for the receiver through the server joins
/// the attempts. It costs the server nothing until it is the one that
/// answers.
#[cfg(feature = "nat-traversal")]
fn spawn_turn_dials(
    turns: &[crate::nat::turn::Turn],
    candidates: &[SocketAddr],
    found: mpsc::UnboundedSender<Found>,
    cancel: CancellationToken,
) {
    let targets: Vec<SocketAddr> = candidates
        .iter()
        .map(|a| crate::address::canonical(*a))
        .filter(|a| crate::address::class::is_global(a.ip()) && a.port() != 0)
        .take(3)
        .collect();
    if targets.is_empty() {
        return;
    }
    for turn in turns {
        let (turn, found, cancel, targets) =
            (turn.clone(), found.clone(), cancel.clone(), targets.clone());
        tokio::spawn(async move {
            // Until the server has given an address there is nothing to go
            // through, and how long that takes is not ours to decide.
            let mut changes = turn.subscribe();
            let ready = tokio::time::timeout(Duration::from_secs(20), async {
                while turn.relayed().is_empty() {
                    if changes.changed().await.is_err() {
                        return;
                    }
                }
            });
            tokio::select! {
                r = ready => if r.is_err() { return },
                _ = cancel.cancelled() => return,
            }
            for addr in targets {
                if let Some(shim) = turn.dial(addr).await {
                    let _ = found.send(Found::Turn(shim));
                }
            }
        });
    }
}

/// The relays written with an identity and an address literal, as a card
/// names them.
#[cfg(feature = "nat-traversal")]
fn literal_relays(relays: &[String]) -> Vec<crate::nat::card::RelayRef> {
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

/// A socket a birthday meeting was made at; there is no such thing without
/// NAT traversal.
#[cfg(feature = "nat-traversal")]
type Hit = crate::nat::birthday::Hit;
#[cfg(not(feature = "nat-traversal"))]
type Hit = std::convert::Infallible;

/// A socket a birthday meeting was made at *after* the session was up — a
/// session carried by a relay or a TURN server — and the address the
/// receiver got through to it from. The receiver's NAT lets packets in at
/// that socket and at no other, so the frames that ask it whether the way
/// is open go out from here, what arrives here is read with everything
/// else, and once the receiver has proven the address (as for any move to a
/// new one) this becomes the socket the session runs on.
#[cfg(feature = "nat-traversal")]
struct Aux {
    socket: Arc<BatchSocket>,
    peer: SocketAddr,
    since: Instant,
}

/// How long the receiver is given to prove an address at such a socket.
#[cfg(feature = "nat-traversal")]
const AUX_PATIENCE: Duration = Duration::from_secs(20);

/// A relay we are talking to, and the inbox its datagrams go into.
type RelayInbox = (SocketAddr, mpsc::Sender<(Vec<u8>, SocketAddr)>);
/// Every relay's inbox, added to as each relay's name resolves.
type RelayInboxes = Arc<parking_lot::RwLock<Vec<RelayInbox>>>;
/// How long a relay's name may take to resolve before it is given up.
#[cfg(feature = "nat-traversal")]
const RELAY_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Who we are, whom we talk to, and the shared secret.
struct Peer {
    identity: Identity,
    receiver: SharpId,
    psk: [u8; 32],
}

/// An established encrypted session with the receiver.
struct Secure {
    keys: Arc<SessionKeys>,
    /// Our connection id: the receiver addresses its packets to it.
    local_cid: u64,
    /// The receiver's connection id: our packets are addressed to it.
    peer_cid: u64,
    next_pn: u64,
    replay: ReplayWindow,
    auth_failures: u64,
}

/// Compact record of a received ACK, kept for diagnostics.
#[derive(Debug, Clone, Copy)]
struct AckRecord {
    at: Instant,
    received: u64,
    contiguous: u64,
    highest: u64,
    holes: usize,
    first_hole: Option<(u64, u64)>,
    last_hole: Option<(u64, u64)>,
    stale: bool,
}

struct Engine {
    cfg: TransportConfig,
    /// Which addresses the socket can send to, and how it writes them.
    reach: crate::address::Reach,
    /// Datagrams the network refused to send, for the log.
    send_failures: u64,
    /// Retransmission timeouts in a row that looked like a path losing
    /// only full-size packets.
    mtu_suspect: u32,
    /// Since when the receiver's user has been deciding, again, whether to
    /// take the transfer (see `run`).
    awaiting_decision: Option<Instant>,
    last_decision_poll: Option<Instant>,
    /// When to try a larger chunk again, and which.
    mtu_raise: Option<(Instant, u16)>,
    socket: Arc<BatchSocket>,
    /// The receiver's proven address: everything we send goes there.
    peer: SocketAddr,
    /// An address the receiver claims but has not proven yet.
    path: PathProbe,
    reader: Arc<Source>,
    size: u64,
    file_name: String,
    transfer_id: [u8; 16],
    clock: Clock,
    events: Option<EventCallback>,
    cancel: CancellationToken,

    auth: Peer,
    secure: Option<Secure>,
    /// Handshake attempts waiting for an answer, with their send times and
    /// the address each was sent to.
    attempts: VecDeque<(Initiator, Instant, SocketAddr)>,
    /// Latest cookie, with the address that issued it: a cookie proves our
    /// address to one receiver and is worthless anywhere else.
    cookie: Option<([u8; 16], Instant, SocketAddr)>,
    /// Addresses the receiver's name resolved to; handshake attempts rotate
    /// through them until one answers.
    candidates: Vec<SocketAddr>,
    next_candidate: usize,
    /// Relays being asked for an introduction, and the inbox each one's
    /// datagrams are routed into. The engine owns the socket's receive
    /// loop, so it has to hand them over. Always empty without the
    /// `nat-traversal` feature, which is the only thing that fills it.
    #[cfg_attr(not(feature = "nat-traversal"), allow(dead_code))]
    relay_inboxes: RelayInboxes,
    /// Where NAT discovery's STUN answers go, while it runs.
    #[cfg(feature = "nat-traversal")]
    stun_inbox: Option<mpsc::Sender<crate::nat::stun::Incoming>>,
    /// Sockets a birthday meeting was made at (see `nat::birthday`): the
    /// receiver's packets can only be received at one of those, so the
    /// handshake moves there.
    hits: Option<mpsc::UnboundedReceiver<Hit>>,
    /// The socket of a meeting made after the handshake, while its address
    /// is being proven (see [`Aux`]).
    #[cfg(feature = "nat-traversal")]
    aux: Option<Aux>,
    /// Addresses the introductions, the names and NAT64 turn up, as they
    /// turn up.
    found_rx: mpsc::UnboundedReceiver<Found>,
    /// Names that did not resolve, for the error when nothing else turned
    /// up either.
    unresolved: Arc<parking_lot::Mutex<Vec<String>>>,
    /// A candidate that answered an attempt we could not adopt. Worth going
    /// straight back to rather than finishing the round.
    answered_at: Option<SocketAddr>,
    /// The addresses (without ports) the receiver is known to be at: what
    /// it published, what a relay says. A punch from one of them, from a
    /// port we were never told, is the receiver's NAT telling us which port
    /// it gave the receiver for us — the one place a peer behind a NAT
    /// that numbers its ports per destination can be reached.
    peer_ips: std::collections::HashSet<std::net::IpAddr>,
    /// Ports learned that way: how many initiations each has had, and when
    /// the last went.
    #[cfg(feature = "nat-traversal")]
    reflexive: std::collections::HashMap<SocketAddr, (u32, Instant)>,
    /// TURN allocations, whose loopback addresses are places the receiver
    /// can be sent to and be heard from.
    #[cfg(feature = "nat-traversal")]
    turns: Vec<crate::nat::turn::Turn>,
    /// Addresses that carry the transfer and are not the receiver: a
    /// relay's port for the pair, a TURN server's relayed address. A
    /// session over one keeps asking the other addresses whether a direct
    /// path has opened (see `probe_direct`).
    relayed: std::collections::HashSet<SocketAddr>,
    /// When the next such question goes out, and how many rounds have.
    next_direct_probe: Instant,
    direct_probes: u32,
    /// Initiations sent so far; while this is below the number of
    /// candidates, there are still untried addresses and probing stays
    /// brisk.
    probes_sent: usize,
    /// Answer to a handshake or to a state query, not yet acted upon.
    answer: Option<HelloAck>,
    /// Still negotiating: every HELLO_ACK counts, including the one the
    /// receiver sends on its own once its user decided.
    negotiating: bool,
    /// Responses whose authentication failed (a different shared secret).
    handshake_failures: u32,
    /// Sizes acknowledged by PROBE_ACK.
    probe_acks: Vec<u16>,

    chunk: u16,
    pending: RangeSet,
    inflight: BTreeMap<u64, Inflight>,
    inflight_bytes: u64,
    send_log: VecDeque<(Instant, u64, u64)>,
    seq: u64,
    highest_sent: u64,

    rtt: RttEstimator,
    cc: Cubic,
    pacer: Pacer,
    rwnd: u64,

    received_bytes: u64,
    max_ack_received: u64,
    resumed_from: u64,
    /// ACKs describing bytes the file does not have; dropped unread.
    impossible_acks: u64,
    ack_log: VecDeque<AckRecord>,
    /// Last time an ACK acknowledged new data (restarts the RTO, RFC 6298 5.3).
    last_ack_progress: Instant,
    /// Send time of the most recently sent packet known to be delivered
    /// (RACK, RFC 8985): anything sent noticeably earlier and still missing
    /// is lost.
    rack_sent_at: Option<Instant>,

    // Loss classification: bytes sent and declared lost in the current round
    // (about one RTT), and the smoothed loss rate of completed rounds.
    round_start: Instant,
    round_sent: u64,
    round_lost: u64,
    /// Fast-moving loss rate of recent rounds (diagnostics).
    loss_rate: f64,
    /// Bytes sent and lost in recent rounds without a congestion signal,
    /// decayed per round; their ratio is the path's background
    /// (non-congestive) loss rate. Pooling counts instead of averaging
    /// per-round rates lets large rounds weigh more, so the estimate
    /// converges within a few rounds.
    bg_sent: f64,
    bg_lost: f64,
    /// Whether the current round already saw a congestion signal.
    round_congestive: bool,
    random_loss_events: u64,
    /// Most bytes in flight during the current and the previous round
    /// (whether the congestion window is actually used).
    peak_inflight: u64,
    prev_peak_inflight: u64,

    // Tail loss probes (RFC 8985 section 7).
    last_send_at: Instant,
    tail_probes: u32,
    tail_probe_count: u64,
    /// When the last tail probe went out; the RTO waits for its answer.
    last_tail_probe_at: Instant,
    last_idle_probe: Option<Instant>,

    start: Instant,
    last_rx: Instant,
    last_ping: Instant,
    probe_ts: Vec<u32>,
    stalled: bool,
    ping_backoff: u32,

    bytes_sent: u64,
    retransmitted_bytes: u64,
    healed_bytes: u64,
    rto_events: u64,
    last_progress_at: Instant,
    last_progress_bytes: u64,

    my_hash: Option<[u8; 32]>,
    pending_fin: Option<[u8; 32]>,
    fin_verdict: Option<(u8, Instant, [u8; 32])>,
    /// The receiver confirmed that it got the verdict (FIN_DONE).
    fin_confirmed: bool,

    cache_start: u64,
    cache: Vec<u8>,
    read_buf: Vec<u8>,
    tx_buf: Vec<u8>,
    ctl_buf: Vec<u8>,
    /// Batches between being built and being sent.
    pipe: Pipe,
    /// DATA datagrams of the batch being built, back to back.
    batch: Vec<u8>,
    /// Per datagram of `batch`: where it starts, and the range it carries
    /// (retransmitted or not).
    batch_items: Vec<(usize, u64, u64, bool)>,
    rx_bufs: Vec<Vec<u8>>,
    rx_meta: Vec<Received>,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cfg: TransportConfig,
        socket: Arc<BatchSocket>,
        peer: SocketAddr,
        candidates: Vec<SocketAddr>,
        relay_inboxes: RelayInboxes,
        found_rx: mpsc::UnboundedReceiver<Found>,
        unresolved: Arc<parking_lot::Mutex<Vec<String>>>,
        auth: Peer,
        reader: Arc<Source>,
        file_name: String,
        transfer_id: [u8; 16],
        events: Option<EventCallback>,
        cancel: CancellationToken,
    ) -> Self {
        // Where the receiver may show up from: whatever it was said to be at.
        let peer_ips = candidates
            .iter()
            .map(|a| crate::address::canonical(*a).ip())
            .collect();
        let now = Instant::now();
        let chunk = cfg.max_chunk;
        let cc = Cubic::new(chunk, cfg.initial_cwnd_chunks, cfg.max_cwnd_bytes);
        let mut rtt = RttEstimator::new(cfg.min_rto, cfg.max_rto);
        // Until the receiver announces its own, assume it ACKs like we would.
        rtt.set_max_ack_delay(cfg.ack_interval);
        let rate = cc.pacing_rate(rtt.srtt(), cfg.max_rate_bytes);
        let pacer = Pacer::new(now, rate, burst_for_rate(rate, chunk));
        let size = reader.size();
        Self {
            cfg,
            reach: crate::address::Reach::of(&socket.udp()),
            send_failures: 0,
            mtu_suspect: 0,
            awaiting_decision: None,
            last_decision_poll: None,
            mtu_raise: None,
            socket,
            peer,
            path: PathProbe::new(),
            reader,
            size,
            file_name,
            transfer_id,
            clock: Clock::new(),
            events,
            cancel,
            auth,
            secure: None,
            attempts: VecDeque::new(),
            cookie: None,
            candidates,
            next_candidate: 0,
            relay_inboxes,
            #[cfg(feature = "nat-traversal")]
            stun_inbox: None,
            hits: None,
            #[cfg(feature = "nat-traversal")]
            aux: None,
            found_rx,
            unresolved,
            answered_at: None,
            peer_ips,
            #[cfg(feature = "nat-traversal")]
            reflexive: std::collections::HashMap::new(),
            #[cfg(feature = "nat-traversal")]
            turns: Vec::new(),
            relayed: std::collections::HashSet::new(),
            next_direct_probe: now,
            direct_probes: 0,
            probes_sent: 0,
            answer: None,
            negotiating: true,
            handshake_failures: 0,
            probe_acks: Vec::new(),
            chunk,
            pending: RangeSet::new(),
            inflight: BTreeMap::new(),
            inflight_bytes: 0,
            send_log: VecDeque::new(),
            seq: 0,
            highest_sent: 0,
            rtt,
            cc,
            pacer,
            rwnd: u64::MAX,
            received_bytes: 0,
            max_ack_received: 0,
            resumed_from: 0,
            impossible_acks: 0,
            ack_log: VecDeque::new(),
            last_ack_progress: now,
            rack_sent_at: None,
            round_start: now,
            round_sent: 0,
            round_lost: 0,
            loss_rate: 0.0,
            bg_sent: 0.0,
            bg_lost: 0.0,
            round_congestive: false,
            random_loss_events: 0,
            peak_inflight: 0,
            prev_peak_inflight: 0,
            last_send_at: now,
            tail_probes: 0,
            tail_probe_count: 0,
            last_tail_probe_at: now,
            last_idle_probe: None,
            start: now,
            last_rx: now,
            last_ping: now,
            probe_ts: Vec::new(),
            stalled: false,
            ping_backoff: 0,
            bytes_sent: 0,
            retransmitted_bytes: 0,
            healed_bytes: 0,
            rto_events: 0,
            last_progress_at: now,
            last_progress_bytes: 0,
            my_hash: None,
            pending_fin: None,
            fin_verdict: None,
            fin_confirmed: false,
            cache_start: 0,
            cache: Vec::new(),
            read_buf: Vec::new(),
            tx_buf: Vec::with_capacity(MAX_CHUNK as usize + DATA_OVERHEAD),
            ctl_buf: Vec::with_capacity(MAX_CONTROL_DATAGRAM),
            pipe: Pipe::new(),
            batch: Vec::with_capacity(MAX_SEND_BYTES),
            batch_items: Vec::new(),
            rx_bufs: recv_buffers(RX_BUFFERS),
            rx_meta: vec![
                Received {
                    from: peer,
                    len: 0,
                    stride: 0,
                    dst: None,
                };
                RX_BUFFERS
            ],
        }
    }

    fn tid_hex(&self) -> String {
        hex16(&self.transfer_id)
    }

    /// Handles everything queued on the socket.
    fn drain_socket(&mut self) -> Result<(), SendError> {
        let socket = self.socket.clone();
        self.drain(&socket)?;
        #[cfg(feature = "nat-traversal")]
        if let Some(aux) = self.aux.as_ref().map(|a| a.socket.clone()) {
            self.drain(&aux)?;
        }
        Ok(())
    }

    /// Everything that is queued on `socket`.
    fn drain(&mut self, socket: &BatchSocket) -> Result<(), SendError> {
        for _ in 0..MAX_RECV_CALLS {
            let n = match socket.try_recv(&mut self.rx_bufs, &mut self.rx_meta) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => {
                    tracing::debug!("recv error: {}", e);
                    return Ok(());
                }
            };
            for i in 0..n {
                let r = self.rx_meta[i];
                let mut buf = std::mem::take(&mut self.rx_bufs[i]);
                let mut result = Ok(());
                for d in r.segments() {
                    result = self.on_datagram(&mut buf[d], r.from);
                    if result.is_err() {
                        break;
                    }
                }
                self.rx_bufs[i] = buf;
                result?;
            }
        }
        Ok(())
    }

    /// Encrypts `msg` as a transport packet and sends it to the receiver's
    /// proven address. Without an established session there is nobody to
    /// send it to.
    fn send_frame(&mut self, flags: u8, msg: &Message<'_>) -> io::Result<()> {
        self.send_frame_to(self.peer, flags, msg)
    }

    /// Encrypts `msg` as a transport packet and sends it to `to`. Only
    /// address validation sends anywhere but the proven address, and only
    /// the small PATH_CHALLENGE / PATH_RESPONSE frames: the file itself is
    /// never sent to an address the receiver has not proven.
    fn send_frame_to(&mut self, to: SocketAddr, flags: u8, msg: &Message<'_>) -> io::Result<()> {
        let Some(sec) = self.secure.as_mut() else {
            return Ok(());
        };
        let pn = sec.next_pn;
        sec.next_pn += 1;
        begin_packet(
            &mut self.ctl_buf,
            sec.peer_cid,
            type_byte(msg.msg_type(), flags),
            pn,
        );
        wire::encode_body(msg, &mut self.ctl_buf, MAX_CONTROL_BODY);
        sec.keys
            .send
            .seal(&mut self.ctl_buf)
            .map_err(io::Error::other)?;
        // Towards the address a late meeting was made at, from the socket it
        // was made at: no other socket has a way in there.
        #[cfg(feature = "nat-traversal")]
        let out: &BatchSocket = match &self.aux {
            Some(aux) if aux.peer == to => &aux.socket,
            _ => &self.socket,
        };
        #[cfg(not(feature = "nat-traversal"))]
        let out: &BatchSocket = &self.socket;
        match out.try_send(to, &self.ctl_buf) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || is_no_buffer_error(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Best-effort notice to the receiver that the transfer is over (sent
    /// twice, as nothing acknowledges it).
    fn send_abort(&mut self, code: u16, reason: &str) {
        let msg = Message::Abort(Abort {
            code,
            reason: reason.to_string(),
        });
        for _ in 0..2 {
            let _ = self.send_frame(0, &msg);
        }
    }

    /// The address the next handshake attempt goes to.
    ///
    /// Once a session exists its proven address is the only sensible target.
    /// Before that, attempts rotate through every address the receiver's
    /// name gave us: only one of them may be reachable, and only the
    /// handshake can tell which one is really the receiver.
    fn next_target(&mut self) -> Option<SocketAddr> {
        if self.secure.is_some() {
            // A receiver that has gone silent may simply have moved — its
            // address changed, or it is only reachable through a relay now —
            // so while it is silent the re-handshakes take turns among
            // everything it is known by, its last address first. The
            // answer, if any, says which one it is.
            if !self.stalled || self.candidates.is_empty() {
                return Some(self.peer);
            }
            let others: Vec<SocketAddr> = self
                .candidates
                .iter()
                .copied()
                .filter(|c| *c != self.peer)
                .collect();
            let i = self.next_candidate % (others.len() + 1);
            self.next_candidate = self.next_candidate.wrapping_add(1);
            return Some(if i == 0 { self.peer } else { others[i - 1] });
        }
        // An address that already answered beats carrying on round the ring.
        if let Some(known) = self.answered_at.take() {
            return Some(known);
        }
        // Nothing to try until a relay turns something up.
        if self.candidates.is_empty() {
            return None;
        }
        // Round the ring, however short. A single address used not to move
        // it, so it counted as untried for ever and the handshake never
        // started backing off.
        let target = self.candidates[self.next_candidate % self.candidates.len()];
        self.next_candidate = self.next_candidate.wrapping_add(1);
        Some(target)
    }

    /// Whether any candidate address is still untried. While that holds, the
    /// handshake probes briskly instead of backing off: an address that is
    /// simply dead should not hold up the ones behind it.
    fn candidates_left(&self) -> bool {
        // The ring position, not the number of initiations sent: retries at
        // an address that already answered, and attempts that carry a fresh
        // cookie, do not try anything new, and counting them would end brisk
        // probing while addresses were still untouched.
        self.secure.is_none() && self.next_candidate < self.candidates.len()
    }

    /// Takes in addresses a relay introduction, a name or NAT64 has turned
    /// up. They arrive while the handshake is already trying the ones we
    /// started with, so they simply join the ring — and because they are
    /// untried, probing goes back to being brisk until they have had their
    /// turn.
    fn take_new_candidates(&mut self) {
        while let Ok(found) = self.found_rx.try_recv() {
            self.add_candidate(found);
        }
    }

    /// Moves the handshake to the socket a birthday meeting was made at:
    /// the receiver's NAT lets packets through to that one and to no other.
    /// The packet that made the meeting is handled as if it had come in
    /// here, which answers it — a punch from the receiver is exactly what
    /// draws our first initiation.
    #[cfg(feature = "nat-traversal")]
    async fn adopt_socket(&mut self, hit: Hit) -> Result<(), SendError> {
        let Hit {
            socket,
            from,
            mut datagram,
        } = hit;
        let batch = BatchSocket::wrap(socket).await?;
        tracing::info!(
            "the receiver's NAT let {} through to {}; carrying on from there",
            from,
            batch.local_addr()?
        );
        self.socket = Arc::new(batch);
        self.on_datagram(&mut datagram, from)
    }

    #[cfg(not(feature = "nat-traversal"))]
    async fn adopt_socket(&mut self, hit: Hit) -> Result<(), SendError> {
        match hit {}
    }

    /// Whether a meeting made now is worth taking up: while the session is
    /// carried by a relay or a TURN server, and none is being proven.
    fn can_take_meeting(&self) -> bool {
        #[cfg(feature = "nat-traversal")]
        {
            self.secure.is_some() && self.aux.is_none() && self.is_relayed(self.peer)
        }
        #[cfg(not(feature = "nat-traversal"))]
        {
            false
        }
    }

    /// The socket being proven, for the loop to wait on.
    fn aux_socket(&self) -> Option<Arc<BatchSocket>> {
        #[cfg(feature = "nat-traversal")]
        {
            self.aux.as_ref().map(|a| a.socket.clone())
        }
        #[cfg(not(feature = "nat-traversal"))]
        {
            None
        }
    }

    /// A birthday meeting made after the handshake, while the session is
    /// carried. Before it was, the handshake moved to the socket and the
    /// session was never anywhere else; now the session is up, elsewhere,
    /// and moving it is the same business as moving to any new address —
    /// each end proving the other's — with the difference that the frames
    /// asking go out from the socket the receiver's NAT lets in.
    #[cfg(feature = "nat-traversal")]
    async fn meet_late(&mut self, hit: Hit) {
        let Hit { socket, from, .. } = hit;
        let Ok(batch) = BatchSocket::wrap(socket).await else {
            return;
        };
        let Some(from) = self.reach.native(from) else {
            return;
        };
        tracing::info!(
            "the receiver's NAT let {} through to {} while the session is carried by {}: asking it there",
            from,
            batch.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            self.peer
        );
        self.aux = Some(Aux {
            socket: Arc::new(batch),
            peer: from,
            since: Instant::now(),
        });
        // An address to ask like any other, and at once.
        if self.candidates.len() < MAX_CANDIDATES && !self.candidates.contains(&from) {
            self.candidates.push(from);
        }
        self.peer_ips.insert(crate::address::canonical(from).ip());
        self.next_direct_probe = Instant::now();
    }

    #[cfg(not(feature = "nat-traversal"))]
    async fn meet_late(&mut self, hit: Hit) {
        match hit {}
    }

    /// The receiver has proven `addr`: if that is the address a late meeting
    /// was made at, the socket it was made at is the session's from now on.
    #[cfg(feature = "nat-traversal")]
    fn adopt_aux(&mut self, addr: SocketAddr) {
        if let Some(aux) = self.aux.take_if(|a| a.peer == addr) {
            tracing::info!(
                "the session now runs from {}, where the meeting was made",
                aux.socket
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_default()
            );
            self.socket = aux.socket;
        }
    }

    /// Adds an address that turned up, if it is one we are willing to send
    /// to.
    ///
    /// The screen matters most for a relay's: a relay is not trusted, and
    /// the value is entirely its choice. Without it a hostile one could name
    /// a port on this very host, a multicast or broadcast group, or an
    /// address this socket cannot reach at all, and we would fire handshake
    /// initiations there for the length of the handshake timeout. What it
    /// cannot do is tell an ordinary address from a victim's: any host on
    /// our network or beyond it may be named, and what bounds that is how
    /// little is sent — a handful of initiations, a quarter of a second
    /// apart, that draw no answer from anyone but the receiver. A name the
    /// user gave may point at this host (see
    /// `address::class::is_sendable_named`).
    fn add_candidate(&mut self, found: Found) {
        let local = self.socket.local_addr().unwrap_or(self.peer);
        let (addr, usable) = match found {
            Found::Relay(a) | Found::Carrier(a) => {
                (a, crate::address::class::is_sendable_hint(a, local))
            }
            Found::Named(a) => (a, crate::address::class::is_sendable_named(a, local)),
            // Only an address one of our own allocations made; anybody else's
            // loopback is what the screen above exists to refuse.
            #[cfg(feature = "nat-traversal")]
            Found::Turn(a) => (a, self.turns.iter().any(|t| t.is_shim(a))),
            #[cfg(not(feature = "nat-traversal"))]
            Found::Turn(a) => (a, false),
        };
        if !usable {
            tracing::debug!("ignoring {}: not an address worth sending to", addr);
            return;
        }
        // Written as replies from it will arrive, like every other
        // candidate.
        let Some(addr) = self.reach.native(addr) else {
            return;
        };
        if self.candidates.len() >= MAX_CANDIDATES || self.candidates.contains(&addr) {
            return;
        }
        tracing::debug!("another address to try: {}", addr);
        // What a relay carries is not where the receiver is, and is no
        // evidence of where it might turn up from: it is somewhere to be
        // carried, and a way through until a direct one opens.
        if matches!(found, Found::Carrier(_)) {
            self.relayed.insert(crate::address::canonical(addr));
        } else {
            self.peer_ips.insert(crate::address::canonical(addr).ip());
        }
        self.candidates.push(addr);
    }

    /// A punch from an address that is not one we were given, but whose IP
    /// is the receiver's: it opens a hole from its side to ours, and the
    /// port it comes from is where the receiver's NAT will take our packets.
    /// Answer it at once, from here, so that the hole is used while it is
    /// open — the first initiation to the same address that would otherwise
    /// wait for its turn in the rotation is lost to a NAT that has not heard
    /// from us yet, and the next may come after the receiver has stopped.
    ///
    /// Punches are unauthenticated, so what this does is bounded: only an
    /// address whose IP we already had reason to try, a few addresses, a
    /// few initiations each, spaced apart. It never changes who is trusted:
    /// only the receiver's key can answer.
    #[cfg(feature = "nat-traversal")]
    fn on_punch(&mut self, from: SocketAddr) -> Result<(), SendError> {
        /// Ports a receiver may be seen from before we stop believing it.
        const MAX_REFLEXIVE: usize = 16;
        /// Initiations one such port gets.
        const PER_ADDRESS: u32 = 12;
        /// Least time between two.
        const GAP: Duration = Duration::from_millis(80);
        // A session that is already direct has nothing to gain; one that is
        // being carried does, and what the receiver's punch shows of where
        // it can be reached directly is what it is looking for.
        let carried = self.secure.is_some() && self.is_relayed(self.peer);
        if self.secure.is_some() && !carried {
            return Ok(());
        }
        // A punch that came through one of our own TURN allocations is the
        // receiver's, sent to the address on the server we gave it: what it
        // sent from is one address on loopback, and the only way to answer.
        let via_turn = self.turns.iter().any(|t| t.is_shim(from));
        if !via_turn {
            let ip = crate::address::canonical(from).ip();
            if !self.peer_ips.contains(&ip) {
                return Ok(());
            }
            let local = self.socket.local_addr().unwrap_or(self.peer);
            if !crate::address::class::is_sendable_hint(from, local) {
                return Ok(());
            }
        }
        let now = Instant::now();
        if !self.reflexive.contains_key(&from) && self.reflexive.len() >= MAX_REFLEXIVE {
            return Ok(());
        }
        let entry = self.reflexive.entry(from).or_insert((0, now - GAP));
        if entry.0 >= PER_ADDRESS || now.saturating_duration_since(entry.1) < GAP {
            return Ok(());
        }
        let first = entry.0 == 0;
        entry.0 += 1;
        entry.1 = now;
        if first {
            tracing::info!(
                "the receiver's NAT let a datagram through from {}; answering it there",
                from
            );
            self.add_candidate(if via_turn {
                Found::Turn(from)
            } else {
                Found::Relay(from)
            });
            if !carried {
                self.answered_at = Some(from);
            }
        }
        if carried {
            // The session is up; what is asked is whether the receiver
            // answers on this path too (see `probe_direct`).
            let ping = self.ping_message();
            if let Some(to) = self.reach.native(from) {
                let _ = self.send_frame_to(to, 0, &ping);
            }
            return Ok(());
        }
        self.send_initiation_to(self.reach.native(from))
    }

    /// Starts a new handshake attempt: a fresh ephemeral key and connection
    /// id, carrying HELLO. The receiver answers with its current state.
    fn send_initiation(&mut self) -> Result<(), SendError> {
        self.send_initiation_to(None)
    }

    /// [`Engine::send_initiation`] aimed at a given address instead of the
    /// next candidate in the rotation.
    fn send_initiation_to(&mut self, to: Option<SocketAddr>) -> Result<(), SendError> {
        let now = Instant::now();
        let Some(to) = to.or_else(|| self.next_target()) else {
            return Ok(());
        };
        let mut attempt = Initiator::new(&self.auth.identity, &self.auth.receiver, &self.auth.psk)
            .map_err(|e| SendError::Handshake(e.to_string()))?;
        let ts = self.clock.now_us().max(1);
        let payload = wire::encode_initiation(&wire::Initiation {
            timestamp: hs::initiation_timestamp(),
            suites: Suite::ALL_BITS,
            hardware_aes: Suite::hardware_aes(),
            hello_flags: HELLO_FLAG_RESUME,
            hello: self.hello(ts),
        });
        // A cookie proves our address to one receiver, so it is only worth
        // anything at the address that issued it.
        let cookie = self
            .cookie
            .filter(|(_, at, from)| {
                *from == to && now.saturating_duration_since(*at) < hs::COOKIE_LIFETIME
            })
            .map(|(c, _, _)| c);
        let pkt = attempt
            .initiation(&payload, cookie.as_ref())
            .map_err(|e| SendError::Handshake(e.to_string()))?;
        match self.socket.try_send(to, &pkt) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || is_no_buffer_error(&e) => {}
            // Never the end of the transfer. One unreachable address (a
            // broken IPv6 path, say) must not end it while others are
            // untried, and a network that is gone for a moment — a Wi-Fi
            // hand-over, an interface coming back up — must not end it
            // either: the handshake has its own deadline, and a session
            // its own rules for when the peer is gone.
            Err(e) => {
                self.send_failures += 1;
                if self.send_failures.is_power_of_two() {
                    tracing::info!(
                        "cannot send to {} ({}; {} time(s) so far)",
                        to,
                        e,
                        self.send_failures
                    );
                }
                return Ok(());
            }
        }
        if self.attempts.len() >= MAX_ATTEMPTS {
            self.attempts.pop_front();
        }
        self.attempts.push_back((attempt, now, to));
        self.probes_sent += 1;
        tracing::debug!(
            "handshake initiation sent to {} ({})",
            to,
            self.auth.receiver.short()
        );
        Ok(())
    }

    /// A datagram addressed to one of our handshake attempts: a response or
    /// a cookie reply.
    fn on_handshake_reply(
        &mut self,
        idx: usize,
        pkt: &[u8],
        from: SocketAddr,
    ) -> Result<(), SendError> {
        let (sent_at, target) = (self.attempts[idx].1, self.attempts[idx].2);
        if pkt.len() == COOKIE_REPLY_LEN {
            // A cookie proves our address to the receiver we sent to, so
            // only a reply from there is worth keeping. Anybody who saw the
            // initiation can make one (see below), and keeping whichever
            // came last let them replace the real one with theirs.
            if from != target {
                return Ok(());
            }
            if let Some(cookie) = self.attempts[idx].0.read_cookie_reply(pkt) {
                tracing::debug!("{} is under load and asked for a cookie", target);
                // Keep it for the next scheduled attempt, and send nothing
                // now. A cookie reply is sealed under a key derived from the
                // receiver's *public* key, with the initiation's own mac1 as
                // associated data, so anybody who receives one initiation can
                // mint a convincing reply. Starting a fresh handshake on the
                // strength of one would let them spin us through Noise
                // initiations — a few hundred bytes and a static-static DH
                // each — as fast as they cared to send 64-byte forgeries.
                // WireGuard carries the cookie on the next retry for the same
                // reason; so do we. A real receiver under load loses nothing
                // but the wait it was asking for anyway.
                self.cookie = Some((cookie, Instant::now(), target));
            }
            return Ok(());
        }
        // Authenticated before anything is believed or used up. The
        // connection id this is addressed to travels in the clear, so it
        // may come from anyone who saw the initiation; a failed read leaves
        // the attempt ready for the real answer.
        let read = self.attempts[idx].0.read_response(pkt);
        let (receiver_cid, payload, split) = match read {
            Ok(v) => v,
            Err(e) => {
                if self.attempts[idx].0.is_spent() {
                    self.attempts.remove(idx);
                }
                match e {
                    // Not made by the receiver we talk to; ignore.
                    CryptoError::Mac | CryptoError::Malformed => {}
                    // The receiver authenticated our initiation but its
                    // response does not decrypt: it mixes in a different
                    // pre-shared key — or somebody who knows our public key
                    // is sending rubbish, which costs them the same.
                    e => {
                        self.handshake_failures += 1;
                        tracing::debug!("handshake response rejected: {}", e);
                    }
                }
                return Ok(());
            }
        };
        let now = Instant::now();
        // However it ends, the round trip is real and worth knowing: it is
        // how long the next attempt must at least wait (see `handshake`).
        self.rtt.on_sample(now.saturating_duration_since(sent_at));
        let (attempt, _, _) = self.attempts.remove(idx).expect("index in range");
        // Only the newest attempt may be adopted, and that is not a detail:
        // when several initiations are outstanding, both ends have to agree
        // on which one won. The receiver's replay guard already decides it —
        // initiation timestamps must increase, so an older one arriving late
        // is refused and the receiver keeps the newest it saw. Adopting an
        // older response here would leave the two sides holding different
        // keys and connection ids, and the transfer would stall until the
        // next re-handshake.
        //
        // A superseded answer is not wasted, though: it proves that address
        // answers, so the next initiation goes straight back to it instead
        // of carrying on round the candidates — and not before its round
        // trip has had time to complete.
        if idx < self.attempts.len() {
            if self.answered_at != Some(target) {
                tracing::debug!("{} answered a superseded attempt; trying it again", target);
                self.answered_at = Some(target);
            }
            return Ok(());
        }
        let cid = attempt.cid();
        let resp = wire::decode_response(&payload)
            .map_err(|e| SendError::Protocol(format!("bad handshake response: {}", e)))?;
        // Busy is a state, not a verdict. In the middle of a transfer it
        // means the receiver has no room for the session right now — after
        // it restarted, say — and the transfer should wait and ask again,
        // as for any silence, rather than end and throw its state away.
        if resp.ack.status == HELLO_REJECTED
            && resp.ack.reason == REASON_BUSY
            && self.secure.is_some()
        {
            tracing::info!("the receiver has no room for the transfer right now; waiting");
            return Ok(());
        }
        if resp.ack.status == HELLO_REJECTED {
            return Err(SendError::Rejected {
                reason: reason_name(resp.ack.reason).to_string(),
                message: resp.ack.message,
            });
        }
        let suite = Suite::from_u8(resp.suite)
            .ok_or_else(|| SendError::Protocol("receiver chose an unknown cipher".into()))?;
        self.secure = Some(Secure {
            keys: Arc::new(SessionKeys::derive(&split, true, suite)),
            local_cid: cid,
            peer_cid: receiver_cid,
            next_pn: 0,
            replay: ReplayWindow::new(),
            auth_failures: 0,
        });
        // Older attempts are obsolete now.
        self.attempts.clear();
        // We sent this attempt to `target` and got back an answer bound to
        // it, so `target` is reachable and is the receiver: that round trip
        // is the proof, and it settles which of the candidate addresses a
        // name resolved to is the real one.
        if self.peer != target {
            tracing::info!("receiver answered at {}", target);
            self.peer = target;
        }
        // The new keys are in place, so liveness and — when the answer came
        // from an address we have not proven — its validation can both run
        // under them. A handshake response is authentic, but authenticity
        // says nothing about where it was sent from: it could have been
        // captured and repeated with a forged source. Until that address
        // answers a challenge, the file keeps going to the proven one.
        self.path.reset();
        self.note_alive(now, from, pkt.len());
        tracing::debug!(
            "session with {} established ({})",
            self.auth.receiver.short(),
            suite.name()
        );
        self.answer = Some(resp.ack);
        Ok(())
    }

    fn hello(&self, ts: u32) -> Hello {
        Hello {
            transfer_id: self.transfer_id,
            timestamp: ts,
            file_size: self.size,
            file_mtime: self.reader.mtime_unix(),
            max_chunk: self.cfg.max_chunk,
            capabilities: SUPPORTED_CAPS,
            tree: self.reader.tree_info(),
            file_name: self.file_name.clone(),
        }
    }

    // ----- handshake -------------------------------------------------------

    async fn handshake(&mut self) -> Result<HelloAck, SendError> {
        let deadline = Instant::now() + self.cfg.handshake_timeout;
        let mut delay = Duration::from_millis(250);
        let mut next_attempt = Instant::now();
        let mut next_poll: Option<Instant> = None;
        let mut socket = self.socket.clone();
        let cancel = self.cancel.clone();
        loop {
            if cancel.is_cancelled() {
                return Err(SendError::Cancelled);
            }
            let now = Instant::now();
            self.take_new_candidates();
            if let Some(ack) = self.answer.take() {
                match ack.status {
                    HELLO_ACCEPTED => {
                        if ack.capabilities & !SUPPORTED_CAPS != 0 {
                            return Err(SendError::Protocol(format!(
                                "receiver confirmed capabilities {:#x} that were not offered",
                                ack.capabilities & !SUPPORTED_CAPS
                            )));
                        }
                        return Ok(ack);
                    }
                    HELLO_REJECTED => {
                        return Err(SendError::Rejected {
                            reason: reason_name(ack.reason).to_string(),
                            message: ack.message,
                        })
                    }
                    _ => {
                        // The receiver's user is deciding; keep asking.
                        if next_poll.is_none() {
                            tracing::info!("waiting for the receiver to accept the transfer");
                        }
                        next_poll.get_or_insert(now + DECISION_POLL);
                    }
                }
            }
            if now >= deadline {
                return Err(if next_poll.is_some() {
                    SendError::Rejected {
                        reason: reason_name(REASON_TIMEOUT).to_string(),
                        message: "no decision in time".into(),
                    }
                } else if self.handshake_failures > 0 {
                    SendError::Handshake(
                        "the receiver answered, but its keys do not match ours \
                         (different shared secret?)"
                            .into(),
                    )
                } else {
                    SendError::HandshakeTimeout
                });
            }
            if self.secure.is_none() && now >= next_attempt {
                let brisk = self.candidates_left();
                self.send_initiation()?;
                let step = if brisk {
                    // Still addresses nobody has tried. A dead one must not
                    // hold up the rest, so keep the probes close together
                    // and start backing off only once the ring is complete.
                    CANDIDATE_PROBE
                } else {
                    let d = delay;
                    delay = (delay * 2).min(Duration::from_secs(4));
                    d
                };
                // And never sooner than an answer could be back. Only the
                // newest attempt can be adopted, so on a path slower than
                // the retry interval every answer used to arrive after a
                // newer attempt had replaced the one it answered — and the
                // handshake never completed. Once any answer has shown how
                // long the round trip is, the retries wait that long.
                let patience = if self.rtt.has_sample() {
                    self.rtt.srtt() * 3 / 2 + Duration::from_millis(20)
                } else {
                    Duration::ZERO
                };
                next_attempt = now + step.max(patience);
            }
            if let Some(at) = next_poll {
                if now >= at {
                    let ts = self.clock.now_us().max(1);
                    self.probe_ts.push(ts);
                    let hello = Message::Hello(self.hello(ts));
                    // Lost like any datagram if it cannot be sent; the
                    // next poll asks again.
                    let _ = self.send_frame(HELLO_FLAG_RESUME, &hello);
                    next_poll = Some(now + DECISION_POLL);
                }
            }

            let mut wake = deadline;
            if self.secure.is_none() {
                wake = wake.min(next_attempt);
            }
            if let Some(at) = next_poll {
                wake = wake.min(at);
            }
            // An introduction can arrive at any point, including after the
            // retry delay has doubled its way up to seconds. Without an arm
            // of its own the engine would sleep through it, which is exactly
            // what moving the introductions off the critical path was meant
            // to avoid.
            let mut found = None;
            // Once every relay, name and NAT64 task is done the channel is
            // closed, and a closed channel is always ready: without the
            // guard this loop would spin for as long as the handshake lasts.
            let finders_pending = !self.found_rx.is_closed();
            // With nothing to try and nothing left that could turn up
            // something, waiting out the handshake timeout would only
            // postpone the error.
            if !finders_pending && self.candidates.is_empty() && self.secure.is_none() {
                self.take_new_candidates();
                if self.candidates.is_empty() {
                    let why = self.unresolved.lock().join("; ");
                    return Err(SendError::Unreachable(if why.is_empty() {
                        "no address of the receiver could be used".to_string()
                    } else {
                        why
                    }));
                }
            }
            let mut hit = None;
            let hits_pending = self.hits.is_some() && self.secure.is_none();
            tokio::select! {
                r = socket.readable() => { let _ = r; }
                a = self.found_rx.recv(), if finders_pending => { found = a; }
                h = async { self.hits.as_mut().unwrap().recv().await }, if hits_pending => { hit = h; }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
                _ = cancel.cancelled() => return Err(SendError::Cancelled),
            }
            if let Some(hit) = hit {
                self.adopt_socket(hit).await?;
                socket = self.socket.clone();
            }
            if let Some(found) = found {
                let before = self.candidates.len();
                self.add_candidate(found);
                if self.candidates.len() != before {
                    // Untried, so probe it now rather than after the backoff.
                    next_attempt = Instant::now();
                }
            }
            self.drain_socket()?;
        }
    }

    /// Rebuilds `pending` from the receiver's description of what it holds
    /// (HELLO_ACK), discarding all in-flight bookkeeping.
    fn apply_receiver_state(&mut self, ack: &HelloAck) {
        self.rwnd = ack.rwnd.max(2 * self.chunk as u64);
        self.rtt.set_max_ack_delay(
            Duration::from_micros(ack.max_ack_delay_us as u64).min(MAX_PEER_ACK_DELAY),
        );
        let mut pending = RangeSet::new();
        for &(s, e) in &ack.holes {
            let e = e.min(self.size);
            if s < e {
                pending.insert(s, e);
            }
        }
        if ack.known_end < self.size {
            pending.insert(ack.known_end, self.size);
        }
        self.pending = pending;
        self.inflight.clear();
        self.inflight_bytes = 0;
        self.send_log.clear();
        self.highest_sent = self.highest_sent.max(ack.known_end.min(self.size));
        let have = self.size - self.pending.total();
        self.received_bytes = have;
        self.max_ack_received = have;
        self.last_ack_progress = Instant::now();
    }

    /// Applies the handshake answer: negotiated chunk, receive window and
    /// what to send.
    fn apply_hello_ack(&mut self, ack: &HelloAck) {
        let negotiated = self.family_chunk(ack.max_chunk.min(self.cfg.max_chunk).max(MIN_CHUNK));
        self.set_chunk(negotiated);
        self.apply_receiver_state(ack);
        self.resumed_from = self.received_bytes;
        tracing::info!(
            "transfer {} accepted by {}: chunk {} B, {} B already at receiver, {} B to send",
            self.tid_hex(),
            self.peer,
            self.chunk,
            self.resumed_from,
            self.pending.total()
        );
    }

    /// Re-synchronises with the receiver after silence (answer to a probe HELLO).
    fn resync(&mut self, ack: &HelloAck, now: Instant) {
        let before = self.pending.total() + self.inflight_bytes;
        self.apply_receiver_state(ack);
        // Keep the probed chunk size: the path may not carry the negotiated one.
        let chunk = self.family_chunk(self.chunk.min(ack.max_chunk.max(MIN_CHUNK)));
        if chunk != self.chunk {
            self.set_chunk(chunk);
        }
        self.cc.on_rto(now);
        self.rtt.reset_backoff();
        self.update_pacer();
        tracing::info!(
            "re-synchronised with receiver: {} B outstanding (was {} B)",
            self.pending.total(),
            before
        );
    }

    /// `chunk`, or less where the path's address family cannot carry it:
    /// when the configuration leaves the chunk at its default, which fits a
    /// 1500-byte MTU over IPv4, a path over IPv6 — whose header is 20 bytes
    /// longer — starts at the size that fits there instead of finding out
    /// by losing a probe.
    fn family_chunk(&self, chunk: u16) -> u16 {
        if self.cfg.max_chunk == DEFAULT_CHUNK && crate::address::canonical(self.peer).is_ipv6() {
            chunk.min(DEFAULT_CHUNK_V6)
        } else {
            chunk
        }
    }

    fn set_chunk(&mut self, chunk: u16) {
        self.chunk = chunk;
        self.cc.set_mss(chunk);
        self.update_pacer();
    }

    fn update_pacer(&mut self) {
        let rate = self
            .cc
            .pacing_rate(self.rtt.srtt(), self.cfg.max_rate_bytes);
        self.pacer.set_rate(rate);
        self.pacer.set_burst(burst_for_rate(rate, self.chunk));
    }

    // ----- path MTU probe --------------------------------------------------

    async fn probe_mtu(&mut self) -> Result<(), SendError> {
        if !self.cfg.probe_mtu {
            return Ok(());
        }
        // 1500 bytes over IPv4, then 1500 over IPv6 — which is also 1492
        // over IPv4, the PPPoE links DSL runs on — then what every path
        // carries.
        let mut candidates: Vec<u16> =
            vec![self.chunk, DEFAULT_CHUNK, DEFAULT_CHUNK_V6, SAFE_CHUNK];
        // Through a TURN server the way is longer by the server's framing,
        // and the loopback the engine sends to says nothing of it: only the
        // size every path carries is known to fit.
        #[cfg(feature = "nat-traversal")]
        if self.turns.iter().any(|t| t.is_shim(self.peer)) {
            candidates = vec![SAFE_CHUNK];
        }
        candidates.retain(|&c| c <= self.chunk && c >= MIN_CHUNK);
        candidates.sort_unstable_by(|a, b| b.cmp(a));
        candidates.dedup();

        let socket = self.socket.clone();
        let wait = (self.rtt.srtt() * 3).clamp(Duration::from_millis(150), Duration::from_secs(2));
        for cand in candidates {
            let size = (cand as usize + DATA_OVERHEAD) as u16;
            let mut acked = false;
            'attempts: for _ in 0..2 {
                match self.send_frame(0, &Message::Probe(Probe { size })) {
                    Ok(()) => {}
                    Err(e) if is_msgsize_error(&e) => {
                        tracing::debug!("probe {} B rejected locally (EMSGSIZE)", size);
                        break 'attempts;
                    }
                    Err(e) => {
                        tracing::debug!("probe send error: {}", e);
                        break 'attempts;
                    }
                }
                let deadline = Instant::now() + wait;
                loop {
                    if self.probe_acks.contains(&size) {
                        acked = true;
                        break 'attempts;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    tokio::select! {
                        r = socket.readable() => { let _ = r; }
                        _ = tokio::time::sleep(deadline - now) => break,
                        _ = self.cancel.cancelled() => return Err(SendError::Cancelled),
                    }
                    self.drain_socket()?;
                }
            }
            if acked {
                if cand != self.chunk {
                    tracing::info!("path MTU probe: using {} byte chunks", cand);
                }
                self.set_chunk(cand);
                return Ok(());
            }
        }
        // Nothing answered; fall back to the safe size and let the transfer
        // itself discover whether the path works at all.
        let fallback = SAFE_CHUNK.min(self.chunk);
        tracing::warn!(
            "no probe answered; falling back to {} byte chunks",
            fallback
        );
        self.set_chunk(fallback);
        Ok(())
    }

    // ----- main loop -------------------------------------------------------

    async fn run(
        &mut self,
        hash_task: JoinHandle<io::Result<[u8; 32]>>,
    ) -> Result<TransferSummary, SendError> {
        let ack = self.handshake().await?;
        self.negotiating = false;
        self.apply_hello_ack(&ack);
        self.probe_mtu().await?;
        self.start = Instant::now();
        self.last_progress_at = self.start;
        self.last_progress_bytes = self.received_bytes;
        let cipher = self
            .secure
            .as_ref()
            .map(|s| s.keys.suite.name())
            .unwrap_or("none");
        tracing::info!(
            "sending to {} ({}), encrypted with {}",
            self.peer,
            self.auth.receiver,
            cipher
        );
        emit(
            &self.events,
            TransferEvent::Started {
                transfer_id: self.tid_hex(),
                peer: self.peer.to_string(),
                peer_id: self.auth.receiver.to_string(),
                cipher: cipher.to_string(),
                file_name: self.file_name.clone(),
                file_size: self.size,
                directory: self.reader.tree_info().map(|t| DirectoryInfo {
                    files: t.files,
                    dirs: t.dirs,
                }),
                resumed_from: self.resumed_from,
                chunk_size: self.chunk,
            },
        );

        let mut hash_task = Some(hash_task);
        let mut socket = self.socket.clone();
        let cancel = self.cancel.clone();
        let mut next_tick = Instant::now() + TICK;
        let mut next_progress = Instant::now() + self.cfg.progress_interval;

        loop {
            if cancel.is_cancelled() {
                return Err(SendError::Cancelled);
            }

            // 1. Input: everything that is already queued on the socket. The
            // socket may have changed since: a late birthday meeting whose
            // address the receiver has proven is where the session runs now.
            if !Arc::ptr_eq(&socket, &self.socket) {
                socket = self.socket.clone();
            }
            self.drain_socket()?;
            // An answer to a re-handshake or state query: adopt the
            // receiver's view of what it holds.
            if let Some(ack) = self.answer.take() {
                match ack.status {
                    HELLO_ACCEPTED => {
                        if self.awaiting_decision.take().is_some() {
                            tracing::info!("the receiver accepted the transfer again");
                        }
                        self.resync(&ack, Instant::now())
                    }
                    HELLO_REJECTED => {
                        return Err(SendError::Rejected {
                            reason: reason_name(ack.reason).to_string(),
                            message: ack.message,
                        })
                    }
                    // A receiver that lost the session — it restarted — asks
                    // its user again. Ignoring that used to leave us sending
                    // into a session that took nothing, re-handshaking, and
                    // having it ask again: a prompt every few seconds, for
                    // ever, and never the user's answer. So wait for the
                    // decision, asking for it as during the first handshake.
                    _ => {
                        if self.awaiting_decision.is_none() {
                            tracing::info!("the receiver is asking its user again; waiting");
                            self.awaiting_decision = Some(Instant::now());
                        }
                    }
                }
            }

            // 2. Local whole-file hash finished?
            if hash_task.as_ref().is_some_and(|h| h.is_finished()) {
                let task = hash_task.take().expect("checked above");
                let hash = task
                    .await
                    .map_err(|e| SendError::Protocol(format!("hash task failed: {}", e)))??;
                self.my_hash = Some(hash);
                if let Some(theirs) = self.pending_fin.take() {
                    self.answer_fin(theirs, Instant::now())?;
                }
            }

            // 3. Timers.
            let now = Instant::now();
            if now >= next_tick {
                self.housekeeping(now)?;
                next_tick = now + TICK;
            }
            if now >= next_progress {
                self.emit_progress(now);
                next_progress = now + self.cfg.progress_interval;
            }
            if let Some(summary) = self.finished(now)? {
                return Ok(summary);
            }

            // 4. Output.
            let block = self.fill_window(now)?;

            // 5. Wait for the next event.
            let mut deadline = next_tick.min(next_progress);
            let mut want_write = false;
            match block {
                SendBlock::Yield => {
                    tokio::task::yield_now().await;
                    continue;
                }
                SendBlock::Pacer(d) => deadline = deadline.min(now + d),
                SendBlock::Socket => want_write = true,
                SendBlock::Idle | SendBlock::Window | SendBlock::Pipeline => {}
            }
            let sealing = self.pipe.in_pool > 0;
            // While the session is carried, a meeting made at a socket of
            // ours is a way to a direct path; and the socket of one being
            // proven is read alongside this one.
            let aux_socket = self.aux_socket();
            let hits_open = self.hits.is_some() && self.can_take_meeting();
            let mut late_hit = None;
            tokio::select! {
                r = socket.readable() => { let _ = r; }
                r = socket.writable(), if want_write => { let _ = r; }
                r = async { aux_socket.as_ref().unwrap().readable().await }, if aux_socket.is_some() => { let _ = r; }
                h = async { self.hits.as_mut().unwrap().recv().await }, if hits_open => { late_hit = h; }
                r = self.pipe.results.recv(), if sealing => {
                    if let Some(batch) = r {
                        self.pipe.in_pool -= 1;
                        self.pipe.ready.insert(batch.seq, batch);
                    }
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
                _ = cancel.cancelled() => {}
            }
            if let Some(hit) = late_hit {
                self.meet_late(hit).await;
            }
        }
    }

    /// Checks whether the transfer has reached a terminal state.
    fn finished(&mut self, now: Instant) -> Result<Option<TransferSummary>, SendError> {
        let Some((verdict, at, receiver_hash)) = self.fin_verdict else {
            return Ok(None);
        };
        // Until the receiver confirms the verdict (FIN_DONE), stay to answer
        // a repeated FIN in case our FIN_ACK was lost. This only costs time
        // when FIN_ACK or FIN_DONE was actually lost.
        let linger = (FIN_LINGER_BASE + self.rtt.srtt() * 4).min(FIN_LINGER_MAX);
        if !self.fin_confirmed && now.saturating_duration_since(at) < linger {
            return Ok(None);
        }
        let my_hash = self.my_hash.unwrap_or([0u8; 32]);
        if verdict == VERDICT_OK {
            let elapsed = self.start.elapsed();
            let moved = self.size.saturating_sub(self.resumed_from);
            let summary = TransferSummary {
                transfer_id: self.tid_hex(),
                file_size: self.size,
                resumed_from: self.resumed_from,
                bytes_sent: self.bytes_sent,
                retransmitted_bytes: self.retransmitted_bytes,
                loss_events: self.cc.loss_events(),
                rto_events: self.rto_events,
                chunk_size: self.chunk,
                elapsed,
                avg_rate_bps: if elapsed.as_secs_f64() > 0.0 {
                    moved as f64 * 8.0 / elapsed.as_secs_f64()
                } else {
                    0.0
                },
                file_hash_hex: hash_to_hex(&my_hash),
            };
            let stats = self.stats(now);
            emit(
                &self.events,
                TransferEvent::Completed {
                    transfer_id: self.tid_hex(),
                    file_name: self.file_name.clone(),
                    path: None,
                    file_hash_hex: summary.file_hash_hex.clone(),
                    peer_confirmed: true,
                    stats,
                },
            );
            return Ok(Some(summary));
        }
        let err = SendError::HashMismatch {
            sender: hash_to_hex(&my_hash),
            receiver: hash_to_hex(&receiver_hash),
        };
        emit(
            &self.events,
            TransferEvent::Failed {
                transfer_id: self.tid_hex(),
                error: err.to_string(),
                resumable: false,
            },
        );
        Err(err)
    }

    // ----- sending ---------------------------------------------------------

    fn window(&self) -> u64 {
        self.cc.cwnd().min(self.rwnd).max(2 * self.chunk as u64)
    }

    /// Makes the payload for `[s, e)` available, from the read-ahead block
    /// for new data or with a direct read for retransmissions.
    fn load_payload(&mut self, s: u64, e: u64, retransmit: bool) -> io::Result<PayloadSrc> {
        let cache_end = self.cache_start + self.cache.len() as u64;
        if !self.cache.is_empty() && s >= self.cache_start && e <= cache_end {
            return Ok(PayloadSrc::Cache(
                (s - self.cache_start) as usize,
                (e - self.cache_start) as usize,
            ));
        }
        if !retransmit {
            let end = s.saturating_add(BLOCK_SIZE).min(self.size).max(e);
            self.cache.resize((end - s) as usize, 0);
            if let Err(err) = self.reader.read_at(s, &mut self.cache) {
                self.cache.clear();
                return Err(err);
            }
            self.cache_start = s;
            return Ok(PayloadSrc::Cache(0, (e - s) as usize));
        }
        self.read_buf.resize((e - s) as usize, 0);
        self.reader.read_at(s, &mut self.read_buf)?;
        Ok(PayloadSrc::Buf)
    }

    fn fill_window(&mut self, now: Instant) -> Result<SendBlock, SendError> {
        while let Ok(batch) = self.pipe.results.try_recv() {
            self.pipe.in_pool -= 1;
            self.pipe.ready.insert(batch.seq, batch);
        }
        if let Some(block) = self.flush_ready()? {
            return Ok(block);
        }
        // Nothing to send while the receiver's user decides: the session
        // would take none of it.
        if self.stalled
            || self.fin_verdict.is_some()
            || self.pending_fin.is_some()
            || self.secure.is_none()
            || self.awaiting_decision.is_some()
        {
            return Ok(SendBlock::Idle);
        }
        self.pacer.refill(now);
        let mut sent_in_call = 0usize;
        loop {
            if self.pipe.len() >= MAX_PIPELINE {
                return Ok(SendBlock::Pipeline);
            }
            let block = self.build_batch(now)?;
            if !self.batch_items.is_empty() {
                sent_in_call += self.batch_items.len();
                self.record_sent(now);
                self.dispatch_batch();
                if let Some(b) = self.flush_ready()? {
                    return Ok(b);
                }
            }
            if let Some(b) = block {
                return Ok(b);
            }
            if sent_in_call >= MAX_BATCH {
                return Ok(SendBlock::Yield);
            }
        }
    }

    /// Builds the next batch of DATA datagrams, unencrypted, in `batch`: as
    /// many as the window, the pacer and one segmented send allow. Every
    /// datagram of a batch but the last has the full size. Returns why the
    /// batch ended early, if it did.
    fn build_batch(&mut self, now: Instant) -> Result<Option<SendBlock>, SendError> {
        self.batch.clear();
        self.batch_items.clear();
        let chunk = self.chunk as u64;
        let full = self.chunk as usize + DATA_OVERHEAD;
        // A segmented send leaves as one burst; keep it to about a
        // millisecond at the pacing rate (as TCP sizes its offload bursts)
        // so that shallow buffers on the path are not overrun.
        let burst = (self.pacer.rate() * BATCH_BURST.as_secs_f64() / full as f64) as usize;
        let max_items = self
            .socket
            .max_segments()
            .min(MAX_SEND_BYTES / full)
            .min(burst.max(2))
            .max(1);
        let mut outstanding = self.inflight_bytes;
        let ts = self.clock.now_us_at(now).max(1);
        let mut block = None;
        while self.batch_items.len() < max_items {
            if self.pending.is_empty() {
                block = Some(SendBlock::Idle);
                break;
            }
            if outstanding > 0 && outstanding + chunk > self.window() {
                block = Some(SendBlock::Window);
                break;
            }
            if !self.pacer.try_take(chunk) {
                block = Some(SendBlock::Pacer(self.pacer.delay_for(chunk)));
                break;
            }
            let Some((s, e)) = self.pending.take_first(chunk) else {
                block = Some(SendBlock::Idle);
                break;
            };
            let retransmit = s < self.highest_sent;
            let src = match self.load_payload(s, e, retransmit) {
                Ok(src) => src,
                Err(err) => {
                    self.pending.insert(s, e);
                    self.pacer.refund(chunk);
                    self.unbuild_batch();
                    return Err(SendError::Io(err));
                }
            };
            let sec = self.secure.as_mut().expect("checked by fill_window");
            let at = self.batch.len();
            let pn = sec.next_pn;
            sec.next_pn += 1;
            let flags = if retransmit { DATA_FLAG_RETRANSMIT } else { 0 };
            push_header(
                &mut self.batch,
                sec.peer_cid,
                type_byte(MsgType::Data, flags),
                pn,
            );
            self.batch.extend_from_slice(&s.to_be_bytes());
            self.batch.extend_from_slice(&ts.to_be_bytes());
            let payload: &[u8] = match src {
                PayloadSrc::Cache(a, b) => &self.cache[a..b],
                PayloadSrc::Buf => &self.read_buf[..],
            };
            self.batch.extend_from_slice(payload);
            self.batch.extend_from_slice(&[0u8; TAG_LEN]);
            self.batch_items.push((at, s, e, retransmit));
            outstanding += e - s;
            if e - s < chunk {
                // Only the last datagram of a segmented send may be shorter.
                break;
            }
        }
        Ok(block)
    }

    /// Puts the ranges of a batch that was built but not counted as sent
    /// back, and returns their pacing tokens.
    fn unbuild_batch(&mut self) {
        let chunk = self.chunk as u64;
        for &(_, s, e, _) in &self.batch_items {
            self.pending.insert(s, e);
            self.pacer.refund(chunk);
        }
        self.batch.clear();
        self.batch_items.clear();
    }

    /// Counts the datagrams of the batch just built as sent (they leave
    /// within microseconds, in order).
    fn record_sent(&mut self, now: Instant) {
        for i in 0..self.batch_items.len() {
            let (_, s, e, _) = self.batch_items[i];
            let len = e - s;
            self.seq += 1;
            self.inflight.insert(
                s,
                Inflight {
                    end: e,
                    sent_at: now,
                    seq: self.seq,
                },
            );
            self.send_log.push_back((now, s, self.seq));
            self.inflight_bytes += len;
            self.bytes_sent += len;
            self.round_sent += len;
            self.retransmitted_bytes += e.min(self.highest_sent).saturating_sub(s);
            self.highest_sent = self.highest_sent.max(e);
        }
        self.peak_inflight = self.peak_inflight.max(self.inflight_bytes);
        self.last_send_at = now;
    }

    /// Encrypts the batch just built: on the crypto pool when it is large
    /// (the engine carries on meanwhile), otherwise right here.
    fn dispatch_batch(&mut self) {
        let keys = self
            .secure
            .as_ref()
            .expect("checked by fill_window")
            .keys
            .clone();
        let seq = self.pipe.next_seq;
        self.pipe.next_seq += 1;
        let starts: Vec<usize> = self.batch_items.iter().map(|item| item.0).collect();
        let ranges: Vec<(u64, u64)> = self
            .batch_items
            .iter()
            .map(|&(_, s, e, _)| (s, e))
            .collect();
        self.batch_items.clear();
        let fresh = self.pipe.take_buf();
        let mut buf = std::mem::replace(&mut self.batch, fresh);
        let segment = starts.get(1).copied().unwrap_or(buf.len());
        let chunk = self.chunk;
        match parallel::pool() {
            Some(pool) if starts.len() >= MIN_POOLED => {
                let tx = self.pipe.results_tx.clone();
                self.pipe.in_pool += 1;
                pool.spawn(move || {
                    let failed = !seal_all(&keys.send, &mut buf, &starts);
                    let _ = tx.send(Batch {
                        seq,
                        buf,
                        chunk,
                        segment,
                        ranges,
                        failed,
                    });
                });
            }
            _ => {
                let failed = !seal_all(&keys.send, &mut buf, &starts);
                self.pipe.ready.insert(
                    seq,
                    Batch {
                        seq,
                        buf,
                        chunk,
                        segment,
                        ranges,
                        failed,
                    },
                );
            }
        }
    }

    /// Sends encrypted batches in order, as far as the socket takes them.
    ///
    /// No send error ends the transfer. A network that is gone for a moment
    /// — a Wi-Fi hand-over, an interface going down and up — refuses sends
    /// for that moment, and ending the transfer on the first refusal threw
    /// away what the liveness rules exist to decide: whether the receiver
    /// is still there, and how long to keep trying before keeping the state
    /// for resume.
    fn flush_ready(&mut self) -> Result<Option<SendBlock>, SendError> {
        while let Some(batch) = self.pipe.ready.remove(&self.pipe.next_send) {
            if batch.failed {
                self.unsend(&batch.ranges);
                return Err(SendError::Protocol("cannot encrypt a packet".into()));
            }
            let sent = self
                .socket
                .try_send_segments(self.peer, &batch.buf, batch.segment);
            let block = match sent {
                Ok(()) => None,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.pipe.ready.insert(batch.seq, batch);
                    return Ok(Some(SendBlock::Socket));
                }
                Err(err) if is_no_buffer_error(&err) => {
                    // The device queue is full; the socket may well be
                    // writable, so retry after a moment instead of waiting
                    // for a writability change that may not come.
                    self.pipe.ready.insert(batch.seq, batch);
                    return Ok(Some(SendBlock::Pacer(NO_BUFFER_BACKOFF)));
                }
                Err(err) if batch.ranges.len() > 1 && self.socket.max_segments() == 1 => {
                    // The network stack refused segmentation offload (and it
                    // is off now): send these datagrams one by one.
                    tracing::debug!("segmented send failed ({}); sending datagrams singly", err);
                    self.send_singly(&batch)
                }
                Err(err) => {
                    self.unsend(&batch.ranges);
                    self.on_send_error(&err, batch.chunk)
                }
            };
            self.pipe.next_send += 1;
            self.pipe.recycle(batch.buf);
            if block.is_some() {
                return Ok(block);
            }
        }
        Ok(None)
    }

    /// Sends a batch one datagram at a time; what does not leave goes back
    /// into `pending`. Returns what to wait for, if it had to stop.
    fn send_singly(&mut self, batch: &Batch) -> Option<SendBlock> {
        for (k, datagram) in batch.buf.chunks(batch.segment).enumerate() {
            match self.socket.try_send(self.peer, datagram) {
                Ok(()) => {}
                Err(err) => {
                    self.unsend(&batch.ranges[k..]);
                    return Some(if err.kind() == io::ErrorKind::WouldBlock {
                        SendBlock::Socket
                    } else if is_no_buffer_error(&err) {
                        SendBlock::Pacer(NO_BUFFER_BACKOFF)
                    } else {
                        self.on_send_error(&err, batch.chunk)
                            .unwrap_or(SendBlock::Yield)
                    });
                }
            }
        }
        None
    }

    /// What a refused send means, for data built with `built_with` chunks
    /// (or, for a single datagram, carrying that much file data). Returns
    /// what to wait for before sending again, if anything.
    fn on_send_error(&mut self, err: &io::Error, built_with: u16) -> Option<SendBlock> {
        if is_msgsize_error(err) {
            // Too big for the local interface: the sockets ignore what ICMP
            // claims about the path (see `set_dont_fragment`), so this is
            // no stranger's say-so. One step down per size the path refuses
            // — a whole pipeline of batches built at the old size fails
            // together, and stepping down once for each used to walk the
            // chunk to the floor on a single event, and then end the
            // transfer. The size grows again only on an acknowledged PROBE.
            if built_with > self.chunk || self.step_down_chunk("the interface refused the size") {
                return None;
            }
            // Nothing smaller to try. Keep trying, slowly; the liveness
            // rules decide when to stop.
            return Some(SendBlock::Pacer(SEND_ERROR_BACKOFF));
        }
        self.send_failures += 1;
        if self.send_failures.is_power_of_two() {
            tracing::warn!(
                "cannot send to {} ({}; {} time(s) so far); still trying",
                self.peer,
                err,
                self.send_failures
            );
        }
        Some(SendBlock::Pacer(SEND_ERROR_BACKOFF))
    }

    /// One step down in chunk size: from the size a 1500-byte MTU carries
    /// over IPv4 to the one it carries over IPv6 (also a PPPoE link's), else
    /// to the size every path carries, then by halves to the floor. False
    /// when already at the floor.
    fn step_down_chunk(&mut self, why: &str) -> bool {
        let smaller = if self.chunk == DEFAULT_CHUNK {
            DEFAULT_CHUNK_V6
        } else if self.chunk > SAFE_CHUNK {
            SAFE_CHUNK
        } else {
            (self.chunk / 2).max(MIN_CHUNK)
        };
        if smaller >= self.chunk {
            return false;
        }
        tracing::warn!("{}: reducing chunk {} -> {}", why, self.chunk, smaller);
        // Worth trying the old size again later: what shrank the path may
        // have been a moment's detour.
        self.mtu_raise = Some((Instant::now() + MTU_RAISE_AFTER, self.chunk));
        self.set_chunk(smaller);
        true
    }

    /// Takes ranges that were counted as sent but never left back into
    /// `pending`.
    fn unsend(&mut self, ranges: &[(u64, u64)]) {
        for &(s, e) in ranges {
            if self.inflight.get(&s).is_some_and(|inf| inf.end == e) {
                self.remove_inflight(s);
            }
            self.pending.insert(s, e);
        }
    }

    // ----- incoming --------------------------------------------------------

    /// Routes a datagram by its connection id: transport packets of the
    /// session, or answers to a handshake attempt. Anything else is dropped.
    fn on_datagram(&mut self, pkt: &mut [u8], from: SocketAddr) -> Result<(), SendError> {
        // A relay's own datagrams — from its control port or a port it
        // set aside for us — handed over to whichever introduction is
        // waiting for them. They can never be confused with traffic: the
        // connection id they would parse as is one no endpoint ever picks.
        // STUN answers to our own NAT tests, while they run: told apart
        // by the magic cookie, which a transport packet has one chance in
        // four billion of carrying.
        #[cfg(feature = "nat-traversal")]
        if let Some(tx) = &self.stun_inbox {
            if tx.is_closed() {
                self.stun_inbox = None;
            } else if crate::nat::stun::is_stun_message(pkt) {
                let _ = tx.try_send((pkt.to_vec(), from));
                return Ok(());
            }
        }
        #[cfg(feature = "nat-traversal")]
        if crate::relay::is_control(pkt) {
            if let Some((_, tx)) = self
                .relay_inboxes
                .read()
                .iter()
                .find(|(a, _)| a.ip() == from.ip())
            {
                let _ = tx.try_send((pkt.to_vec(), from));
                return Ok(());
            }
            if matches!(
                crate::relay::Message::decode(pkt),
                Some(crate::relay::Message::Punch)
            ) {
                return self.on_punch(from);
            }
            return Ok(());
        }
        let Some(dcid) = peek_cid(pkt) else {
            return Ok(());
        };
        if self.secure.as_ref().is_some_and(|s| s.local_cid == dcid) {
            return self.on_transport(pkt, from);
        }
        if let Some(i) = self.attempts.iter().position(|(a, _, _)| a.cid() == dcid) {
            return self.on_handshake_reply(i, pkt, from);
        }
        Ok(())
    }

    fn on_transport(&mut self, pkt: &mut [u8], from: SocketAddr) -> Result<(), SendError> {
        let len = pkt.len();
        let sec = self.secure.as_mut().expect("caller checked the session");
        let (tb, pn, body) = match sec.keys.recv.open(pkt) {
            Ok(v) => v,
            Err(_) => {
                sec.auth_failures += 1;
                return Ok(());
            }
        };
        if !sec.replay.accept(pn) {
            return Ok(());
        }
        let msg = match wire::parse_type_byte(tb).and_then(|(t, _)| wire::decode_body(t, body)) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("malformed frame from {}: {}", from, e);
                return Ok(());
            }
        };
        let now = Instant::now();
        self.note_alive(now, from, len);
        match msg {
            Message::Ack(ack) => self.on_ack(ack, now),
            Message::Fin(fin) => {
                // Every byte is at the receiver: nothing left to (re)send.
                self.pending = RangeSet::new();
                self.inflight.clear();
                self.inflight_bytes = 0;
                self.send_log.clear();
                self.received_bytes = self.size;
                if self.my_hash.is_some() {
                    self.answer_fin(fin.file_hash, now)?;
                } else {
                    if self.pending_fin.is_none() {
                        tracing::info!("receiver finished; waiting for the local hash");
                    }
                    self.pending_fin = Some(fin.file_hash);
                    // Tell the receiver we are alive; it answers with PONG
                    // and keeps retrying FIN until the verdict arrives.
                    let ts = self.clock.now_us().max(1);
                    let _ = self.send_frame(0, &Message::Ping(Ping { timestamp: ts }));
                }
            }
            Message::Pong(p) => {
                let sample = self.clock.since_us(p.echo);
                self.rtt.on_sample(Duration::from_micros(sample as u64));
                self.update_pacer();
            }
            Message::HelloAck(ack) => {
                // While negotiating every answer counts; later only answers
                // to our own state queries do (late duplicates are ignored)
                // — and, while the receiver's user is deciding, the decision
                // it sends of its own accord.
                if self.negotiating
                    || self.awaiting_decision.is_some()
                    || self.probe_ts.contains(&ack.echo_ts)
                {
                    self.probe_ts.clear();
                    self.answer = Some(ack);
                }
            }
            Message::Abort(a) => {
                return Err(SendError::Aborted {
                    code: a.code,
                    reason: a.reason,
                })
            }
            Message::FinDone(_) => {
                // Only meaningful once our verdict is out; nothing is left to
                // answer, so the transfer can end without lingering.
                if self.fin_verdict.is_some() {
                    self.fin_confirmed = true;
                }
            }
            Message::ProbeAck(p) => {
                if self.probe_acks.len() < 16 {
                    self.probe_acks.push(p.size);
                }
                // The size we stepped down from gets through again.
                if let Some((_, size)) = self.mtu_raise {
                    let chunk = (p.size as usize).saturating_sub(DATA_OVERHEAD);
                    if chunk == size as usize && size > self.chunk {
                        tracing::info!("path carries {} byte chunks again", size);
                        self.set_chunk(size);
                        self.mtu_raise = None;
                    }
                }
            }
            // The receiver is validating an address of ours: echo the token
            // back from the address it challenged, and nowhere else.
            Message::PathChallenge(p) => {
                let _ = self.send_frame_to(
                    from,
                    0,
                    &Message::PathResponse(wire::PathResponse { data: p.data }),
                );
            }
            Message::PathResponse(p) => {
                if let Some(addr) = self.path.on_response(from, p.data) {
                    tracing::info!("receiver address {} proven; sending there now", addr);
                    self.peer = addr;
                    #[cfg(feature = "nat-traversal")]
                    self.adopt_aux(addr);
                    // A move from IPv4 to IPv6 makes every header 20 bytes
                    // longer.
                    let fitted = self.family_chunk(self.chunk);
                    if fitted < self.chunk {
                        self.set_chunk(fitted);
                    }
                }
            }
            Message::Ping(_) => {}
            Message::Hello(_) | Message::Data(_) | Message::FinAck(_) | Message::Probe(_) => {}
        }
        Ok(())
    }

    fn answer_fin(&mut self, receiver_hash: [u8; 32], now: Instant) -> Result<(), SendError> {
        let my_hash = self
            .my_hash
            .ok_or_else(|| SendError::Protocol("local hash unavailable".into()))?;
        let verdict = if receiver_hash == my_hash {
            VERDICT_OK
        } else {
            VERDICT_MISMATCH
        };
        // If it cannot be sent it is as good as lost, and a lost verdict is
        // asked for again (the receiver repeats its FIN).
        let _ = self.send_frame(
            0,
            &Message::FinAck(wire::FinAck {
                verdict,
                file_hash: my_hash,
            }),
        );
        if self.fin_verdict.is_none() {
            tracing::info!(
                "receiver reported completion; whole-file hash {}",
                if verdict == VERDICT_OK {
                    "matches"
                } else {
                    "MISMATCH"
                }
            );
        }
        // A repeated FIN means our FIN_ACK was lost: wait for FIN_DONE anew.
        self.fin_verdict = Some((verdict, now, receiver_hash));
        Ok(())
    }

    /// Something authentic arrived from the receiver.
    ///
    /// A packet from an address the receiver has not proven does not move
    /// the transfer there. This is the side that matters most: the sender
    /// pushes the whole file, so an attacker that could redirect it by
    /// repeating one captured packet from a forged source address would have
    /// a multi-gigabit weapon pointed wherever it likes. It has to answer a
    /// challenge at the new address first (see [`crate::transport::path`]).
    fn note_alive(&mut self, now: Instant, from: SocketAddr, len: usize) {
        self.last_rx = now;
        self.ping_backoff = 0;
        if let Some(c) = self.path.on_authentic(from, self.peer, now, len) {
            tracing::info!(
                "receiver claims address {} (was {}); validating it",
                c.to,
                self.peer
            );
            let _ = self.send_frame_to(
                c.to,
                0,
                &Message::PathChallenge(wire::PathChallenge { data: c.nonce }),
            );
        }
        if self.stalled {
            self.stalled = false;
            self.rtt.reset_backoff();
            tracing::info!("receiver is back; resuming");
            emit(
                &self.events,
                TransferEvent::Recovered {
                    transfer_id: self.tid_hex(),
                },
            );
        }
    }

    fn remove_inflight(&mut self, key: u64) -> Option<Inflight> {
        let inf = self.inflight.remove(&key)?;
        self.inflight_bytes = self.inflight_bytes.saturating_sub(inf.end - key);
        Some(inf)
    }

    fn on_ack(&mut self, ack: wire::Ack, now: Instant) {
        // The receiver's byte count never shrinks within a session, so an ACK
        // reporting less than an earlier one was reordered on the path; its
        // holes are outdated.
        self.ack_log.push_back(AckRecord {
            at: now,
            received: ack.received_bytes,
            contiguous: ack.contiguous_upto,
            highest: ack.highest,
            holes: ack.holes.len(),
            first_hole: ack.holes.first().copied(),
            last_hole: ack.holes.last().copied(),
            stale: ack.received_bytes < self.max_ack_received,
        });
        if self.ack_log.len() > ACK_LOG_LEN {
            self.ack_log.pop_front();
        }
        // Nothing a receiver can honestly report exceeds the file it is
        // being sent. An ACK that does is a bug or a hostile peer, and
        // believing it once would be permanent: `max_ack_received` only
        // grows, so an impossible count would make every honest ACK
        // afterwards look outdated and stall the transfer for good. The
        // decoder already guarantees `contiguous_upto <= highest`.
        if ack.received_bytes > self.size || ack.highest > self.size {
            self.impossible_acks += 1;
            if self.impossible_acks.is_power_of_two() {
                tracing::warn!(
                    "ignoring an ACK beyond the file: {} B received, up to {}, file is {} B \
                     ({} such ACKs so far)",
                    ack.received_bytes,
                    ack.highest,
                    self.size,
                    self.impossible_acks
                );
            }
            return;
        }
        if ack.received_bytes < self.max_ack_received {
            return;
        }
        if ack.received_bytes > self.max_ack_received {
            // The receiver got new data (possibly beyond the interval this
            // ACK can describe): the path is alive, so restart the RTO.
            self.last_ack_progress = now;
            self.tail_probes = 0;
        }
        self.max_ack_received = ack.received_bytes;
        self.rwnd = ack.rwnd;
        self.received_bytes = self.received_bytes.max(ack.received_bytes.min(self.size));
        if ack.echo_ts != 0 {
            let raw = self.clock.since_us(ack.echo_ts);
            if raw < 60_000_000 {
                let sample = raw.saturating_sub(ack.ack_delay_us).max(1);
                self.rtt.on_sample(Duration::from_micros(sample as u64));
            }
        }

        // Anything the receiver confirms must not be sent again, even if it
        // was queued for retransmission before the original arrived late.
        self.pending.remove(0, ack.contiguous_upto);
        let mut acked: u64 = 0;
        let mut newest_delivered: Option<Instant> = None;
        let mut note_delivered = |t: Instant| {
            newest_delivered = Some(newest_delivered.map_or(t, |n: Instant| n.max(t)));
        };
        // Cumulative part.
        while let Some((off, end, sent_at)) = self
            .inflight
            .iter()
            .next()
            .map(|(&k, inf)| (k, inf.end, inf.sent_at))
        {
            if end > ack.contiguous_upto {
                break;
            }
            acked += end - off;
            note_delivered(sent_at);
            self.remove_inflight(off);
        }

        // Selective part. The receiver guarantees that `holes` lists every
        // gap in [contiguous_upto, highest), so everything else in that
        // interval has arrived.
        if ack.highest > ack.contiguous_upto {
            let mut received = RangeSet::new();
            received.insert(ack.contiguous_upto, ack.highest);
            for &(s, e) in &ack.holes {
                received.remove(s, e);
            }
            for (s, e) in received.iter() {
                self.pending.remove(s, e);
            }
            let keys: Vec<(u64, u64, Instant)> = self
                .inflight
                .range(ack.contiguous_upto..ack.highest)
                .map(|(&k, inf)| (k, inf.end, inf.sent_at))
                .collect();
            for (k, end, sent_at) in keys {
                if received.contains(k, end) {
                    acked += end - k;
                    note_delivered(sent_at);
                    self.remove_inflight(k);
                }
            }
        }
        if let Some(t) = newest_delivered {
            self.rack_sent_at = Some(self.rack_sent_at.map_or(t, |r| r.max(t)));
        }

        let mut lost: Vec<(u64, u64)> = Vec::new();
        if ack.highest > ack.contiguous_upto {
            // Loss detection (RACK): a packet in a reported hole is lost when
            // a packet sent sufficiently later has been delivered, or when it
            // has been outstanding longer than an RTT plus the reordering
            // window. Send order, not file offset, decides, so a fresh
            // retransmission is not condemned by ACKs that predate it.
            let reo_wnd = (self.rtt.min_rtt() / 4)
                .clamp(Duration::from_millis(1), Duration::from_millis(250));
            let time_threshold = self.rtt.srtt().max(self.rtt.latest()) + reo_wnd;
            let rack = self.rack_sent_at;
            for &(hs, he) in &ack.holes {
                let first_key = self
                    .inflight
                    .range(..hs)
                    .next_back()
                    .map(|(&k, _)| k)
                    .unwrap_or(hs);
                let candidates: Vec<(u64, u64, Instant)> = self
                    .inflight
                    .range(first_key..he)
                    .filter(|(&k, inf)| inf.end > hs && k < he)
                    .map(|(&k, inf)| (k, inf.end, inf.sent_at))
                    .collect();
                for (k, end, sent_at) in candidates {
                    let by_order = rack.is_some_and(|r| sent_at + reo_wnd <= r);
                    let by_time = now.saturating_duration_since(sent_at) >= time_threshold;
                    if by_order || by_time {
                        self.remove_inflight(k);
                        lost.push((k, end));
                    }
                }
            }
        }
        for &(s, e) in &lost {
            self.pending.insert(s, e);
        }

        // Self-healing: a reported hole that is neither in flight nor queued
        // would never be sent again; queue it.
        let mut healed = 0u64;
        for &(hs, he) in &ack.holes {
            let he = he.min(self.size);
            if hs >= he {
                continue;
            }
            let mut missing = RangeSet::from_ranges([(hs, he)]);
            let first_key = self
                .inflight
                .range(..hs)
                .next_back()
                .map(|(&k, _)| k)
                .unwrap_or(hs);
            for (&k, inf) in self.inflight.range(first_key..he) {
                if inf.end > hs {
                    missing.remove(k, inf.end);
                }
            }
            for (s, e) in self.pending.intersecting(hs, he) {
                missing.remove(s, e);
            }
            for (s, e) in missing.iter() {
                if self.pending.len() >= MAX_HEALED_RANGES && self.pending.would_add_range(s, e) {
                    continue;
                }
                healed += e - s;
                self.pending.insert(s, e);
            }
        }
        if healed > 0 {
            self.healed_bytes += healed;
            tracing::debug!("re-queued {} B reported missing but not tracked", healed);
        }

        // Grow the window only while it is used (RFC 9002, 7.8): a sender
        // limited by its own speed or by the receiver would otherwise build
        // a window it never fills, and pacing derived from it would stop
        // pacing.
        let window_used = 2 * self.peak_inflight.max(self.prev_peak_inflight) >= self.cc.cwnd();
        if acked > 0 && window_used {
            self.cc.on_ack(acked, now, &self.rtt);
        }
        if acked > 0 {
            self.rtt.reset_backoff();
            self.last_ack_progress = now;
            self.tail_probes = 0;
            self.mtu_suspect = 0;
        }
        if !lost.is_empty() {
            let lost_bytes: u64 = lost.iter().map(|&(s, e)| e - s).sum();
            self.round_lost += lost_bytes;
            self.end_round_if_due(now);
            if self.loss_is_congestive() {
                self.round_congestive = true;
                if self.cc.on_loss(now, self.rtt.srtt()) {
                    tracing::debug!(
                        "congestive loss ({} ranges, standing queue {:?}, loss rate {:.1}%); cwnd -> {} B",
                        lost.len(),
                        self.rtt.standing_queue(),
                        self.current_loss_rate() * 100.0,
                        self.cc.cwnd()
                    );
                }
            } else {
                self.random_loss_events += 1;
            }
        } else {
            self.end_round_if_due(now);
        }
        self.update_pacer();
    }

    /// Closes the current measurement round once it spans about one RTT.
    fn end_round_if_due(&mut self, now: Instant) {
        let len = self.rtt.srtt().max(Duration::from_millis(5));
        if now.saturating_duration_since(self.round_start) < len {
            return;
        }
        // Only rounds with enough packets say something about the loss rate.
        if self.round_sent >= 16 * self.chunk as u64 {
            let rate = (self.round_lost as f64 / self.round_sent as f64).min(1.0);
            self.loss_rate = 0.5 * self.loss_rate + 0.5 * rate;
            if !self.round_congestive {
                self.bg_sent = self.bg_sent * BG_DECAY + self.round_sent as f64;
                self.bg_lost = self.bg_lost * BG_DECAY + self.round_lost as f64;
            }
        }
        self.round_start = now;
        self.round_sent = 0;
        self.round_lost = 0;
        self.round_congestive = false;
        self.prev_peak_inflight = self.peak_inflight;
        self.peak_inflight = self.inflight_bytes;
    }

    /// Background (non-congestive) loss rate of the path.
    fn base_loss_rate(&self) -> f64 {
        if self.bg_sent > 0.0 {
            (self.bg_lost / self.bg_sent).min(BASE_LOSS_MAX)
        } else {
            0.0
        }
    }

    fn current_loss_rate(&self) -> f64 {
        let partial = if self.round_sent >= 16 * self.chunk as u64 {
            (self.round_lost as f64 / self.round_sent as f64).min(1.0)
        } else {
            0.0
        };
        self.loss_rate.max(partial)
    }

    /// A loss is taken as a congestion signal when a queue has built up (the
    /// minimum RTT of a whole round is elevated, which jitter alone never
    /// causes), or when the loss rate rises clearly above the path's
    /// background level (which is what overdriving a shallow buffer looks
    /// like). Losses at the background level on an otherwise empty path
    /// (radio links, noisy lines) are repaired without slowing down.
    fn loss_is_congestive(&self) -> bool {
        let min_rtt = self.rtt.min_rtt();
        let queue_threshold = (min_rtt / 4).max(Duration::from_millis(2));
        if self.rtt.standing_queue() >= queue_threshold {
            return true;
        }
        let chunk = self.chunk.max(1) as f64;
        let sent = self.round_sent as f64 / chunk;
        let lost = self.round_lost as f64 / chunk;
        if sent >= 20.0 && lost / sent >= LOSS_CEILING {
            return true;
        }
        // More losses in this round than the background rate explains, by a
        // clear margin (about three standard deviations of a Poisson count):
        // one or two stray losses in a small round never qualify.
        let expected = self.base_loss_rate() * sent;
        lost > expected + 3.0 * (expected + 1.0).sqrt() + 1.0
    }

    /// Tail loss probe: when data is in flight but nothing was sent and no
    /// ACK made progress for about two RTTs, resend the last packet to
    /// provoke an ACK that reveals which packets were lost, instead of
    /// waiting for the RTO. ACKs without progress (the receiver repeating its
    /// holes) do not postpone the probe, and the probe fires no later than
    /// the RTO would, which it then postpones (RFC 8985 section 7.2): a lost
    /// tail is repaired with the current window instead of a collapsed one.
    /// Whether `addr` carries the transfer without being the receiver: a
    /// port a relay set aside, or an address on a TURN server, or a
    /// loopback address that stands for the receiver through one.
    fn is_relayed(&self, addr: SocketAddr) -> bool {
        let addr = crate::address::canonical(addr);
        #[cfg(feature = "nat-traversal")]
        if self.turns.iter().any(|t| t.is_shim(addr)) {
            return true;
        }
        self.relayed.contains(&addr)
    }

    fn ping_message(&self) -> Message<'static> {
        let ts = self.clock.now_us();
        Message::Ping(Ping { timestamp: ts })
    }

    /// While a session is carried by a relay, asks the receiver's other
    /// addresses whether a direct path has opened: an authenticated ping to
    /// each, which the receiver answers from where it arrived if it arrives
    /// at all, and then moves the session to (each end proving the other's
    /// address first, as for any change of address). A relay is somewhere to
    /// stand until the way opens, not a place to stay: it costs whoever runs
    /// it the bandwidth and is slower than what the two ends can manage
    /// between them.
    ///
    /// Bounded: a few addresses, a datagram each, once a second at first
    /// and then every few seconds, and only while the session is carried.
    fn probe_direct(&mut self, now: Instant) {
        /// Addresses asked in a round.
        const ADDRESSES: usize = 4;
        /// Rounds at the brisk pace, and how long the slow pace waits.
        const BRISK_ROUNDS: u32 = 30;
        const BRISK: Duration = Duration::from_secs(1);
        const SLOW: Duration = Duration::from_secs(4);
        if self.secure.is_none() || now < self.next_direct_probe || !self.is_relayed(self.peer) {
            return;
        }
        self.direct_probes += 1;
        self.next_direct_probe = now
            + if self.direct_probes <= BRISK_ROUNDS {
                BRISK
            } else {
                SLOW
            };
        #[cfg_attr(not(feature = "nat-traversal"), allow(unused_mut))]
        let mut asked: Vec<SocketAddr> = self
            .candidates
            .iter()
            .copied()
            .filter(|a| *a != self.peer && !self.is_relayed(*a))
            .take(ADDRESSES)
            .collect();
        // The address of a meeting being proven is asked whatever else is
        // being: it is the one that has been shown to lead somewhere.
        #[cfg(feature = "nat-traversal")]
        if let Some(aux) = &self.aux {
            asked.retain(|a| *a != aux.peer);
            asked.insert(0, aux.peer);
            asked.truncate(ADDRESSES);
        }
        if asked.is_empty() {
            return;
        }
        if self.direct_probes == 1 {
            tracing::info!(
                "carried by {}: asking the receiver's other address(es) whether a direct path has opened",
                self.peer
            );
        }
        let ping = self.ping_message();
        for a in asked {
            let _ = self.send_frame_to(a, 0, &ping);
        }
    }

    fn maybe_send_tail_probe(&mut self, now: Instant) -> Result<(), SendError> {
        if self.inflight.is_empty()
            || self.stalled
            || self.tail_probes >= MAX_TAIL_PROBES
            || self.secure.is_none()
        {
            return Ok(());
        }
        let pto = (self.rtt.srtt() * 2 + self.rtt.max_ack_delay())
            .min(self.rtt.rto())
            .max(Duration::from_millis(10));
        let quiet_since = self.last_send_at.max(self.last_ack_progress);
        if now.saturating_duration_since(quiet_since) < pto {
            return Ok(());
        }
        let Some((s, e)) = self
            .inflight
            .iter()
            .next_back()
            .map(|(&k, inf)| (k, inf.end))
        else {
            return Ok(());
        };
        self.read_buf.resize((e - s) as usize, 0);
        self.reader.read_at(s, &mut self.read_buf)?;
        let ts = self.clock.now_us().max(1);
        {
            let sec = self.secure.as_mut().expect("checked above");
            seal_data(
                sec,
                &mut self.tx_buf,
                DATA_FLAG_RETRANSMIT,
                s,
                ts,
                &self.read_buf,
            )
            .map_err(|e| SendError::Protocol(e.to_string()))?;
        }
        match self.socket.try_send(self.peer, &self.tx_buf) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock || is_no_buffer_error(&err) => {
                return Ok(())
            }
            // As for any other datagram: never the end of the transfer. It
            // repeats a range sent earlier, at the size it was sent at, so
            // that — not the current chunk — is what was refused.
            Err(err) => {
                let size = (e - s).min(u16::MAX as u64) as u16;
                self.on_send_error(&err, size);
                return Ok(());
            }
        }
        self.seq += 1;
        if let Some(inf) = self.inflight.get_mut(&s) {
            inf.sent_at = now;
            inf.seq = self.seq;
        }
        self.send_log.push_back((now, s, self.seq));
        self.retransmitted_bytes += e - s;
        self.bytes_sent += e - s;
        self.last_send_at = now;
        self.last_tail_probe_at = now;
        self.tail_probes += 1;
        self.tail_probe_count += 1;
        tracing::debug!("tail loss probe #{} for {}..{}", self.tail_probes, s, e);
        Ok(())
    }

    // ----- timers ----------------------------------------------------------

    fn housekeeping(&mut self, now: Instant) -> Result<(), SendError> {
        // Waiting for the receiver's user: ask for the decision now and
        // then, for as long as a first handshake would wait for one.
        if let Some(since) = self.awaiting_decision {
            if now.saturating_duration_since(since) >= self.cfg.handshake_timeout {
                return Err(SendError::Rejected {
                    reason: reason_name(REASON_TIMEOUT).to_string(),
                    message: "no decision in time".into(),
                });
            }
            let due = self
                .last_decision_poll
                .is_none_or(|t| now.saturating_duration_since(t) >= DECISION_POLL);
            if due {
                self.last_decision_poll = Some(now);
                self.send_state_query();
            }
        }
        // Repeat unanswered address challenges, or give claims up. Paced by
        // the round trip itself, not by a timeout that an outage may have
        // backed off to half a minute.
        for c in self.path.poll(now, self.rtt.pto()) {
            let _ = self.send_frame_to(
                c.to,
                0,
                &Message::PathChallenge(wire::PathChallenge { data: c.nonce }),
            );
        }
        #[cfg(feature = "nat-traversal")]
        if self
            .aux
            .as_ref()
            .is_some_and(|a| now.saturating_duration_since(a.since) >= AUX_PATIENCE)
        {
            tracing::info!(
                "the receiver did not prove the address of the late meeting; leaving it"
            );
            self.aux = None;
        }
        self.probe_direct(now);
        self.maybe_send_tail_probe(now)?;
        // Retransmission timeout.
        let rto = self.rtt.rto();
        let mut expired: Vec<u64> = Vec::new();
        while let Some(&(sent_at, off, seq)) = self.send_log.front() {
            match self.inflight.get(&off) {
                Some(inf) if inf.seq == seq => {
                    // As long as ACKs keep acknowledging new data the path
                    // is alive; unacknowledged packets are then either
                    // reported as holes or simply not described yet. A tail
                    // probe gets its answer before the timer may expire.
                    let since = sent_at
                        .max(self.last_ack_progress)
                        .max(self.last_tail_probe_at);
                    if now.saturating_duration_since(since) >= rto {
                        expired.push(off);
                        self.send_log.pop_front();
                    } else {
                        break;
                    }
                }
                _ => {
                    self.send_log.pop_front();
                }
            }
        }
        if !expired.is_empty() {
            let mut bytes = 0;
            for off in expired {
                if let Some(inf) = self.remove_inflight(off) {
                    bytes += inf.end - off;
                    self.pending.insert(off, inf.end);
                }
            }
            self.rto_events += 1;
            self.cc.on_rto(now);
            self.rtt.backoff();
            self.update_pacer();
            tracing::debug!(
                "RTO ({:?}): {} B back to pending, cwnd {} B",
                rto,
                bytes,
                self.cc.cwnd()
            );
            // The receiver is still heard from — its ACKs and PONGs are
            // small — but no data has got through. That is what a path
            // whose MTU shrank looks like once ICMP is not believed: every
            // full-size packet vanishes and nothing else does. Step down,
            // and try the old size again later with an acknowledged PROBE.
            let heard =
                now.saturating_duration_since(self.last_rx) < self.cfg.stall_timeout.max(rto * 3);
            let stuck = now.saturating_duration_since(self.last_ack_progress) >= rto;
            if heard && stuck {
                self.mtu_suspect += 1;
                if self.mtu_suspect >= MTU_BLACKHOLE_RTOS {
                    self.mtu_suspect = 0;
                    self.step_down_chunk(
                        "full-size packets are lost while small ones get through (MTU black hole?)",
                    );
                }
            }
        }
        // Try the size we stepped down from again: one PROBE, which only an
        // acknowledgement under the session's keys can answer.
        if let Some((at, size)) = self.mtu_raise {
            if now >= at && size > self.chunk {
                let wire = (size as usize + DATA_OVERHEAD) as u16;
                let _ = self.send_frame(0, &Message::Probe(Probe { size: wire }));
                self.mtu_raise = Some((now + MTU_RAISE_AFTER * 2, size));
            }
        }

        // Nothing queued or in flight, yet the receiver still misses bytes:
        // the bookkeeping disagrees with the receiver. Ask it what it holds.
        let idle = self.pending.is_empty()
            && self.inflight.is_empty()
            && self.fin_verdict.is_none()
            && self.pending_fin.is_none()
            && self.max_ack_received < self.size;
        if idle {
            let wait = (self.rtt.srtt() * 4).max(Duration::from_millis(200));
            let due = self
                .last_idle_probe
                .is_none_or(|t| now.saturating_duration_since(t) >= wait);
            if due {
                if self.last_idle_probe.is_none() {
                    self.log_inconsistency();
                }
                self.last_idle_probe = Some(now);
                self.send_state_query();
            }
        } else if !self.pending.is_empty() || !self.inflight.is_empty() {
            self.last_idle_probe = None;
        }

        // Liveness.
        let since_rx = now.saturating_duration_since(self.last_rx);
        if since_rx >= self.cfg.stall_timeout && !self.stalled {
            self.stalled = true;
            tracing::warn!(
                "no packets from {} for {:?}; pausing and probing",
                self.peer,
                since_rx
            );
            emit(
                &self.events,
                TransferEvent::Stalled {
                    transfer_id: self.tid_hex(),
                    since: since_rx,
                },
            );
        }
        if self.stalled && since_rx >= self.cfg.give_up_timeout {
            emit(
                &self.events,
                TransferEvent::Failed {
                    transfer_id: self.tid_hex(),
                    error: format!("receiver unreachable for {:?}", since_rx),
                    resumable: true,
                },
            );
            return Err(SendError::PeerUnreachable(since_rx));
        }
        let ping_interval = if self.stalled {
            Duration::from_secs(1 << self.ping_backoff.min(2))
        } else {
            (self.rtt.rto() * 2).clamp(Duration::from_millis(500), Duration::from_secs(3))
        };
        if since_rx >= ping_interval
            && now.saturating_duration_since(self.last_ping) >= ping_interval
        {
            self.last_ping = now;
            if self.stalled {
                self.ping_backoff += 1;
            }
            let ts = self.clock.now_us().max(1);
            let _ = self.send_frame(0, &Message::Ping(Ping { timestamp: ts }));
            // After a few seconds of silence also perform a new handshake: a
            // live session answers with its current state, and a restarted
            // receiver (which lost the session keys) resumes from its saved
            // state.
            let resync_after = self.cfg.stall_timeout.min(Duration::from_secs(3));
            if since_rx >= resync_after && self.fin_verdict.is_none() {
                self.send_initiation()?;
            }
        }
        Ok(())
    }

    /// Sends HELLO over the session; the receiver answers with its exact
    /// current state, which `resync` then adopts.
    fn send_state_query(&mut self) {
        let ts = self.clock.now_us().max(1);
        if self.probe_ts.len() >= 16 {
            self.probe_ts.remove(0);
        }
        self.probe_ts.push(ts);
        let hello = Message::Hello(self.hello(ts));
        let _ = self.send_frame(HELLO_FLAG_RESUME, &hello);
    }

    /// Logs the evidence when the sender believes everything is delivered but
    /// the receiver reports otherwise. This indicates a bug; the transfer
    /// recovers through a resync, but the details are needed to fix it.
    fn log_inconsistency(&self) {
        tracing::warn!(
            "sender idle but receiver incomplete: receiver reports {} of {} B; resynchronising",
            self.max_ack_received,
            self.size
        );
        let base = self
            .ack_log
            .back()
            .map(|r| r.at)
            .unwrap_or_else(Instant::now);
        for r in &self.ack_log {
            tracing::warn!(
                "  ack -{:>6.1} ms: received {} contiguous {} highest {} holes {} first {:?} last {:?}{}",
                base.saturating_duration_since(r.at).as_secs_f64() * 1000.0,
                r.received,
                r.contiguous,
                r.highest,
                r.holes,
                r.first_hole,
                r.last_hole,
                if r.stale { " STALE" } else { "" }
            );
        }
    }

    fn stats(&mut self, now: Instant) -> TransferStats {
        let elapsed = now.saturating_duration_since(self.start);
        let dt = now
            .saturating_duration_since(self.last_progress_at)
            .as_secs_f64();
        let delta = self.received_bytes.saturating_sub(self.last_progress_bytes);
        let rate = if dt > 0.0 {
            delta as f64 * 8.0 / dt
        } else {
            0.0
        };
        let moved = self.received_bytes.saturating_sub(self.resumed_from);
        let avg = if elapsed.as_secs_f64() > 0.0 {
            moved as f64 * 8.0 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let remaining = self.size.saturating_sub(self.received_bytes);
        let eta = if rate > 0.0 {
            Some(Duration::from_secs_f64(remaining as f64 * 8.0 / rate))
        } else {
            None
        };
        TransferStats {
            transfer_id: self.tid_hex(),
            bytes_done: self.received_bytes,
            total_bytes: self.size,
            rate_bps: rate,
            avg_rate_bps: avg,
            rtt_ms: self.rtt.srtt().as_secs_f64() * 1000.0,
            cwnd_bytes: self.cc.cwnd(),
            inflight_bytes: self.inflight_bytes,
            chunk_size: self.chunk,
            retransmitted_bytes: self.retransmitted_bytes,
            loss_events: self.cc.loss_events(),
            elapsed,
            eta,
            stalled: self.stalled,
        }
    }

    fn emit_progress(&mut self, now: Instant) {
        let stats = self.stats(now);
        self.last_progress_at = now;
        self.last_progress_bytes = self.received_bytes;
        tracing::debug!(
            "progress {}/{} B, {:.1} Mbit/s, rtt {:.2} ms (min {:.2}), cwnd {} B, inflight {} B, \
             pending {} B, retx {} B, healed {} B, rto {}, delay exits {}, loss rate {:.2}%, \
             base {:.2}%, random losses {}, tail probes {}",
            stats.bytes_done,
            stats.total_bytes,
            stats.rate_bps / 1e6,
            stats.rtt_ms,
            self.rtt.min_rtt().as_secs_f64() * 1000.0,
            stats.cwnd_bytes,
            stats.inflight_bytes,
            self.pending.total(),
            stats.retransmitted_bytes,
            self.healed_bytes,
            self.rto_events,
            self.cc.delay_exits(),
            self.loss_rate * 100.0,
            self.base_loss_rate() * 100.0,
            self.random_loss_events,
            self.tail_probe_count
        );
        emit(&self.events, TransferEvent::Progress(stats));
    }
}

pub fn reason_name(code: u8) -> &'static str {
    match code {
        REASON_NONE => "none",
        REASON_DISK_SPACE => "not enough disk space",
        REASON_BAD_FILE_NAME => "bad file name",
        REASON_BUSY => "receiver busy",
        REASON_DECLINED => "declined by user",
        REASON_CONN_CONFLICT => "connection id conflict",
        REASON_INTERNAL => "internal error",
        REASON_TIMEOUT => "decision timeout",
        REASON_UNAUTHORIZED => "sender not authorized",
        REASON_NO_SUITE => "no cipher in common",
        _ => "unknown",
    }
}
