# Changelog

## 0.5.0 — protocol v3 (unreleased)

Version 3 puts the version 2 transport inside an authenticated, encrypted
channel, transfers whole directories and moves datagrams in batches for
multi-gigabit links. Version 2 peers cannot talk to version 3 peers (the
version is bound into the handshake). See [docs/PROTOCOL.md](docs/PROTOCOL.md).

### Security
- Long-term X25519 identities, created on first use and kept in the
  per-user data directory with owner-only permissions. A peer is addressed
  by its SHARP ID (`sh-` + 56 base32 characters with a checksum); senders
  use `ID@host:port`.
- Noise `IKpsk2_25519_ChaChaPoly_BLAKE2s` handshake: the receiver is
  authenticated by its ID, the sender by its static key (sent encrypted),
  fresh keys per session (forward secrecy), optional shared secret turned
  into the pre-shared key with Argon2id (64 MiB, 3 passes) and salted with
  the receiver's key.
- Every datagram after the handshake is AEAD-protected (AES-256-GCM when
  both sides have AES instructions, ChaCha20-Poly1305 otherwise) with QUIC
  style header protection, per-epoch keys (2^22 packets) and a replay
  window. Forged, corrupted and replayed packets are dropped before they
  are looked at. This replaces the unauthenticated integrity tag of v2.
- Stealth: without a valid mac1 (which needs the receiver's ID) a datagram
  gets no answer. Under load the receiver demands address-bound cookies
  (as WireGuard does), so spoofed floods cost one MAC per packet and cannot
  be amplified. Per-address handshake rate limits and a replay guard on
  initiation timestamps.
- Receivers can admit only listed sender IDs (`--allow`,
  `--authorized-senders FILE`); refused senders get an authenticated
  rejection. Resume state is bound to the sender's identity.
- Address validation (PATH_CHALLENGE / PATH_RESPONSE, QUIC's RFC 9000
  section 8). Authenticity proves who made a packet, not where it was sent
  from, so an attacker on the path can copy one and repeat it with a forged
  source address. A session therefore treats an unproven address as a claim:
  it keeps sending to the address already proven and asks the new one to
  echo eight unpredictable bytes. Only the holder of the session keys can
  answer, and only delivery at that address can return it. Nothing else is
  sent there meanwhile, so the mechanism cannot amplify either. A captured
  packet can no longer aim a transfer at a third party.
- Name resolution is a hint, not an authority: a name resolves to all of its
  addresses (families interleaved) and handshake attempts rotate through
  them, with the handshake deciding which one is the receiver. A poisoned
  DNS or mDNS answer costs time rather than safety, and a host whose first
  address is unreachable no longer strands the transfer.
- The replay guard evicts in constant time, so a flood of fresh identities
  cannot make admission cost grow with the table.
- ACKs describing more bytes than the file holds are dropped unread: the
  staleness counter only grows, so believing one would have stalled the
  transfer for good.
- A datagram refused for its size steps the packet size down towards the
  minimum instead of failing the transfer. The ICMP message behind such a
  refusal is unauthenticated, so a forged one now costs throughput at worst;
  the size only ever grows again on an authenticated PROBE_ACK.
- The session limit is shared rather than first-come-first-served: one
  sender identity may hold only a configured number of concurrent transfers
  (`max_sessions_per_sender`, 8 of 16 by default), so it cannot take every
  slot and lock everybody else out.
- `docs/THREAT_MODEL.md`: adversary classes and what each can achieve, every
  guarantee with the mechanism responsible, explicit non-goals and residual
  risks.

### Getting through NAT
- The receiver measures what the NAT in front of it actually does, with the
  tests of RFC 5780 run on the transfer socket itself: whether the external
  port follows the destination (which decides whether any address is worth
  publishing at all) and which inbound packets reach a mapping already open
  (which decides whether the sender must be let in first), plus hairpinning
  and port preservation. "NAT type" in the RFC 3489 sense is gone; it was
  never one property. Where a server cannot measure something the answer is
  "unknown" rather than a guess — in particular, an answer to CHANGE-REQUEST
  counts only if it arrives from the address it was asked to come from,
  since a server that ignores the attribute answers from its primary address
  and would otherwise look like a wide-open filter.
- Port forwards are now asked for over PCP (RFC 6887) and NAT-PMP (RFC 6886)
  as well as UPnP-IGD. The two binary protocols go first: they are two
  datagrams against UPnP's multicast discovery plus HTTP and SOAP, and they
  are what most routers of the last decade implement. The router is found
  from the routing table where that is readable, and from the first address
  of each local subnet otherwise.
- Every address the receiver might be reached at is published together, as
  `ID@host:port,host:port,…` — the port forward, the address the world sees,
  and the local ones — as candidates in the sense of ICE (RFC 8445). The
  sender tries them a quarter of a second apart while any are untried, then
  backs off. Since completing a handshake takes the receiver's private key,
  publishing an address that might not work risks nothing and costs a
  quarter of a second.
- None of this is trusted: STUN servers and routers are unauthenticated and
  only ever produce addresses worth *trying*. Addresses a server tells us to
  send to are screened first, so clients cannot be used as reflectors, and
  PCP's nonce is checked so another request's answer is not taken for ours.

### Directories
- A directory is sent as one stream: a manifest (structure, sizes, Unix
  permission bits, modification times) followed by the file contents, so
  resume and the final BLAKE3 verification cover names, structure and
  metadata too.
- The receiver verifies the manifest against the hash announced in HELLO
  and decodes it strictly (single-component names only, no `.`/`..`,
  parents first, sorted unique siblings, bounded depth, path length, entry
  count and size) before creating anything; data that overtakes the
  manifest waits in a bounded buffer.
- The tree is built in a private staging directory with create-new
  semantics (names that collide on the local file system are reported,
  never overwritten; names are mapped for Windows), then hashed, given its
  times and permissions (never set-id bits, masked by the umask) and
  renamed into place without replacing anything. Symbolic links and special
  files are skipped and reported by the sender.
- Interrupted directory transfers resume after a restart of either side;
  the manifest is kept with the resume state.
- CLI and GUI senders accept folders; receivers show "N files in M folders".

### Performance
- Batched datagram I/O via quinn-udp: up to 64 datagrams per segmented
  send (GSO on Linux, USO on Windows), `recvmmsg` with UDP GRO on receive;
  coalesced runs travel from the dispatcher to their session without
  copies, and all payloads of a run reach the writer as one command.
- Packet encryption and decryption run on a pool of worker threads while
  the engines carry on; results are used strictly in order.
  `SHARP256_CRYPTO_THREADS` sets the pool size (0 disables it).
- Loopback on a 4-core VM running both ends: 2 GiB in 3.5 s
  (4.9 Gbit/s, no retransmissions), up from 1.1 Gbit/s.
- Segmented sends carry at most about 1 ms of data at the pacing rate and
  the pacer's burst is 1 ms, so shallow buffers are not overrun; the
  congestion window grows only while it is used (RFC 9002, 7.8); the
  receiver's window accounts for datagrams it has not processed yet.
- Socket buffers default to 32 MiB; a privileged process exceeds
  `net.core.rmem_max`, otherwise the receiver prints the `sysctl` that
  raises it.

### Protocol
- HELLO_ACK status "pending": while the receiver's user decides, the
  sender polls and starts as soon as the transfer is accepted.
- The frame type and flags share one (masked) byte; the magic, version and
  connection-id header of v2 are gone (connection ids are now 64-bit and
  chosen by each recipient).
- New reject reasons: sender not authorised, no cipher suite in common,
  unsupported request.

### Fixed
- The first handshake packet of every transfer was silently dropped
  because the socket was used before the runtime had seen it writable,
  which cost a 250 ms retry.
- Writer errors (disk full, colliding names) now end a transfer promptly
  instead of surfacing only when the file is closed.

### Front ends
- CLI tools print and take SHARP IDs (`--id`, `--identity`), a shared
  secret (`--secret` or `SHARP256_SECRET`) and receiver allow-lists; the
  receiver prints the address string senders need.
- The GUIs show the own ID with a copy button, the peer's ID, the cipher
  in use and folder contents; the sender picks files or folders.

## 0.4.0 — protocol v2 (unreleased)

A ground-up rewrite of the transport. The 0.3 prototype could not complete
a transfer in practice: the receiver stopped reading its socket after the
handshake, file offsets were derived from mutable batch parameters, and a
single lost packet stalled a transfer forever. Version 2 fixes the design
rather than the symptoms. The wire format is specified in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

### Wire protocol
- Self-describing DATA packets (absolute offset + payload) and a keyed
  BLAKE3 integrity tag on every datagram.
- Selective acknowledgements whose hole lists are varint-encoded (about
  250–300 holes per ACK) and always *complete* for the interval they
  describe, so a missing byte can never be acknowledged by mistake.
- Every control message fits into 1200 bytes by construction.
- Two-way capability negotiation (offered in HELLO, confirmed in
  HELLO_ACK) and forward-compatible control messages (decoders ignore
  appended fields), so features can be added without a new version.
- HELLO_ACK announces the receiver's maximum ACK delay; the sender adds it
  to its timeouts.
- Three-way close (FIN → FIN_ACK → FIN_DONE): the sender ends as soon as
  the receiver has its verdict instead of lingering.
- ABORT tells the peer why a transfer ends (cancel, I/O error, timeout,
  protocol error), so the other side releases the session at once.

### Transport
- RACK loss detection (RFC 8985) by send order and time, tail loss probes
  that fire no later than the RTO and postpone it, and an RTO that restarts
  on progress (RFC 6298 §5.3) and includes the peer's ACK delay.
- CUBIC congestion control with pacing, HyStart++ (RFC 9406) with
  conservative slow start, and a standing-queue brake in congestion
  avoidance. Queues are detected from per-round minimum RTTs, so jitter
  (Wi-Fi, cellular) is not mistaken for congestion.
- Loss classification: losses at the path's background rate (radio links,
  noisy lines) are repaired without slowing down; a standing queue or a
  statistically significant rise in loss is treated as congestion. The
  background rate is learned from pooled counts and settles within a few
  rounds.
- Self-healing bookkeeping (holes that are neither queued nor in flight
  are re-queued), stale-ACK filtering, and a resynchronisation through
  HELLO if the peers' views ever diverge.
- Path-MTU probing with "don't fragment" sockets; safe 1192-byte chunks as
  fallback; `EMSGSIZE` handled mid-transfer.
- Liveness probes, stall detection, automatic re-synchronisation after
  outages, peers may change address, resume across restarts of either peer
  from fsynced state.
- Whole-file BLAKE3-256 verification confirmed by both peers before a
  transfer is reported complete; the receiver verifies in the background
  while it keeps answering.
- Receiver serves many concurrent transfers; one dispatcher drains the
  socket; a coalescing writer thread takes payloads without copying them.

### Resume and lifecycle
- The receiver resumes by transfer id or by file name, size and source
  modification time; a source file that changed since the interrupted
  attempt is sent afresh instead of failing the final hash check.
- Sessions that receive no data after the handshake expire and remove their
  empty partial file; suspended sessions are reported to the application.
- Resume state older than 30 days is removed on start, together with its
  partial file.

### Reachability
- NAT handling moved to the receiver, in the background, so transfers start
  immediately. The sender needs no NAT handling of its own.

### Fixed
- Receiver no longer blocks its receive loop while a transfer is running.
- Receiver no longer exits on a malformed datagram; such datagrams are
  dropped.
- File names from the network are sanitised to a base name inside the
  output directory.
- `--no-nat` actually disables NAT traversal.
- No `block_on` inside `Drop` (which panicked inside the runtime); UPnP
  mappings are removed through explicit cleanup.
- Finalisation waits for all writes to complete before hashing and
  renaming.
- The sender terminates after a successful transfer.
- Windows: an ICMP "port unreachable" no longer breaks the receive loop
  (`SIO_UDP_CONNRESET` disabled); the GUI builds again (`winapi/winuser`).

### Removed
- The non-functional `--encrypt` flag and `tls` feature (no encryption was
  ever implemented; see the roadmap in the README).
- The relay binary, the coordinator client and the hole-punching code (no
  client ever used the relay, the two spoke incompatible protocols, and
  punching without a rendezvous service cannot work).
- The batch/hash-packet machinery, SAO batch sizing, and the MTU stub.
- Build artefacts (`target/`, 1.1 GB) and IDE files from version control.

### Front ends
- CLI tools print live progress, honour Ctrl-C (state is kept for resume),
  and expose chunk size, probing, rate cap and state directory options.
- The GUI sender drives the real transport instead of animating a fake
  progress bar; the GUI receiver shows an accept/reject dialog, real
  progress and the receiver's reachability.

### Tooling
- Minimum supported Rust version 1.82 (declared in `Cargo.toml`).
- Unit tests for the wire format (including malformed input), range sets
  (randomised against a bitmap), congestion control, file I/O and state;
  end-to-end tests through an impairing UDP proxy; an opt-in benchmark of
  lossy link profiles (`SHARP_BENCH` selects profiles).

### Licensing
- Relicensed under MIT (README already said so; the LICENSE file did not).
