# Changelog

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
- NAT handling moved to the receiver, in the background: STUN reports the
  public address, UPnP-IGD maps a port (renewed, removed on shutdown).
  Transfers start immediately. The sender needs no NAT handling.

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
