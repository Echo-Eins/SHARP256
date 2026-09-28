# SHARP-256 wire protocol, version 2

SHARP-256 (Swift Hash Assurance Rust Protocol) moves a single file from a
sender to a receiver over UDP. Version 2 replaces the batch/hash-packet
design of the original prototype with a self-describing, selectively
acknowledged, congestion-controlled transport whose correctness does not
depend on any shared mutable state between the peers.

Design goals, in priority order:

1. **Correctness.** A completed transfer is byte-exact. Every DATA packet
   carries its absolute file offset and an integrity tag; the whole file is
   verified with BLAKE3-256 by both peers before the transfer is declared
   complete.
2. **Robustness.** Any packet may be lost, duplicated, reordered or delayed.
   Either peer may crash, lose connectivity for minutes or change its
   address; the transfer resumes from durable state and never resends what
   the receiver already stored.
3. **Efficiency.** Selective acknowledgements, RACK loss detection, CUBIC
   congestion control with pacing and loss classification, path-MTU probing
   and coalesced disk writes keep the channel full without flooding it —
   also on paths with random (non-congestive) loss.
4. **Universality.** No assumptions about MTU, link speed, NAT or file size
   beyond a 64-bit offset space. Every control message fits into 1200 bytes.

Section 8 lists the default values of every tunable mentioned below.

## 1. Datagram layout

Every datagram is `header | body | tag`, all integers big-endian:

```
 offset  size  field
      0     2  magic       "SH" (0x53 0x48)
      2     1  version     2
      3     1  type        message type (section 2)
      4     2  flags       type-specific bits
      6     2  reserved    sent as 0, ignored on receipt
      8     4  conn_id     connection id chosen by the sender, never 0
     12     n  body        type-specific
   12+n    16  tag         truncated keyed BLAKE3 over header+body
```

The **tag** is `BLAKE3-keyed(K, header || body)[0..16]` where
`K = BLAKE3-derive_key("sharp256 v2 2026-09 datagram integrity tag", transfer_id)`.
`transfer_id` is a random 128-bit value chosen by the sender and carried in
HELLO. A datagram whose tag does not verify is dropped before any of its
fields is acted upon, so the tag protects against corruption that slipped
past the UDP checksum and against datagrams of other sessions or stray
traffic.

*Threat model.* The transfer id travels in the clear, so the tag is not an
authentication mechanism: an on-path attacker who saw HELLO can forge
datagrams, and nothing is encrypted. The 16-byte slot is sized for the MAC
or AEAD tag of a future authenticated handshake (section 7), which will
replace the derived key without changing the layout. Anyone who can reach
the receiver can also open sessions; the receiver bounds the damage (a
limited number of sessions, the free-space check, sparse pre-allocation,
and sessions without data expire after `handshake_timeout` together with
their empty partial file), and an application can decide on every request
through the `Ask` accept policy.

`conn_id` demultiplexes concurrent transfers at the receiver. Two transfers
that collide on `conn_id` with different transfer ids are rejected with
`REASON_CONN_CONFLICT`; the sender picks another id. A sender that restarts
presents the same transfer id under a new `conn_id`; the receiver moves the
session to the new id.

Receivers drop datagrams with a wrong magic, an unknown version or type, a
bad tag, or a malformed body. They never answer them.

## 2. Messages

| type | name       | direction | body |
|-----:|------------|-----------|------|
| 1 | HELLO      | S → R | `transfer_id[16] timestamp:u32 file_size:u64 file_mtime:i64 max_chunk:u16 capabilities:u32 name_len:u8 name[]` |
| 2 | HELLO_ACK  | R → S | `status:u8 reason:u8 max_chunk:u16 capabilities:u32 echo_ts:u32 max_ack_delay_us:u32 rwnd:u64 resume_upto:u64 known_end:u64 holes msg_len:u8 msg[]` |
| 3 | DATA       | S → R | `offset:u64 timestamp:u32 payload[]` |
| 4 | ACK        | R → S | `contiguous_upto:u64 highest:u64 received_bytes:u64 echo_ts:u32 ack_delay_us:u32 rwnd:u64 holes` |
| 5 | FIN        | R → S | `file_hash[32]` |
| 6 | FIN_ACK    | S → R | `verdict:u8 file_hash[32]` |
| 7 | PING       | S → R | `timestamp:u32` |
| 8 | PONG       | R → S | `echo:u32` |
| 9 | PROBE      | S → R | `size:u16 padding[]` (datagram padded to exactly `size` bytes) |
| 10 | PROBE_ACK | R → S | `size:u16` (size of the probe datagram actually received) |
| 11 | ABORT     | both  | `code:u16 len:u8 reason[]` |
| 12 | FIN_DONE  | R → S | `verdict:u8` (the verdict the receiver acted on) |

Text fields (`name`, `msg`, `reason`) are UTF-8, at most 255 bytes, and
shortened at a character boundary by the encoder when the datagram would
otherwise exceed 1200 bytes. File names must not be empty.

### Hole lists

`holes` is `n:u16` followed by `n` pairs of unsigned LEB128 varints
`(gap, len)`: the first hole starts `gap` bytes after the *base*, every
further hole `gap` bytes after the end of the previous one, and each hole
is `len` bytes long. The base is `resume_upto` in HELLO_ACK and
`contiguous_upto` in ACK; holes must lie within `[base, limit]` where the
limit is `known_end` (HELLO_ACK) or `highest` (ACK). A decoder rejects a
list with more than 1024 entries, a zero `len`, a zero `gap` after the
first hole (adjacent holes are one hole), an over-long varint, or a hole
beyond the limit.

A hole list uses at most 1024 bytes, enough for about 250–300 holes at
typical sizes. **Complete-description rule:** the list is always complete
for the interval it describes. When the receiver has more gaps than fit, it
shortens the interval — `highest` or `known_end` becomes the start of the
first gap that does not fit. Every byte in `[base, limit)` that is not in a
listed hole has therefore been received, which is what lets the sender
retire in-flight data from an ACK without ever acknowledging a byte that is
missing.

### Timestamps and RTT

Timestamps are the sender's monotonic microsecond clock truncated to 32
bits; 0 means "no timestamp" and is never sent by a sender. The receiver
echoes the timestamp of the most recent DATA packet in the next ACK, only
once (later ACKs echo 0 until new data arrives, so a sample is never
inflated), together with the time it held it (`ack_delay_us`). The sender
takes `now − echo_ts − ack_delay_us` as an RTT sample and ignores samples
above 60 s. HELLO/HELLO_ACK and PING/PONG provide further samples.

HELLO_ACK announces `max_ack_delay_us`, the longest time the receiver holds
back an ACK while data arrives (its ACK interval). RTT samples exclude that
delay, so the sender adds it back to its timeouts (as QUIC does with its
`max_ack_delay` transport parameter); values above 1 s are clamped.

### Flags

* HELLO `0x0001 RESUME` — the sender is willing to resume.
* HELLO_ACK `0x0001 RESUMED` — the receiver already stores part of the file.
* DATA `0x0001 RETRANSMIT` — the range was sent before (statistics only).

Unknown flag bits are ignored.

### Codes

HELLO_ACK `status`: 1 accepted, 2 rejected. `reason` when rejected:
1 disk space, 2 bad file name, 3 busy (too many sessions), 4 declined by
user, 5 connection-id conflict, 6 internal error, 7 decision timeout.
FIN_ACK `verdict`: 1 hashes match, 2 mismatch.
ABORT `code`: 2 cancelled, 3 I/O error, 4 timeout (peer unreachable),
5 protocol error. Code 1 is reserved: a peer that does not know a
connection has no key to tag an answer with, so "unknown connection" is
expressed by silence.

### Capabilities

HELLO offers a set of capability bits; HELLO_ACK confirms the subset the
receiver supports and will use. A peer uses a feature only if its bit is
confirmed. A receiver never confirms a bit it does not know; a sender that
sees a confirmed bit it did not offer aborts the handshake with a protocol
error. No capabilities are defined in version 2 (both sides send 0).

## 3. Session life cycle

```
Sender                                   Receiver
  |-- HELLO (retry w/ backoff) ------------>|  validate name, disk, policy
  |<------------------------- HELLO_ACK ----|  resume info from durable state
  |-- PROBE (largest first) --------------->|
  |<------------------------- PROBE_ACK ----|  chunk = largest acknowledged
  |== DATA (paced, window-limited) =======>|  written at its offset
  |<------------------------------- ACK ----|  every 8 packets / 20 ms / on gap
  |-- DATA (RACK loss, TLP, RTO) ---------->|
  |<------------------------------- FIN ----|  all bytes stored, fsynced, hashed
  |-- FIN_ACK (verdict) ------------------->|
  |<-------------------------- FIN_DONE ----|  verdict acted upon
```

### Handshake

The sender sends HELLO with exponential backoff (250 ms, doubling to 4 s)
until it receives HELLO_ACK or `handshake_timeout` expires. HELLO is
idempotent: the receiver answers every HELLO of a known transfer with a
*fresh* HELLO_ACK describing what it holds at that moment. The session is
created on the first HELLO; an `Ask` accept policy may take up to
`handshake_timeout − 2 s` to decide while duplicate HELLOs queue up.

HELLO_ACK tells the sender exactly what to send: the ranges in `holes` plus
everything from `known_end` to `file_size`. Everything else below
`known_end` is already stored. If the receiver's state is too fragmented to
describe, `known_end` is lowered as described above; the sender then resends
part of the tail, which is correct and only slightly wasteful. `rwnd` is
the receiver's free buffer space in bytes.

The chunk (file bytes per DATA packet) is `min(sender max, receiver max)`,
at least 512. The sender then probes the path: PROBE datagrams of exactly
the DATA size of each candidate chunk — the negotiated chunk, 1432 (fits a
1500-byte MTU over IPv4) and 1192 (fits the 1280-byte IPv6 minimum MTU) —
are sent largest first, each up to twice, waiting `clamp(3·SRTT, 150 ms,
2 s)`; the first size echoed by PROBE_ACK is used. If nothing answers, the
sender uses 1192 and lets the transfer itself find out whether the path
works. Sockets are "don't fragment" where the OS supports it, so oversized
datagrams fail (locally with `EMSGSIZE` or on the path) instead of being
fragmented. An `EMSGSIZE` during the transfer drops the chunk to 1192.

DATA packets are self-describing, so the chunk size may change at any time
without the receiver noticing.

### Data transmission (sender)

The file is partitioned into `pending` (to be sent), `inflight` (sent,
unacknowledged, with send time and send sequence) and acknowledged ranges.
The sender transmits the lowest pending range first (so retransmissions go
before new data) while `inflight + chunk ≤ max(min(cwnd, rwnd), 2 chunks)`
and the pacer permits. New data is read in 256 KiB read-ahead blocks;
retransmissions are read directly.

### Acknowledgement (receiver)

Each tag-verified DATA packet inside the file and at most 8960 bytes long
is inserted into a range set; bytes that are new go to a writer thread that
coalesces adjacent chunks into large positional writes. When the writer's
buffer is full the packet is dropped *without* being recorded — it stays a
hole and is retransmitted — and the shrinking `rwnd` slows the sender down.

The receiver sends an ACK after 8 DATA packets, at least every
`ack_interval` (20 ms) while data arrives, 2 ms after a packet above the
previous highest offset opens a gap (a short grace period for reordering),
every 200 ms while holes exist below the highest received byte (so lost
retransmissions are requested again even when no new data arrives), and
at once when the last missing byte arrives.

### ACK processing (sender)

1. **Stale filter.** `received_bytes` never decreases within a session, so
   an ACK that reports fewer bytes than an earlier one was reordered on the
   path and is ignored.
2. **Progress.** When `received_bytes` grew, the path is alive: the
   retransmission timer restarts and tail-probe accounting resets, even if
   the new bytes lie beyond the interval this ACK can describe.
3. **Delivery.** Everything below `contiguous_upto`, and every byte of
   `[contiguous_upto, highest)` outside the listed holes, is removed from
   `pending` and retires the in-flight packets it covers.
4. **Loss detection (RACK, RFC 8985).** An in-flight packet that overlaps a
   reported hole is lost when a packet sent at least `reo_wnd` later has
   been delivered, or when it has been outstanding for longer than
   `max(SRTT, latest RTT) + reo_wnd`, where
   `reo_wnd = clamp(min_rtt / 4, 1 ms, 250 ms)`. Send order, not file
   offset, decides, so a fresh retransmission is never condemned by ACKs
   that predate it. Lost packets return to `pending`.
5. **Self-healing.** Any part of a reported hole that is neither in flight
   nor pending is queued again, so no bookkeeping error can leave a gap
   unsent.
6. **Congestion response** according to the loss classification below.

### Loss classification

Radio links and noisy lines lose packets without being congested; treating
every loss as congestion collapses throughput there. The sender therefore
counts packets sent and lost per *round* (about one SRTT) and treats a loss
as a congestion signal only if

* a standing queue exists: the smallest RTT sample of the last complete
  round exceeds `min_rtt` by at least `max(min_rtt / 4, 2 ms)` (jitter
  moves single samples, not the minimum of a whole round, so a jittery
  but uncongested path does not qualify); or
* at least 20 % of the round's packets (with at least 20 sent) were lost;
  or
* the round lost clearly more than the path's background rate explains:
  `lost > E + 3·√(E + 1) + 1` with `E = base_loss_rate · sent` (about three
  standard deviations of a Poisson count, so one or two stray losses in a
  small round never qualify).

`base_loss_rate` is the ratio of bytes lost to bytes sent, pooled over
recent rounds with at least 16 packets and no congestion signal (both
counters decay by 0.9 per round, a memory of about ten rounds) and capped
at 15 %. Pooling counts rather than averaging per-round rates lets large
rounds weigh more, so the estimate settles within a few rounds instead of
misreading random loss as congestion for seconds. Other losses are repaired
without slowing down.

### Congestion control and pacing

CUBIC (RFC 8312) in bytes with `β = 0.7`, `C = 0.4`, fast convergence and
the TCP-friendly region, reducing at most once per SRTT. The initial window
is 32 chunks.

Slow start ends on the first congestive loss or through HyStart++
(RFC 9406). Time is divided into rounds of one SRTT, and the smallest RTT
sample of each round is kept. When a round's minimum (after at least 8
samples) exceeds the previous round's by `clamp(previous / 8, 4 ms, 16 ms)`,
a queue is building and slow start turns *conservative*: the window grows
at a quarter of the rate and pacing drops to the congestion-avoidance gain.
If a later round's minimum falls below the one that triggered this, the
rise was jitter and slow start resumes; if it persists for 5 rounds, slow
start ends before the buffer overflows. Comparing round minimums instead of
`SRTT − min_rtt` keeps jittery paths (Wi-Fi, cellular), whose average RTT
always lies above the minimum, from ending slow start early.

In congestion avoidance the window stops growing while the standing queue
(as defined above) exceeds `min_rtt + 10 ms`, so deep buffers do not turn
into seconds of latency and burst loss. `min_rtt` is a windowed minimum over
the current and the previous 10-second bucket, so a path whose base delay
grows (route change, roaming) is re-learned within 10–20 s.

The pacing rate is `gain · cwnd / SRTT` (gain 2 in slow start, 1.25 in
congestion avoidance, never below 64 chunks per second, optionally capped),
implemented as a token bucket whose burst is 2 ms worth of data at the
current rate, bounded to 16–1024 chunks, so that 1 ms timer granularity
does not starve fast links. Tokens of a datagram that could not be sent are
returned.

### Timers

* **Retransmission timeout** (RFC 6298, with the peer's ACK delay added
  as in QUIC): `SRTT + max(4·RTTVAR, 1 ms) + max_ack_delay`, clamped to
  `[min_rto, max_rto]`, doubled on each expiry up to 64×. It runs from the
  latest of the packet's send time, the last ACK progress (RFC 6298 §5.3)
  and the last tail probe. On expiry the expired packets return to
  `pending`, the window collapses to 2 chunks with
  `ssthresh = max(0.7·cwnd, 4 chunks)` and slow start begins again.
* **Tail loss probe** (RFC 8985 §7): when data is in flight but nothing was
  sent and no ACK made progress for
  `PTO = max(min(2·SRTT + max_ack_delay, RTO), 10 ms)`, the highest
  in-flight packet is sent again to provoke an ACK that reveals the losses
  (ACKs without progress, such as the receiver's periodic hole reports, do
  not postpone it). At most 2 probes are sent until an ACK makes progress.
  Because the probe fires no later than the RTO and postpones it, a lost
  tail is repaired by RACK with the current window; the window only
  collapses when the probes get no answer either.
* **Resynchronisation.** If nothing is pending or in flight but the
  receiver still misses bytes (only possible if the peers' views
  diverged), the sender asks with a HELLO every `max(4·SRTT, 200 ms)`
  and adopts the answer.

### Liveness, outages and resume

Both peers track the time of the last valid datagram from the other.

The sender sends PING after `clamp(2·RTO, 0.5 s, 3 s)` of silence and, from
3 s of silence on (or `stall_timeout` if shorter), also HELLO. A live
session answers HELLO with its current state; a restarted receiver resumes
from its saved state. Whichever HELLO_ACK answers such a probe, the sender
rebuilds `pending` from it, forgets its in-flight bookkeeping, keeps its
probed chunk size and restarts slow start. After `stall_timeout` of silence
the transfer is *stalled*: data stops, PING continues every 1, 2, then 4 s.
After `give_up_timeout` the sender sends ABORT (timeout), saves its state
and exits with a resumable error.

Either peer follows the other's address change (NAT rebinding, roaming):
it always answers the address the latest valid datagram came from.

**Durable state.** The receiver records `(transfer_id, file name, size,
source mtime, partial and final path, durable ranges)`. It persists every
`persist_interval`, but only after the writer thread has fsynced everything
the snapshot contains, so the recorded ranges are always really on disk.
On a new HELLO it looks the transfer up by transfer id, then by file name,
size and source mtime (so that a restarted sender with a new id resumes
too), and requires the partial file to exist with the announced size. The
sender records `(file path, size, peer) → (transfer_id, mtime)` when it is
cancelled or gives up, and presents that id again only if the file's mtime
is unchanged; a source that changed in between is sent afresh instead of
failing the final hash check. State files older than 30 days are deleted
when an endpoint starts, together with the partial files they describe.

**Session lifetime at the receiver.**

* A session that received no data within `handshake_timeout` after
  accepting it (sender vanished, spoofed HELLO) is dropped and its empty
  partial file removed; a partial file resumed from an earlier attempt is
  kept.
* ABORT from the sender suspends the session (state kept for resume), or
  drops it as above if no data arrived yet.
* After `stall_timeout` of silence the session reports *stalled* and
  flushes; after `session_ttl` it is suspended and reported as a resumable
  failure.
* On shutdown every transfer in progress is suspended the same way; a
  transfer that was already verified is reported complete (unconfirmed).

### Completion

When the receiver holds every byte it sends a final ACK and, in the
background, closes the writer (fsync), hashes the partial file with
BLAKE3-256 and renames it to its final name, answering HELLO, PING and PROBE
all the while. It then sends FIN with the hash, repeating it after 200 ms
and then with doubling intervals up to 3 s.

The sender stops sending on the first FIN and answers FIN_ACK with its
verdict and its own hash. Its hash is computed in the background from the
start; if it is not ready yet, the sender answers each FIN with a PING (so
the receiver knows it is alive) and sends FIN_ACK as soon as the hash is
done. The receiver answers the first FIN_ACK with FIN_DONE and ends the
session; the sender ends as soon as FIN_DONE arrives. Without FIN_DONE the
sender stays for `min(1 s + 4·SRTT, 3 s)` after its last FIN_ACK and
answers every repeated FIN, which restarts that wait: if a FIN_ACK was
lost, the receiver's retries (after 200 ms and 400 ms more) still find the
sender. The verdict itself never depends on FIN_DONE. `verdict = 1` completes the transfer on both
sides and removes resume state. `verdict = 2` fails it: the receiver keeps
the file under a `.mismatch` suffix, and both sides discard resume state so
the next attempt starts clean. A receiver that gets no FIN_ACK before the
sender falls silent for `stall_timeout` (or within `give_up_timeout`) keeps
the file — every packet passed its tag and the file is complete — and
reports it complete but *unconfirmed*.

## 4. File handling

* File names from the wire are reduced to a base name; control characters
  and characters illegal on Windows are replaced, reserved device names are
  prefixed. The output path is always inside the configured directory.
* Partial files are written as `name.sharp-part` (or `name (1).sharp-part`
  if an unrelated partial file already exists) and renamed on success. An
  existing complete `name` is never overwritten unless configured; the new
  file becomes `name (1)`.
* Files are pre-sized with `set_len`, which creates a sparse file where the
  file system supports it. Free space is checked for the bytes still to be
  received plus a 1 MiB margin before accepting.
* The "256" of the name survives as the 256 KiB block granularity of the
  sender's read-ahead and as the 256-bit output of BLAKE3.

## 5. Reachability and NAT

A receiver must be reachable at the address senders use. With the
`nat-traversal` feature the receiver, in the background and without
delaying transfers, asks public STUN servers under which address its
transfer socket is seen (and whether the mapping depends on the
destination), and asks the router for a UPnP-IGD port forward — the same
external port if possible, any port otherwise — renewed at half its lease
and removed on shutdown. The result is reported as a `Reachability` event.
STUN responses arrive on the transfer socket and are routed to the NAT task
by the receiver's dispatcher.

The sender needs no NAT handling: its outgoing datagrams create the mapping
on its own NAT, and the receiver always answers the address datagrams come
from. Two peers that are both behind NATs without a port forward cannot
reach each other; that needs a rendezvous or relay service (section 7).

## 6. Implementation notes

* The receiver's socket is read by one dispatcher task that drains all
  queued datagrams, verifies HELLOs, and routes everything else by
  `conn_id` to per-session tasks (queues of 16384 datagrams; a full queue
  drops, which the protocol treats as loss).
* The sender's engine is a single-owner state machine; each turn drains
  the socket, runs timers and then sends up to 256 datagrams before
  yielding.
* Sockets request 8 MiB kernel buffers (the OS may clamp this; see
  `net.core.rmem_max` on Linux). On Windows, `SIO_UDP_CONNRESET` is
  disabled so that an ICMP "port unreachable" does not break the receive
  loop.

## 7. Versioning and extensibility

The format is designed to grow without breaking deployed peers:

* `version` is checked strictly; an incompatible change bumps it. A
  version 2 receiver silently drops datagrams of any other version, so a
  sender of a later version that gets no answer to its HELLO falls back to
  a version 2 HELLO. Future versions keep the version-independent prefix —
  magic, version and type in bytes 0–3, `conn_id` in bytes 8–11 and, for
  HELLO, the transfer id in bytes 12–27 — so that a receiver can always
  recognise and answer a HELLO it understands.
* `reserved` header bytes are sent as 0 and ignored; unknown flag bits are
  ignored.
* Control messages grow by appending fields at the end of the body; a
  decoder ignores trailing bytes it does not understand. DATA has no room
  at the end (its payload runs to the end of the body), so new DATA fields
  require a flag bit that announces them.
* New behaviour is negotiated through capability bits (section 2); a
  feature is only used once HELLO_ACK has confirmed it.
* Every control message is bounded to 1200 bytes by construction.

Extensions planned on this basis:

| extension | mechanism |
|-----------|-----------|
| Authenticated handshake and encryption (X25519, Noise-style) | capability bit; key exchange in appended HELLO/HELLO_ACK fields; the 16-byte tag becomes the AEAD tag; `conn_id` stays in the clear for demultiplexing |
| Block-hash manifest (BLAKE3 per 256 KiB) | capability bit; verifies resumed data and localises corruption before the final check |
| Several files or a directory per session | capability bit; file index in appended HELLO fields |
| Rendezvous / relay for peers that are both behind NAT | separate service; the transfer protocol is unchanged |
| Batched socket I/O (`sendmmsg`/`recvmmsg`, GSO/GRO) | local optimisation, no wire change |

## 8. Defaults

| setting | default | meaning |
|---------|---------|---------|
| `max_chunk` | 1432 B | largest file bytes per DATA packet (512–8960) |
| `probe_mtu` | on | probe the path before sending data |
| `initial_cwnd_chunks` | 32 | initial congestion window |
| `max_cwnd_bytes` | 256 MiB | upper bound of the congestion window |
| `max_rate_bytes` | none | optional send-rate cap |
| `ack_interval` | 20 ms | ACK at least this often while data arrives |
| `ack_every_packets` | 8 | ACK after this many DATA packets |
| `min_rto` / `max_rto` | 100 ms / 30 s | bounds of the retransmission timeout |
| `stall_timeout` | 20 s | silence after which a transfer is stalled |
| `give_up_timeout` | 5 min | silence after which the sender gives up (resumable) |
| `handshake_timeout` | 60 s | total time for HELLO retries; idle-session limit |
| `socket_buffer_bytes` | 8 MiB | requested kernel socket buffers |
| `persist_interval` | 2 s | how often the receiver persists durable progress |
| `writer_capacity_bytes` | 64 MiB | receiver write buffer (source of `rwnd`) |
| `session_ttl` | 10 min | silence after which a receiver session is suspended |
| `max_sessions` | 16 | concurrent transfers per receiver |
