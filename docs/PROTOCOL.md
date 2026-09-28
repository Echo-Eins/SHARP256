# SHARP-256 wire protocol, version 3

SHARP-256 (Swift Hash Assurance Rust Protocol) moves a file or a whole
directory tree from a sender to a receiver over UDP. Version 3 keeps the
reliable, selectively acknowledged, congestion-controlled transport of
version 2 and puts it inside an authenticated, encrypted channel: every
datagram after the handshake is an AEAD-protected transport packet, both
peers are identified by long-term keys, and a receiver stays silent to
anyone who does not know its identity.

Design goals, in priority order:

1. **Correctness.** A completed transfer is byte-exact. Every DATA packet
   carries its absolute stream offset; the whole stream is verified with
   BLAKE3-256 by both peers before the transfer is declared complete.
2. **Security.** Confidentiality and integrity of everything after the
   handshake, mutual authentication by long-term keys, forward secrecy,
   resistance to replay, and a receiver that neither answers strangers nor
   spends public-key operations on spoofed traffic.
3. **Robustness.** Any packet may be lost, duplicated, reordered, delayed
   or forged. Either peer may crash, lose connectivity for minutes or
   change its address; the transfer resumes from durable state and never
   resends what the receiver already stored.
4. **Efficiency.** Selective acknowledgements, RACK loss detection, CUBIC
   with pacing and loss classification, path-MTU probing, batched datagram
   I/O and multi-core packet encryption keep the channel full without
   flooding it, from lossy radio links to 10 GbE.
5. **Universality.** No assumptions about MTU, link speed, NAT or data size
   beyond a 64-bit offset space. Every control datagram fits into
   1200 bytes.

Section 12 lists the default values of every tunable mentioned below. All
integers on the wire are big-endian unless stated otherwise.

## 1. Identities and addressing

Every endpoint has a long-term **identity**: an X25519 key pair, created on
first use and stored in the per-user data directory
(`~/.local/share/sharp-256/identity.key`, `%APPDATA%\sharp-256\identity.key`,
...) with owner-only permissions.

A **SHARP ID** is the public key in text form: `sh-` followed by 56
lower-case base32 characters (RFC 4648 alphabet, no padding) encoding the
32-byte public key and a 3-byte checksum,
`BLAKE3-derive_key("sharp256 id checksum", public_key)[0..3]`, so that a
mistyped ID is rejected instead of addressing somebody else.

A sender addresses a receiver as `ID@host:port`. The ID is not a hint: the
handshake succeeds only with the holder of the matching private key, so it
authenticates the receiver. IDs are exchanged out of band (the receiver
prints its own), like SSH host keys.

A receiver may restrict senders to an **allow-list** of sender IDs. Both
sides may additionally share a **secret**: a passphrase that becomes the
Noise pre-shared key
`PSK = Argon2id(passphrase, salt = "sharp256 v3 psk " || receiver_public_key)`
with 64 MiB of memory, 3 passes, 1 lane and 32 bytes of output. Salting
with the receiver's key makes the same passphrase yield unrelated keys for
different receivers; the cost makes offline guessing expensive. Without a
secret the PSK is 32 zero bytes.

## 2. Handshake

The handshake is Noise `IKpsk2_25519_ChaChaPoly_BLAKE2s` (the pattern
WireGuard uses) with the prologue `SHARP-256 v3`, wrapped with connection
ids and two MACs:

```
initiation  S → R   sender_cid[8] | e[32] | enc(s)[48] | enc(payload)[n+16] | mac1[16] | mac2[16]
response    R → S   sender_cid[8] | receiver_cid[8] | e[32] | enc(payload)[n+16] | mac1[16] | mac2[16]
cookie      R → S   sender_cid[8] | nonce[24] | enc(cookie)[16] | tag[16]
```

* The sender knows the receiver's static key (its ID) in advance, so the
  receiver is authenticated by construction; the sender's static key
  travels encrypted (identity hiding). Both sides contribute ephemeral
  keys, so every session has fresh keys (forward secrecy). The PSK is mixed
  in after the key exchange (`psk2`), which also protects recorded traffic
  against a future break of X25519 when a secret is used.
* Connection ids are random, non-zero 64-bit values chosen by the side
  that *receives* with them: the sender chooses `sender_cid` per attempt,
  the receiver `receiver_cid` per session. Every later datagram starts with
  the id of its recipient, which is all the receiver needs to find the
  session.
* `mac1 = BLAKE3-keyed(K1, datagram up to mac1)[0..16]` with
  `K1 = BLAKE3-derive_key("sharp256 v3 mac1", recipient_public_key)`. A
  receiver checks mac1 of every datagram that belongs to no session before
  doing anything else, and drops it silently if it is wrong: to anyone who
  does not know its ID, a receiver looks like a closed port. The response
  carries a mac1 keyed with the *sender's* key; its mac2 is zero.
* `mac2 = BLAKE3-keyed(K2, datagram up to mac2)[0..16]` with
  `K2 = BLAKE3-derive_key("sharp256 v3 mac2", cookie)` proves that the
  sender receives at its source address (below); it is zero when the
  sender has no cookie.

### Admission control

A receiver processes a datagram that belongs to no session as follows:

1. **mac1.** Wrong: drop silently.
2. **Load.** When more than `handshake_load_threshold` initiations per
   second arrive (all sources together), the receiver is *under load* and
   requires a valid mac2. An initiation without one gets a **cookie
   reply** instead of any public-key work. The cookie is
   `BLAKE3-keyed(secret, source_ip_as_ipv6 || source_port)[0..16]`; the
   secret changes every 120 s (the previous one stays valid). It travels
   encrypted with XChaCha20-Poly1305 under
   `BLAKE3-derive_key("sharp256 v3 cookie", receiver_public_key)`, a random
   nonce and the initiation's mac1 as associated data, so only the sender
   of that initiation can use it. The sender repeats its initiation with
   mac2 computed from the cookie. Spoofed floods thus cost one MAC per
   datagram and never produce amplification (the reply is smaller than
   the initiation).
3. **Rate limit.** Each source address may start `handshake_rate`
   handshakes per second (burst `handshake_burst`); excess is dropped.
4. **Noise.** The initiation must decrypt under the receiver's static key.
5. **Replay.** The initiation payload starts with a timestamp (nanoseconds
   since the Unix epoch, strictly increasing per process). The receiver
   remembers the latest timestamp per sender identity (up to 100 000
   senders) and drops initiations that are not newer. A recorded
   initiation therefore cannot be replayed, and it could not complete the
   handshake anyway without the sender's keys.
6. **Authorisation.** A sender that is not on the allow-list receives an
   authenticated rejection (reason 8) and nothing else.

The PSK is verified by the sender when it reads the response: a receiver
with a different secret produces a response that fails to decrypt, which
the sender reports as a probable secret mismatch.

### Handshake payloads

The encrypted payload of the initiation is
`timestamp:u64 suites:u8 hardware_aes:u8 hello_flags:u8 HELLO-body`; the
payload of the response is `suite:u8 ack_flags:u8 HELLO_ACK-body` (frame
bodies are defined in section 4). The response payload is bounded so that
the response datagram never exceeds 1200 bytes.

`suites` is the set of AEAD suites the sender supports (bit 0x1
AES-256-GCM, bit 0x2 ChaCha20-Poly1305) and `hardware_aes` tells whether
the sender has AES instructions. The receiver picks AES-256-GCM if both
sides accelerate it and ChaCha20-Poly1305 otherwise; with nothing in
common it rejects (reason 9). A rejected response carries suite 0 and no
session is created.

### Traffic keys

From the Noise split `(k_i→r, k_r→i)` and the handshake hash `h`, each
direction gets the secret
`S = BLAKE3-derive_key("sharp256 v3 traffic secret", k || h)`, and from it

* `iv = BLAKE3-derive_key("sharp256 v3 aead iv", S)[0..12]`,
* `hp = BLAKE3-derive_key("sharp256 v3 header protection", S)`,
* per *epoch* of 2^22 packets:
  `key(epoch) = BLAKE3-derive_key("sharp256 v3 aead key", S || epoch:u64)`.

Keys change every 2^22 packets without any signalling (both sides derive
the epoch from the packet number), which keeps every key far inside the
usage limits of AES-GCM.

### Attempts and retries

Every handshake attempt uses a new ephemeral key and a new `sender_cid`.
The sender retries with exponential backoff (250 ms, doubling to 4 s) until
`handshake_timeout`; a response may answer any of its last four attempts.
The session starts when a response authenticates.

## 3. Transport packets

After the handshake every datagram is a transport packet:

```
 0        8      9               17                      n-16      n
 +--------+------+----------------+-----------------------+---------+
 |  dcid  | type | packet number  |  encrypted frame body |   tag   |
 +--------+------+----------------+-----------------------+---------+
            \_______ masked ______/
```

* `dcid` — the recipient's connection id, in the clear.
* `type` — the frame type (low four bits) and four frame-specific flag bits
  (high four bits).
* `packet number` — 64-bit, starting at 0 per direction and session, never
  reused.
* The body is encrypted with the session's AEAD, nonce `iv XOR (0^4 || pn)`,
  associated data the *unmasked* 17-byte header; the 16-byte tag follows.
* **Header protection** (as in QUIC): `type` and `packet number` are XORed
  with the first 9 bytes of a mask computed from the tag as sample:
  `AES-256(hp, tag)` for AES-GCM sessions, or the ChaCha20 keystream under
  key `hp` with counter `tag[0..4]` (little-endian) and nonce `tag[4..16]`.
  An observer sees neither message kinds nor packet numbers, so
  retransmissions, reordering and acknowledgement patterns stay hidden.

A packet is 33 bytes plus the frame body. The recipient finds the session
by `dcid`, removes header protection, and drops the packet unless the tag
verifies. Packet numbers pass a replay window of 8192 packets (a packet
older than the window, or seen before, is dropped), so an attacker can
neither inject nor replay anything. Datagrams addressed to a connection id
that was replaced by a newer handshake are dropped as stale.

## 4. Frames

Every transport packet carries exactly one frame. HELLO and HELLO_ACK also
travel inside the handshake (section 2).

| type | name       | direction | body |
|-----:|------------|-----------|------|
| 1 | HELLO      | S → R | `transfer_id[16] timestamp:u32 file_size:u64 file_mtime:i64 max_chunk:u16 capabilities:u32 kind:u8 [tree] name_len:u8 name[]` |
| 2 | HELLO_ACK  | R → S | `status:u8 reason:u8 max_chunk:u16 capabilities:u32 echo_ts:u32 max_ack_delay_us:u32 rwnd:u64 resume_upto:u64 known_end:u64 holes msg_len:u8 msg[]` |
| 3 | DATA       | S → R | `offset:u64 timestamp:u32 payload[]` |
| 4 | ACK        | R → S | `contiguous_upto:u64 highest:u64 received_bytes:u64 echo_ts:u32 ack_delay_us:u32 rwnd:u64 holes` |
| 5 | FIN        | R → S | `stream_hash[32]` |
| 6 | FIN_ACK    | S → R | `verdict:u8 stream_hash[32]` |
| 7 | PING       | S → R | `timestamp:u32` |
| 8 | PONG       | R → S | `echo:u32` |
| 9 | PROBE      | S → R | `size:u16 padding[]` (packet padded to exactly `size` bytes) |
| 10 | PROBE_ACK | R → S | `size:u16` (size of the probe datagram actually received) |
| 11 | ABORT     | both  | `code:u16 len:u8 reason[]` |
| 12 | FIN_DONE  | R → S | `verdict:u8` (the verdict the receiver acted on) |
| 13 | PATH_CHALLENGE | both | `token[8]` (unpredictable) |
| 14 | PATH_RESPONSE  | both | `token[8]` (echo of a challenge) |

`kind` is 0 for a single file and 1 for a directory; a directory adds
`tree = manifest_len:u64 manifest_hash[32] files:u64 dirs:u64` (section 6).
For a directory `file_size` is the length of the whole stream and `name`
the name of the directory.

Text fields (`name`, `msg`, `reason`) are UTF-8, at most 255 bytes, and
shortened at a character boundary by the encoder when the datagram would
otherwise exceed 1200 bytes. Names must not be empty.

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
above 60 s. The handshake and PING/PONG provide further samples.

HELLO_ACK announces `max_ack_delay_us`, the longest time the receiver holds
back an ACK while data arrives. RTT samples exclude that delay, so the
sender adds it back to its timeouts (as QUIC does with its `max_ack_delay`
transport parameter); values above 1 s are clamped.

### Flags

Flags occupy the high four bits of the type byte:

* HELLO `0x1 RESUME` — the sender is willing to resume.
* HELLO_ACK `0x1 RESUMED` — the receiver already stores part of the stream.
* DATA `0x1 RETRANSMIT` — the range was sent before (statistics only).

Unknown flag bits are ignored.

### Codes

HELLO_ACK `status`: 1 accepted, 2 rejected, 3 pending (the receiver's user
has not decided yet). `reason` when rejected: 1 disk space, 2 bad name,
3 busy (too many sessions), 4 declined by user, 5 connection-id conflict,
6 internal error, 7 decision timeout, 8 sender not authorised, 9 no cipher
suite in common, 10 unsupported request (for instance a directory listing
beyond the receiver's limits).
FIN_ACK `verdict`: 1 hashes match, 2 mismatch.
ABORT `code`: 2 cancelled, 3 I/O error (also: a directory that cannot be
stored, such as colliding names or an invalid listing), 4 timeout (peer
unreachable), 5 protocol error.

### Capabilities

HELLO offers a set of capability bits; HELLO_ACK confirms the subset the
receiver supports and will use. A peer uses a feature only if its bit is
confirmed. A receiver never confirms a bit it does not know; a sender that
sees a confirmed bit it did not offer aborts with a protocol error. No
capabilities are defined in version 3 (both sides send 0); directory
transfers and encryption are part of the base protocol.

## 5. Session life cycle

```
Sender                                          Receiver
  |-- initiation {HELLO} (retry w/ backoff) ----->|  mac1, load, rate, Noise, replay,
  |                                               |  allow-list; name, disk, policy
  |<------------------- response {HELLO_ACK} -----|  resume info from durable state
  |   [status pending: HELLO every 1 s  ------->  |  the user decides ...
  |    <------------ HELLO_ACK (accepted) ------- ]|
  |-- PROBE (largest first) --------------------->|
  |<------------------------------- PROBE_ACK ----|  chunk = largest acknowledged
  |== DATA (paced, window-limited, batched) =====>|  written at its offset
  |<------------------------------------- ACK ----|  per receive batch / 20 ms / on gap
  |-- DATA (RACK loss, TLP, RTO) ---------------->|
  |<------------------------------------- FIN ----|  all bytes stored, fsynced, hashed
  |-- FIN_ACK (verdict) ------------------------->|
  |<-------------------------------- FIN_DONE ----|  verdict acted upon
```

### Handshake and decision

The initiation carries HELLO; the response carries a HELLO_ACK that
describes exactly what the receiver holds at that moment, so every
handshake doubles as a resume point. If the receiver's application has to
decide (an accept dialog), the response says *pending*; the sender then
sends a HELLO frame over the new session every second, each answered with
the current status, and the receiver also sends an unsolicited HELLO_ACK as
soon as the decision is made. No decision within `handshake_timeout` means
rejected (reason 7).

HELLO_ACK tells the sender what to send: the ranges in `holes` plus
everything from `known_end` to `file_size`. Everything else below
`known_end` is already stored. If the receiver's state is too fragmented to
describe, `known_end` is lowered as described above; the sender then resends
part of the tail, which is correct and only slightly wasteful. `rwnd` is
the receiver's free buffer space in bytes.

The chunk (payload bytes per DATA packet) is `min(sender max, receiver
max)`, at least 512. The sender then probes the path: PROBE packets of
exactly the DATA size of each candidate chunk — the negotiated chunk, 1427
(fits a 1500-byte MTU over IPv4) and 1187 (fits the 1280-byte IPv6 minimum
MTU) — are sent largest first, each up to twice, waiting
`clamp(3·SRTT, 150 ms, 2 s)`; the first size echoed by PROBE_ACK is used.
If nothing answers, the sender uses 1187 and lets the transfer itself find
out whether the path works. Sockets are "don't fragment" where the OS
supports it, so oversized datagrams fail (locally with `EMSGSIZE` or on the
path) instead of being fragmented. An `EMSGSIZE` during the transfer drops
the chunk to 1187. DATA packets are self-describing, so the chunk size may
change at any time without the receiver noticing.

### Data transmission (sender)

The stream is partitioned into `pending` (to be sent), `inflight` (sent,
unacknowledged, with send time and send sequence) and acknowledged ranges.
The sender transmits the lowest pending range first (so retransmissions go
before new data) while `inflight + chunk ≤ max(min(cwnd, rwnd), 2 chunks)`
and the pacer permits. New data is read in 256 KiB read-ahead blocks;
retransmissions are read directly.

Datagrams are built back to back into *batches* that one system call sends
(section 10); every datagram of a batch but the last has the full size, and
a batch never carries more than about 1 ms of data at the current pacing
rate, so a batch never becomes a burst that overruns a shallow buffer on
the path.

### Acknowledgement (receiver)

Each authentic DATA packet inside the stream and at most 8927 payload bytes
long is inserted into a range set; bytes that are new go to a writer thread
that coalesces adjacent payloads into large positional writes. When the
writer's buffer is full the packet is dropped *without* being recorded — it
stays a hole and is retransmitted — and the shrinking `rwnd` slows the
sender down. `rwnd` is the writer's free space minus the datagrams still
queued for the session, so a receiver whose processing falls behind asks
for less.

The receiver sends an ACK after each batch of received datagrams that
brings at least 8 new DATA packets, at least every `ack_interval` (20 ms)
while data arrives, 2 ms after a packet above the previous highest offset
opens a gap (a short grace period for reordering), every 200 ms while
holes exist below the highest received byte (so lost retransmissions are
requested again even when no new data arrives), and at once when the last
missing byte arrives.

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
   `reo_wnd = clamp(min_rtt / 4, 1 ms, 250 ms)`. Send order, not stream
   offset, decides, so a fresh retransmission is never condemned by ACKs
   that predate it. Lost packets return to `pending`.
5. **Self-healing.** Any part of a reported hole that is neither in flight
   nor pending is queued again, so no bookkeeping error can leave a gap
   unsent.
6. **Congestion response** according to the loss classification below.

### Loss classification

Radio links and noisy lines lose packets without being congested; treating
every loss as congestion collapses throughput there. The sender therefore
counts packets sent and lost per *round* (about one SRTT, at least 5 ms)
and treats a loss as a congestion signal only if

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
rounds weigh more, so the estimate settles within a few rounds. Other
losses are repaired without slowing down.

### Congestion control and pacing

CUBIC (RFC 8312) in bytes with `β = 0.7`, `C = 0.4`, fast convergence and
the TCP-friendly region, reducing at most once per SRTT. The initial window
is 32 chunks. The window grows only while it is used: when neither the
current nor the previous round had at least half the window in flight, the
sender is limited by something else (its own speed, the receiver) and ACKs
do not grow the window (RFC 9002, section 7.8). A window that is never
filled would otherwise make pacing meaningless.

Slow start ends on the first congestive loss or through HyStart++
(RFC 9406). Time is divided into rounds of one SRTT, and the smallest RTT
sample of each round is kept. When a round's minimum (after at least 8
samples) exceeds the previous round's by `clamp(previous / 8, 4 ms, 16 ms)`,
a queue is building and slow start turns *conservative*: the window grows
at a quarter of the rate and pacing drops to the congestion-avoidance gain.
If a later round's minimum falls below the one that triggered this, the
rise was jitter and slow start resumes; if it persists for 5 rounds, slow
start ends before the buffer overflows.

In congestion avoidance the window stops growing while the standing queue
exceeds `min_rtt + 10 ms`, so deep buffers do not turn into seconds of
latency and burst loss. `min_rtt` is a windowed minimum over the current
and the previous 10-second bucket, so a path whose base delay grows is
re-learned within 10–20 s.

The pacing rate is `gain · cwnd / SRTT` (gain 2 in slow start, 1.25 in
congestion avoidance, never below 64 chunks per second, optionally capped),
implemented as a token bucket whose burst is 1 ms worth of data at the
current rate (the timer granularity), bounded to 16–1024 chunks.

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
  in-flight packet is sent again to provoke an ACK that reveals the losses.
  At most 2 probes are sent until an ACK makes progress. Because the probe
  fires no later than the RTO and postpones it, a lost tail is repaired by
  RACK with the current window.
* **Resynchronisation.** If nothing is pending or in flight but the
  receiver still misses bytes (only possible if the peers' views
  diverged), the sender asks with a HELLO frame every `max(4·SRTT, 200 ms)`
  and adopts the HELLO_ACK that echoes it.

### Liveness, outages and resume

Both peers track the time of the last authentic packet from the other.

The sender sends PING after `clamp(2·RTO, 0.5 s, 3 s)` of silence and, from
3 s of silence on (or `stall_timeout` if shorter), also a **new
handshake**. A live receiver session answers it with its current state
under new keys and a new connection id; a restarted receiver, which lost
the session keys, resumes from its saved state. Whichever HELLO_ACK
answers, the sender rebuilds `pending` from it, forgets its in-flight
bookkeeping, keeps its probed chunk size and restarts slow start. After
`stall_timeout` of silence the transfer is *stalled*: data stops, PING
continues every 1, 2, then 4 s. After `give_up_timeout` the sender sends
ABORT (timeout), saves its state and exits with a resumable error.

Either peer follows the other's address change (NAT rebinding, roaming):
it always answers the address the latest authentic packet came from. Since
packets are authenticated, an attacker cannot redirect a session by
spoofing its source address.

**Durable state.** The receiver records `(transfer_id, sender ID, name,
size, source mtime or manifest hash, partial and final path, durable
ranges)`, and for a directory its manifest. It persists every
`persist_interval`, but only after the writer thread has fsynced everything
the snapshot contains, so the recorded ranges are always really on disk. On
a handshake it looks the transfer up by transfer id, then by sender, name,
size and source mtime (or manifest hash), so that a restarted sender with a
new transfer id resumes too; only the sender that started a partial
transfer may continue it, and a partial path that became a symbolic link is
never followed. The sender records `(path, size, receiver ID) →
(transfer_id, mtime or manifest hash)` when it is cancelled or gives up,
and presents that id again only if the source is unchanged; a source that
changed in between is sent afresh instead of failing the final hash check.
State files older than 30 days are deleted when an endpoint starts,
together with the partial files or staging directories they describe.

**Session lifetime at the receiver.**

* A session that received no data within `handshake_timeout` after
  accepting it is dropped and its empty partial file removed; a partial
  file resumed from an earlier attempt is kept.
* ABORT from the sender suspends the session (state kept for resume), or
  drops it as above if no data arrived yet.
* A writer error ends the transfer: names that collide on the receiver's
  file system abandon it (nothing can fix them), other I/O errors (disk
  full) suspend it for a later resume.
* After `stall_timeout` of silence the session reports *stalled* and
  flushes; after `session_ttl` it is suspended and reported as a resumable
  failure.
* On shutdown every transfer in progress is suspended the same way; a
  transfer that was already verified is reported complete (unconfirmed).

### Completion

When the receiver holds every byte it sends a final ACK and, in the
background, closes the writer (fsync), hashes the stream with BLAKE3-256 and
moves the result to its final name, answering HELLO, PING and PROBE all the
while. It then sends FIN with the hash, repeating it after 200 ms and then
with doubling intervals up to 3 s.

The sender stops sending on the first FIN and answers FIN_ACK with its
verdict and its own hash, which it computes in the background from the
start; if it is not ready yet, the sender answers each FIN with a PING and
sends FIN_ACK as soon as the hash is done. The receiver answers the first
FIN_ACK with FIN_DONE and ends the session; the sender ends as soon as
FIN_DONE arrives. Without FIN_DONE the sender stays for
`min(1 s + 4·SRTT, 3 s)` after its last FIN_ACK and answers every repeated
FIN. `verdict = 1` completes the transfer on both sides and removes resume
state. `verdict = 2` fails it: the receiver keeps the result under a
`.mismatch` suffix, and both sides discard resume state. A receiver that
gets no FIN_ACK before the sender falls silent for `stall_timeout` keeps
the result — every packet was authentic and the stream is complete — and
reports it complete but *unconfirmed*.

## 6. Directory transfers

A directory travels as one stream, so that everything above — reliability,
flow control, resume and the final verification — applies unchanged:

```
[ manifest ][ contents of file 1 ][ contents of file 2 ] ... [ file n ]
```

The **manifest** lists every directory and regular file below the root:
parents before their children, siblings in byte order of their names, each
with its size, Unix permission bits and modification time. File contents
follow in manifest order; directories and empty files occupy no bytes. The
final BLAKE3 hash of the stream therefore covers names, structure,
metadata and contents. Symbolic links and special files are not
transferred; the sender skips and reports them. Names must be valid
Unicode (a sender refuses to send a tree that contains other names).

### Manifest encoding

```
manifest = version:u8 (1)  reserved:u8 (0)  root  count:varint  entry*
root     = head  meta
entry    = head  parent:varint  name_len:varint  name  [size:varint]  meta
head     = u8: bit 0 directory, bit 1 mode present, bit 2 mtime present
meta     = [mode:varint]  [seconds:zigzag varint  nanoseconds:varint]
```

`parent` is 0 for the root, otherwise one plus the index of an earlier
directory entry; `size` is present for files only; `mode` holds Unix
permission bits (at most `0o7777`); `seconds` and `nanoseconds` are the
modification time relative to the Unix epoch (nanoseconds below 10^9).
Varints are minimal unsigned LEB128.

A decoder rejects everything else: unknown bits, a parent that is not an
earlier directory, names that are empty, `.` or `..`, contain `/` or NUL,
or exceed 255 bytes, siblings out of order or repeated, a depth beyond 256
levels, a relative path beyond 4096 bytes, more than 2^21 entries, a
manifest beyond 64 MiB, sizes that overflow, and trailing bytes.

### HELLO fields

`tree = manifest_len:u64 manifest_hash[32] files:u64 dirs:u64`, with
`manifest_hash = BLAKE3(manifest)`. The receiver can show "12 files in 3
folders, 4.2 GiB" before accepting, and it checks every one of these values
against the manifest.

### Receiving safely

* The receiver collects the manifest region `[0, manifest_len)` in memory.
  Only when it is complete, matches `manifest_hash`, decodes, and agrees
  with the HELLO (stream length, counts) does the writer create anything.
  DATA that overtakes the manifest (because some of its packets were lost)
  waits in a bounded buffer. A manifest that fails any check ends the
  transfer (ABORT, I/O error) and leaves nothing behind.
* The tree is built inside a fresh staging directory `name.sharp-part`
  next to the output, which only its owner may enter. Nothing outside it is
  ever written, and no symbolic link is created inside it.
* Names are single components by construction. They are stored as they are
  on Unix; on Windows, reserved characters (`<>:"/\|?*` and control
  characters) become `_`, trailing dots and spaces are removed and device
  names (`CON`, `nul.txt`, `COM1`, ...) get a `_` prefix.
* Every entry is created with "create new" semantics. Two names that the
  local file system considers the same (case-insensitive file systems,
  names mapped for Windows) are therefore reported as a collision — the
  transfer is abandoned — instead of one overwriting the other. Files are
  created when their first byte arrives, directories when something inside
  them is created, the rest when the stream is complete.
* When complete, the receiver hashes the stream from disk, applies
  modification times and permission bits (deepest entries first; never
  set-id or sticky bits; masked with the receiver's umask) and renames the
  staging directory to the final name, which never replaces anything: a
  taken name becomes `name (1)`.
* The manifest is kept with the resume state, so an interrupted directory
  resumes after a restart of either side without resending it. Files that
  already exist in the staging directory are reused on resume; their data
  is still covered by the final hash.

## 7. File handling

* Names of single files from the wire are reduced to a base name; control
  characters and characters illegal on Windows are replaced, reserved
  device names are prefixed. The output path is always inside the
  configured directory.
* Partial files are written as `name.sharp-part` (or `name (1).sharp-part`
  if an unrelated partial file already exists) and renamed on success. An
  existing complete `name` is never overwritten unless configured; the new
  file becomes `name (1)`. Directories are never overwritten or merged.
* Files are pre-sized with `set_len`, which creates a sparse file where the
  file system supports it. Free space is checked for the bytes still to be
  received plus a 1 MiB margin before accepting.
* The "256" of the name survives as the 256 KiB block granularity of the
  sender's read-ahead and as the 256-bit output of BLAKE3.

## 8. Reachability, addresses and NAT

### Finding the receiver

`ID@host:port` is resolved to *every* address the name has, with the
address families interleaved. Name resolution is a hint and nothing more:
DNS and mDNS answers are unauthenticated and among the easiest records on a
network to forge. Handshake attempts therefore rotate through all of the
addresses (at most 8) until one answers, and completing a handshake takes
the receiver's private key — so an address that is not the receiver simply
never answers, and a forged or stale record costs time rather than safety.
It also means a host whose first address is unreachable, the usual case
being a broken IPv6 path, no longer strands the transfer. The address that
answers an attempt sent to it is proven reachable by that round trip and
becomes the session's address.

### Address validation

Either peer's address may change mid-transfer: a NAT rebinds, a laptop
moves between links, a mobile connection changes base station. A session
never follows such a change on trust. An authentic packet from an address
that has not been proven is treated as a *claim*: the session keeps sending
to the address it has already proven and sends a PATH_CHALLENGE carrying
eight unpredictable bytes to the new one. Only a peer holding the session
keys can produce the matching PATH_RESPONSE, and only delivery at the
challenged address can return it, so the pair of frames proves both. The
claim is accepted — and the session's traffic moves — the moment the token
comes back **from the address it was sent to**. A challenge is repeated up
to four times and then abandoned, leaving the proven address in place.

This follows QUIC (RFC 9000 section 8) and is needed for the same reason:
authentication proves who made a packet, not where it was sent from. An
attacker on the path can copy an authentic packet and re-send it with a
forged source address; without validation both ends would aim their traffic
at whatever address it chose, and on the sending side that is the whole
file. Nothing but the challenge is ever sent to an unproven address, so the
mechanism cannot be used for amplification either: the one small frame it
costs answers a packet at least as large. A repeated PATH_RESPONSE is
caught by the packet-number window, and a token is used once.

Handshakes are treated the same way, since a handshake message is just as
easy to capture and repeat from elsewhere as any other packet.

### NAT

A receiver must be reachable at the address senders use. With the
`nat-traversal` feature the receiver, in the background and without
delaying transfers, asks public STUN servers under which address its
transfer socket is seen, and asks the router for a UPnP-IGD port forward,
renewed at half its lease and removed on shutdown. The result is reported
as a `Reachability` event; the receiver prints the address to give senders
as `ID@address`. STUN responses arrive on the transfer socket and are
routed to the NAT task by the receiver's dispatcher.

The sender needs no NAT handling: its outgoing datagrams create the mapping
on its own NAT, and the receiver answers the address a handshake came from
(and follows a mapping that changes later through address validation). Two
peers that are both behind NATs without a port forward cannot reach each
other; that needs a rendezvous or relay service (section 11).

## 9. Security considerations

**Protected.** Everything after the handshake is confidential and
authenticated: contents, names, sizes, offsets, acknowledgements, packet
kinds and packet numbers. A receiver authenticates to the sender through
its ID; a sender authenticates through its static key (and optionally the
shared secret and the allow-list). Every session has fresh keys; recorded
traffic cannot be decrypted later even if long-term keys leak (forward
secrecy), and with a shared secret not even if X25519 is broken.
Initiations cannot be replayed, transport packets neither (packet-number
window). Forged, corrupted or replayed packets are dropped before any of
their contents is acted upon, which also protects against corruption the
UDP checksum missed.

**Denial of service.** Datagrams without a valid mac1 cost one keyed hash
and get no answer. Floods from spoofed addresses are met with cookies
(one MAC per datagram, no public-key operations, no amplification);
per-address rate limits, a session limit with a per-sender share (so one
authenticated sender cannot take every slot), the free-space check, sparse
pre-allocation and the expiry of idle sessions bound what an authenticated
but hostile sender can occupy. A directory listing is size-limited and
validated before any file is created.

**Traffic redirection.** Neither peer follows its counterpart to an address
that has not answered a challenge, so a captured packet repeated from a
forged source address cannot turn a transfer into a stream aimed at a third
party (section 8). Nothing but the challenge goes to an unproven address.

**Impossible statements.** An ACK describing more bytes than the file holds
is dropped unread: the sender's staleness counter only grows, so believing
one would have made every honest ACK afterwards look outdated and stalled
the transfer permanently.

**Not protected.** An observer still sees that two addresses exchange UDP
traffic, its volume and timing, and the connection ids (random, changing
with every handshake). The receiver's IP address and port are, as for any
server, reachable — only the answer is withheld from strangers. Anyone who
knows a receiver's ID (and its secret, if one is set) can offer transfers
unless the receiver uses an allow-list or asks its user. IDs must be
exchanged over a channel the users trust; the protocol cannot detect a
substituted ID. Identity files are protected only by file permissions.

## 10. Implementation notes

* **Batched datagram I/O.** At multi-gigabit rates the cost per datagram,
  not per byte, decides the speed. The sender builds DATA datagrams back to
  back and hands up to 64 of them (at most 64 KB) to the kernel with one
  segmented send (UDP GSO on Linux, USO on Windows). The receiver reads with
  `recvmmsg` and UDP GRO, which delivers runs of datagrams from one sender
  in one buffer; the dispatcher passes a run to its session as a whole,
  large runs without copying. Platforms without these features fall back
  to one datagram per call transparently, and so does a socket whose
  segmented sends fail although the stack offered them (some drivers).
* **Packet crypto off the engine threads.** AES-256-GCM costs about 1.4 µs
  per full packet on one core. The sender hands batches of eight or more
  datagrams to a pool of worker threads for sealing and carries on; sealed
  batches are sent strictly in the order they were built. The receiver's
  sessions hand larger deliveries to the same pool for opening and process
  the results in arrival order; results decrypted under keys that were
  replaced in the meantime are discarded. The pool has one thread per core
  beyond two (at most four); `SHARP256_CRYPTO_THREADS` overrides this (0
  turns it off).
* **Receiver.** One dispatcher task drains the socket, runs admission
  control for handshakes and routes everything else by connection id to
  per-session tasks (queues of at most 16 384 deliveries and 32 MiB; a full
  queue drops, which the protocol treats as loss). A session opens all
  datagrams of a run first and gives their payloads to the writer thread as
  one command, then acts on control frames, so a suspension can never
  persist data that is counted as received but not queued for writing.
* **Sender.** The engine is a single-owner state machine; each turn drains
  the socket, runs timers and then sends as far as window, pacer and
  pipeline allow.
* **Sockets** request 32 MiB kernel buffers. Linux caps ordinary requests
  at `net.core.rmem_max`/`wmem_max`; a privileged process exceeds the cap,
  otherwise a small buffer is reported with the `sysctl` command that raises
  it. On Windows, `SIO_UDP_CONNRESET` is disabled so that an ICMP "port
  unreachable" does not break the receive loop.

## 11. Versioning and extensibility

* The protocol version is bound into the handshake (Noise prologue and the
  labels of every derived key), so peers of different versions cannot
  complete a handshake by accident and no version field is needed on the
  wire. A future version must use a new prologue and new labels.
* Control frames grow by appending fields at the end of the body; a decoder
  ignores trailing bytes it does not understand. DATA has no room at the
  end (its payload runs to the end of the body), so new DATA fields require
  a flag bit that announces them.
* New behaviour is negotiated through capability bits (section 4); a
  feature is only used once HELLO_ACK has confirmed it.
* The manifest has its own version byte and rejects unknown entry bits.
* Every control datagram is bounded to 1200 bytes by construction.

Extensions planned on this basis:

| extension | mechanism |
|-----------|-----------|
| Block-hash manifest (BLAKE3 per 256 KiB) | capability bit; verifies resumed data and localises corruption before the final check |
| Per-file resume of directories whose contents changed | capability bit; compare per-entry metadata instead of the whole manifest |
| Rendezvous / relay for peers that are both behind NAT | separate service; the transfer protocol is unchanged |
| Delivery-rate based slow-start exit | sender-local; no wire change |

## 12. Defaults

| setting | default | meaning |
|---------|---------|---------|
| `max_chunk` | 1427 B | largest payload bytes per DATA packet (512–8927) |
| `probe_mtu` | on | probe the path before sending data |
| `initial_cwnd_chunks` | 32 | initial congestion window |
| `max_cwnd_bytes` | 256 MiB | upper bound of the congestion window |
| `max_rate_bytes` | none | optional send-rate cap |
| `ack_interval` | 20 ms | ACK at least this often while data arrives |
| `ack_every_packets` | 8 | ACK after this many DATA packets |
| `min_rto` / `max_rto` | 100 ms / 30 s | bounds of the retransmission timeout |
| `stall_timeout` | 20 s | silence after which a transfer is stalled |
| `give_up_timeout` | 5 min | silence after which the sender gives up (resumable) |
| `handshake_timeout` | 60 s | total time for handshake retries and decisions; idle-session limit |
| `socket_buffer_bytes` | 32 MiB | requested kernel socket buffers |
| `persist_interval` | 2 s | how often the receiver persists durable progress |
| `writer_capacity_bytes` | 64 MiB | receiver write buffer (source of `rwnd`) |
| `session_ttl` | 10 min | silence after which a receiver session is suspended |
| `max_sessions` | 16 | concurrent transfers per receiver |
| `handshake_rate` / `handshake_burst` | 20/s / 40 | handshakes per source address |
| `handshake_load_threshold` | 200/s | handshakes (all sources) beyond which cookies are required |
