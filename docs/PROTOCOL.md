# SHARP-256 wire protocol, versions 3 and 4

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

Version 4 (section 2, *Version 4*) is version 3 with a hybrid key exchange —
X25519 and ML-KEM-768 together, so that traffic recorded today stays
unreadable to whoever can break only one of them later — and with the
HELLO moved after the handshake, where it has forward secrecy. Everything
from section 3 on is the same in both.

Section 12 lists the default values of every tunable mentioned below. All
integers on the wire are big-endian unless stated otherwise.

## 1. Identities and addressing

Every endpoint has a long-term **identity**: an X25519 key pair, created on
first use and stored in the per-user data directory
(`~/.local/share/sharp-256/identity.key`, `%APPDATA%\sharp-256\identity.key`,
...) with owner-only permissions.

The identity file is text: comment lines naming the ID, then the private
key, either as 64 hex digits (the default) or sealed:

```
sharp256-identity-2 <public> passphrase argon2id <memory KiB> <passes> <lanes> <salt[16]> <nonce[24]> <sealed[48]>
sharp256-identity-2 <public> keystore secret-service|keychain <nonce[24]> <sealed[48]>
sharp256-identity-2 <public> keystore dpapi <blob> <nonce[24]> <sealed[48]>
```

(every value in hex). `sealed` is the private key encrypted with
XChaCha20-Poly1305 under a key that is either `Argon2id(passphrase, salt)`
(version 0x13, 32 bytes) with the parameters written before it (256 MiB, 3
passes and 1 lane by default) or
a random 32-byte key the operating system keeps for the user: in the
Secret Service (attributes `application=sharp-256`, `identity=<ID>`), in
the Keychain (service `sharp-256`, account `identity <ID>`), or sealed by
DPAPI to the Windows account, with `"sharp256 identity " || public` as its
entropy, and carried in the file as `blob`. The associated data is the
fields before the nonce joined by single spaces (none after the last); the
key that comes out must have
`public` as its public key. A file is always replaced whole: written next
to the old one, flushed, renamed over it, and the directory flushed.

A **SHARP ID** is the public key in text form: `sh-` followed by 56
lower-case base32 characters (RFC 4648 alphabet, no padding) encoding the
32-byte public key and a 3-byte checksum,
`BLAKE3-derive_key("sharp256 id checksum", public_key)[0..3]`, so that a
mistyped ID is rejected instead of addressing somebody else.

A receiver that speaks version 4 writes the same key as `sh4-` and 56
characters, with a checksum of its own,
`BLAKE3-derive_key("sharp256 id checksum v4", public_key)[0..3]`. The form
of the ID says which version a sender speaks: to `sh4-` version 4 and
nothing else, to `sh-` version 3. A version 4 receiver prints the `sh4-`
form and answers version 4 only, unless told to answer version 3 as well
(`sharp-receiver --accept-v3`, while IDs in the old form are still in use):
otherwise whoever has the old form talks to it classically, without ML-KEM
and with the transfer's name and size in the first message. A sender never
falls back from version 4 to version 3, so nobody on the way can talk it down to the classical handshake by
dropping what it sends, and a `4` lost in copying is a checksum error, not
the other version. A contact card says the same in flag bit 2.

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
initiation  S → R   sender_cid[8] | e[32] | enc(s)[48] | enc(sender_cid[8] | payload)[n+24] | mac1[16] | mac2[16]
response    R → S   sender_cid[8] | receiver_cid[8] | e[32] | enc(receiver_cid[8] | payload)[n+24] | mac1[16] | mac2[16]
cookie      R → S   sender_cid[8] | nonce[24] | enc(cookie)[16] | tag[16]
```

* The sender knows the receiver's static key (its ID) in advance, so the
  receiver is authenticated by construction; the sender's static key
  travels encrypted (identity hiding). Both sides contribute ephemeral
  keys, so every session has fresh keys (forward secrecy). The PSK is mixed
  in after the key exchange (`psk2`), which also protects recorded traffic
  against a future break of X25519 when a secret is used.
* Connection ids are random 64-bit values chosen by the side that
  *receives* with them: the sender chooses `sender_cid` per attempt, the
  receiver `receiver_cid` per session. Every later datagram starts with the
  id of its recipient, which is all the receiver needs to find the session.
  Zero, the relay magic `SHRELAY1` (section 8) and any id whose second four bytes are
  the STUN magic cookie `0x2112A442` are never chosen, so a transport packet
  can never be mistaken for a relay control message or for STUN on a socket
  that carries both.
* Each side's id travels twice: in the clear, where the other side's
  dispatcher needs it, and **sealed** as the first eight bytes of the Noise
  payload. The clear copy is covered only by mac1, whose key anybody can
  derive from a public key, so a copy raced ahead with the id changed would
  otherwise misaddress the session. The receiver refuses an initiation
  whose two copies differ (before its replay guard takes it into account);
  the sender takes the receiver's id only from the sealed copy.
* Static keys that are small-order points (the eight low-order points of
  Curve25519 and its twist, in every encoding) have no private half: every
  Diffie-Hellman with them is the same constant. They are refused wherever
  an identity comes in — when an ID is parsed, as a receiver key before a
  handshake starts, as a sender key in an initiation, and by relays.
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
3. **Rate limit.** Each client — an IPv4 address or an IPv6 /64, the block
   one subscriber can send from at no cost — may start `handshake_rate`
   handshakes per second (burst `handshake_burst`); excess is dropped. The
   table is bounded (65 536 clients); full, it makes room at most four times
   a second and otherwise refuses newcomers.
4. **Noise.** The initiation must decrypt under the receiver's static key,
   its sealed connection id must match the clear one, and the sender's
   static key must not be a small-order point.
5. **Authorisation.** A sender that is not on the allow-list receives an
   authenticated rejection (reason 8) and nothing else. This comes before
   the replay guard, so that strangers' identities — which cost nothing to
   make — never enter it.
6. **Replay.** The initiation payload starts with a timestamp (nanoseconds
   since the Unix epoch, strictly increasing per process, and kept across
   runs in the sender's state directory so that a clock set back does not
   get it silently refused). The receiver remembers the latest timestamp
   per sender identity (up to 100 000 senders) and drops initiations that
   are not newer. When full it forgets the oldest sender that has **no
   transfer in progress**: a live sender is never pushed out, so a captured
   initiation of a running transfer can never be taken again.
7. **Declined.** A transfer the receiver's user declined is remembered for
   two minutes; handshakes for it that were already on their way get the
   same refusal (reason 5) instead of a new question.

A handshake response goes to an address nobody has proven yet, so it is
no longer than the initiation that drew it — no more goes back than came
in (RFC 9000 allows three times; here one): the HELLO_ACK hole list is
shortened to fit, which only makes the sender resend more, a rejection's
message is shortened or dropped, and an initiation too short for even that
is not answered. A sender that resumes — a re-handshake of a running
session, or a transfer id kept from an interrupted attempt — pads its
initiation to 1200 bytes with zeros after the payload, inside the
encryption (the payload's decoder ignores them), so that the answer has
room for the holes of what the receiver holds; a fresh transfer's answer
is short, and so are its initiations, which go round every address the
receiver may be at.

Until the session's address has proven itself — a transport packet from
it under the keys the response made, or an answer to a challenge — the
receiver sends nothing more there than what the initiations from there
left over after the responses: a copy of an initiation sent ahead of the
original from a forged address would otherwise start the session at that
address and have acknowledgements of the real sender's data aimed at it.
A refusal that does not fit (the user declined at once, say) waits for the
sender's next decision poll, which proves the address, for at most five
seconds.

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

The epoch of a received packet is the one its packet number names, and
until the packet authenticates that is only a claim. A recipient keeps the
keys of the newest epoch `e` that has carried an authentic packet and of
`e − 1` and `e + 1`, and moves on only when an authentic packet of a later
epoch arrives. A packet naming an epoch from `e + 2` to `e + 16` is tried
with a key made for it alone (kept if it authenticates); one naming any
other epoch is opened with the key of `e`, and fails. A sender never has
more than 2^19 packets unacknowledged, so an authentic packet is always
within an epoch of `e`; the look-ahead is margin. The key for a packet is
chosen without a branch on its epoch.

### Attempts and retries

Every handshake attempt uses a new ephemeral key and a new `sender_cid`.
The sender goes round its candidate addresses 250 ms apart, then retries
with exponential backoff (250 ms, doubling to 4 s) until
`handshake_timeout`; a single address counts as a complete round. It keeps
its last four attempts.

In version 4 **the first answer to arrive is adopted**, whichever attempt
it answers: the receiver keeps each handshake it answered apart, keys and
connection id, until a HELLO under one of them makes the session, and lets
the others expire. The fastest of the paths tried wins, even when the next
address in the rotation was tried before its answer came back.

In version 3 **only the newest may be adopted**: the receiver makes the
session at the initiation, its replay guard keeps the newest it saw, and
adopting an older answer would leave the two sides with different keys. An
answer to a superseded attempt proves its address answers — the next
attempt goes straight back there — and gives a round-trip sample, and no
retry is sent sooner than 1.5 round trips after the last: on a path slower
than the retry interval, every answer would otherwise arrive after a newer
attempt had replaced the one it answered.

A datagram addressed to an attempt is **authenticated before anything is
used up**: the Noise state restores itself after a failed read, so junk
sent to an attempt's (cleartext) connection id leaves it ready for the real
answer. A cookie reply counts only when it comes from the address the
initiation went to. The session starts when a response authenticates.
Send errors never end a handshake; its deadline does.

### Version 4

The handshake is `Noise_IKpsk2+hfs_25519+MLKEM768_ChaChaPoly_BLAKE2s`:
IKpsk2 with the tokens of Noise's hybrid forward secrecy draft, in the
layout I2P's proposal 169 uses for IK, and the prologue `SHARP-256 v4`:

```
  <- s
  ...
  -> e, es, e1, s, ss
  <- e, ee, ekem1, se, psk
```

`e1` is the sender's ephemeral ML-KEM-768 (FIPS 203) encapsulation key,
sent with `EncryptAndHash` (1184 + 16 bytes); `ekem1` is the receiver's
ciphertext to it (`EncryptAndHash`, 1088 + 16 bytes) followed by `MixKey`
of the shared secret. The receiver refuses an encapsulation key that fails
FIPS 203's modulus check. The keys of the session depend on X25519 and on
ML-KEM alike; authentication is version 3's (the static X25519 keys and the
PSK).

Message 1 is about 1300 bytes, too long for a control datagram, and goes in
up to four **fragments** of about equal size (two in practice): as many as
1159 bytes of message each need (1200 less the fragment's own 41), every
one ⌈length / count⌉ bytes of it but the last, numbered from 0. The
receiver needs only the numbers; the cut is the sender's, this one is what
the test vectors (`docs/vectors`) show:

```
fragment    S → R   sender_cid[8] | index:4 count:4 | chunk | mac1[16] | mac2[16]
response    R → S   sender_cid[8] | e[32] | enc(ct)[1104] | enc(receiver_cid[8] | payload)[n+24] | mac1[16]
```

Each fragment carries its own `mac1`, keyed
`BLAKE3-derive_key("sharp256 v4 mac1", receiver_public_key)` — a version 3
receiver hears nothing it knows in one, and a version 4 receiver tells the
versions apart by it — and its own `mac2`: under load every fragment needs
a cookie's, and a cookie reply to any fragment gives the cookie (sealed to
that fragment's mac1). The receiver puts together only fragments whose mac1
is its own, bounded: at most eight initiations per client (an IPv4 address
or an IPv6 /64), 1024 in all (the oldest go first), each for two seconds;
a fragment already there, or one that disagrees on the count, is not taken.
Nothing is answered until every fragment is in.

The response fits one control datagram: it has no clear copy of the
receiver's connection id (only the sealed one ever counted) and no `mac2`
(always zero in an answer); its `mac1` is keyed with the sender's key under
the version 4 label. It is shorter than the fragments together.

The payload of message 1 is `sender_cid[8] timestamp:u64 suites:u8
hardware_aes:u8` — the sealed copy of the connection id as in version 3,
and no HELLO; the response's is `receiver_cid[8] suite:u8 reason:u8`, the
suite chosen or 0 and why the handshake is refused (the allow-list, no
suite in common, busy). The rest of this section is version 3's, labels
included: `mac2` and its key, cookies, the traffic keys
(`"sharp256 v3 …"` in both versions).
What the receiver makes of the transfer is said later, in answer to the
HELLO.

**HELLO after the handshake.** Once the response authenticates, the sender
sends its HELLO as the first transport packet under the new keys, again
until it is answered, and the receiver answers it with HELLO_ACK as it
answers any HELLO in a session (section 5). Until that HELLO arrives the
receiver holds keys and nothing else — at most 4096 such handshakes, each
for ten seconds — and acts on nothing message 1 said beyond the allow-list,
the replay guard and the suites: the HELLO is the first thing that proves
the sender's key (message 1 can be made by anyone who holds the receiver's
own key), and what it says (the name and size of the transfer) has forward
secrecy, where message 1's payload does not. The HELLO names the transfer,
which makes or finds the session; a refusal then (declined, busy) is a
HELLO_ACK sealed under the handshake's keys, sent only to the address the
HELLO has just proven. The HELLO_ACK of a resume, with its holes, goes to
an address the HELLO has proven, so a version 4 initiation is never
padded. This costs one round trip per handshake, resumes included.

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
handshake doubles as a resume point. (In version 4 the HELLO is the first
packet after the handshake and the HELLO_ACK its answer: section 2,
*Version 4*; the rest is the same.) If the receiver's application has to
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
max)`, at least 512. Where the sender's maximum is left at its default and
the receiver is reached over IPv6, whose header is 20 bytes longer than
IPv4's, the sender starts from 1407 instead of 1427. It then probes the
path: PROBE packets of exactly the DATA size of each candidate chunk — the
negotiated chunk, 1427 (fits a 1500-byte MTU over IPv4), 1407 (fits 1500
over IPv6, and 1492 over IPv4 — the PPPoE links DSL runs on), 1387 (IPv4 in
a DS-Lite tunnel over a 1500-byte link: 1460), 1187 (fits the 1280-byte
IPv6 minimum MTU) and 1155 (a DATA datagram of a control
datagram's 1200 bytes, QUIC's base PMTU: what the handshake took, on an IPv4
path below 1260 bytes — a tunnel, a VPN) — are sent largest first, each up
to twice, waiting `clamp(3·SRTT, 150 ms, 2 s)`; the first size echoed by
PROBE_ACK is used. A path narrower than 1228 bytes takes no handshake at
all (THREAT_MODEL Р7: the floor QUIC has too).
If nothing answers, the sender uses 1187 and lets the transfer itself find
out whether the path works. DATA packets are self-describing, so the chunk
size may change at any time without the receiver noticing.

The path MTU is learned **only from acknowledged PROBEs** (RFC 8899,
datagram PLPMTUD). Sockets set "don't fragment" for every address family
they speak but run in probe mode where the system has one: on Linux
`IP_PMTUDISC_PROBE` and `IPV6_PMTUDISC_PROBE`, plus `IPV6_DONTFRAG`
(RFC 3542), since Linux in probe mode still fragments an IPv6 datagram
larger than the interface; on macOS and the BSDs `IP_DONTFRAG` and
`IPV6_DONTFRAG`; on Windows `IP_DONTFRAGMENT` and `IPV6_DONTFRAG`, with
`IP_MTU_DISCOVER = PROBE` where available. A dual-stack socket gets the IPv4
options too, for IPv4 peers reached through mapped addresses, where the
system accepts them on an IPv6 socket (Linux and Windows do; macOS and
FreeBSD may not, and those datagrams may then be fragmented on the way —
a cost in efficiency, not correctness). The kernel ignores what ICMP says
about the path, so a forged "fragmentation needed" can neither shrink a
transfer nor make the kernel refuse its control messages. `EMSGSIZE` then
only ever means the local interface, and costs one step down — from 1427
to 1407, else to 1387, else to 1187, else to 1155, then by halves to 512 — per size
refused: batches built at a larger size than the current one fail
without stepping down again, so one event is one step. A real drop of the
path MTU shows up the way RFC 8899 (section 4.3) describes: full-size
packets are lost over two retransmission timeouts in a row while the
receiver's small ones keep arriving. That they arrive is asked outright:
at each retransmission timeout with nothing acknowledged the sender sends
a `Ping`, and the next one counts only if something came back after it. A
path that went quiet altogether answers no small packet either, and is
left to the liveness rules; it used to be taken for a black hole while
what had arrived before the cut still counted. The sender then steps down the same
way, and 30 s later (60 s, …) sends one PROBE of the previous size; only
its PROBE_ACK, sent under the session keys, brings the size back. No send
error of any kind ends a transfer: the batch goes back into `pending`, the
sender waits 100 ms, and the liveness rules (below) decide.

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

Two limits hold whatever a sender does with the window it is given:

* **Pieces.** A session keeps at most 65 536 separate received ranges.
  Past that, only DATA that extends or joins what is already there (or
  starts the file) is taken; the lowest hole always does, so an honest
  transfer slows and never stops, while a sender scattering one-byte
  pieces cannot make the receiver keep, persist and describe one entry per
  byte. The sender likewise queues at most 65 536 ranges on the receiver's
  word alone (holes it reports that were never in flight).
* **Memory.** `memory_budget` (512 MiB by default) bounds all sessions
  together: a quarter for datagrams queued to sessions, counted across all
  of them; the rest shared by the sessions that are receiving, and each
  one's `rwnd` and admission are held to its share
  (`min(writer capacity, ¾·budget / receiving)`).

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
   `reo_wnd = clamp(min(m · min_rtt / 4, SRTT), 1 ms, 250 ms)`. The
   multiple `m` starts at 1 and grows by one (once a round, up to 8) when a
   packet taken for lost turns out to have arrived — acknowledged while
   still queued to be sent again, or its resend acknowledged sooner than
   half a minimum round trip after it went (RFC 8985 widens on a DSACK;
   this is the same news, without one) — and shrinks by one after 16
   rounds without. Send order, not stream offset, decides, so a fresh
   retransmission is never condemned by ACKs that predate it. Lost packets
   return to `pending`.
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
* at least 35 % of what was sent in the last rounds was lost, pooled (the
  counters halve per round, a memory of about two; at least 60 packets).
  It used to be 20 % of a single round: in a round of twenty-odd packets a
  path losing 5 % at random loses a fifth now and then, which was taken for
  congestion every second or so; and a path losing a fifth at random was
  congested in every round, its window at its least. Below the ceiling a
  path that holds to a rate without a queue — a policer, a shallow buffer
  overdriven — is found by the rate it lets through (see "Congestion
  control and pacing"); or
* the round lost clearly more than the path's background rate explains:
  `lost > E + 3·√(E + 1) + 1` with `E = base_loss_rate · sent` (about three
  standard deviations of a Poisson count, so one or two stray losses in a
  small round never qualify).

`base_loss_rate` is the ratio of bytes lost to bytes sent, pooled over
recent rounds with at least 16 packets and no standing queue — however
many they lost: counting only rounds without a congestion signal biased it
low, and kept it there (both
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

**A policer** is recognised by the rate it lets through, as BBR's
long-term bandwidth estimate does: it drops what exceeds its rate without
queueing it, so the RTT never rises, and on a short path even a window of
two chunks a round trip is far more than it passes. Sampling starts at a
loss; an interval lasts at least 4 rounds and 50 ms and ends on a loss. Two
intervals in a row that each lost at least a fifth of what they delivered,
at delivery rates within an eighth of each other, make a policer suspected,
at the mean of the two rates; an interval of 16 rounds and 200 ms without
that much loss starts the sampling over. Random loss of a fifth looks the
same, so the suspicion is **checked**: the sender is paced at the rate for
4 rounds, 50 ms and 32 KiB answered at least, counting only what it sent
since the check began (what went out faster before is still being answered
then). Losing less than a tenth of that, having sent at seven tenths of the
rate or more, it is a policer; losing more, the check is made again at four
fifths of the rate, and losing as much there, it is random loss, and
nothing is suspected for 30 s (doubled for each such false alarm in a row,
up to 600 s). A check at which the sender did not come up to the rate says
nothing, and sampling starts over. A policer found caps the pacing rate for
48 rounds and 2 s at least; then the cap rises by 1.25 every 4 rounds and
200 ms, and is lifted at 16 times the rate found. A policer still in place
is suspected again at the first step and checked. Only datagram paths are
sampled, and a change of path forgets it. A recognised policer also makes
UDP suspect for the trial on a stream ("Carriers other than UDP").

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
continues every 1, 2, then 4 s. While stalled, the re-handshakes take turns
among every address the receiver is known by — its last one first, then
the others it published and those relays turned up — since a silent
receiver may simply have moved. After `give_up_timeout` the sender sends
ABORT (timeout), saves its state and exits with a resumable error.

A re-handshake may be answered with PENDING, by a receiver that restarted
and is asking its user again: the sender then stops sending data and asks
for the decision every second (HELLO), for at most `handshake_timeout`,
and takes the receiver's decision whenever it arrives. A BUSY answer in
the middle of a transfer is waited out like silence, and the resume state
is kept.

Either peer follows the other's address change (NAT rebinding, roaming),
but only once the new address has proven itself (section 8, *Address
validation*): an authentic packet from a new address is a claim, not a
move, because an attacker can repeat a captured packet from a forged
source.

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

**What a power cut leaves.** After a crash a disk holds what was flushed:
a file's contents by an fsync of the file, its name — creation, rename,
removal — by an fsync of the directory. The receiver orders its writes so
that every moment leaves either the old state or the new one:

* A state file is written beside the old one under a name of its own,
  flushed, renamed over it, and the directory flushed; a removed one is
  removed with its directory flushed.
* A new partial file or staging directory has its name flushed with the
  output directory before any state describing it is kept, so no state
  outlives the file it describes.
* When the writer has flushed the whole stream, the state is saved once
  more saying so, before the stream is hashed: a cut during verification
  resumes with every byte already there.
* A directory's times and permissions are applied and every entry
  flushed, then the staging directory, before the tree is moved into
  place. A staging directory found on resume is made writable for its
  owner again (a cut after the permissions and before the move may have
  left read-only entries); the permissions are applied again at the end.
* The output directory is flushed after the result is moved to its final
  name and before FIN is sent: a sender that heard FIN has a result that
  is on disk under that name.

Right after the move (and the flush of its directory) the resume state
records the final name and the result's hash. A transfer cut between
then and the sender's confirmation — a crash, a lost connection — is
finished from the result in place when the sender tries again: the
receiver hashes the file (or tree) under its final name, and if it is
what was stored, answers FIN with nothing received again; if it has
changed since, it is left as it is, the state is dropped, and the next
attempt receives the transfer anew beside it. Only a cut between the
move and that record still stores the result a second time under the
next free name (`name (1)`) — a whole copy, never a damaged one.

Windows offers no documented way to flush a directory. There the move
to the final name is a `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`, and
the directory is flushed through a handle to it as far as NTFS takes
that; neither is tested by a cut (`scripts/crashlab/`,
docs/evidence/crash).

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
* One partial file has one session. A transfer that would continue resume
  state another session of the same sender holds — the sender was
  restarted without its own resume state, and sends the file as a new
  transfer while the old one's session still waits for it — first asks
  that session to let go, and waits for it up to 10 s; if it has not let go
  by then, the transfer is refused as busy. A session that lets go keeps
  what the transfer that continues needs: one in progress is suspended,
  its partial file and state kept (dropped if no data came, as at
  `handshake_timeout`); one being verified finishes verifying; one whose
  result is in place leaves its state as it is, and the new transfer
  confirms the result from there. The old transfer is reported as a
  failure that says why. Nor is a fresh partial file given a name that
  another session has chosen and not created yet.
* A sender whose share of the sessions (`max_sessions_per_sender`) is
  full, or that finds every session taken, makes room with its own
  transfer silent longest, if that one has been silent for
  `stall_timeout`: it lets go the same way, and resumes when the sender
  sends it again. Other senders' sessions make no room for it. A session
  asked to let go counts against no limit while it ends.

### Completion

When the receiver holds every byte it sends a final ACK and, in the
background, closes the writer (fsync), hashes the stream with BLAKE3-256 and
moves the result to its final name, flushing the directory it is in
(section 5, *What a power cut leaves*), answering HELLO, PING and PROBE all
the while. It then sends FIN with the hash, repeating it after 200 ms and then
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
`manifest_hash = BLAKE3(manifest)` and `dirs` not counting the root. The receiver can show "12 files in 3
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
* Names are single components by construction. They are stored in
  Unicode's composed form (NFC): macOS hands names over decomposed, and
  the same name in two forms would be two files elsewhere. Otherwise as
  they are on Unix; on Windows, reserved characters (`<>:"/\|?*` and
  control characters) become `_`, trailing dots and spaces are removed and
  device names (`CON`, `nul.txt`, `COM1`, ...) get a `_` prefix. The
  manifest itself carries the names as the sender's system gave them.
* Every entry is created with "create new" semantics. Two names that the
  local file system considers the same (case-insensitive file systems,
  names that differ only in Unicode form, names mapped for Windows) are
  therefore reported as a collision — the transfer is abandoned — instead
  of one overwriting the other. Files are
  created when their first byte arrives, directories when something inside
  them is created, the rest when the stream is complete.
* When complete, the receiver hashes the stream from disk, applies
  modification times and permission bits (deepest entries first; never
  set-id or sticky bits; masked with the receiver's umask) and renames the
  staging directory to the final name, which never replaces anything: a
  taken name becomes `name (1)`. The system itself refuses the move when
  the name is taken — `renameat2` with `RENAME_NOREPLACE` on Linux,
  `renamex_np` with `RENAME_EXCL` on macOS, `MoveFileExW` without
  `MOVEFILE_REPLACE_EXISTING` on Windows — so a name another process takes
  between the choosing and the moving is passed over, not replaced.
* The manifest is kept with the resume state, so an interrupted directory
  resumes after a restart of either side without resending it. Files that
  already exist in the staging directory are reused on resume; their data
  is still covered by the final hash.

## 7. File handling

* Names of single files from the wire are reduced to a base name in NFC;
  control characters and characters illegal on Windows are replaced,
  reserved device names are prefixed. The output path is always inside the
  configured directory.
* A received file is never written through a symbolic link at its name
  (`O_NOFOLLOW`; on Windows the link itself is opened, and refused), so
  someone else who can write the output directory cannot have the
  transfer written into another file. The file moved into place is the
  one written and hashed: its device and file number are compared before
  hashing, after, and before the move.
* Partial files are written as `name.sharp-part` (or `name (1).sharp-part`
  if an unrelated partial file already exists) and renamed on success. An
  existing complete `name` is never overwritten unless configured; the new
  file becomes `name (1)`, by the same refusing move as a directory (a
  hard link where the system has no such call). Directories are never
  overwritten or merged.
* Files are pre-sized with `set_len`, which creates a sparse file where the
  file system supports it. Free space is checked for the bytes still to be
  received plus a 1 MiB margin before accepting.
* The "256" of the name survives as the 256 KiB block granularity of the
  sender's read-ahead and as the 256-bit output of BLAKE3.

## 8. Reachability, addresses and NAT

### Sockets and address families

Every endpoint binds one dual-stack socket by default (`[::]` with
`IPV6_V6ONLY` off, RFC 3493): the receiver `[::]:5555`, the sender
`[::]:0`, the relay `[::]:5560`. It speaks IPv6 natively and IPv4 through
mapped addresses (`::ffff:a.b.c.d`). Where the system has no IPv6 — switched
off in the kernel, or no address — the wildcard falls back to IPv4 on the
same port; an explicit address is bound as given or not at all — an IPv6
one IPv6-only (`IPV6_V6ONLY` on: it cannot speak IPv4 anyway, and Windows
refuses IPv4 options on it), an IPv4-mapped one with `IPV6_V6ONLY` off —
and a port already taken is an error, never a fallback.

Addresses are compared, screened and remembered in canonical form: a mapped
address is the IPv4 address it maps, the flow label is zeroed, and the zone
(scope id) is kept only for link-local addresses, where it is part of the
address. Every address is classified by the special-purpose registries
(RFC 6890): loopback, private, shared (CGN), link-local, documentation,
multicast, reserved, global. What a *stranger* suggests — a relay's
introduction, a STUN server's other address — is sent to only if it is a
unicast address the socket can reach; a name the *user* gave may point
anywhere, including home.

### Finding the receiver

`ID@host:port,host:port,…` names every candidate; each may be a literal
(IPv6 in brackets, with a zone for link-local: `[fe80::1%eth0]:5555`) or a
name. Names are resolved in the background, alongside the handshake
attempts to the literals, as Happy Eyeballs v2 (RFC 8305) prescribes: A and
AAAA are asked for separately and at once; an A answer waits at most 50 ms
for the AAAA one (the resolution delay), after which addresses are used as
they come. The addresses are sorted by the default address selection rules
of RFC 6724 (rules 1, 2, 5, 6 and 8: usable destinations first, matching
scope, matching label, precedence, smaller scope) and then interleaved by
family, and a new attempt starts every 250 ms (the connection attempt
delay) without waiting for the previous one to fail — so a broken IPv6
path costs a quarter of a second, not a timeout. A name that yields no
address at all, with nothing else left to try, ends the transfer at once
with the resolver's answer rather than after `handshake_timeout`.

On an IPv6-only network with NAT64 and DNS64, an IPv4 literal — and any
IPv4 candidate — is unreachable as it stands. When the host has no IPv4
route, the NAT64 prefix is discovered by resolving `ipv4only.arpa`
(RFC 7050; the answers are checked against the well-known IPv4 addresses and
the prefix lengths of RFC 6052, cached for five minutes), and the IPv6
address synthesised from it is tried as well (RFC 8305 section 7). Only
global IPv4 addresses are translated.

Name resolution is a hint and nothing more: DNS and mDNS answers are
unauthenticated and among the easiest records on a network to forge.
Handshake attempts therefore rotate through all of the addresses (at most
8 per name) until one answers, and completing a handshake takes the
receiver's private key — so an address that is not the receiver simply
never answers, and a forged or stale record costs time rather than safety.
The address that answers an attempt sent to it is proven reachable by that
round trip and becomes the session's address.

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
comes back **from the address it was sent to**.

* Up to four claims are tested side by side, so someone racing copies from
  forged addresses cannot crowd out the peer's real move; a new claim
  replaces a given-up one first, then the oldest.
* A challenge is repeated with exponential backoff, starting from the
  measured round trip (never from a timeout an outage has backed off) and
  capped at 8 s, six times in all; then the claim is given up and the proven
  address keeps the traffic. The token of a given-up claim is still honoured
  for 30 s, and a claim that speaks again is re-tested with the same token,
  so an answer that is merely slower than the challenges still counts. On
  a path with a round trip over a second, a NAT rebinding used to be
  abandoned and restarted with a new token for ever.
* Challenges to an unproven address are held to the bytes received from it
  (RFC 9000 allows three times); more traffic from it raises the allowance.
  A packet that carries a PATH_CHALLENGE is answered with a PATH_RESPONSE
  of its own size, and that answer is counted first: a copy of the peer's
  challenge sent from a forged address draws the answer and no challenge
  of ours on top.

This follows QUIC (RFC 9000 section 8) and is needed for the same reason:
authentication proves who made a packet, not where it was sent from. An
attacker on the path can copy an authentic packet and re-send it with a
forged source address; without validation both ends would aim their traffic
at whatever address it chose, and on the sending side that is the whole
file. Nothing but challenges, answers to challenges and a handshake
response — together no longer than what came from the address — is ever
sent to an unproven address. A repeated PATH_RESPONSE is caught by the
packet-number window, and a token proves its claim once.

Handshakes are treated the same way, since a handshake message is just as
easy to capture and repeat from elsewhere as any other packet.

### NAT

A receiver must be reachable at the address senders use. With the
`nat-traversal` feature the receiver works that out in the background,
without delaying transfers, and reports it as a `Reachability` event: the
address tests and the port-forward request run side by side, the result
is reported as soon as the tests are done, and again when a forward is
granted, so a router that is slow to answer holds nothing up.

Addresses are compared and screened in their canonical form (an IPv4 peer
on a dual-stack socket appears as `::ffff:a.b.c.d` and is the same peer as
`a.b.c.d`), and written the way the socket sends to them. A dual-stack
socket runs the tests over IPv4, where the NATs are; its IPv6 addresses are
published as host candidates. NAT66 and NPTv6 are not detected: behind them
an IPv6 host candidate leads nowhere, and the sender simply moves on to the
next candidate.

**What the NAT does.** "NAT type" in the RFC 3489 sense — full cone,
restricted, symmetric — was retired because it was never one property. The
receiver measures the two choices a NAT really makes, separately, with the
tests of RFC 5780 run on the transfer socket itself (the mapping of *that*
socket is the one that matters):

* *mapping behaviour* — does the external port follow the destination? A
  mapping that does not is the same one a sender would arrive at, so
  publishing the address is worth something. One that does means no address
  we can learn is the address a peer would need, and only a relay is left.
* *filtering behaviour* — which inbound packets reach a mapping we have
  already opened? This says whether a sender has to be let in first.

The tests need a server with a second address and port. One that has none
still reports the mapped address, and two independent servers still
cross-check the mapping between them; where neither is possible the answer
is "unknown", never a guess.

Every Binding request is padded to 128 bytes with a SOFTWARE attribute
(RFC 8489; a server may ignore it). `sharp-relay`'s STUN server (`--stun`)
answers only a request at least as long as its answer — at most 92 bytes,
three IPv6 addresses — since the answer goes to an address nobody has
proven: a bare 20-byte request, which would draw 56 bytes (IPv4) or 92
(IPv6), is not answered. RFC 5780's PADDING is the attribute made for this,
but a server has to understand it or refuse the request (RFC 8489 section
7.3.1); SOFTWARE works with every server. The filtering test additionally requires that
the answer arrive *from the address it was asked to come from*: a server
that ignores CHANGE-REQUEST answers from its primary address anyway, and
reading that as "anything gets in" would send a peer punching at a NAT that
will never let it through.

**Port forwards.** A forward is the one way through that depends on neither
the peer's behaviour nor on timing. All three protocols routers speak for it
are tried: PCP (RFC 6887) and NAT-PMP (RFC 6886) first, as two small
datagrams on UDP port 5351 — every router candidate asked from every
interface at once, any extra grant given back — then UPnP-IGD. PCP is also
asked at its anycast address (RFC 7723: `192.0.0.9`, and `2001:1::1` for the
IPv6 firewall), where the nearest PCP server on the way out answers: a
carrier's NAT, which RFC 6888 asks to let subscribers map ports with PCP —
with DS-Lite (RFC 6333) the home router translates nothing, and only the
carrier can forward. NAT-PMP has no anycast address and is asked of the
default gateway alone. The lease is
renewed at half its length (each renewal bounded and interruptible) and
given back on shutdown. A router that reports a private or carrier-grade
NAT address as its own is itself behind another NAT: its forward is not
published, and the summary says so.

UPnP has no authentication at all — anything on the local network may
answer the search, and the answer names a URL to fetch and post to — so
its client is deliberately narrow: a device is believed only if it is on
one of our networks and only about itself (the description and control
URLs must be on the address that answered), every HTTP exchange has a 3 s
deadline and the whole attempt 10 s, and a description over 64 KiB or a
SOAP answer over 16 KiB is an error.

**IPv6 firewall pinholes.** Over IPv6 nothing is translated, but the home
router's firewall (RFC 6092) drops what nobody inside asked for; PCP `MAP`
(RFC 6887) and the IGD v2 service `WANIPv6FirewallControl` (`AddPinhole`,
`UpdatePinhole`, `DeletePinhole`) are how a host asks it for a hole. PCP goes
to the default gateway and to `2001:1::1`; for UPnP the search goes to the
IPv6 groups `ff02::c` and `ff05::c` (UPnP Device Architecture 1.1, 1.3.2) on
every network the host has IPv6 on, alongside the IPv4 one. An answer is
believed if it came in on the network it was asked on, from an address a
router has there (link-local, or inside a prefix the host has on that
network). The router is then asked at the address that answered, at the port
and path of the answer's `LOCATION` (a router that answers from its link-local
address and names its global one is asked at the first), and the request
leaves *from the address the pinhole is for*: a router lets a host open a
pinhole to itself only — miniupnpd checks the address the request comes from
against `InternalClient` and, for a request that came over IPv4, has no IPv6
address to check and refuses it (error 606) — so a pinhole asked for over IPv4
is only tried after the IPv6 one, for routers that turn out to answer nothing
else.

**Candidates.** Every address that might work is published together, as
`ID@host:port,host:port,…`: the port forward, the address the world sees the
receiver at, and its addresses on the local network — candidates in the
sense of ICE (RFC 8445), ordered so the ones that work from outside come
first (global IPv6, global IPv4, then private ones). The sender tries them a
quarter of a second apart while any remain untried, then backs off. Nothing
is risked by publishing an address that turns out not to work, because
completing a handshake takes the receiver's private key: a wrong candidate
costs a quarter of a second.

Host candidates follow ICE's rules (RFC 8445 section 5.1.1.1): never
loopback, IPv6 link-local (a peer cannot know which of its interfaces the
zone would be), deprecated site-local or IPv4-compatible addresses. An IPv6
address the system itself no longer prefers or has not finished checking —
deprecated, tentative, failed duplicate address detection — is left out.
Where the system uses temporary addresses (RFC 8981), one address stands for
each interface and /64, and it is the temporary one: publishing the stable
address beside it would give away exactly what the temporary one hides.
With `publish_lan_addresses` off (`--no-lan-addresses`) only globally
routable addresses are published. The host's addresses are looked at again
every five minutes, since interfaces come and go and temporary addresses
are replaced.

**Keeping the mapping.** A NAT forgets an idle UDP mapping, and from then on
a published address leads nowhere. RFC 4787 asks NATs to keep one for at
least two minutes, but plenty keep one for thirty seconds or less. So the
mapping behind a published address is refreshed with a STUN Binding
Indication (RFC 8489: no answer, no state on the server) every 15 s — RFC
8445's default for ICE keepalives — and checked with a Binding request every
60 s. Where the server has shown itself an RFC 5780 one, the NAT's mapping
lifetime is measured in the background with RESPONSE-PORT (RFC 5780
section 4.6): a socket of its own makes a mapping and falls silent for 15,
30, 60 or 120 s, then another socket asks the server to answer to that
mapping; the answer arrives only if the mapping is still there. The interval
is then half the measured lifetime, between 5 and 60 s. A mapping seen to
have changed anyway — the STUN check or a relay reports a new address —
halves the interval (not below the floor), and the new address is reported
at once. Every wait is jittered by a tenth either way. One policy serves
the STUN keepalives and every relay registration of the socket, because they
all rest on the same mapping.

STUN messages arrive on the transfer socket and are routed to the NAT task
by the receiver's dispatcher, requests included — the hairpinning test works
by watching for our own request to come back.

**None of it is trusted.** STUN servers and routers are unauthenticated, and
on a network we do not own anything may answer. All any of them can produce
is an address that does or does not work: they decide which addresses are
worth *trying*, never who we talk to. An address a server tells us to send
to is screened before we send there, so clients cannot be used as
reflectors, and PCP's nonce is checked so that another request's answer is
not taken for ours. A plain STUN answer counts only from the server it was
sent to (the transaction id travels in the clear), and a STUN error answer
ends the test instead of passing for silence.

The sender needs no NAT handling: its outgoing datagrams create the mapping
on its own NAT, and the receiver answers the address a handshake came from
(and follows a mapping that changes later through address validation).

**When nothing else works.** Two peers both behind NATs that give out a
different port per destination cannot reach each other however hard either
tries: no address either can publish is the address the other would need.
For that case there is a relay (`sharp-relay`), which either side names as
`--relay [ID@]host:port`.

A receiver registers its identity with the relay, over its transfer socket,
and keeps the registration alive — refreshed at the keepalive interval of
the socket's NAT mapping (above), not merely within the relay's lease, since
a mapping forgotten between refreshes leaves the relay introducing senders
to an address that leads nowhere. A relay that sees the receiver at a new
address after a refresh has shown the mapping lapsed, and the refreshes get
closer together; a relay that stays silent for a whole lease has forgotten
the receiver, and registering starts over. A sender asks to be put through,
and the relay does two things at once:

1. **Introduces them.** It tells each end where the other appears to be, and
   they push outwards simultaneously — the receiver with a few small
   datagrams that draw no reply, the sender with its handshake. That is hole
   punching, and where the NATs allow it the transfer runs directly and the
   relay carries nothing.
2. **Sets a port aside.** The relay allocates a UDP port for the pair. Each
   end presents the ticket it was given, which both says which side it is
   and opens the way back through its own NAT — the relay cannot assume
   either address, because the NAT it exists to get around is precisely the
   kind that uses a different port here than it did for the control
   exchange. A side is bound only once its address has shown it receives
   there: the first `Open` draws a `Confirm` back to that address, carrying
   a keyed hash of the ticket and the address, and only an `Open` repeating
   it binds the side. A forged source never sees the confirmation — and
   none of the relay's own ports ever answers one, which is what makes it
   impossible to set two allocations forwarding a datagram to each other
   for ever. Once both sides are bound, datagrams are copied between
   exactly those two addresses.

The sender takes both as candidates, after its own: the direct one first,
the relayed one last, so a relay is only used when it has to be.

A relay is written `ID@host:port` for a receiver, which must prove its
identity against the relay's key, and `host:port` for a sender, which then
never names itself; a sender given the relay's ID too names itself only to a
relay that refuses strangers (below). Names are resolved in the background
to every address the socket can reach, in the order of section 8, and a
receiver moves on to the next address after two unanswered attempts, so a
relay whose IPv6 path is broken is still reached over IPv4. A receiver
keeps retrying a name that does not resolve yet, and keeps re-registering
through send errors, since the relay may be the only way anyone can reach
it. A sender is as persistent about the relay: told that the relay has no
registration for the receiver (`Error` code 1) — the receiver may be
registering at this very moment, or renewing a registration that lapsed — it
asks again, pausing 0.6 s and doubling up to 4 s, for up to two minutes; and
a relay none of whose addresses answered is asked again for up to a minute,
pausing 1 s and doubling up to 8 s. Giving up on a relay at the first
refusal or silence would lose the introduction, which is the only way in
wherever the receiver's NAT lets nothing in unasked. Other refusals (busy,
bad proof, not on the list) end the asking, as they always did.
A dual-stack relay carries a pair across the families: a sender over
IPv6 and a receiver over IPv4 meet on one allocated port.

Relay control messages begin with the eight bytes `SHRELAY1` (the one
connection id no endpoint picks) and a kind byte; an address is
`family:u8 (4|6) port:u16 ip[4|16]`. Anything that is not exactly one of
these, with nothing left over, is ignored.

| kind | message | direction | body |
|---|---|---|---|
| 1 | Register | receiver → relay | `id[32] token[16] flags:u8 stamp:u64 hints nonce[16] proof[16]` (flag 0x01: private) |
| 2 | Challenge | relay → peer | `token[16] tag[16]` |
| 3 | Registered | relay → receiver | `lease:u32 observed:addr tag[16]` |
| 4 | Connect | sender → relay | `target[32] token[16] hints nonce[16]` |
| 5 | Allocated | relay → sender | `port:u16 peer:addr ticket[16] hints tag[16]` (peer unspecified: private) |
| 6 | Incoming | relay → receiver | `port:u16 peer:addr ticket[16] hints tag[16]` |
| 7 | Error | relay → peer | `code:u8 tag[16]` (1 unknown, 2 bad token or proof, 3 busy, 4 stale) |
| 8 | Open | peer → allocated port | `ticket[16] proof[16]` (proof zero: asking) |
| 9 | Punch | peer → peer | — |
| 10 | Bye | receiver → relay | `id[32] token[16] stamp:u64 nonce[16] proof[16]` |
| 11 | Confirm | allocated port → peer | `proof[16]` |
| 12 | ConnectAs | sender → relay | `target[32] token[16] hints nonce[16] id[32] proof[16]` |

Refusal 5 is *forbidden*: the relay serves only identities on its list.

**Every answer a relay gives is one only it could give.** A datagram's
source address is anybody's to write, and a peer used to believe whatever
came "from the relay's address": a forged `Incoming` had a receiver push
datagrams at any address it named — with hints claiming a NAT that draws
ports at random, a spray of 2048 — a forged refusal took a receiver off its
relay for ten minutes, and a forged `Registered` told it a made-up address
and shortened its keepalive. Now every request carries a `nonce` (a
receiver picks one when it starts and puts it in all its registrations and
its goodbye; a sender picks one per attempt to be put through), and every
message the relay sends closes with a `tag`:

* To a receiver whose registration it has checked — `Registered`,
  `Incoming`, and the refusals it gives after checking (`busy` for a full
  share, `stale`, `forbidden`) — the tag is
  `BLAKE3-keyed(K', nonce || message up to it)[0..16]`, with
  `K' = BLAKE3-derive_key("sharp256 relay v1 relay to peer", K)` and `K` the
  registration key below. Only the relay and the receiver can compute it,
  and it holds for this run of the receiver only.
* To anybody else, and before a registration's proof is checked
  (`Challenge`, a `busy` under load, `bad token or proof`, and everything a
  sender is told), the tag is the nonce of the request it answers, given
  back: somebody who cannot see the requests cannot answer them.

A receiver acts on `Registered`, `Incoming`, `stale` and `forbidden` only
with the MAC, and on anything else only with one of the two; a sender only
on answers that give its nonce back. Anything else from the relay's address
is ignored. What is left is a party *on the path* to the relay: it sees a
sender's nonce and can answer in the relay's name — as it could drop the
sender's datagrams anyway — and a `forbidden` it forges still makes a sender
that knows the relay's ID name itself (`docs/THREAT_MODEL.md`, Р11). A
receiver's messages it cannot forge: the MAC needs the key.

**Hints** are `nat[6] alt`, where `alt` is either the single byte `0` (nothing
to say) or `addr nat[6]`: the peer's address in the *other* address family
and what the NAT in front of that one does. A relay sees a peer over one
family only, whichever the message came in on, and can say nothing of the
other; on a host with both, the other family is often the path that works —
IPv6 has no NAT to get through, and two IPv4 NATs that give a new port for
every destination cannot be punched at all — but a firewall that lets in
only what its own side sent out first has to be told the other end's address
*before* they talk, or its side never opens. So each peer says, in the family
it is reached over, how its NAT behaves, and in the other, where to aim.

**NAT hints** (`nat[6]`) say what the NAT or firewall in front of the sender
of the message does, as its own RFC 5780 tests measured it, so that the
other end can aim its punches (see `docs/NAT.md`). Byte 0 is the mapping
(0 not measured, 1 endpoint-independent, 2 address-dependent, 3
address-and-port-dependent, 4 no translation), byte 1 the filtering (0 to 3,
the same order), byte 2 how a NAT that varies the port numbers them (0
unknown, 1 keeps the host's own port, 2 counts up, 3 random), bytes 3–4 the
step of a counting NAT as a signed big-endian integer, and byte 5 flags:
bits 0–1 hairpinning (0 unknown, 1 no, 2 yes), bit 2 a carrier-grade NAT in
front. Any other value is a malformed message, and so is a family byte in
`alt` that is neither 0, 4 nor 6. A relay keeps the receiver's hints with
its registration and passes them to each sender it introduces, and hands the
receiver the sender's; for a receiver that registered as private both are
sent as all zero (and `alt` as `0`). The hints are advice from a peer that
need not be honest: they change how many datagrams of nine bytes are sent
and to which ports, never who is trusted. In Register the proof covers them.

The relay passes an `alt` on only if it can be what it says: in the family
the message did *not* come in on (an IPv4-mapped IPv6 address is IPv4), with
a nonzero port, and an address the internet routes (RFC 6890). Anything
else is dropped, not refused, and what is passed on is written in its plain
spelling. The peer that receives it screens it again, since the relay is not
trusted either: it is one more address to send nine-byte punches to and to
try in the handshake, subject to the same limits as any other candidate.

`proof` in Register, Bye and ConnectAs is
`BLAKE3-keyed(K, message up to it)[0..16]` with
`K = BLAKE3-derive_key("sharp256 relay v1 registration",
DH(peer, relay) || peer_id || relay_id)`, the peer being the receiver or
the sender that sends the message.

**Registering is the owner's to do.** A receiver proves it holds the private
key for the identity it registers: the two sides already know each other's
long-term public keys — the receiver is given the relay's in its address,
and the relay reads the receiver's out of the registration — so a static
Diffie-Hellman between them is a secret only those two can compute, with
nothing to exchange first. The registration carries a MAC under a key
derived from it, covering the whole message. That construction has no
forward secrecy and nothing fresh in it, which is exactly why transfers use
the Noise handshake instead; it is the right tool for proving to somebody
who knows your public key that you hold the private one. Without it, anyone
who knew a published ID could register it and have senders put through to
them — the handshake would fail, but the transfer would fail with it. A
small-order point as the identity is refused: the exchange with it is the
same for every secret, so its "proof" is one anybody can make.

Registrations and goodbyes also carry a **stamp** that must increase per
identity (the owner uses the wall clock in nanoseconds, never repeating
itself). The proof binds a message to its owner, but only the stamp binds
it to a moment: without it, a registration captured from the owner's
address could be sent again while its token lived — to move the
registration back to an old address, or to make a private one public —
and an old goodbye could end a registration made since. The relay keeps
each identity's newest stamp, and for four minutes after a registration
ends (as long as any captured token could still be good); a message not
newer is answered `Stale` (refusal 4).

**The relay is trusted with metadata, not with the transfer.** It carries
sealed transport packets, so it cannot read them, cannot alter one without
the AEAD rejecting it, and cannot inject one without the peers' keys; it
cannot impersonate a peer, because completing a handshake takes that peer's
private key; and it decides nothing about who may send to whom, since the
receiver still admits or refuses a sender by its identity. A hostile relay
can refuse to carry the traffic, and it sees what it is there to see: which
identity is registered at which address, who asks for whom, when, and how
many bytes each pair moves. The control messages are not encrypted, so an
observer on the path to the relay sees the same; relay replies are not
authenticated either. Choosing a relay is choosing whom to trust with that.

**Who may use a relay, and how much.** A relay carries traffic on its
operator's bandwidth, so access is the operator's to decide. By default a
relay serves anyone and says so when it starts. A list of receivers limits
who may register: `Forbidden` is sent only after the registration's proof
has been checked, so the list is not disclosed to anyone who asks. A list of
senders limits whom it puts through: an anonymous `Connect` is answered
`Forbidden`, and a sender that knows the relay's identity then asks again
with `ConnectAs`, proving its own identity with a MAC made as a
registration's is, over the whole message. A sender that does not know the
relay's identity cannot prove anything and reports the refusal. `ConnectAs`
carries no stamp: repeated from the address it came from while its token
lives, it asks again for what the sender asked for, and from anywhere else
the token does not match. A forged `Forbidden` makes a sender that knows the
relay's identity name itself in the clear — which is why receivers hand
senders the relay's address without its ID.

Quotas bound what is carried, on the all-or-nothing principle — a datagram
refused by one limit spends nothing from the others: a rate per client (an
IPv4 address or an IPv6 /64; 100 Mbit/s by default), a volume per client per
hour, a total rate for the relay, and a volume per pair after which its port
is closed. The rates are token buckets holding a quarter of a second of
their rate (at least 64 KiB); a datagram over any limit is dropped, which the transfer's
congestion control answers by slowing down to what is allowed. One that
came on a stream instead waits for the quota, up to 50 ms, and so does one
for a stream whose queue is full: the stream is not read meanwhile, and TCP
slows the sender, which on a stream leaves loss recovery to TCP and would
send a dropped datagram again and again. The table of
clients is bounded and forgets only clients whose allowance has fully
recovered, so being pushed out of it never refills an allowance.

A registration is also accepted only once it echoes a token derived from the
address the relay saw, so a forged source address cannot point the relay's
traffic at somebody who never asked for it. The token is a keyed hash of
that address, so no table of pending registrations exists to fill up; its
secret is replaced every 120 s on the clock, and a token is good for at
most two such periods however long the relay goes unasked. Registrations,
ports and the request rate each have a share per client — an IPv4 address
or an IPv6 /64 — an idle pair is reclaimed (after 60 s; and a client that
holds its whole share, or finds every port taken, gets the one of its own
pairs that has carried nothing longest, if for 10 s, made room with: one
sending file after file through the relay left a pair behind for each),
and a receiver says goodbye on
the way out so that senders are not sent to a dead address for the rest of
the lease (a goodbye whose token went stale draws a fresh one and is sent
again). The relay's sockets ignore ICMP errors, and its control loop waits
out receive errors instead of stopping.

**Hiding where a receiver is.** By default the relay tells each side where
the other appears to be, which is what lets them meet directly and leaves
the relay carrying nothing. A receiver that would rather not be described
registers as private: the relay then tells neither side anything about the
other — in its first introduction and every repeat — there is no direct
path to try, and everything goes through the relay. Such a receiver
publishes nothing of its own either: no NAT discovery, no port forward, no
direct candidates. It is written as its ID alone, and a sender given that
and `--relay` reaches it through the relay. It costs the relay's bandwidth
and gives up the direct path, and it is the only arrangement in which a
relay actually hides anyone — from those who do not already know where it
is.

This is also the honest answer to hiding one's own address from a peer: run
the traffic through a relay you control. Forging a source address is not an
alternative to it — a transfer needs a return path, and it is an attack
technique rather than a defence.

### Contact cards

A card is what one end tells the other by any channel that carries a line of
text, so that two people on different networks can start sending at each
other at the same moment. It is a hint, like every address here: it selects
what to try and never whom to trust (the identity in it is the one the
handshake demands a private key for).

    version:u8 (1)  role:u8 (1 sender, 2 receiver)  created:u32 (seconds)
    id[32]
    n:u8 (≤ 16)  n × ( kind:u8  addr )
    flags:u8 (bit 0: IPv4 hints follow, bit 1: IPv6 hints follow, bit 2: version 4)
    hints[6] per family present
    m:u8 (≤ 4)   m × ( id[32]  addr )          the relays it can be reached through

`kind` is 0 for an address of an interface, 1 for what a STUN server saw,
2 for one a router granted (port forward or IPv6 pinhole) and 3 for an
address on a TURN server. The text form is `shc1-` and the base32 of the
body followed by the first four bytes of its BLAKE3 hash; whitespace and
dashes inside are ignored, so a line a chat client wrapped still reads. The
checksum catches a mangled line, not a forged one. A receiver takes cards
given on the command line or pasted into the running process, sends at every
address on each (kind 3 included) and — for a card given at the start —
accepts only the senders whose cards it has. A card carries the time it was
made, and a program says so when one is more than an hour old (or, by its
own clock, made in the future): an address written down a while ago may not
be one now.

Two people may swap bare addresses (`IP:PORT`) instead of cards. The
receiver's `Senders use:` line lists its candidates and, behind a NAT that
numbers ports per destination, ends with the address a STUN server saw it
at: no candidate (it is where *that server* reaches the receiver), but what
tells the sender which IP the receiver's punches will come from — a sender
answers a punch only from an IP it has reason to try — and where predictions
of the receiver's next port start. `sharp-sender --card` prints the sender's
own outside addresses and punches at the receiver's as it does at a DHT's,
nothing being known of the NAT in front of them; the receiver punches at an
address pasted into it (or given with `--peer-addr`) the same way. A bare
address says nothing of who is behind it, so, unlike a card given at the
start, it restricts nobody. Neither line has an address on a TURN server on
it: written bare, nothing would say that it is one, and a peer punching at it
as at a host whose NAT is unknown would spray somebody else's server with
guessed ports. Only a card carries one, marked as what it is (kind 3).

### Punching

What a punch is, and how much is sent, is decided from what each end's NAT
does (the hints above) by `nat::punch::plan`, for the address being aimed
at:

| ours | theirs | plan |
|---|---|---|
| any | no translation, filters by address alone or not at all | one socket, one port |
| random | keeps one port per source (stable) | *birthday, hard side*: 256 sockets of ours, each sending at the peer's one address |
| any | counts up by `step` | *prediction*: the peer's port, then `PREDICT_WINDOW` (48) further on and `PREDICT_BEHIND` (12) back, `step` apart |
| stable or counting | random | *birthday, easy side*: `BIRTHDAY_PROBES` (2048) random ports of the peer, once each |
| random or counting | random | nothing works in reasonable time: a relay |
| anything else | stable | the address as told |

A pass lasts six seconds and repeats every ten. A spray is sent at most once
in ten seconds to one address and to at most eight addresses at a time; a
prediction or a spray is aimed only at an address the internet routes (the
peer's private address on a card is its own network). Where the peer's NAT
is not known — an address from a DHT, from a name, from a list typed by
hand — the first pass is the easy case and the passes after it are the plans
a peer of each harder kind would call for, in turn (a peer that is strict
but stable, one that counts up, one that draws at random), the ones that
could not work left out. A punch is a nine-byte datagram (`Punch`, above)
that draws no reply from anyone; the whole cost of a hostile hint is that.

The hard side's sockets come out of one allowance for the whole process:
half the descriptors the system lets it have open, where it says (1024 by
default on Linux, 256 on macOS), and never more than two meetings' worth
(512). A meeting that finds less opens less and is only the less likely to
meet; one that finds none opens none. A process that ran out of descriptors
could not open the file it is receiving into.

Punching for a meeting — at the addresses on a card, at an address typed in,
at one the DHT turned up — goes on for as long as a person may take on the
other side (five minutes) and stops as soon as a session with that peer runs
directly to its host: at the sender, when its session is on neither a relay's
port nor a TURN address (and when its transfer ends, whatever the state); at
the receiver, when a session from that peer — the card's sender, or anyone
for a bare address — runs at the host punched at, at an address the peer has
shown it receives at: a transport packet from the address the handshake came
from (it takes the keys that the answer to the handshake made, and the answer
went there; the handshake alone proves nothing of its source, which a copy
may have forged), or an address that answered a challenge. A session carried
by a server stops none of it: that punching is how a direct path opens
(below).

The sender, once it has been told the receiver's addresses, answers a punch
that comes from an address it did not know but whose IP it did — the peer's
NAT telling it which port it gave the peer for the sender — at once, from
its own socket, so that the hole is used while it is open (at most sixteen
such ports, twelve initiations each, eighty milliseconds apart).

### The local network

A receiver started with `--announce-lan` answers, for its identity, questions
in multicast DNS (RFC 6762) for the service instance
`<id, lower case>._sharp256._udp.local.`: the SRV (port), TXT and the A and
AAAA records of the host name `sharp-<first twelve characters of the ID>.local.`
alongside. A sender started with `--lan` asks that one question once, from an
ephemeral port with the unicast-response bit set (RFC 6762 section 5.4, 6.7)
and takes the addresses in the answer as candidates. The question is padded
to 1200 bytes with an EDNS(0) OPT record carrying padding (RFC 6891, RFC
7830), and the answer is never longer than the question: the responder
leaves addresses out, last first, until it fits, or does not answer (an
unpadded question, some 100 bytes, would draw four times that at whatever
address it claimed to come from). An answer is taken only
from an address on the same link (section 11), everything read is bounded
(at most 64 records a section, 255 bytes a name, 16 compression pointers),
and neither end does anything unless asked to: an announcement tells the
whole network that this host receives SHARP-256 transfers, and a question
tells it whom the sender is looking for.

### The DHT

With `--dht` the two ends use the Mainline DHT (BEP 5) as a meeting place.
Both derive `key = BLAKE3-derive_key("sharp256 dht rendezvous v1", receiver_id
|| secret)` (the secret, if any, being the 32-byte PSK `--secret` stands for,
section 1; nothing without one)
and the infohashes `BLAKE3-keyed(key, "receiver")[..20]` and
`BLAKE3-keyed(key, "sender")[..20]`. The receiver announces the first and
asks for the second, the sender the reverse; `announce_peer` carries the port
the NAT tests found for the transfer socket, and the address is the one the
node saw the announcement come from. The client is read-only (BEP 43), uses a
socket of its own, walks towards the nodes closest to the infohash (the eight
closest, three queries at a time, sixty at most, 256 candidates at most) and
reads answers strictly and bounded: a reply is taken only from the address
the query went to and under its four-byte transaction id, at most 32 nodes and
32 peers are read from one, and a token longer than 64 bytes is not one.
What turns up is punched at as an address on a card is, with one difference:
a node answers a lookup with whatever it likes, and one on the lookup's path
sees the infohash in the question, so an address from the DHT gets only the
plain punches until it is vouched for — two nodes at addresses of their own
have named it (`VOUCHERS`; an announcement is stored on every node it goes
to), or a punch has come from its host — and the predictions, sprays and
birthday sockets of unknown-NAT punching after. The sender tries it in the
handshake only once it is vouched for, too (a version 4 initiation is a
kilobyte and a half), and an address only the nodes vouch for gets eight
initiations (`DHT_INITIATIONS`) until a punch from its host backs it: in the
real DHT, nodes answered a receiver nobody else could know of with an
address that was not its own, and agreed on it (`docs/evidence/field/`). A
punch from the host of an address the DHT named — the receiver looks the
sender up and punches at it — makes that address a candidate at once,
however many nodes named it: in the real DHT one node often holds the
announcement. Until something vouched for
has turned up, the lookups go on at the brisk pace: an address one node made
up is no reason to look less often for the real one. Nothing is said of the
NAT in front of an address, which is why unknown-NAT punching above exists.

Every node asked learns this host's address and that it looks for, or
announces, an infohash; anyone who knows the infohash can read what was
announced under it. Without a shared secret the key is a function of the
receiver's ID alone, so anybody who knows the ID can compute it: the receiver
is then as easy to find as if its address were published. This is said in the
log where it happens.

### TURN

An allocation on a TURN server (RFC 8656, with RFC 6156 for an IPv6 relayed
address) gives an address that reaches its holder whatever its NAT does. The
client speaks UDP to the server only: an Allocate without credentials to be
told the realm and a nonce, again with a long-term credential
(`MD5(user:realm:password)`, HMAC-SHA1 over each request, checked on each
success answer); a stale nonce (438) is taken and the request repeated;
CreatePermission for each address that may send (permissions last five
minutes and are renewed at four), ChannelBind for a peer that is being talked
to (ten minutes, renewed at nine), Refresh at half the granted lifetime and
with lifetime zero on the way out, and a Binding request every 25 seconds to
keep the NAT's mapping towards the server. Requests are repeated after
0.5, 1, 2 and 4 seconds.

The transfer engine does not speak TURN. Each allocation has a socket of its
own, and for each peer a loopback socket, the *shim*, connected to the
engine's: what the engine sends to the shim goes to that peer through the
server, and what the peer sends to the relayed address comes to the engine
from the shim's address. A peer costs one loopback address; at most sixteen at
a time, the quietest let go to make room for a new one. A datagram of more
than 1232 bytes (the engine's own floor, `UDP_PAYLOAD_SAFE`) is dropped, so
that the engine's path-MTU probing settles on it. The server forwards only
what comes from an address it has a permission for, so the holder needs the
other end's address before it can be reached — from that end's card, or from a
relay's introduction — and every address punched at is permitted.

### Leaving a relay for a direct path

A relay's port and an address on a TURN server carry a session; neither is
where the receiver is. While a session runs over one, the sender sends an
authenticated `Ping` to each of the receiver's other addresses (four at
most) every second for thirty rounds and every four seconds after, and keeps
learning the receiver's punches as addresses. These pings are padded to 128
bytes (zeros after the timestamp): the receiver sends an address it does
not know no more than it got from it, and a bare ping (37 bytes) is shorter
than the challenge (41) it is meant to draw. A receiver that gets the ping
from an address it did not know treats it as any packet from a new address:
it challenges the address (`PATH_CHALLENGE`, section 4), and on the answer
moves the session there; the sender does the same for what the receiver then
sends. Both ends prove the other's address before they move (section 8,
address validation), so nothing here can be turned on a third party.

Neither end follows the other back to a server's address — a relay's port,
an address on a TURN server, a TURN shim — while the direct address it runs
on has been heard from within the last three seconds (`DIRECT_GRACE`). What
arrives through the server meanwhile is the other end catching up: packets
it sent before it moved, answers to challenges made then. Followed back,
they made the two ends swap paths in turn, each moving because the other
just had, and a session could end on a TURN server with a direct path open
all along (seen in the laboratory where the server's path is the slower
one). The sender knows which of the receiver's addresses are servers'; the
receiver counts its own TURN shims, the hosts of its relays, and the TURN
addresses on the cards it was given. A direct path that stays quiet longer
is left in the usual way (below). A stream straight to the other end
(see carriers, below) stands between the two: a session on UDP does not
follow the other end onto a stream while UDP is heard, and one on a stream
does not follow it onto a server's address while the stream is. A relay's
stream ranks below the relay's own UDP port.

A sender whose NAT draws its ports at random meets a receiver behind an
ordinary one with many sockets (section 8, punching), and only the socket
the receiver's packet reached has a way in. The sender keeps that socket
next to the one it started on and reads both. What goes to the address the
meeting was made with leaves from the meeting's socket; everything else, and
above all what goes to a relay or a TURN server, leaves from the first one,
which is the socket they know the sender by (a relay by the address it sees
it at; a TURN shim is connected to it). A meeting made before the handshake
completed is where the handshake goes. One made while the session is
carried — it takes a few seconds, so a relay's or a TURN server's answer
usually comes first — is an address like any other: the pings and address
challenges to it leave from its socket, and once the receiver has proven it
(to the receiver this is a sender at a new address, nothing more) the
session runs on that socket. If it is not proven in twenty seconds the
socket is let go.

### Going back to a server

A direct path can die in the middle of a transfer: a gateway reboots and
forgets its mappings, a firewall rule changes, a route goes. Once the
session's path has been quiet for `min(stall_timeout, 3 s)`, the sender's
re-handshakes go round every address the receiver is known by — its last
one first, then the rest best first: UDP straight to the receiver, a stream
straight to it, a server's UDP port, a relay's stream (see carriers, below)
— each from the socket it is reached from, and whichever answers carries the
session (the transfer resumes where it stopped, as after any silence). The
stall rules proper (`stall_timeout`, 20 s by default) only pause sending
and say so. A server's way stays open only as long as the server keeps
it: a relay releases a pair's port after a minute with nothing flowing
(`sharp-relay --idle`), so a direct path that dies later than that has only
a TURN server to go back to — its allocations are kept by both ends for as
long as they run — or nothing, and the transfer then ends after
`give_up_timeout` with its state kept for a resume. A session back on a
server asks the receiver's other addresses again, as above, the meeting's
first — a few each round, in turn, so that one found late is asked too.

**A change of network.** A session falls back from a direct path to a
server's also when one end changed networks (Wi-Fi to LTE): its packets
leave through another NAT now, whose mapping the other end's NAT was never
sent to and nobody knows. So a sender whose session falls back from a
direct path to a server's tests its NAT again (STUN only, at most every
30 s), and asks every relay again for the receiver with the same token,
from where it is now (at most every 5 s, and every fifth round of asking
the receiver's addresses while carried). The relay answers where the
receiver is registered now — a receiver that moved learns its new mapping
at its next keepalive to the relay and registers it — and that address
joins the candidates and is punched at; and it introduces the sender to the
receiver again, at the address it sees the sender at now and with the
hints of the NAT test, which the receiver punches at as at a new
introduction (a repeat with another address or other hints is one). The
answer to asking again counts only if it carries back the request's nonce.
`natlab.py mobility`: every case back on a direct path.

### Carriers other than UDP

Some networks let no UDP through, cut it in the middle of a transfer, or
let it through held back — policed to a trickle, or dropped in part — while
TCP passes; some let nothing out but TCP to port 443. For them the same
datagrams go over a TCP stream, and, to a relay, over TLS on that stream
(the `tls` build feature, on by default). Nothing above the carrier knows
it is there: a datagram on a stream is exactly the datagram that would
have gone over UDP, sealed end to end, with its connection id and packet
number.

**Framing.** The side that opens a stream sends an 8-byte preamble,
`"SHRP" | version (1) | kind | 0 0`, kind 1 for a stream to a receiver and
2 for one to a relay; the side that accepts it sends the same eight bytes
back, which tells the opener that a SHARP-256 endpoint is there (and not a
web server on port 443). Then each way, frames: `length (u16) | port (u16)
| datagram[length]`. On a stream to a receiver the port is 0. On one to a
relay it is the relay's port the datagram is to or from: 0 for its control
port, a pair's port otherwise. A frame of length 0 is ignored; one whose
length has its top bit set (`0x8000`) is the carrier's own business — the
TLS binding below — and not a datagram. No datagram is longer than a jumbo
frame's UDP payload; a frame claiming more ends the stream.

**Receivers** accept streams on the TCP port with the number of their UDP
port, on the same address (both families where the UDP socket takes both),
and hand what they carry to the dispatcher as if it had come in on the
socket, from the address the stream comes from; what they send to that
address goes back on the stream. At most 64 streams at once, 4 from one
client (an IPv4 address, an IPv6 /64); the preamble must come within 5 s,
and a stream that carries nothing for 60 s is closed. `sharp-receiver
--no-tcp` keeps to UDP.

**Senders** dial streams when UDP has not answered the first initiations
within 1.5 s, when the receiver has gone quiet for `min(stall_timeout, 3 s)`
in the middle of a transfer, when a stream the session ran on ends, and
while the session is carried by a server and the receiver's own UDP
addresses have not answered five rounds of pings (see leaving a relay,
above). The receiver's addresses are tried as RFC 8305 tries them: one at a
time, 250 ms apart, families taking turns, the first stream up kept; one
stream at a time, an address that failed tried again after 30 s at the
soonest, streams asked for at most every 10 s. The relays the sender was
given are reached over streams of their own at the same moments (below).
Each stream is joined to the engine through a *shim*, a loopback UDP socket
that stands for the stream as a TURN shim stands for the server, so a
stream is one more address of the receiver's, moved to and from by proving
it like any other (section 8, address validation). A stream that comes up
while the session has been quiet for a second gets an initiation at once
when no other datagram path is known; otherwise it waits its turn round the
re-handshakes, after the UDP ones (going back to a server, above): UDP
first, a stream where UDP does not get through. During the handshake the
same holds for a datagram path learned late — a relay's port, an address a
name resolved to: for 1.5 s after it, a stream that comes up waits its turn
round the ring rather than making that path's attempt moot. An initiation makes the one
before it moot; so while a stream straight to the receiver is up, a relay's
stream gets none, and a session that ended up on a relay's stream all the
same moves to the direct one — by proving it, asked every two seconds —
when there is one; on a relay's stream the sender also asks the servers'
UDP ports, which rank above it. `sharp-sender --no-tcp` keeps to UDP.

**On a stream**, the engine steps aside for TCP: a stream is reliable and
has congestion control of its own, and running the session's own as well
would have both resend what one of them only delayed. The window is what is
in flight plus the room left in the stream's queue (1 MiB), capped by the
receiver's window; nothing is paced (unless a rate cap is set); there are no
tail loss probes; the retransmission timer is at least 10 s and only
notices a stream that died without saying so. Moving between a stream and
a datagram path starts congestion control and the round-trip estimate
afresh, and what was in flight on a path quiet for a second or more is sent
again at once.

**Relays** accept streams on the TCP port with the number of their UDP port
(`sharp-relay --no-tcp` turns it off), and over TLS where `--tls ADDR` says
(`[::]:443`, typically). A client's stream to a relay carries its control
messages on port 0 and each pair's datagrams on the pair's port, so a
sender and a receiver can each reach the relay over UDP or a stream, in any
combination, and the relay carries between them as before. A client on a
stream is known to the relay by its TCP address, and shown to others as no
address at all (it has none they could send to). 256 streams at once, 8
from one client, idle ones closed after 120 s. A receiver registers over
UDP while that works, which is what lets senders punch through to it; after
8 s with no registration over UDP it registers over a stream instead, and
every 10 minutes it tries UDP again alongside, going back to it — and
closing the stream — as soon as UDP holds the registration. Clients try a
relay over TCP at its port and, 250 ms later, over TLS at port 443
(`--relay-tls-port`), the first up winning — TLS only to a relay whose ID
they were given, for the reason below.

**TLS to a relay** is a way through a network that lets out only what looks
like HTTPS, not a layer of security: everything inside is sealed already.
TLS 1.3 only (rustls, ring). The relay's certificate is a self-signed
Ed25519 one it makes at start-up, and a client takes any certificate whose
key signed the handshake. What a client checks instead is that the session
is the relay's own and not one a TLS-inspecting proxy opened on the way:
after the preambles it sends, in a frame of its own, `1 | ephemeral X25519
public key (32) | nonce (16)`; the relay answers `2 | MAC (32)`, a keyed BLAKE3
MAC under `derive_secret("sharp256 relay tls binding v1", [DH(ephemeral,
relay key), ephemeral key, relay ID, nonce])` over a key both ends export
from the TLS session (RFC 8446 section 7.5, label
`EXPORTER-sharp256-relay-binding`, the nonce as context). Only the holder
of the relay's long-term key can make the MAC, and a proxy that ended the
client's TLS and opened its own has a different exported key on each side.
A client that gets a wrong answer, or none, does not use the stream, and
says why: the sender's error names the relay whose TLS was opened on the
way, should nothing else get through, and the receiver logs it.

**UDP held back.** A policer looks, from inside, just like a slow link with
a shallow buffer; only the other carrier tells them apart. Over windows of 5
s the sender measures what had to be sent again and what got through. A
window in which the path went quiet for a second or more is an outage's, not
a policer's, and is not counted (in the laboratory, a direct path that was
cut had been taken for a policed one). When a tenth or more was sent again —
or a hundredth, with at least 30 s still to go at the rate measured, or the
congestion controller recognised a policer and sends at its rate (see
"Congestion control and pacing") — and at least 15 s are left, it moves
the session to a stream for a trial: one
already up, or one dialled now, which the sender proves as a path on its own
initiative (a packet on the UDP path does not end that asking, as it ends a
claim the other end made). 4 s are given to the receiver to follow, 6 s are
measured. TCP that carries at least 1.25 times what UDP did is kept for 2
minutes, twice as long after each such trial in a row, up to 30; otherwise
the session goes back to UDP and the next trial waits a minute, doubling
likewise. While a trial or a hold keeps it on the stream, the sender asks no
UDP address whether it answers, and does not follow the receiver back to
UDP; the receiver follows onto the stream once it no longer hears the sender
over UDP (`DIRECT_GRACE`). After a hold the session goes back to UDP as
after any stream, and a UDP still held back is found out again and left for
longer.

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
traffic, its timing and its volume — which gives away the file's size to
within a few per cent — and the connection ids (random, changing with every
handshake, but constant within a session, so a peer that moves to another
network mid-session can be linked to its old address). Anyone who already
knows a receiver's ID can tell whether a handshake is addressed to it (mac1
is computed from the ID); nobody else can. Relay control messages are in
the clear (section 8). The receiver's IP address and port are, as for any
server, reachable — only the answer is withheld from strangers. Anyone who
knows a receiver's ID (and its secret, if one is set) can offer transfers
unless the receiver uses an allow-list or asks its user. IDs must be
exchanged over a channel the users trust; the protocol cannot detect a
substituted ID. Identity files are protected by file permissions, and
optionally sealed with a passphrase or by the operating system's key store
(section 1); by default they are not sealed.

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
* **Secrets.** Every key that lives longer than one computation — the
  identity, the pre-shared key, the state of a handshake in progress, each
  session's keys, cookie and token secrets — is kept in memory locked in
  RAM and left out of core dumps, and wiped when dropped
  (`crypto::secret`); the Noise handshake is implemented in `crypto::noise`
  so that its states are wiped too (it writes exactly what snow wrote). MAC
  and tag comparisons are constant-time, and `docs/evidence/crypto/`
  records timing measurements of them.
* **Untrusted input is fuzzed.** Every parser of what arrives from others —
  transport frames, handshake payloads, whole datagrams, manifests, relay
  messages, STUN, PCP and NAT-PMP, UPnP's HTTP and XML, addresses and text —
  has a cargo-fuzz target (`fuzz/`, libFuzzer with AddressSanitizer) that
  also checks that whatever decodes survives encoding again. The same entry
  points (`src/fuzz.rs`) run on thousands of mutated seeds, and on every
  input that ever crashed one, in each `cargo test`.

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
| Encrypted relay control messages | new relay message kinds; the transfer protocol is unchanged |
| New connection ids on migration (as RFC 9000 section 9.5) | capability bit |
| Delivery-rate based slow-start exit | sender-local; no wire change |

IPv6 firewall pinholes, once on this list, are done (section 8, "IPv6
firewall pinholes"). The plan beyond the wire format is in
[ROADMAP.md](ROADMAP.md).

## 12. Defaults

| setting | default | meaning |
|---------|---------|---------|
| `max_chunk` | 1427 B | largest payload bytes per DATA packet (512–8927); lowered on `EMSGSIZE` or a detected MTU black hole, raised again only by an acknowledged PROBE |
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
| `max_sessions_per_sender` | 8 | concurrent transfers one sender identity may hold; when they (or all sessions) are taken, its own transfer silent longest, for `stall_timeout` at least, lets go for its next |
| `memory_budget` | 512 MiB | data not yet on disk, all transfers together (¼ queued datagrams, ¾ unwritten data) |
| `handshake_rate` / `handshake_burst` | 20/s / 40 | handshakes per client (IPv4 address or IPv6 /64) |
| `handshake_load_threshold` | 200/s | handshakes (all sources) beyond which cookies are required |
| `bind` | `[::]:5555` (receiver), `[::]:0` (sender) | dual-stack; IPv4 where the system has no IPv6 |
| `publish_lan_addresses` | on | publish local-network addresses as candidates |
| `nat_keepalive` | 15 s | initial interval of NAT mapping keepalives (then half the measured lifetime, 5–60 s) |

Fixed limits: 65 536 received ranges per transfer, 65 536 ranges queued by
the sender on the receiver's word, four concurrent address claims per
session (six challenges each, tokens honoured 30 s after giving up), a
handshake answer no longer than the initiation, nothing to an unproven
address beyond what came from it, 65 536 clients in the handshake limiter.

The relay (`sharp-relay`): 4096 registrations and 256 carried pairs, of
which one client may hold 128 and 16 (`--registrations-per-client`,
`--pairs-per-client`); 10 requests per second per client, burst 20;
registration lease 120 s; an idle pair is released after 60 s; address
tokens good for 120–240 s; stamps remembered 240 s after a registration
ends; bound to `[::]:5560`; open to every receiver and sender unless given
lists (`--allow-receiver`, `--allowed-receivers`, `--allow-sender`,
`--allowed-senders`); 100 Mbit/s per client (`--client-rate`), with no
hourly volume, total rate or per-pair volume limit unless set
(`--client-quota`, `--total-rate`, `--pair-bytes`).
