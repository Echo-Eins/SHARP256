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
  answer, and only delivery at that address can return it. A captured
  packet can no longer aim a transfer at a third party. Up to four claims
  are tested side by side, so forged-source copies cannot crowd out the
  peer's real move; challenges back off from the measured round trip, a
  given-up claim's token keeps counting for 30 s (on paths slower than a
  second a rebinding used to be abandoned and retried with a new token for
  ever), and everything sent to an unproven address — challenges and the
  handshake answer alike — is held to three times what it sent (RFC 9000).
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
- The path MTU is taken only from acknowledged PROBEs (RFC 8899): sockets
  run in probe mode, so the kernel ignores ICMP about the path and a forged
  "fragmentation needed" can neither shrink a transfer nor get its control
  messages refused. A real drop shows up as full-size packets lost while
  small ones arrive, and costs one step down; the old size is probed again
  later. EMSGSIZE from the interface is one step per event, not one per
  batch in the pipeline.
- No send error ends a transfer: a network gone for a moment (a Wi-Fi
  hand-over, ENETUNREACH) is waited out by the liveness rules and the resume
  state is kept; segmentation offload is turned off only by an error that
  means the driver cannot segment.
- Connection ids are sealed inside the Noise payloads as well as sent in the
  clear, so a copy raced ahead with a changed id cannot misaddress a
  session; a datagram addressed to a handshake attempt is authenticated
  before the attempt is used up, so junk from anyone on the path no longer
  stops a handshake; no connection id can look like STUN or a relay message.
- Small-order X25519 points are refused as identities everywhere: when an ID
  is parsed, in the handshake in both directions, and by relays.
- The handshake no longer fails on paths slower than its retry interval:
  a single address counts as a complete round, and retries wait at least one
  and a half measured round trips. Send errors never end a handshake, and
  the newest initiation timestamp is kept across runs so that a clock set
  back does not get a sender silently refused.
- Resource bounds that hold whatever peers do: at most 65 536 received
  pieces per transfer (a sender scattering one-byte pieces used to grow the
  receiver's bookkeeping without limit), at most 65 536 pieces queued on the
  receiver's word by the sender, and one `memory_budget` (512 MiB) for data
  not yet on disk across all transfers together — a quarter for queued
  datagrams, the rest shared by the transfers receiving, counted globally.
  The handshake limiter counts an IPv6 /64 as one client and its table is
  bounded; the replay guard never forgets a sender with a transfer in
  progress and never hears of senders refused by the allow-list.
- After a receiver restarts and asks its user again, the sender waits for
  the decision and hears it; a declined transfer is remembered, so the user
  is asked once, not every few seconds for ever. BUSY in the middle of a
  transfer is waited out and keeps the resume state; while the receiver is
  silent, re-handshakes take turns among all its known addresses.
- The session limit is shared rather than first-come-first-served: one
  sender identity may hold only a configured number of concurrent transfers
  (`max_sessions_per_sender`, 8 of 16 by default), so it cannot take every
  slot and lock everybody else out.
- `docs/THREAT_MODEL.md`: adversary classes and what each can achieve, every
  guarantee with the mechanism responsible, explicit non-goals and residual
  risks.

### Secret hygiene
- Every crate that holds a key now wipes it when it is dropped. The
  `zeroize` features of aes, aes-gcm, ghash, polyval, poly1305, chacha20,
  argon2, blake3 and x25519-dalek were off, so the AES round keys of every
  session, the GHASH and Poly1305 keys, the ChaCha20 state of header
  protection and Argon2's memory stayed behind in freed memory. A test
  stops compiling if one of them is switched off again.
- Key derivation and MACs under secret keys — traffic, AEAD and header
  protection keys, cookies, the relay's proofs, tags and tokens, the DHT
  rendezvous key — go through helpers that wipe BLAKE3's hasher afterwards
  and hand keys out in wiping containers; the one-shot calls left the key
  in a stack slot, and the material of each epoch's key was a plain array.
  The keys are the same as before, byte for byte.
- The identity file is read into, and written from, memory that is wiped,
  and the private key's hex is written and read without a branch on its
  digits (`format!("{:02x}")` and `from_str_radix` branch on each one).
- The Noise handshake is our own (`crypto::noise`, with BLAKE2s and its
  HMAC in `crypto::blake2s`) instead of snow's. No version of snow wipes
  anything, so every handshake left a copy of the long-term private key,
  the ephemeral key, the pre-shared key and the chaining key in freed
  memory; here each of them, and every intermediate of HKDF and HMAC, is
  wiped. It writes exactly what snow wrote (the same bytes and keys for the
  same ephemeral keys, over hundreds of random handshakes) and passes the
  Noise test vector for the protocol from cacophony, so peers built before
  talk to it unchanged; snow stays for the tests only. An ephemeral key
  that is a small-order point is now refused, as a static one always was.
- Keys are kept in locked memory (`crypto::secret`): the identity's private
  key, the pre-shared key, the state of every handshake in progress (its
  chaining key and ephemeral key), the secrets of cookies and relay tokens,
  the relay's registration keys, the DHT rendezvous key and a TURN
  server's key lie on pages locked in RAM (`mlock`, `VirtualLock`) and, on
  Linux and FreeBSD, left out of core dumps; they are wiped when the last
  copy goes, and copies of a key are handles to one place rather than
  copies of it. Pages are counted, since locking is per page and keys share
  them. A system that refuses (`RLIMIT_MEMLOCK`) is reported once, with
  how to raise the limit; keys then work as before. None of these types
  prints its contents.
- The passphrase of `--secret` (and `SHARP256_SECRET`), the one typed into
  the sender's window, and a TURN server's password are held in strings
  that are wiped.
- Session keys are in locked memory too: each direction's traffic secret,
  IV, header protection key and the AEADs of its epochs, kept inline in
  one locked allocation instead of boxes on ordinary pages.
- A forged packet no longer makes a key. The epoch of a packet comes from
  its packet number, which an unauthenticated packet only claims, and every
  forged packet used to cost a key derivation for whatever epoch it named
  and push the real epoch's key out of a cache of three. Keys are now kept
  for the newest epoch that has carried an authentic packet and the ones
  on either side of it, and move on only when an authentic packet reaches
  the next; a packet naming any other epoch is opened with the newest key
  and fails like any forgery, in the same time. One up to 16 epochs ahead
  (far beyond anything a sender's window allows) is tried with a key made
  for it alone and kept only if it authenticates. Throughput is unchanged
  (2 GiB over loopback, six runs of each build alternated: 1.88 s against
  1.86 s on average).
- Timing measurements in the manner of dudect (`src/crypto/dudect.rs`,
  `scripts/dudect.sh`, results in `docs/evidence/crypto/`): every MAC and
  tag check, a wrong value differing at its first byte against at a random
  one — `subtle`'s comparison, mac1, mac2, the relay's proofs and tags, the
  AEADs' tags — the rejection of a forged transport packet whatever its
  header unmasks to, and reading the identity file's key; with a control
  (a comparison that stops at the first difference) that the harness must
  and does find. It found one thing: choosing the epoch's key compared the
  unmasked epoch with branches, and a forged packet naming a kept epoch was
  rejected about a cycle sooner than one naming another; the choice is now
  made with constant-time selection, and the difference is gone.

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
  send to are screened first, in canonical form, so clients cannot be used
  as reflectors; PCP's nonce is checked so another request's answer is not
  taken for ours; a plain STUN answer counts only from the server asked.
- UPnP-IGD is spoken by a small client of our own instead of the igd crate:
  a device is believed only on one of our subnets and only about itself,
  every step has a deadline and every answer a size limit. PCP and NAT-PMP
  ask every router candidate from every interface at once, the address
  tests and the port-forward request run side by side, and the address is
  reported as soon as the tests are done. A router behind another NAT is
  recognised and its forward not published.
- Addresses are compared in canonical form and written the way the socket
  sends to them, so dual-stack sockets work with IPv4 peers and relays, and
  candidates a socket cannot reach are skipped.
- `sharp-relay`: a meeting point for the case nothing on either side can
  fix — both peers behind NATs that give out a different port per
  destination, where no address either can publish is the one the other
  would need. It introduces the two so they can punch through directly, and
  allocates a UDP port for the pair when that is not enough. Either end
  names one with `--relay host:port`.
- The relay is trusted with no part of the transfer: it carries sealed
  transport packets, so it cannot read, alter or inject one, and it cannot
  impersonate a peer
  because completing a handshake takes that peer's private key. A receiver
  still admits or refuses a sender by its identity. Registering an identity
  that is not yours therefore buys only a failed handshake; what is guarded
  is registering from a forged source address, which would point the relay's
  traffic at a stranger, so a registration must echo a token derived from
  the address the relay saw. Each side of an allocated port binds itself
  with a ticket, from whatever address its NAT gives it there, and only
  those two addresses are carried.
- Registering an identity with a relay is the owner's to do: the two sides
  already know each other's long-term public keys, so a static
  Diffie-Hellman between them is a secret only those two can compute, and
  the registration carries a MAC under a key derived from it covering the
  whole message. Without it anyone who knew a published ID could register it
  and have senders put through to them. A relay is written `ID@host:port`
  for a receiver; a sender, which claims no identity there, may write the
  address alone.
- A receiver may register as private (`--relay-private`), and the relay then
  tells neither side where the other is — in repeats of the introduction
  too. Such a receiver publishes nothing of its own either (no NAT
  discovery, no port forward, no direct candidates) and is written as its
  ID alone; a sender given that and `--relay` reaches it through the relay.
  It costs the relay's bandwidth and gives up the direct path, and it is
  the only arrangement in which a relay actually hides anyone.
- Relay registrations and goodbyes carry a stamp that must increase per
  identity, remembered after a registration ends, so a captured one cannot
  be sent again; address tokens expire on the clock; an allocated port binds
  a side only once its address answers a confirmation, which rules out
  loops between the relay's own ports; limits count per client (an IPv4
  address or an IPv6 /64) with configurable shares; relay sockets ignore
  ICMP errors and the control loop never stops on receive errors; a
  goodbye with a stale token is asked again. Relay names resolve in the
  background on both sides, the receiver keeps registering through send
  errors, and it waits for its goodbyes on shutdown.
- What a relay does see is stated plainly now (`docs/THREAT_MODEL.md`, Н1
  and Н4б): which identity is registered where, who asks for whom, when and
  how much — and its control messages travel in the clear, so an observer
  on the path sees the same.

### Getting through NAT, in full (laboratory-proven)
Every way through that makes sense for a UDP transfer, checked on the
real kernel's NAT against independent implementations (`docs/NAT.md`,
`scripts/natlab`); what could not be checked is said there too.
- **Find out and hand over.** `sharp-probe` measures what the internet sees
  of this host (address, port, what the NAT does, per family), asks the
  router for a forward, and prints a *contact card* (`shc1-…`, one line, to
  be sent by chat). Given the other side's card it sends at every address on
  it the way a transfer would and says whether a packet got through — no
  file sent. The sender takes the receiver's card in place of an address;
  the receiver takes cards on the command line or pasted into the running
  process. A program says so when a card is more than an hour old.
- **Punching, all of it.** Simultaneous open, learning a peer's port from
  its punch (peer-reflexive), prediction for NATs that count ports up,
  the birthday method for one that draws at random against one that keeps
  its port, IPv6 stateful firewalls, and both address families at once:
  a relay now passes on each peer's address in the *other* family too, so
  two peers whose IPv4 NATs cannot meet get through over IPv6 (9 of 9
  firewall pairs, IPv6-only and dual-stack). What a NAT does is told with the
  address (six bytes, advice not authority) and the plan follows it;
  with no hints (an address from a DHT or a name) the passes go through the
  ways a peer of each harder kind would need. An address that lets in by
  address alone is sent to from one socket.
- **Port forwards, IPv4 and IPv6.** PCP, NAT-PMP and UPnP-IGD (v1 and v2)
  for IPv4; for IPv6 the router's firewall is opened for this host (PCP, and
  IGD2's `AddPinhole`/`UpdatePinhole`/`DeletePinhole`), the gateway found
  from the IPv6 routing table (Linux's `/proc/net/ipv6_route`, and the output
  of `route get` on macOS/BSD and `route print` on Windows; the two are read
  by parsers tested on captured output, not run on those systems here).
- **A carrier's PCP server is asked too.** PCP also goes to its anycast
  address (RFC 7723: `192.0.0.9`, `2001:1::1`), where the nearest PCP server
  on the way out answers, whoever runs it: RFC 6888 (REQ-9) asks a
  carrier-grade NAT to let subscribers map ports and names PCP for it, and
  with DS-Lite (RFC 6333) the home router translates nothing — the carrier's
  AFTR does — so asking the default gateway could never get a forward there.
  NAT-PMP, which has no anycast address, is still asked of the gateway alone.
  The laboratory's `portmap --anycast` puts miniupnpd on a carrier's NAT,
  listening at `192.0.0.9` only, behind a home router that only routes:
  before the change the receiver was granted no forward, after it a sender
  behind any NAT reaches it through one; `portmap6` does the same over IPv6
  (`pcp-anycast`, the router's PCP reachable at `2001:1::1` alone).
- **UPnP pinholes are asked for over IPv6.** The UPnP client used to speak to
  the router over IPv4 only, and miniupnpd — like any router that follows the
  IGD v2 recommendation — lets a host open a pinhole for its own address
  only, judged by the address the request comes from: it answered every
  `AddPinhole` with error 606 ("not authorized", the requester being an IPv4
  address), which the laboratory showed once PCP, the other way in, was
  switched off. The search now also goes to `ff02::c` and `ff05::c` on every
  network with IPv6, an answer is believed only from an address on the network
  it came in on, and the request leaves from the address the pinhole is for.
- **A receiver can be given a bare address.** `sharp-receiver --peer-addr
  IP:PORT` (or the address pasted into the running receiver) starts sending
  there as a card would, for a sender whose side printed only an address; so
  does `sharp-probe --peer-addr`. With no hints about the NAT in front of it
  every way of getting through is tried in turn. `sharp-probe` and
  `sharp-sender --card` print the address (`Addresses:`), the latter for a
  receiver given by address, which used to make the sender say nothing of
  itself.
- **Addresses typed in by hand meet as cards do.** The laboratory's matrix of
  the two people who swap `IP:PORT`s instead of cards (`matrix --via addr`,
  new in CI) came out 27 of 36, the same nine pairs every run, for two
  reasons. A receiver behind a NAT that numbers its ports per destination
  published no outside address at all, so a sender given its `Senders use:`
  line did not know its IP and ignored its punches (only a punch from an IP
  the sender has reason to try is answered): that address now ends the line,
  after everything that can work. And a sender given addresses only sent
  handshakes there; one asked for its own (`--card`) now punches at them the
  way it does at a DHT's — the ways each kind of NAT needs, in turn — and
  waits for the receiver as long as with a card. 36 of 36 now, as the theory
  says (the four pairs of two port-per-destination NATs need a relay).
- **Punching for a meeting stops when it has done its work.** A sender's
  punches at the addresses on a receiver's card went on for five minutes
  after the transfer had ended (in a program that outlives one transfer; the
  command-line sender exits); and on both sides the punching at a peer —
  card, typed address, DHT — went on for those five minutes even with a
  session already running directly to it, sprays of guessed ports included.
  It now stops once a session with that peer runs directly to its host (one
  carried by a relay or a TURN server keeps it going: that is how a direct
  path opens), and a sender's stops with its transfer.
- **A direct path that dies goes back to the server.** A sender whose NAT
  draws ports at random meets its receiver on a socket of its own (the
  birthday method), and moving the session there dropped the socket it had
  started on — the one a relay knows it by and a TURN shim is connected to.
  When the direct path then died, the session had no way back and the
  transfer stopped. The first socket is now kept and read, whatever goes to
  a relay or a TURN server leaves from it, and a session that goes back to
  one goes back to it. The laboratory's new `fallback` scenario cuts the
  direct path in the middle of a transfer, the server still reachable: before
  the change a relayed pair of that kind never came back (nothing delivered
  in 150 s), after it every case is carried by its server again 20–26 s after
  the cut (the stall timeout, then a round of re-handshakes), and delivered.
  A relay keeps an idle pair's port for a minute (`--idle`), so later than
  that only a TURN server is a way back.
- **A direct path is kept while it is heard from.** With a direct path and a
  server's both alive, what came through the server after a move — packets
  sent before it, answers to challenges made then — made an end check the
  server's address, find it alive and move back; the other end followed,
  and the two swapped paths in turn. In the laboratory's virtual machine,
  where the path through coturn is much the slower, 10 of the 18 IPv6 cells
  with a TURN server ended on it with a direct path open both ways. Neither
  end now follows the other to a relay's port, an address on a TURN server
  or a TURN shim while its direct address was heard from in the last three
  seconds; a direct path that stays quiet longer is left as before.
- **Only the relay speaks for the relay.** A peer believed whatever came
  from its relay's address, and the source address of a datagram is anybody's
  to write: a forged `Incoming` had a receiver push datagrams at any address
  it named — with hints claiming a NAT that draws ports at random, a spray of
  2048, which made receivers reflectors with an amplification in the hundreds
  — a forged refusal took a receiver off its relay for ten minutes, and a
  forged `Registered` gave it a made-up address and a shorter keepalive.
  Every request now carries a nonce and every answer a tag: to a receiver, a
  MAC on the key its registration was proven with, over the message and the
  nonce of this run of the receiver; to a sender, the nonce of its request
  given back. What does not carry its tag is ignored. On the previous code a
  test that forges an introduction from the relay's address had the receiver
  send 7 datagrams at a stranger in two seconds; now it sends none, and the
  real introduction works as before. This changes the relay's wire format:
  relays and peers are updated together.
- **A test that failed on a busy machine.**
  `a_sender_cannot_shatter_the_receivers_bookkeeping` read "what the receiver
  holds" as the largest figure acknowledged within half a second, and 0 when
  nothing came: on a CI runner
  busy with the other tests it subtracted 1 from 0 (it failed once, in one of
  two runs of the same commit). Pinned to one core beside three busy loops it
  failed 5 times out of 5. It now waits for the acknowledgement of a marker
  sent after its question — the receiver deals with datagrams in the order
  they arrive — and passes 5 times out of 5 under the same load.
- **What an adversarial review of this round found, fixed.** An address on a
  TURN server was on the lines people copy (`Senders use:`, `Addresses:`),
  and a peer given it punched at it as at a host whose NAT is unknown —
  sprays of guessed ports at somebody else's server; only a card carries one
  now, marked as what it is. A receiver ended its punching at a sender on a
  handshake alone, whose source a copy may have forged; now only once the
  sender has shown it receives there (a transport packet from the
  handshake's address, or an answered challenge). A sender's asking of its
  relays outlived the transfer (bound to the sender, not to the transfer),
  and multicast DNS readers outlived their question. Birthday meetings had
  no bound for the process: four at once used up the 1024 descriptors Linux
  gives a process by default, and one the 256 of macOS, leaving none for the
  file being received; they now share one allowance (half the limit, at most
  two meetings' worth), and a meeting that finds less opens less.
- **Laboratory scenarios that could not fail, can.** `early` did not require
  the sender to have asked again, `timeout` judged the last samples rather
  than those after the receiver adapted, and a transfer counted as "long"
  (long enough to move off a server) by its rate alone, whatever its size.
  A rule a scenario put in the laboratory's core namespace outlived that
  scenario and cut the paths of the next one in the same run. The NAT-PMP
  rows of `portmap` proved PCP: miniupnpd switches the two on together and
  the receiver asks PCP first, so PCP made every one of those forwards (the
  daemon's log says so); PCP is now dropped at the router for them, and
  every row quotes the daemon's line for the request that made its forward.
  A laboratory left the ends of its links in its own namespace until the
  kernel got round to destroying the namespaces of their peers, and the next
  one could try to make links of the same names first: `samenat` failed so
  once ("File exists"), before any transfer. They are deleted on closing.
- **A carrier-grade NAT in front of the home router is a scenario of its
  own** (`cgn`, in CI): two NATs in a row, the outer one keeping ports or
  drawing them at random, on either side. Punching and the birthday method
  work through both (a random carrier makes the pair as hard as a random
  home NAT would, and two of them need the relay, which carries them). The
  laboratory's router behind such a NAT translated to the carrier's address
  where it named one (a NAT that counts ports up); no scenario had used it.
- **Multicast DNS did nothing on a network with only IPv6.** The library that
  lists this host's addresses leaves the link-local IPv6 ones out (on purpose:
  it says so in its source), and the question was asked only on networks with
  a link-local address, so a sender on an IPv6-only network found no sockets
  to ask on and gave up after 35 ms. Found by the laboratory's `lan --v6`, not
  by any test: no unit test asks a real network. Now any IPv6 address means a
  network that does IPv6. The wait after the last question also spun for a
  moment instead of waiting.
- **Finding each other without a server of ours.** Multicast DNS on the local
  network (`--announce-lan`, `--lan`), and the Mainline DHT (`--dht`, BEP 5,
  read-only, on its own socket): both opt-in, and both say what they tell
  whoever listens.
- **Relays, own and other people's.** TURN (RFC 8656, RFC 6156) over UDP:
  `--turn USER:PASSWORD@HOST` (or `SHARP256_TURN`), for the sender, the
  receiver and `sharp-probe`; the engine still speaks plain UDP, each peer
  through a loopback shim. `sharp-relay` also answers as an RFC 5780 STUN
  server. Any number of relays and TURN servers may be given; the first to
  answer wins.
- **A relay is a step, not a destination.** While a session is carried, the
  sender asks the receiver's other addresses with authenticated pings; when
  one answers, address validation moves the session there. That includes a
  meeting made by many sockets (a NAT that draws its ports at random) after
  the handshake: the socket is kept, pinged from, and becomes the session's
  once the receiver has proven the address. Before, such a session stayed on
  the server to the end.
- **A relay is asked as long as it may yet answer.** A sender told that the
  relay has no registration for the receiver — two people starting together,
  a registration being renewed — asks again for up to two minutes; a relay
  that did not answer is asked again for up to a minute. Giving up at the
  first "unknown" lost the introduction for good, which showed in CI as two
  IPv6-only pairs failing in one run and not in the next.
- **`sharp-probe` predicts what a transfer does.** Its test with a peer's
  card meets by many sockets too: it used to report "nothing got through" for
  pairs a transfer connects in a second (a random-port NAT against an
  ordinary one), and told people to look for a relay they did not need. All
  36 pairs of the six NAT kinds are checked (`natlab.py probe --all`).
- **What a program says of its NAT is checked against the NAT.** Behind a
  NAT that lets in only the hosts it was sent to (a "restricted cone":
  endpoint-independent mapping, address-dependent filtering), `sharp-probe`,
  the receiver's `Network:` line and every card said "lets in packets from
  anyone". The mapping tests of RFC 5780 send from the same socket to the
  STUN server's other address, and such a NAT lets that address in from
  then on; asked afterwards to answer from there, the server got through.
  The filtering tests now run on a new socket of the same kind, which has
  sent to nothing but the server's primary address. Transfers were not
  affected (a peer's filtering decides how it is approached only when it has
  no NAT), but the reconnaissance was wrong for one NAT kind in six. The
  laboratory's `probe` now holds each host's report — the address the
  internet sees, mapping, filtering, port numbering, hairpinning — against
  the NAT it built: 60 of 72 reports were right before, 72 of 72 after. The
  unit tests' simulated NAT did not remember what a mapping had sent to and
  could not show it; it does now, per socket.
- **Tests that nobody answered are run again.** A receiver whose first
  round of NAT tests got no answer at all — no STUN server reachable yet: a
  laptop just woken, a link still coming up — kept that for as long as it
  ran: no outside address published, nothing kept alive (so did a sender
  that prints its card or looks in the DHT). The tests now run
  again 5 s later, then twice as long each time up to five minutes, until
  something answers, and what they find is reported as the first round's
  would have been. Found while looking into the next item: the laboratory's
  routers held the first packets through them for a second (duplicate
  address detection of their own link-local addresses, during which Linux
  solicits no neighbour for a packet it forwards), and on CI's fast machines
  an IPv6-only host's `sharp-probe`, which measures IPv6 the moment it
  starts, said "IPv6: not measured" behind every firewall (18 of 36 reports
  wrong; the slow virtual machine, 36 of 36). The laboratory now has DAD
  off everywhere.
- **A forward when the port is taken.** A receiver asks for the outside port
  equal to its own; when somebody else has it, PCP and NAT-PMP servers pick
  another, an IGDv2 router one through `AddAnyPortMapping`, and on an IGDv1
  router the receiver tries a few of its own. All four ran only against a
  simulated router until `portmap --taken` (in CI): miniupnpd with port
  5555 forwarded elsewhere first, 16 of 16 transfers through the port it
  picked. Every `portmap` row now also finds the forward in the router's
  own nftables rules, not only in the daemon's log, whose NAT-PMP line names
  the port asked for rather than the one given.
- **Hairpinning, both ways.** A NAT that loops back what an inside host sends
  to the outside address (RFC 4787 REQ-9) is a case of `samenat` now: the
  two hosts meet at their outside addresses with the relay only introducing,
  and the receiver reports "hairpinning works" (behind the NAT without the
  loop, "no hairpinning"). The laboratory could not show this before: its
  router's bridge, with br_netfilter, put what it only switches through the
  NAT's rules, and a packet looped back to the host it came from went back
  untranslated and was dropped.
- **The laboratory notices a method that is gone.** Two builds of the same
  commit, each with one method switched off by a one-line change: port
  prediction (a window of the named port alone) and the birthday method (no
  extra sockets, no spray). The pairs that need them connect on the commit's
  own binaries and fail on the builds without
  (`docs/evidence/nat/mutation.log`).
- **Reports** name the family a measurement is for; IPv6 gateways are found
  and pinholes reported; the relay answers a question from the address it was
  asked at (it has several on one interface with IPv6).
- **The laboratory** (`scripts/natlab`) runs in network namespaces on the
  host's own kernel or, for IPv6, in a virtual machine: the six NAT kinds of
  RFC 4787 checked by an independent oracle first; matrices of every pair
  through a relay, by cards, through coturn and through a DHT; miniupnpd for
  PCP, NAT-PMP, UPnP and IPv6 pinholes (with a control); a carrier-grade NAT
  in front; two hosts behind one NAT; a NAT that forgets a flow in seconds;
  networks that cannot reach each other at all. CI runs it on every push.
- **Fuzzing** covers what the new code reads: multicast DNS, TURN and STUN
  messages, ChannelData, bencoding and DHT answers, contact cards, relay
  messages.

### Relay access and quotas
- A relay carries traffic on its operator's bandwidth, so the operator
  decides who may use it. `--allow-receiver ID` / `--allowed-receivers FILE`
  limit who may register (refused with the new `Forbidden`, and only after
  the registration's proof has been checked, so the list is not disclosed);
  `--allow-sender ID` / `--allowed-senders FILE` limit whom it puts through.
  Such a relay answers an anonymous `Connect` with `Forbidden`, and a sender
  that was given the relay as `ID@host:port` asks again with the new
  `ConnectAs`, proving its identity with a MAC made as a registration's is.
  A sender never names itself to a relay that does not ask. An open relay
  says so when it starts.
- Quotas: a rate per client (an IPv4 address or an IPv6 /64; 100 Mbit/s by
  default, `--client-rate`), a volume per client per hour
  (`--client-quota`), a total rate (`--total-rate`) and a volume per pair
  (`--pair-bytes`). Metering is all-or-nothing — a datagram refused by one
  limit spends nothing from the others — and the bounded table of clients
  forgets only clients whose allowance has fully recovered, so being pushed
  out of it never refills one. Datagrams over a limit are dropped, and the
  transfer's congestion control slows to what the relay allows (measured:
  8.1 Mbit/s through a relay set to 8 Mbit/s).
- The relay binds `[::]:5560` by default and carries pairs across address
  families; its allocated ports bind the address of its control socket.

### Keeping NAT mappings alive
- A NAT forgets an idle mapping — many within thirty seconds — and the
  receiver's published address then leads nowhere. The mapping behind a
  published address is now refreshed with STUN Binding Indications every
  15 s (RFC 8445 section 11; `--keepalive`) and checked with a request
  every minute. Against an RFC 5780 server the NAT's mapping lifetime is
  measured in the background with RESPONSE-PORT (section 4.6), and the
  interval becomes half of it, between 5 and 60 s. A mapping seen to change
  anyway halves the interval, and the new address is reported at once.
- One policy per socket: relay registrations are refreshed at the same
  interval (not merely within the lease), a relay that reports a new
  address shortens it for everyone, and a relay that stays silent for a
  whole lease is registered with again, on its next address if it has one.
- A shorter interval takes effect at once. Learning that the NAT forgets
  sooner — its mapping's lifetime measured, or a mapping seen to change —
  used to apply only from the refresh after the one already planned by the
  old interval, so the mapping lapsed once more: behind a NAT that forgets in
  eight seconds, the laboratory's `timeout` saw the receiver's flow to its
  relay missing for ten seconds after the receiver had adapted (found once
  that scenario judged the samples after the adaptation rather than the
  last few). The refresh already planned is brought forward, for the relay
  registrations and for the STUN keepalive alike.

### IPv6
- IPv6 and IPv4 by default: receiver, sender and relay bind one dual-stack
  socket (`[::]`, `IPV6_V6ONLY` off) and fall back to IPv4 on the same port
  where the system has no IPv6. An explicit address is bound as given; a
  taken port is an error, never a fallback.
- Name resolution follows Happy Eyeballs v2 (RFC 8305): A and AAAA are asked
  for separately and at once (`getaddrinfo` per family, on Windows too), an
  A answer waits at most 50 ms for AAAA, addresses are sorted by RFC 6724
  (usable destinations, scope, label, precedence) and interleaved by family,
  and a new attempt starts every 250 ms without waiting for the last to
  fail. Names resolve while the handshake already runs on the literal
  candidates; a name with no address and nothing else to try fails at once
  with the resolver's answer.
- NAT64: on an IPv6-only host the prefix is discovered from
  `ipv4only.arpa` (RFC 7050, RFC 6052 prefix lengths, cached five minutes),
  and IPv4 literals and candidates are tried through it as well.
- Addresses are classified by RFC 6890; host candidates follow RFC 8445
  section 5.1.1.1: never loopback or IPv6 link-local, never a deprecated,
  tentative or duplicate IPv6 address, and where temporary addresses
  (RFC 8981) exist, the temporary one stands for its interface and /64
  instead of the stable one. Link-local literals keep their zone
  (`[fe80::1%eth0]:5555`); every other address loses zone and flow label.
- "Don't fragment" for every family on every platform: `IPV6_DONTFRAG` and
  `IPV6_PMTUDISC_PROBE` next to `IP_PMTUDISC_PROBE` on Linux, `IP_DONTFRAG` /
  `IPV6_DONTFRAG` on macOS and the BSDs, `IP_DONTFRAGMENT` / `IPV6_DONTFRAG`
  on Windows. The log says what the system accepted.
- Packets sized for the family: over IPv6 the default chunk starts at 1407
  bytes instead of 1427 (the header is 20 bytes longer), 1407 is also a
  probe candidate and the first step down — which suits PPPoE links too.
- `--no-lan-addresses`: publish only globally routable addresses, so that
  whoever is given the receiver's address learns nothing about the local
  network.

### Fuzzing and CI
- Ten cargo-fuzz targets (`fuzz/`) cover everything read from others:
  transport frames, handshake payloads, whole datagrams, manifests, relay
  messages, STUN, PCP/NAT-PMP, UPnP, addresses and text. Decoded messages
  must survive encoding again. The same entry points (`src/fuzz.rs`) run on
  mutated seeds and on every input that ever crashed one in each
  `cargo test`.
- GitHub Actions: formatting and clippy for every feature set (and for
  FreeBSD), all tests on Linux, macOS and Windows with IPv6 required
  (`SHARP_REQUIRE_IPV6`: an IPv6 test that cannot run fails instead of
  skipping), the minimum Rust version, the network-namespace tests, and a
  minute of fuzzing per target.

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
- Found by fuzzing: ChaCha20 header protection panicked when a packet's
  sample named the keystream block at counter `u32::MAX` — the stream
  cipher refused to go on, and the mask is computed before the AEAD check.
  Anyone who knew a session's connection id (an on-path observer, a relay)
  could take that side of the session down with one packet; one's own
  packets did it once in 2^32. The block is now computed directly.
  Checked against the RFC 9001 appendix A.5 vector.
- Found by fuzzing: a damaged resume-state file with non-ASCII bytes where a
  transfer id belongs panicked the parser.
- Found by the first CI run on Windows: Windows answers `IPV6_V6ONLY` with a
  single byte where socket2 reads an `int`. Debug builds hit socket2's
  assertion on every socket; release builds read three bytes nobody wrote,
  so whether the default `[::]` socket counted as dual-stack — and so
  whether it reached IPv4 peers at all, and set "don't fragment" for them —
  depended on stale memory. The option is now read into a zeroed buffer of
  our own on Windows.
- "Never replaces anything" was a free name chosen and then a plain rename:
  a file another process created under that name in between would have been
  replaced (and on POSIX an empty directory too). The move is now refused
  by the system itself when the name is taken — `renameat2` with
  `RENAME_NOREPLACE` on Linux, `renamex_np` with `RENAME_EXCL` on macOS,
  `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` on Windows, a hard link
  elsewhere — and the next free name is tried.
- Found by the first end-to-end run on Windows: a socket bound to an explicit
  IPv6 address (`[::1]`, say) had `IPV6_V6ONLY` switched off, which such a
  socket cannot use anyway; quinn-udp then set IPv4 options on it, and
  Windows refused them — every IPv6 transfer from or to an explicit IPv6
  address failed with WSAEINVAL. An explicit IPv6 address is now bound
  IPv6-only (a mapped IPv4 one still not), and only a wildcard counts as
  dual-stack.
- Also found on Windows: a directory being sent was described from the
  copies of its entries' metadata in the directory listing, which NTFS
  updates lazily — a directory's modification time went out stale, and a
  file's size could have. Each entry's own metadata is read now.
- The test that scatters one-byte pieces over a file measured the receiver
  from acknowledgements that could be stale (its last ones lost in a full
  socket buffer, as on macOS), and with datagrams dropped on the way the
  receiver might not reach its limit at all. It now asks afresh after each
  step, sends twice the limit, and checks that a piece joining nothing is
  refused at the limit — not only that joining data is taken.
- The test that both sides settle on the newest handshake ran its session
  over a path with a 400 or 700 ms round trip under the usual 800 ms test
  stall timeout, so a busy CI runner could read a slow pause as a lost
  session. It now allows 3 s; a session really lost stalls however long
  the timeout, so the test still catches what it is for.
- The README claimed "10 GbE and beyond"; it now gives the measured figure
  (4.6–5.0 Gbit/s over loopback on one 4-core VM, re-measured on this
  release's code: seven runs of ten; the other three 3.0–3.6 Gbit/s, with
  both the default and an IPv4-only bind) and says that no real 10 GbE
  network was measured.
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
