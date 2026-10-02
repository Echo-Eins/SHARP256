# Test vectors

Known-answer vectors for every key derivation and every format of
SHARP-256, versions 3 and 4 ([PROTOCOL.md](../PROTOCOL.md)). An
implementation that computes all of them byte for byte speaks the protocol;
one that differs anywhere does not.

| file | what | PROTOCOL.md |
|------|------|-------------|
| `ids.json` | the text forms of an ID: `sh-` (version 3) and `sh4-` (version 4), with their checksums | 1 |
| `psk.json` | the pre-shared key from a passphrase (Argon2id); the first case at the protocol's own cost | 1 |
| `identity_file.json` | an identity file's key line sealed with a passphrase, and the cost new files are sealed with | 1 |
| `mac_keys.json` | the keys of `mac1` (both versions), of the cookie reply, and of `mac2` | 2 |
| `cookie_reply.json` | a cookie reply, sealed to the `mac1` it answers | 2, admission control |
| `handshake_v3.json` | whole version 3 handshakes, without and with a PSK and a cookie | 2 |
| `handshake_v4.json` | whole version 4 (hybrid, ML-KEM-768) handshakes, message 1 in fragments | 2, version 4 |
| `traffic.json` | a direction's traffic secret, IV, header protection key, AEAD keys of epochs | 2, traffic keys |
| `packets.json` | transport packets of both suites, across epochs and lengths | 3 |
| `frames.json` | every frame body and type byte; the handshake payloads of both versions (a padded one too) | 4; 2, handshake payloads |
| `manifest.json` | a directory's manifest, entry by entry, and its hash | 6 |
| `relay.json` | every relay message, with registration keys, proofs and tags | 8 |
| `cards.json` | contact cards: body and text form | 8, contact cards |
| `dht.json` | the DHT's rendezvous key and infohashes, without and with a secret | 8, the DHT |
| `carriers.json` | stream preambles and frames, and the binding of TLS to a relay | 8, carriers |

Every byte string is lower-case hex; connection ids are the 8 bytes of
their big-endian encoding; addresses are written as `IP:PORT`. A
handshake case gives every value that would be random — static and ephemeral keys, ML-KEM's seed `d || z` and the `m` of
its encapsulation (FIPS 203's `KeyGen_internal` and `Encaps_internal`), the
connection ids — and everything that follows from them: both Noise
messages, the datagrams on the wire, the split and the handshake hash, the
traffic secrets, and the first transport packet each way. The intermediate
values (`noise_message_*`, `kem_*`) are there to find where a mismatch
begins.

## Where they come from

`scripts/vectors` computes them: a second implementation of what these
sections specify, in Go, sharing no code with the crate — its own BLAKE3
(checked against the official BLAKE3 test vectors) and Noise (checked
against cacophony's vector for `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`), Go's
X25519, AES-GCM and ML-KEM, and `golang.org/x/crypto`'s ChaCha20-Poly1305,
XChaCha20-Poly1305, BLAKE2s and Argon2id; the encodings written out by
hand from the tables of the specification. Its inputs are BLAKE3 output of
a label (`"sharp256 test vectors: " + label`), so anyone can make them again.

```
cd scripts/vectors
go test ./...        # BLAKE3 and Noise against third parties' vectors
go run .             # these files are what it computes (exit 1 otherwise)
go run . -write ../../docs/vectors
```

The crate checks its own code against the same files
(`src/vectors.rs`, every random value given through test-only hooks;
every message built field by field, encoded and decoded), and CI runs
both. A value here has then been computed twice, by implementations that
share nothing but the specification. What the crate's
own tests cannot see — both of its ends wrong the same way, which
interoperates perfectly — they see here: before these vectors, a constant
AEAD nonce or a constant `mac1` key passed every test of the crate.

## What is not here

What other specifications define and this protocol only uses: STUN, TURN,
PCP and NAT-PMP, mDNS, the DHT's own messages (BEP 5), TLS itself (the
exported key of a binding is given, not made). And what never leaves a
machine: resume state, lists of IDs.
