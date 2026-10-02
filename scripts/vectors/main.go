// Command vectors computes SHARP-256's test vectors from PROTOCOL.md, apart
// from the protocol's own code, and checks the ones in docs/vectors against
// them:
//
//	go run .                       # check docs/vectors (exit 1 on any difference)
//	go run . -write ../../docs/vectors
//
// The crate checks its own code against the same files
// (src/crypto/vectors.rs). A value both compute alike was computed twice,
// by two implementations that share no code; one the crate's own tests
// could not see — the crate agreeing with itself whatever its nonces or MAC
// keys — has to come out right here as well.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Every input that would be random: bytes from BLAKE3's output for a label,
// so anyone can make them again.
func det(label string, n int) []byte {
	return Blake3([]byte("sharp256 test vectors: "+label), n)
}

func detCID(label string) uint64 {
	for i := 0; ; i++ {
		c := binary.BigEndian.Uint64(det(fmt.Sprintf("%s %d", label, i), 8))
		// Zero, the relay magic and a STUN magic cookie in the second four
		// bytes are never chosen (PROTOCOL.md section 2).
		if c != 0 && c != binary.BigEndian.Uint64([]byte("SHRELAY1")) && uint32(c) != 0x2112A442 {
			return c
		}
	}
}

type file struct {
	Description string `json:"description"`
	Cases       any    `json:"cases"`
}

// A file whose cases come with defaults the protocol sets.
type fileWithDefaults struct {
	Description string `json:"description"`
	Defaults    any    `json:"defaults"`
	Cases       any    `json:"cases"`
}

// --- IDs, PSK, identity file ------------------------------------------------

type idCase struct {
	PublicKey string `json:"public_key"`
	IDv3      string `json:"id_v3"`
	IDv4      string `json:"id_v4"`
}

func ids() file {
	var cases []idCase
	for _, label := range []string{"id 1", "id 2", "id 3"} {
		public := x25519Public(det(label, 32))
		cases = append(cases, idCase{hx(public), sharpID(public, false), sharpID(public, true)})
	}
	return file{"SHARP IDs (PROTOCOL.md section 1): the public key and its text forms, version 3 (sh-) and version 4 (sh4-).", cases}
}

type pskCase struct {
	Passphrase     string `json:"passphrase"`
	ReceiverPublic string `json:"receiver_public_key"`
	MemoryKiB      uint32 `json:"memory_kib"`
	Passes         uint32 `json:"passes"`
	Lanes          uint8  `json:"lanes"`
	PSK            string `json:"psk"`
}

func psks() file {
	receiver := x25519Public(det("psk receiver", 32))
	var cases []pskCase
	for _, c := range []struct {
		pass        string
		mem, passes uint32
	}{
		{"correct horse battery staple", 64 * 1024, 3}, // the protocol's cost
		{"correct horse battery staple", 8, 1},
		{"пароль с пробелами и ё", 8, 1},
	} {
		cases = append(cases, pskCase{c.pass, hx(receiver), c.mem, c.passes, 1,
			hx(psk(c.pass, receiver, c.mem, c.passes, 1))})
	}
	return file{"Pre-shared keys from a shared passphrase (PROTOCOL.md section 1): Argon2id, salt \"sharp256 v3 psk \" || receiver public key, 32 bytes. The first case is the protocol's cost (64 MiB, 3 passes, 1 lane); the others are cheap, to check the construction quickly.", cases}
}

type identityCase struct {
	SecretKey      string `json:"secret_key"`
	PublicKey      string `json:"public_key"`
	Passphrase     string `json:"passphrase"`
	MemoryKiB      uint32 `json:"memory_kib"`
	Passes         uint32 `json:"passes"`
	Lanes          uint8  `json:"lanes"`
	Salt           string `json:"salt"`
	Nonce          string `json:"nonce"`
	AssociatedData string `json:"associated_data"`
	Line           string `json:"line"`
}

func identityFiles() fileWithDefaults {
	secret := det("identity secret", 32)
	salt, nonce := det("identity salt", 16), det("identity nonce", 24)
	pass := "a passphrase"
	var mem, passes uint32 = 64, 1
	line, ad := identityLine(secret, pass, mem, passes, 1, salt, nonce)
	return fileWithDefaults{
		Description: "The key line of an identity file sealed with a passphrase (PROTOCOL.md section 1): XChaCha20-Poly1305 under Argon2id(passphrase, salt) with the parameters on the line, the fields before the nonce joined by single spaces as associated data. The case is cheap — the line says what it costs; defaults is the cost a new file is sealed with.",
		Defaults:    map[string]uint32{"memory_kib": 256 * 1024, "passes": 3, "lanes": 1},
		Cases:       []identityCase{{hx(secret), hx(x25519Public(secret)), pass, mem, passes, 1, hx(salt), hx(nonce), ad, line}},
	}
}

// --- MAC keys and cookies ---------------------------------------------------

type macKeyCase struct {
	PublicKey string `json:"public_key"`
	Mac1KeyV3 string `json:"mac1_key_v3"`
	Mac1KeyV4 string `json:"mac1_key_v4"`
	CookieKey string `json:"cookie_key"`
}

type mac2Case struct {
	Cookie  string `json:"cookie"`
	Mac2Key string `json:"mac2_key"`
}

func macKeys() file {
	var keys []macKeyCase
	for _, label := range []string{"mac key 1", "mac key 2"} {
		p := x25519Public(det(label, 32))
		keys = append(keys, macKeyCase{hx(p), hx(mac1Key(p, false)), hx(mac1Key(p, true)), hx(cookieKey(p))})
	}
	c := det("cookie", macLen)
	return file{"MAC keys (PROTOCOL.md section 2): mac1's of a public key for versions 3 and 4, the cookie key of a receiver, and mac2's of a cookie. A MAC is BLAKE3-keyed(key, data)[0..16].",
		map[string]any{"public_keys": keys, "cookies": []mac2Case{{hx(c), hx(mac2Key(c))}}}}
}

type cookieReplyCase struct {
	ReceiverPublic string `json:"receiver_public_key"`
	SenderCID      string `json:"sender_cid"`
	Mac1           string `json:"mac1"`
	Nonce          string `json:"nonce"`
	Cookie         string `json:"cookie"`
	Reply          string `json:"reply"`
}

func cookieReplies() file {
	p := x25519Public(det("cookie receiver", 32))
	cid := detCID("cookie sender cid")
	mac1, nonce, cookie := det("cookie mac1", macLen), det("cookie nonce", 24), det("cookie value", macLen)
	return file{"A cookie reply (PROTOCOL.md section 2, admission control): sender_cid | nonce | the cookie sealed with XChaCha20-Poly1305 under the receiver's cookie key, the answered datagram's mac1 as associated data | tag.",
		[]cookieReplyCase{{hx(p), fmt.Sprintf("%016x", cid), hx(mac1), hx(nonce), hx(cookie), hx(cookieReply(cid, p, nonce, cookie, mac1))}}}
}

// --- Traffic keys and packets -----------------------------------------------

type epochKey struct {
	Epoch uint64 `json:"epoch"`
	Key   string `json:"key"`
}

type trafficCase struct {
	K        string     `json:"split_key"`
	H        string     `json:"handshake_hash"`
	Secret   string     `json:"traffic_secret"`
	IV       string     `json:"iv"`
	HP       string     `json:"header_protection_key"`
	AEADKeys []epochKey `json:"aead_keys"`
}

func traffic() file {
	k, h := det("traffic split key", 32), det("traffic hash", 32)
	s := trafficSecret(k, h)
	d := newDirection(s)
	c := trafficCase{K: hx(k), H: hx(h), Secret: hx(s), IV: hx(d.iv), HP: hx(d.hp)}
	for _, e := range []uint64{0, 1, 2, 255, 1 << 20, 1<<42 - 1} {
		c.AEADKeys = append(c.AEADKeys, epochKey{e, hx(d.key(e))})
	}
	return file{"Traffic keys (PROTOCOL.md section 2, traffic keys): a direction's secret from a split key and the handshake hash, its IV, its header protection key, and the AEAD key of epochs (2^22 packets each).", []trafficCase{c}}
}

type packetCase struct {
	Suite  string `json:"suite"`
	Secret string `json:"traffic_secret"`
	DCID   string `json:"dcid"`
	Type   uint8  `json:"type"`
	PN     uint64 `json:"packet_number"`
	Body   string `json:"body"`
	Packet string `json:"packet"`
}

func packetOf(suite string, d direction, dcid uint64, t byte, pn uint64, body []byte) packetCase {
	return packetCase{suite, hx(d.secret), fmt.Sprintf("%016x", dcid), t, pn, hx(body), hx(d.seal(suite, dcid, t, pn, body))}
}

func packets() file {
	var cases []packetCase
	for _, suite := range []string{"AES-256-GCM", "ChaCha20-Poly1305"} {
		d := newDirection(det("packet secret "+suite, 32))
		dcid := detCID("packet dcid " + suite)
		for i, c := range []struct {
			t   byte
			pn  uint64
			len int
		}{
			{0x01, 0, 60},           // the first packet
			{0x03, 1, 1400},         // a DATA packet of the usual size
			{0x04, 255, 0},          // an empty body
			{0x13, 1<<22 - 1, 37},   // the last of epoch 0, a flag bit set
			{0x03, 1 << 22, 37},     // the first of epoch 1
			{0x05, 5<<22 + 7, 9},    // further on
			{0x0b, 1<<40 + 17, 120}, // a long session
		} {
			body := det(fmt.Sprintf("packet body %s %d", suite, i), c.len)
			cases = append(cases, packetOf(suite, d, dcid, c.t, c.pn, body))
		}
	}
	return file{"Transport packets (PROTOCOL.md section 3): the header dcid | type | packet number, the body sealed with the epoch's AEAD key, nonce iv XOR (0^4 || pn), the unmasked header as associated data, and type and packet number masked from the tag. Each suite.", cases}
}

// --- Handshakes -------------------------------------------------------------

type transport struct {
	DCID   string `json:"dcid"`
	Type   uint8  `json:"type"`
	PN     uint64 `json:"packet_number"`
	Body   string `json:"body"`
	Packet string `json:"packet"`
}

type handshakeCase struct {
	Name               string    `json:"name"`
	Prologue           string    `json:"prologue"`
	InitiatorStatic    string    `json:"initiator_static_secret"`
	ResponderStatic    string    `json:"responder_static_secret"`
	InitiatorPublic    string    `json:"initiator_static_public"`
	ResponderPublic    string    `json:"responder_static_public"`
	PSK                string    `json:"psk"`
	InitiatorEphemeral string    `json:"initiator_ephemeral_secret"`
	ResponderEphemeral string    `json:"responder_ephemeral_secret"`
	KEMSeed            string    `json:"kem_seed,omitempty"`
	KEMRandom          string    `json:"kem_encapsulation_random,omitempty"`
	SenderCID          string    `json:"sender_cid"`
	ReceiverCID        string    `json:"receiver_cid"`
	Cookie             string    `json:"cookie,omitempty"`
	InitiationPayload  string    `json:"initiation_payload"`
	ResponsePayload    string    `json:"response_payload"`
	KEMPublic          string    `json:"kem_encapsulation_key,omitempty"`
	KEMCiphertext      string    `json:"kem_ciphertext,omitempty"`
	KEMShared          string    `json:"kem_shared_secret,omitempty"`
	Message1           string    `json:"noise_message_1"`
	Message2           string    `json:"noise_message_2"`
	Initiation         []string  `json:"initiation_datagrams"`
	Response           string    `json:"response_datagram"`
	HandshakeHash      string    `json:"handshake_hash"`
	SplitI2R           string    `json:"split_initiator_to_responder"`
	SplitR2I           string    `json:"split_responder_to_initiator"`
	SecretI2R          string    `json:"traffic_secret_initiator_to_responder"`
	SecretR2I          string    `json:"traffic_secret_responder_to_initiator"`
	Suite              string    `json:"suite"`
	PacketI2R          transport `json:"first_packet_initiator_to_responder"`
	PacketR2I          transport `json:"first_packet_responder_to_initiator"`
}

func handshakeCaseOf(name string, hybrid bool, withPSK bool, cookie []byte, suite string, payload1, payload2 []byte) handshakeCase {
	in := handshakeInputs{
		hybrid:             hybrid,
		prologue:           []byte("SHARP-256 v3"),
		initiatorStatic:    det(name+" initiator static", 32),
		responderStatic:    det(name+" responder static", 32),
		initiatorEphemeral: det(name+" initiator ephemeral", 32),
		responderEphemeral: det(name+" responder ephemeral", 32),
		psk:                make([]byte, 32),
	}
	if hybrid {
		in.prologue = []byte("SHARP-256 v4")
		in.kemSeed = det(name+" kem seed", 64)
		in.kemRandom = det(name+" kem random", 32)
	}
	if withPSK {
		in.psk = det(name+" psk", 32)
	}
	scid, rcid := detCID(name+" sender cid"), detCID(name+" receiver cid")
	// Each side's connection id is sealed as the first eight bytes of its
	// Noise payload (PROTOCOL.md section 2).
	in.payload1 = append(be64(scid), payload1...)
	in.payload2 = append(be64(rcid), payload2...)
	out, err := runHandshake(in)
	if err != nil {
		panic(name + ": " + err.Error())
	}
	is, rs := x25519Public(in.initiatorStatic), x25519Public(in.responderStatic)
	var datagrams [][]byte
	var response []byte
	if hybrid {
		datagrams = fragmentsV4(scid, out.msg1, rs, cookie)
		response = responseV4(scid, out.msg2, is)
	} else {
		datagrams = [][]byte{initiationV3(scid, out.msg1, rs, cookie)}
		response = responseV3(scid, rcid, out.msg2, is)
	}
	for _, d := range datagrams {
		if len(d) > maxControl {
			panic(name + ": a datagram over 1200 bytes")
		}
	}
	si2r, sr2i := trafficSecret(out.i2r, out.h), trafficSecret(out.r2i, out.h)
	first := func(d direction, dcid uint64, t byte, label string) transport {
		body := det(name+" "+label, 48)
		return transport{fmt.Sprintf("%016x", dcid), t, 0, hx(body), hx(d.seal(suite, dcid, t, 0, body))}
	}
	c := handshakeCase{
		Name: name, Prologue: string(in.prologue),
		InitiatorStatic: hx(in.initiatorStatic), ResponderStatic: hx(in.responderStatic),
		InitiatorPublic: hx(is), ResponderPublic: hx(rs), PSK: hx(in.psk),
		InitiatorEphemeral: hx(in.initiatorEphemeral), ResponderEphemeral: hx(in.responderEphemeral),
		SenderCID: fmt.Sprintf("%016x", scid), ReceiverCID: fmt.Sprintf("%016x", rcid),
		InitiationPayload: hx(payload1), ResponsePayload: hx(payload2),
		Message1: hx(out.msg1), Message2: hx(out.msg2), Response: hx(response),
		HandshakeHash: hx(out.h), SplitI2R: hx(out.i2r), SplitR2I: hx(out.r2i),
		SecretI2R: hx(si2r), SecretR2I: hx(sr2i), Suite: suite,
		// The sender's packets go to the receiver's connection id, and the
		// receiver's to the sender's.
		PacketI2R: first(newDirection(si2r), rcid, 0x01, "first packet i2r"),
		PacketR2I: first(newDirection(sr2i), scid, 0x02, "first packet r2i"),
	}
	if cookie != nil {
		c.Cookie = hx(cookie)
	}
	if hybrid {
		c.KEMSeed, c.KEMRandom = hx(in.kemSeed), hx(in.kemRandom)
		c.KEMPublic, c.KEMCiphertext, c.KEMShared = hx(out.kemPublic), hx(out.kemCipher), hx(out.kemShared)
	}
	for _, d := range datagrams {
		c.Initiation = append(c.Initiation, hx(d))
	}
	return c
}

func handshakesV3() file {
	return file{"Version 3 handshakes (PROTOCOL.md section 2): Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s with the prologue \"SHARP-256 v3\", every random value given; the initiation and response datagrams, the split and the handshake hash, the traffic secrets, and the first transport packet each way under them.",
		[]handshakeCase{
			handshakeCaseOf("v3 plain", false, false, nil, "ChaCha20-Poly1305", det("v3 plain payload 1", 63), det("v3 plain payload 2", 41)),
			handshakeCaseOf("v3 psk cookie", false, true, det("v3 cookie", macLen), "AES-256-GCM", det("v3 psk payload 1", 63), det("v3 psk payload 2", 41)),
		}}
}

func handshakesV4() file {
	return file{"Version 4 handshakes (PROTOCOL.md section 2, version 4): Noise_IKpsk2+hfs_25519+MLKEM768_ChaChaPoly_BLAKE2s with the prologue \"SHARP-256 v4\". kem_seed is d || z of FIPS 203's ML-KEM.KeyGen_internal, kem_encapsulation_random the m of Encaps_internal. Message 1 goes in fragments.",
		[]handshakeCase{
			handshakeCaseOf("v4 plain", true, false, nil, "ChaCha20-Poly1305", det("v4 plain payload 1", 10), det("v4 plain payload 2", 2)),
			handshakeCaseOf("v4 psk cookie", true, true, det("v4 cookie", macLen), "AES-256-GCM", det("v4 psk payload 1", 10), det("v4 psk payload 2", 2)),
		}}
}

// ---------------------------------------------------------------------------

func all() map[string]any {
	return map[string]any{
		"ids.json":           ids(),
		"psk.json":           psks(),
		"identity_file.json": identityFiles(),
		"mac_keys.json":      macKeys(),
		"cookie_reply.json":  cookieReplies(),
		"traffic.json":       traffic(),
		"packets.json":       packets(),
		"handshake_v3.json":  handshakesV3(),
		"handshake_v4.json":  handshakesV4(),
	}
}

func encode(f any) []byte {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func main() {
	write := flag.String("write", "", "write the vectors to this directory")
	check := flag.String("check", "../../docs/vectors", "check the vectors in this directory")
	flag.Parse()
	files := all()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	if *write != "" {
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(*write, n), encode(files[n]), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		fmt.Printf("%d files written to %s\n", len(names), *write)
		return
	}
	bad := 0
	for _, n := range names {
		have, err := os.ReadFile(filepath.Join(*check, n))
		if err != nil {
			fmt.Printf("%s: %v\n", n, err)
			bad++
			continue
		}
		if !bytes.Equal(have, encode(files[n])) {
			fmt.Printf("%s: differs from what this implementation of PROTOCOL.md computes\n", n)
			bad++
			continue
		}
		fmt.Printf("%s: as computed\n", n)
	}
	if bad > 0 {
		os.Exit(1)
	}
}
