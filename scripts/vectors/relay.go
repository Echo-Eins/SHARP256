package main

// PROTOCOL.md section 8: the relay's control messages and their proofs and
// tags, contact cards, the DHT's rendezvous keys, and the framing of
// carriers other than UDP with the binding of TLS to a relay.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// --- Addresses and hints -----------------------------------------------------

// family:u8 (4|6) port:u16 ip[4|16]
func encAddr(a netip.AddrPort) []byte {
	ip := a.Addr()
	out := []byte{6}
	if ip.Is4() {
		out[0] = 4
	}
	out = binary.BigEndian.AppendUint16(out, a.Port())
	return append(out, ip.AsSlice()...)
}

// What a NAT does, as the six bytes hints carry: mapping, filtering,
// allocation, a signed step, and hairpinning (bits 0–1) and a carrier-grade
// NAT (bit 2).
type nat struct {
	mapping, filtering, allocation byte
	delta                          int16
	hairpin                        byte // 0 unknown, 1 no, 2 yes
	cgn                            bool
}

func (n nat) bytes() []byte {
	f := n.hairpin
	if n.cgn {
		f |= 4
	}
	out := []byte{n.mapping, n.filtering, n.allocation}
	out = binary.BigEndian.AppendUint16(out, uint16(n.delta))
	return append(out, f)
}

type alt struct {
	addr netip.AddrPort
	nat  nat
}

type hints struct {
	nat nat
	alt *alt
}

// nat[6] alt, alt being 0 or addr nat[6].
func (h hints) bytes() []byte {
	out := h.nat.bytes()
	if h.alt == nil {
		return append(out, 0)
	}
	return append(append(out, encAddr(h.alt.addr)...), h.alt.nat.bytes()...)
}

type altJSON struct {
	Addr string `json:"addr"`
	NAT  string `json:"nat"`
}

type hintsJSON struct {
	NAT string   `json:"nat"`
	Alt *altJSON `json:"alt"`
}

func (h hints) json() *hintsJSON {
	j := &hintsJSON{NAT: hx(h.nat.bytes())}
	if h.alt != nil {
		j.Alt = &altJSON{h.alt.addr.String(), hx(h.alt.nat.bytes())}
	}
	return j
}

// --- The relay's messages ----------------------------------------------------

var relayMagic = []byte("SHRELAY1")

func relayMsg(kind byte, parts ...[]byte) []byte {
	out := append(append([]byte(nil), relayMagic...), kind)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// K = BLAKE3-derive_key("sharp256 relay v1 registration",
// DH(peer, relay) || peer_id || relay_id), the peer being the receiver or
// the sender proving itself.
func registrationKey(peerSecret, relayPublic []byte) []byte {
	peer := x25519Public(peerSecret)
	material := append(append(x25519(peerSecret, relayPublic), peer...), relayPublic...)
	return Blake3DeriveKey("sharp256 relay v1 registration", material, 32)
}

// A proof closes a message: BLAKE3-keyed(K, message up to it)[0..16].
func withProof(k, msg []byte) []byte { return append(msg, blakeMAC(k, msg)...) }

// A tag to a registered receiver: BLAKE3-keyed(K', nonce || message up to
// it)[0..16], K' = BLAKE3-derive_key("sharp256 relay v1 relay to peer", K).
func withRelayTag(k, nonce, msg []byte) []byte {
	own := Blake3DeriveKey("sharp256 relay v1 relay to peer", k, 32)
	return append(msg, Blake3Keyed(own, append(append([]byte(nil), nonce...), msg...), macLen)...)
}

// Every field of a message that has one, in hex or as written.
type relayCase struct {
	Name     string     `json:"name"`
	Kind     byte       `json:"kind"`
	ID       string     `json:"id,omitempty"`
	Target   string     `json:"target,omitempty"`
	Token    string     `json:"token,omitempty"`
	Flags    *byte      `json:"flags,omitempty"`
	Stamp    *uint64    `json:"stamp,omitempty"`
	Hints    *hintsJSON `json:"hints,omitempty"`
	Nonce    string     `json:"nonce,omitempty"`
	Lease    *uint32    `json:"lease,omitempty"`
	Observed string     `json:"observed,omitempty"`
	Port     *uint16    `json:"port,omitempty"`
	Peer     string     `json:"peer,omitempty"`
	Ticket   string     `json:"ticket,omitempty"`
	Code     *byte      `json:"code,omitempty"`
	Proof    string     `json:"proof,omitempty"`
	Tag      string     `json:"tag,omitempty"`
	TaggedBy string     `json:"tagged_by,omitempty"` // "relay key" or "nonce"
	Message  string     `json:"message"`
}

type relayFile struct {
	Description    string      `json:"description"`
	ReceiverSecret string      `json:"receiver_static_secret"`
	SenderSecret   string      `json:"sender_static_secret"`
	RelaySecret    string      `json:"relay_static_secret"`
	ReceiverKey    string      `json:"registration_key_receiver"`
	SenderKey      string      `json:"registration_key_sender"`
	ReceiverNonce  string      `json:"receiver_nonce"`
	SenderNonce    string      `json:"sender_nonce"`
	Messages       []relayCase `json:"cases"`
}

func ptr[T any](v T) *T { return &v }

func relayMessages() relayFile {
	rs, ss, ls := det("relay receiver", 32), det("relay sender", 32), det("relay itself", 32)
	rp, sp, lp := x25519Public(rs), x25519Public(ss), x25519Public(ls)
	kr, ks := registrationKey(rs, lp), registrationKey(ss, lp)
	rnonce, snonce := det("relay receiver nonce", 16), det("relay sender nonce", 16)
	token, ticketR, ticketS := det("relay token", 16), det("relay ticket receiver", 16), det("relay ticket sender", 16)
	recvHints := hints{
		nat: nat{mapping: 1, filtering: 3, allocation: 1, hairpin: 2},
		alt: &alt{netip.MustParseAddrPort("[2001:db8:7::5]:40400"), nat{mapping: 4, filtering: 3}},
	}
	sendHints := hints{nat: nat{mapping: 3, filtering: 3, allocation: 2, delta: -2, hairpin: 1, cgn: true}}
	none := hints{}
	recvAddr := netip.MustParseAddrPort("203.0.113.7:5555")
	sendAddr := netip.MustParseAddrPort("198.51.100.20:61001")
	var out []relayCase

	stamp := uint64(1_790_000_000_123_456_789)
	reg := relayMsg(1, rp, token, []byte{0}, binary.BigEndian.AppendUint64(nil, stamp), recvHints.bytes(), rnonce)
	reg = withProof(kr, reg)
	out = append(out, relayCase{Name: "register", Kind: 1, ID: hx(rp), Token: hx(token), Flags: ptr(byte(0)),
		Stamp: ptr(stamp), Hints: recvHints.json(), Nonce: hx(rnonce), Proof: hx(reg[len(reg)-16:]), Message: hx(reg)})

	regp := withProof(kr, relayMsg(1, rp, token, []byte{1}, binary.BigEndian.AppendUint64(nil, stamp+1), none.bytes(), rnonce))
	out = append(out, relayCase{Name: "register as private", Kind: 1, ID: hx(rp), Token: hx(token), Flags: ptr(byte(1)),
		Stamp: ptr(stamp + 1), Hints: none.json(), Nonce: hx(rnonce), Proof: hx(regp[len(regp)-16:]), Message: hx(regp)})

	ch := relayMsg(2, token, rnonce)
	out = append(out, relayCase{Name: "challenge", Kind: 2, Token: hx(token), Tag: hx(rnonce), TaggedBy: "nonce", Message: hx(ch)})

	regd := withRelayTag(kr, rnonce, relayMsg(3, be32(120), encAddr(recvAddr)))
	out = append(out, relayCase{Name: "registered", Kind: 3, Lease: ptr(uint32(120)), Observed: recvAddr.String(),
		Tag: hx(regd[len(regd)-16:]), TaggedBy: "relay key", Message: hx(regd)})

	conn := relayMsg(4, rp, token, sendHints.bytes(), snonce)
	out = append(out, relayCase{Name: "connect", Kind: 4, Target: hx(rp), Token: hx(token), Hints: sendHints.json(),
		Nonce: hx(snonce), Message: hx(conn)})

	alloc := relayMsg(5, be16(40001), encAddr(recvAddr), ticketS, recvHints.bytes(), snonce)
	out = append(out, relayCase{Name: "allocated", Kind: 5, Port: ptr(uint16(40001)), Peer: recvAddr.String(),
		Ticket: hx(ticketS), Hints: recvHints.json(), Tag: hx(snonce), TaggedBy: "nonce", Message: hx(alloc)})

	inc := withRelayTag(kr, rnonce, relayMsg(6, be16(40001), encAddr(sendAddr), ticketR, sendHints.bytes()))
	out = append(out, relayCase{Name: "incoming", Kind: 6, Port: ptr(uint16(40001)), Peer: sendAddr.String(),
		Ticket: hx(ticketR), Hints: sendHints.json(), Tag: hx(inc[len(inc)-16:]), TaggedBy: "relay key", Message: hx(inc)})

	stale := withRelayTag(kr, rnonce, relayMsg(7, []byte{4}))
	out = append(out, relayCase{Name: "refused as stale", Kind: 7, Code: ptr(byte(4)), Tag: hx(stale[len(stale)-16:]),
		TaggedBy: "relay key", Message: hx(stale)})

	busy := relayMsg(7, []byte{3}, snonce)
	out = append(out, relayCase{Name: "refused as busy", Kind: 7, Code: ptr(byte(3)), Tag: hx(snonce), TaggedBy: "nonce", Message: hx(busy)})

	ask := relayMsg(8, ticketS, make([]byte, 16))
	out = append(out, relayCase{Name: "open, asking", Kind: 8, Ticket: hx(ticketS), Proof: hx(make([]byte, 16)), Message: hx(ask)})

	confirmation := det("relay confirmation", 16)
	open := relayMsg(8, ticketS, confirmation)
	out = append(out, relayCase{Name: "open", Kind: 8, Ticket: hx(ticketS), Proof: hx(confirmation), Message: hx(open)})

	out = append(out, relayCase{Name: "punch", Kind: 9, Message: hx(relayMsg(9))})

	bye := withProof(kr, relayMsg(10, rp, token, binary.BigEndian.AppendUint64(nil, stamp+2), rnonce))
	out = append(out, relayCase{Name: "bye", Kind: 10, ID: hx(rp), Token: hx(token), Stamp: ptr(stamp + 2), Nonce: hx(rnonce),
		Proof: hx(bye[len(bye)-16:]), Message: hx(bye)})

	confirm := relayMsg(11, confirmation)
	out = append(out, relayCase{Name: "confirm", Kind: 11, Proof: hx(confirmation), Message: hx(confirm)})

	cas := withProof(ks, relayMsg(12, rp, token, sendHints.bytes(), snonce, sp))
	out = append(out, relayCase{Name: "connect as", Kind: 12, Target: hx(rp), Token: hx(token), Hints: sendHints.json(),
		Nonce: hx(snonce), ID: hx(sp), Proof: hx(cas[len(cas)-16:]), Message: hx(cas)})

	for _, c := range out {
		if len(c.Message)/2 > 192 {
			panic("a relay message over 192 bytes: " + c.Name)
		}
	}
	return relayFile{
		Description:    "The relay's control messages (PROTOCOL.md section 8): SHRELAY1, a kind byte, the body. A proof is BLAKE3-keyed(K, message up to it)[0..16] with K the registration key of the peer that sends it; a tag is either that relay key's (to a registered receiver) or the nonce of the request answered.",
		ReceiverSecret: hx(rs), SenderSecret: hx(ss), RelaySecret: hx(ls),
		ReceiverKey: hx(kr), SenderKey: hx(ks), ReceiverNonce: hx(rnonce), SenderNonce: hx(snonce),
		Messages: out,
	}
}

// --- Contact cards ------------------------------------------------------------

type candidateJSON struct {
	Kind byte   `json:"kind"`
	Addr string `json:"addr"`
}

type relayRefJSON struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

type cardCase struct {
	Role       byte            `json:"role"`
	Created    uint32          `json:"created"`
	ID         string          `json:"id"`
	Version    int             `json:"version"`
	Candidates []candidateJSON `json:"candidates"`
	V4         string          `json:"v4_hints,omitempty"`
	V6         string          `json:"v6_hints,omitempty"`
	Relays     []relayRefJSON  `json:"relays"`
	Body       string          `json:"body"`
	Text       string          `json:"text"`
}

func cardOf(role byte, created uint32, id []byte, version int, cands []candidateJSON, v4, v6 *nat, relays []relayRefJSON) cardCase {
	body := []byte{1, role}
	body = append(body, be32(created)...)
	body = append(body, id...)
	body = append(body, byte(len(cands)))
	for _, c := range cands {
		body = append(append(body, c.Kind), encAddr(netip.MustParseAddrPort(c.Addr))...)
	}
	var flags byte
	if v4 != nil {
		flags |= 1
	}
	if v6 != nil {
		flags |= 2
	}
	if version == 4 {
		flags |= 4
	}
	body = append(body, flags)
	c := cardCase{Role: role, Created: created, ID: hx(id), Version: version, Candidates: cands, Relays: relays}
	if v4 != nil {
		body = append(body, v4.bytes()...)
		c.V4 = hx(v4.bytes())
	}
	if v6 != nil {
		body = append(body, v6.bytes()...)
		c.V6 = hx(v6.bytes())
	}
	body = append(body, byte(len(relays)))
	for _, r := range relays {
		body = append(append(body, unhexOrPanic(r.ID)...), encAddr(netip.MustParseAddrPort(r.Addr))...)
	}
	c.Body = hx(body)
	whole := append(append([]byte(nil), body...), Blake3(body, 4)...)
	c.Text = "shc1-" + strings.ToLower(base32Lower.EncodeToString(whole))
	return c
}

func cards() file {
	relayID := x25519Public(det("card relay", 32))
	return file{"Contact cards (PROTOCOL.md section 8): the body, and its text form shc1- and the base32 of the body followed by the first four bytes of its BLAKE3 hash. Flag bit 2 says its maker speaks version 4.",
		[]cardCase{
			cardOf(2, 1_790_000_000, x25519Public(det("card receiver", 32)), 4,
				[]candidateJSON{{0, "192.168.1.20:5555"}, {1, "203.0.113.7:5555"}, {2, "[2001:db8:7::5]:5555"}, {3, "198.51.100.9:49152"}},
				&nat{mapping: 1, filtering: 3, allocation: 1, hairpin: 2}, &nat{mapping: 4, filtering: 3},
				[]relayRefJSON{{hx(relayID), "198.51.100.1:5560"}}),
			cardOf(1, 1_790_000_100, x25519Public(det("card sender", 32)), 3,
				[]candidateJSON{{1, "198.51.100.20:61001"}},
				&nat{mapping: 3, filtering: 3, allocation: 2, delta: 1, hairpin: 1, cgn: true}, nil, nil),
		}}
}

// --- The DHT ------------------------------------------------------------------

type dhtCase struct {
	Receiver  string `json:"receiver_id"`
	Secret    string `json:"secret"`
	Key       string `json:"key"`
	Receivers string `json:"infohash_receiver"`
	Senders   string `json:"infohash_sender"`
}

func dht() file {
	id := x25519Public(det("dht receiver", 32))
	var cases []dhtCase
	for _, secret := range [][]byte{nil, det("dht secret", 32)} {
		key := Blake3DeriveKey("sharp256 dht rendezvous v1", append(append([]byte(nil), id...), secret...), 32)
		cases = append(cases, dhtCase{hx(id), hx(secret), hx(key),
			hx(Blake3Keyed(key, []byte("receiver"), 20)), hx(Blake3Keyed(key, []byte("sender"), 20))})
	}
	return file{"The DHT's rendezvous key and infohashes (PROTOCOL.md section 8, the DHT): without a secret, and with one (the 32 bytes of the PSK).", cases}
}

// --- Carriers -----------------------------------------------------------------

type frameCase struct {
	Port  uint16 `json:"port"`
	Own   bool   `json:"own"`
	Data  string `json:"data"`
	Frame string `json:"frame"`
}

type bindingCase struct {
	RelaySecret     string `json:"relay_static_secret"`
	EphemeralSecret string `json:"ephemeral_secret"`
	Nonce           string `json:"nonce"`
	Exported        string `json:"exported_key"`
	Shared          string `json:"shared_secret"`
	Key             string `json:"binding_key"`
	MAC             string `json:"mac"`
	AskFrame        string `json:"ask_frame"`
	AnswerFrame     string `json:"answer_frame"`
}

type carriersFile struct {
	Description string            `json:"description"`
	Preambles   map[string]string `json:"preambles"`
	Frames      []frameCase       `json:"frames"`
	Binding     []bindingCase     `json:"tls_binding"`
}

// length (u16) | port (u16) | datagram; the carrier's own with the
// length's top bit set and port 0.
func frameOf(port uint16, own bool, data []byte) frameCase {
	l := uint16(len(data))
	if own {
		l |= 0x8000
		port = 0
	}
	return frameCase{port, own, hx(data), hx(append(append(be16(l), be16(port)...), data...))}
}

func carriers() carriersFile {
	relay, eph := det("tls relay", 32), det("tls ephemeral", 32)
	nonce, exported := det("tls nonce", 16), det("tls exported", 32)
	ephPub, relayPub := x25519Public(eph), x25519Public(relay)
	shared := x25519(eph, relayPub)
	key := Blake3DeriveKey("sharp256 relay tls binding v1",
		append(append(append(append([]byte(nil), shared...), ephPub...), relayPub...), nonce...), 32)
	mac := Blake3Keyed(key, exported, 32)
	ask := append(append([]byte{1}, ephPub...), nonce...)
	answer := append([]byte{2}, mac...)
	return carriersFile{
		Description: "Carriers other than UDP (PROTOCOL.md section 8): the preambles, frames — length (u16) | port (u16) | datagram, the carrier's own with the length's top bit set — and the binding of TLS to a relay: a MAC under a key from DH(ephemeral, relay), the ephemeral key, the relay's ID and the nonce, over a key exported from the TLS session (given here; RFC 8446 7.5, label EXPORTER-sharp256-relay-binding, the nonce as context).",
		Preambles:   map[string]string{"receiver": hx([]byte("SHRP\x01\x01\x00\x00")), "relay": hx([]byte("SHRP\x01\x02\x00\x00"))},
		Frames: []frameCase{
			frameOf(0, false, det("frame to a receiver", 60)),
			frameOf(0, false, det("frame to a relay's control port", 25)),
			frameOf(40001, false, det("frame on a pair's port", 1200)),
			frameOf(0, false, nil),
			frameOf(0, true, ask),
		},
		Binding: []bindingCase{{hx(relay), hx(eph), hx(nonce), hx(exported), hx(shared), hx(key), hx(mac),
			frameOf(0, true, ask).Frame, frameOf(0, true, answer).Frame}},
	}
}

func unhexOrPanic(s string) []byte {
	var out []byte
	_, err := fmt.Sscanf(s, "%x", &out)
	if err != nil {
		panic(err)
	}
	return out
}
