package main

// What PROTOCOL.md adds around the Noise handshake, section by section:
// IDs and the PSK (1), the datagrams of the handshake and their MACs and
// cookies (2), traffic keys (2, "Traffic keys") and transport packets (3),
// and the sealed identity file (1).

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	macLen           = 16
	cidLen           = 8
	headerLen        = cidLen + 1 + 8
	tagLen           = 16
	epochBits        = 22
	maxControl       = 1200
	fragmentOverhead = cidLen + 1 + 2*macLen
	maxFragments     = 4
)

// --- Section 1 ---------------------------------------------------------------

var base32Lower = base32.StdEncoding.WithPadding(base32.NoPadding)

// The text form of an ID: version 3's `sh-`, version 4's `sh4-`.
func sharpID(public []byte, v4 bool) string {
	label, prefix := "sharp256 id checksum", "sh-"
	if v4 {
		label, prefix = "sharp256 id checksum v4", "sh4-"
	}
	data := append(append([]byte(nil), public...), Blake3DeriveKey(label, public, 32)[:3]...)
	return prefix + strings.ToLower(base32Lower.EncodeToString(data))
}

func psk(passphrase string, receiverPublic []byte, memoryKiB, passes uint32, lanes uint8) []byte {
	salt := append([]byte("sharp256 v3 psk "), receiverPublic...)
	return argon2.IDKey([]byte(passphrase), salt, passes, memoryKiB, lanes, 32)
}

// A key line of the identity file sealed with a passphrase, and the
// associated data it was sealed with.
func identityLine(secret []byte, passphrase string, memoryKiB, passes uint32, lanes uint8, salt, nonce []byte) (line, ad string) {
	ad = fmt.Sprintf("sharp256-identity-2 %x passphrase argon2id %d %d %d %x",
		x25519Public(secret), memoryKiB, passes, lanes, salt)
	key := argon2.IDKey([]byte(passphrase), salt, passes, memoryKiB, lanes, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	sealed := aead.Seal(nil, nonce, secret, []byte(ad))
	return fmt.Sprintf("%s %x %x", ad, nonce, sealed), ad
}

// --- Section 2 ---------------------------------------------------------------

func mac1Key(public []byte, v4 bool) []byte {
	if v4 {
		return Blake3DeriveKey("sharp256 v4 mac1", public, 32)
	}
	return Blake3DeriveKey("sharp256 v3 mac1", public, 32)
}

func cookieKey(receiverPublic []byte) []byte {
	return Blake3DeriveKey("sharp256 v3 cookie", receiverPublic, 32)
}

func mac2Key(cookie []byte) []byte {
	return Blake3DeriveKey("sharp256 v3 mac2", cookie, 32)
}

func blakeMAC(key, data []byte) []byte { return Blake3Keyed(key, data, macLen) }

func be64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// mac1 and mac2 after `body`; mac2 is zero without a cookie.
func withMACs(body, mac1KeyBytes, cookie []byte) []byte {
	out := append(append([]byte(nil), body...), blakeMAC(mac1KeyBytes, body)...)
	if cookie == nil {
		return append(out, make([]byte, macLen)...)
	}
	return append(out, blakeMAC(mac2Key(cookie), out)...)
}

// The version 3 initiation: sender_cid | Noise message 1 | mac1 | mac2.
func initiationV3(senderCID uint64, msg1, receiverPublic, cookie []byte) []byte {
	return withMACs(append(be64(senderCID), msg1...), mac1Key(receiverPublic, false), cookie)
}

// The version 3 response: sender_cid | receiver_cid | message 2 | mac1
// keyed with the sender's key | a zero mac2.
func responseV3(senderCID, receiverCID uint64, msg2, senderPublic []byte) []byte {
	body := append(append(be64(senderCID), be64(receiverCID)...), msg2...)
	return withMACs(body, mac1Key(senderPublic, false), nil)
}

// Version 4: message 1 in up to four fragments of about equal size, each
// sender_cid | index·count | chunk | mac1 | mac2. (PROTOCOL.md says "of
// about equal size"; the cut here — as many fragments as the chunk room
// needs, each the same length but the last — is what makes a vector.)
func fragmentsV4(senderCID uint64, msg1, receiverPublic, cookie []byte) [][]byte {
	room := maxControl - fragmentOverhead
	count := (len(msg1) + room - 1) / room
	if count > maxFragments {
		panic("message 1 too long")
	}
	per := (len(msg1) + count - 1) / count
	var out [][]byte
	for i := 0; i < count; i++ {
		end := min((i+1)*per, len(msg1))
		body := append(be64(senderCID), byte(i<<4|count))
		body = append(body, msg1[i*per:end]...)
		out = append(out, withMACs(body, mac1Key(receiverPublic, true), cookie))
	}
	return out
}

// The version 4 response: sender_cid | message 2 | mac1 keyed with the
// sender's key under the version 4 label; no mac2.
func responseV4(senderCID uint64, msg2, senderPublic []byte) []byte {
	body := append(be64(senderCID), msg2...)
	return append(body, blakeMAC(mac1Key(senderPublic, true), body)...)
}

// A cookie reply: sender_cid | nonce | cookie sealed with XChaCha20-Poly1305
// under the receiver's cookie key, the answered datagram's mac1 as
// associated data | tag.
func cookieReply(senderCID uint64, receiverPublic, nonce, cookie, mac1 []byte) []byte {
	aead, err := chacha20poly1305.NewX(cookieKey(receiverPublic))
	if err != nil {
		panic(err)
	}
	return append(append(be64(senderCID), nonce...), aead.Seal(nil, nonce, cookie, mac1)...)
}

// --- Traffic keys and section 3 ---------------------------------------------

type direction struct {
	secret, iv, hp []byte
}

func trafficSecret(k, h []byte) []byte {
	return Blake3DeriveKey("sharp256 v3 traffic secret", append(append([]byte(nil), k...), h...), 32)
}

func newDirection(secret []byte) direction {
	return direction{
		secret: secret,
		iv:     Blake3DeriveKey("sharp256 v3 aead iv", secret, 32)[:12],
		hp:     Blake3DeriveKey("sharp256 v3 header protection", secret, 32),
	}
}

func (d direction) key(epoch uint64) []byte {
	return Blake3DeriveKey("sharp256 v3 aead key", append(append([]byte(nil), d.secret...), be64(epoch)...), 32)
}

// iv XOR (0^4 || pn).
func (d direction) nonce(pn uint64) []byte {
	n := append([]byte(nil), d.iv...)
	for i, b := range be64(pn) {
		n[4+i] ^= b
	}
	return n
}

func aeadFor(suite string, key []byte) cipher.AEAD {
	switch suite {
	case "AES-256-GCM":
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		return a
	case "ChaCha20-Poly1305":
		a, err := chacha20poly1305.New(key)
		if err != nil {
			panic(err)
		}
		return a
	}
	panic("no such suite: " + suite)
}

// The header protection mask for a sample (the tag).
func (d direction) mask(suite string, sample []byte) []byte {
	mask := make([]byte, 16)
	switch suite {
	case "AES-256-GCM":
		block, err := aes.NewCipher(d.hp)
		if err != nil {
			panic(err)
		}
		block.Encrypt(mask, sample)
	case "ChaCha20-Poly1305":
		c, err := chacha20.NewUnauthenticatedCipher(d.hp, sample[4:16])
		if err != nil {
			panic(err)
		}
		c.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
		c.XORKeyStream(mask, mask)
	default:
		panic("no such suite: " + suite)
	}
	return mask
}

// A transport packet: dcid | masked(type | pn) | sealed body | tag.
func (d direction) seal(suite string, dcid uint64, typeByte byte, pn uint64, body []byte) []byte {
	header := append(append(be64(dcid), typeByte), be64(pn)...)
	sealed := aeadFor(suite, d.key(pn>>epochBits)).Seal(nil, d.nonce(pn), body, header)
	mask := d.mask(suite, sealed[len(sealed)-tagLen:])
	for i := 0; i < 9; i++ {
		header[cidLen+i] ^= mask[i]
	}
	return append(header, sealed...)
}

func hx(b []byte) string { return hex.EncodeToString(b) }
