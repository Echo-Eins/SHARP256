package main

// The handshake of PROTOCOL.md section 2, from the Noise Protocol Framework
// (revision 34: sections 4 and 5, and 9 for the psk modifier) and Noise's
// hybrid forward secrecy draft (the `e1` and `ekem1` tokens):
//
//	IKpsk2:       -> e, es, s, ss          <- e, ee, se, psk
//	IKpsk2+hfs:   -> e, es, e1, s, ss      <- e, ee, ekem1, se, psk
//
// with X25519, ChaCha20-Poly1305 and BLAKE2s, and ML-KEM-768 for the
// hybrid. Both roles are here, and the generator runs them against each
// other: the two must agree before anything is written down.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	noiseName    = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	noiseNameHFS = "Noise_IKpsk2+hfs_25519+MLKEM768_ChaChaPoly_BLAKE2s"
)

func newBlake2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

func hashOf(parts ...[]byte) []byte {
	h := newBlake2s()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func hmacOf(key []byte, parts ...[]byte) []byte {
	m := hmac.New(newBlake2s, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// HKDF of the Noise specification, section 4.3: two or three outputs.
func noiseHKDF(ck, ikm []byte, n int) [][]byte {
	temp := hmacOf(ck, ikm)
	out := [][]byte{hmacOf(temp, []byte{1})}
	for i := 2; i <= n; i++ {
		out = append(out, hmacOf(temp, out[i-2], []byte{byte(i)}))
	}
	return out
}

func x25519Public(secret []byte) []byte {
	k, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		panic(err)
	}
	return k.PublicKey().Bytes()
}

func x25519(secret, public []byte) []byte {
	k, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		panic(err)
	}
	p, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		panic(err)
	}
	shared, err := k.ECDH(p)
	if err != nil {
		panic(err) // a low-order point: never among the inputs here
	}
	return shared
}

type cipherState struct {
	k []byte
	n uint64
}

// Section 5.1, with ChaChaPoly's nonce: 32 bits of zeros, then n as a
// little-endian 64-bit number (section 12.3).
func (c *cipherState) nonce() []byte {
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], c.n)
	c.n++
	return nonce
}

func (c *cipherState) encrypt(ad, plaintext []byte) []byte {
	if c.k == nil {
		return append([]byte(nil), plaintext...)
	}
	aead, err := chacha20poly1305.New(c.k)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, c.nonce(), plaintext, ad)
}

func (c *cipherState) decrypt(ad, ciphertext []byte) ([]byte, error) {
	if c.k == nil {
		return append([]byte(nil), ciphertext...), nil
	}
	aead, err := chacha20poly1305.New(c.k)
	if err != nil {
		panic(err)
	}
	return aead.Open(nil, c.nonce(), ciphertext, ad)
}

// SymmetricState, section 5.2.
type symmetricState struct {
	ck, h []byte
	cs    cipherState
}

func newSymmetricState(name string, prologue, responderStatic []byte) *symmetricState {
	var h []byte
	if len(name) <= 32 {
		h = make([]byte, 32)
		copy(h, name)
	} else {
		h = hashOf([]byte(name))
	}
	s := &symmetricState{ck: append([]byte(nil), h...), h: h}
	s.mixHash(prologue)
	s.mixHash(responderStatic) // the pre-message `<- s`
	return s
}

func (s *symmetricState) mixHash(data []byte) { s.h = hashOf(s.h, data) }

func (s *symmetricState) mixKey(ikm []byte) {
	out := noiseHKDF(s.ck, ikm, 2)
	s.ck, s.cs = out[0], cipherState{k: out[1]}
}

func (s *symmetricState) mixKeyAndHash(ikm []byte) {
	out := noiseHKDF(s.ck, ikm, 3)
	s.ck = out[0]
	s.mixHash(out[1])
	s.cs = cipherState{k: out[2]}
}

func (s *symmetricState) encryptAndHash(plaintext []byte) []byte {
	ct := s.cs.encrypt(s.h, plaintext)
	s.mixHash(ct)
	return ct
}

func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	pt, err := s.cs.decrypt(s.h, ciphertext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	return pt, nil
}

// An `e` token in a handshake with a psk modifier: MixHash, then MixKey
// (section 9.2).
func (s *symmetricState) ephemeral(public []byte) {
	s.mixHash(public)
	s.mixKey(public)
}

func (s *symmetricState) split() (i2r, r2i []byte) {
	out := noiseHKDF(s.ck, nil, 2)
	return out[0], out[1]
}

// The inputs of one handshake, every random value among them.
type handshakeInputs struct {
	hybrid                                 bool
	prologue                               []byte
	initiatorStatic, responderStatic       []byte // private keys
	initiatorEphemeral, responderEphemeral []byte
	psk                                    []byte
	kemSeed                                []byte // d || z, the hybrid's e1
	kemRandom                              []byte // m, the hybrid's encapsulation
	payload1, payload2                     []byte // the Noise payloads
}

type handshakeOutputs struct {
	msg1, msg2  []byte
	i2r, r2i, h []byte
	kemPublic   []byte // e1
	kemCipher   []byte // ekem1, before encryption
	kemShared   []byte
}

func (in handshakeInputs) name() string {
	if in.hybrid {
		return noiseNameHFS
	}
	return noiseName
}

// Runs the handshake: the initiator writes message 1, the responder reads
// it and writes message 2, the initiator reads that; both must end with the
// same keys and hash.
func runHandshake(in handshakeInputs) (handshakeOutputs, error) {
	var out handshakeOutputs
	rs := x25519Public(in.responderStatic)
	is := x25519Public(in.initiatorStatic)

	// -> e, es, [e1,] s, ss, payload
	i := newSymmetricState(in.name(), in.prologue, rs)
	ie := x25519Public(in.initiatorEphemeral)
	msg1 := append([]byte(nil), ie...)
	i.ephemeral(ie)
	i.mixKey(x25519(in.initiatorEphemeral, rs))
	var dk *mlkem.DecapsulationKey768
	if in.hybrid {
		var err error
		dk, err = mlkem.NewDecapsulationKey768(in.kemSeed)
		if err != nil {
			return out, err
		}
		out.kemPublic = dk.EncapsulationKey().Bytes()
		msg1 = append(msg1, i.encryptAndHash(out.kemPublic)...)
	}
	msg1 = append(msg1, i.encryptAndHash(is)...)
	i.mixKey(x25519(in.initiatorStatic, rs))
	msg1 = append(msg1, i.encryptAndHash(in.payload1)...)
	out.msg1 = msg1

	// The responder reads it.
	r := newSymmetricState(in.name(), in.prologue, rs)
	at := 32
	re := msg1[:at]
	r.ephemeral(re)
	r.mixKey(x25519(in.responderStatic, re))
	var ek []byte
	if in.hybrid {
		var err error
		ek, err = r.decryptAndHash(msg1[at : at+1184+16])
		if err != nil {
			return out, err
		}
		at += 1184 + 16
	}
	gotStatic, err := r.decryptAndHash(msg1[at : at+32+16])
	if err != nil {
		return out, err
	}
	at += 32 + 16
	if !bytes.Equal(gotStatic, is) {
		return out, errors.New("the responder read another static key")
	}
	r.mixKey(x25519(in.responderStatic, gotStatic))
	got1, err := r.decryptAndHash(msg1[at:])
	if err != nil {
		return out, err
	}
	if !bytes.Equal(got1, in.payload1) {
		return out, errors.New("the responder read another payload")
	}

	// <- e, ee, [ekem1,] se, psk, payload
	rePub := x25519Public(in.responderEphemeral)
	msg2 := append([]byte(nil), rePub...)
	r.ephemeral(rePub)
	r.mixKey(x25519(in.responderEphemeral, ie))
	if in.hybrid {
		key, err := mlkem.NewEncapsulationKey768(ek)
		if err != nil {
			return out, err
		}
		shared, ct, err := mlkemtest.Encapsulate768(key, in.kemRandom)
		if err != nil {
			return out, err
		}
		out.kemCipher, out.kemShared = ct, shared
		msg2 = append(msg2, r.encryptAndHash(ct)...)
		r.mixKey(shared)
	}
	r.mixKey(x25519(in.responderEphemeral, gotStatic))
	r.mixKeyAndHash(in.psk)
	msg2 = append(msg2, r.encryptAndHash(in.payload2)...)
	out.msg2 = msg2
	rI2R, rR2I := r.split()

	// The initiator reads it.
	at = 32
	reGot := msg2[:at]
	i.ephemeral(reGot)
	i.mixKey(x25519(in.initiatorEphemeral, reGot))
	if in.hybrid {
		ct, err := i.decryptAndHash(msg2[at : at+1088+16])
		if err != nil {
			return out, err
		}
		at += 1088 + 16
		shared, err := dk.Decapsulate(ct)
		if err != nil {
			return out, err
		}
		i.mixKey(shared)
	}
	i.mixKey(x25519(in.initiatorStatic, reGot))
	i.mixKeyAndHash(in.psk)
	got2, err := i.decryptAndHash(msg2[at:])
	if err != nil {
		return out, err
	}
	if !bytes.Equal(got2, in.payload2) {
		return out, errors.New("the initiator read another payload")
	}
	out.i2r, out.r2i = i.split()
	out.h = i.h
	if !bytes.Equal(out.i2r, rI2R) || !bytes.Equal(out.r2i, rR2I) || !bytes.Equal(i.h, r.h) {
		return out, errors.New("the two sides ended with different keys")
	}
	return out, nil
}
