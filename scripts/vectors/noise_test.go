package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Cacophony's test vector for Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s (the one
// the crate also checks itself against): both handshake messages byte for
// byte, and the handshake hash. Nothing of this program comes from the
// crate's code; the vector is a third party's.
func TestNoiseCacophonyVector(t *testing.T) {
	raw, err := os.ReadFile("../../src/crypto/noise_ikpsk2_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Prologue      string   `json:"init_prologue"`
		PSKs          []string `json:"init_psks"`
		InitStatic    string   `json:"init_static"`
		InitEphemeral string   `json:"init_ephemeral"`
		RespStatic    string   `json:"resp_static"`
		RespEphemeral string   `json:"resp_ephemeral"`
		Hash          string   `json:"handshake_hash"`
		Messages      []struct {
			Payload    string `json:"payload"`
			Ciphertext string `json:"ciphertext"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out, err := runHandshake(handshakeInputs{
		prologue:           unhex(t, v.Prologue),
		initiatorStatic:    unhex(t, v.InitStatic),
		responderStatic:    unhex(t, v.RespStatic),
		initiatorEphemeral: unhex(t, v.InitEphemeral),
		responderEphemeral: unhex(t, v.RespEphemeral),
		psk:                unhex(t, v.PSKs[0]),
		payload1:           unhex(t, v.Messages[0].Payload),
		payload2:           unhex(t, v.Messages[1].Payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(out.msg1); got != v.Messages[0].Ciphertext {
		t.Errorf("message 1: %s", got)
	}
	if got := hex.EncodeToString(out.msg2); got != v.Messages[1].Ciphertext {
		t.Errorf("message 2: %s", got)
	}
	if got := hex.EncodeToString(out.h); got != v.Hash {
		t.Errorf("handshake hash: %s", got)
	}
	// The transport messages after it: the initiator's with the first key,
	// the responder's with the second, each counting from zero.
	sends := [2]cipherState{{k: out.i2r}, {k: out.r2i}}
	for i, m := range v.Messages[2:] {
		c := &sends[i%2]
		if got := hex.EncodeToString(c.encrypt(nil, unhex(t, m.Payload))); got != m.Ciphertext {
			t.Errorf("transport message %d: %s", i, got)
		}
	}
}
