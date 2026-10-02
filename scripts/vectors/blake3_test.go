package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The official BLAKE3 test vectors (BLAKE3-team/BLAKE3, tag 1.8.2,
// test_vectors/test_vectors.json; sha256 dcb91ea8…f624): every input
// length the tree's shapes turn on, the three modes, 131 bytes of output.
func TestBlake3OfficialVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/blake3_test_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Key     string `json:"key"`
		Context string `json:"context_string"`
		Cases   []struct {
			InputLen  int    `json:"input_len"`
			Hash      string `json:"hash"`
			KeyedHash string `json:"keyed_hash"`
			DeriveKey string `json:"derive_key"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) < 30 {
		t.Fatalf("only %d cases", len(v.Cases))
	}
	for _, c := range v.Cases {
		input := make([]byte, c.InputLen)
		for i := range input {
			input[i] = byte(i % 251)
		}
		for name, got := range map[string][]byte{
			c.Hash:      Blake3(input, len(c.Hash)/2),
			c.KeyedHash: Blake3Keyed([]byte(v.Key), input, len(c.KeyedHash)/2),
			c.DeriveKey: Blake3DeriveKey(v.Context, input, len(c.DeriveKey)/2),
		} {
			if hex.EncodeToString(got) != name {
				t.Errorf("input of %d bytes: got %x, want %s", c.InputLen, got, name)
			}
		}
	}
}
