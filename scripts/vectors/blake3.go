package main

// BLAKE3, written from its specification (the BLAKE3 paper, section 2, and
// the reference implementation's structure) for this program alone: the
// protocol's own code uses the `blake3` crate, and a check that used the
// same code would check nothing. Plain and slow; every input here is a few
// kilobytes at most. blake3_test.go holds it to the official test vectors.

import (
	"encoding/binary"
	"math/bits"
)

const (
	b3BlockLen = 64
	b3ChunkLen = 1024

	b3ChunkStart        = 1 << 0
	b3ChunkEnd          = 1 << 1
	b3Parent            = 1 << 2
	b3Root              = 1 << 3
	b3KeyedHash         = 1 << 4
	b3DeriveKeyContext  = 1 << 5
	b3DeriveKeyMaterial = 1 << 6
)

var b3IV = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var b3Permutation = [16]int{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

func b3G(s *[16]uint32, a, b, c, d int, x, y uint32) {
	s[a] = s[a] + s[b] + x
	s[d] = bits.RotateLeft32(s[d]^s[a], -16)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -12)
	s[a] = s[a] + s[b] + y
	s[d] = bits.RotateLeft32(s[d]^s[a], -8)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -7)
}

func b3Compress(cv [8]uint32, block [16]uint32, counter uint64, blockLen, flags uint32) [16]uint32 {
	s := [16]uint32{
		cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
		b3IV[0], b3IV[1], b3IV[2], b3IV[3],
		uint32(counter), uint32(counter >> 32), blockLen, flags,
	}
	m := block
	for r := 0; r < 7; r++ {
		b3G(&s, 0, 4, 8, 12, m[0], m[1])
		b3G(&s, 1, 5, 9, 13, m[2], m[3])
		b3G(&s, 2, 6, 10, 14, m[4], m[5])
		b3G(&s, 3, 7, 11, 15, m[6], m[7])
		b3G(&s, 0, 5, 10, 15, m[8], m[9])
		b3G(&s, 1, 6, 11, 12, m[10], m[11])
		b3G(&s, 2, 7, 8, 13, m[12], m[13])
		b3G(&s, 3, 4, 9, 14, m[14], m[15])
		var p [16]uint32
		for i := range p {
			p[i] = m[b3Permutation[i]]
		}
		m = p
	}
	for i := 0; i < 8; i++ {
		s[i] ^= s[i+8]
		s[i+8] ^= cv[i]
	}
	return s
}

func b3Words(b []byte) [16]uint32 {
	var full [b3BlockLen]byte
	copy(full[:], b)
	var w [16]uint32
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(full[4*i:])
	}
	return w
}

func b3First8(w [16]uint32) [8]uint32 {
	var cv [8]uint32
	copy(cv[:], w[:8])
	return cv
}

// A node not yet compressed: what makes a chaining value, or, at the root,
// any amount of output.
type b3Output struct {
	cv       [8]uint32
	block    [16]uint32
	counter  uint64
	blockLen uint32
	flags    uint32
}

func (o b3Output) chainingValue() [8]uint32 {
	return b3First8(b3Compress(o.cv, o.block, o.counter, o.blockLen, o.flags))
}

func (o b3Output) root(n int) []byte {
	out := make([]byte, 0, n+b3BlockLen)
	for i := uint64(0); len(out) < n; i++ {
		w := b3Compress(o.cv, o.block, i, o.blockLen, o.flags|b3Root)
		for _, x := range w {
			out = binary.LittleEndian.AppendUint32(out, x)
		}
	}
	return out[:n]
}

// The output of one chunk (at most 1024 bytes) at position `counter`.
func b3Chunk(input []byte, counter uint64, key [8]uint32, flags uint32) b3Output {
	cv := key
	start := uint32(b3ChunkStart)
	for len(input) > b3BlockLen {
		cv = b3First8(b3Compress(cv, b3Words(input[:b3BlockLen]), counter, b3BlockLen, flags|start))
		input = input[b3BlockLen:]
		start = 0
	}
	return b3Output{cv, b3Words(input), counter, uint32(len(input)), flags | start | b3ChunkEnd}
}

// The output of the subtree over `input`, whose first chunk is chunk
// number `counter`: the left subtree holds the largest power of two of
// whole chunks that leaves something for the right.
func b3Subtree(input []byte, counter uint64, key [8]uint32, flags uint32) b3Output {
	if len(input) <= b3ChunkLen {
		return b3Chunk(input, counter, key, flags)
	}
	chunks := (len(input) + b3ChunkLen - 1) / b3ChunkLen
	left := 1
	for left*2 < chunks {
		left *= 2
	}
	l := b3Subtree(input[:left*b3ChunkLen], counter, key, flags).chainingValue()
	r := b3Subtree(input[left*b3ChunkLen:], counter+uint64(left), key, flags).chainingValue()
	var block [16]uint32
	copy(block[:8], l[:])
	copy(block[8:], r[:])
	return b3Output{key, block, 0, b3BlockLen, flags | b3Parent}
}

func b3KeyWords(key []byte) [8]uint32 {
	var w [8]uint32
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	return w
}

// Blake3 is BLAKE3's hash of input, n bytes of it.
func Blake3(input []byte, n int) []byte {
	return b3Subtree(input, 0, b3IV, 0).root(n)
}

// Blake3Keyed is BLAKE3's keyed hash, n bytes of it.
func Blake3Keyed(key []byte, input []byte, n int) []byte {
	if len(key) != 32 {
		panic("a BLAKE3 key has 32 bytes")
	}
	return b3Subtree(input, 0, b3KeyWords(key), b3KeyedHash).root(n)
}

// Blake3DeriveKey is BLAKE3's key derivation, n bytes of it.
func Blake3DeriveKey(context string, material []byte, n int) []byte {
	ck := b3Subtree([]byte(context), 0, b3IV, b3DeriveKeyContext).root(32)
	return b3Subtree(material, 0, b3KeyWords(ck), b3DeriveKeyMaterial).root(n)
}
