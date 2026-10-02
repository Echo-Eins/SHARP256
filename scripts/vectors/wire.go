package main

// PROTOCOL.md sections 2 ("Handshake payloads") and 4: the payloads of the
// handshake and the bodies of the frames; and section 6: the manifest of a
// directory.

import (
	"encoding/binary"
	"strings"
)

// Unsigned LEB128, minimal.
func uvarint(v uint64) []byte { return binary.AppendUvarint(nil, v) }

// [start, end) holes, as gaps and lengths from `base`: n:u16 and the pairs.
func holesBytes(base uint64, holes [][2]uint64) []byte {
	out := be16(uint16(len(holes)))
	at := base
	for _, h := range holes {
		out = append(out, uvarint(h[0]-at)...)
		out = append(out, uvarint(h[1]-h[0])...)
		at = h[1]
	}
	return out
}

func text(s string) []byte { return append([]byte{byte(len(s))}, s...) }

type treeJSON struct {
	ManifestLen  uint64 `json:"manifest_len"`
	ManifestHash string `json:"manifest_hash"`
	Files        uint64 `json:"files"`
	Dirs         uint64 `json:"dirs"`
}

type helloJSON struct {
	TransferID   string    `json:"transfer_id"`
	Timestamp    uint32    `json:"timestamp"`
	FileSize     uint64    `json:"file_size"`
	FileMtime    int64     `json:"file_mtime"`
	MaxChunk     uint16    `json:"max_chunk"`
	Capabilities uint32    `json:"capabilities"`
	Tree         *treeJSON `json:"tree"`
	Name         string    `json:"name"`
}

func (h helloJSON) body() []byte {
	out := append([]byte(nil), unhexOrPanic(h.TransferID)...)
	out = append(out, be32(h.Timestamp)...)
	out = binary.BigEndian.AppendUint64(out, h.FileSize)
	out = binary.BigEndian.AppendUint64(out, uint64(h.FileMtime))
	out = append(out, be16(h.MaxChunk)...)
	out = append(out, be32(h.Capabilities)...)
	if h.Tree == nil {
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = binary.BigEndian.AppendUint64(out, h.Tree.ManifestLen)
		out = append(out, unhexOrPanic(h.Tree.ManifestHash)...)
		out = binary.BigEndian.AppendUint64(out, h.Tree.Files)
		out = binary.BigEndian.AppendUint64(out, h.Tree.Dirs)
	}
	return append(out, text(h.Name)...)
}

type helloAckJSON struct {
	Status        byte        `json:"status"`
	Reason        byte        `json:"reason"`
	MaxChunk      uint16      `json:"max_chunk"`
	Capabilities  uint32      `json:"capabilities"`
	EchoTS        uint32      `json:"echo_ts"`
	MaxAckDelayUS uint32      `json:"max_ack_delay_us"`
	Rwnd          uint64      `json:"rwnd"`
	ResumeUpto    uint64      `json:"resume_upto"`
	KnownEnd      uint64      `json:"known_end"`
	Holes         [][2]uint64 `json:"holes"`
	Message       string      `json:"message"`
}

func (a helloAckJSON) body() []byte {
	out := []byte{a.Status, a.Reason}
	out = append(out, be16(a.MaxChunk)...)
	out = append(out, be32(a.Capabilities)...)
	out = append(out, be32(a.EchoTS)...)
	out = append(out, be32(a.MaxAckDelayUS)...)
	for _, v := range []uint64{a.Rwnd, a.ResumeUpto, a.KnownEnd} {
		out = binary.BigEndian.AppendUint64(out, v)
	}
	out = append(out, holesBytes(a.ResumeUpto, a.Holes)...)
	return append(out, text(a.Message)...)
}

type ackJSON struct {
	ContiguousUpto uint64      `json:"contiguous_upto"`
	Highest        uint64      `json:"highest"`
	ReceivedBytes  uint64      `json:"received_bytes"`
	EchoTS         uint32      `json:"echo_ts"`
	AckDelayUS     uint32      `json:"ack_delay_us"`
	Rwnd           uint64      `json:"rwnd"`
	Holes          [][2]uint64 `json:"holes"`
}

func (a ackJSON) body() []byte {
	var out []byte
	for _, v := range []uint64{a.ContiguousUpto, a.Highest, a.ReceivedBytes} {
		out = binary.BigEndian.AppendUint64(out, v)
	}
	out = append(out, be32(a.EchoTS)...)
	out = append(out, be32(a.AckDelayUS)...)
	out = binary.BigEndian.AppendUint64(out, a.Rwnd)
	return append(out, holesBytes(a.ContiguousUpto, a.Holes)...)
}

// One frame: its type and flags, its fields (those of its type), and the
// type byte and body.
type frameVector struct {
	Name     string        `json:"name"`
	Type     byte          `json:"type"`
	Flags    byte          `json:"flags"`
	Hello    *helloJSON    `json:"hello,omitempty"`
	HelloAck *helloAckJSON `json:"hello_ack,omitempty"`
	Ack      *ackJSON      `json:"ack,omitempty"`
	Offset   *uint64       `json:"offset,omitempty"`
	Value    *uint32       `json:"value,omitempty"` // timestamp, echo
	Size     *uint16       `json:"size,omitempty"`
	Code     *uint16       `json:"code,omitempty"`
	Verdict  *byte         `json:"verdict,omitempty"`
	Bytes    string        `json:"bytes,omitempty"` // payload, hash, token
	Reason   *string       `json:"reason,omitempty"`
	TypeByte byte          `json:"type_byte"`
	Body     string        `json:"body"`
}

func (f frameVector) done(body []byte) frameVector {
	f.TypeByte = f.Flags<<4 | f.Type
	f.Body = hx(body)
	return f
}

type payloadVector struct {
	Name        string        `json:"name"`
	Version     int           `json:"version"`
	Timestamp   uint64        `json:"timestamp,omitempty"`
	Suites      byte          `json:"suites,omitempty"`
	HardwareAES bool          `json:"hardware_aes,omitempty"`
	HelloFlags  byte          `json:"hello_flags,omitempty"`
	Hello       *helloJSON    `json:"hello,omitempty"`
	Padded      bool          `json:"padded,omitempty"`
	Suite       *byte         `json:"suite,omitempty"`
	AckFlags    byte          `json:"ack_flags,omitempty"`
	HelloAck    *helloAckJSON `json:"hello_ack,omitempty"`
	Reason      *byte         `json:"reason,omitempty"`
	Payload     string        `json:"payload"`
}

type framesFile struct {
	Description string          `json:"description"`
	Frames      []frameVector   `json:"cases"`
	Payloads    []payloadVector `json:"handshake_payloads"`
}

// Bytes a transport packet adds around its body (section 3).
const transportOverhead = 33

// What a version 3 initiation adds around its payload: the clear and the
// sealed connection id, e, the sealed s, the payload's tag, mac1, mac2.
const initiationOverhead = 2*cidLen + 32 + 48 + 16 + 2*macLen

func frames() framesFile {
	tid := hx(det("frames transfer id", 16))
	hash := hx(det("frames stream hash", 32))
	manifest, info := manifestBytes()
	fileHello := helloJSON{tid, 0x12345678, 5_000_000_000, 1_790_000_000, 1427, 0, nil, "отчёт за 2026.pdf"}
	dirHello := helloJSON{tid, 7, info.Files, -1, 8927, 0,
		&treeJSON{uint64(len(manifest)), hx(Blake3(manifest, 32)), info.Files, info.Dirs}, "photos"}
	dirHello.FileSize = uint64(len(manifest)) + info.Data
	accepted := helloAckJSON{1, 0, 1427, 0, 0x12345678, 25_000, 64 << 20, 1 << 20, 6 << 20,
		[][2]uint64{{1<<20 + 100, 1<<20 + 228}, {2 << 20, 3 << 20}, {5 << 20, 5<<20 + 1}}, ""}
	rejected := helloAckJSON{2, 3, 0, 0, 7, 0, 0, 0, 0, nil, "too many concurrent transfers"}
	ack := ackJSON{1000, 1_000_000_000, 999_000_000, 0x0abcdef0, 1500, 32 << 20,
		[][2]uint64{{1000, 2427}, {2427 + 128, 2427 + 128 + 16384}, {999_999_000, 999_999_999}}}
	u64 := func(v uint64) *uint64 { return &v }
	u32 := func(v uint32) *uint32 { return &v }
	u16 := func(v uint16) *uint16 { return &v }
	u8 := func(v byte) *byte { return &v }
	str := func(v string) *string { return &v }
	payload := det("frames data", 1427)
	token := det("frames path token", 8)
	probe := append(be16(1400), make([]byte, 1400-transportOverhead-2)...)

	out := []frameVector{
		frameVector{Name: "hello, a file, resuming", Type: 1, Flags: 1, Hello: &fileHello}.done(fileHello.body()),
		frameVector{Name: "hello, a directory", Type: 1, Hello: &dirHello}.done(dirHello.body()),
		frameVector{Name: "hello_ack, accepted, resumed with holes", Type: 2, Flags: 1, HelloAck: &accepted}.done(accepted.body()),
		frameVector{Name: "hello_ack, rejected", Type: 2, HelloAck: &rejected}.done(rejected.body()),
		frameVector{Name: "data, sent again", Type: 3, Flags: 1, Offset: u64(1<<32 + 7), Value: u32(99), Bytes: hx(payload)}.
			done(append(append(binary.BigEndian.AppendUint64(nil, 1<<32+7), be32(99)...), payload...)),
		frameVector{Name: "ack with holes", Type: 4, Ack: &ack}.done(ack.body()),
		frameVector{Name: "fin", Type: 5, Bytes: hash}.done(unhexOrPanic(hash)),
		frameVector{Name: "fin_ack", Type: 6, Verdict: u8(1), Bytes: hash}.done(append([]byte{1}, unhexOrPanic(hash)...)),
		frameVector{Name: "ping", Type: 7, Value: u32(0xdeadbeef)}.done(be32(0xdeadbeef)),
		frameVector{Name: "pong", Type: 8, Value: u32(0xdeadbeef)}.done(be32(0xdeadbeef)),
		frameVector{Name: "probe of 1400 bytes", Type: 9, Size: u16(1400)}.done(probe),
		frameVector{Name: "probe_ack", Type: 10, Size: u16(1387)}.done(be16(1387)),
		frameVector{Name: "abort", Type: 11, Code: u16(3), Reason: str("cannot write: No space left on device")}.
			done(append(be16(3), text("cannot write: No space left on device")...)),
		frameVector{Name: "fin_done", Type: 12, Verdict: u8(2)}.done([]byte{2}),
		frameVector{Name: "path_challenge", Type: 13, Bytes: hx(token)}.done(token),
		frameVector{Name: "path_response", Type: 14, Bytes: hx(token)}.done(token),
	}

	ts := uint64(1_790_000_000_123_456_789)
	init3 := append(append(binary.BigEndian.AppendUint64(nil, ts), 3, 1, 1), fileHello.body()...)
	padded := append(append([]byte(nil), init3...), make([]byte, maxControl-initiationOverhead-len(init3))...)
	resp3 := append([]byte{2, 1}, accepted.body()...)
	payloads := []payloadVector{
		{Name: "version 3 initiation", Version: 3, Timestamp: ts, Suites: 3, HardwareAES: true, HelloFlags: 1,
			Hello: &fileHello, Payload: hx(init3)},
		{Name: "version 3 initiation, padded for a resume", Version: 3, Timestamp: ts, Suites: 3, HardwareAES: true,
			HelloFlags: 1, Hello: &fileHello, Padded: true, Payload: hx(padded)},
		{Name: "version 3 response", Version: 3, Suite: u8(2), AckFlags: 1, HelloAck: &accepted, Payload: hx(resp3)},
		{Name: "version 4 initiation", Version: 4, Timestamp: ts, Suites: 2, Payload: hx(append(binary.BigEndian.AppendUint64(nil, ts), 2, 0))},
		{Name: "version 4 response, refused", Version: 4, Suite: u8(0), Reason: u8(8), Payload: hx([]byte{0, 8})},
	}
	return framesFile{
		Description: "Frame bodies (PROTOCOL.md section 4), the type byte with its flags in the high four bits, and the handshake payloads (section 2): every integer big-endian, holes as n:u16 and LEB128 (gap, len) pairs from the base, text as len:u8 and UTF-8. Holes here are absolute [start, end) ranges.",
		Frames:      out,
		Payloads:    payloads,
	}
}

// --- Section 6 ----------------------------------------------------------------

type manifestEntry struct {
	Parent  uint32  `json:"parent"`
	Dir     bool    `json:"dir"`
	Name    string  `json:"name"`
	Size    uint64  `json:"size"`
	Mode    *uint32 `json:"mode"`
	Seconds *int64  `json:"mtime_seconds"`
	Nanos   *uint32 `json:"mtime_nanoseconds"`
}

func (e manifestEntry) meta() (head byte, meta []byte) {
	if e.Dir {
		head |= 1
	}
	if e.Mode != nil {
		head |= 2
		meta = uvarint(uint64(*e.Mode))
	}
	if e.Seconds != nil {
		head |= 4
		s := *e.Seconds
		meta = append(meta, uvarint(uint64(s<<1)^uint64(s>>63))...) // zigzag
		meta = append(meta, uvarint(uint64(*e.Nanos))...)
	}
	return head, meta
}

type manifestInfo struct {
	Files, Dirs, Data uint64
}

func manifestTree() (root manifestEntry, entries []manifestEntry) {
	mode := func(m uint32) *uint32 { return &m }
	secs := func(s int64) *int64 { return &s }
	nanos := func(n uint32) *uint32 { return &n }
	root = manifestEntry{Dir: true, Mode: mode(0o755), Seconds: secs(1_790_000_000), Nanos: nanos(123_456_789)}
	entries = []manifestEntry{
		{Parent: 0, Dir: true, Name: "a", Mode: mode(0o750)},
		{Parent: 1, Name: "b.txt", Size: 5, Mode: mode(0o640), Seconds: secs(1_790_000_001), Nanos: nanos(0)},
		{Parent: 1, Name: "c.bin", Size: 0},
		{Parent: 0, Dir: true, Name: "empty"},
		{Parent: 0, Name: "отчёт.txt", Size: 70_000, Seconds: secs(-1), Nanos: nanos(999_999_999)},
	}
	return root, entries
}

func manifestBytes() ([]byte, manifestInfo) {
	root, entries := manifestTree()
	head, meta := root.meta()
	out := append([]byte{1, 0, head}, meta...)
	out = append(out, uvarint(uint64(len(entries)))...)
	var info manifestInfo
	for _, e := range entries {
		head, meta := e.meta()
		out = append(out, head)
		out = append(out, uvarint(uint64(e.Parent))...)
		out = append(out, uvarint(uint64(len(e.Name)))...)
		out = append(out, e.Name...)
		if !e.Dir {
			out = append(out, uvarint(e.Size)...)
			info.Files++
			info.Data += e.Size
		} else {
			info.Dirs++
		}
		out = append(out, meta...)
	}
	return out, info
}

type manifestFile struct {
	Description string          `json:"description"`
	Root        manifestEntry   `json:"root"`
	Entries     []manifestEntry `json:"entries"`
	Files       uint64          `json:"files"`
	Dirs        uint64          `json:"dirs"`
	DataLen     uint64          `json:"data_len"`
	Manifest    string          `json:"manifest"`
	Hash        string          `json:"manifest_hash"`
}

func manifests() manifestFile {
	root, entries := manifestTree()
	m, info := manifestBytes()
	desc := []string{
		"A directory's manifest (PROTOCOL.md section 6): entries in the order they are written, parent 0 for the root and otherwise one plus the index of the directory entry it is in; siblings in byte order of their names.",
		"files and dirs are what HELLO's tree says (dirs not counting the root).",
	}
	return manifestFile{strings.Join(desc, " "), root, entries, info.Files, info.Dirs, info.Data, hx(m), hx(Blake3(m, 32))}
}
