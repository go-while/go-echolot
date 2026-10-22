// Package blake2s is unkeyed BLAKE2s (RFC 7693) with any digest size from
// 1 to 32 bytes.
//
// yamn's keyid is BLAKE2s with a 16-byte digest and no key
// (github.com/dchest/blake2s, Y:keymgr/public.go:600).
// golang.org/x/crypto/blake2s can't make it: its 128-bit variant needs a
// key.  Dependencies are limited to the standard library and
// golang.org/x, so it's here, in the ~80 lines the RFC takes.
package blake2s

import (
	"encoding/binary"
	"math/bits"
)

var iv = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var sigma = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// Sum returns the unkeyed BLAKE2s digest of data, size bytes long.  It
// panics unless 1 <= size <= 32.
func Sum(data []byte, size int) []byte {
	if size < 1 || size > 32 {
		panic("blake2s: digest size must be 1 to 32 bytes")
	}
	h := iv
	h[0] ^= 0x01010000 | uint32(size) // fanout 1, depth 1, no key
	var t uint64                      // bytes compressed so far
	// Every block but the last is compressed as it comes; the last one,
	// full or not (or empty), with the final flag.
	for len(data) > 64 {
		t += 64
		compress(&h, data[:64], t, false)
		data = data[64:]
	}
	var last [64]byte
	copy(last[:], data)
	t += uint64(len(data))
	compress(&h, last[:], t, true)

	var out [32]byte
	for i, v := range h {
		binary.LittleEndian.PutUint32(out[4*i:], v)
	}
	return out[:size]
}

// Sum128 returns the 16-byte digest: a yamn keyid.
func Sum128(data []byte) [16]byte {
	return [16]byte(Sum(data, 16))
}

func compress(h *[8]uint32, block []byte, t uint64, final bool) {
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[4*i:])
	}
	var v [16]uint32
	copy(v[:8], h[:])
	copy(v[8:], iv[:])
	v[12] ^= uint32(t)
	v[13] ^= uint32(t >> 32)
	if final {
		v[14] = ^v[14]
	}
	g := func(a, b, c, d int, x, y uint32) {
		v[a] += v[b] + x
		v[d] = bits.RotateLeft32(v[d]^v[a], -16)
		v[c] += v[d]
		v[b] = bits.RotateLeft32(v[b]^v[c], -12)
		v[a] += v[b] + y
		v[d] = bits.RotateLeft32(v[d]^v[a], -8)
		v[c] += v[d]
		v[b] = bits.RotateLeft32(v[b]^v[c], -7)
	}
	for _, s := range sigma {
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := range h {
		h[i] ^= v[i] ^ v[i+8]
	}
}
