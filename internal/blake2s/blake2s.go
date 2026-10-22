// Package blake2s gives the unkeyed BLAKE2s digests go-echolot needs,
// above all yamn's keyid: BLAKE2s-128 of the public key, no key
// (Y:keymgr/public.go makeKeyID).
//
// golang.org/x/crypto/blake2s can't make it: its 128-bit variant needs a
// key.  So this wraps github.com/dchest/blake2s, the package yamn itself
// uses, at the same version (v1.0.0, same go.sum hash).  It's the one
// exception to the standard-library-and-golang.org/x rule, for this
// reason only; the review is yamn's ISSUES.md Y-52 (go-while/yamn#68).
package blake2s

import "github.com/dchest/blake2s"

// Sum returns the unkeyed BLAKE2s digest of data, size bytes long.  It
// panics unless 1 <= size <= 32.
func Sum(data []byte, size int) []byte {
	if size < 1 || size > 32 {
		panic("blake2s: digest size must be 1 to 32 bytes")
	}
	h, err := blake2s.New(&blake2s.Config{Size: uint8(size)})
	if err != nil {
		panic(err) // can't happen: the size is checked above
	}
	h.Write(data)
	return h.Sum(nil)
}

// Sum128 returns the 16-byte digest: a yamn keyid.
func Sum128(data []byte) [16]byte {
	return [16]byte(Sum(data, 16))
}
