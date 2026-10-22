// Package minisign reads and writes minisign keys and signatures (design
// §9.5), compatible with the reference tool (https://jedisct1.github.io/minisign/):
// `minisign -Vm pubring.mix -P <key>` verifies what go-echolot signs.
//
// Signatures are Ed25519 over BLAKE2b-512 of the file (minisign's "ED",
// prehashed, its default since 0.11), plus a second signature over the
// first and the trusted comment.  Secret keys are minisign's format
// without a password (minisign -G -W): the daemon has to read its key
// unattended, so the file's mode protects it.
package minisign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// The algorithm tags of minisign's formats.
var (
	algEd     = []byte("Ed") // keys; legacy signatures over the file itself
	algED     = []byte("ED") // signatures over BLAKE2b-512 of the file
	kdfNone   = []byte{0, 0} // a secret key without a password
	kdfScrypt = []byte("Sc")
	chkB2     = []byte("B2")
)

const (
	keyIDLen = 8
	// MaxComment is the longest comment Sign writes: minisign reads
	// longer ones, but nothing go-echolot signs needs more.
	MaxComment = 1024
	// maxSigFile bounds what ParseSignature reads: the four lines of a
	// signature with comments of up to minisign's 8 KiB.
	maxSigFile = 16 << 10

	untrustedPrefix = "untrusted comment: "
	trustedPrefix   = "trusted comment: "

	secretKeyLen = 2 + 2 + 2 + 32 + 8 + 8 + keyIDLen + ed25519.PrivateKeySize + 32 // 158
	publicKeyLen = 2 + keyIDLen + ed25519.PublicKeySize                            // 42
	sigLen       = 2 + keyIDLen + ed25519.SignatureSize                            // 74
)

// UntrustedComment is the untrusted comment of go-echolot's signatures.
const UntrustedComment = "go-echolot signature"

// Errors of Verify.
var (
	ErrWrongKey     = errors.New("minisign: signed by another key")
	ErrBadSignature = errors.New("minisign: bad signature")
)

// KeyID is the random number minisign gives a key pair; signatures carry it.
type KeyID [keyIDLen]byte

// String is the key ID as minisign prints it: hex of the little-endian
// number, so the bytes in reverse order.
func (id KeyID) String() string {
	return fmt.Sprintf("%016X", binary.LittleEndian.Uint64(id[:]))
}

// PublicKey is a minisign public key.
type PublicKey struct {
	ID  KeyID
	Key ed25519.PublicKey
}

// String is the key's base64 line, what `minisign -P` and yamn's
// pinger_keys take.
func (p PublicKey) String() string {
	b := make([]byte, 0, publicKeyLen)
	b = append(b, algEd...)
	b = append(b, p.ID[:]...)
	b = append(b, p.Key...)
	return base64.StdEncoding.EncodeToString(b)
}

// File returns the public key file (pinger.pub): minisign's two lines.
func (p PublicKey) File() []byte {
	return []byte(untrustedPrefix + "minisign public key " + p.ID.String() + "\n" + p.String() + "\n")
}

// ParsePublicKey reads a public key file, or its base64 line alone.
func ParsePublicKey(data []byte) (PublicKey, error) {
	s := strings.TrimSpace(string(data))
	if first, rest, ok := strings.Cut(s, "\n"); ok {
		if !strings.HasPrefix(first, untrustedPrefix) {
			return PublicKey{}, errors.New("minisign: public key file must start with an untrusted comment")
		}
		s = strings.TrimSpace(rest)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != publicKeyLen {
		return PublicKey{}, errors.New("minisign: not a public key")
	}
	if !bytes.Equal(b[:2], algEd) {
		return PublicKey{}, fmt.Errorf("minisign: unknown key algorithm %q", b[:2])
	}
	var p PublicKey
	copy(p.ID[:], b[2:10])
	p.Key = ed25519.PublicKey(bytes.Clone(b[10:]))
	return p, nil
}

// PrivateKey is a minisign secret key.
type PrivateKey struct {
	ID  KeyID
	Key ed25519.PrivateKey
}

// Public returns the key's public half.
func (k *PrivateKey) Public() PublicKey {
	return PublicKey{ID: k.ID, Key: bytes.Clone(k.Key.Public().(ed25519.PublicKey))}
}

// GenerateKey returns a new key pair, with randomness from r (nil:
// crypto/rand).
func GenerateKey(r io.Reader) (*PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	var id KeyID
	if _, err := io.ReadFull(r, id[:]); err != nil {
		return nil, err
	}
	_, sk, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{ID: id, Key: sk}, nil
}

// checksum is minisign's check of a secret key: BLAKE2b-256 of the
// algorithm, the key ID and the key.
func checksum(id KeyID, sk ed25519.PrivateKey) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(algEd)
	h.Write(id[:])
	h.Write(sk)
	return h.Sum(nil)
}

// File returns the secret key file, without a password, as `minisign -G
// -W` writes it (but with its checksum, which minisign 0.12 leaves 0).
func (k *PrivateKey) File() []byte {
	b := make([]byte, 0, secretKeyLen)
	b = append(b, algEd...)
	b = append(b, kdfNone...)
	b = append(b, chkB2...)
	b = append(b, make([]byte, 32+8+8)...) // salt, opslimit, memlimit: unused
	b = append(b, k.ID[:]...)
	b = append(b, k.Key...)
	b = append(b, checksum(k.ID, k.Key)...)
	return []byte(untrustedPrefix + "minisign secret key, not encrypted\n" + base64.StdEncoding.EncodeToString(b) + "\n")
}

// ParsePrivateKey reads a secret key file without a password.
func ParsePrivateKey(data []byte) (*PrivateKey, error) {
	first, rest, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
	if !strings.HasPrefix(first, untrustedPrefix) {
		return nil, errors.New("minisign: secret key file must start with an untrusted comment")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(rest))
	if err != nil || len(b) != secretKeyLen {
		return nil, errors.New("minisign: not a secret key")
	}
	switch {
	case !bytes.Equal(b[0:2], algEd):
		return nil, fmt.Errorf("minisign: unknown key algorithm %q", b[0:2])
	case bytes.Equal(b[2:4], kdfScrypt):
		return nil, errors.New("minisign: the secret key has a password; remove it with `minisign -C -W -s <file>`")
	case !bytes.Equal(b[2:4], kdfNone):
		return nil, fmt.Errorf("minisign: unknown key derivation %q", b[2:4])
	case !bytes.Equal(b[4:6], chkB2):
		return nil, fmt.Errorf("minisign: unknown checksum algorithm %q", b[4:6])
	}
	b = b[54:]
	var k PrivateKey
	copy(k.ID[:], b[:keyIDLen])
	k.Key = ed25519.PrivateKey(bytes.Clone(b[keyIDLen : keyIDLen+ed25519.PrivateKeySize]))
	chk := b[keyIDLen+ed25519.PrivateKeySize:]
	// minisign 0.12 writes a key without a password with a checksum of 0.
	if !bytes.Equal(chk, make([]byte, 32)) && subtle.ConstantTimeCompare(chk, checksum(k.ID, k.Key)) != 1 {
		return nil, errors.New("minisign: the secret key's checksum is wrong")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(k.Key.Seed()), k.Key) {
		return nil, errors.New("minisign: the secret key's two halves don't match")
	}
	return &k, nil
}

// oneLine reports whether a comment can go into a signature file.
func oneLine(s string) bool {
	return len(s) <= MaxComment && !strings.ContainsAny(s, "\r\n\x00")
}

// Sign returns the signature file (<file>.minisig) of data, with the
// trusted comment trusted and the untrusted comment untrusted.
func Sign(k *PrivateKey, data []byte, trusted, untrusted string) ([]byte, error) {
	if !oneLine(trusted) || !oneLine(untrusted) {
		return nil, errors.New("minisign: a comment must be one line of at most 1024 bytes")
	}
	h := blake2b.Sum512(data)
	sig := make([]byte, 0, sigLen)
	sig = append(sig, algED...)
	sig = append(sig, k.ID[:]...)
	sig = append(sig, ed25519.Sign(k.Key, h[:])...)
	global := ed25519.Sign(k.Key, append(bytes.Clone(sig[10:]), trusted...))
	var b bytes.Buffer
	b.WriteString(untrustedPrefix + untrusted + "\n")
	b.WriteString(base64.StdEncoding.EncodeToString(sig) + "\n")
	b.WriteString(trustedPrefix + trusted + "\n")
	b.WriteString(base64.StdEncoding.EncodeToString(global) + "\n")
	return b.Bytes(), nil
}

// Signature is a parsed signature file.
type Signature struct {
	Untrusted string
	Prehashed bool // "ED"; false: the legacy "Ed", over the file itself
	KeyID     KeyID
	Sig       []byte // over the file, or its BLAKE2b-512
	Trusted   string
	Global    []byte // over Sig and Trusted
}

// ParseSignature reads a signature file: four lines, as minisign writes
// them.  Lines may end in CR LF; blank lines after the four are ignored,
// as minisign does.
func ParseSignature(data []byte) (*Signature, error) {
	if len(data) > maxSigFile {
		return nil, errors.New("minisign: signature file too long")
	}
	lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
	if len(lines) != 4 {
		return nil, errors.New("minisign: a signature file has four lines")
	}
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	var s Signature
	var ok bool
	if s.Untrusted, ok = strings.CutPrefix(lines[0], untrustedPrefix); !ok {
		return nil, errors.New("minisign: no untrusted comment")
	}
	if s.Trusted, ok = strings.CutPrefix(lines[2], trustedPrefix); !ok {
		return nil, errors.New("minisign: no trusted comment")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(lines[1])
	if err != nil || len(sig) != sigLen {
		return nil, errors.New("minisign: bad signature line")
	}
	switch {
	case bytes.Equal(sig[:2], algED):
		s.Prehashed = true
	case bytes.Equal(sig[:2], algEd):
	default:
		return nil, fmt.Errorf("minisign: unknown signature algorithm %q", sig[:2])
	}
	copy(s.KeyID[:], sig[2:10])
	s.Sig = sig[10:]
	if s.Global, err = base64.StdEncoding.Strict().DecodeString(lines[3]); err != nil || len(s.Global) != ed25519.SignatureSize {
		return nil, errors.New("minisign: bad trusted comment signature")
	}
	return &s, nil
}

// VerifyComment checks that p signed the trusted comment of s.  It
// doesn't check the file: it proves that p's owner wrote the comment (and
// its timestamp), whatever file it came with.
func (s *Signature) VerifyComment(p PublicKey) error {
	if s.KeyID != p.ID {
		return ErrWrongKey
	}
	if !ed25519.Verify(p.Key, append(bytes.Clone(s.Sig), s.Trusted...), s.Global) {
		return ErrBadSignature
	}
	return nil
}

// Verify checks that p signed data with the signature file sig, and
// returns its trusted comment.  Legacy signatures (minisign -l) are
// accepted, as `minisign -V` does without -H.
func Verify(p PublicKey, data, sig []byte) (trusted string, err error) {
	s, err := ParseSignature(sig)
	if err != nil {
		return "", err
	}
	if s.KeyID != p.ID {
		return "", ErrWrongKey
	}
	msg := data
	if s.Prehashed {
		h := blake2b.Sum512(data)
		msg = h[:]
	}
	if !ed25519.Verify(p.Key, msg, s.Sig) {
		return "", ErrBadSignature
	}
	if err := s.VerifyComment(p); err != nil {
		return "", err
	}
	return s.Trusted, nil
}
