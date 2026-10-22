package pinger

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
)

// Size limits (design §6.3).  Seal keeps the plaintext within
// MaxPlaintext by shortening the garbage, which keeps the sealed text
// within MaxSealed, so a ping is always one yamn chunk.  Open refuses a
// mail body over MaxBody.
const (
	MaxPlaintext = 8704  // 8.5 KiB
	MaxSealed    = 12288 // 12 KiB
	MaxBody      = 16384 // 16 KiB
)

// The armor around the sealed ping.
const (
	armorBegin   = "-----BEGIN ECHOLOT PING-----"
	armorEnd     = "-----END ECHOLOT PING-----"
	armorVersion = "Version: go-echolot-1"
	armorWidth   = 64
	nonceLen     = 24
)

// Seal returns the sealed, armored form of b: the body of the mail
// given to yamn.  boxKey seals it (NaCl secretbox, a fresh nonce from
// rand), macKey makes the mac line.  The garbage is up to garbageLen hex
// digits, of random length (Echolot's random_garbage: rand(n/2) random
// bytes as hex, E:Tools.pm:421), less if the plaintext would exceed
// MaxPlaintext.
func Seal(macKey, boxKey *[32]byte, b Body, garbageLen int, rand io.Reader) ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	header := b.header(macKey)
	// The most random bytes that still fit.
	maxBytes := min(max(0, garbageLen), MaxPlaintext) / 2
	for maxBytes > 0 && len(header)+garbageSize(maxBytes) > MaxPlaintext {
		maxBytes--
	}
	if len(header)+garbageSize(maxBytes) > MaxPlaintext {
		return nil, fmt.Errorf("%w: plaintext over %d bytes", ErrTooLarge, MaxPlaintext)
	}
	var r [8]byte
	if _, err := io.ReadFull(rand, r[:]); err != nil {
		return nil, fmt.Errorf("ping: random: %w", err)
	}
	n := int(binary.BigEndian.Uint64(r[:]) % uint64(maxBytes+1))
	g := make([]byte, n)
	if _, err := io.ReadFull(rand, g); err != nil {
		return nil, fmt.Errorf("ping: random: %w", err)
	}
	plain := header + garbageText(g)

	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand, nonce[:]); err != nil {
		return nil, fmt.Errorf("ping: random: %w", err)
	}
	box := secretbox.Seal(nonce[:], []byte(plain), &nonce, boxKey)
	enc := base64.StdEncoding.EncodeToString(box)

	var out bytes.Buffer
	out.Grow(len(enc) + len(enc)/armorWidth + 128)
	out.WriteString(armorBegin + "\n" + armorVersion + "\n\n")
	for len(enc) > 0 {
		k := min(armorWidth, len(enc))
		out.WriteString(enc[:k] + "\n")
		enc = enc[k:]
	}
	out.WriteString(armorEnd + "\n")
	if out.Len() > MaxSealed {
		return nil, fmt.Errorf("%w: sealed ping of %d bytes", ErrTooLarge, out.Len())
	}
	return out.Bytes(), nil
}

// Open finds the sealed ping in mailBody, opens it with boxKey and
// checks its MAC with macKey.  It copes with what remailers do to a
// body: CRLF line ends, blank lines or spaces added inside the armor
// (the broken middleman workaround, E:Pinger.pm:162-166), the armor
// quoted with "> ", and text before or after it.  If the body has more
// than one armor, the first that opens counts.
//
// A Body from Open was made by us, so Body.Remailer and Body.KeyID name
// the key the ping was encrypted to: its coming back proves that key
// (design §9.2).  The caller looks up Body.ID in its journal and checks
// that address and keyid agree with the entry before counting it.
func Open(macKey, boxKey *[32]byte, mailBody []byte) (Body, error) {
	if len(mailBody) > MaxBody {
		return Body{}, fmt.Errorf("%w: mail body of %d bytes", ErrTooLarge, len(mailBody))
	}
	lines := strings.Split(strings.ReplaceAll(string(mailBody), "\r", ""), "\n")
	for i := range lines {
		lines[i] = unquote(lines[i])
	}
	first := error(ErrNoPing)
	for i := 0; i < len(lines); i++ {
		if lines[i] != armorBegin {
			continue
		}
		b, next, err := openArmor(macKey, boxKey, lines[i+1:])
		if err == nil {
			return b, nil
		}
		if first == ErrNoPing {
			first = err
		}
		i += next
	}
	return Body{}, first
}

// unquote strips the quote marks ("> ", ">", any number) and the spaces
// around a line.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, ">") {
		s = strings.TrimSpace(s[1:])
	}
	return s
}

// openArmor opens the armor whose BEGIN line came just before lines.  It
// also returns how many lines it used.
func openArmor(macKey, boxKey *[32]byte, lines []string) (Body, int, error) {
	i := 0
	for i < len(lines) && lines[i] == "" {
		i++
	}
	if i == len(lines) || lines[i] != armorVersion {
		return Body{}, i, fmt.Errorf("%w: no %q line", ErrMalformed, armorVersion)
	}
	var enc strings.Builder
	for i++; ; i++ {
		if i == len(lines) {
			return Body{}, i, fmt.Errorf("%w: no END line", ErrMalformed)
		}
		if lines[i] == armorEnd {
			break
		}
		for _, f := range strings.Fields(lines[i]) {
			enc.WriteString(f)
		}
	}
	box, err := base64.StdEncoding.DecodeString(enc.String())
	if err != nil {
		return Body{}, i, fmt.Errorf("%w: base64: %v", ErrMalformed, err)
	}
	if len(box) < nonceLen+secretbox.Overhead {
		return Body{}, i, fmt.Errorf("%w: box too short", ErrMalformed)
	}
	if len(box) > nonceLen+secretbox.Overhead+MaxPlaintext {
		return Body{}, i, fmt.Errorf("%w: box of %d bytes", ErrTooLarge, len(box))
	}
	nonce := [nonceLen]byte(box[:nonceLen])
	plain, ok := secretbox.Open(nil, box[nonceLen:], &nonce, boxKey)
	if !ok {
		return Body{}, i, ErrBadBox
	}
	b, err := parseBody(macKey, plain)
	return b, i, err
}
