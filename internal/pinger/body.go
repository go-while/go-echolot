// Package pinger builds pings, has yamn encrypt them, and opens the ones
// that come back (design §6.3).
//
// A ping is a small plaintext (Body) sealed with NaCl secretbox under a
// key only this pinger has, put in a mail to one of our ping tokens, and
// encrypted with yamn to the key being tested.  When it comes back, Open
// proves two things: that we made it (box and MAC), and which key it was
// encrypted to (Body.KeyID).  The second is the proof of possession of
// design §9.2: only the holder of that key's secret could have sent it on.
package pinger

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/replies"
)

// TypeMix is the only ping type: a yamn (Mixmaster v2 style) key.
const TypeMix = "mix"

// Body is what a ping says (design §6.3).
type Body struct {
	Remailer string    // the address the ping went to
	Type     string    // TypeMix
	KeyID    string    // the key it was encrypted to, 32 hex digits
	WithFrom bool      // the mail given to yamn had a From line (E:Pinger.pm:142)
	Sent     time.Time // when it was made; whole seconds
	ID       uint64    // the journal's ping ID
}

// Errors of Seal and Open.  Use errors.Is.
var (
	ErrNoPing    = errors.New("no ping armor found")
	ErrTooLarge  = errors.New("ping too large")
	ErrBadBox    = errors.New("ping box does not open") // wrong key or tampered
	ErrBadMAC    = errors.New("ping MAC mismatch")
	ErrMalformed = errors.New("malformed ping")
)

// Lines of the plaintext.
const (
	garbageBegin = "-----BEGIN GARBAGE-----"
	garbageEnd   = "-----END GARBAGE-----"
	garbageWidth = 64 // hex digits per line (E:Tools.pm:436)
)

// check reports whether b can be sealed: every field is one the MAC
// input can't confuse with another (no ":" or line break in any value).
func (b Body) check() error {
	switch {
	case !replies.ValidAddress(b.Remailer):
		return fmt.Errorf("%w: bad remailer address %q", ErrMalformed, b.Remailer)
	case b.Type != TypeMix:
		return fmt.Errorf("%w: unknown type %q", ErrMalformed, b.Type)
	case !isKeyID(b.KeyID):
		return fmt.Errorf("%w: bad keyid %q", ErrMalformed, b.KeyID)
	case b.Sent.Unix() <= 0:
		return fmt.Errorf("%w: no sent time", ErrMalformed)
	case b.ID == 0:
		return fmt.Errorf("%w: no ping id", ErrMalformed)
	}
	return nil
}

// isKeyID reports whether s is 32 lower-case hex digits.
func isKeyID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func boolDigit(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// mac returns hex(HMAC-SHA256(key, "v1:"+remailer+":"+type+":"+key+":"+
// with_from+":"+sent+":"+id)), design §6.3.
func (b Body) mac(key *[32]byte) string {
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte("v1:" + b.Remailer + ":" + b.Type + ":" + b.KeyID + ":" +
		boolDigit(b.WithFrom) + ":" + strconv.FormatInt(b.Sent.Unix(), 10) + ":" +
		strconv.FormatUint(b.ID, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// header returns the fields of the plaintext, up to and including the
// mac line.
func (b Body) header(macKey *[32]byte) string {
	return "remailer: " + b.Remailer + "\n" +
		"type: " + b.Type + "\n" +
		"key: " + b.KeyID + "\n" +
		"with_from: " + boolDigit(b.WithFrom) + "\n" +
		"sent: " + strconv.FormatInt(b.Sent.Unix(), 10) + "\n" +
		"id: " + strconv.FormatUint(b.ID, 10) + "\n" +
		"mac: " + b.mac(macKey) + "\n"
}

// garbageText returns the garbage block for random bytes g: hex, 64
// digits per line, between the BEGIN and END lines (E:Tools.pm:415-442).
func garbageText(g []byte) string {
	h := hex.EncodeToString(g)
	var s strings.Builder
	s.Grow(len(h) + len(h)/garbageWidth + len(garbageBegin) + len(garbageEnd) + 4)
	s.WriteString(garbageBegin + "\n")
	for len(h) > 0 {
		n := min(garbageWidth, len(h))
		s.WriteString(h[:n] + "\n")
		h = h[n:]
	}
	s.WriteString(garbageEnd + "\n")
	return s.String()
}

// garbageSize is the length of garbageText for n random bytes.
func garbageSize(n int) int {
	h := 2 * n
	return len(garbageBegin) + 1 + h + (h+garbageWidth-1)/garbageWidth + len(garbageEnd) + 1
}

// parseBody reads a plaintext made by Body.header and garbageText, and
// checks its MAC.  The plaintext comes out of an authenticated box, so
// it is parsed strictly.
func parseBody(macKey *[32]byte, plain []byte) (Body, error) {
	lines := strings.Split(string(plain), "\n")
	names := []string{"remailer", "type", "key", "with_from", "sent", "id", "mac"}
	if len(lines) < len(names)+3 {
		return Body{}, fmt.Errorf("%w: too few lines", ErrMalformed)
	}
	vals := make([]string, len(names))
	for i, name := range names {
		v, ok := strings.CutPrefix(lines[i], name+": ")
		if !ok {
			return Body{}, fmt.Errorf("%w: line %d is not %q", ErrMalformed, i+1, name)
		}
		vals[i] = v
	}
	rest := lines[len(names):]
	if rest[0] != garbageBegin || rest[len(rest)-2] != garbageEnd || rest[len(rest)-1] != "" {
		return Body{}, fmt.Errorf("%w: no garbage block", ErrMalformed)
	}
	sent, err := strconv.ParseInt(vals[4], 10, 64)
	if err != nil {
		return Body{}, fmt.Errorf("%w: sent: %v", ErrMalformed, err)
	}
	id, err := strconv.ParseUint(vals[5], 10, 64)
	if err != nil {
		return Body{}, fmt.Errorf("%w: id: %v", ErrMalformed, err)
	}
	if vals[3] != "0" && vals[3] != "1" {
		return Body{}, fmt.Errorf("%w: with_from %q", ErrMalformed, vals[3])
	}
	b := Body{
		Remailer: vals[0],
		Type:     vals[1],
		KeyID:    vals[2],
		WithFrom: vals[3] == "1",
		Sent:     time.Unix(sent, 0).UTC(),
		ID:       id,
	}
	if err := b.check(); err != nil {
		return Body{}, err
	}
	// Constant time, though the box already authenticated it.
	if !hmac.Equal([]byte(b.mac(macKey)), []byte(vals[6])) {
		return Body{}, ErrBadMAC
	}
	return b, nil
}
