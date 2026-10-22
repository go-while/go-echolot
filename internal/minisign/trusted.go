package minisign

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Trusted is the trusted comment of a pinger's signature: the contract
// between go-echolot and yamn's verifier (design §9.5).
//
//	trusted = pair *( SP pair )          ; one space between pairs
//	pair    = key ":" value              ; any order, each key at most once
//	key     = 1*( %x61-7A / DIGIT / "_" ) ; a-z, 0-9, _
//	value   = 1*( %x21-7E )              ; printable ASCII, no space
//
// Required keys: timestamp and expires, in Unix seconds UTC (1 to 18
// decimal digits), and file, the published file's base name.  Optional: pinger,
// the pinger's name, for people.  A reader ignores keys it doesn't know.
type Trusted struct {
	Timestamp time.Time // when it was signed; never goes backwards per file
	File      string    // base name: pubring.mix, type2.list, mlist2.txt, ...
	Expires   time.Time
	Pinger    string // optional
}

// String returns the trusted comment: timestamp, file, pinger (if set),
// expires.
func (t Trusted) String() string {
	s := fmt.Sprintf("timestamp:%d file:%s", t.Timestamp.Unix(), t.File)
	if t.Pinger != "" {
		s += " pinger:" + t.Pinger
	}
	return s + fmt.Sprintf(" expires:%d", t.Expires.Unix())
}

// ValidValue reports whether s may be a value in a trusted comment.
func ValidValue(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validKey reports whether s may be a key.
func validKey(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// Check returns an error if t can't be written as a trusted comment.
func (t Trusted) Check() error {
	switch {
	case !ValidValue(t.File) || strings.Contains(t.File, "/"):
		return fmt.Errorf("minisign: file %q must be a base name without spaces", t.File)
	case t.Pinger != "" && !ValidValue(t.Pinger):
		return fmt.Errorf("minisign: pinger %q must be printable ASCII without spaces", t.Pinger)
	case t.Timestamp.Unix() < 0:
		return errors.New("minisign: timestamp before 1970")
	case !t.Expires.After(t.Timestamp):
		return errors.New("minisign: expires must be after timestamp")
	}
	return nil
}

// unixSeconds parses decimal Unix seconds.
func unixSeconds(s string) (time.Time, bool) {
	if s == "" || len(s) > 18 {
		return time.Time{}, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return time.Time{}, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return time.Unix(n, 0).UTC(), err == nil
}

// ParseTrusted reads a trusted comment by the grammar of Trusted.
func ParseTrusted(s string) (Trusted, error) {
	var t Trusted
	seen := map[string]bool{}
	for _, pair := range strings.Split(s, " ") {
		k, v, ok := strings.Cut(pair, ":")
		if !ok || !validKey(k) || !ValidValue(v) {
			return Trusted{}, fmt.Errorf("minisign: trusted comment: bad pair %q", pair)
		}
		if seen[k] {
			return Trusted{}, fmt.Errorf("minisign: trusted comment: %s twice", k)
		}
		seen[k] = true
		switch k {
		case "timestamp", "expires":
			u, ok := unixSeconds(v)
			if !ok {
				return Trusted{}, fmt.Errorf("minisign: trusted comment: %s %q is not Unix seconds", k, v)
			}
			if k == "timestamp" {
				t.Timestamp = u
			} else {
				t.Expires = u
			}
		case "file":
			t.File = v
		case "pinger":
			t.Pinger = v
		}
	}
	for _, k := range []string{"timestamp", "file", "expires"} {
		if !seen[k] {
			return Trusted{}, fmt.Errorf("minisign: trusted comment: no %s", k)
		}
	}
	if err := t.Check(); err != nil {
		return Trusted{}, err
	}
	return t, nil
}

// Errors of VerifyFile.
var (
	ErrWrongFile = errors.New("minisign: signature is for another file")
	ErrExpired   = errors.New("minisign: signature expired")
)

// VerifyFile verifies a published file, as yamn does (design §9.5): p
// signed data with sig, the trusted comment follows the contract, its
// file is name, and it hasn't expired at now.  It returns the comment
// also when the only error is ErrExpired.
func VerifyFile(p PublicKey, name string, data, sig []byte, now time.Time) (Trusted, error) {
	c, err := Verify(p, data, sig)
	if err != nil {
		return Trusted{}, err
	}
	t, err := ParseTrusted(c)
	if err != nil {
		return Trusted{}, err
	}
	if t.File != name {
		return Trusted{}, fmt.Errorf("%w: %s, not %s", ErrWrongFile, t.File, name)
	}
	if !now.Before(t.Expires) {
		return t, fmt.Errorf("%w at %s", ErrExpired, t.Expires.Format(time.RFC3339))
	}
	return t, nil
}
