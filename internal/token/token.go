// Package token makes and checks the reply addresses go-echolot sends
// from (design §6.1), and derives its keys from the secret.
//
// A reply address has Echolot's shape:
//
//	<local><delim><kind>[.<id>]=<unixtime>=<mac>@<domain>
//	pinger+key.12=1792560000=3f9a0c51d2e47b08@pinger.example.org
//
// or, with an empty delimiter, <local>@<domain>(<kind>[.<id>]=<unixtime>=<mac>).
// mac is the first 16 hex digits of HMAC-SHA256 over "<kind>[.<id>]=<unixtime>".
package token

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Kind says what a reply is to.
type Kind string

const (
	KindConf      Kind = "conf"      // remailer-conf request
	KindKey       Kind = "key"       // remailer-key request
	KindHelp      Kind = "help"      // remailer-help request
	KindAdminkey  Kind = "adminkey"  // remailer-adminkey request
	KindBounce    Kind = "bounce"    // envelope sender of mail to a remailer (VERP)
	KindPing      Kind = "ping"      // a ping coming back
	KindChainping Kind = "chainping" // a chain ping coming back (phase 3)
)

// Limits on a token's time (design §6.1).
const (
	MaxFuture     = time.Hour          // clock skew allowed
	RequestMaxAge = 7 * 24 * time.Hour // requests and bounces
	PingMaxAge    = 12 * 24 * time.Hour
)

// MACLen is the number of hex digits of the MAC in an address.
const MACLen = 16

// legacyMACLen is Echolot's hash_len (E:Config.pm:88).
const legacyMACLen = 8

// valid reports whether k is a kind this package knows.
func (k Kind) valid() bool {
	switch k {
	case KindConf, KindKey, KindHelp, KindAdminkey, KindBounce, KindPing, KindChainping:
		return true
	}
	return false
}

// HasID reports whether tokens of kind k carry a remailer ID.
func (k Kind) HasID() bool { return k != KindPing && k != KindChainping }

// IsRequest reports whether k is the reply to a request mail.
func (k Kind) IsRequest() bool {
	return k == KindConf || k == KindKey || k == KindHelp || k == KindAdminkey
}

// MaxAge is how old a token of kind k may be.
func (k Kind) MaxAge() time.Duration {
	if k == KindPing || k == KindChainping {
		return PingMaxAge
	}
	return RequestMaxAge
}

// Token is what a reply address says.
type Token struct {
	Kind   Kind
	ID     int       // remailer ID; 0 for pings
	Time   time.Time // when it was made, whole seconds
	Legacy bool      // an Echolot MD5 token (Verify only)
}

// String returns "<kind>[.<id>]=<unixtime>", the text the MAC covers.
func (t Token) String() string {
	if t.Kind.HasID() {
		return fmt.Sprintf("%s.%d=%d", t.Kind, t.ID, t.Time.Unix())
	}
	return fmt.Sprintf("%s=%d", t.Kind, t.Time.Unix())
}

// Errors of Verify.
var (
	ErrNoToken = errors.New("no reply token in address")
	ErrBadMAC  = errors.New("reply token: wrong MAC")
	ErrTooOld  = errors.New("reply token: too old")
	ErrFuture  = errors.New("reply token: time in the future")
)

// Config is what a Minter needs.
type Config struct {
	Secret    []byte // the 32-byte secret of the state dir
	Address   string // pinger.address: local@domain
	Delimiter string // pinger.recipient_delimiter: "+", "-" or ""

	// Echolot's secret (32 hex digits) and until when its MD5 tokens are
	// accepted on request replies, after an import (design §5.5).
	LegacySecret string
	LegacyUntil  time.Time
}

// Minter makes and checks reply addresses.
type Minter struct {
	key          [32]byte
	local        string // as configured, for Address
	localLower   string // for Verify
	domain       string
	delim        string
	legacySecret string
	legacyUntil  time.Time
	delimRE      *regexp.Regexp // nil without a delimiter
}

// The token text: kind, optional id, time, mac.  IDs and times are
// limited in length so they can't overflow.
const tokenRE = `([a-z]+)(?:\.([0-9]{1,9}))?=([0-9]{1,12})=([0-9a-f]{8,64})`

// parenRE matches local@domain(token), Echolot's form without a delimiter,
// which Echolot also accepts with one (E:Tools.pm:124-131).
var parenRE = regexp.MustCompile(`([a-z0-9._-]+)@[a-z0-9.-]+[ \t]*\(` + tokenRE + `\)`)

// New returns a Minter for c.
func New(c Config) (*Minter, error) {
	if len(c.Secret) != 32 {
		return nil, fmt.Errorf("token: secret is %d bytes, want 32", len(c.Secret))
	}
	local, domain, ok := strings.Cut(c.Address, "@")
	if !ok || local == "" || domain == "" {
		return nil, fmt.Errorf("token: address %q isn't local@domain", c.Address)
	}
	if c.Delimiter != "" && c.Delimiter != "+" && c.Delimiter != "-" {
		return nil, fmt.Errorf("token: delimiter %q", c.Delimiter)
	}
	if c.LegacySecret != "" {
		if b, err := hex.DecodeString(c.LegacySecret); err != nil || len(b) != 16 || strings.ToLower(c.LegacySecret) != c.LegacySecret {
			return nil, errors.New("token: Echolot's secret must be 32 lower-case hex digits")
		}
	}
	m := &Minter{
		key:          DeriveKey(c.Secret, PurposeToken),
		local:        local,
		localLower:   strings.ToLower(local),
		domain:       domain,
		delim:        c.Delimiter,
		legacySecret: c.LegacySecret,
		legacyUntil:  c.LegacyUntil,
	}
	if c.Delimiter != "" {
		m.delimRE = regexp.MustCompile(`([a-z0-9._-]+)` + regexp.QuoteMeta(c.Delimiter) + tokenRE + `@`)
	}
	return m, nil
}

// Address returns the reply address for t.  Its time is cut to seconds.
func (m *Minter) Address(t Token) (string, error) {
	if !t.Kind.valid() {
		return "", fmt.Errorf("token: unknown kind %q", t.Kind)
	}
	if t.Kind.HasID() && t.ID <= 0 || !t.Kind.HasID() && t.ID != 0 {
		return "", fmt.Errorf("token: kind %s with ID %d", t.Kind, t.ID)
	}
	if t.Time.Unix() <= 0 {
		return "", errors.New("token: no time")
	}
	text := t.String()
	full := text + "=" + m.mac(text)
	if m.delim == "" {
		return m.local + "@" + m.domain + "(" + full + ")", nil
	}
	return m.local + m.delim + full + "@" + m.domain, nil
}

func (m *Minter) mac(text string) string {
	h := hmac.New(sha256.New, m.key[:])
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))[:MACLen]
}

func (m *Minter) legacyMAC(text string) string {
	sum := md5.Sum([]byte(text + m.legacySecret)) // E:Tools.pm:94-145
	return hex.EncodeToString(sum[:])[:legacyMACLen]
}

// Verify finds a reply token of ours in addr and checks it at time now.
// addr is a recipient as in X-Original-To, Delivered-To or To; it may
// have a display name or several addresses.  Case doesn't matter, as
// some MTAs lower-case addresses.  The domain isn't checked: mail can
// reach us under another name, and the MAC is what counts.
func (m *Minter) Verify(addr string, now time.Time) (Token, error) {
	addr = strings.ToLower(addr)
	var matches [][]string
	if m.delimRE != nil {
		matches = m.delimRE.FindAllStringSubmatch(addr, -1)
	}
	matches = append(matches, parenRE.FindAllStringSubmatch(addr, -1)...)
	firstErr := ErrNoToken
	for _, sm := range matches {
		if sm[1] != m.localLower {
			continue
		}
		tok, err := m.check(sm[2], sm[3], sm[4], sm[5], now)
		if err == nil {
			return tok, nil
		}
		if firstErr == ErrNoToken {
			firstErr = err
		}
	}
	return Token{}, firstErr
}

// check verifies one token found by Verify.
func (m *Minter) check(kind, id, unix, mac string, now time.Time) (Token, error) {
	t := Token{Kind: Kind(kind)}
	if !t.Kind.valid() || t.Kind.HasID() != (id != "") {
		return Token{}, fmt.Errorf("%w: %s", ErrNoToken, kind)
	}
	text := kind + "=" + unix
	if id != "" {
		text = kind + "." + id + "=" + unix
	}
	switch {
	case len(mac) == MACLen && subtle.ConstantTimeCompare([]byte(mac), []byte(m.mac(text))) == 1:
	case len(mac) == legacyMACLen && m.legacySecret != "" && t.Kind.IsRequest() && now.Before(m.legacyUntil) &&
		subtle.ConstantTimeCompare([]byte(mac), []byte(m.legacyMAC(text))) == 1:
		t.Legacy = true
	default:
		return Token{}, ErrBadMAC
	}
	// Both parse: the regexp limits them to 9 and 12 digits.
	t.ID, _ = strconv.Atoi(id)
	sec, _ := strconv.ParseInt(unix, 10, 64)
	t.Time = time.Unix(sec, 0).UTC()
	if t.Time.After(now.Add(MaxFuture)) {
		return Token{}, ErrFuture
	}
	if now.Sub(t.Time) > t.Kind.MaxAge() {
		return Token{}, ErrTooOld
	}
	return t, nil
}

// Purposes of the keys derived from the secret (design §6.1).
const (
	PurposeToken   = "token"    // reply-address MACs
	PurposePingMAC = "ping-mac" // MAC of the ping body
	PurposePingBox = "ping-box" // secretbox key of the ping body
	PurposeSched   = "sched"    // scheduling slots (§8.3)
)

// DeriveKey returns the key for purpose:
// HKDF-SHA256(secret, salt "go-echolot", info "v1 "+purpose).
func DeriveKey(secret []byte, purpose string) [32]byte {
	b, err := hkdf.Key(sha256.New, secret, []byte("go-echolot"), "v1 "+purpose, 32)
	if err != nil {
		panic(err) // only for lengths over 255*32
	}
	return [32]byte(b)
}
