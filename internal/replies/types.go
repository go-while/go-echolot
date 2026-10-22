// Package replies parses what yamn remailers send back: remailer-key and
// remailer-conf replies (design §6.4).  The key format is also that of
// pubring.mix, so ParseKey reads pinger pubrings too.
//
// The rule: never accept what a yamn client would reject
// (Y:keymgr/public.go readPubring, ValidName, ValidAddress, makeKeyID).
// A key go-echolot publishes but yamn rejects is silently dropped by every
// client.  Being stricter than yamn is fine.
package replies

import (
	"fmt"
	"strings"

	"github.com/go-while/go-echolot/internal/civil"
)

// SummaryLine is a key header line, as in pubring.mix and the supported
// list of a conf reply:
//
//	victor yamn@virebent.art dd34d8b7f010229bb790a2402c9ffe65 4:0.2c M 2026-10-17 2026-10-31
type SummaryLine struct {
	Nick    string // ValidName; may be longer than 12 (the keys policy quarantines those)
	Address string // ValidAddress
	KeyID   string // 32 lower-case hex digits
	Version string // e.g. "4:0.2c"
	Caps    string // e.g. "M" (middle) or "E" (exit)
	Created civil.Date
	Expires civil.Date
}

// String returns the line in canonical form: the seven fields, one space
// apart.  Output files are written from this, never from the input text.
func (s SummaryLine) String() string {
	return fmt.Sprintf("%s %s %s %s %s %s %s", s.Nick, s.Address, s.KeyID, s.Version, s.Caps, s.Created, s.Expires)
}

// ParsedKey is a key from a key block that passed every check yamn makes:
// the block's keyid equals the summary line's, and is BLAKE2s-128 of PK.
// Dates aren't checked against today here; that's the keys package.
type ParsedKey struct {
	SummaryLine
	PK [32]byte
}

// KeyReply is the result of ParseKey.
type KeyReply struct {
	Keys   []ParsedKey
	Errors []error // keys that were skipped, and why; for the log
}

// ConfReply is the result of ParseConf.
type ConfReply struct {
	Type      string        // "Remailer-Type:" value, e.g. "Mixmaster 0.2c"
	Nick      string        // from the caps line
	Address   string        // from the caps line
	Options   string        // caps after the address, e.g. "middle v2"
	Caps      string        // the whole $remailer{...}; line, canonical
	Supported []SummaryLine // SUPPORTED MIXMASTER (TYPE II) REMAILERS
}

// maxAddressLen is yamn's maxAddyLen: the size of the next-hop field
// (Y:keymgr/secret.go:18).
const maxAddressLen = 52

// ValidName reports whether name can be a remailer name, as yamn's
// ValidName: lower-case letters and digits, not empty.  Upper case is
// rejected, not lower-cased.  yamn has no length limit.
func ValidName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// ValidAddress reports whether addr can be a remailer address, as yamn's
// ValidAddress: one local@domain of at most 52 bytes, printable ASCII,
// no spaces and none of "(),:;<>[\].
func ValidAddress(addr string) bool {
	if len(addr) > maxAddressLen {
		return false
	}
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`"(),:;<>[\]`, c) >= 0 {
			return false
		}
	}
	return true
}
