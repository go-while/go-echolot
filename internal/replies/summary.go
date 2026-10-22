package replies

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-while/go-echolot/internal/civil"
)

// ParseSummary parses a key header line as yamn's readPubring does
// (Y:keymgr/public.go): strings.Split on single spaces must give exactly
// seven fields.  Stricter than yamn: no field may be empty, version and
// caps must be printable ASCII, and nick, version and caps have length
// limits (see maxFieldLen).  The keyid may be upper case (yamn's
// hex.DecodeString takes it) and is returned in lower case.
func ParseSummary(line string) (SummaryLine, error) {
	return parseFields(strings.Split(line, " "))
}

// isSummaryShape reports whether yamn would take line for a header line.
func isSummaryShape(line string) bool {
	return strings.Count(line, " ") == 6
}

func parseFields(f []string) (SummaryLine, error) {
	if len(f) != 7 {
		return SummaryLine{}, fmt.Errorf("summary line has %d fields, want 7", len(f))
	}
	if len(f[0]) > maxNickLen {
		return SummaryLine{}, fmt.Errorf("remailer name is longer than %d bytes", maxNickLen)
	}
	if !ValidName(f[0]) {
		return SummaryLine{}, fmt.Errorf("invalid remailer name %q", f[0])
	}
	nick := f[0]
	for i, v := range f[1:] {
		if v == "" {
			return SummaryLine{}, fmt.Errorf("%s: field %d of summary line is empty", nick, i+2)
		}
	}
	if !ValidAddress(f[1]) {
		return SummaryLine{}, fmt.Errorf("%s: invalid address %q", nick, f[1])
	}
	keyid, ok := hexID(f[2])
	if !ok {
		return SummaryLine{}, fmt.Errorf("%s: keyid %q is not 32 hex digits", nick, f[2])
	}
	for i, name := range []string{"version", "caps"} {
		if v := f[3+i]; len(v) > maxFieldLen {
			return SummaryLine{}, fmt.Errorf("%s: %s is longer than %d bytes", nick, name, maxFieldLen)
		}
	}
	if !printable(f[3]) {
		return SummaryLine{}, fmt.Errorf("%s: invalid version %q", nick, f[3])
	}
	if !printable(f[4]) {
		return SummaryLine{}, fmt.Errorf("%s: invalid caps %q", nick, f[4])
	}
	created, err := civil.Parse(f[5])
	if err != nil {
		return SummaryLine{}, fmt.Errorf("%s: created date: %w", nick, err)
	}
	expires, err := civil.Parse(f[6])
	if err != nil {
		return SummaryLine{}, fmt.Errorf("%s: expiry date: %w", nick, err)
	}
	return SummaryLine{
		Nick:    nick,
		Address: f[1],
		KeyID:   keyid,
		Version: f[3],
		Caps:    f[4],
		Created: created,
		Expires: expires,
	}, nil
}

// hexID returns s in lower case if it is 32 hex digits.
func hexID(s string) (string, bool) {
	if len(s) != 32 {
		return "", false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", false
	}
	return strings.ToLower(s), true
}

// printable reports whether s is non-empty printable ASCII without spaces.
func printable(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
