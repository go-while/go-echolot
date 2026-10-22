package pinger

import (
	"bytes"
	"strings"
)

// noBreaks removes CR and LF, so an address can't add header lines.
var noBreaks = strings.NewReplacer("\r", "", "\n", "")

// Mail returns the mail given to yamn (design §6.3): a From line only
// with withFrom (alternating per 2-hour session, E:Pinger.pm:142), the
// ping token as To, a blank line, and the sealed body.  yamn keeps only
// To and, with --keep-from, From (Y-20, Y-47); everything the receiver
// needs is in the To address and the body.
func Mail(token, from string, withFrom bool, sealed []byte) []byte {
	var b bytes.Buffer
	b.Grow(len(sealed) + len(token) + len(from) + 16)
	if withFrom {
		b.WriteString("From: " + noBreaks.Replace(from) + "\n")
	}
	b.WriteString("To: " + noBreaks.Replace(token) + "\n\n")
	b.Write(sealed)
	return b.Bytes()
}
