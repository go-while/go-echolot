package mailout

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// maxSubject bounds the Subject of a request ("remailer-adminkey" is 17).
const maxSubject = 200

// ComposeRequest returns a request mail (design §6.2): From, To, Subject,
// Date (UTC, +0000), Message-ID (<time.random@msgIDDomain>), MIME-Version
// and Content-Type text/plain us-ascii, then body.  Lines end in LF; the
// SMTP client sends them as CRLF, sendmail -i wants LF.
//
// Every field is checked: from and to must be plain addresses, subject
// printable ASCII, msgIDDomain a host name, body US-ASCII without NUL.
// So no CR or LF ever gets into a header.
func ComposeRequest(from, to, subject string, body []byte, now time.Time, msgIDDomain string) ([]byte, error) {
	if err := checkAddress("From", from); err != nil {
		return nil, err
	}
	if err := checkAddress("To", to); err != nil {
		return nil, err
	}
	if subject == "" || len(subject) > maxSubject ||
		strings.ContainsFunc(subject, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return nil, fmt.Errorf("%w: Subject %q must be 1 to %d printable ASCII characters", ErrInvalid, subject, maxSubject)
	}
	if !validHost(msgIDDomain) {
		return nil, fmt.Errorf("%w: Message-ID domain %q is not a host name", ErrInvalid, msgIDDomain)
	}
	for _, c := range body {
		if c == 0 || c > 0x7f {
			return nil, fmt.Errorf("%w: the body must be US-ASCII without NUL", ErrInvalid)
		}
	}
	body = toLF(body)

	rnd := make([]byte, 8)
	rand.Read(rnd) // never fails (crypto/rand since Go 1.24)
	now = now.UTC()

	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\n", from)
	fmt.Fprintf(&b, "To: %s\n", to)
	fmt.Fprintf(&b, "Subject: %s\n", subject)
	fmt.Fprintf(&b, "Date: %s\n", now.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	fmt.Fprintf(&b, "Message-ID: <%s.%s@%s>\n", now.Format("20060102150405"), hex.EncodeToString(rnd), msgIDDomain)
	b.WriteString("MIME-Version: 1.0\n")
	b.WriteString("Content-Type: text/plain; charset=us-ascii\n")
	b.WriteString("\n")
	b.Write(body)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// RequestText is the body of a request mail, Echolot's remailerxxxtext
// (E:Config.pm:224-236) with address (the remailer's) and
// operatorAddress filled in.
func RequestText(address, operatorAddress string) []byte {
	return []byte("Hello,\n" +
		"\n" +
		"This message requests remailer configuration data. The pinging software thinks\n" +
		address + " is a remailer. Either it has been told so by the\n" +
		"maintainer of the pinger or it found the address in a remailer-conf or\n" +
		"remailer-key reply of some other remailer.\n" +
		"\n" +
		"If this is _not_ a remailer, you can tell this pinger that and it will stop\n" +
		"sending you those requests immediately (otherwise it will try a few more times).\n" +
		"Just reply and make sure the following is the first line of your message:\n" +
		"\tnot a remailer\n" +
		"\n" +
		"If you want to talk to a human please mail " + operatorAddress + ".\n")
}
