package replies

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
)

// Body returns the text of a reply ready for ParseKey and ParseConf: the
// Content-Transfer-Encoding undone (yamn sends plain text, so this is
// defensive), CRLF and lone CR turned into LF (the CRLF hazard, design
// §2.2), and PGP dash-escaping undone (a leading "- " removed,
// E:Conf.pm:457).
func Body(h mail.Header, body []byte) ([]byte, error) {
	cte := strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding")))
	switch cte {
	case "", "7bit", "8bit", "binary":
	case "quoted-printable":
		b, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, fmt.Errorf("quoted-printable body: %w", err)
		}
		body = b
	case "base64":
		clean := bytes.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, body)
		b := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
		n, err := base64.StdEncoding.Decode(b, clean)
		if err != nil {
			return nil, fmt.Errorf("base64 body: %w", err)
		}
		body = b[:n]
	default:
		return nil, fmt.Errorf("unknown content-transfer-encoding %q", cte)
	}

	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))
	body = bytes.ReplaceAll(body, []byte("\r"), []byte("\n"))

	lines := bytes.Split(body, []byte("\n"))
	for i, l := range lines {
		lines[i] = bytes.TrimPrefix(l, []byte("- "))
	}
	return bytes.Join(lines, []byte("\n")), nil
}

var notARemailer = regexp.MustCompile(`(?i)\A\s*not\s+a\s+remailer\b`)

// IsNotARemailer reports whether the reply starts with "not a remailer"
// (E:Conf.pm:47-54).
func IsNotARemailer(body []byte) bool {
	return notARemailer.Match(body)
}
