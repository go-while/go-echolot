package replies

import (
	"errors"
	"regexp"
	"strings"
)

const supportedHeader = "SUPPORTED MIXMASTER (TYPE II) REMAILERS"

// capsLine is design §6.4's caps regex; the nick and address are checked
// with ValidName and ValidAddress afterwards.
var capsLine = regexp.MustCompile(`^\s*\$remailer\{"([^"]*)"\}\s*=\s*"<([^>]*)>([^"]*)";\s*$`)

// ParseConf parses a remailer-conf reply (Y:server.go, E:Conf.pm:138-206):
// the first Remailer-Type line, the first valid caps line, and the summary
// lines of the first SUPPORTED MIXMASTER (TYPE II) REMAILERS list.  The
// list runs until the first line that doesn't have seven fields; summary
// lines that fail ParseSummary are skipped.  A reply without a valid caps
// line is an error.
func ParseConf(body []byte) (*ConfReply, error) {
	c := &ConfReply{}
	haveCaps, inList, listDone := false, false, false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if inList {
			if !isSummaryShape(line) {
				inList, listDone = false, true
			} else {
				if s, err := ParseSummary(line); err == nil {
					c.Supported = append(c.Supported, s)
				}
				continue
			}
		}
		switch {
		case !listDone && strings.TrimSpace(line) == supportedHeader:
			inList = true
		case c.Type == "" && hasPrefixFold(strings.TrimSpace(line), "Remailer-Type:"):
			t := strings.TrimSpace(strings.TrimSpace(line)[len("Remailer-Type:"):])
			if printableText(t) {
				c.Type = t
			}
		case !haveCaps:
			if nick, addr, opts, ok := parseCaps(line); ok {
				c.Nick, c.Address, c.Options = nick, addr, opts
				c.Caps = capsString(nick, addr, opts)
				haveCaps = true
			}
		}
	}
	if !haveCaps {
		return nil, errors.New("no valid $remailer{...} caps line")
	}
	return c, nil
}

// parseCaps parses a $remailer{"nick"} = "<address> options"; line.  The
// options are returned with runs of white space made single spaces.
func parseCaps(line string) (nick, addr, opts string, ok bool) {
	m := capsLine.FindStringSubmatch(line)
	if m == nil || !ValidName(m[1]) || !ValidAddress(m[2]) {
		return "", "", "", false
	}
	opts = strings.Join(strings.Fields(m[3]), " ")
	if opts != "" && !printableText(opts) {
		return "", "", "", false
	}
	return m[1], m[2], opts, true
}

// capsString is the canonical caps line.
func capsString(nick, addr, opts string) string {
	if opts != "" {
		opts = " " + opts
	}
	return `$remailer{"` + nick + `"} = "<` + addr + `>` + opts + `";`
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// printableText reports whether s is non-empty printable ASCII; spaces are
// allowed.
func printableText(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
