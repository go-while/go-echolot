package config

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"
)

// The config file format (design §10.3):
//
//	# a comment line
//	[section]
//	key = value        # a comment after a value
//	[peer mixmin]      # a named section; [peer <name>] repeats
//
// A '#' starts a comment at the start of a line, at the start of a value,
// or after a space or tab.  So a value can contain '#' ("a#b") but not
// " #".  Values are not quoted; leading and trailing blanks are dropped.
// Lines may end in CRLF.

// section is one [name] or [name label] block of the file.
type section struct {
	name  string // "pinger", "peer"
	label string // "mixmin" in [peer mixmin]; "" otherwise
	line  int
	keys  []keyValue
}

type keyValue struct {
	key, value string
	line       int
}

// lineError is an error at a line of the config file.
type lineError struct {
	line int
	msg  string
}

func (e *lineError) Error() string { return fmt.Sprintf("line %d: %s", e.line, e.msg) }

func errorAt(line int, format string, args ...any) error {
	return &lineError{line: line, msg: fmt.Sprintf(format, args...)}
}

// parseINI splits data into sections.  It checks only the syntax; which
// sections and keys exist is up to decode.
func parseINI(data []byte) ([]section, []error) {
	var (
		secs []section
		errs []error
	)
	data = bytes.TrimPrefix(data, []byte("\uFEFF"))
	for i, raw := range strings.Split(string(data), "\n") {
		n := i + 1
		line := strings.TrimSuffix(raw, "\r")
		if !utf8.ValidString(line) {
			errs = append(errs, errorAt(n, "not valid UTF-8"))
			continue
		}
		if strings.ContainsFunc(line, func(r rune) bool { return r < ' ' && r != '\t' || r == 0x7f }) {
			errs = append(errs, errorAt(n, "control character"))
			continue
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line[0] == '#':
		case line[0] == '[':
			s, err := parseHeader(line, n)
			if err != nil {
				errs = append(errs, err)
				// Skip the keys of a broken header: they'd only add noise.
				s = section{line: n}
			}
			secs = append(secs, s)
		default:
			key, value, ok := strings.Cut(line, "=")
			key = strings.TrimSpace(key)
			switch {
			case !ok:
				errs = append(errs, errorAt(n, "expected key = value or [section], got %q", line))
			case !isName(key):
				errs = append(errs, errorAt(n, "bad key %q: use a-z, 0-9 and _", key))
			case len(secs) == 0:
				errs = append(errs, errorAt(n, "key %q before the first [section]", key))
			case secs[len(secs)-1].name == "":
				// Inside a broken header, already reported.
			default:
				s := &secs[len(secs)-1]
				s.keys = append(s.keys, keyValue{key: key, value: stripComment(value), line: n})
			}
		}
	}
	return secs, errs
}

// parseHeader parses "[name]" or "[name label]", with an optional comment
// after the bracket.
func parseHeader(line string, n int) (section, error) {
	inner, rest, ok := strings.Cut(line[1:], "]")
	if rest = strings.TrimSpace(rest); !ok || rest != "" && rest[0] != '#' {
		return section{}, errorAt(n, "bad section header %q", line)
	}
	f := strings.Fields(inner)
	if len(f) == 0 || len(f) > 2 || !isName(f[0]) {
		return section{}, errorAt(n, "bad section header %q", line)
	}
	s := section{name: f[0], line: n}
	if len(f) == 2 {
		s.label = f[1]
	}
	return s, nil
}

// stripComment returns the value without a trailing comment and blanks.
func stripComment(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "#") {
		return ""
	}
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return strings.TrimSpace(v[:i])
		}
	}
	return v
}

// isName reports whether s is a section or key name: [a-z0-9_]+.
func isName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !('a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}
