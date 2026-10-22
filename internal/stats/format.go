package stats

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// MinHr formats a latency as E:Stats.pm:60-83 make_min_hr: "hh:mm",
// or "hh:mm:ss" with withSec.  No data, a negative latency or more than
// 99 hours give 99:59(:59).
func MinHr(sec *float64, withSec bool) string {
	var h, m, s int64 = 99, 59, 59
	if sec != nil && *sec >= 0 && math.Trunc(*sec/60/60) <= 99 {
		v := *sec
		// Perl's % uses the integer part of a float operand.
		h = int64(v / 60 / 60)
		m = int64(v/60) % 60
		s = int64(v) % 60
	}
	switch {
	case withSec && h != 0:
		return fmt.Sprintf("%2d:%02d:%02d", h, m, s)
	case withSec && m != 0:
		return fmt.Sprintf("   %2d:%02d", m, s)
	case withSec:
		return fmt.Sprintf("      %2d", s)
	case h != 0:
		return fmt.Sprintf("%2d:%02d", h, m)
	default:
		return fmt.Sprintf("  :%02d", m)
	}
}

// history builds a per-day string, oldest day on the left.
func history(days []*float64, none byte, char func(float64) byte) string {
	b := make([]byte, len(days))
	for d, v := range days {
		c := none
		if v != nil {
			c = char(*v)
		}
		b[len(days)-1-d] = c
	}
	return string(b)
}

// latencyEdges are the upper bounds of the mlist2.txt latency alphabet
// (E:Stats.pm:104-133).
var latencyEdges = []struct {
	below float64
	c     byte
}{
	{20 * 60, '0'}, {1 * 3600, '1'}, {2 * 3600, '2'}, {3 * 3600, '3'}, {4 * 3600, '4'},
	{5 * 3600, '5'}, {6 * 3600, '6'}, {7 * 3600, '7'}, {8 * 3600, '8'}, {9 * 3600, '9'},
	{12 * 3600, 'A'}, {18 * 3600, 'B'}, {24 * 3600, 'C'}, {30 * 3600, 'D'},
	{36 * 3600, 'E'}, {42 * 3600, 'F'}, {48 * 3600, 'G'},
}

// LatencyHist is mlist2.txt's latency history of per-day medians
// (E:Stats.pm:104-133): 0 to 9, A to H, '?' for no data.
func LatencyHist(days []*float64) string {
	return history(days, '?', func(v float64) byte {
		for _, e := range latencyEdges {
			if v < e.below {
				return e.c
			}
		}
		return 'H'
	})
}

// UptimeHist is mlist2.txt's reliability history (E:Stats.pm:135-149):
// '+' from 0.9999, else the tenths digit, '?' if nothing was sent.
func UptimeHist(days []*float64) string {
	return history(days, '?', func(v float64) byte {
		if v >= 0.9999 {
			return '+'
		}
		return strconv.Itoa(int(v * 10))[0]
	})
}

// LatencyHist1 is mlist.txt's type-I latency history (E:Stats.pm:86-102):
// # * + - . _ from fast to slow, ' ' for no data.
func LatencyHist1(days []*float64) string {
	return history(days, ' ', func(v float64) byte {
		switch {
		case v < 300:
			return '#'
		case v < 3600:
			return '*'
		case v < 14400:
			return '+'
		case v < 86400:
			return '-'
		case v < 172800:
			return '.'
		}
		return '_'
	})
}

// word matches w as a whole word, ignoring ASCII case only: Perl's /i on
// Echolot's byte strings doesn't fold e.g. the Kelvin sign to k, Go's would.
func word(w string) *regexp.Regexp {
	var b strings.Builder
	esc := false
	for _, c := range w {
		if lc, uc := unicode.ToLower(c), unicode.ToUpper(c); !esc && c < 0x80 && lc != uc {
			fmt.Fprintf(&b, "[%c%c]", lc, uc)
		} else {
			b.WriteRune(c)
		}
		esc = !esc && c == '\\'
	}
	return regexp.MustCompile(`\b` + b.String() + `\b`)
}

type capChar struct {
	re *regexp.Regexp
	c  byte
}

// optionColumns are the options columns but the last; each shows the
// character of its first matching alternative (E:Stats.pm:154-188).
var optionColumns = [][]capChar{
	{{word("middle"), 'D'}},
	{{word("post"), 'P'}, {word("anon-post-to"), 'P'}},
	{{word("remix2"), '2'}, {word("remix"), 'R'}, {word("mix"), 'M'}},
	{{word("hybrid"), 'H'}},
	{{word("repgp2"), '2'}, {word("repgp"), 'G'}},
	{{word("pgponly"), 'O'}},
	{{word("ext"), 'X'}},
	{{word("max"), 'A'}},
	{{word("test"), 'T'}},
	{{word("latent"), 'L'}},
	{{word("ekx"), 'E'}, {word("ek"), 'e'}},
	{{word("esub"), 'U'}},
	{{word(`inflt\d+`), 'I'}},
	{{word(`rhop\d+`), 'N'}},
}

var capKlen = word(`klen(\d+)`)

// Options is mlist2.txt's 15-character options column from a conf caps
// line (E:Stats.pm:151-203), with Echolot's case-insensitive word
// matches over the whole line, address included.
func Options(caps string) string {
	b := make([]byte, 0, len(optionColumns)+1)
	for _, col := range optionColumns {
		c := byte(' ')
		for _, alt := range col {
			if alt.re.MatchString(caps) {
				c = alt.c
				break
			}
		}
		b = append(b, c)
	}
	return string(append(b, klenDigit(caps)))
}

// klenDigit is the hundreds digit of the first klen<n> word, '9' from
// 900 up (E:Stats.pm:189-200).
func klenDigit(caps string) byte {
	m := capKlen.FindStringSubmatch(caps)
	if m == nil {
		return ' '
	}
	n := strings.TrimLeft(m[1], "0")
	if len(n) > 3 {
		return '9'
	}
	v, _ := strconv.Atoi("0" + n)
	return byte('0' + min(v/100, 9))
}
