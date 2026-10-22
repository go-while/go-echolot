package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseINI(t *testing.T) {
	in := "\uFEFF# comment\r\n" +
		"  # indented comment\n" +
		"\n" +
		"[pinger]   # comment after a header\r\n" +
		"sitename = Pinger#1 at example   # comment\n" +
		"empty =\n" +
		"hash_first = # only a comment\n" +
		"nospace=#x\n" +
		"tab = a\t# comment\n" +
		"eq = a=b\n" +
		"[peer  mixmin ]\n" +
		"mlist2 = https://example.org/mlist2.txt#frag\n"
	secs, errs := parseINI([]byte(in))
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	want := []section{
		{name: "pinger", line: 4, keys: []keyValue{
			{"sitename", "Pinger#1 at example", 5},
			{"empty", "", 6},
			{"hash_first", "", 7},
			{"nospace", "", 8},
			{"tab", "a", 9},
			{"eq", "a=b", 10},
		}},
		{name: "peer", label: "mixmin", line: 11, keys: []keyValue{
			{"mlist2", "https://example.org/mlist2.txt#frag", 12},
		}},
	}
	if !reflect.DeepEqual(secs, want) {
		t.Errorf("got  %+v\nwant %+v", secs, want)
	}
}

func TestParseINIErrors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"key = v\n", `line 1: key "key" before the first [section]`},
		{"[pinger]\njust text\n", "line 2: expected key = value"},
		{"[pinger]\nKey = v\n", `line 2: bad key "Key"`},
		{"[pinger]\n= v\n", `line 2: bad key ""`},
		{"[pinger\n", "line 1: bad section header"},
		{"[]\n", "line 1: bad section header"},
		{"[a b c]\n", "line 1: bad section header"},
		{"[Pinger]\n", "line 1: bad section header"},
		{"[pinger] x\n", "line 1: bad section header"},
		{"[pinger]\nk = a\x00b\n", "line 2: control character"},
		{"[pinger]\nk = \xff\n", "line 2: not valid UTF-8"},
	} {
		_, errs := parseINI([]byte(tc.in))
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), tc.want) {
			t.Errorf("%q: got %v, want one error with %q", tc.in, errs, tc.want)
		}
	}
}

// TestParseINIBrokenHeader checks that the keys after a broken header
// don't add errors of their own.
func TestParseINIBrokenHeader(t *testing.T) {
	secs, errs := parseINI([]byte("[pinger\nsitename = x\n[log]\nlevel = info\n"))
	if len(errs) != 1 {
		t.Errorf("got %d errors, want 1: %v", len(errs), errs)
	}
	if len(secs) != 2 || secs[1].name != "log" || len(secs[1].keys) != 1 {
		t.Errorf("sections after a broken header: %+v", secs)
	}
}
