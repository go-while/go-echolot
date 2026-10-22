package replies

import (
	"os"
	"strings"
	"testing"
)

// TestLongFields: yamn reads pubring.mix with bufio.Scanner, whose line
// limit is 64 KiB.  One longer line makes it drop the whole keyring, so
// fields that reach the published files are limited on input.
func TestLongFields(t *testing.T) {
	data, err := os.ReadFile("../../testdata/pubrings/mixmin.mix")
	if err != nil {
		t.Fatal(err)
	}
	// The report: mixmin.mix with a 70000-character caps field.
	line := "yamn4 yamn4@mixmin.net 97e043d6925403e32ed7bfe9a23e270e 4:0.2.7 M 2026-10-19 2026-11-02"
	long := strings.Replace(string(data), line, strings.Replace(line, " M ", " "+strings.Repeat("M", 70000)+" ", 1), 1)
	if r := ParseKey([]byte(long)); len(r.Keys) != 5 || len(r.Errors) != 1 {
		t.Errorf("70000-character caps: %d keys, errors %v", len(r.Keys), r.Errors)
	}

	ok := "victor yamn@virebent.art dd34d8b7f010229bb790a2402c9ffe65 4:0.2c M 2026-10-17 2026-10-31"
	for _, tc := range []struct{ old, new string }{
		{"4:0.2c", strings.Repeat("v", maxFieldLen+1)},
		{" M ", " " + strings.Repeat("M", maxFieldLen+1) + " "},
		{"victor", strings.Repeat("v", maxNickLen+1)},
	} {
		if _, err := ParseSummary(strings.Replace(ok, tc.old, tc.new, 1)); err == nil || !strings.Contains(err.Error(), "longer than") {
			t.Errorf("%.20s...: %v", tc.new, err)
		}
	}
	for _, tc := range []struct{ old, new string }{
		{"4:0.2c", strings.Repeat("v", maxFieldLen)},
		{" M ", " " + strings.Repeat("M", maxFieldLen) + " "},
		{"victor", strings.Repeat("v", maxNickLen)},
	} {
		if _, err := ParseSummary(strings.Replace(ok, tc.old, tc.new, 1)); err != nil {
			t.Errorf("at the limit: %v", err)
		}
	}

	conf := "Remailer-Type: Mixmaster 0.2c\n\n$remailer{\"victor\"} = \"<yamn@virebent.art> middle v2\";\n"
	for _, tc := range []struct{ old, new string }{
		{"middle v2", strings.Repeat("x", maxOptionsLen+1)},
		{"victor", strings.Repeat("v", maxNickLen+1)},
	} {
		if _, err := ParseConf([]byte(strings.Replace(conf, tc.old, tc.new, 1))); err == nil {
			t.Errorf("conf with %.20s... accepted", tc.new)
		}
	}
	c, err := ParseConf([]byte(strings.Replace(conf, "Mixmaster 0.2c", strings.Repeat("t", maxTypeLen+1), 1)))
	if err != nil || c.Type != "" {
		t.Errorf("long Remailer-Type kept: %q, %v", c.Type, err)
	}
	c, err = ParseConf([]byte(strings.Replace(conf, "middle v2", strings.Repeat("x", maxOptionsLen), 1)))
	if err != nil || len(c.Options) != maxOptionsLen {
		t.Errorf("options at the limit: %v", err)
	}
}
