package replies

import (
	"strings"
	"testing"
)

func TestParseConfT65(t *testing.T) {
	body, err := Body(nil, readFile(t, "replies/t_65.conf"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConf(body)
	if err != nil {
		t.Fatal(err)
	}
	if c.Type != "Mixmaster 0.2c" || c.Nick != "victor" || c.Address != "yamn@virebent.art" || c.Options != "middle v2" {
		t.Errorf("got %+v", c)
	}
	if want := `$remailer{"victor"} = "<yamn@virebent.art> middle v2";`; c.Caps != want {
		t.Errorf("Caps = %q, want %q", c.Caps, want)
	}
	if len(c.Supported) != 6 {
		t.Fatalf("got %d supported lines, want 6", len(c.Supported))
	}
	want := SummaryLine{
		Nick:    "yamn4",
		Address: "yamn4@mixmin.net",
		KeyID:   "97e043d6925403e32ed7bfe9a23e270e",
		Version: "4:0.2.7",
		Caps:    "M",
		Created: date("2026-10-19"),
		Expires: date("2026-11-02"),
	}
	if c.Supported[5] != want {
		t.Errorf("Supported[5] = %+v, want %+v", c.Supported[5], want)
	}
	if c.Supported[1].String() != victorHeader {
		t.Errorf("Supported[1] = %q", c.Supported[1])
	}
	if IsNotARemailer(body) {
		t.Error("IsNotARemailer = true")
	}
}

func TestParseConfCaps(t *testing.T) {
	tests := []struct {
		line, nick, addr, opts, caps string
	}{
		{`$remailer{"victor"} = "<yamn@virebent.art> middle v2";`, "victor", "yamn@virebent.art", "middle v2", `$remailer{"victor"} = "<yamn@virebent.art> middle v2";`},
		{`$remailer{"yamn"} = "<yamn@mixmin.net>";`, "yamn", "yamn@mixmin.net", "", `$remailer{"yamn"} = "<yamn@mixmin.net>";`},
		{` $remailer{"yamn"}="<yamn@mixmin.net>  v2 ";` + "\r", "yamn", "yamn@mixmin.net", "v2", `$remailer{"yamn"} = "<yamn@mixmin.net> v2";`},
		{"$remailer{\"yamn\"} = \"<yamn@mixmin.net>\tmiddle\t v2\";", "yamn", "yamn@mixmin.net", "middle v2", `$remailer{"yamn"} = "<yamn@mixmin.net> middle v2";`},
		{`$remailer{"averyveryverylongname"} = "<a@b> v2";`, "averyveryverylongname", "a@b", "v2", `$remailer{"averyveryverylongname"} = "<a@b> v2";`},
	}
	for _, tt := range tests {
		c, err := ParseConf([]byte("Remailer-Type: Mixmaster 0.2c\n\n" + tt.line + "\n"))
		if err != nil {
			t.Errorf("%q: %v", tt.line, err)
			continue
		}
		if c.Nick != tt.nick || c.Address != tt.addr || c.Options != tt.opts || c.Caps != tt.caps {
			t.Errorf("%q: got %+v", tt.line, c)
		}
	}

	for _, line := range []string{
		``,
		`$remailer{"Victor"} = "<yamn@virebent.art> middle v2";`,
		`$remailer{""} = "<yamn@virebent.art> middle v2";`,
		`$remailer{"vic tor"} = "<yamn@virebent.art> middle v2";`,
		`$remailer{"victor"} = "<yamn virebent.art> middle v2";`,
		`$remailer{"victor"} = "<ya mn@virebent.art> middle v2";`,
		`$remailer{"victor"} = "<yamn@vire@bent.art> middle v2";`,
		`$remailer{"victor"} = "<` + strings.Repeat("a", 40) + `@virebent.art>";`,
		`$remailer{"victor"} = "yamn@virebent.art middle v2";`,
		`$remailer{"victor"} = "<yamn@virebent.art> middle v2"`,
		`$remailer{"victor"} = "<yamn@virebent.art> middle v2"; x`,
		"$remailer{\"victor\"} = \"<yamn@virebent.art> middle\x01v2\";",
		"$remailer{\"victor\"} = \"<yamn@virebent.art> middlé\";",
	} {
		if c, err := ParseConf([]byte("Remailer-Type: Mixmaster 0.2c\n" + line + "\n")); err == nil {
			t.Errorf("%q: got %+v", line, c)
		}
	}
}

func TestParseConfSupported(t *testing.T) {
	body := "Remailer-Type: Mixmaster 0.2c\n" +
		`$remailer{"yamn"} = "<yamn@mixmin.net>";` + "\n" +
		"\n" + supportedHeader + "\r\n" +
		victorHeader + "\r\n" +
		strings.Replace(victorHeader, "victor", "Victor", 1) + "\n" + // skipped
		strings.Replace(victorHeader, "2026-10-31", "2026-13-01", 1) + "\n" + // skipped
		strings.Replace(victorHeader, "victor", "frell", 1) + "\n" +
		"\n" +
		strings.Replace(victorHeader, "victor", "after", 1) + "\n" + // after the list
		supportedHeader + "\n" + // a second list is ignored
		strings.Replace(victorHeader, "victor", "second", 1) + "\n"
	c, err := ParseConf([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Supported) != 2 || c.Supported[0].Nick != "victor" || c.Supported[1].Nick != "frell" {
		t.Errorf("got %+v", c.Supported)
	}

	// The list ends at the first line that isn't one.
	c, err = ParseConf([]byte(supportedHeader + "\n" + victorHeader + "\nfoo\n" + victorHeader + "\n" + `$remailer{"yamn"} = "<yamn@mixmin.net>";`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Supported) != 1 || c.Type != "" {
		t.Errorf("got %+v", c)
	}
}

func TestParseConfType(t *testing.T) {
	caps := "\n" + `$remailer{"yamn"} = "<yamn@mixmin.net>";` + "\n"
	for in, want := range map[string]string{
		"Remailer-Type: Mixmaster 0.2c":           "Mixmaster 0.2c",
		"  remailer-type:Mixmaster 0.2c  \r":      "Mixmaster 0.2c",
		"Remailer-Type:":                          "",
		"Remailer-Type: a\x00b":                   "",
		"X-Remailer-Type: foo":                    "",
		"Remailer-Type: one\nRemailer-Type: two":  "one",
		"Remailer-Type: \x7f\nRemailer-Type: two": "two",
	} {
		c, err := ParseConf([]byte(in + caps))
		if err != nil {
			t.Fatal(err)
		}
		if c.Type != want {
			t.Errorf("%q: Type = %q, want %q", in, c.Type, want)
		}
	}
}

func TestIsNotARemailer(t *testing.T) {
	for in, want := range map[string]bool{
		"not a remailer":                   true,
		"Not A Remailer\n":                 true,
		"  \n NOT\t a\n  remailer, sorry.": true,
		"not a remailer-key reply":         true,
		"not a remailers":                  false,
		"notaremailer":                     false,
		"I am not a remailer":              false,
		"x\nnot a remailer":                false,
		"":                                 false,
	} {
		if got := IsNotARemailer([]byte(in)); got != want {
			t.Errorf("IsNotARemailer(%q) = %v", in, got)
		}
	}
}
