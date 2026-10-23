package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// minimal is the smallest valid config: the keys without a default.
const minimal = `[pinger]
sitename = Test pinger
address = pinger@pinger.example.org
operator_address = remops@example.org
`

func mustParse(t *testing.T, data string) *Config {
	t.Helper()
	c, err := Parse("test.ini", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMinimal(t *testing.T) {
	c := mustParse(t, minimal)
	want := Defaults()
	want.Pinger.Sitename = "Test pinger"
	want.Pinger.Address = "pinger@pinger.example.org"
	want.Pinger.OperatorAddress = "remops@example.org"
	want.Paths.Maildir = "/var/lib/go-echolot/Maildir"
	want.Paths.ResultsDir = "/var/lib/go-echolot/results"
	want.Paths.PrivateResultsDir = "/var/lib/go-echolot/results.private"
	want.Signing.KeyFile = "/var/lib/go-echolot/pinger.key"
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got  %+v\nwant %+v", c, want)
	}
}

// TestDefaultsNeedPinger checks that the defaults alone are invalid only
// because of the three keys without a default.
func TestDefaultsNeedPinger(t *testing.T) {
	_, err := Parse("empty.ini", nil)
	if err == nil {
		t.Fatal("an empty config is valid")
	}
	for _, key := range []string{"pinger.sitename", "pinger.address", "pinger.operator_address"} {
		if !strings.Contains(err.Error(), key+" is required") {
			t.Errorf("no error for %s: %v", key, err)
		}
	}
	if n := strings.Count(err.Error(), "\n") + 1; n != 3 {
		t.Errorf("got %d errors, want 3:\n%v", n, err)
	}
}

func TestRelativePaths(t *testing.T) {
	c := mustParse(t, minimal+`
[paths]
state_dir = /srv/pinger/
maildir = mail/../Maildir
results_dir = /var/www/yamn
[mail]
password_file = smtp.pw
username = pinger
[log]
file = log/go-echolot.log
`)
	for _, x := range []struct{ got, want string }{
		{c.Paths.StateDir, "/srv/pinger"},
		{c.Paths.Maildir, "/srv/pinger/Maildir"},
		{c.Paths.ResultsDir, "/var/www/yamn"},
		{c.Paths.PrivateResultsDir, "/srv/pinger/results.private"},
		{c.Mail.PasswordFile, "/srv/pinger/smtp.pw"},
		{c.Signing.KeyFile, "/srv/pinger/pinger.key"},
		{c.Log.File, "/srv/pinger/log/go-echolot.log"},
	} {
		if x.got != x.want {
			t.Errorf("got %s, want %s", x.got, x.want)
		}
	}
}

func TestValues(t *testing.T) {
	c := mustParse(t, minimal+`
[schedule]
tick = 1m
ping_interval = 90m
[stats]
days = 3
weights = 1, 0.5 ,0.25
sort_by_latency = yes
[keys]
require_proof = off
[signing]
files =
[compat]
legacy_md5_tokens_until = 2026-10-24T14:00:00+02:00
[peer mixmin]
mlist2 = https://www.mixmin.net/yamn/mlist2.txt
[peer victor]
mlist2 = https://echolot.virebent.art/mlist2.txt
pubring = https://echolot.virebent.art/keys/pubring.mix
`)
	if c.Schedule.Tick != time.Minute || c.Schedule.PingInterval != 90*time.Minute {
		t.Errorf("schedule: %+v", c.Schedule)
	}
	if !reflect.DeepEqual(c.Stats.Weights, []float64{1, 0.5, 0.25}) || !c.Stats.SortByLatency {
		t.Errorf("stats: %+v", c.Stats)
	}
	if c.Keys.RequireProof {
		t.Error("keys.require_proof = off is true")
	}
	if c.Signing.Files != nil {
		t.Errorf("signing.files = (empty) is %q", c.Signing.Files)
	}
	if want := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC); !c.Compat.LegacyMD5TokensUntil.Equal(want) ||
		c.Compat.LegacyMD5TokensUntil.Location() != time.UTC {
		t.Errorf("compat.legacy_md5_tokens_until: %v, want %v", c.Compat.LegacyMD5TokensUntil, want)
	}
	want := []Peer{
		{Name: "mixmin", Mlist2: "https://www.mixmin.net/yamn/mlist2.txt"},
		{Name: "victor", Mlist2: "https://echolot.virebent.art/mlist2.txt", Pubring: "https://echolot.virebent.art/keys/pubring.mix"},
	}
	if !reflect.DeepEqual(c.Peers, want) {
		t.Errorf("peers: %+v", c.Peers)
	}
	if got := c.Peers[0].PubringURL(); got != "https://www.mixmin.net/yamn/pubring.mix" {
		t.Errorf("mixmin's pubring: %s", got)
	}
	if got := c.Peers[1].PubringURL(); got != "https://echolot.virebent.art/keys/pubring.mix" {
		t.Errorf("victor's pubring: %s", got)
	}
}

func TestDecodeErrors(t *testing.T) {
	in := minimal + `[pinger]
[nosuch]
[log]
nosuch = 1
level = info
level = debug
[peer]
[health x]
[peer a]
[peer a]
[yamn]
timeout = 30
[mail]
smtp_port = 25x
usetls = 1
[stats]
skew_percent = NaN
weights = 1,,2
[schedule]
tick =
[compat]
legacy_md5_tokens_until = 2026-10-24
`
	_, err := Parse("bad.ini", []byte(in))
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{
		"bad.ini: line 5: [pinger] again, first at line 1",
		"bad.ini: line 6: unknown section [nosuch]",
		`bad.ini: line 8: unknown key "nosuch" in [log]`,
		"bad.ini: line 10: log.level again, first at line 9",
		"bad.ini: line 11: [peer] needs a name",
		"bad.ini: line 12: [health] takes no name",
		"bad.ini: line 14: [peer a] again, first at line 13",
		`bad.ini: line 16: yamn.timeout: bad duration "30"`,
		`bad.ini: line 18: mail.smtp_port: needs a whole number, not "25x"`,
		`bad.ini: line 19: mail.usetls: needs true or false, not "1"`,
		`bad.ini: line 21: stats.skew_percent: needs a number, not "NaN"`,
		`bad.ini: line 22: stats.weights: empty item in list "1,,2"`,
		"bad.ini: line 24: schedule.tick: needs a duration",
		`bad.ini: line 26: compat.legacy_md5_tokens_until: bad time "2026-10-24"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing error %q", want)
		}
	}
	if n, want := strings.Count(err.Error(), "\n")+1, 14; n != want {
		t.Errorf("got %d errors, want %d:\n%v", n, want, err)
	}
}

func TestLoad(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nosuch.ini")); !os.IsNotExist(err) {
		t.Errorf("missing file: got %v", err)
	}
	path := filepath.Join(t.TempDir(), "bad.ini")
	if err := os.WriteFile(path, []byte("[pinger]\nx = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.HasPrefix(err.Error(), path+": line 2: ") {
		t.Errorf("error doesn't start with the file name and line: %v", err)
	}
}

// TestExample checks that examples/config.ini is valid and sets every key
// (the peers are commented out), so it documents them all.
func TestExample(t *testing.T) {
	data, err := os.ReadFile("../../examples/config.ini")
	if err != nil {
		t.Fatal(err)
	}
	mustParse(t, string(data))
	secs, _ := parseINI(data)
	set := map[string]bool{}
	for _, s := range secs {
		for _, kv := range s.keys {
			set[s.name+"."+kv.key] = true
		}
	}
	cv := reflect.ValueOf(Config{})
	for i := range cv.NumField() {
		sec := cv.Type().Field(i).Tag.Get("ini")
		st := cv.Field(i).Type()
		if st.Kind() == reflect.Slice {
			continue
		}
		for j := range st.NumField() {
			if key := sec + "." + st.Field(j).Tag.Get("ini"); !set[key] {
				t.Errorf("examples/config.ini doesn't set %s", key)
			}
		}
	}
}

// designExample returns the config example of docs/design.md §10.3.
func designExample(t *testing.T) []byte {
	data, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := bytes.Cut(data, []byte("\n### 10.3 Config example\n"))
	_, after, ok2 := bytes.Cut(after, []byte("\n```ini\n"))
	example, _, ok3 := bytes.Cut(after, []byte("\n```\n"))
	if !ok || !ok2 || !ok3 {
		t.Fatal("no ini block in docs/design.md §10.3")
	}
	return example
}

func TestDesignExample(t *testing.T) {
	c := mustParse(t, string(designExample(t)))
	if len(c.Peers) != 2 || c.Paths.ResultsDir != "/var/www/pinger/yamn" {
		t.Errorf("unexpected values: %+v %+v", c.Peers, c.Paths)
	}
}

func TestFormatRoundTrip(t *testing.T) {
	for name, data := range map[string]string{
		"minimal": minimal,
		"design":  string(designExample(t)),
		"values": minimal + `
[mail]
method = smtp
smtp_relay = 127.0.0.1
usetls = false
username = pinger
password_file = /etc/go-echolot/smtp.pw
[stats]
weights = 1e-3, 0.3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
[schedule]
tick = 90s
ping_interval = 3h7m30s
[compat]
legacy_md5_tokens_until = 2026-10-24T12:00:00.5Z
[peer a]
mlist2 = http://a.example/m.txt
`,
	} {
		c := mustParse(t, data)
		var b bytes.Buffer
		if err := c.Format(&b); err != nil {
			t.Fatal(err)
		}
		c2, err := Parse("formatted", b.Bytes())
		if err != nil {
			t.Fatalf("%s: formatted config doesn't load: %v\n%s", name, err, b.String())
		}
		if !reflect.DeepEqual(c, c2) {
			t.Errorf("%s: round trip changed the config:\n%+v\n%+v\n%s", name, c, c2, b.String())
		}
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                         "0s",
		168 * time.Hour:           "168h",
		90 * time.Minute:          "90m",
		90 * time.Second:          "90s",
		1500 * time.Millisecond:   "1.5s",
		-2 * time.Hour:            "-2h",
		time.Hour + time.Second/2: "1h0m0.5s",
	} {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%d) = %s, want %s", d, got, want)
		}
	}
}

func TestLogLevel(t *testing.T) {
	c := Defaults()
	for level, want := range map[string]string{"debug": "DEBUG", "info": "INFO", "warn": "WARN", "error": "ERROR"} {
		c.Log.Level = level
		if got := c.LogLevel().String(); got != want {
			t.Errorf("%s: got %s", level, got)
		}
	}
}

// FuzzParse checks that Parse doesn't panic and that every config it
// accepts survives Format and Parse unchanged.
func FuzzParse(f *testing.F) {
	f.Add([]byte(minimal))
	f.Add([]byte(minimal + "[peer a]\nmlist2 = https://a.example/x\n[stats]\nweights = 1,2,3,4,5,6,7,8,9,10,11,12\n"))
	f.Add([]byte(minimal + "[compat]\nlegacy_md5_tokens_until = 2026-10-24T12:00:00Z\n[schedule]\ntick = 2m\n"))
	f.Add([]byte("[pinger]\r\nsitename=a#b # c\r\n[x y z]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse("fuzz", data)
		if err != nil {
			return
		}
		var b bytes.Buffer
		if err := c.Format(&b); err != nil {
			t.Fatal(err)
		}
		c2, err := Parse("formatted", b.Bytes())
		if err != nil {
			t.Fatalf("formatted config doesn't load: %v\n%s", err, b.String())
		}
		if !reflect.DeepEqual(c, c2) {
			t.Fatalf("round trip changed the config:\n%s", b.String())
		}
	})
}

// TestErrorsNamed checks that every error line starts with the file name.
func TestErrorsNamed(t *testing.T) {
	_, err := Parse("x.ini", []byte("[log]\nlevel = loud\n"))
	for line := range strings.Lines(err.Error()) {
		if !strings.HasPrefix(line, "x.ini: ") {
			t.Errorf("error without the file name: %q", line)
		}
	}
}
