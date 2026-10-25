package main

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/blake2s"
)

const mlistA = `Stats-Version: 2.0
Generated: Sun 25 Oct 2026 12:33:00 GMT
Mixmaster    Latent-Hist   Latent  Uptime-Hist   Uptime  Options
------------------------------------------------------------------------
alpha        ???????????0    :03   ???????????+  100.0%  D M     T
beta         ????????????  99:59   ???????????0    0.0%    M     T
gamma        ???????????0  1:05    ???????????+   99.0%    M     T
onlya        ???????????0    :03   ???????????+  100.0%    M     T

Broken type-I remailer chains:
`

const mlistB = `Stats-Version: 2.0
Generated: Sun 25 Oct 2026 12:30:00 GMT
Mixmaster    Latent-Hist   Latent  Uptime-Hist   Uptime  Options
------------------------------------------------------------------------
alpha        ???????????0    :04   ???????????+   99.0%  D M     T
beta         ????????????  99:59   ???????????0    0.0%    M     T
gamma        ???????????0  1:20    ???????????+   95.0%    M     T

`

// key returns a pubring.mix header line and key block for name, with a
// public key made from seed and its real keyid (blake2s-128), which
// replies.ParseKey checks.
func key(name string, seed byte) (line, keyid string) {
	pk := bytes.Repeat([]byte{seed}, 32)
	sum := blake2s.Sum128(pk)
	keyid = hex.EncodeToString(sum[:])
	line = name + " " + name + "@x.org " + keyid + " 4:0.2 M 2026-10-25 2026-11-08\n\n" +
		"-----Begin Mix Key-----\n" + keyid + "\n" + hex.EncodeToString(pk) + "\n-----End Mix Key-----\n\n"
	return line, keyid
}

func pubring(blocks ...string) string { return strings.Join(blocks, "") }

func dir(t *testing.T, mlist, pub string) string {
	t.Helper()
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "mlist2.txt"), []byte(mlist), 0o644)
	if pub != "" {
		os.WriteFile(filepath.Join(d, "pubring.mix"), []byte(pub), 0o644)
	}
	return d
}

func TestParseMlist2(t *testing.T) {
	gen, rows, err := parseMlist2([]byte(mlistA))
	if err != nil {
		t.Fatal(err)
	}
	if !gen.Equal(time.Date(2026, 10, 25, 12, 33, 0, 0, time.UTC)) {
		t.Errorf("generated %v", gen)
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows: %v", len(rows), rows)
	}
	if r := rows["alpha"]; r.latency != 3*time.Minute || r.uptime != 100 || r.options != "D M T" {
		t.Errorf("alpha %+v", r)
	}
	if r := rows["beta"]; r.latency != noLatency || r.uptime != 0 {
		t.Errorf("beta %+v", r)
	}
	if r := rows["gamma"]; r.latency != 65*time.Minute || r.uptime != 99 {
		t.Errorf("gamma %+v", r)
	}
	for _, bad := range []string{"no table\n", "-----\nalpha x :0 y 1%\n", "-----\nalpha x :03 y 100\n", "-----\nshort line\n"} {
		if _, _, err := parseMlist2([]byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	for s, want := range map[string]time.Duration{":00": 0, ":59": 59 * time.Minute, "2:01": 121 * time.Minute, "99:59": noLatency} {
		if d, err := parseLatency(s); err != nil || d != want {
			t.Errorf("%s: %v %v", s, d, err)
		}
	}
	for _, s := range []string{"", "3", ":3", ":60", "-1:00", "a:00"} {
		if _, err := parseLatency(s); err == nil {
			t.Errorf("%q: no error", s)
		}
	}
}

func TestReport(t *testing.T) {
	alpha, _ := key("alpha", 1)
	gamma1, g1 := key("gamma", 2)
	gamma2, g2 := key("gamma", 3)
	a := dir(t, mlistA, pubring(alpha, gamma1))
	b := dir(t, mlistB, pubring(alpha, gamma2))
	var out, errb bytes.Buffer
	if code := run([]string{a, b}, &out, &errb, time.Now()); code != 1 {
		t.Fatalf("exit %d, stderr %s\n%s", code, errb.String(), out.String())
	}
	got := out.String()
	for _, want := range []string{
		"  alpha         100.0%   99.0%   +1.0     :03    :04  -25%  same", // within: -1 min
		"  beta            0.0%    0.0%   +0.0   99:59  99:59     -  none",
		"! gamma          99.0%   95.0%   +4.0    1:05   1:20  -19%  ours " + g1[:8] + ", theirs " + g2[:8],
		"only in ours: onlya",
		"outside the bounds: 1 of 3",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	// Wider bounds and the same keys: all within.
	b2 := dir(t, mlistB, pubring(alpha, gamma1))
	out.Reset()
	if code := run([]string{"-rel", "5", "-lat", "30", a, b2}, &out, &errb, time.Now()); code != 0 {
		t.Errorf("exit %d\n%s", code, out.String())
	}
	// A missing pubring.mix: keys aren't compared, uptime still is.
	out.Reset()
	if code := run([]string{a, dir(t, mlistB, "")}, &out, &errb, time.Now()); code != 1 || !strings.Contains(out.String(), "pubring.mix: open") {
		t.Errorf("exit %d\n%s", code, out.String())
	}
	// Bad usage and a missing mlist2.txt.
	if code := run([]string{a}, &out, &errb, time.Now()); code != 2 {
		t.Errorf("one argument: exit %d", code)
	}
	if code := run([]string{a, t.TempDir()}, &out, &errb, time.Now()); code != 2 {
		t.Errorf("no mlist2.txt: exit %d", code)
	}
}

func TestHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/yamn/mlist2.txt":
			w.Write([]byte(mlistB))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var out, errb bytes.Buffer
	code := run([]string{"-rel", "5", "-lat", "30", dir(t, mlistA, ""), srv.URL + "/yamn/"}, &out, &errb, time.Now())
	if code != 0 || !strings.Contains(out.String(), "/yamn/pubring.mix: 404 Not Found") {
		t.Errorf("exit %d, stderr %s\n%s", code, errb.String(), out.String())
	}
	if code := run([]string{dir(t, mlistA, ""), srv.URL + "/none/"}, &out, &errb, time.Now()); code != 2 {
		t.Errorf("404 mlist2.txt: exit %d", code)
	}
}

// TestRotations: a key theirs lists an hour before ours is reported as
// "theirs first by 1h0m0s"; keys both listed in the same run aren't.
func TestRotations(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	old, oldID := key("alpha", 1)
	rot, rotID := key("alpha", 4)
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	var out, errb bytes.Buffer
	run([]string{"-state", state, dir(t, mlistA, pubring(old)), dir(t, mlistB, pubring(old))}, &out, &errb, t0)
	if !strings.Contains(out.String(), "  none") {
		t.Errorf("first run:\n%s", out.String())
	}
	out.Reset()
	run([]string{"-state", state, dir(t, mlistA, pubring(old)), dir(t, mlistB, pubring(old, rot))}, &out, &errb, t0.Add(time.Hour))
	if !strings.Contains(out.String(), "alpha        "+rotID[:8]+"  ours -                 theirs 2026-10-25 13:00  only theirs so far") {
		t.Errorf("second run:\n%s", out.String())
	}
	out.Reset()
	run([]string{"-state", state, dir(t, mlistA, pubring(rot)), dir(t, mlistB, pubring(rot))}, &out, &errb, t0.Add(2*time.Hour))
	got := out.String()
	if !strings.Contains(got, "alpha        "+rotID[:8]+"  ours 2026-10-25 14:00  theirs 2026-10-25 13:00  theirs first by 1h0m0s") {
		t.Errorf("third run:\n%s", got)
	}
	if strings.Contains(got, oldID[:8]) {
		t.Errorf("the old key, listed by both in the same run, is reported:\n%s", got)
	}
	// Keys nobody lists for 14 days leave the state file.
	run([]string{"-state", state, dir(t, mlistA, pubring(rot)), dir(t, mlistB, pubring(rot))}, &out, &errb, t0.Add(15*24*time.Hour))
	b, _ := os.ReadFile(state)
	if strings.Contains(string(b), oldID) {
		t.Errorf("old key still in the state:\n%s", b)
	}
}
