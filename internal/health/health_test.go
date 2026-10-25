package health

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func want(t *testing.T, c Check, l Level, detail string) {
	t.Helper()
	if c.State != l || !strings.Contains(c.Detail, detail) {
		t.Errorf("%s: %s %q, want %s with %q", c.Name, c.State, c.Detail, l, detail)
	}
}

func TestScan(t *testing.T) {
	start := t0.Add(-time.Hour)
	want(t, Scan(t0.Add(-time.Minute), start, t0), OK, "last good scan 1m ago")
	want(t, Scan(t0.Add(-6*time.Minute), start, t0), Warn, "6m ago")
	want(t, Scan(t0.Add(-31*time.Minute), start, t0), Crit, "31m ago")
	want(t, Scan(time.Time{}, t0.Add(-2*time.Minute), t0), OK, "no good scan since the start 2m ago")
	want(t, Scan(time.Time{}, start, t0), Crit, "no good scan")
}

func TestReplies(t *testing.T) {
	last := t0.Add(-10 * time.Hour)
	want(t, Replies(last, time.Time{}, 5, 2*time.Hour, t0), OK, "no ping waiting")
	want(t, Replies(time.Time{}, time.Time{}, 5, 2*time.Hour, t0), OK, "last reply never")
	want(t, Replies(last, t0.Add(-2*time.Hour), 5, 2*time.Hour, t0), OK, "last reply 10h ago")
	want(t, Replies(last, t0.Add(-4*time.Hour), 5, 2*time.Hour, t0), Warn, "no ping reply for 4h")
	want(t, Replies(last, t0.Add(-7*time.Hour), 5, 2*time.Hour, t0), Crit, "5 remailers pingable")
	// One remailer: it may just be down.
	want(t, Replies(last, t0.Add(-7*time.Hour), 1, 2*time.Hour, t0), Warn, "1 remailers")
	// A long ping interval moves the thresholds.
	want(t, Replies(last, t0.Add(-7*time.Hour), 5, 6*time.Hour, t0), OK, "")
	want(t, Replies(last, t0.Add(-10*time.Hour), 5, 6*time.Hour, t0), Warn, "10h")
	want(t, Replies(last, t0.Add(-19*time.Hour), 5, 6*time.Hour, t0), Crit, "19h")
}

func TestSends(t *testing.T) {
	want(t, Sends(0, 0, 0), OK, "too few")
	want(t, Sends(2, 2, 0), OK, "too few")
	want(t, Sends(10, 1, 0), OK, "1 of 10")
	want(t, Sends(10, 2, 0), Warn, "2 of 10")
	want(t, Sends(3, 3, 0), Crit, "all 3")
	want(t, Sends(10, 0, 4), Warn, "0 of 10 sends failed in the last hour; mail.max_per_hour held back 4 mails")
	want(t, Sends(3, 3, 4), Crit, "held back 4")
}

func TestWindow(t *testing.T) {
	var w Window
	w.Add(t0, true)
	w.Add(t0.Add(30*time.Minute), false)
	w.Add(t0.Add(50*time.Minute), true)
	w.Limited(t0.Add(55 * time.Minute))
	if s, f, l := w.Counts(t0.Add(time.Hour)); s != 3 || f != 2 || l != 1 {
		t.Errorf("at 1h: %d %d %d", s, f, l)
	}
	if s, f, l := w.Counts(t0.Add(time.Hour + time.Second)); s != 2 || f != 1 || l != 1 {
		t.Errorf("at 1h1s: %d %d %d", s, f, l)
	}
	if s, f, l := w.Counts(t0.Add(3 * time.Hour)); s != 0 || f != 0 || l != 0 {
		t.Errorf("at 3h: %d %d %d", s, f, l)
	}
}

func TestMlist2(t *testing.T) {
	start := t0.Add(-24 * time.Hour)
	want(t, Mlist2(t0.Add(-5*time.Minute), nil, 5*time.Minute, start, t0), OK, "generated 5m ago")
	want(t, Mlist2(t0.Add(-16*time.Minute), nil, 5*time.Minute, start, t0), Warn, "16m")
	want(t, Mlist2(t0.Add(-61*time.Minute), nil, 5*time.Minute, start, t0), Crit, "1h1m")
	// A longer stats interval moves the thresholds.
	want(t, Mlist2(t0.Add(-50*time.Minute), nil, 20*time.Minute, start, t0), OK, "50m")
	want(t, Mlist2(t0.Add(-61*time.Minute), nil, 20*time.Minute, start, t0), Warn, "1h1m")
	// Not written yet: only crit once the stats should be there.
	nf := errors.New("mlist2.txt not written yet")
	want(t, Mlist2(time.Time{}, nf, 5*time.Minute, t0.Add(-time.Minute), t0), OK, "not written yet")
	want(t, Mlist2(time.Time{}, nf, 5*time.Minute, start, t0), Crit, "not written yet")
}

func TestKeysCheck(t *testing.T) {
	want(t, Keys(0, nil), Crit, "no keys")
	want(t, Keys(12, nil), OK, "12 keys")
	want(t, Keys(12, []string{"a (expires 2026-10-23)"}), Warn, "with no new key: a (expires")
}

func TestOthers(t *testing.T) {
	want(t, SelfTest(nil, time.Time{}, t0), OK, "not run yet")
	want(t, SelfTest(nil, t0.Add(-time.Hour), t0), OK, "passed 1h ago")
	want(t, SelfTest(errors.New("no yamn"), t0, t0), Crit, "no pings can be sent")
	want(t, Pending(nil), OK, "none")
	want(t, Pending([]string{"a@b: key 12"}), Warn, "1 changes in quarantine")
	b := map[string]time.Time{"old@x": t0.Add(-25 * time.Hour), "new@x": t0.Add(-time.Hour)}
	want(t, Bounces(b, t0), Warn, "for new@x (")
	if c := Bounces(b, t0); strings.Contains(c.Detail, "old@x") {
		t.Errorf("an old bounce counts: %q", c.Detail)
	}
	want(t, Bounces(map[string]time.Time{"old@x": t0.Add(-25 * time.Hour)}, t0), OK, "none")
	const gib = 1 << 30
	want(t, Disk("state", 0.5, 50*gib, nil), OK, "50.0% free (50.0 GiB)")
	want(t, Disk("state", 0.05, 2*gib, nil), Warn, "5.0% free (2.0 GiB)")
	want(t, Disk("state", 0.01, 500<<20, nil), Crit, "1.0% free (500 MiB)")
	// A large disk: a low share with many bytes left is fine, and a
	// warn-level share with under 1 GiB is only a warning.
	want(t, Disk("state", 0.05, 100*gib, nil), OK, "5.0% free (100.0 GiB)")
	want(t, Disk("state", 0.01, 3*gib, nil), Warn, "1.0% free (3.0 GiB)")
	// A small disk: plenty of share, few bytes: fine.
	want(t, Disk("state", 0.5, 500<<20, nil), OK, "50.0%")
	want(t, Disk("state", 0, 0, errors.New("gone")), Warn, "unknown")
	if Bytes(3<<40/2) != "1.5 TiB" {
		t.Errorf("Bytes: %s", Bytes(3<<40/2))
	}
	if c := Disk("results", 1, 1, nil); c.Name != "disk_results" {
		t.Errorf("name %q", c.Name)
	}
	want(t, PeerKeys(nil), OK, "agree")
	want(t, PeerKeys([]string{"mixmin: a@b ours 1, theirs 2"}), OK, "1 disagreements")
}

func TestList(t *testing.T) {
	var names []string
	for range 12 {
		names = append(names, "x")
	}
	if got := list(names); !strings.HasSuffix(got, "x and 2 more") {
		t.Errorf("%q", got)
	}
}

func TestPeerCheck(t *testing.T) {
	want(t, PeerCheck("m", Peer{}, t0), OK, "not fetched yet")
	want(t, PeerCheck("m", Peer{Checked: t0, Err: "timeout"}, t0), Warn, "never fetched: timeout")
	want(t, PeerCheck("m", Peer{Checked: t0, Generated: t0.Add(-time.Hour)}, t0), OK, "generated 1h ago")
	want(t, PeerCheck("m", Peer{Checked: t0, Generated: t0.Add(-7 * time.Hour)}, t0), Warn, "7h")
	// Down since: its last good fetch ages.
	c := PeerCheck("m", Peer{Checked: t0, Generated: t0.Add(-25 * time.Hour), Err: "refused"}, t0)
	want(t, c, Crit, "generated 25h ago; the last fetch failed: refused")
	if c.Name != "peer_m" {
		t.Errorf("name %q", c.Name)
	}
}

func TestDur(t *testing.T) {
	for d, s := range map[time.Duration]string{
		1500 * time.Millisecond:          "2s",
		90 * time.Second:                 "2m",
		3*time.Hour + 20*time.Minute:     "3h20m",
		3 * time.Hour:                    "3h",
		-(5*time.Minute + 2*time.Second): "-5m",
	} {
		if got := Dur(d); got != s {
			t.Errorf("%v: %q, want %q", d, got, s)
		}
	}
}

func TestReport(t *testing.T) {
	r := NewReport("Test pinger", "v1", t0, []Check{
		{Name: "a", State: OK, Detail: "fine"},
		{Name: "b", State: Warn, Detail: "hmm"},
	})
	if r.State != Warn {
		t.Errorf("state %s", r.State)
	}
	js, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"state": "warn"`) {
		t.Errorf("json:\n%s", js)
	}
	back, err := ParseReport(js)
	if err != nil || back.State != Warn || len(back.Checks) != 2 || !back.Generated.Equal(t0) || back.Checks[1].Detail != "hmm" {
		t.Errorf("round trip: %+v, %v", back, err)
	}
	if _, err := ParseReport([]byte(`{"state":"bad"}`)); err == nil {
		t.Error("a bad level parsed")
	}
	if _, err := ParseReport([]byte(`{}`)); err == nil {
		t.Error("no generated time parsed")
	}
	txt := string(r.Text())
	for _, s := range []string{"go-echolot health: WARN\n", "generated: 2026-10-23T12:00:00Z\n", "warn  b                  hmm\n"} {
		if !strings.Contains(txt, s) {
			t.Errorf("text has no %q:\n%s", s, txt)
		}
	}
}

func TestDue(t *testing.T) {
	checks := []Check{{Name: "a", State: Warn}, {Name: "b", State: OK}, {Name: "c", State: Crit}}
	names := func(cs []Check) string {
		var s []string
		for _, c := range cs {
			s = append(s, c.Name)
		}
		return strings.Join(s, ",")
	}
	// Nothing mailed yet: the non-ok ones.
	if got := names(Due(checks, nil, t0)); got != "a,c" {
		t.Errorf("first: %s", got)
	}
	n := map[string]Notice{"a": {Warn, t0}, "c": {Crit, t0}}
	if got := names(Due(checks, n, t0.Add(time.Minute))); got != "" {
		t.Errorf("unchanged: %s", got)
	}
	// a recovers within 6 h: it waits.
	checks[0].State = OK
	if got := names(Due(checks, n, t0.Add(time.Hour))); got != "" {
		t.Errorf("within 6h: %s", got)
	}
	if got := names(Due(checks, n, t0.Add(NotifyEvery))); got != "a" {
		t.Errorf("after 6h: %s", got)
	}
	// It flapped back to warn by then: nothing to say.
	checks[0].State = Warn
	if got := names(Due(checks, n, t0.Add(NotifyEvery))); got != "" {
		t.Errorf("flapped back: %s", got)
	}
	r := NewReport("P", "", t0, checks)
	checks[2].Detail = strings.Repeat("a-long-item-name, ", 80)
	subject, body := Digest(r, checks[2:])
	if subject != "go-echolot health: CRIT (P)" || !strings.HasPrefix(string(body), "Changed:\n\ncrit  c\n      a-long-item-name,") ||
		!strings.Contains(string(body), "The whole status (CRIT, generated 2026-10-23T12:00:00Z):\n\nwarn  a\n") {
		t.Errorf("digest %q:\n%s", subject, body)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if len(line) > mailWidth+20 {
			t.Errorf("long line in the mail: %q", line)
		}
	}
}

func TestParseGenerated(t *testing.T) {
	for in, w := range map[string]time.Time{
		"Stats-Version: 2.0\nGenerated: Fri 23 Oct 2026 12:00:00 GMT\nMixmaster ...\n":     t0,
		"Stats-Version: 2.0\r\nGenerated: Fri 23 Oct 2026 12:00:00 GMT\r\n":                t0,
		"Generated: Fri  2 Oct 2026 12:00:00 GMT\n":                                        time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC),
		"Generated: Fri, 23 Oct 2026 14:00:00 +0200\n":                                     t0,
		"Stats-Version: 2.0\nGenerated:   Fri 23 Oct 2026 12:00:00 GMT  \nMixmaster ...\n": t0,
	} {
		got, err := ParseGenerated([]byte(in))
		if err != nil || !got.Equal(w) || got.Location() != time.UTC {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "Stats-Version: 2.0\n", "Generated: yesterday\n",
		strings.Repeat("x\n", 10) + "Generated: Fri 23 Oct 2026 12:00:00 GMT\n"} {
		if _, err := ParseGenerated([]byte(in)); err == nil {
			t.Errorf("%q parsed", in)
		}
	}
}

func TestLevelText(t *testing.T) {
	if _, err := Level(5).MarshalText(); err == nil {
		t.Error("level 5 marshalled")
	}
	if Level(5).String() != "level(5)" {
		t.Error(Level(5).String())
	}
}
