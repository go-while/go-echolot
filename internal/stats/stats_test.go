package stats

import (
	"testing"
	"time"
)

// The golden comparisons with Echolot are in internal/output; these are
// the cases Perl can't run (it would index day -1) and unit checks.

var (
	now = time.Unix(1792572345, 0)
	def = Params{Days: 12, Weights: []float64{0.5, 1.0, 1.0, 1.0, 1.0, 0.9, 0.8, 0.5, 0.3, 0.2, 0.2, 0.1},
		SkewAbs: 15 * time.Minute, SkewPercent: 0.8}
)

func f(v float64) *float64 { return &v }

func ago(sec int64) time.Time { return now.Add(-time.Duration(sec) * time.Second) }

func TestCalculateFuture(t *testing.T) {
	// Two days ahead: clamped to day 0 and counted.
	r := Calculate([]time.Time{now.Add(49 * time.Hour)}, []Done{{now.Add(30 * time.Hour), 60}, {ago(3600), 120}}, now, def)
	if r.Clamped != 2 {
		t.Errorf("clamped %d, want 2", r.Clamped)
	}
	if *r.LatencyDay[0] != 90 || *r.ReliabilityDay[0] != 1 || r.Reliability != 1 {
		t.Errorf("got %v %v %v", *r.LatencyDay[0], *r.ReliabilityDay[0], r.Reliability)
	}
	// Less than a day ahead truncates to day 0, as in Perl: not clamped.
	if r := Calculate([]time.Time{now.Add(23 * time.Hour)}, nil, now, def); r.Clamped != 0 || r.ReliabilityDay[0] == nil {
		t.Errorf("got %+v", r)
	}
}

func TestCalculatePercentile(t *testing.T) {
	// An out ping 900 + 0.8*100 s old: x == 100 exactly, and the strict >
	// leaves the latency 100 out: p = 1/3.
	done := []Done{{ago(5 * 86400), 50}, {ago(5 * 86400), 100}, {ago(5 * 86400), 200}}
	r := Calculate([]time.Time{ago(980)}, done, now, def)
	if got := *r.ReliabilityDay[0]; got != 1.0/3 {
		t.Errorf("day 0 %v, want 1/3", got)
	}
	// rel = (0.9*3 + 0.5/3) / (0.9*3 + 0.5)
	w0, w5, third := 0.5, 0.9, 1.0/3 // variables: constant arithmetic would be exact
	if want := (w5 + w5 + w5 + float64(w0*third)) / (w5 + w5 + w5 + w0); r.Reliability != want {
		t.Errorf("reliability %v, want %v", r.Reliability, want)
	}
	if *r.Latency != 100 || r.LatencyDay[0] != nil {
		t.Errorf("latency %v %v", *r.Latency, r.LatencyDay[0])
	}
}

func TestCalculateEdges(t *testing.T) {
	if r := Calculate(nil, []Done{{ago(1), 1}}, now, Params{}); r.LatencyDay != nil || r.Reliability != 0 {
		t.Errorf("days 0: %+v", r)
	}
	// Missing weights count 0, as Perl's undef: no division by zero.
	r := Calculate([]time.Time{ago(3 * 86400)}, nil, now, Params{Days: 4, Weights: []float64{1}, SkewPercent: 0.8})
	if r.Reliability != 0 || *r.ReliabilityDay[3] != 0 || len(r.LatencyDay) != 4 {
		t.Errorf("got %+v", r)
	}
	// The cutoff is strict.
	r = Calculate([]time.Time{ago(12 * 86400)}, []Done{{ago(12 * 86400), 5}, {ago(12*86400 - 1), 7}}, now, def)
	if *r.Latency != 7 || *r.ReliabilityDay[11] != 1 {
		t.Errorf("got %v %v", *r.Latency, *r.ReliabilityDay[11])
	}
}

func TestMinHr(t *testing.T) {
	for _, c := range []struct {
		sec       *float64
		short, hm string
	}{
		{nil, "99:59", "99:59:59"},
		{f(-1), "99:59", "99:59:59"},
		{f(0), "  :00", "       0"},
		{f(59.9), "  :00", "      59"},
		{f(60), "  :01", "    1:00"},
		{f(3599.5), "  :59", "   59:59"},
		{f(3600), " 1:00", " 1:00:00"},
		{f(99*3600 + 59*60 + 59.5), "99:59", "99:59:59"},
		{f(100 * 3600), "99:59", "99:59:59"},
		{f(1e300), "99:59", "99:59:59"},
	} {
		if got := MinHr(c.sec, false); got != c.short {
			t.Errorf("MinHr(%v) = %q, want %q", c.sec, got, c.short)
		}
		if got := MinHr(c.sec, true); got != c.hm {
			t.Errorf("MinHr(%v, sec) = %q, want %q", c.sec, got, c.hm)
		}
	}
}

func TestHistories(t *testing.T) {
	days := []*float64{f(1199), f(1200), nil, f(172800), f(0.5)}
	if got := LatencyHist(days); got != "0H?10" {
		t.Errorf("LatencyHist %q", got)
	}
	if got := LatencyHist1(days); got != "#_ **" {
		t.Errorf("LatencyHist1 %q", got)
	}
	edges := []*float64{f(299), f(300), f(3600), f(14400), f(86400), f(172799.5)}
	if got := LatencyHist1(edges); got != "..-+*#" {
		t.Errorf("LatencyHist1 edges %q", got)
	}
	up := []*float64{f(0.9999), f(0.99989), nil, f(0), f(0.15)}
	if got := UptimeHist(up); got != "10?9+" {
		t.Errorf("UptimeHist %q", got)
	}
}

func TestOptions(t *testing.T) {
	for caps, want := range map[string]string{
		// yamn's caps lines (live mlist2.txt: "D" + 14 spaces, 15 spaces).
		`$remailer{"yamn"} = "<yamn@yamn.paranoici.org> mid v2";`:           "               ",
		`$remailer{"frell"} = "<yamn@frell.eu.org> middle v2";`:             "D              ",
		`$remailer{"x"} = "<mix@example.org> Middle klen9999999999999";`:    "D M           9",
		`$remailer{"x"} = "<x@example.org> klen12a klen350 inflt rhop7";`:   "             N3",
		`$remailer{"x"} = "<x@example.org> middle-man premix post-office";`: "DP             ",
		// The Kelvin sign isn't k for Perl's /i on bytes (but it is a
		// non-word character before "ek").
		"<x@example.org> \u212alen500 \u212aek": "          e    ",
	} {
		if got := Options(caps); got != want {
			t.Errorf("Options(%q) = %q, want %q", caps, got, want)
		}
	}
}
