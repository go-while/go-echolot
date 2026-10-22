package output

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/stats"
)

// golden is a case's in.json, as tools/golden/gen.py writes it.
type golden struct {
	Now  int64 `json:"now"`
	Rems map[string]struct {
		Nick   *string `json:"nick"`
		Caps   *string `json:"caps"`
		ShowIt *int    `json:"showit"`
		Keys   map[string]struct {
			Out  []int64    `json:"out"`
			Done [][2]int64 `json:"done"`
		} `json:"keys"`
	} `json:"rems"`
	Config struct {
		Days          *int      `json:"stats_days"`
		Weights       []float64 `json:"pings_weight"`
		SortByLatency int       `json:"stats_sort_by_latency"`
	} `json:"config"`
	Files map[string]string `json:"files"`
}

// calcResult is one address in calc.json: Echolot's calculate().
type calcResult struct {
	Latency        *float64   `json:"avr_latency"`
	Reliability    float64    `json:"avr_reliability"`
	LatencyDay     []*float64 `json:"latency_day"`
	ReliabilityDay []*float64 `json:"reliability_day"`
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// goldenParams are the harness's stats parameters (Echolot's defaults),
// with the case's overrides.
func goldenParams(g *golden) stats.Params {
	p := stats.Params{Days: 12, Weights: []float64{0.5, 1.0, 1.0, 1.0, 1.0, 0.9, 0.8, 0.5, 0.3, 0.2, 0.2, 0.1},
		SkewAbs: 15 * time.Minute, SkewPercent: 0.8}
	if g.Config.Days != nil {
		p.Days = *g.Config.Days
	}
	if g.Config.Weights != nil {
		p.Weights = g.Config.Weights
	}
	return p
}

// goldenStats runs Calculate per address over its keys in sorted order,
// as the harness's storage stub hands them to Echolot.
func goldenStats(t *testing.T, g *golden) map[string]stats.Result {
	t.Helper()
	p := goldenParams(g)
	res := map[string]stats.Result{}
	for addr, rem := range g.Rems {
		var out []time.Time
		var done []stats.Done
		for _, k := range sortedKeys(rem.Keys) {
			for _, s := range rem.Keys[k].Out {
				out = append(out, time.Unix(s, 0))
			}
			for _, d := range rem.Keys[k].Done {
				done = append(done, stats.Done{Sent: time.Unix(d[0], 0), Latency: d[1]})
			}
		}
		r := stats.Calculate(out, done, time.Unix(g.Now, 0), p)
		if r.Clamped != 0 {
			t.Errorf("%s: %d pings clamped", addr, r.Clamped)
		}
		res[addr] = r
	}
	return res
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// goldenRows are the rows Echolot lists: addresses with a key, a nick and
// caps (E:Stats.pm:479-494).
func goldenRows(g *golden, res map[string]stats.Result) []Row {
	var rows []Row
	for addr, rem := range g.Rems {
		if len(rem.Keys) == 0 || rem.Nick == nil || rem.Caps == nil {
			continue
		}
		show := rem.ShowIt == nil || *rem.ShowIt != 0
		rows = append(rows, Row{Nick: *rem.Nick, Address: addr, Caps: *rem.Caps,
			ListIt: ListIt(show, *rem.Caps), Stats: res[addr]})
	}
	return rows
}

func goldenSections(g *golden) Sections {
	get := func(name string) *string {
		if s, ok := g.Files[name]; ok {
			return &s
		}
		return nil
	}
	return Sections{SameOp: get("sameop"), Broken1: get("broken1"), Broken2: get("broken2")}
}

func near(a, b *float64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return math.Abs(*a-*b) <= 1e-9
}

func fmtp(p *float64) string {
	if p == nil {
		return "undef"
	}
	return strconv.FormatFloat(*p, 'g', -1, 64)
}

func goldenCases(t *testing.T) []string {
	dirs, err := filepath.Glob("../../testdata/golden/case*")
	if err != nil || len(dirs) == 0 {
		t.Fatal("no golden cases", err)
	}
	return dirs
}

// TestGoldenCalculate compares Calculate with Echolot's calculate() on
// every golden case, within 1e-9.
func TestGoldenCalculate(t *testing.T) {
	for _, dir := range goldenCases(t) {
		var g golden
		readJSON(t, filepath.Join(dir, "in.json"), &g)
		var want map[string]calcResult
		readJSON(t, filepath.Join(dir, "calc.json"), &want)
		got := goldenStats(t, &g)
		if len(got) != len(want) {
			t.Errorf("%s: %d results, want %d", dir, len(got), len(want))
		}
		for addr, w := range want {
			r := got[addr]
			rel, wrel := r.Reliability, w.Reliability
			if !near(r.Latency, w.Latency) || !near(&rel, &wrel) {
				t.Errorf("%s %s: latency %s reliability %v, want %s %v", dir, addr,
					fmtp(r.Latency), rel, fmtp(w.Latency), wrel)
			}
			days := goldenParams(&g).Days
			if len(r.LatencyDay) != days || len(r.ReliabilityDay) != days || len(w.LatencyDay) > days || len(w.ReliabilityDay) > days {
				t.Fatalf("%s %s: day counts %d %d, want %d", dir, addr, len(r.LatencyDay), len(r.ReliabilityDay), days)
			}
			for d := range days {
				var wl, wr *float64 // Perl's arrays end at the last defined day
				if d < len(w.LatencyDay) {
					wl = w.LatencyDay[d]
				}
				if d < len(w.ReliabilityDay) {
					wr = w.ReliabilityDay[d]
				}
				if !near(r.LatencyDay[d], wl) || !near(r.ReliabilityDay[d], wr) {
					t.Errorf("%s %s day %d: %s %s, want %s %s", dir, addr, d,
						fmtp(r.LatencyDay[d]), fmtp(r.ReliabilityDay[d]), fmtp(wl), fmtp(wr))
				}
			}
		}
	}
}

// TestGoldenLists compares mlist2.txt and mlist.txt, public and private,
// byte for byte with Echolot's, and checks that WriteStats writes them.
func TestGoldenLists(t *testing.T) {
	for _, dir := range goldenCases(t) {
		var g golden
		readJSON(t, filepath.Join(dir, "in.json"), &g)
		rows := goldenRows(&g, goldenStats(t, &g))
		sec := goldenSections(&g)
		now := time.Unix(g.Now, 0)
		byLat := g.Config.SortByLatency != 0
		for _, set := range []struct {
			sub  string
			rows []Row
		}{{"priv", rows}, {"pub", Public(rows)}} {
			out := t.TempDir()
			if err := WriteStats(out, set.rows, sec, now, byLat, true, nil); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"mlist2.txt", "mlist.txt"} {
				want, err := os.ReadFile(filepath.Join(dir, set.sub, name))
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(out, name))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s/%s/%s differs:\n%s\nwant:\n%s", dir, set.sub, name, got, want)
				}
				meta, err := os.ReadFile(filepath.Join(out, name+".meta"))
				if err != nil || !bytes.Equal(meta, Meta(now.Add(5*time.Minute))) {
					t.Errorf("%s.meta: %v %q", name, err, meta)
				}
			}
		}
	}
}

func TestWriteStatsRefuses(t *testing.T) {
	now := time.Unix(1792572345, 0)
	long := strings.Repeat("x", MaxLineLen)
	tooLong := long + "x"
	for name, c := range map[string]struct {
		rows []Row
		sec  Sections
	}{
		"long caps":    {[]Row{{Nick: "a", Caps: `$remailer{"a"} = "<a@b> ` + long + `";`}}, Sections{}},
		"long section": {[]Row{{Nick: "a", Caps: "c"}}, Sections{SameOp: &tooLong}},
		"empty nick":   {[]Row{{Caps: "c"}}, Sections{}},
		"space nick":   {[]Row{{Nick: "a b", Caps: "c"}}, Sections{}},
		"newline caps": {[]Row{{Nick: "a", Caps: "c\nd"}}, Sections{}},
	} {
		dir := t.TempDir()
		if err := WriteStats(dir, c.rows, c.sec, now, false, true, nil); err == nil {
			t.Errorf("%s: no error", name)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("%s: wrote %v", name, ents)
		}
	}
	// The longest allowed line is fine.
	caps := `$remailer{"a"} = "<a@b> ` + long[:MaxLineLen-26] + `";`
	if err := WriteStats(t.TempDir(), []Row{{Nick: "a", Caps: caps}}, Sections{}, now, false, false, nil); err != nil || len(caps) != MaxLineLen {
		t.Error(err, len(caps))
	}
}

func TestSortRows(t *testing.T) {
	l := func(v float64) *float64 { return &v }
	rows := []Row{
		{Nick: "b", Stats: stats.Result{Reliability: 0.5}},
		{Nick: "c", Stats: stats.Result{Reliability: 0.9, Latency: l(10000)}},
		{Nick: "a", Stats: stats.Result{Reliability: 0.9}}, // no latency: 9999
		{Nick: "d", Address: "b@x", Stats: stats.Result{Reliability: 0.9, Latency: l(5)}},
		{Nick: "d", Address: "a@x", Stats: stats.Result{Reliability: 0.9, Latency: l(5)}},
	}
	nicks := func() (s string) {
		for _, r := range rows {
			s += r.Nick + r.Address + " "
		}
		return s
	}
	SortRows(rows, false)
	if got := nicks(); got != "a c da@x db@x b " {
		t.Errorf("by nick: %s", got)
	}
	SortRows(rows, true)
	if got := nicks(); got != "da@x db@x a c b " {
		t.Errorf("by latency: %s", got)
	}
}

func TestListIt(t *testing.T) {
	for _, c := range []struct {
		show bool
		caps string
		want bool
	}{
		{true, `"<a@b> mid v2"`, true},
		{false, `"<a@b> mid v2"`, false},
		{true, `"<a@b> TESTING v2"`, false},
		{true, `"<a@b> testing2 v2"`, true},
	} {
		if got := ListIt(c.show, c.caps); got != c.want {
			t.Errorf("ListIt(%v, %q) = %v", c.show, c.caps, got)
		}
	}
}
