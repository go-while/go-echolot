package chain

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/sched"
	"github.com/go-while/go-echolot/internal/store"
)

var now = time.Unix(1792572345, 0).UTC()

func TestPairs(t *testing.T) {
	got := Pairs([]Hop{
		{"c@x", "kc"}, {"a@x", "ka"}, {"b@x", "kb"},
		{"a@x", "other"}, // a second key for a: the first wins
		{"", "k"}, {"d@x", ""},
	})
	want := []Pair{
		{Hop{"a@x", "ka"}, Hop{"b@x", "kb"}}, {Hop{"a@x", "ka"}, Hop{"c@x", "kc"}},
		{Hop{"b@x", "kb"}, Hop{"a@x", "ka"}}, {Hop{"b@x", "kb"}, Hop{"c@x", "kc"}},
		{Hop{"c@x", "kc"}, Hop{"a@x", "ka"}}, {Hop{"c@x", "kc"}, Hop{"b@x", "kb"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Pairs:\n%v\nwant\n%v", got, want)
	}
	if Pairs([]Hop{{"a@x", "k"}}) != nil || Pairs(nil) != nil {
		t.Error("pairs of one remailer")
	}
	p := want[0]
	if p.SlotID() != "a@x|b@x" || p.Key() != (Key{"a@x", "b@x"}) || p.String() != "a@x b@x" {
		t.Errorf("%q %v %q", p.SlotID(), p.Key(), p)
	}
}

// TestDue: over one weekly session every pair fires once; a pair in
// intensive care also once a day.
func TestDue(t *testing.T) {
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	pairs := Pairs([]Hop{{"a@x", "k"}, {"b@x", "k"}, {"c@x", "k"}, {"d@x", "k"}})
	care := map[Key]string{{"a@x", "b@x"}: "bad: 0/3", {"x@x", "y@x"}: "gone"}
	tick := 5 * time.Minute
	start := time.Unix(sched.Session(now, Period)*int64(Period/time.Second), 0)
	weekly := map[Key]int{}
	daily := map[Key]int{}
	for i := range int(Period / tick) {
		at := start.Add(time.Duration(i) * tick)
		for _, p := range Due(key, pairs, care, at, tick) {
			if sched.Due(key, p.SlotID(), at, Period, tick) {
				weekly[p.Key()]++
			} else {
				daily[p.Key()]++
			}
		}
		if got := Due(key, pairs, nil, at, tick); len(got) > 0 && !sched.Due(key, got[0].SlotID(), at, Period, tick) {
			t.Fatalf("%v due at %v without intensive care", got[0], at)
		}
	}
	for _, p := range pairs {
		k := p.Key()
		if weekly[k] != 1 {
			t.Errorf("%v: %d weekly slots", k, weekly[k])
		}
		wantDaily := 0
		if k == (Key{"a@x", "b@x"}) {
			wantDaily = 7 // one of them may fall on the weekly slot
		}
		if daily[k] != wantDaily && daily[k] != wantDaily-1 {
			t.Errorf("%v: %d daily slots", k, daily[k])
		}
	}
}

func lat(s float64) *float64 { return &s }

func rems() []Remailer {
	return []Remailer{
		{Addr: "a@x", Nick: "a", ListIt: true, Reliability: 1, Latency: lat(600)},
		{Addr: "b@x", Nick: "b", ListIt: true, Reliability: 1, Latency: lat(600)},
		{Addr: "h@x", Nick: "h", ListIt: false, Reliability: 0.5, Latency: lat(300.5)},
		{Addr: "z@x", Nick: "z", ListIt: true, Reliability: 0, Latency: nil},
	}
}

// pings makes n chain pings a→b sent at sent (minus i seconds), the first
// done of them back.
func pings(a, b string, n, done int, sent time.Time) []store.ChainPing {
	var ps []store.ChainPing
	for i := range n {
		p := store.ChainPing{A: a, B: b, Sent: sent.Add(-time.Duration(i) * time.Second)}
		if i < done {
			p.Status, p.Latency = store.PingDone, 100
		}
		ps = append(ps, p)
	}
	return ps
}

func old(a, b string, n, done int) []store.ChainPing {
	return pings(a, b, n, done, now.Add(-48*time.Hour))
}

func evaluate(ps ...[]store.ChainPing) Result {
	return Evaluate(slices.Concat(ps...), rems(), now)
}

func TestEvaluateSamples(t *testing.T) {
	for _, c := range []struct {
		name      string
		pings     []store.ChainPing
		care      string
		broken    bool
		done, out int
	}{
		{"none", nil, "", false, 0, 0},
		{"1 out", old("a@x", "b@x", 1, 0), "only 1 sample, none returned so far", false, 0, 0},
		{"2 out", old("a@x", "b@x", 2, 0), "only 2 samples, none returned so far", false, 0, 0},
		{"exactly 3 out", old("a@x", "b@x", 3, 0), "bad: 0/3", true, 0, 3},
		{"1 of 1 back", old("a@x", "b@x", 1, 1), "", false, 1, 1},
		{"1 of 2 back", old("a@x", "b@x", 2, 1), "", false, 1, 2},
		// rel 1 × 1 × 0.3: 3/10 is broken, 4/10 is not.
		{"3/10", old("a@x", "b@x", 10, 3), "bad: 3/10", true, 3, 10},
		{"4/10", old("a@x", "b@x", 10, 4), "", false, 4, 10},
		// rel 1 × 0.5 × 0.3 = 0.15: 3/20 is broken, 4/20 not.
		{"3/20", old("a@x", "h@x", 20, 3), "bad: 3/20", true, 3, 20},
		{"4/20", old("a@x", "h@x", 20, 4), "", false, 4, 20},
		// rel 0: broken with none back; any ping back beats 0.
		{"dead", old("a@x", "z@x", 3, 0), "bad: 0/3", true, 0, 3},
		{"dead, 1 back", old("z@x", "a@x", 5, 1), "", false, 1, 5},
	} {
		res := evaluate(c.pings)
		var k Key
		if len(c.pings) > 0 {
			k = Key{c.pings[0].A, c.pings[0].B}
		}
		if res.Care[k] != c.care || len(res.Care) > 1 || (c.care == "" && len(res.Care) != 0) {
			t.Errorf("%s: care %v", c.name, res.Care)
		}
		if c.broken != (len(res.Broken) == 1) || len(res.Broken) > 1 {
			t.Errorf("%s: broken %v", c.name, res.Broken)
			continue
		}
		if c.broken {
			b := res.Broken[0]
			if b.A != k.A || b.B != k.B || b.Done != c.done || b.Out != c.out {
				t.Errorf("%s: %+v", c.name, b)
			}
		}
	}
}

// TestEvaluateGrace: an unreturned ping younger than 1.5 × (lat A + lat
// B) doesn't count; one back always does.
func TestEvaluateGrace(t *testing.T) {
	grace := 1800 * time.Second // (600 + 600) × 1.5
	atAB := func(a, b string, d time.Duration, done bool) []store.ChainPing {
		p := store.ChainPing{A: a, B: b, Sent: now.Add(-d)}
		if done {
			p.Status = store.PingDone
		}
		return []store.ChainPing{p}
	}
	at := func(d time.Duration, done bool) []store.ChainPing { return atAB("a@x", "b@x", d, done) }
	if r := evaluate(old("a@x", "b@x", 2, 0), at(grace-time.Second, false)); r.Care[Key{"a@x", "b@x"}] != "only 2 samples, none returned so far" {
		t.Errorf("young ping counted: %v", r.Care)
	}
	if r := evaluate(old("a@x", "b@x", 2, 0), at(grace, false)); len(r.Broken) != 1 {
		t.Errorf("ping exactly at the grace not counted: %v", r.Care)
	}
	if r := evaluate(old("a@x", "b@x", 3, 0), at(time.Second, true)); r.Care[Key{"a@x", "b@x"}] != "bad: 1/4" {
		t.Errorf("young ping back: %v", r.Care)
	}
	// x.5 latencies: (600 + 300.5) × 1.5 = 1350.75 s.
	if r := evaluate(old("a@x", "h@x", 2, 0), atAB("a@x", "h@x", 1350*time.Second, false)); len(r.Care) != 1 || len(r.Broken) != 0 {
		t.Errorf("1350 s counted: %v", r.Care)
	}
	if r := evaluate(old("a@x", "h@x", 2, 0), atAB("a@x", "h@x", 1351*time.Second, false)); len(r.Broken) != 1 {
		t.Errorf("1351 s not counted: %v", r.Care)
	}
	// No latency counts as 0: z→a has a grace of 600 × 1.5 = 900 s.
	if r := evaluate(old("z@x", "a@x", 2, 0), atAB("z@x", "a@x", 899*time.Second, false)); len(r.Broken) != 0 {
		t.Errorf("z, 899 s: %v", r.Care)
	}
	if r := evaluate(old("z@x", "a@x", 2, 0), atAB("z@x", "a@x", 900*time.Second, false)); len(r.Broken) != 1 {
		t.Errorf("z, 900 s: %v", r.Care)
	}
	// A ping from the future (clock skew) has a negative age, below any
	// grace: not counted until it is back.
	if r := evaluate(old("a@x", "b@x", 2, 0), at(-time.Hour, false)); len(r.Broken) != 0 {
		t.Errorf("future ping counted: %v", r.Care)
	}
}

func TestEvaluateWindowAndFilters(t *testing.T) {
	edge := pings("a@x", "b@x", 1, 0, now.Add(-Window))                // counts
	outside := pings("a@x", "b@x", 1, 1, now.Add(-Window-time.Second)) // doesn't
	if r := evaluate(old("a@x", "b@x", 2, 0), edge); len(r.Broken) != 1 {
		t.Errorf("ping exactly at the window not counted: %v", r.Care)
	}
	if r := evaluate(old("a@x", "b@x", 2, 0), outside); len(r.Broken) != 0 {
		t.Errorf("ping outside the window counted: %v", r.Care)
	}
	// Sub-second now: Echolot's time() is whole seconds.
	if r := Evaluate(slices.Concat(old("a@x", "b@x", 2, 0), edge), rems(), now.Add(999*time.Millisecond)); len(r.Broken) != 1 {
		t.Errorf("sub-second now: %v", r.Care)
	}
	aborted := old("a@x", "b@x", 3, 0)
	aborted[0].Status = store.PingAborted
	if r := evaluate(aborted); len(r.Broken) != 0 {
		t.Errorf("aborted ping counted: %v", r.Care)
	}
	if r := evaluate(old("a@x", "q@x", 5, 0), old("q@x", "a@x", 5, 0)); len(r.Care) != 0 {
		t.Errorf("unknown remailer: %v", r.Care)
	}
}

func TestEvaluateBroken(t *testing.T) {
	r := evaluate(old("b@x", "a@x", 3, 0), old("a@x", "h@x", 3, 0), old("a@x", "b@x", 3, 0))
	want := []Broken{
		{A: "a@x", B: "b@x", Chain: "(a b)", Public: true, Done: 0, Out: 3},
		{A: "a@x", B: "h@x", Chain: "(a h)", Public: false, Done: 0, Out: 3},
		{A: "b@x", B: "a@x", Chain: "(b a)", Public: true, Done: 0, Out: 3},
	}
	if !reflect.DeepEqual(r.Broken, want) {
		t.Errorf("broken:\n%+v\nwant\n%+v", r.Broken, want)
	}
	if len(r.Care) != 3 || r.Broken[1].String() != "(a h) 0/3" {
		t.Errorf("care %v, %s", r.Care, r.Broken[1])
	}
}

func TestCompress(t *testing.T) {
	for _, c := range []struct {
		num  int
		in   []string
		want []string
	}{
		{4, []string{"(a b)", "(c b)"}, []string{"(* b)"}},                   // 2 ≥ 4 × 0.5
		{5, []string{"(a b)", "(c b)"}, []string{"(a b)", "(c b)"}},          // 2 < 2.5
		{5, []string{"(a b)", "(c b)", "(d b)"}, []string{"(* b)"}},          // 3 ≥ 2.5
		{6, []string{"(a b)", "(a b)", "(c b)"}, []string{"(a b)", "(c b)"}}, // duplicates count once
		{4, []string{"(a b)", "(a c)", "(d e)"}, []string{"(a *)", "(d e)"}}, // left
		{10, []string{"(* b)", "(a b)"}, []string{"(* b)"}},                  // (* b) adds num
		{10, []string{"(a *)", "(a c)"}, []string{"(a *)"}},                  // (a *) adds num
		{2, []string{"(* b)", "(* c)"}, []string{"(* *)", "(* b)", "(* c)"}}, // "*" as a nick
		{0, []string{"(a b)"}, []string{"(* b)", "(a *)"}},                   // threshold 0
		{0, nil, nil},
		{3, []string{"junk", "", "(a b"}, []string{"", "(a b", "junk"}},                                           // kept, sorted
		{3, []string{"((a b))"}, []string{"((a b))"}},                                                             // nicks "(a" and "b)"
		{2, []string{"((a b))"}, []string{"((a *)", "(* b))"}},                                                    // ... compressed
		{9, []string{"x(a b)y", "(a\tb)", "(a\vb)", "(a  b)"}, []string{"(a\tb)", "(a\vb)", "(a  b)", "x(a b)y"}}, // \t < \v < space
		{6, []string{"x(a b)y", "(a\tb)", "(a\vb)", "(a  b)"}, []string{"(* b)", "(a  b)", "(a *)"}},
	} {
		if got := Compress(c.num, c.in); !slices.Equal(got, c.want) {
			t.Errorf("Compress(%d, %q) = %q, want %q", c.num, c.in, got, c.want)
		}
	}
}

func TestHardLines(t *testing.T) {
	for in, want := range map[string][]string{
		"":               {},
		"\n":             {},
		"(a b)":          {"(a b)"},
		"(a b)\n":        {"(a b)"},
		"(a b)\n\n\n":    {"(a b)"},
		"\n(a b)\n\nx\n": {"", "(a b)", "", "x"},
		"(a b)\r\n":      {"(a b)\r"},
	} {
		if got := HardLines(in); !slices.Equal(got, want) {
			t.Errorf("HardLines(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBrokenText(t *testing.T) {
	broken := []Broken{
		{Chain: "(a b)", Public: true}, {Chain: "(c b)", Public: false}, {Chain: "(d e)", Public: true},
	}
	pub, priv := Broken2Text(broken, []string{"(x y)", "(d e)"}, 4)
	if pub != "(a b)\n(d e)\n(x y)" || priv != "(* b)\n(d e)\n(x y)" {
		t.Errorf("pub %q priv %q", pub, priv)
	}
	if pub, priv := Broken2Text(nil, nil, 4); pub != "" || priv != "" {
		t.Errorf("empty: %q %q", pub, priv)
	}
	if got := Broken1Text(HardLines("(alpha zulu)\n(* bravo)\n")); got != "(* *)\n(* bravo)\n(* zulu)\n(alpha *)" {
		t.Errorf("Broken1Text: %q", got)
	}
	if got := Broken1Text(nil); got != "" || strings.Contains(got, "\n") {
		t.Errorf("Broken1Text(nil): %q", got)
	}
}
