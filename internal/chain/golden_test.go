package chain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/stats"
	"github.com/go-while/go-echolot/internal/store"
)

// golden is a chain case's in.json (tools/golden/gen.py chainN).
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
	ChainPings [][4]any          `json:"chainpings"` // sent, addr1, addr2, latency or null
	Files      map[string]string `json:"files"`
	Compress   [][2]any          `json:"compress"` // num, list
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

// rows are the harness's remailers as the daemon's stats run makes them:
// stats.Calculate over all keys of an address, with Echolot's default
// parameters; only addresses with a key, a nick and caps
// (E:Stats.pm:479-494).
func (g *golden) rows() []output.Row {
	p := stats.Params{Days: 12, Weights: []float64{0.5, 1.0, 1.0, 1.0, 1.0, 0.9, 0.8, 0.5, 0.3, 0.2, 0.2, 0.1},
		SkewAbs: 15 * time.Minute, SkewPercent: 0.8}
	var rows []output.Row
	for addr, rem := range g.Rems {
		if len(rem.Keys) == 0 || rem.Nick == nil || rem.Caps == nil {
			continue
		}
		var out []time.Time
		var done []stats.Done
		for _, k := range rem.Keys {
			for _, s := range k.Out {
				out = append(out, time.Unix(s, 0))
			}
			for _, d := range k.Done {
				done = append(done, stats.Done{Sent: time.Unix(d[0], 0), Latency: d[1]})
			}
		}
		show := rem.ShowIt == nil || *rem.ShowIt != 0
		rows = append(rows, output.Row{Nick: *rem.Nick, Address: addr, Caps: *rem.Caps,
			ListIt: output.ListIt(show, *rem.Caps), Stats: stats.Calculate(out, done, time.Unix(g.Now, 0), p)})
	}
	return rows
}

// remailers are the rows as Evaluate wants them.
func remailers(rows []output.Row) []Remailer {
	var rems []Remailer
	for _, r := range rows {
		rems = append(rems, Remailer{Addr: r.Address, Nick: r.Nick, ListIt: r.ListIt,
			Reliability: r.Stats.Reliability, Latency: r.Stats.Latency})
	}
	return rems
}

// pings are the case's chain pings as the store returns them.
func (g *golden) pings(t *testing.T) []store.ChainPing {
	var ps []store.ChainPing
	for i, c := range g.ChainPings {
		sent, ok1 := c[0].(float64)
		a, ok2 := c[1].(string)
		b, ok3 := c[2].(string)
		if !ok1 || !ok2 || !ok3 {
			t.Fatalf("chain ping %v", c)
		}
		p := store.ChainPing{ID: uint64(i + 1), A: a, KeyA: "k1", B: b, KeyB: "k2", Sent: time.Unix(int64(sent), 0).UTC()}
		if lat, ok := c[3].(float64); ok {
			p.Status, p.Latency, p.Received = store.PingDone, int64(lat), p.Sent.Add(time.Duration(lat)*time.Second)
		}
		ps = append(ps, p)
	}
	return ps
}

// hard returns the lines of an operator file of the case; nil if missing.
func (g *golden) hard(name string) []string {
	if s, ok := g.Files[name]; ok {
		return HardLines(s)
	}
	return nil
}

func goldenCases(t *testing.T) []string {
	dirs, err := filepath.Glob("../../testdata/golden/chain*")
	if err != nil || len(dirs) == 0 {
		t.Fatal("no golden chain cases", err)
	}
	return dirs
}

// TestGoldenChains compares the evaluation with Echolot's on every chain
// case: the intensive care (which holds every broken chain, "bad: d/o"),
// and mlist2.txt and mlist.txt, public and private, byte for byte, with
// the broken sections from Broken1Text and Broken2Text.
func TestGoldenChains(t *testing.T) {
	for _, dir := range goldenCases(t) {
		var g golden
		readJSON(t, filepath.Join(dir, "in.json"), &g)
		now := time.Unix(g.Now, 0)
		rows := g.rows()
		res := Evaluate(g.pings(t), remailers(rows), now)

		var wantIC map[string]string
		readJSON(t, filepath.Join(dir, "ic.json"), &wantIC)
		gotIC := map[string]string{}
		for k, v := range res.Care {
			gotIC[k.A+" "+k.B] = v
		}
		for k, v := range wantIC {
			if gotIC[k] != v {
				t.Errorf("%s: intensive care %s: %q, want %q", dir, k, gotIC[k], v)
			}
		}
		for k, v := range gotIC {
			if _, ok := wantIC[k]; !ok {
				t.Errorf("%s: intensive care %s: %q, not in Echolot's", dir, k, v)
			}
		}

		pub, priv := Broken2Text(res.Broken, g.hard("broken2"), len(rows))
		b1 := Broken1Text(g.hard("broken1"))
		var sameop *string
		if s, ok := g.Files["sameop"]; ok {
			sameop = &s
		}
		for _, set := range []struct {
			sub     string
			rows    []output.Row
			broken2 string
		}{{"priv", rows, priv}, {"pub", output.Public(rows), pub}} {
			out := t.TempDir()
			sec := output.Sections{SameOp: sameop, Broken1: &b1, Broken2: &set.broken2}
			if err := output.WriteStats(out, set.rows, sec, now, false, false, nil); err != nil {
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
			}
		}
	}
}

// TestGoldenCompress compares Compress with compress_broken_chain on the
// lists of chain3.
func TestGoldenCompress(t *testing.T) {
	var g golden
	readJSON(t, "../../testdata/golden/chain3/in.json", &g)
	var want [][]string
	readJSON(t, "../../testdata/golden/chain3/compress.json", &want)
	if len(g.Compress) == 0 || len(want) != len(g.Compress) {
		t.Fatalf("%d cases, %d results", len(g.Compress), len(want))
	}
	for i, c := range g.Compress {
		num := int(c[0].(float64))
		var list []string
		for _, s := range c[1].([]any) {
			list = append(list, s.(string))
		}
		got := Compress(num, list)
		if len(got) == 0 && len(want[i]) == 0 {
			continue
		}
		if !slices.Equal(got, want[i]) {
			t.Errorf("Compress(%d, %q) = %q, want %q", num, list, got, want[i])
		}
	}
}
