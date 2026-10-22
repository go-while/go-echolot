package echolotimport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// liveKeys returns the keys of mixmin's live pubring by nick.
func liveKeys(t *testing.T) map[string]replies.ParsedKey {
	data, err := os.ReadFile("../../../testdata/pubrings/mixmin.mix")
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]replies.ParsedKey{}
	for _, k := range replies.ParseKey(data).Keys {
		m[k.Nick] = k
	}
	return m
}

// echolotDir writes an Echolot data dir as Echolot (with the yamn patch)
// keeps it, and its metadata exported to JSON as the docs say.
func echolotDir(t *testing.T) (Options, map[string]replies.ParsedKey) {
	dir := t.TempDir()
	ks := liveKeys(t)
	type key struct {
		Key, Summary, Nick, Stats string
		LastUpdate                any `json:"last_update"`
	}
	block := func(k replies.ParsedKey) string {
		return fmt.Sprintf("-----Begin Mix Key-----\n%s\n%x\n-----End Mix Key-----", k.KeyID, k.PK)
	}
	rem := func(conf map[string]any, list ...replies.ParsedKey) map[string]any {
		mix := map[string]key{}
		for _, k := range list {
			stats := k.Address + ".mix." + k.KeyID[:4] + ".1792000000.123_4"
			mix[k.KeyID] = key{block(k), k.String(), k.Nick, stats, "1792600000"} // a number as a string, as Perl may write it
		}
		return map[string]any{"conf": conf, "keys": map[string]any{"mix": mix}}
	}
	conf := func(nick, addr, opts string) map[string]any {
		return map[string]any{"nick": nick, "type": "Mixmaster 0.2.7", "last_update": 1792600000,
			"capabilities": fmt.Sprintf(`$remailer{"%s"} = "<%s> %s";`, nick, addr, opts)}
	}
	md := map[string]any{
		"version": 1, "secret": "0123456789abcdef0123456789abcdef", "addresses_maxid": 9,
		"addresses": map[string]any{
			"yamn@mixmin.net":            map[string]any{"id": 2, "status": "active", "ttl": 5, "fetch": 1, "showit": 1, "pingit": 1},
			"yamn@virebent.art":          map[string]any{"id": 5, "status": "ttl timeout", "ttl": "0", "resurrection_ttl": 6, "fetch": 1, "showit": 0, "pingit": 1},
			"nyam@remailer.frell.eu.org": map[string]any{"id": 7, "status": "disabled by user request", "ttl": 5, "fetch": 0, "showit": 0, "pingit": 0},
			"bad address":                map[string]any{"id": 8},
		},
		"remailers": map[string]any{
			"yamn@mixmin.net":            rem(conf("yamn", "yamn@mixmin.net", "v2"), ks["yamn"]),
			"yamn@virebent.art":          rem(conf("victor", "yamn@virebent.art", "middle v2"), ks["victor"]),
			"nyam@remailer.frell.eu.org": rem(nil, ks["frell"]),
		},
		"prospective_addresses": map[string]any{"yamn3@mixmin.net": []string{"1792500000; reliable-caps-reply-type2; yamn@mixmin.net", "garbage"}},
	}
	data, _ := json.Marshal(md)
	os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o600)

	// Ping files: yamn has 3 done, 1 old out (a loss), 1 young out (dropped).
	y := ks["yamn"]
	base := filepath.Join(dir, y.Address+".mix."+y.KeyID[:4]+".1792000000.123_4")
	n := now.Unix()
	os.WriteFile(base+".done", []byte(fmt.Sprintf("%d 600\n%d 1200\n%d 300\nnot a line\n", n-3*86400, n-2*86400, n-86400)), 0o600)
	os.WriteFile(base+".out", []byte(fmt.Sprintf("%d\n%d\n", n-2*86400, n-3600)), 0o600)

	// Chain pings, as Echolot keeps them (.out has every one sent):
	// yamn → victor in .done only (never sent: dropped, as Echolot);
	// victor → frell in .out and .done (done); yamn → victor out, old (a
	// loss) and young (dropped); one with a key that wasn't imported
	// (chains go by address: a loss); a bad line.
	v, f := ks["victor"], ks["frell"]
	chain := func(sent int64, a, b replies.ParsedKey) string {
		return fmt.Sprintf("%d %s mix %s %s mix %s", sent, a.Address, a.KeyID, b.Address, b.KeyID)
	}
	os.WriteFile(filepath.Join(dir, "chainpings.mix.done"), []byte(chain(n-4*86400, y, v)+" 900\n"+chain(n-3*86400, v, f)+" 1800\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "chainpings.mix.out"), []byte(chain(n-2*86400, y, v)+"\n"+chain(n-3600, y, v)+"\n"+
		chain(n-3*86400, v, f)+"\n"+fmt.Sprintf("%d %s mix %s %s mix %s\n", n-2*86400, y.Address, "00000000000000000000000000000000", v.Address, v.KeyID)+
		"junk\n"), 0o600)

	th := filepath.Join(dir, "thesaurus")
	os.MkdirAll(th, 0o700)
	os.WriteFile(filepath.Join(th, "2.key"), []byte("reply"), 0o600)
	os.WriteFile(filepath.Join(th, "2.stats"), []byte("x"), 0o600) // not a kind we keep
	os.WriteFile(filepath.Join(th, "index.html"), []byte("x"), 0o600)
	return Options{Metadata: filepath.Join(dir, "metadata.json"), DataDir: dir, Thesaurus: th, Now: now}, ks
}

func TestImport(t *testing.T) {
	opt, ks := echolotDir(t)
	stateDir := t.TempDir()
	st, err := store.Open(stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rep, err := Import(st, opt)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Remailers != 3 || rep.Keys != 3 || rep.Done != 3 || rep.Out != 1 || rep.OutDropped != 1 || rep.Suggestions != 1 || rep.Thesaurus != 1 {
		t.Errorf("report: %+v", rep)
	}
	if rep.ChainDone != 1 || rep.ChainOut != 2 || rep.ChainDropped != 2 {
		t.Errorf("chain pings: %+v", rep)
	}
	if cps := st.ChainPings(time.Time{}); len(cps) != 3 || cps[0].Status != store.PingDone || cps[0].Latency != 1800 || cps[0].B != "nyam@remailer.frell.eu.org" {
		t.Errorf("chain pings: %+v", cps)
	}
	for _, want := range []string{"bad address: not an address", "not a line", `"garbage" not imported`} {
		if !strings.Contains(strings.Join(rep.Problems, "\n"), want) {
			t.Errorf("no problem %q in %q", want, rep.Problems)
		}
	}
	st.View(func(s *store.State) {
		if s.MaxID != 9 {
			t.Errorf("MaxID %d", s.MaxID)
		}
		y := s.Remailers["yamn@mixmin.net"]
		if y.ID != 2 || y.Nick != "yamn" || y.Conf == nil || y.Conf.Caps != `$remailer{"yamn"} = "<yamn@mixmin.net> v2";` {
			t.Errorf("yamn: %+v %+v", y, y.Conf)
		}
		k := y.Keys[ks["yamn"].KeyID]
		first := now.Add(-3*24*time.Hour + 600*time.Second)
		if k == nil || k.State != store.KeyStateActive || !k.ProvenAt.Equal(first) || k.LastSeen.Unix() != 1792600000 {
			t.Errorf("yamn key: %+v", k)
		}
		v := s.Remailers["yamn@virebent.art"]
		if v.Status != store.StatusTTLTimeout || v.TTL != 0 || v.ResurrectionTTL != 6 || v.ShowIt || v.Nick != "victor" {
			t.Errorf("victor: %+v", v)
		}
		f := s.Remailers["nyam@remailer.frell.eu.org"]
		if f.Status != store.StatusDisabled || f.Fetch || f.Nick != "frell" || f.Conf != nil {
			t.Errorf("frell: %+v", f) // nick pinned from its key, as there's no conf
		}
		if len(s.Prospective["yamn3@mixmin.net"]) != 1 {
			t.Errorf("suggestions: %+v", s.Prospective)
		}
	})
	out, done := st.Pings("yamn@mixmin.net", time.Time{})
	if len(out) != 1 || len(done) != 3 || !done[0].Counted || done[0].Latency != 600 {
		t.Errorf("pings: out %+v done %+v", out, done)
	}
	secret, until, err := ReadLegacy(stateDir)
	if err != nil || secret != "0123456789abcdef0123456789abcdef" || !until.Equal(now.Add(LegacyWindow)) {
		t.Errorf("legacy: %q %v %v", secret, until, err)
	}
	if fi, err := os.Stat(filepath.Join(stateDir, LegacyFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("legacy file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "thesaurus", "2.key")); err != nil {
		t.Errorf("thesaurus: %v", err)
	}

	// Only into an empty state dir.
	if _, err := Import(st, opt); err == nil || !strings.Contains(err.Error(), "already has remailers") {
		t.Errorf("second import: %v", err)
	}
}

func TestImportNickMismatch(t *testing.T) {
	opt, ks := echolotDir(t)
	var md map[string]any
	data, _ := os.ReadFile(opt.Metadata)
	json.Unmarshal(data, &md)
	// yamn's conf now says nick "other": its key (nick yamn) is quarantined.
	r := md["remailers"].(map[string]any)["yamn@mixmin.net"].(map[string]any)
	r["conf"].(map[string]any)["nick"] = "other"
	r["conf"].(map[string]any)["capabilities"] = `$remailer{"other"} = "<yamn@mixmin.net> v2";`
	data, _ = json.Marshal(md)
	os.WriteFile(opt.Metadata, data, 0o600)
	st, _ := store.Open(t.TempDir(), nil)
	defer st.Close()
	rep, err := Import(st, opt)
	if err != nil {
		t.Fatal(err)
	}
	st.View(func(s *store.State) {
		if k := s.Remailers["yamn@mixmin.net"].Keys[ks["yamn"].KeyID]; k.State != store.KeyStateQuarantined {
			t.Errorf("key with another nick is %s; problems %q", k.State, rep.Problems)
		}
	})
}

// TestFakeMetadata: the synthetic metadata file of testdata, exported with
// the perl command of the docs.  Its address and key are broken: both are
// reported, nothing is imported.
func TestFakeMetadata(t *testing.T) {
	st, _ := store.Open(t.TempDir(), nil)
	defer st.Close()
	rep, err := Import(st, Options{Metadata: "../../../testdata/echolot-import/fake-metadata.json", DataDir: t.TempDir(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Remailers != 0 || rep.Keys != 0 || rep.Suggestions != 1 || !strings.Contains(rep.Problems[0], "yamn.net: not an address") {
		t.Errorf("%+v", rep)
	}
}

func TestImportErrors(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(t.TempDir(), nil)
	defer st.Close()
	for name, content := range map[string]string{
		"perl.txt":  "$METADATA = {};",
		"v2.json":   `{"version":2}`,
		"badn.json": `{"version":"x"}`,
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o600)
		if _, err := Import(st, Options{Metadata: p, Now: now}); err == nil {
			t.Errorf("%s imported", name)
		}
	}
	if _, err := Import(st, Options{Metadata: filepath.Join(dir, "nosuch"), Now: now}); err == nil {
		t.Error("missing file")
	}
}

// TestImportReplacedKey: stock Echolot doesn't check that a keyid matches
// its key, so a forged reply with the same keyid but another key replaces
// the stored key, and the ping history stays with the keyid.  Those pings
// were encrypted to the old key; they must not prove the new one.  The
// import checks keyid = BLAKE2s(key) before a key gets any history or
// proof (review 2026-10-22).
func TestImportReplacedKey(t *testing.T) {
	opt, ks := echolotDir(t)
	var md map[string]any
	data, _ := os.ReadFile(opt.Metadata)
	json.Unmarshal(data, &md)
	y, other := ks["yamn"], ks["yamn2"]
	k := md["remailers"].(map[string]any)["yamn@mixmin.net"].(map[string]any)["keys"].(map[string]any)["mix"].(map[string]any)[y.KeyID].(map[string]any)
	// Same keyid everywhere, yamn2's public key in the block.
	k["key"] = fmt.Sprintf("-----Begin Mix Key-----\n%s\n%x\n-----End Mix Key-----", y.KeyID, other.PK)
	data, _ = json.Marshal(md)
	os.WriteFile(opt.Metadata, data, 0o600)

	st, _ := store.Open(t.TempDir(), nil)
	defer st.Close()
	rep, err := Import(st, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Problems, "\n"), "is not BLAKE2s of the public key") {
		t.Errorf("not reported: %q", rep.Problems)
	}
	st.View(func(s *store.State) {
		if k := s.Remailers["yamn@mixmin.net"].Keys[y.KeyID]; k != nil {
			t.Errorf("replaced key imported: %+v", k)
		}
	})
	if out, done := st.Pings("yamn@mixmin.net", time.Time{}); len(out)+len(done) != 0 || rep.Done != 0 {
		t.Errorf("history of the replaced key imported: out %d done %d", len(out), len(done))
	}
}
