package output

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// now is when testdata/pubrings was fetched.
var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

var keysCfg = config.Keys{Retention: 120 * time.Hour, RotationWindow: 72 * time.Hour,
	Quarantine: 24 * time.Hour, MinSightings: 2, RequireProof: true}

func live(t *testing.T, name string) ([]byte, []replies.ParsedKey) {
	t.Helper()
	data, err := os.ReadFile("../../testdata/pubrings/" + name + ".mix")
	if err != nil {
		t.Fatal(err)
	}
	r := replies.ParseKey(data)
	if len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	return data, r.Keys
}

// TestPubringRoundTrip: parsing a live pubring and writing it again gives
// the same bytes, also from shuffled input.
func TestPubringRoundTrip(t *testing.T) {
	for _, name := range []string{"mixmin", "victor", "frell"} {
		data, ks := live(t, name)
		for i, j := 0, len(ks)-1; i < j; i, j = i+1, j-1 {
			ks[i], ks[j] = ks[j], ks[i]
		}
		got, err := Pubring(ks)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%s: %v\n%s", name, err, got)
		}
		list, err := Type2List(ks)
		var want strings.Builder
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Count(line, " ") == 6 {
				want.WriteString(line + "\n")
			}
		}
		if err != nil || string(list) != want.String() {
			t.Errorf("%s type2.list: %v\n%s", name, err, list)
		}
	}
}

// TestLiveEndToEnd builds the state from each live pubring through the
// key policy, as if every remailer had answered key and conf requests,
// and writes the keyring: it is the live file byte for byte, without
// frell's expired middleman key.
func TestLiveEndToEnd(t *testing.T) {
	for _, name := range []string{"mixmin", "victor", "frell"} {
		data, ks := live(t, name)
		st := &store.State{Version: store.StateVersion, Remailers: map[string]*store.Remailer{}}
		for _, pk := range ks {
			rem, _ := st.AddRemailer(pk.Address, now)
			tok := now.Add(-2 * time.Hour)
			keys.ApplyKeyReply(st, rem, []replies.ParsedKey{pk}, tok, now, now, keysCfg)
			conf := &replies.ConfReply{Nick: pk.Nick, Address: pk.Address, Type: "Mixmaster 0.2.7",
				Caps: `$remailer{"` + pk.Nick + `"} = "<` + pk.Address + `> v2";`}
			keys.ApplyConfReply(st, rem, conf, tok, now, now, keysCfg)
			if k := rem.Keys[pk.KeyID]; k != nil {
				keys.SetProven(k, now.Add(-time.Hour))
			}
		}
		public, private := Keyrings(st, now, true)
		if len(public) != 6 || len(private) != 6 {
			t.Errorf("%s: %d public, %d private keys", name, len(public), len(private))
		}
		dir := t.TempDir()
		if _, err := WriteKeyrings(dir, public, now, true, time.Hour, nil); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(filepath.Join(dir, "pubring.mix"))
		want := string(data)
		if name == "frell" {
			want = removeEntry(want, "middleman ")
		}
		if string(got) != want {
			t.Errorf("%s: written pubring differs:\n%s", name, got)
		}
	}
}

// removeEntry removes the pubring entry whose summary line starts with
// prefix.
func removeEntry(ring, prefix string) string {
	i := strings.Index(ring, "\n"+prefix) + 1
	end := strings.Index(ring[i:], "-----End Mix Key-----\n\n") + len("-----End Mix Key-----\n\n")
	return ring[:i] + ring[i+end:]
}

func TestKeyringsSelection(t *testing.T) {
	_, ks := live(t, "mixmin")
	st := &store.State{Version: store.StateVersion, Remailers: map[string]*store.Remailer{}}
	byNick := map[string]*store.Remailer{}
	for _, pk := range ks {
		rem, _ := st.AddRemailer(pk.Address, now)
		keys.ApplyKeyReply(st, rem, []replies.ParsedKey{pk}, now.Add(-time.Hour), now, now, keysCfg)
		keys.SetProven(rem.Keys[pk.KeyID], now)
		rem.Conf = &store.Conf{Nick: pk.Nick, Caps: `$remailer{"` + pk.Nick + `"} = "<` + pk.Address + `> v2";`}
		byNick[pk.Nick] = rem
	}
	byNick["yamn"].ShowIt = false                                                       // private only
	byNick["yamn2"].Conf.Caps = `$remailer{"yamn2"} = "<yamn2@mixmin.net> testing v2";` // private only
	byNick["yamn3"].Conf = nil                                                          // neither
	byNick["frell"].Conf.Nick = "other"                                                 // neither
	byNick["victor"].Keys["dd34d8b7f010229bb790a2402c9ffe65"].ProvenAt = time.Time{}    // unproven

	nicks := func(ks []replies.ParsedKey) string {
		var n []string
		for _, k := range ks {
			n = append(n, k.Nick)
		}
		slices.Sort(n)
		return strings.Join(n, " ")
	}
	public, private := Keyrings(st, now, true)
	if got := nicks(public); got != "yamn4" {
		t.Errorf("public: %s", got)
	}
	if got := nicks(private); got != "yamn yamn2 yamn4" {
		t.Errorf("private: %s", got)
	}
	public, _ = Keyrings(st, now, false)
	if got := nicks(public); got != "victor yamn4" {
		t.Errorf("public without require_proof: %s", got)
	}
}

func TestPubringRefuses(t *testing.T) {
	_, ks := live(t, "mixmin")
	for name, edit := range map[string]func(ks []replies.ParsedKey){
		"keyid":       func(ks []replies.ParsedKey) { ks[0].PK[0] ^= 1 },
		"nick twice":  func(ks []replies.ParsedKey) { ks[1].Nick = ks[0].Nick },
		"addr twice":  func(ks []replies.ParsedKey) { ks[1].Address = ks[0].Address },
		"bad nick":    func(ks []replies.ParsedKey) { ks[0].Nick = "Frell" },
		"bad address": func(ks []replies.ParsedKey) { ks[0].Address = "a b@example.org" },
	} {
		c := append([]replies.ParsedKey(nil), ks...)
		edit(c)
		if _, err := Pubring(c); err == nil {
			t.Errorf("%s: no error", name)
		}
		if _, err := Type2List(c); err == nil {
			t.Errorf("%s: type2.list, no error", name)
		}
	}
}

// TestLongLine: a line over MaxLineLen is never written, and the files
// already there stay.
func TestLongLine(t *testing.T) {
	_, ks := live(t, "mixmin")
	dir := t.TempDir()
	if _, err := WriteKeyrings(dir, ks, now, false, 0, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "pubring.mix"))
	ks[2].Caps = strings.Repeat("E", MaxLineLen) // the parser limits caps; the writer is the second defence
	if _, err := WriteKeyrings(dir, ks, now, false, 0, nil); err == nil || !strings.Contains(err.Error(), "more than 1024") {
		t.Errorf("got %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "pubring.mix")); !bytes.Equal(before, after) {
		t.Error("pubring.mix changed")
	}
	if err := checkLines("x", []byte(strings.Repeat("a", MaxLineLen)+"\n"+strings.Repeat("b", MaxLineLen))); err != nil {
		t.Errorf("lines of exactly %d bytes: %v", MaxLineLen, err)
	}
	if err := checkLines("x", []byte("a\n"+strings.Repeat("b", MaxLineLen+1))); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("unterminated long last line: %v", err)
	}
}

func TestWriteKeyrings(t *testing.T) {
	_, ks := live(t, "victor")
	dir := t.TempDir()
	changed, err := WriteKeyrings(dir, ks, now, true, time.Hour, nil)
	if err != nil || !changed {
		t.Fatalf("first write: %v, %v", changed, err)
	}
	ring := filepath.Join(dir, "pubring.mix")
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(ring, old, old)
	changed, err = WriteKeyrings(dir, ks, now.Add(time.Hour), true, time.Hour, nil)
	if err != nil || changed {
		t.Errorf("unchanged keys: changed %v, %v", changed, err)
	}
	if fi, _ := os.Stat(ring); !fi.ModTime().Equal(old) {
		t.Error("pubring.mix rewritten without a change")
	}
	for _, name := range []string{"pubring.mix.meta", "type2.list.meta"} {
		got, _ := os.ReadFile(filepath.Join(dir, name))
		if string(got) != "Expires: Thu, 22 Oct 2026 14:00:00 +0000\n" {
			t.Errorf("%s: %q", name, got)
		}
	}
	if fi, _ := os.Stat(ring); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	changed, err = WriteKeyrings(dir, ks[1:], now, true, time.Hour, nil)
	if err != nil || !changed {
		t.Errorf("one key less: changed %v, %v", changed, err)
	}

	// No keys: empty files, which yamn refuses to download (§7.1).
	dir = t.TempDir()
	if _, err := WriteKeyrings(dir, nil, now, false, 0, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pubring.mix", "type2.list"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Size() != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "pubring.mix.meta")); !os.IsNotExist(err) {
		t.Error(".meta written with meta off")
	}
}

func TestMeta(t *testing.T) {
	// Echolot's date822: "%s, %02d %s %d %02d:%02d:%02d +0000" in UTC.
	tz := time.FixedZone("x", 2*3600)
	if got := string(Meta(time.Date(2026, 3, 5, 1, 2, 3, 0, tz))); got != "Expires: Wed, 04 Mar 2026 23:02:03 +0000\n" {
		t.Errorf("got %q", got)
	}
}
