package keys

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// These tests run real data through the parser and the policy: the
// replies in testdata/replies and the pinger pubrings in
// testdata/pubrings, fetched 2026-10-22.

var liveNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestLiveReplies applies victor's real key and conf replies to a new
// remailer: the key is accepted, the nick pinned, and the other remailers
// in the supported list become suggestions only.
func TestLiveReplies(t *testing.T) {
	st := &store.State{Version: store.StateVersion, Remailers: map[string]*store.Remailer{}}
	rem, _ := st.AddRemailer("yamn@virebent.art", liveNow.Add(-time.Hour))

	kr := replies.ParseKey(readTestdata(t, "replies/t_65.key"))
	if len(kr.Keys) != 1 || len(kr.Errors) != 0 {
		t.Fatalf("t_65.key: %+v", kr)
	}
	tok := liveNow.Add(-30 * time.Minute)
	ApplyKeyReply(st, rem, kr.Keys, tok, liveNow, liveNow, cfg)
	k := Publishable(rem, liveNow, false)
	if rem.Nick != "victor" || k == nil || k.KeyID != "dd34d8b7f010229bb790a2402c9ffe65" {
		t.Fatalf("after the key reply: nick %q, publishable %+v", rem.Nick, k)
	}
	if Publishable(rem, liveNow, true) != nil {
		t.Error("published before a ping came back (keys.require_proof)")
	}

	conf, err := replies.ParseConf(readTestdata(t, "replies/t_65.conf"))
	if err != nil {
		t.Fatal(err)
	}
	ApplyConfReply(st, rem, conf, tok.Add(time.Minute), liveNow, liveNow, cfg)
	if rem.Conf == nil || rem.Conf.Caps != `$remailer{"victor"} = "<yamn@virebent.art> middle v2";` {
		t.Errorf("conf: %+v", rem.Conf)
	}
	if len(st.Remailers) != 1 {
		t.Errorf("the supported list added remailers: %d", len(st.Remailers))
	}
	// frell, yamn, yamn2, yamn3, yamn4; victor is this remailer
	if len(st.Prospective) != 5 {
		t.Errorf("%d suggestions, want 5: %v", len(st.Prospective), st.Prospective)
	}
	if len(st.Pending) != 0 {
		t.Errorf("pending changes: %+v", st.Pending)
	}
}

// TestLivePubrings applies each live pubring as if every remailer had
// sent its own key: every key with valid dates is published unchanged,
// in canonical form, and frell's expired middleman key isn't.
func TestLivePubrings(t *testing.T) {
	for _, name := range []string{"mixmin", "victor", "frell"} {
		data := readTestdata(t, "pubrings/"+name+".mix")
		kr := replies.ParseKey(data)
		if len(kr.Errors) != 0 {
			t.Fatalf("%s: %v", name, kr.Errors)
		}
		st := &store.State{Version: store.StateVersion, Remailers: map[string]*store.Remailer{}}
		published := 0
		for _, pk := range kr.Keys {
			rem, _ := st.AddRemailer(pk.Address, liveNow)
			res := ApplyKeyReply(st, rem, []replies.ParsedKey{pk}, liveNow.Add(-time.Hour), liveNow, liveNow, cfg)
			k := Publishable(rem, liveNow, false)
			if pk.Nick == "middleman" { // expired 2026-10-19
				if k != nil || len(res) != 1 || res[0].Decision != Rejected {
					t.Errorf("%s: expired middleman key: %+v, %v", name, k, res)
				}
				continue
			}
			if k == nil {
				t.Errorf("%s: %s not published: %v", name, pk.Nick, res)
				continue
			}
			published++
			line := replies.SummaryLine{Nick: k.Nick, Address: k.Address, KeyID: k.KeyID,
				Version: k.Version, Caps: k.Caps, Created: k.Created, Expires: k.Expires}.String()
			if !strings.Contains(string(data), line+"\n\n-----Begin Mix Key-----\n"+k.KeyID+"\n") {
				t.Errorf("%s: published line %q isn't in the pubring", name, line)
			}
		}
		if published != 6 {
			t.Errorf("%s: %d keys published, want 6", name, published)
		}
	}
}

// TestLiveForgedKey is Y-03: someone who can mail the pinger sends a
// key reply for victor with a key of their own.  victor's real key keeps
// two weeks of validity, so the forged one is quarantined, never
// published, and yamn's self-check would have nothing to report.
func TestLiveForgedKey(t *testing.T) {
	st := &store.State{Version: store.StateVersion, Remailers: map[string]*store.Remailer{}}
	rem, _ := st.AddRemailer("yamn@virebent.art", liveNow)

	real := replies.ParseKey(readTestdata(t, "replies/t_65.key")).Keys
	ApplyKeyReply(st, rem, real, liveNow.Add(-3*time.Hour), liveNow, liveNow, cfg)
	SetProven(rem.Keys[real[0].KeyID], liveNow.Add(-2*time.Hour))

	// A valid key block from the live pubrings, relabelled as victor's:
	// the parser accepts it (the keyid is BLAKE2s of its key).
	pr := replies.ParseKey(readTestdata(t, "pubrings/mixmin.mix")).Keys
	var forged replies.ParsedKey
	for _, pk := range pr {
		if pk.Nick == "yamn4" {
			forged = pk
		}
	}
	forged.Nick, forged.Address = "victor", "yamn@virebent.art"
	for i := range 3 { // repeated replies don't help: the old key is still seen
		tok := liveNow.Add(time.Duration(i) * time.Hour)
		ApplyKeyReply(st, rem, []replies.ParsedKey{forged}, tok, tok, tok, cfg)
		ApplyKeyReply(st, rem, real, tok.Add(time.Minute), tok, tok, cfg)
	}
	ResolvePending(st, liveNow.Add(48*time.Hour), cfg)
	if k := Publishable(rem, liveNow.Add(48*time.Hour), true); k == nil || k.KeyID != real[0].KeyID {
		t.Errorf("published %+v, want victor's real key", k)
	}
	if got := rem.Keys[forged.KeyID].State; got != store.KeyStateQuarantined {
		t.Errorf("forged key is %s", got)
	}
}

// TestLiveForgerAlone: the real remailer goes quiet and only the forger
// keeps answering.  After the quarantine the forged key becomes active,
// but with keys.require_proof it is still never published: no ping
// encrypted to it comes back (§9.2).
func TestLiveForgerAlone(t *testing.T) {
	st := &store.State{Version: store.StateVersion, Remailers: map[string]*store.Remailer{}}
	rem, _ := st.AddRemailer("yamn@virebent.art", liveNow)
	real := replies.ParseKey(readTestdata(t, "replies/t_65.key")).Keys
	ApplyKeyReply(st, rem, real, liveNow.Add(-3*time.Hour), liveNow, liveNow, cfg)
	SetProven(rem.Keys[real[0].KeyID], liveNow.Add(-2*time.Hour))

	var forged replies.ParsedKey
	for _, pk := range replies.ParseKey(readTestdata(t, "pubrings/mixmin.mix")).Keys {
		if pk.Nick == "yamn4" {
			forged = pk
		}
	}
	forged.Nick, forged.Address = "victor", "yamn@virebent.art"
	for i := range 12 {
		tok := liveNow.Add(time.Duration(i) * 2 * time.Hour)
		ApplyKeyReply(st, rem, []replies.ParsedKey{forged}, tok, tok, tok, cfg)
	}
	later := liveNow.Add(30 * time.Hour)
	ResolvePending(st, later, cfg)
	if got := rem.Keys[forged.KeyID].State; got != store.KeyStateActive {
		t.Fatalf("forged key is %s after the quarantine; this test expects it active", got)
	}
	if k := Publishable(rem, later, true); k == nil || k.KeyID != real[0].KeyID {
		t.Errorf("published %+v, want victor's real, proven key", k)
	}
	if k := Publishable(rem, later, false); k == nil || k.KeyID != forged.KeyID {
		t.Errorf("without require_proof: published %+v; this is the case proof of possession prevents", k)
	}
}
