package app

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/mailout"
	"github.com/go-while/go-echolot/internal/pinger"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/token"
)

// plainEncoder stands in for yamn: it "encrypts" by returning the mail as
// it is, addressed to the first hop.
type plainEncoder struct{ fail error }

func (e plainEncoder) Encode(_ context.Context, chain []pinger.Hop, mail []byte) (string, []byte, error) {
	if e.fail != nil {
		return "", nil, e.fail
	}
	return chain[0].Address, mail, nil
}

// pingHarness has victor with its real key, proven and published, and a
// forged key for it, quarantined.
func pingHarness(t *testing.T) (*harness, string, string) {
	h := newHarness(t, true)
	h.d.encoder = plainEncoder{}
	h.command("add", "yamn@virebent.art", "victor")
	real := replies.ParseKey([]byte(liveKey(t, "victor"))).Keys[0]
	forged := replies.ParseKey([]byte(liveKey(t, "yamn4"))).Keys[0]
	h.st.Update(func(st *store.State) error {
		r := st.Remailers["yamn@virebent.art"]
		r.Keys = map[string]*store.Key{}
		for _, k := range []struct {
			pk    replies.ParsedKey
			state string
		}{{real, store.KeyStateActive}, {forged, store.KeyStateQuarantined}} {
			r.Keys[k.pk.KeyID] = &store.Key{KeyID: k.pk.KeyID, Nick: "victor", Address: r.Address, Version: k.pk.Version,
				Caps: k.pk.Caps, Created: k.pk.Created, Expires: k.pk.Expires, PK: store.PublicKey(k.pk.PK),
				LastSeen: h.clock.Now(), State: k.state}
		}
		r.Keys[real.KeyID].ProvenAt = h.clock.Now().Add(-time.Hour)
		return nil
	})
	return h, real.KeyID, forged.KeyID
}

// TestPingCounted: a ping counts only if its key was published when it
// was sent, decided then: deleting the forged key later doesn't turn its
// lost pings into losses of victor (review of #8).
func TestPingCounted(t *testing.T) {
	h, real, forged := pingHarness(t)
	h.command("sendpings")
	out, _ := h.st.Pings("yamn@virebent.art", time.Time{})
	if len(out) != 2 {
		t.Fatalf("pings: %+v\n%s", out, h.log)
	}
	for _, p := range out {
		if want := p.KeyID == real; p.Counted != want {
			t.Errorf("ping to %s: counted %v", p.KeyID, p.Counted)
		}
	}
	h.st.Update(func(st *store.State) error { delete(st.Remailers["yamn@virebent.art"].Keys, forged); return nil })
	var ks map[string]*store.Key
	h.st.View(func(st *store.State) { ks = st.Remailers["yamn@virebent.art"].Keys })
	counted := h.d.countedPing(ks)
	for _, p := range out {
		if counted(p) != (p.KeyID == real) {
			t.Errorf("after deleting the forged key, ping to %s counted %v", p.KeyID, counted(p))
		}
	}
}

// TestPingSendFailure: any send error is ours, an abort, even a 5xx.
func TestPingSendFailure(t *testing.T) {
	h, _, _ := pingHarness(t)
	h.mailer.fail = fmt.Errorf("550 relaying denied: %w", mailout.ErrPermanent)
	h.command("sendpings")
	out, _ := h.st.Pings("yamn@virebent.art", time.Time{})
	if len(out) != 0 {
		t.Errorf("pings still out (counted as lost): %+v", out)
	}
	h.d.encoder = plainEncoder{fail: fmt.Errorf("yamn: exit status 1: %w", pinger.ErrLocal)}
	h.mailer.fail = nil
	h.command("sendpings")
	if out, _ := h.st.Pings("yamn@virebent.art", time.Time{}); len(out) != 0 {
		t.Errorf("pings out after a yamn failure: %+v", out)
	}
}

// TestProofAfterCrash: the done was saved but the proof wasn't (a crash
// between the two); the same mail again proves the key.
func TestProofAfterCrash(t *testing.T) {
	h, _, forged := pingHarness(t)
	sent := h.clock.Now()
	p, _ := h.st.AddPing(store.Ping{Addr: "yamn@virebent.art", KeyID: forged, Sent: sent})
	sealed, err := pinger.Seal(&h.d.macKey, &h.d.boxKey, pinger.Body{Remailer: p.Addr, Type: pinger.TypeMix,
		KeyID: forged, Sent: p.Sent, ID: p.ID}, 64, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	to, _ := h.d.minter.Address(token.Token{Kind: token.KindPing, Time: p.Sent})
	h.clock.Advance(time.Minute)
	h.st.PingDone(p.ID, h.clock.Now(), 60) // saved before the "crash"
	h.deliver(string(pinger.Mail(to, "", false, sealed)))
	h.d.ScanMail(context.Background())
	h.st.View(func(st *store.State) {
		if k := st.Remailers["yamn@virebent.art"].Keys[forged]; k.ProvenAt.IsZero() {
			t.Errorf("key not proven after the mail came again\n%s", h.log)
		}
	})
}

// TestFromlines: a ping that comes back records the exit's From header
// and whether it added text above or below (E:Pinger.pm:150-205).
func TestFromlines(t *testing.T) {
	h, real, _ := pingHarness(t)
	for i, tc := range []struct {
		withFrom   bool
		from, pre  string
		post       string
		top, bot   bool
		wantFrom   string
		wantStored bool
	}{
		{false, "Nobody <nobody@exit.example>", "", "", false, false, "Nobody <nobody@exit.example>", true},
		{true, "pinger@pinger.example.org", "This mail was sent anonymously.\n\n", "\n-- \nAbuse: abuse@exit.example\n", true, true, "pinger@pinger.example.org", true},
	} {
		sent := h.clock.Now().Add(time.Duration(i) * time.Second)
		p, _ := h.st.AddPing(store.Ping{Addr: "yamn@virebent.art", KeyID: real, WithFrom: tc.withFrom, Sent: sent})
		sealed, _ := pinger.Seal(&h.d.macKey, &h.d.boxKey, pinger.Body{Remailer: p.Addr, Type: pinger.TypeMix,
			KeyID: real, WithFrom: tc.withFrom, Sent: p.Sent, ID: p.ID}, 64, rand.Reader)
		to, _ := h.d.minter.Address(token.Token{Kind: token.KindPing, Time: p.Sent})
		h.clock.Advance(time.Minute)
		h.deliver(fmt.Sprintf("From: %s\nTo: %s\n\n%s%s%s", tc.from, to, tc.pre, sealed, tc.post))
		h.d.ScanMail(context.Background())
		h.st.View(func(st *store.State) {
			wf := 0
			if tc.withFrom {
				wf = 1
			}
			f, ok := st.Fromlines["yamn@virebent.art"][wf]
			if !ok || f.From != tc.wantFrom || f.DisclaimTop != tc.top || f.DisclaimBot != tc.bot {
				t.Errorf("case %d: %+v %v\n%s", i, f, ok, h.log)
			}
		})
	}
	// Expired after 5 days.
	h.st.Update(func(st *store.State) error { expireFromlines(st, h.clock.Now().Add(6*24*time.Hour)); return nil })
	h.st.View(func(st *store.State) {
		if len(st.Fromlines) != 0 {
			t.Errorf("not expired: %+v", st.Fromlines)
		}
	})
	if got := cleanFrom("a\x00bé" + strings.Repeat("x", 300)); strings.ContainsAny(got, "\x00é") || len(got) > maxFromLen+3 {
		t.Errorf("cleanFrom: %q", got)
	}
}

// TestBrokenChains: chain pings that don't come back make a broken chain
// in mlist2.txt; the sections are always printed with chain pings on.
func TestBrokenChains(t *testing.T) {
	h := newHarness(t, false)
	h.d.encoder = plainEncoder{}
	// victor is added with its domain in upper case: its key says
	// yamn@virebent.art (same address, §6.4), the chain pings and their
	// evaluation must still match (review of phase 3).
	stored := map[string]string{"victor": "yamn@VIREBENT.art", "yamn4": "yamn4@mixmin.net"}
	for _, nick := range []string{"victor", "yamn4"} {
		k := replies.ParseKey([]byte(liveKey(t, nick))).Keys[0]
		h.command("add", stored[nick], nick)
		h.st.Update(func(st *store.State) error {
			r := st.Remailers[stored[nick]]
			r.Conf = &store.Conf{Nick: nick, Caps: fmt.Sprintf(`$remailer{"%s"} = "<%s> v2";`, nick, k.Address)}
			r.Keys = map[string]*store.Key{k.KeyID: {KeyID: k.KeyID, Nick: nick, Address: k.Address, Version: k.Version,
				Caps: k.Caps, Created: k.Created, Expires: k.Expires, PK: store.PublicKey(k.PK), LastSeen: h.clock.Now(),
				State: store.KeyStateActive}}
			return nil
		})
	}
	h.clock.Advance(12 * time.Hour) // keys of 2026-10-17..31 valid; e2eStart is 10-22 00:00
	for range 3 {
		h.command("sendchainpings", "yamn@VIREBENT.art:yamn4@mixmin.net")
		h.clock.Advance(24 * time.Hour)
	}
	if got := len(h.st.ChainPings(time.Time{})); got != 3 {
		t.Fatalf("%d chain pings journalled\n%s", got, h.log)
	}
	if n := len(h.mailer.take()); n != 3 {
		t.Errorf("%d chain pings sent", n)
	}
	h.command("buildstats")
	ml, _ := os.ReadFile(filepath.Join(h.cfg.Paths.PrivateResultsDir, "mlist2.txt"))
	if !strings.Contains(string(ml), "Broken type-I remailer chains:\n") || !strings.Contains(string(ml), "Broken type-II remailer chains:\n(") {
		t.Errorf("mlist2.txt:\n%s", ml)
	}
	html, _ := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, "mlist2.html"))
	if !strings.Contains(string(html), "victor") {
		t.Errorf("mlist2.html lacks the chain")
	}

	// The mail fuse stops the loop: one try, not every pair.
	h.mailer.fail = fmt.Errorf("fuse: %w", mailout.ErrRateLimited)
	before := len(h.st.ChainPings(time.Time{}))
	h.command("sendchainpings", "all")
	if !strings.Contains(h.log.String(), "mail.max_per_hour reached: chain pings left") || len(h.st.ChainPings(time.Time{})) != before {
		t.Errorf("rate limit: %d chain pings\n%s", len(h.st.ChainPings(time.Time{})), h.log)
	}
}
