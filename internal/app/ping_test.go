package app

import (
	"context"
	"crypto/rand"
	"fmt"
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
