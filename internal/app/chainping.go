package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/chain"
	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/mailin"
	"github.com/go-while/go-echolot/internal/mailout"
	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/pinger"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/token"
)

// Chain pings (design §8.2, phase 3): every ordered pair (A, B) of the
// remailers we ping, through both, A first, weekly; daily while a pair is
// in intensive care.  Their returns decide the broken chains of mlist2.txt.

// chainHops returns the remailers chain pings go through at t: those we
// ping, each with the key clients encrypt to (Publishable).
func (d *Daemon) chainHops(t time.Time) ([]chain.Hop, map[string]replies.ParsedKey, map[string]int) {
	var hops []chain.Hop
	pks := map[string]replies.ParsedKey{}
	ids := map[string]int{}
	d.st.View(func(st *store.State) {
		for _, addr := range slices.Sorted(maps.Keys(st.Remailers)) {
			r := st.Remailers[addr]
			if !r.PingIt || r.Status == store.StatusDead || r.Status == store.StatusDisabled || r.Status == store.StatusNotARemailer {
				continue
			}
			k := keys.Publishable(r, t, d.cfg.Keys.RequireProof)
			if k == nil {
				continue
			}
			hops = append(hops, chain.Hop{Addr: addr, KeyID: k.KeyID})
			pks[addr] = parsedKey(k)
			ids[addr] = r.ID
		}
	})
	return hops, pks, ids
}

// ChainPings sends the chain pings due at the tick at.  With now set, it
// sends those of pairs ("a:b" each, by address) now, or of every pair if
// pairs is empty: sendchainpings.
func (d *Daemon) ChainPings(ctx context.Context, at time.Time, pairs []string, now bool) {
	hops, pks, ids := d.chainHops(at)
	var due []chain.Pair
	switch {
	case !now:
		due = chain.Due(d.schedKey, chain.Pairs(hops), d.chainRes.Care, at, d.cfg.Schedule.Tick)
	case len(pairs) == 0:
		due = chain.Pairs(hops)
	default:
		for _, p := range pairs {
			a, b, ok := strings.Cut(p, ":")
			ka, oka := pks[a]
			kb, okb := pks[b]
			if !ok || !oka || !okb || a == b {
				d.log.Warn("sendchainpings: not a pair of pinged remailers with a published key", "pair", p)
				continue
			}
			due = append(due, chain.Pair{A: chain.Hop{Addr: a, KeyID: ka.KeyID}, B: chain.Hop{Addr: b, KeyID: kb.KeyID}})
		}
	}
	for i, p := range due {
		err := d.sendChainPing(ctx, ids[p.A.Addr], pks[p.A.Addr], pks[p.B.Addr])
		if ctx.Err() != nil {
			d.log.Warn("tick over: chain pings left for their next slot", "chain", p.String(), "left", len(due)-i)
			return
		}
		if err != nil {
			d.log.Warn("chain ping", "chain", p.String(), "err", err)
		}
	}
}

// sendChainPing records a chain ping through a then b, builds and sends
// it.  Any failure is ours: an abort, which doesn't count (§5.3).
func (d *Daemon) sendChainPing(ctx context.Context, idA int, a, b replies.ParsedKey) error {
	p, err := d.st.AddChainPing(store.ChainPing{A: a.Address, KeyA: a.KeyID, B: b.Address, KeyB: b.KeyID,
		Sent: d.tokenTime(token.KindChainping, 0)})
	if err != nil {
		return err
	}
	abort := func(err error) error {
		if aerr := d.st.ChainPingAborted(p.ID, bounded(err.Error())); aerr != nil {
			d.log.Error("chain ping abort not saved", "id", p.ID, "err", aerr)
		}
		return err
	}
	sealed, err := pinger.Seal(&d.macKey, &d.boxKey, pinger.Body{
		Remailer: a.Address, Type: pinger.TypeMix, KeyID: a.KeyID, Remailer2: b.Address, KeyID2: b.KeyID,
		Sent: p.Sent, ID: p.ID,
	}, d.cfg.Stats.RandomGarbage, rand.Reader)
	if err != nil {
		return abort(err)
	}
	to, err := d.minter.Address(token.Token{Kind: token.KindChainping, Time: p.Sent})
	if err != nil {
		return abort(err)
	}
	hop, data, err := d.encoder.Encode(ctx, []pinger.Hop{pinger.HopOf(a), pinger.HopOf(b)},
		pinger.Mail(to, d.cfg.Pinger.Address, false, sealed))
	if err != nil {
		return abort(err)
	}
	envelope := d.cfg.Pinger.Address
	if d.cfg.Pinger.RecipientDelimiter != "" {
		if envelope, err = d.minter.Address(token.Token{Kind: token.KindBounce, ID: idA, Time: d.tokenTime(token.KindBounce, idA)}); err != nil {
			return abort(err)
		}
	}
	err = d.mailer.Send(ctx, mailout.Mail{EnvelopeFrom: envelope, Rcpt: []string{hop}, Data: d.addDateID(data, p.Sent)})
	if errors.Is(err, mailout.ErrOnionWithoutTor) {
		abort(err)
		return fmt.Errorf("skipping .onion remailer: mail.tor_socks is not set")
	}
	if err != nil {
		return abort(err)
	}
	d.log.Debug("chain ping sent", "a", a.Address, "b", b.Address, "id", p.ID)
	return nil
}

// receiveChainPing handles a chain ping that came back: it must match its
// journal entry exactly, then it's done.
func (d *Daemon) receiveChainPing(tok token.Token, m *mailin.Message) error {
	body, err := replies.Body(m.Header, m.Body)
	if err != nil {
		return mailin.Permanent(err)
	}
	b, err := pinger.Open(&d.macKey, &d.boxKey, body)
	if err != nil {
		return mailin.Permanent(fmt.Errorf("chain ping: %w", err))
	}
	if !b.Chain() {
		return mailin.Permanent(errors.New("a plain ping on a chain ping token"))
	}
	p, ok := d.st.ChainPing(b.ID)
	switch {
	case !ok:
		return mailin.Permanent(fmt.Errorf("chain ping %d is not in the journal (expired?)", b.ID))
	case p.A != b.Remailer || p.KeyA != b.KeyID || p.B != b.Remailer2 || p.KeyB != b.KeyID2 ||
		!p.Sent.Equal(b.Sent) || !tok.Time.Equal(p.Sent):
		return mailin.Permanent(fmt.Errorf("chain ping %d doesn't match the journal", b.ID))
	}
	received := m.Delivered
	if d.cfg.Compat.LatencyFrom == "processing" {
		received = d.clock.Now()
	}
	latency := max(int64(received.Sub(p.Sent)/time.Second), 0)
	if _, news, err := d.st.ChainPingDone(p.ID, received, latency); err != nil {
		return err
	} else if news {
		d.log.Debug("chain ping back", "a", p.A, "b", p.B, "latency", latency)
	}
	return nil
}

// chainSections evaluates the chains when due (at most every 4 h, §8.2)
// and returns the broken sections, public and private.  rows are the
// private mlist2.txt rows of this stats run: their reliability and
// latency judge the chains.
func (d *Daemon) chainSections(rows []output.Row, at time.Time) (pub, priv output.Sections) {
	if d.chainAt.IsZero() || at.Sub(d.chainAt) >= chain.Update {
		rems := make([]chain.Remailer, len(rows))
		for i, r := range rows {
			rems[i] = chain.Remailer{Addr: r.Address, Nick: r.Nick, ListIt: r.ListIt,
				Reliability: r.Stats.Reliability, Latency: r.Stats.Latency}
		}
		d.chainRes = chain.Evaluate(d.st.ChainPings(at.Add(-chain.Window)), rems, at)
		d.chainAt = at
		if n := len(d.chainRes.Broken); n > 0 {
			d.log.Info("broken chains", "count", n)
		}
	}
	read := func(name string) []string {
		b, err := os.ReadFile(filepath.Join(d.cfg.Paths.StateDir, name))
		if err != nil {
			return nil
		}
		return chain.HardLines(string(b))
	}
	pubText, privText := chain.Broken2Text(d.chainRes.Broken, read("broken2.txt"), len(rows))
	b1 := chain.Broken1Text(read("broken1.txt"))
	sameop := d.sections().SameOp
	return output.Sections{SameOp: sameop, Broken1: &b1, Broken2: &pubText},
		output.Sections{SameOp: sameop, Broken1: &b1, Broken2: &privText}
}
