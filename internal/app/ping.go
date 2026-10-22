package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/mailin"
	"github.com/go-while/go-echolot/internal/mailout"
	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/pinger"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/sched"
	"github.com/go-while/go-echolot/internal/stats"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/token"
)

// Pings sends the pings due at the tick at (design §4.2, §8.3): one per
// pingable key of every remailer with pingit, at the key's hashed slot.
// With now set, it pings the keys of only (or of all remailers) at once:
// sendpings.
func (d *Daemon) Pings(ctx context.Context, at time.Time, only []string, now bool) {
	type ping struct {
		id   int
		addr string
		key  replies.ParsedKey
	}
	var due []ping
	s := d.cfg.Schedule
	d.st.View(func(st *store.State) {
		for _, addr := range slices.Sorted(maps.Keys(st.Remailers)) {
			r := st.Remailers[addr]
			// Pinging goes on in "ttl timeout", so the stats show the
			// outage, but not when dead or disabled (§8.5).
			if !r.PingIt || r.Status == store.StatusDead || r.Status == store.StatusDisabled || r.Status == store.StatusNotARemailer {
				continue
			}
			if len(only) > 0 && !slices.ContainsFunc(only, func(a string) bool { return keys.SameAddress(a, addr) }) {
				continue
			}
			for _, k := range keys.Pingable(r, at, d.cfg.Keys.Retention) {
				if now || sched.Due(d.schedKey, addr+"|mix|"+k.KeyID, at, s.PingInterval, s.Tick) {
					due = append(due, ping{r.ID, addr, parsedKey(k)})
				}
			}
		}
	})
	withFrom := sched.WithFrom(at, s.PingInterval)
	for i, p := range due {
		err := d.sendPing(ctx, p.id, p.addr, p.key, withFrom)
		if ctx.Err() != nil {
			d.log.Warn("tick over: pings left for their next slot", "remailer", p.addr, "left", len(due)-i)
			return
		}
		if err != nil {
			d.log.Warn("ping", "remailer", p.addr, "keyid", p.key.KeyID, "err", err)
		}
	}
}

// sendPing records the ping, then builds and sends it.  A failure on our
// side is an abort, which doesn't count as a lost ping (§5.3); a refusal
// by the remailer's side leaves it out, a loss like any other.
func (d *Daemon) sendPing(ctx context.Context, id int, addr string, k replies.ParsedKey, withFrom bool) error {
	sent := d.tokenTime(token.KindPing, 0)
	p, err := d.st.NewPing(addr, k.KeyID, withFrom, sent)
	if err != nil {
		return err // not recorded, not sent
	}
	abort := func(err error) error {
		if aerr := d.st.PingAborted(p.ID, bounded(err.Error())); aerr != nil {
			d.log.Error("ping abort not saved", "id", p.ID, "err", aerr)
		}
		return err
	}
	sealed, err := pinger.Seal(&d.macKey, &d.boxKey, pinger.Body{
		Remailer: addr, Type: pinger.TypeMix, KeyID: k.KeyID, WithFrom: withFrom, Sent: p.Sent, ID: p.ID,
	}, d.cfg.Stats.RandomGarbage, rand.Reader)
	if err != nil {
		return abort(err)
	}
	to, err := d.minter.Address(token.Token{Kind: token.KindPing, Time: p.Sent})
	if err != nil {
		return abort(err)
	}
	hop, mailData, err := d.encoder.Encode(ctx, []pinger.Hop{pinger.HopOf(k)},
		pinger.Mail(to, d.cfg.Pinger.Address, withFrom, sealed))
	if err != nil {
		return abort(err)
	}
	envelope := d.cfg.Pinger.Address
	if d.cfg.Pinger.RecipientDelimiter != "" {
		if envelope, err = d.minter.Address(token.Token{Kind: token.KindBounce, ID: id, Time: d.tokenTime(token.KindBounce, id)}); err != nil {
			return abort(err)
		}
	}
	err = d.mailer.Send(ctx, mailout.Mail{EnvelopeFrom: envelope, Rcpt: []string{hop}, Data: d.addDateID(mailData, p.Sent)})
	switch {
	case errors.Is(err, mailout.ErrOnionWithoutTor):
		abort(err)
		return fmt.Errorf("skipping .onion remailer: mail.tor_socks is not set")
	case mailout.IsPermanent(err):
		return err // refused by the remailer's side: a lost ping
	case err != nil:
		return abort(err)
	}
	d.log.Debug("ping sent", "remailer", addr, "keyid", k.KeyID, "id", p.ID)
	return nil
}

// addDateID adds Date and Message-ID to yamn's output, which has only
// To, From and Subject (§6.3).  sendmail would add them; SMTP doesn't.
func (d *Daemon) addDateID(mail []byte, now time.Time) []byte {
	var r [8]byte
	rand.Read(r[:])
	_, domain, _ := strings.Cut(d.cfg.Pinger.Address, "@")
	h := fmt.Sprintf("Date: %s\nMessage-ID: <%s.%s@%s>\n",
		now.UTC().Format("Mon, 02 Jan 2006 15:04:05 +0000"), now.UTC().Format("20060102150405"), hex.EncodeToString(r[:]), domain)
	return append([]byte(h), mail...)
}

// receivePing handles a ping that came back: it must match the journal
// entry it claims to be, then it is done, and its key is proven (§9.2).
func (d *Daemon) receivePing(tok token.Token, m *mailin.Message) error {
	body, err := replies.Body(m.Header, m.Body)
	if err != nil {
		return mailin.Permanent(err)
	}
	b, err := pinger.Open(&d.macKey, &d.boxKey, body)
	if err != nil {
		return mailin.Permanent(fmt.Errorf("ping: %w", err))
	}
	p, ok := d.st.Ping(b.ID)
	switch {
	case !ok:
		return mailin.Permanent(fmt.Errorf("ping %d is not in the journal (expired?)", b.ID))
	case p.Addr != b.Remailer || p.KeyID != b.KeyID || !p.Sent.Equal(b.Sent) || !tok.Time.Equal(p.Sent):
		return mailin.Permanent(fmt.Errorf("ping %d doesn't match the journal", b.ID))
	}
	received := m.Delivered
	if d.cfg.Compat.LatencyFrom == "processing" {
		received = d.clock.Now()
	}
	latency := max(int64(received.Sub(p.Sent)/time.Second), 0)
	if _, news, err := d.st.PingDone(p.ID, received, latency); err != nil {
		return err // transient: try again
	} else if !news {
		return nil // a copy, or already counted
	}
	var proven bool
	err = d.st.Update(func(st *store.State) error {
		if r := st.Remailers[p.Addr]; r != nil {
			if k := r.Keys[p.KeyID]; k != nil {
				proven = keys.SetProven(k, received)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	d.log.Debug("ping back", "remailer", p.Addr, "keyid", p.KeyID, "latency", latency)
	if proven {
		d.log.Info("key proven: a ping to it came back", "remailer", p.Addr, "keyid", p.KeyID)
		d.loop.Trigger(jobPubring)
	}
	return nil
}

// BuildStats writes mlist2.txt and mlist.txt (design §7.3-7.4).
func (d *Daemon) BuildStats(at time.Time) {
	since := at.Add(-time.Duration(d.cfg.Stats.Days) * 24 * time.Hour)
	params := stats.Params{Days: d.cfg.Stats.Days, Weights: d.cfg.Stats.Weights,
		SkewAbs: d.cfg.Stats.SkewAbs, SkewPercent: d.cfg.Stats.SkewPercent}
	type rem struct {
		nick, addr, caps string
		showIt           bool
		counted          func(store.Ping) bool
	}
	var rems []rem
	d.st.View(func(st *store.State) {
		for _, r := range st.Remailers {
			if r.Conf == nil || len(r.Keys) == 0 {
				continue
			}
			ks := maps.Clone(r.Keys)
			rems = append(rems, rem{r.Conf.Nick, r.Address, r.Conf.Caps, r.ShowIt, d.countedPing(ks)})
		}
	})
	var rows []output.Row
	for _, r := range rems {
		outs, dones := d.st.Pings(r.addr, since)
		var out []time.Time
		var done []stats.Done
		for _, p := range outs {
			if r.counted(p) {
				out = append(out, p.Sent)
			}
		}
		for _, p := range dones {
			if r.counted(p) {
				done = append(done, stats.Done{Sent: p.Sent, Latency: p.Latency})
			}
		}
		res := stats.Calculate(out, done, at, params)
		if res.Clamped > 0 {
			d.log.Warn("pings sent in the future (clock skew?)", "remailer", r.addr, "pings", res.Clamped)
		}
		rows = append(rows, output.Row{Nick: r.nick, Address: r.addr, Caps: r.caps,
			ListIt: output.ListIt(r.showIt, r.caps), Stats: res})
	}
	sec := d.sections()
	for _, w := range []struct {
		dir  string
		rows []output.Row
	}{{d.cfg.Paths.PrivateResultsDir, rows}, {d.cfg.Paths.ResultsDir, output.Public(rows)}} {
		if err := os.MkdirAll(w.dir, 0o755); err != nil {
			d.log.Error("stats", "dir", w.dir, "err", err)
			continue
		}
		if err := output.WriteStats(w.dir, w.rows, sec, at, d.cfg.Stats.SortByLatency, d.cfg.Compat.MetaFiles); err != nil {
			d.log.Error("stats not written", "dir", w.dir, "err", err)
		}
	}
}

// countedPing returns which pings of a remailer with keys ks count in its
// stats (§13 questions 3 and 18): pings to a key that wasn't published
// when they were sent don't; with keys.require_proof that's before the
// key was proven, or while it is quarantined or rejected.  Pings of keys
// that are gone count (the 12-day history outlives keys) unless
// compat.drop_pings_with_key restores Echolot's behaviour.
func (d *Daemon) countedPing(ks map[string]*store.Key) func(store.Ping) bool {
	return func(p store.Ping) bool {
		k := ks[p.KeyID]
		if k == nil {
			return !d.cfg.Compat.DropPingsWithKey
		}
		if k.State != store.KeyStateActive {
			return false
		}
		return !d.cfg.Keys.RequireProof || keys.Proven(k) && !p.Sent.Before(k.ProvenAt)
	}
}

// sections reads the operator's optional texts from the state dir:
// sameop.txt, broken1.txt, broken2.txt (E:Stats.pm:668-679; chain pings
// are phase 3, so a missing file leaves its section out).
func (d *Daemon) sections() output.Sections {
	read := func(name string) *string {
		b, err := os.ReadFile(filepath.Join(d.cfg.Paths.StateDir, name))
		if err != nil {
			return nil
		}
		s := string(bytes.TrimRight(b, "\n"))
		return &s
	}
	return output.Sections{SameOp: read("sameop.txt"), Broken1: read("broken1.txt"), Broken2: read("broken2.txt")}
}

// parsedKey is a stored key as the encoder and the writers want it.
func parsedKey(k *store.Key) replies.ParsedKey {
	return replies.ParsedKey{
		SummaryLine: replies.SummaryLine{Nick: k.Nick, Address: k.Address, KeyID: k.KeyID,
			Version: k.Version, Caps: k.Caps, Created: k.Created, Expires: k.Expires},
		PK: [32]byte(k.PK),
	}
}
