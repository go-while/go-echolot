package keys

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/civil"
	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// reply is one key or conf reply being applied to rem.
type reply struct {
	st       *store.State
	rem      *store.Remailer
	tok      time.Time // token time: when the request was sent
	received time.Time // when the reply was delivered
	now      time.Time
	cfg      config.Keys
	res      []Result
}

func (r *reply) add(keyid string, d Decision, format string, args ...any) {
	r.res = append(r.res, Result{Address: r.rem.Address, KeyID: keyid, Decision: d, Reason: fmt.Sprintf(format, args...)})
}

// source names rem in suggestions: its nick, or its address while unpinned.
func source(rem *store.Remailer) string {
	if rem.Nick != "" {
		return rem.Nick
	}
	return rem.Address
}

// ApplyKeyReply applies the keys of a remailer-key reply that came back on
// a token for rem (§9.1, §9.2).  tok is the token time, received the
// delivery time, now the processing time; the token's age was checked by
// the caller.
//
// Lines for other addresses become Suggestions and aren't stored.  The
// others are checked (CheckKey); replays are ignored.  A new keyid is
// accepted when it's a normal rotation with an acceptable nick, else it
// is stored quarantined with a PendingChange.
func ApplyKeyReply(st *store.State, rem *store.Remailer, keys []replies.ParsedKey, tok, received, now time.Time, cfg config.Keys) []Result {
	r := &reply{st: st, rem: rem, tok: tok.UTC(), received: received.UTC(), now: now.UTC(), cfg: cfg}
	// yamn sends one key; with more, the older first, so a rotation inside
	// one reply is judged in order
	keys = slices.Clone(keys)
	slices.SortStableFunc(keys, func(a, b replies.ParsedKey) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		if c := a.Expires.Compare(b.Expires); c != 0 {
			return c
		}
		return strings.Compare(a.KeyID, b.KeyID)
	})
	alive := false
	for _, pk := range keys {
		if r.key(pk) {
			alive = true
		}
	}
	if alive && RestoreTTL(rem) {
		r.add("", Accepted, "remailer is alive again")
	}
	return r.res
}

// key applies one key line and reports whether it showed rem is alive
// (it passed CheckKey and wasn't a replay).
func (r *reply) key(pk replies.ParsedKey) bool {
	rem := r.rem
	if !SameAddress(pk.Address, rem.Address) {
		if o := findRemailer(r.st, pk.Address); o != nil {
			r.res = append(r.res, Result{Address: pk.Address, KeyID: pk.KeyID, Decision: Ignored,
				Reason: "listed in the key reply of " + source(rem)})
			return false
		}
		r.suggest(pk.Address, "key reply of "+source(rem))
		return false
	}
	if err := CheckKey(pk, rem, civil.Of(r.now)); err != nil {
		r.add(pk.KeyID, Rejected, "%v", err)
		return false
	}
	if k := rem.Keys[pk.KeyID]; k != nil {
		return r.knownKey(k, pk)
	}

	nickWhy := nickProblem(r.st, rem, pk.Nick)
	cur := Current(rem, r.now)
	keyWhy := rotationProblem(cur, pk, r.now, r.cfg.RotationWindow)
	k := &store.Key{
		KeyID: pk.KeyID, Nick: pk.Nick, Address: pk.Address, Version: pk.Version, Caps: pk.Caps,
		Created: pk.Created, Expires: pk.Expires, PK: store.PublicKey(pk.PK),
		FirstSeen: r.tok, LastSeen: r.tok, LastReceived: r.received, Sightings: 1, SightedAt: r.tok,
		State: store.KeyStateQuarantined,
	}
	if rem.Keys == nil {
		rem.Keys = map[string]*store.Key{}
	}
	rem.Keys[k.KeyID] = k

	if nickWhy == "" && keyWhy == "" {
		r.pin(pk.Nick)
		k.State = store.KeyStateActive
		switch {
		case cur != nil:
			r.add(k.KeyID, Rotation, "current key %s expires %s", cur.KeyID, cur.Expires)
		case len(rem.Keys) == 1:
			r.add(k.KeyID, Accepted, "first key")
		default:
			r.add(k.KeyID, Accepted, "no valid key")
		}
		return true
	}
	var why []string
	if nickWhy != "" {
		pc := r.pend(store.PendingNickChange, rem.Nick, pk.Nick)
		if pc.Rejected {
			k.State = store.KeyStateRejected
			r.add(k.KeyID, Rejected, "nick change to %s was rejected by the operator", pk.Nick)
			return true
		}
		why = append(why, nickWhy)
	}
	if keyWhy != "" {
		r.pend(store.PendingKeyChange, cur.KeyID, k.KeyID)
		why = append(why, keyWhy)
	}
	r.add(k.KeyID, Quarantined, "%s", strings.Join(why, "; "))
	return true
}

// knownKey applies a line for a keyid rem already has.
func (r *reply) knownKey(k *store.Key, pk replies.ParsedKey) bool {
	rem := r.rem
	if !r.tok.After(k.LastSeen) {
		r.add(k.KeyID, Ignored, "replay: token time not after last seen %s", k.LastSeen.Format(time.RFC3339))
		return false
	}
	// the dates come from the secret key and never change; name, address,
	// version and caps come from yamn's config and may
	if k.Created != pk.Created || k.Expires != pk.Expires {
		r.add(k.KeyID, Rejected, "dates %s %s differ from the stored %s %s", pk.Created, pk.Expires, k.Created, k.Expires)
		return true
	}
	if k.State == store.KeyStateRejected {
		r.seen(k)
		r.add(k.KeyID, Rejected, "key rejected by the operator")
		return true
	}
	if why := nickProblem(r.st, rem, pk.Nick); why != "" {
		// the key isn't touched: this line doesn't match the pins
		pc := r.pend(store.PendingNickChange, rem.Nick, pk.Nick)
		if pc.Rejected {
			r.add(k.KeyID, Rejected, "nick change to %s was rejected by the operator", pk.Nick)
		} else {
			r.add(k.KeyID, Quarantined, "%s", why)
		}
		return true
	}
	r.pin(pk.Nick)
	r.seen(k)
	k.Nick, k.Address, k.Version, k.Caps = pk.Nick, pk.Address, pk.Version, pk.Caps
	if k.State == store.KeyStateQuarantined {
		if activate(r.st, rem, k) {
			r.add(k.KeyID, Accepted, "quarantine lifted")
		} else {
			r.add(k.KeyID, Quarantined, "seen again (%d sightings), waiting for the pending change", k.Sightings)
		}
		return true
	}
	r.add(k.KeyID, Seen, "")
	return true
}

// seen records a sighting of k: one per token at least SightingGap after
// the last counted one (§9.2, "distinct tokens >= 30 min apart").
func (r *reply) seen(k *store.Key) {
	if k.SightedAt.IsZero() { // state written before SightedAt
		k.SightedAt = k.LastSeen
		if k.Sightings <= 1 {
			k.SightedAt = k.FirstSeen
		}
	}
	sighting(&k.Sightings, &k.SightedAt, r.tok)
	if r.tok.After(k.LastSeen) {
		k.LastSeen = r.tok
	}
	if r.received.After(k.LastReceived) {
		k.LastReceived = r.received
	}
}

// pin pins nick as rem's nick if rem is unpinned (TOFU), and records that
// the pinned nick was seen.  The caller checked nickProblem.
func (r *reply) pin(nick string) {
	if r.rem.Nick == "" {
		r.rem.Nick = nick
		r.add("", Accepted, "nick %s pinned", nick)
		return
	}
	r.seeOld(store.PendingNickChange, nick)
}

// rotationProblem returns why a new key with these dates isn't a normal
// rotation (§9.2), or "".  cur is Current(rem, now).
func rotationProblem(cur *store.Key, pk replies.ParsedKey, now time.Time, window time.Duration) string {
	if cur == nil {
		return ""
	}
	if pk.Created.Before(cur.Created) {
		return fmt.Sprintf("created %s before the current key %s (%s)", pk.Created, cur.KeyID, cur.Created)
	}
	if left := cur.Expires.End().Sub(now); left > window {
		return fmt.Sprintf("current key %s is valid for another %s", cur.KeyID, left.Round(time.Minute))
	}
	return ""
}

// pend finds or adds the pending change kind old -> new for rem and counts
// a sighting of it.  Key changes count sightings on the key instead.
func (r *reply) pend(kind, old, new string) *store.PendingChange {
	for i := range r.st.Pending {
		pc := &r.st.Pending[i]
		if pc.Address != r.rem.Address || pc.Kind != kind || pc.New != new {
			continue
		}
		if kind != store.PendingKeyChange && r.tok.After(pc.LastSeen) {
			if pc.SightedAt.IsZero() { // state written before SightedAt
				pc.SightedAt = pc.LastSeen
				if pc.Sightings <= 1 {
					pc.SightedAt = pc.Since
				}
			}
			sighting(&pc.Sightings, &pc.SightedAt, r.tok)
			pc.LastSeen = r.tok
		}
		return pc
	}
	pc := store.PendingChange{Address: r.rem.Address, Kind: kind, Old: old, New: new, Since: r.now}
	if kind != store.PendingKeyChange {
		pc.Sightings, pc.LastSeen, pc.SightedAt = 1, r.tok, r.tok
	}
	r.st.Pending = append(r.st.Pending, pc)
	return &r.st.Pending[len(r.st.Pending)-1]
}

// seeOld records that a reply showed old, the pinned nick or address, for
// the pending changes away from it.
func (r *reply) seeOld(kind, old string) {
	for i := range r.st.Pending {
		pc := &r.st.Pending[i]
		if pc.Address == r.rem.Address && pc.Kind == kind && pc.Old == old && r.tok.After(pc.OldSeen) {
			pc.OldSeen = r.tok
		}
	}
}

// suggest records a Suggestion for addr unless it is known (§9.3).  One
// per source and reason; a new one updates the time.
func (r *reply) suggest(addr, reason string) {
	if findRemailer(r.st, addr) != nil {
		return
	}
	addr = canonAddress(addr)
	s := store.Suggestion{Time: r.now, Reason: reason, Source: source(r.rem)}
	if r.st.Prospective == nil {
		r.st.Prospective = map[string][]store.Suggestion{}
	}
	list := r.st.Prospective[addr]
	i := slices.IndexFunc(list, func(o store.Suggestion) bool { return o.Source == s.Source && o.Reason == s.Reason })
	if i >= 0 {
		list[i].Time = s.Time
	} else {
		r.st.Prospective[addr] = append(list, s)
	}
	r.res = append(r.res, Result{Address: addr, Decision: Suggested, Reason: reason})
}

// ApplyConfReply applies a remailer-conf reply that came back on a token
// for rem.  A conf for another address, or with a nick that isn't
// acceptable, is not stored but quarantined as a PendingChange; nothing is
// mailed to a new address until the change is applied (§9.2).  Supported
// lines for unknown addresses become Suggestions (§9.3).
func ApplyConfReply(st *store.State, rem *store.Remailer, conf *replies.ConfReply, tok, received, now time.Time, cfg config.Keys) []Result {
	r := &reply{st: st, rem: rem, tok: tok.UTC(), received: received.UTC(), now: now.UTC(), cfg: cfg}
	if conf == nil {
		return nil
	}
	if rem.Conf != nil && !r.tok.After(rem.Conf.LastUpdate) {
		r.add("", Ignored, "conf replay: token time not after last update %s", rem.Conf.LastUpdate.Format(time.RFC3339))
		return r.res
	}
	if !replies.ValidName(conf.Nick) || !replies.ValidAddress(conf.Address) {
		r.add("", Rejected, "bad nick or address in conf")
		return r.res
	}
	if RestoreTTL(rem) {
		r.add("", Accepted, "remailer is alive again")
	}
	r.conf(conf)
	// after r.conf, so a nick pinned by this conf names the source
	for _, s := range conf.Supported {
		if !SameAddress(s.Address, rem.Address) {
			r.suggest(s.Address, "supported by "+source(rem))
		}
	}
	return r.res
}

// conf stores conf, or quarantines its address or nick.
func (r *reply) conf(conf *replies.ConfReply) {
	rem := r.rem
	if !SameAddress(conf.Address, rem.Address) {
		pc := r.pend(store.PendingAddressChange, rem.Address, conf.Address)
		if pc.Rejected {
			r.add("", Rejected, "address change to %s was rejected by the operator", conf.Address)
		} else {
			r.add("", Quarantined, "conf names the address %s", conf.Address)
		}
		return
	}
	r.seeOld(store.PendingAddressChange, rem.Address)
	if why := nickProblem(r.st, rem, conf.Nick); why != "" {
		pc := r.pend(store.PendingNickChange, rem.Nick, conf.Nick)
		if pc.Rejected {
			r.add("", Rejected, "nick change to %s was rejected by the operator", conf.Nick)
		} else {
			r.add("", Quarantined, "conf: %s", why)
		}
		return
	}
	r.pin(conf.Nick)
	c := &store.Conf{Nick: conf.Nick, Type: conf.Type, Caps: conf.Caps, LastUpdate: r.tok, Received: r.received}
	if rem.Conf != nil {
		c.DontExpire = rem.Conf.DontExpire
	}
	rem.Conf = c
	r.add("", Accepted, "conf")
}

// sighting counts tok as a new sighting if it is at least SightingGap after
// the last counted one, *at.  The gap is not measured from the last reply:
// a remailer asked more often than every SightingGap would never get a
// second sighting (seen on the testnet, 2026-10-29).
func sighting(n *int, at *time.Time, tok time.Time) {
	if !tok.Before(at.Add(SightingGap)) {
		*n++
		*at = tok
	}
}
