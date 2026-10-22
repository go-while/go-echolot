package keys

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/store"
)

// pendingKey reports whether a pending key change waits for keyid.
func pendingKey(st *store.State, rem *store.Remailer, keyid string) bool {
	return slices.ContainsFunc(st.Pending, func(pc store.PendingChange) bool {
		return pc.Address == rem.Address && pc.Kind == store.PendingKeyChange && pc.New == keyid
	})
}

// activate makes a quarantined key active when nothing holds it back: its
// nick is the pinned one (an unpinned remailer is pinned to it if that is
// acceptable) and no pending key change waits for it.
func activate(st *store.State, rem *store.Remailer, k *store.Key) bool {
	switch k.State {
	case store.KeyStateActive:
		return true
	case store.KeyStateRejected:
		return false
	}
	if rem.Nick == "" && nickProblem(st, rem, k.Nick) == "" {
		rem.Nick = k.Nick
	}
	if k.Nick != rem.Nick || pendingKey(st, rem, k.KeyID) {
		return false
	}
	k.State = store.KeyStateActive
	return true
}

// removePending removes st.Pending[i].
func removePending(st *store.State, i int) store.PendingChange {
	pc := st.Pending[i]
	st.Pending = slices.Delete(st.Pending, i, i+1)
	return pc
}

// ResolvePending applies the pending changes whose quarantine is over
// (§9.2): cfg.Quarantine has passed since Since, the change was seen in at
// least cfg.MinSightings replies, and the old key, nick or address wasn't
// seen again since.  A nick longer than 12 characters, or one pinned to
// another remailer, and an address that is already known, wait for the
// operator.  Changes made stale by another change are dropped.
func ResolvePending(st *store.State, now time.Time, cfg config.Keys) []Result {
	var res []Result
	for i := 0; i < len(st.Pending); {
		pc := &st.Pending[i]
		r := Result{Address: pc.Address}
		if pc.Kind == store.PendingKeyChange {
			r.KeyID = pc.New
		}
		d, why := resolve(st, pc, now, cfg)
		r.Decision, r.Reason = d, why
		switch d {
		case Applied:
			c := removePending(st, i)
			r.Reason = applyChange(st, c)
		case Dropped:
			removePending(st, i)
		default:
			i++
		}
		if d != "" {
			res = append(res, r)
		}
	}
	return res
}

// resolve decides what ResolvePending does with pc.
func resolve(st *store.State, pc *store.PendingChange, now time.Time, cfg config.Keys) (Decision, string) {
	if pc.Rejected {
		return "", ""
	}
	rem := st.Remailers[pc.Address]
	if rem == nil {
		return Dropped, "remailer is gone"
	}
	sightings, oldSeen := pc.Sightings, pc.OldSeen
	switch pc.Kind {
	case store.PendingKeyChange:
		k := rem.Keys[pc.New]
		if k == nil || k.State == store.KeyStateRejected {
			return Dropped, "key is gone or rejected"
		}
		sightings = k.Sightings
		oldSeen = time.Time{}
		if old := rem.Keys[pc.Old]; old != nil {
			oldSeen = old.LastSeen
		}
	case store.PendingNickChange:
		if pc.Old != rem.Nick {
			return Dropped, fmt.Sprintf("pinned nick is now %q", rem.Nick)
		}
		if len(pc.New) > MaxNickLen {
			return Waiting, fmt.Sprintf("nick longer than %d characters: operator only", MaxNickLen)
		}
		if o := nickOwner(st, pc.New, rem); o != nil {
			return Waiting, "nick is pinned to " + o.Address + ": operator only"
		}
	case store.PendingAddressChange:
		if pc.Old != rem.Address {
			return Dropped, "address changed meanwhile"
		}
		if findRemailer(st, pc.New) != nil {
			return Waiting, "new address is already known: operator only"
		}
	default:
		return Dropped, "unknown kind " + pc.Kind
	}
	switch {
	case now.Sub(pc.Since) < cfg.Quarantine:
		return Waiting, fmt.Sprintf("in quarantine until %s", pc.Since.Add(cfg.Quarantine).Format(time.RFC3339))
	case sightings < cfg.MinSightings:
		return Waiting, fmt.Sprintf("%d of %d sightings", sightings, cfg.MinSightings)
	case !oldSeen.Before(pc.Since):
		return Waiting, fmt.Sprintf("old %s %s seen again", pc.Kind, pc.Old)
	}
	return Applied, ""
}

// applyChange carries out a pending change that was removed from st.Pending and
// returns a reason for the log.
func applyChange(st *store.State, pc store.PendingChange) string {
	rem := st.Remailers[pc.Address]
	switch pc.Kind {
	case store.PendingKeyChange:
		k := rem.Keys[pc.New]
		if k == nil {
			return "key is gone"
		}
		if k.State == store.KeyStateRejected {
			k.State = store.KeyStateQuarantined
		}
		if !activate(st, rem, k) {
			return "key " + pc.New + " still waits for a nick change"
		}
		return "key " + pc.New + " is active"
	case store.PendingNickChange:
		applyNick(st, rem, pc.New)
		return fmt.Sprintf("nick %q -> %s", pc.Old, pc.New)
	case store.PendingAddressChange:
		applyAddress(st, rem, pc.New)
		return fmt.Sprintf("address %s -> %s", pc.Old, pc.New)
	}
	return ""
}

// applyNick pins nick to rem.  Active keys with the old nick take the new
// one, as yamn writes its name from its config into key.txt at startup;
// quarantined keys with the new nick become active unless a key change
// holds them.  The stored conf names the old nick, so it is dropped until
// the next conf reply.
func applyNick(st *store.State, rem *store.Remailer, nick string) {
	old := rem.Nick
	rem.Nick = nick
	for _, k := range sortedKeys(rem) {
		switch {
		case k.State == store.KeyStateActive && old != "" && k.Nick == old:
			k.Nick = nick
		case k.State == store.KeyStateQuarantined && k.Nick == nick:
			activate(st, rem, k)
		}
	}
	rem.Conf = nil
}

// applyAddress moves rem to address, keeping its ID.  Pending changes and
// suggestions follow; the stored conf names the old address, so it is
// dropped until the next conf reply.  Keys keep the address they were
// advertised with and aren't published or pinged until a key reply from
// the new address lists them again.
func applyAddress(st *store.State, rem *store.Remailer, address string) {
	old := rem.Address
	delete(st.Remailers, old)
	rem.Address = address
	st.Remailers[address] = rem
	for i := range st.Pending {
		if st.Pending[i].Address == old {
			st.Pending[i].Address = address
		}
	}
	for a := range st.Prospective {
		if SameAddress(a, address) {
			delete(st.Prospective, a)
		}
	}
	rem.Conf = nil
}

func sortedKeys(rem *store.Remailer) []*store.Key {
	ks := make([]*store.Key, 0, len(rem.Keys))
	for _, k := range rem.Keys {
		ks = append(ks, k)
	}
	slices.SortFunc(ks, func(a, b *store.Key) int { return cmp.Compare(a.KeyID, b.KeyID) })
	return ks
}

// kindOrder is the order approvals are applied in: an address first, then
// a nick, so a key approved with them can become active.
var kindOrder = map[string]int{store.PendingAddressChange: 0, store.PendingNickChange: 1, store.PendingKeyChange: 2}

// matching returns the indexes of rem's pending changes that what names:
// "" for all, a kind ("key", "nick", "address"), or the new keyid, nick
// or address.
func matching(st *store.State, rem *store.Remailer, what string) []int {
	var idx []int
	for i, pc := range st.Pending {
		if pc.Address == rem.Address && (what == "" || what == pc.Kind || what == pc.New) {
			idx = append(idx, i)
		}
	}
	return idx
}

// Approve applies the pending changes of address that what names ("" for
// all, a kind, or the new keyid, nick or address) at once, also rejected
// ones (the CLI's approve).  With no pending change, a keyid of a
// quarantined or rejected key makes that key active.  A nick pinned to
// another remailer, or an address that is already known, can't be
// approved; nothing is changed then.
func Approve(st *store.State, address, what string, now time.Time) ([]Result, error) {
	rem := findRemailer(st, address)
	if rem == nil {
		return nil, fmt.Errorf("unknown remailer %s", address)
	}
	idx := matching(st, rem, what)
	if len(idx) == 0 {
		k := rem.Keys[what]
		if k == nil || k.State == store.KeyStateActive {
			return nil, fmt.Errorf("nothing to approve for %s", strings.TrimSpace(rem.Address+" "+what))
		}
		if k.Nick != rem.Nick && nickProblem(st, rem, k.Nick) != "" {
			return nil, fmt.Errorf("key %s has nick %s, not the pinned nick %q: approve the nick first", k.KeyID, k.Nick, rem.Nick)
		}
		k.State = store.KeyStateQuarantined
		activate(st, rem, k)
		return []Result{{Address: rem.Address, KeyID: k.KeyID, Decision: Accepted, Reason: "approved by the operator"}}, nil
	}
	changes := make([]store.PendingChange, len(idx))
	for j, i := range idx {
		changes[j] = st.Pending[i]
	}
	slices.SortStableFunc(changes, func(a, b store.PendingChange) int { return cmp.Compare(kindOrder[a.Kind], kindOrder[b.Kind]) })
	for _, pc := range changes {
		switch pc.Kind {
		case store.PendingNickChange:
			if o := nickOwner(st, pc.New, rem); o != nil {
				return nil, fmt.Errorf("nick %s is pinned to %s: change that first", pc.New, o.Address)
			}
		case store.PendingAddressChange:
			if o := findRemailer(st, pc.New); o != nil {
				return nil, fmt.Errorf("address %s is already known (id %d)", pc.New, o.ID)
			}
		}
	}
	// remove them all, then apply in kindOrder
	for j := len(idx) - 1; j >= 0; j-- {
		removePending(st, idx[j])
	}
	var res []Result
	for _, pc := range changes {
		pc.Address = rem.Address // an address change applied first moved rem
		r := Result{Address: rem.Address, Decision: Accepted}
		if pc.Kind == store.PendingKeyChange {
			r.KeyID = pc.New
		}
		r.Reason = "approved by the operator: " + applyChange(st, pc)
		res = append(res, r)
	}
	return res, nil
}

// Reject rejects the pending changes of address that what names, as
// Approve (the CLI's reject).  A rejected key change marks the key
// rejected and drops the change.  A rejected nick or address change is
// kept with Rejected set, so the same change isn't quarantined again, and
// quarantined keys with that nick are rejected.  With no pending change, a
// keyid rejects that key, also an active one.
func Reject(st *store.State, address, what string, now time.Time) ([]Result, error) {
	rem := findRemailer(st, address)
	if rem == nil {
		return nil, fmt.Errorf("unknown remailer %s", address)
	}
	var idx []int
	for _, i := range matching(st, rem, what) {
		if !st.Pending[i].Rejected {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		k := rem.Keys[what]
		if k == nil || k.State == store.KeyStateRejected {
			return nil, fmt.Errorf("nothing to reject for %s", strings.TrimSpace(rem.Address+" "+what))
		}
		k.State = store.KeyStateRejected
		return []Result{{Address: rem.Address, KeyID: k.KeyID, Decision: Rejected, Reason: "rejected by the operator"}}, nil
	}
	var res []Result
	for j := len(idx) - 1; j >= 0; j-- {
		pc := &st.Pending[idx[j]]
		r := Result{Address: rem.Address, Decision: Rejected, Reason: "rejected by the operator: " + pc.Kind + " " + pc.New}
		switch pc.Kind {
		case store.PendingKeyChange:
			r.KeyID = pc.New
			if k := rem.Keys[pc.New]; k != nil {
				k.State = store.KeyStateRejected
			}
			removePending(st, idx[j])
		case store.PendingNickChange:
			pc.Rejected = true
			for _, k := range sortedKeys(rem) {
				if k.State == store.KeyStateQuarantined && k.Nick == pc.New {
					k.State = store.KeyStateRejected
				}
			}
		default:
			pc.Rejected = true
		}
		res = append(res, r)
	}
	slices.Reverse(res)
	return res, nil
}
