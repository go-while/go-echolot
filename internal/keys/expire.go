package keys

import (
	"slices"
	"time"

	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/store"
)

// Expire is the daily job (§5.1 retention, §8.5 states):
//   - a key goes when LastSeen is older than cfg.Retention and it is
//     expired, or KeyMaxAge after LastSeen whatever its dates;
//   - a conf goes ConfMaxAge after its LastUpdate unless DontExpire;
//   - a suggestion goes SuggestionMaxAge after its time, or when its
//     address became known;
//   - a pending change goes when its remailer or its new key is gone; an
//     open nick or address change when it wasn't seen for cfg.Retention; a
//     rejected one RejectedMaxAge after it was last seen;
//   - an active remailer with TTL <= 0 goes to "ttl timeout", one in "ttl
//     timeout" with ResurrectionTTL <= 0 to "dead".
func Expire(st *store.State, now time.Time, cfg config.Keys) []Result {
	var res []Result
	addrs := make([]string, 0, len(st.Remailers))
	for a := range st.Remailers {
		addrs = append(addrs, a)
	}
	slices.Sort(addrs)
	for _, a := range addrs {
		rem := st.Remailers[a]
		for _, k := range sortedKeys(rem) {
			age := now.Sub(k.LastSeen)
			expired := !now.Before(k.Expires.End())
			switch {
			case age > KeyMaxAge:
				res = append(res, Result{Address: a, KeyID: k.KeyID, Decision: Expired, Reason: "not seen for 30 days"})
			case age > cfg.Retention && expired:
				res = append(res, Result{Address: a, KeyID: k.KeyID, Decision: Expired, Reason: "expired and not seen within retention"})
			default:
				continue
			}
			delete(rem.Keys, k.KeyID)
		}
		if len(rem.Keys) == 0 {
			rem.Keys = nil
		}
		if c := rem.Conf; c != nil && !c.DontExpire && now.Sub(c.LastUpdate) > ConfMaxAge {
			rem.Conf = nil
			res = append(res, Result{Address: a, Decision: Expired, Reason: "conf older than 5 days"})
		}
		old := rem.Status
		if ttlTransition(rem) {
			res = append(res, Result{Address: a, Decision: State, Reason: old + " -> " + rem.Status})
		}
	}

	for a, list := range st.Prospective {
		known := findRemailer(st, a) != nil
		list = slices.DeleteFunc(list, func(s store.Suggestion) bool {
			return known || now.Sub(s.Time) > SuggestionMaxAge
		})
		if len(list) == 0 {
			delete(st.Prospective, a)
			res = append(res, Result{Address: a, Decision: Dropped, Reason: "suggestion"})
		} else {
			st.Prospective[a] = list
		}
	}
	if len(st.Prospective) == 0 {
		st.Prospective = nil
	}

	st.Pending = slices.DeleteFunc(st.Pending, func(pc store.PendingChange) bool {
		why := stalePending(st, pc, now, cfg)
		if why != "" {
			r := Result{Address: pc.Address, Decision: Dropped, Reason: pc.Kind + " change to " + pc.New + ": " + why}
			if pc.Kind == store.PendingKeyChange {
				r.KeyID = pc.New
			}
			res = append(res, r)
		}
		return why != ""
	})
	if len(st.Pending) == 0 {
		st.Pending = nil
	}
	return res
}

// stalePending returns why Expire drops pc, or "".
func stalePending(st *store.State, pc store.PendingChange, now time.Time, cfg config.Keys) string {
	rem := st.Remailers[pc.Address]
	switch {
	case rem == nil:
		return "remailer is gone"
	case pc.Kind == store.PendingKeyChange:
		if rem.Keys[pc.New] == nil {
			return "key is gone"
		}
	case pc.Rejected:
		if now.Sub(pc.LastSeen) > RejectedMaxAge {
			return "rejected and not seen for 30 days"
		}
	case now.Sub(pc.LastSeen) > cfg.Retention:
		return "not seen within retention"
	}
	return ""
}
