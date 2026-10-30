// Package keys is the key policy: which keys are valid, pinged and
// published, how key and conf replies change the state, and the
// quarantine of unexpected changes (design §8.4, §8.5, §9.1-9.3).
//
// Everything here is a pure function over *store.State.  The caller
// holds the state lock, passes the time in and saves the state after.
//
// Who does what with the remailer states (§8.5):
//   - the conf request sender calls DecreaseTTL once per request, and the
//     weekly resurrection check calls DecreaseResurrectionTTL; both switch
//     the state at once, as Echolot's decrease_ttl does;
//   - Expire, the daily job, does the same transitions again for state
//     that was changed by hand;
//   - ApplyKeyReply and ApplyConfReply call RestoreTTL on a live reply.
package keys

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/civil"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// Limits of the policy.
const (
	MaxNickLen       = 12                  // longer nicks are quarantined (§6.4)
	MaxValidity      = 400                 // days from created to expires
	SightingGap      = 30 * time.Minute    // tokens closer than this count as one sighting
	KeyMaxAge        = 30 * 24 * time.Hour // a key goes this long after LastSeen, whatever its dates
	ConfMaxAge       = 5 * 24 * time.Hour  // E:Storage/File.pm:1589-1594
	SuggestionMaxAge = 5 * 24 * time.Hour  // E:Storage/File.pm:915-928
	RejectedMaxAge   = 30 * 24 * time.Hour // a rejected nick or address change is remembered this long after LastSeen
)

// Decision is what happened to a key, conf or change.
type Decision string

// Decisions.
const (
	Accepted    Decision = "accepted"    // first key, or stored conf, or applied by approval
	Rotation    Decision = "rotation"    // new key accepted as a normal rotation
	Seen        Decision = "seen"        // known key seen again
	Quarantined Decision = "quarantined" // stored, waiting for its time or the operator
	Rejected    Decision = "rejected"    // failed a check or rejected by the operator
	Ignored     Decision = "ignored"     // replay or not for this remailer
	Suggested   Decision = "suggested"   // another address; kept as a Suggestion
	Applied     Decision = "applied"     // pending change applied after the quarantine
	Waiting     Decision = "waiting"     // pending change not applied yet
	Dropped     Decision = "dropped"     // pending change or suggestion removed
	Expired     Decision = "expired"     // key or conf removed by Expire
	State       Decision = "state"       // remailer state changed by Expire
	Replaced    Decision = "replaced"    // old key of an applied key change, once the new one is proven
)

// Result describes one decision, for the log and status.  It never holds
// key material.
type Result struct {
	Address  string
	KeyID    string // "" for confs, nick and address changes
	Decision Decision
	Reason   string
}

func (r Result) String() string {
	s := r.Address
	if r.KeyID != "" {
		s += " key " + r.KeyID
	}
	s += ": " + string(r.Decision)
	if r.Reason != "" {
		s += ": " + r.Reason
	}
	return s
}

// Valid reports whether now is inside k's dates: from 00:00 UTC of its
// created date to 00:00 UTC after its expiry date, as yamn clients check
// (Y:keymgr/public.go).  It doesn't look at k.State.
func Valid(k *store.Key, now time.Time) bool {
	if k.Created.IsZero() || k.Expires.IsZero() {
		return false
	}
	return !now.Before(k.Created.Start()) && now.Before(k.Expires.End())
}

// Proven reports whether a ping encrypted to k came back (§9.2).
func Proven(k *store.Key) bool { return !k.ProvenAt.IsZero() }

// SetProven records the first returned ping to k.  It reports whether
// ProvenAt was set now; later calls keep the first time.
func SetProven(k *store.Key, at time.Time) bool {
	if Proven(k) {
		return false
	}
	k.ProvenAt = at.UTC()
	return true
}

// SameAddress compares two addresses: the local part exactly, the domain
// without regard to case (§6.4).
func SameAddress(a, b string) bool {
	la, da, oka := strings.Cut(a, "@")
	lb, db, okb := strings.Cut(b, "@")
	return oka && okb && la == lb && strings.EqualFold(da, db)
}

// canonAddress lower-cases the domain, for map keys of suggestions.
func canonAddress(a string) string {
	l, d, ok := strings.Cut(a, "@")
	if !ok {
		return a
	}
	return l + "@" + strings.ToLower(d)
}

// keyBefore is the order of §8.4: LastSeen descending, then Created
// descending, then Expires descending, then keyid ascending.
func keyBefore(a, b *store.Key) int {
	if c := b.LastSeen.Compare(a.LastSeen); c != 0 {
		return c
	}
	if c := b.Created.Compare(a.Created); c != 0 {
		return c
	}
	if c := b.Expires.Compare(a.Expires); c != 0 {
		return c
	}
	return cmp.Compare(a.KeyID, b.KeyID)
}

// first returns the first key of rem in keyBefore order that ok accepts.
func first(rem *store.Remailer, ok func(*store.Key) bool) *store.Key {
	var best *store.Key
	for _, k := range rem.Keys {
		if ok(k) && (best == nil || keyBefore(k, best) < 0) {
			best = k
		}
	}
	return best
}

// Current returns the key rotations are judged against: the most recently
// seen active Valid key, proven or not, or nil.
func Current(rem *store.Remailer, now time.Time) *store.Key {
	return first(rem, func(k *store.Key) bool {
		return k.State == store.KeyStateActive && Valid(k, now)
	})
}

// Publishable returns the key to publish for rem, or nil (§8.4): active,
// Valid, proven unless requireProof is off, with the pinned nick and the
// remailer's address.  The last two hold anyway for active keys; they're
// checked again so a key that doesn't match the pins (yamn's self-check,
// §9.7) is never published.
func Publishable(rem *store.Remailer, now time.Time, requireProof bool) *store.Key {
	if rem.Nick == "" {
		return nil
	}
	return first(rem, func(k *store.Key) bool {
		return k.State == store.KeyStateActive && Valid(k, now) &&
			(Proven(k) || !requireProof) &&
			k.Nick == rem.Nick && SameAddress(k.Address, rem.Address)
	})
}

// Pingable returns the keys of rem to ping, in the order of §8.4: Valid,
// active or quarantined (pings to new keys prove possession, §9.2), seen
// within retention, and for the remailer's current address.
func Pingable(rem *store.Remailer, now time.Time, retention time.Duration) []*store.Key {
	var ks []*store.Key
	for _, k := range rem.Keys {
		if (k.State == store.KeyStateActive || k.State == store.KeyStateQuarantined) &&
			Valid(k, now) && !k.LastSeen.Before(now.Add(-retention)) &&
			SameAddress(k.Address, rem.Address) {
			ks = append(ks, k)
		}
	}
	slices.SortFunc(ks, keyBefore)
	return ks
}

// CheckKey checks a parsed key against rem and today (§6.4): created no
// later than today, expires no earlier than today, expires after created
// and at most 400 days later, and the remailer's address.  The key block
// checks were done by the parser.
func CheckKey(pk replies.ParsedKey, rem *store.Remailer, today civil.Date) error {
	switch {
	case !replies.ValidName(pk.Nick):
		return fmt.Errorf("bad nick %q", pk.Nick)
	case !replies.ValidAddress(pk.Address):
		return fmt.Errorf("bad address %q", pk.Address)
	case pk.Created.IsZero() || pk.Expires.IsZero():
		return fmt.Errorf("missing dates")
	case pk.Created.After(today):
		return fmt.Errorf("created %s is after today %s", pk.Created, today)
	case pk.Expires.Before(today):
		return fmt.Errorf("expired %s", pk.Expires)
	case !pk.Expires.After(pk.Created):
		return fmt.Errorf("expires %s is not after created %s", pk.Expires, pk.Created)
	case pk.Created.AddDays(MaxValidity).Before(pk.Expires):
		return fmt.Errorf("valid for more than %d days (%s to %s)", MaxValidity, pk.Created, pk.Expires)
	case !SameAddress(pk.Address, rem.Address):
		return fmt.Errorf("address %s is not %s", pk.Address, rem.Address)
	}
	return nil
}

// MarkNotARemailer handles a "not a remailer" reply (§6.4): no more
// requests or pings.  Only the operator turns it back on.
func MarkNotARemailer(rem *store.Remailer) {
	rem.PingIt = false
	rem.Fetch = false
	rem.Status = store.StatusNotARemailer
}

// RestoreTTL is what a live reply does (E:Storage/File.pm restore_ttl):
// both TTLs back to their defaults, and "ttl timeout" or "dead" back to
// active.  States set by the operator or by "not a remailer" stay: those
// also turned Fetch and PingIt off, and only the operator turns them on.
// It reports whether the state changed.
func RestoreTTL(rem *store.Remailer) bool {
	rem.TTL = store.DefaultTTL
	rem.ResurrectionTTL = store.DefaultResurrectionTTL
	if rem.Status == store.StatusTTLTimeout || rem.Status == store.StatusDead {
		rem.Status = store.StatusActive
		return true
	}
	return false
}

// DecreaseTTL is called once per conf request sent to rem.  At 0 an active
// remailer goes to "ttl timeout" with a fresh ResurrectionTTL, as
// Echolot's decrease_ttl.  It reports whether the state changed.
func DecreaseTTL(rem *store.Remailer) bool {
	rem.TTL--
	return ttlTransition(rem)
}

// DecreaseResurrectionTTL is called once per weekly check of a remailer
// in "ttl timeout".  At 0 it is "dead".  It reports whether the state
// changed.
func DecreaseResurrectionTTL(rem *store.Remailer) bool {
	if rem.Status != store.StatusTTLTimeout {
		return false
	}
	rem.ResurrectionTTL--
	return ttlTransition(rem)
}

func ttlTransition(rem *store.Remailer) bool {
	switch {
	case rem.Status == store.StatusActive && rem.TTL <= 0:
		rem.Status = store.StatusTTLTimeout
		rem.ResurrectionTTL = store.DefaultResurrectionTTL
		return true
	case rem.Status == store.StatusTTLTimeout && rem.ResurrectionTTL <= 0:
		rem.Status = store.StatusDead
		return true
	}
	return false
}

// findRemailer returns the remailer with address a, comparing as
// SameAddress, or nil.
func findRemailer(st *store.State, a string) *store.Remailer {
	if r := st.Remailers[a]; r != nil {
		return r
	}
	for _, r := range st.Remailers {
		if SameAddress(r.Address, a) {
			return r
		}
	}
	return nil
}

// nickOwner returns the remailer other than rem that has nick pinned, or
// nil.  With several (a broken state), the lowest ID.
func nickOwner(st *store.State, nick string, rem *store.Remailer) *store.Remailer {
	var owner *store.Remailer
	for _, r := range st.Remailers {
		if r != rem && r.Nick == nick && (owner == nil || r.ID < owner.ID) {
			owner = r
		}
	}
	return owner
}

// nickProblem returns why nick can't be used for rem without a pending
// change, or "" when it can: it is the pinned nick, or rem is unpinned
// and nick is free and at most 12 characters (it is then pinned, TOFU).
func nickProblem(st *store.State, rem *store.Remailer, nick string) string {
	switch {
	case !replies.ValidName(nick):
		return fmt.Sprintf("bad nick %q", nick)
	case rem.Nick != "" && nick == rem.Nick:
		return ""
	case len(nick) > MaxNickLen:
		return fmt.Sprintf("nick %s is longer than %d characters", nick, MaxNickLen)
	}
	if o := nickOwner(st, nick, rem); o != nil {
		return fmt.Sprintf("nick %s is pinned to %s", nick, o.Address)
	}
	if rem.Nick != "" {
		return fmt.Sprintf("nick %s is not the pinned nick %s", nick, rem.Nick)
	}
	return ""
}
