// Package chain decides which chain pings go out and which chains are
// broken (design §8.2, phase 3), as Echolot does: E:Chain.pm:126-207 for
// scheduling and E:Stats.pm:509-645 for the evaluation, its compression
// and the broken type-II section of mlist2.txt.
//
// A chain ping goes through two remailers, A then B (B delivers it), each
// encrypted to its newest key.  Every ordered pair is pinged once a week,
// pairs in "intensive care" (few samples, or broken) once a day.  A pair
// is broken when far fewer of its pings come back than the reliability of
// A and B predicts; mlist2.txt lists it as "(nickA nickB)", or as "(A *)"
// and "(* B)" when a remailer is in many broken chains.
package chain

import (
	"cmp"
	"slices"
	"time"

	"github.com/go-while/go-echolot/internal/sched"
)

// Echolot's chain ping settings (E:Config.pm:123-131).
const (
	Period    = 7 * 24 * time.Hour  // chainping_every_nth_time: 2016 × 5 min
	ICPeriod  = 24 * time.Hour      // chainping_ic_every_nth_time: 288 × 5 min
	Window    = 10 * 24 * time.Hour // chainping_period ("12 days" in the comment, design §2.1-11)
	Expire    = 12 * 24 * time.Hour // expire_chainpings (E:Config.pm:142)
	Update    = 4 * time.Hour       // chainping_update: re-evaluate at most this often
	Fudge     = 0.3                 // chainping_fudge
	Grace     = 1.5                 // chainping_grace
	MinSample = 3                   // chainping_minsample
	AllBad    = 0.5                 // chainping_allbad_factor
)

// Hop is a remailer as a chain hop: its address and the key chain pings
// encrypt to.
type Hop struct {
	Addr  string
	KeyID string
}

// Pair is a chain: A first, B second (B delivers).
type Pair struct {
	A, B Hop
}

// Key is a chain by addresses, as Echolot's intensive care keys it
// (addr1." ".addr2, E:Chain.pm:212).
type Key struct {
	A, B string
}

// Key returns p's addresses.
func (p Pair) Key() Key { return Key{p.A.Addr, p.B.Addr} }

// SlotID is p's id for sched.Due (design §8.3): A + "|" + B.
func (p Pair) SlotID() string { return p.A.Addr + "|" + p.B.Addr }

// Pairs returns every ordered pair (A, B) of hops with A ≠ B, sorted by A
// then B.  The hops are the remailers chain pings go to, one per address,
// each with its newest key (E:Chain.pm:148-168):
//   - Echolot takes every remailer with pingit that has a mix key, with
//     the key of the newest last_update.  The daemon passes the remailers
//     it pings (pingit, not dead or disabled), each with
//     keys.Publishable(rem, now, requireProof): the same choice (§8.4),
//     the key clients encrypt to.  A remailer without one is left out.
//   - B need not be an exit: Echolot pings every pair (E:Chain.pm:170-203).
//     A middleman as B gets the exit packet and randhops it through an
//     exit of its own choice, as with a plain ping to a middleman.
//
// A hop with an empty address or key, or a second hop for an address, is
// ignored.
func Pairs(hops []Hop) []Pair {
	seen := map[string]bool{}
	var hs []Hop
	for _, h := range hops {
		if h.Addr == "" || h.KeyID == "" || seen[h.Addr] {
			continue
		}
		seen[h.Addr] = true
		hs = append(hs, h)
	}
	slices.SortFunc(hs, func(a, b Hop) int { return cmp.Compare(a.Addr, b.Addr) })
	var ps []Pair
	for _, a := range hs {
		for _, b := range hs {
			if a.Addr != b.Addr {
				ps = append(ps, Pair{a, b})
			}
		}
	}
	return ps
}

// Due returns the pairs whose chain ping is due at the tick containing t
// (E:Chain.pm:193-199): a pair fires in its weekly slot, and a pair in
// intensive care also in its daily slot.  key is K_sched; care is the
// intensive care of the last Evaluate (nil: none yet).  Period and
// ICPeriod must be multiples of tick.
func Due(key [32]byte, pairs []Pair, care map[Key]string, t time.Time, tick time.Duration) []Pair {
	var due []Pair
	for _, p := range pairs {
		id := p.SlotID()
		_, ic := care[p.Key()]
		if sched.Due(key, id, t, Period, tick) || (ic && sched.Due(key, id, t, ICPeriod, tick)) {
			due = append(due, p)
		}
	}
	return due
}
