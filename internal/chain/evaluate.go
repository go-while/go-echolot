package chain

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/go-while/go-echolot/internal/store"
)

// Remailer is a remailer as the evaluation sees it: a row of the private
// mlist2.txt (Echolot's build_rems(['mix']), E:Stats.pm:473-507).
type Remailer struct {
	Addr        string
	Nick        string
	ListIt      bool     // listed in the public mlist2.txt (output.ListIt)
	Reliability float64  // stats.Result.Reliability (avr_reliability)
	Latency     *float64 // stats.Result.Latency (avr_latency), seconds; nil: no data
}

// Broken is a broken chain.
type Broken struct {
	A, B   string // addresses
	Chain  string // "(nickA nickB)", as mlist2.txt lists it
	Public bool   // both remailers are listed publicly (E:Stats.pm:615-616)
	Done   int    // pings back, in the window
	Out    int    // pings counted, in the window
}

// Result is an evaluation: the broken chains, and the pairs in intensive
// care with Echolot's reason (for the log).
type Result struct {
	Broken []Broken       // sorted by A, then B
	Care   map[Key]string // pinged daily until the next evaluation
}

// Evaluate judges the chains (E:Stats.pm:557-622), exactly:
//   - Only pings sent within Window (10 d) count, a ping sent exactly
//     Window ago included, and only between two remailers of rems.
//   - A ping back counts as done and as out.  A ping not back counts as
//     out unless it is younger than Grace × (latency A + latency B), the
//     remailers' median latencies (none: 0).
//   - A pair with fewer than MinSample (3) out and none done goes into
//     intensive care, unjudged.
//   - Otherwise it is broken if done/out ≤ Fudge × rel(A) × rel(B); a
//     broken pair also goes into intensive care.
//
// Pairs without any counted ping are neither (E:Stats.pm:597-598 loops
// over pairs with pings only), so a new pair waits for its weekly slot.
// Aborted pings never reach here (store.ChainPings leaves them out): a
// local failure is not a lost chain ping.  Echolot counts it as out
// (E:Chain.pm:113-122), design §5.3 does not.
//
// The pings may be in any order.  now is truncated to whole seconds, as
// Echolot's time().  Echolot keeps the result for Update (4 h) and so
// should the caller; the reliabilities and latencies are those of the
// stats run that evaluates.
func Evaluate(pings []store.ChainPing, rems []Remailer, now time.Time) Result {
	byAddr := make(map[string]*Remailer, len(rems))
	for i := range rems {
		byAddr[rems[i].Addr] = &rems[i]
	}
	lat := func(r *Remailer) float64 {
		if r.Latency == nil {
			return 0
		}
		return *r.Latency
	}
	type count struct{ out, done int }
	counts := map[Key]*count{}
	t := now.Unix()
	cutoff := t - int64(Window/time.Second)
	for _, p := range pings {
		if p.Status == store.PingAborted {
			continue
		}
		sent := p.Sent.Unix()
		if sent < cutoff {
			continue
		}
		a, b := byAddr[p.A], byAddr[p.B]
		if a == nil || b == nil {
			continue
		}
		if p.Status != store.PingDone {
			// float64 as Perl's numbers: latencies may be x.5.
			if float64(t-sent) < (lat(a)+lat(b))*Grace {
				continue
			}
		}
		k := Key{p.A, p.B}
		c := counts[k]
		if c == nil {
			c = &count{}
			counts[k] = c
		}
		c.out++
		if p.Status == store.PingDone {
			c.done++
		}
	}

	res := Result{Care: map[Key]string{}}
	for k, c := range counts {
		if c.out < MinSample && c.done == 0 {
			s := ""
			if c.out > 1 {
				s = "s"
			}
			res.Care[k] = fmt.Sprintf("only %d sample%s, none returned so far", c.out, s)
			continue
		}
		a, b := byAddr[k.A], byAddr[k.B]
		theoretical := a.Reliability * b.Reliability
		if float64(c.done)/float64(c.out) > theoretical*Fudge {
			continue
		}
		res.Broken = append(res.Broken, Broken{A: k.A, B: k.B, Chain: "(" + a.Nick + " " + b.Nick + ")",
			Public: a.ListIt && b.ListIt, Done: c.done, Out: c.out})
		res.Care[k] = fmt.Sprintf("bad: %d/%d", c.done, c.out)
	}
	slices.SortFunc(res.Broken, func(x, y Broken) int {
		return cmp.Or(cmp.Compare(x.A, y.A), cmp.Compare(x.B, y.B))
	})
	return res
}
