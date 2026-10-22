// Package stats computes a remailer's latency and reliability exactly as
// Echolot's calculate() does (design §8.1, E:Stats.pm:205-300), and the
// strings mlist2.txt and mlist.txt show for them (E:Stats.pm:48-203).
//
// The caller picks the pings: per address, those of all keys whose pings
// count (§13 items 3 and 18: by default every key the address had during
// the last Days days, but not keys that were never published).  Calculate
// itself drops pings sent Days days ago or earlier, as Echolot does.
// Aborted pings (a local failure) must not be passed at all.
package stats

import (
	"slices"
	"sort"
	"time"
)

// SecondsPerDay is Echolot's seconds_per_day (E:Config.pm).
const SecondsPerDay = 86400

// Done is a ping that came back.
type Done struct {
	Sent    time.Time
	Latency int64 // seconds
}

// Params are the stats parameters (config [stats], E:Config.pm:89,200 and
// the constants of E:Stats.pm:235-236).
type Params struct {
	Days        int       // stats_days, 1 to 12
	Weights     []float64 // per day, newest first; a missing one counts 0
	SkewAbs     time.Duration
	SkewPercent float64
}

// Result is what calculate() returns.  Days are indexed by age: index 0
// is the last 24 hours.
type Result struct {
	Latency        *float64   // median latency in seconds; nil: none came back
	Reliability    float64    // 0 to 1
	LatencyDay     []*float64 // per day; nil: none came back that day
	ReliabilityDay []*float64 // per day; nil: nothing was sent that day
	// Clamped counts pings sent more than a day in the future (clock
	// skew).  Perl would index a negative day; they count as day 0, and
	// the caller should log it.
	Clamped int
}

// Calculate is E:Stats.pm:231-300.  out are the sent times of the pings
// still outstanding, done those that came back.  The sums run over done
// first, then out, each in the order given, as Echolot's do (its order
// is the storage's), so pass them in a stable order.
func Calculate(out []time.Time, done []Done, now time.Time, p Params) Result {
	days := p.Days
	if days < 1 {
		return Result{}
	}
	nowS := now.Unix()
	cutoff := nowS - int64(days)*SecondsPerDay
	r := Result{LatencyDay: make([]*float64, days), ReliabilityDay: make([]*float64, days)}

	// day is int((now - t) / 86400), truncating toward zero (E:Stats.pm:254).
	day := func(t int64) int {
		d := (nowS - t) / SecondsPerDay
		if d < 0 {
			r.Clamped++
			return 0
		}
		return int(min(d, int64(days-1))) // after the cutoff, d < days
	}
	weight := func(d int) float64 {
		if d < len(p.Weights) {
			return p.Weights[d]
		}
		return 0 // Perl: undef
	}

	var sentW, recvW float64
	sentDay := make([]int, days)
	recvDay := make([]float64, days)
	latDay := make([][]int64, days)
	var lats []int64
	for _, dn := range done {
		s := dn.Sent.Unix()
		if s <= cutoff {
			continue
		}
		d := day(s)
		w := weight(d)
		latDay[d] = append(latDay[d], dn.Latency)
		lats = append(lats, dn.Latency)
		sentW += w
		recvW += w
		sentDay[d]++
		recvDay[d]++
	}

	slices.Sort(lats)
	r.Latency = median(lats)
	for d := range days {
		slices.Sort(latDay[d])
		r.LatencyDay[d] = median(latDay[d])
	}

	skew := p.SkewAbs.Seconds()
	for _, t := range out {
		s := t.Unix()
		if s <= cutoff {
			continue
		}
		pr := 0.0
		if len(lats) > 0 {
			pr = percentile((float64(nowS-s)-skew)/p.SkewPercent, lats)
		}
		d := day(s)
		w := weight(d)
		sentW += w
		recvW += float64(w * pr) // the conversion forbids a fused multiply-add
		sentDay[d]++
		recvDay[d] += pr
	}

	if sentW != 0 {
		r.Reliability = recvW / sentW
	}
	for d := range days {
		if sentDay[d] > 0 {
			v := recvDay[d] / float64(sentDay[d])
			r.ReliabilityDay[d] = &v
		}
	}
	return r
}

// median of sorted lats; an even count gives the mean of the middle two
// (E:Stats.pm:205-216).
func median(lats []int64) *float64 {
	n := len(lats)
	if n == 0 {
		return nil
	}
	var v float64
	if n%2 == 0 {
		v = float64(lats[(n-1)/2]+lats[n/2]) / 2
	} else {
		v = float64(lats[(n-1)/2])
	}
	return &v
}

// percentile is the share of sorted lats strictly greater than x
// (E:Stats.pm:220-229).
func percentile(x float64, lats []int64) float64 {
	i := sort.Search(len(lats), func(i int) bool { return x < float64(lats[i]) })
	return float64(len(lats)-i) / float64(len(lats))
}
