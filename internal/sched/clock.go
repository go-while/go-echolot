package sched

import (
	"cmp"
	"slices"
	"sync"
	"time"
)

// Clock is the time source of a Loop.
type Clock interface {
	Now() time.Time
	// NewTimer returns a timer that fires once after d of elapsed time.
	NewTimer(d time.Duration) Timer
}

// Timer is a one-shot timer.
type Timer interface {
	C() <-chan time.Time
	// Stop prevents the timer from firing; it reports whether it did.
	Stop() bool
}

// RealClock returns the system clock.
func RealClock() Clock { return realClock{} }

type realClock struct{}

func (realClock) Now() time.Time                 { return time.Now() }
func (realClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time { return r.t.C }
func (r realTimer) Stop() bool          { return r.t.Stop() }

// Fake is a manual clock for tests.  It keeps a wall time and an elapsed
// (monotonic) time: Advance moves both, Jump moves only the wall time,
// like a clock step or a suspended machine.  Timers run on elapsed time,
// as Go's timers do.
type Fake struct {
	mu     sync.Mutex
	wall   time.Time
	mono   time.Duration
	seq    int
	timers []*fakeTimer
}

type fakeTimer struct {
	f    *Fake
	when time.Duration
	seq  int
	c    chan time.Time
}

// NewFake returns a fake clock showing t.
func NewFake(t time.Time) *Fake { return &Fake{wall: t} }

// Now returns the fake wall time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wall
}

// NewTimer returns a timer firing after d of elapsed time; d <= 0 fires
// at once.
func (f *Fake) NewTimer(d time.Duration) Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	t := &fakeTimer{f: f, when: f.mono + d, seq: f.seq, c: make(chan time.Time, 1)}
	if d <= 0 {
		t.c <- f.wall
		return t
	}
	f.timers = append(f.timers, t)
	return t
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

func (t *fakeTimer) Stop() bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	i := slices.Index(t.f.timers, t)
	if i < 0 {
		return false
	}
	t.f.timers = slices.Delete(t.f.timers, i, i+1)
	return true
}

// Advance lets d pass and fires the timers that are due, earliest first
// (ties in creation order).  It returns how many fired.
func (f *Fake) Advance(d time.Duration) int {
	if d < 0 {
		panic("sched: Fake.Advance with negative duration")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = f.wall.Add(d)
	f.mono += d
	slices.SortFunc(f.timers, func(a, b *fakeTimer) int {
		return cmp.Or(cmp.Compare(a.when, b.when), cmp.Compare(a.seq, b.seq))
	})
	n := 0
	for len(f.timers) > 0 && f.timers[0].when <= f.mono {
		f.timers[0].c <- f.wall
		f.timers = f.timers[1:]
		n++
	}
	return n
}

// Jump moves the wall time by d (either way) without elapsed time; no
// timer fires.
func (f *Fake) Jump(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = f.wall.Add(d)
}

// Timers returns how many timers are pending.
func (f *Fake) Timers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.timers)
}
