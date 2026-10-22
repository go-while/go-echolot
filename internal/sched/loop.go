package sched

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// defaultMaxWait bounds every wait, so that a wall-clock step or a
// suspended machine (during which Go's timers don't advance) is noticed
// within a minute.
const defaultMaxWait = time.Minute

// Loop runs jobs one at a time in a single goroutine: periodic jobs at
// wall-clock multiples of their period (Every) and debounced jobs some
// delay after a Trigger (Debounced).
//
// Jobs run in time order of when they became due; jobs due at the same
// instant run in registration order.  A periodic run that was missed
// (a job ran long, the machine slept, the clock jumped) is skipped, not
// caught up: the job runs once for the latest multiple of its period and
// the skipped count is logged.  A panicking job is logged and the loop
// goes on.
type Loop struct {
	clock   Clock
	log     *slog.Logger
	maxWait time.Duration

	mu      sync.Mutex
	jobs    []*job // registration order
	byName  map[string]*job
	onTick  func(name string, at time.Time)
	err     error // first registration error
	running bool

	wake chan struct{}
	idle chan struct{} // tests: receives once per wait, after the timer is set
}

type job struct {
	name   string
	period time.Duration // > 0 for Every
	delay  time.Duration // for Debounced
	fn     func(ctx context.Context, at time.Time)

	due     time.Time // next run; zero = not scheduled yet / not triggered
	pending bool      // debounced: triggered and not run yet
}

// New returns a Loop on clock (nil = the system clock), logging to log
// (nil = discard).
func New(clock Clock, log *slog.Logger) *Loop {
	if clock == nil {
		clock = RealClock()
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Loop{
		clock:   clock,
		log:     log,
		maxWait: defaultMaxWait,
		byName:  map[string]*job{},
		wake:    make(chan struct{}, 1),
	}
}

// Every runs fn at each multiple of d counted from the Unix epoch; at is
// that multiple, not the actual start, so slot computations agree across
// restarts.  The first run is at the first multiple not before the start
// of Run.
func (l *Loop) Every(name string, d time.Duration, fn func(ctx context.Context, at time.Time)) {
	if d <= 0 {
		l.fail(fmt.Errorf("sched: job %q: period must be positive, not %s", name, d))
		return
	}
	l.add(&job{name: name, period: d, fn: fn})
}

// Debounced registers fn to run delay after the first Trigger(name);
// further triggers until it runs are coalesced.  A trigger while fn runs
// schedules one more run.  at is the time the run was due.
func (l *Loop) Debounced(name string, delay time.Duration, fn func(ctx context.Context, at time.Time)) {
	if delay < 0 {
		l.fail(fmt.Errorf("sched: job %q: delay must not be negative, not %s", name, delay))
		return
	}
	l.add(&job{name: name, delay: delay, fn: fn})
}

// OnTick sets a function called after each periodic run that returned
// normally (not after a panic), in the loop goroutine.  It is the place
// to send WATCHDOG=1 after the main tick.
func (l *Loop) OnTick(fn func(name string, at time.Time)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onTick = fn
}

// Trigger asks for a run of the debounced job name.  It never blocks and
// may be called from any goroutine, including from a job.
func (l *Loop) Trigger(name string) {
	l.mu.Lock()
	j := l.byName[name]
	switch {
	case j == nil || j.period > 0:
		l.mu.Unlock()
		l.log.Warn("sched: trigger of an unknown debounced job", "job", name)
		return
	case !j.pending:
		j.pending = true
		j.due = l.now().Add(j.delay)
	}
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *Loop) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = err
	}
}

func (l *Loop) add(j *job) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case j.fn == nil:
		l.err = cmpErr(l.err, fmt.Errorf("sched: job %q: nil function", j.name))
	case l.byName[j.name] != nil:
		l.err = cmpErr(l.err, fmt.Errorf("sched: job %q registered twice", j.name))
	default:
		l.jobs = append(l.jobs, j)
		l.byName[j.name] = j
	}
}

func cmpErr(old, err error) error {
	if old != nil {
		return old
	}
	return err
}

// now is the clock's wall time without a monotonic reading, so that all
// comparisons are against the wall clock.
func (l *Loop) now() time.Time { return l.clock.Now().Round(0) }

// Run runs the jobs until ctx is cancelled, then returns nil.  It returns
// an error at once for a bad registration or a second call.  A running
// job is not interrupted; it gets ctx.
func (l *Loop) Run(ctx context.Context) error {
	l.mu.Lock()
	err := l.err
	if err == nil && l.running {
		err = errors.New("sched: Run called twice")
	}
	l.running = true
	l.mu.Unlock()
	if err != nil {
		return err
	}

	for {
		select {
		case <-l.wake: // state is re-read below
		default:
		}
		if ctx.Err() != nil {
			return nil
		}
		now := l.now()
		j, at, skipped, next := l.pick(now)
		if j != nil {
			if skipped > 0 {
				l.log.Warn("sched: skipped missed runs", "job", j.name, "skipped", skipped, "at", at)
			}
			l.run(ctx, j, at)
			continue
		}

		wait := l.maxWait
		if !next.IsZero() && (wait <= 0 || next.Sub(now) < wait) {
			wait = next.Sub(now)
		}
		var c <-chan time.Time
		var t Timer
		if wait > 0 {
			t = l.clock.NewTimer(wait)
			c = t.C()
		}
		if l.idle != nil {
			select {
			case l.idle <- struct{}{}:
			case <-ctx.Done():
			}
		}
		select {
		case <-ctx.Done():
		case <-c:
		case <-l.wake:
		}
		if t != nil {
			t.Stop()
		}
	}
}

// pick returns the job to run now and its at time, or else the time of
// the next due job (zero if none).  It schedules new periodic jobs and
// reschedules after the wall clock went backwards.
func (l *Loop) pick(now time.Time) (pj *job, at time.Time, skipped int64, next time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, j := range l.jobs {
		if j.period > 0 {
			switch {
			case j.due.IsZero():
				j.due = alignUp(now, j.period)
			case j.due.Sub(now) > j.period:
				l.log.Warn("sched: wall clock went backwards", "job", j.name, "was_due", j.due, "now", now)
				j.due = alignUp(now, j.period)
			}
		} else if !j.pending {
			continue
		} else if j.due.Sub(now) > j.delay {
			l.log.Warn("sched: wall clock went backwards", "job", j.name, "was_due", j.due, "now", now)
			j.due = now.Add(j.delay)
		}
		if !j.due.After(now) {
			if pj == nil || j.due.Before(pj.due) {
				pj = j
			}
			continue
		}
		if next.IsZero() || j.due.Before(next) {
			next = j.due
		}
	}
	if pj == nil {
		return nil, time.Time{}, 0, next
	}
	if pj.period == 0 {
		pj.pending = false
		at, pj.due = pj.due, time.Time{}
		return pj, at, 0, time.Time{}
	}
	at = alignDown(now, pj.period)
	skipped = int64(at.Sub(pj.due) / pj.period)
	pj.due = at.Add(pj.period)
	return pj, at, skipped, time.Time{}
}

// run calls j.fn and, for a periodic job that returned, the tick hook;
// a panic in either is recovered and logged.
func (l *Loop) run(ctx context.Context, j *job, at time.Time) {
	l.mu.Lock()
	hook := l.onTick
	l.mu.Unlock()
	if j.period == 0 {
		hook = nil
	}
	start := l.now()
	ok := false
	defer func() {
		if r := recover(); r != nil {
			l.log.Error("sched: job panicked", "job", j.name, "at", at,
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
		}
		l.log.Debug("sched: job done", "job", j.name, "at", at, "took", l.now().Sub(start), "ok", ok)
	}()
	j.fn(ctx, at)
	ok = true
	if hook != nil {
		hook(j.name, at)
	}
}
