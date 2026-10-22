package sched

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuf is a log sink safe for the loop goroutine and the test.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *lockedBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// harness drives a Loop on a fake clock.  The loop signals l.idle each
// time it is about to wait, so the test only acts while it is parked.
type harness struct {
	t      *testing.T
	fc     *Fake
	l      *Loop
	log    *lockedBuf
	cancel context.CancelFunc
	done   chan error

	mu    sync.Mutex
	runs  []string
	ticks []string
}

func newHarness(t *testing.T, start time.Time) *harness {
	h := &harness{t: t, fc: NewFake(start), log: &lockedBuf{}, done: make(chan error, 1)}
	h.l = New(h.fc, slog.New(slog.NewTextHandler(h.log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	h.l.idle = make(chan struct{})
	h.l.OnTick(func(name string, at time.Time) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.ticks = append(h.ticks, name+" "+at.Format("15:04:05"))
	})
	return h
}

// rec returns a job function that records its runs.
func (h *harness) rec(name string) func(context.Context, time.Time) {
	return func(_ context.Context, at time.Time) { h.add(name, at) }
}

func (h *harness) add(name string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.runs = append(h.runs, name+" "+at.Format("15:04:05"))
}

func (h *harness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- h.l.Run(ctx) }()
	h.t.Cleanup(h.stop)
	h.waitIdle()
}

func (h *harness) waitIdle() {
	h.t.Helper()
	select {
	case <-h.l.idle:
	case err := <-h.done:
		h.t.Fatalf("Run returned early: %v", err)
	case <-time.After(5 * time.Second):
		h.t.Fatal("loop did not settle")
	}
}

// advance lets d pass; if that fires the loop's timer, it waits until
// the loop has run what was due and parked again.
func (h *harness) advance(d time.Duration) {
	h.t.Helper()
	if h.fc.Advance(d) > 0 {
		h.waitIdle()
	}
}

func (h *harness) trigger(name string) {
	h.t.Helper()
	h.l.Trigger(name)
	h.waitIdle()
}

func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	h.cancel = nil
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		h.t.Error("Run did not stop")
	}
}

// expect checks and clears the recorded runs.
func (h *harness) expect(want ...string) {
	h.t.Helper()
	h.mu.Lock()
	got := h.runs
	h.runs = nil
	h.mu.Unlock()
	if !slices.Equal(got, want) {
		h.t.Errorf("runs = %q, want %q", got, want)
	}
}

func at(hms string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", "2026-10-22 "+hms)
	if err != nil {
		panic(err)
	}
	return t
}

func TestLoopAlignment(t *testing.T) {
	h := newHarness(t, at("12:03:20"))
	h.l.Every("tick", 5*time.Minute, h.rec("tick"))
	h.l.Every("hourly", time.Hour, h.rec("hourly"))
	h.start()
	h.expect()
	h.advance(time.Minute) // 12:04:20
	h.expect()
	h.advance(40 * time.Second) // 12:05:00
	h.expect("tick 12:05:00")
	h.advance(4*time.Minute + 59*time.Second)
	h.expect()
	h.advance(time.Second) // 12:10:00
	h.expect("tick 12:10:00")
	for range 10 {
		h.advance(5 * time.Minute)
	}
	h.expect("tick 12:15:00", "tick 12:20:00", "tick 12:25:00", "tick 12:30:00",
		"tick 12:35:00", "tick 12:40:00", "tick 12:45:00", "tick 12:50:00",
		"tick 12:55:00", "tick 13:00:00", "hourly 13:00:00")
}

// A start exactly on a multiple runs at once.
func TestLoopStartOnMultiple(t *testing.T) {
	h := newHarness(t, at("12:00:00"))
	h.l.Every("tick", 5*time.Minute, h.rec("tick"))
	h.start()
	h.expect("tick 12:00:00")
}

func TestLoopOrder(t *testing.T) {
	h := newHarness(t, at("12:00:00"))
	h.l.Every("a", 5*time.Minute, h.rec("a"))
	h.l.Every("b", 10*time.Minute, h.rec("b"))
	h.l.Every("c", 5*time.Minute, h.rec("c"))
	h.l.Debounced("d", 4*time.Minute, h.rec("d"))
	h.start()
	h.expect("a 12:00:00", "b 12:00:00", "c 12:00:00") // registration order
	h.advance(5 * time.Minute)
	h.expect("a 12:05:00", "c 12:05:00")
	h.advance(5*time.Minute + 30*time.Second)
	h.expect("a 12:10:00", "b 12:10:00", "c 12:10:00")
	h.trigger("d") // due 12:14:30
	h.fc.Jump(4 * time.Minute)
	h.advance(time.Minute) // 12:15:30: the overdue d first, then a, c
	h.expect("d 12:14:30", "a 12:15:00", "c 12:15:00")
}

func TestLoopDebounce(t *testing.T) {
	h := newHarness(t, at("12:00:00"))
	h.l.Every("tick", 5*time.Minute, h.rec("tick"))
	again := true
	h.l.Debounced("keys", 5*time.Minute, func(ctx context.Context, t time.Time) {
		h.add("keys", t)
		if again {
			again = false
			h.l.Trigger("keys") // during the run: one more run later
		}
	})
	h.start()
	h.expect("tick 12:00:00")
	h.trigger("keys")
	h.advance(time.Minute)
	h.trigger("keys")
	h.advance(time.Minute)
	h.trigger("keys")
	h.advance(time.Minute)
	h.advance(time.Minute)
	h.expect()
	h.advance(time.Minute) // 12:05
	h.expect("tick 12:05:00", "keys 12:05:00")
	h.advance(5 * time.Minute)
	h.expect("tick 12:10:00", "keys 12:10:00")
	h.advance(5 * time.Minute)
	h.advance(5 * time.Minute)
	h.expect("tick 12:15:00", "tick 12:20:00")
	h.mu.Lock()
	ticks := len(h.ticks)
	h.mu.Unlock()
	if ticks != 5 {
		t.Errorf("OnTick ran %d times, want 5 (not for debounced jobs)", ticks)
	}
	if strings.Contains(h.log.String(), "level=WARN") {
		t.Errorf("unexpected warning:\n%s", h.log)
	}
}

func TestLoopSkipAfterLongJob(t *testing.T) {
	h := newHarness(t, at("12:00:00"))
	h.l.Every("tick", 5*time.Minute, func(ctx context.Context, t time.Time) {
		h.add("tick", t)
		if t.Equal(at("12:05:00")) {
			h.fc.Advance(17 * time.Minute) // runs until 12:22
		}
	})
	h.start()
	h.advance(5 * time.Minute)
	h.expect("tick 12:00:00", "tick 12:05:00", "tick 12:20:00")
	if l := h.log.String(); !strings.Contains(l, "skipped missed runs") || !strings.Contains(l, "skipped=2") {
		t.Errorf("log lacks the skip count:\n%s", l)
	}
	h.advance(3 * time.Minute)
	h.expect("tick 12:25:00")
}

func TestLoopSkipAfterClockJump(t *testing.T) {
	for _, jump := range []bool{true, false} {
		h := newHarness(t, at("12:00:00"))
		h.l.Every("tick", 5*time.Minute, h.rec("tick"))
		h.start()
		h.expect("tick 12:00:00")
		if jump {
			// the wall clock steps (or the machine slept): no timer
			// fires, the loop notices at its next bounded wait
			h.fc.Jump(time.Hour)
			h.advance(time.Minute)
		} else {
			h.advance(time.Hour) // a timer firing late
		}
		h.expect("tick 13:00:00")
		if l := h.log.String(); strings.Count(l, "skipped missed runs") != 1 || !strings.Contains(l, "skipped=11") {
			t.Errorf("jump=%v: log lacks one skip line with the count:\n%s", jump, l)
		}
		h.stop()
	}
}

func TestLoopClockBackwards(t *testing.T) {
	h := newHarness(t, at("12:00:00"))
	h.l.Every("tick", 5*time.Minute, h.rec("tick"))
	h.l.Debounced("keys", 5*time.Minute, h.rec("keys"))
	h.start()
	h.expect("tick 12:00:00")
	h.trigger("keys") // due 12:05
	h.advance(time.Minute)
	h.fc.Jump(-2 * time.Hour) // 10:01
	h.advance(time.Minute)    // 10:02
	h.expect()
	if !strings.Contains(h.log.String(), "wall clock went backwards") {
		t.Errorf("no log of the backward step:\n%s", h.log)
	}
	h.advance(3 * time.Minute)
	h.expect("tick 10:05:00")
	h.advance(2 * time.Minute)
	h.expect("keys 10:07:00")
}

func TestLoopPanic(t *testing.T) {
	h := newHarness(t, at("12:00:00"))
	h.l.Every("bad", 5*time.Minute, func(context.Context, time.Time) { panic("boom") })
	h.l.Every("good", 5*time.Minute, h.rec("good"))
	h.start()
	h.advance(5 * time.Minute)
	h.expect("good 12:00:00", "good 12:05:00")
	l := h.log.String()
	if strings.Count(l, "job panicked") != 2 || !strings.Contains(l, "job=bad") || !strings.Contains(l, "panic=boom") {
		t.Errorf("panic not logged with the job name:\n%s", l)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !slices.Equal(h.ticks, []string{"good 12:00:00", "good 12:05:00"}) {
		t.Errorf("OnTick = %q, want only the jobs that returned", h.ticks)
	}
}

func TestLoopTickHookPanic(t *testing.T) {
	h := newHarness(t, at("12:00:00"))
	h.l.Every("tick", 5*time.Minute, h.rec("tick"))
	h.l.OnTick(func(string, time.Time) { panic("hook") })
	h.start()
	h.advance(5 * time.Minute)
	h.expect("tick 12:00:00", "tick 12:05:00")
}

func TestLoopCancelWhileWaiting(t *testing.T) {
	h := newHarness(t, at("12:00:01"))
	h.l.Every("daily", 24*time.Hour, h.rec("daily"))
	h.start()
	h.stop()
	h.expect()
}

func TestLoopCancelDuringJob(t *testing.T) {
	h := newHarness(t, at("12:00:00"))
	ctx, cancel := context.WithCancel(context.Background())
	h.l.Every("a", 5*time.Minute, func(c context.Context, t time.Time) {
		h.add("a", t)
		cancel()
		if c.Err() == nil {
			h.t.Error("job ctx not cancelled")
		}
	})
	h.l.Every("b", 5*time.Minute, h.rec("b"))
	done := make(chan error)
	go func() { done <- h.l.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	h.expect("a 12:00:00") // b, due too, did not start
}

// With the real clock and no bound on the wait, cancel still stops Run.
func TestLoopCancelRealClock(t *testing.T) {
	l := New(nil, nil)
	l.maxWait = 0
	l.Every("weekly", 7*24*time.Hour, func(context.Context, time.Time) {})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := l.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Run took %s to stop", d)
	}
}

func TestLoopErrors(t *testing.T) {
	fn := func(context.Context, time.Time) {}
	for name, reg := range map[string]func(*Loop){
		"zero period":    func(l *Loop) { l.Every("x", 0, fn) },
		"negative delay": func(l *Loop) { l.Debounced("x", -time.Second, fn) },
		"nil fn":         func(l *Loop) { l.Every("x", time.Minute, nil) },
		"duplicate":      func(l *Loop) { l.Every("x", time.Minute, fn); l.Debounced("x", time.Minute, fn) },
	} {
		l := New(NewFake(at("12:00:00")), nil)
		reg(l)
		if err := l.Run(context.Background()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}

	h := newHarness(t, at("12:00:01"))
	h.l.Every("tick", 5*time.Minute, fn)
	h.start()
	if err := h.l.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("second Run: %v", err)
	}
	h.l.Trigger("nope")
	h.l.Trigger("tick")
	if strings.Count(h.log.String(), "unknown debounced job") != 2 {
		t.Errorf("bad triggers not logged:\n%s", h.log)
	}
}

func TestFakeClock(t *testing.T) {
	fc := NewFake(at("12:00:00"))
	t2 := fc.NewTimer(2 * time.Second)
	t1 := fc.NewTimer(time.Second)
	t3 := fc.NewTimer(3 * time.Second)
	t1b := fc.NewTimer(time.Second)
	if fc.Timers() != 4 {
		t.Fatalf("Timers = %d", fc.Timers())
	}
	if !t3.Stop() || t3.Stop() {
		t.Error("Stop of a pending timer must report true once")
	}
	fc.Jump(time.Hour)
	if fc.Advance(0) != 0 {
		t.Error("Jump fired timers")
	}
	if n := fc.Advance(2 * time.Second); n != 3 {
		t.Errorf("Advance fired %d, want 3", n)
	}
	for _, tm := range []Timer{t1, t1b, t2} {
		select {
		case v := <-tm.C():
			if !v.Equal(at("13:00:02")) {
				t.Errorf("fired with %v", v)
			}
		default:
			t.Error("timer did not fire")
		}
	}
	if t1.Stop() {
		t.Error("Stop of a fired timer reported true")
	}
	select {
	case <-fc.NewTimer(0).C():
	default:
		t.Error("zero timer did not fire at once")
	}
	select {
	case <-RealClock().NewTimer(time.Millisecond).C():
	case <-time.After(5 * time.Second):
		t.Error("real timer did not fire")
	}
}
