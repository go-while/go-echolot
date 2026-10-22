package mailout

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// countMailer counts sends and fails every other one.
type countMailer struct {
	mu sync.Mutex
	n  int
}

func (c *countMailer) Send(context.Context, Mail) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	if c.n%2 == 0 {
		return &Error{Op: "test", Err: errors.New("421 later")}
	}
	return nil
}

func TestLimit(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := &countMailer{}
	m := Limit(c, 3, clock)
	send := func() error { return m.Send(context.Background(), testMail()) }

	for range 3 {
		send() // failures count too
		now = now.Add(10 * time.Minute)
	}
	err := send()
	var e *Error
	if !errors.Is(err, ErrRateLimited) || !errors.Is(err, ErrTemporary) || IsPermanent(err) || !errors.As(err, &e) {
		t.Fatalf("got %v, want a temporary ErrRateLimited", err)
	}
	if c.n != 3 {
		t.Fatalf("%d sends reached the mailer, want 3", c.n)
	}
	// An invalid mail is refused for what it is, and not counted.
	if err := m.Send(context.Background(), Mail{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("got %v, want ErrInvalid", err)
	}
	// The first send (12:00) leaves the window at 13:00.
	now = time.Date(2026, 10, 21, 13, 0, 0, 0, time.UTC)
	if err := send(); errors.Is(err, ErrRateLimited) {
		t.Fatalf("at 13:00: %v", err)
	}
	if err := send(); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second at 13:00: %v", err)
	}
	if c.n != 4 {
		t.Errorf("%d sends, want 4", c.n)
	}

	if err := Limit(c, 0, nil).Send(context.Background(), testMail()); !errors.Is(err, ErrRateLimited) {
		t.Errorf("limit 0: %v", err)
	}
}

func TestLimitConcurrent(t *testing.T) {
	c := &countMailer{}
	m := Limit(c, 50, nil)
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() { m.Send(context.Background(), testMail()) })
	}
	wg.Wait()
	if c.n != 50 {
		t.Errorf("%d sends, want 50", c.n)
	}
}
