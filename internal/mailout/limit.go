package mailout

import (
	"context"
	"sync"
	"time"
)

// Limit returns a Mailer that passes at most maxPerHour mails in any
// 60 minutes to m (mail.max_per_hour, the abuse fuse of §9.4).  Over the
// limit, Send returns a temporary *Error wrapping ErrRateLimited and sends
// nothing.  Every attempt counts, failed or not; a Mail that fails the
// checks doesn't, nor (behind New) a .onion one without mail.tor_socks.  maxPerHour < 1 lets nothing through.  clock nil means
// time.Now.
func Limit(m Mailer, maxPerHour int, clock func() time.Time) Mailer {
	if clock == nil {
		clock = time.Now
	}
	return &limiter{m: m, max: maxPerHour, clock: clock}
}

type limiter struct {
	m     Mailer
	max   int
	clock func() time.Time

	mu   sync.Mutex
	sent []time.Time // oldest first
}

func (l *limiter) Send(ctx context.Context, m Mail) error {
	if r, ok := l.m.(*router); ok {
		if _, err := r.precheck(m); err != nil {
			return err
		}
	} else if err := m.check(); err != nil {
		return err
	}
	if !l.take() {
		return &Error{Op: "rate fuse", Err: ErrRateLimited}
	}
	return l.m.Send(ctx, m)
}

// take records a send now, if the last hour has room for it.
func (l *limiter) take() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	cut := now.Add(-time.Hour)
	i := 0
	for i < len(l.sent) && !l.sent[i].After(cut) {
		i++
	}
	l.sent = l.sent[i:]
	if len(l.sent) >= l.max {
		return false
	}
	l.sent = append(l.sent, now)
	return true
}
