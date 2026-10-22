// Package civil has Date, a calendar date in UTC: the "2006-01-02" created
// and expiry dates of yamn keys (design §4).
package civil

import (
	"fmt"
	"time"
)

const layout = "2006-01-02"

// Date is a calendar date in UTC.  The zero Date means "no date".
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// Parse parses a "2006-01-02" date.
func Parse(s string) (Date, error) {
	t, err := time.Parse(layout, s)
	if err != nil {
		return Date{}, fmt.Errorf("bad date %q: want YYYY-MM-DD", s)
	}
	return Of(t), nil
}

// Of returns the UTC date of t.
func Of(t time.Time) Date {
	y, m, d := t.UTC().Date()
	return Date{y, m, d}
}

// IsZero reports whether d is the zero Date.
func (d Date) IsZero() bool { return d == Date{} }

// String returns d as "2006-01-02".
func (d Date) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day)
}

// Start returns 00:00 UTC of d: the start of a key's validity on its
// created date (yamn's lastMidnight, Y:keymgr/public.go:611).
func (d Date) Start() time.Time {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
}

// End returns 00:00 UTC of the day after d: the end of a key's validity
// on its expiry date (yamn's nextMidnight).
func (d Date) End() time.Time {
	return time.Date(d.Year, d.Month, d.Day+1, 0, 0, 0, 0, time.UTC)
}

// AddDays returns d plus n days.
func (d Date) AddDays(n int) Date {
	return Of(time.Date(d.Year, d.Month, d.Day+n, 0, 0, 0, 0, time.UTC))
}

// Compare returns -1, 0 or +1 as d is before, equal to or after e.
func (d Date) Compare(e Date) int {
	return d.Start().Compare(e.Start())
}

// Before reports whether d is before e.
func (d Date) Before(e Date) bool { return d.Compare(e) < 0 }

// After reports whether d is after e.
func (d Date) After(e Date) bool { return d.Compare(e) > 0 }

// MarshalText writes d as "2006-01-02", and the zero Date as "".
func (d Date) MarshalText() ([]byte, error) {
	if d.IsZero() {
		return []byte{}, nil
	}
	return []byte(d.String()), nil
}

// UnmarshalText reads what MarshalText writes.
func (d *Date) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*d = Date{}
		return nil
	}
	v, err := Parse(string(b))
	if err != nil {
		return err
	}
	*d = v
	return nil
}
