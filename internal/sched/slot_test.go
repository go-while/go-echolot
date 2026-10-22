package sched

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func testKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// The values must never change: a change moves every item's slot and
// breaks the spacing of pings across a restart with a new binary.
// Cross-checked with Python's hmac module.
var goldenSlots = []struct {
	id      string
	session int64
	n       int
	want    int
}{
	{"remailer@example.org|mix|0123456789abcdef", 245678, 24, 15},
	{"remailer@example.org|key", 245678, 24, 2},
	{"remailer@example.org|conf", 20473, 288, 159},
	{"a@x|b@y", 2924, 2016, 113},
	{"", 0, 1073741824, 157735814},
	{"x", -1, 1000003, 888217},
}

func TestSlotGolden(t *testing.T) {
	k := testKey()
	for _, g := range goldenSlots {
		if got := Slot(k, g.id, g.session, g.n); got != g.want {
			t.Errorf("Slot(%q, %d, %d) = %d, want %d", g.id, g.session, g.n, got, g.want)
		}
		// the formula, written out independently
		m := hmac.New(sha256.New, k[:])
		m.Write([]byte(g.id + "|" + strconv.FormatInt(g.session, 10)))
		v := binary.BigEndian.Uint64(m.Sum(nil)[:8]) % uint64(g.n)
		if int(v) != g.want {
			t.Errorf("formula(%q, %d, %d) = %d, want %d", g.id, g.session, g.n, v, g.want)
		}
	}
}

func TestSlotPanicsOnZeroN(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	Slot(testKey(), "x", 1, 0)
}

func TestSlotDistribution(t *testing.T) {
	const n, items = 24, 24000
	k := testKey()
	var count [n]int
	for i := range items {
		count[Slot(k, fmt.Sprintf("r%d@example.org|key", i), 245678, n)]++
	}
	for s, c := range count {
		// expected 1000, sd about 31
		if c < 850 || c > 1150 {
			t.Errorf("slot %d: %d items, want about %d", s, c, items/n)
		}
	}
}

func TestSlotChangesWithSessionAndKey(t *testing.T) {
	k := testKey()
	k2 := k
	k2[0] ^= 1
	sameS, sameK := 0, 0
	for i := range 1000 {
		id := fmt.Sprintf("r%d|conf", i)
		a := Slot(k, id, 100, 288)
		if a == Slot(k, id, 101, 288) {
			sameS++
		}
		if a == Slot(k2, id, 100, 288) {
			sameK++
		}
	}
	// by chance about 1000/288 = 3.5
	if sameS > 15 || sameK > 15 {
		t.Errorf("slots barely change: same across sessions %d, across keys %d", sameS, sameK)
	}
}

func TestSession(t *testing.T) {
	for _, c := range []struct {
		t      time.Time
		period time.Duration
		want   int64
	}{
		{time.Unix(0, 0), 2 * time.Hour, 0},
		{time.Unix(7199, 999999999), 2 * time.Hour, 0},
		{time.Unix(7200, 0), 2 * time.Hour, 1},
		{time.Unix(-1, 0), 2 * time.Hour, -1},
		{time.Unix(-7200, 0), 2 * time.Hour, -1},
		{time.Unix(-7201, 0), 2 * time.Hour, -2},
		{time.Date(2026, 10, 22, 13, 37, 0, 0, time.UTC), 24 * time.Hour, 20748},
		{time.Unix(0, 1500), 1000, 1}, // sub-second period
		{time.Unix(0, -1), 1000, -1},
	} {
		if got := Session(c.t, c.period); got != c.want {
			t.Errorf("Session(%v, %s) = %d, want %d", c.t, c.period, got, c.want)
		}
	}
}

func TestWithFromAlternates(t *testing.T) {
	const period = 2 * time.Hour
	start := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC) // session 248976 (even)
	for i := range 10 {
		at := start.Add(time.Duration(i)*period + 17*time.Minute)
		want := i%2 == 1
		if got := WithFrom(at, period); got != want {
			t.Errorf("session %d: WithFrom = %v, want %v", Session(at, period), got, want)
		}
	}
	if !WithFrom(time.Unix(-1, 0), period) {
		t.Error("session -1 must be odd")
	}
}

// Over each whole period every item is due exactly once, in its slot.
func TestDueOncePerPeriod(t *testing.T) {
	k := testKey()
	const tick = 5 * time.Minute
	for _, period := range []time.Duration{tick, 2 * time.Hour, 24 * time.Hour} {
		n := int(period / tick)
		start := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
		for p := range 3 {
			ps := start.Add(time.Duration(p) * period)
			for i := range 50 {
				id := fmt.Sprintf("r%d@example.org|mix|%x", i, i)
				fired := 0
				for s := range n {
					at := ps.Add(time.Duration(s)*tick + 90*time.Second) // inside the tick
					if Due(k, id, at, period, tick) {
						fired++
						if want := Slot(k, id, Session(at, period), n); s != want {
							t.Errorf("%s fired in slot %d, want %d", id, s, want)
						}
					}
				}
				if fired != 1 {
					t.Errorf("period %s, session %d: %s fired %d times", period, Session(ps, period), id, fired)
				}
			}
		}
	}
}

func TestAlign(t *testing.T) {
	d := 7 * 24 * time.Hour // not a divisor of the year-1 epoch offset
	at := time.Date(2026, 10, 22, 13, 37, 1, 5, time.UTC)
	down := alignDown(at, d)
	if down.Unix()%int64(d/time.Second) != 0 || down.After(at) || at.Sub(down) >= d {
		t.Errorf("alignDown = %v", down)
	}
	if up := alignUp(at, d); !up.Equal(down.Add(d)) {
		t.Errorf("alignUp = %v", up)
	}
	if up := alignUp(down, d); !up.Equal(down) {
		t.Errorf("alignUp of an aligned time = %v, want %v", up, down)
	}
	if got := alignDown(time.Unix(0, 2500), 1000); !got.Equal(time.Unix(0, 2000)) {
		t.Errorf("sub-second alignDown = %v", got)
	}
}
