// Package sched decides when items fire (hashed slots, design §8.3) and
// runs the periodic and debounced jobs of the daemon in one goroutine
// (§4.2).
package sched

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"time"
)

// Slot returns the slot of id in session, out of n (design §8.3):
//
//	uint64_be(HMAC-SHA256(key, id + "|" + decimal(session))[:8]) mod n
//
// key is K_sched (token.DeriveKey(secret, token.PurposeSched)).  The
// result must never change for the same inputs; the golden test pins it.
// Slot panics if n < 1.
func Slot(key [32]byte, id string, session int64, n int) int {
	if n < 1 {
		panic("sched: slot count must be positive")
	}
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(id))
	m.Write([]byte{'|'})
	m.Write(strconv.AppendInt(nil, session, 10))
	sum := m.Sum(nil)
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(n))
}

// Session returns floor(t / period), counted from the Unix epoch.
func Session(t time.Time, period time.Duration) int64 {
	return floorDiv(t, period)
}

// WithFrom reports whether a ping sent at t carries a From line
// (session mod 2, as Echolot).
func WithFrom(t time.Time, period time.Duration) bool {
	return Session(t, period)&1 == 1
}

// Due reports whether the item id fires at the tick containing t: its
// slot in the current session equals (t / tick) mod (period / tick).
// period must be a whole multiple of tick (the config ensures it).
func Due(key [32]byte, id string, t time.Time, period, tick time.Duration) bool {
	n := int64(period / tick)
	if n < 1 || tick <= 0 {
		panic("sched: period must be a positive multiple of tick")
	}
	this := floorDiv(t, tick) % n
	if this < 0 {
		this += n
	}
	return int64(Slot(key, id, Session(t, period), int(n))) == this
}

// floorDiv returns floor((t - epoch) / d).
func floorDiv(t time.Time, d time.Duration) int64 {
	if d <= 0 {
		panic("sched: duration must be positive")
	}
	if d%time.Second == 0 {
		// whole seconds: no overflow for any practical t
		s, p := t.Unix(), int64(d/time.Second)
		q := s / p
		if s%p < 0 {
			q--
		}
		return q
	}
	ns, p := t.UnixNano(), int64(d)
	q := ns / p
	if ns%p < 0 {
		q--
	}
	return q
}

// alignDown returns the latest multiple of d (from the Unix epoch) not
// after t.
func alignDown(t time.Time, d time.Duration) time.Time {
	q := floorDiv(t, d)
	if d%time.Second == 0 {
		return time.Unix(q*int64(d/time.Second), 0).UTC()
	}
	return time.Unix(0, q*int64(d)).UTC()
}

// alignUp returns the earliest multiple of d not before t.
func alignUp(t time.Time, d time.Duration) time.Time {
	a := alignDown(t, d)
	if a.Before(t) {
		a = a.Add(d)
	}
	return a
}
