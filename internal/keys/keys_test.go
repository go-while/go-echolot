package keys

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/civil"
	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

var (
	now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	cfg = config.Keys{
		Retention:      5 * 24 * time.Hour,
		RotationWindow: 72 * time.Hour,
		Quarantine:     24 * time.Hour,
		MinSightings:   2,
		RequireProof:   true,
	}
)

// Live summary lines (2026-10-22).
const (
	victorLine = "victor yamn@virebent.art dd34d8b7f010229bb790a2402c9ffe65 4:0.2c M 2026-10-17 2026-10-31"
	yamnLine   = "yamn yamn@mixmin.net 47c15db37d0d840b1f5ad4274384be22 4:0.2.7 E 2026-10-18 2026-10-23"
	yamn4Line  = "yamn4 yamn4@mixmin.net 97e043d6925403e32ed7bfe9a23e270e 4:0.2.7 M 2026-10-19 2026-11-02"
)

func date(s string) civil.Date {
	d, err := civil.Parse(s)
	if err != nil {
		panic(err)
	}
	return d
}

// pk makes a ParsedKey from a summary line; PK is the keyid twice.
func pk(line string) replies.ParsedKey {
	f := strings.Fields(line)
	if len(f) != 7 {
		panic("bad line " + line)
	}
	p := replies.ParsedKey{SummaryLine: replies.SummaryLine{
		Nick: f[0], Address: f[1], KeyID: f[2], Version: f[3], Caps: f[4],
		Created: date(f[5]), Expires: date(f[6]),
	}}
	b, _ := hex.DecodeString(f[2])
	copy(p.PK[:], b)
	copy(p.PK[16:], b)
	return p
}

// key makes a stored key from a summary line.
func key(line string, seen time.Time, state string) *store.Key {
	p := pk(line)
	return &store.Key{
		KeyID: p.KeyID, Nick: p.Nick, Address: p.Address, Version: p.Version, Caps: p.Caps,
		Created: p.Created, Expires: p.Expires, PK: store.PublicKey(p.PK),
		FirstSeen: seen, LastSeen: seen, LastReceived: seen.Add(time.Minute), Sightings: 1, State: state,
	}
}

// newState returns the three remailers, unpinned and without keys.
func newState() *store.State {
	st := &store.State{Version: store.StateVersion, Remailers: map[string]*store.Remailer{}}
	for _, a := range []string{"yamn@virebent.art", "yamn@mixmin.net", "yamn4@mixmin.net"} {
		if _, err := st.AddRemailer(a, now.Add(-30*24*time.Hour)); err != nil {
			panic(err)
		}
	}
	return st
}

// pinned returns newState with nicks pinned and the live keys stored,
// active, last seen tok.
func pinned(tok time.Time) *store.State {
	st := newState()
	for _, l := range []string{victorLine, yamnLine, yamn4Line} {
		k := key(l, tok, store.KeyStateActive)
		rem := st.Remailers[k.Address]
		rem.Nick = k.Nick
		rem.Keys = map[string]*store.Key{k.KeyID: k}
	}
	return st
}

func hasResult(res []Result, keyid string, d Decision, reason string) bool {
	for _, r := range res {
		if r.KeyID == keyid && r.Decision == d && strings.Contains(r.Reason, reason) {
			return true
		}
	}
	return false
}

func TestValid(t *testing.T) {
	k := key(yamnLine, now, store.KeyStateRejected) // State doesn't matter
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{
		{date("2026-10-18").Start().Add(-time.Nanosecond), false},
		{date("2026-10-18").Start(), true},
		{now, true},
		{date("2026-10-24").Start().Add(-time.Nanosecond), true},
		{date("2026-10-24").Start(), false},
	} {
		if got := Valid(k, tc.at); got != tc.want {
			t.Errorf("Valid at %s = %v", tc.at, got)
		}
	}
	if Valid(&store.Key{}, now) {
		t.Error("key without dates is valid")
	}
}

func TestSameAddress(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"yamn@mixmin.net", "yamn@mixmin.net", true},
		{"yamn@mixmin.net", "yamn@MixMin.NET", true},
		{"Yamn@mixmin.net", "yamn@mixmin.net", false},
		{"yamn@mixmin.net", "yamn4@mixmin.net", false},
		{"yamn", "yamn", false},
	} {
		if got := SameAddress(tc.a, tc.b); got != tc.want {
			t.Errorf("SameAddress(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

func TestCheckKey(t *testing.T) {
	rem := &store.Remailer{Address: "yamn@mixmin.net"}
	today := civil.Of(now) // 2026-10-22
	line := func(nick, addr, created, expires string) replies.ParsedKey {
		return pk(nick + " " + addr + " 47c15db37d0d840b1f5ad4274384be22 4:0.2.7 E " + created + " " + expires)
	}
	for _, tc := range []struct {
		name string
		p    replies.ParsedKey
		err  string // "" = ok
	}{
		{"live", pk(yamnLine), ""},
		{"today is created", line("yamn", "yamn@mixmin.net", "2026-10-22", "2026-11-05"), ""},
		{"today is expires", line("yamn", "yamn@mixmin.net", "2026-10-08", "2026-10-22"), ""},
		{"created tomorrow", line("yamn", "yamn@mixmin.net", "2026-10-23", "2026-11-05"), "after today"},
		{"expired yesterday", line("yamn", "yamn@mixmin.net", "2026-10-07", "2026-10-21"), "expired"},
		{"expires on created", line("yamn", "yamn@mixmin.net", "2026-10-22", "2026-10-22"), "not after created"},
		{"400 days", line("yamn", "yamn@mixmin.net", "2026-10-22", "2027-11-26"), ""},
		{"401 days", line("yamn", "yamn@mixmin.net", "2026-10-22", "2027-11-27"), "more than 400 days"},
		{"domain case", line("yamn", "yamn@MIXMIN.net", "2026-10-18", "2026-10-23"), ""},
		{"local part case", line("yamn", "Yamn@mixmin.net", "2026-10-18", "2026-10-23"), "is not yamn@mixmin.net"},
		{"other address", line("yamn", "yamn4@mixmin.net", "2026-10-18", "2026-10-23"), "is not yamn@mixmin.net"},
		{"upper-case nick", line("Yamn", "yamn@mixmin.net", "2026-10-18", "2026-10-23"), "bad nick"},
	} {
		err := CheckKey(tc.p, rem, today)
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}
	}
}

func TestPublishable(t *testing.T) {
	proven := now.Add(-time.Hour)
	mk := func(id, created, expires string, seen time.Time, state string, proven time.Time) *store.Key {
		k := key("yamn yamn@mixmin.net "+id+" 4:0.2.7 E "+created+" "+expires, seen, state)
		k.ProvenAt = proven
		return k
	}
	t0 := now.Add(-2 * time.Hour)
	t1 := now.Add(-time.Hour)
	const a, b = "aaaa0000000000000000000000000000", "bbbb0000000000000000000000000000"
	for _, tc := range []struct {
		name         string
		keys         []*store.Key
		requireProof bool
		want         string // keyid, "" = none
	}{
		{"last seen first", []*store.Key{
			mk(a, "2026-10-20", "2026-11-03", t1, "active", proven),
			mk(b, "2026-10-21", "2026-11-04", t0, "active", proven)}, true, a},
		{"then created", []*store.Key{
			mk(a, "2026-10-20", "2026-11-04", t1, "active", proven),
			mk(b, "2026-10-21", "2026-11-03", t1, "active", proven)}, true, b},
		{"then expires", []*store.Key{
			mk(a, "2026-10-20", "2026-11-03", t1, "active", proven),
			mk(b, "2026-10-20", "2026-11-04", t1, "active", proven)}, true, b},
		{"then keyid", []*store.Key{
			mk(b, "2026-10-20", "2026-11-03", t1, "active", proven),
			mk(a, "2026-10-20", "2026-11-03", t1, "active", proven)}, true, a},
		{"unproven skipped", []*store.Key{
			mk(a, "2026-10-20", "2026-11-03", t1, "active", time.Time{}),
			mk(b, "2026-10-19", "2026-11-03", t0, "active", proven)}, true, b},
		{"proof not required", []*store.Key{
			mk(a, "2026-10-20", "2026-11-03", t1, "active", time.Time{}),
			mk(b, "2026-10-19", "2026-11-03", t0, "active", proven)}, false, a},
		{"quarantined skipped", []*store.Key{
			mk(a, "2026-10-20", "2026-11-03", t1, "quarantined", proven),
			mk(b, "2026-10-19", "2026-11-03", t0, "active", proven)}, true, b},
		{"expired skipped", []*store.Key{
			mk(a, "2026-10-08", "2026-10-21", t1, "active", proven),
			mk(b, "2026-10-19", "2026-11-03", t0, "active", proven)}, true, b},
		{"none", []*store.Key{mk(a, "2026-10-20", "2026-11-03", t1, "rejected", proven)}, true, ""},
	} {
		rem := &store.Remailer{Address: "yamn@mixmin.net", Nick: "yamn", Keys: map[string]*store.Key{}}
		for _, k := range tc.keys {
			rem.Keys[k.KeyID] = k
		}
		got := ""
		if k := Publishable(rem, now, tc.requireProof); k != nil {
			got = k.KeyID
		}
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}

	// the pins are checked again
	rem := &store.Remailer{Address: "yamn@mixmin.net", Nick: "yamn", Keys: map[string]*store.Key{}}
	k := mk(a, "2026-10-20", "2026-11-03", t1, "active", proven)
	rem.Keys[a] = k
	k.Nick = "other"
	if Publishable(rem, now, true) != nil {
		t.Error("published a key with another nick")
	}
	k.Nick, k.Address = "yamn", "yamn@elsewhere.net"
	if Publishable(rem, now, true) != nil {
		t.Error("published a key with another address")
	}
	k.Address, rem.Nick = "yamn@mixmin.net", ""
	if Publishable(rem, now, true) != nil {
		t.Error("published a key of an unpinned remailer")
	}
}

func TestPingable(t *testing.T) {
	rem := &store.Remailer{Address: "yamn@mixmin.net", Nick: "yamn", Keys: map[string]*store.Key{}}
	add := func(id, expires string, seen time.Time, state string) {
		rem.Keys[id] = key("yamn yamn@mixmin.net "+id+" 4:0.2.7 E 2026-10-18 "+expires, seen, state)
	}
	ret := cfg.Retention
	add("a0000000000000000000000000000000", "2026-10-23", now.Add(-time.Hour), store.KeyStateActive)
	add("b0000000000000000000000000000000", "2026-11-05", now.Add(-time.Minute), store.KeyStateQuarantined)
	add("c0000000000000000000000000000000", "2026-11-05", now, store.KeyStateRejected)
	add("d0000000000000000000000000000000", "2026-10-21", now, store.KeyStateActive)           // expired
	add("e0000000000000000000000000000000", "2026-11-05", now.Add(-ret), store.KeyStateActive) // just inside
	add("f0000000000000000000000000000000", "2026-11-05", now.Add(-ret-time.Second), store.KeyStateActive)
	var got []string
	for _, k := range Pingable(rem, now, ret) {
		got = append(got, k.KeyID[:1])
	}
	if strings.Join(got, "") != "bae" {
		t.Errorf("Pingable = %v, want b a e", got)
	}
}

func TestSetProven(t *testing.T) {
	k := key(yamnLine, now, store.KeyStateActive)
	if !SetProven(k, now) || SetProven(k, now.Add(time.Hour)) || !k.ProvenAt.Equal(now) {
		t.Errorf("ProvenAt = %s", k.ProvenAt)
	}
}

func TestMarkNotARemailer(t *testing.T) {
	st := newState()
	rem := st.Remailers["yamn@mixmin.net"]
	MarkNotARemailer(rem)
	if rem.PingIt || rem.Fetch || !rem.ShowIt || rem.Status != store.StatusNotARemailer {
		t.Errorf("%+v", rem)
	}
	// a later valid reply doesn't turn it back on
	ApplyKeyReply(st, rem, []replies.ParsedKey{pk(yamnLine)}, now, now, now, cfg)
	if rem.Status != store.StatusNotARemailer || rem.PingIt {
		t.Errorf("after a reply: %+v", rem)
	}
}

func TestTTL(t *testing.T) {
	rem := &store.Remailer{Status: store.StatusActive, TTL: 2, ResurrectionTTL: 1}
	if DecreaseTTL(rem) || rem.Status != store.StatusActive {
		t.Fatalf("TTL 1: %+v", rem)
	}
	if !DecreaseTTL(rem) || rem.Status != store.StatusTTLTimeout || rem.ResurrectionTTL != store.DefaultResurrectionTTL {
		t.Fatalf("TTL 0: %+v", rem)
	}
	for i := 1; i < store.DefaultResurrectionTTL; i++ {
		if DecreaseResurrectionTTL(rem) {
			t.Fatalf("dead early: %+v", rem)
		}
	}
	if !DecreaseResurrectionTTL(rem) || rem.Status != store.StatusDead {
		t.Fatalf("not dead: %+v", rem)
	}
	if DecreaseResurrectionTTL(rem) {
		t.Fatal("changed a dead remailer")
	}
	if !RestoreTTL(rem) || rem.Status != store.StatusActive || rem.TTL != store.DefaultTTL || rem.ResurrectionTTL != store.DefaultResurrectionTTL {
		t.Fatalf("restore: %+v", rem)
	}
	rem.Status, rem.TTL = store.StatusDisabled, 0
	if RestoreTTL(rem) || rem.Status != store.StatusDisabled || rem.TTL != store.DefaultTTL {
		t.Fatalf("restore disabled: %+v", rem)
	}
}

func TestResultString(t *testing.T) {
	r := Result{Address: "yamn@mixmin.net", KeyID: "47c1", Decision: Quarantined, Reason: "why"}
	if s := r.String(); s != "yamn@mixmin.net key 47c1: quarantined: why" {
		t.Error(s)
	}
	if s := (Result{Address: "a@b", Decision: Seen}).String(); s != "a@b: seen" {
		t.Error(s)
	}
}
