package keys

import (
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

const (
	// new keys, made up
	yamnNext   = "yamn yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05"
	victorNext = "victor yamn@virebent.art 0a1b2c3d4e5f60718293a4b5c6d7e8f9 4:0.2c M 2026-10-22 2026-11-05"
)

func apply(st *store.State, addr string, tok time.Time, lines ...string) []Result {
	var ks []replies.ParsedKey
	for _, l := range lines {
		ks = append(ks, pk(l))
	}
	return ApplyKeyReply(st, st.Remailers[addr], ks, tok, tok.Add(5*time.Minute), now, cfg)
}

func findPending(st *store.State, addr, kind, new string) *store.PendingChange {
	for i := range st.Pending {
		pc := &st.Pending[i]
		if pc.Address == addr && pc.Kind == kind && pc.New == new {
			return pc
		}
	}
	return nil
}

func TestFirstKeyTOFU(t *testing.T) {
	st := newState()
	rem := st.Remailers["yamn@mixmin.net"]
	rem.Status, rem.TTL, rem.ResurrectionTTL = store.StatusTTLTimeout, 0, 3
	tok := now.Add(-time.Hour)
	res := apply(st, "yamn@mixmin.net", tok, yamnLine)
	k := rem.Keys["47c15db37d0d840b1f5ad4274384be22"]
	if k == nil || k.State != store.KeyStateActive || rem.Nick != "yamn" {
		t.Fatalf("key %+v nick %q: %v", k, rem.Nick, res)
	}
	if !k.FirstSeen.Equal(tok) || !k.LastSeen.Equal(tok) || !k.LastReceived.Equal(tok.Add(5*time.Minute)) || k.Sightings != 1 {
		t.Errorf("times: %+v", k)
	}
	if !hasResult(res, k.KeyID, Accepted, "first key") || !hasResult(res, "", Accepted, "pinned") {
		t.Errorf("results: %v", res)
	}
	if rem.Status != store.StatusActive || rem.TTL != store.DefaultTTL || rem.ResurrectionTTL != store.DefaultResurrectionTTL {
		t.Errorf("not restored: %+v", rem)
	}
	if len(st.Pending) != 0 {
		t.Errorf("pending: %v", st.Pending)
	}
}

func TestNewKey(t *testing.T) {
	seen := now.Add(-3 * time.Hour)
	tok := now.Add(-time.Hour)
	for _, tc := range []struct {
		name    string
		setup   func(st *store.State)
		addr    string
		line    string
		want    Decision
		reason  string
		pending []string // kind:old:new
	}{
		{name: "rotation inside the window", addr: "yamn@mixmin.net", line: yamnNext,
			want: Rotation, reason: "current key 47c15db37d0d840b1f5ad4274384be22 expires 2026-10-23"},
		{name: "outside the window (self-check: key not in secring)", addr: "yamn@virebent.art", line: victorNext,
			want: Quarantined, reason: "is valid for another",
			pending: []string{"key:dd34d8b7f010229bb790a2402c9ffe65:0a1b2c3d4e5f60718293a4b5c6d7e8f9"}},
		{name: "current key already expired", addr: "yamn@virebent.art", line: victorNext,
			setup: func(st *store.State) {
				k := st.Remailers["yamn@virebent.art"].Keys["dd34d8b7f010229bb790a2402c9ffe65"]
				k.Created, k.Expires = date("2026-10-07"), date("2026-10-21")
			},
			want: Accepted, reason: "no valid key"},
		{name: "current key quarantined only", addr: "yamn@virebent.art", line: victorNext,
			setup: func(st *store.State) {
				st.Remailers["yamn@virebent.art"].Keys["dd34d8b7f010229bb790a2402c9ffe65"].State = store.KeyStateQuarantined
			},
			want: Accepted, reason: "no valid key"},
		{name: "created before the current key", addr: "yamn@mixmin.net",
			line: "yamn yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-17 2026-10-31",
			want: Quarantined, reason: "created 2026-10-17 before the current key",
			pending: []string{"key:47c15db37d0d840b1f5ad4274384be22:5f1e0d2c3b4a59687766554433221100"}},
		{name: "self-check: name with another address", addr: "yamn4@mixmin.net",
			line: "yamn yamn4@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 M 2026-10-22 2026-11-05",
			want: Quarantined, reason: "nick yamn is pinned to yamn@mixmin.net",
			pending: []string{
				"nick:yamn4:yamn",
				"key:97e043d6925403e32ed7bfe9a23e270e:5f1e0d2c3b4a59687766554433221100"}},
		{name: "self-check: address under another name", addr: "yamn@mixmin.net",
			line: "mixmin yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05",
			want: Quarantined, reason: "nick mixmin is not the pinned nick yamn",
			pending: []string{"nick:yamn:mixmin"}},
		{name: "13-character nick on an unpinned remailer", addr: "yamn@mixmin.net",
			setup: func(st *store.State) {
				rem := st.Remailers["yamn@mixmin.net"]
				rem.Nick, rem.Keys = "", nil
			},
			line: "abcdefghijklm yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05",
			want: Quarantined, reason: "longer than 12 characters",
			pending: []string{"nick::abcdefghijklm"}},
		{name: "12-character nick on an unpinned remailer", addr: "yamn@mixmin.net",
			setup: func(st *store.State) {
				rem := st.Remailers["yamn@mixmin.net"]
				rem.Nick, rem.Keys = "", nil
			},
			line: "abcdefghijkl yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05",
			want: Accepted, reason: "first key"},
		{name: "nick taken, unpinned remailer", addr: "yamn4@mixmin.net",
			setup: func(st *store.State) {
				rem := st.Remailers["yamn4@mixmin.net"]
				rem.Nick, rem.Keys = "", nil
			},
			line: "victor yamn4@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 M 2026-10-22 2026-11-05",
			want: Quarantined, reason: "nick victor is pinned to yamn@virebent.art",
			pending: []string{"nick::victor"}},
		{name: "fails CheckKey", addr: "yamn@mixmin.net",
			line: "yamn yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-07 2026-10-21",
			want: Rejected, reason: "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := pinned(seen)
			if tc.setup != nil {
				tc.setup(st)
			}
			rem := st.Remailers[tc.addr]
			oldNick := rem.Nick
			res := apply(st, tc.addr, tok, tc.line)
			p := pk(tc.line)
			if !hasResult(res, p.KeyID, tc.want, tc.reason) {
				t.Fatalf("want %s %q, got %v", tc.want, tc.reason, res)
			}
			k := rem.Keys[p.KeyID]
			switch tc.want {
			case Rejected:
				if k != nil {
					t.Errorf("stored a rejected key")
				}
			case Quarantined:
				if k == nil || k.State != store.KeyStateQuarantined {
					t.Errorf("key %+v", k)
				}
				if rem.Nick != oldNick {
					t.Errorf("nick changed to %q", rem.Nick)
				}
			default:
				if k == nil || k.State != store.KeyStateActive || rem.Nick != p.Nick {
					t.Errorf("key %+v nick %q", k, rem.Nick)
				}
			}
			var got []string
			for _, pc := range st.Pending {
				got = append(got, pc.Kind+":"+pc.Old+":"+pc.New)
				if !pc.Since.Equal(now) {
					t.Errorf("Since %s", pc.Since)
				}
			}
			if len(got) != len(tc.pending) {
				t.Fatalf("pending %v, want %v", got, tc.pending)
			}
			for i := range got {
				if got[i] != tc.pending[i] {
					t.Errorf("pending %v, want %v", got, tc.pending)
				}
			}
		})
	}
}

func TestKnownKey(t *testing.T) {
	seen := now.Add(-3 * time.Hour)
	const id = "47c15db37d0d840b1f5ad4274384be22"
	st := pinned(seen)
	rem := st.Remailers["yamn@mixmin.net"]
	k := rem.Keys[id]

	// replays: same and older token time
	for _, tok := range []time.Time{seen, seen.Add(-time.Hour)} {
		res := apply(st, rem.Address, tok, yamnLine)
		if !hasResult(res, id, Ignored, "replay") || k.Sightings != 1 || !k.LastSeen.Equal(seen) {
			t.Errorf("replay at %s: %v %+v", tok, res, k)
		}
	}
	// 20 min later: seen, not a new sighting
	res := apply(st, rem.Address, seen.Add(20*time.Minute), yamnLine)
	if !hasResult(res, id, Seen, "") || k.Sightings != 1 || !k.LastSeen.Equal(seen.Add(20*time.Minute)) {
		t.Errorf("20 min: %v %+v", res, k)
	}
	// 29 min after the first: still one
	apply(st, rem.Address, seen.Add(29*time.Minute), yamnLine)
	if k.Sightings != 1 {
		t.Errorf("29 min: %d sightings", k.Sightings)
	}
	// 30 min after the first counted one, though only 1 min after the last
	// reply: two
	apply(st, rem.Address, seen.Add(30*time.Minute), yamnLine)
	if k.Sightings != 2 || !k.SightedAt.Equal(seen.Add(30*time.Minute)) {
		t.Errorf("30 min: %+v", k)
	}
	// replies every 10 min: one sighting per 30 min
	for m := 40; m <= 90; m += 10 {
		apply(st, rem.Address, seen.Add(time.Duration(m)*time.Minute), yamnLine)
	}
	if k.Sightings != 4 || !k.LastReceived.Equal(seen.Add(95*time.Minute)) {
		t.Errorf("90 min: %+v", k)
	}

	// version and caps follow yamn's config
	apply(st, rem.Address, seen.Add(3*time.Hour), "yamn yamn@mixmin.net "+id+" 4:0.2.8 M 2026-10-18 2026-10-23")
	if k.Version != "4:0.2.8" || k.Caps != "M" || k.State != store.KeyStateActive {
		t.Errorf("update: %+v", k)
	}
	// dates never change
	res = apply(st, rem.Address, seen.Add(4*time.Hour), "yamn yamn@mixmin.net "+id+" 4:0.2.8 M 2026-10-18 2026-10-30")
	if !hasResult(res, id, Rejected, "differ") || k.Expires != date("2026-10-23") {
		t.Errorf("dates: %v %+v", res, k)
	}
	// the same key under another nick: a nick change; the key isn't touched
	last := k.LastSeen
	res = apply(st, rem.Address, seen.Add(5*time.Hour), "mixmin yamn@mixmin.net "+id+" 4:0.2.8 M 2026-10-18 2026-10-23")
	if !hasResult(res, id, Quarantined, "not the pinned nick") || k.Nick != "yamn" || !k.LastSeen.Equal(last) ||
		findPending(st, rem.Address, store.PendingNickChange, "mixmin") == nil {
		t.Errorf("nick: %v %+v %v", res, k, st.Pending)
	}
	// a rejected key stays rejected
	k.State = store.KeyStateRejected
	res = apply(st, rem.Address, seen.Add(6*time.Hour), yamnLine)
	if !hasResult(res, id, Rejected, "by the operator") || k.State != store.KeyStateRejected || !k.LastSeen.Equal(seen.Add(6*time.Hour)) {
		t.Errorf("rejected: %v %+v", res, k)
	}
}

func TestTwoKeysInOneReply(t *testing.T) {
	// the older is applied first, whatever the order in the reply
	st := newState()
	res := apply(st, "yamn@mixmin.net", now.Add(-time.Hour), yamnNext, yamnLine)
	if !hasResult(res, "47c15db37d0d840b1f5ad4274384be22", Accepted, "first key") ||
		!hasResult(res, "5f1e0d2c3b4a59687766554433221100", Rotation, "") || len(st.Pending) != 0 {
		t.Errorf("%v", res)
	}
}

func TestQuarantinedKeySightings(t *testing.T) {
	st := pinned(now.Add(-3 * time.Hour))
	tok := now.Add(-2 * time.Hour)
	apply(st, "yamn@virebent.art", tok, victorNext)
	res := apply(st, "yamn@virebent.art", tok.Add(time.Hour), victorNext)
	k := st.Remailers["yamn@virebent.art"].Keys[pk(victorNext).KeyID]
	if k.Sightings != 2 || k.State != store.KeyStateQuarantined || !hasResult(res, k.KeyID, Quarantined, "2 sightings") {
		t.Errorf("%v %+v", res, k)
	}
	if len(st.Pending) != 1 {
		t.Errorf("duplicate pending: %v", st.Pending)
	}
}

func TestNickChangeSightings(t *testing.T) {
	st := pinned(now.Add(-3 * time.Hour))
	const line = "mixmin yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05"
	tok := now.Add(-2 * time.Hour)
	apply(st, "yamn@mixmin.net", tok, line)
	apply(st, "yamn@mixmin.net", tok.Add(10*time.Minute), line) // not 30 min apart
	pc := findPending(st, "yamn@mixmin.net", store.PendingNickChange, "mixmin")
	if pc == nil || pc.Sightings != 1 || !pc.LastSeen.Equal(tok.Add(10*time.Minute)) {
		t.Fatalf("%+v", pc)
	}
	apply(st, "yamn@mixmin.net", tok.Add(30*time.Minute), line) // 20 min after the last reply, 30 after the first
	if pc.Sightings != 2 {
		t.Errorf("%+v", pc)
	}
	// the old nick seen again
	apply(st, "yamn@mixmin.net", tok.Add(90*time.Minute), yamnLine)
	if !pc.OldSeen.Equal(tok.Add(90 * time.Minute)) {
		t.Errorf("OldSeen %s", pc.OldSeen)
	}
	if len(st.Pending) != 1 { // the key itself is a normal rotation
		t.Errorf("%v", st.Pending)
	}
}

func TestOtherAddresses(t *testing.T) {
	st := pinned(now.Add(-3 * time.Hour))
	res := apply(st, "yamn@virebent.art", now.Add(-time.Hour),
		"frell frell@frell.eu.org 1234567890abcdef1234567890abcdef 4:0.2.7 M 2026-10-20 2026-11-03",
		yamn4Line)
	if !hasResult(res, "", Suggested, "key reply of victor") ||
		!hasResult(res, "97e043d6925403e32ed7bfe9a23e270e", Ignored, "key reply of victor") {
		t.Errorf("%v", res)
	}
	s := st.Prospective["frell@frell.eu.org"]
	if len(s) != 1 || s[0].Source != "victor" || !s[0].Time.Equal(now) {
		t.Errorf("suggestions %v", st.Prospective)
	}
	if len(st.Remailers) != 3 || len(st.Remailers["yamn@virebent.art"].Keys) != 1 || len(st.Remailers["yamn4@mixmin.net"].Keys) != 1 {
		t.Error("stored a key for another address")
	}
	// the same suggestion again only updates its time
	ApplyKeyReply(st, st.Remailers["yamn@virebent.art"],
		[]replies.ParsedKey{pk("frell frell@FRELL.eu.org 1234567890abcdef1234567890abcdef 4:0.2.7 M 2026-10-20 2026-11-03")},
		now, now, now.Add(time.Hour), cfg)
	s = st.Prospective["frell@frell.eu.org"]
	if len(s) != 1 || !s[0].Time.Equal(now.Add(time.Hour)) || len(st.Prospective) != 1 {
		t.Errorf("suggestions %v", st.Prospective)
	}
}

func TestStatusRestore(t *testing.T) {
	for _, tc := range []struct{ from, want string }{
		{store.StatusTTLTimeout, store.StatusActive},
		{store.StatusDead, store.StatusActive},
		{store.StatusDisabled, store.StatusDisabled},
		{store.StatusNotARemailer, store.StatusNotARemailer},
	} {
		st := pinned(now.Add(-3 * time.Hour))
		rem := st.Remailers["yamn@mixmin.net"]
		rem.Status, rem.TTL = tc.from, -1
		apply(st, rem.Address, now.Add(-time.Hour), yamnLine)
		if rem.Status != tc.want || rem.TTL != store.DefaultTTL {
			t.Errorf("%s: %s ttl %d", tc.from, rem.Status, rem.TTL)
		}
	}
	// a replay isn't a sign of life
	st := pinned(now.Add(-3 * time.Hour))
	rem := st.Remailers["yamn@mixmin.net"]
	rem.Status, rem.TTL = store.StatusTTLTimeout, 0
	apply(st, rem.Address, now.Add(-3*time.Hour), yamnLine)
	if rem.Status != store.StatusTTLTimeout || rem.TTL != 0 {
		t.Errorf("replay restored: %+v", rem)
	}
}

func conf(nick, addr string, supported ...string) *replies.ConfReply {
	c := &replies.ConfReply{
		Type: "Mixmaster 4:0.2.7", Nick: nick, Address: addr, Options: "middle v2",
		Caps: `$remailer{"` + nick + `"} = "<` + addr + `> middle v2";`,
	}
	for _, l := range supported {
		c.Supported = append(c.Supported, pk(l).SummaryLine)
	}
	return c
}

func TestApplyConfReply(t *testing.T) {
	st := newState()
	rem := st.Remailers["yamn4@mixmin.net"]
	tok := now.Add(-time.Hour)
	res := ApplyConfReply(st, rem, conf("yamn4", "yamn4@mixmin.net", victorLine, yamn4Line,
		"frell frell@frell.eu.org 1234567890abcdef1234567890abcdef 4:0.2.7 M 2026-10-20 2026-11-03"),
		tok, tok.Add(time.Minute), now, cfg)
	if rem.Nick != "yamn4" || rem.Conf == nil || !rem.Conf.LastUpdate.Equal(tok) || !rem.Conf.Received.Equal(tok.Add(time.Minute)) ||
		rem.Conf.Type != "Mixmaster 4:0.2.7" || !hasResult(res, "", Accepted, "conf") {
		t.Fatalf("%v %+v", res, rem.Conf)
	}
	if s := st.Prospective["frell@frell.eu.org"]; len(s) != 1 || s[0].Source != "yamn4" || s[0].Reason != "supported by yamn4" || len(st.Prospective) != 1 {
		t.Errorf("suggestions %v", st.Prospective)
	}

	// replay
	res = ApplyConfReply(st, rem, conf("other", "yamn4@mixmin.net"), tok, now, now, cfg)
	if !hasResult(res, "", Ignored, "replay") || len(st.Pending) != 0 {
		t.Errorf("replay: %v", res)
	}

	// DontExpire survives an update
	rem.Conf.DontExpire = true
	ApplyConfReply(st, rem, conf("yamn4", "yamn4@mixmin.net"), tok.Add(time.Hour), now, now, cfg)
	if !rem.Conf.DontExpire || !rem.Conf.LastUpdate.Equal(tok.Add(time.Hour)) {
		t.Errorf("%+v", rem.Conf)
	}

	// another nick: pending, conf not stored
	res = ApplyConfReply(st, rem, conf("mix4", "yamn4@mixmin.net"), tok.Add(2*time.Hour), now, now, cfg)
	if !hasResult(res, "", Quarantined, "not the pinned nick") || rem.Conf.Nick != "yamn4" || rem.Nick != "yamn4" ||
		findPending(st, rem.Address, store.PendingNickChange, "mix4") == nil {
		t.Errorf("nick: %v %+v", res, rem.Conf)
	}

	// another address: pending, nothing applied
	rem.Status = store.StatusDead
	res = ApplyConfReply(st, rem, conf("yamn4", "yamn5@mixmin.net"), tok.Add(3*time.Hour), now, now, cfg)
	pc := findPending(st, rem.Address, store.PendingAddressChange, "yamn5@mixmin.net")
	if !hasResult(res, "", Quarantined, "names the address yamn5@mixmin.net") || pc == nil || pc.Old != "yamn4@mixmin.net" ||
		rem.Address != "yamn4@mixmin.net" || st.Remailers["yamn5@mixmin.net"] != nil || !rem.Conf.LastUpdate.Equal(tok.Add(time.Hour)) {
		t.Errorf("address: %v %+v", res, pc)
	}
	if rem.Status != store.StatusActive {
		t.Errorf("status %s", rem.Status)
	}
	// the old address seen again
	ApplyConfReply(st, rem, conf("yamn4", "yamn4@mixmin.net"), tok.Add(4*time.Hour), now, now, cfg)
	if !pc.OldSeen.Equal(tok.Add(4 * time.Hour)) {
		t.Errorf("OldSeen %s", pc.OldSeen)
	}

	// a nick taken by another remailer, and a long one
	st = pinned(tok)
	rem = st.Remailers["yamn4@mixmin.net"]
	res = ApplyConfReply(st, rem, conf("yamn", "yamn4@mixmin.net"), now, now, now, cfg)
	if !hasResult(res, "", Quarantined, "pinned to yamn@mixmin.net") || rem.Conf != nil {
		t.Errorf("taken: %v", res)
	}
	res = ApplyConfReply(st, rem, conf("abcdefghijklm", "yamn4@mixmin.net"), now, now, now, cfg)
	if !hasResult(res, "", Quarantined, "longer than 12") || rem.Conf != nil {
		t.Errorf("long: %v", res)
	}
	if ApplyConfReply(st, rem, nil, now, now, now, cfg) != nil {
		t.Error("nil conf")
	}
}

func TestSightingsFrequentReplies(t *testing.T) {
	// a quarantined key in replies every 5 min, as on the testnet: one
	// sighting per 30 min, not stuck at one
	st := pinned(now.Add(-3 * time.Hour))
	tok := now.Add(-2 * time.Hour)
	for m := 0; m <= 60; m += 5 {
		apply(st, "yamn@virebent.art", tok.Add(time.Duration(m)*time.Minute), victorNext)
	}
	k := st.Remailers["yamn@virebent.art"].Keys[pk(victorNext).KeyID]
	if k.Sightings != 3 {
		t.Errorf("%d sightings, want 3", k.Sightings)
	}

	// state written before SightedAt: the first sighting is FirstSeen
	k.Sightings, k.SightedAt, k.LastSeen = 1, time.Time{}, tok.Add(60*time.Minute)
	apply(st, "yamn@virebent.art", tok.Add(65*time.Minute), victorNext)
	if k.Sightings != 2 || !k.SightedAt.Equal(tok.Add(65*time.Minute)) {
		t.Errorf("old state: %+v", k)
	}
}
