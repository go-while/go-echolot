package keys

import (
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// applyAt applies a key reply with token time tok, processed at at.
func applyAt(st *store.State, addr string, tok, at time.Time, lines ...string) []Result {
	var ks []replies.ParsedKey
	for _, l := range lines {
		ks = append(ks, pk(l))
	}
	return ApplyKeyReply(st, st.Remailers[addr], ks, tok, tok.Add(5*time.Minute), at, cfg)
}

const victorNextID = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"

func TestResolvePendingKey(t *testing.T) {
	// victor's key has 8 days left; the new one is quarantined at now
	setup := func() *store.State {
		st := pinned(now.Add(-3 * time.Hour))
		applyAt(st, "yamn@virebent.art", now.Add(-time.Hour), now, victorNext)
		return st
	}
	victor := func(st *store.State) *store.Key { return st.Remailers["yamn@virebent.art"].Keys[victorNextID] }

	st := setup()
	if res := ResolvePending(st, now.Add(23*time.Hour), cfg); !hasResult(res, victorNextID, Waiting, "in quarantine until") {
		t.Errorf("too early: %v", res)
	}
	if res := ResolvePending(st, now.Add(25*time.Hour), cfg); !hasResult(res, victorNextID, Waiting, "1 of 2 sightings") {
		t.Errorf("one sighting: %v", res)
	}
	// a second sighting; then the old key is seen again
	applyAt(st, "yamn@virebent.art", now.Add(time.Hour), now.Add(time.Hour), victorNext)
	applyAt(st, "yamn@virebent.art", now.Add(2*time.Hour), now.Add(2*time.Hour), victorLine)
	if res := ResolvePending(st, now.Add(25*time.Hour), cfg); !hasResult(res, victorNextID, Waiting, "old key dd34d8b7f010229bb790a2402c9ffe65 seen again") {
		t.Errorf("old seen: %v", res)
	}
	if victor(st).State != store.KeyStateQuarantined || len(st.Pending) != 1 {
		t.Error("applied")
	}

	// the old key in a reply to a request sent before the change doesn't count
	st = setup()
	applyAt(st, "yamn@virebent.art", now.Add(-30*time.Minute), now.Add(time.Minute), victorLine)
	applyAt(st, "yamn@virebent.art", now.Add(time.Hour), now.Add(time.Hour), victorNext)
	res := ResolvePending(st, now.Add(25*time.Hour), cfg)
	if !hasResult(res, victorNextID, Applied, "is active") || victor(st).State != store.KeyStateActive || len(st.Pending) != 0 {
		t.Fatalf("success: %v %v", res, st.Pending)
	}
	// published once proven, as the most recently seen
	rem := st.Remailers["yamn@virebent.art"]
	SetProven(rem.Keys["dd34d8b7f010229bb790a2402c9ffe65"], now)
	if k := Publishable(rem, now.Add(25*time.Hour), true); k == nil || k.KeyID != "dd34d8b7f010229bb790a2402c9ffe65" {
		t.Errorf("published %v before proof", k)
	}
	SetProven(victor(st), now.Add(2*time.Hour))
	if k := Publishable(rem, now.Add(25*time.Hour), true); k == nil || k.KeyID != victorNextID {
		t.Errorf("published %v", k)
	}

	// a rejected or deleted key drops the change
	st = setup()
	victor(st).State = store.KeyStateRejected
	if res := ResolvePending(st, now.Add(time.Hour), cfg); !hasResult(res, victorNextID, Dropped, "rejected") || len(st.Pending) != 0 {
		t.Errorf("rejected: %v", res)
	}
	st = setup()
	delete(st.Remailers, "yamn@virebent.art")
	if res := ResolvePending(st, now.Add(time.Hour), cfg); !hasResult(res, victorNextID, Dropped, "remailer is gone") || len(st.Pending) != 0 {
		t.Errorf("gone: %v", res)
	}
}

func TestResolvePendingNick(t *testing.T) {
	// yamn@mixmin.net renames itself to mixmin with its next key, inside
	// the rotation window: only the nick waits
	const line = "mixmin yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05"
	st := pinned(now.Add(-3 * time.Hour))
	rem := st.Remailers["yamn@mixmin.net"]
	rem.Conf = &store.Conf{Nick: "yamn", LastUpdate: now}
	applyAt(st, rem.Address, now.Add(-time.Hour), now, line)
	if res := ResolvePending(st, now.Add(25*time.Hour), cfg); !hasResult(res, "", Waiting, "1 of 2") {
		t.Errorf("one sighting: %v", res)
	}
	applyAt(st, rem.Address, now.Add(time.Hour), now.Add(time.Hour), line)
	res := ResolvePending(st, now.Add(25*time.Hour), cfg)
	if !hasResult(res, "", Applied, `nick "yamn" -> mixmin`) || rem.Nick != "mixmin" || len(st.Pending) != 0 {
		t.Fatalf("%v %v", res, st.Pending)
	}
	if k := rem.Keys["5f1e0d2c3b4a59687766554433221100"]; k.State != store.KeyStateActive {
		t.Errorf("new key %+v", k)
	}
	if k := rem.Keys["47c15db37d0d840b1f5ad4274384be22"]; k.Nick != "mixmin" || k.State != store.KeyStateActive {
		t.Errorf("old key %+v", k)
	}
	if rem.Conf != nil {
		t.Error("conf with the old nick kept")
	}

	for _, tc := range []struct {
		name, addr, line, want string
		setup                  func(st *store.State)
	}{
		{name: "long nick", addr: "yamn@mixmin.net", want: "operator only",
			line: "abcdefghijklm yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05"},
		{name: "taken nick", addr: "yamn4@mixmin.net", want: "pinned to yamn@mixmin.net: operator only",
			line: "yamn yamn4@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 M 2026-10-22 2026-11-05"},
		{name: "old nick seen again", addr: "yamn@mixmin.net", want: "old nick yamn seen again",
			line: "mixmin yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05",
			setup: func(st *store.State) {
				applyAt(st, "yamn@mixmin.net", now.Add(2*time.Hour), now.Add(2*time.Hour), yamnLine)
			}},
	} {
		st := pinned(now.Add(-3 * time.Hour))
		applyAt(st, tc.addr, now.Add(-time.Hour), now, tc.line)
		applyAt(st, tc.addr, now.Add(time.Hour), now.Add(time.Hour), tc.line)
		if tc.setup != nil {
			tc.setup(st)
		}
		nick := st.Remailers[tc.addr].Nick
		res := ResolvePending(st, now.Add(48*time.Hour), cfg)
		if !hasResult(res, "", Waiting, tc.want) || st.Remailers[tc.addr].Nick != nick {
			t.Errorf("%s: %v", tc.name, res)
		}
	}

	// stale: the pinned nick changed meanwhile
	st = pinned(now.Add(-3 * time.Hour))
	applyAt(st, "yamn@mixmin.net", now.Add(-time.Hour), now,
		"mixmin yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05")
	st.Remailers["yamn@mixmin.net"].Nick = "other"
	if res := ResolvePending(st, now.Add(48*time.Hour), cfg); !hasResult(res, "", Dropped, "pinned nick is now") || len(st.Pending) != 0 {
		t.Errorf("stale: %v", res)
	}
}

func TestResolvePendingAddress(t *testing.T) {
	st := pinned(now.Add(-3 * time.Hour))
	rem := st.Remailers["yamn4@mixmin.net"]
	id := rem.ID
	ApplyConfReply(st, rem, conf("yamn4", "yamn5@mixmin.net"), now.Add(-time.Hour), now, now, cfg)
	ApplyConfReply(st, rem, conf("yamn4", "yamn5@mixmin.net"), now.Add(time.Hour), now, now.Add(time.Hour), cfg)
	st.Prospective = map[string][]store.Suggestion{"yamn5@mixmin.net": {{Time: now, Reason: "x", Source: "victor"}}}
	if res := ResolvePending(st, now.Add(23*time.Hour), cfg); !hasResult(res, "", Waiting, "quarantine") {
		t.Errorf("early: %v", res)
	}
	res := ResolvePending(st, now.Add(25*time.Hour), cfg)
	if !hasResult(res, "", Applied, "address yamn4@mixmin.net -> yamn5@mixmin.net") {
		t.Fatalf("%v", res)
	}
	if st.Remailers["yamn4@mixmin.net"] != nil || st.Remailers["yamn5@mixmin.net"] != rem || rem.ID != id ||
		rem.Address != "yamn5@mixmin.net" || rem.Conf != nil || st.Prospective["yamn5@mixmin.net"] != nil {
		t.Errorf("not moved: %+v", rem)
	}
	// keys keep the old address: not pinged or published until refreshed
	if len(Pingable(rem, now, cfg.Retention)) != 0 || Publishable(rem, now, false) != nil {
		t.Error("old-address key used")
	}
	applyAt(st, "yamn5@mixmin.net", now.Add(26*time.Hour), now.Add(26*time.Hour),
		"yamn4 yamn5@mixmin.net 97e043d6925403e32ed7bfe9a23e270e 4:0.2.7 M 2026-10-19 2026-11-02")
	if k := Publishable(rem, now.Add(26*time.Hour), false); k == nil || k.Address != "yamn5@mixmin.net" {
		t.Errorf("refreshed key %+v", k)
	}

	// an address that is known waits for the operator
	st = pinned(now.Add(-3 * time.Hour))
	rem = st.Remailers["yamn4@mixmin.net"]
	ApplyConfReply(st, rem, conf("yamn4", "yamn@mixmin.net"), now.Add(-time.Hour), now, now, cfg)
	ApplyConfReply(st, rem, conf("yamn4", "yamn@mixmin.net"), now.Add(time.Hour), now, now, cfg)
	if res := ResolvePending(st, now.Add(48*time.Hour), cfg); !hasResult(res, "", Waiting, "already known") {
		t.Errorf("known: %v", res)
	}
}

func TestApprove(t *testing.T) {
	st := pinned(now.Add(-3 * time.Hour))
	applyAt(st, "yamn@virebent.art", now.Add(-time.Hour), now, victorNext)
	res, err := Approve(st, "yamn@VIREBENT.art", victorNextID, now)
	if err != nil || !hasResult(res, victorNextID, Accepted, "approved by the operator: key") ||
		st.Remailers["yamn@virebent.art"].Keys[victorNextID].State != store.KeyStateActive || len(st.Pending) != 0 {
		t.Fatalf("%v %v", res, err)
	}

	// nick and key at once: yamn4 renames to mix4 with a key 14 days early
	const line = "mix4 yamn4@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 M 2026-10-22 2026-11-05"
	st = pinned(now.Add(-3 * time.Hour))
	rem := st.Remailers["yamn4@mixmin.net"]
	applyAt(st, rem.Address, now.Add(-time.Hour), now, line)
	if len(st.Pending) != 2 {
		t.Fatalf("%v", st.Pending)
	}
	if _, err := Approve(st, rem.Address, "key", now); err != nil {
		t.Fatal(err)
	}
	if k := rem.Keys["5f1e0d2c3b4a59687766554433221100"]; k.State != store.KeyStateQuarantined {
		t.Errorf("active before its nick: %+v", k)
	}
	if _, err := Approve(st, rem.Address, "mix4", now); err != nil {
		t.Fatal(err)
	}
	if k := rem.Keys["5f1e0d2c3b4a59687766554433221100"]; k.State != store.KeyStateActive || rem.Nick != "mix4" || len(st.Pending) != 0 {
		t.Errorf("after the nick: %+v %v", k, st.Pending)
	}

	// all at once
	st = pinned(now.Add(-3 * time.Hour))
	rem = st.Remailers["yamn4@mixmin.net"]
	applyAt(st, rem.Address, now.Add(-time.Hour), now, line)
	if res, err := Approve(st, rem.Address, "", now); err != nil || len(res) != 2 ||
		rem.Keys["5f1e0d2c3b4a59687766554433221100"].State != store.KeyStateActive {
		t.Errorf("all: %v %v", res, err)
	}

	// a taken nick and a known address can't be approved
	st = pinned(now.Add(-3 * time.Hour))
	rem = st.Remailers["yamn4@mixmin.net"]
	ApplyConfReply(st, rem, conf("yamn", "yamn4@mixmin.net"), now.Add(-time.Hour), now, now, cfg)
	if _, err := Approve(st, rem.Address, "yamn", now); err == nil || !strings.Contains(err.Error(), "pinned to yamn@mixmin.net") || rem.Nick != "yamn4" {
		t.Errorf("taken: %v", err)
	}
	ApplyConfReply(st, rem, conf("yamn4", "yamn@virebent.art"), now.Add(time.Hour), now, now, cfg)
	if _, err := Approve(st, rem.Address, "address", now); err == nil || !strings.Contains(err.Error(), "already known") {
		t.Errorf("known: %v", err)
	}
	if len(st.Pending) != 2 {
		t.Errorf("pending changed: %v", st.Pending)
	}

	// approving a key without a pending change; errors
	k := st.Remailers["yamn@mixmin.net"].Keys["47c15db37d0d840b1f5ad4274384be22"]
	k.State = store.KeyStateRejected
	if _, err := Approve(st, "yamn@mixmin.net", k.KeyID, now); err != nil || k.State != store.KeyStateActive {
		t.Errorf("rejected key: %v %+v", err, k)
	}
	if _, err := Approve(st, "yamn@mixmin.net", k.KeyID, now); err == nil {
		t.Error("approved an active key")
	}
	if _, err := Approve(st, "nobody@example.org", "", now); err == nil {
		t.Error("unknown remailer")
	}
}

func TestReject(t *testing.T) {
	st := pinned(now.Add(-3 * time.Hour))
	applyAt(st, "yamn@virebent.art", now.Add(-time.Hour), now, victorNext)
	rem := st.Remailers["yamn@virebent.art"]
	res, err := Reject(st, "yamn@virebent.art", "", now)
	if err != nil || !hasResult(res, victorNextID, Rejected, "by the operator") ||
		rem.Keys[victorNextID].State != store.KeyStateRejected || len(st.Pending) != 0 {
		t.Fatalf("%v %v", res, err)
	}
	if len(Pingable(rem, now, cfg.Retention)) != 1 {
		t.Error("rejected key pinged")
	}

	// a rejected nick is remembered
	const line = "mixmin yamn@mixmin.net 5f1e0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05"
	st = pinned(now.Add(-3 * time.Hour))
	rem = st.Remailers["yamn@mixmin.net"]
	applyAt(st, rem.Address, now.Add(-time.Hour), now, line)
	if _, err := Reject(st, rem.Address, "mixmin", now); err != nil {
		t.Fatal(err)
	}
	pc := findPending(st, rem.Address, store.PendingNickChange, "mixmin")
	if pc == nil || !pc.Rejected || rem.Keys["5f1e0d2c3b4a59687766554433221100"].State != store.KeyStateRejected {
		t.Fatalf("%+v", pc)
	}
	res = applyAt(st, rem.Address, now.Add(time.Hour), now.Add(time.Hour),
		"mixmin yamn@mixmin.net ffff0d2c3b4a59687766554433221100 4:0.2.7 E 2026-10-22 2026-11-05")
	if !hasResult(res, "ffff0d2c3b4a59687766554433221100", Rejected, "rejected by the operator") ||
		rem.Keys["ffff0d2c3b4a59687766554433221100"].State != store.KeyStateRejected || len(st.Pending) != 1 {
		t.Errorf("again: %v %v", res, st.Pending)
	}
	if res := ResolvePending(st, now.Add(48*time.Hour), cfg); len(res) != 0 || rem.Nick != "yamn" {
		t.Errorf("resolved a rejected change: %v", res)
	}
	if _, err := Reject(st, rem.Address, "mixmin", now); err == nil {
		t.Error("rejected twice")
	}
	// the operator changes his mind
	if _, err := Approve(st, rem.Address, "mixmin", now); err != nil || rem.Nick != "mixmin" || len(st.Pending) != 0 {
		t.Errorf("approve rejected: %v %s", err, rem.Nick)
	}

	// a rejected address change
	st = pinned(now.Add(-3 * time.Hour))
	rem = st.Remailers["yamn4@mixmin.net"]
	ApplyConfReply(st, rem, conf("yamn4", "yamn5@mixmin.net"), now.Add(-time.Hour), now, now, cfg)
	if _, err := Reject(st, rem.Address, "yamn5@mixmin.net", now); err != nil {
		t.Fatal(err)
	}
	res = ApplyConfReply(st, rem, conf("yamn4", "yamn5@mixmin.net"), now.Add(time.Hour), now, now, cfg)
	if !hasResult(res, "", Rejected, "address change to yamn5@mixmin.net was rejected") {
		t.Errorf("%v", res)
	}

	// an active key without a pending change
	k := st.Remailers["yamn@mixmin.net"].Keys["47c15db37d0d840b1f5ad4274384be22"]
	if _, err := Reject(st, "yamn@mixmin.net", k.KeyID, now); err != nil || k.State != store.KeyStateRejected {
		t.Errorf("%v %+v", err, k)
	}
	if _, err := Reject(st, "yamn@mixmin.net", "nothing", now); err == nil {
		t.Error("rejected nothing")
	}
}

func TestExpire(t *testing.T) {
	st := pinned(now)
	rem := st.Remailers["yamn@mixmin.net"]
	day := 24 * time.Hour
	keys := []struct {
		id      string
		seen    time.Duration // before now
		expires string
		keep    bool
	}{
		{"a0000000000000000000000000000000", 6 * day, "2026-10-21", false}, // expired, past retention
		{"b0000000000000000000000000000000", 6 * day, "2026-11-05", true},  // valid, past retention
		{"c0000000000000000000000000000000", 4 * day, "2026-10-21", true},  // expired, within retention
		{"d0000000000000000000000000000000", 5 * day, "2026-10-21", true},  // exactly retention
		{"e0000000000000000000000000000000", 31 * day, "2027-01-05", false},
		{"f0000000000000000000000000000000", 30 * day, "2027-01-05", true},
	}
	for _, k := range keys {
		rem.Keys[k.id] = key("yamn yamn@mixmin.net "+k.id+" 4:0.2.7 E 2026-09-20 "+k.expires, now.Add(-k.seen), store.KeyStateActive)
	}
	rem.Conf = &store.Conf{Nick: "yamn", LastUpdate: now.Add(-6 * day)}
	st.Remailers["yamn@virebent.art"].Conf = &store.Conf{Nick: "victor", LastUpdate: now.Add(-6 * day), DontExpire: true}
	st.Remailers["yamn4@mixmin.net"].Conf = &store.Conf{Nick: "yamn4", LastUpdate: now.Add(-4 * day)}
	st.Prospective = map[string][]store.Suggestion{
		"old@example.org":   {{Time: now.Add(-6 * day), Source: "victor"}},
		"mixed@example.org": {{Time: now.Add(-6 * day), Source: "victor"}, {Time: now.Add(-4 * day), Source: "yamn"}},
		"yamn@MIXMIN.net":   {{Time: now, Source: "victor"}}, // known meanwhile
	}
	st.Pending = []store.PendingChange{
		{Address: "yamn@mixmin.net", Kind: store.PendingKeyChange, New: "a0000000000000000000000000000000"}, // key goes
		{Address: "yamn@mixmin.net", Kind: store.PendingKeyChange, New: "b0000000000000000000000000000000"},
		{Address: "gone@example.org", Kind: store.PendingKeyChange, New: "b0000000000000000000000000000000"},
		{Address: "yamn@mixmin.net", Kind: store.PendingNickChange, New: "old", LastSeen: now.Add(-6 * day)},
		{Address: "yamn@mixmin.net", Kind: store.PendingNickChange, New: "recent", LastSeen: now.Add(-4 * day)},
		{Address: "yamn@mixmin.net", Kind: store.PendingNickChange, New: "nope", LastSeen: now.Add(-10 * day), Rejected: true},
		{Address: "yamn@mixmin.net", Kind: store.PendingAddressChange, New: "x@y", LastSeen: now.Add(-31 * day), Rejected: true},
	}
	victor := st.Remailers["yamn@virebent.art"]
	victor.TTL = 0
	yamn4 := st.Remailers["yamn4@mixmin.net"]
	yamn4.Status, yamn4.ResurrectionTTL = store.StatusTTLTimeout, 0

	res := Expire(st, now, cfg)

	for _, k := range keys {
		if _, ok := rem.Keys[k.id]; ok != k.keep {
			t.Errorf("key %s kept %v", k.id[:1], ok)
		}
	}
	if !hasResult(res, "e0000000000000000000000000000000", Expired, "30 days") {
		t.Errorf("%v", res)
	}
	if rem.Conf != nil || victor.Conf == nil || yamn4.Conf == nil {
		t.Error("confs")
	}
	if len(st.Prospective) != 1 || len(st.Prospective["mixed@example.org"]) != 1 || st.Prospective["mixed@example.org"][0].Source != "yamn" {
		t.Errorf("suggestions %v", st.Prospective)
	}
	var news []string
	for _, pc := range st.Pending {
		news = append(news, pc.New)
	}
	if strings.Join(news, " ") != "b0000000000000000000000000000000 recent nope" {
		t.Errorf("pending %v", news)
	}
	if victor.Status != store.StatusTTLTimeout || victor.ResurrectionTTL != store.DefaultResurrectionTTL || yamn4.Status != store.StatusDead {
		t.Errorf("states %s %s", victor.Status, yamn4.Status)
	}
	if !hasResult(res, "", State, "active -> ttl timeout") {
		t.Errorf("%v", res)
	}

	// a remailer without keys left; nothing to do the next day
	st.Pending, st.Prospective = nil, nil
	victor.Keys = map[string]*store.Key{"dd34d8b7f010229bb790a2402c9ffe65": key(victorLine, now.Add(-40*day), store.KeyStateActive)}
	Expire(st, now, cfg)
	if victor.Keys != nil || st.Pending != nil || st.Prospective != nil {
		t.Errorf("%v %v", victor.Keys, st.Pending)
	}
}
