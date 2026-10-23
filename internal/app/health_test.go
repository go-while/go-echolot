package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/health"
	"github.com/go-while/go-echolot/internal/mailout"
	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/token"
)

// healthHarness is pingHarness with victor's conf, so its key is in the
// public keyring.
func healthHarness(t *testing.T) (*harness, string, string) {
	h, real, forged := pingHarness(t)
	h.st.Update(func(st *store.State) error {
		r := st.Remailers["yamn@virebent.art"]
		r.Conf = &store.Conf{Nick: "victor", Caps: `$remailer{"victor"} = "<yamn@virebent.art> v2";`, LastUpdate: h.clock.Now()}
		return nil
	})
	return h, real, forged
}

// checks runs the health checks now, by name.
func (h *harness) checks() map[string]health.Check {
	h.t.Helper()
	m := map[string]health.Check{}
	for _, c := range h.d.HealthChecks(h.clock.Now()) {
		m[c.Name] = c
	}
	return m
}

func (h *harness) wantCheck(name string, l health.Level, detail string) {
	h.t.Helper()
	c, ok := h.checks()[name]
	if !ok || c.State != l || !strings.Contains(c.Detail, detail) {
		h.t.Errorf("%s: %s %q, want %s with %q", name, c.State, c.Detail, l, detail)
	}
}

func TestHealthStatusFiles(t *testing.T) {
	h, _, _ := healthHarness(t)
	ctx := context.Background()
	h.d.ScanMail(ctx)
	h.d.BuildStats(h.clock.Now())
	r := h.d.Health(ctx, h.clock.Now())
	got := map[string]health.Check{}
	for _, c := range r.Checks {
		got[c.Name] = c
	}
	for _, name := range []string{"mailbox_scan", "ping_replies", "send_failures", "mlist2_age", "keys", "yamn_selftest", "pending", "bounces", "disk_state", "disk_results"} {
		if _, ok := got[name]; !ok {
			t.Errorf("no check %s", name)
		}
	}
	if _, ok := got["key_agreement"]; ok {
		t.Error("peer_keys without peers")
	}
	if c := got["keys"]; c.State != health.OK || c.Detail != "1 keys published" {
		t.Errorf("keys: %+v", c)
	}
	data, err := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, StatusJSON))
	if err != nil {
		t.Fatal(err)
	}
	back, err := health.ParseReport(data)
	if err != nil || !back.Generated.Equal(h.clock.Now()) || back.Pinger != "Test pinger" || len(back.Checks) != len(r.Checks) {
		t.Errorf("status.json: %+v, %v", back, err)
	}
	txt, _ := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, StatusText))
	if !strings.Contains(string(txt), "ok    mailbox_scan       last good scan 0s ago\n") {
		t.Errorf("status.txt:\n%s", txt)
	}

	// No scan and no stats for 40 minutes.
	h.clock.Advance(40 * time.Minute)
	h.wantCheck("mailbox_scan", health.Crit, "last good scan 40m ago")
	h.wantCheck("mlist2_age", health.Warn, "generated 40m ago")
	h.d.ScanMail(ctx)
	h.wantCheck("mailbox_scan", health.OK, "0s ago")

	// The self-test.
	h.d.SelfTest(ctx, h.clock.Now())
	h.wantCheck("yamn_selftest", health.OK, "passed")
	h.d.encoder = plainEncoder{fail: errors.New("yamn is gone")}
	h.d.SelfTest(ctx, h.clock.Now())
	h.wantCheck("yamn_selftest", health.Crit, "no pings can be sent")
	if !strings.Contains(h.log.String(), "yamn is gone") {
		t.Error("the self-test error isn't logged")
	}
}

func TestHealthKeys(t *testing.T) {
	h, real, forged := healthHarness(t)
	var exp time.Time
	h.st.View(func(st *store.State) { exp = st.Remailers["yamn@virebent.art"].Keys[real].Expires.End() })
	// A key change waits in quarantine.
	h.st.Update(func(st *store.State) error {
		st.Pending = []store.PendingChange{{Address: "yamn@virebent.art", Kind: store.PendingKeyChange, New: forged}}
		return nil
	})
	h.wantCheck("pending", health.Warn, "yamn@virebent.art: key "+forged)
	// 12 hours before the published key expires; the forged key expires
	// earlier, so it's no successor.
	h.clock.Jump(exp.Add(-12 * time.Hour).Sub(h.clock.Now()))
	h.st.Update(func(st *store.State) error {
		st.Remailers["yamn@virebent.art"].Keys[forged].Expires = st.Remailers["yamn@virebent.art"].Keys[real].Expires.AddDays(-1)
		return nil
	})
	h.wantCheck("keys", health.Warn, "victor (expires ")
	h.st.Update(func(st *store.State) error {
		st.Remailers["yamn@virebent.art"].Keys[forged].Expires = st.Remailers["yamn@virebent.art"].Keys[real].Expires.AddDays(10)
		return nil
	})
	h.wantCheck("keys", health.OK, "1 keys published")
	h.st.Update(func(st *store.State) error { st.Remailers["yamn@virebent.art"].ShowIt = false; return nil })
	h.wantCheck("keys", health.Crit, "no keys published")
}

func TestHealthReplies(t *testing.T) {
	h, _, _ := healthHarness(t)
	h.wantCheck("ping_replies", health.OK, "no ping waiting")
	h.command("sendpings")
	h.clock.Advance(2 * time.Hour)
	h.wantCheck("ping_replies", health.OK, "last reply never")
	h.clock.Advance(2 * time.Hour)
	h.wantCheck("ping_replies", health.Warn, "no ping reply for 4h")
	h.clock.Advance(4 * time.Hour)
	// One remailer pingable: warn, not crit.
	h.wantCheck("ping_replies", health.Warn, "no ping reply for 8h (last reply never; 1 remailers pingable)")
	// After a restart, the pings sent before it count from the start.
	h.restart()
	h.wantCheck("ping_replies", health.OK, "")
}

func TestHealthSendFailures(t *testing.T) {
	h, _, _ := healthHarness(t)
	h.command("sendpings") // two keys: two sends
	h.wantCheck("send_failures", health.OK, "0 of 2 sends failed")
	h.mailer.fail = fmt.Errorf("421 try later: %w", mailout.ErrTemporary)
	h.command("sendpings")
	h.wantCheck("send_failures", health.Warn, "2 of 4 sends failed")
	// The rate fuse sends nothing: it isn't a failure, but shows.
	h.mailer.fail = &mailout.Error{Op: "rate fuse", Err: mailout.ErrRateLimited}
	h.command("sendpings")
	h.wantCheck("send_failures", health.Warn, "2 of 4 sends failed in the last hour; mail.max_per_hour held back 1 mails")
	h.clock.Advance(time.Hour + time.Second)
	h.mailer.fail = errors.New("sendmail: exit status 75")
	h.command("sendpings")
	h.command("sendpings")
	h.wantCheck("send_failures", health.Crit, "all 4 sends failed")
}

func TestHealthBounces(t *testing.T) {
	h, _, _ := healthHarness(t)
	h.wantCheck("bounces", health.OK, "none")
	bounceTo, _ := h.d.minter.Address(token.Token{Kind: token.KindBounce, ID: 1, Time: h.clock.Now().Add(-time.Hour)})
	h.deliver("From: MAILER-DAEMON@relay.example\nX-Original-To: " + bounceTo + "\nSubject: Undelivered Mail\n\nsorry\n")
	h.d.ScanMail(context.Background())
	h.wantCheck("bounces", health.Warn, "yamn@virebent.art")
	h.restart()
	h.wantCheck("bounces", health.Warn, "yamn@virebent.art")
	h.clock.Advance(25 * time.Hour)
	h.wantCheck("bounces", health.OK, "none")
}

func TestHealthNotify(t *testing.T) {
	h, _, _ := healthHarness(t)
	h.cfg.Health.Notify = "ops@example.org"
	h.restart()
	ctx := context.Background()
	h.d.ScanMail(ctx)
	h.d.BuildStats(h.clock.Now())
	mailsTo := func() []mailout.Mail {
		var ms []mailout.Mail
		for _, m := range h.mailer.take() {
			if m.Rcpt[0] == "ops@example.org" {
				ms = append(ms, m)
			}
		}
		return ms
	}
	h.d.Health(ctx, h.clock.Now())
	if ms := mailsTo(); len(ms) != 0 {
		t.Fatalf("mail while all is well:\n%s", ms[0].Data)
	}

	// The scan stops: one mail, not one per tick.
	h.clock.Advance(10 * time.Minute)
	h.d.BuildStats(h.clock.Now())
	h.d.Health(ctx, h.clock.Now())
	ms := mailsTo()
	if len(ms) != 1 || !strings.Contains(string(ms[0].Data), "Subject: go-echolot health: WARN (Test pinger)\n") ||
		!strings.Contains(string(ms[0].Data), "Changed:\n\nwarn  mailbox_scan") || ms[0].EnvelopeFrom != "pinger@pinger.example.org" {
		t.Fatalf("mails: %d\n%s", len(ms), ms)
	}
	if sent, _, _ := h.d.health.sends.Counts(h.clock.Now()); sent != 0 {
		t.Errorf("the health mail counts as a send: %d", sent)
	}
	h.clock.Advance(5 * time.Minute)
	h.d.BuildStats(h.clock.Now())
	h.d.Health(ctx, h.clock.Now())
	if ms := mailsTo(); len(ms) != 0 {
		t.Errorf("mailed again:\n%s", ms[0].Data)
	}
	// It goes crit 15 minutes later: within 6 hours of the last mail, so
	// it waits; also over a restart.
	h.clock.Advance(20 * time.Minute)
	h.restart()
	h.d.health.scanned(h.clock.Now().Add(-31 * time.Minute))
	h.d.BuildStats(h.clock.Now())
	h.d.Health(ctx, h.clock.Now())
	if ms := mailsTo(); len(ms) != 0 {
		t.Errorf("mailed within 6 h:\n%s", ms[0].Data)
	}
	// 6 hours after the first mail: crit is mailed.  The first try fails;
	// it's tried again 30 minutes later, not at every tick.
	h.clock.Advance(6 * time.Hour)
	h.d.BuildStats(h.clock.Now())
	h.mailer.fail = errors.New("sendmail: exit status 75")
	h.d.Health(ctx, h.clock.Now())
	if !strings.Contains(h.log.String(), "health mail not sent") {
		t.Error("the failed mail isn't logged")
	}
	h.mailer.fail = nil
	h.clock.Advance(5 * time.Minute)
	h.d.BuildStats(h.clock.Now())
	h.d.Health(ctx, h.clock.Now())
	if ms := mailsTo(); len(ms) != 0 {
		t.Errorf("retried at once:\n%s", ms[0].Data)
	}
	h.clock.Advance(25 * time.Minute)
	h.d.BuildStats(h.clock.Now())
	h.d.Health(ctx, h.clock.Now())
	if ms := mailsTo(); len(ms) != 1 || !strings.Contains(string(ms[0].Data), "crit  mailbox_scan") {
		t.Errorf("crit not mailed: %d %s", len(ms), ms)
	}
	// The scan comes back: ok is mailed 6 hours after the last mail.
	h.clock.Advance(time.Hour)
	h.d.ScanMail(ctx)
	h.d.BuildStats(h.clock.Now())
	h.d.Health(ctx, h.clock.Now())
	if ms := mailsTo(); len(ms) != 0 {
		t.Errorf("ok mailed within 6 h:\n%s", ms[0].Data)
	}
	h.clock.Advance(5 * time.Hour)
	h.d.ScanMail(ctx)
	h.d.BuildStats(h.clock.Now())
	h.d.Health(ctx, h.clock.Now())
	if ms := mailsTo(); len(ms) != 1 || !strings.Contains(string(ms[0].Data), "Subject: go-echolot health: OK") {
		t.Errorf("ok not mailed: %d %s", len(ms), ms)
	}
}

func TestHealthPeers(t *testing.T) {
	h, real, forged := healthHarness(t)
	now := h.clock.Now()
	mlist := func(gen time.Time) string {
		return "Stats-Version: 2.0\nGenerated: " + gen.UTC().Format("Mon 02 Jan 2006 15:04:05 GMT") + "\nMixmaster ...\n"
	}
	// Their key for victor is another one.
	other := replies.ParseKey([]byte(liveKey(t, "yamn4"))).Keys[0]
	other.Nick, other.Address = "victor", "yamn@virebent.art"
	ring, err := output.Pubring([]replies.ParsedKey{other})
	if err != nil {
		t.Fatal(err)
	}
	up := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); !strings.HasPrefix(ua, "go-echolot/") {
			t.Errorf("User-Agent %q", ua)
		}
		switch r.URL.Path {
		case "/fresh/mlist2.txt":
			if !up {
				http.Error(w, "down", http.StatusBadGateway)
				return
			}
			fmt.Fprint(w, mlist(now.Add(-time.Hour)))
		case "/fresh/pubring.mix":
			w.Write(ring)
		case "/stale/mlist2.txt":
			fmt.Fprint(w, mlist(now.Add(-7*time.Hour)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	h.cfg.Peers = []config.Peer{
		{Name: "fresh", Mlist2: srv.URL + "/fresh/mlist2.txt"},
		{Name: "stale", Mlist2: srv.URL + "/stale/mlist2.txt"},
		{Name: "down", Mlist2: srv.URL + "/down/mlist2.txt"},
	}
	h.restart()
	h.wantCheck("peer_fresh", health.OK, "not fetched yet")
	h.d.CheckPeers(context.Background(), now)
	h.wantCheck("peer_fresh", health.OK, "generated 1h ago")
	h.wantCheck("peer_stale", health.Warn, "generated 7h ago")
	h.wantCheck("peer_down", health.Warn, "never fetched: "+srv.URL+"/down/mlist2.txt: 404 Not Found")
	h.wantCheck("key_agreement", health.OK, "fresh: yamn@virebent.art ours "+real+", theirs "+forged)
	if !strings.Contains(h.log.String(), "peer key disagreement") {
		t.Error("the disagreement isn't logged")
	}

	// fresh goes down: it ages from its last good fetch, over a restart.
	up = false
	h.clock.Advance(25 * time.Hour)
	h.restart()
	h.d.CheckPeers(context.Background(), h.clock.Now())
	h.wantCheck("peer_fresh", health.Crit, "generated 26h ago; the last fetch failed: ")
	h.wantCheck("key_agreement", health.OK, "fresh: yamn@virebent.art") // kept: the pubring still came
	// A peer taken out of the config is forgotten.
	h.cfg.Peers = h.cfg.Peers[:1]
	h.restart()
	h.d.CheckPeers(context.Background(), h.clock.Now())
	h.st.View(func(st *store.State) {
		if len(st.Health.Peers) != 1 {
			t.Errorf("peers kept: %v", st.Health.Peers)
		}
	})
}

// TestHealthNotifyReadOnlyState: state.json can't be written (a full
// disk, say): the mail goes out once, not at every tick.
func TestHealthNotifyReadOnlyState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into read-only directories")
	}
	h, _, _ := healthHarness(t)
	h.cfg.Health.Notify = "ops@example.org"
	h.restart()
	ctx := context.Background()
	os.Chmod(h.cfg.Paths.StateDir, 0o500)
	t.Cleanup(func() { os.Chmod(h.cfg.Paths.StateDir, 0o700) })
	h.clock.Advance(10 * time.Minute)
	for range 3 {
		h.d.Health(ctx, h.clock.Now())
		h.clock.Advance(2 * time.Minute)
	}
	n := 0
	for _, m := range h.mailer.take() {
		if m.Rcpt[0] == "ops@example.org" {
			n++
		}
	}
	if n != 1 || !strings.Contains(h.log.String(), "health mail not recorded in state.json") {
		t.Errorf("%d mails\n%s", n, h.log)
	}
}

// TestReplyClock: pings sent before a start count from it, but a daemon
// that restarts again and again with no reply still warns.
func TestReplyClock(t *testing.T) {
	h, _, _ := healthHarness(t)
	h.command("sendpings")
	h.d.markStart(h.clock.Now())
	for range 5 { // a restart every 2 hours
		h.clock.Advance(2 * time.Hour)
		h.restart()
		h.d.markStart(h.clock.Now())
	}
	h.wantCheck("ping_replies", health.Warn, "no ping reply for 10h")
	// A reply came after the last start: the next start resets the clock.
	out, _ := h.st.Pings("yamn@virebent.art", time.Time{})
	h.st.PingDone(out[0].ID, h.clock.Now(), 3600)
	h.clock.Advance(time.Hour)
	h.restart()
	h.d.markStart(h.clock.Now())
	h.wantCheck("ping_replies", health.OK, "last reply 1h ago")
}

// TestPeerFuture: a peer's Generated: in the future counts as the time
// of the fetch, so the peer still goes stale when it's down.
func TestPeerFuture(t *testing.T) {
	h, _, _ := healthHarness(t)
	up := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, "Stats-Version: 2.0\nGenerated: Fri 01 Jan 2100 00:00:00 GMT\n")
	}))
	defer srv.Close()
	h.cfg.Peers = []config.Peer{{Name: "ahead", Mlist2: srv.URL + "/mlist2.txt"}}
	h.restart()
	h.d.CheckPeers(context.Background(), h.clock.Now())
	h.wantCheck("peer_ahead", health.OK, "generated 0s ago")
	up = false
	h.clock.Advance(25 * time.Hour)
	h.d.CheckPeers(context.Background(), h.clock.Now())
	h.wantCheck("peer_ahead", health.Crit, "generated 25h ago")
}
