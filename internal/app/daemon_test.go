package app

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/mailout"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/sched"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/token"
)

// Phase 1 end to end (design §12.3 step 6): requests go out through a
// fake mailer, a fake remailer answers into the Maildir with real yamn
// replies, and the daemon turns them into a keyring.

// fakeMailer records what would have been sent.
type fakeMailer struct {
	mu   sync.Mutex
	sent []mailout.Mail
	fail error
}

func (f *fakeMailer) Send(_ context.Context, m mailout.Mail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeMailer) take() []mailout.Mail {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sent
	f.sent = nil
	return s
}

type harness struct {
	t      *testing.T
	dir    string
	cfg    *config.Config
	st     *store.Store
	mailer *fakeMailer
	clock  *sched.Fake
	d      *Daemon
	log    *bytes.Buffer
}

// e2eStart is midnight UTC of the day testdata/pubrings was fetched.
var e2eStart = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)

func newHarness(t *testing.T, requireProof bool) *harness {
	t.Helper()
	dir := t.TempDir()
	ini := fmt.Sprintf(`[pinger]
sitename = Test pinger
address = pinger@pinger.example.org
operator_address = remops@example.org
[paths]
state_dir = %s
results_dir = %s
[keys]
require_proof = %v
`, filepath.Join(dir, "state"), filepath.Join(dir, "www"), requireProof)
	cfg, err := config.Parse("test.ini", []byte(ini))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, cfg: cfg, mailer: &fakeMailer{}, clock: sched.NewFake(e2eStart), log: &bytes.Buffer{}}
	for _, sub := range []string{"new", "cur", "tmp"} {
		os.MkdirAll(filepath.Join(cfg.Paths.Maildir, sub), 0o700)
	}
	h.open()
	return h
}

func (h *harness) open() {
	h.t.Helper()
	st, err := store.Open(h.cfg.Paths.StateDir, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.st = st
	h.t.Cleanup(func() { st.Close() })
	log := slogText(h.log)
	if h.d, err = NewDaemon(h.cfg, st, h.mailer, log, h.clock); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) command(verb string, args ...string) []string {
	return h.d.Command(context.Background(), Command{Verb: verb, Args: args}, h.clock.Now())
}

// ticks runs the request job for every tick in [from, from+d).
func (h *harness) ticks(from time.Time, d time.Duration) {
	for at := from; at.Before(from.Add(d)); at = at.Add(h.cfg.Schedule.Tick) {
		h.clock.Advance(at.Sub(h.clock.Now()))
		h.d.Requests(context.Background(), at, nil, false)
	}
}

// liveKey returns the pubring entry of nick from testdata, as the body of
// yamn's key reply (Y:server.go: prefix, then key.txt).
func liveKey(t *testing.T, nick string) string {
	for _, f := range []string{"replies/t_65.key", "pubrings/mixmin.mix"} {
		data, _ := os.ReadFile("../../testdata/" + f)
		for _, k := range replies.ParseKey(data).Keys {
			if k.Nick == nick {
				return fmt.Sprintf("Here is the Mixmaster key:\n\n=-=-=-=-=-=-=-=-=-=-=-=\n%s\n\n-----Begin Mix Key-----\n%s\n%x\n-----End Mix Key-----\n\n",
					k.String(), k.KeyID, k.PK)
			}
		}
	}
	t.Fatalf("no key for %s", nick)
	return ""
}

// remailer answers requests like a yamn remailer would.
type remailer struct {
	nick, addr string
	keyReply   string
}

func (h *harness) answer(m mailout.Mail, rems map[string]remailer, body func(r remailer, subject string) string) {
	h.t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(m.Data))
	if err != nil {
		h.t.Fatal(err)
	}
	r := rems[m.Rcpt[0]]
	b := body(r, msg.Header.Get("Subject"))
	if b == "" {
		return
	}
	reply := fmt.Sprintf("From: %s\nTo: %s\nSubject: reply\nDate: %s\n\n%s",
		r.addr, msg.Header.Get("From"), h.clock.Now().Format(time.RFC1123Z), b)
	h.deliver(reply)
}

var deliverN int

func (h *harness) deliver(mailText string) {
	deliverN++
	path := filepath.Join(h.cfg.Paths.Maildir, "new", fmt.Sprintf("%d.%d.test", h.clock.Now().Unix(), deliverN))
	if err := os.WriteFile(path, []byte(mailText), 0o600); err != nil {
		h.t.Fatal(err)
	}
	os.Chtimes(path, h.clock.Now(), h.clock.Now())
}

func yamnReply(r remailer, subject string) string {
	switch subject {
	case "remailer-key":
		return r.keyReply
	case "remailer-conf":
		return fmt.Sprintf("Remailer-Type: Mixmaster 0.2.7\nSupported Formats:\n   Mixmaster\n\n$remailer{\"%s\"} = \"<%s> v2\";\n\nSUPPORTED MIXMASTER (TYPE II) REMAILERS\n", r.nick, r.addr)
	case "remailer-help":
		return "help text\n"
	}
	return "" // adminkey: this remailer has none
}

func TestEndToEnd(t *testing.T) {
	h := newHarness(t, false) // phase 1: no pings, so no proof
	rems := map[string]remailer{
		"yamn@virebent.art": {"victor", "yamn@virebent.art", liveKey(t, "victor")},
		"yamn4@mixmin.net":  {"yamn4", "yamn4@mixmin.net", liveKey(t, "yamn4")},
	}
	h.command("add", "yamn@virebent.art")
	h.command("add", "yamn4@mixmin.net", "yamn4")

	// One day of ticks: every remailer gets 12 key requests and one conf
	// request, each from its own token address.
	h.ticks(e2eStart, 24*time.Hour)
	sent := h.mailer.take()
	count := map[string]int{}
	froms := map[string]bool{}
	for _, m := range sent {
		msg, _ := mail.ReadMessage(bytes.NewReader(m.Data))
		subj, from := msg.Header.Get("Subject"), msg.Header.Get("From")
		count[m.Rcpt[0]+" "+subj]++
		if froms[from] {
			t.Errorf("token address used twice: %s", from)
		}
		froms[from] = true
		tok, err := h.d.minter.Verify(from, h.clock.Now())
		if err != nil || "remailer-"+string(tok.Kind) != subj {
			t.Errorf("From %s: %+v, %v", from, tok, err)
		}
		if btok, err := h.d.minter.Verify(m.EnvelopeFrom, h.clock.Now()); err != nil || btok.Kind != token.KindBounce || btok.ID != tok.ID {
			t.Errorf("envelope %s: %+v, %v", m.EnvelopeFrom, btok, err)
		}
		if !bytes.Contains(m.Data, []byte("\tnot a remailer\n")) || !bytes.Contains(m.Data, []byte(m.Rcpt[0]+" is a remailer")) {
			t.Errorf("request text:\n%s", m.Data)
		}
	}
	for addr := range rems {
		if count[addr+" remailer-key"] != 12 || count[addr+" remailer-conf"] != 1 {
			t.Errorf("%s: %v", addr, count)
		}
	}
	h.st.View(func(st *store.State) {
		if r := st.Remailers["yamn@virebent.art"]; r.TTL != store.DefaultTTL-1 {
			t.Errorf("TTL after one unanswered conf request: %d", r.TTL)
		}
	})

	// The remailers answer the requests of the last two hours; one bad
	// mail and one bounce arrive too.
	var recent []mailout.Mail
	for _, m := range sent {
		msg, _ := mail.ReadMessage(bytes.NewReader(m.Data))
		if tok, _ := h.d.minter.Verify(msg.Header.Get("From"), h.clock.Now()); tok.Time.After(h.clock.Now().Add(-2*time.Hour)) || tok.Kind == token.KindConf {
			recent = append(recent, m)
		}
	}
	for _, m := range recent {
		h.answer(m, rems, yamnReply)
	}
	h.deliver("From: spam@example.com\nTo: pinger@pinger.example.org\nSubject: hi\n\nbuy now\n")
	bounceTo, _ := h.d.minter.Address(token.Token{Kind: token.KindBounce, ID: 1, Time: h.clock.Now().Add(-time.Hour)})
	h.deliver("From: MAILER-DAEMON@relay.example\nX-Original-To: " + bounceTo + "\nSubject: Undelivered Mail\n\nsorry\n")
	h.d.ScanMail(context.Background())

	entries, _ := os.ReadDir(filepath.Join(h.cfg.Paths.Maildir, "new"))
	if len(entries) != 0 {
		t.Errorf("mail left in new/: %v", entries)
	}
	errs, _ := os.ReadDir(filepath.Join(h.cfg.Paths.StateDir, "mail-errors"))
	if len(errs) != 2 { // the spam and its .reason file
		t.Errorf("mail-errors: %v", errs)
	}
	if !strings.Contains(h.log.String(), "msg=bounce") {
		t.Errorf("bounce not logged:\n%s", h.log)
	}
	h.st.View(func(st *store.State) {
		v := st.Remailers["yamn@virebent.art"]
		if v.Nick != "victor" || v.Conf == nil || len(v.Keys) != 1 || v.TTL != store.DefaultTTL {
			t.Errorf("victor: %+v", v)
		}
	})
	if _, err := os.Stat(filepath.Join(h.cfg.Paths.StateDir, "thesaurus", "1.key")); err != nil {
		t.Errorf("thesaurus: %v", err)
	}

	// The keyring is the live entries of both remailers, byte for byte.
	h.d.BuildKeys(h.clock.Now())
	ring, _ := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, "pubring.mix"))
	want := liveKey(t, "victor") + liveKey(t, "yamn4")
	want = strings.ReplaceAll(want, "Here is the Mixmaster key:\n\n=-=-=-=-=-=-=-=-=-=-=-=\n", "")
	if string(ring) != want {
		t.Errorf("pubring.mix:\n%s\nwant\n%s", ring, want)
	}
	if _, err := os.Stat(filepath.Join(h.cfg.Paths.ResultsDir, "pubring.mix.meta")); err != nil {
		t.Errorf("meta: %v", err)
	}

	// Y-03: a forged key for victor on a valid token stays quarantined.
	forged := strings.ReplaceAll(liveKey(t, "yamn4"), "yamn4 yamn4@mixmin.net", "victor yamn@virebent.art")
	tokAddr, _ := h.d.minter.Address(token.Token{Kind: token.KindKey, ID: 1, Time: h.clock.Now()})
	h.clock.Advance(time.Minute)
	h.deliver("From: yamn@virebent.art\nTo: " + tokAddr + "\nSubject: Remailer key\n\n" + forged)
	h.d.ScanMail(context.Background())
	h.d.BuildKeys(h.clock.Now())
	if again, _ := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, "pubring.mix")); !bytes.Equal(again, ring) {
		t.Errorf("forged key changed the keyring:\n%s", again)
	}
	var out bytes.Buffer
	h.st.View(func(st *store.State) { WriteStatus(&out, st, h.clock.Now(), false, "") })
	if !strings.Contains(out.String(), "pending changes") {
		t.Errorf("status:\n%s", out.String())
	}

	// "not a remailer" from yamn4: no more requests to it.
	notAddr, _ := h.d.minter.Address(token.Token{Kind: token.KindConf, ID: 2, Time: h.clock.Now()})
	h.deliver("From: yamn4@mixmin.net\nTo: " + notAddr + "\nSubject: Re: remailer-conf\n\nnot a remailer\n")
	h.d.ScanMail(context.Background())
	h.mailer.take()
	h.ticks(h.clock.Now().Truncate(5*time.Minute).Add(5*time.Minute), 24*time.Hour)
	for _, m := range h.mailer.take() {
		if m.Rcpt[0] == "yamn4@mixmin.net" {
			t.Fatal("request sent after \"not a remailer\"")
		}
	}

	// A command spooled by the CLI while the daemon runs.
	if err := Spool(h.cfg.Paths.StateDir, Command{Verb: "add", Args: []string{"nyam@remailer.frell.eu.org"}}, h.clock.Now()); err != nil {
		t.Fatal(err)
	}
	h.d.Commands(context.Background(), h.clock.Now())
	if cmds, _ := ReadSpool(h.cfg.Paths.StateDir); len(cmds) != 0 {
		t.Errorf("spool not emptied: %v", cmds)
	}

	// Restart: everything is still there.
	h.st.Close()
	h.open()
	h.st.View(func(st *store.State) {
		if len(st.Remailers) != 3 || st.Remailers["yamn4@mixmin.net"].Status != store.StatusNotARemailer {
			t.Errorf("after restart: %+v", st.Remailers)
		}
	})
	h.d.Daily(h.clock.Now())
}

// TestRequireProof: with keys.require_proof (from phase 2 on) nothing is
// published before a ping came back, but the private keyring is empty too.
func TestRequireProof(t *testing.T) {
	h := newHarness(t, true)
	h.command("add", "yamn@virebent.art")
	h.command("getkeyconf")
	rems := map[string]remailer{"yamn@virebent.art": {"victor", "yamn@virebent.art", liveKey(t, "victor")}}
	for _, m := range h.mailer.take() {
		h.answer(m, rems, yamnReply)
	}
	h.d.ScanMail(context.Background())
	h.command("buildkeys")
	ring, err := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, "pubring.mix"))
	if err != nil || len(ring) != 0 {
		t.Errorf("pubring.mix before any proof: %v %q", err, ring)
	}
}

func TestSendFailures(t *testing.T) {
	h := newHarness(t, false)
	h.command("add", "yamn@virebent.art")
	h.mailer.fail = fmt.Errorf("relay down: %w", mailout.ErrTemporary)
	h.command("getkeyconf")
	h.st.View(func(st *store.State) {
		if r := st.Remailers["yamn@virebent.art"]; r.TTL != store.DefaultTTL {
			t.Errorf("TTL changed by our own failure: %d", r.TTL)
		}
	})
	if !strings.Contains(h.log.String(), "request not sent") {
		t.Errorf("log:\n%s", h.log)
	}
	h.mailer.fail = mailout.ErrOnionWithoutTor
	h.command("getkeyconf")
	if !strings.Contains(h.log.String(), "mail.tor_socks is not set") {
		t.Errorf("log:\n%s", h.log)
	}
}

func TestRunStops(t *testing.T) {
	h := newHarness(t, false)
	h.d.clock = sched.RealClock()
	h.d.loop = sched.New(h.d.clock, nil)
	ctx, cancel := context.WithCancel(context.Background())
	hup := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- h.d.Run(ctx, hup) }()
	hup <- os.Interrupt // any signal on the channel runs the spool
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't stop")
	}
}

func slogText(w *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(&lockedWriter{w: w}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
