package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/pinger"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// Phase 2 end to end with the real yamn binary (set YAMN_BIN; see
// internal/pinger/yamn_test.go for how the remailer is set up): a key
// reply and a conf reply from a real yamn remailer, a ping encoded by the
// real yamn client, decrypted and delivered by the real remailer, back
// into our Maildir; the key is proven only then, and published.

type yamnRemailer struct {
	bin, dir, addr string
	key            replies.ParsedKey
}

func newYamnRemailer(t *testing.T, bin, name string) *yamnRemailer {
	t.Helper()
	r := &yamnRemailer{bin: bin, dir: t.TempDir(), addr: name + "@example.invalid"}
	cfg := fmt.Sprintf("general: {loglevel: warn}\nurls: {fetch: false, pubring: \"\", mlist2: \"\", key_pinning: \"off\"}\n"+
		"mail: {outfile: true}\nremailer: {name: %s, address: %s, exit: true}\npool: {size: 0, rate: 100, min_send: 0}\n", name, r.addr)
	os.WriteFile(filepath.Join(r.dir, "yamn.yml"), []byte(cfg), 0o600)
	r.run(t, nil, "-M")
	data, _ := os.ReadFile(filepath.Join(r.dir, "key.txt"))
	kr := replies.ParseKey(data)
	if len(kr.Keys) != 1 {
		t.Fatalf("key.txt: %v", kr.Errors)
	}
	r.key = kr.Keys[0]
	return r
}

func (r *yamnRemailer) run(t *testing.T, stdin []byte, args ...string) {
	t.Helper()
	cmd := exec.Command(r.bin, append([]string{"--config", filepath.Join(r.dir, "yamn.yml"), "--dir", r.dir}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("yamn %v: %v\n%s", args, err, out)
	}
}

// deliver gives m to the remailer and returns the mails it sends out.
func (r *yamnRemailer) deliver(t *testing.T, m []byte) [][]byte {
	t.Helper()
	r.run(t, m, "-R")
	r.run(t, nil, "-M", "-S")
	files, _ := filepath.Glob(filepath.Join(r.dir, "pool", "outfile-*"))
	var out [][]byte
	for _, f := range files {
		b, _ := os.ReadFile(f)
		out = append(out, b)
		os.Remove(f)
	}
	return out
}

// yamnBin returns $YAMN_BIN, or skips the test without it, or as root:
// yamn refuses to run as root (go-while/yamn PR #73).
func yamnBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("YAMN_BIN")
	if bin == "" {
		t.Skip("YAMN_BIN not set")
	}
	if os.Geteuid() == 0 {
		t.Skip("yamn refuses to run as root; run the yamn tests as another user")
	}
	return bin
}

func TestYamnEndToEnd(t *testing.T) {
	bin := yamnBin(t)
	rem := newYamnRemailer(t, bin, "exit1")
	h := newHarnessAt(t, true, time.Now().UTC().Truncate(time.Second))
	h.d.encoder = &pinger.YamnEncoder{Binary: bin, Timeout: 30 * time.Second, Sender: h.cfg.Pinger.Address}
	h.command("add", rem.addr, "exit1")

	// Key and conf requests, answered with the remailer's real key.txt.
	h.command("getkeyconf")
	key, _ := os.ReadFile(filepath.Join(rem.dir, "key.txt"))
	rems := map[string]remailer{rem.addr: {"exit1", rem.addr, "Here is the Mixmaster key:\n\n=-=-=-=-=-=-=-=-=-=-=-=\n" + string(key)}}
	for _, m := range h.mailer.take() {
		h.answer(m, rems, yamnReply)
	}
	h.d.ScanMail(context.Background())
	h.command("buildkeys")
	ring := filepath.Join(h.cfg.Paths.ResultsDir, "pubring.mix")
	if b, _ := os.ReadFile(ring); len(b) != 0 {
		t.Fatalf("published before proof:\n%s", b)
	}

	// A ping: encoded by yamn, decrypted and delivered by the remailer.
	h.command("sendpings")
	sent := h.mailer.take()
	if len(sent) != 1 || sent[0].Rcpt[0] != rem.addr {
		t.Fatalf("pings sent: %+v\nlog:\n%s", sent, h.log)
	}
	if !bytes.HasPrefix(sent[0].Data, []byte("Date: ")) || !bytes.Contains(sent[0].Data, []byte("\nMessage-ID: <")) {
		t.Errorf("ping mail lacks Date or Message-ID:\n%.300s", sent[0].Data)
	}
	h.clock.Advance(90 * time.Second)
	out := rem.deliver(t, sent[0].Data)
	if len(out) != 1 {
		t.Fatalf("remailer sent %d mails", len(out))
	}
	h.deliver(string(out[0]))
	h.d.ScanMail(context.Background())

	h.st.View(func(st *store.State) {
		k := st.Remailers[rem.addr].Keys[rem.key.KeyID]
		if k == nil || k.ProvenAt.IsZero() {
			t.Fatalf("key not proven: %+v\nlog:\n%s", k, h.log)
		}
	})
	if _, done := h.st.Pings(rem.addr, time.Time{}); len(done) != 1 || done[0].Latency < 90 {
		t.Errorf("done pings: %+v", done)
	}

	// Proven: now it's published, and the stats list it.
	h.command("buildkeys")
	if b, _ := os.ReadFile(ring); !bytes.Contains(b, []byte(rem.key.String())) {
		t.Errorf("pubring.mix after proof:\n%s", b)
	}
	// Pings before the proof don't count (§13 q18); this one proved the
	// key, so the stats count from the next one: send and return it.
	h.clock.Advance(time.Minute)
	h.command("sendpings")
	for _, m := range h.mailer.take() {
		for _, o := range rem.deliver(t, m.Data) {
			h.clock.Advance(30 * time.Second)
			h.deliver(string(o))
		}
	}
	h.d.ScanMail(context.Background())
	h.command("buildstats")
	ml, _ := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, "mlist2.txt"))
	if !bytes.Contains(ml, []byte("\nexit1 ")) || !strings.Contains(string(ml), "100.0%") {
		t.Errorf("mlist2.txt:\n%s\nlog:\n%s", ml, h.log)
	}

	// The HTML pages (phase 3): the remailer, its replies and its fromline
	// from the real exit.
	www := h.cfg.Paths.ResultsDir
	for _, f := range []string{"index.html", "mlist2.html", "fromlines.html", "thesaurus/index.html", "echolot.css"} {
		if _, err := os.Stat(filepath.Join(www, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(www, "mlist2.html")); !bytes.Contains(b, []byte("exit1")) {
		t.Errorf("mlist2.html lacks exit1")
	}
	if txt, _ := filepath.Glob(filepath.Join(www, "thesaurus", "*.key.txt")); len(txt) != 1 {
		t.Errorf("thesaurus replies: %v", txt)
	}
	var fl string
	h.st.View(func(st *store.State) {
		for _, f := range st.Fromlines[rem.addr] {
			fl = f.From
		}
	})
	if b, _ := os.ReadFile(filepath.Join(www, "fromlines.html")); fl == "" || !bytes.Contains(b, []byte("exit1")) {
		t.Errorf("fromline %q; fromlines.html:\n%s", fl, b)
	}
}

// TestYamnChainPing: a chain ping through two real yamn remailers, A then
// B, comes back and is done.
func TestYamnChainPing(t *testing.T) {
	bin := yamnBin(t)
	a, b := newYamnRemailer(t, bin, "exita"), newYamnRemailer(t, bin, "exitb")
	// A forwards to B only if B's key is in A's pubring (yamn checkNextHop).
	bKey, _ := os.ReadFile(filepath.Join(b.dir, "key.txt"))
	os.WriteFile(filepath.Join(a.dir, "pubring.mix"), bKey, 0o600)
	h := newHarnessAt(t, false, time.Now().UTC().Truncate(time.Second))
	h.d.encoder = &pinger.YamnEncoder{Binary: bin, Timeout: 30 * time.Second, Sender: h.cfg.Pinger.Address}
	rems := map[string]remailer{}
	for _, r := range []*yamnRemailer{a, b} {
		nick := strings.TrimSuffix(r.addr, "@example.invalid")
		h.command("add", r.addr, nick)
		key, _ := os.ReadFile(filepath.Join(r.dir, "key.txt"))
		rems[r.addr] = remailer{nick, r.addr, "Here is the Mixmaster key:\n\n=-=-=-=-=-=-=-=-=-=-=-=\n" + string(key)}
	}
	h.command("getkeyconf")
	for _, m := range h.mailer.take() {
		h.answer(m, rems, yamnReply)
	}
	h.d.ScanMail(context.Background())

	h.command("sendchainpings", a.addr+":"+b.addr)
	sent := h.mailer.take()
	if len(sent) != 1 || sent[0].Rcpt[0] != a.addr {
		t.Fatalf("chain pings sent: %d\n%s", len(sent), h.log)
	}
	fromA := a.deliver(t, sent[0].Data)
	if len(fromA) != 1 {
		t.Fatalf("A sent %d mails", len(fromA))
	}
	fromB := b.deliver(t, fromA[0])
	if len(fromB) != 1 {
		t.Fatalf("B sent %d mails", len(fromB))
	}
	h.clock.Advance(2 * time.Minute)
	h.deliver(string(fromB[0]))
	h.d.ScanMail(context.Background())
	cps := h.st.ChainPings(time.Time{})
	if len(cps) != 1 || cps[0].Status != store.PingDone || cps[0].A != a.addr || cps[0].B != b.addr {
		t.Errorf("chain pings: %+v\n%s", cps, h.log)
	}
}
