package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/minisign"
	"github.com/go-while/go-echolot/internal/store"
)

// withSigning turns signing on in h with a new key and restarts the
// daemon; it returns the public key.
func (h *harness) withSigning() minisign.PublicKey {
	h.t.Helper()
	k, err := minisign.GenerateKey(nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.cfg.Signing.Enabled = true
	h.cfg.Signing.KeyFile = filepath.Join(h.dir, "pinger.key")
	if err := WriteKeyFile(h.cfg.Signing.KeyFile, k); err != nil {
		h.t.Fatal(err)
	}
	h.restart()
	return k.Public()
}

// restart makes a new daemon on the same store, as after a restart.
func (h *harness) restart() {
	h.t.Helper()
	d, err := NewDaemon(h.cfg, h.st, h.mailer, slogText(h.log), h.clock)
	if err != nil {
		h.t.Fatal(err)
	}
	h.d = d
}

// verified checks the published file name and returns its trusted comment.
func (h *harness) verified(pub minisign.PublicKey, name string) minisign.Trusted {
	h.t.Helper()
	dir := h.cfg.Paths.ResultsDir
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		h.t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join(dir, name+".minisig"))
	if err != nil {
		h.t.Fatal(err)
	}
	tr, err := minisign.VerifyFile(pub, name, data, sig, h.clock.Now())
	if err != nil {
		h.t.Fatalf("%s: %v", name, err)
	}
	return tr
}

func TestSignedOutputs(t *testing.T) {
	h := newHarness(t, false)
	pub := h.withSigning()
	at := h.clock.Now()
	h.d.BuildKeys(at)
	h.d.BuildStats(at)
	for name, v := range map[string]time.Duration{"pubring.mix": 48 * time.Hour, "type2.list": 48 * time.Hour, "mlist2.txt": 6 * time.Hour} {
		tr := h.verified(pub, name)
		if tr.Pinger != "Test_pinger" || tr.Expires.Sub(tr.Timestamp) != v || tr.Timestamp.Before(at) {
			t.Errorf("%s: %+v", name, tr)
		}
	}
	// mlist.txt isn't in the default signing.files; the private files
	// aren't signed.
	for _, p := range []string{
		filepath.Join(h.cfg.Paths.ResultsDir, "mlist.txt.minisig"),
		filepath.Join(h.cfg.Paths.PrivateResultsDir, "pubring.mix.minisig"),
		filepath.Join(h.cfg.Paths.PrivateResultsDir, "mlist2.txt.minisig"),
	} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists", p)
		}
	}
	b, err := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, "pinger.pub"))
	if err != nil || string(b) != string(pub.File()) {
		t.Errorf("pinger.pub: %q, %v", b, err)
	}
	b, _ = os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, "index.html"))
	// html/template writes "+" as "&#43;".
	if !strings.Contains(string(b), strings.ReplaceAll(pub.String(), "+", "&#43;")) {
		t.Error("the index page doesn't show the key")
	}

	// Unchanged keyrings are signed again an hour later.
	h.clock.Advance(time.Hour)
	before := h.verified(pub, "pubring.mix").Timestamp
	h.d.BuildKeys(h.clock.Now())
	if after := h.verified(pub, "pubring.mix").Timestamp; !after.Equal(before.Add(time.Hour)) {
		t.Errorf("re-signed at %s, want %s", after, before.Add(time.Hour))
	}

	// Signing turned off: the signatures go with the next write.
	h.cfg.Signing.Enabled = false
	h.restart()
	h.d.BuildKeys(h.clock.Now())
	h.d.BuildStats(h.clock.Now())
	for _, name := range []string{"pubring.mix", "type2.list", "mlist2.txt"} {
		if _, err := os.Stat(filepath.Join(h.cfg.Paths.ResultsDir, name+".minisig")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s.minisig left after signing was turned off", name)
		}
	}
}

// TestSignatureTimestampsNeverGoBack: rollback protection in yamn refuses
// a timestamp older than one it has seen (design §9.5), so they must
// never go backwards: not with a clock step back, a restart, or a state
// dir restored from a backup.
func TestSignatureTimestampsNeverGoBack(t *testing.T) {
	h := newHarness(t, false)
	pub := h.withSigning()
	ts := func() int64 { return h.verified(pub, "mlist2.txt").Timestamp.Unix() }

	h.d.BuildStats(h.clock.Now())
	t0 := ts()
	h.d.BuildStats(h.clock.Now()) // the same second
	if got := ts(); got != t0+1 {
		t.Errorf("same second: %d, want %d", got, t0+1)
	}
	h.clock.Jump(-5 * time.Minute) // the clock steps back a little
	h.d.BuildStats(h.clock.Now())
	if got := ts(); got != t0+2 {
		t.Errorf("after the clock went back: %d, want %d", got, t0+2)
	}
	if !strings.Contains(h.log.String(), "ahead of the clock") {
		t.Error("no warning about the clock")
	}
	// Further back than MaxAhead: nothing is signed (the old signature no
	// longer matches, so clients keep their copy) until the clock is back.
	h.clock.Jump(-time.Hour)
	h.d.BuildStats(h.clock.Now())
	if !strings.Contains(h.log.String(), "not signed: the next timestamp is") {
		t.Errorf("no error for a clock far behind:\n%s", h.log)
	}
	sig, _ := os.ReadFile(filepath.Join(h.cfg.Paths.ResultsDir, "mlist2.txt.minisig"))
	if got, _ := SignatureTime(pub, sig); got != t0+2 {
		t.Errorf("signed with the clock far behind: %d", got)
	}
	h.clock.Jump(time.Hour)
	h.restart()
	h.d.BuildStats(h.clock.Now())
	if got := ts(); got != t0+3 {
		t.Errorf("after a restart: %d, want %d", got, t0+3)
	}
	// The state dir comes back from a backup without the timestamps: the
	// signatures in the results directory still hold them.
	if err := h.st.Update(func(st *store.State) error { st.Signed = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	h.restart()
	h.d.BuildStats(h.clock.Now())
	if got := ts(); got != t0+4 {
		t.Errorf("after a restore: %d, want %d", got, t0+4)
	}
	// Someone else's signature with a far future timestamp, put into the
	// results directory, doesn't move ours.
	other, _ := minisign.GenerateKey(nil)
	far := h.clock.Now().Add(1000 * 24 * time.Hour)
	forged, _ := minisign.Sign(other, []byte("x"), minisign.Trusted{Timestamp: far, File: "mlist2.txt", Expires: far.Add(time.Hour)}.String(), "")
	if err := os.WriteFile(filepath.Join(h.cfg.Paths.ResultsDir, "mlist2.txt.minisig"), forged, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Update(func(st *store.State) error { st.Signed = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	h.restart()
	h.d.BuildStats(h.clock.Now())
	if got := ts(); got != h.clock.Now().Unix() {
		t.Errorf("after a forged signature: %d, want the clock's %d", got, h.clock.Now().Unix())
	}
}

func TestSigningKeyErrors(t *testing.T) {
	h := newHarness(t, false)
	h.cfg.Signing.Enabled = true
	h.cfg.Signing.KeyFile = filepath.Join(h.dir, "pinger.key")
	if _, err := NewDaemon(h.cfg, h.st, h.mailer, nil, h.clock); err == nil || !strings.Contains(err.Error(), "go-echolot keygen") {
		t.Errorf("no key: %v", err)
	}
	k, _ := minisign.GenerateKey(nil)
	if err := os.WriteFile(h.cfg.Signing.KeyFile, k.File(), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDaemon(h.cfg, h.st, h.mailer, nil, h.clock); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("readable by the group: %v", err)
	}
	if err := WriteKeyFile(h.cfg.Signing.KeyFile, k); err == nil || !strings.Contains(err.Error(), "never overwrites") {
		t.Errorf("WriteKeyFile over a key: %v", err)
	}
	os.Chmod(h.cfg.Signing.KeyFile, 0o600)
	if _, err := NewDaemon(h.cfg, h.st, h.mailer, nil, h.clock); err != nil {
		t.Errorf("good key: %v", err)
	}
}

func TestPingerName(t *testing.T) {
	for in, want := range map[string]string{
		"mixmin":                "mixmin",
		"Test pinger":           "Test_pinger",
		"caf\u00e9\tx":          "caf___x", // é is two bytes
		strings.Repeat("a", 70): strings.Repeat("a", 64),
	} {
		if got := PingerName(in); got != want || !minisign.ValidValue(got) {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// TestNewKeyStartsAfresh: timestamps are kept per key, so a new key
// recovers from a clock that was once far ahead (design §9.5).
func TestNewKeyStartsAfresh(t *testing.T) {
	h := newHarness(t, false)
	h.withSigning()
	h.clock.Jump(365 * 24 * time.Hour) // the clock is a year ahead
	h.d.BuildStats(h.clock.Now())
	h.clock.Jump(-365 * 24 * time.Hour) // and fixed
	os.Remove(h.cfg.Signing.KeyFile)
	pub := h.withSigning() // a new key
	h.d.BuildStats(h.clock.Now())
	if got := h.verified(pub, "mlist2.txt").Timestamp; !got.Equal(h.clock.Now()) {
		t.Errorf("new key signed at %s, want the clock's %s", got, h.clock.Now())
	}
}
