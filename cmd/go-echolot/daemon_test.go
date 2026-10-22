package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/store"
)

// testConfig writes a config with everything under a temp dir.
func testConfig(t *testing.T) (path, stateDir string) {
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	path = filepath.Join(dir, "config.ini")
	ini := fmt.Sprintf("[pinger]\nsitename = t\naddress = pinger@pinger.example.org\noperator_address = remops@example.org\n[paths]\nstate_dir = %s\nresults_dir = %s\n",
		stateDir, filepath.Join(dir, "www"))
	if err := os.WriteFile(path, []byte(ini), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, stateDir
}

func TestStateCommands(t *testing.T) {
	cfg, _ := testConfig(t)
	code, out, errOut := runCmd("add", "--config", cfg, "yamn@virebent.art", "victor")
	if code != 0 || !strings.Contains(out, "added yamn@virebent.art (id 1), nick victor pinned") {
		t.Fatalf("add: %d %q %q", code, out, errOut)
	}
	code, _, errOut = runCmd("add", "--config", cfg, "yamn@virebent.art")
	if code != 1 || !strings.Contains(errOut, "already known") {
		t.Errorf("add twice: %d %q", code, errOut)
	}
	runCmd("disable", "--config", cfg, "yamn@virebent.art")
	code, out, _ = runCmd("status", "--config", cfg)
	if code != 0 || !strings.Contains(out, "victor yamn@virebent.art  id 1  disabled") {
		t.Errorf("status: %d %q", code, out)
	}
	code, out, _ = runCmd("keys", "--config", cfg, "yamn@virebent.art")
	if code != 0 || !strings.Contains(out, "victor") {
		t.Errorf("keys: %d %q", code, out)
	}
	if code, _, _ := runCmd("keys", "--config", cfg); code != 2 {
		t.Errorf("keys without address: %d", code)
	}
	if code, _, _ := runCmd("buildkeys", "--config", cfg, "x"); code != 2 {
		t.Errorf("buildkeys with an argument: %d", code)
	}
	if code, out, errOut := runCmd("buildkeys", "--config", cfg); code != 0 || !strings.Contains(out, "keyrings built") {
		t.Errorf("buildkeys: %d %q %q", code, out, errOut)
	}
}

// TestSpoolWhileRunning: with the state dir locked (as by the daemon), a
// command is checked, spooled, and the lock holder gets SIGHUP.
func TestSpoolWhileRunning(t *testing.T) {
	cfg, stateDir := testConfig(t)
	st, err := store.Open(stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP) // the "daemon" is this process
	defer signal.Stop(hup)
	code, out, errOut := runCmd("add", "--config", cfg, "yamn@virebent.art")
	if code != 0 || !strings.Contains(out, fmt.Sprintf("queued for the running daemon (pid %d)", os.Getpid())) {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	select {
	case <-hup:
	case <-time.After(5 * time.Second):
		t.Error("no SIGHUP")
	}
	files, _ := filepath.Glob(filepath.Join(stateDir, "commands", "*.json"))
	if len(files) != 1 {
		t.Errorf("spool: %v", files)
	}
	// A bad command is refused at once, not spooled.
	if code, _, errOut := runCmd("delete", "--config", cfg, "nosuch@x.org"); code != 1 || !strings.Contains(errOut, "not a known remailer") {
		t.Errorf("bad command: %d %q", code, errOut)
	}
}

func TestDeliver(t *testing.T) {
	cfg, stateDir := testConfig(t)
	defer func() { stdin = os.Stdin }()
	stdin = strings.NewReader("From: a@b\nSubject: x\n\nhello\n")
	if code, _, errOut := runCmd("deliver", "--config", cfg); code != 0 {
		t.Fatalf("deliver: %d %q", code, errOut)
	}
	files, _ := filepath.Glob(filepath.Join(stateDir, "Maildir", "new", "*"))
	if len(files) != 1 {
		t.Errorf("Maildir: %v", files)
	}
	stdin = strings.NewReader(strings.Repeat("x", 2<<20))
	if code, _, _ := runCmd("deliver", "--config", cfg); code != 65 {
		t.Errorf("oversized: exit %d, want 65", code)
	}
	if code, _, _ := runCmd("deliver", "--config", filepath.Join(t.TempDir(), "nosuch.ini")); code != 75 {
		t.Errorf("no config: exit %d, want 75", code)
	}
}
