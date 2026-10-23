package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/health"
)

func TestCheck(t *testing.T) {
	cfg, stateDir := testConfig(t)
	results := filepath.Join(filepath.Dir(stateDir), "www")
	t0 := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return t0 }
	defer func() { now = time.Now }()

	code, out, _ := runCmd("check", "--config", cfg)
	if code != 2 || !strings.HasPrefix(out, "GO-ECHOLOT CRITICAL - ") || !strings.Contains(out, "is the daemon running?") {
		t.Errorf("no status.json: %d %q", code, out)
	}
	write := func(gen time.Time, checks ...health.Check) {
		t.Helper()
		js, err := health.NewReport("t", "v", gen, checks).JSON()
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(results, 0o755)
		if err := os.WriteFile(filepath.Join(results, "status.json"), js, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ok := health.Check{Name: "mailbox_scan", State: health.OK, Detail: "last good scan 10s ago"}
	write(t0.Add(-time.Minute), ok)
	code, out, _ = runCmd("check", "--config", cfg)
	if code != 0 || !strings.HasPrefix(out, "GO-ECHOLOT OK - 2 checks ok\ngo-echolot health: OK\n") ||
		!strings.Contains(out, "ok    status_age         status.json written 1m ago\n") {
		t.Errorf("ok: %d %q", code, out)
	}
	write(t0.Add(-time.Minute), ok, health.Check{Name: "pending", State: health.Warn, Detail: "1 changes"},
		health.Check{Name: "bounces", State: health.Warn, Detail: "for a@b"})
	code, out, _ = runCmd("check", "--config", cfg)
	if code != 1 || !strings.HasPrefix(out, "GO-ECHOLOT WARNING - pending: 1 changes; bounces: for a@b\n") {
		t.Errorf("warn: %d %q", code, out)
	}
	write(t0.Add(-time.Minute), ok, health.Check{Name: "keys", State: health.Crit, Detail: "no keys published"})
	if code, out, _ = runCmd("check", "--config", cfg); code != 2 || !strings.HasPrefix(out, "GO-ECHOLOT CRITICAL - keys: no keys published\n") {
		t.Errorf("crit: %d %q", code, out)
	}
	// The daemon stopped writing it.
	write(t0.Add(-20*time.Minute), ok)
	if code, out, _ = runCmd("check", "--config", cfg); code != 1 || !strings.Contains(out, "status_age: status.json written 20m ago (is the daemon running?)") {
		t.Errorf("20m old: %d %q", code, out)
	}
	write(t0.Add(-time.Hour), ok)
	if code, _, _ = runCmd("check", "--config", cfg); code != 2 {
		t.Errorf("1h old: %d", code)
	}
	os.WriteFile(filepath.Join(results, "status.json"), []byte("{"), 0o644)
	if code, out, _ = runCmd("check", "--config", cfg); code != 2 || !strings.Contains(out, "GO-ECHOLOT CRITICAL") {
		t.Errorf("bad json: %d %q", code, out)
	}
	if code, _, _ = runCmd("check", "--config", cfg, "extra"); code != 2 {
		t.Errorf("extra argument: %d", code)
	}
}
