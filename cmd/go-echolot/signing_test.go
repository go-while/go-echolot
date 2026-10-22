package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestSigningVerbs(t *testing.T) {
	cfg, stateDir := testConfig(t)
	code, out, errOut := runCmd("keygen", "--config", cfg)
	if code != 0 || !strings.Contains(out, "secret key written to "+filepath.Join(stateDir, "pinger.key")) {
		t.Fatalf("keygen: %d %q %q", code, out, errOut)
	}
	key := regexp.MustCompile(`(?m)^RW[A-Za-z0-9+/]{54}$`).FindString(out)
	if key == "" {
		t.Fatalf("keygen printed no public key: %q", out)
	}
	if fi, err := os.Stat(filepath.Join(stateDir, "pinger.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v, %v", fi.Mode(), err)
	}
	if code, _, errOut := runCmd("keygen", "--config", cfg); code != 1 || !strings.Contains(errOut, "never overwrites") {
		t.Errorf("second keygen: %d %q", code, errOut)
	}

	t0 := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return t0 }
	defer func() { now = time.Now }()
	file := filepath.Join(t.TempDir(), "pinger.pub")
	os.WriteFile(file, []byte("the new key\n"), 0o644)
	code, out, errOut = runCmd("sign", "--config", cfg, "--valid", "720h", file)
	if code != 0 || !strings.Contains(out, "timestamp:1792670400 file:pinger.pub pinger:t expires:1795262400") {
		t.Fatalf("sign: %d %q %q", code, out, errOut)
	}
	// Signing again in the same second still moves the timestamp on.
	if _, out, _ := runCmd("sign", "--config", cfg, file); !strings.Contains(out, "timestamp:1792670401 ") {
		t.Errorf("second sign: %q", out)
	}
	code, out, errOut = runCmd("verify", "--pub", key, file)
	if code != 0 || !strings.Contains(out, "good signature") {
		t.Errorf("verify: %d %q %q", code, out, errOut)
	}
	// --pub takes a file too.
	pubFile := filepath.Join(t.TempDir(), "k.pub")
	os.WriteFile(pubFile, []byte("untrusted comment: x\n"+key+"\n"), 0o644)
	if code, out, _ := runCmd("verify", "--pub", pubFile, file); code != 0 {
		t.Errorf("verify --pub file: %d %q", code, out)
	}
	now = func() time.Time { return t0.Add(49 * time.Hour) }
	if code, out, _ := runCmd("verify", "--pub", key, file); code != 1 || !strings.Contains(out, "expired") {
		t.Errorf("verify expired: %d %q", code, out)
	}
	now = func() time.Time { return t0 }
	os.WriteFile(file, []byte("another key\n"), 0o644)
	if code, out, _ := runCmd("verify", "--pub", key, file); code != 1 || !strings.Contains(out, "BAD") {
		t.Errorf("verify changed file: %d %q", code, out)
	}
	if code, _, _ := runCmd("sign", "--config", cfg); code != 2 {
		t.Errorf("sign without files: %d", code)
	}

	// The daemon's files are its own to sign.
	data, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, append(data, []byte("[signing]\nenabled = true\n")...), 0o644)
	www := filepath.Join(filepath.Dir(stateDir), "www")
	os.MkdirAll(www, 0o755)
	os.WriteFile(filepath.Join(www, "pubring.mix"), nil, 0o644)
	if code, _, errOut := runCmd("sign", "--config", cfg, filepath.Join(www, "pubring.mix")); code != 1 || !strings.Contains(errOut, "the daemon signs it") {
		t.Errorf("sign pubring.mix: %d %q", code, errOut)
	}
	// buildkeys signs and publishes pinger.pub; verify finds it there.
	if code, _, errOut := runCmd("buildkeys", "--config", cfg); code != 0 {
		t.Fatalf("buildkeys: %d %q", code, errOut)
	}
	code, out, errOut = runCmd("verify", "--config", cfg, filepath.Join(www, "pubring.mix"), filepath.Join(www, "type2.list"))
	if code != 0 || strings.Count(out, "good signature") != 2 {
		t.Errorf("verify --config: %d %q %q", code, out, errOut)
	}
}
