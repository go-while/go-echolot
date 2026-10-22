package output

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteSignature(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	var calls []string
	sign := func(name string, data []byte) ([]byte, error) {
		// The file is on disk, with exactly these bytes, before its
		// signature is made.
		disk, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(disk, data) {
			t.Errorf("%s: signed before it was written", name)
		}
		calls = append(calls, name)
		if name == "type2.list" || name == "mlist.txt" {
			return nil, nil // not signed
		}
		return []byte("sig of " + name + "\n"), nil
	}
	// Stale signatures of unsigned files go.
	for _, n := range []string{"type2.list", "mlist.txt"} {
		os.WriteFile(filepath.Join(dir, n+SigSuffix), []byte("old"), 0o644)
	}
	if _, err := WriteKeyrings(dir, nil, now, false, 0, sign); err != nil {
		t.Fatal(err)
	}
	// Unchanged keyrings are signed again: the signature stays fresh.
	if _, err := WriteKeyrings(dir, nil, now, false, 0, sign); err != nil {
		t.Fatal(err)
	}
	if err := WriteStats(dir, nil, Sections{}, now, false, false, sign); err != nil {
		t.Fatal(err)
	}
	want := []string{"pubring.mix", "type2.list", "pubring.mix", "type2.list", "mlist2.txt", "mlist.txt"}
	if len(calls) != len(want) {
		t.Fatalf("calls %q, want %q", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls %q, want %q", calls, want)
		}
	}
	for name, signed := range map[string]bool{"pubring.mix": true, "type2.list": false, "mlist2.txt": true, "mlist.txt": false} {
		b, err := os.ReadFile(filepath.Join(dir, name+SigSuffix))
		switch {
		case signed && string(b) != "sig of "+name+"\n":
			t.Errorf("%s: %q, %v", name, b, err)
		case !signed && !errors.Is(err, os.ErrNotExist):
			t.Errorf("%s: signature not removed", name)
		}
	}
	// Without a SignFunc, every signature goes.
	if err := WriteStats(dir, nil, Sections{}, now, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mlist2.txt"+SigSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Error("mlist2.txt.minisig not removed")
	}
	// A signing error is returned.
	boom := errors.New("boom")
	if _, err := WriteKeyrings(dir, nil, now, false, 0, func(string, []byte) ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Errorf("sign error: %v", err)
	}
}
