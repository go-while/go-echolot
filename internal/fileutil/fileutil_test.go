package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	for _, data := range []string{"one", "two, longer"} {
		if err := WriteAtomic(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != data {
			t.Errorf("got %q, %v; want %q", got, err, data)
		}
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", fi.Mode(), err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary files left: %v", entries)
	}
}

// TestWriteAtomicCrash simulates a crash before the rename: the old file
// is unchanged, and RemoveTemps cleans up the temporary file.
func TestWriteAtomicCrash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := WriteAtomic(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("crash")
	var left string
	rename = func(from, to string) error { left = from; return crash }
	defer func() { rename = os.Rename }()
	if err := WriteAtomic(path, []byte("new"), 0o600); !errors.Is(err, crash) {
		t.Fatalf("got %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old" {
		t.Errorf("after a failed write: %q", got)
	}
	// A failed WriteAtomic removes its own temporary file.  A crash
	// doesn't, so put one back as a crash would leave it.
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Errorf("temporary file %s kept after an error", left)
	}
	if err := os.WriteFile(left, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "notes.tmp-1") // not ours: no leading dot
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTemps(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Errorf("RemoveTemps kept %s", left)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("RemoveTemps removed %s", other)
	}
}

func TestWriteAtomicNoDir(t *testing.T) {
	if err := WriteAtomic(filepath.Join(t.TempDir(), "nosuch", "f"), nil, 0o600); err == nil {
		t.Error("no error for a missing directory")
	}
}

// TestWriteAtomicDirSync checks that a failed directory fsync after the
// rename is reported as ErrDirSync, with the new data in place.
func TestWriteAtomicDirSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	syncDir = func(string) error { return errors.New("EIO") }
	defer func() { syncDir = SyncDir }()
	err := WriteAtomic(path, []byte("new"), 0o600)
	if !errors.Is(err, ErrDirSync) {
		t.Fatalf("got %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Errorf("got %q", got)
	}
}
