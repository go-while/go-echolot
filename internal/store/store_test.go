package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/civil"
	"github.com/go-while/go-echolot/internal/fileutil"
)

// t0 is a fixed time for tests.
var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func open(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenNew(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := open(t, dir)
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state dir: %v, %v", fi.Mode(), err)
	}
	fi, err = os.Stat(filepath.Join(dir, "secret"))
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 65 {
		t.Errorf("secret: %v %d, %v", fi.Mode(), fi.Size(), err)
	}
	secret := s.Secret()
	if len(secret) != 32 || bytes.Equal(secret, make([]byte, 32)) {
		t.Errorf("secret %x", secret)
	}
	s.View(func(st *State) {
		if st.Version != StateVersion || st.MaxID != 0 || st.Remailers == nil {
			t.Errorf("new state: %+v", st)
		}
	})
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Error("state.json written before any change")
	}
	s.Close()
	s = open(t, dir)
	if !bytes.Equal(s.Secret(), secret) {
		t.Error("secret changed on reopen")
	}
}

func TestSecretChecks(t *testing.T) {
	dir := t.TempDir()
	open(t, dir).Close()
	path := filepath.Join(dir, "secret")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("group-readable secret: %v", err)
	}
	if err := os.WriteFile(path, []byte("abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); err == nil || !strings.Contains(err.Error(), "64 hex digits") {
		t.Errorf("short secret: %v", err)
	}
	// A failed Open releases the lock.
	os.Remove(path)
	open(t, dir)
}

func TestLock(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	_, err := Open(dir, nil)
	var le *LockedError
	if !errors.As(err, &le) || le.PID != os.Getpid() || le.Dir != dir {
		t.Fatalf("second Open: %v", err)
	}
	if want := "already running (pid "; !strings.Contains(err.Error(), want) {
		t.Errorf("message %q", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	open(t, dir)
}

func TestLockedErrorNoPID(t *testing.T) {
	err := &LockedError{Dir: "/x"}
	if err.Error() != "/x is in use by another go-echolot" {
		t.Error(err)
	}
}

func sampleState() *State {
	st := newState()
	r, _ := st.AddRemailer("yamn@mixmin.net", t0)
	r.Nick = "yamn"
	r.Conf = &Conf{Nick: "yamn", Type: "Mixmaster", Caps: `$remailer{"yamn"} = "<yamn@mixmin.net> mid"`,
		LastUpdate: t0, Received: t0.Add(time.Minute)}
	r.Keys = map[string]*Key{"a1b2": {
		KeyID: "a1b2", Nick: "yamn", Address: "yamn@mixmin.net", Version: "4:0.2.7", Caps: "C",
		Created: civil.Date{Year: 2026, Month: 10, Day: 20}, Expires: civil.Date{Year: 2026, Month: 11, Day: 3},
		PK: PublicKey{1, 2, 3, 255}, FirstSeen: t0, LastSeen: t0, LastReceived: t0, Sightings: 1, State: KeyStateActive,
	}}
	st.AddRemailer("frell@frell.eu.org", t0)
	st.Prospective = map[string][]Suggestion{"new@example.org": {{Time: t0, Reason: "listed", Source: "yamn"}}}
	st.Pending = []PendingChange{{Address: "yamn@mixmin.net", Kind: PendingKeyChange, Old: "a1b2", New: "c3d4", Since: t0}}
	st.Fromlines = map[string]map[int]Fromline{"yamn@mixmin.net": {1: {LastUpdate: t0, From: "Anonymous"}}}
	return st
}

func TestUpdate(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	want := sampleState()
	if err := s.Update(func(st *State) error { *st = *sampleState(); return nil }); err != nil {
		t.Fatal(err)
	}
	snap, err := Snapshot(dir) // without the lock, while s is open
	if err != nil || !reflect.DeepEqual(snap, want) {
		t.Errorf("Snapshot: %v\n%+v", err, snap)
	}
	s.Close()
	s = open(t, dir)
	s.View(func(st *State) {
		if !reflect.DeepEqual(st, want) {
			t.Errorf("reopened state differs:\n%+v", st)
		}
		if r := st.RemailerByID(2); r == nil || r.Address != "frell@frell.eu.org" || st.RemailerByID(3) != nil {
			t.Errorf("RemailerByID: %+v", r)
		}
	})
	data, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	for _, s := range []string{`"pk": "010203ff00`, `"created": "2026-10-20"`, `"proven_at": "0001-01-01T00:00:00Z"`, `"status": "active"`} {
		if !bytes.Contains(data, []byte(s)) {
			t.Errorf("state.json lacks %s:\n%s", s, data)
		}
	}
}

func TestAddRemailer(t *testing.T) {
	st := newState()
	a, _ := st.AddRemailer("a@example.org", t0)
	b, _ := st.AddRemailer("b@example.org", t0)
	if a.ID != 1 || b.ID != 2 || !a.Fetch || !a.PingIt || !a.ShowIt || a.TTL != 5 || a.ResurrectionTTL != 8 || a.Status != StatusActive {
		t.Errorf("%+v %+v", a, b)
	}
	if _, err := st.AddRemailer("a@example.org", t0); err == nil {
		t.Error("added twice")
	}
	delete(st.Remailers, "b@example.org")
	if c, _ := st.AddRemailer("c@example.org", t0); c.ID != 3 {
		t.Errorf("ID of a deleted remailer reused: %d", c.ID)
	}
}

// countWrites counts the state.json writes, and fails them while fail is
// set.
func countWrites(t *testing.T, fail *bool) *int {
	n := new(int)
	writeFile = func(path string, data []byte, perm fs.FileMode) error {
		if *fail {
			return errors.New("disk full")
		}
		*n++
		return os.WriteFile(path, data, perm)
	}
	t.Cleanup(func() { writeFile = origWriteFile })
	return n
}

var origWriteFile = writeFile

func TestUpdateRollback(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	fail := false
	writes := countWrites(t, &fail)
	add := func(addr string) func(*State) error {
		return func(st *State) error { _, err := st.AddRemailer(addr, t0); return err }
	}
	if err := s.Update(add("a@example.org")); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "state.json"))

	// fn fails after changing the state.
	err := s.Update(func(st *State) error {
		st.Remailers["a@example.org"].Nick = "changed"
		st.AddRemailer("b@example.org", t0)
		return errors.New("no")
	})
	if err == nil || err.Error() != "no" {
		t.Fatal(err)
	}
	// The write fails.
	fail = true
	if err := s.Update(add("c@example.org")); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatal(err)
	}
	fail = false
	s.View(func(st *State) {
		if len(st.Remailers) != 1 || st.MaxID != 1 || st.Remailers["a@example.org"].Nick != "" {
			t.Errorf("not rolled back: %+v", st)
		}
	})
	if after, _ := os.ReadFile(filepath.Join(dir, "state.json")); !bytes.Equal(before, after) {
		t.Error("state.json changed")
	}
	// No change, no write.
	if err := s.Update(func(*State) error { return nil }); err != nil || *writes != 1 {
		t.Errorf("no-op Update: %v, %d writes", err, *writes)
	}
	s.Close()
	if err := s.Update(add("d@example.org")); err == nil {
		t.Error("Update after Close")
	}
}

func TestStateErrors(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ data, want string }{
		{`{"version":2,"remailers":{}}`, "state version 2"},
		{`{"version":1`, "unexpected end"},
		{`{"version":1,"remailers":{"a":{"keys":{"k":{"pk":"00"}}}}}`, "want 64 hex digits"},
	} {
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(tc.data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.data, err)
		}
		if _, err := Snapshot(dir); err == nil {
			t.Errorf("Snapshot of %s", tc.data)
		}
	}
	snap, err := Snapshot(t.TempDir())
	if err != nil || snap.Version != StateVersion || len(snap.Remailers) != 0 {
		t.Errorf("Snapshot without state.json: %+v, %v", snap, err)
	}
}

// TestOpenRemovesTemps checks that Open removes the temporary file of a
// write a crash interrupted.
func TestOpenRemovesTemps(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".state.json.tmp-123")
	if err := os.WriteFile(tmp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	open(t, dir)
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("temporary file kept")
	}
}

func TestConcurrent(t *testing.T) {
	s := open(t, t.TempDir())
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 20 {
				p, err := s.NewPing("a@example.org", "k", false, t0)
				if err != nil {
					t.Error(err)
					return
				}
				s.PingDone(p.ID, t0.Add(time.Minute), 60)
				s.Update(func(st *State) error { st.MaxID = i*100 + j; return nil })
				s.View(func(st *State) { _ = st.MaxID })
				s.Pings("a@example.org", time.Time{})
			}
		})
	}
	wg.Wait()
	if _, done := s.Pings("a@example.org", time.Time{}); len(done) != 160 {
		t.Errorf("%d pings done, want 160", len(done))
	}
}

// logBuffer returns a logger that writes to the returned buffer.
func logBuffer() (*slog.Logger, *bytes.Buffer) {
	var b bytes.Buffer
	return slog.New(slog.NewTextHandler(&b, nil)), &b
}

// dirSyncFails makes writeFile write the file, then fail the directory
// fsync.
func dirSyncFails(t *testing.T) {
	writeFile = func(path string, data []byte, perm fs.FileMode) error {
		if err := os.WriteFile(path, data, perm); err != nil {
			return err
		}
		return fmt.Errorf("%w: EIO", fileutil.ErrDirSync)
	}
	t.Cleanup(func() { writeFile = origWriteFile })
}

// TestUpdateDirSyncFails: state.json was replaced, so the change stays,
// in memory as on disk.
func TestUpdateDirSyncFails(t *testing.T) {
	dir := t.TempDir()
	log, buf := logBuffer()
	s, err := Open(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dirSyncFails(t)
	if err := s.Update(func(st *State) error { _, err := st.AddRemailer("a@example.org", t0); return err }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "may not survive a power loss") {
		t.Errorf("not logged: %s", buf)
	}
	snap, _ := Snapshot(dir)
	s.View(func(st *State) {
		if st.MaxID != 1 || snap.MaxID != 1 {
			t.Errorf("memory %d, disk %d", st.MaxID, snap.MaxID)
		}
	})
}

func TestUpdatePanics(t *testing.T) {
	s := open(t, t.TempDir())
	func() {
		defer func() { recover() }()
		s.Update(func(st *State) error {
			st.AddRemailer("a@example.org", t0)
			panic("bug")
		})
	}()
	s.View(func(st *State) {
		if st.MaxID != 0 || len(st.Remailers) != 0 {
			t.Errorf("not rolled back after a panic: %+v", st)
		}
	})
}
