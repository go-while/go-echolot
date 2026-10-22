package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// LockedError is returned by Open when another process holds the state
// dir: usually the running daemon (design §5.4).
type LockedError struct {
	Dir    string
	PID    int  // 0 if the lock file doesn't say
	Daemon bool // the holder is `go-echolot run` (Store.MarkDaemon), not a CLI command
}

func (e *LockedError) Error() string {
	switch {
	case e.PID == 0:
		return fmt.Sprintf("%s is in use by another go-echolot", e.Dir)
	case e.Daemon:
		return fmt.Sprintf("go-echolot is already running (pid %d) with %s", e.PID, e.Dir)
	}
	return fmt.Sprintf("%s is in use by another go-echolot command (pid %d); try again", e.Dir, e.PID)
}

// lock takes the exclusive lock on dir/lock and writes our PID into it.
// The lock lasts until the returned file is closed, or the process ends.
func lock(dir string) (*os.File, error) {
	path := filepath.Join(dir, "lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			pid, daemon := readLock(path)
			return nil, &LockedError{Dir: dir, PID: pid, Daemon: daemon}
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// readLock returns the PID in a lock file (0 if none) and whether it's a
// daemon's: "<pid>\n" or "<pid> daemon\n".
func readLock(path string) (pid int, daemon bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, false
	}
	pid, err = strconv.Atoi(f[0])
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, len(f) > 1 && f[1] == "daemon"
}

// MarkDaemon records in the lock file that this process is the daemon:
// only then do CLI commands spool for it and send it SIGHUP (design §5.4).
// Call it after SIGHUP is handled.
func (s *Store) MarkDaemon() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockF == nil {
		return errors.New("store is closed")
	}
	if err := s.lockF.Truncate(0); err != nil {
		return err
	}
	_, err := s.lockF.WriteAt([]byte(strconv.Itoa(os.Getpid())+" daemon\n"), 0)
	return err
}
