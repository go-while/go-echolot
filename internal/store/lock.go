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
	Dir string
	PID int // 0 if the lock file doesn't say
}

func (e *LockedError) Error() string {
	if e.PID == 0 {
		return fmt.Sprintf("%s is in use by another go-echolot", e.Dir)
	}
	return fmt.Sprintf("go-echolot is already running (pid %d) with %s", e.PID, e.Dir)
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
			return nil, &LockedError{Dir: dir, PID: readPID(path)}
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

// readPID returns the PID in a lock file, or 0.
func readPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}
