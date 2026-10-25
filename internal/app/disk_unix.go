//go:build linux || darwin || freebsd

package app

import (
	"errors"
	"io/fs"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// diskFree returns the share and the bytes of the file system of path
// that are free for an unprivileged user.  A directory not made yet is on
// the file system of its nearest parent.
func diskFree(path string) (float64, uint64, error) {
	var s unix.Statfs_t
	for {
		err := unix.Statfs(path, &s)
		if err == nil {
			break
		}
		parent := filepath.Dir(path)
		if !errors.Is(err, fs.ErrNotExist) || parent == path {
			return 0, 0, err
		}
		path = parent
	}
	bytes := uint64(s.Bavail) * uint64(s.Bsize)
	if s.Blocks == 0 {
		return 1, bytes, nil
	}
	return float64(s.Bavail) / float64(s.Blocks), bytes, nil
}
