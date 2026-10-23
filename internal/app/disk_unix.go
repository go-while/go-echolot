//go:build linux || darwin || freebsd

package app

import (
	"errors"
	"io/fs"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// diskFree returns the share of the file system of path that is free
// for an unprivileged user.  A directory not made yet is on the file
// system of its nearest parent.
func diskFree(path string) (float64, error) {
	var s unix.Statfs_t
	for {
		err := unix.Statfs(path, &s)
		if err == nil {
			break
		}
		parent := filepath.Dir(path)
		if !errors.Is(err, fs.ErrNotExist) || parent == path {
			return 0, err
		}
		path = parent
	}
	if s.Blocks == 0 {
		return 1, nil
	}
	return float64(s.Bavail) / float64(s.Blocks), nil
}
