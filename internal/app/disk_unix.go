//go:build linux || darwin || freebsd

package app

import "golang.org/x/sys/unix"

// diskFree returns the share of the file system of path that is free
// for an unprivileged user.
func diskFree(path string) (float64, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return 0, err
	}
	if s.Blocks == 0 {
		return 1, nil
	}
	return float64(s.Bavail) / float64(s.Blocks), nil
}
