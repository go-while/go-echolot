//go:build !(linux || darwin || freebsd)

package app

import "errors"

func diskFree(string) (float64, error) {
	return 0, errors.New("free space unknown on this system")
}
