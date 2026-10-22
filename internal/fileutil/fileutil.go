// Package fileutil writes files so that a crash leaves either the old or
// the new content, never a mix (design §5.3).
package fileutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// tempMarker is in the name of every temporary file WriteAtomic makes.
const tempMarker = ".tmp-"

// rename and syncDir are os.Rename and SyncDir; tests replace them.
var (
	rename  = os.Rename
	syncDir = SyncDir
)

// ErrDirSync is in the error of a WriteAtomic whose rename worked but
// whose directory fsync failed: the file has the new data, which may not
// survive a power loss.
var ErrDirSync = errors.New("fsync of the directory failed after the rename")

// WriteAtomic writes data to path: to a temporary file in the same
// directory, fsync, rename over path, then fsync the directory.  After a
// crash path has the old or the new data.  A leftover temporary file is
// named ".<name>.tmp-*"; RemoveTemps removes those.
//
// On an error that matches ErrDirSync, path already has the new data.  On
// any other error it has the old.
func WriteAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir, name := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+name+tempMarker+"*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = rename(tmp, path); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%w: %w", ErrDirSync, err)
	}
	return nil
}

// SyncDir fsyncs a directory, so that renames and new files in it are
// durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// RemoveTemps removes the temporary files WriteAtomic left in dir when it
// was interrupted.  Call it only while no WriteAtomic runs in dir.
func RemoveTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if n := e.Name(); e.Type().IsRegular() && strings.HasPrefix(n, ".") && strings.Contains(n, tempMarker) {
			if err := os.Remove(filepath.Join(dir, n)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
