package mailin

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
)

// rename is os.Rename; a test replaces it.
var rename = os.Rename

// moveToErrors moves src to ErrorsDir/<name> (or <name>.<n> if taken) and
// writes <that>.reason.  Across file systems it copies at most MaxSize
// bytes and then removes src.
func (s *Scanner) moveToErrors(src string, delivered, now time.Time, reason Reason, detail string) error {
	name := filepath.Base(src)
	dst := filepath.Join(s.ErrorsDir, name)
	for i := 1; taken(dst) || taken(dst+".reason"); i++ {
		if i > 1000 {
			return fmt.Errorf("no free name for %q in %s", sanitize(name, 80), s.ErrorsDir)
		}
		dst = filepath.Join(s.ErrorsDir, name+"."+strconv.Itoa(i))
	}
	err := rename(src, dst)
	if errors.Is(err, syscall.EXDEV) {
		var truncated bool
		truncated, err = copyFile(src, dst)
		if err == nil {
			if truncated {
				detail += " (copy cut to MaxSize)"
			}
			err = os.Remove(src)
		}
	}
	if err != nil {
		return err
	}
	// PruneErrors goes by mtime: count the retention from now, not from
	// the delivery.
	_ = os.Chtimes(dst, now, now)
	text := fmt.Sprintf("reason: %s\ndetail: %s\nfile: %s\ndelivered: %s\nmoved: %s\n",
		reason, detail, sanitize(name, 200),
		delivered.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	if err := fileutil.WriteAtomic(dst+".reason", []byte(text), 0o600); err != nil {
		s.Log.Error("mailin: writing reason", "file", sanitize(name, 80), "err", err)
	}
	if err := fileutil.SyncDir(filepath.Dir(src)); err != nil {
		s.Log.Error("mailin: fsync", "dir", filepath.Dir(src), "err", err)
	}
	return nil
}

// taken reports whether path exists (as anything, symlinks included).
func taken(path string) bool {
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// copyFile copies up to MaxSize bytes of src to a new file dst (0600),
// fsynced.  truncated is true if src was longer.
func copyFile(src, dst string) (truncated bool, err error) {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	n, err := io.Copy(out, io.LimitReader(in, MaxSize+1))
	if err == nil && n > MaxSize {
		truncated = true
		err = out.Truncate(MaxSize)
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dst)
		return false, err
	}
	return truncated, nil
}

// PruneErrors removes the regular files in dir whose mtime is more than
// maxAge before now, and returns how many it removed.  A missing dir is
// not an error.  Use ErrorRetention for maxAge.
func PruneErrors(dir string, now time.Time, maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	cut := now.Add(-maxAge)
	n := 0
	var firstErr error
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cut) {
			continue
		}
		err = os.Remove(filepath.Join(dir, e.Name()))
		switch {
		case err == nil:
			n++
		case !errors.Is(err, fs.ErrNotExist) && firstErr == nil:
			firstErr = err
		}
	}
	return n, firstErr
}
