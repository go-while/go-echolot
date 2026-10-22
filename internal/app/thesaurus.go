package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
	"github.com/go-while/go-echolot/internal/token"
)

// The thesaurus keeps the last raw reply of each kind per remailer, as
// Echolot's (E:Thesaurus.pm:40-58): state_dir/thesaurus/<id>.<kind>.  The
// file's mtime is the token time of the reply (when we asked), so a late
// reply to an older request never replaces a newer one.  Phase 3
// publishes it as HTML.

const thesaurusDir = "thesaurus"

// thesaurusMaxAge is how long a reply is kept (design §5.1).
const thesaurusMaxAge = 21 * 24 * time.Hour

// SaveThesaurus stores body as the last reply of kind from remailer id,
// asked at the token time asked, unless a reply to a later request is
// stored already.
func SaveThesaurus(stateDir string, id int, kind token.Kind, body []byte, asked time.Time) error {
	dir := filepath.Join(stateDir, thesaurusDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.%s", id, kind))
	if fi, err := os.Stat(path); err == nil && !asked.After(fi.ModTime()) {
		return nil
	}
	if err := fileutil.WriteAtomic(path, body, 0o600); err != nil {
		return err
	}
	return os.Chtimes(path, asked, asked)
}

// PruneThesaurus removes replies older than 21 days and those of remailers
// that are gone (known reports whether an ID still exists).  It returns
// how many it removed.
func PruneThesaurus(stateDir string, now time.Time, known func(id int) bool) (int, error) {
	dir := filepath.Join(stateDir, thesaurusDir)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		idText, _, _ := strings.Cut(e.Name(), ".")
		id, err := strconv.Atoi(idText)
		fi, ierr := e.Info()
		if err == nil && ierr == nil && known(id) && now.Sub(fi.ModTime()) <= thesaurusMaxAge {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			n++
		}
	}
	return n, nil
}
