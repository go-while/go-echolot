// Package output writes the files a pinger publishes, byte-compatible with
// Echolot's (design §7).  So far: pubring.mix, type2.list and their .meta
// files.
//
// Every file is written atomically, and no line may be longer than
// MaxLineLen: yamn clients read these files with bufio.Scanner (64 KiB
// per line), and one overlong line loses the whole file for every client.
package output

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
)

// MaxLineLen is the longest line any output file may have (§7).
const MaxLineLen = 1024

// filePerm is the mode of published files: the web server reads them.
const filePerm fs.FileMode = 0o644

// checkLines returns an error if a line of data is longer than MaxLineLen.
func checkLines(name string, data []byte) error {
	for n := 1; len(data) > 0; n++ {
		line, rest, _ := bytes.Cut(data, []byte("\n"))
		if len(line) > MaxLineLen {
			return fmt.Errorf("%s: line %d is %d bytes, more than %d", name, n, len(line), MaxLineLen)
		}
		data = rest
	}
	return nil
}

// writeIfChanged writes data to dir/name unless the file already holds
// exactly data, so its mtime (the web server's Last-Modified) changes only
// with its content.  It reports whether it wrote.
func writeIfChanged(dir, name string, data []byte) (bool, error) {
	if err := checkLines(name, data); err != nil {
		return false, err
	}
	path := filepath.Join(dir, name)
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	return true, fileutil.WriteAtomic(path, data, filePerm)
}

// Meta returns the contents of a .meta file for Apache's mod_cern_meta
// (§7.2), as Echolot's write_meta_information (E:Tools.pm:195-225):
//
//	Expires: Thu, 22 Oct 2026 13:00:00 +0000
func Meta(expires time.Time) []byte {
	return []byte("Expires: " + expires.UTC().Format("Mon, 02 Jan 2006 15:04:05 +0000") + "\n")
}

// writeMeta writes dir/name.meta.  It's rewritten at every build, even
// when the file itself didn't change, so the expiry stays ahead.
func writeMeta(dir, name string, expires time.Time) error {
	return fileutil.WriteAtomic(filepath.Join(dir, name+".meta"), Meta(expires), filePerm)
}
