package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
)

// The command spool (design §5.4): while the daemon holds the state lock,
// a mutating command is written to state_dir/commands/ (atomically), and
// the daemon is sent SIGHUP.  The daemon also looks every 10 seconds.
// This keeps Echolot's commands.txt + HUP model without a shared file.

const spoolDir = "commands"

// spoolExt names complete command files; WriteAtomic's temporary files
// start with a dot and are skipped.
const spoolExt = ".json"

// Spool writes c for the daemon of stateDir.
func Spool(stateDir string, c Command, now time.Time) error {
	dir := filepath.Join(stateDir, spoolDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var r [4]byte
	rand.Read(r[:])
	// The name sorts by time, so commands run in the order given.
	name := fmt.Sprintf("%020d-%s%s", now.UnixNano(), hex.EncodeToString(r[:]), spoolExt)
	return fileutil.WriteAtomic(filepath.Join(dir, name), append(data, '\n'), 0o600)
}

// Spooled is a command read from the spool.
type Spooled struct {
	Command
	Path string
}

// ReadSpool returns the spooled commands of stateDir, oldest first.  A
// file that isn't a command is renamed to <name>.bad and reported, so it
// isn't read again.
func ReadSpool(stateDir string) ([]Spooled, []error) {
	dir := filepath.Join(stateDir, spoolDir)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, []error{err}
	}
	var (
		out  []Spooled
		errs []error
	)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if n := e.Name(); e.Type().IsRegular() && !strings.HasPrefix(n, ".") && strings.HasSuffix(n, spoolExt) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	for _, n := range names {
		path := filepath.Join(dir, n)
		data, err := os.ReadFile(path)
		var c Command
		if err == nil {
			err = json.Unmarshal(data, &c)
		}
		if err == nil && c.Verb == "" {
			err = fmt.Errorf("no verb")
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("spooled command %s: %w", n, err))
			os.Rename(path, path+".bad")
			continue
		}
		out = append(out, Spooled{Command: c, Path: path})
	}
	return out, errs
}

// Done removes a spooled command after the daemon ran it.
func (s Spooled) Done() error { return os.Remove(s.Path) }
