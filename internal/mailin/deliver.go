package mailin

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
)

// Errors of Deliver that retrying won't fix.
var (
	ErrTooLarge     = errors.New("mail is larger than the limit")
	ErrBadRecipient = errors.New("original recipient has control characters or is too long")
)

// maxRcpt keeps the added header line well under 998 bytes.
const maxRcpt = 900

// Deliver writes the mail read from r into maildir (`go-echolot deliver`
// from .forward, §10.1 b) and returns the new file's path in new/.
//
// It reads at most MaxSize bytes, writes tmp/<unique> (0600), fsyncs it,
// links it into new/ and fsyncs new/: the scanner never sees a partial
// file.  A leading mbox "From " line, which Postfix's local(8) adds for
// commands, is dropped.  If env("ORIGINAL_RECIPIENT") is set (Postfix;
// else env("RECIPIENT")), "X-Original-To: <value>" is prepended unless
// the mail already has an X-Original-To with that value; a sender's own
// X-Original-To must not hide the real recipient.  The cur/, new/ and
// tmp/ directories are created (0700) if missing.  env may be nil.
//
// Exit codes for the command (sysexits.h): ErrTooLarge and
// ErrBadRecipient are permanent, exit 65 (EX_DATAERR) and the MTA
// bounces; any other error is local trouble (disk full, permissions),
// exit 75 (EX_TEMPFAIL) and the MTA keeps the mail queued and retries.
// Better still, set the MTA's own size limit (Postfix message_size_limit)
// below MaxSize so oversized mail is refused during SMTP.
func Deliver(maildir string, r io.Reader, env func(string) string, now time.Time) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil {
		return "", fmt.Errorf("deliver: reading mail: %w", err)
	}
	if len(data) > MaxSize {
		return "", ErrTooLarge
	}
	if bytes.HasPrefix(data, []byte("From ")) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	if env == nil {
		env = func(string) string { return "" }
	}
	rcpt := env("ORIGINAL_RECIPIENT")
	if rcpt == "" {
		rcpt = env("RECIPIENT")
	}
	if rcpt != "" {
		if len(rcpt) > maxRcpt || strings.ContainsFunc(rcpt, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return "", ErrBadRecipient
		}
		if !hasHeader(data, "X-Original-To", rcpt) {
			eol := "\n"
			if i := bytes.IndexByte(data, '\n'); i > 0 && data[i-1] == '\r' {
				eol = "\r\n"
			}
			data = append([]byte("X-Original-To: "+rcpt+eol), data...)
		}
		if len(data) > MaxSize {
			return "", ErrTooLarge
		}
	}

	for _, sub := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildir, sub), 0o700); err != nil {
			return "", fmt.Errorf("deliver: %w", err)
		}
	}
	name, err := uniqueName(now)
	if err != nil {
		return "", err
	}
	tmp := filepath.Join(maildir, "tmp", name)
	dst := filepath.Join(maildir, "new", name)
	if err := writeSynced(tmp, data); err != nil {
		return "", fmt.Errorf("deliver: %w", err)
	}
	defer os.Remove(tmp)
	_ = os.Chtimes(tmp, now, now) // the scanner takes the delivery time from mtime
	if err := os.Link(tmp, dst); err != nil {
		// Some file systems have no hard links; the name is unique anyway.
		if errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("deliver: %w", err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			return "", fmt.Errorf("deliver: %w", err)
		}
	}
	if err := fileutil.SyncDir(filepath.Join(maildir, "new")); err != nil {
		return "", fmt.Errorf("deliver: %w", err)
	}
	return dst, nil
}

// writeSynced creates path (0600, must not exist), writes data and fsyncs.
func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// uniqueName returns a Maildir name: <sec>.M<usec>P<pid>R<random>.<host>.
func uniqueName(now time.Time) (string, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", err
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	// The Maildir convention for "/" and ":", plus no dot-prefix or
	// control characters.
	host = strings.NewReplacer("/", `\057`, ":", `\072`).Replace(host)
	host = strings.Map(func(r rune) rune {
		if r <= 0x20 || r >= 0x7f {
			return '_'
		}
		return r
	}, host)
	return fmt.Sprintf("%d.M%dP%dR%s.%s", now.Unix(), now.Nanosecond()/1000, os.Getpid(),
		hex.EncodeToString(rnd[:]), host), nil
}

// hasHeader reports whether the header block of data has a field name
// whose value (unfolded, trimmed) equals value, ignoring case.  It
// doesn't need the mail to parse.
func hasHeader(data []byte, name, value string) bool {
	var field []byte // current field, unfolded
	check := func() bool {
		k, v, ok := bytes.Cut(field, []byte(":"))
		return ok && strings.EqualFold(string(bytes.TrimSpace(k)), name) &&
			strings.EqualFold(string(bytes.TrimSpace(v)), value)
	}
	for line := range bytes.Lines(data) {
		l := bytes.TrimRight(line, "\r\n")
		if len(l) == 0 {
			break
		}
		if l[0] == ' ' || l[0] == '\t' {
			field = append(append(field, ' '), bytes.TrimSpace(l)...)
			continue
		}
		if check() {
			return true
		}
		field = append(field[:0], l...)
	}
	return check()
}
