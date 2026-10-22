package mailin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/mail"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
	"github.com/go-while/go-echolot/internal/token"
)

// Scanner processes the mail in Maildir/new.  Set the exported fields
// before the first Scan.  Only one Scanner may run per Maildir (the
// state-dir lock ensures that); Scan itself is serialized.
//
// Transient handler errors: a file stays in new/ and is retried on each
// scan until it has failed in MaxTries scans, or RetryFor has passed
// since its first failure; then it goes to the errors directory.  The
// counts are kept in memory, so a restart gives every file a new budget.
// The backstop is the token's age limit (7 or 12 days): an older token
// fails verification and the file goes to the errors directory.
//
// A handler panic is recovered and treated as a permanent error, so one
// mail can't crash-loop the daemon.
type Scanner struct {
	Maildir   string        // has new/, cur/, tmp/
	ErrorsDir string        // state_dir/mail-errors; created if missing
	Minter    *token.Minter // checks the tokens
	Handler   Handler
	Log       *slog.Logger     // nil: discard
	Now       func() time.Time // nil: time.Now
	MaxTries  int              // 0: DefaultMaxTries
	RetryFor  time.Duration    // 0: DefaultRetryFor

	mu       sync.Mutex
	failures map[string]*failure // by file name

	// beforeUnlink is a test hook: returning false simulates a crash
	// after the handler and before the unlink.
	beforeUnlink func(path string) bool
}

type failure struct {
	n     int
	first time.Time
}

// Result counts what a Scan did.
type Result struct {
	Handled  int // handled and deleted
	Rejected int // moved to the errors directory
	Pending  int // kept for the next scan
}

type outcome int

const (
	skipped outcome = iota
	handled
	rejected
	pending
	crashed
)

// errCrash is returned by Scan when the test hook simulated a crash.
var errCrash = errors.New("mailin: simulated crash")

// Scan processes each regular file in new/ once, oldest first.  Names
// starting with "." and anything that isn't a regular file (symlinks
// included) are left alone.  The error is about the directories or ctx,
// not about single mails; those are logged and counted.
func (s *Scanner) Scan(ctx context.Context) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == nil {
		s.failures = make(map[string]*failure)
	}
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	var res Result
	newDir := filepath.Join(s.Maildir, "new")
	entries, err := os.ReadDir(newDir)
	if err != nil {
		return res, fmt.Errorf("mailin: %w", err)
	}
	if err := os.MkdirAll(s.ErrorsDir, 0o700); err != nil {
		return res, fmt.Errorf("mailin: %w", err)
	}

	type item struct {
		name  string
		mtime time.Time
	}
	items := make([]item, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if name == "" || name[0] == '.' || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // gone meanwhile
		}
		items = append(items, item{name, info.ModTime()})
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].mtime.Equal(items[j].mtime) {
			return items[i].mtime.Before(items[j].mtime)
		}
		return items[i].name < items[j].name
	})

	seen := make(map[string]bool, len(items))
	removed := false
	defer func() {
		if removed {
			if err := fileutil.SyncDir(newDir); err != nil {
				s.Log.Error("mailin: fsync", "dir", newDir, "err", err)
			}
		}
	}()
	for _, it := range items {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		seen[it.name] = true
		switch s.one(ctx, filepath.Join(newDir, it.name), now) {
		case handled:
			res.Handled++
			removed = true
		case rejected:
			res.Rejected++
		case pending:
			res.Pending++
		case crashed:
			return res, errCrash
		}
	}
	for name := range s.failures {
		if !seen[name] {
			delete(s.failures, name)
		}
	}
	return res, nil
}

// one processes the file at path.
func (s *Scanner) one(ctx context.Context, path string, now time.Time) outcome {
	name := filepath.Base(path)
	data, delivered, size, err := readMail(path)
	switch {
	case errors.Is(err, errSkip):
		return skipped
	case errors.Is(err, errTooBig):
		return s.reject(path, delivered, now, ReasonOversized, fmt.Errorf("%d bytes or more", size))
	case err != nil:
		return s.retry(path, delivered, now, err)
	}
	m, err := parse(data)
	if err != nil {
		return s.reject(path, delivered, now, ReasonUnparsable, err)
	}
	m.Path, m.Delivered = path, delivered
	tok, rcpt, err := s.find(m, now)
	if err != nil {
		reason := ReasonBadToken
		if errors.Is(err, token.ErrNoToken) {
			reason = ReasonNoToken
		}
		return s.reject(path, delivered, now, reason, err)
	}
	m.Rcpt = rcpt
	err = s.call(ctx, tok, m)
	switch {
	case err == nil:
	case IsPermanent(err):
		return s.reject(path, delivered, now, ReasonHandler, err)
	case ctx.Err() != nil:
		return pending // shutting down; not the mail's fault
	default:
		return s.retry(path, delivered, now, err)
	}
	if s.beforeUnlink != nil && !s.beforeUnlink(path) {
		return crashed
	}
	delete(s.failures, name)
	s.Log.Debug("mailin: handled", "file", sanitize(name, 80), "kind", tok.Kind, "id", tok.ID,
		"token_age", now.Sub(tok.Time).Round(time.Second))
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Handled and persisted; the next scan offers it again.
		s.Log.Error("mailin: removing handled mail", "file", sanitize(name, 80), "err", err)
	}
	return handled
}

// call runs the handler, turning a panic into a permanent error.
func (s *Scanner) call(ctx context.Context, tok token.Token, m *Message) (err error) {
	defer func() {
		if r := recover(); r != nil {
			s.Log.Error("mailin: handler panic", "file", sanitize(filepath.Base(m.Path), 80),
				"panic", sanitize(fmt.Sprint(r), 200), "stack", string(debug.Stack()))
			err = Permanent(fmt.Errorf("handler panic: %v", r))
		}
	}()
	return s.Handler.Handle(ctx, tok, m)
}

// retry counts a transient failure and gives up past the budget.
func (s *Scanner) retry(path string, delivered, now time.Time, err error) outcome {
	name := filepath.Base(path)
	f := s.failures[name]
	if f == nil {
		f = &failure{first: now}
		s.failures[name] = f
	}
	f.n++
	maxTries, retryFor := s.MaxTries, s.RetryFor
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}
	if retryFor <= 0 {
		retryFor = DefaultRetryFor
	}
	if f.n >= maxTries || now.Sub(f.first) >= retryFor {
		return s.reject(path, delivered, now, ReasonRetries,
			fmt.Errorf("failed in %d scans since %s: %w", f.n, f.first.UTC().Format(time.RFC3339), err))
	}
	s.Log.Warn("mailin: will retry", "file", sanitize(name, 80), "tries", f.n,
		"err", sanitize(err.Error(), 200))
	return pending
}

// reject moves path to the errors directory.
func (s *Scanner) reject(path string, delivered, now time.Time, reason Reason, detail error) outcome {
	name := filepath.Base(path)
	d := sanitize(detail.Error(), 200)
	if err := s.moveToErrors(path, delivered, now, reason, d); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return skipped
		}
		s.Log.Error("mailin: moving to errors", "file", sanitize(name, 80), "err", err)
		return pending
	}
	delete(s.failures, name)
	s.Log.Info("mailin: rejected", "file", sanitize(name, 80), "reason", string(reason), "detail", d)
	return rejected
}

var (
	errSkip   = errors.New("not a regular file")
	errTooBig = errors.New("mail too large")
)

// readMail reads up to MaxSize bytes of path without following a
// symlink.  It returns errSkip for something that isn't a regular file
// (or is gone), errTooBig for a larger file, and other errors for read
// problems.
func readMail(path string) (data []byte, delivered time.Time, size int64, err error) {
	// O_NONBLOCK: a FIFO put there meanwhile must not block the open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ELOOP) {
			return nil, time.Time{}, 0, errSkip
		}
		return nil, time.Time{}, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, time.Time{}, 0, errSkip
	}
	delivered, size = info.ModTime(), info.Size()
	if size > MaxSize {
		return nil, delivered, size, errTooBig
	}
	data, err = io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, delivered, size, err
	}
	if len(data) > MaxSize {
		return nil, delivered, int64(len(data)), errTooBig
	}
	return data, delivered, size, nil
}

// parse reads the header with net/mail; the rest is the body.  A leading
// mbox "From " line, which some delivery agents add, is skipped.
// textproto has no line-length limit, unlike bufio.Scanner (Y-55).
func parse(data []byte) (*Message, error) {
	if bytes.HasPrefix(data, []byte("From ")) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, err
	}
	return &Message{Header: msg.Header, Body: body}, nil
}

// rcptHeaders are searched for a token in this order, every value of
// each.  Cc is last: a reply should come To us, but some MTAs and
// clients move addresses around.
var rcptHeaders = []string{"X-Original-To", "Delivered-To", "To", "Cc"}

// find returns the first valid token in the recipient headers.  Without
// one, it looks for a bounce token in the body: a DSN quotes the headers
// of our mail, whose envelope sender was the bounce token.  Only a
// bounce token counts there; the quoted From has a request token that
// must not be taken as a reply.
func (s *Scanner) find(m *Message, now time.Time) (token.Token, string, error) {
	firstErr := token.ErrNoToken
	for _, h := range rcptHeaders {
		for _, v := range m.Header[h] {
			tok, err := s.Minter.Verify(v, now)
			if err == nil {
				return tok, v, nil
			}
			if firstErr == token.ErrNoToken && !errors.Is(err, token.ErrNoToken) {
				firstErr = err
			}
		}
	}
	for line := range bytes.Lines(m.Body) {
		if !bytes.Contains(bytes.ToLower(line), []byte("bounce")) {
			continue
		}
		tok, err := s.Minter.Verify(string(line), now)
		if err == nil && tok.Kind == token.KindBounce {
			return tok, string(bytes.TrimSpace(line)), nil
		}
	}
	return token.Token{}, "", firstErr
}
