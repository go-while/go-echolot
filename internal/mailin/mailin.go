// Package mailin reads the replies in the pinger's Maildir (design §4.2)
// and writes into it for `go-echolot deliver` (§10.1 b).
//
// A Scanner looks at Maildir/new only.  Each file is processed where it
// lies; there is no claim step that moves it first.  The daemon holds the
// state-dir lock, so one Scanner runs at a time, and the order is:
//
//	read and verify → Handler.Handle (which persists) → unlink → fsync(new/)
//
// A crash before the unlink leaves the file in new/, and the next scan
// offers it to the handler again with the same token.  Handlers are
// idempotent (§5.3): a duplicate done or a reply with a non-newer token
// time is ignored.  Nothing is half-applied because the handler's own
// write is atomic and the file is the only other state.
//
// Mail that isn't a valid reply goes to the errors directory (Y-12):
// errors/<name> plus errors/<name>.reason, a few "key: value" lines.
// Moved files get the move time as mtime, and PruneErrors removes them
// after ErrorRetention.  Maildir/cur and Maildir/tmp are never touched.
package mailin

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/token"
)

// MaxSize is the most bytes read of one mail.  Replies are a few kB;
// larger mail goes to the errors directory without being read.
const MaxSize = 1 << 20

// ErrorRetention is how long mail stays in the errors directory (§5.1).
const ErrorRetention = 7 * 24 * time.Hour

// Defaults of the Scanner's retry budget for transient handler errors.
const (
	DefaultMaxTries = 60
	DefaultRetryFor = 24 * time.Hour
)

// Message is one mail from the Maildir.
type Message struct {
	Path      string      // file in Maildir/new
	Delivered time.Time   // file mtime: when the MTA delivered it
	Header    mail.Header // as parsed by net/mail
	Body      []byte      // raw, not decoded (see replies.Body)
	Rcpt      string      // header value (or, for a bounce, body line) the token was found in
}

// Handler processes a mail with a valid token.  It must persist what it
// learns before returning nil, and must be idempotent: the same mail can
// come again after a crash.  An error wrapped with Permanent moves the
// mail to the errors directory; any other error keeps it for the next
// scan.
type Handler interface {
	Handle(ctx context.Context, tok token.Token, m *Message) error
}

// HandlerFunc lets a function be a Handler.
type HandlerFunc func(ctx context.Context, tok token.Token, m *Message) error

// Handle calls f.
func (f HandlerFunc) Handle(ctx context.Context, tok token.Token, m *Message) error {
	return f(ctx, tok, m)
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Permanent marks err as one that retrying won't fix, such as a reply
// that doesn't parse.  Permanent(nil) is nil.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err}
}

// IsPermanent reports whether err was marked with Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// Reason says why a mail went to the errors directory.
type Reason string

const (
	ReasonOversized  Reason = "oversized"     // over MaxSize
	ReasonUnparsable Reason = "unparsable"    // net/mail can't read the header
	ReasonNoToken    Reason = "no token"      // no reply token of ours
	ReasonBadToken   Reason = "bad token"     // wrong MAC, too old, in the future
	ReasonHandler    Reason = "handler error" // permanent handler error or panic
	ReasonRetries    Reason = "retries used"  // transient errors past the budget
)

// sanitize makes s safe for a log line or reason file: printable ASCII
// only, at most n bytes.
func sanitize(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r >= 0x7f { // also catches invalid UTF-8
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
