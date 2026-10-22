// Package mailout sends go-echolot's mail: requests and pings (design
// §4.1, §6.2, §10.1).
//
// There is no retry queue.  A failed send is logged, and the request or
// ping goes out again at its next slot with a new token (§9.4).  Errors
// therefore fall into three groups:
//
//   - permanent (errors.Is(err, ErrPermanent)): the receiving server refused
//     this message with a 5xx reply to MAIL, RCPT or DATA, or sendmail
//     said the message or address is bad.  Count it like a bounce.
//   - temporary (errors.Is(err, ErrTemporary)): network errors, timeouts,
//     4xx replies, TLS and AUTH problems, sendmail's EX_TEMPFAIL and other
//     local trouble, and the rate fuse (ErrRateLimited).
//   - neither: a Mail that fails the checks here (ErrInvalid), and a .onion
//     recipient without mail.tor_socks (ErrOnionWithoutTor).  Nothing was
//     sent; the caller should log and skip.
package mailout

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/config"
)

// Mail is one outgoing message.  Data is the whole message, headers and
// body, with LF or CRLF line ends.
type Mail struct {
	EnvelopeFrom string
	Rcpt         []string
	Data         []byte
}

// Mailer sends mail.
type Mailer interface {
	Send(ctx context.Context, m Mail) error
}

var (
	// ErrPermanent and ErrTemporary classify an *Error (see the package
	// comment).  Use errors.Is.
	ErrPermanent = errors.New("permanent failure")
	ErrTemporary = errors.New("temporary failure")

	// ErrInvalid is wrapped by errors for a Mail or header field that
	// fails the checks: bad addresses, CR, LF or NUL in a field.
	ErrInvalid = errors.New("invalid mail")

	// ErrOnionWithoutTor: a .onion recipient, and mail.tor_socks isn't set.
	ErrOnionWithoutTor = errors.New("a .onion recipient needs mail.tor_socks")

	// ErrRateLimited: mail.max_per_hour reached, nothing was sent.  It
	// comes wrapped in a temporary *Error.
	ErrRateLimited = errors.New("mail.max_per_hour reached")
)

// Error is a failed delivery attempt.
type Error struct {
	Server    string // "host:port", the sendmail path, or "" (rate fuse)
	Op        string // the step that failed, e.g. "dial", "starttls", "rcpt"
	Permanent bool
	Err       error
}

func (e *Error) Error() string {
	var b strings.Builder
	if e.Server != "" {
		b.WriteString(e.Server)
		b.WriteString(": ")
	}
	b.WriteString(e.Op)
	b.WriteString(": ")
	b.WriteString(e.Err.Error())
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrPermanent) and errors.Is(err, ErrTemporary)
// work.
func (e *Error) Is(target error) bool {
	return target == ErrPermanent && e.Permanent || target == ErrTemporary && !e.Permanent
}

// IsPermanent reports whether err is a permanent failure.
func IsPermanent(err error) bool { return errors.Is(err, ErrPermanent) }

// Options tunes the mailers.  Zero values get the defaults.
type Options struct {
	DialTimeout     time.Duration // TCP connect to the relay (30s)
	TorDialTimeout  time.Duration // connect through Tor, SOCKS handshake included (2m)
	CommandTimeout  time.Duration // each SMTP step: greeting, EHLO, STARTTLS, AUTH, MAIL, RCPT, DATA, ... (2m)
	SessionTimeout  time.Duration // the whole SMTP session after connecting (5m)
	SendmailTimeout time.Duration // the sendmail command (5m)
	RootCAs         *x509.CertPool
}

func (o Options) withDefaults() Options {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.DialTimeout, 30*time.Second)
	def(&o.TorDialTimeout, 2*time.Minute)
	def(&o.CommandTimeout, 2*time.Minute)
	def(&o.SessionTimeout, 5*time.Minute)
	def(&o.SendmailTimeout, 5*time.Minute)
	return o
}

// New returns the Mailer for cfg: .onion recipients go through Tor
// (cfg.TorSocks), all others by cfg.Method.  Every send counts against
// cfg.MaxPerHour (Limit).  password is the content of cfg.PasswordFile
// (see ReadPassword), or "" without a login.
func New(cfg config.Mail, password string, o Options) (Mailer, error) {
	o = o.withDefaults()
	r := &router{}
	switch cfg.Method {
	case config.MethodSendmail:
		r.other = NewSendmail(cfg.Sendmail, o.SendmailTimeout)
	case config.MethodSMTP:
		m, err := NewSMTP(cfg, password, o)
		if err != nil {
			return nil, err
		}
		r.other = m
	default:
		return nil, fmt.Errorf("mail.method must be sendmail or smtp, not %q", cfg.Method)
	}
	if cfg.TorSocks != "" {
		r.tor = newTor(cfg.TorSocks, o)
	}
	return Limit(r, cfg.MaxPerHour, nil), nil
}

// router sends mail for .onion recipients through Tor, the rest through
// other.
type router struct {
	tor   Mailer // nil without mail.tor_socks
	other Mailer
}

func (r *router) Send(ctx context.Context, m Mail) error {
	onion, err := r.precheck(m)
	if err != nil {
		return err
	}
	if onion {
		return r.tor.Send(ctx, m)
	}
	return r.other.Send(ctx, m)
}

// precheck returns the errors that come before sending, so Limit doesn't
// count them, and whether m goes through Tor.
func (r *router) precheck(m Mail) (onion bool, err error) {
	if err := m.check(); err != nil {
		return false, err
	}
	host, onion, err := onionHost(m.Rcpt)
	if err != nil {
		return false, err
	}
	if onion && r.tor == nil {
		return false, fmt.Errorf("%s: %w", host, ErrOnionWithoutTor)
	}
	return onion, nil
}

// onionHost reports whether the recipients are at a .onion host.  They
// must then all be at the same valid v3 one.
func onionHost(rcpt []string) (host string, onion bool, err error) {
	var n int
	for _, a := range rcpt {
		d := strings.ToLower(domainOf(a))
		if !isOnion(d) {
			continue
		}
		if !validOnion(d) {
			return "", false, fmt.Errorf("%w: recipient %q: not a v3 .onion address", ErrInvalid, a)
		}
		if host != "" && d != host {
			return "", false, fmt.Errorf("%w: recipients at more than one .onion host", ErrInvalid)
		}
		host = d
		n++
	}
	if n > 0 && n < len(rcpt) {
		return "", false, fmt.Errorf("%w: .onion and other recipients in one mail", ErrInvalid)
	}
	return host, n > 0, nil
}

// check validates m before anything is sent.
func (m Mail) check() error {
	if err := checkAddress("envelope sender", m.EnvelopeFrom); err != nil {
		return err
	}
	if len(m.Rcpt) == 0 {
		return fmt.Errorf("%w: no recipients", ErrInvalid)
	}
	for _, a := range m.Rcpt {
		if err := checkAddress("recipient", a); err != nil {
			return err
		}
	}
	if len(m.Data) == 0 {
		return fmt.Errorf("%w: empty message", ErrInvalid)
	}
	if bytes.IndexByte(m.Data, 0) >= 0 {
		return fmt.Errorf("%w: NUL in message", ErrInvalid)
	}
	return nil
}

// checkAddress reports an error unless addr is a plain ASCII address that
// is safe in a header, in RCPT TO or MAIL FROM, and as a sendmail
// argument: one "@", a dot-atom local part without "%" and "!", and a host
// name (as yamn's validRecipient, Y-24).  This also rules out CR, LF, NUL,
// spaces, "<", ">" and a leading "-".
func checkAddress(what, addr string) error {
	if !validAddress(addr) {
		return fmt.Errorf("%w: %s %q is not a plain address like name@example.org", ErrInvalid, what, addr)
	}
	return nil
}

func validAddress(addr string) bool {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || len(local) > 64 || len(addr) > 254 || local[0] == '-' {
		return false
	}
	for _, atom := range strings.Split(local, ".") {
		if atom == "" || strings.ContainsFunc(atom, func(c rune) bool { return !isAtext(c) }) {
			return false
		}
	}
	return validHost(domain)
}

// validHost reports whether s is a host name: dot-separated labels of
// letters, digits and inner hyphens.
func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.ContainsFunc(label, func(c rune) bool { return !isAlnum(c) && c != '-' }) {
			return false
		}
	}
	return true
}

func isAlnum(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// isAtext reports whether c may appear in a dot-atom (RFC 5322 atext),
// leaving out "%" and "!", which some MTAs treat as routing.
func isAtext(c rune) bool {
	return isAlnum(c) || strings.ContainsRune("#$&'*+-/=?^_`{|}~", c)
}

// domainOf returns the part of addr after the last "@".
func domainOf(addr string) string {
	return addr[strings.LastIndexByte(addr, '@')+1:]
}

// toLF returns b with CRLF and lone CR turned into LF.  A lone CR isn't a
// line end to Go's SMTP client, so "\r.\r" would reach the server
// unescaped (Y-25).  As LF it's sent as CRLF over SMTP, and dot-stuffed.
func toLF(b []byte) []byte {
	if bytes.IndexByte(b, '\r') < 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '\r' {
			if i+1 < len(b) && b[i+1] == '\n' {
				continue
			}
			c = '\n'
		}
		out = append(out, c)
	}
	return out
}
