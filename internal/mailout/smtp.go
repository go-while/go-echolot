package mailout

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/config"
)

// tlsUse says when a session uses STARTTLS.
type tlsUse int

const (
	tlsNever     tlsUse = iota // plaintext, even if offered (loopback relay without usetls)
	tlsIfOffered               // STARTTLS if the server offers it, else plaintext
	tlsRequired                // STARTTLS or no delivery (no plaintext fallback)
)

// policy is how one SMTP session talks to its server.
type policy struct {
	serverName string // EHLO target, TLS ServerName, PlainAuth host
	tls        tlsUse
	verify     bool // verify the certificate (ServerName, RootCAs)
	rootCAs    *x509.CertPool
	auth       smtp.Auth // nil: no login
	plainAuth  bool      // the login may go out without TLS (loopback)
}

// smtpMailer sends through the configured relay (mail.method smtp).
type smtpMailer struct {
	addr string // relay host:port
	pol  policy
	o    Options
	dial func(ctx context.Context, network, addr string) (net.Conn, error) // tests replace it
}

// NewSMTP returns a Mailer that sends through cfg.SMTPRelay with yamn's
// policy (Y-02, §10.1):
//   - a relay that isn't on this machine must offer STARTTLS and have a
//     certificate valid for cfg.SMTPRelay (o.RootCAs, or the system pool);
//     there is no plaintext fallback;
//   - a relay on this machine (localhost, 127.0.0.0/8, ::1) may be
//     plaintext; with usetls it gets STARTTLS if offered, with require_tls
//     it must offer it; its certificate isn't checked, as nothing leaves
//     the host;
//   - with cfg.Username, the login (AUTH PLAIN, password from
//     cfg.PasswordFile, see ReadPassword) goes only over TLS or to this
//     machine, and only to the relay.
//
// Every step of the session has its own deadline (o.CommandTimeout), and
// the session as a whole o.SessionTimeout (Y-06, Y-28).
func NewSMTP(cfg config.Mail, password string, o Options) (Mailer, error) {
	o = o.withDefaults()
	relay := cfg.SMTPRelay
	if !validHost(relay) && net.ParseIP(relay) == nil {
		return nil, fmt.Errorf("mail.smtp_relay must be a host name or IP address, not %q", relay)
	}
	if isOnion(relay) {
		return nil, fmt.Errorf("mail.smtp_relay %s: a .onion relay isn't supported; .onion recipients go through mail.tor_socks", relay)
	}
	if cfg.SMTPPort < 1 || cfg.SMTPPort > 65535 {
		return nil, fmt.Errorf("mail.smtp_port must be 1 to 65535, not %d", cfg.SMTPPort)
	}
	loop := isLoopback(relay)
	if !cfg.UseTLS && !loop {
		return nil, fmt.Errorf("mail.usetls must be true for a relay that isn't on this machine (%s)", relay)
	}
	if cfg.RequireTLS && !cfg.UseTLS {
		return nil, errors.New("mail.require_tls needs mail.usetls = true")
	}
	if (cfg.Username == "") != (password == "") {
		return nil, errors.New("mail.username and a password must be set together")
	}
	if strings.ContainsAny(cfg.Username, "\r\n\x00") || strings.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("mail.username and the password must not contain CR, LF or NUL")
	}
	pol := policy{serverName: relay, rootCAs: o.RootCAs, plainAuth: loop}
	switch {
	case !cfg.UseTLS:
		pol.tls = tlsNever
	case !loop || cfg.RequireTLS:
		pol.tls = tlsRequired
	default:
		pol.tls = tlsIfOffered
	}
	pol.verify = !loop
	if cfg.Username != "" {
		pol.auth = smtp.PlainAuth("", cfg.Username, password, relay)
	}
	d := &net.Dialer{Timeout: o.DialTimeout}
	return &smtpMailer{
		addr: net.JoinHostPort(relay, strconv.Itoa(cfg.SMTPPort)),
		pol:  pol,
		o:    o,
		dial: d.DialContext,
	}, nil
}

func (s *smtpMailer) Send(ctx context.Context, m Mail) error {
	if err := m.check(); err != nil {
		return err
	}
	dctx, cancel := context.WithTimeout(ctx, s.o.DialTimeout)
	defer cancel()
	conn, err := s.dial(dctx, "tcp", s.addr)
	if err != nil {
		return &Error{Server: s.addr, Op: "dial", Err: err}
	}
	return session(ctx, conn, s.addr, s.pol, s.o, m)
}

// session delivers m over conn and closes it.  Only a 5xx reply to MAIL,
// RCPT or DATA is permanent.  One refused recipient fails the whole mail;
// go-echolot sends one recipient per mail.
func session(ctx context.Context, conn net.Conn, addr string, p policy, o Options, m Mail) error {
	defer conn.Close()
	// Cancelling ctx unblocks whatever step is waiting.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	end := time.Now().Add(o.SessionTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(end) {
		end = d
	}
	// step gives the next command its own deadline (net/smtp has none).
	// After STARTTLS it still applies: the TLS conn wraps conn.
	step := func() error {
		d := time.Now().Add(o.CommandTimeout)
		if d.After(end) {
			d = end
		}
		return conn.SetDeadline(d)
	}
	fail := func(op string, err error, mayBePermanent bool) error {
		if cerr := ctx.Err(); cerr != nil {
			err = cerr
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			err = fmt.Errorf("no answer in time: %w", err)
		}
		return &Error{Server: addr, Op: op, Permanent: mayBePermanent && is5xx(err), Err: err}
	}

	if err := step(); err != nil {
		return fail("greeting", err, false)
	}
	c, err := smtp.NewClient(conn, p.serverName)
	if err != nil {
		return fail("greeting", err, false)
	}
	if err := step(); err != nil {
		return fail("ehlo", err, false)
	}
	if err := c.Hello(domainOf(m.EnvelopeFrom)); err != nil {
		return fail("ehlo", err, false)
	}
	offered, _ := c.Extension("STARTTLS")
	secure := false
	switch {
	case offered && p.tls != tlsNever:
		if err := step(); err != nil {
			return fail("starttls", err, false)
		}
		tc := &tls.Config{
			ServerName:         p.serverName,
			RootCAs:            p.rootCAs,
			InsecureSkipVerify: !p.verify,
			MinVersion:         tls.VersionTLS12,
		}
		if err := c.StartTLS(tc); err != nil {
			return fail("starttls", err, false)
		}
		secure = true
	case p.tls == tlsRequired:
		return fail("starttls", errors.New("the server offers no STARTTLS, and TLS is required"), false)
	}
	if p.auth != nil {
		if !secure && !p.plainAuth {
			return fail("auth", errors.New("no login without TLS"), false)
		}
		if ok, _ := c.Extension("AUTH"); !ok {
			return fail("auth", errors.New("the server offers no AUTH"), false)
		}
		if err := step(); err != nil {
			return fail("auth", err, false)
		}
		if err := c.Auth(p.auth); err != nil {
			return fail("auth", err, false)
		}
	}
	if err := step(); err != nil {
		return fail("mail from", err, false)
	}
	if err := c.Mail(m.EnvelopeFrom); err != nil {
		return fail("mail from", err, true)
	}
	for _, r := range m.Rcpt {
		if err := step(); err != nil {
			return fail("rcpt to", err, false)
		}
		if err := c.Rcpt(r); err != nil {
			return fail("rcpt to "+r, err, true)
		}
	}
	if err := step(); err != nil {
		return fail("data", err, false)
	}
	w, err := c.Data()
	if err != nil {
		return fail("data", err, true)
	}
	// The dot writer sends each LF as CRLF and escapes leading dots.
	if err := step(); err != nil {
		return fail("data", err, false)
	}
	if _, err := w.Write(toLF(m.Data)); err != nil {
		return fail("data", err, false)
	}
	if err := step(); err != nil {
		return fail("data", err, false)
	}
	if err := w.Close(); err != nil {
		return fail("data", err, true)
	}
	// The message is accepted.  A failed QUIT isn't a failed delivery.
	if step() == nil {
		_ = c.Quit()
	}
	return nil
}

// is5xx reports whether err is a 5xx SMTP reply.
func is5xx(err error) bool {
	var tp *textproto.Error
	return errors.As(err, &tp) && tp.Code >= 500 && tp.Code <= 599
}

// isLoopback reports whether host is this machine, as yamn's
// isLoopbackHost and config's isLoopback.
func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// ReadPassword reads the SMTP password from mail.password_file: the first
// line, without its line end.  A file that everyone may read is refused.
func ReadPassword(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o004 != 0 {
		return "", fmt.Errorf("mail.password_file %s must not be readable by everyone (mode %04o)", path, fi.Mode().Perm())
	}
	buf, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", fmt.Errorf("mail.password_file %s: %w", path, err)
	}
	if len(buf) > 4096 {
		return "", fmt.Errorf("mail.password_file %s is too long", path)
	}
	pw, _, _ := strings.Cut(string(buf), "\n")
	pw = strings.TrimSuffix(pw, "\r")
	if pw == "" {
		return "", fmt.Errorf("mail.password_file %s is empty", path)
	}
	if strings.ContainsAny(pw, "\r\x00") {
		return "", fmt.Errorf("mail.password_file %s: the password must not contain CR or NUL", path)
	}
	return pw, nil
}
