package mailout

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/config"
)

const (
	testFrom = "pinger+bounce.12=1792560000=3f9a0c51d2e47b08@pinger.example.org"
	testRcpt = "yamn@remailer.example.net"
)

func testMail() Mail {
	return Mail{
		EnvelopeFrom: testFrom,
		Rcpt:         []string{testRcpt},
		Data:         []byte("From: a@example.org\nSubject: x\n\nline one\n.leading dot\nend\n"),
	}
}

// fastOpts keeps the tests quick.
var fastOpts = Options{
	DialTimeout:    2 * time.Second,
	TorDialTimeout: 2 * time.Second,
	CommandTimeout: 2 * time.Second,
	SessionTimeout: 5 * time.Second,
}

// smtpCfg is a relay config for f; relay is the configured host name.
func smtpCfg(f *fakeSMTP, relay string) config.Mail {
	return config.Mail{
		Method:     config.MethodSMTP,
		SMTPRelay:  relay,
		SMTPPort:   f.port(),
		UseTLS:     true,
		MaxPerHour: 100,
	}
}

// newTestSMTP returns an SMTP mailer for cfg that connects to f, whatever
// cfg.SMTPRelay says, so a non-loopback relay can be tested.
func newTestSMTP(t *testing.T, f *fakeSMTP, cfg config.Mail, password string, roots *x509.CertPool) Mailer {
	t.Helper()
	o := fastOpts
	o.RootCAs = roots
	m, err := NewSMTP(cfg, password, o)
	if err != nil {
		t.Fatal(err)
	}
	addr := f.ln.Addr().String()
	m.(*smtpMailer).dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return m
}

func TestSMTPSuccess(t *testing.T) {
	f := newFakeSMTP(t, nil)
	cfg := smtpCfg(f, "127.0.0.1")
	cfg.UseTLS = false
	m, err := NewSMTP(cfg, "", fastOpts)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		"From: a@example.org\nSubject: x\n\nline one\n.leading dot\nend\n",
		"From: a@example.org\r\nSubject: x\r\n\r\nline one\r\n.leading dot\r\nend\r\n",
		"From: a@example.org\rSubject: x\r\rline one\r.leading dot\rend",
	} {
		mail := testMail()
		mail.Data = []byte(data)
		if err := m.Send(context.Background(), mail); err != nil {
			t.Fatalf("%q: %v", data, err)
		}
	}
	want := "From: a@example.org\r\nSubject: x\r\n\r\nline one\r\n..leading dot\r\nend\r\n"
	ss := f.snapshot()
	if len(ss) != 3 {
		t.Fatalf("%d sessions, want 3", len(ss))
	}
	for i, s := range ss {
		if !s.accepted || s.from != testFrom || !slices.Equal(s.rcpt, []string{testRcpt}) {
			t.Errorf("session %d: %+v", i, s)
		}
		if string(s.raw) != want {
			t.Errorf("session %d: data on the wire %q, want %q", i, s.raw, want)
		}
		if s.ehlo != "pinger.example.org" {
			t.Errorf("session %d: EHLO %q", i, s.ehlo)
		}
		if s.tls || s.user != "" {
			t.Errorf("session %d: tls %v, user %q", i, s.tls, s.user)
		}
	}
}

func TestSMTPReplies(t *testing.T) {
	for _, tc := range []struct {
		key, reply string
		permanent  bool
		op         string
	}{
		{"MAIL", "550 5.1.8 bad sender", true, "mail from"},
		{"RCPT", "550 5.1.1 no such user", true, "rcpt to " + testRcpt},
		{"DATA", "554 5.6.0 no", true, "data"},
		{"DOT", "552 5.3.4 too big", true, "data"},
		{"MAIL", "421 4.3.2 shutting down", false, "mail from"},
		{"RCPT", "450 4.2.0 greylisted", false, "rcpt to " + testRcpt},
		{"DATA", "451 4.3.0 later", false, "data"},
		{"DOT", "451 4.3.0 later", false, "data"},
		{"GREETING", "554 no service", false, "greeting"},
		{"EHLO", "550 go away", false, "ehlo"},
	} {
		t.Run(tc.key+" "+tc.reply[:3], func(t *testing.T) {
			f := newFakeSMTP(t, func(f *fakeSMTP) { f.replies[tc.key] = tc.reply })
			cfg := smtpCfg(f, "127.0.0.1")
			cfg.UseTLS = false
			m, err := NewSMTP(cfg, "", fastOpts)
			if err != nil {
				t.Fatal(err)
			}
			err = m.Send(context.Background(), testMail())
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("got %v, want an *Error", err)
			}
			if IsPermanent(err) != tc.permanent || errors.Is(err, ErrTemporary) == tc.permanent {
				t.Errorf("%v: permanent %v, want %v", err, IsPermanent(err), tc.permanent)
			}
			if e.Op != tc.op {
				t.Errorf("op %q, want %q", e.Op, tc.op)
			}
			// net/smtp tries HELO after a failed EHLO, and the fake
			// server doesn't know it.
			if tc.key != "EHLO" && !strings.Contains(err.Error(), tc.reply[4:]) {
				t.Errorf("error %q lacks the reply", err)
			}
		})
	}
}

func TestSMTPTarpit(t *testing.T) {
	o := fastOpts
	o.CommandTimeout = 200 * time.Millisecond
	for _, tc := range []struct {
		name  string
		setup func(f *fakeSMTP)
		op    string
	}{
		{"silent", func(f *fakeSMTP) { f.tarpit = true }, "greeting"},
		{"hangs at MAIL", func(f *fakeSMTP) { f.replies["MAIL"] = "HANG" }, "mail from"},
		{"hangs at RCPT", func(f *fakeSMTP) { f.replies["RCPT"] = "HANG" }, "rcpt to " + testRcpt},
		{"hangs after data", func(f *fakeSMTP) { f.replies["DOT"] = "HANG" }, "data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSMTP(t, tc.setup)
			cfg := smtpCfg(f, "127.0.0.1")
			cfg.UseTLS = false
			m, err := NewSMTP(cfg, "", o)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err = m.Send(context.Background(), testMail())
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("took %s", d)
			}
			var e *Error
			if !errors.As(err, &e) || e.Op != tc.op || !errors.Is(err, os.ErrDeadlineExceeded) || IsPermanent(err) {
				t.Errorf("got %v, want a temporary timeout at %s", err, tc.op)
			}
		})
	}
}

func TestSMTPSessionDeadline(t *testing.T) {
	// Each step stays within CommandTimeout, the session doesn't.
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.replies["RCPT"] = "HANG" })
	cfg := smtpCfg(f, "127.0.0.1")
	cfg.UseTLS = false
	o := fastOpts
	o.CommandTimeout = time.Minute
	o.SessionTimeout = 300 * time.Millisecond
	m, err := NewSMTP(cfg, "", o)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = m.Send(context.Background(), testMail())
	if d := time.Since(start); d > 2*time.Second || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("after %s: %v", d, err)
	}

	// The same with a context deadline, and with cancelling.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	o.SessionTimeout = time.Minute
	m, _ = NewSMTP(cfg, "", o)
	start = time.Now()
	err = m.Send(ctx, testMail())
	if d := time.Since(start); d > 2*time.Second || !errors.Is(err, ErrTemporary) {
		t.Errorf("ctx deadline: after %s: %v", d, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start = time.Now()
	err = m.Send(ctx, testMail())
	if d := time.Since(start); d > 2*time.Second || !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: after %s: %v", d, err)
	}
}

func TestSMTPStartTLS(t *testing.T) {
	tlsConf, pool := testCert(t, "relay.example.org")
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.tlsConf = tlsConf })

	// Verified with the test CA.
	m := newTestSMTP(t, f, smtpCfg(f, "relay.example.org"), "", pool)
	if err := m.Send(context.Background(), testMail()); err != nil {
		t.Fatal(err)
	}
	if s := f.snapshot()[0]; !s.tls || !s.accepted {
		t.Errorf("session %+v, want TLS and accepted", s)
	}

	// Refused without it, and with the wrong name.  No plaintext fallback.
	for _, tc := range []struct {
		relay string
		pool  *x509.CertPool
	}{
		{"relay.example.org", nil},
		{"other.example.org", pool},
	} {
		n := len(f.snapshot())
		m := newTestSMTP(t, f, smtpCfg(f, tc.relay), "", tc.pool)
		err := m.Send(context.Background(), testMail())
		var e *Error
		if !errors.As(err, &e) || e.Op != "starttls" || IsPermanent(err) {
			t.Errorf("%s: got %v, want a starttls error", tc.relay, err)
		}
		if s := f.snapshot()[n]; slices.Contains(s.cmds, "MAIL") {
			t.Errorf("%s: mail sent after a failed STARTTLS: %v", tc.relay, s.cmds)
		}
	}
}

func TestSMTPNoStartTLS(t *testing.T) {
	f := newFakeSMTP(t, nil) // no STARTTLS
	for _, tc := range []struct {
		name    string
		relay   string
		require bool
		ok      bool
	}{
		{"remote relay", "relay.example.org", false, false},
		{"remote relay, require_tls", "relay.example.org", true, false},
		{"loopback, require_tls", "127.0.0.1", true, false},
		{"loopback, usetls", "127.0.0.1", false, true},
		{"localhost, usetls", "localhost", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := smtpCfg(f, tc.relay)
			cfg.RequireTLS = tc.require
			n := len(f.snapshot())
			err := newTestSMTP(t, f, cfg, "", nil).Send(context.Background(), testMail())
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var e *Error
			if !errors.As(err, &e) || e.Op != "starttls" {
				t.Errorf("got %v, want a starttls error", err)
			}
			if s := f.snapshot()[n]; slices.Contains(s.cmds, "MAIL") {
				t.Errorf("mail sent without TLS: %v", s.cmds)
			}
		})
	}
}

func TestSMTPLoopbackUnverifiedTLS(t *testing.T) {
	// A relay on this machine gets STARTTLS, but its certificate isn't
	// checked.
	tlsConf, _ := testCert(t, "elsewhere.example.org")
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.tlsConf = tlsConf })
	cfg := smtpCfg(f, "127.0.0.1")
	cfg.RequireTLS = true
	if err := newTestSMTP(t, f, cfg, "", nil).Send(context.Background(), testMail()); err != nil {
		t.Fatal(err)
	}
	if s := f.snapshot()[0]; !s.tls {
		t.Error("no TLS")
	}

	// Without usetls, plaintext even if offered.
	cfg.UseTLS, cfg.RequireTLS = false, false
	if err := newTestSMTP(t, f, cfg, "", nil).Send(context.Background(), testMail()); err != nil {
		t.Fatal(err)
	}
	if s := f.snapshot()[1]; s.tls {
		t.Error("TLS without usetls")
	}
}

func TestSMTPAuth(t *testing.T) {
	tlsConf, pool := testCert(t, "relay.example.org")
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.tlsConf = tlsConf; f.auth = true })
	cfg := smtpCfg(f, "relay.example.org")
	cfg.Username, cfg.PasswordFile = "pinger", "/etc/go-echolot/smtp.pw"
	if err := newTestSMTP(t, f, cfg, "s3cret", pool).Send(context.Background(), testMail()); err != nil {
		t.Fatal(err)
	}
	s := f.snapshot()[0]
	if s.user != "pinger" || s.pass != "s3cret" || !s.authTLS || !s.accepted {
		t.Errorf("session %+v", s)
	}
	if slices.Index(s.cmds, "AUTH") < slices.Index(s.cmds, "STARTTLS") {
		t.Errorf("AUTH before STARTTLS: %v", s.cmds)
	}

	// Plaintext AUTH only to this machine.
	g := newFakeSMTP(t, func(f *fakeSMTP) { f.auth = true })
	cfg = smtpCfg(g, "127.0.0.1")
	cfg.UseTLS = false
	cfg.Username, cfg.PasswordFile = "pinger", "/x"
	if err := newTestSMTP(t, g, cfg, "s3cret", nil).Send(context.Background(), testMail()); err != nil {
		t.Fatal(err)
	}
	if s := g.snapshot()[0]; s.user != "pinger" || s.authTLS {
		t.Errorf("loopback session %+v", s)
	}

	// A login is configured, the server offers no AUTH: nothing is sent.
	h := newFakeSMTP(t, func(f *fakeSMTP) { f.tlsConf = tlsConf })
	cfg = smtpCfg(h, "relay.example.org")
	cfg.Username, cfg.PasswordFile = "pinger", "/x"
	err := newTestSMTP(t, h, cfg, "s3cret", pool).Send(context.Background(), testMail())
	var e *Error
	if !errors.As(err, &e) || e.Op != "auth" || IsPermanent(err) || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("got %v, want an auth error", err)
	}
	if s := h.snapshot()[0]; slices.Contains(s.cmds, "MAIL") {
		t.Errorf("mail sent without login: %v", s.cmds)
	}
}

func TestSMTPAuthNeverPlaintextRemote(t *testing.T) {
	// The policy itself refuses, even if config validation were bypassed.
	f := newFakeSMTP(t, func(f *fakeSMTP) { f.auth = true })
	m := newTestSMTP(t, f, smtpCfg(f, "127.0.0.1"), "", nil).(*smtpMailer)
	m.pol = policy{serverName: "relay.example.org", tls: tlsIfOffered, verify: true}
	m.pol.auth = plainAuthFor("relay.example.org")
	err := m.Send(context.Background(), testMail())
	var e *Error
	if !errors.As(err, &e) || e.Op != "auth" {
		t.Errorf("got %v, want an auth error", err)
	}
	if s := f.snapshot()[0]; slices.Contains(s.cmds, "AUTH") {
		t.Errorf("AUTH sent in plaintext: %v", s.cmds)
	}
}

func plainAuthFor(host string) smtp.Auth { return smtp.PlainAuth("", "u", "p", host) }

func TestNewSMTPConfig(t *testing.T) {
	base := config.Mail{Method: config.MethodSMTP, SMTPRelay: "relay.example.org", SMTPPort: 587, UseTLS: true}
	for _, tc := range []struct {
		name string
		mod  func(c *config.Mail, pw *string)
	}{
		{"onion relay", func(c *config.Mail, _ *string) {
			c.SMTPRelay = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
		}},
		{"plaintext remote", func(c *config.Mail, _ *string) { c.UseTLS = false }},
		{"require without use", func(c *config.Mail, _ *string) { c.SMTPRelay = "localhost"; c.UseTLS = false; c.RequireTLS = true }},
		{"user without password", func(c *config.Mail, _ *string) { c.Username = "u" }},
		{"password without user", func(_ *config.Mail, pw *string) { *pw = "p" }},
		{"bad relay", func(c *config.Mail, _ *string) { c.SMTPRelay = "relay.example.org\r\n" }},
		{"bad port", func(c *config.Mail, _ *string) { c.SMTPPort = 0 }},
		{"CR in user", func(c *config.Mail, pw *string) { c.Username = "u\r"; *pw = "p" }},
	} {
		c, pw := base, ""
		tc.mod(&c, &pw)
		if _, err := NewSMTP(c, pw, Options{}); err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}
	if _, err := NewSMTP(base, "", Options{}); err != nil {
		t.Errorf("base: %v", err)
	}
	ipv6 := base
	ipv6.SMTPRelay, ipv6.UseTLS = "::1", false
	m, err := NewSMTP(ipv6, "", Options{})
	if err != nil || m.(*smtpMailer).addr != "[::1]:587" {
		t.Errorf("::1: %v", err)
	}
}

func TestInvalidBeforeConnect(t *testing.T) {
	f := newFakeSMTP(t, nil)
	cfg := smtpCfg(f, "127.0.0.1")
	cfg.UseTLS = false
	smtpM, err := NewSMTP(cfg, "", fastOpts)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	t.Setenv("FAKESENDMAIL_OUT", out)
	socks := newFakeSOCKS(t, f.ln.Addr().String())
	tor := newTor(socks.ln.Addr().String(), fastOpts)
	routed := &router{tor: tor, other: smtpM}
	mailers := map[string]Mailer{
		"smtp":     smtpM,
		"sendmail": NewSendmail(fakeSendmail(t), time.Second),
		"tor":      tor,
		"router":   routed,
		"limit":    Limit(routed, 100, nil),
	}
	for _, tc := range []struct {
		name string
		mod  func(m *Mail)
	}{
		{"CR in rcpt", func(m *Mail) { m.Rcpt = []string{"a\r@example.org"} }},
		{"LF in rcpt", func(m *Mail) { m.Rcpt = []string{"a@example.org\nRCPT TO:<b@example.org>"} }},
		{"NUL in rcpt", func(m *Mail) { m.Rcpt = []string{"a@exa\x00mple.org"} }},
		{"ESMTP params in rcpt", func(m *Mail) { m.Rcpt = []string{"a@example.org> NOTIFY=NEVER"} }},
		{"quoted rcpt", func(m *Mail) { m.Rcpt = []string{`"a>b"@example.org`} }},
		{"option as rcpt", func(m *Mail) { m.Rcpt = []string{"-oQ/tmp@example.org"} }},
		{"route in rcpt", func(m *Mail) { m.Rcpt = []string{"a%b@example.org"} }},
		{"no rcpt", func(m *Mail) { m.Rcpt = nil }},
		{"CR in envelope", func(m *Mail) { m.EnvelopeFrom = "a@example.org\r" }},
		{"LF in envelope", func(m *Mail) { m.EnvelopeFrom = "a@example.org\nX" }},
		{"NUL in envelope", func(m *Mail) { m.EnvelopeFrom = "a\x00@example.org" }},
		{"empty envelope", func(m *Mail) { m.EnvelopeFrom = "" }},
		{"NUL in data", func(m *Mail) { m.Data = []byte("Subject: x\n\na\x00b\n") }},
		{"no data", func(m *Mail) { m.Data = nil }},
		{"v2 onion", func(m *Mail) { m.Rcpt = []string{"yamn@expyuzz4wqqyqhjn.onion"} }},
	} {
		for name, mailer := range mailers {
			if tc.name == "v2 onion" && (name == "smtp" || name == "sendmail") {
				continue // they don't route; it's a valid address to them
			}
			m := testMail()
			tc.mod(&m)
			err := mailer.Send(context.Background(), m)
			if !errors.Is(err, ErrInvalid) || IsPermanent(err) || errors.Is(err, ErrTemporary) {
				t.Errorf("%s via %s: got %v, want ErrInvalid", tc.name, name, err)
			}
		}
	}
	if n := len(f.snapshot()); n != 0 {
		t.Errorf("%d SMTP connections, want 0", n)
	}
	if _, err := os.Stat(out + ".args"); err == nil {
		t.Error("sendmail was run")
	}
	socks.mu.Lock()
	defer socks.mu.Unlock()
	if len(socks.users) != 0 {
		t.Error("tor was used")
	}
}

func TestReadPassword(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		content string
		mode    os.FileMode
		want    string
	}{
		{"s3cret\n", 0o600, "s3cret"},
		{"s3cret\r\n", 0o640, "s3cret"},
		{"s3cret", 0o400, "s3cret"},
		{"s3 cret\nsecond line\n", 0o600, "s3 cret"},
		{"s3cret\n", 0o644, ""},
		{"\n", 0o600, ""},
		{"", 0o600, ""},
		{"a\x00b\n", 0o600, ""},
		{strings.Repeat("x", 5000), 0o600, ""},
	} {
		p := write("pw", tc.content, tc.mode)
		got, err := ReadPassword(p)
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("%q %o: got %q, %v", tc.content, tc.mode, got, err)
		}
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("error shows the password: %v", err)
		}
		os.Remove(p)
	}
	if _, err := ReadPassword(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file: no error")
	}
}

func TestErrorFormat(t *testing.T) {
	e := &Error{Server: net.JoinHostPort("relay.example.org", strconv.Itoa(25)), Op: "rcpt to x@y.org", Permanent: true, Err: errors.New("550 no")}
	if got := e.Error(); got != "relay.example.org:25: rcpt to x@y.org: 550 no" {
		t.Errorf("got %q", got)
	}
	if !errors.Is(e, ErrPermanent) || errors.Is(e, ErrTemporary) {
		t.Error("classification")
	}
}
