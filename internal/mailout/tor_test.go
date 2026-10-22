package mailout

import (
	"context"
	"encoding/base32"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/config"
)

// torProject is torproject.org's v3 onion address.
const torProject = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"

// makeOnion builds a v3 address for a public key made of b.
func makeOnion(b byte, version byte) string {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = b + byte(i)
	}
	raw := append(pub, onionChecksum(pub, version)[:2]...)
	raw = append(raw, version)
	return strings.ToLower(base32.StdEncoding.EncodeToString(raw)) + ".onion"
}

func TestValidOnion(t *testing.T) {
	good := makeOnion(7, 3)
	badSum := good[:10] + string("abcdefghijklmnopqrstuvwxyz234567"[(strings.IndexByte("abcdefghijklmnopqrstuvwxyz234567", good[10])+1)%32]) + good[11:]
	for _, tc := range []struct {
		host string
		ok   bool
	}{
		{torProject, true},
		{strings.ToUpper(torProject), true},
		{"mail." + torProject, true},
		{torProject + ".", true},
		{good, true},
		{badSum, false},
		{makeOnion(7, 2), false}, // version 2 in a v3 shape
		{"expyuzz4wqqyqhjn.onion", false},
		{torProject[:55] + ".onion", false},
		{"1" + torProject[1:], false}, // not base32
		{"onion", false},
		{".onion", false},
		{"example.org", false},
		{strings.TrimSuffix(torProject, ".onion") + ".org", false},
	} {
		if got := validOnion(tc.host); got != tc.ok {
			t.Errorf("validOnion(%q) = %v, want %v", tc.host, got, tc.ok)
		}
	}
}

func TestOnionWithoutTor(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv("FAKESENDMAIL_OUT", out)
	// One mail an hour: the skipped .onion ones don't use it up.
	cfg := config.Mail{Method: config.MethodSendmail, Sendmail: fakeSendmail(t), MaxPerHour: 1}
	m, err := New(cfg, "", fastOpts)
	if err != nil {
		t.Fatal(err)
	}
	mail := testMail()
	mail.Rcpt = []string{"yamn@" + strings.ToUpper(torProject)}
	m.Send(context.Background(), mail)
	err = m.Send(context.Background(), mail)
	if !errors.Is(err, ErrOnionWithoutTor) || IsPermanent(err) || errors.Is(err, ErrTemporary) {
		t.Errorf("got %v, want ErrOnionWithoutTor", err)
	}
	if !strings.Contains(err.Error(), torProject) {
		t.Errorf("error %q doesn't name the host", err)
	}
	if _, err := os.Stat(out + ".args"); err == nil {
		t.Error("sendmail was run for a .onion recipient")
	}
	// Mixed recipients and two onion hosts are refused.
	for _, rcpt := range [][]string{
		{"yamn@" + torProject, testRcpt},
		{"yamn@" + torProject, "yamn@" + makeOnion(1, 3)},
	} {
		mail.Rcpt = rcpt
		if err := m.Send(context.Background(), mail); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: got %v, want ErrInvalid", rcpt, err)
		}
	}
	// Others still go out.
	mail.Rcpt = []string{testRcpt}
	if err := m.Send(context.Background(), mail); err != nil {
		t.Error(err)
	}
}

func TestOnionThroughTor(t *testing.T) {
	smtpd := newFakeSMTP(t, nil)
	socks := newFakeSOCKS(t, smtpd.ln.Addr().String())
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv("FAKESENDMAIL_OUT", out)
	// Method sendmail: the .onion mail goes through Tor anyway.
	cfg := config.Mail{Method: config.MethodSendmail, Sendmail: fakeSendmail(t), MaxPerHour: 10, TorSocks: socks.ln.Addr().String()}
	m, err := New(cfg, "", fastOpts)
	if err != nil {
		t.Fatal(err)
	}
	mail := testMail()
	mail.Rcpt = []string{"yamn@" + torProject}
	for range 2 {
		if err := m.Send(context.Background(), mail); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(out + ".args"); err == nil {
		t.Error("sendmail was run for a .onion recipient")
	}
	socks.mu.Lock()
	users, pass, hosts, ports := socks.users, socks.pass, socks.hosts, socks.ports
	socks.mu.Unlock()
	if len(users) != 2 {
		t.Fatalf("%d SOCKS connections, want 2", len(users))
	}
	if users[0] == "" || users[0] == users[1] || pass[0] == "" || pass[0] == pass[1] {
		t.Errorf("SOCKS logins %q / %q aren't random per connection", users, pass)
	}
	if !slices.Equal(hosts, []string{torProject, torProject}) || !slices.Equal(ports, []int{25, 25}) {
		t.Errorf("SOCKS requests for %v %v", hosts, ports)
	}
	ss := smtpd.snapshot()
	if len(ss) != 2 || !ss[0].accepted || !slices.Equal(ss[0].rcpt, mail.Rcpt) || ss[0].tls || ss[0].user != "" {
		t.Errorf("sessions %+v", ss)
	}
}

func TestOnionTLSUnverified(t *testing.T) {
	// An onion host's self-signed certificate is fine.
	tlsConf, _ := testCert(t, "self-signed.example")
	smtpd := newFakeSMTP(t, func(f *fakeSMTP) { f.tlsConf = tlsConf; f.auth = true })
	socks := newFakeSOCKS(t, smtpd.ln.Addr().String())
	m := newTor(socks.ln.Addr().String(), fastOpts)
	mail := testMail()
	mail.Rcpt = []string{"yamn@" + torProject}
	if err := m.Send(context.Background(), mail); err != nil {
		t.Fatal(err)
	}
	if s := smtpd.snapshot()[0]; !s.tls || s.user != "" || slices.Contains(s.cmds, "AUTH") {
		t.Errorf("session %+v", s)
	}
}

func TestOnionReplies(t *testing.T) {
	smtpd := newFakeSMTP(t, func(f *fakeSMTP) { f.replies["RCPT"] = "550 5.1.1 no such user" })
	socks := newFakeSOCKS(t, smtpd.ln.Addr().String())
	m := newTor(socks.ln.Addr().String(), fastOpts)
	mail := testMail()
	mail.Rcpt = []string{"yamn@" + torProject}
	if err := m.Send(context.Background(), mail); !IsPermanent(err) {
		t.Errorf("got %v, want permanent", err)
	}
}

func TestTorDialErrors(t *testing.T) {
	smtpd := newFakeSMTP(t, nil)
	socks := newFakeSOCKS(t, smtpd.ln.Addr().String())
	socks.code = 0xf0
	m := newTor(socks.ln.Addr().String(), fastOpts)
	mail := testMail()
	mail.Rcpt = []string{"yamn@" + torProject}
	err := m.Send(context.Background(), mail)
	var e *Error
	if !errors.As(err, &e) || IsPermanent(err) || !strings.Contains(err.Error(), "onion service descriptor not found") {
		t.Errorf("got %v", err)
	}
	if !strings.HasPrefix(e.Op, "dial through tor_socks ") {
		t.Errorf("op %q", e.Op)
	}

	// No SOCKS server at all.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := newTor(addr, fastOpts).Send(context.Background(), mail); !errors.Is(err, ErrTemporary) {
		t.Errorf("no proxy: got %v", err)
	}

	// A proxy that never answers: the dial timeout hits.
	tarpit, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tarpit.Close()
	go func() {
		for {
			c, err := tarpit.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	o := fastOpts
	o.TorDialTimeout = 200 * time.Millisecond
	start := time.Now()
	if err := newTor(tarpit.Addr().String(), o).Send(context.Background(), mail); !errors.Is(err, ErrTemporary) || time.Since(start) > 2*time.Second {
		t.Errorf("tarpit proxy: got %v after %s", err, time.Since(start))
	}
}

func TestDescribeTorError(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"socks connect tcp 127.0.0.1:9050->x.onion:25: unknown code: 242", "socks connect tcp 127.0.0.1:9050->x.onion:25: unknown code: 242 (onion service introduction failed)"},
		{"unknown code: 7", "unknown code: 7"},
		{"connection refused", "connection refused"},
	} {
		if got := describeTorError(errors.New(tc.in)).Error(); got != tc.want {
			t.Errorf("%q: got %q", tc.in, got)
		}
	}
}
