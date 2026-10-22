package mailout

import (
	"bytes"
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/config"
)

const (
	reqFrom = "pinger+key.12=1792560000=3f9a0c51d2e47b08@pinger.example.org"
	reqTo   = "yamn@mixmin.net"
	reqOps  = "remops@pinger.example.org"
)

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRequestText(t *testing.T) {
	if got, want := RequestText(reqTo, reqOps), readGolden(t, "requesttext.golden"); !bytes.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

var msgIDRe = regexp.MustCompile(`(?m)^Message-ID: <20261021044000\.([0-9a-f]{16})@pinger\.example\.org>$`)

func TestComposeRequest(t *testing.T) {
	// 06:40 in UTC+2 is 04:40 UTC.
	now := time.Date(2026, 10, 21, 6, 40, 0, 0, time.FixedZone("CEST", 2*3600))
	got, err := ComposeRequest(reqFrom, reqTo, "remailer-key", RequestText(reqTo, reqOps), now, "pinger.example.org")
	if err != nil {
		t.Fatal(err)
	}
	m := msgIDRe.FindSubmatch(got)
	if m == nil {
		t.Fatalf("no Message-ID like the design's in\n%s", got)
	}
	masked := bytes.Replace(got, m[1], []byte("RANDOM"), 1)
	if want := readGolden(t, "request.golden"); !bytes.Equal(masked, want) {
		t.Errorf("got\n%s\nwant\n%s", masked, want)
	}
	again, _ := ComposeRequest(reqFrom, reqTo, "remailer-key", RequestText(reqTo, reqOps), now, "pinger.example.org")
	if m2 := msgIDRe.FindSubmatch(again); m2 == nil || bytes.Equal(m2[1], m[1]) {
		t.Error("Message-ID isn't random")
	}

	// CRLF in, LF out, and a final line end added.
	got, err = ComposeRequest(reqFrom, reqTo, "remailer-conf", []byte("a\r\nb"), now, "pinger.example.org")
	if err != nil || !bytes.HasSuffix(got, []byte("\n\na\nb\n")) || bytes.ContainsRune(got, '\r') {
		t.Errorf("got %q, %v", got, err)
	}
}

// TestComposeRequestBothPaths sends one request over SMTP and sendmail:
// CRLF on the SMTP wire, LF to sendmail, the same text.
func TestComposeRequestBothPaths(t *testing.T) {
	data, err := ComposeRequest(reqFrom, reqTo, "remailer-key", RequestText(reqTo, reqOps), time.Unix(1792560000, 0), "pinger.example.org")
	if err != nil {
		t.Fatal(err)
	}
	mail := Mail{EnvelopeFrom: testFrom, Rcpt: []string{reqTo}, Data: data}

	f := newFakeSMTP(t, nil)
	cfg := smtpCfg(f, "localhost")
	cfg.UseTLS = false
	m, err := NewSMTP(cfg, "", fastOpts)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), mail); err != nil {
		t.Fatal(err)
	}
	wire := f.snapshot()[0].raw
	if want := bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n")); !bytes.Equal(wire, want) {
		t.Errorf("SMTP wire\n%q\nwant\n%q", wire, want)
	}

	out := t.TempDir() + "/out"
	t.Setenv("FAKESENDMAIL_OUT", out)
	if err := NewSendmail(fakeSendmail(t), 5*time.Second).Send(context.Background(), mail); err != nil {
		t.Fatal(err)
	}
	if stdin := readFile(t, out+".stdin"); !bytes.Equal(stdin, data) {
		t.Errorf("sendmail stdin\n%q\nwant\n%q", stdin, data)
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestComposeRequestInvalid(t *testing.T) {
	now := time.Unix(1792560000, 0)
	body := RequestText(reqTo, reqOps)
	for _, tc := range []struct {
		name, from, to, subject, domain string
		body                            []byte
	}{
		{"CR in subject", reqFrom, reqTo, "remailer-key\rBcc: x@example.org", "pinger.example.org", body},
		{"LF in subject", reqFrom, reqTo, "remailer-key\nBcc: x@example.org", "pinger.example.org", body},
		{"NUL in subject", reqFrom, reqTo, "remailer-key\x00", "pinger.example.org", body},
		{"8-bit subject", reqFrom, reqTo, "remailer-kéy", "pinger.example.org", body},
		{"empty subject", reqFrom, reqTo, "", "pinger.example.org", body},
		{"long subject", reqFrom, reqTo, strings.Repeat("x", 201), "pinger.example.org", body},
		{"CRLF in from", reqFrom + "\r\nBcc: x@example.org", reqTo, "remailer-key", "pinger.example.org", body},
		{"display name in from", "Pinger <" + reqFrom + ">", reqTo, "remailer-key", "pinger.example.org", body},
		{"LF in to", reqFrom, reqTo + "\nCc: x@example.org", "remailer-key", "pinger.example.org", body},
		{"two to", reqFrom, reqTo + ", x@example.org", "remailer-key", "pinger.example.org", body},
		{"CR in domain", reqFrom, reqTo, "remailer-key", "pinger.example.org\r", body},
		{"empty domain", reqFrom, reqTo, "remailer-key", "", body},
		{"NUL in body", reqFrom, reqTo, "remailer-key", "pinger.example.org", []byte("a\x00b\n")},
		{"8-bit body", reqFrom, reqTo, "remailer-key", "pinger.example.org", []byte("caf\xc3\xa9\n")},
	} {
		if _, err := ComposeRequest(tc.from, tc.to, tc.subject, tc.body, now, tc.domain); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", tc.name, err)
		}
	}
}

func TestNew(t *testing.T) {
	f := newFakeSMTP(t, nil)
	cfg := smtpCfg(f, "127.0.0.1")
	cfg.UseTLS = false
	cfg.MaxPerHour = 2
	m, err := New(cfg, "", fastOpts)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		err := m.Send(context.Background(), testMail())
		if i < 2 && err != nil {
			t.Fatal(err)
		}
		if i == 2 && !errors.Is(err, ErrRateLimited) {
			t.Errorf("third mail: got %v, want ErrRateLimited", err)
		}
	}
	if n := len(f.snapshot()); n != 2 {
		t.Errorf("%d sessions, want 2", n)
	}

	cfg = config.Mail{Method: config.MethodSendmail, Sendmail: fakeSendmail(t), MaxPerHour: 10}
	if _, err := New(cfg, "", Options{}); err != nil {
		t.Error(err)
	}
	cfg.Method = "pigeon"
	if _, err := New(cfg, "", Options{}); err == nil {
		t.Error("unknown method: no error")
	}
	cfg = config.Mail{Method: config.MethodSMTP, SMTPRelay: "relay.example.org", SMTPPort: 25}
	if _, err := New(cfg, "", Options{}); err == nil {
		t.Error("bad smtp config: no error")
	}
}
