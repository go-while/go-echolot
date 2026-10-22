package mailin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/token"
)

var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func testMinter(t testing.TB) *token.Minter {
	t.Helper()
	m, err := token.New(token.Config{
		Secret:    bytes.Repeat([]byte{7}, 32),
		Address:   "pinger@pinger.example.org",
		Delimiter: "+",
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func addr(t testing.TB, kind token.Kind, id int, at time.Time) string {
	t.Helper()
	a, err := testMinter(t).Address(token.Token{Kind: kind, ID: id, Time: at})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// call is one Handle call.
type call struct {
	tok token.Token
	m   *Message
}

// recorder is a Handler that records calls and returns what next says.
type recorder struct {
	mu    sync.Mutex
	calls []call
	next  func(n int) error // n counts calls from 1; nil: always nil
}

func (r *recorder) Handle(_ context.Context, tok token.Token, m *Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call{tok, m})
	if r.next != nil {
		return r.next(len(r.calls))
	}
	return nil
}

type env struct {
	maildir, errors string
	h               *recorder
	s               *Scanner
	now             time.Time
}

func newEnv(t testing.TB) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{maildir: filepath.Join(dir, "Maildir"), errors: filepath.Join(dir, "mail-errors"), h: &recorder{}, now: t0}
	for _, sub := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(e.maildir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.s = &Scanner{Maildir: e.maildir, ErrorsDir: e.errors, Minter: testMinter(t), Handler: e.h,
		Now: func() time.Time { return e.now }}
	return e
}

// put writes a mail into new/ with mtime t0 - age.
func (e *env) put(t testing.TB, name, content string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(e.maildir, "new", name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	mt := t0.Add(-age)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *env) scan(t testing.TB) Result {
	t.Helper()
	res, err := e.s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// reason returns the reason file of a rejected mail, or "".
func (e *env) reason(name string) string {
	b, _ := os.ReadFile(filepath.Join(e.errors, name+".reason"))
	return string(b)
}

func reply(to string, extra ...string) string {
	h := "Return-Path: <remailer@remailer.example>\n" +
		"X-Original-To: " + to + "\n" +
		"Delivered-To: " + to + "\n" +
		"From: remailer@remailer.example\n" +
		"To: " + to + "\n" +
		"Subject: Remailer key for test\n"
	for _, x := range extra {
		h += x + "\n"
	}
	return h + "\nbody line\n"
}

func TestHandledAndDeleted(t *testing.T) {
	e := newEnv(t)
	to := addr(t, token.KindKey, 12, t0.Add(-time.Hour))
	p := e.put(t, "1.M1P1.host", reply(to), 30*time.Minute)
	res := e.scan(t)
	if res != (Result{Handled: 1}) {
		t.Fatalf("result %+v", res)
	}
	if len(e.h.calls) != 1 {
		t.Fatalf("%d calls", len(e.h.calls))
	}
	c := e.h.calls[0]
	if c.tok.Kind != token.KindKey || c.tok.ID != 12 || !c.tok.Time.Equal(t0.Add(-time.Hour)) {
		t.Errorf("token %+v", c.tok)
	}
	if c.m.Path != p || !c.m.Delivered.Equal(t0.Add(-30*time.Minute)) || c.m.Rcpt != to {
		t.Errorf("message %q %v %q", c.m.Path, c.m.Delivered, c.m.Rcpt)
	}
	if string(c.m.Body) != "body line\n" || c.m.Header.Get("Subject") != "Remailer key for test" {
		t.Errorf("body %q subject %q", c.m.Body, c.m.Header.Get("Subject"))
	}
	if exists(p) {
		t.Error("handled mail not deleted")
	}
	if ents, _ := os.ReadDir(e.errors); len(ents) != 0 {
		t.Errorf("errors dir has %d entries", len(ents))
	}
}

func TestOldestFirst(t *testing.T) {
	e := newEnv(t)
	for i, age := range []time.Duration{time.Minute, 3 * time.Minute, 2 * time.Minute} {
		e.put(t, fmt.Sprintf("m%d", i), reply(addr(t, token.KindConf, i+1, t0.Add(-time.Hour))), age)
	}
	e.scan(t)
	var ids []int
	for _, c := range e.h.calls {
		ids = append(ids, c.tok.ID)
	}
	if fmt.Sprint(ids) != "[2 3 1]" {
		t.Errorf("order %v", ids)
	}
}

func TestTransientThenSuccess(t *testing.T) {
	e := newEnv(t)
	e.h.next = func(n int) error {
		if n == 1 {
			return errors.New("disk full")
		}
		return nil
	}
	p := e.put(t, "m", reply(addr(t, token.KindKey, 3, t0.Add(-time.Hour))), time.Minute)
	if res := e.scan(t); res != (Result{Pending: 1}) || !exists(p) {
		t.Fatalf("first scan %+v, exists %v", res, exists(p))
	}
	e.now = e.now.Add(time.Minute)
	if res := e.scan(t); res != (Result{Handled: 1}) || exists(p) {
		t.Fatalf("second scan %+v, exists %v", res, exists(p))
	}
	if len(e.h.calls) != 2 || e.h.calls[0].tok != e.h.calls[1].tok {
		t.Errorf("calls %+v", e.h.calls)
	}
}

func TestTransientDoesNotBlockOthers(t *testing.T) {
	e := newEnv(t)
	bad := addr(t, token.KindKey, 1, t0.Add(-time.Hour))
	e.h.next = func(n int) error {
		if e.h.calls[n-1].tok.ID == 1 {
			return errors.New("busy")
		}
		return nil
	}
	e.put(t, "a", reply(bad), 2*time.Minute)
	e.put(t, "b", reply(addr(t, token.KindKey, 2, t0.Add(-time.Hour))), time.Minute)
	if res := e.scan(t); res != (Result{Handled: 1, Pending: 1}) {
		t.Errorf("result %+v", res)
	}
}

func TestTransientGivesUp(t *testing.T) {
	t.Run("tries", func(t *testing.T) {
		e := newEnv(t)
		e.s.MaxTries = 3
		e.h.next = func(int) error { return errors.New("store unavailable") }
		e.put(t, "m", reply(addr(t, token.KindKey, 3, t0.Add(-time.Hour))), time.Minute)
		for i := 0; i < 2; i++ {
			if res := e.scan(t); res != (Result{Pending: 1}) {
				t.Fatalf("scan %d: %+v", i, res)
			}
		}
		if res := e.scan(t); res != (Result{Rejected: 1}) {
			t.Fatalf("third scan %+v", res)
		}
		if r := e.reason("m"); !strings.Contains(r, "reason: retries used") || !strings.Contains(r, "store unavailable") {
			t.Errorf("reason %q", r)
		}
	})
	t.Run("time", func(t *testing.T) {
		e := newEnv(t)
		e.h.next = func(int) error { return errors.New("store unavailable") }
		e.put(t, "m", reply(addr(t, token.KindKey, 3, t0.Add(-time.Hour))), time.Minute)
		e.scan(t)
		e.now = e.now.Add(DefaultRetryFor)
		if res := e.scan(t); res != (Result{Rejected: 1}) {
			t.Fatalf("after a day %+v", res)
		}
	})
}

func TestPermanent(t *testing.T) {
	e := newEnv(t)
	e.h.next = func(int) error { return fmt.Errorf("conf: %w", Permanent(errors.New("no $remailer line"))) }
	p := e.put(t, "m", reply(addr(t, token.KindConf, 3, t0.Add(-time.Hour))), time.Minute)
	if res := e.scan(t); res != (Result{Rejected: 1}) {
		t.Fatalf("result %+v", res)
	}
	if exists(p) || !exists(filepath.Join(e.errors, "m")) {
		t.Error("not moved")
	}
	if r := e.reason("m"); !strings.Contains(r, "reason: handler error") || !strings.Contains(r, "no $remailer line") {
		t.Errorf("reason %q", r)
	}
	if Permanent(nil) != nil || IsPermanent(errors.New("x")) {
		t.Error("Permanent(nil) or IsPermanent")
	}
}

func TestHandlerPanic(t *testing.T) {
	e := newEnv(t)
	e.h.next = func(int) error { panic("boom") }
	e.put(t, "m", reply(addr(t, token.KindConf, 3, t0.Add(-time.Hour))), time.Minute)
	if res := e.scan(t); res != (Result{Rejected: 1}) {
		t.Fatalf("result %+v", res)
	}
	if r := e.reason("m"); !strings.Contains(r, "handler panic: boom") {
		t.Errorf("reason %q", r)
	}
}

func TestRejected(t *testing.T) {
	good := addr(t, token.KindKey, 5, t0.Add(-time.Hour))
	at := strings.Index(good, "@")
	last := "0"
	if good[at-1] == '0' {
		last = "1"
	}
	badMAC := good[:at-1] + last + good[at:] // a hex digit off
	for _, tc := range []struct {
		name, mail string
		reason     Reason
	}{
		{"none", reply("pinger@pinger.example.org"), ReasonNoToken},
		{"spam", "From: spammer@example.com\nTo: someone@example.com\nSubject: buy\n\nnow\n", ReasonNoToken},
		{"badmac", reply(badMAC), ReasonBadToken},
		{"old", reply(addr(t, token.KindKey, 5, t0.Add(-8*24*time.Hour))), ReasonBadToken},
		{"future", reply(addr(t, token.KindKey, 5, t0.Add(2*time.Hour))), ReasonBadToken},
		{"unparsable", "this is not a header line\n\nbody\n", ReasonUnparsable},
		{"empty", "", ReasonUnparsable},
		{"binary", "\x00\x01\x02\xff\xfe", ReasonUnparsable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			p := e.put(t, tc.name, tc.mail, time.Hour)
			if res := e.scan(t); res != (Result{Rejected: 1}) {
				t.Fatalf("result %+v", res)
			}
			if len(e.h.calls) != 0 {
				t.Error("handler called")
			}
			if exists(p) {
				t.Error("still in new/")
			}
			moved := filepath.Join(e.errors, tc.name)
			got, err := os.ReadFile(moved)
			if err != nil || string(got) != tc.mail {
				t.Errorf("moved content %q, %v", got, err)
			}
			if fi, err := os.Stat(moved); err != nil || !fi.ModTime().Equal(t0) {
				t.Errorf("moved mtime %v, %v; want the move time", fi.ModTime(), err)
			}
			r := e.reason(tc.name)
			if !strings.Contains(r, "reason: "+string(tc.reason)+"\n") || !strings.Contains(r, "delivered: 2026-10-22T11:00:00Z") {
				t.Errorf("reason file %q", r)
			}
			if strings.ContainsAny(r, "\x00\x01\xff") {
				t.Errorf("reason file not sanitized: %q", r)
			}
		})
	}
}

func TestErrorsNameTaken(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.errors, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(e.errors, "m"), []byte("older"), 0o600)
	e.put(t, "m", "junk\n", time.Minute)
	e.scan(t)
	if b, _ := os.ReadFile(filepath.Join(e.errors, "m")); string(b) != "older" {
		t.Error("overwrote an existing file")
	}
	if b, _ := os.ReadFile(filepath.Join(e.errors, "m.1")); string(b) != "junk\n" {
		t.Errorf("m.1 = %q", b)
	}
}

func TestOversized(t *testing.T) {
	t.Run("limit", func(t *testing.T) {
		e := newEnv(t)
		to := addr(t, token.KindKey, 5, t0.Add(-time.Hour))
		head := reply(to)
		ok := head + strings.Repeat("x", MaxSize-len(head))
		e.put(t, "ok", ok, 2*time.Minute)
		e.put(t, "big", ok+"x", time.Minute)
		if res := e.scan(t); res != (Result{Handled: 1, Rejected: 1}) {
			t.Fatalf("result %+v", res)
		}
		if r := e.reason("big"); !strings.Contains(r, "reason: oversized") {
			t.Errorf("reason %q", r)
		}
	})
	t.Run("sparse", func(t *testing.T) {
		// 64 GiB: reading it would take far longer than the test.
		e := newEnv(t)
		p := filepath.Join(e.maildir, "new", "huge")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(reply(addr(t, token.KindKey, 5, t0.Add(-time.Hour))))
		if err := f.Truncate(64 << 30); err != nil {
			t.Skip("no sparse files:", err)
		}
		f.Close()
		start := time.Now()
		if res := e.scan(t); res != (Result{Rejected: 1}) {
			t.Fatalf("result %+v", res)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("took %v", d)
		}
		if len(e.h.calls) != 0 || !strings.Contains(e.reason("huge"), "reason: oversized") {
			t.Error("not rejected as oversized")
		}
	})
}

func TestLongLines(t *testing.T) {
	// net/mail (textproto) has no line limit for headers; check it.
	long := strings.Repeat("a", 100<<10)
	msg, err := mail.ReadMessage(strings.NewReader("X-Long: " + long + "\nSubject: s\n\nb\n"))
	if err != nil || msg.Header.Get("X-Long") != long {
		t.Fatalf("net/mail: %v", err)
	}

	e := newEnv(t)
	to := addr(t, token.KindKey, 5, t0.Add(-time.Hour))
	mailText := "X-Long: " + long + "\n" + "X-Original-To: " + to + "\n\n" + long + "\nend\n"
	e.put(t, "m", mailText, time.Minute)
	if res := e.scan(t); res != (Result{Handled: 1}) {
		t.Fatalf("result %+v", res)
	}
	m := e.h.calls[0].m
	if m.Header.Get("X-Long") != long || string(m.Body) != long+"\nend\n" {
		t.Error("long header or body line mangled")
	}
}

func TestRecipientHeaders(t *testing.T) {
	keyA := addr(t, token.KindKey, 1, t0.Add(-time.Hour))
	keyB := addr(t, token.KindKey, 2, t0.Add(-time.Hour))
	for _, tc := range []struct {
		name, mail string
		id         int
		rcpt       string
	}{
		{"delivered-to second",
			"Delivered-To: other@pinger.example.org\nDelivered-To: " + keyB + "\nTo: x@y\n\nb\n", 2, keyB},
		{"folded to",
			"From: r@r\nTo: Pinger\n <" + keyA + ">,\n\tother@example.org\n\nb\n", 1, "Pinger <" + keyA + ">, other@example.org"},
		{"x-original-to preferred",
			"To: " + keyB + "\nX-Original-To: " + keyA + "\n\nb\n", 1, keyA},
		{"delivered-to before to",
			"To: " + keyB + "\nDelivered-To: " + keyA + "\n\nb\n", 1, keyA},
		{"cc", "To: someone@example.org\nCc: \"P\" <" + keyB + ">\n\nb\n", 2, "\"P\" <" + keyB + ">"},
		{"bad x-original-to, good to",
			"X-Original-To: pinger+key.1=1=0000000000000000@pinger.example.org\nTo: " + keyB + "\n\nb\n", 2, keyB},
		{"upper case", "To: " + strings.ToUpper(keyA) + "\n\nb\n", 1, strings.ToUpper(keyA)},
		{"mbox from line", "From remailer@remailer.example Thu Oct 22 11:00:00 2026\nTo: " + keyA + "\n\nb\n", 1, keyA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.put(t, "m", tc.mail, time.Minute)
			if res := e.scan(t); res != (Result{Handled: 1}) {
				t.Fatalf("result %+v", res)
			}
			c := e.h.calls[0]
			if c.tok.ID != tc.id || c.m.Rcpt != tc.rcpt {
				t.Errorf("got id %d rcpt %q; want %d %q", c.tok.ID, c.m.Rcpt, tc.id, tc.rcpt)
			}
		})
	}
}

// postfixDSN is a Postfix bounce of our remailer-key request to
// remailer@remailer.example, sent to rcpt, the request's envelope
// sender being bounceAddr and its From fromAddr.
func postfixDSN(rcpt, bounceAddr, fromAddr string) string {
	s := `Return-Path: <>
X-Original-To: RCPT
Delivered-To: RCPT
Received: by mail.pinger.example.org (Postfix)
	id 4Hb2Xk1zQ2z9vB; Thu, 22 Oct 2026 11:30:02 +0000 (UTC)
Date: Thu, 22 Oct 2026 11:30:02 +0000 (UTC)
From: MAILER-DAEMON@mail.pinger.example.org (Mail Delivery System)
Subject: Undelivered Mail Returned to Sender
To: RCPT
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status;
	boundary="4Hb2Xj6yZTz9vC.1792668602/mail.pinger.example.org"
Content-Transfer-Encoding: 8bit
Message-Id: <4Hb2Xk1zQ2z9vB@mail.pinger.example.org>

This is a MIME-encapsulated message.

--4Hb2Xj6yZTz9vC.1792668602/mail.pinger.example.org
Content-Description: Notification
Content-Type: text/plain; charset=us-ascii

This is the mail system at host mail.pinger.example.org.

I'm sorry to have to inform you that your message could not
be delivered to one or more recipients. It's attached below.

For further assistance, please send mail to postmaster.

If you do so, please include this problem report. You can
delete your own text from the attached returned message.

                   The mail system

<remailer@remailer.example>: host mx.remailer.example[192.0.2.25] said:
    550 5.1.1 <remailer@remailer.example>: Recipient address rejected: User
    unknown in local recipient table (in reply to RCPT TO command)

--4Hb2Xj6yZTz9vC.1792668602/mail.pinger.example.org
Content-Description: Delivery report
Content-Type: message/delivery-status

Reporting-MTA: dns; mail.pinger.example.org
X-Postfix-Queue-ID: 4Hb2Xj6yZTz9vC
X-Postfix-Sender: rfc822; BOUNCE
Arrival-Date: Thu, 22 Oct 2026 11:30:01 +0000 (UTC)

Final-Recipient: rfc822; remailer@remailer.example
Original-Recipient: rfc822;remailer@remailer.example
Action: failed
Status: 5.1.1
Remote-MTA: dns; mx.remailer.example
Diagnostic-Code: smtp; 550 5.1.1 <remailer@remailer.example>: Recipient address
    rejected: User unknown in local recipient table

--4Hb2Xj6yZTz9vC.1792668602/mail.pinger.example.org
Content-Description: Undelivered Message Headers
Content-Type: text/rfc822-headers
Content-Transfer-Encoding: 8bit

Return-Path: <BOUNCE>
Received: by mail.pinger.example.org (Postfix, from userid 1001)
	id 4Hb2Xj6yZTz9vC; Thu, 22 Oct 2026 11:30:01 +0000 (UTC)
From: FROM
To: remailer@remailer.example
Subject: remailer-key
Message-Id: <20261022113001.4Hb2Xj6yZTz9vC@mail.pinger.example.org>
Date: Thu, 22 Oct 2026 11:30:01 +0000 (UTC)

--4Hb2Xj6yZTz9vC.1792668602/mail.pinger.example.org--
`
	return strings.NewReplacer("RCPT", rcpt, "BOUNCE", bounceAddr, "FROM", fromAddr).Replace(s)
}

func TestBounce(t *testing.T) {
	sent := t0.Add(-30 * time.Minute)
	bounce := addr(t, token.KindBounce, 12, sent)
	from := addr(t, token.KindKey, 12, sent)
	t.Run("verp recipient", func(t *testing.T) {
		e := newEnv(t)
		e.put(t, "dsn", postfixDSN(bounce, bounce, from), time.Minute)
		if res := e.scan(t); res != (Result{Handled: 1}) {
			t.Fatalf("result %+v", res)
		}
		c := e.h.calls[0]
		if c.tok.Kind != token.KindBounce || c.tok.ID != 12 || c.m.Rcpt != bounce {
			t.Errorf("token %+v rcpt %q", c.tok, c.m.Rcpt)
		}
	})
	t.Run("in body only", func(t *testing.T) {
		// Delivered to the plain address: the token is only in the
		// returned headers, next to the From with a key token.
		e := newEnv(t)
		e.put(t, "dsn", postfixDSN("pinger@pinger.example.org", bounce, from), time.Minute)
		if res := e.scan(t); res != (Result{Handled: 1}) {
			t.Fatalf("result %+v", res)
		}
		c := e.h.calls[0]
		if c.tok.Kind != token.KindBounce || c.tok.ID != 12 {
			t.Errorf("token %+v", c.tok)
		}
		if !strings.Contains(c.m.Rcpt, bounce) {
			t.Errorf("rcpt %q", c.m.Rcpt)
		}
	})
	t.Run("key token in body is not a reply", func(t *testing.T) {
		e := newEnv(t)
		e.put(t, "m", "To: pinger@pinger.example.org\n\nFrom: "+from+"\n", time.Minute)
		if res := e.scan(t); res != (Result{Rejected: 1}) {
			t.Fatalf("result %+v", res)
		}
	})
}

func TestIgnored(t *testing.T) {
	e := newEnv(t)
	valid := reply(addr(t, token.KindKey, 5, t0.Add(-time.Hour)))
	tmp := filepath.Join(e.maildir, "tmp", "partial")
	os.WriteFile(tmp, []byte(valid), 0o600)
	cur := filepath.Join(e.maildir, "cur", "seen:2,S")
	os.WriteFile(cur, []byte(valid), 0o600)
	dot := e.put(t, ".hidden", valid, time.Minute)
	os.Mkdir(filepath.Join(e.maildir, "new", "subdir"), 0o700)

	outside := filepath.Join(t.TempDir(), "target")
	os.WriteFile(outside, []byte(valid), 0o600)
	link := filepath.Join(e.maildir, "new", "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	if res := e.scan(t); res != (Result{}) {
		t.Errorf("result %+v", res)
	}
	if len(e.h.calls) != 0 {
		t.Error("handler called")
	}
	for _, p := range []string{tmp, cur, dot, link, outside} {
		if !exists(p) {
			t.Errorf("%s removed", p)
		}
	}
	if b, _ := os.ReadFile(outside); string(b) != valid {
		t.Error("symlink target changed")
	}
}

func TestReadMailNoFollow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("To: x\n\n"), 0o600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	if _, _, _, err := readMail(link); !errors.Is(err, errSkip) {
		t.Errorf("readMail(symlink) = %v", err)
	}
}

func TestCrashBeforeUnlink(t *testing.T) {
	e := newEnv(t)
	persisted := 0
	e.h.next = func(int) error { persisted++; return nil }
	e.s.beforeUnlink = func(string) bool { return false } // "crash"
	p := e.put(t, "m", reply(addr(t, token.KindKey, 5, t0.Add(-time.Hour))), time.Minute)
	if _, err := e.s.Scan(context.Background()); !errors.Is(err, errCrash) {
		t.Fatalf("scan: %v", err)
	}
	if persisted != 1 || !exists(p) {
		t.Fatalf("persisted %d, exists %v", persisted, exists(p))
	}
	// Restart: a new Scanner sees the same file.
	e.s = &Scanner{Maildir: e.maildir, ErrorsDir: e.errors, Minter: testMinter(t), Handler: e.h,
		Now: func() time.Time { return e.now }}
	if res := e.scan(t); res != (Result{Handled: 1}) || exists(p) {
		t.Fatalf("after restart %+v, exists %v", res, exists(p))
	}
	if persisted != 2 || e.h.calls[0].tok != e.h.calls[1].tok {
		t.Errorf("calls %+v", e.h.calls)
	}
}

func TestCanceled(t *testing.T) {
	e := newEnv(t)
	p := e.put(t, "m", reply(addr(t, token.KindKey, 5, t0.Add(-time.Hour))), time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.s.Scan(ctx); !errors.Is(err, context.Canceled) || !exists(p) {
		t.Errorf("err %v exists %v", err, exists(p))
	}
}

func TestMissingNew(t *testing.T) {
	s := &Scanner{Maildir: filepath.Join(t.TempDir(), "nope"), ErrorsDir: t.TempDir(), Minter: testMinter(t), Handler: &recorder{}}
	if _, err := s.Scan(context.Background()); err == nil {
		t.Error("no error for a missing Maildir")
	}
}

func TestPruneErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, age time.Duration) {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, t0.Add(-age), t0.Add(-age))
	}
	write("old", 8*24*time.Hour)
	write("old.reason", 8*24*time.Hour)
	write("new", 6*24*time.Hour)
	write("new.reason", 6*24*time.Hour)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	n, err := PruneErrors(dir, t0, ErrorRetention)
	if err != nil || n != 2 {
		t.Fatalf("n %d err %v", n, err)
	}
	for name, want := range map[string]bool{"old": false, "old.reason": false, "new": true, "new.reason": true, "sub": true} {
		if exists(filepath.Join(dir, name)) != want {
			t.Errorf("%s exists = %v", name, !want)
		}
	}
	if n, err := PruneErrors(filepath.Join(dir, "missing"), t0, ErrorRetention); n != 0 || err != nil {
		t.Errorf("missing dir: %d %v", n, err)
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("a\x00b\nc\xffd", 100); got != "a?b?c?d" {
		t.Errorf("got %q", got)
	}
	if got := sanitize(strings.Repeat("x", 50), 10); got != "xxxxxxxxxx..." {
		t.Errorf("got %q", got)
	}
}

func TestMoveAcrossFileSystems(t *testing.T) {
	defer func(old func(string, string) error) { rename = old }(rename)
	rename = func(string, string) error { return &os.LinkError{Op: "rename", Err: syscall.EXDEV} }
	e := newEnv(t)
	e.put(t, "small", "junk\n", time.Minute)
	e.put(t, "big", strings.Repeat("y", MaxSize+10), 2*time.Minute)
	if res := e.scan(t); res != (Result{Rejected: 2}) {
		t.Fatalf("result %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(e.errors, "small")); string(b) != "junk\n" {
		t.Errorf("small copy %q", b)
	}
	if fi, err := os.Stat(filepath.Join(e.errors, "big")); err != nil || fi.Size() != MaxSize || fi.Mode().Perm() != 0o600 {
		t.Errorf("big copy %v %v", fi, err)
	}
	if !strings.Contains(e.reason("big"), "copy cut to MaxSize") {
		t.Errorf("reason %q", e.reason("big"))
	}
	if n := listDir(t, filepath.Join(e.maildir, "new")); len(n) != 0 {
		t.Errorf("new/ has %v", n)
	}
}

func TestUnreadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads anything")
	}
	e := newEnv(t)
	e.s.MaxTries = 2
	p := e.put(t, "m", "To: x\n\n", time.Minute)
	os.Chmod(p, 0)
	if res := e.scan(t); res != (Result{Pending: 1}) {
		t.Fatalf("first %+v", res)
	}
	if res := e.scan(t); res != (Result{Rejected: 1}) {
		t.Fatalf("second %+v", res)
	}
}

func TestHandlerFunc(t *testing.T) {
	e := newEnv(t)
	var got token.Kind
	e.s.Handler = HandlerFunc(func(_ context.Context, tok token.Token, _ *Message) error { got = tok.Kind; return nil })
	e.put(t, "m", reply(addr(t, token.KindHelp, 1, t0.Add(-time.Hour))), time.Minute)
	if e.scan(t); got != token.KindHelp {
		t.Errorf("kind %q", got)
	}
}
