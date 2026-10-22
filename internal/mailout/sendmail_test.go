package mailout

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSendmail returns the absolute path of the test script.
func fakeSendmail(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("testdata/fakesendmail.sh")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSendmail(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv("FAKESENDMAIL_OUT", out)
	m := NewSendmail(fakeSendmail(t), 5*time.Second)
	mail := testMail()
	mail.Rcpt = []string{testRcpt, "second@remailer.example.net"}
	mail.Data = []byte("Subject: x\r\n\r\nline one\r\n.\r\nend\r\n")
	if err := m.Send(context.Background(), mail); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(out + ".args")
	if err != nil {
		t.Fatal(err)
	}
	want := "-i\n-f\n" + testFrom + "\n--\n" + testRcpt + "\nsecond@remailer.example.net\n"
	if string(args) != want {
		t.Errorf("args %q, want %q", args, want)
	}
	stdin, err := os.ReadFile(out + ".stdin")
	if err != nil {
		t.Fatal(err)
	}
	// LF line ends; -i keeps the lone dot from ending the message.
	if want := "Subject: x\n\nline one\n.\nend\n"; string(stdin) != want {
		t.Errorf("stdin %q, want %q", stdin, want)
	}
}

func TestSendmailExit(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv("FAKESENDMAIL_OUT", out)
	t.Setenv("FAKESENDMAIL_STDERR", "sendmail: queue file write error\x1b[31m")
	m := NewSendmail(fakeSendmail(t), 5*time.Second)
	for _, tc := range []struct {
		exit      string
		permanent bool
	}{
		{"75", false}, // EX_TEMPFAIL
		{"1", false},
		{"69", false}, // EX_UNAVAILABLE
		{"71", false}, // EX_OSERR
		{"65", true},  // EX_DATAERR
		{"67", true},  // EX_NOUSER
	} {
		t.Setenv("FAKESENDMAIL_EXIT", tc.exit)
		err := m.Send(context.Background(), testMail())
		var e *Error
		if !errors.As(err, &e) || IsPermanent(err) != tc.permanent || errors.Is(err, ErrTemporary) == tc.permanent {
			t.Errorf("exit %s: got %v, permanent %v, want %v", tc.exit, err, IsPermanent(err), tc.permanent)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "exit status "+tc.exit) || !strings.Contains(msg, "queue file write error") || strings.ContainsAny(msg, "\n\x1b") {
			t.Errorf("exit %s: error %q", tc.exit, msg)
		}
	}
}

func TestSendmailTimeout(t *testing.T) {
	t.Setenv("FAKESENDMAIL_OUT", filepath.Join(t.TempDir(), "out"))
	t.Setenv("FAKESENDMAIL_SLEEP", "30")
	m := NewSendmail(fakeSendmail(t), 300*time.Millisecond)
	start := time.Now()
	err := m.Send(context.Background(), testMail())
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
	if !errors.Is(err, ErrTemporary) || !strings.Contains(err.Error(), "killed after 300ms") {
		t.Errorf("got %v", err)
	}
}

func TestSendmailMissing(t *testing.T) {
	m := NewSendmail(filepath.Join(t.TempDir(), "no-sendmail"), time.Second)
	err := m.Send(context.Background(), testMail())
	if !errors.Is(err, ErrTemporary) {
		t.Errorf("got %v, want a temporary error", err)
	}
}

func TestBoundedBuffer(t *testing.T) {
	b := &boundedBuffer{max: 10}
	b.Write([]byte("hello\n"))
	b.Write([]byte("world, and more"))
	b.Write([]byte("x"))
	if got := b.text(); got != "hello worl ..." {
		t.Errorf("got %q", got)
	}
}
