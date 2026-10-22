package mailin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/token"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestDeliver(t *testing.T) {
	maildir := filepath.Join(t.TempDir(), "Maildir") // created by Deliver
	rcpt := addr(t, token.KindKey, 7, t0.Add(-time.Hour))
	in := "From remailer@remailer.example Thu Oct 22 11:59:00 2026\nDelivered-To: pinger@pinger.example.org\nTo: x@y\n\nbody\n"
	p, err := Deliver(maildir, strings.NewReader(in), envOf(map[string]string{"ORIGINAL_RECIPIENT": rcpt}), t0)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != filepath.Join(maildir, "new") {
		t.Errorf("path %s", p)
	}
	name := filepath.Base(p)
	if strings.HasPrefix(name, ".") || strings.ContainsAny(name, "/:") || !strings.HasPrefix(name, "1792670400.M0P") {
		t.Errorf("name %q", name)
	}
	got, _ := os.ReadFile(p)
	want := "X-Original-To: " + rcpt + "\nDelivered-To: pinger@pinger.example.org\nTo: x@y\n\nbody\n"
	if string(got) != want {
		t.Errorf("content %q\nwant %q", got, want)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 || !fi.ModTime().Equal(t0) {
		t.Errorf("mode %v mtime %v", fi.Mode(), fi.ModTime())
	}
	for _, sub := range []string{"cur", "new", "tmp"} {
		if fi, err := os.Stat(filepath.Join(maildir, sub)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", sub, fi, err)
		}
	}
	if n := listDir(t, filepath.Join(maildir, "tmp")); len(n) != 0 {
		t.Errorf("tmp/ has %v", n)
	}

	// The scanner handles it.
	e := newEnv(t)
	e.s.Maildir = maildir
	if res := e.scan(t); res != (Result{Handled: 1}) || e.h.calls[0].tok.ID != 7 {
		t.Errorf("scan %+v", res)
	}
}

func TestDeliverOriginalTo(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		env      map[string]string
		want     string
		err      error
	}{
		{"kept", "x-original-to:  A@B.example\nTo: z\n\nb\n",
			map[string]string{"ORIGINAL_RECIPIENT": "a@b.example"},
			"x-original-to:  A@B.example\nTo: z\n\nb\n", nil},
		{"sender's own does not hide ours", "X-Original-To: forged@example\nTo: z\n\nb\n",
			map[string]string{"ORIGINAL_RECIPIENT": "a@b.example"},
			"X-Original-To: a@b.example\nX-Original-To: forged@example\nTo: z\n\nb\n", nil},
		{"recipient fallback", "To: z\n\nb\n", map[string]string{"RECIPIENT": "r@b.example"},
			"X-Original-To: r@b.example\nTo: z\n\nb\n", nil},
		{"crlf", "To: z\r\n\r\nb\r\n", map[string]string{"ORIGINAL_RECIPIENT": "a@b.example"},
			"X-Original-To: a@b.example\r\nTo: z\r\n\r\nb\r\n", nil},
		{"none", "To: z\n\nb\n", nil, "To: z\n\nb\n", nil},
		{"lf injection", "To: z\n\nb\n", map[string]string{"ORIGINAL_RECIPIENT": "a@b\nBcc: victim@example"}, "", ErrBadRecipient},
		{"cr injection", "To: z\n\nb\n", map[string]string{"ORIGINAL_RECIPIENT": "a@b\rFrom: x"}, "", ErrBadRecipient},
		{"nul", "To: z\n\nb\n", map[string]string{"ORIGINAL_RECIPIENT": "a@b\x00"}, "", ErrBadRecipient},
		{"too long", "To: z\n\nb\n", map[string]string{"ORIGINAL_RECIPIENT": strings.Repeat("a", 1000) + "@b"}, "", ErrBadRecipient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maildir := t.TempDir()
			p, err := Deliver(maildir, strings.NewReader(tc.in), envOf(tc.env), t0)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err %v, want %v", err, tc.err)
			}
			if err != nil {
				if n := listDir(t, maildir); len(n) != 0 {
					t.Errorf("maildir has %v after an error", n)
				}
				return
			}
			got, _ := os.ReadFile(p)
			if string(got) != tc.want {
				t.Errorf("got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestDeliverOversize(t *testing.T) {
	maildir := t.TempDir()
	big := strings.Repeat("x", MaxSize+1)
	if _, err := Deliver(maildir, strings.NewReader(big), nil, t0); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err %v", err)
	}
	// Exactly MaxSize fits, but not with the header added.
	exact := "To: z\n\n" + strings.Repeat("x", MaxSize-7)
	if _, err := Deliver(maildir, strings.NewReader(exact), envOf(map[string]string{"ORIGINAL_RECIPIENT": "a@b"}), t0); !errors.Is(err, ErrTooLarge) {
		t.Errorf("with header: err %v", err)
	}
	if n := listDir(t, maildir); len(n) != 0 {
		t.Errorf("maildir has %v", n)
	}
	if _, err := Deliver(maildir, strings.NewReader(exact), nil, t0); err != nil {
		t.Errorf("exact size: %v", err)
	}
}

func TestDeliverUnique(t *testing.T) {
	maildir := t.TempDir()
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := Deliver(maildir, strings.NewReader("To: z\n\nb\n"), nil, t0)
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatalf("name %s twice", p)
		}
		seen[p] = true
	}
}

func TestHasHeader(t *testing.T) {
	data := []byte("Subject: x\nX-Original-To:\n a@b\nTo: c\n\nX-Original-To: body@x\n")
	if !hasHeader(data, "x-original-to", "A@B") {
		t.Error("folded header not found")
	}
	if hasHeader(data, "X-Original-To", "body@x") {
		t.Error("found a body line")
	}
}
