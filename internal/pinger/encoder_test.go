package pinger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/blake2s"
	"github.com/go-while/go-echolot/internal/civil"
	"github.com/go-while/go-echolot/internal/replies"
)

// testKey returns a key for nick at address with a random public key.
func testKey(t *testing.T, nick, address string) replies.ParsedKey {
	t.Helper()
	var pk [32]byte
	rand.Read(pk[:])
	sum := blake2s.Sum128(pk[:])
	today := civil.Of(time.Now())
	return replies.ParsedKey{
		SummaryLine: replies.SummaryLine{Nick: nick, Address: address, KeyID: hex.EncodeToString(sum[:]),
			Version: "4:0.2.7", Caps: "M", Created: today.AddDays(-1), Expires: today.AddDays(13)},
		PK: pk,
	}
}

// fakeYamn installs testdata/fakeyamn.sh in a temp dir with mode and
// returns its path and the record dir.
func fakeYamn(t *testing.T, mode string) (bin, rec string) {
	t.Helper()
	dir := t.TempDir()
	script, err := os.ReadFile("testdata/fakeyamn.sh")
	if err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "yamn")
	if err := os.WriteFile(bin, script, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mode"), []byte(mode+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return bin, filepath.Join(dir, "record")
}

func readRec(t *testing.T, rec, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rec, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testPingMail(t *testing.T, withFrom bool) []byte {
	b := testBody()
	b.WithFrom = withFrom
	return Mail("pinger+ping=1792560000=0123456789abcdef@example.org", "pinger@example.org", withFrom, seal(t, b, 500))
}

func TestYamnEncoder(t *testing.T) {
	bin, rec := fakeYamn(t, "ok")
	tmp := t.TempDir()
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: tmp, Timeout: 10 * time.Second}
	middle := testKey(t, "middle", "mix@middle.example")
	exit := testKey(t, "exit", "mix@exit.example")
	in := testPingMail(t, false)

	to, m, err := enc.Encode(context.Background(), []Hop{HopOf(middle), HopOf(exit)}, in)
	if err != nil {
		t.Fatal(err)
	}
	if to != middle.Address {
		t.Errorf("to = %q", to)
	}
	wantMail := "To: mix@middle.example\nFrom: pinger@example.org\nSubject: yamn-0.2.7\n\n" +
		"::\nRemailer-Type: yamn-0.2.7\n\n-----BEGIN REMAILER MESSAGE-----\n20480\n" +
		"From the body, escaped\nAAAA\n-----END REMAILER MESSAGE-----\n"
	if string(m) != wantMail {
		t.Errorf("mail:\n%q\nwant\n%q", m, wantMail)
	}

	dir := strings.TrimSpace(readRec(t, rec, "dir"))
	wantArgs := []string{"--config", filepath.Join(dir, "yamn.yml"), "--dir", dir,
		"-m", "--stdout", "-c", "1", "--nodummy", "-l", "mix@middle.example,mix@exit.example"}
	if got := strings.Split(strings.TrimSuffix(readRec(t, rec, "args"), "\n"), "\n"); !slices.Equal(got, wantArgs) {
		t.Errorf("args:\n%q\nwant\n%q", got, wantArgs)
	}
	if got := readRec(t, rec, "stdin"); got != string(in) {
		t.Errorf("stdin differs")
	}
	if got := strings.TrimSpace(readRec(t, rec, "mode")); got != "700" {
		t.Errorf("D has mode %s", got)
	}
	if !strings.HasPrefix(dir, tmp+string(os.PathSeparator)) {
		t.Errorf("D %s is not in TmpDir %s", dir, tmp)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("D not removed: %v", err)
	}
	if got := strings.Fields(readRec(t, rec, "ls")); !slices.Equal(got, []string{"pubring.mix", "yamn.yml"}) {
		t.Errorf("D holds %q", got)
	}
	// The keyring: exactly the hop keys, canonical.
	ring := readRec(t, rec, "pubring.mix")
	kr := replies.ParseKey([]byte(ring))
	if len(kr.Keys) != 2 || len(kr.Errors) != 0 {
		t.Fatalf("pubring.mix: %d keys, errors %v", len(kr.Keys), kr.Errors)
	}
	for _, k := range kr.Keys {
		if k != middle && k != exit {
			t.Errorf("pubring.mix has %s", k.String())
		}
	}
	// The config.
	cfg := readRec(t, rec, "yamn.yml")
	for _, want := range []string{
		"\n  fetch: false\n", "\n  key_pinning: \"off\"\n", "\n  num_copies: 1\n",
		"\n  use_expired: false\n", "\n  address: \"pinger@example.org\"\n",
		"\n  pubring: \"" + filepath.Join(dir, "pubring.mix") + "\"\n",
		"\n  mlist2: \"" + filepath.Join(dir, "mlist2.txt") + "\"\n",
		"\n  pooldir: \"" + filepath.Join(dir, "pool") + "\"\n",
		"\n  keypins: \"" + filepath.Join(dir, "keypins.json") + "\"\n",
		"\n  pubring: \"\"\n", "\n  outfile: true\n",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("yamn.yml lacks %q:\n%s", want, cfg)
		}
	}
	// A minimal environment: nothing of ours leaks into yamn.
	env := readRec(t, rec, "env")
	if !strings.Contains(env, "HOME="+dir+"\n") || strings.Contains(env, "YAMNCFG") {
		t.Errorf("env:\n%s", env)
	}
}

func TestYamnEncoderKeepFrom(t *testing.T) {
	bin, rec := fakeYamn(t, "ok")
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
	if _, _, err := enc.Encode(context.Background(), []Hop{HopOf(testKey(t, "exit", "mix@exit.example"))}, testPingMail(t, true)); err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSuffix(readRec(t, rec, "args"), "\n"), "\n")
	if !slices.Contains(args, "--keep-from") || args[len(args)-1] != "mix@exit.example" {
		t.Errorf("args %q", args)
	}
}

func TestYamnEncoderFailures(t *testing.T) {
	key := testKey(t, "exit", "mix@exit.example")
	for _, c := range []struct {
		mode, op string
		exit     int
		stderr   string
	}{
		{"exit1", "run", 1, "Remailer address not found"},
		{"two", "output", 0, ""},
		{"none", "output", 0, ""},
		{"wrongto", "output", 0, ""},
	} {
		bin, rec := fakeYamn(t, c.mode)
		enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
		_, _, err := enc.Encode(context.Background(), []Hop{HopOf(key)}, testPingMail(t, false))
		var e *EncodeError
		if !errors.As(err, &e) || !errors.Is(err, ErrLocal) {
			t.Fatalf("%s: got %v, want a local EncodeError", c.mode, err)
		}
		if e.Op != c.op || e.ExitCode != c.exit || !strings.Contains(e.Stderr, c.stderr) {
			t.Errorf("%s: got op %q exit %d stderr %q", c.mode, e.Op, e.ExitCode, e.Stderr)
		}
		if _, err := os.Stat(strings.TrimSpace(readRec(t, rec, "dir"))); !os.IsNotExist(err) {
			t.Errorf("%s: D not removed", c.mode)
		}
	}
}

func TestYamnEncoderTimeout(t *testing.T) {
	bin, _ := fakeYamn(t, "sleep")
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir(), Timeout: 300 * time.Millisecond}
	start := time.Now()
	_, _, err := enc.Encode(context.Background(), []Hop{HopOf(testKey(t, "exit", "mix@exit.example"))}, testPingMail(t, false))
	if !errors.Is(err, ErrTimeout) || !errors.Is(err, ErrLocal) {
		t.Fatalf("got %v, want ErrTimeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestYamnEncoderCanceled(t *testing.T) {
	bin, _ := fakeYamn(t, "sleep")
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	_, _, err := enc.Encode(ctx, []Hop{HopOf(testKey(t, "exit", "mix@exit.example"))}, testPingMail(t, false))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrLocal) || errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestYamnEncoderChecks(t *testing.T) {
	bin, rec := fakeYamn(t, "ok")
	key := testKey(t, "exit", "mix@exit.example")
	other := testKey(t, "other", "mix@other.example")
	dup := testKey(t, "exit", "mix@third.example") // same nick
	mismatch := HopOf(key)
	mismatch.KeyID = other.KeyID
	good := testPingMail(t, false)
	for name, c := range map[string]struct {
		enc   YamnEncoder
		chain []Hop
		mail  []byte
	}{
		"no binary":     {YamnEncoder{Sender: "pinger@example.org"}, []Hop{HopOf(key)}, good},
		"bad sender":    {YamnEncoder{Binary: bin, Sender: "pinger\"@example.org"}, []Hop{HopOf(key)}, good},
		"no sender":     {YamnEncoder{Binary: bin}, []Hop{HopOf(key)}, good},
		"no hops":       {YamnEncoder{Binary: bin, Sender: "pinger@example.org"}, nil, good},
		"keyid":         {YamnEncoder{Binary: bin, Sender: "pinger@example.org"}, []Hop{mismatch}, good},
		"same nick":     {YamnEncoder{Binary: bin, Sender: "pinger@example.org"}, []Hop{HopOf(key), HopOf(dup)}, good},
		"too large":     {YamnEncoder{Binary: bin, Sender: "pinger@example.org"}, []Hop{HopOf(key)}, append(good, make([]byte, MaxBody)...)},
		"not a mail":    {YamnEncoder{Binary: bin, Sender: "pinger@example.org"}, []Hop{HopOf(key)}, []byte("no header")},
		"too many hops": {YamnEncoder{Binary: bin, Sender: "pinger@example.org"}, make([]Hop, 11), good},
	} {
		c.enc.TmpDir = t.TempDir()
		_, _, err := c.enc.Encode(context.Background(), c.chain, c.mail)
		if !errors.Is(err, ErrLocal) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := os.Stat(rec); !os.IsNotExist(err) {
		t.Error("yamn ran despite failed checks")
	}
}

func TestSelfTestFake(t *testing.T) {
	bin, rec := fakeYamn(t, "okwarn")
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
	if err := SelfTest(context.Background(), enc, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readRec(t, rec, "args"), "selftest@example.invalid") {
		t.Error("selftest chain not used")
	}
	bin, _ = fakeYamn(t, "exit1")
	enc.Binary = bin
	if err := SelfTest(context.Background(), enc, time.Now()); !errors.Is(err, ErrLocal) {
		t.Errorf("got %v", err)
	}
}

func TestSplitMbox(t *testing.T) {
	in := "junk before\nFrom a\nTo: x\n\n>From body\n>>From two\n\nFrom b\nTo: y\n\nbody\n\n"
	got := splitMbox([]byte(in))
	want := []string{"To: x\n\nFrom body\n>From two\n", "To: y\n\nbody\n"}
	if len(got) != len(want) {
		t.Fatalf("got %d mails", len(got))
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("mail %d: %q, want %q", i, got[i], want[i])
		}
	}
}

func TestClean(t *testing.T) {
	if got := clean("a\x1b[31m\nb\r\n"); got != "a[31m | b" {
		t.Errorf("got %q", got)
	}
}

func TestCapped(t *testing.T) {
	c := &capped{max: 4}
	c.Write([]byte("abc"))
	c.Write([]byte("def"))
	if c.b.String() != "abcd" || !c.over {
		t.Errorf("got %q over=%v", c.b.String(), c.over)
	}
}
