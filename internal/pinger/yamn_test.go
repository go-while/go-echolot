package pinger

// Tests with the real yamn binary, a full round trip without network.
// Build yamn and point YAMN_BIN at it:
//
//	(cd yamn && go build -o /some/dir/yamn .)
//	YAMN_BIN=/some/dir/yamn go test ./internal/pinger/
//
// How it works, for CI and the daemon's end-to-end test:
//   - Each remailer is a directory with a yamn.yml (urls.fetch false,
//     key_pinning off, mail.outfile true, pool size 0 and rate 100) and is
//     only ever run once per step, never as a daemon.
//   - `yamn --config R/yamn.yml --dir R -M` once makes its secring and
//     key.txt; key.txt is a pubring entry, read with replies.ParseKey.
//   - YamnEncoder encodes the ping mail to that key.
//   - `yamn ... -R` (stdin: the encoder's mail) puts it into R/Maildir,
//     `yamn ... -M -S` decrypts it and flushes the pool; with mail.outfile
//     the mail it would send lands in R/pool/outfile-*.
//   - For an exit that file is the delivered ping; for a middleman it is
//     the randhopped yamn mail to its exit, which is fed to the exit the
//     same way.  The middleman needs the exit's key in its pubring.mix and
//     stats for it in mlist2.txt, as randhopping picks a random exit
//     (Y:server.go randhop, Y:chain.go makeChain).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/replies"
)

// yamnBin returns $YAMN_BIN, or skips the test without it, or as root:
// yamn refuses to run as root (go-while/yamn PR #73) and go-echolot never
// asks it to.
func yamnBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("YAMN_BIN")
	if bin == "" {
		t.Skip("YAMN_BIN not set")
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 { // yamn checks both
		t.Skip("yamn refuses to run as root; run the yamn tests as another user")
	}
	return bin
}

// remailer is a yamn remailer in a temp dir.
type remailer struct {
	bin, dir string
	key      replies.ParsedKey
}

func newRemailer(t *testing.T, bin, name string, exit bool) *remailer {
	t.Helper()
	r := &remailer{bin: bin, dir: t.TempDir()}
	cfg := fmt.Sprintf(`general: {loglevel: warn}
urls: {fetch: false, pubring: "", mlist2: "", key_pinning: "off"}
mail: {outfile: true}
remailer: {name: %s, address: %s@example.invalid, exit: %v}
pool: {size: 0, rate: 100, min_send: 0}
`, name, name, exit)
	if err := os.WriteFile(filepath.Join(r.dir, "yamn.yml"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	r.run(t, nil, "-M")
	data, err := os.ReadFile(filepath.Join(r.dir, "key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	kr := replies.ParseKey(data)
	if len(kr.Keys) != 1 {
		t.Fatalf("%s/key.txt: %d keys, %v", name, len(kr.Keys), kr.Errors)
	}
	r.key = kr.Keys[0]
	return r
}

func (r *remailer) run(t *testing.T, stdin []byte, args ...string) {
	t.Helper()
	cmd := exec.Command(r.bin, append([]string{"--config", filepath.Join(r.dir, "yamn.yml"), "--dir", r.dir}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("yamn %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// deliver hands m to the remailer and returns the mails it sends.
func (r *remailer) deliver(t *testing.T, m []byte) [][]byte {
	t.Helper()
	r.run(t, m, "-R")
	r.run(t, nil, "-M", "-S")
	files, err := filepath.Glob(filepath.Join(r.dir, "pool", "outfile-*"))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
		os.Remove(f)
	}
	return out
}

// pingFor seals a ping to key k and returns its body and the mail.
func pingFor(t *testing.T, k replies.ParsedKey, withFrom bool) (Body, []byte) {
	t.Helper()
	b := Body{Remailer: k.Address, Type: TypeMix, KeyID: k.KeyID, WithFrom: withFrom,
		Sent: time.Now().Truncate(time.Second).UTC(), ID: 42}
	return b, Mail(testToken, "pinger@example.org", withFrom, seal(t, b, 8192))
}

const testToken = "pinger+ping=1792560000=0123456789abcdef@example.org"

// openDelivered checks a mail delivered by an exit and opens its ping.
func openDelivered(t *testing.T, delivered []byte) Body {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(delivered))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header.Get("To"); got != testToken {
		t.Errorf("delivered To: %q", got)
	}
	var body bytes.Buffer
	body.ReadFrom(msg.Body)
	b, err := Open(&testMAC, &testBox, body.Bytes())
	if err != nil {
		t.Fatalf("open: %v\n%s", err, delivered)
	}
	return b
}

func TestYamnRoundTripExit(t *testing.T) {
	bin := yamnBin(t)
	exit := newRemailer(t, bin, "exit1", true)
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir(), Timeout: 30 * time.Second}
	for _, wf := range []bool{false, true} {
		want, m := pingFor(t, exit.key, wf)
		to, out, err := enc.Encode(context.Background(), []Hop{HopOf(exit.key)}, m)
		if err != nil {
			t.Fatal(err)
		}
		if to != exit.key.Address {
			t.Errorf("to %q", to)
		}
		sent := exit.deliver(t, out)
		if len(sent) != 1 {
			t.Fatalf("exit sent %d mails", len(sent))
		}
		if got := openDelivered(t, sent[0]); got != want {
			t.Errorf("with_from %v: got %+v, want %+v", wf, got, want)
		}
	}
}

// TestYamnRoundTripMiddle: a ping to a middleman is a one-hop chain; the
// middleman randhops it through an exit of its own choice.
func TestYamnRoundTripMiddle(t *testing.T) {
	bin := yamnBin(t)
	exit := newRemailer(t, bin, "exit1", true)
	middle := newRemailer(t, bin, "middle1", false)
	ring, err := output.Pubring([]replies.ParsedKey{exit.key})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(middle.dir, "pubring.mix"), ring, 0600); err != nil {
		t.Fatal(err)
	}
	stats := "Stats-Version: 2.0\n" +
		"Generated: " + time.Now().UTC().Format("Mon 02 Jan 2006 15:04:05 GMT") + "\n" +
		"Mixmaster    Latent-Hist   Latent  Uptime-Hist   Uptime  Options\n" +
		strings.Repeat("-", 64) + "\n" +
		"exit1        000000000000    :10   ++++++++++++  100.0%\n\n"
	if err := os.WriteFile(filepath.Join(middle.dir, "mlist2.txt"), []byte(stats), 0600); err != nil {
		t.Fatal(err)
	}

	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
	want, m := pingFor(t, middle.key, false)
	to, out, err := enc.Encode(context.Background(), []Hop{HopOf(middle.key)}, m)
	if err != nil {
		t.Fatal(err)
	}
	if to != middle.key.Address {
		t.Errorf("to %q", to)
	}
	hop := middle.deliver(t, out)
	if len(hop) != 1 {
		t.Fatalf("middle sent %d mails", len(hop))
	}
	if msg, err := mail.ReadMessage(bytes.NewReader(hop[0])); err != nil || msg.Header.Get("To") != exit.key.Address {
		t.Fatalf("middle's mail isn't to the exit: %v\n%s", err, hop[0])
	}
	sent := exit.deliver(t, hop[0])
	if len(sent) != 1 {
		t.Fatalf("exit sent %d mails", len(sent))
	}
	if got := openDelivered(t, sent[0]); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestYamnUnusableKeys: yamn drops expired keys (use_expired false) and
// keys not valid yet; that is exit status 1, a local failure.
func TestYamnUnusableKeys(t *testing.T) {
	bin := yamnBin(t)
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
	for name, f := range map[string]func(*replies.ParsedKey){
		"expired":       func(k *replies.ParsedKey) { k.Created, k.Expires = k.Created.AddDays(-20), k.Created.AddDays(-2) },
		"not valid yet": func(k *replies.ParsedKey) { k.Created = k.Created.AddDays(3) },
	} {
		k := testKey(t, "exit", "mix@exit.example")
		f(&k)
		_, m := pingFor(t, k, false)
		_, _, err := enc.Encode(context.Background(), []Hop{HopOf(k)}, m)
		var e *EncodeError
		if !errors.As(err, &e) || !errors.Is(err, ErrLocal) || e.ExitCode != 1 ||
			!strings.Contains(e.Stderr, "not found in public keyring") {
			t.Errorf("%s: got %v, want exit status 1", name, err)
		}
		t.Logf("%s: %v", name, err)
	}
}

func TestYamnSelfTest(t *testing.T) {
	bin := yamnBin(t)
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
	if err := SelfTest(context.Background(), enc, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestYamnConfigKeys: yamn knows every key of our yamn.yml (an unknown one
// is only a warning, and wouldn't apply) and reads the values we mean.
func TestYamnConfigKeys(t *testing.T) {
	bin := yamnBin(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "yamn.yml")
	if err := os.WriteFile(cfg, yamnConfig(dir, "pinger@example.org"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--config", cfg, "--dir", dir, "--debug")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("yamn warns about the config: %s", stderr.String())
	}
	for _, want := range []string{
		"    fetch: false\n", "    key_pinning: \"off\"\n", "    num_copies: 1\n",
		"    use_expired: false\n", "    outfile: true\n", "    address: pinger@example.org\n",
		"    pubring: " + filepath.Join(dir, "pubring.mix") + "\n",
		"    keypins: " + filepath.Join(dir, "keypins.json") + "\n",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("yamn --debug lacks %q:\n%s", want, out)
		}
	}
}
