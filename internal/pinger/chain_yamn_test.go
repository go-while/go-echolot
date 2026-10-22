package pinger

// Chain pings with the real yamn binary (YAMN_BIN, see yamn_test.go):
// client → A → B → delivered.

import (
	"bytes"
	"context"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/replies"
)

const testChainToken = "pinger+chainping=1792560000=0123456789abcdef@example.org"

// chainPingFor seals a chain ping through a then b and returns its body
// and the mail given to yamn (no From, as Echolot's chain pings).
func chainPingFor(t *testing.T, a, b replies.ParsedKey) (Body, []byte) {
	t.Helper()
	body := Body{Remailer: a.Address, Type: TypeMix, KeyID: a.KeyID, Remailer2: b.Address, KeyID2: b.KeyID,
		Sent: time.Now().Truncate(time.Second).UTC(), ID: 7}
	return body, Mail(testChainToken, "pinger@example.org", false, seal(t, body, 8192))
}

// openChainDelivered checks a mail delivered by the last exit and opens
// its chain ping.
func openChainDelivered(t *testing.T, delivered []byte) Body {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(delivered))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header.Get("To"); got != testChainToken {
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

// forwardTo checks that m goes to r and hands it over; r sends no
// dummies (yamn adds one to about half of the messages it forwards).
func forwardTo(t *testing.T, r *remailer, m []byte) [][]byte {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(m))
	if err != nil || msg.Header.Get("To") != r.key.Address {
		t.Fatalf("mail isn't to %s: %v\n%s", r.key.Address, err, m)
	}
	r.run(t, m, "-R")
	r.run(t, nil, "-M", "-S", "--nodummy")
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

// knows writes the keys ks to r's pubring.mix: a hop forwards only to a
// remailer in its pubring (Y:server.go checkNextHop).
func (r *remailer) knows(t *testing.T, ks ...replies.ParsedKey) {
	t.Helper()
	ring, err := output.Pubring(ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "pubring.mix"), ring, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestYamnChainRoundTrip: a 2-hop chain, middleman or exit first, exit
// last.  yamn gets -l a,b and a pubring with exactly the two keys.
func TestYamnChainRoundTrip(t *testing.T) {
	bin := yamnBin(t)
	exit1 := newRemailer(t, bin, "exit1", true)
	exit2 := newRemailer(t, bin, "exit2", true)
	middle := newRemailer(t, bin, "middle1", false)
	middle.knows(t, exit1.key)
	exit1.knows(t, exit2.key)
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
	for _, c := range []struct{ a, b *remailer }{{middle, exit1}, {exit1, exit2}} {
		want, m := chainPingFor(t, c.a.key, c.b.key)
		to, out, err := enc.Encode(context.Background(), []Hop{HopOf(c.a.key), HopOf(c.b.key)}, m)
		if err != nil {
			t.Fatal(err)
		}
		if to != c.a.key.Address {
			t.Errorf("to %q", to)
		}
		hop := forwardTo(t, c.a, out)
		if len(hop) != 1 {
			t.Fatalf("%s sent %d mails", c.a.key.Nick, len(hop))
		}
		sent := forwardTo(t, c.b, hop[0])
		if len(sent) != 1 {
			t.Fatalf("%s sent %d mails", c.b.key.Nick, len(sent))
		}
		if got := openChainDelivered(t, sent[0]); got != want || !got.Chain() {
			t.Errorf("%s,%s: got %+v, want %+v", c.a.key.Nick, c.b.key.Nick, got, want)
		}
	}
}

// TestYamnChainMiddleLast: Echolot pings every pair, so B may be a
// middleman; it gets the exit packet and randhops it through an exit of
// its choice, as with a plain ping to a middleman.
func TestYamnChainMiddleLast(t *testing.T) {
	bin := yamnBin(t)
	exit1 := newRemailer(t, bin, "exit1", true)
	exit2 := newRemailer(t, bin, "exit2", true)
	middle := newRemailer(t, bin, "middle1", false)
	exit1.knows(t, middle.key)
	middle.knows(t, exit2.key)
	stats := "Stats-Version: 2.0\n" +
		"Generated: " + time.Now().UTC().Format("Mon 02 Jan 2006 15:04:05 GMT") + "\n" +
		"Mixmaster    Latent-Hist   Latent  Uptime-Hist   Uptime  Options\n" +
		strings.Repeat("-", 64) + "\n" +
		"exit2        000000000000    :10   ++++++++++++  100.0%\n\n"
	if err := os.WriteFile(filepath.Join(middle.dir, "mlist2.txt"), []byte(stats), 0600); err != nil {
		t.Fatal(err)
	}
	enc := &YamnEncoder{Binary: bin, Sender: "pinger@example.org", TmpDir: t.TempDir()}
	want, m := chainPingFor(t, exit1.key, middle.key)
	_, out, err := enc.Encode(context.Background(), []Hop{HopOf(exit1.key), HopOf(middle.key)}, m)
	if err != nil {
		t.Fatal(err)
	}
	hop := forwardTo(t, exit1, out)
	if len(hop) != 1 {
		t.Fatalf("exit1 sent %d mails", len(hop))
	}
	hop = forwardTo(t, middle, hop[0])
	if len(hop) != 1 {
		t.Fatalf("middle sent %d mails", len(hop))
	}
	sent := forwardTo(t, exit2, hop[0])
	if len(sent) != 1 {
		t.Fatalf("exit2 sent %d mails", len(sent))
	}
	if got := openChainDelivered(t, sent[0]); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
