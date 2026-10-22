package pinger

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

// testChainBody is a chain ping (design §8.2): first hop the test body's
// remailer, second hop an exit.
func testChainBody() Body {
	b := testBody()
	b.Remailer2 = "exit@example.org"
	b.KeyID2 = "0123456789abcdef0123456789abcdef"
	b.WithFrom = false // Echolot's chain pings never have a From (E:Chain.pm:56)
	b.ID = 17
	return b
}

func TestChainRoundTrip(t *testing.T) {
	b := testChainBody()
	if !b.Chain() || testBody().Chain() {
		t.Fatal("Chain()")
	}
	for _, g := range []int{0, 100, 8192} {
		got, err := Open(&testMAC, &testBox, seal(t, b, g))
		if err != nil {
			t.Fatalf("garbage %d: %v", g, err)
		}
		if got != b {
			t.Errorf("garbage %d: got %+v, want %+v", g, got, b)
		}
	}
}

// TestChainPlaintextGolden: the chain fields come after key, and the MAC
// (computed independently with Python's hmac) covers them.
func TestChainPlaintextGolden(t *testing.T) {
	b := testChainBody()
	want := "remailer: yamn@mixmin.net\n" +
		"type: mix\n" +
		"key: 47c15db37d0d840b1f5ad4274384be22\n" +
		"remailer2: exit@example.org\n" +
		"key2: 0123456789abcdef0123456789abcdef\n" +
		"with_from: 0\n" +
		"sent: 1792560000\n" +
		"id: 17\n" +
		"mac: 729b63043f66cfec115c4dd5969d25325ef186f731aa6a9705f77653ca1103c4\n"
	if got := b.header(&testMAC); got != want {
		t.Errorf("header:\n%s\nwant:\n%s", got, want)
	}
	for name, f := range map[string]func(*Body){
		"remailer2": func(b *Body) { b.Remailer2 = "exit@example.net" },
		"key2":      func(b *Body) { b.KeyID2 = "1123456789abcdef0123456789abcdef" },
		"swapped": func(b *Body) {
			b.Remailer, b.Remailer2 = b.Remailer2, b.Remailer
			b.KeyID, b.KeyID2 = b.KeyID2, b.KeyID
		},
	} {
		c := testChainBody()
		f(&c)
		if c.mac(&testMAC) == b.mac(&testMAC) {
			t.Errorf("%s not in the MAC", name)
		}
	}
	// The single-hop MAC input is unchanged.
	single := b
	single.Remailer2, single.KeyID2 = "", ""
	if single.mac(&testMAC) == b.mac(&testMAC) {
		t.Error("chain and single-hop MAC agree")
	}
}

func TestSealChecksChainBody(t *testing.T) {
	for name, f := range map[string]func(*Body){
		"bad remailer2":      func(b *Body) { b.Remailer2 = "no-at-sign" },
		"colon in remailer2": func(b *Body) { b.Remailer2 = "a:b@example.org" },
		"no key2":            func(b *Body) { b.KeyID2 = "" },
		"short key2":         func(b *Body) { b.KeyID2 = "0123" },
		"key2 alone":         func(b *Body) { b.Remailer2 = "" },
	} {
		b := testChainBody()
		f(&b)
		if _, err := Seal(&testMAC, &testBox, b, 100, rand.Reader); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}

// TestOpenStrictChainPlaintext: chain plaintexts that aren't ours, among
// them a chain ping turned into a plain one and back.
func TestOpenStrictChainPlaintext(t *testing.T) {
	b := testChainBody()
	good := b.header(&testMAC) + garbageText([]byte{1, 2, 3})
	chainLines := "remailer2: exit@example.org\nkey2: 0123456789abcdef0123456789abcdef\n"
	single := testBody()
	single.WithFrom, single.ID = false, 17
	for name, plain := range map[string]string{
		"other remailer2":   strings.Replace(good, "exit@example.org", "exit@example.net", 1),
		"other key2":        strings.Replace(good, "key2: 0", "key2: 1", 1),
		"no key2":           strings.Replace(good, "key2: 0123456789abcdef0123456789abcdef\n", "", 1),
		"empty remailer2":   strings.Replace(good, "remailer2: exit@example.org", "remailer2: ", 1),
		"key2 before":       strings.Replace(good, chainLines, "key2: 0123456789abcdef0123456789abcdef\nremailer2: exit@example.org\n", 1),
		"chain lines moved": strings.Replace(strings.Replace(good, chainLines, "", 1), "id: 17\n", "id: 17\n"+chainLines, 1),
		// A plain ping's plaintext and MAC with chain lines added, and a
		// chain ping's with them removed: the MACs differ.
		"single + chain lines": strings.Replace(single.header(&testMAC), "with_from:", strings.TrimSuffix(chainLines, "\n")+"\nwith_from:", 1) + garbageText(nil),
		"chain - chain lines":  strings.Replace(good, chainLines, "", 1),
	} {
		_, err := Open(&testMAC, &testBox, sealPlain(t, plain))
		if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrBadMAC) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	got, err := Open(&testMAC, &testBox, sealPlain(t, good))
	if err != nil || got != b {
		t.Errorf("good: %+v, %v", got, err)
	}
	if got.Sent != time.Unix(1792560000, 0).UTC() {
		t.Errorf("sent %v", got.Sent)
	}
}

// FuzzParseChainBody is FuzzParseBody seeded with chain plaintexts.
func FuzzParseChainBody(f *testing.F) {
	b := testChainBody()
	f.Add([]byte(b.header(&testMAC) + garbageText([]byte{1, 2, 3})))
	f.Add([]byte(b.header(&testMAC) + garbageText(nil)))
	f.Fuzz(func(t *testing.T, plain []byte) {
		got, err := parseBody(&testMAC, plain)
		if err != nil {
			return
		}
		if got.check() != nil {
			t.Fatalf("accepted an invalid body %+v", got)
		}
	})
}
