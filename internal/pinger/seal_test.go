package pinger

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	mrand "math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/token"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	testMAC = token.DeriveKey([]byte("0123456789abcdef0123456789abcdef"), token.PurposePingMAC)
	testBox = token.DeriveKey([]byte("0123456789abcdef0123456789abcdef"), token.PurposePingBox)
)

func testBody() Body {
	return Body{
		Remailer: "yamn@mixmin.net",
		Type:     TypeMix,
		KeyID:    "47c15db37d0d840b1f5ad4274384be22",
		WithFrom: true,
		Sent:     time.Unix(1792560000, 0).UTC(),
		ID:       4711,
	}
}

// detRand is a deterministic random source for golden tests.
func detRand(seed uint64) *mrand.ChaCha8 {
	var s [32]byte
	s[0] = byte(seed)
	return mrand.NewChaCha8(s)
}

func seal(t *testing.T, b Body, garbage int) []byte {
	t.Helper()
	s, err := Seal(&testMAC, &testBox, b, garbage, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	for _, g := range []int{0, 1, 2, 64, 1000, 8192, 10240} {
		for _, wf := range []bool{false, true} {
			b := testBody()
			b.WithFrom = wf
			s := seal(t, b, g)
			if len(s) > MaxSealed {
				t.Errorf("garbage %d: sealed %d bytes", g, len(s))
			}
			got, err := Open(&testMAC, &testBox, s)
			if err != nil {
				t.Fatalf("garbage %d: %v", g, err)
			}
			if got != b {
				t.Errorf("garbage %d: got %+v, want %+v", g, got, b)
			}
		}
	}
}

func TestSealChecksBody(t *testing.T) {
	for name, f := range map[string]func(*Body){
		"address":    func(b *Body) { b.Remailer = "no-at-sign" },
		"colon":      func(b *Body) { b.Remailer = "a:b@example.org" },
		"type":       func(b *Body) { b.Type = "cpunk" },
		"keyid":      func(b *Body) { b.KeyID = "47C15DB37D0D840B1F5AD4274384BE22" },
		"short key":  func(b *Body) { b.KeyID = "47c15d" },
		"no sent":    func(b *Body) { b.Sent = time.Time{} },
		"no id":      func(b *Body) { b.ID = 0 },
		"line break": func(b *Body) { b.Remailer = "a\n@example.org" },
	} {
		b := testBody()
		f(&b)
		if _, err := Seal(&testMAC, &testBox, b, 100, rand.Reader); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}

// TestPlaintextGolden checks the plaintext layout: field order, the mac,
// garbage lines of 64 hex digits (E:Tools.pm:415-442).
func TestPlaintextGolden(t *testing.T) {
	b := testBody()
	b.WithFrom = false
	want := "remailer: yamn@mixmin.net\n" +
		"type: mix\n" +
		"key: 47c15db37d0d840b1f5ad4274384be22\n" +
		"with_from: 0\n" +
		"sent: 1792560000\n" +
		"id: 4711\n" +
		"mac: " + b.mac(&testMAC) + "\n"
	if got := b.header(&testMAC); got != want {
		t.Errorf("header:\n%s\nwant:\n%s", got, want)
	}
	g := make([]byte, 70)
	for i := range g {
		g[i] = byte(i)
	}
	wantG := "-----BEGIN GARBAGE-----\n" +
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n" +
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\n" +
		"404142434445\n" +
		"-----END GARBAGE-----\n"
	if got := garbageText(g); got != wantG {
		t.Errorf("garbage:\n%s\nwant:\n%s", got, wantG)
	}
	if garbageSize(70) != len(wantG) || garbageSize(0) != len(garbageText(nil)) || garbageSize(32) != len(garbageText(make([]byte, 32))) {
		t.Error("garbageSize disagrees with garbageText")
	}
	// The mac, computed independently with Python's hmac and a by-hand
	// HKDF, so a change of the MAC input or key derivation is noticed.
	if m := b.mac(&testMAC); m != "61a31540fbcc7a5b26098139edaccc0fb6462fdd21fd5ff2e989e7f50d86de92" {
		t.Errorf("mac %q", m)
	}
	c := b
	c.WithFrom = true
	if c.mac(&testMAC) == b.mac(&testMAC) {
		t.Error("with_from not in the MAC")
	}
}

// TestSealedLayout opens the box by hand and checks the armor and the
// plaintext lines.
func TestSealedLayout(t *testing.T) {
	s, err := Seal(&testMAC, &testBox, testBody(), 4096, detRand(1))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(s), "\n"), "\n")
	if lines[0] != armorBegin || lines[1] != armorVersion || lines[2] != "" || lines[len(lines)-1] != armorEnd {
		t.Fatalf("armor:\n%s", s)
	}
	for i, l := range lines[3 : len(lines)-1] {
		if len(l) > 64 || i < len(lines)-5 && len(l) != 64 {
			t.Errorf("base64 line %d of %d chars", i, len(l))
		}
	}
	plain := openPlain(t, s)
	pl := strings.Split(plain, "\n")
	for i, p := range []string{"remailer: ", "type: ", "key: ", "with_from: ", "sent: ", "id: ", "mac: "} {
		if !strings.HasPrefix(pl[i], p) {
			t.Errorf("line %d = %q, want prefix %q", i, pl[i], p)
		}
	}
	if pl[7] != garbageBegin || pl[len(pl)-2] != garbageEnd {
		t.Errorf("garbage block: %q ... %q", pl[7], pl[len(pl)-2])
	}
	hexRE := regexp.MustCompile(`^[0-9a-f]+$`)
	g := pl[8 : len(pl)-2]
	for i, l := range g {
		if !hexRE.MatchString(l) || len(l) > 64 || i < len(g)-1 && len(l) != 64 {
			t.Errorf("garbage line %d: %q", i, l)
		}
	}
}

func openPlain(t *testing.T, s []byte) string {
	t.Helper()
	lines := strings.Split(string(s), "\n")
	enc := strings.Join(lines[3:len(lines)-2], "")
	box, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	return string(mustOpenBox(t, box))
}

// TestGarbageLength checks that the garbage length is random up to
// garbageLen hex digits, and that a large garbageLen is cut to fit.
func TestGarbageLength(t *testing.T) {
	minG, maxG := math.MaxInt, 0
	for i := range 300 {
		s, err := Seal(&testMAC, &testBox, testBody(), 512, detRand(uint64(i)))
		if err != nil {
			t.Fatal(err)
		}
		n := garbageDigits(openPlain(t, s))
		minG, maxG = min(minG, n), max(maxG, n)
		if n > 512 || n%2 != 0 {
			t.Fatalf("garbage of %d digits", n)
		}
	}
	if minG > 100 || maxG < 400 {
		t.Errorf("garbage lengths %d..%d, want spread over 0..512", minG, maxG)
	}
	// 10240, the config maximum, is cut so the plaintext fits.
	for i := range 50 {
		s, err := Seal(&testMAC, &testBox, testBody(), 1<<20, detRand(uint64(i)))
		if err != nil {
			t.Fatal(err)
		}
		if p := openPlain(t, s); len(p) > MaxPlaintext || len(s) > MaxSealed {
			t.Fatalf("plaintext %d, sealed %d bytes", len(p), len(s))
		}
	}
}

func garbageDigits(plain string) int {
	_, g, _ := strings.Cut(plain, garbageBegin+"\n")
	g, _, _ = strings.Cut(g, garbageEnd)
	return len(strings.ReplaceAll(g, "\n", ""))
}

func TestOpenMangled(t *testing.T) {
	b := testBody()
	s := string(seal(t, b, 2000))
	blankLines := regexp.MustCompile(`\n`).ReplaceAllString(s, "\n\n") // broken middleman
	cases := map[string]string{
		"crlf":        strings.ReplaceAll(s, "\n", "\r\n"),
		"blank lines": blankLines,
		"blank crlf":  strings.ReplaceAll(blankLines, "\n", "\r\n"),
		"spaces":      strings.ReplaceAll(s, "\n", "  \n "),
		"tabs inside": strings.Replace(s, "\n\n", "\n\n\t", 1),
		"quoted":      "> " + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n> ") + "\n",
		"quoted >>":   ">> " + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n>>") + "\n",
		"disclaimer":  "This message was sent by an anonymous remailer.\nDon't reply.\n\n" + s + "\n-- \nabuse@example.org\n",
		"no final LF": strings.TrimSuffix(s, "\n"),
		"second armor": "-----BEGIN ECHOLOT PING-----\nVersion: go-echolot-1\n\nAAAA\n-----END ECHOLOT PING-----\n" +
			s,
	}
	for name, body := range cases {
		got, err := Open(&testMAC, &testBox, []byte(body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != b {
			t.Errorf("%s: got %+v", name, got)
		}
	}
}

func TestOpenRejects(t *testing.T) {
	s := string(seal(t, testBody(), 300))
	lines := strings.Split(s, "\n")
	// Flip one base64 character in the middle of the box.
	flip := append([]string(nil), lines...)
	mid := []byte(flip[5])
	if mid[10] == 'A' {
		mid[10] = 'B'
	} else {
		mid[10] = 'A'
	}
	flip[5] = string(mid)
	otherKey := token.DeriveKey([]byte("another secret, 32 bytes long..."), token.PurposePingBox)

	// A box that opens but holds a plaintext with a bad MAC.
	b := testBody()
	wrongMACKey := token.DeriveKey([]byte("another secret, 32 bytes long..."), token.PurposePingMAC)
	sealedWrongMAC, err := Seal(&wrongMACKey, &testBox, b, 100, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		body string
		key  *[32]byte
		want error
	}{
		{"empty", "", &testBox, ErrNoPing},
		{"no armor", "hello\n", &testBox, ErrNoPing},
		{"tampered box", strings.Join(flip, "\n"), &testBox, ErrBadBox},
		{"wrong box key", s, &otherKey, ErrBadBox},
		{"wrong mac key", string(sealedWrongMAC), &testBox, ErrBadMAC},
		{"truncated", strings.Join(lines[:len(lines)/2], "\n"), &testBox, ErrMalformed},
		{"truncated box", strings.Join(append(lines[:4:4], lines[len(lines)-2:]...), "\n"), &testBox, ErrBadBox},
		{"no version", strings.Replace(s, armorVersion+"\n", "", 1), &testBox, ErrMalformed},
		{"other version", strings.Replace(s, armorVersion, "Version: go-echolot-2", 1), &testBox, ErrMalformed},
		{"bad base64", strings.Replace(s, "\n\n", "\n\n!!!!", 1), &testBox, ErrMalformed},
		{"short box", armorBegin + "\n" + armorVersion + "\n\nAAAA\n" + armorEnd + "\n", &testBox, ErrMalformed},
		{"oversized", s + strings.Repeat("x", MaxBody), &testBox, ErrTooLarge},
	}
	for _, c := range cases {
		_, err := Open(&testMAC, c.key, []byte(c.body))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// TestOpenOversizedBox: a box larger than any Seal makes is refused
// before it is opened, even within MaxBody.
func TestOpenOversizedBox(t *testing.T) {
	big := make([]byte, nonceLen+16+MaxPlaintext+1)
	enc := base64.StdEncoding.EncodeToString(big)
	var b bytes.Buffer
	b.WriteString(armorBegin + "\n" + armorVersion + "\n\n")
	for len(enc) > 0 {
		k := min(64, len(enc))
		b.WriteString(enc[:k] + "\n")
		enc = enc[k:]
	}
	b.WriteString(armorEnd + "\n")
	if _, err := Open(&testMAC, &testBox, b.Bytes()); !errors.Is(err, ErrTooLarge) {
		t.Errorf("got %v, want ErrTooLarge", err)
	}
}

// TestOpenStrictPlaintext: a box holding a plaintext that isn't ours.
func TestOpenStrictPlaintext(t *testing.T) {
	b := testBody()
	good := b.header(&testMAC) + garbageText([]byte{1, 2, 3})
	for name, plain := range map[string]string{
		"no garbage":      b.header(&testMAC),
		"reordered":       strings.Replace(good, "type: mix\nkey: "+b.KeyID, "key: "+b.KeyID+"\ntype: mix", 1),
		"bad with_from":   strings.Replace(good, "with_from: 1", "with_from: 2", 1),
		"bad id":          strings.Replace(good, "id: 4711", "id: x", 1),
		"bad sent":        strings.Replace(good, "sent: 1792560000", "sent: -", 1),
		"changed id":      strings.Replace(good, "id: 4711", "id: 4712", 1),
		"trailing text":   good + "more\n",
		"no final LF":     strings.TrimSuffix(good, "\n"),
		"upper-case key":  strings.Replace(good, b.KeyID, strings.ToUpper(b.KeyID), 1),
		"other remailer":  strings.Replace(good, "yamn@mixmin.net", "yamn@mixmin.org", 1),
		"empty":           "",
		"only begin line": garbageBegin + "\n",
	} {
		_, err := Open(&testMAC, &testBox, sealPlain(t, plain))
		if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrBadMAC) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := Open(&testMAC, &testBox, sealPlain(t, good)); err != nil {
		t.Errorf("good: %v", err)
	}
}

// mustOpenBox opens nonce||box with testBox.
func mustOpenBox(t *testing.T, box []byte) []byte {
	t.Helper()
	nonce := [nonceLen]byte(box[:nonceLen])
	plain, ok := secretbox.Open(nil, box[nonceLen:], &nonce, &testBox)
	if !ok {
		t.Fatal("box does not open")
	}
	return plain
}

// sealPlain seals any plaintext in the armor, as Seal would.
func sealPlain(t *testing.T, plain string) []byte {
	t.Helper()
	var nonce [nonceLen]byte
	rand.Read(nonce[:])
	enc := base64.StdEncoding.EncodeToString(secretbox.Seal(nonce[:], []byte(plain), &nonce, &testBox))
	return []byte(armorBegin + "\n" + armorVersion + "\n\n" + enc + "\n" + armorEnd + "\n")
}

func TestMail(t *testing.T) {
	sealed := []byte("BODY\n")
	got := string(Mail("pinger+ping=1=ab@example.org", "pinger@example.org", true, sealed))
	if want := "From: pinger@example.org\nTo: pinger+ping=1=ab@example.org\n\nBODY\n"; got != want {
		t.Errorf("with from:\n%q\nwant\n%q", got, want)
	}
	got = string(Mail("pinger+ping=1=ab@example.org\r\nBcc: x@y", "pinger@example.org", false, sealed))
	if want := "To: pinger+ping=1=ab@example.orgBcc: x@y\n\nBODY\n"; got != want {
		t.Errorf("without from:\n%q\nwant\n%q", got, want)
	}
}
