package pinger

import (
	"crypto/rand"
	"strings"
	"testing"
)

// FuzzOpen: Open never panics, and what it accepts is a valid body.
func FuzzOpen(f *testing.F) {
	s, err := Seal(&testMAC, &testBox, testBody(), 300, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(s)
	f.Add([]byte(strings.ReplaceAll(string(s), "\n", "\r\n\r\n")))
	f.Add([]byte("> " + strings.ReplaceAll(string(s), "\n", "\n> ")))
	f.Add([]byte(armorBegin + "\n" + armorVersion + "\n\nAAAA\n" + armorEnd + "\n"))
	f.Add([]byte(armorBegin + "\n" + armorBegin + "\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		b, err := Open(&testMAC, &testBox, body)
		if err != nil {
			return
		}
		if b.check() != nil {
			t.Fatalf("accepted an invalid body %+v", b)
		}
	})
}

// FuzzParseBody fuzzes the plaintext inside the box, which FuzzOpen
// can't reach.
func FuzzParseBody(f *testing.F) {
	b := testBody()
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
