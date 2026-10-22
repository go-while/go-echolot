package blake2s

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Vectors from Python's hashlib.blake2s(data, digest_size=n).  The "abc"
// one with 32 bytes is also RFC 7693, appendix B.
func TestSum(t *testing.T) {
	seq := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}
	for _, tc := range []struct {
		data []byte
		size int
		want string
	}{
		{nil, 16, "64550d6ffe2c0a01a14aba1eade0200c"},
		{[]byte("abc"), 16, "aa4938119b1dc7b87cbad0ffd200d0ae"},
		{[]byte("abc"), 32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"},
		{seq(64), 16, "dc66ca8f03865801b0ffe06ed8a1a90e"}, // exactly one block
		{seq(65), 16, "399d3e92ccfcedcdde9bf4c2be14cf8c"},
		{bytes.Repeat(seq(256), 3), 16, "02791852856c6ef2e11dfa3027185216"},
		{seq(128), 32, "1fa877de67259d19863a2a34bcc6962a2b25fcbf5cbecd7ede8f1fa36688a796"},
	} {
		if got := hex.EncodeToString(Sum(tc.data, tc.size)); got != tc.want {
			t.Errorf("Sum(%d bytes, %d) = %s, want %s", len(tc.data), tc.size, got, tc.want)
		}
	}
}

func TestSizePanics(t *testing.T) {
	for _, n := range []int{0, 33} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Sum(_, %d) didn't panic", n)
				}
			}()
			Sum(nil, n)
		}()
	}
}

// TestLiveKeyids checks every key of the live pubrings in
// testdata/pubrings: the keyid line is BLAKE2s-128 of the key line.
func TestLiveKeyids(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/pubrings/*.mix")
	if len(files) == 0 {
		t.Fatal("no pubrings")
	}
	n := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			if sc.Text() != "-----Begin Mix Key-----" {
				continue
			}
			sc.Scan()
			keyid := sc.Text()
			sc.Scan()
			pk, err := hex.DecodeString(sc.Text())
			if err != nil || len(pk) != 32 {
				t.Fatalf("%s: bad key line %q", f, sc.Text())
			}
			sum := Sum128(pk)
			if got := hex.EncodeToString(sum[:]); got != keyid {
				t.Errorf("%s: keyid %s, BLAKE2s-128 %s", filepath.Base(f), keyid, got)
			}
			n++
		}
	}
	if n != 19 {
		t.Errorf("%d keys checked, want 19", n)
	}
}
