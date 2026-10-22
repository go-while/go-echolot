package replies

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-while/go-echolot/internal/blake2s"
)

func addSeeds(f *testing.F, names ...string) {
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", n))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
}

func FuzzParseKey(f *testing.F) {
	addSeeds(f, "replies/t_65.key", "pubrings/frell.mix", "replies/t_65.conf")
	f.Add([]byte(entry(victorHeader, victorKeyID, victorPK)))
	f.Fuzz(func(t *testing.T, in []byte) {
		r := ParseKey(in)
		for _, k := range r.Keys {
			sum := blake2s.Sum128(k.PK[:])
			if hex.EncodeToString(sum[:]) != k.KeyID {
				t.Fatalf("%s: keyid %s is not BLAKE2s(pk)", k.Nick, k.KeyID)
			}
			if !ValidName(k.Nick) || !ValidAddress(k.Address) {
				t.Fatalf("invalid name or address: %q %q", k.Nick, k.Address)
			}
			if len(k.String()) > 1024 {
				t.Fatalf("summary line of %d bytes", len(k.String()))
			}
			s, err := ParseSummary(k.String())
			if err != nil || s != k.SummaryLine {
				t.Fatalf("%q doesn't parse back: %+v, %v", k.String(), s, err)
			}
			r2 := ParseKey([]byte(pubringEntry(k)))
			if len(r2.Errors) != 0 || len(r2.Keys) != 1 || r2.Keys[0] != k {
				t.Fatalf("%q: pubring entry doesn't parse back", k.String())
			}
		}
	})
}

func FuzzParseConf(f *testing.F) {
	addSeeds(f, "replies/t_65.conf", "replies/t_65.key")
	f.Fuzz(func(t *testing.T, in []byte) {
		c, err := ParseConf(in)
		if err != nil {
			return
		}
		if len(c.Caps) > 1024 || len(c.Type) > 1024 {
			t.Fatalf("caps line of %d bytes, type of %d", len(c.Caps), len(c.Type))
		}
		c2, err := ParseConf([]byte(c.Caps))
		if err != nil {
			t.Fatalf("caps %q doesn't parse: %v", c.Caps, err)
		}
		if c2.Nick != c.Nick || c2.Address != c.Address || c2.Options != c.Options || c2.Caps != c.Caps {
			t.Fatalf("caps %q parses to %+v", c.Caps, c2)
		}
		for _, s := range c.Supported {
			if s2, err := ParseSummary(s.String()); err != nil || s2 != s {
				t.Fatalf("%q doesn't parse back", s.String())
			}
		}
	})
}
