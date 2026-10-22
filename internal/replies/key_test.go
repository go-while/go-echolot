package replies

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/blake2s"
	"github.com/go-while/go-echolot/internal/civil"
)

const (
	victorHeader = "victor yamn@virebent.art dd34d8b7f010229bb790a2402c9ffe65 4:0.2c M 2026-10-17 2026-10-31"
	victorKeyID  = "dd34d8b7f010229bb790a2402c9ffe65"
	victorPK     = "ff64d55659f8cd2fd7ac3fd75aefa70b00a864a9ed9cd3aa921dbbcb327b0e04"
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// entry is one pubring.mix entry, as the pubring writer will write it.
func entry(header, keyid, pk string) string {
	return header + "\n\n" + beginLine + "\n" + keyid + "\n" + pk + "\n" + endLine + "\n\n"
}

// pubringEntry re-serializes k.
func pubringEntry(k ParsedKey) string {
	return entry(k.String(), k.KeyID, hex.EncodeToString(k.PK[:]))
}

// newKey makes a valid key for nick from a seed byte.
func newKey(nick string, seed byte) (header, keyid, pk string) {
	var p [32]byte
	for i := range p {
		p[i] = seed + byte(i)
	}
	sum := blake2s.Sum128(p[:])
	keyid = hex.EncodeToString(sum[:])
	header = nick + " " + nick + "@example.org " + keyid + " 4:0.2.7 E 2026-10-18 2026-10-23"
	return header, keyid, hex.EncodeToString(p[:])
}

func date(s string) civil.Date {
	d, err := civil.Parse(s)
	if err != nil {
		panic(err)
	}
	return d
}

func errorStrings(errs []error) string {
	var s []string
	for _, e := range errs {
		s = append(s, e.Error())
	}
	return strings.Join(s, "; ")
}

func TestParseKeyT65(t *testing.T) {
	body, err := Body(nil, readFile(t, "replies/t_65.key"))
	if err != nil {
		t.Fatal(err)
	}
	r := ParseKey(body)
	if len(r.Errors) != 0 {
		t.Fatalf("errors: %v", errorStrings(r.Errors))
	}
	if len(r.Keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(r.Keys))
	}
	k := r.Keys[0]
	want := SummaryLine{
		Nick:    "victor",
		Address: "yamn@virebent.art",
		KeyID:   victorKeyID,
		Version: "4:0.2c",
		Caps:    "M",
		Created: date("2026-10-17"),
		Expires: date("2026-10-31"),
	}
	if k.SummaryLine != want {
		t.Errorf("summary = %+v, want %+v", k.SummaryLine, want)
	}
	if hex.EncodeToString(k.PK[:]) != victorPK {
		t.Errorf("pk = %x", k.PK)
	}
	if k.String() != victorHeader {
		t.Errorf("String() = %q", k.String())
	}
}

// TestPubrings checks the live pubrings and their layout: each entry is
// summary, blank, Begin, keyid, pk, End, blank; the file ends in "-----\n\n".
func TestPubrings(t *testing.T) {
	for name, n := range map[string]int{"mixmin": 6, "victor": 6, "frell": 7} {
		t.Run(name, func(t *testing.T) {
			raw := readFile(t, "pubrings/"+name+".mix")
			r := ParseKey(raw)
			if len(r.Errors) != 0 {
				t.Fatalf("errors: %v", errorStrings(r.Errors))
			}
			if len(r.Keys) != n {
				t.Fatalf("got %d keys, want %d", len(r.Keys), n)
			}
			var b strings.Builder
			for i, k := range r.Keys {
				b.WriteString(pubringEntry(k))
				if i > 0 && r.Keys[i-1].String() >= k.String() {
					t.Errorf("entries not sorted at %s", k.Nick)
				}
			}
			if b.String() != string(raw) {
				t.Errorf("re-serialized pubring differs:\n%s", b.String())
			}
		})
	}
}

func TestParseKeyRejects(t *testing.T) {
	h, id, pk := victorHeader, victorKeyID, victorPK
	repl := func(s, old, new string) string {
		if !strings.Contains(s, old) {
			panic(old)
		}
		return strings.Replace(s, old, new, 1)
	}
	flip := func(s string, i int) string {
		c := byte('0')
		if s[i] == '0' {
			c = '1'
		}
		return s[:i] + string(c) + s[i+1:]
	}
	long := "victor " + strings.Repeat("a", 53-len("@virebent.art")) + "@virebent.art" + h[len("victor yamn@virebent.art"):]
	tests := []struct {
		name, body, err string
	}{
		{"6 fields", entry(repl(h, " 2026-10-31", ""), id, pk), "key block without summary line"},
		{"8 fields", entry(h+" x", id, pk), "key block without summary line"},
		{"double space", entry(repl(h, " M ", "  "), id, pk), "victor: field 5 of summary line is empty"},
		{"leading space", entry(" "+repl(h, " M ", " "), id, pk), `invalid remailer name ""`},
		{"upper-case name", entry(repl(h, "victor", "Victor"), id, pk), `invalid remailer name "Victor"`},
		{"name with dash", entry(repl(h, "victor", "vic-tor"), id, pk), `invalid remailer name "vic-tor"`},
		{"address 53 bytes", entry(long, id, pk), "victor: invalid address"},
		{"address two @", entry(repl(h, "yamn@", "ya@mn@"), id, pk), "victor: invalid address"},
		{"address no @", entry(repl(h, "yamn@", "yamn"), id, pk), "victor: invalid address"},
		{"address non-ASCII", entry(repl(h, "yamn@", "yämn@"), id, pk), "victor: invalid address"},
		{"header keyid not hex", entry(repl(h, "dd34", "zz34"), id, pk), "victor: keyid \"zz34"},
		{"header keyid short", entry(repl(h, "dd34", "34"), id, pk), "victor: keyid \"34"},
		{"header keyid long", entry(repl(h, "dd34", "00dd34"), id, pk), "is not 32 hex digits"},
		{"block keyid not hex", entry(h, "zz"+id[2:], pk), "victor: keyid in block is not 32 hex digits"},
		{"block keyid short", entry(h, id[2:], pk), "victor: keyid in block is not 32 hex digits"},
		{"keyid mismatch", entry(h, flip(id, 5), pk), "victor: keyid in header differs from keyid in block"},
		{"keyid mismatch both", entry(repl(h, id, flip(id, 5)), flip(id, 5), pk), "victor: keyid " + flip(id, 5) + " is not BLAKE2s of the public key"},
		{"pk flipped", entry(h, id, flip(pk, 40)), "victor: keyid " + id + " is not BLAKE2s of the public key"},
		{"pk 62 digits", entry(h, id, pk[:62]), "victor: public key is not 64 hex digits"},
		{"pk 66 digits", entry(h, id, pk+"00"), "victor: public key is not 64 hex digits"},
		{"pk 63 digits", entry(h, id, pk[:63]), "victor: public key is not 64 hex digits"},
		{"pk not hex", entry(h, id, "x"+pk[1:]), "victor: public key is not 64 hex digits"},
		{"bad created", entry(repl(h, "2026-10-17", "2026-02-30"), id, pk), "victor: created date: bad date \"2026-02-30\""},
		{"bad expires", entry(repl(h, "2026-10-31", "2026-10-1"), id, pk), "victor: expiry date: bad date"},
		{"version control char", entry(repl(h, "4:0.2c", "4:0.2c\t"), id, pk), "victor: invalid version"},
		{"caps non-ASCII", entry(repl(h, " M ", " Mé "), id, pk), "victor: invalid caps"},
		{"missing End", strings.TrimSuffix(entry(h, id, pk), endLine+"\n\n"), "victor: no End line after key"},
		{"missing pk", h + "\n\n" + beginLine + "\n" + id + "\n", "victor: public key is not 64 hex digits"},
		{"ends after keyid", h + "\n\n" + beginLine + "\n" + id, "victor: key block ends early"},
		{"no block", h + "\n\n", "victor: summary line without key block"},
		{"Begin without header", entry("", id, pk), "key block without summary line"},
		{"second header before Begin", h + "\n" + entry(h, id, pk), "victor: summary line without key block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ParseKey([]byte(tt.body))
			if len(r.Keys) != 0 {
				t.Errorf("got %d keys, want 0", len(r.Keys))
			}
			if len(r.Errors) == 0 || !strings.Contains(r.Errors[0].Error(), tt.err) {
				t.Errorf("errors = %q, want first containing %q", errorStrings(r.Errors), tt.err)
			}
		})
	}
}

func TestParseKeyAccepts(t *testing.T) {
	h, id, pk := victorHeader, victorKeyID, victorPK
	addr52 := strings.Repeat("a", 52-len("@virebent.art")) + "@virebent.art"
	tests := []struct {
		name, body string
	}{
		{"upper-case keyids and pk", entry(strings.Replace(h, id, strings.ToUpper(id), 1), strings.ToUpper(id), strings.ToUpper(pk))},
		{"CRLF", strings.ReplaceAll(entry(h, id, pk), "\n", "\r\n")},
		{"lines between header and Begin, pk and End", h + "\nfoo\n\n" + beginLine + "\n" + id + "\n" + pk + "\nbar\n" + endLine + "\n"},
		{"no blank lines", h + "\n" + beginLine + "\n" + id + "\n" + pk + "\n" + endLine},
		{"long name", entry(strings.Replace(h, "victor", "averyveryverylongname", 1), id, pk)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ParseKey([]byte(tt.body))
			if len(r.Errors) != 0 || len(r.Keys) != 1 {
				t.Fatalf("got %d keys, errors %q", len(r.Keys), errorStrings(r.Errors))
			}
			if r.Keys[0].KeyID != id || hex.EncodeToString(r.Keys[0].PK[:]) != pk {
				t.Errorf("got %+v", r.Keys[0])
			}
		})
	}

	r := ParseKey([]byte(entry(strings.Replace(h, "yamn@virebent.art", addr52, 1), id, pk)))
	if len(r.Keys) != 1 || r.Keys[0].Address != addr52 {
		t.Errorf("52-byte address: %d keys, errors %q", len(r.Keys), errorStrings(r.Errors))
	}
}

func TestParseKeySeveral(t *testing.T) {
	h1, id1, pk1 := newKey("alpha", 1)
	h2, id2, pk2 := newKey("beta", 2)

	r := ParseKey([]byte("Here is the Mixmaster key:\n\n" + entry(h1, id1, pk1) + entry(h2, id2, pk2)))
	if len(r.Errors) != 0 || len(r.Keys) != 2 || r.Keys[0].Nick != "alpha" || r.Keys[1].Nick != "beta" {
		t.Errorf("two keys: got %d keys, errors %q", len(r.Keys), errorStrings(r.Errors))
	}

	// One good key and one with a bad pk.
	r = ParseKey([]byte(entry(h1, id1, pk2) + entry(h2, id2, pk2)))
	if len(r.Keys) != 1 || r.Keys[0].Nick != "beta" || len(r.Errors) != 1 {
		t.Errorf("good and bad: got %d keys, errors %q", len(r.Keys), errorStrings(r.Errors))
	}

	// A rejected summary line and its block give one error, not two.
	r = ParseKey([]byte(entry(strings.Replace(h1, "alpha", "Alpha", 1), id1, pk1) + entry(h2, id2, pk2)))
	if len(r.Keys) != 1 || len(r.Errors) != 1 {
		t.Errorf("bad name: got %d keys, errors %q", len(r.Keys), errorStrings(r.Errors))
	}

	// yamn would pair alpha's summary with beta's block here; both go.
	missingEnd := strings.TrimSuffix(entry(h1, id1, pk1), endLine+"\n\n") + "\n"
	r = ParseKey([]byte(missingEnd + entry(h2, id2, pk2)))
	if len(r.Keys) != 0 || len(r.Errors) != 2 {
		t.Errorf("missing End: got %d keys, errors %q", len(r.Keys), errorStrings(r.Errors))
	}
	r = ParseKey([]byte(h1 + "\n" + entry(h2, id2, pk2)))
	if len(r.Keys) != 0 || len(r.Errors) != 2 {
		t.Errorf("two headers: got %d keys, errors %q", len(r.Keys), errorStrings(r.Errors))
	}

	if r := ParseKey(nil); len(r.Keys) != 0 || len(r.Errors) != 0 {
		t.Errorf("empty: %+v", r)
	}
}

func TestParseSummary(t *testing.T) {
	s, err := ParseSummary(strings.Replace(victorHeader, victorKeyID, strings.ToUpper(victorKeyID), 1))
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyID != victorKeyID || s.String() != victorHeader {
		t.Errorf("got %+v", s)
	}
	if s.Created.Start() != time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) {
		t.Errorf("created = %v", s.Created)
	}
	for _, bad := range []string{"", victorHeader + " ", victorHeader + "\r", " " + victorHeader} {
		if _, err := ParseSummary(bad); err == nil {
			t.Errorf("ParseSummary(%q) succeeded", bad)
		}
	}
}

func TestValidAddress(t *testing.T) {
	for _, c := range []string{" ", "\t", "\x7f", "\x00", "é", `"`, "(", ")", ",", ":", ";", "<", ">", "[", `\`, "]", "@"} {
		if a := "ya" + c + "mn@virebent.art"; ValidAddress(a) {
			t.Errorf("ValidAddress(%q) = true", a)
		}
		if a := "yamn@vire" + c + "bent.art"; ValidAddress(a) {
			t.Errorf("ValidAddress(%q) = true", a)
		}
	}
	for _, a := range []string{"@virebent.art", "yamn@", "yamn", strings.Repeat("a", 40) + "@virebent.art"} {
		if ValidAddress(a) {
			t.Errorf("ValidAddress(%q) = true", a)
		}
	}
	for _, a := range []string{"yamn@virebent.art", "a@b", "a+b.c!d#e$f%g&h'i*j=k?l^m_n`o{p|q}r~s@x", strings.Repeat("a", 39) + "@virebent.art"} {
		if !ValidAddress(a) {
			t.Errorf("ValidAddress(%q) = false", a)
		}
	}
}
