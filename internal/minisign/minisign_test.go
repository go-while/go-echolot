package minisign

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite go-echolot's files in testdata/signing")

// vectors is the test data shared with yamn's verifier (design §9.5).
const vectors = "../../testdata/signing"

// vectorTime is when the vectors were signed: 2026-10-22 12:00 UTC.
var vectorTime = time.Unix(1792670400, 0).UTC()

// vectorFiles are the signed files of the vectors and their validity.
var vectorFiles = []struct {
	name     string
	validity time.Duration
}{{"pubring.mix", 48 * time.Hour}, {"mlist2.txt", 6 * time.Hour}}

func newKey(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyRoundTrip(t *testing.T) {
	k := newKey(t)
	k2, err := ParsePrivateKey(k.File())
	if err != nil {
		t.Fatal(err)
	}
	if k2.ID != k.ID || !bytes.Equal(k2.Key, k.Key) {
		t.Fatal("secret key changed in the round trip")
	}
	p := k.Public()
	for _, in := range [][]byte{p.File(), []byte(p.String()), []byte(" " + p.String() + "\n")} {
		p2, err := ParsePublicKey(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if p2.ID != p.ID || !bytes.Equal(p2.Key, p.Key) {
			t.Fatal("public key changed in the round trip")
		}
	}
	if !strings.HasPrefix(string(p.File()), "untrusted comment: minisign public key "+p.ID.String()+"\nRW") {
		t.Errorf("public key file: %q", p.File())
	}
}

func TestKeyID(t *testing.T) {
	// minisign prints the ID as a little-endian number.
	id := KeyID{0xf5, 0x61, 0x58, 0x4c, 0x28, 0x2b, 0xf9, 0x16}
	if got := id.String(); got != "16F92B284C5861F5" {
		t.Errorf("got %s", got)
	}
}

func TestBadSecretKeys(t *testing.T) {
	k := newKey(t)
	good := k.File()
	lines := strings.Split(string(good), "\n")
	mutate := func(f func(b []byte)) []byte {
		b, _ := decodeB64(lines[1])
		f(b)
		return []byte(lines[0] + "\n" + encodeB64(b) + "\n")
	}
	for name, in := range map[string][]byte{
		"no comment":    []byte(lines[1] + "\n"),
		"short":         []byte(lines[0] + "\nRWQAAA==\n"),
		"password":      mutate(func(b []byte) { copy(b[2:4], "Sc") }),
		"unknown kdf":   mutate(func(b []byte) { copy(b[2:4], "Xx") }),
		"unknown alg":   mutate(func(b []byte) { copy(b[0:2], "Xx") }),
		"bad checksum":  mutate(func(b []byte) { b[len(b)-1] ^= 1 }),
		"halves differ": mutate(func(b []byte) { b[54+8+40] ^= 1; copy(b[126:], checksumRaw(b)) }),
	} {
		if _, err := ParsePrivateKey(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// minisign 0.12 writes keys without a password with a 0 checksum.
	zero := mutate(func(b []byte) { copy(b[126:], make([]byte, 32)) })
	if _, err := ParsePrivateKey(zero); err != nil {
		t.Errorf("zero checksum: %v", err)
	}
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func encodeB64(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }

func checksumRaw(b []byte) []byte {
	var id KeyID
	copy(id[:], b[54:62])
	return checksum(id, b[62:126])
}

func TestSignVerify(t *testing.T) {
	k := newKey(t)
	p := k.Public()
	data := []byte("some file\n")
	sig, err := Sign(k, data, "timestamp:1 file:x expires:2", "test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(p, data, sig)
	if err != nil || c != "timestamp:1 file:x expires:2" {
		t.Fatalf("Verify: %q, %v", c, err)
	}
	if _, err := Verify(p, []byte("other\n"), sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("other data: %v", err)
	}
	if _, err := Verify(newKey(t).Public(), data, sig); !errors.Is(err, ErrWrongKey) {
		t.Errorf("other key: %v", err)
	}
	// Changing the trusted comment breaks the second signature.
	forged := bytes.Replace(sig, []byte("expires:2"), []byte("expires:9"), 1)
	if _, err := Verify(p, data, forged); !errors.Is(err, ErrBadSignature) {
		t.Errorf("forged comment: %v", err)
	}
	// The same key ID with another key doesn't verify either.
	k2 := newKey(t)
	k2.ID = k.ID
	if _, err := Verify(k2.Public(), data, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("same ID, other key: %v", err)
	}
	crlf := bytes.ReplaceAll(sig, []byte("\n"), []byte("\r\n"))
	if _, err := Verify(p, data, crlf); err != nil {
		t.Errorf("CR LF: %v", err)
	}
	for _, c := range []string{"a\nb", "a\rb", strings.Repeat("x", MaxComment+1)} {
		if _, err := Sign(k, data, c, ""); err == nil {
			t.Errorf("comment %.20q accepted", c)
		}
	}
}

func TestParseSignatureErrors(t *testing.T) {
	k := newKey(t)
	sig, _ := Sign(k, []byte("x"), "t", "u")
	lines := strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n")
	join := func(l ...string) []byte { return []byte(strings.Join(l, "\n") + "\n") }
	for name, in := range map[string][]byte{
		"three lines":    join(lines[:3]...),
		"five lines":     join(append(lines, "x")...),
		"no untrusted":   join("x", lines[1], lines[2], lines[3]),
		"no trusted":     join(lines[0], lines[1], "x", lines[3]),
		"bad sig":        join(lines[0], "AAAA", lines[2], lines[3]),
		"bad global":     join(lines[0], lines[1], lines[2], "AAAA"),
		"unknown alg":    join(lines[0], encodeB64(append([]byte("XX"), make([]byte, 72)...)), lines[2], lines[3]),
		"too long":       bytes.Repeat([]byte("x"), maxSigFile+1),
		"empty":          nil,
		"trailing lines": append(join(lines...), '\n'),
	} {
		if _, err := ParseSignature(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTrusted(t *testing.T) {
	ts := time.Unix(1792670400, 0).UTC()
	tr := Trusted{Timestamp: ts, File: "pubring.mix", Pinger: "mixmin", Expires: ts.Add(48 * time.Hour)}
	s := tr.String()
	if s != "timestamp:1792670400 file:pubring.mix pinger:mixmin expires:1792843200" {
		t.Fatalf("String: %q", s)
	}
	got, err := ParseTrusted(s)
	if err != nil || got != tr {
		t.Fatalf("ParseTrusted: %+v, %v", got, err)
	}
	// Any order; unknown keys are ignored; pinger is optional.
	got, err = ParseTrusted("expires:1792843200 sha256:abcd file:pubring.mix timestamp:1792670400 x_1:y:z")
	if err != nil || got.File != "pubring.mix" || !got.Timestamp.Equal(ts) || got.Pinger != "" {
		t.Fatalf("reordered: %+v, %v", got, err)
	}
	for _, bad := range []string{
		"",
		"timestamp:1 file:x",                              // no expires
		"timestamp:1 expires:2",                           // no file
		"file:x expires:2",                                // no timestamp
		"timestamp:1 file:x expires:2 file:y",             // twice
		"timestamp:1  file:x expires:2",                   // two spaces
		" timestamp:1 file:x expires:2",                   // leading space
		"timestamp:1 file:x expires:2 ",                   // trailing space
		"timestamp:-1 file:x expires:2",                   // sign
		"timestamp:+1 file:x expires:2",                   // sign
		"timestamp:1.5 file:x expires:2",                  // not an integer
		"timestamp:1 file:x expires:1",                    // expires not after timestamp
		"timestamp:1 file:a/b expires:2",                  // not a base name
		"timestamp:1 file: expires:2",                     // empty value
		"timestamp:1 file:x expires:2 Pinger:x",           // upper-case key
		"timestamp:1 file:x expires:2 nocolon",            // no colon
		"timestamp:1\tfile:x expires:2",                   // tab
		"timestamp:1 file:xé expires:2",                   // not ASCII
		"timestamp:99999999999999999999 file:x expires:2", // too big
	} {
		if _, err := ParseTrusted(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestVerifyFile(t *testing.T) {
	k := newKey(t)
	p := k.Public()
	ts := time.Unix(1792670400, 0).UTC()
	data := []byte("ring\n")
	sign := func(tr Trusted) []byte {
		sig, err := Sign(k, data, tr.String(), "")
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	sig := sign(Trusted{Timestamp: ts, File: "pubring.mix", Expires: ts.Add(time.Hour)})
	if _, err := VerifyFile(p, "pubring.mix", data, sig, ts.Add(30*time.Minute)); err != nil {
		t.Errorf("good: %v", err)
	}
	if _, err := VerifyFile(p, "mlist2.txt", data, sig, ts); !errors.Is(err, ErrWrongFile) {
		t.Errorf("other file: %v", err)
	}
	if tr, err := VerifyFile(p, "pubring.mix", data, sig, ts.Add(time.Hour)); !errors.Is(err, ErrExpired) || tr.File != "pubring.mix" {
		t.Errorf("expired: %v", err)
	}
	bad, _ := Sign(k, data, "not a contract", "")
	if _, err := VerifyFile(p, "pubring.mix", data, bad, ts); err == nil {
		t.Error("comment outside the grammar accepted")
	}
}

// TestVectors checks the files in testdata/signing that yamn's verifier
// tests use too: go-echolot's signatures are reproduced byte for byte,
// and those of the reference minisign tool verify.  With -update it
// writes go-echolot's files (and a new test key if there is none).
func TestVectors(t *testing.T) {
	keyPath := filepath.Join(vectors, "pinger.key")
	if *update {
		if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(keyPath, newKey(t).File(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(kb)
	if err != nil {
		t.Fatal(err)
	}
	p := k.Public()
	check := func(name string, want []byte) {
		t.Helper()
		path := filepath.Join(vectors, name)
		if *update {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from what go-echolot writes (go test -update?):\n%s\nwant\n%s", name, got, want)
		}
	}
	check("pinger.pub", p.File())
	for _, f := range vectorFiles {
		data, err := os.ReadFile(filepath.Join(vectors, f.name))
		if err != nil {
			t.Fatal(err)
		}
		tr := Trusted{Timestamp: vectorTime, File: f.name, Pinger: "test", Expires: vectorTime.Add(f.validity)}
		sig, err := Sign(k, data, tr.String(), UntrustedComment)
		if err != nil {
			t.Fatal(err)
		}
		check(f.name+".minisig", sig)
		got, err := VerifyFile(p, f.name, data, sig, vectorTime)
		if err != nil || got != tr {
			t.Errorf("%s: %+v, %v", f.name, got, err)
		}
		// The same file and comment signed by the reference tool.
		ref, err := os.ReadFile(filepath.Join(vectors, f.name+".minisign-tool.minisig"))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := VerifyFile(p, f.name, data, ref, vectorTime); err != nil || got != tr {
			t.Errorf("%s, minisign's signature: %+v, %v", f.name, got, err)
		}
	}
}

// minisignBin returns the reference minisign binary from MINISIGN_BIN,
// or skips the test.
func minisignBin(t *testing.T) string {
	bin := os.Getenv("MINISIGN_BIN")
	if bin == "" {
		t.Skip("MINISIGN_BIN not set")
	}
	return bin
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// TestMinisignTool checks go-echolot's formats against the reference
// tool, both ways.
func TestMinisignTool(t *testing.T) {
	bin := minisignBin(t)
	dir := t.TempDir()
	data := []byte("some file\nwith two lines\n")
	file := filepath.Join(dir, "pubring.mix")
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(time.Now().Unix(), 0).UTC()
	tr := Trusted{Timestamp: ts, File: "pubring.mix", Pinger: "test", Expires: ts.Add(time.Hour)}

	// go-echolot's key and signature, verified by minisign.
	k := newKey(t)
	pub := filepath.Join(dir, "pinger.pub")
	if err := os.WriteFile(pub, k.Public().File(), 0o644); err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(k, data, tr.String(), UntrustedComment)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file+".minisig", sig, 0o644); err != nil {
		t.Fatal(err)
	}
	out := run(t, bin, "-Vm", file, "-p", pub)
	if !strings.Contains(out, "Trusted comment: "+tr.String()) {
		t.Errorf("minisign -V: %s", out)
	}
	run(t, bin, "-VHm", file, "-P", k.Public().String()) // prehashed, key on the command line

	// minisign signs with go-echolot's secret key file.
	skPath := filepath.Join(dir, "pinger.key")
	if err := os.WriteFile(skPath, k.File(), 0o600); err != nil {
		t.Fatal(err)
	}
	refSig := filepath.Join(dir, "ref.minisig")
	run(t, bin, "-S", "-s", skPath, "-m", file, "-x", refSig, "-t", tr.String())
	rb, err := os.ReadFile(refSig)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyFile(k.Public(), "pubring.mix", data, rb, ts); err != nil || got != tr {
		t.Errorf("minisign's signature with our key: %+v, %v", got, err)
	}
	// Ed25519 is deterministic: the same key, file and comment give the
	// same signatures.
	if a, b := sigLines(t, sig), sigLines(t, rb); a != b {
		t.Errorf("signatures differ:\n%s\n%s", a, b)
	}

	// minisign's own key pair (without a password), read by go-echolot.
	mpub, msec := filepath.Join(dir, "m.pub"), filepath.Join(dir, "m.key")
	run(t, bin, "-G", "-W", "-p", mpub, "-s", msec)
	run(t, bin, "-S", "-s", msec, "-m", file, "-t", tr.String())
	mb, _ := os.ReadFile(mpub)
	mp, err := ParsePublicKey(mb)
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := os.ReadFile(file + ".minisig")
	if _, err := VerifyFile(mp, "pubring.mix", data, ms, ts); err != nil {
		t.Errorf("minisign's key and signature: %v", err)
	}
	sb, _ := os.ReadFile(msec)
	mk, err := ParsePrivateKey(sb)
	if err != nil {
		t.Fatalf("minisign's secret key: %v", err)
	}
	if mk.Public().String() != mp.String() {
		t.Error("minisign's secret and public keys don't match here")
	}
	// A legacy (not prehashed) signature verifies too.
	run(t, bin, "-S", "-l", "-s", msec, "-m", file, "-t", tr.String())
	ms, _ = os.ReadFile(file + ".minisig")
	if s, err := ParseSignature(ms); err != nil || s.Prehashed {
		t.Fatalf("legacy signature: %+v, %v", s, err)
	}
	if _, err := VerifyFile(mp, "pubring.mix", data, ms, ts); err != nil {
		t.Errorf("legacy signature: %v", err)
	}
}

// sigLines returns the two signature lines of a signature file.
func sigLines(t *testing.T, sig []byte) string {
	t.Helper()
	l := strings.Split(string(sig), "\n")
	if len(l) < 4 {
		t.Fatalf("signature file: %q", sig)
	}
	return l[1] + "\n" + l[3]
}

func FuzzParseSignature(f *testing.F) {
	k, _ := GenerateKey(nil)
	sig, _ := Sign(k, []byte("x"), "timestamp:1 file:x expires:2", "u")
	f.Add(sig)
	f.Add([]byte("untrusted comment: \n\ntrusted comment: \n\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseSignature(b)
		if err != nil {
			return
		}
		_ = s.VerifyComment(k.Public())
		if tr, err := ParseTrusted(s.Trusted); err == nil {
			if again, err := ParseTrusted(tr.String()); err != nil || again != tr {
				t.Fatalf("%q: round trip %+v, %v", s.Trusted, again, err)
			}
		}
	})
}
