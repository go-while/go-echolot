package token

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	secret = func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}()
	t0 = time.Unix(1792560000, 0).UTC()
)

func minter(t testing.TB, delim string) *Minter {
	t.Helper()
	m, err := New(Config{Secret: secret, Address: "pinger@pinger.example.org", Delimiter: delim})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func address(t testing.TB, m *Minter, tok Token) string {
	t.Helper()
	a, err := m.Address(tok)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestGolden pins the address format and the key derivation: changing
// either would break the replies in flight.
func TestGolden(t *testing.T) {
	m := minter(t, "+")
	got := address(t, m, Token{Kind: KindKey, ID: 12, Time: t0})
	if want := "pinger+key.12=1792560000=" + golden + "@pinger.example.org"; got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	// The same MAC, computed here from the design's formulas (§6.1).
	k, _ := hkdf.Key(sha256.New, secret, []byte("go-echolot"), "v1 token", 32)
	h := hmac.New(sha256.New, k)
	h.Write([]byte("key.12=1792560000"))
	if mac := hex.EncodeToString(h.Sum(nil))[:16]; mac != golden {
		t.Errorf("MAC by the formula %s, golden %s", mac, golden)
	}
}

const golden = "9b92f38f5e707520"

func TestAddressForms(t *testing.T) {
	tok := Token{Kind: KindPing, Time: t0}
	for delim, want := range map[string]string{
		"+": "pinger+ping=1792560000=",
		"-": "pinger-ping=1792560000=",
		"":  "pinger@pinger.example.org(ping=1792560000=",
	} {
		if a := address(t, minter(t, delim), tok); !strings.HasPrefix(a, want) {
			t.Errorf("delimiter %q: %s", delim, a)
		}
	}
	m, _ := New(Config{Secret: secret, Address: "Pinger@Example.org", Delimiter: "+"})
	if a := address(t, m, tok); !strings.HasPrefix(a, "Pinger+ping=") || !strings.HasSuffix(a, "@Example.org") {
		t.Errorf("case not kept: %s", a)
	}
	// Room for a token in the 64-character local part: config allows a
	// local part of 20 characters with a 6-digit ID (internal/config).
	m, _ = New(Config{Secret: secret, Address: strings.Repeat("p", 20) + "@example.org", Delimiter: "+"})
	a := address(t, m, Token{Kind: KindAdminkey, ID: 999999, Time: time.Unix(9999999999, 0)})
	if local, _, _ := strings.Cut(a, "@"); len(local) != 64 {
		t.Errorf("local part of %s is %d characters", a, len(local))
	}
}

func TestAddressErrors(t *testing.T) {
	m := minter(t, "+")
	for _, tok := range []Token{
		{Kind: "stats", ID: 1, Time: t0},
		{Kind: KindKey, Time: t0},
		{Kind: KindKey, ID: -1, Time: t0},
		{Kind: KindPing, ID: 3, Time: t0},
		{Kind: KindPing, ID: -3, Time: t0},
		{Kind: KindConf, ID: 1},
	} {
		if a, err := m.Address(tok); err == nil {
			t.Errorf("%+v: %s", tok, a)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, delim := range []string{"+", "-", ""} {
		m := minter(t, delim)
		for _, tok := range []Token{
			{Kind: KindConf, ID: 1, Time: t0},
			{Kind: KindKey, ID: 123456789, Time: t0},
			{Kind: KindHelp, ID: 7, Time: t0},
			{Kind: KindAdminkey, ID: 7, Time: t0},
			{Kind: KindBounce, ID: 3, Time: t0},
			{Kind: KindPing, Time: t0},
			{Kind: KindChainping, Time: t0},
		} {
			a := address(t, m, tok)
			for _, now := range []time.Time{t0, t0.Add(-MaxFuture), t0.Add(tok.Kind.MaxAge())} {
				got, err := m.Verify(a, now)
				if err != nil || got != tok {
					t.Errorf("%q at %v: %+v, %v", a, now, got, err)
				}
			}
		}
	}
}

func TestVerifyHeaders(t *testing.T) {
	m := minter(t, "+")
	a := address(t, m, Token{Kind: KindKey, ID: 12, Time: t0})
	local, _, _ := strings.Cut(a, "@")
	for _, header := range []string{
		a,
		"<" + a + ">",
		"Pinger Test <" + a + ">",
		strings.ToUpper(a),
		"someone@example.org, " + a,
		"pinger+key.12=1792560000=0000000000000000@x.org, " + a, // a bad one before
		local + "@localhost", // another domain
		// Echolot's form without a delimiter is accepted as well.
		"pinger@pinger.example.org (" + strings.TrimPrefix(local, "pinger+") + ")",
	} {
		if tok, err := m.Verify(header, t0); err != nil || tok.ID != 12 {
			t.Errorf("%q: %+v, %v", header, tok, err)
		}
	}
}

func TestVerifyErrors(t *testing.T) {
	m := minter(t, "+")
	key := address(t, m, Token{Kind: KindKey, ID: 12, Time: t0})
	ping := address(t, m, Token{Kind: KindPing, Time: t0})
	flip := func(a string) string { // change the last MAC digit
		i := strings.Index(a, "@") - 1
		c := byte('0')
		if a[i] == '0' {
			c = '1'
		}
		return a[:i] + string(c) + a[i+1:]
	}
	for _, tc := range []struct {
		addr string
		now  time.Time
		want error
	}{
		{"pinger@pinger.example.org", t0, ErrNoToken},
		{"", t0, ErrNoToken},
		{strings.Replace(key, "pinger+", "other+", 1), t0, ErrNoToken},
		{strings.Replace(key, "pinger+", "xpinger+", 1), t0, ErrNoToken},
		{strings.Replace(key, "pinger+", "pinger-", 1), t0, ErrNoToken}, // not our delimiter
		{flip(key), t0, ErrBadMAC},
		{strings.Replace(key, "key.12", "key.13", 1), t0, ErrBadMAC},
		{strings.Replace(key, "key.12", "conf.12", 1), t0, ErrBadMAC},
		{strings.Replace(key, "key.12", "key.012", 1), t0, ErrBadMAC},
		{strings.Replace(key, "1792560000", "1792560001", 1), t0, ErrBadMAC},
		{key[:strings.Index(key, "@")-4] + key[strings.Index(key, "@"):], t0, ErrBadMAC}, // 12-digit MAC
		{strings.Replace(key, "key.12", "stats.12", 1), t0, ErrNoToken},
		{strings.Replace(key, "key.12", "key", 1), t0, ErrNoToken},
		{strings.Replace(ping, "ping=", "ping.4=", 1), t0, ErrNoToken},
		{key, t0.Add(RequestMaxAge + time.Second), ErrTooOld},
		{ping, t0.Add(PingMaxAge + time.Second), ErrTooOld},
		{key, t0.Add(-MaxFuture - time.Second), ErrFuture},
	} {
		if _, err := m.Verify(tc.addr, tc.now); !errors.Is(err, tc.want) {
			t.Errorf("%q: got %v, want %v", tc.addr, err, tc.want)
		}
	}
}

// TestLegacy checks Echolot's MD5 tokens with vectors from Perl's
// Digest::MD5: md5_hex("key.12=1792560000" . secret), first 8 digits.
func TestLegacy(t *testing.T) {
	const echolotSecret = "0123456789abcdef0123456789abcdef"
	until := t0.Add(48 * time.Hour)
	m, err := New(Config{Secret: secret, Address: "pinger@pinger.example.org", Delimiter: "+",
		LegacySecret: echolotSecret, LegacyUntil: until})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr string
		now  time.Time
		want error
	}{
		{"pinger+key.12=1792560000=7f220fb7@pinger.example.org", t0, nil},
		{"pinger@pinger.example.org(conf.3=1792500000=39ee6926)", t0, nil},
		{"pinger+key.12=1792560000=7f220fb7@pinger.example.org", until, ErrBadMAC},        // too late
		{"pinger+key.12=1792560000=7f220fb8@pinger.example.org", t0, ErrBadMAC},           // wrong
		{"pinger+ping=1792560000=" + legacy("ping=1792560000") + "@x.org", t0, ErrBadMAC}, // not a request
		{"pinger+bounce.1=1792560000=" + legacy("bounce.1=1792560000") + "@x.org", t0, ErrBadMAC},
	} {
		tok, err := m.Verify(tc.addr, tc.now)
		if !errors.Is(err, tc.want) || err == nil && !tok.Legacy {
			t.Errorf("%q: %+v, %v; want %v", tc.addr, tok, err, tc.want)
		}
	}
	// Without the Echolot secret, MD5 tokens are refused.
	if _, err := minter(t, "+").Verify("pinger+key.12=1792560000=7f220fb7@x.org", t0); !errors.Is(err, ErrBadMAC) {
		t.Errorf("without the legacy secret: %v", err)
	}
	// New tokens still work, and aren't legacy.
	tok, err := m.Verify(address(t, m, Token{Kind: KindKey, ID: 1, Time: t0}), t0)
	if err != nil || tok.Legacy {
		t.Errorf("new token: %+v, %v", tok, err)
	}
}

// legacy computes an Echolot MAC with the test's Echolot secret.
func legacy(text string) string {
	m := &Minter{legacySecret: "0123456789abcdef0123456789abcdef"}
	return m.legacyMAC(text)
}

func TestNewErrors(t *testing.T) {
	for _, c := range []Config{
		{Secret: secret[:16], Address: "p@x.org", Delimiter: "+"},
		{Secret: secret, Address: "p", Delimiter: "+"},
		{Secret: secret, Address: "@x.org", Delimiter: "+"},
		{Secret: secret, Address: "p@", Delimiter: "+"},
		{Secret: secret, Address: "p@x.org", Delimiter: "="},
		{Secret: secret, Address: "p@x.org", Delimiter: "+", LegacySecret: "abc"},
		{Secret: secret, Address: "p@x.org", Delimiter: "+", LegacySecret: "0123456789ABCDEF0123456789ABCDEF"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestDeriveKey(t *testing.T) {
	seen := map[[32]byte]string{}
	for _, p := range []string{PurposeToken, PurposePingMAC, PurposePingBox, PurposeSched} {
		k := DeriveKey(secret, p)
		if other, dup := seen[k]; dup {
			t.Errorf("%s and %s have the same key", p, other)
		}
		seen[k] = p
	}
	if DeriveKey(secret, PurposeToken) != DeriveKey(secret, PurposeToken) {
		t.Error("not deterministic")
	}
	other := append([]byte{1}, secret[1:]...)
	if DeriveKey(other, PurposeToken) == DeriveKey(secret, PurposeToken) {
		t.Error("the key doesn't depend on the secret")
	}
}

// FuzzVerify checks that Verify doesn't panic, and that whatever it
// accepts is a token Address makes again.
func FuzzVerify(f *testing.F) {
	m := minter(f, "+")
	for _, tok := range []Token{{Kind: KindKey, ID: 12, Time: t0}, {Kind: KindPing, Time: t0}} {
		f.Add(address(f, m, tok))
	}
	f.Add("pinger@x.org(conf.3=1792500000=39ee6926)")
	f.Add("Name <pinger+bounce.1=1792560000=00@x>, pinger+help.9=0=ffffffffffffffff@y")
	f.Fuzz(func(t *testing.T, addr string) {
		tok, err := m.Verify(addr, t0)
		if err != nil {
			return
		}
		a := address(t, m, tok)
		if again, err := m.Verify(a, t0); err != nil || again != tok {
			t.Fatalf("%q -> %+v -> %q -> %+v, %v", addr, tok, a, again, err)
		}
	})
}

// FuzzRoundTrip checks that every address Address makes verifies to its
// token.
func FuzzRoundTrip(f *testing.F) {
	f.Add(uint8(0), 12, int64(1792560000), uint8(0))
	f.Add(uint8(5), 0, int64(1), uint8(2))
	kinds := []Kind{KindConf, KindKey, KindHelp, KindAdminkey, KindBounce, KindPing, KindChainping}
	minters := []*Minter{minter(f, "+"), minter(f, "-"), minter(f, "")}
	f.Fuzz(func(t *testing.T, k uint8, id int, unix int64, d uint8) {
		tok := Token{Kind: kinds[int(k)%len(kinds)], ID: id, Time: time.Unix(unix, 0).UTC()}
		m := minters[int(d)%len(minters)]
		a, err := m.Address(tok)
		if err != nil {
			return
		}
		got, err := m.Verify(a, tok.Time)
		if id > 999999999 || unix > 999999999999 {
			if err == nil {
				t.Fatalf("%q verified with an over-long ID or time", a)
			}
			return
		}
		if err != nil || got != tok {
			t.Fatalf("%+v -> %q -> %+v, %v", tok, a, got, err)
		}
	})
}
