package mailout

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is an SMTP server on 127.0.0.1 that a test scripts.
type fakeSMTP struct {
	ln      net.Listener
	tlsConf *tls.Config       // non-nil: offer STARTTLS
	auth    bool              // offer AUTH PLAIN
	replies map[string]string // by "GREETING", "EHLO", "MAIL", "RCPT", "DATA", "DOT"; "HANG" never answers
	tarpit  bool              // accept, never say anything

	mu       sync.Mutex
	sessions []*fakeSession
}

type fakeSession struct {
	cmds     []string // verbs in order; "STARTTLS" marks the switch
	ehlo     string
	tls      bool
	user     string
	pass     string
	authTLS  bool
	from     string
	rcpt     []string
	raw      []byte // DATA as on the wire, CRLF and dot-stuffing included
	accepted bool
}

func newFakeSMTP(t *testing.T, setup func(f *fakeSMTP)) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, replies: map[string]string{}}
	if setup != nil {
		setup(f)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

// snapshot returns a copy of the sessions so far.
func (f *fakeSMTP) snapshot() []fakeSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeSession, len(f.sessions))
	for i, s := range f.sessions {
		out[i] = *s
		out[i].cmds = append([]string(nil), s.cmds...)
		out[i].rcpt = append([]string(nil), s.rcpt...)
	}
	return out
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer func() { c.Close() }()
	s := &fakeSession{}
	f.mu.Lock()
	f.sessions = append(f.sessions, s)
	f.mu.Unlock()
	update := func(fn func()) {
		f.mu.Lock()
		fn()
		f.mu.Unlock()
	}
	if f.tarpit {
		io.Copy(io.Discard, c)
		return
	}
	tp := textproto.NewConn(c)
	// answer sends the scripted reply for key, or def.  false: hang up.
	answer := func(key, def string) bool {
		r, ok := f.replies[key]
		if !ok {
			r = def
		}
		if r == "HANG" {
			io.Copy(io.Discard, c)
			return false
		}
		tp.PrintfLine("%s", r)
		return true
	}
	if !answer("GREETING", "220 fake ESMTP") {
		return
	}
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		update(func() { s.cmds = append(s.cmds, verb) })
		switch verb {
		case "EHLO":
			update(func() { s.ehlo = arg })
			if r, ok := f.replies["EHLO"]; ok {
				if !answer("EHLO", r) {
					return
				}
				continue
			}
			lines := []string{"fake"}
			if f.tlsConf != nil && !s.tls {
				lines = append(lines, "STARTTLS")
			}
			if f.auth {
				lines = append(lines, "AUTH PLAIN")
			}
			lines = append(lines, "8BITMIME")
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				tp.PrintfLine("250%s%s", sep, l)
			}
		case "STARTTLS":
			tp.PrintfLine("220 go ahead")
			tc := tls.Server(c, f.tlsConf)
			if err := tc.Handshake(); err != nil {
				return
			}
			c = tc
			tp = textproto.NewConn(tc)
			update(func() { s.tls = true })
		case "AUTH":
			mech, resp, _ := strings.Cut(arg, " ")
			raw, err := base64.StdEncoding.DecodeString(resp)
			parts := strings.Split(string(raw), "\x00")
			if mech != "PLAIN" || err != nil || len(parts) != 3 {
				tp.PrintfLine("501 bad auth")
				continue
			}
			update(func() { s.user, s.pass, s.authTLS = parts[1], parts[2], s.tls })
			tp.PrintfLine("235 ok")
		case "MAIL":
			update(func() { s.from = addrArg(arg) })
			if !answer("MAIL", "250 ok") {
				return
			}
		case "RCPT":
			update(func() { s.rcpt = append(s.rcpt, addrArg(arg)) })
			if !answer("RCPT", "250 ok") {
				return
			}
		case "DATA":
			if !answer("DATA", "354 go") {
				return
			}
			if r := f.replies["DATA"]; r != "" && r[0] != '3' {
				continue
			}
			var raw []byte
			for {
				l, err := tp.R.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				raw = append(raw, l...)
			}
			r, ok := f.replies["DOT"]
			update(func() { s.raw = raw; s.accepted = !ok || r[0] == '2' })
			if !answer("DOT", "250 queued") {
				return
			}
		case "QUIT":
			tp.PrintfLine("221 bye")
			return
		case "RSET", "NOOP":
			tp.PrintfLine("250 ok")
		default:
			tp.PrintfLine("500 what")
		}
	}
}

// addrArg returns the address in "FROM:<a> ..." or "TO:<a>".
func addrArg(arg string) string {
	_, a, _ := strings.Cut(arg, "<")
	a, _, _ = strings.Cut(a, ">")
	return a
}

// testCert returns a self-signed certificate for names and 127.0.0.1, and
// a pool that trusts it.
func testCert(t *testing.T, names ...string) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake relay"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              names,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

// fakeSOCKS is a SOCKS5 server on 127.0.0.1 that wants a user name and
// password and connects every request to target.
type fakeSOCKS struct {
	ln     net.Listener
	target string
	code   byte // reply code; 0 = success

	mu    sync.Mutex
	users []string
	pass  []string
	hosts []string
	ports []int
}

func newFakeSOCKS(t *testing.T, target string) *fakeSOCKS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSOCKS{ln: ln, target: target}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSOCKS) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil
		}
		return b
	}
	hdr := read(2)
	if hdr == nil || hdr[0] != 5 {
		return
	}
	methods := read(int(hdr[1]))
	if !strings.ContainsRune(string(methods), 2) {
		c.Write([]byte{5, 0xff})
		return
	}
	c.Write([]byte{5, 2})
	v := read(2)
	if v == nil || v[0] != 1 {
		return
	}
	user := read(int(v[1]))
	pl := read(1)
	if pl == nil {
		return
	}
	pass := read(int(pl[0]))
	c.Write([]byte{1, 0})
	req := read(4)
	if req == nil || req[1] != 1 || req[3] != 3 {
		return
	}
	nl := read(1)
	if nl == nil {
		return
	}
	host := read(int(nl[0]))
	port := read(2)
	if port == nil {
		return
	}
	f.mu.Lock()
	f.users = append(f.users, string(user))
	f.pass = append(f.pass, string(pass))
	f.hosts = append(f.hosts, string(host))
	f.ports = append(f.ports, int(binary.BigEndian.Uint16(port)))
	f.mu.Unlock()
	if f.code != 0 {
		c.Write([]byte{5, f.code, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.Dial("tcp", f.target)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go func() {
		io.Copy(up, r)
		up.Close()
	}()
	io.Copy(c, up)
}
