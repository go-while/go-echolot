package mailout

import (
	"context"
	"crypto/rand"
	"crypto/sha3"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Mail for a .onion recipient goes straight to that host, port 25,
// through Tor's SOCKS port (mail.tor_socks), whatever mail.method is.  The
// .onion name goes to Tor as it is and is never looked up in DNS
// (Y-54).  There is no TLS requirement: Tor encrypts the connection end
// to end and the address is the service's key.  STARTTLS is used if
// offered, without checking the (mostly self-signed) certificate.  No
// login is ever sent there.

// torMailer delivers mail for .onion recipients.
type torMailer struct {
	socks string
	o     Options
	dial  func(ctx context.Context, addr string) (net.Conn, error) // tests replace it
}

func newTor(socks string, o Options) *torMailer {
	o = o.withDefaults()
	t := &torMailer{socks: socks, o: o}
	t.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		return torDial(ctx, socks, addr, o.TorDialTimeout)
	}
	return t
}

func (t *torMailer) Send(ctx context.Context, m Mail) error {
	if err := m.check(); err != nil {
		return err
	}
	host, onion, err := onionHost(m.Rcpt)
	if err != nil {
		return err
	}
	if !onion {
		return fmt.Errorf("%w: no .onion recipient", ErrInvalid)
	}
	addr := net.JoinHostPort(host, "25")
	conn, err := t.dial(ctx, addr)
	if err != nil {
		return &Error{Server: addr, Op: "dial through tor_socks " + t.socks, Err: err}
	}
	pol := policy{serverName: host, tls: tlsIfOffered}
	return session(ctx, conn, addr, pol, t.o, m)
}

// torDial connects to addr (host:port) through the SOCKS5 proxy at
// socks.  Every call logs in with a new random user name and password, so
// Tor (IsolateSOCKSAuth, on by default) gives it its own circuit, and
// mails to different remailers don't share one.  timeout covers the SOCKS
// handshake, which waits until Tor has reached the onion service.
func torDial(ctx context.Context, socks, addr string, timeout time.Duration) (net.Conn, error) {
	auth := &proxy.Auth{User: randomHex(16), Password: randomHex(16)}
	dialer, err := proxy.SOCKS5("tcp", socks, auth, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("tor_socks %s: %w", socks, err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, describeTorError(err)
	}
	return conn, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b) // never fails (crypto/rand since Go 1.24)
	return hex.EncodeToString(b)
}

// isOnion reports whether host is a Tor .onion name, in any case.
func isOnion(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "onion" || strings.HasSuffix(host, ".onion")
}

// validOnion reports whether host is a v3 onion address, optionally with
// subdomains (Tor ignores those): 56 base32 characters encoding the
// service's public key, a checksum and version 3.  Version 2 addresses
// (16 characters) stopped working in 2021.  As yamn's validOnion.
func validOnion(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	name, ok := strings.CutSuffix(host, ".onion")
	if !ok {
		return false
	}
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	if len(name) != 56 {
		return false
	}
	raw, err := base32.StdEncoding.DecodeString(strings.ToUpper(name))
	if err != nil || len(raw) != 35 {
		return false
	}
	pubkey, checksum, version := raw[:32], raw[32:34], raw[34]
	if version != 3 {
		return false
	}
	sum := onionChecksum(pubkey, version)
	return sum[0] == checksum[0] && sum[1] == checksum[1]
}

// onionChecksum is SHA3-256(".onion checksum" | pubkey | version).
func onionChecksum(pubkey []byte, version byte) []byte {
	h := sha3.New256()
	h.Write([]byte(".onion checksum"))
	h.Write(pubkey)
	h.Write([]byte{version})
	return h.Sum(nil)
}

// describeTorError adds the meaning of Tor's own SOCKS5 reply codes for
// onion services, which golang.org/x/net/proxy reports as "unknown code:
// N".  Tor sends them with the SocksPort flag ExtendedErrors.
func describeTorError(err error) error {
	_, after, ok := strings.Cut(err.Error(), "unknown code: ")
	if !ok {
		return err
	}
	end := strings.IndexFunc(after, func(c rune) bool { return c < '0' || c > '9' })
	if end < 0 {
		end = len(after)
	}
	code, cerr := strconv.Atoi(after[:end])
	if cerr != nil {
		return err
	}
	if desc := torReply(code); desc != "" {
		return fmt.Errorf("%w (%s)", err, desc)
	}
	return err
}

// torReply describes Tor's SOCKS5 reply codes for onion services.
func torReply(code int) string {
	switch code {
	case 0xf0:
		return "onion service descriptor not found"
	case 0xf1:
		return "onion service descriptor is invalid"
	case 0xf2:
		return "onion service introduction failed"
	case 0xf3:
		return "onion service rendezvous failed"
	case 0xf4:
		return "onion service needs client authorization"
	case 0xf5:
		return "onion service client authorization is wrong"
	case 0xf6:
		return "invalid onion address"
	case 0xf7:
		return "onion service introduction timed out"
	}
	return ""
}
