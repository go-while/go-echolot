package pinger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/replies"
)

// Hop is one remailer of a ping's chain and the key to encrypt to.
type Hop struct {
	Address string            // where the packet goes; given to yamn's -l
	KeyID   string            // the key the ping is for
	Key     replies.ParsedKey // that key; its Address and KeyID must match
}

// HopOf returns the hop for key k.
func HopOf(k replies.ParsedKey) Hop {
	return Hop{Address: k.Address, KeyID: k.KeyID, Key: k}
}

// Encoder turns the mail given to yamn into the encrypted mail for the
// first hop of chain.
//
// A ping to a middleman is a one-hop chain, the middleman alone: the
// packet is a final-hop packet encrypted to it, and since it isn't an
// exit it randhops the message through a random exit from its own
// pubring and stats (Y:server.go:584-598 decodeV2, 735-764 randhop).
// That is what Echolot measures (design §2.2, question 14); the yamn
// client accepts the one-hop chain and needs no exit keys or stats.
// A chain (phase 3 chain pings) lists every hop, exit last.
//
// Every error means nothing was sent: errors.Is(err, ErrLocal) holds,
// and the caller journals the ping as aborted, not lost (design §8.4).
type Encoder interface {
	Encode(ctx context.Context, chain []Hop, plaintextMail []byte) (to string, mail []byte, err error)
}

var (
	// ErrLocal is wrapped by every Encode error: a local failure, the
	// ping never left.
	ErrLocal = errors.New("local failure")
	// ErrTimeout: yamn didn't finish within the timeout.
	ErrTimeout = errors.New("yamn timed out")
)

// EncodeError is a failed Encode.  It wraps ErrLocal and Err.
type EncodeError struct {
	Op       string // "check", "setup", "run", "output"
	ExitCode int    // yamn's exit status, -1 if it didn't exit normally
	Stderr   string // the start of yamn's stderr, cleaned for logging
	Err      error
}

func (e *EncodeError) Error() string {
	s := "yamn encode: " + e.Op + ": " + e.Err.Error()
	if e.Stderr != "" {
		s += ": " + e.Stderr
	}
	return s
}

func (e *EncodeError) Unwrap() []error { return []error{ErrLocal, e.Err} }

// Defaults and limits of YamnEncoder.
const (
	DefaultTimeout = 30 * time.Second
	maxChain       = 10      // yamn's maxChainLength
	maxStdout      = 1 << 20 // one ping is one ~28 KB mail
	maxStderr      = 2048    // kept for the error and the log
)

// YamnEncoder runs the yamn client (design §6.3).  Each call gets a fresh
// directory D (mode 0700) holding a pubring.mix with exactly the keys of
// the chain and a yamn.yml that never fetches, never pins and never
// sends; yamn writes the encrypted mail to stdout.  D is removed after.
// If the mail has a From line (with_from), yamn gets --keep-from, as it
// would remove it otherwise (Y-47).
type YamnEncoder struct {
	Binary  string        // the yamn binary
	Timeout time.Duration // per call; 0 means DefaultTimeout
	Sender  string        // pinger.address: yamn's remailer.address, the From of the mail
	TmpDir  string        // where D is made; "" means os.TempDir()
	Log     *slog.Logger  // nil: discard
}

// Encode implements Encoder.
func (y *YamnEncoder) Encode(ctx context.Context, chain []Hop, plaintextMail []byte) (string, []byte, error) {
	fail := func(op string, err error) (string, []byte, error) {
		return "", nil, &EncodeError{Op: op, ExitCode: -1, Err: err}
	}
	keepFrom, err := y.check(chain, plaintextMail)
	if err != nil {
		return fail("check", err)
	}
	dir, err := y.setup(chain)
	if dir != "" {
		defer func() {
			if err := os.RemoveAll(dir); err != nil {
				y.log().Warn("removing yamn temp dir", "dir", dir, "err", err)
			}
		}()
	}
	if err != nil {
		return fail("setup", err)
	}

	timeout := y.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(tctx, y.Binary, y.args(dir, chain, keepFrom)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir, "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(plaintextMail)
	stdout := &capped{max: maxStdout}
	stderr := &capped{max: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()
	errText := clean(stderr.b.String())

	if runErr != nil {
		e := &EncodeError{Op: "run", ExitCode: -1, Stderr: errText, Err: runErr}
		switch {
		case ctx.Err() != nil:
			e.Err = ctx.Err()
		case errors.Is(tctx.Err(), context.DeadlineExceeded):
			e.Err = fmt.Errorf("%w after %s", ErrTimeout, timeout)
		default:
			var exit *exec.ExitError
			if errors.As(runErr, &exit) {
				e.ExitCode = exit.ExitCode()
			}
		}
		return "", nil, e
	}
	if stdout.over {
		return "", nil, &EncodeError{Op: "output", ExitCode: 0, Stderr: errText,
			Err: fmt.Errorf("more than %d bytes on stdout", maxStdout)}
	}
	m, err := oneMail(stdout.b.Bytes(), chain[0].Address)
	if err != nil {
		return "", nil, &EncodeError{Op: "output", ExitCode: 0, Stderr: errText, Err: err}
	}
	if errText != "" {
		y.log().Info("yamn stderr", "text", errText)
	}
	return chain[0].Address, m, nil
}

func (y *YamnEncoder) log() *slog.Logger {
	if y.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return y.Log
}

// check checks the call, and reports whether the mail has a From line
// (yamn removes it unless --keep-from is given, Y-47).
func (y *YamnEncoder) check(chain []Hop, plaintextMail []byte) (keepFrom bool, err error) {
	if y.Binary == "" {
		return false, errors.New("no yamn binary configured")
	}
	if !plainAddress(y.Sender) {
		return false, fmt.Errorf("bad sender address %q", y.Sender)
	}
	if len(chain) == 0 || len(chain) > maxChain {
		return false, fmt.Errorf("chain of %d hops", len(chain))
	}
	for _, h := range chain {
		if h.Address != h.Key.Address || h.KeyID != h.Key.KeyID || !replies.ValidAddress(h.Address) {
			return false, fmt.Errorf("hop %q: address or keyid doesn't match its key", h.Address)
		}
	}
	if len(plaintextMail) > MaxBody {
		return false, fmt.Errorf("%w: mail of %d bytes", ErrTooLarge, len(plaintextMail))
	}
	msg, err := mail.ReadMessage(bytes.NewReader(plaintextMail))
	if err != nil {
		return false, fmt.Errorf("mail: %w", err)
	}
	return msg.Header.Get("From") != "", nil
}

// plainAddress reports whether s is local@domain without anything that
// could break the yamn.yml or a header.
func plainAddress(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || len(s) > 254 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f || strings.IndexByte(`"'\<>(),;:[]`, c) >= 0 {
			return false
		}
	}
	return true
}

// setup makes D with pubring.mix and yamn.yml.  It returns D's path even
// on errors after D was made, so the caller can remove it.
func (y *YamnEncoder) setup(chain []Hop) (string, error) {
	ks := make([]replies.ParsedKey, len(chain))
	for i, h := range chain {
		ks[i] = h.Key
	}
	ring, err := output.Pubring(ks)
	if err != nil {
		return "", err
	}
	base := y.TmpDir
	if base == "" {
		base = os.TempDir()
	}
	if base, err = filepath.Abs(base); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(base, "yamn-ping-") // mode 0700
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "pubring.mix"), ring, 0600); err != nil {
		return dir, err
	}
	if err := os.WriteFile(filepath.Join(dir, "yamn.yml"), yamnConfig(dir, y.Sender), 0600); err != nil {
		return dir, err
	}
	return dir, nil
}

// yamnConfig returns the yamn.yml for D.  Every key exists in yamn's
// config/config.go (yamn master, PR #71); an unknown one would only be
// warned about and silently not apply.
//   - urls.fetch false, no URLs: never download a keyring (Y-49).
//   - urls.key_pinning off: yamn would hold a new or changed key and
//     refuse to encrypt to it, so a quarantined key could never be
//     proven (design §9.2).  Our key policy replaces pinning.
//   - stats.use_expired false: we never ping expired keys (addendum
//     2026-10-21).
//   - stats.num_copies 1, and mail.outfile so nothing could ever be sent
//     from D (the client only writes to stdout with --stdout anyway).
//   - every file in D, so nothing of a remailer on this host is touched
//     (design question 15).
func yamnConfig(dir, sender string) []byte {
	q := strconv.Quote
	f := func(name string) string { return q(filepath.Join(dir, name)) }
	return []byte("# Written by go-echolot for one ping, removed after it.\n" +
		"general:\n" +
		"  loglevel: warn\n" +
		"  logtofile: false\n" +
		"  logtojournal: false\n" +
		"files:\n" +
		"  pubring: " + f("pubring.mix") + "\n" +
		"  mlist2: " + f("mlist2.txt") + "\n" +
		"  pubkey: " + f("key.txt") + "\n" +
		"  secring: " + f("secring.mix") + "\n" +
		"  pooldir: " + f("pool") + "\n" +
		"  maildir: " + f("Maildir") + "\n" +
		"  idlog: " + f("idlog") + "\n" +
		"  chunkdb: " + f("chunkdb") + "\n" +
		"  logfile: " + f("yamn.log") + "\n" +
		"  dest_block: " + f("dest.blk") + "\n" +
		"  keypins: " + f("keypins.json") + "\n" +
		"urls:\n" +
		"  fetch: false\n" +
		"  pubring: \"\"\n" +
		"  mlist2: \"\"\n" +
		"  key_pinning: \"off\"\n" +
		"mail:\n" +
		"  outfile: true\n" +
		"remailer:\n" +
		"  address: " + q(sender) + "\n" +
		"stats:\n" +
		"  num_copies: 1\n" +
		"  use_expired: false\n")
}

// args returns yamn's arguments.  -l takes addresses, not nicks, so a
// nick can't be ambiguous (Y:keymgr/public.go:139-165).  --stdout never
// sends a dummy; --nodummy says so again.
func (y *YamnEncoder) args(dir string, chain []Hop, keepFrom bool) []string {
	addrs := make([]string, len(chain))
	for i, h := range chain {
		addrs[i] = h.Address
	}
	a := []string{"--config", filepath.Join(dir, "yamn.yml"), "--dir", dir,
		"-m", "--stdout", "-c", "1", "--nodummy"}
	if keepFrom {
		a = append(a, "--keep-from")
	}
	return append(a, "-l", strings.Join(addrs, ","))
}

// oneMail returns the single mail of yamn's mboxrd output (Y:mbox.go)
// after checking that it goes to firstHop.
func oneMail(out []byte, firstHop string) ([]byte, error) {
	mails := splitMbox(out)
	if len(mails) != 1 {
		return nil, fmt.Errorf("yamn wrote %d mails, want 1", len(mails))
	}
	msg, err := mail.ReadMessage(bytes.NewReader(mails[0]))
	if err != nil {
		return nil, fmt.Errorf("yamn's mail: %w", err)
	}
	to, err := mail.ParseAddress(msg.Header.Get("To"))
	if err != nil {
		return nil, fmt.Errorf("yamn's mail: To: %w", err)
	}
	if !strings.EqualFold(to.Address, firstHop) {
		return nil, fmt.Errorf("yamn's mail goes to %q, not to the first hop %q", to.Address, firstHop)
	}
	if !bytes.Contains(mails[0], []byte("\n-----BEGIN REMAILER MESSAGE-----\n")) {
		return nil, errors.New("yamn's mail has no remailer message")
	}
	return mails[0], nil
}

// splitMbox returns the mails of an mboxrd stream: each starts after a
// "From " line, one ">" is removed from ">From " lines, and the blank
// line that ends each entry is dropped.  Text before the first "From "
// line belongs to no mail.
func splitMbox(data []byte) [][]byte {
	var mails [][]byte
	var cur *bytes.Buffer
	finish := func() {
		if cur != nil {
			mails = append(mails, bytes.TrimSuffix(cur.Bytes(), []byte("\n")))
		}
	}
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "From ") {
			finish()
			cur = new(bytes.Buffer)
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(line, ">"), "From ") {
			line = line[1:]
		}
		cur.WriteString(line)
	}
	finish()
	return mails
}

// capped is a writer that keeps at most max bytes and notes the rest.
type capped struct {
	b    bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.b.Len(); len(p) > room {
		c.b.Write(p[:max(0, room)])
		c.over = true
	} else {
		c.b.Write(p)
	}
	return len(p), nil
}

// clean makes yamn's stderr fit for one log line:
// line breaks as " | ", no control characters.
func clean(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(" | ")
		case r < ' ' || r == 0x7f:
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
