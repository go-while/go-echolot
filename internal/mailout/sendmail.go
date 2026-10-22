package mailout

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// sendmail's exit codes (sysexits.h) that say the message or an address
// is bad, so it's no use sending it again as it is.
const (
	exDataErr  = 65 // EX_DATAERR
	exNoUser   = 67 // EX_NOUSER
	exTempFail = 75 // EX_TEMPFAIL
)

var errKilled = errors.New("sendmail timeout")

// maxOutput bounds the sendmail output kept for the error.
const maxOutput = 1024

type sendmail struct {
	path    string
	timeout time.Duration
}

// NewSendmail returns a Mailer that runs "<path> -i -f <envelope> --
// <rcpt...>" (no shell) with the message on stdin, LF line ends.  The
// command is killed after timeout (0: 5 minutes).
//
// Exit status: 0 is success.  EX_DATAERR (65) and EX_NOUSER (67) are
// permanent: sendmail refused the message or an address.  Everything else
// is temporary: EX_TEMPFAIL (75), and also the other codes, a signal or
// the timeout, as they mean trouble on this machine (no queue, config,
// permissions), not a refusal by the remailer.  The MTA queues and
// retries; its later bounces come back to the VERP sender.
func NewSendmail(path string, timeout time.Duration) Mailer {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &sendmail{path: path, timeout: timeout}
}

func (s *sendmail) Send(ctx context.Context, m Mail) error {
	if err := m.check(); err != nil {
		return err
	}
	args := append([]string{"-i", "-f", m.EnvelopeFrom, "--"}, m.Rcpt...)
	ctx, cancel := context.WithTimeoutCause(ctx, s.timeout, errKilled)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.path, args...)
	cmd.Stdin = bytes.NewReader(toLF(m.Data))
	out := &boundedBuffer{max: maxOutput}
	cmd.Stdout = out
	cmd.Stderr = out
	// A child that keeps the output pipes open must not hold us up.
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if err == nil {
		return nil
	}
	e := &Error{Server: s.path, Op: "run"}
	var ee *exec.ExitError
	switch {
	case context.Cause(ctx) == errKilled:
		e.Err = fmt.Errorf("killed after %s", s.timeout)
	case ctx.Err() != nil:
		e.Err = context.Cause(ctx)
	case errors.As(err, &ee) && ee.Exited():
		code := ee.ExitCode()
		e.Permanent = code == exDataErr || code == exNoUser
		e.Err = fmt.Errorf("exit status %d", code)
		if code == exTempFail {
			e.Err = fmt.Errorf("exit status %d (temporary failure)", code)
		}
	default:
		e.Err = err
	}
	if msg := out.text(); msg != "" {
		e.Err = fmt.Errorf("%w: %s", e.Err, msg)
	}
	return e
}

// boundedBuffer keeps the first max bytes written to it.
type boundedBuffer struct {
	max int
	buf []byte
	cut bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.max - len(b.buf); room > 0 {
		if len(p) > room {
			b.buf = append(b.buf, p[:room]...)
			b.cut = true
		} else {
			b.buf = append(b.buf, p...)
		}
	} else if len(p) > 0 {
		b.cut = true
	}
	return len(p), nil
}

// text returns the output on one line, control characters as spaces.
func (b *boundedBuffer) text() string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, string(b.buf))
	s = strings.Join(strings.Fields(s), " ")
	if b.cut && s != "" {
		s += " ..."
	}
	return s
}
