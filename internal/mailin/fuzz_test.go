package mailin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/token"
)

// FuzzScan feeds arbitrary bytes as a mail file through the scanner.  It
// must not panic, and the file must end handled (gone) or moved to the
// errors directory: the handler always succeeds.
func FuzzScan(f *testing.F) {
	key := addr(f, token.KindKey, 3, t0.Add(-time.Hour))
	bounce := addr(f, token.KindBounce, 3, t0.Add(-time.Hour))
	f.Add([]byte(reply(key)))
	f.Add([]byte(postfixDSN("pinger@pinger.example.org", bounce, key)))
	f.Add([]byte("From x\nTo: " + key + "\r\n\r\nb"))
	f.Add([]byte("To: a\n b\n\tc\n\n"))
	f.Add([]byte("\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		e := newEnv(t)
		p := filepath.Join(e.maildir, "new", "m")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := e.s.Scan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if exists(p) || res.Handled+res.Rejected != 1 || res.Handled != len(e.h.calls) {
			t.Fatalf("result %+v, still there %v, calls %d", res, exists(p), len(e.h.calls))
		}
		if res.Rejected == 1 && !exists(filepath.Join(e.errors, "m")) {
			t.Fatal("rejected but not in the errors directory")
		}
	})
}
