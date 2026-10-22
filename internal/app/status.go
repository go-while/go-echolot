package app

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/store"
)

// WriteStatus writes the operator's view of st (the status and keys
// commands, design §10.4): every remailer with its state and keys, then
// pending changes and suggestions.  With addr set, only that remailer.
// It reads only; the daemon may be running.
func WriteStatus(w io.Writer, st *store.State, now time.Time, requireProof bool, addr string) error {
	ew := &errWriter{w: w}
	addrs := slices.Sorted(maps.Keys(st.Remailers))
	if addr != "" {
		r := find(st, addr)
		if r == nil {
			return fmt.Errorf("%s is not a known remailer", addr)
		}
		addrs = []string{r.Address}
	}
	for _, a := range addrs {
		r := st.Remailers[a]
		nick := r.Nick
		if nick == "" {
			nick = "(no nick yet)"
		}
		ew.printf("%s %s  id %d  %s  showit=%s pingit=%s fetch=%s  ttl %d\n",
			nick, r.Address, r.ID, r.Status, onOff(r.ShowIt), onOff(r.PingIt), onOff(r.Fetch), r.TTL)
		if r.Conf != nil {
			ew.printf("  conf %s (asked %s)\n", r.Conf.Caps, r.Conf.LastUpdate.Format(time.RFC3339))
		}
		pub := keys.Publishable(r, now, requireProof)
		ks := slices.Collect(maps.Values(r.Keys))
		slices.SortFunc(ks, func(a, b *store.Key) int { return b.LastSeen.Compare(a.LastSeen) })
		for _, k := range ks {
			mark := " "
			if pub != nil && k.KeyID == pub.KeyID {
				mark = "*"
			}
			proven := "not proven"
			if keys.Proven(k) {
				proven = "proven " + k.ProvenAt.Format(time.RFC3339)
			}
			ew.printf("  %s key %s %s..%s %s, %s, first seen %s, last seen %s\n", mark, k.KeyID,
				k.Created, k.Expires, k.State, proven, k.FirstSeen.Format(time.RFC3339), k.LastSeen.Format(time.RFC3339))
		}
	}
	if addr == "" {
		if len(st.Pending) > 0 {
			ew.printf("\npending changes (approve or reject <address> [what]):\n")
		}
		for _, p := range st.Pending {
			state := ""
			if p.Rejected {
				state = " (rejected)"
			}
			ew.printf("  %s: %s %s -> %s since %s%s\n", p.Address, p.Kind, orNone(p.Old), p.New, p.Since.Format(time.RFC3339), state)
		}
		if len(st.Prospective) > 0 {
			ew.printf("\nsuggestions (add <address> to ping them):\n")
		}
		for _, a := range slices.Sorted(maps.Keys(st.Prospective)) {
			var why []string
			for _, s := range st.Prospective[a] {
				why = append(why, s.Reason)
			}
			ew.printf("  %s: %s\n", a, strings.Join(why, "; "))
		}
		ew.printf("\n* = published\n")
	}
	return ew.err
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// errWriter keeps the first write error.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, a...)
	}
}
