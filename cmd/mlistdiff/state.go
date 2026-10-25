package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"
)

// keep is how long a key nobody lists any more stays in the state file.
const keep = 14 * 24 * time.Hour

// seen is when each pinger first and last listed a key.
type seen struct {
	OursFirst   time.Time `json:"ours_first,omitzero"`
	TheirsFirst time.Time `json:"theirs_first,omitzero"`
	Last        time.Time `json:"last"`
}

// rotations updates the state file at path with the keys both pubrings
// list now and prints, for each key first listed within the last 14 days
// by one pinger before the other, which one and by how much.
func rotations(w io.Writer, path string, ours, theirs *side, now time.Time) error {
	if ours.keysErr != nil || theirs.keysErr != nil {
		fmt.Fprintln(w, "\nrotations: skipped, a pubring.mix is missing")
		return nil
	}
	st := map[string]*seen{} // "<remailer> <keyid>"
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(data, &st); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	now = now.UTC().Truncate(time.Second)
	mark := func(keys map[string][]string, first func(*seen) *time.Time) {
		for name, ids := range keys {
			for _, id := range ids {
				k := name + " " + id
				s := st[k]
				if s == nil {
					s = &seen{}
					st[k] = s
				}
				if f := first(s); f.IsZero() {
					*f = now
				}
				s.Last = now
			}
		}
	}
	mark(ours.keys, func(s *seen) *time.Time { return &s.OursFirst })
	mark(theirs.keys, func(s *seen) *time.Time { return &s.TheirsFirst })
	for k, s := range st {
		if now.Sub(s.Last) > keep {
			delete(st, k)
		}
	}
	out, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	var lines []string
	for k, s := range st {
		first := s.OursFirst
		if first.IsZero() || (!s.TheirsFirst.IsZero() && s.TheirsFirst.Before(first)) {
			first = s.TheirsFirst
		}
		if now.Sub(first) > keep {
			continue
		}
		name, id, _ := strings.Cut(k, " ")
		var d string
		switch {
		case s.OursFirst.IsZero():
			d = "only theirs so far"
		case s.TheirsFirst.IsZero():
			d = "only ours so far"
		case s.OursFirst.Equal(s.TheirsFirst):
			continue // both in the same run: nothing to compare
		case s.OursFirst.Before(s.TheirsFirst):
			d = "ours first by " + s.TheirsFirst.Sub(s.OursFirst).String()
		default:
			d = "theirs first by " + s.OursFirst.Sub(s.TheirsFirst).String()
		}
		lines = append(lines, fmt.Sprintf("  %-12s %s  ours %s  theirs %s  %s",
			name, id[:min(8, len(id))], stamp(s.OursFirst), stamp(s.TheirsFirst), d))
	}
	slices.Sort(lines)
	fmt.Fprintf(w, "\nkeys one pinger listed before the other, last %d days (state %s):\n", int(keep.Hours()/24), path)
	if len(lines) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return nil
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "-               "
	}
	return t.Format("2006-01-02 15:04")
}
