// Command mlistdiff compares two pingers' published files, for the
// side-by-side run of design §11-6: per remailer, the uptime and latency
// in mlist2.txt and the keyids in pubring.mix, with the rows outside the
// expected bounds marked.  With -state, run hourly, it also records when
// each pinger first listed each key, so the pickup of a key rotation can
// be compared.
//
//	mlistdiff [flags] OURS THEIRS
//
// OURS and THEIRS are a directory or an http(s) base URL that holds
// mlist2.txt and pubring.mix, e.g. /var/lib/go-echolot/results or
// https://www.mixmin.net/yamn/.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/replies"
)

const (
	maxFile      = 2 << 20 // per downloaded file
	fetchTimeout = 30 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now()))
}

// run returns the exit status: 0 all rows within the bounds, 1 some
// outside, 2 an error or bad usage.
func run(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("mlistdiff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	relMax := fs.Float64("rel", 2, "uptime: mark a difference of more than this many points")
	latPct := fs.Float64("lat", 10, "latency: mark a difference of more than this many percent ...")
	latMin := fs.Duration("latmin", 2*time.Minute, "... that is also more than this")
	statePath := fs.String("state", "", "JSON file that records when each pinger first listed each key (run hourly)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: mlistdiff [flags] OURS THEIRS")
		fmt.Fprintln(stderr, "OURS, THEIRS: a directory or http(s) base URL with mlist2.txt and pubring.mix")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}
	var sides [2]*side
	for i, src := range fs.Args() {
		s, err := load(src)
		if err != nil {
			fmt.Fprintln(stderr, "mlistdiff:", err)
			return 2
		}
		sides[i] = s
	}
	b := bounds{rel: *relMax, latPct: *latPct, latMin: *latMin}
	outside := report(stdout, sides[0], sides[1], b)
	if *statePath != "" {
		if err := rotations(stdout, *statePath, sides[0], sides[1], now); err != nil {
			fmt.Fprintln(stderr, "mlistdiff:", err)
			return 2
		}
	}
	if outside > 0 {
		return 1
	}
	return 0
}

// side is one pinger's files.
type side struct {
	src       string
	generated time.Time
	rows      map[string]row      // by remailer name
	keys      map[string][]string // remailer name -> keyids in pubring.mix
	keysErr   error               // pubring.mix couldn't be read
}

func load(src string) (*side, error) {
	s := &side{src: src}
	data, err := read(src, "mlist2.txt")
	if err != nil {
		return nil, err
	}
	if s.generated, s.rows, err = parseMlist2(data); err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	data, err = read(src, "pubring.mix")
	if err != nil {
		s.keysErr = err
		return s, nil
	}
	s.keys = map[string][]string{}
	for _, k := range replies.ParseKey(data).Keys {
		s.keys[k.Nick] = append(s.keys[k.Nick], k.KeyID)
	}
	for _, ids := range s.keys {
		slices.Sort(ids)
	}
	return s, nil
}

// read reads name from a directory or below a base URL.
func read(src, name string) ([]byte, error) {
	if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		return os.ReadFile(filepath.Join(src, name))
	}
	u := strings.TrimSuffix(src, "/") + "/" + name
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "go-echolot-mlistdiff")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFile+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	if len(data) > maxFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", u, maxFile)
	}
	return data, nil
}

type bounds struct {
	rel, latPct float64
	latMin      time.Duration
}

// report prints the comparison and returns how many rows are outside
// the bounds.
func report(w io.Writer, ours, theirs *side, b bounds) int {
	for _, s := range []struct {
		label string
		s     *side
	}{{"ours  ", ours}, {"theirs", theirs}} {
		var keys string
		if s.s.keysErr != nil {
			keys = "pubring.mix: " + s.s.keysErr.Error()
		} else {
			n := 0
			for _, ids := range s.s.keys {
				n += len(ids)
			}
			keys = fmt.Sprintf("%d keys", n)
		}
		fmt.Fprintf(w, "%s %s  generated %s, %d remailers, %s\n",
			s.label, s.s.src, s.s.generated.UTC().Format("2006-01-02 15:04 MST"), len(s.s.rows), keys)
	}
	if d := ours.generated.Sub(theirs.generated); d.Abs() > time.Hour {
		fmt.Fprintf(w, "note: the files were generated %s apart\n", d.Abs().Round(time.Minute))
	}
	fmt.Fprintln(w)

	names := map[string]bool{}
	for n := range ours.rows {
		names[n] = true
	}
	for n := range theirs.rows {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	slices.Sort(sorted)

	fmt.Fprintf(w, "  %-12s %7s %7s %6s  %6s %6s %5s  %s\n", "remailer", "uptime", "theirs", "Δ", "lat", "theirs", "Δ", "keys")
	outside := 0
	var onlyOurs, onlyTheirs []string
	for _, n := range sorted {
		o, okO := ours.rows[n]
		t, okT := theirs.rows[n]
		switch {
		case !okT:
			onlyOurs = append(onlyOurs, n)
			continue
		case !okO:
			onlyTheirs = append(onlyTheirs, n)
			continue
		}
		mark := " "
		dRel := o.uptime - t.uptime
		if math.Abs(dRel) > b.rel {
			mark = "!"
		}
		latD := "-"
		if o.latency != noLatency && t.latency != noLatency && t.latency > 0 {
			d := o.latency - t.latency
			pct := 100 * float64(d) / float64(t.latency)
			latD = fmt.Sprintf("%+.0f%%", pct)
			if math.Abs(pct) > b.latPct && d.Abs() > b.latMin {
				mark = "!"
			}
		}
		keys := keyDiff(ours, theirs, n)
		if keys != "same" && keys != "none" && keys != "" {
			mark = "!"
		}
		if mark == "!" {
			outside++
		}
		fmt.Fprintf(w, "%s %-12s %6.1f%% %6.1f%% %+6.1f  %6s %6s %5s  %s\n",
			mark, n, o.uptime, t.uptime, dRel, fmtLatency(o.latency), fmtLatency(t.latency), latD, keys)
	}
	fmt.Fprintln(w)
	if len(onlyOurs) > 0 {
		fmt.Fprintf(w, "only in ours: %s\n", strings.Join(onlyOurs, ", "))
	}
	if len(onlyTheirs) > 0 {
		fmt.Fprintf(w, "only in theirs: %s\n", strings.Join(onlyTheirs, ", "))
	}
	fmt.Fprintf(w, "outside the bounds: %d of %d (uptime Δ > %.1f points; latency Δ > %.0f%% and > %s; keys differ)\n",
		outside, len(sorted)-len(onlyOurs)-len(onlyTheirs), b.rel, b.latPct, b.latMin)
	return outside
}

// keyDiff compares the keyids both pubrings list for name: "same", a
// short description of the difference, or "" if a pubring is missing.
func keyDiff(ours, theirs *side, name string) string {
	if ours.keysErr != nil || theirs.keysErr != nil {
		return ""
	}
	o, t := ours.keys[name], theirs.keys[name]
	if slices.Equal(o, t) {
		if len(o) == 0 {
			return "none"
		}
		return "same"
	}
	return fmt.Sprintf("ours %s, theirs %s", short(o), short(t))
}

func short(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = id[:min(8, len(id))]
	}
	return strings.Join(s, "+")
}

func fmtLatency(d time.Duration) string {
	if d == noLatency {
		return "99:59"
	}
	m := int(d / time.Minute)
	if m < 60 {
		return fmt.Sprintf(":%02d", m)
	}
	return fmt.Sprintf("%d:%02d", m/60, m%60)
}

var errNoTable = errors.New("no remailer table in mlist2.txt")
