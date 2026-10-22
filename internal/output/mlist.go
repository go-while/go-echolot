package output

import (
	"bytes"
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
	"github.com/go-while/go-echolot/internal/stats"
)

// StatsMetaExpiry is how far ahead the .meta files of the stats lists
// expire: Echolot's buildstats (E:Config.pm:106, E:Stats.pm:311-315).
const StatsMetaExpiry = 5 * time.Minute

// Row is one remailer in mlist2.txt and mlist.txt.  Echolot lists every
// address that has a mix key and a conf (E:Stats.pm:486-494); the caller
// passes only remailers with a conf.
type Row struct {
	Nick    string // the conf's nick
	Address string // only breaks ties between equal nicks
	Caps    string // the conf's caps line: $remailer{"nick"} = "<addr> ...";
	ListIt  bool   // in the public lists too; see ListIt
	Stats   stats.Result
}

// ListIt reports whether a remailer goes into the public lists, as
// Echolot's list-it (E:Stats.pm:491): shown, and no "testing" in its caps.
func ListIt(showIt bool, caps string) bool {
	return showIt && !testingCaps.MatchString(caps)
}

// Public returns the rows with ListIt set, in their order.
func Public(rows []Row) []Row {
	var pub []Row
	for _, r := range rows {
		if r.ListIt {
			pub = append(pub, r)
		}
	}
	return pub
}

// Sections are the optional texts between the rows and the capabilities.
// nil leaves a section out; an empty text prints its heading alone, as
// Echolot does for broken chains when chain pings are on (§7.3).
type Sections struct {
	SameOp  *string // sameop.txt
	Broken1 *string // broken type-I chains
	Broken2 *string // broken type-II chains
}

// text is the sections as E:Stats.pm:410-412 and 333-335 print them.
// Echolot interpolates the texts into a sprintf format, so a '%' in them
// would be mangled there; here they go in verbatim.
func (s Sections) text() string {
	var b strings.Builder
	for _, sec := range []struct {
		head string
		text *string
	}{
		{"Groups of remailers sharing a machine or operator:", s.SameOp},
		{"Broken type-I remailer chains:", s.Broken1},
		{"Broken type-II remailer chains:", s.Broken2},
	} {
		if sec.text != nil {
			b.WriteString("\n" + sec.head + "\n" + *sec.text + "\n")
		}
	}
	return b.String()
}

// SortRows sorts rows as E:Stats.pm:498-504: reliability descending, then
// median latency ascending if byLatency (no data counts as 9999 s), then
// nick byte-wise, then address.
func SortRows(rows []Row, byLatency bool) {
	lat := func(r Row) float64 {
		if r.Stats.Latency == nil {
			return 9999
		}
		return *r.Stats.Latency
	}
	slices.SortStableFunc(rows, func(a, b Row) int {
		if c := cmp.Compare(b.Stats.Reliability, a.Stats.Reliability); c != 0 {
			return c
		}
		if byLatency {
			if c := cmp.Compare(lat(a), lat(b)); c != 0 {
				return c
			}
		}
		if c := strings.Compare(a.Nick, b.Nick); c != 0 {
			return c
		}
		return strings.Compare(a.Address, b.Address)
	})
}

// pad left-justifies s[:n] in n bytes, as Perl's "%-ns" of substr(s, 0,
// n) on byte strings.
func pad(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}

// date is E:Stats.pm:48-58 make_date.
func date(t time.Time) string {
	return t.UTC().Format("Mon 02 Jan 2006 15:04:05 GMT")
}

// Mlist2 returns mlist2.txt for rows, in their order (see SortRows), as
// E:Stats.pm:390-423 build_list2 (§7.3).
func Mlist2(rows []Row, sec Sections, generated time.Time) []byte {
	var b bytes.Buffer
	b.WriteString("Stats-Version: 2.0\n")
	b.WriteString("Generated: " + date(generated) + "\n")
	b.WriteString("Mixmaster    Latent-Hist   Latent  Uptime-Hist   Uptime  Options\n")
	b.WriteString(strings.Repeat("-", 72) + "\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s %s %6s   %s  %5.1f%%  %s\n",
			pad(r.Nick, 12),
			pad(stats.LatencyHist(r.Stats.LatencyDay), 12),
			stats.MinHr(r.Stats.Latency, false),
			pad(stats.UptimeHist(r.Stats.ReliabilityDay), 12),
			r.Stats.Reliability*100,
			stats.Options(r.Caps))
	}
	b.WriteString(sec.text())
	b.WriteString("\n\n\nRemailer-Capabilities:\n\n")
	for _, c := range sortedCaps(rows) {
		b.WriteString(c + "\n")
	}
	return b.Bytes()
}

// sortedCaps are the caps lines of rows, sorted byte-wise.
func sortedCaps(rows []Row) []string {
	caps := make([]string, len(rows))
	for i, r := range rows {
		caps[i] = r.Caps
	}
	slices.Sort(caps)
	return caps
}

// Mlist returns mlist.txt for rows, in their order, as E:Stats.pm:330-354
// build_mlist1 (§7.4).
func Mlist(rows []Row, sec Sections, generated time.Time) []byte {
	var b bytes.Buffer
	b.WriteString(sec.text())
	b.WriteString("Last update: " + date(generated) + "\n")
	b.WriteString("mixmaster           history  latency  uptime\n")
	b.WriteString(strings.Repeat("-", 44) + "\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%s %s %8s %6.2f%%\n",
			pad(r.Nick, 14),
			pad(stats.LatencyHist1(r.Stats.LatencyDay), 12),
			stats.MinHr(r.Stats.Latency, true),
			r.Stats.Reliability*100)
	}
	return b.Bytes()
}

// checkRows refuses what would break a row's fields: yamn splits a row
// on whitespace, and a newline would end it.
func checkRows(rows []Row) error {
	for _, r := range rows {
		if r.Nick == "" || strings.ContainsFunc(r.Nick, func(c rune) bool { return c <= ' ' || c == 0x7f }) {
			return fmt.Errorf("bad nick %q", r.Nick)
		}
		if strings.ContainsAny(r.Caps, "\r\n") {
			return fmt.Errorf("%s: newline in caps", r.Nick)
		}
	}
	return nil
}

// WriteStats writes mlist2.txt and mlist.txt for rows into dir, sorted by
// SortRows, and their .meta files (now + StatsMetaExpiry) if meta is set.
// Unlike the keyrings they're rewritten every time: Generated: must
// advance (§4.2).  Nothing is written if a check fails.  Call it once with
// all rows for the private directory and once with Public(rows) for the
// public one (E:Stats.pm:683-687).  Each file is signed with sign after
// it's written (nil: none).
func WriteStats(dir string, rows []Row, sec Sections, now time.Time, sortByLatency, meta bool, sign SignFunc) error {
	if err := checkRows(rows); err != nil {
		return err
	}
	rows = slices.Clone(rows)
	SortRows(rows, sortByLatency)
	files := []struct {
		name string
		data []byte
	}{
		{"mlist2.txt", Mlist2(rows, sec, now)},
		{"mlist.txt", Mlist(rows, sec, now)},
	}
	for _, f := range files {
		if err := checkLines(f.name, f.data); err != nil {
			return err
		}
	}
	for _, f := range files {
		if err := fileutil.WriteAtomic(filepath.Join(dir, f.name), f.data, filePerm); err != nil {
			return err
		}
		if err := writeSignature(dir, f.name, f.data, sign); err != nil {
			return err
		}
		if meta {
			if err := writeMeta(dir, f.name, now.Add(StatsMetaExpiry)); err != nil {
				return err
			}
		}
	}
	return nil
}
