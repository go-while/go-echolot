package output

// The HTML pages (design §7, §12.2 phase 3): index.html, mlist2.html,
// fromlines.html and thesaurus/index.html with the raw replies next to
// it, ported from Echolot's templates/*.html, Thesaurus.pm and
// Fromlines.pm.  Only list-it remailers appear; there are no private
// variants (§7.5).
//
// Everything a remailer sends (nicks, caps lines, From headers, replies)
// is untrusted.  html/template escapes it for its context; before that,
// clean replaces control and bidi characters and invalid UTF-8, and
// shortens overlong values.  The raw replies are published as .txt files
// only, never as HTML.

import (
	"bytes"
	"cmp"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-while/go-echolot/internal/fileutil"
	"github.com/go-while/go-echolot/internal/stats"
	"github.com/go-while/go-echolot/internal/store"
)

//go:embed templates/*.html templates/echolot.css
var templateFS embed.FS

var pageTemplates = template.Must(template.New("").Funcs(template.FuncMap{
	"iso":   func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	"day":   func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"clock": func(t time.Time) string { return t.UTC().Format("15:04") },
	"add":   func(a, b int) int { return a + b },
}).ParseFS(templateFS, "templates/*.html"))

// ThesaurusDir is the subdirectory of the results directory that holds
// the thesaurus index and the raw replies.
const ThesaurusDir = "thesaurus"

// ThesaurusKinds are the replies the thesaurus shows, in Echolot's column
// order (templates/thesaurusindex.html; yamn has no remailer-stats).
var ThesaurusKinds = []string{"conf", "help", "key", "adminkey"}

// maxShown is the most bytes of an untrusted value a page shows; longer
// values are cut and end in "…".
const maxShown = 1024

// Site is what the pages say about the pinger.
type Site struct {
	Name     string // [pinger] sitename
	Operator string // [pinger] operator_address
	Version  string // go-echolot's version; "" shows none
	// PingerKey is the fingerprint of the minisign key pinger.pub (phase
	// 4, §9.5).  "" leaves the index page's signing key section out.
	PingerKey string
}

// Remailer is a remailer for the thesaurus and From header pages.
type Remailer struct {
	ID      int    // store.Remailer.ID: names the thesaurus replies
	Nick    string // the conf's nick; "" leaves the remailer out
	Address string
	Caps    string // the conf's caps line
	ListIt  bool   // as Row.ListIt: has a conf, and ListIt(ShowIt, Caps)
	// Fromlines is store.State.Fromlines[Address]: with_from 0 or 1 to
	// what a ping showed.
	Fromlines map[int]store.Fromline
}

// Reply is a remailer's last reply of one kind, as the state directory's
// thesaurus keeps it (see ReadReplies).
type Reply struct {
	ID   int       // Remailer.ID
	Kind string    // one of ThesaurusKinds; others are ignored
	Time time.Time // when it was requested (the file's mtime)
	Body []byte
}

// Pages is the input of WriteHTML.
type Pages struct {
	Site          Site
	Rows          []Row    // as for WriteStats; only ListIt rows are shown
	Sections      Sections // as for WriteStats
	SortByLatency bool
	Remailers     []Remailer // all remailers; only ListIt ones are shown
	Replies       []Reply
	Meta          bool // also write .meta files (§7.2), as for WriteStats
}

// WriteHTML writes into dir (the public results directory) echolot.css,
// index.html, mlist2.html, fromlines.html, and thesaurus/index.html with
// thesaurus/<id>.<kind>.txt for each reply of a list-it remailer.  Raw
// replies no longer listed are removed.  Each file is written atomically;
// nothing is written if a page fails to render.
func WriteHTML(dir string, p Pages, now time.Time) error {
	r, err := render(p, now)
	if err != nil {
		return err
	}
	tdir := filepath.Join(dir, ThesaurusDir)
	if err := os.MkdirAll(tdir, 0o755); err != nil {
		return err
	}
	if _, err := writeChanged(filepath.Join(dir, "echolot.css"), r.css); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, raw := range r.raws {
		keep[raw.name] = true
		path := filepath.Join(tdir, raw.name)
		wrote, err := writeChanged(path, raw.data)
		if err != nil {
			return err
		}
		if wrote && !raw.time.IsZero() {
			// Last-Modified: when the reply was requested.
			if err := os.Chtimes(path, raw.time, raw.time); err != nil {
				return err
			}
		}
	}
	if err := writePage(tdir, "index.html", r.thesaurus, p.Meta, now); err != nil {
		return err
	}
	if err := removeStaleReplies(tdir, keep); err != nil {
		return err
	}
	for _, pg := range []struct {
		name string
		data []byte
	}{
		{"fromlines.html", r.fromlines},
		{"mlist2.html", r.mlist2},
		{"index.html", r.index},
	} {
		if err := writePage(dir, pg.name, pg.data, p.Meta, now); err != nil {
			return err
		}
	}
	return nil
}

// writePage writes a page, and its .meta file if meta is set.
func writePage(dir, name string, data []byte, meta bool, now time.Time) error {
	if _, err := writeChanged(filepath.Join(dir, name), data); err != nil {
		return err
	}
	if meta {
		return writeMeta(dir, name, now.Add(StatsMetaExpiry))
	}
	return nil
}

// writeChanged is writeIfChanged without the line length check, which is
// for the files yamn clients read.
func writeChanged(path string, data []byte) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	return true, fileutil.WriteAtomic(path, data, filePerm)
}

// rawName matches the names of the raw replies WriteHTML writes.
var rawName = regexp.MustCompile(`^[0-9]+\.[a-z]+\.txt$`)

// removeStaleReplies removes the raw replies in dir not in keep: those of
// remailers no longer listed, and replies that expired.
func removeStaleReplies(dir string, keep map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if n := e.Name(); rawName.MatchString(n) && !keep[n] {
			if err := os.Remove(filepath.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// ReadReplies reads the state directory's thesaurus (dir), where the
// daemon keeps each remailer's last reply of a kind as <id>.<kind>, with
// the request's time as mtime (E:Thesaurus.pm:40-58).  Other files are
// skipped; a missing dir has no replies.
func ReadReplies(dir string) ([]Reply, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var replies []Reply
	for _, e := range entries {
		idText, kind, _ := strings.Cut(e.Name(), ".")
		id, err := strconv.Atoi(idText)
		if !e.Type().IsRegular() || err != nil || id <= 0 || !slices.Contains(ThesaurusKinds, kind) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fi, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		replies = append(replies, Reply{ID: id, Kind: kind, Time: fi.ModTime().UTC(), Body: body})
	}
	return replies, nil
}

// rendered is what WriteHTML writes.
type rendered struct {
	css, index, mlist2, fromlines, thesaurus []byte
	raws                                     []raw
}

// raw is a raw reply as published.
type raw struct {
	name string
	time time.Time
	data []byte
}

// common is what every page's frame (templates/layout.html) shows.
type common struct {
	Site         Site
	Title        string
	Root         string // the results directory, relative to the page
	Up           bool
	Links        []link
	Generator    string
	Generated    string
	GeneratedISO string
	Operator     string
}

type link struct{ Href, Text string }

func render(p Pages, now time.Time) (*rendered, error) {
	css, err := templateFS.ReadFile("templates/echolot.css")
	if err != nil {
		return nil, err
	}
	rows := Public(p.Rows)
	if err := checkRows(rows); err != nil {
		return nil, err
	}
	rows = slices.Clone(rows)
	SortRows(rows, p.SortByLatency)

	site := Site{
		Name:      clean(p.Site.Name),
		Operator:  clean(p.Site.Operator),
		Version:   clean(p.Site.Version),
		PingerKey: clean(p.Site.PingerKey),
	}
	gen := "go-echolot"
	if site.Version != "" {
		gen += " " + site.Version
	}
	base := func(title, root string, up bool, links ...link) common {
		return common{
			Site: site, Title: title, Root: root, Up: up, Links: links,
			Generator:    gen,
			Generated:    date(now),
			GeneratedISO: now.UTC().Format(time.RFC3339),
			// Hidden from harvesters, as E:Tools.pm:241-242 does with
			// s/@/./, but still readable.
			Operator: strings.Replace(site.Operator, "@", " (at) ", 1),
		}
	}

	r := &rendered{css: css}
	if r.index, err = execute("index.html", indexPage(base("Remailer Reliability Stats", "./", false), rows)); err != nil {
		return nil, err
	}
	if r.mlist2, err = execute("mlist2.html", mlist2Page(base("Remailer Reliability Stats", "./", true,
		link{"mlist2.txt", "Plain text version"}), rows, p.Sections)); err != nil {
		return nil, err
	}
	listed := listedRemailers(p.Remailers)
	if r.fromlines, err = execute("fromlines.html", fromlinesPage(base("From Headers", "./", true), listed)); err != nil {
		return nil, err
	}
	tp, raws := thesaurusPage(base("Thesaurus", "../", true), listed, p.Replies)
	if r.thesaurus, err = execute("thesaurus.html", tp); err != nil {
		return nil, err
	}
	r.raws = raws
	return r, nil
}

func execute(name string, data any) ([]byte, error) {
	var b bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&b, name, data); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return b.Bytes(), nil
}

// listedRemailers are the list-it remailers with a nick, by nick, then
// address (E:Thesaurus.pm:115-117, E:Fromlines.pm:115-116), cleaned.
func listedRemailers(rems []Remailer) []Remailer {
	var out []Remailer
	for _, r := range rems {
		if r.ListIt && r.Nick != "" {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b Remailer) int {
		return cmp.Or(strings.Compare(a.Nick, b.Nick), strings.Compare(a.Address, b.Address))
	})
	return out
}

type indexData struct {
	common
	Total, Over98 int
}

// indexPage counts as E:Stats.pm:688-689.
func indexPage(c common, rows []Row) indexData {
	d := indexData{common: c, Total: len(rows)}
	for _, r := range rows {
		if r.Stats.Reliability >= 0.98 {
			d.Over98++
		}
	}
	return d
}

type mlist2Data struct {
	common
	Rows     []statRow
	Sections []section
	Caps     []string
}

type statRow struct{ Nick, LatentHist, Latent, UptimeHist, Uptime, Options string }

type section struct{ Head, Text string }

// mlist2Page shows what Mlist2 prints, field by field.
func mlist2Page(c common, rows []Row, sec Sections) mlist2Data {
	d := mlist2Data{common: c}
	for _, r := range rows {
		d.Rows = append(d.Rows, statRow{
			Nick:       clean(r.Nick),
			LatentHist: stats.LatencyHist(r.Stats.LatencyDay),
			Latent:     strings.TrimSpace(stats.MinHr(r.Stats.Latency, false)),
			UptimeHist: stats.UptimeHist(r.Stats.ReliabilityDay),
			Uptime:     fmt.Sprintf("%.1f%%", r.Stats.Reliability*100),
			Options:    stats.Options(r.Caps),
		})
	}
	for _, s := range []struct {
		head string
		text *string
	}{
		{"Groups of remailers sharing a machine or operator", sec.SameOp},
		{"Broken type-I remailer chains", sec.Broken1},
		{"Broken type-II remailer chains", sec.Broken2},
	} {
		if s.text != nil {
			d.Sections = append(d.Sections, section{s.head, strings.TrimRight(cleanText(*s.text), "\n")})
		}
	}
	for _, cp := range sortedCaps(rows) {
		d.Caps = append(d.Caps, clean(cp))
	}
	return d
}

type fromlinesData struct {
	common
	Default, UserSupplied []fromRow
}

type fromRow struct {
	Nick      string
	Available bool
	From      string
	Top, Bot  bool
	Seen      time.Time
}

// same reports whether two rows show the same (E:Fromlines.pm:101-111).
func (a fromRow) same(b fromRow) bool {
	return a.Available == b.Available && a.From == b.From && a.Top == b.Top && a.Bot == b.Bot
}

// fromlinesPage is E:Fromlines.pm:41-122: exits only; a user supplied
// From line is listed only where it differs from the default.  Echolot's
// middleman test is case sensitive; this one is mlist2's D option.
func fromlinesPage(c common, rems []Remailer) fromlinesData {
	d := fromlinesData{common: c}
	for _, r := range rems {
		if stats.Options(r.Caps)[0] == 'D' {
			continue
		}
		var rows [2]fromRow
		for wf := range rows {
			rows[wf].Nick = clean(r.Nick)
			if f, ok := r.Fromlines[wf]; ok {
				rows[wf] = fromRow{Nick: rows[wf].Nick, Available: true, From: clean(f.From),
					Top: f.DisclaimTop, Bot: f.DisclaimBot, Seen: f.LastUpdate}
			}
		}
		d.Default = append(d.Default, rows[0])
		if !rows[1].same(rows[0]) {
			d.UserSupplied = append(d.UserSupplied, rows[1])
		}
	}
	return d
}

type thesaurusData struct {
	common
	Kinds     []string
	Remailers []thesaurusRow
}

type thesaurusRow struct {
	Nick, Address string
	Cells         []cell // per ThesaurusKinds
}

type cell struct {
	Href string // "" : no reply
	Time time.Time
}

// thesaurusPage is E:Thesaurus.pm:61-138: the listed remailers with a
// reply, and the replies to publish.
func thesaurusPage(c common, rems []Remailer, replies []Reply) (thesaurusData, []raw) {
	byID := map[int][]Reply{}
	for _, rp := range replies {
		if slices.Contains(ThesaurusKinds, rp.Kind) {
			byID[rp.ID] = append(byID[rp.ID], rp)
		}
	}
	d := thesaurusData{common: c, Kinds: ThesaurusKinds}
	var raws []raw
	seen := map[int]bool{}
	for _, r := range rems {
		if seen[r.ID] || len(byID[r.ID]) == 0 {
			continue
		}
		seen[r.ID] = true
		row := thesaurusRow{Nick: clean(r.Nick), Address: clean(r.Address), Cells: make([]cell, len(ThesaurusKinds))}
		for _, rp := range byID[r.ID] {
			i := slices.Index(ThesaurusKinds, rp.Kind)
			if row.Cells[i].Href != "" && !rp.Time.After(row.Cells[i].Time) {
				continue // a duplicate; the newest wins
			}
			name := fmt.Sprintf("%d.%s.txt", r.ID, rp.Kind)
			row.Cells[i] = cell{Href: name, Time: rp.Time}
			raws = slices.DeleteFunc(raws, func(x raw) bool { return x.name == name })
			raws = append(raws, raw{name: name, time: rp.Time, data: cleanBody(rp.Body)})
		}
		d.Remailers = append(d.Remailers, row)
	}
	return d, raws
}

// clean makes an untrusted value safe to show on one line: invalid UTF-8,
// control characters and bidi controls become U+FFFD, tabs spaces, and
// it's cut to maxShown bytes.
func clean(s string) string {
	return cut(sanitize(s, false), maxShown)
}

// cleanText is clean for a text of several lines, uncut.
func cleanText(s string) string {
	return sanitize(s, true)
}

// cleanBody is a raw reply as published: CRLF as LF, and otherwise as
// cleanText, so a browser that sniffs gets nothing it could mistake for
// markup controls or another encoding.
func cleanBody(b []byte) []byte {
	return []byte(sanitize(string(b), true))
}

func sanitize(s string, lines bool) string {
	s = strings.ToValidUTF8(s, "�")
	if lines {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	return strings.Map(func(r rune) rune {
		switch {
		case lines && (r == '\n' || r == '\t'):
			return r
		case r == '\t':
			return ' '
		case r < 0x20, r >= 0x7f && r < 0xa0, isBidi(r):
			return utf8.RuneError
		}
		return r
	}, s)
}

// isBidi reports the invisible characters that reorder text, with which a
// nick could pass for another.
func isBidi(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
}

// cut shortens s to at most n bytes on a rune boundary, ending in "…".
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	n -= len("…")
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
