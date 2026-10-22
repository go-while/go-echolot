package output

import (
	"bytes"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/go-while/go-echolot/internal/stats"
	"github.com/go-while/go-echolot/internal/store"
)

var update = flag.Bool("update", false, "rewrite testdata/html")

var htmlNow = time.Date(2026, 10, 22, 13, 5, 0, 0, time.UTC)

func fp(v float64) *float64 { return &v }
func sp(s string) *string   { return &s }

func days(vs ...float64) []*float64 {
	out := make([]*float64, 12)
	for i, v := range vs {
		if v >= 0 {
			out[i] = fp(v)
		}
	}
	return out
}

// htmlInput is the fixed input of the golden pages: two listed exits,
// a listed middleman, one remailer not shown and one testing.
func htmlInput() Pages {
	const (
		alphaCaps  = `$remailer{"alpha"} = "<alpha@example.org> mix klen1000";`
		betaCaps   = `$remailer{"beta"} = "<beta@example.net> mix middle klen64";`
		gammaCaps  = `$remailer{"gamma"} = "<gamma@example.com> mix post";`
		hiddenCaps = `$remailer{"hidden"} = "<hidden@example.org> mix";`
		testCaps   = `$remailer{"tester"} = "<tester@example.org> mix testing";`
	)
	t := htmlNow.Add(-26 * time.Hour)
	return Pages{
		Site: Site{Name: "Test Pinger", Operator: "pinger@example.org", Version: "v0.3.0"},
		Rows: []Row{
			{Nick: "beta", Address: "beta@example.net", Caps: betaCaps, ListIt: true, Stats: stats.Result{
				Latency: fp(300), Reliability: 0.9999, LatencyDay: days(290, 310, 300), ReliabilityDay: days(1, 1, 1)}},
			{Nick: "alpha", Address: "alpha@example.org", Caps: alphaCaps, ListIt: true, Stats: stats.Result{
				Latency: fp(4000), Reliability: 0.955, LatencyDay: days(-1, 4000, 3900), ReliabilityDay: days(0.5, 0.95, 1)}},
			{Nick: "gamma", Address: "gamma@example.com", Caps: gammaCaps, ListIt: true, Stats: stats.Result{
				Reliability: 0, LatencyDay: days(), ReliabilityDay: days(0)}},
			{Nick: "hidden", Address: "hidden@example.org", Caps: hiddenCaps, ListIt: false, Stats: stats.Result{
				Latency: fp(60), Reliability: 1, LatencyDay: days(60), ReliabilityDay: days(1)}},
			{Nick: "tester", Address: "tester@example.org", Caps: testCaps, ListIt: ListIt(true, testCaps), Stats: stats.Result{
				Latency: fp(60), Reliability: 1, LatencyDay: days(60), ReliabilityDay: days(1)}},
		},
		Sections: Sections{SameOp: sp("alpha beta\n"), Broken1: sp(""), Broken2: sp("(alpha gamma)\n")},
		Remailers: []Remailer{
			{ID: 3, Nick: "gamma", Address: "gamma@example.com", Caps: gammaCaps, ListIt: true},
			{ID: 1, Nick: "alpha", Address: "alpha@example.org", Caps: alphaCaps, ListIt: true, Fromlines: map[int]store.Fromline{
				0: {LastUpdate: t, From: "From: Nobody <nobody@example.org>", DisclaimBot: true},
				1: {LastUpdate: t, From: "From: User Supplied <nobody@example.org>", DisclaimTop: true, DisclaimBot: true},
			}},
			{ID: 2, Nick: "beta", Address: "beta@example.net", Caps: betaCaps, ListIt: true, Fromlines: map[int]store.Fromline{
				0: {LastUpdate: t, From: "From: Middle <beta@example.net>"},
			}},
			{ID: 4, Nick: "hidden", Address: "hidden@example.org", Caps: hiddenCaps, ListIt: false, Fromlines: map[int]store.Fromline{
				0: {LastUpdate: t, From: "From: Hidden <hidden@example.org>"},
			}},
			{ID: 5, Nick: "tester", Address: "tester@example.org", Caps: testCaps, ListIt: ListIt(true, testCaps)},
			{ID: 6, Nick: "", Address: "noconf@example.org", ListIt: false},
		},
		Replies: []Reply{
			{ID: 1, Kind: "conf", Time: t, Body: []byte("Remailer-Type: yamn-0.2.8\r\n$remailer{\"alpha\"} = \"<alpha@example.org> mix klen1000\";\r\n")},
			{ID: 1, Kind: "key", Time: t.Add(time.Minute), Body: []byte("Here is the Mixmaster key:\n\n=-=-=-=-=-=-=-=-=-=-=-=\nalpha alpha@example.org 0123456789abcdef0123456789abcdef 4:0.2.8 E 2026-10-01 2027-01-29\n")},
			{ID: 2, Kind: "help", Time: t.Add(-48 * time.Hour), Body: []byte("This is the beta remailer.\n")},
			{ID: 2, Kind: "stats", Time: t, Body: []byte("not a yamn kind\n")},
			{ID: 4, Kind: "conf", Time: t, Body: []byte("Remailer-Type: hidden\n")},
			{ID: 5, Kind: "conf", Time: t, Body: []byte("Remailer-Type: tester\n")},
			{ID: 9, Kind: "conf", Time: t, Body: []byte("unknown remailer\n")},
		},
	}
}

// readTree returns the files under dir by slash path, without
// echolot.css (it's the embedded file as is).
func readTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if rel == "echolot.css" {
			return nil
		}
		data, err := os.ReadFile(path)
		files[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestHTMLGolden(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTML(dir, htmlInput(), htmlNow); err != nil {
		t.Fatal(err)
	}
	got := readTree(t, dir)
	golden := filepath.Join("testdata", "html")
	if *update {
		os.RemoveAll(golden)
		for name, data := range got {
			path := filepath.Join(golden, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := readTree(t, golden)
	for name, data := range want {
		if !bytes.Equal(got[name], data) {
			t.Errorf("%s differs from the golden file (go test -update to rewrite):\n%s", name, got[name])
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected file %s", name)
		}
	}
	css, err := os.ReadFile(filepath.Join(dir, "echolot.css"))
	if err != nil || !bytes.Contains(css, []byte("prefers-color-scheme: dark")) {
		t.Errorf("echolot.css: %v", err)
	}
}

// TestHTMLNotListed: a remailer not list-it appears nowhere.
func TestHTMLNotListed(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTML(dir, htmlInput(), htmlNow); err != nil {
		t.Fatal(err)
	}
	for name, data := range readTree(t, dir) {
		for _, s := range []string{"hidden", "tester", "noconf", "unknown remailer", "not a yamn kind"} {
			if bytes.Contains(data, []byte(s)) {
				t.Errorf("%s shows %q", name, s)
			}
		}
	}
	for _, name := range []string{"4.conf.txt", "5.conf.txt", "9.conf.txt", "2.stats.txt"} {
		if _, err := os.Stat(filepath.Join(dir, ThesaurusDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was written", name)
		}
	}
}

func TestHTMLPingerKey(t *testing.T) {
	dir := t.TempDir()
	p := htmlInput()
	p.Site.PingerKey = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
	if err := WriteHTML(dir, p, htmlNow); err != nil {
		t.Fatal(err)
	}
	index, _ := os.ReadFile(filepath.Join(dir, "index.html"))
	for _, s := range []string{`id="signing-key"`, `href="pinger.pub"`, p.Site.PingerKey} {
		if !bytes.Contains(index, []byte(s)) {
			t.Errorf("index.html lacks %q", s)
		}
	}
	golden, _ := os.ReadFile("testdata/html/index.html")
	if bytes.Contains(golden, []byte("signing-key")) || bytes.Contains(golden, []byte("pinger.pub")) {
		t.Error("the index without a key shows the signing key section")
	}
}

// hostile is what a malicious remailer could put into every field.
const hostile = "<script>alert(\"x\")</script>'\"&amp;<img src=x onerror=alert(1)>\x00\x1b[31m‮\x7f\x85"

func TestHTMLHostile(t *testing.T) {
	dir := t.TempDir()
	nick := `<script>alert(1)</script>` // passes checkRows: no space or control
	caps := `$remailer{"x"} = "<x@example.org> mix"; ` + hostile
	long := strings.Repeat("A<b>&", 40000)
	p := Pages{
		Site: Site{Name: hostile, Operator: hostile, Version: hostile},
		Rows: []Row{{Nick: nick, Address: "x@example.org", Caps: caps, ListIt: true,
			Stats: stats.Result{LatencyDay: days(), ReliabilityDay: days()}}},
		Sections: Sections{SameOp: sp(hostile + "\n" + hostile), Broken2: sp(hostile)},
		Remailers: []Remailer{{ID: 7, Nick: nick + hostile, Address: hostile, Caps: caps, ListIt: true,
			Fromlines: map[int]store.Fromline{0: {From: hostile + long, LastUpdate: htmlNow}, 1: {From: hostile}}}},
		Replies: []Reply{{ID: 7, Kind: "conf", Time: htmlNow, Body: []byte(hostile + "\r\n" + long + "\n")}},
	}
	if err := WriteHTML(dir, p, htmlNow); err != nil {
		t.Fatal(err)
	}
	files := readTree(t, dir)
	for name, data := range files {
		if strings.HasSuffix(name, ".txt") {
			continue
		}
		checkHTML(t, name, data)
		if bytes.Contains(bytes.ToLower(data), []byte("<script")) || bytes.Contains(data, []byte("<img")) {
			t.Errorf("%s: markup got through", name)
		}
		for _, c := range []string{"\x00", "\x1b", "\x7f", "\u0085", "‮"} {
			if bytes.Contains(data, []byte(c)) {
				t.Errorf("%s: contains %q", name, c)
			}
		}
		if len(data) > 64<<10 {
			t.Errorf("%s: %d bytes; the long From line wasn't cut", name, len(data))
		}
	}
	if !bytes.Contains(files["mlist2.html"], []byte("&lt;script&gt;alert(1)&lt;/script&gt;")) {
		t.Error("mlist2.html doesn't show the nick escaped")
	}
	body := files["thesaurus/7.conf.txt"]
	if !bytes.Contains(body, []byte("\n"+long+"\n")) {
		t.Error("the reply's long line is not kept")
	}
	for _, c := range []string{"\x00", "\x1b", "\r", "\x7f", "\u0085", "‮"} {
		if bytes.Contains(body, []byte(c)) {
			t.Errorf("reply contains %q", c)
		}
	}
}

// checkHTML parses a page and fails on anything active: scripts, event
// handlers, frames, and links that leave the results directory.
func checkHTML(t *testing.T, name string, data []byte) {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "iframe", "object", "embed", "img", "form", "base", "style":
				t.Errorf("%s: <%s> element", name, n.Data)
			}
			for _, a := range n.Attr {
				if strings.HasPrefix(a.Key, "on") || a.Key == "style" {
					t.Errorf("%s: attribute %s on <%s>", name, a.Key, n.Data)
				}
				if (a.Key == "href" || a.Key == "src") && (strings.Contains(a.Val, ":") || strings.HasPrefix(a.Val, "/")) {
					t.Errorf("%s: link %q", name, a.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
}

func TestHTMLSafeGolden(t *testing.T) {
	for name, data := range readTree(t, filepath.Join("testdata", "html")) {
		if strings.HasSuffix(name, ".html") {
			checkHTML(t, name, data)
		}
	}
}

func TestClean(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain", "plain"},
		{"a\tb\nc\r", "a b�c�"},
		{"\xff\xfe", "�"},
		{"x‮y", "x�y"},
		{"ünï", "ünï"},
	} {
		if got := clean(c.in); got != c.want {
			t.Errorf("clean(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	long := strings.Repeat("ä", maxShown)
	got := clean(long)
	if len(got) > maxShown || !strings.HasSuffix(got, "…") || !strings.HasPrefix(got, "ää") {
		t.Errorf("clean(long) = %d bytes, %q…", len(got), got[:10])
	}
	if got := cleanText("a\r\nb\tc\x00"); got != "a\nb\tc�" {
		t.Errorf("cleanText = %q", got)
	}
}

// TestHTMLStale: replies of a remailer that's no longer listed go, and
// unchanged files are left alone.
func TestHTMLStale(t *testing.T) {
	dir := t.TempDir()
	p := htmlInput()
	if err := WriteHTML(dir, p, htmlNow); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, ThesaurusDir, "1.conf.txt")
	fi, err := os.Stat(conf)
	if err != nil {
		t.Fatal(err)
	}
	if want := p.Replies[0].Time; !fi.ModTime().Equal(want) {
		t.Errorf("1.conf.txt mtime %v, want the request's %v", fi.ModTime(), want)
	}
	other := filepath.Join(dir, ThesaurusDir, "README")
	if err := os.WriteFile(other, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p.Remailers[1].ListIt = false // alpha
	if err := WriteHTML(dir, p, htmlNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1.conf.txt", "1.key.txt"} {
		if _, err := os.Stat(filepath.Join(dir, ThesaurusDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s is still there: %v", name, err)
		}
	}
	for _, name := range []string{"2.help.txt", "README"} {
		if _, err := os.Stat(filepath.Join(dir, ThesaurusDir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	index, _ := os.ReadFile(filepath.Join(dir, ThesaurusDir, "index.html"))
	if bytes.Contains(index, []byte("alpha")) {
		t.Error("the thesaurus still lists alpha")
	}
}

// TestHTMLAtomic: a reader never sees a partial page, no temporary file
// is left, and a failed render writes nothing.
func TestHTMLAtomic(t *testing.T) {
	dir := t.TempDir()
	p := htmlInput()
	if err := WriteHTML(dir, p, htmlNow); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			for _, name := range []string{"index.html", "mlist2.html", "fromlines.html", "thesaurus/index.html"} {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.HasPrefix(data, []byte("<!DOCTYPE html>")) || !bytes.HasSuffix(data, []byte("</html>\n")) {
					t.Errorf("%s: partial read (%d bytes), %v", name, len(data), err)
					return
				}
			}
		}
	}()
	for i := range 30 {
		p.Site.Name = strings.Repeat("x", i*100) // a new size each time
		if err := WriteHTML(dir, p, htmlNow.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Error(err)
		}
	}
	stop.Store(true)
	wg.Wait()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && strings.Contains(d.Name(), ".tmp-") {
			t.Errorf("temporary file %s left", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	empty := t.TempDir()
	bad := htmlInput()
	bad.Rows[0].Nick = "two words"
	if err := WriteHTML(empty, bad, htmlNow); err == nil {
		t.Error("a bad nick was accepted")
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Errorf("a failed render wrote %v", entries)
	}
}

func TestHTMLMeta(t *testing.T) {
	dir := t.TempDir()
	p := htmlInput()
	p.Meta = true
	if err := WriteHTML(dir, p, htmlNow); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html.meta", "mlist2.html.meta", "fromlines.html.meta", "thesaurus/index.html.meta"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != string(Meta(htmlNow.Add(StatsMetaExpiry))) {
			t.Errorf("%s: %q, %v", name, data, err)
		}
	}
}

func TestReadReplies(t *testing.T) {
	dir := t.TempDir()
	if r, err := ReadReplies(filepath.Join(dir, "missing")); r != nil || err != nil {
		t.Errorf("missing dir: %v, %v", r, err)
	}
	at := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	for _, name := range []string{"12.conf", "12.key", "3.adminkey", "3.bounce", "x.conf", "0.conf", ".12.conf.tmp-1", "4.help"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ReadReplies(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range got {
		names = append(names, string(r.Body))
		if !r.Time.Equal(at) || r.Body == nil || string(r.Body) != filepath.Base(string(r.Body)) {
			t.Errorf("%+v", r)
		}
	}
	slices.Sort(names)
	if want := []string{"12.conf", "12.key", "3.adminkey", "4.help"}; !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
}
