package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func journal(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "pings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPings(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	a, b := "a@example.org", "b@example.org"
	p1, _ := s.NewPing(a, "k1", false, t0.Add(500*time.Millisecond)) // stored in whole seconds
	p2, _ := s.NewPing(a, "k2", true, t0.Add(time.Hour))
	p3, _ := s.NewPing(a, "k1", false, t0.Add(2*time.Hour))
	p4, _ := s.NewPing(b, "k9", false, t0.Add(time.Hour))
	p5, _ := s.NewPing(a, "k1", false, t0.Add(3*time.Hour))
	if p1.ID != 1 || p5.ID != 5 || !p1.Sent.Equal(t0) || p1.Status != PingOut {
		t.Fatalf("NewPing: %+v %+v", p1, p5)
	}
	got, news, err := s.PingDone(p2.ID, t0.Add(90*time.Minute), 1800)
	if err != nil || !news || got.Addr != a || got.KeyID != "k2" {
		t.Errorf("PingDone: %+v %v %v", got, news, err)
	}
	if _, news, _ := s.PingDone(p2.ID, t0.Add(2*time.Hour), 1); news {
		t.Error("second PingDone is news")
	}
	if _, news, _ := s.PingDone(99, t0, 1); news {
		t.Error("PingDone of an unknown ping is news")
	}
	if err := s.PingAborted(p3.ID, "smtp: refused"); err != nil {
		t.Fatal(err)
	}
	s.PingAborted(p2.ID, "late abort") // ignored: p2 is back
	s.PingAborted(p5.ID, "abort")
	s.PingDone(p5.ID, t0.Add(4*time.Hour), 3600) // a done after an abort counts
	s.NewPing(a, "k1", false, t0.Add(-time.Hour))

	check := func(s *Store) {
		t.Helper()
		out, done := s.Pings(a, t0) // strictly after t0: p1 is out
		if len(out) != 0 {
			t.Errorf("out: %+v", out)
		}
		if len(done) != 2 || done[0].ID != p2.ID || done[1].ID != p5.ID ||
			done[0].Latency != 1800 || !done[0].Received.Equal(t0.Add(90*time.Minute)) || !done[0].WithFrom {
			t.Errorf("done: %+v", done)
		}
		out, _ = s.Pings(a, t0.Add(-2*time.Hour))
		if len(out) != 2 || out[0].ID != 6 || out[1].ID != p1.ID {
			t.Errorf("out since -2h: %+v", out)
		}
		if p, ok := s.Ping(p3.ID); !ok || p.Status != PingAborted || p.Err != "smtp: refused" {
			t.Errorf("aborted: %+v", p)
		}
		if out, _ := s.Pings(b, time.Time{}); len(out) != 1 || out[0].ID != p4.ID {
			t.Errorf("b: %+v", out)
		}
	}
	check(s)
	s.Close()
	s = open(t, dir)
	check(s)
	if p, _ := s.NewPing(a, "k1", false, t0); p.ID != 7 {
		t.Errorf("next ID after reopen: %d", p.ID)
	}
}

func TestPingArgs(t *testing.T) {
	s := open(t, t.TempDir())
	if _, err := s.NewPing("", "k", false, t0); err == nil {
		t.Error("no address")
	}
	if _, err := s.NewPing("a@example.org", "k", false, time.Time{}); err == nil {
		t.Error("zero time")
	}
	p, _ := s.NewPing("a@example.org", "k", false, t0)
	if _, _, err := s.PingDone(p.ID, time.Time{}, 1); err == nil {
		t.Error("PingDone at zero time")
	}
}

// TestJournalFormat checks the lines against the design's example (§5.2).
func TestJournalFormat(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	sent := time.Unix(1792560000, 0)
	p, _ := s.NewPing("yamn@mixmin.net", "a1b2", false, sent)
	s.PingDone(p.ID, sent.Add(1234*time.Second), 1234)
	q, _ := s.NewPing("yamn@mixmin.net", "a1b2", true, sent)
	s.PingAborted(q.ID, "smtp: <refused> & gone")
	r, _ := s.NewPing("yamn@mixmin.net", "a1b2", false, sent)
	s.PingDone(r.ID, sent, 0)
	c, _ := s.AddPing(Ping{Addr: "yamn@mixmin.net", KeyID: "a1b2", Counted: true, Sent: sent})
	want := `{"ev":"out","id":1,"addr":"yamn@mixmin.net","key":"a1b2","wf":0,"sent":1792560000}
{"ev":"done","id":1,"lat":1234,"rcv":1792561234}
{"ev":"out","id":2,"addr":"yamn@mixmin.net","key":"a1b2","wf":1,"sent":1792560000}
{"ev":"abort","id":2,"err":"smtp: <refused> & gone"}
{"ev":"out","id":3,"addr":"yamn@mixmin.net","key":"a1b2","wf":0,"sent":1792560000}
{"ev":"done","id":3,"lat":0,"rcv":1792560000}
{"ev":"out","id":4,"addr":"yamn@mixmin.net","key":"a1b2","wf":0,"sent":1792560000,"pub":1}
`
	if got := journal(t, dir); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	s.Close()
	s = open(t, dir)
	if p, _ := s.Ping(c.ID); !p.Counted {
		t.Error("Counted lost on reopen")
	}
	if p, _ := s.Ping(r.ID); p.Counted {
		t.Error("NewPing counted")
	}
	s.Compact(sent.Add(-time.Hour))
	s.Close()
	s = open(t, dir)
	if p, _ := s.Ping(c.ID); !p.Counted {
		t.Error("Counted lost in compaction")
	}
}

// TestJournalTruncatedTail is a crash in the middle of an append: the
// incomplete last line is cut off, and appends continue on a new line.
func TestJournalTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	s.NewPing("a@example.org", "k", false, t0)
	s.Close()
	path := filepath.Join(dir, "pings.jsonl")
	good := journal(t, dir)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"ev":"out","id":2,"addr":"a@ex`)
	f.Close()

	log, buf := logBuffer()
	s, err := Open(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !strings.Contains(buf.String(), "incomplete last line") {
		t.Errorf("not logged: %s", buf)
	}
	if got := journal(t, dir); got != good {
		t.Errorf("not truncated:\n%s", got)
	}
	if p, _ := s.NewPing("a@example.org", "k", false, t0); p.ID != 2 {
		t.Errorf("ID %d", p.ID)
	}
	s.Close()
	_, buf = logBuffer()
	s, _ = Open(dir, log)
	defer s.Close()
	if out, _ := s.Pings("a@example.org", time.Time{}); len(out) != 2 || buf.Len() != 0 {
		t.Errorf("after recovery: %+v, log %s", out, buf)
	}
}

func TestJournalBadLines(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`{"ev":"out","id":1,"addr":"a@example.org","key":"k","wf":0,"sent":1792560000}`,
		`garbage`,
		`{"ev":"out","id":2,"addr":"a@example.org","key":"k","sent":1792560000}`,        // no wf
		`{"ev":"out","id":1,"addr":"b@example.org","key":"k","wf":0,"sent":1792560000}`, // id 1 again
		`{"ev":"sent","id":3}`,                                                               // unknown event
		`{"ev":"done","id":1,"rcv":1792560100}`,                                              // no lat
		`{"ev":"done","id":1,"lat":100,"rcv":1792560100,"x":1}`,                              // unknown field
		`{"ev":"out","id":4,"addr":"a@example.org","key":"k","wf":1,"sent":1792560000}`,      // good
		`{"ev":"done","id":4,"lat":100,"rcv":1792560100}`,                                    // good
		`{"ev":"done","id":77,"lat":100,"rcv":1792560100}`,                                   // unknown ping: ignored quietly
		`{"ev":"abort","id":4,"err":"too late"}`,                                             // after done: ignored quietly
		`{"ev":"next","id":10}`,                                                              // good
		`{"ev":"out","id":0,"addr":"a@example.org","key":"k","wf":0,"sent":1792560000}`,      // id 0
		`{"ev":"out","id":5,"addr":"a@example.org","key":"k","wf":0,"sent":-1}`,              // bad time
		`{"ev":"out","id":6,"addr":"a@example.org","key":"","wf":0,"sent":1792560000}`,       // no key
		`{"ev":"done","id":1,"lat":5,"rcv":1792560100} {"ev":"done","id":1,"lat":5,"rcv":1}`, // two on a line
	}
	if err := os.WriteFile(filepath.Join(dir, "pings.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log, buf := logBuffer()
	s, err := Open(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n := strings.Count(buf.String(), "skipping a bad line"); n != 10 {
		t.Errorf("%d bad lines logged, want 10:\n%s", n, buf)
	}
	out, done := s.Pings("a@example.org", time.Time{})
	if len(out) != 1 || out[0].ID != 1 || len(done) != 1 || done[0].ID != 4 {
		t.Errorf("out %+v done %+v", out, done)
	}
	if p, _ := s.NewPing("a@example.org", "k", false, t0); p.ID != 10 {
		t.Errorf("next ID %d, want 10", p.ID)
	}
}

// TestJournalWriteFails checks that a write that fails part way is cut
// off, so the journal stays readable.
func TestJournalWriteFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	s.NewPing("a@example.org", "k", false, t0)
	before := journal(t, dir)
	journalWrite = func(f *os.File, b []byte) (int, error) {
		n, _ := f.Write(b[:len(b)/2])
		return n, errors.New("disk full")
	}
	_, err := s.NewPing("a@example.org", "k", false, t0)
	journalWrite = (*os.File).Write
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatal(err)
	}
	if got := journal(t, dir); got != before {
		t.Errorf("partial write kept:\n%s", got)
	}
	if out, _ := s.Pings("a@example.org", time.Time{}); len(out) != 1 {
		t.Errorf("failed ping in memory: %+v", out)
	}
	if p, err := s.NewPing("a@example.org", "k", false, t0); err != nil || p.ID != 3 {
		t.Errorf("next ping: %+v, %v", p, err)
	}
	s.Close()
	s = open(t, dir)
	if out, _ := s.Pings("a@example.org", time.Time{}); len(out) != 2 {
		t.Errorf("after reopen: %+v", out)
	}
}

func TestCompact(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	a := "a@example.org"
	for i := range 6 {
		p, _ := s.NewPing(a, "k", i%2 == 1, t0.Add(time.Duration(i)*24*time.Hour))
		switch i % 3 {
		case 1:
			s.PingDone(p.ID, p.Sent.Add(time.Hour), 3600)
		case 2:
			s.PingAborted(p.ID, "x")
		}
	}
	all := func(s *Store) []Ping {
		var ps []Ping
		for id := uint64(1); id <= 6; id++ {
			if p, ok := s.Ping(id); ok {
				ps = append(ps, p)
			}
		}
		return ps
	}
	want := all(s)[3:]
	if err := s.Compact(t0.Add(3 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := all(s); !reflect.DeepEqual(got, want) {
		t.Errorf("after Compact:\n%+v\nwant\n%+v", got, want)
	}
	if j := journal(t, dir); !strings.HasPrefix(j, `{"ev":"next","id":7}`+"\n"+`{"ev":"out","id":4,`) || strings.Count(j, "\n") != 6 {
		t.Errorf("journal:\n%s", j)
	}
	// Appends go to the new journal.
	s.NewPing(a, "k", false, t0.Add(10*24*time.Hour))
	s.Close()
	s = open(t, dir)
	if got := all(s); !reflect.DeepEqual(got, want) {
		t.Errorf("after reopen:\n%+v", got)
	}
	// All pings expire: IDs still aren't reused.
	if err := s.Compact(t0.Add(30 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open(t, dir)
	if p, _ := s.NewPing(a, "k", false, t0); p.ID != 8 {
		t.Errorf("ID after everything expired: %d, want 8", p.ID)
	}
}

func TestCompactFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	s.NewPing("a@example.org", "k", false, t0)
	before := journal(t, dir)
	fail := true
	countWrites(t, &fail)
	if err := s.Compact(t0.Add(time.Hour)); err == nil {
		t.Fatal("no error")
	}
	if _, ok := s.Ping(1); !ok {
		t.Error("ping forgotten after a failed Compact")
	}
	if p, err := s.NewPing("a@example.org", "k", false, t0); err != nil || p.ID != 2 {
		t.Errorf("NewPing after a failed Compact: %+v, %v", p, err)
	}
	if got := journal(t, dir); !strings.HasPrefix(got, before) {
		t.Errorf("journal changed:\n%s", got)
	}
}

func TestClosed(t *testing.T) {
	s := open(t, t.TempDir())
	p, _ := s.NewPing("a@example.org", "k", false, t0)
	s.Close()
	if _, err := s.NewPing("a@example.org", "k", false, t0); err == nil {
		t.Error("NewPing after Close")
	}
	if _, _, err := s.PingDone(p.ID, t0, 1); err == nil {
		t.Error("PingDone after Close")
	}
	if err := s.Compact(t0); err == nil {
		t.Error("Compact after Close")
	}
}

// TestCompactDirSyncFails: the compacted journal was renamed into place,
// so the store must append to it, not to the old, unlinked one.
func TestCompactDirSyncFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	s.NewPing("a@example.org", "k", false, t0)
	s.NewPing("a@example.org", "k", false, t0.Add(2*time.Hour))
	dirSyncFails(t)
	if err := s.Compact(t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	writeFile = origWriteFile
	p, err := s.NewPing("a@example.org", "k", false, t0.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s = open(t, dir)
	if _, ok := s.Ping(p.ID); !ok {
		t.Errorf("ping %d written after Compact is lost:\n%s", p.ID, journal(t, dir))
	}
	if _, ok := s.Ping(1); ok {
		t.Error("compacted ping is back")
	}
}

// TestJournalTruncateFails: a failed write that can't be cut off stops
// all further writes, and the next Open drops the partial line.
func TestJournalTruncateFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	s.NewPing("a@example.org", "k", false, t0)
	journalWrite = func(f *os.File, b []byte) (int, error) {
		n, _ := f.Write(b[:len(b)/2])
		f.Close() // so that Truncate fails as well
		return n, errors.New("EIO")
	}
	_, err := s.NewPing("a@example.org", "k", false, t0)
	journalWrite = (*os.File).Write
	if err == nil || !strings.Contains(err.Error(), "unusable until restart") {
		t.Fatalf("got %v", err)
	}
	for _, err := range []error{
		func() error { _, err := s.NewPing("a@example.org", "k", false, t0); return err }(),
		func() error { _, _, err := s.PingDone(1, t0, 1); return err }(),
		s.Compact(t0),
	} {
		if err == nil || !strings.Contains(err.Error(), "unusable until restart") {
			t.Errorf("write after the failure: %v", err)
		}
	}
	s.Close()
	log, buf := logBuffer()
	s, err = Open(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if out, _ := s.Pings("a@example.org", time.Time{}); len(out) != 1 || !strings.Contains(buf.String(), "incomplete last line") {
		t.Errorf("after reopen: %+v\n%s", out, buf)
	}
}

func TestReplyStatus(t *testing.T) {
	s := open(t, t.TempDir())
	if last, waiting := s.ReplyStatus(); !last.IsZero() || !waiting.IsZero() {
		t.Errorf("empty: %v %v", last, waiting)
	}
	a, b := "a@x.example", "b@x.example"
	p1, _ := s.NewPing(a, "k1", false, t0)
	s.NewPing(b, "k2", false, t0.Add(time.Hour))
	if last, waiting := s.ReplyStatus(); !last.IsZero() || !waiting.Equal(t0) {
		t.Errorf("none back: %v %v", last, waiting)
	}
	s.PingDone(p1.ID, t0.Add(90*time.Minute), 5400)
	if last, waiting := s.ReplyStatus(); !last.Equal(t0.Add(90*time.Minute)) || !waiting.IsZero() {
		t.Errorf("one back after the other was sent: %v %v", last, waiting)
	}
	p3, _ := s.NewPing(a, "k1", false, t0.Add(2*time.Hour))
	p4, _ := s.NewPing(b, "k2", false, t0.Add(3*time.Hour))
	s.PingAborted(p3.ID, "local failure")
	if last, waiting := s.ReplyStatus(); !last.Equal(t0.Add(90*time.Minute)) || !waiting.Equal(p4.Sent) {
		t.Errorf("aborted left out: %v %v", last, waiting)
	}
}
