package store

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func chainJournal(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "chainpings.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func addChain(t *testing.T, s *Store, a, b string, sent time.Time) ChainPing {
	t.Helper()
	p, err := s.AddChainPing(ChainPing{A: a, KeyA: "ka", B: b, KeyB: "kb", Sent: sent})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestChainPings(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	a, b, c := "a@example.org", "b@example.org", "c@example.org"
	p1 := addChain(t, s, a, b, t0.Add(500*time.Millisecond)) // whole seconds
	p2 := addChain(t, s, a, c, t0.Add(time.Hour))
	p3 := addChain(t, s, b, a, t0.Add(2*time.Hour))
	p4 := addChain(t, s, c, a, t0.Add(-time.Hour))
	if p1.ID != 1 || p4.ID != 4 || !p1.Sent.Equal(t0) || p1.Status != PingOut || p1.KeyA != "ka" || p1.KeyB != "kb" {
		t.Fatalf("AddChainPing: %+v %+v", p1, p4)
	}
	got, news, err := s.ChainPingDone(p2.ID, t0.Add(90*time.Minute), 1800)
	if err != nil || !news || got.A != a || got.B != c || got.Latency != 1800 {
		t.Errorf("ChainPingDone: %+v %v %v", got, news, err)
	}
	if _, news, _ := s.ChainPingDone(p2.ID, t0.Add(2*time.Hour), 1); news {
		t.Error("second ChainPingDone is news")
	}
	if _, news, err := s.ChainPingDone(99, t0, 1); news || err != nil {
		t.Errorf("ChainPingDone of an unknown ping: %v %v", news, err)
	}
	if _, _, err := s.ChainPingDone(p1.ID, time.Unix(0, 0), 1); err == nil {
		t.Error("ChainPingDone with a bad time")
	}
	if err := s.ChainPingAborted(p3.ID, "yamn: exit 1"); err != nil {
		t.Fatal(err)
	}
	s.ChainPingAborted(p2.ID, "late abort") // ignored: back
	s.ChainPingAborted(77, "unknown")       // ignored
	if _, err := s.AddChainPing(ChainPing{A: a, KeyA: "k", B: "", KeyB: "k", Sent: t0}); err == nil {
		t.Error("AddChainPing without B")
	}
	if _, err := s.AddChainPing(ChainPing{A: a, KeyA: "k", B: b, KeyB: "k"}); err == nil {
		t.Error("AddChainPing without a time")
	}

	check := func(s *Store) {
		t.Helper()
		ps := s.ChainPings(t0) // at or after t0; p3 aborted, p4 before
		if len(ps) != 2 || ps[0].ID != p1.ID || ps[1].ID != p2.ID || ps[1].Status != PingDone ||
			!ps[1].Received.Equal(t0.Add(90*time.Minute)) || ps[1].Latency != 1800 {
			t.Errorf("ChainPings: %+v", ps)
		}
		if all := s.ChainPings(time.Time{}); len(all) != 3 || all[0].ID != p4.ID {
			t.Errorf("all: %+v", all)
		}
		if p, ok := s.ChainPing(p3.ID); !ok || p.Status != PingAborted || p.Err != "yamn: exit 1" {
			t.Errorf("aborted: %+v %v", p, ok)
		}
	}
	check(s)
	s.Close()
	s = open(t, dir)
	check(s)
	// Calls refused before writing use up no ID.
	if p := addChain(t, s, a, b, t0); p.ID != 5 {
		t.Errorf("next ID %d, want 5", p.ID)
	}
	// The ping journal is separate.
	if out, done := s.Pings(a, time.Time{}); len(out)+len(done) != 0 {
		t.Errorf("chain pings in the ping journal: %+v %+v", out, done)
	}
	if p, _ := s.NewPing(a, "k", false, t0); p.ID != 1 {
		t.Errorf("ping ID %d", p.ID)
	}
}

func TestChainJournalFormat(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	sent := time.Unix(1792560000, 0)
	p := addChain(t, s, "a@example.org", "b@example.org", sent)
	s.ChainPingDone(p.ID, sent.Add(4321*time.Second), 4321)
	q := addChain(t, s, "b@example.org", "a@example.org", sent)
	s.ChainPingAborted(q.ID, "yamn: exit 1")
	want := `{"ev":"out","id":1,"a":"a@example.org","ka":"ka","b":"b@example.org","kb":"kb","sent":1792560000}
{"ev":"done","id":1,"lat":4321,"rcv":1792564321}
{"ev":"out","id":2,"a":"b@example.org","ka":"ka","b":"a@example.org","kb":"kb","sent":1792560000}
{"ev":"abort","id":2,"err":"yamn: exit 1"}
`
	if got := chainJournal(t, dir); got != want {
		t.Errorf("journal:\n%s\nwant:\n%s", got, want)
	}
	s.CompactChains(sent.Add(-time.Hour))
	if got := chainJournal(t, dir); got != `{"ev":"next","id":3}`+"\n"+want {
		t.Errorf("compacted:\n%s", got)
	}
}

func TestChainJournalTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	addChain(t, s, "a@example.org", "b@example.org", t0)
	s.Close()
	good := chainJournal(t, dir)
	f, _ := os.OpenFile(filepath.Join(dir, "chainpings.jsonl"), os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"ev":"out","id":2,"a":"a@ex`)
	f.Close()

	log, buf := logBuffer()
	s, err := Open(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !strings.Contains(buf.String(), "chain ping journal: dropping an incomplete last line") {
		t.Errorf("not logged: %s", buf)
	}
	if got := chainJournal(t, dir); got != good {
		t.Errorf("not truncated:\n%s", got)
	}
	if p := addChain(t, s, "a@example.org", "b@example.org", t0); p.ID != 2 {
		t.Errorf("ID %d", p.ID)
	}
	s.Close()
	log, buf = logBuffer()
	s, _ = Open(dir, log)
	defer s.Close()
	if ps := s.ChainPings(time.Time{}); len(ps) != 2 || buf.Len() != 0 {
		t.Errorf("after recovery: %+v, log %s", ps, buf)
	}
}

func TestChainJournalBadLines(t *testing.T) {
	dir := t.TempDir()
	lines := []string{
		`{"ev":"out","id":1,"a":"a@example.org","ka":"k","b":"b@example.org","kb":"k","sent":1792560000}`,
		`garbage`,
		`{"ev":"out","id":2,"a":"a@example.org","ka":"k","b":"b@example.org","sent":1792560000}`,          // no kb
		`{"ev":"out","id":1,"a":"c@example.org","ka":"k","b":"b@example.org","kb":"k","sent":1792560000}`, // id 1 again
		`{"ev":"sent","id":3}`,                                                                            // unknown event
		`{"ev":"done","id":1,"rcv":1792560100}`,                                                           // no lat
		`{"ev":"done","id":1,"lat":100,"rcv":1792560100,"x":1}`,                                           // unknown field
		`{"ev":"out","id":4,"addr":"a@example.org","key":"k","wf":1,"sent":1792560000}`,                   // a ping event
		`{"ev":"out","id":5,"a":"a@example.org","ka":"k","b":"b@example.org","kb":"k","sent":1792560000}`, // good
		`{"ev":"done","id":5,"lat":100,"rcv":1792560100}`,                                                 // good
		`{"ev":"done","id":77,"lat":100,"rcv":1792560100}`,                                                // unknown ping: ignored quietly
		`{"ev":"abort","id":5,"err":"too late"}`,                                                          // after done: ignored quietly
		`{"ev":"next","id":10}`,                                                                           // good
		`{"ev":"out","id":0,"a":"a@example.org","ka":"k","b":"b@example.org","kb":"k","sent":1792560000}`, // id 0
		`{"ev":"out","id":6,"a":"a@example.org","ka":"k","b":"b@example.org","kb":"k","sent":-1}`,         // bad time
		`{"ev":"done","id":1,"lat":5,"rcv":1792560100} {"ev":"done","id":1,"lat":5,"rcv":1}`,              // two on a line
	}
	if err := os.WriteFile(filepath.Join(dir, "chainpings.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log, buf := logBuffer()
	s, err := Open(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if n := strings.Count(buf.String(), "chain ping journal: skipping a bad line"); n != 10 {
		t.Errorf("%d bad lines logged, want 10:\n%s", n, buf)
	}
	ps := s.ChainPings(time.Time{})
	if len(ps) != 2 || ps[0].ID != 1 || ps[0].Status != PingOut || ps[1].ID != 5 || ps[1].Status != PingDone {
		t.Errorf("pings %+v", ps)
	}
	if p := addChain(t, s, "a@example.org", "b@example.org", t0); p.ID != 10 {
		t.Errorf("next ID %d, want 10", p.ID)
	}
}

func TestChainJournalWriteFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	addChain(t, s, "a@example.org", "b@example.org", t0)
	before := chainJournal(t, dir)
	journalWrite = func(f *os.File, b []byte) (int, error) {
		n, _ := f.Write(b[:len(b)/2])
		return n, errors.New("disk full")
	}
	_, err := s.AddChainPing(ChainPing{A: "a@example.org", KeyA: "k", B: "b@example.org", KeyB: "k", Sent: t0})
	journalWrite = (*os.File).Write
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatal(err)
	}
	if got := chainJournal(t, dir); got != before {
		t.Errorf("partial write kept:\n%s", got)
	}
	if ps := s.ChainPings(time.Time{}); len(ps) != 1 {
		t.Errorf("failed ping in memory: %+v", ps)
	}
	if p := addChain(t, s, "a@example.org", "b@example.org", t0); p.ID != 3 {
		t.Errorf("next ping: %+v", p)
	}
	s.Close()
	s = open(t, dir)
	if ps := s.ChainPings(time.Time{}); len(ps) != 2 {
		t.Errorf("after reopen: %+v", ps)
	}
}

func TestChainJournalTruncateFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	addChain(t, s, "a@example.org", "b@example.org", t0)
	journalWrite = func(f *os.File, b []byte) (int, error) {
		n, _ := f.Write(b[:len(b)/2])
		f.Close() // so that Truncate fails as well
		return n, errors.New("EIO")
	}
	_, err := s.AddChainPing(ChainPing{A: "a@example.org", KeyA: "k", B: "b@example.org", KeyB: "k", Sent: t0})
	journalWrite = (*os.File).Write
	if err == nil || !strings.Contains(err.Error(), "unusable until restart") {
		t.Fatalf("got %v", err)
	}
	for _, err := range []error{
		func() error {
			_, err := s.AddChainPing(ChainPing{A: "a@example.org", KeyA: "k", B: "b@example.org", KeyB: "k", Sent: t0})
			return err
		}(),
		func() error { _, _, err := s.ChainPingDone(1, t0, 1); return err }(),
		s.ChainPingAborted(1, "x"),
		s.CompactChains(t0),
	} {
		if err == nil || !strings.Contains(err.Error(), "unusable until restart") {
			t.Errorf("write after the failure: %v", err)
		}
	}
	// The ping journal is unaffected.
	if _, err := s.NewPing("a@example.org", "k", false, t0); err != nil {
		t.Errorf("NewPing: %v", err)
	}
	s.Close()
	log, buf := logBuffer()
	s, err = Open(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if ps := s.ChainPings(time.Time{}); len(ps) != 1 || !strings.Contains(buf.String(), "incomplete last line") {
		t.Errorf("after reopen: %+v\n%s", ps, buf)
	}
}

func TestCompactChains(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	for i := range 6 {
		p := addChain(t, s, "a@example.org", "b@example.org", t0.Add(time.Duration(i)*24*time.Hour))
		switch i % 3 {
		case 1:
			s.ChainPingDone(p.ID, p.Sent.Add(time.Hour), 3600)
		case 2:
			s.ChainPingAborted(p.ID, "x")
		}
	}
	all := func(s *Store) []ChainPing {
		var ps []ChainPing
		for id := uint64(1); id <= 6; id++ {
			if p, ok := s.ChainPing(id); ok {
				ps = append(ps, p)
			}
		}
		return ps
	}
	want := all(s)[3:]
	pj := journal(t, dir)
	if err := s.CompactChains(t0.Add(3 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := all(s); !reflect.DeepEqual(got, want) {
		t.Errorf("after CompactChains:\n%+v\nwant\n%+v", got, want)
	}
	if j := chainJournal(t, dir); !strings.HasPrefix(j, `{"ev":"next","id":7}`+"\n"+`{"ev":"out","id":4,`) || strings.Count(j, "\n") != 6 {
		t.Errorf("journal:\n%s", j)
	}
	if journal(t, dir) != pj {
		t.Error("CompactChains changed the ping journal")
	}
	addChain(t, s, "a@example.org", "b@example.org", t0.Add(10*24*time.Hour))
	s.Close()
	s = open(t, dir)
	if got := all(s); !reflect.DeepEqual(got, want) {
		t.Errorf("after reopen:\n%+v", got)
	}
	// Everything expires: IDs still aren't reused ("next").
	if err := s.CompactChains(t0.Add(30 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if j := chainJournal(t, dir); j != `{"ev":"next","id":8}`+"\n" {
		t.Errorf("journal:\n%s", j)
	}
	s.Close()
	s = open(t, dir)
	if p := addChain(t, s, "a@example.org", "b@example.org", t0); p.ID != 8 {
		t.Errorf("ID after everything expired: %d, want 8", p.ID)
	}
}

func TestCompactChainsFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	addChain(t, s, "a@example.org", "b@example.org", t0)
	before := chainJournal(t, dir)
	fail := true
	countWrites(t, &fail)
	if err := s.CompactChains(t0.Add(time.Hour)); err == nil {
		t.Fatal("no error")
	}
	if _, ok := s.ChainPing(1); !ok {
		t.Error("ping forgotten after a failed CompactChains")
	}
	if p := addChain(t, s, "a@example.org", "b@example.org", t0); p.ID != 2 {
		t.Errorf("after a failed CompactChains: %+v", p)
	}
	if got := chainJournal(t, dir); !strings.HasPrefix(got, before) {
		t.Errorf("journal changed:\n%s", got)
	}
}

func TestCompactChainsDirSyncFails(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	addChain(t, s, "a@example.org", "b@example.org", t0)
	addChain(t, s, "a@example.org", "b@example.org", t0.Add(2*time.Hour))
	dirSyncFails(t)
	if err := s.CompactChains(t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	writeFile = origWriteFile
	p := addChain(t, s, "a@example.org", "b@example.org", t0.Add(3*time.Hour))
	s.Close()
	s = open(t, dir)
	if _, ok := s.ChainPing(p.ID); !ok {
		t.Errorf("chain ping %d written after CompactChains is lost:\n%s", p.ID, chainJournal(t, dir))
	}
	if _, ok := s.ChainPing(1); ok {
		t.Error("compacted chain ping is back")
	}
}

func TestChainClosed(t *testing.T) {
	s := open(t, t.TempDir())
	p := addChain(t, s, "a@example.org", "b@example.org", t0)
	s.Close()
	if _, err := s.AddChainPing(ChainPing{A: "a@example.org", KeyA: "k", B: "b@example.org", KeyB: "k", Sent: t0}); err == nil {
		t.Error("AddChainPing after Close")
	}
	if _, _, err := s.ChainPingDone(p.ID, t0, 1); err == nil {
		t.Error("ChainPingDone after Close")
	}
	if err := s.CompactChains(t0); err == nil {
		t.Error("CompactChains after Close")
	}
}

// chainHelperEnv makes the test binary run chainCrashHelper instead of
// the tests; init runs before TestMain.
const chainHelperEnv = "GO_ECHOLOT_STORE_CHAIN_HELPER"

func init() {
	if dir := os.Getenv(chainHelperEnv); dir != "" {
		chainCrashHelper(dir)
		os.Exit(0)
	}
}

// chainCrashHelper writes chain pings (every second one back), pings and
// state until it is killed, compacting the chain journal now and then.
// After each round it prints "ack <round> <chain ping id>".
func chainCrashHelper(dir string) {
	s, err := Open(dir, nil)
	if err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	fmt.Println("open")
	for i := 1; ; i++ {
		p, err := s.AddChainPing(ChainPing{A: "a@example.org", KeyA: "ka", B: "b@example.org", KeyB: "kb",
			Sent: time.Unix(1792560000+int64(i), 0)})
		if err == nil && i%2 == 0 {
			_, _, err = s.ChainPingDone(p.ID, time.Unix(1792570000, 0), int64(i))
		}
		if err == nil && i%3 == 0 {
			_, err = s.NewPing("a@example.org", "k", false, time.Unix(1792560000+int64(i), 0))
		}
		if err == nil {
			err = s.Update(func(st *State) error { st.MaxID = i; return nil })
		}
		if err == nil && i%89 == 0 {
			err = s.CompactChains(time.Unix(1792560000+int64(i)-40, 0))
		}
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println("ack", i, p.ID)
	}
}

// TestChainCrash kills a process writing chain pings at an arbitrary
// moment and checks that every acknowledged write is there, the next ID
// is new, and both journals open cleanly.
func TestChainCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	for round := range 5 {
		dir := t.TempDir()
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), chainHelperEnv+"="+dir)
		cmd.Stderr = os.Stderr
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(stdout)
		if !sc.Scan() || sc.Text() != "open" {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("helper: %q", sc.Text())
		}
		var lastI, lastID int
		for n := 0; n < 60+round*90 && sc.Scan(); n++ {
			f := strings.Fields(sc.Text())
			if len(f) != 3 || f[0] != "ack" {
				t.Fatalf("helper: %q", sc.Text())
			}
			lastI, _ = strconv.Atoi(f[1])
			lastID, _ = strconv.Atoi(f[2])
		}
		cmd.Process.Signal(syscall.SIGKILL)
		cmd.Wait()

		log, buf := logBuffer()
		s, err := Open(dir, log)
		if err != nil {
			t.Fatalf("round %d: Open after the crash: %v", round, err)
		}
		p, ok := s.ChainPing(uint64(lastID))
		if !ok || p.Sent.Unix() != 1792560000+int64(lastI) || (lastI%2 == 0) != (p.Status == PingDone) {
			t.Errorf("round %d: last acknowledged chain ping %d: %+v", round, lastID, p)
		}
		next, err := s.AddChainPing(ChainPing{A: "a@example.org", KeyA: "k", B: "b@example.org", KeyB: "k", Sent: time.Now()})
		if err != nil || next.ID <= uint64(lastID) {
			t.Errorf("round %d: next chain ping %d after %d, %v", round, next.ID, lastID, err)
		}
		if strings.Contains(buf.String(), "bad line") {
			t.Errorf("round %d: bad journal lines:\n%s", round, buf)
		}
		s.Close()
	}
}
