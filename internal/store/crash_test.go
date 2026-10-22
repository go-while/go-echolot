package store

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// helperEnv makes the test binary run crashHelper instead of the tests.
const helperEnv = "GO_ECHOLOT_STORE_HELPER"

func TestMain(m *testing.M) {
	if dir := os.Getenv(helperEnv); dir != "" {
		crashHelper(dir)
		return
	}
	os.Exit(m.Run())
}

// crashHelper opens the store in dir and writes to it until it is
// killed.  After each round's writes are done, it prints
// "ack <round> <ping id>".
func crashHelper(dir string) {
	s, err := Open(dir, nil)
	if err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	fmt.Println("open")
	for i := 1; ; i++ {
		p, err := s.NewPing("a@example.org", "k", i%2 == 0, time.Unix(1792560000+int64(i), 0))
		if err == nil && i%2 == 0 {
			_, _, err = s.PingDone(p.ID, time.Unix(1792570000, 0), int64(i))
		}
		if err == nil {
			err = s.Update(func(st *State) error {
				st.MaxID = i
				st.Prospective = map[string][]Suggestion{"x": {{Reason: strings.Repeat("x", i%4096)}}}
				return nil
			})
		}
		if err == nil && i%97 == 0 {
			err = s.Compact(time.Unix(1792560000+int64(i)-50, 0))
		}
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println("ack", i, p.ID)
	}
}

// startHelper runs crashHelper on dir and waits until it has the store
// open.
func startHelper(t *testing.T, dir string) (*exec.Cmd, *bufio.Scanner) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"="+dir)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	sc := bufio.NewScanner(stdout)
	if !sc.Scan() || sc.Text() != "open" {
		t.Fatalf("helper: %q", sc.Text())
	}
	return cmd, sc
}

// TestLockOtherProcess checks the lock against another process, and that
// it goes away when that process dies.
func TestLockOtherProcess(t *testing.T) {
	dir := t.TempDir()
	cmd, _ := startHelper(t, dir)
	_, err := Open(dir, nil)
	var le *LockedError
	if !errors.As(err, &le) || le.PID != cmd.Process.Pid {
		t.Fatalf("Open while the helper runs: %v (helper pid %d)", err, cmd.Process.Pid)
	}
	cmd.Process.Kill()
	cmd.Wait()
	open(t, dir)
}

// TestCrash kills a process that writes to the store at an arbitrary
// moment, several times, and checks that every write it had finished is
// there and the store opens cleanly.
func TestCrash(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	for round := range 6 {
		dir := t.TempDir()
		cmd, sc := startHelper(t, dir)
		var lastI, lastID int
		for n := 0; n < 50+round*80 && sc.Scan(); n++ {
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
		s.View(func(st *State) {
			if st.MaxID < lastI {
				t.Errorf("round %d: state has round %d, acknowledged %d", round, st.MaxID, lastI)
			}
		})
		p, ok := s.Ping(uint64(lastID))
		if !ok || p.Sent.Unix() != 1792560000+int64(lastI) || (lastI%2 == 0) != (p.Status == PingDone) {
			t.Errorf("round %d: last acknowledged ping %d: %+v", round, lastID, p)
		}
		next, err := s.NewPing("a@example.org", "k", false, time.Now())
		if err != nil || next.ID <= uint64(lastID) {
			t.Errorf("round %d: next ping %d after %d, %v", round, next.ID, lastID, err)
		}
		if strings.Contains(buf.String(), "bad line") {
			t.Errorf("round %d: bad journal lines:\n%s", round, buf)
		}
		s.Close()
	}
}
