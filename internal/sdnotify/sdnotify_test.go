package sdnotify

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func listen(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func recv(t *testing.T, c *net.UnixConn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestNotifyPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	c := listen(t, path)
	t.Setenv("NOTIFY_SOCKET", path)
	for _, s := range []string{Ready, Status("tick 12:05\nok"), Watchdog, Stopping, Ready + "\n" + Status("up")} {
		if err := Notify(s); err != nil {
			t.Fatal(err)
		}
		want := s
		if got := recv(t, c); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if Status("a\r\nb") != "STATUS=a  b" {
		t.Errorf("Status = %q", Status("a\r\nb"))
	}
}

func TestNotifyAbstract(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("abstract sockets are Linux-only")
	}
	name := fmt.Sprintf("@go-echolot-sdnotify-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	c := listen(t, name)
	t.Setenv("NOTIFY_SOCKET", name)
	if err := Notify(Watchdog); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, c); got != Watchdog {
		t.Errorf("got %q", got)
	}
}

func TestNotifyUnsetAndErrors(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Notify(Ready); err != nil {
		t.Errorf("unset: %v", err)
	}
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing"))
	if err := Notify(Ready); err == nil {
		t.Error("missing socket: no error")
	}
	t.Setenv("NOTIFY_SOCKET", "vsock:2:1234")
	if err := Notify(Ready); err == nil {
		t.Error("vsock: no error")
	}
}

func TestWatchdogInterval(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	for _, c := range []struct {
		usec, pid string
		want      time.Duration
		err       bool
	}{
		{"", "", 0, false},
		{"600000000", "", 10 * time.Minute, false},
		{"600000000", pid, 10 * time.Minute, false},
		{"600000000", "1", 0, false},
		{"600000000", "x", 0, true},
		{"0", "", 0, true},
		{"-5", "", 0, true},
		{"10s", "", 0, true},
		{"99999999999999999", "", 0, true},
	} {
		t.Setenv("WATCHDOG_USEC", c.usec)
		t.Setenv("WATCHDOG_PID", c.pid)
		got, err := WatchdogInterval()
		if got != c.want || (err != nil) != c.err {
			t.Errorf("usec %q pid %q: %s, %v", c.usec, c.pid, got, err)
		}
	}
}
