// Package sdnotify sends service state to systemd through $NOTIFY_SOCKET
// (sd_notify(3)), without a dependency (design §10.1).
package sdnotify

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// States for Notify.
const (
	Ready    = "READY=1"
	Stopping = "STOPPING=1"
	Watchdog = "WATCHDOG=1"
)

// Status returns a STATUS= state carrying the one-line text s.
func Status(s string) string {
	return "STATUS=" + strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// Notify sends state (one or more "KEY=value" lines) to the socket named
// by $NOTIFY_SOCKET: a path, or a name in the abstract namespace when it
// starts with '@'.  Without $NOTIFY_SOCKET it does nothing and returns
// nil.
func Notify(state string) error {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return nil
	}
	if name[0] != '/' && name[0] != '@' {
		return fmt.Errorf("sdnotify: unsupported NOTIFY_SOCKET %q", name)
	}
	// Go maps a leading '@' to the abstract namespace on Linux.
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("sdnotify: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("sdnotify: %w", err)
	}
	return nil
}

// WatchdogInterval returns the watchdog timeout systemd expects
// (WatchdogSec, from $WATCHDOG_USEC), or 0 when the watchdog is off or
// meant for another process ($WATCHDOG_PID).  Send Watchdog well within
// it, e.g. at half the interval.
func WatchdogInterval() (time.Duration, error) {
	us := os.Getenv("WATCHDOG_USEC")
	if us == "" {
		return 0, nil
	}
	if p := os.Getenv("WATCHDOG_PID"); p != "" {
		pid, err := strconv.Atoi(p)
		if err != nil {
			return 0, fmt.Errorf("sdnotify: bad WATCHDOG_PID %q", p)
		}
		if pid != os.Getpid() {
			return 0, nil
		}
	}
	n, err := strconv.ParseInt(us, 10, 64)
	if err != nil || n <= 0 || n > int64(1<<63-1)/int64(time.Microsecond) {
		return 0, errors.New("sdnotify: bad WATCHDOG_USEC " + strconv.Quote(us))
	}
	return time.Duration(n) * time.Microsecond, nil
}
