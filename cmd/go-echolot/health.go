package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/app"
	"github.com/go-while/go-echolot/internal/health"
)

// The check verb (design §10.2, §10.4).

func init() {
	commands = append(commands,
		command{"check", "check the health for Nagios or cron: exit 0 ok, 1 warn, 2 crit", cmdCheck})
}

// exitCode ends the program with this status, without a message.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// statusAge returns the warn and crit ages of status.json, which the
// daemon rewrites every tick: older, the daemon has stopped or hangs.
func statusAge(tick time.Duration) (warn, crit time.Duration) {
	return max(15*time.Minute, 3*tick), max(30*time.Minute, 6*tick)
}

var nagiosNames = []string{"OK", "WARNING", "CRITICAL"}

// cmdCheck reads the daemon's status.json and exits with its state.  The
// first line is Nagios's summary; the whole status follows.
func cmdCheck(args []string, stdout, stderr io.Writer) error {
	cfg, rest, err := loadConfig("check", args, stderr)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return usageError(stderr, "check", rest[0])
	}
	path := filepath.Join(cfg.Paths.ResultsDir, app.StatusJSON)
	data, err := os.ReadFile(path)
	var r *health.Report
	if err == nil {
		r, err = health.ParseReport(data)
	}
	if err != nil {
		fmt.Fprintf(stdout, "GO-ECHOLOT CRITICAL - %s: %v (is the daemon running?)\n", path, err)
		return exitCode(health.Crit)
	}
	warn, crit := statusAge(cfg.Schedule.Tick)
	age := now().Sub(r.Generated)
	c := health.Check{Name: "status_age", Detail: fmt.Sprintf("%s written %s ago", app.StatusJSON, health.Dur(age))}
	switch {
	case age > crit:
		c.State = health.Crit
	case age > warn:
		c.State = health.Warn
	}
	if c.State != health.OK {
		c.Detail += " (is the daemon running?)"
	}
	r = health.NewReport(r.Pinger, r.Version, r.Generated, append([]health.Check{c}, r.Checks...))
	var bad []string
	for _, c := range r.Checks {
		if c.State != health.OK {
			bad = append(bad, c.Name+": "+c.Detail)
		}
	}
	summary := fmt.Sprintf("%d checks ok", len(r.Checks))
	if len(bad) > 0 {
		summary = strings.Join(bad, "; ")
	}
	fmt.Fprintf(stdout, "GO-ECHOLOT %s - %s\n", nagiosNames[r.State], summary)
	stdout.Write(r.Text())
	if r.State != health.OK {
		return exitCode(r.State)
	}
	return nil
}
