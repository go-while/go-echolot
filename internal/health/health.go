// Package health is go-echolot's self-monitoring (design §10.2): the
// checks, each ok, warn or crit; the status files; and the rules of the
// operator's notification mails.  The daemon gathers the inputs; every
// function here is pure, so the thresholds are easy to test.
package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// Thresholds (design §10.2).
const (
	ScanWarn = 5 * time.Minute // last good mailbox scan
	ScanCrit = 30 * time.Minute

	RepliesWarn = 3 * time.Hour // a ping out with no reply of any ping since
	RepliesCrit = 6 * time.Hour
	MinPingable = 2 // remailers pingable for RepliesCrit to be crit

	SendWindow = time.Hour // outgoing send failures are counted over this
	FailWarn   = 0.10      // warn above this share of failures
	MinSends   = 3         // fewer sends in SendWindow: too few to judge

	Mlist2Warn = 15 * time.Minute // at least; 3 stats intervals if longer
	Mlist2Crit = time.Hour        // at least; 12 stats intervals if longer

	KeyExpiryWarn = 24 * time.Hour // a published key expires sooner with no successor
	BounceWindow  = 24 * time.Hour

	DiskWarn = 0.10 // free share of the file system
	DiskCrit = 0.02

	PeerInterval = time.Hour // how often the peers' files are fetched
	PeerWarn     = 6 * time.Hour
	PeerCrit     = 24 * time.Hour

	NotifyEvery = 6 * time.Hour // at most one mail per check in this time

	maxListed = 10 // names listed in one detail
)

// Level is a check's state.
type Level int

// The levels, in order of severity.
const (
	OK Level = iota
	Warn
	Crit
)

var levelNames = []string{"ok", "warn", "crit"}

func (l Level) String() string {
	if l < OK || l > Crit {
		return fmt.Sprintf("level(%d)", int(l))
	}
	return levelNames[l]
}

// MarshalText writes ok, warn or crit.
func (l Level) MarshalText() ([]byte, error) {
	if l < OK || l > Crit {
		return nil, fmt.Errorf("bad level %d", int(l))
	}
	return []byte(l.String()), nil
}

// UnmarshalText reads ok, warn or crit.
func (l *Level) UnmarshalText(b []byte) error {
	i := slices.Index(levelNames, string(b))
	if i < 0 {
		return fmt.Errorf("bad level %q", b)
	}
	*l = Level(i)
	return nil
}

// Check is the result of one check.
type Check struct {
	Name   string `json:"name"` // stable: mailbox_scan, peer_mixmin, ...
	State  Level  `json:"state"`
	Detail string `json:"detail"`
}

func check(name string, l Level, format string, a ...any) Check {
	return Check{Name: name, State: l, Detail: fmt.Sprintf(format, a...)}
}

// level returns crit at or over crit, warn at or over warn (both
// exclusive: "over"), else ok.
func level(v, warn, crit time.Duration) Level {
	switch {
	case v > crit:
		return Crit
	case v > warn:
		return Warn
	}
	return OK
}

// Dur writes d rounded for people: seconds under a minute, else minutes.
func Dur(d time.Duration) string {
	if d < 0 {
		return "-" + Dur(-d)
	}
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	s := strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// list joins names, at most maxListed of them.
func list(names []string) string {
	if len(names) > maxListed {
		return strings.Join(names[:maxListed], ", ") + fmt.Sprintf(" and %d more", len(names)-maxListed)
	}
	return strings.Join(names, ", ")
}

// Scan checks the last good mailbox scan.  last is zero before the first
// one; since is when the daemon started.
func Scan(last, since, now time.Time) Check {
	const name = "mailbox_scan"
	if last.IsZero() {
		age := now.Sub(since)
		return check(name, level(age, ScanWarn, ScanCrit), "no good scan since the start %s ago", Dur(age))
	}
	age := now.Sub(last)
	return check(name, level(age, ScanWarn, ScanCrit), "last good scan %s ago", Dur(age))
}

// Replies checks that pings come back.  waiting is when the oldest ping
// still out that was sent after the last reply left (zero: none is
// out), but not before the daemon started; pingable is the number of
// remailers being pinged.  Only with at least MinPingable of them is a
// long silence crit: with one, that remailer may just be down.
func Replies(lastReply, waiting time.Time, pingable int, now time.Time) Check {
	const name = "ping_replies"
	last := "never"
	if !lastReply.IsZero() {
		last = Dur(now.Sub(lastReply)) + " ago"
	}
	if waiting.IsZero() {
		return check(name, OK, "last reply %s; no ping waiting", last)
	}
	age := now.Sub(waiting)
	l := level(age, RepliesWarn, RepliesCrit)
	if l == Crit && pingable < MinPingable {
		l = Warn
	}
	if l == OK {
		return check(name, OK, "last reply %s", last)
	}
	return check(name, l, "no ping reply for %s (last reply %s; %d remailers pingable)", Dur(age), last, pingable)
}

// Sends checks the outgoing send failures in the last SendWindow.
func Sends(sent, failed int) Check {
	const name = "send_failures"
	switch {
	case sent < MinSends:
		return check(name, OK, "%d of %d sends failed in the last hour (too few to judge)", failed, sent)
	case failed == sent:
		return check(name, Crit, "all %d sends failed in the last hour", sent)
	case float64(failed) > FailWarn*float64(sent):
		return check(name, Warn, "%d of %d sends failed in the last hour", failed, sent)
	}
	return check(name, OK, "%d of %d sends failed in the last hour", failed, sent)
}

// Mlist2Thresholds are the warn and crit ages of mlist2.txt for a stats
// interval.
func Mlist2Thresholds(interval time.Duration) (warn, crit time.Duration) {
	return max(Mlist2Warn, 3*interval), max(Mlist2Crit, 12*interval)
}

// Mlist2 checks the Generated: time of our mlist2.txt; err is the error
// reading it.  since is when the daemon started: a missing file is crit
// only once the stats should have been written.
func Mlist2(generated time.Time, err error, interval time.Duration, since, now time.Time) Check {
	const name = "mlist2_age"
	warn, crit := Mlist2Thresholds(interval)
	if err != nil {
		return check(name, level(now.Sub(since), warn, crit), "%v", err)
	}
	age := now.Sub(generated)
	return check(name, level(age, warn, crit), "generated %s ago", Dur(age))
}

// Keys checks the public keyring: published is how many keys it has,
// expiring the remailers whose key expires within KeyExpiryWarn with no
// successor.
func Keys(published int, expiring []string) Check {
	const name = "keys"
	switch {
	case published == 0:
		return check(name, Crit, "no keys published")
	case len(expiring) > 0:
		return check(name, Warn, "%d keys published; expiring in less than %s with no new key: %s",
			published, Dur(KeyExpiryWarn), list(expiring))
	}
	return check(name, OK, "%d keys published", published)
}

// SelfTest checks the yamn self-test; err is its result, ran when it was
// run.
func SelfTest(err error, ran, now time.Time) Check {
	const name = "yamn_selftest"
	switch {
	case ran.IsZero():
		return check(name, OK, "not run yet")
	case err != nil:
		return check(name, Crit, "failed %s ago: no pings can be sent: %v", Dur(now.Sub(ran)), err)
	}
	return check(name, OK, "passed %s ago", Dur(now.Sub(ran)))
}

// Pending checks the quarantined changes waiting (design §9.2).
func Pending(changes []string) Check {
	const name = "pending"
	if len(changes) > 0 {
		return check(name, Warn, "%d changes in quarantine (approve or reject them): %s", len(changes), list(changes))
	}
	return check(name, OK, "none")
}

// Bounces checks the bounces of the last BounceWindow: the time of the
// last bounce for each remailer address.
func Bounces(last map[string]time.Time, now time.Time) Check {
	const name = "bounces"
	var addrs []string
	for _, a := range slices.Sorted(maps.Keys(last)) {
		if now.Sub(last[a]) <= BounceWindow {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) > 0 {
		return check(name, Warn, "bounces in the last %s for %s (see mail-errors)", Dur(BounceWindow), list(addrs))
	}
	return check(name, OK, "none in the last %s", Dur(BounceWindow))
}

// Disk checks the free space of the file system of path: free is its
// free share, err the error finding it.
func Disk(name, path string, free float64, err error) Check {
	name = "disk_" + name
	if err != nil {
		return check(name, Warn, "%s: %v", path, err)
	}
	l := OK
	switch {
	case free < DiskCrit:
		l = Crit
	case free < DiskWarn:
		l = Warn
	}
	return check(name, l, "%.1f%% free on %s", free*100, path)
}

// Peer is what the last fetches of a peer's files found.
type Peer struct {
	Checked   time.Time // the last attempt; zero: none yet
	Generated time.Time // Generated: of its mlist2.txt at the last good fetch; zero: none
	Err       string    // the last attempt's error
}

// PeerCheck checks the peer pinger name: how old its mlist2.txt was at
// the last good fetch.  A peer that can't be fetched ages from its last
// good fetch, so a host that is down goes warn and crit too.
func PeerCheck(name string, p Peer, now time.Time) Check {
	name = "peer_" + name
	switch {
	case p.Checked.IsZero():
		return check(name, OK, "not fetched yet")
	case p.Generated.IsZero():
		return check(name, Warn, "never fetched: %s", p.Err)
	}
	age := now.Sub(p.Generated)
	c := check(name, level(age, PeerWarn, PeerCrit), "mlist2.txt generated %s ago", Dur(age))
	if p.Err != "" {
		c.Detail += "; the last fetch failed: " + p.Err
	}
	return c
}

// PeerKeys reports the peers' key disagreements with our public keyring.
// It's information only: always ok.
func PeerKeys(disagree []string) Check {
	const name = "peer_keys"
	if len(disagree) > 0 {
		return check(name, OK, "%d disagreements: %s", len(disagree), list(disagree))
	}
	return check(name, OK, "the peers' keyrings agree with ours")
}

// Report is the content of status.json.
type Report struct {
	Generated time.Time `json:"generated"`
	Pinger    string    `json:"pinger"`
	Version   string    `json:"version,omitempty"`
	State     Level     `json:"state"` // the worst of the checks
	Checks    []Check   `json:"checks"`
}

// NewReport returns the report of checks.
func NewReport(pinger, version string, now time.Time, checks []Check) *Report {
	r := &Report{Generated: now.UTC(), Pinger: pinger, Version: version, Checks: checks}
	for _, c := range checks {
		r.State = max(r.State, c.State)
	}
	return r
}

// JSON returns status.json.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseReport reads status.json.
func ParseReport(data []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.Generated.IsZero() {
		return nil, errors.New("no generated time")
	}
	return &r, nil
}

// Text returns status.txt.
func (r *Report) Text() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "go-echolot health: %s\n", strings.ToUpper(r.State.String()))
	fmt.Fprintf(&b, "pinger: %s\n", r.Pinger)
	fmt.Fprintf(&b, "generated: %s\n\n", r.Generated.UTC().Format(time.RFC3339))
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "%-5s %-18s %s\n", c.State, c.Name, c.Detail)
	}
	return b.Bytes()
}

// Window counts the outgoing sends and their failures in the last
// SendWindow.  It is safe for concurrent use.
type Window struct {
	mu     sync.Mutex
	events []sendEvent // oldest first
}

type sendEvent struct {
	at     time.Time
	failed bool
}

// Add records a send at at.
func (w *Window) Add(at time.Time, failed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, sendEvent{at, failed})
}

// Counts returns the sends and failures within SendWindow before now and
// forgets older ones.
func (w *Window) Counts(now time.Time) (sent, failed int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	i := 0
	for i < len(w.events) && now.Sub(w.events[i].at) > SendWindow {
		i++
	}
	w.events = slices.Delete(w.events, 0, i)
	for _, e := range w.events {
		sent++
		if e.failed {
			failed++
		}
	}
	return sent, failed
}

// Notice is the last notification mail about a check.
type Notice struct {
	State Level     `json:"state"`
	Sent  time.Time `json:"sent"`
}

// Due returns the checks to mail about now: those whose state differs
// from the one last mailed (ok if none was) and that weren't mailed in
// the last NotifyEvery.  A check that changes again within that time
// waits; once it's due, the mail has its state then.
func Due(checks []Check, notified map[string]Notice, now time.Time) []Check {
	var due []Check
	for _, c := range checks {
		n, ok := notified[c.Name]
		if c.State == n.State || ok && now.Sub(n.Sent) < NotifyEvery {
			continue
		}
		due = append(due, c)
	}
	return due
}

// Digest returns the notification mail about due for r: the subject and
// the body.  The body lists the changed checks, then the whole status.
func Digest(r *Report, due []Check) (subject string, body []byte) {
	subject = fmt.Sprintf("go-echolot health: %s (%s)", strings.ToUpper(r.State.String()), r.Pinger)
	var b bytes.Buffer
	b.WriteString("Changed:\n\n")
	for _, c := range due {
		fmt.Fprintf(&b, "%-5s %-18s %s\n", c.State, c.Name, c.Detail)
	}
	b.WriteString("\nThe whole status:\n\n")
	b.Write(r.Text())
	fmt.Fprintf(&b, "\nA check is mailed about at most once in %s.\n", Dur(NotifyEvery))
	return subject, b.Bytes()
}

// generatedLayouts are the forms of an mlist2.txt Generated: line:
// Echolot's (E:Stats.pm make_date), also with an unpadded day.
var generatedLayouts = []string{"Mon 02 Jan 2006 15:04:05 GMT", "Mon _2 Jan 2006 15:04:05 GMT", time.RFC1123Z}

// maxHeaderLines is how far into an mlist2.txt the Generated: line may be.
const maxHeaderLines = 10

// ParseGenerated returns the Generated: time of an mlist2.txt.
func ParseGenerated(data []byte) (time.Time, error) {
	for i, line := range strings.SplitN(string(data), "\n", maxHeaderLines+1) {
		if i == maxHeaderLines {
			break
		}
		v, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "Generated:")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		for _, layout := range generatedLayouts {
			if t, err := time.Parse(layout, v); err == nil {
				return t.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("can't read the time in Generated: %.40q", v)
	}
	return time.Time{}, errors.New("no Generated: line")
}
