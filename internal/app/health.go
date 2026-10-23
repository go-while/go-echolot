package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/fileutil"
	"github.com/go-while/go-echolot/internal/health"
	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/mailout"
	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/pinger"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// Health and staleness self-monitoring (design §10.2).

// The status files in the results directory, rewritten every tick.
const (
	StatusJSON = "status.json"
	StatusText = "status.txt"
)

const (
	peerTimeout  = 30 * time.Second // one fetch of a peer's file
	maxPeerFile  = 2 << 20          // bytes; a pubring.mix of 100 keys is about 60 KiB
	maxPeerKeys  = 20               // key disagreements kept per peer
	jobHealth    = "health"         // the checks, every schedule.tick
	jobHourly    = "hourly"         // peers and the yamn self-test
	jobHourlyNow = "hourly-now"     // the same, once soon after the start
	hourlyDelay  = time.Minute
)

// healthState is what the checks need from the running daemon.
type healthState struct {
	mu          sync.Mutex
	started     time.Time
	lastScan    time.Time // the last good mailbox scan
	selfTestErr error
	selfTestRan time.Time
	sends       health.Window
}

func (h *healthState) scanned(at time.Time) {
	h.mu.Lock()
	h.lastScan = at
	h.mu.Unlock()
}

func (h *healthState) selfTested(at time.Time, err error) {
	h.mu.Lock()
	h.selfTestRan, h.selfTestErr = at, err
	h.mu.Unlock()
}

// countingMailer counts the sends and their failures for the health
// check.  Mail that wasn't attempted doesn't count: the rate fuse, and a
// .onion recipient without mail.tor_socks.
type countingMailer struct {
	m   mailout.Mailer
	w   *health.Window
	now func() time.Time
}

func (c countingMailer) Send(ctx context.Context, m mailout.Mail) error {
	err := c.m.Send(ctx, m)
	if !errors.Is(err, mailout.ErrRateLimited) && !errors.Is(err, mailout.ErrOnionWithoutTor) {
		c.w.Add(c.now(), err != nil)
	}
	return err
}

// SelfTest runs the yamn self-test and keeps its result for the health
// check.
func (d *Daemon) SelfTest(ctx context.Context, at time.Time) error {
	err := pinger.SelfTest(ctx, d.encoder, at)
	d.health.selfTested(at, err)
	return err
}

// Hourly fetches the peers' files and runs the yamn self-test again.
func (d *Daemon) Hourly(ctx context.Context, at time.Time) {
	d.CheckPeers(ctx, at)
	if err := d.SelfTest(ctx, at); err != nil {
		d.log.Error("yamn self-test failed: no pings can be sent", "binary", d.cfg.Yamn.Binary, "err", err)
	}
}

// Health runs the checks, writes status.json and status.txt, and mails
// the operator about changes.
func (d *Daemon) Health(at time.Time) *health.Report {
	r := health.NewReport(d.cfg.Pinger.Sitename, d.Version, at, d.HealthChecks(at))
	if err := writeStatus(d.cfg.Paths.ResultsDir, r); err != nil {
		d.log.Error("status files not written", "err", err)
	}
	d.notify(r, at)
	return r
}

func writeStatus(dir string, r *health.Report) error {
	js, err := r.JSON()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(filepath.Join(dir, StatusJSON), js, 0o644); err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(dir, StatusText), r.Text(), 0o644)
}

// HealthChecks runs the checks at now (design §10.2).
func (d *Daemon) HealthChecks(now time.Time) []health.Check {
	h := &d.health
	h.mu.Lock()
	started, lastScan, stErr, stRan := h.started, h.lastScan, h.selfTestErr, h.selfTestRan
	h.mu.Unlock()

	lastReply, waiting := d.st.ReplyStatus()
	if !waiting.IsZero() && waiting.Before(started) {
		waiting = started // pings sent before a restart get the time since
	}
	sent, failed := h.sends.Counts(now)
	gen, genErr := readGenerated(filepath.Join(d.cfg.Paths.ResultsDir, "mlist2.txt"))

	var (
		pingable          int
		published         int
		expiring, pending []string
		bounces           map[string]time.Time
		peers             = map[string]health.Peer{}
		disagree          []string
	)
	d.st.View(func(st *store.State) {
		for _, r := range st.Remailers {
			if r.PingIt && r.Status != store.StatusDead && r.Status != store.StatusDisabled &&
				r.Status != store.StatusNotARemailer && len(keys.Pingable(r, now, d.cfg.Keys.Retention)) > 0 {
				pingable++
			}
		}
		public, _ := output.Keyrings(st, now, d.cfg.Keys.RequireProof)
		published = len(public)
		for _, pk := range public {
			if r := find(st, pk.Address); r != nil && pk.Expires.End().Sub(now) < health.KeyExpiryWarn && !hasSuccessor(r, pk) {
				expiring = append(expiring, fmt.Sprintf("%s (expires %s)", pk.Nick, pk.Expires))
			}
		}
		slices.Sort(expiring)
		for _, p := range st.Pending {
			if !p.Rejected {
				pending = append(pending, fmt.Sprintf("%s: %s %s", p.Address, p.Kind, p.New))
			}
		}
		if st.Health != nil {
			bounces = maps.Clone(st.Health.Bounces)
			for _, p := range d.cfg.Peers {
				if ps := st.Health.Peers[p.Name]; ps != nil {
					peers[p.Name] = health.Peer{Checked: ps.Checked, Generated: ps.Generated, Err: ps.Err}
					for _, k := range ps.Keys {
						disagree = append(disagree, p.Name+": "+k)
					}
				}
			}
		}
	})

	checks := []health.Check{
		health.Scan(lastScan, started, now),
		health.Replies(lastReply, waiting, pingable, now),
		health.Sends(sent, failed),
		health.Mlist2(gen, genErr, d.cfg.Schedule.StatsInterval, started, now),
		health.Keys(published, expiring),
		health.SelfTest(stErr, stRan, now),
		health.Pending(pending),
		health.Bounces(bounces, now),
	}
	for _, p := range []struct{ name, path string }{{"state", d.cfg.Paths.StateDir}, {"results", d.cfg.Paths.ResultsDir}} {
		free, err := diskFree(p.path)
		checks = append(checks, health.Disk(p.name, p.path, free, err))
	}
	for _, p := range d.cfg.Peers {
		checks = append(checks, health.PeerCheck(p.Name, peers[p.Name], now))
	}
	if len(d.cfg.Peers) > 0 {
		checks = append(checks, health.PeerKeys(disagree))
	}
	return checks
}

// hasSuccessor reports whether r has a key that can follow pk: active or
// in quarantine, expiring later.
func hasSuccessor(r *store.Remailer, pk replies.ParsedKey) bool {
	for _, k := range r.Keys {
		if k.KeyID != pk.KeyID && (k.State == store.KeyStateActive || k.State == store.KeyStateQuarantined) &&
			k.Expires.After(pk.Expires) {
			return true
		}
	}
	return false
}

// readGenerated returns the Generated: time of the mlist2.txt at path.
func readGenerated(path string) (time.Time, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, errors.New("mlist2.txt not written yet")
	}
	if err != nil {
		return time.Time{}, err
	}
	t, err := health.ParseGenerated(data)
	if err != nil {
		return time.Time{}, fmt.Errorf("mlist2.txt: %w", err)
	}
	return t, nil
}

// recordBounce keeps the time of a bounce for remailer addr, and forgets
// those too old to count.
func (d *Daemon) recordBounce(addr string, at time.Time) {
	err := d.st.Update(func(st *store.State) error {
		b := st.HealthState().Bounces
		maps.DeleteFunc(b, func(_ string, t time.Time) bool { return at.Sub(t) > health.BounceWindow })
		b[addr] = at.UTC()
		return nil
	})
	if err != nil {
		d.log.Error("bounce not recorded", "remailer", addr, "err", err)
	}
}

// notify mails the operator (health.notify) about the checks that are due
// (health.Due).  A failed send is tried again at the next run.
func (d *Daemon) notify(r *health.Report, now time.Time) {
	to := d.cfg.Health.Notify
	if to == "" {
		return
	}
	notified := map[string]health.Notice{}
	d.st.View(func(st *store.State) {
		if st.Health == nil {
			return
		}
		for name, n := range st.Health.Notified {
			var l health.Level
			if l.UnmarshalText([]byte(n.State)) == nil {
				notified[name] = health.Notice{State: l, Sent: n.Sent}
			}
		}
	})
	due := health.Due(r.Checks, notified, now)
	if len(due) == 0 {
		return
	}
	subject, body := health.Digest(r, due)
	from := d.cfg.Pinger.Address
	_, domain, _ := strings.Cut(from, "@")
	data, err := mailout.ComposeRequest(from, to, ascii(subject), []byte(ascii(string(body))), now, domain)
	if err == nil {
		err = d.notifier.Send(context.Background(), mailout.Mail{EnvelopeFrom: from, Rcpt: []string{to}, Data: data})
	}
	if err != nil {
		d.log.Error("health mail not sent", "to", to, "err", err)
		return
	}
	var names []string
	for _, c := range due {
		names = append(names, c.Name+"="+c.State.String())
	}
	d.log.Info("health mail sent", "to", to, "checks", strings.Join(names, " "))
	err = d.st.Update(func(st *store.State) error {
		n := st.HealthState().Notified
		for _, c := range due {
			n[c.Name] = store.Notice{State: c.State.String(), Sent: now.UTC()}
		}
		// Forget the checks that are gone (a peer taken out of the config).
		maps.DeleteFunc(n, func(name string, _ store.Notice) bool {
			return !slices.ContainsFunc(r.Checks, func(c health.Check) bool { return c.Name == name })
		})
		return nil
	})
	if err != nil {
		d.log.Error("health mail not recorded", "err", err)
	}
}

// ascii replaces what isn't printable ASCII, keeping newlines and tabs.
func ascii(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 && r <= 0x7e {
			return r
		}
		return '?'
	}, s)
}

// peerResult is what one round of fetches found for a peer.
type peerResult struct {
	generated time.Time
	err       error
	keys      []string // disagreements; nil with keysErr set: not compared
	keysErr   error
}

// CheckPeers fetches every peer's mlist2.txt and pubring.mix (design
// §10.2), all at once, and keeps what they show.
func (d *Daemon) CheckPeers(ctx context.Context, at time.Time) {
	var ours map[string]string // address -> keyid of our public keyring
	d.st.View(func(st *store.State) {
		public, _ := output.Keyrings(st, at, d.cfg.Keys.RequireProof)
		ours = map[string]string{}
		for _, k := range public {
			ours[canonical(k.Address)] = k.KeyID
		}
	})
	results := make([]peerResult, len(d.cfg.Peers))
	var wg sync.WaitGroup
	for i, p := range d.cfg.Peers {
		wg.Go(func() { results[i] = d.checkPeer(ctx, p, ours) })
	}
	wg.Wait()
	err := d.st.Update(func(st *store.State) error {
		hs := st.HealthState()
		maps.DeleteFunc(hs.Peers, func(name string, _ *store.PeerStatus) bool {
			return !slices.ContainsFunc(d.cfg.Peers, func(p config.Peer) bool { return p.Name == name })
		})
		for i, p := range d.cfg.Peers {
			res := results[i]
			ps := hs.Peers[p.Name]
			if ps == nil {
				ps = &store.PeerStatus{}
				hs.Peers[p.Name] = ps
			}
			ps.Checked = at.UTC()
			ps.Err = ""
			if res.err != nil {
				ps.Err = bounded(res.err.Error())
			} else {
				ps.Generated = res.generated
			}
			ps.KeysErr = ""
			if res.keysErr != nil {
				ps.KeysErr = bounded(res.keysErr.Error())
			} else {
				ps.Keys = res.keys
			}
		}
		return nil
	})
	if err != nil {
		d.log.Error("peer checks not saved", "err", err)
	}
	for i, p := range d.cfg.Peers {
		res := results[i]
		switch {
		case res.err != nil:
			d.log.Warn("peer not fetched", "peer", p.Name, "url", p.Mlist2, "err", res.err)
		default:
			d.log.Debug("peer fetched", "peer", p.Name, "generated", res.generated.Format(time.RFC3339))
		}
		if res.keysErr != nil {
			d.log.Info("peer pubring not fetched", "peer", p.Name, "url", p.PubringURL(), "err", res.keysErr)
		}
		for _, k := range res.keys {
			d.log.Info("peer key disagreement", "peer", p.Name, "key", k)
		}
	}
}

// checkPeer fetches one peer's files.
func (d *Daemon) checkPeer(ctx context.Context, p config.Peer, ours map[string]string) peerResult {
	var res peerResult
	data, err := d.fetch(ctx, p.Mlist2)
	if err == nil {
		res.generated, err = health.ParseGenerated(data)
	}
	res.err = err
	data, err = d.fetch(ctx, p.PubringURL())
	if err != nil {
		res.keysErr = err
		return res
	}
	theirs := replies.ParseKey(data).Keys
	if len(theirs) == 0 {
		res.keysErr = errors.New("no keys in it")
		return res
	}
	res.keys = []string{}
	for _, k := range theirs {
		if id, ok := ours[canonical(k.Address)]; ok && id != k.KeyID {
			res.keys = append(res.keys, fmt.Sprintf("%s ours %s, theirs %s", k.Address, id, k.KeyID))
		}
	}
	slices.Sort(res.keys)
	res.keys = slices.Compact(res.keys)
	if len(res.keys) > maxPeerKeys {
		res.keys = res.keys[:maxPeerKeys]
	}
	return res
}

// fetch gets url, at most maxPeerFile bytes.
func (d *Daemon) fetch(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, peerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "go-echolot/"+d.Version)
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPeerFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPeerFile {
		return nil, fmt.Errorf("%s: more than %d bytes", url, maxPeerFile)
	}
	return data, nil
}

// canonical lower-cases an address's domain, to compare addresses.
func canonical(addr string) string {
	l, dom, ok := strings.Cut(addr, "@")
	if !ok {
		return addr
	}
	return l + "@" + strings.ToLower(dom)
}
