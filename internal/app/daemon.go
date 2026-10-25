package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-while/go-echolot/internal/chain"
	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/health"
	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/mailin"
	"github.com/go-while/go-echolot/internal/mailout"
	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/pinger"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/sched"
	"github.com/go-while/go-echolot/internal/sdnotify"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/store/echolotimport"
	"github.com/go-while/go-echolot/internal/token"
)

// Job names.
const (
	jobTick     = "tick"     // requests and pings, every schedule.tick
	jobStats    = "stats"    // mlist2.txt and mlist.txt, every schedule.stats_interval
	jobMail     = "mail"     // Maildir scan, every minute
	jobPubring  = "pubring"  // keyrings, debounced after a key change
	jobPubCheck = "pubcheck" // keyrings, every schedule.pubring_check_interval
	jobDaily    = "daily"    // expiry and pruning
	jobCommands = "commands" // the command spool, every 10 s and on SIGHUP
)

const (
	mailInterval     = time.Minute
	commandsInterval = 10 * time.Second
	commandsDelay    = time.Second // after a SIGHUP
	keyringMetaTTL   = time.Hour   // .meta Expires of the keyrings (design §7.2)
	pingRetention    = 12 * 24 * time.Hour
	maxLoggedErrors  = 5 // per reply: a reply is attacker-controlled text
)

// bounded cuts s for the log.
func bounded(s string) string {
	const n = 200
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Daemon is the running pinger: `go-echolot run`.
type Daemon struct {
	Version string // shown on the HTML pages

	cfg      *config.Config
	st       *store.Store
	minter   *token.Minter
	mailer   mailout.Mailer
	log      *slog.Logger
	clock    sched.Clock
	loop     *sched.Loop
	scanner  *mailin.Scanner
	schedKey [32]byte
	encoder  pinger.Encoder
	macKey   [32]byte // ping MAC (§6.3)
	boxKey   [32]byte // ping secretbox

	tokMu   sync.Mutex
	lastTok map[string]int64 // kind.id -> last token time minted, unix

	tickBudget time.Duration // how long a request tick may take: schedule.tick

	chainRes chain.Result // the last evaluation of the chains (§8.2)
	chainAt  time.Time    // when it was made; zero: not yet

	signer *signer // nil: signing is off (§9.5)

	health     healthState    // for the checks (§10.2)
	notifier   mailout.Mailer // health mails: not counted as sends
	httpClient *http.Client   // the peers' files
}

// NewDaemon returns the daemon for cfg on the open store st.  mailer sends
// the requests (already rate-limited by the caller).  clock may be nil.
func NewDaemon(cfg *config.Config, st *store.Store, mailer mailout.Mailer, log *slog.Logger, clock sched.Clock) (*Daemon, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if clock == nil {
		clock = sched.RealClock()
	}
	m, err := NewMinter(cfg, st.Dir(), st.Secret())
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		cfg: cfg, st: st, minter: m, log: log, clock: clock,
		loop:     sched.New(clock, log),
		schedKey: token.DeriveKey(st.Secret(), token.PurposeSched),
		lastTok:  map[string]int64{},

		tickBudget: cfg.Schedule.Tick,
		macKey:     token.DeriveKey(st.Secret(), token.PurposePingMAC),
		boxKey:     token.DeriveKey(st.Secret(), token.PurposePingBox),
		encoder: &pinger.YamnEncoder{Binary: cfg.Yamn.Binary, Timeout: cfg.Yamn.Timeout,
			Sender: cfg.Pinger.Address, Log: log},
	}
	d.health.started = clock.Now()
	d.notifier = mailer
	d.mailer = countingMailer{m: mailer, w: &d.health.sends, now: clock.Now}
	d.httpClient = &http.Client{Timeout: peerTimeout}
	if d.signer, err = newSigner(cfg, st, log); err != nil {
		return nil, err
	}
	d.scanner = &mailin.Scanner{
		Maildir:   cfg.Paths.Maildir,
		ErrorsDir: filepath.Join(cfg.Paths.StateDir, "mail-errors"),
		Minter:    m,
		Handler:   d,
		Log:       log,
		Now:       clock.Now,
		// Retry transient failures (a full disk, say) for a day, not 60
		// scans: the scan runs every minute.
		MaxTries: int(mailin.DefaultRetryFor/mailInterval) + 1,
		RetryFor: mailin.DefaultRetryFor,
	}
	return d, nil
}

// NewMinter returns the reply token minter for cfg and the store's secret.
// After import-echolot, Echolot's MD5 tokens are accepted on request
// replies until the time import-echolot recorded, or
// compat.legacy_md5_tokens_until if that is set (§5.5).
func NewMinter(cfg *config.Config, stateDir string, secret []byte) (*token.Minter, error) {
	legacy, until, err := echolotimport.ReadLegacy(stateDir)
	if err != nil {
		return nil, err
	}
	if !cfg.Compat.LegacyMD5TokensUntil.IsZero() {
		until = cfg.Compat.LegacyMD5TokensUntil
	}
	return token.New(token.Config{
		Secret:       secret,
		Address:      cfg.Pinger.Address,
		Delimiter:    cfg.Pinger.RecipientDelimiter,
		LegacySecret: legacy,
		LegacyUntil:  until,
	})
}

// Run runs the jobs until ctx is cancelled.  hup delivers SIGHUPs: each
// one runs the command spool soon.  The caller must handle SIGHUP before
// opening the store; Run then marks the lock as the daemon's, so CLI
// commands spool for it and signal it.
func (d *Daemon) Run(ctx context.Context, hup <-chan os.Signal) error {
	if err := d.st.MarkDaemon(); err != nil {
		return err
	}
	s := d.cfg.Schedule
	d.loop.Every(jobTick, s.Tick, d.Tick)
	d.loop.Every(jobStats, s.StatsInterval, func(_ context.Context, at time.Time) { d.BuildStats(at) })
	d.loop.Every(jobMail, mailInterval, func(ctx context.Context, _ time.Time) { d.ScanMail(ctx) })
	d.loop.Every(jobPubCheck, s.PubringCheckInterval, func(ctx context.Context, at time.Time) { d.BuildKeys(at) })
	d.loop.Debounced(jobPubring, s.PubringDebounce, func(ctx context.Context, at time.Time) { d.BuildKeys(at) })
	d.loop.Every(jobDaily, 24*time.Hour, func(ctx context.Context, at time.Time) { d.Daily(at) })
	d.loop.Every(jobCommands, commandsInterval, func(ctx context.Context, at time.Time) { d.Commands(ctx, at) })
	d.loop.Debounced("hup", commandsDelay, func(ctx context.Context, at time.Time) { d.Commands(ctx, at) })
	d.loop.Every(jobHealth, s.Tick, func(ctx context.Context, _ time.Time) { d.Health(ctx, d.clock.Now()) })
	d.loop.Every(jobHourly, health.PeerInterval, d.Hourly)
	d.loop.Debounced(jobHourlyNow, hourlyDelay, d.Hourly)
	// The watchdog is fed whenever a job completes: the loop runs every
	// job in one goroutine, so a stuck job starves it and systemd
	// restarts the daemon.  A request tick is limited to one tick
	// (Requests), so WatchdogSec must be well over twice schedule.tick.
	d.loop.OnTick(func(string, time.Time) { sdnotify.Notify(sdnotify.Watchdog) })
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				d.loop.Trigger("hup")
			}
		}
	}()
	d.markStart(d.clock.Now())
	// pinger.pub at once, and the keyrings a pubring_debounce after the
	// start instead of at the next pubring_check_interval, so a new
	// pinger's files are there within minutes.
	if err := d.signer.writePingerKey(d.cfg.Paths.ResultsDir); err != nil {
		d.log.Error("pinger.pub not written", "err", err)
	}
	d.loop.Trigger(jobPubring)
	d.SelfTest(ctx, d.clock.Now())
	if len(d.cfg.Peers) > 0 {
		d.loop.Trigger(jobHourlyNow) // the peers' first fetch, not at the next full hour
	}
	sdnotify.Notify(sdnotify.Ready)
	d.log.Info("go-echolot running", "state_dir", d.cfg.Paths.StateDir)
	err := d.loop.Run(ctx)
	sdnotify.Notify(sdnotify.Stopping)
	return err
}

// Tick runs one scheduler tick: the requests, then the pings due at.
// What's left after one tick waits for its next slot, so slow or
// tarpitting remailers can't hold the job loop (and the watchdog).
func (d *Daemon) Tick(ctx context.Context, at time.Time) {
	ctx, cancel := context.WithTimeout(ctx, d.tickBudget)
	defer cancel()
	d.Requests(ctx, at, nil, false)
	if ctx.Err() == nil {
		d.Pings(ctx, at, nil, false)
	}
	if ctx.Err() == nil {
		d.ChainPings(ctx, at, nil, false)
	}
}

// Requests sends the requests due at the tick at (design §6.2, §8.3).
// With only set, it sends key and conf requests now to those addresses
// (or all with fetch on when only is empty and now is true): getkeyconf.
func (d *Daemon) Requests(ctx context.Context, at time.Time, only []string, now bool) {
	type req struct {
		id   int
		addr string
		kind token.Kind
	}
	var due []req
	s := d.cfg.Schedule
	d.st.View(func(st *store.State) {
		for _, addr := range slices.Sorted(maps.Keys(st.Remailers)) {
			r := st.Remailers[addr]
			if !r.Fetch || len(only) > 0 && !slices.ContainsFunc(only, func(a string) bool { return keys.SameAddress(a, addr) }) {
				continue
			}
			if now {
				for _, k := range []token.Kind{token.KindKey, token.KindConf} {
					due = append(due, req{r.ID, addr, k})
				}
				continue
			}
			var kinds []token.Kind
			var periods []time.Duration
			switch r.Status {
			case store.StatusActive:
				kinds = []token.Kind{token.KindKey, token.KindConf, token.KindHelp, token.KindAdminkey}
				periods = []time.Duration{s.KeyRequestInterval, s.ConfRequestInterval, s.HelpRequestInterval, s.AdminkeyRequestInterval}
			case store.StatusTTLTimeout: // weekly resurrection checks (§6.2)
				kinds = []token.Kind{token.KindKey, token.KindConf}
				periods = []time.Duration{7 * 24 * time.Hour, 7 * 24 * time.Hour}
			}
			for i, k := range kinds {
				if sched.Due(d.schedKey, addr+"|"+string(k), at, periods[i], s.Tick) {
					due = append(due, req{r.ID, addr, k})
				}
			}
		}
	})
	for i, q := range due {
		err := d.sendRequest(ctx, q.id, q.addr, q.kind)
		if ctx.Err() != nil {
			d.log.Warn("tick over: requests left for their next slot", "remailer", q.addr, "kind", q.kind, "left", len(due)-i)
			return
		}
		switch {
		case errors.Is(err, mailout.ErrOnionWithoutTor):
			d.log.Info("skipping .onion remailer: mail.tor_socks is not set", "remailer", q.addr)
			continue
		case errors.Is(err, mailout.ErrRateLimited):
			d.log.Warn("mail.max_per_hour reached: requests left for their next slot", "left", len(due)-i)
			return
		case mailout.IsPermanent(err):
			// The remailer's side refused it: like a bounce, it counts
			// as a request without a reply (Y-41: no retrying for days).
			d.log.Warn("request refused", "remailer", q.addr, "kind", q.kind, "err", err)
		case err != nil:
			d.log.Warn("request not sent", "remailer", q.addr, "kind", q.kind, "err", err)
			continue // our failure, not the remailer's: no TTL change
		default:
			d.log.Debug("request sent", "remailer", q.addr, "kind", q.kind)
		}
		if q.kind != token.KindConf || now {
			continue // TTLs count scheduled conf requests only
		}
		err = d.st.Update(func(st *store.State) error {
			if r := st.RemailerByID(q.id); r != nil {
				changed := false
				if r.Status == store.StatusTTLTimeout {
					changed = keys.DecreaseResurrectionTTL(r)
				} else {
					changed = keys.DecreaseTTL(r)
				}
				if changed {
					d.log.Warn("remailer state changed", "remailer", r.Address, "status", r.Status)
				}
			}
			return nil
		})
		if err != nil {
			d.log.Error("TTL not saved", "remailer", q.addr, "err", err)
		}
	}
}

// tokenTime returns the time for a new token of kind for remailer id:
// now, but always later than the last one, so no token address is ever
// used twice (yamn answers each address once a day, §9.4).
func (d *Daemon) tokenTime(kind token.Kind, id int) time.Time {
	d.tokMu.Lock()
	defer d.tokMu.Unlock()
	k := fmt.Sprintf("%s.%d", kind, id)
	t := max(d.clock.Now().Unix(), d.lastTok[k]+1)
	d.lastTok[k] = t
	return time.Unix(t, 0).UTC()
}

// sendRequest sends one remailer-<kind> request, from a new token address
// (never reused: yamn answers each address once a day, §9.4) with a VERP
// bounce address as the envelope sender.
func (d *Daemon) sendRequest(ctx context.Context, id int, addr string, kind token.Kind) error {
	now := d.tokenTime(kind, id)
	from, err := d.minter.Address(token.Token{Kind: kind, ID: id, Time: now})
	if err != nil {
		return err
	}
	envelope := d.cfg.Pinger.Address
	if d.cfg.Pinger.RecipientDelimiter != "" {
		if envelope, err = d.minter.Address(token.Token{Kind: token.KindBounce, ID: id, Time: d.tokenTime(token.KindBounce, id)}); err != nil {
			return err
		}
	}
	_, domain, _ := strings.Cut(d.cfg.Pinger.Address, "@")
	body := mailout.RequestText(addr, d.cfg.Pinger.OperatorAddress)
	data, err := mailout.ComposeRequest(from, addr, "remailer-"+string(kind), body, now, domain)
	if err != nil {
		return err
	}
	return d.mailer.Send(ctx, mailout.Mail{EnvelopeFrom: envelope, Rcpt: []string{addr}, Data: data})
}

// ScanMail processes the replies in the Maildir.
func (d *Daemon) ScanMail(ctx context.Context) {
	res, err := d.scanner.Scan(ctx)
	if err != nil {
		d.log.Error("mailbox scan", "err", err)
		return
	}
	d.health.scanned(d.clock.Now())
	if res.Handled+res.Rejected+res.Pending > 0 {
		d.log.Info("mailbox scanned", "handled", res.Handled, "rejected", res.Rejected, "pending", res.Pending)
	}
}

// Handle handles one reply with a valid token (mailin.Handler).  Errors
// that more tries won't fix are permanent: the mail goes to mail-errors.
func (d *Daemon) Handle(ctx context.Context, tok token.Token, m *mailin.Message) error {
	now := d.clock.Now()
	switch tok.Kind {
	case token.KindPing:
		return d.receivePing(tok, m)
	case token.KindChainping:
		return d.receiveChainPing(tok, m)
	case token.KindBounce:
		var addr string
		d.st.View(func(st *store.State) {
			if r := st.RemailerByID(tok.ID); r != nil {
				addr = r.Address
			}
		})
		d.log.Warn("bounce", "remailer", addr, "id", tok.ID, "sent", tok.Time.Format(time.RFC3339))
		if addr != "" {
			at := m.Delivered
			if at.IsZero() || at.After(now) {
				at = now
			}
			d.recordBounce(addr, at)
		}
		// Kept in mail-errors for the operator (§9.4), not processed.
		return mailin.Permanent(fmt.Errorf("bounce for remailer id %d (%s)", tok.ID, addr))
	}
	body, err := replies.Body(m.Header, m.Body)
	if err != nil {
		return mailin.Permanent(err)
	}
	var known bool
	d.st.View(func(st *store.State) { known = st.RemailerByID(tok.ID) != nil })
	if !known {
		return mailin.Permanent(fmt.Errorf("reply for remailer id %d, which isn't known", tok.ID))
	}
	if err := SaveThesaurus(d.cfg.Paths.StateDir, tok.ID, tok.Kind, body, tok.Time); err != nil {
		return err // transient: try again next scan
	}
	if replies.IsNotARemailer(body) {
		return d.st.Update(func(st *store.State) error {
			if r := st.RemailerByID(tok.ID); r != nil {
				keys.MarkNotARemailer(r)
				d.log.Warn("remailer says it is not a remailer; requests and pings stopped", "remailer", r.Address)
			}
			return nil
		})
	}
	var results []keys.Result
	switch tok.Kind {
	case token.KindKey:
		kr := replies.ParseKey(body)
		for i, e := range kr.Errors {
			if i == maxLoggedErrors {
				d.log.Info("key reply: more keys skipped", "id", tok.ID, "more", len(kr.Errors)-i)
				break
			}
			d.log.Info("key reply: skipped a key", "id", tok.ID, "err", bounded(e.Error()))
		}
		err = d.st.Update(func(st *store.State) error {
			if r := st.RemailerByID(tok.ID); r != nil {
				results = keys.ApplyKeyReply(st, r, kr.Keys, tok.Time, m.Delivered, now, d.cfg.Keys)
			}
			return nil
		})
	case token.KindConf:
		conf, perr := replies.ParseConf(body)
		if perr != nil {
			return mailin.Permanent(perr)
		}
		err = d.st.Update(func(st *store.State) error {
			if r := st.RemailerByID(tok.ID); r != nil {
				results = keys.ApplyConfReply(st, r, conf, tok.Time, m.Delivered, now, d.cfg.Keys)
			}
			return nil
		})
	default: // help, adminkey: the thesaurus is all
		return nil
	}
	if err != nil {
		return err
	}
	d.logResults(results)
	return nil
}

// logResults logs key policy decisions, and rebuilds the keyrings after
// one that can change them.
func (d *Daemon) logResults(results []keys.Result) {
	rebuild := false
	for _, r := range results {
		lvl := slog.LevelInfo
		switch r.Decision {
		case keys.Seen, keys.Ignored:
			lvl = slog.LevelDebug
		case keys.Quarantined, keys.Rejected:
			lvl = slog.LevelWarn
		}
		d.log.Log(context.Background(), lvl, "key policy", "remailer", r.Address, "keyid", r.KeyID, "decision", r.Decision, "reason", r.Reason)
		switch r.Decision {
		case keys.Accepted, keys.Rotation, keys.Applied, keys.Expired, keys.Seen:
			rebuild = true
		}
	}
	if rebuild {
		d.loop.Trigger(jobPubring)
	}
}

// BuildKeys applies the pending changes whose time has come and writes
// the public and private keyrings (design §7.1).
func (d *Daemon) BuildKeys(at time.Time) {
	var results []keys.Result
	if err := d.st.Update(func(st *store.State) error {
		results = keys.ResolvePending(st, at, d.cfg.Keys)
		return nil
	}); err != nil {
		d.log.Error("pending changes", "err", err)
	}
	for _, r := range results {
		d.log.Info("key policy", "remailer", r.Address, "keyid", r.KeyID, "decision", r.Decision, "reason", r.Reason)
	}
	var public, private []replies.ParsedKey
	d.st.View(func(st *store.State) { public, private = output.Keyrings(st, at, d.cfg.Keys.RequireProof) })
	// Only the public files are signed: clients fetch those.
	for _, w := range []struct {
		dir  string
		ks   []replies.ParsedKey
		sign output.SignFunc
	}{{d.cfg.Paths.ResultsDir, public, d.signer.sign(at)}, {d.cfg.Paths.PrivateResultsDir, private, nil}} {
		if err := os.MkdirAll(w.dir, 0o755); err != nil {
			d.log.Error("keyring", "dir", w.dir, "err", err)
			continue
		}
		changed, err := output.WriteKeyrings(w.dir, w.ks, at, d.cfg.Compat.MetaFiles, keyringMetaTTL, w.sign)
		switch {
		case err != nil:
			d.log.Error("keyring not written", "dir", w.dir, "err", err)
		case changed:
			d.log.Info("keyring written", "dir", w.dir, "keys", len(w.ks))
		}
	}
	if err := d.signer.writePingerKey(d.cfg.Paths.ResultsDir); err != nil {
		d.log.Error("pinger.pub not written", "err", err)
	}
}

// Daily expires keys, confs, suggestions and pending changes, and prunes
// the old files (design §5.1).
func (d *Daemon) Daily(at time.Time) {
	var results []keys.Result
	var ids map[int]bool
	if err := d.st.Update(func(st *store.State) error {
		results = keys.Expire(st, at, d.cfg.Keys)
		expireFromlines(st, at)
		ids = map[int]bool{}
		for _, r := range st.Remailers {
			ids[r.ID] = true
		}
		return nil
	}); err != nil {
		d.log.Error("expiry", "err", err)
	}
	d.logResults(results)
	if err := d.st.Compact(at.Add(-pingRetention)); err != nil {
		d.log.Error("ping journal compaction", "err", err)
	}
	if err := d.st.CompactChains(at.Add(-chain.Expire)); err != nil {
		d.log.Error("chain ping journal compaction", "err", err)
	}
	if n, err := mailin.PruneErrors(d.scanner.ErrorsDir, at, mailin.ErrorRetention); err != nil {
		d.log.Error("mail-errors", "err", err)
	} else if n > 0 {
		d.log.Info("old mail errors removed", "files", n)
	}
	if _, err := PruneThesaurus(d.cfg.Paths.StateDir, at, func(id int) bool { return ids[id] }); err != nil {
		d.log.Error("thesaurus", "err", err)
	}
}

// Commands runs the spooled commands.
func (d *Daemon) Commands(ctx context.Context, at time.Time) {
	cmds, errs := ReadSpool(d.cfg.Paths.StateDir)
	for _, err := range errs {
		d.log.Warn("command spool", "err", err)
	}
	for _, c := range cmds {
		if err := c.Start(); err != nil { // at most once, even after a crash
			d.log.Error("command spool", "err", err)
			continue
		}
		d.Command(ctx, c.Command, at)
		if err := c.Done(); err != nil {
			d.log.Error("command spool", "err", err)
		}
	}
}

// Command runs one operator command in the daemon and returns what to
// tell the operator.
func (d *Daemon) Command(ctx context.Context, c Command, at time.Time) []string {
	var out []string
	// Manual sends get a tick's budget too: they run in the job loop.
	ctx, cancel := context.WithTimeout(ctx, d.tickBudget)
	defer cancel()
	switch c.Verb {
	case "getkeyconf":
		d.Requests(ctx, at, c.Args, true)
		out = []string{"requests sent"}
	case "buildkeys":
		d.BuildKeys(at)
		out = []string{"keyrings built"}
	case "sendpings":
		d.Pings(ctx, at, c.Args, true)
		out = []string{"pings sent"}
	case "sendchainpings":
		d.ChainPings(ctx, at, c.Args, true)
		out = []string{"chain pings sent"}
	case "buildstats":
		d.BuildStats(at)
		out = []string{"stats written"}
	default:
		err := d.st.Update(func(st *store.State) error {
			var err error
			out, err = Apply(st, c, at)
			return err
		})
		if err != nil {
			d.log.Warn("command failed", "command", c.String(), "err", err)
			return []string{"error: " + err.Error()}
		}
		d.loop.Trigger(jobPubring)
	}
	d.log.Info("command", "command", c.String(), "result", strings.Join(out, "; "))
	return out
}
