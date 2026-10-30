// Package config reads go-echolot's config file: a small INI format
// (design §10.3), parsed with the standard library only.
//
// Every key has a default (Defaults), except the three that only the
// operator can know: pinger.sitename, pinger.address and
// pinger.operator_address.  Unknown sections and keys are errors, so a
// misspelt option doesn't pass silently.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultPath is the config file used when none is given.
const DefaultPath = "/etc/go-echolot/config.ini"

// Config is the whole config file.  The ini tags name the sections and
// keys; Format writes the sections in this order.
type Config struct {
	Pinger    Pinger    `ini:"pinger"`
	Paths     Paths     `ini:"paths"`
	Yamn      Yamn      `ini:"yamn"`
	Mail      Mail      `ini:"mail"`
	Schedule  Schedule  `ini:"schedule"`
	Stats     Stats     `ini:"stats"`
	Keys      Keys      `ini:"keys"`
	Discovery Discovery `ini:"discovery"`
	Signing   Signing   `ini:"signing"`
	Health    Health    `ini:"health"`
	Peers     []Peer    `ini:"peer"` // [peer <name>], one per peer
	Compat    Compat    `ini:"compat"`
	Log       Log       `ini:"log"`
}

// Pinger identifies this pinger.
type Pinger struct {
	Sitename           string `ini:"sitename"`            // shown on the result pages
	Address            string `ini:"address"`             // local part + domain for reply tokens
	RecipientDelimiter string `ini:"recipient_delimiter"` // "+", "-", or "" for local@domain(token)
	OperatorAddress    string `ini:"operator_address"`    // named in request mails
}

// Paths are the directories go-echolot uses.  Relative paths, here and in
// the other sections, are relative to StateDir.
type Paths struct {
	StateDir          string `ini:"state_dir"`
	Maildir           string `ini:"maildir"`
	ResultsDir        string `ini:"results_dir"` // served by the web server
	PrivateResultsDir string `ini:"private_results_dir"`
}

// Yamn is the yamn binary that builds ping packets (design §3).
type Yamn struct {
	Binary  string        `ini:"binary"`
	Timeout time.Duration `ini:"timeout"`
}

// Mail is how mail goes out (design §10.1).
type Mail struct {
	Method       string `ini:"method"`   // "sendmail" or "smtp"
	Sendmail     string `ini:"sendmail"` // for method sendmail
	SMTPRelay    string `ini:"smtp_relay"`
	SMTPPort     int    `ini:"smtp_port"`
	UseTLS       bool   `ini:"usetls"`
	RequireTLS   bool   `ini:"require_tls"`
	Username     string `ini:"username"`
	PasswordFile string `ini:"password_file"`
	MaxPerHour   int    `ini:"max_per_hour"` // abuse fuse (§8.3)
	TorSocks     string `ini:"tor_socks"`    // Tor SOCKS host:port for .onion remailers; "" = skip them
}

// Mail methods.
const (
	MethodSendmail = "sendmail"
	MethodSMTP     = "smtp"
)

// Schedule holds the periods of the jobs (design §8.3).  The slot-based
// ones (pings and requests) must be multiples of Tick.
type Schedule struct {
	Tick                    time.Duration `ini:"tick"`
	PingInterval            time.Duration `ini:"ping_interval"`
	KeyRequestInterval      time.Duration `ini:"key_request_interval"`
	ConfRequestInterval     time.Duration `ini:"conf_request_interval"`
	HelpRequestInterval     time.Duration `ini:"help_request_interval"`
	AdminkeyRequestInterval time.Duration `ini:"adminkey_request_interval"`
	StatsInterval           time.Duration `ini:"stats_interval"`
	PubringCheckInterval    time.Duration `ini:"pubring_check_interval"`
	PubringDebounce         time.Duration `ini:"pubring_debounce"`
}

// Stats are the parameters of Echolot's stats (design §8.1).
type Stats struct {
	Days          int           `ini:"days"`
	Weights       []float64     `ini:"weights"` // one per day, newest first
	SkewAbs       time.Duration `ini:"skew_abs"`
	SkewPercent   float64       `ini:"skew_percent"`
	SortByLatency bool          `ini:"sort_by_latency"`
	RandomGarbage int           `ini:"random_garbage"` // bytes of padding in a ping
}

// Keys is the key policy (design §8.4, §9.2).
type Keys struct {
	Retention      time.Duration `ini:"retention"`
	RotationWindow time.Duration `ini:"rotation_window"`
	Quarantine     time.Duration `ini:"quarantine"`
	MinSightings   int           `ini:"min_sightings"`
	RequireProof   bool          `ini:"require_proof"` // publish only keys a ping came back from
}

// Discovery is how remailers are added (design §9.3).
type Discovery struct {
	Mode string `ini:"mode"` // "manual" or "echolot"
}

// Discovery modes.
const (
	DiscoveryManual  = "manual"
	DiscoveryEcholot = "echolot"
)

// Signing is the minisign signing of output files (design §9.5).
type Signing struct {
	Enabled bool     `ini:"enabled"`
	KeyFile string   `ini:"key_file"`
	Files   []string `ini:"files"`
}

// Health is the self-monitoring (design §10.2).
type Health struct {
	Notify string `ini:"notify"` // operator address for health mails; "" = none
	// DailyStatusMail is when the daily status mail goes to Notify, in
	// UTC, as cron's first two fields: "minute [hour]", the hour 3 if
	// left out; "" = no daily mail (DailyStatus).
	DailyStatusMail string `ini:"daily_status_mail"`
}

// DefaultDailyStatusHour is the hour of the daily status mail when
// daily_status_mail gives only the minute.
const DefaultDailyStatusHour = 3

// DailyStatus returns the time of day (UTC) of the daily status mail
// from DailyStatusMail; ok is false when it is unset.
func (h Health) DailyStatus() (at time.Duration, ok bool, err error) {
	f := strings.Fields(h.DailyStatusMail)
	if len(f) == 0 {
		return 0, false, nil
	}
	if len(f) > 2 {
		return 0, false, fmt.Errorf("health.daily_status_mail must be \"minute [hour]\" like \"15 03\", not %q", h.DailyStatusMail)
	}
	minute, err := clockField(f[0], 59)
	if err != nil {
		return 0, false, fmt.Errorf("health.daily_status_mail: minute %q must be 0 to 59", f[0])
	}
	hour := DefaultDailyStatusHour
	if len(f) == 2 {
		if hour, err = clockField(f[1], 23); err != nil {
			return 0, false, fmt.Errorf("health.daily_status_mail: hour %q must be 0 to 23", f[1])
		}
	}
	return time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute, true, nil
}

// clockField parses a number from 0 to max, digits only (cron's * and
// lists aren't taken).
func clockField(s string, max int) (int, error) {
	if s == "" || len(s) > 2 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("not a number")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > max {
		return 0, fmt.Errorf("out of range")
	}
	return n, nil
}

// Peer is another pinger whose mlist2.txt is checked for staleness, and
// whose pubring.mix is compared with ours (design §10.2).
type Peer struct {
	Name    string `ini:"-"` // from [peer <name>]
	Mlist2  string `ini:"mlist2"`
	Pubring string `ini:"pubring"` // "" = pubring.mix next to mlist2 (PubringURL)
}

// PubringURL is the peer's pubring.mix: Pubring, or pubring.mix in the
// directory of Mlist2.
func (p Peer) PubringURL() string {
	if p.Pubring != "" {
		return p.Pubring
	}
	u, err := url.Parse(p.Mlist2)
	if err != nil {
		return ""
	}
	return u.ResolveReference(&url.URL{Path: "pubring.mix"}).String()
}

// Compat holds the switches back to Echolot's behaviour (design §8.4).
type Compat struct {
	MetaFiles            bool      `ini:"meta_files"`
	DropPingsWithKey     bool      `ini:"drop_pings_with_key"`
	LatencyFrom          string    `ini:"latency_from"`            // "delivery" or "processing"
	LegacyMD5TokensUntil time.Time `ini:"legacy_md5_tokens_until"` // RFC 3339; zero = none (§5.5)
}

// Latency sources.
const (
	LatencyFromDelivery   = "delivery"
	LatencyFromProcessing = "processing"
)

// Log is the logging setup (design §10.5).
type Log struct {
	Level string `ini:"level"` // debug, info, warn, error
	File  string `ini:"file"`  // "" = stderr
}

// Defaults returns the config with every default set.  It isn't valid
// until the pinger section is filled in.
func Defaults() *Config {
	return &Config{
		Pinger: Pinger{RecipientDelimiter: "+"},
		Paths: Paths{
			StateDir:          "/var/lib/go-echolot",
			Maildir:           "Maildir",
			ResultsDir:        "results",
			PrivateResultsDir: "results.private",
		},
		Yamn: Yamn{Binary: "/usr/local/bin/yamn", Timeout: 30 * time.Second},
		Mail: Mail{
			Method:     MethodSendmail,
			Sendmail:   "/usr/sbin/sendmail",
			SMTPRelay:  "localhost",
			SMTPPort:   25,
			UseTLS:     true,
			MaxPerHour: 200,
		},
		Schedule: Schedule{
			Tick:                    5 * time.Minute,
			PingInterval:            2 * time.Hour,
			KeyRequestInterval:      2 * time.Hour,
			ConfRequestInterval:     24 * time.Hour,
			HelpRequestInterval:     7 * 24 * time.Hour,
			AdminkeyRequestInterval: 7 * 24 * time.Hour,
			StatsInterval:           5 * time.Minute,
			PubringCheckInterval:    time.Hour,
			PubringDebounce:         5 * time.Minute,
		},
		Stats: Stats{
			Days:          12,
			Weights:       []float64{0.5, 1.0, 1.0, 1.0, 1.0, 0.9, 0.8, 0.5, 0.3, 0.2, 0.2, 0.1}, // E:Config.pm:200
			SkewAbs:       15 * time.Minute,
			SkewPercent:   0.8,
			RandomGarbage: 8192,
		},
		Keys: Keys{
			Retention:      5 * 24 * time.Hour,
			RotationWindow: 72 * time.Hour,
			Quarantine:     24 * time.Hour,
			MinSightings:   2,
			RequireProof:   true,
		},
		Discovery: Discovery{Mode: DiscoveryManual},
		Signing: Signing{
			KeyFile: "pinger.key",
			Files:   []string{"pubring.mix", "type2.list", "mlist2.txt"},
		},
		Compat: Compat{MetaFiles: true, LatencyFrom: LatencyFromDelivery},
		Log:    Log{Level: "info"},
	}
}

// Load reads, checks and returns the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data)
}

// Parse is Load for config data that has already been read; name is used
// in error messages.  The defaults apply to every key the data doesn't
// set.  All errors are returned, each with its line number.
func Parse(name string, data []byte) (*Config, error) {
	c := Defaults()
	secs, errs := parseINI(data)
	errs = append(errs, decode(c, secs)...)
	if len(errs) == 0 {
		c.resolvePaths()
		if err := c.Validate(); err != nil {
			errs = err.(interface{ Unwrap() []error }).Unwrap()
		}
	}
	if len(errs) > 0 {
		for i, err := range errs {
			errs[i] = fmt.Errorf("%s: %w", name, err)
		}
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// resolvePaths makes relative paths relative to Paths.StateDir.  A
// relative StateDir is left for Validate to report.
func (c *Config) resolvePaths() {
	if !filepath.IsAbs(c.Paths.StateDir) {
		return
	}
	c.Paths.StateDir = filepath.Clean(c.Paths.StateDir)
	for _, p := range c.paths() {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(c.Paths.StateDir, *p)
		}
	}
}

// paths returns the path options other than StateDir.  An empty path
// means "not set".
func (c *Config) paths() []*string {
	return []*string{
		&c.Paths.Maildir, &c.Paths.ResultsDir, &c.Paths.PrivateResultsDir,
		&c.Mail.PasswordFile, &c.Signing.KeyFile, &c.Log.File,
	}
}

// LogLevel returns Log.Level as a slog level.
func (c *Config) LogLevel() slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(c.Log.Level)); err != nil {
		return slog.LevelInfo // Validate rejects it
	}
	return l
}
