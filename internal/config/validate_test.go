package config

import (
	"strings"
	"testing"
	"time"
)

// valid returns a valid config, as loaded from minimal.
func valid(t *testing.T) *Config {
	t.Helper()
	return mustParse(t, minimal)
}

func TestValidateOK(t *testing.T) {
	for name, edit := range map[string]func(c *Config){
		"no delimiter":    func(c *Config) { c.Pinger.RecipientDelimiter = "" },
		"dash delimiter":  func(c *Config) { c.Pinger.RecipientDelimiter = "-" },
		"long local part": func(c *Config) { c.Pinger.Address = strings.Repeat("a", 20) + "@example.org" },
		"no delim, longer": func(c *Config) {
			c.Pinger.RecipientDelimiter = ""
			c.Pinger.Address = strings.Repeat("a", 40) + "@example.org"
		},
		"operator +":   func(c *Config) { c.Pinger.OperatorAddress = "remops+pinger@example.org" },
		"yamn in PATH": func(c *Config) { c.Yamn.Binary = "yamn" },
		"tor":          func(c *Config) { c.Mail.TorSocks = "127.0.0.1:9050" },
		"smtp loopback": func(c *Config) {
			c.Mail.Method, c.Mail.SMTPRelay, c.Mail.UseTLS = MethodSMTP, "::1", false
		},
		"smtp TLS": func(c *Config) {
			c.Mail.Method, c.Mail.SMTPRelay, c.Mail.RequireTLS = MethodSMTP, "mail.example.org", true
			c.Mail.Username, c.Mail.PasswordFile = "pinger", "/etc/go-echolot/smtp.pw"
		},
		"sendmail ignores smtp": func(c *Config) { c.Mail.SMTPRelay, c.Mail.UseTLS = "", false },
		"results elsewhere":     func(c *Config) { c.Paths.ResultsDir = "/var/www/yamn" },
		"results next to state": func(c *Config) { c.Paths.ResultsDir = "/var/lib/go-echolot-www" },
		"signing":               func(c *Config) { c.Signing.Enabled = true; c.Signing.Files = []string{"mlist.txt"} },
		"peer": func(c *Config) {
			c.Peers = []Peer{{"mixmin", "https://www.mixmin.net/yamn/mlist2.txt"}, {"victor-2.b_c", "http://x.example/m"}}
		},
		"3 days": func(c *Config) { c.Stats.Days, c.Stats.Weights = 3, []float64{1, 0, 0} },
		"slots":  func(c *Config) { c.Schedule.Tick, c.Schedule.PingInterval = 90*time.Second, 3*time.Minute },
	} {
		c := valid(t)
		edit(c)
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateErrors(t *testing.T) {
	for _, tc := range []struct {
		edit func(c *Config)
		want string
	}{
		{func(c *Config) { c.Pinger.Sitename = "" }, "pinger.sitename is required"},
		{func(c *Config) { c.Pinger.Address = "pinger" }, `pinger.address: "pinger" isn't local@domain`},
		{func(c *Config) { c.Pinger.Address = "a@b@example.org" }, "isn't local@domain"},
		{func(c *Config) { c.Pinger.Address = "pin ger@example.org" }, "local part \"pin ger\" may use only"},
		{func(c *Config) { c.Pinger.Address = ".pinger@example.org" }, "may use only"},
		{func(c *Config) { c.Pinger.Address = "pin..ger@example.org" }, "may use only"},
		{func(c *Config) { c.Pinger.Address = "@example.org" }, "may use only"},
		{func(c *Config) { c.Pinger.Address = "pinger@localhost" }, `"localhost" isn't a domain name`},
		{func(c *Config) { c.Pinger.Address = "pinger@example..org" }, "isn't a domain name"},
		{func(c *Config) { c.Pinger.Address = "pinger@-x.example.org" }, "isn't a domain name"},
		{func(c *Config) { c.Pinger.Address = "pinger@example.org." }, "isn't a domain name"},
		{func(c *Config) { c.Pinger.Address = "ping-er@example.org"; c.Pinger.RecipientDelimiter = "-" }, "contains the recipient delimiter"},
		{func(c *Config) { c.Pinger.Address = strings.Repeat("a", 21) + "@example.org" }, "too long"},
		{func(c *Config) { c.Pinger.RecipientDelimiter = "=" }, "pinger.recipient_delimiter must be"},
		{func(c *Config) { c.Pinger.OperatorAddress = "" }, "pinger.operator_address is required"},
		{func(c *Config) { c.Pinger.OperatorAddress = "Remops <remops@example.org>" }, "pinger.operator_address must be a plain address"},
		{func(c *Config) { c.Pinger.OperatorAddress = "remops" }, "pinger.operator_address must be a plain address"},

		{func(c *Config) { c.Paths.StateDir = "var/lib/go-echolot" }, "paths.state_dir must be an absolute path"},
		{func(c *Config) { c.Paths.Maildir = "" }, "paths.maildir is required"},
		{func(c *Config) { c.Paths.ResultsDir = "" }, "paths.results_dir is required"},
		{func(c *Config) { c.Paths.PrivateResultsDir = "" }, "paths.private_results_dir is required"},
		{func(c *Config) { c.Paths.ResultsDir = "/var/lib/go-echolot" }, "paths.state_dir (/var/lib/go-echolot) must not be in paths.results_dir"},
		{func(c *Config) { c.Paths.ResultsDir = "/var/lib" }, "paths.state_dir (/var/lib/go-echolot) must not be in"},
		{func(c *Config) { c.Paths.ResultsDir = "/" }, "paths.state_dir (/var/lib/go-echolot) must not be in"},
		{func(c *Config) { c.Paths.PrivateResultsDir = c.Paths.ResultsDir }, "paths.private_results_dir"},
		{func(c *Config) { c.Paths.ResultsDir = "/var/www"; c.Paths.Maildir = "/var/www/Maildir" }, "paths.maildir (/var/www/Maildir) must not be in"},
		{func(c *Config) { c.Paths.ResultsDir = "/var/www"; c.Signing.KeyFile = "/var/www/yamn/pinger.key" }, "signing.key_file"},
		{func(c *Config) { c.Paths.ResultsDir = "/var/www"; c.Mail.PasswordFile = "/var/www/pw" }, "mail.password_file"},
		{func(c *Config) { c.Paths.ResultsDir = "/var/log"; c.Log.File = "/var/log/go-echolot.log" }, "log.file"},

		{func(c *Config) { c.Yamn.Binary = "" }, "yamn.binary must be"},
		{func(c *Config) { c.Yamn.Binary = "bin/yamn" }, "yamn.binary must be"},
		{func(c *Config) { c.Yamn.Timeout = 0 }, "yamn.timeout must be more than 0"},

		{func(c *Config) { c.Mail.Method = "pipe" }, "mail.method must be sendmail or smtp"},
		{func(c *Config) { c.Mail.Sendmail = "" }, "mail.sendmail must be"},
		{func(c *Config) { c.Mail.MaxPerHour = 0 }, "mail.max_per_hour must be at least 1"},
		{func(c *Config) { c.Mail.Method, c.Mail.SMTPRelay = MethodSMTP, "" }, "mail.smtp_relay must be"},
		{func(c *Config) { c.Mail.Method, c.Mail.SMTPRelay = MethodSMTP, "mail.example.org:25" }, "mail.smtp_relay must be"},
		{func(c *Config) { c.Mail.Method, c.Mail.SMTPPort = MethodSMTP, 0 }, "mail.smtp_port must be 1 to 65535"},
		{func(c *Config) { c.Mail.Method, c.Mail.SMTPPort = MethodSMTP, 65536 }, "mail.smtp_port must be 1 to 65535"},
		{func(c *Config) { c.Mail.Method, c.Mail.UseTLS, c.Mail.RequireTLS = MethodSMTP, false, true }, "mail.require_tls needs mail.usetls = true"},
		{func(c *Config) {
			c.Mail.Method, c.Mail.SMTPRelay, c.Mail.UseTLS = MethodSMTP, "mail.example.org", false
		}, "mail.usetls must be true for a relay that isn't on this machine (mail.example.org)"},
		{func(c *Config) { c.Mail.Method, c.Mail.Username = MethodSMTP, "pinger" }, "mail.username and mail.password_file must be set together"},
		{func(c *Config) { c.Mail.Method, c.Mail.PasswordFile = MethodSMTP, "/etc/pw" }, "must be set together"},
		{func(c *Config) { c.Mail.TorSocks = "9050" }, "mail.tor_socks must be host:port"},
		{func(c *Config) { c.Mail.TorSocks = ":9050" }, "mail.tor_socks must be host:port"},
		{func(c *Config) { c.Mail.TorSocks = "127.0.0.1:99999" }, "mail.tor_socks must be host:port"},
		{func(c *Config) { c.Mail.TorSocks = "127.0.0.1:tor" }, "mail.tor_socks must be host:port"},

		{func(c *Config) { c.Schedule.Tick = 30 * time.Second }, "schedule.tick must be at least 1m"},
		{func(c *Config) { c.Schedule.Tick = time.Minute + time.Millisecond }, "whole number of seconds"},
		{func(c *Config) { c.Schedule.PingInterval = 7 * time.Minute }, "schedule.ping_interval must be a multiple of schedule.tick (5m), not 7m0s"},
		{func(c *Config) { c.Schedule.KeyRequestInterval = 0 }, "schedule.key_request_interval must be a multiple"},
		{func(c *Config) { c.Schedule.ConfRequestInterval = -5 * time.Minute }, "schedule.conf_request_interval"},
		{func(c *Config) { c.Schedule.HelpRequestInterval = time.Minute }, "schedule.help_request_interval"},
		{func(c *Config) { c.Schedule.AdminkeyRequestInterval = 0 }, "schedule.adminkey_request_interval"},
		{func(c *Config) { c.Schedule.StatsInterval = 0 }, "schedule.stats_interval must be more than 0"},
		{func(c *Config) { c.Schedule.PubringCheckInterval = 0 }, "schedule.pubring_check_interval must be more than 0"},
		{func(c *Config) { c.Schedule.PubringDebounce = -time.Second }, "schedule.pubring_debounce must be more than 0"},

		{func(c *Config) { c.Stats.Days = 13 }, "stats.days must be 1 to 12"},
		{func(c *Config) { c.Stats.Days = 0 }, "stats.days must be 1 to 12"},
		{func(c *Config) { c.Stats.Weights = c.Stats.Weights[1:] }, "stats.weights needs one weight per day (stats.days = 12), not 11"},
		{func(c *Config) { c.Stats.Weights[3] = -1 }, "stats.weights must not be negative"},
		{func(c *Config) { c.Stats.Weights = make([]float64, 12) }, "stats.weights must not all be 0"},
		{func(c *Config) { c.Stats.SkewAbs = -time.Second }, "stats.skew_abs must not be negative"},
		{func(c *Config) { c.Stats.SkewPercent = 0 }, "stats.skew_percent must be more than 0 and at most 1"},
		{func(c *Config) { c.Stats.SkewPercent = 1.5 }, "stats.skew_percent"},
		{func(c *Config) { c.Stats.RandomGarbage = -1 }, "stats.random_garbage must be 0 to 10240"},
		{func(c *Config) { c.Stats.RandomGarbage = 10241 }, "stats.random_garbage"},

		{func(c *Config) { c.Keys.Retention = 0 }, "keys.retention must be more than 0"},
		{func(c *Config) { c.Keys.Retention = 721 * time.Hour }, "at most 720h"},
		{func(c *Config) { c.Keys.RotationWindow = 0 }, "keys.rotation_window must be more than 0"},
		{func(c *Config) { c.Keys.Quarantine = 0 }, "keys.quarantine must be more than 0"},
		{func(c *Config) { c.Keys.MinSightings = 0 }, "keys.min_sightings must be at least 1"},

		{func(c *Config) { c.Discovery.Mode = "auto" }, "discovery.mode must be manual or echolot"},

		{func(c *Config) { c.Signing.Enabled, c.Signing.KeyFile = true, "" }, "signing.key_file is required"},
		{func(c *Config) { c.Signing.Enabled, c.Signing.Files = true, nil }, "signing.files must not be empty"},
		{func(c *Config) { c.Signing.Files = []string{"pubring.mix", "rlist2.txt"} }, `signing.files: "rlist2.txt" isn't an output file`},
		{func(c *Config) { c.Signing.Files = []string{"mlist2.txt", "mlist2.txt"} }, `signing.files: "mlist2.txt" twice`},

		{func(c *Config) { c.Health.Notify = "remops" }, "health.notify must be a plain address"},

		{func(c *Config) { c.Peers = []Peer{{"Mixmin", "https://x.example/m"}} }, "[peer Mixmin]: the name may use"},
		{func(c *Config) { c.Peers = []Peer{{strings.Repeat("a", 33), "https://x.example/m"}} }, "up to 32 characters"},
		{func(c *Config) { c.Peers = []Peer{{"a", "https://x.example/m"}, {"a", "https://y.example/m"}} }, "[peer a] twice"},
		{func(c *Config) { c.Peers = []Peer{{"a", ""}} }, "[peer a]: mlist2 is required"},
		{func(c *Config) { c.Peers = []Peer{{"a", "ftp://x.example/m"}} }, "[peer a]: mlist2 must be an http or https URL"},
		{func(c *Config) { c.Peers = []Peer{{"a", "https:///m"}} }, "must be an http or https URL"},
		{func(c *Config) { c.Peers = []Peer{{"a", "https://u:p@x.example/m"}} }, "must be an http or https URL"},
		{func(c *Config) { c.Peers = []Peer{{"a", "x.example/m"}} }, "must be an http or https URL"},

		{func(c *Config) { c.Compat.LatencyFrom = "" }, "compat.latency_from must be delivery or processing"},
		{func(c *Config) { c.Log.Level = "INFO" }, "log.level must be debug, info, warn or error"},
	} {
		c := valid(t)
		tc.edit(c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("got %v, want an error with %q", err, tc.want)
		}
	}
}

// TestValidateAll checks that Validate reports every problem, not only
// the first.
func TestValidateAll(t *testing.T) {
	c := valid(t)
	c.Pinger.Sitename = ""
	c.Mail.MaxPerHour = 0
	c.Log.Level = "loud"
	err := c.Validate()
	if n := strings.Count(err.Error(), "\n") + 1; n != 3 {
		t.Errorf("got %d errors, want 3:\n%v", n, err)
	}
}
