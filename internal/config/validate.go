package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// maxTokenSuffix is the longest part a reply token adds to the local part
// of pinger.address after the delimiter (design §6.1):
// "adminkey." + 6-digit id + "=" + 10-digit time + "=" + 16 hex digits.
const maxTokenSuffix = len("adminkey.") + 6 + 1 + 10 + 1 + 16

// maxRandomGarbage keeps a ping within the pinger's size limit (8.5 KiB
// of plaintext, design §6.3; a ping stays one yamn packet): the garbage
// is at most this many hex digits.
const maxRandomGarbage = 8192

// signableFiles are the output files signing.files may name.
var signableFiles = []string{"pubring.mix", "type2.list", "mlist2.txt", "mlist.txt"}

// Validate checks c and returns every problem found.  Load calls it; call
// it again after changing a Config.
func (c *Config) Validate() error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	required := func(v, name string) bool {
		check(v != "", "%s is required", name)
		return v != ""
	}

	p := c.Pinger
	required(p.Sitename, "pinger.sitename")
	check(slices.Contains([]string{"", "+", "-"}, p.RecipientDelimiter),
		`pinger.recipient_delimiter must be "+", "-" or empty, not %q`, p.RecipientDelimiter)
	if required(p.Address, "pinger.address") {
		if err := checkPingerAddress(p.Address, p.RecipientDelimiter); err != nil {
			errs = append(errs, fmt.Errorf("pinger.address: %w", err))
		}
	}
	if required(p.OperatorAddress, "pinger.operator_address") {
		check(isBareAddress(p.OperatorAddress),
			"pinger.operator_address must be a plain address like remops@example.org, not %q", p.OperatorAddress)
	}

	errs = append(errs, c.validatePaths()...)

	check(isCommand(c.Yamn.Binary), "yamn.binary must be an absolute path or a command name, not %q", c.Yamn.Binary)
	check(c.Yamn.Timeout > 0, "yamn.timeout must be more than 0, not %s", c.Yamn.Timeout)

	errs = append(errs, c.Mail.validate()...)
	errs = append(errs, c.Schedule.validate()...)

	s := c.Stats
	check(s.Days >= 1 && s.Days <= 12, "stats.days must be 1 to 12, not %d", s.Days)
	check(len(s.Weights) == s.Days, "stats.weights needs one weight per day (stats.days = %d), not %d", s.Days, len(s.Weights))
	sum := 0.0
	for _, w := range s.Weights {
		check(w >= 0, "stats.weights must not be negative: %g", w)
		sum += w
	}
	check(sum > 0, "stats.weights must not all be 0")
	check(s.SkewAbs >= 0, "stats.skew_abs must not be negative, not %s", s.SkewAbs)
	check(s.SkewPercent > 0 && s.SkewPercent <= 1, "stats.skew_percent must be more than 0 and at most 1, not %g", s.SkewPercent)
	check(s.RandomGarbage >= 0 && s.RandomGarbage <= maxRandomGarbage,
		"stats.random_garbage must be 0 to %d bytes, not %d", maxRandomGarbage, s.RandomGarbage)

	k := c.Keys
	check(k.Retention > 0 && k.Retention <= 30*24*time.Hour,
		"keys.retention must be more than 0 and at most 720h (keys go 30 days after they were last seen), not %s", k.Retention)
	check(k.RotationWindow > 0, "keys.rotation_window must be more than 0, not %s", k.RotationWindow)
	check(k.Quarantine > 0, "keys.quarantine must be more than 0, not %s", k.Quarantine)
	check(k.MinSightings >= 1, "keys.min_sightings must be at least 1, not %d", k.MinSightings)

	check(c.Discovery.Mode == DiscoveryManual || c.Discovery.Mode == DiscoveryEcholot,
		"discovery.mode must be manual or echolot, not %q", c.Discovery.Mode)

	g := c.Signing
	check(!g.Enabled || g.KeyFile != "", "signing.key_file is required when signing.enabled is true")
	check(!g.Enabled || len(g.Files) > 0, "signing.files must not be empty when signing.enabled is true")
	for i, f := range g.Files {
		check(slices.Contains(signableFiles, f), "signing.files: %q isn't an output file; use %s", f, strings.Join(signableFiles, ", "))
		check(!slices.Contains(g.Files[:i], f), "signing.files: %q twice", f)
	}

	check(c.Health.Notify == "" || isBareAddress(c.Health.Notify),
		"health.notify must be a plain address like remops@example.org, not %q", c.Health.Notify)

	for i, peer := range c.Peers {
		check(isPeerName(peer.Name), "[peer %s]: the name may use a-z, 0-9, '.', '_' and '-', up to 32 characters", peer.Name)
		check(!slices.ContainsFunc(c.Peers[:i], func(q Peer) bool { return q.Name == peer.Name }), "[peer %s] twice", peer.Name)
		if u, err := url.Parse(peer.Mlist2); peer.Mlist2 == "" {
			errs = append(errs, fmt.Errorf("[peer %s]: mlist2 is required", peer.Name))
		} else {
			check(err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil,
				"[peer %s]: mlist2 must be an http or https URL, not %q", peer.Name, peer.Mlist2)
		}
	}

	check(c.Compat.LatencyFrom == LatencyFromDelivery || c.Compat.LatencyFrom == LatencyFromProcessing,
		"compat.latency_from must be delivery or processing, not %q", c.Compat.LatencyFrom)

	check(slices.Contains([]string{"debug", "info", "warn", "error"}, c.Log.Level),
		"log.level must be debug, info, warn or error, not %q", c.Log.Level)

	return errors.Join(errs...)
}

func (c *Config) validatePaths() []error {
	var errs []error
	pp := c.Paths
	if pp.StateDir == "" || !filepath.IsAbs(pp.StateDir) {
		// Other relative paths can't be resolved, so stop here.
		return []error{fmt.Errorf("paths.state_dir must be an absolute path, not %q", pp.StateDir)}
	}
	type opt struct{ name, path string }
	for _, o := range []opt{
		{"paths.maildir", pp.Maildir},
		{"paths.results_dir", pp.ResultsDir},
		{"paths.private_results_dir", pp.PrivateResultsDir},
	} {
		if o.path == "" {
			errs = append(errs, fmt.Errorf("%s is required", o.name))
		}
	}
	if pp.ResultsDir == "" {
		return errs
	}
	// The results dir is published.  Nothing private may be in it.
	for _, o := range []opt{
		{"paths.state_dir", pp.StateDir},
		{"paths.maildir", pp.Maildir},
		{"paths.private_results_dir", pp.PrivateResultsDir},
		{"mail.password_file", c.Mail.PasswordFile},
		{"signing.key_file", c.Signing.KeyFile},
		{"log.file", c.Log.File},
	} {
		if o.path != "" && within(o.path, pp.ResultsDir) {
			errs = append(errs, fmt.Errorf("%s (%s) must not be in paths.results_dir (%s), which is published",
				o.name, o.path, pp.ResultsDir))
		}
	}
	return errs
}

func (m Mail) validate() []error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(m.MaxPerHour >= 1, "mail.max_per_hour must be at least 1, not %d", m.MaxPerHour)
	if m.TorSocks != "" {
		host, port, err := net.SplitHostPort(m.TorSocks)
		n, perr := strconv.Atoi(port)
		check(err == nil && host != "" && perr == nil && n > 0 && n < 65536,
			"mail.tor_socks must be host:port, e.g. 127.0.0.1:9050, not %q", m.TorSocks)
	}
	switch m.Method {
	case MethodSendmail:
		check(isCommand(m.Sendmail), "mail.sendmail must be an absolute path or a command name, not %q", m.Sendmail)
	case MethodSMTP:
		check(isHost(m.SMTPRelay), "mail.smtp_relay must be a host name or IP address, not %q", m.SMTPRelay)
		check(!strings.HasSuffix(strings.ToLower(m.SMTPRelay), ".onion"),
			"mail.smtp_relay can't be a .onion host; mail for .onion remailers goes through mail.tor_socks")
		check(m.SMTPPort >= 1 && m.SMTPPort <= 65535, "mail.smtp_port must be 1 to 65535, not %d", m.SMTPPort)
		check(m.UseTLS || !m.RequireTLS, "mail.require_tls needs mail.usetls = true")
		// The same policy as yamn: plaintext SMTP only on this machine.
		check(m.UseTLS || isLoopback(m.SMTPRelay),
			"mail.usetls must be true for a relay that isn't on this machine (%s)", m.SMTPRelay)
		check((m.Username == "") == (m.PasswordFile == ""),
			"mail.username and mail.password_file must be set together")
	default:
		errs = append(errs, fmt.Errorf("mail.method must be sendmail or smtp, not %q", m.Method))
	}
	return errs
}

func (s Schedule) validate() []error {
	var errs []error
	if s.Tick < time.Minute || s.Tick%time.Second != 0 {
		return []error{fmt.Errorf("schedule.tick must be at least 1m and a whole number of seconds, not %s", s.Tick)}
	}
	// Pings and requests are spread over the slots of their period
	// (design §8.3), so the period must be a whole number of ticks.
	for _, x := range []struct {
		name string
		d    time.Duration
	}{
		{"ping_interval", s.PingInterval},
		{"key_request_interval", s.KeyRequestInterval},
		{"conf_request_interval", s.ConfRequestInterval},
		{"help_request_interval", s.HelpRequestInterval},
		{"adminkey_request_interval", s.AdminkeyRequestInterval},
	} {
		if x.d < s.Tick || x.d%s.Tick != 0 {
			errs = append(errs, fmt.Errorf("schedule.%s must be a multiple of schedule.tick (%s), not %s",
				x.name, formatDuration(s.Tick), x.d))
		}
	}
	if (7*24*time.Hour)%s.Tick != 0 {
		errs = append(errs, fmt.Errorf("schedule.tick (%s) must divide a week: the resurrection checks are weekly", formatDuration(s.Tick)))
	}
	for _, x := range []struct {
		name string
		d    time.Duration
	}{
		{"stats_interval", s.StatsInterval},
		{"pubring_check_interval", s.PubringCheckInterval},
		{"pubring_debounce", s.PubringDebounce},
	} {
		if x.d <= 0 {
			errs = append(errs, fmt.Errorf("schedule.%s must be more than 0, not %s", x.name, x.d))
		}
	}
	return errs
}

// checkPingerAddress checks the address reply tokens are made from
// (design §6.1): local@domain, with room in the local part for a token.
func checkPingerAddress(addr, delim string) error {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || strings.Contains(domain, "@") {
		return fmt.Errorf("%q isn't local@domain", addr)
	}
	if local == "" || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") ||
		strings.ContainsFunc(local, func(r rune) bool { return !isAlnum(r) && !strings.ContainsRune("._-", r) }) {
		return fmt.Errorf("local part %q may use only a-z, A-Z, 0-9, '.', '_' and '-'", local)
	}
	if delim != "" && strings.Contains(local, delim) {
		return fmt.Errorf("local part %q contains the recipient delimiter %q", local, delim)
	}
	if delim != "" && len(local)+len(delim)+maxTokenSuffix > 64 {
		return fmt.Errorf("local part %q is too long: with a reply token it must fit in 64 characters, so at most %d",
			local, 64-len(delim)-maxTokenSuffix)
	}
	if !isDomain(domain) {
		return fmt.Errorf("%q isn't a domain name", domain)
	}
	return nil
}

// isBareAddress reports whether s is an address without a display name.
func isBareAddress(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s && !strings.ContainsAny(s, "<>")
}

// isDomain reports whether s is a domain name with at least two labels.
func isDomain(s string) bool {
	labels := strings.Split(s, ".")
	if len(s) > 253 || len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' ||
			strings.ContainsFunc(l, func(r rune) bool { return !isAlnum(r) && r != '-' }) {
			return false
		}
	}
	return true
}

// isHost reports whether s is a host name or an IP address.
func isHost(s string) bool {
	return net.ParseIP(s) != nil || s == "localhost" || isDomain(s)
}

// isLoopback reports whether host is this machine, as yamn's
// isLoopbackHost (Y:mail.go:817).
func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// isCommand reports whether s is an absolute path or a bare command name,
// looked up in $PATH when it's run.
func isCommand(s string) bool {
	return s != "" && (filepath.IsAbs(s) || !strings.ContainsRune(s, '/'))
}

func isPeerName(s string) bool {
	return s != "" && len(s) <= 32 && !strings.ContainsFunc(s, func(r rune) bool {
		return !('a' <= r && r <= 'z' || '0' <= r && r <= '9' || strings.ContainsRune("._-", r))
	})
}

func isAlnum(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9'
}

// within reports whether path is dir or inside it.  Both are absolute.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
