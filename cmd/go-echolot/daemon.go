package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-while/go-echolot/internal/app"
	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/mailin"
	"github.com/go-while/go-echolot/internal/mailout"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/store/echolotimport"
)

// stdin is where deliver reads the mail; tests replace it.
var stdin io.Reader = os.Stdin

// exitError ends the program with a given exit status.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func init() {
	commands = append(commands,
		command{"run", "run the pinger (in the foreground; systemd handles the rest)", cmdRun},
		command{"deliver", "deliver the mail on stdin into the Maildir (for .forward)", cmdDeliver},
		command{"status", "show remailers, keys, pending changes and suggestions", cmdStatus},
		command{"keys", "show the keys of one remailer: keys <address>", cmdKeys},
		command{"add", "add a remailer: add <address> [nick]", stateCmd("add")},
		command{"delete", "delete remailers: delete <address>...", stateCmd("delete")},
		command{"enable", "enable remailers: enable <address>...", stateCmd("enable")},
		command{"disable", "disable remailers: disable <address>...", stateCmd("disable")},
		command{"set", "set flags: set showit|pingit|fetch=on|off... <address>...", stateCmd("set")},
		command{"approve", "approve pending changes: approve <address> [keyid|nick|address|key]", stateCmd("approve")},
		command{"reject", "reject pending changes: reject <address> [keyid|nick|address|key]", stateCmd("reject")},
		command{"getkeyconf", "send key and conf requests now: getkeyconf [address...]", stateCmd("getkeyconf")},
		command{"buildkeys", "write the keyrings now", stateCmd("buildkeys")},
		command{"sendpings", "send pings now: sendpings [address...]", stateCmd("sendpings")},
		command{"import-echolot", "import an Echolot data dir into a new state dir (see --help)", cmdImport},
		command{"buildstats", "write mlist2.txt and mlist.txt now", stateCmd("buildstats")},
	)
}

// loadConfig parses the flags (only --config) and loads the config.  The
// arguments after the flags are returned.
func loadConfig(name string, args []string, stderr io.Writer) (*config.Config, []string, error) {
	fs := newFlags(name, stderr)
	path := fs.String("config", config.DefaultPath, "config file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil, err
		}
		return nil, nil, errUsage
	}
	c, err := config.Load(*path)
	return c, fs.Args(), err
}

// newLogger returns the logger of cfg: text to stderr or to log.file.
func newLogger(cfg *config.Config, stderr io.Writer) (*slog.Logger, io.Closer, error) {
	w, closer := stderr, io.Closer(io.NopCloser(nil))
	if cfg.Log.File != "" {
		f, err := os.OpenFile(cfg.Log.File, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
		if err != nil {
			return nil, nil, err
		}
		w, closer = f, f
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: cfg.LogLevel()})), closer, nil
}

func newMailer(cfg *config.Config) (mailout.Mailer, error) {
	pw := ""
	if cfg.Mail.Username != "" {
		var err error
		if pw, err = mailout.ReadPassword(cfg.Mail.PasswordFile); err != nil {
			return nil, err
		}
	}
	return mailout.New(cfg.Mail, pw, mailout.Options{})
}

func cmdRun(args []string, stdout, stderr io.Writer) error {
	cfg, rest, err := loadConfig("run", args, stderr)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return usageError(stderr, "run", rest[0])
	}
	log, closer, err := newLogger(cfg, stderr)
	if err != nil {
		return err
	}
	defer closer.Close()
	// SIGHUP is handled before the lock is taken: a CLI command that finds
	// the lock signals its holder, and Go's default for SIGHUP is to exit.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	st, err := store.Open(cfg.Paths.StateDir, log)
	if err != nil {
		return err
	}
	defer st.Close()
	mailer, err := newMailer(cfg)
	if err != nil {
		return err
	}
	d, err := app.NewDaemon(cfg, st, mailer, log, nil)
	if err != nil {
		return err
	}
	d.Version = versionString()
	return d.Run(ctx, hup)
}

// cmdDeliver writes stdin into the Maildir.  The exit status tells the
// MTA what to do: 65 (EX_DATAERR) bounces a mail we will never take, 75
// (EX_TEMPFAIL) makes it try again later.
func cmdDeliver(args []string, stdout, stderr io.Writer) error {
	cfg, rest, err := loadConfig("deliver", args, stderr)
	if err != nil {
		if errors.Is(err, errUsage) || errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &exitError{75, err}
	}
	if len(rest) > 0 {
		return usageError(stderr, "deliver", rest[0])
	}
	if _, err := mailin.Deliver(cfg.Paths.Maildir, stdin, os.Getenv, time.Now()); err != nil {
		if errors.Is(err, mailin.ErrTooLarge) || errors.Is(err, mailin.ErrBadRecipient) {
			return &exitError{65, err}
		}
		return &exitError{75, err}
	}
	return nil
}

func cmdStatus(args []string, stdout, stderr io.Writer) error {
	return showStatus("status", args, stdout, stderr, false)
}

func cmdKeys(args []string, stdout, stderr io.Writer) error {
	return showStatus("keys", args, stdout, stderr, true)
}

// showStatus reads state.json without the lock (design §5.4).
func showStatus(name string, args []string, stdout, stderr io.Writer, one bool) error {
	cfg, rest, err := loadConfig(name, args, stderr)
	if err != nil {
		return err
	}
	addr := ""
	switch {
	case one && len(rest) == 1:
		addr = rest[0]
	case one || len(rest) > 0:
		fmt.Fprintf(stderr, "usage: go-echolot %s [--config file]%s\n", name, map[bool]string{true: " <address>"}[one])
		return errUsage
	}
	st, err := store.Snapshot(cfg.Paths.StateDir)
	if err != nil {
		return err
	}
	return app.WriteStatus(stdout, st, time.Now(), cfg.Keys.RequireProof, addr)
}

// stateCmd returns a command that changes the state.  It's checked on a
// snapshot first, so mistakes show at once.  Then it is applied directly,
// or, when the daemon holds the lock, spooled for it with a SIGHUP
// (design §5.4).
func stateCmd(verb string) func(args []string, stdout, stderr io.Writer) error {
	return func(args []string, stdout, stderr io.Writer) error {
		cfg, rest, err := loadConfig(verb, args, stderr)
		if err != nil {
			return err
		}
		c := app.Command{Verb: verb, Args: rest}
		now := time.Now()
		daemonVerb := verb == "getkeyconf" || verb == "buildkeys" || verb == "sendpings" || verb == "buildstats"
		if !daemonVerb {
			snap, err := store.Snapshot(cfg.Paths.StateDir)
			if err != nil {
				return err
			}
			if _, err := app.Apply(snap, c, now); err != nil {
				return err
			}
		} else if (verb == "buildkeys" || verb == "buildstats") && len(rest) > 0 {
			return usageError(stderr, verb, rest[0])
		}
		log, closer, err := newLogger(cfg, stderr)
		if err != nil {
			return err
		}
		defer closer.Close()
		// Only a daemon is sent SIGHUP, but catch it here anyway, so a
		// stray one can't kill this command half way.  (A private channel,
		// not signal.Ignore, which would cancel every other handler.)
		stray := make(chan os.Signal, 1)
		signal.Notify(stray, syscall.SIGHUP)
		defer signal.Stop(stray)
		st, err := store.Open(cfg.Paths.StateDir, log)
		var locked *store.LockedError
		if errors.As(err, &locked) && !locked.Daemon {
			return err // another command holds it: try again
		}
		if errors.As(err, &locked) {
			if err := app.Spool(cfg.Paths.StateDir, c, now); err != nil {
				return err
			}
			if locked.PID > 0 {
				syscall.Kill(locked.PID, syscall.SIGHUP)
				fmt.Fprintf(stdout, "queued for the running daemon (pid %d)\n", locked.PID)
			} else {
				fmt.Fprintln(stdout, "queued for the running daemon")
			}
			return nil
		}
		if err != nil {
			return err
		}
		defer st.Close()
		var out []string
		if daemonVerb {
			mailer, err := newMailer(cfg)
			if err != nil {
				return err
			}
			d, err := app.NewDaemon(cfg, st, mailer, log, nil)
			if err != nil {
				return err
			}
			d.Version = versionString()
			out = d.Command(context.Background(), c, now)
		} else {
			err := st.Update(func(s *store.State) error {
				var err error
				out, err = app.Apply(s, c, now)
				return err
			})
			if err != nil {
				return err
			}
		}
		for _, line := range out {
			fmt.Fprintln(stdout, line)
		}
		return nil
	}
}

// cmdImport imports an Echolot data dir (design §5.5).  The daemon must
// not run, and the state dir must be new.
func cmdImport(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("import-echolot", stderr)
	path := fs.String("config", config.DefaultPath, "config file")
	meta := fs.String("metadata", "", "Echolot's data/metadata converted to JSON (required):\n"+
		"perl -MJSON::PP -e 'my $f=shift; my $c=do{local(@ARGV,$/)=($f);<>}; my $METADATA; eval $c; die $@ if $@;\n"+
		"  print JSON::PP->new->canonical->encode($METADATA)' ~/echolot/data/metadata > metadata.json")
	data := fs.String("datadir", "", "Echolot's data dir, with the ping files (required)")
	thes := fs.String("thesaurus", "", "Echolot's results/thesaurus (optional)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *meta == "" || *data == "" {
		fmt.Fprintln(stderr, "go-echolot import-echolot: --metadata and --datadir are required")
		return errUsage
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.Paths.StateDir, nil)
	if err != nil {
		return err
	}
	defer st.Close()
	rep, err := echolotimport.Import(st, echolotimport.Options{Metadata: *meta, DataDir: *data, Thesaurus: *thes, Now: time.Now()})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "imported %d remailers, %d keys, %d returned pings, %d lost pings, %d suggestions, %d thesaurus files\n",
		rep.Remailers, rep.Keys, rep.Done, rep.Out, rep.Suggestions, rep.Thesaurus)
	fmt.Fprintf(stdout, "dropped %d pings sent in the last day (their replies are Echolot's and can't be read)\n", rep.OutDropped)
	for _, p := range rep.Problems {
		fmt.Fprintln(stdout, "not imported:", p)
	}
	fmt.Fprintf(stdout, "Echolot's reply tokens are accepted until %s; stop Echolot before starting go-echolot.\n",
		time.Now().Add(echolotimport.LegacyWindow).UTC().Format(time.RFC3339))
	return nil
}

func usageError(stderr io.Writer, name, arg string) error {
	fmt.Fprintf(stderr, "go-echolot %s: unexpected argument %q\n", name, arg)
	return errUsage
}
