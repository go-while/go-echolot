// Command go-echolot is a pinger for the yamn remailer network
// (docs/design.md).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/go-while/go-echolot/internal/config"
)

// version is set at build time with -ldflags "-X main.version=...";
// otherwise it comes from the module or VCS build info.
var version = ""

type command struct {
	name, help string
	run        func(args []string, stdout, stderr io.Writer) error
}

var commands = []command{
	{"dumpconf", "check the config file and print it with all defaults", cmdDumpconf},
	{"version", "print the version", cmdVersion},
}

// errUsage reports bad arguments; the flag package has already printed why.
var errUsage = errors.New("usage")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command in args and returns the exit status: 0, 1 for
// a failure, 2 for bad usage.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	for _, c := range commands {
		if c.name != args[0] {
			continue
		}
		err := c.run(args[1:], stdout, stderr)
		switch {
		case err == nil:
			return 0
		case errors.Is(err, flag.ErrHelp):
			return 0
		case errors.Is(err, errUsage):
			return 2
		}
		var code exitCode
		if errors.As(err, &code) {
			return int(code)
		}
		var exit *exitError
		if errors.As(err, &exit) {
			fmt.Fprintf(stderr, "go-echolot %s: %v\n", c.name, err)
			return exit.code
		}
		fmt.Fprintf(stderr, "go-echolot %s: %v\n", c.name, err)
		return 1
	}
	fmt.Fprintf(stderr, "go-echolot: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: go-echolot <command> [flags]\n\ncommands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-11s %s\n", c.name, c.help)
	}
}

// newFlags returns the flag set of a command, printing to stderr.
func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("go-echolot "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseFlags parses args and refuses extra arguments.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return errUsage
	}
	return nil
}

func cmdDumpconf(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("dumpconf", stderr)
	path := fs.String("config", config.DefaultPath, "config file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "# %s, with defaults\n\n", *path)
	return c.Format(stdout)
}

func cmdVersion(args []string, stdout, stderr io.Writer) error {
	if err := parseFlags(newFlags("version", stderr), args); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "go-echolot", versionString())
	return nil
}

func versionString() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(unknown)"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return "(devel)"
	}
	return "(devel) " + rev[:min(12, len(rev))] + dirty
}
