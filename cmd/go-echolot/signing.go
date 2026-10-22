package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-while/go-echolot/internal/app"
	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/fileutil"
	"github.com/go-while/go-echolot/internal/minisign"
	"github.com/go-while/go-echolot/internal/output"
)

// The signing verbs (design §9.5, §10.4).

// now is the clock of sign and verify; tests replace it.
var now = time.Now

func init() {
	commands = append(commands,
		command{"keygen", "make the pinger's signing key (signing.key_file)", cmdKeygen},
		command{"sign", "sign files: sign [--key FILE] [--valid DUR] FILE...", cmdSign},
		command{"verify", "verify signed files: verify [--pub KEY|FILE] FILE...", cmdVerify},
	)
}

// parseCmd parses the flags of fs plus --config and returns the
// arguments after them.
func parseCmd(fs *flag.FlagSet, args []string) (configPath string, rest []string, err error) {
	path := fs.String("config", config.DefaultPath, "config file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", nil, err
		}
		return "", nil, errUsage
	}
	return *path, fs.Args(), nil
}

func cmdKeygen(args []string, stdout, stderr io.Writer) error {
	cfg, rest, err := loadConfig("keygen", args, stderr)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return usageError(stderr, "keygen", rest[0])
	}
	k, err := minisign.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := app.WriteKeyFile(cfg.Signing.KeyFile, k); err != nil {
		return err
	}
	p := k.Public()
	fmt.Fprintf(stdout, "secret key written to %s (keep it; back it up offline)\n", cfg.Signing.KeyFile)
	fmt.Fprintf(stdout, "public key (key ID %s):\n\n%s\n", p.ID, p.String())
	fmt.Fprintf(stdout, "Set signing.enabled = true and restart: the daemon publishes pinger.pub in %s.\n", cfg.Paths.ResultsDir)
	fmt.Fprintln(stdout, "Then list the public key in the yamn repository (doc/pingers.md) through a reviewed PR.")
	return nil
}

func cmdSign(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("sign", stderr)
	keyPath := fs.String("key", "", "secret key file (default: signing.key_file)")
	valid := fs.Duration("valid", 48*time.Hour, "how long the signatures are valid")
	path, files, err := parseCmd(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "go-echolot sign: no files to sign")
		return errUsage
	}
	if *valid <= 0 {
		return fmt.Errorf("--valid must be more than 0, not %s", *valid)
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if *keyPath == "" {
		*keyPath = cfg.Signing.KeyFile
	}
	k, err := app.LoadSigningKey(*keyPath)
	if err != nil {
		return err
	}
	pub := k.Public()
	for _, f := range files {
		name := filepath.Base(f)
		// The published files are the daemon's to sign, from the bytes it
		// wrote and with its timestamps; it also removes the signatures
		// of those it doesn't sign.
		if slices.Contains(app.OutputFiles, name) {
			return fmt.Errorf("%s: the daemon signs the published files (signing.files), not this command", f)
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		// The timestamp never goes back past an earlier signature of ours.
		ts := now().Unix()
		if old, err := os.ReadFile(f + output.SigSuffix); err == nil {
			if t, ok := app.SignatureTime(pub, old); ok && t >= ts {
				ts = t + 1
			}
		}
		t := time.Unix(ts, 0).UTC()
		tr := minisign.Trusted{Timestamp: t, File: name, Pinger: app.PingerName(cfg.Pinger.Sitename), Expires: t.Add(*valid)}
		if err := tr.Check(); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		sig, err := minisign.Sign(k, data, tr.String(), minisign.UntrustedComment)
		if err != nil {
			return err
		}
		if err := fileutil.WriteAtomic(f+output.SigSuffix, sig, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s%s: %s\n", f, output.SigSuffix, tr)
	}
	return nil
}

func cmdVerify(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("verify", stderr)
	pubArg := fs.String("pub", "", "public key: a pinger.pub file or its base64 line (default: pinger.pub in results_dir)")
	path, files, err := parseCmd(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "go-echolot verify: no files to verify")
		return errUsage
	}
	if *pubArg == "" {
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		*pubArg = filepath.Join(cfg.Paths.ResultsDir, "pinger.pub")
	}
	// A base64 key line, or else a file.
	pub, err := minisign.ParsePublicKey([]byte(*pubArg))
	if err != nil {
		b, rerr := os.ReadFile(*pubArg)
		if rerr != nil {
			return rerr
		}
		if pub, err = minisign.ParsePublicKey(b); err != nil {
			return fmt.Errorf("%s: %w", *pubArg, err)
		}
	}
	failed := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err == nil {
			var sig []byte
			if sig, err = os.ReadFile(f + output.SigSuffix); err == nil {
				var tr minisign.Trusted
				tr, err = minisign.VerifyFile(pub, filepath.Base(f), data, sig, now())
				if err == nil {
					fmt.Fprintf(stdout, "%s: good signature by %s, signed %s, expires %s\n", f, pub.ID,
						tr.Timestamp.Format(time.RFC3339), tr.Expires.Format(time.RFC3339))
					continue
				}
			}
		}
		failed++
		fmt.Fprintf(stdout, "%s: BAD: %v\n", f, err)
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d files failed", failed, len(files))
	}
	return nil
}
