package app

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/go-while/go-echolot/internal/config"
	"github.com/go-while/go-echolot/internal/fileutil"
	"github.com/go-while/go-echolot/internal/minisign"
	"github.com/go-while/go-echolot/internal/output"
	"github.com/go-while/go-echolot/internal/store"
)

// Signed outputs (design §9.5, phase 4): the files of signing.files in
// the results directory get a minisign signature, <file>.minisig.

// SignValidity is how long a signature of each signable file is valid:
// its trusted comment's expires is timestamp plus this.  The keyrings are
// re-signed at every check (hourly), the stats at every build.
var SignValidity = map[string]time.Duration{
	"pubring.mix": 48 * time.Hour,
	"type2.list":  48 * time.Hour,
	"mlist2.txt":  6 * time.Hour,
	"mlist.txt":   6 * time.Hour,
}

// maxPingerName bounds the pinger name in trusted comments.
const maxPingerName = 64

// PingerName is the pinger's name in trusted comments: the sitename with
// every byte that isn't printable ASCII or is a space replaced by "_".
func PingerName(sitename string) string {
	b := []byte(sitename)
	for i, c := range b {
		if c < 0x21 || c > 0x7e {
			b[i] = '_'
		}
	}
	if len(b) > maxPingerName {
		b = b[:maxPingerName]
	}
	return string(b)
}

// LoadSigningKey reads the secret key file at path.  Like ssh, it refuses
// a file that others may read.
func LoadSigningKey(path string) (*minisign.PrivateKey, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("signing key %s doesn't exist; create it with `go-echolot keygen`", path)
	}
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("signing key %s: mode %#o lets others read it; chmod 600 it", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := minisign.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("signing key %s: %w", path, err)
	}
	return k, nil
}

// SignatureTime returns the timestamp of the signature file sig if pub
// signed its trusted comment, else ok false.  Only our own signatures
// may raise the timestamp floor: anyone who can write the results
// directory could otherwise push it far into the future.
func SignatureTime(pub minisign.PublicKey, sig []byte) (int64, bool) {
	s, err := minisign.ParseSignature(sig)
	if err != nil || s.VerifyComment(pub) != nil {
		return 0, false
	}
	t, err := minisign.ParseTrusted(s.Trusted)
	if err != nil {
		return 0, false
	}
	return t.Timestamp.Unix(), true
}

// signer signs the published files of signing.files.
type signer struct {
	key    *minisign.PrivateKey
	pub    minisign.PublicKey
	files  map[string]bool
	pinger string
	st     *store.Store
	log    *slog.Logger
	// floor is the newest timestamp of our own signatures found in the
	// results directory at start: a state dir restored from a backup
	// mustn't take the timestamps back either.
	floor map[string]int64
}

// newSigner returns the signer of cfg, or nil if signing is off.
func newSigner(cfg *config.Config, st *store.Store, log *slog.Logger) (*signer, error) {
	if !cfg.Signing.Enabled {
		return nil, nil
	}
	k, err := LoadSigningKey(cfg.Signing.KeyFile)
	if err != nil {
		return nil, err
	}
	s := &signer{key: k, pub: k.Public(), files: map[string]bool{}, pinger: PingerName(cfg.Pinger.Sitename),
		st: st, log: log, floor: map[string]int64{}}
	for _, f := range cfg.Signing.Files {
		s.files[f] = true
		if sig, err := os.ReadFile(filepath.Join(cfg.Paths.ResultsDir, f+output.SigSuffix)); err == nil {
			if ts, ok := SignatureTime(s.pub, sig); ok {
				s.floor[f] = ts
			}
		}
	}
	return s, nil
}

// nextTimestamp returns the timestamp of the next signature of name at
// now and saves it: now, but always after every timestamp name had
// before (design §9.5).  It's saved before the signature is published,
// so a crash can't make it go backwards.
func (s *signer) nextTimestamp(name string, now time.Time) (int64, error) {
	var ts int64
	err := s.st.Update(func(st *store.State) error {
		ts = max(now.Unix(), st.Signed[name]+1, s.floor[name]+1)
		if st.Signed == nil {
			st.Signed = map[string]int64{}
		}
		st.Signed[name] = ts
		return nil
	})
	if err != nil {
		return 0, err
	}
	if ahead := time.Duration(ts-now.Unix()) * time.Second; ahead > time.Minute {
		// The clock went back: the timestamps stay ahead of it until it
		// catches up.
		s.log.Warn("signature timestamp ahead of the clock (did the clock go back?)", "file", name, "ahead", ahead)
	}
	return ts, nil
}

// sign returns the SignFunc for the results directory at now.
func (s *signer) sign(now time.Time) output.SignFunc {
	if s == nil {
		return nil
	}
	return func(name string, data []byte) ([]byte, error) {
		if !s.files[name] {
			return nil, nil
		}
		v, ok := SignValidity[name]
		if !ok {
			return nil, fmt.Errorf("no signature validity for %s", name)
		}
		ts, err := s.nextTimestamp(name, now)
		if err != nil {
			return nil, err
		}
		t := time.Unix(ts, 0).UTC()
		tr := minisign.Trusted{Timestamp: t, File: name, Pinger: s.pinger, Expires: t.Add(v)}
		return minisign.Sign(s.key, data, tr.String(), minisign.UntrustedComment)
	}
}

// writePingerKey publishes pinger.pub in the results directory.
func (s *signer) writePingerKey(dir string) error {
	if s == nil {
		return nil
	}
	return output.WritePingerKey(dir, s.pub.File())
}

// pingerKey is the public key line shown on the index page.
func (s *signer) pingerKey() string {
	if s == nil {
		return ""
	}
	return s.pub.String()
}

// WriteKeyFile writes a new secret key to path, readable only by its
// owner, making its directory if needed.  It never overwrites a file.
func WriteKeyFile(path string, k *minisign.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s exists; keygen never overwrites a key (move it away to make a new one)", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(k.File()); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return fileutil.SyncDir(filepath.Dir(path))
}
