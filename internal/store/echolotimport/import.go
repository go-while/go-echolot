// Package echolotimport imports an Echolot data directory into a new
// go-echolot state dir (design §5.5).
//
// Echolot keeps its metadata as Perl source (Data::Dumper), so it is
// converted to JSON first, with the perl every Echolot host has:
//
//	perl -MJSON::PP -e 'my $f=shift; my $c=do{local(@ARGV,$/)=($f);<>}; my $METADATA;
//	  eval $c; die $@ if $@; print JSON::PP->new->canonical->encode($METADATA)' \
//	  ~/echolot/data/metadata > metadata.json
//
// Then Import reads metadata.json, the ping files of the data dir and the
// thesaurus.
package echolotimport

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/token"
)

// LegacyFile is the state dir file with Echolot's secret and until when
// its MD5 tokens are accepted (§5.5): "<32 hex>\n<RFC 3339>\n", mode 0600.
const LegacyFile = "legacy_secret"

// LegacyWindow is how long Echolot's tokens are accepted after an import:
// replies to requests Echolot sent shortly before.
const LegacyWindow = 48 * time.Hour

// outMinAge: out pings younger than this are dropped, not imported as
// losses: their replies are GPG-encrypted, go-echolot can't read them,
// and counting them lost would be wrong (§5.5).
const outMinAge = 24 * time.Hour

// Options says where Echolot's files are.
type Options struct {
	Metadata  string    // metadata.json (see the package comment)
	DataDir   string    // Echolot's data dir, with the <stats>.out/.done ping files
	Thesaurus string    // Echolot's results/thesaurus; "" = skip
	Now       time.Time // import time
}

// Report says what was imported and what wasn't.
type Report struct {
	Remailers, Keys, Done, Out, OutDropped, Suggestions, Thesaurus int
	Problems                                                       []string
}

func (r *Report) problem(format string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

// metadata is the part of Echolot's $METADATA that is imported
// (E:Storage/File.pm).  Perl's JSON may write numbers as strings, so
// they're read as json.Number via num.
type metadata struct {
	Version     num                        `json:"version"`
	Secret      string                     `json:"secret"`
	MaxID       num                        `json:"addresses_maxid"`
	Addresses   map[string]address         `json:"addresses"`
	Remailers   map[string]remailer        `json:"remailers"`
	Prospective map[string][]string        `json:"prospective_addresses"`
	Fromlines   map[string]json.RawMessage `json:"fromlines"`
}

type address struct {
	ID              num    `json:"id"`
	Status          string `json:"status"`
	TTL             num    `json:"ttl"`
	ResurrectionTTL num    `json:"resurrection_ttl"`
	Fetch           num    `json:"fetch"`
	ShowIt          num    `json:"showit"`
	PingIt          num    `json:"pingit"`
}

type remailer struct {
	Conf *struct {
		Nick       string `json:"nick"`
		Type       string `json:"type"`
		Caps       string `json:"capabilities"`
		LastUpdate num    `json:"last_update"`
		DontExpire num    `json:"dont_expire"`
	} `json:"conf"`
	Keys map[string]map[string]struct { // type -> keyid -> key
		Key        string `json:"key"`
		Summary    string `json:"summary"`
		Nick       string `json:"nick"`
		LastUpdate num    `json:"last_update"`
		Stats      string `json:"stats"`
	} `json:"keys"`
}

// num is a number Perl may have written as a string.
type num int64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("not a whole number: %s", b)
	}
	*n = num(v)
	return nil
}

// Import imports Echolot's data into st, which must be empty.  Keys are
// checked with yamn's rules; what fails is reported, not imported.
func Import(st *store.Store, opt Options) (*Report, error) {
	data, err := os.ReadFile(opt.Metadata)
	if err != nil {
		return nil, err
	}
	var md metadata
	if err := json.Unmarshal(data, &md); err != nil {
		return nil, fmt.Errorf("%s: %w (convert Echolot's metadata with the perl command in the docs)", opt.Metadata, err)
	}
	if md.Version != 1 {
		return nil, fmt.Errorf("%s: Echolot metadata version %d, want 1", opt.Metadata, md.Version)
	}
	var empty bool
	st.View(func(s *store.State) { empty = len(s.Remailers) == 0 && s.MaxID == 0 })
	if !empty {
		return nil, errors.New("the state dir already has remailers; import into a new one")
	}
	rep := &Report{}
	now := opt.Now.UTC()
	type pingFile struct {
		addr, keyid, stats string
	}
	var pingFiles []pingFile
	err = st.Update(func(s *store.State) error {
		s.MaxID = int(md.MaxID)
		for _, addr := range slices.Sorted(maps.Keys(md.Addresses)) {
			a := md.Addresses[addr]
			if !replies.ValidAddress(addr) {
				rep.problem("%s: not an address yamn accepts; skipped", addr)
				continue
			}
			if a.ID <= 0 || int(a.ID) > s.MaxID {
				rep.problem("%s: bad id %d; skipped", addr, a.ID)
				continue
			}
			if r := s.RemailerByID(int(a.ID)); r != nil {
				rep.problem("%s: id %d is %s's too; skipped", addr, a.ID, r.Address)
				continue
			}
			r := &store.Remailer{
				ID: int(a.ID), Address: addr, Status: status(a.Status, rep, addr),
				TTL: int(a.TTL), ResurrectionTTL: int(a.ResurrectionTTL),
				Fetch: a.Fetch != 0, PingIt: a.PingIt != 0, ShowIt: a.ShowIt != 0,
				Added: now, Keys: map[string]*store.Key{},
			}
			if r.ResurrectionTTL == 0 {
				r.ResurrectionTTL = store.DefaultResurrectionTTL
			}
			s.Remailers[addr] = r
			rep.Remailers++
			rm := md.Remailers[addr]
			if c := rm.Conf; c != nil && c.Nick != "" {
				conf, err := replies.ParseConf([]byte(c.Caps + "\n"))
				switch {
				case err != nil || conf.Nick != c.Nick || !keys.SameAddress(conf.Address, addr):
					rep.problem("%s: conf caps line %q doesn't fit; conf not imported", addr, c.Caps)
				case len(c.Nick) > keys.MaxNickLen:
					rep.problem("%s: nick %s is longer than %d characters; not pinned", addr, c.Nick, keys.MaxNickLen)
				default:
					t := time.Unix(int64(c.LastUpdate), 0).UTC()
					r.Conf = &store.Conf{Nick: c.Nick, Type: c.Type, Caps: conf.Caps, LastUpdate: t, Received: t, DontExpire: c.DontExpire != 0}
				}
			}
			for typ, ks := range rm.Keys {
				if typ != "mix" {
					rep.problem("%s: %d %s keys not imported (yamn only)", addr, len(ks), typ)
					continue
				}
				for _, keyid := range slices.Sorted(maps.Keys(ks)) {
					k := ks[keyid]
					kr := replies.ParseKey([]byte(k.Summary + "\n\n" + strings.TrimSpace(k.Key) + "\n"))
					if len(kr.Keys) != 1 || kr.Keys[0].KeyID != keyid || !keys.SameAddress(kr.Keys[0].Address, addr) {
						why := "doesn't parse with yamn's rules"
						if len(kr.Errors) > 0 {
							why = kr.Errors[0].Error()
						}
						rep.problem("%s: key %s not imported: %s", addr, keyid, why)
						continue
					}
					pk := kr.Keys[0]
					t := time.Unix(int64(k.LastUpdate), 0).UTC()
					s.Remailers[addr].Keys[keyid] = &store.Key{
						KeyID: keyid, Nick: pk.Nick, Address: pk.Address, Version: pk.Version, Caps: pk.Caps,
						Created: pk.Created, Expires: pk.Expires, PK: store.PublicKey(pk.PK),
						FirstSeen: t, LastSeen: t, LastReceived: t, Sightings: 1, State: store.KeyStateActive,
					}
					rep.Keys++
					if k.Stats != "" {
						pingFiles = append(pingFiles, pingFile{addr, keyid, k.Stats})
					}
				}
			}
			// The conf's nick is pinned when the keys agree with it;
			// keys with another nick are quarantined (§5.5).
			if r.Conf != nil {
				r.Nick = r.Conf.Nick
			}
			for _, k := range r.Keys {
				switch {
				case r.Nick == "" && len(k.Nick) <= keys.MaxNickLen && nickFree(s, k.Nick, r):
					r.Nick = k.Nick
				case k.Nick != r.Nick:
					k.State = store.KeyStateQuarantined
					rep.problem("%s: key %s has nick %s, not the conf's %s; quarantined", addr, k.KeyID, k.Nick, r.Nick)
				}
			}
			if r.Nick != "" && !nickFree(s, r.Nick, r) {
				rep.problem("%s: nick %s is used by another remailer too; not pinned", addr, r.Nick)
				r.Nick = ""
			}
		}
		for addr, list := range md.Prospective {
			for _, line := range list {
				// "time; reason; additional" (E:Storage/File.pm:915-928)
				f := strings.SplitN(line, "; ", 3)
				sec, err := strconv.ParseInt(f[0], 10, 64)
				if len(f) < 2 || err != nil || !replies.ValidAddress(addr) {
					rep.problem("prospective address %s: %q not imported", addr, line)
					continue
				}
				sug := store.Suggestion{Time: time.Unix(sec, 0).UTC(), Reason: f[1]}
				if len(f) == 3 {
					sug.Source = f[2]
				}
				if s.Prospective == nil {
					s.Prospective = map[string][]store.Suggestion{}
				}
				s.Prospective[addr] = append(s.Prospective[addr], sug)
				rep.Suggestions++
			}
		}
		if len(md.Fromlines) > 0 {
			rep.problem("fromlines not imported (they expire after 5 days anyway)")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Pings, per key (§5.5): every done one; out ones older than a day as
	// losses.  Echolot's returned pings were encrypted to that key, so the
	// first one also proves it (§9.2).
	for _, pf := range pingFiles {
		if err := importPings(st, opt.DataDir, pf.addr, pf.keyid, pf.stats, now, rep); err != nil {
			return rep, err
		}
	}
	if err := writeLegacy(st.Dir(), md.Secret, now.Add(LegacyWindow)); err != nil {
		rep.problem("Echolot's secret not imported: %v; replies to Echolot's last requests will be refused", err)
	}
	if opt.Thesaurus != "" {
		if err := copyThesaurus(opt.Thesaurus, filepath.Join(st.Dir(), "thesaurus"), rep); err != nil {
			rep.problem("thesaurus: %v", err)
		}
	}
	return rep, nil
}

// importPings imports the ping files <stats>.out and <stats>.done of one
// key, in time order.
func importPings(st *store.Store, dir, addr, keyid, stats string, now time.Time, rep *Report) error {
	if strings.ContainsAny(stats, "/\\") || strings.HasPrefix(stats, ".") {
		rep.problem("%s: bad ping file name %q", addr, stats)
		return nil
	}
	type ping struct {
		sent int64
		lat  int64
		done bool
	}
	var ps []ping
	read := func(ext string, fields int) {
		f, err := os.Open(filepath.Join(dir, stats+"."+ext))
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			rep.problem("%s: %v", addr, err)
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for n := 1; sc.Scan(); n++ {
			fs := strings.Fields(sc.Text())
			var v [2]int64
			ok := len(fs) == fields
			for i := 0; ok && i < fields; i++ {
				var err error
				v[i], err = strconv.ParseInt(fs[i], 10, 64)
				ok = err == nil && v[i] >= 0
			}
			if !ok || v[0] == 0 {
				rep.problem("%s.%s:%d: bad line %q", stats, ext, n, bounded(sc.Text()))
				continue
			}
			ps = append(ps, ping{v[0], v[1], fields == 2})
		}
		if err := sc.Err(); err != nil {
			rep.problem("%s.%s: %v", stats, ext, err)
		}
	}
	read("done", 2)
	read("out", 1)
	slices.SortStableFunc(ps, func(a, b ping) int { return cmp.Compare(a.sent, b.sent) })
	var proven time.Time
	for _, p := range ps {
		sent := time.Unix(p.sent, 0).UTC()
		if !p.done && now.Sub(sent) < outMinAge {
			rep.OutDropped++
			continue
		}
		sp, err := st.AddPing(store.Ping{Addr: addr, KeyID: keyid, Counted: true, Sent: sent})
		if err != nil {
			return err
		}
		if !p.done {
			rep.Out++
			continue
		}
		back := sent.Add(time.Duration(p.lat) * time.Second)
		if _, _, err := st.PingDone(sp.ID, back, p.lat); err != nil {
			return err
		}
		rep.Done++
		if proven.IsZero() || back.Before(proven) {
			proven = back
		}
	}
	if proven.IsZero() {
		return nil
	}
	return st.Update(func(s *store.State) error {
		if k := s.Remailers[addr].Keys[keyid]; k != nil {
			keys.SetProven(k, proven)
		}
		return nil
	})
}

// status maps Echolot's states to ours (§8.5).
func status(s string, rep *Report, addr string) string {
	switch {
	case s == "" || s == store.StatusActive:
		return store.StatusActive
	case s == store.StatusTTLTimeout || s == store.StatusDead:
		return s
	case strings.Contains(s, "not a remailer"):
		return store.StatusNotARemailer
	case strings.HasPrefix(s, "disabled"):
		return store.StatusDisabled
	}
	rep.problem("%s: unknown state %q; imported as active", addr, s)
	return store.StatusActive
}

func nickFree(s *store.State, nick string, self *store.Remailer) bool {
	for _, r := range s.Remailers {
		if r != self && r.Nick == nick {
			return false
		}
	}
	return true
}

// writeLegacy stores Echolot's secret for its MD5 tokens (§5.5).
func writeLegacy(stateDir, secret string, until time.Time) error {
	if _, err := token.New(token.Config{Secret: make([]byte, 32), Address: "x@y", LegacySecret: secret}); err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(stateDir, LegacyFile),
		[]byte(secret+"\n"+until.UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// ReadLegacy returns the Echolot secret and its end from the state dir,
// or "" if there is none.
func ReadLegacy(stateDir string) (secret string, until time.Time, err error) {
	data, err := os.ReadFile(filepath.Join(stateDir, LegacyFile))
	if os.IsNotExist(err) {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, err
	}
	f := strings.Fields(string(data))
	if len(f) != 2 {
		return "", time.Time{}, fmt.Errorf("%s: want the secret and a time", LegacyFile)
	}
	until, err = time.Parse(time.RFC3339, f[1])
	return f[0], until, err
}

// copyThesaurus copies Echolot's <id>.<type> replies (§5.5).
func copyThesaurus(from, to string, rep *Report) error {
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(to, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		id, kind, ok := strings.Cut(e.Name(), ".")
		if _, err := strconv.Atoi(id); err != nil || !ok || !e.Type().IsRegular() ||
			!slices.Contains([]string{"conf", "key", "help", "adminkey"}, kind) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() > 1<<20 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			rep.problem("thesaurus %s: %v", e.Name(), err)
			continue
		}
		dst := filepath.Join(to, e.Name())
		if err := fileutil.WriteAtomic(dst, data, 0o600); err != nil {
			return err
		}
		os.Chtimes(dst, info.ModTime(), info.ModTime())
		rep.Thesaurus++
	}
	return nil
}

func bounded(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
