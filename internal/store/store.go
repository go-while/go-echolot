// Package store keeps go-echolot's state in plain files under one locked
// state dir (design §5.2–5.4):
//
//	lock         flock'ed while a Store is open; holds "pid\n"
//	secret       32 random bytes as hex, mode 0600
//	state.json   State, replaced atomically
//	pings.jsonl  the ping journal, append-only
//	chainpings.jsonl  the chain ping journal, append-only (chainjournal.go)
//
// Everything is held in memory.  The files only have to be durable and
// readable with cat and jq.
package store

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
)

// File names in the state dir.
const (
	stateFile   = "state.json"
	journalFile = "pings.jsonl"
	secretFile  = "secret"
)

// writeFile is fileutil.WriteAtomic; tests replace it to simulate a
// crash or a full disk.
var writeFile = fileutil.WriteAtomic

// Store is an open state dir.  Its methods are safe for concurrent use.
type Store struct {
	dir    string
	log    *slog.Logger
	lockF  *os.File
	secret []byte

	mu      sync.Mutex
	state   *State
	saved   []byte // state.json as last written; restores State after a failed Update
	pings   *pings
	journal *os.File // nil after Close, or when jerr is set
	jerr    error    // why the journal can't be written to any more
	jsize   int64    // journal length after the last complete write

	chains   *chainPings // the chain ping journal, as pings/journal/jerr/jsize
	cjournal *os.File
	cjerr    error
	cjsize   int64
}

// Open locks dir, creating it if needed, and loads the state, the secret
// (made on first use) and the ping journal.  If another process has the
// dir open, the error is a *LockedError.  log may be nil.
func Open(dir string, log *slog.Logger) (_ *Store, err error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := fileutil.SyncDir(filepath.Dir(dir)); err != nil {
			return nil, err
		}
	}
	lockF, err := lock(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, log: log, lockF: lockF}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	// Nothing else writes in dir while we hold the lock.
	if err := fileutil.RemoveTemps(dir); err != nil {
		return nil, err
	}
	if s.secret, err = loadSecret(filepath.Join(dir, secretFile)); err != nil {
		return nil, err
	}
	if s.state, s.saved, err = readState(dir); err != nil {
		return nil, err
	}
	if err := s.openJournal(); err != nil {
		return nil, err
	}
	if err := s.openChainJournal(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close releases the state dir.  The Store can't be used afterwards.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.journal != nil {
		errs = append(errs, s.journal.Close())
		s.journal = nil
	}
	if s.cjournal != nil {
		errs = append(errs, s.cjournal.Close())
		s.cjournal = nil
	}
	if s.lockF != nil {
		errs = append(errs, s.lockF.Close()) // closing releases the flock
		s.lockF = nil
	}
	return errors.Join(errs...)
}

// Dir returns the state dir.
func (s *Store) Dir() string { return s.dir }

// Secret returns the pinger's 32-byte secret, from which the token, ping
// and scheduling keys are derived (design §6.1).
func (s *Store) Secret() []byte { return slices.Clone(s.secret) }

// View calls fn with the state.  fn must not change it or keep pointers
// into it.
func (s *Store) View(fn func(*State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.state)
}

// Update calls fn to change the state, then writes state.json.  If fn
// returns an error or panics, or the write fails, the state is as it was
// before.  fn must not keep pointers into the state.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockF == nil {
		return errors.New("store is closed")
	}
	committed := false
	defer func() {
		if !committed {
			s.restore()
		}
	}()
	if err := fn(s.state); err != nil {
		return err
	}
	data, err := marshalState(s.state)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, s.saved) {
		err := writeFile(filepath.Join(s.dir, stateFile), data, 0o600)
		if errors.Is(err, fileutil.ErrDirSync) {
			// state.json is the new one: keep it, so memory and disk agree.
			s.log.Error("state.json may not survive a power loss", "err", err)
		} else if err != nil {
			return fmt.Errorf("write %s: %w", stateFile, err)
		}
		s.saved = data
	}
	committed = true
	return nil
}

// restore throws away changes to the state since the last write.
func (s *Store) restore() {
	st, err := unmarshalState(s.saved)
	if err != nil {
		panic("store: can't read back state written before: " + err.Error())
	}
	s.state = st
}

// Snapshot reads state.json of dir without the lock, for read-only
// commands while the daemon runs (design §5.4).  The atomic writes make
// it consistent.  A missing state.json is an empty state.
func Snapshot(dir string) (*State, error) {
	st, _, err := readState(dir)
	return st, err
}

func readState(dir string) (*State, []byte, error) {
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	if os.IsNotExist(err) {
		st := newState()
		data, err := marshalState(st)
		return st, data, err
	}
	if err != nil {
		return nil, nil, err
	}
	st, err := unmarshalState(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", filepath.Join(dir, stateFile), err)
	}
	return st, data, nil
}

func marshalState(st *State) ([]byte, error) {
	data, err := json.MarshalIndent(st, "", "\t")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func unmarshalState(data []byte) (*State, error) {
	st := new(State)
	if err := json.Unmarshal(data, st); err != nil {
		return nil, err
	}
	if st.Version != StateVersion {
		return nil, fmt.Errorf("state version %d, this go-echolot reads version %d", st.Version, StateVersion)
	}
	if st.Remailers == nil {
		st.Remailers = map[string]*Remailer{}
	}
	return st, nil
}

// loadSecret reads the secret file, or makes one if there is none.
func loadSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		secret := make([]byte, 32)
		rand.Read(secret)
		return secret, writeFile(path, []byte(hex.EncodeToString(secret)+"\n"), 0o600)
	}
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s can be read by others (mode %v); chmod 600 it", path, fi.Mode().Perm())
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(secret) != 32 {
		return nil, fmt.Errorf("%s: want 64 hex digits", path)
	}
	return secret, nil
}

// openJournal replays the journal, cuts off a write a crash interrupted,
// and opens it for appending.
func (s *Store) openJournal() error {
	path := filepath.Join(s.dir, journalFile)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return err
	}
	ps, good := replay(data, s.log)
	if good < int64(len(data)) {
		if err := f.Truncate(good); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	// Make the name of a new journal durable.
	if err := fileutil.SyncDir(s.dir); err != nil {
		f.Close()
		return err
	}
	s.pings, s.journal, s.jsize = ps, f, good
	return nil
}

// journalFailed stops all writes to the journal: after a write that
// can't be undone, appending more would hide the damage.
func (s *Store) journalFailed(err error) error {
	s.log.Error("ping journal unusable until restart", "err", err)
	if s.journal != nil {
		s.journal.Close()
		s.journal = nil
	}
	s.jerr = fmt.Errorf("ping journal unusable until restart: %w", err)
	return s.jerr
}

// appendEvents writes evs to the journal and fsyncs it.  A write that
// fails part way is cut off, so the next one starts on a new line.
func (s *Store) appendEvents(evs ...event) error {
	if s.jerr != nil {
		return s.jerr
	}
	if s.journal == nil {
		return errors.New("store is closed")
	}
	data := encode(evs...)
	_, err := journalWrite(s.journal, data)
	if err == nil {
		err = s.journal.Sync()
	}
	if err != nil {
		// Cut off what may have been written, or the next event would be
		// glued to a partial line.  If that fails too, stop writing: the
		// partial line is dropped at the next Open.
		if terr := s.journal.Truncate(s.jsize); terr != nil {
			return s.journalFailed(errors.Join(err, terr))
		}
		return fmt.Errorf("ping journal: %w", err)
	}
	s.jsize += int64(len(data))
	return nil
}

// NewPing records a ping that doesn't count in the stats; see AddPing.
func (s *Store) NewPing(addr, keyID string, withFrom bool, sent time.Time) (Ping, error) {
	return s.AddPing(Ping{Addr: addr, KeyID: keyID, WithFrom: withFrom, Sent: sent})
}

// AddPing records a ping as sent, before it is sent (design §5.3): its
// Addr, KeyID, WithFrom, Counted and Sent; the rest is ignored.  It
// returns the ping with its new ID.
func (s *Store) AddPing(in Ping) (Ping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	addr, keyID, sent := in.Addr, in.KeyID, in.Sent
	p := &Ping{ID: s.pings.nextID, Addr: addr, KeyID: keyID, WithFrom: in.WithFrom, Counted: in.Counted,
		Sent: time.Unix(sent.Unix(), 0).UTC()}
	if addr == "" || keyID == "" || p.Sent.Unix() <= 0 {
		return Ping{}, errors.New("NewPing: empty address or keyid, or bad time")
	}
	// The ID is used up even if the write fails: a ping that may have
	// reached the disk mustn't share its ID.
	s.pings.nextID++
	ev := outEvent(p)
	if err := s.appendEvents(ev); err != nil {
		return Ping{}, err
	}
	s.pings.apply(ev)
	return *p, nil
}

// PingDone records that ping id came back at received, with latency in
// seconds.  It returns the ping and whether this was news: false for an
// unknown ping or one already back.
func (s *Store) PingDone(id uint64, received time.Time, latency int64) (Ping, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pings.byID[id]
	if p == nil {
		return Ping{}, false, nil
	}
	if p.Status == PingDone {
		return *p, false, nil
	}
	ev := doneEvent(&Ping{ID: id, Received: received, Latency: latency})
	if ev.Rcv <= 0 {
		return Ping{}, false, errors.New("PingDone: bad time")
	}
	if err := s.appendEvents(ev); err != nil {
		return Ping{}, false, err
	}
	s.pings.apply(ev)
	return *p, true, nil
}

// PingAborted records that ping id failed before it left (design §5.3).
// Such pings don't count in the stats.
func (s *Store) PingAborted(id uint64, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pings.byID[id]
	if p == nil || p.Status != PingOut {
		return nil
	}
	ev := abortEvent(&Ping{ID: id, Err: reason})
	if err := s.appendEvents(ev); err != nil {
		return err
	}
	s.pings.apply(ev)
	return nil
}

// Pings returns the pings to addr sent after since, all keys together
// (design §8.1): those still out and those that came back.  Aborted pings
// are left out.  Both lists are in the order sent.
func (s *Store) Pings(addr string, since time.Time) (out, done []Ping) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.pings.byID {
		if p.Addr != addr || !p.Sent.After(since) {
			continue
		}
		switch p.Status {
		case PingOut:
			out = append(out, *p)
		case PingDone:
			done = append(done, *p)
		}
	}
	bySent := func(a, b Ping) int {
		if c := a.Sent.Compare(b.Sent); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	}
	slices.SortFunc(out, bySent)
	slices.SortFunc(done, bySent)
	return out, done
}

// ReplyStatus returns the newest reception time of a ping that came
// back (zero: none), and the send time of the oldest ping still out that
// was sent after it (zero: none), for the health check (design §10.2).
func (s *Store) ReplyStatus() (lastReply, waiting time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.pings.byID {
		if p.Status == PingDone && p.Received.After(lastReply) {
			lastReply = p.Received
		}
	}
	for _, p := range s.pings.byID {
		if p.Status == PingOut && p.Sent.After(lastReply) && (waiting.IsZero() || p.Sent.Before(waiting)) {
			waiting = p.Sent
		}
	}
	return lastReply, waiting
}

// Ping returns ping id.
func (s *Store) Ping(id uint64) (Ping, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.pings.byID[id]; p != nil {
		return *p, true
	}
	return Ping{}, false
}

// Compact forgets the pings sent before before and rewrites the journal
// with the rest (design §5.3; daily, with expiry).
func (s *Store) Compact(before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jerr != nil {
		return s.jerr
	}
	if s.journal == nil {
		return errors.New("store is closed")
	}
	data, keep := s.pings.compacted(before)
	path := filepath.Join(s.dir, journalFile)
	werr := writeFile(path, data, 0o600)
	if werr != nil && !errors.Is(werr, fileutil.ErrDirSync) {
		return fmt.Errorf("compact ping journal: %w", werr) // the old journal is still in place
	}
	// The new journal is in place: switch to it, even if it may not
	// survive a power loss.
	s.pings.byID = keep
	s.journal.Close()
	s.journal = nil
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return s.journalFailed(fmt.Errorf("reopen after compacting: %w", err))
	}
	s.journal, s.jsize = f, int64(len(data))
	if werr != nil {
		s.log.Error("compacted ping journal may not survive a power loss", "err", werr)
	}
	return nil
}
