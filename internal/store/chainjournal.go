package store

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-while/go-echolot/internal/fileutil"
)

// The chain ping journal, chainpings.jsonl (design §5.2, §8.2), works like
// the ping journal (same crash safety, §5.3) with its own IDs:
//
//	{"ev":"out","id":3,"a":"…","ka":"…","b":"…","kb":"…","sent":1792560000}
//	{"ev":"done","id":3,"lat":4321,"rcv":1792564321}
//	{"ev":"abort","id":3,"err":"yamn encode: …"}
//	{"ev":"next","id":4}
//
// A chain ping goes through A, then B: A gets it from us, B delivers it
// (E:Chain.pm:94-124).  Echolot keeps two files, chainpings.mix.out with
// every ping sent and .done with those back (E:Storage/File.pm:632-878).
// Compaction is CompactChains, separate from the ping journal's Compact,
// so that a failure of one leaves the other alone; the daily job calls
// both (expire_chainpings 12 d, E:Config.pm:142).

const chainJournalFile = "chainpings.jsonl"

// ChainPing is one chain ping through two remailers, each with the key it
// was encrypted to.
type ChainPing struct {
	ID       uint64
	A, KeyA  string    // the first hop and its key
	B, KeyB  string    // the second hop, which delivers it, and its key
	Sent     time.Time // whole seconds
	Status   PingStatus
	Received time.Time // PingDone only
	Latency  int64     // seconds; PingDone only
	Err      string    // PingAborted only
}

type chainEvent struct {
	Ev   string `json:"ev"`
	ID   uint64 `json:"id"`
	A    string `json:"a,omitempty"`
	KA   string `json:"ka,omitempty"`
	B    string `json:"b,omitempty"`
	KB   string `json:"kb,omitempty"`
	Sent int64  `json:"sent,omitempty"`
	Lat  *int64 `json:"lat,omitempty"`
	Rcv  int64  `json:"rcv,omitempty"`
	Err  string `json:"err,omitempty"`
}

func chainOutEvent(p *ChainPing) chainEvent {
	return chainEvent{Ev: "out", ID: p.ID, A: p.A, KA: p.KeyA, B: p.B, KB: p.KeyB, Sent: p.Sent.Unix()}
}

func chainDoneEvent(p *ChainPing) chainEvent {
	lat := p.Latency
	return chainEvent{Ev: "done", ID: p.ID, Lat: &lat, Rcv: p.Received.Unix()}
}

func chainAbortEvent(p *ChainPing) chainEvent {
	return chainEvent{Ev: "abort", ID: p.ID, Err: p.Err}
}

// chainPings is the in-memory form of the chain ping journal.
type chainPings struct {
	byID   map[uint64]*ChainPing
	nextID uint64
}

func newChainPings() *chainPings { return &chainPings{byID: map[uint64]*ChainPing{}, nextID: 1} }

// apply applies one event, as pings.apply does.
func (cs *chainPings) apply(ev chainEvent) error {
	p := cs.byID[ev.ID]
	switch ev.Ev {
	case "next":
		cs.nextID = max(cs.nextID, ev.ID)
	case "out":
		if ev.ID == 0 || ev.A == "" || ev.KA == "" || ev.B == "" || ev.KB == "" || ev.Sent <= 0 {
			return fmt.Errorf("incomplete out event")
		}
		if p != nil {
			return fmt.Errorf("chain ping %d sent twice", ev.ID)
		}
		cs.byID[ev.ID] = &ChainPing{ID: ev.ID, A: ev.A, KeyA: ev.KA, B: ev.B, KeyB: ev.KB,
			Sent: time.Unix(ev.Sent, 0).UTC()}
		cs.nextID = max(cs.nextID, ev.ID+1)
	case "done":
		if ev.Lat == nil || ev.Rcv <= 0 {
			return fmt.Errorf("incomplete done event")
		}
		// Unknown pings and second dones are ignored (E:Storage/File.pm
		// 818-833 lists a done only once, and only for a ping sent).
		if p != nil && p.Status != PingDone {
			p.Status, p.Latency, p.Received, p.Err = PingDone, *ev.Lat, time.Unix(ev.Rcv, 0).UTC(), ""
		}
	case "abort":
		if p != nil && p.Status == PingOut {
			p.Status, p.Err = PingAborted, ev.Err
		}
	default:
		return fmt.Errorf("unknown event %q", ev.Ev)
	}
	return nil
}

// replayChains reads a chain ping journal; see replay.
func replayChains(data []byte, log *slog.Logger) (cs *chainPings, good int64) {
	cs = newChainPings()
	lineNo := 0
	for len(data[good:]) > 0 {
		line, _, complete := bytes.Cut(data[good:], []byte("\n"))
		if !complete {
			log.Warn("chain ping journal: dropping an incomplete last line", "line", lineNo+1, "bytes", len(line))
			break
		}
		lineNo++
		good += int64(len(line)) + 1
		var ev chainEvent
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		err := dec.Decode(&ev)
		if err == nil && dec.More() {
			err = errors.New("more than one event on the line")
		}
		if err == nil {
			err = cs.apply(ev)
		}
		if err != nil {
			log.Warn("chain ping journal: skipping a bad line", "line", lineNo, "err", err)
		}
	}
	return cs, good
}

func encodeChain(evs ...chainEvent) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	for _, ev := range evs {
		if err := enc.Encode(ev); err != nil {
			panic(err) // can't happen: plain strings and numbers
		}
	}
	return b.Bytes()
}

// compacted returns the journal for the chain pings sent at or after
// before.
func (cs *chainPings) compacted(before time.Time) (data []byte, keep map[uint64]*ChainPing) {
	keep = map[uint64]*ChainPing{}
	evs := []chainEvent{{Ev: "next", ID: cs.nextID}}
	for _, id := range slices.Sorted(maps.Keys(cs.byID)) {
		p := cs.byID[id]
		if p.Sent.Before(before) {
			continue
		}
		keep[id] = p
		evs = append(evs, chainOutEvent(p))
		switch p.Status {
		case PingDone:
			evs = append(evs, chainDoneEvent(p))
		case PingAborted:
			evs = append(evs, chainAbortEvent(p))
		}
	}
	return encodeChain(evs...), keep
}

// openChainJournal replays chainpings.jsonl, cuts off a write a crash
// interrupted, and opens it for appending; see openJournal.
func (s *Store) openChainJournal() error {
	path := filepath.Join(s.dir, chainJournalFile)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return err
	}
	cs, good := replayChains(data, s.log)
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
	if err := fileutil.SyncDir(s.dir); err != nil {
		f.Close()
		return err
	}
	s.chains, s.cjournal, s.cjsize = cs, f, good
	return nil
}

// chainJournalFailed stops all writes to the chain ping journal.
func (s *Store) chainJournalFailed(err error) error {
	s.log.Error("chain ping journal unusable until restart", "err", err)
	if s.cjournal != nil {
		s.cjournal.Close()
		s.cjournal = nil
	}
	s.cjerr = fmt.Errorf("chain ping journal unusable until restart: %w", err)
	return s.cjerr
}

// appendChainEvents writes evs to the chain ping journal and fsyncs it;
// see appendEvents.
func (s *Store) appendChainEvents(evs ...chainEvent) error {
	if s.cjerr != nil {
		return s.cjerr
	}
	if s.cjournal == nil {
		return errors.New("store is closed")
	}
	data := encodeChain(evs...)
	_, err := journalWrite(s.cjournal, data)
	if err == nil {
		err = s.cjournal.Sync()
	}
	if err != nil {
		if terr := s.cjournal.Truncate(s.cjsize); terr != nil {
			return s.chainJournalFailed(errors.Join(err, terr))
		}
		return fmt.Errorf("chain ping journal: %w", err)
	}
	s.cjsize += int64(len(data))
	return nil
}

// AddChainPing records a chain ping as sent, before it is sent (design
// §5.3): its A, KeyA, B, KeyB and Sent; the rest is ignored.  It returns
// the ping with its new ID.
func (s *Store) AddChainPing(in ChainPing) (ChainPing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &ChainPing{ID: s.chains.nextID, A: in.A, KeyA: in.KeyA, B: in.B, KeyB: in.KeyB,
		Sent: time.Unix(in.Sent.Unix(), 0).UTC()}
	if p.A == "" || p.KeyA == "" || p.B == "" || p.KeyB == "" || p.Sent.Unix() <= 0 {
		return ChainPing{}, errors.New("AddChainPing: empty address or keyid, or bad time")
	}
	// The ID is used up even if the write fails, as in AddPing.
	s.chains.nextID++
	ev := chainOutEvent(p)
	if err := s.appendChainEvents(ev); err != nil {
		return ChainPing{}, err
	}
	s.chains.apply(ev)
	return *p, nil
}

// ChainPingDone records that chain ping id came back at received, with
// latency in seconds.  It returns the ping and whether this was news:
// false for an unknown ping or one already back.
func (s *Store) ChainPingDone(id uint64, received time.Time, latency int64) (ChainPing, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.chains.byID[id]
	if p == nil {
		return ChainPing{}, false, nil
	}
	if p.Status == PingDone {
		return *p, false, nil
	}
	ev := chainDoneEvent(&ChainPing{ID: id, Received: received, Latency: latency})
	if ev.Rcv <= 0 {
		return ChainPing{}, false, errors.New("ChainPingDone: bad time")
	}
	if err := s.appendChainEvents(ev); err != nil {
		return ChainPing{}, false, err
	}
	s.chains.apply(ev)
	return *p, true, nil
}

// ChainPingAborted records that chain ping id failed before it left.
// Such pings don't count (unlike Echolot, which registers a chain ping
// whether or not the mix call worked, E:Chain.pm:113-122; design §5.3).
func (s *Store) ChainPingAborted(id uint64, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.chains.byID[id]
	if p == nil || p.Status != PingOut {
		return nil
	}
	ev := chainAbortEvent(&ChainPing{ID: id, Err: reason})
	if err := s.appendChainEvents(ev); err != nil {
		return err
	}
	s.chains.apply(ev)
	return nil
}

// ChainPings returns the chain pings sent at or after since, out and
// done, in the order sent (then by ID).  Aborted pings are left out.
// Echolot's window keeps a ping sent exactly at the cutoff
// (E:Stats.pm:578), hence "at or after"; chain.Evaluate applies the
// window itself, so since may be earlier.
func (s *Store) ChainPings(since time.Time) []ChainPing {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ps []ChainPing
	for _, p := range s.chains.byID {
		if p.Status == PingAborted || p.Sent.Before(since) {
			continue
		}
		ps = append(ps, *p)
	}
	slices.SortFunc(ps, func(a, b ChainPing) int {
		return cmp.Or(a.Sent.Compare(b.Sent), cmp.Compare(a.ID, b.ID))
	})
	return ps
}

// ChainPing returns chain ping id.
func (s *Store) ChainPing(id uint64) (ChainPing, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.chains.byID[id]; p != nil {
		return *p, true
	}
	return ChainPing{}, false
}

// CompactChains forgets the chain pings sent before before and rewrites
// the chain ping journal with the rest, keeping the next ID; see Compact.
func (s *Store) CompactChains(before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cjerr != nil {
		return s.cjerr
	}
	if s.cjournal == nil {
		return errors.New("store is closed")
	}
	data, keep := s.chains.compacted(before)
	path := filepath.Join(s.dir, chainJournalFile)
	werr := writeFile(path, data, 0o600)
	if werr != nil && !errors.Is(werr, fileutil.ErrDirSync) {
		return fmt.Errorf("compact chain ping journal: %w", werr)
	}
	s.chains.byID = keep
	s.cjournal.Close()
	s.cjournal = nil
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return s.chainJournalFailed(fmt.Errorf("reopen after compacting: %w", err))
	}
	s.cjournal, s.cjsize = f, int64(len(data))
	if werr != nil {
		s.log.Error("compacted chain ping journal may not survive a power loss", "err", werr)
	}
	return nil
}
