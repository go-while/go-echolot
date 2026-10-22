package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"time"
)

// The ping journal, pings.jsonl, has one JSON event per line (design §5.2):
//
//	{"ev":"out","id":7,"addr":"…","key":"…","wf":0,"sent":1792560000}
//	{"ev":"done","id":7,"lat":1234,"rcv":1792561234}
//	{"ev":"abort","id":7,"err":"smtp: …"}
//	{"ev":"next","id":8}
//
// "next" is written first by Compact, so that ping IDs aren't reused
// after the pings with the highest IDs expire.

// PingStatus is where a ping is.
type PingStatus uint8

const (
	PingOut     PingStatus = iota // sent, not back (yet)
	PingDone                      // came back
	PingAborted                   // failed locally before it left; not a loss
)

// Ping is one ping to one key of a remailer.
type Ping struct {
	ID       uint64
	Addr     string
	KeyID    string
	WithFrom bool
	Sent     time.Time // whole seconds
	Status   PingStatus
	Received time.Time // PingDone only
	Latency  int64     // seconds; PingDone only
	Err      string    // PingAborted only
}

type event struct {
	Ev   string `json:"ev"`
	ID   uint64 `json:"id"`
	Addr string `json:"addr,omitempty"`
	Key  string `json:"key,omitempty"`
	WF   *int   `json:"wf,omitempty"`
	Sent int64  `json:"sent,omitempty"`
	Lat  *int64 `json:"lat,omitempty"`
	Rcv  int64  `json:"rcv,omitempty"`
	Err  string `json:"err,omitempty"`
}

func outEvent(p *Ping) event {
	wf := 0
	if p.WithFrom {
		wf = 1
	}
	return event{Ev: "out", ID: p.ID, Addr: p.Addr, Key: p.KeyID, WF: &wf, Sent: p.Sent.Unix()}
}

func doneEvent(p *Ping) event {
	lat := p.Latency
	return event{Ev: "done", ID: p.ID, Lat: &lat, Rcv: p.Received.Unix()}
}

func abortEvent(p *Ping) event {
	return event{Ev: "abort", ID: p.ID, Err: p.Err}
}

// pings is the in-memory form of the journal.
type pings struct {
	byID   map[uint64]*Ping
	nextID uint64
}

func newPings() *pings { return &pings{byID: map[uint64]*Ping{}, nextID: 1} }

// apply applies one event.  It returns an error for an event that makes
// no sense: replay logs and skips it.  Repeated events (a duplicate done)
// are not errors; mail can be processed twice after a crash (§5.3).
func (ps *pings) apply(ev event) error {
	p := ps.byID[ev.ID]
	switch ev.Ev {
	case "next":
		ps.nextID = max(ps.nextID, ev.ID)
	case "out":
		if ev.ID == 0 || ev.Addr == "" || ev.Key == "" || ev.Sent <= 0 || ev.WF == nil {
			return fmt.Errorf("incomplete out event")
		}
		if p != nil {
			return fmt.Errorf("ping %d sent twice", ev.ID)
		}
		ps.byID[ev.ID] = &Ping{ID: ev.ID, Addr: ev.Addr, KeyID: ev.Key, WithFrom: *ev.WF != 0, Sent: time.Unix(ev.Sent, 0).UTC()}
		ps.nextID = max(ps.nextID, ev.ID+1)
	case "done":
		if ev.Lat == nil || ev.Rcv <= 0 {
			return fmt.Errorf("incomplete done event")
		}
		// An unknown ping (expired, or from another state dir) and a
		// second done are ignored.  A done after an abort counts: the
		// ping did leave.
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

// replay reads a journal.  A last line without "\n" is a write cut short
// by a crash: replay returns the length without it, for the caller to
// truncate the file to.  Bad lines elsewhere are logged and skipped.
func replay(data []byte, log *slog.Logger) (ps *pings, good int64) {
	ps = newPings()
	lineNo := 0
	for len(data[good:]) > 0 {
		line, _, complete := bytes.Cut(data[good:], []byte("\n"))
		if !complete {
			log.Warn("ping journal: dropping an incomplete last line", "line", lineNo+1, "bytes", len(line))
			break
		}
		lineNo++
		good += int64(len(line)) + 1
		var ev event
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		err := dec.Decode(&ev)
		if err == nil && dec.More() {
			err = errors.New("more than one event on the line")
		}
		if err == nil {
			err = ps.apply(ev)
		}
		if err != nil {
			log.Warn("ping journal: skipping a bad line", "line", lineNo, "err", err)
		}
	}
	return ps, good
}

// encode returns the journal lines for evs.
func encode(evs ...event) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b) // one line per event, "\n" terminated
	enc.SetEscapeHTML(false)
	for _, ev := range evs {
		if err := enc.Encode(ev); err != nil {
			panic(err) // can't happen: plain strings and numbers
		}
	}
	return b.Bytes()
}

// compacted returns the journal for the pings sent at or after before.
func (ps *pings) compacted(before time.Time) (data []byte, keep map[uint64]*Ping) {
	keep = map[uint64]*Ping{}
	evs := []event{{Ev: "next", ID: ps.nextID}}
	for _, id := range slices.Sorted(maps.Keys(ps.byID)) {
		p := ps.byID[id]
		if p.Sent.Before(before) {
			continue
		}
		keep[id] = p
		evs = append(evs, outEvent(p))
		switch p.Status {
		case PingDone:
			evs = append(evs, doneEvent(p))
		case PingAborted:
			evs = append(evs, abortEvent(p))
		}
	}
	return encode(evs...), keep
}

// journalWrite writes to the journal file; tests replace it.
var journalWrite = (*os.File).Write
