package app

import (
	"bytes"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/store"
)

// Fromlines record what an exit does to a mail, from the pings that come
// back through it (E:Pinger.pm:150-205, E:Fromlines.pm): the From header
// it delivers, with and without a From of the sender (with_from), and
// whether it adds text above or below the message.  The HTML page shows
// them (phase 3).

// The armor of a sealed ping (internal/pinger, design §6.3).
const (
	pingArmorBegin = "-----BEGIN ECHOLOT PING-----"
	pingArmorEnd   = "-----END ECHOLOT PING-----"
)

// fromlineMaxAge: fromlines expire as in Echolot (§5.5: 5 days).
const fromlineMaxAge = 5 * 24 * time.Hour

// maxFromLen bounds the From header kept: it comes from the remailer.
const maxFromLen = 256

// recordFromline stores what the ping that came back through addr shows.
// from is its From header ("" if none), body its decoded body.
func recordFromline(st *store.State, addr string, withFrom bool, from string, body []byte, at time.Time) {
	if st.Remailers[addr] == nil {
		return
	}
	top, bot := disclaimers(body)
	if from == "" {
		from = "undefined" // as Echolot
	}
	wf := 0
	if withFrom {
		wf = 1
	}
	if st.Fromlines == nil {
		st.Fromlines = map[string]map[int]store.Fromline{}
	}
	if st.Fromlines[addr] == nil {
		st.Fromlines[addr] = map[int]store.Fromline{}
	}
	if old, ok := st.Fromlines[addr][wf]; ok && !at.After(old.LastUpdate) {
		return
	}
	st.Fromlines[addr][wf] = store.Fromline{LastUpdate: at.UTC(), From: cleanFrom(from), DisclaimTop: top, DisclaimBot: bot}
}

// disclaimers reports whether non-blank text comes before the ping's
// armor (top) or after it (bot), as E:Pinger.pm:166-167.
func disclaimers(body []byte) (top, bot bool) {
	i := bytes.Index(body, []byte(pingArmorBegin))
	j := bytes.LastIndex(body, []byte(pingArmorEnd))
	if i < 0 || j < 0 {
		return false, false
	}
	top = len(bytes.TrimSpace(body[:i])) > 0
	bot = len(bytes.TrimSpace(body[j+len(pingArmorEnd):])) > 0
	return top, bot
}

// cleanFrom keeps printable ASCII of a From header, at most maxFromLen.
func cleanFrom(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return '?'
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > maxFromLen {
		s = s[:maxFromLen] + "..."
	}
	return s
}

// expireFromlines drops fromlines older than fromlineMaxAge and those of
// remailers that are gone.
func expireFromlines(st *store.State, now time.Time) {
	for addr, m := range st.Fromlines {
		for wf, f := range m {
			if now.Sub(f.LastUpdate) > fromlineMaxAge || st.Remailers[addr] == nil {
				delete(m, wf)
			}
		}
		if len(m) == 0 {
			delete(st.Fromlines, addr)
		}
	}
}
