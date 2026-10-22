// Package app ties go-echolot's packages together: the operator commands,
// their spool for a running daemon, and the daemon itself.
package app

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// Command is an operator command that changes the state (design §10.4).
// It is applied directly when no daemon runs, or spooled for the daemon.
type Command struct {
	Verb string   `json:"verb"`
	Args []string `json:"args,omitempty"`
}

func (c Command) String() string { return strings.TrimSpace(c.Verb + " " + strings.Join(c.Args, " ")) }

// stateVerbs are the commands Apply knows.  getkeyconf and buildkeys are
// for the daemon (Daemon.command).
var stateVerbs = []string{"add", "delete", "enable", "disable", "set", "approve", "reject"}

// Apply applies c to st.  It returns what to tell the operator.  On an
// error st may be half changed; the caller runs it inside store.Update,
// which then throws the changes away.
func Apply(st *store.State, c Command, now time.Time) ([]string, error) {
	switch c.Verb {
	case "add":
		return add(st, c.Args, now)
	case "delete":
		return forEach(st, c.Args, func(r *store.Remailer) string {
			delete(st.Remailers, r.Address)
			st.Pending = slices.DeleteFunc(st.Pending, func(p store.PendingChange) bool { return p.Address == r.Address })
			return "deleted " + r.Address
		})
	case "enable", "disable":
		on := c.Verb == "enable"
		return forEach(st, c.Args, func(r *store.Remailer) string {
			r.ShowIt, r.PingIt, r.Fetch = on, on, on
			switch {
			case !on:
				r.Status = store.StatusDisabled
			case r.Status == store.StatusDisabled || r.Status == store.StatusNotARemailer:
				r.Status = store.StatusActive
				keys.RestoreTTL(r)
			}
			return c.Verb + "d " + r.Address
		})
	case "set":
		return set(st, c.Args)
	case "approve", "reject":
		if len(c.Args) < 1 || len(c.Args) > 2 {
			return nil, fmt.Errorf("usage: %s <address> [keyid|nick|address|key]", c.Verb)
		}
		r := find(st, c.Args[0])
		if r == nil {
			return nil, fmt.Errorf("%s is not a known remailer", c.Args[0])
		}
		what := ""
		if len(c.Args) == 2 {
			what = c.Args[1]
		}
		f := keys.Approve
		if c.Verb == "reject" {
			f = keys.Reject
		}
		res, err := f(st, r.Address, what, now)
		var out []string
		for _, x := range res {
			out = append(out, x.String())
		}
		return out, err
	}
	return nil, fmt.Errorf("unknown command %q", c.Verb)
}

// add adds a remailer: add <address> [nick].  A nick given here is pinned
// at once, as design §9.2 allows the operator to.
func add(st *store.State, args []string, now time.Time) ([]string, error) {
	if len(args) < 1 || len(args) > 2 {
		return nil, errors.New("usage: add <address> [nick]")
	}
	addr := args[0]
	if !replies.ValidAddress(addr) {
		return nil, fmt.Errorf("%q is not a remailer address yamn accepts", addr)
	}
	if r := find(st, addr); r != nil {
		return nil, fmt.Errorf("%s is already known (as %s)", addr, r.Address)
	}
	nick := ""
	if len(args) == 2 {
		nick = args[1]
		if !replies.ValidName(nick) || len(nick) > keys.MaxNickLen {
			return nil, fmt.Errorf("nick %q: use a-z and 0-9, at most %d characters", nick, keys.MaxNickLen)
		}
		for _, r := range st.Remailers {
			if r.Nick == nick {
				return nil, fmt.Errorf("nick %s is pinned to %s", nick, r.Address)
			}
		}
	}
	r, err := st.AddRemailer(addr, now)
	if err != nil {
		return nil, err
	}
	r.Nick = nick
	st.Prospective = deleteSuggestions(st.Prospective, addr)
	msg := fmt.Sprintf("added %s (id %d)", addr, r.ID)
	if nick != "" {
		msg += ", nick " + nick + " pinned"
	}
	return []string{msg}, nil
}

// set changes flags: set showit|pingit|fetch=on|off ... <address> ...
// (E:pingd command_set).
func set(st *store.State, args []string) ([]string, error) {
	var settings, addrs []string
	for _, a := range args {
		if strings.Contains(a, "=") {
			settings = append(settings, a)
		} else {
			addrs = append(addrs, a)
		}
	}
	if len(settings) == 0 || len(addrs) == 0 {
		return nil, errors.New("usage: set showit|pingit|fetch=on|off ... <address> ...")
	}
	type flag struct {
		name string
		on   bool
	}
	var flags []flag
	for _, s := range settings {
		name, v, _ := strings.Cut(s, "=")
		if name != "showit" && name != "pingit" && name != "fetch" || v != "on" && v != "off" {
			return nil, fmt.Errorf("bad setting %q: use showit, pingit or fetch = on or off", s)
		}
		flags = append(flags, flag{name, v == "on"})
	}
	return forEach(st, addrs, func(r *store.Remailer) string {
		for _, f := range flags {
			switch f.name {
			case "showit":
				r.ShowIt = f.on
			case "pingit":
				r.PingIt = f.on
			case "fetch":
				r.Fetch = f.on
			}
		}
		return fmt.Sprintf("%s: showit=%s pingit=%s fetch=%s", r.Address, onOff(r.ShowIt), onOff(r.PingIt), onOff(r.Fetch))
	})
}

// forEach applies f to the remailer of every address; all must be known.
func forEach(st *store.State, addrs []string, f func(*store.Remailer) string) ([]string, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no address given")
	}
	var rems []*store.Remailer
	for _, a := range addrs {
		r := find(st, a)
		if r == nil {
			return nil, fmt.Errorf("%s is not a known remailer", a)
		}
		rems = append(rems, r)
	}
	var out []string
	for _, r := range rems {
		out = append(out, f(r))
	}
	return out, nil
}

// find returns the remailer with address a (domain in any case), or nil.
func find(st *store.State, a string) *store.Remailer {
	if r := st.Remailers[a]; r != nil {
		return r
	}
	for _, r := range st.Remailers {
		if keys.SameAddress(r.Address, a) {
			return r
		}
	}
	return nil
}

func deleteSuggestions(p map[string][]store.Suggestion, addr string) map[string][]store.Suggestion {
	for a := range p {
		if keys.SameAddress(a, addr) {
			delete(p, a)
		}
	}
	return p
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
