package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/store"
)

var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func newState() *store.State {
	return &store.State{Version: store.StateVersion, Remailers: map[string]*store.Remailer{}}
}

func run(t *testing.T, st *store.State, verb string, args ...string) []string {
	t.Helper()
	out, err := Apply(st, Command{Verb: verb, Args: args}, t0)
	if err != nil {
		t.Fatalf("%s %v: %v", verb, args, err)
	}
	return out
}

func TestAddDelete(t *testing.T) {
	st := newState()
	st.Prospective = map[string][]store.Suggestion{"yamn@virebent.art": {{Reason: "supported"}}}
	out := run(t, st, "add", "yamn@virebent.art", "victor")
	if len(out) != 1 || out[0] != "added yamn@virebent.art (id 1), nick victor pinned" {
		t.Errorf("%q", out)
	}
	r := st.Remailers["yamn@virebent.art"]
	if r.Nick != "victor" || !r.Fetch || !r.PingIt || !r.ShowIt || len(st.Prospective) != 0 {
		t.Errorf("%+v %v", r, st.Prospective)
	}
	run(t, st, "add", "yamn@mixmin.net")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"yamn@VIREBENT.art"}, "already known"},
		{[]string{"a b@x.org"}, "not a remailer address"},
		{[]string{"x@x.org", "Victor"}, "nick"},
		{[]string{"x@x.org", "abcdefghijklm"}, "at most 12"},
		{[]string{"x@x.org", "victor"}, "pinned to yamn@virebent.art"},
		{nil, "usage"},
	} {
		if _, err := Apply(st, Command{Verb: "add", Args: tc.args}, t0); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("add %v: %v", tc.args, err)
		}
	}
	st.Pending = []store.PendingChange{{Address: "yamn@mixmin.net", Kind: store.PendingKeyChange}}
	run(t, st, "delete", "yamn@MIXMIN.NET")
	if len(st.Remailers) != 1 || len(st.Pending) != 0 {
		t.Errorf("after delete: %v %v", st.Remailers, st.Pending)
	}
	if _, err := Apply(st, Command{Verb: "delete", Args: []string{"nosuch@x.org"}}, t0); err == nil {
		t.Error("delete of an unknown address")
	}
}

func TestEnableDisableSet(t *testing.T) {
	st := newState()
	run(t, st, "add", "a@x.org")
	run(t, st, "add", "b@x.org")
	run(t, st, "disable", "a@x.org", "b@x.org")
	a := st.Remailers["a@x.org"]
	if a.Fetch || a.PingIt || a.ShowIt || a.Status != store.StatusDisabled {
		t.Errorf("disabled: %+v", a)
	}
	a.TTL = 0
	run(t, st, "enable", "a@x.org")
	if !a.Fetch || !a.PingIt || !a.ShowIt || a.Status != store.StatusActive || a.TTL != store.DefaultTTL {
		t.Errorf("enabled: %+v", a)
	}
	a.Status = store.StatusTTLTimeout
	run(t, st, "enable", "a@x.org") // doesn't touch a TTL state
	if a.Status != store.StatusTTLTimeout {
		t.Errorf("enable changed %s", a.Status)
	}
	out := run(t, st, "set", "showit=off", "fetch=on", "b@x.org")
	if b := st.Remailers["b@x.org"]; b.ShowIt || !b.Fetch || b.PingIt || out[0] != "b@x.org: showit=off pingit=off fetch=on" {
		t.Errorf("set: %+v %q", b, out)
	}
	for _, args := range [][]string{{"showit=off"}, {"b@x.org"}, {"showit=maybe", "b@x.org"}, {"color=red", "b@x.org"}} {
		if _, err := Apply(st, Command{Verb: "set", Args: args}, t0); err == nil {
			t.Errorf("set %v accepted", args)
		}
	}
	// One unknown address: nothing is changed.
	if _, err := Apply(st, Command{Verb: "disable", Args: []string{"a@x.org", "nosuch@x.org"}}, t0); err == nil || !st.Remailers["a@x.org"].Fetch {
		t.Errorf("partial disable: %v", err)
	}
}

func TestApproveReject(t *testing.T) {
	st := newState()
	run(t, st, "add", "yamn@mixmin.net", "yamn")
	st.Pending = []store.PendingChange{{Address: "yamn@mixmin.net", Kind: store.PendingNickChange, Old: "yamn", New: "yamn9", Since: t0}}
	out := run(t, st, "approve", "yamn@mixmin.net", "nick")
	if st.Remailers["yamn@mixmin.net"].Nick != "yamn9" || len(out) == 0 {
		t.Errorf("approve: %q %+v", out, st.Remailers["yamn@mixmin.net"])
	}
	for _, args := range [][]string{nil, {"nosuch@x.org"}, {"a", "b", "c"}} {
		if _, err := Apply(st, Command{Verb: "reject", Args: args}, t0); err == nil {
			t.Errorf("reject %v accepted", args)
		}
	}
	if _, err := Apply(st, Command{Verb: "frobnicate"}, t0); err == nil {
		t.Error("unknown verb accepted")
	}
}

func TestSpool(t *testing.T) {
	dir := t.TempDir()
	if cmds, errs := ReadSpool(dir); cmds != nil || errs != nil {
		t.Errorf("no spool dir: %v %v", cmds, errs)
	}
	for i, c := range []Command{{Verb: "add", Args: []string{"a@x.org"}}, {Verb: "enable", Args: []string{"a@x.org"}}} {
		if err := Spool(dir, c, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	spool := filepath.Join(dir, "commands")
	os.WriteFile(filepath.Join(spool, "00-bad.json"), []byte("{"), 0o600)
	os.WriteFile(filepath.Join(spool, ".tmp-half.json"), []byte("{"), 0o600) // an interrupted write
	cmds, errs := ReadSpool(dir)
	if len(cmds) != 2 || cmds[0].Verb != "add" || cmds[1].Verb != "enable" || len(errs) != 1 {
		t.Fatalf("%+v %v", cmds, errs)
	}
	if _, err := os.Stat(filepath.Join(spool, "00-bad.json.bad")); err != nil {
		t.Error("bad command not set aside")
	}
	if err := cmds[0].Start(); err != nil {
		t.Fatal(err)
	}
	cmds[0].Done()
	if cmds, _ := ReadSpool(dir); len(cmds) != 1 || cmds[0].Verb != "enable" {
		t.Errorf("after Done: %+v", cmds)
	}
	// A crash while running: the command isn't run again.
	cmds, _ = ReadSpool(dir)
	cmds[0].Start()
	if cmds, errs := ReadSpool(dir); len(cmds) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "interrupted") {
		t.Errorf("after an interrupted run: %+v %v", cmds, errs)
	}
	if fi, _ := os.Stat(spool); fi.Mode().Perm() != 0o700 {
		t.Errorf("spool mode %v", fi.Mode())
	}
}
