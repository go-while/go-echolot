package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-while/go-echolot/internal/civil"
	"github.com/go-while/go-echolot/internal/store"
	"github.com/go-while/go-echolot/internal/token"
)

func TestThesaurus(t *testing.T) {
	dir := t.TempDir()
	if n, err := PruneThesaurus(dir, t0, func(int) bool { return true }); n != 0 || err != nil {
		t.Errorf("no thesaurus: %d %v", n, err)
	}
	SaveThesaurus(dir, 1, token.KindKey, []byte("old"), t0.Add(-22*24*time.Hour))
	SaveThesaurus(dir, 1, token.KindConf, []byte("conf"), t0)
	SaveThesaurus(dir, 2, token.KindKey, []byte("gone"), t0)
	if err := SaveThesaurus(dir, 1, token.KindKey, []byte("new"), t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "thesaurus", "1.key"))
	if string(got) != "new" {
		t.Errorf("1.key = %q", got)
	}
	SaveThesaurus(dir, 3, token.KindHelp, []byte("x"), t0.Add(-22*24*time.Hour))
	n, err := PruneThesaurus(dir, t0, func(id int) bool { return id != 2 })
	if n != 2 || err != nil {
		t.Errorf("pruned %d, %v; want 2 (id 2 gone, 3.help too old)", n, err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "thesaurus"))
	if len(entries) != 2 {
		t.Errorf("left: %v", entries)
	}
}

func TestWriteStatus(t *testing.T) {
	st := newState()
	run(t, st, "add", "yamn@virebent.art", "victor")
	run(t, st, "add", "new@x.org")
	r := st.Remailers["yamn@virebent.art"]
	r.Keys = map[string]*store.Key{"dd34d8b7f010229bb790a2402c9ffe65": {
		KeyID: "dd34d8b7f010229bb790a2402c9ffe65", Nick: "victor", Address: "yamn@virebent.art",
		Created: civil.Date{Year: 2026, Month: 10, Day: 17}, Expires: civil.Date{Year: 2026, Month: 10, Day: 31},
		State: store.KeyStateActive, LastSeen: t0, ProvenAt: t0}}
	st.Pending = []store.PendingChange{{Address: "yamn@virebent.art", Kind: "key", Old: "dd34", New: "ee45", Since: t0}}
	st.Prospective = map[string][]store.Suggestion{"other@y.org": {{Reason: "supported by victor"}}}
	var b bytes.Buffer
	if err := WriteStatus(&b, st, t0, true, ""); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(no nick yet) new@x.org  id 2  active",
		"victor yamn@virebent.art  id 1  active  showit=on pingit=on fetch=on  ttl 5",
		"  * key dd34d8b7f010229bb790a2402c9ffe65 2026-10-17..2026-10-31 active, proven 2026-10-22T12:00:00Z",
		"  yamn@virebent.art: key dd34 -> ee45 since",
		"  other@y.org: supported by victor",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
	b.Reset()
	if err := WriteStatus(&b, st, t0, true, "yamn@virebent.art"); err != nil || strings.Contains(b.String(), "new@x.org") || strings.Contains(b.String(), "suggestions") {
		t.Errorf("one remailer: %v\n%s", err, b.String())
	}
	if err := WriteStatus(&b, st, t0, true, "nosuch@x.org"); err == nil {
		t.Error("unknown address")
	}
}
