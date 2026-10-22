package civil

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	d, err := Parse("2026-10-22")
	if err != nil || d != (Date{2026, time.October, 22}) || d.String() != "2026-10-22" {
		t.Errorf("got %v, %v", d, err)
	}
	for _, bad := range []string{"", "2026-1-22", "2026-10-2", "2026-02-30", "2026-13-01", "22.10.2026", "2026-10-22T00:00:00Z", " 2026-10-22"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestOf(t *testing.T) {
	// 01:30 in UTC+3 is still the previous day in UTC.
	tz := time.FixedZone("UTC+3", 3*3600)
	if d := Of(time.Date(2026, 10, 22, 1, 30, 0, 0, tz)); d != (Date{2026, time.October, 21}) {
		t.Errorf("got %v", d)
	}
}

func TestStartEnd(t *testing.T) {
	d := Date{2026, time.December, 31}
	if got, want := d.Start(), time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("Start: %v", got)
	}
	if got, want := d.End(), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("End: %v", got)
	}
	if got := d.AddDays(1); got != (Date{2027, time.January, 1}) {
		t.Errorf("AddDays(1): %v", got)
	}
	if got := (Date{2028, time.March, 1}).AddDays(-1); got != (Date{2028, time.February, 29}) {
		t.Errorf("AddDays(-1) in a leap year: %v", got)
	}
}

func TestCompare(t *testing.T) {
	a, b := Date{2026, time.October, 22}, Date{2026, time.November, 1}
	if !a.Before(b) || a.After(b) || !b.After(a) || a.Compare(a) != 0 || a.Before(a) {
		t.Error("wrong order")
	}
}

func TestJSON(t *testing.T) {
	type rec struct {
		A, B Date
	}
	in := rec{A: Date{2026, time.October, 22}}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"A":"2026-10-22","B":""}` {
		t.Errorf("got %s", data)
	}
	var out rec
	if err := json.Unmarshal(data, &out); err != nil || out != in {
		t.Errorf("got %+v, %v", out, err)
	}
	if err := json.Unmarshal([]byte(`{"A":"2026-10-32"}`), &out); err == nil {
		t.Error("bad date accepted")
	}
}
