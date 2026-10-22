package config

import (
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	durationType = reflect.TypeFor[time.Duration]()
	timeType     = reflect.TypeFor[time.Time]()
)

// decode sets the fields of c from secs.  A struct field of Config is a
// section; a slice field ([]Peer) is a repeated [name label] section.
func decode(c *Config, secs []section) []error {
	var errs []error
	seen := map[string]int{} // "name label" -> line
	cv := reflect.ValueOf(c).Elem()
	for _, s := range secs {
		if s.name == "" { // broken header, already reported
			continue
		}
		f, ok := fieldByTag(cv, s.name)
		if !ok {
			errs = append(errs, errorAt(s.line, "unknown section [%s]", s.name))
			continue
		}
		id := strings.TrimSpace(s.name + " " + s.label)
		if prev, dup := seen[id]; dup {
			errs = append(errs, errorAt(s.line, "[%s] again, first at line %d", id, prev))
			continue
		}
		seen[id] = s.line
		var target reflect.Value
		switch f.Kind() {
		case reflect.Struct:
			if s.label != "" {
				errs = append(errs, errorAt(s.line, "[%s] takes no name", s.name))
				continue
			}
			target = f
		case reflect.Slice:
			if s.label == "" {
				errs = append(errs, errorAt(s.line, "[%s] needs a name: [%s <name>]", s.name, s.name))
				continue
			}
			f.Set(reflect.Append(f, reflect.Zero(f.Type().Elem())))
			target = f.Index(f.Len() - 1)
			target.FieldByName("Name").SetString(s.label)
		}
		keys := map[string]int{}
		for _, kv := range s.keys {
			if prev, dup := keys[kv.key]; dup {
				errs = append(errs, errorAt(kv.line, "%s.%s again, first at line %d", s.name, kv.key, prev))
				continue
			}
			keys[kv.key] = kv.line
			fv, ok := fieldByTag(target, kv.key)
			if !ok {
				errs = append(errs, errorAt(kv.line, "unknown key %q in [%s]", kv.key, s.name))
				continue
			}
			if err := setValue(fv, kv.value); err != nil {
				errs = append(errs, errorAt(kv.line, "%s.%s: %v", s.name, kv.key, err))
			}
		}
	}
	return errs
}

// fieldByTag returns the field of struct v whose ini tag is name.
func fieldByTag(v reflect.Value, name string) (reflect.Value, bool) {
	for i := range v.NumField() {
		if v.Type().Field(i).Tag.Get("ini") == name {
			return v.Field(i), true
		}
	}
	return reflect.Value{}, false
}

// setValue parses s into v.  An empty value clears a string, list or
// time; the other types need a value.
func setValue(v reflect.Value, s string) error {
	switch v.Type() {
	case durationType:
		if s == "" {
			return fmt.Errorf("needs a duration, e.g. 30s, 5m, 2h")
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("bad duration %q: use e.g. 30s, 5m, 2h", s)
		}
		v.SetInt(int64(d))
		return nil
	case timeType:
		var t time.Time
		if s != "" {
			var err error
			if t, err = time.Parse(time.RFC3339, s); err != nil {
				return fmt.Errorf("bad time %q: use RFC 3339, e.g. 2026-10-24T12:00:00Z", s)
			}
			t = t.UTC()
		}
		v.Set(reflect.ValueOf(t))
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(s)
	case reflect.Bool:
		b, err := parseBool(s)
		if err != nil {
			return err
		}
		v.SetBool(b)
	case reflect.Int:
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("needs a whole number, not %q", s)
		}
		v.SetInt(int64(n))
	case reflect.Float64:
		f, err := parseFloat(s)
		if err != nil {
			return err
		}
		v.SetFloat(f)
	case reflect.Slice:
		items, err := splitList(s)
		if err != nil {
			return err
		}
		out := reflect.MakeSlice(v.Type(), 0, len(items))
		for _, item := range items {
			e := reflect.New(v.Type().Elem()).Elem()
			if err := setValue(e, item); err != nil {
				return err
			}
			out = reflect.Append(out, e)
		}
		if len(items) == 0 {
			out = reflect.Zero(v.Type())
		}
		v.Set(out)
	default:
		panic("config: unsupported field type " + v.Type().String())
	}
	return nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("needs true or false, not %q", s)
}

func parseFloat(s string) (float64, error) {
	f, err := strconv.ParseFloat(s, 64)
	// No NaN, Inf or hex floats: only plain decimal numbers.
	if err != nil || strings.ContainsAny(strings.ToLower(s), "nix") {
		return 0, fmt.Errorf("needs a number, not %q", s)
	}
	return f, nil
}

// splitList splits a comma-separated list.  "" is the empty list.
func splitList(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	items := strings.Split(s, ",")
	for i, item := range items {
		if items[i] = strings.TrimSpace(item); items[i] == "" {
			return nil, fmt.Errorf("empty item in list %q", s)
		}
	}
	return items, nil
}

// Format writes c in the config file format.  Load reads it back to the
// same Config.
func (c *Config) Format(w io.Writer) error {
	var b strings.Builder
	cv := reflect.ValueOf(c).Elem()
	for i := range cv.NumField() {
		name := cv.Type().Field(i).Tag.Get("ini")
		f := cv.Field(i)
		if f.Kind() == reflect.Slice {
			for j := range f.Len() {
				e := f.Index(j)
				fmt.Fprintf(&b, "\n[%s %s]\n", name, e.FieldByName("Name").String())
				formatKeys(&b, e)
			}
			continue
		}
		fmt.Fprintf(&b, "\n[%s]\n", name)
		formatKeys(&b, f)
	}
	_, err := io.WriteString(w, strings.TrimPrefix(b.String(), "\n"))
	return err
}

func formatKeys(b *strings.Builder, v reflect.Value) {
	for i := range v.NumField() {
		key := v.Type().Field(i).Tag.Get("ini")
		if key == "-" {
			continue
		}
		if s := formatValue(v.Field(i)); s == "" {
			fmt.Fprintf(b, "%s =\n", key)
		} else {
			fmt.Fprintf(b, "%s = %s\n", key, s)
		}
	}
}

func formatValue(v reflect.Value) string {
	switch v.Type() {
	case durationType:
		return formatDuration(time.Duration(v.Int()))
	case timeType:
		if t := v.Interface().(time.Time); !t.IsZero() {
			return t.Format(time.RFC3339Nano)
		}
		return ""
	}
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Int:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Float64:
		s := strconv.FormatFloat(v.Float(), 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	case reflect.Slice:
		items := make([]string, v.Len())
		for i := range items {
			items[i] = formatValue(v.Index(i))
		}
		return strings.Join(items, ", ")
	}
	panic("config: unsupported field type " + v.Type().String())
}

// formatDuration writes d in the largest unit that holds it exactly:
// 168h rather than 168h0m0s.
func formatDuration(d time.Duration) string {
	for _, u := range []struct {
		d time.Duration
		s string
	}{{time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if d != 0 && d%u.d == 0 {
			return strconv.FormatInt(int64(d/u.d), 10) + u.s
		}
	}
	return d.String()
}
