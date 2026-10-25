package main

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// noLatency is Echolot's "99:59", a remailer without returned pings.
const noLatency = 99*time.Hour + 59*time.Minute

// row is one remailer line of mlist2.txt:
//
//	11101        ???????????0    :03   ???????????+  100.0%    M     T
type row struct {
	latency time.Duration
	uptime  float64 // percent
	options string
}

// parseMlist2 reads the Generated time and the remailer table (the lines
// after the dashes, up to the first empty line).
func parseMlist2(data []byte) (time.Time, map[string]row, error) {
	var gen time.Time
	rows := map[string]row{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	inTable := false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		switch {
		case strings.HasPrefix(line, "Generated:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "Generated:"))
			for _, layout := range []string{"Mon 02 Jan 2006 15:04:05 GMT", "Mon _2 Jan 2006 15:04:05 GMT", time.RFC1123Z} {
				if t, err := time.Parse(layout, v); err == nil {
					gen = t
					break
				}
			}
		case strings.HasPrefix(line, "-----"):
			inTable = true
		case inTable && line == "":
			if len(rows) > 0 {
				return gen, rows, nil
			}
		case inTable:
			name, r, err := parseRow(line)
			if err != nil {
				return gen, nil, err
			}
			rows[name] = r
		}
	}
	if err := sc.Err(); err != nil {
		return gen, nil, err
	}
	if !inTable {
		return gen, nil, errNoTable
	}
	return gen, rows, nil
}

func parseRow(line string) (string, row, error) {
	f := strings.Fields(line)
	if len(f) < 5 {
		return "", row{}, fmt.Errorf("mlist2.txt: short line %q", line)
	}
	lat, err := parseLatency(f[2])
	if err != nil {
		return "", row{}, fmt.Errorf("mlist2.txt: %q: %w", line, err)
	}
	up, err := strconv.ParseFloat(strings.TrimSuffix(f[4], "%"), 64)
	if err != nil || !strings.HasSuffix(f[4], "%") {
		return "", row{}, fmt.Errorf("mlist2.txt: %q: bad uptime %q", line, f[4])
	}
	return f[0], row{latency: lat, uptime: up, options: strings.Join(f[5:], " ")}, nil
}

// parseLatency reads Echolot's "h:mm" or ":mm".
func parseLatency(s string) (time.Duration, error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(m) != 2 {
		return 0, fmt.Errorf("bad latency %q", s)
	}
	hours := 0
	if h != "" {
		var err error
		if hours, err = strconv.Atoi(h); err != nil || hours < 0 {
			return 0, fmt.Errorf("bad latency %q", s)
		}
	}
	mins, err := strconv.Atoi(m)
	if err != nil || mins < 0 || mins > 59 {
		return 0, fmt.Errorf("bad latency %q", s)
	}
	return time.Duration(hours)*time.Hour + time.Duration(mins)*time.Minute, nil
}
