package replies

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-while/go-echolot/internal/blake2s"
)

const (
	beginLine = "-----Begin Mix Key-----"
	endLine   = "-----End Mix Key-----"
)

// ParseKey returns every key block in body: a key reply or a whole
// pubring.mix.  It follows yamn's readPubring (Y:keymgr/public.go): a
// summary line, then (other lines skipped) the Begin line, the keyid, the
// public key, then (other lines skipped) the End line.  Where yamn would
// pair a summary line with the wrong block (a second summary line before
// Begin, or a summary or Begin line before End), both keys are dropped
// with an error.  body should be LF text (see Body); a trailing CR on a
// line is ignored anyway.
func ParseKey(body []byte) *KeyReply {
	r := &KeyReply{}
	fail := func(format string, a ...any) {
		r.Errors = append(r.Errors, fmt.Errorf(format, a...))
	}
	var (
		cur     ParsedKey
		phase   int  // yamn's key_phase: 0 header, 1 Begin, 2 keyid, 3 pk, 4 End
		blocked bool // the last summary line was rejected; its block is expected
	)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		switch phase {
		case 0:
			if line == beginLine {
				if !blocked {
					fail("key block without summary line")
				}
				blocked = false
				continue
			}
			if !isSummaryShape(line) {
				continue
			}
			s, err := ParseSummary(line)
			if err != nil {
				fail("%w", err)
				blocked = true
				continue
			}
			cur = ParsedKey{SummaryLine: s}
			blocked = false
			phase = 1
		case 1:
			switch {
			case line == beginLine:
				phase = 2
			case isSummaryShape(line):
				fail("%s: summary line without key block", cur.Nick)
				phase = 0
			}
		case 2:
			keyid, ok := hexID(line)
			switch {
			case !ok:
				fail("%s: keyid in block is not 32 hex digits", cur.Nick)
				phase = 0
			case keyid != cur.KeyID:
				fail("%s: keyid in header differs from keyid in block", cur.Nick)
				phase = 0
			default:
				phase = 3
			}
		case 3:
			pk, err := hex.DecodeString(line)
			if err != nil || len(pk) != len(cur.PK) {
				fail("%s: public key is not 64 hex digits", cur.Nick)
				phase = 0
				continue
			}
			copy(cur.PK[:], pk)
			sum := blake2s.Sum128(pk)
			if hex.EncodeToString(sum[:]) != cur.KeyID {
				fail("%s: keyid %s is not BLAKE2s of the public key", cur.Nick, cur.KeyID)
				phase = 0
				continue
			}
			phase = 4
		case 4:
			switch {
			case line == endLine:
				r.Keys = append(r.Keys, cur)
				phase = 0
			case line == beginLine || isSummaryShape(line):
				fail("%s: no End line after key", cur.Nick)
				phase = 0
			}
		}
	}
	switch phase {
	case 1:
		fail("%s: summary line without key block", cur.Nick)
	case 2, 3:
		fail("%s: key block ends early", cur.Nick)
	case 4:
		fail("%s: no End line after key", cur.Nick)
	}
	return r
}
