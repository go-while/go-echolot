package output

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-while/go-echolot/internal/blake2s"
	"github.com/go-while/go-echolot/internal/keys"
	"github.com/go-while/go-echolot/internal/replies"
	"github.com/go-while/go-echolot/internal/store"
)

// Pubring returns the pubring.mix for ks (§7.1): per key its summary
// line, a blank line, the key block and a blank line, sorted by summary
// line.  An empty ks gives an empty file; yamn then keeps its previous
// copy.
//
// It refuses what would make yamn clients drop keys: a keyid that isn't
// BLAKE2s-128 of the key, a bad name or address, and a nick or address
// used twice (yamn drops both, Y:keymgr/public.go dropAmbiguous).
func Pubring(ks []replies.ParsedKey) ([]byte, error) {
	ks, err := checked(ks)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, k := range ks {
		fmt.Fprintf(&b, "%s\n\n-----Begin Mix Key-----\n%s\n%s\n-----End Mix Key-----\n\n",
			k.String(), k.KeyID, hex.EncodeToString(k.PK[:]))
	}
	return b.Bytes(), nil
}

// Type2List returns the type2.list for ks: the summary lines alone, in
// the order of Pubring (E:Stats.pm:834).
func Type2List(ks []replies.ParsedKey) ([]byte, error) {
	ks, err := checked(ks)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, k := range ks {
		b.WriteString(k.String() + "\n")
	}
	return b.Bytes(), nil
}

// checked returns ks sorted by summary line, after the checks of Pubring.
func checked(ks []replies.ParsedKey) ([]replies.ParsedKey, error) {
	ks = slices.Clone(ks)
	slices.SortFunc(ks, func(a, b replies.ParsedKey) int {
		return strings.Compare(a.String(), b.String())
	})
	nicks, addrs := map[string]bool{}, map[string]bool{}
	for _, k := range ks {
		sum := blake2s.Sum128(k.PK[:])
		switch {
		case hex.EncodeToString(sum[:]) != k.KeyID:
			return nil, fmt.Errorf("%s: keyid %s is not BLAKE2s of the key", k.Nick, k.KeyID)
		case !replies.ValidName(k.Nick) || !replies.ValidAddress(k.Address):
			return nil, fmt.Errorf("bad name or address in %q", k.String())
		case nicks[k.Nick]:
			return nil, fmt.Errorf("nick %s twice", k.Nick)
		case addrs[k.Address]:
			return nil, fmt.Errorf("address %s twice", k.Address)
		}
		nicks[k.Nick], addrs[k.Address] = true, true
	}
	return ks, nil
}

// testingCaps matches the caps of a remailer that asks not to be listed
// (E:Stats.pm:822).
var testingCaps = regexp.MustCompile(`(?i)\btesting\b`)

// Keyrings returns the keys to publish (§7.1): one per remailer, its
// Publishable key, if the remailer has a conf with the key's nick.
// private has them all; public only those of remailers that are
// "list-it": ShowIt, and no "testing" in the conf caps.
func Keyrings(st *store.State, now time.Time, requireProof bool) (public, private []replies.ParsedKey) {
	for _, rem := range st.Remailers {
		k := keys.Publishable(rem, now, requireProof)
		if k == nil || rem.Conf == nil || rem.Conf.Nick != k.Nick {
			continue
		}
		pk := replies.ParsedKey{
			SummaryLine: replies.SummaryLine{Nick: k.Nick, Address: k.Address, KeyID: k.KeyID,
				Version: k.Version, Caps: k.Caps, Created: k.Created, Expires: k.Expires},
			PK: [32]byte(k.PK),
		}
		private = append(private, pk)
		if rem.ShowIt && !testingCaps.MatchString(rem.Conf.Caps) {
			public = append(public, pk)
		}
	}
	return public, private
}

// WriteKeyrings writes pubring.mix and type2.list for ks into dir, each
// only if its content changed, and their .meta files if meta is set.  It
// reports whether pubring.mix changed.  Nothing is written if a check
// fails.
func WriteKeyrings(dir string, ks []replies.ParsedKey, now time.Time, meta bool, metaExpiry time.Duration) (changed bool, err error) {
	ring, err := Pubring(ks)
	if err != nil {
		return false, err
	}
	list, err := Type2List(ks)
	if err != nil {
		return false, err
	}
	// Check both before writing either, so they stay in step.
	if err := checkLines("pubring.mix", ring); err != nil {
		return false, err
	}
	if err := checkLines("type2.list", list); err != nil {
		return false, err
	}
	if changed, err = writeIfChanged(dir, "pubring.mix", ring); err != nil {
		return false, err
	}
	if _, err := writeIfChanged(dir, "type2.list", list); err != nil {
		return changed, err
	}
	if meta {
		for _, name := range []string{"pubring.mix", "type2.list"} {
			if err := writeMeta(dir, name, now.Add(metaExpiry)); err != nil {
				return changed, err
			}
		}
	}
	return changed, nil
}
