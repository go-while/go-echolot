package pinger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-while/go-echolot/internal/blake2s"
	"github.com/go-while/go-echolot/internal/civil"
	"github.com/go-while/go-echolot/internal/replies"
)

// selfTestAddress is the remailer of the self test.  Nothing is sent.
const selfTestAddress = "selftest@example.invalid"

// SelfTest encodes a ping to a throwaway key with enc, as the daemon and
// the selftest command do at startup: it shows that yamn runs, accepts
// the config and keyring go-echolot writes, and prints one mail.  The
// result is thrown away.
func SelfTest(ctx context.Context, enc Encoder, now time.Time) error {
	var pk [32]byte
	if _, err := rand.Read(pk[:]); err != nil {
		return err
	}
	sum := blake2s.Sum128(pk[:])
	today := civil.Of(now)
	key := replies.ParsedKey{
		SummaryLine: replies.SummaryLine{
			Nick: "selftest", Address: selfTestAddress, KeyID: hex.EncodeToString(sum[:]),
			Version: "4:0.2.7", Caps: "E", Created: today.AddDays(-1), Expires: today.AddDays(13),
		},
		PK: pk,
	}
	var macKey, boxKey [32]byte
	rand.Read(macKey[:])
	rand.Read(boxKey[:])
	b := Body{Remailer: selfTestAddress, Type: TypeMix, KeyID: key.KeyID, Sent: now, ID: 1}
	sealed, err := Seal(&macKey, &boxKey, b, 1024, rand.Reader)
	if err != nil {
		return fmt.Errorf("selftest: %w", err)
	}
	m := Mail("pinger-selftest@example.invalid", "", false, sealed)
	to, out, err := enc.Encode(ctx, []Hop{HopOf(key)}, m)
	if err != nil {
		return fmt.Errorf("selftest: %w", err)
	}
	if to != selfTestAddress || len(out) == 0 {
		return fmt.Errorf("selftest: encoder returned a mail to %q", to)
	}
	return nil
}
