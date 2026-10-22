package store

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-while/go-echolot/internal/civil"
)

// StateVersion is the version of state.json this code reads and writes.
const StateVersion = 1

// Defaults of a new remailer (E:Storage/File.pm, design §8.5).
const (
	DefaultTTL             = 5 // conf requests without a reply until "ttl timeout"
	DefaultResurrectionTTL = 8 // weekly checks in "ttl timeout" until "dead"
)

// Remailer states (Remailer.Status), as Echolot's.
const (
	StatusActive       = "active"
	StatusTTLTimeout   = "ttl timeout"
	StatusDead         = "dead"
	StatusNotARemailer = "disabled: not a remailer"
	StatusDisabled     = "disabled"
)

// Key states (Key.State).
const (
	KeyStateActive      = "active"
	KeyStateQuarantined = "quarantined"
	KeyStateRejected    = "rejected"
)

// Kinds of quarantined change (PendingChange.Kind).
const (
	PendingKeyChange     = "key"
	PendingNickChange    = "nick"
	PendingAddressChange = "address"
)

// State is everything in state.json (design §5.1).  Pings are in the
// journal, not here.
type State struct {
	Version     int                         `json:"version"`
	MaxID       int                         `json:"max_id"`                // highest Remailer.ID given out
	Remailers   map[string]*Remailer        `json:"remailers"`             // by address
	Prospective map[string][]Suggestion     `json:"prospective,omitempty"` // by address
	Pending     []PendingChange             `json:"pending,omitempty"`     // quarantined changes
	Fromlines   map[string]map[int]Fromline `json:"fromlines,omitempty"`   // address -> with_from -> line (phase 3)
	// Signed is the newest signature timestamp (Unix seconds) per signing
	// key and file, "<KEYID>/<file>" (design §9.5): saved before the
	// signature is published, so timestamps never go backwards, also
	// after a restart.
	Signed map[string]int64 `json:"signed,omitempty"`
}

// Remailer is one remailer address the pinger knows.
type Remailer struct {
	ID              int             `json:"id"` // stable; in tokens and thesaurus names
	Address         string          `json:"address"`
	Nick            string          `json:"nick"` // pinned nick; "" until the first accepted conf
	Status          string          `json:"status"`
	TTL             int             `json:"ttl"`
	ResurrectionTTL int             `json:"resurrection_ttl"`
	Fetch           bool            `json:"fetch"`
	PingIt          bool            `json:"pingit"`
	ShowIt          bool            `json:"showit"`
	Added           time.Time       `json:"added"`
	Conf            *Conf           `json:"conf,omitempty"`
	Keys            map[string]*Key `json:"keys,omitempty"` // by keyid
}

// Conf is a remailer's last accepted remailer-conf reply.
type Conf struct {
	Nick       string    `json:"nick"`
	Type       string    `json:"type"`
	Caps       string    `json:"caps"`        // the whole $remailer{...} line
	LastUpdate time.Time `json:"last_update"` // token time of the request
	Received   time.Time `json:"received"`
	DontExpire bool      `json:"dont_expire,omitempty"`
}

// Key is a yamn key of a remailer.
type Key struct {
	KeyID        string     `json:"keyid"`
	Nick         string     `json:"nick"`
	Address      string     `json:"address"`
	Version      string     `json:"version"`
	Caps         string     `json:"caps"`
	Created      civil.Date `json:"created"`
	Expires      civil.Date `json:"expires"`
	PK           PublicKey  `json:"pk"`
	FirstSeen    time.Time  `json:"first_seen"` // token time of the first reply listing it
	LastSeen     time.Time  `json:"last_seen"`  // token time of the last reply listing it
	LastReceived time.Time  `json:"last_received"`
	Sightings    int        `json:"sightings"`
	ProvenAt     time.Time  `json:"proven_at"` // first returned ping to this key; zero = not yet (§9.2)
	State        string     `json:"state"`
}

// PublicKey is a yamn public key.  It is hex in state.json.
type PublicKey [32]byte

// MarshalText writes the key as 64 hex digits.
func (k PublicKey) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(k[:])), nil
}

// UnmarshalText reads 64 hex digits.
func (k *PublicKey) UnmarshalText(b []byte) error {
	if len(b) != 2*len(k) {
		return fmt.Errorf("public key: want %d hex digits, got %d", 2*len(k), len(b))
	}
	_, err := hex.Decode(k[:], b)
	return err
}

// PendingChange is a quarantined change waiting for its time or for the
// operator (design §9.2).
//
// A key change counts sightings on the new key; a nick or address change
// counts them here.  OldSeen is the last token time a reply showed the old
// nick or address again.  A rejected nick or address change is kept, with
// Rejected set, so the same change isn't quarantined again.
type PendingChange struct {
	Address   string    `json:"address"`
	Kind      string    `json:"kind"` // PendingKeyChange, PendingNickChange, PendingAddressChange
	Old       string    `json:"old"`
	New       string    `json:"new"` // keyid, nick or address
	Since     time.Time `json:"since"`
	Sightings int       `json:"sightings,omitempty"` // nick and address changes
	LastSeen  time.Time `json:"last_seen"`           // token time of the last reply showing New
	OldSeen   time.Time `json:"old_seen"`            // token time of the last reply showing Old
	Rejected  bool      `json:"rejected,omitempty"`  // by the operator
}

// Suggestion is a reason to add an address, from another remailer's
// conf reply (design §9.3).
type Suggestion struct {
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
	Source string    `json:"source"`
}

// Fromline is what a remailer does to the From line (phase 3).
type Fromline struct {
	LastUpdate  time.Time `json:"last_update"`
	From        string    `json:"from"`
	DisclaimTop bool      `json:"disclaim_top"`
	DisclaimBot bool      `json:"disclaim_bot"`
}

func newState() *State {
	return &State{Version: StateVersion, Remailers: map[string]*Remailer{}}
}

// AddRemailer adds address with a new ID and Echolot's defaults: active,
// fetch, pingit and showit on.
func (st *State) AddRemailer(address string, now time.Time) (*Remailer, error) {
	if _, ok := st.Remailers[address]; ok {
		return nil, fmt.Errorf("%s is already known", address)
	}
	st.MaxID++
	r := &Remailer{
		ID:              st.MaxID,
		Address:         address,
		Status:          StatusActive,
		TTL:             DefaultTTL,
		ResurrectionTTL: DefaultResurrectionTTL,
		Fetch:           true,
		PingIt:          true,
		ShowIt:          true,
		Added:           now.UTC(),
	}
	st.Remailers[address] = r
	return r, nil
}

// RemailerByID returns the remailer with id, or nil.
func (st *State) RemailerByID(id int) *Remailer {
	for _, r := range st.Remailers {
		if r.ID == id {
			return r
		}
	}
	return nil
}
