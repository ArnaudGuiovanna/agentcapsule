//go:build linux

package keyauthority

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6;
// docs/adr/005-keys-outside-restored-domain.md, Decision). A receipt key
// encrypts the idempotency receipts the API writes in one day, the secrets
// of the tokens it issues included, and is destroyed once the last of them
// has expired. A backup of the database then holds receipts that nothing
// can decrypt.
//
// The key authority keeps a receipt key as the key of a reserved binding:
// the agent ReceiptKeyAgent, which no agent has, and a volume ID that names
// the day. So it is written, wrapped to the unlock key, replicated,
// snapshotted, promoted and destroyed exactly as a volume key is, with no
// new format on disk, in the stream or in the replica. Only its rules
// differ, and its callers apply them: it has no store, so its destruction
// waits for its day to end instead of a seal, and its creation continues in
// degraded mode (internal/restoreauthority, Catalog.Append).

// ReceiptKeyAgent is the reserved agent of the receipt keys. Agent IDs are
// random: none is all zeros, and the authorities refuse to register it.
const ReceiptKeyAgent = "agt_00000000000000000000000000000000"

// receiptVolumePrefix is followed by the day, YYYYMMDD: 32 hex digits in all.
const receiptVolumePrefix = "vol_000000000000000000000000"

// ReceiptDay is the day of t, in UTC: midnight that starts it.
func ReceiptDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// ReceiptKeyVolume is the volume ID that names day's receipt key.
func ReceiptKeyVolume(day time.Time) string {
	return receiptVolumePrefix + ReceiptDay(day).Format("20060102")
}

// ReceiptKeyDay returns the day a receipt key's binding names. It is false
// for every other binding, a volume key's included.
func ReceiptKeyDay(agent, volume string) (time.Time, bool) {
	digits, ok := strings.CutPrefix(volume, receiptVolumePrefix)
	if agent != ReceiptKeyAgent || !ok || len(digits) != 8 {
		return time.Time{}, false
	}
	day, err := time.Parse("20060102", digits)
	if err != nil || ReceiptKeyVolume(day) != volume {
		return time.Time{}, false
	}
	return day, true
}

// ReceiptKey is a day whose receipt key this authority holds. Usable is
// false while its creation has not completed: a journaled key waits for its
// allocation marker until the replica holds it.
type ReceiptKey struct {
	Day    time.Time
	Usable bool
}

// ReceiptKeys lists the days whose receipt key this authority holds, in day
// order: the key file exists, and no tombstone. It reads names only, never a
// key, and takes no lock: a key published or destroyed meanwhile shows at the
// next call.
func (s *Files) ReceiptKeys() ([]ReceiptKey, error) {
	if err := s.checkIdentity(); err != nil {
		return nil, err
	}
	names, err := os.ReadDir(filepath.Join(s.root, "records"))
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	present := map[string]bool{}
	for _, n := range names {
		present[n.Name()] = true
	}
	var held []ReceiptKey
	for _, n := range names {
		day, ok := ReceiptKeyDay(ReceiptKeyAgent, n.Name())
		if !ok {
			continue
		}
		_, err := os.Lstat(filepath.Join(s.root, "revoked", n.Name()))
		switch {
		case err == nil:
			continue // destroyed: the key file goes once the replica holds the destruction
		case !errors.Is(err, os.ErrNotExist):
			return nil, errors.Join(ErrUnavailable, err)
		}
		held = append(held, ReceiptKey{Day: day, Usable: present[n.Name()+".allocated"]})
	}
	slices.SortFunc(held, func(a, b ReceiptKey) int { return a.Day.Compare(b.Day) })
	return held, nil
}
