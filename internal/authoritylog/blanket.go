package authoritylog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// The blanket revocation after a failover (docs/adr/005-keys-outside-restored-domain.md,
// "What the code must do", item 14; docs/adr/006-authority-service.md §7,
// wave 7). When the standby's last contact with the old primary is older than
// the degraded delay, the promotion assumes that a degraded period ran: the
// primary may have confirmed outcomes and bearer tokens' revocations that the
// standby never received. The promotion then writes one access revocation
// record of kind AccessBlanket into the promoted catalogue. It revokes every
// bearer token issued before the failover and moves every delegation trust's
// minimum_iat there; it also names the window to announce, from the last
// contact to the failover. The reconciliation replays it into PostgreSQL like
// any other record.

// BlanketID is the ID of the blanket record of the promotion to epoch, for
// the restore authority restoreAuthority: the same at each attempt of that
// promotion, and no other record's.
func BlanketID(restoreAuthority string, epoch uint64) string {
	h := sha256.New()
	h.Write([]byte("agentcapsule-blanket-revocation-v1\x00"))
	h.Write([]byte(restoreAuthority))
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	h.Write(e[:])
	return "arv_" + hex.EncodeToString(h.Sum(nil)[:16])
}

// Blanket is what a blanket record says.
type Blanket struct {
	// IssuedBefore is the failover's time: every bearer token issued before
	// it is revoked, and every delegation trust's minimum_iat moves to it.
	IssuedBefore time.Time
	// WindowFrom is the standby's last contact with the old primary. The
	// window to announce runs from it to IssuedBefore: outcomes confirmed
	// and revocations made on the primary in it may be lost.
	WindowFrom time.Time
}

// blanketTime is the format of a blanket record's times: UTC, to the
// millisecond.
const blanketTime = "2006-01-02T15:04:05.000Z07:00"

// The parts that name a blanket record's objects.
const (
	blanketIssuedBefore = "issued_before"
	blanketWindow       = "window"
)

// Objects returns the record's objects: [["issued_before", failover],
// ["window", last contact, failover]].
func (b Blanket) Objects() [][]string {
	to := b.IssuedBefore.UTC().Format(blanketTime)
	return [][]string{{blanketIssuedBefore, to}, {blanketWindow, b.WindowFrom.UTC().Format(blanketTime), to}}
}

// ParseBlanket reads a blanket record's objects, as Objects writes them.
func ParseBlanket(objects [][]string) (Blanket, bool) {
	var b Blanket
	if len(objects) != 2 || len(objects[0]) != 2 || objects[0][0] != blanketIssuedBefore ||
		len(objects[1]) != 3 || objects[1][0] != blanketWindow || objects[1][2] != objects[0][1] {
		return b, false
	}
	var err error
	if b.IssuedBefore, err = time.Parse(time.RFC3339Nano, objects[0][1]); err != nil {
		return b, false
	}
	if b.WindowFrom, err = time.Parse(time.RFC3339Nano, objects[1][1]); err != nil || b.WindowFrom.After(b.IssuedBefore) {
		return b, false
	}
	return b, true
}
