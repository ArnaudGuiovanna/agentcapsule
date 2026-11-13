package capsuleprotocol

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"
)

// ControlOutcomes is the read-only inspection of the outcomes that a guest's
// store holds. A restore uses it on the restricted boot of a restored image,
// to find the acknowledged outcomes that the image lacks (REC-02, ADR 003).
// It is optional: a boot that does not offer it can still serve, but cannot be
// restored from an archive.
const ControlOutcomes ControlFeature = "outcomes"

// MaxOutcomeQuery bounds the outcome IDs of one inspection request.
const MaxOutcomeQuery = 1024

// HeldOutcome is one outcome that the guest's store holds: its ID and the
// digest of its stored result (harnessstore.StoredOutcomeFingerprint), in
// lowercase hexadecimal.
type HeldOutcome struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

func validOutcomeID(id string) bool {
	h, ok := strings.CutPrefix(id, "outcome-v1/")
	if !ok || len(h) != 64 || strings.ToLower(h) != h {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

func validOutcomeQuery(ids []string) bool {
	if len(ids) < 1 || len(ids) > MaxOutcomeQuery {
		return false
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !validOutcomeID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func heldOutcomes(held map[string][32]byte) []HeldOutcome {
	out := make([]HeldOutcome, 0, len(held))
	for id, digest := range held {
		out = append(out, HeldOutcome{ID: id, Digest: hex.EncodeToString(digest[:])})
	}
	slices.SortFunc(out, func(a, b HeldOutcome) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Outcomes asks the guest which of ids its store holds, with the digest of
// each one's stored result. An ID it does not return is absent from the
// image. It writes nothing, and a restricted boot answers it. The caller
// checks first that the boot offers ControlOutcomes.
func (c *Client) Outcomes(ctx context.Context, ids []string) (map[string][32]byte, error) {
	held := make(map[string][32]byte)
	for chunk := range slices.Chunk(ids, MaxOutcomeQuery) {
		if !validOutcomeQuery(chunk) {
			return nil, ErrProtocol
		}
		r, err := c.call(ctx, "/v1/outcomes", &request{Outcomes: chunk})
		if err != nil {
			return nil, err
		}
		asked := make(map[string]bool, len(chunk))
		for _, id := range chunk {
			asked[id] = true
		}
		for _, h := range r.Held {
			b, err := hex.DecodeString(h.Digest)
			if !asked[h.ID] || err != nil || len(b) != 32 || strings.ToLower(h.Digest) != h.Digest {
				return nil, ErrProtocol
			}
			if _, duplicate := held[h.ID]; duplicate {
				return nil, ErrProtocol
			}
			held[h.ID] = [32]byte(b)
		}
	}
	return held, nil
}
