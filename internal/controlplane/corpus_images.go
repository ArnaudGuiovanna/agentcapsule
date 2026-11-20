package controlplane

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
)

// FeatureCorpusMount: the system image's capsule-init reads corpora.json,
// checks each corpus drive's UUID and mounts the corpora under /corpus; it
// also exposes the builder's build drives (ADR 023 §5.5).
const FeatureCorpusMount = "corpus.mount"

// SystemImageFeatures is the closed list of features a system image may
// declare at its approval; migration 0056 keeps the same list.
var SystemImageFeatures = []string{FeatureCorpusMount}

// Guest bases a release may name (harness.yaml base); only GuestBase2 has
// the /corpus mount point (internal/harnesspkg).
const (
	GuestBase1 = "agentcapsule-guest/1"
	GuestBase2 = "agentcapsule-guest/2"
)

// ErrCorpusIncompatible: the harness release or the system image cannot
// mount corpora (422 corpus_incompatible, ADR 023 §14).
var ErrCorpusIncompatible = errors.New("the harness or the system image cannot mount corpora")

// validFeatures: each a known feature, at most once.
func validFeatures(features []string) bool {
	seen := map[string]bool{}
	for _, f := range features {
		if !slices.Contains(SystemImageFeatures, f) || seen[f] {
			return false
		}
		seen[f] = true
	}
	return true
}

// sortedFeatures is features in a stable order, never nil: an approval and
// its replay compare equal, and a list shows [] rather than null.
func sortedFeatures(features []string) []string {
	out := append([]string{}, features...)
	slices.Sort(out)
	return out
}

// releaseBase is the base recorded for an imported release; a manifest that
// names none is of base 1.
func releaseBase(base string) (string, bool) {
	switch base {
	case "", GuestBase1:
		return GuestBase1, true
	case GuestBase2:
		return GuestBase2, true
	}
	return "", false
}

// corporaMountable checks, in tx, that an agent of releaseID booted on the
// system image systemImage can have corpora mounted: its harness has the
// /corpus mount point, a release of base 2 or that image's own built-in
// harness, and the image's capsule-init mounts corpora (corpus.mount).
// Both rows are read FOR SHARE, as validateTemplate does, so neither changes
// before the caller commits. An agent created without a template records no
// system image (systemImage ""), and cannot mount corpora in this version
// (ADR 023 C7). Lot 6 calls it from validateTemplate and the binding routes.
func corporaMountable(ctx context.Context, tx pgx.Tx, releaseID, systemImage string) error {
	if releaseID == "" || systemImage == "" {
		return ErrCorpusIncompatible
	}
	var ok bool
	err := tx.QueryRow(ctx, `SELECT (r.base=$3 OR (r.source='local-approved' AND r.artifact_digest=i.initrd_digest)) AND $4=ANY(i.features)
 FROM harness_releases r, system_images i WHERE r.id=$1 AND i.id=$2 FOR SHARE OF r,i`, releaseID, systemImage, GuestBase2, FeatureCorpusMount).Scan(&ok)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrCorpusIncompatible
	case err != nil:
		return err
	case !ok:
		return ErrCorpusIncompatible
	}
	return nil
}
