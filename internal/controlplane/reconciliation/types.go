package reconciliation

import (
	"context"
	"errors"
	"time"
)

// ErrNotReconciled means that PostgreSQL has not been reconciled with the
// authority service's epoch: the API refuses to open until agentcapsule-admin
// reconcile has run.
var ErrNotReconciled = errors.New("database not reconciled with the authorities' epoch: run agentcapsule-admin reconcile")

// ErrReconciliationRecord means that the authority holds an access
// revocation record that this binary cannot replay. Nothing is marked
// reconciled.
var ErrReconciliationRecord = errors.New("access revocation record that cannot be replayed")

// ErrReconciliationConflict means that the authority service changed epoch
// during the run, does not hold its announced blanket record, or that this
// epoch was reconciled with other authorities. Nothing is marked reconciled.
var ErrReconciliationConflict = errors.New("reconciliation conflict: run it again, and check the pinned identities")

// AuthorityRecord is an access revocation record as the authority holds it.
type AuthorityRecord struct {
	AccessRecord
	RecordedAt time.Time
	Epoch, Seq uint64
	// OnReplica and Degraded are the record's progress, as on_replica gives it.
	OnReplica, Degraded bool
}

// AuthorityStore is a store as the authority knows it.
type AuthorityStore struct {
	ID, Volume  string
	Incarnation uint64
	Sealed      bool
}

// FailoverAnnouncement is what the promotion to an epoch announced.
type FailoverAnnouncement struct {
	Epoch uint64
	// Degraded: the promotion assumed that a degraded period ran. The window
	// from WindowFrom to WindowTo is announced, and Blanket is the record
	// that revokes every bearer token issued before WindowTo.
	Degraded             bool
	WindowFrom, WindowTo time.Time
	Blanket              string
}

// ReconciliationAuthority is the authority service, as the reconciliation
// reaches it on its API socket (internal/authorityclient).
type ReconciliationAuthority interface {
	// RecordAccess appends a record PostgreSQL holds and the authority
	// lacks.
	AccessRecorder
	// AuthorityEpoch gives the restore authority's identity and epoch.
	AuthorityEpoch(ctx context.Context) (string, uint64, error)
	AuthorityRecords(ctx context.Context) ([]AuthorityRecord, error)
	AuthoritySubjects(ctx context.Context) ([]string, error)
	AuthorityStores(ctx context.Context) ([]AuthorityStore, error)
	AuthorityAnnouncement(ctx context.Context) (FailoverAnnouncement, error)
	// ImportSubjects begins, in the authority, the subjects it lacks.
	ImportSubjects(ctx context.Context, subjects []string) error
}

// Reconciliation is what a run did and found.
type Reconciliation struct {
	Epoch            uint64 `json:"epoch"`
	RestoreAuthority string `json:"restore_authority_id"`
	// Announcement is set when the promotion assumed a degraded period.
	Announcement *ReconciledWindow `json:"announcement,omitempty"`
	// Replayed counts the records PostgreSQL lacked; Kept those it held
	// and the authority lacked. SubjectsKept and SubjectsCopied count the
	// same for the revocation subjects.
	Replayed       int `json:"records_replayed"`
	Kept           int `json:"records_kept"`
	SubjectsKept   int `json:"subjects_kept"`
	SubjectsCopied int `json:"subjects_copied"`
	// DeletionsResumed are the agents whose deletion PostgreSQL did not
	// know; Unresumed the ones it could not resume.
	DeletionsResumed []string          `json:"deletions_resumed"`
	Unresumed        []StoreDivergence `json:"deletions_not_resumed"`
	// Divergent are the stores whose registration or incarnation differs.
	Divergent    []StoreDivergence `json:"divergent_stores"`
	ReconciledAt time.Time         `json:"reconciled_at"`
}

// ReconciledWindow is the announcement of a degraded period: outcomes
// confirmed and revocations made in the window may be lost, and every bearer
// token issued before its end is revoked.
type ReconciledWindow struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Blanket string    `json:"blanket_revocation_id"`
}

// StoreDivergence is a store that PostgreSQL and the authority see apart.
type StoreDivergence struct {
	Store  string `json:"store"`
	Reason string `json:"reason"`
	// The incarnation each side holds; 0 when that side has none.
	Authority uint64 `json:"authority_incarnation,omitempty"`
	Database  uint64 `json:"database_incarnation,omitempty"`
}

// The reasons of a divergence.
const (
	DivergenceNotEnrolled   = "not_enrolled"   // the authority registered it; PostgreSQL does not know it
	DivergenceNotRegistered = "not_registered" // PostgreSQL enrolled it past installation; the authority does not know it
	DivergenceVolume        = "volume"         // their volumes differ
	DivergenceIncarnation   = "incarnation"    // their incarnations differ
	DivergenceUnknownAgent  = "unknown_agent"  // a deletion to resume, of an agent PostgreSQL does not know
	DivergencePhase         = "phase"          // a deletion to resume, of an agent in a phase no deletion starts from
)

// RevocationScope is a revocation subject and the stores that can act on
// it; no store means every store.
type RevocationScope struct {
	Subject string
	Stores  []string
}

// ScopedImporter is a reconciliation authority that takes each imported
// subject's scope. The reconciliation uses it when the authority offers it.
type ScopedImporter interface {
	ImportScopes(ctx context.Context, scopes []RevocationScope) error
}
