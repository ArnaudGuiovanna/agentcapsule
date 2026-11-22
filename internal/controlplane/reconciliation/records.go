package reconciliation

import (
	"context"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/jackc/pgx/v5"
)

// ErrAuthorityUnavailable means that the authority service did not record a
// personal volume's claim, which needs its answer before the commit: it does
// not answer, or the standby holds its record back before degraded mode
// begins. Nothing was committed: try again in a moment.
var ErrAuthorityUnavailable = errors.New("authority service did not record the revocation: try again")

// The states of an access revocation.
const (
	// RevocationRecording: the revocation took effect here; the authority
	// service does not hold its record yet.
	RevocationRecording = "recording"
	RevocationPending   = "pending"
	RevocationConfirmed = "confirmed"
)

// AccessRecord is the record a revoking transaction appends: its kind (one of
// authoritylog.AccessKinds), the organization whose access it revokes, and
// the revoked objects, each named by the parts of its identity.
type AccessRecord struct {
	ID           string
	Kind         string
	Organization string
	Objects      [][]string
}

// AccessReceipt is the authority service's answer about a record.
type AccessReceipt struct {
	// Known is false when the service holds no record of that ID.
	Known      bool
	Epoch, Seq uint64
	// OnReplica: the standby's replica holds the record, or no replica
	// exists. Degraded: the record was committed in degraded mode, and the
	// replica does not hold it yet.
	OnReplica, Degraded bool
}

// AccessRecorder is the authority service, as the API and agentcapsule-admin
// reach it (internal/authorityclient).
type AccessRecorder interface {
	// RecordAccess appends r: the service commits it, then waits for the
	// replica until ctx's deadline. An error means that it may not have
	// committed it.
	RecordAccess(ctx context.Context, r AccessRecord) (AccessReceipt, error)
	// AccessProgress asks how far the record id has gone.
	AccessProgress(ctx context.Context, id string) (AccessReceipt, error)
}

// Confirmable is the API's rule: the replica holds the record, or it is a
// bearer token's and the service runs in degraded mode.
func Confirmable(kind string, r AccessReceipt) bool {
	bearer, _ := authoritylog.AccessBearer(kind)
	return r.Known && (r.OnReplica || (bearer && r.Degraded))
}

// SettleReceipt moves a recording row to the state its receipt gives. A row
// another pass recorded first keeps what that pass wrote.
func SettleReceipt(ctx context.Context, db rowReader, id, kind string, receipt AccessReceipt) (string, *time.Time, bool) {
	state := RevocationPending
	if Confirmable(kind, receipt) {
		state = RevocationConfirmed
	}
	var at *time.Time
	err := db.QueryRow(ctx, `UPDATE access_revocations SET state=$2,epoch=$3,seq=$4,
        confirmed_at=CASE WHEN $2='confirmed' THEN clock_timestamp() END
        WHERE id=$1 AND state='recording' RETURNING confirmed_at`, id, state, int64(receipt.Epoch), int64(receipt.Seq)).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		err = db.QueryRow(ctx, `SELECT state,confirmed_at FROM access_revocations WHERE id=$1`, id).Scan(&state, &at)
	}
	return state, at, err == nil
}
