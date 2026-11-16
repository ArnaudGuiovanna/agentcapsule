//go:build linux && cgo

// Package authorityservice is the authority service of
// docs/adr/006-authority-service.md: one process per host owns the key
// authority and the restore authority, holds the link to the standby, runs
// degraded mode and the barrier, and serves the worker and the API on two
// local sockets. This file is the protocol, shared with
// internal/authorityclient.
//
// Each frame is a JSON object behind a 4-byte big-endian length, as on the
// replication link (authoritylog.WriteFrame). The first frame of a
// connection is the client's Hello; the service answers with its Status, or
// an error and the end of the connection. Then one Request at a time, each
// answered by one Response. A hold answers first with a held frame, and for
// a key exactly 32 raw bytes after it, never inside JSON; the client sends
// release, and the service answers once the hold has ended.
package authorityservice

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// Protocol is this protocol's version. The service accepts it and the
// previous one; a client refuses a service older than it needs.
const Protocol = 1

// The roles of a client, one per socket.
const (
	RoleWorker = "worker"
	RoleAPI    = "api"
)

// The operations (ADR 006 §2).
const (
	OpStatus             = "status"
	OpLookup             = "lookup"
	OpCheckBinding       = "check_binding"
	OpHoldBinding        = "hold_binding"
	OpEnsureKey          = "ensure_key"
	OpHoldKey            = "hold_key"
	OpDestroyKey         = "destroy_key"
	OpRegister           = "register"
	OpReserveIncarnation = "reserve_incarnation"
	OpBeginRevocation    = "begin_revocation"
	OpScan               = "scan"
	OpRecordFence        = "record_fence"
	OpHoldFences         = "hold_fences"
	OpSubjectBarrier     = "subject_barrier"
	OpHoldRevocation     = "hold_revocation"
	OpRecordOutcome      = "record_outcome"
	OpRecordRerun        = "record_rerun"
	OpRecordSeal         = "record_seal"
	OpLosses             = "losses"
	OpOutcomeStatus      = "outcome_status"
	OpSignArchive        = "sign_archive"
	OpValidateArchive    = "validate_archive"
	OpRecordedOutcomes   = "recorded_outcomes"
	OpDeclareLosses      = "declare_losses"
	OpHoldActivation     = "hold_activation"
	// OpRelease ends a hold; it is valid only after a held frame.
	OpRelease = "release"
)

// The kinds of a hold, for the metrics.
const (
	HoldBinding    = "binding"
	HoldKey        = "key"
	HoldFences     = "fences"
	HoldRevocation = "revocation"
	HoldActivation = "activation"
)

// HoldKinds lists every kind of hold.
func HoldKinds() []string {
	return []string{HoldBinding, HoldKey, HoldFences, HoldRevocation, HoldActivation}
}

// Bounds of a request.
const (
	// MaxTimeout bounds a request's timeout_ms: a client without a deadline
	// sends this one.
	MaxTimeout = 10 * time.Minute
	// MaxRequest bounds a request frame; MaxResponse a response frame.
	MaxRequest  = 4 << 20
	MaxResponse = 8 << 20
	// KeySize is the size of a volume key after its held frame.
	KeySize = 32
	// OutcomesPage bounds the outcomes of one recorded_outcomes answer.
	OutcomesPage = 1000
)

// The error codes, a closed vocabulary (ADR 006 §2).
const (
	CodeInput           = "input"
	CodeUnavailable     = "unavailable"
	CodeConflict        = "conflict"
	CodeStale           = "stale"
	CodeRevoked         = "revoked"
	CodeSealed          = "sealed"
	CodeHistory         = "history"
	CodeNotDeclared     = "not_declared"
	CodeWaitsForReplica = "waits_for_replica"
	CodeReplicaRequired = "replica_required"
	CodeNotArmed        = "not_armed"
	CodeDiverged        = "diverged"
	CodeKeyUnavailable  = "key_unavailable"
	CodeKeyRevoked      = "key_revoked"
	CodeKeyConflict     = "key_conflict"
	CodeKeyInput        = "key_input"
	CodeHoldExpired     = "hold_expired"
	CodeRole            = "role"
	CodeProtocol        = "protocol"
	CodeIdentity        = "identity"
)

// Codes lists every error code.
func Codes() []string {
	return []string{CodeInput, CodeUnavailable, CodeConflict, CodeStale, CodeRevoked, CodeSealed, CodeHistory, CodeNotDeclared,
		CodeWaitsForReplica, CodeReplicaRequired, CodeNotArmed, CodeDiverged, CodeKeyUnavailable, CodeKeyRevoked, CodeKeyConflict,
		CodeKeyInput, CodeHoldExpired, CodeRole, CodeProtocol, CodeIdentity}
}

// Errors of the service itself. Each one is also restoreauthority's
// ErrUnavailable on the client's side: never a stale binding.
var (
	// ErrHoldExpired means that a hold reached its cap: the service ended
	// it and closed the connection.
	ErrHoldExpired = errors.New("authority hold reached its cap")
	// ErrHoldLost means that the hold's connection ended before its release.
	ErrHoldLost = errors.New("authority hold lost with its connection")
	// ErrRole means an operation that this socket does not serve, or a
	// client of another role.
	ErrRole = errors.New("authority operation outside the socket's role")
	// ErrProtocol means a malformed exchange, or an unsupported version.
	ErrProtocol = errors.New("authority service protocol error")
	// ErrIdentity means that the service holds other authorities than the
	// ones the client pins: another installation's.
	ErrIdentity = errors.New("authority service holds other authorities")
)

// codeErrors are the sentinels each code stands for: the client returns
// them, so that every errors.Is of today's callers keeps working.
var codeErrors = map[string][]error{
	CodeInput:           {restoreauthority.ErrInput},
	CodeUnavailable:     {restoreauthority.ErrUnavailable},
	CodeConflict:        {restoreauthority.ErrConflict},
	CodeStale:           {restoreauthority.ErrStale},
	CodeRevoked:         {restoreauthority.ErrRevoked},
	CodeSealed:          {restoreauthority.ErrSealed},
	CodeHistory:         {restoreauthority.ErrHistory},
	CodeNotDeclared:     {restoreauthority.ErrNotDeclared},
	CodeWaitsForReplica: {restoreauthority.ErrUnavailable, restoreauthority.ErrWaitsForReplica},
	CodeReplicaRequired: {restoreauthority.ErrUnavailable, restoreauthority.ErrReplicaRequired},
	CodeNotArmed:        {restoreauthority.ErrNotArmed},
	CodeDiverged:        {restoreauthority.ErrUnavailable, restoreauthority.ErrDiverged},
	CodeKeyUnavailable:  {keyauthority.ErrUnavailable},
	CodeKeyRevoked:      {keyauthority.ErrRevoked},
	CodeKeyConflict:     {keyauthority.ErrConflict},
	CodeKeyInput:        {keyauthority.ErrInput},
	CodeHoldExpired:     {restoreauthority.ErrUnavailable, ErrHoldExpired},
	CodeRole:            {restoreauthority.ErrUnavailable, ErrRole},
	CodeProtocol:        {restoreauthority.ErrUnavailable, ErrProtocol},
	CodeIdentity:        {restoreauthority.ErrUnavailable, ErrIdentity},
}

// Code is the code the service sends for err. An error that carries
// ErrUnavailable is an outage, never a stale binding: it is checked before
// the refusals, so that a caller never retires a VM on an outage.
func Code(err error) string {
	checks := []struct {
		target error
		code   string
	}{
		{ErrHoldExpired, CodeHoldExpired},
		{restoreauthority.ErrWaitsForReplica, CodeWaitsForReplica},
		{restoreauthority.ErrReplicaRequired, CodeReplicaRequired},
		{restoreauthority.ErrNotArmed, CodeNotArmed},
		{restoreauthority.ErrDiverged, CodeDiverged},
		{ErrRole, CodeRole},
		{ErrIdentity, CodeIdentity},
		{ErrProtocol, CodeProtocol},
		{restoreauthority.ErrUnavailable, CodeUnavailable},
		{keyauthority.ErrUnavailable, CodeKeyUnavailable},
		{restoreauthority.ErrStale, CodeStale},
		{restoreauthority.ErrSealed, CodeSealed},
		{restoreauthority.ErrRevoked, CodeRevoked},
		{restoreauthority.ErrHistory, CodeHistory},
		{restoreauthority.ErrNotDeclared, CodeNotDeclared},
		{restoreauthority.ErrConflict, CodeConflict},
		{keyauthority.ErrRevoked, CodeKeyRevoked},
		{keyauthority.ErrConflict, CodeKeyConflict},
		{restoreauthority.ErrInput, CodeInput},
		{keyauthority.ErrInput, CodeKeyInput},
	}
	for _, c := range checks {
		if errors.Is(err, c.target) {
			return c.code
		}
	}
	// A context that ended, a database or file error: an outage.
	return CodeUnavailable
}

// Error is a code received from the service. It unwraps to the code's
// sentinels.
type Error struct {
	Code string
	errs []error
}

func (e *Error) Error() string   { return "authority service: " + e.Code }
func (e *Error) Unwrap() []error { return e.errs }

// ErrorOf returns the error for a code received from the service. An
// unknown code, from a newer service, is a protocol error.
func ErrorOf(code string) error {
	errs, ok := codeErrors[code]
	if !ok {
		return &Error{Code: CodeProtocol, errs: codeErrors[CodeProtocol]}
	}
	return &Error{Code: code, errs: errs}
}

// Hello is a connection's first frame.
type Hello struct {
	Protocol         int    `json:"protocol"`
	Role             string `json:"role"`
	RestoreAuthority string `json:"restore_authority"`
	KeyAuthority     string `json:"key_authority"`
}

// Request is one operation. Its timeout becomes the operation's context in
// the service: a wait at the barrier ends at the caller's deadline.
type Request struct {
	Op        string          `json:"op"`
	TimeoutMS int64           `json:"timeout_ms,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
}

// Response is a result, an error, or the start of a hold.
type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	Held   *Held           `json:"held,omitempty"`
}

// Held starts a hold. The service ends it after HoldMS milliseconds, the
// shorter of the request's deadline and the hold's cap.
type Held struct {
	HoldMS int64 `json:"hold_ms"`
}

// Status is the service's state, the answer to a hello and to status.
type Status struct {
	Protocol         int    `json:"protocol"`
	RestoreAuthority string `json:"restore_authority"`
	KeyAuthority     string `json:"key_authority"`
	RestoreRoot      string `json:"restore_root"`
	KeyRoot          string `json:"key_root"`
	Epoch            uint64 `json:"epoch"`
	// Mode is one of restoreauthority's modes: standalone, synchronous,
	// degraded, waiting.
	Mode string `json:"mode"`
	// DegradedSince is the start of degraded mode, in Unix milliseconds;
	// 0 outside it.
	DegradedSince int64 `json:"degraded_since_ms,omitempty"`
}

// The arguments and results of the operations.
type (
	StoreArgs struct {
		Store string `json:"store"`
	}
	RegisterArgs struct {
		Store  string `json:"store"`
		Volume string `json:"volume"`
	}
	BindingArgs struct {
		Binding restoreauthority.Binding `json:"binding"`
	}
	ReserveArgs struct {
		Binding   restoreauthority.Binding `json:"binding"`
		Operation string                   `json:"operation"`
	}
	SubjectArgs struct {
		Subject string `json:"subject"`
	}
	ReceiptArgs struct {
		Receipt restoreauthority.Receipt `json:"receipt"`
	}
	BarrierArgs struct {
		Binding restoreauthority.Binding `json:"binding"`
		Subject string                   `json:"subject"`
	}
	RevocationArgs struct {
		Subject string                     `json:"subject"`
		Targets []restoreauthority.Binding `json:"targets"`
	}
	OutcomeArgs struct {
		Binding restoreauthority.Binding `json:"binding"`
		Outcome restoreauthority.Outcome `json:"outcome"`
	}
	IDArgs struct {
		ID string `json:"id"`
	}
	ArchiveArgs struct {
		Archive restoreauthority.Archive `json:"archive"`
	}
	// KeyArgs names a volume key. With an incarnation, hold_key holds the
	// binding {agent, volume, incarnation} around the key, in one hold.
	KeyArgs struct {
		Agent       string `json:"agent"`
		Volume      string `json:"volume"`
		Incarnation uint64 `json:"incarnation,omitempty"`
	}
	RecordedArgs struct {
		Receipt restoreauthority.Receipt `json:"receipt"`
		After   string                   `json:"after,omitempty"`
	}
	// LossArgs carries the worker's inspection: the IDs the image lacks,
	// against the recorded list whose digest it names.
	LossArgs struct {
		Receipt restoreauthority.Receipt `json:"receipt"`
		Digest  string                   `json:"digest"`
		Missing []string                 `json:"missing"`
	}

	BindingResult struct {
		Binding restoreauthority.Binding `json:"binding"`
	}
	RevisionResult struct {
		Revision uint64 `json:"revision"`
	}
	ReceiptResult struct {
		Receipt restoreauthority.Receipt `json:"receipt"`
	}
	BarrierResult struct {
		Acknowledged bool `json:"acknowledged"`
		Sealed       bool `json:"sealed"`
	}
	LossesResult struct {
		Losses []restoreauthority.Loss `json:"losses"`
	}
	OutcomeStatusResult struct {
		Status restoreauthority.Status `json:"status"`
		Losses []restoreauthority.Loss `json:"losses"`
	}
	ArchiveResult struct {
		Archive restoreauthority.Archive `json:"archive"`
	}
	// RecordedResult is one page of the recorded outcomes, in ID order.
	// Digest is that of the whole list; Next, when not empty, is the After
	// of the next page.
	RecordedResult struct {
		Outcomes []restoreauthority.Outcome `json:"outcomes"`
		Digest   string                     `json:"digest"`
		Next     string                     `json:"next,omitempty"`
	}
)

// OutcomesDigest is the digest of the outcomes recorded for r's store, as
// the activation's steps name them: the service checks it in its
// transaction, so that a list that changed since the worker's inspection is
// stale.
func OutcomesDigest(r restoreauthority.Receipt, outcomes []restoreauthority.Outcome) string {
	h := sha256.New()
	h.Write([]byte("agentcapsule-recorded-outcomes-v1\x00"))
	field := func(s string) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s))))
		h.Write([]byte(s))
	}
	field(r.Store)
	h.Write(binary.BigEndian.AppendUint64(nil, r.Incarnation))
	for _, o := range outcomes {
		field(o.ID)
		h.Write(o.Digest[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Frames are the replication link's.
var (
	writeFrame = authoritylog.WriteFrame
	readFrame  = authoritylog.ReadFrame
)
