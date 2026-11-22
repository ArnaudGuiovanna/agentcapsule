//go:build linux && cgo

package authorityclient

import (
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// operations lists the operations a span may name; another is "invalid".
var operations = []string{svc.OpStatus, svc.OpLookup, svc.OpCheckBinding, svc.OpHoldBinding, svc.OpEnsureKey, svc.OpHoldKey,
	svc.OpDestroyKey, svc.OpRegister, svc.OpReserveIncarnation, svc.OpBeginRevocation, svc.OpScan, svc.OpRecordFence, svc.OpHoldFences,
	svc.OpSubjectBarrier, svc.OpHoldRevocation, svc.OpRecordOutcome, svc.OpRecordRerun, svc.OpRecordSeal, svc.OpLosses,
	svc.OpOutcomeStatus, svc.OpSignArchive, svc.OpValidateArchive, svc.OpRecordedOutcomes, svc.OpDeclareLosses, svc.OpHoldActivation,
	svc.OpAppendAccess, svc.OpOnReplica, svc.OpExportAccess, svc.OpExportSubjects, svc.OpExportStores, svc.OpAnnouncement,
	svc.OpImportSubjects, svc.OpReceiptKey, svc.OpBeginRevocations}

// callSpan is one call to the authority service (OPR-3): its operation and
// outcome, the service's error code or "outage" when the connection failed,
// and for a hold whether it was granted. A hold's span lasts the hold, and
// the work done under it is its child.
var callSpan = telemetry.NewSpanType("authority.call", telemetry.SpanClient, telemetry.SpanAttributes{
	Codes: []telemetry.Label{{Name: "agentcapsule.authority.op", Values: operations},
		{Name: "agentcapsule.outcome", Values: append([]string{"ok", "outage"}, svc.Codes()...)},
		{Name: "agentcapsule.authority.held", Values: []string{"yes", "no"}}}})

// endCall ends a call's span. answer is the service's error code, if it
// answered with one; ok whether the call itself succeeded.
func endCall(span *telemetry.Span, op, answer string, hold, granted, ok bool) {
	if span == nil {
		return
	}
	span.Code("agentcapsule.authority.op", op)
	outcome := "ok"
	if !ok {
		outcome = answer
		if outcome == "" {
			outcome = "outage"
		}
		span.Fail()
	}
	span.Code("agentcapsule.outcome", outcome)
	if hold {
		held := "no"
		if granted {
			held = "yes"
		}
		span.Code("agentcapsule.authority.held", held)
	}
	span.End()
}
